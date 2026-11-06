"""Edge proxy: the single decision point.

Low-score traffic passes to the real upstream untouched. High-score or canary-triggered
sessions are diverted to the decoy world and stay there.

Hard rules enforced here:
  * Protected routes (login, signup, payment, ...) are never diverted.
  * Fail open: any error in scoring/bookkeeping sends the request to the real upstream.
  * Nothing is ever sent to attacker infrastructure; the proxy only talks to the configured upstream.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import random
import threading
import time
import zlib
from contextlib import asynccontextmanager
from email.utils import formatdate

import httpx
from fastapi import FastAPI, Request, WebSocket
from fastapi.responses import Response, StreamingResponse
from starlette.background import BackgroundTask

from .canary import CanaryMatcher, record_hits
from .config import Settings
from .db import DB
from .decoy import DecoyService
from .scoring import SessionState, observe, score

log = logging.getLogger("labyrinth.proxy")

HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers",
              "transfer-encoding", "upgrade", "host", "content-length"}
# Response bodies are streamed raw, so content-encoding and content-length are passed through as-is.
HOP_BY_HOP_RESPONSE = {"connection", "keep-alive", "proxy-authenticate", "te", "trailers", "transfer-encoding", "upgrade"}
FORWARDED = {"x-forwarded-for", "x-forwarded-proto", "x-forwarded-host", "x-real-ip", "forwarded"}
SCAN_BYTES = 256 * 1024  # how much of a request body is searched for canaries
REDACT = {"authorization", "cookie", "x-api-key", "proxy-authorization"}


IDENTITY_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-content-type-options", "x-frame-options",
                    "referrer-policy", "cross-origin-opener-policy", "strict-transport-security", "x-xss-protection",
                    "permissions-policy", "content-security-policy")
CAPTURE_BYTES = 64 * 1024     # max body kept for a replayable response
REPLAY_PER_SESSION = 50       # max real responses remembered per session (memory only)


class Fingerprint:
    """What the real app looks like from outside, learned from its responses, so the decoy can look the same.

    Holds only response *shape*: identity/security headers and the app's own 404 page(s).
    """

    def __init__(self) -> None:
        self.headers: dict[str, str] = {}
        self._not_found: dict[str, tuple[int, str, str, str]] = {}  # prefix -> (status, ctype, body, original path)

    def learn_headers(self, up: httpx.Response) -> None:
        for k in IDENTITY_HEADERS:
            if k in up.headers:
                self.headers[k] = up.headers[k]

    def learn_not_found(self, path: str, ctype: str, body: bytes) -> None:
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            return
        self._not_found[self._prefix(path)] = (404, ctype, text, path)

    def not_found_for(self, path: str) -> tuple[int, str, str] | None:
        hit = self._not_found.get(self._prefix(path)) or next(iter(self._not_found.values()), None)
        if not hit:
            return None
        status, ctype, text, orig = hit
        # Many 404 pages echo the requested path, sometimes without its leading slash (e.g. Next.js).
        text = text.replace(orig, path).replace(orig.lstrip("/"), path.lstrip("/")) if orig.strip("/") else text
        return status, ctype, text

    @staticmethod
    def _prefix(path: str) -> str:
        return "api" if path.startswith("/api") else "web"


class Sessions:
    def __init__(self, db: DB):
        self.db = db
        self._lock = threading.Lock()
        self._live: dict[str, SessionState] = {}

    def get(self, sid: str, client: str, ua: str) -> SessionState:
        with self._lock:
            s = self._live.get(sid)
            if s is None:
                s = SessionState(id=sid, client=client, user_agent=ua)
                row = self.db.get_session(sid)
                if row:  # restore sticky diversion + counters across restarts
                    for k in ("first_seen", "request_count", "score", "reasons", "diverted", "diverted_at",
                              "decoy_requests", "llm_generations", "techniques"):
                        setattr(s, k, row[k])
                self._live[sid] = s
            return s


def replay_key(conn: Request) -> str:
    return f"{conn.url.path}?{conn.url.query}"


async def tee(up: httpx.Response, on_body):
    """Stream the upstream body through untouched, keeping a copy of small bodies."""
    buf, overflow = bytearray(), False
    async for chunk in up.aiter_raw():
        if not overflow:
            if len(buf) + len(chunk) <= CAPTURE_BYTES:
                buf.extend(chunk)
            else:
                overflow = True
        yield chunk
    if not overflow:
        on_body(bytes(buf))


def session_id_for(request: Request, settings: Settings) -> tuple[str, str, str]:
    client = request.client.host if request.client else "unknown"
    if settings.trust_forwarded_for and request.headers.get("x-forwarded-for"):
        client = request.headers["x-forwarded-for"].split(",")[0].strip()
    ua = request.headers.get("user-agent", "")
    sid = hashlib.sha256(f"{client}|{ua}".encode()).hexdigest()[:16]
    return sid, client, ua


def create_app(settings: Settings | None = None, db: DB | None = None,
               upstream_transport: httpx.AsyncBaseTransport | None = None) -> FastAPI:
    settings = settings or Settings()
    db = db or DB(settings.db_path)
    sessions = Sessions(db)
    matcher = CanaryMatcher(db)
    decoy = DecoyService(db, settings)
    client_kwargs = {"base_url": settings.upstream, "timeout": settings.upstream_timeout, "follow_redirects": False}
    if upstream_transport is not None:
        client_kwargs["transport"] = upstream_transport
    upstream = httpx.AsyncClient(**client_kwargs)
    upstream_url = httpx.URL(settings.upstream)
    fingerprint = Fingerprint()
    replay: dict[str, dict[str, tuple[int, list[tuple[str, str]], bytes]]] = {}  # session -> GET url -> real response

    @asynccontextmanager
    async def lifespan(_app):
        log.warning("Labyrinth proxy: mode=%s upstream=%s threshold=%s", settings.mode, settings.upstream, settings.threshold)
        yield
        await upstream.aclose()

    app = FastAPI(title="Labyrinth edge proxy", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.db, app.state.settings, app.state.sessions = db, settings, sessions

    def is_protected(path: str) -> bool:
        p = path.lower()
        return any(p == pref or p.startswith(pref.rstrip("/") + "/") for pref in settings.protected_prefixes)

    def forward_headers(conn: Request | WebSocket) -> list[tuple[str, str]]:
        """Request headers for the upstream: hop-by-hop removed, duplicates kept, X-Forwarded-* set."""
        client = conn.client.host if conn.client else ""
        drop = HOP_BY_HOP | FORWARDED
        out = [(k, v) for k, v in conn.headers.items() if k.lower() not in drop]
        prior_xff = conn.headers.get("x-forwarded-for") if settings.trust_forwarded_for else None
        out.append(("x-forwarded-for", f"{prior_xff}, {client}" if prior_xff else client))
        proto = (conn.headers.get("x-forwarded-proto") if settings.trust_forwarded_for else None) or conn.url.scheme
        out.append(("x-forwarded-proto", proto.replace("ws", "http")))
        if conn.headers.get("host"):
            out.append(("x-forwarded-host", conn.headers["host"]))
            if settings.preserve_host:
                out.append(("host", conn.headers["host"]))
        return out

    def upstream_target(conn: Request | WebSocket) -> httpx.URL:
        """Exact path + query bytes as the client sent them (no re-encoding)."""
        raw = conn.scope.get("raw_path") or conn.url.path.encode()
        qs = conn.scope.get("query_string") or b""
        base_path = upstream_url.raw_path.split(b"?")[0].rstrip(b"/")
        return upstream_url.copy_with(raw_path=base_path + raw + (b"?" + qs if qs else b""))

    def decide(state: SessionState, method: str, path: str, query: str, body_text: str,
               header_blob: str, client: str, ua: str, now: float, protected: bool) -> tuple[str, set[str]]:
        tech = observe(state, method, path, query, body_text[:4000], now)
        hits = matcher.find(header_blob, query, body_text)
        if hits:
            state.canary_used = True
            state.techniques.add("canary_credential_use")
            tech.add("canary_credential_use")
            record_hits(db, settings, hits, state.id, method, path, client, ua)
        state.score, reasons = score(state, now)
        if not state.diverted:
            state.reasons = reasons
            if state.score >= settings.threshold and not protected:
                state.diverted, state.diverted_at = True, now
                verb = "diverting" if settings.mode == "divert" else "flagging (observe mode)"
                log.warning("%s session %s (score %s): %s", verb, state.id, state.score, "; ".join(reasons))
        if not state.diverted:
            return "upstream", tech
        if protected:
            return "protected", tech
        return ("decoy" if settings.mode == "divert" else "flagged"), tech

    def record(state, method, path, query, headers, body_text, status, route, snippet, tech, now):
        try:
            state.statuses.append(status)
            hdrs = {k: ("[redacted]" if k.lower() in REDACT and not route.startswith("decoy") else v)
                    for k, v in headers.items()}
            db.log_event(session_id=state.id, ts=now, method=method, path=path, query=query,
                         headers=json.dumps(hdrs), body=body_text[:4000] if route.startswith("decoy") else body_text[:200],
                         status=status, route=route, score=state.score, response_snippet=snippet[:600],
                         techniques=json.dumps(sorted(tech)))
            db.upsert_session(state.as_row())
        except Exception:  # noqa: BLE001
            log.exception("engagement logging failed")

    @app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
    async def handle(request: Request, full_path: str):  # noqa: ARG001
        body = await request.body()
        path, query = request.url.path, request.url.query
        body_text = body[:SCAN_BYTES].decode("utf-8", "replace")
        now = time.time()
        route, tech, state = "upstream", set(), None
        protected = is_protected(path)

        # ---- decide (fail open) -------------------------------------------------------
        try:
            sid, client, ua = session_id_for(request, settings)
            state = sessions.get(sid, client, ua)
            header_blob = "\n".join(f"{k}: {v}" for k, v in request.headers.items())
            route, tech = decide(state, request.method, path, query, body_text, header_blob, client, ua, now, protected)
        except Exception:  # noqa: BLE001
            log.exception("scoring failed; failing open")
            route = "upstream"

        # ---- decoy -------------------------------------------------------------------
        if route == "decoy":
            try:
                if settings.tarpit_ms:
                    await asyncio.sleep(settings.tarpit_ms / 1000 * random.uniform(0.6, 1.6))
                seen = replay.get(state.id, {}).get(replay_key(request))
                if seen:
                    # This session already saw the real response for this URL before it was caught:
                    # serve it again so the world doesn't change under the attacker's feet.
                    status, hdrs, raw = seen
                    resp = Response(content=raw, status_code=status)
                    resp.raw_headers = [(k.encode("latin-1"), v.encode("latin-1")) for k, v in hdrs]
                    text, gen = raw[:600].decode("utf-8", "replace"), "replay"
                else:
                    history = [p for _, p in state.paths]
                    status, ctype, text, gen = await decoy.respond(state, request.method, path, query, body_text,
                                                                   history, fingerprint)
                    headers = dict(fingerprint.headers)
                    headers["date"] = formatdate(usegmt=True)
                    resp = Response(content=text, status_code=status, media_type=ctype, headers=headers)
                state.decoy_requests += 1
            except Exception:  # noqa: BLE001
                # A diverted session is never sent to the real system on decoy failure: it gets a bland 503.
                log.exception("decoy failed")
                status, gen, text = 503, "error", '{"error":"service_unavailable"}'
                resp = Response(content=text, status_code=503, media_type="application/json")
            record(state, request.method, path, query, request.headers, body_text, status, f"decoy:{gen}", text, tech, now)
            return resp

        # ---- real upstream, streamed both ways -----------------------------------------
        try:
            hdrs = forward_headers(request)
            if request.method == "HEAD":
                # Some servers (e.g. gunicorn) send a body on HEAD; never reuse that connection.
                hdrs.append(("connection", "close"))
            req = upstream.build_request(request.method, upstream_target(request), headers=hdrs, content=body)
            up = await upstream.send(req, stream=True)
        except httpx.HTTPError as exc:
            log.error("upstream error: %s", exc)
            return Response('{"error":"bad_gateway"}', status_code=502, media_type="application/json")
        if state is not None:
            record(state, request.method, path, query, request.headers, body_text, up.status_code, route, "", tech, now)
        out_headers = [(k, v) for k, v in up.headers.multi_items() if k.lower() not in HOP_BY_HOP_RESPONSE]
        try:
            fingerprint.learn_headers(up)
        except Exception:  # noqa: BLE001
            pass

        def on_body(raw: bytes) -> None:
            """Called once the whole response body has streamed, if it was small enough to keep."""
            try:
                ctype = up.headers.get("content-type", "")
                if up.status_code == 404:
                    enc = up.headers.get("content-encoding", "identity").lower()
                    if enc in ("gzip", "deflate", "identity"):
                        plain = zlib.decompress(raw, 47) if enc != "identity" else raw  # 47: gzip or zlib header
                        fingerprint.learn_not_found(path, ctype, plain)
                if state is not None and route == "upstream" and request.method == "GET" and "text/event-stream" not in ctype:
                    keep = [(k, v) for k, v in out_headers if k.lower() not in ("set-cookie", "date")]
                    mem = replay.setdefault(state.id, {})
                    if len(mem) < REPLAY_PER_SESSION:
                        mem[replay_key(request)] = (up.status_code, keep, raw)
            except Exception:  # noqa: BLE001
                log.exception("fingerprint capture failed")

        resp = StreamingResponse(tee(up, on_body), status_code=up.status_code, background=BackgroundTask(up.aclose))
        resp.raw_headers = [(k.encode("latin-1"), v.encode("latin-1")) for k, v in out_headers]
        return resp

    # ---- websockets: pass through for normal sessions, closed for diverted ones -------------
    @app.websocket("/{full_path:path}")
    async def ws_handle(ws: WebSocket, full_path: str):  # noqa: ARG001
        import websockets

        now = time.time()
        path, query = ws.url.path, ws.url.query
        route, state, tech = "upstream", None, set()
        try:
            client = ws.client.host if ws.client else "unknown"
            if settings.trust_forwarded_for and ws.headers.get("x-forwarded-for"):
                client = ws.headers["x-forwarded-for"].split(",")[0].strip()
            ua = ws.headers.get("user-agent", "")
            sid = hashlib.sha256(f"{client}|{ua}".encode()).hexdigest()[:16]
            state = sessions.get(sid, client, ua)
            header_blob = "\n".join(f"{k}: {v}" for k, v in ws.headers.items())
            route, tech = decide(state, "WS", path, query, "", header_blob, client, ua, now, is_protected(path))
        except Exception:  # noqa: BLE001
            log.exception("websocket scoring failed; failing open")
        if state is not None:
            record(state, "WS", path, query, ws.headers, "", 101 if route != "decoy" else 403, route, "", tech, now)
        if route == "decoy":
            await ws.close(code=1008)
            return

        target = upstream_target(ws)
        uri = str(target.copy_with(scheme="wss" if target.scheme == "https" else "ws"))
        skip = HOP_BY_HOP | FORWARDED | {"sec-websocket-key", "sec-websocket-version", "sec-websocket-extensions",
                                         "sec-websocket-protocol", "origin", "user-agent"}
        extra = [(k, v) for k, v in forward_headers(ws) if k.lower() not in skip]
        protos = [p.strip() for p in ws.headers.get("sec-websocket-protocol", "").split(",") if p.strip()]
        try:
            async with websockets.connect(uri, additional_headers=extra, origin=ws.headers.get("origin"),
                                          user_agent_header=ws.headers.get("user-agent"),
                                          subprotocols=protos or None, open_timeout=10) as up_ws:
                await ws.accept(subprotocol=up_ws.subprotocol)

                async def client_to_upstream():
                    while True:
                        msg = await ws.receive()
                        if msg["type"] == "websocket.disconnect":
                            await up_ws.close()
                            return
                        await up_ws.send(msg["bytes"] if msg.get("bytes") is not None else msg.get("text", ""))

                async def upstream_to_client():
                    async for m in up_ws:
                        await (ws.send_bytes(m) if isinstance(m, bytes) else ws.send_text(m))
                    await ws.close()

                tasks = [asyncio.create_task(client_to_upstream()), asyncio.create_task(upstream_to_client())]
                await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for t in tasks:
                    t.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)  # either side hanging up is a normal end
        except Exception as exc:  # noqa: BLE001
            log.info("websocket session ended: %s", exc)
            try:
                await ws.close(code=1011)
            except Exception:  # noqa: BLE001
                pass

    return app


if __name__ == "__main__":
    import uvicorn

    logging.basicConfig(level=logging.INFO)
    s = Settings()
    uvicorn.run(create_app(s), host=s.proxy_host, port=s.proxy_port, proxy_headers=False,
                server_header=False, date_header=False)
