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
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import Response

from .canary import CanaryMatcher, record_hits
from .config import Settings
from .db import DB
from .decoy import DecoyService
from .scoring import SessionState, observe, score

log = logging.getLogger("labyrinth.proxy")

HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers",
              "transfer-encoding", "upgrade", "host", "content-length"}
STRIP_RESPONSE = HOP_BY_HOP | {"content-encoding"}
REDACT = {"authorization", "cookie", "x-api-key", "proxy-authorization"}


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
    client_kwargs = {"base_url": settings.upstream, "timeout": 30, "follow_redirects": False}
    if upstream_transport is not None:
        client_kwargs["transport"] = upstream_transport
    upstream = httpx.AsyncClient(**client_kwargs)

    @asynccontextmanager
    async def lifespan(_app):
        yield
        await upstream.aclose()

    app = FastAPI(title="Labyrinth edge proxy", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.db, app.state.settings, app.state.sessions = db, settings, sessions


    def is_protected(path: str) -> bool:
        p = path.lower()
        return any(p == pref or p.startswith(pref.rstrip("/") + "/") for pref in settings.protected_prefixes)

    async def forward(request: Request, body: bytes) -> httpx.Response:
        headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP_BY_HOP}
        return await upstream.request(request.method, request.url.path, params=request.url.query or None,
                                      headers=headers, content=body)

    @app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
    async def handle(request: Request, full_path: str):  # noqa: ARG001
        body = await request.body()
        path, query = request.url.path, request.url.query
        body_text = body.decode("utf-8", "replace")[:4000]
        now = time.time()
        route, tech, state = "upstream", set(), None
        protected = is_protected(path)

        # ---- decide (fail open) -------------------------------------------------------
        try:
            sid, client, ua = session_id_for(request, settings)
            state = sessions.get(sid, client, ua)
            tech = observe(state, request.method, path, query, body_text, now)
            header_blob = "\n".join(f"{k}: {v}" for k, v in request.headers.items())
            hits = matcher.find(header_blob, query, body_text)
            if hits:
                state.canary_used = True
                state.techniques.add("canary_credential_use")
                tech.add("canary_credential_use")
                record_hits(db, settings, hits, sid, request.method, path, client, ua)
            state.score, reasons = score(state, now)
            if not state.diverted:
                state.reasons = reasons
                if state.score >= settings.threshold and not protected:
                    state.diverted, state.diverted_at = True, now
                    log.warning("diverting session %s (score %s): %s", sid, state.score, "; ".join(reasons))
            if state.diverted:
                route = "protected" if protected else "decoy"
        except Exception:  # noqa: BLE001
            log.exception("scoring failed; failing open")
            route = "upstream"

        # ---- serve -------------------------------------------------------------------
        if route == "decoy":
            try:
                if settings.tarpit_ms:
                    await asyncio.sleep(settings.tarpit_ms / 1000 * random.uniform(0.6, 1.6))
                history = [p for _, p in state.paths]
                status, ctype, text, gen = await decoy.respond(state, request.method, path, query, body_text, history)
                state.decoy_requests += 1
                resp = Response(content=text, status_code=status, media_type=ctype,
                                headers={"server": "nginx", "x-request-id": hashlib.md5(f"{state.id}{now}".encode()).hexdigest()[:20]})
            except Exception:  # noqa: BLE001
                # A diverted session is never sent to the real system on decoy failure: it gets a bland 503.
                log.exception("decoy failed")
                status, gen, text = 503, "error", '{"error":"service_unavailable"}'
                resp = Response(content=text, status_code=503, media_type="application/json")
        else:
            try:
                up = await forward(request, body)
            except httpx.HTTPError as exc:
                log.error("upstream error: %s", exc)
                return Response('{"error":"bad_gateway"}', status_code=502, media_type="application/json")
            status, text, gen = up.status_code, up.text[:300], route
            resp = Response(content=up.content, status_code=up.status_code,
                            headers={k: v for k, v in up.headers.items() if k.lower() not in STRIP_RESPONSE})

        # ---- record (never blocks the response on failure) -----------------------------
        try:
            if state is not None:
                state.statuses.append(status)
                hdrs = {k: ("[redacted]" if k.lower() in REDACT and route != "decoy" else v)
                        for k, v in request.headers.items()}
                db.log_event(session_id=state.id, ts=now, method=request.method, path=path, query=query,
                             headers=json.dumps(hdrs), body=body_text if route == "decoy" else body_text[:200],
                             status=status, route=route if route != "decoy" else f"decoy:{gen}",
                             score=state.score, response_snippet=text[:600], techniques=json.dumps(sorted(tech)))
                db.upsert_session(state.as_row())
        except Exception:  # noqa: BLE001
            log.exception("engagement logging failed")
        return resp

    return app


app = None  # set by `python -m labyrinth.proxy`

if __name__ == "__main__":
    import uvicorn

    logging.basicConfig(level=logging.INFO)
    uvicorn.run(create_app(), host="0.0.0.0", port=int(__import__("os").getenv("LABYRINTH_PORT", "8080")))
