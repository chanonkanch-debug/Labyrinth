"""Admin app (separate port from the proxy): canary management API + engagement dashboard."""
from __future__ import annotations

import html
import json
import logging
import time

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel

from .canary import KINDS, create_canary
from .config import Settings
from .db import DB

log = logging.getLogger("labyrinth.admin")


class CanaryIn(BaseModel):
    kind: str = "api_key"
    label: str | None = None
    placement: str | None = None


def _fmt_dur(sec: float | None) -> str:
    if not sec:
        return "0s"
    sec = int(sec)
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    return f"{h}h {m}m" if h else (f"{m}m {s}s" if m else f"{s}s")


def _ago(ts: float | None) -> str:
    return _fmt_dur(time.time() - ts) + " ago" if ts else "—"


def summary(db: DB) -> dict:
    trapped = db.all("SELECT * FROM sessions WHERE diverted=1 ORDER BY diverted_at DESC")
    for s in trapped:
        s["time_in_decoy"] = max(0.0, s["last_seen"] - (s["diverted_at"] or s["last_seen"]))
        s["reasons"] = json.loads(s["reasons"])
        s["techniques"] = json.loads(s["techniques"])
        s["paths_explored"] = (db.one("SELECT COUNT(DISTINCT path) n FROM events WHERE session_id=? AND route LIKE 'decoy%'",
                                      (s["id"],)) or {"n": 0})["n"]
    tech_counts: dict[str, int] = {}
    for s in trapped:
        for t in s["techniques"]:
            tech_counts[t] = tech_counts.get(t, 0) + 1
    return {
        "sessions_total": (db.one("SELECT COUNT(*) n FROM sessions") or {"n": 0})["n"],
        "sessions_trapped": len(trapped),
        "time_wasted_seconds": sum(s["time_in_decoy"] for s in trapped),
        "decoy_requests": sum(s["decoy_requests"] for s in trapped),
        "canary_hits": (db.one("""SELECT COUNT(*) n FROM canary_hits h JOIN canaries c ON c.id=h.canary_id
                                   WHERE c.origin='planted'""") or {"n": 0})["n"],
        "decoy_keys_reused": (db.one("""SELECT COUNT(*) n FROM canary_hits h JOIN canaries c ON c.id=h.canary_id
                                         WHERE c.origin='decoy'""") or {"n": 0})["n"],
        "canaries_planted": (db.one("SELECT COUNT(*) n FROM canaries WHERE origin='planted'") or {"n": 0})["n"],
        "techniques": dict(sorted(tech_counts.items(), key=lambda kv: -kv[1])),
        "trapped": trapped,
    }


CSS = """
:root{--bg:#f7f7f5;--card:#fff;--ink:#1b1b1f;--mute:#6b6b76;--line:#e4e4e0;--accent:#7a3cff;--bad:#c2410c;--ok:#15803d}
@media (prefers-color-scheme:dark){:root{--bg:#121216;--card:#1b1b21;--ink:#ececf1;--mute:#9a9aa6;--line:#2c2c35;--accent:#a98bff;--bad:#fb923c;--ok:#4ade80}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1200px;margin:0 auto;padding:24px 16px}h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 10px}
.sub{color:var(--mute);margin-bottom:20px}a{color:var(--accent)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.tile b{display:block;font-size:24px;font-variant-numeric:tabular-nums}.tile span{color:var(--mute);font-size:12px}
.wrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;color:var(--mute);font-weight:600}tr:last-child td{border-bottom:0}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
.tag{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:0 8px;margin:1px;font-size:11px}
.decoy{color:var(--bad)}.upstream{color:var(--ok)}pre{white-space:pre-wrap;word-break:break-all;margin:0;max-height:160px;overflow:auto}
form{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:10px}
input,select,button{font:inherit;padding:6px 10px;border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--ink)}
button{background:var(--accent);color:#fff;border:0;cursor:pointer}
"""


def page(title: str, body: str, refresh: bool = True) -> HTMLResponse:
    meta = '<meta http-equiv="refresh" content="5">' if refresh else ""
    return HTMLResponse(f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
{meta}<title>{html.escape(title)}</title><style>{CSS}</style></head><body><main>{body}</main></body></html>""")


def create_admin_app(settings: Settings | None = None, db: DB | None = None) -> FastAPI:
    settings = settings or Settings()
    db = db or DB(settings.db_path)
    app = FastAPI(title="Labyrinth admin")
    if not settings.admin_token:
        log.warning("LABYRINTH_ADMIN_TOKEN not set: admin app is unauthenticated (local dev only)")

    def auth(request: Request):
        if not settings.admin_token:
            return
        supplied = (request.headers.get("x-admin-token") or request.cookies.get("lbr_admin")
                    or request.query_params.get("token"))
        if supplied != settings.admin_token:
            raise HTTPException(401, "admin token required")

    # ---------------- JSON API ----------------
    @app.post("/api/canaries", dependencies=[Depends(auth)])
    def api_create_canary(c: CanaryIn):
        if c.kind not in KINDS:
            raise HTTPException(400, f"kind must be one of {KINDS}")
        return create_canary(db, c.kind, c.label, c.placement, company=settings.company_name)

    @app.get("/api/canaries", dependencies=[Depends(auth)])
    def api_list_canaries():
        return db.all("""SELECT c.*, (SELECT COUNT(*) FROM canary_hits h WHERE h.canary_id=c.id) hits
                         FROM canaries c ORDER BY c.id DESC""")

    @app.get("/api/summary", dependencies=[Depends(auth)])
    def api_summary():
        return summary(db)

    @app.get("/api/sessions/{sid}/events", dependencies=[Depends(auth)])
    def api_events(sid: str):
        return db.all("SELECT * FROM events WHERE session_id=? ORDER BY ts", (sid,))

    # ---------------- HTML dashboard ----------------
    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request):
        auth(request)
        s = summary(db)
        observe_mode = settings.mode != "divert"
        tiles = "".join(f'<div class="tile"><b>{v}</b><span>{k}</span></div>' for k, v in [
            ("Sessions flagged (not diverted)" if observe_mode else "Sessions trapped", s["sessions_trapped"]),
            ("Attacker time wasted", _fmt_dur(s["time_wasted_seconds"])),
            ("Decoy responses served", s["decoy_requests"]),
            ("Planted canary hits", s["canary_hits"]),
            ("Decoy keys reused by attackers", s["decoy_keys_reused"]),
            ("Canaries planted", s["canaries_planted"]),
        ])
        rows = "".join(f"""<tr><td><a class="mono" href="/sessions/{t['id']}">{t['id']}</a><br><span class="mono">{html.escape(t['client'] or '')}</span></td>
            <td class="mono">{html.escape((t['user_agent'] or '')[:60])}</td><td>{t['score']}</td>
            <td>{'<br>'.join(html.escape(r) for r in t['reasons'])}</td><td>{_ago(t['diverted_at'])}</td>
            <td>{_fmt_dur(t['time_in_decoy'])}</td><td>{t['decoy_requests']} / {t['paths_explored']}</td>
            <td>{''.join(f'<span class="tag">{html.escape(x)}</span>' for x in t['techniques'])}</td></tr>"""
                       for t in s["trapped"]) or '<tr><td colspan="8">No sessions trapped yet.</td></tr>'
        techs = "".join(f'<span class="tag">{html.escape(k)} · {v}</span>' for k, v in s["techniques"].items()) or "None yet."
        canaries = db.all("""SELECT c.*, (SELECT COUNT(*) FROM canary_hits h WHERE h.canary_id=c.id) hits
                             FROM canaries c WHERE origin='planted' ORDER BY id DESC LIMIT 50""")
        crow = "".join(f"""<tr><td>{c['id']}</td><td>{c['kind']}</td><td>{html.escape(c['label'] or '')}</td>
            <td>{html.escape(c['placement'] or '')}</td><td class="mono">{html.escape(c['token'][:14])}…</td>
            <td>{c['hits']}</td></tr>""" for c in canaries) or '<tr><td colspan="6">No canaries yet.</td></tr>'
        hits = db.all("""SELECT h.*, c.kind, c.origin, c.label FROM canary_hits h JOIN canaries c ON c.id=h.canary_id
                         WHERE c.origin='planted' ORDER BY h.ts DESC LIMIT 20""")
        hrow = "".join(f"""<tr><td>{_ago(h['ts'])}</td><td>{h['kind']} ({h['origin']})</td>
            <td><a class="mono" href="/sessions/{h['session_id']}">{h['session_id']}</a></td>
            <td class="mono">{h['method']} {html.escape(h['path'])}</td></tr>""" for h in hits) or '<tr><td colspan="4">No hits.</td></tr>'
        opts = "".join(f"<option>{k}</option>" for k in KINDS)
        return page("Labyrinth", f"""
<h1>Labyrinth</h1><div class="sub">Engagement dashboard · refreshes every 5s · upstream <code>{html.escape(settings.upstream)}</code> ·
mode <b>{'OBSERVE (nothing is diverted)' if observe_mode else 'divert'}</b></div>
<div class="tiles">{tiles}</div>
<h2>{'Flagged sessions' if observe_mode else 'Trapped sessions'}</h2><div class="wrap"><table><tr><th>Session</th><th>User-agent</th><th>Score</th><th>Why diverted</th>
<th>Diverted</th><th>Time in decoy</th><th>Requests / paths</th><th>Techniques</th></tr>{rows}</table></div>
<h2>Techniques observed</h2><div>{techs}</div>
<h2>Planted canary hits</h2><div class="wrap"><table><tr><th>When</th><th>Canary</th><th>Session</th><th>Request</th></tr>{hrow}</table></div>
<h2>Planted canaries</h2>
<form method="post" action="/canaries"><select name="kind">{opts}</select><input name="label" placeholder="Label (e.g. CI deploy key)">
<input name="placement" placeholder="Where you'll plant it (e.g. repo .env.example)"><button>Generate canary</button></form>
<div class="wrap"><table><tr><th>ID</th><th>Kind</th><th>Label</th><th>Placement</th><th>Token</th><th>Hits</th></tr>{crow}</table></div>""")

    @app.post("/canaries")
    def form_create(request: Request, kind: str = Form(...), label: str = Form(""), placement: str = Form("")):
        auth(request)
        c = create_canary(db, kind, label or None, placement or None, company=settings.company_name)
        return page("Canary created", f"""<h1>Canary created</h1><div class="sub">Plant this exactly as shown. Any use triggers an alert.</div>
<div class="wrap" style="padding:14px"><pre class="mono">{html.escape(c['display'])}</pre></div><p><a href="/">Back to dashboard</a></p>""",
                    refresh=False)

    @app.get("/sessions/{sid}", response_class=HTMLResponse)
    def session_page(request: Request, sid: str):
        auth(request)
        s = db.get_session(sid)
        if not s:
            raise HTTPException(404)
        evs = db.all("SELECT * FROM events WHERE session_id=? ORDER BY ts", (sid,))
        t0 = evs[0]["ts"] if evs else 0
        rows = "".join(f"""<tr><td>+{e['ts']-t0:.1f}s</td><td class="{'decoy' if e['route'].startswith('decoy') else 'upstream'}">{e['route']}</td>
            <td class="mono">{e['method']} {html.escape(e['path'])}{('?' + html.escape(e['query'])) if e['query'] else ''}</td>
            <td>{e['status']}</td><td>{e['score']}</td>
            <td>{''.join(f'<span class="tag">{html.escape(x)}</span>' for x in json.loads(e['techniques'] or '[]'))}</td>
            <td><pre class="mono">{html.escape(e['response_snippet'] or '')}</pre></td></tr>""" for e in evs)
        return page(f"Session {sid}", f"""<p><a href="/">← Dashboard</a></p><h1 class="mono">Session {sid}</h1>
<div class="sub">{html.escape(s['client'] or '')} · <span class="mono">{html.escape(s['user_agent'] or '')}</span> · score {s['score']} ·
{'diverted' if s['diverted'] else 'not diverted'} · {len(evs)} requests</div>
<div>{''.join(f'<span class="tag">{html.escape(r)}</span>' for r in s['reasons'])}</div>
<h2>Playbook timeline</h2><div class="wrap"><table><tr><th>T</th><th>Route</th><th>Request</th><th>Status</th><th>Score</th><th>Techniques</th><th>Response (start)</th></tr>{rows}</table></div>""")

    return app


if __name__ == "__main__":
    import os

    import uvicorn

    logging.basicConfig(level=logging.INFO)
    s = Settings()
    uvicorn.run(create_admin_app(s), host=s.admin_host, port=s.admin_port)
