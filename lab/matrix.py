"""Labyrinth framework lab: run the same checks against every framework, direct vs. through Labyrinth.

    python lab/matrix.py                      # all targets in lab/targets.json
    python lab/matrix.py --only django,rails  # a subset
    python lab/matrix.py --quick              # skip the slow human-paced browsing check

Three groups of checks:
  transparency  legit traffic through the proxy behaves exactly like direct traffic
  safety        normal users, browsers and API clients are never diverted
  detection     attackers are diverted, and how a diverted attacker could tell (decoy "tells")
Writes lab/results/results.json and lab/results/REPORT.md.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import random
import re
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import httpx

HERE = Path(__file__).parent
CHROME = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"
SCANNER_PATHS = ["/", "/robots.txt", "/.env", "/.git/config", "/admin", "/api", "/api/v1", "/api/users", "/api/users/1",
                 "/api/admin", "/backup.zip", "/config.json", "/debug", "/actuator/env", "/phpinfo.php",
                 "/wp-login.php", "/server-status", "/api/items/1'%20OR%201=1--", "/api/keys", "/internal"]
CSRF_FIELDS = re.compile(r'name="(csrfmiddlewaretoken|authenticity_token|_token|__RequestVerificationToken)"\s+value="([^"]+)"')
DROP_HEADERS = {"date", "content-length", "transfer-encoding", "connection", "keep-alive", "set-cookie", "etag",
                "x-request-id", "x-runtime", "last-modified", "vary"}


@dataclass
class Target:
    name: str
    direct: str
    proxy: str
    admin: str
    admin_token: str = "lab"
    websocket: bool = True
    csrf: bool = False


@dataclass
class Result:
    group: str
    check: str
    status: str  # pass | fail | warn | n/a
    detail: str = ""


@dataclass
class Report:
    target: str
    results: list[Result] = field(default_factory=list)
    metrics: dict = field(default_factory=dict)

    def add(self, group, check, status, detail=""):
        self.results.append(Result(group, check, status, detail))


def ua(tag: str) -> str:
    return f"{CHROME} lab/{tag}/{uuid.uuid4().hex[:6]}"


def client(base: str, tag: str, **kw) -> httpx.Client:
    return httpx.Client(base_url=base, headers={"user-agent": ua(tag)}, timeout=20, follow_redirects=False, **kw)


def summary(t: Target) -> dict:
    return httpx.get(f"{t.admin}/api/summary", headers={"x-admin-token": t.admin_token}, timeout=10).json()


def flagged_uas(t: Target) -> set[str]:
    return {s["user_agent"] for s in summary(t)["trapped"]}


def shape(text: str) -> str:
    """A page's shape with volatile parts (timestamps, ids, numbers) removed."""
    try:
        o = json.loads(text)
        return json.dumps(sorted(o)) if isinstance(o, dict) else type(o).__name__
    except ValueError:
        return re.sub(r"[A-Za-z0-9_-]{20,}|[0-9a-f]{8,}|\d+", "#", text)  # incl. per-request nonces


def headers_of(r: httpx.Response) -> set[str]:
    return {k.lower() for k in r.headers if k.lower() not in DROP_HEADERS}


# ------------------------------------------------------------------ transparency
def login(c: httpx.Client, base: str) -> httpx.Response:
    form = c.get("/login")
    data = {"username": "alice", "password": "wonderland"}
    m = CSRF_FIELDS.search(form.text)
    if m:
        data[m.group(1)] = m.group(2)
    return c.post("/login", data=data, headers={"origin": base, "referer": f"{base}/login"})


def transparency(t: Target, rep: Report) -> None:
    g = "transparency"
    d, p = client(t.direct, "t-direct"), client(t.proxy, "t-proxy")

    for path in ["/api/health", "/api/items", "/api/items/1", "/api/items/999"]:
        a, b = d.get(path), p.get(path)
        ok = a.status_code == b.status_code and a.content == b.content
        rep.add(g, f"GET {path}", "pass" if ok else "fail", "" if ok else f"direct {a.status_code}, proxy {b.status_code}")

    a, b = d.head("/api/health"), p.head("/api/health")
    # after a HEAD, the same connections must still work (gunicorn sends a body on HEAD)
    after = [p.get("/api/items/1").status_code for _ in range(3)]
    rep.add(g, "Requests after HEAD still work", "pass" if after == [200, 200, 200] else "fail", str(after))
    d = client(t.direct, "t-direct")
    rep.add(g, "HEAD request", "pass" if a.status_code == b.status_code else "fail", f"{a.status_code} vs {b.status_code}")

    a, b = d.post("/api/items", json={"name": "Thing"}), p.post("/api/items", json={"name": "Thing"})
    rep.add(g, "POST JSON", "pass" if (a.status_code, a.json()) == (b.status_code, b.json()) else "fail",
            f"{a.status_code} vs {b.status_code}")

    extra_direct, extra_proxy = headers_of(d.get("/api/health")) - headers_of(p.get("/api/health")), \
        headers_of(p.get("/api/health")) - headers_of(d.get("/api/health"))
    rep.add(g, "Response headers match", "pass" if not (extra_direct or extra_proxy) else "fail",
            f"lost {sorted(extra_direct)} added {sorted(extra_proxy)}" if (extra_direct or extra_proxy) else "")

    a, b = d.get("/api/items", headers={"accept-encoding": "gzip"}), p.get("/api/items", headers={"accept-encoding": "gzip"})
    rep.add(g, "Compression preserved", "pass" if a.headers.get("content-encoding") == b.headers.get("content-encoding") else "fail",
            f"direct {a.headers.get('content-encoding')}, proxy {b.headers.get('content-encoding')}")

    # Login with the framework's own CSRF + cookie session
    dl, pl = client(t.direct, "login-direct"), client(t.proxy, "login-proxy")
    a, b = login(dl, t.direct), login(pl, t.proxy)
    ok = b.status_code == 302 and b.headers.get("location", "").endswith("/dashboard")
    rep.add(g, "Login (CSRF + session cookie)", "pass" if ok else "fail", f"proxy {b.status_code} {b.headers.get('location', '')}")
    ca, cb = len(a.headers.get_list("set-cookie")), len(b.headers.get_list("set-cookie"))
    rep.add(g, "All Set-Cookie headers kept", "pass" if ca == cb and cb >= 2 else "fail", f"direct {ca}, proxy {cb}")
    dash = pl.get("/dashboard")
    rep.add(g, "Session works after login", "pass" if dash.status_code == 200 and "Welcome alice" in dash.text else "fail",
            f"{dash.status_code}")
    co = pl.post("/checkout")
    rep.add(g, "Checkout with session", "pass" if co.status_code == 200 else "fail", f"{co.status_code}")

    if t.csrf:
        a = client(t.direct, "csrf-d").post("/login", data={"username": "alice", "password": "wonderland"})
        b = client(t.proxy, "csrf-p").post("/login", data={"username": "alice", "password": "wonderland"})
        rep.add(g, "CSRF still enforced", "pass" if a.status_code == b.status_code and b.status_code >= 400 else "fail",
                f"direct {a.status_code}, proxy {b.status_code}")
    else:
        rep.add(g, "CSRF still enforced", "n/a", "no CSRF in this app")

    blob = random.randbytes(5 * 1024 * 1024)
    a = d.post("/upload", files={"file": ("big.bin", blob)})
    b = p.post("/upload", files={"file": ("big.bin", blob)})
    rep.add(g, "5 MB multipart upload", "pass" if b.status_code == 200 and b.json().get("size") == len(blob) else
            ("warn" if a.text == b.text else "fail"),
            f"direct {a.status_code} proxy {b.status_code} {b.text[:80]}")

    a, b = d.get("/redirect"), p.get("/redirect")
    la, lb = a.headers.get("location", ""), b.headers.get("location", "")
    host_ok = (not lb.startswith("http")) or lb.startswith(t.proxy)
    rep.add(g, "Redirect Location", "pass" if b.status_code == a.status_code and host_ok else "fail", f"direct {la!r}, proxy {lb!r}")

    # Streaming (SSE): the first event must arrive before the stream ends.
    t0 = time.time()
    first, events = None, 0
    with httpx.stream("GET", f"{t.proxy}/stream", headers={"user-agent": ua("sse")}, timeout=20) as r:
        for line in r.iter_lines():
            if line.startswith("data:"):
                events += 1
                first = first or time.time() - t0
    ok = events == 3 and first is not None and first < 0.6
    rep.add(g, "Server-sent events stream live", "pass" if ok else "fail",
            f"{events} events, first after {first:.2f}s" if first is not None else "no events")

    if t.websocket:
        from websockets.sync.client import connect
        try:
            ws_url = t.proxy.replace("http", "ws", 1) + "/ws"
            with connect(ws_url, user_agent_header=ua("ws"), open_timeout=10) as ws:
                ws.send("ping")
                reply = ws.recv(timeout=5)
            rep.add(g, "WebSocket echo", "pass" if reply == "echo:ping" else "fail", repr(reply))
        except Exception as exc:  # noqa: BLE001
            rep.add(g, "WebSocket echo", "fail", str(exc)[:120])
    else:
        rep.add(g, "WebSocket echo", "n/a", "app has no websocket endpoint")


# ------------------------------------------------------------------ safety (false positives)
def safety(t: Target, rep: Report, quick: bool) -> None:
    g = "safety"
    uas = {}

    # 1. A person: logs in, browses with human pauses, checks out.
    if not quick:
        c = client(t.proxy, "human")
        uas["Human browsing session"] = c.headers["user-agent"]
        login(c, t.proxy)
        for path in ["/dashboard", "/api/items", "/api/items/1", "/api/items/2", "/dashboard", "/api/items", "/redirect",
                     "/api/items/999", "/dashboard", "/api/health", "/api/items/1"]:
            time.sleep(random.uniform(0.4, 2.5))
            c.get(path)
        c.post("/checkout")

    # 2. A browser page load: the page, then a burst of parallel asset requests (incl. 404s like favicon).
    c = client(t.proxy, "burst", limits=httpx.Limits(max_connections=8))
    uas["Browser page-load burst (25 parallel requests)"] = c.headers["user-agent"]
    home = c.get("/")
    assets = re.findall(r'(?:src|href)="(/[^"]+)"', home.text)[:20]
    paths = assets + ["/favicon.ico", "/apple-touch-icon.png", "/api/items", "/api/health", "/manifest.json"]
    paths += [f"/api/items/{i}" for i in range(1, 25 - len(paths) + 1)] if len(paths) < 25 else []
    with cf.ThreadPoolExecutor(8) as ex:
        list(ex.map(c.get, paths[:25]))

    # 3. An API integration polling on a fixed timer (machine-regular timing, by design).
    c = client(t.proxy, "poller")
    uas["API client polling every 1s"] = c.headers["user-agent"]
    for _ in range(12):
        c.get("/api/items")
        time.sleep(1.0)

    # 4. A user who mistypes a few URLs.
    c = client(t.proxy, "typos")
    uas["User hitting a few 404s"] = c.headers["user-agent"]
    for path in ["/dashbord", "/api/item", "/api/items/7", "/login", "/api/items/1"]:
        c.get(path)
        time.sleep(random.uniform(0.5, 1.5))

    flagged = flagged_uas(t)
    for label, u in uas.items():
        rep.add(g, label, "fail" if u in flagged else "pass", "diverted!" if u in flagged else "not diverted")


# ------------------------------------------------------------------ detection + decoy tells
def detection(t: Target, rep: Report) -> None:
    g = "detection"
    # Real responses first, to compare against what the attacker sees later.
    real = client(t.direct, "ref")
    real_health, real_404 = real.get("/api/health"), real.get("/no-such-page-xyz")

    c = client(t.proxy, "scanner")
    sid_ua = c.headers["user-agent"]
    pre_health, pre_items = c.get("/api/health"), c.get("/api/items")  # real data, seen before it is caught
    n_to_divert = None
    for i, path in enumerate(SCANNER_PATHS, 1):
        c.get(path)
        time.sleep(0.15)
        if n_to_divert is None and sid_ua in flagged_uas(t):
            n_to_divert = i
    rep.metrics["requests_until_diverted"] = n_to_divert
    rep.add(g, "Scanner diverted by behaviour", "pass" if n_to_divert else "fail",
            f"after {n_to_divert} requests" if n_to_divert else "never diverted")

    if n_to_divert:
        # Tells: what a careful agent could notice once inside the decoy.
        h, items, nf = c.get("/api/health"), c.get("/api/items"), c.get("/no-such-page-xyz")
        tells = []
        if items.text != pre_items.text:
            tells.append("same URL returned different data after diversion (/api/items)")
        if h.text != pre_health.text:
            tells.append("same URL returned different data after diversion (/api/health)")
        if nf.status_code != real_404.status_code or nf.headers.get("content-type", "").split(";")[0] != \
                real_404.headers.get("content-type", "").split(";")[0] or shape(nf.text) != shape(real_404.text):
            tells.append(f"404 page differs (real {real_404.status_code} {real_404.headers.get('content-type', '')}, "
                         f"decoy {nf.status_code} {nf.headers.get('content-type', '')})")
        real_sig = {k: real_health.headers.get(k) for k in ("server", "x-powered-by")}
        decoy_sig = {k: h.headers.get(k) for k in ("server", "x-powered-by")}
        if real_sig != decoy_sig:
            tells.append(f"server headers differ (real {real_sig}, decoy {decoy_sig})")
        rep.metrics["decoy_tells"] = tells
        rep.add(g, "Decoy indistinguishable from real app", "pass" if not tells else "warn",
                "; ".join(tells) if tells else "no tells found")

        # Protected routes still reach the real app even for a diverted session.
        r = login(c, t.proxy)
        rep.add(g, "Login still reaches real app when diverted", "pass" if r.status_code == 302 else "fail", f"{r.status_code}")

    # Canary use: diverted on the first request.
    canary = httpx.post(f"{t.admin}/api/canaries", headers={"x-admin-token": t.admin_token},
                        json={"kind": "api_key", "label": "lab", "placement": "lab"}).json()["token"]
    c = client(t.proxy, "canary")
    c.get("/api/items", headers={"authorization": f"Bearer {canary}"})
    ok = c.headers["user-agent"] in flagged_uas(t)
    rep.add(g, "Canary key diverts on first request", "pass" if ok else "fail")


# ------------------------------------------------------------------ main
def run_target(t: Target, quick: bool) -> Report:
    rep = Report(t.name)
    try:
        httpx.get(f"{t.direct}/api/health", timeout=5).raise_for_status()
        httpx.get(f"{t.proxy}/api/health", timeout=5).raise_for_status()
    except Exception as exc:  # noqa: BLE001
        rep.add("setup", "Target reachable", "fail", str(exc)[:160])
        return rep
    for fn in (lambda: transparency(t, rep), lambda: safety(t, rep, quick), lambda: detection(t, rep)):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            rep.add("error", fn.__name__, "fail", f"{type(exc).__name__}: {exc}"[:200])
    return rep


def write_report(reports: list[Report], out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_text(json.dumps(
        [{"target": r.target, "metrics": r.metrics, "results": [vars(x) for x in r.results]} for r in reports], indent=2))
    icon = {"pass": "✅", "fail": "❌", "warn": "⚠️", "n/a": "–"}
    checks = []
    for r in reports:
        for x in r.results:
            if (x.group, x.check) not in checks:
                checks.append((x.group, x.check))
    lines = ["# Labyrinth framework lab results", "", f"Run at {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}.", "",
             "| Check | " + " | ".join(r.target for r in reports) + " |",
             "| --- | " + " | ".join("---" for _ in reports) + " |"]
    for grp, chk in checks:
        cells = []
        for r in reports:
            x = next((y for y in r.results if (y.group, y.check) == (grp, chk)), None)
            cells.append(icon[x.status] if x else "")
        lines.append(f"| {grp}: {chk} | " + " | ".join(cells) + " |")
    lines += ["", "| Metric | " + " | ".join(r.target for r in reports) + " |", "| --- | " + " | ".join("---" for _ in reports) + " |",
              "| Requests until scanner diverted | " + " | ".join(str(r.metrics.get("requests_until_diverted", "")) for r in reports) + " |"]
    lines += ["", "## Details (everything that is not a pass)", ""]
    for r in reports:
        bad = [x for x in r.results if x.status in ("fail", "warn")]
        if bad:
            lines.append(f"**{r.target}**")
            lines += [f"- {icon[x.status]} {x.group}: {x.check}: {x.detail}" for x in bad]
            lines.append("")
    (out / "REPORT.md").write_text("\n".join(lines) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--targets", default=str(HERE / "targets.json"))
    ap.add_argument("--only", default="")
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--out", default=str(HERE / "results"))
    a = ap.parse_args()
    targets = [Target(**x) for x in json.loads(Path(a.targets).read_text())]
    if a.only:
        targets = [t for t in targets if t.name in a.only.split(",")]
    with cf.ThreadPoolExecutor(len(targets)) as ex:
        reports = list(ex.map(lambda t: run_target(t, a.quick), targets))
    write_report(reports, Path(a.out))
    fails = sum(1 for r in reports for x in r.results if x.status == "fail")
    print((Path(a.out) / "REPORT.md").read_text())
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
