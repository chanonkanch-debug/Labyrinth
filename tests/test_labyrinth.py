import json

from labyrinth.canary import create_canary, make_token
from labyrinth.scoring import SessionState, observe, score

from .conftest import AGENT_UA, LEGIT_UA


def session_rows(db):
    return {r["user_agent"]: r for r in db.all("SELECT * FROM sessions")}


def test_legit_user_passes_through_untouched(env):
    c = env["proxy"]
    tok = c.post("/login", json={"email": "a@b.c", "password": "correct-horse"}, headers={"user-agent": LEGIT_UA}).json()["token"]
    for p in ["/users/me", "/projects", "/projects/1"]:
        r = c.get(p, headers={"user-agent": LEGIT_UA, "authorization": f"Bearer {tok}"})
        assert r.status_code == 200
    assert c.get("/users/me", headers={"user-agent": LEGIT_UA, "authorization": f"Bearer {tok}"}).json()["id"] == 42
    s = session_rows(env["db"])[LEGIT_UA]
    assert s["diverted"] == 0
    routes = {e["route"] for e in env["db"].all("SELECT route FROM events")}
    assert routes == {"upstream"}


def test_canary_use_diverts_and_alerts(env):
    canary = create_canary(env["db"], "api_key", label="leaked")
    r = env["proxy"].get("/projects", headers={"user-agent": AGENT_UA, "authorization": f"Bearer {canary['token']}"})
    assert r.status_code == 200 and "data" in r.json()          # real API would have said 401
    s = session_rows(env["db"])[AGENT_UA]
    assert s["diverted"] == 1 and s["score"] == 100
    assert env["db"].one("SELECT COUNT(*) n FROM canary_hits")["n"] == 1
    # sticky: later requests without the key still go to the decoy
    env["proxy"].get("/users/me", headers={"user-agent": AGENT_UA})
    last = env["db"].all("SELECT route FROM events ORDER BY id DESC LIMIT 1")[0]
    assert last["route"].startswith("decoy")


def test_canary_in_body_or_query_detected(env):
    canary = create_canary(env["db"], "aws_key")
    env["proxy"].post("/projects", json={"key": canary["token"]}, headers={"user-agent": "ua-body"})
    env["proxy"].get(f"/projects?api_key={create_canary(env['db'], 'github_token')['token']}", headers={"user-agent": "ua-q"})
    rows = session_rows(env["db"])
    assert rows["ua-body"]["diverted"] == 1 and rows["ua-q"]["diverted"] == 1


def test_protected_routes_never_diverted(env):
    canary = create_canary(env["db"], "api_key")
    h = {"user-agent": AGENT_UA, "authorization": f"Bearer {canary['token']}"}
    env["proxy"].get("/projects", headers=h)  # diverted now
    r = env["proxy"].post("/login", json={"email": "x", "password": "correct-horse"}, headers=h)
    assert r.json() == {"token": "real-user-token"}  # came from the real API
    r = env["proxy"].post("/checkout", headers={"user-agent": AGENT_UA, "authorization": "Bearer real-user-token"})
    assert r.json() == {"ok": True, "order_id": 1001}
    ev = env["db"].all("SELECT path, route FROM events WHERE path IN ('/login','/checkout')")
    assert {e["route"] for e in ev} == {"protected"}


def test_decoy_is_consistent_per_session(env):
    canary = create_canary(env["db"], "api_key")
    h = {"user-agent": AGENT_UA, "authorization": f"Bearer {canary['token']}"}
    a = env["proxy"].get("/admin/exports", headers=h).text
    b = env["proxy"].get("/admin/exports", headers=h).text
    assert a == b
    users = env["proxy"].get("/users", headers=h).json()["data"]
    u3 = env["proxy"].get("/users/3", headers=h).json()
    assert users[2]["email"] == u3["email"]


def test_different_sessions_get_different_worlds(env):
    for ua in ("agent-1", "agent-2"):
        env["proxy"].get("/projects", headers={"user-agent": ua, "authorization": f"Bearer {create_canary(env['db'], 'api_key')['token']}"})
    one = env["proxy"].get("/users/3", headers={"user-agent": "agent-1"}).json()
    two = env["proxy"].get("/users/3", headers={"user-agent": "agent-2"}).json()
    assert one["email"] != two["email"] or one["created_at"] != two["created_at"]


def test_secrets_in_decoy_are_session_bound_canaries(env):
    canary = create_canary(env["db"], "api_key")
    h = {"user-agent": AGENT_UA, "authorization": f"Bearer {canary['token']}"}
    text = env["proxy"].get("/.env", headers=h).text
    issued = env["db"].all("SELECT token, session_id FROM canaries WHERE origin='decoy'")
    assert issued and all(t["token"] in text for t in issued)
    sid = session_rows(env["db"])[AGENT_UA]["id"]
    assert {t["session_id"] for t in issued} == {sid}


def test_behavioural_detection_diverts_scanner(env):
    h = {"user-agent": AGENT_UA}
    for p in ["/.env", "/.git/config", "/users?id=1' OR 1=1--"]:
        env["proxy"].get(p, headers=h)
    s = session_rows(env["db"])[AGENT_UA]
    assert s["diverted"] == 1
    assert "sql_injection" in json.loads(s["techniques"])


def test_fail_open_when_scoring_breaks(env, monkeypatch):
    import labyrinth.proxy as proxy_mod

    def boom(*a, **k):
        raise RuntimeError("scoring down")
    monkeypatch.setattr(proxy_mod, "observe", boom)
    r = env["proxy"].get("/health", headers={"user-agent": AGENT_UA})
    assert r.status_code == 200 and r.json() == {"ok": True}


def test_scoring_ignores_human_paced_browsing():
    s = SessionState(id="x", client="c", user_agent=LEGIT_UA)
    t = 1000.0
    for i, p in enumerate(["/", "/projects", "/projects/1", "/users/me", "/projects/2", "/projects", "/users/me", "/projects/1", "/"]):
        t += [1.1, 4.0, 2.3, 7.9, 0.8, 3.2, 12.0, 1.7, 5.5][i]
        observe(s, "GET", p, "", "", t)
        s.statuses.append(200)
    assert score(s, t)[0] < 30


def test_canary_formats():
    assert make_token("aws_key")["token"].startswith("AKIA")
    assert make_token("api_key")["token"].startswith("sk_live_")
    assert "postgres://" in make_token("db_url")["display"]


def test_admin_api_and_dashboard(env):
    a = env["admin"]
    c = a.post("/api/canaries", json={"kind": "stripe_key", "label": "billing", "placement": "wiki"}).json()
    assert c["token"].startswith("rk_live_")
    env["proxy"].get("/projects", headers={"user-agent": AGENT_UA, "authorization": f"Bearer {c['token']}"})
    s = a.get("/api/summary").json()
    assert s["sessions_trapped"] == 1 and s["canary_hits"] == 1
    page = a.get("/").text
    assert "Trapped sessions" in page and s["trapped"][0]["id"] in page
    assert a.get(f"/sessions/{s['trapped'][0]['id']}").status_code == 200


def test_admin_token_enforced(env):
    from fastapi.testclient import TestClient

    from labyrinth.admin import create_admin_app
    env["settings"].admin_token = "s3cret"
    a = TestClient(create_admin_app(env["settings"], env["db"]))
    assert a.get("/api/summary").status_code == 401
    assert a.get("/api/summary", headers={"x-admin-token": "s3cret"}).status_code == 200


def test_llm_generator_mints_canaries_and_falls_back(env):
    import asyncio
    from types import SimpleNamespace

    from labyrinth.decoy import DecoyService, LLMWorld
    from labyrinth.scoring import SessionState

    class FakeMessages:
        def __init__(self, text=None, fail=False):
            self.text, self.fail = text, fail

        async def create(self, **kw):
            assert "real.user@example.com" not in json.dumps(kw)  # generator never sees production data
            if self.fail:
                raise RuntimeError("api down")
            return SimpleNamespace(content=[SimpleNamespace(type="text", text=self.text)])

    svc = DecoyService(env["db"], env["settings"])
    llm = LLMWorld.__new__(LLMWorld)
    llm.db, llm.s = env["db"], env["settings"]
    llm.client = SimpleNamespace(messages=FakeMessages(json.dumps(
        {"status": 200, "content_type": "application/json", "body": {"deploy_key": "{{CANARY:github_token}}", "links": ["/internal/keys"]}})))
    svc.llm = llm
    sess = SessionState(id="s1", client="c", user_agent="u")
    status, ctype, body, gen = asyncio.run(svc.respond(sess, "GET", "/internal/deploy", "", "", []))
    assert gen == "llm" and "{{CANARY" not in body and "ghp_" in body
    tok = env["db"].one("SELECT token FROM canaries WHERE origin='decoy' AND session_id='s1'")["token"]
    assert tok in body
    # cached on revisit
    assert asyncio.run(svc.respond(sess, "GET", "/internal/deploy", "", "", []))[3] == "cache"
    # LLM failure falls back to the template generator
    llm.client = SimpleNamespace(messages=FakeMessages(fail=True))
    assert asyncio.run(svc.respond(sess, "GET", "/users/9", "", "", []))[3] == "template"
