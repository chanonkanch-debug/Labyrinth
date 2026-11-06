"""The proxy must be invisible to legitimate traffic: same cookies, headers, redirects, bytes."""
import gzip

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.testclient import TestClient

from labyrinth.canary import create_canary
from labyrinth.config import Settings
from labyrinth.db import DB
from labyrinth.proxy import create_app

echo = FastAPI()


@echo.api_route("/echo", methods=["GET", "POST"])
async def _echo(request: Request):
    return {"headers": [[k, v] for k, v in request.headers.items()], "raw_path": request.scope["raw_path"].decode(),
            "query": request.scope["query_string"].decode(), "body_len": len(await request.body())}


@echo.get("/cookies")
def _cookies():
    r = JSONResponse({"ok": True})
    r.set_cookie("session", "abc", httponly=True)
    r.set_cookie("csrftoken", "xyz", samesite="lax")
    r.headers.append("x-multi", "1")
    r.headers.append("x-multi", "2")
    return r


@echo.get("/gz")
def _gz():
    return Response(gzip.compress(b"hello " * 100), headers={"content-encoding": "gzip"}, media_type="text/plain")


@echo.get("/redir")
def _redir():
    return RedirectResponse("/echo?from=redir", status_code=302)


@pytest.fixture
def make(tmp_path):
    def _make(**overrides):
        s = Settings(db_path=str(tmp_path / "t.db"), tarpit_ms=0, upstream="http://upstream.internal:9000")
        s.llm_enabled = False
        for k, v in overrides.items():
            setattr(s, k, v)
        db = DB(s.db_path)
        return TestClient(create_app(s, db, upstream_transport=httpx.ASGITransport(app=echo)),
                          base_url="http://shop.example.com"), db
    return _make


def test_multiple_set_cookie_headers_survive(make):
    c, _ = make()
    r = c.get("/cookies")
    cookies = r.headers.get_list("set-cookie")
    assert len(cookies) == 2 and any("session=abc" in x for x in cookies) and any("csrftoken=xyz" in x for x in cookies)
    assert r.headers.get_list("x-multi") == ["1", "2"]


def test_host_preserved_and_forwarded_headers_set(make):
    c, _ = make()
    h = dict(c.get("/echo").json()["headers"])
    assert h["host"] == "shop.example.com"
    assert h["x-forwarded-host"] == "shop.example.com"
    assert h["x-forwarded-proto"] == "http"
    assert h["x-forwarded-for"] == "testclient"


def test_host_rewrite_when_disabled(make):
    c, _ = make(preserve_host=False)
    h = dict(c.get("/echo").json()["headers"])
    assert h["host"] == "upstream.internal:9000"


def test_spoofed_forwarded_for_is_replaced_unless_trusted(make):
    c, _ = make()
    h = dict(c.get("/echo", headers={"x-forwarded-for": "6.6.6.6"}).json()["headers"])
    assert h["x-forwarded-for"] == "testclient"


def test_raw_path_and_query_not_reencoded(make):
    c, _ = make()
    j = c.get("/echo?q=a+b&x=%2F%20&y=1&y=2").json()
    assert j["query"] == "q=a+b&x=%2F%20&y=1&y=2"


def test_duplicate_request_headers_forwarded(make):
    c, _ = make()
    h = c.get("/echo", headers=[("x-dup", "1"), ("x-dup", "2")]).json()["headers"]
    assert [v for k, v in h if k == "x-dup"] in (["1", "2"], ["1, 2"])


def test_gzip_passed_through_untouched(make):
    c, _ = make()
    r = c.get("/gz")
    assert r.headers["content-encoding"] == "gzip" and r.text == "hello " * 100


def test_redirect_not_followed(make):
    c, _ = make()
    r = c.get("/redir", follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == "/echo?from=redir"


def test_large_body_forwarded_whole_and_canary_found_deep_inside(make):
    c, db = make()
    big = b"x" * (5 * 1024 * 1024)
    assert c.post("/echo", content=big).json()["body_len"] == len(big)
    tok = create_canary(db, "api_key")["token"]
    c.post("/echo", content=b"y" * 100_000 + tok.encode(), headers={"user-agent": "deep"})
    assert db.one("SELECT diverted FROM sessions WHERE user_agent='deep'")["diverted"] == 1


def test_observe_mode_flags_but_never_diverts(make):
    c, db = make(mode="observe")
    tok = create_canary(db, "api_key")["token"]
    r = c.get("/echo", headers={"authorization": f"Bearer {tok}", "user-agent": "agent"})
    assert "headers" in r.json()                         # real upstream answered
    assert db.one("SELECT diverted FROM sessions WHERE user_agent='agent'")["diverted"] == 1   # but flagged
    assert db.one("SELECT COUNT(*) n FROM canary_hits")["n"] == 1                               # and alerted
    assert {e["route"] for e in db.all("SELECT route FROM events")} == {"flagged"}


@echo.get("/api/thing")
def _thing():
    return {"real": True}


@echo.get("/{rest:path}")
def _fallback(rest: str):
    return JSONResponse({"detail": f"No page at /{rest}"}, status_code=404, headers={"x-powered-by": "EchoFramework"})


def test_decoy_replays_what_session_saw_and_mirrors_real_404(make):
    c, db = make()
    ua = {"user-agent": "attacker-x"}
    seen = c.get("/api/thing", headers=ua).json()
    c.get("/nope-123", headers={"user-agent": "someone-else"})   # proxy learns the real 404 page + headers
    tok = create_canary(db, "api_key")["token"]
    c.get("/api/other", headers={**ua, "authorization": f"Bearer {tok}"})        # now diverted
    assert c.get("/api/thing", headers=ua).json() == seen                     # same answer as before diversion
    r = c.get("/totally-random-word", headers=ua)
    assert r.status_code == 404 and r.json() == {"detail": "No page at /totally-random-word"}
    assert r.headers["x-powered-by"] == "EchoFramework" and "server" not in r.headers
    assert db.one("SELECT route FROM events ORDER BY id DESC LIMIT 1")["route"] == "decoy:mirrored-404"
