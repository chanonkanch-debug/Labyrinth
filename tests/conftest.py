import httpx
import pytest
from fastapi.testclient import TestClient

from harness.sample_api import app as real_api
from labyrinth.admin import create_admin_app
from labyrinth.config import Settings
from labyrinth.db import DB
from labyrinth.proxy import create_app

LEGIT_UA = "Mozilla/5.0 (Macintosh) Safari/605.1.15"
AGENT_UA = "Mozilla/5.0 (X11; Linux x86_64) Chrome/131.0"


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("LABYRINTH_LLM", "off")
    settings = Settings(db_path=str(tmp_path / "t.db"), tarpit_ms=0, upstream="http://real")
    settings.llm_enabled = False
    db = DB(settings.db_path)
    proxy = create_app(settings, db, upstream_transport=httpx.ASGITransport(app=real_api))
    with TestClient(proxy) as pc:
        yield {"settings": settings, "db": db, "proxy": pc, "admin": TestClient(create_admin_app(settings, db))}
