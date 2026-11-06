"""Canary credentials: realistic-looking fake secrets. Any use is a high-confidence alarm."""
from __future__ import annotations

import random
import secrets
import string
import time
from typing import Any

from .alerts import alert
from .config import Settings
from .db import DB

KINDS = ("api_key", "aws_key", "db_url", "github_token", "stripe_key", "jwt_secret")

_ALNUM = string.ascii_letters + string.digits
_UPPER = string.ascii_uppercase + string.digits


def _rand(rng: random.Random | None, alphabet: str, n: int) -> str:
    if rng is None:
        return "".join(secrets.choice(alphabet) for _ in range(n))
    return "".join(rng.choice(alphabet) for _ in range(n))


def make_token(kind: str, company: str = "acme", rng: random.Random | None = None) -> dict[str, str]:
    """Return {'token': <value matched in traffic>, 'display': <how it is planted>}."""
    if kind == "api_key":
        tok = f"sk_live_{_rand(rng, _ALNUM, 32)}"
        return {"token": tok, "display": f"{company.upper()}_API_KEY={tok}"}
    if kind == "aws_key":
        key_id = "AKIA" + _rand(rng, _UPPER, 16)
        secret = _rand(rng, _ALNUM + "/+", 40)
        return {"token": key_id, "display": f"aws_access_key_id = {key_id}\naws_secret_access_key = {secret}"}
    if kind == "db_url":
        pw = _rand(rng, _ALNUM, 20)
        tok = f"postgres://{company}_admin:{pw}@db-prod-{_rand(rng, string.digits, 2)}.internal.{company}.io:5432/{company}_prod"
        return {"token": pw, "display": f"DATABASE_URL={tok}"}
    if kind == "github_token":
        tok = "ghp_" + _rand(rng, _ALNUM, 36)
        return {"token": tok, "display": f"GITHUB_TOKEN={tok}"}
    if kind == "stripe_key":
        tok = "rk_live_" + _rand(rng, _ALNUM, 24)
        return {"token": tok, "display": f"STRIPE_SECRET_KEY={tok}"}
    if kind == "jwt_secret":
        tok = "eyJhbGciOiJIUzI1NiJ9." + _rand(rng, _ALNUM, 40)
        return {"token": tok, "display": f"Authorization: Bearer {tok}"}
    raise ValueError(f"unknown canary kind {kind!r}; choose from {KINDS}")


def create_canary(db: DB, kind: str, label: str | None = None, placement: str | None = None,
                  company: str = "acme", origin: str = "planted", session_id: str | None = None,
                  rng: random.Random | None = None) -> dict[str, Any]:
    t = make_token(kind, company, rng)
    cid = db.add_canary(t["token"], kind, label, placement, origin, session_id)
    return {"id": cid, "kind": kind, "label": label, "placement": placement, **t}


class CanaryMatcher:
    """Finds canary tokens in request material. Reloads from DB so new canaries apply immediately."""

    def __init__(self, db: DB):
        self.db = db

    def find(self, *haystacks: str) -> list[int]:
        text = "\n".join(h for h in haystacks if h)
        if not text:
            return []
        return [cid for tok, cid in self.db.canary_tokens().items() if tok in text]


def record_hits(db: DB, settings: Settings, canary_ids: list[int], session_id: str, method: str,
                path: str, client: str, user_agent: str) -> None:
    now = time.time()
    for cid in canary_ids:
        db.execute(
            "INSERT INTO canary_hits(canary_id, session_id, ts, method, path, client, user_agent) VALUES (?,?,?,?,?,?,?)",
            (cid, session_id, now, method, path, client, user_agent),
        )
        prior = db.one("SELECT COUNT(*) n FROM canary_hits WHERE canary_id=? AND session_id=?", (cid, session_id))
        if prior and prior["n"] > 1:
            continue  # alert once per (canary, session); every use is still recorded
        c = db.one("SELECT kind, label, placement, origin FROM canaries WHERE id=?", (cid,)) or {}
        if c.get("origin") == "decoy":
            continue  # a trapped session reusing a key we handed it: logged, but no new alert
        alert(settings, {
            "title": f"Canary credential used ({c.get('kind')}: {c.get('label') or c.get('placement') or cid})",
            "canary_id": cid, "origin": c.get("origin"), "session_id": session_id,
            "method": method, "path": path, "client": client, "user_agent": user_agent, "ts": now,
        })
