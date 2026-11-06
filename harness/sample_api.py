"""A tiny stand-in for the customer's real API (the thing Labyrinth protects)."""
from __future__ import annotations

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Acme real API")
PROJECTS = {1: {"id": 1, "name": "Website relaunch"}, 2: {"id": 2, "name": "Mobile app"}}
TOKENS = {"real-user-token": {"id": 42, "name": "Real User", "email": "real.user@example.com"}}


class Login(BaseModel):
    email: str
    password: str


@app.get("/")
def root():
    return {"service": "acme-api", "version": "1.4.2"}


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/login")
def login(body: Login):
    if body.password != "correct-horse":
        raise HTTPException(401, "invalid credentials")
    return {"token": "real-user-token"}


def _user(authorization: str | None):
    tok = (authorization or "").removeprefix("Bearer ").strip()
    if tok not in TOKENS:
        raise HTTPException(401, "unauthorized")
    return TOKENS[tok]


@app.get("/users/me")
def me(authorization: str | None = Header(None)):
    return _user(authorization)


@app.get("/projects")
def projects(authorization: str | None = Header(None)):
    _user(authorization)
    return {"data": list(PROJECTS.values())}


@app.get("/projects/{pid}")
def project(pid: int, authorization: str | None = Header(None)):
    _user(authorization)
    if pid not in PROJECTS:
        raise HTTPException(404, "not found")
    return PROJECTS[pid]


@app.post("/checkout")
def checkout(authorization: str | None = Header(None)):
    _user(authorization)
    return {"ok": True, "order_id": 1001}
