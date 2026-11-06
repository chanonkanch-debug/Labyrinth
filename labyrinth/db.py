"""SQLite storage for canaries, sessions, the engagement log and the decoy cache."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS canaries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    kind TEXT NOT NULL,
    label TEXT,
    placement TEXT,
    origin TEXT NOT NULL DEFAULT 'planted',   -- planted by customer | issued by decoy
    session_id TEXT,                          -- for decoy-issued canaries: which session got it
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS canary_hits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    canary_id INTEGER NOT NULL REFERENCES canaries(id),
    session_id TEXT NOT NULL,
    ts REAL NOT NULL,
    method TEXT, path TEXT, client TEXT, user_agent TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    client TEXT, user_agent TEXT,
    first_seen REAL NOT NULL, last_seen REAL NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 0,
    score INTEGER NOT NULL DEFAULT 0,
    reasons TEXT NOT NULL DEFAULT '[]',
    diverted INTEGER NOT NULL DEFAULT 0,
    diverted_at REAL,
    decoy_requests INTEGER NOT NULL DEFAULT 0,
    llm_generations INTEGER NOT NULL DEFAULT 0,
    techniques TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    ts REAL NOT NULL,
    method TEXT, path TEXT, query TEXT,
    headers TEXT, body TEXT,
    status INTEGER, route TEXT,               -- upstream | decoy | protected
    score INTEGER, response_snippet TEXT, techniques TEXT
);
CREATE INDEX IF NOT EXISTS events_session ON events(session_id, ts);
CREATE TABLE IF NOT EXISTS decoy_cache (
    session_id TEXT NOT NULL,
    cache_key TEXT NOT NULL,
    status INTEGER NOT NULL,
    content_type TEXT NOT NULL,
    body TEXT NOT NULL,
    generator TEXT NOT NULL,
    created_at REAL NOT NULL,
    PRIMARY KEY (session_id, cache_key)
);
"""


class DB:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(SCHEMA)

    def execute(self, sql: str, params: tuple | dict = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._conn.execute(sql, params)

    def one(self, sql: str, params: tuple | dict = ()) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(sql, params).fetchone()
        return dict(row) if row else None

    def all(self, sql: str, params: tuple | dict = ()) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, params).fetchall()]

    # ---- canaries -------------------------------------------------------
    def add_canary(self, token: str, kind: str, label: str | None, placement: str | None,
                   origin: str = "planted", session_id: str | None = None) -> int:
        cur = self.execute(
            "INSERT INTO canaries(token, kind, label, placement, origin, session_id, created_at) VALUES (?,?,?,?,?,?,?)",
            (token, kind, label, placement, origin, session_id, time.time()),
        )
        return int(cur.lastrowid)

    def canary_tokens(self) -> dict[str, int]:
        return {r["token"]: r["id"] for r in self.all("SELECT id, token FROM canaries")}

    # ---- sessions -------------------------------------------------------
    def upsert_session(self, s: dict[str, Any]) -> None:
        self.execute(
            """INSERT INTO sessions(id, client, user_agent, first_seen, last_seen, request_count, score, reasons,
                                    diverted, diverted_at, decoy_requests, llm_generations, techniques)
               VALUES (:id,:client,:user_agent,:first_seen,:last_seen,:request_count,:score,:reasons,
                       :diverted,:diverted_at,:decoy_requests,:llm_generations,:techniques)
               ON CONFLICT(id) DO UPDATE SET last_seen=:last_seen, request_count=:request_count, score=:score,
                   reasons=:reasons, diverted=:diverted, diverted_at=:diverted_at,
                   decoy_requests=:decoy_requests, llm_generations=:llm_generations, techniques=:techniques""",
            {**s, "reasons": json.dumps(s["reasons"]), "techniques": json.dumps(sorted(s["techniques"])),
             "diverted": int(s["diverted"])},
        )

    def get_session(self, sid: str) -> dict[str, Any] | None:
        row = self.one("SELECT * FROM sessions WHERE id=?", (sid,))
        if row:
            row["reasons"] = json.loads(row["reasons"])
            row["techniques"] = set(json.loads(row["techniques"]))
            row["diverted"] = bool(row["diverted"])
        return row

    # ---- events ---------------------------------------------------------
    def log_event(self, **e: Any) -> None:
        self.execute(
            """INSERT INTO events(session_id, ts, method, path, query, headers, body, status, route, score,
                                  response_snippet, techniques)
               VALUES (:session_id,:ts,:method,:path,:query,:headers,:body,:status,:route,:score,
                       :response_snippet,:techniques)""",
            e,
        )

    # ---- decoy cache ----------------------------------------------------
    def get_decoy(self, sid: str, key: str) -> dict[str, Any] | None:
        return self.one("SELECT * FROM decoy_cache WHERE session_id=? AND cache_key=?", (sid, key))

    def put_decoy(self, sid: str, key: str, status: int, content_type: str, body: str, generator: str) -> None:
        self.execute(
            "INSERT OR IGNORE INTO decoy_cache VALUES (?,?,?,?,?,?,?)",
            (sid, key, status, content_type, body, generator, time.time()),
        )
