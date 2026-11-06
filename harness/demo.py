"""End-to-end demo: real API + Labyrinth proxy + dashboard, then a real user and an AI-style attacker.

    python -m harness.demo            # run the scenario, print results, keep dashboard up
    python -m harness.demo --no-serve # run the scenario and exit
"""
from __future__ import annotations

import argparse
import logging
import os
import threading
import time

import uvicorn


def _serve(app, port: int) -> uvicorn.Server:
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    while not server.started:
        time.sleep(0.05)
    return server


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-serve", action="store_true")
    ap.add_argument("--fresh", action="store_true", help="delete the demo database first")
    a = ap.parse_args()

    os.environ.setdefault("LABYRINTH_DB", "demo.db")
    os.environ.setdefault("LABYRINTH_UPSTREAM", "http://127.0.0.1:9000")
    os.environ.setdefault("LABYRINTH_TARPIT_MS", "150")
    if a.fresh:
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(os.environ["LABYRINTH_DB"] + suffix)
            except FileNotFoundError:
                pass
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

    from labyrinth.admin import create_admin_app
    from labyrinth.canary import create_canary
    from labyrinth.config import Settings
    from labyrinth.db import DB
    from labyrinth.proxy import create_app

    from . import attacker, legit_user
    from .sample_api import app as real_api

    settings = Settings()
    db = DB(settings.db_path)
    _serve(real_api, 9000)
    _serve(create_app(settings, db), 8080)
    _serve(create_admin_app(settings, db), 8090)
    print(f"real API :9000 · proxy :8080 · dashboard http://127.0.0.1:8090  (LLM decoys: {'on' if settings.llm_enabled else 'off, template generator'})\n")

    leaked = create_canary(db, "api_key", label="leaked CI key", placement="public repo .env.example")
    print(f"planted canary: {leaked['display']}\n")

    print("--- real user ---")
    legit_user.run("http://127.0.0.1:8080")
    print("\n--- attacker A: AI-style agent, no credentials, caught by behaviour ---")
    attacker.run("http://127.0.0.1:8080", steps=40, ua=attacker.UA)
    print("\n--- attacker B: different agent that found the leaked key in a public repo ---")
    attacker.run("http://127.0.0.1:8080", steps=25, leaked_key=leaked["token"], ua=attacker.UA_B)

    from labyrinth.admin import summary
    s = summary(db)
    print(f"\nsessions seen {s['sessions_total']}, trapped {s['sessions_trapped']}, "
          f"decoy responses {s['decoy_requests']}, canary hits {s['canary_hits']}")
    for t in s["trapped"]:
        print(f"  trapped {t['id']} score {t['score']}: {'; '.join(t['reasons'])}")
        print(f"    techniques: {', '.join(t['techniques'])}")

    if not a.no_serve:
        print("\nDashboard: http://127.0.0.1:8090   (Ctrl+C to stop)")
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
