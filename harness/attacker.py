"""Scripted stand-in for an autonomous AI pentest agent.

It behaves like one: machine-regular timing, broad enumeration, sensitive-file probes,
and it *reads and trusts* what it finds (follows links, reuses any key it discovers).
Point it ONLY at your own Labyrinth proxy.
"""
from __future__ import annotations

import argparse
import json
import re
import time

import httpx

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"
WORDLIST = ["/", "/health", "/api", "/api/v1", "/v1/users", "/users", "/users/1", "/users/2", "/projects",
            "/projects/1", "/admin", "/.env", "/.git/config", "/config.json", "/backup", "/debug", "/swagger.json",
            "/internal", "/actuator/health", "/server-status", "/users/3", "/users/4", "/api/v1/keys"]
UA_B = "python-requests/2.32.3"
KEY_RX = re.compile(r"(sk_live_[A-Za-z0-9]{32}|rk_live_[A-Za-z0-9]{24}|ghp_[A-Za-z0-9]{36})")


def run(base: str, steps: int = 60, leaked_key: str | None = None, interval: float = 0.15, verbose: bool = True,
        ua: str = UA) -> dict:
    seen, queue, keys = set(), list(WORDLIST), []
    if leaked_key:
        keys.append(leaked_key)
    log = []
    with httpx.Client(base_url=base, headers={"user-agent": ua}, timeout=30) as c:
        for i in range(steps):
            if not queue:
                break
            path = queue.pop(0)
            if path in seen:
                continue
            seen.add(path)
            headers = {"authorization": f"Bearer {keys[-1]}"} if keys else {}
            r = c.get(path, headers=headers)
            text = r.text
            log.append((r.status_code, path))
            if verbose:
                print(f"[agent] {r.status_code} GET {path}")
            for k in KEY_RX.findall(text):
                if k not in keys:
                    keys.append(k)
                    if verbose:
                        print(f"[agent]   found credential {k[:12]}..., will use it")
            # follow every link it is offered: this is the weakness Labyrinth exploits
            try:
                data = json.loads(text)
            except ValueError:
                data = None
            links: list[str] = []

            def walk(o):
                if isinstance(o, dict):
                    for v in o.values():
                        walk(v)
                elif isinstance(o, list):
                    for v in o:
                        walk(v)
                elif isinstance(o, str) and o.startswith("/") and " " not in o:
                    links.append(o)
            walk(data)
            links += re.findall(r"(?<![\w.])(/[a-z0-9_\-/]+)", text if data is None else "")
            for l in links:
                if l not in seen:
                    queue.insert(0, l)
            time.sleep(interval)
    return {"requests": len(log), "keys_found": keys, "log": log}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8080")
    ap.add_argument("--steps", type=int, default=60)
    ap.add_argument("--leaked-key", help="a planted canary key the agent 'found' in a public repo")
    a = ap.parse_args()
    out = run(a.base, a.steps, a.leaked_key)
    print(f"\n[agent] done: {out['requests']} requests, {len(out['keys_found'])} credentials 'found'")
