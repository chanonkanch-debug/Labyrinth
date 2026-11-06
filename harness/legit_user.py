"""A real user: logs in, browses a few pages with human timing, checks out."""
from __future__ import annotations

import random
import time

import httpx

UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"


def run(base: str, think: tuple[float, float] = (0.3, 2.5), verbose: bool = True) -> list[tuple[int, str]]:
    out = []
    with httpx.Client(base_url=base, headers={"user-agent": UA}, timeout=30) as c:
        r = c.post("/login", json={"email": "real.user@example.com", "password": "correct-horse"})
        out.append((r.status_code, "/login"))
        auth = {"authorization": f"Bearer {r.json().get('token', '')}"}
        for path in ["/users/me", "/projects", "/projects/1", "/projects/2", "/projects/1", "/users/me"]:
            time.sleep(random.uniform(*think))
            r = c.get(path, headers=auth)
            out.append((r.status_code, path))
        r = c.post("/checkout", headers=auth)
        out.append((r.status_code, "/checkout"))
    if verbose:
        for st, p in out:
            print(f"[user]  {st} {p}")
    return out


if __name__ == "__main__":
    run("http://127.0.0.1:8080")
