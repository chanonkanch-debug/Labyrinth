"""Run the proxy and the admin dashboard together (what the Docker image runs).

    LABYRINTH_UPSTREAM=http://my-app:3000 python -m labyrinth.serve
"""
from __future__ import annotations

import asyncio
import logging

import uvicorn

from .admin import create_admin_app
from .config import Settings
from .db import DB
from .proxy import create_app

log = logging.getLogger("labyrinth")


async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    settings = Settings()
    if settings.admin_host not in ("127.0.0.1", "localhost") and not settings.admin_token:
        raise SystemExit("Refusing to expose the admin dashboard without LABYRINTH_ADMIN_TOKEN set.")
    db = DB(settings.db_path)
    proxy = uvicorn.Server(uvicorn.Config(create_app(settings, db), host=settings.proxy_host,
                                          port=settings.proxy_port, proxy_headers=False, log_level="warning",
                                          server_header=False, date_header=False))
    admin = uvicorn.Server(uvicorn.Config(create_admin_app(settings, db), host=settings.admin_host,
                                          port=settings.admin_port, log_level="warning"))
    log.warning("proxy on %s:%s -> %s (mode=%s); dashboard on %s:%s", settings.proxy_host, settings.proxy_port,
                settings.upstream, settings.mode, settings.admin_host, settings.admin_port)
    await asyncio.gather(proxy.serve(), admin.serve())


if __name__ == "__main__":
    asyncio.run(main())
