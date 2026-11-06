"""Alerting: webhook + email, best-effort, never blocks the request path.

Alerts only ever go to the customer's own configured destinations,
never to anything derived from attacker traffic.
"""
from __future__ import annotations

import json
import logging
import smtplib
import threading
from email.message import EmailMessage
from typing import Any

import httpx

from .config import Settings

log = logging.getLogger("labyrinth.alerts")


def _send(settings: Settings, payload: dict[str, Any]) -> None:
    if settings.alert_webhook:
        try:
            httpx.post(settings.alert_webhook, json=payload, timeout=5)
        except Exception as exc:  # noqa: BLE001
            log.warning("webhook alert failed: %s", exc)
    if settings.smtp_host and settings.alert_email_to:
        try:
            msg = EmailMessage()
            msg["Subject"] = f"[Labyrinth] {payload.get('title', 'alert')}"
            msg["From"] = settings.smtp_user or "labyrinth@localhost"
            msg["To"] = settings.alert_email_to
            msg.set_content(json.dumps(payload, indent=2))
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as s:
                s.starttls()
                if settings.smtp_user and settings.smtp_password:
                    s.login(settings.smtp_user, settings.smtp_password)
                s.send_message(msg)
        except Exception as exc:  # noqa: BLE001
            log.warning("email alert failed: %s", exc)


def alert(settings: Settings, payload: dict[str, Any]) -> None:
    log.warning("ALERT %s", json.dumps(payload))
    threading.Thread(target=_send, args=(settings, payload), daemon=True).start()
