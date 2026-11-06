"""All settings come from environment variables (no secrets in code)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _list(name: str, default: str) -> list[str]:
    return [p.strip() for p in os.getenv(name, default).split(",") if p.strip()]


@dataclass
class Settings:
    upstream: str = field(default_factory=lambda: os.getenv("LABYRINTH_UPSTREAM", "http://127.0.0.1:9000"))
    db_path: str = field(default_factory=lambda: os.getenv("LABYRINTH_DB", "labyrinth.db"))
    threshold: int = field(default_factory=lambda: int(os.getenv("LABYRINTH_THRESHOLD", "70")))
    # Routes that are NEVER diverted, no matter the score (hard rule).
    protected_prefixes: list[str] = field(
        default_factory=lambda: _list(
            "LABYRINTH_PROTECTED_PREFIXES",
            "/login,/logout,/signup,/register,/auth,/oauth,/password,/payment,/payments,/checkout,/billing",
        )
    )
    api_description: str = field(
        default_factory=lambda: os.getenv(
            "LABYRINTH_API_DESCRIPTION",
            "A B2B SaaS REST API for project management: users, projects, tasks, invoices. JSON over HTTPS, bearer-token auth.",
        )
    )
    company_name: str = field(default_factory=lambda: os.getenv("LABYRINTH_COMPANY", "acme"))
    tarpit_ms: int = field(default_factory=lambda: int(os.getenv("LABYRINTH_TARPIT_MS", "400")))
    llm_model: str = field(default_factory=lambda: os.getenv("LABYRINTH_MODEL", "claude-haiku-5-5"))
    llm_enabled: bool = field(
        default_factory=lambda: bool(os.getenv("ANTHROPIC_API_KEY")) and os.getenv("LABYRINTH_LLM", "on") != "off"
    )
    # Cost cap: max LLM generations per session; after that the template generator takes over.
    llm_max_per_session: int = field(default_factory=lambda: int(os.getenv("LABYRINTH_LLM_MAX_PER_SESSION", "60")))
    alert_webhook: str | None = field(default_factory=lambda: os.getenv("LABYRINTH_ALERT_WEBHOOK") or None)
    smtp_host: str | None = field(default_factory=lambda: os.getenv("LABYRINTH_SMTP_HOST") or None)
    smtp_port: int = field(default_factory=lambda: int(os.getenv("LABYRINTH_SMTP_PORT", "587")))
    smtp_user: str | None = field(default_factory=lambda: os.getenv("LABYRINTH_SMTP_USER") or None)
    smtp_password: str | None = field(default_factory=lambda: os.getenv("LABYRINTH_SMTP_PASSWORD") or None)
    alert_email_to: str | None = field(default_factory=lambda: os.getenv("LABYRINTH_ALERT_EMAIL") or None)
    admin_token: str | None = field(default_factory=lambda: os.getenv("LABYRINTH_ADMIN_TOKEN") or None)
    # "divert": send flagged sessions to the decoy. "observe": score, log and alert only; all traffic reaches the real app.
    mode: str = field(default_factory=lambda: os.getenv("LABYRINTH_MODE", "divert").lower())
    # Forward the client's Host header (frameworks build redirects, CSRF and cookie checks from it).
    preserve_host: bool = field(default_factory=lambda: os.getenv("LABYRINTH_PRESERVE_HOST", "on") == "on")
    upstream_timeout: float = field(default_factory=lambda: float(os.getenv("LABYRINTH_UPSTREAM_TIMEOUT", "60")))
    proxy_host: str = field(default_factory=lambda: os.getenv("LABYRINTH_HOST", "0.0.0.0"))
    proxy_port: int = field(default_factory=lambda: int(os.getenv("LABYRINTH_PORT", "8080")))
    admin_host: str = field(default_factory=lambda: os.getenv("LABYRINTH_ADMIN_HOST", "127.0.0.1"))
    admin_port: int = field(default_factory=lambda: int(os.getenv("LABYRINTH_ADMIN_PORT", "8090")))
    trust_forwarded_for: bool = field(default_factory=lambda: os.getenv("LABYRINTH_TRUST_XFF", "off") == "on")
