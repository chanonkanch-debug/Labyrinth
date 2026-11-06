"""Session scoring: is this an automated (likely AI-driven) attacker?

Score is 0-100. Signals are deliberately conservative: only canary use alone can
cross the default threshold (70); behavioural signals must stack up.
"""
from __future__ import annotations

import re
import statistics
import time
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import unquote

SCANNER_PATHS = re.compile(
    r"(^|/)(\.env|\.git|\.aws|\.ssh|\.DS_Store|\.svn|\.htaccess|wp-admin|wp-login\.php|xmlrpc\.php|phpinfo|"
    r"server-status|actuator|\.well-known/security|config\.(json|ya?ml|php)|backup|dump\.sql|id_rsa|"
    r"swagger\.json|openapi\.json|graphql|debug|console|admin)(/|$|\.|\?)",
    re.IGNORECASE,
)
SCANNER_UA = re.compile(r"sqlmap|nikto|nuclei|gobuster|dirbuster|ffuf|feroxbuster|masscan|zgrab|wpscan|nmap", re.I)
PAYLOADS = {
    "sql_injection": re.compile(r"('|%27)\s*(or|and)\s+\d|union(\s|%20|\+)+select|sleep\(\d|;--", re.I),
    "path_traversal": re.compile(r"\.\./|\.\.%2f|%2e%2e/", re.I),
    "xss_probe": re.compile(r"<script|javascript:|onerror=", re.I),
    "ssrf_probe": re.compile(r"169\.254\.169\.254|metadata\.google|localhost:\d+|127\.0\.0\.1", re.I),
    "command_injection": re.compile(r";\s*(cat|ls|id|whoami|curl|wget)\b|\$\(|`", re.I),
}


def techniques_for(method: str, path: str, query: str, body: str) -> set[str]:
    """Classify what a single request is attempting (used for both scoring and the dashboard)."""
    blob = unquote(f"{path}?{query}\n{body}")
    found = {name for name, rx in PAYLOADS.items() if rx.search(blob)}
    if SCANNER_PATHS.search(path):
        found.add("sensitive_file_probe" if re.search(r"\.(env|git|aws|ssh)|id_rsa|dump|backup", path, re.I)
                  else "admin_or_debug_discovery")
    if re.search(r"/(users?|accounts?|customers?)/\d+", path) and method == "GET":
        found.add("object_enumeration")
    if method in ("PUT", "PATCH", "DELETE"):
        found.add("state_change_attempt")
    return found


@dataclass
class SessionState:
    id: str
    client: str
    user_agent: str
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    request_count: int = 0
    score: int = 0
    reasons: list[str] = field(default_factory=list)
    diverted: bool = False
    diverted_at: float | None = None
    decoy_requests: int = 0
    llm_generations: int = 0
    techniques: set[str] = field(default_factory=set)
    canary_used: bool = False
    # rolling windows (in memory only)
    times: deque = field(default_factory=lambda: deque(maxlen=50))
    paths: deque = field(default_factory=lambda: deque(maxlen=200))  # (ts, path)
    statuses: deque = field(default_factory=lambda: deque(maxlen=50))
    scanner_path_hits: int = 0
    payload_hits: int = 0

    def as_row(self) -> dict:
        return {k: getattr(self, k) for k in (
            "id", "client", "user_agent", "first_seen", "last_seen", "request_count", "score", "reasons",
            "diverted", "diverted_at", "decoy_requests", "llm_generations", "techniques")}


def observe(s: SessionState, method: str, path: str, query: str, body: str, now: float | None = None) -> set[str]:
    now = now or time.time()
    s.request_count += 1
    s.last_seen = now
    s.times.append(now)
    s.paths.append((now, path))
    tech = techniques_for(method, path, query, body)
    if "sensitive_file_probe" in tech or "admin_or_debug_discovery" in tech:
        s.scanner_path_hits += 1
    if tech & set(PAYLOADS):
        s.payload_hits += 1
    s.techniques |= tech
    return tech


def score(s: SessionState, now: float | None = None) -> tuple[int, list[str]]:
    now = now or time.time()
    pts = 0
    reasons: list[str] = []

    if s.canary_used:
        return 100, ["canary credential used"]

    if SCANNER_UA.search(s.user_agent or ""):
        pts += 40
        reasons.append("known scanner user-agent")

    if s.scanner_path_hits:
        p = min(50, 25 * s.scanner_path_hits)
        pts += p
        reasons.append(f"{s.scanner_path_hits} sensitive/admin path probe(s)")

    if s.payload_hits:
        p = min(60, 30 * s.payload_hits)
        pts += p
        reasons.append(f"{s.payload_hits} attack payload(s) in request")

    recent = {p for t, p in s.paths if now - t <= 60}
    if len(recent) >= 30:
        pts += 35
        reasons.append(f"{len(recent)} distinct paths in 60s")
    elif len(recent) >= 15:
        pts += 20
        reasons.append(f"{len(recent)} distinct paths in 60s")

    if len(s.statuses) >= 10:
        miss = sum(1 for st in s.statuses if st in (401, 403, 404, 405)) / len(s.statuses)
        if miss > 0.5:
            pts += 20
            reasons.append(f"{miss:.0%} of responses were 4xx misses")

    if len(s.times) >= 8:
        ts = list(s.times)[-20:]
        gaps = [b - a for a, b in zip(ts, ts[1:])]
        mean = statistics.mean(gaps)
        if mean > 0 and mean < 2.0:
            cv = statistics.pstdev(gaps) / mean
            if cv < 0.35:
                pts += 25
                reasons.append(f"machine-regular timing (mean gap {mean*1000:.0f}ms, cv {cv:.2f})")

    return min(100, pts), reasons
