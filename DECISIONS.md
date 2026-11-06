# Decisions log

Short record of choices made in the Phase 1 prototype, and what to revisit.

1. **All Python, one SQLite file, no Docker.** The kickoff prompt suggested Node proxy + FastAPI + Postgres + Redis.
   For a solo prototype that is three runtimes to babysit. Everything here is FastAPI + httpx + SQLite, runnable with
   `pip install`. Each module maps 1:1 to a planned service, so splitting later is mechanical.
   *Revisit:* Postgres + Redis when there is more than one proxy instance.

2. **Decoy runs in-process with the proxy**, not as a separate service. Saves a network hop and a deploy.
   *Revisit:* split out when LLM latency or isolation matters (the decoy should not share a process with real traffic at scale).

3. **Two decoy generators.** A deterministic template world (offline, free, instant) and an LLM world (Anthropic API).
   The LLM is optional, capped per session, and falls back to templates on any error. This keeps the demo and tests
   working without a key and bounds cost per trapped session.

4. **Consistency = cache + seeded entities.** Every response is cached by (session, method, path, query), and entities
   are seeded by (session, kind, id) so list and detail views agree. Different attackers get different worlds.

5. **Secrets in the decoy are real canaries.** The LLM writes `{{CANARY:kind}}` placeholders; we mint a canary bound to
   that session. So any key an attacker carries out of the decoy and uses anywhere we watch is attributable.
   Decoy-key reuse is logged but does not page anyone (the session is already known).

6. **Protected routes always reach the real API, even for diverted sessions.** Follows the hard rule "never divert
   login, signup or payment". Trade-off: a known attacker can still hit the real login. Real auth must still hold.

7. **Fail open on scoring/logging errors; fail closed-ish on decoy errors.** If scoring breaks, the request goes to the
   real API. If the decoy breaks for an already-diverted session, it gets a bland 503 rather than the real API, since
   that session is already judged hostile. *Change this* if you want strict fail-open everywhere.

8. **Alerts once per (canary, session).** Every hit is recorded; only the first per session alerts.

9. **Session identity is IP + user-agent.** Simple and good enough for the test harness. Weak against agents that
   rotate either. *Revisit in Phase 2:* TLS/HTTP fingerprints, auth token lineage, cookie seeding inside the decoy.

10. **Logging redacts credentials for real traffic** (`authorization`, `cookie`, `x-api-key`) and stores full requests
    only for decoy traffic, which is the attacker's playbook.

11. **Model:** `claude-haiku-5-5` by default for cost and latency, configurable with `LABYRINTH_MODEL`.

## Known gaps (next phase)

- Not yet tested against real AI pentest agents; the scripted attacker is a stand-in.
- Behavioural thresholds are hand-set; need data from real traffic to tune false-positive rate.
- Proxy does not handle websockets or streaming responses.
- No "playbook → detection rule" step yet (the Learn stage).
- Admin auth is a single shared token.
