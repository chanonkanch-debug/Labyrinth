# Framework lab

Ten small but real apps, one per major web framework, each running behind its own Labyrinth. A single script
(`matrix.py`) runs the same checks against all of them and writes a report.

| App | Framework | Websocket | Built-in CSRF |
| --- | --- | --- | --- |
| `express` | Node.js, Express 4 | yes | no |
| `nextjs` | Next.js 15 (App Router, route handlers, a client-rendered page) | no | no |
| `fastapi` | Python, FastAPI | yes | no |
| `django` | Python, Django 5 (real CSRF middleware, signed-cookie sessions) | no | yes |
| `flask` | Python, Flask 3 | no | no |
| `spring` | Java 21, Spring Boot 3 | yes | no |
| `go` | Go `net/http` + gorilla/websocket | yes | no |
| `rails` | Ruby, Rails 8 (CSRF with Origin check, cookie sessions) | no | yes |
| `laravel` | PHP, Laravel 12 (CSRF, encrypted cookie sessions) | no | yes |
| `aspnet` | .NET 9, ASP.NET Core minimal API | yes | no |

Every app implements the same contract: `/api/health`, `/api/items[/:id]` (GET, POST JSON), `/login` (GET form,
POST sets two cookies and redirects), `/dashboard` (needs the session), `/checkout` (POST, needs the session),
`/upload` (multipart), `/redirect` (302), `/stream` (server-sent events), `/ws` (websocket echo, where supported).
Login is `alice` / `wonderland`.

## Run it

```bash
docker compose -f lab/docker-compose.yml up -d --build     # first build takes a while (10 frameworks)
pip install -r requirements.txt
python lab/matrix.py                                        # ~2 minutes; add --quick to skip the slow browsing check
open lab/results/REPORT.md
```

Ports, all on 127.0.0.1: app direct `70NN`, through Labyrinth `71NN`, dashboard `72NN` (token `lab`), where NN is
01 express, 02 nextjs, 03 fastapi, 04 django, 05 flask, 06 spring, 07 go, 08 rails, 09 laravel, 10 aspnet.
So the Django dashboard is http://127.0.0.1:7204/?token=lab.

Try observe-only mode across the lab with `LABYRINTH_MODE=observe docker compose -f lab/docker-compose.yml up -d`.
Add `ANTHROPIC_API_KEY=...` to the environment to run the decoys on Claude instead of templates.

## What the checks mean

**Transparency** (legit traffic must not notice Labyrinth): same status and bytes as hitting the app directly for
JSON GET/POST, HEAD, 404s; same response headers; compression kept; the framework's own login with CSRF works and
*every* `Set-Cookie` arrives; the session works afterwards; CSRF is still enforced; a 5 MB upload arrives whole;
redirects point at the public host, not the internal one; server-sent events arrive live (first event in <0.6 s,
not buffered until the end); websockets echo.

**Safety** (no false diversions): a person logging in and browsing with human pauses; a browser page load firing
25 parallel requests including 404s like `favicon.ico`; an API client polling on an exact 1 s timer; a user who
mistypes URLs. None of these may be diverted.

**Detection**: a scanner with a normal browser user-agent gets diverted (and how many requests it took); a canary
key diverts on the first request; a diverted session can still reach the real login; and "decoy tells": whether a
careful attacker could notice the switch (URLs it already saw changing, a 404 page that doesn't match the
framework's, different server headers).

## Adding your own app

Add an entry to `targets.json` (direct URL, Labyrinth URL, dashboard URL) and implement the contract above, or
point `matrix.py` at a copy of your app and expect the contract checks to fail where your routes differ.
