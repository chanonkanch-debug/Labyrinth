# Putting Labyrinth in front of a real service

Labyrinth is a reverse proxy. Traffic goes **client → (your load balancer / TLS) → Labyrinth → your app**.
It needs one setting, `LABYRINTH_UPSTREAM`, the address of the app it protects. One Labyrinth instance protects
one upstream.

## Roll it out in observe mode first

`LABYRINTH_MODE=observe` scores every session, records it, and alerts on canaries, but **never diverts anyone**:
all traffic reaches your app. Run it like this until the dashboard's "Flagged sessions" list contains only
traffic you agree is hostile.

1. **Staging, observe mode.** Put Labyrinth in front of staging, run your normal test suite and click through the
   app. Nothing should be flagged. If your own test runner or monitoring is flagged, that's expected for
   machine traffic; note its user-agent.
2. **Production, observe mode, about a week.** Check the flagged list daily. Any real user or partner
   integration in it is a false positive: tell me which signal flagged it and we tune the scoring.
3. **Plant canaries.** Generate keys in the dashboard and put them where attackers look (a public repo's
   `.env.example`, CI variables, an internal wiki, a storage bucket). A canary hit alerts even in observe mode.
4. **Switch to divert** (`LABYRINTH_MODE=divert`, the default) once step 2 is clean.

## Run it

### Docker (recommended)

```bash
docker build -t labyrinth .
docker run -d --name labyrinth -p 8080:8080 -p 127.0.0.1:8090:8090 -v labyrinth-data:/data \
  -e LABYRINTH_UPSTREAM=http://my-app:3000 \
  -e LABYRINTH_MODE=observe \
  -e LABYRINTH_ADMIN_HOST=0.0.0.0 -e LABYRINTH_ADMIN_TOKEN="$(openssl rand -hex 16)" \
  labyrinth
```

Port 8080 is the proxy (point your traffic here). Port 8090 is the dashboard: never expose it publicly; reach it
over an SSH tunnel or VPN. The container refuses to start with a non-local dashboard and no token.

### Docker Compose, next to your app

```yaml
services:
  app:
    image: my-app
    expose: ["3000"]          # no public port any more
  labyrinth:
    build: ./labyrinth       # or a pushed image
    ports: ["80:8080", "127.0.0.1:8090:8090"]
    environment:
      LABYRINTH_UPSTREAM: http://app:3000
      LABYRINTH_MODE: observe
      LABYRINTH_ADMIN_HOST: 0.0.0.0
      LABYRINTH_ADMIN_TOKEN: ${LABYRINTH_ADMIN_TOKEN}
      LABYRINTH_PROTECTED_PREFIXES: /login,/signup,/auth,/password,/checkout,/billing
    volumes: ["labyrinth-data:/data"]
volumes:
  labyrinth-data:
```

### Behind nginx, Caddy or a cloud load balancer

Keep TLS on your load balancer and send traffic to Labyrinth instead of the app. Because Labyrinth then sees the
load balancer's IP, tell it to trust `X-Forwarded-For`, **but only if Labyrinth is not reachable any other way**
(otherwise an attacker can fake their IP):

```bash
LABYRINTH_TRUST_XFF=on
```

nginx needs websocket upgrade headers and must not buffer streaming responses:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;   # map $http_upgrade $connection_upgrade { default upgrade; '' close; }
    proxy_buffering off;
}
```

Caddy: `reverse_proxy 127.0.0.1:8080` handles all of that by default.

### Kubernetes, as a sidecar

Run Labyrinth in the same pod as the app, point the Service at Labyrinth's port, and have the app listen only on
localhost:

```yaml
containers:
  - name: app
    image: my-app
    env: [{ name: PORT, value: "3000" }]
  - name: labyrinth
    image: registry.example.com/labyrinth:latest
    ports: [{ containerPort: 8080 }]
    env:
      - { name: LABYRINTH_UPSTREAM, value: "http://127.0.0.1:3000" }
      - { name: LABYRINTH_MODE, value: "observe" }
      - { name: LABYRINTH_TRUST_XFF, value: "on" }      # traffic only arrives via the ingress
    volumeMounts: [{ name: labyrinth-data, mountPath: /data }]
# Service: targetPort: 8080
```

With several replicas, each pod keeps its own SQLite database and its own view of sessions. That's fine for a
trial; a shared database is on the roadmap.

### Without Docker

```bash
pip install -r requirements.txt
LABYRINTH_UPSTREAM=http://127.0.0.1:3000 LABYRINTH_MODE=observe python -m labyrinth.serve
```

## Tell it which routes must never be diverted

`LABYRINTH_PROTECTED_PREFIXES` lists path prefixes that always go to the real app, even for a session that has
been diverted. The default covers `/login /logout /signup /register /auth /oauth /password /payment(s) /checkout
/billing`. Add your framework's own paths:

| Framework / library | Add |
| --- | --- |
| Django auth / allauth | `/accounts/login,/accounts/signup,/accounts/password` |
| Rails + Devise | `/users/sign_in,/users/sign_up,/users/password` |
| Laravel Breeze / Fortify | `/login,/register,/forgot-password,/reset-password` (already mostly covered) |
| Next.js + Auth.js | `/api/auth` |
| Spring Security | `/login,/logout,/oauth2` |
| ASP.NET Core Identity | `/Identity/Account` |
| Stripe / payment webhooks | your webhook path, e.g. `/webhooks/stripe` |

Also add webhook endpoints from payment providers and partners: they are machine traffic and must never be
diverted.

## What Labyrinth does to real traffic

Verified across ten frameworks in `lab/` (see `lab/results/REPORT.md`):

- Request and response bodies stream through untouched (uploads, downloads, server-sent events).
- Every header is kept, including multiple `Set-Cookie` headers; compression is passed through as-is.
- The original `Host` header is forwarded (turn off with `LABYRINTH_PRESERVE_HOST=off`), plus
  `X-Forwarded-For`, `X-Forwarded-Proto` and `X-Forwarded-Host`, so redirects, CSRF and cookie checks work.
- Websockets pass through for normal sessions; a diverted session's websocket is closed.
- If scoring or logging fails, the request goes to your app anyway.
- Real responses are not stored, except that each session's own recent GET responses are kept **in memory** so
  that, if that session is later diverted, URLs it already saw keep returning the same thing.

## Settings added for deployment

| Variable | Default | Meaning |
| --- | --- | --- |
| `LABYRINTH_MODE` | `divert` | `observe` = score, log and alert only |
| `LABYRINTH_HOST` / `LABYRINTH_PORT` | `0.0.0.0` / `8080` | Where the proxy listens |
| `LABYRINTH_ADMIN_HOST` / `LABYRINTH_ADMIN_PORT` | `127.0.0.1` / `8090` | Where the dashboard listens |
| `LABYRINTH_PRESERVE_HOST` | `on` | Forward the client's `Host` header to the app |
| `LABYRINTH_UPSTREAM_TIMEOUT` | `60` | Seconds to wait for the app |

## Known limits

- Talks HTTP/1.1 to the upstream. One upstream per instance.
- Sessions are identified by IP + user-agent; an attacker that rotates either starts fresh.
- The dashboard has a single shared token.
