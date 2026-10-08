# claude_for_browes

Access the original Claude.ai web interface through a self-hosted gateway. The gateway holds the Claude session cookies server-side and injects them into proxied requests, so the client browser renders Claude natively — no remote-desktop video streaming, no input lag, native clipboard / Russian input / file drag-and-drop.

Claude sees the **server's IP**, not the client's. Useful when Claude.ai is geo-blocked or you want to keep Claude cookies off the client machine.

## How it works

```
Client browser ──HTTPS──> Cloudflare ──> Server (Caddy → Gateway) ──HTTPS──> claude.ai
 (renders Claude            (hides        (injects session cookies)      (sees server IP)
  natively, no lag)         client IP)
```

- **Gateway** (Node.js): reverse proxy that injects stored Claude session cookies into requests to `claude.ai`, rewrites HTML/CSS/JS asset URLs and CSP headers so the SPA works through the proxy, and strips the basic_auth header before forwarding (Claude rejects requests carrying both an auth header and a session cookie).
- **Caddy**: TLS + basic_auth + routing. Asset paths are served without basic_auth (public JS/CSS) to avoid 401 on dynamic `import()`.
- **Browser extension**: transparently redirects `claude.ai` and its asset hosts to the gateway and adds the basic_auth header.
- **Remote Chromium** (optional, linuxserver/chromium): used only to log in once via magic-link and extract the session cookies.

## Repo layout

| Path | What |
|---|---|
| `gateway/gateway.js` | the cookie-injecting proxy (Node, no deps) |
| `server/compose.yaml` | docker-compose: browser + gateway + caddy |
| `server/Caddyfile.template` | Caddy config template |
| `server/extract_cookies.py` | pulls session cookies from the remote Chromium via CDP |
| `extension/` | Chrome/Edge extension (Manifest V3) |
| `configure.sh` | fills your domain into the templates |
| `docs/DEPLOY-SERVER.md` | server setup |
| `docs/SETUP-CLIENT.md` | client (Mac) setup |

## Quick start

```sh
./configure.sh claude.example.com   # your gateway domain
```

Then follow `docs/DEPLOY-SERVER.md` (server) and `docs/SETUP-CLIENT.md` (each client).

## Security notes

- Session cookies live only on the server (`server/cookies/`, gitignored). Never commit them.
- The basic_auth hash is set in `server/Caddyfile` (generated, gitignored), not in the template.
- The gateway strips `Authorization`/`Proxy-Authorization` before forwarding upstream and never logs cookie values.
- Keep the client browser profile in English (US) + UTC with WebRTC off for a clean fingerprint.
