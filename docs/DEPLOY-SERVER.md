# Deploy the server

The server has three containers: a TLS-only front door, the application gateway, and Caddy. Public TCP 443 reaches the front door; TCP 80 reaches Caddy for Let's Encrypt HTTP-01 certificate issuance. Caddy requests a short-lived certificate for the public IP and renews it automatically. The gateway listeners on 8088 and 8443 stay inside the Docker network.

## Requirements

- Ubuntu/Debian server with a stable public IPv4 address in a region where Claude is available
- Docker Engine and the Docker Compose plugin
- A DNS A record for your gateway domain, such as `claude.example.com`
- Inbound TCP 80 and 443 allowed by the provider firewall and host firewall

The domain is used for the Claude reverse gateway. Artifact CONNECT goes directly to the server's public IP and verifies that IP certificate. Cloudflare can proxy the domain traffic; it does not proxy the direct IP CONNECT connection.

## Recommended installation

Use the repository installer, which prepares the config, certificate variables, extension packages, backups, and all files mounted by Compose:

For an upgrade from the legacy systemd mux, first verify that `claude-port443.service` belongs to this deployment, then back up its unit/config and the existing key/data. Stop that exact unit before confirming the installer's Compose start. The installer does not stop system services automatically; leave the old unit enabled until the new stack is healthy. See the migration procedure below.

```sh
git clone <repository-url> /root/claude-browser
cd /root/claude-browser
bash install.sh
```

When prompted, provide the gateway domain and confirm the public IP that clients will use for CONNECT. Keep `.env` mode `600`; it contains `COOKIES_KEY` and the public hosts. Save an off-server copy of the cookie encryption key and the separate backup key.

The generated `.env` sets `PUBLIC_HOST` to the HTTPS domain used by Claude requests and `CONNECT_HOST` to the server's public IPv4 address used by artifact tunnels. Caddy serves the domain certificate and requests a separate short-lived Let's Encrypt certificate for `CONNECT_HOST` with HTTP-01. Keep both values correct when moving the server or changing IPs.

The deploy folder must contain the generated `Caddyfile`, `compose.yaml`, `port443-mux.py`, `privacy.html`, `gateway/src/gateway.js`, persistent `gateway/cookies/`, extension release files, management scripts, and `.env`. Do not expose ports 8088 or 8443 from the host.

The generated Caddyfile filters all default Caddy runtime records by deleting the complete `request.uri` and `request.headers` fields (including query, Referer, User-Agent, cookie, and authorization values). Status, method, logger/message, and TLS/ACME diagnostics remain; arbitrary message strings and other components’ logs are not sanitized. When updating an existing deployment, regenerate the Caddyfile and recreate the Caddy container for this filter to take effect.

The front door's optional `FRONTDOOR_DIAGNOSTICS` setting defaults to `0`. Setting it to `1` emits 30-second interval counters for fixed error categories, accepted/active/closed connections, and the active-connection peak; these counters contain no addresses, hostnames, tokens, or traffic contents. Turn it off when the diagnostic run is complete and recreate the frontdoor container to apply the setting.

After start, inspect the actual container health and logs. The installation check should verify domain TLS and authenticated `/__health`; confirm that the public IP TLS certificate is ready before handing out the extension. A successful unit test does not verify the public CONNECT route, Cloudflare forwarding, OAuth, or artifact rendering.

### Migrating from the legacy systemd port-443 mux

An older deployment may have `claude-port443.service` binding TCP 443 with the plaintext mux. The installer does not stop system services automatically. Before starting the new Compose `frontdoor`, inspect `systemctl cat claude-port443.service` and confirm its `ExecStart`/working directory point to this deployment's legacy mux. Do not stop or kill an unrelated process just because it uses port 443; investigate ownership first.

Back up the old unit and config for rollback, and preserve the cookie-encryption key and Compose named volumes. Once the unit is confirmed as this deployment's legacy mux, stop it so Compose can bind 443:

```sh
sudo systemctl stop claude-port443.service
```

Start the new Compose stack and verify domain TLS, authenticated `/__health`, the IP certificate, and the public CONNECT path. After the new deployment is healthy, prevent the legacy unit from starting on reboot while keeping its unit file available:

```sh
sudo systemctl disable claude-port443.service
```

For rollback, stop the Compose `frontdoor` first to release TCP 443, then restore the saved legacy unit/config and start that exact service. Keep the same cookie key and data volumes; do not remove them during rollback.

## DNS and network

1. Point the domain at the server's public IP, or configure the Cloudflare record as proxied if required by the client network.
2. Allow inbound TCP 80 and 443.
3. If using Cloudflare, choose a TLS mode that verifies the origin certificate. Cloudflare handles the domain route; artifact CONNECT still uses the server IP directly.
4. Keep Docker's internal gateway ports private. The Compose file does not publish them.

### Docker network overrides and address collisions

The default transport network uses subnet `172.30.240.0/24`, frontdoor address `172.30.240.2`, and dynamic address range `172.30.240.128/25` for Caddy and gateway. If you override the network, coordinate all three `.env` values: `FRONTDOOR_SUBNET`, `FRONTDOOR_IP`, and `TRANSPORT_IP_RANGE`. The static frontdoor address must be inside the subnet and outside the dynamic range; the dynamic range must fit inside the subnet. Choose a parent subnet that does not overlap existing Docker, host, or VPN networks.

If Docker reports an address allocation collision after changing these values, recreate the Compose network while preserving named volumes:

```sh
docker compose down          # do not add -v; Caddy data and config volumes must remain
docker network ls            # find any leftover <project>_transport network
docker network rm <project>_transport   # only if it still exists after compose down
docker compose up -d
```

Do not remove the named `caddy-data` or `caddy-config` volumes when rebuilding the transport network; they hold certificate and Caddy state.

## Users

Run management commands from the deploy directory:

```sh
./add-user.sh alice
./remove-user.sh alice
```

The first command generates a gateway password and prints it once. The user installs the current Chromium package from `https://<domain>/__ext/`, creates a dedicated browser profile, enters the gateway host/user/password, and completes Claude sign-in. Firefox 140+ packages exist, but secure artifact CONNECT is disabled there; do not offer Firefox as a full-parity client.

Removing a user restarts the gateway and revokes all short-lived proxy sessions. Other users will need to reconnect; their cookie files must remain intact. Check the current script behavior before production operations and make a backup first.

## Operations and recovery

| Task | Action |
|---|---|
| Check service state | `docker compose ps` and inspect `docker compose logs --tail=200 frontdoor gateway caddy` |
| Check authenticated gateway | `curl -u <user> https://<domain>/__health` |
| Create backup | `./backup.sh` (scheduled daily by installer where cron is available) |
| Restore | `./restore.sh backups/state-<date>.tar.gz.enc` |
| Gateway extension downloads | `https://<domain>/__ext/` behind gateway authentication |
| Update | Follow the release instructions and preserve `.env`, cookie files, Caddy data, and backup keys |

The CONNECT token expires after 15 minutes and refreshes while the gateway remains reachable. Certificate or gateway failure intentionally leaves artifact requests blocked. Unknown CDN hosts and Claude/API WebSocket paths are not arbitrary proxy fallbacks.

## Important limits

- Google/Apple OAuth may report `origin_mismatch`; this deployment has no approved workaround.
- Chromium uses a narrowly scoped debugger path for eligible inline artifact documents opened under the exact gateway origin. For a response that needs a header change, it reads the body in memory up to 8 MiB; oversized or failed rewrites are blocked. `X-Frame-Options` is removed for a rewritten eligible response, while the gateway origin is added to an existing `frame-ancestors` only when it already permits Claude. All CSP policies and other directives are preserved. Responses marked `Content-Disposition: attachment` pass through as native browser downloads without body buffering in this compatibility path; this does not establish that every real artifact or download works. Chrome 125+ is required, the browser shows its debugger banner, and DevTools conflicts fail closed. Firefox artifact previews remain unsupported.
- Firefox is fail-closed for artifact/dependency proxy traffic pending safe browser lifecycle evidence.
- A bounded synthetic front-door load test used the deployment image `python:3.13-alpine` with 256 MiB memory, `pids_limit=320`, and `nofile=1024`: 256 connections were handled, 8 beyond the configured limit were rejected, and the next 16 were accepted after slots freed; peak RSS was 45.6 MiB with no OOM. Production connection capacity was raised from 128 to 256 at 07:50 UTC; timeouts were unchanged. This is one synthetic configuration test, not a capacity guarantee for arbitrary traffic.
- Read [SECURITY.md](../SECURITY.md) before exposing the service to users.
