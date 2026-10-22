# Privacy Policy — Gateway Connector for Claude

_Last updated: October 22, 2026. The same policy is published from `server/privacy.html` at `https://<gateway>/privacy`._

## What the extension stores

The extension stores the following data locally in your browser:

- Your gateway host (the domain of your own gateway server)
- Your gateway username and password
- A short-lived proxy session token in browser session storage while secure artifact routing is active

## Where this data goes

Your gateway username and password are sent over HTTPS only to the exact gateway origin you configure. After gateway authentication, the extension can receive a separate short-lived token over HTTPS. It uses that token to authenticate a TLS-protected CONNECT tunnel to the gateway's advertised public IP for supported Claude artifact and dependency hosts. The token is separate from your gateway password. Neither credential is sent to the extension developer.

When the extension renews its proxy session, it sends the exact prior bearer token to the same gateway authority. After successfully issuing a replacement, the gateway revokes that presented token and its tunnels—even if the client changed accounts. This rotation targets only the presented token; separate session-cap, expiry, and user-removal rules can revoke other sessions. A failed token issuance leaves the active token intact. If issuance succeeds but the route check fails, artifact routing stays blocked and the new candidate is retained for retry; the prior token has already been revoked. The gateway removes the secret proxy header before forwarding requests upstream. The configured Caddy runtime logger removes request URI and request header fields; this is a specific log filter, not a guarantee that every component's logs contain no sensitive data.

Before enabling artifact routes, the extension performs a fixed HTTPS `HEAD` with no body to `https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js` through the protected CONNECT route. Redirects are rejected and the check times out after eight seconds. The CDN receives ordinary request metadata from the gateway egress IP; this is a route/authentication warm-up, not a page-content upload. For this exact request, origin `Authorization`/`Cookie` and response `Set-Cookie` headers are removed.

## What the extension does not do

- No analytics, tracking, or telemetry of any kind
- No data collection by the developer — the developer receives nothing
- The extension does not collect or transmit browsing history or page content. Its bundled script changes selected browser APIs on gateway and artifact pages; it does not send page contents to the developer.
- No data is sold or shared with third parties

## Permissions

- **declarativeNetRequest** — routes supported Claude requests through your configured gateway, limits credential attachment to that HTTPS origin, and blocks unsupported direct requests: across the protected browser profile in Chromium, only from Claude pages and artifact frames in Firefox.
- **scripting** — registers the bundled fingerprint script at document start on configured gateway/artifact pages, if the browser accepts registration.
- **storage** — stores gateway host and credentials in browser local storage and temporary proxy session data in session storage.
- **proxy** — configures the HTTPS proxy route for supported artifact/dependency hosts only after a secure gateway session is ready. Chromium uses a PAC script for the dedicated profile. Firefox routes each request from Claude pages and artifact frames individually; other sites keep the browser's own proxy settings.
- **webRequest** — answers the browser's proxy-auth challenge only when the configured CONNECT endpoint, realm, protocol, and protected destination match the active session.
- **webRequestAuthProvider** (Chromium) — supplies the short-lived proxy token to a matching CONNECT challenge, not the gateway password.
- **webRequestBlocking** (Firefox) — applies only to requests from Claude pages and artifact frames: supported artifact/dependency hosts go through the authenticated proxy route, unknown and cleartext destinations are cancelled, and artifact frames receive the same narrow `frame-ancestors`/CORS header adjustments described under **debugger**, without reading response bodies. Requests from other sites are not changed.
- **webNavigation** (Firefox) — reads the frame tree of the current tab to confirm that an artifact frame belongs to a page at the exact gateway origin, and resets that check when a frame navigates. Nothing is stored or sent.
- **debugger** (Chromium) — attaches only to tabs at the exact configured gateway origin and their frames. For an eligible inline HTTPS artifact document response that needs a header change, it reads the body in memory up to 8 MiB; a failed or oversized rewrite is blocked. `X-Frame-Options` is removed for a rewritten response. The gateway origin is added to an existing CSP `frame-ancestors` only if it already allows Claude; all CSP policies and other directives are preserved. Separately, using this same permission, for HTTPS GET/HEAD XHR or Fetch requests to the approved `claudeusercontent.com` and `claudemcpcontent.com` hosts, it may process request/response headers only when the initiating frame's current URL and request `Origin` both exactly match the configured gateway origin. It changes that request `Origin` to `https://claude.ai`, then changes a single matching response `Access-Control-Allow-Origin` back to the gateway origin. This does not use a wildcard, grant credential access, change CSP or other response headers, or read/buffer the response body. Responses without the expected single header remain unchanged; redirects, transport/protocol errors, or a changed/unverified frame are blocked. Responses marked `Content-Disposition: attachment` pass through as native browser downloads without body buffering by this compatibility path; this is not a guarantee that every file download works. The extension does not persist inline bodies it reads for CSP compatibility or send them to the developer. Chrome displays its normal debugging banner while attached; DevTools or another debugger can make artifact handling unavailable. Firefox does not request this permission; it uses the **webRequestBlocking** adapter above.
- **privacy** (Chromium) — disables non-proxied WebRTC UDP and network prediction for the browser profile while configured protection is active; the settings are restored when protection is cleared. The Firefox build does not change these browser-wide settings; it removes WebRTC only inside gateway and artifact pages.
- **alarms** — refreshes and expires short-lived proxy sessions.

In Chrome and Edge, use a dedicated browser profile for this extension: while protection is active, ordinary websites and other tabs in that profile are restricted by its network policy. The Firefox build restricts only Claude pages and artifacts; other sites work as usual.

## Source code

The extension is open source: https://github.com/JFT-git/claude_for_browes

## Contact

Open an issue at https://github.com/JFT-git/claude_for_browes/issues
