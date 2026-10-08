// Claude cookie-injecting gateway — MULTI-USER
//
// Routing:
//   /foo                  -> claude.ai/foo        (relative URLs work)
//   /p/<host>/<path>      -> <host>/<path>        (asset domains)
//
// Multi-user:
//   Caddy authenticates basic_auth and passes the username via X-Remote-User.
//   The gateway loads cookies from <COOKIES_DIR>/<user>.json and injects them
//   into requests to claude.ai. Asset hosts are proxied without cookies.
//
// Self-service login:
//   When a user has no cookies yet, the gateway proxies claude.ai without them,
//   letting the user complete the magic-link login through the gateway. Set-Cookie
//   response headers are captured and merged into the user's cookie file (and are
//   NOT forwarded to the client, so cookies stay server-side).
//
// Security:
//   - Username is sanitized (path-traversal safe).
//   - Authorization / Proxy-Authorization are stripped before forwarding upstream
//     (Claude rejects requests carrying both an auth header and a session cookie).
//   - Cookie values are never logged.

const http = require("http"), https = require("https"), fs = require("fs"), path = require("path");

const COOKIES_DIR = process.env.COOKIES_DIR || "/cookies";
const PORT = parseInt(process.env.PORT || "8088", 10);
const LISTEN = process.env.LISTEN || "0.0.0.0";
const PUBLIC_HOST = process.env.PUBLIC_HOST || "claude.example.com";
const FIXED_UA = process.env.FIXED_UA || "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36";
const UPSTREAM_TIMEOUT_MS = parseInt(process.env.UPSTREAM_TIMEOUT_MS || "30000", 10);

const ALLOWED_HOSTS = new Set(["claude.ai", "www.claude.ai", "assets.claude.ai", "assets-proxy.anthropic.com"]);
const COOKIE_HOSTS = new Set(["claude.ai", "www.claude.ai"]);

// ---- per-user cookie store with mtime cache ----
// cache: user -> { mtime, header, cookies: Map(name->cookieObj) }
const store = new Map();

function sanitizeUser(u) {
  if (!u) return "";
  const s = String(u).replace(/[^a-zA-Z0-9._-]/g, "");
  if (s === "" || s === "." || s === "..") return "";
  return s;
}

function userFile(user) { return path.join(COOKIES_DIR, sanitizeUser(user) + ".json"); }

function loadUser(user) {
  user = sanitizeUser(user);
  if (!user) return null;
  const file = userFile(user);
  let st;
  try { st = fs.statSync(file); } catch (e) { return null; }
  const cached = store.get(user);
  if (cached && cached.mtime === st.mtimeMs) return cached;
  try {
    const d = JSON.parse(fs.readFileSync(file, "utf8"));
    const map = new Map();
    (d.cookies || []).forEach(c => map.set(c.name, c));
    const entry = { mtime: st.mtimeMs, cookies: map };
    entry.header = (d.cookies || []).map(c => c.name + "=" + c.value).join("; ");
    store.set(user, entry);
    console.log("[cookies] user=" + user + " loaded " + map.size);
    return entry;
  } catch (e) { console.error("[cookies] user=" + user + " load failed: " + e.message); return null; }
}

function cookieHeaderFor(user) {
  const e = loadUser(user);
  return e ? e.header : "";
}

// merge Set-Cookie headers into the user's store and persist
function captureSetCookies(user, setCookies) {
  user = sanitizeUser(user);
  if (!user || !setCookies || !setCookies.length) return;
  const file = userFile(user);
  let entry = loadUser(user) || { mtime: 0, cookies: new Map(), header: "" };
  let changed = false;
  for (const sc of setCookies) {
    const pair = sc.split(";")[0];
    const eq = pair.indexOf("=");
    if (eq <= 0) continue;
    const name = pair.slice(0, eq).trim();
    const value = pair.slice(eq + 1).trim();
    if (!name) continue;
    // capture only auth-relevant claude/anthropic cookies
    if (!/session|auth|token|key|user|account|org|intercom|device|activity/i.test(name)) continue;
    const existing = entry.cookies.get(name);
    if (!existing || existing.value !== value) {
      entry.cookies.set(name, { name, value, domain: ".claude.ai", path: "/" });
      changed = true;
    }
  }
  if (!changed) return;
  try {
    fs.mkdirSync(COOKIES_DIR, { recursive: true });
    const arr = Array.from(entry.cookies.values());
    fs.writeFileSync(file, JSON.stringify({ extracted_at: Math.floor(Date.now() / 1000), cookies: arr }, null, 2), { mode: 0o600 });
    entry.header = arr.map(c => c.name + "=" + c.value).join("; ");
    entry.mtime = fs.statSync(file).mtimeMs;
    store.set(user, entry);
    console.log("[cookies] user=" + user + " captured, total=" + arr.length);
  } catch (e) { console.error("[cookies] capture failed: " + e.message); }
}

function pub(h, p) { return "https://" + PUBLIC_HOST + (h === "claude.ai" ? "" : "/p/" + h) + p; }

function rewriteBody(buf, ct) {
  if (!ct || !(ct.includes("text/html") || ct.includes("text/css") || ct.includes("javascript"))) return buf;
  let s = buf.toString("utf8");
  for (const h of ALLOWED_HOSTS) { if (h === "claude.ai") continue; s = s.replace(new RegExp("https?://" + h.replace(/\./g, "\\."), "g"), pub(h, "")); }
  return Buffer.from(s, "utf8");
}

function rewriteCsp(csp) {
  if (!csp) return csp;
  const hosts = ["assets-proxy.anthropic.com", "assets.claude.ai", "a-cdn.claude.ai", "a.claude.ai", "a-cdn.anthropic.com", "s-cdn.anthropic.com"];
  let out = csp;
  for (const h of hosts) { out = out.split(h).join(PUBLIC_HOST); }
  out = out.replace(/\*\.anthropic\.com/g, "*." + PUBLIC_HOST + " *.anthropic.com");
  out = out.replace(/\*\.claude\.ai/g, "*." + PUBLIC_HOST + " *.claude.ai");
  out = out.replace(/\*\.claude\.com/g, "*." + PUBLIC_HOST + " *.claude.com");
  return out;
}

const server = http.createServer((req, res) => {
  if (req.url === "/__health") {
    res.writeHead(200, { "content-type": "application/json" });
    return res.end(JSON.stringify({ ok: true, users: store.size }));
  }
  let host, urlPath;
  const m = req.url.match(/^\/p\/([^\/]+)(\/.*)?$/);
  if (m) { host = m[1]; urlPath = m[2] || "/"; if (!ALLOWED_HOSTS.has(host)) { res.writeHead(403); return res.end("host not allowed"); } }
  else { host = "claude.ai"; urlPath = req.url; }

  // user identity comes from Caddy after basic_auth (gateway is not publicly reachable)
  const user = sanitizeUser(req.headers["x-remote-user"] || "");
  const needsCookies = COOKIE_HOSTS.has(host);
  const cookieHeader = needsCookies ? cookieHeaderFor(user) : "";

  const chunks = [];
  req.on("data", c => chunks.push(c));
  req.on("end", () => {
    const body = Buffer.concat(chunks);
    const headers = { ...req.headers };
    ["host","cookie","origin","referer","x-forwarded-for","x-forwarded-host","x-forwarded-proto","true-client-ip","accept-encoding","authorization","proxy-authorization","x-remote-user"].forEach(k => delete headers[k]);
    headers["host"] = host;
    if (needsCookies && cookieHeader) headers["cookie"] = cookieHeader;
    headers["accept-language"] = "en-US,en;q=0.9";
    headers["user-agent"] = FIXED_UA;
    if (needsCookies) { headers["origin"] = "https://" + host; headers["referer"] = "https://" + host + "/"; }

    const proxyReq = https.request({ hostname: host, port: 443, path: urlPath, method: req.method, headers }, (proxyRes) => {
      const rh = { ...proxyRes.headers };
      // capture session cookies for this user (self-service login), never forward them
      if (needsCookies && rh["set-cookie"]) captureSetCookies(user, rh["set-cookie"]);
      delete rh["set-cookie"];
      if (rh["content-security-policy"]) rh["content-security-policy"] = rewriteCsp(rh["content-security-policy"]);
      if (rh["location"]) { for (const h of ALLOWED_HOSTS) { rh["location"] = rh["location"].replace(new RegExp("https?://" + h, "g"), pub(h, "")); } }
      const ct = rh["content-type"] || "";
      if (ct.includes("text/html") || ct.includes("text/css") || ct.includes("javascript")) {
        const bc = []; proxyRes.on("data", c => bc.push(c)); proxyRes.on("end", () => {
          const rb = rewriteBody(Buffer.concat(bc), ct);
          delete rh["content-length"]; rh["content-length"] = rb.length;
          if (ct.includes("text/html")) { rh["cache-control"] = "no-cache, no-store, must-revalidate"; }
          else { rh["cache-control"] = "public, max-age=86400"; }
          console.log("[resp] " + (user || "-") + " " + host + " " + urlPath + " -> " + proxyRes.statusCode + " (rewritten)");
          res.writeHead(proxyRes.statusCode, rh); res.end(rb);
        });
      } else {
        console.log("[resp] " + (user || "-") + " " + host + " " + urlPath + " -> " + proxyRes.statusCode);
        res.writeHead(proxyRes.statusCode, rh); proxyRes.pipe(res);
      }
    });
    proxyReq.setTimeout(UPSTREAM_TIMEOUT_MS, () => proxyReq.destroy(new Error("timeout")));
    proxyReq.on("error", e => { console.error("[upstream " + host + "] " + e.message); if (!res.headersSent) { res.writeHead(502); res.end("bad gateway"); } else res.end(); });
    if (body.length) proxyReq.write(body);
    proxyReq.end();
  });
  req.on("error", () => {});
});
server.listen(PORT, LISTEN, () => console.log("[gateway] multi-user listening on " + LISTEN + ":" + PORT + " cookies dir " + COOKIES_DIR));
