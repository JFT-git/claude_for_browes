// Claude gateway — multi-user cookie-injecting reverse proxy (no dependencies).
//
// Routing
//   /foo                -> https://claude.ai/foo        (relative URLs keep working)
//   /p/<host>/<path>    -> https://<host>/<path>        (allow-listed asset/API hosts only)
//
// Identity
//   Caddy performs basic_auth and sets X-Remote-User to the authenticated user.
//   The gateway listens only on the private docker network and trusts that header.
//   The user name selects <COOKIES_DIR>/<user>.json (a per-user cookie jar).
//
// Self-service login
//   Without cookies the gateway proxies claude.ai anonymously so the user can finish
//   the magic-link login. Set-Cookie headers from claude.ai are stored in the user's
//   jar and are NEVER forwarded to the browser.
//
// What this file deliberately does (see SECURITY.md)
//   * strips every header that could reveal the real client (IP, country, proxy chain)
//   * strips Authorization (claude.ai rejects "auth header + session cookie")
//   * sends session cookies only to claude.ai (not to asset or API hosts)
//   * never logs cookie values, query strings or request bodies
//   * streams request bodies (no unbounded buffering of uploads)

"use strict";
const http = require("http");
const https = require("https");
const fs = require("fs");
const path = require("path");

const cfg = {
  cookiesDir: process.env.COOKIES_DIR || "/cookies",
  port: parseInt(process.env.PORT || "8088", 10),
  listen: process.env.LISTEN || "0.0.0.0",
  publicHost: process.env.PUBLIC_HOST || "claude.example.com",
  // User-Agent presented to claude.ai. Empty string = pass the browser's own UA through.
  fixedUA: process.env.FIXED_UA === undefined
    ? "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36"
    : process.env.FIXED_UA,
  upstreamIdleMs: parseInt(process.env.UPSTREAM_TIMEOUT_MS || "120000", 10),
  maxRewriteBytes: parseInt(process.env.MAX_REWRITE_BYTES || String(20 * 1024 * 1024), 10),
  maxCookies: 100,
  maxCookieValue: 8192,
};

const ALLOWED_HOSTS = new Set([
  "claude.ai", "www.claude.ai", "assets.claude.ai", "assets-proxy.anthropic.com", "api.anthropic.com",
]);
// Session cookies are sent ONLY to these hosts.
const COOKIE_HOSTS = new Set(["claude.ai", "www.claude.ai"]);

// ---------------------------------------------------------------- identity ----

function sanitizeUser(u) {
  if (u === undefined || u === null) return "";
  const s = String(u).replace(/[^a-zA-Z0-9._-]/g, "");
  if (s === "" || s === "." || s === ".." || s.length > 64) return "";
  return s;
}

function userFile(user) {
  const u = sanitizeUser(user);
  if (!u) return null;
  const file = path.join(cfg.cookiesDir, u + ".json");
  // defence in depth: the resolved path must stay inside the cookie directory
  if (path.dirname(path.resolve(file)) !== path.resolve(cfg.cookiesDir)) return null;
  return file;
}

// -------------------------------------------------------------- cookie jar ----
// jar entry: { mtime, cookies: Map(name -> {name,value,expires}) }

const jars = new Map();

function nowSec() { return Math.floor(Date.now() / 1000); }

function loadJar(user) {
  const file = userFile(user);
  if (!file) return null;
  let st;
  try { st = fs.statSync(file); } catch (e) { return null; }
  const cached = jars.get(user);
  if (cached && cached.mtime === st.mtimeMs) return cached;
  const jar = { mtime: st.mtimeMs, cookies: new Map() };
  try {
    const raw = fs.readFileSync(file, "utf8");
    if (raw.trim()) {
      const d = JSON.parse(raw);
      for (const c of (d.cookies || [])) {
        if (c && typeof c.name === "string" && typeof c.value === "string") {
          jar.cookies.set(c.name, { name: c.name, value: c.value, expires: Number(c.expires) || 0 });
        }
      }
    }
  } catch (e) {
    console.error("[cookies] user=" + user + " unreadable jar: " + e.message);
  }
  jars.set(user, jar);
  return jar;
}

function cookieHeaderFor(user) {
  const jar = loadJar(user);
  if (!jar) return "";
  const t = nowSec();
  const parts = [];
  for (const c of jar.cookies.values()) {
    if (c.expires > 0 && c.expires < t) continue; // expired
    parts.push(c.name + "=" + c.value);
  }
  return parts.join("; ");
}

// Merge Set-Cookie headers from claude.ai into the user's jar (a tiny cookie-jar).
function captureSetCookies(user, setCookies) {
  const file = userFile(user);
  if (!file || !Array.isArray(setCookies) || !setCookies.length) return false;
  const jar = loadJar(user) || { mtime: 0, cookies: new Map() };
  let changed = false;
  const t = nowSec();

  for (const sc of setCookies) {
    const segs = String(sc).split(";");
    const eq = segs[0].indexOf("=");
    if (eq <= 0) continue;
    const name = segs[0].slice(0, eq).trim();
    const value = segs[0].slice(eq + 1).trim();
    if (!name || name.length > 256) continue;

    let expires = 0, remove = value === "";
    for (const a of segs.slice(1)) {
      const i = a.indexOf("=");
      const k = (i < 0 ? a : a.slice(0, i)).trim().toLowerCase();
      const v = i < 0 ? "" : a.slice(i + 1).trim();
      if (k === "max-age") {
        const n = parseInt(v, 10);
        if (!Number.isNaN(n)) { if (n <= 0) remove = true; else expires = t + n; }
      } else if (k === "expires" && !expires) {
        const ms = Date.parse(v);
        if (!Number.isNaN(ms)) { const s = Math.floor(ms / 1000); if (s <= t) remove = true; else expires = s; }
      }
    }

    if (remove) {                       // logout / cookie deletion
      if (jar.cookies.delete(name)) changed = true;
      continue;
    }
    if (value.length > cfg.maxCookieValue) continue;
    const prev = jar.cookies.get(name);
    if (!prev || prev.value !== value || prev.expires !== expires) {
      if (!prev && jar.cookies.size >= cfg.maxCookies) continue;
      jar.cookies.set(name, { name, value, expires });
      changed = true;
    }
  }
  if (!changed) return false;

  try {
    fs.mkdirSync(cfg.cookiesDir, { recursive: true, mode: 0o700 });
    const tmp = file + "." + process.pid + ".tmp";
    const data = JSON.stringify({ saved_at: t, cookies: Array.from(jar.cookies.values()) }, null, 2);
    fs.writeFileSync(tmp, data, { mode: 0o600 });
    fs.renameSync(tmp, file);           // atomic replace
    jar.mtime = fs.statSync(file).mtimeMs;
    jars.set(user, jar);
    console.log("[cookies] user=" + user + " jar updated (" + jar.cookies.size + " cookies)");
    return true;
  } catch (e) {
    console.error("[cookies] user=" + user + " cannot persist jar: " + e.message);
    return false;
  }
}

// ------------------------------------------------------- header handling -----

// Anything that can reveal the real client, the proxy chain, or Cloudflare's view of the client.
const DROP_EXACT = new Set([
  "host", "cookie", "origin", "referer", "accept-encoding",
  "authorization", "proxy-authorization", "x-remote-user",
  "forwarded", "via", "x-real-ip", "true-client-ip", "x-client-ip", "client-ip",
  "cdn-loop", "x-request-id", "x-correlation-id", "dnt",
  // hop-by-hop
  "connection", "keep-alive", "proxy-connection", "te", "trailer", "upgrade", "transfer-encoding",
]);
const DROP_PREFIX = ["cf-", "x-forwarded-", "x-envoy-", "x-amzn-", "x-azure-", "fastly-", "x-vercel-"];

function buildUpstreamHeaders(inHeaders, host, cookieHeader) {
  const out = {};
  for (const [k, v] of Object.entries(inHeaders)) {
    const key = k.toLowerCase();
    if (DROP_EXACT.has(key) || DROP_PREFIX.some(p => key.startsWith(p))) continue;
    out[key] = v;
  }
  out["host"] = host;
  out["accept-language"] = "en-US,en;q=0.9";
  if (cfg.fixedUA) {
    out["user-agent"] = cfg.fixedUA;
    // keep client hints consistent with the UA we present
    if (out["sec-ch-ua-platform"]) out["sec-ch-ua-platform"] = '"Linux"';
    if (out["sec-ch-ua-platform-version"]) delete out["sec-ch-ua-platform-version"];
  }
  if (COOKIE_HOSTS.has(host)) {
    if (cookieHeader) out["cookie"] = cookieHeader;
    out["origin"] = "https://" + host;       // never expose the gateway domain upstream
    out["referer"] = "https://" + host + "/";
  }
  return out;
}

// Response headers that would make the browser talk to Anthropic/Cloudflare endpoints
// on behalf of the gateway origin, or advertise an alternative (HTTP/3) route.
const DROP_RESPONSE = new Set(["set-cookie", "report-to", "reporting-endpoints", "nel", "alt-svc", "content-length"]);

function pub(h, p) { return "https://" + cfg.publicHost + (h === "claude.ai" ? "" : "/p/" + h) + p; }

function rewriteBody(buf, ct) {
  if (!ct || !(ct.includes("text/html") || ct.includes("text/css") || ct.includes("javascript"))) return buf;
  let s = buf.toString("utf8");
  for (const h of ALLOWED_HOSTS) {
    if (h === "claude.ai") continue;
    s = s.replace(new RegExp("https?://" + h.replace(/\./g, "\\."), "g"), pub(h, ""));
  }
  if (ct.includes("javascript")) {
    // OAuth (Google/Apple) validates the JS origin. The page runs on the gateway
    // host, so libraries that read location.origin would send the wrong origin.
    // Make them see claude.ai instead. Requests to claude.ai are redirected back
    // to the gateway by the extension, so this is safe.
    s = s.replace(/(window|self|globalThis)\.location\.origin/g, '"https://claude.ai"');
    s = s.replace(/([^.\w])location\.origin/g, '$1"https://claude.ai"');
  }
  return Buffer.from(s, "utf8");
}

function rewriteCsp(csp) {
  if (!csp) return csp;
  let out = csp;
  for (const h of ["assets-proxy.anthropic.com", "assets.claude.ai", "a-cdn.claude.ai", "a.claude.ai", "a-cdn.anthropic.com", "s-cdn.anthropic.com"]) {
    out = out.split(h).join(cfg.publicHost);
  }
  out = out.replace(/\*\.anthropic\.com/g, "*." + cfg.publicHost + " *.anthropic.com");
  out = out.replace(/\*\.claude\.ai/g, "*." + cfg.publicHost + " *.claude.ai");
  out = out.replace(/\*\.claude\.com/g, "*." + cfg.publicHost + " *.claude.com");
  return out;
}

// Logs must never contain query strings (magic-link tokens, OAuth codes, ...).
function redactPath(p) {
  const clean = String(p).split("?")[0].split("#")[0];
  return clean.length > 120 ? clean.slice(0, 120) + "…" : clean;
}

// ------------------------------------------------------------------ server ----

function createServer() {
  return http.createServer((req, res) => {
    if (req.url === "/__health") {
      res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
      return res.end(JSON.stringify({ ok: true, users: jars.size }));
    }

    let host, urlPath;
    const m = req.url.match(/^\/p\/([^\/?#]+)(\/.*)?$/);
    if (m) {
      host = m[1].toLowerCase();
      urlPath = m[2] || "/";
      if (!ALLOWED_HOSTS.has(host)) { res.writeHead(403); return res.end("host not allowed"); }
    } else {
      host = "claude.ai";
      urlPath = req.url;
    }
    if (!urlPath.startsWith("/")) { res.writeHead(400); return res.end("bad request"); }

    const user = sanitizeUser(req.headers["x-remote-user"]);
    const sendsCookies = COOKIE_HOSTS.has(host);
    const headers = buildUpstreamHeaders(req.headers, host, sendsCookies ? cookieHeaderFor(user) : "");
    const logPath = redactPath(urlPath);

    const proxyReq = https.request({ hostname: host, port: 443, path: urlPath, method: req.method, headers }, (up) => {
      const rh = {};
      for (const [k, v] of Object.entries(up.headers)) if (!DROP_RESPONSE.has(k)) rh[k] = v;

      if (sendsCookies && user && up.headers["set-cookie"]) captureSetCookies(user, up.headers["set-cookie"]);
      if (rh["content-security-policy"]) rh["content-security-policy"] = rewriteCsp(rh["content-security-policy"]);
      if (rh["location"]) {
        for (const h of ALLOWED_HOSTS) rh["location"] = rh["location"].replace(new RegExp("https?://" + h.replace(/\./g, "\\."), "g"), pub(h, ""));
      }

      const ct = String(rh["content-type"] || "");
      const rewritable = ct.includes("text/html") || ct.includes("text/css") || ct.includes("javascript");
      if (!rewritable) {
        if (up.headers["content-length"]) rh["content-length"] = up.headers["content-length"];
        console.log("[resp] " + (user || "-") + " " + host + " " + logPath + " -> " + up.statusCode);
        res.writeHead(up.statusCode, rh);
        up.pipe(res);
        return;
      }
      const chunks = []; let size = 0, aborted = false;
      up.on("data", (c) => {
        size += c.length;
        if (size > cfg.maxRewriteBytes) { aborted = true; up.destroy(); if (!res.headersSent) { res.writeHead(502); } res.end(); return; }
        chunks.push(c);
      });
      up.on("end", () => {
        if (aborted) return;
        const body = rewriteBody(Buffer.concat(chunks), ct);
        rh["content-length"] = body.length;
        rh["cache-control"] = ct.includes("text/html") ? "no-cache, no-store, must-revalidate" : "public, max-age=86400";
        console.log("[resp] " + (user || "-") + " " + host + " " + logPath + " -> " + up.statusCode + " (rewritten)");
        res.writeHead(up.statusCode, rh);
        res.end(body);
      });
    });

    proxyReq.setTimeout(cfg.upstreamIdleMs, () => proxyReq.destroy(new Error("upstream idle timeout")));
    proxyReq.on("error", (e) => {
      console.error("[upstream] " + host + " " + logPath + " " + e.message);
      if (!res.headersSent) { res.writeHead(502, { "content-type": "text/plain" }); res.end("bad gateway"); } else res.end();
    });
    req.on("aborted", () => proxyReq.destroy());
    req.pipe(proxyReq); // stream the body — no buffering of uploads
  });
}

module.exports = {
  cfg, ALLOWED_HOSTS, COOKIE_HOSTS,
  sanitizeUser, userFile, loadJar, cookieHeaderFor, captureSetCookies,
  buildUpstreamHeaders, rewriteBody, rewriteCsp, redactPath, createServer,
};

if (require.main === module) {
  createServer().listen(cfg.port, cfg.listen, () =>
    console.log("[gateway] listening on " + cfg.listen + ":" + cfg.port + " public host " + cfg.publicHost));
}
