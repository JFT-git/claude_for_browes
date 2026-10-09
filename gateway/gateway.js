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
const crypto = require("crypto");

function parseKey(v) {
  if (!v) return null;
  const k = /^[0-9a-fA-F]{64}$/.test(v) ? Buffer.from(v, "hex") : Buffer.from(v, "base64");
  if (k.length !== 32) throw new Error("COOKIES_KEY must be 32 bytes (64 hex chars or base64)");
  return k;
}

const cfg = {
  cookiesDir: process.env.COOKIES_DIR || "/cookies",
  port: parseInt(process.env.PORT || "8088", 10),
  listen: process.env.LISTEN || "0.0.0.0",
  publicHost: process.env.PUBLIC_HOST || "claude.example.com",
  // User-Agent presented to claude.ai. Default: pass the browser's own UA (and client hints)
  // through unchanged so headers and navigator.* in the page stay consistent.
  fixedUA: process.env.FIXED_UA || "",
  // AES-256-GCM key for cookie files at rest (optional but recommended)
  cookiesKey: parseKey(process.env.COOKIES_KEY),
  adminUsers: (process.env.ADMIN_USERS || "").split(",").map(x => x.trim()).filter(Boolean),
  extDir: process.env.EXT_DIR || "/ext",
  // brute-force protection (failed basic_auth attempts reported by Caddy)
  authMaxFails: parseInt(process.env.AUTH_MAX_FAILS || "10", 10),
  authWindowMs: parseInt(process.env.AUTH_WINDOW_MS || String(15 * 60 * 1000), 10),
  authBanMs: parseInt(process.env.AUTH_BAN_MS || String(15 * 60 * 1000), 10),
  // in-memory cache of public static assets
  cacheMaxBytes: parseInt(process.env.CACHE_MAX_BYTES || String(64 * 1024 * 1024), 10),
  cacheMaxItem: 5 * 1024 * 1024,
  // optional Telegram alerts
  tgToken: process.env.TELEGRAM_BOT_TOKEN || "",
  tgChat: process.env.TELEGRAM_CHAT_ID || "",
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

// ---- optional encryption at rest (AES-256-GCM). Plain files are still readable (migration).
function seal(plain) {
  if (!cfg.cookiesKey) return plain;
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", cfg.cookiesKey, iv);
  const data = Buffer.concat([c.update(plain, "utf8"), c.final()]);
  return JSON.stringify({ enc: 1, iv: iv.toString("base64"), tag: c.getAuthTag().toString("base64"), data: data.toString("base64") });
}
function unseal(raw) {
  if (!raw.trim()) return raw;
  let d; try { d = JSON.parse(raw); } catch (e) { return raw; }
  if (!d || d.enc !== 1) return raw;
  if (!cfg.cookiesKey) throw new Error("jar is encrypted but COOKIES_KEY is not set");
  const dc = crypto.createDecipheriv("aes-256-gcm", cfg.cookiesKey, Buffer.from(d.iv, "base64"));
  dc.setAuthTag(Buffer.from(d.tag, "base64"));
  return Buffer.concat([dc.update(Buffer.from(d.data, "base64")), dc.final()]).toString("utf8");
}
// Encrypt every plain jar on startup (after COOKIES_KEY was introduced).
function migrateAll() {
  if (!cfg.cookiesKey) return 0;
  let n = 0;
  let files = []; try { files = fs.readdirSync(cfg.cookiesDir); } catch (e) { return 0; }
  for (const f of files) {
    if (!f.endsWith(".json")) continue;
    const file = path.join(cfg.cookiesDir, f);
    try {
      const raw = fs.readFileSync(file, "utf8");
      const d = raw.trim() ? JSON.parse(raw) : null;
      if (d && d.enc === 1) continue;
      const tmp = file + "." + process.pid + ".tmp";
      fs.writeFileSync(tmp, seal(raw.trim() ? raw : '{"cookies":[]}'), { mode: 0o600 });
      fs.renameSync(tmp, file); n++;
    } catch (e) { console.error("[cookies] migrate " + f + ": " + e.message); }
  }
  return n;
}

function loadJar(user) {
  const file = userFile(user);
  if (!file) return null;
  let st;
  try { st = fs.statSync(file); } catch (e) { return null; }
  const cached = jars.get(user);
  if (cached && cached.mtime === st.mtimeMs) return cached;
  const jar = { mtime: st.mtimeMs, cookies: new Map() };
  try {
    const raw = unseal(fs.readFileSync(file, "utf8"));
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
    const data = seal(JSON.stringify({ saved_at: t, cookies: Array.from(jar.cookies.values()) }, null, 2));
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

// ------------------------------------------------ session monitoring / alerts ----

const stats = new Map(); // user -> { lastSeen, expired, alertedAt }

function hasSession(user) {
  const jar = loadJar(user);
  if (!jar) return false;
  const t = nowSec();
  const c = jar.cookies.get("sessionKey");
  return !!c && !(c.expires > 0 && c.expires < t);
}
function statOf(user) {
  let s = stats.get(user);
  if (!s) { s = { lastSeen: 0, expired: false, alertedAt: 0 }; stats.set(user, s); }
  return s;
}
function sessionState(user) {
  if (!hasSession(user)) return "none";
  return statOf(user).expired ? "expired" : "ok";
}

function notify(text) {
  if (!cfg.tgToken || !cfg.tgChat) return;
  const body = JSON.stringify({ chat_id: cfg.tgChat, text: text, disable_web_page_preview: true });
  const r = https.request({ hostname: "api.telegram.org", port: 443, method: "POST", path: "/bot" + cfg.tgToken + "/sendMessage",
    headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) }, timeout: 5000 }, (x) => x.resume());
  r.on("error", () => {}); r.on("timeout", () => r.destroy());
  r.end(body);
}

// Called for every claude.ai response that carried the user's session cookie.
function noteClaudeResponse(user, urlPath, status, sentSession) {
  if (!user) return;
  const s = statOf(user);
  s.lastSeen = Date.now();
  if (!sentSession || !urlPath.startsWith("/api/")) return;
  if (status === 401) {
    if (!s.expired) {
      s.expired = true;
      if (Date.now() - s.alertedAt > 6 * 3600 * 1000) {
        s.alertedAt = Date.now();
        notify("⚠️ Claude gateway: сессия пользователя «" + user + "» истекла — нужен повторный вход.");
      }
    }
  } else if (status === 200 && urlPath.startsWith("/api/organizations")) {
    s.expired = false;
  }
}

function listUsers() {
  let files = []; try { files = fs.readdirSync(cfg.cookiesDir); } catch (e) { /* none */ }
  return files.filter(f => f.endsWith(".json")).map(f => f.slice(0, -5)).sort().map(u => {
    const s = statOf(u);
    const jar = loadJar(u);
    return { user: u, session: sessionState(u), cookies: jar ? jar.cookies.size : 0,
      lastSeen: s.lastSeen ? new Date(s.lastSeen).toISOString() : null };
  });
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

function buildUpstreamHeaders(inHeaders, host, cookieHeader, opts) {
  const out = {};
  for (const [k, v] of Object.entries(inHeaders)) {
    const key = k.toLowerCase();
    if (DROP_EXACT.has(key) || DROP_PREFIX.some(p => key.startsWith(p))) continue;
    out[key] = v;
  }
  out["host"] = host;
  out["accept-language"] = "en-US,en;q=0.9";
  if (opts && opts.ws) { out["connection"] = "Upgrade"; out["upgrade"] = "websocket"; out["origin"] = "https://claude.ai"; }
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

// ------------------------------------------------ brute-force protection ----
// Caddy asks us (forward_auth) whether an IP is banned BEFORE checking the password,
// and reports every failed basic_auth attempt to /__authfail.

const fails = new Map(); // ip -> { times: [], bannedUntil }

function cleanIp(v) {
  v = String(v || "").trim();
  return /^[0-9a-fA-F:.]{2,45}$/.test(v) ? v : "unknown";
}
function isBanned(ip) {
  const f = fails.get(ip);
  return !!f && f.bannedUntil > Date.now();
}
function recordFail(ip) {
  const now = Date.now();
  let f = fails.get(ip);
  if (!f) { f = { times: [], bannedUntil: 0 }; fails.set(ip, f); }
  f.times = f.times.filter(t => now - t < cfg.authWindowMs);
  f.times.push(now);
  if (f.times.length >= cfg.authMaxFails && f.bannedUntil <= now) {
    f.bannedUntil = now + cfg.authBanMs;
    f.times = [];
    console.log("[auth] ip " + ip + " banned for " + Math.round(cfg.authBanMs / 60000) + " min");
    notify("🚫 Claude gateway: IP " + ip + " заблокирован на " + Math.round(cfg.authBanMs / 60000) + " мин после " + cfg.authMaxFails + " неудачных попыток входа.");
  }
  if (fails.size > 10000) {
    for (const [k, v] of fails) if (v.bannedUntil <= now && v.times.every(t => now - t >= cfg.authWindowMs)) fails.delete(k);
  }
  return isBanned(ip);
}

// ------------------------------------------------ static asset cache (LRU) ----

const CACHE_HOSTS = new Set(["assets.claude.ai", "assets-proxy.anthropic.com"]);
const cache = new Map(); // key -> { status, headers, body }
let cacheBytes = 0;

function cacheGet(k) {
  const e = cache.get(k);
  if (e) { cache.delete(k); cache.set(k, e); }
  return e;
}
function cachePut(k, e) {
  const size = e.body.length;
  if (size > cfg.cacheMaxItem || size > cfg.cacheMaxBytes) return;
  const old = cache.get(k);
  if (old) { cacheBytes -= old.body.length; cache.delete(k); }
  while (cacheBytes + size > cfg.cacheMaxBytes && cache.size) {
    const first = cache.keys().next().value;
    cacheBytes -= cache.get(first).body.length;
    cache.delete(first);
  }
  cache.set(k, e);
  cacheBytes += size;
}

// ------------------------------------------------ extension download page ----

const EXT_FILES = { "claude-gateway-chrome.zip": "application/zip", "claude-gateway-firefox.zip": "application/zip" };

function extIndexHtml() {
  const h = cfg.publicHost;
  return '<!doctype html><meta charset="utf-8"><title>Claude Gateway — extension</title>' +
    '<body style="font-family:-apple-system,sans-serif;max-width:640px;margin:40px auto;padding:0 16px;line-height:1.5">' +
    '<h2>Claude Gateway — расширение</h2>' +
    '<p>Сборка уже настроена на <b>' + h + '</b>.</p><ul>' +
    '<li><a href="/__ext/claude-gateway-chrome.zip">Chrome / Edge (zip)</a> — распакуйте, <code>chrome://extensions</code> → режим разработчика → «Загрузить распакованное»</li>' +
    '<li><a href="/__ext/claude-gateway-firefox.zip">Firefox ≥ 128 (zip)</a> — распакуйте, <code>about:debugging</code> → «Load Temporary Add-on» → manifest.json</li></ul>' +
    '<p>В настройках расширения введите хост <code>' + h + '</code>, ваш логин и пароль.</p></body>';
}

function serveExt(req, res) {
  const name = req.url.split("?")[0].slice("/__ext/".length);
  if (name === "" || name === "index.html") {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
    return res.end(extIndexHtml());
  }
  if (!Object.prototype.hasOwnProperty.call(EXT_FILES, name)) { res.writeHead(404); return res.end("not found"); }
  const file = path.join(cfg.extDir, name);
  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) { res.writeHead(404); return res.end("not found"); }
    res.writeHead(200, { "content-type": EXT_FILES[name], "content-length": st.size,
      "content-disposition": 'attachment; filename="' + name + '"', "cache-control": "no-store" });
    fs.createReadStream(file).pipe(res);
  });
}

// --------------------------------------------------------------- websockets ----

function resolveTarget(rawUrl) {
  let host, urlPath;
  const m = rawUrl.match(/^\/p\/([^\/?#]+)(\/.*)?$/);
  if (m) {
    host = m[1].toLowerCase();
    urlPath = m[2] || "/";
    if (!ALLOWED_HOSTS.has(host)) return null;
  } else { host = "claude.ai"; urlPath = rawUrl; }
  if (!urlPath.startsWith("/")) return null;
  return { host, urlPath };
}

function handleUpgrade(req, socket) {
  socket.on("error", () => socket.destroy());
  const t = resolveTarget(req.url);
  if (!t) { socket.end("HTTP/1.1 403 Forbidden\r\nconnection: close\r\ncontent-length: 0\r\n\r\n"); return; }
  const user = sanitizeUser(req.headers["x-remote-user"]);
  const cookie = COOKIE_HOSTS.has(t.host) ? cookieHeaderFor(user) : "";
  const headers = buildUpstreamHeaders(req.headers, t.host, cookie, { ws: true });
  const preq = https.request({ hostname: t.host, port: 443, path: t.urlPath, method: "GET", headers });
  preq.on("upgrade", (pres, psock, phead) => {
    let out = "HTTP/1.1 101 Switching Protocols\r\n";
    for (let i = 0; i < pres.rawHeaders.length; i += 2) {
      if (pres.rawHeaders[i].toLowerCase() === "set-cookie") continue;
      out += pres.rawHeaders[i] + ": " + pres.rawHeaders[i + 1] + "\r\n";
    }
    socket.write(out + "\r\n");
    if (phead && phead.length) socket.write(phead);
    psock.on("error", () => socket.destroy());
    psock.on("close", () => socket.destroy());
    socket.on("close", () => psock.destroy());
    psock.pipe(socket); socket.pipe(psock);
    console.log("[ws] " + (user || "-") + " " + t.host + " " + redactPath(t.urlPath) + " -> 101");
  });
  preq.on("response", (pres) => {
    socket.end("HTTP/1.1 " + pres.statusCode + " " + (pres.statusMessage || "") + "\r\nconnection: close\r\ncontent-length: 0\r\n\r\n");
    pres.resume();
    console.log("[ws] " + (user || "-") + " " + t.host + " " + redactPath(t.urlPath) + " -> " + pres.statusCode);
  });
  preq.on("error", (e) => { console.error("[ws] " + t.host + " " + e.message); socket.destroy(); });
  preq.end();
}

// ------------------------------------------------------------------ server ----

function json(res, code, obj) {
  res.writeHead(code, { "content-type": "application/json", "cache-control": "no-store" });
  res.end(JSON.stringify(obj));
}

function createServer() {
  const server = http.createServer((req, res) => {
    const pathOnly = req.url.split("?")[0];

    if (pathOnly === "/__ban-check") {
      if (isBanned(cleanIp(req.headers["x-client-ip"]))) { res.writeHead(429, { "retry-after": "900" }); return res.end(); }
      res.writeHead(200); return res.end("ok");
    }
    if (pathOnly === "/__authfail") {
      const banned = recordFail(cleanIp(req.headers["x-client-ip"]));
      res.writeHead(banned ? 429 : 401); return res.end();
    }
    const user = sanitizeUser(req.headers["x-remote-user"]);
    if (pathOnly === "/__health") {
      return json(res, 200, { ok: true, users: jars.size, user: user, session: user ? sessionState(user) : "none" });
    }
    if (pathOnly === "/__admin/status") {
      if (!user || !cfg.adminUsers.includes(user)) { res.writeHead(403); return res.end("forbidden"); }
      return json(res, 200, { users: listUsers(), cacheItems: cache.size, cacheBytes: cacheBytes, bannedIps: Array.from(fails.values()).filter(f => f.bannedUntil > Date.now()).length });
    }
    if (pathOnly === "/__ext" || pathOnly.startsWith("/__ext/")) {
      if (!user) { res.writeHead(401); return res.end(); }
      return serveExt(req, res);
    }

    const t = resolveTarget(req.url);
    if (!t) { res.writeHead(/^\/p\//.test(req.url) ? 403 : 400); return res.end("not allowed"); }
    const host = t.host, urlPath = t.urlPath;
    const sendsCookies = COOKIE_HOSTS.has(host);
    const cookieHeader = sendsCookies ? cookieHeaderFor(user) : "";
    const sentSession = cookieHeader.includes("sessionKey=");
    const headers = buildUpstreamHeaders(req.headers, host, cookieHeader);
    const logPath = redactPath(urlPath);
    if (user) statOf(user).lastSeen = Date.now();

    const cacheable = req.method === "GET" && CACHE_HOSTS.has(host) && !req.headers["range"];
    const cacheKey = host + urlPath;
    if (cacheable) {
      const hit = cacheGet(cacheKey);
      if (hit) {
        res.writeHead(hit.status, Object.assign({}, hit.headers, { "content-length": hit.body.length, "x-cache": "HIT" }));
        return res.end(hit.body);
      }
    }

    const proxyReq = https.request({ hostname: host, port: 443, path: urlPath, method: req.method, headers }, (up) => {
      const rh = {};
      for (const [k, v] of Object.entries(up.headers)) if (!DROP_RESPONSE.has(k)) rh[k] = v;

      if (sendsCookies && user) {
        const had = hasSession(user);
        if (up.headers["set-cookie"]) {
          captureSetCookies(user, up.headers["set-cookie"]);
          const st = statOf(user);
          if (hasSession(user)) st.expired = false;
          else if (had) notify("ℹ️ Claude gateway: сессия пользователя «" + user + "» завершена (выход/удаление cookie).");
        }
        noteClaudeResponse(user, urlPath, up.statusCode, sentSession);
      }
      if (rh["content-security-policy"]) rh["content-security-policy"] = rewriteCsp(rh["content-security-policy"]);
      if (rh["location"]) {
        for (const h of ALLOWED_HOSTS) rh["location"] = rh["location"].replace(new RegExp("https?://" + h.replace(/\./g, "\\."), "g"), pub(h, ""));
      }

      const ct = String(rh["content-type"] || "");
      const rewritable = ct.includes("text/html") || ct.includes("text/css") || ct.includes("javascript");
      const cl = parseInt(up.headers["content-length"] || "0", 10);
      const canCache = cacheable && up.statusCode === 200 && cl > 0 && cl <= cfg.cacheMaxItem;

      if (!rewritable && !canCache) {
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
        let body = Buffer.concat(chunks);
        if (rewritable) {
          body = rewriteBody(body, ct);
          rh["cache-control"] = ct.includes("text/html") ? "no-cache, no-store, must-revalidate" : "public, max-age=86400";
        }
        rh["content-length"] = body.length;
        if (canCache) {
          const stored = Object.assign({}, rh); delete stored["date"]; delete stored["age"];
          cachePut(cacheKey, { status: up.statusCode, headers: stored, body: body });
        }
        console.log("[resp] " + (user || "-") + " " + host + " " + logPath + " -> " + up.statusCode + (rewritable ? " (rewritten)" : ""));
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
  server.on("upgrade", handleUpgrade);
  return server;
}

module.exports = {
  cfg, ALLOWED_HOSTS, COOKIE_HOSTS,
  sanitizeUser, userFile, loadJar, cookieHeaderFor, captureSetCookies,
  buildUpstreamHeaders, rewriteBody, rewriteCsp, redactPath, createServer,
  seal, unseal, migrateAll, isBanned, recordFail, cleanIp, cacheGet, cachePut, sessionState, noteClaudeResponse, listUsers,
};

if (require.main === module) {
  const n = migrateAll();
  if (n) console.log("[cookies] encrypted " + n + " plain jar(s)");
  console.log("[gateway] cookies at rest: " + (cfg.cookiesKey ? "encrypted" : "PLAIN (set COOKIES_KEY)") +
    "; telegram: " + (cfg.tgToken ? "on" : "off") + "; admins: " + (cfg.adminUsers.join(",") || "-"));
  createServer().listen(cfg.port, cfg.listen, () =>
    console.log("[gateway] listening on " + cfg.listen + ":" + cfg.port + " public host " + cfg.publicHost));
}
