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
const net = require("net");
const tls = require("tls");
const dns = require("dns").promises;
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
  // CONNECT is TLS-only. A protected session endpoint mints independent short-lived credentials.
  connectPort: parseInt(process.env.CONNECT_PORT || "0", 10),
  connectAdvertise: process.env.CONNECT_ADVERTISE || "",
  connectTlsCert: process.env.CONNECT_TLS_CERT || "",
  connectTlsKey: process.env.CONNECT_TLS_KEY || "",
  proxySessionTtlMs: 15 * 60 * 1000,
  proxySessionsPerUser: 3,
  proxySessionLimit: 10000,
  connectMaxTunnels: 128,
  connectMaxPerToken: 16,
  connectMaxPerUser: 32,
  connectIdleMs: 120000,
  connectDialMs: 10000,
  upstreamIdleMs: parseInt(process.env.UPSTREAM_TIMEOUT_MS || "120000", 10),
  maxRewriteBytes: parseInt(process.env.MAX_REWRITE_BYTES || String(20 * 1024 * 1024), 10),
  maxCookies: 100,
  maxCookieValue: 8192,
};

const ALLOWED_HOSTS = new Set([
  "claude.ai", "www.claude.ai", "assets.claude.ai", "assets-proxy.anthropic.com", "api.anthropic.com",
  "a.claude.ai", "a-cdn.claude.ai", "a-cdn.anthropic.com", "s-cdn.anthropic.com",
  // Artifact families are recognized here, but excluded from reverse routes below.
  "claudeusercontent.com", "www.claudeusercontent.com", "gdrive.claudeusercontent.com",
  "sandbox.claudemcpcontent.com",
]);
const CONNECT_DEPENDENCY_HOSTS = new Set(["cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com", "fonts.googleapis.com", "fonts.gstatic.com", "esm.sh", "cdn.tailwindcss.com", "code.jquery.com", "cdn.plot.ly"]);
const ALLOWED_SUFFIXES = [".claudeusercontent.com", ".claudemcpcontent.com"];
function canonicalHost(value) {
  const host = String(value || "").toLowerCase().replace(/\.$/, "");
  if (host.length > 253 || !host.split(".").every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) return "";
  return host;
}
function allowedHost(host) {
  host = canonicalHost(host);
  if (!host) return false;
  return ALLOWED_HOSTS.has(host) || ALLOWED_SUFFIXES.some(x => host.endsWith(x));
}
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

// Error messages from JSON.parse and filesystem APIs can contain cookie material
// or filenames. Log only a known error classification, never the input excerpt.
function safeError(error) {
  if (error instanceof SyntaxError) return "invalid JSON";
  const code = error && error.code;
  return typeof code === "string" && /^(?:E[A-Z0-9_]{1,60}|ERR_[A-Z0-9_]{1,60})$/.test(code) ? code : "operation failed";
}

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
    } catch (e) { console.error("[cookies] migration failed: " + safeError(e)); }
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
    console.error("[cookies] user=" + sanitizeUser(user) + " unreadable jar: " + safeError(e));
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
    console.error("[cookies] user=" + sanitizeUser(user) + " cannot persist jar: " + safeError(e));
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
  "authorization", "proxy-authorization", "x-remote-user", "x-gateway-previous-proxy-token",
  "forwarded", "via", "x-real-ip", "true-client-ip", "x-client-ip", "client-ip",
  "cdn-loop", "x-request-id", "x-correlation-id", "dnt",
  // hop-by-hop
  "connection", "keep-alive", "proxy-connection", "te", "trailer", "upgrade", "transfer-encoding",
]);
const DROP_PREFIX = ["cf-", "x-forwarded-", "x-envoy-", "x-amzn-", "x-azure-", "fastly-", "x-vercel-"];
const HOP_BY_HOP = new Set(["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade"]);

function connectionHeaders(headers) {
  return new Set(String(headers.connection || "").split(",").map(x => x.trim().toLowerCase()).filter(Boolean));
}

function buildUpstreamHeaders(inHeaders, host, cookieHeader, opts) {
  const out = {};
  const connection = connectionHeaders(inHeaders);
  for (const [k, v] of Object.entries(inHeaders)) {
    const key = k.toLowerCase();
    if (DROP_EXACT.has(key) || HOP_BY_HOP.has(key) || connection.has(key) || DROP_PREFIX.some(p => key.startsWith(p))) continue;
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

function buildResponseHeaders(headers, upgraded) {
  const out = {};
  const connection = connectionHeaders(headers);
  for (const [name, value] of Object.entries(headers)) {
    const key = name.toLowerCase();
    if (DROP_RESPONSE.has(key) || HOP_BY_HOP.has(key) || connection.has(key)) continue;
    out[key] = value;
  }
  if (upgraded) { out.connection = "Upgrade"; out.upgrade = "websocket"; }
  return out;
}

function pub(h, p) { return "https://" + cfg.publicHost + (h === "claude.ai" ? "" : "/p/" + h) + p; }

// Hosts whose URLs are rewritten to the gateway. Artifact hosts are deliberately absent:
// PDF/artifact iframes must keep their real origin (postMessage checks it); the extension
// appends the exact gateway origin to frame-ancestors while preserving artifact CSP.
const REWRITE_HOSTS = [
  "assets.claude.ai", "assets-proxy.anthropic.com", "api.anthropic.com",
  "a-cdn.claude.ai", "a.claude.ai", "a-cdn.anthropic.com", "s-cdn.anthropic.com",
];
const REVERSE_HOSTS = new Set(["claude.ai", "www.claude.ai", ...REWRITE_HOSTS]);

function rewriteLocation(value, host, urlPath) {
  try {
    const target = new URL(value, "https://" + host + urlPath);
    const targetHost = canonicalHost(target.hostname);
    if ((target.protocol === "https:" || target.protocol === "http:") && !target.username && !target.password
        && (!target.port || target.port === "443") && REVERSE_HOSTS.has(targetHost)) {
      return pub(targetHost, target.pathname + target.search + target.hash);
    }
  } catch (_) { /* Preserve malformed or non-HTTP redirect values unchanged. */ }
  // Artifact and other external origins must not acquire the gateway's origin.
  return value;
}

function rewriteUrls(s) {
  for (const h of REWRITE_HOSTS) {
    const re = h.replace(/\./g, "\\.");
    s = s.replace(new RegExp("https?:\\/\\/" + re, "g"), pub(h, ""));       // plain
    s = s.replace(new RegExp("https?:\\\\/\\\\/" + re, "g"), pub(h, "").replace(/\//g, "\\/")); // JSON-escaped
  }
  return s;
}

function rewriteBody(buf, ct) {
  if (!ct || !(ct.includes("text/html") || ct.includes("text/css") || ct.includes("javascript"))) return buf;
  return Buffer.from(rewriteUrls(buf.toString("utf8")), "utf8");
}

function rewriteCsp(csp) {
  if (!csp) return csp;
  let out = csp;
  // artifact frames must be embeddable from the gateway origin
  if (/frame-ancestors/i.test(out)) {
    out = out.replace(/frame-ancestors([^;]*)/i, (m, g) =>
      g.includes(cfg.publicHost) ? m : "frame-ancestors" + g + " https://" + cfg.publicHost);
  }
  // NOTE: artifact hosts (claudeusercontent/claudemcpcontent) must stay as-is in CSP —
  // frame-src must match the real frame URL; the extension adds the exact gateway
  // origin to artifact frame-ancestors while preserving the remaining CSP.
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

const EXT_FILES = { "claude-gateway-chrome.zip": "application/zip", "claude-gateway-firefox.zip": "application/zip", "gateway-connector-firefox.xpi": "application/x-xpinstall" };

function extIndexHtml() {
  const h = cfg.publicHost;
  let signedFirefox = false;
  try { signedFirefox = fs.statSync(path.join(cfg.extDir, "gateway-connector-firefox.xpi")).isFile(); } catch (_) { /* optional package */ }
  return '<!doctype html><meta charset="utf-8"><title>Claude Gateway — extension</title>' +
    '<body style="font-family:-apple-system,sans-serif;max-width:640px;margin:40px auto;padding:0 16px;line-height:1.5">' +
    '<h2>Claude Gateway — расширение 2.0.3</h2>' +
    '<p>Создайте отдельный профиль браузера только для шлюза. При активной защите другие внешние сайты и запросы блокируются во всём профиле, включая новые окна и фоновые процессы.</p><ul>' +
    '<li><a href="/__ext/claude-gateway-chrome.zip">Chrome / Edge ≥ 125 (zip)</a> — скачайте свежую сборку, распакуйте, откройте <code>chrome://extensions</code> → режим разработчика → «Загрузить распакованное».</li>' +
    '<li><a href="/__ext/claude-gateway-firefox.zip">Firefox ≥ 140 (zip, без подписи)</a> — сборка для проверки. Защищённый маршрут артефактов пока не поддерживается и блокирует запросы (fail-closed); полноценная работа файлов и артефактов не подтверждена.</li>' +
    (signedFirefox ? '<li><a href="/__ext/gateway-connector-firefox.xpi">Firefox ≥ 140 (подписанный .xpi)</a> — те же ограничения защищённого маршрута.</li>' : '<li>Подписанный Firefox XPI на этом сервере отсутствует.</li>') + '</ul>' +
    '<p>Сборки не привязаны к домену. В настройках расширения (Options) введите домен шлюза <code>' + h + '</code>, ваш логин и пароль, затем нажмите «Сохранить и разрешить».</p>' +
    '<p>Chrome запрашивает разрешение debugger для защищённого маршрута и совместимости артефактов; при подключении появится баннер отладки браузера. DevTools может конфликтовать с подключением расширения: закройте DevTools перед работой, а при потере защиты переподключите расширение и проверьте его статус.</p>' +
    '<p>Inline-preview артефактов, которым требуется изменение CSP-заголовков, ограничен body 8 MiB. Файлы с <code>Content-Disposition: attachment</code> идут через штатную загрузку браузера без этого буфера; поддержка каждого типа загрузки не гарантируется.</p>' +
    '<p>После обновления расширения перезагрузите его на странице расширений и сделайте hard reload страницы Claude: Ctrl+Shift+R или ⌘+Shift+R. Перед работой проверьте в расширении, что защищённый маршрут активен.</p></body>';
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
    host = canonicalHost(m[1]);
    urlPath = m[2] || "/";
    // Artifact HTML/JS is user-generated and must retain its isolated real origin.
    // Serving it below /p/ would give it the gateway's cookies and API access.
    if (!allowedHost(host) || isArtifactProxyHost(host)) return null;
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
    for (const [name, value] of Object.entries(buildResponseHeaders(pres.headers, true))) {
      for (const item of Array.isArray(value) ? value : [value]) out += name + ": " + item + "\r\n";
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
  preq.setTimeout(cfg.upstreamIdleMs, () => preq.destroy());
  socket.on("close", () => preq.destroy());
  preq.on("error", (e) => { console.error("[ws] " + t.host + " " + safeError(e)); socket.destroy(); });
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
      return json(res, 200, { ok: true, users: jars.size, user: user, session: user ? sessionState(user) : "none", connectProxy: connectReady() ? "https://" + proxyEndpoint().host + ":" + proxyEndpoint().port : null, connectReady: connectReady() });
    }
    if (pathOnly === "/__proxy-session") {
      if (req.method !== "POST") { res.setHeader("allow", "POST"); return json(res, 405, { error: "method_not_allowed" }); }
      if (!user || user !== req.headers["x-remote-user"]) return json(res, 401, { error: "unauthorized" });
      if (req.headers["x-gateway-proxy-session"] !== "1" || (req.headers.origin && req.headers.origin !== "https://" + cfg.publicHost && !/^(?:chrome-extension|moz-extension):\/\/[a-zA-Z0-9-]+$/.test(req.headers.origin))) return json(res, 403, { error: "forbidden_origin" });
      const previousToken = req.headers["x-gateway-previous-proxy-token"];
      if (previousToken !== undefined && (typeof previousToken !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(previousToken))) return json(res, 400, { error: "invalid_previous_token" });
      if (!connectReady()) return json(res, 503, { error: "secure_proxy_unavailable" });
      const session = mintProxySession(user, Date.now(), previousToken);
      return json(res, session ? 200 : 503, session || { error: "session_capacity" });
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
      const rh = buildResponseHeaders(up.headers);
      const failResponse = () => {
        if (res.destroyed || res.writableEnded) return;
        if (res.headersSent) res.destroy();
        else { res.writeHead(502, { "content-type": "text/plain" }); res.end("bad gateway"); }
      };
      up.once("error", failResponse);
      up.once("aborted", failResponse);
      res.once("close", () => { if (!up.complete) up.destroy(); });

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
      const rewriteHeader = (v) => Array.isArray(v) ? v.map(rewriteUrls) : rewriteUrls(v);
      if (rh["location"]) rh["location"] = Array.isArray(rh["location"])
        ? rh["location"].map(value => rewriteLocation(value, host, urlPath)) : rewriteLocation(rh["location"], host, urlPath);
      if (rh["link"]) rh["link"] = rewriteHeader(rh["link"]);

      const ct = String(rh["content-type"] || "");
      const preserveBody = req.method === "HEAD" || up.statusCode === 206 || !!req.headers.range || !!rh["content-range"]
        || /^\s*attachment\s*(?:;|$)/i.test(String(rh["content-disposition"] || ""));
      const rewritable = !preserveBody && (ct.includes("text/html") || ct.includes("text/css") || ct.includes("javascript"));
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
      console.error("[upstream] " + host + " " + logPath + " " + safeError(e));
      if (!res.headersSent) { res.writeHead(502, { "content-type": "text/plain" }); res.end("bad gateway"); } else res.destroy();
    });
    req.on("aborted", () => proxyReq.destroy());
    res.once("close", () => { if (!res.writableEnded) proxyReq.destroy(); });
    req.pipe(proxyReq); // stream the body — no buffering of uploads
  });
  server.on("upgrade", handleUpgrade);
  // Never accept proxy credentials or tunnels on the internal HTTP listener.
  server.on("connect", (req, socket) => socket.end("HTTP/1.1 403 Forbidden\r\nconnection: close\r\ncontent-length: 0\r\n\r\n"));
  return server;
}

// Artifact iframes must keep their real origin (postMessage checks it) while the
// TCP connection comes from this server, so the user's IP is not revealed.
function isArtifactProxyHost(host) {
  host = canonicalHost(host);
  return host === "claudeusercontent.com" || host.endsWith(".claudeusercontent.com")
    || host === "claudemcpcontent.com" || host.endsWith(".claudemcpcontent.com");
}

function parseConnectTarget(target) {
  const match = /^([^:]+):443$/.exec(String(target || ""));
  if (!match) return null;
  const host = canonicalHost(match[1]);
  return host && (isArtifactProxyHost(host) || CONNECT_DEPENDENCY_HOSTS.has(host)) ? host : null;
}

// Tokens are separate from gateway Basic credentials; only their digest is retained.
const proxySessions = new Map();
let liveConnectServers = 0;
let activeTunnels = 0;
const userTunnels = new Map();
function proxyEndpoint() {
  try {
    const endpoint = new URL(cfg.connectAdvertise.includes("://") ? cfg.connectAdvertise : "https://" + cfg.connectAdvertise);
    if (endpoint.protocol !== "https:" || !endpoint.hostname || endpoint.username || endpoint.password || endpoint.pathname !== "/" || endpoint.search || endpoint.hash) return null;
    const host = endpoint.hostname;
    if (!(net.isIP(host) || canonicalHost(host))) return null;
    return { scheme: "https", host, port: Number(endpoint.port || 443) };
  } catch (_) { return null; }
}
function readConnectCredentials() {
  if (!cfg.connectTlsCert || !cfg.connectTlsKey || !proxyEndpoint()) throw new Error("TLS CONNECT is not configured");
  const cert = fs.readFileSync(cfg.connectTlsCert), key = fs.readFileSync(cfg.connectTlsKey);
  const x509 = new crypto.X509Certificate(cert);
  const now = Date.now(), endpoint = proxyEndpoint();
  if (now < Date.parse(x509.validFrom) || now >= Date.parse(x509.validTo)) throw new Error("TLS certificate expired or not yet valid");
  if (!(net.isIP(endpoint.host) ? x509.checkIP(endpoint.host) : x509.checkHost(endpoint.host))) throw new Error("TLS certificate identity mismatch");
  tls.createSecureContext({ cert, key, minVersion: "TLSv1.2" });
  return { cert, key, minVersion: "TLSv1.2" };
}
function connectReady() {
  if (!liveConnectServers || !proxyEndpoint()) return false;
  try { readConnectCredentials(); return true; } catch (_) { return false; }
}
function pruneProxySessions(now = Date.now()) {
  for (const [digest, session] of proxySessions) if (session.expiresAt <= now) revokeProxySession(digest);
}
function revokeProxySession(digest) {
  const session = proxySessions.get(digest);
  if (!session) return;
  proxySessions.delete(digest);
  for (const socket of session.sockets) socket.destroy();
}
function mintProxySession(user, now = Date.now(), previousToken) {
  if (!user || sanitizeUser(user) !== user || (previousToken !== undefined && (typeof previousToken !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(previousToken)))) return null;
  pruneProxySessions(now);
  const removals = new Set();
  if (previousToken) {
    const previousDigest = crypto.createHash("sha256").update(previousToken).digest("hex");
    const previous = proxySessions.get(previousDigest);
    // Possession of the exact bearer secret authorizes revoking only that token,
    // including after switching gateway accounts. Never disclose its owner.
    // An own token frees an own profile slot; a foreign token frees only global
    // capacity because it was never included in this user's owned list below.
    // Unknown/expired tokens are ignored so restart/expiry recovery still works.
    if (previous) removals.add(previousDigest);
  }
  const owned = [...proxySessions].filter(([digest, session]) => session.user === user && !removals.has(digest));
  if (cfg.proxySessionsPerUser <= 0) return null;
  while (owned.length >= cfg.proxySessionsPerUser) {
    const [digest] = owned.shift();
    removals.add(digest);
  }
  if (proxySessions.size - removals.size + 1 > cfg.proxySessionLimit) return null;
  const proxyPassword = crypto.randomBytes(32).toString("base64url");
  const expiresAt = now + cfg.proxySessionTtlMs;
  // All fallible planning is finished before revoking a still-valid credential.
  proxySessions.set(crypto.createHash("sha256").update(proxyPassword).digest("hex"), { user, expiresAt, tunnels: 0, sockets: new Set() });
  for (const digest of removals) revokeProxySession(digest);
  return { proxyUsername: "gateway-proxy", proxyPassword, expiresAt, proxy: proxyEndpoint() };
}
function verifyProxyAuth(header, now = Date.now()) {
  if (typeof header !== "string" || !/^Basic [A-Za-z0-9+/]+={0,2}$/.test(header) || header.length > 200) return null;
  const decoded = Buffer.from(header.slice(6), "base64").toString("utf8");
  const match = /^gateway-proxy:([A-Za-z0-9_-]{43})$/.exec(decoded);
  if (!match) return null;
  const digest = crypto.createHash("sha256").update(match[1]).digest("hex");
  const session = proxySessions.get(digest);
  if (!session || session.expiresAt <= now) { revokeProxySession(digest); return null; }
  return session;
}
// DNS answers are checked as a set and the selected address is pinned for dialing,
// so a later DNS lookup cannot turn an approved hostname into an internal target.
function isPublicAddress(address) {
  const family = net.isIP(address);
  if (family === 4) {
    const [a, b, c] = address.split(".").map(Number);
    return !(a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127)
      || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && (b === 0 || b === 168 || (b === 88 && c === 99)))
      || (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) || (a === 203 && b === 0 && c === 113));
  }
  if (family === 6) {
    const lower = address.toLowerCase();
    const [prefix, subnet] = lower.split(":").map(group => parseInt(group || "0", 16));
    return /^[23][0-9a-f]{3}:/.test(lower)
      && !(prefix === 0x2001 && (subnet < 0x200 || subnet === 0xdb8))
      && prefix !== 0x2002 && !(prefix === 0x3fff && subnet <= 0xfff);
  }
  return false;
}
async function resolveConnectAddress(host) {
  const answers = await dns.lookup(host, { all: true, verbatim: true });
  if (!answers.length || answers.some(answer => !isPublicAddress(answer.address))) throw new Error("non-public DNS answer");
  return answers.find(answer => answer.family === 4) || answers[0];
}
function handleConnect(req, socket, head) {
  socket.on("error", () => socket.destroy());
  const deny = (code, extra = "") => socket.end("HTTP/1.1 " + code + "\r\n" + extra + "connection: close\r\ncontent-length: 0\r\n\r\n");
  if (!socket.encrypted || !connectReady()) return deny("503 Service Unavailable");
  const host = parseConnectTarget(req.url);
  if (!host) return deny("403 Forbidden");
  const session = verifyProxyAuth(req.headers["proxy-authorization"]);
  if (!session) return deny("407 Proxy Authentication Required", 'proxy-authenticate: Basic realm="gateway-proxy"\r\n');
  if (activeTunnels >= cfg.connectMaxTunnels || session.tunnels >= cfg.connectMaxPerToken || (userTunnels.get(session.user) || 0) >= cfg.connectMaxPerUser) return deny("429 Too Many Requests");
  activeTunnels++; session.tunnels++;
  session.sockets.add(socket);
  userTunnels.set(session.user, (userTunnels.get(session.user) || 0) + 1);
  let up, released = false, resolving = true;
  const release = () => {
    // dns.lookup cannot be cancelled: retain the reservation until it settles,
    // otherwise rapidly disconnected clients could enqueue unlimited DNS work.
    if (released || resolving) return;
    released = true; activeTunnels--; session.tunnels--;
    session.sockets.delete(socket);
    const count = userTunnels.get(session.user) - 1;
    if (count) userTunnels.set(session.user, count); else userTunnels.delete(session.user);
  };
  const expiry = setTimeout(() => socket.destroy(), Math.max(1, session.expiresAt - Date.now()));
  const dialDeadline = setTimeout(() => socket.destroy(), cfg.connectDialMs);
  socket.setTimeout(cfg.connectIdleMs, () => socket.destroy());
  socket.once("close", () => { clearTimeout(expiry); clearTimeout(dialDeadline); release(); if (up) up.destroy(); });
  resolveConnectAddress(host).then(address => {
    if (socket.destroyed) return;
    up = net.connect({ port: 443, host: address.address, family: address.family }, () => {
      clearTimeout(dialDeadline);
      socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head && head.length) up.write(head);
      up.pipe(socket); socket.pipe(up);
    });
    up.setTimeout(cfg.connectIdleMs, () => up.destroy());
    up.on("error", () => socket.destroy());
    up.on("close", () => socket.destroy());
  }).catch(() => { if (!socket.destroyed) deny("502 Bad Gateway"); })
    .finally(() => { resolving = false; if (socket.destroyed) release(); });
}
function createConnectServer({ reloadMs = 30000 } = {}) {
  const credentials = readConnectCredentials(); // No certificate means no listener.
  const s = https.createServer({ ...credentials, handshakeTimeout: 10000, requestTimeout: 15000, headersTimeout: 10000 }, (req, res) => {
    res.writeHead(405, { "connection": "close" }); res.end("connect only");
  });
  s.maxConnections = 256;
  let counted = false, timer;
  s.once("listening", () => {
    liveConnectServers++; counted = true;
    timer = setInterval(() => {
      try { s.setSecureContext(readConnectCredentials()); }
      catch (_) { /* connectReady() rejects sessions/tunnels until renewal succeeds. */ }
      pruneProxySessions();
    }, reloadMs);
    timer.unref();
  });
  s.once("close", () => { if (counted) liveConnectServers--; clearInterval(timer); });
  s.on("connect", handleConnect);
  return s;
}

// Certificates may be issued after the process starts. Keep the HTTP gateway
// available and retry TLS startup without ever opening a plaintext proxy.
function startConnectListener({ retryMs = 30000 } = {}) {
  let server = null, stopped = false;
  const attempt = () => {
    if (stopped || server) return;
    try {
      server = createConnectServer();
      const candidate = server;
      candidate.once("error", () => { if (server === candidate) server = null; candidate.close(() => {}); });
      candidate.listen(cfg.connectPort, cfg.listen);
    } catch (_) { server = null; }
  };
  const timer = setInterval(attempt, retryMs);
  timer.unref();
  attempt();
  return {
    get server() { return server; },
    close() { stopped = true; clearInterval(timer); if (server) server.close(); }
  };
}

module.exports = {
  cfg, ALLOWED_HOSTS, COOKIE_HOSTS, CONNECT_DEPENDENCY_HOSTS, startConnectListener,
  mintProxySession, verifyProxyAuth, proxyEndpoint, connectReady, isPublicAddress, resolveConnectAddress,
  sanitizeUser, userFile, loadJar, cookieHeaderFor, captureSetCookies,
  buildUpstreamHeaders, buildResponseHeaders, rewriteBody, rewriteCsp, rewriteUrls, redactPath, createServer, createConnectServer, allowedHost, isArtifactProxyHost, parseConnectTarget,
  seal, unseal, migrateAll, isBanned, recordFail, cleanIp, cacheGet, cachePut, sessionState, noteClaudeResponse, listUsers,
};

if (require.main === module) {
  const n = migrateAll();
  if (n) console.log("[cookies] encrypted " + n + " plain jar(s)");
  console.log("[gateway] cookies at rest: " + (cfg.cookiesKey ? "encrypted" : "PLAIN (set COOKIES_KEY)") +
    "; telegram: " + (cfg.tgToken ? "on" : "off") + "; admins: " + (cfg.adminUsers.join(",") || "-"));
  createServer().listen(cfg.port, cfg.listen, () =>
    console.log("[gateway] listening on " + cfg.listen + ":" + cfg.port + " public host " + cfg.publicHost));
  if (cfg.connectPort) {
    startConnectListener();
  }
}
