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
// Encryption at rest
//   Each jar is sealed with a key derived from that user's own gateway password
//   (see "encryption at rest" below). The key exists only in memory while the
//   user is active, so cookie files, backups and disk snapshots are useless
//   without the password.
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
const zlib = require("zlib");

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
  // Legacy AES-256-GCM key (v1 jars). Jars move to password-derived keys (v2)
  // on their user's next request; this key only reads the old format and
  // seals jars for identity proxies that do not forward a password.
  cookiesKey: parseKey(process.env.COOKIES_KEY),
  // A password-derived jar key leaves memory after this long without requests.
  jarKeyIdleMs: parseInt(process.env.JAR_KEY_IDLE_MS || String(60 * 60 * 1000), 10),
  // Loopback-only operator API used by server/admin.sh and the dashboard; 0 disables it.
  adminPort: parseInt(process.env.ADMIN_PORT || "8089", 10),
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
  // Bound encoded input, decoded text and the final rewritten representation.
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
// jar entry: { mtime, entry, format, locked, meta, cookies: Map(name -> {name,value,expires}) }
//   format: "v2" (password key), "v1" (COOKIES_KEY) or "plain"
//   locked: the jar is sealed with a key that is not in memory (no cookies available)

const jars = new Map();

function nowSec() { return Math.floor(Date.now() / 1000); }

// Error messages from JSON.parse and filesystem APIs can contain cookie material
// or filenames. Log only a known error classification, never the input excerpt.
function safeError(error) {
  if (error instanceof SyntaxError) return "invalid JSON";
  const code = error && error.code;
  return typeof code === "string" && /^(?:E[A-Z0-9_]{1,60}|ERR_[A-Z0-9_]{1,60})$/.test(code) ? code : "operation failed";
}

// ---- encryption at rest
// v2: AES-256-GCM under a key derived with scrypt from the user's own gateway
//     password. Caddy has verified that password when a request reaches the
//     gateway, and the derived key stays in memory only while the user is
//     active. Without the password, cookie files, backups and disk snapshots
//     cannot be decrypted, even together with .env.
// v1: AES-256-GCM under COOKIES_KEY from .env, which sits on the same disk.
//     Read so that jars move to v2 on their user's next request; still written
//     when an identity proxy supplies no password.
// Plain JSON is the oldest format; startup seals it as v1.
const JAR_KDF = { N: 1 << 15, r: 8, p: 1 };
const jarKeys = new Map();        // user -> { key, salt, verifier, usedAt }
const jarKeyPending = new Map();  // user -> { verifier, promise }
const verifierSecret = crypto.randomBytes(32);
let kdfQueue = Promise.resolve();

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
  const dc = crypto.createDecipheriv("aes-256-gcm", cfg.cookiesKey, Buffer.from(d.iv, "base64"), { authTagLength: 16 });
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
      if (d && (d.enc === 1 || d.enc === 2)) continue;
      const tmp = file + "." + process.pid + ".tmp";
      fs.writeFileSync(tmp, seal(raw.trim() ? raw : '{"cookies":[]}'), { mode: 0o600 });
      fs.renameSync(tmp, file); n++;
    } catch (e) { console.error("[cookies] migration failed: " + safeError(e)); }
  }
  return n;
}

// The user name and the plaintext metadata are authenticated: a jar copied to
// another user's file, or edited metadata, fails to open.
function jarAad(user, meta) { return Buffer.from("claude-gateway jar v2\0" + user + "\0" + JSON.stringify(meta), "utf8"); }
function sealJar(user, plain, entry, meta) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", entry.key, iv);
  c.setAAD(jarAad(user, meta));
  const data = Buffer.concat([c.update(plain, "utf8"), c.final()]);
  return JSON.stringify({ enc: 2, user, kdf: { name: "scrypt", N: JAR_KDF.N, r: JAR_KDF.r, p: JAR_KDF.p, salt: entry.salt.toString("base64") },
    meta, iv: iv.toString("base64"), tag: c.getAuthTag().toString("base64"), data: data.toString("base64") });
}
function openJar(user, d, key) {
  if (d.user !== user) throw new Error("jar belongs to another user");
  const dc = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(String(d.iv), "base64"), { authTagLength: 16 });
  dc.setAAD(jarAad(user, d.meta));
  dc.setAuthTag(Buffer.from(String(d.tag), "base64"));
  return Buffer.concat([dc.update(Buffer.from(String(d.data), "base64")), dc.final()]).toString("utf8");
}
function jarSalt(d) {
  const k = d && d.enc === 2 && d.kdf;
  if (!k || k.name !== "scrypt" || k.N !== JAR_KDF.N || k.r !== JAR_KDF.r || k.p !== JAR_KDF.p || typeof k.salt !== "string") return null;
  const salt = Buffer.from(k.salt, "base64");
  return salt.length === 16 ? salt : null;
}
function deriveJarKey(password, salt) {
  const run = () => new Promise((resolve, reject) => crypto.scrypt(password, salt, 32, { ...JAR_KDF, maxmem: 64 * 1024 * 1024 },
    (error, key) => error ? reject(error) : resolve(key)));
  // One derivation at a time: each needs 32 MiB and the container has 256 MiB.
  const result = kdfQueue.then(run, run);
  kdfQueue = result.catch(() => {});
  return result;
}

// Caddy forwards the Basic credentials it has just verified. Only a password
// sent under the same user name as X-Remote-User is used.
function basicPassword(header, user) {
  const m = /^Basic +([A-Za-z0-9+/]{1,1400}={0,2})$/i.exec(String(header || ""));
  if (!m || !user) return "";
  const decoded = Buffer.from(m[1], "base64").toString("utf8");
  const i = decoded.indexOf(":");
  return i > 0 && decoded.slice(0, i) === user && i < decoded.length - 1 ? decoded.slice(i + 1) : "";
}

function readJarDoc(user) {
  const file = userFile(user);
  try { return file ? JSON.parse(fs.readFileSync(file, "utf8")) : null; } catch (_) { return null; }
}

// Makes the user's jar key available before the request is handled. Returns
// null when nothing has to wait (no password, or the key is already in memory).
function unlockJar(user, authorization, now = Date.now()) {
  const password = basicPassword(authorization, user);
  if (!password || !userFile(user)) return null;
  const verifier = crypto.createHmac("sha256", verifierSecret).update(user + "\0" + password).digest();
  const entry = jarKeys.get(user);
  if (entry && crypto.timingSafeEqual(entry.verifier, verifier)) { entry.usedAt = now; return null; }
  const pending = jarKeyPending.get(user);
  if (pending && pending.verifier.equals(verifier)) return pending.promise;
  const promise = (async () => {
    const salt = jarSalt(readJarDoc(user)) || crypto.randomBytes(16);
    const key = await deriveJarKey(password, salt);
    // After a password reset the previous key, while still in memory, opens
    // the jar once more so the Claude session survives under the new key.
    const previous = jarKeys.has(user) ? loadJar(user) : null;
    jarKeys.set(user, { key, salt, verifier, usedAt: Date.now() });
    jars.delete(user);
    const jar = loadJar(user);
    if (!jar) return;
    let from = "";
    if (jar.format === "v1" || jar.format === "plain") from = jar.format;
    else if (jar.locked && previous && !previous.locked && previous.format === "v2") { jar.cookies = previous.cookies; from = "previous password"; }
    if (!from) return;
    writeJar(user, userFile(user), jar);
    console.log("[cookies] user=" + user + " jar sealed with the user's password key (was " + from + ")");
  })();
  jarKeyPending.set(user, { verifier, promise });
  promise.then(() => {}, () => {}).then(() => { if (jarKeyPending.get(user) && jarKeyPending.get(user).promise === promise) jarKeyPending.delete(user); });
  return promise;
}

// Keys and decrypted cookies of users without recent requests leave memory.
function forgetJarKeys(now = Date.now()) {
  let n = 0;
  for (const [user, entry] of jarKeys) {
    const s = stats.get(user);
    if (now - entry.usedAt < cfg.jarKeyIdleMs || (s && s.ws.size)) continue;
    jarKeys.delete(user); jars.delete(user); n++;
  }
  return n;
}

function loadJar(user) {
  const file = userFile(user);
  if (!file) return null;
  let st;
  try { st = fs.statSync(file); } catch (e) { return null; }
  const entry = jarKeys.get(user) || null;
  const cached = jars.get(user);
  if (cached && cached.mtime === st.mtimeMs && cached.entry === entry) return cached;
  const jar = { mtime: st.mtimeMs, entry, format: "plain", locked: false, meta: null, cookies: new Map() };
  try {
    let raw = fs.readFileSync(file, "utf8");
    let d = null;
    try { d = raw.trim() ? JSON.parse(raw) : null; } catch (_) { /* reported below */ }
    if (d && d.enc === 2) {
      jar.format = "v2";
      jar.meta = d.meta && typeof d.meta === "object" ? d.meta : null;
      raw = "";
      try { if (entry) raw = openJar(user, d, entry.key); else jar.locked = true; }
      catch (_) { jar.locked = true; }  // sealed under another password or damaged
    } else if (d && d.enc === 1) {
      jar.format = "v1";
      raw = unseal(raw);
    }
    if (raw.trim()) {
      const plain = JSON.parse(raw);
      for (const c of (plain.cookies || [])) {
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

function writeJar(user, file, jar) {
  const t = nowSec();
  const cookies = Array.from(jar.cookies.values());
  const entry = jarKeys.get(user) || null;
  let data;
  if (entry) {
    const session = jar.cookies.get("sessionKey");
    // Non-secret facts for operators while the jar is locked.
    const meta = { saved_at: t, cookies: cookies.length, session: !!session, session_expires: session ? session.expires : 0 };
    data = sealJar(user, JSON.stringify({ saved_at: t, cookies }), entry, meta);
    Object.assign(jar, { format: "v2", locked: false, meta });
  } else {
    data = seal(JSON.stringify({ saved_at: t, cookies }, null, 2));
    jar.format = cfg.cookiesKey ? "v1" : "plain";
  }
  fs.mkdirSync(cfg.cookiesDir, { recursive: true, mode: 0o700 });
  const tmp = file + "." + process.pid + ".tmp";
  fs.writeFileSync(tmp, data, { mode: 0o600 });
  fs.renameSync(tmp, file);           // atomic replace
  jar.entry = entry;
  jar.mtime = fs.statSync(file).mtimeMs;
  jars.set(user, jar);
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
  if (!file || !Array.isArray(setCookies) || !setCookies.length || removedUsers.has(user)) return false;
  const jar = loadJar(user) || { mtime: 0, entry: null, format: "plain", locked: false, meta: null, cookies: new Map() };
  // A jar sealed with a key that is not in memory is never replaced. With the
  // key in memory a locked jar belongs to a previous password and is replaced.
  if (jar.locked && !jarKeys.has(user)) return false;
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
    writeJar(user, file, jar);
    console.log("[cookies] user=" + user + " jar updated (" + jar.cookies.size + " cookies)");
    return true;
  } catch (e) {
    console.error("[cookies] user=" + sanitizeUser(user) + " cannot persist jar: " + safeError(e));
    return false;
  }
}

// ------------------------------------------------ session monitoring / alerts ----

// user -> { lastSeen, expired, alertedAt, inflight, ws: Set(socket), hours: [{ h, req, bytes }] }
const stats = new Map();

function hasSession(user) {
  const jar = loadJar(user);
  if (!jar) return false;
  const t = nowSec();
  if (jar.locked) {
    const m = jar.meta;
    return !!(m && m.session) && !(m.session_expires > 0 && m.session_expires < t);
  }
  const c = jar.cookies.get("sessionKey");
  return !!c && !(c.expires > 0 && c.expires < t);
}
function statOf(user) {
  let s = stats.get(user);
  if (!s) { s = { lastSeen: 0, expired: false, alertedAt: 0, inflight: 0, ws: new Set(), hours: [] }; stats.set(user, s); }
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

function listUsers(now = Date.now()) {
  let files = []; try { files = fs.readdirSync(cfg.cookiesDir); } catch (e) { /* none */ }
  return files.filter(f => f.endsWith(".json")).map(f => f.slice(0, -5)).filter(u => sanitizeUser(u) === u).sort().map(u => {
    const s = statOf(u);
    const jar = loadJar(u);
    const day = s.hours.filter(e => now - e.h < 24 * 3600 * 1000);
    return { user: u, session: sessionState(u),
      cookies: jar ? (jar.locked ? (jar.meta && Number(jar.meta.cookies)) || 0 : jar.cookies.size) : 0,
      encryption: jar ? jar.format : "none", unlocked: jarKeys.has(u),
      savedAt: jar && jar.meta && jar.meta.saved_at ? new Date(jar.meta.saved_at * 1000).toISOString() : null,
      lastSeen: s.lastSeen ? new Date(s.lastSeen).toISOString() : null,
      active: { requests: s.inflight, websockets: s.ws.size, tunnels: userTunnels.get(u) || 0 },
      requests24h: day.reduce((n, e) => n + e.req, 0), bytes24h: day.reduce((n, e) => n + e.bytes, 0) };
  });
}

// ----------------------------------------------------------------- metrics ----
// Counters and gauges for operators (server/admin.sh, dashboard). They hold no
// paths, query strings, cookies, passwords or client addresses.

const startedAt = Date.now();
const HISTORY_MINUTES = 24 * 60;
const HISTORY_FIELDS = ["t", "req", "s2", "s3", "s4", "s5", "r429", "upErr", "bytesIn", "bytesOut", "wsOpened", "tunnelsOpened",
  "inflight", "ws", "tunnels", "users", "ttfbAvg", "ttfbMax", "lagP99", "lagMax"];
const history = [];
const live = { inflight: 0, ws: 0 };
const totals = { req: 0, s5: 0, upErr: 0, bytesIn: 0, bytesOut: 0, wsOpened: 0, tunnelsOpened: 0 };
let loopDelay = null;
try { loopDelay = require("perf_hooks").monitorEventLoopDelay({ resolution: 20 }); loopDelay.enable(); } catch (_) { /* optional */ }

function closeMinute(b) {
  b.users = b.userSet.size; b.userSet = null;
  if (loopDelay) {
    b.lagP99 = Math.round(loopDelay.percentile(99) / 1e5) / 10;
    b.lagMax = Math.round(loopDelay.max / 1e5) / 10;
    loopDelay.reset();
  }
}
function minute(now = Date.now()) {
  const t = now - now % 60000;
  let b = history[history.length - 1];
  if (b && b.t === t) return b;
  if (b) closeMinute(b);
  b = { t, req: 0, s2: 0, s3: 0, s4: 0, s5: 0, r429: 0, upErr: 0, bytesIn: 0, bytesOut: 0, wsOpened: 0, tunnelsOpened: 0,
    inflight: live.inflight, ws: live.ws, tunnels: activeTunnels, userSet: new Set(), users: 0, ttfbSum: 0, ttfbN: 0, ttfbMax: 0, lagP99: 0, lagMax: 0 };
  history.push(b);
  while (history.length > HISTORY_MINUTES) history.shift();
  return b;
}
function gauge(b = minute()) {
  b.inflight = Math.max(b.inflight, live.inflight);
  b.ws = Math.max(b.ws, live.ws);
  b.tunnels = Math.max(b.tunnels, activeTunnels);
  return b;
}
function userHour(s, now = Date.now()) {
  const h = now - now % 3600000;
  let e = s.hours[s.hours.length - 1];
  if (!e || e.h !== h) { e = { h, req: 0, bytes: 0 }; s.hours.push(e); while (s.hours.length > 25) s.hours.shift(); }
  return e;
}
const metrics = {
  requestStarted(user) {
    const b = minute(); b.req++; totals.req++; live.inflight++; gauge(b);
    if (user) { const s = statOf(user); b.userSet.add(user); s.inflight++; userHour(s).req++; }
  },
  requestFinished(user, status) {
    live.inflight--;
    if (user) statOf(user).inflight--;
    if (!status) return;
    const b = minute();
    const cls = "s" + Math.min(5, Math.max(2, Math.floor(status / 100)));
    b[cls]++;
    if (status === 429) b.r429++;
    if (status >= 500) totals.s5++;
  },
  bytes(user, received, sent) {
    const b = minute();
    b.bytesIn += received; b.bytesOut += sent; totals.bytesIn += received; totals.bytesOut += sent;
    if (user) userHour(statOf(user)).bytes += received + sent;
  },
  upstreamError() { minute().upErr++; totals.upErr++; },
  ttfb(ms) { const b = minute(); b.ttfbSum += ms; b.ttfbN++; b.ttfbMax = Math.max(b.ttfbMax, ms); },
  wsOpened(user, socket) {
    const b = minute(); live.ws++; b.wsOpened++; totals.wsOpened++; gauge(b);
    const s = statOf(user); s.ws.add(socket); s.lastSeen = Date.now(); b.userSet.add(user);
    socket.once("close", () => { live.ws--; s.ws.delete(socket); metrics.bytes(user, socket.bytesRead, socket.bytesWritten); });
  },
  tunnelOpened(user) { const b = minute(); b.tunnelsOpened++; totals.tunnelsOpened++; gauge(b); if (user) b.userSet.add(user); },
};

function historyRows(minutes) {
  return history.slice(-Math.max(1, Math.min(HISTORY_MINUTES, minutes | 0))).map(b => HISTORY_FIELDS.map(f =>
    f === "users" ? (b.userSet ? b.userSet.size : b.users) : f === "ttfbAvg" ? (b.ttfbN ? Math.round(b.ttfbSum / b.ttfbN) : 0) : b[f]));
}

function adminStatus(historyMinutes = 60, now = Date.now()) {
  gauge(minute(now));
  const users = listUsers(now);
  const jarsByFormat = { v2: 0, v1: 0, plain: 0 };
  for (const u of users) if (u.encryption in jarsByFormat) jarsByFormat[u.encryption]++;
  const mem = process.memoryUsage();
  return {
    gateway: { startedAt: new Date(startedAt).toISOString(), uptimeSec: Math.round((now - startedAt) / 1000), node: process.version, publicHost: cfg.publicHost },
    memory: { rss: mem.rss, heapUsed: mem.heapUsed, external: mem.external },
    now: { inflight: live.inflight, websockets: live.ws, tunnels: activeTunnels, proxySessions: proxySessions.size, jarKeysInMemory: jarKeys.size,
      lagP99: loopDelay ? Math.round(loopDelay.percentile(99) / 1e5) / 10 : null, connectReady: connectReady() },
    limits: { tunnels: cfg.connectMaxTunnels, tunnelsPerUser: cfg.connectMaxPerUser, proxySessions: cfg.proxySessionLimit, cacheBytes: cfg.cacheMaxBytes },
    totals,
    history: { fields: HISTORY_FIELDS, rows: historyRows(historyMinutes) },
    users,
    bans: Array.from(fails).filter(([, f]) => f.bannedUntil > now).map(([ip, f]) => ({ ip, until: new Date(f.bannedUntil).toISOString() })),
    cache: { items: cache.size, bytes: cacheBytes },
    encryption: { jars: jarsByFormat, legacyKey: !!cfg.cookiesKey, kdf: "scrypt N=" + JAR_KDF.N + " r=" + JAR_KDF.r + " p=" + JAR_KDF.p,
      keyIdleMinutes: Math.round(cfg.jarKeyIdleMs / 60000) },
  };
}

// Ends a user's live access without restarting the gateway: CONNECT tokens and
// their tunnels, open WebSockets and every WebSocket cookie issued so far.
// With forget, the jar key and decrypted cookies also leave memory.
const wsRevokedAt = new Map(); // user -> unix seconds
// Removed users: responses still in flight must not write a new jar. Cleared
// when the user authenticates again (Caddy only lets re-added users through).
const removedUsers = new Set();
function revokeUser(user, forget) {
  let tokens = 0, websockets = 0;
  for (const [digest, session] of proxySessions) if (session.user === user) { revokeProxySession(digest); tokens++; }
  const s = stats.get(user);
  if (s) for (const socket of s.ws) { socket.destroy(); websockets++; }
  wsRevokedAt.set(user, nowSec());
  if (forget) { jarKeys.delete(user); jarKeyPending.delete(user); jars.delete(user); stats.delete(user); removedUsers.add(user); }
  return { user, tokens, websockets, forgotten: !!forget };
}

// A second listener on the container's loopback interface: nothing on the
// docker network (Caddy, front door) reaches it. Operators use it through
// `docker compose exec gateway` (server/admin.sh).
function createAdminServer() {
  return http.createServer((req, res) => {
    const from = req.socket.remoteAddress;
    if (from !== "127.0.0.1" && from !== "::1" && from !== "::ffff:127.0.0.1") { res.writeHead(403); return res.end(); }
    let url;
    try { url = new URL(req.url, "http://127.0.0.1"); } catch (_) { return json(res, 400, { error: "bad_request" }); }
    if (req.method === "GET" && url.pathname === "/status") {
      return json(res, 200, adminStatus(parseInt(url.searchParams.get("history") || "60", 10) || 60));
    }
    let m = /^\/users\/([^/]+)\/revoke$/.exec(url.pathname);
    if (req.method === "POST" && m) {
      const name = decodeURIComponent(m[1]), user = sanitizeUser(name);
      if (!user || user !== name) return json(res, 400, { error: "invalid_user" });
      return json(res, 200, revokeUser(user, url.searchParams.get("forget") === "1"));
    }
    m = /^\/bans\/([^/]+)\/clear$/.exec(url.pathname);
    if (req.method === "POST" && m) {
      const ip = cleanIp(decodeURIComponent(m[1]));
      return json(res, 200, { ip, cleared: ip !== "unknown" && fails.delete(ip) });
    }
    json(res, 404, { error: "not_found" });
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
  out["accept-encoding"] = "identity";
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

// Responses behind basic auth must not enter Cloudflare's shared cache: a cached
// object is served to anyone without authentication (a corrupted s.js was).
// no-transform also stops Email Obfuscation from injecting a script that
// Claude's CSP blocks. Hashed public Claude assets may stay edge-cached.
const EDGE_CACHEABLE_HOSTS = new Set(["assets-proxy.anthropic.com", "assets.claude.ai"]);
function edgeHeaders(rh, host) {
  const cc = String(rh["cache-control"] || "");
  if (!/(?:^|,)\s*no-transform\s*(?:,|$)/i.test(cc)) rh["cache-control"] = cc ? cc + ", no-transform" : "no-transform";
  if (!EDGE_CACHEABLE_HOSTS.has(host)) rh["cloudflare-cdn-cache-control"] = "no-store";
  return rh;
}

const REWRITTEN_DESTINATIONS = new Set(["document", "iframe", "frame", "script", "style", "worker", "sharedworker", "serviceworker"]);
function likelyRewritten(headers, urlPath) {
  const dest = String(headers["sec-fetch-dest"] || "").toLowerCase();
  return REWRITTEN_DESTINATIONS.has(dest) || /\.(?:m?js|css|html?)(?:[?#]|$)/i.test(urlPath);
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
// Web-search citations show site icons from these two services. Only the icon
// endpoints are rewritten and proxied (without Claude cookies), so the browser
// never contacts Google directly and no other Google path is reachable.
const FAVICON_ROUTES = new Map([["www.google.com", "/s2/favicons"], ["t0.gstatic.com", "/faviconV2"]]);
function faviconRoute(host, urlPath) {
  const prefix = FAVICON_ROUTES.get(host);
  return !!prefix && (urlPath === prefix || urlPath.startsWith(prefix + "?"));
}

function rewriteLocation(value, host, urlPath) {
  try {
    const target = new URL(value, "https://" + host + urlPath);
    const targetHost = canonicalHost(target.hostname);
    if ((target.protocol === "https:" || target.protocol === "http:") && !target.username && !target.password
        && (!target.port || target.port === "443")
        && (REVERSE_HOSTS.has(targetHost) || faviconRoute(targetHost, target.pathname + target.search))) {
      // Google's s2/favicons redirects to t0.gstatic.com; keep icons on the gateway.
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
  for (const [h, prefix] of FAVICON_ROUTES) {
    s = s.split("https://" + h + prefix).join(pub(h, prefix));
    s = s.split(("https://" + h + prefix).replace(/\//g, "\\/")).join(pub(h, prefix).replace(/\//g, "\\/"));
  }
  return s;
}

function rewriteBody(buf, ct) {
  if (!ct || !(ct.includes("text/html") || ct.includes("text/css") || ct.includes("javascript"))) return buf;
  return Buffer.from(rewriteUrls(buf.toString("utf8")), "utf8");
}

function decodeRewriteBody(body, encoding) {
  const coding = String(encoding || "identity").trim().toLowerCase();
  if (coding === "identity") return Promise.resolve(body);
  const decoder = coding === "gzip" ? zlib.gunzip : coding === "br" ? zlib.brotliDecompress : coding === "deflate" ? zlib.inflate : null;
  if (!decoder) return Promise.reject(new Error("unsupported content encoding"));
  // Bound decoded output as well as the encoded input buffered by createServer.
  return new Promise((resolve, reject) => decoder(body, { maxOutputLength: cfg.maxRewriteBytes }, (error, decoded) => error ? reject(error) : resolve(decoded)));
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
    '<h2>Claude Gateway — расширение 2.0.9</h2>' +
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
    if (faviconRoute(host, urlPath)) return { host, urlPath };
    if (!allowedHost(host) || isArtifactProxyHost(host)) return null;
  } else { host = "claude.ai"; urlPath = rawUrl; }
  if (!urlPath.startsWith("/")) return null;
  return { host, urlPath };
}

// Browsers apply no header rules to WebSocket handshakes, so they cannot carry
// the extension's Basic credentials. Authenticated responses therefore also set
// a short-lived signed cookie, which the upgrade path accepts instead. The key
// lives only in this process: a restart (e.g. on user removal) revokes them all.
const WS_COOKIE = "__Host-gw_ws";
const WS_COOKIE_MAX_AGE = 12 * 3600;
const wsCookieKey = crypto.randomBytes(32);
function wsCookieMac(payload) { return crypto.createHmac("sha256", wsCookieKey).update(payload).digest(); }
function wsCookieHeader(user, now = Date.now()) {
  const payload = Buffer.from(JSON.stringify({ u: user, e: Math.floor(now / 1000) + WS_COOKIE_MAX_AGE })).toString("base64url");
  return WS_COOKIE + "=" + payload + "." + wsCookieMac(payload).toString("base64url") +
    "; Path=/; Max-Age=" + WS_COOKIE_MAX_AGE + "; Secure; HttpOnly; SameSite=Strict";
}
function wsCookieUser(cookieHeader, now = Date.now()) {
  for (const part of String(cookieHeader || "").split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0 || part.slice(0, eq).trim() !== WS_COOKIE) continue;
    const [payload, mac, extra] = part.slice(eq + 1).trim().split(".");
    if (!payload || !mac || extra !== undefined) continue;
    const want = wsCookieMac(payload), got = Buffer.from(mac, "base64url");
    if (got.length !== want.length || !crypto.timingSafeEqual(got, want)) continue;
    try {
      const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
      const user = sanitizeUser(data.u);
      // Cookies issued before revokeUser() ran for this user are void.
      const revokedAt = wsRevokedAt.get(user);
      if (user && user === data.u && Number.isSafeInteger(data.e) && data.e * 1000 > now
          && !(revokedAt !== undefined && data.e - WS_COOKIE_MAX_AGE <= revokedAt)) return user;
    } catch (_) { /* malformed payload */ }
  }
  return "";
}
// Refresh the cookie whenever a Basic-authenticated response finds it missing or stale.
function withWsCookie(headers, user, cookieHeader) {
  return user && wsCookieUser(cookieHeader) !== user ? Object.assign({}, headers, { "set-cookie": wsCookieHeader(user) }) : headers;
}

function handleUpgrade(req, socket) {
  socket.on("error", () => socket.destroy());
  // Caddy's forward_auth and handle_errors subrequests carry the client's
  // Upgrade headers; answer them here instead of proxying them to Claude.
  const pathOnly = req.url.split("?")[0];
  if (pathOnly.startsWith("/__")) {
    let status = 404;
    if (pathOnly === "/__ban-check") status = isBanned(cleanIp(req.headers["x-client-ip"])) ? 429 : 200;
    else if (pathOnly === "/__authfail") status = recordFail(cleanIp(req.headers["x-client-ip"])) ? 429 : 401;
    socket.end("HTTP/1.1 " + status + " " + (http.STATUS_CODES[status] || "") + "\r\nconnection: close\r\ncontent-length: 0\r\n\r\n");
    return;
  }
  const t = resolveTarget(req.url);
  if (!t) { socket.end("HTTP/1.1 403 Forbidden\r\nconnection: close\r\ncontent-length: 0\r\n\r\n"); return; }
  // Caddy strips X-Remote-User on its cookie-authenticated WebSocket route.
  const user = sanitizeUser(req.headers["x-remote-user"]) || wsCookieUser(req.headers.cookie);
  // A stale cookie after a restart must not count as a password failure.
  if (!user) { socket.end("HTTP/1.1 401 Unauthorized\r\nconnection: close\r\ncontent-length: 0\r\n\r\n"); return; }
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
    metrics.wsOpened(user, socket);
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
    metrics.requestStarted(user);
    res.once("close", () => metrics.requestFinished(user, res.headersSent ? res.statusCode : 0));
    // The jar key comes from the Basic password Caddy has just verified.
    if (user && removedUsers.has(user) && basicPassword(req.headers.authorization, user)) removedUsers.delete(user);
    const unlocking = user ? unlockJar(user, req.headers.authorization) : null;
    if (!unlocking) return handleRequest(req, res, pathOnly, user);
    unlocking.then(() => { if (!res.destroyed) handleRequest(req, res, pathOnly, user); }, () => {
      console.error("[cookies] user=" + user + " jar key derivation failed");
      if (!res.headersSent) json(res, 503, { error: "jar_unavailable" });
    });
  });
  server.on("upgrade", handleUpgrade);
  // Never accept proxy credentials or tunnels on the internal HTTP listener.
  server.on("connect", (req, socket) => socket.end("HTTP/1.1 403 Forbidden\r\nconnection: close\r\ncontent-length: 0\r\n\r\n"));
  return server;
}

function handleRequest(req, res, pathOnly, user) {
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
  // Rewritten documents, scripts and styles differ from upstream's bytes, so
  // upstream validators must not answer for them: a 304 kept stale or
  // corrupted copies alive in browsers and in Cloudflare's cache.
  if (likelyRewritten(req.headers, urlPath)) { delete headers["if-modified-since"]; delete headers["if-none-match"]; }
  const logPath = redactPath(urlPath);
  if (user) statOf(user).lastSeen = Date.now();

  const cacheable = req.method === "GET" && CACHE_HOSTS.has(host) && !req.headers["range"];
  const cacheKey = host + urlPath;
  if (cacheable) {
    const hit = cacheGet(cacheKey);
    if (hit) {
      res.writeHead(hit.status, withWsCookie(Object.assign({}, hit.headers, { "content-length": hit.body.length, "x-cache": "HIT" }), user, req.headers.cookie));
      metrics.bytes(user, 0, hit.body.length);
      return res.end(hit.body);
    }
  }

  const sentAt = Date.now();
  const proxyReq = https.request({ hostname: host, port: 443, path: urlPath, method: req.method, headers }, (up) => {
    metrics.ttfb(Date.now() - sentAt);
    // Attached in the same tick as pipe()/the buffering listener below.
    up.on("data", chunk => metrics.bytes(user, 0, chunk.length));
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
    const preserveBody = req.method === "HEAD" || [204, 205, 304].includes(up.statusCode) || up.statusCode === 206 || !!req.headers.range || !!rh["content-range"]
      || /^\s*attachment\s*(?:;|$)/i.test(String(rh["content-disposition"] || ""));
    const rewritable = !preserveBody && (ct.includes("text/html") || ct.includes("text/css") || ct.includes("javascript"));
    const cl = parseInt(up.headers["content-length"] || "0", 10);
    const canCache = cacheable && up.statusCode === 200 && cl > 0 && cl <= cfg.cacheMaxItem;

    if (!rewritable && !canCache) {
      if (up.headers["content-length"]) rh["content-length"] = up.headers["content-length"];
      edgeHeaders(rh, host);
      console.log("[resp] " + (user || "-") + " " + host + " " + logPath + " -> " + up.statusCode);
      res.writeHead(up.statusCode, withWsCookie(rh, user, req.headers.cookie));
      up.pipe(res);
      return;
    }
    const chunks = []; let size = 0, aborted = false;
    up.on("data", (c) => {
      size += c.length;
      if (size > cfg.maxRewriteBytes) { aborted = true; up.destroy(); if (!res.headersSent) { res.writeHead(502); } res.end(); return; }
      chunks.push(c);
    });
    up.on("end", async () => {
      if (aborted || res.destroyed || res.writableEnded) return;
      try {
        let body = Buffer.concat(chunks);
        if (rewritable) {
          body = await decodeRewriteBody(body, up.headers["content-encoding"]);
          if (res.destroyed || res.writableEnded) return;
          body = rewriteBody(body, ct);
          if (body.length > cfg.maxRewriteBytes) return failResponse();
          // Rewritten bytes form a new identity representation, so origin byte
          // validators and range support no longer describe the response.
          for (const name of ["content-encoding", "etag", "last-modified", "content-md5", "digest", "content-digest", "repr-digest", "accept-ranges"]) delete rh[name];
          rh["cache-control"] = ct.includes("text/html") ? "no-cache, no-store, must-revalidate" : "public, max-age=86400";
        }
        edgeHeaders(rh, host);
        rh["content-length"] = body.length;
        if (canCache) {
          const stored = Object.assign({}, rh); delete stored["date"]; delete stored["age"];
          cachePut(cacheKey, { status: up.statusCode, headers: stored, body: body });
        }
        console.log("[resp] " + (user || "-") + " " + host + " " + logPath + " -> " + up.statusCode + (rewritable ? " (rewritten)" : ""));
        // After cachePut: the shared cache must never hold a per-user cookie.
        res.writeHead(up.statusCode, withWsCookie(rh, user, req.headers.cookie));
        res.end(body);
      } catch (_) {
        failResponse();
      }
    });
  });

  proxyReq.setTimeout(cfg.upstreamIdleMs, () => proxyReq.destroy(new Error("upstream idle timeout")));
  let clientGone = false;
  proxyReq.on("error", (e) => {
    // A browser that navigated away aborts the request; that is not an upstream fault.
    if (!clientGone) { console.error("[upstream] " + host + " " + logPath + " " + safeError(e)); metrics.upstreamError(); }
    if (!res.headersSent) { res.writeHead(502, { "content-type": "text/plain" }); res.end("bad gateway"); } else res.destroy();
  });
  req.on("aborted", () => { clientGone = true; proxyReq.destroy(); });
  res.once("close", () => { if (!res.writableEnded) { clientGone = true; proxyReq.destroy(); } });
  req.on("data", chunk => metrics.bytes(user, chunk.length, 0));
  req.pipe(proxyReq); // stream the body — no buffering of uploads
}

// Artifact iframes must keep their real origin (postMessage checks it) while the
// TCP connection comes from this server, so the user's IP is not revealed.
function isArtifactProxyHost(host) {
  host = canonicalHost(host);
  return host === "claudeusercontent.com" || host.endsWith(".claudeusercontent.com")
    || host === "claudemcpcontent.com" || host.endsWith(".claudemcpcontent.com");
}

// Claude's login (send_magic_link) requires an invisible hCaptcha token; its
// script, frame and API use hcaptcha.com subdomains.
function isChallengeHost(host) {
  host = canonicalHost(host);
  return host === "hcaptcha.com" || host.endsWith(".hcaptcha.com");
}

function parseConnectTarget(target) {
  const match = /^([^:]+):443$/.exec(String(target || ""));
  if (!match) return null;
  const host = canonicalHost(match[1]);
  return host && (isArtifactProxyHost(host) || isChallengeHost(host) || CONNECT_DEPENDENCY_HOSTS.has(host)) ? host : null;
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
    metrics.bytes(session.user, socket.bytesRead, socket.bytesWritten);
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
      metrics.tunnelOpened(session.user);
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
  unlockJar, forgetJarKeys, basicPassword, jarKeys, adminStatus, revokeUser, createAdminServer, metrics, HISTORY_FIELDS,
  mintProxySession, verifyProxyAuth, proxyEndpoint, connectReady, isPublicAddress, resolveConnectAddress,
  sanitizeUser, userFile, loadJar, cookieHeaderFor, captureSetCookies,
  buildUpstreamHeaders, buildResponseHeaders, rewriteBody, rewriteCsp, rewriteUrls, redactPath, createServer, createConnectServer, allowedHost, isArtifactProxyHost, isChallengeHost, parseConnectTarget, edgeHeaders, likelyRewritten, wsCookieHeader, wsCookieUser, withWsCookie, resolveTarget, rewriteLocation,
  seal, unseal, migrateAll, isBanned, recordFail, cleanIp, cacheGet, cachePut, sessionState, noteClaudeResponse, listUsers,
};

if (require.main === module) {
  const n = migrateAll();
  if (n) console.log("[cookies] encrypted " + n + " plain jar(s)");
  console.log("[gateway] cookies at rest: sealed with each user's password key" +
    (cfg.cookiesKey ? " (legacy key present)" : " (no legacy key: password-less jars stay PLAIN)") +
    "; telegram: " + (cfg.tgToken ? "on" : "off") + "; admins: " + (cfg.adminUsers.join(",") || "-"));
  createServer().listen(cfg.port, cfg.listen, () =>
    console.log("[gateway] listening on " + cfg.listen + ":" + cfg.port + " public host " + cfg.publicHost));
  if (cfg.adminPort) createAdminServer().listen(cfg.adminPort, "127.0.0.1");
  setInterval(() => gauge(minute()), 15000).unref();
  setInterval(forgetJarKeys, 5 * 60 * 1000).unref();
  if (cfg.connectPort) {
    startConnectListener();
  }
}
