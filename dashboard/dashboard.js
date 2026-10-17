#!/usr/bin/env node
// Local operator dashboard for a Claude gateway: users, adding and removing
// them, and the gateway's load. It runs on the operator's own computer and
// reaches the server only over SSH (server/admin.sh), so the server exposes
// nothing new to the Internet.
//
//   node dashboard/dashboard.js root@203.0.113.10 [--dir /root/claude-browser] [--port 8790] [--no-open]
//
// The server address is remembered in ~/.config/claude-gateway/dashboard.json;
// later runs (or dashboard/start.command) need no arguments.
//
// The page listens on 127.0.0.1 only and every API call needs a random
// per-launch token. Generated passwords pass through memory once; they are
// never logged or written anywhere.
"use strict";
const http = require("http");
const fs = require("fs");
const os = require("os");
const path = require("path");
const readline = require("readline");
const crypto = require("crypto");
const { spawn } = require("child_process");

const USER_RE = /^(?!\.{1,2}$)[A-Za-z0-9._-]{1,64}$/;
const IP_RE = /^[0-9a-fA-F:.]{2,45}$/;
const PUBLIC = path.join(__dirname, "public");
const STATIC = { "/": ["index.html", "text/html; charset=utf-8"], "/app.js": ["app.js", "text/javascript; charset=utf-8"], "/app.css": ["app.css", "text/css; charset=utf-8"] };
const SECURITY_HEADERS = {
  "content-security-policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  "x-frame-options": "DENY", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer", "cache-control": "no-store",
  "cross-origin-opener-policy": "same-origin", "cross-origin-resource-policy": "same-origin",
};

function usage(message) {
  if (message) console.error("Error: " + message);
  console.error("Usage: node dashboard/dashboard.js <ssh-destination> [--dir /root/claude-browser] [--port 8790] [--no-open]");
  process.exit(2);
}

const OPTIONS_WITH_VALUE = new Set(["--dir", "--port", "--interval"]);
function hasTarget(argv) {
  for (let i = 0; i < argv.length; i++) {
    if (OPTIONS_WITH_VALUE.has(argv[i])) i++;
    else if (!argv[i].startsWith("-")) return true;
  }
  return false;
}
// Adds the remembered server unless one is given; parseArgs validates it.
function withSaved(argv, saved) {
  if (hasTarget(argv) || !saved || typeof saved.target !== "string" || !saved.target) return argv;
  const dir = typeof saved.dir === "string" && saved.dir && !argv.includes("--dir") ? ["--dir", saved.dir] : [];
  return [saved.target, ...dir, ...argv];
}
const configFile = () => path.join(process.env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config"), "claude-gateway", "dashboard.json");
function loadSaved() {
  try { const d = JSON.parse(fs.readFileSync(configFile(), "utf8")); return d && typeof d === "object" ? d : {}; } catch (_) { return {}; }
}
function saveTarget(opts) {
  try {
    fs.mkdirSync(path.dirname(configFile()), { recursive: true, mode: 0o700 });
    fs.writeFileSync(configFile(), JSON.stringify({ target: opts.target, dir: opts.dir }, null, 2) + "\n", { mode: 0o600 });
  } catch (_) { /* remembering is a convenience */ }
}
// One interface for all questions: answers typed ahead are not lost.
async function askAll(questions) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const answers = [];
  try { for (const q of questions) answers.push((await new Promise(resolve => rl.question(q, resolve))).trim()); }
  finally { rl.close(); }
  return answers;
}

function parseArgs(argv) {
  const opts = { target: "", dir: "/root/claude-browser", port: 8790, open: true, interval: 5 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--dir") opts.dir = argv[++i] || "";
    else if (a === "--port") opts.port = Number(argv[++i]);
    else if (a === "--interval") opts.interval = Number(argv[++i]);
    else if (a === "--no-open") opts.open = false;
    else if (a === "-h" || a === "--help") usage();
    else if (!opts.target && !a.startsWith("-")) opts.target = a;
    else usage("unknown argument " + JSON.stringify(a));
  }
  // The destination becomes an ssh argument: never let it look like an option.
  if (!/^[A-Za-z0-9_][A-Za-z0-9._@:-]{0,254}$/.test(opts.target)) usage("ssh destination like root@203.0.113.10 or a Host alias from ~/.ssh/config");
  if (!/^\/[A-Za-z0-9_./-]{1,255}$/.test(opts.dir) || opts.dir.split("/").includes("..")) usage("--dir must be an absolute path");
  if (!Number.isInteger(opts.port) || opts.port < 1024 || opts.port > 65535) usage("--port must be 1024–65535");
  if (!Number.isInteger(opts.interval) || opts.interval < 2 || opts.interval > 300) usage("--interval must be 2–300 seconds");
  return opts;
}

// ------------------------------------------------------------------ parsing ----

// admin.sh prints "@@section" headers; "@@end" closes one snapshot.
function parseSnapshot(text) {
  const sections = {};
  let name = null;
  for (const line of text.split("\n")) {
    if (line.startsWith("@@")) { name = line.slice(2).trim(); sections[name] = []; continue; }
    if (name && line.trim()) sections[name].push(line);
  }
  const json = s => { try { return JSON.parse(s); } catch (_) { return null; } };
  const pairs = lines => Object.fromEntries((lines || []).map(l => { const i = l.indexOf(" "); return i < 0 ? [l, ""] : [l.slice(0, i), l.slice(i + 1)]; }));
  // "TIMESTAMP {json}" from `docker compose logs --timestamps`.
  const frontLine = (sections.frontdoor || [])[0] || "";
  const brace = frontLine.indexOf("{");
  const frontdoor = brace >= 0 ? json(frontLine.slice(brace)) : null;
  return {
    gateway: json((sections.gateway || []).join("\n")),
    frontdoor: frontdoor && frontdoor.event === "frontdoor_diagnostics" ? Object.assign({ at: frontLine.slice(0, brace).trim() }, frontdoor) : null,
    containers: (sections.containers || []).map(json).filter(Boolean).map(parseContainer),
    host: pairs(sections.host),
    config: pairs(sections.config),
  };
}

const UNITS = { b: 1, kb: 1e3, mb: 1e6, gb: 1e9, tb: 1e12, kib: 1024, mib: 1024 ** 2, gib: 1024 ** 3, tib: 1024 ** 4 };
function bytes(text) {
  const m = /^\s*([\d.]+)\s*([a-z]*)\s*$/i.exec(String(text || ""));
  return m ? Math.round(parseFloat(m[1]) * (UNITS[m[2].toLowerCase()] || 1)) : 0;
}
function parseContainer(c) {
  const [memUsed, memLimit] = String(c.MemUsage || "").split("/");
  const [netIn, netOut] = String(c.NetIO || "").split("/");
  const name = String(c.Name || "").replace(/^.*?[-_](frontdoor|gateway|caddy)[-_]\d+$/, "$1");
  return { name, cpu: parseFloat(c.CPUPerc) || 0, memUsed: bytes(memUsed), memLimit: bytes(memLimit), netIn: bytes(netIn), netOut: bytes(netOut), pids: Number(c.PIDs) || 0 };
}

// ------------------------------------------------------------------- state ----

function createState() {
  return {
    connected: false, error: "", lastUpdate: 0, snapshot: null,
    history: new Map(),          // minute -> row (gateway HISTORY_FIELDS)
    fields: null,
    frontdoor: [],               // [{ t, active, active_peak, capacity_rejected, accepted }]
    cpu: [],                     // [{ t, frontdoor, gateway, caddy }]
  };
}

function absorb(state, snap, now = Date.now()) {
  state.snapshot = snap;
  state.lastUpdate = now;
  const g = snap.gateway;
  if (g && g.history && Array.isArray(g.history.fields)) {
    state.fields = g.history.fields;
    for (const row of g.history.rows || []) state.history.set(row[0], row);
    if (state.history.size > 1440) {
      const old = Array.from(state.history.keys()).sort((a, b) => a - b).slice(0, state.history.size - 1440);
      for (const t of old) state.history.delete(t);
    }
  }
  const f = snap.frontdoor;
  if (f && f.at && !state.frontdoor.some(x => x.at === f.at)) {
    state.frontdoor.push({ at: f.at, t: Date.parse(f.at) || now, active: f.active, active_peak: f.active_peak, capacity_rejected: f.capacity_rejected, accepted: f.accepted });
    while (state.frontdoor.length > 2880) state.frontdoor.shift();
  }
  if (snap.containers.length) {
    const point = { t: now };
    for (const c of snap.containers) point[c.name] = c.cpu;
    state.cpu.push(point);
    while (state.cpu.length > 720) state.cpu.shift();
  }
}

function publicState(state, opts) {
  const snap = state.snapshot || {};
  const gateway = snap.gateway && !snap.gateway.error ? Object.assign({}, snap.gateway, { history: undefined }) : null;
  return {
    target: opts.target, connected: state.connected, error: state.error, lastUpdate: state.lastUpdate, now: Date.now(),
    gatewayError: snap.gateway && snap.gateway.error ? snap.gateway.error : null,
    gateway, history: { fields: state.fields, rows: Array.from(state.history.values()).sort((a, b) => a[0] - b[0]) },
    frontdoor: { latest: snap.frontdoor || null, series: state.frontdoor.slice(-240) },
    containers: snap.containers || [], cpu: state.cpu.slice(-360), host: snap.host || {}, config: snap.config || {},
  };
}

// --------------------------------------------------------------------- ssh ----

function sshArgs(opts, words) {
  return ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3",
    "--", opts.target, opts.dir + "/admin.sh", ...words];
}
const sshBin = () => process.env.DASHBOARD_SSH || "ssh";
function lastLine(text) { return String(text || "").trim().split("\n").pop().replace(/[^\x20-\x7eЀ-ӿ]/g, "").slice(0, 300); }

function runAdmin(opts, words, timeoutMs = 90000) {
  return new Promise(resolve => {
    const child = spawn(sshBin(), sshArgs(opts, words), { stdio: ["ignore", "pipe", "pipe"] });
    let out = "", err = "";
    const timer = setTimeout(() => child.kill("SIGTERM"), timeoutMs);
    child.stdout.on("data", c => { out += c; });
    child.stderr.on("data", c => { err += c; });
    child.on("error", e => { clearTimeout(timer); resolve({ code: -1, out: "", err: e.message }); });
    child.on("close", code => { clearTimeout(timer); resolve({ code, out, err }); });
  });
}

function startWatcher(opts, state, onFirstError) {
  let child = null, buffer = "", delay = 2000, stopped = false, retry = null, reported = false;
  const connect = () => {
    if (stopped) return;
    buffer = "";
    let stderr = "";
    child = spawn(sshBin(), sshArgs(opts, ["watch", String(opts.interval)]), { stdio: ["ignore", "pipe", "pipe"] });
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", chunk => {
      buffer += chunk;
      if (buffer.length > 8 * 1024 * 1024) buffer = buffer.slice(-1024 * 1024);
      let end;
      while ((end = buffer.indexOf("\n@@end\n")) >= 0 || buffer.startsWith("@@end\n")) {
        const cut = end >= 0 ? end + 7 : 6;
        const text = buffer.slice(0, cut);
        buffer = buffer.slice(cut);
        absorb(state, parseSnapshot(text));
        state.connected = true; state.error = ""; delay = 2000;
      }
    });
    child.stderr.on("data", c => { stderr = (stderr + c).slice(-4000); });
    child.on("error", e => { state.error = e.message; });
    child.on("close", code => {
      state.connected = false;
      state.error = lastLine(stderr) || "ssh exited with code " + code;
      if (!reported && onFirstError) { reported = true; onFirstError(state.error); }
      if (!stopped) retry = setTimeout(connect, delay);
      delay = Math.min(delay * 2, 30000);
    });
  };
  connect();
  return { stop() { stopped = true; clearTimeout(retry); if (child) child.kill("SIGTERM"); } };
}

// ------------------------------------------------------------------ server ----

function createDashboardServer(opts, state, token) {
  // opts.port is final once listen() succeeds; read it per request.
  const own = () => ["127.0.0.1:" + opts.port, "localhost:" + opts.port];
  const tokenBuf = Buffer.from(token);
  const send = (res, code, body, type = "application/json; charset=utf-8") => {
    res.writeHead(code, Object.assign({ "content-type": type }, SECURITY_HEADERS));
    res.end(typeof body === "string" || Buffer.isBuffer(body) ? body : JSON.stringify(body));
  };
  const refresh = async () => {
    const r = await runAdmin(opts, ["status", "5"], 60000);
    if (r.code === 0) absorb(state, parseSnapshot(r.out));
  };
  const action = async (res, words, label) => {
    const r = await runAdmin(opts, words);
    if (r.code !== 0) {
      console.log("[action] " + label + ": failed");
      return send(res, 502, { error: lastLine(r.err) || "command failed" });
    }
    console.log("[action] " + label + ": ok");
    let body = {};
    try { body = JSON.parse(r.out.trim().split("\n").pop() || "{}"); } catch (_) { body = {}; }
    send(res, 200, body);
    refresh().catch(() => {});
  };
  const readJson = req => new Promise(resolve => {
    let data = "";
    req.on("data", c => { data += c; if (data.length > 4096) req.destroy(); });
    req.on("end", () => { try { resolve(JSON.parse(data || "{}")); } catch (_) { resolve(null); } });
    req.on("error", () => resolve(null));
  });

  return http.createServer(async (req, res) => {
    // DNS rebinding: only our own loopback name may address this server.
    if (!own().includes(String(req.headers.host || "").toLowerCase())) return send(res, 421, { error: "misdirected" });
    const url = new URL(req.url, "http://127.0.0.1");
    if (req.method === "GET" && STATIC[url.pathname]) {
      const [file, type] = STATIC[url.pathname];
      return fs.readFile(path.join(PUBLIC, file), (err, body) => err ? send(res, 500, { error: "missing asset" }) : send(res, 200, body, type));
    }
    if (!url.pathname.startsWith("/api/")) return send(res, 404, { error: "not_found" });
    const got = Buffer.from(String(req.headers["x-dashboard-token"] || ""));
    if (got.length !== tokenBuf.length || !crypto.timingSafeEqual(got, tokenBuf)) return send(res, 401, { error: "token" });
    if (req.method !== "GET") {
      // Cross-site pages cannot send this content type or header without a preflight we never answer.
      if (req.headers.origin && !own().map(h => "http://" + h).includes(req.headers.origin)) return send(res, 403, { error: "origin" });
      if (!/^application\/json\b/.test(String(req.headers["content-type"] || ""))) return send(res, 415, { error: "json_only" });
    }
    if (req.method === "GET" && url.pathname === "/api/state") return send(res, 200, publicState(state, opts));
    if (req.method === "POST" && url.pathname === "/api/users") {
      const body = await readJson(req);
      const name = body && typeof body.name === "string" ? body.name.trim() : "";
      if (!USER_RE.test(name)) return send(res, 400, { error: "Имя: 1–64 латинских букв, цифр, точек, дефисов или подчёркиваний" });
      return action(res, ["add", name], "add user " + name);
    }
    let m = /^\/api\/users\/([^/]+)(\/reset)?$/.exec(url.pathname);
    if (m) {
      const name = decodeURIComponent(m[1]);
      if (!USER_RE.test(name)) return send(res, 400, { error: "invalid user" });
      if (req.method === "POST" && m[2]) return action(res, ["reset", name], "reset password " + name);
      if (req.method === "DELETE" && !m[2]) {
        const body = await readJson(req);
        if (!body || body.confirm !== name) return send(res, 400, { error: "confirmation does not match" });
        return action(res, ["remove", name], "remove user " + name);
      }
    }
    m = /^\/api\/bans\/([^/]+)\/clear$/.exec(url.pathname);
    if (m && req.method === "POST") {
      const ip = decodeURIComponent(m[1]);
      if (!IP_RE.test(ip)) return send(res, 400, { error: "invalid ip" });
      return action(res, ["unban", ip], "unban " + ip);
    }
    send(res, 404, { error: "not_found" });
  });
}

function listen(server, opts, attempts = 20) {
  const first = opts.port;
  return new Promise((resolve, reject) => {
    const tryPort = p => {
      opts.port = p;
      server.once("error", e => (e.code === "EADDRINUSE" && p < first + attempts ? tryPort(p + 1) : reject(e)));
      server.listen(p, "127.0.0.1", () => resolve(p));
    };
    tryPort(first);
  });
}

function openBrowser(url) {
  const [cmd, args] = process.platform === "darwin" ? ["open", [url]] : process.platform === "win32" ? ["cmd", ["/c", "start", "", url]] : ["xdg-open", [url]];
  try { spawn(cmd, args, { stdio: "ignore", detached: true }).unref(); } catch (_) { /* printed below anyway */ }
}

async function main() {
  let argv = withSaved(process.argv.slice(2), loadSaved());
  if (!hasTarget(argv) && process.stdin.isTTY && !argv.some(a => a === "-h" || a === "--help")) {
    console.log("Панель шлюза Claude: первый запуск.");
    const [target, dir] = await askAll(["SSH-адрес сервера (например root@203.0.113.10): ", "Каталог установки на сервере [/root/claude-browser]: "]);
    argv = [target, ...(dir ? ["--dir", dir] : []), ...argv];
  }
  const opts = parseArgs(argv);
  saveTarget(opts);
  const state = createState();
  const token = crypto.randomBytes(24).toString("base64url");
  const server = createDashboardServer(opts, state, token);
  await listen(server, opts);
  const watcher = startWatcher(opts, state, error => {
    console.error("SSH: " + error);
    if (/permission denied|publickey/i.test(error)) console.error("Нужен вход по ключу: выполните ssh-copy-id " + opts.target + " и запустите панель снова.");
    else if (/admin\.sh|no such file/i.test(error)) console.error("На сервере нет admin.sh: обновите сервер (git pull && bash install.sh) или укажите --dir.");
  });
  const url = "http://127.0.0.1:" + opts.port + "/#token=" + token;
  console.log("Claude gateway dashboard for " + opts.target + ":" + opts.dir);
  console.log("Open: " + url);
  console.log("Stop: Ctrl+C");
  if (opts.open) openBrowser(url);
  const stop = () => { watcher.stop(); server.close(); process.exit(0); };
  process.on("SIGINT", stop); process.on("SIGTERM", stop);
}

module.exports = { parseArgs, hasTarget, withSaved, parseSnapshot, parseContainer, createState, absorb, publicState, createDashboardServer, sshArgs, runAdmin, startWatcher };

if (require.main === module) main().catch(e => { console.error("Error: " + e.message); process.exit(1); });
