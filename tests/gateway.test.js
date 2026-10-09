// Run: node --test tests/
const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-"));
process.env.COOKIES_DIR = dir;
process.env.PUBLIC_HOST = "gw.example.org";
const g = require("../gateway/gateway.js");

test("sanitizeUser blocks traversal and junk", () => {
  assert.strictEqual(g.sanitizeUser("alice"), "alice");
  assert.ok(!/[\/\\]/.test(g.sanitizeUser("../../etc/passwd")));
  assert.strictEqual(g.sanitizeUser(".."), "");
  assert.strictEqual(g.sanitizeUser(undefined), "");
  assert.strictEqual(g.sanitizeUser("a".repeat(65)), "");
  assert.ok(g.userFile("../x").startsWith(dir));
});

test("upstream headers never reveal the client", () => {
  const h = g.buildUpstreamHeaders({
    host: "gw.example.org", cookie: "evil=1", authorization: "Basic xxx", referer: "https://gw.example.org/",
    origin: "https://gw.example.org", "x-forwarded-for": "1.2.3.4", "cf-connecting-ip": "1.2.3.4",
    "cf-ipcountry": "RU", "x-real-ip": "1.2.3.4", forwarded: "for=1.2.3.4", via: "1.1 cf", "cdn-loop": "cloudflare",
    "x-remote-user": "alice", "accept-language": "ru-RU", "user-agent": "X", "x-forwarded-proto": "https",
  }, "claude.ai", "sessionKey=abc");
  for (const k of ["authorization", "x-forwarded-for", "cf-connecting-ip", "cf-ipcountry", "x-real-ip",
    "forwarded", "via", "cdn-loop", "x-remote-user", "x-forwarded-proto"]) assert.ok(!(k in h), k + " leaked");
  assert.strictEqual(h.cookie, "sessionKey=abc");
  assert.strictEqual(h.origin, "https://claude.ai");
  assert.strictEqual(h["accept-language"], "en-US,en;q=0.9");
  assert.strictEqual(h.host, "claude.ai");
});

test("cookies are not sent to non-claude hosts", () => {
  const h = g.buildUpstreamHeaders({ cookie: "x=1" }, "api.anthropic.com", "sessionKey=abc");
  assert.ok(!("cookie" in h));
  assert.ok(!g.COOKIE_HOSTS.has("assets.claude.ai"));
});

test("cookie jar: capture, merge, expiry, deletion, permissions", () => {
  assert.strictEqual(g.cookieHeaderFor("bob"), "");
  fs.writeFileSync(path.join(dir, "bob.json"), '{"cookies":[]}');
  assert.ok(g.captureSetCookies("bob", ["sessionKey=s1; Path=/; HttpOnly; Max-Age=3600", "lastActiveOrg=o1; Path=/"]));
  assert.match(g.cookieHeaderFor("bob"), /sessionKey=s1/);
  assert.match(g.cookieHeaderFor("bob"), /lastActiveOrg=o1/);
  assert.strictEqual(fs.statSync(path.join(dir, "bob.json")).mode & 0o777, 0o600);
  g.captureSetCookies("bob", ["lastActiveOrg=; Max-Age=0"]);          // deletion honoured
  assert.doesNotMatch(g.cookieHeaderFor("bob"), /lastActiveOrg/);
  g.captureSetCookies("bob", ["old=1; Expires=Thu, 01 Jan 1970 00:00:00 GMT"]);
  assert.doesNotMatch(g.cookieHeaderFor("bob"), /old=/);
  g.captureSetCookies("../evil", ["a=b"]);
  assert.ok(!fs.existsSync(path.join(dir, "..", "evil.json")));
});

test("corrupt jar does not crash", () => {
  fs.writeFileSync(path.join(dir, "carl.json"), "not json");
  assert.strictEqual(g.cookieHeaderFor("carl"), "");
});

test("logs never contain query strings", () => {
  assert.strictEqual(g.redactPath("/magic-link?token=SECRET&x=1"), "/magic-link");
  assert.strictEqual(g.redactPath("/a#frag"), "/a");
});

test("js rewriting spoofs location.origin for OAuth", () => {
  const js = 'var o=window.location.origin; var p=self.location.origin; var q=location.origin;';
  const out = g.rewriteBody(Buffer.from(js), "application/javascript").toString();
  assert.ok(!out.includes("location.origin"), "origin refs left: " + out);
  assert.match(out, /"https:\/\/claude.ai"/);
});

test("csp and body rewriting", () => {
  assert.match(g.rewriteCsp("script-src https://assets-proxy.anthropic.com"), /gw\.example\.org/);
  const out = g.rewriteBody(Buffer.from('<script src="https://assets-proxy.anthropic.com/a.js">'), "text/html").toString();
  assert.match(out, /https:\/\/gw\.example\.org\/p\/assets-proxy\.anthropic\.com\/a\.js/);
});

test("http: host allow-list, health, no set-cookie to browser", async () => {
  const srv = g.createServer();
  await new Promise(r => srv.listen(0, "127.0.0.1", r));
  const port = srv.address().port;
  const get = (p, h) => fetch("http://127.0.0.1:" + port + p, { headers: h });
  assert.strictEqual((await get("/__health")).status, 200);
  assert.strictEqual((await get("/p/evil.com/x")).status, 403);
  assert.strictEqual((await get("/p/169.254.169.254/latest")).status, 403);
  assert.strictEqual((await get("/p/claude.ai.evil.com/")).status, 403);
  srv.close();
});

// ------------------------------------------------------------ new features ----
const net = require("net");
const crypto = require("crypto");

test("UA/client hints pass through unchanged by default", () => {
  const h = g.buildUpstreamHeaders({ "user-agent": "Mozilla/5.0 (Macintosh) X", "sec-ch-ua-platform": '"macOS"' }, "claude.ai", "");
  assert.strictEqual(h["user-agent"], "Mozilla/5.0 (Macintosh) X");
  assert.strictEqual(h["sec-ch-ua-platform"], '"macOS"');
});

test("websocket headers are kept only for ws handshakes", () => {
  const inH = { upgrade: "websocket", connection: "Upgrade", "sec-websocket-key": "abc", "sec-websocket-version": "13" };
  const ws = g.buildUpstreamHeaders(inH, "claude.ai", "", { ws: true });
  assert.strictEqual(ws.upgrade, "websocket");
  assert.strictEqual(ws["sec-websocket-key"], "abc");
  assert.strictEqual(ws.origin, "https://claude.ai");
  assert.ok(!("upgrade" in g.buildUpstreamHeaders(inH, "claude.ai", "")));
});

test("cookies at rest: encrypted on write, plain files migrate, wrong key fails", () => {
  g.cfg.cookiesKey = crypto.randomBytes(32);
  try {
    fs.writeFileSync(path.join(dir, "enc1.json"), JSON.stringify({ cookies: [{ name: "sessionKey", value: "SECRETVALUE", expires: 0 }] }));
    assert.strictEqual(g.migrateAll() >= 1, true);
    const raw = fs.readFileSync(path.join(dir, "enc1.json"), "utf8");
    assert.ok(!raw.includes("SECRETVALUE"), "plaintext left on disk");
    assert.match(g.cookieHeaderFor("enc1"), /sessionKey=SECRETVALUE/);
    g.captureSetCookies("enc1", ["x=1; Max-Age=100"]);
    assert.ok(!fs.readFileSync(path.join(dir, "enc1.json"), "utf8").includes("SECRETVALUE"));
    g.cfg.cookiesKey = crypto.randomBytes(32);                 // wrong key
    assert.throws(() => g.unseal(raw));
  } finally { g.cfg.cookiesKey = null; }
});

test("brute-force protection bans an IP after N failures", () => {
  const ip = "203.0.113.7";
  for (let i = 0; i < g.cfg.authMaxFails - 1; i++) assert.strictEqual(g.recordFail(ip), false);
  assert.strictEqual(g.isBanned(ip), false);
  assert.strictEqual(g.recordFail(ip), true);
  assert.strictEqual(g.isBanned(ip), true);
  assert.strictEqual(g.isBanned("198.51.100.1"), false);
  assert.strictEqual(g.cleanIp("1.2.3.4; rm -rf"), "unknown");
});

test("static asset cache is an LRU bounded by bytes", () => {
  const old = g.cfg.cacheMaxBytes; g.cfg.cacheMaxBytes = 100;
  try {
    g.cachePut("a", { status: 200, headers: {}, body: Buffer.alloc(60) });
    g.cachePut("b", { status: 200, headers: {}, body: Buffer.alloc(30) });
    g.cacheGet("a");                                            // a is now most recent
    g.cachePut("c", { status: 200, headers: {}, body: Buffer.alloc(30) }); // evicts b
    assert.ok(g.cacheGet("a") && g.cacheGet("c"));
    assert.strictEqual(g.cacheGet("b"), undefined);
    g.cachePut("huge", { status: 200, headers: {}, body: Buffer.alloc(500) });
    assert.strictEqual(g.cacheGet("huge"), undefined);
  } finally { g.cfg.cacheMaxBytes = old; }
});

test("session state: none -> ok -> expired -> ok", () => {
  fs.writeFileSync(path.join(dir, "dana.json"), JSON.stringify({ cookies: [{ name: "sessionKey", value: "v", expires: 0 }] }));
  assert.strictEqual(g.sessionState("dana"), "ok");
  g.noteClaudeResponse("dana", "/api/organizations", 401, true);
  assert.strictEqual(g.sessionState("dana"), "expired");
  g.noteClaudeResponse("dana", "/api/organizations", 200, true);
  assert.strictEqual(g.sessionState("dana"), "ok");
  assert.strictEqual(g.sessionState("nobody"), "none");
  assert.ok(g.listUsers().some(u => u.user === "dana"));
});

test("http: internal auth endpoints, admin, extension page, websocket allow-list", async () => {
  g.cfg.adminUsers = ["root1"];
  const srv = g.createServer();
  await new Promise(r => srv.listen(0, "127.0.0.1", r));
  const port = srv.address().port, base = "http://127.0.0.1:" + port;
  const f = (p, h, m) => fetch(base + p, { headers: h, method: m || "GET" });
  assert.strictEqual((await f("/__ban-check", { "x-client-ip": "192.0.2.9" })).status, 200);
  for (let i = 0; i < g.cfg.authMaxFails; i++) await f("/__authfail", { "x-client-ip": "192.0.2.9" }, "POST");
  assert.strictEqual((await f("/__ban-check", { "x-client-ip": "192.0.2.9" })).status, 429);
  assert.strictEqual((await f("/__admin/status", { "x-remote-user": "alice" })).status, 403);
  assert.strictEqual((await f("/__admin/status")).status, 403);
  const adm = await f("/__admin/status", { "x-remote-user": "root1" });
  assert.strictEqual(adm.status, 200);
  assert.ok(Array.isArray((await adm.json()).users));
  assert.strictEqual((await f("/__ext/")).status, 401);
  const ext = await f("/__ext/", { "x-remote-user": "alice" });
  assert.strictEqual(ext.status, 200);
  assert.match(await ext.text(), /gw\.example\.org/);
  assert.strictEqual((await f("/__ext/%2e%2e%2f%2e%2e%2fetc%2fpasswd", { "x-remote-user": "alice" })).status, 404);
  const h = await (await f("/__health", { "x-remote-user": "dana" })).json();
  assert.strictEqual(h.session, "ok");
  // websocket to a non-allow-listed host is refused
  const resp = await new Promise((resolve) => {
    const s = net.connect(port, "127.0.0.1", () => s.write(
      "GET /p/evil.com/ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"));
    let buf = ""; s.on("data", d => buf += d); s.on("close", () => resolve(buf));
  });
  assert.match(resp, /^HTTP\/1\.1 403/);
  srv.close();
});
