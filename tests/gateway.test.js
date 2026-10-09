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
