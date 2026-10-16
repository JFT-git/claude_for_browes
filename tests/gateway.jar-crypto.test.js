// Password-bound cookie encryption (v2), its migrations and the operator API.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "gateway-jar-crypto-"));
process.env.COOKIES_DIR = dir;
process.env.PUBLIC_HOST = "gateway.example.test";
const g = require("../gateway/gateway.js");

const basic = (user, password) => "Basic " + Buffer.from(user + ":" + password).toString("base64");
const file = user => path.join(dir, user + ".json");
const read = user => fs.readFileSync(file(user), "utf8");
const forgetAll = () => g.forgetJarKeys(Date.now() + 365 * 24 * 3600 * 1000);
async function unlock(user, password) { await (g.unlockJar(user, basic(user, password)) || Promise.resolve()); }

test.after(() => fs.rmSync(dir, { recursive: true, force: true }));

test("only a Basic password sent under the authenticated user name is used", () => {
  assert.equal(g.basicPassword(basic("alice", "pw:with:colons"), "alice"), "pw:with:colons");
  assert.equal(g.basicPassword(basic("alice", "pw"), "bob"), "");
  assert.equal(g.basicPassword(basic("alice", ""), "alice"), "");
  assert.equal(g.basicPassword("Bearer abc", "alice"), "");
  assert.equal(g.basicPassword("Basic " + "A".repeat(5000), "alice"), "");
  assert.equal(g.unlockJar("alice", undefined), null);
});

test("jars are sealed with the user's password key and never hold plaintext", async () => {
  fs.writeFileSync(file("alice"), '{"cookies":[]}', { mode: 0o600 });
  await unlock("alice", "alice-password-1");
  let doc = JSON.parse(read("alice"));
  assert.equal(doc.enc, 2, "a fresh plain jar is re-sealed on the first request");
  assert.equal(doc.user, "alice");
  assert.equal(doc.kdf.name, "scrypt"); assert.equal(doc.kdf.N, 32768); assert.equal(Buffer.from(doc.kdf.salt, "base64").length, 16);
  assert.ok(g.captureSetCookies("alice", ["sessionKey=SECRET-SESSION; Path=/; Max-Age=3600", "lastActiveOrg=ORG; Path=/"]));
  const raw = read("alice");
  assert.ok(!raw.includes("SECRET-SESSION") && !raw.includes("ORG"), "cookie values on disk");
  doc = JSON.parse(raw);
  assert.equal(doc.meta.session, true); assert.equal(doc.meta.cookies, 2);
  assert.equal(fs.statSync(file("alice")).mode & 0o777, 0o600);
  assert.match(g.cookieHeaderFor("alice"), /sessionKey=SECRET-SESSION/);
  assert.equal(g.unlockJar("alice", basic("alice", "alice-password-1")), null, "the key stays cached");
});

test("without the key in memory a jar is locked: no cookies, no overwrite, state from metadata", async () => {
  await unlock("alice", "alice-password-1");
  assert.equal(forgetAll() >= 1, true);
  const before = read("alice");
  assert.equal(g.cookieHeaderFor("alice"), "");
  assert.equal(g.sessionState("alice"), "ok");
  assert.equal(g.captureSetCookies("alice", ["sessionKey=ATTACKER; Max-Age=60"]), false);
  assert.equal(read("alice"), before);
  const listed = g.listUsers().find(u => u.user === "alice");
  assert.equal(listed.encryption, "v2"); assert.equal(listed.unlocked, false); assert.equal(listed.cookies, 2);
  await unlock("alice", "alice-password-1");
  assert.match(g.cookieHeaderFor("alice"), /sessionKey=SECRET-SESSION/);
});

test("a jar opens only for its own user name and with untouched metadata", async () => {
  fs.copyFileSync(file("alice"), file("mallory"));
  await unlock("mallory", "alice-password-1");
  assert.equal(g.cookieHeaderFor("mallory"), "", "a copied jar must not open under another name");
  const doc = JSON.parse(read("alice"));
  doc.meta.cookies = 99;
  fs.writeFileSync(file("tampered"), JSON.stringify(Object.assign(doc, { user: "tampered" })));
  await unlock("tampered", "alice-password-1");
  assert.equal(g.cookieHeaderFor("tampered"), "");
});

test("password reset keeps the session while the old key is in memory, otherwise starts a new one", async () => {
  fs.writeFileSync(file("bob"), '{"cookies":[]}');
  await unlock("bob", "bob-password-old");
  g.captureSetCookies("bob", ["sessionKey=BOB-SESSION; Max-Age=3600"]);
  await unlock("bob", "bob-password-new");
  assert.match(g.cookieHeaderFor("bob"), /BOB-SESSION/);
  forgetAll();
  await unlock("bob", "bob-password-old");
  assert.equal(g.cookieHeaderFor("bob"), "", "the old password no longer opens the jar");
  forgetAll();
  await unlock("bob", "bob-password-new");
  assert.match(g.cookieHeaderFor("bob"), /BOB-SESSION/);
  // Reset while the gateway restarted: the jar belongs to the previous password.
  forgetAll();
  await unlock("bob", "bob-password-third");
  assert.equal(g.cookieHeaderFor("bob"), "");
  assert.ok(g.captureSetCookies("bob", ["sessionKey=BOB-NEW-LOGIN; Max-Age=3600"]), "the verified user may log in again");
  forgetAll();
  await unlock("bob", "bob-password-third");
  assert.match(g.cookieHeaderFor("bob"), /BOB-NEW-LOGIN/);
});

test("legacy COOKIES_KEY jars move to the password key on the next request", async () => {
  g.cfg.cookiesKey = crypto.randomBytes(32);
  try {
    fs.writeFileSync(file("carol"), g.seal(JSON.stringify({ cookies: [{ name: "sessionKey", value: "CAROL-LEGACY", expires: 0 }] })));
    assert.equal(JSON.parse(read("carol")).enc, 1);
    assert.match(g.cookieHeaderFor("carol"), /CAROL-LEGACY/);
    await unlock("carol", "carol-password-1");
    const raw = read("carol");
    assert.equal(JSON.parse(raw).enc, 2);
    assert.ok(!raw.includes("CAROL-LEGACY"));
    g.cfg.cookiesKey = null;  // .env without the old key no longer matters
    forgetAll();
    await unlock("carol", "carol-password-1");
    assert.match(g.cookieHeaderFor("carol"), /CAROL-LEGACY/);
    assert.equal(g.migrateAll(), 0, "startup migration leaves v2 jars alone");
  } finally { g.cfg.cookiesKey = null; }
});

test("parallel requests after a restart share one key derivation", async () => {
  fs.writeFileSync(file("dave"), '{"cookies":[]}');
  const a = g.unlockJar("dave", basic("dave", "dave-password-1"));
  const b = g.unlockJar("dave", basic("dave", "dave-password-1"));
  assert.ok(a && a === b);
  await a;
  assert.equal(g.unlockJar("dave", basic("dave", "dave-password-1")), null);
});

test("HTTP requests unlock the jar only with matching Basic credentials", async () => {
  fs.writeFileSync(file("erin"), '{"cookies":[]}');
  const server = g.createServer();
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const base = "http://127.0.0.1:" + server.address().port;
  try {
    let r = await fetch(base + "/__health", { headers: { "x-remote-user": "erin", authorization: basic("someone", "erin-password-1") } });
    assert.equal(r.status, 200);
    assert.equal(g.jarKeys.has("erin"), false);
    r = await fetch(base + "/__health", { headers: { "x-remote-user": "erin", authorization: basic("erin", "erin-password-1") } });
    assert.equal((await r.json()).user, "erin");
    assert.equal(g.jarKeys.has("erin"), true);
    assert.equal(JSON.parse(read("erin")).enc, 2);
  } finally { server.close(); }
});

test("operator API reports load and users without secrets, revokes and unbans", async () => {
  await unlock("alice", "alice-password-1");
  g.metrics.requestStarted("alice"); g.metrics.bytes("alice", 100, 900); g.metrics.requestFinished("alice", 429);
  for (let i = 0; i < g.cfg.authMaxFails; i++) g.recordFail("198.51.100.23");
  const wsCookie = g.wsCookieHeader("alice", Date.now() - 5000).split(";")[0];
  assert.equal(g.wsCookieUser(wsCookie), "alice");

  const admin = g.createAdminServer();
  await new Promise(resolve => admin.listen(0, "127.0.0.1", resolve));
  const base = "http://127.0.0.1:" + admin.address().port;
  try {
    const status = await (await fetch(base + "/status?history=5")).json();
    const text = JSON.stringify(status);
    for (const secret of ["SECRET-SESSION", "alice-password-1", "BOB-SESSION"]) assert.ok(!text.includes(secret), secret);
    assert.deepEqual(status.history.fields, g.HISTORY_FIELDS);
    const row = status.history.rows[status.history.rows.length - 1];
    const col = name => row[status.history.fields.indexOf(name)];
    assert.ok(col("req") >= 1 && col("r429") >= 1 && col("bytesOut") >= 900);
    const alice = status.users.find(u => u.user === "alice");
    assert.equal(alice.encryption, "v2"); assert.equal(alice.unlocked, true); assert.ok(alice.requests24h >= 1);
    assert.ok(status.encryption.jars.v2 >= 3);
    assert.ok(status.bans.some(b => b.ip === "198.51.100.23"));

    const revoked = await (await fetch(base + "/users/alice/revoke?forget=1", { method: "POST" })).json();
    assert.deepEqual([revoked.user, revoked.forgotten], ["alice", true]);
    assert.equal(g.jarKeys.has("alice"), false);
    assert.equal(g.wsCookieUser(wsCookie), "", "WebSocket cookies issued before revocation are void");
    assert.equal(g.captureSetCookies("alice", ["late=1; Max-Age=60"]), false, "responses in flight cannot recreate a removed user's jar");
    assert.equal((await fetch(base + "/users/..%2Fx/revoke", { method: "POST" })).status, 400);

    const cleared = await (await fetch(base + "/bans/198.51.100.23/clear", { method: "POST" })).json();
    assert.equal(cleared.cleared, true);
    assert.equal(g.isBanned("198.51.100.23"), false);
    assert.equal((await fetch(base + "/nope")).status, 404);
  } finally { admin.close(); }
});
