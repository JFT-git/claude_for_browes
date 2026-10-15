"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const https = require("node:https");
const net = require("node:net");
const dns = require("node:dns").promises;
const { spawnSync } = require("node:child_process");
const g = require("../gateway/gateway.js");
const dir = fs.mkdtempSync(path.join(os.tmpdir(), "gateway-proxy-"));
const cert = path.join(dir, "proxy.crt"), key = path.join(dir, "proxy.key");
let gateway, proxy, echo, originalLookup, originalConnect;
const sockets = new Set();
function track(server) { server.on("connection", socket => { sockets.add(socket); socket.once("close", () => sockets.delete(socket)); }); return server; }
function listen(server) { return new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); }); }
function auth(session) { return "Basic " + Buffer.from(session.proxyUsername + ":" + session.proxyPassword).toString("base64"); }
function requestSession({ method = "POST", user = "proxy-test-user", headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: "127.0.0.1", port: gateway.address().port, path: "/__proxy-session", method,
      headers: { ...(user ? { "x-remote-user": user } : {}), ...headers } }, res => {
      let body = ""; res.on("data", chunk => body += chunk); res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: JSON.parse(body) }));
    }); req.on("error", reject); req.end();
  });
}
const mint = options => requestSession({ ...options, headers: { "x-gateway-proxy-session": "1", ...(options && options.headers) } });
function connect(target, authorization, { plaintext = false, regular = false } = {}) {
  return new Promise((resolve, reject) => {
    const transport = plaintext ? http : https;
    const req = transport.request({ hostname: "127.0.0.1", port: regular ? gateway.address().port : proxy.address().port, method: "CONNECT", path: target,
      servername: "proxy.example.test", ca: fs.readFileSync(cert), headers: authorization ? { "proxy-authorization": authorization } : {} });
    req.on("connect", (res, socket, head) => resolve({ status: res.statusCode, socket, head }));
    req.on("error", reject); req.end();
  });
}
function makeCertificate() {
  const result = spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=proxy.example.test", "-addext", "subjectAltName=DNS:proxy.example.test", "-keyout", key, "-out", cert], { stdio: "ignore" });
  assert.equal(result.status, 0, "isolated TLS certificate fixture generation failed");
}
test.before(async () => {
  Object.assign(g.cfg, { connectAdvertise: "https://proxy.example.test:443", connectTlsCert: cert, connectTlsKey: key, listen: "127.0.0.1" });
  makeCertificate();
  gateway = track(g.createServer()); await listen(gateway);
  proxy = track(g.createConnectServer({ reloadMs: 20 })); await listen(proxy);
  echo = track(net.createServer(socket => socket.pipe(socket))); await listen(echo);
  originalLookup = dns.lookup; originalConnect = net.connect;
  dns.lookup = async host => { assert.equal(g.parseConnectTarget(host + ":443"), host); return [{ address: "8.8.8.8", family: 4 }]; };
  net.connect = function(options, callback) {
    if (options && options.host === "8.8.8.8") return originalConnect.call(net, { ...options, host: "127.0.0.1", port: echo.address().port }, callback);
    return originalConnect.apply(net, arguments);
  };
});
test.after(async () => {
  dns.lookup = originalLookup; net.connect = originalConnect;
  sockets.forEach(socket => socket.destroy());
  await Promise.all([gateway, proxy, echo].map(server => new Promise(resolve => server.close(resolve))));
  fs.rmSync(dir, { recursive: true, force: true });
});
test("protected session minting requires identity, custom header and trusted origin", async () => {
  assert.equal((await mint({ user: "" })).status, 401);
  assert.equal((await mint({ user: "alice!" })).status, 401);
  assert.equal((await mint({ method: "GET" })).status, 405);
  assert.equal((await requestSession()).status, 403);
  assert.equal((await mint({ headers: { origin: "https://evil.example" } })).status, 403);
  assert.equal((await mint({ headers: { origin: "chrome-extension://abcdefghijklmnopabcdefghijklmnop" } })).status, 200);
  assert.equal((await mint({ headers: { origin: "moz-extension://11111111-2222-3333-4444-555555555555" } })).status, 200);
  assert.equal((await mint({ headers: { origin: "null" } })).status, 403);
  const result = await mint({ headers: { origin: "https://" + g.cfg.publicHost } });
  assert.equal(result.status, 200);
  assert.equal(result.headers["cache-control"], "no-store");
  assert.equal(result.headers["access-control-allow-origin"], undefined);
  assert.equal(result.body.proxyUsername, "gateway-proxy");
  assert.match(result.body.proxyPassword, /^[A-Za-z0-9_-]{43}$/);
  assert.deepEqual(result.body.proxy, { scheme: "https", host: "proxy.example.test", port: 443 });
  assert.ok(Math.abs(result.body.expiresAt - Date.now() - 900000) < 2000);
});
test("proxy credentials are independent, expire and have bounded per-user/global retention", () => {
  const first = g.mintProxySession("bounded-user");
  assert.ok(g.verifyProxyAuth(auth(first)));
  assert.equal(g.verifyProxyAuth(auth(first), first.expiresAt), null);
  const sessions = Array.from({ length: 4 }, () => g.mintProxySession("evicted-user"));
  assert.equal(g.verifyProxyAuth(auth(sessions[0])), null);
  assert.ok(g.verifyProxyAuth(auth(sessions[3])));
  assert.equal(g.verifyProxyAuth("Basic " + Buffer.from("alice:gateway-password").toString("base64")), null);
  assert.equal(g.verifyProxyAuth("Bearer " + first.proxyPassword), null);
  const old = g.cfg.proxySessionLimit; g.cfg.proxySessionLimit = 0;
  try { assert.equal(g.mintProxySession("capacity-user"), null); } finally { g.cfg.proxySessionLimit = old; }
});
test("CONNECT allowlist includes only artifact domains and nine exact dependencies", () => {
  const dependencies = ["cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com", "fonts.googleapis.com", "fonts.gstatic.com", "esm.sh", "cdn.tailwindcss.com", "code.jquery.com", "cdn.plot.ly"];
  assert.deepEqual([...g.CONNECT_DEPENDENCY_HOSTS].sort(), [...dependencies].sort());
  for (const host of dependencies) {
    assert.equal(g.parseConnectTarget(host + ":443"), host);
    assert.equal(g.parseConnectTarget("evil." + host + ":443"), null);
    assert.equal(g.parseConnectTarget(host + ".evil.example:443"), null);
    assert.equal(g.parseConnectTarget(host.replace(".", "-") + ":443"), null);
  }
  for (const target of ["claude.ai:443", "api.anthropic.com:443", "github.com:443", "127.0.0.1:443", "foo.claudeusercontent.com:8443"]) assert.equal(g.parseConnectTarget(target), null);
});
test("public-address filter denies private, link-local, mapped, documentation and mixed DNS answers", async () => {
  for (const address of ["127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.0.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1", "198.18.0.1", "192.0.2.1", "203.0.113.2", "::1", "::ffff:8.8.8.8", "fc00::1", "fe80::1", "2001:db8::1", "2001:0db8::1", "3fff:fff::1", "2002:0808:0808::1"]) assert.equal(g.isPublicAddress(address), false, address);
  for (const address of ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "2001:4860:4860::8888"]) assert.equal(g.isPublicAddress(address), true, address);
  const previous = dns.lookup;
  dns.lookup = async () => [{ address: "8.8.8.8", family: 4 }, { address: "127.0.0.1", family: 4 }];
  try {
    await assert.rejects(g.resolveConnectAddress("sandbox.claudemcpcontent.com"), /non-public/);
    dns.lookup = async () => [{ address: "2001:4860:4860::8888", family: 6 }, { address: "8.8.8.8", family: 4 }];
    assert.equal((await g.resolveConnectAddress("sandbox.claudemcpcontent.com")).family, 4);
  } finally { dns.lookup = previous; }
});
test("TLS CONNECT authenticates tokens locally, rejects Basic and tunnels bytes to a pinned public answer", async () => {
  const noAuth = await connect("sandbox.claudemcpcontent.com:443"); assert.equal(noAuth.status, 407); noAuth.socket.destroy();
  const basic = await connect("sandbox.claudemcpcontent.com:443", "Basic " + Buffer.from("alice:gateway-password").toString("base64")); assert.equal(basic.status, 407); basic.socket.destroy();
  const session = (await mint()).body;
  const denied = await connect("169.254.169.254:443", auth(session)); assert.equal(denied.status, 403); denied.socket.destroy();
  const tunnel = await connect("sandbox.claudemcpcontent.com:443", auth(session)); assert.equal(tunnel.status, 200);
  const data = new Promise((resolve, reject) => { tunnel.socket.once("data", resolve); tunnel.socket.once("error", reject); });
  tunnel.socket.write("synthetic-tunnel-bytes"); assert.equal((await data).toString(), "synthetic-tunnel-bytes"); tunnel.socket.destroy();
  const httpConnect = await connect("sandbox.claudemcpcontent.com:443", auth(session), { plaintext: true, regular: true }); assert.equal(httpConnect.status, 403); httpConnect.socket.destroy();
  await assert.rejects(connect("sandbox.claudemcpcontent.com:443", auth(session), { plaintext: true }));
});

test("protected rotation replaces only its own prior credential and preserves three profiles", { timeout: 3000 }, async () => {
  const user = "selective-rotation-user";
  const oldest = (await mint({ user })).body, previous = (await mint({ user })).body, third = (await mint({ user })).body;
  const foreign = (await mint({ user: "selective-other-user" })).body;
  const opened = [];
  const tunnelFor = async session => {
    const tunnel = await connect("sandbox.claudemcpcontent.com:443", auth(session));
    assert.equal(tunnel.status, 200); opened.push(tunnel.socket); return tunnel.socket;
  };
  try {
    const oldSocket = await tunnelFor(previous), oldestSocket = await tunnelFor(oldest), foreignSocket = await tunnelFor(foreign);
    const closed = new Promise(resolve => oldSocket.once("close", resolve));
    const rotated = await mint({ user, headers: { "x-gateway-previous-proxy-token": previous.proxyPassword } });
    assert.equal(rotated.status, 200); await closed;
    assert.equal(g.verifyProxyAuth(auth(previous)), null);
    for (const session of [oldest, third, foreign, rotated.body]) assert.ok(g.verifyProxyAuth(auth(session)));
    await tunnelFor(rotated.body);
    for (const socket of [oldestSocket, foreignSocket]) {
      const echoed = new Promise((resolve, reject) => { socket.once("data", resolve); socket.once("error", reject); });
      socket.write("still-live-after-selective-rotation");
      assert.equal((await echoed).toString(), "still-live-after-selective-rotation");
    }
    const challenged = await connect("sandbox.claudemcpcontent.com:443", auth(previous));
    assert.equal(challenged.status, 407); challenged.socket.destroy();
  } finally { opened.forEach(socket => socket.destroy()); }
});

test("failed rotation preserves prior credentials and active sockets", { timeout: 3000 }, async () => {
  const user = "failed-rotation-user", previous = (await mint({ user })).body;
  const tunnel = await connect("sandbox.claudemcpcontent.com:443", auth(previous));
  assert.equal(tunnel.status, 200);
  const previousLimit = g.cfg.proxySessionLimit, previousCert = g.cfg.connectTlsCert;
  try {
    const headers = { "x-gateway-previous-proxy-token": previous.proxyPassword };
    g.cfg.proxySessionLimit = 0;
    assert.equal((await mint({ user, headers })).status, 503);
    g.cfg.proxySessionLimit = previousLimit;
    g.cfg.connectTlsCert = path.join(dir, "not-issued-for-rotation.crt");
    assert.equal((await mint({ user, headers })).status, 503);
    g.cfg.connectTlsCert = previousCert;
    for (const malformed of ["bad-token", "A".repeat(44), "A".repeat(2000), ""]) assert.equal((await mint({ user, headers: { "x-gateway-previous-proxy-token": malformed } })).status, 400);
    assert.ok(g.verifyProxyAuth(auth(previous)));
    const echoed = new Promise((resolve, reject) => { tunnel.socket.once("data", resolve); tunnel.socket.once("error", reject); });
    tunnel.socket.write("prior-credential-survives-failed-rotation");
    assert.equal((await echoed).toString(), "prior-credential-survives-failed-rotation");
  } finally { g.cfg.proxySessionLimit = previousLimit; g.cfg.connectTlsCert = previousCert; tunnel.socket.destroy(); }
});

test("unknown and expired previous credentials allow recovery without revoking unrelated tokens", async () => {
  const foreign = (await mint({ user: "foreign-previous-owner" })).body;
  const expired = g.mintProxySession("expired-previous-owner", Date.now() - g.cfg.proxySessionTtlMs - 1);
  for (const token of ["A".repeat(43), expired.proxyPassword]) {
    const recovered = await mint({ user: "recovered-rotation-user", headers: { "x-gateway-previous-proxy-token": token } });
    assert.equal(recovered.status, 200);
    assert.ok(g.verifyProxyAuth(auth(recovered.body)));
    assert.ok(g.verifyProxyAuth(auth(foreign)));
  }
});

test("account switching revokes only the presented bearer credential and preserves other profiles", { timeout: 3000 }, async () => {
  const oldAccount = "previous-account-user", newAccount = "next-account-user";
  const previous = (await mint({ user: oldAccount })).body, oldOtherProfile = (await mint({ user: oldAccount })).body;
  const newOtherProfile = (await mint({ user: newAccount })).body;
  const tunnel = await connect("sandbox.claudemcpcontent.com:443", auth(previous));
  assert.equal(tunnel.status, 200);
  const previousLimit = g.cfg.proxySessionLimit;
  try {
    const headers = { "x-gateway-previous-proxy-token": previous.proxyPassword };
    g.cfg.proxySessionLimit = 0;
    assert.equal((await mint({ user: newAccount, headers })).status, 503);
    assert.ok(g.verifyProxyAuth(auth(previous)));
    assert.equal(tunnel.socket.destroyed, false);
    g.cfg.proxySessionLimit = previousLimit;
    const closed = new Promise(resolve => tunnel.socket.once("close", resolve));
    const switched = await mint({ user: newAccount, headers });
    assert.equal(switched.status, 200); await closed;
    assert.deepEqual(Object.keys(switched.body).sort(), ["expiresAt", "proxy", "proxyPassword", "proxyUsername"]);
    assert.equal(g.verifyProxyAuth(auth(previous)), null);
    for (const credential of [oldOtherProfile, newOtherProfile, switched.body]) assert.ok(g.verifyProxyAuth(auth(credential)));
  } finally { g.cfg.proxySessionLimit = previousLimit; tunnel.socket.destroy(); }
});

test("a foreign previous credential does not bypass the new user's three-profile quota", async () => {
  const user = "profile-quota-account", foreign = (await mint({ user: "foreign-quota-account" })).body;
  const profiles = [];
  for (let i = 0; i < g.cfg.proxySessionsPerUser; i++) profiles.push((await mint({ user })).body);
  const replacement = await mint({ user, headers: { "x-gateway-previous-proxy-token": foreign.proxyPassword } });
  assert.equal(replacement.status, 200);
  assert.equal(g.verifyProxyAuth(auth(foreign)), null);
  assert.equal(g.verifyProxyAuth(auth(profiles[0])), null, "ordinary oldest-profile eviction still enforces the quota");
  for (const credential of [...profiles.slice(1), replacement.body]) assert.ok(g.verifyProxyAuth(auth(credential)));
});

test("selective bearer replacement succeeds at global capacity without removing unrelated credentials", async () => {
  const previousLimit = g.cfg.proxySessionLimit;
  g.cfg.proxySessionLimit = 256;
  try {
    const previous = (await mint({ user: "global-capacity-old-user" })).body;
    const unrelated = (await mint({ user: "global-capacity-new-user" })).body;
    let reachedCapacity = false;
    for (let i = 0; i < 256; i++) {
      if (!g.mintProxySession("capacity-filler-" + i)) { reachedCapacity = true; break; }
    }
    assert.equal(reachedCapacity, true);
    assert.equal((await mint({ user: "capacity-blocked-user" })).status, 503);
    const replacement = await mint({ user: "global-capacity-new-user", headers: { "x-gateway-previous-proxy-token": previous.proxyPassword } });
    assert.equal(replacement.status, 200);
    assert.equal(g.verifyProxyAuth(auth(previous)), null);
    assert.ok(g.verifyProxyAuth(auth(unrelated)));
    assert.ok(g.verifyProxyAuth(auth(replacement.body)));
    assert.equal((await mint({ user: "capacity-still-blocked-user" })).status, 503);
  } finally { g.cfg.proxySessionLimit = previousLimit; }
});

test("tunnel quotas reject excess connections and token expiry closes an active tunnel", async () => {
  const oldLimit = g.cfg.connectMaxPerToken, oldTtl = g.cfg.proxySessionTtlMs;
  g.cfg.connectMaxPerToken = 1; g.cfg.proxySessionTtlMs = 180;
  try {
    const session = g.mintProxySession("short-lived-user");
    const first = await connect("sandbox.claudemcpcontent.com:443", auth(session)); assert.equal(first.status, 200);
    const second = await connect("sandbox.claudemcpcontent.com:443", auth(session)); assert.equal(second.status, 429); second.socket.destroy();
    await new Promise(resolve => first.socket.once("close", resolve));
    const expired = await connect("sandbox.claudemcpcontent.com:443", auth(session)); assert.equal(expired.status, 407); expired.socket.destroy();
  } finally { g.cfg.connectMaxPerToken = oldLimit; g.cfg.proxySessionTtlMs = oldTtl; }
});
test("per-user quotas survive token rotation and leave room for another user", async () => {
  const old = g.cfg.connectMaxPerUser; g.cfg.connectMaxPerUser = 1;
  let first, third;
  try {
    first = await connect("sandbox.claudemcpcontent.com:443", auth(g.mintProxySession("rotating-user"))); assert.equal(first.status, 200);
    const replacement = g.mintProxySession("rotating-user");
    const second = await connect("sandbox.claudemcpcontent.com:443", auth(replacement)); assert.equal(second.status, 429); second.socket.destroy();
    third = await connect("sandbox.claudemcpcontent.com:443", auth(g.mintProxySession("another-user"))); assert.equal(third.status, 200);
  } finally { if (first) first.socket.destroy(); if (third) third.socket.destroy(); g.cfg.connectMaxPerUser = old; }
});

test("evicting a proxy credential revokes its active tunnels", { timeout: 2000 }, async () => {
  const first = g.mintProxySession("revoked-user");
  const tunnel = await connect("sandbox.claudemcpcontent.com:443", auth(first));
  assert.equal(tunnel.status, 200);
  const closed = new Promise(resolve => tunnel.socket.once("close", resolve));
  for (let i = 0; i < g.cfg.proxySessionsPerUser; i++) g.mintProxySession("revoked-user");
  await closed;
  const revoked = await connect("sandbox.claudemcpcontent.com:443", auth(first));
  assert.equal(revoked.status, 407); revoked.socket.destroy();
});

test("disconnected clients cannot bypass the global quota while DNS is pending", { timeout: 3000 }, async () => {
  const previousLookup = dns.lookup, oldLimit = g.cfg.connectMaxTunnels;
  const pending = [];
  let lookupStarted;
  const started = new Promise(resolve => { lookupStarted = resolve; });
  dns.lookup = () => new Promise(resolve => { pending.push(resolve); lookupStarted(); });
  g.cfg.connectMaxTunnels = 1;
  let request;
  try {
    const session = g.mintProxySession("pending-dns-user");
    request = https.request({ hostname: "127.0.0.1", port: proxy.address().port, method: "CONNECT", path: "sandbox.claudemcpcontent.com:443",
      servername: "proxy.example.test", ca: fs.readFileSync(cert), headers: { "proxy-authorization": auth(session) } });
    request.on("error", () => {}); request.end();
    await started;
    const closed = new Promise(resolve => request.once("close", resolve)); request.destroy(); await closed;
    await new Promise(resolve => setTimeout(resolve, 20));
    const second = await Promise.race([
      connect("sandbox.claudemcpcontent.com:443", auth(g.mintProxySession("other-dns-user"))),
      new Promise((_resolve, reject) => { const timer = setTimeout(() => reject(new Error("pending DNS bypassed global quota")), 1000); timer.unref(); }),
    ]);
    assert.equal(second.status, 429); second.socket.destroy();
    assert.equal(pending.length, 1);
    dns.lookup = previousLookup;
    for (const resolve of pending) resolve([{ address: "8.8.8.8", family: 4 }]);
    await new Promise(resolve => setImmediate(resolve));
    const recovered = await connect("sandbox.claudemcpcontent.com:443", auth(g.mintProxySession("recovered-dns-user")));
    assert.equal(recovered.status, 200); recovered.socket.destroy();
  } finally {
    if (request) request.destroy();
    dns.lookup = previousLookup; g.cfg.connectMaxTunnels = oldLimit;
    for (const resolve of pending) resolve([{ address: "8.8.8.8", family: 4 }]);
  }
});
test("missing or mismatched TLS material fails closed and startup recovers once certificate appears", async () => {
  const oldCert = g.cfg.connectTlsCert, oldPort = g.cfg.connectPort;
  g.cfg.connectTlsCert = path.join(dir, "not-issued.crt"); g.cfg.connectPort = 0;
  assert.equal(g.connectReady(), false); assert.throws(() => g.createConnectServer());
  assert.equal((await mint()).status, 503);
  const retry = g.startConnectListener({ retryMs: 20 });
  try {
    assert.equal(retry.server, null);
    fs.copyFileSync(cert, g.cfg.connectTlsCert);
    await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error("TLS startup did not recover")), 2000);
      const poll = setInterval(() => { if (retry.server && retry.server.listening) { clearTimeout(timeout); clearInterval(poll); resolve(); } }, 20);
    });
    assert.ok(g.connectReady());
    const previous = g.cfg.connectAdvertise; g.cfg.connectAdvertise = "https://wrong.example.test";
    try { assert.equal(g.connectReady(), false); assert.throws(() => g.createConnectServer()); } finally { g.cfg.connectAdvertise = previous; }
  } finally { retry.close(); g.cfg.connectTlsCert = oldCert; g.cfg.connectPort = oldPort; }
});

test("a partial certificate rotation fails closed and recovers with restored valid material", async () => {
  const previousKey = fs.readFileSync(key);
  try {
    fs.writeFileSync(key, "incomplete key rotation");
    await new Promise(resolve => setTimeout(resolve, 50));
    assert.equal(g.connectReady(), false);
    assert.equal((await mint()).status, 503);
    const rejected = await connect("sandbox.claudemcpcontent.com:443", auth(g.mintProxySession("rotation-user")));
    assert.equal(rejected.status, 503); rejected.socket.destroy();
  } finally { fs.writeFileSync(key, previousKey); }
  await new Promise(resolve => setTimeout(resolve, 50));
  assert.equal(g.connectReady(), true);
  assert.equal((await mint()).status, 200);
});

test("valid renewed TLS certificate is reloaded without restarting the listener", async () => {
  const { X509Certificate } = require("node:crypto");
  const previous = new X509Certificate(fs.readFileSync(cert)).fingerprint256;
  makeCertificate();
  const renewed = new X509Certificate(fs.readFileSync(cert)).fingerprint256;
  assert.notEqual(previous, renewed);
  await new Promise(resolve => setTimeout(resolve, 50));
  await new Promise((resolve, reject) => {
    const req = https.get({ hostname: "127.0.0.1", port: proxy.address().port, servername: "proxy.example.test", ca: fs.readFileSync(cert), agent: false }, res => {
      assert.equal(res.statusCode, 405);
      assert.equal(res.socket.getPeerCertificate().fingerprint256, renewed);
      res.resume(); res.once("end", resolve);
    }); req.on("error", reject);
  });
});
