// Local dashboard: request guards, SSH command construction and parsing.
// A fake ssh binary stands in for the server; nothing leaves this machine.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");

const base = fs.mkdtempSync(path.join(os.tmpdir(), "gateway-dashboard-"));
const sshLog = path.join(base, "ssh.log");
const fakeSsh = path.join(base, "ssh");
const SNAPSHOT = [
  "@@gateway",
  JSON.stringify({ gateway: { publicHost: "gw.example.test", uptimeSec: 60, node: "v22" }, now: { websockets: 1, tunnels: 0, connectReady: true, jarKeysInMemory: 1, proxySessions: 0 },
    limits: { tunnels: 128, cacheBytes: 1 }, totals: { req: 5, bytesOut: 10 }, history: { fields: ["t", "req"], rows: [[1790000000000, 4], [1790000060000, 5]] },
    users: [{ user: "owner", session: "ok", encryption: "v2" }], bans: [], cache: { items: 0, bytes: 0 }, encryption: { jars: { v2: 1, v1: 0, plain: 0 } } }),
  "@@frontdoor",
  '2026-10-16T15:00:00.000000000Z {"event":"frontdoor_diagnostics","accepted":3,"capacity_rejected":0,"active":2,"active_peak":3}',
  "@@containers",
  JSON.stringify({ Name: "claude-browser-gateway-1", CPUPerc: "1.50%", MemUsage: "68.13MiB / 256MiB", NetIO: "52.7MB / 51.6MB", PIDs: "11" }),
  "@@host", "cpus 1", "load 0.05 0.04 0.01", "mem_total_kb 2000000", "mem_available_kb 1500000",
  "@@config", "users owner sasha", "admins owner", "public_host gw.example.test", "legacy_key yes",
  "@@end", "",
].join("\n");
fs.writeFileSync(fakeSsh, `#!/bin/sh
printf '%s\\n' "$*" >> "${sshLog}"
for last; do :; done
case "$*" in
  *"admin.sh watch "*) cat "${path.join(base, "snapshot")}"; exec sleep 30;;
  *"admin.sh status "*) cat "${path.join(base, "snapshot")}";;
  *"admin.sh add "*|*"admin.sh reset "*) printf '{"user":"%s","password":"0123456789abcdef01234567","reset":false}\\n' "$last";;
  *"admin.sh remove "*) printf '{"user":"%s","removed":true}\\n' "$last";;
  *"admin.sh unban "*) printf '{"cleared":true}\\n';;
  *) echo "unexpected" >&2; exit 3;;
esac
`, { mode: 0o755 });
fs.writeFileSync(path.join(base, "snapshot"), SNAPSHOT);
process.env.DASHBOARD_SSH = fakeSsh;
const d = require("../dashboard/dashboard.js");

test.after(() => fs.rmSync(base, { recursive: true, force: true }));

test("arguments: ssh destination and directory cannot inject options or paths", () => {
  const exit = process.exit, error = console.error;
  process.exit = code => { throw new Error("exit " + code); };
  console.error = () => {};
  try {
    for (const argv of [[], ["-oProxyCommand=x"], ["root@host;id"], ["root@host", "--dir", "/root/../etc"], ["root@host", "--dir", "rel"], ["root@host", "--port", "80"], ["a", "b"]]) {
      assert.throws(() => d.parseArgs(argv), /exit 2/, JSON.stringify(argv));
    }
  } finally { process.exit = exit; console.error = error; }
  const opts = d.parseArgs(["gateway-alias", "--dir", "/srv/claude", "--port", "9000", "--no-open"]);
  assert.deepEqual([opts.target, opts.dir, opts.port, opts.open], ["gateway-alias", "/srv/claude", 9000, false]);
  const args = d.sshArgs(opts, ["add", "bob"]);
  assert.deepEqual(args.slice(-5), ["--", "gateway-alias", "/srv/claude/admin.sh", "add", "bob"]);
  assert.equal(args[args.indexOf("--") + 1], "gateway-alias");
  assert.ok(args.includes("BatchMode=yes"));
});

test("snapshot parsing reads every section of admin.sh output", () => {
  const snap = d.parseSnapshot(SNAPSHOT);
  assert.equal(snap.gateway.users[0].user, "owner");
  assert.equal(snap.frontdoor.active, 2); assert.equal(snap.frontdoor.at, "2026-10-16T15:00:00.000000000Z");
  assert.deepEqual(snap.containers[0], { name: "gateway", cpu: 1.5, memUsed: Math.round(68.13 * 1024 ** 2), memLimit: 256 * 1024 ** 2, netIn: 52700000, netOut: 51600000, pids: 11 });
  assert.equal(snap.host.load, "0.05 0.04 0.01");
  assert.equal(snap.config.users, "owner sasha");
  const state = d.createState();
  d.absorb(state, snap); d.absorb(state, snap);
  assert.equal(state.history.size, 2);
  assert.equal(state.frontdoor.length, 1, "the same front door interval is stored once");
});

function call(port, method, url, { host = "127.0.0.1:" + port, token, origin, body, type } = {}) {
  return new Promise((resolve, reject) => {
    const headers = { host };
    if (token) headers["x-dashboard-token"] = token;
    if (origin) headers.origin = origin;
    const payload = body === undefined ? undefined : JSON.stringify(body);
    if (payload !== undefined) { headers["content-type"] = type || "application/json"; headers["content-length"] = Buffer.byteLength(payload); }
    const req = http.request({ host: "127.0.0.1", port, method, path: url, headers }, res => {
      let data = "";
      res.on("data", c => { data += c; });
      res.on("end", () => { let json = null; try { json = JSON.parse(data); } catch (_) { /* html */ } resolve({ status: res.statusCode, headers: res.headers, json, text: data }); });
    });
    req.on("error", reject);
    req.end(payload);
  });
}

test("the local server answers only its own host, with the token, same-origin JSON and valid names", async t => {
  const opts = d.parseArgs(["root@203.0.113.10", "--port", "8790", "--no-open"]);
  const state = d.createState();
  const token = "test-token-0123456789abcdef";
  const server = d.createDashboardServer(opts, state, token);
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  opts.port = server.address().port;
  const watcher = d.startWatcher(opts, state);
  t.after(() => { watcher.stop(); server.close(); });
  const port = opts.port, own = "http://127.0.0.1:" + port;
  const logs = [];
  const log = console.log;
  console.log = (...a) => { logs.push(a.join(" ")); };
  try {
    const page = await call(port, "GET", "/");
    assert.equal(page.status, 200);
    assert.match(page.headers["content-security-policy"], /default-src 'none'.*frame-ancestors 'none'/);
    assert.equal(page.headers["x-frame-options"], "DENY");
    assert.equal((await call(port, "GET", "/", { host: "evil.example:" + port })).status, 421, "DNS rebinding");
    assert.equal((await call(port, "GET", "/api/state")).status, 401);
    assert.equal((await call(port, "GET", "/api/state", { token: "wrong-token-0123456789abcd" })).status, 401);
    for (let i = 0; i < 50 && !state.connected; i++) await new Promise(r => setTimeout(r, 50));
    const st = await call(port, "GET", "/api/state", { token });
    assert.equal(st.status, 200);
    assert.equal(st.json.connected, true);
    assert.equal(st.json.gateway.users[0].user, "owner");
    assert.deepEqual(st.json.history.rows.map(r => r[1]), [4, 5]);

    assert.equal((await call(port, "POST", "/api/users", { token, origin: "https://evil.example", body: { name: "bob" } })).status, 403);
    assert.equal((await call(port, "POST", "/api/users", { token, origin: own, body: { name: "bob" }, type: "text/plain" })).status, 415);
    fs.writeFileSync(sshLog, "");
    for (const name of ["bo b", "../x", "-oProxyCommand=x", "a;id", "", "."]) {
      assert.equal((await call(port, "POST", "/api/users", { token, origin: own, body: { name } })).status, 400, name);
    }
    assert.equal(fs.readFileSync(sshLog, "utf8"), "", "invalid names never reach ssh");
    const added = await call(port, "POST", "/api/users", { token, origin: own, body: { name: "bob" } });
    assert.equal(added.status, 200);
    assert.deepEqual([added.json.user, added.json.password], ["bob", "0123456789abcdef01234567"]);
    assert.match(fs.readFileSync(sshLog, "utf8"), /-- root@203\.0\.113\.10 \/root\/claude-browser\/admin\.sh add bob\n/);
    assert.ok(!logs.join("\n").includes("0123456789abcdef01234567"), "passwords are never logged");
    assert.ok(logs.some(l => l.includes("add user bob: ok")));

    assert.equal((await call(port, "DELETE", "/api/users/bob", { token, origin: own, body: { confirm: "alice" } })).status, 400);
    const removed = await call(port, "DELETE", "/api/users/bob", { token, origin: own, body: { confirm: "bob" } });
    assert.equal(removed.status, 200, removed.text);
    assert.equal(removed.json.removed, true);
    assert.equal((await call(port, "POST", "/api/users/bob/reset", { token, origin: own, body: {} })).json.user, "bob");
    assert.equal((await call(port, "POST", "/api/bans/1.2.3.4;id/clear", { token, origin: own, body: {} })).status, 400);
    assert.equal((await call(port, "POST", "/api/bans/198.51.100.7/clear", { token, origin: own, body: {} })).json.cleared, true);
  } finally { console.log = log; }
});
