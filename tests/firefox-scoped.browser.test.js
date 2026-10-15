"use strict";

// Native Firefox gate for the packaged add-on in an everyday-profile setting:
// other sites (including shared CDNs and cleartext) keep working, Claude is
// redirected to the gateway, and Claude-owned CDN/artifact requests use the
// authenticated CONNECT relay or fail closed. The gateway runs on a high port;
// the no-DIRECT-fallback check additionally needs loopback :443 (CI enables it).
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const https = require("node:https");
const net = require("node:net");
const H = require("./firefox-harness");

const ROOT = path.resolve(__dirname, "..");
const PACKAGE = path.join(ROOT, "extension/dist/firefox");
const GATEWAY = "gateway.audit.test", RELAY = "proxy.audit.test", SITE = "news.audit.test", UNKNOWN = "unapproved.audit.test";
const ARTIFACT = "review.claudeusercontent.com", CDN = "cdn.jsdelivr.net";
const NAMES = [GATEWAY, RELAY, SITE, UNKNOWN, ARTIFACT, CDN, "claude.ai"];
const TOKEN = "T".repeat(43);

test("Firefox add-on routes only Claude traffic and leaves other browsing untouched", { timeout: 120000 }, async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-firefox-scoped-"));
  const keys = H.createFixtureCA(dir, NAMES);
  const hits = [], connects = [], sockets = new Set(), tunnels = new Set();
  let relayMode = "tunnel";
  const track = server => server.on("connection", socket => { sockets.add(socket); socket.on("close", () => sockets.delete(socket)); });
  const handler = label => (req, res) => {
    const host = String(req.headers.host || "").split(":")[0];
    hits.push({ label, host, path: req.url, method: req.method });
    if (host === GATEWAY && req.url === "/__health") return json(res, { ok: true, users: 1, session: "ok" });
    if (host === GATEWAY && req.url === "/__proxy-session" && req.method === "POST") {
      return json(res, { proxyUsername: "gateway-proxy", proxyPassword: TOKEN, expiresAt: Date.now() + 14 * 60000,
        proxy: { scheme: "https", host: RELAY, port: relay.address().port } });
    }
    res.writeHead(200, { "content-type": "text/html; charset=utf-8", "access-control-allow-origin": "*", "cache-control": "no-store" });
    res.end(req.method === "HEAD" ? undefined : "<!doctype html><title>" + host + "</title><main id=marker>" + host + "</main>");
  };
  const json = (res, body) => { res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" }); res.end(JSON.stringify(body)); };
  const direct = https.createServer({ key: keys.key, cert: keys.cert }, handler("direct")); track(direct);
  const tunnelEnd = https.createServer({ key: keys.key, cert: keys.cert }, handler("tunnel")); track(tunnelEnd);
  const plain = http.createServer(handler("cleartext")); track(plain);
  const relay = https.createServer({ key: keys.key, cert: keys.cert }); track(relay);
  relay.on("connection", socket => { tunnels.add(socket); socket.on("close", () => tunnels.delete(socket)); });
  relay.on("connect", (req, socket) => {
    const authorized = req.headers["proxy-authorization"] === "Basic " + Buffer.from("gateway-proxy:" + TOKEN).toString("base64");
    connects.push({ target: req.url, authorized });
    if (relayMode === "drop") return socket.destroy();
    if (!authorized) return socket.end("HTTP/1.1 407 Proxy Authentication Required\r\nproxy-authenticate: Basic realm=\"gateway-proxy\"\r\nconnection: close\r\ncontent-length: 0\r\n\r\n");
    const upstream = net.connect(tunnelEnd.address().port, "127.0.0.1", () => {
      socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      upstream.pipe(socket); socket.pipe(upstream);
    });
    upstream.on("error", () => socket.destroy()); socket.on("error", () => upstream.destroy());
  });
  // Protected requests are portless, so only a :443 listener can observe a DIRECT fallback.
  const direct443 = https.createServer({ key: keys.key, cert: keys.cert }, handler("direct")); track(direct443);
  const has443 = await new Promise(resolve => { direct443.once("error", () => resolve(false)); direct443.listen(443, "127.0.0.1", () => resolve(true)); });
  if (!has443) t.diagnostic("loopback :443 unavailable; DIRECT-fallback observation skipped");
  for (const server of [direct, tunnelEnd, plain, relay]) await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const P = direct.address().port, GW = `${GATEWAY}:${P}`;

  let harness;
  t.after(async () => {
    // Servers must close even if stopping the browser fails, or Node never exits.
    try { if (harness) await H.stopFirefoxHarness(harness); }
    finally {
      for (const socket of sockets) socket.destroy();
      await Promise.all([direct, tunnelEnd, plain, relay, ...(has443 ? [direct443] : [])].map(server => new Promise(resolve => server.close(resolve))));
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
  harness = await H.launchFirefoxHarness({ sourceDir: PACKAGE });
  await H.addFixtureCA(harness, keys.ca);
  await H.setFirefoxLocalDomains(harness, NAMES);
  const addonId = JSON.parse(fs.readFileSync(path.join(PACKAGE, "manifest.json"), "utf8")).browser_specific_settings.gecko.id;
  // Temporary installs are always allowed in private windows, so this gate checks
  // the cause instead: the add-on never takes over the browser-wide proxy.
  const root = await H.executeChromeScript(harness, `return WebExtensionPolicy.getByID(${JSON.stringify(addonId)}).extension.getURL("/");`);

  const navigate = url => harness.client.command("WebDriver:Navigate", { url });
  const script = async (source, args = []) => (await harness.client.command("WebDriver:ExecuteAsyncScript", {
    script: "const done = arguments[arguments.length - 1]; Promise.resolve().then(async () => { " + source + " }).then(done, error => done({ error: String(error) }));", args })).value;
  const pageFetch = url => script("const ctrl = new AbortController(); const timer = setTimeout(() => ctrl.abort(), 6000);" +
    "try { const r = await fetch(arguments[0], { cache: 'no-store', signal: ctrl.signal }); await r.text(); return { ok: true, status: r.status }; }" +
    "catch (e) { return { ok: false, error: e.name }; } finally { clearTimeout(timer); }", [url]);
  const since = (start, predicate) => hits.slice(start).filter(predicate);
  const extension = async source => { await navigate(root + "options.html"); return script(source); };

  // 1. Installed but not configured: everyday browsing keeps working.
  await navigate(`https://${SITE}:${P}/`);
  let start = hits.length;
  assert.equal((await pageFetch(`https://${CDN}:${P}/npm/site.js`)).status, 200, "a regular site reaches a shared CDN");
  assert.equal(since(start, h => h.host === CDN && h.label === "direct").length, 1);

  // 2. Configure the gateway exactly as Options does.
  await H.executeChromeScript(harness, `
    const { ExtensionPermissions } = ChromeUtils.importESModule("resource://gre/modules/ExtensionPermissions.sys.mjs");
    const policy = WebExtensionPolicy.getByID(${JSON.stringify(addonId)});
    await ExtensionPermissions.add(${JSON.stringify(addonId)}, { permissions: [], origins: ["https://${GATEWAY}/*"] }, policy.extension);
    return true;`);
  await extension(`await browser.storage.local.set({ gatewayHost: ${JSON.stringify(GW)}, authUser: "owner", authPass: "pass" }); return true;`);
  let configured;
  for (let attempt = 0; attempt < 40; attempt++) {
    configured = await script(`
      const status = await browser.runtime.sendMessage({ type: "status" });
      if (!status.proxyReady && arguments[0] % 8 === 7) await browser.runtime.sendMessage({ type: "health" });
      const proxy = await browser.proxy.settings.get({});
      return { status, proxyControl: proxy.levelOfControl };`, [attempt]);
    if (configured?.status?.proxyReady) break;
    await new Promise(resolve => setTimeout(resolve, 250));
  }
  assert.equal(configured.status.proxyReady, true, JSON.stringify(configured.status));
  assert.notEqual(configured.proxyControl, "controlled_by_this_extension", "no browser-wide proxy");
  assert(connects.some(c => c.target === `${CDN}:443` && c.authorized), "the warmup HEAD used the authenticated relay");

  // 3. Other sites are untouched: shared CDN goes direct, unknown hosts and cleartext work.
  await navigate(`https://${SITE}:${P}/`);
  start = hits.length; let relayed = connects.length;
  assert.equal((await pageFetch(`https://${CDN}:${P}/npm/site.js`)).status, 200);
  assert.equal((await pageFetch(`https://${UNKNOWN}:${P}/any`)).status, 200);
  assert.equal(since(start, h => h.label === "direct" && (h.host === CDN || h.host === UNKNOWN)).length, 2);
  assert.equal(connects.length, relayed, "other sites never use the gateway relay");
  await navigate(`http://${SITE}:${plain.address().port}/plain`);
  assert.equal((await script("return document.querySelector('#marker')?.textContent || ''")), SITE, "cleartext sites still load");

  // 4. Claude is redirected to the gateway; its CDN and artifact traffic is relayed.
  await navigate("https://claude.ai/");
  assert.equal(await script("return location.host"), GW);
  start = hits.length; relayed = connects.length;
  assert.equal((await pageFetch(`https://${CDN}/npm/claude.js`)).status, 200);
  assert.equal((await pageFetch(`https://${ARTIFACT}/frame`)).status, 200);
  assert.deepEqual(since(start, h => h.host === CDN || h.host === ARTIFACT).map(h => h.label), ["tunnel", "tunnel"]);
  assert(connects.slice(relayed).every(c => c.authorized));
  start = hits.length;
  assert.equal((await pageFetch(`https://${UNKNOWN}:${P}/exfil`)).ok, false, "unknown destinations from Claude are blocked");
  assert.equal((await pageFetch(`https://${CDN}:${P}/exfil`)).ok, false, "the same CDN URL that works for other sites is closed for Claude");
  assert.equal((await pageFetch(`http://${SITE}:${plain.address().port}/exfil`)).ok, false, "cleartext from Claude is blocked");
  assert.equal(since(start, h => h.path === "/exfil").length, 0);

  // 5. A failing relay never falls back to a direct connection. Open tunnels
  // are closed first, otherwise Firefox correctly reuses them.
  relayMode = "drop"; start = hits.length; relayed = connects.length;
  for (const socket of tunnels) socket.destroy();
  assert.equal((await pageFetch(`https://${CDN}/npm/relay-down.js`)).ok, false);
  assert(connects.length > relayed, "the request reached the relay");
  assert.equal(since(start, h => h.path === "/npm/relay-down.js").length, 0, "no DIRECT fallback");
  relayMode = "tunnel";

  // 6. Clearing the gateway releases everything.
  await extension(`await browser.storage.local.set({ gatewayHost: "" }); await new Promise(resolve => setTimeout(resolve, 500)); return true;`);
  await navigate(`https://${SITE}:${P}/`);
  assert.equal((await pageFetch(`https://${CDN}:${P}/npm/after.js`)).status, 200);
  console.log("FIREFOX_SCOPED_NATIVE", JSON.stringify({ version: harness.capabilities.browserVersion, connects: connects.length, hits: hits.length }));
});
