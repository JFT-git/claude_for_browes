"use strict";

// Focused native regression: only synthetic TLS fixtures, a temporary extension
// copy and a fresh browser profile. No personal browser or external account.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const cp = require("node:child_process");
const https = require("node:https");
const tls = require("node:tls");
const net = require("node:net");
const { chromium } = require("playwright");
const ROOT = path.resolve(__dirname, "..");
const FILE = "<!doctype html><title>Synthetic local HTML download</title>\n";
const TOKEN = "d".repeat(43);
const BASIC = "Basic " + Buffer.from("fixture-user:fixture-password").toString("base64");
const PROXY_BASIC = "Basic " + Buffer.from("gateway-proxy:" + TOKEN).toString("base64");
const HOSTS = ["gateway.local-download.test", "proxy.local-download.test", "frame.claudemcpcontent.com", "cdn.jsdelivr.net", "evil.local-download.test"];
function listen(server) { return new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", () => resolve(server.address().port)); }); }
function track(server) {
  const sockets = new Set();
  server.on("connection", socket => { sockets.add(socket); socket.on("close", () => sockets.delete(socket)); });
  return () => { for (const socket of sockets) socket.destroy(); return new Promise(resolve => server.close(resolve)); };
}
function pageHtml(artifact = false) {
  return `<!doctype html><title>Synthetic ${artifact ? "artifact" : "gateway"} local download</title>
    <button id="blob">Download blob</button><button id="data">Download data</button><main id="frames"></main>
    <script nonce="local-download-fixture">
    for(const kind of ['blob','data'])document.getElementById(kind).onclick=()=>{
      const a=document.createElement('a'); const body=${JSON.stringify(FILE)};
      const url=kind==='blob'?URL.createObjectURL(new Blob([body],{type:'text/html'})):'data:text/html;charset=utf-8,'+encodeURIComponent(body);
      a.href=url;a.download='synthetic-'+kind+'.html';document.body.appendChild(a);a.click();a.remove();
      if(kind==='blob')setTimeout(()=>URL.revokeObjectURL(url),1000);
    };</script>`;
}
function makeProxy(keys, upstreamPort, evidence) {
  const server = tls.createServer(keys, socket => {
    let buffer = Buffer.alloc(0);
    const receive = chunk => {
      buffer = Buffer.concat([buffer, chunk]);
      const end = buffer.indexOf("\r\n\r\n");
      if (end < 0) return;
      const headers = buffer.subarray(0, end + 4).toString("latin1");
      const rest = buffer.subarray(end + 4);
      const target = /^CONNECT ([^ ]+) HTTP\/1\.[01]/.exec(headers)?.[1];
      const auth = /^proxy-authorization:\s*(.+)$/im.exec(headers)?.[1]?.trim();
      if (!target || !["frame.claudemcpcontent.com:443", "cdn.jsdelivr.net:443"].includes(target)) { socket.destroy(); return; }
      if (auth !== PROXY_BASIC) {
        socket.end('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="gateway-proxy"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
        return;
      }
      evidence.push({ kind: "tunnel", target });
      socket.removeListener("data", receive);
      const upstream = net.connect(upstreamPort, "127.0.0.1", () => {
        socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        if (rest.length) upstream.write(rest);
        socket.pipe(upstream); upstream.pipe(socket);
      });
      upstream.on("error", () => socket.destroy());
      socket.on("close", () => upstream.destroy());
    };
    socket.on("data", receive); socket.on("error", () => {});
  });
  return server;
}

test("protected gateway and artifact realms permit native blob/data HTML downloads", { timeout: 90000 }, async t => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "cg-local-download-"));
  const extension = path.join(temp, "extension");
  fs.mkdirSync(extension);
  for (const entry of fs.readdirSync(path.join(ROOT, "extension"), { withFileTypes: true })) {
    if (entry.isFile() && /\.(?:js|html|png|json)$/.test(entry.name)) fs.copyFileSync(path.join(ROOT, "extension", entry.name), path.join(extension, entry.name));
  }
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, "extension/manifest.chrome.json"), "utf8"));
  manifest.host_permissions.push("https://gateway.local-download.test/*");
  fs.writeFileSync(path.join(extension, "manifest.json"), JSON.stringify(manifest));
  const keyPath = path.join(temp, "key.pem"), certPath = path.join(temp, "cert.pem");
  cp.execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", keyPath, "-out", certPath, "-days", "1", "-subj", "/CN=gateway.local-download.test", "-addext", "subjectAltName=" + HOSTS.map(host => "DNS:" + host).join(",")], { stdio: "ignore" });
  const keys = { key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) };
  const evidence = [];
  const servers = [];
  let browser;
  try {
    const collector = https.createServer(keys, (req, res) => {
      evidence.push({ kind: "direct", host: req.headers.host?.split(":")[0] });
      res.writeHead(200); res.end("direct control");
    });
    servers.push(track(collector)); const collectorPort = await listen(collector);
    const upstream = https.createServer(keys, (req, res) => {
      const host = req.headers.host?.split(":")[0];
      evidence.push({ kind: "upstream", host, method: req.method });
      if (host === "cdn.jsdelivr.net") { res.writeHead(200, { "content-type": "application/javascript" }); res.end(req.method === "HEAD" ? undefined : "/* fixture */"); return; }
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "content-security-policy": "default-src 'self'; script-src 'nonce-local-download-fixture'; frame-ancestors https://claude.ai https://*.claude.ai; connect-src 'none'; object-src 'none'" });
      res.end(pageHtml(true));
    });
    servers.push(track(upstream)); const upstreamPort = await listen(upstream);
    const proxy = makeProxy(keys, upstreamPort, evidence);
    servers.push(track(proxy)); const proxyPort = await listen(proxy);
    const gateway = https.createServer(keys, (req, res) => {
      if (req.url === "/__health" || req.url === "/__proxy-session") {
        if (req.headers.authorization !== BASIC) { res.writeHead(401); res.end(); return; }
        res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
        res.end(JSON.stringify(req.url === "/__health" ? { session: "ok", users: 1 } : { proxyUsername: "gateway-proxy", proxyPassword: TOKEN, expiresAt: Date.now() + 300000, proxy: { scheme: "https", host: "proxy.local-download.test", port: proxyPort } }));
        return;
      }
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" }); res.end(pageHtml());
    });
    servers.push(track(gateway)); const gatewayPort = await listen(gateway);
    const resolver = [`MAP gateway.local-download.test 127.0.0.1:${gatewayPort}`, `MAP proxy.local-download.test 127.0.0.1:${proxyPort}`, ...["frame.claudemcpcontent.com", "cdn.jsdelivr.net", "evil.local-download.test"].map(host => `MAP ${host} 127.0.0.1:${collectorPort}`), "MAP * ~NOTFOUND"].join(",");
    browser = await chromium.launchPersistentContext(path.join(temp, "profile"), {
      channel: process.env.CHROME ? undefined : "chromium", executablePath: process.env.CHROME || undefined,
      headless: true, ignoreHTTPSErrors: true, acceptDownloads: true,
      args: ["--disable-extensions-except=" + extension, "--load-extension=" + extension, "--disable-background-networking", "--disable-sync", "--ignore-certificate-errors", "--site-per-process", "--host-resolver-rules=" + resolver],
    });
    const worker = browser.serviceWorkers()[0] || await browser.waitForEvent("serviceworker", { timeout: 15000 });
    const options = await browser.newPage();
    await options.goto(`chrome-extension://${new URL(worker.url()).host}/options.html`);
    await options.locator("#host").fill("gateway.local-download.test");
    await options.locator("#user").fill("fixture-user");
    await options.locator("#pass").fill("fixture-password");
    await options.locator("#save").click();
    await options.waitForFunction(() => document.getElementById("status").textContent.includes("✔"), null, { timeout: 20000 });
    assert.equal((await worker.evaluate(() => status())).proxyReady, true);
    const page = await browser.newPage();
    await page.goto("https://gateway.local-download.test/download-fixture");
    await worker.evaluate(async () => { for (let n = 0; n < 80; n++) { if (artifactDebugger.status().attachedTabs) return; await new Promise(resolve => setTimeout(resolve, 100)); } throw new Error("gateway debugger not ready"); });
    await page.evaluate(() => { const frame = document.createElement("iframe"); frame.id = "artifact"; frame.src = "https://frame.claudemcpcontent.com/local-download-fixture"; document.getElementById("frames").append(frame); });
    const artifact = page.frameLocator("#artifact");
    await artifact.locator("#blob").waitFor({ timeout: 15000 });
    for (const [realm, locator] of [["gateway", page], ["artifact", artifact]]) {
      for (const kind of ["blob", "data"]) {
        await t.test(`${realm} ${kind} HTML download keeps exact file bytes`, async () => {
          const downloadEvent = page.waitForEvent("download", { timeout: 10000 });
          await locator.locator("#" + kind).click();
          const download = await downloadEvent;
          assert.equal(download.suggestedFilename(), "synthetic-" + kind + ".html");
          assert.equal(await download.failure(), null);
          assert.equal(download.url().startsWith(kind + ":"), true);
          const saved = path.join(temp, `${realm}-${kind}.html`);
          await download.saveAs(saved);
          assert.equal(fs.readFileSync(saved, "utf8"), FILE);
          assert.equal((await worker.evaluate(() => status())).proxyReady, true);
        });
      }
    }
    assert.ok(evidence.some(entry => entry.kind === "tunnel" && entry.target === "frame.claudemcpcontent.com:443"));
    assert.equal(evidence.some(entry => entry.kind === "direct"), false, "local download tests must not create direct external requests");
    await page.evaluate(() => fetch("https://evil.local-download.test/egress-control", { mode: "no-cors" }).catch(() => {}));
    assert.equal(evidence.some(entry => entry.kind === "direct"), false, "the existing unknown-destination block must remain active");
  } finally {
    await browser?.close();
    for (const stop of servers.reverse()) await stop();
    fs.rmSync(temp, { recursive: true, force: true });
  }
});
