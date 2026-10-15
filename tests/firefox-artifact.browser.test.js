"use strict";

// Native adapter coverage, separate from the complete connector/proxy tests.
// The unchanged artifact modules run in a temporary Firefox add-on. A local
// CONNECT fixture makes synthetic HTTPS authorities available on port 443;
// this router does not stand in for the product's authenticated proxy policy.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const https = require("node:https");
const net = require("node:net");
const crypto = require("node:crypto");
const zlib = require("node:zlib");
const {
  launchFirefoxHarness, stopFirefoxHarness, createFixtureCA,
  addFixtureCA, executeChromeScript,
} = require("./firefox-harness.js");

const ROOT = path.resolve(__dirname, "..");
const GATEWAY = "https://gateway.audit.test";
const ARTIFACT = "https://frame.claudemcpcontent.com";
const FILE_HOST = "https://file.claudemcpcontent.com";
const HOSTS = ["gateway.audit.test", "foreign.audit.test", "frame.claudemcpcontent.com",
  "file.claudemcpcontent.com", "child.claudemcpcontent.com", "wrapper.claudeusercontent.com"];
const MODULES = ["artifact-csp.js", "artifact-cors.js", "artifact-firefox.js"];
const EXPORT = Buffer.concat([
  Buffer.from("<!doctype html><title>Native Firefox export</title>\n"),
  Buffer.alloc(9 * 1024 * 1024, 120),
]);
const hash = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
const listen = server => new Promise((resolve, reject) => {
  server.once("error", reject);
  server.listen(0, "127.0.0.1", () => resolve(server.address().port));
});
async function until(predicate, message) {
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  assert.fail(message);
}

function writeAddon(directory) {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, "extension/manifest.firefox.json"), "utf8"));
  assert.equal(manifest.manifest_version, 2,
    "Firefox MV3 cannot replace CSP or ACAO: the native adapter requires the Firefox MV2 package");
  const hashes = {};
  for (const name of MODULES) {
    const bytes = fs.readFileSync(path.join(ROOT, "extension", name));
    fs.writeFileSync(path.join(directory, name), bytes);
    hashes[name] = hash(bytes);
  }
  fs.writeFileSync(path.join(directory, "manifest.json"), JSON.stringify({
    manifest_version: manifest.manifest_version,
    name: "Isolated artifact adapter regression",
    version: "1.0",
    permissions: ["webRequest", "webRequestBlocking", "webNavigation",
      "https://*.audit.test/*", "https://*.claudemcpcontent.com/*", "https://*.claudeusercontent.com/*"],
    background: { scripts: [...MODULES, "fixture-background.js"] },
    browser_specific_settings: { gecko: { id: "artifact-native-regression@example.test" } },
  }));
  // Record the real adapter's returned BlockingResponse and the final headers
  // processed by Firefox. Return each awaited result without modifying it.
  fs.writeFileSync(path.join(directory, "fixture-background.js"), `
    const observations = [];
    const wrapped = { runtime: browser.runtime, webNavigation: browser.webNavigation, tabs: browser.tabs, webRequest: {} };
    for (const name of ["onBeforeRequest", "onBeforeSendHeaders", "onHeadersReceived", "onBeforeRedirect", "onCompleted", "onErrorOccurred"]) {
      const listeners = new Map();
      wrapped.webRequest[name] = {
        addListener(fn, ...args) {
          const listener = async details => {
            const result = await fn(details);
            if (/\\.claude(?:mcpcontent|usercontent)\\.com\\//.test(details.url)) {
              observations.push({ name, id: details.requestId, type: details.type, url: details.url,
                documentUrl: details.documentUrl, originUrl: details.originUrl,
                frameId: details.frameId, parentFrameId: details.parentFrameId,
                frameAncestors: details.frameAncestors, statusCode: details.statusCode,
                originalHeaders: details.responseHeaders, error: details.error, result });
            }
            return result;
          };
          listeners.set(fn, listener);
          browser.webRequest[name].addListener(listener, ...args);
        },
        removeListener(fn) { const listener = listeners.get(fn); if (listener) browser.webRequest[name].removeListener(listener); listeners.delete(fn); }
      };
    }
    browser.webRequest.onResponseStarted.addListener(details => observations.push({
      name: "finalHeaders", url: details.url, responseHeaders: details.responseHeaders
    }), { urls: ["https://*.claudemcpcontent.com/*", "https://*.claudeusercontent.com/*"] }, ["responseHeaders"]);
    const manager = GatewayArtifactFirefox.create({ browser: wrapped, isReady: () => true,
      onUnsafeDetach: () => observations.push({ fault: true }) });
    manager.configure("gateway.audit.test");
    setInterval(() => fetch("${GATEWAY}/fixture-report", { method: "POST",
      body: JSON.stringify({ observations, status: manager.status() }) }).catch(() => {}), 200);
  `);
  return hashes;
}

function fixtureServers(keys, state) {
  const server = https.createServer({ key: keys.key, cert: keys.cert }, (request, response) => {
    const host = request.headers.host.split(":")[0];
    const pathname = new URL(request.url, GATEWAY).pathname;
    if (pathname === "/fixture-report") {
      let data = "";
      request.on("data", chunk => { data += chunk; });
      request.on("end", () => { state.report = JSON.parse(data); response.end("ok"); });
      return;
    }
    state.hits.push({ host, pathname, origin: request.headers.origin, method: request.method });
    response.setHeader("Cache-Control", "no-store");
    if (pathname.startsWith("/file/")) {
      const kind = pathname.split("/")[2];
      if (kind === "wildcard") response.setHeader("Access-Control-Allow-Origin", "*");
      else if (kind === "duplicate") response.setHeader("Access-Control-Allow-Origin", ["https://claude.ai", "https://claude.ai"]);
      else if (kind === "foreign") response.setHeader("Access-Control-Allow-Origin", "https://foreign.audit.test");
      else if (kind === "null") response.setHeader("Access-Control-Allow-Origin", "null");
      else if (kind !== "absent" && request.headers.origin === "https://claude.ai") response.setHeader("Access-Control-Allow-Origin", "https://claude.ai");
      if (kind === "credentials") response.setHeader("Access-Control-Allow-Credentials", "true");
      if (kind === "redirect") {
        response.writeHead(302, { Location: FILE_HOST + "/file/redirect-final" }); response.end(); return;
      }
      response.setHeader("Vary", "Origin");
      response.setHeader("Content-Type", "text/html");
      response.setHeader("Content-Security-Policy", ["default-src 'none'; script-src 'nonce-original'", "connect-src 'none'"]);
      response.setHeader("Content-Encoding", "gzip");
      response.end(request.method === "HEAD" ? undefined : zlib.gzipSync(EXPORT));
      return;
    }
    if (pathname === "/redirect") {
      response.writeHead(302, { Location: ARTIFACT + "/frame-redirected" }); response.end(); return;
    }
    response.setHeader("Content-Type", "text/html");
    if (pathname.startsWith("/frame-")) {
      const nonce = "fresh" + (++state.sequence);
      response.setHeader("Content-Security-Policy", [
        `default-src 'none'; script-src 'nonce-${nonce}'; frame-ancestors https://claude.ai https://wrapper.claudeusercontent.com; connect-src 'none'; object-src 'none'`,
        pathname === "/frame-deny" ? "script-src 'none'" : "img-src data:",
      ]);
      response.end(`<!doctype html><body>artifact-body<script nonce="${nonce}">window.executed=true;window.nonceValue="${nonce}";</script>`);
      return;
    }
    if (pathname === "/wrapper") {
      response.setHeader("Content-Security-Policy", "default-src 'none'; frame-src https://child.claudemcpcontent.com; frame-ancestors https://claude.ai");
      response.end('<!doctype html><iframe src="https://child.claudemcpcontent.com/frame-nested"></iframe>'); return;
    }
    if (pathname === "/sandbox") {
      response.end(`<!doctype html><iframe src="${ARTIFACT}/frame-opaque"></iframe>`); return;
    }
    response.end(`<!doctype html><title>Gateway fixture</title><body>gateway-fixture<button id="download">Download HTML export</button>
      <script>document.getElementById('download').onclick=async()=>{const response=await fetch('${FILE_HOST}/file/official');
      const bytes=await response.arrayBuffer();const anchor=document.createElement('a');anchor.href=URL.createObjectURL(new Blob([bytes],{type:'text/html'}));
      anchor.download='synthetic-firefox-export.html';document.body.append(anchor);anchor.click();anchor.remove();};</script>`);
  });
  const proxy = http.createServer();
  const sockets = new Set();
  for (const listener of [server, proxy]) listener.on("connection", socket => {
    sockets.add(socket); socket.on("close", () => sockets.delete(socket));
  });
  const allowed = new Set(HOSTS.map(host => host + ":443"));
  proxy.on("connect", (request, client, head) => {
    if (!allowed.has(request.url)) { client.destroy(); return; }
    state.tunnels.push(request.url);
    const upstream = net.connect(server.address().port, "127.0.0.1", () => {
      client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head.length) upstream.write(head);
      client.pipe(upstream); upstream.pipe(client);
    });
    upstream.on("error", () => client.destroy());
    client.on("close", () => upstream.destroy());
  });
  return { server, proxy, async close() {
    for (const socket of sockets) socket.destroy();
    await Promise.all([server, proxy].map(listener => listener.listening ? new Promise(resolve => listener.close(resolve)) : undefined));
  } };
}

test("Firefox artifact adapter preserves native CSP, scoped CORS and HTML export bytes", { timeout: 90000 }, async t => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "cg-firefox-artifact-"));
  const extension = path.join(temporary, "extension"), downloads = path.join(temporary, "downloads");
  fs.mkdirSync(extension); fs.mkdirSync(downloads);
  const hashes = writeAddon(extension);
  const keys = createFixtureCA(temporary, HOSTS);
  const state = { sequence: 0, hits: [], tunnels: [], report: null };
  const fixtures = fixtureServers(keys, state);
  let harness;
  try {
    await listen(fixtures.server); const proxyPort = await listen(fixtures.proxy);
    harness = await launchFirefoxHarness({ sourceDir: extension });
    assert.equal(harness.capabilities.acceptInsecureCerts, false);
    await addFixtureCA(harness, keys.ca);
    await executeChromeScript(harness, `
      Services.prefs.setIntPref("network.proxy.type", 1);
      Services.prefs.setCharPref("network.proxy.ssl", "127.0.0.1");
      Services.prefs.setIntPref("network.proxy.ssl_port", ${proxyPort});
      Services.prefs.setCharPref("network.proxy.no_proxies_on", "");
      Services.prefs.setIntPref("browser.download.folderList", 2);
      Services.prefs.setCharPref("browser.download.dir", ${JSON.stringify(downloads)});
      Services.prefs.setBoolPref("browser.download.useDownloadDir", true);
      Services.prefs.setBoolPref("browser.download.always_ask_before_handling_new_types", false);
      Services.prefs.setCharPref("browser.helperApps.neverAsk.saveToDisk", "text/html,application/octet-stream");
      return true;
    `);
    const execute = async script => (await harness.client.command("WebDriver:ExecuteScript", { script, args: [] })).value;
    const fetchFile = async (name, credentials = "omit", method = "GET") => (await harness.client.command("WebDriver:ExecuteAsyncScript", {
      script: `const done=arguments[arguments.length-1];fetch('${FILE_HOST}/file/${name}',{credentials:'${credentials}',method:'${method}'}).then(async response=>{
        const bytes=await response.arrayBuffer();const digest=[...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(n=>n.toString(16).padStart(2,'0')).join('');
        done({ok:true,status:response.status,bytes:bytes.byteLength,sha256:digest});},error=>done({ok:false,error:String(error)}));`,
      args: [], scriptTimeout: 15000,
    })).value;
    const switchFrame = async selector => {
      const element = await harness.client.command("WebDriver:FindElement", { using: "css selector", value: selector });
      await harness.client.command("WebDriver:SwitchToFrame", { id: element.value });
    };
    const top = () => harness.client.command("WebDriver:SwitchToFrame", { id: null });
    const frameState = () => execute("return {url:location.href,executed:window.executed===true,nonce:window.nonceValue||null,text:document.body?.textContent||''}");
    await harness.client.command("WebDriver:Navigate", { url: GATEWAY + "/parent" });
    await until(() => state.report?.status.active, "the native adapter must configure before exercising it");

    await t.test("large gzip exports preserve bytes and original credential policy", async () => {
      for (const [kind, credentials] of [["official", "omit"], ["credentials", "include"], ["wildcard", "omit"]]) {
        assert.deepEqual(await fetchFile(kind, credentials), { ok: true, status: 200, bytes: EXPORT.length, sha256: hash(EXPORT) });
      }
      assert.deepEqual(await fetchFile("official", "omit", "HEAD"), { ok: true, status: 200, bytes: 0, sha256: hash(Buffer.alloc(0)) });
      for (const kind of ["absent", "duplicate", "foreign", "null"]) assert.equal((await fetchFile(kind)).ok, false, kind);
      assert.equal((await fetchFile("official", "include")).ok, false, "the adapter must not invent ACAC");
      assert.equal((await fetchFile("redirect")).ok, false, "an Origin-rewritten redirect must fail closed");
      assert.equal(state.hits.some(hit => hit.pathname === "/file/redirect-final"), false);
    });

    await t.test("a real export button downloads exact HTML bytes through native blob handling", async () => {
      const button = await harness.client.command("WebDriver:FindElement", { using: "css selector", value: "#download" });
      await harness.client.command("WebDriver:ElementClick", { id: button.value["element-6066-11e4-a52e-4f735466cecf"] });
      const saved = path.join(downloads, "synthetic-firefox-export.html");
      await until(() => fs.existsSync(saved) && fs.statSync(saved).size === EXPORT.length && !fs.existsSync(saved + ".part"), "Firefox must finish saving the scripted HTML export");
      assert.equal(hash(fs.readFileSync(saved)), hash(EXPORT));
    });

    await execute(`for(const [id,url,sandbox] of ${JSON.stringify([
      ["positive", ARTIFACT + "/frame-good"], ["deny", ARTIFACT + "/frame-deny"],
      ["redirect", ARTIFACT + "/redirect"], ["wrapper", "https://wrapper.claudeusercontent.com/wrapper"],
      ["sandbox", GATEWAY + "/sandbox", true], ["foreign", "https://foreign.audit.test/parent"],
    ])}) {const frame=document.createElement('iframe');frame.id=id;if(sandbox)frame.sandbox='allow-scripts';frame.src=url;document.body.append(frame);}return true;`);
    await until(() => state.report?.observations.some(item => item.name === "onCompleted" && item.url.includes("/frame-nested")), "nested artifact must complete its native load");

    await t.test("fresh nonce, restrictive second policy, nested ancestors and frame redirects retain meaning", async () => {
      await switchFrame("#positive"); const first = await frameState(); await top();
      assert.equal(first.executed, true); assert.equal(first.url, ARTIFACT + "/frame-good");
      await execute(`document.getElementById('positive').src='${ARTIFACT}/frame-good?fresh=2';return true;`);
      await until(() => state.report?.observations.some(item => item.name === "onCompleted" && item.url.endsWith("?fresh=2")), "fresh-nonce reload must complete");
      await switchFrame("#positive"); const second = await frameState(); await top();
      assert.equal(second.executed, true); assert.notEqual(second.nonce, first.nonce);
      await switchFrame("#deny"); const denied = await frameState(); await top();
      assert.match(denied.text, /artifact-body/); assert.equal(denied.executed, false, "second CSP script-src none must still apply");
      await switchFrame("#redirect"); assert.equal((await frameState()).executed, true); await top();
      await switchFrame("#wrapper"); await switchFrame("iframe");
      assert.equal((await frameState()).executed, true); await top();
    });

    await t.test("foreign initiators and HTTPS sandbox ancestors receive no additional permission", async () => {
      await switchFrame("#foreign"); assert.equal((await fetchFile("official")).ok, false); await top();
      assert.ok(state.hits.some(hit => hit.pathname === "/file/official" && hit.origin === "https://foreign.audit.test"));
      await switchFrame("#sandbox"); await switchFrame("iframe");
      assert.equal((await frameState()).executed, false); await top();
      await until(() => state.report?.observations.some(item => item.name === "onErrorOccurred" && item.url.endsWith("/frame-opaque")), "opaque ancestor must fail native CSP enforcement");
      assert.equal(state.report.observations.some(item => item.url?.endsWith("/frame-opaque") && item.result?.responseHeaders), false);
    });

    await until(() => state.report?.status.pendingRequests === 0, "adapter request tracking must drain after terminal events");
    for (const item of state.report.observations.filter(item => item.result?.responseHeaders)) {
      const unchanged = headers => headers.filter(header => !["content-security-policy", "content-security-policy-report-only", "x-frame-options", "access-control-allow-origin"].includes(header.name.toLowerCase()));
      assert.deepEqual(unchanged(item.result.responseHeaders), unchanged(item.originalHeaders), "unrelated headers and transport metadata must be unchanged");
    }
    assert.equal(state.report.observations.some(item => item.fault), false);
    assert.ok(state.tunnels.includes("file.claudemcpcontent.com:443"));
    const final = state.report.observations.find(item => item.name === "finalHeaders" && item.url.endsWith("/frame-good"));
    assert.ok(final.responseHeaders.some(header => header.name.toLowerCase() === "content-security-policy" && header.value.includes(GATEWAY)));
    t.diagnostic(JSON.stringify({ firefox: harness.capabilities.browserVersion, strictTLS: true, moduleHashes: hashes, exportBytes: EXPORT.length, exportSha256: hash(EXPORT) }));
  } finally {
    if (harness) await stopFirefoxHarness(harness);
    await fixtures.close();
    fs.rmSync(temporary, { recursive: true, force: true });
  }
});
