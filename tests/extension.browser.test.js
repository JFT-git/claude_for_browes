"use strict";

// Native browser regression tests. The only network targets are synthetic
// .test names mapped to loopback; each run gets a fresh extension directory and
// profile. The temporary package adds only the exact synthetic gateway host.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const crypto = require("node:crypto");
const os = require("node:os");
const path = require("node:path");
const net = require("node:net");
const http = require("node:http");
const https = require("node:https");
const http2 = require("node:http2");
const tls = require("node:tls");
const cp = require("node:child_process");
const { chromium } = require("playwright");

const ROOT = path.resolve(__dirname, "..");
const CHROME_PACKAGE = path.join(ROOT, "extension/dist/chrome");
const BASIC = "Basic " + Buffer.from("synthetic-user:synthetic-password").toString("base64");
const BASIC_C = "Basic " + Buffer.from("synthetic-user-next:synthetic-password-next").toString("base64");
const PROXY_TOKEN_A = "a".repeat(43);
const PROXY_TOKEN_B = "b".repeat(43);
const PROXY_TOKEN_C = "c".repeat(43);
const THUMBNAIL_PNG = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADUlEQVR4nGP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC", "base64");
const CORS_LARGE_FIXTURE = Buffer.alloc(9 * 1024 * 1024);
for (let index = 0; index < CORS_LARGE_FIXTURE.length; index++) CORS_LARGE_FIXTURE[index] = (index * 31 + 17) & 0xff;
const CORS_LARGE_SHA256 = crypto.createHash("sha256").update(CORS_LARGE_FIXTURE).digest("hex");
const CORS_HTML_EXPORT = Buffer.from(`<!doctype html><html><head><meta charset="utf-8"><title>synthetic CORS export</title></head><body><main id="cors-export">PUBLIC_CORS_FETCH_BLOB_EXPORT_READY</main></body></html>\n`, "utf8");
const CORS_HTML_EXPORT_SHA256 = crypto.createHash("sha256").update(CORS_HTML_EXPORT).digest("hex");
const CORS_H2_EXPORT = Buffer.from(`<!doctype html><html><head><meta charset="utf-8"><title>synthetic HTTP2 CORS export</title></head><body><main id="cors-h2-export">PUBLIC_HTTP2_CORS_BLOB_EXPORT_READY</main></body></html>\n`, "utf8");
const CORS_H2_EXPORT_SHA256 = crypto.createHash("sha256").update(CORS_H2_EXPORT).digest("hex");
function proxyTokenVersion(value) {
  return value === PROXY_TOKEN_A ? "A" : value === PROXY_TOKEN_B ? "B" : value === PROXY_TOKEN_C ? "C" : "unknown";
}
function makeSyntheticPdf() {
  const objects = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
    "<< /Length 62 >>\nstream\nBT /F1 12 Tf 72 720 Td (Synthetic PDF download fixture) Tj ET\nendstream",
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    "<< /Title (Synthetic browser download proof) /Author (Local fixture) >>",
  ];
  let source = "%PDF-1.4\n";
  const offsets = [0];
  for (let index = 0; index < objects.length; index++) {
    offsets.push(Buffer.byteLength(source, "ascii"));
    source += `${index + 1} 0 obj\n${objects[index]}\nendobj\n`;
  }
  const xrefOffset = Buffer.byteLength(source, "ascii");
  source += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const offset of offsets.slice(1)) source += `${String(offset).padStart(10, "0")} 00000 n \n`;
  source += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R /Info 6 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`;
  return Buffer.from(source, "ascii");
}
function assertSyntheticPdf(bytes) {
  const source = bytes.toString("ascii");
  assert.ok(source.startsWith("%PDF-1.4\n"), "download must begin with a PDF signature");
  assert.ok(source.includes("/Type /Catalog") && source.includes("/Type /Pages") && source.includes("/Type /Page"),
    "fixture must contain a catalog and a one-page document tree");
  assert.ok(source.includes("/Title (Synthetic browser download proof) /Author (Local fixture)"), "PDF metadata must survive download unchanged");
  const declaredLength = Number(/<< \/Length (\d+) >>\nstream\n/.exec(source)?.[1]);
  const streamStart = source.indexOf("stream\n") + "stream\n".length;
  const streamEnd = source.indexOf("endstream", streamStart);
  assert.equal(streamEnd - streamStart, declaredLength, "PDF stream length must match its exact bytes");
  const startXref = Number(/startxref\n(\d+)\n%%EOF\n$/.exec(source)?.[1]);
  assert.ok(Number.isInteger(startXref) && source.startsWith("xref\n", startXref), "startxref must point at the xref table");
  const xrefHeader = /^xref\n0 (\d+)\n/.exec(source.slice(startXref));
  assert.ok(xrefHeader, "PDF must contain a conventional xref table");
  const count = Number(xrefHeader[1]);
  const xrefLines = source.slice(startXref).split("\n").slice(2, 2 + count);
  assert.equal(xrefLines.length, count, "xref must contain one entry for every object including object zero");
  for (let object = 1; object < count; object++) {
    const offset = Number(xrefLines[object].slice(0, 10));
    assert.ok(source.startsWith(`${object} 0 obj\n`, offset), `xref entry for object ${object} must point to that object`);
  }
  assert.ok(source.includes("trailer\n<< /Size 7 /Root 1 0 R /Info 6 0 R >>"), "PDF trailer must reference its catalog and metadata");
}
const PDF_FIXTURE = makeSyntheticPdf();
const CODE_FIXTURE = Buffer.from('# Synthetic code artifact\nprint("local browser download")\n', "utf8");
const hosts = [
  "gateway.audit.test", "gateway.audit.test.evil.test", "sub.gateway.audit.test",
  "gateway.audit.testing", "unrelated.audit.test", "evil.audit.test",
  "unknown.claudeusercontent.com", "frame.claudemcpcontent.com", "proxy.audit.test",
  "wrapper.claudeusercontent.com", "cdn.tailwindcss.com", "cdn.jsdelivr.net", "h2.frame.claudemcpcontent.com",
];

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => { server.removeListener("error", reject); resolve(server.address().port); });
  });
}

function close(server) {
  if (!server?.listening) return Promise.resolve();
  server.destroyConnections?.();
  server.closeAllConnections?.();
  return new Promise(resolve => server.close(resolve));
}

function generateCertificate(dir) {
  const key = path.join(dir, "fixture-key.pem");
  const cert = path.join(dir, "fixture-cert.pem");
  const san = hosts.map(host => "DNS:" + host).join(",");
  cp.execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
    "-out", cert, "-days", "1", "-subj", "/CN=gateway.audit.test", "-addext", "subjectAltName=" + san], { stdio: "ignore" });
  return { key: fs.readFileSync(key), cert: fs.readFileSync(cert) };
}

async function waitForNativeGatewayTab(worker, targetUrl) {
  return worker.evaluate(async url => {
    const deadline = Date.now() + 8000;
    let lastState = "tab_not_found";
    while (Date.now() < deadline) {
      const tab = (await chrome.tabs.query({})).find(candidate => candidate.url === url);
      if (tab) {
        const commands = globalThis.__browserAuditFetchEnableCommands || [];
        const fetchEnable = [...commands].reverse().find(command => command.tabId === tab.id);
        if (fetchEnable?.outcome === "rejected") {
          return { ready: false, tabId: tab.id, state: "fetch_enable_rejected" };
        }
        if (fetchEnable?.outcome !== "resolved") {
          lastState = "fetch_enable_pending";
          await new Promise(resolve => setTimeout(resolve, 25));
          continue;
        }
        try {
          const tree = await chrome.debugger.sendCommand({ tabId: tab.id }, "Page.getFrameTree");
          const rootFrameUrl = tree.frameTree?.frame?.url || "";
          if (rootFrameUrl !== url) {
            lastState = "root_frame_url_mismatch";
            await new Promise(resolve => setTimeout(resolve, 25));
            continue;
          }
          const current = await status();
          if ((current.artifactDebugger?.attachedTabs || 0) < 1) {
            lastState = "lifecycle_setup_pending";
            await new Promise(resolve => setTimeout(resolve, 25));
            continue;
          }
          return { ready: true, tabId: tab.id, rootFrameUrl,
            fetchEnable: fetchEnable.outcome, attachedTabs: current.artifactDebugger?.attachedTabs || 0 };
        } catch (_) { lastState = "frame_tree_unavailable_after_fetch_enable"; }
      }
      await new Promise(resolve => setTimeout(resolve, 25));
    }
    return { ready: false, state: lastState };
  }, targetUrl);
}

async function installPassiveFetchEnableObserver(worker) {
  await worker.evaluate(() => {
    if (globalThis.__browserAuditFetchEnableCommands) return;
    globalThis.__browserAuditFetchEnableCommands = [];
    const debuggerApi = chrome.debugger;
    const sendCommand = debuggerApi.sendCommand;
    debuggerApi.sendCommand = function (...args) {
      const [debuggee, method] = args;
      const observe = method === "Fetch.enable" && Number.isInteger(debuggee?.tabId) && !debuggee?.sessionId;
      const result = sendCommand.apply(debuggerApi, args);
      if (!observe) return result;
      const record = { tabId: debuggee.tabId, outcome: "pending" };
      const records = globalThis.__browserAuditFetchEnableCommands;
      records.push(record);
      if (records.length > 128) records.splice(0, records.length - 128);
      return Promise.resolve(result).then(value => {
        record.outcome = "resolved";
        return value;
      }, error => {
        record.outcome = "rejected";
        throw error;
      });
    };
  });
}

async function installPassiveFetchObserver(worker) {
  await worker.evaluate(() => {
    if (globalThis.__browserAuditFetchEvents) return;
    globalThis.__browserAuditFetchEvents = [];
    chrome.debugger.onEvent.addListener((source, method, params) => {
      const events = globalThis.__browserAuditFetchEvents;
      if (method === "Page.frameNavigated") {
        events.push({ tabId: source.tabId, method, frameId: params?.frame?.id || "",
          parentId: params?.frame?.parentId || "", url: params?.frame?.url || "" });
        if (events.length > 256) events.splice(0, events.length - 256);
        return;
      }
      if (method !== "Fetch.requestPaused") return;
      const headers = Array.isArray(params?.responseHeaders) ? params.responseHeaders : [];
      events.push({ tabId: source.tabId, url: params?.request?.url || "", resourceType: params?.resourceType || "",
        status: params?.responseStatusCode || 0, statusTextState: params?.responseStatusCode === undefined ? "request" : params?.responseStatusText === "" ? "empty" : typeof params?.responseStatusText === "string" ? "present" : "missing",
        frameId: params?.frameId || "",
        hasAttachment: headers.some(header => header?.name?.toLowerCase() === "content-disposition" && /^attachment(?:\s*;|\s*$)/i.test(header?.value || "")),
        accessControlAllowOrigin: headers.find(header => header?.name?.toLowerCase() === "access-control-allow-origin")?.value || "" });
      const recorded = events[events.length - 1];
      recorded.contentType = headers.find(header => header?.name?.toLowerCase() === "content-type")?.value || "";
      recorded.contentDisposition = headers.find(header => header?.name?.toLowerCase() === "content-disposition")?.value || "";
      if (events.length > 256) events.splice(0, events.length - 256);
    });
  });
}

async function getPassiveFetchEvents(worker) {
  return worker.evaluate(() => globalThis.__browserAuditFetchEvents || []);
}

async function installPassiveTabObserver(worker, tabId) {
  await worker.evaluate(id => {
    if (!globalThis.__browserAuditTabEvents) globalThis.__browserAuditTabEvents = [];
    chrome.tabs.onUpdated.addListener((changedId, change, tab) => {
      if (changedId !== id) return;
      const origin = value => { try { return new URL(value).origin; } catch (_) { return ""; } };
      globalThis.__browserAuditTabEvents.push({ status: change.status || "",
        committedOrigin: origin(tab.url || ""), pendingOrigin: origin(tab.pendingUrl || ""),
        changedOrigin: origin(change.url || "") });
      if (globalThis.__browserAuditTabEvents.length > 64) globalThis.__browserAuditTabEvents.shift();
    });
  }, tabId);
}

async function installPassiveAuthObserver(worker) {
  await worker.evaluate(() => {
    if (globalThis.__browserAuditAuthEvents) return;
    globalThis.__browserAuditAuthEvents = [];
    const record = event => {
      const events = globalThis.__browserAuditAuthEvents;
      events.push(event);
      if (events.length > 256) events.splice(0, events.length - 256);
    };
    chrome.webRequest.onAuthRequired.addListener(details => {
      record({ kind: "auth-challenge",
        requestId: details.requestId,
        url: details.url,
        type: details.type,
        method: details.method || "",
        initiator: details.initiator || "",
        tabId: details.tabId,
        isProxy: details.isProxy === true,
        challengerHost: details.challenger?.host || "",
        challengerPort: details.challenger?.port || 0,
        scheme: details.scheme || "",
        realm: details.realm || "",
      });
      // Passive observer: never supplies credentials or cancels the request.
    }, { urls: ["https://frame.claudemcpcontent.com/*", "https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"] });
    chrome.webRequest.onCompleted.addListener(details => record({ kind: "completed", url: details.url, type: details.type, method: details.method || "", initiator: details.initiator || "", tabId: details.tabId, statusCode: details.statusCode }),
      { urls: ["https://frame.claudemcpcontent.com/*", "https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"] });
    chrome.webRequest.onErrorOccurred.addListener(details => record({ kind: "error", url: details.url, type: details.type, method: details.method || "", initiator: details.initiator || "", tabId: details.tabId, error: details.error }),
      { urls: ["https://frame.claudemcpcontent.com/*", "https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"] });
  });
}

async function getPassiveAuthEvents(worker) {
  return worker.evaluate(() => globalThis.__browserAuditAuthEvents || []);
}

function makeProxy(server, proxyEvents, upstreamPort, getChallengeMode = () => "close", getAcceptedTokenVersions = () => new Set(["A"]), getUpstreamPort = () => upstreamPort) {
  const sockets = new Set();
  server.on("connection", socket => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  server.destroyConnections = () => { for (const socket of sockets) socket.destroy(); };
  server.on("secureConnection", socket => {
    let buffer = Buffer.alloc(0);
    const onData = chunk => {
      buffer = Buffer.concat([buffer, chunk]);
      const end = buffer.indexOf("\r\n\r\n");
      if (end < 0) return;
      const header = buffer.subarray(0, end + 4).toString("latin1");
      const extra = buffer.subarray(end + 4);
      buffer = Buffer.alloc(0);
      const requestLine = header.split("\r\n", 1)[0];
      const authorization = /^Proxy-Authorization:\s*(.+)$/im.exec(header)?.[1]?.trim();
      let tokenVersion = "unknown";
      if (/^Basic\s+/i.test(authorization || "")) {
        const decoded = Buffer.from(authorization.replace(/^Basic\s+/i, ""), "base64").toString("utf8");
        const separator = decoded.indexOf(":");
        if (separator > 0 && decoded.slice(0, separator) === "gateway-proxy") tokenVersion = proxyTokenVersion(decoded.slice(separator + 1));
      }
      const validAuthorization = getAcceptedTokenVersions().has(tokenVersion);
      if (!requestLine.startsWith("CONNECT ")) {
        proxyEvents.push({ kind: "non-connect", requestLine, hasProxyAuthorization: !!authorization });
        socket.destroy();
        return;
      }
      const target = requestLine.slice(8).split(" ")[0];
      if (!validAuthorization) {
        proxyEvents.push({ kind: "challenge", target, hasProxyAuthorization: !!authorization, tokenVersion, tokenMatches: false });
        // Exercise both persistent and production-style cold challenge behavior.
        const closeAfterChallenge = getChallengeMode() === "close";
        const response = `HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="gateway-proxy"\r\nContent-Length: 0\r\nConnection: ${closeAfterChallenge ? "close" : "keep-alive"}\r\n\r\n`;
        if (closeAfterChallenge) socket.end(response);
        else socket.write(response);
        return;
      }
      proxyEvents.push({ kind: "connect", target, hasProxyAuthorization: !!authorization, tokenVersion, tokenMatches: validAuthorization });
      const upstream = net.connect(getUpstreamPort(target), "127.0.0.1", () => {
        socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        if (extra.length) upstream.write(extra);
        socket.pipe(upstream);
        upstream.pipe(socket);
      });
      upstream.on("error", () => socket.destroy());
      socket.removeListener("data", onData);
    };
    socket.on("data", onData);
    socket.on("error", () => {});
  });
  return server;
}

test("packaged Chrome extension uses native network APIs and fails closed", { timeout: 120000 }, async t => {
  assert.ok(fs.existsSync(path.join(CHROME_PACKAGE, "manifest.json")), "build the extension with npm run build:extension first");
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "cg-extension-browser-"));
  const extension = path.join(temp, "chrome-package");
  fs.cpSync(CHROME_PACKAGE, extension, { recursive: true });
  const manifest = JSON.parse(fs.readFileSync(path.join(extension, "manifest.json"), "utf8"));
  assert.equal(manifest.manifest_version, 3);
  assert.ok(Number.parseInt(manifest.minimum_chrome_version, 10) >= 125, "the packaged native debugger path requires Chrome 125 or newer");
  assert.ok(manifest.optional_host_permissions?.includes("https://*/*"), "the packaged extension must retain optional gateway permissions");
  assert.ok(!(manifest.host_permissions || []).some(origin => origin === "https://*/*"), "the package must not grant wildcard access by default");

  const keys = generateCertificate(temp);
  const events = [];
  const downloadResponses = [];
  const directControlPaths = new Set();
  const proxyEvents = [];
  let proxyChallengeMode = "close";
  let mintedProxyTokenVersion = "A";
  let acceptedProxyTokenVersions = new Set(["A"]);
  const sessionTokenVersions = [];
  const rotationRequestEvidence = [];
  let proxySessionStatus = 200;
  let closeActiveProxyTunnels = () => {};
  let pauseWarmupHead = false;
  let releaseWarmupHead;
  let markWarmupHeadObserved;
  const warmupHeadObserved = new Promise(resolve => { markWarmupHeadObserved = resolve; });
  let collectorPort;
  const directCollector = https.createServer(keys, (req, res) => {
    events.push({ kind: "direct", host: req.headers.host?.split(":")[0], path: req.url, method: req.method, authorization: req.headers.authorization, origin: req.headers.origin, cookie: req.headers.cookie });
    if (req.headers.host?.startsWith("frame.claudemcpcontent.com") && /^\/_f\/[^/]+\/_thumb\.img$/.test(req.url)) {
      res.writeHead(200, { "content-type": "image/png", "content-length": THUMBNAIL_PNG.length, "access-control-allow-origin": "*" });
      return res.end(THUMBNAIL_PNG);
    }
    res.writeHead(200, { "content-type": "text/html", "access-control-allow-origin": "*" });
    res.end("<!doctype html><title>direct collector</title><p>direct</p>");
  });
  collectorPort = await listen(directCollector);
  const tunnelCollector = https.createServer(keys, async (req, res) => {
    events.push({ kind: "tunneled", host: req.headers.host?.split(":")[0], path: req.url, method: req.method, authorization: req.headers.authorization, origin: req.headers.origin, cookie: req.headers.cookie,
      hasProxyAuthorization: !!req.headers["proxy-authorization"] });
    const host = req.headers.host?.split(":")[0];
    if (host === "cdn.jsdelivr.net" && req.method === "HEAD" && req.url === "/npm/lodash@4.17.21/lodash.min.js") {
      markWarmupHeadObserved();
      if (pauseWarmupHead) await new Promise(resolve => { releaseWarmupHead = resolve; });
    }
    if (host === "frame.claudemcpcontent.com" && /^\/_f\/[^/]+\/_thumb\.img$/.test(req.url)) {
      res.writeHead(200, { "content-type": "image/png", "content-length": THUMBNAIL_PNG.length, "cache-control": "no-store", "access-control-allow-origin": "*" });
      return res.end(THUMBNAIL_PNG);
    }
    if (host === "cdn.jsdelivr.net" && req.url === "/npm/lodash@4.17.21/lodash.min.js") {
      res.writeHead(200, { "content-type": "application/javascript; charset=utf-8", "cache-control": "no-store" });
      return res.end(req.method === "HEAD" ? undefined : "/* synthetic approved CDN response */");
    }
    if (host === "cdn.tailwindcss.com" && req.url === "/cors-foreign-frame") {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
      return res.end(`<!doctype html><body><script>
        fetch("https://frame.claudemcpcontent.com/cors/foreign-frame", { cache: "no-store" })
          .then(() => parent.postMessage({ kind: "cors-foreign-result", ok: true }, "https://gateway.audit.test"),
            () => parent.postMessage({ kind: "cors-foreign-result", ok: false }, "https://gateway.audit.test"));
      </script></body>`);
    }
    if (host === "frame.claudemcpcontent.com" && req.url === "/downloads/synthetic-report.pdf") {
      const headers = {
        "content-type": "application/pdf",
        "content-disposition": 'attachment; filename="synthetic-report.pdf"',
        "content-length": String(PDF_FIXTURE.length),
        "content-security-policy": "default-src 'none'; frame-ancestors https://claude.ai https://*.claude.ai",
        "x-frame-options": "DENY",
        "cache-control": "no-store",
      };
      downloadResponses.push({ path: req.url, method: req.method, contentType: headers["content-type"], disposition: headers["content-disposition"], contentLength: headers["content-length"], csp: headers["content-security-policy"], xFrameOptions: headers["x-frame-options"] });
      res.writeHead(200, headers);
      return res.end(PDF_FIXTURE);
    }
    if (host === "frame.claudemcpcontent.com" && req.url === "/downloads/synthetic-analysis.py") {
      const headers = {
        "content-type": "application/octet-stream",
        "content-disposition": 'attachment; filename="synthetic-analysis.py"',
        "content-length": String(CODE_FIXTURE.length),
        "content-security-policy": "default-src 'none'; frame-ancestors https://claude.ai https://*.claude.ai",
        "x-frame-options": "DENY",
        "cache-control": "no-store",
      };
      downloadResponses.push({ path: req.url, method: req.method, contentType: headers["content-type"], disposition: headers["content-disposition"], contentLength: headers["content-length"], csp: headers["content-security-policy"], xFrameOptions: headers["x-frame-options"] });
      res.writeHead(200, headers);
      return res.end(CODE_FIXTURE);
    }
    if (host === "frame.claudemcpcontent.com" && req.url.startsWith("/cors/")) {
      const corsHeaders = { "cache-control": "no-store", "access-control-allow-origin": "https://claude.ai" };
      if (req.url === "/cors/html-export") {
        res.writeHead(200, { ...corsHeaders, "content-type": "text/html; charset=utf-8", "content-length": String(CORS_HTML_EXPORT.length) });
        return res.end(CORS_HTML_EXPORT);
      }
      if (req.url === "/cors/positive" || req.url === "/cors/head") {
        res.writeHead(200, { ...corsHeaders, "content-type": "text/plain; charset=utf-8" });
        return res.end("synthetic-cors-ok-001");
      }
      if (req.url === "/cors/large-binary") {
        res.writeHead(200, { ...corsHeaders, "content-type": "application/octet-stream", "content-length": String(CORS_LARGE_FIXTURE.length) });
        return res.end(CORS_LARGE_FIXTURE);
      }
      if (req.url === "/cors/no-acao") {
        res.writeHead(200, { "cache-control": "no-store", "content-type": "text/plain" });
        return res.end("no-acao-body");
      }
      if (req.url === "/cors/wrong-acao") {
        res.writeHead(200, { ...corsHeaders, "access-control-allow-origin": "https://wrong-origin.example", "content-type": "text/plain" });
        return res.end("wrong-acao-body");
      }
      if (req.url === "/cors/duplicate-acao") {
        res.writeHead(200, ["Cache-Control", "no-store", "Content-Type", "text/plain", "Access-Control-Allow-Origin", "https://claude.ai", "Access-Control-Allow-Origin", "https://wrong-origin.example"]);
        return res.end("duplicate-acao");
      }
      if (req.url === "/cors/redirect") {
        res.writeHead(302, { ...corsHeaders, location: "https://frame.claudemcpcontent.com/cors/redirect-target", "content-length": "0" });
        return res.end();
      }
      if (req.url === "/cors/redirect-target") {
        res.writeHead(200, { ...corsHeaders, "content-type": "text/plain" });
        return res.end("redirect-target");
      }
      if (req.url === "/cors/custom-port") {
        res.writeHead(200, { ...corsHeaders, "content-type": "text/plain" });
        return res.end("custom-port-body");
      }
      if (req.url === "/cors/post") {
        res.writeHead(200, { ...corsHeaders, "content-type": "text/plain" });
        return res.end("post-ok!");
      }
      if (req.url === "/cors/foreign-frame") {
        res.writeHead(200, { ...corsHeaders, "content-type": "text/plain" });
        return res.end("foreign-body");
      }
    }
    if (host === "wrapper.claudeusercontent.com" && req.url === "/csp-wrapper") {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store",
        "content-security-policy": "default-src 'self'; frame-ancestors https://claude.ai https://*.claude.ai; frame-src https://frame.claudemcpcontent.com" });
      return res.end(`<!doctype html><title>artifact wrapper</title><iframe id="nested-artifact" src="https://frame.claudemcpcontent.com/csp-artifact"></iframe>`);
    }
    if (host === "cdn.tailwindcss.com" && ["/csp-wrapper-unknown", "/csp-foreign-root"].includes(req.url)) {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
      return res.end(`<!doctype html><title>approved CDN wrapper</title><body><script>window.cspMessages=[];addEventListener('message',event=>{if(event.origin==='https://frame.claudemcpcontent.com')window.cspMessages.push(event.data)})</script><iframe id="blocked-artifact" src="https://frame.claudemcpcontent.com/csp-artifact-unknown-parent"></iframe></body>`);
    }
    if (host === "frame.claudemcpcontent.com" && ["/csp-artifact", "/csp-artifact-unknown-parent"].includes(req.url)) {
      const body = `<!doctype html><title>synthetic CSP artifact</title><main id="artifact-rendered">artifact-rendered</main>
        <script nonce="audit-csp-nonce">document.documentElement.dataset.nonceScript="ran";top.postMessage({probe:"nonce-script-ran"},"*");
          addEventListener("securitypolicyviolation",event=>top.postMessage({probe:"csp-violation",directive:event.effectiveDirective},"*"));
          fetch("/csp-connect-probe",{mode:"no-cors"}).then(()=>top.postMessage({probe:"connect-fetch-allowed"},"*"),()=>top.postMessage({probe:"connect-fetch-rejected"},"*"));</script>
        <script>top.postMessage({probe:"nonce-free-script-ran"},"*")</script>
        <script src="https://cdn.tailwindcss.com/csp-fixture.js"></script><img src="/csp-image-probe">`;
      // Use raw header pairs so the browser receives two independent CSP
      // policies. Their directives intersect; both frame-ancestor directives
      // need the gateway origin appended while all other directives survive.
      res.writeHead(200, [
        "Content-Type", "text/html; charset=utf-8",
        "Content-Security-Policy", `default-src 'self'; frame-ancestors https://claude.ai https://*.claude.ai https://wrapper.claudeusercontent.com; script-src 'self' 'nonce-audit-csp-nonce' https://cdn.tailwindcss.com; img-src 'none'; connect-src 'self' https://api.anthropic.com`,
        "Content-Security-Policy", `frame-ancestors https://claude.ai https://*.claude.ai https://wrapper.claudeusercontent.com; script-src 'nonce-audit-csp-nonce' https://cdn.tailwindcss.com; connect-src 'none'`,
        "Cache-Control", "no-store",
      ]);
      return res.end(body);
    }
    if (req.headers.host?.split(":")[0] === "cdn.tailwindcss.com" && req.url === "/csp-fixture.js") {
      res.writeHead(200, { "content-type": "application/javascript; charset=utf-8", "cache-control": "no-store" });
      return res.end(`document.documentElement.dataset.cdnScript="loaded";top.postMessage({probe:"cdn-script-loaded"},"*")`);
    }
    res.writeHead(200, { "content-type": "text/html", "access-control-allow-origin": "*" });
    res.end("<!doctype html><title>proxy tunnel collector</title><p>tunneled</p>");
  });
  const tunnelPort = await listen(tunnelCollector);

  const h2Sessions = [];
  const liveH2Sessions = new Set();
  const h2Collector = http2.createSecureServer({ key: keys.key, cert: keys.cert, allowHTTP1: true });
  h2Collector.on("session", session => {
    liveH2Sessions.add(session);
    h2Sessions.push({ alpnProtocol: session.socket.alpnProtocol || "" });
    session.once("close", () => liveH2Sessions.delete(session));
  });
  h2Collector.destroyConnections = () => { for (const session of liveH2Sessions) session.destroy(); };
  h2Collector.on("stream", (stream, headers) => {
    const host = String(headers[":authority"] || "").split(":")[0];
    const requestPath = String(headers[":path"] || "/");
    events.push({ kind: "tunneled-h2", host, path: requestPath, method: headers[":method"] || "",
      origin: headers.origin, authorization: headers.authorization, cookie: headers.cookie,
      hasProxyAuthorization: Object.keys(headers).some(name => name.toLowerCase() === "proxy-authorization") });
    if (host === "h2.frame.claudemcpcontent.com" && requestPath === "/cors/h2-export") {
      stream.respond({ ":status": 200, "content-type": "text/html; charset=utf-8", "content-length": String(CORS_H2_EXPORT.length),
        "cache-control": "no-store", "access-control-allow-origin": "https://claude.ai" });
      stream.end(CORS_H2_EXPORT);
      return;
    }
    stream.respond({ ":status": 404, "content-type": "text/plain", "content-length": "0" });
    stream.end();
  });
  const h2Port = await listen(h2Collector);

  const gateway = https.createServer(keys, (req, res) => {
    const requestPath = new URL(req.url, "https://gateway.audit.test").pathname;
    events.push({ kind: "gateway", host: req.headers.host?.split(":")[0], path: req.url, authorization: req.headers.authorization,
      sessionHeader: req.headers["x-gateway-proxy-session"], origin: req.headers.origin, cookie: req.headers.cookie });
    if (req.url === "/__health") {
      const expectedBasic = mintedProxyTokenVersion === "C" ? BASIC_C : BASIC;
      if (req.headers.authorization !== expectedBasic) { res.writeHead(401); return res.end(); }
      res.writeHead(200, { "content-type": "application/json" });
      return res.end(JSON.stringify({ users: 1, session: "ok" }));
    }
    if (req.url === "/__proxy-session") {
      const allowedOrigin = /^chrome-extension:\/\/[a-p]{32}$/.test(req.headers.origin || "") || /^moz-extension:\/\//.test(req.headers.origin || "");
      const expectedBasic = mintedProxyTokenVersion === "C" ? BASIC_C : BASIC;
      if (req.headers.authorization !== expectedBasic || req.headers["x-gateway-proxy-session"] !== "1" || !allowedOrigin) {
        res.writeHead(403, { "content-type": "application/json" });
        return res.end(JSON.stringify({ error: "invalid synthetic extension request" }));
      }
      if (proxySessionStatus !== 200) { res.writeHead(proxySessionStatus); return res.end("unavailable"); }
      const previousProxyToken = req.headers["x-gateway-previous-proxy-token"] || "";
      const previousVersion = proxyTokenVersion(previousProxyToken);
      rotationRequestEvidence.push({ mintedVersion: mintedProxyTokenVersion, previousVersion, previousHeaderPresent: !!previousProxyToken });
      sessionTokenVersions.push(mintedProxyTokenVersion);
      if (mintedProxyTokenVersion !== "A" && previousVersion !== "unknown") {
        acceptedProxyTokenVersions = new Set([mintedProxyTokenVersion]);
        closeActiveProxyTunnels();
      }
      res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
      const proxyToken = { A: PROXY_TOKEN_A, B: PROXY_TOKEN_B, C: PROXY_TOKEN_C }[mintedProxyTokenVersion];
      return res.end(JSON.stringify({ proxyUsername: "gateway-proxy", proxyPassword: proxyToken,
        expiresAt: Date.now() + 5 * 60_000, proxy: { scheme: "https", host: "proxy.audit.test", port: proxyPort } }));
    }
    if (req.url === "/csp-host") {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
      return res.end(`<!doctype html><title>CSP host fixture</title><body>
        <script>window.cspMessages=[];addEventListener('message',event=>{if(event.origin==='https://frame.claudemcpcontent.com'||event.origin==='https://gateway.audit.test')window.cspMessages.push({origin:event.origin,...event.data})})</script>
        <iframe id="artifact-frame" src="https://frame.claudemcpcontent.com/csp-artifact"></iframe>
        <iframe id="unrelated-frame" src="https://gateway.audit.test/unrelated-csp-frame"></iframe>
      </body>`);
    }
    if (req.url === "/nested-csp-host" || req.url === "/unknown-intermediate-host") {
      const wrapper = req.url === "/nested-csp-host"
        ? "https://wrapper.claudeusercontent.com/csp-wrapper"
        : "https://cdn.tailwindcss.com/csp-wrapper-unknown";
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
      return res.end(`<!doctype html><title>nested CSP host fixture</title><body>
        <script>window.cspMessages=[];addEventListener('message',event=>{if(event.origin==='https://frame.claudemcpcontent.com'||event.origin==='https://gateway.audit.test')window.cspMessages.push({origin:event.origin,...event.data})})</script>
        <iframe id="artifact-wrapper" src="${wrapper}"></iframe>
      </body>`);
    }
    if (requestPath === "/native-debugger-ready") {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
      return res.end(`<!doctype html><title>native debugger readiness fixture</title><body><script>window.cspMessages=[];addEventListener('message',event=>{if(event.origin==='https://frame.claudemcpcontent.com'||event.origin==='https://gateway.audit.test')window.cspMessages.push({origin:event.origin,...event.data})})</script><main>ready</main></body>`);
    }
    if (requestPath === "/cold-proxy-image-host") {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
      return res.end("<!doctype html><title>cold proxy image fixture</title><body><main>ready for first proxy request</main></body>");
    }
    if (requestPath === "/download-host") {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
      return res.end(`<!doctype html><title>native download host</title><body>
        <a id="pdf-download" href="https://frame.claudemcpcontent.com/downloads/synthetic-report.pdf">Download PDF</a>
        <a id="code-download" href="https://frame.claudemcpcontent.com/downloads/synthetic-analysis.py">Download code</a>
      </body>`);
    }
    if (requestPath === "/cors-host") {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
      return res.end(`<!doctype html><title>synthetic CORS host</title><body><script>
        window.corsProbeResults = [];
        addEventListener("message", event => { if (event.origin === "https://cdn.tailwindcss.com" && event.data?.kind === "cors-foreign-result") corsProbeResults.push(event.data); });
      </script><main>local synthetic CORS fixture</main></body>`);
    }
    if (req.url === "/unrelated-csp-frame") {
      events.push({ kind: "gateway-unrelated-frame", host: req.headers.host?.split(":")[0], path: req.url });
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", "content-security-policy": "default-src 'none'; frame-ancestors 'none'; script-src 'nonce-unrelated-frame'" });
      return res.end(`<script nonce="unrelated-frame">parent.postMessage({probe:"unrelated-frame-script-ran"},"https://gateway.audit.test")</script><p>must not be framed</p>`);
    }
    // Main-frame script probes one unknown host and navigates to a second one.
    const mainFrame = "https://unknown.claudeusercontent.com/mainframe-probe";
    const opaque = "https://frame.claudemcpcontent.com/opaque-frame-probe";
    res.writeHead(200, { "content-type": "text/html" });
    res.end(`<!doctype html><title>synthetic gateway</title><body>synthetic gateway <button id="popup-probe">open probe</button></body><script>
      fetch("https://evil.audit.test/subresource-probe", { mode: "no-cors" }).catch(()=>{});
      const f=document.createElement('iframe'); f.setAttribute('sandbox','allow-scripts');
      f.srcdoc='<img src="${opaque}"><img src="https://evil.audit.test/opaque-unknown-probe"><script>parent.postMessage({probe:"opaque-frame-started"},"*")<\\/script>'; document.body.appendChild(f);
      addEventListener('message',event=>{if(event.data?.probe==='opaque-frame-started')document.documentElement.dataset.opaqueFrameStarted='true'});
      window.runMainFrameProbe=()=>location.assign(${JSON.stringify(mainFrame)});
      document.getElementById('popup-probe').onclick=()=>window.open("https://evil.audit.test/popup-probe","_blank");
    </script>`);
  });
  const gatewayPort = await listen(gateway);
  // The extension package keeps its production optional-permission model. Add
  // only this synthetic gateway hostname to the temporary copy so the test can
  // exercise the native permission APIs without a browser prompt.
  manifest.host_permissions = [...(manifest.host_permissions || []), "https://gateway.audit.test/*"];
  fs.writeFileSync(path.join(extension, "manifest.json"), JSON.stringify(manifest));
  const plain = http.createServer((req, res) => {
    events.push({ kind: "plain", host: req.headers.host?.split(":")[0], path: req.url, authorization: req.headers.authorization });
    res.writeHead(200, { "content-type": "text/plain" }); res.end("synthetic http");
  });
  const plainPort = await listen(plain);
  const proxy = makeProxy(tls.createServer(keys), proxyEvents, tunnelPort, () => proxyChallengeMode, () => acceptedProxyTokenVersions,
    target => target.startsWith("h2.frame.claudemcpcontent.com:") ? h2Port : tunnelPort);
  closeActiveProxyTunnels = () => proxy.destroyConnections();
  const proxyPort = await listen(proxy);
  const directHosts = new Set([hosts[1], hosts[2], hosts[3], hosts[4], hosts[5], hosts[6], hosts[7], "cdn.tailwindcss.com", "cdn.jsdelivr.net", "h2.frame.claudemcpcontent.com"]);
  const resolver = [
    `MAP gateway.audit.test 127.0.0.1:${gatewayPort}`,
    ...[...directHosts].map(host => `MAP ${host} 127.0.0.1:${collectorPort}`),
    `MAP proxy.audit.test 127.0.0.1:${proxyPort}`,
    "MAP * ~NOTFOUND",
  ].join(",");
  let context;
  try {
    // Prove the direct collector can receive the synthetic host before the
    // extension's global egress policy is installed; this keeps absence of
    // requests in the protected run a meaningful negative signal.
    const directControl = await chromium.launchPersistentContext(path.join(temp, "direct-control-profile"), {
      channel: process.env.CHROME ? undefined : "chromium", executablePath: process.env.CHROME || undefined,
      headless: true, ignoreHTTPSErrors: true,
      args: ["--disable-background-networking", "--disable-sync", "--ignore-certificate-errors", "--host-resolver-rules=" + resolver],
    });
    try {
      const controlPage = await directControl.newPage();
      await controlPage.goto("https://evil.audit.test/direct-control");
      assert.ok(events.some(event => event.kind === "direct" && event.path === "/direct-control"), "direct collector control request must be observable");
      await controlPage.evaluate(() => fetch("https://frame.claudemcpcontent.com/csp-connect-probe", { mode: "no-cors" }));
      assert.ok(events.some(event => event.kind === "direct" && event.host === "frame.claudemcpcontent.com" && event.path === "/csp-connect-probe"),
        "the exact artifact-origin collector endpoint must be reachable when no extension policy is installed");
      await controlPage.evaluate(() => fetch("https://frame.claudemcpcontent.com/csp-image-probe", { mode: "no-cors" }));
      assert.ok(events.some(event => event.kind === "direct" && event.host === "frame.claudemcpcontent.com" && event.path === "/csp-image-probe"),
        "the artifact-origin image endpoint must be observable when no extension policy is installed");
      await controlPage.evaluate(() => fetch("https://cdn.tailwindcss.com/csp-fixture.js", { mode: "no-cors" }));
      assert.ok(events.some(event => event.kind === "direct" && event.host === "cdn.tailwindcss.com" && event.path === "/csp-fixture.js"),
        "the approved CDN endpoint must be reachable when no extension policy is installed");
      await controlPage.evaluate(async () => {
        const paths = ["anonymous-cold", "ordinary-cold"];
        await Promise.all(paths.map(id => new Promise(resolve => {
          const image = new Image();
          if (id === "anonymous-cold") image.crossOrigin = "anonymous";
          image.onload = image.onerror = resolve;
          image.src = `https://frame.claudemcpcontent.com/_f/${id}/_thumb.img`;
        })));
      });
      assert.ok(events.some(event => event.kind === "direct" && event.host === "frame.claudemcpcontent.com" && event.path === "/_f/anonymous-cold/_thumb.img"),
        "the anonymous thumbnail target must be reachable through the direct-control profile");
      assert.ok(events.some(event => event.kind === "direct" && event.host === "frame.claudemcpcontent.com" && event.path === "/_f/ordinary-cold/_thumb.img"),
        "the ordinary thumbnail target must be reachable through the direct-control profile");
    } finally { await directControl.close(); }
    for (const event of events.filter(event => event.kind === "direct")) directControlPaths.add(event.path);
    events.length = 0;

    context = await chromium.launchPersistentContext(path.join(temp, "isolated-profile"), {
      channel: process.env.CHROME ? undefined : "chromium",
      executablePath: process.env.CHROME || undefined,
      headless: true,
      ignoreHTTPSErrors: true,
      acceptDownloads: true,
      locale: "ru-RU",
      timezoneId: "Europe/Moscow",
      args: [
        "--disable-extensions-except=" + extension,
        "--load-extension=" + extension,
        "--disable-background-networking", "--disable-sync", "--ignore-certificate-errors",
        "--site-per-process",
        "--host-resolver-rules=" + resolver,
      ],
    });
    const worker = context.serviceWorkers()[0] || await context.waitForEvent("serviceworker", { timeout: 15000 });
    await installPassiveFetchEnableObserver(worker);
    const unconfigured = await context.newPage();
    await unconfigured.goto("https://unknown.claudeusercontent.com/startup-block-probe", { timeout: 5000 }).catch(() => {});
    await unconfigured.waitForTimeout(300);
    assert.equal(events.some(event => event.kind === "direct" && event.path === "/startup-block-probe"), false,
      "the packaged startup block must prevent artifact egress before credentials or a proxy session exist");
    await context.addCookies([{ name: "browser-cookie", value: "synthetic-browser-cookie", domain: "gateway.audit.test", path: "/", secure: true, httpOnly: true }]);
    await context.addCookies([{ name: "cdn-browser-cookie", value: "synthetic-cdn-cookie", domain: "cdn.jsdelivr.net", path: "/", secure: true, httpOnly: true }]);
    const extensionId = new URL(worker.url()).host;
    const options = await context.newPage();
    await options.goto(`chrome-extension://${extensionId}/options.html`);
    await installPassiveAuthObserver(worker);
    assert.ok((await context.cookies("https://cdn.jsdelivr.net")).some(cookie => cookie.name === "cdn-browser-cookie" && cookie.value === "synthetic-cdn-cookie"),
      "the warmup host must have a real synthetic browser cookie for the omission assertion");
    await options.locator("#host").fill("gateway.audit.test");
    await options.locator("#user").fill("synthetic-user");
    await options.locator("#pass").fill("synthetic-password");
    pauseWarmupHead = true;
    const saveClick = options.locator("#save").click();
    try {
      await Promise.race([warmupHeadObserved, new Promise((_, reject) => setTimeout(() => reject(new Error("warmup HEAD did not reach the synthetic collector")), 15000))]);
      const warmingState = await worker.evaluate(() => status());
      const warmingSessionRules = await worker.evaluate(() => chrome.declarativeNetRequest.getSessionRules());
      assert.equal(warmingState.proxyReady, false, "proxy session must remain unavailable while its native HEAD challenge is pending");
      assert.equal(warmingState.proxyWarming, true, "worker status must expose the pending native proxy-auth warmup");
      assert.ok(warmingSessionRules.some(rule => rule.id === 2020 && rule.condition?.requestMethods?.includes("head")
        && rule.condition?.initiatorDomains?.includes(extensionId) && rule.condition?.regexFilter === "^https://cdn\\.jsdelivr\\.net/npm/lodash@4\\.17\\.21/lodash\\.min\\.js$"),
      `only the exact extension-origin HEAD should receive a temporary warmup exception (${JSON.stringify(warmingSessionRules.filter(rule => rule.id === 2020))})`);
      assert.equal(warmingSessionRules.some(rule => [2000, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018].includes(rule.id)), false,
        "the artifact session allow must stay absent until the native HEAD is authenticated");
      assert.equal(events.some(event => event.kind === "tunneled" && event.host === "frame.claudemcpcontent.com"), false,
        "no artifact request should precede successful proxy warmup");
    } finally {
      pauseWarmupHead = false;
      releaseWarmupHead?.();
      await saveClick;
    }
    await options.waitForFunction(() => document.getElementById("status").textContent.includes("✔") || document.getElementById("status").textContent.includes("недоступен"), null, { timeout: 20000 });
    const initialized = await worker.evaluate(() => status());
    assert.equal(initialized.fingerprint && initialized.proxyReady, true,
      `the packaged options flow must register the MAIN script and install the proxy session (${JSON.stringify(initialized)}; ${await options.locator("#status").textContent()})`);

    await t.test("cold proxy authentication loads anonymous and ordinary artifact thumbnails", { timeout: 30000 }, async () => {
      const page = await context.newPage();
      const responses = [];
      page.on("response", response => {
        if (/\/\_f\/[^/]+\/_thumb\.img$/.test(new URL(response.url()).pathname)) {
          responses.push({ url: response.url(), status: response.status(), type: response.request().resourceType() });
        }
      });
      await page.goto("https://gateway.audit.test/cold-proxy-image-host");
      const proxyStart = proxyEvents.length;
      const imageResults = await page.evaluate(async () => {
        const load = (id, anonymous) => new Promise(resolve => {
          const image = new Image();
          if (anonymous) image.crossOrigin = "anonymous";
          image.onload = () => resolve({ id, loaded: true, width: image.naturalWidth });
          image.onerror = () => resolve({ id, loaded: false, width: image.naturalWidth });
          image.src = `https://frame.claudemcpcontent.com/_f/${id}/_thumb.img`;
          document.body.append(image);
        });
        const anonymous = await load("anonymous-cold", true);
        const ordinary = await load("ordinary-cold", false);
        return [anonymous, ordinary];
      });
      await page.waitForTimeout(300);
      const authEvents = await getPassiveAuthEvents(worker);
      const authAttemptsSize = await worker.evaluate(() => authAttempts.size);
      const coldProxyEvents = proxyEvents.slice(proxyStart);
      assert.deepEqual(imageResults, [
        { id: "anonymous-cold", loaded: true, width: 1 },
        { id: "ordinary-cold", loaded: true, width: 1 },
      ], `a cold anonymous image request must complete, and a normal image must also render (${JSON.stringify({ responses, authAttemptsSize, authEvents, proxyEvents: coldProxyEvents, tunnel: events.filter(event => event.kind === "tunneled" && event.path.startsWith("/_f/")), direct: events.filter(event => event.kind === "direct" && event.path.startsWith("/_f/"))})})`);
      const completedResponses = responses.filter(response => response.status === 200 && response.type === "image");
      assert.equal(completedResponses.length, 2, "both synthetic thumbnails must receive an HTTP 200 image response");
      const headUrl = "https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js";
      const headChallenge = authEvents.find(event => event.kind === "auth-challenge" && event.url === headUrl && event.method === "HEAD");
      assert.ok(headChallenge && headChallenge.isProxy && headChallenge.challengerHost === "proxy.audit.test"
        && headChallenge.challengerPort === proxyPort && headChallenge.scheme.toLowerCase() === "basic"
        && headChallenge.realm === "gateway-proxy" && headChallenge.initiator === `chrome-extension://${extensionId}`
        && headChallenge.tabId === -1,
      `the shipped extension lifecycle must answer an extension-origin HEAD proxy challenge before any protected image (${JSON.stringify(headChallenge)})`);
      const headCompleted = authEvents.find(event => event.kind === "completed" && event.url === headUrl && event.method === "HEAD");
      assert.equal(headCompleted?.statusCode, 200, "the native extension HEAD warmup must complete successfully");
      const headConnect = proxyEvents.find(event => event.kind === "connect" && event.target === "cdn.jsdelivr.net:443" && event.tokenVersion === "A" && event.tokenMatches);
      assert.ok(headConnect, "the shipped HEAD request must authenticate the cold proxy using session A");
      const cdnHead = events.find(event => event.kind === "tunneled" && event.host === "cdn.jsdelivr.net"
        && event.path === "/npm/lodash@4.17.21/lodash.min.js" && event.method === "HEAD");
      assert.ok(cdnHead && cdnHead.cookie === undefined && cdnHead.authorization === undefined && !cdnHead.hasProxyAuthorization,
      `the approved CDN must receive the extension-origin HEAD with no Authorization, Cookie, or Proxy-Authorization header (${JSON.stringify(cdnHead && {
        origin: cdnHead.origin, hasAuthorization: cdnHead.authorization !== undefined,
        hasCookie: cdnHead.cookie !== undefined, hasProxyAuthorization: cdnHead.hasProxyAuthorization,
        originMatches: cdnHead.origin === `chrome-extension://${extensionId}`,
      })})`);
      assert.equal(authEvents.some(event => event.kind === "auth-challenge" && event.type === "image"), false,
        "the cold image requests must not be the requests that receive proxy authentication challenges");
      const acceptedConnections = coldProxyEvents.filter(event => event.kind === "connect" && event.target === "frame.claudemcpcontent.com:443" && event.tokenVersion === "A" && event.tokenMatches);
      assert.ok(acceptedConnections.length >= 1, "the anonymous and ordinary images must traverse the proxy using the warmed session token");
      for (const id of ["anonymous-cold", "ordinary-cold"]) {
        const targetUrl = `https://frame.claudemcpcontent.com/_f/${id}/_thumb.img`;
        const completed = authEvents.find(event => event.kind === "completed" && event.url === targetUrl && event.type === "image");
        assert.equal(completed?.statusCode, 200, `${id} must finish after proxy authentication`);
        assert.ok(events.some(event => event.kind === "tunneled" && event.host === "frame.claudemcpcontent.com" && event.path === `/_f/${id}/_thumb.img`),
          `${id} must reach the tunnel collector`);
      }
      assert.equal(events.some(event => event.kind === "direct" && event.host === "frame.claudemcpcontent.com" && event.path.startsWith("/_f/")), false,
        "cold thumbnail requests must never reach the direct collector");
      assert.ok(directControlPaths.has("/_f/anonymous-cold/_thumb.img") && directControlPaths.has("/_f/ordinary-cold/_thumb.img"),
        "separate direct-control profile proves both exact thumbnail endpoints would be observable without extension routing");
    });

    await t.test("proxy token rotation replaces Chromium's cached credential before images", { timeout: 30000 }, async () => {
      assert.ok(sessionTokenVersions.includes("A"), "the first configured proxy session must mint synthetic token A");
      mintedProxyTokenVersion = "B";
      const proxyStart = proxyEvents.length;
      const authStart = (await getPassiveAuthEvents(worker)).length;
      const refreshed = await worker.evaluate(async () => {
        try { await refreshProxySession(await getConfig(), configEpoch); return { ok: true }; }
        catch (error) { return { ok: false, errorName: error?.name || "refresh_failed" }; }
      });
      assert.deepEqual(refreshed, { ok: true }, "the native lifecycle must mint replacement session B");
      const state = await worker.evaluate(() => status());
      assert.equal(state.proxyReady, true, `replacement session must become ready after native warmup (${JSON.stringify(state)})`);
      const rotation = rotationRequestEvidence.at(-1);
      assert.deepEqual(rotation, { mintedVersion: "B", previousVersion: "A", previousHeaderPresent: true },
        "the B mint request must prove it carries A as the prior session before the gateway revokes A");

      const rotationAuthEvents = (await getPassiveAuthEvents(worker)).slice(authStart);
      const rotationProxyEvents = proxyEvents.slice(proxyStart);
      const rejectedA = rotationProxyEvents.find(event => event.kind === "challenge" && event.target === "cdn.jsdelivr.net:443" && event.tokenVersion === "A");
      const acceptedHeadB = rotationProxyEvents.find(event => event.kind === "connect" && event.target === "cdn.jsdelivr.net:443" && event.tokenVersion === "B" && event.tokenMatches);
      assert.ok(rejectedA, `the gateway must reject Chromium's cached A after minting B (${JSON.stringify(rotationProxyEvents)})`);
      assert.ok(acceptedHeadB, `the extension HEAD auth callback must retry with B (${JSON.stringify(rotationProxyEvents)})`);
      const rotationHeadChallenge = rotationAuthEvents.find(event => event.kind === "auth-challenge"
        && event.url === "https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js" && event.method === "HEAD");
      assert.ok(rotationHeadChallenge && rotationHeadChallenge.initiator === `chrome-extension://${extensionId}`
        && rotationHeadChallenge.tabId === -1 && rotationHeadChallenge.isProxy,
      `the native rotation challenge must be an extension-worker HEAD (${JSON.stringify(rotationHeadChallenge)})`);
      const rotationHeadComplete = rotationAuthEvents.find(event => event.kind === "completed"
        && event.url === "https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js" && event.method === "HEAD" && event.statusCode === 200);
      assert.ok(rotationHeadComplete, "the retry of the replacement HEAD must finish with 200");

      const page = await context.newPage();
      await page.goto("https://gateway.audit.test/cold-proxy-image-host");
      const imageResults = await page.evaluate(async () => Promise.all([true, false].map(anonymous => new Promise(resolve => {
        const id = `rotated-${anonymous ? "anonymous" : "ordinary"}`;
        const image = new Image();
        if (anonymous) image.crossOrigin = "anonymous";
        image.onload = () => resolve({ id, loaded: true, width: image.naturalWidth });
        image.onerror = () => resolve({ id, loaded: false, width: image.naturalWidth });
        image.src = `https://frame.claudemcpcontent.com/_f/${id}/_thumb.img`;
        document.body.append(image);
      }))));
      await page.waitForTimeout(250);
      assert.deepEqual(imageResults, [
        { id: "rotated-anonymous", loaded: true, width: 1 },
        { id: "rotated-ordinary", loaded: true, width: 1 },
      ], "both fresh thumbnail requests must render after session rotation");
      assert.ok(proxyEvents.slice(proxyStart).some(event => event.kind === "connect" && event.target === "frame.claudemcpcontent.com:443" && event.tokenVersion === "B" && event.tokenMatches),
        "the image CONNECT requests must use B after A has been revoked");
      for (const id of ["rotated-anonymous", "rotated-ordinary"]) {
        assert.ok(events.some(event => event.kind === "tunneled" && event.host === "frame.claudemcpcontent.com" && event.path === `/_f/${id}/_thumb.img`),
          `${id} must reach the TLS collector through the proxy`);
      }
      assert.equal(events.some(event => event.kind === "direct" && event.host === "frame.claudemcpcontent.com" && event.path.startsWith("/_f/rotated-")), false,
        "rotated image requests must never fall through to the direct collector");
      assert.equal(await worker.evaluate(() => authAttempts.size), 0, "completed A-to-B retry state must be cleared");
    });

    await t.test("same-gateway account switch revokes the former owner's proxy token", { timeout: 30000 }, async () => {
      assert.ok(rotationRequestEvidence.some(item => item.mintedVersion === "B" && item.previousVersion === "A"),
        "the prior native rotation test must have established token B");
      mintedProxyTokenVersion = "C";
      const proxyStart = proxyEvents.length;
      const authStart = (await getPassiveAuthEvents(worker)).length;
      await options.locator("#user").fill("synthetic-user-next");
      await options.locator("#pass").fill("synthetic-password-next");
      await options.locator("#save").click();
      const accountDeadline = Date.now() + 20000;
      while (Date.now() < accountDeadline && !rotationRequestEvidence.some(item => item.mintedVersion === "C")) await new Promise(resolve => setTimeout(resolve, 50));
      assert.ok(rotationRequestEvidence.some(item => item.mintedVersion === "C"), "saving the new account must request a replacement proxy token");
      await worker.evaluate(async () => {
        const deadline = Date.now() + 10000;
        while (Date.now() < deadline && !(sessionUsable() && proxySession?.proxyPassword === "c".repeat(43))) await new Promise(resolve => setTimeout(resolve, 50));
      });
      const state = await worker.evaluate(() => status());
      assert.equal(state.proxyReady, true, `new account must become ready after its native proxy warmup (${JSON.stringify(state)})`);
      assert.deepEqual(rotationRequestEvidence.at(-1), { mintedVersion: "C", previousVersion: "B", previousHeaderPresent: true },
        "the same-authority account change must present B for targeted revocation before minting C");

      const accountProxyEvents = proxyEvents.slice(proxyStart);
      assert.ok(accountProxyEvents.some(event => event.kind === "challenge" && event.target === "cdn.jsdelivr.net:443" && event.tokenVersion === "B"),
        `the new account must reject the browser's cached B (${JSON.stringify(accountProxyEvents)})`);
      assert.ok(accountProxyEvents.some(event => event.kind === "connect" && event.target === "cdn.jsdelivr.net:443" && event.tokenVersion === "C" && event.tokenMatches),
        "the extension worker must answer the warmup challenge with account token C");
      const accountAuthEvents = (await getPassiveAuthEvents(worker)).slice(authStart);
      assert.ok(accountAuthEvents.some(event => event.kind === "auth-challenge" && event.url === "https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"
        && event.method === "HEAD" && event.initiator === `chrome-extension://${extensionId}` && event.tabId === -1),
      "account replacement must use the native extension-origin HEAD challenge");

      const page = await context.newPage();
      await page.goto("https://gateway.audit.test/cold-proxy-image-host");
      const imageResult = await page.evaluate(() => new Promise(resolve => {
        const image = new Image();
        image.onload = () => resolve({ loaded: true, width: image.naturalWidth });
        image.onerror = () => resolve({ loaded: false, width: image.naturalWidth });
        image.src = "https://frame.claudemcpcontent.com/_f/account-c/_thumb.img";
        document.body.append(image);
      }));
      assert.deepEqual(imageResult, { loaded: true, width: 1 }, "an artifact image must still load through the replacement account session");
      assert.ok(proxyEvents.slice(proxyStart).some(event => event.kind === "connect" && event.target === "frame.claudemcpcontent.com:443" && event.tokenVersion === "C" && event.tokenMatches),
        "the artifact image must authenticate using account token C");
      assert.equal(events.some(event => event.kind === "direct" && event.host === "frame.claudemcpcontent.com" && event.path === "/_f/account-c/_thumb.img"), false,
        "account switch must preserve mandatory proxy routing");
    });

    await t.test("native PDF and code downloads preserve exact bytes and attachment metadata through the proxy", { timeout: 30000 }, async () => {
      const page = await context.newPage();
      await page.goto("https://gateway.audit.test/download-host");
      const initialReadiness = await waitForNativeGatewayTab(worker, page.url());
      assert.equal(initialReadiness.ready, true, `the exact gateway tab must be attached before starting a download (${JSON.stringify(initialReadiness)})`);
      await installPassiveFetchObserver(worker);
      await installPassiveTabObserver(worker, initialReadiness.tabId);
      const cases = [
        { selector: "#pdf-download", url: "https://frame.claudemcpcontent.com/downloads/synthetic-report.pdf", name: "synthetic-report.pdf", mime: "application/pdf", body: PDF_FIXTURE },
        { selector: "#code-download", url: "https://frame.claudemcpcontent.com/downloads/synthetic-analysis.py", name: "synthetic-analysis.py", mime: "application/octet-stream", body: CODE_FIXTURE },
      ];
      const proxyStart = proxyEvents.length;
      for (const item of cases) {
        let downloadSeen = false;
        let responseSeen = false;
        const requestFailures = [];
        const onRequestFailed = request => {
          if (request.url() === item.url) requestFailures.push({ resourceType: request.resourceType(), error: request.failure()?.errorText || "unknown" });
        };
        page.on("requestfailed", onRequestFailed);
        const downloadPromise = page.waitForEvent("download", { timeout: 8000 }).then(value => { downloadSeen = true; return value; });
        const responsePromise = page.waitForResponse(response => response.url() === item.url, { timeout: 8000 }).then(value => { responseSeen = true; return value; });
        await page.locator(item.selector).click({ noWaitAfter: true });
        let download;
        let response;
        try {
          [download, response] = await Promise.all([downloadPromise, responsePromise]);
        } catch (error) {
          const nativeStatus = await worker.evaluate(() => status()).catch(failure => ({ error: failure?.name || "error" }));
          page.off("requestfailed", onRequestFailed);
          const fetchEvents = (await getPassiveFetchEvents(worker)).filter(event => event.tabId === initialReadiness.tabId && event.url === item.url);
          const tabEvents = await worker.evaluate(() => globalThis.__browserAuditTabEvents || []);
          assert.fail(`native download did not expose both browser events (download=${downloadSeen}, response=${responseSeen}, failed=${JSON.stringify(requestFailures)}, page=${page.url()}, collector=${JSON.stringify(downloadResponses)}, tunnel=${JSON.stringify(events.filter(event => event.kind === "tunneled" && event.host === "frame.claudemcpcontent.com").map(({path,method}) => ({path,method})))}, fetch=${JSON.stringify(fetchEvents)}, tabs=${JSON.stringify(tabEvents)}, proxy=${JSON.stringify(proxyEvents.slice(proxyStart).map(({kind,target,tokenVersion,tokenMatches,authorized}) => ({kind,target,tokenVersion,tokenMatches,authorized})))}, debugger=${JSON.stringify(nativeStatus?.artifactDebugger)}, cause=${error.name})`);
        }
        page.off("requestfailed", onRequestFailed);
        assert.equal(download.url(), item.url);
        assert.equal(download.suggestedFilename(), item.name, "Content-Disposition filename must be honored by Chromium");
        assert.equal(await download.failure(), null, "native download must finish without a browser failure");
        assert.equal(response.status(), 200);
        const responseHeaders = await response.allHeaders();
        assert.equal(responseHeaders["content-type"], item.mime, "download MIME type must be preserved");
        assert.equal(responseHeaders["content-disposition"], `attachment; filename="${item.name}"`);
        assert.equal(responseHeaders["content-security-policy"], "default-src 'none'; frame-ancestors https://claude.ai https://*.claude.ai",
          "attachment responses must bypass artifact-document CSP rewriting");
        assert.equal(responseHeaders["x-frame-options"], "DENY", "attachment response must retain its original X-Frame-Options header");

        const savedPath = path.join(temp, `download-${item.name}`);
        await download.saveAs(savedPath);
        const bytes = fs.readFileSync(savedPath);
        assert.deepEqual(bytes, item.body, `${item.name} bytes must match the exact local TLS fixture response`);
        assert.equal(crypto.createHash("sha256").update(bytes).digest("hex"), crypto.createHash("sha256").update(item.body).digest("hex"),
          `${item.name} download hash must match the fixture`);
        if (item.mime === "application/pdf") assertSyntheticPdf(bytes);

        const collectorResponse = downloadResponses.find(entry => entry.path === new URL(item.url).pathname);
        assert.deepEqual(collectorResponse, {
          path: new URL(item.url).pathname, method: "GET", contentType: item.mime,
          disposition: `attachment; filename="${item.name}"`, contentLength: String(item.body.length),
          csp: "default-src 'none'; frame-ancestors https://claude.ai https://*.claude.ai", xFrameOptions: "DENY",
        }, "the TLS collector must receive an ordinary GET and return fixed attachment metadata");
        assert.ok(events.some(event => event.kind === "tunneled" && event.host === "frame.claudemcpcontent.com"
          && event.path === new URL(item.url).pathname && event.method === "GET"), "download response must traverse the TLS tunnel");
        assert.equal(events.some(event => event.kind === "direct" && event.host === "frame.claudemcpcontent.com"
          && event.path === new URL(item.url).pathname), false, "download must never reach the direct collector");
      }
      assert.equal(page.url(), "https://gateway.audit.test/download-host", "an attachment download must leave its gateway tab on the original page");
      const readiness = await waitForNativeGatewayTab(worker, page.url());
      assert.equal(readiness.ready, true, `the original gateway tab must remain attached after downloads (${JSON.stringify(readiness)})`);
      await page.evaluate(() => {
        window.afterDownloadMessages = [];
        addEventListener("message", event => {
          if (event.origin === "https://frame.claudemcpcontent.com") window.afterDownloadMessages.push(event.data);
        });
        const frame = document.createElement("iframe");
        frame.id = "after-download-artifact";
        frame.src = "https://frame.claudemcpcontent.com/csp-artifact";
        document.body.append(frame);
      });
      await page.waitForFunction(() => window.afterDownloadMessages?.some(message => message.probe === "nonce-script-ran"), null, { timeout: 10000 });
      const afterDownloadFrame = page.frames().find(frame => frame.url().startsWith("https://frame.claudemcpcontent.com/csp-artifact"));
      assert.ok(afterDownloadFrame, "the post-download artifact iframe must retain its original HTTPS origin");
      assert.equal(await afterDownloadFrame.locator("#artifact-rendered").textContent(), "artifact-rendered",
        "the same gateway tab must continue to rewrite eligible artifact CSP after an attachment navigation is canceled");
      assert.ok(events.some(event => event.kind === "tunneled" && event.host === "frame.claudemcpcontent.com" && event.path === "/csp-artifact"),
        "the post-download artifact frame must still travel through the authenticated TLS tunnel");
      assert.ok(proxyEvents.slice(proxyStart).some(event => event.kind === "connect" && event.target === "frame.claudemcpcontent.com:443"
        && event.tokenVersion === "C" && event.tokenMatches), "downloads must use the active authenticated proxy token");
    });

    await t.test("native MAIN registration and actual TLS requests scope Basic credentials", { timeout: 20000 }, async () => {
      const registered = await worker.evaluate(() => chrome.scripting.getRegisteredContentScripts());
      assert.ok(registered.some(script => script.world === "MAIN" && script.js.includes("fingerprint.js") && script.matches.includes("https://gateway.audit.test/*")));

      const page = await context.newPage();
      await page.goto("https://gateway.audit.test/credential-probe");
      assert.equal(await page.evaluate(() => Intl.DateTimeFormat().resolvedOptions().timeZone), "UTC", "registered MAIN script must patch the actual page realm");
      assert.equal(await page.evaluate(() => navigator.language), "en-US", "registered MAIN script must patch page language");
      for (const host of [hosts[1], hosts[2], hosts[3], hosts[4]]) {
        await page.goto(`https://${host}/credential-probe`).catch(() => {});
      }
      await page.goto(`http://gateway.audit.test:${plainPort}/credential-probe`).catch(() => {});
      await page.waitForTimeout(500);
      const received = events.filter(event => event.kind === "gateway" && event.path === "/credential-probe");
      assert.equal(received.find(event => event.host === hosts[0])?.authorization, BASIC_C);
      assert.match(received.find(event => event.host === hosts[0])?.cookie || "", /browser-cookie=synthetic-browser-cookie/);
      assert.deepEqual(received.map(event => event.host), [hosts[0]], "only the exact gateway should receive a network request");
      const authMatches = await worker.evaluate(async () => {
        const urls = ["https://gateway.audit.test/", "https://gateway.audit.test.evil.test/", "https://sub.gateway.audit.test/", "https://gateway.audit.testing/", "http://gateway.audit.test/"];
        const results = [];
        for (const url of urls) {
          const result = await chrome.declarativeNetRequest.testMatchOutcome({ url, type: "main_frame" });
          results.push(result.matchedRules.some(rule => rule.ruleId === AUTH_RULE_ID));
        }
        return results;
      });
      assert.deepEqual(authMatches, [true, false, false, false, false], "the native Authorization rule must match only the exact HTTPS gateway authority");
      assert.ok(events.filter(event => event.authorization === BASIC).every(event => event.kind === "gateway" && event.host === hosts[0]), "synthetic Basic credentials must never leave the configured host");
      assert.equal(events.find(event => event.kind === "plain")?.authorization, undefined, "HTTP must never receive Basic credentials");
    });

    await t.test("session token is fetched by the extension with its native origin and installs the HTTPS PAC", { timeout: 20000 }, async () => {
      const checked = await worker.evaluate(() => healthCheck());
      const requests = events.filter(event => event.kind === "gateway").map(event => ({ path: event.path, authMatches: event.authorization === BASIC,
        sessionHeader: event.sessionHeader || null, origin: event.origin || null, hasCookie: !!event.cookie }));
      assert.equal(checked.ok, true, `secure proxy session must be obtained from the local TLS gateway fixture (${JSON.stringify({ reason: checked.reason, status: checked.status, requests })})`);
      const token = events.find(event => event.kind === "gateway" && event.path === "/__proxy-session");
      assert.ok(token, "extension must make an actual TLS token request");
      assert.equal(token.authorization, BASIC);
      assert.equal(token.sessionHeader, "1");
      assert.match(token.origin, /^chrome-extension:\/\/[a-p]{32}$/);
      assert.equal(token.cookie, undefined, "extension token requests must omit browser cookies");
      const proxySettings = await worker.evaluate(() => chrome.proxy.settings.get({ incognito: false }));
      assert.equal(proxySettings.levelOfControl, "controlled_by_this_extension");
      assert.equal(proxySettings.value.mode, "pac_script");
      assert.equal(proxySettings.value.pacScript.mandatory, true);
      assert.match(proxySettings.value.pacScript.data, /claudeusercontent\|claudemcpcontent/);
      assert.match(proxySettings.value.pacScript.data, /return "HTTPS 127\.0\.0\.1:9"/);
      const expectedPac = await worker.evaluate(({ port }) => proxyPac({ proxy: { host: "proxy.audit.test", port }, gatewayHost: "gateway.audit.test" }), { port: proxyPort });
      assert.equal(proxySettings.value.pacScript.data, expectedPac, "PAC must send only the gateway direct and unknown hosts to a mandatory dead end");
      const webrtc = await worker.evaluate(() => chrome.privacy.network.webRTCIPHandlingPolicy.get({ incognito: false }));
      assert.equal(webrtc.value, "disable_non_proxied_udp");
      assert.equal(webrtc.levelOfControl, "controlled_by_this_extension");
    });

    await t.test("artifact iframe keeps its origin while duplicate CSP policies are narrowly extended", { timeout: 30000 }, async () => {
      const page = await context.newPage();
      let unrelatedPolicy;
      let resolveArtifactCspHeaders;
      const artifactCspHeadersReady = new Promise(resolve => { resolveArtifactCspHeaders = resolve; });
      page.on("response", response => {
        if (response.url() === "https://gateway.audit.test/unrelated-csp-frame") {
          unrelatedPolicy = response.headers()["content-security-policy"];
        }
        if (response.url() === "https://frame.claudemcpcontent.com/csp-artifact") {
          response.headersArray().then(headers => resolveArtifactCspHeaders(headers.filter(header => header.name.toLowerCase() === "content-security-policy").map(header => header.value)));
        }
      });
      const readyUrl = `https://gateway.audit.test/native-debugger-ready?case=direct-${Date.now()}-${Math.random()}`;
      await page.goto(readyUrl);
      const debuggerReady = await waitForNativeGatewayTab(worker, readyUrl);
      assert.equal(debuggerReady.ready, true, `the extension debugger must attach to this exact gateway tab before its artifact iframe loads (${JSON.stringify(debuggerReady)})`);
      await page.goto("https://gateway.audit.test/csp-host");
      await page.waitForFunction(() => window.cspMessages?.some(message => message.probe === "nonce-script-ran"), null, { timeout: 15000 });
      await page.waitForFunction(() => window.cspMessages?.some(message => message.probe === "cdn-script-loaded"), null, { timeout: 15000 });
      await page.waitForFunction(() => window.cspMessages?.some(message => message.probe === "connect-fetch-rejected"), null, { timeout: 5000 });
      const artifactCspHeaders = await artifactCspHeadersReady;
      const messages = await page.evaluate(() => window.cspMessages);
      const artifactMessages = messages.filter(message => message.origin === "https://frame.claudemcpcontent.com");
      assert.ok(artifactMessages.some(message => message.probe === "nonce-script-ran"), "the original artifact frame must execute its nonce-authorized script");
      assert.ok(artifactMessages.some(message => message.probe === "cdn-script-loaded"), "the approved CDN script must load while preserving its original artifact origin");
      assert.ok(artifactMessages.some(message => message.probe === "connect-fetch-rejected"), "the second CSP policy must continue to block connect-src");
      assert.ok(artifactMessages.some(message => message.probe === "csp-violation" && message.directive === "connect-src"), "the browser must report the preserved restrictive connect-src policy");
      assert.ok(artifactMessages.some(message => message.probe === "csp-violation" && message.directive === "img-src"), "the first CSP policy must retain its image restriction");
      assert.equal(artifactMessages.some(message => message.probe === "nonce-free-script-ran"), false, "the duplicate CSP policies must continue to block inline scripts without the nonce");
      assert.equal(artifactMessages.some(message => message.probe === "connect-fetch-allowed"), false);
      const artifactFrame = page.frames().find(frame => frame.url().startsWith("https://frame.claudemcpcontent.com/csp-artifact"));
      assert.ok(artifactFrame, "the iframe must retain the artifact's original HTTPS origin");
      assert.equal(await artifactFrame.locator("#artifact-rendered").textContent(), "artifact-rendered");
      assert.equal(events.some(event => event.kind === "tunneled" && event.host === "frame.claudemcpcontent.com" && event.path === "/csp-artifact"), true,
        "the artifact response must arrive through the authenticated proxy");
      assert.equal(events.some(event => event.kind === "direct" && event.host === "frame.claudemcpcontent.com" && event.path === "/csp-artifact"), false,
        "the artifact frame must never use the direct collector");
      assert.equal(events.some(event => event.kind === "tunneled" && event.host === "cdn.tailwindcss.com" && event.path === "/csp-fixture.js"), true,
        "the artifact's approved CDN script must traverse the TLS proxy");
      assert.ok(proxyEvents.some(event => event.kind === "connect" && event.target === "cdn.tailwindcss.com:443"), "the CDN must use CONNECT through the proxy");
      assert.equal(events.some(event => event.kind === "direct" && event.host === "cdn.tailwindcss.com" && event.path === "/csp-fixture.js"), false,
        "the approved CDN request must never reach the direct collector");
      assert.equal(events.some(event => event.kind === "tunneled" && event.path === "/csp-connect-probe"), false,
        "the CSP-blocked same-origin fetch must not reach the proxy collector");
      assert.equal(events.some(event => event.kind === "tunneled" && event.path === "/csp-image-probe"), false,
        "the first policy's blocked same-origin image must not reach the proxy collector");
      assert.equal(directControlPaths.has("/csp-connect-probe"), true,
        "the direct control proves a missing connect-src restriction would be observable");
      assert.equal(directControlPaths.has("/csp-image-probe"), true,
        "the direct control proves a missing img-src restriction would be observable");
      const artifactCspText = artifactCspHeaders.join("\n");
      assert.ok(artifactCspText.includes("img-src 'none'") && artifactCspText.includes("connect-src 'none'"),
        `the rewritten response must retain both independently restrictive CSP policies (${JSON.stringify(artifactCspHeaders)})`);
      assert.ok((artifactCspText.match(/https:\/\/gateway\.audit\.test/g) || []).length >= 2,
        "the gateway ancestor must be added to each original CSP policy");
      assert.equal(events.some(event => event.kind === "gateway-unrelated-frame" && event.path === "/unrelated-csp-frame"), true,
        "the unrelated frame fixture response must be received");
      assert.equal(unrelatedPolicy, "default-src 'none'; frame-ancestors 'none'; script-src 'nonce-unrelated-frame'",
        "the debugger must leave unrelated frame response headers untouched");
      assert.equal(messages.some(message => message.probe === "unrelated-frame-script-ran"), false,
        "the unrelated frame's frame-ancestors policy must still block embedding");
    });

    await t.test("nested cross-site artifact child rewrites CSP only for the complete gateway-owned frame chain", { timeout: 30000 }, async () => {
      const page = await context.newPage();
      let childHeadersReadyResolve;
      const childHeadersReady = new Promise(resolve => { childHeadersReadyResolve = resolve; });
      page.on("response", response => {
        if (response.url() === "https://frame.claudemcpcontent.com/csp-artifact") {
          response.headersArray().then(headers => childHeadersReadyResolve(headers.filter(header => header.name.toLowerCase() === "content-security-policy").map(header => header.value)));
        }
      });
      const readyUrl = `https://gateway.audit.test/native-debugger-ready?case=nested-${Date.now()}-${Math.random()}`;
      await page.goto(readyUrl);
      const readiness = await waitForNativeGatewayTab(worker, readyUrl);
      assert.equal(readiness.ready, true, `this exact gateway tab must have a live native debugger session (${JSON.stringify(readiness)})`);
      await page.evaluate(() => {
        const frame = document.createElement("iframe");
        frame.id = "artifact-wrapper";
        frame.src = "https://wrapper.claudeusercontent.com/csp-wrapper";
        document.body.append(frame);
      });
      await page.waitForFunction(() => window.cspMessages?.some(message => message.probe === "nonce-script-ran")
        && window.cspMessages?.some(message => message.probe === "cdn-script-loaded"), null, { timeout: 15000 });
      const messages = await page.evaluate(() => window.cspMessages);
      const childMessages = messages.filter(message => message.origin === "https://frame.claudemcpcontent.com");
      assert.ok(childMessages.some(message => message.probe === "nonce-script-ran"), "the nested cross-site child must execute its original nonce script");
      assert.ok(childMessages.some(message => message.probe === "cdn-script-loaded"), "the nested child must load its approved CDN dependency");
      const wrapperFrame = page.frames().find(frame => frame.url().startsWith("https://wrapper.claudeusercontent.com/csp-wrapper"));
      const childFrame = page.frames().find(frame => frame.url().startsWith("https://frame.claudemcpcontent.com/csp-artifact"));
      assert.ok(wrapperFrame, "the intermediate artifact wrapper must remain loaded at its original origin");
      assert.ok(childFrame, "the nested artifact child must retain its original origin");
      assert.equal(await childFrame.locator("#artifact-rendered").textContent(), "artifact-rendered");
      const cspHeaders = await childHeadersReady;
      const cspText = cspHeaders.join("\n");
      assert.ok(cspText.includes("img-src 'none'") && cspText.includes("connect-src 'none'"), "both nested child CSP policies must remain active");
      assert.ok((cspText.match(/https:\/\/gateway\.audit\.test/g) || []).length >= 2,
        "the debugger must append the gateway ancestor to every child policy while preserving wrapper and Claude ancestors");
      assert.ok(events.some(event => event.kind === "tunneled" && event.host === "wrapper.claudeusercontent.com" && event.path === "/csp-wrapper"),
        "the wrapper must be retrieved through the authenticated proxy");
      assert.ok(events.some(event => event.kind === "tunneled" && event.host === "frame.claudemcpcontent.com" && event.path === "/csp-artifact"),
        "the OOPIF child response must be retrieved through the authenticated proxy");
      assert.equal(events.some(event => event.kind === "direct" && ["wrapper.claudeusercontent.com", "frame.claudemcpcontent.com"].includes(event.host)), false,
        "neither nested artifact origin may use the direct collector");
    });

    await t.test("allowed CDN intermediate and foreign root never receive gateway CSP rewriting", { timeout: 30000 }, async () => {
      const page = await context.newPage();
      let unknownHeaders = [];
      let unknownResponseResolve;
      const unknownResponseReady = new Promise(resolve => { unknownResponseResolve = resolve; });
      page.on("response", response => {
        if (response.url() === "https://frame.claudemcpcontent.com/csp-artifact-unknown-parent") {
          response.headersArray().then(headers => {
            unknownHeaders = headers.filter(header => header.name.toLowerCase() === "content-security-policy").map(header => header.value);
            unknownResponseResolve();
          });
        }
      });
      const readyUrl = `https://gateway.audit.test/native-debugger-ready?case=unknown-intermediate-${Date.now()}-${Math.random()}`;
      await page.goto(readyUrl);
      const readiness = await waitForNativeGatewayTab(worker, readyUrl);
      assert.equal(readiness.ready, true, `the exact target gateway tab must be attached before inserting its unknown intermediate (${JSON.stringify(readiness)})`);
      await installPassiveFetchObserver(worker);
      await page.evaluate(() => {
        const frame = document.createElement("iframe");
        frame.id = "artifact-wrapper";
        frame.src = "https://cdn.tailwindcss.com/csp-wrapper-unknown";
        document.body.append(frame);
      });
      await unknownResponseReady;
      await page.waitForTimeout(300);
      let messages = await page.evaluate(() => window.cspMessages);
      assert.equal(messages.some(message => message.probe === "nonce-script-ran"), false,
        "an allowed CDN wrapper is not a gateway-owned ancestor, so the child's original CSP must block it");
      assert.equal(await page.frameLocator("#artifact-wrapper").frameLocator("#blocked-artifact").locator("#artifact-rendered").count(), 0,
        "the child document must remain inaccessible because its original frame-ancestors policy blocked the navigation");
      const unknownCspText = unknownHeaders.join("\n");
      assert.ok(unknownCspText.includes("frame-ancestors https://claude.ai") && !unknownCspText.includes("https://gateway.audit.test"),
        "the artifact response beneath the CDN intermediate must retain its original frame-ancestors unchanged");
      assert.ok(events.some(event => event.kind === "tunneled" && event.host === "cdn.tailwindcss.com" && event.path === "/csp-wrapper-unknown"),
        "the allowed CDN intermediate must load through the proxy, so its child's block is caused by CSP");
      assert.ok(events.some(event => event.kind === "tunneled" && event.host === "frame.claudemcpcontent.com" && event.path === "/csp-artifact-unknown-parent"),
        "the child request under the unknown intermediate must reach the tunnel collector");
      const pausedRequests = await getPassiveFetchEvents(worker);
      assert.ok(pausedRequests.some(event => event.tabId === readiness.tabId && event.url === "https://frame.claudemcpcontent.com/csp-artifact-unknown-parent"),
        "the exact gateway tab must have intercepted the child response natively before the unchanged-CSP result is accepted");

      for (const existing of context.pages()) {
        if (new URL(existing.url()).hostname === "gateway.audit.test") await existing.goto("about:blank").catch(() => {});
      }
      const detached = await worker.evaluate(async () => {
        for (let attempt = 0; attempt < 40; attempt++) {
          const current = await status();
          if (current.artifactDebugger?.attachedTabs === 0) return current.artifactDebugger;
          await new Promise(resolve => setTimeout(resolve, 100));
        }
        return (await status()).artifactDebugger;
      });
      assert.equal(detached?.attachedTabs, 0, `all gateway-owned debugger sessions must detach before the foreign-root control (${JSON.stringify(detached)})`);
      const foreign = await context.newPage();
      const foreignResponse = new Promise(resolve => {
        foreign.on("response", response => {
          if (response.url() === "https://frame.claudemcpcontent.com/csp-artifact-unknown-parent") resolve(response.headersArray());
        });
      });
      await foreign.goto("https://cdn.tailwindcss.com/csp-foreign-root");
      const foreignChildResponse = await foreignResponse;
      await foreign.waitForTimeout(300);
      messages = await foreign.evaluate(() => window.cspMessages || []);
      assert.equal(messages.some(message => message.probe === "nonce-script-ran"), false,
        "a foreign allowed CDN top-level page must not receive gateway CSP rewriting for its child");
      assert.equal(await foreign.frameLocator("#blocked-artifact").locator("#artifact-rendered").count(), 0,
        "the foreign root's child document must remain blocked by its original frame-ancestors policy");
      const foreignHeaders = foreignChildResponse.filter(header => header.name.toLowerCase() === "content-security-policy").map(header => header.value).join("\n");
      assert.ok(foreignHeaders.includes("frame-ancestors https://claude.ai") && !foreignHeaders.includes("https://gateway.audit.test"),
        "the foreign-root artifact response must preserve its original frame-ancestors");
      const afterForeign = await worker.evaluate(() => status());
      assert.equal(afterForeign.artifactDebugger?.attachedTabs, 0, "the extension debugger must not attach to the allowed CDN top-level tab");
      assert.ok(events.some(event => event.kind === "tunneled" && event.host === "cdn.tailwindcss.com" && event.path === "/csp-foreign-root"),
        "the foreign root must be an allowed, proxy-routed CDN page rather than a blocked-host control");
      assert.equal(events.some(event => event.kind === "direct" && event.host === "frame.claudemcpcontent.com" && event.path === "/csp-artifact-unknown-parent"), false,
        "foreign-root child traffic must not reach the direct collector");
    });

    await t.test("artifact fetch CORS rewriting is origin-, method-, status-, and size-bounded", { timeout: 45000 }, async () => {
      const page = await context.newPage();
      const corsHostUrl = "https://gateway.audit.test/cors-host";
      await page.goto(corsHostUrl);
      const readiness = await waitForNativeGatewayTab(worker, corsHostUrl);
      assert.equal(readiness.ready, true, "CORS probes start only after the exact gateway tab has native debugger interception");

      const resultFor = async (path, options = {}) => page.evaluate(async ({ path, options }) => {
        try {
          const response = await fetch(`https://frame.claudemcpcontent.com${path}`, { cache: "no-store", ...options });
          if (path === "/cors/large-binary") {
            const bytes = await response.arrayBuffer();
            const digest = await crypto.subtle.digest("SHA-256", bytes);
            return { resolved: true, status: response.status, bytes: bytes.byteLength,
              sha256: [...new Uint8Array(digest)].map(value => value.toString(16).padStart(2, "0")).join("") };
          }
          return { resolved: true, status: response.status, body: await response.text() };
        } catch (error) { return { resolved: false, errorName: error?.name || "Error" }; }
      }, { path, options });
      const tunnelRequests = path => events.filter(event => event.kind === "tunneled" && event.path === path);
      const assertNoCredentialLeak = request => {
        assert.equal(request.authorization, undefined, "gateway Basic credentials must never be sent to an artifact origin");
        assert.equal(request.cookie, undefined, "gateway browser cookies must not be sent to an artifact origin");
        assert.equal(request.hasProxyAuthorization, false, "proxy credentials must remain on the client-to-proxy connection");
      };
      const expectOrigin = (path, expected) => {
        const requests = tunnelRequests(path);
        assert.ok(requests.length > 0, `the synthetic tunnel collector must receive ${path}`);
        assert.ok(requests.some(request => request.origin === expected), `request Origin for ${path} must be ${expected}`);
        for (const request of requests) assertNoCredentialLeak(request);
        assert.equal(events.some(event => event.kind === "direct" && event.path === path), false, `${path} must not bypass the authenticated proxy`);
      };

      const positive = await resultFor("/cors/positive");
      assert.deepEqual(positive, { resolved: true, status: 200, body: "synthetic-cors-ok-001" },
        `a matching upstream CORS response must become readable to the exact gateway page (${JSON.stringify({
          readiness,
          collector: tunnelRequests("/cors/positive").map(({ method, origin, host, path }) => ({ method, origin, host, path })),
          passiveFetch: (await getPassiveFetchEvents(worker)).filter(event => event.tabId === readiness.tabId
            && event.url === "https://frame.claudemcpcontent.com/cors/positive").map(({ resourceType, status, statusTextState, accessControlAllowOrigin }) => ({
              resourceType, status, statusTextState, accessControlAllowOrigin,
            })),
        })})`);
      expectOrigin("/cors/positive", "https://claude.ai");
      const positiveRepeat = await resultFor("/cors/positive");
      assert.deepEqual(positiveRepeat, positive, "a second request to the same no-store artifact URL must remain compatible");
      expectOrigin("/cors/positive", "https://claude.ai");

      const nativeDownloadPromise = page.waitForEvent("download", { timeout: 12000 });
      const blobPreparation = await page.evaluate(async () => {
        const response = await fetch("https://frame.claudemcpcontent.com/cors/html-export", { cache: "no-store" });
        if (!response.ok) return { fetched: false, status: response.status };
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement("a");
        anchor.href = url;
        anchor.download = "synthetic-cors-export.html";
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
        setTimeout(() => URL.revokeObjectURL(url), 5000);
        return { fetched: true, status: response.status, blobBytes: blob.size, blobType: blob.type };
      });
      assert.deepEqual(blobPreparation, { fetched: true, status: 200, blobBytes: CORS_HTML_EXPORT.length, blobType: "text/html" },
        "the transformed response must become an HTML Blob before the browser download is triggered");
      const nativeDownload = await nativeDownloadPromise;
      assert.equal(nativeDownload.suggestedFilename(), "synthetic-cors-export.html", "the native download must preserve the synthetic HTML filename");
      assert.equal(await nativeDownload.failure(), null, "the browser must complete the Blob download");
      const nativeDownloadPath = await nativeDownload.path();
      assert.ok(nativeDownloadPath, "the native download must be saved in the isolated Playwright context");
      let nativeDownloadedBytes;
      try {
        fs.chmodSync(nativeDownloadPath, 0o600);
        nativeDownloadedBytes = fs.readFileSync(nativeDownloadPath);
      } finally { try { fs.unlinkSync(nativeDownloadPath); } catch {} }
      assert.ok(nativeDownloadedBytes.equals(CORS_HTML_EXPORT), "fetch-to-Blob-to-download must preserve every HTML byte");
      assert.equal(crypto.createHash("sha256").update(nativeDownloadedBytes).digest("hex"), CORS_HTML_EXPORT_SHA256,
        "downloaded HTML bytes must match the expected synthetic fixture hash");
      expectOrigin("/cors/html-export", "https://claude.ai");

      const h2Fetch = await page.evaluate(async () => {
        try {
          const response = await fetch("https://h2.frame.claudemcpcontent.com/cors/h2-export", { cache: "no-store" });
          const blob = await response.blob();
          window.__syntheticH2ExportBlob = blob;
          return { resolved: true, status: response.status, blobBytes: blob.size, blobType: blob.type };
        } catch (error) { return { resolved: false, errorName: error?.name || "Error" }; }
      });
      assert.deepEqual(h2Fetch, { resolved: true, status: 200, blobBytes: CORS_H2_EXPORT.length, blobType: "text/html" },
        "HTTP/2 ACAO response must remain readable before it can be exported as a Blob");
      assert.ok(h2Sessions.some(session => session.alpnProtocol === "h2"), "the fixture must negotiate real TLS ALPN h2, not HTTP/1.1 fallback");
      const h2Request = events.find(event => event.kind === "tunneled-h2" && event.path === "/cors/h2-export");
      assert.ok(h2Request, "HTTP/2 artifact request must reach its isolated TLS endpoint through the proxy");
      assert.equal(h2Request.origin, "https://claude.ai", "the HTTP/2 request Origin must be narrowly rewritten");
      assert.equal(h2Request.authorization, undefined);
      assert.equal(h2Request.cookie, undefined);
      assert.equal(h2Request.hasProxyAuthorization, false);
      assert.equal(events.some(event => event.kind === "direct" && event.path === "/cors/h2-export"), false,
        "HTTP/2 artifact requests must not escape the mandatory proxy");
      const h2ResponseEvent = (await getPassiveFetchEvents(worker)).find(event => event.tabId === readiness.tabId
        && event.url === "https://h2.frame.claudemcpcontent.com/cors/h2-export" && event.status === 200);
      assert.ok(h2ResponseEvent, "the exact gateway-owned browser request must receive a native Fetch response event");
      assert.equal(h2ResponseEvent.statusTextState, "empty", "HTTP/2 must exercise Chromium's empty response-status-text case");

      const h2DownloadPromise = page.waitForEvent("download", { timeout: 12000 });
      await page.evaluate(() => {
        const anchor = document.createElement("a");
        anchor.href = URL.createObjectURL(window.__syntheticH2ExportBlob);
        anchor.download = "synthetic-http2-cors-export.html";
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
      });
      const h2Download = await h2DownloadPromise;
      assert.equal(h2Download.suggestedFilename(), "synthetic-http2-cors-export.html");
      assert.equal(await h2Download.failure(), null);
      const h2DownloadPath = await h2Download.path();
      assert.ok(h2DownloadPath);
      let h2DownloadedBytes;
      try { fs.chmodSync(h2DownloadPath, 0o600); h2DownloadedBytes = fs.readFileSync(h2DownloadPath); }
      finally { try { fs.unlinkSync(h2DownloadPath); } catch {} }
      assert.ok(h2DownloadedBytes.equals(CORS_H2_EXPORT), "HTTP/2 CORS fetch-to-Blob download must preserve exact HTML bytes");
      assert.equal(crypto.createHash("sha256").update(h2DownloadedBytes).digest("hex"), CORS_H2_EXPORT_SHA256);

      const head = await resultFor("/cors/head", { method: "HEAD" });
      assert.equal(head.resolved, true, "an approved HEAD response must pass the same narrow CORS path");
      assert.equal(head.status, 200);
      expectOrigin("/cors/head", "https://claude.ai");

      const large = await resultFor("/cors/large-binary");
      assert.deepEqual(large, { resolved: true, status: 200, bytes: CORS_LARGE_FIXTURE.length, sha256: CORS_LARGE_SHA256 },
        "a binary response larger than the CSP rewrite cap must stream byte-for-byte with only its ACAO header changed");
      expectOrigin("/cors/large-binary", "https://claude.ai");

      for (const path of ["/cors/no-acao", "/cors/wrong-acao", "/cors/duplicate-acao", "/cors/redirect"]) {
        const rejected = await resultFor(path);
        assert.equal(rejected.resolved, false, `${path} must not receive a synthesized CORS permission`);
        expectOrigin(path, "https://claude.ai");
      }
      assert.equal(tunnelRequests("/cors/redirect-target").length, 0, "redirect responses must not be followed under the CORS rewrite path");

      const post = await resultFor("/cors/post", { method: "POST", headers: { "content-type": "text/plain" }, body: "synthetic-post" });
      assert.equal(post.resolved, false, "non-GET/HEAD methods must remain outside the compatibility path");
      expectOrigin("/cors/post", "https://gateway.audit.test");

      const customPortUrl = `https://frame.claudemcpcontent.com:${tunnelPort}/cors/custom-port`;
      const customPort = await page.evaluate(async url => {
        try { const response = await fetch(url, { cache: "no-store" }); return { resolved: true, status: response.status, body: await response.text() }; }
        catch (error) { return { resolved: false, errorName: error?.name || "Error" }; }
      }, customPortUrl);
      assert.equal(customPort.resolved, false, "non-default artifact ports must not be granted gateway CORS compatibility");
      const customRequests = tunnelRequests("/cors/custom-port");
      if (customRequests.length > 0) {
        assert.ok(customRequests.every(request => request.origin === "https://gateway.audit.test"), "custom-port Origin must remain unchanged");
      }
      for (const request of customRequests) assertNoCredentialLeak(request);
      assert.equal(events.some(event => event.kind === "direct" && event.path === "/cors/custom-port"), false);

      await page.evaluate(() => {
        const frame = document.createElement("iframe");
        frame.id = "cors-foreign-frame";
        frame.src = "https://cdn.tailwindcss.com/cors-foreign-frame";
        document.body.appendChild(frame);
      });
      await page.waitForFunction(() => window.corsProbeResults?.some(result => result.kind === "cors-foreign-result"), null, { timeout: 10000 });
      const foreignResult = await page.evaluate(() => window.corsProbeResults.find(result => result.kind === "cors-foreign-result"));
      assert.deepEqual(foreignResult, { kind: "cors-foreign-result", ok: false }, "a foreign CDN frame must not inherit gateway CORS compatibility");
      expectOrigin("/cors/foreign-frame", "https://cdn.tailwindcss.com");
      assert.ok(proxyEvents.some(event => event.kind === "connect" && event.target === "frame.claudemcpcontent.com:443" && event.tokenMatches),
        "CORS artifact requests must still use the authenticated mandatory TLS proxy");
    });

    await t.test("allowlisted artifact traffic traverses the authenticated TLS proxy", { timeout: 30000 }, async () => {
      const page = await context.newPage();
      await page.goto("https://gateway.audit.test/");
      const frameUrl = "https://unknown.claudeusercontent.com/proxied-artifact";
      const fetched = await page.evaluate(async url => {
        try { await fetch(url, { mode: "no-cors" }); return true; }
        catch (_) { return false; }
      }, frameUrl);
      assert.equal(fetched, true, `authenticated TLS proxy should carry the request (${JSON.stringify(proxyEvents.map(event => ({ kind: event.kind, target: event.target, tokenMatches: event.tokenMatches, hasProxyAuthorization: event.hasProxyAuthorization })))})`);
      const request = events.find(event => event.kind === "tunneled" && event.path === "/proxied-artifact");
      assert.ok(request, "proxied request reaches the tunnel-only synthetic collector");
      assert.equal(events.some(event => event.kind === "direct" && event.path === "/proxied-artifact"), false, "allowlisted traffic must never go straight to the direct collector");
      assert.ok(proxyEvents.some(event => event.kind === "connect" && event.target === "unknown.claudeusercontent.com:443" && event.tokenMatches), "proxy challenge must be answered with the session token");
      assert.equal(request.authorization, undefined, "gateway Basic credentials must not leak through the tunnel");
      assert.equal(request.origin, undefined);

      await close(proxy);
      const offline = await context.newPage();
      await offline.goto("https://unknown.claudeusercontent.com/proxy-offline-probe", { timeout: 5000 }).catch(() => {});
      await offline.waitForTimeout(500);
      assert.equal(events.some(event => event.kind === "direct" && event.path === "/proxy-offline-probe"), false,
        "a disconnected mandatory TLS proxy must fail without a direct fallback");
      assert.equal(events.some(event => event.kind === "tunneled" && event.path === "/proxy-offline-probe"), false,
        "the disconnected proxy must not deliver the new request");
    });

    await t.test("session outage blocks direct collector egress, including opaque frames and main-frame navigation", { timeout: 20000 }, async () => {
      proxySessionStatus = 503;
      const unhealthy = await worker.evaluate(async () => { invalidate(); return healthCheck(); });
      assert.equal(unhealthy.ok, false, "a failed token tunnel request must be unhealthy");
      assert.equal(await worker.evaluate(async () => (await chrome.proxy.settings.get({ incognito: false })).value.mode), "system", "outage must remove the session PAC");
      const before = events.filter(event => event.kind === "direct").length;
      const page = await context.newPage();
      await page.goto("https://gateway.audit.test/egress-probes");
      await page.waitForFunction(() => document.documentElement.dataset.opaqueFrameStarted === "true", null, { timeout: 5000 });
      await page.locator("#popup-probe").click();
      await page.waitForTimeout(1200);
      const afterSubresource = events.filter(event => event.kind === "direct").length;
      assert.equal(afterSubresource, before, "unknown egress and sandboxed opaque-frame requests must not reach a direct collector");
      assert.equal(events.some(event => event.kind === "direct" && event.path === "/popup-probe"), false, "pop-up main-frame navigation must not reach a direct collector");
      await page.evaluate(() => window.runMainFrameProbe());
      await page.waitForTimeout(1200);
      const direct = events.filter(event => event.kind === "direct");
      assert.equal(direct.length, before, "main-frame navigation from the gateway must not fall back to a direct connection");
      const unrelated = await context.newPage();
      await unrelated.goto("https://evil.audit.test/unrelated-profile-probe").catch(() => {});
      await unrelated.waitForTimeout(300);
      assert.equal(events.some(event => event.kind === "direct" && event.path === "/unrelated-profile-probe"), false, "the isolated profile must block unrelated direct egress too");
    });
  } finally {
    if (context) await context.close();
    await Promise.all([close(gateway), close(plain), close(directCollector), close(tunnelCollector), close(h2Collector), close(proxy)]);
    fs.rmSync(temp, { recursive: true, force: true });
  }
});
