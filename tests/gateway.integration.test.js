// Real HTTP streams around the gateway; the HTTPS transport alone is redirected
// to an isolated local upstream. No Claude account or external network is used.
const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const https = require("node:https");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const extensionVersion = require("../extension/manifest.chrome.json").version;

const pdfFixture = Buffer.concat([Buffer.from("%PDF-1.7\n"), Buffer.from(Array.from({ length: 4096 }, (_, i) => i % 256)), Buffer.from("\n%%EOF")]);
const scriptFixture = Buffer.from('const asset = "https://assets.claude.ai/synthetic.js";');
const pdfDisposition = "attachment; filename=synthetic.pdf; filename*=UTF-8''synthetic-%D1%82.pdf";
const sha256 = body => crypto.createHash("sha256").update(body).digest("hex");
const redirectFixtures = {
  root: { location: "/download.pdf?signature=synthetic" },
  parent: { location: "../download.pdf?signature=synthetic" },
  query: { location: "?signature=synthetic" },
  scheme: { location: "//assets.claude.ai/download.pdf?signature=synthetic" },
  main: { status: 307, location: "https://claude.ai/download.pdf?signature=synthetic" },
  www: { status: 308, location: "https://www.claude.ai/download.pdf?signature=synthetic" },
  canonical: { location: "https://ASSETS.CLAUDE.AI:443/download.pdf?signature=synthetic" },
  signed: { location: "/download.pdf?signature=synthetic%2B%2F%3D&encoded=%252F#synthetic-page" },
  artifact: { location: "https://synthetic.claudeusercontent.com/download.pdf?signature=synthetic" },
  external: { location: "https://example.test/download.pdf" },
  lookalike: { location: "https://assets.claude.ai.example.test/download.pdf" },
  userinfo: { location: "https://synthetic@assets.claude.ai/download.pdf" },
};

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "gateway-integration-"));
process.env.COOKIES_DIR = dir;
process.env.PUBLIC_HOST = "gateway.example.test";
const gateway = require("../gateway/gateway.js");
const originalRequest = https.request;
let upstream, server, port;

function listen(s) { return new Promise(resolve => s.listen(0, "127.0.0.1", resolve)); }
function request(url, options = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: "127.0.0.1", port, path: url, method: options.method || "GET", headers: options.headers }, res => {
      const chunks = [];
      res.on("data", chunk => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
      res.on("error", reject);
    });
    req.setTimeout(2000, () => req.destroy(new Error("test request timed out")));
    req.on("error", reject);
    for (const chunk of options.chunks || []) req.write(chunk);
    req.end();
  });
}

test.before(async () => {
  upstream = http.createServer((req, res) => {
    if (req.url.startsWith("/redirect/")) {
      const fixture = redirectFixtures[req.url.slice("/redirect/".length)];
      res.writeHead(fixture.status || 302, { location: fixture.location }); res.end();
    } else if (req.url === "/download-pdf") {
      const headers = { "content-type": "application/pdf", "content-disposition": pdfDisposition,
        "accept-ranges": "bytes", etag: '"synthetic-pdf-etag"', "cache-control": "private, no-store",
        "x-test-received-range": req.headers.range || "none", "x-test-received-if-range": req.headers["if-range"] || "none" };
      const range = /^bytes=(\d+)-(\d*)$/.exec(req.headers.range || "");
      if (range) {
        const start = Number(range[1]), end = range[2] ? Number(range[2]) : pdfFixture.length - 1;
        if (start >= pdfFixture.length || end < start) {
          res.writeHead(416, { ...headers, "content-range": "bytes */" + pdfFixture.length, "content-length": 0 }); return res.end();
        }
        const body = pdfFixture.subarray(start, Math.min(end + 1, pdfFixture.length));
        res.writeHead(206, { ...headers, "content-length": body.length, "content-range": `bytes ${start}-${start + body.length - 1}/${pdfFixture.length}` }); return res.end(body);
      }
      res.writeHead(200, { ...headers, "content-length": pdfFixture.length }); res.end(pdfFixture);
    } else if (["/download-script", "/ranged-script", "/ignored-script-range", "/content-range-script"].includes(req.url)) {
      const ranged = req.url === "/ranged-script" || req.url === "/content-range-script";
      res.writeHead(req.url === "/ranged-script" ? 206 : 200, { "content-type": "application/javascript", "content-length": scriptFixture.length,
        ...(req.url === "/download-script" ? { "content-disposition": 'AtTaChMeNt ; filename="synthetic.js"' } : {}),
        ...(ranged ? { "content-range": `bytes 0-${scriptFixture.length - 1}/1000` } : {}) }); res.end(scriptFixture);
    } else if (req.url === "/upload-binary") {
      const hash = crypto.createHash("sha256"); let bytes = 0;
      req.on("data", chunk => { bytes += chunk.length; hash.update(chunk); });
      req.on("end", () => { res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ bytes, sha256: hash.digest("hex"), contentType: req.headers["content-type"], contentLength: req.headers["content-length"] || null })); });
    } else if (req.url === "/reset-html" || req.url === "/reset-stream") {
      res.writeHead(200, { "content-type": req.url === "/reset-html" ? "text/html" : "text/event-stream" });
      res.write("synthetic partial response");
      setTimeout(() => res.socket.destroy(), 20);
    } else if (req.url === "/upload") {
      let bytes = 0;
      req.on("data", chunk => bytes += chunk.length);
      req.on("end", () => { res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ bytes })); });
    } else if (req.url === "/headers") {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(req.headers));
    } else if (req.url === "/too-large") {
      res.setHeader("content-type", "application/javascript");
      res.end(Buffer.alloc(4096, "x"));
    } else if (req.url === "/capture") {
      res.writeHead(200, { "content-type": "application/json", "set-cookie": "sessionKey=synthetic-session; Path=/; HttpOnly; Max-Age=3600" });
      res.end("{}");
    } else {
      res.writeHead(200, {
        "content-type": "text/html", connection: "keep-alive, x-hop-private", "x-hop-private": "hop-only",
        "set-cookie": "synthetic=private; HttpOnly", "report-to": "{}", nel: "{}", "alt-svc": 'h3=":443"',
      });
      res.write('<html><script src="https://assets.claude.ai/app.js">');
      setImmediate(() => res.end("</script></html>"));
    }
  });
  await listen(upstream);
  https.request = (options, callback) => originalHttpRequest(options, callback);
  server = gateway.createServer();
  await listen(server);
  port = server.address().port;
});

function originalHttpRequest(options, callback) {
  return http.request({ ...options, hostname: "127.0.0.1", port: upstream.address().port }, callback);
}

test.after(async () => {
  https.request = originalRequest;
  for (const s of [server, upstream]) {
    s.closeAllConnections();
    await new Promise(resolve => s.close(resolve));
  }
  fs.rmSync(dir, { recursive: true, force: true });
});

test("chunked upstream HTML is rewritten with valid framing and private headers removed", async () => {
  const response = await request("/chunked-html");
  assert.equal(response.status, 200);
  assert.match(response.body.toString(), /https:\/\/gateway\.example\.test\/p\/assets\.claude\.ai\/app\.js/);
  assert.equal(Number(response.headers["content-length"]), response.body.length);
  for (const name of ["transfer-encoding", "x-hop-private", "set-cookie", "report-to", "nel", "alt-svc"]) assert.equal(response.headers[name], undefined, name);
});

test("artifact HTML cannot execute on the gateway origin through the reverse proxy", async () => {
  for (const host of ["claudeusercontent.com", "attacker.claudeusercontent.com", "claudemcpcontent.com", "attacker.claudemcpcontent.com"]) {
    const response = await request("/p/" + host + "/artifact");
    assert.equal(response.status, 403, host);
    assert.equal(response.body.toString(), "not allowed");
    await new Promise((resolve, reject) => {
      const req = http.request({ hostname: "127.0.0.1", port, path: "/p/" + host + "/socket", headers: { connection: "Upgrade", upgrade: "websocket" } }, res => {
        assert.equal(res.statusCode, 403, host); res.resume(); res.once("end", resolve);
      });
      req.once("upgrade", (_res, socket) => { socket.destroy(); reject(new Error("artifact WebSocket upgraded")); });
      req.on("error", reject); req.end();
    });
  }
});

test("extension download page describes setup and only links an available signed XPI", async () => {
  const previous = gateway.cfg.extDir;
  const xpi = path.join(dir, "gateway-connector-firefox.xpi");
  gateway.cfg.extDir = dir;
  try {
    const page = async () => (await request("/__ext/", { headers: { "x-remote-user": "test-user" } })).body.toString();
    const absent = await page();
    for (const text of ["расширение " + extensionVersion, "≥ 125", "≥ 140", "Options", "не привязаны к домену", "во всём профиле", "fail-closed", "hard reload", "debugger", "баннер отладки", "DevTools"]) assert.ok(absent.includes(text), text);
    assert.doesNotMatch(absent, /href="\/__ext\/gateway-connector-firefox\.xpi"/);
    fs.writeFileSync(xpi, "synthetic signed package fixture");
    assert.match(await page(), /href="\/__ext\/gateway-connector-firefox\.xpi"/);
  } finally { gateway.cfg.extDir = previous; fs.rmSync(xpi, { force: true }); }
});

test("session cookie is stored server-side and never returned to the browser", async () => {
  const response = await request("/capture", { headers: { "x-remote-user": "test-user" } });
  assert.equal(response.headers["set-cookie"], undefined);
  assert.equal(gateway.sessionState("test-user"), "ok");
  assert.equal(fs.statSync(path.join(dir, "test-user.json")).mode & 0o777, 0o600);
});

test("real proxied requests strip client identity and never send a session to asset hosts", async () => {
  const headers = {
    "x-remote-user": "test-user", authorization: "Basic synthetic", cookie: "browser=synthetic", "x-gateway-previous-proxy-token": "synthetic-previous-token",
    "x-forwarded-for": "192.0.2.8", "cf-connecting-ip": "192.0.2.8", "x-real-ip": "192.0.2.8",
    connection: "x-hop-private", "x-hop-private": "hop-only",
  };
  for (const url of ["/headers", "/p/assets.claude.ai/headers"]) {
    const response = await request(url, { headers });
    const sent = JSON.parse(response.body);
    for (const name of ["authorization", "x-remote-user", "x-gateway-previous-proxy-token", "x-forwarded-for", "cf-connecting-ip", "x-real-ip", "x-hop-private"]) assert.equal(sent[name], undefined, name);
    if (url === "/headers") assert.match(sent.cookie, /^sessionKey=/);
    else assert.equal(sent.cookie, undefined);
  }
});

test("large uploads stream through without losing chunks", async () => {
  const chunks = Array.from({ length: 24 }, () => Buffer.alloc(128 * 1024, 0x61));
  const response = await request("/upload", { method: "POST", chunks, headers: { "content-type": "application/octet-stream" } });
  assert.equal(response.status, 200);
  assert.equal(JSON.parse(response.body).bytes, 3 * 1024 * 1024);
});

test("PDF downloads preserve exact binary bytes, attachment metadata and HEAD length", async () => {
  const previous = gateway.cfg.maxRewriteBytes; gateway.cfg.maxRewriteBytes = 32;
  try {
    const response = await request("/download-pdf");
    assert.equal(response.status, 200);
    assert.deepEqual(response.body, pdfFixture);
    assert.equal(response.headers["content-length"], String(pdfFixture.length));
    assert.equal(response.headers["content-disposition"], pdfDisposition);
    assert.equal(response.headers["cache-control"], "private, no-store");
    const head = await request("/download-pdf", { method: "HEAD" });
    assert.equal(head.status, 200); assert.equal(head.body.length, 0);
    for (const header of ["content-length", "content-type", "content-disposition", "etag", "accept-ranges"]) assert.equal(head.headers[header], response.headers[header]);
  } finally { gateway.cfg.maxRewriteBytes = previous; }
});

test("PDF Range and If-Range pass upstream with exact 206 and 416 metadata", async () => {
  const range = "bytes=7-130", validator = '"synthetic-pdf-etag"';
  const partial = await request("/download-pdf", { headers: { range, "if-range": validator } });
  assert.equal(partial.status, 206); assert.deepEqual(partial.body, pdfFixture.subarray(7, 131));
  assert.equal(partial.headers["content-length"], "124");
  assert.equal(partial.headers["content-range"], `bytes 7-130/${pdfFixture.length}`);
  assert.equal(partial.headers["content-disposition"], pdfDisposition);
  assert.equal(partial.headers["accept-ranges"], "bytes"); assert.equal(partial.headers.etag, validator);
  assert.equal(partial.headers["x-test-received-range"], range); assert.equal(partial.headers["x-test-received-if-range"], validator);
  const unsatisfiable = await request("/download-pdf", { headers: { range: "bytes=" + pdfFixture.length + "-" } });
  assert.equal(unsatisfiable.status, 416); assert.equal(unsatisfiable.body.length, 0);
  assert.equal(unsatisfiable.headers["content-range"], "bytes */" + pdfFixture.length);
});

test("PDF and multipart uploads preserve hashes, lengths and multipart boundaries", async () => {
  const boundary = "synthetic-upload-boundary";
  const multipart = Buffer.concat([Buffer.from('--' + boundary + '\r\nContent-Disposition: form-data; name="file"; filename="synthetic.pdf"\r\nContent-Type: application/pdf\r\n\r\n'), pdfFixture, Buffer.from("\r\n--" + boundary + "--\r\n")]);
  for (const [body, contentType, fixedLength] of [[pdfFixture, "application/pdf", true], [multipart, "multipart/form-data; boundary=" + boundary, false]]) {
    const response = await request("/upload-binary", { method: "POST", headers: { "content-type": contentType, ...(fixedLength ? { "content-length": body.length } : {}) }, chunks: [body.subarray(0, 17), body.subarray(17, 129), body.subarray(129)] });
    assert.equal(response.status, 200);
    const uploaded = JSON.parse(response.body);
    assert.deepEqual(uploaded, { bytes: body.length, sha256: sha256(body), contentType, contentLength: fixedLength ? String(body.length) : null });
  }
});

test("download attachments and ranged text responses are never rewritten", async () => {
  for (const [url, headers, expectedStatus] of [["/download-script", {}, 200], ["/ranged-script", {}, 206], ["/ignored-script-range", { range: "bytes=0-" }, 200], ["/content-range-script", {}, 200]]) {
    const response = await request(url, { headers });
    assert.equal(response.status, expectedStatus); assert.deepEqual(response.body, scriptFixture);
    assert.equal(response.headers["content-length"], String(scriptFixture.length));
    if (url === "/ranged-script" || url === "/content-range-script") assert.equal(response.headers["content-range"], `bytes 0-${scriptFixture.length - 1}/1000`);
  }
  const head = await request("/ignored-script-range", { method: "HEAD" });
  assert.equal(head.body.length, 0); assert.equal(head.headers["content-length"], String(scriptFixture.length));
});

test("download redirects preserve source hosts, signed queries and redirect status", async () => {
  const base = "https://gateway.example.test";
  for (const [name, expected] of Object.entries({ root: base + "/p/assets.claude.ai/download.pdf?signature=synthetic", parent: base + "/p/assets.claude.ai/download.pdf?signature=synthetic", query: base + "/p/assets.claude.ai/redirect/query?signature=synthetic", scheme: base + "/p/assets.claude.ai/download.pdf?signature=synthetic", canonical: base + "/p/assets.claude.ai/download.pdf?signature=synthetic", signed: base + "/p/assets.claude.ai" + redirectFixtures.signed.location, main: base + "/download.pdf?signature=synthetic", www: base + "/p/www.claude.ai/download.pdf?signature=synthetic" })) {
    const response = await request("/p/assets.claude.ai/redirect/" + name);
    assert.equal(response.status, redirectFixtures[name].status || 302);
    assert.equal(response.headers.location, expected, name);
  }
  for (const name of ["artifact", "external", "lookalike", "userinfo"]) {
    const response = await request("/p/assets.claude.ai/redirect/" + name);
    assert.equal(response.headers.location, redirectFixtures[name].location, name);
  }
  assert.equal((await request("/redirect/root")).headers.location, base + "/download.pdf?signature=synthetic");
});

test("rewrite size limit returns 502 without leaving a pending response", async () => {
  const previous = gateway.cfg.maxRewriteBytes;
  gateway.cfg.maxRewriteBytes = 1024;
  try { assert.equal((await request("/too-large")).status, 502); }
  finally { gateway.cfg.maxRewriteBytes = previous; }
});

test("upstream resets finish buffered responses and abort incomplete streams", async () => {
  assert.equal((await request("/reset-html")).status, 502);
  await assert.rejects(request("/reset-stream"), error => error.code === "ECONNRESET");
});

test("malformed jar and migration errors never log input excerpts", () => {
  const marker = "SYNTHETIC_SECRET_CANARY";
  fs.writeFileSync(path.join(dir, "malformed.json"), marker);
  const captured = [], previousError = console.error, previousKey = gateway.cfg.cookiesKey;
  console.error = (...args) => captured.push(args.join(" "));
  try {
    gateway.loadJar("malformed");
    gateway.cfg.cookiesKey = Buffer.alloc(32, 1);
    gateway.migrateAll();
    assert.equal(captured.length, 2);
    assert.ok(captured.every(line => !line.includes(marker)));
    assert.ok(captured.every(line => line.endsWith("invalid JSON")));
  } finally { console.error = previousError; gateway.cfg.cookiesKey = previousKey; }
});
