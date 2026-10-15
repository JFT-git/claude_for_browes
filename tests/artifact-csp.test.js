"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const helper = require("../extension/artifact-csp.js");
const HOST = "gateway.example.test:8443";
const ORIGIN = "https://" + HOST;
const context = extra => ({ requestUrl: "https://id.frame.claudeusercontent.com/frame", parentUrl: ORIGIN + "/chat", isSubframe: true, resourceType: "Document", statusCode: 200, responseHeaders: [{ name: "Content-Type", value: "text/html" }, { name: "Content-Security-Policy", value: "default-src 'self'; script-src 'nonce-freshA'; frame-ancestors 'self' https://claude.ai/; connect-src 'none'" }], ...extra });
const event = extra => ({ requestId: "frame-request", request: { url: context().requestUrl }, resourceType: "Document", responseStatusCode: 200, responseHeaders: context().responseHeaders, ...extra });

function transport({ request = event(), replies = [{ data: Buffer.from("<script nonce='freshA'>ok()</script>").toString("base64"), base64Encoded: true, eof: true }], isCurrent } = {}) {
  const calls = [];
  const sendCommand = async (source, method, params) => {
    calls.push({ method, params });
    if (method === "Fetch.takeResponseBodyAsStream") return { stream: "body-stream" };
    if (method === "IO.read") return replies.shift();
    return {};
  };
  return { calls, run: () => helper.fulfillPausedResponse({ source: { tabId: 7 }, event: request, gatewayHost: HOST, parentUrl: ORIGIN + "/chat", isSubframe: true, sendCommand, isCurrent }) };
}

test("only frame-ancestors gains exact gateway; nonce and separate restrictive CSP survive", () => {
  const first = "default-src 'none'; script-src 'nonce-freshA'; frame-ancestors 'self' https://claude.ai/; connect-src 'none'";
  const second = "script-src 'none'; frame-ancestors https://*.claude.ai/; sandbox allow-scripts";
  const headers = [{ name: "Content-Security-Policy", value: first }, { name: "content-security-policy", value: second }, { name: "Set-Cookie", value: "a=one; Secure" }, { name: "Set-Cookie", value: "b=two; Secure" }, { name: "X-Frame-Options", value: "SAMEORIGIN" }];
  const changed = helper.rewriteHeaders(context({ responseHeaders: headers }), HOST);
  assert.deepEqual(changed, [
    { name: "Content-Security-Policy", value: first.replace("https://claude.ai/", "https://claude.ai/ " + ORIGIN) },
    { name: "content-security-policy", value: second.replace("https://*.claude.ai/", "https://*.claude.ai/ " + ORIGIN) },
    headers[2], headers[3]
  ]);
  assert.equal(headers[0].value, first, "source header object must not be mutated");
});

test("comma policies and report-only keep all other bytes and directive boundaries", () => {
  const value = "default-src 'none';FRAME-ANCESTORS\thttps://claude.ai,script-src 'nonce-randomB'; frame-ancestors https://*.claude.ai/; form-action 'none'";
  const changed = helper.appendGatewayAncestor(value, ORIGIN);
  assert.equal(changed, value.replace("https://claude.ai,", "https://claude.ai " + ORIGIN + ",").replace("https://*.claude.ai/;", "https://*.claude.ai/ " + ORIGIN + ";"));
  assert.equal(helper.appendGatewayAncestor(changed, ORIGIN), changed);
  assert.equal(helper.appendGatewayAncestor("script-src 'nonce-frame-ancestors'; report-uri https://logs.test/frame-ancestors", ORIGIN), "script-src 'nonce-frame-ancestors'; report-uri https://logs.test/frame-ancestors");
  assert.throws(() => helper.appendGatewayAncestor("frame-ancestors https://claude.ai,,script-src 'none'", ORIGIN), /Invalid CSP/);
  assert.throws(() => helper.appendGatewayAncestor("frame-ancestors", ORIGIN), /Invalid CSP/);
  assert.throws(() => helper.appendGatewayAncestor("frame-ancestors https://claude.ai ???", ORIGIN), /Invalid CSP/);
  assert.throws(() => helper.appendGatewayAncestor("frame-ancestors https://claude.ai 'unsafe-inline'", ORIGIN), /Invalid CSP/);
  const result = helper.rewriteHeaders(context({ responseHeaders: [{ name: "Content-Security-Policy-Report-Only", value }] }), HOST);
  assert.equal(result[0].value, changed);
});

test("unrelated ancestor constraints and unsupported response contexts are left intact", () => {
  for (const policy of ["frame-ancestors 'none'", "frame-ancestors 'self' https://other.test", "frame-ancestors https://claude.ai.attacker.test", "frame-ancestors http://claude.ai", "frame-ancestors https://claude.ai/specific/"]) assert.equal(helper.appendGatewayAncestor(policy, ORIGIN), policy);
  for (const extra of [
    { parentUrl: "https://gateway.example.test/" }, { parentUrl: "https://sub.gateway.example.test:8443/" },
    { parentUrl: "http://" + HOST + "/" }, { requestUrl: "https://cdn.jsdelivr.net/asset" },
    { requestUrl: "https://id.frame.claudeusercontent.com.attacker.test/" }, { requestUrl: "https://id.frame.claudeusercontent.com:9443/" },
    { isSubframe: false }, { resourceType: "Script" }, { statusCode: 302 }, { statusCode: 206 }, { statusCode: 404 }
  ]) assert.equal(helper.rewriteHeaders(context(extra), HOST), null, JSON.stringify(extra));
});

test("streamed explicit body preserves content and CSP while normalizing transport metadata", async () => {
  const fixture = transport({ request: event({ responseHeaders: [...context().responseHeaders, { name: "Content-Encoding", value: "gzip" }, { name: "Content-Length", value: "42" }, { name: "Transfer-Encoding", value: "chunked" }] }) });
  assert.deepEqual(await fixture.run(), { handled: true, ok: true });
  assert.deepEqual(fixture.calls.map(call => call.method), ["Fetch.takeResponseBodyAsStream", "IO.read", "IO.close", "Fetch.fulfillRequest"]);
  const fulfilled = fixture.calls.at(-1).params;
  assert.equal(Buffer.from(fulfilled.body, "base64").toString(), "<script nonce='freshA'>ok()</script>");
  assert(fulfilled.responseHeaders.some(header => header.value.includes("nonce-freshA")));
  assert.equal(fulfilled.responseHeaders.some(header => /^(?:content-encoding|content-length|transfer-encoding)$/i.test(header.name)), false);
  assert.equal(fixture.calls[1].params.size, 65536);
});

test("oversized declared or decoded bodies fail closed and always close acquired streams", async () => {
  const declared = transport({ request: event({ responseHeaders: [...context().responseHeaders, { name: "Content-Length", value: String(helper.MAX_BODY_BYTES + 1) }] }) });
  assert.equal((await declared.run()).ok, false);
  assert.deepEqual(declared.calls.map(call => call.method), ["Fetch.failRequest"]);
  const chunk = { data: Buffer.alloc(helper.READ_BYTES).toString("base64"), base64Encoded: true, eof: false };
  const decoded = transport({ replies: Array.from({ length: helper.MAX_BODY_BYTES / helper.READ_BYTES + 1 }, () => ({ ...chunk })) });
  assert.equal((await decoded.run()).ok, false);
  assert.equal(decoded.calls.some(call => call.method === "Fetch.fulfillRequest"), false);
  assert.deepEqual(decoded.calls.slice(-2).map(call => call.method), ["IO.close", "Fetch.failRequest"]);
});

test("stale configuration cannot fulfill and stream cleanup ignores epoch changes", async () => {
  let current = true;
  const calls = [];
  const result = await helper.fulfillPausedResponse({ source: { tabId: 1 }, event: event(), gatewayHost: HOST, parentUrl: ORIGIN, isSubframe: true, isCurrent: () => current, sendCommand: async (source, method) => {
    calls.push(method);
    if (method === "Fetch.takeResponseBodyAsStream") return { stream: "stream" };
    if (method === "IO.read") { current = false; return { data: "hello", eof: true }; }
    return {};
  } });
  assert.deepEqual(result, { handled: true, ok: false });
  assert.deepEqual(calls, ["Fetch.takeResponseBodyAsStream", "IO.read", "IO.close", "Fetch.failRequest"]);
});

test("late stream acquisition after timeout is closed without fulfilling", async () => {
  const fs = require("node:fs");
  const vm = require("node:vm");
  const contextVm = vm.createContext({ module: { exports: {} }, URL, TextEncoder, btoa, atob, Date, clearTimeout, setTimeout: (fn, milliseconds) => setTimeout(fn, milliseconds > 1000 ? 1 : milliseconds) });
  vm.runInContext(fs.readFileSync(require("node:path").join(__dirname, "../extension/artifact-csp.js"), "utf8"), contextVm);
  const isolated = contextVm.module.exports;
  let acquire;
  const acquired = new Promise(resolve => { acquire = resolve; });
  const calls = [];
  const result = await isolated.fulfillPausedResponse({ source: { tabId: 1 }, event: event(), gatewayHost: HOST, parentUrl: ORIGIN, isSubframe: true, sendCommand: async (source, method) => {
    calls.push(method);
    return method === "Fetch.takeResponseBodyAsStream" ? acquired : {};
  } });
  assert.equal(result.ok, false);
  acquire({ stream: "late-stream" });
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(calls, ["Fetch.takeResponseBodyAsStream", "Fetch.failRequest", "IO.close"]);
});

test("concurrent body buffering is capped and excess frames fail closed", async () => {
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  let ready;
  const started = new Promise(resolve => { ready = resolve; });
  let reading = 0;
  const sendCommand = async (source, method) => {
    if (method === "Fetch.takeResponseBodyAsStream") return { stream: "stream-" + source.tabId };
    if (method === "IO.read") { if (++reading === helper.MAX_CONCURRENT) ready(); await gate; return { data: "hello", eof: true }; }
    return {};
  };
  const options = tabId => ({ source: { tabId }, event: event(), gatewayHost: HOST, parentUrl: ORIGIN, isSubframe: true, sendCommand });
  const pending = Array.from({ length: helper.MAX_CONCURRENT }, (_, id) => helper.fulfillPausedResponse(options(id)));
  await started;
  assert.deepEqual(await helper.fulfillPausedResponse(options(999)), { handled: true, ok: false });
  release();
  assert((await Promise.all(pending)).every(result => result.ok));
});

test("attachment downloads bypass CSP parsing and the HTML body size limit", async () => {
  for (const mime of ["application/pdf", "application/octet-stream", "text/html"]) {
    const headers = [
      { name: "Content-Type", value: mime },
      { name: "Content-Disposition", value: "ATTACHMENT ; filename=\"synthetic-file\"" },
      { name: "Content-Length", value: String(helper.MAX_BODY_BYTES + 1) },
      { name: "Content-Security-Policy", value: "frame-ancestors https://claude.ai,,script-src 'none'" },
      { name: "X-Frame-Options", value: "SAMEORIGIN" }
    ];
    const unchanged = structuredClone(headers);
    const fixture = transport({ request: event({ responseHeaders: headers }) });
    assert.deepEqual(await fixture.run(), { handled: false });
    assert.deepEqual(fixture.calls, [], "browser should continue the original attachment response without buffering");
    assert.deepEqual(headers, unchanged);
    assert.equal(helper.rewriteHeaders(context({ responseHeaders: headers }), HOST), null);
  }
  assert.equal(helper.isAttachmentResponse([{ name: "Content-Disposition", value: "inline; filename=\"attachment.pdf\"" }]), false);
  assert.equal(helper.isAttachmentResponse([{ name: "Content-Disposition", value: "xattachment" }]), false);
});

test("empty, range and redirect responses are continued without touching their bodies", async () => {
  for (const status of [204, 206, 301, 302, 304, 307, 308]) {
    const fixture = transport({ request: event({ responseStatusCode: status, responseHeaders: [...context().responseHeaders,
      { name: "Content-Range", value: "bytes 0-1023/9000000" }, { name: "Content-Length", value: String(helper.MAX_BODY_BYTES + 1) }] }) });
    assert.deepEqual(await fixture.run(), { handled: false });
    assert.deepEqual(fixture.calls, []);
  }
  const empty = transport({ replies: [{ data: "", eof: true }] });
  assert.deepEqual(await empty.run(), { handled: true, ok: true });
  assert.equal(empty.calls.at(-1).params.body, "");
});

test("inline PDF retains the bounded framing path and exact binary bytes", async () => {
  const pdf = Buffer.concat([Buffer.from("%PDF-1.4\n"), Buffer.from([0, 255, 128, 13, 10]), Buffer.from("%%EOF\n")]);
  const request = event({ responseHeaders: [
    { name: "Content-Type", value: "application/pdf" },
    { name: "Content-Disposition", value: 'inline; filename="synthetic-preview.pdf"' },
    { name: "Content-Length", value: String(pdf.length) },
    { name: "Content-Security-Policy", value: "default-src 'none'; frame-ancestors https://claude.ai https://*.claude.ai" }
  ] });
  const fixture = transport({ request, replies: [{ data: pdf.toString("base64"), base64Encoded: true, eof: true }] });
  assert.deepEqual(await fixture.run(), { handled: true, ok: true });
  const fulfilled = fixture.calls.at(-1).params;
  assert.deepEqual(Buffer.from(fulfilled.body, "base64"), pdf);
  assert(fulfilled.responseHeaders.some(header => header.name === "Content-Type" && header.value === "application/pdf"));
  assert(fulfilled.responseHeaders.some(header => header.name === "Content-Disposition" && header.value === 'inline; filename="synthetic-preview.pdf"'));
  assert(fulfilled.responseHeaders.some(header => header.name === "Content-Security-Policy" && header.value.endsWith(" " + ORIGIN)));
});
