"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const cors = require("../extension/artifact-cors.js");
const HOST = "gateway.example.test:8443";
const ORIGIN = "https://" + HOST;
function event(extra = {}) {
  return { resourceType: "Fetch", request: { url: "https://frame.claudemcpcontent.com/_f/synthetic/file.html", method: "GET", headers: { Origin: ORIGIN, Accept: "text/html", "X-Synthetic": "preserve" } },
    responseStatusCode: 200, responseHeaders: [
      { name: "Access-Control-Allow-Origin", value: "https://claude.ai" }, { name: "Vary", value: "Origin" },
      { name: "Content-Type", value: "text/html" }, { name: "Content-Length", value: "12345" },
      { name: "Content-Security-Policy", value: "script-src 'nonce-fresh'; frame-ancestors https://claude.ai" },
      { name: "Content-Security-Policy", value: "connect-src 'none'" },
      { name: "Set-Cookie", value: "synthetic-one=one; Secure" }, { name: "Set-Cookie", value: "synthetic-two=two; Secure" }
    ], ...extra };
}

test("only an exact gateway Fetch/XHR GET/HEAD request gains the official upstream Origin", () => {
  for (const resourceType of ["Fetch", "XHR"]) for (const method of ["GET", "HEAD"]) {
    const original = event({ resourceType }); original.request.method = method;
    const before = structuredClone(original);
    const result = cors.requestHeaders(original, HOST, ORIGIN + "/chat");
    assert.deepEqual(result, [{ name: "Origin", value: "https://claude.ai" }, { name: "Accept", value: "text/html" }, { name: "X-Synthetic", value: "preserve" }]);
    assert.deepEqual(original, before);
  }
});

test("request scope rejects unrelated frames, opaque contexts and unsafe destinations", () => {
  for (const frame of ["https://gateway.example.test/", "https://sub.gateway.example.test:8443/", "https://gateway.example.test:8443.attacker.test/", "http://gateway.example.test:8443/", "https://user@gateway.example.test:8443/", "https://frame.claudemcpcontent.com/", "blob:" + ORIGIN + "/id", "data:text/html,fixture", "about:blank", "null"]) assert.equal(cors.requestHeaders(event(), HOST, frame), null, frame);
  for (const url of ["http://frame.claudemcpcontent.com/file", "https://frame.claudemcpcontent.com:9443/file", "https://user:pass@frame.claudemcpcontent.com/file", "https://frame.claudemcpcontent.com.attacker.test/file", "https://cdn.jsdelivr.net/file", "https://claude.ai/file", "data:text/html,fixture", "blob:https://frame.claudemcpcontent.com/id"]) {
    const request = event(); request.request.url = url;
    assert.equal(cors.requestHeaders(request, HOST, ORIGIN), null, url);
  }
  for (const resourceType of ["Document", "Script", "Image", "Other"]) assert.equal(cors.requestHeaders(event({ resourceType }), HOST, ORIGIN), null);
  for (const method of ["POST", "PUT", "DELETE", "OPTIONS"]) { const request = event(); request.request.method = method; assert.equal(cors.requestHeaders(request, HOST, ORIGIN), null); }
});

test("absent, foreign, null or duplicate request Origin is never changed", () => {
  for (const headers of [{ Accept: "text/html" }, { Origin: "null" }, { Origin: "https://claude.ai" }, { Origin: ORIGIN + "/" }, { Origin: ORIGIN, origin: ORIGIN }, [{ name: "Origin", value: ORIGIN }, { name: "Origin", value: "https://other.test" }]]) {
    const request = event(); request.request.headers = headers;
    assert.equal(cors.requestHeaders(request, HOST, ORIGIN), null);
  }
});

test("paired response helper changes only a single exact official ACAO header", () => {
  const original = event(); const before = structuredClone(original);
  const changed = cors.responseHeaders(original, HOST);
  assert.deepEqual(changed, original.responseHeaders.map((header, index) => index === 0 ? { ...header, value: ORIGIN } : header));
  assert.deepEqual(original, before, "response status, body metadata and source headers must remain unchanged");
  assert.equal(changed.some(header => header.name.toLowerCase() === "access-control-allow-credentials"), false);
  const credentials = event(); credentials.responseHeaders.push({ name: "Access-Control-Allow-Credentials", value: "true" });
  assert.deepEqual(cors.responseHeaders(credentials, HOST).at(-1), credentials.responseHeaders.at(-1), "the helper must never add or alter credential policy");
});

test("absent, wildcard, null, foreign, joined or duplicate ACAO remains untouched", () => {
  for (const values of [[], ["*"], ["null"], [ORIGIN], ["https://other.test"], ["https://claude.ai/"], ["https://claude.ai, https://other.test"], ["https://claude.ai", "https://claude.ai"], ["https://claude.ai", "https://other.test"]]) {
    const response = event();
    response.responseHeaders = [{ name: "Vary", value: "Origin" }, ...values.map(value => ({ name: "Access-Control-Allow-Origin", value }))];
    assert.equal(cors.responseHeaders(response, HOST), null, JSON.stringify(values));
  }
});

test("redirect, unsafe request and malformed headers cannot receive a CORS rewrite", () => {
  for (const responseStatusCode of [0, 101, 301, 302, 303, 307, 308]) assert.equal(cors.responseHeaders(event({ responseStatusCode }), HOST), null);
  assert.equal(cors.responseHeaders(event({ responseErrorReason: "Failed" }), HOST), null);
  assert.equal(cors.responseHeaders(event({ resourceType: "Document" }), HOST), null);
  for (const host of ["https://gateway.example.test", "gateway.example.test/path", "user@gateway.example.test", "gateway.example.test?x=1"]) assert.equal(cors.responseHeaders(event(), host), null);
  const malformed = event(); malformed.responseHeaders[1].value = "Origin\r\nInjected: unsafe";
  assert.equal(cors.responseHeaders(malformed, HOST), null);
  const request = event(); request.request.headers["X-Synthetic"] = "unsafe\r\n";
  assert.equal(cors.requestHeaders(request, HOST, ORIGIN), null);
});

test("CORS patterns cover only approved artifact Fetch/XHR requests", () => {
  const patterns = cors.buildFetchPatterns();
  assert.equal(patterns.length, 8);
  assert(patterns.every(pattern => pattern.requestStage === "Request" && ["XHR", "Fetch"].includes(pattern.resourceType)));
  assert.deepEqual(new Set(patterns.map(pattern => pattern.urlPattern)), new Set([
    "https://claudeusercontent.com/*", "https://*.claudeusercontent.com/*",
    "https://claudemcpcontent.com/*", "https://*.claudemcpcontent.com/*"
  ]));
  for (const responseStatusCode of [200, 204, 206, 304, 404, 500]) {
    const response = event({ responseStatusCode, body: "synthetic body must remain untouched" });
    const before = structuredClone(response);
    assert(cors.responseHeaders(response, HOST));
    assert.deepEqual(response, before);
  }
});
