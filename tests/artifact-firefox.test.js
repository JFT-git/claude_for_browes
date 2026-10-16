"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const adapter = require("../extension/artifact-firefox.js");
const csp = require("../extension/artifact-csp.js");
const cors = require("../extension/artifact-cors.js");
const HOST = "gateway.example.test:8443", ORIGIN = "https://" + HOST;
const ART = "https://frame.claudemcpcontent.com/file";
function event() {
  let listener;
  return { addListener(fn, filter, flags) { listener = fn; this.filter = filter; this.flags = flags; }, removeListener() { listener = undefined; }, fire(...args) { return listener?.(...args); } };
}
async function fixture() {
  const webRequest = Object.fromEntries(["onBeforeRequest", "onBeforeSendHeaders", "onHeadersReceived", "onBeforeRedirect", "onCompleted", "onErrorOccurred"].map(name => [name, event()]));
  const webNavigation = Object.fromEntries(["onBeforeNavigate", "onCommitted", "onErrorOccurred"].map(name => [name, event()]));
  const state = { ready: true, faults: 0, tab: { url: ORIGIN + "/chat" }, frames: [{ frameId: 0, parentFrameId: -1, url: ORIGIN + "/chat" }], lookup: null };
  webNavigation.getAllFrames = async () => state.lookup ? state.lookup() : structuredClone(state.frames);
  const browser = { webRequest, webNavigation, tabs: { get: async () => structuredClone(state.tab), onRemoved: event() } };
  const manager = adapter.create({ browser, csp, cors, isReady: () => state.ready, onUnsafeDetach: () => state.faults++ });
  await manager.configure(HOST);
  const request = (extra = {}) => ({ requestId: "synthetic", tabId: 1, frameId: 0, parentFrameId: -1, url: ART, method: "GET", type: "xmlhttprequest", documentUrl: ORIGIN + "/chat", originUrl: ORIGIN + "/chat", requestHeaders: [{ name: "Origin", value: ORIGIN }, { name: "Accept", value: "text/html" }], ...extra });
  const response = (req, headers = [{ name: "Access-Control-Allow-Origin", value: "https://claude.ai" }], statusCode = 200) => ({ ...req, statusCode, responseHeaders: headers });
  const frame = (extra = {}) => request({ type: "sub_frame", frameId: 2, parentFrameId: 0, frameAncestors: [{ frameId: 0, url: ORIGIN + "/chat" }], ...extra });
  return { ...browser, state, manager, request, response, frame };
}

test("Firefox listeners use blocking header APIs and only approved artifact resource classes", async () => {
  const f = await fixture();
  assert.equal(f.manager.status().available, true);
  assert.equal(f.manager.status().active, true);
  assert.deepEqual(f.webRequest.onBeforeSendHeaders.flags, ["blocking", "requestHeaders"]);
  assert.deepEqual(f.webRequest.onHeadersReceived.flags, ["blocking", "responseHeaders"]);
  assert.deepEqual(f.webRequest.onBeforeSendHeaders.filter.types, ["sub_frame", "xmlhttprequest"]);
  assert.deepEqual(new Set(f.webRequest.onBeforeSendHeaders.filter.urls), new Set(["https://claudeusercontent.com/*", "https://*.claudeusercontent.com/*", "https://claudemcpcontent.com/*", "https://*.claudemcpcontent.com/*"]));
});

test("paired gateway GET changes only Origin and one exact ACAO, retaining duplicate and binary headers", async () => {
  const f = await fixture(); const req = f.request();
  req.requestHeaders.push({ name: "X-Binary", binaryValue: [0, 255, 17] });
  const original = structuredClone(req);
  const sent = await f.webRequest.onBeforeSendHeaders.fire(req);
  assert.deepEqual(sent.requestHeaders, req.requestHeaders.map((h, i) => i === 0 ? { ...h, value: "https://claude.ai" } : h));
  const headers = [{ name: "Access-Control-Allow-Origin", value: "https://claude.ai" }, { name: "Access-Control-Allow-Credentials", value: "true" }, { name: "Content-Encoding", value: "gzip" }, { name: "Content-Length", value: "999999999" }, { name: "Content-Security-Policy", value: "script-src 'none'" }, { name: "Content-Security-Policy", value: "connect-src 'none'" }, { name: "X-Binary", binaryValue: [128, 0] }];
  const received = await f.webRequest.onHeadersReceived.fire(f.response(req, headers));
  assert.deepEqual(received.responseHeaders, headers.map((h, i) => i === 0 ? { ...h, value: ORIGIN } : h));
  assert.deepEqual(req, original);
  assert.deepEqual(await f.webRequest.onHeadersReceived.fire(f.response(f.request({ requestId: "unpaired" }), headers)), {});
  f.webRequest.onCompleted.fire(req);
  assert.equal(f.manager.status().pendingRequests, 0);
});

test("unapproved requests and non-simple preflight receive no header privilege", async () => {
  const variants = [{ method: "OPTIONS" }, { method: "POST" }, { documentUrl: "https://other.example/" }, { originUrl: "https://other.example/" }, { documentUrl: "about:srcdoc" }, { tabId: -1 }, { url: "http://frame.claudemcpcontent.com/file" }, { url: "https://frame.claudemcpcontent.com:9443/file" }, { url: "https://user@frame.claudemcpcontent.com/file" }, { url: "https://frame.claudemcpcontent.com.attacker.test/file" }, { requestHeaders: [{ name: "Origin", value: "null" }] }, { requestHeaders: [{ name: "Origin", value: ORIGIN }, { name: "Origin", value: ORIGIN }] }];
  for (const extra of variants) {
    const f = await fixture();
    assert.deepEqual(await f.webRequest.onBeforeSendHeaders.fire(f.request(extra)), {}, JSON.stringify(extra));
    assert.equal(f.manager.status().pendingRequests, 0);
  }
  const f = await fixture(); f.state.tab.pendingUrl = "https://other.example/";
  assert.deepEqual(await f.webRequest.onBeforeSendHeaders.fire(f.request()), {});
});

test("foreign, absent, wildcard, joined and duplicate response ACAO stay native", async () => {
  for (const values of [[], ["*"], ["null"], ["https://foreign.example"], ["https://claude.ai, https://foreign.example"], ["https://claude.ai", "https://claude.ai"]]) {
    const f = await fixture(); const req = f.request();
    await f.webRequest.onBeforeSendHeaders.fire(req);
    const headers = values.map(value => ({ name: "Access-Control-Allow-Origin", value }));
    assert.deepEqual(await f.webRequest.onHeadersReceived.fire(f.response(req, headers)), {});
  }
});

test("frame compatibility preserves fresh nonce and every separate policy while adding only gateway ancestor", async () => {
  const f = await fixture(); const req = f.frame();
  await f.webRequest.onBeforeSendHeaders.fire(req);
  const headers = [{ name: "Content-Security-Policy", value: "default-src 'self'; script-src 'nonce-fresh'; frame-ancestors https://claude.ai" }, { name: "Content-Security-Policy", value: "script-src 'none'" }, { name: "Content-Security-Policy-Report-Only", value: "frame-ancestors https://*.claude.ai" }, { name: "X-Frame-Options", value: "DENY" }, { name: "Content-Encoding", value: "br" }, { name: "X-Binary", binaryValue: [0, 129] }];
  const changed = await f.webRequest.onHeadersReceived.fire(f.response(req, headers));
  assert.deepEqual(changed.responseHeaders, [{ ...headers[0], value: headers[0].value + " " + ORIGIN }, headers[1], { ...headers[2], value: headers[2].value + " " + ORIGIN }, headers[4], headers[5]]);
  const originalDeny = [{ name: "Content-Security-Policy", value: "frame-ancestors 'none'" }];
  assert.deepEqual(await f.webRequest.onHeadersReceived.fire(f.response(req, originalDeny)), {});
});

test("complete browser-owned ancestry is required, including nested artifact parents", async () => {
  const f = await fixture();
  f.state.frames.push({ frameId: 3, parentFrameId: 0, url: "https://nested.claudeusercontent.com/preview" });
  const nested = f.frame({ parentFrameId: 3, frameAncestors: [{ frameId: 3, url: f.state.frames[1].url }, { frameId: 0, url: ORIGIN + "/chat" }] });
  await f.webRequest.onBeforeSendHeaders.fire(nested);
  assert.equal(f.manager.status().pendingRequests, 1);
  for (const frameAncestors of [[], [{ frameId: 3, url: f.state.frames[1].url }], [{ frameId: 0, url: ORIGIN + "/chat" }], [{ frameId: 3, url: "https://foreign.example/" }, { frameId: 0, url: ORIGIN + "/chat" }], [{ frameId: 3, url: f.state.frames[1].url }, { frameId: 3, url: f.state.frames[1].url }, { frameId: 0, url: ORIGIN + "/chat" }]]) {
    const req = { ...nested, requestId: JSON.stringify(frameAncestors), frameAncestors };
    await f.webRequest.onBeforeSendHeaders.fire(req);
    assert.deepEqual(await f.webRequest.onHeadersReceived.fire(f.response(req, [{ name: "X-Frame-Options", value: "DENY" }])), {});
  }
});

test("downloads, ranges and empty documents keep original headers with no body access or size cap", async () => {
  for (const [status, extra] of [[200, [{ name: "Content-Disposition", value: "attachment; filename=large.pdf" }]], [206, []], [204, []], [304, []]]) {
    const f = await fixture(); const req = f.frame(); await f.webRequest.onBeforeSendHeaders.fire(req);
    const headers = [{ name: "Content-Type", value: "application/pdf" }, { name: "Content-Length", value: "999999999" }, { name: "Content-Security-Policy", value: "frame-ancestors https://claude.ai" }, { name: "X-Frame-Options", value: "DENY" }, ...extra];
    assert.deepEqual(await f.webRequest.onHeadersReceived.fire(f.response(req, headers, status)), {});
  }
});

test("auth retries retain one exact current pair for either gateway or already-rewritten Origin", async () => {
  const f = await fixture(); const req = f.request();
  const first = await f.webRequest.onBeforeSendHeaders.fire(req);
  await f.webRequest.onHeadersReceived.fire(f.response(req, [{ name: "Access-Control-Allow-Origin", value: "https://claude.ai" }], 401));
  assert.deepEqual(await f.webRequest.onBeforeSendHeaders.fire({ ...req, requestHeaders: first.requestHeaders }), first);
  assert.deepEqual(await f.webRequest.onBeforeSendHeaders.fire(req), first);
  assert.equal(f.manager.status().pendingRequests, 1);
  assert.deepEqual(await f.webRequest.onBeforeSendHeaders.fire({ ...req, url: ART + "/other" }), { cancel: true });
});

test("redirects cannot recreate Origin privileges under the same request ID", async () => {
  const f = await fixture(); const req = f.request();
  await f.webRequest.onBeforeSendHeaders.fire(req);
  assert.deepEqual(await f.webRequest.onHeadersReceived.fire(f.response(req, [{ name: "Location", value: ART + "/next" }], 302)), { cancel: true });
  f.webRequest.onBeforeRedirect.fire(req);
  assert.deepEqual(f.webRequest.onBeforeRequest.fire({ ...req, url: ART + "/next" }), { cancel: true });
  assert.deepEqual(await f.webRequest.onBeforeSendHeaders.fire(req), { cancel: true });
});

test("navigation, stop, reconfiguration and changed frame ownership invalidate in-flight permissions", async () => {
  for (const invalidate of [f => f.webNavigation.onBeforeNavigate.fire({ tabId: 1, frameId: 0 }), f => f.manager.stop(), f => f.manager.configure(HOST), f => { f.state.frames[0].url = "https://foreign.example/"; }, f => { f.state.ready = false; }]) {
    const f = await fixture(); const req = f.request(); await f.webRequest.onBeforeSendHeaders.fire(req);
    await invalidate(f);
    assert.deepEqual(await f.webRequest.onHeadersReceived.fire(f.response(req)), { cancel: true });
  }
});

test("lookup yields cannot insert stale or over-capacity authorizations", async () => {
  const f = await fixture(); let release;
  f.state.lookup = () => new Promise(resolve => { release = resolve; });
  const pending = f.webRequest.onBeforeSendHeaders.fire(f.request());
  await Promise.resolve();
  await f.manager.configure(HOST);
  release(structuredClone(f.state.frames));
  assert.deepEqual(await pending, {});
  assert.equal(f.manager.status().pendingRequests, 0);
  const g = await fixture();
  for (let i = 0; i < adapter.MAX_REQUESTS; i++) await g.webRequest.onBeforeSendHeaders.fire(g.request({ requestId: "bound-" + i }));
  assert.deepEqual(await g.webRequest.onBeforeSendHeaders.fire(g.request({ requestId: "overflow" })), { cancel: true });
  assert.equal(g.state.faults, 1);
  assert.equal(g.manager.status().active, false);
  assert.equal(g.manager.status().pendingRequests, adapter.MAX_REQUESTS);
});


test("frame redirects remain native and final responses require a fresh owned ancestry", async () => {
  const f = await fixture(); const req = f.frame();
  await f.webRequest.onBeforeSendHeaders.fire(req);
  assert.deepEqual(await f.webRequest.onHeadersReceived.fire(f.response(req, [{ name: "Location", value: "https://next.claudeusercontent.com/final" }], 302)), {});
  f.webRequest.onBeforeRedirect.fire(req);
  const final = { ...req, url: "https://next.claudeusercontent.com/final" };
  assert.deepEqual(f.webRequest.onBeforeRequest.fire(final), {});
  await f.webRequest.onBeforeSendHeaders.fire(final);
  const policy = [{ name: "Content-Security-Policy", value: "frame-ancestors https://claude.ai" }];
  assert.deepEqual(await f.webRequest.onHeadersReceived.fire(f.response(final, policy)), { responseHeaders: [{ ...policy[0], value: policy[0].value + " " + ORIGIN }] });
  const fallback = await fixture(); const initial = fallback.frame();
  await fallback.webRequest.onBeforeSendHeaders.fire(initial);
  fallback.webRequest.onBeforeRedirect.fire(initial);
  assert.equal(fallback.manager.status().pendingRequests, 0);
  assert.deepEqual(fallback.webRequest.onBeforeRequest.fire({ ...initial, url: ART + "/redirected" }), {});
  const g = await fixture(); const first = g.frame();
  await g.webRequest.onBeforeSendHeaders.fire(first);
  await g.webRequest.onHeadersReceived.fire(g.response(first, [], 307));
  const foreign = { ...first, url: "https://foreign.example/final" };
  await g.webRequest.onBeforeSendHeaders.fire(foreign);
  assert.deepEqual(await g.webRequest.onHeadersReceived.fire(g.response(foreign, policy)), {});
  g.state.frames[0].url = "https://foreign.example/parent";
  const moved = { ...first, url: ART + "/final" };
  await g.webRequest.onBeforeSendHeaders.fire(moved);
  assert.deepEqual(await g.webRequest.onHeadersReceived.fire(g.response(moved, policy)), {});
});

test("Claude's nested artifact panel is recognised after the app rewrites its own URL", async () => {
  // Real layout: gateway chat → gateway /code/artifact frame → artifact frame. Opening
  // the panel adds ?artifact=<id> to the chat URL with history.pushState.
  const f = await fixture();
  f.state.frames = [{ frameId: 0, parentFrameId: -1, url: ORIGIN + "/chat/abc?artifact=xyz" },
    { frameId: 7, parentFrameId: 0, url: ORIGIN + "/code/artifact/xyz?m=dark" }];
  const req = f.frame({ frameId: 8, parentFrameId: 7, url: "https://xyz.frame.claudeusercontent.com/_f/1/",
    frameAncestors: [{ frameId: 7, url: ORIGIN + "/code/artifact/xyz?m=dark" }, { frameId: 0, url: ORIGIN + "/chat/abc" }] });
  await f.webRequest.onBeforeSendHeaders.fire(req);
  const headers = [{ name: "Content-Security-Policy", value: "frame-ancestors https://claude.ai" }, { name: "X-Frame-Options", value: "SAMEORIGIN" }];
  const received = await f.webRequest.onHeadersReceived.fire(f.response(req, headers));
  assert.deepEqual(received.responseHeaders, [{ name: "Content-Security-Policy", value: "frame-ancestors https://claude.ai " + ORIGIN }]);
  // A different origin in the chain is still refused.
  const g = await fixture();
  g.state.frames = [{ frameId: 0, parentFrameId: -1, url: ORIGIN + "/chat/abc" }, { frameId: 7, parentFrameId: 0, url: "https://foreign.example/code/artifact/xyz" }];
  const foreign = g.frame({ frameId: 8, parentFrameId: 7, url: "https://xyz.frame.claudeusercontent.com/_f/1/",
    frameAncestors: [{ frameId: 7, url: ORIGIN + "/code/artifact/xyz" }, { frameId: 0, url: ORIGIN + "/chat/abc" }] });
  await g.webRequest.onBeforeSendHeaders.fire(foreign);
  assert.deepEqual(await g.webRequest.onHeadersReceived.fire(g.response(foreign, headers)), {});
});
