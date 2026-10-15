"use strict";
const test = require("node:test"), assert = require("node:assert/strict");
const { create } = require("../extension/proxy-firefox.js");
const HOST = "gateway.example.test", WARMUP = "https://cdn.jsdelivr.net/warmup";
const DEAD = { type: "http", host: "127.0.0.1", port: 9 };
const session = () => ({ proxyUsername: "gateway-proxy", proxyPassword: "t".repeat(43), expiresAt: Date.now() + 60000,
  proxy: { scheme: "https", host: "proxy.example.test", port: 443 } });
const request = (extra = {}) => ({ url: "https://id.frame.claudeusercontent.com/frame", method: "GET", ...extra });
const cdn = (extra = {}) => request({ url: "https://cdn.jsdelivr.net/npm/x.js", ...extra });
function fixture({ legacy = false } = {}) {
  const event = () => ({ handlers: [], addListener(fn) { this.handlers.push(fn); }, emit(value) { return this.handlers.map(fn => fn(value)); } });
  let actual = legacy ? { levelOfControl: "controlled_by_this_extension", value: { proxyType: "manual", http: "127.0.0.1:9" } }
    : { levelOfControl: "controllable_by_this_extension", value: { proxyType: "system" } };
  let os = "linux";
  const calls = [], before = event(), proxy = event();
  const browser = { runtime: { getPlatformInfo: async () => ({ os }) },
    proxy: { onRequest: proxy, settings: {
      get: async options => { calls.push(["get", options]); return structuredClone(actual); },
      set: async () => { throw new Error("browser-wide proxy settings must not be written"); },
      clear: async options => { calls.push(["clear", options]); actual = { levelOfControl: "controllable_by_this_extension", value: { proxyType: "system" } }; }
    } }, webRequest: { onBeforeRequest: before } };
  const adapter = create({ browser, protectedHost: host => host.endsWith(".claudeusercontent.com") || host === "cdn.jsdelivr.net",
    artifactHost: host => host.endsWith(".claudeusercontent.com"), upstreamHost: host => host === "claude.ai",
    filter: ["https://*.claudeusercontent.com/*", "https://cdn.jsdelivr.net/*"], warmupUrl: WARMUP,
    isExtensionRequest: details => details.originUrl === "moz-extension://own/" });
  return { adapter, calls, browser, before, proxy, get actual() { return actual; }, os(value) { os = value; } };
}

test("Firefox never writes browser-wide proxy settings and needs no private-window access", async () => {
  const f = fixture();
  await f.adapter.ensure(HOST);
  assert.equal(f.adapter.status().baselineReady, true);
  assert.equal(f.calls.some(call => call[0] === "clear"), false, "settings owned by the user or another extension stay untouched");
  assert.equal(f.actual.value.proxyType, "system");
});

test("upgrade from a build with the dead-end baseline returns the browser proxy to the user", async () => {
  const f = fixture({ legacy: true });
  await f.adapter.ensure(HOST);
  assert.deepEqual(f.calls.find(call => call[0] === "clear")[1], {});
  assert.equal(f.actual.levelOfControl, "controllable_by_this_extension");
});

test("requests of other sites keep Firefox's own routing, including shared CDN hosts", async () => {
  const f = fixture(); await f.adapter.ensure(HOST);
  for (const details of [cdn(), cdn({ originUrl: "https://news.example.org/", documentUrl: "https://news.example.org/" }),
    cdn({ originUrl: "https://" + HOST + ".evil.test/" }), cdn({ originUrl: "http://" + HOST + "/" })]) {
    assert.equal(f.adapter.route(details), undefined, JSON.stringify(details));
    assert.deepEqual(f.adapter.gate(details), {});
  }
  f.adapter.setSession(session());
  assert.equal(f.adapter.route(cdn({ originUrl: "https://news.example.org/" })), undefined);
});

test("Claude-owned requests are closed until the session is ready, then use the authenticated proxy", async () => {
  const f = fixture();
  // Artifact hosts are Claude-only and stay closed even before configuration.
  assert.deepEqual(f.adapter.route(request()), DEAD); assert.deepEqual(f.adapter.gate(request()), { cancel: true });
  await f.adapter.ensure(HOST);
  const fromGateway = cdn({ originUrl: "https://" + HOST + "/chat", documentUrl: "https://" + HOST + "/chat" });
  const fromArtifact = cdn({ documentUrl: "https://id.frame.claudeusercontent.com/frame" });
  const nestedFrame = cdn({ frameAncestors: [{ frameId: 0, url: "https://" + HOST + "/chat" }] });
  for (const details of [request(), fromGateway, fromArtifact, nestedFrame]) {
    assert.deepEqual(f.adapter.route(details), DEAD); assert.deepEqual(f.adapter.gate(details), { cancel: true });
  }
  f.adapter.setSession(session());
  for (const details of [request(), fromGateway, fromArtifact, nestedFrame]) {
    const route = f.adapter.route(details);
    assert.equal(route.type, "https"); assert.equal(route.host, "proxy.example.test"); assert.equal(route.port, 443);
    assert.equal(route.proxyAuthorizationHeader, "Basic " + Buffer.from("gateway-proxy:" + "t".repeat(43)).toString("base64"));
    assert.match(route.connectionIsolationKey, /^gateway-proxy-\d+$/);
    assert.deepEqual(f.adapter.gate(details), {});
  }
});

test("each session gets a separate connection isolation key", async () => {
  const f = fixture(); await f.adapter.ensure(HOST);
  f.adapter.setSession(session()); const first = f.adapter.route(request()).connectionIsolationKey;
  f.adapter.setSession(session()); assert.notEqual(f.adapter.route(request()).connectionIsolationKey, first);
});

test("gateway with a custom port is matched by exact authority", async () => {
  const f = fixture(); await f.adapter.ensure(HOST + ":8443"); f.adapter.setSession(session());
  assert.equal(f.adapter.route(cdn({ originUrl: "https://" + HOST + ":8443/chat" })).type, "https");
  assert.equal(f.adapter.route(cdn({ originUrl: "https://" + HOST + "/chat" })), undefined);
});

test("Firefox warmup permits only the exact extension HEAD and records that it was routed", async () => {
  const f = fixture(); await f.adapter.ensure(HOST); f.adapter.setSession(session(), { warming: true });
  for (const details of [request(), request({ url: WARMUP, method: "GET", originUrl: "moz-extension://own/" }),
    request({ url: WARMUP, method: "HEAD", originUrl: "https://" + HOST })]) {
    assert.deepEqual(f.adapter.route(details), DEAD); assert.deepEqual(f.adapter.gate(details), { cancel: true });
  }
  assert.equal(f.adapter.warmupRouted(), false);
  assert.equal(f.adapter.route(request({ url: WARMUP, method: "HEAD", originUrl: "moz-extension://own/" })).type, "https");
  assert.equal(f.adapter.warmupRouted(), true);
  assert.equal(f.adapter.status().sessionReady, false);
  f.adapter.setSession(session(), { warming: true });
  assert.equal(f.adapter.warmupRouted(), false, "a new warmup must be routed again");
});

test("expiry, malformed session and nonstandard target ports never return DIRECT or null for Claude requests", async () => {
  const f = fixture(); await f.adapter.ensure(HOST); const s = session(); f.adapter.setSession(s);
  for (const url of ["http://id.frame.claudeusercontent.com/", "https://id.frame.claudeusercontent.com:8443/"]) {
    assert.deepEqual(f.adapter.route(request({ url })), DEAD);
  }
  s.expiresAt = Date.now() - 1;
  assert.deepEqual(f.adapter.route(request()), DEAD); assert.deepEqual(f.adapter.gate(request()), { cancel: true });
  assert.throws(() => f.adapter.setSession({ ...session(), proxyPassword: "bad" }));
  assert.deepEqual(f.adapter.route(request()), DEAD);
});

test("reset closes the session; clear forgets the gateway", async () => {
  const f = fixture(); await f.adapter.ensure(HOST); f.adapter.setSession(session()); f.adapter.reset();
  assert.equal(f.adapter.status().baselineReady, true); assert.equal(f.adapter.status().sessionReady, false);
  assert.deepEqual(f.adapter.route(request()), DEAD);
  await f.adapter.clear();
  assert.equal(f.adapter.status().baselineReady, false);
  assert.equal(f.adapter.route(cdn({ originUrl: "https://" + HOST + "/chat" })), undefined);
});

test("Android remains explicitly unsupported", async () => {
  const f = fixture(); f.os("android");
  await assert.rejects(f.adapter.ensure(HOST), error => error.reason === "firefox_android_unsupported");
  assert.equal(f.adapter.status().baselineReady, false);
  const bare = create({ browser: { runtime: { getPlatformInfo: async () => ({ os: "android" }) } },
    protectedHost: () => true, artifactHost: () => true, filter: [], warmupUrl: WARMUP, isExtensionRequest: () => false });
  await assert.rejects(bare.ensure(HOST), error => error.reason === "firefox_android_unsupported");
});

test("blocking gates are registered before routing, with egress covering every URL", () => {
  const f = fixture();
  assert.equal(f.before.handlers.length, 2);
  assert.equal(f.proxy.handlers.length, 1);
});

test("Claude documents, including opaque frames and blob workers, reach only approved destinations", async () => {
  const f = fixture(); await f.adapter.ensure(HOST);
  const contexts = [{ originUrl: "https://" + HOST + "/chat", documentUrl: "https://" + HOST + "/chat" },
    { originUrl: "null", documentUrl: "about:srcdoc", frameAncestors: [{ frameId: 3, url: "https://id.frame.claudeusercontent.com/frame" }, { frameId: 0, url: "https://" + HOST + "/chat" }] },
    { originUrl: "blob:https://id.frame.claudeusercontent.com/2b1c" }];
  for (const context of contexts) {
    for (const [url, type] of [["https://unapproved.example.test/exfil", "xmlhttprequest"], ["wss://unapproved.example.test/socket", "websocket"],
      ["http://cdn.jsdelivr.net/npm/x.js", "script"], ["https://cdn.jsdelivr.net:8443/x.js", "script"], ["https://" + HOST + ":9443/", "xmlhttprequest"],
      ["https://unapproved.example.test/frame", "sub_frame"]]) {
      assert.deepEqual(f.adapter.egress({ url, type, ...context }), { cancel: true }, url + " " + JSON.stringify(context));
    }
    for (const url of ["https://" + HOST + "/api", "wss://" + HOST + "/socket", "https://cdn.jsdelivr.net/npm/x.js", "https://id.frame.claudeusercontent.com/a", "https://claude.ai/api", "data:text/plain,x"]) {
      assert.deepEqual(f.adapter.egress({ url, type: "xmlhttprequest", ...context }), {}, url);
    }
    assert.deepEqual(f.adapter.egress({ url: "https://docs.example.org/", type: "main_frame", ...context }), {});
  }
  for (const other of [{ originUrl: "https://news.example.org/" }, { originUrl: "http://intranet.example.test/" }, {}]) {
    for (const url of ["https://tracker.example.net/p", "http://intranet.example.test/api", "https://cdn.jsdelivr.net/npm/x.js"]) {
      assert.deepEqual(f.adapter.egress({ url, type: "xmlhttprequest", ...other }), {}, url);
    }
  }
});
