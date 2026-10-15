"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const policy = require("../extension/privacy-rules.js");
const HOST = "gateway.example.test";

// Evaluate the browser's documented condition and priority subset used by this
// policy. Native browser tests separately validate initiator and opaque frames.
function applies(rule, { url, type, initiator, tabId = 4 }) {
  const c = rule.condition;
  if (c.regexFilter && !new RegExp(c.regexFilter, "i").test(url)) return false;
  if (c.resourceTypes && !c.resourceTypes.includes(type)) return false;
  // Native Chrome excludes main_frame even with excludedResourceTypes: [].
  if (!c.resourceTypes && type === "main_frame") return false;
  if (c.excludedResourceTypes?.includes(type)) return false;
  if (c.tabIds && !c.tabIds.includes(tabId)) return false;
  if (c.requestDomains && !c.requestDomains.some(domain => new URL(url).hostname === domain || new URL(url).hostname.endsWith("." + domain))) return false;
  if (c.initiatorDomains) {
    let host;
    try { host = new URL(initiator).hostname; } catch (_) { return false; }
    if (!c.initiatorDomains.some(domain => host === domain || host.endsWith("." + domain))) return false;
  }
  return true;
}
function verdict(request, extraRules = []) {
  const matches = [...policy.buildPrivacyRules(HOST), ...extraRules].filter(rule => rule.action.type !== "modifyHeaders" && applies(rule, request)).sort((a, b) => b.priority - a.priority);
  return matches[0]?.action.type || "unmatched";
}
const request = (url, type = "xmlhttprequest", initiator = "https://" + HOST) => ({ url, type, initiator });
const readyRoute = policy.buildProxyAllowRules();

test("gateway and artifact egress rejects arbitrary destinations across request contexts", () => {
  for (const origin of ["https://" + HOST, "https://a.frame.claudeusercontent.com", "https://a.claudemcpcontent.com"]) {
    for (const type of ["main_frame", "sub_frame", "xmlhttprequest", "script", "image", "other", "websocket", "ping", "csp_report"]) {
      const scheme = type === "websocket" ? "wss" : "https";
      assert.equal(verdict(request(scheme + "://unapproved.example.test/exfil", type, origin), readyRoute), "block", type + " from " + origin);
    }
  }
});

test("approved artifact/CDN routes require a ready TLS route and exact destination", () => {
  for (const host of ["claudeusercontent.com", "a.frame.claudeusercontent.com", "a.claudemcpcontent.com", ...policy.DEPENDENCY_HOSTS]) {
    for (const scheme of ["https", "wss"]) {
      const req = request(scheme + "://" + host + "/asset", scheme === "wss" ? "websocket" : "xmlhttprequest");
      assert.equal(verdict(req), "block", req.url);
      assert.equal(verdict(req, readyRoute), "allow", req.url);
    }
    assert.equal(verdict(request("https://" + host + ".attacker.test/exfil"), readyRoute), "block");
  }
});

test("cleartext never wins over a ready route, and upstream sockets fail closed", () => {
  for (const host of [HOST, ...policy.UPSTREAM_HOSTS, "a.frame.claudeusercontent.com", ...policy.DEPENDENCY_HOSTS]) {
    for (const scheme of ["http", "ws"]) {
      assert.equal(verdict(request(scheme + "://" + host + "/asset", scheme === "ws" ? "websocket" : "image"), readyRoute), "block");
    }
  }
  for (const host of policy.UPSTREAM_HOSTS) assert.equal(verdict(request("wss://" + host + "/socket", "websocket"), readyRoute), "block");
  assert.equal(verdict(request("wss://" + HOST + "/socket", "websocket"), readyRoute), "allow");
});

test("dedicated-profile deny covers opaque frames, new popups and background workers", () => {
  for (const type of ["main_frame", "sub_frame", "xmlhttprequest", "script", "image", "websocket", "object", "webtransport", "webbundle"]) {
    assert.equal(verdict(request("https://unapproved.example.test/exfil", type, "null")), "block");
    assert.equal(verdict(request("https://a.frame.claudeusercontent.com/asset", type, "null"), readyRoute), policy.RESOURCE_TYPES.includes(type) ? "allow" : "block");
  }
  assert.equal(verdict({ ...request("https://unapproved.example.test/background", "xmlhttprequest", "null"), tabId: -1 }), "block");
  assert.equal(verdict(request("https://unapproved.example.test/", "main_frame", "https://unrelated.example.test")), "block");
});

test("only legacy artifact frame headers are changed and all CSP policies survive", () => {
  const modifiers = policy.buildPrivacyRules(HOST).filter(rule => rule.action.type === "modifyHeaders");
  assert.equal(modifiers.length, 1);
  const rule = modifiers[0];
  assert.equal(applies(rule, request("https://a.frame.claudeusercontent.com/embed", "sub_frame")), true);
  for (const req of [request("https://cdn.jsdelivr.net/asset", "sub_frame"), request("https://a.frame.claudeusercontent.com/embed", "main_frame"), request("https://a.frame.claudeusercontent.com/embed", "sub_frame", "https://unrelated.example.test")]) assert.equal(applies(rule, req), false);
  assert.deepEqual(rule.action.responseHeaders, [{ header: "x-frame-options", operation: "remove" }]);
});

test("permissions and MAIN script scope cover artifact origins without all-sites request", () => {
  const origins = policy.requiredOrigins(HOST);
  assert(origins.includes("https://" + HOST + "/*"));
  assert(origins.includes("https://claude.ai/*"));
  for (const host of policy.DEPENDENCY_HOSTS) assert(origins.includes("https://" + host + "/*"));
  assert.equal(origins.includes("https://*/*"), false);
  for (const domain of policy.ARTIFACT_DOMAINS) assert(policy.fingerprintMatches(HOST).includes("https://*." + domain + "/*"));
  for (const host of ["https://gateway.example.test", "gateway.example.test/evil", "user@gateway.example.test", "gateway.example.test?evil", "Gateway.example.test"]) assert.throws(() => policy.requiredOrigins(host), /Invalid gateway/);
});

function pageFixture(name, chrome) {
  const fs = require("node:fs");
  const vm = require("node:vm");
  const elements = new Map();
  const element = id => {
    if (!elements.has(id)) elements.set(id, { value: "", textContent: "", style: {}, disabled: false, addEventListener(type, fn) { this[type] = fn; } });
    return elements.get(id);
  };
  const context = vm.createContext({ chrome, GatewayPrivacy: policy, document: { getElementById: element }, setTimeout: () => 1, clearTimeout() {} });
  vm.runInContext(fs.readFileSync(require("node:path").join(__dirname, "../extension/" + name + ".js"), "utf8"), context);
  return { element };
}
const settle = () => new Promise(resolve => setImmediate(resolve));

test("settings requests exact origins within the click before persisting credentials", async () => {
  const calls = [];
  const chrome = {
    storage: { local: { get(keys, callback) { callback({}); }, async set(value) { calls.push(["save", value]); } } },
    permissions: { request(value) { calls.push(["permission", value]); return Promise.resolve(true); } },
    runtime: { sendMessage(message, callback) { if (callback) callback({}); else return Promise.resolve({ ok: true }); } }
  };
  const page = pageFixture("options", chrome);
  page.element("host").value = HOST;
  page.element("user").value = "example-user";
  page.element("pass").value = "example-pass";
  page.element("save").click();
  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], "permission");
  assert.deepEqual(Array.from(calls[0][1].origins), policy.requiredOrigins(HOST));
  await settle();
  assert.equal(calls[1][0], "save");
});

test("denying host access leaves stored credentials and route unchanged", async () => {
  let writes = 0;
  const chrome = {
    storage: { local: { get(keys, callback) { callback({}); }, async set() { writes++; } } },
    permissions: { request() { return Promise.resolve(false); } },
    runtime: { sendMessage(message, callback) { if (callback) callback({}); else throw new Error("must not apply denied settings"); } }
  };
  const page = pageFixture("options", chrome);
  page.element("host").value = HOST;
  page.element("save").click();
  await settle();
  assert.equal(writes, 0);
  assert.match(page.element("status").textContent, /не разрешён/);
});

test("popup does not claim protection from health success without a ready proxy", () => {
  const chrome = {
    runtime: { sendMessage(message, callback) { callback(message.type === "health" ? { ok: true } : { host: HOST, granted: true, fingerprint: true, proxyReady: false }); } },
    tabs: { create() { throw new Error("must not open automatically"); } }
  };
  const page = pageFixture("popup", chrome);
  assert.equal(page.element("open").disabled, true);
  assert.match(page.element("status-text").textContent, /не готов/);
});

test("gateway permissions support custom TLS ports while network exceptions stay authority-bound", () => {
  const host = HOST + ":8443";
  assert.equal(policy.requiredOrigins(host)[0], "https://" + HOST + "/*");
  assert.equal(policy.fingerprintMatches(host)[0], "https://" + HOST + "/*");
  const allow = policy.buildPrivacyRules(host).find(rule => rule.id === 2001);
  assert.equal(applies(allow, request("https://" + host + "/")), true);
  assert.equal(applies(allow, request("https://" + HOST + "/")), false);
  assert.equal(applies(allow, request("https://" + HOST + ":9443/")), false);
});


test("profile restriction remains available independently of malformed gateway settings", () => {
  const rules = policy.buildProfileRestrictionRules();
  assert.deepEqual(rules.map(rule => rule.id), [2002, 2005]);
  for (const type of ["main_frame", "object", "webtransport", "script"]) assert(rules.some(rule => applies(rule, request("https://unapproved.example.test/exfil", type, "null"))));
  assert.throws(() => policy.buildPrivacyRules("bad host"), /Invalid gateway/);
});
