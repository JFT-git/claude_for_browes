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

function pageFixture(name, chrome, browser) {
  const fs = require("node:fs");
  const vm = require("node:vm");
  const elements = new Map();
  const element = id => {
    if (!elements.has(id)) elements.set(id, { value: "", textContent: "", style: {}, hidden: true, disabled: false, addEventListener(type, fn) { this[type] = fn; } });
    return elements.get(id);
  };
  const markup = fs.readFileSync(require("node:path").join(__dirname, "../extension/" + name + ".html"), "utf8");
  const hints = [...markup.matchAll(/<p\b[^>]*\bdata-browser="([a-z]+)"([^>]*)>([\s\S]*?)<\/p>/g)]
    .map(([, browser, rest, text]) => ({ dataset: { browser }, hidden: /\bhidden\b/.test(rest), textContent: text }));
  const context = vm.createContext({ chrome, ...(browser ? { browser } : {}), GatewayPrivacy: policy, document: { getElementById: element, querySelectorAll: () => hints }, setTimeout: () => 1, clearTimeout() {} });
  vm.runInContext(fs.readFileSync(require("node:path").join(__dirname, "../extension/" + name + ".js"), "utf8"), context);
  return { element, hints, evaluate: expression => vm.runInContext(expression, context) };
}
function firefoxApi({ status = {}, statusSequence, apply = { ok: true }, health = { ok: true }, stored = {} } = {}) {
  const chrome = { runtime: { getManifest() { return { browser_specific_settings: { gecko: { id: "test@example" } } }; } } };
  const states = statusSequence ? [...statusSequence] : null;
  const browser = {
    runtime: {
      getManifest() { return chrome.runtime.getManifest(); },
      async sendMessage(message) {
        if (message.type === "status") return states?.shift() || status;
        if (message.type === "apply") return apply;
        if (message.type === "health") return health;
        throw new Error("unexpected message: " + message.type);
      }
    },
    permissions: { async request() { return true; } },
    storage: { local: { async get() { return stored; }, async set() {} } },
    tabs: { async create() {} }
  };
  return { chrome, browser };
}
const settle = () => new Promise(resolve => setImmediate(resolve));

test("settings requests exact origins within the click before persisting credentials", async () => {
  const calls = [];
  const chrome = {
    storage: { local: { get(keys, callback) { callback({}); }, set(value, callback) { calls.push(["save", value]); callback(); } } },
    permissions: { request(value, callback) { calls.push(["permission", value]); callback(true); } },
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
    permissions: { request(value, callback) { callback(false); } },
    runtime: { sendMessage(message, callback) { if (callback) callback({}); else throw new Error("must not apply denied settings"); } }
  };
  const page = pageFixture("options", chrome);
  page.element("host").value = HOST;
  page.element("save").click();
  await settle();
  assert.equal(writes, 0);
  assert.match(page.element("status").textContent, /не разрешён/);
});

test("Firefox Options explain the Claude-only scope and distinguish platform and auth failures", () => {
  const { chrome, browser } = firefoxApi();
  const page = pageFixture("options", chrome, browser);
  const shown = page.hints.filter(hint => !hint.hidden);
  assert(shown.length > 0);
  assert(shown.every(hint => hint.dataset.browser === "firefox"));
  assert(shown.some(hint => /только Claude/.test(hint.textContent)));
  for (const hint of shown) assert.doesNotMatch(hint.textContent, /блокируются во всём профиле|отдельный профиль браузера для Claude/i);

  const unsupported = page.evaluate('routeReasonText("firefox_android_unsupported", "firefox")');
  const authFailed = page.evaluate('routeReasonText("auth_failed", "firefox")');
  const notReady = page.evaluate('routeReasonText("", "firefox")');
  assert.match(unsupported, /Firefox для Android не поддерживается/);
  assert.match(authFailed, /Проверьте имя пользователя и пароль/);
  assert.match(notReady, /другие сайты работают как обычно/);
  assert.notEqual(unsupported, authFailed);
  assert.doesNotMatch(authFailed, /example-pass|token|bearer/i);
});

test("Chromium Options keep the dedicated-profile guidance", () => {
  const chrome = { runtime: { getManifest() { return {}; }, sendMessage(message, callback) { callback({}); } }, storage: { local: { get(keys, callback) { callback({}); } } } };
  const page = pageFixture("options", chrome);
  const shown = page.hints.filter(hint => !hint.hidden);
  assert(shown.length > 0);
  assert(shown.every(hint => hint.dataset.browser === "chromium"));
});

test("Firefox Options save flow displays actionable categorized failures without credentials", async () => {
  async function run({ apply, health, state }) {
    const { chrome, browser } = firefoxApi({ apply, health, status: state });
    const page = pageFixture("options", chrome, browser);
    page.element("host").value = HOST;
    page.element("user").value = "private-test-user";
    page.element("pass").value = "secret-test-password";
    page.element("save").click();
    await settle(); await settle(); await settle();
    return page.element("status").textContent;
  }

  const state = reason => ({ host: HOST, granted: true, proxyPlatform: "firefox", proxyReason: reason, proxyReady: false, fingerprint: false });
  const unsupported = await run({ apply: { ok: false, reason: "firefox_android_unsupported" }, state: state("firefox_android_unsupported") });
  const authFailed = await run({ apply: { ok: true }, health: { ok: false, reason: "auth_failed" }, state: state("auth_failed") });
  const baselineFailed = await run({ apply: { ok: false, reason: "proxy_baseline_unavailable" }, state: state("proxy_baseline_unavailable") });

  assert.match(unsupported, /Firefox для Android не поддерживается/);
  assert.match(authFailed, /Шлюз отклонил вход/);
  assert.match(baselineFailed, /защищённый маршрут Claude/);
  for (const message of [unsupported, authFailed, baselineFailed]) {
    assert.doesNotMatch(message, /about:addons|приватных окнах/);
    assert.doesNotMatch(message, /private-test-user|secret-test-password|bearer|token/i);
  }
});

test("Options marks a route active only when health, proxy, and fingerprint are exactly true", () => {
  const { chrome, browser } = firefoxApi();
  const page = pageFixture("options", chrome, browser);
  assert.equal(page.evaluate('isRouteReady({ok:true}, {proxyReady:true, fingerprint:true})'), true);
  assert.equal(page.evaluate('isRouteReady({ok:false}, {proxyReady:true, fingerprint:true})'), false);
  assert.equal(page.evaluate('isRouteReady({ok:true}, {proxyReady:false, fingerprint:true})'), false);
  assert.equal(page.evaluate('isRouteReady({ok:true}, {proxyReady:true, fingerprint:"true"})'), false);
});

test("Options refresh requires successful health before claiming a ready route", async () => {
  const state = { host: HOST, granted: true, proxyPlatform: "firefox", proxyReady: true, fingerprint: true, proxyReason: "" };
  const { chrome, browser } = firefoxApi({ status: state, health: { ok: false, reason: "auth_failed" }, stored: { gatewayHost: HOST } });
  const page = pageFixture("options", chrome, browser);
  await settle(); await settle();
  assert.match(page.element("perm-status").textContent, /Шлюз отклонил вход/);
  assert.doesNotMatch(page.element("perm-status").textContent, /маршрут активен/);
});

test("Chrome MV3 popup uses callback APIs and does not claim protection without a ready proxy", async () => {
  const chrome = {
    runtime: { sendMessage(message, callback) { callback(message.type === "health" ? { ok: true } : { host: HOST, granted: true, fingerprint: true, proxyReady: false }); } },
    tabs: { create() { throw new Error("must not open automatically"); } }
  };
  const page = pageFixture("popup", chrome);
  await settle(); await settle();
  assert.equal(page.element("open").disabled, true);
  assert.match(page.element("status-text").textContent, /не готов/);
});

test("Firefox MV2 popup uses browser promise APIs and requires health plus route readiness", async () => {
  const state = { host: HOST, granted: true, proxyPlatform: "firefox", fingerprint: true, proxyReady: true, artifactDebugger: { available: true, active: true, attachedTabs: 0 } };
  const { chrome, browser } = firefoxApi({ status: state, health: { ok: true } });
  const page = pageFixture("popup", chrome, browser);
  await settle(); await settle(); await settle();
  assert.equal(page.element("open").disabled, false);
  assert.match(page.element("status-text").textContent, /маршрут активен/);
  assert.match(page.element("debugger-note").textContent, /native header handling/);
});

test("Firefox MV2 popup keeps requests blocked when health fails", async () => {
  const state = { host: HOST, granted: true, proxyPlatform: "firefox", fingerprint: true, proxyReady: true };
  const { chrome, browser } = firefoxApi({ status: state, health: { ok: false, reason: "auth_failed" } });
  const page = pageFixture("popup", chrome, browser);
  await settle(); await settle();
  assert.equal(page.element("open").disabled, true);
  assert.match(page.element("status-text").textContent, /Шлюз отклонил вход/);
});

test("Firefox MV2 popup retries a transient secure-route failure", async () => {
  const initial = { host: HOST, granted: true, proxyPlatform: "firefox", fingerprint: true, proxyReady: false, proxyReason: "secure_proxy_unavailable" };
  const ready = { host: HOST, granted: true, proxyPlatform: "firefox", fingerprint: true, proxyReady: true, proxyReason: "" };
  const { chrome, browser } = firefoxApi({ statusSequence: [initial, ready], health: { ok: true } });
  const page = pageFixture("popup", chrome, browser);
  await settle(); await settle(); await settle();
  assert.equal(page.element("open").disabled, false);
  assert.match(page.element("status-text").textContent, /маршрут активен/);
});

test("Options refresh retries a transient secure-route failure", async () => {
  const initial = { host: HOST, granted: true, proxyPlatform: "firefox", fingerprint: true, proxyReady: false, proxyReason: "secure_proxy_unavailable" };
  const ready = { host: HOST, granted: true, proxyPlatform: "firefox", fingerprint: true, proxyReady: true, proxyReason: "" };
  const { chrome, browser } = firefoxApi({ statusSequence: [initial, ready], health: { ok: true }, stored: { gatewayHost: HOST } });
  const page = pageFixture("options", chrome, browser);
  await settle(); await settle(); await settle();
  assert.match(page.element("perm-status").textContent, /маршрут активен/);
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

test("Firefox scoped rules restrict gateway and artifact initiators without touching other sites", () => {
  const scoped = (req, extra = []) => [...policy.buildPrivacyRules(HOST, policy.RESOURCE_TYPES, { scoped: true }), ...extra]
    .filter(rule => rule.action.type !== "modifyHeaders" && applies(rule, req)).sort((a, b) => b.priority - a.priority)[0]?.action.type || "unmatched";
  const rules = policy.buildPrivacyRules(HOST, policy.RESOURCE_TYPES, { scoped: true });
  assert.equal(rules.some(rule => rule.id === 2005), false);
  assert(rules.filter(rule => rule.action.type === "block" && rule.id !== 2004).every(rule => rule.condition.initiatorDomains?.includes(HOST)));
  for (const origin of ["https://" + HOST, "https://a.frame.claudeusercontent.com", "https://a.claudemcpcontent.com"]) {
    for (const type of ["sub_frame", "xmlhttprequest", "script", "image", "websocket", "ping"]) {
      const scheme = type === "websocket" ? "wss" : "https";
      assert.equal(scoped(request(scheme + "://unapproved.example.test/exfil", type, origin), readyRoute), "block", type + " from " + origin);
      assert.equal(scoped(request("http://unapproved.example.test/exfil", type, origin), readyRoute), "block");
    }
    assert.equal(scoped(request("https://cdn.jsdelivr.net/npm/x.js", "script", origin)), "block");
    assert.equal(scoped(request("https://cdn.jsdelivr.net/npm/x.js", "script", origin), readyRoute), "allow");
  }
  // Ordinary browsing, including shared CDNs, cleartext sites and links opened from Claude.
  for (const req of [request("https://fonts.googleapis.com/css", "stylesheet", "https://news.example.org"),
    request("https://cdn.jsdelivr.net/npm/x.js", "script", "https://news.example.org"),
    request("http://intranet.example.test/", "xmlhttprequest", "http://intranet.example.test"),
    request("https://unapproved.example.test/", "xmlhttprequest", "null"),
    request("https://docs.example.org/", "main_frame", "https://" + HOST)]) assert.equal(scoped(req), "unmatched", req.url);
  assert.equal(scoped(request("https://" + HOST + "/api", "xmlhttprequest")), "allow");
  for (const host of policy.UPSTREAM_HOSTS) assert.equal(scoped(request("wss://" + host + "/socket", "websocket"), readyRoute), "block");
});

test("Firefox packaged blocks cover Claude hosts only, not CDNs shared with other sites", () => {
  const fs = require("node:fs"), path = require("node:path");
  const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, "../extension/manifest.firefox.json"), "utf8"));
  const blocks = JSON.parse(fs.readFileSync(path.join(__dirname, "../extension/" + manifest.declarative_net_request.rule_resources[0].path), "utf8"));
  const domains = new Set(blocks.flatMap(rule => rule.condition.requestDomains));
  assert.deepEqual([...domains].sort(), [...policy.ARTIFACT_DOMAINS, ...policy.UPSTREAM_HOSTS].sort());
  for (const host of policy.DEPENDENCY_HOSTS) assert.equal(domains.has(host), false, host);
});
