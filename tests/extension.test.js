"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { webcrypto, createHash } = require("node:crypto");

// Exercise shipped logic; native tests separately verify browser API semantics.
function backgroundFixture({ failRegistration = false, firefox = false, savedSession, fetchHook, storageHook, warmupHook, savedCandidate } = {}) {
  const config = { gatewayHost: "gateway.example.test", authUser: "test-user", authPass: "test-password" };
  const rules = new Map(), sessionRules = new Map(), scripts = new Map(), alarms = new Map();
  const sessionStorage = savedSession ? { proxySession: savedSession } : {};
  if (savedCandidate) sessionStorage.proxySessionCandidate = savedCandidate;
  const calls = { register: 0, update: 0, fetch: [], order: [], dynamicSnapshots: [] };
  const event = () => ({ listeners: [], addListener(fn) { this.listeners.push(fn); }, emit(...args) { return this.listeners.map(fn => fn(...args)); } });
  let permission = true;
  let installedProxy = { levelOfControl: "controlled_by_this_extension", value: {} };
  let installedPrediction = { levelOfControl: "controlled_by_this_extension", value: true };
  let installedRTC = { levelOfControl: "controlled_by_this_extension", value: "default" };
  const proxyChange = event(), rtcChange = event(), predictionChange = event();
  const chrome = {
    storage: {
      local: { get: async () => ({ ...config }) },
      session: { get: async () => ({ ...sessionStorage }), set: async data => { if (storageHook) await storageHook(data); Object.assign(sessionStorage, data); }, remove: async key => { delete sessionStorage[key]; } },
      onChanged: event()
    },
    declarativeNetRequest: {
      updateDynamicRules: async ({ removeRuleIds = [], addRules = [] }) => { removeRuleIds.forEach(id => rules.delete(id)); addRules.forEach(rule => rules.set(rule.id, rule)); calls.dynamicSnapshots.push([...rules.keys()]); },
      getDynamicRules: async () => [...rules.values()],
      updateSessionRules: async ({ removeRuleIds = [], addRules = [] }) => { calls.order.push(addRules.some(rule => rule.id === 2000) ? "allow" : addRules.length ? "warmup" : "block"); removeRuleIds.forEach(id => sessionRules.delete(id)); addRules.forEach(rule => sessionRules.set(rule.id, rule)); }
    },
    scripting: {
      registerContentScripts: async definitions => { calls.register++; if (failRegistration) throw new Error("synthetic API failure"); for (const script of definitions) { if ("matchAboutBlank" in script) throw new Error("unsupported field"); if (scripts.has(script.id)) throw new Error("duplicate"); scripts.set(script.id, script); } },
      updateContentScripts: async definitions => { calls.update++; definitions.forEach(script => scripts.set(script.id, script)); },
      getRegisteredContentScripts: async () => [...scripts.values()],
      unregisterContentScripts: async ({ ids }) => ids.forEach(id => scripts.delete(id))
    },
    privacy: { network: { networkPredictionEnabled: {
      set: async ({ value }) => { installedPrediction = { value, levelOfControl: "controlled_by_this_extension" }; predictionChange.emit(installedPrediction); },
      get: async () => installedPrediction, clear: async () => { installedPrediction = { value: true, levelOfControl: "controllable_by_this_extension" }; predictionChange.emit(installedPrediction); }, onChange: predictionChange
    }, webRTCIPHandlingPolicy: {
      set: async ({ value }) => { installedRTC = { value, levelOfControl: "controlled_by_this_extension" }; rtcChange.emit(installedRTC); },
      get: async () => installedRTC, clear: async () => { installedRTC = { value: "default", levelOfControl: "controllable_by_this_extension" }; rtcChange.emit(installedRTC); }, onChange: rtcChange
    } } },
    proxy: { settings: {
      set: async ({ value }) => { calls.order.push("pac"); installedProxy = { value, levelOfControl: "controlled_by_this_extension" }; proxyChange.emit(installedProxy); },
      get: async () => installedProxy,
      clear: async () => { calls.order.push("clear"); installedProxy = { value: { mode: "direct" }, levelOfControl: "controllable_by_this_extension" }; proxyChange.emit(installedProxy); }, onChange: proxyChange
    } },
    alarms: { create: async (name, value) => { alarms.set(name, value); }, clear: async name => alarms.delete(name), onAlarm: event() },
    permissions: { contains: async () => permission, onAdded: event(), onRemoved: event() },
    runtime: { id: "test-extension", onMessage: event(), onInstalled: event(), onStartup: event() },
    webRequest: { onAuthRequired: event(), onCompleted: event(), onErrorOccurred: event() }
  };
  const now = { value: Date.now() };
  const sampleSession = (overrides = {}) => ({ proxyUsername: "gateway-proxy", proxyPassword: "A".repeat(43), expiresAt: now.value + 900000, proxy: { scheme: "https", host: "proxy.example.test", port: 8443 }, ...overrides });
  const context = vm.createContext({ chrome, browser: firefox ? { proxy: { onRequest: event() } } : undefined, URL, TextEncoder, AbortController, crypto: webcrypto,
    Date: class extends Date { static now() { return now.value; } },
    btoa: text => Buffer.from(text, "latin1").toString("base64"), setTimeout: () => 1, clearTimeout() {}, console: { error() {} },
    fetch: async (url, options) => {
      calls.fetch.push({ url, options });
      if (options?.method === "HEAD") {
        const authenticate = () => {
          context.warmAuth = { isProxy: true, url, method: "HEAD", initiator: "chrome-extension://test-extension", challenger: vm.runInContext("({...proxyWarmup.session.proxy})", context), scheme: "basic", realm: "gateway-proxy", requestId: "warmup-" + calls.fetch.length };
          const result = vm.runInContext("onProxyAuth(warmAuth)", context);
          chrome.webRequest.onCompleted.emit({ requestId: context.warmAuth.requestId });
          return result;
        };
        if (warmupHook) return warmupHook({ url, options, authenticate, context });
        authenticate(); return { status: 200 };
      }
      if (fetchHook) return fetchHook(url, options, sampleSession);
      return { status: 200, json: async () => url.endsWith("/__proxy-session") ? sampleSession() : { session: "ok", users: 1 } };
    }
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname, "../extension/privacy-rules.js"), "utf8"), context);
  const source = fs.readFileSync(path.join(__dirname, "../extension/background.js"), "utf8");
  vm.runInContext(source.replace(/\ninitialize\(\)\.catch\(\(\) => \{\}\);\s*$/, "\n"), context);
  return { context, config, rules, sessionRules, scripts, calls, alarms, chrome, now, sampleSession, sessionStorage,
    revokePermission() { permission = false; chrome.permissions.onRemoved.emit({ origins: ["https://gateway.example.test/*"] }); },
    loseProxy() { installedProxy = { value: { mode: "direct" }, levelOfControl: "controlled_by_other_extensions" }; proxyChange.emit(installedProxy); },
    losePrediction() { installedPrediction = { value: true, levelOfControl: "controlled_by_other_extensions" }; predictionChange.emit(installedPrediction); },
    loseRTC() { installedRTC = { value: "default", levelOfControl: "controlled_by_other_extensions" }; rtcChange.emit(installedRTC); },
    run: expression => vm.runInContext(expression, context), flush: () => vm.runInContext("operationQueue", context) };
}
const binding = cfg => createHash("sha256").update(JSON.stringify([cfg.gatewayHost, cfg.authUser, cfg.authPass])).digest("hex");
const authDetails = overrides => ({ isProxy: true, url: "https://a.frame.claudeusercontent.com/", challenger: { host: "proxy.example.test", port: 8443 }, scheme: "basic", realm: "gateway-proxy", requestId: "r1", ...overrides });
function auth(f, overrides) { f.context.authInput = authDetails(overrides); return f.run("onProxyAuth(authInput)"); }
const plain = value => JSON.parse(JSON.stringify(value));

for (const browser of ["chrome", "firefox"]) test(browser + " manifest ships startup blocks and required security capabilities", () => {
  const m = JSON.parse(fs.readFileSync(path.join(__dirname, "../extension/manifest." + browser + ".json")));
  for (const permission of ["privacy", "alarms", "proxy", "webRequest", "declarativeNetRequest"]) assert(m.permissions.includes(permission));
  assert(m.host_permissions.includes("https://*.claudeusercontent.com/*"));
  assert.equal(m.declarative_net_request.rule_resources[0].enabled, true);
  const blocks = JSON.parse(fs.readFileSync(path.join(__dirname, "../extension/" + m.declarative_net_request.rule_resources[0].path)));
  const block = blocks[0];
  assert(blocks.some(rule => rule.condition.resourceTypes?.includes("main_frame")));
  assert.equal(block.priority, 100);
  assert.deepEqual(block.condition.excludedResourceTypes, []);
  const expression = new RegExp(block.condition.regexFilter);
  const matcher = { test(value) { const host = new URL(value).hostname; return expression.test(value) && block.condition.requestDomains.some(domain => host === domain || host.endsWith("." + domain)); } };
  assert(block.condition.regexFilter.length < 30);
  for (const url of ["https://a.frame.claudeusercontent.com/", "https://claudemcpcontent.com/", "https://cdn.jsdelivr.net:8443/a", "http://esm.sh/", "wss://fonts.gstatic.com/", "https://claude.ai/", "https://api.anthropic.com/", "https://assets.claude.ai/"]) assert(matcher.test(url), url);
  assert.equal(matcher.test("https://cdn.jsdelivr.net.evil.test/"), false);
  if (browser === "chrome") assert.equal(m.minimum_chrome_version, "125");
  else { assert.equal(m.browser_specific_settings.gecko.strict_min_version, "140.0"); assert(m.permissions.includes("webRequestBlocking")); }
});

test("Basic credentials match only the exact HTTPS authority, including port", () => {
  const f = backgroundFixture();
  const rule = f.run('buildAuthRule("gateway.example.test", "test-user", "test-password")');
  const matches = new RegExp(rule.condition.regexFilter, "i");
  assert(matches.test("https://gateway.example.test/api/messages"));
  for (const url of ["https://gateway.example.test.evil.test/", "https://sub.gateway.example.test/", "https://gatewayXexampleXtest/", "https://evil.test/?next=https://gateway.example.test/", "https://gateway.example.test@evil.test/", "https://gateway.example.test:8443/", "http://gateway.example.test/", "wss://gateway.example.test/"]) assert.equal(matches.test(url), false, url);
  assert.equal(rule.condition.urlFilter, undefined);
  assert(new RegExp(f.run('buildAuthRule("gateway.example.test:9443", "u", "p").condition.regexFilter')).test("https://gateway.example.test:9443/"));
});

test("Basic credentials preserve UTF-8", () => {
  const result = backgroundFixture().run('basicHeader("test-user", "пароль-🔒")');
  assert.equal(Buffer.from(result.slice(6), "base64").toString("utf8"), "test-user:пароль-🔒");
});

test("MAIN fingerprint registration uses native-supported fields and updates in place", async () => {
  const f = backgroundFixture();
  assert.equal((await f.run("applyRules()")).ok, true);
  assert.equal((await f.run("applyRules()")).ok, true);
  const script = f.scripts.get("fingerprint");
  for (const [key, value] of Object.entries({ world: "MAIN", runAt: "document_start", allFrames: true, matchOriginAsFallback: true })) assert.equal(script[key], value);
  assert.equal("matchAboutBlank" in script, false);
  assert(script.matches.includes("https://gateway.example.test/*"));
  assert(script.matches.includes("https://*.claudeusercontent.com/*"));
  assert.equal(f.calls.register, 1); assert.equal(f.calls.update, 1);
});

test("fingerprint registration failure blocks proxy activation", async () => {
  const f = backgroundFixture({ failRegistration: true });
  const result = await f.run("initialize()");
  assert.equal(result.ok, false); assert.equal(result.reason, "fingerprint_registration_failed");
  assert.equal(f.sessionRules.size, 0); assert.equal(f.run("sessionUsable()"), false);
});

test("empty credentials remove the previous Basic rule and OAuth rules stay retired", async () => {
  const f = backgroundFixture(); f.rules.set(10, { id: 10 }); f.rules.set(11, { id: 11 });
  await f.run("applyRules()"); assert(f.rules.has(1000)); assert.equal(f.rules.has(10), false); assert.equal(f.rules.has(11), false);
  f.config.authPass = ""; await f.run("applyRules()"); assert.equal(f.rules.has(1000), false);
  for (const rule of f.rules.values()) assert.doesNotMatch(rule.condition.regexFilter || "", /accounts\\\.google|appleid\\\.apple/);
});

test("session POST is cookie-free, rejects redirects and discovers HTTPS proxy from gateway", async () => {
  const f = backgroundFixture(); assert.equal((await f.run("initialize()")).ok, true);
  assert.deepEqual(f.calls.fetch.filter(x => x.options.method !== "HEAD").map(x => x.url), ["https://gateway.example.test/__health", "https://gateway.example.test/__proxy-session"]);
  for (const { options } of f.calls.fetch.filter(x => x.options.method !== "HEAD")) { assert.equal(options.redirect, "error"); assert.equal(options.credentials, "omit"); }
  const options = f.calls.fetch[1].options;
  assert.equal(options.method, "POST"); assert.equal(options.headers["X-Gateway-Proxy-Session"], "1");
  assert.equal(options.headers.Authorization, "Basic " + Buffer.from("test-user:test-password").toString("base64"));
  assert.equal(f.run("proxySession.proxy.host"), "proxy.example.test");
  assert(f.calls.order.indexOf("pac") < f.calls.order.indexOf("allow"));
  assert.equal(f.sessionRules.get(2000).priority, 200);
  assert.equal(f.sessionRules.size, 10);
  for (const rule of f.sessionRules.values()) assert(rule.condition.regexFilter.length < 80);
  assert(f.alarms.has("proxy-refresh")); assert(f.alarms.has("proxy-expire"));
  const pac = f.run("proxyPac(proxySession)");
  const pacContext = vm.createContext({ dnsDomainIs: (host, domain) => host.endsWith(domain) }); vm.runInContext(pac, pacContext);
  assert.equal(vm.runInContext('FindProxyForURL("https://a.frame.claudeusercontent.com/", "a.frame.claudeusercontent.com")', pacContext), "HTTPS proxy.example.test:8443");
  assert.equal(vm.runInContext('FindProxyForURL("https://example.net/", "example.net")', pacContext), "HTTPS 127.0.0.1:9");
  assert.equal(vm.runInContext('FindProxyForURL("https://gateway.example.test/", "gateway.example.test")', pacContext), "DIRECT");
  for (const url of ["https://gateway.example.test.evil/", "http://gateway.example.test/", "https://gateway.example.test:8443/", "https://a.frame.claudeusercontent.com:8443/", "http://esm.sh/"]) {
    pacContext.testURL = url;
    assert.equal(vm.runInContext('FindProxyForURL(testURL, "irrelevant")', pacContext), "HTTPS 127.0.0.1:9");
  }
});

test("invalid or cleartext proxy metadata never opens the block", async () => {
  for (const overrides of [{ proxyUsername: "test-user" }, { proxyPassword: "short" }, { expiresAt: Date.now() - 1 }, { proxy: { scheme: "http", host: "proxy.example.test", port: 8080 } }, { proxy: { scheme: "https", host: 'evil.test; DIRECT', port: 443 } }]) {
    const f = backgroundFixture({ fetchHook: async (url, options, sample) => ({ status: 200, json: async () => url.endsWith("/__proxy-session") ? sample(overrides) : {} }) });
    assert.equal((await f.run("initialize()")).ok, false); assert.equal(f.sessionRules.size, 0);
  }
});

test("proxy auth uses session credentials only for exact proxy and intended TLS target, once", async () => {
  const f = backgroundFixture(); await f.run("initialize()");
  for (const overrides of [{ isProxy: false }, { challenger: { host: "other.example.test", port: 8443 } }, { challenger: { host: "proxy.example.test", port: 443 } }, { url: "https://a.frame.claudeusercontent.com:8443/" }, { url: "http://a.frame.claudeusercontent.com/" }, { realm: "other" }, { scheme: "digest" }, { url: "https://unrelated.test/" }]) assert.equal(auth(f, overrides).authCredentials, undefined);
  assert.deepEqual(plain(auth(f)), { authCredentials: { username: "gateway-proxy", password: "A".repeat(43) } });
  f.now.value += 121000; assert.deepEqual(plain(auth(f)), { cancel: true });
  f.chrome.webRequest.onCompleted.emit({ requestId: "r1" }); assert(auth(f).authCredentials);
  f.chrome.webRequest.onErrorOccurred.emit({ requestId: "r1" }); assert.equal(f.run("authAttempts.size"), 0);
});

test("auth attempts are bounded without evicting a live request retry guard", async () => {
  const f = backgroundFixture(); await f.run("initialize()");
  for (let i = 0; i < 1000; i++) assert(auth(f, { requestId: "req" + i }).authCredentials);
  assert.deepEqual(plain(auth(f, { requestId: "overflow" })), { cancel: true });
  assert.deepEqual(plain(auth(f, { requestId: "req0" })), { cancel: true });
  assert.equal(f.run("authAttempts.size"), 1000);
});

for (const change of ["loseProxy", "loseRTC", "losePrediction", "revokePermission"]) test(change + " immediately closes session allowance", async () => {
  const f = backgroundFixture(); await f.run("initialize()"); assert(f.sessionRules.has(2000));
  f[change](); assert.equal(f.run("sessionUsable()"), false); assert.equal(f.sessionRules.size, 0);
  await f.flush(); assert.equal(f.sessionStorage.proxySession, undefined);
});

for (const loss of ["loseProxy", "loseRTC", "losePrediction"]) test(loss + " during asynchronous route installation cannot activate allow", async () => {
  let release, entered; const reached = new Promise(resolve => { entered = resolve; });
  const f = backgroundFixture({ storageHook: async () => { entered(); await new Promise(resolve => { release = resolve; }); } });
  const installing = f.run("initialize()"); await reached; f[loss](); release();
  assert.equal((await installing).ok, false); await f.flush(); assert.equal(f.sessionRules.size, 0);
});

test("expiry closes the route and refresh obtains a new session before expiration", async () => {
  const f = backgroundFixture(); await f.run("initialize()");
  f.now.value += 850000; f.chrome.alarms.onAlarm.emit({ name: "proxy-refresh" }); await f.flush();
  assert.equal(f.calls.fetch.filter(x => x.url.endsWith("/__proxy-session")).length, 2);
  f.now.value = f.run("proxySession.expiresAt") + 1; f.chrome.alarms.onAlarm.emit({ name: "proxy-expire" }); await f.flush();
  assert.equal(f.sessionRules.size, 0); assert.equal(f.run("sessionUsable()"), false);
});

test("service-worker restore accepts only a live session bound to identical config", async () => {
  const cfg = { gatewayHost: "gateway.example.test", authUser: "test-user", authPass: "test-password" };
  const source = backgroundFixture();
  const saved = { ...source.sampleSession(), gatewayHost: cfg.gatewayHost, configBinding: binding(cfg), warmupVerified: true };
  const same = backgroundFixture({ savedSession: saved }); await same.run("initialize()"); assert.equal(same.calls.fetch.filter(call => call.options.method !== "HEAD").length, 0); assert(same.sessionRules.has(2000));
  const changed = backgroundFixture({ savedSession: { ...saved, configBinding: "wrong" } }); await changed.run("initialize()"); assert.equal(changed.calls.fetch.filter(call => call.options.method !== "HEAD").length, 2);
});

test("old async token response cannot resurrect route after credential change", async () => {
  let release, entered; const reached = new Promise(resolve => { entered = resolve; }); let first = true;
  const f = backgroundFixture({ fetchHook: async (url, options, sample) => { if (url.endsWith("/__proxy-session") && first) { first = false; entered(); await new Promise(resolve => { release = resolve; }); } return { status: 200, json: async () => url.endsWith("/__proxy-session") ? sample() : {} }; } });
  const old = f.run("initialize()"); await reached;
  f.config.authPass = "changed"; f.chrome.storage.onChanged.emit({ authPass: { newValue: "changed" } }, "local"); release();
  assert.equal((await old).ok, false); await f.flush();
  assert.equal(f.run("proxySession.configBinding"), binding(f.config)); assert(f.sessionRules.has(2000));
  assert.equal(f.calls.order.filter(x => x === "allow").length, 1);
});

test("Firefox keeps bundled block and rejects protected routes until failover is proven safe", async () => {
  const f = backgroundFixture({ firefox: true }); assert.equal((await f.run("initialize()")).ok, false);
  assert.equal(f.sessionRules.size, 0);
  await assert.rejects(f.run('firefoxProxyRequest({url:"https://a.frame.claudeusercontent.com/"})'), /Secure proxy routing unavailable/);
});


test("refresh safely rotates proxy endpoint without treating its own PAC as takeover", async () => {
  let minted = 0;
  const f = backgroundFixture({ fetchHook: async (url, options, sample) => ({ status: 200, json: async () => url.endsWith("/__proxy-session") ? sample({ proxy: { scheme: "https", host: ++minted === 1 ? "proxy.example.test" : "rotated.example.test", port: 8443 } }) : {} }) });
  await f.run("initialize()"); f.now.value += 850000;
  assert.equal((await f.run("healthCheck()")).ok, true);
  assert.equal(f.run("proxySession.proxy.host"), "rotated.example.test"); assert(f.sessionRules.has(2000));
  assert.equal(auth(f).authCredentials, undefined);
  assert(auth(f, { challenger: { host: "rotated.example.test", port: 8443 } }).authCredentials);
});

test("disable restores prior privacy controls and removes profile restriction", async () => {
  const f = backgroundFixture(); await f.run("initialize()");
  assert.equal((await f.chrome.privacy.network.networkPredictionEnabled.get()).value, false);
  await f.run("clearAll()");
  assert.equal(f.rules.size, 0); assert.equal(f.sessionRules.size, 0); assert.equal(f.scripts.size, 0);
  assert.equal((await f.chrome.privacy.network.networkPredictionEnabled.get()).value, true);
  assert.equal((await f.chrome.privacy.network.webRTCIPHandlingPolicy.get()).value, "default");
});


for (const host of ["changed.example.test", "malformed gateway host"]) test("configured reconfigure preserves global deny through every mutation: " + host, async () => {
  const f = backgroundFixture(); await f.run("initialize()");
  const before = f.calls.dynamicSnapshots.length;
  f.config.gatewayHost = host;
  f.chrome.storage.onChanged.emit({ gatewayHost: { newValue: host } }, "local"); await f.flush();
  const mutations = f.calls.dynamicSnapshots.slice(before);
  assert(mutations.length > 0);
  for (const ids of mutations) { assert(ids.includes(2002), JSON.stringify(ids)); assert(ids.includes(2005), JSON.stringify(ids)); }
  assert.equal((await f.chrome.privacy.network.networkPredictionEnabled.get()).value, false);
  if (host.startsWith("malformed")) { assert.equal(f.sessionRules.size, 0); assert.equal(f.run("sessionUsable()"), false); }
});

test("only explicitly empty gateway configuration releases profile restriction", async () => {
  const f = backgroundFixture(); await f.run("initialize()");
  f.config.gatewayHost = ""; f.chrome.storage.onChanged.emit({ gatewayHost: { newValue: "" } }, "local"); await f.flush();
  assert.equal(f.rules.size, 0); assert.equal(f.sessionRules.size, 0);
  assert.equal((await f.chrome.privacy.network.networkPredictionEnabled.get()).value, true);
});


test("permission revocation keeps profile deny and privacy through all cleanup mutations", async () => {
  const f = backgroundFixture(); await f.run("initialize()"); const before = f.calls.dynamicSnapshots.length;
  f.revokePermission(); await f.flush();
  for (const ids of f.calls.dynamicSnapshots.slice(before)) { assert(ids.includes(2002)); assert(ids.includes(2005)); }
  assert(f.rules.has(2002)); assert(f.rules.has(2005)); assert.equal(f.sessionRules.size, 0);
  const rtc = await f.chrome.privacy.network.webRTCIPHandlingPolicy.get();
  assert.equal(rtc.value, "disable_non_proxied_udp"); assert.equal(rtc.levelOfControl, "controlled_by_this_extension");
  assert.equal((await f.chrome.privacy.network.networkPredictionEnabled.get()).value, false);
});

function artifactDebuggerFixture({ rejectAttach = false, attachHook, detachHook, readHook, treeOverride, tabsOverride } = {}) {
  const event = () => ({ handlers: [], addListener(fn) { this.handlers.push(fn); }, emit(...args) { for (const fn of this.handlers) fn(...args); } });
  const tab = { id: 1, url: "https://gateway.example.test/chat/test" };
  const calls = [];
  let nativeAttached = false, ready = true, unsafeCount = 0, manager;
  const frameURL = "https://id.frame.claudeusercontent.com/frame";
  const normalTree = { frame: { id: "root", url: tab.url }, childFrames: [{ frame: { id: "artifact", parentId: "root", url: frameURL } }] };
  const chrome = {
    tabs: { query: async () => tabsOverride || [tab], get: async id => ({ ...((tabsOverride || [tab]).find(value => value.id === id) || tab) }), onUpdated: event(), onRemoved: event(), onCreated: event() },
    debugger: {
      onEvent: event(), onDetach: event(),
      attach: async source => { calls.push({ method: "attach", source }); if (rejectAttach) throw new Error("Another debugger owns tab"); if (attachHook) await attachHook(); nativeAttached = true; },
      detach: async source => { calls.push({ method: "detach", source }); if (detachHook) await detachHook(); nativeAttached = false; },
      sendCommand: async (source, method, params) => {
        calls.push({ source, method, params });
        if (!nativeAttached && !["IO.close", "Fetch.failRequest"].includes(method)) throw new Error("Debugger is not attached");
        if (method === "Page.getFrameTree") return { frameTree: source.sessionId ? { frame: { id: "artifact", url: frameURL } } : (treeOverride || normalTree) };
        if (method === "Fetch.takeResponseBodyAsStream") return { stream: "body-stream" };
        if (method === "IO.read") { if (readHook) await readHook(); return { data: '<script nonce="kept">window.artifact=true</script>', base64Encoded: false, eof: true }; }
        return {};
      }
    }
  };
  const context = vm.createContext({ chrome, URL, TextEncoder, Date, setTimeout, clearTimeout,
    btoa: text => Buffer.from(text, "latin1").toString("base64") });
  for (const file of ["privacy-rules.js", "artifact-csp.js", "artifact-debugger.js"]) vm.runInContext(fs.readFileSync(path.join(__dirname, "../extension/" + file), "utf8"), context);
  context.isReady = () => ready;
  context.onUnsafeDetach = () => { unsafeCount++; ready = false; manager.stop().catch(() => {}); };
  manager = vm.runInContext("GatewayArtifactDebugger.create({chrome,isReady,onUnsafeDetach})", context);
  const paused = (overrides = {}) => ({ requestId: "artifact-request", request: { url: frameURL }, frameId: "artifact", resourceType: "Document", responseStatusCode: 200,
    responseHeaders: [{ name: "Content-Security-Policy", value: "script-src 'nonce-kept'; frame-ancestors 'self' https://claude.ai; connect-src 'none'" }], ...overrides });
  return { chrome, manager, calls, tab, paused, frameURL, setReady(value) { ready = value; }, get unsafeCount() { return unsafeCount; },
    loseNative() { nativeAttached = false; chrome.debugger.onDetach.emit({ tabId: 1 }, "canceled_by_user"); },
    emit(source, method, params) { chrome.debugger.onEvent.emit(source, method, params); },
    async flush(until = () => true) { for (let i = 0; i < 30; i++) { await new Promise(resolve => setImmediate(resolve)); if (until()) return; } assert(until(), "debugger operation did not settle"); } };
}

test("debugger fulfills only an artifact descendant of the exact gateway and preserves explicit body/CSP", async () => {
  const f = artifactDebuggerFixture(); await f.manager.configure("gateway.example.test");
  assert.equal(f.manager.status().attachedTabs, 1);
  f.emit({ tabId: 1 }, "Fetch.requestPaused", f.paused());
  await f.flush(() => f.calls.some(call => call.method === "Fetch.fulfillRequest"));
  const fulfilled = f.calls.find(call => call.method === "Fetch.fulfillRequest").params;
  assert(Buffer.from(fulfilled.body, "base64").toString().includes('nonce="kept"'));
  assert.equal(fulfilled.responseHeaders[0].value, "script-src 'nonce-kept'; frame-ancestors 'self' https://claude.ai https://gateway.example.test; connect-src 'none'");
  assert(f.calls.some(call => call.method === "IO.close"));
  await f.manager.stop();
});

test("a pending artifact attachment keeps the gateway debugger and continues original response", async () => {
  const f = artifactDebuggerFixture(); await f.manager.configure("gateway.example.test");
  const gatewayURL = f.tab.url;
  f.tab.pendingUrl = f.frameURL + "/download.pdf";
  f.tab.url = f.tab.pendingUrl; // Chromium may expose the destination before disposition is resolved.
  f.chrome.tabs.onUpdated.emit(1, { status: "loading" }, f.tab);
  f.emit({ tabId: 1 }, "Fetch.requestPaused", f.paused({ frameId: "root", requestId: "download", responseHeaders: [
    { name: "Content-Disposition", value: 'attachment; filename="download.pdf"' },
    { name: "Content-Length", value: String(16 * 1024 * 1024) },
    { name: "Content-Security-Policy", value: "frame-ancestors 'none'" }
  ] }));
  await f.flush(() => f.calls.some(call => call.method === "Fetch.continueRequest"));
  assert.equal(f.calls.some(call => call.method === "detach"), false);
  assert.equal(f.calls.some(call => ["Fetch.takeResponseBodyAsStream", "Fetch.fulfillRequest"].includes(call.method)), false);
  f.tab.url = gatewayURL; delete f.tab.pendingUrl;
  f.emit({ tabId: 1 }, "Fetch.requestPaused", f.paused({ requestId: "next-preview" }));
  await f.flush(() => f.calls.some(call => call.method === "Fetch.fulfillRequest"));
  assert.equal(f.manager.status().attachedTabs, 1);
  await f.manager.stop();
});

test("only a positively identified root Document can bypass the pending navigation rewrite guard", async () => {
  const f = artifactDebuggerFixture(); await f.manager.configure("gateway.example.test");
  f.tab.pendingUrl = f.frameURL;
  f.emit({ tabId: 1 }, "Fetch.requestPaused", f.paused({ frameId: "root", requestId: "root-navigation" }));
  await f.flush(() => f.calls.some(call => call.method === "Fetch.continueRequest"));
  f.emit({ tabId: 1 }, "Fetch.requestPaused", f.paused({ frameId: "unknown", requestId: "unknown-subframe" }));
  await f.flush(() => f.calls.some(call => call.method === "Fetch.failRequest" && call.params.requestId === "unknown-subframe"));
  assert.equal(f.calls.some(call => call.method === "Fetch.fulfillRequest"), false);
  f.tab.url = f.frameURL; delete f.tab.pendingUrl;
  f.emit({ tabId: 1 }, "Page.frameNavigated", { frame: { id: "root", url: f.tab.url } });
  await f.flush(() => f.calls.some(call => call.method === "detach"));
  assert.equal(f.manager.status().attachedTabs, 0);
});

test("attachment passthrough rejects unknown sessions and actual committed foreign tabs", async () => {
  const f = artifactDebuggerFixture(); await f.manager.configure("gateway.example.test");
  const attachment = f.paused({ responseHeaders: [{ name: "Content-Disposition", value: "attachment" }] });
  f.emit({ tabId: 1, sessionId: "unknown" }, "Fetch.requestPaused", { ...attachment, requestId: "unknown-session" });
  await f.flush(() => f.calls.some(call => call.method === "Fetch.failRequest" && call.params.requestId === "unknown-session"));
  f.tab.url = "https://foreign.example.test/";
  f.emit({ tabId: 1 }, "Page.frameNavigated", { frame: { id: "root", url: f.tab.url } });
  f.emit({ tabId: 1 }, "Fetch.requestPaused", { ...attachment, requestId: "foreign-tab" });
  await f.flush(() => f.calls.some(call => call.method === "Fetch.failRequest" && call.params.requestId === "foreign-tab"));
  assert.equal(f.calls.some(call => call.method === "Fetch.continueRequest"), false);
  await f.manager.stop();
});

test("a transient foreign tab URL retains ownership only with an authoritative gateway root", async () => {
  for (const fails of [false, true]) {
    const f = artifactDebuggerFixture(); await f.manager.configure("gateway.example.test");
    const send = f.chrome.debugger.sendCommand;
    f.chrome.debugger.sendCommand = async (source, method, params) => {
      if (method === "Page.getFrameTree") {
        if (fails) throw new Error("Frame tree unavailable");
        return { frameTree: { frame: { id: "root", url: "https://foreign.example.test/" } } };
      }
      return send(source, method, params);
    };
    f.tab.pendingUrl = f.frameURL;
    f.chrome.tabs.onUpdated.emit(1, { status: "loading" }, f.tab);
    await f.flush(() => f.calls.some(call => call.method === "detach"));
    assert.equal(f.manager.status().attachedTabs, 0);
  }
});

test("debugger leaves foreign or opaque intermediate ancestor policies unchanged", async () => {
  for (const parent of ["https://other.example.test/", "about:srcdoc"]) {
    const f = artifactDebuggerFixture({ treeOverride: { frame: { id: "root", url: "https://gateway.example.test/" }, childFrames: [{ frame: { id: "foreign", parentId: "root", url: parent }, childFrames: [{ frame: { id: "artifact", parentId: "foreign", url: "https://id.frame.claudeusercontent.com/frame" } }] }] } });
    await f.manager.configure("gateway.example.test"); f.emit({ tabId: 1 }, "Fetch.requestPaused", f.paused());
    await f.flush(() => f.calls.some(call => call.method === "Fetch.continueRequest"));
    assert.equal(f.calls.some(call => call.method === "Fetch.fulfillRequest"), false);
    await f.manager.stop();
  }
});

test("debugger recursively initializes only known iframe child sessions and resumes them", async () => {
  const f = artifactDebuggerFixture(); await f.manager.configure("gateway.example.test");
  f.emit({ tabId: 1, sessionId: "foreign-session" }, "Target.attachedToTarget", { sessionId: "untrusted", targetInfo: { type: "iframe" }, waitingForDebugger: true });
  f.emit({ tabId: 1 }, "Target.attachedToTarget", { sessionId: "child", targetInfo: { type: "iframe" }, waitingForDebugger: true });
  await f.flush(() => f.calls.some(call => call.source?.sessionId === "child" && call.method === "Runtime.runIfWaitingForDebugger"));
  assert(f.calls.some(call => call.source?.sessionId === "child" && call.method === "Target.setAutoAttach"));
  assert.equal(f.calls.some(call => call.source?.sessionId === "untrusted"), false);
  f.emit({ tabId: 1, sessionId: "child" }, "Fetch.requestPaused", f.paused());
  await f.flush(() => f.calls.some(call => call.method === "Fetch.fulfillRequest"));
  await f.manager.stop();
});

test("debugger attach rejection closes protection and never detaches a foreign debugger", async () => {
  const f = artifactDebuggerFixture({ rejectAttach: true }); await f.manager.configure("gateway.example.test");
  assert(f.unsafeCount > 0); assert.equal(f.manager.status().attachedTabs, 0); assert.equal(f.manager.status().blockedTabs, 1);
  assert.equal(f.calls.some(call => call.method === "detach"), false);
});

test("unexpected debugger detach stays closed on health-style configure retry until explicit navigation", async () => {
  const f = artifactDebuggerFixture(); await f.manager.configure("gateway.example.test"); f.loseNative();
  await f.flush(() => f.unsafeCount > 0);
  const attached = f.calls.filter(call => call.method === "attach").length;
  f.setReady(true); await f.manager.configure("gateway.example.test");
  assert.equal(f.calls.filter(call => call.method === "attach").length, attached);
  assert.equal(f.manager.status().attachedTabs, 0); assert(f.unsafeCount > 1);
  f.setReady(true); f.chrome.tabs.onUpdated.emit(1, { status: "loading" }, f.tab);
  // configure reestablishes the desired host after the route is restored.
  f.manager.clearSuppressed(); await f.manager.configure("gateway.example.test");
  assert.equal(f.manager.status().attachedTabs, 1); await f.manager.stop();
});

test("late old debugger attach is quarantined across configuration change", async () => {
  let release; const pending = new Promise(resolve => { release = resolve; }); let first = true;
  const f = artifactDebuggerFixture({ attachHook: async () => { if (first) { first = false; await pending; } } });
  const old = f.manager.configure("gateway.example.test"); await f.flush(() => f.calls.some(call => call.method === "attach"));
  await f.manager.stop(); f.setReady(true); f.manager.clearSuppressed(); await f.manager.configure("gateway.example.test");
  assert.equal(f.calls.filter(call => call.method === "attach").length, 1);
  release(); await old; await f.flush(() => f.calls.some(call => call.method === "detach"));
  f.setReady(true); f.manager.clearSuppressed(); await f.manager.configure("gateway.example.test");
  assert.equal(f.manager.status().attachedTabs, 1); assert.equal(f.calls.filter(call => call.method === "detach").length, 1);
  await f.manager.stop();
});

test("late raw detach cannot close a newly attached debugger session", async () => {
  let release; const pending = new Promise(resolve => { release = resolve; }); let first = true;
  const f = artifactDebuggerFixture({ detachHook: async () => { if (first) { first = false; await pending; } } });
  await f.manager.configure("gateway.example.test"); const stopped = f.manager.stop();
  await f.flush(() => f.calls.some(call => call.method === "detach"));
  f.setReady(true); f.manager.clearSuppressed(); await f.manager.configure("gateway.example.test");
  assert.equal(f.calls.filter(call => call.method === "attach").length, 1);
  release(); await stopped; await f.flush();
  f.setReady(true); f.manager.clearSuppressed(); await f.manager.configure("gateway.example.test");
  assert.equal(f.manager.status().attachedTabs, 1); assert.equal(f.calls.filter(call => call.method === "detach").length, 1);
  f.chrome.debugger.onDetach.emit({ tabId: 1 }, "canceled_by_user"); await f.flush();
  assert.equal(f.manager.status().attachedTabs, 1, "a late old onDetach must not close the verified new native attachment");
  await f.manager.stop();
});

test("gateway navigation during a response cancels it and still closes its body stream", async () => {
  let release; const pending = new Promise(resolve => { release = resolve; });
  const f = artifactDebuggerFixture({ readHook: () => pending }); await f.manager.configure("gateway.example.test");
  f.emit({ tabId: 1 }, "Fetch.requestPaused", f.paused()); await f.flush(() => f.calls.some(call => call.method === "IO.read"));
  f.tab.pendingUrl = "https://other.example.test/";
  f.chrome.tabs.onUpdated.emit(1, { status: "loading" }, f.tab); release();
  await f.flush(() => f.calls.some(call => call.method === "IO.close"));
  assert.equal(f.calls.some(call => call.method === "Fetch.fulfillRequest"), false);
  assert(f.calls.some(call => call.method === "Fetch.failRequest"));
});


test("debugger accepts a fully validated gateway to artifact to nested artifact chain", async () => {
  const artifactURL = "https://id.frame.claudeusercontent.com/frame";
  const f = artifactDebuggerFixture({ treeOverride: { frame: { id: "root", url: "https://gateway.example.test/" }, childFrames: [{ frame: { id: "parent", parentId: "root", url: artifactURL }, childFrames: [{ frame: { id: "artifact", parentId: "parent", url: artifactURL } }] }] } });
  await f.manager.configure("gateway.example.test"); f.emit({ tabId: 1 }, "Fetch.requestPaused", f.paused());
  await f.flush(() => f.calls.some(call => call.method === "Fetch.fulfillRequest"));
  assert(f.calls.find(call => call.method === "Fetch.fulfillRequest").params.responseHeaders[0].value.includes("https://gateway.example.test"));
  await f.manager.stop();
});

test("debugger refuses an existing foreign page with a pending gateway navigation", async () => {
  const f = artifactDebuggerFixture(); f.tab.url = "https://foreign.example.test/"; f.tab.pendingUrl = "https://gateway.example.test/";
  await f.manager.configure("gateway.example.test"); assert.equal(f.calls.some(call => call.method === "attach"), false);
  f.tab.url = "about:blank"; await f.manager.configure("gateway.example.test");
  assert.equal(f.manager.status().attachedTabs, 1);
  f.emit({ tabId: 1 }, "Fetch.requestPaused", f.paused()); await f.flush(() => f.calls.some(call => call.method === "Fetch.failRequest"));
  assert.equal(f.calls.some(call => call.method === "Fetch.fulfillRequest"), false, "a pending URL does not authorize response rewriting before commit");
  await f.manager.stop();
});

test("debugger tab bounds count unique pending states and reject overflow explicitly", async () => {
  const tabs = Array.from({ length: 32 }, (_, index) => ({ id: index + 1, url: "https://gateway.example.test/" }));
  const allowed = artifactDebuggerFixture({ tabsOverride: tabs }); await allowed.manager.configure("gateway.example.test");
  assert.equal(allowed.manager.status().attachedTabs, 32); await allowed.manager.stop();
  const rejected = artifactDebuggerFixture({ tabsOverride: [...tabs, { id: 33, url: "https://gateway.example.test/" }] });
  await rejected.manager.configure("gateway.example.test"); assert(rejected.unsafeCount > 0);
  assert.equal(rejected.calls.some(call => call.method === "attach"), false); assert.equal(rejected.manager.status().lastError, "tab_limit");
});


test("proxy HEAD warmup gates public rules and strips CDN origin credentials", async () => {
  let checked = false;
  const f = backgroundFixture({ warmupHook: async ({ options, authenticate, context }) => {
    checked = true;
    assert.equal(vm.runInContext("proxyReady", context), false);
    assert.equal(f.sessionRules.has(2000), false);
    assert.equal(f.sessionRules.has(2010), false);
    const allow = f.sessionRules.get(2020), headers = f.sessionRules.get(2021);
    assert.deepEqual(Array.from(allow.condition.requestMethods), ["head"]);
    assert.deepEqual(Array.from(allow.condition.initiatorDomains), ["test-extension"]);
    assert.equal(allow.condition.regexFilter, "^" + f.run("escapeRegex(PROXY_WARMUP_URL)") + "$");
    assert.equal(options.credentials, "include"); assert.equal(options.redirect, "error"); assert.equal(options.headers, undefined);
    assert.deepEqual(plain(headers.action.requestHeaders), [{ header: "authorization", operation: "remove" }, { header: "cookie", operation: "remove" }]);
    assert.deepEqual(plain(headers.action.responseHeaders), [{ header: "set-cookie", operation: "remove" }]);
    assert(authenticate().authCredentials);
    return { status: 200 };
  } });
  assert.equal((await f.run("initialize()")).ok, true); assert(checked);
  assert(f.sessionRules.has(2000)); assert.equal(f.sessionRules.has(2020), false); assert.equal(f.sessionRules.has(2021), false);
});

test("a cached foreign proxy token cannot falsely complete a newly minted warmup", async () => {
  const f = backgroundFixture({ warmupHook: async () => ({ status: 200 }) });
  assert.equal((await f.run("initialize()")).ok, false);
  assert.equal(f.run("sessionUsable()"), false); assert.equal(f.sessionRules.size, 0);
  assert.equal(f.sessionStorage.proxySession, undefined); assert(f.sessionStorage.proxySessionCandidate);
});

test("failed warmup retains its retirement token for the next mint attempt", async () => {
  let attempts = 0;
  const f = backgroundFixture({ warmupHook: async ({ authenticate }) => { if (++attempts === 1) return { status: 503 }; authenticate(); return { status: 200 }; } });
  assert.equal((await f.run("initialize()")).ok, false);
  assert.equal(f.sessionRules.size, 0);
  assert.equal((await f.run("healthCheck()")).ok, true);
  const mints = f.calls.fetch.filter(call => call.url.endsWith("/__proxy-session"));
  assert.equal(mints[0].options.headers["X-Gateway-Previous-Proxy-Token"], undefined);
  assert.equal(mints[1].options.headers["X-Gateway-Previous-Proxy-Token"], "A".repeat(43));
});

test("retirement capability survives same-gateway account change but never crosses gateway authority", async () => {
  const f = backgroundFixture(); await f.run("initialize()");
  f.config.authUser = "other-user";
  f.chrome.storage.onChanged.emit({ authUser: { newValue: "other-user" } }, "local"); await f.flush();
  let mints = f.calls.fetch.filter(call => call.url.endsWith("/__proxy-session"));
  assert.equal(mints[1].options.headers["X-Gateway-Previous-Proxy-Token"], "A".repeat(43));
  assert.equal(mints[1].options.headers.Authorization, "Basic " + Buffer.from("other-user:test-password").toString("base64"));
  f.config.gatewayHost = "another-gateway.example.test";
  f.chrome.storage.onChanged.emit({ gatewayHost: { newValue: f.config.gatewayHost } }, "local"); await f.flush();
  mints = f.calls.fetch.filter(call => call.url.endsWith("/__proxy-session"));
  assert.equal(mints[2].url, "https://another-gateway.example.test/__proxy-session");
  assert.equal(mints[2].options.headers["X-Gateway-Previous-Proxy-Token"], undefined);
});

test("retirement token survives worker restart after unsuccessful session activation", async () => {
  const base = backgroundFixture();
  const candidate = { ...base.sampleSession(), gatewayHost: "gateway.example.test", configBinding: "old-config-binding", warmupVerified: false };
  const f = backgroundFixture({ savedCandidate: candidate }); await f.run("initialize()");
  const mint = f.calls.fetch.find(call => call.url.endsWith("/__proxy-session"));
  assert.equal(mint.options.headers["X-Gateway-Previous-Proxy-Token"], candidate.proxyPassword);
  assert.equal(f.run("sessionUsable()"), true);
});

test("unready proxy auth allows only the exact extension HEAD warmup request", async () => {
  const f = backgroundFixture({ warmupHook: async ({ url, authenticate, context }) => {
    const candidate = vm.runInContext("proxyWarmup.session", context);
    for (const change of [{ method: "GET" }, { initiator: "https://gateway.example.test" }, { url: url + "?leak=1" }, { challenger: { host: "other.example.test", port: 8443 } }]) {
      context.badWarmAuth = { isProxy: true, url, method: "HEAD", initiator: "chrome-extension://test-extension", challenger: candidate.proxy, scheme: "basic", realm: "gateway-proxy", requestId: "bad-warm", ...change };
      assert.equal(vm.runInContext("onProxyAuth(badWarmAuth).authCredentials", context), undefined);
    }
    authenticate(); return { status: 200 };
  } });
  assert.equal((await f.run("initialize()")).ok, true);
});

test("configuration invalidation aborts warmup and cannot open stale public rules", async () => {
  let release, entered, observedSignal; const reached = new Promise(resolve => { entered = resolve; });
  const f = backgroundFixture({ warmupHook: async ({ options, authenticate }) => { observedSignal = options.signal; entered(); await new Promise(resolve => { release = resolve; }); authenticate(); return { status: 200 }; } });
  const initializing = f.run("initialize()"); await reached; f.run("invalidate()");
  assert.equal(observedSignal.aborted, true); release(); assert.equal((await initializing).ok, false);
  assert.equal(f.sessionRules.size, 0); assert.equal(f.run("sessionUsable()"), false);
});
