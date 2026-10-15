// Claude Gateway — background worker (dynamic, one build for all domains).
// The user enters their gateway host in Options. The extension then:
//   1. Requests host permission for https://<host>/*
//   2. Registers dynamic DNR rules (claude.ai + asset hosts -> <host>)
//   3. Registers the fingerprint content-script for <host>
//   4. Adds the basic_auth Authorization header for <host>
// Packaged blocks protect destinations before the worker starts. Only a
// validated, short-lived HTTPS proxy session opens the session-scoped exception.

const AUTH_RULE_ID = 1000;
const PROXY_ALLOW_ID = 2000;
const GATEWAY_ALLOW_ID = 2001;
const EGRESS_BLOCK_ID = 2002;
// Firefox preloads this module through background.scripts; Chrome workers use
// importScripts so both builds execute the same destination policy.
if (typeof importScripts === "function") {
  if (typeof GatewayPrivacy === "undefined") importScripts("privacy-rules.js");
  importScripts("artifact-csp.js", "artifact-cors.js", "artifact-debugger.js");
}
const extensionAPI = typeof browser !== "undefined" && browser.proxy?.onRequest ? browser : chrome;
const { DEPENDENCY_HOSTS, ARTIFACT_DOMAINS, protectedHost, protectedPattern: PROTECTED_PATTERN, RESOURCE_TYPES } = GatewayPrivacy;
const PROXY_ALLOW_IDS = [PROXY_ALLOW_ID, ...DEPENDENCY_HOSTS.map((_, index) => 2010 + index)];
const PROXY_WARMUP_ALLOW_ID = 2020, PROXY_WARMUP_HEADERS_ID = 2021;
const PROXY_SESSION_RULE_IDS = [...PROXY_ALLOW_IDS, PROXY_WARMUP_ALLOW_ID, PROXY_WARMUP_HEADERS_ID];
const PROXY_WARMUP_URL = "https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js";
function validGatewayHost(host) {
  return GatewayPrivacy.validGatewayHost(host) && !protectedHost(new URL("https://" + host).hostname);
}

function escapeRegex(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
function basicHeader(user, pass) {
  // Basic credentials are UTF-8, including user-supplied non-ASCII passwords.
  const bytes = new TextEncoder().encode(user + ":" + pass);
  return "Basic " + btoa(Array.from(bytes, byte => String.fromCharCode(byte)).join(""));
}
function buildAuthRule(host, user, pass) {
  return { id: AUTH_RULE_ID, priority: 300,
    action: { type: "modifyHeaders", requestHeaders: [{ header: "authorization", operation: "set", value: basicHeader(user, pass) }] },
    // A domain-anchor filter also matches suffixes and subdomains. Credentials
    // must be limited to the configured HTTPS authority and its path boundary.
    condition: { regexFilter: "^https://" + escapeRegex(host) + "/", resourceTypes: RESOURCE_TYPES }
  };
}
function buildRules(host) {
  const esc = escapeRegex(host);
  return [
    { id: 1, priority: 250,
      action: { type: "redirect", redirect: { regexSubstitution: "https://" + host + "\\1" } },
      condition: { regexFilter: "^https://(?:www\\.)?claude\\.ai(/.*)?$", resourceTypes: RESOURCE_TYPES } },
    { id: 2, priority: 250,
      action: { type: "redirect", redirect: { regexSubstitution: "https://" + host + "/p/assets.claude.ai\\1" } },
      condition: { regexFilter: "^https://assets\\.claude\\.ai(/.*)?$", resourceTypes: RESOURCE_TYPES } },
    { id: 3, priority: 250,
      action: { type: "redirect", redirect: { regexSubstitution: "https://" + host + "/p/assets-proxy.anthropic.com\\1" } },
      condition: { regexFilter: "^https://assets-proxy\\.anthropic\\.com(/.*)?$", resourceTypes: RESOURCE_TYPES } },
    { id: 4, priority: 250,
      action: { type: "redirect", redirect: { regexSubstitution: "https://" + host + "/p/api.anthropic.com\\1" } },
      condition: { regexFilter: "^https://api\\.anthropic\\.com(/.*)?$", resourceTypes: RESOURCE_TYPES } },
    { id: 7, priority: 250,
      action: { type: "redirect", redirect: { regexSubstitution: "https://" + host + "/p/s-cdn.anthropic.com\\1" } },
      condition: { regexFilter: "^https://s-cdn\\.anthropic\\.com(/.*)?$", resourceTypes: RESOURCE_TYPES } },
    { id: 8, priority: 250,
      action: { type: "redirect", redirect: { regexSubstitution: "https://" + host + "/p/a-cdn.anthropic.com\\1" } },
      condition: { regexFilter: "^https://a-cdn\\.anthropic\\.com(/.*)?$", resourceTypes: RESOURCE_TYPES } },
    { id: 9, priority: 250,
      action: { type: "redirect", redirect: { regexSubstitution: "https://" + host + "/p/a.claude.ai\\1" } },
      condition: { regexFilter: "^https://a\\.claude\\.ai(/.*)?$", resourceTypes: RESOURCE_TYPES } },
    { id: 12, priority: 250,
      action: { type: "redirect", redirect: { regexSubstitution: "https://" + host + "/p/a-cdn.claude.ai\\1" } },
      condition: { regexFilter: "^https://a-cdn\\.claude\\.ai(/.*)?$", resourceTypes: RESOURCE_TYPES } },
    // Artifact frames (https://<id>.frame.claudeusercontent.com) must keep that origin:
    // the page postMessages to it. If a cached bundle still points the iframe at
    // https://<gateway>/p/<that-host>/..., send it back to the real host.
    { id: 13, priority: 250,
      action: { type: "redirect", redirect: { regexSubstitution: "https://\\1\\2" } },
      condition: { regexFilter: "^https://" + esc + "/p/((?:[^/?#]+\\.)*(?:claudeusercontent|claudemcpcontent)\\.com)(/.*)?$", resourceTypes: RESOURCE_TYPES } },

  ].concat(GatewayPrivacy.buildPrivacyRules(host, RESOURCE_TYPES, { scoped: FIREFOX }));
}
// Chromium restricts the whole dedicated profile. Firefox runs in the user's
// everyday profile, so its restriction is scoped to gateway/artifact
// initiators and installed together with the gateway rules (buildRules).
function profileRestrictionRules() {
  return FIREFOX ? [] : GatewayPrivacy.buildProfileRestrictionRules();
}

async function getConfig() {
  const c = await extensionAPI.storage.local.get(["gatewayHost", "authUser", "authPass"]);
  const host = (c.gatewayHost || "").trim().toLowerCase();
  return { host: validGatewayHost(host) ? host : "", hasHost: !!host, user: (c.authUser || "").trim(), pass: c.authPass || "" };
}

// All mutations share a queue; an event invalidates outstanding network work
// immediately, and its cleanup runs before the next configuration is installed.
let proxySession = null;
// A retirement capability is kept separately from active readiness. It can only
// be presented back to the exact gateway which issued it, including after a
// failed refresh or a same-gateway account change.
let proxyCandidate = null;
let proxyWarmup = null;
let proxyReady = false;
let routeExpectation = null;
let configEpoch = 0;
let operationQueue = Promise.resolve();
const authAttempts = new Map();
const FIREFOX = typeof browser !== "undefined" && !!browser.proxy?.onRequest;
let proxyReason = "";
const PROXY_FILTER = ["*://*.claudeusercontent.com/*", "*://*.claudemcpcontent.com/*", ...DEPENDENCY_HOSTS.map(host => "*://" + host + "/*")];
const proxyFirefox = FIREFOX && typeof GatewayProxyFirefox !== "undefined" ? GatewayProxyFirefox.create({
  browser, protectedHost, artifactHost: GatewayPrivacy.artifactHost, upstreamHost: host => GatewayPrivacy.UPSTREAM_HOSTS.includes(host), filter: PROXY_FILTER, warmupUrl: PROXY_WARMUP_URL, isExtensionRequest: isExtensionProxyRequest
}) : null;
const artifactController = FIREFOX ? (typeof GatewayArtifactFirefox !== "undefined" ? GatewayArtifactFirefox : null)
  : (typeof GatewayArtifactDebugger !== "undefined" ? GatewayArtifactDebugger : null);
const artifactDebugger = artifactController ? artifactController.create({
  browser: FIREFOX ? browser : undefined,
  chrome, isReady: () => sessionUsable(),
  onUnsafeDetach: () => { invalidate(); serialized(resetProxy).catch(() => {}); }
}) : null;
function isExtensionProxyRequest(details) {
  if (!FIREFOX) return details.initiator === "chrome-extension://" + extensionAPI.runtime.id;
  try {
    const own = new URL(extensionAPI.runtime.getURL("/"));
    const value = [details.originUrl, details.documentUrl, details.initiator].find(candidate => typeof candidate === "string");
    const u = new URL(value);
    return u.protocol === "moz-extension:" && u.protocol === own.protocol && u.host === own.host && !u.username && !u.password;
  } catch (_) { return false; }
}
function serialized(fn) {
  const epoch = configEpoch;
  const task = operationQueue.then(() => fn(epoch));
  operationQueue = task.catch(() => {});
  return task;
}
function assertCurrent(epoch) {
  if (epoch !== configEpoch) throw new Error("Configuration changed");
}
function invalidate() {
  configEpoch++;
  proxyWarmup?.controller.abort();
  proxyWarmup = null;
  artifactDebugger?.stop().catch(() => {});
  proxyReady = false;
  routeExpectation = null;
  proxySession = null;
  proxyFirefox?.reset();
  authAttempts.clear();
  // Remove the exception promptly even if an older health request is pending.
  extensionAPI.declarativeNetRequest.updateSessionRules({ removeRuleIds: PROXY_SESSION_RULE_IDS }).catch(() => {});
}
async function configBinding(cfg) {
  const bytes = new TextEncoder().encode(JSON.stringify([cfg.host, cfg.user, cfg.pass]));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("");
}
function validProxySession(session) {
  if (!session || session.proxyUsername !== "gateway-proxy" || !/^[A-Za-z0-9_-]{43}$/.test(session.proxyPassword)
      || !Number.isSafeInteger(session.expiresAt) || session.expiresAt <= Date.now() + 10000 || session.expiresAt > Date.now() + 16 * 60000
      || !session.proxy || session.proxy.scheme !== "https" || !Number.isInteger(session.proxy.port) || session.proxy.port < 1 || session.proxy.port > 65535) return false;
  const host = session.proxy.host;
  // Restrict PAC interpolation to a canonical DNS name or IPv4 address. IPv6 is
  // not accepted until its authority and challenger representations are tested.
  if (typeof host !== "string" || host.length > 253 || !/^[a-z0-9]+(?:[.-][a-z0-9]+)*$/.test(host) || !host.includes(".")) return false;
  return host.split(".").every(label => label.length <= 63);
}
function sessionUsable(session = proxySession) {
  return !!(proxyReady && session && session.expiresAt > Date.now() && session.proxy?.scheme === "https");
}
async function secureWebRTC() {
  // Firefox leaves browser-wide privacy settings to the user: fingerprint.js
  // removes WebRTC in gateway/artifact realms, and only Claude is routed.
  if (FIREFOX) return releaseFirefoxPrivacy();
  const policy = extensionAPI.privacy?.network?.webRTCIPHandlingPolicy;
  if (!policy) throw new Error("WebRTC privacy control unavailable");
  const expectedPolicy = "disable_non_proxied_udp";
  await policy.set({ value: expectedPolicy, scope: "regular" });
  const installed = await policy.get({ incognito: false });
  if (installed.value !== expectedPolicy || installed.levelOfControl !== "controlled_by_this_extension") throw new Error("WebRTC privacy control unavailable");
  const prediction = extensionAPI.privacy?.network?.networkPredictionEnabled;
  if (prediction) {
    await prediction.set({ value: false, scope: "regular" });
    const actual = await prediction.get({ incognito: false });
    if (actual.value !== false || actual.levelOfControl !== "controlled_by_this_extension") throw new Error("Network prediction privacy control unavailable");
  }
}
async function releaseFirefoxPrivacy() {
  // Builds before 2.0.6 forced proxy-only WebRTC for the whole browser.
  for (const setting of [extensionAPI.privacy?.network?.webRTCIPHandlingPolicy, extensionAPI.privacy?.network?.networkPredictionEnabled]) {
    try { if ((await setting?.get({}))?.levelOfControl === "controlled_by_this_extension") await setting.clear({}); }
    catch (_) { /* Not controlled by this extension. */ }
  }
}
async function resetProxy() {
  proxyWarmup?.controller.abort();
  proxyWarmup = null;
  proxyReady = false;
  routeExpectation = null;
  await artifactDebugger?.stop();
  // The packaged block must become effective before removing the TLS route.
  await extensionAPI.declarativeNetRequest.updateSessionRules({ removeRuleIds: PROXY_SESSION_RULE_IDS });
  proxySession = null;
  proxyFirefox?.reset();
  authAttempts.clear();
  await extensionAPI.storage.session.remove("proxySession");
  await extensionAPI.alarms.clear("proxy-refresh");
  await extensionAPI.alarms.clear("proxy-expire");
  if (!FIREFOX && extensionAPI.proxy?.settings) await extensionAPI.proxy.settings.clear({ scope: "regular" });
}
async function clearAllInternal({ preserveRestriction = false } = {}) {
  await resetProxy();
  const ids = [1,2,3,4,5,6,7,8,9,10,11,12,13,AUTH_RULE_ID,GATEWAY_ALLOW_ID,EGRESS_BLOCK_ID,2003,2004,2005];
  await extensionAPI.declarativeNetRequest.updateDynamicRules({ removeRuleIds: preserveRestriction ? ids.filter(id => id !== EGRESS_BLOCK_ID && id !== 2005) : ids });
  // Unregistering an unknown id rejects, which would abort the whole reconfigure.
  if ((await extensionAPI.scripting.getRegisteredContentScripts({ ids: ["fingerprint"] })).length) {
    await extensionAPI.scripting.unregisterContentScripts({ ids: ["fingerprint"] });
  }
  if (!preserveRestriction) {
    await proxyFirefox?.clear();
    if (FIREFOX) await releaseFirefoxPrivacy();
    else {
      await extensionAPI.privacy?.network?.webRTCIPHandlingPolicy?.clear({ scope: "regular" });
      await extensionAPI.privacy?.network?.networkPredictionEnabled?.clear({ scope: "regular" });
    }
  }
}
function clearAll() { invalidate(); return serialized(clearAllInternal); }
function proxyPac(session, gatewayHost = session.gatewayHost) {
  if (!validGatewayHost(gatewayHost)) throw new Error("Invalid gateway authority");
  const endpoint = session.proxy.host + ":" + session.proxy.port;
  // This connector restricts the entire dedicated browser profile. An exact
  // gateway authority is the only direct exception; unknown/cleartext/alternate
  // port requests go to a dead TLS endpoint with no fallback list.
  return "function FindProxyForURL(url, host) {\n" +
    "if (new RegExp(" + JSON.stringify("^https://" + escapeRegex(gatewayHost) + "/") + ", \"i\").test(url)) return \"DIRECT\";\n" +
    "if (new RegExp(" + JSON.stringify("^(?:https|wss)://(?:" + PROTECTED_PATTERN + ")/") + ", \"i\").test(url)) return \"HTTPS " + endpoint + "\";\n" +
    "return \"HTTPS 127.0.0.1:9\";\n}";
}
async function gatewayPermission(cfg) {
  return !!(cfg.host && await extensionAPI.permissions.contains({ origins: GatewayPrivacy.requiredOrigins(cfg.host) }));
}
async function applyRulesInternal(epoch) {
  // Return settings left by earlier Firefox builds even while the gateway is
  // unconfigured or lacks permission; they blocked every site in the browser.
  if (FIREFOX) { await proxyFirefox?.releaseLegacy(); await releaseFirefoxPrivacy(); }
  const cfg = await getConfig();
  assertCurrent(epoch);
  if (cfg.hasHost) {
    await extensionAPI.declarativeNetRequest.updateDynamicRules({ removeRuleIds: [EGRESS_BLOCK_ID, 2005], addRules: profileRestrictionRules() });
    assertCurrent(epoch);
  }
  if (!cfg.host || !await gatewayPermission(cfg)) {
    await clearAllInternal({ preserveRestriction: cfg.hasHost });
    return { ok: false, reason: cfg.host ? "no_permission" : cfg.hasHost ? "invalid_gateway" : "not_configured" };
  }
  assertCurrent(epoch);
  // Browser-level UDP/prediction protection must precede opening gateway routes.
  await secureWebRTC();
  assertCurrent(epoch);
  if (FIREFOX) {
    if (!proxyFirefox) return { ok: false, reason: "firefox_proxy_api_unavailable" };
    try { await proxyFirefox.ensure(cfg.host); proxyReason = ""; }
    catch (error) { proxyReason = error.reason || "proxy_baseline_unavailable"; return { ok: false, reason: proxyReason }; }
    assertCurrent(epoch);
  }
  const rules = buildRules(cfg.host);
  if (cfg.user && cfg.pass) rules.push(buildAuthRule(cfg.host, cfg.user, cfg.pass));
  await extensionAPI.declarativeNetRequest.updateDynamicRules({ removeRuleIds: [...rules.map(r => r.id), AUTH_RULE_ID, 10, 11].filter((id, i, ids) => ids.indexOf(id) === i), addRules: rules });
  assertCurrent(epoch);
  try {
    const script = { id: "fingerprint", matches: GatewayPrivacy.fingerprintMatches(cfg.host), js: ["fingerprint.js"], runAt: "document_start", allFrames: true, matchOriginAsFallback: true, world: "MAIN" };
    const existing = await extensionAPI.scripting.getRegisteredContentScripts({ ids: [script.id] });
    assertCurrent(epoch);
    if (existing.length) await extensionAPI.scripting.updateContentScripts([script]);
    else await extensionAPI.scripting.registerContentScripts([script]);
    assertCurrent(epoch);
  } catch (e) {
    await resetProxy();
    return { ok: false, reason: "fingerprint_registration_failed" };
  }
  return { ok: true };
}
function applyRules() {
  artifactDebugger?.clearSuppressed();
  invalidate();
  return serialized(async epoch => {
    try { await resetProxy(); assertCurrent(epoch); return await applyRulesInternal(epoch); }
    catch (_) { await resetProxy(); return { ok: false, reason: "configuration_failed" }; }
  });
}
function buildProxyAllowRules() {
  return GatewayPrivacy.buildProxyAllowRules(RESOURCE_TYPES);
}
function buildProxyWarmupRules() {
  const initiator = FIREFOX ? new URL(extensionAPI.runtime.getURL("/")).hostname : extensionAPI.runtime.id;
  const condition = { regexFilter: "^" + escapeRegex(PROXY_WARMUP_URL) + "$", initiatorDomains: [initiator], requestMethods: ["head"], resourceTypes: ["xmlhttprequest"] };
  return [
    { id: PROXY_WARMUP_ALLOW_ID, priority: 200, action: { type: "allow" }, condition },
    // credentials:include is required for Chrome's proxy-auth callback. Keep
    // origin credentials/cookies off this fixed CDN request nevertheless.
    { id: PROXY_WARMUP_HEADERS_ID, priority: 300, action: { type: "modifyHeaders", requestHeaders: [{ header: "authorization", operation: "remove" }, { header: "cookie", operation: "remove" }], responseHeaders: [{ header: "set-cookie", operation: "remove" }] }, condition }
  ];
}
async function warmProxyAuthentication(session, epoch, restored) {
  const controller = new AbortController();
  const state = { session, epoch, controller, authorized: false };
  proxyWarmup = state;
  proxyFirefox?.setSession(session, { warming: true });
  const timer = setTimeout(() => controller.abort(), 8000);
  try {
    await extensionAPI.declarativeNetRequest.updateSessionRules({ removeRuleIds: [PROXY_WARMUP_ALLOW_ID, PROXY_WARMUP_HEADERS_ID], addRules: buildProxyWarmupRules() });
    assertCurrent(epoch);
    const response = await fetch(PROXY_WARMUP_URL, { method: "HEAD", credentials: "include", cache: "no-store", redirect: "error", signal: controller.signal });
    assertCurrent(epoch);
    // Firefox authenticates by header, so a fresh route is the proof instead
    // of a 407 challenge; an unrouted request would have gone around the proxy.
    const verified = FIREFOX ? proxyFirefox.warmupRouted() : restored || state.authorized;
    if (response.status < 200 || response.status >= 300 || !verified) throw new Error("Proxy authentication was not verified");
  } finally {
    clearTimeout(timer);
    if (proxyWarmup === state) proxyWarmup = null;
    await extensionAPI.declarativeNetRequest.updateSessionRules({ removeRuleIds: [PROXY_WARMUP_ALLOW_ID, PROXY_WARMUP_HEADERS_ID] });
  }
}
async function applyConnectProxy(session, cfg, epoch, { restored = false } = {}) {
  if (!validProxySession(session) || !authListenerReady || FIREFOX && !proxyFirefox) throw new Error("Invalid proxy session or unsupported proxy API");
  assertCurrent(epoch);
  const binding = await configBinding(cfg);
  assertCurrent(epoch);
  // Close the previous exception before changing its route or credentials.
  proxyReady = false;
  await extensionAPI.declarativeNetRequest.updateSessionRules({ removeRuleIds: PROXY_SESSION_RULE_IDS });
  assertCurrent(epoch);
  routeExpectation = { pac: proxyPac(session, cfg.host) };
  await secureWebRTC();
  assertCurrent(epoch);
  if (FIREFOX) { await proxyFirefox.ensure(cfg.host); assertCurrent(epoch); }
  if (!FIREFOX) {
    if (!extensionAPI.proxy?.settings) throw new Error("HTTPS proxy unavailable");
    const data = proxyPac(session, cfg.host);
    await extensionAPI.proxy.settings.set({ value: { mode: "pac_script", pacScript: { data, mandatory: true } }, scope: "regular" });
    assertCurrent(epoch);
    const installed = await extensionAPI.proxy.settings.get({ incognito: false });
    if (installed.levelOfControl !== "controlled_by_this_extension" || installed.value?.mode !== "pac_script"
        || installed.value.pacScript?.data !== data || installed.value.pacScript?.mandatory !== true) throw new Error("HTTPS proxy is not controlled");
  }
  assertCurrent(epoch);
  if (!await gatewayPermission(cfg)) throw new Error("Gateway permission revoked");
  assertCurrent(epoch);
  proxyCandidate = { ...session, gatewayHost: cfg.host, configBinding: binding, warmupVerified: restored && session.warmupVerified === true };
  await extensionAPI.storage.session.set({ proxySessionCandidate: proxyCandidate });
  assertCurrent(epoch);
  await warmProxyAuthentication(proxyCandidate, epoch, restored && proxyCandidate.warmupVerified);
  assertCurrent(epoch);
  proxySession = { ...proxyCandidate, warmupVerified: true };
  proxyCandidate = proxySession;
  await extensionAPI.storage.session.set({ proxySession, proxySessionCandidate: proxyCandidate });
  assertCurrent(epoch);
  await extensionAPI.alarms.create("proxy-refresh", { when: Math.max(Date.now() + 1000, session.expiresAt - 60000) });
  await extensionAPI.alarms.create("proxy-expire", { when: session.expiresAt });
  assertCurrent(epoch);
  proxyReady = true;
  if (FIREFOX) {
    proxyFirefox.setSession(proxySession);
    if (!artifactDebugger?.status().available) throw new Error("Firefox artifact adapter unavailable");
    await artifactDebugger.configure(cfg.host);
    assertCurrent(epoch);
    if (!artifactDebugger.status().active) throw new Error("Firefox artifact adapter unavailable");
  }
  await extensionAPI.declarativeNetRequest.updateSessionRules({ removeRuleIds: PROXY_SESSION_RULE_IDS, addRules: buildProxyAllowRules() });
  assertCurrent(epoch);
  if (!FIREFOX && artifactDebugger) {
    if (!artifactDebugger.status().available) throw new Error("Artifact debugger unavailable");
    await artifactDebugger.configure(cfg.host);
    assertCurrent(epoch);
  }
}
async function refreshProxySession(cfg, epoch) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 8000);
  try {
    const headers = { Authorization: basicHeader(cfg.user, cfg.pass), "X-Gateway-Proxy-Session": "1" };
    if (proxyCandidate?.gatewayHost === cfg.host && proxyCandidate.proxy?.scheme === "https"
        && proxyCandidate.proxyUsername === "gateway-proxy" && /^[A-Za-z0-9_-]{43}$/.test(proxyCandidate.proxyPassword)) {
      headers["X-Gateway-Previous-Proxy-Token"] = proxyCandidate.proxyPassword;
    }
    const response = await fetch("https://" + cfg.host + "/__proxy-session", { method: "POST", headers, signal: ctrl.signal, cache: "no-store", redirect: "error", credentials: "omit" });
    assertCurrent(epoch);
    if (response.status !== 200) throw new Error("Secure proxy unavailable");
    const session = await response.json();
    assertCurrent(epoch);
    await applyConnectProxy(session, cfg, epoch);
  } finally { clearTimeout(timer); }
}
async function healthCheckInternal(epoch) {
  const cfg = await getConfig();
  assertCurrent(epoch);
  if (!cfg.host || !cfg.user || !cfg.pass) { await resetProxy(); return { ok: false, reason: "not_configured" }; }
  if (!await gatewayPermission(cfg)) { await clearAllInternal({ preserveRestriction: true }); return { ok: false, reason: "no_permission" }; }
  assertCurrent(epoch);
  if (FIREFOX && !proxyFirefox?.status().baselineReady) {
    proxyReason = proxyFirefox?.status().reason || "firefox_proxy_api_unavailable";
    await resetProxy(); return { ok: false, reason: proxyReason };
  }
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 8000);
  try {
    const res = await fetch("https://" + cfg.host + "/__health", { headers: { Authorization: basicHeader(cfg.user, cfg.pass) }, signal: ctrl.signal, cache: "no-store", redirect: "error", credentials: "omit" });
    assertCurrent(epoch);
    if (res.status !== 200) { proxyReason = res.status === 401 ? "auth_failed" : "http_" + res.status; await resetProxy(); return { ok: false, status: res.status, reason: proxyReason }; }
    const body = await res.json();
    assertCurrent(epoch);
    const binding = await configBinding(cfg);
    if (!sessionUsable() || proxySession.configBinding !== binding || proxySession.expiresAt - Date.now() < 90000) await refreshProxySession(cfg, epoch);
    assertCurrent(epoch);
    proxyReason = "";
    return { ok: true, status: 200, users: body.users, session: body.session, connectProxy: "https://" + proxySession.proxy.host + ":" + proxySession.proxy.port };
  } catch (error) { proxyReason = error.reason || "secure_proxy_unavailable"; await resetProxy(); return { ok: false, reason: proxyReason }; }
  finally { clearTimeout(timer); }
}
function healthCheck() { return serialized(healthCheckInternal); }
async function status() {
  const cfg = await getConfig();
  const scripts = await extensionAPI.scripting.getRegisteredContentScripts({ ids: ["fingerprint"] });
  const rules = await extensionAPI.declarativeNetRequest.getDynamicRules();
  return { host: cfg.host, granted: await gatewayPermission(cfg), fingerprint: scripts.some(s => s.world === "MAIN"), rules: rules.length, configured: !!(cfg.host && cfg.user && cfg.pass), proxyReady: sessionUsable(), proxyWarming: !!proxyWarmup, proxyPlatform: FIREFOX ? "firefox" : "chromium", proxyReason: proxyReason || proxyFirefox?.status().reason || "", firefoxProxy: proxyFirefox?.status(), artifactDebugger: artifactDebugger?.status() || { available: false, attachedTabs: 0, blockedTabs: 0, lastError: "unsupported" } };
}
function onProxyAuth(details, callback) {
  let result = {};
  let url;
  try { url = new URL(details.url); } catch (_) { /* invalid target */ }
  const challenger = details.challenger || {};
  const warming = proxyWarmup && proxyWarmup.epoch === configEpoch && proxyWarmup.session.expiresAt > Date.now()
    && details.url === PROXY_WARMUP_URL && details.method === "HEAD" && isExtensionProxyRequest(details);
  const session = sessionUsable() ? proxySession : warming ? proxyWarmup.session : null;
  if (details.isProxy && url && protectedHost(url.hostname)) {
    result = { cancel: true };
    if (session && challenger.host === session.proxy.host && Number(challenger.port) === session.proxy.port
        && details.scheme === "basic" && details.realm === "gateway-proxy" && !url.port && ["https:", "wss:"].includes(url.protocol)) {
      // Never evict a live request to admit another retry.
      if (!authAttempts.has(details.requestId) && authAttempts.size < 1000) {
        authAttempts.set(details.requestId, true);
        result = { authCredentials: { username: session.proxyUsername, password: session.proxyPassword } };
        if (warming) proxyWarmup.authorized = true;
      }
    }
  }
  if (typeof callback === "function") callback(result);
  return result;
}
let authListenerReady = false;
try {
  extensionAPI.webRequest.onAuthRequired.addListener(onProxyAuth, { urls: PROXY_FILTER }, [FIREFOX ? "blocking" : "asyncBlocking"]);
  authListenerReady = true;
} catch (_) { /* Packaged blocks stay active if proxy authentication is unavailable. */ }
for (const event of [extensionAPI.webRequest.onCompleted, extensionAPI.webRequest.onErrorOccurred]) {
  if (event) event.addListener(details => authAttempts.delete(details.requestId), { urls: PROXY_FILTER });
}
function firefoxProxyRequest(details) {
  return proxyFirefox ? proxyFirefox.route(details) : Promise.reject(new Error("Secure proxy routing unavailable"));
}
// Losing route ownership must close the DNR exception immediately, before any
// queued refresh or settings cleanup can run.
function proxySettingsChanged(change) {
  if ((!proxyReady && !routeExpectation) || FIREFOX) return;
  const expected = routeExpectation?.pac || (proxySession && proxyPac(proxySession));
  if (change.levelOfControl !== "controlled_by_this_extension" || change.value?.mode !== "pac_script"
      || change.value.pacScript?.data !== expected || change.value.pacScript?.mandatory !== true) {
    invalidate();
    serialized(resetProxy).catch(() => {});
  }
}
if (!FIREFOX && extensionAPI.proxy?.settings?.onChange) extensionAPI.proxy.settings.onChange.addListener(proxySettingsChanged);
const rtcPolicy = FIREFOX ? null : extensionAPI.privacy?.network?.webRTCIPHandlingPolicy;
if (rtcPolicy?.onChange) rtcPolicy.onChange.addListener(change => {
  if ((proxyReady || routeExpectation) && (change.value !== "disable_non_proxied_udp" || change.levelOfControl !== "controlled_by_this_extension")) {
    invalidate();
    serialized(resetProxy).catch(() => {});
  }
});
const predictionPolicy = FIREFOX ? null : extensionAPI.privacy?.network?.networkPredictionEnabled;
if (predictionPolicy?.onChange) predictionPolicy.onChange.addListener(change => {
  if ((proxyReady || routeExpectation) && (change.value !== false || change.levelOfControl !== "controlled_by_this_extension")) {
    invalidate();
    serialized(resetProxy).catch(() => {});
  }
});
extensionAPI.alarms.onAlarm.addListener(alarm => {
  if (alarm.name === "proxy-refresh") healthCheck().catch(() => {});
  if (alarm.name === "proxy-expire" && !sessionUsable()) { invalidate(); serialized(resetProxy).catch(() => {}); }
});
extensionAPI.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || (sender.id && sender.id !== extensionAPI.runtime.id)) return;
  const handler = { health: healthCheck, status, apply: applyRules }[msg.type];
  if (handler) { handler().then(sendResponse, () => sendResponse({ ok: false, reason: "configuration_failed" })); return true; }
});
function reconfigure() {
  artifactDebugger?.clearSuppressed();
  invalidate();
  return serialized(async epoch => {
    try {
      const cfg = await getConfig();
      assertCurrent(epoch);
      if (cfg.hasHost) {
        await extensionAPI.declarativeNetRequest.updateDynamicRules({ removeRuleIds: [EGRESS_BLOCK_ID, 2005], addRules: profileRestrictionRules() });
        assertCurrent(epoch);
      }
      await clearAllInternal({ preserveRestriction: cfg.hasHost });
      assertCurrent(epoch);
      const result = await applyRulesInternal(epoch);
      if (result.ok) await healthCheckInternal(epoch);
    }
    catch (_) { await resetProxy(); }
  });
}
extensionAPI.runtime.onInstalled.addListener(async details => {
  await reconfigure();
  if (details.reason === "install" && !(await getConfig()).host) extensionAPI.runtime.openOptionsPage();
});
extensionAPI.runtime.onStartup.addListener(() => reconfigure());
extensionAPI.permissions.onAdded.addListener(p => { if (p?.origins?.length) reconfigure(); });
extensionAPI.permissions.onRemoved.addListener(p => { if (p?.origins?.length || p?.permissions?.length) reconfigure(); });
extensionAPI.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && (changes.gatewayHost || changes.authUser || changes.authPass)) reconfigure();
});
function initialize() {
  return serialized(async epoch => {
    try {
      const stored = await extensionAPI.storage.session.get(["proxySession", "proxySessionCandidate"]);
      const saved = stored.proxySession;
      proxyCandidate = stored.proxySessionCandidate || saved || null;
      await resetProxy();
      assertCurrent(epoch);
      const cfg = await getConfig();
      const result = await applyRulesInternal(epoch);
      if (!result.ok) return result;
      if (saved && saved.gatewayHost === cfg.host && saved.configBinding === await configBinding(cfg) && saved.warmupVerified === true && validProxySession(saved)) await applyConnectProxy(saved, cfg, epoch, { restored: true });
      else return await healthCheckInternal(epoch);
      return { ok: true };
    } catch (_) { await resetProxy(); return { ok: false, reason: "configuration_failed" }; }
  });
}
initialize().catch(() => {});
