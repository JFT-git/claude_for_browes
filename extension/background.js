// Claude Gateway — background worker (dynamic, one build for all domains).
// The user enters their gateway host in Options. The extension then:
//   1. Requests host permission for https://<host>/*
//   2. Registers dynamic DNR rules (claude.ai + asset hosts -> <host>)
//   3. Registers the fingerprint content-script for <host>
//   4. Adds the basic_auth Authorization header for <host>
// Everything persists across browser restarts.

const AUTH_RULE_ID = 1000;
const RESOURCE_TYPES = ["main_frame","sub_frame","xmlhttprequest","script","stylesheet","image","font","media","websocket","other","csp_report","ping"];

function escapeRegex(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
function buildRules(host) {
  const esc = escapeRegex(host);
  return [
    { id: 1, priority: 1,
      action: { type: "redirect", redirect: { regexSubstitution: "https://" + host + "\\1" } },
      condition: { regexFilter: "^https://(?:www\\.)?claude\\.ai(/.*)?$", resourceTypes: RESOURCE_TYPES } },
    { id: 2, priority: 1,
      action: { type: "redirect", redirect: { regexSubstitution: "https://" + host + "/p/assets.claude.ai\\1" } },
      condition: { regexFilter: "^https://assets\\.claude\\.ai(/.*)?$", resourceTypes: RESOURCE_TYPES } },
    { id: 3, priority: 1,
      action: { type: "redirect", redirect: { regexSubstitution: "https://" + host + "/p/assets-proxy.anthropic.com\\1" } },
      condition: { regexFilter: "^https://assets-proxy\\.anthropic\\.com(/.*)?$", resourceTypes: RESOURCE_TYPES } },
    { id: 4, priority: 1,
      action: { type: "redirect", redirect: { regexSubstitution: "https://" + host + "/p/api.anthropic.com\\1" } },
      condition: { regexFilter: "^https://api\\.anthropic\\.com(/.*)?$", resourceTypes: RESOURCE_TYPES } },
    { id: 7, priority: 1,
      action: { type: "redirect", redirect: { regexSubstitution: "https://" + host + "/p/s-cdn.anthropic.com\\1" } },
      condition: { regexFilter: "^https://s-cdn\\.anthropic\\.com(/.*)?$", resourceTypes: RESOURCE_TYPES } },
    { id: 8, priority: 1,
      action: { type: "redirect", redirect: { regexSubstitution: "https://" + host + "/p/a-cdn.anthropic.com\\1" } },
      condition: { regexFilter: "^https://a-cdn\\.anthropic\\.com(/.*)?$", resourceTypes: RESOURCE_TYPES } },
    { id: 9, priority: 1,
      action: { type: "redirect", redirect: { regexSubstitution: "https://" + host + "/p/a.claude.ai\\1" } },
      condition: { regexFilter: "^https://a\\.claude\\.ai(/.*)?$", resourceTypes: RESOURCE_TYPES } },
    { id: 12, priority: 1,
      action: { type: "redirect", redirect: { regexSubstitution: "https://" + host + "/p/a-cdn.claude.ai\\1" } },
      condition: { regexFilter: "^https://a-cdn\\.claude\\.ai(/.*)?$", resourceTypes: RESOURCE_TYPES } },
    // Artifact frames live on per-artifact subdomains (https://<id>.frame.claudeusercontent.com).
    // Do NOT proxy them (postMessage needs real origins). Instead strip the CSP header that
    // limits frame-ancestors to claude.ai so they can be embedded from the gateway origin.
    { id: 5, priority: 1,
      action: { type: "modifyHeaders", responseHeaders: [
        { header: "content-security-policy", operation: "remove" },
        { header: "x-frame-options", operation: "remove" }
      ] },
      condition: { regexFilter: "^https://([^/]+\\.)?claudeusercontent\\.com/", resourceTypes: ["sub_frame"] } },
    { id: 6, priority: 1,
      action: { type: "modifyHeaders", responseHeaders: [
        { header: "content-security-policy", operation: "remove" },
        { header: "x-frame-options", operation: "remove" }
      ] },
      condition: { regexFilter: "^https://([^/]+\\.)?claudemcpcontent\\.com/", resourceTypes: ["sub_frame"] } },
    { id: 10, priority: 3,
      action: { type: "redirect", redirect: { regexSubstitution: "https://accounts.google.com/\\1claude.ai\\2" } },
      condition: { regexFilter: "^https://accounts\\.google\\.com/(.*)" + esc + "(.*)$", resourceTypes: ["main_frame", "sub_frame"] } },
    { id: 11, priority: 3,
      action: { type: "redirect", redirect: { regexSubstitution: "https://appleid.apple.com/\\1claude.ai\\2" } },
      condition: { regexFilter: "^https://appleid\\.apple\\.com/(.*)" + esc + "(.*)$", resourceTypes: ["main_frame", "sub_frame"] } },
  ];
}

async function getConfig() {
  const c = await chrome.storage.local.get(["gatewayHost", "authUser", "authPass"]);
  return { host: (c.gatewayHost || "").trim(), user: (c.authUser || "").trim(), pass: c.authPass || "" };
}

async function clearAll() {
  try { await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: [1,2,3,4,5,6,7,8,9,10,11,12,AUTH_RULE_ID] }); } catch (e) { /* no rules yet */ }
  try { await chrome.scripting.unregisterContentScripts({ ids: ["fingerprint"] }); } catch (e) { /* no script yet */ }
}

async function applyRules() {
  const cfg = await getConfig();
  if (!cfg.host || cfg.host.includes("__")) {
    await clearAll();
    return { ok: false, reason: "not_configured" };
  }
  const rules = buildRules(cfg.host);
  await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: rules.map(r => r.id), addRules: rules });

  if (cfg.user && cfg.pass) {
    const b64 = btoa(cfg.user + ":" + cfg.pass);
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: [AUTH_RULE_ID],
      addRules: [{ id: AUTH_RULE_ID, priority: 2,
        action: { type: "modifyHeaders", requestHeaders: [{ header: "authorization", operation: "set", value: "Basic " + b64 }] },
        condition: { urlFilter: "||" + cfg.host, resourceTypes: RESOURCE_TYPES } }]
    });
  }

  try {
    await chrome.scripting.registerContentScripts([{
      id: "fingerprint",
      matches: ["https://" + cfg.host + "/*"],
      js: ["fingerprint.js"],
      runAt: "document_start",
      allFrames: true,
      matchAboutBlank: true,
      world: "MAIN"
    }]);
  } catch (e) {
    // DNR rules above must work even if the content script can't register yet
    console.error("[gateway] content script registration failed:", e && e.message);
  }

  return { ok: true };
}

async function requestHostPermission() {
  const cfg = await getConfig();
  if (!cfg.host || cfg.host.includes("__")) return { granted: false, reason: "not_configured" };
  try {
    const granted = await chrome.permissions.request({ origins: ["https://" + cfg.host + "/*"] });
    if (granted) await applyRules();
    return { granted };
  } catch (e) {
    return { granted: false, error: e.message };
  }
}

async function healthCheck() {
  const cfg = await getConfig();
  if (!cfg.host || cfg.host.includes("__")) return { ok: false, reason: "not_configured" };
  const granted = await chrome.permissions.contains({ origins: ["https://" + cfg.host + "/*"] });
  if (!granted) return { ok: false, reason: "no_permission" };
  const headers = {};
  if (cfg.user && cfg.pass) headers["Authorization"] = "Basic " + btoa(cfg.user + ":" + cfg.pass);
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 8000);
    const res = await fetch("https://" + cfg.host + "/__health", { headers, signal: ctrl.signal, cache: "no-store" });
    clearTimeout(t);
    if (res.status === 200) {
      const body = await res.json().catch(() => ({}));
      return { ok: true, status: 200, users: body.users, session: body.session };
    }
    if (res.status === 401) return { ok: false, status: 401, reason: "auth_failed" };
    return { ok: false, status: res.status, reason: "http_" + res.status };
  } catch (e) {
    return { ok: false, reason: "unreachable" };
  }
}

async function status() {
  const cfg = await getConfig();
  const granted = cfg.host && !cfg.host.includes("__")
    ? await chrome.permissions.contains({ origins: ["https://" + cfg.host + "/*"] })
    : false;
  let fpRegistered = false;
  try {
    const scripts = await chrome.scripting.getRegisteredContentScripts({ ids: ["fingerprint"] });
    fpRegistered = scripts.length > 0;
  } catch (e) { /* ignore */ }
  let ruleCount = 0;
  try {
    const dr = await chrome.declarativeNetRequest.getDynamicRules();
    ruleCount = dr.length;
  } catch (e) { /* ignore */ }
  return { host: cfg.host, granted, fingerprint: fpRegistered, rules: ruleCount, configured: !!(cfg.host && cfg.user && cfg.pass) };
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg) return;
  const handlers = {
    health: healthCheck,
    status: status,
    apply: applyRules,
  };
  const h = handlers[msg.type];
  if (h) { h().then(sendResponse); return true; }
});

chrome.runtime.onInstalled.addListener(async (details) => {
  await applyRules();
  if (details.reason === "install") {
    const cfg = await getConfig();
    if (!cfg.host) chrome.runtime.openOptionsPage();
  }
});
chrome.runtime.onStartup.addListener(applyRules);
chrome.permissions.onAdded.addListener((p) => {
  // user just granted access to the gateway host — (re)register everything
  if (p && p.origins && p.origins.length) applyRules();
});
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && (changes.gatewayHost || changes.authUser || changes.authPass)) {
    clearAll().then(applyRules);
  }
});
applyRules();
