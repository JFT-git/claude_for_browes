// Claude Gateway — background worker.
// - Static redirect rules (rules.json) route claude.ai + asset hosts to the gateway.
// - The basic_auth Authorization header is applied dynamically from credentials
//   entered on the Options page (no file editing per client).
// - Onboarding: opens Options on first install if not configured.
// - Health: answers "ping" from the popup with gateway reachability + auth status.

const HOST_PLACEHOLDER = "__GATEWAY_HOST__";
const AUTH_RULE_ID = 1000;
const RESOURCE_TYPES = ["main_frame","sub_frame","xmlhttprequest","script","stylesheet","image","font","media","websocket","other","csp_report","ping"];

async function getConfig() {
  const c = await chrome.storage.local.get(["gatewayHost", "authUser", "authPass"]);
  return {
    host: (c.gatewayHost || "").trim(),
    user: (c.authUser || "").trim(),
    pass: c.authPass || ""
  };
}

function configured(cfg) {
  return cfg.host && !cfg.host.includes("__") && cfg.user && cfg.pass;
}

async function applyAuthRule() {
  const cfg = await getConfig();
  if (!configured(cfg)) return false;
  const b64 = btoa(cfg.user + ":" + cfg.pass);
  const rule = {
    id: AUTH_RULE_ID,
    priority: 2,
    action: { type: "modifyHeaders", requestHeaders: [{ header: "authorization", operation: "set", value: "Basic " + b64 }] },
    condition: { urlFilter: "||" + cfg.host, resourceTypes: RESOURCE_TYPES }
  };
  try {
    await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: [AUTH_RULE_ID], addRules: [rule] });
    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: [AUTH_RULE_ID], addRules: [rule] });
    return true;
  } catch (e) {
    console.error("[claude-gateway] auth rule failed", e);
    return false;
  }
}

// Health check used by the popup: reach the gateway /__health with basic_auth.
async function healthCheck() {
  const cfg = await getConfig();
  if (!cfg.host || cfg.host.includes("__")) return { ok: false, reason: "not_configured" };
  const headers = {};
  if (cfg.user && cfg.pass) headers["Authorization"] = "Basic " + btoa(cfg.user + ":" + cfg.pass);
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 8000);
    const res = await fetch("https://" + cfg.host + "/__health", { headers, signal: ctrl.signal, cache: "no-store" });
    clearTimeout(t);
    if (res.status === 200) {
      const body = await res.json().catch(() => ({}));
      return { ok: true, status: 200, users: body.users };
    }
    if (res.status === 401) return { ok: false, status: 401, reason: "auth_failed" };
    return { ok: false, status: res.status, reason: "http_" + res.status };
  } catch (e) {
    return { ok: false, reason: "unreachable" };
  }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.type === "health") {
    healthCheck().then(sendResponse);
    return true; // async
  }
});

chrome.runtime.onInstalled.addListener(async (details) => {
  await applyAuthRule();
  if (details.reason === "install") {
    const cfg = await getConfig();
    if (!configured(cfg)) chrome.runtime.openOptionsPage();
  }
});
chrome.runtime.onStartup.addListener(applyAuthRule);
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && (changes.authUser || changes.authPass || changes.gatewayHost)) applyAuthRule();
});
applyAuthRule();
