// Claude Gateway extension background worker.
// - Redirects claude.ai + asset hosts to the gateway (static rules in rules.json).
// - Adds the basic_auth Authorization header from credentials stored via the Options page.
// The auth rule is applied dynamically (updateSessionRules) so each client enters
// their own credentials in Options — no file editing needed.

const GATEWAY_HOST_PLACEHOLDER = "__GATEWAY_HOST__"; // e.g. claude.example.com
const AUTH_RULE_ID = 1000;

async function getGatewayHost() {
  const { gatewayHost } = await chrome.storage.local.get(["gatewayHost"]);
  return (gatewayHost && gatewayHost.trim()) || GATEWAY_HOST_PLACEHOLDER;
}

async function applyAuthRule() {
  const { authUser, authPass, gatewayHost } = await chrome.storage.local.get(["authUser", "authPass", "gatewayHost"]);
  const host = (gatewayHost && gatewayHost.trim()) || GATEWAY_HOST_PLACEHOLDER;
  if (!authUser || !authPass || host.includes("__")) return; // not configured yet
  const b64 = btoa(authUser.trim() + ":" + authPass);
  const rule = {
    id: AUTH_RULE_ID,
    priority: 2,
    action: {
      type: "modifyHeaders",
      requestHeaders: [
        { header: "authorization", operation: "set", value: "Basic " + b64 }
      ]
    },
    condition: {
      urlFilter: "||" + host,
      resourceTypes: ["main_frame","sub_frame","xmlhttprequest","script","stylesheet","image","font","media","websocket","other","csp_report","ping"]
    }
  };
  try {
    await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: [AUTH_RULE_ID], addRules: [rule] });
    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: [AUTH_RULE_ID], addRules: [rule] });
    console.log("[claude-gateway] auth rule applied for", host);
  } catch (e) {
    console.error("[claude-gateway] failed to apply auth rule", e);
  }
}

chrome.runtime.onInstalled.addListener(applyAuthRule);
chrome.runtime.onStartup.addListener(applyAuthRule);
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && (changes.authUser || changes.authPass || changes.gatewayHost)) applyAuthRule();
});
// Apply eagerly on worker start (covers the first request after browser launch).
applyAuthRule();
