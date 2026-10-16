// Shared policy for the background worker and settings page. Destination lists
// must agree with the gateway's CONNECT allowlist; unknown artifact requests
// remain blocked even while the secure proxy is ready.
(function (root) {
  "use strict";
  const DEPENDENCY_HOSTS = Object.freeze(["cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com", "fonts.googleapis.com", "fonts.gstatic.com", "esm.sh", "cdn.tailwindcss.com", "code.jquery.com", "cdn.plot.ly"]);
  const ARTIFACT_DOMAINS = Object.freeze(["claudeusercontent.com", "claudemcpcontent.com"]);
  // Claude's email login requires an invisible hCaptcha token (send_magic_link).
  const CHALLENGE_DOMAINS = Object.freeze(["hcaptcha.com"]);
  const UPSTREAM_HOSTS = Object.freeze(["claude.ai", "www.claude.ai", "assets.claude.ai", "assets-proxy.anthropic.com", "api.anthropic.com", "s-cdn.anthropic.com", "a-cdn.anthropic.com", "a.claude.ai", "a-cdn.claude.ai"]);
  const RESOURCE_TYPES = Object.freeze(["main_frame", "sub_frame", "xmlhttprequest", "script", "stylesheet", "image", "font", "media", "websocket", "other", "csp_report", "ping"]);
  const escapeRegex = value => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const artifactPattern = "(?:[a-z0-9-]+\\.)*(?:claudeusercontent|claudemcpcontent)\\.com";
  const challengePattern = "(?:[a-z0-9-]+\\.)*hcaptcha\\.com";
  const protectedPattern = artifactPattern + "|" + challengePattern + "|" + DEPENDENCY_HOSTS.map(escapeRegex).join("|");

  function validGatewayHost(host) {
    if (typeof host !== "string" || host !== host.toLowerCase()) return false;
    try {
      const url = new URL("https://" + host);
      return url.host === host && url.hostname.includes(".") && !url.username && !url.password && url.pathname === "/" && !url.search && !url.hash;
    } catch (_) { return false; }
  }
  function artifactHost(host) {
    host = String(host).toLowerCase();
    return ARTIFACT_DOMAINS.some(domain => host === domain || host.endsWith("." + domain));
  }
  function challengeHost(host) {
    host = String(host).toLowerCase();
    return CHALLENGE_DOMAINS.some(domain => host === domain || host.endsWith("." + domain));
  }
  function protectedHost(host) {
    return artifactHost(host) || challengeHost(host) || DEPENDENCY_HOSTS.includes(String(host).toLowerCase());
  }
  function requiredOrigins(host) {
    if (!validGatewayHost(host)) throw new Error("Invalid gateway host");
    // Browser host-permission match patterns have no port field. Network/auth
    // rules continue to bind the exact configured authority including its port.
    const gatewayName = new URL("https://" + host).hostname;
    return [...new Set(["https://" + gatewayName + "/*", ...UPSTREAM_HOSTS.map(value => "https://" + value + "/*"), ...DEPENDENCY_HOSTS.map(value => "https://" + value + "/*"), ...[...ARTIFACT_DOMAINS, ...CHALLENGE_DOMAINS].map(value => "https://*." + value + "/*")])];
  }
  function fingerprintMatches(host) {
    if (!validGatewayHost(host)) throw new Error("Invalid gateway host");
    return ["https://" + new URL("https://" + host).hostname + "/*", ...ARTIFACT_DOMAINS.map(domain => "https://*." + domain + "/*")];
  }
  function buildProfileRestrictionRules() {
    // No host validation: malformed nonempty configuration must retain the
    // existing profile restriction while the user repairs their settings.
    // Chrome excludes main_frame even with an empty excluded list.
    return [
      { id: 2002, priority: 150, action: { type: "block" }, condition: { excludedResourceTypes: [] } },
      { id: 2005, priority: 150, action: { type: "block" }, condition: { resourceTypes: ["main_frame"] } }
    ];
  }
  function buildProxyAllowRules(resourceTypes = RESOURCE_TYPES) {
    // Keep each regex small enough for Chrome's compiled RE2 memory limit.
    return [{ id: 2000, priority: 200, action: { type: "allow" }, condition: { requestDomains: [...ARTIFACT_DOMAINS], regexFilter: "^(?:https|wss)://[^/:]+/", resourceTypes: [...resourceTypes] } },
      ...DEPENDENCY_HOSTS.map((host, index) => ({ id: 2010 + index, priority: 200, action: { type: "allow" }, condition: { regexFilter: "^(?:https|wss)://" + escapeRegex(host) + "/", resourceTypes: [...resourceTypes] } })),
      { id: 2019, priority: 200, action: { type: "allow" }, condition: { requestDomains: [...CHALLENGE_DOMAINS], regexFilter: "^(?:https|wss)://[^/:]+/", resourceTypes: [...resourceTypes] } }];
  }
  function buildScopedRestrictionRules(host) {
    if (!validGatewayHost(host)) throw new Error("Invalid gateway host");
    // Firefox runs in the user's everyday profile: only requests started by
    // gateway pages or artifact frames are restricted. Top-level navigations
    // (links opened from Claude) remain ordinary browsing.
    const initiatorDomains = [new URL("https://" + host).hostname, ...ARTIFACT_DOMAINS];
    return [
      { id: 2002, priority: 150, action: { type: "block" }, condition: { initiatorDomains, excludedResourceTypes: ["main_frame"] } },
      { id: 2003, priority: 350, action: { type: "block" }, condition: { regexFilter: "^(?:http|ws)://", initiatorDomains, excludedResourceTypes: ["main_frame"] } }
    ];
  }
  function buildPrivacyRules(host, resourceTypes = RESOURCE_TYPES, { scoped = false } = {}) {
    if (!validGatewayHost(host)) throw new Error("Invalid gateway host");
    const gatewayDomain = new URL("https://" + host).hostname;
    const restriction = scoped ? buildScopedRestrictionRules(host) : [
      // Dedicated browser profile: no initiator filter. Sandboxed opaque frames,
      // popups and service workers can omit the originating site's domain.
      // Only higher-priority gateway/redirect/ready TLS-route rules can allow
      // a destination. The PAC also rejects unknown targets without DIRECT.
      // Enumerating only familiar resource types would omit object,
      // WebTransport, webbundles or future browser types. Chrome still excludes
      // main_frame with an empty excluded list, so a separate rule covers it.
      ...buildProfileRestrictionRules(),
      // No unencrypted fallback, including destinations on the CONNECT list.
      { id: 2003, priority: 350, action: { type: "block" }, condition: { regexFilter: "^(?:http|ws)://", excludedResourceTypes: [] } }
    ];
    return [
      // Do not remove Content-Security-Policy: DNR cannot safely remove only a
      // frame-ancestors directive from a mixed policy. artifact-csp.js handles
      // the narrow gateway ancestor addition while retaining every policy.
      { id: 5, priority: 300, action: { type: "modifyHeaders", responseHeaders: [{ header: "x-frame-options", operation: "remove" }] }, condition: { regexFilter: "^https://(?:" + artifactPattern + ")/", initiatorDomains: [gatewayDomain], resourceTypes: ["sub_frame"] } },
      { id: 2001, priority: 200, action: { type: "allow" }, condition: { regexFilter: "^(?:https|wss)://" + escapeRegex(host) + "/", resourceTypes: [...resourceTypes] } },
      ...restriction,
      // Claude/API sockets require the gateway's server-side cookie session.
      // Until a tested socket rewrite exists, reject them before any transport.
      { id: 2004, priority: 350, action: { type: "block" }, condition: { regexFilter: "^wss://", requestDomains: [...UPSTREAM_HOSTS], resourceTypes: ["websocket"] } }
    ];
  }

  const api = Object.freeze({ DEPENDENCY_HOSTS, ARTIFACT_DOMAINS, CHALLENGE_DOMAINS, UPSTREAM_HOSTS, RESOURCE_TYPES, artifactHost, challengeHost, protectedHost, protectedPattern, artifactPattern, validGatewayHost, requiredOrigins, fingerprintMatches, buildProfileRestrictionRules, buildScopedRestrictionRules, buildProxyAllowRules, buildPrivacyRules });
  root.GatewayPrivacy = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(globalThis);
