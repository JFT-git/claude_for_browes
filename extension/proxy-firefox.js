// Firefox runs in the user's everyday profile, so routing is scoped to Claude:
// artifact hosts always, and CDN hosts only when a gateway page, an artifact
// frame or this extension's own check requests them. Every other request keeps
// Firefox's own network settings; no browser-wide proxy is installed. Claude
// documents may reach only the gateway, Claude hosts and the CONNECT list.
(function (root) {
  "use strict";
  const DEAD = Object.freeze({ type: "http", host: "127.0.0.1", port: 9 });
  function create({ browser, protectedHost, artifactHost, upstreamHost = () => false, filter, warmupUrl, isExtensionRequest }) {
    const setting = browser.proxy?.settings;
    let gateway = "", configured = false, session = null, warming = false, warmupRouted = false, isolation = "", serial = 0;
    let reason = "proxy_baseline_unavailable";
    let available = !!(browser.proxy?.onRequest && browser.webRequest?.onBeforeRequest);
    const fail = code => { const error = new Error(code); error.reason = code; return error; };
    function usable() {
      const p = session?.proxy;
      return !!(configured && session?.proxyUsername === "gateway-proxy" && /^[A-Za-z0-9_-]{43}$/.test(session.proxyPassword)
        && Number.isSafeInteger(session.expiresAt) && session.expiresAt > Date.now() && p?.scheme === "https"
        && typeof p.host === "string" && p.host.includes(".") && /^[a-z0-9]+(?:[.-][a-z0-9]+)*$/.test(p.host)
        && Number.isInteger(p.port) && p.port > 0 && p.port <= 65535);
    }
    function claudeDocument(value) {
      try {
        let u = new URL(value);
        if (u.protocol === "blob:") u = new URL(u.pathname);
        return u.protocol === "https:" && !u.username && !u.password && (!!gateway && u.host === gateway || artifactHost(u.hostname));
      } catch (_) { return false; }
    }
    // Unlike DNR initiators, document and ancestor URLs also identify opaque
    // sandboxed frames and blob workers inside Claude pages.
    function fromClaude(details) {
      const ancestors = Array.isArray(details.frameAncestors) ? details.frameAncestors.map(frame => frame?.url) : [];
      return [details.originUrl, details.documentUrl, ...ancestors].some(claudeDocument);
    }
    // Requests outside this scope belong to the user's other sites.
    function inScope(details) {
      try { if (artifactHost(new URL(details.url).hostname)) return true; } catch (_) { return false; }
      return fromClaude(details) || isExtensionRequest(details);
    }
    function egress(details) {
      // Links opened from Claude are ordinary browsing in a new document.
      if (details.type === "main_frame" || !fromClaude(details)) return {};
      let u;
      try { u = new URL(details.url); } catch (_) { return { cancel: true }; }
      if (!["http:", "https:", "ws:", "wss:"].includes(u.protocol)) return {};
      const secure = (u.protocol === "https:" || u.protocol === "wss:") && !u.username && !u.password;
      // Protected hosts are decided by the gate; Claude hosts are redirected to the gateway.
      return secure && (!!gateway && u.host === gateway || !u.port && (protectedHost(u.hostname) || upstreamHost(u.hostname))) ? {} : { cancel: true };
    }
    function intended(details) {
      try {
        const u = new URL(details.url);
        if (!["https:", "wss:"].includes(u.protocol) || u.port || u.username || u.password || !protectedHost(u.hostname)) return false;
        return !warming || details.url === warmupUrl && details.method === "HEAD" && isExtensionRequest(details);
      } catch (_) { return false; }
    }
    const allowed = details => usable() && intended(details);
    function route(details) {
      // Undefined keeps Firefox's own proxy choice. Explicit null would force
      // DIRECT, so in-scope requests always receive an explicit route.
      if (!inScope(details)) return undefined;
      if (!allowed(details)) return { ...DEAD };
      if (warming) warmupRouted = true;
      // Header authentication avoids the 407 round trip; the isolation key
      // keeps tunnels opened with a retired token out of the new session.
      return { type: "https", host: session.proxy.host, port: session.proxy.port, failoverTimeout: 5,
        proxyAuthorizationHeader: "Basic " + btoa(session.proxyUsername + ":" + session.proxyPassword), connectionIsolationKey: isolation };
    }
    function gate(details) { return inScope(details) && !allowed(details) ? { cancel: true } : {}; }
    if (available) {
      try {
        // Register the blocking gates before the routing callback.
        browser.webRequest.onBeforeRequest.addListener(egress, { urls: ["<all_urls>"] }, ["blocking"]);
        browser.webRequest.onBeforeRequest.addListener(gate, { urls: filter }, ["blocking"]);
        browser.proxy.onRequest.addListener(route, { urls: filter });
      } catch (_) { available = false; reason = "firefox_proxy_api_unavailable"; }
    }
    async function releaseLegacySetting() {
      // Builds before 2.0.6 installed a browser-wide dead-end proxy. Clearing
      // needs no private-window access and restores the user's own settings.
      try {
        if ((await setting?.get({}))?.levelOfControl === "controlled_by_this_extension") await setting.clear({});
      } catch (_) { /* Not ours, or unsupported on this platform. */ }
    }
    return {
      async ensure(host) {
        configured = false; session = null; warming = false; reason = "proxy_baseline_unavailable";
        if (!browser.runtime?.getPlatformInfo) throw fail("firefox_proxy_api_unavailable");
        const platform = await browser.runtime.getPlatformInfo();
        if (platform.os === "android") { reason = "firefox_android_unsupported"; throw fail(reason); }
        if (!available) { reason = "firefox_proxy_api_unavailable"; throw fail(reason); }
        let origin;
        try { origin = new URL("https://" + host); } catch (_) { throw fail("invalid_gateway"); }
        if (origin.host !== host || origin.username || origin.password || origin.pathname !== "/" || origin.search || origin.hash) throw fail("invalid_gateway");
        await releaseLegacySetting();
        gateway = host; configured = true; reason = "";
      },
      setSession(value, options = {}) {
        session = value; warming = options.warming === true; warmupRouted = false; isolation = "gateway-proxy-" + (++serial);
        if (!usable()) { session = null; warming = false; throw fail("proxy_baseline_unavailable"); }
      },
      warmupRouted() { return warmupRouted; },
      releaseLegacy: releaseLegacySetting,
      reset() { session = null; warming = false; },
      async clear() {
        configured = false; session = null; warming = false; gateway = ""; reason = "not_configured";
        await releaseLegacySetting();
      },
      status() { return { available, baselineReady: configured, sessionReady: usable() && !warming, warming: usable() && warming, reason }; },
      // Pure predicates support unit tests and keep all credential data private.
      inScope, route, gate, egress
    };
  }
  const api = Object.freeze({ create });
  root.GatewayProxyFirefox = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(globalThis);
