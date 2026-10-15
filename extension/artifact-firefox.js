// Firefox's blocking webRequest adapter changes only scoped artifact headers.
// It never reads a response body and never owns proxy or network exceptions.
(function (root) {
  "use strict";
  const MAX_REQUESTS = 128, MAX_TABS = 32, MAX_FRAMES = 1024;
  const REQUEST_TIMEOUT_MS = 15000, LOOKUP_TIMEOUT_MS = 2000;
  const DOMAINS = ["claudeusercontent.com", "claudemcpcontent.com"];
  const URLS = DOMAINS.flatMap(domain => ["https://" + domain + "/*", "https://*." + domain + "/*"]);
  const FILTER = { urls: URLS, types: ["sub_frame", "xmlhttprequest"] };
  function create({ browser, isReady = () => false, onUnsafeDetach = () => {}, csp = root.GatewayArtifactCsp, cors = root.GatewayArtifactCors }) {
    const requests = new Map(), tabStates = new Map();
    let host = "", epoch = 0, failed = false, lastError = "";
    const registrations = [];
    let available = !!(browser?.webRequest && browser?.webNavigation?.getAllFrames && browser?.tabs?.get && csp?.appendGatewayAncestor && cors?.requestHeaders);
    function ready() { try { return available && !failed && !!host && isReady(); } catch (_) { return false; } }
    function origin(value = host) {
      try { const u = new URL("https://" + value); return u.host === value && u.hostname.includes(".") && !u.username && !u.password && u.pathname === "/" && !u.search && !u.hash ? u.origin : null; }
      catch (_) { return null; }
    }
    function owned(url) { try { const u = new URL(url); return u.protocol === "https:" && !u.username && !u.password && u.origin === origin(); } catch (_) { return false; } }
    function artifact(url) { try { const u = new URL(url); return u.protocol === "https:" && !u.port && !u.username && !u.password && DOMAINS.some(d => u.hostname === d || u.hostname.endsWith("." + d)); } catch (_) { return false; } }
    function fault(reason) {
      if (failed) return;
      failed = true; lastError = reason; epoch++;
      for (const pair of requests.values()) pair.blocked = true;
      try { onUnsafeDetach(); } catch (_) { /* The network owner remains responsible for routing. */ }
    }
    function bounded(promise) {
      let timer;
      return Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("Frame lookup timeout")), LOOKUP_TIMEOUT_MS); })]).finally(() => clearTimeout(timer));
    }
    function live(pair) { return ready() && pair.epoch === epoch && !pair.blocked && pair.until > Date.now(); }
    function same(details, pair) { return details.tabId === pair.tabId && details.frameId === pair.frameId && details.url === pair.url && details.method === pair.method; }
    function cancel(pair) { if (pair) pair.blocked = true; return { cancel: true }; }
    function headersCopy(headers) {
      if (!Array.isArray(headers)) return null;
      const result = [];
      for (const header of headers) {
        if (!header || typeof header.name !== "string" || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(header.name)) return null;
        if (typeof header.value === "string") { if (/[\r\n]/.test(header.value)) return null; }
        else if (!Array.isArray(header.binaryValue)) return null;
        result.push({ ...header, ...(Array.isArray(header.binaryValue) ? { binaryValue: header.binaryValue.slice() } : {}) });
      }
      return result;
    }
    function corsEvent(details, headers, response = false) {
      return { resourceType: "Fetch", request: { url: details.url, method: details.method, headers },
        ...(response ? { responseStatusCode: details.statusCode, responseHeaders: headers } : {}) };
    }
    function corsHeaders(details, headers, frameUrl, response = false, repeat = false) {
      const copy = headersCopy(headers);
      if (!copy) return null;
      const target = response ? "access-control-allow-origin" : "origin";
      const selected = copy.filter(header => header.name.toLowerCase() === target);
      if (selected.length !== 1 || typeof selected[0].value !== "string") return null;
      const view = copy.filter(header => typeof header.value === "string");
      if (repeat && !response && selected[0].value === cors.UPSTREAM_ORIGIN) return copy;
      const changed = response ? cors.responseHeaders(corsEvent(details, view, true), host) : cors.requestHeaders(corsEvent(details, view), host, frameUrl);
      if (!changed) return null;
      const replacement = changed.find(header => header.name.toLowerCase() === target);
      return copy.map(header => header.name.toLowerCase() === target ? { ...header, value: replacement.value } : header);
    }
    function frameHeaders(details) {
      if (details.statusCode !== 200 || csp.isAttachmentResponse(details.responseHeaders)) return null;
      const copy = headersCopy(details.responseHeaders);
      if (!copy) return null;
      // Unknown binary security policy must remain original, rather than being
      // silently dropped while changing some other header.
      if (copy.some(h => ["content-security-policy", "content-security-policy-report-only", "x-frame-options"].includes(h.name.toLowerCase()) && typeof h.value !== "string")) return null;
      let changed = false;
      const result = [];
      for (const header of copy) {
        const name = header.name.toLowerCase();
        if (name === "x-frame-options") { changed = true; continue; }
        const value = ["content-security-policy", "content-security-policy-report-only"].includes(name) ? csp.appendGatewayAncestor(header.value, origin()) : header.value;
        if (value !== header.value) changed = true;
        result.push(typeof header.value === "string" ? { ...header, value } : header);
      }
      return changed ? result : null;
    }
    function revisionMatches(scope) { return scope.state === tabStates.get(scope.tabId) && scope.ids.every(id => (scope.state.versions.get(id) || 0) === (scope.versions.get(id) || 0)); }
    async function scope(details, kind) {
      if (!ready() || !artifact(details.url) || !Number.isInteger(details.tabId) || details.tabId < 0 || !Number.isInteger(details.frameId) || details.frameId < 0) return null;
      if (kind === "cors" && (!owned(details.documentUrl) || details.originUrl && !owned(details.originUrl))) return null;
      if (kind === "frame" && (!Array.isArray(details.frameAncestors) || !details.frameAncestors.length)) return null;
      let state = tabStates.get(details.tabId);
      if (!state) {
        if (tabStates.size >= MAX_TABS) { fault("tab_limit"); return null; }
        state = { versions: new Map() }; tabStates.set(details.tabId, state);
      }
      const savedEpoch = epoch, versions = new Map(state.versions);
      const [tab, all] = await bounded(Promise.all([browser.tabs.get(details.tabId), browser.webNavigation.getAllFrames({ tabId: details.tabId })]));
      if (!ready() || epoch !== savedEpoch || !owned(tab?.url) || tab.pendingUrl && !owned(tab.pendingUrl) || !Array.isArray(all) || all.length > MAX_FRAMES) return null;
      const frames = new Map(all.map(frame => [frame.frameId, frame]));
      if (frames.size !== all.length || !owned(frames.get(0)?.url)) return null;
      const ancestors = [];
      let frame;
      if (kind === "frame") {
        if (details.frameId === 0 || details.frameAncestors[0]?.frameId !== details.parentFrameId) return null;
        for (const item of details.frameAncestors) {
          frame = frames.get(item.frameId);
          if (!frame || frame.url !== item.url) return null;
          ancestors.push(frame);
        }
      } else {
        frame = frames.get(details.frameId);
        if (!frame || !owned(frame.url) || frame.url !== details.documentUrl) return null;
        let cursor = frame;
        const seen = new Set();
        while (cursor) {
          if (seen.has(cursor.frameId)) return null;
          seen.add(cursor.frameId); ancestors.push(cursor);
          if (cursor.frameId === 0) break;
          cursor = frames.get(cursor.parentFrameId);
        }
      }
      if (!ancestors.length || ancestors.at(-1).frameId !== 0 || !owned(ancestors.at(-1).url)) return null;
      const ids = [details.frameId];
      for (let index = 0; index < ancestors.length; index++) {
        const item = ancestors[index];
        if (kind === "frame" && item.frameId === details.frameId || ids.includes(item.frameId) && !(kind === "cors" && index === 0 && item.frameId === details.frameId)) return null;
        if (!owned(item.url) && !artifact(item.url)) return null;
        if (index + 1 < ancestors.length && item.parentFrameId !== ancestors[index + 1].frameId) return null;
        if (!ids.includes(item.frameId)) ids.push(item.frameId);
      }
      const result = { tabId: details.tabId, frameUrl: kind === "cors" ? frames.get(details.frameId).url : ancestors.at(-1).url, ids, state, versions, epoch: savedEpoch };
      return revisionMatches(result) ? result : null;
    }
    function matchesScope(pair, currentScope) { return pair.scope.ids.length === currentScope.ids.length && pair.scope.ids.every((id, index) => id === currentScope.ids[index]) && revisionMatches(pair.scope); }
    function insert(details, kind, context) {
      if (!ready() || context.epoch !== epoch || !revisionMatches(context)) return null;
      if (requests.size >= MAX_REQUESTS) { fault("request_limit"); return null; }
      const pair = { kind, tabId: details.tabId, frameId: details.frameId, url: details.url, method: details.method,
        epoch, scope: context, until: Date.now() + REQUEST_TIMEOUT_MS, blocked: false };
      requests.set(details.requestId, pair);
      return pair;
    }
    function beforeRequest(details) {
      const pair = requests.get(details.requestId);
      if (pair && (!live(pair) || !same(details, pair))) return cancel(pair);
      return {};
    }
    async function beforeSend(details) {
      let pair = requests.get(details.requestId);
      if (pair && (!live(pair) || !same(details, pair))) return cancel(pair);
      if (!ready() || !artifact(details.url)) return {};
      const kind = details.type === "xmlhttprequest" ? "cors" : details.type === "sub_frame" ? "frame" : null;
      if (!kind) return {};
      if (pair && pair.kind !== kind) return cancel(pair);
      try {
        const context = await scope(details, kind);
        if (!context) return pair?.kind === "cors" ? cancel(pair) : {};
        if (pair && (!live(pair) || requests.get(details.requestId) !== pair || !matchesScope(pair, context))) return cancel(pair);
        const changed = kind === "cors" ? corsHeaders(details, details.requestHeaders, context.frameUrl, false, !!pair) : null;
        if (kind === "cors" && !changed) return pair ? cancel(pair) : {};
        // The asynchronous lookups yield; repeat identity/capacity checks with
        // no await before storing a new Origin rewrite authorization.
        if (!pair) {
          if (requests.has(details.requestId)) return cancel(requests.get(details.requestId));
          pair = insert(details, kind, context);
          if (!pair) return kind === "cors" && !ready() ? { cancel: true } : {};
        }
        return changed ? { requestHeaders: changed } : {};
      } catch (_) { lastError = "scope_unavailable"; return pair?.kind === "cors" ? cancel(pair) : {}; }
    }
    async function received(details) {
      const pair = requests.get(details.requestId);
      if (!pair) return {};
      // A frame navigation that becomes a download is not an embedded document.
      // Preserve all metadata and let Firefox stream it without any body limit.
      if (pair.kind === "frame" && csp.isAttachmentResponse(details.responseHeaders)) { requests.delete(details.requestId); return {}; }
      if (!live(pair) || !same(details, pair)) return cancel(pair);
      if (details.statusCode >= 300 && details.statusCode < 400 && details.statusCode !== 304) {
        // Frame requests never rewrite Origin. Let the browser follow its
        // redirect under the profile route policy, then independently validate
        // the final artifact frame before granting any header compatibility.
        if (pair.kind === "frame") { requests.delete(details.requestId); return {}; }
        return cancel(pair);
      }
      try {
        const context = await scope(details, pair.kind);
        if (!context || !live(pair) || requests.get(details.requestId) !== pair || !matchesScope(pair, context)) return cancel(pair);
        const changed = pair.kind === "cors" ? corsHeaders(details, details.responseHeaders, context.frameUrl, true) : frameHeaders(details);
        return changed ? { responseHeaders: changed } : {};
      } catch (_) { lastError = "response_unavailable"; return cancel(pair); }
    }
    function redirect(details) {
      const pair = requests.get(details.requestId);
      if (pair?.kind === "frame") requests.delete(details.requestId);
      else if (pair) pair.blocked = true;
    }
    function terminal(details) { requests.delete(details.requestId); }
    function navigate(details) {
      const state = tabStates.get(details.tabId);
      if (state) {
        if (!state.versions.has(details.frameId) && state.versions.size >= MAX_FRAMES) { fault("frame_limit"); return; }
        state.versions.set(details.frameId, (state.versions.get(details.frameId) || 0) + 1);
      }
      for (const pair of requests.values()) if (pair.tabId === details.tabId && pair.scope.ids.includes(details.frameId)) pair.blocked = true;
    }
    function removed(tabId) { tabStates.delete(tabId); for (const [id, pair] of requests) if (pair.tabId === tabId) requests.delete(id); }
    function register(event, listener, ...args) {
      if (!event?.addListener || !event?.removeListener) throw new Error("Required Firefox API unavailable");
      event.addListener(listener, ...args); registrations.push([event, listener]);
    }
    try {
      if (!available) throw new Error("Required Firefox API unavailable");
      register(browser.webRequest.onBeforeRequest, beforeRequest, { urls: ["<all_urls>"] }, ["blocking"]);
      register(browser.webRequest.onBeforeSendHeaders, beforeSend, FILTER, ["blocking", "requestHeaders"]);
      register(browser.webRequest.onHeadersReceived, received, FILTER, ["blocking", "responseHeaders"]);
      register(browser.webRequest.onBeforeRedirect, redirect, FILTER);
      register(browser.webRequest.onCompleted, terminal, { urls: ["<all_urls>"] });
      register(browser.webRequest.onErrorOccurred, terminal, { urls: ["<all_urls>"] });
      register(browser.webNavigation.onBeforeNavigate, navigate);
      register(browser.webNavigation.onCommitted, navigate);
      register(browser.webNavigation.onErrorOccurred, navigate);
      register(browser.tabs.onRemoved, removed);
    } catch (_) {
      available = false; lastError = "unsupported";
      for (const [event, listener] of registrations) { try { event.removeListener(listener); } catch (_) {} }
    }
    return {
      async configure(value) {
        epoch++; for (const pair of requests.values()) pair.blocked = true;
        tabStates.clear(); failed = false; host = origin(value) ? value : "";
        lastError = available ? (host ? "" : "invalid_gateway") : "unsupported";
      },
      async stop() { epoch++; host = ""; for (const pair of requests.values()) pair.blocked = true; tabStates.clear(); },
      clearSuppressed() { if (!host) { failed = false; lastError = available ? "" : "unsupported"; } },
      status() { return { available, active: ready(), attachedTabs: 0, blockedTabs: failed ? 1 : 0, pendingRequests: requests.size, lastError }; }
    };
  }
  const api = Object.freeze({ create, MAX_REQUESTS, MAX_TABS, MAX_FRAMES, REQUEST_TIMEOUT_MS, LOOKUP_TIMEOUT_MS });
  root.GatewayArtifactFirefox = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(globalThis);
