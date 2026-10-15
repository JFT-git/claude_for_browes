// The debugger preserves artifact frame policy and pairs narrow CORS header
// compatibility for exact gateway-owned frames. Network routing and proxy
// authentication remain owned by the background's fail-closed lifecycle.
(function (root) {
  "use strict";
  const MAX_TABS = 32, MAX_SESSIONS = 256, MAX_FRAMES = 1024, MAX_RESPONSES = 4;
  const MAX_CORS_REQUESTS = 128, CORS_TIMEOUT_MS = 15000;
  function create({ chrome, isReady, onUnsafeDetach }) {
    const api = chrome.debugger;
    const tabs = new Map(), suppressed = new Set(), detaching = new Map(), attaching = new Map();
    let host = "", generation = 0;
    const supported = !!(api?.attach && api?.sendCommand && chrome.tabs?.get && chrome.tabs?.query);
    let lastError = supported ? "" : "unsupported";
    const origin = () => host && new URL("https://" + host).origin;
    function ownedURL(url) {
      try { const u = new URL(url); return u.protocol === "https:" && !u.username && !u.password && u.origin === origin(); }
      catch (_) { return false; }
    }
    function candidateTab(tab) {
      if (!tab) return false;
      if (ownedURL(tab.url)) return !tab.pendingUrl || ownedURL(tab.pendingUrl);
      // Never attach an existing foreign page merely because it is navigating
      // toward the gateway. A fresh blank tab with that pending URL is safe.
      return tab.url === "about:blank" && ownedURL(tab.pendingUrl);
    }
    function atCapacity(tabId) {
      const occupied = new Set([...tabs.keys(), ...attaching.keys(), ...detaching.keys()]);
      return !occupied.has(tabId) && occupied.size >= MAX_TABS;
    }
    function current(state) { return state.active && state.generation === generation && tabs.get(state.tabId) === state && host === state.host && isReady(); }
    function sourceKey(source) { return source.sessionId || "root"; }
    async function bounded(promise) {
      let timer;
      try {
        return await Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("Artifact debugger timeout")), 5000); })]);
      } finally { clearTimeout(timer); }
    }
    function command(source, method, params = {}) { return bounded(api.sendCommand(source, method, params)); }
    function mergeFrame(state, frame) {
      if (!frame?.id) return;
      if (!state.frames.has(frame.id) && state.frames.size >= MAX_FRAMES) throw new Error("Artifact frame limit");
      state.frames.set(frame.id, { ...state.frames.get(frame.id), ...frame });
    }
    function mergeTree(state, tree) {
      if (!tree) return;
      mergeFrame(state, tree.frame);
      for (const child of tree.childFrames || []) mergeTree(state, child);
    }
    async function refreshFrames(state, source = { tabId: state.tabId }) {
      const tree = await command(source, "Page.getFrameTree");
      if (!current(state)) throw new Error("Artifact configuration changed");
      mergeTree(state, tree.frameTree);
      if (!source.sessionId) state.rootFrameId = tree.frameTree?.frame?.id;
    }
    async function ownedTab(state) {
      const tab = await chrome.tabs.get(state.tabId);
      return current(state) && ownedURL(tab.url) && (!tab.pendingUrl || ownedURL(tab.pendingUrl));
    }
    async function verifyCommittedRoot(state) {
      try {
        const result = await command({ tabId: state.tabId }, "Page.getFrameTree");
        if (!current(state)) return;
        if (!ownedURL(result.frameTree?.frame?.url)) { await detachState(state); return; }
        mergeTree(state, result.frameTree);
        state.rootFrameId = result.frameTree.frame.id;
      } catch (_) { if (current(state)) await detachState(state); }
    }
    function parentFor(state, frameId) {
      const frame = state.frames.get(frameId);
      if (!frame?.parentId || frame.id === state.rootFrameId) return null;
      const seen = new Set([frameId]);
      let cursor = state.frames.get(frame.parentId);
      while (cursor) {
        if (seen.has(cursor.id)) return null;
        seen.add(cursor.id);
        if (cursor.id === state.rootFrameId) return ownedURL(cursor.url) ? cursor.url : null;
        let artifact = false;
        try {
          const u = new URL(cursor.url);
          artifact = u.protocol === "https:" && !u.port && !u.username && !u.password
            && GatewayPrivacy.ARTIFACT_DOMAINS.some(domain => u.hostname === domain || u.hostname.endsWith("." + domain));
        } catch (_) { /* Opaque or unknown intermediate frame: leave CSP intact. */ }
        if (!ownedURL(cursor.url) && !artifact) return null;
        cursor = state.frames.get(cursor.parentId);
      }
      return null;
    }
    async function detachState(state) {
      const owner = tabs.get(state.tabId);
      if (owner && owner !== state) { state.active = false; return; }
      if (tabs.get(state.tabId) === state) tabs.delete(state.tabId);
      state.active = false;
      state.frames.clear(); state.sessions.clear();
      for (const pair of state.corsRequests.values()) clearTimeout(pair.timer);
      state.corsRequests.clear();
      // A rejected/pending attach does not prove ownership. Never detach the
      // debugger belonging to DevTools or another extension to recover it.
      if (!state.nativeAttached) return;
      if (state.detachTask) { try { await bounded(state.detachTask); } catch (_) {} return; }
      const task = api.detach({ tabId: state.tabId });
      state.detachTask = task;
      detaching.set(state.tabId, task);
      task.then(() => { if (detaching.get(state.tabId) === task) detaching.delete(state.tabId); },
        () => { if (detaching.get(state.tabId) === task) detaching.delete(state.tabId); });
      // The caller has a deadline; the quarantine keeps the raw operation until
      // it actually settles, preventing a late detach from closing a new one.
      try { await bounded(task); } catch (_) { /* Already gone or outcome unknown. */ }
    }
    async function unsafe(state) {
      if (!current(state)) return;
      suppressed.add(state.tabId);
      lastError = "detached";
      onUnsafeDetach();
      if (state.active) await detachState(state);
    }
    async function setupSession(state, source, waiting = false) {
      try {
        if (!current(state)) throw new Error("Artifact configuration changed");
        await command(source, "Page.enable");
        await refreshFrames(state, source);
        await command(source, "Fetch.enable", { patterns: [...GatewayArtifactCsp.buildFetchPatterns(), ...GatewayArtifactCors.buildFetchPatterns()], handleAuthRequests: false });
        await command(source, "Target.setAutoAttach", { autoAttach: true, waitForDebuggerOnStart: true, flatten: true, filter: [{ type: "iframe", exclude: false }] });
        if (!current(state)) throw new Error("Artifact configuration changed");
      } finally {
        // No child may remain suspended if setup fails or configuration changes.
        if (waiting) { try { await command(source, "Runtime.runIfWaitingForDebugger"); } catch (_) { /* Root detach also resumes children. */ } }
      }
    }
    async function attach(tabId) {
      if (!supported || !host || !isReady() || suppressed.has(tabId) || tabs.has(tabId) || attaching.has(tabId)) return;
      if (atCapacity(tabId)) { lastError = "tab_limit"; onUnsafeDetach(); return; }
      if (detaching.has(tabId)) return;
      if (tabs.has(tabId) || attaching.has(tabId) || suppressed.has(tabId) || !host || !isReady()) return;
      const tab = await chrome.tabs.get(tabId).catch(() => null);
      if (attaching.has(tabId) || !candidateTab(tab)) return;
      if (atCapacity(tabId)) { lastError = "tab_limit"; onUnsafeDetach(); return; }
      const state = { tabId, host, generation, active: true, ready: false, sessions: new Map(), frames: new Map(), corsRequests: new Map(), inFlight: 0 };
      tabs.set(tabId, state);
      state.setup = (async () => {
        let attached = false;
        try {
          const attempt = api.attach({ tabId }, "1.3");
          attaching.set(tabId, attempt);
          // Keep the tab quarantined while an attach has an unknown outcome.
          // A later configuration must not race a late old attach/detach.
          attempt.then(async () => {
            state.nativeAttached = true;
            if (!current(state) && !tabs.has(tabId)) await detachState(state);
            if (attaching.get(tabId) === attempt) attaching.delete(tabId);
            if (!tabs.has(tabId) && host && isReady() && !suppressed.has(tabId)) attach(tabId).catch(() => {});
          }, () => { if (attaching.get(tabId) === attempt) attaching.delete(tabId); });
          await bounded(attempt); attached = true; state.nativeAttached = true;
          if (!current(state)) throw new Error("Artifact configuration changed");
          state.sessions.set("root", { tabId });
          await setupSession(state, { tabId });
          if (!current(state) || !candidateTab(await chrome.tabs.get(tabId))) throw new Error("Gateway tab navigated");
          state.ready = true;
        } catch (_) {
          // Never detach a session we failed to attach: it may belong to DevTools
          // or another extension. Original artifact CSP remains in force.
          const wasCurrent = current(state);
          if (!attached) { state.active = false; if (tabs.get(tabId) === state) tabs.delete(tabId); }
          if (wasCurrent) { suppressed.add(tabId); lastError = attached ? "setup_failed" : "attach_failed"; onUnsafeDetach(); }
          if (attached) await detachState(state);
          else { state.active = false; if (tabs.get(tabId) === state) tabs.delete(tabId); }
        }
      })();
      await state.setup;
    }
    const corsKey = (source, requestId) => sourceKey(source) + "\0" + requestId;
    function forgetCors(state, key) {
      const pair = state.corsRequests.get(key);
      if (pair) clearTimeout(pair.timer);
      state.corsRequests.delete(key);
      return pair;
    }
    async function corsPaused(state, source, event) {
      const key = corsKey(source, event.requestId);
      const paired = state.corsRequests.get(key);
      const fail = () => command(source, "Fetch.failRequest", { requestId: event.requestId, errorReason: "BlockedByClient" }).catch(() => {});
      try {
        const response = event.responseStatusCode !== undefined || event.responseErrorReason !== undefined;
        if (response && (!paired || event.responseErrorReason || event.responseStatusCode >= 300 && event.responseStatusCode < 400
            || event.request?.url !== paired.url)) { forgetCors(state, key); await fail(); return; }
        if (!await ownedTab(state)) {
          if (paired) { forgetCors(state, key); await fail(); }
          else await command(source, "Fetch.continueRequest", { requestId: event.requestId });
          return;
        }
        await refreshFrames(state);
        if (source.sessionId) await refreshFrames(state, source);
        if (!current(state)) throw new Error("Artifact configuration changed");
        const frameUrl = state.frames.get(event.frameId)?.url;
        if (response) {
          if (paired !== state.corsRequests.get(key) || paired.frameId !== event.frameId || !ownedURL(frameUrl)) throw new Error("Artifact export frame changed");
          const headers = GatewayArtifactCors.responseHeaders(event, state.host);
          forgetCors(state, key);
          if (!headers) { await command(source, "Fetch.continueRequest", { requestId: event.requestId }); return; }
          if (!await ownedTab(state) || !current(state) || !ownedURL(state.frames.get(paired.frameId)?.url)) throw new Error("Gateway tab navigated");
          const params = { requestId: event.requestId, responseCode: event.responseStatusCode, responseHeaders: headers };
          // HTTP/2 has no reason phrase. CDP rejects an explicitly empty phrase;
          // omitting it lets Chrome select the standard phrase for the status.
          if (typeof event.responseStatusText === "string" && event.responseStatusText.length) params.responsePhrase = event.responseStatusText;
          await command(source, "Fetch.continueResponse", params);
          return;
        }
        const headers = GatewayArtifactCors.requestHeaders(event, state.host, frameUrl);
        if (!headers) { await command(source, "Fetch.continueRequest", { requestId: event.requestId }); return; }
        if (event.redirectedRequestId || state.corsRequests.size >= MAX_CORS_REQUESTS || paired) { await fail(); return; }
        if (!await ownedTab(state) || !current(state)) throw new Error("Gateway tab navigated");
        if (!GatewayArtifactCors.requestHeaders(event, state.host, state.frames.get(event.frameId)?.url)) throw new Error("Artifact export frame changed");
        // The tab lookup yields; enforce the capacity/identity bound again with
        // no await between this check and insertion.
        if (event.redirectedRequestId || state.corsRequests.size >= MAX_CORS_REQUESTS || state.corsRequests.has(key)) { await fail(); return; }
        const pair = { url: event.request.url, frameId: event.frameId, timer: null };
        pair.timer = setTimeout(() => {
          if (state.corsRequests.get(key) !== pair) return;
          forgetCors(state, key);
          fail();
        }, CORS_TIMEOUT_MS);
        state.corsRequests.set(key, pair);
        await command(source, "Fetch.continueRequest", { requestId: event.requestId, headers, interceptResponse: true });
      } catch (_) { forgetCors(state, key); await fail(); }
    }
    async function paused(state, source, event) {
      if (["XHR", "Fetch"].includes(event.resourceType)) { await corsPaused(state, source, event); return; }
      // A top-level artifact navigation may become an attachment instead of
      // committing. Chrome can update tab.url before resolving disposition.
      // Preserve the original response on this known active debugger source;
      // this grants no ancestor/header/body rewrite or network exception.
      // Unknown subframe ancestry must never be mistaken for the root frame.
      const isRootDocument = !source.sessionId && event.resourceType === "Document" && typeof state.rootFrameId === "string" && event.frameId === state.rootFrameId;
      const isAttachment = GatewayArtifactCsp.isAttachmentResponse(event.responseHeaders);
      if (isRootDocument || isAttachment) {
        try { await command(source, "Fetch.continueRequest", { requestId: event.requestId }); }
        catch (_) { await command(source, "Fetch.failRequest", { requestId: event.requestId, errorReason: "BlockedByClient" }).catch(() => {}); }
        return;
      }
      if (state.inFlight >= MAX_RESPONSES) {
        await command(source, "Fetch.failRequest", { requestId: event.requestId, errorReason: "BlockedByClient" }).catch(() => {}); return;
      }
      state.inFlight++;
      const deadline = Date.now() + GatewayArtifactCsp.TIMEOUT_MS;
      try {
        if (!await ownedTab(state)) throw new Error("Gateway tab navigated");
        await refreshFrames(state);
        if (source.sessionId) await refreshFrames(state, source);
        const parentUrl = parentFor(state, event.frameId);
        const isCurrent = () => current(state) && Date.now() < deadline && parentFor(state, event.frameId) === parentUrl;
        const result = await GatewayArtifactCsp.fulfillPausedResponse({ source, event, gatewayHost: state.host, parentUrl,
          isSubframe: !!parentUrl, isCurrent,
          sendCommand: async (target, method, params) => {
            if (["IO.close", "Fetch.failRequest"].includes(method)) return command(target, method, params);
            if (!isCurrent()) throw new Error("Artifact configuration changed");
            if (method === "Fetch.fulfillRequest") {
              if (!current(state) || !await ownedTab(state)) throw new Error("Gateway tab navigated");
              await refreshFrames(state);
              if (!isCurrent()) throw new Error("Artifact frame changed");
            }
            // The CSP helper owns body deadlines and observes late stream
            // acquisition to close its handle. Do not mask that raw promise
            // with the shorter debugger setup timeout.
            if (["Fetch.takeResponseBodyAsStream", "IO.read"].includes(method)) return api.sendCommand(target, method, params);
            return command(target, method, params);
          }
        });
        if (!result.handled) await command(source, "Fetch.continueRequest", { requestId: event.requestId });
        else if (!result.ok) { lastError = "response_failed"; await command(source, "Fetch.failRequest", { requestId: event.requestId, errorReason: "BlockedByClient" }).catch(() => {}); }
      } catch (_) {
        await command(source, "Fetch.failRequest", { requestId: event.requestId, errorReason: "BlockedByClient" }).catch(() => {});
      } finally { state.inFlight--; }
    }
    async function event(source, method, params = {}) {
      const state = tabs.get(source.tabId);
      if (!state || !current(state) || !state.sessions.has(sourceKey(source))) {
        if (method === "Fetch.requestPaused") await command(source, "Fetch.failRequest", { requestId: params.requestId, errorReason: "BlockedByClient" }).catch(() => {});
        return;
      }
      if (method === "Target.attachedToTarget") {
        const child = { tabId: state.tabId, sessionId: params.sessionId };
        if (params.targetInfo?.type !== "iframe" || state.sessions.size >= MAX_SESSIONS) {
          if (params.waitingForDebugger) await command(child, "Runtime.runIfWaitingForDebugger").catch(() => {});
          await command(source, "Target.detachFromTarget", { sessionId: params.sessionId }).catch(() => {});
          if (state.sessions.size >= MAX_SESSIONS) { lastError = "session_limit"; await unsafe(state); }
          return;
        }
        state.sessions.set(params.sessionId, child);
        try { await setupSession(state, child, params.waitingForDebugger); }
        catch (_) { await unsafe(state); }
        return;
      }
      if (method === "Target.detachedFromTarget") {
        state.sessions.delete(params.sessionId);
        for (const key of state.corsRequests.keys()) if (key.startsWith(params.sessionId + "\0")) forgetCors(state, key);
        return;
      }
      if (method === "Page.frameAttached") { mergeFrame(state, { id: params.frameId, parentId: params.parentFrameId }); return; }
      if (method === "Page.frameNavigated") {
        mergeFrame(state, params.frame);
        if (!source.sessionId && params.frame?.id === state.rootFrameId && !ownedURL(params.frame.url)) await detachState(state);
        return;
      }
      if (method === "Page.frameDetached" && params.reason !== "swap") { state.frames.delete(params.frameId); return; }
      if (method === "Fetch.requestPaused") await paused(state, source, params);
    }
    if (supported) {
      api.onEvent.addListener((source, method, params) => { event(source, method, params).catch(() => { const state = tabs.get(source.tabId); if (state) unsafe(state).catch(() => {}); }); });
      api.onDetach.addListener(source => {
        const state = tabs.get(source.tabId);
        if (!state) return;
        (async () => {
          await state.setup;
          if (!current(state)) return;
          // onDetach has no session identity. A late event from our deliberate
          // old detach must not close a newly attached session for the same tab.
          try { await command({ tabId: state.tabId }, "Page.getFrameTree"); return; } catch (_) { /* Current attachment really is gone. */ }
          if (current(state)) await unsafe(state);
        })().catch(() => {});
      });
      chrome.tabs.onUpdated.addListener((tabId, change, tab) => {
        if (!change.url && change.status !== "loading") return;
        const state = tabs.get(tabId);
        // tab.url can change before Chrome resolves an attachment navigation.
        // Verify the committed root before retaining an existing session;
        // Page.frameNavigated also detaches on foreign commits. ownedTab still
        // forbids rewriting while either the current or pending tab URL differs.
        if (state) { if (!candidateTab(tab)) verifyCommittedRoot(state).catch(() => {}); return; }
        if (!candidateTab(tab)) { if (state) detachState(state).catch(() => {}); return; }
        // An explicit gateway navigation/reload is the user's retry after a
        // canceled debugging banner or a DevTools conflict.
        suppressed.delete(tabId);
        attach(tabId).catch(() => {});
      });
      chrome.tabs.onCreated?.addListener(tab => { if (candidateTab(tab)) attach(tab.id).catch(() => {}); });
      chrome.tabs.onRemoved.addListener(tabId => { suppressed.delete(tabId); const state = tabs.get(tabId); if (state) detachState(state).catch(() => {}); });
    }
    return {
      async configure(value) {
        host = value;
        if (!supported || !host || !isReady()) return;
        const all = await chrome.tabs.query({});
        const relevant = all.filter(candidateTab);
        if (relevant.length > MAX_TABS) { lastError = "tab_limit"; onUnsafeDetach(); return; }
        await Promise.all(relevant.map(tab => tabs.get(tab.id)?.setup || attach(tab.id)));
        if (relevant.some(tab => !tabs.get(tab.id)?.ready)) {
          lastError = lastError || "attach_unavailable";
          onUnsafeDetach();
        }
      },
      async stop() { generation++; host = ""; await Promise.all([...tabs.values()].map(detachState)); },
      clearSuppressed() { suppressed.clear(); lastError = supported ? "" : "unsupported"; },
      status() { return { available: supported, attachedTabs: [...tabs.values()].filter(state => state.ready && current(state)).length, blockedTabs: suppressed.size, lastError }; }
    };
  }
  const api = Object.freeze({ create, MAX_TABS, MAX_SESSIONS, MAX_FRAMES, MAX_RESPONSES, MAX_CORS_REQUESTS, CORS_TIMEOUT_MS });
  root.GatewayArtifactDebugger = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(globalThis);
