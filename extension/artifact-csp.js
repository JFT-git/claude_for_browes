// Artifact embedding compatibility. The caller owns debugger attachment and must
// derive parentUrl/isSubframe from the browser's frame tree, never page messages.
(function (root) {
  "use strict";
  const MAX_BODY_BYTES = 8 * 1024 * 1024;
  const MAX_CONCURRENT = 4;
  const TIMEOUT_MS = 8000;
  const ARTIFACT_DOMAINS = ["claudeusercontent.com", "claudemcpcontent.com"];
  let active = 0;

  function gatewayOrigin(host) {
    const url = new URL("https://" + host);
    if (url.host !== host || !url.hostname.includes(".") || url.username || url.password || url.pathname !== "/" || url.search || url.hash) throw new Error("Invalid gateway authority");
    return url.origin;
  }
  function buildFetchPatterns() {
    return ARTIFACT_DOMAINS.flatMap(host => [host, "*." + host].map(name => ({ urlPattern: "https://" + name + "/*", resourceType: "Document", requestStage: "Response" })));
  }
  function isAttachmentResponse(headers) {
    return Array.isArray(headers) && headers.some(header => typeof header?.name === "string" && header.name.toLowerCase() === "content-disposition"
      && typeof header.value === "string" && /^[ \t]*attachment(?:[ \t]*;|[ \t]*$)/i.test(header.value));
  }
  function inScope(context, host) {
    try {
      const target = new URL(context.requestUrl);
      return context.isSubframe === true && context.resourceType === "Document" && context.statusCode === 200
        // A download must keep the browser's original streaming response; the
        // HTML compatibility buffer and size limit do not apply to attachments.
        && !isAttachmentResponse(context.responseHeaders)
        && target.protocol === "https:" && !target.port && !target.username && !target.password
        && ARTIFACT_DOMAINS.some(domain => target.hostname === domain || target.hostname.endsWith("." + domain))
        && new URL(context.parentUrl).origin === gatewayOrigin(host);
    } catch (_) { return false; }
  }
  function appendGatewayAncestor(value, origin) {
    // A comma separates CSP policies; each semicolon-delimited directive must
    // have a valid name. Never turn an unrelated or malformed ancestor policy
    // into a gateway permission.
    for (const policy of value.split(",")) {
      if (!policy.trim()) throw new Error("Invalid CSP policy list");
      for (const directive of policy.split(";")) {
        const text = directive.trim();
        if (text && !/^[a-z][a-z0-9-]*(?:[ \t]+[^\r\n]*)?$/i.test(text)) throw new Error("Invalid CSP directive");
        if (/^frame-ancestors(?:[ \t]|$)/i.test(text)) {
          const sources = text.split(/[ \t]+/).slice(1);
          if (!sources.length || sources.some(source => !/^(?:'self'|'none'|[a-z][a-z0-9+.-]*:|(?:[a-z][a-z0-9+.-]*:\/\/)?(?:\*\.)?(?:[a-z0-9][a-z0-9.-]*|\*)(?::(?:[0-9]+|\*))?(?:\/[^\s;,'"]*)?)$/i.test(source))) throw new Error("Invalid CSP frame ancestors");
        }
      }
    }
    return value.replace(/(^|[;,])([ \t]*frame-ancestors[ \t]+)([^;,]*)/gi, (all, delimiter, directive, sources) => {
      const tokens = sources.trim().split(/[ \t]+/);
      if (!tokens.some(token => /^https:\/\/(?:\*\.)?claude\.ai\/?$/i.test(token)) || tokens.includes(origin)) return all;
      return delimiter + directive + sources + " " + origin;
    });
  }

  function rewriteHeaders(context, host) {
    if (!inScope(context, host)) return null;
    const origin = gatewayOrigin(host);
    if (!Array.isArray(context.responseHeaders)) throw new Error("Missing response headers");
    let changed = false;
    const result = [];
    for (const entry of context.responseHeaders) {
      if (!entry || typeof entry.name !== "string" || typeof entry.value !== "string" || /[\r\n]/.test(entry.name + entry.value)) throw new Error("Invalid response header");
      const name = entry.name.toLowerCase();
      if (name === "x-frame-options") { changed = true; continue; }
      const value = ["content-security-policy", "content-security-policy-report-only"].includes(name) ? appendGatewayAncestor(entry.value, origin) : entry.value;
      if (value !== entry.value) changed = true;
      result.push({ ...entry, value });
    }
    return changed ? result : null;
  }
  function declaredSize(headers) {
    for (const header of headers) {
      if (header.name.toLowerCase() !== "content-length") continue;
      if (!/^[0-9]+$/.test(header.value.trim()) || Number(header.value) > MAX_BODY_BYTES) throw new Error("Artifact response too large");
    }
  }
  const READ_BYTES = 64 * 1024;
  function chunkBinary(result) {
    if (!result || typeof result.data !== "string") throw new Error("Missing response body chunk");
    if (result.base64Encoded) {
      if (result.data.length > Math.ceil(READ_BYTES / 3) * 4 + 4 || result.data.length % 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(result.data)) throw new Error("Invalid response body chunk");
      const binary = atob(result.data);
      if (binary.length > READ_BYTES) throw new Error("Oversized response body chunk");
      return binary;
    }
    if (result.data.length > READ_BYTES) throw new Error("Oversized response body chunk");
    const bytes = new TextEncoder().encode(result.data);
    if (bytes.byteLength > READ_BYTES) throw new Error("Oversized response body chunk");
    let binary = "";
    for (let offset = 0; offset < bytes.length; offset += 32768) binary += String.fromCharCode(...bytes.subarray(offset, offset + 32768));
    return binary;
  }
  async function readBoundedBody({ requestId, command, closeStream }) {
    const result = await command("Fetch.takeResponseBodyAsStream", { requestId });
    if (!result || typeof result.stream !== "string" || !result.stream) throw new Error("Missing response stream");
    const handle = result.stream;
    const chunks = [];
    let total = 0;
    try {
      for (let reads = 0; reads < 4096; reads++) {
        const part = await command("IO.read", { handle, size: READ_BYTES });
        const binary = chunkBinary(part);
        total += binary.length;
        if (total > MAX_BODY_BYTES) throw new Error("Artifact response too large");
        chunks.push(binary);
        if (part.eof === true) return btoa(chunks.join(""));
      }
      throw new Error("Artifact response did not finish");
    } finally { await closeStream(handle); }
  }

  async function fulfillPausedResponse({ source, event, gatewayHost, parentUrl, isSubframe, sendCommand, isCurrent = () => true }) {
    const context = { requestUrl: event?.request?.url, parentUrl, isSubframe, resourceType: event?.resourceType, statusCode: event?.responseStatusCode, responseHeaders: event?.responseHeaders };
    if (!inScope(context, gatewayHost)) return { handled: false };
    const requestId = event.requestId;
    const cleanup = async (method, params) => {
      let timer;
      try { await Promise.race([sendCommand(source, method, params), new Promise(resolve => { timer = setTimeout(resolve, 1000); })]); }
      catch (_) { /* Target may already be closed. */ }
      finally { clearTimeout(timer); }
    };
    const fail = () => cleanup("Fetch.failRequest", { requestId, errorReason: "BlockedByClient" });
    if (active >= MAX_CONCURRENT) { await fail(); return { handled: true, ok: false }; }
    active++;
    const deadline = Date.now() + TIMEOUT_MS;
    async function command(method, params) {
      if (!isCurrent()) throw new Error("Artifact configuration changed");
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new Error("Artifact response timeout");
      let timer;
      let abandoned = false;
      let resolved;
      let closed = false;
      const closeAbandonedStream = () => {
        if (method !== "Fetch.takeResponseBodyAsStream" || closed || typeof resolved?.stream !== "string") return;
        closed = true;
        cleanup("IO.close", { handle: resolved.stream });
      };
      const pending = Promise.resolve().then(() => sendCommand(source, method, params));
      // A timed-out acquisition can still resolve with a new stream handle.
      // Close that late handle independently of the request's expired epoch.
      pending.then(result => { resolved = result; if (abandoned) closeAbandonedStream(); }, () => {});
      try {
        const result = await Promise.race([pending, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("Artifact response timeout")), remaining); })]);
        if (!isCurrent()) throw new Error("Artifact configuration changed");
        return result;
      } catch (error) {
        abandoned = true;
        closeAbandonedStream();
        throw error;
      } finally { clearTimeout(timer); }
    }
    try {
      const headers = rewriteHeaders(context, gatewayHost);
      if (!headers) return { handled: false };
      declaredSize(event.responseHeaders);
      const body = await readBoundedBody({ requestId, command, closeStream: handle => cleanup("IO.close", { handle }) });
      if (!isCurrent()) throw new Error("Artifact configuration changed");
      // The explicit CDP body is decoded. Normalize transport metadata only;
      // preserve every security header and every separate CSP policy entry.
      const responseHeaders = headers.filter(header => !["content-encoding", "content-length", "transfer-encoding"].includes(header.name.toLowerCase()));
      await command("Fetch.fulfillRequest", { requestId, responseCode: 200, responseHeaders, body });
      return { handled: true, ok: true };
    } catch (_) { await fail(); return { handled: true, ok: false }; }
    finally { active--; }
  }
  const api = Object.freeze({ MAX_BODY_BYTES, MAX_CONCURRENT, TIMEOUT_MS, READ_BYTES, readBoundedBody, buildFetchPatterns, isAttachmentResponse, inScope, appendGatewayAncestor, rewriteHeaders, fulfillPausedResponse });
  root.GatewayArtifactCsp = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(globalThis);
