// Narrow artifact-file CORS compatibility. The debugger caller must pair the
// request and response by source/requestId/configuration epoch, reject redirects,
// and verify the browser-owned initiating frame again before response changes.
(function (root) {
  "use strict";
  const UPSTREAM_ORIGIN = "https://claude.ai";
  const ARTIFACT_DOMAINS = ["claudeusercontent.com", "claudemcpcontent.com"];
  function buildFetchPatterns() {
    return ARTIFACT_DOMAINS.flatMap(host => [host, "*." + host].flatMap(name => ["XHR", "Fetch"].map(resourceType => ({
      urlPattern: "https://" + name + "/*", resourceType, requestStage: "Request"
    }))));
  }
  function gatewayOrigin(host) {
    try {
      const url = new URL("https://" + host);
      return typeof host === "string" && url.host === host && url.hostname.includes(".") && !url.username && !url.password
        && url.pathname === "/" && !url.search && !url.hash ? url.origin : null;
    } catch (_) { return null; }
  }
  function approvedRequest(event) {
    if (!["XHR", "Fetch"].includes(event?.resourceType) || !["GET", "HEAD"].includes(event?.request?.method)) return false;
    try {
      const url = new URL(event.request.url);
      return url.protocol === "https:" && !url.port && !url.username && !url.password
        && ARTIFACT_DOMAINS.some(domain => url.hostname === domain || url.hostname.endsWith("." + domain));
    } catch (_) { return false; }
  }
  function clonedHeaders(headers, allowObject = false) {
    let entries = headers;
    if (allowObject && headers && !Array.isArray(headers) && typeof headers === "object") entries = Object.entries(headers).map(([name, value]) => ({ name, value }));
    if (!Array.isArray(entries)) return null;
    const result = [];
    for (const header of entries) {
      if (!header || typeof header.name !== "string" || typeof header.value !== "string" || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(header.name) || /[\r\n]/.test(header.value)) return null;
      result.push({ ...header });
    }
    return result;
  }
  function requestHeaders(event, host, frameUrl) {
    const origin = gatewayOrigin(host);
    if (!origin || !approvedRequest(event)) return null;
    try {
      const frame = new URL(frameUrl);
      if (frame.protocol !== "https:" || frame.username || frame.password || frame.origin !== origin) return null;
    } catch (_) { return null; }
    const headers = clonedHeaders(event.request.headers, true);
    if (!headers) return null;
    const origins = headers.filter(header => header.name.toLowerCase() === "origin");
    if (origins.length !== 1 || origins[0].value !== origin) return null;
    return headers.map(header => header.name.toLowerCase() === "origin" ? { ...header, value: UPSTREAM_ORIGIN } : header);
  }
  function responseHeaders(event, host) {
    const origin = gatewayOrigin(host);
    if (!origin || !approvedRequest(event) || !Number.isInteger(event.responseStatusCode) || event.responseStatusCode < 200 || event.responseStatusCode > 599
      || [301, 302, 303, 307, 308].includes(event.responseStatusCode) || event.responseErrorReason) return null;
    const headers = clonedHeaders(event.responseHeaders);
    if (!headers) return null;
    const origins = headers.filter(header => header.name.toLowerCase() === "access-control-allow-origin");
    if (origins.length !== 1 || origins[0].value !== UPSTREAM_ORIGIN) return null;
    return headers.map(header => header.name.toLowerCase() === "access-control-allow-origin" ? { ...header, value: origin } : header);
  }
  const api = Object.freeze({ UPSTREAM_ORIGIN, buildFetchPatterns, approvedRequest, requestHeaders, responseHeaders });
  root.GatewayArtifactCors = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(globalThis);
