"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const https = require("node:https");
const path = require("node:path");
const { launchFirefoxHarness, stopFirefoxHarness, createFixtureCA, addFixtureCA, setFirefoxLocalDomains, grantPrivateWindowAccess } = require("./firefox-harness");
const ROOT = path.resolve(__dirname, "..");
const FIREFOX_PACKAGE = path.join(ROOT, "extension/dist/firefox");

test("Firefox native harness installs the packaged add-on in an isolated strict-TLS profile", { timeout: 40000 }, async t => {
  const harness = await launchFirefoxHarness();
  t.after(() => stopFirefoxHarness(harness));
  assert.equal(harness.addonInstalled, true, "web-ext must report a temporary installation of the packaged Firefox add-on");
  assert.equal(harness.capabilities.acceptInsecureCerts, false, "Firefox WebDriver must retain strict certificate validation");
  assert.ok(harness.capabilities.browserVersion, "the native Firefox version must be observable");

  const navigated = await harness.client.command("WebDriver:Navigate", { url: "about:blank" });
  assert.ok(navigated && typeof navigated === "object", "Marionette must complete navigation in the isolated Firefox tab");
  const page = await harness.client.command("WebDriver:ExecuteScript", { script: "return navigator.userAgent", args: [] });
  assert.match(page?.value || "", /Firefox\//, "native tab control must execute in Firefox content context");
  assert.equal(harness.capabilities["moz:headless"], true, "the native run must be headless and isolated");

  const fixtureDir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-firefox-fixture-"));
  let fixtureServer;
  t.after(async () => {
    if (fixtureServer?.listening) await new Promise(resolve => fixtureServer.close(resolve));
    fs.rmSync(fixtureDir, { recursive: true, force: true });
  });
  const ca = createFixtureCA(fixtureDir);
  await setFirefoxLocalDomains(harness, ["gateway.audit.test", "proxy.audit.test", "collector.audit.test"]);
  let directHits = 0;
  const httpPaths = [];
  fixtureServer = https.createServer({ key: ca.key, cert: ca.cert }, (request, response) => {
    httpPaths.push(request.url);
    if (request.url === "/tls-control") directHits++;
    response.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
    response.end("<!doctype html><title>strict TLS fixture</title><main id=fixture>fixture-ca-accepted</main>");
  });
  await new Promise((resolve, reject) => {
    fixtureServer.once("error", reject);
    fixtureServer.listen(0, "127.0.0.1", () => { fixtureServer.removeListener("error", reject); resolve(); });
  });
  const fixturePort = fixtureServer.address().port;
  await assert.rejects(
    harness.client.command("WebDriver:Navigate", { url: `https://collector.audit.test:${fixturePort}/tls-untrusted` }),
    /insecure certificate/i,
    "fixture HTTPS must fail strict TLS validation before the test CA is imported",
  );
  assert.equal(directHits, 0, "Firefox must reject the untrusted server certificate before delivering an HTTP request");
  assert.equal(httpPaths.includes("/tls-untrusted"), false, "untrusted TLS must not deliver an HTTP request to the collector");
  await addFixtureCA(harness, ca.ca);
  await harness.client.command("WebDriver:Navigate", { url: `https://collector.audit.test:${fixturePort}/tls-control` });
  const strictTLSPage = await harness.client.command("WebDriver:ExecuteScript", {
    script: "return { secure: location.protocol === 'https:', host: location.hostname, marker: document.querySelector('#fixture')?.textContent || '' }",
    args: [],
  });
  assert.deepEqual(strictTLSPage?.value, { secure: true, host: "collector.audit.test", marker: "fixture-ca-accepted" },
    "Firefox must trust the fixture certificate only after profile CA import, with WebDriver strict TLS validation enabled");
  assert.equal(directHits, 1, "a non-loopback synthetic hostname must reach the direct TLS collector control after profile-only CA trust");
  const addonId = JSON.parse(fs.readFileSync(path.join(FIREFOX_PACKAGE, "manifest.json"), "utf8")).browser_specific_settings.gecko.id;
  const privateGrant = await grantPrivateWindowAccess(harness, addonId);
  assert.equal(privateGrant?.installed, true, "the packaged test add-on must remain installed after Firefox's native private-access grant");
  assert.equal(privateGrant?.permissionStored, true, "the disposable profile must persist Firefox's native private-browsing permission");
  await harness.client.command("WebDriver:Navigate", { url: `${privateGrant.extensionRoot}options.html` });
  const privateAccess = await harness.client.command("WebDriver:ExecuteAsyncScript", {
    script: "const done=arguments[arguments.length-1]; browser.extension.isAllowedIncognitoAccess().then(done, error => done({error:String(error)}));",
    args: [],
  });
  assert.equal(privateAccess?.value, true, "the installed extension must observe private access through Firefox's own API");
  const manifest = JSON.parse(fs.readFileSync(path.join(FIREFOX_PACKAGE, "manifest.json"), "utf8"));
  console.log("FIREFOX_NATIVE_SMOKE", JSON.stringify({
    browserVersion: harness.capabilities.browserVersion,
    headless: harness.capabilities["moz:headless"],
    acceptInsecureCerts: harness.capabilities.acceptInsecureCerts,
    ownedProfile: true,
    addonId: manifest.browser_specific_settings.gecko.id,
    addonVersion: manifest.version,
    addonInstalled: harness.addonInstalled,
    privateAccess: privateAccess.value,
    untrustedTlsRejected: true,
    directControlRequests: directHits,
  }));
});
