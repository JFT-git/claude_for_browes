"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { launchFirefoxHarness, stopFirefoxHarness, executeChromeScript } = require("./firefox-harness");
const { startStunCollector, probeRtc } = require("./firefox-rtc-fixture");

const PACKAGE = path.resolve(__dirname, "../extension/dist/firefox");

async function extensionScript(harness, script) {
  const result = await harness.client.command("WebDriver:ExecuteAsyncScript", {
    script: `const done = arguments[arguments.length - 1]; Promise.resolve().then(async () => { ${script} }).then(value => done({ value }), error => done({ error: error?.name || "Error" }));`,
    args: [],
  });
  assert.equal(result?.value?.error, undefined, "native extension API call must complete");
  return result?.value?.value;
}

test("Firefox product leaves WebRTC of other sites working and releases the earlier proxy_only control", { timeout: 70000 }, async t => {
  const harness = await launchFirefoxHarness();
  t.after(() => stopFirefoxHarness(harness));
  // ICE can exclude loopback routes. Use an address assigned to this same
  // machine so the positive control still stays entirely local to the host.
  const localAddress = Object.values(os.networkInterfaces()).flat().find(address => address.family === "IPv4" && !address.internal);
  const collector = await startStunCollector(localAddress?.address || "127.0.0.1");
  t.after(() => collector.close());
  const page = http.createServer((_request, response) => {
    response.writeHead(200, { "content-type": "text/html", "cache-control": "no-store" });
    response.end("<!doctype html><title>isolated RTC fixture</title>");
  });
  await new Promise(resolve => page.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise(resolve => page.close(resolve)));
  const fixtureUrl = `http://127.0.0.1:${page.address().port}/`;
  const addonId = JSON.parse(fs.readFileSync(path.join(PACKAGE, "manifest.json"), "utf8")).browser_specific_settings.gecko.id;
  const optionsUrl = await executeChromeScript(harness, `return WebExtensionPolicy.getByID(${JSON.stringify(addonId)}).extension.getURL("options.html");`);
  await harness.client.command("WebDriver:SetTimeouts", { script: 12000 });

  // Builds before 2.0.7 forced proxy_only for the whole browser; reproduce that state.
  await harness.client.command("WebDriver:Navigate", { url: optionsUrl });
  const legacy = await extensionScript(harness, `
    await browser.privacy.network.webRTCIPHandlingPolicy.set({ value: "proxy_only" });
    return browser.privacy.network.webRTCIPHandlingPolicy.get({});`);
  assert.equal(legacy.value, "proxy_only");
  collector.reset();
  await harness.client.command("WebDriver:Navigate", { url: fixtureUrl });
  const blocked = await probeRtc(harness, collector);
  assert.equal(blocked.failureCategory, undefined);
  assert.equal(collector.snapshot().packets, 0, "the earlier global policy broke WebRTC on unrelated sites");

  await harness.client.command("WebDriver:Navigate", { url: optionsUrl });
  const released = await extensionScript(harness, `
    const background = await browser.runtime.getBackgroundPage();
    if (typeof background?.secureWebRTC !== "function") throw new Error("product privacy function unavailable");
    await background.secureWebRTC();
    return { rtc: await browser.privacy.network.webRTCIPHandlingPolicy.get({}), prediction: await browser.privacy.network.networkPredictionEnabled.get({}) };
  `);
  assert.notEqual(released.rtc.value, "proxy_only");
  assert.notEqual(released.rtc.levelOfControl, "controlled_by_this_extension");
  assert.notEqual(released.prediction.levelOfControl, "controlled_by_this_extension");
  collector.reset();
  await harness.client.command("WebDriver:Navigate", { url: fixtureUrl });
  const ordinary = await probeRtc(harness, collector);
  assert.equal(ordinary.supported, true, "actual Firefox must support the native RTC probe");
  assert.equal(ordinary.failureCategory, undefined);
  const udp = collector.snapshot();
  assert.ok(udp.bindingRequests > 0 && udp.responses > 0, "WebRTC of an unrelated site must work: " + JSON.stringify({ probe: ordinary, udp }));
  console.log("FIREFOX_NATIVE_RTC", JSON.stringify({
    browserVersion: harness.capabilities.browserVersion, acceptInsecureCerts: harness.capabilities.acceptInsecureCerts,
    released: released.rtc.value, ownership: released.rtc.levelOfControl, ordinaryUdp: udp.bindingRequests,
    scope: "isolated local IPv4 STUN/ICE probe on an unrelated page; gateway realms remove WebRTC in fingerprint.js",
  }));
});
