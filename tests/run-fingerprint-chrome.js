"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { pathToFileURL } = require("node:url");
const { chromium } = require("playwright");

async function run() {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "cg-fingerprint-test-"));
  let context;
  try {
    context = await chromium.launchPersistentContext(profile, {
      channel: "chromium",
      executablePath: process.env.CHROME || undefined,
      headless: true,
      locale: "ru-RU",
      timezoneId: "Europe/Moscow",
      env: { ...process.env, TZ: "Europe/Moscow" },
      args: ["--disable-background-networking", "--disable-sync", "--host-resolver-rules=MAP * ~NOTFOUND"],
    });
    const page = await context.newPage();
    const file = pathToFileURL(path.join(__dirname, "fingerprint.html")).href;
    const results = [];
    for (const spoof of [false, true]) {
      await page.goto(file + (spoof ? "?spoof" : ""));
      await page.waitForFunction(() => !!document.documentElement.dataset.testStatus, null, { timeout: 10000 });
      assert.equal(await page.getAttribute("html", "data-test-status"), "complete", "fingerprint page raised an exception");
      const result = JSON.parse(await page.locator("#out").textContent());
      assert.equal(result.ctorOk, true, "Date constructor/prototype changed");
      assert.match(result.toStringNative, /\[native code\]/);
      if (!spoof) {
        assert.equal(result.tz, "Europe/Moscow");
        assert.equal(result.offset, -180);
        assert.equal(result.hours, 15);
        assert.equal(result.lang, "ru-RU");
        assert.equal(result.rtc, "function");
      } else {
        assert.equal(result.tz, "UTC");
        assert.equal(result.locale, "en-US");
        assert.equal(result.numLocale, "en-US");
        assert.equal(result.offset, 0);
        assert.equal(result.hours, 12);
        assert.equal(result.localCtorHour, 10);
        assert.equal(result.isoLocal, 10);
        assert.equal(result.lang, "en-US");
        assert.equal(result.langs, "en-US,en");
        assert.equal(result.num, "1,234,567.89");
        assert.equal(result.rtc, "undefined");
        assert.equal(result.geo, "denied:1");
        assert.equal(result.perm, "denied");
      }
      results.push({ mode: spoof ? "spoof" : "baseline", timezone: result.tz, language: result.lang });
    }
    console.log(JSON.stringify({ ok: true, results }));
  } finally {
    if (context) await context.close();
    fs.rmSync(profile, { recursive: true, force: true });
  }
}

run().catch(error => {
  console.error("Fingerprint test failed:", String(error.message).split("\n")[0]);
  process.exitCode = 1;
});
