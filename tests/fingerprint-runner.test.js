"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

test("fingerprint command fails when the browser cannot launch", () => {
  const result = spawnSync("sh", [path.join(__dirname, "run-fingerprint-chrome.sh")], {
    env: { ...process.env, CHROME: path.join(__dirname, "missing-browser-executable") },
    timeout: 20000,
    encoding: "utf8",
  });
  assert.equal(result.error, undefined);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Fingerprint test failed/);
  assert.doesNotMatch(result.stdout, /"ok":true/);
});
