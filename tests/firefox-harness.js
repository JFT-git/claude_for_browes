"use strict";

// Firefox native harness. web-ext creates a disposable profile and installs
// the packaged Firefox add-on temporarily. Marionette controls only that
// browser; no user profile, TLS-ignore capability, or external driver is used.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawn, execFileSync } = require("node:child_process");
const https = require("node:https");

const ROOT = path.resolve(__dirname, "..");
const FIREFOX = process.env.FIREFOX || "/Applications/Firefox.app/Contents/MacOS/firefox";
const DEFAULT_FIREFOX_PACKAGE = path.join(ROOT, "extension/dist/firefox");
const WEB_EXT = path.join(ROOT, "node_modules/.bin/web-ext");
async function reservePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

function isInside(parent, child) {
  const relative = path.relative(parent, child);
  return relative !== "" && relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

function waitForChildExit(child, timeoutMs) {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  return new Promise(resolve => {
    const finish = () => { clearTimeout(timer); child.removeListener("exit", finish); resolve(); };
    child.once("exit", finish);
    const timer = setTimeout(() => { child.kill("SIGKILL"); finish(); }, timeoutMs);
    if (child.exitCode !== null || child.signalCode !== null) finish();
  });
}

function parsePacket(buffer) {
  const separator = buffer.indexOf(58);
  if (separator < 1) return null;
  const lengthText = buffer.subarray(0, separator).toString("ascii");
  if (!/^\d+$/.test(lengthText)) throw new Error("Invalid Marionette packet length");
  const length = Number(lengthText);
  if (!Number.isSafeInteger(length) || length < 1) throw new Error("Invalid Marionette packet size");
  const start = separator + 1;
  if (buffer.length < start + length) return null;
  return { packet: JSON.parse(buffer.subarray(start, start + length).toString("utf8")), rest: buffer.subarray(start + length) };
}

class MarionetteClient {
  constructor(socket) {
    this.socket = socket;
    this.buffer = Buffer.alloc(0);
    this.nextId = 0;
    this.pending = new Map();
    this.unmatched = [];
    this.waiting = [];
    this.terminalError = null;
    socket.on("data", chunk => {
      this.buffer = Buffer.concat([this.buffer, chunk]);
      for (;;) {
        const parsed = parsePacket(this.buffer);
        if (!parsed) break;
        this.buffer = parsed.rest;
        this.dispatch(parsed.packet);
      }
    });
    socket.on("error", error => this.fail(error));
    socket.on("close", () => this.fail(new Error("Marionette connection closed")));
  }

  dispatch(packet) {
    if (Array.isArray(packet) && packet[0] === 1 && this.pending.has(packet[1])) {
      const { resolve } = this.pending.get(packet[1]);
      this.pending.delete(packet[1]);
      if (packet[2]) resolve({ error: packet[2] });
      else resolve({ result: packet[3] });
      return;
    }
    const waiter = this.waiting.shift();
    if (waiter) waiter.resolve(packet);
    else this.unmatched.push(packet);
  }

  fail(error) {
    this.terminalError ||= error;
    for (const waiter of this.waiting.splice(0)) waiter.reject(error);
    for (const { reject } of this.pending.values()) reject(error);
    this.pending.clear();
  }

  nextPacket() {
    if (this.unmatched.length) return Promise.resolve(this.unmatched.shift());
    return new Promise((resolve, reject) => this.waiting.push({ resolve, reject }));
  }

  async command(method, params = {}) {
    if (this.terminalError || this.socket.destroyed) throw this.terminalError || new Error("Marionette socket is closed");
    const id = ++this.nextId;
    const payload = Buffer.from(JSON.stringify([0, id, method, params]), "utf8");
    const response = new Promise((resolve, reject) => this.pending.set(id, { resolve, reject }));
    this.socket.write(Buffer.concat([Buffer.from(String(payload.length) + ":", "ascii"), payload]));
    const packet = await response;
    if (packet.error) throw new Error(`Marionette ${method}: ${packet.error.error || "error"} (${packet.error.message || "no details"})`);
    return packet.result;
  }

  async close() {
    if (!this.socket.destroyed && !this.terminalError) {
      try { await this.command("WebDriver:DeleteSession"); } catch { /* Browser may already be closing. */ }
    }
    if (!this.socket.destroyed) this.socket.end();
  }
}

function connectMarionette(port, deadline) {
  return new Promise((resolve, reject) => {
    let finished = false;
    const attempt = () => {
      if (finished) return;
      if (Date.now() >= deadline) {
        finished = true;
        return reject(new Error("Firefox Marionette startup timed out"));
      }
      const socket = net.createConnection({ host: "127.0.0.1", port });
      socket.once("connect", () => {
        if (finished) return socket.destroy();
        finished = true;
        resolve(socket);
      });
      socket.once("error", error => {
        socket.destroy();
        if (finished) return;
        if (error.code === "ECONNREFUSED" || error.code === "ECONNRESET") setTimeout(attempt, 100);
        else { finished = true; reject(error); }
      });
    };
    attempt();
  });
}

function waitForTemporaryAddonInstall(child, readOutput, timeoutMs = 15000) {
  if (/Installed .* as a temporary add-on/.test(readOutput())) return Promise.resolve();
  return new Promise((resolve, reject) => {
    let timer;
    const check = () => {
      if (/Installed .* as a temporary add-on/.test(readOutput())) finish();
    };
    const onExit = code => finish(new Error(`web-ext exited before temporary add-on install (exit ${code})`));
    const onError = error => finish(new Error(`web-ext could not start: ${error.code || error.name}`));
    const finish = error => {
      clearTimeout(timer);
      child.stdout.removeListener("data", check);
      child.stderr.removeListener("data", check);
      child.removeListener("exit", onExit);
      child.removeListener("error", onError);
      if (error) reject(error); else resolve();
    };
    child.stdout.on("data", check);
    child.stderr.on("data", check);
    child.once("exit", onExit);
    child.once("error", onError);
    timer = setTimeout(() => finish(new Error("web-ext did not confirm temporary add-on installation")), timeoutMs);
    check();
  });
}

async function launchFirefoxHarness({ sourceDir = DEFAULT_FIREFOX_PACKAGE, installAddon = true, signatureEnforcement = false } = {}) {
  if (!fs.existsSync(FIREFOX)) throw new Error(`Firefox binary not found: ${FIREFOX}`);
  const firefoxPackage = path.resolve(sourceDir);
  if (installAddon && !fs.existsSync(firefoxPackage)) throw new Error("Build the Firefox package before running this test");
  if (installAddon && !fs.existsSync(WEB_EXT)) throw new Error("Install project devDependencies before running this test");

  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cg-firefox-native-"));
  const marionettePort = await reservePort();
  const directProfile = path.join(tempRoot, "firefox-profile");
  let executable, args;
  if (installAddon) {
    executable = WEB_EXT;
    args = [
      "run", "--source-dir", firefoxPackage, "--firefox", FIREFOX,
      "--no-reload", "--no-input", "--start-url", "about:blank",
      `--pref=marionette.port=${marionettePort}`,
      "--args=--marionette", "--args=--headless", "--args=--remote-allow-system-access",
    ];
  } else {
    fs.mkdirSync(directProfile, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(directProfile, "user.js"), [
      `user_pref("marionette.port", ${marionettePort});`,
      `user_pref("xpinstall.signatures.required", ${signatureEnforcement ? "true" : "false"});`,
    ].join("\n") + "\n", { mode: 0o600 });
    executable = FIREFOX;
    args = ["--no-remote", "--profile", directProfile, "--marionette", "--headless", "--remote-allow-system-access", "about:blank"];
  }
  const child = spawn(executable, args, { cwd: ROOT, stdio: ["ignore", "pipe", "pipe"], env: {
    ...process.env,
    TMPDIR: tempRoot,
    TMP: tempRoot,
    TEMP: tempRoot,
    MOZ_HEADLESS: "1",
    MOZ_REMOTE_ALLOW_SYSTEM_ACCESS: "1",
  } });
  let output = "";
  for (const stream of [child.stdout, child.stderr]) stream.on("data", chunk => {
    output = (output + chunk.toString("utf8")).slice(-12000);
  });

  let socket;
  let client;
  try {
    socket = await connectMarionette(marionettePort, Date.now() + 20000);
    socket.setTimeout(15000, () => socket.destroy(new Error("Marionette socket timed out")));
    client = new MarionetteClient(socket);
    const greeting = await client.nextPacket();
    if (greeting?.applicationType !== "gecko" || greeting?.marionetteProtocol !== 3) {
      throw new Error("Unexpected Firefox Marionette handshake");
    }
    const created = await client.command("WebDriver:NewSession");
    const capabilities = created?.capabilities;
    if (!capabilities?.browserVersion || capabilities.acceptInsecureCerts !== false || !capabilities["moz:profile"]) {
      throw new Error("Firefox did not create a strict-TLS isolated WebDriver session");
    }
    if (installAddon) await waitForTemporaryAddonInstall(child, () => output);
    const profile = path.resolve(capabilities["moz:profile"]);
    const ownedTempRoot = fs.realpathSync(tempRoot);
    const realProfile = fs.realpathSync(profile);
    if (!isInside(ownedTempRoot, realProfile)) {
      throw new Error("Firefox profile is outside this harness-owned temporary directory");
    }
    return {
      child, client, capabilities, profile: realProfile, tempRoot: ownedTempRoot, marionettePort,
      addonInstalled: installAddon,
      signatureEnforcement,
      output: () => output.replaceAll(firefoxPackage, "<firefox-package>"),
    };
  } catch (error) {
    try { await client?.close(); } catch { /* cleanup */ }
    child.kill("SIGTERM");
    await waitForChildExit(child, 5000);
    fs.rmSync(tempRoot, { recursive: true, force: true });
    throw error;
  }
}

async function stopFirefoxHarness(harness) {
  // Terminating web-ext leaves its Firefox running, so ask the browser to quit;
  // web-ext then exits by itself and removes its copy of the profile.
  try { await harness.client.command("Marionette:Quit", { flags: ["eForceQuit"] }); } catch { /* Browser may already be closing. */ }
  await harness.client.close();
  const { child } = harness;
  if (child.exitCode === null && child.signalCode === null) {
    let timer;
    await Promise.race([new Promise(resolve => child.once("exit", resolve)), new Promise(resolve => { timer = setTimeout(resolve, 10000); })]);
    clearTimeout(timer);
  }
  if (child.exitCode === null && child.signalCode === null) {
    child.kill("SIGTERM");
    await waitForChildExit(child, 5000);
  }
  // Remove any remnant only after the browser and web-ext have exited. A
  // leftover temporary directory must not fail the test or skip later hooks.
  try { fs.rmSync(harness.tempRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 }); }
  catch { /* The OS temporary-file cleanup owns any remnant. */ }
}

function createFixtureCA(directory, dnsNames = ["gateway.audit.test", "proxy.audit.test", "collector.audit.test"]) {
  const caKey = path.join(directory, "firefox-fixture-ca.key");
  const caCert = path.join(directory, "firefox-fixture-ca.pem");
  const serverKey = path.join(directory, "firefox-fixture-server.key");
  const serverCsr = path.join(directory, "firefox-fixture-server.csr");
  const serverCert = path.join(directory, "firefox-fixture-server.pem");
  const extensions = path.join(directory, "firefox-fixture-server.ext");
  const openssl = process.env.OPENSSL || "openssl";
  execFileSync(openssl, [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", caKey, "-out", caCert,
    "-days", "1", "-sha256", "-subj", "/CN=Isolated Firefox native test CA",
    "-addext", "basicConstraints=critical,CA:TRUE",
    "-addext", "keyUsage=critical,keyCertSign,cRLSign",
  ], { stdio: "ignore" });
  execFileSync(openssl, ["req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", serverKey,
    "-out", serverCsr, "-subj", "/CN=collector.audit.test"], { stdio: "ignore" });
  fs.writeFileSync(extensions, [
    "basicConstraints=critical,CA:FALSE",
    "keyUsage=critical,digitalSignature,keyEncipherment",
    "extendedKeyUsage=serverAuth",
    "subjectAltName=" + dnsNames.map(name => "DNS:" + name).join(","),
  ].join("\n"));
  execFileSync(openssl, ["x509", "-req", "-in", serverCsr, "-CA", caCert, "-CAkey", caKey,
    "-CAcreateserial", "-out", serverCert, "-days", "1", "-sha256", "-extfile", extensions],
  { stdio: "ignore" });
  return { key: fs.readFileSync(serverKey), cert: fs.readFileSync(serverCert), ca: fs.readFileSync(caCert) };
}

async function addFixtureCA(harness, certificatePem) {
  const base64 = certificatePem.toString("ascii").replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s/g, "");
  await harness.client.command("Marionette:SetContext", { value: "chrome" });
  try {
    const result = await harness.client.command("WebDriver:ExecuteScript", {
      script: `const database = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB); database.addCertFromBase64(${JSON.stringify(base64)}, "C,,", "Isolated Firefox native test CA"); return true;`,
      args: [],
    });
    if (result?.value !== true) throw new Error("Firefox profile CA import did not complete");
  } finally {
    await harness.client.command("Marionette:SetContext", { value: "content" });
  }
}

async function setFirefoxLocalDomains(harness, domains) {
  await harness.client.command("Marionette:SetContext", { value: "chrome" });
  try {
    const pref = JSON.stringify(domains.join(","));
    const result = await harness.client.command("WebDriver:ExecuteScript", {
      script: `Services.prefs.setCharPref("network.dns.localDomains", ${pref}); return Services.prefs.getCharPref("network.dns.localDomains");`,
      args: [],
    });
    assert.equal(result?.value, domains.join(","), "synthetic DNS aliases must be configured in this isolated profile");
  } finally {
    await harness.client.command("Marionette:SetContext", { value: "content" });
  }
}


async function executeChromeScript(harness, script) {
  await harness.client.command("Marionette:SetContext", { value: "chrome" });
  try {
    const result = await harness.client.command("WebDriver:ExecuteAsyncScript", {
      script: `const done = arguments[arguments.length - 1]; Promise.resolve().then(async () => { ${script} }).then(value => done({ value }), error => done({ error: String(error?.message || error) }));`,
      args: [],
    });
    if (result?.value?.error) throw new Error(`Firefox chrome-context script failed: ${result.value.error}`);
    return result?.value?.value;
  } finally {
    await harness.client.command("Marionette:SetContext", { value: "content" });
  }
}

async function grantPrivateWindowAccess(harness, addonId) {
  return executeChromeScript(harness, `
    const { AddonManager } = ChromeUtils.importESModule("resource://gre/modules/AddonManager.sys.mjs");
    const { ExtensionPermissions } = ChromeUtils.importESModule("resource://gre/modules/ExtensionPermissions.sys.mjs");
    const addon = await AddonManager.getAddonByID(${JSON.stringify(addonId)});
    const policy = WebExtensionPolicy.getByID(${JSON.stringify(addonId)});
    if (!addon || !policy?.extension) throw new Error("temporary test add-on is not active");
    await ExtensionPermissions.add(${JSON.stringify(addonId)}, { permissions: ["internal:privateBrowsingAllowed"], origins: [] }, policy.extension);
    if (addon.isActive) await addon.reload();
    return { installed: addon.isActive === true, permissionStored: true, extensionRoot: policy.extension.getURL("/") };
  `);
}

module.exports = {
  launchFirefoxHarness, stopFirefoxHarness, createFixtureCA, addFixtureCA,
  setFirefoxLocalDomains, executeChromeScript, grantPrivateWindowAccess,
};
