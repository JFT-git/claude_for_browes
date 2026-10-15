'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const hash = '$2a$14$' + 'A'.repeat(53);
function fixture(t) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'gateway-install-'));
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  const repo = path.join(base, 'repo'), deploy = path.join(base, 'deploy'), bin = path.join(base, 'bin'), cron = path.join(base, 'cron');
  for (const dir of [repo, bin, cron, path.join(repo, 'gateway'), path.join(repo, 'extension')]) fs.mkdirSync(dir, {recursive: true});
  for (const name of ['install.sh', 'configure.sh']) fs.copyFileSync(path.join(root, name), path.join(repo, name));
  fs.cpSync(path.join(root, 'server'), path.join(repo, 'server'), {recursive: true});
  fs.writeFileSync(path.join(repo, 'gateway/gateway.js'), '// fixture\n');
  fs.writeFileSync(path.join(repo, 'extension/build.sh'), '#!/bin/sh\nmkdir -p extension/dist\ntouch extension/dist/claude-gateway-chrome.zip extension/dist/claude-gateway-firefox.zip\n');
  fs.writeFileSync(path.join(bin, 'docker'), `#!/bin/sh
printf '%s\\n' "$*" >> "$DOCKER_LOG"
case "$*" in
  *hash-password*) printf '%s\\n' '${hash}';;
  *validate*) [ ! -f "$FAIL_VALIDATE" ] || { echo "sensitive-hash-and-password" >&2; exit 1; };;
  "compose restart caddy") [ ! -f "\${FAIL_RESTART_CADDY:-/nonexistent}" ] || exit 1;;
esac
`);
  fs.writeFileSync(path.join(bin, 'curl'), '#!/bin/sh\nprintf 401\n');
  // Any accidental backup invocation is an immediate test failure.
  fs.writeFileSync(path.join(bin, 'scp'), '#!/bin/sh\necho forbidden-scp >&2\nexit 99\n');
  fs.writeFileSync(path.join(bin, 'id'), '#!/bin/sh\nprintf 0\n');
  for (const file of fs.readdirSync(bin)) fs.chmodSync(path.join(bin, file), 0o755);
  const env = {...process.env, PATH: `${bin}:${process.env.PATH}`, BACKUP_KEY_FILE: path.join(base, 'backup.key'), CRON_DIR: cron, DOCKER_LOG: path.join(base, 'docker.log'), FAIL_VALIDATE: path.join(base, 'fail-validate')};
  delete env.COOKIES_KEY; delete env.BACKUP_REMOTE;
  const run = (script, input = '', args = [], cwd = repo) => spawnSync('bash', [script, ...args], {cwd, env, input, encoding: 'utf8', timeout: 15000});
  const fresh = () => run('install.sh', `${deploy}\nclaude.example.com\n8.8.8.8\nowner\npassword123456\npassword123456\n\ny\n`);
  const rerun = () => run('install.sh', `${deploy}\n\n\ny\n`);
  return {base, repo, deploy, env, run, fresh, rerun, cron};
}
function success(result) { assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`); }
function read(file) { return fs.readFileSync(file, 'utf8'); }
function mode(file) { return fs.statSync(file).mode & 0o777; }
test('fresh install deploys TLS stack, private cookies/backups and cron without revealing backup key', t => {
  const f = fixture(t); const r = f.fresh(); success(r);
  for (const name of ['port443-mux.py', 'privacy.html', 'install-lib.sh', 'extension/claude-gateway-chrome.zip', 'extension/claude-gateway-firefox.zip']) assert.ok(fs.existsSync(path.join(f.deploy, name)), name);
  assert.match(read(path.join(f.deploy, '.env')), /^PUBLIC_HOST=claude.example.com\nCONNECT_HOST=8\.8\.8\.8\nCOOKIES_KEY=[a-f0-9]{64}$/m);
  assert.equal(mode(path.join(f.deploy, '.env')), 0o600);
  assert.equal(mode(path.join(f.deploy, 'gateway/cookies')), 0o700);
  assert.equal(mode(path.join(f.deploy, 'backups')), 0o700);
  const secret = read(f.env.BACKUP_KEY_FILE).trim(); assert.ok(!r.stdout.includes(secret));
  const cron = read(path.join(f.cron, 'claude-gateway-backup'));
  assert.ok(cron.includes(`BACKUP_KEY_FILE=${f.env.BACKUP_KEY_FILE}`));
  // Execute the real generated cron command with a harmless backup stub. Redirection must work on a fresh install.
  fs.writeFileSync(path.join(f.deploy, 'backup.sh'), '#!/bin/sh\necho backup-stub\n');
  fs.chmodSync(path.join(f.deploy, 'backup.sh'), 0o700);
  success(spawnSync('sh', ['-c', cron.replace(/^17 3 \* \* \* root /, '')], {encoding: 'utf8', env: f.env}));
  assert.match(read(path.join(f.deploy, 'backups/backup.log')), /backup-stub/);
  const calls = read(f.env.DOCKER_LOG); assert.ok(calls.indexOf('validate') < calls.indexOf('compose up'));
});
test('rerun preserves cookie encryption key, env secrets/admins and exact dotted auth users', t => {
  const f = fixture(t); success(f.fresh());
  const envPath = path.join(f.deploy, '.env'); const key = read(envPath).match(/COOKIES_KEY=([^\n]+)/)[1];
  fs.appendFileSync(envPath, `CUSTOM_VALUE='$(touch ${f.base}/executed)'\n`);
  let env = read(envPath).replace(`COOKIES_KEY=${key}`, `export COOKIES_KEY = '${key}' # preserved key`).replace('ADMIN_USERS=owner', 'ADMIN_USERS=owner,alice.smith');
  fs.writeFileSync(envPath, env);
  const caddy = path.join(f.deploy, 'Caddyfile');
  fs.writeFileSync(caddy, read(caddy).replace(`owner ${hash}`, `owner ${hash}\n            alice.smith ${hash}\n            aliceXsmith ${hash}`));
  fs.writeFileSync(path.join(f.deploy, 'gateway/cookies/alice.smith.json'), '{"enc":1,"data":"old-encrypted-session"}');
  const oldCookie = read(path.join(f.deploy, 'gateway/cookies/alice.smith.json'));
  fs.appendFileSync(caddy, '\n# obsolete local route\n');
  const r = f.rerun(); success(r);
  assert.ok(read(envPath).includes(`export COOKIES_KEY = '${key}' # preserved key`));
  assert.match(read(envPath), /ADMIN_USERS=owner,alice\.smith/);
  assert.match(read(envPath), /CUSTOM_VALUE='\$\(touch /);
  assert.ok(!fs.existsSync(path.join(f.base, 'executed')));
  assert.equal(read(path.join(f.deploy, 'gateway/cookies/alice.smith.json')), oldCookie);
  const users = read(caddy); assert.ok(users.includes(`alice.smith ${hash}`)); assert.ok(users.includes(`aliceXsmith ${hash}`)); assert.ok(!users.includes('obsolete local route'));
  assert.equal((read(f.env.DOCKER_LOG).match(/hash-password/g) || []).length, 1);
});
test('missing encryption key fails closed before deployment writes', t => {
  const f = fixture(t); success(f.fresh());
  const envPath = path.join(f.deploy, '.env'); fs.writeFileSync(envPath, read(envPath).replace(/^COOKIES_KEY=.*\n/m, ''));
  fs.writeFileSync(path.join(f.deploy, 'gateway/cookies/owner.json'), '{"enc": 1,"data":"saved"}');
  const before = [read(envPath), read(path.join(f.deploy, 'Caddyfile')), read(path.join(f.deploy, 'gateway/cookies/owner.json'))];
  const r = f.run('install.sh', `${f.deploy}\n`); assert.notEqual(r.status, 0); assert.match(r.stderr, /Encrypted cookie jars/);
  assert.deepEqual([read(envPath), read(path.join(f.deploy, 'Caddyfile')), read(path.join(f.deploy, 'gateway/cookies/owner.json'))], before);
});
test('invalid Caddy candidate leaves existing deployment untouched', t => {
  const f = fixture(t); success(f.fresh()); const before = read(path.join(f.deploy, 'Caddyfile'));
  fs.writeFileSync(f.env.FAIL_VALIDATE, 'fail');
  const r = f.rerun(); assert.notEqual(r.status, 0); assert.equal(read(path.join(f.deploy, 'Caddyfile')), before); assert.ok(!(r.stdout + r.stderr).includes('sensitive-hash-and-password'));
});
test('user changes match exact usernames and removal revokes all minted tokens after Caddy restart', t => {
  const f = fixture(t); success(f.fresh());
  const runUser = (name, args) => f.run(path.join(f.deploy, name), '', args, f.deploy);
  success(runUser('add-user.sh', ['alice.smith', 'password123456']));
  success(runUser('add-user.sh', ['aliceXsmith', 'password123456']));
  assert.notEqual(runUser('remove-user.sh', ['alice.smit.']).status, 0);
  const r = runUser('remove-user.sh', ['alice.smith']); success(r); assert.match(r.stdout, /All users must reconnect/);
  const caddy = read(path.join(f.deploy, 'Caddyfile')); assert.ok(!caddy.includes(`alice.smith ${hash}`)); assert.ok(caddy.includes(`aliceXsmith ${hash}`));
  assert.match(read(f.env.DOCKER_LOG), /compose restart caddy\ncompose restart gateway\n$/);
  for (const invalid of ['.', '..', 'a/b', 'a'.repeat(65), 'a b']) {
    assert.notEqual(runUser('add-user.sh', [invalid, 'password123456']).status, 0, invalid);
    assert.notEqual(runUser('remove-user.sh', [invalid]).status, 0, invalid);
  }
  fs.writeFileSync(f.env.FAIL_VALIDATE, 'fail'); const before = read(path.join(f.deploy, 'Caddyfile'));
  assert.notEqual(runUser('remove-user.sh', ['aliceXsmith']).status, 0); assert.equal(read(path.join(f.deploy, 'Caddyfile')), before);
});
test('configure preserves existing users and does not mutate compose', t => {
  const f = fixture(t); success(f.fresh());
  const caddy = path.join(f.repo, 'server/Caddyfile'); fs.copyFileSync(path.join(f.deploy, 'Caddyfile'), caddy);
  const composePath = path.join(f.repo, 'server/compose.yaml'); const compose = read(composePath);
  success(f.run('configure.sh', '', ['updated.example.com', '8.8.8.8']));
  assert.equal(read(composePath), compose); assert.ok(read(caddy).includes(`owner ${hash}`)); assert.match(read(caddy), /updated\.example\.com \{/);
});

test('thousands of encrypted jars cannot bypass missing-key preflight via SIGPIPE', t => {
  const f = fixture(t); success(f.fresh());
  const envPath = path.join(f.deploy, '.env'); fs.writeFileSync(envPath, read(envPath).replace(/^COOKIES_KEY=.*\n/m, ''));
  for (let i=0; i<4000; i++) fs.writeFileSync(path.join(f.deploy, 'gateway/cookies', `encrypted-${i}.json`), '{"enc":1,"data":"saved"}');
  const before = [read(envPath), read(path.join(f.deploy, 'Caddyfile'))];
  const r = f.run('install.sh', `${f.deploy}\n`); assert.notEqual(r.status, 0); assert.match(r.stderr, /Encrypted cookie jars/);
  assert.deepEqual([read(envPath), read(path.join(f.deploy, 'Caddyfile'))], before);
});
test('host validators reject newlines, private IPs and malformed labels', t => {
  const f = fixture(t);
  for (const host of ['good.example\nevil.example', 'bad..example', '-bad.example', 'bad.example/route']) assert.notEqual(f.run('configure.sh', '', [host, '8.8.8.8']).status, 0, host);
  for (const ip of ['8.8.8.8\n1.1.1.1', '10.1.1.1', '127.0.0.1', '192.168.1.1', '8.008.8.8', '224.0.0.1']) {
    const r = f.run('install.sh', `${f.deploy}\nclaude.example.com\n${ip}\n`); assert.notEqual(r.status, 0, ip);
  }
});

test('removal still attempts token revocation when Caddy restart fails', t => {
  const f = fixture(t); success(f.fresh());
  success(f.run(path.join(f.deploy, 'add-user.sh'), '', ['alice.smith', 'password123456'], f.deploy));
  f.env.FAIL_RESTART_CADDY = path.join(f.base, 'fail-caddy-restart'); fs.writeFileSync(f.env.FAIL_RESTART_CADDY, 'fail');
  const r = f.run(path.join(f.deploy, 'remove-user.sh'), '', ['alice.smith'], f.deploy);
  assert.notEqual(r.status, 0); assert.match(read(f.env.DOCKER_LOG), /compose restart caddy\ncompose restart gateway\n$/);
});
test('rerun preserves a valid unpadded base64 cookie key', t => {
  const f = fixture(t); success(f.fresh());
  const envPath = path.join(f.deploy, '.env'), key = Buffer.alloc(32, 255).toString('base64url');
  fs.writeFileSync(envPath, read(envPath).replace(/^COOKIES_KEY=.*$/m, `COOKIES_KEY=${key}`));
  success(f.rerun()); assert.ok(read(envPath).includes(`COOKIES_KEY=${key}\n`));
});
