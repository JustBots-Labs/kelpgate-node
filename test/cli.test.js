'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { startMockApi } = require('./helpers/mock-api');

let api; let dir;
before(async () => {
  api = await startMockApi();
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kg-cli-'));
  fs.writeFileSync(path.join(dir, 'ok.txt'), 'fine');
  fs.writeFileSync(path.join(dir, 'bad.txt'), 'MOCK-MALWARE');
});
after(async () => { await api.close(); });

// async spawn: the mock server lives in this process, so a sync spawn would deadlock
function cli(args, env = {}) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [path.join(__dirname, '..', 'bin', 'kelpgate.js'), ...args], {
      env: { PATH: process.env.PATH, KELPGATE_API_URL: api.apiUrl, KELPGATE_TOKEN_URL: api.tokenUrl, KELPGATE_CLIENT_ID: 'id1', KELPGATE_CLIENT_SECRET: 'secret1', ...env },
    });
    let stdout = ''; let stderr = '';
    p.stdout.on('data', (d) => { stdout += d; });
    p.stderr.on('data', (d) => { stderr += d; });
    p.on('close', (status) => resolve({ status, stdout, stderr }));
  });
}

test('clean file exits 0', async () => {
  const r = await cli(['scan', path.join(dir, 'ok.txt')]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /clean/);
});

test('infected file exits 1', async () => {
  const r = await cli(['scan', path.join(dir, 'ok.txt'), path.join(dir, 'bad.txt')]);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /INFECTED/);
});

test('--json prints machine-readable lines', async () => {
  const r = await cli(['scan', '--json', path.join(dir, 'bad.txt')]);
  assert.equal(JSON.parse(r.stdout).infected, true);
});

test('errors exit 2 and never print the secret', async () => {
  const r = await cli(['scan', path.join(dir, 'ok.txt')], { KELPGATE_CLIENT_SECRET: 'wrong-secret' });
  assert.equal(r.status, 2);
  assert.ok(!r.stderr.includes('wrong-secret'));
});

test('health, version and help', async () => {
  assert.equal((await cli(['health'])).status, 0);
  assert.match((await cli(['--version'])).stdout, /^\d+\.\d+\.\d+/);
  assert.equal((await cli([])).status, 2);
});
