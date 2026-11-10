'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const K = require('..');
const { kelpgateScan } = require('../express');
const { startMockApi } = require('./helpers/mock-api');

let api; let client;
before(async () => {
  api = await startMockApi();
  client = new K.KelpgateClient({ apiUrl: api.apiUrl, tokenUrl: api.tokenUrl, clientId: 'id1', clientSecret: 'secret1', retryDelayMs: 1, maxRetries: 0 });
});
after(async () => { await api.close(); });

function run(mw, req) {
  return new Promise((resolve) => {
    const res = { code: 200, status(c) { this.code = c; return this; }, json(b) { resolve({ res: this, body: b, nexted: false }); } };
    mw(req, res, () => resolve({ res, nexted: true }));
  });
}

test('requires a client', () => {
  assert.throws(() => kelpgateScan({}), K.ConfigError);
});

test('no files: passes straight through', async () => {
  const out = await run(kelpgateScan({ client }), {});
  assert.equal(out.nexted, true);
});

test('clean buffer upload continues and sets req.kelpgate', async () => {
  const req = { file: { buffer: Buffer.from('fine'), originalname: 'a.txt' } };
  const out = await run(kelpgateScan({ client }), req);
  assert.equal(out.nexted, true);
  assert.equal(req.kelpgate[0].infected, false);
});

test('infected disk file is rejected with 422 and deleted', async () => {
  const p = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'kg-')), 'bad.bin');
  fs.writeFileSync(p, 'MOCK-MALWARE');
  const out = await run(kelpgateScan({ client }), { files: [{ path: p, originalname: 'bad.bin' }] });
  assert.equal(out.nexted, false);
  assert.equal(out.res.code, 422);
  assert.equal(fs.existsSync(p), false);
});

test('onInfected "pass" lets the handler decide', async () => {
  const req = { file: { buffer: Buffer.from('MOCK-MALWARE'), originalname: 'bad.bin' } };
  const out = await run(kelpgateScan({ client, onInfected: 'pass' }), req);
  assert.equal(out.nexted, true);
  assert.equal(req.kelpgate[0].infected, true);
});

test('scan failure blocks by default and can be allowed', async () => {
  api.state.failNext.push({ status: 500 });
  const blocked = await run(kelpgateScan({ client }), { file: { buffer: Buffer.from('x') } });
  assert.equal(blocked.res.code, 503);

  api.state.failNext.push({ status: 500 });
  const req = { file: { buffer: Buffer.from('x') } };
  const allowed = await run(kelpgateScan({ client, onError: 'allow' }), req);
  assert.equal(allowed.nexted, true);
  assert.ok(req.kelpgateError instanceof K.ServerError);
});

test('quota exhaustion maps to 402', async () => {
  api.state.failNext.push({ status: 402, body: {} });
  const out = await run(kelpgateScan({ client }), { file: { buffer: Buffer.from('x') } });
  assert.equal(out.res.code, 402);
});
