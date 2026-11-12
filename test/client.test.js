'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const K = require('..');
const { startMockApi } = require('./helpers/mock-api');

// like real fetch: rejects at once if the signal is already aborted
const abortableFetch = (url, init) => new Promise((_, rej) => {
  const fail = () => rej(Object.assign(new Error('aborted'), { name: 'AbortError' }));
  if (init.signal.aborted) return fail();
  init.signal.addEventListener('abort', fail);
});

let api;
before(async () => { api = await startMockApi(); });
after(async () => { await api.close(); });

const make = (extra = {}) => new K.KelpgateClient({
  apiUrl: api.apiUrl, tokenUrl: api.tokenUrl, clientId: 'id1', clientSecret: 'secret1', retryDelayMs: 1, ...extra,
});

test('config: rejects plain http to a remote host and missing credentials', () => {
  assert.throws(() => new K.KelpgateClient({ apiUrl: 'http://example.com', tokenUrl: 'https://a.b/t', clientId: 'a', clientSecret: 'b' }), K.ConfigError);
  assert.throws(() => new K.KelpgateClient({ apiUrl: 'https://api.example.com', tokenUrl: 'https://a.b/t' }), K.ConfigError);
  assert.throws(() => new K.KelpgateClient({ apiUrl: 'nonsense' }), K.ConfigError);
});

test('the client never serialises its credentials', () => {
  const c = make();
  assert.ok(!JSON.stringify(c).includes('secret1'));
});

test('scanBuffer stays as an alias of scanBytes', async () => {
  const r = await make().scanBuffer(Buffer.from('hello'), { filename: 'a.txt' });
  assert.equal(r.infected, false);
});

test('scanBytes: clean file', async () => {
  const r = await make().scanBytes(Buffer.from('hello'), { filename: 'a.txt' });
  assert.equal(r.infected, false);
  assert.equal(r.status, 'CLEAN');
  assert.equal(r.filename, 'a.txt');
  assert.equal(r.requestId, 'req-test');
});

test('scanFile: infected file returns a verdict, assertClean throws', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kg-'));
  const p = path.join(dir, 'bad.bin');
  fs.writeFileSync(p, 'xx MOCK-MALWARE xx');
  const r = await make().scanFile(p);
  assert.equal(r.infected, true);
  assert.equal(r.signature, 'Mock.Test.Signature');
  assert.equal(r.filename, 'bad.bin');
  assert.throws(() => K.assertClean(r), K.InfectedError);
});

test('scanFile accepts a stream and a Blob', async () => {
  const c = make();
  const s = await c.scanFile(require('node:stream').Readable.from([Buffer.from('MOCK-'), Buffer.from('MALWARE')]), { filename: 's.bin' });
  assert.equal(s.infected, true);
  const b = await c.scanFile(new Blob(['fine']), { filename: 'b.txt' });
  assert.equal(b.infected, false);
});

test('maxBytes is enforced before sending', async () => {
  await assert.rejects(make({ maxBytes: 3 }).scanBytes(Buffer.from('toolong')), K.PayloadTooLargeError);
});

test('token is cached across calls and shared by concurrent calls', async () => {
  const before = api.state.tokenCalls;
  const c = make();
  await Promise.all([c.scanBytes(Buffer.from('1')), c.scanBytes(Buffer.from('2')), c.scanBytes(Buffer.from('3'))]);
  await c.scanBytes(Buffer.from('4'));
  assert.equal(api.state.tokenCalls - before, 1);
});

test('token is renewed ahead of expiry', async () => {
  const short = await startMockApi({ tokenTtl: 60 }); // under the 120 s refresh-ahead window
  try {
    const c = new K.KelpgateClient({ apiUrl: short.apiUrl, tokenUrl: short.tokenUrl, clientId: 'id1', clientSecret: 'secret1' });
    await c.scanBytes(Buffer.from('a'));
    await c.scanBytes(Buffer.from('b'));
    assert.equal(short.state.tokenCalls, 2);
  } finally { await short.close(); }
});

test('a revoked token is replaced once after a 401', async () => {
  const c = make();
  await c.scanBytes(Buffer.from('warm'));
  api.state.validToken = 'something-else'; // server no longer accepts the cached token
  const tokensBefore = api.state.tokenCalls;
  const r = await c.scanBytes(Buffer.from('again'));
  assert.equal(r.infected, false);
  assert.equal(api.state.tokenCalls, tokensBefore + 1);
});

test('wrong client secret gives AuthError', async () => {
  const c = make({ clientSecret: 'nope' });
  await assert.rejects(c.scanBytes(Buffer.from('x')), (e) => e instanceof K.AuthError && e.code === 'TOKEN_REQUEST_FAILED');
});

test('bearerToken skips the token endpoint', async () => {
  const before = api.state.tokenCalls;
  const c = new K.KelpgateClient({ apiUrl: api.apiUrl, bearerToken: 'static' });
  await c.scanBytes(Buffer.from('x'));
  assert.equal(api.state.tokenCalls, before);
});

test('error mapping', async () => {
  const c = make({ maxRetries: 0 });
  const cases = [
    [402, { error: 'q', quota: 10, usage: 10, upgrade_url: 'https://u' }, K.QuotaExceededError],
    [413, { error: 'big', upgrade_url: 'https://u' }, K.PayloadTooLargeError],
    [415, { error: 'type' }, K.UnsupportedFileError],
    [429, { error: 'busy' }, K.RateLimitedError],
    [412, { error: 'bad' }, K.ScanError],
    [500, { error: 'boom' }, K.ServerError],
    [403, { error: 'suspended' }, K.AuthError],
  ];
  for (const [status, body, Cls] of cases) {
    api.state.failNext.push({ status, body });
    await assert.rejects(c.scanBytes(Buffer.from('x')), (e) => e instanceof Cls && e.status === status && e.requestId === 'req-test', `status ${status}`);
  }
  api.state.failNext.push({ status: 402, body: { quota: 5, usage: 6, upgrade_url: 'https://u' } });
  await assert.rejects(c.scanBytes(Buffer.from('x')), (e) => e.quota === 5 && e.usage === 6 && e.upgradeUrl === 'https://u');
});

test('retries 503 and honours Retry-After on 429, then succeeds', async () => {
  const c = make({ maxRetries: 2 });
  api.state.failNext.push({ status: 503 }, { status: 429, headers: { 'retry-after': '0' } });
  const r = await c.scanBytes(Buffer.from('ok'));
  assert.equal(r.infected, false);
});

test('gives up after maxRetries', async () => {
  const c = make({ maxRetries: 1 });
  api.state.failNext.push({ status: 503 }, { status: 503 }, { status: 503 });
  await assert.rejects(c.scanBytes(Buffer.from('x')), K.ServerError);
  api.state.failNext.length = 0;
});

test('network failure maps to NetworkError and timeouts to TimeoutError', async () => {
  const dead = new K.KelpgateClient({ apiUrl: 'http://127.0.0.1:1', bearerToken: 't', maxRetries: 0 });
  await assert.rejects(dead.health(), K.NetworkError);
  const slow = new K.KelpgateClient({
    apiUrl: api.apiUrl, bearerToken: 't', maxRetries: 0, timeoutMs: 20,
    fetch: abortableFetch,
  });
  await assert.rejects(slow.health(), K.TimeoutError);
});

test('caller can abort', async () => {
  const ac = new AbortController();
  const c = new K.KelpgateClient({
    apiUrl: api.apiUrl, bearerToken: 't', maxRetries: 3,
    fetch: abortableFetch,
  });
  const p = c.scanUrl('https://example.com/f', { signal: ac.signal });
  ac.abort();
  await assert.rejects(p, (e) => e instanceof K.NetworkError && e.code === 'ABORTED');
});

test('scanUrl', async () => {
  const r = await make().scanUrl('https://example.com/file.pdf');
  assert.equal(r.status, 'CLEAN');
});

test('async: accept, poll, wait', async () => {
  const c = make();
  api.state.asyncPolls = 0;
  const acc = await c.scanFileAsync(Buffer.from('hello'), { filename: 'a.txt', webhookUrl: 'https://example.com/hook' });
  assert.equal(acc.scanId, 'scan-1');
  const sent = api.state.requests.at(-1).body.toString('latin1');
  assert.match(sent, /name="webhook_url"/);
  const first = await c.getAsyncResult(acc.scanId);
  assert.equal(first.pending, true);
  const done = await c.waitForResult(acc.scanId, { intervalMs: 5, timeoutMs: 2000 });
  assert.equal(done.status, 'CLEAN');
});

test('waitForResult times out', async () => {
  const c = make();
  api.state.asyncPolls = -1000;
  await assert.rejects(c.waitForResult('scan-1', { intervalMs: 5, timeoutMs: 30 }), K.TimeoutError);
});

test('health needs no credentials', async () => {
  const h = await new K.KelpgateClient({ apiUrl: api.apiUrl, bearerToken: 'x' }).health();
  assert.deepEqual([h.ok, h.signatureVersion], [true, 'v-test']);
});

test('policy and degraded flags come from the signature text', async () => {
  const fake = async () => new Response(JSON.stringify({ 'av-status': 'INFECTED', 'av-signature': 'POLICY: macro | WARNING: yara did not complete - scan coverage reduced' }), { status: 406 });
  const r = await new K.KelpgateClient({ apiUrl: api.apiUrl, bearerToken: 't', fetch: fake }).scanBytes(Buffer.from('x'));
  assert.equal(r.policyRejected, true);
  assert.equal(r.degraded, true);
});

test('fromEnv uses production defaults', () => {
  const c = K.fromEnv({ KELPGATE_CLIENT_ID: 'a', KELPGATE_CLIENT_SECRET: 'b' });
  assert.equal(c.apiUrl, 'https://api.kelpgate.cloud');
});
