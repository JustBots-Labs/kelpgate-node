'use strict';

const http = require('node:http');

/**
 * A small stand-in for the Kelpgate API and its token endpoint.
 * A file whose bytes contain MOCK-MALWARE is answered as infected.
 */
async function startMockApi(opts = {}) {
  const state = { tokenCalls: 0, apiCalls: 0, requests: [], failNext: [], asyncPolls: 0, tokenTtl: opts.tokenTtl ?? 3600, validToken: null };
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      const json = (status, obj, headers = {}) => {
        res.writeHead(status, { 'content-type': 'application/json', 'x-request-id': 'req-test', ...headers });
        res.end(JSON.stringify(obj));
      };
      state.requests.push({ method: req.method, url: req.url, headers: req.headers, body });

      if (req.url === '/oauth2/token') {
        state.tokenCalls++;
        const want = 'Basic ' + Buffer.from('id1:secret1').toString('base64');
        if (req.headers.authorization !== want) return json(401, { error: 'invalid_client' });
        state.validToken = `tok-${state.tokenCalls}`;
        return json(200, { access_token: state.validToken, token_type: 'bearer', expires_in: state.tokenTtl });
      }
      if (req.url === '/api/v1/health') return json(200, { status: 'ok', signature_version: 'v-test' });

      state.apiCalls++;
      const forced = state.failNext.shift();
      if (forced) return json(forced.status, forced.body || {}, forced.headers || {});
      if (req.headers.authorization !== `Bearer ${state.validToken}` && req.headers.authorization !== 'Bearer static') {
        return json(401, { error: 'unauthorized' });
      }
      const infected = body.includes('MOCK-MALWARE');
      const verdict = (filename) => ({
        'av-status': infected ? 'INFECTED' : 'CLEAN',
        'av-signature': infected ? 'Mock.Test.Signature' : 'OK',
        'av-timestamp': '2026-01-01T00:00:00Z',
        sha256: 'abc123',
        scan_id: 'scan-1',
        filename,
      });
      if (req.url === '/api/v1/scan/file' || req.url === '/api/v1/async-scan/file') {
        const m = /filename="([^"]*)"/.exec(body.toString('latin1'));
        if (req.url.includes('async')) return json(202, { scan_id: 'scan-1', filename: m && m[1] });
        return json(infected ? 406 : 200, verdict(m && m[1]));
      }
      if (req.url === '/api/v1/scan/url' || req.url === '/api/v1/async-scan/url') {
        if (req.url.includes('async')) return json(202, { scan_id: 'scan-2' });
        return json(200, verdict('remote.bin'));
      }
      if (req.url.startsWith('/api/v1/async-scan/')) {
        state.asyncPolls++;
        if (state.asyncPolls < 3) return json(202, { 'av-status': 'PROCESSING', scan_id: 'scan-1' });
        return json(200, verdict('a.txt'));
      }
      return json(404, { error: 'not found' });
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  return {
    state,
    apiUrl: base,
    tokenUrl: `${base}/oauth2/token`,
    close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }),
  };
}

module.exports = { startMockApi };
