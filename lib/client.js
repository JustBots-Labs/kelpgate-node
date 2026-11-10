'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { Readable } = require('node:stream');
const E = require('./errors');
const pkg = require('../package.json');

const DEFAULT_MAX_BYTES = 128 * 1024 * 1024; // a little above the largest plan limit
const REFRESH_AHEAD_MS = 120 * 1000;         // renew a token this long before it expires
const RETRY_AFTER_CAP_MS = 30 * 1000;

const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

function checkUrl(name, value) {
  let u;
  try { u = new URL(value); } catch { throw new E.ConfigError(`${name} is not a valid URL`); }
  const secure = u.protocol === 'https:' || (u.protocol === 'http:' && LOOPBACK.has(u.hostname));
  if (!secure) throw new E.ConfigError(`${name} must use https (plain http is only allowed for localhost)`);
  return u.href.replace(/\/+$/, '');
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Combines a timeout and an optional caller signal into one AbortSignal. Written by hand because
 * AbortSignal.any needs Node 20.3 and this package supports Node 18.
 */
function requestSignal(timeoutMs, userSignal) {
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; controller.abort(); }, timeoutMs);
  const onAbort = () => controller.abort();
  if (userSignal) {
    if (userSignal.aborted) controller.abort(); else userSignal.addEventListener('abort', onAbort, { once: true });
  }
  return {
    signal: controller.signal,
    didTimeOut: () => timedOut,
    done: () => { clearTimeout(timer); if (userSignal) userSignal.removeEventListener('abort', onAbort); },
  };
}

class KelpgateClient {
  /**
   * @param {object} options
   * @param {string} options.apiUrl     Base URL of the Kelpgate API (https).
   * @param {string} [options.tokenUrl] OAuth2 token endpoint (https). Needed unless bearerToken is set.
   * @param {string} [options.clientId]
   * @param {string} [options.clientSecret]
   * @param {string} [options.bearerToken] A static bearer token, instead of client credentials.
   * @param {string} [options.scope='scan']
   * @param {number} [options.timeoutMs=60000]
   * @param {number} [options.maxRetries=2]
   * @param {number} [options.retryDelayMs=500]
   * @param {number} [options.maxBytes]     Largest file this client will send.
   * @param {Function} [options.fetch]      A fetch implementation (for tests or proxies).
   */
  constructor(options = {}) {
    if (!options || typeof options !== 'object') throw new E.ConfigError('options are required');
    this.apiUrl = checkUrl('apiUrl', options.apiUrl || '');
    this.bearerToken = options.bearerToken || null;
    if (!this.bearerToken) {
      this.tokenUrl = checkUrl('tokenUrl', options.tokenUrl || '');
      if (!options.clientId || !options.clientSecret) {
        throw new E.ConfigError('clientId and clientSecret are required (or pass bearerToken)');
      }
      this.clientId = String(options.clientId);
      this._clientSecret = String(options.clientSecret); // kept out of enumerable output
    }
    this.scope = options.scope || 'scan';
    this.timeoutMs = Number.isFinite(options.timeoutMs) ? options.timeoutMs : 60000;
    this.maxRetries = Number.isInteger(options.maxRetries) ? Math.max(0, options.maxRetries) : 2;
    this.retryDelayMs = Number.isFinite(options.retryDelayMs) ? options.retryDelayMs : 500;
    this.maxBytes = Number.isFinite(options.maxBytes) ? options.maxBytes : DEFAULT_MAX_BYTES;
    this._fetch = options.fetch || globalThis.fetch;
    if (typeof this._fetch !== 'function') throw new E.ConfigError('no fetch available: use Node 18 or newer, or pass options.fetch');
    this._token = null;      // { value, expiresAt }
    this._inflight = null;   // a token request in progress, shared by concurrent callers
    Object.defineProperty(this, '_clientSecret', { enumerable: false });
  }

  toJSON() { return { apiUrl: this.apiUrl, scope: this.scope }; } // never expose credentials by accident

  // ---- authentication

  async _getToken(forceRefresh = false) {
    if (this.bearerToken) return this.bearerToken;
    const now = Date.now();
    const t = this._token;
    if (!forceRefresh && t && t.expiresAt - now > REFRESH_AHEAD_MS) return t.value;
    if (!this._inflight) {
      this._inflight = this._fetchToken()
        .then((fresh) => { this._token = fresh; return fresh; })
        .catch((err) => {
          // renewing early failed but the old token is still good: keep using it
          if (!forceRefresh && t && t.expiresAt > Date.now()) return t;
          throw err;
        })
        .finally(() => { this._inflight = null; });
    }
    return (await this._inflight).value;
  }

  async _fetchToken() {
    const enc = encodeURIComponent;
    const basic = Buffer.from(`${enc(this.clientId)}:${enc(this._clientSecret)}`).toString('base64');
    const body = new URLSearchParams({ grant_type: 'client_credentials', scope: this.scope });
    const timing = requestSignal(this.timeoutMs);
    let res;
    try {
      res = await this._fetch(this.tokenUrl, {
        method: 'POST',
        headers: { authorization: `Basic ${basic}`, 'content-type': 'application/x-www-form-urlencoded', 'user-agent': `${pkg.name}/${pkg.version}` },
        body,
        redirect: 'error',
        signal: timing.signal,
      });
    } catch (err) {
      throw this._networkError(err, timing, 'token request');
    } finally {
      timing.done();
    }
    const data = await readJson(res);
    if (!res.ok || !data.access_token) {
      const why = data.error_description || data.error || `HTTP ${res.status}`;
      throw new E.AuthError(`Could not get an access token: ${why}`, { status: res.status, code: 'TOKEN_REQUEST_FAILED', body: redact(data) });
    }
    const seconds = Number(data.expires_in) > 0 ? Number(data.expires_in) : 300;
    return { value: data.access_token, expiresAt: Date.now() + seconds * 1000 };
  }

  // ---- HTTP

  _networkError(err, timing, what) {
    if (timing.didTimeOut()) return new E.TimeoutError(`The ${what} timed out after ${this.timeoutMs} ms`, { cause: err });
    if (err && err.name === 'AbortError') return new E.NetworkError(`The ${what} was cancelled`, { code: 'ABORTED', cause: err });
    const detail = (err && err.cause && (err.cause.code || err.cause.message)) || (err && err.message) || 'unknown error';
    return new E.NetworkError(`The ${what} failed: ${detail}`, { cause: err });
  }

  /** Sends a request with auth, one token retry on 401, and bounded retries on transient failures. */
  async _request(method, urlPath, { body, headers = {}, signal, auth = true } = {}) {
    let tokenRetried = false;
    for (let attempt = 0; ; attempt++) {
      const timing = requestSignal(this.timeoutMs, signal);
      let res;
      try {
        const h = { 'user-agent': `${pkg.name}/${pkg.version}`, accept: 'application/json', ...headers };
        if (auth) h.authorization = `Bearer ${await this._getToken()}`;
        res = await this._fetch(this.apiUrl + urlPath, { method, headers: h, body, redirect: 'error', signal: timing.signal });
      } catch (err) {
        timing.done();
        const mapped = err instanceof E.KelpgateError ? err : this._networkError(err, timing, 'request');
        if (mapped.code === 'ABORTED' || attempt >= this.maxRetries || !(mapped instanceof E.NetworkError)) throw mapped;
        await sleep(this._backoff(attempt));
        continue;
      }
      const text = await res.text().catch(() => '');
      timing.done();
      const data = parseJson(text);
      const requestId = res.headers.get('x-request-id') || undefined;

      if (res.status === 401 && auth && !this.bearerToken && !tokenRetried) {
        tokenRetried = true; // the token may have been revoked or rotated: get a fresh one once
        this._token = null;
        await this._getToken(true);
        continue;
      }
      const retryable = res.status === 429 || res.status === 502 || res.status === 503 || res.status === 504;
      if (retryable && attempt < this.maxRetries) {
        await sleep(this._backoff(attempt, res.headers.get('retry-after')));
        continue;
      }
      return { status: res.status, data, requestId, headers: res.headers };
    }
  }

  _backoff(attempt, retryAfter) {
    const seconds = Number(retryAfter);
    if (Number.isFinite(seconds) && seconds >= 0) return Math.min(seconds * 1000, RETRY_AFTER_CAP_MS);
    return this.retryDelayMs * 2 ** attempt + Math.floor(Math.random() * Math.min(100, this.retryDelayMs));
  }

  _fail(r) {
    const d = r.data || {};
    const message = d.error || d.message || `Kelpgate returned HTTP ${r.status}`;
    const details = { status: r.status, requestId: r.requestId, body: d };
    switch (r.status) {
      case 401: case 403: return new E.AuthError(message, { ...details, code: r.status === 401 ? 'UNAUTHORIZED' : 'FORBIDDEN' });
      case 402: return new E.QuotaExceededError(message, details);
      case 413: return new E.PayloadTooLargeError(message, details);
      case 415: return new E.UnsupportedFileError(message, details);
      case 429: return new E.RateLimitedError(message, { ...details, retryAfterSeconds: Number(r.headers.get('retry-after')) || undefined });
      case 404: return new E.KelpgateError(message, { ...details, code: 'NOT_FOUND' });
      case 400: case 412: return new E.ScanError(message, details);
      default: return r.status >= 500 ? new E.ServerError(message, details) : new E.KelpgateError(message, details);
    }
  }

  // ---- input handling

  async _toBlob(source, filename) {
    let blob; let name = filename;
    if (typeof source === 'string') {
      blob = typeof fs.openAsBlob === 'function' ? await fs.openAsBlob(source) : new Blob([await fs.promises.readFile(source)]);
      name = name || path.basename(source);
    } else if (source instanceof Blob) {
      blob = source;
      name = name || source.name;
    } else if (source instanceof ArrayBuffer || ArrayBuffer.isView(source)) {
      blob = new Blob([source]);
    } else if (source && (typeof source.pipe === 'function' || typeof source[Symbol.asyncIterator] === 'function')) {
      const stream = typeof source.pipe === 'function' ? source : Readable.from(source);
      const chunks = []; let size = 0;
      for await (const chunk of stream) {
        size += chunk.length;
        if (size > this.maxBytes) { stream.destroy && stream.destroy(); throw this._tooBig(size); }
        chunks.push(chunk);
      }
      blob = new Blob(chunks);
      name = name || (source.path && path.basename(String(source.path)));
    } else {
      throw new E.ConfigError('source must be a file path, Buffer, Uint8Array, Blob, or a readable stream');
    }
    if (blob.size > this.maxBytes) throw this._tooBig(blob.size);
    return { blob, name: path.basename(String(name || 'upload.bin')) };
  }

  _tooBig(size) {
    return new E.PayloadTooLargeError(`The file is ${size} bytes, over this client's limit of ${this.maxBytes} bytes`, { status: 413, code: 'PAYLOAD_TOO_LARGE' });
  }

  async _upload(urlPath, source, options = {}, extra = {}) {
    const { blob, name } = await this._toBlob(source, options.filename);
    const form = new FormData();
    form.append('file', blob, name);
    if (extra.webhookUrl) form.append('webhook_url', extra.webhookUrl);
    return this._request('POST', urlPath, { body: form, signal: options.signal });
  }

  // ---- results

  _verdict(r) {
    const d = r.data || {};
    const signature = d['av-signature'] || '';
    return {
      infected: d['av-status'] === 'INFECTED',
      status: d['av-status'],
      signature,
      sha256: d.sha256,
      ruleAuthors: Array.isArray(d.rule_authors) ? d.rule_authors : [],
      filename: d.filename,
      scanId: d.scan_id,
      timestamp: d['av-timestamp'],
      s3Path: d.s3_path,
      downloadUrl: d.download_url,
      policyRejected: signature.startsWith('POLICY:'),
      degraded: signature.includes('scan coverage reduced'),
      requestId: r.requestId,
      pending: false,
      raw: d,
    };
  }

  /** A scan answers 200 (clean) or 406 (infected); both are verdicts. Everything else is an error. */
  _scanResult(r) {
    if ((r.status === 200 || r.status === 406) && r.data && r.data['av-status']) return this._verdict(r);
    throw this._fail(r);
  }

  // ---- public API

  /** Scans a file: a path, Buffer, Uint8Array, Blob or readable stream. */
  async scanFile(source, options = {}) {
    return this._scanResult(await this._upload('/api/v1/scan/file', source, options));
  }

  /** Same as scanFile, for bytes you already have in memory. */
  async scanBuffer(bytes, options = {}) { return this.scanFile(bytes, options); }

  /** Asks the service to fetch and scan a remote file. */
  async scanUrl(url, options = {}) {
    const r = await this._request('POST', '/api/v1/scan/url', {
      body: JSON.stringify({ url: String(url) }), headers: { 'content-type': 'application/json' }, signal: options.signal,
    });
    return this._scanResult(r);
  }

  /** Starts an asynchronous scan of a file. Returns { scanId }. */
  async scanFileAsync(source, options = {}) {
    return this._accepted(await this._upload('/api/v1/async-scan/file', source, options, { webhookUrl: options.webhookUrl }));
  }

  /** Starts an asynchronous scan of a remote file. Returns { scanId }. */
  async scanUrlAsync(url, options = {}) {
    const payload = { url: String(url) };
    if (options.webhookUrl) payload.webhook_url = options.webhookUrl;
    return this._accepted(await this._request('POST', '/api/v1/async-scan/url', {
      body: JSON.stringify(payload), headers: { 'content-type': 'application/json' }, signal: options.signal,
    }));
  }

  _accepted(r) {
    if (r.status === 202 && r.data && r.data.scan_id) {
      return { scanId: r.data.scan_id, filename: r.data.filename, message: r.data.message, requestId: r.requestId };
    }
    throw this._fail(r);
  }

  /** Reads an asynchronous result. Returns { pending: true } until the verdict is ready. */
  async getAsyncResult(scanId, options = {}) {
    const kind = options.kind === 'url' ? 'url' : 'file';
    const r = await this._request('GET', `/api/v1/async-scan/${kind}?scan_id=${encodeURIComponent(scanId)}`, { signal: options.signal });
    if (r.status === 202 || (r.data && r.data['av-status'] === 'PROCESSING')) return { pending: true, scanId, requestId: r.requestId };
    return this._scanResult(r);
  }

  /** Polls until an asynchronous scan finishes, or throws a TimeoutError. */
  async waitForResult(scanId, options = {}) {
    const interval = options.intervalMs || 1000;
    const deadline = Date.now() + (options.timeoutMs || 120000);
    for (;;) {
      const result = await this.getAsyncResult(scanId, options);
      if (!result.pending) return result;
      if (Date.now() + interval > deadline) throw new E.TimeoutError(`Scan ${scanId} was not finished after ${options.timeoutMs || 120000} ms`);
      await sleep(interval);
    }
  }

  /** Checks that the service is up. Needs no credentials. */
  async health() {
    const r = await this._request('GET', '/api/v1/health', { auth: false });
    return {
      ok: r.status === 200,
      status: r.status,
      signatureVersion: r.data && r.data.signature_version,
      requestId: r.requestId,
    };
  }
}

/** Throws InfectedError if the result is infected. Returns the result otherwise. */
function assertClean(result) {
  if (result && result.infected) throw new E.InfectedError(result);
  return result;
}

function parseJson(text) {
  if (!text) return {};
  try { return JSON.parse(text); } catch { return { error: text.slice(0, 200) }; }
}

async function readJson(res) { return parseJson(await res.text().catch(() => '')); }

function redact(data) {
  const copy = { ...data };
  delete copy.access_token; delete copy.refresh_token;
  return copy;
}

module.exports = { KelpgateClient, assertClean };
