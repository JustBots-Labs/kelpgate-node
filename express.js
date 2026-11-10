'use strict';

const fs = require('node:fs');
const { KelpgateClient } = require('./lib/client');
const E = require('./lib/errors');

function collectFiles(req) {
  const out = [];
  if (req.file) out.push(req.file);
  if (Array.isArray(req.files)) out.push(...req.files);
  else if (req.files && typeof req.files === 'object') for (const list of Object.values(req.files)) out.push(...list);
  return out;
}

/**
 * Express/Connect middleware that scans files parsed by Multer (or any parser that sets
 * req.file / req.files with `path` or `buffer`). Use it after the upload middleware.
 *
 *   app.post('/upload', upload.single('doc'), kelpgateScan({ client }), handler)
 *
 * Results are left on `req.kelpgate` (an array of scan results, in file order).
 * Options:
 *   client      a KelpgateClient (required)
 *   onInfected  'reject' (default) answers 422; 'pass' continues with req.kelpgate set, so you decide
 *   onError     'block' (default) answers 503 when the scan cannot run; 'allow' lets the upload through
 *   deleteInfected  remove infected files saved to disk (default true)
 */
function kelpgateScan(options = {}) {
  const { client, onInfected = 'reject', onError = 'block', deleteInfected = true } = options;
  if (!(client instanceof KelpgateClient)) throw new E.ConfigError('kelpgateScan needs a KelpgateClient as options.client');

  return async function kelpgateMiddleware(req, res, next) {
    const files = collectFiles(req);
    if (files.length === 0) return next();
    const results = [];
    try {
      for (const f of files) {
        const source = f.buffer || f.path;
        if (!source) continue;
        const result = await client.scanFile(source, { filename: f.originalname });
        results.push(result);
        if (result.infected && deleteInfected && f.path) await fs.promises.unlink(f.path).catch(() => {});
      }
    } catch (err) {
      if (onError === 'allow') { req.kelpgate = results; req.kelpgateError = err; return next(); }
      for (const f of files) if (f.path) await fs.promises.unlink(f.path).catch(() => {});
      if (err instanceof E.QuotaExceededError) return res.status(402).json({ error: 'Scan quota exceeded' });
      if (err instanceof E.PayloadTooLargeError) return res.status(413).json({ error: 'File too large to scan' });
      if (err instanceof E.UnsupportedFileError) return res.status(415).json({ error: 'File type not allowed' });
      return res.status(503).json({ error: 'File could not be scanned, try again later' });
    }
    req.kelpgate = results;
    const bad = results.find((r) => r.infected);
    if (bad && onInfected === 'reject') {
      for (const f of files) if (f.path) await fs.promises.unlink(f.path).catch(() => {});
      return res.status(422).json({ error: 'File rejected by malware scan', signature: bad.signature });
    }
    return next();
  };
}

module.exports = { kelpgateScan };
