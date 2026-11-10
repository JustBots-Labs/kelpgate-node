# @kelpgate/client

Node.js client for the [Kelpgate](https://kelpgate.cloud) malware-scanning API. Scan uploaded files or remote URLs, get a verdict, and keep infected files out of your app.

- No runtime dependencies. Node 18 or newer. CommonJS and ESM, with TypeScript types.
- Handles the OAuth2 token for you (cached, renewed before it expires).
- Retries transient failures; typed errors for quota, size, file type and rate limits.
- Express/Multer middleware and a `kelpgate` command line tool included.

```bash
npm install @kelpgate/client
```

## Quick start

Create an API client in the [Kelpgate console](https://console.kelpgate.cloud), then:

```js
const { KelpgateClient, assertClean } = require('@kelpgate/client');

const kelpgate = new KelpgateClient({
  apiUrl: 'https://api.kelpgate.cloud',
  tokenUrl: 'https://auth.kelpgate.cloud/oauth2/token',
  clientId: process.env.KELPGATE_CLIENT_ID,
  clientSecret: process.env.KELPGATE_CLIENT_SECRET,
});

const result = await kelpgate.scanFile('./upload.pdf');
if (result.infected) {
  console.log('Rejected:', result.signature);
}

// or throw instead:
assertClean(await kelpgate.scanBuffer(buffer, { filename: 'report.docx' }));
```

`fromEnv()` builds the same client from `KELPGATE_CLIENT_ID`, `KELPGATE_CLIENT_SECRET` (or `KELPGATE_TOKEN`) and the optional `KELPGATE_API_URL` / `KELPGATE_TOKEN_URL`.

## Scanning

| Method | What it does |
| --- | --- |
| `scanFile(source, opts)` | Scan a path, `Buffer`, `Uint8Array`, `Blob` or stream |
| `scanBuffer(bytes, opts)` | Same, for bytes in memory |
| `scanUrl(url)` | Kelpgate fetches the URL and scans it |
| `scanFileAsync` / `scanUrlAsync` | Start a scan and get a `scanId`; pass `webhookUrl` to be called back |
| `getAsyncResult(scanId)` | `{ pending: true }` until the verdict is ready |
| `waitForResult(scanId, { intervalMs, timeoutMs })` | Poll until done |
| `health()` | Service status; needs no credentials |

A scan result has `infected`, `status`, `signature`, `sha256`, `scanId`, `ruleAuthors`, `requestId`, plus two flags worth checking:

- `policyRejected`: the file was refused by policy (for example a disallowed type), not detected as malware.
- `degraded`: an engine did not finish, so coverage was reduced for this scan.

An infected file is a normal result (`infected: true`), not an exception. Use `assertClean(result)` if you prefer one.

## Errors

All errors extend `KelpgateError` and carry `status`, `code`, `requestId` (quote it to support) and the response `body`.

| Error | When |
| --- | --- |
| `AuthError` | Bad credentials (401) or a suspended tenant (403) |
| `QuotaExceededError` | Plan quota used up (402); has `quota`, `usage`, `upgradeUrl` |
| `PayloadTooLargeError` | File over the plan limit (413) or the client's `maxBytes` |
| `UnsupportedFileError` | File type not allowed, or encrypted archive (415) |
| `RateLimitedError` | Too many concurrent scans (429); has `retryAfterSeconds` |
| `ScanError` | Invalid request (400) or file could not be parsed (412) |
| `ServerError` | 5xx |
| `NetworkError`, `TimeoutError` | Could not reach the service |
| `ConfigError` | Wrong options, thrown by the constructor |
| `InfectedError` | Thrown by `assertClean` |

## Options

`apiUrl`, `tokenUrl`, `clientId`, `clientSecret` (or `bearerToken`), `scope` (default `scan`), `timeoutMs` (60000), `maxRetries` (2), `retryDelayMs` (500), `maxBytes` (128 MiB), `fetch`.

Both URLs must be `https`; plain `http` is accepted only for `localhost`. Redirects are never followed, so credentials cannot be sent to another host.

## Express

```js
const multer = require('multer');
const { kelpgateScan } = require('@kelpgate/client/express');

const upload = multer({ dest: 'uploads/' });
app.post('/upload', upload.single('doc'), kelpgateScan({ client: kelpgate }), (req, res) => {
  res.json({ ok: true, scan: req.kelpgate[0] });
});
```

Infected uploads get a `422` and are deleted from disk. If scanning fails, the request is blocked with `503` (`onError: 'allow'` lets it through instead). `onInfected: 'pass'` leaves the decision to your handler.

## Command line

```bash
export KELPGATE_CLIENT_ID=... KELPGATE_CLIENT_SECRET=...
npx kelpgate scan ./file.zip other.pdf
npx kelpgate scan-url https://example.com/file.exe
npx kelpgate health
```

Exit code `0` clean, `1` infected, `2` error. Add `--json` for machine-readable output.

## Licence

GPL-2.0-or-later, the same as the Kelpgate WordPress plugin and Drupal module. Note that the GPL applies to software you distribute that includes this package; using it on your own server does not require you to publish your code.
