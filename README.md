# Kelpgate Client for Node.js

**Check every upload for malware before your app stores it.**

Node.js client for the [Kelpgate](https://kelpgate.cloud) malware-scanning API. Scan uploaded files or remote URLs, get a verdict, and keep infected files out of your app. It includes Express middleware and a command line tool.

> This package is open source under the MIT license. It is a client for the Kelpgate scanning service, a hosted commercial product that is not part of this package. You need a Kelpgate account to use it.

## Contents

[Why Kelpgate](#why-kelpgate) · [How it works](#how-it-works) · [Install](#install) · [Quick start](#quick-start) · [Scanning](#scanning) · [Errors](#errors) · [Options](#options) · [Express](#express) · [Command line](#command-line) · [Failure policy](#failure-policy) · [Security and privacy](#security-and-privacy) · [Compatibility](#compatibility) · [Verify your setup](#verify-your-setup) · [Troubleshooting](#troubleshooting) · [Support and versioning](#support-and-versioning) · [Contributing and security](#contributing-and-security) · [License](#license)

## Why Kelpgate

| | |
| --- | --- |
| **One call per file** | Send a file, a buffer, a stream or a URL and get a verdict back. An infected file is a normal result, not an exception. |
| **Credentials handled for you** | The OAuth 2.0 access token is fetched, cached in memory and renewed before it expires. |
| **Predictable failure behavior** | Typed errors for quota, size, file type, rate limits and network problems. You choose what happens when the scanner cannot answer: block or allow. |
| **Safe by default** | API and token URLs must use HTTPS, redirects are never followed, and secrets never appear in errors. |
| **Ready for your stack** | Express and Multer middleware, a command line tool, CommonJS and ESM, and TypeScript types. |
| **Light** | No runtime dependencies. |

## How it works

1. The client obtains an OAuth 2.0 access token with your client credentials. Tokens are cached and renewed shortly before they expire.
2. The file is sent to the scanning API over HTTPS.
3. The API answers with a verdict. A clean file and an infected file (HTTP 406) both come back as a result with `infected` set to `false` or `true`. Anything that stops a verdict, such as an exhausted quota or an unreachable service, is thrown as a typed error. Your code, or the middleware, decides what to do next.

## Install

```bash
npm install @kelpgate/client
```

The package is `@kelpgate/client` on npm and needs Node 18 or newer. You also need a Kelpgate account.

## Quick start

Create an API client in the [Kelpgate Console](https://console.kelpgate.cloud), then:

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
assertClean(await kelpgate.scanBytes(buffer, { filename: 'report.docx' }));
```

`fromEnv()` builds the same client from `KELPGATE_CLIENT_ID`, `KELPGATE_CLIENT_SECRET` (or `KELPGATE_TOKEN`) and the optional `KELPGATE_API_URL` / `KELPGATE_TOKEN_URL`.

## Scanning

| Method | What it does |
| --- | --- |
| `scanFile(source, opts)` | Scan a path, `Buffer`, `Uint8Array`, `Blob` or stream |
| `scanBytes(bytes, opts)` | Same, for bytes in memory (`scanBuffer` still works as an alias) |
| `scanUrl(url)` | Kelpgate fetches the URL and scans it |
| `scanFileAsync` / `scanUrlAsync` | Start a scan and get a `scanId`; pass `webhookUrl` to be called back |
| `getAsyncResult(scanId)` | `{ pending: true }` until the verdict is ready |
| `waitForResult(scanId, { intervalMs, timeoutMs })` | Poll until done |
| `health()` | Service status; needs no credentials |

A scan result has `infected`, `status`, `signature`, `sha256`, `scanId`, `ruleAuthors`, `requestId`, plus two flags worth checking:

- `policyRejected`: the file was refused by policy (for example a disallowed type), not detected as malware.
- `degraded`: an engine did not finish, so coverage was reduced for this scan.

An infected file is a normal result (`infected: true`), not an exception. Use `assertClean(result)` if you prefer one.

### Retries and your quota

Every scan call sends an `Idempotency-Key`. The client makes a random one for each call and reuses it on its own retries, so a retry after a timeout or a 502, 503 or 504 is not counted against your quota twice. You do not have to do anything.

Pass `idempotencyKey` to protect retries you make yourself, for example one key per upload job:

```js
await kelpgate.scanFile(path, { idempotencyKey: `job-${job.id}` });
```

A key is 1 to 128 characters from `A-Za-z0-9._:-` (anything else throws `ConfigError`). The service ties a key to the file: the same key on a different file is counted as a new scan, so never reuse one key for different uploads.

## Errors

All errors extend `KelpgateError` and carry `status`, `code`, `requestId` (quote it to support) and the response `body`.

| Error | When |
| --- | --- |
| `AuthError` | Bad credentials (401) or a suspended organization (403) |
| `QuotaExceededError` | Plan quota used up (402); has `quota`, `usage`, `upgradeUrl` |
| `PayloadTooLargeError` | File over the plan limit (413) or the client's `maxBytes` |
| `UnsupportedFileError` | File type not allowed, or encrypted archive (415) |
| `RateLimitedError` | Too many scans at once (429); has `retryAfterSeconds` |
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

## Failure policy

When the scanner cannot give a verdict, the client throws a typed error. The Express middleware turns that into a decision you control with `onError`.

| Situation | Client | Middleware, `onError: 'block'` (default) | Middleware, `onError: 'allow'` |
| --- | --- | --- | --- |
| Scanner unreachable, timed out or returned 5xx after retries | Throws `NetworkError`, `TimeoutError` or `ServerError` | Request rejected with `503` | Request continues; the error is in `req.kelpgateError` |
| Authentication fails | Throws `AuthError` | `503` | Continues |
| Plan quota used up | Throws `QuotaExceededError` | `402` | Continues |
| File over the plan limit or `maxBytes` | Throws `PayloadTooLargeError` | `413` | Continues |
| File type not allowed | Throws `UnsupportedFileError` | `415` | Continues |

Choose `block` where stopping malware matters more than availability, and `allow` where uploads must keep working during an outage. A retry sends the whole file again. Streams are buffered in memory before they are sent, so for very large files prefer a path.

## Security and privacy

- **What leaves your server:** the uploaded file and its file name, sent over HTTPS to the API URL you configure. Nothing else about your application is sent.
- **Transport:** API and token endpoints must use HTTPS (plain HTTP is accepted only for `localhost`). Redirects are never followed.
- **Secrets:** the client secret never appears in error messages or when a client is serialised. Keep it in an environment variable or a secrets manager, not in source control.
- **Token handling:** access tokens are kept in memory only, never written to disk, and refreshed ahead of expiry. A rejected token is discarded and retried once.
- **Nothing stored locally:** the package writes nothing to disk. The Express middleware deletes infected files that Multer saved.
- **Data kept by the service:** files that scan clean are kept briefly and infected files are quarantined, according to your Kelpgate plan. That is the service's behavior, not this package's.

## Compatibility

Node 18, 20, 22 and 24, tested in CI on every change. The package has no runtime dependencies, works with both `require` and `import`, and ships TypeScript types that are type-checked in CI.

## Verify your setup

Download the standard EICAR test file from [eicar.org](https://www.eicar.org/download-anti-malware-testfile/). It is a harmless file that every scanner treats as a virus.

```bash
npx kelpgate scan ./eicar.com
```

The scan should report `INFECTED` and exit with code `1`. Then scan any ordinary file and confirm it reports `clean` and exits with `0`.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `ConfigError`: must use https | `apiUrl` or `tokenUrl` is not HTTPS. Plain HTTP works only for `localhost`. |
| `AuthError` with code `TOKEN_REQUEST_FAILED` | The client ID or secret is wrong, or the API client does not have the `scan` scope. |
| `AuthError` with status 403 | The organization is suspended, or the API client is not linked to an organization. |
| `QuotaExceededError` | The plan's scan quota is used up. The error carries an `upgradeUrl`. |
| `RateLimitedError`, or slow scans under load | Too many scans at once. The client retries and honours `Retry-After`; lower your concurrency. |
| `PayloadTooLargeError` | The file is over the plan limit or the client's `maxBytes`. |
| `TimeoutError` on large files | Raise `timeoutMs`, or use `scanFileAsync` and `waitForResult`. |
| Clean results with `degraded: true` | An engine did not finish for that scan. The result is still valid; coverage was reduced. |

## Support and versioning

This project follows [Semantic Versioning](https://semver.org): breaking changes only in major versions, new features in minor versions, fixes in patch versions. Releases are tagged on GitHub, and user-visible changes are listed in the [changelog](CHANGELOG.md).

Fixes, including security fixes, go into the latest release only, so upgrade to receive them. The tested runtime versions are listed under Compatibility. The client talks to version 1 of the Kelpgate API (`/api/v1`).

For help, see [getting help](https://github.com/KelpGate/.github/blob/main/SUPPORT.md) or email support@kelpgate.cloud.

## Contributing and security

Bug reports and pull requests are welcome; see the [contributing guide](https://github.com/KelpGate/.github/blob/main/CONTRIBUTING.md). To report a vulnerability, follow the [security policy](https://github.com/KelpGate/.github/blob/main/SECURITY.md) and report it privately. For help, see [getting help](https://github.com/KelpGate/.github/blob/main/SUPPORT.md).

## License

MIT. See [LICENSE](LICENSE). You can use this package in open-source and proprietary software alike. The Kelpgate scanning service it connects to is a hosted commercial product with its own terms.
