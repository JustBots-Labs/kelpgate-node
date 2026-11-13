# Changelog

## 0.4.0

- Every scan now sends an `Idempotency-Key`, so a retry after a timeout or a 502, 503 or 504 is not counted against your quota twice. The client makes a random key for each call and reuses it on its own retries; no change is needed in your code.
- New optional `idempotencyKey` on `scanFile`, `scanBytes`, `scanUrl`, `scanFileAsync` and `scanUrlAsync`, to protect your own retries (a job id, for example). An invalid key (not 1 to 128 characters from `A-Za-z0-9._:-`) throws `ConfigError` before any request. Do not reuse one key for different files: the service counts a different file under the same key as a new scan.
- See the [Kelpgate client standard](https://github.com/KelpGate/.github/blob/main/docs/client-standard.md#idempotency).

## 0.3.0

- The license changed from GPL-2.0-or-later to MIT, so the package can be used in proprietary software as well as open-source software. Versions published earlier remain available under the GPL. The WordPress plugin and Drupal module stay GPL, as WordPress.org and Drupal.org require.
- No code changes.

## 0.2.0

- `scanBytes` is the name for scanning bytes in memory, matching the other Kelpgate clients (see the [Kelpgate client standard](https://github.com/KelpGate/.github/blob/main/docs/client-standard.md)). `scanBuffer` still works as an alias.

## 0.1.1

- Package metadata: author is JustBots Labs, and the repository, homepage and issue links point to github.com/KelpGate/kelpgate-node. No code changes.

## 0.1.0

First release.

- `KelpgateClient`: scan files (path, Buffer, Blob, stream) and URLs, sync or async, with `waitForResult`.
- OAuth2 client-credentials with a cached token, renewed before it expires.
- Retries on network errors, 429, 502, 503 and 504; typed errors for every API status.
- `@kelpgate/client/express`: middleware for Multer uploads.
- `kelpgate` command line tool (exit code 0 clean, 1 infected, 2 error).
- TypeScript declarations; no runtime dependencies; Node 18 or newer.
