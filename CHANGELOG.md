# Changelog

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
