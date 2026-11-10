import cjs from './index.js';

export const {
  KelpgateClient, assertClean, fromEnv,
  KelpgateError, ConfigError, AuthError, QuotaExceededError, PayloadTooLargeError,
  UnsupportedFileError, RateLimitedError, ScanError, ServerError, NetworkError, TimeoutError, InfectedError,
} = cjs;
export default cjs;
