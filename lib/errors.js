'use strict';

/** Base class for every error this package throws on purpose. */
class KelpgateError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = this.constructor.name;
    this.code = details.code || 'KELPGATE_ERROR';
    this.status = details.status;
    this.requestId = details.requestId;
    this.body = details.body;
    if (details.cause) this.cause = details.cause;
  }
}

/** The options passed to the client are wrong. Thrown by the constructor, before any request. */
class ConfigError extends KelpgateError {
  constructor(message) { super(message, { code: 'CONFIG' }); }
}

/** The API refused the credentials (401), or the tenant may not use it (403). */
class AuthError extends KelpgateError {}

/** The plan's monthly scan quota is used up (402). */
class QuotaExceededError extends KelpgateError {
  constructor(message, details = {}) {
    super(message, { ...details, code: 'QUOTA_EXCEEDED' });
    this.quota = details.body && details.body.quota;
    this.usage = details.body && details.body.usage;
    this.upgradeUrl = details.body && details.body.upgrade_url;
  }
}

/** The file is larger than the plan allows (413), or larger than `maxBytes` set on the client. */
class PayloadTooLargeError extends KelpgateError {
  constructor(message, details = {}) {
    super(message, { ...details, code: 'PAYLOAD_TOO_LARGE' });
    this.upgradeUrl = details.body && details.body.upgrade_url;
  }
}

/** The file type is not allowed, or it is an encrypted archive (415). */
class UnsupportedFileError extends KelpgateError {
  constructor(message, details = {}) { super(message, { ...details, code: 'UNSUPPORTED_FILE' }); }
}

/** Too many scans at once for this tenant (429). */
class RateLimitedError extends KelpgateError {
  constructor(message, details = {}) {
    super(message, { ...details, code: 'RATE_LIMITED' });
    this.retryAfterSeconds = details.retryAfterSeconds;
  }
}

/** The request was rejected as invalid (400), or the file could not be parsed (412). */
class ScanError extends KelpgateError {
  constructor(message, details = {}) { super(message, { ...details, code: details.code || 'SCAN_ERROR' }); }
}

/** The service failed (5xx). */
class ServerError extends KelpgateError {
  constructor(message, details = {}) { super(message, { ...details, code: 'SERVER_ERROR' }); }
}

/** The service could not be reached, or the connection broke. */
class NetworkError extends KelpgateError {
  constructor(message, details = {}) { super(message, { ...details, code: details.code || 'NETWORK' }); }
}

/** The request took longer than `timeoutMs`. */
class TimeoutError extends NetworkError {
  constructor(message, details = {}) { super(message, { ...details, code: 'TIMEOUT' }); }
}

/** Thrown by `assertClean` when a scan found malware. */
class InfectedError extends KelpgateError {
  constructor(result) {
    super(`File rejected: ${result.signature || 'infected'}`, { code: 'INFECTED', status: 406, requestId: result.requestId });
    this.result = result;
    this.signature = result.signature;
  }
}

module.exports = {
  KelpgateError, ConfigError, AuthError, QuotaExceededError, PayloadTooLargeError,
  UnsupportedFileError, RateLimitedError, ScanError, ServerError, NetworkError, TimeoutError, InfectedError,
};
