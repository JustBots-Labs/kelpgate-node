/// <reference types="node" />

export type ScanSource = string | Buffer | Uint8Array | ArrayBuffer | Blob | NodeJS.ReadableStream | AsyncIterable<Uint8Array>;

export interface KelpgateClientOptions {
  /** Base URL of the Kelpgate API, e.g. https://api.kelpgate.cloud */
  apiUrl: string;
  /** OAuth2 token endpoint. Required unless `bearerToken` is set. */
  tokenUrl?: string;
  clientId?: string;
  clientSecret?: string;
  /** A static bearer token, instead of client credentials. */
  bearerToken?: string;
  /** OAuth scope. Default "scan". */
  scope?: string;
  /** Per-request timeout. Default 60000. */
  timeoutMs?: number;
  /** Retries for network errors, 429, 502, 503 and 504. Default 2. */
  maxRetries?: number;
  /** Base delay between retries. Default 500. */
  retryDelayMs?: number;
  /** Largest file the client will send. Default 128 MiB. */
  maxBytes?: number;
  /** A fetch implementation, for tests or proxies. */
  fetch?: typeof fetch;
}

export interface RequestOptions {
  signal?: AbortSignal;
}

export interface UploadOptions extends RequestOptions {
  /** Name sent with the file. Defaults to the path's basename or the Blob's name. */
  filename?: string;
}

export interface AsyncUploadOptions extends UploadOptions {
  /** URL that Kelpgate calls when the scan finishes. */
  webhookUrl?: string;
}

export interface ScanResult {
  infected: boolean;
  /** "CLEAN" or "INFECTED". */
  status: string;
  /** Detection name, or "OK" for a clean file. */
  signature: string;
  sha256?: string;
  /** Authors of the rules that matched, for rule-licence attribution. */
  ruleAuthors: string[];
  filename?: string;
  scanId?: string;
  timestamp?: string;
  s3Path?: string;
  downloadUrl?: string;
  requestId?: string;
  /** The file was refused by policy (type or content rules) rather than detected as malware. */
  policyRejected: boolean;
  /** An engine did not finish, so coverage was reduced. Consider treating the file with care. */
  degraded: boolean;
  pending: false;
  /** The response body as received. */
  raw: Record<string, unknown>;
}

export interface PendingResult {
  pending: true;
  scanId: string;
  requestId?: string;
}

export interface AcceptedScan {
  scanId: string;
  filename?: string;
  message?: string;
  requestId?: string;
}

export interface HealthResult {
  ok: boolean;
  status: number;
  signatureVersion?: string;
  requestId?: string;
}

export class KelpgateClient {
  constructor(options: KelpgateClientOptions);
  readonly apiUrl: string;
  scanFile(source: ScanSource, options?: UploadOptions): Promise<ScanResult>;
  scanBuffer(bytes: Buffer | Uint8Array | ArrayBuffer, options?: UploadOptions): Promise<ScanResult>;
  scanUrl(url: string, options?: RequestOptions): Promise<ScanResult>;
  scanFileAsync(source: ScanSource, options?: AsyncUploadOptions): Promise<AcceptedScan>;
  scanUrlAsync(url: string, options?: RequestOptions & { webhookUrl?: string }): Promise<AcceptedScan>;
  getAsyncResult(scanId: string, options?: RequestOptions & { kind?: 'file' | 'url' }): Promise<ScanResult | PendingResult>;
  waitForResult(scanId: string, options?: RequestOptions & { kind?: 'file' | 'url'; intervalMs?: number; timeoutMs?: number }): Promise<ScanResult>;
  health(): Promise<HealthResult>;
}

/** Throws InfectedError when the result is infected; otherwise returns it. */
export function assertClean<T extends ScanResult>(result: T): T;

/** Builds a client from KELPGATE_* environment variables. */
export function fromEnv(env?: Record<string, string | undefined>, overrides?: Partial<KelpgateClientOptions>): KelpgateClient;

export interface ErrorDetails {
  code?: string;
  status?: number;
  requestId?: string;
  body?: any;
  cause?: unknown;
}

export class KelpgateError extends Error {
  constructor(message: string, details?: ErrorDetails);
  code: string;
  status?: number;
  requestId?: string;
  body?: any;
  cause?: unknown;
}
export class ConfigError extends KelpgateError { constructor(message: string); }
export class AuthError extends KelpgateError {}
export class QuotaExceededError extends KelpgateError { quota?: number; usage?: number; upgradeUrl?: string; }
export class PayloadTooLargeError extends KelpgateError { upgradeUrl?: string; }
export class UnsupportedFileError extends KelpgateError {}
export class RateLimitedError extends KelpgateError { retryAfterSeconds?: number; }
export class ScanError extends KelpgateError {}
export class ServerError extends KelpgateError {}
export class NetworkError extends KelpgateError {}
export class TimeoutError extends NetworkError {}
export class InfectedError extends KelpgateError {
  constructor(result: ScanResult);
  result: ScanResult;
  signature: string;
}
