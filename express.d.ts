import type { KelpgateClient, ScanResult } from './index';

export interface KelpgateScanOptions {
  client: KelpgateClient;
  /** "reject" (default) answers 422; "pass" continues so the handler decides. */
  onInfected?: 'reject' | 'pass';
  /** "block" (default) answers 503 when scanning fails; "allow" lets the upload through. */
  onError?: 'block' | 'allow';
  /** Delete infected files saved to disk. Default true. */
  deleteInfected?: boolean;
}

export type KelpgateMiddleware = (req: any, res: any, next: (err?: unknown) => void) => Promise<void>;

export function kelpgateScan(options: KelpgateScanOptions): KelpgateMiddleware;

declare global {
  namespace Express {
    interface Request {
      kelpgate?: ScanResult[];
      kelpgateError?: Error;
    }
  }
}
