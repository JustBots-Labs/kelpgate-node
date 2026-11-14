import { KelpgateClient, assertClean, fromEnv, QuotaExceededError, type ScanResult } from '../../index';
import { kelpgateScan } from '../../express';

async function main() {
  const c = new KelpgateClient({ apiUrl: 'https://api.kelpgate.cloud', tokenUrl: 'https://auth.kelpgate.cloud/oauth2/token', clientId: 'a', clientSecret: 'b' });
  const r: ScanResult = assertClean(await c.scanFile('./sample.bin'));
  const sig: string = r.signature;
  const acc = await c.scanFileAsync(Buffer.from('x'), { webhookUrl: 'https://x' });
  const done = await c.waitForResult(acc.scanId, { timeoutMs: 1000 });
  const p = await c.getAsyncResult('id');
  if (p.pending) { const id: string = p.scanId; void id; }
  await c.scanFile('./sample.bin', { idempotencyKey: 'job-1' });
  await c.scanUrl('https://x', { idempotencyKey: 'job-1' });
  await c.scanUrlAsync('https://x', { idempotencyKey: 'job-1', webhookUrl: 'https://x' });
  try { await c.scanUrl('https://x'); } catch (e) { if (e instanceof QuotaExceededError) void e.upgradeUrl; }
  void sig; void done; void fromEnv(); void kelpgateScan({ client: c, onInfected: 'pass' });
}
void main;
