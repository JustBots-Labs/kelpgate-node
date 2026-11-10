#!/usr/bin/env node
'use strict';

const { fromEnv } = require('..');
const pkg = require('../package.json');

const HELP = `kelpgate ${pkg.version}

Usage:
  kelpgate scan <file...>      Scan one or more files
  kelpgate scan-url <url>      Have Kelpgate fetch and scan a URL
  kelpgate health              Check the service

Options:
  --json     Print results as JSON
  -h, --help
  -v, --version

Environment:
  KELPGATE_CLIENT_ID, KELPGATE_CLIENT_SECRET   OAuth client credentials
  KELPGATE_TOKEN                               or a bearer token
  KELPGATE_API_URL, KELPGATE_TOKEN_URL         override the default endpoints

Exit codes: 0 clean, 1 infected, 2 error.
`;

async function main(argv) {
  const json = argv.includes('--json');
  const args = argv.filter((a) => a !== '--json');
  const [cmd, ...rest] = args;
  if (!cmd || cmd === '-h' || cmd === '--help') { process.stdout.write(HELP); return cmd ? 0 : 2; }
  if (cmd === '-v' || cmd === '--version') { process.stdout.write(`${pkg.version}\n`); return 0; }

  const client = fromEnv();
  const out = (v) => process.stdout.write(`${typeof v === 'string' ? v : JSON.stringify(v)}\n`);

  if (cmd === 'health') {
    const h = await client.health();
    out(json ? h : `${h.ok ? 'ok' : 'unhealthy'} (HTTP ${h.status})${h.signatureVersion ? `, signatures ${h.signatureVersion}` : ''}`);
    return h.ok ? 0 : 2;
  }
  if (cmd !== 'scan' && cmd !== 'scan-url') { process.stderr.write(`Unknown command: ${cmd}\n\n${HELP}`); return 2; }
  if (rest.length === 0) { process.stderr.write(`${cmd} needs an argument\n`); return 2; }

  let infected = false;
  for (const target of rest) {
    const r = cmd === 'scan' ? await client.scanFile(target) : await client.scanUrl(target);
    infected = infected || r.infected;
    if (json) out({ target, infected: r.infected, status: r.status, signature: r.signature, sha256: r.sha256, scanId: r.scanId });
    else out(`${r.infected ? 'INFECTED' : 'clean   '}  ${target}${r.infected || r.degraded ? `  (${r.signature})` : ''}`);
  }
  return infected ? 1 : 0;
}

main(process.argv.slice(2)).then(
  (code) => { process.exitCode = code; },
  (err) => {
    process.stderr.write(`kelpgate: ${err.message}${err.requestId ? ` (request ${err.requestId})` : ''}\n`);
    process.exitCode = 2;
  },
);
