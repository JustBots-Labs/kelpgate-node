'use strict';

const { KelpgateClient, assertClean } = require('./lib/client');
const errors = require('./lib/errors');

/** Builds a client from KELPGATE_* environment variables. */
function fromEnv(env = process.env, overrides = {}) {
  return new KelpgateClient({
    apiUrl: env.KELPGATE_API_URL || 'https://api.kelpgate.cloud',
    tokenUrl: env.KELPGATE_TOKEN_URL || 'https://auth.kelpgate.cloud/oauth2/token',
    clientId: env.KELPGATE_CLIENT_ID,
    clientSecret: env.KELPGATE_CLIENT_SECRET,
    bearerToken: env.KELPGATE_TOKEN,
    ...overrides,
  });
}

module.exports = { KelpgateClient, assertClean, fromEnv, ...errors };
