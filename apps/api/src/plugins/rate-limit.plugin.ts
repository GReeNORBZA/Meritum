import { type FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';
import rateLimit from '@fastify/rate-limit';

// ---------------------------------------------------------------------------
// Rate limit tiers (from CLAUDE.md):
//   Default:        100 req/min per user
//   Auth endpoints: 10 req/min per IP
//   File uploads:   5 req/min per user
//   Internal:       no rate limiting
// ---------------------------------------------------------------------------

export interface RateLimitPluginOptions {
  /** Override default max for testing. */
  defaultMax?: number;
}

async function rateLimitPlugin(app: FastifyInstance, opts: RateLimitPluginOptions) {
  const defaultMax = opts.defaultMax ?? 100;

  await app.register(rateLimit, {
    max: defaultMax,
    timeWindow: '1 minute',
    keyGenerator: (request) => {
      // Use authenticated userId if available, otherwise fall back to IP
      return request.authContext?.userId ?? request.ip;
    },
    errorResponseBuilder: (_request, context) => ({
      error: {
        code: 'RATE_LIMITED',
        message: `Rate limit exceeded. Retry after ${Math.ceil(context.ttl / 1000)} seconds.`,
      },
    }),
  });
}

// ---------------------------------------------------------------------------
// Route-level rate limit config factories
// ---------------------------------------------------------------------------

/**
 * Auth endpoint rate limiting: 10 req/min per IP.
 * Use as route-level config: { config: { rateLimit: authRateLimit() } }
 */
export function authRateLimit() {
  return {
    max: 10,
    timeWindow: '1 minute',
    keyGenerator: (request: any) => request.ip,
  };
}

/**
 * File upload rate limiting: 5 req/min per user.
 * Use as route-level config: { config: { rateLimit: uploadRateLimit() } }
 */
export function uploadRateLimit() {
  return {
    max: 5,
    timeWindow: '1 minute',
    keyGenerator: (request: any) => request.authContext?.userId ?? request.ip,
  };
}

/**
 * No rate limiting (internal/service-to-service endpoints).
 * Use as route-level config: { config: { rateLimit: noRateLimit() } }
 */
export function noRateLimit() {
  return {
    max: 0, // 0 = disabled
  };
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

export const rateLimitPluginFp = fp(rateLimitPlugin, {
  name: 'rate-limit-plugin',
});

export { rateLimitPlugin };
