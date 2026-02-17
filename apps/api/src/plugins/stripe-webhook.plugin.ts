import { type FastifyInstance, type FastifyRequest, type FastifyReply } from 'fastify';
import fp from 'fastify-plugin';
import type { StripeEvent, StripeClient } from '../domains/platform/platform.service.js';

// ---------------------------------------------------------------------------
// Type augmentation: add stripeRawBody and stripeEvent to Fastify request
// ---------------------------------------------------------------------------

declare module 'fastify' {
  interface FastifyRequest {
    stripeRawBody?: string;
    stripeEvent?: StripeEvent;
  }
}

// ---------------------------------------------------------------------------
// Plugin options
// ---------------------------------------------------------------------------

export interface StripeWebhookPluginOptions {
  /**
   * The Stripe webhook endpoint path.
   * Raw body parsing is scoped to this path only.
   */
  webhookPath: string;

  /**
   * Stripe client with webhooks.constructEvent capability.
   */
  stripe: StripeClient;

  /**
   * STRIPE_WEBHOOK_SECRET from environment variables.
   */
  webhookSecret: string;

  /**
   * Max webhook requests per minute. Defaults to 100.
   * Stripe controls call frequency, but a ceiling prevents abuse.
   */
  maxPerMinute?: number;
}

// ---------------------------------------------------------------------------
// Plugin implementation
// ---------------------------------------------------------------------------

async function stripeWebhookPlugin(app: FastifyInstance, opts: StripeWebhookPluginOptions) {
  const { webhookPath, stripe, webhookSecret, maxPerMinute = 100 } = opts;

  // -------------------------------------------------------------------------
  // Raw body capture: add a content type parser for application/json that
  // preserves the raw buffer for requests to the webhook path.
  // We re-register application/json parsing. Fastify allows removing the
  // default parser and replacing it.
  // -------------------------------------------------------------------------

  app.removeContentTypeParser('application/json');
  app.addContentTypeParser(
    'application/json',
    { parseAs: 'buffer' },
    (request: FastifyRequest, body: Buffer, done: (err: Error | null, body?: unknown) => void) => {
      if (request.url === webhookPath || request.url.startsWith(webhookPath + '?')) {
        // Preserve raw body for Stripe signature verification
        request.stripeRawBody = body.toString('utf8');
        try {
          done(null, JSON.parse(request.stripeRawBody));
        } catch (err) {
          done(err as Error);
        }
      } else {
        // Normal JSON parsing for all other routes
        try {
          done(null, JSON.parse(body.toString('utf8')));
        } catch (err) {
          done(err as Error);
        }
      }
    },
  );

  // -------------------------------------------------------------------------
  // Signature verification preHandler
  // -------------------------------------------------------------------------

  app.decorate(
    'verifyStripeWebhook',
    async function verifyStripeWebhook(request: FastifyRequest, reply: FastifyReply) {
      const rawBody = request.stripeRawBody;
      if (!rawBody) {
        reply.code(400).send({
          error: { code: 'WEBHOOK_ERROR', message: 'Invalid webhook request' },
        });
        return;
      }

      const signature = request.headers['stripe-signature'] as string | undefined;
      if (!signature) {
        reply.code(400).send({
          error: { code: 'WEBHOOK_ERROR', message: 'Invalid webhook request' },
        });
        return;
      }

      try {
        const event = stripe.webhooks.constructEvent(rawBody, signature, webhookSecret);
        request.stripeEvent = event;
      } catch {
        reply.code(400).send({
          error: { code: 'WEBHOOK_ERROR', message: 'Invalid webhook request' },
        });
      }
    },
  );

  // -------------------------------------------------------------------------
  // Rate limit config for webhook endpoint
  // -------------------------------------------------------------------------

  app.decorate('webhookRateLimit', function webhookRateLimit() {
    return {
      max: maxPerMinute,
      timeWindow: '1 minute',
      keyGenerator: (request: FastifyRequest) => request.ip,
    };
  });
}

// ---------------------------------------------------------------------------
// Type augmentation for decorators
// ---------------------------------------------------------------------------

declare module 'fastify' {
  interface FastifyInstance {
    verifyStripeWebhook: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
    webhookRateLimit: () => {
      max: number;
      timeWindow: string;
      keyGenerator: (request: FastifyRequest) => string;
    };
  }
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

export const stripeWebhookPluginFp = fp(stripeWebhookPlugin, {
  name: 'stripe-webhook-plugin',
});

export { stripeWebhookPlugin };
