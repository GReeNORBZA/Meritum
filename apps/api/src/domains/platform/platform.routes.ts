import { type FastifyInstance } from 'fastify';
import {
  createCheckoutSessionSchema,
  createPortalSessionSchema,
  adminSubscriptionQuerySchema,
  incidentHistoryQuerySchema,
  createIncidentSchema,
  updateIncidentSchema,
  updateComponentStatusSchema,
} from '@meritum/shared/schemas/platform.schema.js';
import { z } from 'zod';
import {
  createPlatformHandlers,
  type PlatformHandlerDeps,
} from './platform.handlers.js';

// ---------------------------------------------------------------------------
// Pagination query schema for payment history
// ---------------------------------------------------------------------------

const paymentHistoryQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  page_size: z.coerce.number().int().min(1).max(50).default(20),
});

// ---------------------------------------------------------------------------
// Admin update subscription status schema
// ---------------------------------------------------------------------------

const adminUpdateStatusParamsSchema = z.object({
  id: z.string().uuid(),
});

const adminUpdateStatusBodySchema = z.object({
  status: z.string().min(1),
});

// ---------------------------------------------------------------------------
// Role-checking preHandler helpers
// ---------------------------------------------------------------------------

function requireRole(...roles: string[]) {
  return async function requireRoleHandler(request: any, reply: any) {
    const ctx = request.authContext;
    if (!ctx) {
      reply.code(401).send({
        error: { code: 'UNAUTHORIZED', message: 'Authentication required' },
      });
      return;
    }
    const userRole = ctx.role?.toUpperCase();
    if (!roles.map((r) => r.toUpperCase()).includes(userRole)) {
      reply.code(403).send({
        error: { code: 'FORBIDDEN', message: 'Insufficient permissions' },
      });
      return;
    }
  };
}

// ---------------------------------------------------------------------------
// Platform Routes
// ---------------------------------------------------------------------------

export async function platformRoutes(
  app: FastifyInstance,
  opts: { deps: PlatformHandlerDeps },
) {
  const handlers = createPlatformHandlers(opts.deps);

  // =========================================================================
  // Webhook route — NO auth middleware, Stripe signature verification only
  // =========================================================================

  app.post('/api/v1/webhooks/stripe', {
    preHandler: [app.verifyStripeWebhook],
    handler: handlers.stripeWebhookHandler,
  });

  // =========================================================================
  // Subscription routes — auth required, physician role only
  // =========================================================================

  app.post('/api/v1/subscriptions/checkout', {
    schema: { body: createCheckoutSessionSchema },
    preHandler: [app.authenticate, requireRole('PHYSICIAN')],
    handler: handlers.createCheckoutHandler,
  });

  app.post('/api/v1/subscriptions/portal', {
    schema: { body: createPortalSessionSchema },
    preHandler: [app.authenticate, requireRole('PHYSICIAN')],
    handler: handlers.createPortalHandler,
  });

  app.get('/api/v1/subscriptions/current', {
    preHandler: [app.authenticate, requireRole('PHYSICIAN')],
    handler: handlers.getCurrentSubscriptionHandler,
  });

  app.get('/api/v1/subscriptions/payments', {
    schema: { querystring: paymentHistoryQuerySchema },
    preHandler: [app.authenticate, requireRole('PHYSICIAN')],
    handler: handlers.listPaymentsHandler,
  });

  // =========================================================================
  // Admin routes — auth required, admin role only
  // =========================================================================

  app.get('/api/v1/admin/subscriptions', {
    schema: { querystring: adminSubscriptionQuerySchema },
    preHandler: [app.authenticate, requireRole('ADMIN')],
    handler: handlers.listAllSubscriptionsHandler,
  });

  app.patch('/api/v1/admin/subscriptions/:id/status', {
    schema: {
      params: adminUpdateStatusParamsSchema,
      body: adminUpdateStatusBodySchema,
    },
    preHandler: [app.authenticate, requireRole('ADMIN')],
    handler: handlers.adminUpdateStatusHandler,
  });

  // =========================================================================
  // Public status page routes — NO auth required
  // =========================================================================

  app.get('/api/v1/status', {
    handler: handlers.getStatusPageHandler,
  });

  app.get('/api/v1/status/incidents', {
    schema: { querystring: incidentHistoryQuerySchema },
    handler: handlers.getIncidentHistoryHandler,
  });

  app.get('/api/v1/status/incidents/:id', {
    schema: { params: z.object({ id: z.string().uuid() }) },
    handler: handlers.getIncidentDetailHandler,
  });

  // =========================================================================
  // Admin incident management routes — auth required, admin role only
  // =========================================================================

  app.post('/api/v1/admin/incidents', {
    schema: { body: createIncidentSchema },
    preHandler: [app.authenticate, requireRole('ADMIN')],
    handler: handlers.createIncidentHandler,
  });

  app.post('/api/v1/admin/incidents/:id/updates', {
    schema: {
      params: z.object({ id: z.string().uuid() }),
      body: updateIncidentSchema,
    },
    preHandler: [app.authenticate, requireRole('ADMIN')],
    handler: handlers.updateIncidentHandler,
  });

  app.patch('/api/v1/admin/components/:id/status', {
    schema: {
      params: z.object({ id: z.string().uuid() }),
      body: updateComponentStatusSchema,
    },
    preHandler: [app.authenticate, requireRole('ADMIN')],
    handler: handlers.updateComponentStatusHandler,
  });
}
