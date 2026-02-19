// ============================================================================
// Domain 8: Subscription Routes
// 4 endpoints for report subscription CRUD.
// All require authentication. Delegates need specific permissions.
// ============================================================================

import { type FastifyInstance, type FastifyRequest, type FastifyReply } from 'fastify';
import {
  createSubscriptionSchema,
  updateSubscriptionSchema,
  subscriptionIdParamSchema,
  type CreateSubscription,
  type UpdateSubscription,
  type SubscriptionIdParam,
} from '@meritum/shared/schemas/validation/analytics.validation.js';
import { AnalyticsAuditAction } from '@meritum/shared/constants/analytics.constants.js';
import type { ReportSubscriptionsRepository } from '../repos/report-subscriptions.repo.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SubscriptionRouteDeps {
  subscriptionsRepo: ReportSubscriptionsRepository;
  auditLog: (entry: {
    action: string;
    providerId: string;
    details: Record<string, unknown>;
  }) => Promise<void>;
}

// ---------------------------------------------------------------------------
// Helper: extract providerId from auth context
// ---------------------------------------------------------------------------

function getProviderId(request: FastifyRequest): string {
  const ctx = request.authContext;
  if (ctx.role?.toUpperCase() === 'DELEGATE' && (ctx as any).delegateContext) {
    return (ctx as any).delegateContext.physicianProviderId;
  }
  return ctx.userId;
}

// ---------------------------------------------------------------------------
// Helper: sanitize subscription for API response
// ---------------------------------------------------------------------------

function sanitizeSubscription(sub: Record<string, any>) {
  return {
    subscription_id: sub.subscriptionId,
    provider_id: sub.providerId,
    report_type: sub.reportType,
    frequency: sub.frequency,
    delivery_method: sub.deliveryMethod,
    is_active: sub.isActive,
    created_at:
      sub.createdAt instanceof Date
        ? sub.createdAt.toISOString()
        : sub.createdAt,
    updated_at:
      sub.updatedAt instanceof Date
        ? sub.updatedAt.toISOString()
        : sub.updatedAt,
  };
}

// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

export async function subscriptionRoutes(
  app: FastifyInstance,
  opts: { deps: SubscriptionRouteDeps },
) {
  const { subscriptionsRepo, auditLog } = opts.deps;

  // =========================================================================
  // GET /api/v1/report-subscriptions
  // List all subscriptions for the authenticated physician.
  // Permission: REPORT_VIEW
  // =========================================================================

  app.get('/api/v1/report-subscriptions', {
    preHandler: [app.authenticate, app.authorize('REPORT_VIEW')],
    handler: async (request: FastifyRequest, reply: FastifyReply) => {
      const providerId = getProviderId(request);

      const subscriptions = await subscriptionsRepo.listByProvider(providerId);

      return reply.code(200).send({
        data: subscriptions.map(sanitizeSubscription),
      });
    },
  });

  // =========================================================================
  // POST /api/v1/report-subscriptions
  // Create a new subscription. 409 if duplicate (provider_id, report_type).
  // Permission: REPORT_EXPORT
  // Audit: SUBSCRIPTION_CREATED
  // =========================================================================

  app.post('/api/v1/report-subscriptions', {
    schema: { body: createSubscriptionSchema },
    preHandler: [app.authenticate, app.authorize('REPORT_EXPORT')],
    handler: async (
      request: FastifyRequest<{ Body: CreateSubscription }>,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);
      const body = request.body;

      try {
        const subscription = await subscriptionsRepo.create({
          providerId,
          reportType: body.report_type,
          frequency: body.frequency,
          deliveryMethod: body.delivery_method,
        });

        auditLog({
          action: AnalyticsAuditAction.SUBSCRIPTION_CREATED,
          providerId,
          details: {
            subscriptionId: subscription.subscriptionId,
            reportType: body.report_type,
            frequency: body.frequency,
            deliveryMethod: body.delivery_method,
          },
        }).catch(() => {});

        return reply.code(201).send({
          data: sanitizeSubscription(subscription),
        });
      } catch (error: any) {
        // Unique constraint violation: (provider_id, report_type)
        if (
          error?.code === '23505' ||
          error?.constraint?.includes('report_subscriptions_provider_report_type')
        ) {
          return reply.code(409).send({
            error: {
              code: 'CONFLICT',
              message: 'Subscription for this report type already exists',
            },
          });
        }
        throw error;
      }
    },
  });

  // =========================================================================
  // PUT /api/v1/report-subscriptions/:id
  // Update subscription fields. 404 if not found or wrong provider.
  // Permission: REPORT_EXPORT
  // Audit: SUBSCRIPTION_UPDATED
  // =========================================================================

  app.put('/api/v1/report-subscriptions/:id', {
    schema: {
      params: subscriptionIdParamSchema,
      body: updateSubscriptionSchema,
    },
    preHandler: [app.authenticate, app.authorize('REPORT_EXPORT')],
    handler: async (
      request: FastifyRequest<{
        Params: SubscriptionIdParam;
        Body: UpdateSubscription;
      }>,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);
      const { id } = request.params;
      const body = request.body;

      const updateData: Record<string, any> = {};
      if (body.frequency !== undefined) updateData.frequency = body.frequency;
      if (body.delivery_method !== undefined)
        updateData.deliveryMethod = body.delivery_method;
      if (body.is_active !== undefined) updateData.isActive = body.is_active;

      const updated = await subscriptionsRepo.update(
        id,
        providerId,
        updateData,
      );

      if (!updated) {
        return reply.code(404).send({
          error: { code: 'NOT_FOUND', message: 'Resource not found' },
        });
      }

      auditLog({
        action: AnalyticsAuditAction.SUBSCRIPTION_UPDATED,
        providerId,
        details: {
          subscriptionId: id,
          changes: body,
        },
      }).catch(() => {});

      return reply.code(200).send({
        data: sanitizeSubscription(updated),
      });
    },
  });

  // =========================================================================
  // DELETE /api/v1/report-subscriptions/:id
  // Cancel (hard delete) a subscription. 404 if not found or wrong provider.
  // Permission: REPORT_EXPORT
  // Audit: SUBSCRIPTION_CANCELLED
  // =========================================================================

  app.delete('/api/v1/report-subscriptions/:id', {
    schema: { params: subscriptionIdParamSchema },
    preHandler: [app.authenticate, app.authorize('REPORT_EXPORT')],
    handler: async (
      request: FastifyRequest<{ Params: SubscriptionIdParam }>,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);
      const { id } = request.params;

      const deleted = await subscriptionsRepo.delete(id, providerId);

      if (!deleted) {
        return reply.code(404).send({
          error: { code: 'NOT_FOUND', message: 'Resource not found' },
        });
      }

      auditLog({
        action: AnalyticsAuditAction.SUBSCRIPTION_CANCELLED,
        providerId,
        details: {
          subscriptionId: id,
        },
      }).catch(() => {});

      return reply.code(204).send();
    },
  });
}
