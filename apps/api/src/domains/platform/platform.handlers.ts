import { type FastifyRequest, type FastifyReply } from 'fastify';
import {
  type CreateCheckoutSession,
  type CreatePortalSession,
  type AdminSubscriptionQuery,
  type CreateIncident,
  type UpdateIncident,
  type UpdateComponentStatus,
  type IncidentHistoryQuery,
} from '@meritum/shared/schemas/platform.schema.js';
import {
  createCheckoutSession,
  createPortalSession,
  processWebhookEvent,
  getSubscriptionStatus,
  getStatusPage,
  getIncidentHistory,
  createIncident,
  updateIncident,
  updateComponentStatus,
  type PlatformServiceDeps,
  type PlatformEventEmitter,
} from './platform.service.js';

// ---------------------------------------------------------------------------
// Handler dependencies
// ---------------------------------------------------------------------------

export interface PlatformHandlerDeps {
  serviceDeps: PlatformServiceDeps;
  eventEmitter?: PlatformEventEmitter;
}

// ---------------------------------------------------------------------------
// Handler factory
// ---------------------------------------------------------------------------

export function createPlatformHandlers(deps: PlatformHandlerDeps) {
  // -------------------------------------------------------------------------
  // POST /api/v1/webhooks/stripe — Stripe webhook (no auth, signature only)
  // -------------------------------------------------------------------------

  async function stripeWebhookHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const rawBody = request.stripeRawBody;
    if (!rawBody) {
      return reply.code(400).send({
        error: { code: 'WEBHOOK_ERROR', message: 'Invalid webhook request' },
      });
    }

    const signature = request.headers['stripe-signature'] as string | undefined;
    if (!signature) {
      return reply.code(400).send({
        error: { code: 'WEBHOOK_ERROR', message: 'Invalid webhook request' },
      });
    }

    const result = await processWebhookEvent(
      deps.serviceDeps,
      rawBody,
      signature,
      deps.eventEmitter,
    );

    return reply.code(200).send({ data: result });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/subscriptions/checkout — Create checkout session
  // -------------------------------------------------------------------------

  async function createCheckoutHandler(
    request: FastifyRequest<{ Body: CreateCheckoutSession }>,
    reply: FastifyReply,
  ) {
    const result = await createCheckoutSession(
      deps.serviceDeps,
      request.authContext.userId,
      request.body.plan,
      request.body.success_url,
      request.body.cancel_url,
    );

    return reply.code(200).send({ data: result });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/subscriptions/portal — Create portal session
  // -------------------------------------------------------------------------

  async function createPortalHandler(
    request: FastifyRequest<{ Body: CreatePortalSession }>,
    reply: FastifyReply,
  ) {
    const result = await createPortalSession(
      deps.serviceDeps,
      request.authContext.userId,
      request.body.return_url,
    );

    return reply.code(200).send({ data: result });
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/subscriptions/current — Get current subscription
  // -------------------------------------------------------------------------

  async function getCurrentSubscriptionHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const result = await getSubscriptionStatus(
      deps.serviceDeps,
      request.authContext.userId,
    );

    return reply.code(200).send({ data: result });
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/subscriptions/payments — List payment history
  // -------------------------------------------------------------------------

  async function listPaymentsHandler(
    request: FastifyRequest<{
      Querystring: { page?: number; page_size?: number };
    }>,
    reply: FastifyReply,
  ) {
    const page = request.query.page ?? 1;
    const pageSize = request.query.page_size ?? 20;

    // Find the user's subscription first
    const subscription =
      await deps.serviceDeps.subscriptionRepo.findSubscriptionByProviderId(
        request.authContext.userId,
      );

    if (!subscription) {
      return reply.code(200).send({
        data: [],
        pagination: { total: 0, page, pageSize, hasMore: false },
      });
    }

    const result =
      await deps.serviceDeps.paymentRepo.listPaymentsForSubscription(
        subscription.subscriptionId,
        { page, pageSize },
      );

    // Strip Stripe internal IDs from physician-facing payment responses
    const sanitisedPayments = result.data.map((p: any) => ({
      paymentId: p.paymentId,
      subscriptionId: p.subscriptionId,
      amountCad: p.amountCad,
      gstAmount: p.gstAmount,
      totalCad: p.totalCad,
      status: p.status,
      paidAt: p.paidAt,
      createdAt: p.createdAt,
    }));

    return reply.code(200).send({
      data: sanitisedPayments,
      pagination: {
        total: result.total,
        page,
        pageSize,
        hasMore: page * pageSize < result.total,
      },
    });
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/admin/subscriptions — List all subscriptions (admin)
  // -------------------------------------------------------------------------

  async function listAllSubscriptionsHandler(
    request: FastifyRequest<{ Querystring: AdminSubscriptionQuery }>,
    reply: FastifyReply,
  ) {
    // Admin endpoint: list all subscriptions with optional status filter
    // We need a method on the repo for this — use findAll pattern
    const query = request.query;
    const page = query.page ?? 1;
    const pageSize = query.page_size ?? 50;

    const result =
      await deps.serviceDeps.subscriptionRepo.findAllSubscriptions({
        status: query.status,
        page,
        pageSize,
      });

    return reply.code(200).send({
      data: result.data,
      pagination: {
        total: result.total,
        page,
        pageSize,
        hasMore: page * pageSize < result.total,
      },
    });
  }

  // -------------------------------------------------------------------------
  // PATCH /api/v1/admin/subscriptions/:id/status — Admin update status
  // -------------------------------------------------------------------------

  async function adminUpdateStatusHandler(
    request: FastifyRequest<{
      Params: { id: string };
      Body: { status: string };
    }>,
    reply: FastifyReply,
  ) {
    const result =
      await deps.serviceDeps.subscriptionRepo.updateSubscriptionStatus(
        request.params.id,
        request.body.status,
      );

    if (!result) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    return reply.code(200).send({ data: result });
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/status — Public status page
  // -------------------------------------------------------------------------

  async function getStatusPageHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const result = await getStatusPage(deps.serviceDeps);
    return reply.code(200).send({ data: result });
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/status/incidents — Public incident history
  // -------------------------------------------------------------------------

  async function getIncidentHistoryHandler(
    request: FastifyRequest<{ Querystring: IncidentHistoryQuery }>,
    reply: FastifyReply,
  ) {
    const page = request.query.page ?? 1;
    const pageSize = request.query.page_size ?? 20;
    const result = await getIncidentHistory(deps.serviceDeps, page, pageSize);
    return reply.code(200).send(result);
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/status/incidents/:id — Public incident detail
  // -------------------------------------------------------------------------

  async function getIncidentDetailHandler(
    request: FastifyRequest<{ Params: { id: string } }>,
    reply: FastifyReply,
  ) {
    const incident = await deps.serviceDeps.incidentRepo.findIncidentById(
      request.params.id,
    );

    if (!incident) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    return reply.code(200).send({
      data: {
        incidentId: incident.incidentId,
        title: incident.title,
        status: incident.status,
        severity: incident.severity,
        affectedComponents: incident.affectedComponents,
        createdAt: incident.createdAt,
        updatedAt: incident.updatedAt,
        resolvedAt: incident.resolvedAt ?? null,
        updates: incident.updates.map((u) => ({
          updateId: u.updateId,
          status: u.status,
          message: u.message,
          createdAt: u.createdAt,
        })),
      },
    });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/admin/incidents — Create incident (admin only)
  // -------------------------------------------------------------------------

  async function createIncidentHandler(
    request: FastifyRequest<{ Body: CreateIncident }>,
    reply: FastifyReply,
  ) {
    const result = await createIncident(
      deps.serviceDeps,
      request.authContext.userId,
      request.body,
      deps.eventEmitter,
    );

    return reply.code(201).send({ data: result });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/admin/incidents/:id/updates — Update incident (admin only)
  // -------------------------------------------------------------------------

  async function updateIncidentHandler(
    request: FastifyRequest<{
      Params: { id: string };
      Body: UpdateIncident;
    }>,
    reply: FastifyReply,
  ) {
    const result = await updateIncident(
      deps.serviceDeps,
      request.authContext.userId,
      request.params.id,
      request.body.status.toUpperCase(),
      request.body.message,
      deps.eventEmitter,
    );

    return reply.code(200).send({ data: result });
  }

  // -------------------------------------------------------------------------
  // PATCH /api/v1/admin/components/:id/status — Update component (admin only)
  // -------------------------------------------------------------------------

  async function updateComponentStatusHandler(
    request: FastifyRequest<{
      Params: { id: string };
      Body: UpdateComponentStatus;
    }>,
    reply: FastifyReply,
  ) {
    const result = await updateComponentStatus(
      deps.serviceDeps,
      request.authContext.userId,
      request.params.id,
      request.body.status,
    );

    return reply.code(200).send({ data: result });
  }

  return {
    stripeWebhookHandler,
    createCheckoutHandler,
    createPortalHandler,
    getCurrentSubscriptionHandler,
    listPaymentsHandler,
    listAllSubscriptionsHandler,
    adminUpdateStatusHandler,
    getStatusPageHandler,
    getIncidentHistoryHandler,
    getIncidentDetailHandler,
    createIncidentHandler,
    updateIncidentHandler,
    updateComponentStatusHandler,
  };
}
