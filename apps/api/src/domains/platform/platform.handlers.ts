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
  type CreateAmendment,
  type AmendmentResponse,
  type AmendmentIdParam,
  type ListAmendmentsQuery,
  type CreateBreach,
  type BreachIdParam,
  type BreachUpdate,
  type ListBreachesQuery,
} from '@meritum/shared/schemas/compliance.schema.js';
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
  createAmendment,
  acknowledgeAmendment,
  respondToAmendment,
  getBlockingAmendments,
  createBreach,
  sendBreachNotifications,
  addBreachUpdate,
  resolveBreach,
  markBackupPurged,
  type PlatformServiceDeps,
  type PlatformEventEmitter,
} from './platform.service.js';
import {
  handleCancellation,
  type CancellationServiceDeps,
} from './cancellation.service.js';
import {
  generateFullHiExport,
  type FullHiExportDeps,
} from './export.service.js';
import { type FullHiExport } from '@meritum/shared/schemas/compliance.schema.js';

// ---------------------------------------------------------------------------
// Handler dependencies
// ---------------------------------------------------------------------------

export interface PlatformHandlerDeps {
  serviceDeps: PlatformServiceDeps;
  eventEmitter?: PlatformEventEmitter;
  exportDeps?: FullHiExportDeps;
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

  // -------------------------------------------------------------------------
  // POST /api/v1/subscriptions/cancel — Cancel subscription (physician)
  // -------------------------------------------------------------------------

  async function cancelSubscriptionHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const cancellationDeps: CancellationServiceDeps = {
      subscriptionRepo: deps.serviceDeps.subscriptionRepo,
      paymentRepo: deps.serviceDeps.paymentRepo,
      stripe: deps.serviceDeps.stripe as any,
    };

    const result = await handleCancellation(
      cancellationDeps,
      request.authContext.userId,
    );

    return reply.code(200).send({ data: result });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/platform/amendments — Create amendment (admin only)
  // -------------------------------------------------------------------------

  async function createAmendmentHandler(
    request: FastifyRequest<{ Body: CreateAmendment }>,
    reply: FastifyReply,
  ) {
    const result = await createAmendment(
      deps.serviceDeps,
      {
        userId: request.authContext.userId,
        role: request.authContext.role,
      },
      {
        amendmentType: request.body.amendment_type,
        title: request.body.title,
        description: request.body.description,
        documentText: request.body.document_text,
        effectiveDate: new Date(request.body.effective_date),
      },
      deps.eventEmitter,
    );

    return reply.code(201).send({ data: result });
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/platform/amendments — List amendments (admin only)
  // -------------------------------------------------------------------------

  async function listAmendmentsHandler(
    request: FastifyRequest<{ Querystring: ListAmendmentsQuery }>,
    reply: FastifyReply,
  ) {
    if (!deps.serviceDeps.amendmentRepo) {
      return reply.code(200).send({
        data: [],
        pagination: { total: 0, page: 1, pageSize: 50, hasMore: false },
      });
    }

    const page = request.query.page ?? 1;
    const pageSize = request.query.page_size ?? 50;

    const result = await deps.serviceDeps.amendmentRepo.listAmendments({
      status: request.query.status,
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
  // GET /api/v1/platform/amendments/:id — Get amendment (admin only)
  // -------------------------------------------------------------------------

  async function getAmendmentHandler(
    request: FastifyRequest<{ Params: AmendmentIdParam }>,
    reply: FastifyReply,
  ) {
    if (!deps.serviceDeps.amendmentRepo) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    const amendment = await deps.serviceDeps.amendmentRepo.findAmendmentById(
      request.params.id,
    );

    if (!amendment) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    return reply.code(200).send({ data: amendment });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/platform/amendments/:id/acknowledge — Acknowledge (physician)
  // -------------------------------------------------------------------------

  async function acknowledgeAmendmentHandler(
    request: FastifyRequest<{ Params: AmendmentIdParam }>,
    reply: FastifyReply,
  ) {
    await acknowledgeAmendment(
      deps.serviceDeps,
      {
        userId: request.authContext.userId,
        providerId: request.authContext.userId,
        ipAddress: request.ip,
        userAgent: request.headers['user-agent'] ?? '',
      },
      request.params.id,
      deps.eventEmitter,
    );

    return reply.code(200).send({ data: { acknowledged: true } });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/platform/amendments/:id/respond — Respond (physician)
  // -------------------------------------------------------------------------

  async function respondToAmendmentHandler(
    request: FastifyRequest<{
      Params: AmendmentIdParam;
      Body: AmendmentResponse;
    }>,
    reply: FastifyReply,
  ) {
    const responseType = request.body.response_type as 'ACCEPTED' | 'REJECTED';

    await respondToAmendment(
      deps.serviceDeps,
      {
        userId: request.authContext.userId,
        providerId: request.authContext.userId,
        ipAddress: request.ip,
        userAgent: request.headers['user-agent'] ?? '',
      },
      request.params.id,
      responseType,
      deps.eventEmitter,
    );

    return reply.code(200).send({ data: { responded: true, responseType } });
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/account/pending-amendments — Physician pending amendments
  // -------------------------------------------------------------------------

  async function getMyPendingAmendmentsHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const blocking = await getBlockingAmendments(
      deps.serviceDeps,
      request.authContext.userId,
    );

    // Also include MATERIAL pending amendments (not just blocking NON_MATERIAL)
    let allPending: Array<{
      amendmentId: string;
      title: string;
      effectiveDate: Date;
      amendmentType?: string;
    }> = [];

    if (deps.serviceDeps.amendmentRepo) {
      const pending =
        await deps.serviceDeps.amendmentRepo.findPendingAmendmentsForProvider(
          request.authContext.userId,
        );
      allPending = pending.map((a) => ({
        amendmentId: a.amendmentId,
        title: a.title,
        effectiveDate: a.effectiveDate,
        amendmentType: a.amendmentType,
      }));
    }

    return reply.code(200).send({ data: allPending });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/platform/breaches — Create breach (admin only)
  // -------------------------------------------------------------------------

  async function createBreachHandler(
    request: FastifyRequest<{ Body: CreateBreach }>,
    reply: FastifyReply,
  ) {
    const result = await createBreach(
      deps.serviceDeps,
      {
        userId: request.authContext.userId,
        role: request.authContext.role,
      },
      {
        breachDescription: request.body.breach_description,
        breachDate: new Date(request.body.breach_date),
        awarenessDate: new Date(request.body.awareness_date),
        hiDescription: request.body.hi_description,
        includesIihi: request.body.includes_iihi,
        affectedCount: request.body.affected_count,
        riskAssessment: request.body.risk_assessment,
        mitigationSteps: request.body.mitigation_steps,
        contactName: request.body.contact_name,
        contactEmail: request.body.contact_email,
        affectedProviderIds: request.body.affected_provider_ids,
      },
      deps.eventEmitter,
    );

    return reply.code(201).send({ data: result });
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/platform/breaches — List breaches (admin only)
  // -------------------------------------------------------------------------

  async function listBreachesHandler(
    request: FastifyRequest<{ Querystring: ListBreachesQuery }>,
    reply: FastifyReply,
  ) {
    if (!deps.serviceDeps.breachRepo) {
      return reply.code(200).send({
        data: [],
        pagination: { total: 0, page: 1, pageSize: 50, hasMore: false },
      });
    }

    const page = request.query.page ?? 1;
    const pageSize = request.query.page_size ?? 50;

    const result = await deps.serviceDeps.breachRepo.listBreaches({
      status: request.query.status,
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
  // GET /api/v1/platform/breaches/:id — Get breach (admin only)
  // -------------------------------------------------------------------------

  async function getBreachHandler(
    request: FastifyRequest<{ Params: BreachIdParam }>,
    reply: FastifyReply,
  ) {
    if (!deps.serviceDeps.breachRepo) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    const breach = await deps.serviceDeps.breachRepo.findBreachById(
      request.params.id,
    );

    if (!breach) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    return reply.code(200).send({ data: breach });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/platform/breaches/:id/notify — Send notifications (admin)
  // -------------------------------------------------------------------------

  async function sendBreachNotificationsHandler(
    request: FastifyRequest<{ Params: BreachIdParam }>,
    reply: FastifyReply,
  ) {
    const result = await sendBreachNotifications(
      deps.serviceDeps,
      {
        userId: request.authContext.userId,
        role: request.authContext.role,
      },
      request.params.id,
      deps.eventEmitter,
    );

    return reply.code(200).send({ data: result });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/platform/breaches/:id/updates — Add update (admin only)
  // -------------------------------------------------------------------------

  async function addBreachUpdateHandler(
    request: FastifyRequest<{
      Params: BreachIdParam;
      Body: BreachUpdate;
    }>,
    reply: FastifyReply,
  ) {
    const result = await addBreachUpdate(
      deps.serviceDeps,
      {
        userId: request.authContext.userId,
        role: request.authContext.role,
      },
      request.params.id,
      request.body.content,
      deps.eventEmitter,
    );

    return reply.code(201).send({ data: result });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/platform/breaches/:id/resolve — Resolve breach (admin)
  // -------------------------------------------------------------------------

  async function resolveBreachHandler(
    request: FastifyRequest<{ Params: BreachIdParam }>,
    reply: FastifyReply,
  ) {
    const result = await resolveBreach(
      deps.serviceDeps,
      {
        userId: request.authContext.userId,
        role: request.authContext.role,
      },
      request.params.id,
      deps.eventEmitter,
    );

    return reply.code(200).send({ data: result });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/platform/export/full — Full HI export (physician)
  // -------------------------------------------------------------------------

  async function generateFullExportHandler(
    request: FastifyRequest<{ Body: FullHiExport }>,
    reply: FastifyReply,
  ) {
    if (!deps.exportDeps) {
      return reply.code(500).send({
        error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
      });
    }

    const format = request.body.format ?? 'csv';
    const ctx = {
      userId: request.authContext.userId,
      providerId: request.authContext.userId,
    };

    const result = await generateFullHiExport(deps.exportDeps, ctx, format);

    return reply.code(202).send({ data: result });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/admin/destruction/:providerId/backup-purged — IMA-060
  // -------------------------------------------------------------------------

  async function markBackupPurgedHandler(
    request: FastifyRequest<{ Params: { providerId: string } }>,
    reply: FastifyReply,
  ) {
    const result = await markBackupPurged(
      deps.serviceDeps,
      {
        userId: request.authContext.userId,
        role: request.authContext.role,
      },
      request.params.providerId,
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
    cancelSubscriptionHandler,
    createAmendmentHandler,
    listAmendmentsHandler,
    getAmendmentHandler,
    acknowledgeAmendmentHandler,
    respondToAmendmentHandler,
    getMyPendingAmendmentsHandler,
    createBreachHandler,
    listBreachesHandler,
    getBreachHandler,
    sendBreachNotificationsHandler,
    addBreachUpdateHandler,
    resolveBreachHandler,
    generateFullExportHandler,
    markBackupPurgedHandler,
  };
}
