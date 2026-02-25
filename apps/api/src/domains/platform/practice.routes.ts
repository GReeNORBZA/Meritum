import { type FastifyInstance, type FastifyRequest, type FastifyReply } from 'fastify';
import {
  createPracticeSchema,
  updatePracticeSchema,
  invitePhysicianSchema,
  acceptInvitationParamsSchema,
  practiceIdParamsSchema,
  removeSeatParamsSchema,
  practiceSeatsQuerySchema,
  practiceInvoicesQuerySchema,
  type CreatePractice,
  type UpdatePractice,
  type InvitePhysician,
  type AcceptInvitationParams,
  type PracticeIdParams,
  type RemoveSeatParams,
  type PracticeSeatsQuery,
  type PracticeInvoicesQuery,
} from '@meritum/shared/schemas/platform.schema.js';
import {
  createPractice,
  invitePhysician,
  acceptInvitation,
  removePhysician,
  getPracticeSeats,
  getPracticeInvoice,
  type PracticeServiceDeps,
} from './practice.service.js';
import { type PracticeRepository } from './practice.repository.js';

// ---------------------------------------------------------------------------
// Handler dependencies
// ---------------------------------------------------------------------------

export interface PracticeHandlerDeps {
  serviceDeps: PracticeServiceDeps;
  practiceRepo: PracticeRepository;
}

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
// Practice-admin authorization: verifies the authenticated user is the
// admin_user_id for the specified practice. Returns 403 if not.
// ---------------------------------------------------------------------------

function requirePracticeAdmin(practiceRepo: PracticeRepository) {
  return async function requirePracticeAdminHandler(request: any, reply: any) {
    const ctx = request.authContext;
    if (!ctx) {
      reply.code(401).send({
        error: { code: 'UNAUTHORIZED', message: 'Authentication required' },
      });
      return;
    }

    const practiceId = request.params?.id;
    if (!practiceId) {
      reply.code(400).send({
        error: { code: 'VALIDATION_ERROR', message: 'Practice ID is required' },
      });
      return;
    }

    const practice = await practiceRepo.findPracticeById(practiceId);
    if (!practice) {
      reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
      return;
    }

    if (practice.adminUserId !== ctx.userId) {
      reply.code(403).send({
        error: { code: 'FORBIDDEN', message: 'Insufficient permissions' },
      });
      return;
    }
  };
}

// ---------------------------------------------------------------------------
// Handler factory
// ---------------------------------------------------------------------------

function createPracticeHandlers(deps: PracticeHandlerDeps) {
  // -------------------------------------------------------------------------
  // POST /api/v1/practices — Create a new practice
  // -------------------------------------------------------------------------

  async function createPracticeHandler(
    request: FastifyRequest<{ Body: CreatePractice }>,
    reply: FastifyReply,
  ) {
    const result = await createPractice(
      deps.serviceDeps,
      request.authContext.userId,
      request.body.name,
      request.body.billing_frequency,
    );

    return reply.code(201).send({ data: result });
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/practices/:id — Get practice details
  // -------------------------------------------------------------------------

  async function getPracticeHandler(
    request: FastifyRequest<{ Params: PracticeIdParams }>,
    reply: FastifyReply,
  ) {
    const practice = await deps.practiceRepo.findPracticeById(request.params.id);
    if (!practice) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    return reply.code(200).send({ data: practice });
  }

  // -------------------------------------------------------------------------
  // PATCH /api/v1/practices/:id — Update practice
  // -------------------------------------------------------------------------

  async function updatePracticeHandler(
    request: FastifyRequest<{ Params: PracticeIdParams; Body: UpdatePractice }>,
    reply: FastifyReply,
  ) {
    const updated = await deps.practiceRepo.updatePractice(
      request.params.id,
      request.body as any,
    );

    return reply.code(200).send({ data: updated });
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/practices/:id/seats — Get practice seats
  // -------------------------------------------------------------------------

  async function getPracticeSeatsHandler(
    request: FastifyRequest<{
      Params: PracticeIdParams;
      Querystring: PracticeSeatsQuery;
    }>,
    reply: FastifyReply,
  ) {
    const seats = await getPracticeSeats(
      deps.serviceDeps,
      request.params.id,
      request.authContext.userId,
    );

    // Apply pagination
    const page = request.query.page ?? 1;
    const pageSize = request.query.page_size ?? 50;
    const start = (page - 1) * pageSize;
    const paginatedSeats = seats.slice(start, start + pageSize);

    return reply.code(200).send({
      data: paginatedSeats,
      pagination: {
        total: seats.length,
        page,
        pageSize,
        hasMore: start + pageSize < seats.length,
      },
    });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/practices/:id/invitations — Invite physician
  // -------------------------------------------------------------------------

  async function invitePhysicianHandler(
    request: FastifyRequest<{
      Params: PracticeIdParams;
      Body: InvitePhysician;
    }>,
    reply: FastifyReply,
  ) {
    const invitation = await invitePhysician(
      deps.serviceDeps,
      request.params.id,
      request.body.email,
      request.authContext.userId,
    );

    return reply.code(201).send({ data: invitation });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/practice-invitations/:token/accept — Accept invitation
  // -------------------------------------------------------------------------

  async function acceptInvitationHandler(
    request: FastifyRequest<{ Params: AcceptInvitationParams }>,
    reply: FastifyReply,
  ) {
    const membership = await acceptInvitation(
      deps.serviceDeps,
      request.params.token,
      request.authContext.userId,
    );

    return reply.code(200).send({ data: membership });
  }

  // -------------------------------------------------------------------------
  // DELETE /api/v1/practices/:id/seats/:userId — Remove physician
  // -------------------------------------------------------------------------

  async function removePhysicianHandler(
    request: FastifyRequest<{ Params: RemoveSeatParams }>,
    reply: FastifyReply,
  ) {
    await removePhysician(
      deps.serviceDeps,
      request.params.id,
      request.params.userId,
      request.authContext.userId,
    );

    return reply.code(204).send();
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/practices/:id/invoices — Get practice invoices
  // -------------------------------------------------------------------------

  async function getPracticeInvoicesHandler(
    request: FastifyRequest<{
      Params: PracticeIdParams;
      Querystring: PracticeInvoicesQuery;
    }>,
    reply: FastifyReply,
  ) {
    const invoiceInfo = await getPracticeInvoice(
      deps.serviceDeps,
      request.params.id,
      request.authContext.userId,
    );

    return reply.code(200).send({ data: invoiceInfo });
  }

  return {
    createPracticeHandler,
    getPracticeHandler,
    updatePracticeHandler,
    getPracticeSeatsHandler,
    invitePhysicianHandler,
    acceptInvitationHandler,
    removePhysicianHandler,
    getPracticeInvoicesHandler,
  };
}

// ---------------------------------------------------------------------------
// Practice Routes Plugin
// ---------------------------------------------------------------------------

export async function practiceRoutes(
  app: FastifyInstance,
  opts: { deps: PracticeHandlerDeps },
) {
  const handlers = createPracticeHandlers(opts.deps);
  const practiceAdmin = requirePracticeAdmin(opts.deps.practiceRepo);

  // =========================================================================
  // POST /api/v1/practices — Any physician can create a practice
  // =========================================================================

  app.post('/api/v1/practices', {
    schema: { body: createPracticeSchema },
    preHandler: [app.authenticate, requireRole('PHYSICIAN', 'PRACTICE_ADMIN')],
    handler: handlers.createPracticeHandler,
  });

  // =========================================================================
  // GET /api/v1/practices/:id — Practice admin only
  // =========================================================================

  app.get('/api/v1/practices/:id', {
    schema: { params: practiceIdParamsSchema },
    preHandler: [app.authenticate, practiceAdmin],
    handler: handlers.getPracticeHandler,
  });

  // =========================================================================
  // PATCH /api/v1/practices/:id — Practice admin only
  // =========================================================================

  app.patch('/api/v1/practices/:id', {
    schema: {
      params: practiceIdParamsSchema,
      body: updatePracticeSchema,
    },
    preHandler: [app.authenticate, practiceAdmin],
    handler: handlers.updatePracticeHandler,
  });

  // =========================================================================
  // GET /api/v1/practices/:id/seats — Practice admin only
  // =========================================================================

  app.get('/api/v1/practices/:id/seats', {
    schema: {
      params: practiceIdParamsSchema,
      querystring: practiceSeatsQuerySchema,
    },
    preHandler: [app.authenticate, practiceAdmin],
    handler: handlers.getPracticeSeatsHandler,
  });

  // =========================================================================
  // POST /api/v1/practices/:id/invitations — Practice admin only
  // =========================================================================

  app.post('/api/v1/practices/:id/invitations', {
    schema: {
      params: practiceIdParamsSchema,
      body: invitePhysicianSchema,
    },
    preHandler: [app.authenticate, practiceAdmin],
    handler: handlers.invitePhysicianHandler,
  });

  // =========================================================================
  // POST /api/v1/practice-invitations/:token/accept — Physician auth only
  // =========================================================================

  app.post('/api/v1/practice-invitations/:token/accept', {
    schema: { params: acceptInvitationParamsSchema },
    preHandler: [app.authenticate, requireRole('PHYSICIAN', 'PRACTICE_ADMIN')],
    handler: handlers.acceptInvitationHandler,
  });

  // =========================================================================
  // DELETE /api/v1/practices/:id/seats/:userId — Practice admin only
  // =========================================================================

  app.delete('/api/v1/practices/:id/seats/:userId', {
    schema: { params: removeSeatParamsSchema },
    preHandler: [app.authenticate, practiceAdmin],
    handler: handlers.removePhysicianHandler,
  });

  // =========================================================================
  // GET /api/v1/practices/:id/invoices — Practice admin only
  // =========================================================================

  app.get('/api/v1/practices/:id/invoices', {
    schema: {
      params: practiceIdParamsSchema,
      querystring: practiceInvoicesQuerySchema,
    },
    preHandler: [app.authenticate, practiceAdmin],
    handler: handlers.getPracticeInvoicesHandler,
  });
}
