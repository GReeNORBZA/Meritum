import { type FastifyRequest, type FastifyReply } from 'fastify';
import {
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
// Handler factory
// ---------------------------------------------------------------------------

export function createPracticeHandlers(deps: PracticeHandlerDeps) {
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
  // GET /api/v1/practices/:id/seats — Get practice seats (ZERO PHI)
  // CRITICAL: Return ONLY what getPracticeSeats() returns.
  // No enrichment with claim data, billing volumes, or any PHI.
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
  // CRITICAL: Response MUST NOT include the raw token.
  // Only: invitationId, invitedEmail, status, expiresAt.
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
