// ============================================================================
// Domain 10: Mobile Routes — Quick Claim, Patient, Summary, Sync Placeholder
// 5 endpoints: quick claim entry, mobile patient creation, recent patients,
// mobile summary KPIs, and Phase 2 sync placeholder (501).
// All require authentication except the sync placeholder.
// ============================================================================

import { type FastifyInstance, type FastifyRequest, type FastifyReply } from 'fastify';
import { z } from 'zod';
import {
  quickClaimSchema,
  mobilePatientSchema,
  type QuickClaim,
  type MobilePatient,
} from '@meritum/shared/schemas/validation/mobile.validation.js';
import { SYNC_ENDPOINT } from '@meritum/shared/constants/mobile.constants.js';
import { AppError } from '../../../lib/errors.js';
import type { QuickClaimServiceDeps } from '../services/quick-claim.service.js';
import type { MobileSummaryServiceDeps } from '../services/mobile-summary.service.js';
import {
  createQuickClaim,
  createMinimalPatient,
  getRecentPatients,
} from '../services/quick-claim.service.js';
import { getSummary, resetAuditRateLimiter } from '../services/mobile-summary.service.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface MobileRouteDeps {
  quickClaimServiceDeps: QuickClaimServiceDeps;
  summaryServiceDeps: MobileSummaryServiceDeps;
}

// ---------------------------------------------------------------------------
// Query schema for recent patients
// ---------------------------------------------------------------------------

const recentPatientsQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(20).default(20),
});

type RecentPatientsQuery = z.infer<typeof recentPatientsQuerySchema>;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getProviderId(request: FastifyRequest): string {
  const ctx = request.authContext;
  if (ctx.role?.toUpperCase() === 'DELEGATE' && (ctx as any).delegateContext) {
    return (ctx as any).delegateContext.physicianProviderId;
  }
  return ctx.userId;
}

function handleAppError(err: unknown, reply: FastifyReply): FastifyReply {
  if (err instanceof AppError) {
    const message = err.statusCode === 404 ? 'Resource not found' : err.message;
    return reply.code(err.statusCode).send({
      error: { code: err.code, message },
    });
  }
  throw err;
}

// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

export async function mobileRoutes(
  app: FastifyInstance,
  opts: { deps: MobileRouteDeps },
) {
  const { quickClaimServiceDeps, summaryServiceDeps } = opts.deps;

  // =========================================================================
  // POST /api/v1/mobile/quick-claim — create draft AHCIP claim from mobile
  // =========================================================================

  app.post('/api/v1/mobile/quick-claim', {
    schema: { body: quickClaimSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_CREATE')],
    handler: async (
      request: FastifyRequest<{ Body: QuickClaim }>,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);
      const body = request.body;

      try {
        const result = await createQuickClaim(
          quickClaimServiceDeps,
          providerId,
          {
            patientId: body.patient_id,
            healthServiceCode: body.health_service_code,
            modifiers: body.modifiers,
            dateOfService: body.date_of_service,
          },
        );

        return reply.code(201).send({ data: result });
      } catch (err) {
        return handleAppError(err, reply);
      }
    },
  });

  // =========================================================================
  // POST /api/v1/mobile/patients — create minimal patient from mobile
  // =========================================================================

  app.post('/api/v1/mobile/patients', {
    schema: { body: mobilePatientSchema },
    preHandler: [app.authenticate, app.authorize('PATIENT_CREATE')],
    handler: async (
      request: FastifyRequest<{ Body: MobilePatient }>,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);
      const body = request.body;

      try {
        const result = await createMinimalPatient(
          quickClaimServiceDeps,
          providerId,
          {
            firstName: body.first_name,
            lastName: body.last_name,
            phn: body.phn,
            dateOfBirth: body.date_of_birth,
            gender: body.gender,
          },
        );

        return reply.code(201).send({ data: result });
      } catch (err) {
        return handleAppError(err, reply);
      }
    },
  });

  // =========================================================================
  // GET /api/v1/mobile/recent-patients — recent patients for quick entry
  // =========================================================================

  app.get('/api/v1/mobile/recent-patients', {
    schema: { querystring: recentPatientsQuerySchema },
    preHandler: [app.authenticate, app.authorize('PATIENT_VIEW')],
    handler: async (
      request: FastifyRequest<{ Querystring: RecentPatientsQuery }>,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);
      const { limit } = request.query;

      const data = await getRecentPatients(
        quickClaimServiceDeps,
        providerId,
        limit,
      );

      return reply.code(200).send({ data });
    },
  });

  // =========================================================================
  // GET /api/v1/mobile/summary — lightweight KPI summary for home screen
  // =========================================================================

  app.get('/api/v1/mobile/summary', {
    preHandler: [app.authenticate, app.authorize('CLAIM_VIEW')],
    handler: async (
      request: FastifyRequest,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);

      const data = await getSummary(summaryServiceDeps, providerId);

      return reply.code(200).send({ data });
    },
  });

  // =========================================================================
  // POST /api/v1/sync/claims — Phase 2 placeholder (501 Not Implemented)
  // No authentication required — client may call without valid session
  // when reconnecting after offline period.
  // =========================================================================

  app.post(SYNC_ENDPOINT, {
    handler: async (
      _request: FastifyRequest,
      reply: FastifyReply,
    ) => {
      return reply.code(501).send({
        message: 'Offline sync is not available in this version',
        phase: 2,
      });
    },
  });
}
