// ============================================================================
// Domain 10: ED Shift Routes
// Endpoints for shift management: start, active, end, summary, list,
// patient logging, confirm-inferred, and encounter CRUD within a shift.
// All require authentication. Physician role only (delegates cannot manage shifts).
// ============================================================================

import { type FastifyInstance, type FastifyRequest, type FastifyReply } from 'fastify';
import {
  startShiftSchema,
  mobileShiftIdParamSchema,
  listShiftsQuerySchema,
  logPatientSchema,
  logEncounterSchema,
  encounterIdParamSchema,
  scheduleIdParamSchema,
  type StartShift,
  type MobileShiftIdParam,
  type ListShiftsQuery,
  type LogPatient,
  type LogEncounter,
  type EncounterIdParam,
} from '@meritum/shared/schemas/validation/mobile.validation.js';
import { AppError } from '../../../lib/errors.js';
import type { EdShiftServiceDeps } from '../services/ed-shift.service.js';
import {
  startShift,
  getActiveShift,
  endShift,
  getShiftSummary,
  listShifts,
  logPatient as logPatientService,
} from '../services/ed-shift.service.js';
import type { ShiftScheduleServiceDeps } from '../services/shift-schedule.service.js';
import { createInferredShift } from '../services/shift-schedule.service.js';
import type { EncounterServiceDeps } from '../services/encounter.service.js';
import {
  logEncounter as logEncounterService,
  listEncounters as listEncountersService,
  deleteEncounter as deleteEncounterService,
  PhnValidationError,
} from '../services/encounter.service.js';
import { z } from 'zod';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ShiftRouteDeps {
  serviceDeps: EdShiftServiceDeps;
  scheduleDeps?: ShiftScheduleServiceDeps;
  encounterDeps?: EncounterServiceDeps;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getProviderId(request: FastifyRequest): string {
  return request.authContext.userId;
}

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
    if (!roles.map((r: string) => r.toUpperCase()).includes(userRole)) {
      reply.code(403).send({
        error: { code: 'FORBIDDEN', message: 'Insufficient permissions' },
      });
      return;
    }
  };
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

export async function shiftRoutes(
  app: FastifyInstance,
  opts: { deps: ShiftRouteDeps },
) {
  const { serviceDeps } = opts.deps;

  // =========================================================================
  // GET /api/v1/shifts/active — must be registered BEFORE /:id routes
  // =========================================================================

  app.get('/api/v1/shifts/active', {
    preHandler: [app.authenticate, requireRole('PHYSICIAN'), app.authorize('CLAIM_VIEW')],
    handler: async (
      request: FastifyRequest,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);
      const shift = await getActiveShift(serviceDeps, providerId);

      if (!shift) {
        return reply.code(204).send();
      }

      return reply.code(200).send({ data: shift });
    },
  });

  // =========================================================================
  // GET /api/v1/shifts — list recent shifts
  // =========================================================================

  app.get('/api/v1/shifts', {
    schema: { querystring: listShiftsQuerySchema },
    preHandler: [app.authenticate, requireRole('PHYSICIAN'), app.authorize('CLAIM_VIEW')],
    handler: async (
      request: FastifyRequest<{ Querystring: ListShiftsQuery }>,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);
      const query = request.query;

      const result = await listShifts(serviceDeps, providerId, {
        limit: query.limit,
        status: query.status,
      });

      return reply.code(200).send({
        data: result.data,
        pagination: {
          total: result.total,
          page: 1,
          pageSize: query.limit,
          hasMore: result.total > query.limit,
        },
      });
    },
  });

  // =========================================================================
  // POST /api/v1/shifts — start new shift
  // =========================================================================

  app.post('/api/v1/shifts', {
    schema: { body: startShiftSchema },
    preHandler: [app.authenticate, requireRole('PHYSICIAN'), app.authorize('CLAIM_CREATE')],
    handler: async (
      request: FastifyRequest<{ Body: StartShift }>,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);
      const body = request.body;

      try {
        const shift = await startShift(serviceDeps, providerId, body.location_id);
        return reply.code(201).send({ data: shift });
      } catch (err) {
        return handleAppError(err, reply);
      }
    },
  });

  // =========================================================================
  // POST /api/v1/shifts/:id/end — end active shift
  // =========================================================================

  app.post('/api/v1/shifts/:id/end', {
    schema: { params: mobileShiftIdParamSchema },
    preHandler: [app.authenticate, requireRole('PHYSICIAN'), app.authorize('CLAIM_CREATE')],
    handler: async (
      request: FastifyRequest<{ Params: MobileShiftIdParam }>,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);
      const { id } = request.params;

      try {
        const result = await endShift(serviceDeps, providerId, id);
        return reply.code(200).send({ data: result });
      } catch (err) {
        return handleAppError(err, reply);
      }
    },
  });

  // =========================================================================
  // GET /api/v1/shifts/:id/summary — shift summary with linked claims
  // =========================================================================

  app.get('/api/v1/shifts/:id/summary', {
    schema: { params: mobileShiftIdParamSchema },
    preHandler: [app.authenticate, requireRole('PHYSICIAN'), app.authorize('CLAIM_VIEW')],
    handler: async (
      request: FastifyRequest<{ Params: MobileShiftIdParam }>,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);
      const { id } = request.params;

      try {
        const summary = await getShiftSummary(serviceDeps, providerId, id);
        return reply.code(200).send({ data: summary });
      } catch (err) {
        return handleAppError(err, reply);
      }
    },
  });

  // =========================================================================
  // POST /api/v1/shifts/:id/patients — log patient encounter in shift
  // =========================================================================

  app.post('/api/v1/shifts/:id/patients', {
    schema: {
      params: mobileShiftIdParamSchema,
      body: logPatientSchema,
    },
    preHandler: [app.authenticate, requireRole('PHYSICIAN'), app.authorize('CLAIM_CREATE')],
    handler: async (
      request: FastifyRequest<{ Params: MobileShiftIdParam; Body: LogPatient }>,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);
      const { id } = request.params;
      const body = request.body;

      try {
        const result = await logPatientService(
          serviceDeps,
          providerId,
          id,
          {
            patientId: body.patient_id,
            healthServiceCode: body.health_service_code,
            modifiers: body.modifiers,
            dateOfService: body.date_of_service,
            quickNote: body.quick_note,
          },
        );

        return reply.code(201).send({
          data: {
            claimId: result.claimId,
            afterHoursEligible: result.afterHours.eligible,
            afterHoursModifier: result.afterHours.modifier,
          },
        });
      } catch (err) {
        return handleAppError(err, reply);
      }
    },
  });

  // =========================================================================
  // GET /api/v1/shifts/:id — get shift details
  // =========================================================================

  app.get('/api/v1/shifts/:id', {
    schema: { params: mobileShiftIdParamSchema },
    preHandler: [app.authenticate, requireRole('PHYSICIAN'), app.authorize('CLAIM_VIEW')],
    handler: async (
      request: FastifyRequest<{ Params: MobileShiftIdParam }>,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);
      const { id } = request.params;

      try {
        const summary = await getShiftSummary(serviceDeps, providerId, id);
        return reply.code(200).send({ data: summary });
      } catch (err) {
        return handleAppError(err, reply);
      }
    },
  });

  // =========================================================================
  // POST /api/v1/shifts/:id/confirm-inferred — confirm an inferred shift
  // =========================================================================

  if (opts.deps.scheduleDeps) {
    const schedDeps = opts.deps.scheduleDeps;

    app.post('/api/v1/shifts/confirm-inferred', {
      schema: { body: z.object({ schedule_id: z.string().uuid() }) },
      preHandler: [app.authenticate, requireRole('PHYSICIAN'), app.authorize('CLAIM_CREATE')],
      handler: async (
        request: FastifyRequest<{ Body: { schedule_id: string } }>,
        reply: FastifyReply,
      ) => {
        const providerId = getProviderId(request);
        const { schedule_id } = request.body;

        try {
          const result = await createInferredShift(schedDeps, providerId, schedule_id);
          return reply.code(201).send({ data: result });
        } catch (err) {
          return handleAppError(err, reply);
        }
      },
    });
  }

  // =========================================================================
  // Encounter routes within shifts (MOB-002 §8.3)
  // =========================================================================

  if (opts.deps.encounterDeps) {
    const encDeps = opts.deps.encounterDeps;

    // POST /api/v1/shifts/:shiftId/encounters — log encounter
    app.post('/api/v1/shifts/:id/encounters', {
      schema: {
        params: mobileShiftIdParamSchema,
        body: logEncounterSchema,
      },
      preHandler: [app.authenticate, requireRole('PHYSICIAN'), app.authorize('CLAIM_CREATE')],
      handler: async (
        request: FastifyRequest<{
          Params: MobileShiftIdParam;
          Body: LogEncounter;
        }>,
        reply: FastifyReply,
      ) => {
        const providerId = getProviderId(request);
        const { id: shiftId } = request.params;
        const body = request.body;

        try {
          const encounter = await logEncounterService(
            encDeps,
            providerId,
            shiftId,
            {
              phn: body.phn,
              phnCaptureMethod: body.phn_capture_method,
              phnIsPartial: body.phn_is_partial,
              healthServiceCode: body.health_service_code,
              modifiers: body.modifiers,
              diCode: body.di_code,
              freeTextTag: body.free_text_tag,
              encounterTimestamp: body.encounter_timestamp,
            },
          );
          return reply.code(201).send({ data: encounter });
        } catch (err) {
          if (err instanceof PhnValidationError) {
            return reply.code(422).send({
              error: { code: 'PHN_VALIDATION_ERROR', message: err.message },
            });
          }
          return handleAppError(err, reply);
        }
      },
    });

    // GET /api/v1/shifts/:shiftId/encounters — list encounters
    app.get('/api/v1/shifts/:id/encounters', {
      schema: { params: mobileShiftIdParamSchema },
      preHandler: [app.authenticate, requireRole('PHYSICIAN'), app.authorize('CLAIM_VIEW')],
      handler: async (
        request: FastifyRequest<{ Params: MobileShiftIdParam }>,
        reply: FastifyReply,
      ) => {
        const providerId = getProviderId(request);
        const { id: shiftId } = request.params;

        const encounters = await listEncountersService(
          encDeps,
          providerId,
          shiftId,
        );
        return reply.code(200).send({ data: encounters });
      },
    });

    // DELETE /api/v1/shifts/:shiftId/encounters/:encounterId
    app.delete('/api/v1/shifts/:id/encounters/:encounterId', {
      schema: {
        params: z.object({
          id: z.string().uuid(),
          encounterId: z.string().uuid(),
        }),
      },
      preHandler: [app.authenticate, requireRole('PHYSICIAN'), app.authorize('CLAIM_CREATE')],
      handler: async (
        request: FastifyRequest<{
          Params: { id: string; encounterId: string };
        }>,
        reply: FastifyReply,
      ) => {
        const providerId = getProviderId(request);
        const { id: shiftId, encounterId } = request.params;

        try {
          await deleteEncounterService(encDeps, providerId, shiftId, encounterId);
          return reply.code(204).send();
        } catch (err) {
          return handleAppError(err, reply);
        }
      },
    });
  }
}
