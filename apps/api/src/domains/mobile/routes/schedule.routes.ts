// ============================================================================
// Domain 10: Shift Schedule Routes (MOB-002 §8.1)
// 5 endpoints for schedule management: list, create, get calendar,
// update, and delete shift schedules.
// All require authentication. Physician role only.
// ============================================================================

import { type FastifyInstance, type FastifyRequest, type FastifyReply } from 'fastify';
import {
  createShiftScheduleSchema,
  updateShiftScheduleSchema,
  scheduleIdParamSchema,
  type CreateShiftSchedule,
  type UpdateShiftSchedule,
  type ScheduleIdParam,
} from '@meritum/shared/schemas/validation/mobile.validation.js';
import { AppError } from '../../../lib/errors.js';
import type { ShiftScheduleServiceDeps } from '../services/shift-schedule.service.js';
import {
  createSchedule,
  updateSchedule,
  deleteSchedule,
  listSchedules,
  getCalendarInstances,
} from '../services/shift-schedule.service.js';
import { z } from 'zod';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ScheduleRouteDeps {
  serviceDeps: ShiftScheduleServiceDeps;
}

// ---------------------------------------------------------------------------
// Query schemas
// ---------------------------------------------------------------------------

const calendarQuerySchema = z.object({
  from: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'Must be YYYY-MM-DD'),
  to: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'Must be YYYY-MM-DD'),
});

type CalendarQuery = z.infer<typeof calendarQuerySchema>;

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

export async function scheduleRoutes(
  app: FastifyInstance,
  opts: { deps: ScheduleRouteDeps },
) {
  const { serviceDeps } = opts.deps;

  // =========================================================================
  // GET /api/v1/mobile/schedules/calendar — must be BEFORE /:id
  // =========================================================================

  app.get('/api/v1/mobile/schedules/calendar', {
    schema: { querystring: calendarQuerySchema },
    preHandler: [app.authenticate, requireRole('PHYSICIAN'), app.authorize('CLAIM_VIEW')],
    handler: async (
      request: FastifyRequest<{ Querystring: CalendarQuery }>,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);
      const { from, to } = request.query;

      const fromDate = new Date(from + 'T00:00:00');
      const toDate = new Date(to + 'T23:59:59');

      const instances = await getCalendarInstances(
        serviceDeps,
        providerId,
        fromDate,
        toDate,
      );

      return reply.code(200).send({ data: instances });
    },
  });

  // =========================================================================
  // GET /api/v1/mobile/schedules — list all schedules
  // =========================================================================

  app.get('/api/v1/mobile/schedules', {
    preHandler: [app.authenticate, requireRole('PHYSICIAN'), app.authorize('CLAIM_VIEW')],
    handler: async (
      request: FastifyRequest,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);
      const schedules = await listSchedules(serviceDeps, providerId);
      return reply.code(200).send({ data: schedules });
    },
  });

  // =========================================================================
  // POST /api/v1/mobile/schedules — create new schedule
  // =========================================================================

  app.post('/api/v1/mobile/schedules', {
    schema: { body: createShiftScheduleSchema },
    preHandler: [app.authenticate, requireRole('PHYSICIAN'), app.authorize('CLAIM_CREATE')],
    handler: async (
      request: FastifyRequest<{ Body: CreateShiftSchedule }>,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);
      const body = request.body;

      try {
        const schedule = await createSchedule(serviceDeps, providerId, {
          locationId: body.location_id,
          name: body.name,
          rrule: body.rrule,
          shiftStartTime: body.shift_start_time,
          shiftDurationMinutes: body.shift_duration_minutes,
        });
        return reply.code(201).send({ data: schedule });
      } catch (err) {
        return handleAppError(err, reply);
      }
    },
  });

  // =========================================================================
  // PUT /api/v1/mobile/schedules/:id — update schedule
  // =========================================================================

  app.put('/api/v1/mobile/schedules/:id', {
    schema: {
      params: scheduleIdParamSchema,
      body: updateShiftScheduleSchema,
    },
    preHandler: [app.authenticate, requireRole('PHYSICIAN'), app.authorize('CLAIM_CREATE')],
    handler: async (
      request: FastifyRequest<{
        Params: ScheduleIdParam;
        Body: UpdateShiftSchedule;
      }>,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);
      const { id } = request.params;
      const body = request.body;

      try {
        const schedule = await updateSchedule(serviceDeps, providerId, id, {
          name: body.name,
          rrule: body.rrule,
          shiftStartTime: body.shift_start_time,
          shiftDurationMinutes: body.shift_duration_minutes,
          isActive: body.is_active,
        });
        return reply.code(200).send({ data: schedule });
      } catch (err) {
        return handleAppError(err, reply);
      }
    },
  });

  // =========================================================================
  // DELETE /api/v1/mobile/schedules/:id — deactivate schedule
  // =========================================================================

  app.delete('/api/v1/mobile/schedules/:id', {
    schema: { params: scheduleIdParamSchema },
    preHandler: [app.authenticate, requireRole('PHYSICIAN'), app.authorize('CLAIM_CREATE')],
    handler: async (
      request: FastifyRequest<{ Params: ScheduleIdParam }>,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);
      const { id } = request.params;

      try {
        await deleteSchedule(serviceDeps, providerId, id);
        return reply.code(204).send();
      } catch (err) {
        return handleAppError(err, reply);
      }
    },
  });
}
