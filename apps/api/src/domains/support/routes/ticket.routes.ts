// ============================================================================
// Domain 13: Support Ticket Routes
// Ticket creation (multipart), listing, detail, rating.
// All endpoints require authentication. Physician scoping enforced.
// ============================================================================

import { type FastifyInstance, type FastifyRequest, type FastifyReply } from 'fastify';
import {
  createTicketSchema,
  ticketListQuerySchema,
  ticketIdParamSchema,
  ticketRatingSchema,
  type CreateTicket,
  type TicketListQuery,
  type TicketIdParam,
  type TicketRating,
} from '@meritum/shared/schemas/validation/support.validation.js';
import { AppError } from '../../../lib/errors.js';
import type { SupportTicketService, ScreenshotFile } from '../services/support-ticket.service.js';

// ---------------------------------------------------------------------------
// Dependencies
// ---------------------------------------------------------------------------

export interface TicketRoutesDeps {
  supportTicketService: SupportTicketService;
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
// Helper: catch AppError and format response
// ---------------------------------------------------------------------------

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
// Helper: strip screenshot_path from response (defense-in-depth)
// ---------------------------------------------------------------------------

function sanitizeTicketResponse(ticket: Record<string, unknown>): Record<string, unknown> {
  const { screenshotPath: _, screenshot_path: __, ...rest } = ticket;
  return rest;
}

function sanitizeTicketListResponse(
  tickets: Record<string, unknown>[],
): Record<string, unknown>[] {
  return tickets.map(sanitizeTicketResponse);
}

// ---------------------------------------------------------------------------
// Allowed screenshot MIME types
// ---------------------------------------------------------------------------

const ALLOWED_SCREENSHOT_TYPES = new Set([
  'image/png',
  'image/jpeg',
  'image/webp',
]);

const MAX_SCREENSHOT_SIZE = 5 * 1024 * 1024; // 5 MB

// ---------------------------------------------------------------------------
// Magic bytes detection for image content-type validation
// ---------------------------------------------------------------------------

function detectMimeType(buffer: Buffer): string | null {
  if (buffer.length < 4) return null;

  // PNG: 89 50 4E 47
  if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4e && buffer[3] === 0x47) {
    return 'image/png';
  }

  // JPEG: FF D8 FF
  if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
    return 'image/jpeg';
  }

  // WebP: RIFF....WEBP
  if (
    buffer.length >= 12 &&
    buffer[0] === 0x52 && buffer[1] === 0x49 && buffer[2] === 0x46 && buffer[3] === 0x46 &&
    buffer[8] === 0x57 && buffer[9] === 0x45 && buffer[10] === 0x42 && buffer[11] === 0x50
  ) {
    return 'image/webp';
  }

  return null;
}

// ---------------------------------------------------------------------------
// Ticket Routes
// ---------------------------------------------------------------------------

export async function ticketRoutes(
  app: FastifyInstance,
  opts: { deps: TicketRoutesDeps },
) {
  const { supportTicketService } = opts.deps;

  // =========================================================================
  // POST /api/v1/support/tickets — Create ticket (multipart or JSON)
  // =========================================================================

  app.post('/api/v1/support/tickets', {
    preHandler: [app.authenticate],
    handler: async (request: FastifyRequest, reply: FastifyReply) => {
      const providerId = getProviderId(request);

      let ticketData: CreateTicket;
      let screenshotFile: ScreenshotFile | undefined;

      // Determine if this is multipart or JSON
      const contentType = request.headers['content-type'] ?? '';

      if (contentType.includes('multipart/form-data')) {
        // Multipart form data: JSON fields + optional screenshot
        const parts = request.parts();
        let jsonBody: Record<string, unknown> = {};

        for await (const part of parts) {
          if (part.type === 'file') {
            if (part.fieldname === 'screenshot') {
              const chunks: Buffer[] = [];
              for await (const chunk of part.file) {
                chunks.push(chunk);
              }
              const buffer = Buffer.concat(chunks);

              // Validate file size
              if (buffer.length > MAX_SCREENSHOT_SIZE) {
                return reply.code(400).send({
                  error: {
                    code: 'VALIDATION_ERROR',
                    message: 'Screenshot must be 5MB or smaller',
                  },
                });
              }

              // Validate content-type via magic bytes (server-side, not trusting client)
              const detectedType = detectMimeType(buffer);
              if (!detectedType || !ALLOWED_SCREENSHOT_TYPES.has(detectedType)) {
                return reply.code(400).send({
                  error: {
                    code: 'VALIDATION_ERROR',
                    message: 'Screenshot must be a PNG, JPEG, or WebP image',
                  },
                });
              }

              screenshotFile = {
                buffer,
                mimetype: detectedType,
                size: buffer.length,
                originalname: part.filename ?? 'screenshot',
              };
            } else {
              // Consume unknown file fields to prevent hanging
              // eslint-disable-next-line @typescript-eslint/no-unused-vars
              for await (const _chunk of part.file) {
                // drain
              }
            }
          } else {
            // Field part
            const value = part.value;
            if (part.fieldname === 'context_metadata' && typeof value === 'string') {
              try {
                jsonBody[part.fieldname] = JSON.parse(value);
              } catch {
                jsonBody[part.fieldname] = value;
              }
            } else {
              jsonBody[part.fieldname] = value;
            }
          }
        }

        // Validate the JSON fields against the schema
        const parsed = createTicketSchema.safeParse(jsonBody);
        if (!parsed.success) {
          return reply.code(400).send({
            error: {
              code: 'VALIDATION_ERROR',
              message: 'Invalid ticket data',
              details: parsed.error.issues,
            },
          });
        }
        ticketData = parsed.data;
      } else {
        // JSON body
        const parsed = createTicketSchema.safeParse(request.body);
        if (!parsed.success) {
          return reply.code(400).send({
            error: {
              code: 'VALIDATION_ERROR',
              message: 'Invalid ticket data',
              details: parsed.error.issues,
            },
          });
        }
        ticketData = parsed.data;
      }

      try {
        const ticket = await supportTicketService.createTicket(
          providerId,
          {
            subject: ticketData.subject,
            description: ticketData.description,
            contextUrl: ticketData.context_url,
            contextMetadata: ticketData.context_metadata,
            priority: ticketData.priority,
          },
          screenshotFile,
        );

        return reply.code(201).send({ data: sanitizeTicketResponse(ticket as any) });
      } catch (err) {
        return handleAppError(err, reply);
      }
    },
  });

  // =========================================================================
  // GET /api/v1/support/tickets — List physician's tickets
  // =========================================================================

  app.get('/api/v1/support/tickets', {
    schema: { querystring: ticketListQuerySchema },
    preHandler: [app.authenticate],
    handler: async (
      request: FastifyRequest<{ Querystring: TicketListQuery }>,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);
      const { status, limit, offset } = request.query;

      try {
        const result = await supportTicketService.listTickets(providerId, {
          status,
          limit,
          offset,
        });

        return reply.code(200).send({
          data: sanitizeTicketListResponse(result.data as any),
          pagination: result.pagination,
        });
      } catch (err) {
        return handleAppError(err, reply);
      }
    },
  });

  // =========================================================================
  // GET /api/v1/support/tickets/:id — Get ticket details
  // =========================================================================

  app.get('/api/v1/support/tickets/:id', {
    schema: { params: ticketIdParamSchema },
    preHandler: [app.authenticate],
    handler: async (
      request: FastifyRequest<{ Params: TicketIdParam }>,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);
      const { id } = request.params;

      try {
        const ticket = await supportTicketService.getTicket(providerId, id);
        if (!ticket) {
          return reply.code(404).send({
            error: { code: 'NOT_FOUND', message: 'Resource not found' },
          });
        }

        return reply.code(200).send({ data: sanitizeTicketResponse(ticket as any) });
      } catch (err) {
        return handleAppError(err, reply);
      }
    },
  });

  // =========================================================================
  // POST /api/v1/support/tickets/:id/rating — Submit satisfaction rating
  // =========================================================================

  app.post('/api/v1/support/tickets/:id/rating', {
    schema: {
      params: ticketIdParamSchema,
      body: ticketRatingSchema,
    },
    preHandler: [app.authenticate],
    handler: async (
      request: FastifyRequest<{ Params: TicketIdParam; Body: TicketRating }>,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);
      const { id } = request.params;
      const { rating, comment } = request.body;

      try {
        // First check ticket exists and belongs to this provider
        const existing = await supportTicketService.getTicket(providerId, id);
        if (!existing) {
          return reply.code(404).send({
            error: { code: 'NOT_FOUND', message: 'Resource not found' },
          });
        }

        // Check ticket is in a ratable status
        if (existing.status !== 'RESOLVED' && existing.status !== 'CLOSED') {
          return reply.code(400).send({
            error: {
              code: 'VALIDATION_ERROR',
              message: 'Rating can only be submitted for resolved or closed tickets',
            },
          });
        }

        const ticket = await supportTicketService.rateTicket(
          providerId,
          id,
          rating,
          comment,
        );

        if (!ticket) {
          return reply.code(404).send({
            error: { code: 'NOT_FOUND', message: 'Resource not found' },
          });
        }

        return reply.code(200).send({ data: sanitizeTicketResponse(ticket as any) });
      } catch (err) {
        return handleAppError(err, reply);
      }
    },
  });
}
