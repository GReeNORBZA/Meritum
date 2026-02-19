// ============================================================================
// Domain 10: Favourite Codes Routes
// 5 endpoints for favourite codes CRUD and reorder.
// All require authentication. Permission-gated: CLAIM_VIEW for list,
// CLAIM_CREATE for create/update/delete/reorder.
// ============================================================================

import { type FastifyInstance, type FastifyRequest, type FastifyReply } from 'fastify';
import {
  createFavouriteSchema,
  updateFavouriteSchema,
  favouriteIdParamSchema,
  reorderFavouritesSchema,
  type CreateFavourite,
  type UpdateFavourite,
  type FavouriteIdParam,
  type ReorderFavourites,
} from '@meritum/shared/schemas/validation/mobile.validation.js';
import { AppError } from '../../../lib/errors.js';
import type { FavouriteCodesServiceDeps } from '../services/favourite-codes.service.js';
import {
  addFavourite,
  updateFavourite as updateFavouriteService,
  removeFavourite,
  reorderFavourites as reorderFavouritesService,
  listFavourites,
  seedFavourites,
} from '../services/favourite-codes.service.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface FavouriteRouteDeps {
  serviceDeps: FavouriteCodesServiceDeps;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getProviderId(request: FastifyRequest): string {
  return request.authContext.userId;
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

export async function favouriteRoutes(
  app: FastifyInstance,
  opts: { deps: FavouriteRouteDeps },
) {
  const { serviceDeps } = opts.deps;

  // =========================================================================
  // GET /api/v1/favourites — list favourites (auto-seed on first call)
  // =========================================================================

  app.get('/api/v1/favourites', {
    preHandler: [app.authenticate, app.authorize('CLAIM_VIEW')],
    handler: async (
      request: FastifyRequest,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);

      // Auto-seed on first call if empty
      await seedFavourites(serviceDeps, providerId);

      const data = await listFavourites(serviceDeps, providerId);
      return reply.code(200).send({ data });
    },
  });

  // =========================================================================
  // POST /api/v1/favourites — add a favourite code
  // =========================================================================

  app.post('/api/v1/favourites', {
    schema: { body: createFavouriteSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_CREATE')],
    handler: async (
      request: FastifyRequest<{ Body: CreateFavourite }>,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);
      const body = request.body;

      try {
        const favourite = await addFavourite(serviceDeps, providerId, {
          healthServiceCode: body.health_service_code,
          displayName: body.display_name,
          defaultModifiers: body.default_modifiers,
          sortOrder: body.sort_order,
        });
        return reply.code(201).send({ data: favourite });
      } catch (err) {
        return handleAppError(err, reply);
      }
    },
  });

  // =========================================================================
  // PUT /api/v1/favourites/reorder — bulk reorder (must be before /:id)
  // =========================================================================

  app.put('/api/v1/favourites/reorder', {
    schema: { body: reorderFavouritesSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_CREATE')],
    handler: async (
      request: FastifyRequest<{ Body: ReorderFavourites }>,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);
      const { items } = request.body;

      try {
        await reorderFavouritesService(serviceDeps, providerId, items);
        return reply.code(200).send({ data: { success: true } });
      } catch (err) {
        return handleAppError(err, reply);
      }
    },
  });

  // =========================================================================
  // PUT /api/v1/favourites/:id — update a favourite
  // =========================================================================

  app.put('/api/v1/favourites/:id', {
    schema: { params: favouriteIdParamSchema, body: updateFavouriteSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_CREATE')],
    handler: async (
      request: FastifyRequest<{ Params: FavouriteIdParam; Body: UpdateFavourite }>,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);
      const { id } = request.params;
      const body = request.body;

      try {
        const favourite = await updateFavouriteService(
          serviceDeps,
          providerId,
          id,
          {
            displayName: body.display_name,
            defaultModifiers: body.default_modifiers,
            sortOrder: body.sort_order,
          },
        );
        return reply.code(200).send({ data: favourite });
      } catch (err) {
        return handleAppError(err, reply);
      }
    },
  });

  // =========================================================================
  // DELETE /api/v1/favourites/:id — remove a favourite
  // =========================================================================

  app.delete('/api/v1/favourites/:id', {
    schema: { params: favouriteIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_CREATE')],
    handler: async (
      request: FastifyRequest<{ Params: FavouriteIdParam }>,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);
      const { id } = request.params;

      try {
        await removeFavourite(serviceDeps, providerId, id);
        return reply.code(204).send();
      } catch (err) {
        return handleAppError(err, reply);
      }
    },
  });
}
