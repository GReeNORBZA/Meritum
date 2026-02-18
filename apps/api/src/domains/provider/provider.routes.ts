import { type FastifyInstance } from 'fastify';
import {
  updateProviderSchema,
  completeOnboardingSchema,
  createBaSchema,
  updateBaSchema,
  baIdParamSchema,
  createLocationSchema,
  updateLocationSchema,
  locationIdParamSchema,
  createWcbConfigSchema,
  updateWcbConfigSchema,
  wcbConfigIdParamSchema,
  updateSubmissionPreferencesSchema,
  updateHlinkConfigSchema,
  inviteDelegateSchema,
  updateDelegatePermissionsSchema,
  delegateRelIdParamSchema,
  acceptInvitationSchema,
  switchContextParamSchema,
  providerIdParamSchema,
  baForClaimQuerySchema,
  wcbConfigForFormQuerySchema,
} from '@meritum/shared/schemas/provider.schema.js';
import {
  createProviderHandlers,
  createInternalProviderHandlers,
  type ProviderHandlerDeps,
  type InternalProviderHandlerDeps,
} from './provider.handlers.js';

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
    if (!roles.map((r: string) => r.toUpperCase()).includes(userRole)) {
      reply.code(403).send({
        error: { code: 'FORBIDDEN', message: 'Insufficient permissions' },
      });
      return;
    }
  };
}

// ---------------------------------------------------------------------------
// Provider Routes
// ---------------------------------------------------------------------------

export async function providerRoutes(
  app: FastifyInstance,
  opts: { deps: ProviderHandlerDeps },
) {
  const handlers = createProviderHandlers(opts.deps);

  // =========================================================================
  // Provider Profile Routes
  // =========================================================================

  app.get('/api/v1/providers/me', {
    preHandler: [app.authenticate, app.authorize('PROVIDER_VIEW')],
    handler: handlers.getProfileHandler,
  });

  app.put('/api/v1/providers/me', {
    schema: { body: updateProviderSchema },
    preHandler: [app.authenticate, app.authorize('PREFERENCE_EDIT')],
    handler: handlers.updateProfileHandler,
  });

  app.get('/api/v1/providers/me/onboarding-status', {
    preHandler: [app.authenticate, app.authorize('PROVIDER_VIEW')],
    handler: handlers.onboardingStatusHandler,
  });

  app.post('/api/v1/providers/me/complete-onboarding', {
    schema: { body: completeOnboardingSchema },
    preHandler: [app.authenticate, requireRole('PHYSICIAN')],
    handler: handlers.completeOnboardingHandler,
  });

  // =========================================================================
  // Business Arrangement Routes
  // =========================================================================

  app.get('/api/v1/providers/me/bas', {
    preHandler: [app.authenticate, app.authorize('PROVIDER_VIEW')],
    handler: handlers.listBasHandler,
  });

  app.post('/api/v1/providers/me/bas', {
    schema: { body: createBaSchema },
    preHandler: [app.authenticate, app.authorize('PREFERENCE_EDIT')],
    handler: handlers.addBaHandler,
  });

  app.put('/api/v1/providers/me/bas/:id', {
    schema: { body: updateBaSchema, params: baIdParamSchema },
    preHandler: [app.authenticate, app.authorize('PREFERENCE_EDIT')],
    handler: handlers.updateBaHandler,
  });

  app.delete('/api/v1/providers/me/bas/:id', {
    schema: { params: baIdParamSchema },
    preHandler: [app.authenticate, app.authorize('PREFERENCE_EDIT')],
    handler: handlers.deactivateBaHandler,
  });

  // =========================================================================
  // Practice Location Routes
  // =========================================================================

  app.get('/api/v1/providers/me/locations', {
    preHandler: [app.authenticate, app.authorize('PROVIDER_VIEW')],
    handler: handlers.listLocationsHandler,
  });

  app.post('/api/v1/providers/me/locations', {
    schema: { body: createLocationSchema },
    preHandler: [app.authenticate, app.authorize('PREFERENCE_EDIT')],
    handler: handlers.addLocationHandler,
  });

  app.put('/api/v1/providers/me/locations/:id', {
    schema: { body: updateLocationSchema, params: locationIdParamSchema },
    preHandler: [app.authenticate, app.authorize('PREFERENCE_EDIT')],
    handler: handlers.updateLocationHandler,
  });

  app.put('/api/v1/providers/me/locations/:id/set-default', {
    schema: { params: locationIdParamSchema },
    preHandler: [app.authenticate, app.authorize('PREFERENCE_EDIT')],
    handler: handlers.setDefaultLocationHandler,
  });

  app.delete('/api/v1/providers/me/locations/:id', {
    schema: { params: locationIdParamSchema },
    preHandler: [app.authenticate, app.authorize('PREFERENCE_EDIT')],
    handler: handlers.deactivateLocationHandler,
  });

  // =========================================================================
  // WCB Configuration Routes
  // =========================================================================

  app.get('/api/v1/providers/me/wcb', {
    preHandler: [app.authenticate, app.authorize('PROVIDER_VIEW')],
    handler: handlers.listWcbConfigsHandler,
  });

  app.post('/api/v1/providers/me/wcb', {
    schema: { body: createWcbConfigSchema },
    preHandler: [app.authenticate, app.authorize('PREFERENCE_EDIT')],
    handler: handlers.addWcbConfigHandler,
  });

  app.put('/api/v1/providers/me/wcb/:id', {
    schema: { body: updateWcbConfigSchema, params: wcbConfigIdParamSchema },
    preHandler: [app.authenticate, app.authorize('PREFERENCE_EDIT')],
    handler: handlers.updateWcbConfigHandler,
  });

  app.delete('/api/v1/providers/me/wcb/:id', {
    schema: { params: wcbConfigIdParamSchema },
    preHandler: [app.authenticate, app.authorize('PREFERENCE_EDIT')],
    handler: handlers.removeWcbConfigHandler,
  });

  app.get('/api/v1/providers/me/wcb/form-permissions', {
    preHandler: [app.authenticate, app.authorize('PROVIDER_VIEW')],
    handler: handlers.formPermissionsHandler,
  });

  // =========================================================================
  // Submission Preferences Routes
  // =========================================================================

  app.get('/api/v1/providers/me/submission-preferences', {
    preHandler: [app.authenticate, app.authorize('PREFERENCE_VIEW')],
    handler: handlers.getPreferencesHandler,
  });

  app.put('/api/v1/providers/me/submission-preferences', {
    schema: { body: updateSubmissionPreferencesSchema },
    preHandler: [app.authenticate, app.authorize('PREFERENCE_EDIT')],
    handler: handlers.updatePreferencesHandler,
  });

  // =========================================================================
  // H-Link Configuration Routes
  // =========================================================================

  app.get('/api/v1/providers/me/hlink', {
    preHandler: [app.authenticate, requireRole('PHYSICIAN')],
    handler: handlers.getHlinkConfigHandler,
  });

  app.put('/api/v1/providers/me/hlink', {
    schema: { body: updateHlinkConfigSchema },
    preHandler: [app.authenticate, requireRole('PHYSICIAN')],
    handler: handlers.updateHlinkConfigHandler,
  });

  // =========================================================================
  // Delegate Management Routes (physician role)
  // =========================================================================

  app.get('/api/v1/providers/me/delegates', {
    preHandler: [app.authenticate, requireRole('PHYSICIAN')],
    handler: handlers.listDelegatesHandler,
  });

  app.post('/api/v1/providers/me/delegates/invite', {
    schema: { body: inviteDelegateSchema },
    preHandler: [app.authenticate, requireRole('PHYSICIAN')],
    handler: handlers.inviteDelegateHandler,
  });

  app.put('/api/v1/providers/me/delegates/:rel_id/permissions', {
    schema: { body: updateDelegatePermissionsSchema, params: delegateRelIdParamSchema },
    preHandler: [app.authenticate, requireRole('PHYSICIAN')],
    handler: handlers.updateDelegatePermissionsHandler,
  });

  app.post('/api/v1/providers/me/delegates/:rel_id/revoke', {
    schema: { params: delegateRelIdParamSchema },
    preHandler: [app.authenticate, requireRole('PHYSICIAN')],
    handler: handlers.revokeDelegateHandler,
  });

  // =========================================================================
  // Delegate Self-Service Routes (delegate role)
  // =========================================================================

  app.get('/api/v1/delegates/me/physicians', {
    preHandler: [app.authenticate, requireRole('DELEGATE')],
    handler: handlers.listPhysiciansHandler,
  });

  app.post('/api/v1/delegates/me/switch-context/:provider_id', {
    schema: { params: switchContextParamSchema },
    preHandler: [app.authenticate, requireRole('DELEGATE')],
    handler: handlers.switchContextHandler,
  });

  // =========================================================================
  // Invitation Acceptance (unauthenticated — token-based)
  // =========================================================================

  app.post('/api/v1/delegates/invitations/:token/accept', {
    schema: { body: acceptInvitationSchema },
    handler: handlers.acceptInvitationHandler,
  });
}

// ---------------------------------------------------------------------------
// Internal Provider Context Routes (service-to-service, API key auth)
// ---------------------------------------------------------------------------

export async function internalProviderRoutes(
  app: FastifyInstance,
  opts: { deps: InternalProviderHandlerDeps },
) {
  const handlers = createInternalProviderHandlers(opts.deps);

  // GET /api/v1/internal/providers/:id/claim-context
  app.get('/api/v1/internal/providers/:id/claim-context', {
    schema: { params: providerIdParamSchema },
    handler: handlers.claimContextHandler,
  });

  // GET /api/v1/internal/providers/:id/ba-for-claim
  app.get('/api/v1/internal/providers/:id/ba-for-claim', {
    schema: { params: providerIdParamSchema, querystring: baForClaimQuerySchema },
    handler: handlers.baForClaimHandler,
  });

  // GET /api/v1/internal/providers/:id/wcb-config-for-form
  app.get('/api/v1/internal/providers/:id/wcb-config-for-form', {
    schema: { params: providerIdParamSchema, querystring: wcbConfigForFormQuerySchema },
    handler: handlers.wcbConfigForFormHandler,
  });
}
