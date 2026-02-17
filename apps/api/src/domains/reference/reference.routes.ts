import { type FastifyInstance, type FastifyRequest, type FastifyReply } from 'fastify';
import multipart from '@fastify/multipart';
import {
  hscSearchSchema,
  hscDetailParamSchema,
  hscDetailQuerySchema,
  diSearchSchema,
  diDetailParamSchema,
  modifierLookupSchema,
  modifierDetailParamSchema,
  fcListSchema,
  explCodeParamSchema,
  rrnpParamSchema,
  rrnpLookupSchema,
  pcpcmParamSchema,
  pcpcmLookupSchema,
  holidayListSchema,
  holidayCheckSchema,
  adminUploadParamSchema,
  adminStagingParamSchema,
  adminPublishSchema,
  adminVersionListSchema,
  createHolidaySchema,
  updateHolidaySchema,
  holidayParamSchema,
  dryRunParamSchema,
  dryRunSchema,
  validateContextSchema,
  ruleDetailSchema,
  ruleDetailQuerySchema,
  versionQuerySchema,
  evaluateBatchSchema,
  changeListSchema,
  changeDetailParamSchema,
  changeDetailQuerySchema,
} from '@meritum/shared/schemas/reference.schema.js';
import {
  createReferenceHandlers,
  type ReferenceHandlerDeps,
} from './reference.handlers.js';

// ---------------------------------------------------------------------------
// Reference Data Routes — 13 public search/lookup endpoints
// ---------------------------------------------------------------------------

export async function referenceRoutes(
  app: FastifyInstance,
  opts: { deps: ReferenceHandlerDeps },
) {
  const handlers = createReferenceHandlers(opts.deps);

  // =========================================================================
  // HSC Code endpoints
  // =========================================================================

  // Subscription guard: read-only routes allow TRIAL, ACTIVE, SUSPENDED
  const checkReadAccess = app.checkSubscription('TRIAL', 'ACTIVE', 'SUSPENDED');

  app.get('/api/v1/ref/hsc/search', {
    schema: { querystring: hscSearchSchema },
    preHandler: [app.authenticate, checkReadAccess, app.authorize('CLAIM_VIEW')],
    handler: handlers.searchHscHandler,
  });

  app.get('/api/v1/ref/hsc/favourites', {
    preHandler: [app.authenticate, checkReadAccess, app.authorize('CLAIM_VIEW')],
    handler: handlers.hscFavouritesHandler,
  });

  app.get('/api/v1/ref/hsc/:code', {
    schema: { params: hscDetailParamSchema, querystring: hscDetailQuerySchema },
    preHandler: [app.authenticate, checkReadAccess, app.authorize('CLAIM_VIEW')],
    handler: handlers.hscDetailHandler,
  });

  // =========================================================================
  // DI Code endpoints
  // =========================================================================

  app.get('/api/v1/ref/di/search', {
    schema: { querystring: diSearchSchema },
    preHandler: [app.authenticate, checkReadAccess, app.authorize('CLAIM_VIEW')],
    handler: handlers.searchDiHandler,
  });

  app.get('/api/v1/ref/di/:code', {
    schema: { params: diDetailParamSchema },
    preHandler: [app.authenticate, checkReadAccess, app.authorize('CLAIM_VIEW')],
    handler: handlers.diDetailHandler,
  });

  // =========================================================================
  // Modifier endpoints
  // =========================================================================

  app.get('/api/v1/ref/modifiers', {
    schema: { querystring: modifierLookupSchema },
    preHandler: [app.authenticate, checkReadAccess, app.authorize('CLAIM_VIEW')],
    handler: handlers.modifierListHandler,
  });

  app.get('/api/v1/ref/modifiers/:code', {
    schema: { params: modifierDetailParamSchema },
    preHandler: [app.authenticate, checkReadAccess, app.authorize('CLAIM_VIEW')],
    handler: handlers.modifierDetailHandler,
  });

  // =========================================================================
  // Functional Centres
  // =========================================================================

  app.get('/api/v1/ref/functional-centres', {
    schema: { querystring: fcListSchema },
    preHandler: [app.authenticate, checkReadAccess, app.authorize('CLAIM_VIEW')],
    handler: handlers.fcListHandler,
  });

  // =========================================================================
  // Explanatory Codes
  // =========================================================================

  app.get('/api/v1/ref/explanatory-codes/:code', {
    schema: { params: explCodeParamSchema },
    preHandler: [app.authenticate, checkReadAccess, app.authorize('CLAIM_VIEW')],
    handler: handlers.explCodeHandler,
  });

  // =========================================================================
  // RRNP
  // =========================================================================

  app.get('/api/v1/ref/rrnp/:community_id', {
    schema: { params: rrnpParamSchema, querystring: rrnpLookupSchema },
    preHandler: [app.authenticate, checkReadAccess, app.authorize('CLAIM_VIEW')],
    handler: handlers.rrnpHandler,
  });

  // =========================================================================
  // PCPCM
  // =========================================================================

  app.get('/api/v1/ref/pcpcm/:hsc_code', {
    schema: { params: pcpcmParamSchema, querystring: pcpcmLookupSchema },
    preHandler: [app.authenticate, checkReadAccess, app.authorize('CLAIM_VIEW')],
    handler: handlers.pcpcmHandler,
  });

  // =========================================================================
  // Holidays
  // =========================================================================

  app.get('/api/v1/ref/holidays', {
    schema: { querystring: holidayListSchema },
    preHandler: [app.authenticate, checkReadAccess, app.authorize('CLAIM_VIEW')],
    handler: handlers.holidayListHandler,
  });

  app.get('/api/v1/ref/holidays/check', {
    schema: { querystring: holidayCheckSchema },
    preHandler: [app.authenticate, checkReadAccess, app.authorize('CLAIM_VIEW')],
    handler: handlers.holidayCheckHandler,
  });

  // =========================================================================
  // Internal Validation Routes (authenticated, all roles)
  // =========================================================================
  // NOTE: Register validate-context and evaluate-batch BEFORE :rule_id
  // to prevent path parameter matching on those literal paths.

  app.get('/api/v1/ref/rules/validate-context', {
    schema: { querystring: validateContextSchema },
    preHandler: [app.authenticate, checkReadAccess],
    handler: handlers.validateContextHandler,
  });

  app.post('/api/v1/ref/rules/evaluate-batch', {
    schema: { body: evaluateBatchSchema },
    preHandler: [app.authenticate, checkReadAccess],
    handler: handlers.evaluateBatchHandler,
  });

  app.get('/api/v1/ref/rules/:rule_id', {
    schema: { params: ruleDetailSchema, querystring: ruleDetailQuerySchema },
    preHandler: [app.authenticate, checkReadAccess],
    handler: handlers.ruleDetailHandler,
  });

  app.get('/api/v1/ref/somb/version', {
    schema: { querystring: versionQuerySchema },
    preHandler: [app.authenticate, checkReadAccess],
    handler: handlers.sombVersionHandler,
  });

  // =========================================================================
  // Change Summary Routes (authenticated, subscription-gated)
  // =========================================================================

  app.get('/api/v1/ref/changes', {
    schema: { querystring: changeListSchema },
    preHandler: [app.authenticate, checkReadAccess],
    handler: handlers.changeSummaryListHandler,
  });

  app.get('/api/v1/ref/changes/:version_id/detail', {
    schema: { params: changeDetailParamSchema, querystring: changeDetailQuerySchema },
    preHandler: [app.authenticate, checkReadAccess],
    handler: handlers.changeDetailHandler,
  });

  app.get('/api/v1/ref/changes/:version_id/physician-impact', {
    schema: { params: changeDetailParamSchema },
    preHandler: [app.authenticate, checkReadAccess],
    handler: handlers.physicianImpactHandler,
  });

  // =========================================================================
  // Admin Data Management Routes (admin role required)
  // =========================================================================

  // Admin role guard
  async function requireAdmin(request: FastifyRequest, reply: FastifyReply) {
    const ctx = request.authContext;
    if (!ctx) {
      reply.code(401).send({
        error: { code: 'UNAUTHORIZED', message: 'Authentication required' },
      });
      return;
    }
    if (ctx.role?.toUpperCase() !== 'ADMIN') {
      reply.code(403).send({
        error: { code: 'FORBIDDEN', message: 'Insufficient permissions' },
      });
      return;
    }
  }

  // Register multipart for file uploads
  await app.register(multipart, {
    limits: {
      fileSize: 50 * 1024 * 1024, // 50 MB
    },
  });

  app.post('/api/v1/admin/ref/:dataset/upload', {
    schema: { params: adminUploadParamSchema },
    preHandler: [app.authenticate, requireAdmin],
    handler: handlers.uploadHandler,
  });

  app.get('/api/v1/admin/ref/:dataset/staging/:id/diff', {
    schema: { params: adminStagingParamSchema },
    preHandler: [app.authenticate, requireAdmin],
    handler: handlers.diffHandler,
  });

  app.post('/api/v1/admin/ref/:dataset/staging/:id/publish', {
    schema: { params: adminStagingParamSchema, body: adminPublishSchema },
    preHandler: [app.authenticate, requireAdmin],
    handler: handlers.publishHandler,
  });

  app.delete('/api/v1/admin/ref/:dataset/staging/:id', {
    schema: { params: adminStagingParamSchema },
    preHandler: [app.authenticate, requireAdmin],
    handler: handlers.discardStagingHandler,
  });

  app.get('/api/v1/admin/ref/:dataset/versions', {
    schema: { params: adminVersionListSchema },
    preHandler: [app.authenticate, requireAdmin],
    handler: handlers.listVersionsHandler,
  });

  app.post('/api/v1/admin/ref/holidays', {
    schema: { body: createHolidaySchema },
    preHandler: [app.authenticate, requireAdmin],
    handler: handlers.createHolidayHandler,
  });

  app.put('/api/v1/admin/ref/holidays/:id', {
    schema: { params: holidayParamSchema, body: updateHolidaySchema },
    preHandler: [app.authenticate, requireAdmin],
    handler: handlers.updateHolidayHandler,
  });

  app.delete('/api/v1/admin/ref/holidays/:id', {
    schema: { params: holidayParamSchema },
    preHandler: [app.authenticate, requireAdmin],
    handler: handlers.deleteHolidayHandler,
  });

  app.post('/api/v1/admin/ref/rules/:rule_id/dry-run', {
    schema: { params: dryRunParamSchema, body: dryRunSchema },
    preHandler: [app.authenticate, requireAdmin],
    handler: handlers.dryRunHandler,
  });
}
