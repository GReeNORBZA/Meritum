import { type FastifyInstance } from 'fastify';
import {
  listBatchesSchema,
  batchIdParamSchema,
  feeCalculateSchema,
  batchAssessmentParamSchema,
  claimIdParamSchema,
} from './ahcip.schema.js';
import {
  createAhcipHandlers,
  type AhcipHandlerDeps,
} from './ahcip.handlers.js';

// ---------------------------------------------------------------------------
// AHCIP Routes
// ---------------------------------------------------------------------------

export async function ahcipRoutes(
  app: FastifyInstance,
  opts: { deps: AhcipHandlerDeps },
) {
  const handlers = createAhcipHandlers(opts.deps);

  // =========================================================================
  // Batch Management
  // =========================================================================

  app.get('/api/v1/ahcip/batches', {
    schema: { querystring: listBatchesSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_VIEW')],
    handler: handlers.listBatchesHandler,
  });

  app.get('/api/v1/ahcip/batches/next', {
    preHandler: [app.authenticate, app.authorize('CLAIM_VIEW')],
    handler: handlers.previewNextBatchHandler,
  });

  app.get('/api/v1/ahcip/batches/:id', {
    schema: { params: batchIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_VIEW')],
    handler: handlers.getBatchHandler,
  });

  app.post('/api/v1/ahcip/batches/:id/retry', {
    schema: { params: batchIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_SUBMIT')],
    handler: handlers.retryBatchHandler,
  });

  // =========================================================================
  // Assessment
  // =========================================================================

  app.get('/api/v1/ahcip/assessments/pending', {
    preHandler: [app.authenticate, app.authorize('CLAIM_VIEW')],
    handler: handlers.listPendingAssessmentsHandler,
  });

  app.get('/api/v1/ahcip/assessments/:batch_id', {
    schema: { params: batchAssessmentParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_VIEW')],
    handler: handlers.getAssessmentResultsHandler,
  });

  // =========================================================================
  // Fee Calculation
  // =========================================================================

  app.post('/api/v1/ahcip/fee-calculate', {
    schema: { body: feeCalculateSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_VIEW')],
    handler: handlers.feeCalculateHandler,
  });

  app.get('/api/v1/ahcip/claims/:id/fee-breakdown', {
    schema: { params: claimIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_VIEW')],
    handler: handlers.feeBreakdownHandler,
  });
}
