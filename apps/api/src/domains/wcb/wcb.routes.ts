import { type FastifyInstance } from 'fastify';
import { z } from 'zod';
import {
  wcbClaimCreateSchema,
  wcbClaimUpdateSchema,
  wcbClaimIdParamSchema,
  wcbBatchCreateSchema,
  wcbBatchIdParamSchema,
  wcbBatchConfirmUploadSchema,
  wcbBatchListQuerySchema,
  wcbRemittanceListQuerySchema,
  wcbRemittanceIdParamSchema,
  wcbManualOutcomeSchema,
} from './wcb.schema.js';
import {
  createWcbHandlers,
  type WcbHandlerDeps,
} from './wcb.handlers.js';

// --- Return batch_id param schema (uses batch_id, not id) ---
const wcbReturnBatchIdParamSchema = z.object({
  batch_id: z.string().uuid(),
});

// ---------------------------------------------------------------------------
// WCB Routes
// ---------------------------------------------------------------------------

export async function wcbRoutes(
  app: FastifyInstance,
  opts: { deps: WcbHandlerDeps },
) {
  const handlers = createWcbHandlers(opts.deps);

  // =========================================================================
  // Claim CRUD
  // =========================================================================

  app.post('/api/v1/wcb/claims', {
    schema: { body: wcbClaimCreateSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_CREATE')],
    handler: handlers.createClaimHandler,
  });

  app.get('/api/v1/wcb/claims/:id', {
    schema: { params: wcbClaimIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_VIEW')],
    handler: handlers.getClaimHandler,
  });

  app.put('/api/v1/wcb/claims/:id', {
    schema: { body: wcbClaimUpdateSchema, params: wcbClaimIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_EDIT')],
    handler: handlers.updateClaimHandler,
  });

  app.delete('/api/v1/wcb/claims/:id', {
    schema: { params: wcbClaimIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_DELETE')],
    handler: handlers.deleteClaimHandler,
  });

  // =========================================================================
  // Validation & Form Schema
  // =========================================================================

  app.post('/api/v1/wcb/claims/:id/validate', {
    schema: { params: wcbClaimIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_VIEW')],
    handler: handlers.validateClaimHandler,
  });

  app.get('/api/v1/wcb/claims/:id/form-schema', {
    schema: { params: wcbClaimIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_VIEW')],
    handler: handlers.getFormSchemaHandler,
  });

  // =========================================================================
  // Batch Management
  // =========================================================================

  app.post('/api/v1/wcb/batches', {
    schema: { body: wcbBatchCreateSchema },
    preHandler: [app.authenticate, app.authorize('BATCH_APPROVE')],
    handler: handlers.createBatchHandler,
  });

  app.get('/api/v1/wcb/batches/:id', {
    schema: { params: wcbBatchIdParamSchema },
    preHandler: [app.authenticate, app.authorize('BATCH_VIEW')],
    handler: handlers.getBatchHandler,
  });

  app.get('/api/v1/wcb/batches/:id/download', {
    schema: { params: wcbBatchIdParamSchema },
    preHandler: [app.authenticate, app.authorize('BATCH_VIEW'), app.authorize('WCB_BATCH_UPLOAD')],
    handler: handlers.downloadBatchHandler,
  });

  app.post('/api/v1/wcb/batches/:id/confirm-upload', {
    schema: { params: wcbBatchIdParamSchema, body: wcbBatchConfirmUploadSchema },
    preHandler: [app.authenticate, app.authorize('WCB_BATCH_UPLOAD')],
    handler: handlers.confirmUploadHandler,
  });

  app.get('/api/v1/wcb/batches', {
    schema: { querystring: wcbBatchListQuerySchema },
    preHandler: [app.authenticate, app.authorize('BATCH_VIEW')],
    handler: handlers.listBatchesHandler,
  });

  // =========================================================================
  // Return File
  // =========================================================================

  app.post('/api/v1/wcb/returns/upload', {
    preHandler: [app.authenticate, app.authorize('BATCH_VIEW')],
    handler: handlers.uploadReturnHandler,
  });

  app.get('/api/v1/wcb/returns/:batch_id', {
    schema: { params: wcbReturnBatchIdParamSchema },
    preHandler: [app.authenticate, app.authorize('BATCH_VIEW')],
    handler: handlers.getReturnResultsHandler,
  });

  // =========================================================================
  // Remittance
  // =========================================================================

  app.post('/api/v1/wcb/remittances/upload', {
    preHandler: [app.authenticate, app.authorize('REPORT_VIEW')],
    handler: handlers.uploadRemittanceHandler,
  });

  app.get('/api/v1/wcb/remittances', {
    schema: { querystring: wcbRemittanceListQuerySchema },
    preHandler: [app.authenticate, app.authorize('REPORT_VIEW')],
    handler: handlers.listRemittancesHandler,
  });

  app.get('/api/v1/wcb/remittances/:id/discrepancies', {
    schema: { params: wcbRemittanceIdParamSchema },
    preHandler: [app.authenticate, app.authorize('REPORT_VIEW')],
    handler: handlers.getDiscrepanciesHandler,
  });

  // =========================================================================
  // MVP Endpoints (feature-flagged)
  // =========================================================================

  app.get('/api/v1/wcb/claims/:id/export', {
    schema: { params: wcbClaimIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_VIEW')],
    handler: handlers.exportClaimHandler,
  });

  app.post('/api/v1/wcb/claims/:id/manual-outcome', {
    schema: { params: wcbClaimIdParamSchema, body: wcbManualOutcomeSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_EDIT')],
    handler: handlers.manualOutcomeHandler,
  });
}
