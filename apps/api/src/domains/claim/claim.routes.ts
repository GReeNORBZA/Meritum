import { type FastifyInstance } from 'fastify';
import { z } from 'zod';
import {
  createClaimSchema,
  updateClaimSchema,
  claimIdParamSchema,
  listClaimsSchema,
  writeOffClaimSchema,
  dismissSuggestionSchema,
  suggestionIdParamSchema,
  createImportSchema,
  claimImportIdParamSchema,
  createTemplateSchema,
  updateTemplateSchema,
  templateIdParamSchema,
  createShiftSchema,
  addEncounterSchema,
  shiftIdParamSchema,
  createExportSchema,
  claimExportIdParamSchema,
  updateSubmissionModeSchema,
  createClaimTemplateSchema,
  updateClaimTemplateSchema,
  claimTemplateIdParamSchema,
  listClaimTemplatesQuerySchema,
  applyClaimTemplateSchema,
  reorderClaimTemplatesSchema,
  createJustificationSchema,
  updateJustificationSchema,
  justificationIdParamSchema,
  justificationHistoryQuerySchema,
  recordRecentReferrerSchema,
  bundlingCheckSchema,
  anesthesiaCalculateSchema,
} from '@meritum/shared/schemas/claim.schema.js';
import {
  uploadSccExtractSchema,
  sccImportIdParamSchema,
  confirmSccImportSchema,
  listSccImportsQuerySchema,
} from '@meritum/shared/schemas/scc.schema.js';
import {
  createClaimHandlers,
  type ClaimHandlerDeps,
} from './claim.handlers.js';

// ---------------------------------------------------------------------------
// Combined param schemas for nested routes
// ---------------------------------------------------------------------------

const claimSuggestionParamSchema = z.object({
  id: z.string().uuid(),
  sug_id: z.string().uuid(),
});

// ---------------------------------------------------------------------------
// Claim Routes
// ---------------------------------------------------------------------------

export async function claimRoutes(
  app: FastifyInstance,
  opts: { deps: ClaimHandlerDeps },
) {
  const handlers = createClaimHandlers(opts.deps);

  // =========================================================================
  // Rejection Management (must be before /:id to avoid param conflicts)
  // =========================================================================

  app.get('/api/v1/claims/rejected', {
    preHandler: [app.authenticate, app.authorize('CLAIM_VIEW')],
    handler: handlers.listRejectedHandler,
  });

  // =========================================================================
  // Claim CRUD
  // =========================================================================

  app.post('/api/v1/claims', {
    schema: { body: createClaimSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_CREATE')],
    handler: handlers.createClaimHandler,
  });

  app.get('/api/v1/claims', {
    schema: { querystring: listClaimsSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_VIEW')],
    handler: handlers.listClaimsHandler,
  });

  app.get('/api/v1/claims/:id', {
    schema: { params: claimIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_VIEW')],
    handler: handlers.getClaimHandler,
  });

  app.put('/api/v1/claims/:id', {
    schema: { body: updateClaimSchema, params: claimIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_EDIT')],
    handler: handlers.updateClaimHandler,
  });

  app.delete('/api/v1/claims/:id', {
    schema: { params: claimIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_DELETE')],
    handler: handlers.deleteClaimHandler,
  });

  // =========================================================================
  // State Transitions
  // =========================================================================

  app.post('/api/v1/claims/:id/validate', {
    schema: { params: claimIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_EDIT')],
    handler: handlers.validateClaimHandler,
  });

  app.post('/api/v1/claims/:id/queue', {
    schema: { params: claimIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_SUBMIT')],
    handler: handlers.queueClaimHandler,
  });

  app.post('/api/v1/claims/:id/unqueue', {
    schema: { params: claimIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_SUBMIT')],
    handler: handlers.unqueueClaimHandler,
  });

  app.post('/api/v1/claims/:id/write-off', {
    schema: { body: writeOffClaimSchema, params: claimIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_EDIT')],
    handler: handlers.writeOffHandler,
  });

  app.post('/api/v1/claims/:id/resubmit', {
    schema: { params: claimIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_SUBMIT')],
    handler: handlers.resubmitHandler,
  });

  // =========================================================================
  // AI Coach
  // =========================================================================

  app.get('/api/v1/claims/:id/suggestions', {
    schema: { params: claimIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_VIEW')],
    handler: handlers.getSuggestionsHandler,
  });

  app.post('/api/v1/claims/:id/suggestions/:sug_id/accept', {
    schema: { params: claimSuggestionParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_EDIT')],
    handler: handlers.acceptSuggestionHandler,
  });

  app.post('/api/v1/claims/:id/suggestions/:sug_id/dismiss', {
    schema: { params: claimSuggestionParamSchema, body: dismissSuggestionSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_EDIT')],
    handler: handlers.dismissSuggestionHandler,
  });

  // =========================================================================
  // Rejection Details
  // =========================================================================

  app.get('/api/v1/claims/:id/rejection-details', {
    schema: { params: claimIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_VIEW')],
    handler: handlers.rejectionDetailsHandler,
  });

  // =========================================================================
  // Claim Audit
  // =========================================================================

  app.get('/api/v1/claims/:id/audit', {
    schema: { params: claimIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_VIEW')],
    handler: handlers.claimAuditHandler,
  });

  // =========================================================================
  // EMR Import
  // =========================================================================

  app.post('/api/v1/imports', {
    schema: { body: createImportSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_CREATE')],
    handler: handlers.uploadImportHandler,
  });

  app.get('/api/v1/imports/:id', {
    schema: { params: claimImportIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_VIEW')],
    handler: handlers.getImportHandler,
  });

  app.get('/api/v1/imports/:id/preview', {
    schema: { params: claimImportIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_VIEW')],
    handler: handlers.previewImportHandler,
  });

  app.post('/api/v1/imports/:id/commit', {
    schema: { params: claimImportIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_CREATE')],
    handler: handlers.commitImportHandler,
  });

  // =========================================================================
  // Field Mapping Templates
  // =========================================================================

  app.post('/api/v1/field-mapping-templates', {
    schema: { body: createTemplateSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_CREATE')],
    handler: handlers.createTemplateHandler,
  });

  app.get('/api/v1/field-mapping-templates', {
    preHandler: [app.authenticate, app.authorize('CLAIM_VIEW')],
    handler: handlers.listTemplatesHandler,
  });

  app.put('/api/v1/field-mapping-templates/:id', {
    schema: { body: updateTemplateSchema, params: templateIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_EDIT')],
    handler: handlers.updateTemplateHandler,
  });

  app.delete('/api/v1/field-mapping-templates/:id', {
    schema: { params: templateIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_DELETE')],
    handler: handlers.deleteTemplateHandler,
  });

  // =========================================================================
  // ED Shifts
  // =========================================================================

  app.post('/api/v1/shifts', {
    schema: { body: createShiftSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_CREATE')],
    handler: handlers.createShiftHandler,
  });

  app.post('/api/v1/shifts/:id/encounters', {
    schema: { body: addEncounterSchema, params: shiftIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_CREATE')],
    handler: handlers.addEncounterHandler,
  });

  app.put('/api/v1/shifts/:id/complete', {
    schema: { params: shiftIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_EDIT')],
    handler: handlers.completeShiftHandler,
  });

  app.get('/api/v1/shifts/:id', {
    schema: { params: shiftIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_VIEW')],
    handler: handlers.getShiftHandler,
  });

  // =========================================================================
  // Data Export
  // =========================================================================

  app.post('/api/v1/exports', {
    schema: { body: createExportSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_VIEW')],
    handler: handlers.requestExportHandler,
  });

  app.get('/api/v1/exports/:id', {
    schema: { params: claimExportIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_VIEW')],
    handler: handlers.getExportHandler,
  });

  // =========================================================================
  // Submission Preferences
  // =========================================================================

  app.get('/api/v1/submission-preferences', {
    preHandler: [app.authenticate, app.authorize('CLAIM_VIEW')],
    handler: handlers.getPreferencesHandler,
  });

  app.put('/api/v1/submission-preferences', {
    schema: { body: updateSubmissionModeSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_EDIT')],
    handler: handlers.updatePreferencesHandler,
  });

  // =========================================================================
  // Claim Templates (MVPADD-001 §4.1)
  // =========================================================================

  app.get('/api/v1/claims/templates', {
    schema: { querystring: listClaimTemplatesQuerySchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_VIEW')],
    handler: handlers.listClaimTemplatesHandler,
  });

  app.post('/api/v1/claims/templates', {
    schema: { body: createClaimTemplateSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_CREATE')],
    handler: handlers.createClaimTemplateHandler,
  });

  app.put('/api/v1/claims/templates/:id', {
    schema: { body: updateClaimTemplateSchema, params: claimTemplateIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_EDIT')],
    handler: handlers.updateClaimTemplateHandler,
  });

  app.delete('/api/v1/claims/templates/:id', {
    schema: { params: claimTemplateIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_DELETE')],
    handler: handlers.deleteClaimTemplateHandler,
  });

  app.post('/api/v1/claims/templates/:id/apply', {
    schema: { body: applyClaimTemplateSchema, params: claimTemplateIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_CREATE')],
    handler: handlers.applyClaimTemplateHandler,
  });

  app.put('/api/v1/claims/templates/reorder', {
    schema: { body: reorderClaimTemplatesSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_EDIT')],
    handler: handlers.reorderClaimTemplatesHandler,
  });

  // =========================================================================
  // Claim Justifications (MVPADD-001 §4.4)
  // =========================================================================

  app.post('/api/v1/claims/:id/justification', {
    schema: { body: createJustificationSchema, params: claimIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_EDIT')],
    handler: handlers.createJustificationHandler,
  });

  app.get('/api/v1/claims/:id/justification', {
    schema: { params: claimIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_VIEW')],
    handler: handlers.getJustificationHandler,
  });

  app.get('/api/v1/claims/justifications/history', {
    schema: { querystring: justificationHistoryQuerySchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_VIEW')],
    handler: handlers.justificationHistoryHandler,
  });

  app.post('/api/v1/claims/justifications/:id/save-personal', {
    schema: { params: justificationIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_EDIT')],
    handler: handlers.saveJustificationAsTemplateHandler,
  });

  // =========================================================================
  // Recent Referrers (MVPADD-001 §2.1.2)
  // =========================================================================

  app.get('/api/v1/claims/referrers/recent', {
    preHandler: [app.authenticate, app.authorize('CLAIM_VIEW')],
    handler: handlers.listRecentReferrersHandler,
  });

  app.post('/api/v1/claims/referrers/recent', {
    schema: { body: recordRecentReferrerSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_CREATE')],
    handler: handlers.recordRecentReferrerHandler,
  });

  // =========================================================================
  // Bundling Check (MVPADD-001 §4.3.2)
  // =========================================================================

  app.post('/api/v1/claims/bundling/check', {
    schema: { body: bundlingCheckSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_VIEW')],
    handler: handlers.bundlingCheckHandler,
  });

  // =========================================================================
  // Anesthesia Calculator (MVPADD-001 §4.2.2)
  // =========================================================================

  app.post('/api/v1/claims/anesthesia/calculate', {
    schema: { body: anesthesiaCalculateSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_VIEW')],
    handler: handlers.anesthesiaCalculateHandler,
  });

  // =========================================================================
  // Connect Care Import (FRD CC-001 §4)
  // =========================================================================

  app.post('/api/v1/claims/connect-care/import', {
    schema: { body: uploadSccExtractSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_CREATE')],
    handler: handlers.uploadConnectCareImportHandler,
  });

  app.get('/api/v1/claims/connect-care/import/history', {
    schema: { querystring: listSccImportsQuerySchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_VIEW')],
    handler: handlers.connectCareImportHistoryHandler,
  });

  app.get('/api/v1/claims/connect-care/import/:id', {
    schema: { params: sccImportIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_VIEW')],
    handler: handlers.getConnectCareImportHandler,
  });

  app.post('/api/v1/claims/connect-care/import/:id/confirm', {
    schema: { body: confirmSccImportSchema, params: sccImportIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_CREATE')],
    handler: handlers.confirmConnectCareImportHandler,
  });

  app.post('/api/v1/claims/connect-care/import/:id/cancel', {
    schema: { params: sccImportIdParamSchema },
    preHandler: [app.authenticate, app.authorize('CLAIM_EDIT')],
    handler: handlers.cancelConnectCareImportHandler,
  });

  // =========================================================================
  // Reconciliation (MOB-002 §5.1–5.9)
  // =========================================================================

  app.post('/api/v1/claims/connect-care/reconcile', {
    schema: {
      body: z.object({
        batch_id: z.string().uuid(),
      }),
    },
    preHandler: [app.authenticate, app.authorize('CLAIM_CREATE')],
    handler: handlers.triggerReconciliationHandler,
  });

  app.get('/api/v1/claims/connect-care/reconcile/:batchId', {
    schema: {
      params: z.object({ batchId: z.string().uuid() }),
    },
    preHandler: [app.authenticate, app.authorize('CLAIM_VIEW')],
    handler: handlers.getReconciliationResultHandler,
  });

  app.post('/api/v1/claims/connect-care/reconcile/:batchId/confirm', {
    schema: {
      params: z.object({ batchId: z.string().uuid() }),
    },
    preHandler: [app.authenticate, app.authorize('CLAIM_CREATE')],
    handler: handlers.confirmReconciliationHandler,
  });

  app.post('/api/v1/claims/connect-care/reconcile/:batchId/resolve-time', {
    schema: {
      params: z.object({ batchId: z.string().uuid() }),
      body: z.object({
        claim_id: z.string().uuid(),
        inferred_service_time: z.string().datetime(),
      }),
    },
    preHandler: [app.authenticate, app.authorize('CLAIM_CREATE')],
    handler: handlers.resolveTimeHandler,
  });

  app.post('/api/v1/claims/connect-care/reconcile/:batchId/resolve-partial', {
    schema: {
      params: z.object({ batchId: z.string().uuid() }),
      body: z.object({
        encounter_id: z.string().uuid(),
        claim_id: z.string().uuid(),
      }),
    },
    preHandler: [app.authenticate, app.authorize('CLAIM_CREATE')],
    handler: handlers.resolvePartialPhnHandler,
  });
}
