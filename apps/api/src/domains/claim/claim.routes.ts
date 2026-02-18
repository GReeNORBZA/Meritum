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
} from '@meritum/shared/schemas/claim.schema.js';
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
}
