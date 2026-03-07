import { type FastifyRequest, type FastifyReply } from 'fastify';
import {
  type CreateClaim,
  type UpdateClaim,
  type ClaimIdParam,
  type ListClaims,
  type WriteOffClaim,
  type DismissSuggestion,
  type SuggestionIdParam,
  type CreateImport,
  type ClaimImportIdParam,
  type CreateTemplate,
  type UpdateTemplate,
  type TemplateIdParam,
  type CreateShift,
  type AddEncounter,
  type ShiftIdParam,
  type CreateExport,
  type ClaimExportIdParam,
  type UpdateSubmissionMode,
  type CreateClaimTemplate,
  type UpdateClaimTemplate,
  type ClaimTemplateIdParam,
  type ListClaimTemplatesQuery,
  type ApplyClaimTemplate,
  type ReorderClaimTemplates,
  type CreateJustification,
  type UpdateJustification,
  type JustificationIdParam,
  type JustificationHistoryQuery,
  type RecordRecentReferrer,
  type BundlingCheck,
  type AnesthesiaCalculate,
} from '@meritum/shared/schemas/claim.schema.js';
import { ActorContext } from '@meritum/shared/constants/claim.constants.js';
import {
  type UploadSccExtract,
  type SccImportIdParam,
  type ConfirmSccImport,
  type ListSccImportsQuery,
} from '@meritum/shared/schemas/scc.schema.js';
import {
  uploadAndParse,
  confirmImport as confirmCcImport,
  cancelImport as cancelCcImport,
  getImportHistory,
  getImportBatchDetail,
  type ConnectCareImportDeps,
} from './connect-care-import.service.js';
import {
  reconcileImportWithShift,
  confirmReconciliation as confirmReconciliationService,
  resolveUnmatchedTime as resolveUnmatchedTimeService,
  resolvePartialPhn as resolvePartialPhnService,
  ReconciliationError,
  type ReconciliationDeps,
} from './reconciliation.service.js';
import {
  createClaim,
  validateClaim,
  queueClaim,
  unqueueClaim,
  writeOffClaim,
  resubmitClaim,
  getClaimSuggestions,
  acceptSuggestion,
  dismissSuggestion,
  listRejectedClaims,
  getRejectionDetails,
  uploadImport,
  previewImport,
  commitImport,
  createShift,
  addEncounter,
  completeShift,
  getShiftDetails,
  requestExport,
  getExportStatus,
  getSubmissionPreferences,
  updateSubmissionPreferences,
  listRecentReferrers,
  recordRecentReferrer,
  listClaimTemplates,
  createClaimTemplate,
  updateClaimTemplate,
  deleteClaimTemplate,
  applyClaimTemplate,
  createJustification,
  getJustificationForClaim,
  updateJustification as updateJustificationService,
  searchJustificationHistory,
  saveJustificationAsPersonalTemplate,
  checkBundlingConflicts,
  calculateAnesthesiaBenefit,
  type ClaimServiceDeps,
} from './claim.service.js';

// ---------------------------------------------------------------------------
// Handler dependencies
// ---------------------------------------------------------------------------

export interface ClaimHandlerDeps {
  serviceDeps: ClaimServiceDeps;
}

// ---------------------------------------------------------------------------
// Helper: extract physicianId from auth context
// ---------------------------------------------------------------------------

function getPhysicianId(request: FastifyRequest): string {
  const ctx = request.authContext;
  if (ctx.role?.toUpperCase() === 'DELEGATE' && (ctx as any).delegateContext) {
    return (ctx as any).delegateContext.physicianProviderId;
  }
  return ctx.userId;
}

function getActorContext(request: FastifyRequest): string {
  const ctx = request.authContext;
  if (ctx.role?.toUpperCase() === 'DELEGATE') {
    return ActorContext.DELEGATE;
  }
  return ActorContext.PHYSICIAN;
}

// ---------------------------------------------------------------------------
// Handler factory
// ---------------------------------------------------------------------------

export function createClaimHandlers(deps: ClaimHandlerDeps) {
  const { serviceDeps } = deps;

  // =========================================================================
  // Claim CRUD
  // =========================================================================

  async function createClaimHandler(
    request: FastifyRequest<{ Body: CreateClaim }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const body = request.body;

    const result = await createClaim(
      serviceDeps,
      physicianId,
      request.authContext.userId,
      getActorContext(request),
      {
        claimType: body.claim_type,
        patientId: body.patient_id,
        dateOfService: body.date_of_service,
        importSource: body.import_source,
      },
    );

    return reply.code(201).send({ data: result });
  }

  async function listClaimsHandler(
    request: FastifyRequest<{ Querystring: ListClaims }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const query = request.query;

    const result = await serviceDeps.repo.listClaims(physicianId, {
      state: query.state,
      claimType: query.claim_type,
      dateFrom: query.date_from,
      dateTo: query.date_to,
      patientId: query.patient_id,
      isClean: query.is_clean,
      page: query.page,
      pageSize: query.page_size,
    });

    return reply.code(200).send({
      data: result.data,
      pagination: result.pagination,
    });
  }

  async function getClaimHandler(
    request: FastifyRequest<{ Params: ClaimIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;

    const claim = await serviceDeps.repo.findClaimById(id, physicianId);
    if (!claim) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    return reply.code(200).send({ data: claim });
  }

  async function updateClaimHandler(
    request: FastifyRequest<{ Body: UpdateClaim; Params: ClaimIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;
    const body = request.body;

    const existing = await serviceDeps.repo.findClaimById(id, physicianId);
    if (!existing) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    const updateData: Record<string, unknown> = {};
    if (body.patient_id !== undefined) updateData.patientId = body.patient_id;
    if (body.date_of_service !== undefined) updateData.dateOfService = body.date_of_service;
    if (body.import_source !== undefined) updateData.importSource = body.import_source;
    updateData.updatedBy = request.authContext.userId;

    const updated = await serviceDeps.repo.updateClaim(id, physicianId, updateData as any);

    return reply.code(200).send({ data: updated });
  }

  async function deleteClaimHandler(
    request: FastifyRequest<{ Params: ClaimIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;

    const existing = await serviceDeps.repo.findClaimById(id, physicianId);
    if (!existing) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    if ((existing as any).state !== 'DRAFT') {
      return reply.code(409).send({
        error: { code: 'CONFLICT', message: 'Only draft claims can be deleted' },
      });
    }

    const deleted = await serviceDeps.repo.softDeleteClaim(id, physicianId);
    if (!deleted) {
      return reply.code(409).send({
        error: { code: 'CONFLICT', message: 'Only draft claims can be deleted' },
      });
    }

    return reply.code(204).send();
  }

  // =========================================================================
  // State Transitions
  // =========================================================================

  async function validateClaimHandler(
    request: FastifyRequest<{ Params: ClaimIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;

    const result = await validateClaim(
      serviceDeps,
      id,
      physicianId,
      request.authContext.userId,
      getActorContext(request),
    );

    return reply.code(200).send({ data: result });
  }

  async function queueClaimHandler(
    request: FastifyRequest<{ Params: ClaimIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;

    const result = await queueClaim(
      serviceDeps,
      id,
      physicianId,
      request.authContext.userId,
      getActorContext(request),
    );

    return reply.code(200).send({ data: result });
  }

  async function unqueueClaimHandler(
    request: FastifyRequest<{ Params: ClaimIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;

    await unqueueClaim(
      serviceDeps,
      id,
      physicianId,
      request.authContext.userId,
    );

    return reply.code(200).send({ data: { success: true } });
  }

  async function writeOffHandler(
    request: FastifyRequest<{ Params: ClaimIdParam; Body: WriteOffClaim }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;
    const { reason } = request.body;

    await writeOffClaim(
      serviceDeps,
      id,
      physicianId,
      request.authContext.userId,
      reason,
    );

    return reply.code(200).send({ data: { success: true } });
  }

  async function resubmitHandler(
    request: FastifyRequest<{ Params: ClaimIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;

    const result = await resubmitClaim(
      serviceDeps,
      id,
      physicianId,
      request.authContext.userId,
    );

    return reply.code(200).send({ data: result });
  }

  // =========================================================================
  // AI Coach
  // =========================================================================

  async function getSuggestionsHandler(
    request: FastifyRequest<{ Params: ClaimIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;

    const result = await getClaimSuggestions(serviceDeps, id, physicianId);

    return reply.code(200).send({ data: result });
  }

  async function acceptSuggestionHandler(
    request: FastifyRequest<{ Params: ClaimIdParam & SuggestionIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id, sug_id } = request.params;

    await acceptSuggestion(
      serviceDeps,
      id,
      sug_id,
      physicianId,
      request.authContext.userId,
    );

    return reply.code(200).send({ data: { success: true } });
  }

  async function dismissSuggestionHandler(
    request: FastifyRequest<{ Params: ClaimIdParam & SuggestionIdParam; Body: DismissSuggestion }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id, sug_id } = request.params;
    const { reason } = request.body;

    await dismissSuggestion(
      serviceDeps,
      id,
      sug_id,
      physicianId,
      request.authContext.userId,
      reason,
    );

    return reply.code(200).send({ data: { success: true } });
  }

  // =========================================================================
  // Rejection Management
  // =========================================================================

  async function listRejectedHandler(
    request: FastifyRequest<{ Querystring: { page?: number; page_size?: number } }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const page = (request.query as any).page ?? 1;
    const pageSize = (request.query as any).page_size ?? 25;

    const result = await listRejectedClaims(serviceDeps, physicianId, page, pageSize);

    return reply.code(200).send({
      data: result.data,
      pagination: result.pagination,
    });
  }

  async function rejectionDetailsHandler(
    request: FastifyRequest<{ Params: ClaimIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;

    const details = await getRejectionDetails(serviceDeps, id, physicianId);
    if (!details) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    return reply.code(200).send({ data: details });
  }

  // =========================================================================
  // Claim Audit
  // =========================================================================

  async function claimAuditHandler(
    request: FastifyRequest<{ Params: ClaimIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;

    const history = await serviceDeps.repo.getClaimAuditHistory(id, physicianId);

    return reply.code(200).send({ data: history });
  }

  // =========================================================================
  // EMR Import
  // =========================================================================

  async function uploadImportHandler(
    request: FastifyRequest<{ Body: CreateImport }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);

    // Extract file from multipart or JSON body fallback
    const file = (request as any).file;
    const fileName = file?.filename ?? file?.fileName ?? 'upload.csv';
    const content = file?.data ?? file?.content ?? '';

    const result = await uploadImport(
      serviceDeps,
      physicianId,
      request.authContext.userId,
      { fileName, content },
      request.body?.field_mapping_template_id,
    );

    return reply.code(201).send({ data: result });
  }

  async function getImportHandler(
    request: FastifyRequest<{ Params: ClaimImportIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;

    const batch = await serviceDeps.repo.findImportBatchById(id, physicianId);
    if (!batch) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    return reply.code(200).send({ data: batch });
  }

  async function previewImportHandler(
    request: FastifyRequest<{ Params: ClaimImportIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;

    // File content must be re-provided or cached. For the handler layer,
    // we accept it from the request body or from a cached source.
    const fileContent = (request.body as any)?.file_content ?? '';

    const result = await previewImport(serviceDeps, id, physicianId, fileContent);

    return reply.code(200).send({ data: result });
  }

  async function commitImportHandler(
    request: FastifyRequest<{ Params: ClaimImportIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;

    const fileContent = (request.body as any)?.file_content ?? '';

    const result = await commitImport(
      serviceDeps,
      id,
      physicianId,
      request.authContext.userId,
      fileContent,
    );

    return reply.code(200).send({ data: result });
  }

  // =========================================================================
  // Field Mapping Templates
  // =========================================================================

  async function createTemplateHandler(
    request: FastifyRequest<{ Body: CreateTemplate }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const body = request.body;

    const template = await serviceDeps.repo.createTemplate({
      physicianId,
      name: body.name,
      emrType: body.emr_type ?? null,
      mappings: body.mappings,
      delimiter: body.delimiter ?? ',',
      hasHeaderRow: body.has_header_row,
      dateFormat: body.date_format ?? null,
    } as any);

    return reply.code(201).send({ data: template });
  }

  async function listTemplatesHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);

    const templates = await serviceDeps.repo.listTemplates(physicianId);

    return reply.code(200).send({ data: templates });
  }

  async function updateTemplateHandler(
    request: FastifyRequest<{ Body: UpdateTemplate; Params: TemplateIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;

    const existing = await serviceDeps.repo.findTemplateById(id, physicianId);
    if (!existing) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    const body = request.body;
    const updateData: Record<string, unknown> = {};
    if (body.name !== undefined) updateData.name = body.name;
    if (body.emr_type !== undefined) updateData.emrType = body.emr_type;
    if (body.mappings !== undefined) updateData.mappings = body.mappings;
    if (body.delimiter !== undefined) updateData.delimiter = body.delimiter;
    if (body.has_header_row !== undefined) updateData.hasHeaderRow = body.has_header_row;
    if (body.date_format !== undefined) updateData.dateFormat = body.date_format;

    const updated = await serviceDeps.repo.updateTemplate(id, physicianId, updateData as any);

    return reply.code(200).send({ data: updated });
  }

  async function deleteTemplateHandler(
    request: FastifyRequest<{ Params: TemplateIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;

    const existing = await serviceDeps.repo.findTemplateById(id, physicianId);
    if (!existing) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    await serviceDeps.repo.deleteTemplate(id, physicianId);

    return reply.code(204).send();
  }

  // =========================================================================
  // ED Shifts
  // =========================================================================

  async function createShiftHandler(
    request: FastifyRequest<{ Body: CreateShift }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const body = request.body;

    const result = await createShift(serviceDeps, physicianId, {
      facilityId: body.facility_id,
      shiftDate: body.shift_date,
      startTime: body.start_time,
      endTime: body.end_time,
    });

    return reply.code(201).send({ data: result });
  }

  async function addEncounterHandler(
    request: FastifyRequest<{ Body: AddEncounter; Params: ShiftIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;
    const body = request.body;

    const result = await addEncounter(
      serviceDeps,
      physicianId,
      request.authContext.userId,
      id,
      {
        patientId: body.patient_id,
        dateOfService: body.date_of_service,
        claimType: body.claim_type,
      },
    );

    return reply.code(201).send({ data: result });
  }

  async function completeShiftHandler(
    request: FastifyRequest<{ Params: ShiftIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;

    const result = await completeShift(serviceDeps, physicianId, id);

    return reply.code(200).send({ data: result });
  }

  async function getShiftHandler(
    request: FastifyRequest<{ Params: ShiftIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;

    const result = await getShiftDetails(serviceDeps, physicianId, id);

    return reply.code(200).send({ data: result });
  }

  // =========================================================================
  // Data Export
  // =========================================================================

  async function requestExportHandler(
    request: FastifyRequest<{ Body: CreateExport }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const body = request.body;

    const result = await requestExport(serviceDeps, physicianId, {
      dateFrom: body.date_from,
      dateTo: body.date_to,
      claimType: body.claim_type,
      format: body.format,
    });

    return reply.code(201).send({ data: result });
  }

  async function getExportHandler(
    request: FastifyRequest<{ Params: ClaimExportIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;

    const result = await getExportStatus(serviceDeps, id, physicianId);
    if (!result) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    return reply.code(200).send({ data: result });
  }

  // =========================================================================
  // Submission Preferences
  // =========================================================================

  async function getPreferencesHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);

    const result = await getSubmissionPreferences(serviceDeps, physicianId);

    return reply.code(200).send({ data: result });
  }

  async function updatePreferencesHandler(
    request: FastifyRequest<{ Body: UpdateSubmissionMode }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { mode } = request.body;

    await updateSubmissionPreferences(
      serviceDeps,
      physicianId,
      request.authContext.userId,
      mode,
    );

    return reply.code(200).send({ data: { success: true } });
  }

  // =========================================================================
  // Recent Referrers (MVPADD-001 §2.1.2)
  // =========================================================================

  async function listRecentReferrersHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const referrers = await listRecentReferrers(serviceDeps, physicianId);
    return reply.code(200).send({ data: referrers });
  }

  async function recordRecentReferrerHandler(
    request: FastifyRequest<{ Body: RecordRecentReferrer }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { referrer_cpsa, referrer_name } = request.body;
    const referrer = await recordRecentReferrer(
      serviceDeps,
      physicianId,
      referrer_cpsa,
      referrer_name,
    );
    return reply.code(201).send({ data: referrer });
  }

  // =========================================================================
  // Claim Templates (MVPADD-001 §4.1)
  // =========================================================================

  async function listClaimTemplatesHandler(
    request: FastifyRequest<{ Querystring: ListClaimTemplatesQuery }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const query = request.query;
    const result = await listClaimTemplates(serviceDeps, physicianId, {
      templateType: query.template_type,
      claimType: query.claim_type,
      page: query.page,
      pageSize: query.page_size,
    });
    return reply.code(200).send({ data: result.data, pagination: result.pagination });
  }

  async function createClaimTemplateHandler(
    request: FastifyRequest<{ Body: CreateClaimTemplate }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const body = request.body;
    const template = await createClaimTemplate(
      serviceDeps,
      physicianId,
      request.authContext.userId,
      {
        name: body.name,
        description: body.description,
        templateType: body.template_type,
        claimType: body.claim_type,
        lineItems: body.line_items as Record<string, unknown>[],
        specialtyCode: body.specialty_code,
      },
    );
    return reply.code(201).send({ data: template });
  }

  async function updateClaimTemplateHandler(
    request: FastifyRequest<{ Body: UpdateClaimTemplate; Params: ClaimTemplateIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;
    const body = request.body;
    const updated = await updateClaimTemplate(serviceDeps, physicianId, id, {
      name: body.name,
      description: body.description,
      lineItems: body.line_items as Record<string, unknown>[] | undefined,
    });
    return reply.code(200).send({ data: updated });
  }

  async function deleteClaimTemplateHandler(
    request: FastifyRequest<{ Params: ClaimTemplateIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;
    await deleteClaimTemplate(serviceDeps, physicianId, id);
    return reply.code(204).send();
  }

  async function applyClaimTemplateHandler(
    request: FastifyRequest<{ Params: ClaimTemplateIdParam; Body: ApplyClaimTemplate }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;
    const { patient_id, date_of_service, auto_submit } = request.body;
    const result = await applyClaimTemplate(
      serviceDeps,
      physicianId,
      request.authContext.userId,
      getActorContext(request),
      id,
      patient_id,
      date_of_service,
      auto_submit,
    );
    return reply.code(201).send({ data: result });
  }

  async function reorderClaimTemplatesHandler(
    request: FastifyRequest<{ Body: ReorderClaimTemplates }>,
    reply: FastifyReply,
  ) {
    // Reorder is a no-op in the current implementation — templates are sorted by usage_count.
    // This endpoint exists for future drag-and-drop ordering support.
    return reply.code(200).send({ data: { success: true } });
  }

  // =========================================================================
  // Claim Justifications (MVPADD-001 §4.4)
  // =========================================================================

  async function createJustificationHandler(
    request: FastifyRequest<{ Params: ClaimIdParam; Body: CreateJustification }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const body = request.body;
    const justification = await createJustification(
      serviceDeps,
      physicianId,
      request.authContext.userId,
      {
        claimId: request.params.id,
        scenario: body.scenario,
        justificationText: body.justification_text,
        templateId: body.template_id,
      },
    );
    return reply.code(201).send({ data: justification });
  }

  async function getJustificationHandler(
    request: FastifyRequest<{ Params: ClaimIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;
    const justification = await getJustificationForClaim(serviceDeps, physicianId, id);
    if (!justification) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'No justification found for this claim' },
      });
    }
    return reply.code(200).send({ data: justification });
  }

  async function updateJustificationHandler(
    request: FastifyRequest<{ Params: JustificationIdParam; Body: UpdateJustification }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;
    const updated = await updateJustificationService(
      serviceDeps,
      physicianId,
      id,
      request.body.justification_text,
    );
    return reply.code(200).send({ data: updated });
  }

  async function justificationHistoryHandler(
    request: FastifyRequest<{ Querystring: JustificationHistoryQuery }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const query = request.query;
    const result = await searchJustificationHistory(serviceDeps, physicianId, {
      scenario: query.scenario,
      page: query.page,
      pageSize: query.page_size,
    });
    return reply.code(200).send({ data: result.data, pagination: result.pagination });
  }

  async function saveJustificationAsTemplateHandler(
    request: FastifyRequest<{ Params: JustificationIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;
    const result = await saveJustificationAsPersonalTemplate(serviceDeps, physicianId, id);
    return reply.code(200).send({ data: result });
  }

  // =========================================================================
  // Bundling Check (MVPADD-001 §4.3.2)
  // =========================================================================

  async function bundlingCheckHandler(
    request: FastifyRequest<{ Body: BundlingCheck }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { codes, claim_type, patient_id, date_of_service } = request.body;
    const result = await checkBundlingConflicts(
      serviceDeps,
      physicianId,
      codes,
      claim_type,
      patient_id,
      date_of_service,
    );
    return reply.code(200).send({ data: result });
  }

  // =========================================================================
  // Anesthesia Calculator (MVPADD-001 §4.2.2)
  // =========================================================================

  async function anesthesiaCalculateHandler(
    request: FastifyRequest<{ Body: AnesthesiaCalculate }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { procedure_codes, start_time, end_time, duration_minutes } = request.body;
    const result = await calculateAnesthesiaBenefit(
      serviceDeps,
      physicianId,
      procedure_codes,
      start_time,
      end_time,
      duration_minutes,
    );
    return reply.code(200).send({ data: result });
  }

  // =========================================================================
  // Connect Care Import (FRD CC-001 §4)
  // =========================================================================

  async function uploadConnectCareImportHandler(
    request: FastifyRequest<{ Body: UploadSccExtract }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const actorId = request.authContext.userId;

    // Multipart file is attached by Fastify multipart plugin
    const file = (request as any).uploadedFile;
    if (!file) {
      return reply.code(400).send({ error: 'No file uploaded' });
    }

    const ccDeps: ConnectCareImportDeps = {
      repo: serviceDeps.repo as any,
      duplicateCheck: serviceDeps.repo as any,
    };

    const providerCtx = {
      providerId: physicianId,
      billingNumber: (request.authContext as any).billingNumber ?? '',
      businessArrangements: (request.authContext as any).businessArrangements ?? [],
    };

    const result = await uploadAndParse(
      ccDeps,
      physicianId,
      actorId,
      providerCtx,
      {
        fileName: file.filename ?? file.fileName,
        content: file.content ?? file.data,
        size: file.size ?? (file.content ?? file.data).length,
      },
      request.body.extract_type,
    );

    return reply.code(201).send({ data: result });
  }

  async function getConnectCareImportHandler(
    request: FastifyRequest<{ Params: SccImportIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const ccDeps: ConnectCareImportDeps = {
      repo: serviceDeps.repo as any,
      duplicateCheck: serviceDeps.repo as any,
    };
    const batch = await getImportBatchDetail(ccDeps, physicianId, request.params.id);
    return reply.code(200).send({ data: batch });
  }

  async function confirmConnectCareImportHandler(
    request: FastifyRequest<{ Params: SccImportIdParam; Body: ConfirmSccImport }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const actorId = request.authContext.userId;
    const ccDeps: ConnectCareImportDeps = {
      repo: serviceDeps.repo as any,
      duplicateCheck: serviceDeps.repo as any,
    };

    // The parseResult was stored during upload — retrieve from batch
    const batch = await getImportBatchDetail(ccDeps, physicianId, request.params.id);
    const parseResult = (batch as any).parseResult;

    const result = await confirmCcImport(
      ccDeps,
      physicianId,
      actorId,
      request.params.id,
      parseResult,
      // excluded_row_ids from schema maps to excluded row numbers
      request.body.excluded_row_ids?.map((_id, idx) => idx) ?? [],
    );

    return reply.code(200).send({ data: result });
  }

  async function cancelConnectCareImportHandler(
    request: FastifyRequest<{ Params: SccImportIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const ccDeps: ConnectCareImportDeps = {
      repo: serviceDeps.repo as any,
      duplicateCheck: serviceDeps.repo as any,
    };
    const result = await cancelCcImport(ccDeps, physicianId, request.params.id);
    return reply.code(200).send({ data: result });
  }

  async function connectCareImportHistoryHandler(
    request: FastifyRequest<{ Querystring: ListSccImportsQuery }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const ccDeps: ConnectCareImportDeps = {
      repo: serviceDeps.repo as any,
      duplicateCheck: serviceDeps.repo as any,
    };
    const { page, page_size } = request.query;
    const result = await getImportHistory(ccDeps, physicianId, page, page_size);
    return reply.code(200).send({ data: result.data, pagination: result.pagination });
  }

  // =========================================================================
  // Reconciliation (MOB-002 §5.1–5.9)
  // =========================================================================

  async function triggerReconciliationHandler(
    request: FastifyRequest<{ Body: { batch_id: string } }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const reconcDeps: ReconciliationDeps = serviceDeps.repo as any;

    try {
      const result = await reconcileImportWithShift(
        reconcDeps,
        physicianId,
        request.body.batch_id,
      );
      return reply.code(200).send({ data: result });
    } catch (err) {
      if (err instanceof ReconciliationError) {
        return reply.code(400).send({ error: { code: 'RECONCILIATION_ERROR', message: err.message } });
      }
      throw err;
    }
  }

  async function getReconciliationResultHandler(
    request: FastifyRequest<{ Params: { batchId: string } }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const reconcDeps: ReconciliationDeps = serviceDeps.repo as any;

    const result = await reconcDeps.getReconciliationResult(
      request.params.batchId,
      physicianId,
    );

    if (!result) {
      return reply.code(404).send({ error: { code: 'NOT_FOUND', message: 'Reconciliation result not found' } });
    }

    return reply.code(200).send({ data: result });
  }

  async function confirmReconciliationHandler(
    request: FastifyRequest<{ Params: { batchId: string } }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const reconcDeps: ReconciliationDeps = serviceDeps.repo as any;

    try {
      const result = await confirmReconciliationService(
        reconcDeps,
        physicianId,
        request.params.batchId,
      );
      return reply.code(200).send({ data: result });
    } catch (err) {
      if (err instanceof ReconciliationError) {
        return reply.code(400).send({ error: { code: 'RECONCILIATION_ERROR', message: err.message } });
      }
      throw err;
    }
  }

  async function resolveTimeHandler(
    request: FastifyRequest<{
      Params: { batchId: string };
      Body: { claim_id: string; inferred_service_time: string };
    }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const reconcDeps: ReconciliationDeps = serviceDeps.repo as any;

    try {
      await resolveUnmatchedTimeService(
        reconcDeps,
        physicianId,
        request.params.batchId,
        request.body.claim_id,
        request.body.inferred_service_time,
      );
      return reply.code(200).send({ data: { resolved: true } });
    } catch (err) {
      if (err instanceof ReconciliationError) {
        return reply.code(400).send({ error: { code: 'RECONCILIATION_ERROR', message: err.message } });
      }
      throw err;
    }
  }

  async function resolvePartialPhnHandler(
    request: FastifyRequest<{
      Params: { batchId: string };
      Body: { encounter_id: string; claim_id: string };
    }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const reconcDeps: ReconciliationDeps = serviceDeps.repo as any;

    try {
      await resolvePartialPhnService(
        reconcDeps,
        physicianId,
        request.params.batchId,
        request.body.encounter_id,
        request.body.claim_id,
      );
      return reply.code(200).send({ data: { resolved: true } });
    } catch (err) {
      if (err instanceof ReconciliationError) {
        return reply.code(400).send({ error: { code: 'RECONCILIATION_ERROR', message: err.message } });
      }
      throw err;
    }
  }

  return {
    createClaimHandler,
    listClaimsHandler,
    getClaimHandler,
    updateClaimHandler,
    deleteClaimHandler,
    validateClaimHandler,
    queueClaimHandler,
    unqueueClaimHandler,
    writeOffHandler,
    resubmitHandler,
    getSuggestionsHandler,
    acceptSuggestionHandler,
    dismissSuggestionHandler,
    listRejectedHandler,
    rejectionDetailsHandler,
    claimAuditHandler,
    uploadImportHandler,
    getImportHandler,
    previewImportHandler,
    commitImportHandler,
    createTemplateHandler,
    listTemplatesHandler,
    updateTemplateHandler,
    deleteTemplateHandler,
    createShiftHandler,
    addEncounterHandler,
    completeShiftHandler,
    getShiftHandler,
    requestExportHandler,
    getExportHandler,
    getPreferencesHandler,
    updatePreferencesHandler,
    // Phase 5 extensions
    listRecentReferrersHandler,
    recordRecentReferrerHandler,
    listClaimTemplatesHandler,
    createClaimTemplateHandler,
    updateClaimTemplateHandler,
    deleteClaimTemplateHandler,
    applyClaimTemplateHandler,
    reorderClaimTemplatesHandler,
    createJustificationHandler,
    getJustificationHandler,
    updateJustificationHandler,
    justificationHistoryHandler,
    saveJustificationAsTemplateHandler,
    bundlingCheckHandler,
    anesthesiaCalculateHandler,
    // Phase 7: Connect Care Import
    uploadConnectCareImportHandler,
    getConnectCareImportHandler,
    confirmConnectCareImportHandler,
    cancelConnectCareImportHandler,
    connectCareImportHistoryHandler,
    // Phase 10: Reconciliation
    triggerReconciliationHandler,
    getReconciliationResultHandler,
    confirmReconciliationHandler,
    resolveTimeHandler,
    resolvePartialPhnHandler,
  };
}
