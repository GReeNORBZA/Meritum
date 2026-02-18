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
} from '@meritum/shared/schemas/claim.schema.js';
import { ActorContext } from '@meritum/shared/constants/claim.constants.js';
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
  };
}
