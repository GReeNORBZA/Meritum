import { type FastifyRequest, type FastifyReply } from 'fastify';
import { timingSafeEqual } from 'node:crypto';
import {
  type CreatePatient,
  type UpdatePatient,
  type PatientIdParam,
  type PatientSearchQuery,
  type RecentPatientsQuery,
  type ImportMapping,
  type ImportIdParam,
  type MergePreview,
  type MergeExecute,
  type ExportIdParam,
  type InternalPatientIdParam,
  type ValidatePhnParam,
  type CheckEligibility,
  type OverrideEligibility,
  type BulkCheckEligibility,
  type DetectProvince,
} from '@meritum/shared/schemas/patient.schema.js';
import { type PatientCorrection } from '@meritum/shared/schemas/compliance.schema.js';
import {
  createPatient,
  getPatient,
  updatePatient,
  correctPatient,
  deactivatePatient,
  reactivatePatient,
  searchPatients,
  getRecentPatients,
  initiateImport,
  getImportPreview,
  updateImportMapping,
  commitImport,
  getImportStatus,
  getMergePreview,
  executeMerge,
  requestExport,
  getExportStatus,
  exportPatientHealthInformation,
  getPatientAccessExportDownload,
  getPatientClaimContext,
  validatePhnService,
  checkEligibility,
  overrideEligibility,
  bulkCheckEligibility,
  detectPatientProvince,
  type PatientServiceDeps,
} from './patient.service.js';
import { ValidationError } from '../../lib/errors.js';

// ---------------------------------------------------------------------------
// Handler dependencies
// ---------------------------------------------------------------------------

export interface PatientHandlerDeps {
  serviceDeps: PatientServiceDeps;
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

// ---------------------------------------------------------------------------
// Handler factory
// ---------------------------------------------------------------------------

export function createPatientHandlers(deps: PatientHandlerDeps) {
  const { serviceDeps } = deps;

  // =========================================================================
  // CRUD Handlers
  // =========================================================================

  async function createPatientHandler(
    request: FastifyRequest<{ Body: CreatePatient }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const body = request.body;

    const patient = await createPatient(
      serviceDeps,
      physicianId,
      {
        phn: body.phn ?? undefined,
        phnProvince: body.phn_province,
        firstName: body.first_name,
        middleName: body.middle_name,
        lastName: body.last_name,
        dateOfBirth: body.date_of_birth,
        gender: body.gender,
        phone: body.phone,
        email: body.email,
        addressLine1: body.address_line_1,
        addressLine2: body.address_line_2,
        city: body.city,
        province: body.province,
        postalCode: body.postal_code,
        notes: body.notes,
      },
      request.authContext.userId,
    );

    return reply.code(201).send({ data: patient });
  }

  async function getPatientHandler(
    request: FastifyRequest<{ Params: PatientIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;

    const patient = await getPatient(serviceDeps, id, physicianId);
    if (!patient) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    return reply.code(200).send({ data: patient });
  }

  async function updatePatientHandler(
    request: FastifyRequest<{ Body: UpdatePatient; Params: PatientIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;
    const body = request.body;

    const updated = await updatePatient(
      serviceDeps,
      id,
      physicianId,
      {
        phn: body.phn,
        phnProvince: body.phn_province,
        firstName: body.first_name,
        middleName: body.middle_name,
        lastName: body.last_name,
        dateOfBirth: body.date_of_birth,
        gender: body.gender,
        phone: body.phone,
        email: body.email,
        addressLine1: body.address_line_1,
        addressLine2: body.address_line_2,
        city: body.city,
        province: body.province,
        postalCode: body.postal_code,
        notes: body.notes,
      },
      request.authContext.userId,
    );

    return reply.code(200).send({ data: updated });
  }

  async function deactivateHandler(
    request: FastifyRequest<{ Params: PatientIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;

    const deactivated = await deactivatePatient(
      serviceDeps,
      id,
      physicianId,
      request.authContext.userId,
    );

    return reply.code(200).send({ data: deactivated });
  }

  async function reactivateHandler(
    request: FastifyRequest<{ Params: PatientIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;

    const reactivated = await reactivatePatient(
      serviceDeps,
      id,
      physicianId,
      request.authContext.userId,
    );

    return reply.code(200).send({ data: reactivated });
  }

  // =========================================================================
  // Search Handlers
  // =========================================================================

  async function searchHandler(
    request: FastifyRequest<{ Querystring: PatientSearchQuery }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const query = request.query;

    const result = await searchPatients(
      serviceDeps,
      physicianId,
      {
        phn: query.phn,
        name: query.name,
        dob: query.dob,
        page: query.page,
        pageSize: query.page_size,
      },
      request.authContext.userId,
    );

    return reply.code(200).send({
      data: result.patients,
      pagination: {
        total: result.total,
        page: result.page,
        pageSize: result.page_size,
        hasMore: result.page * result.page_size < result.total,
      },
    });
  }

  async function recentHandler(
    request: FastifyRequest<{ Querystring: RecentPatientsQuery }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { limit } = request.query;

    const patients = await getRecentPatients(serviceDeps, physicianId, limit);

    return reply.code(200).send({ data: patients });
  }

  // =========================================================================
  // CSV Import Handlers
  // =========================================================================

  async function uploadHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);

    const data = await request.file();
    if (!data) {
      throw new ValidationError('No file uploaded');
    }

    // Validate file extension
    const fileName = data.filename ?? '';
    const ext = fileName.toLowerCase().split('.').pop();
    if (ext !== 'csv' && ext !== 'txt') {
      throw new ValidationError('Only .csv and .txt files are accepted');
    }

    // Validate content type (loose check — some systems send text/plain for CSV)
    const mime = data.mimetype ?? '';
    const allowedMimes = ['text/csv', 'text/plain', 'application/csv', 'application/vnd.ms-excel'];
    if (mime && !allowedMimes.includes(mime)) {
      throw new ValidationError('Only .csv and .txt files are accepted');
    }

    // Consume file buffer
    const chunks: Buffer[] = [];
    for await (const chunk of data.file) {
      chunks.push(chunk);
    }
    const fileBuffer = Buffer.concat(chunks);

    // Check if the stream was truncated (file exceeded limit)
    if (data.file.truncated) {
      throw new ValidationError('File exceeds maximum size of 10MB');
    }

    const result = await initiateImport(
      serviceDeps,
      physicianId,
      fileBuffer,
      fileName,
      request.authContext.userId,
    );

    return reply.code(201).send({ data: result });
  }

  async function previewHandler(
    request: FastifyRequest<{ Params: ImportIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;

    const preview = await getImportPreview(serviceDeps, id, physicianId);

    return reply.code(200).send({ data: preview });
  }

  async function mappingHandler(
    request: FastifyRequest<{ Params: ImportIdParam; Body: ImportMapping }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;
    const { mapping } = request.body;

    await updateImportMapping(serviceDeps, id, physicianId, mapping);

    return reply.code(200).send({ data: { success: true } });
  }

  async function commitHandler(
    request: FastifyRequest<{ Params: ImportIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;

    const result = await commitImport(
      serviceDeps,
      id,
      physicianId,
      request.authContext.userId,
    );

    return reply.code(200).send({ data: result });
  }

  async function statusHandler(
    request: FastifyRequest<{ Params: ImportIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;

    const status = await getImportStatus(serviceDeps, id, physicianId);

    return reply.code(200).send({ data: status });
  }

  // =========================================================================
  // Merge Handlers
  // =========================================================================

  async function mergePreviewHandler(
    request: FastifyRequest<{ Body: MergePreview }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { surviving_id, merged_id } = request.body;

    const preview = await getMergePreview(
      serviceDeps,
      physicianId,
      surviving_id,
      merged_id,
    );

    return reply.code(200).send({ data: preview });
  }

  async function mergeExecuteHandler(
    request: FastifyRequest<{ Body: MergeExecute }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { surviving_id, merged_id } = request.body;

    const result = await executeMerge(
      serviceDeps,
      physicianId,
      surviving_id,
      merged_id,
      request.authContext.userId,
    );

    return reply.code(200).send({ data: result });
  }

  // =========================================================================
  // Export Handlers
  // =========================================================================

  async function requestExportHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);

    const result = await requestExport(
      serviceDeps,
      physicianId,
      request.authContext.userId,
    );

    return reply.code(201).send({ data: result });
  }

  async function exportStatusHandler(
    request: FastifyRequest<{ Params: ExportIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;

    const status = await getExportStatus(
      serviceDeps,
      id,
      physicianId,
      request.authContext.userId,
    );

    return reply.code(200).send({ data: status });
  }

  // =========================================================================
  // Patient Access Request Export (IMA S74)
  // =========================================================================

  async function exportPatientHiHandler(
    request: FastifyRequest<{ Params: PatientIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;

    const result = await exportPatientHealthInformation(
      serviceDeps,
      physicianId,
      id,
      request.authContext.userId,
    );

    return reply.code(201).send({
      data: {
        exportId: result.exportId,
        downloadUrl: result.downloadUrl,
        expiresAt: result.expiresAt.toISOString(),
      },
    });
  }

  async function downloadPatientHiHandler(
    request: FastifyRequest<{ Params: { id: string; exportId: string } }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { exportId } = request.params;

    const result = await getPatientAccessExportDownload(
      serviceDeps,
      exportId,
      physicianId,
    );

    return reply
      .code(200)
      .header('Content-Type', 'application/zip')
      .header(
        'Content-Disposition',
        `attachment; filename="patient_${result.patientId}_export.zip"`,
      )
      .send(result.zipBuffer);
  }

  // =========================================================================
  // Correction Handler (IMA S3.10)
  // =========================================================================

  async function correctPatientHandler(
    request: FastifyRequest<{ Body: PatientCorrection; Params: PatientIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;
    const body = request.body;

    const corrected = await correctPatient(
      serviceDeps,
      id,
      physicianId,
      {
        correctionReason: body.correction_reason,
        phn: body.phn,
        firstName: body.first_name,
        middleName: body.middle_name,
        lastName: body.last_name,
        dateOfBirth: body.date_of_birth,
        gender: body.gender,
        phone: body.phone,
        email: body.email,
        addressLine1: body.address_line1,
        addressLine2: body.address_line2,
        city: body.city,
        province: body.province,
        postalCode: body.postal_code,
        notes: body.notes,
      },
      request.authContext.userId,
    );

    return reply.code(200).send({ data: corrected });
  }

  // =========================================================================
  // Eligibility Handlers (FRD MVPADD-001 §B2)
  // =========================================================================

  async function checkEligibilityHandler(
    request: FastifyRequest<{ Body: CheckEligibility }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { phn, date_of_service } = request.body;

    const result = await checkEligibility(
      serviceDeps,
      physicianId,
      phn,
      date_of_service,
      request.authContext.userId,
    );

    return reply.code(200).send({
      data: {
        phn_masked: result.phnMasked,
        is_eligible: result.isEligible,
        source: result.source,
        details: result.details,
        verified_at: result.verifiedAt.toISOString(),
      },
    });
  }

  async function overrideEligibilityHandler(
    request: FastifyRequest<{ Body: OverrideEligibility }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { phn, reason } = request.body;

    const result = await overrideEligibility(
      serviceDeps,
      physicianId,
      phn,
      reason,
      request.authContext.userId,
    );

    return reply.code(200).send({
      data: {
        phn_masked: result.phnMasked,
        overridden: result.overridden,
        reason: result.reason,
      },
    });
  }

  async function bulkCheckEligibilityHandler(
    request: FastifyRequest<{ Body: BulkCheckEligibility }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { entries } = request.body;

    const result = await bulkCheckEligibility(
      serviceDeps,
      physicianId,
      entries.map((e) => ({ phn: e.phn, dateOfService: e.date_of_service })),
      request.authContext.userId,
    );

    return reply.code(200).send({
      data: {
        results: result.results.map((r) => ({
          phn_masked: r.phnMasked,
          is_eligible: r.isEligible,
          source: r.source,
          details: r.details,
          verified_at: r.verifiedAt.toISOString(),
        })),
        summary: result.summary,
      },
    });
  }

  // =========================================================================
  // Province Detection Handler (FRD MVPADD-001 §3.2)
  // =========================================================================

  async function detectProvinceHandler(
    request: FastifyRequest<{ Body: DetectProvince }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { health_number } = request.body;

    const result = await detectPatientProvince(
      serviceDeps,
      physicianId,
      health_number,
      request.authContext.userId,
    );

    return reply.code(200).send({
      data: {
        detected_province: result.detectedProvince,
        confidence: result.confidence,
        is_out_of_province: result.isOutOfProvince,
        billing_mode: result.billingMode,
        reciprocal_eligible: result.reciprocalEligible,
      },
    });
  }

  return {
    createPatientHandler,
    getPatientHandler,
    updatePatientHandler,
    correctPatientHandler,
    deactivateHandler,
    reactivateHandler,
    searchHandler,
    recentHandler,
    uploadHandler,
    previewHandler,
    mappingHandler,
    commitHandler,
    statusHandler,
    mergePreviewHandler,
    mergeExecuteHandler,
    requestExportHandler,
    exportStatusHandler,
    exportPatientHiHandler,
    downloadPatientHiHandler,
    checkEligibilityHandler,
    overrideEligibilityHandler,
    bulkCheckEligibilityHandler,
    detectProvinceHandler,
  };
}

// ---------------------------------------------------------------------------
// Internal API key verification (service-to-service)
// ---------------------------------------------------------------------------

export function verifyInternalApiKey(
  request: FastifyRequest,
  reply: FastifyReply,
): boolean {
  const apiKey = request.headers['x-internal-api-key'] as string | undefined;
  const expectedKey = process.env.INTERNAL_API_KEY;

  if (!apiKey || !expectedKey) {
    reply.code(401).send({
      error: { code: 'UNAUTHORIZED', message: 'Authentication required' },
    });
    return false;
  }

  const keyBuffer = Buffer.from(apiKey);
  const expectedBuffer = Buffer.from(expectedKey);

  if (keyBuffer.length !== expectedBuffer.length) {
    reply.code(401).send({
      error: { code: 'UNAUTHORIZED', message: 'Authentication required' },
    });
    return false;
  }

  if (!timingSafeEqual(keyBuffer, expectedBuffer)) {
    reply.code(401).send({
      error: { code: 'UNAUTHORIZED', message: 'Authentication required' },
    });
    return false;
  }

  return true;
}

// ---------------------------------------------------------------------------
// Internal Patient Handlers (service-to-service, API key auth)
// ---------------------------------------------------------------------------

export interface InternalPatientHandlerDeps {
  serviceDeps: PatientServiceDeps;
}

export function createInternalPatientHandlers(deps: InternalPatientHandlerDeps) {
  const { serviceDeps } = deps;

  async function claimContextHandler(
    request: FastifyRequest<{ Params: InternalPatientIdParam }>,
    reply: FastifyReply,
  ) {
    if (!verifyInternalApiKey(request, reply)) return;

    const { id } = request.params;

    // Internal API requires physician context via query parameter
    const physicianId = (request.query as Record<string, string>).physician_id;
    if (!physicianId) {
      return reply.code(400).send({
        error: { code: 'VALIDATION_ERROR', message: 'physician_id query parameter is required' },
      });
    }

    const context = await getPatientClaimContext(serviceDeps, id, physicianId);

    if (!context) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    return reply.code(200).send({ data: context });
  }

  async function validatePhnHandler(
    request: FastifyRequest<{ Params: ValidatePhnParam }>,
    reply: FastifyReply,
  ) {
    if (!verifyInternalApiKey(request, reply)) return;

    const { phn } = request.params;

    // Internal API requires physician context via query parameter
    const physicianId = (request.query as Record<string, string>).physician_id;
    if (!physicianId) {
      return reply.code(400).send({
        error: { code: 'VALIDATION_ERROR', message: 'physician_id query parameter is required' },
      });
    }

    const result = await validatePhnService(serviceDeps, physicianId, phn);

    return reply.code(200).send({ data: result });
  }

  return {
    claimContextHandler,
    validatePhnHandler,
  };
}
