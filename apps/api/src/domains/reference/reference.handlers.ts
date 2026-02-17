import { type FastifyRequest, type FastifyReply } from 'fastify';
import {
  type HscSearch,
  type HscDetailParam,
  type HscDetailQuery,
  type DiSearch,
  type DiDetailParam,
  type ModifierLookup,
  type ModifierDetailParam,
  type FcList,
  type ExplCodeParam,
  type RrnpParam,
  type RrnpLookup,
  type PcpcmParam,
  type PcpcmLookup,
  type HolidayList,
  type HolidayCheck,
  type AdminUploadParam,
  type AdminStagingParam,
  type AdminPublish,
  type AdminVersionList,
  type CreateHoliday,
  type UpdateHoliday,
  type HolidayParam,
  type DryRun,
  type DryRunParam,
  type ValidateContext,
  type RuleDetail,
  type RuleDetailQuery,
  type VersionQuery,
  type EvaluateBatch,
  type ChangeList,
  type ChangeDetailParam,
  type ChangeDetailQuery,
} from '@meritum/shared/schemas/reference.schema.js';
import {
  searchHscCodes,
  getHscFavourites,
  getHscDetail,
  searchDiCodes,
  getDiDetail,
  getModifiersForHsc,
  getModifierDetail,
  getExplanatoryCode,
  getRrnpRate,
  getPcpcmBasket,
  listHolidays,
  isHoliday,
  resolveVersion,
  uploadDataSet,
  getStagingDiff,
  publishVersion,
  discardStaging,
  createHoliday,
  updateHoliday,
  deleteHoliday,
  dryRunRule,
  getValidationContext,
  getRuleDetail,
  evaluateRulesBatch,
  getChangeSummaries,
  getChangeDetail,
  getPhysicianImpact,
  type ReferenceServiceDeps,
} from './reference.service.js';
import { type ReferenceRepository } from './reference.repository.js';
import { ValidationError } from '../../lib/errors.js';

// ---------------------------------------------------------------------------
// Handler dependencies
// ---------------------------------------------------------------------------

export interface ReferenceHandlerDeps {
  serviceDeps: ReferenceServiceDeps;
}

// ---------------------------------------------------------------------------
// Handler factory
// ---------------------------------------------------------------------------

export function createReferenceHandlers(deps: ReferenceHandlerDeps) {
  const { serviceDeps } = deps;

  // -------------------------------------------------------------------------
  // GET /api/v1/ref/hsc/search
  // -------------------------------------------------------------------------

  async function searchHscHandler(
    request: FastifyRequest<{ Querystring: HscSearch }>,
    reply: FastifyReply,
  ) {
    const { q, specialty, facility, date, limit } = request.query;
    const results = await searchHscCodes(serviceDeps, q, {
      specialty,
      facility,
      dateOfService: date ? new Date(date) : undefined,
      limit,
    });
    return reply.send({ data: { results } });
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/ref/hsc/favourites
  // -------------------------------------------------------------------------

  async function hscFavouritesHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const userId = request.authContext.userId;
    const favourites = await getHscFavourites(serviceDeps, userId);
    return reply.send({ data: { favourites } });
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/ref/hsc/:code
  // -------------------------------------------------------------------------

  async function hscDetailHandler(
    request: FastifyRequest<{ Params: HscDetailParam; Querystring: HscDetailQuery }>,
    reply: FastifyReply,
  ) {
    const { code } = request.params;
    const { date } = request.query;
    const detail = await getHscDetail(
      serviceDeps,
      code,
      date ? new Date(date) : undefined,
    );
    return reply.send({ data: detail });
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/ref/di/search
  // -------------------------------------------------------------------------

  async function searchDiHandler(
    request: FastifyRequest<{ Querystring: DiSearch }>,
    reply: FastifyReply,
  ) {
    const { q, specialty, limit } = request.query;
    const results = await searchDiCodes(serviceDeps, q, {
      specialty,
      limit,
    });
    return reply.send({ data: { results } });
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/ref/di/:code
  // -------------------------------------------------------------------------

  async function diDetailHandler(
    request: FastifyRequest<{ Params: DiDetailParam }>,
    reply: FastifyReply,
  ) {
    const { code } = request.params;
    const detail = await getDiDetail(serviceDeps, code);
    return reply.send({ data: detail });
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/ref/modifiers
  // -------------------------------------------------------------------------

  async function modifierListHandler(
    request: FastifyRequest<{ Querystring: ModifierLookup }>,
    reply: FastifyReply,
  ) {
    const { hsc, date } = request.query;

    if (hsc) {
      const modifiers = await getModifiersForHsc(
        serviceDeps,
        hsc,
        date ? new Date(date) : undefined,
      );
      return reply.send({ data: { modifiers } });
    }

    // No HSC specified — list all modifiers from active version
    const { versionId } = await resolveVersion(serviceDeps, 'MODIFIERS', date ? new Date(date) : undefined);
    const allModifiers = await serviceDeps.repo.listAllModifiers(versionId);
    const modifiers = allModifiers.map((m) => ({
      modifierCode: m.modifierCode,
      name: m.name,
      description: m.description,
      type: m.type,
      calculationMethod: m.calculationMethod,
      calculationParams: (m.calculationParams ?? {}) as Record<string, unknown>,
      helpText: m.helpText ?? null,
    }));
    return reply.send({ data: { modifiers } });
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/ref/modifiers/:code
  // -------------------------------------------------------------------------

  async function modifierDetailHandler(
    request: FastifyRequest<{ Params: ModifierDetailParam }>,
    reply: FastifyReply,
  ) {
    const { code } = request.params;
    const detail = await getModifierDetail(serviceDeps, code);
    return reply.send({ data: detail });
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/ref/functional-centres
  // -------------------------------------------------------------------------

  async function fcListHandler(
    request: FastifyRequest<{ Querystring: FcList }>,
    reply: FastifyReply,
  ) {
    const { facility_type } = request.query;
    const { versionId } = await resolveVersion(serviceDeps, 'FUNCTIONAL_CENTRES');
    const centres = await serviceDeps.repo.listFunctionalCentres(versionId, facility_type);
    return reply.send({ data: { centres } });
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/ref/explanatory-codes/:code
  // -------------------------------------------------------------------------

  async function explCodeHandler(
    request: FastifyRequest<{ Params: ExplCodeParam }>,
    reply: FastifyReply,
  ) {
    const { code } = request.params;
    const detail = await getExplanatoryCode(serviceDeps, code);
    return reply.send({ data: detail });
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/ref/rrnp/:community_id
  // -------------------------------------------------------------------------

  async function rrnpHandler(
    request: FastifyRequest<{ Params: RrnpParam; Querystring: RrnpLookup }>,
    reply: FastifyReply,
  ) {
    const { community_id } = request.params;
    const { date } = request.query;
    const rate = await getRrnpRate(
      serviceDeps,
      community_id,
      date ? new Date(date) : undefined,
    );
    return reply.send({ data: rate });
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/ref/pcpcm/:hsc_code
  // -------------------------------------------------------------------------

  async function pcpcmHandler(
    request: FastifyRequest<{ Params: PcpcmParam; Querystring: PcpcmLookup }>,
    reply: FastifyReply,
  ) {
    const { hsc_code } = request.params;
    const { date } = request.query;
    const basket = await getPcpcmBasket(
      serviceDeps,
      hsc_code,
      date ? new Date(date) : undefined,
    );
    return reply.send({ data: basket });
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/ref/holidays
  // -------------------------------------------------------------------------

  async function holidayListHandler(
    request: FastifyRequest<{ Querystring: HolidayList }>,
    reply: FastifyReply,
  ) {
    const { year } = request.query;
    const holidays = await listHolidays(serviceDeps, year);
    return reply.send({ data: { holidays } });
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/ref/holidays/check
  // -------------------------------------------------------------------------

  async function holidayCheckHandler(
    request: FastifyRequest<{ Querystring: HolidayCheck }>,
    reply: FastifyReply,
  ) {
    const { date } = request.query;
    const result = await isHoliday(serviceDeps, new Date(date));
    return reply.send({ data: result });
  }

  // =========================================================================
  // Admin Handlers
  // =========================================================================

  // -------------------------------------------------------------------------
  // POST /api/v1/admin/ref/:dataset/upload
  // -------------------------------------------------------------------------

  const MAX_UPLOAD_SIZE = 50 * 1024 * 1024; // 50 MB
  const ALLOWED_CONTENT_TYPES = new Set([
    'text/csv',
    'application/json',
    'application/octet-stream',
  ]);

  async function uploadHandler(
    request: FastifyRequest<{ Params: AdminUploadParam }>,
    reply: FastifyReply,
  ) {
    const { dataset } = request.params;
    const adminUserId = request.authContext.userId;

    const file = await request.file();
    if (!file) {
      throw new ValidationError('No file uploaded');
    }

    // Validate content type
    if (!ALLOWED_CONTENT_TYPES.has(file.mimetype)) {
      throw new ValidationError(
        `Invalid content type: ${file.mimetype}. Accepted: text/csv, application/json, application/octet-stream`,
      );
    }

    // Read file buffer
    const chunks: Buffer[] = [];
    let totalSize = 0;
    for await (const chunk of file.file) {
      totalSize += chunk.length;
      if (totalSize > MAX_UPLOAD_SIZE) {
        throw new ValidationError('File exceeds maximum size of 50MB');
      }
      chunks.push(chunk);
    }

    // Check if the stream was truncated by fastify-multipart
    if (file.file.truncated) {
      throw new ValidationError('File exceeds maximum size of 50MB');
    }

    const fileBuffer = Buffer.concat(chunks);
    const fileName = file.filename;

    const result = await uploadDataSet(
      serviceDeps,
      adminUserId,
      dataset,
      fileBuffer,
      fileName,
    );

    return reply.code(200).send({ data: result });
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/admin/ref/:dataset/staging/:id/diff
  // -------------------------------------------------------------------------

  async function diffHandler(
    request: FastifyRequest<{ Params: AdminStagingParam }>,
    reply: FastifyReply,
  ) {
    const { dataset, id } = request.params;
    const adminUserId = request.authContext.userId;

    const diff = await getStagingDiff(serviceDeps, adminUserId, dataset, id);
    return reply.send({ data: diff });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/admin/ref/:dataset/staging/:id/publish
  // -------------------------------------------------------------------------

  async function publishHandler(
    request: FastifyRequest<{ Params: AdminStagingParam; Body: AdminPublish }>,
    reply: FastifyReply,
  ) {
    const { dataset, id } = request.params;
    const adminUserId = request.authContext.userId;
    const body = request.body;

    const result = await publishVersion(
      serviceDeps,
      adminUserId,
      dataset,
      id,
      {
        versionLabel: body.version_label,
        effectiveFrom: body.effective_from,
        sourceDocument: body.source_document,
        changeSummary: body.change_summary,
      },
    );

    return reply.code(201).send({ data: result });
  }

  // -------------------------------------------------------------------------
  // DELETE /api/v1/admin/ref/:dataset/staging/:id
  // -------------------------------------------------------------------------

  async function discardStagingHandler(
    request: FastifyRequest<{ Params: AdminStagingParam }>,
    reply: FastifyReply,
  ) {
    const { dataset, id } = request.params;
    const adminUserId = request.authContext.userId;

    await discardStaging(serviceDeps, adminUserId, dataset, id);
    return reply.send({ data: { success: true } });
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/admin/ref/:dataset/versions
  // -------------------------------------------------------------------------

  async function listVersionsHandler(
    request: FastifyRequest<{ Params: AdminVersionList }>,
    reply: FastifyReply,
  ) {
    const { dataset } = request.params;
    const versions = await serviceDeps.repo.listVersions(dataset);
    return reply.send({ data: { versions } });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/admin/ref/holidays
  // -------------------------------------------------------------------------

  async function createHolidayHandler(
    request: FastifyRequest<{ Body: CreateHoliday }>,
    reply: FastifyReply,
  ) {
    const adminUserId = request.authContext.userId;
    const result = await createHoliday(serviceDeps, adminUserId, request.body);
    return reply.code(201).send({ data: result });
  }

  // -------------------------------------------------------------------------
  // PUT /api/v1/admin/ref/holidays/:id
  // -------------------------------------------------------------------------

  async function updateHolidayHandler(
    request: FastifyRequest<{ Params: HolidayParam; Body: UpdateHoliday }>,
    reply: FastifyReply,
  ) {
    const adminUserId = request.authContext.userId;
    const { id } = request.params;
    const result = await updateHoliday(
      serviceDeps,
      adminUserId,
      id,
      request.body,
    );
    return reply.send({ data: result });
  }

  // -------------------------------------------------------------------------
  // DELETE /api/v1/admin/ref/holidays/:id
  // -------------------------------------------------------------------------

  async function deleteHolidayHandler(
    request: FastifyRequest<{ Params: HolidayParam }>,
    reply: FastifyReply,
  ) {
    const adminUserId = request.authContext.userId;
    const { id } = request.params;
    await deleteHoliday(serviceDeps, adminUserId, id);
    return reply.send({ data: { success: true } });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/admin/ref/rules/:rule_id/dry-run
  // -------------------------------------------------------------------------

  async function dryRunHandler(
    request: FastifyRequest<{ Params: DryRunParam; Body: DryRun }>,
    reply: FastifyReply,
  ) {
    const adminUserId = request.authContext.userId;
    const { rule_id } = request.params;
    const { updated_rule_logic } = request.body;

    const result = await dryRunRule(
      serviceDeps,
      adminUserId,
      rule_id,
      updated_rule_logic,
    );

    return reply.send({ data: result });
  }

  // =========================================================================
  // Internal Validation Handlers
  // =========================================================================

  // -------------------------------------------------------------------------
  // GET /api/v1/ref/rules/validate-context
  // -------------------------------------------------------------------------

  async function validateContextHandler(
    request: FastifyRequest<{ Querystring: ValidateContext }>,
    reply: FastifyReply,
  ) {
    const { hsc, di, facility, date, modifiers } = request.query;
    const result = await getValidationContext(
      serviceDeps,
      hsc,
      di ?? null,
      facility ?? null,
      new Date(date),
      modifiers,
    );
    return reply.send({ data: result });
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/ref/rules/:rule_id
  // -------------------------------------------------------------------------

  async function ruleDetailHandler(
    request: FastifyRequest<{ Params: RuleDetail; Querystring: RuleDetailQuery }>,
    reply: FastifyReply,
  ) {
    const { rule_id } = request.params;
    const { date } = request.query;
    const result = await getRuleDetail(
      serviceDeps,
      rule_id,
      date ? new Date(date) : undefined,
    );
    return reply.send({ data: result });
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/ref/somb/version
  // -------------------------------------------------------------------------

  async function sombVersionHandler(
    request: FastifyRequest<{ Querystring: VersionQuery }>,
    reply: FastifyReply,
  ) {
    const { date } = request.query;
    const result = await resolveVersion(serviceDeps, 'SOMB', new Date(date));
    return reply.send({ data: result });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/ref/rules/evaluate-batch
  // -------------------------------------------------------------------------

  async function evaluateBatchHandler(
    request: FastifyRequest<{ Body: EvaluateBatch }>,
    reply: FastifyReply,
  ) {
    const { claims } = request.body;

    // Map raw claim objects to BatchClaimInput
    const batchClaims = claims.map((c: Record<string, unknown>) => ({
      hscCodes: (c.hscCodes ?? c.hsc_codes ?? []) as string[],
      diCode: (c.diCode ?? c.di_code) as string | undefined,
      facilityCode: (c.facilityCode ?? c.facility_code) as string | undefined,
      dateOfService: new Date(c.dateOfService as string ?? c.date_of_service as string),
      modifiers: (c.modifiers ?? []) as string[],
    }));

    const results = await evaluateRulesBatch(serviceDeps, batchClaims);
    return reply.send({ data: { results } });
  }

  // =========================================================================
  // Change Summary Handlers
  // =========================================================================

  // -------------------------------------------------------------------------
  // GET /api/v1/ref/changes
  // -------------------------------------------------------------------------

  async function changeSummaryListHandler(
    request: FastifyRequest<{ Querystring: ChangeList }>,
    reply: FastifyReply,
  ) {
    const { dataset, since } = request.query;
    const result = await getChangeSummaries(
      serviceDeps,
      dataset,
      since ? new Date(since) : undefined,
    );
    return reply.send({ data: result });
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/ref/changes/:version_id/detail
  // -------------------------------------------------------------------------

  async function changeDetailHandler(
    request: FastifyRequest<{ Params: ChangeDetailParam; Querystring: ChangeDetailQuery }>,
    reply: FastifyReply,
  ) {
    const { version_id } = request.params;
    const { specialty } = request.query;
    const result = await getChangeDetail(serviceDeps, version_id, specialty);
    return reply.send({ data: result });
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/ref/changes/:version_id/physician-impact
  // -------------------------------------------------------------------------

  async function physicianImpactHandler(
    request: FastifyRequest<{ Params: ChangeDetailParam }>,
    reply: FastifyReply,
  ) {
    const { version_id } = request.params;
    const userId = request.authContext.userId;
    const result = await getPhysicianImpact(serviceDeps, version_id, userId);
    return reply.send({ data: result });
  }

  return {
    searchHscHandler,
    hscFavouritesHandler,
    hscDetailHandler,
    searchDiHandler,
    diDetailHandler,
    modifierListHandler,
    modifierDetailHandler,
    fcListHandler,
    explCodeHandler,
    rrnpHandler,
    pcpcmHandler,
    holidayListHandler,
    holidayCheckHandler,
    // Internal validation handlers
    validateContextHandler,
    ruleDetailHandler,
    sombVersionHandler,
    evaluateBatchHandler,
    // Change summary handlers
    changeSummaryListHandler,
    changeDetailHandler,
    physicianImpactHandler,
    // Admin handlers
    uploadHandler,
    diffHandler,
    publishHandler,
    discardStagingHandler,
    listVersionsHandler,
    createHolidayHandler,
    updateHolidayHandler,
    deleteHolidayHandler,
    dryRunHandler,
  };
}
