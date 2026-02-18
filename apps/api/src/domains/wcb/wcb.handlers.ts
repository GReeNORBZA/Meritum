import { type FastifyRequest, type FastifyReply } from 'fastify';
import type {
  WcbClaimCreate,
  WcbClaimUpdate,
  WcbClaimIdParam,
  WcbBatchIdParam,
  WcbBatchListQuery,
  WcbRemittanceListQuery,
  WcbRemittanceIdParam,
  WcbManualOutcome,
} from './wcb.schema.js';
import {
  createWcbClaim,
  updateWcbClaim,
  deleteWcbClaim,
  getFormSchema,
  validateWcbClaim,
  assembleAndGenerateBatch,
  generateDownloadUrl,
  confirmBatchUpload,
  processReturnFile,
  processRemittanceFile,
  generateMvpExport,
  recordManualOutcome,
  isMvpPhaseActive,
  type WcbServiceDeps,
} from './wcb.service.js';
import { AppError } from '../../lib/errors.js';

// ---------------------------------------------------------------------------
// Handler dependencies
// ---------------------------------------------------------------------------

export interface WcbHandlerDeps {
  serviceDeps: WcbServiceDeps;
  wcbPhase?: string;
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

export function createWcbHandlers(deps: WcbHandlerDeps) {
  const { serviceDeps, wcbPhase } = deps;

  // =========================================================================
  // POST /api/v1/wcb/claims — Create WCB claim
  // =========================================================================

  async function createClaimHandler(
    request: FastifyRequest<{ Body: WcbClaimCreate }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const body = request.body;

    const result = await createWcbClaim(
      serviceDeps,
      physicianId,
      request.authContext.userId,
      body,
    );

    return reply.code(201).send({ data: result });
  }

  // =========================================================================
  // GET /api/v1/wcb/claims/:id — Retrieve claim with child records
  // =========================================================================

  async function getClaimHandler(
    request: FastifyRequest<{ Params: WcbClaimIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;

    const claim = await serviceDeps.wcbRepo.getWcbClaim(id, physicianId);
    if (!claim) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    return reply.code(200).send({ data: claim });
  }

  // =========================================================================
  // PUT /api/v1/wcb/claims/:id — Update claim (partial)
  // =========================================================================

  async function updateClaimHandler(
    request: FastifyRequest<{ Params: WcbClaimIdParam; Body: WcbClaimUpdate }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;
    const body = request.body;

    try {
      const updated = await updateWcbClaim(
        serviceDeps,
        physicianId,
        request.authContext.userId,
        id,
        body,
      );

      return reply.code(200).send({ data: updated });
    } catch (err: any) {
      if (err instanceof AppError) {
        return reply.code(err.statusCode).send({
          error: { code: err.code, message: err.statusCode === 404 ? 'Resource not found' : err.message },
        });
      }
      throw err;
    }
  }

  // =========================================================================
  // DELETE /api/v1/wcb/claims/:id — Soft delete (draft only)
  // =========================================================================

  async function deleteClaimHandler(
    request: FastifyRequest<{ Params: WcbClaimIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;

    try {
      await deleteWcbClaim(
        serviceDeps,
        physicianId,
        request.authContext.userId,
        id,
      );

      return reply.code(204).send();
    } catch (err: any) {
      if (err instanceof AppError) {
        if (err.statusCode === 404) {
          return reply.code(404).send({
            error: { code: 'NOT_FOUND', message: 'Resource not found' },
          });
        }
        if (err.statusCode === 422) {
          return reply.code(422).send({
            error: { code: err.code, message: err.message },
          });
        }
      }
      throw err;
    }
  }

  // =========================================================================
  // POST /api/v1/wcb/claims/:id/validate — Run validation pipeline
  // =========================================================================

  async function validateClaimHandler(
    request: FastifyRequest<{ Params: WcbClaimIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;

    try {
      const result = await validateWcbClaim(serviceDeps, id, physicianId);
      return reply.code(200).send({ data: result });
    } catch (err: any) {
      if (err instanceof AppError && err.statusCode === 404) {
        return reply.code(404).send({
          error: { code: 'NOT_FOUND', message: 'Resource not found' },
        });
      }
      throw err;
    }
  }

  // =========================================================================
  // GET /api/v1/wcb/claims/:id/form-schema — Return form field definitions
  // =========================================================================

  async function getFormSchemaHandler(
    request: FastifyRequest<{ Params: WcbClaimIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;

    // Load claim to get form_id and existing data for conditional resolution
    const claim = await serviceDeps.wcbRepo.getWcbClaim(id, physicianId);
    if (!claim) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    const formId = claim.detail.formId as string;

    // Build existing data map from claim detail for conditional field resolution
    const existingData: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(claim.detail)) {
      if (value !== null && value !== undefined) {
        existingData[key] = value;
      }
    }

    try {
      const schema = getFormSchema(formId, existingData);
      return reply.code(200).send({ data: schema });
    } catch (err: any) {
      if (err instanceof AppError) {
        return reply.code(err.statusCode).send({
          error: { code: err.code, message: err.message },
        });
      }
      throw err;
    }
  }

  // =========================================================================
  // POST /api/v1/wcb/batches — Initiate batch generation
  // =========================================================================

  async function createBatchHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);

    try {
      const result = await assembleAndGenerateBatch(
        serviceDeps,
        physicianId,
        request.authContext.userId,
      );
      return reply.code(201).send({ data: result });
    } catch (err: any) {
      if (err instanceof AppError) {
        return reply.code(err.statusCode).send({
          error: { code: err.code, message: err.message },
        });
      }
      throw err;
    }
  }

  // =========================================================================
  // GET /api/v1/wcb/batches/:id — Retrieve batch details
  // =========================================================================

  async function getBatchHandler(
    request: FastifyRequest<{ Params: WcbBatchIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;

    const batch = await serviceDeps.wcbRepo.getBatch(id, physicianId);
    if (!batch) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    return reply.code(200).send({ data: batch });
  }

  // =========================================================================
  // GET /api/v1/wcb/batches/:id/download — Download XML (signed URL)
  // =========================================================================

  async function downloadBatchHandler(
    request: FastifyRequest<{ Params: WcbBatchIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;

    try {
      const result = await generateDownloadUrl(
        serviceDeps,
        id,
        physicianId,
        request.authContext.userId,
      );
      return reply.code(200).send({ data: result });
    } catch (err: any) {
      if (err instanceof AppError) {
        return reply.code(err.statusCode).send({
          error: { code: err.code, message: err.statusCode === 404 ? 'Resource not found' : err.message },
        });
      }
      throw err;
    }
  }

  // =========================================================================
  // POST /api/v1/wcb/batches/:id/confirm-upload — Confirm portal upload
  // =========================================================================

  async function confirmUploadHandler(
    request: FastifyRequest<{ Params: WcbBatchIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;

    try {
      const result = await confirmBatchUpload(
        serviceDeps,
        id,
        physicianId,
        request.authContext.userId,
      );
      return reply.code(200).send({ data: result });
    } catch (err: any) {
      if (err instanceof AppError) {
        return reply.code(err.statusCode).send({
          error: { code: err.code, message: err.statusCode === 404 ? 'Resource not found' : err.message },
        });
      }
      throw err;
    }
  }

  // =========================================================================
  // GET /api/v1/wcb/batches — List batches with filtering
  // =========================================================================

  async function listBatchesHandler(
    request: FastifyRequest<{ Querystring: WcbBatchListQuery }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const query = request.query;

    const result = await serviceDeps.wcbRepo.listBatches(physicianId, {
      status: query.status,
      page: query.page,
      pageSize: query.page_size,
    });

    return reply.code(200).send({
      data: result.data,
      pagination: result.pagination,
    });
  }

  // =========================================================================
  // POST /api/v1/wcb/returns/upload — Upload return file (multipart)
  // =========================================================================

  async function uploadReturnHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);

    // Extract file content from multipart or raw body
    let fileContent: string;
    if ((request as any).file) {
      const file = (request as any).file;
      fileContent = file.buffer ? file.buffer.toString('utf-8') : '';
    } else if (typeof request.body === 'string') {
      fileContent = request.body;
    } else if (request.body && typeof (request.body as any).file_content === 'string') {
      fileContent = (request.body as any).file_content;
    } else {
      return reply.code(400).send({
        error: { code: 'VALIDATION_ERROR', message: 'Return file content is required' },
      });
    }

    if (!fileContent.trim()) {
      return reply.code(400).send({
        error: { code: 'VALIDATION_ERROR', message: 'Return file content is empty' },
      });
    }

    try {
      const result = await processReturnFile(
        serviceDeps,
        physicianId,
        request.authContext.userId,
        fileContent,
      );
      return reply.code(200).send({ data: result });
    } catch (err: any) {
      if (err instanceof AppError) {
        return reply.code(err.statusCode).send({
          error: { code: err.code, message: err.message },
        });
      }
      throw err;
    }
  }

  // =========================================================================
  // GET /api/v1/wcb/returns/:batch_id — Get return results for batch
  // =========================================================================

  async function getReturnResultsHandler(
    request: FastifyRequest<{ Params: { batch_id: string } }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { batch_id } = request.params;

    // Verify batch belongs to physician
    const batch = await serviceDeps.wcbRepo.getBatch(batch_id, physicianId);
    if (!batch) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    const records = await serviceDeps.wcbRepo.getReturnRecordsByBatch(batch_id);
    return reply.code(200).send({ data: records });
  }

  // =========================================================================
  // POST /api/v1/wcb/remittances/upload — Upload remittance XML (multipart)
  // =========================================================================

  async function uploadRemittanceHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);

    // Extract XML content from multipart or raw body
    let xmlContent: string;
    if ((request as any).file) {
      const file = (request as any).file;
      xmlContent = file.buffer ? file.buffer.toString('utf-8') : '';
    } else if (typeof request.body === 'string') {
      xmlContent = request.body;
    } else if (request.body && typeof (request.body as any).xml_content === 'string') {
      xmlContent = (request.body as any).xml_content;
    } else {
      return reply.code(400).send({
        error: { code: 'VALIDATION_ERROR', message: 'Remittance XML content is required' },
      });
    }

    if (!xmlContent.trim()) {
      return reply.code(400).send({
        error: { code: 'VALIDATION_ERROR', message: 'Remittance XML content is empty' },
      });
    }

    try {
      const result = await processRemittanceFile(
        serviceDeps,
        physicianId,
        request.authContext.userId,
        xmlContent,
      );
      return reply.code(200).send({ data: result });
    } catch (err: any) {
      if (err instanceof AppError) {
        return reply.code(err.statusCode).send({
          error: { code: err.code, message: err.message },
        });
      }
      throw err;
    }
  }

  // =========================================================================
  // GET /api/v1/wcb/remittances — List remittance imports
  // =========================================================================

  async function listRemittancesHandler(
    request: FastifyRequest<{ Querystring: WcbRemittanceListQuery }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const query = request.query;

    const result = await serviceDeps.wcbRepo.listRemittanceImports(physicianId, {
      startDate: query.start_date,
      endDate: query.end_date,
      page: query.page,
      pageSize: query.page_size,
    });

    return reply.code(200).send({
      data: result.data,
      pagination: result.pagination,
    });
  }

  // =========================================================================
  // GET /api/v1/wcb/remittances/:id/discrepancies — Get discrepancies
  // =========================================================================

  async function getDiscrepanciesHandler(
    request: FastifyRequest<{ Params: WcbRemittanceIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;

    // Verify the remittance import belongs to physician via repo scoping
    const imports = await serviceDeps.wcbRepo.listRemittanceImports(physicianId, {
      page: 1,
      pageSize: 1,
    });

    // Use getRemittanceDiscrepancies (physician-scoped in repo)
    const discrepancies = await serviceDeps.wcbRepo.getRemittanceDiscrepancies(id, physicianId);
    return reply.code(200).send({ data: discrepancies });
  }

  // =========================================================================
  // GET /api/v1/wcb/claims/:id/export — Generate pre-filled export (MVP)
  // =========================================================================

  async function exportClaimHandler(
    request: FastifyRequest<{ Params: WcbClaimIdParam }>,
    reply: FastifyReply,
  ) {
    if (!isMvpPhaseActive(wcbPhase)) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    const physicianId = getPhysicianId(request);
    const { id } = request.params;

    try {
      const result = await generateMvpExport(
        serviceDeps,
        physicianId,
        id,
        request.authContext.userId,
        wcbPhase,
      );
      return reply.code(200).send({ data: result });
    } catch (err: any) {
      if (err instanceof AppError) {
        return reply.code(err.statusCode).send({
          error: { code: err.code, message: err.statusCode === 404 ? 'Resource not found' : err.message },
        });
      }
      throw err;
    }
  }

  // =========================================================================
  // POST /api/v1/wcb/claims/:id/manual-outcome — Record manual outcome (MVP)
  // =========================================================================

  async function manualOutcomeHandler(
    request: FastifyRequest<{ Params: WcbClaimIdParam; Body: WcbManualOutcome }>,
    reply: FastifyReply,
  ) {
    if (!isMvpPhaseActive(wcbPhase)) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    const physicianId = getPhysicianId(request);
    const { id } = request.params;
    const body = request.body;

    try {
      const result = await recordManualOutcome(
        serviceDeps,
        physicianId,
        id,
        request.authContext.userId,
        body,
        wcbPhase,
      );
      return reply.code(200).send({ data: result });
    } catch (err: any) {
      if (err instanceof AppError) {
        return reply.code(err.statusCode).send({
          error: { code: err.code, message: err.statusCode === 404 ? 'Resource not found' : err.message },
        });
      }
      throw err;
    }
  }

  return {
    createClaimHandler,
    getClaimHandler,
    updateClaimHandler,
    deleteClaimHandler,
    validateClaimHandler,
    getFormSchemaHandler,
    createBatchHandler,
    getBatchHandler,
    downloadBatchHandler,
    confirmUploadHandler,
    listBatchesHandler,
    uploadReturnHandler,
    getReturnResultsHandler,
    uploadRemittanceHandler,
    listRemittancesHandler,
    getDiscrepanciesHandler,
    exportClaimHandler,
    manualOutcomeHandler,
  };
}
