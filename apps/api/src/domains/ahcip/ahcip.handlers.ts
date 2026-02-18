import { type FastifyRequest, type FastifyReply } from 'fastify';
import type {
  ListBatches,
  BatchIdParam,
  FeeCalculate,
  BatchAssessmentParam,
  ClaimIdParam,
} from './ahcip.schema.js';
import {
  previewNextBatch,
  retryFailedBatch,
  getAssessmentResults,
  listBatchesAwaitingResponse,
  calculateFeePreview,
  getFeeBreakdown,
  type BatchCycleDeps,
  type FeeCalculationDeps,
  type AssessmentIngestionDeps,
} from './ahcip.service.js';

// ---------------------------------------------------------------------------
// Handler dependencies
// ---------------------------------------------------------------------------

export interface AhcipHandlerDeps {
  batchCycleDeps: BatchCycleDeps;
  feeCalculationDeps: FeeCalculationDeps;
  assessmentDeps: AssessmentIngestionDeps;
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

export function createAhcipHandlers(deps: AhcipHandlerDeps) {
  const { batchCycleDeps, feeCalculationDeps, assessmentDeps } = deps;

  // =========================================================================
  // Batch Management
  // =========================================================================

  async function listBatchesHandler(
    request: FastifyRequest<{ Querystring: ListBatches }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const query = request.query;

    const result = await batchCycleDeps.repo.listBatches(physicianId, {
      status: query.status,
      dateFrom: query.date_from,
      dateTo: query.date_to,
      page: query.page,
      pageSize: query.page_size,
    });

    return reply.code(200).send({
      data: result.data,
      pagination: result.pagination,
    });
  }

  async function previewNextBatchHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);

    const preview = await previewNextBatch(batchCycleDeps, physicianId);

    return reply.code(200).send({ data: preview });
  }

  async function getBatchHandler(
    request: FastifyRequest<{ Params: BatchIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;

    const batch = await batchCycleDeps.repo.findBatchById(id, physicianId);
    if (!batch) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    return reply.code(200).send({ data: batch });
  }

  async function retryBatchHandler(
    request: FastifyRequest<{ Params: BatchIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;

    try {
      const result = await retryFailedBatch(batchCycleDeps, id, physicianId);
      return reply.code(200).send({ data: result });
    } catch (err: any) {
      if (err.message === 'Batch not found') {
        return reply.code(404).send({
          error: { code: 'NOT_FOUND', message: 'Resource not found' },
        });
      }
      if (err.message?.startsWith('Can only retry batches')) {
        return reply.code(409).send({
          error: { code: 'CONFLICT', message: err.message },
        });
      }
      throw err;
    }
  }

  // =========================================================================
  // Assessment
  // =========================================================================

  async function getAssessmentResultsHandler(
    request: FastifyRequest<{ Params: BatchAssessmentParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { batch_id } = request.params;

    try {
      const results = await getAssessmentResults(assessmentDeps, batch_id, physicianId);
      return reply.code(200).send({ data: results });
    } catch (err: any) {
      if (err.message === 'Batch not found') {
        return reply.code(404).send({
          error: { code: 'NOT_FOUND', message: 'Resource not found' },
        });
      }
      throw err;
    }
  }

  async function listPendingAssessmentsHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);

    const pending = await listBatchesAwaitingResponse(assessmentDeps, physicianId);

    return reply.code(200).send({ data: pending });
  }

  // =========================================================================
  // Fee Calculation
  // =========================================================================

  async function feeCalculateHandler(
    request: FastifyRequest<{ Body: FeeCalculate }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const body = request.body;

    const breakdown = await calculateFeePreview(feeCalculationDeps, physicianId, {
      healthServiceCode: body.health_service_code,
      dateOfService: body.date_of_service,
      modifier1: body.modifier_1,
      modifier2: body.modifier_2,
      modifier3: body.modifier_3,
      calls: body.calls,
    });

    return reply.code(200).send({ data: breakdown });
  }

  async function feeBreakdownHandler(
    request: FastifyRequest<{ Params: ClaimIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;

    try {
      const breakdown = await getFeeBreakdown(feeCalculationDeps, id, physicianId);
      return reply.code(200).send({ data: breakdown });
    } catch (err: any) {
      if (err.message === 'Claim not found') {
        return reply.code(404).send({
          error: { code: 'NOT_FOUND', message: 'Resource not found' },
        });
      }
      throw err;
    }
  }

  return {
    listBatchesHandler,
    previewNextBatchHandler,
    getBatchHandler,
    retryBatchHandler,
    getAssessmentResultsHandler,
    listPendingAssessmentsHandler,
    feeCalculateHandler,
    feeBreakdownHandler,
  };
}
