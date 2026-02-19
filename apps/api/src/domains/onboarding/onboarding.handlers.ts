import { type FastifyRequest, type FastifyReply } from 'fastify';
import { type ZodSchema } from 'zod';
import {
  type OnboardingStep1,
  type OnboardingStep2,
  type OnboardingStep3,
  type OnboardingStep4,
  type OnboardingStep5,
  type OnboardingStep6,
  type ImaAcknowledge,
  type StepNumberParam,
  onboardingStep1Schema,
  onboardingStep2Schema,
  onboardingStep3Schema,
  onboardingStep4Schema,
  onboardingStep5Schema,
  onboardingStep6Schema,
  imaAcknowledgeSchema,
} from '@meritum/shared/schemas/onboarding.schema.js';
import {
  getOrCreateProgress,
  completeStep1,
  completeStep2,
  completeStep3,
  completeStep4,
  completeStep5,
  completeStep6,
  completeStep7,
  renderIma,
  acknowledgeIma,
  downloadImaPdf,
  generateAhc11236Pdf,
  downloadPiaPdf,
  completeGuidedTour,
  dismissGuidedTour,
  completePatientImport,
  confirmBaActive,
  type OnboardingServiceDeps,
  type ComputedProgress,
} from './onboarding.service.js';
import { ValidationError } from '../../lib/errors.js';

// ---------------------------------------------------------------------------
// Handler dependencies
// ---------------------------------------------------------------------------

export interface OnboardingHandlerDeps {
  serviceDeps: OnboardingServiceDeps;
}

// ---------------------------------------------------------------------------
// Helper: format progress for API response
// ---------------------------------------------------------------------------

function formatProgressResponse(computed: ComputedProgress) {
  const p = computed.progress;
  return {
    progress_id: p.progressId,
    provider_id: p.providerId,
    step_1_completed: p.step1Completed,
    step_2_completed: p.step2Completed,
    step_3_completed: p.step3Completed,
    step_4_completed: p.step4Completed,
    step_5_completed: p.step5Completed,
    step_6_completed: p.step6Completed,
    step_7_completed: p.step7Completed,
    patient_import_completed: p.patientImportCompleted,
    guided_tour_completed: p.guidedTourCompleted,
    guided_tour_dismissed: p.guidedTourDismissed,
    started_at: p.startedAt.toISOString(),
    completed_at: p.completedAt ? p.completedAt.toISOString() : null,
    current_step: computed.current_step,
    is_complete: computed.is_complete,
    required_steps_remaining: computed.required_steps_remaining,
  };
}

// ---------------------------------------------------------------------------
// Step body schemas (for server-side validation per step)
// ---------------------------------------------------------------------------

const stepBodySchemas: Record<number, ZodSchema | null> = {
  1: onboardingStep1Schema,
  2: onboardingStep2Schema,
  3: onboardingStep3Schema,
  4: onboardingStep4Schema,
  5: onboardingStep5Schema,
  6: onboardingStep6Schema,
  7: null, // Step 7 has no body — IMA uses ip/user-agent
};

// ---------------------------------------------------------------------------
// Handler factory
// ---------------------------------------------------------------------------

export function createOnboardingHandlers(deps: OnboardingHandlerDeps) {
  const { serviceDeps } = deps;

  // =========================================================================
  // GET /api/v1/onboarding/progress
  // =========================================================================

  async function getProgressHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const userId = request.authContext.userId;

    // Check if provider exists for this user
    const provider = await serviceDeps.providerService.findProviderByUserId(userId);
    if (!provider) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    const computed = await getOrCreateProgress(serviceDeps, provider.providerId);

    return reply.code(200).send({ data: formatProgressResponse(computed) });
  }

  // =========================================================================
  // POST /api/v1/onboarding/steps/:step_number
  // =========================================================================

  async function completeStepHandler(
    request: FastifyRequest<{ Params: StepNumberParam }>,
    reply: FastifyReply,
  ) {
    const userId = request.authContext.userId;

    // Check if provider exists for this user
    const provider = await serviceDeps.providerService.findProviderByUserId(userId);
    const providerId = provider?.providerId ?? userId;

    const { step_number } = request.params;

    // Validate step-specific body
    const schema = stepBodySchemas[step_number];
    let parsedBody: unknown = undefined;

    if (schema) {
      const result = schema.safeParse(request.body);
      if (!result.success) {
        throw new ValidationError('Validation failed', result.error.issues);
      }
      parsedBody = result.data;
    }

    // Dispatch to the appropriate service function
    let computed: ComputedProgress;

    switch (step_number) {
      case 1:
        computed = await completeStep1(serviceDeps, providerId, parsedBody as OnboardingStep1);
        break;
      case 2:
        computed = await completeStep2(serviceDeps, providerId, parsedBody as OnboardingStep2);
        break;
      case 3:
        computed = await completeStep3(serviceDeps, providerId, parsedBody as OnboardingStep3);
        break;
      case 4:
        computed = await completeStep4(serviceDeps, providerId, parsedBody as OnboardingStep4);
        break;
      case 5:
        computed = await completeStep5(serviceDeps, providerId, parsedBody as OnboardingStep5);
        break;
      case 6:
        computed = await completeStep6(serviceDeps, providerId, parsedBody as OnboardingStep6);
        break;
      case 7:
        computed = await completeStep7(
          serviceDeps,
          providerId,
          request.ip ?? '0.0.0.0',
          request.headers['user-agent'] ?? 'unknown',
        );
        break;
      default:
        throw new ValidationError(`Invalid step number: ${step_number}`);
    }

    return reply.code(200).send({ data: formatProgressResponse(computed) });
  }

  // =========================================================================
  // GET /api/v1/onboarding/ima
  // =========================================================================

  async function getImaHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const userId = request.authContext.userId;

    const provider = await serviceDeps.providerService.findProviderByUserId(userId);
    if (!provider) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    const rendered = await renderIma(serviceDeps, provider.providerId);

    return reply.code(200).send({
      data: {
        content: rendered.html,
        hash: rendered.hash,
        template_version: rendered.templateVersion,
      },
    });
  }

  // =========================================================================
  // POST /api/v1/onboarding/ima/acknowledge
  // =========================================================================

  async function acknowledgeImaHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const userId = request.authContext.userId;

    const provider = await serviceDeps.providerService.findProviderByUserId(userId);
    if (!provider) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    const result = imaAcknowledgeSchema.safeParse(request.body);
    if (!result.success) {
      throw new ValidationError('Validation failed', result.error.issues);
    }
    const body = result.data as ImaAcknowledge;

    const ipAddress = request.ip ?? '0.0.0.0';
    const userAgent = request.headers['user-agent'] ?? 'unknown';

    const imaResult = await acknowledgeIma(
      serviceDeps,
      provider.providerId,
      body.document_hash,
      ipAddress,
      userAgent,
    );

    return reply.code(201).send({
      data: {
        ima_id: imaResult.imaId,
        document_hash: imaResult.documentHash,
        template_version: imaResult.templateVersion,
        acknowledged_at: imaResult.acknowledgedAt.toISOString(),
      },
    });
  }

  // =========================================================================
  // GET /api/v1/onboarding/ima/download
  // =========================================================================

  async function downloadImaHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const userId = request.authContext.userId;

    const provider = await serviceDeps.providerService.findProviderByUserId(userId);
    if (!provider) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    const providerDetails = await serviceDeps.providerService.getProviderDetails(provider.providerId);
    const providerName = providerDetails
      ? `${providerDetails.firstName}-${providerDetails.lastName}`
      : 'physician';

    const pdfBuffer = await downloadImaPdf(serviceDeps, provider.providerId);

    return reply
      .type('application/pdf')
      .header('Content-Disposition', `attachment; filename="IMA-${providerName}.pdf"`)
      .send(pdfBuffer);
  }

  // =========================================================================
  // GET /api/v1/onboarding/ahc11236/download
  // =========================================================================

  async function downloadAhc11236Handler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const userId = request.authContext.userId;

    const provider = await serviceDeps.providerService.findProviderByUserId(userId);
    if (!provider) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    const pdfBuffer = await generateAhc11236Pdf(serviceDeps, provider.providerId);

    return reply
      .type('application/pdf')
      .header('Content-Disposition', 'attachment; filename="AHC11236.pdf"')
      .send(pdfBuffer);
  }

  // =========================================================================
  // GET /api/v1/onboarding/pia/download
  // =========================================================================

  async function downloadPiaHandler(
    _request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const pdfBuffer = await downloadPiaPdf(serviceDeps);

    return reply
      .type('application/pdf')
      .header('Content-Disposition', 'attachment; filename="PIA-Appendix.pdf"')
      .send(pdfBuffer);
  }

  // =========================================================================
  // POST /api/v1/onboarding/guided-tour/complete
  // =========================================================================

  async function completeGuidedTourHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const userId = request.authContext.userId;

    const provider = await serviceDeps.providerService.findProviderByUserId(userId);
    if (!provider) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    await completeGuidedTour(serviceDeps, provider.providerId);

    const computed = await getOrCreateProgress(serviceDeps, provider.providerId);
    return reply.code(200).send({ data: formatProgressResponse(computed) });
  }

  // =========================================================================
  // POST /api/v1/onboarding/guided-tour/dismiss
  // =========================================================================

  async function dismissGuidedTourHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const userId = request.authContext.userId;

    const provider = await serviceDeps.providerService.findProviderByUserId(userId);
    if (!provider) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    await dismissGuidedTour(serviceDeps, provider.providerId);

    const computed = await getOrCreateProgress(serviceDeps, provider.providerId);
    return reply.code(200).send({ data: formatProgressResponse(computed) });
  }

  // =========================================================================
  // POST /api/v1/onboarding/patient-import/complete
  // =========================================================================

  async function completePatientImportHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const userId = request.authContext.userId;

    const provider = await serviceDeps.providerService.findProviderByUserId(userId);
    if (!provider) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    await completePatientImport(serviceDeps, provider.providerId);

    const computed = await getOrCreateProgress(serviceDeps, provider.providerId);
    return reply.code(200).send({ data: formatProgressResponse(computed) });
  }

  // =========================================================================
  // POST /api/v1/onboarding/ba/:ba_id/confirm-active
  // =========================================================================

  async function confirmBaActiveHandler(
    request: FastifyRequest<{ Params: { ba_id: string } }>,
    reply: FastifyReply,
  ) {
    const userId = request.authContext.userId;

    const provider = await serviceDeps.providerService.findProviderByUserId(userId);
    if (!provider) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    const { ba_id: baId } = request.params;

    await confirmBaActive(serviceDeps, provider.providerId, baId);

    const ba = await serviceDeps.providerService.findBaById(baId, provider.providerId);
    return reply.code(200).send({
      data: {
        ba_id: baId,
        status: ba?.status ?? 'ACTIVE',
      },
    });
  }

  return {
    getProgressHandler,
    completeStepHandler,
    getImaHandler,
    acknowledgeImaHandler,
    downloadImaHandler,
    downloadAhc11236Handler,
    downloadPiaHandler,
    completeGuidedTourHandler,
    dismissGuidedTourHandler,
    completePatientImportHandler,
    confirmBaActiveHandler,
  };
}
