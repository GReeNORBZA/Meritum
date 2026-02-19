import { type FastifyInstance, type FastifyRequest, type FastifyReply } from 'fastify';
import fp from 'fastify-plugin';
import { z } from 'zod';
import { stepNumberParamSchema } from '@meritum/shared/schemas/onboarding.schema.js';
import {
  createOnboardingHandlers,
  type OnboardingHandlerDeps,
} from './onboarding.handlers.js';
import {
  getOnboardingStatus,
  type OnboardingServiceDeps,
} from './onboarding.service.js';

// ---------------------------------------------------------------------------
// Role-checking preHandler helper
// ---------------------------------------------------------------------------

function requireRole(...roles: string[]) {
  return async function requireRoleHandler(request: any, reply: any) {
    const ctx = request.authContext;
    if (!ctx) {
      reply.code(401).send({
        error: { code: 'UNAUTHORIZED', message: 'Authentication required' },
      });
      return;
    }
    const userRole = ctx.role?.toUpperCase();
    if (!roles.map((r: string) => r.toUpperCase()).includes(userRole)) {
      reply.code(403).send({
        error: { code: 'FORBIDDEN', message: 'Insufficient permissions' },
      });
      return;
    }
  };
}

// ---------------------------------------------------------------------------
// Onboarding Routes
// ---------------------------------------------------------------------------

export async function onboardingRoutes(
  app: FastifyInstance,
  opts: { deps: OnboardingHandlerDeps },
) {
  const handlers = createOnboardingHandlers(opts.deps);
  const physicianOnly = requireRole('PHYSICIAN');

  // GET /api/v1/onboarding/progress
  app.get('/api/v1/onboarding/progress', {
    preHandler: [app.authenticate, physicianOnly],
    handler: handlers.getProgressHandler,
  });

  // POST /api/v1/onboarding/steps/:step_number
  app.post('/api/v1/onboarding/steps/:step_number', {
    schema: { params: stepNumberParamSchema },
    preHandler: [app.authenticate, physicianOnly],
    handler: handlers.completeStepHandler,
  });

  // GET /api/v1/onboarding/ima
  app.get('/api/v1/onboarding/ima', {
    preHandler: [app.authenticate, physicianOnly],
    handler: handlers.getImaHandler,
  });

  // POST /api/v1/onboarding/ima/acknowledge
  app.post('/api/v1/onboarding/ima/acknowledge', {
    preHandler: [app.authenticate, physicianOnly],
    handler: handlers.acknowledgeImaHandler,
  });

  // GET /api/v1/onboarding/ima/download
  app.get('/api/v1/onboarding/ima/download', {
    preHandler: [app.authenticate, physicianOnly],
    handler: handlers.downloadImaHandler,
  });

  // GET /api/v1/onboarding/ahc11236/download
  app.get('/api/v1/onboarding/ahc11236/download', {
    preHandler: [app.authenticate, physicianOnly],
    handler: handlers.downloadAhc11236Handler,
  });

  // GET /api/v1/onboarding/pia/download
  app.get('/api/v1/onboarding/pia/download', {
    preHandler: [app.authenticate, physicianOnly],
    handler: handlers.downloadPiaHandler,
  });

  // POST /api/v1/onboarding/guided-tour/complete
  app.post('/api/v1/onboarding/guided-tour/complete', {
    preHandler: [app.authenticate, physicianOnly],
    handler: handlers.completeGuidedTourHandler,
  });

  // POST /api/v1/onboarding/guided-tour/dismiss
  app.post('/api/v1/onboarding/guided-tour/dismiss', {
    preHandler: [app.authenticate, physicianOnly],
    handler: handlers.dismissGuidedTourHandler,
  });

  // POST /api/v1/onboarding/patient-import/complete
  app.post('/api/v1/onboarding/patient-import/complete', {
    preHandler: [app.authenticate, physicianOnly],
    handler: handlers.completePatientImportHandler,
  });

  // POST /api/v1/onboarding/ba/:ba_id/confirm-active
  app.post('/api/v1/onboarding/ba/:ba_id/confirm-active', {
    schema: {
      params: z.object({ ba_id: z.string().uuid() }),
    },
    preHandler: [app.authenticate, physicianOnly],
    handler: handlers.confirmBaActiveHandler,
  });
}

// ---------------------------------------------------------------------------
// Onboarding Gate Middleware
// ---------------------------------------------------------------------------

// Paths that bypass the onboarding gate
const BYPASS_PREFIXES = [
  '/api/v1/onboarding',
  '/api/v1/auth',
  '/api/v1/platform/subscriptions',
  '/api/v1/platform/webhooks',
  '/health',
];

function shouldBypassGate(url: string): boolean {
  for (const prefix of BYPASS_PREFIXES) {
    if (url.startsWith(prefix)) {
      return true;
    }
  }
  return false;
}

export interface OnboardingGateOptions {
  serviceDeps: OnboardingServiceDeps;
}

/**
 * Onboarding gate middleware.
 *
 * Registered as an `onRequest` hook. For non-bypassed paths, it attempts to
 * populate `request.authContext` by calling `app.authenticate` so it can
 * check the physician's onboarding status before the request proceeds.
 *
 * If authentication fails (no cookie, invalid session), the gate skips
 * silently — the route's own `authenticate` preHandler will return 401.
 */
async function onboardingGatePlugin(
  app: FastifyInstance,
  opts: OnboardingGateOptions,
) {
  const { serviceDeps } = opts;

  app.addHook('onRequest', async (request: FastifyRequest, reply: FastifyReply) => {
    // Skip for bypassed paths
    if (shouldBypassGate(request.url)) {
      return;
    }

    // Attempt to populate authContext early so the gate can inspect the role.
    // If authenticate sends a 401 response, we catch it and skip the gate —
    // the route's own authenticate handler will enforce 401 later.
    if (!request.authContext) {
      try {
        await app.authenticate(request, reply);
      } catch {
        // Authentication failed — skip the gate
        return;
      }
      // If authenticate sent a reply (401), skip the gate
      if (reply.sent) {
        return;
      }
    }

    // Still no authContext after attempting auth — skip
    if (!request.authContext) {
      return;
    }

    const role = request.authContext.role?.toUpperCase();

    // Skip for delegates — they don't go through onboarding
    if (role === 'DELEGATE') {
      return;
    }

    // Skip for admins
    if (role === 'ADMIN') {
      return;
    }

    // Only gate physician users
    if (role !== 'PHYSICIAN') {
      return;
    }

    // Check onboarding status
    const status = await getOnboardingStatus(serviceDeps, request.authContext.userId);

    if (status.is_complete) {
      return;
    }

    // Compute current step for the error response
    let currentStep = 1;
    if (status.progress) {
      const p = status.progress;
      if (!p.step1Completed) currentStep = 1;
      else if (!p.step2Completed) currentStep = 2;
      else if (!p.step3Completed) currentStep = 3;
      else if (!p.step4Completed) currentStep = 4;
      else if (!p.step7Completed) currentStep = 7;
    }

    reply.code(403).send({
      error: {
        code: 'ONBOARDING_REQUIRED',
        message: 'onboarding_required',
        current_step: currentStep,
      },
    });
  });
}

export const onboardingGateFp = fp(onboardingGatePlugin, {
  name: 'onboarding-gate',
  dependencies: ['auth-plugin'],
});
