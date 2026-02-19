import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { createHash, randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Environment setup (must be before imports that read env)
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);

// ---------------------------------------------------------------------------
// Mock otplib (required by iam.service.ts transitive import)
// ---------------------------------------------------------------------------

vi.mock('otplib', () => ({
  authenticator: {
    options: {},
    generateSecret: vi.fn(() => 'JBSWY3DPEHPK3PXP'),
    keyuri: vi.fn(() => 'otpauth://totp/test'),
    verify: vi.fn(() => false),
  },
}));

// ---------------------------------------------------------------------------
// Imports (after mocks)
// ---------------------------------------------------------------------------

import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { onboardingRoutes, onboardingGateFp } from '../../../src/domains/onboarding/onboarding.routes.js';
import { type OnboardingHandlerDeps } from '../../../src/domains/onboarding/onboarding.handlers.js';
import { type OnboardingServiceDeps } from '../../../src/domains/onboarding/onboarding.service.js';

// ---------------------------------------------------------------------------
// Helper: hashToken
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

const PHYSICIAN1_USER_ID = '00000000-1111-0000-0000-000000000001';
const PHYSICIAN1_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN1_SESSION_TOKEN_HASH = hashToken(PHYSICIAN1_SESSION_TOKEN);
const PHYSICIAN1_PROGRESS_ID = '00000000-3333-0000-0000-000000000001';

const DELEGATE_USER_ID = '00000000-1111-0000-0000-000000000099';
const DELEGATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_SESSION_TOKEN_HASH = hashToken(DELEGATE_SESSION_TOKEN);

// ---------------------------------------------------------------------------
// Mock progress record builder
// ---------------------------------------------------------------------------

function makeMockProgress(overrides: Record<string, unknown> = {}) {
  return {
    progressId: PHYSICIAN1_PROGRESS_ID,
    providerId: PHYSICIAN1_USER_ID,
    step1Completed: false,
    step2Completed: false,
    step3Completed: false,
    step4Completed: false,
    step5Completed: false,
    step6Completed: false,
    step7Completed: false,
    patientImportCompleted: false,
    guidedTourCompleted: false,
    guidedTourDismissed: false,
    startedAt: new Date('2026-01-01T00:00:00Z'),
    completedAt: null,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Mock session repo
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      if (tokenHash === PHYSICIAN1_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: '00000000-2222-0000-0000-000000000001',
            userId: PHYSICIAN1_USER_ID,
            tokenHash: PHYSICIAN1_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: PHYSICIAN1_USER_ID,
            role: 'PHYSICIAN',
            subscriptionStatus: 'ACTIVE',
          },
        };
      }
      if (tokenHash === DELEGATE_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: '00000000-2222-0000-0000-000000000099',
            userId: DELEGATE_USER_ID,
            tokenHash: DELEGATE_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: DELEGATE_USER_ID,
            role: 'DELEGATE',
            subscriptionStatus: 'ACTIVE',
          },
        };
      }
      return undefined;
    }),
    refreshSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Mock onboarding repository
// ---------------------------------------------------------------------------

function createMockOnboardingRepo() {
  return {
    createProgress: vi.fn(async (providerId: string) =>
      makeMockProgress({ providerId }),
    ),
    findProgressByProviderId: vi.fn(async (_providerId: string) => null as any),
    markStepCompleted: vi.fn(async (providerId: string, stepNumber: number) => {
      const key = `step${stepNumber}Completed`;
      return makeMockProgress({ providerId, [key]: true });
    }),
    markOnboardingCompleted: vi.fn(async (providerId: string) =>
      makeMockProgress({
        providerId,
        step1Completed: true,
        step2Completed: true,
        step3Completed: true,
        step4Completed: true,
        step7Completed: true,
        completedAt: new Date(),
      }),
    ),
    markPatientImportCompleted: vi.fn(),
    markGuidedTourCompleted: vi.fn(),
    markGuidedTourDismissed: vi.fn(),
    createImaRecord: vi.fn(),
    findLatestImaRecord: vi.fn(),
    listImaRecords: vi.fn(),
  };
}

// ---------------------------------------------------------------------------
// Mock provider service
// ---------------------------------------------------------------------------

function createMockProviderService() {
  return {
    createOrUpdateProvider: vi.fn(async () => ({ providerId: PHYSICIAN1_USER_ID })),
    updateProviderSpecialty: vi.fn(async () => {}),
    createBa: vi.fn(async () => ({ baId: crypto.randomUUID() })),
    createLocation: vi.fn(async () => ({ locationId: crypto.randomUUID() })),
    createWcbConfig: vi.fn(async () => ({ wcbConfigId: crypto.randomUUID() })),
    updateSubmissionPreferences: vi.fn(async () => {}),
    findProviderByUserId: vi.fn(async (userId: string) => {
      if (userId === PHYSICIAN1_USER_ID) {
        return { providerId: PHYSICIAN1_USER_ID };
      }
      return null;
    }),
    getProviderDetails: vi.fn(async () => null),
    findBaById: vi.fn(async () => null),
    updateBaStatus: vi.fn(async () => ({ baId: '', status: '' })),
  };
}

// ---------------------------------------------------------------------------
// Mock reference data service
// ---------------------------------------------------------------------------

function createMockReferenceData() {
  return {
    validateSpecialtyCode: vi.fn(async () => true),
    validateFunctionalCentreCode: vi.fn(async () => true),
    validateCommunityCode: vi.fn(async () => true),
    getRrnpRate: vi.fn(async () => null),
    getWcbFormTypes: vi.fn(async () => ['C8', 'C10']),
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let mockRepo: ReturnType<typeof createMockOnboardingRepo>;
let mockAuditRepo: { appendAuditLog: ReturnType<typeof vi.fn> };
let mockEvents: { emit: ReturnType<typeof vi.fn> };
let mockProviderService: ReturnType<typeof createMockProviderService>;
let mockReferenceData: ReturnType<typeof createMockReferenceData>;

async function buildTestApp(): Promise<FastifyInstance> {
  mockRepo = createMockOnboardingRepo();
  mockAuditRepo = { appendAuditLog: vi.fn() };
  mockEvents = { emit: vi.fn() };
  mockProviderService = createMockProviderService();
  mockReferenceData = createMockReferenceData();

  const serviceDeps: OnboardingServiceDeps = {
    repo: mockRepo as any,
    auditRepo: mockAuditRepo,
    events: mockEvents,
    providerService: mockProviderService,
    referenceData: mockReferenceData,
  };

  const handlerDeps: OnboardingHandlerDeps = { serviceDeps };

  const testApp = Fastify({ logger: false });

  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  // Register auth plugin
  const mockSessionRepo = createMockSessionRepo();
  await testApp.register(authPluginFp, {
    sessionDeps: {
      sessionRepo: mockSessionRepo,
      auditRepo: { appendAuditLog: vi.fn() },
      events: { emit: vi.fn() },
    },
  });

  // Error handler
  testApp.setErrorHandler((error, _request, reply) => {
    if ('statusCode' in error && 'code' in error && typeof (error as any).code === 'string') {
      const statusCode = (error as any).statusCode ?? 500;
      if (statusCode >= 400 && statusCode < 500) {
        return reply.code(statusCode).send({
          error: {
            code: (error as any).code,
            message: error.message,
            details: (error as any).details,
          },
        });
      }
    }
    if (error.validation) {
      return reply.code(400).send({
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Validation failed',
          details: error.validation,
        },
      });
    }
    return reply.code(500).send({
      error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
    });
  });

  // Register onboarding routes
  await testApp.register(onboardingRoutes, { deps: handlerDeps });

  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// App with gate (for gate-specific tests)
// ---------------------------------------------------------------------------

async function buildGatedTestApp(): Promise<FastifyInstance> {
  mockRepo = createMockOnboardingRepo();
  mockAuditRepo = { appendAuditLog: vi.fn() };
  mockEvents = { emit: vi.fn() };
  mockProviderService = createMockProviderService();
  mockReferenceData = createMockReferenceData();

  const serviceDeps: OnboardingServiceDeps = {
    repo: mockRepo as any,
    auditRepo: mockAuditRepo,
    events: mockEvents,
    providerService: mockProviderService,
    referenceData: mockReferenceData,
  };

  const handlerDeps: OnboardingHandlerDeps = { serviceDeps };

  const testApp = Fastify({ logger: false });

  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  // Register auth plugin
  const mockSessionRepo = createMockSessionRepo();
  await testApp.register(authPluginFp, {
    sessionDeps: {
      sessionRepo: mockSessionRepo,
      auditRepo: { appendAuditLog: vi.fn() },
      events: { emit: vi.fn() },
    },
  });

  // Error handler
  testApp.setErrorHandler((error, _request, reply) => {
    if ('statusCode' in error && 'code' in error && typeof (error as any).code === 'string') {
      const statusCode = (error as any).statusCode ?? 500;
      if (statusCode >= 400 && statusCode < 500) {
        return reply.code(statusCode).send({
          error: {
            code: (error as any).code,
            message: error.message,
            details: (error as any).details,
          },
        });
      }
    }
    if (error.validation) {
      return reply.code(400).send({
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Validation failed',
          details: error.validation,
        },
      });
    }
    return reply.code(500).send({
      error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
    });
  });

  // Register the onboarding gate BEFORE other routes
  await testApp.register(onboardingGateFp, { serviceDeps });

  // Register onboarding routes
  await testApp.register(onboardingRoutes, { deps: handlerDeps });

  // Register a dummy gated route to test the gate
  testApp.get('/api/v1/claims', {
    preHandler: [testApp.authenticate],
    handler: async (_request, reply) => {
      return reply.code(200).send({ data: [] });
    },
  });

  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function authedPost(
  target: FastifyInstance,
  url: string,
  body?: Record<string, unknown>,
  token = PHYSICIAN1_SESSION_TOKEN,
) {
  return target.inject({
    method: 'POST',
    url,
    headers: {
      cookie: `session=${token}`,
      'content-type': 'application/json',
    },
    payload: body ?? {},
  });
}

function authedGet(
  target: FastifyInstance,
  url: string,
  token = PHYSICIAN1_SESSION_TOKEN,
) {
  return target.inject({
    method: 'GET',
    url,
    headers: { cookie: `session=${token}` },
  });
}

function unauthedGet(target: FastifyInstance, url: string) {
  return target.inject({ method: 'GET', url });
}

function unauthedPost(target: FastifyInstance, url: string, body?: Record<string, unknown>) {
  return target.inject({
    method: 'POST',
    url,
    headers: { 'content-type': 'application/json' },
    payload: body ?? {},
  });
}

// ---------------------------------------------------------------------------
// Valid step data
// ---------------------------------------------------------------------------

const VALID_STEP1 = {
  billing_number: '12345',
  cpsa_number: 'CPSA001',
  legal_first_name: 'John',
  legal_last_name: 'Doe',
};

const VALID_STEP2 = {
  specialty_code: '01',
  physician_type: 'gp' as const,
};

const VALID_STEP3 = {
  primary_ba_number: 'BA001',
  is_pcpcm_enrolled: false,
};

const VALID_STEP3_PCPCM = {
  primary_ba_number: 'BA001',
  is_pcpcm_enrolled: true,
  pcpcm_ba_number: 'PCPCM001',
  ffs_ba_number: 'FFS001',
};

const VALID_STEP4 = {
  location_name: 'Main Clinic',
  functional_centre_code: 'FCC01',
  address: {
    street: '123 Main St',
    city: 'Edmonton',
    province: 'AB',
    postal_code: 'T5A 0A1',
  },
  community_code: 'CC01',
};

const VALID_STEP5 = {
  contract_id: 'WCB001',
  role: 'physician',
  skill_code: 'GP',
};

const VALID_STEP6 = {
  ahcip_mode: 'auto_clean' as const,
  wcb_mode: 'require_approval' as const,
};

// ---------------------------------------------------------------------------
// Tests: Route CRUD
// ---------------------------------------------------------------------------

describe('Onboarding Progress Integration Tests', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    vi.clearAllMocks();
  });

  // =========================================================================
  // 1. GET /api/v1/onboarding/progress
  // =========================================================================

  describe('GET /api/v1/onboarding/progress', () => {
    it('returns onboarding status for authenticated physician', async () => {
      // No existing progress — getOrCreateProgress will create one
      mockRepo.findProgressByProviderId.mockResolvedValueOnce(null);
      mockRepo.createProgress.mockResolvedValueOnce(makeMockProgress());

      const res = await authedGet(app, '/api/v1/onboarding/progress');
      expect(res.statusCode).toBe(200);

      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.progress_id).toBe(PHYSICIAN1_PROGRESS_ID);
      expect(body.data.step_1_completed).toBe(false);
      expect(body.data.current_step).toBe(1);
      expect(body.data.is_complete).toBe(false);
      expect(body.data.required_steps_remaining).toBe(5);
    });

    it('returns 404 if no provider record exists', async () => {
      mockProviderService.findProviderByUserId.mockResolvedValueOnce(null);

      const res = await authedGet(app, '/api/v1/onboarding/progress');
      expect(res.statusCode).toBe(404);
      expect(res.json().error.code).toBe('NOT_FOUND');
    });

    it('returns existing progress when already started', async () => {
      mockRepo.findProgressByProviderId.mockResolvedValueOnce(
        makeMockProgress({
          step1Completed: true,
          step2Completed: true,
        }),
      );

      const res = await authedGet(app, '/api/v1/onboarding/progress');
      expect(res.statusCode).toBe(200);

      const body = res.json();
      expect(body.data.step_1_completed).toBe(true);
      expect(body.data.step_2_completed).toBe(true);
      expect(body.data.current_step).toBe(3);
      expect(body.data.required_steps_remaining).toBe(3);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedGet(app, '/api/v1/onboarding/progress');
      expect(res.statusCode).toBe(401);
      expect(res.json().data).toBeUndefined();
    });
  });

  // =========================================================================
  // 2. POST /api/v1/onboarding/steps/1 — Professional Identity
  // =========================================================================

  describe('POST /api/v1/onboarding/steps/1', () => {
    it('completes step 1 with valid data', async () => {
      const completedProgress = makeMockProgress({ step1Completed: true });
      mockRepo.markStepCompleted.mockResolvedValueOnce(completedProgress);

      const res = await authedPost(app, '/api/v1/onboarding/steps/1', VALID_STEP1);
      expect(res.statusCode).toBe(200);

      const body = res.json();
      expect(body.data.step_1_completed).toBe(true);
      expect(mockProviderService.createOrUpdateProvider).toHaveBeenCalledTimes(1);
      expect(mockRepo.markStepCompleted).toHaveBeenCalledWith(
        PHYSICIAN1_USER_ID,
        1,
      );
    });

    it('returns 400 with invalid billing number (not 5 digits)', async () => {
      const res = await authedPost(app, '/api/v1/onboarding/steps/1', {
        ...VALID_STEP1,
        billing_number: '123', // too short
      });
      expect(res.statusCode).toBe(400);
    });

    it('returns 400 with non-numeric billing number', async () => {
      const res = await authedPost(app, '/api/v1/onboarding/steps/1', {
        ...VALID_STEP1,
        billing_number: 'ABCDE',
      });
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedPost(app, '/api/v1/onboarding/steps/1', VALID_STEP1);
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // 3. POST /api/v1/onboarding/steps/2 — Specialty & Type
  // =========================================================================

  describe('POST /api/v1/onboarding/steps/2', () => {
    it('completes step 2 with valid data', async () => {
      const completedProgress = makeMockProgress({ step2Completed: true });
      mockRepo.markStepCompleted.mockResolvedValueOnce(completedProgress);

      const res = await authedPost(app, '/api/v1/onboarding/steps/2', VALID_STEP2);
      expect(res.statusCode).toBe(200);
      expect(res.json().data.step_2_completed).toBe(true);
    });

    it('returns 400 with invalid physician_type', async () => {
      const res = await authedPost(app, '/api/v1/onboarding/steps/2', {
        specialty_code: '01',
        physician_type: 'invalid_type',
      });
      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // 4. POST /api/v1/onboarding/steps/3 — Business Arrangement
  // =========================================================================

  describe('POST /api/v1/onboarding/steps/3', () => {
    it('completes step 3 with valid non-PCPCM data', async () => {
      const completedProgress = makeMockProgress({ step3Completed: true });
      mockRepo.markStepCompleted.mockResolvedValueOnce(completedProgress);

      const res = await authedPost(app, '/api/v1/onboarding/steps/3', VALID_STEP3);
      expect(res.statusCode).toBe(200);
      expect(res.json().data.step_3_completed).toBe(true);
    });

    it('completes step 3 with valid PCPCM data', async () => {
      const completedProgress = makeMockProgress({ step3Completed: true });
      mockRepo.markStepCompleted.mockResolvedValueOnce(completedProgress);

      const res = await authedPost(app, '/api/v1/onboarding/steps/3', VALID_STEP3_PCPCM);
      expect(res.statusCode).toBe(200);
      expect(res.json().data.step_3_completed).toBe(true);
      // Should create multiple BAs
      expect(mockProviderService.createBa).toHaveBeenCalled();
    });

    it('returns 400 with PCPCM but missing dual-BA', async () => {
      const res = await authedPost(app, '/api/v1/onboarding/steps/3', {
        primary_ba_number: 'BA001',
        is_pcpcm_enrolled: true,
        // missing pcpcm_ba_number and ffs_ba_number
      });
      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // 5. POST /api/v1/onboarding/steps/4 — Practice Location
  // =========================================================================

  describe('POST /api/v1/onboarding/steps/4', () => {
    it('completes step 4 with valid data', async () => {
      const completedProgress = makeMockProgress({ step4Completed: true });
      mockRepo.markStepCompleted.mockResolvedValueOnce(completedProgress);

      const res = await authedPost(app, '/api/v1/onboarding/steps/4', VALID_STEP4);
      expect(res.statusCode).toBe(200);
      expect(res.json().data.step_4_completed).toBe(true);
      expect(mockProviderService.createLocation).toHaveBeenCalledTimes(1);
    });
  });

  // =========================================================================
  // 6. Invalid step number
  // =========================================================================

  describe('POST /api/v1/onboarding/steps/:step_number (invalid)', () => {
    it('returns 400 for step 8 (out of range)', async () => {
      const res = await authedPost(app, '/api/v1/onboarding/steps/8', {});
      expect(res.statusCode).toBe(400);
    });

    it('returns 400 for step 0 (out of range)', async () => {
      const res = await authedPost(app, '/api/v1/onboarding/steps/0', {});
      expect(res.statusCode).toBe(400);
    });

    it('returns 400 for non-numeric step', async () => {
      const res = await authedPost(app, '/api/v1/onboarding/steps/abc', {});
      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // 7. Completing required steps in sequence marks onboarding complete
  // =========================================================================

  describe('Full onboarding completion flow', () => {
    it('completing steps 1, 2, 3, 4, 7 in sequence sets onboarding complete', async () => {
      // Step 1
      mockRepo.markStepCompleted.mockResolvedValueOnce(
        makeMockProgress({ step1Completed: true }),
      );
      let res = await authedPost(app, '/api/v1/onboarding/steps/1', VALID_STEP1);
      expect(res.statusCode).toBe(200);
      expect(res.json().data.step_1_completed).toBe(true);

      // Step 2
      mockRepo.markStepCompleted.mockResolvedValueOnce(
        makeMockProgress({ step1Completed: true, step2Completed: true }),
      );
      res = await authedPost(app, '/api/v1/onboarding/steps/2', VALID_STEP2);
      expect(res.statusCode).toBe(200);
      expect(res.json().data.step_2_completed).toBe(true);

      // Step 3
      mockRepo.markStepCompleted.mockResolvedValueOnce(
        makeMockProgress({
          step1Completed: true,
          step2Completed: true,
          step3Completed: true,
        }),
      );
      res = await authedPost(app, '/api/v1/onboarding/steps/3', VALID_STEP3);
      expect(res.statusCode).toBe(200);
      expect(res.json().data.step_3_completed).toBe(true);

      // Step 4
      mockRepo.markStepCompleted.mockResolvedValueOnce(
        makeMockProgress({
          step1Completed: true,
          step2Completed: true,
          step3Completed: true,
          step4Completed: true,
        }),
      );
      res = await authedPost(app, '/api/v1/onboarding/steps/4', VALID_STEP4);
      expect(res.statusCode).toBe(200);
      expect(res.json().data.step_4_completed).toBe(true);

      // Step 7 — IMA Acknowledgement (completes onboarding)
      const allRequiredDone = makeMockProgress({
        step1Completed: true,
        step2Completed: true,
        step3Completed: true,
        step4Completed: true,
        step7Completed: true,
      });
      mockRepo.markStepCompleted.mockResolvedValueOnce(allRequiredDone);
      mockRepo.markOnboardingCompleted.mockResolvedValueOnce({
        ...allRequiredDone,
        completedAt: new Date(),
      });

      res = await authedPost(app, '/api/v1/onboarding/steps/7', {});
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.step_7_completed).toBe(true);
      expect(body.data.is_complete).toBe(true);
      expect(body.data.required_steps_remaining).toBe(0);
      expect(mockRepo.markOnboardingCompleted).toHaveBeenCalledWith(PHYSICIAN1_USER_ID);
    });
  });
});

// ---------------------------------------------------------------------------
// Tests: Onboarding Gate Middleware
// ---------------------------------------------------------------------------

describe('Onboarding Gate Middleware', () => {
  let gatedApp: FastifyInstance;

  beforeAll(async () => {
    gatedApp = await buildGatedTestApp();
  });

  afterAll(async () => {
    await gatedApp.close();
  });

  beforeEach(() => {
    vi.clearAllMocks();
  });

  // =========================================================================
  // 8. Gate blocks /api/v1/claims when onboarding incomplete
  // =========================================================================

  it('blocks /api/v1/claims when onboarding incomplete', async () => {
    // Provider exists but onboarding is not complete
    mockProviderService.findProviderByUserId.mockResolvedValueOnce({
      providerId: PHYSICIAN1_USER_ID,
    });
    mockRepo.findProgressByProviderId.mockResolvedValueOnce(
      makeMockProgress({ step1Completed: true }),
    );

    const res = await authedGet(gatedApp, '/api/v1/claims');
    expect(res.statusCode).toBe(403);
    const body = res.json();
    expect(body.error.message).toBe('onboarding_required');
    expect(body.error.current_step).toBeDefined();
  });

  // =========================================================================
  // 9. Gate allows /api/v1/onboarding routes through
  // =========================================================================

  it('allows /api/v1/onboarding routes through', async () => {
    // Even with incomplete onboarding, the onboarding routes work
    mockRepo.findProgressByProviderId.mockResolvedValueOnce(null);
    mockRepo.createProgress.mockResolvedValueOnce(makeMockProgress());

    const res = await authedGet(gatedApp, '/api/v1/onboarding/progress');
    expect(res.statusCode).toBe(200);
  });

  // =========================================================================
  // 10. Gate skips check for delegate users
  // =========================================================================

  it('skips onboarding check for delegate users', async () => {
    const res = await authedGet(
      gatedApp,
      '/api/v1/claims',
      DELEGATE_SESSION_TOKEN,
    );
    expect(res.statusCode).toBe(200);
  });

  // =========================================================================
  // Gate allows through when onboarding is complete
  // =========================================================================

  it('allows through when onboarding is complete', async () => {
    mockProviderService.findProviderByUserId.mockResolvedValueOnce({
      providerId: PHYSICIAN1_USER_ID,
    });
    mockRepo.findProgressByProviderId.mockResolvedValueOnce(
      makeMockProgress({
        step1Completed: true,
        step2Completed: true,
        step3Completed: true,
        step4Completed: true,
        step7Completed: true,
        completedAt: new Date(),
      }),
    );

    const res = await authedGet(gatedApp, '/api/v1/claims');
    expect(res.statusCode).toBe(200);
  });

  it('allows unauthenticated requests through (auth plugin handles 401)', async () => {
    const res = await unauthedGet(gatedApp, '/api/v1/claims');
    // The gate skips because no authContext; the route's preHandler (authenticate) returns 401
    expect(res.statusCode).toBe(401);
  });
});
