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
import { onboardingRoutes } from '../../../src/domains/onboarding/onboarding.routes.js';
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

const PHYSICIAN2_USER_ID = '00000000-1111-0000-0000-000000000002';
const PHYSICIAN2_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN2_SESSION_TOKEN_HASH = hashToken(PHYSICIAN2_SESSION_TOKEN);

// Test BA IDs
const BA_ID_PENDING = '00000000-4444-0000-0000-000000000001';
const BA_ID_ACTIVE = '00000000-4444-0000-0000-000000000002';
const BA_ID_OTHER_PHYSICIAN = '00000000-4444-0000-0000-000000000003';

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
      if (tokenHash === PHYSICIAN2_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: '00000000-2222-0000-0000-000000000002',
            userId: PHYSICIAN2_USER_ID,
            tokenHash: PHYSICIAN2_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: PHYSICIAN2_USER_ID,
            role: 'PHYSICIAN',
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
    markPatientImportCompleted: vi.fn(async (providerId: string) =>
      makeMockProgress({ providerId, patientImportCompleted: true }),
    ),
    markGuidedTourCompleted: vi.fn(async (providerId: string) =>
      makeMockProgress({ providerId, guidedTourCompleted: true }),
    ),
    markGuidedTourDismissed: vi.fn(async (providerId: string) =>
      makeMockProgress({ providerId, guidedTourDismissed: true }),
    ),
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
      if (userId === PHYSICIAN2_USER_ID) {
        return { providerId: PHYSICIAN2_USER_ID };
      }
      return null;
    }),
    getProviderDetails: vi.fn(async () => null),
    findBaById: vi.fn(async (baId: string, providerId: string) => {
      // BA_ID_PENDING belongs to physician1
      if (baId === BA_ID_PENDING && providerId === PHYSICIAN1_USER_ID) {
        return { baId: BA_ID_PENDING, providerId: PHYSICIAN1_USER_ID, status: 'PENDING' };
      }
      // BA_ID_ACTIVE belongs to physician1 but is already ACTIVE
      if (baId === BA_ID_ACTIVE && providerId === PHYSICIAN1_USER_ID) {
        return { baId: BA_ID_ACTIVE, providerId: PHYSICIAN1_USER_ID, status: 'ACTIVE' };
      }
      // BA_ID_OTHER_PHYSICIAN belongs to physician2 — physician1 must NOT see it
      if (baId === BA_ID_OTHER_PHYSICIAN && providerId === PHYSICIAN2_USER_ID) {
        return { baId: BA_ID_OTHER_PHYSICIAN, providerId: PHYSICIAN2_USER_ID, status: 'PENDING' };
      }
      return null;
    }),
    updateBaStatus: vi.fn(async (_providerId: string, baId: string, status: string) => ({
      baId,
      status,
    })),
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

function unauthedPost(
  target: FastifyInstance,
  url: string,
  body?: Record<string, unknown>,
) {
  return target.inject({
    method: 'POST',
    url,
    headers: { 'content-type': 'application/json' },
    payload: body ?? {},
  });
}

// ---------------------------------------------------------------------------
// Tests: Supplementary Onboarding Endpoints
// ---------------------------------------------------------------------------

describe('Onboarding Supplementary Integration Tests', () => {
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
  // 1. POST /api/v1/onboarding/guided-tour/complete
  // =========================================================================

  describe('POST /api/v1/onboarding/guided-tour/complete', () => {
    it('marks guided tour completed and returns updated progress', async () => {
      const progressWithTour = makeMockProgress({
        guidedTourCompleted: false,
        completedAt: new Date(),
      });
      mockRepo.findProgressByProviderId.mockResolvedValueOnce(progressWithTour);
      // After completing tour, getOrCreateProgress re-fetches
      mockRepo.findProgressByProviderId.mockResolvedValueOnce(
        makeMockProgress({ guidedTourCompleted: true, completedAt: new Date() }),
      );

      const res = await authedPost(app, '/api/v1/onboarding/guided-tour/complete');
      expect(res.statusCode).toBe(200);

      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.guided_tour_completed).toBe(true);
      expect(mockRepo.markGuidedTourCompleted).toHaveBeenCalledWith(PHYSICIAN1_USER_ID);
    });

    it('is idempotent — second call succeeds without error', async () => {
      // Tour already completed
      const alreadyCompleted = makeMockProgress({
        guidedTourCompleted: true,
        completedAt: new Date(),
      });
      mockRepo.findProgressByProviderId.mockResolvedValueOnce(alreadyCompleted);
      // getOrCreateProgress re-fetches
      mockRepo.findProgressByProviderId.mockResolvedValueOnce(alreadyCompleted);

      const res = await authedPost(app, '/api/v1/onboarding/guided-tour/complete');
      expect(res.statusCode).toBe(200);

      const body = res.json();
      expect(body.data.guided_tour_completed).toBe(true);
      // Should NOT call markGuidedTourCompleted again (idempotent check in service)
      expect(mockRepo.markGuidedTourCompleted).not.toHaveBeenCalled();
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedPost(app, '/api/v1/onboarding/guided-tour/complete');
      expect(res.statusCode).toBe(401);
      expect(res.json().data).toBeUndefined();
    });
  });

  // =========================================================================
  // 2. POST /api/v1/onboarding/guided-tour/dismiss
  // =========================================================================

  describe('POST /api/v1/onboarding/guided-tour/dismiss', () => {
    it('marks guided tour dismissed and returns updated progress', async () => {
      const progressWithTour = makeMockProgress({
        guidedTourDismissed: false,
        completedAt: new Date(),
      });
      mockRepo.findProgressByProviderId.mockResolvedValueOnce(progressWithTour);
      // After dismissing tour, getOrCreateProgress re-fetches
      mockRepo.findProgressByProviderId.mockResolvedValueOnce(
        makeMockProgress({ guidedTourDismissed: true, completedAt: new Date() }),
      );

      const res = await authedPost(app, '/api/v1/onboarding/guided-tour/dismiss');
      expect(res.statusCode).toBe(200);

      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.guided_tour_dismissed).toBe(true);
      expect(mockRepo.markGuidedTourDismissed).toHaveBeenCalledWith(PHYSICIAN1_USER_ID);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedPost(app, '/api/v1/onboarding/guided-tour/dismiss');
      expect(res.statusCode).toBe(401);
      expect(res.json().data).toBeUndefined();
    });
  });

  // =========================================================================
  // 3. POST /api/v1/onboarding/patient-import/complete
  // =========================================================================

  describe('POST /api/v1/onboarding/patient-import/complete', () => {
    it('marks patient import completed and returns updated progress', async () => {
      const progress = makeMockProgress({ patientImportCompleted: false });
      mockRepo.findProgressByProviderId.mockResolvedValueOnce(progress);
      // After completing import, getOrCreateProgress re-fetches
      mockRepo.findProgressByProviderId.mockResolvedValueOnce(
        makeMockProgress({ patientImportCompleted: true }),
      );

      const res = await authedPost(app, '/api/v1/onboarding/patient-import/complete');
      expect(res.statusCode).toBe(200);

      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.patient_import_completed).toBe(true);
      expect(mockRepo.markPatientImportCompleted).toHaveBeenCalledWith(PHYSICIAN1_USER_ID);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedPost(app, '/api/v1/onboarding/patient-import/complete');
      expect(res.statusCode).toBe(401);
      expect(res.json().data).toBeUndefined();
    });
  });

  // =========================================================================
  // 4. POST /api/v1/onboarding/ba/:ba_id/confirm-active
  // =========================================================================

  describe('POST /api/v1/onboarding/ba/:ba_id/confirm-active', () => {
    it('updates PENDING BA to ACTIVE and returns updated status', async () => {
      // The progress lookup in service
      mockRepo.findProgressByProviderId.mockResolvedValueOnce(makeMockProgress());

      // After confirmBaActive, findBaById is called again in handler
      // First call is in service (via providerService.findBaById) — returns PENDING
      // After update, handler calls findBaById again — returns ACTIVE
      mockProviderService.findBaById
        .mockResolvedValueOnce({
          baId: BA_ID_PENDING,
          providerId: PHYSICIAN1_USER_ID,
          status: 'PENDING',
        })
        .mockResolvedValueOnce({
          baId: BA_ID_PENDING,
          providerId: PHYSICIAN1_USER_ID,
          status: 'ACTIVE',
        });

      const res = await authedPost(
        app,
        `/api/v1/onboarding/ba/${BA_ID_PENDING}/confirm-active`,
      );
      expect(res.statusCode).toBe(200);

      const body = res.json();
      expect(body.data.ba_id).toBe(BA_ID_PENDING);
      expect(body.data.status).toBe('ACTIVE');
      expect(mockProviderService.updateBaStatus).toHaveBeenCalledWith(
        PHYSICIAN1_USER_ID,
        BA_ID_PENDING,
        'ACTIVE',
        PHYSICIAN1_USER_ID,
      );
    });

    it('returns 400 for non-PENDING BA', async () => {
      // findBaById returns an ACTIVE BA
      mockProviderService.findBaById.mockResolvedValueOnce({
        baId: BA_ID_ACTIVE,
        providerId: PHYSICIAN1_USER_ID,
        status: 'ACTIVE',
      });

      const res = await authedPost(
        app,
        `/api/v1/onboarding/ba/${BA_ID_ACTIVE}/confirm-active`,
      );
      // BusinessRuleError → 422
      expect(res.statusCode).toBe(422);
      expect(res.json().error.code).toBe('BUSINESS_RULE_VIOLATION');
    });

    it("returns 404 for another physician's BA (cross-tenant isolation)", async () => {
      // findBaById returns null for physician1 looking up physician2's BA
      mockProviderService.findBaById.mockResolvedValueOnce(null);

      const res = await authedPost(
        app,
        `/api/v1/onboarding/ba/${BA_ID_OTHER_PHYSICIAN}/confirm-active`,
      );
      expect(res.statusCode).toBe(404);
      expect(res.json().error.code).toBe('NOT_FOUND');
    });

    it('returns 400 for non-UUID ba_id parameter', async () => {
      const res = await authedPost(
        app,
        '/api/v1/onboarding/ba/not-a-uuid/confirm-active',
      );
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedPost(
        app,
        `/api/v1/onboarding/ba/${BA_ID_PENDING}/confirm-active`,
      );
      expect(res.statusCode).toBe(401);
      expect(res.json().data).toBeUndefined();
    });
  });
});
