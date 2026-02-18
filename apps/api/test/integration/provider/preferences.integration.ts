import { describe, it, expect, vi, beforeAll, afterAll } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { createHash, randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Environment setup
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);

// ---------------------------------------------------------------------------
// Mock otplib
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
// Imports
// ---------------------------------------------------------------------------

import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { providerRoutes } from '../../../src/domains/provider/provider.routes.js';
import { type ProviderHandlerDeps } from '../../../src/domains/provider/provider.handlers.js';
import { type ProviderServiceDeps } from '../../../src/domains/provider/provider.service.js';

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Fixed identities
// ---------------------------------------------------------------------------

const PHYSICIAN_USER_ID = '00000000-a200-0000-0000-000000000001';
const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_SESSION_ID = '00000000-a200-0000-0000-000000000002';

// ---------------------------------------------------------------------------
// Test data
// ---------------------------------------------------------------------------

const MOCK_PROVIDER = {
  providerId: PHYSICIAN_USER_ID,
  billingNumber: '123456',
  cpsaRegistrationNumber: 'CPSA12345',
  firstName: 'Jane',
  middleName: null,
  lastName: 'Smith',
  specialtyCode: 'GP',
  specialtyDescription: 'General Practice',
  subSpecialtyCode: null,
  physicianType: 'GP',
  status: 'ACTIVE',
  onboardingCompleted: true,
  createdAt: new Date(),
  updatedAt: new Date(),
};

const PREFERENCE_ID = '00000000-a200-0000-0000-000000000010';

const MOCK_PREFERENCES = {
  preferenceId: PREFERENCE_ID,
  providerId: PHYSICIAN_USER_ID,
  ahcipSubmissionMode: 'AUTO_CLEAN',
  wcbSubmissionMode: 'REQUIRE_APPROVAL',
  batchReviewReminder: true,
  deadlineReminderDays: 7,
  updatedBy: PHYSICIAN_USER_ID,
  createdAt: new Date(),
  updatedAt: new Date(),
};

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      if (tokenHash === PHYSICIAN_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: PHYSICIAN_SESSION_ID,
            userId: PHYSICIAN_USER_ID,
            tokenHash: PHYSICIAN_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: PHYSICIAN_USER_ID,
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

function createMockProviderRepo() {
  return {
    // Provider
    findProviderById: vi.fn(async (providerId: string) => {
      if (providerId === PHYSICIAN_USER_ID) return { ...MOCK_PROVIDER };
      return undefined;
    }),
    getFullProviderContext: vi.fn(async () => undefined),
    updateProvider: vi.fn(),
    getOnboardingStatus: vi.fn(),
    createProvider: vi.fn(),

    // BAs (stubs)
    listBasForProvider: vi.fn(async () => []),
    listActiveBasForProvider: vi.fn(async () => []),
    countActiveBasForProvider: vi.fn(async () => 0),
    findBaByNumber: vi.fn(async () => undefined),
    createBa: vi.fn(),
    findBaById: vi.fn(),
    updateBa: vi.fn(),
    deactivateBa: vi.fn(),

    // Locations (stubs)
    listLocationsForProvider: vi.fn(async () => []),
    listActiveLocationsForProvider: vi.fn(async () => []),
    createLocation: vi.fn(),
    findLocationById: vi.fn(),
    updateLocation: vi.fn(),
    setDefaultLocation: vi.fn(),
    deactivateLocation: vi.fn(),
    getDefaultLocation: vi.fn(),

    // PCPCM (stubs)
    findPcpcmEnrolmentForProvider: vi.fn(async () => undefined),
    createPcpcmEnrolment: vi.fn(),
    updatePcpcmEnrolment: vi.fn(),

    // WCB configs (stubs)
    listWcbConfigsForProvider: vi.fn(async () => []),
    createWcbConfig: vi.fn(),
    findWcbConfigById: vi.fn(),
    updateWcbConfig: vi.fn(),
    deleteWcbConfig: vi.fn(),
    getAggregatedFormPermissions: vi.fn(async () => []),
    getWcbConfigForForm: vi.fn(),

    // Delegates (stubs)
    createDelegateRelationship: vi.fn(),
    findRelationshipById: vi.fn(),
    acceptRelationship: vi.fn(),
    listDelegatesForPhysician: vi.fn(async () => []),
    updateDelegatePermissions: vi.fn(),
    revokeRelationship: vi.fn(),
    listPhysiciansForDelegate: vi.fn(async () => []),
    findActiveRelationship: vi.fn(),

    // Submission preferences
    findSubmissionPreferences: vi.fn(async (providerId: string) => {
      if (providerId === PHYSICIAN_USER_ID) return { ...MOCK_PREFERENCES };
      return undefined;
    }),
    createSubmissionPreferences: vi.fn(),
    updateSubmissionPreferences: vi.fn(async (providerId: string, data: Record<string, unknown>, _actorId: string) => {
      if (providerId === PHYSICIAN_USER_ID) {
        return { ...MOCK_PREFERENCES, ...data, updatedAt: new Date() };
      }
      return undefined;
    }),

    // H-Link (stubs)
    findHlinkConfig: vi.fn(async () => undefined),
    createHlinkConfig: vi.fn(),
    updateHlinkConfig: vi.fn(),

    // Internal
    getBaForClaim: vi.fn(),
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let mockRepo: ReturnType<typeof createMockProviderRepo>;
let mockAuditRepo: { appendAuditLog: ReturnType<typeof vi.fn> };
let mockEvents: { emit: ReturnType<typeof vi.fn> };

async function buildTestApp(): Promise<FastifyInstance> {
  mockRepo = createMockProviderRepo();
  mockAuditRepo = { appendAuditLog: vi.fn() };
  mockEvents = { emit: vi.fn() };

  const serviceDeps: ProviderServiceDeps = {
    repo: mockRepo as any,
    auditRepo: mockAuditRepo,
    events: mockEvents,
  };

  const handlerDeps: ProviderHandlerDeps = { serviceDeps };

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  const mockSessionRepo = createMockSessionRepo();
  await testApp.register(authPluginFp, {
    sessionDeps: {
      sessionRepo: mockSessionRepo,
      auditRepo: { appendAuditLog: vi.fn() },
      events: { emit: vi.fn() },
    },
  });

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

  await testApp.register(providerRoutes, { deps: handlerDeps });
  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function authedGet(url: string) {
  return app.inject({
    method: 'GET',
    url,
    headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
  });
}

function authedPut(url: string, body: Record<string, unknown>) {
  return app.inject({
    method: 'PUT',
    url,
    headers: {
      cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
      'content-type': 'application/json',
    },
    payload: body,
  });
}

function unauthedGet(url: string) {
  return app.inject({ method: 'GET', url });
}

function unauthedPut(url: string, body: Record<string, unknown>) {
  return app.inject({
    method: 'PUT',
    url,
    headers: { 'content-type': 'application/json' },
    payload: body,
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Submission Preferences Integration Tests', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  // =========================================================================
  // GET /api/v1/providers/me/submission-preferences
  // =========================================================================

  describe('GET /api/v1/providers/me/submission-preferences', () => {
    it('returns current submission preferences', async () => {
      const res = await authedGet('/api/v1/providers/me/submission-preferences');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.ahcipSubmissionMode).toBe('AUTO_CLEAN');
      expect(body.data.wcbSubmissionMode).toBe('REQUIRE_APPROVAL');
      expect(body.data.batchReviewReminder).toBe(true);
      expect(body.data.deadlineReminderDays).toBe(7);
    });

    it('returns null when preferences not initialized', async () => {
      mockRepo.findSubmissionPreferences.mockResolvedValueOnce(undefined);

      const res = await authedGet('/api/v1/providers/me/submission-preferences');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeNull();
    });

    it('returns 401 without session', async () => {
      const res = await unauthedGet('/api/v1/providers/me/submission-preferences');
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // PUT /api/v1/providers/me/submission-preferences
  // =========================================================================

  describe('PUT /api/v1/providers/me/submission-preferences', () => {
    it('updates submission modes', async () => {
      const res = await authedPut('/api/v1/providers/me/submission-preferences', {
        ahcip_submission_mode: 'AUTO_ALL',
        wcb_submission_mode: 'AUTO_CLEAN',
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.ahcipSubmissionMode).toBe('AUTO_ALL');
      expect(body.data.wcbSubmissionMode).toBe('AUTO_CLEAN');
    });

    it('updates batch review reminder', async () => {
      const res = await authedPut('/api/v1/providers/me/submission-preferences', {
        batch_review_reminder: false,
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
    });

    it('updates deadline reminder days', async () => {
      const res = await authedPut('/api/v1/providers/me/submission-preferences', {
        deadline_reminder_days: 14,
      });
      expect(res.statusCode).toBe(200);
    });

    it('rejects invalid submission mode', async () => {
      const res = await authedPut('/api/v1/providers/me/submission-preferences', {
        ahcip_submission_mode: 'INVALID_MODE',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects deadline_reminder_days outside valid range', async () => {
      const res = await authedPut('/api/v1/providers/me/submission-preferences', {
        deadline_reminder_days: 0,
      });
      expect(res.statusCode).toBe(400);

      const res2 = await authedPut('/api/v1/providers/me/submission-preferences', {
        deadline_reminder_days: 31,
      });
      expect(res2.statusCode).toBe(400);
    });

    it('returns 401 without session', async () => {
      const res = await unauthedPut('/api/v1/providers/me/submission-preferences', {
        ahcip_submission_mode: 'AUTO_ALL',
      });
      expect(res.statusCode).toBe(401);
    });

    it('emits audit log on update', async () => {
      await authedPut('/api/v1/providers/me/submission-preferences', {
        ahcip_submission_mode: 'REQUIRE_APPROVAL',
      });
      expect(mockAuditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'submission_preference.changed',
          resourceType: 'submission_preferences',
        }),
      );
    });
  });
});
