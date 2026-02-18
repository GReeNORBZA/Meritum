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
import { providerRoutes } from '../../../src/domains/provider/provider.routes.js';
import { type ProviderHandlerDeps } from '../../../src/domains/provider/provider.handlers.js';
import { type ProviderServiceDeps } from '../../../src/domains/provider/provider.service.js';

// ---------------------------------------------------------------------------
// Helper: hashToken
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

const PHYSICIAN_USER_ID = '00000000-1111-0000-0000-000000000001';
const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_SESSION_ID = '00000000-2222-0000-0000-000000000001';

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
  onboardingCompleted: false,
  createdAt: new Date(),
  updatedAt: new Date(),
};

const MOCK_PROVIDER_CONTEXT = {
  provider_id: PHYSICIAN_USER_ID,
  billing_number: '123456',
  specialty_code: 'GP',
  physician_type: 'GP',
  bas: [],
  default_location: null,
  all_locations: [],
  pcpcm_enrolled: false,
  pcpcm_ba_number: null,
  ffs_ba_number: null,
  wcb_configs: [],
  default_wcb_config: null,
  submission_preferences: null,
  hlink_accreditation_status: null,
  hlink_submitter_prefix: null,
  onboarding_completed: false,
  status: 'ACTIVE',
};

// ---------------------------------------------------------------------------
// Mock session repo
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

// ---------------------------------------------------------------------------
// Mock provider repository
// ---------------------------------------------------------------------------

function createMockProviderRepo() {
  return {
    getFullProviderContext: vi.fn(async (providerId: string) => {
      if (providerId === PHYSICIAN_USER_ID) return { ...MOCK_PROVIDER_CONTEXT };
      return undefined;
    }),
    findProviderById: vi.fn(async (providerId: string) => {
      if (providerId === PHYSICIAN_USER_ID) return { ...MOCK_PROVIDER };
      return undefined;
    }),
    updateProvider: vi.fn(async (providerId: string, data: Record<string, unknown>) => {
      if (providerId === PHYSICIAN_USER_ID) {
        return { ...MOCK_PROVIDER, ...data, updatedAt: new Date() };
      }
      return undefined;
    }),
    getOnboardingStatus: vi.fn(async (providerId: string) => {
      if (providerId === PHYSICIAN_USER_ID) {
        return {
          onboardingCompleted: false,
          populated: ['billingNumber', 'cpsaRegistrationNumber', 'specialtyCode', 'physicianType'],
          missing: [],
          complete: false,
        };
      }
      return undefined;
    }),
    listActiveBasForProvider: vi.fn(async () => []),
    listActiveLocationsForProvider: vi.fn(async () => []),
    listBasForProvider: vi.fn(async () => []),
    listLocationsForProvider: vi.fn(async () => []),
    countActiveBasForProvider: vi.fn(async () => 0),
    findBaByNumber: vi.fn(async () => undefined),
    createBa: vi.fn(),
    findBaById: vi.fn(),
    updateBa: vi.fn(),
    deactivateBa: vi.fn(),
    createLocation: vi.fn(),
    findLocationById: vi.fn(),
    updateLocation: vi.fn(),
    setDefaultLocation: vi.fn(),
    deactivateLocation: vi.fn(),
    getDefaultLocation: vi.fn(),
    findPcpcmEnrolmentForProvider: vi.fn(),
    createPcpcmEnrolment: vi.fn(),
    updatePcpcmEnrolment: vi.fn(),
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

  const handlerDeps: ProviderHandlerDeps = {
    serviceDeps,
  };

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

  // Register provider routes
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

function authedPost(url: string, body?: Record<string, unknown>) {
  return app.inject({
    method: 'POST',
    url,
    headers: {
      cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
      'content-type': 'application/json',
    },
    payload: body ?? {},
  });
}

function unauthedGet(url: string) {
  return app.inject({
    method: 'GET',
    url,
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Provider Profile Integration Tests', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  describe('GET /api/v1/providers/me', () => {
    it('returns full profile for authenticated physician', async () => {
      const res = await authedGet('/api/v1/providers/me');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.provider_id).toBe(PHYSICIAN_USER_ID);
      expect(body.data.billing_number).toBe('123456');
      expect(body.data.specialty_code).toBe('GP');
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedGet('/api/v1/providers/me');
      expect(res.statusCode).toBe(401);
      expect(res.json().data).toBeUndefined();
    });
  });

  describe('PUT /api/v1/providers/me', () => {
    it('updates profile and returns updated data', async () => {
      const res = await authedPut('/api/v1/providers/me', {
        first_name: 'Janet',
        specialty_code: 'IM',
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(mockRepo.updateProvider).toHaveBeenCalled();
    });

    it('returns 400 for invalid body', async () => {
      const res = await authedPut('/api/v1/providers/me', {
        physician_type: 'INVALID_TYPE',
      });
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without authentication', async () => {
      const res = app.inject({
        method: 'PUT',
        url: '/api/v1/providers/me',
        headers: { 'content-type': 'application/json' },
        payload: { first_name: 'Test' },
      });
      expect((await res).statusCode).toBe(401);
    });
  });

  describe('GET /api/v1/providers/me/onboarding-status', () => {
    it('returns onboarding status with step checklist', async () => {
      const res = await authedGet('/api/v1/providers/me/onboarding-status');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.steps).toBeDefined();
      expect(Array.isArray(body.data.steps)).toBe(true);
      expect(body.data.onboardingCompleted).toBe(false);
    });

    it('returns missing fields for incomplete provider', async () => {
      const res = await authedGet('/api/v1/providers/me/onboarding-status');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      // BAs and locations are empty, so those steps should be incomplete
      const baStep = body.data.steps.find((s: any) => s.field === 'business_arrangement');
      expect(baStep.complete).toBe(false);
      const locationStep = body.data.steps.find((s: any) => s.field === 'location');
      expect(locationStep.complete).toBe(false);
    });
  });

  describe('POST /api/v1/providers/me/complete-onboarding', () => {
    it('fails with missing fields list when requirements not met', async () => {
      const res = await authedPost('/api/v1/providers/me/complete-onboarding');
      expect(res.statusCode).toBe(422);
      const body = res.json();
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('BUSINESS_RULE_VIOLATION');
      expect(body.error.details.missingFields).toBeDefined();
      expect(body.error.details.missingFields).toContain('business_arrangement');
      expect(body.error.details.missingFields).toContain('location');
    });

    it('succeeds when all required fields are set', async () => {
      // Override mock to simulate complete provider
      mockRepo.listActiveBasForProvider.mockResolvedValueOnce([
        { baId: 'ba-1', providerId: PHYSICIAN_USER_ID, baType: 'FFS', status: 'ACTIVE', isPrimary: true },
      ]);
      mockRepo.listActiveLocationsForProvider.mockResolvedValueOnce([
        { locationId: 'loc-1', providerId: PHYSICIAN_USER_ID, name: 'Main', isActive: true },
      ]);
      mockRepo.findProviderById.mockResolvedValueOnce({
        ...MOCK_PROVIDER,
        onboardingCompleted: false,
      });
      mockRepo.updateProvider.mockResolvedValueOnce({
        ...MOCK_PROVIDER,
        onboardingCompleted: true,
      });

      const res = await authedPost('/api/v1/providers/me/complete-onboarding');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.message).toBe('Onboarding completed');
      expect(body.data.provider.onboardingCompleted).toBe(true);
    });
  });
});
