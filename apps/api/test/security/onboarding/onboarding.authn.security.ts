import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

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
// Real imports (after mocks are hoisted)
// ---------------------------------------------------------------------------

import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { onboardingRoutes } from '../../../src/domains/onboarding/onboarding.routes.js';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { type OnboardingHandlerDeps } from '../../../src/domains/onboarding/onboarding.handlers.js';
import { type OnboardingServiceDeps } from '../../../src/domains/onboarding/onboarding.service.js';
import {
  type SessionManagementDeps,
  hashToken,
} from '../../../src/domains/iam/iam.service.js';
import { randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Fixed test user/session
// ---------------------------------------------------------------------------

const FIXED_SESSION_TOKEN = randomBytes(32).toString('hex');
const FIXED_SESSION_TOKEN_HASH = hashToken(FIXED_SESSION_TOKEN);
const FIXED_USER_ID = '22222222-0000-0000-0000-000000000001';
const FIXED_PROVIDER_ID = FIXED_USER_ID;
const FIXED_SESSION_ID = '33333333-0000-0000-0000-000000000001';

// ---------------------------------------------------------------------------
// Mock stores
// ---------------------------------------------------------------------------

interface MockUser {
  userId: string;
  email: string;
  passwordHash: string;
  mfaConfigured: boolean;
  totpSecretEncrypted: string | null;
  failedLoginCount: number;
  lockedUntil: Date | null;
  isActive: boolean;
  role?: string;
  subscriptionStatus?: string;
}

interface MockSession {
  sessionId: string;
  userId: string;
  tokenHash: string;
  ipAddress: string;
  userAgent: string;
  createdAt: Date;
  lastActiveAt: Date;
  revoked: boolean;
  revokedReason: string | null;
}

let users: MockUser[] = [];
let sessions: MockSession[] = [];
let auditEntries: Array<Record<string, unknown>> = [];

// ---------------------------------------------------------------------------
// Mock repositories
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    createSession: vi.fn(async () => {
      return { sessionId: '44444444-0000-0000-0000-000000000001' };
    }),
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      const session = sessions.find((s) => s.tokenHash === tokenHash && !s.revoked);
      if (!session) return undefined;
      const user = users.find((u) => u.userId === session.userId);
      if (!user) return undefined;
      return {
        session,
        user: {
          userId: user.userId,
          role: user.role ?? 'PHYSICIAN',
          subscriptionStatus: user.subscriptionStatus ?? 'TRIAL',
        },
      };
    }),
    refreshSession: vi.fn(async () => {}),
    listActiveSessions: vi.fn(async () => []),
    revokeSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
  };
}

function createMockAuditRepo() {
  return {
    appendAuditLog: vi.fn(async (entry: Record<string, unknown>) => {
      auditEntries.push(entry);
    }),
  };
}

function createMockEvents() {
  return { emit: vi.fn() };
}

// ---------------------------------------------------------------------------
// Mock onboarding repository (stubs — not exercised in authn tests)
// ---------------------------------------------------------------------------

function createStubOnboardingRepo() {
  return {
    createProgress: vi.fn(async () => ({})),
    findProgressByProviderId: vi.fn(async () => null),
    markStepCompleted: vi.fn(async () => ({})),
    markOnboardingCompleted: vi.fn(async () => ({})),
    markPatientImportCompleted: vi.fn(async () => ({})),
    markGuidedTourCompleted: vi.fn(async () => ({})),
    markGuidedTourDismissed: vi.fn(async () => ({})),
    createImaRecord: vi.fn(async () => ({})),
    findLatestImaRecord: vi.fn(async () => null),
    listImaRecords: vi.fn(async () => []),
  };
}

// ---------------------------------------------------------------------------
// Mock provider service (stubs — not exercised in authn tests)
// ---------------------------------------------------------------------------

function createStubProviderService() {
  return {
    createOrUpdateProvider: vi.fn(async () => ({ providerId: FIXED_USER_ID })),
    updateProviderSpecialty: vi.fn(async () => {}),
    createBa: vi.fn(async () => ({ baId: '00000000-0000-0000-0000-000000000099' })),
    createLocation: vi.fn(async () => ({ locationId: '00000000-0000-0000-0000-000000000099' })),
    createWcbConfig: vi.fn(async () => ({ wcbConfigId: '00000000-0000-0000-0000-000000000099' })),
    updateSubmissionPreferences: vi.fn(async () => {}),
    findProviderByUserId: vi.fn(async () => ({ providerId: FIXED_PROVIDER_ID })),
    getProviderDetails: vi.fn(async () => null),
    findBaById: vi.fn(async () => null),
    updateBaStatus: vi.fn(async () => ({ baId: '', status: '' })),
  };
}

// ---------------------------------------------------------------------------
// Mock reference data service
// ---------------------------------------------------------------------------

function createStubReferenceData() {
  return {
    validateSpecialtyCode: vi.fn(async () => true),
    validateFunctionalCentreCode: vi.fn(async () => true),
    validateCommunityCode: vi.fn(async () => true),
    getRrnpRate: vi.fn(async () => null),
    getWcbFormTypes: vi.fn(async () => ['C8', 'C10']),
  };
}

// ---------------------------------------------------------------------------
// Stub service deps
// ---------------------------------------------------------------------------

function createStubServiceDeps(): OnboardingServiceDeps {
  return {
    repo: createStubOnboardingRepo() as any,
    auditRepo: createMockAuditRepo(),
    events: createMockEvents(),
    providerService: createStubProviderService(),
    referenceData: createStubReferenceData(),
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let mockSessionRepo: ReturnType<typeof createMockSessionRepo>;

async function buildTestApp(): Promise<FastifyInstance> {
  mockSessionRepo = createMockSessionRepo();

  const sessionDeps: SessionManagementDeps = {
    sessionRepo: mockSessionRepo,
    auditRepo: createMockAuditRepo(),
    events: createMockEvents(),
  };

  const handlerDeps: OnboardingHandlerDeps = {
    serviceDeps: createStubServiceDeps(),
  };

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  await testApp.register(authPluginFp, { sessionDeps });

  testApp.setErrorHandler((error, _request, reply) => {
    if ('statusCode' in error && 'code' in error && typeof (error as any).code === 'string') {
      const statusCode = (error as any).statusCode ?? 500;
      if (statusCode >= 400 && statusCode < 500) {
        return reply.code(statusCode).send({
          error: { code: (error as any).code, message: error.message },
        });
      }
    }
    if (error.validation) {
      return reply.code(400).send({
        error: { code: 'VALIDATION_ERROR', message: 'Validation failed', details: error.validation },
      });
    }
    return reply.code(500).send({
      error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
    });
  });

  await testApp.register(onboardingRoutes, { deps: handlerDeps });
  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Generates a tampered cookie (valid format but won't match any session hash). */
function createTamperedCookie(): string {
  return randomBytes(32).toString('hex').replace(/[0-9a-f]$/, 'x');
}

/** Expired session token — seeded as revoked in mock store. */
const EXPIRED_SESSION_TOKEN = randomBytes(32).toString('hex');
const EXPIRED_SESSION_TOKEN_HASH = hashToken(EXPIRED_SESSION_TOKEN);
const EXPIRED_SESSION_ID = '55555555-0000-0000-0000-000000000001';

/** Placeholder UUID for route params. */
const PLACEHOLDER_UUID = '00000000-0000-0000-0000-000000000001';

// ---------------------------------------------------------------------------
// Authenticated routes to test (all 17 onboarding routes)
// ---------------------------------------------------------------------------

interface RouteSpec {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  url: string;
  payload?: Record<string, unknown>;
  description: string;
}

const AUTHENTICATED_ROUTES: RouteSpec[] = [
  // Progress
  {
    method: 'GET',
    url: '/api/v1/onboarding/progress',
    description: 'Get onboarding progress',
  },

  // Steps 1-7
  {
    method: 'POST',
    url: '/api/v1/onboarding/steps/1',
    payload: {
      billing_number: '123456',
      cpsa_registration_number: 'REG123',
      first_name: 'Test',
      last_name: 'Physician',
    },
    description: 'Complete step 1 (profile)',
  },
  {
    method: 'POST',
    url: '/api/v1/onboarding/steps/2',
    payload: {
      specialty_code: 'GP',
      physician_type: 'GP',
    },
    description: 'Complete step 2 (specialty)',
  },
  {
    method: 'POST',
    url: '/api/v1/onboarding/steps/3',
    payload: {
      ba_number: '12345',
      ba_type: 'FFS',
      is_primary: true,
    },
    description: 'Complete step 3 (BA)',
  },
  {
    method: 'POST',
    url: '/api/v1/onboarding/steps/4',
    payload: {
      location_name: 'Test Clinic',
      address_line_1: '123 Main St',
      city: 'Calgary',
      province: 'AB',
      postal_code: 'T2P0A1',
      functional_centre_code: 'FC01',
    },
    description: 'Complete step 4 (location)',
  },
  {
    method: 'POST',
    url: '/api/v1/onboarding/steps/5',
    payload: {
      wcb_provider_number: 'WCB123',
      wcb_form_types: ['C8'],
    },
    description: 'Complete step 5 (WCB config)',
  },
  {
    method: 'POST',
    url: '/api/v1/onboarding/steps/6',
    payload: {
      default_submission_method: 'HLINK',
      auto_validate: true,
    },
    description: 'Complete step 6 (submission preferences)',
  },
  {
    method: 'POST',
    url: '/api/v1/onboarding/steps/7',
    description: 'Complete step 7 (IMA acknowledgment)',
  },

  // IMA endpoints
  {
    method: 'GET',
    url: '/api/v1/onboarding/ima',
    description: 'Get IMA document',
  },
  {
    method: 'POST',
    url: '/api/v1/onboarding/ima/acknowledge',
    payload: {
      document_hash: 'abc123hash',
    },
    description: 'Acknowledge IMA',
  },
  {
    method: 'GET',
    url: '/api/v1/onboarding/ima/download',
    description: 'Download IMA PDF',
  },

  // Document downloads
  {
    method: 'GET',
    url: '/api/v1/onboarding/ahc11236/download',
    description: 'Download AHC11236 form',
  },
  {
    method: 'GET',
    url: '/api/v1/onboarding/pia/download',
    description: 'Download PIA appendix',
  },

  // Guided tour
  {
    method: 'POST',
    url: '/api/v1/onboarding/guided-tour/complete',
    description: 'Complete guided tour',
  },
  {
    method: 'POST',
    url: '/api/v1/onboarding/guided-tour/dismiss',
    description: 'Dismiss guided tour',
  },

  // Patient import
  {
    method: 'POST',
    url: '/api/v1/onboarding/patient-import/complete',
    description: 'Complete patient import',
  },

  // BA confirmation
  {
    method: 'POST',
    url: `/api/v1/onboarding/ba/${PLACEHOLDER_UUID}/confirm-active`,
    description: 'Confirm BA active',
  },
];

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Onboarding Authentication Enforcement (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    users = [];
    sessions = [];
    auditEntries = [];

    // Seed the valid authenticated user and active session
    users.push({
      userId: FIXED_USER_ID,
      email: 'physician@example.com',
      passwordHash: 'hashed',
      mfaConfigured: true,
      totpSecretEncrypted: null,
      failedLoginCount: 0,
      lockedUntil: null,
      isActive: true,
      role: 'PHYSICIAN',
      subscriptionStatus: 'ACTIVE',
    });
    sessions.push({
      sessionId: FIXED_SESSION_ID,
      userId: FIXED_USER_ID,
      tokenHash: FIXED_SESSION_TOKEN_HASH,
      ipAddress: '127.0.0.1',
      userAgent: 'test-agent',
      createdAt: new Date(),
      lastActiveAt: new Date(),
      revoked: false,
      revokedReason: null,
    });

    // Seed an expired (revoked) session for expired-cookie tests
    sessions.push({
      sessionId: EXPIRED_SESSION_ID,
      userId: FIXED_USER_ID,
      tokenHash: EXPIRED_SESSION_TOKEN_HASH,
      ipAddress: '127.0.0.1',
      userAgent: 'test-agent',
      createdAt: new Date(Date.now() - 25 * 60 * 60 * 1000),
      lastActiveAt: new Date(Date.now() - 2 * 60 * 60 * 1000),
      revoked: true,
      revokedReason: 'expired_absolute',
    });
  });

  // =========================================================================
  // No Cookie — each route returns 401 with no data leakage
  // =========================================================================

  describe('Requests without session cookie return 401', () => {
    for (const route of AUTHENTICATED_ROUTES) {
      it(`${route.method} ${route.url} — returns 401 without session cookie`, async () => {
        const res = await app.inject({
          method: route.method,
          url: route.url,
          ...(route.payload ? { payload: route.payload } : {}),
        });

        expect(res.statusCode).toBe(401);
        const body = JSON.parse(res.body);
        expect(body.error).toBeDefined();
        expect(body.error.code).toBe('UNAUTHORIZED');
        expect(body.data).toBeUndefined();
      });
    }
  });

  // =========================================================================
  // Expired Cookie — each route returns 401
  // =========================================================================

  describe('Requests with expired/revoked session cookie return 401', () => {
    for (const route of AUTHENTICATED_ROUTES) {
      it(`${route.method} ${route.url} — returns 401 with expired session`, async () => {
        const res = await app.inject({
          method: route.method,
          url: route.url,
          headers: { cookie: `session=${EXPIRED_SESSION_TOKEN}` },
          ...(route.payload ? { payload: route.payload } : {}),
        });

        expect(res.statusCode).toBe(401);
        const body = JSON.parse(res.body);
        expect(body.error).toBeDefined();
        expect(body.error.code).toBe('UNAUTHORIZED');
        expect(body.data).toBeUndefined();
      });
    }
  });

  // =========================================================================
  // Tampered Cookie — each route returns 401
  // =========================================================================

  describe('Requests with tampered/invalid session cookie return 401', () => {
    for (const route of AUTHENTICATED_ROUTES) {
      it(`${route.method} ${route.url} — returns 401 with tampered cookie`, async () => {
        const tamperedToken = createTamperedCookie();
        const res = await app.inject({
          method: route.method,
          url: route.url,
          headers: { cookie: `session=${tamperedToken}` },
          ...(route.payload ? { payload: route.payload } : {}),
        });

        expect(res.statusCode).toBe(401);
        const body = JSON.parse(res.body);
        expect(body.error).toBeDefined();
        expect(body.error.code).toBe('UNAUTHORIZED');
        expect(body.data).toBeUndefined();
      });
    }
  });

  // =========================================================================
  // Empty cookie value — returns 401
  // =========================================================================

  describe('Requests with empty session cookie return 401', () => {
    for (const route of AUTHENTICATED_ROUTES) {
      it(`${route.method} ${route.url} — returns 401 with empty cookie value`, async () => {
        const res = await app.inject({
          method: route.method,
          url: route.url,
          headers: { cookie: 'session=' },
          ...(route.payload ? { payload: route.payload } : {}),
        });

        expect(res.statusCode).toBe(401);
        const body = JSON.parse(res.body);
        expect(body.error).toBeDefined();
        expect(body.data).toBeUndefined();
      });
    }
  });

  // =========================================================================
  // Wrong cookie name — returns 401
  // =========================================================================

  describe('Requests with wrong cookie name return 401', () => {
    it('cookie named "token" instead of "session" returns 401', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/onboarding/progress',
        headers: { cookie: `token=${FIXED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(401);
    });

    it('cookie named "auth" instead of "session" returns 401', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/onboarding/ima',
        headers: { cookie: `auth=${FIXED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // Sanity: valid session cookie is accepted (not 401)
  // =========================================================================

  describe('Sanity: valid session cookie is accepted', () => {
    it('GET /api/v1/onboarding/progress returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/onboarding/progress',
        headers: { cookie: `session=${FIXED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/onboarding/ima returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/onboarding/ima',
        headers: { cookie: `session=${FIXED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/onboarding/guided-tour/complete returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/guided-tour/complete',
        headers: { cookie: `session=${FIXED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/onboarding/steps/7 returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/7',
        headers: { cookie: `session=${FIXED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).not.toBe(401);
    });
  });

  // =========================================================================
  // 401 response body must not leak information
  // =========================================================================

  describe('401 responses contain no sensitive information', () => {
    it('401 response does not contain stack traces', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/onboarding/progress',
      });

      expect(res.statusCode).toBe(401);
      const rawBody = res.body;
      expect(rawBody).not.toContain('stack');
      expect(rawBody).not.toContain('node_modules');
      expect(rawBody).not.toContain('.ts:');
    });

    it('401 response does not contain internal identifiers', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/onboarding/ima',
      });

      expect(res.statusCode).toBe(401);
      const rawBody = res.body;
      expect(rawBody).not.toContain('postgres');
      expect(rawBody).not.toContain('drizzle');
      expect(rawBody).not.toContain('session_id');
      expect(rawBody).not.toContain('user_id');
      expect(rawBody).not.toContain('provider_id');
    });

    it('401 response has consistent error shape', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/onboarding/progress',
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
      expect(Object.keys(body.error).sort()).toEqual(['code', 'message']);
    });

    it('401 response does not contain onboarding data on POST step', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/1',
        payload: {
          billing_number: '123456',
          cpsa_registration_number: 'REG123',
          first_name: 'Attacker',
          last_name: 'Test',
        },
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('401 response does not contain IMA data on POST acknowledge', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/ima/acknowledge',
        payload: { document_hash: 'abc123hash' },
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('401 response does not contain PDF data on download endpoints', async () => {
      for (const url of [
        '/api/v1/onboarding/ima/download',
        '/api/v1/onboarding/ahc11236/download',
        '/api/v1/onboarding/pia/download',
      ]) {
        const res = await app.inject({
          method: 'GET',
          url,
        });

        expect(res.statusCode).toBe(401);
        const body = JSON.parse(res.body);
        expect(body.data).toBeUndefined();
        expect(body.error.code).toBe('UNAUTHORIZED');
      }
    });
  });

  // =========================================================================
  // No Set-Cookie header on 401 responses
  // =========================================================================

  describe('401 responses do not issue session cookies', () => {
    it('GET /api/v1/onboarding/progress — no Set-Cookie header on 401', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/onboarding/progress',
      });

      expect(res.statusCode).toBe(401);
      expect(res.headers['set-cookie']).toBeUndefined();
    });

    it('POST /api/v1/onboarding/steps/1 — no Set-Cookie header on 401', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/1',
        payload: {
          billing_number: '123456',
          cpsa_registration_number: 'REG123',
          first_name: 'Test',
          last_name: 'User',
        },
      });

      expect(res.statusCode).toBe(401);
      expect(res.headers['set-cookie']).toBeUndefined();
    });

    it('POST /api/v1/onboarding/ima/acknowledge — no Set-Cookie header on 401', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/ima/acknowledge',
        payload: { document_hash: 'abc123hash' },
      });

      expect(res.statusCode).toBe(401);
      expect(res.headers['set-cookie']).toBeUndefined();
    });

    it('GET /api/v1/onboarding/ima/download — no Set-Cookie header on 401', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/onboarding/ima/download',
      });

      expect(res.statusCode).toBe(401);
      expect(res.headers['set-cookie']).toBeUndefined();
    });

    it('POST /api/v1/onboarding/ba/:ba_id/confirm-active — no Set-Cookie header on 401', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/onboarding/ba/${PLACEHOLDER_UUID}/confirm-active`,
      });

      expect(res.statusCode).toBe(401);
      expect(res.headers['set-cookie']).toBeUndefined();
    });
  });
});
