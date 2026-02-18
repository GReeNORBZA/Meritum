import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

// ---------------------------------------------------------------------------
// Environment setup (must be before imports that read env)
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);

// ---------------------------------------------------------------------------
// Mock otplib
// ---------------------------------------------------------------------------

vi.mock('otplib', () => {
  const mockAuthenticator = {
    options: {},
    generateSecret: vi.fn(() => 'JBSWY3DPEHPK3PXP'),
    keyuri: vi.fn(
      (email: string, issuer: string, secret: string) =>
        `otpauth://totp/${issuer}:${email}?secret=${secret}&issuer=${issuer}`,
    ),
    verify: vi.fn(({ token }: { token: string }) => token === '123456'),
  };
  return { authenticator: mockAuthenticator };
});

// ---------------------------------------------------------------------------
// Real imports (after mocks are hoisted)
// ---------------------------------------------------------------------------

import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { ahcipRoutes } from '../../../src/domains/ahcip/ahcip.routes.js';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { type AhcipHandlerDeps } from '../../../src/domains/ahcip/ahcip.handlers.js';
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
const FIXED_PROVIDER_ID = FIXED_USER_ID; // 1:1 mapping
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
// Stub AHCIP repository & deps (not exercised in authn tests — just stubs)
// ---------------------------------------------------------------------------

function createStubAhcipRepo() {
  return {
    createAhcipDetail: vi.fn(async () => ({})),
    findAhcipDetailByClaimId: vi.fn(async () => undefined),
    updateAhcipDetail: vi.fn(async () => ({})),
    findBatchById: vi.fn(async () => undefined),
    listBatches: vi.fn(async () => ({
      data: [],
      pagination: { total: 0, page: 1, pageSize: 25, hasMore: false },
    })),
    findNextBatchPreview: vi.fn(async () => null),
    createBatch: vi.fn(async () => ({})),
    updateBatchStatus: vi.fn(async () => ({})),
    findClaimsForBatch: vi.fn(async () => []),
    findAssessmentsByBatchId: vi.fn(async () => []),
    createAssessment: vi.fn(async () => ({})),
    listBatchesAwaitingResponse: vi.fn(async () => []),
    findFeeScheduleEntry: vi.fn(async () => undefined),
    findClaimWithAhcipDetail: vi.fn(async () => undefined),
    bulkUpdateClaimStates: vi.fn(async () => []),
    appendClaimAudit: vi.fn(async () => ({})),
  };
}

function createStubHandlerDeps(): AhcipHandlerDeps {
  const repo = createStubAhcipRepo() as any;
  return {
    batchCycleDeps: {
      repo,
      feeRefData: { lookupFee: vi.fn(async () => null), getCurrentVersion: vi.fn(async () => '1.0') },
      feeProviderService: { getProviderFeeConfig: vi.fn(async () => ({})) },
      claimStateService: { transition: vi.fn(async () => ({})) },
      notificationService: { emit: vi.fn(async () => {}) },
      hlinkTransmission: { transmit: vi.fn(async () => ({})) },
      fileEncryption: { encrypt: vi.fn(async () => Buffer.from('')), decrypt: vi.fn(async () => Buffer.from('')) },
      submissionPreferences: { getSubmissionMode: vi.fn(async () => 'MANUAL') },
      validationRunner: { validate: vi.fn(async () => ({ valid: true, errors: [] })) },
    },
    feeCalculationDeps: {
      repo,
      feeRefData: { lookupFee: vi.fn(async () => null), getCurrentVersion: vi.fn(async () => '1.0') },
      feeProviderService: { getProviderFeeConfig: vi.fn(async () => ({})) },
    },
    assessmentDeps: {
      repo,
      claimStateService: { transition: vi.fn(async () => ({})) },
      notificationService: { emit: vi.fn(async () => {}) },
      hlinkRetrieval: { retrieve: vi.fn(async () => ({})) },
      explanatoryCodeService: { getExplanatoryCode: vi.fn(async () => null) },
      fileEncryption: { encrypt: vi.fn(async () => Buffer.from('')), decrypt: vi.fn(async () => Buffer.from('')) },
    },
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

  const handlerDeps = createStubHandlerDeps();

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  await testApp.register(authPluginFp, { sessionDeps });

  testApp.setErrorHandler((error, request, reply) => {
    if (error.statusCode && error.statusCode >= 400 && error.statusCode < 500) {
      return reply.code(error.statusCode).send({
        error: { code: (error as any).code ?? 'ERROR', message: error.message },
      });
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

  await testApp.register(ahcipRoutes, { deps: handlerDeps });
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
// Authenticated routes to test
// ---------------------------------------------------------------------------

interface RouteSpec {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  url: string;
  payload?: Record<string, unknown>;
  description: string;
}

const AUTHENTICATED_ROUTES: RouteSpec[] = [
  // Batch Management
  { method: 'GET', url: '/api/v1/ahcip/batches', description: 'List batches' },
  { method: 'GET', url: '/api/v1/ahcip/batches/next', description: 'Preview next batch' },
  { method: 'GET', url: `/api/v1/ahcip/batches/${PLACEHOLDER_UUID}`, description: 'Get batch by ID' },
  { method: 'POST', url: `/api/v1/ahcip/batches/${PLACEHOLDER_UUID}/retry`, description: 'Retry batch' },

  // Assessment
  { method: 'GET', url: '/api/v1/ahcip/assessments/pending', description: 'List pending assessments' },
  { method: 'GET', url: `/api/v1/ahcip/assessments/${PLACEHOLDER_UUID}`, description: 'Get assessment results' },

  // Fee Calculation
  {
    method: 'POST',
    url: '/api/v1/ahcip/fee-calculate',
    payload: {
      health_service_code: '03.04A',
      functional_centre: 'MEDE',
      encounter_type: 'CONSULTATION',
      date_of_service: '2026-01-15',
      patient_id: PLACEHOLDER_UUID,
    },
    description: 'Calculate fee preview',
  },
  { method: 'GET', url: `/api/v1/ahcip/claims/${PLACEHOLDER_UUID}/fee-breakdown`, description: 'Get fee breakdown' },
];

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('AHCIP Authentication Enforcement (Security)', () => {
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
      subscriptionStatus: 'TRIAL',
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
      createdAt: new Date(Date.now() - 25 * 60 * 60 * 1000), // 25 hours ago
      lastActiveAt: new Date(Date.now() - 2 * 60 * 60 * 1000), // 2 hours ago
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
        // No data leakage — must not contain data field
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
        url: '/api/v1/ahcip/batches',
        headers: { cookie: `token=${FIXED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(401);
    });

    it('cookie named "auth" instead of "session" returns 401', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ahcip/batches',
        headers: { cookie: `auth=${FIXED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(401);
    });

    it('cookie named "sid" instead of "session" returns 401', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ahcip/fee-calculate',
        headers: { cookie: `sid=${FIXED_SESSION_TOKEN}` },
        payload: {
          health_service_code: '03.04A',
          functional_centre: 'MEDE',
          encounter_type: 'CONSULTATION',
          date_of_service: '2026-01-15',
          patient_id: PLACEHOLDER_UUID,
        },
      });

      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // Sanity: valid session cookie is accepted (not 401)
  // =========================================================================

  describe('Sanity: valid session cookie is accepted', () => {
    it('GET /api/v1/ahcip/batches returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ahcip/batches',
        headers: { cookie: `session=${FIXED_SESSION_TOKEN}` },
      });

      // Should not be 401 — confirms our test setup is correct
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/ahcip/batches/next returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ahcip/batches/next',
        headers: { cookie: `session=${FIXED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/ahcip/assessments/pending returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ahcip/assessments/pending',
        headers: { cookie: `session=${FIXED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/ahcip/claims/:id/fee-breakdown returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/ahcip/claims/${PLACEHOLDER_UUID}/fee-breakdown`,
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
        url: '/api/v1/ahcip/batches',
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
        url: `/api/v1/ahcip/batches/${PLACEHOLDER_UUID}`,
      });

      expect(res.statusCode).toBe(401);
      const rawBody = res.body;
      expect(rawBody).not.toContain('postgres');
      expect(rawBody).not.toContain('drizzle');
      expect(rawBody).not.toContain('session_id');
      expect(rawBody).not.toContain('user_id');
      expect(rawBody).not.toContain('provider_id');
      expect(rawBody).not.toContain('physician_id');
    });

    it('401 response has consistent error shape', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ahcip/batches',
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
      // Should only have code and message — no extra fields
      expect(Object.keys(body.error).sort()).toEqual(['code', 'message']);
    });

    it('401 response does not contain batch data on POST', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/ahcip/batches/${PLACEHOLDER_UUID}/retry`,
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('401 response does not contain fee data on POST', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ahcip/fee-calculate',
        payload: {
          health_service_code: '03.04A',
          functional_centre: 'MEDE',
          encounter_type: 'CONSULTATION',
          date_of_service: '2026-01-15',
          patient_id: PLACEHOLDER_UUID,
        },
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
    });

    it('401 response does not contain assessment data on GET', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/ahcip/assessments/${PLACEHOLDER_UUID}`,
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
    });
  });

  // =========================================================================
  // No Set-Cookie header on 401 responses
  // =========================================================================

  describe('401 responses do not issue session cookies', () => {
    it('GET /api/v1/ahcip/batches — no Set-Cookie header on 401', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ahcip/batches',
      });

      expect(res.statusCode).toBe(401);
      expect(res.headers['set-cookie']).toBeUndefined();
    });

    it('POST /api/v1/ahcip/fee-calculate — no Set-Cookie header on 401', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ahcip/fee-calculate',
        payload: {
          health_service_code: '03.04A',
          functional_centre: 'MEDE',
          encounter_type: 'CONSULTATION',
          date_of_service: '2026-01-15',
          patient_id: PLACEHOLDER_UUID,
        },
      });

      expect(res.statusCode).toBe(401);
      expect(res.headers['set-cookie']).toBeUndefined();
    });

    it('POST /api/v1/ahcip/batches/:id/retry — no Set-Cookie header on 401', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/ahcip/batches/${PLACEHOLDER_UUID}/retry`,
      });

      expect(res.statusCode).toBe(401);
      expect(res.headers['set-cookie']).toBeUndefined();
    });
  });
});
