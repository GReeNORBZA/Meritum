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
import { claimRoutes } from '../../../src/domains/claim/claim.routes.js';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { type ClaimHandlerDeps } from '../../../src/domains/claim/claim.handlers.js';
import {
  type SessionManagementDeps,
  hashToken,
} from '../../../src/domains/iam/iam.service.js';
import { createHash, randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Fixed test user/session
// ---------------------------------------------------------------------------

const FIXED_SESSION_TOKEN = randomBytes(32).toString('hex');
const FIXED_SESSION_TOKEN_HASH = hashToken(FIXED_SESSION_TOKEN);
const FIXED_USER_ID = '22222222-0000-0000-0000-000000000001';
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
    createSession: vi.fn(async () => ({ sessionId: '44444444-0000-0000-0000-000000000001' })),
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
// Stub claim handler deps
// ---------------------------------------------------------------------------

function createStubHandlerDeps(): ClaimHandlerDeps {
  return {
    serviceDeps: {
      repo: {
        createClaim: vi.fn(async () => ({})),
        findClaimById: vi.fn(async () => undefined),
        updateClaim: vi.fn(async () => ({})),
        softDeleteClaim: vi.fn(async () => false),
        listClaims: vi.fn(async () => ({ data: [], pagination: { total: 0, page: 1, pageSize: 25, hasMore: false } })),
        countClaimsByState: vi.fn(async () => []),
        findClaimsApproachingDeadline: vi.fn(async () => []),
        transitionState: vi.fn(async () => ({})),
        classifyClaim: vi.fn(async () => ({})),
        updateValidationResult: vi.fn(async () => ({})),
        updateAiSuggestions: vi.fn(async () => ({})),
        updateDuplicateAlert: vi.fn(async () => ({})),
        updateFlags: vi.fn(async () => ({})),
        createImportBatch: vi.fn(async () => ({})),
        findImportBatchById: vi.fn(async () => undefined),
        updateImportBatchStatus: vi.fn(async () => ({})),
        findDuplicateImportByHash: vi.fn(async () => undefined),
        listImportBatches: vi.fn(async () => ({ data: [], pagination: { total: 0, page: 1, pageSize: 25, hasMore: false } })),
        findClaimsForBatchAssembly: vi.fn(async () => []),
        bulkTransitionState: vi.fn(async () => []),
        createTemplate: vi.fn(async () => ({})),
        findTemplateById: vi.fn(async () => undefined),
        updateTemplate: vi.fn(async () => ({})),
        deleteTemplate: vi.fn(async () => {}),
        listTemplates: vi.fn(async () => []),
        createShift: vi.fn(async () => ({})),
        findShiftById: vi.fn(async () => undefined),
        updateShiftStatus: vi.fn(async () => ({})),
        updateShiftTimes: vi.fn(async () => ({})),
        incrementEncounterCount: vi.fn(async () => ({})),
        listShifts: vi.fn(async () => ({ data: [], pagination: { total: 0, page: 1, pageSize: 25, hasMore: false } })),
        findClaimsByShift: vi.fn(async () => []),
        createExportRecord: vi.fn(async () => ({})),
        findExportById: vi.fn(async () => undefined),
        updateExportStatus: vi.fn(async () => ({})),
        appendClaimAudit: vi.fn(async () => ({})),
        getClaimAuditHistory: vi.fn(async () => []),
        getClaimAuditHistoryPaginated: vi.fn(async () => ({ data: [], pagination: { total: 0, page: 1, pageSize: 25, hasMore: false } })),
      } as any,
      providerCheck: { isActive: vi.fn(async () => true), getRegistrationDate: vi.fn(async () => null) },
      patientCheck: { exists: vi.fn(async () => true) },
      pathwayValidators: {},
      referenceDataVersion: { getCurrentVersion: vi.fn(async () => '1.0') },
      notificationEmitter: { emit: vi.fn(async () => {}) },
      submissionPreference: { getSubmissionMode: vi.fn(async () => 'MANUAL') },
      facilityCheck: { belongsToPhysician: vi.fn(async () => true) },
      afterHoursPremiumCalculators: {},
      explanatoryCodeLookup: { getExplanatoryCode: vi.fn(async () => null) },
    } as any,
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;

async function buildTestApp(): Promise<FastifyInstance> {
  const mockSessionRepo = createMockSessionRepo();

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

  await testApp.register(claimRoutes, { deps: handlerDeps });
  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function createTamperedCookie(): string {
  return randomBytes(32).toString('hex').replace(/[0-9a-f]$/, 'x');
}

const EXPIRED_SESSION_TOKEN = randomBytes(32).toString('hex');
const EXPIRED_SESSION_TOKEN_HASH = hashToken(EXPIRED_SESSION_TOKEN);
const EXPIRED_SESSION_ID = '55555555-0000-0000-0000-000000000001';

const PLACEHOLDER_UUID = '00000000-0000-0000-0000-000000000001';

// ---------------------------------------------------------------------------
// All 14 Claim Extension endpoints
// ---------------------------------------------------------------------------

interface RouteSpec {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  url: string;
  payload?: Record<string, unknown>;
  description: string;
}

const EXTENSION_ROUTES: RouteSpec[] = [
  // Templates
  { method: 'GET', url: '/api/v1/claims/templates', description: 'List claim templates' },
  {
    method: 'POST',
    url: '/api/v1/claims/templates',
    payload: {
      name: 'Test Template',
      claim_type: 'AHCIP',
      line_items: [{ health_service_code: '03.04A', calls: 1 }],
    },
    description: 'Create claim template',
  },
  {
    method: 'PUT',
    url: `/api/v1/claims/templates/${PLACEHOLDER_UUID}`,
    payload: { name: 'Updated Template' },
    description: 'Update claim template',
  },
  { method: 'DELETE', url: `/api/v1/claims/templates/${PLACEHOLDER_UUID}`, description: 'Delete claim template' },
  {
    method: 'POST',
    url: `/api/v1/claims/templates/${PLACEHOLDER_UUID}/apply`,
    payload: { patient_id: PLACEHOLDER_UUID, date_of_service: '2026-01-15' },
    description: 'Apply claim template',
  },
  {
    method: 'PUT',
    url: '/api/v1/claims/templates/reorder',
    payload: { template_ids: [PLACEHOLDER_UUID] },
    description: 'Reorder claim templates',
  },

  // Justifications
  {
    method: 'POST',
    url: `/api/v1/claims/${PLACEHOLDER_UUID}/justification`,
    payload: {
      claim_id: PLACEHOLDER_UUID,
      scenario: 'UNLISTED_PROCEDURE',
      justification_text: 'This procedure requires justification for the unlisted code used.',
    },
    description: 'Create justification',
  },
  { method: 'GET', url: `/api/v1/claims/${PLACEHOLDER_UUID}/justification`, description: 'Get justification' },
  { method: 'GET', url: '/api/v1/claims/justifications/history', description: 'Get justification history' },
  {
    method: 'POST',
    url: `/api/v1/claims/justifications/${PLACEHOLDER_UUID}/save-personal`,
    description: 'Save justification as personal template',
  },

  // Referrers
  { method: 'GET', url: '/api/v1/claims/referrers/recent', description: 'List recent referrers' },
  {
    method: 'POST',
    url: '/api/v1/claims/referrers/recent',
    payload: { referrer_cpsa: '12345', referrer_name: 'Dr. Smith' },
    description: 'Record recent referrer',
  },

  // Bundling
  {
    method: 'POST',
    url: '/api/v1/claims/bundling/check',
    payload: { codes: ['03.04A', '03.04B'], claim_type: 'AHCIP' },
    description: 'Check bundling conflicts',
  },

  // Anesthesia
  {
    method: 'POST',
    url: '/api/v1/claims/anesthesia/calculate',
    payload: { procedure_codes: ['20.11A'] },
    description: 'Calculate anesthesia benefit',
  },
];

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Claim Extension Authentication Enforcement (Security)', () => {
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

    // Seed an expired (revoked) session
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
  // No Cookie — each route returns 401
  // =========================================================================

  describe('Requests without session cookie return 401', () => {
    for (const route of EXTENSION_ROUTES) {
      it(`${route.method} ${route.url} -- returns 401 without session cookie`, async () => {
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
    for (const route of EXTENSION_ROUTES) {
      it(`${route.method} ${route.url} -- returns 401 with expired session`, async () => {
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
    for (const route of EXTENSION_ROUTES) {
      it(`${route.method} ${route.url} -- returns 401 with tampered cookie`, async () => {
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
    for (const route of EXTENSION_ROUTES) {
      it(`${route.method} ${route.url} -- returns 401 with empty cookie value`, async () => {
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
    it('cookie named "token" instead of "session" returns 401 on GET templates', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/claims/templates',
        headers: { cookie: `token=${FIXED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(401);
    });

    it('cookie named "auth" instead of "session" returns 401 on POST bundling check', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/claims/bundling/check',
        headers: { cookie: `auth=${FIXED_SESSION_TOKEN}` },
        payload: { codes: ['03.04A', '03.04B'], claim_type: 'AHCIP' },
      });

      expect(res.statusCode).toBe(401);
    });

    it('cookie named "sid" instead of "session" returns 401 on POST anesthesia calculate', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/claims/anesthesia/calculate',
        headers: { cookie: `sid=${FIXED_SESSION_TOKEN}` },
        payload: { procedure_codes: ['20.11A'] },
      });

      expect(res.statusCode).toBe(401);
    });

    it('cookie named "jwt" instead of "session" returns 401 on POST referrer', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/claims/referrers/recent',
        headers: { cookie: `jwt=${FIXED_SESSION_TOKEN}` },
        payload: { referrer_cpsa: '12345', referrer_name: 'Dr. Smith' },
      });

      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // Sanity: valid session cookie is accepted (not 401)
  // =========================================================================

  describe('Sanity: valid session cookie is accepted', () => {
    it('GET /api/v1/claims/templates returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/claims/templates',
        headers: { cookie: `session=${FIXED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/claims/referrers/recent returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/claims/referrers/recent',
        headers: { cookie: `session=${FIXED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/claims/justifications/history returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/claims/justifications/history',
        headers: { cookie: `session=${FIXED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/claims/bundling/check returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/claims/bundling/check',
        headers: { cookie: `session=${FIXED_SESSION_TOKEN}` },
        payload: { codes: ['03.04A', '03.04B'], claim_type: 'AHCIP' },
      });

      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/claims/anesthesia/calculate returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/claims/anesthesia/calculate',
        headers: { cookie: `session=${FIXED_SESSION_TOKEN}` },
        payload: { procedure_codes: ['20.11A'] },
      });

      expect(res.statusCode).not.toBe(401);
    });
  });

  // =========================================================================
  // 401 response body must not leak information
  // =========================================================================

  describe('401 responses contain no sensitive information', () => {
    it('401 response does not contain stack traces (GET templates)', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/claims/templates',
      });

      expect(res.statusCode).toBe(401);
      const rawBody = res.body;
      expect(rawBody).not.toContain('stack');
      expect(rawBody).not.toContain('node_modules');
      expect(rawBody).not.toContain('.ts:');
    });

    it('401 response does not contain internal identifiers (POST justification)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/claims/${PLACEHOLDER_UUID}/justification`,
        payload: {
          claim_id: PLACEHOLDER_UUID,
          scenario: 'UNLISTED_PROCEDURE',
          justification_text: 'This procedure requires justification for the unlisted code used.',
        },
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

    it('401 response has consistent error shape (POST bundling)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/claims/bundling/check',
        payload: { codes: ['03.04A', '03.04B'], claim_type: 'AHCIP' },
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
      expect(Object.keys(body.error).sort()).toEqual(['code', 'message']);
    });

    it('401 response does not contain template data on POST', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/claims/templates',
        payload: {
          name: 'Test Template',
          claim_type: 'AHCIP',
          line_items: [{ health_service_code: '03.04A', calls: 1 }],
        },
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('401 response does not contain referrer data on POST', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/claims/referrers/recent',
        payload: { referrer_cpsa: '12345', referrer_name: 'Dr. Smith' },
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
    });

    it('401 response does not contain anesthesia data on POST', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/claims/anesthesia/calculate',
        payload: { procedure_codes: ['20.11A'] },
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
    it('GET /api/v1/claims/templates -- no Set-Cookie header on 401', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/claims/templates',
      });

      expect(res.statusCode).toBe(401);
      expect(res.headers['set-cookie']).toBeUndefined();
    });

    it('POST /api/v1/claims/bundling/check -- no Set-Cookie header on 401', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/claims/bundling/check',
        payload: { codes: ['03.04A', '03.04B'], claim_type: 'AHCIP' },
      });

      expect(res.statusCode).toBe(401);
      expect(res.headers['set-cookie']).toBeUndefined();
    });

    it('POST /api/v1/claims/anesthesia/calculate -- no Set-Cookie header on 401', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/claims/anesthesia/calculate',
        payload: { procedure_codes: ['20.11A'] },
      });

      expect(res.statusCode).toBe(401);
      expect(res.headers['set-cookie']).toBeUndefined();
    });
  });
});
