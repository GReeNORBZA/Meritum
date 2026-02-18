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
import { claimRoutes } from '../../../src/domains/claim/claim.routes.js';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { type ClaimHandlerDeps } from '../../../src/domains/claim/claim.handlers.js';
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
// Stub claim repository (not exercised in authn tests — just stubs)
// ---------------------------------------------------------------------------

function createStubClaimRepo() {
  return {
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
  };
}

function createStubServiceDeps() {
  return {
    repo: createStubClaimRepo() as any,
    providerCheck: {
      isActive: vi.fn(async () => true),
      getRegistrationDate: vi.fn(async () => null),
    },
    patientCheck: {
      exists: vi.fn(async () => true),
    },
    pathwayValidators: {},
    referenceDataVersion: { getCurrentVersion: vi.fn(async () => '1.0') },
    notificationEmitter: { emit: vi.fn(async () => {}) },
    submissionPreference: { getSubmissionMode: vi.fn(async () => 'MANUAL') },
    facilityCheck: { belongsToPhysician: vi.fn(async () => true) },
    afterHoursPremiumCalculators: {},
    explanatoryCodeLookup: { getExplanatoryCode: vi.fn(async () => null) },
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

  const handlerDeps: ClaimHandlerDeps = {
    serviceDeps: createStubServiceDeps(),
  };

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
const PLACEHOLDER_SUG_UUID = '00000000-0000-0000-0000-000000000002';

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
  // Claim CRUD
  {
    method: 'POST',
    url: '/api/v1/claims',
    payload: { claim_type: 'AHCIP', patient_id: PLACEHOLDER_UUID, date_of_service: '2026-01-15' },
    description: 'Create claim',
  },
  { method: 'GET', url: '/api/v1/claims', description: 'List claims' },
  { method: 'GET', url: `/api/v1/claims/${PLACEHOLDER_UUID}`, description: 'Get claim by ID' },
  {
    method: 'PUT',
    url: `/api/v1/claims/${PLACEHOLDER_UUID}`,
    payload: { date_of_service: '2026-02-01' },
    description: 'Update claim',
  },
  { method: 'DELETE', url: `/api/v1/claims/${PLACEHOLDER_UUID}`, description: 'Delete claim' },

  // State transitions
  { method: 'POST', url: `/api/v1/claims/${PLACEHOLDER_UUID}/validate`, description: 'Validate claim' },
  { method: 'POST', url: `/api/v1/claims/${PLACEHOLDER_UUID}/queue`, description: 'Queue claim' },
  { method: 'POST', url: `/api/v1/claims/${PLACEHOLDER_UUID}/unqueue`, description: 'Unqueue claim' },
  {
    method: 'POST',
    url: `/api/v1/claims/${PLACEHOLDER_UUID}/write-off`,
    payload: { reason: 'test' },
    description: 'Write off claim',
  },
  { method: 'POST', url: `/api/v1/claims/${PLACEHOLDER_UUID}/resubmit`, description: 'Resubmit claim' },

  // AI Coach suggestions
  { method: 'GET', url: `/api/v1/claims/${PLACEHOLDER_UUID}/suggestions`, description: 'Get claim suggestions' },
  {
    method: 'POST',
    url: `/api/v1/claims/${PLACEHOLDER_UUID}/suggestions/${PLACEHOLDER_SUG_UUID}/accept`,
    description: 'Accept suggestion',
  },
  {
    method: 'POST',
    url: `/api/v1/claims/${PLACEHOLDER_UUID}/suggestions/${PLACEHOLDER_SUG_UUID}/dismiss`,
    payload: { reason: 'not applicable' },
    description: 'Dismiss suggestion',
  },

  // Rejection management
  { method: 'GET', url: '/api/v1/claims/rejected', description: 'List rejected claims' },
  { method: 'GET', url: `/api/v1/claims/${PLACEHOLDER_UUID}/rejection-details`, description: 'Get rejection details' },

  // Claim audit
  { method: 'GET', url: `/api/v1/claims/${PLACEHOLDER_UUID}/audit`, description: 'Get claim audit history' },

  // EMR Import
  {
    method: 'POST',
    url: '/api/v1/imports',
    payload: { file_name: 'test.csv', file_content: 'a,b,c' },
    description: 'Upload EMR import',
  },
  { method: 'GET', url: `/api/v1/imports/${PLACEHOLDER_UUID}`, description: 'Get import batch' },
  { method: 'GET', url: `/api/v1/imports/${PLACEHOLDER_UUID}/preview`, description: 'Preview import' },
  { method: 'POST', url: `/api/v1/imports/${PLACEHOLDER_UUID}/commit`, description: 'Commit import' },

  // Field Mapping Templates
  {
    method: 'POST',
    url: '/api/v1/field-mapping-templates',
    payload: { name: 'Test Template', mappings: [{ source_column: 'col1', target_field: 'field1' }], has_header_row: true },
    description: 'Create field mapping template',
  },
  { method: 'GET', url: '/api/v1/field-mapping-templates', description: 'List field mapping templates' },
  {
    method: 'PUT',
    url: `/api/v1/field-mapping-templates/${PLACEHOLDER_UUID}`,
    payload: { name: 'Updated Template' },
    description: 'Update field mapping template',
  },
  {
    method: 'DELETE',
    url: `/api/v1/field-mapping-templates/${PLACEHOLDER_UUID}`,
    description: 'Delete field mapping template',
  },

  // ED Shifts
  {
    method: 'POST',
    url: '/api/v1/shifts',
    payload: { facility_id: PLACEHOLDER_UUID, shift_date: '2026-01-15', start_time: '08:00', end_time: '16:00' },
    description: 'Create ED shift',
  },
  {
    method: 'POST',
    url: `/api/v1/shifts/${PLACEHOLDER_UUID}/encounters`,
    payload: { patient_id: PLACEHOLDER_UUID, date_of_service: '2026-01-15', claim_type: 'AHCIP' },
    description: 'Add encounter to shift',
  },
  { method: 'PUT', url: `/api/v1/shifts/${PLACEHOLDER_UUID}/complete`, description: 'Complete ED shift' },
  { method: 'GET', url: `/api/v1/shifts/${PLACEHOLDER_UUID}`, description: 'Get shift details' },

  // Data Export
  {
    method: 'POST',
    url: '/api/v1/exports',
    payload: { date_from: '2026-01-01', date_to: '2026-01-31', format: 'CSV' },
    description: 'Request data export',
  },
  { method: 'GET', url: `/api/v1/exports/${PLACEHOLDER_UUID}`, description: 'Get export status' },

  // Submission Preferences
  { method: 'GET', url: '/api/v1/submission-preferences', description: 'Get submission preferences' },
  {
    method: 'PUT',
    url: '/api/v1/submission-preferences',
    payload: { mode: 'AUTO_CLEAN' },
    description: 'Update submission preferences',
  },
];

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Claim Authentication Enforcement (Security)', () => {
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
        url: '/api/v1/claims',
        headers: { cookie: `token=${FIXED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(401);
    });

    it('cookie named "auth" instead of "session" returns 401', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/claims',
        headers: { cookie: `auth=${FIXED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(401);
    });

    it('cookie named "sid" instead of "session" returns 401', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/claims',
        headers: { cookie: `sid=${FIXED_SESSION_TOKEN}` },
        payload: { claim_type: 'AHCIP', patient_id: PLACEHOLDER_UUID, date_of_service: '2026-01-15' },
      });

      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // Sanity: valid session cookie is accepted (not 401)
  // =========================================================================

  describe('Sanity: valid session cookie is accepted', () => {
    it('GET /api/v1/claims returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/claims',
        headers: { cookie: `session=${FIXED_SESSION_TOKEN}` },
      });

      // Should not be 401 — confirms our test setup is correct
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/claims/rejected returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/claims/rejected',
        headers: { cookie: `session=${FIXED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/field-mapping-templates returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/field-mapping-templates',
        headers: { cookie: `session=${FIXED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/submission-preferences returns non-401 with valid session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/submission-preferences',
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
        url: '/api/v1/claims',
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
        url: `/api/v1/claims/${PLACEHOLDER_UUID}`,
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
        url: '/api/v1/claims',
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
      // Should only have code and message — no extra fields
      expect(Object.keys(body.error).sort()).toEqual(['code', 'message']);
    });

    it('401 response does not contain claim data on POST', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/claims',
        payload: { claim_type: 'AHCIP', patient_id: PLACEHOLDER_UUID, date_of_service: '2026-01-15' },
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('401 response does not contain import data on POST', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/imports',
        payload: { file_name: 'test.csv', file_content: 'a,b,c' },
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
    });

    it('401 response does not contain shift data on POST', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/shifts',
        payload: { facility_id: PLACEHOLDER_UUID, shift_date: '2026-01-15', start_time: '08:00', end_time: '16:00' },
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
    it('GET /api/v1/claims — no Set-Cookie header on 401', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/claims',
      });

      expect(res.statusCode).toBe(401);
      expect(res.headers['set-cookie']).toBeUndefined();
    });

    it('POST /api/v1/claims — no Set-Cookie header on 401', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/claims',
        payload: { claim_type: 'AHCIP', patient_id: PLACEHOLDER_UUID, date_of_service: '2026-01-15' },
      });

      expect(res.statusCode).toBe(401);
      expect(res.headers['set-cookie']).toBeUndefined();
    });

    it('POST /api/v1/imports — no Set-Cookie header on 401', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/imports',
        payload: { file_name: 'test.csv', file_content: 'a,b,c' },
      });

      expect(res.statusCode).toBe(401);
      expect(res.headers['set-cookie']).toBeUndefined();
    });
  });
});
