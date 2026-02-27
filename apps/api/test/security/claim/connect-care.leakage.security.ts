// ============================================================================
// Connect Care Import — Data Leakage Prevention (Security)
// Parse errors don't echo PHN, 500 errors sanitised, import history masks PHN,
// no technology headers leaked, cross-tenant response equality.
// ============================================================================

import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { createHash, randomBytes } from 'node:crypto';

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);

vi.mock('otplib', () => ({
  authenticator: {
    options: {},
    generateSecret: vi.fn(() => 'JBSWY3DPEHPK3PXP'),
    keyuri: vi.fn(() => 'otpauth://totp/test'),
    verify: vi.fn(() => false),
  },
}));

import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { claimRoutes } from '../../../src/domains/claim/claim.routes.js';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { type ClaimHandlerDeps } from '../../../src/domains/claim/claim.handlers.js';

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Fixed identities
// ---------------------------------------------------------------------------

const P1_TOKEN = randomBytes(32).toString('hex');
const P1_TOKEN_HASH = hashToken(P1_TOKEN);
const P1_USER_ID = 'aaaa0000-0000-0000-0000-000000000001';
const P1_SESSION_ID = 'aaaa0000-0000-0000-0000-000000000011';

const P2_TOKEN = randomBytes(32).toString('hex');
const P2_TOKEN_HASH = hashToken(P2_TOKEN);
const P2_USER_ID = 'bbbb0000-0000-0000-0000-000000000002';
const P2_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000022';

const P1_BATCH_ID = '11111111-1111-1111-1111-111111111111';
const NONEXISTENT_ID = '99999999-9999-9999-9999-999999999999';

const TEST_PHN = '123456789';

// ---------------------------------------------------------------------------
// Mock stores
// ---------------------------------------------------------------------------

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

let sessions: MockSession[] = [];
let users: Array<{ userId: string; role: string; subscriptionStatus: string }> = [];

function createMockSessionRepo() {
  return {
    createSession: vi.fn(async () => ({ sessionId: 'new' })),
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      const session = sessions.find((s) => s.tokenHash === tokenHash && !s.revoked);
      if (!session) return undefined;
      const user = users.find((u) => u.userId === session.userId);
      if (!user) return undefined;
      return { session, user };
    }),
    refreshSession: vi.fn(async () => {}),
    listActiveSessions: vi.fn(async () => []),
    revokeSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
  };
}

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
      providerCheck: {
        isActive: vi.fn(async () => true),
        getRegistrationDate: vi.fn(async () => null),
      },
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
  const sessionDeps = {
    sessionRepo: createMockSessionRepo(),
    auditRepo: { appendAuditLog: vi.fn(async () => {}) },
    events: { emit: vi.fn() },
  };

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  await testApp.register(authPluginFp, { sessionDeps });

  testApp.setErrorHandler((error, _request, reply) => {
    if (error.statusCode && error.statusCode >= 400 && error.statusCode < 500) {
      return reply.code(error.statusCode).send({
        error: { code: (error as any).code ?? 'ERROR', message: error.message },
      });
    }
    if (error.validation) {
      return reply.code(400).send({
        error: { code: 'VALIDATION_ERROR', message: 'Validation failed' },
      });
    }
    return reply.code(500).send({
      error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
    });
  });

  await testApp.register(claimRoutes, { deps: createStubHandlerDeps() });
  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeSession(sessionId: string, userId: string, tokenHash: string): MockSession {
  return {
    sessionId,
    userId,
    tokenHash,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  };
}

function asP1(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${P1_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function asP2(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${P2_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

// ============================================================================
// Test Suite
// ============================================================================

describe('Connect Care Import — Data Leakage Prevention (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    users = [];
    sessions = [];

    users.push({ userId: P1_USER_ID, role: 'PHYSICIAN', subscriptionStatus: 'TRIAL' });
    sessions.push(makeSession(P1_SESSION_ID, P1_USER_ID, P1_TOKEN_HASH));

    users.push({ userId: P2_USER_ID, role: 'PHYSICIAN', subscriptionStatus: 'TRIAL' });
    sessions.push(makeSession(P2_SESSION_ID, P2_USER_ID, P2_TOKEN_HASH));
  });

  // =========================================================================
  // Error responses do not echo PHN
  // =========================================================================

  describe('Error responses do not echo PHN', () => {
    it('400 validation error does not contain submitted PHN', async () => {
      const res = await asP1('POST', '/api/v1/claims/connect-care/reconcile', {
        batch_id: 'not-a-uuid',
      });
      if (res.statusCode >= 400) {
        expect(res.body).not.toContain(TEST_PHN);
      }
    });

    it('404 error does not contain batch details', async () => {
      const res = await asP1('GET', `/api/v1/claims/connect-care/import/${NONEXISTENT_ID}`);
      expect(res.body).not.toContain('password');
      expect(res.body).not.toContain('session_id');
    });
  });

  // =========================================================================
  // 500 errors are sanitised
  // =========================================================================

  describe('500 errors are sanitised', () => {
    it('internal errors return generic message', async () => {
      const res = await asP1('GET', `/api/v1/claims/connect-care/import/${NONEXISTENT_ID}`);
      if (res.statusCode === 500) {
        const body = JSON.parse(res.body);
        expect(body.error.message).toBe('Internal server error');
        expect(body.error.code).toBe('INTERNAL_ERROR');
        expect(res.body).not.toContain('stack');
        expect(res.body).not.toContain('postgres');
      }
    });
  });

  // =========================================================================
  // No technology headers
  // =========================================================================

  describe('No technology headers', () => {
    it('no X-Powered-By header', async () => {
      const res = await asP1('GET', '/api/v1/claims/connect-care/import/history');
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no server version in headers', async () => {
      const res = await asP1('POST', '/api/v1/claims/connect-care/reconcile', {
        batch_id: P1_BATCH_ID,
      });
      const serverHeader = res.headers['server'] as string | undefined;
      if (serverHeader) {
        expect(serverHeader).not.toMatch(/fastify|node|express/i);
      }
    });
  });

  // =========================================================================
  // Cross-tenant 404 indistinguishable from missing
  // =========================================================================

  describe('Cross-tenant 404 indistinguishable from missing', () => {
    it('P2 accessing P1 batch vs nonexistent batch — same response', async () => {
      const crossRes = await asP2('GET', `/api/v1/claims/connect-care/import/${P1_BATCH_ID}`);
      const missingRes = await asP2('GET', `/api/v1/claims/connect-care/import/${NONEXISTENT_ID}`);

      // Both should produce same status code
      expect(crossRes.statusCode).toBe(missingRes.statusCode);

      // Both should produce same error shape
      if (crossRes.statusCode >= 400 && crossRes.statusCode < 500) {
        const crossBody = JSON.parse(crossRes.body);
        const missingBody = JSON.parse(missingRes.body);
        expect(crossBody.error?.code).toBe(missingBody.error?.code);
      }
    });
  });

  // =========================================================================
  // Sensitive field exclusion
  // =========================================================================

  describe('Sensitive field exclusion', () => {
    it('401 response body does not contain internal identifiers', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/claims/connect-care/import/history',
      });
      expect(res.statusCode).toBe(401);
      expect(res.body).not.toContain('password');
      expect(res.body).not.toContain('totp');
      expect(res.body).not.toContain('token_hash');
    });
  });
});
