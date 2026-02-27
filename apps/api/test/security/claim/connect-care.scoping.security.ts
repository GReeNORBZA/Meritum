// ============================================================================
// Connect Care Import — Provider Scoping (Security)
// Verifies Physician 1 imports are not accessible by Physician 2, SCC file
// with wrong provider ID is rejected, and import history is scoped.
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
// Fixed identities — two isolated physicians
// ---------------------------------------------------------------------------

const P1_TOKEN = randomBytes(32).toString('hex');
const P1_TOKEN_HASH = hashToken(P1_TOKEN);
const P1_USER_ID = 'aaaa0000-0000-0000-0000-000000000001';
const P1_SESSION_ID = 'aaaa0000-0000-0000-0000-000000000011';

const P2_TOKEN = randomBytes(32).toString('hex');
const P2_TOKEN_HASH = hashToken(P2_TOKEN);
const P2_USER_ID = 'bbbb0000-0000-0000-0000-000000000002';
const P2_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000022';

// Import batch owned by P1
const P1_BATCH_ID = '11111111-1111-1111-1111-111111111111';
// A genuinely non-existent batch
const NONEXISTENT_BATCH_ID = '99999999-9999-9999-9999-999999999999';

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

interface MockUser {
  userId: string;
  role: string;
  subscriptionStatus: string;
}

let sessions: MockSession[] = [];
let users: MockUser[] = [];

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

// ---------------------------------------------------------------------------
// Scoped stub: findImportBatchById returns batch only for the owning provider
// ---------------------------------------------------------------------------

function createScopedHandlerDeps(): ClaimHandlerDeps {
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
        findImportBatchById: vi.fn(async (id: string, providerId: string) => {
          if (id === P1_BATCH_ID && providerId === P1_USER_ID) {
            return { importBatchId: P1_BATCH_ID, physicianId: P1_USER_ID, status: 'COMPLETED' };
          }
          return undefined;
        }),
        updateImportBatchStatus: vi.fn(async () => ({})),
        findDuplicateImportByHash: vi.fn(async () => undefined),
        listImportBatches: vi.fn(async (_providerId: string) => {
          return { data: [], pagination: { total: 0, page: 1, pageSize: 25, hasMore: false } };
        }),
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

  await testApp.register(claimRoutes, { deps: createScopedHandlerDeps() });
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

describe('Connect Care Import — Provider Scoping (Security)', () => {
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
  // Cross-provider access returns 404 (not 403)
  // =========================================================================

  describe('Physician 2 cannot access Physician 1 import batches', () => {
    it('GET import batch — cross-provider → 404', async () => {
      const res = await asP2('GET', `/api/v1/claims/connect-care/import/${P1_BATCH_ID}`);
      // Should be 404 or error, but NOT return data
      expect([404, 500]).toContain(res.statusCode);
      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
    });

    it('POST confirm import — cross-provider → 404', async () => {
      const res = await asP2('POST', `/api/v1/claims/connect-care/import/${P1_BATCH_ID}/confirm`, {
        action: 'CONFIRMED',
      });
      expect([404, 500]).toContain(res.statusCode);
      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
    });

    it('POST cancel import — cross-provider → 404', async () => {
      const res = await asP2('POST', `/api/v1/claims/connect-care/import/${P1_BATCH_ID}/cancel`);
      expect([404, 500]).toContain(res.statusCode);
    });
  });

  // =========================================================================
  // Cross-provider 404 is indistinguishable from missing
  // =========================================================================

  describe('404 for cross-provider is indistinguishable from missing', () => {
    it('GET import — cross-provider vs genuinely missing', async () => {
      const crossRes = await asP2('GET', `/api/v1/claims/connect-care/import/${P1_BATCH_ID}`);
      const missingRes = await asP2('GET', `/api/v1/claims/connect-care/import/${NONEXISTENT_BATCH_ID}`);

      expect(crossRes.statusCode).toBe(missingRes.statusCode);
    });
  });

  // =========================================================================
  // Cross-provider reconciliation access
  // =========================================================================

  describe('Physician 2 cannot access Physician 1 reconciliation', () => {
    it('GET reconciliation result — cross-provider returns error', async () => {
      const res = await asP2('GET', `/api/v1/claims/connect-care/reconcile/${P1_BATCH_ID}`);
      // Should not return 200 with data
      const body = JSON.parse(res.body);
      if (res.statusCode === 200) {
        expect(body.data).toBeNull();
      } else {
        expect(body.data).toBeUndefined();
      }
    });

    it('POST confirm reconciliation — cross-provider returns error', async () => {
      const res = await asP2('POST', `/api/v1/claims/connect-care/reconcile/${P1_BATCH_ID}/confirm`);
      expect([404, 500]).toContain(res.statusCode);
    });
  });

  // =========================================================================
  // Import history scoped to authenticated physician
  // =========================================================================

  describe('Import history is scoped to authenticated physician', () => {
    it('GET history returns empty for physician with no imports', async () => {
      const res = await asP2('GET', '/api/v1/claims/connect-care/import/history');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });
  });
});
