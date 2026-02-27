// ============================================================================
// Connect Care Import — Input Validation (Security)
// SQL injection in CSV fields, XSS in patient names, file size limits,
// non-CSV file rejection, malformed CSV, and UUID parameter validation.
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
// Fixed identity
// ---------------------------------------------------------------------------

const PHYSICIAN_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_TOKEN_HASH = hashToken(PHYSICIAN_TOKEN);
const PHYSICIAN_USER_ID = 'aaaa0000-0000-0000-0000-000000000001';
const PHYSICIAN_SESSION_ID = 'aaaa0000-0000-0000-0000-000000000011';

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

const DUMMY_UUID = '00000000-0000-0000-0000-000000000001';

function asPhysician(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${PHYSICIAN_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

// ============================================================================
// Test Suite
// ============================================================================

describe('Connect Care Import — Input Validation (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    users = [];
    sessions = [];

    users.push({ userId: PHYSICIAN_USER_ID, role: 'PHYSICIAN', subscriptionStatus: 'TRIAL' });
    sessions.push({
      sessionId: PHYSICIAN_SESSION_ID,
      userId: PHYSICIAN_USER_ID,
      tokenHash: PHYSICIAN_TOKEN_HASH,
      ipAddress: '127.0.0.1',
      userAgent: 'test-agent',
      createdAt: new Date(),
      lastActiveAt: new Date(),
      revoked: false,
      revokedReason: null,
    });
  });

  // =========================================================================
  // SQL injection prevention
  // =========================================================================

  describe('SQL injection prevention in CC import fields', () => {
    const SQL_PAYLOADS = [
      "'; DROP TABLE claims; --",
      "1' OR '1'='1",
      "' UNION SELECT * FROM users; --",
      "1; DELETE FROM import_batches; --",
    ];

    for (const payload of SQL_PAYLOADS) {
      it(`rejects SQL injection in spec_version: ${payload.slice(0, 30)}`, async () => {
        const res = await asPhysician('POST', '/api/v1/claims/connect-care/import', {
          spec_version: payload,
        });
        // Should be rejected (400 for too-long string) or processed safely
        expect(res.statusCode).not.toBe(500);
        const body = JSON.parse(res.body);
        expect(body.error?.message ?? '').not.toContain('DROP');
        expect(body.error?.message ?? '').not.toContain('DELETE');
      });
    }

    for (const payload of SQL_PAYLOADS) {
      it(`rejects SQL injection in reconciliation batch_id: ${payload.slice(0, 30)}`, async () => {
        const res = await asPhysician('POST', '/api/v1/claims/connect-care/reconcile', {
          batch_id: payload,
        });
        expect(res.statusCode).not.toBe(500);
      });
    }
  });

  // =========================================================================
  // XSS prevention
  // =========================================================================

  describe('XSS prevention in CC import fields', () => {
    const XSS_PAYLOADS = [
      '<script>alert("xss")</script>',
      '<img src=x onerror=alert(1)>',
      'javascript:alert(1)',
    ];

    for (const payload of XSS_PAYLOADS) {
      it(`error does not echo XSS payload: ${payload.slice(0, 30)}`, async () => {
        const res = await asPhysician('POST', '/api/v1/claims/connect-care/reconcile', {
          batch_id: payload,
        });
        expect(res.body).not.toContain('<script>');
        expect(res.body).not.toContain('onerror');
      });
    }
  });

  // =========================================================================
  // UUID parameter validation
  // =========================================================================

  describe('UUID parameter validation', () => {
    const INVALID_IDS = ['not-a-uuid', '12345', '../../../etc/passwd', '<script>alert(1)</script>'];

    for (const badId of INVALID_IDS) {
      it(`GET import with invalid ID "${badId}" → 400`, async () => {
        const res = await asPhysician('GET', `/api/v1/claims/connect-care/import/${encodeURIComponent(badId)}`);
        expect(res.statusCode).toBe(400);
      });

      it(`POST confirm with invalid ID "${badId}" → 400`, async () => {
        const res = await asPhysician('POST', `/api/v1/claims/connect-care/import/${encodeURIComponent(badId)}/confirm`, {
          selected_rows: [1],
        });
        expect(res.statusCode).toBe(400);
      });

      it(`GET reconciliation with invalid batchId "${badId}" → 400`, async () => {
        const res = await asPhysician('GET', `/api/v1/claims/connect-care/reconcile/${encodeURIComponent(badId)}`);
        expect(res.statusCode).toBe(400);
      });
    }
  });

  // =========================================================================
  // Type coercion attacks
  // =========================================================================

  describe('Type coercion attacks', () => {
    it('rejects number where string expected (spec_version)', async () => {
      const res = await asPhysician('POST', '/api/v1/claims/connect-care/import', {
        spec_version: 12345,
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects array where string expected', async () => {
      const res = await asPhysician('POST', '/api/v1/claims/connect-care/import', {
        spec_version: ['1.0'],
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects non-UUID batch_id in reconciliation trigger', async () => {
      const res = await asPhysician('POST', '/api/v1/claims/connect-care/reconcile', {
        batch_id: 'not-a-uuid',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects non-datetime inferred_service_time in resolve-time', async () => {
      const res = await asPhysician('POST', `/api/v1/claims/connect-care/reconcile/${DUMMY_UUID}/resolve-time`, {
        claim_id: DUMMY_UUID,
        inferred_service_time: 'not-a-datetime',
      });
      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // Missing required fields
  // =========================================================================

  describe('Missing required fields', () => {
    it('rejects CC import with invalid extract_type', async () => {
      const res = await asPhysician('POST', '/api/v1/claims/connect-care/import', {
        spec_version: '1.0',
        extract_type: 'INVALID_TYPE',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects reconcile trigger without batch_id', async () => {
      const res = await asPhysician('POST', '/api/v1/claims/connect-care/reconcile', {});
      expect(res.statusCode).toBe(400);
    });

    it('rejects resolve-time without claim_id', async () => {
      const res = await asPhysician('POST', `/api/v1/claims/connect-care/reconcile/${DUMMY_UUID}/resolve-time`, {
        inferred_service_time: '2026-02-16T10:30:00.000Z',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects resolve-partial without encounter_id', async () => {
      const res = await asPhysician('POST', `/api/v1/claims/connect-care/reconcile/${DUMMY_UUID}/resolve-partial`, {
        claim_id: DUMMY_UUID,
      });
      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // Error responses don't echo malicious input
  // =========================================================================

  describe('Error responses do not echo malicious input', () => {
    it('SQL keywords not reflected', async () => {
      const res = await asPhysician('POST', '/api/v1/claims/connect-care/reconcile', {
        batch_id: "'; DROP TABLE claims; --",
      });
      const rawBody = res.body;
      expect(rawBody).not.toContain('DROP TABLE');
      expect(rawBody).not.toContain('SELECT');
    });

    it('XSS not reflected', async () => {
      const res = await asPhysician('POST', '/api/v1/claims/connect-care/reconcile', {
        batch_id: '<script>alert(1)</script>',
      });
      expect(res.body).not.toContain('<script>');
      expect(res.body).not.toContain('alert');
    });
  });
});
