// ============================================================================
// Connect Care Import — Authorization Enforcement (Security)
// Verifies delegate permission boundaries for CC import + reconciliation.
// Delegates without CLAIM_CREATE → 403 on write endpoints.
// Delegates with CLAIM_VIEW → 200 on read endpoints.
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

const PHYSICIAN_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_TOKEN_HASH = hashToken(PHYSICIAN_TOKEN);
const PHYSICIAN_USER_ID = 'aaaa0000-0000-0000-0000-000000000001';
const PHYSICIAN_SESSION_ID = 'aaaa0000-0000-0000-0000-000000000011';

const DELEGATE_VIEW_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_VIEW_TOKEN_HASH = hashToken(DELEGATE_VIEW_TOKEN);
const DELEGATE_VIEW_USER_ID = 'bbbb0000-0000-0000-0000-000000000002';
const DELEGATE_VIEW_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000022';

const DELEGATE_CREATE_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_CREATE_TOKEN_HASH = hashToken(DELEGATE_CREATE_TOKEN);
const DELEGATE_CREATE_USER_ID = 'cccc0000-0000-0000-0000-000000000003';
const DELEGATE_CREATE_SESSION_ID = 'cccc0000-0000-0000-0000-000000000033';

const DELEGATE_NONE_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_NONE_TOKEN_HASH = hashToken(DELEGATE_NONE_TOKEN);
const DELEGATE_NONE_USER_ID = 'dddd0000-0000-0000-0000-000000000004';
const DELEGATE_NONE_SESSION_ID = 'dddd0000-0000-0000-0000-000000000044';

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
  delegateContext?: {
    delegateUserId: string;
    physicianProviderId: string;
    permissions: string[];
    linkageId: string;
  };
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

function asUser(token: string, method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${token}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

// ============================================================================
// Test Suite
// ============================================================================

describe('Connect Care Import — Authorization Enforcement (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    users = [];
    sessions = [];

    // Physician (full access)
    users.push({ userId: PHYSICIAN_USER_ID, role: 'PHYSICIAN', subscriptionStatus: 'TRIAL' });
    sessions.push(makeSession(PHYSICIAN_SESSION_ID, PHYSICIAN_USER_ID, PHYSICIAN_TOKEN_HASH));

    // Delegate with CLAIM_VIEW only
    users.push({
      userId: DELEGATE_VIEW_USER_ID,
      role: 'DELEGATE',
      subscriptionStatus: 'TRIAL',
      delegateContext: {
        delegateUserId: DELEGATE_VIEW_USER_ID,
        physicianProviderId: PHYSICIAN_USER_ID,
        permissions: ['CLAIM_VIEW'],
        linkageId: 'link-view',
      },
    });
    sessions.push(makeSession(DELEGATE_VIEW_SESSION_ID, DELEGATE_VIEW_USER_ID, DELEGATE_VIEW_TOKEN_HASH));

    // Delegate with CLAIM_CREATE + CLAIM_VIEW
    users.push({
      userId: DELEGATE_CREATE_USER_ID,
      role: 'DELEGATE',
      subscriptionStatus: 'TRIAL',
      delegateContext: {
        delegateUserId: DELEGATE_CREATE_USER_ID,
        physicianProviderId: PHYSICIAN_USER_ID,
        permissions: ['CLAIM_VIEW', 'CLAIM_CREATE'],
        linkageId: 'link-create',
      },
    });
    sessions.push(makeSession(DELEGATE_CREATE_SESSION_ID, DELEGATE_CREATE_USER_ID, DELEGATE_CREATE_TOKEN_HASH));

    // Delegate with no permissions
    users.push({
      userId: DELEGATE_NONE_USER_ID,
      role: 'DELEGATE',
      subscriptionStatus: 'TRIAL',
      delegateContext: {
        delegateUserId: DELEGATE_NONE_USER_ID,
        physicianProviderId: PHYSICIAN_USER_ID,
        permissions: [],
        linkageId: 'link-none',
      },
    });
    sessions.push(makeSession(DELEGATE_NONE_SESSION_ID, DELEGATE_NONE_USER_ID, DELEGATE_NONE_TOKEN_HASH));
  });

  // =========================================================================
  // Delegate without CLAIM_CREATE → 403 on write endpoints
  // =========================================================================

  describe('Delegate without CLAIM_CREATE → 403 on write endpoints', () => {
    const WRITE_ENDPOINTS = [
      { method: 'POST' as const, url: '/api/v1/claims/connect-care/import', payload: { spec_version: '1.0' }, desc: 'Upload CC import' },
      { method: 'POST' as const, url: `/api/v1/claims/connect-care/import/${DUMMY_UUID}/confirm`, payload: { action: 'CONFIRMED' }, desc: 'Confirm CC import' },
      { method: 'POST' as const, url: '/api/v1/claims/connect-care/reconcile', payload: { batch_id: DUMMY_UUID }, desc: 'Trigger reconciliation' },
      { method: 'POST' as const, url: `/api/v1/claims/connect-care/reconcile/${DUMMY_UUID}/confirm`, desc: 'Confirm reconciliation' },
      { method: 'POST' as const, url: `/api/v1/claims/connect-care/reconcile/${DUMMY_UUID}/resolve-time`, payload: { claim_id: DUMMY_UUID, inferred_service_time: '2026-02-16T10:30:00.000Z' }, desc: 'Resolve time' },
      { method: 'POST' as const, url: `/api/v1/claims/connect-care/reconcile/${DUMMY_UUID}/resolve-partial`, payload: { encounter_id: DUMMY_UUID, claim_id: DUMMY_UUID }, desc: 'Resolve partial PHN' },
    ];

    for (const ep of WRITE_ENDPOINTS) {
      it(`${ep.desc} — delegate with CLAIM_VIEW only → 403`, async () => {
        const res = await asUser(DELEGATE_VIEW_TOKEN, ep.method, ep.url, ep.payload);
        expect(res.statusCode).toBe(403);
        const body = JSON.parse(res.body);
        expect(body.error).toBeDefined();
        expect(body.error.code).toBe('FORBIDDEN');
      });
    }
  });

  // =========================================================================
  // Delegate without any permissions → 403 on all endpoints
  // =========================================================================

  describe('Delegate without any permissions → 403 on all endpoints', () => {
    const ALL_ENDPOINTS = [
      { method: 'POST' as const, url: '/api/v1/claims/connect-care/import', payload: { spec_version: '1.0' }, desc: 'Upload CC import' },
      { method: 'GET' as const, url: '/api/v1/claims/connect-care/import/history', desc: 'List history' },
      { method: 'GET' as const, url: `/api/v1/claims/connect-care/import/${DUMMY_UUID}`, desc: 'Get import' },
      { method: 'POST' as const, url: `/api/v1/claims/connect-care/import/${DUMMY_UUID}/confirm`, payload: { action: 'CONFIRMED' }, desc: 'Confirm' },
      { method: 'POST' as const, url: `/api/v1/claims/connect-care/import/${DUMMY_UUID}/cancel`, desc: 'Cancel' },
      { method: 'POST' as const, url: '/api/v1/claims/connect-care/reconcile', payload: { batch_id: DUMMY_UUID }, desc: 'Reconcile' },
      { method: 'GET' as const, url: `/api/v1/claims/connect-care/reconcile/${DUMMY_UUID}`, desc: 'Get result' },
      { method: 'POST' as const, url: `/api/v1/claims/connect-care/reconcile/${DUMMY_UUID}/confirm`, desc: 'Confirm recon' },
    ];

    for (const ep of ALL_ENDPOINTS) {
      it(`${ep.desc} — delegate with no permissions → 403`, async () => {
        const res = await asUser(DELEGATE_NONE_TOKEN, ep.method, ep.url, ep.payload);
        expect(res.statusCode).toBe(403);
      });
    }
  });

  // =========================================================================
  // Delegate with CLAIM_VIEW → allowed on read endpoints
  // =========================================================================

  describe('Delegate with CLAIM_VIEW → allowed on read endpoints', () => {
    it('GET /api/v1/claims/connect-care/import/history → not 403', async () => {
      const res = await asUser(DELEGATE_VIEW_TOKEN, 'GET', '/api/v1/claims/connect-care/import/history');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /api/v1/claims/connect-care/import/:id → not 403', async () => {
      const res = await asUser(DELEGATE_VIEW_TOKEN, 'GET', `/api/v1/claims/connect-care/import/${DUMMY_UUID}`);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /api/v1/claims/connect-care/reconcile/:batchId → not 403', async () => {
      const res = await asUser(DELEGATE_VIEW_TOKEN, 'GET', `/api/v1/claims/connect-care/reconcile/${DUMMY_UUID}`);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });
  });

  // =========================================================================
  // Delegate with CLAIM_CREATE → allowed on write endpoints
  // =========================================================================

  describe('Delegate with CLAIM_CREATE → allowed on write endpoints', () => {
    it('POST /api/v1/claims/connect-care/import → not 403', async () => {
      const res = await asUser(DELEGATE_CREATE_TOKEN, 'POST', '/api/v1/claims/connect-care/import', {
        spec_version: '1.0',
      });
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST /api/v1/claims/connect-care/reconcile → not 403', async () => {
      const res = await asUser(DELEGATE_CREATE_TOKEN, 'POST', '/api/v1/claims/connect-care/reconcile', {
        batch_id: DUMMY_UUID,
      });
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });
  });

  // =========================================================================
  // 403 response shape validation
  // =========================================================================

  describe('403 response shape validation', () => {
    it('403 response includes error.code FORBIDDEN', async () => {
      const res = await asUser(DELEGATE_NONE_TOKEN, 'POST', '/api/v1/claims/connect-care/import', {
        spec_version: '1.0',
      });
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });
  });
});
