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
// Fixed test identities
// ---------------------------------------------------------------------------

// Physician session (full access — all permissions)
const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_USER_ID = '11111111-0000-0000-0000-000000000001';
const PHYSICIAN_SESSION_ID = '11111111-0000-0000-0000-000000000011';

// Delegate with CLAIM_VIEW only
const DELEGATE_VIEW_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_VIEW_SESSION_TOKEN_HASH = hashToken(DELEGATE_VIEW_SESSION_TOKEN);
const DELEGATE_VIEW_USER_ID = '22222222-0000-0000-0000-000000000002';
const DELEGATE_VIEW_SESSION_ID = '22222222-0000-0000-0000-000000000022';

// Delegate with CLAIM_CREATE only
const DELEGATE_CREATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_CREATE_SESSION_TOKEN_HASH = hashToken(DELEGATE_CREATE_SESSION_TOKEN);
const DELEGATE_CREATE_USER_ID = '33333333-0000-0000-0000-000000000003';
const DELEGATE_CREATE_SESSION_ID = '33333333-0000-0000-0000-000000000033';

// Delegate with CLAIM_SUBMIT only
const DELEGATE_SUBMIT_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_SUBMIT_SESSION_TOKEN_HASH = hashToken(DELEGATE_SUBMIT_SESSION_TOKEN);
const DELEGATE_SUBMIT_USER_ID = '55555555-0000-0000-0000-000000000005';
const DELEGATE_SUBMIT_SESSION_ID = '55555555-0000-0000-0000-000000000055';

// Delegate with no claim permissions (only PATIENT_VIEW)
const DELEGATE_NONE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_NONE_SESSION_TOKEN_HASH = hashToken(DELEGATE_NONE_SESSION_TOKEN);
const DELEGATE_NONE_USER_ID = '77777777-0000-0000-0000-000000000007';
const DELEGATE_NONE_SESSION_ID = '77777777-0000-0000-0000-000000000077';

// Admin user (no explicit PHI access)
const ADMIN_SESSION_TOKEN = randomBytes(32).toString('hex');
const ADMIN_SESSION_TOKEN_HASH = hashToken(ADMIN_SESSION_TOKEN);
const ADMIN_USER_ID = '99999999-0000-0000-0000-000000000009';
const ADMIN_SESSION_ID = '99999999-0000-0000-0000-000000000099';

// Placeholder UUID for route params
const PLACEHOLDER_UUID = '00000000-0000-0000-0000-000000000001';

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
  role: string;
  subscriptionStatus: string;
  delegateContext?: {
    delegateUserId: string;
    physicianProviderId: string;
    permissions: string[];
    linkageId: string;
  };
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

// ---------------------------------------------------------------------------
// Mock repositories
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    createSession: vi.fn(async () => ({ sessionId: 'new-session-id' })),
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      const session = sessions.find((s) => s.tokenHash === tokenHash && !s.revoked);
      if (!session) return undefined;
      const user = users.find((u) => u.userId === session.userId);
      if (!user) return undefined;
      const result: any = {
        session,
        user: {
          userId: user.userId,
          role: user.role,
          subscriptionStatus: user.subscriptionStatus,
        },
      };
      if (user.delegateContext) {
        result.user.delegateContext = user.delegateContext;
      }
      return result;
    }),
    refreshSession: vi.fn(async () => {}),
    listActiveSessions: vi.fn(async () => []),
    revokeSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
  };
}

function createMockAuditRepo() {
  return {
    appendAuditLog: vi.fn(async () => {}),
  };
}

function createMockEvents() {
  return { emit: vi.fn() };
}

// ---------------------------------------------------------------------------
// Stub AHCIP repository & deps (not exercised in authz tests — just stubs)
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

  await testApp.register(ahcipRoutes, { deps: handlerDeps });
  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------

function physicianRequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function delegateViewRequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${DELEGATE_VIEW_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function delegateCreateRequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${DELEGATE_CREATE_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function delegateSubmitRequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${DELEGATE_SUBMIT_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function delegateNoneRequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${DELEGATE_NONE_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function adminRequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

// ---------------------------------------------------------------------------
// Seed test data
// ---------------------------------------------------------------------------

function seedUsers() {
  users = [];
  sessions = [];

  // Physician user (full access to all routes)
  users.push({
    userId: PHYSICIAN_USER_ID,
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
    sessionId: PHYSICIAN_SESSION_ID,
    userId: PHYSICIAN_USER_ID,
    tokenHash: PHYSICIAN_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

  // Delegate with CLAIM_VIEW only
  users.push({
    userId: DELEGATE_VIEW_USER_ID,
    email: 'delegate-view@example.com',
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    role: 'DELEGATE',
    subscriptionStatus: 'TRIAL',
    delegateContext: {
      delegateUserId: DELEGATE_VIEW_USER_ID,
      physicianProviderId: PHYSICIAN_USER_ID,
      permissions: ['CLAIM_VIEW'],
      linkageId: 'aaaaaaaa-0000-0000-0000-000000000001',
    },
  });
  sessions.push({
    sessionId: DELEGATE_VIEW_SESSION_ID,
    userId: DELEGATE_VIEW_USER_ID,
    tokenHash: DELEGATE_VIEW_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

  // Delegate with CLAIM_CREATE only
  users.push({
    userId: DELEGATE_CREATE_USER_ID,
    email: 'delegate-create@example.com',
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    role: 'DELEGATE',
    subscriptionStatus: 'TRIAL',
    delegateContext: {
      delegateUserId: DELEGATE_CREATE_USER_ID,
      physicianProviderId: PHYSICIAN_USER_ID,
      permissions: ['CLAIM_CREATE'],
      linkageId: 'bbbbbbbb-0000-0000-0000-000000000002',
    },
  });
  sessions.push({
    sessionId: DELEGATE_CREATE_SESSION_ID,
    userId: DELEGATE_CREATE_USER_ID,
    tokenHash: DELEGATE_CREATE_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

  // Delegate with CLAIM_SUBMIT only
  users.push({
    userId: DELEGATE_SUBMIT_USER_ID,
    email: 'delegate-submit@example.com',
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    role: 'DELEGATE',
    subscriptionStatus: 'TRIAL',
    delegateContext: {
      delegateUserId: DELEGATE_SUBMIT_USER_ID,
      physicianProviderId: PHYSICIAN_USER_ID,
      permissions: ['CLAIM_SUBMIT'],
      linkageId: 'dddddddd-0000-0000-0000-000000000004',
    },
  });
  sessions.push({
    sessionId: DELEGATE_SUBMIT_SESSION_ID,
    userId: DELEGATE_SUBMIT_USER_ID,
    tokenHash: DELEGATE_SUBMIT_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

  // Delegate with no claim permissions (only PATIENT_VIEW)
  users.push({
    userId: DELEGATE_NONE_USER_ID,
    email: 'delegate-none@example.com',
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    role: 'DELEGATE',
    subscriptionStatus: 'TRIAL',
    delegateContext: {
      delegateUserId: DELEGATE_NONE_USER_ID,
      physicianProviderId: PHYSICIAN_USER_ID,
      permissions: ['PATIENT_VIEW'],
      linkageId: 'ffffffff-0000-0000-0000-000000000006',
    },
  });
  sessions.push({
    sessionId: DELEGATE_NONE_SESSION_ID,
    userId: DELEGATE_NONE_USER_ID,
    tokenHash: DELEGATE_NONE_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

  // Admin user (passes authorize check for all permissions per auth plugin)
  users.push({
    userId: ADMIN_USER_ID,
    email: 'admin@meritum.ca',
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    role: 'ADMIN',
    subscriptionStatus: 'ACTIVE',
  });
  sessions.push({
    sessionId: ADMIN_SESSION_ID,
    userId: ADMIN_USER_ID,
    tokenHash: ADMIN_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });
}

// ---------------------------------------------------------------------------
// Valid payloads
// ---------------------------------------------------------------------------

const validFeeCalculatePayload = {
  health_service_code: '03.04A',
  functional_centre: 'MEDE',
  encounter_type: 'CONSULTATION',
  date_of_service: '2026-01-15',
  patient_id: PLACEHOLDER_UUID,
};

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('AHCIP Authorization & Permission Enforcement (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    seedUsers();
  });

  // =========================================================================
  // 1. Physician has full access to all AHCIP routes
  // =========================================================================

  describe('Physician role — full access', () => {
    it('GET /api/v1/ahcip/batches — allowed', async () => {
      const res = await physicianRequest('GET', '/api/v1/ahcip/batches');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /api/v1/ahcip/batches/next — allowed', async () => {
      const res = await physicianRequest('GET', '/api/v1/ahcip/batches/next');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /api/v1/ahcip/batches/:id — allowed', async () => {
      const res = await physicianRequest('GET', `/api/v1/ahcip/batches/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST /api/v1/ahcip/batches/:id/retry — allowed', async () => {
      const res = await physicianRequest('POST', `/api/v1/ahcip/batches/${PLACEHOLDER_UUID}/retry`);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /api/v1/ahcip/assessments/pending — allowed', async () => {
      const res = await physicianRequest('GET', '/api/v1/ahcip/assessments/pending');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /api/v1/ahcip/assessments/:batch_id — allowed', async () => {
      const res = await physicianRequest('GET', `/api/v1/ahcip/assessments/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST /api/v1/ahcip/fee-calculate — allowed', async () => {
      const res = await physicianRequest('POST', '/api/v1/ahcip/fee-calculate', validFeeCalculatePayload);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /api/v1/ahcip/claims/:id/fee-breakdown — allowed', async () => {
      const res = await physicianRequest('GET', `/api/v1/ahcip/claims/${PLACEHOLDER_UUID}/fee-breakdown`);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });
  });

  // =========================================================================
  // 2. Delegate with CLAIM_VIEW — allowed on CLAIM_VIEW routes
  // =========================================================================

  describe('Delegate with CLAIM_VIEW only', () => {
    // Allowed: routes guarded by CLAIM_VIEW
    it('GET /api/v1/ahcip/batches — allowed (has CLAIM_VIEW)', async () => {
      const res = await delegateViewRequest('GET', '/api/v1/ahcip/batches');
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/ahcip/batches/next — allowed (has CLAIM_VIEW)', async () => {
      const res = await delegateViewRequest('GET', '/api/v1/ahcip/batches/next');
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/ahcip/batches/:id — allowed (has CLAIM_VIEW)', async () => {
      const res = await delegateViewRequest('GET', `/api/v1/ahcip/batches/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/ahcip/assessments/pending — allowed (has CLAIM_VIEW)', async () => {
      const res = await delegateViewRequest('GET', '/api/v1/ahcip/assessments/pending');
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/ahcip/assessments/:batch_id — allowed (has CLAIM_VIEW)', async () => {
      const res = await delegateViewRequest('GET', `/api/v1/ahcip/assessments/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/ahcip/fee-calculate — allowed (has CLAIM_VIEW)', async () => {
      const res = await delegateViewRequest('POST', '/api/v1/ahcip/fee-calculate', validFeeCalculatePayload);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/ahcip/claims/:id/fee-breakdown — allowed (has CLAIM_VIEW)', async () => {
      const res = await delegateViewRequest('GET', `/api/v1/ahcip/claims/${PLACEHOLDER_UUID}/fee-breakdown`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    // Denied: route requiring CLAIM_SUBMIT
    it('POST /api/v1/ahcip/batches/:id/retry — 403 (requires CLAIM_SUBMIT)', async () => {
      const res = await delegateViewRequest('POST', `/api/v1/ahcip/batches/${PLACEHOLDER_UUID}/retry`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });
  });

  // =========================================================================
  // 3. Delegate with CLAIM_CREATE — boundary tests for AHCIP
  // =========================================================================

  describe('Delegate with CLAIM_CREATE only', () => {
    // Denied: all AHCIP routes require CLAIM_VIEW or CLAIM_SUBMIT, not CLAIM_CREATE
    it('GET /api/v1/ahcip/batches — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateCreateRequest('GET', '/api/v1/ahcip/batches');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/ahcip/batches/:id — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateCreateRequest('GET', `/api/v1/ahcip/batches/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/ahcip/batches/:id/retry — 403 (requires CLAIM_SUBMIT)', async () => {
      const res = await delegateCreateRequest('POST', `/api/v1/ahcip/batches/${PLACEHOLDER_UUID}/retry`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/ahcip/assessments/pending — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateCreateRequest('GET', '/api/v1/ahcip/assessments/pending');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/ahcip/assessments/:batch_id — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateCreateRequest('GET', `/api/v1/ahcip/assessments/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/ahcip/fee-calculate — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateCreateRequest('POST', '/api/v1/ahcip/fee-calculate', validFeeCalculatePayload);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/ahcip/claims/:id/fee-breakdown — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateCreateRequest('GET', `/api/v1/ahcip/claims/${PLACEHOLDER_UUID}/fee-breakdown`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });
  });

  // =========================================================================
  // 4. Delegate with CLAIM_SUBMIT — batch retry allowed, CLAIM_VIEW routes denied
  // =========================================================================

  describe('Delegate with CLAIM_SUBMIT only', () => {
    // Allowed: route guarded by CLAIM_SUBMIT
    it('POST /api/v1/ahcip/batches/:id/retry — allowed (has CLAIM_SUBMIT)', async () => {
      const res = await delegateSubmitRequest('POST', `/api/v1/ahcip/batches/${PLACEHOLDER_UUID}/retry`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    // Denied: routes guarded by CLAIM_VIEW
    it('GET /api/v1/ahcip/batches — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateSubmitRequest('GET', '/api/v1/ahcip/batches');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/ahcip/batches/next — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateSubmitRequest('GET', '/api/v1/ahcip/batches/next');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/ahcip/batches/:id — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateSubmitRequest('GET', `/api/v1/ahcip/batches/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/ahcip/assessments/pending — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateSubmitRequest('GET', '/api/v1/ahcip/assessments/pending');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/ahcip/assessments/:batch_id — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateSubmitRequest('GET', `/api/v1/ahcip/assessments/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/ahcip/fee-calculate — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateSubmitRequest('POST', '/api/v1/ahcip/fee-calculate', validFeeCalculatePayload);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/ahcip/claims/:id/fee-breakdown — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateSubmitRequest('GET', `/api/v1/ahcip/claims/${PLACEHOLDER_UUID}/fee-breakdown`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });
  });

  // =========================================================================
  // 5. Delegate with no claim permissions (PATIENT_VIEW only) — all denied
  // =========================================================================

  describe('Delegate with no claim permissions (PATIENT_VIEW only)', () => {
    it('GET /api/v1/ahcip/batches — 403', async () => {
      const res = await delegateNoneRequest('GET', '/api/v1/ahcip/batches');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/ahcip/batches/next — 403', async () => {
      const res = await delegateNoneRequest('GET', '/api/v1/ahcip/batches/next');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/ahcip/batches/:id — 403', async () => {
      const res = await delegateNoneRequest('GET', `/api/v1/ahcip/batches/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/ahcip/batches/:id/retry — 403', async () => {
      const res = await delegateNoneRequest('POST', `/api/v1/ahcip/batches/${PLACEHOLDER_UUID}/retry`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/ahcip/assessments/pending — 403', async () => {
      const res = await delegateNoneRequest('GET', '/api/v1/ahcip/assessments/pending');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/ahcip/assessments/:batch_id — 403', async () => {
      const res = await delegateNoneRequest('GET', `/api/v1/ahcip/assessments/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/ahcip/fee-calculate — 403', async () => {
      const res = await delegateNoneRequest('POST', '/api/v1/ahcip/fee-calculate', validFeeCalculatePayload);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/ahcip/claims/:id/fee-breakdown — 403', async () => {
      const res = await delegateNoneRequest('GET', `/api/v1/ahcip/claims/${PLACEHOLDER_UUID}/fee-breakdown`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });
  });

  // =========================================================================
  // 6. Admin role — passes authorization (admin has all permissions)
  // =========================================================================

  describe('Admin role — access control', () => {
    it('GET /api/v1/ahcip/batches — admin passes authorization', async () => {
      const res = await adminRequest('GET', '/api/v1/ahcip/batches');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /api/v1/ahcip/batches/:id — admin passes authorization', async () => {
      const res = await adminRequest('GET', `/api/v1/ahcip/batches/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST /api/v1/ahcip/batches/:id/retry — admin passes authorization', async () => {
      const res = await adminRequest('POST', `/api/v1/ahcip/batches/${PLACEHOLDER_UUID}/retry`);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /api/v1/ahcip/assessments/pending — admin passes authorization', async () => {
      const res = await adminRequest('GET', '/api/v1/ahcip/assessments/pending');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /api/v1/ahcip/assessments/:batch_id — admin passes authorization', async () => {
      const res = await adminRequest('GET', `/api/v1/ahcip/assessments/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST /api/v1/ahcip/fee-calculate — admin passes authorization', async () => {
      const res = await adminRequest('POST', '/api/v1/ahcip/fee-calculate', validFeeCalculatePayload);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /api/v1/ahcip/claims/:id/fee-breakdown — admin passes authorization', async () => {
      const res = await adminRequest('GET', `/api/v1/ahcip/claims/${PLACEHOLDER_UUID}/fee-breakdown`);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });
  });

  // =========================================================================
  // 7. 403 response shape — no data leakage on permission denial
  // =========================================================================

  describe('403 response shape — no data leakage', () => {
    it('403 response has consistent error shape with no data field', async () => {
      const res = await delegateNoneRequest('GET', '/api/v1/ahcip/batches');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('403 response does not contain internal identifiers', async () => {
      const res = await delegateNoneRequest('POST', `/api/v1/ahcip/batches/${PLACEHOLDER_UUID}/retry`);
      expect(res.statusCode).toBe(403);
      const rawBody = res.body;
      expect(rawBody).not.toContain('postgres');
      expect(rawBody).not.toContain('drizzle');
      expect(rawBody).not.toContain('session_id');
      expect(rawBody).not.toContain('provider_id');
      expect(rawBody).not.toContain('physician_id');
      expect(rawBody).not.toContain('stack');
    });

    it('403 response does not contain route handler details', async () => {
      const res = await delegateNoneRequest('POST', '/api/v1/ahcip/fee-calculate', validFeeCalculatePayload);
      expect(res.statusCode).toBe(403);
      const rawBody = res.body;
      expect(rawBody).not.toContain('handler');
      expect(rawBody).not.toContain('service');
      expect(rawBody).not.toContain('repository');
    });

    it('403 on batch retry does not leak batch existence', async () => {
      const res = await delegateViewRequest('POST', `/api/v1/ahcip/batches/${PLACEHOLDER_UUID}/retry`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.message).not.toContain(PLACEHOLDER_UUID);
      expect(body.error.message).not.toContain('batch');
    });
  });

  // =========================================================================
  // 8. Delegate permission escalation prevention
  // =========================================================================

  describe('Permission escalation prevention', () => {
    it('delegate with CLAIM_VIEW cannot access CLAIM_SUBMIT route by crafting request', async () => {
      const res = await delegateViewRequest('POST', `/api/v1/ahcip/batches/${PLACEHOLDER_UUID}/retry`);
      expect(res.statusCode).toBe(403);
    });

    it('delegate with CLAIM_SUBMIT cannot access CLAIM_VIEW routes', async () => {
      const res = await delegateSubmitRequest('GET', '/api/v1/ahcip/batches');
      expect(res.statusCode).toBe(403);
    });

    it('delegate with CLAIM_CREATE cannot access any AHCIP route', async () => {
      const routes = [
        { method: 'GET' as const, url: '/api/v1/ahcip/batches' },
        { method: 'GET' as const, url: `/api/v1/ahcip/batches/${PLACEHOLDER_UUID}` },
        { method: 'POST' as const, url: `/api/v1/ahcip/batches/${PLACEHOLDER_UUID}/retry` },
        { method: 'GET' as const, url: '/api/v1/ahcip/assessments/pending' },
        { method: 'GET' as const, url: `/api/v1/ahcip/assessments/${PLACEHOLDER_UUID}` },
        { method: 'POST' as const, url: '/api/v1/ahcip/fee-calculate' },
        { method: 'GET' as const, url: `/api/v1/ahcip/claims/${PLACEHOLDER_UUID}/fee-breakdown` },
      ];

      for (const route of routes) {
        const payload = route.url === '/api/v1/ahcip/fee-calculate' ? validFeeCalculatePayload : undefined;
        const res = await delegateCreateRequest(route.method, route.url, payload);
        expect(res.statusCode).toBe(403);
      }
    });

    it('delegate with no claim permissions cannot access any AHCIP route', async () => {
      const routes = [
        { method: 'GET' as const, url: '/api/v1/ahcip/batches' },
        { method: 'GET' as const, url: '/api/v1/ahcip/batches/next' },
        { method: 'GET' as const, url: `/api/v1/ahcip/batches/${PLACEHOLDER_UUID}` },
        { method: 'POST' as const, url: `/api/v1/ahcip/batches/${PLACEHOLDER_UUID}/retry` },
        { method: 'GET' as const, url: '/api/v1/ahcip/assessments/pending' },
        { method: 'GET' as const, url: `/api/v1/ahcip/assessments/${PLACEHOLDER_UUID}` },
        { method: 'POST' as const, url: '/api/v1/ahcip/fee-calculate' },
        { method: 'GET' as const, url: `/api/v1/ahcip/claims/${PLACEHOLDER_UUID}/fee-breakdown` },
      ];

      for (const route of routes) {
        const payload = route.url === '/api/v1/ahcip/fee-calculate' ? validFeeCalculatePayload : undefined;
        const res = await delegateNoneRequest(route.method, route.url, payload);
        expect(res.statusCode).toBe(403);
      }
    });
  });
});
