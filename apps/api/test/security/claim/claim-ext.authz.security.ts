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
import { randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

// Physician session (full access)
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

// Delegate with CLAIM_EDIT only
const DELEGATE_EDIT_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_EDIT_SESSION_TOKEN_HASH = hashToken(DELEGATE_EDIT_SESSION_TOKEN);
const DELEGATE_EDIT_USER_ID = '44444444-0000-0000-0000-000000000004';
const DELEGATE_EDIT_SESSION_ID = '44444444-0000-0000-0000-000000000044';

// Delegate with CLAIM_DELETE only
const DELEGATE_DELETE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_DELETE_SESSION_TOKEN_HASH = hashToken(DELEGATE_DELETE_SESSION_TOKEN);
const DELEGATE_DELETE_USER_ID = '66666666-0000-0000-0000-000000000006';
const DELEGATE_DELETE_SESSION_ID = '66666666-0000-0000-0000-000000000066';

// Delegate with no claim permissions (only PATIENT_VIEW)
const DELEGATE_NONE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_NONE_SESSION_TOKEN_HASH = hashToken(DELEGATE_NONE_SESSION_TOKEN);
const DELEGATE_NONE_USER_ID = '77777777-0000-0000-0000-000000000007';
const DELEGATE_NONE_SESSION_ID = '77777777-0000-0000-0000-000000000077';

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

function delegateEditRequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${DELEGATE_EDIT_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function delegateDeleteRequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${DELEGATE_DELETE_SESSION_TOKEN}` },
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

// ---------------------------------------------------------------------------
// Seed test data
// ---------------------------------------------------------------------------

function seedUsers() {
  users = [];
  sessions = [];

  // Physician user (full access)
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

  // Delegate with CLAIM_EDIT only
  users.push({
    userId: DELEGATE_EDIT_USER_ID,
    email: 'delegate-edit@example.com',
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    role: 'DELEGATE',
    subscriptionStatus: 'TRIAL',
    delegateContext: {
      delegateUserId: DELEGATE_EDIT_USER_ID,
      physicianProviderId: PHYSICIAN_USER_ID,
      permissions: ['CLAIM_EDIT'],
      linkageId: 'cccccccc-0000-0000-0000-000000000003',
    },
  });
  sessions.push({
    sessionId: DELEGATE_EDIT_SESSION_ID,
    userId: DELEGATE_EDIT_USER_ID,
    tokenHash: DELEGATE_EDIT_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

  // Delegate with CLAIM_DELETE only
  users.push({
    userId: DELEGATE_DELETE_USER_ID,
    email: 'delegate-delete@example.com',
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    role: 'DELEGATE',
    subscriptionStatus: 'TRIAL',
    delegateContext: {
      delegateUserId: DELEGATE_DELETE_USER_ID,
      physicianProviderId: PHYSICIAN_USER_ID,
      permissions: ['CLAIM_DELETE'],
      linkageId: 'eeeeeeee-0000-0000-0000-000000000005',
    },
  });
  sessions.push({
    sessionId: DELEGATE_DELETE_SESSION_ID,
    userId: DELEGATE_DELETE_USER_ID,
    tokenHash: DELEGATE_DELETE_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

  // Delegate with no claim permissions
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
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Claim Extension Authorization Enforcement (Security)', () => {
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
  // Delegates without CLAIM_CREATE -> 403 on write endpoints requiring CREATE
  // =========================================================================

  describe('Delegates without CLAIM_CREATE get 403 on CREATE endpoints', () => {
    it('CLAIM_VIEW delegate cannot POST /api/v1/claims/templates', async () => {
      const res = await delegateViewRequest('POST', '/api/v1/claims/templates', {
        name: 'Test Template',
        claim_type: 'AHCIP',
        line_items: [{ health_service_code: '03.04A', calls: 1 }],
      });
      expect(res.statusCode).toBe(403);
    });

    it('CLAIM_VIEW delegate cannot POST /api/v1/claims/templates/:id/apply', async () => {
      const res = await delegateViewRequest('POST', `/api/v1/claims/templates/${PLACEHOLDER_UUID}/apply`, {
        patient_id: PLACEHOLDER_UUID,
        date_of_service: '2026-01-15',
      });
      expect(res.statusCode).toBe(403);
    });

    it('CLAIM_VIEW delegate cannot POST /api/v1/claims/referrers/recent', async () => {
      const res = await delegateViewRequest('POST', '/api/v1/claims/referrers/recent', {
        referrer_cpsa: '12345',
        referrer_name: 'Dr. Smith',
      });
      expect(res.statusCode).toBe(403);
    });

    it('CLAIM_EDIT delegate cannot POST /api/v1/claims/templates', async () => {
      const res = await delegateEditRequest('POST', '/api/v1/claims/templates', {
        name: 'Test Template',
        claim_type: 'AHCIP',
        line_items: [{ health_service_code: '03.04A', calls: 1 }],
      });
      expect(res.statusCode).toBe(403);
    });

    it('CLAIM_DELETE delegate cannot POST /api/v1/claims/templates', async () => {
      const res = await delegateDeleteRequest('POST', '/api/v1/claims/templates', {
        name: 'Test Template',
        claim_type: 'AHCIP',
        line_items: [{ health_service_code: '03.04A', calls: 1 }],
      });
      expect(res.statusCode).toBe(403);
    });

    it('CLAIM_DELETE delegate cannot POST /api/v1/claims/referrers/recent', async () => {
      const res = await delegateDeleteRequest('POST', '/api/v1/claims/referrers/recent', {
        referrer_cpsa: '12345',
        referrer_name: 'Dr. Smith',
      });
      expect(res.statusCode).toBe(403);
    });
  });

  // =========================================================================
  // Delegates without CLAIM_EDIT -> 403 on EDIT endpoints
  // =========================================================================

  describe('Delegates without CLAIM_EDIT get 403 on EDIT endpoints', () => {
    it('CLAIM_VIEW delegate cannot PUT /api/v1/claims/templates/:id', async () => {
      const res = await delegateViewRequest('PUT', `/api/v1/claims/templates/${PLACEHOLDER_UUID}`, {
        name: 'Updated Template',
      });
      expect(res.statusCode).toBe(403);
    });

    it('CLAIM_VIEW delegate cannot PUT /api/v1/claims/templates/reorder', async () => {
      const res = await delegateViewRequest('PUT', '/api/v1/claims/templates/reorder', {
        template_ids: [PLACEHOLDER_UUID],
      });
      expect(res.statusCode).toBe(403);
    });

    it('CLAIM_VIEW delegate cannot POST /api/v1/claims/:id/justification', async () => {
      const res = await delegateViewRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/justification`, {
        claim_id: PLACEHOLDER_UUID,
        scenario: 'UNLISTED_PROCEDURE',
        justification_text: 'This procedure requires justification for the unlisted code used.',
      });
      expect(res.statusCode).toBe(403);
    });

    it('CLAIM_VIEW delegate cannot POST /api/v1/claims/justifications/:id/save-personal', async () => {
      const res = await delegateViewRequest('POST', `/api/v1/claims/justifications/${PLACEHOLDER_UUID}/save-personal`);
      expect(res.statusCode).toBe(403);
    });

    it('CLAIM_CREATE delegate cannot PUT /api/v1/claims/templates/:id', async () => {
      const res = await delegateCreateRequest('PUT', `/api/v1/claims/templates/${PLACEHOLDER_UUID}`, {
        name: 'Updated Template',
      });
      expect(res.statusCode).toBe(403);
    });

    it('CLAIM_CREATE delegate cannot POST /api/v1/claims/:id/justification', async () => {
      const res = await delegateCreateRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/justification`, {
        claim_id: PLACEHOLDER_UUID,
        scenario: 'UNLISTED_PROCEDURE',
        justification_text: 'This procedure requires justification for the unlisted code used.',
      });
      expect(res.statusCode).toBe(403);
    });
  });

  // =========================================================================
  // Delegates without CLAIM_DELETE -> 403 on DELETE endpoints
  // =========================================================================

  describe('Delegates without CLAIM_DELETE get 403 on DELETE endpoints', () => {
    it('CLAIM_VIEW delegate cannot DELETE /api/v1/claims/templates/:id', async () => {
      const res = await delegateViewRequest('DELETE', `/api/v1/claims/templates/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
    });

    it('CLAIM_CREATE delegate cannot DELETE /api/v1/claims/templates/:id', async () => {
      const res = await delegateCreateRequest('DELETE', `/api/v1/claims/templates/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
    });

    it('CLAIM_EDIT delegate cannot DELETE /api/v1/claims/templates/:id', async () => {
      const res = await delegateEditRequest('DELETE', `/api/v1/claims/templates/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
    });
  });

  // =========================================================================
  // Delegates with CLAIM_VIEW -> can access read endpoints
  // =========================================================================

  describe('Delegates with CLAIM_VIEW can access read endpoints', () => {
    it('CLAIM_VIEW delegate can GET /api/v1/claims/templates', async () => {
      const res = await delegateViewRequest('GET', '/api/v1/claims/templates');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('CLAIM_VIEW delegate can GET /api/v1/claims/:id/justification', async () => {
      const res = await delegateViewRequest('GET', `/api/v1/claims/${PLACEHOLDER_UUID}/justification`);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('CLAIM_VIEW delegate can GET /api/v1/claims/justifications/history', async () => {
      const res = await delegateViewRequest('GET', '/api/v1/claims/justifications/history');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('CLAIM_VIEW delegate can GET /api/v1/claims/referrers/recent', async () => {
      const res = await delegateViewRequest('GET', '/api/v1/claims/referrers/recent');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('CLAIM_VIEW delegate can POST /api/v1/claims/bundling/check (requires CLAIM_VIEW)', async () => {
      const res = await delegateViewRequest('POST', '/api/v1/claims/bundling/check', {
        codes: ['03.04A', '03.04B'],
        claim_type: 'AHCIP',
      });
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('CLAIM_VIEW delegate can POST /api/v1/claims/anesthesia/calculate (requires CLAIM_VIEW)', async () => {
      const res = await delegateViewRequest('POST', '/api/v1/claims/anesthesia/calculate', {
        procedure_codes: ['20.11A'],
      });
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });
  });

  // =========================================================================
  // Delegates with no permissions -> 403 on all extension endpoints
  // =========================================================================

  describe('Delegates with no claim permissions get 403 on all extension endpoints', () => {
    // Templates (CLAIM_VIEW)
    it('No-permission delegate cannot GET /api/v1/claims/templates', async () => {
      const res = await delegateNoneRequest('GET', '/api/v1/claims/templates');
      expect(res.statusCode).toBe(403);
    });

    // Templates (CLAIM_CREATE)
    it('No-permission delegate cannot POST /api/v1/claims/templates', async () => {
      const res = await delegateNoneRequest('POST', '/api/v1/claims/templates', {
        name: 'Test Template',
        claim_type: 'AHCIP',
        line_items: [{ health_service_code: '03.04A', calls: 1 }],
      });
      expect(res.statusCode).toBe(403);
    });

    // Templates (CLAIM_EDIT)
    it('No-permission delegate cannot PUT /api/v1/claims/templates/:id', async () => {
      const res = await delegateNoneRequest('PUT', `/api/v1/claims/templates/${PLACEHOLDER_UUID}`, {
        name: 'Updated Template',
      });
      expect(res.statusCode).toBe(403);
    });

    // Templates (CLAIM_DELETE)
    it('No-permission delegate cannot DELETE /api/v1/claims/templates/:id', async () => {
      const res = await delegateNoneRequest('DELETE', `/api/v1/claims/templates/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
    });

    // Apply template (CLAIM_CREATE)
    it('No-permission delegate cannot POST /api/v1/claims/templates/:id/apply', async () => {
      const res = await delegateNoneRequest('POST', `/api/v1/claims/templates/${PLACEHOLDER_UUID}/apply`, {
        patient_id: PLACEHOLDER_UUID,
        date_of_service: '2026-01-15',
      });
      expect(res.statusCode).toBe(403);
    });

    // Reorder (CLAIM_EDIT)
    it('No-permission delegate cannot PUT /api/v1/claims/templates/reorder', async () => {
      const res = await delegateNoneRequest('PUT', '/api/v1/claims/templates/reorder', {
        template_ids: [PLACEHOLDER_UUID],
      });
      expect(res.statusCode).toBe(403);
    });

    // Justification (CLAIM_EDIT)
    it('No-permission delegate cannot POST /api/v1/claims/:id/justification', async () => {
      const res = await delegateNoneRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/justification`, {
        claim_id: PLACEHOLDER_UUID,
        scenario: 'UNLISTED_PROCEDURE',
        justification_text: 'This procedure requires justification for the unlisted code used.',
      });
      expect(res.statusCode).toBe(403);
    });

    // Justification (CLAIM_VIEW)
    it('No-permission delegate cannot GET /api/v1/claims/:id/justification', async () => {
      const res = await delegateNoneRequest('GET', `/api/v1/claims/${PLACEHOLDER_UUID}/justification`);
      expect(res.statusCode).toBe(403);
    });

    // Justification history (CLAIM_VIEW)
    it('No-permission delegate cannot GET /api/v1/claims/justifications/history', async () => {
      const res = await delegateNoneRequest('GET', '/api/v1/claims/justifications/history');
      expect(res.statusCode).toBe(403);
    });

    // Save justification (CLAIM_EDIT)
    it('No-permission delegate cannot POST /api/v1/claims/justifications/:id/save-personal', async () => {
      const res = await delegateNoneRequest('POST', `/api/v1/claims/justifications/${PLACEHOLDER_UUID}/save-personal`);
      expect(res.statusCode).toBe(403);
    });

    // Referrers (CLAIM_VIEW)
    it('No-permission delegate cannot GET /api/v1/claims/referrers/recent', async () => {
      const res = await delegateNoneRequest('GET', '/api/v1/claims/referrers/recent');
      expect(res.statusCode).toBe(403);
    });

    // Referrers (CLAIM_CREATE)
    it('No-permission delegate cannot POST /api/v1/claims/referrers/recent', async () => {
      const res = await delegateNoneRequest('POST', '/api/v1/claims/referrers/recent', {
        referrer_cpsa: '12345',
        referrer_name: 'Dr. Smith',
      });
      expect(res.statusCode).toBe(403);
    });

    // Bundling (CLAIM_VIEW)
    it('No-permission delegate cannot POST /api/v1/claims/bundling/check', async () => {
      const res = await delegateNoneRequest('POST', '/api/v1/claims/bundling/check', {
        codes: ['03.04A', '03.04B'],
        claim_type: 'AHCIP',
      });
      expect(res.statusCode).toBe(403);
    });

    // Anesthesia (CLAIM_VIEW)
    it('No-permission delegate cannot POST /api/v1/claims/anesthesia/calculate', async () => {
      const res = await delegateNoneRequest('POST', '/api/v1/claims/anesthesia/calculate', {
        procedure_codes: ['20.11A'],
      });
      expect(res.statusCode).toBe(403);
    });
  });

  // =========================================================================
  // Physician has full access (sanity)
  // =========================================================================

  describe('Physician has full access to all extension endpoints', () => {
    it('Physician can POST /api/v1/claims/templates', async () => {
      const res = await physicianRequest('POST', '/api/v1/claims/templates', {
        name: 'Test Template',
        claim_type: 'AHCIP',
        line_items: [{ health_service_code: '03.04A', calls: 1 }],
      });
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('Physician can GET /api/v1/claims/templates', async () => {
      const res = await physicianRequest('GET', '/api/v1/claims/templates');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('Physician can POST /api/v1/claims/bundling/check', async () => {
      const res = await physicianRequest('POST', '/api/v1/claims/bundling/check', {
        codes: ['03.04A', '03.04B'],
        claim_type: 'AHCIP',
      });
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('Physician can POST /api/v1/claims/anesthesia/calculate', async () => {
      const res = await physicianRequest('POST', '/api/v1/claims/anesthesia/calculate', {
        procedure_codes: ['20.11A'],
      });
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });
  });

  // =========================================================================
  // 403 response body must not leak data
  // =========================================================================

  describe('403 responses do not leak sensitive information', () => {
    it('403 response has consistent error shape', async () => {
      const res = await delegateNoneRequest('GET', '/api/v1/claims/templates');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBeDefined();
      expect(body.data).toBeUndefined();
    });

    it('403 response does not contain specific permission names or delegate details', async () => {
      const res = await delegateNoneRequest('POST', '/api/v1/claims/templates', {
        name: 'Test Template',
        claim_type: 'AHCIP',
        line_items: [{ health_service_code: '03.04A', calls: 1 }],
      });
      expect(res.statusCode).toBe(403);
      const rawBody = res.body;
      // Must not reveal which specific permission is missing
      expect(rawBody).not.toContain('CLAIM_CREATE');
      expect(rawBody).not.toContain('PATIENT_VIEW');
      // Must not reveal delegate identity or linkage
      expect(rawBody).not.toContain('delegateUserId');
      expect(rawBody).not.toContain('linkageId');
      expect(rawBody).not.toContain('physicianProviderId');
    });
  });
});
