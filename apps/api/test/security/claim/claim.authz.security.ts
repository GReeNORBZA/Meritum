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

// Delegate with CLAIM_EDIT only
const DELEGATE_EDIT_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_EDIT_SESSION_TOKEN_HASH = hashToken(DELEGATE_EDIT_SESSION_TOKEN);
const DELEGATE_EDIT_USER_ID = '44444444-0000-0000-0000-000000000004';
const DELEGATE_EDIT_SESSION_ID = '44444444-0000-0000-0000-000000000044';

// Delegate with CLAIM_SUBMIT only
const DELEGATE_SUBMIT_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_SUBMIT_SESSION_TOKEN_HASH = hashToken(DELEGATE_SUBMIT_SESSION_TOKEN);
const DELEGATE_SUBMIT_USER_ID = '55555555-0000-0000-0000-000000000005';
const DELEGATE_SUBMIT_SESSION_ID = '55555555-0000-0000-0000-000000000055';

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

// Placeholder UUID for route params
const PLACEHOLDER_UUID = '00000000-0000-0000-0000-000000000001';
const PLACEHOLDER_SUG_UUID = '00000000-0000-0000-0000-000000000002';

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
// Stub claim repository (not exercised in authz tests — just stubs)
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

async function buildTestApp(): Promise<FastifyInstance> {
  const mockSessionRepo = createMockSessionRepo();

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

function delegateSubmitRequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${DELEGATE_SUBMIT_SESSION_TOKEN}` },
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
}

// ---------------------------------------------------------------------------
// Valid payloads
// ---------------------------------------------------------------------------

const validCreateClaim = {
  claim_type: 'AHCIP',
  patient_id: PLACEHOLDER_UUID,
  date_of_service: '2026-01-15',
};

const validUpdateClaim = {
  date_of_service: '2026-02-01',
};

const validWriteOff = {
  reason: 'Patient unable to pay',
};

const validDismissSuggestion = {
  reason: 'Not applicable',
};

const validCreateImport = {
  file_name: 'test.csv',
  file_content: 'col1,col2\nval1,val2',
};

const validCreateTemplate = {
  name: 'Test Template',
  mappings: [{ source_column: 'col1', target_field: 'field1' }],
  has_header_row: true,
};

const validUpdateTemplate = {
  name: 'Updated Template',
};

const validCreateShift = {
  facility_id: PLACEHOLDER_UUID,
  shift_date: '2026-01-15',
  start_time: '08:00',
  end_time: '16:00',
};

const validAddEncounter = {
  patient_id: PLACEHOLDER_UUID,
  date_of_service: '2026-01-15',
  claim_type: 'AHCIP',
};

const validCreateExport = {
  date_from: '2026-01-01',
  date_to: '2026-01-31',
  format: 'CSV',
};

const validUpdateSubmissionMode = {
  mode: 'AUTO_CLEAN',
};

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Claim Authorization & Permission Enforcement (Security)', () => {
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
  // 1. Delegate with CLAIM_VIEW only — boundary tests
  // =========================================================================

  describe('Delegate with CLAIM_VIEW only', () => {
    // Allowed: routes guarded by CLAIM_VIEW
    it('GET /api/v1/claims — allowed (has CLAIM_VIEW)', async () => {
      const res = await delegateViewRequest('GET', '/api/v1/claims');
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/claims/:id — allowed (has CLAIM_VIEW)', async () => {
      const res = await delegateViewRequest('GET', `/api/v1/claims/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/claims/rejected — allowed (has CLAIM_VIEW)', async () => {
      const res = await delegateViewRequest('GET', '/api/v1/claims/rejected');
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/claims/:id/rejection-details — allowed (has CLAIM_VIEW)', async () => {
      const res = await delegateViewRequest('GET', `/api/v1/claims/${PLACEHOLDER_UUID}/rejection-details`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/claims/:id/suggestions — allowed (has CLAIM_VIEW)', async () => {
      const res = await delegateViewRequest('GET', `/api/v1/claims/${PLACEHOLDER_UUID}/suggestions`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/claims/:id/audit — allowed (has CLAIM_VIEW)', async () => {
      const res = await delegateViewRequest('GET', `/api/v1/claims/${PLACEHOLDER_UUID}/audit`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/imports/:id — allowed (has CLAIM_VIEW)', async () => {
      const res = await delegateViewRequest('GET', `/api/v1/imports/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/imports/:id/preview — allowed (has CLAIM_VIEW)', async () => {
      const res = await delegateViewRequest('GET', `/api/v1/imports/${PLACEHOLDER_UUID}/preview`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/field-mapping-templates — allowed (has CLAIM_VIEW)', async () => {
      const res = await delegateViewRequest('GET', '/api/v1/field-mapping-templates');
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/shifts/:id — allowed (has CLAIM_VIEW)', async () => {
      const res = await delegateViewRequest('GET', `/api/v1/shifts/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/exports — allowed (has CLAIM_VIEW)', async () => {
      const res = await delegateViewRequest('POST', '/api/v1/exports', validCreateExport);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/exports/:id — allowed (has CLAIM_VIEW)', async () => {
      const res = await delegateViewRequest('GET', `/api/v1/exports/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/submission-preferences — allowed (has CLAIM_VIEW)', async () => {
      const res = await delegateViewRequest('GET', '/api/v1/submission-preferences');
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    // Denied: routes requiring CLAIM_CREATE
    it('POST /api/v1/claims — 403 (requires CLAIM_CREATE)', async () => {
      const res = await delegateViewRequest('POST', '/api/v1/claims', validCreateClaim);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/imports — 403 (requires CLAIM_CREATE)', async () => {
      const res = await delegateViewRequest('POST', '/api/v1/imports', validCreateImport);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/imports/:id/commit — 403 (requires CLAIM_CREATE)', async () => {
      const res = await delegateViewRequest('POST', `/api/v1/imports/${PLACEHOLDER_UUID}/commit`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/field-mapping-templates — 403 (requires CLAIM_CREATE)', async () => {
      const res = await delegateViewRequest('POST', '/api/v1/field-mapping-templates', validCreateTemplate);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/shifts — 403 (requires CLAIM_CREATE)', async () => {
      const res = await delegateViewRequest('POST', '/api/v1/shifts', validCreateShift);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/shifts/:id/encounters — 403 (requires CLAIM_CREATE)', async () => {
      const res = await delegateViewRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/encounters`, validAddEncounter);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    // Denied: routes requiring CLAIM_EDIT
    it('PUT /api/v1/claims/:id — 403 (requires CLAIM_EDIT)', async () => {
      const res = await delegateViewRequest('PUT', `/api/v1/claims/${PLACEHOLDER_UUID}`, validUpdateClaim);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/claims/:id/validate — 403 (requires CLAIM_EDIT)', async () => {
      const res = await delegateViewRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/validate`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/claims/:id/write-off — 403 (requires CLAIM_EDIT)', async () => {
      const res = await delegateViewRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/write-off`, validWriteOff);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/claims/:id/suggestions/:sug_id/accept — 403 (requires CLAIM_EDIT)', async () => {
      const res = await delegateViewRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/suggestions/${PLACEHOLDER_SUG_UUID}/accept`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/claims/:id/suggestions/:sug_id/dismiss — 403 (requires CLAIM_EDIT)', async () => {
      const res = await delegateViewRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/suggestions/${PLACEHOLDER_SUG_UUID}/dismiss`, validDismissSuggestion);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('PUT /api/v1/field-mapping-templates/:id — 403 (requires CLAIM_EDIT)', async () => {
      const res = await delegateViewRequest('PUT', `/api/v1/field-mapping-templates/${PLACEHOLDER_UUID}`, validUpdateTemplate);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('PUT /api/v1/shifts/:id/complete — 403 (requires CLAIM_EDIT)', async () => {
      const res = await delegateViewRequest('PUT', `/api/v1/shifts/${PLACEHOLDER_UUID}/complete`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('PUT /api/v1/submission-preferences — 403 (requires CLAIM_EDIT)', async () => {
      const res = await delegateViewRequest('PUT', '/api/v1/submission-preferences', validUpdateSubmissionMode);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    // Denied: routes requiring CLAIM_DELETE
    it('DELETE /api/v1/claims/:id — 403 (requires CLAIM_DELETE)', async () => {
      const res = await delegateViewRequest('DELETE', `/api/v1/claims/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('DELETE /api/v1/field-mapping-templates/:id — 403 (requires CLAIM_DELETE)', async () => {
      const res = await delegateViewRequest('DELETE', `/api/v1/field-mapping-templates/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    // Denied: routes requiring CLAIM_SUBMIT
    it('POST /api/v1/claims/:id/queue — 403 (requires CLAIM_SUBMIT)', async () => {
      const res = await delegateViewRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/queue`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/claims/:id/unqueue — 403 (requires CLAIM_SUBMIT)', async () => {
      const res = await delegateViewRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/unqueue`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/claims/:id/resubmit — 403 (requires CLAIM_SUBMIT)', async () => {
      const res = await delegateViewRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/resubmit`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });
  });

  // =========================================================================
  // 2. Delegate with CLAIM_CREATE only — boundary tests
  // =========================================================================

  describe('Delegate with CLAIM_CREATE only', () => {
    // Allowed: routes guarded by CLAIM_CREATE
    it('POST /api/v1/claims — allowed (has CLAIM_CREATE)', async () => {
      const res = await delegateCreateRequest('POST', '/api/v1/claims', validCreateClaim);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/imports — allowed (has CLAIM_CREATE)', async () => {
      const res = await delegateCreateRequest('POST', '/api/v1/imports', validCreateImport);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/imports/:id/commit — allowed (has CLAIM_CREATE)', async () => {
      const res = await delegateCreateRequest('POST', `/api/v1/imports/${PLACEHOLDER_UUID}/commit`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/field-mapping-templates — allowed (has CLAIM_CREATE)', async () => {
      const res = await delegateCreateRequest('POST', '/api/v1/field-mapping-templates', validCreateTemplate);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/shifts — allowed (has CLAIM_CREATE)', async () => {
      const res = await delegateCreateRequest('POST', '/api/v1/shifts', validCreateShift);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/shifts/:id/encounters — allowed (has CLAIM_CREATE)', async () => {
      const res = await delegateCreateRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/encounters`, validAddEncounter);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    // Denied: routes requiring CLAIM_VIEW
    it('GET /api/v1/claims — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateCreateRequest('GET', '/api/v1/claims');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/claims/:id — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateCreateRequest('GET', `/api/v1/claims/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/claims/rejected — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateCreateRequest('GET', '/api/v1/claims/rejected');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/claims/:id/suggestions — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateCreateRequest('GET', `/api/v1/claims/${PLACEHOLDER_UUID}/suggestions`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/claims/:id/rejection-details — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateCreateRequest('GET', `/api/v1/claims/${PLACEHOLDER_UUID}/rejection-details`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/claims/:id/audit — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateCreateRequest('GET', `/api/v1/claims/${PLACEHOLDER_UUID}/audit`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/imports/:id — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateCreateRequest('GET', `/api/v1/imports/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/imports/:id/preview — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateCreateRequest('GET', `/api/v1/imports/${PLACEHOLDER_UUID}/preview`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/field-mapping-templates — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateCreateRequest('GET', '/api/v1/field-mapping-templates');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/shifts/:id — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateCreateRequest('GET', `/api/v1/shifts/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/submission-preferences — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateCreateRequest('GET', '/api/v1/submission-preferences');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/exports — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateCreateRequest('POST', '/api/v1/exports', validCreateExport);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/exports/:id — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateCreateRequest('GET', `/api/v1/exports/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    // Denied: routes requiring CLAIM_EDIT
    it('PUT /api/v1/claims/:id — 403 (requires CLAIM_EDIT)', async () => {
      const res = await delegateCreateRequest('PUT', `/api/v1/claims/${PLACEHOLDER_UUID}`, validUpdateClaim);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/claims/:id/validate — 403 (requires CLAIM_EDIT)', async () => {
      const res = await delegateCreateRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/validate`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/claims/:id/write-off — 403 (requires CLAIM_EDIT)', async () => {
      const res = await delegateCreateRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/write-off`, validWriteOff);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    // Denied: routes requiring CLAIM_SUBMIT
    it('POST /api/v1/claims/:id/queue — 403 (requires CLAIM_SUBMIT)', async () => {
      const res = await delegateCreateRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/queue`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/claims/:id/resubmit — 403 (requires CLAIM_SUBMIT)', async () => {
      const res = await delegateCreateRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/resubmit`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    // Denied: routes requiring CLAIM_DELETE
    it('DELETE /api/v1/claims/:id — 403 (requires CLAIM_DELETE)', async () => {
      const res = await delegateCreateRequest('DELETE', `/api/v1/claims/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });
  });

  // =========================================================================
  // 3. Delegate with CLAIM_EDIT only — boundary tests
  // =========================================================================

  describe('Delegate with CLAIM_EDIT only', () => {
    // Allowed: routes guarded by CLAIM_EDIT
    it('PUT /api/v1/claims/:id — allowed (has CLAIM_EDIT)', async () => {
      const res = await delegateEditRequest('PUT', `/api/v1/claims/${PLACEHOLDER_UUID}`, validUpdateClaim);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/claims/:id/validate — allowed (has CLAIM_EDIT)', async () => {
      const res = await delegateEditRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/validate`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/claims/:id/write-off — allowed (has CLAIM_EDIT)', async () => {
      const res = await delegateEditRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/write-off`, validWriteOff);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/claims/:id/suggestions/:sug_id/accept — allowed (has CLAIM_EDIT)', async () => {
      const res = await delegateEditRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/suggestions/${PLACEHOLDER_SUG_UUID}/accept`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/claims/:id/suggestions/:sug_id/dismiss — allowed (has CLAIM_EDIT)', async () => {
      const res = await delegateEditRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/suggestions/${PLACEHOLDER_SUG_UUID}/dismiss`, validDismissSuggestion);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('PUT /api/v1/field-mapping-templates/:id — allowed (has CLAIM_EDIT)', async () => {
      const res = await delegateEditRequest('PUT', `/api/v1/field-mapping-templates/${PLACEHOLDER_UUID}`, validUpdateTemplate);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('PUT /api/v1/shifts/:id/complete — allowed (has CLAIM_EDIT)', async () => {
      const res = await delegateEditRequest('PUT', `/api/v1/shifts/${PLACEHOLDER_UUID}/complete`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('PUT /api/v1/submission-preferences — allowed (has CLAIM_EDIT)', async () => {
      const res = await delegateEditRequest('PUT', '/api/v1/submission-preferences', validUpdateSubmissionMode);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    // Denied: routes requiring CLAIM_VIEW
    it('GET /api/v1/claims — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateEditRequest('GET', '/api/v1/claims');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/claims/:id — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateEditRequest('GET', `/api/v1/claims/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/claims/rejected — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateEditRequest('GET', '/api/v1/claims/rejected');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/submission-preferences — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateEditRequest('GET', '/api/v1/submission-preferences');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    // Denied: routes requiring CLAIM_CREATE
    it('POST /api/v1/claims — 403 (requires CLAIM_CREATE)', async () => {
      const res = await delegateEditRequest('POST', '/api/v1/claims', validCreateClaim);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/shifts — 403 (requires CLAIM_CREATE)', async () => {
      const res = await delegateEditRequest('POST', '/api/v1/shifts', validCreateShift);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    // Denied: routes requiring CLAIM_SUBMIT
    it('POST /api/v1/claims/:id/queue — 403 (requires CLAIM_SUBMIT)', async () => {
      const res = await delegateEditRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/queue`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/claims/:id/unqueue — 403 (requires CLAIM_SUBMIT)', async () => {
      const res = await delegateEditRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/unqueue`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/claims/:id/resubmit — 403 (requires CLAIM_SUBMIT)', async () => {
      const res = await delegateEditRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/resubmit`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    // Denied: routes requiring CLAIM_DELETE
    it('DELETE /api/v1/claims/:id — 403 (requires CLAIM_DELETE)', async () => {
      const res = await delegateEditRequest('DELETE', `/api/v1/claims/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });
  });

  // =========================================================================
  // 4. Delegate with CLAIM_SUBMIT only — boundary tests
  // =========================================================================

  describe('Delegate with CLAIM_SUBMIT only', () => {
    // Allowed: routes guarded by CLAIM_SUBMIT
    it('POST /api/v1/claims/:id/queue — allowed (has CLAIM_SUBMIT)', async () => {
      const res = await delegateSubmitRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/queue`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/claims/:id/unqueue — allowed (has CLAIM_SUBMIT)', async () => {
      const res = await delegateSubmitRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/unqueue`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/claims/:id/resubmit — allowed (has CLAIM_SUBMIT)', async () => {
      const res = await delegateSubmitRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/resubmit`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    // Denied: routes requiring CLAIM_VIEW
    it('GET /api/v1/claims — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateSubmitRequest('GET', '/api/v1/claims');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/claims/:id — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateSubmitRequest('GET', `/api/v1/claims/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/claims/rejected — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateSubmitRequest('GET', '/api/v1/claims/rejected');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    // Denied: routes requiring CLAIM_CREATE
    it('POST /api/v1/claims — 403 (requires CLAIM_CREATE)', async () => {
      const res = await delegateSubmitRequest('POST', '/api/v1/claims', validCreateClaim);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/imports — 403 (requires CLAIM_CREATE)', async () => {
      const res = await delegateSubmitRequest('POST', '/api/v1/imports', validCreateImport);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    // Denied: routes requiring CLAIM_EDIT
    it('PUT /api/v1/claims/:id — 403 (requires CLAIM_EDIT)', async () => {
      const res = await delegateSubmitRequest('PUT', `/api/v1/claims/${PLACEHOLDER_UUID}`, validUpdateClaim);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/claims/:id/validate — 403 (requires CLAIM_EDIT)', async () => {
      const res = await delegateSubmitRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/validate`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/claims/:id/write-off — 403 (requires CLAIM_EDIT)', async () => {
      const res = await delegateSubmitRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/write-off`, validWriteOff);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    // Denied: routes requiring CLAIM_DELETE
    it('DELETE /api/v1/claims/:id — 403 (requires CLAIM_DELETE)', async () => {
      const res = await delegateSubmitRequest('DELETE', `/api/v1/claims/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });
  });

  // =========================================================================
  // 5. Delegate with CLAIM_DELETE only — boundary tests
  // =========================================================================

  describe('Delegate with CLAIM_DELETE only', () => {
    // Allowed: routes guarded by CLAIM_DELETE
    it('DELETE /api/v1/claims/:id — allowed (has CLAIM_DELETE)', async () => {
      const res = await delegateDeleteRequest('DELETE', `/api/v1/claims/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('DELETE /api/v1/field-mapping-templates/:id — allowed (has CLAIM_DELETE)', async () => {
      const res = await delegateDeleteRequest('DELETE', `/api/v1/field-mapping-templates/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    // Denied: routes requiring CLAIM_VIEW
    it('GET /api/v1/claims — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateDeleteRequest('GET', '/api/v1/claims');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/claims/:id — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateDeleteRequest('GET', `/api/v1/claims/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    // Denied: routes requiring CLAIM_CREATE
    it('POST /api/v1/claims — 403 (requires CLAIM_CREATE)', async () => {
      const res = await delegateDeleteRequest('POST', '/api/v1/claims', validCreateClaim);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    // Denied: routes requiring CLAIM_EDIT
    it('PUT /api/v1/claims/:id — 403 (requires CLAIM_EDIT)', async () => {
      const res = await delegateDeleteRequest('PUT', `/api/v1/claims/${PLACEHOLDER_UUID}`, validUpdateClaim);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    // Denied: routes requiring CLAIM_SUBMIT
    it('POST /api/v1/claims/:id/queue — 403 (requires CLAIM_SUBMIT)', async () => {
      const res = await delegateDeleteRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/queue`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });
  });

  // =========================================================================
  // 6. Delegate with no claim permissions (PATIENT_VIEW only)
  // =========================================================================

  describe('Delegate with no claim permissions', () => {
    it('GET /api/v1/claims — 403', async () => {
      const res = await delegateNoneRequest('GET', '/api/v1/claims');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/claims/:id — 403', async () => {
      const res = await delegateNoneRequest('GET', `/api/v1/claims/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/claims — 403', async () => {
      const res = await delegateNoneRequest('POST', '/api/v1/claims', validCreateClaim);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('PUT /api/v1/claims/:id — 403', async () => {
      const res = await delegateNoneRequest('PUT', `/api/v1/claims/${PLACEHOLDER_UUID}`, validUpdateClaim);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('DELETE /api/v1/claims/:id — 403', async () => {
      const res = await delegateNoneRequest('DELETE', `/api/v1/claims/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/claims/:id/validate — 403', async () => {
      const res = await delegateNoneRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/validate`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/claims/:id/queue — 403', async () => {
      const res = await delegateNoneRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/queue`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/claims/:id/unqueue — 403', async () => {
      const res = await delegateNoneRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/unqueue`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/claims/:id/write-off — 403', async () => {
      const res = await delegateNoneRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/write-off`, validWriteOff);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/claims/:id/resubmit — 403', async () => {
      const res = await delegateNoneRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/resubmit`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/claims/:id/suggestions — 403', async () => {
      const res = await delegateNoneRequest('GET', `/api/v1/claims/${PLACEHOLDER_UUID}/suggestions`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/claims/:id/suggestions/:sug_id/accept — 403', async () => {
      const res = await delegateNoneRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/suggestions/${PLACEHOLDER_SUG_UUID}/accept`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/claims/:id/suggestions/:sug_id/dismiss — 403', async () => {
      const res = await delegateNoneRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/suggestions/${PLACEHOLDER_SUG_UUID}/dismiss`, validDismissSuggestion);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/claims/rejected — 403', async () => {
      const res = await delegateNoneRequest('GET', '/api/v1/claims/rejected');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/claims/:id/rejection-details — 403', async () => {
      const res = await delegateNoneRequest('GET', `/api/v1/claims/${PLACEHOLDER_UUID}/rejection-details`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/claims/:id/audit — 403', async () => {
      const res = await delegateNoneRequest('GET', `/api/v1/claims/${PLACEHOLDER_UUID}/audit`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/imports — 403', async () => {
      const res = await delegateNoneRequest('POST', '/api/v1/imports', validCreateImport);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/imports/:id — 403', async () => {
      const res = await delegateNoneRequest('GET', `/api/v1/imports/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/imports/:id/commit — 403', async () => {
      const res = await delegateNoneRequest('POST', `/api/v1/imports/${PLACEHOLDER_UUID}/commit`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/field-mapping-templates — 403', async () => {
      const res = await delegateNoneRequest('POST', '/api/v1/field-mapping-templates', validCreateTemplate);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/field-mapping-templates — 403', async () => {
      const res = await delegateNoneRequest('GET', '/api/v1/field-mapping-templates');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('PUT /api/v1/field-mapping-templates/:id — 403', async () => {
      const res = await delegateNoneRequest('PUT', `/api/v1/field-mapping-templates/${PLACEHOLDER_UUID}`, validUpdateTemplate);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('DELETE /api/v1/field-mapping-templates/:id — 403', async () => {
      const res = await delegateNoneRequest('DELETE', `/api/v1/field-mapping-templates/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/shifts — 403', async () => {
      const res = await delegateNoneRequest('POST', '/api/v1/shifts', validCreateShift);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/shifts/:id/encounters — 403', async () => {
      const res = await delegateNoneRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/encounters`, validAddEncounter);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('PUT /api/v1/shifts/:id/complete — 403', async () => {
      const res = await delegateNoneRequest('PUT', `/api/v1/shifts/${PLACEHOLDER_UUID}/complete`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/shifts/:id — 403', async () => {
      const res = await delegateNoneRequest('GET', `/api/v1/shifts/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/exports — 403', async () => {
      const res = await delegateNoneRequest('POST', '/api/v1/exports', validCreateExport);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/exports/:id — 403', async () => {
      const res = await delegateNoneRequest('GET', `/api/v1/exports/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/submission-preferences — 403', async () => {
      const res = await delegateNoneRequest('GET', '/api/v1/submission-preferences');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('PUT /api/v1/submission-preferences — 403', async () => {
      const res = await delegateNoneRequest('PUT', '/api/v1/submission-preferences', validUpdateSubmissionMode);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });
  });

  // =========================================================================
  // 7. 403 responses do not leak claim data
  // =========================================================================

  describe('403 responses do not leak claim data', () => {
    it('403 on CLAIM_CREATE route does not contain PHI or claim data', async () => {
      const res = await delegateViewRequest('POST', '/api/v1/claims', validCreateClaim);
      expect(res.statusCode).toBe(403);
      const rawBody = res.body;
      expect(rawBody).not.toContain('claim_id');
      expect(rawBody).not.toContain(PHYSICIAN_USER_ID);
      expect(rawBody).not.toContain('patient_id');
      expect(rawBody).not.toContain('phn');
      expect(rawBody).not.toContain('AHCIP');
    });

    it('403 on CLAIM_EDIT route does not contain PHI or claim data', async () => {
      const res = await delegateViewRequest('PUT', `/api/v1/claims/${PLACEHOLDER_UUID}`, validUpdateClaim);
      expect(res.statusCode).toBe(403);
      const rawBody = res.body;
      expect(rawBody).not.toContain('claim_id');
      expect(rawBody).not.toContain(PHYSICIAN_USER_ID);
      expect(rawBody).not.toContain('date_of_service');
    });

    it('403 on CLAIM_DELETE route does not contain PHI or claim data', async () => {
      const res = await delegateViewRequest('DELETE', `/api/v1/claims/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
      const rawBody = res.body;
      expect(rawBody).not.toContain('claim_id');
      expect(rawBody).not.toContain(PHYSICIAN_USER_ID);
    });

    it('403 on CLAIM_SUBMIT route does not contain PHI or claim data', async () => {
      const res = await delegateViewRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/queue`);
      expect(res.statusCode).toBe(403);
      const rawBody = res.body;
      expect(rawBody).not.toContain('claim_id');
      expect(rawBody).not.toContain(PHYSICIAN_USER_ID);
      expect(rawBody).not.toContain('QUEUED');
      expect(rawBody).not.toContain('SUBMITTED');
    });

    it('403 response has consistent error shape with no extra fields', async () => {
      const res = await delegateNoneRequest('GET', '/api/v1/claims');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
      expect(Object.keys(body.error).sort()).toEqual(['code', 'message']);
    });

    it('403 response does not contain stack traces or internals', async () => {
      const res = await delegateNoneRequest('POST', '/api/v1/claims', validCreateClaim);
      expect(res.statusCode).toBe(403);
      const rawBody = res.body;
      expect(rawBody).not.toContain('stack');
      expect(rawBody).not.toContain('node_modules');
      expect(rawBody).not.toContain('.ts:');
      expect(rawBody).not.toContain('postgres');
      expect(rawBody).not.toContain('drizzle');
    });
  });

  // =========================================================================
  // 8. Sanity: physician can access all claim routes (not 403/401)
  // =========================================================================

  describe('Sanity: physician can access all claim routes', () => {
    // Claim CRUD
    it('POST /api/v1/claims — physician is not 403', async () => {
      const res = await physicianRequest('POST', '/api/v1/claims', validCreateClaim);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/claims — physician is not 403', async () => {
      const res = await physicianRequest('GET', '/api/v1/claims');
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/claims/:id — physician is not 403', async () => {
      const res = await physicianRequest('GET', `/api/v1/claims/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('PUT /api/v1/claims/:id — physician is not 403', async () => {
      const res = await physicianRequest('PUT', `/api/v1/claims/${PLACEHOLDER_UUID}`, validUpdateClaim);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('DELETE /api/v1/claims/:id — physician is not 403', async () => {
      const res = await physicianRequest('DELETE', `/api/v1/claims/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    // State transitions
    it('POST /api/v1/claims/:id/validate — physician is not 403', async () => {
      const res = await physicianRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/validate`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/claims/:id/queue — physician is not 403', async () => {
      const res = await physicianRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/queue`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/claims/:id/unqueue — physician is not 403', async () => {
      const res = await physicianRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/unqueue`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/claims/:id/write-off — physician is not 403', async () => {
      const res = await physicianRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/write-off`, validWriteOff);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/claims/:id/resubmit — physician is not 403', async () => {
      const res = await physicianRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/resubmit`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    // AI Coach
    it('GET /api/v1/claims/:id/suggestions — physician is not 403', async () => {
      const res = await physicianRequest('GET', `/api/v1/claims/${PLACEHOLDER_UUID}/suggestions`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/claims/:id/suggestions/:sug_id/accept — physician is not 403', async () => {
      const res = await physicianRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/suggestions/${PLACEHOLDER_SUG_UUID}/accept`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/claims/:id/suggestions/:sug_id/dismiss — physician is not 403', async () => {
      const res = await physicianRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/suggestions/${PLACEHOLDER_SUG_UUID}/dismiss`, validDismissSuggestion);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    // Rejection management
    it('GET /api/v1/claims/rejected — physician is not 403', async () => {
      const res = await physicianRequest('GET', '/api/v1/claims/rejected');
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/claims/:id/rejection-details — physician is not 403', async () => {
      const res = await physicianRequest('GET', `/api/v1/claims/${PLACEHOLDER_UUID}/rejection-details`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    // Claim audit
    it('GET /api/v1/claims/:id/audit — physician is not 403', async () => {
      const res = await physicianRequest('GET', `/api/v1/claims/${PLACEHOLDER_UUID}/audit`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    // EMR Import
    it('POST /api/v1/imports — physician is not 403', async () => {
      const res = await physicianRequest('POST', '/api/v1/imports', validCreateImport);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/imports/:id — physician is not 403', async () => {
      const res = await physicianRequest('GET', `/api/v1/imports/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/imports/:id/preview — physician is not 403', async () => {
      const res = await physicianRequest('GET', `/api/v1/imports/${PLACEHOLDER_UUID}/preview`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/imports/:id/commit — physician is not 403', async () => {
      const res = await physicianRequest('POST', `/api/v1/imports/${PLACEHOLDER_UUID}/commit`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    // Field Mapping Templates
    it('POST /api/v1/field-mapping-templates — physician is not 403', async () => {
      const res = await physicianRequest('POST', '/api/v1/field-mapping-templates', validCreateTemplate);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/field-mapping-templates — physician is not 403', async () => {
      const res = await physicianRequest('GET', '/api/v1/field-mapping-templates');
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('PUT /api/v1/field-mapping-templates/:id — physician is not 403', async () => {
      const res = await physicianRequest('PUT', `/api/v1/field-mapping-templates/${PLACEHOLDER_UUID}`, validUpdateTemplate);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('DELETE /api/v1/field-mapping-templates/:id — physician is not 403', async () => {
      const res = await physicianRequest('DELETE', `/api/v1/field-mapping-templates/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    // ED Shifts
    it('POST /api/v1/shifts — physician is not 403', async () => {
      const res = await physicianRequest('POST', '/api/v1/shifts', validCreateShift);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/shifts/:id/encounters — physician is not 403', async () => {
      const res = await physicianRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/encounters`, validAddEncounter);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('PUT /api/v1/shifts/:id/complete — physician is not 403', async () => {
      const res = await physicianRequest('PUT', `/api/v1/shifts/${PLACEHOLDER_UUID}/complete`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/shifts/:id — physician is not 403', async () => {
      const res = await physicianRequest('GET', `/api/v1/shifts/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    // Data Export
    it('POST /api/v1/exports — physician is not 403', async () => {
      const res = await physicianRequest('POST', '/api/v1/exports', validCreateExport);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/exports/:id — physician is not 403', async () => {
      const res = await physicianRequest('GET', `/api/v1/exports/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    // Submission Preferences
    it('GET /api/v1/submission-preferences — physician is not 403', async () => {
      const res = await physicianRequest('GET', '/api/v1/submission-preferences');
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('PUT /api/v1/submission-preferences — physician is not 403', async () => {
      const res = await physicianRequest('PUT', '/api/v1/submission-preferences', validUpdateSubmissionMode);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });
  });
});
