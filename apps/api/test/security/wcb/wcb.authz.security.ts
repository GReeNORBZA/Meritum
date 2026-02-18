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
import { wcbRoutes } from '../../../src/domains/wcb/wcb.routes.js';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { type WcbHandlerDeps } from '../../../src/domains/wcb/wcb.handlers.js';
import { type WcbServiceDeps } from '../../../src/domains/wcb/wcb.service.js';
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

// Delegate with CLAIM_DELETE only
const DELEGATE_DELETE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_DELETE_SESSION_TOKEN_HASH = hashToken(DELEGATE_DELETE_SESSION_TOKEN);
const DELEGATE_DELETE_USER_ID = '55555555-0000-0000-0000-000000000005';
const DELEGATE_DELETE_SESSION_ID = '55555555-0000-0000-0000-000000000055';

// Delegate with BATCH_APPROVE only
const DELEGATE_BATCH_APPROVE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_BATCH_APPROVE_SESSION_TOKEN_HASH = hashToken(DELEGATE_BATCH_APPROVE_SESSION_TOKEN);
const DELEGATE_BATCH_APPROVE_USER_ID = '66666666-0000-0000-0000-000000000006';
const DELEGATE_BATCH_APPROVE_SESSION_ID = '66666666-0000-0000-0000-000000000066';

// Delegate with BATCH_VIEW only
const DELEGATE_BATCH_VIEW_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_BATCH_VIEW_SESSION_TOKEN_HASH = hashToken(DELEGATE_BATCH_VIEW_SESSION_TOKEN);
const DELEGATE_BATCH_VIEW_USER_ID = '77777777-0000-0000-0000-000000000007';
const DELEGATE_BATCH_VIEW_SESSION_ID = '77777777-0000-0000-0000-000000000077';

// Delegate with WCB_BATCH_UPLOAD only
const DELEGATE_UPLOAD_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_UPLOAD_SESSION_TOKEN_HASH = hashToken(DELEGATE_UPLOAD_SESSION_TOKEN);
const DELEGATE_UPLOAD_USER_ID = '88888888-0000-0000-0000-000000000008';
const DELEGATE_UPLOAD_SESSION_ID = '88888888-0000-0000-0000-000000000088';

// Delegate with REPORT_VIEW only
const DELEGATE_REPORT_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_REPORT_SESSION_TOKEN_HASH = hashToken(DELEGATE_REPORT_SESSION_TOKEN);
const DELEGATE_REPORT_USER_ID = 'aaaaaaaa-0000-0000-0000-000000000009';
const DELEGATE_REPORT_SESSION_ID = 'aaaaaaaa-0000-0000-0000-000000000099';

// Delegate with CLAIM_VIEW + CLAIM_CREATE (combined)
const DELEGATE_VIEW_CREATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_VIEW_CREATE_SESSION_TOKEN_HASH = hashToken(DELEGATE_VIEW_CREATE_SESSION_TOKEN);
const DELEGATE_VIEW_CREATE_USER_ID = 'bbbbbbbb-0000-0000-0000-00000000000a';
const DELEGATE_VIEW_CREATE_SESSION_ID = 'bbbbbbbb-0000-0000-0000-0000000000aa';

// Delegate with BATCH_VIEW + WCB_BATCH_UPLOAD (combined — needed for download)
const DELEGATE_VIEW_UPLOAD_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_VIEW_UPLOAD_SESSION_TOKEN_HASH = hashToken(DELEGATE_VIEW_UPLOAD_SESSION_TOKEN);
const DELEGATE_VIEW_UPLOAD_USER_ID = 'cccccccc-0000-0000-0000-00000000000b';
const DELEGATE_VIEW_UPLOAD_SESSION_ID = 'cccccccc-0000-0000-0000-0000000000bb';

// Delegate with no relevant permissions (only PATIENT_VIEW)
const DELEGATE_NONE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_NONE_SESSION_TOKEN_HASH = hashToken(DELEGATE_NONE_SESSION_TOKEN);
const DELEGATE_NONE_USER_ID = 'dddddddd-0000-0000-0000-00000000000c';
const DELEGATE_NONE_SESSION_ID = 'dddddddd-0000-0000-0000-0000000000cc';

// Admin user (passes all authorize checks)
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
// Stub WCB repositories & deps (not exercised in authz tests — just stubs)
// ---------------------------------------------------------------------------

function createStubWcbRepo() {
  return {
    createWcbClaim: vi.fn(async () => ({})),
    getWcbClaim: vi.fn(async () => null),
    updateWcbClaim: vi.fn(async () => ({})),
    softDeleteWcbClaim: vi.fn(async () => true),
    getWcbClaimBySubmitterTxnId: vi.fn(async () => null),
    updateWcbClaimNumber: vi.fn(async () => ({})),
    upsertInjuries: vi.fn(async () => []),
    getInjuries: vi.fn(async () => []),
    upsertPrescriptions: vi.fn(async () => []),
    getPrescriptions: vi.fn(async () => []),
    upsertConsultations: vi.fn(async () => []),
    getConsultations: vi.fn(async () => []),
    upsertWorkRestrictions: vi.fn(async () => []),
    getWorkRestrictions: vi.fn(async () => []),
    listWcbClaimsForPhysician: vi.fn(async () => ({
      data: [],
      pagination: { total: 0, page: 1, pageSize: 25, hasMore: false },
    })),
    upsertInvoiceLines: vi.fn(async () => []),
    getInvoiceLines: vi.fn(async () => []),
    validateC570Pairing: vi.fn(async () => ({ valid: true, errors: [] })),
    upsertAttachments: vi.fn(async () => []),
    getAttachments: vi.fn(async () => []),
    getAttachmentContent: vi.fn(async () => null),
    createBatch: vi.fn(async () => ({})),
    getBatch: vi.fn(async () => null),
    getBatchByControlId: vi.fn(async () => null),
    listBatches: vi.fn(async () => ({
      data: [],
      pagination: { total: 0, page: 1, pageSize: 25, hasMore: false },
    })),
    updateBatchStatus: vi.fn(async () => ({})),
    setBatchUploaded: vi.fn(async () => ({})),
    setBatchReturnReceived: vi.fn(async () => ({})),
    getQueuedClaimsForBatch: vi.fn(async () => []),
    assignClaimsToBatch: vi.fn(async () => ({})),
    createReturnRecords: vi.fn(async () => []),
    createReturnInvoiceLines: vi.fn(async () => []),
    getReturnRecordsByBatch: vi.fn(async () => []),
    matchReturnToClaimBySubmitterTxnId: vi.fn(async () => null),
    createRemittanceImport: vi.fn(async () => ({ wcbRemittanceImportId: crypto.randomUUID() })),
    createRemittanceRecords: vi.fn(async () => []),
    matchRemittanceToClaimByTxnId: vi.fn(async () => null),
    listRemittanceImports: vi.fn(async () => ({
      data: [],
      pagination: { total: 0, page: 1, pageSize: 25, hasMore: false },
    })),
    getRemittanceDiscrepancies: vi.fn(async () => []),
  };
}

function createStubClaimRepo() {
  return {
    createClaim: vi.fn(async () => ({ claimId: crypto.randomUUID(), state: 'DRAFT' })),
    findClaimById: vi.fn(async () => undefined),
    appendClaimAudit: vi.fn(async () => {}),
    transitionClaimState: vi.fn(async () => ({})),
  };
}

function createStubServiceDeps(): WcbServiceDeps {
  return {
    wcbRepo: createStubWcbRepo() as any,
    claimRepo: createStubClaimRepo() as any,
    providerLookup: {
      findProviderById: vi.fn(async () => undefined),
      getWcbConfigForForm: vi.fn(async () => null),
    },
    patientLookup: {
      findPatientById: vi.fn(async () => undefined),
    },
    auditEmitter: { emit: vi.fn(async () => {}) },
    referenceLookup: {
      findHscBaseRate: vi.fn(async () => null),
      getRrnpVariablePremiumRate: vi.fn(async () => '0.00'),
    },
    fileStorage: {
      storeEncrypted: vi.fn(async () => {}),
      readEncrypted: vi.fn(async () => Buffer.from('<xml/>')),
    },
    secretsProvider: {
      getVendorSourceId: () => 'MERITUM',
      getSubmitterId: () => 'MRT-SUBMIT',
    },
    downloadUrlGenerator: {
      generateSignedUrl: vi.fn(async () => 'https://meritum.ca/download/signed-url'),
    },
    notificationEmitter: { emit: vi.fn(async () => {}) },
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

  const handlerDeps: WcbHandlerDeps = {
    serviceDeps: createStubServiceDeps(),
    wcbPhase: 'mvp',
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

  await testApp.register(wcbRoutes, { deps: handlerDeps });
  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------

function makeRequest(
  sessionToken: string,
  method: 'GET' | 'POST' | 'PUT' | 'DELETE',
  url: string,
  payload?: unknown,
) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${sessionToken}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

const physicianRequest = (method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) =>
  makeRequest(PHYSICIAN_SESSION_TOKEN, method, url, payload);

const delegateViewRequest = (method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) =>
  makeRequest(DELEGATE_VIEW_SESSION_TOKEN, method, url, payload);

const delegateCreateRequest = (method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) =>
  makeRequest(DELEGATE_CREATE_SESSION_TOKEN, method, url, payload);

const delegateEditRequest = (method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) =>
  makeRequest(DELEGATE_EDIT_SESSION_TOKEN, method, url, payload);

const delegateDeleteRequest = (method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) =>
  makeRequest(DELEGATE_DELETE_SESSION_TOKEN, method, url, payload);

const delegateBatchApproveRequest = (method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) =>
  makeRequest(DELEGATE_BATCH_APPROVE_SESSION_TOKEN, method, url, payload);

const delegateBatchViewRequest = (method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) =>
  makeRequest(DELEGATE_BATCH_VIEW_SESSION_TOKEN, method, url, payload);

const delegateUploadRequest = (method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) =>
  makeRequest(DELEGATE_UPLOAD_SESSION_TOKEN, method, url, payload);

const delegateReportRequest = (method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) =>
  makeRequest(DELEGATE_REPORT_SESSION_TOKEN, method, url, payload);

const delegateViewCreateRequest = (method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) =>
  makeRequest(DELEGATE_VIEW_CREATE_SESSION_TOKEN, method, url, payload);

const delegateViewUploadRequest = (method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) =>
  makeRequest(DELEGATE_VIEW_UPLOAD_SESSION_TOKEN, method, url, payload);

const delegateNoneRequest = (method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) =>
  makeRequest(DELEGATE_NONE_SESSION_TOKEN, method, url, payload);

const adminRequest = (method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) =>
  makeRequest(ADMIN_SESSION_TOKEN, method, url, payload);

// ---------------------------------------------------------------------------
// Seed test data
// ---------------------------------------------------------------------------

function createDelegateUser(
  userId: string,
  sessionId: string,
  tokenHash: string,
  email: string,
  permissions: string[],
  linkageId: string,
) {
  users.push({
    userId,
    email,
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    role: 'DELEGATE',
    subscriptionStatus: 'TRIAL',
    delegateContext: {
      delegateUserId: userId,
      physicianProviderId: PHYSICIAN_USER_ID,
      permissions,
      linkageId,
    },
  });
  sessions.push({
    sessionId,
    userId,
    tokenHash,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });
}

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

  // Delegates with individual permissions
  createDelegateUser(DELEGATE_VIEW_USER_ID, DELEGATE_VIEW_SESSION_ID, DELEGATE_VIEW_SESSION_TOKEN_HASH, 'delegate-view@example.com', ['CLAIM_VIEW'], 'aaaaaaaa-0000-0000-0000-000000000001');
  createDelegateUser(DELEGATE_CREATE_USER_ID, DELEGATE_CREATE_SESSION_ID, DELEGATE_CREATE_SESSION_TOKEN_HASH, 'delegate-create@example.com', ['CLAIM_CREATE'], 'bbbbbbbb-0000-0000-0000-000000000002');
  createDelegateUser(DELEGATE_EDIT_USER_ID, DELEGATE_EDIT_SESSION_ID, DELEGATE_EDIT_SESSION_TOKEN_HASH, 'delegate-edit@example.com', ['CLAIM_EDIT'], 'cccccccc-0000-0000-0000-000000000003');
  createDelegateUser(DELEGATE_DELETE_USER_ID, DELEGATE_DELETE_SESSION_ID, DELEGATE_DELETE_SESSION_TOKEN_HASH, 'delegate-delete@example.com', ['CLAIM_DELETE'], 'dddddddd-0000-0000-0000-000000000004');
  createDelegateUser(DELEGATE_BATCH_APPROVE_USER_ID, DELEGATE_BATCH_APPROVE_SESSION_ID, DELEGATE_BATCH_APPROVE_SESSION_TOKEN_HASH, 'delegate-batch-approve@example.com', ['BATCH_APPROVE'], 'eeeeeeee-0000-0000-0000-000000000005');
  createDelegateUser(DELEGATE_BATCH_VIEW_USER_ID, DELEGATE_BATCH_VIEW_SESSION_ID, DELEGATE_BATCH_VIEW_SESSION_TOKEN_HASH, 'delegate-batch-view@example.com', ['BATCH_VIEW'], 'ffffffff-0000-0000-0000-000000000006');
  createDelegateUser(DELEGATE_UPLOAD_USER_ID, DELEGATE_UPLOAD_SESSION_ID, DELEGATE_UPLOAD_SESSION_TOKEN_HASH, 'delegate-upload@example.com', ['WCB_BATCH_UPLOAD'], '11111111-aaaa-0000-0000-000000000007');
  createDelegateUser(DELEGATE_REPORT_USER_ID, DELEGATE_REPORT_SESSION_ID, DELEGATE_REPORT_SESSION_TOKEN_HASH, 'delegate-report@example.com', ['REPORT_VIEW'], '22222222-aaaa-0000-0000-000000000008');

  // Delegates with combined permissions
  createDelegateUser(DELEGATE_VIEW_CREATE_USER_ID, DELEGATE_VIEW_CREATE_SESSION_ID, DELEGATE_VIEW_CREATE_SESSION_TOKEN_HASH, 'delegate-view-create@example.com', ['CLAIM_VIEW', 'CLAIM_CREATE'], '33333333-aaaa-0000-0000-000000000009');
  createDelegateUser(DELEGATE_VIEW_UPLOAD_USER_ID, DELEGATE_VIEW_UPLOAD_SESSION_ID, DELEGATE_VIEW_UPLOAD_SESSION_TOKEN_HASH, 'delegate-view-upload@example.com', ['BATCH_VIEW', 'WCB_BATCH_UPLOAD'], '44444444-aaaa-0000-0000-00000000000a');

  // Delegate with no relevant permissions
  createDelegateUser(DELEGATE_NONE_USER_ID, DELEGATE_NONE_SESSION_ID, DELEGATE_NONE_SESSION_TOKEN_HASH, 'delegate-none@example.com', ['PATIENT_VIEW'], '55555555-aaaa-0000-0000-00000000000b');

  // Admin user
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

const validCreateClaimPayload = {
  form_id: 'C050E',
  patient_id: PLACEHOLDER_UUID,
  date_of_injury: '2026-01-14',
  report_completion_date: '2026-01-15',
};

const validUpdateClaimPayload = {
  symptoms: 'Updated symptoms',
};

const validBatchCreatePayload = {};

const validConfirmUploadPayload = {
  uploaded_at: '2026-01-15T10:00:00.000Z',
};

const validReturnUploadPayload = {
  file_content: 'RETURN|DATA|CONTENT',
};

const validRemittanceUploadPayload = {
  xml_content: '<remittance/>',
};

const validManualOutcomePayload = {
  acceptance_status: 'accepted',
};

// ---------------------------------------------------------------------------
// Assertion helpers
// ---------------------------------------------------------------------------

function assert403(res: Awaited<ReturnType<typeof app.inject>>) {
  expect(res.statusCode).toBe(403);
  const body = JSON.parse(res.body);
  expect(body.error).toBeDefined();
  expect(body.error.code).toBe('FORBIDDEN');
  expect(body.data).toBeUndefined();
}

function assertNotForbidden(res: Awaited<ReturnType<typeof app.inject>>) {
  expect(res.statusCode).not.toBe(401);
  expect(res.statusCode).not.toBe(403);
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('WCB Authorization & Permission Enforcement (Security)', () => {
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
  // 1. Physician has full access to all WCB routes
  // =========================================================================

  describe('Physician role — full access', () => {
    it('POST /api/v1/wcb/claims — allowed', async () => {
      const res = await physicianRequest('POST', '/api/v1/wcb/claims', validCreateClaimPayload);
      assertNotForbidden(res);
    });

    it('GET /api/v1/wcb/claims/:id — allowed', async () => {
      const res = await physicianRequest('GET', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}`);
      assertNotForbidden(res);
    });

    it('PUT /api/v1/wcb/claims/:id — allowed', async () => {
      const res = await physicianRequest('PUT', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}`, validUpdateClaimPayload);
      assertNotForbidden(res);
    });

    it('DELETE /api/v1/wcb/claims/:id — allowed', async () => {
      const res = await physicianRequest('DELETE', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}`);
      assertNotForbidden(res);
    });

    it('POST /api/v1/wcb/claims/:id/validate — allowed', async () => {
      const res = await physicianRequest('POST', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}/validate`);
      assertNotForbidden(res);
    });

    it('GET /api/v1/wcb/claims/:id/form-schema — allowed', async () => {
      const res = await physicianRequest('GET', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}/form-schema`);
      assertNotForbidden(res);
    });

    it('POST /api/v1/wcb/batches — allowed', async () => {
      const res = await physicianRequest('POST', '/api/v1/wcb/batches', validBatchCreatePayload);
      assertNotForbidden(res);
    });

    it('GET /api/v1/wcb/batches/:id — allowed', async () => {
      const res = await physicianRequest('GET', `/api/v1/wcb/batches/${PLACEHOLDER_UUID}`);
      assertNotForbidden(res);
    });

    it('GET /api/v1/wcb/batches/:id/download — allowed', async () => {
      const res = await physicianRequest('GET', `/api/v1/wcb/batches/${PLACEHOLDER_UUID}/download`);
      assertNotForbidden(res);
    });

    it('POST /api/v1/wcb/batches/:id/confirm-upload — allowed', async () => {
      const res = await physicianRequest('POST', `/api/v1/wcb/batches/${PLACEHOLDER_UUID}/confirm-upload`, validConfirmUploadPayload);
      assertNotForbidden(res);
    });

    it('GET /api/v1/wcb/batches — allowed', async () => {
      const res = await physicianRequest('GET', '/api/v1/wcb/batches');
      assertNotForbidden(res);
    });

    it('POST /api/v1/wcb/returns/upload — allowed', async () => {
      const res = await physicianRequest('POST', '/api/v1/wcb/returns/upload', validReturnUploadPayload);
      assertNotForbidden(res);
    });

    it('GET /api/v1/wcb/returns/:batch_id — allowed', async () => {
      const res = await physicianRequest('GET', `/api/v1/wcb/returns/${PLACEHOLDER_UUID}`);
      assertNotForbidden(res);
    });

    it('POST /api/v1/wcb/remittances/upload — allowed', async () => {
      const res = await physicianRequest('POST', '/api/v1/wcb/remittances/upload', validRemittanceUploadPayload);
      assertNotForbidden(res);
    });

    it('GET /api/v1/wcb/remittances — allowed', async () => {
      const res = await physicianRequest('GET', '/api/v1/wcb/remittances');
      assertNotForbidden(res);
    });

    it('GET /api/v1/wcb/remittances/:id/discrepancies — allowed', async () => {
      const res = await physicianRequest('GET', `/api/v1/wcb/remittances/${PLACEHOLDER_UUID}/discrepancies`);
      assertNotForbidden(res);
    });

    it('GET /api/v1/wcb/claims/:id/export — allowed', async () => {
      const res = await physicianRequest('GET', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}/export`);
      assertNotForbidden(res);
    });

    it('POST /api/v1/wcb/claims/:id/manual-outcome — allowed', async () => {
      const res = await physicianRequest('POST', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}/manual-outcome`, validManualOutcomePayload);
      assertNotForbidden(res);
    });
  });

  // =========================================================================
  // 2. Delegate with CLAIM_VIEW only
  // =========================================================================

  describe('Delegate with CLAIM_VIEW only', () => {
    // Allowed: routes guarded by CLAIM_VIEW
    it('GET /api/v1/wcb/claims/:id — allowed (has CLAIM_VIEW)', async () => {
      const res = await delegateViewRequest('GET', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}`);
      assertNotForbidden(res);
    });

    it('POST /api/v1/wcb/claims/:id/validate — allowed (has CLAIM_VIEW)', async () => {
      const res = await delegateViewRequest('POST', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}/validate`);
      assertNotForbidden(res);
    });

    it('GET /api/v1/wcb/claims/:id/form-schema — allowed (has CLAIM_VIEW)', async () => {
      const res = await delegateViewRequest('GET', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}/form-schema`);
      assertNotForbidden(res);
    });

    it('GET /api/v1/wcb/claims/:id/export — allowed (has CLAIM_VIEW)', async () => {
      const res = await delegateViewRequest('GET', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}/export`);
      assertNotForbidden(res);
    });

    // Denied: CLAIM_CREATE
    it('POST /api/v1/wcb/claims — 403 (requires CLAIM_CREATE)', async () => {
      const res = await delegateViewRequest('POST', '/api/v1/wcb/claims', validCreateClaimPayload);
      assert403(res);
    });

    // Denied: CLAIM_EDIT
    it('PUT /api/v1/wcb/claims/:id — 403 (requires CLAIM_EDIT)', async () => {
      const res = await delegateViewRequest('PUT', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}`, validUpdateClaimPayload);
      assert403(res);
    });

    it('POST /api/v1/wcb/claims/:id/manual-outcome — 403 (requires CLAIM_EDIT)', async () => {
      const res = await delegateViewRequest('POST', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}/manual-outcome`, validManualOutcomePayload);
      assert403(res);
    });

    // Denied: CLAIM_DELETE
    it('DELETE /api/v1/wcb/claims/:id — 403 (requires CLAIM_DELETE)', async () => {
      const res = await delegateViewRequest('DELETE', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}`);
      assert403(res);
    });

    // Denied: BATCH_APPROVE
    it('POST /api/v1/wcb/batches — 403 (requires BATCH_APPROVE)', async () => {
      const res = await delegateViewRequest('POST', '/api/v1/wcb/batches', validBatchCreatePayload);
      assert403(res);
    });

    // Denied: BATCH_VIEW
    it('GET /api/v1/wcb/batches/:id — 403 (requires BATCH_VIEW)', async () => {
      const res = await delegateViewRequest('GET', `/api/v1/wcb/batches/${PLACEHOLDER_UUID}`);
      assert403(res);
    });

    it('GET /api/v1/wcb/batches — 403 (requires BATCH_VIEW)', async () => {
      const res = await delegateViewRequest('GET', '/api/v1/wcb/batches');
      assert403(res);
    });

    // Denied: BATCH_VIEW + WCB_BATCH_UPLOAD
    it('GET /api/v1/wcb/batches/:id/download — 403 (requires BATCH_VIEW + WCB_BATCH_UPLOAD)', async () => {
      const res = await delegateViewRequest('GET', `/api/v1/wcb/batches/${PLACEHOLDER_UUID}/download`);
      assert403(res);
    });

    // Denied: WCB_BATCH_UPLOAD
    it('POST /api/v1/wcb/batches/:id/confirm-upload — 403 (requires WCB_BATCH_UPLOAD)', async () => {
      const res = await delegateViewRequest('POST', `/api/v1/wcb/batches/${PLACEHOLDER_UUID}/confirm-upload`, validConfirmUploadPayload);
      assert403(res);
    });

    // Denied: BATCH_VIEW (returns)
    it('POST /api/v1/wcb/returns/upload — 403 (requires BATCH_VIEW)', async () => {
      const res = await delegateViewRequest('POST', '/api/v1/wcb/returns/upload', validReturnUploadPayload);
      assert403(res);
    });

    it('GET /api/v1/wcb/returns/:batch_id — 403 (requires BATCH_VIEW)', async () => {
      const res = await delegateViewRequest('GET', `/api/v1/wcb/returns/${PLACEHOLDER_UUID}`);
      assert403(res);
    });

    // Denied: REPORT_VIEW
    it('POST /api/v1/wcb/remittances/upload — 403 (requires REPORT_VIEW)', async () => {
      const res = await delegateViewRequest('POST', '/api/v1/wcb/remittances/upload', validRemittanceUploadPayload);
      assert403(res);
    });

    it('GET /api/v1/wcb/remittances — 403 (requires REPORT_VIEW)', async () => {
      const res = await delegateViewRequest('GET', '/api/v1/wcb/remittances');
      assert403(res);
    });

    it('GET /api/v1/wcb/remittances/:id/discrepancies — 403 (requires REPORT_VIEW)', async () => {
      const res = await delegateViewRequest('GET', `/api/v1/wcb/remittances/${PLACEHOLDER_UUID}/discrepancies`);
      assert403(res);
    });
  });

  // =========================================================================
  // 3. Delegate with CLAIM_CREATE only
  // =========================================================================

  describe('Delegate with CLAIM_CREATE only', () => {
    // Allowed: route guarded by CLAIM_CREATE
    it('POST /api/v1/wcb/claims — allowed (has CLAIM_CREATE)', async () => {
      const res = await delegateCreateRequest('POST', '/api/v1/wcb/claims', validCreateClaimPayload);
      assertNotForbidden(res);
    });

    // Denied: CLAIM_VIEW routes
    it('GET /api/v1/wcb/claims/:id — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateCreateRequest('GET', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}`);
      assert403(res);
    });

    it('POST /api/v1/wcb/claims/:id/validate — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateCreateRequest('POST', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}/validate`);
      assert403(res);
    });

    it('GET /api/v1/wcb/claims/:id/form-schema — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateCreateRequest('GET', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}/form-schema`);
      assert403(res);
    });

    it('GET /api/v1/wcb/claims/:id/export — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateCreateRequest('GET', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}/export`);
      assert403(res);
    });

    // Denied: CLAIM_EDIT
    it('PUT /api/v1/wcb/claims/:id — 403 (requires CLAIM_EDIT)', async () => {
      const res = await delegateCreateRequest('PUT', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}`, validUpdateClaimPayload);
      assert403(res);
    });

    it('POST /api/v1/wcb/claims/:id/manual-outcome — 403 (requires CLAIM_EDIT)', async () => {
      const res = await delegateCreateRequest('POST', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}/manual-outcome`, validManualOutcomePayload);
      assert403(res);
    });

    // Denied: CLAIM_DELETE
    it('DELETE /api/v1/wcb/claims/:id — 403 (requires CLAIM_DELETE)', async () => {
      const res = await delegateCreateRequest('DELETE', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}`);
      assert403(res);
    });

    // Denied: batch/return/remittance routes
    it('POST /api/v1/wcb/batches — 403 (requires BATCH_APPROVE)', async () => {
      const res = await delegateCreateRequest('POST', '/api/v1/wcb/batches', validBatchCreatePayload);
      assert403(res);
    });

    it('GET /api/v1/wcb/batches — 403 (requires BATCH_VIEW)', async () => {
      const res = await delegateCreateRequest('GET', '/api/v1/wcb/batches');
      assert403(res);
    });
  });

  // =========================================================================
  // 4. Delegate with CLAIM_EDIT only
  // =========================================================================

  describe('Delegate with CLAIM_EDIT only', () => {
    // Allowed: CLAIM_EDIT routes
    it('PUT /api/v1/wcb/claims/:id — allowed (has CLAIM_EDIT)', async () => {
      const res = await delegateEditRequest('PUT', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}`, validUpdateClaimPayload);
      assertNotForbidden(res);
    });

    it('POST /api/v1/wcb/claims/:id/manual-outcome — allowed (has CLAIM_EDIT)', async () => {
      const res = await delegateEditRequest('POST', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}/manual-outcome`, validManualOutcomePayload);
      assertNotForbidden(res);
    });

    // Denied: CLAIM_VIEW
    it('GET /api/v1/wcb/claims/:id — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateEditRequest('GET', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}`);
      assert403(res);
    });

    it('GET /api/v1/wcb/claims/:id/export — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateEditRequest('GET', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}/export`);
      assert403(res);
    });

    // Denied: CLAIM_CREATE
    it('POST /api/v1/wcb/claims — 403 (requires CLAIM_CREATE)', async () => {
      const res = await delegateEditRequest('POST', '/api/v1/wcb/claims', validCreateClaimPayload);
      assert403(res);
    });

    // Denied: CLAIM_DELETE
    it('DELETE /api/v1/wcb/claims/:id — 403 (requires CLAIM_DELETE)', async () => {
      const res = await delegateEditRequest('DELETE', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}`);
      assert403(res);
    });

    // Denied: batch routes
    it('POST /api/v1/wcb/batches — 403 (requires BATCH_APPROVE)', async () => {
      const res = await delegateEditRequest('POST', '/api/v1/wcb/batches', validBatchCreatePayload);
      assert403(res);
    });

    it('GET /api/v1/wcb/batches — 403 (requires BATCH_VIEW)', async () => {
      const res = await delegateEditRequest('GET', '/api/v1/wcb/batches');
      assert403(res);
    });
  });

  // =========================================================================
  // 5. Delegate with CLAIM_DELETE only
  // =========================================================================

  describe('Delegate with CLAIM_DELETE only', () => {
    // Allowed: CLAIM_DELETE route
    it('DELETE /api/v1/wcb/claims/:id — allowed (has CLAIM_DELETE)', async () => {
      const res = await delegateDeleteRequest('DELETE', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}`);
      assertNotForbidden(res);
    });

    // Denied: CLAIM_VIEW
    it('GET /api/v1/wcb/claims/:id — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateDeleteRequest('GET', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}`);
      assert403(res);
    });

    // Denied: CLAIM_CREATE
    it('POST /api/v1/wcb/claims — 403 (requires CLAIM_CREATE)', async () => {
      const res = await delegateDeleteRequest('POST', '/api/v1/wcb/claims', validCreateClaimPayload);
      assert403(res);
    });

    // Denied: CLAIM_EDIT
    it('PUT /api/v1/wcb/claims/:id — 403 (requires CLAIM_EDIT)', async () => {
      const res = await delegateDeleteRequest('PUT', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}`, validUpdateClaimPayload);
      assert403(res);
    });

    // Denied: batch routes
    it('POST /api/v1/wcb/batches — 403 (requires BATCH_APPROVE)', async () => {
      const res = await delegateDeleteRequest('POST', '/api/v1/wcb/batches', validBatchCreatePayload);
      assert403(res);
    });
  });

  // =========================================================================
  // 6. Delegate with BATCH_APPROVE only
  // =========================================================================

  describe('Delegate with BATCH_APPROVE only', () => {
    // Allowed: BATCH_APPROVE route
    it('POST /api/v1/wcb/batches — allowed (has BATCH_APPROVE)', async () => {
      const res = await delegateBatchApproveRequest('POST', '/api/v1/wcb/batches', validBatchCreatePayload);
      assertNotForbidden(res);
    });

    // Denied: BATCH_VIEW routes
    it('GET /api/v1/wcb/batches/:id — 403 (requires BATCH_VIEW)', async () => {
      const res = await delegateBatchApproveRequest('GET', `/api/v1/wcb/batches/${PLACEHOLDER_UUID}`);
      assert403(res);
    });

    it('GET /api/v1/wcb/batches — 403 (requires BATCH_VIEW)', async () => {
      const res = await delegateBatchApproveRequest('GET', '/api/v1/wcb/batches');
      assert403(res);
    });

    it('GET /api/v1/wcb/batches/:id/download — 403 (requires BATCH_VIEW + WCB_BATCH_UPLOAD)', async () => {
      const res = await delegateBatchApproveRequest('GET', `/api/v1/wcb/batches/${PLACEHOLDER_UUID}/download`);
      assert403(res);
    });

    // Denied: WCB_BATCH_UPLOAD
    it('POST /api/v1/wcb/batches/:id/confirm-upload — 403 (requires WCB_BATCH_UPLOAD)', async () => {
      const res = await delegateBatchApproveRequest('POST', `/api/v1/wcb/batches/${PLACEHOLDER_UUID}/confirm-upload`, validConfirmUploadPayload);
      assert403(res);
    });

    // Denied: claim CRUD
    it('POST /api/v1/wcb/claims — 403 (requires CLAIM_CREATE)', async () => {
      const res = await delegateBatchApproveRequest('POST', '/api/v1/wcb/claims', validCreateClaimPayload);
      assert403(res);
    });

    it('GET /api/v1/wcb/claims/:id — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateBatchApproveRequest('GET', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}`);
      assert403(res);
    });

    // Denied: return/remittance routes
    it('POST /api/v1/wcb/returns/upload — 403 (requires BATCH_VIEW)', async () => {
      const res = await delegateBatchApproveRequest('POST', '/api/v1/wcb/returns/upload', validReturnUploadPayload);
      assert403(res);
    });

    it('GET /api/v1/wcb/remittances — 403 (requires REPORT_VIEW)', async () => {
      const res = await delegateBatchApproveRequest('GET', '/api/v1/wcb/remittances');
      assert403(res);
    });
  });

  // =========================================================================
  // 7. Delegate with BATCH_VIEW only
  // =========================================================================

  describe('Delegate with BATCH_VIEW only', () => {
    // Allowed: BATCH_VIEW routes
    it('GET /api/v1/wcb/batches/:id — allowed (has BATCH_VIEW)', async () => {
      const res = await delegateBatchViewRequest('GET', `/api/v1/wcb/batches/${PLACEHOLDER_UUID}`);
      assertNotForbidden(res);
    });

    it('GET /api/v1/wcb/batches — allowed (has BATCH_VIEW)', async () => {
      const res = await delegateBatchViewRequest('GET', '/api/v1/wcb/batches');
      assertNotForbidden(res);
    });

    it('POST /api/v1/wcb/returns/upload — allowed (has BATCH_VIEW)', async () => {
      const res = await delegateBatchViewRequest('POST', '/api/v1/wcb/returns/upload', validReturnUploadPayload);
      assertNotForbidden(res);
    });

    it('GET /api/v1/wcb/returns/:batch_id — allowed (has BATCH_VIEW)', async () => {
      const res = await delegateBatchViewRequest('GET', `/api/v1/wcb/returns/${PLACEHOLDER_UUID}`);
      assertNotForbidden(res);
    });

    // Denied: download requires BATCH_VIEW + WCB_BATCH_UPLOAD (missing WCB_BATCH_UPLOAD)
    it('GET /api/v1/wcb/batches/:id/download — 403 (also requires WCB_BATCH_UPLOAD)', async () => {
      const res = await delegateBatchViewRequest('GET', `/api/v1/wcb/batches/${PLACEHOLDER_UUID}/download`);
      assert403(res);
    });

    // Denied: BATCH_APPROVE
    it('POST /api/v1/wcb/batches — 403 (requires BATCH_APPROVE)', async () => {
      const res = await delegateBatchViewRequest('POST', '/api/v1/wcb/batches', validBatchCreatePayload);
      assert403(res);
    });

    // Denied: WCB_BATCH_UPLOAD
    it('POST /api/v1/wcb/batches/:id/confirm-upload — 403 (requires WCB_BATCH_UPLOAD)', async () => {
      const res = await delegateBatchViewRequest('POST', `/api/v1/wcb/batches/${PLACEHOLDER_UUID}/confirm-upload`, validConfirmUploadPayload);
      assert403(res);
    });

    // Denied: claim CRUD
    it('POST /api/v1/wcb/claims — 403 (requires CLAIM_CREATE)', async () => {
      const res = await delegateBatchViewRequest('POST', '/api/v1/wcb/claims', validCreateClaimPayload);
      assert403(res);
    });

    it('GET /api/v1/wcb/claims/:id — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateBatchViewRequest('GET', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}`);
      assert403(res);
    });

    // Denied: remittance (REPORT_VIEW)
    it('GET /api/v1/wcb/remittances — 403 (requires REPORT_VIEW)', async () => {
      const res = await delegateBatchViewRequest('GET', '/api/v1/wcb/remittances');
      assert403(res);
    });
  });

  // =========================================================================
  // 8. Delegate with WCB_BATCH_UPLOAD only
  // =========================================================================

  describe('Delegate with WCB_BATCH_UPLOAD only', () => {
    // Allowed: WCB_BATCH_UPLOAD route
    it('POST /api/v1/wcb/batches/:id/confirm-upload — allowed (has WCB_BATCH_UPLOAD)', async () => {
      const res = await delegateUploadRequest('POST', `/api/v1/wcb/batches/${PLACEHOLDER_UUID}/confirm-upload`, validConfirmUploadPayload);
      assertNotForbidden(res);
    });

    // Denied: download requires BOTH BATCH_VIEW + WCB_BATCH_UPLOAD (missing BATCH_VIEW)
    it('GET /api/v1/wcb/batches/:id/download — 403 (also requires BATCH_VIEW)', async () => {
      const res = await delegateUploadRequest('GET', `/api/v1/wcb/batches/${PLACEHOLDER_UUID}/download`);
      assert403(res);
    });

    // Denied: BATCH_VIEW routes
    it('GET /api/v1/wcb/batches/:id — 403 (requires BATCH_VIEW)', async () => {
      const res = await delegateUploadRequest('GET', `/api/v1/wcb/batches/${PLACEHOLDER_UUID}`);
      assert403(res);
    });

    it('GET /api/v1/wcb/batches — 403 (requires BATCH_VIEW)', async () => {
      const res = await delegateUploadRequest('GET', '/api/v1/wcb/batches');
      assert403(res);
    });

    // Denied: BATCH_APPROVE
    it('POST /api/v1/wcb/batches — 403 (requires BATCH_APPROVE)', async () => {
      const res = await delegateUploadRequest('POST', '/api/v1/wcb/batches', validBatchCreatePayload);
      assert403(res);
    });

    // Denied: claim routes
    it('POST /api/v1/wcb/claims — 403 (requires CLAIM_CREATE)', async () => {
      const res = await delegateUploadRequest('POST', '/api/v1/wcb/claims', validCreateClaimPayload);
      assert403(res);
    });

    it('GET /api/v1/wcb/claims/:id — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateUploadRequest('GET', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}`);
      assert403(res);
    });

    // Denied: return routes (require BATCH_VIEW)
    it('POST /api/v1/wcb/returns/upload — 403 (requires BATCH_VIEW)', async () => {
      const res = await delegateUploadRequest('POST', '/api/v1/wcb/returns/upload', validReturnUploadPayload);
      assert403(res);
    });

    it('GET /api/v1/wcb/returns/:batch_id — 403 (requires BATCH_VIEW)', async () => {
      const res = await delegateUploadRequest('GET', `/api/v1/wcb/returns/${PLACEHOLDER_UUID}`);
      assert403(res);
    });

    // Denied: remittance routes (require REPORT_VIEW)
    it('GET /api/v1/wcb/remittances — 403 (requires REPORT_VIEW)', async () => {
      const res = await delegateUploadRequest('GET', '/api/v1/wcb/remittances');
      assert403(res);
    });
  });

  // =========================================================================
  // 9. Delegate with REPORT_VIEW only
  // =========================================================================

  describe('Delegate with REPORT_VIEW only', () => {
    // Allowed: REPORT_VIEW routes
    it('POST /api/v1/wcb/remittances/upload — allowed (has REPORT_VIEW)', async () => {
      const res = await delegateReportRequest('POST', '/api/v1/wcb/remittances/upload', validRemittanceUploadPayload);
      assertNotForbidden(res);
    });

    it('GET /api/v1/wcb/remittances — allowed (has REPORT_VIEW)', async () => {
      const res = await delegateReportRequest('GET', '/api/v1/wcb/remittances');
      assertNotForbidden(res);
    });

    it('GET /api/v1/wcb/remittances/:id/discrepancies — allowed (has REPORT_VIEW)', async () => {
      const res = await delegateReportRequest('GET', `/api/v1/wcb/remittances/${PLACEHOLDER_UUID}/discrepancies`);
      assertNotForbidden(res);
    });

    // Denied: claim routes
    it('POST /api/v1/wcb/claims — 403 (requires CLAIM_CREATE)', async () => {
      const res = await delegateReportRequest('POST', '/api/v1/wcb/claims', validCreateClaimPayload);
      assert403(res);
    });

    it('GET /api/v1/wcb/claims/:id — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateReportRequest('GET', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}`);
      assert403(res);
    });

    it('PUT /api/v1/wcb/claims/:id — 403 (requires CLAIM_EDIT)', async () => {
      const res = await delegateReportRequest('PUT', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}`, validUpdateClaimPayload);
      assert403(res);
    });

    it('DELETE /api/v1/wcb/claims/:id — 403 (requires CLAIM_DELETE)', async () => {
      const res = await delegateReportRequest('DELETE', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}`);
      assert403(res);
    });

    // Denied: batch routes
    it('POST /api/v1/wcb/batches — 403 (requires BATCH_APPROVE)', async () => {
      const res = await delegateReportRequest('POST', '/api/v1/wcb/batches', validBatchCreatePayload);
      assert403(res);
    });

    it('GET /api/v1/wcb/batches — 403 (requires BATCH_VIEW)', async () => {
      const res = await delegateReportRequest('GET', '/api/v1/wcb/batches');
      assert403(res);
    });

    it('GET /api/v1/wcb/batches/:id — 403 (requires BATCH_VIEW)', async () => {
      const res = await delegateReportRequest('GET', `/api/v1/wcb/batches/${PLACEHOLDER_UUID}`);
      assert403(res);
    });

    // Denied: return routes (require BATCH_VIEW)
    it('POST /api/v1/wcb/returns/upload — 403 (requires BATCH_VIEW)', async () => {
      const res = await delegateReportRequest('POST', '/api/v1/wcb/returns/upload', validReturnUploadPayload);
      assert403(res);
    });
  });

  // =========================================================================
  // 10. Combined permission: CLAIM_VIEW + CLAIM_CREATE
  // =========================================================================

  describe('Delegate with CLAIM_VIEW + CLAIM_CREATE', () => {
    it('POST /api/v1/wcb/claims — allowed (has CLAIM_CREATE)', async () => {
      const res = await delegateViewCreateRequest('POST', '/api/v1/wcb/claims', validCreateClaimPayload);
      assertNotForbidden(res);
    });

    it('GET /api/v1/wcb/claims/:id — allowed (has CLAIM_VIEW)', async () => {
      const res = await delegateViewCreateRequest('GET', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}`);
      assertNotForbidden(res);
    });

    it('POST /api/v1/wcb/claims/:id/validate — allowed (has CLAIM_VIEW)', async () => {
      const res = await delegateViewCreateRequest('POST', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}/validate`);
      assertNotForbidden(res);
    });

    it('GET /api/v1/wcb/claims/:id/form-schema — allowed (has CLAIM_VIEW)', async () => {
      const res = await delegateViewCreateRequest('GET', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}/form-schema`);
      assertNotForbidden(res);
    });

    it('GET /api/v1/wcb/claims/:id/export — allowed (has CLAIM_VIEW)', async () => {
      const res = await delegateViewCreateRequest('GET', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}/export`);
      assertNotForbidden(res);
    });

    // Still denied: CLAIM_EDIT, CLAIM_DELETE, batch, etc.
    it('PUT /api/v1/wcb/claims/:id — 403 (requires CLAIM_EDIT)', async () => {
      const res = await delegateViewCreateRequest('PUT', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}`, validUpdateClaimPayload);
      assert403(res);
    });

    it('DELETE /api/v1/wcb/claims/:id — 403 (requires CLAIM_DELETE)', async () => {
      const res = await delegateViewCreateRequest('DELETE', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}`);
      assert403(res);
    });

    it('POST /api/v1/wcb/batches — 403 (requires BATCH_APPROVE)', async () => {
      const res = await delegateViewCreateRequest('POST', '/api/v1/wcb/batches', validBatchCreatePayload);
      assert403(res);
    });
  });

  // =========================================================================
  // 11. Combined permission: BATCH_VIEW + WCB_BATCH_UPLOAD (download allowed)
  // =========================================================================

  describe('Delegate with BATCH_VIEW + WCB_BATCH_UPLOAD', () => {
    // Both permissions present → download allowed
    it('GET /api/v1/wcb/batches/:id/download — allowed (has both BATCH_VIEW + WCB_BATCH_UPLOAD)', async () => {
      const res = await delegateViewUploadRequest('GET', `/api/v1/wcb/batches/${PLACEHOLDER_UUID}/download`);
      assertNotForbidden(res);
    });

    // BATCH_VIEW routes
    it('GET /api/v1/wcb/batches/:id — allowed (has BATCH_VIEW)', async () => {
      const res = await delegateViewUploadRequest('GET', `/api/v1/wcb/batches/${PLACEHOLDER_UUID}`);
      assertNotForbidden(res);
    });

    it('GET /api/v1/wcb/batches — allowed (has BATCH_VIEW)', async () => {
      const res = await delegateViewUploadRequest('GET', '/api/v1/wcb/batches');
      assertNotForbidden(res);
    });

    // WCB_BATCH_UPLOAD route
    it('POST /api/v1/wcb/batches/:id/confirm-upload — allowed (has WCB_BATCH_UPLOAD)', async () => {
      const res = await delegateViewUploadRequest('POST', `/api/v1/wcb/batches/${PLACEHOLDER_UUID}/confirm-upload`, validConfirmUploadPayload);
      assertNotForbidden(res);
    });

    // BATCH_VIEW return routes
    it('POST /api/v1/wcb/returns/upload — allowed (has BATCH_VIEW)', async () => {
      const res = await delegateViewUploadRequest('POST', '/api/v1/wcb/returns/upload', validReturnUploadPayload);
      assertNotForbidden(res);
    });

    it('GET /api/v1/wcb/returns/:batch_id — allowed (has BATCH_VIEW)', async () => {
      const res = await delegateViewUploadRequest('GET', `/api/v1/wcb/returns/${PLACEHOLDER_UUID}`);
      assertNotForbidden(res);
    });

    // Still denied: BATCH_APPROVE
    it('POST /api/v1/wcb/batches — 403 (requires BATCH_APPROVE)', async () => {
      const res = await delegateViewUploadRequest('POST', '/api/v1/wcb/batches', validBatchCreatePayload);
      assert403(res);
    });

    // Still denied: claim routes
    it('POST /api/v1/wcb/claims — 403 (requires CLAIM_CREATE)', async () => {
      const res = await delegateViewUploadRequest('POST', '/api/v1/wcb/claims', validCreateClaimPayload);
      assert403(res);
    });

    it('GET /api/v1/wcb/claims/:id — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateViewUploadRequest('GET', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}`);
      assert403(res);
    });

    // Still denied: remittance (REPORT_VIEW)
    it('GET /api/v1/wcb/remittances — 403 (requires REPORT_VIEW)', async () => {
      const res = await delegateViewUploadRequest('GET', '/api/v1/wcb/remittances');
      assert403(res);
    });
  });

  // =========================================================================
  // 12. Delegate with no relevant permissions (PATIENT_VIEW only) — all denied
  // =========================================================================

  describe('Delegate with no relevant permissions (PATIENT_VIEW only)', () => {
    const allRoutes: Array<{ method: 'GET' | 'POST' | 'PUT' | 'DELETE'; url: string; payload?: unknown }> = [
      { method: 'POST', url: '/api/v1/wcb/claims', payload: validCreateClaimPayload },
      { method: 'GET', url: `/api/v1/wcb/claims/${PLACEHOLDER_UUID}` },
      { method: 'PUT', url: `/api/v1/wcb/claims/${PLACEHOLDER_UUID}`, payload: validUpdateClaimPayload },
      { method: 'DELETE', url: `/api/v1/wcb/claims/${PLACEHOLDER_UUID}` },
      { method: 'POST', url: `/api/v1/wcb/claims/${PLACEHOLDER_UUID}/validate` },
      { method: 'GET', url: `/api/v1/wcb/claims/${PLACEHOLDER_UUID}/form-schema` },
      { method: 'POST', url: '/api/v1/wcb/batches', payload: validBatchCreatePayload },
      { method: 'GET', url: `/api/v1/wcb/batches/${PLACEHOLDER_UUID}` },
      { method: 'GET', url: `/api/v1/wcb/batches/${PLACEHOLDER_UUID}/download` },
      { method: 'POST', url: `/api/v1/wcb/batches/${PLACEHOLDER_UUID}/confirm-upload`, payload: validConfirmUploadPayload },
      { method: 'GET', url: '/api/v1/wcb/batches' },
      { method: 'POST', url: '/api/v1/wcb/returns/upload', payload: validReturnUploadPayload },
      { method: 'GET', url: `/api/v1/wcb/returns/${PLACEHOLDER_UUID}` },
      { method: 'POST', url: '/api/v1/wcb/remittances/upload', payload: validRemittanceUploadPayload },
      { method: 'GET', url: '/api/v1/wcb/remittances' },
      { method: 'GET', url: `/api/v1/wcb/remittances/${PLACEHOLDER_UUID}/discrepancies` },
      { method: 'GET', url: `/api/v1/wcb/claims/${PLACEHOLDER_UUID}/export` },
      { method: 'POST', url: `/api/v1/wcb/claims/${PLACEHOLDER_UUID}/manual-outcome`, payload: validManualOutcomePayload },
    ];

    for (const route of allRoutes) {
      it(`${route.method} ${route.url} — 403`, async () => {
        const res = await delegateNoneRequest(route.method, route.url, route.payload);
        assert403(res);
      });
    }
  });

  // =========================================================================
  // 13. Admin role — passes authorization on all routes
  // =========================================================================

  describe('Admin role — access control', () => {
    it('POST /api/v1/wcb/claims — admin passes authorization', async () => {
      const res = await adminRequest('POST', '/api/v1/wcb/claims', validCreateClaimPayload);
      assertNotForbidden(res);
    });

    it('GET /api/v1/wcb/claims/:id — admin passes authorization', async () => {
      const res = await adminRequest('GET', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}`);
      assertNotForbidden(res);
    });

    it('PUT /api/v1/wcb/claims/:id — admin passes authorization', async () => {
      const res = await adminRequest('PUT', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}`, validUpdateClaimPayload);
      assertNotForbidden(res);
    });

    it('DELETE /api/v1/wcb/claims/:id — admin passes authorization', async () => {
      const res = await adminRequest('DELETE', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}`);
      assertNotForbidden(res);
    });

    it('POST /api/v1/wcb/claims/:id/validate — admin passes authorization', async () => {
      const res = await adminRequest('POST', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}/validate`);
      assertNotForbidden(res);
    });

    it('GET /api/v1/wcb/claims/:id/form-schema — admin passes authorization', async () => {
      const res = await adminRequest('GET', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}/form-schema`);
      assertNotForbidden(res);
    });

    it('POST /api/v1/wcb/batches — admin passes authorization', async () => {
      const res = await adminRequest('POST', '/api/v1/wcb/batches', validBatchCreatePayload);
      assertNotForbidden(res);
    });

    it('GET /api/v1/wcb/batches/:id — admin passes authorization', async () => {
      const res = await adminRequest('GET', `/api/v1/wcb/batches/${PLACEHOLDER_UUID}`);
      assertNotForbidden(res);
    });

    it('GET /api/v1/wcb/batches/:id/download — admin passes authorization', async () => {
      const res = await adminRequest('GET', `/api/v1/wcb/batches/${PLACEHOLDER_UUID}/download`);
      assertNotForbidden(res);
    });

    it('POST /api/v1/wcb/batches/:id/confirm-upload — admin passes authorization', async () => {
      const res = await adminRequest('POST', `/api/v1/wcb/batches/${PLACEHOLDER_UUID}/confirm-upload`, validConfirmUploadPayload);
      assertNotForbidden(res);
    });

    it('GET /api/v1/wcb/batches — admin passes authorization', async () => {
      const res = await adminRequest('GET', '/api/v1/wcb/batches');
      assertNotForbidden(res);
    });

    it('POST /api/v1/wcb/returns/upload — admin passes authorization', async () => {
      const res = await adminRequest('POST', '/api/v1/wcb/returns/upload', validReturnUploadPayload);
      assertNotForbidden(res);
    });

    it('GET /api/v1/wcb/returns/:batch_id — admin passes authorization', async () => {
      const res = await adminRequest('GET', `/api/v1/wcb/returns/${PLACEHOLDER_UUID}`);
      assertNotForbidden(res);
    });

    it('POST /api/v1/wcb/remittances/upload — admin passes authorization', async () => {
      const res = await adminRequest('POST', '/api/v1/wcb/remittances/upload', validRemittanceUploadPayload);
      assertNotForbidden(res);
    });

    it('GET /api/v1/wcb/remittances — admin passes authorization', async () => {
      const res = await adminRequest('GET', '/api/v1/wcb/remittances');
      assertNotForbidden(res);
    });

    it('GET /api/v1/wcb/remittances/:id/discrepancies — admin passes authorization', async () => {
      const res = await adminRequest('GET', `/api/v1/wcb/remittances/${PLACEHOLDER_UUID}/discrepancies`);
      assertNotForbidden(res);
    });

    it('GET /api/v1/wcb/claims/:id/export — admin passes authorization', async () => {
      const res = await adminRequest('GET', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}/export`);
      assertNotForbidden(res);
    });

    it('POST /api/v1/wcb/claims/:id/manual-outcome — admin passes authorization', async () => {
      const res = await adminRequest('POST', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}/manual-outcome`, validManualOutcomePayload);
      assertNotForbidden(res);
    });
  });

  // =========================================================================
  // 14. 403 response shape — no data leakage on permission denial
  // =========================================================================

  describe('403 response shape — no data leakage', () => {
    it('403 response has consistent error shape with no data field', async () => {
      const res = await delegateNoneRequest('POST', '/api/v1/wcb/claims', validCreateClaimPayload);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('403 response does not contain internal identifiers', async () => {
      const res = await delegateNoneRequest('GET', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}`);
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
      const res = await delegateNoneRequest('PUT', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}`, validUpdateClaimPayload);
      expect(res.statusCode).toBe(403);
      const rawBody = res.body;
      expect(rawBody).not.toContain('handler');
      expect(rawBody).not.toContain('service');
      expect(rawBody).not.toContain('repository');
    });

    it('403 on batch creation does not leak batch existence', async () => {
      const res = await delegateViewRequest('POST', '/api/v1/wcb/batches', validBatchCreatePayload);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.message).not.toContain('batch');
    });

    it('403 on batch download does not leak batch existence', async () => {
      const res = await delegateBatchViewRequest('GET', `/api/v1/wcb/batches/${PLACEHOLDER_UUID}/download`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.message).not.toContain(PLACEHOLDER_UUID);
      expect(body.error.message).not.toContain('batch');
    });
  });

  // =========================================================================
  // 15. Permission escalation prevention
  // =========================================================================

  describe('Permission escalation prevention', () => {
    it('delegate with CLAIM_VIEW cannot access CLAIM_CREATE route by crafting request', async () => {
      const res = await delegateViewRequest('POST', '/api/v1/wcb/claims', validCreateClaimPayload);
      expect(res.statusCode).toBe(403);
    });

    it('delegate with CLAIM_VIEW cannot access CLAIM_EDIT route', async () => {
      const res = await delegateViewRequest('PUT', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}`, validUpdateClaimPayload);
      expect(res.statusCode).toBe(403);
    });

    it('delegate with CLAIM_VIEW cannot access CLAIM_DELETE route', async () => {
      const res = await delegateViewRequest('DELETE', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
    });

    it('delegate with CLAIM_CREATE cannot access CLAIM_EDIT routes', async () => {
      const res = await delegateCreateRequest('PUT', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}`, validUpdateClaimPayload);
      expect(res.statusCode).toBe(403);
    });

    it('delegate with BATCH_VIEW cannot escalate to BATCH_APPROVE', async () => {
      const res = await delegateBatchViewRequest('POST', '/api/v1/wcb/batches', validBatchCreatePayload);
      expect(res.statusCode).toBe(403);
    });

    it('delegate with BATCH_VIEW cannot escalate to WCB_BATCH_UPLOAD for download', async () => {
      const res = await delegateBatchViewRequest('GET', `/api/v1/wcb/batches/${PLACEHOLDER_UUID}/download`);
      expect(res.statusCode).toBe(403);
    });

    it('delegate with WCB_BATCH_UPLOAD cannot escalate to BATCH_VIEW for download', async () => {
      const res = await delegateUploadRequest('GET', `/api/v1/wcb/batches/${PLACEHOLDER_UUID}/download`);
      expect(res.statusCode).toBe(403);
    });

    it('delegate with REPORT_VIEW cannot access any claim or batch route', async () => {
      const claimBatchRoutes = [
        { method: 'POST' as const, url: '/api/v1/wcb/claims', payload: validCreateClaimPayload },
        { method: 'GET' as const, url: `/api/v1/wcb/claims/${PLACEHOLDER_UUID}` },
        { method: 'PUT' as const, url: `/api/v1/wcb/claims/${PLACEHOLDER_UUID}`, payload: validUpdateClaimPayload },
        { method: 'DELETE' as const, url: `/api/v1/wcb/claims/${PLACEHOLDER_UUID}` },
        { method: 'POST' as const, url: '/api/v1/wcb/batches', payload: validBatchCreatePayload },
        { method: 'GET' as const, url: `/api/v1/wcb/batches/${PLACEHOLDER_UUID}` },
        { method: 'GET' as const, url: '/api/v1/wcb/batches' },
      ];

      for (const route of claimBatchRoutes) {
        const res = await delegateReportRequest(route.method, route.url, route.payload);
        expect(res.statusCode).toBe(403);
      }
    });

    it('delegate with no relevant permissions cannot access any WCB route', async () => {
      const allRoutes = [
        { method: 'POST' as const, url: '/api/v1/wcb/claims', payload: validCreateClaimPayload },
        { method: 'GET' as const, url: `/api/v1/wcb/claims/${PLACEHOLDER_UUID}` },
        { method: 'PUT' as const, url: `/api/v1/wcb/claims/${PLACEHOLDER_UUID}`, payload: validUpdateClaimPayload },
        { method: 'DELETE' as const, url: `/api/v1/wcb/claims/${PLACEHOLDER_UUID}` },
        { method: 'POST' as const, url: `/api/v1/wcb/claims/${PLACEHOLDER_UUID}/validate` },
        { method: 'GET' as const, url: `/api/v1/wcb/claims/${PLACEHOLDER_UUID}/form-schema` },
        { method: 'POST' as const, url: '/api/v1/wcb/batches', payload: validBatchCreatePayload },
        { method: 'GET' as const, url: `/api/v1/wcb/batches/${PLACEHOLDER_UUID}` },
        { method: 'GET' as const, url: `/api/v1/wcb/batches/${PLACEHOLDER_UUID}/download` },
        { method: 'POST' as const, url: `/api/v1/wcb/batches/${PLACEHOLDER_UUID}/confirm-upload`, payload: validConfirmUploadPayload },
        { method: 'GET' as const, url: '/api/v1/wcb/batches' },
        { method: 'POST' as const, url: '/api/v1/wcb/returns/upload', payload: validReturnUploadPayload },
        { method: 'GET' as const, url: `/api/v1/wcb/returns/${PLACEHOLDER_UUID}` },
        { method: 'POST' as const, url: '/api/v1/wcb/remittances/upload', payload: validRemittanceUploadPayload },
        { method: 'GET' as const, url: '/api/v1/wcb/remittances' },
        { method: 'GET' as const, url: `/api/v1/wcb/remittances/${PLACEHOLDER_UUID}/discrepancies` },
        { method: 'GET' as const, url: `/api/v1/wcb/claims/${PLACEHOLDER_UUID}/export` },
        { method: 'POST' as const, url: `/api/v1/wcb/claims/${PLACEHOLDER_UUID}/manual-outcome`, payload: validManualOutcomePayload },
      ];

      for (const route of allRoutes) {
        const res = await delegateNoneRequest(route.method, route.url, route.payload);
        expect(res.statusCode).toBe(403);
      }
    });
  });
});
