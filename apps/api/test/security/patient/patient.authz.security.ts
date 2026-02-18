import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

// ---------------------------------------------------------------------------
// Environment setup (must be before imports that read env)
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);
process.env.INTERNAL_API_KEY = 'test-internal-api-key-32chars-ok';

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
import { patientRoutes, internalPatientRoutes } from '../../../src/domains/patient/patient.routes.js';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { type PatientServiceDeps } from '../../../src/domains/patient/patient.service.js';
import {
  type PatientHandlerDeps,
  type InternalPatientHandlerDeps,
} from '../../../src/domains/patient/patient.handlers.js';
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

// Delegate with PATIENT_VIEW only
const DELEGATE_VIEW_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_VIEW_SESSION_TOKEN_HASH = hashToken(DELEGATE_VIEW_SESSION_TOKEN);
const DELEGATE_VIEW_USER_ID = '22222222-0000-0000-0000-000000000002';
const DELEGATE_VIEW_SESSION_ID = '22222222-0000-0000-0000-000000000022';

// Delegate with PATIENT_CREATE only
const DELEGATE_CREATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_CREATE_SESSION_TOKEN_HASH = hashToken(DELEGATE_CREATE_SESSION_TOKEN);
const DELEGATE_CREATE_USER_ID = '33333333-0000-0000-0000-000000000003';
const DELEGATE_CREATE_SESSION_ID = '33333333-0000-0000-0000-000000000033';

// Delegate with no patient permissions (only CLAIM_VIEW)
const DELEGATE_NONE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_NONE_SESSION_TOKEN_HASH = hashToken(DELEGATE_NONE_SESSION_TOKEN);
const DELEGATE_NONE_USER_ID = '44444444-0000-0000-0000-000000000004';
const DELEGATE_NONE_SESSION_ID = '44444444-0000-0000-0000-000000000044';

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
// Mock patient repository (stubs — not exercised in authz tests)
// ---------------------------------------------------------------------------

function createStubPatientRepo() {
  return {
    createPatient: vi.fn(async () => ({})),
    findPatientById: vi.fn(async () => undefined),
    findPatientByPhn: vi.fn(async () => undefined),
    updatePatient: vi.fn(async () => ({})),
    deactivatePatient: vi.fn(async () => ({})),
    reactivatePatient: vi.fn(async () => ({})),
    updateLastVisitDate: vi.fn(async () => ({})),
    searchByPhn: vi.fn(async () => undefined),
    searchByName: vi.fn(async () => ({ data: [], pagination: { total: 0, page: 1, pageSize: 20, hasMore: false } })),
    searchByDob: vi.fn(async () => ({ data: [], pagination: { total: 0, page: 1, pageSize: 20, hasMore: false } })),
    searchCombined: vi.fn(async () => ({ data: [], pagination: { total: 0, page: 1, pageSize: 20, hasMore: false } })),
    getRecentPatients: vi.fn(async () => []),
    createImportBatch: vi.fn(async () => ({})),
    findImportBatchById: vi.fn(async () => undefined),
    findImportByFileHash: vi.fn(async () => undefined),
    updateImportStatus: vi.fn(async () => ({})),
    listImportBatches: vi.fn(async () => ({ data: [], pagination: { total: 0, page: 1, pageSize: 20, hasMore: false } })),
    bulkCreatePatients: vi.fn(async () => []),
    bulkUpsertPatients: vi.fn(async () => ({ created: 0, updated: 0 })),
    getMergePreview: vi.fn(async () => null),
    executeMerge: vi.fn(async () => null),
    listMergeHistory: vi.fn(async () => ({ data: [], pagination: { total: 0, page: 1, pageSize: 20, hasMore: false } })),
    exportActivePatients: vi.fn(async () => []),
    countActivePatients: vi.fn(async () => 0),
    getPatientClaimContext: vi.fn(async () => null),
    validatePhnExists: vi.fn(async () => ({ valid: false, exists: false })),
  };
}

function createStubServiceDeps(): PatientServiceDeps {
  return {
    repo: createStubPatientRepo() as any,
    auditRepo: createMockAuditRepo(),
    events: createMockEvents(),
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

  const serviceDeps = createStubServiceDeps();

  const handlerDeps: PatientHandlerDeps = {
    serviceDeps,
  };

  const internalHandlerDeps: InternalPatientHandlerDeps = {
    serviceDeps,
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

  await testApp.register(patientRoutes, { deps: handlerDeps });
  await testApp.register(internalPatientRoutes, { deps: internalHandlerDeps });
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

  // Delegate user with PATIENT_VIEW only
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
      permissions: ['PATIENT_VIEW'],
      linkageId: '55555555-0000-0000-0000-000000000055',
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

  // Delegate user with PATIENT_CREATE only
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
      permissions: ['PATIENT_CREATE'],
      linkageId: '66666666-0000-0000-0000-000000000066',
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

  // Delegate user with no patient permissions (only CLAIM_VIEW)
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
      permissions: ['CLAIM_VIEW'],
      linkageId: '77777777-0000-0000-0000-000000000077',
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

const validCreatePatient = {
  first_name: 'John',
  last_name: 'Doe',
  date_of_birth: '1990-01-01',
  gender: 'M',
};

const validUpdatePatient = {
  first_name: 'Updated',
};

const validMergePreview = {
  surviving_id: '00000000-0000-0000-0000-000000000002',
  merged_id: '00000000-0000-0000-0000-000000000003',
};

const validMergeExecute = {
  surviving_id: '00000000-0000-0000-0000-000000000002',
  merged_id: '00000000-0000-0000-0000-000000000003',
};

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Patient Authorization & Role Enforcement (Security)', () => {
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
  // 1. Delegate with PATIENT_VIEW only
  // =========================================================================

  describe('Delegate with PATIENT_VIEW only', () => {
    it('GET /api/v1/patients/:id — allowed (200 or non-403)', async () => {
      const res = await delegateViewRequest('GET', `/api/v1/patients/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/patients/search — allowed (200 or non-403)', async () => {
      const res = await delegateViewRequest('GET', '/api/v1/patients/search');
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/patients/recent — allowed (200 or non-403)', async () => {
      const res = await delegateViewRequest('GET', '/api/v1/patients/recent');
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/patients — 403 (requires PATIENT_CREATE)', async () => {
      const res = await delegateViewRequest('POST', '/api/v1/patients', validCreatePatient);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('PUT /api/v1/patients/:id — 403 (requires PATIENT_EDIT)', async () => {
      const res = await delegateViewRequest('PUT', `/api/v1/patients/${PLACEHOLDER_UUID}`, validUpdatePatient);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/patients/:id/deactivate — 403 (requires PATIENT_EDIT)', async () => {
      const res = await delegateViewRequest('POST', `/api/v1/patients/${PLACEHOLDER_UUID}/deactivate`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/patients/:id/reactivate — 403 (requires PATIENT_EDIT)', async () => {
      const res = await delegateViewRequest('POST', `/api/v1/patients/${PLACEHOLDER_UUID}/reactivate`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/patients/imports — 403 (requires PATIENT_IMPORT)', async () => {
      const res = await delegateViewRequest('POST', '/api/v1/patients/imports');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/patients/imports/:id/preview — 403 (requires PATIENT_IMPORT)', async () => {
      const res = await delegateViewRequest('GET', `/api/v1/patients/imports/${PLACEHOLDER_UUID}/preview`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('PUT /api/v1/patients/imports/:id/mapping — 403 (requires PATIENT_IMPORT)', async () => {
      const res = await delegateViewRequest('PUT', `/api/v1/patients/imports/${PLACEHOLDER_UUID}/mapping`, {
        mapping: { first_name: 'First Name' },
      });
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/patients/imports/:id/commit — 403 (requires PATIENT_IMPORT)', async () => {
      const res = await delegateViewRequest('POST', `/api/v1/patients/imports/${PLACEHOLDER_UUID}/commit`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/patients/imports/:id — 403 (requires PATIENT_IMPORT)', async () => {
      const res = await delegateViewRequest('GET', `/api/v1/patients/imports/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/patients/merge/preview — 403 (requires PATIENT_EDIT)', async () => {
      const res = await delegateViewRequest('POST', '/api/v1/patients/merge/preview', validMergePreview);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/patients/merge/execute — 403 (requires PATIENT_EDIT)', async () => {
      const res = await delegateViewRequest('POST', '/api/v1/patients/merge/execute', validMergeExecute);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/patients/exports — 403 (requires PATIENT_VIEW AND REPORT_EXPORT)', async () => {
      const res = await delegateViewRequest('POST', '/api/v1/patients/exports');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/patients/exports/:id — 403 (requires PATIENT_VIEW AND REPORT_EXPORT)', async () => {
      const res = await delegateViewRequest('GET', `/api/v1/patients/exports/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });
  });

  // =========================================================================
  // 2. Delegate with PATIENT_CREATE only
  // =========================================================================

  describe('Delegate with PATIENT_CREATE only', () => {
    it('POST /api/v1/patients — allowed (has PATIENT_CREATE)', async () => {
      const res = await delegateCreateRequest('POST', '/api/v1/patients', validCreatePatient);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/patients/:id — 403 (requires PATIENT_VIEW)', async () => {
      const res = await delegateCreateRequest('GET', `/api/v1/patients/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/patients/search — 403 (requires PATIENT_VIEW)', async () => {
      const res = await delegateCreateRequest('GET', '/api/v1/patients/search');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/patients/recent — 403 (requires PATIENT_VIEW)', async () => {
      const res = await delegateCreateRequest('GET', '/api/v1/patients/recent');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('PUT /api/v1/patients/:id — 403 (requires PATIENT_EDIT)', async () => {
      const res = await delegateCreateRequest('PUT', `/api/v1/patients/${PLACEHOLDER_UUID}`, validUpdatePatient);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/patients/:id/deactivate — 403 (requires PATIENT_EDIT)', async () => {
      const res = await delegateCreateRequest('POST', `/api/v1/patients/${PLACEHOLDER_UUID}/deactivate`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/patients/merge/execute — 403 (requires PATIENT_EDIT)', async () => {
      const res = await delegateCreateRequest('POST', '/api/v1/patients/merge/execute', validMergeExecute);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/patients/imports — 403 (requires PATIENT_IMPORT)', async () => {
      const res = await delegateCreateRequest('POST', '/api/v1/patients/imports');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/patients/exports — 403 (requires PATIENT_VIEW or REPORT_EXPORT)', async () => {
      const res = await delegateCreateRequest('POST', '/api/v1/patients/exports');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });
  });

  // =========================================================================
  // 3. Delegate with no patient permissions (only CLAIM_VIEW)
  // =========================================================================

  describe('Delegate with no patient permissions', () => {
    it('GET /api/v1/patients/:id — 403', async () => {
      const res = await delegateNoneRequest('GET', `/api/v1/patients/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/patients/search — 403', async () => {
      const res = await delegateNoneRequest('GET', '/api/v1/patients/search');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/patients/recent — 403', async () => {
      const res = await delegateNoneRequest('GET', '/api/v1/patients/recent');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/patients — 403', async () => {
      const res = await delegateNoneRequest('POST', '/api/v1/patients', validCreatePatient);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('PUT /api/v1/patients/:id — 403', async () => {
      const res = await delegateNoneRequest('PUT', `/api/v1/patients/${PLACEHOLDER_UUID}`, validUpdatePatient);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/patients/:id/deactivate — 403', async () => {
      const res = await delegateNoneRequest('POST', `/api/v1/patients/${PLACEHOLDER_UUID}/deactivate`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/patients/:id/reactivate — 403', async () => {
      const res = await delegateNoneRequest('POST', `/api/v1/patients/${PLACEHOLDER_UUID}/reactivate`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/patients/merge/preview — 403', async () => {
      const res = await delegateNoneRequest('POST', '/api/v1/patients/merge/preview', validMergePreview);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/patients/merge/execute — 403', async () => {
      const res = await delegateNoneRequest('POST', '/api/v1/patients/merge/execute', validMergeExecute);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/patients/exports — 403', async () => {
      const res = await delegateNoneRequest('POST', '/api/v1/patients/exports');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/patients/exports/:id — 403', async () => {
      const res = await delegateNoneRequest('GET', `/api/v1/patients/exports/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/patients/imports — 403', async () => {
      const res = await delegateNoneRequest('POST', '/api/v1/patients/imports');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/patients/imports/:id/preview — 403', async () => {
      const res = await delegateNoneRequest('GET', `/api/v1/patients/imports/${PLACEHOLDER_UUID}/preview`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('PUT /api/v1/patients/imports/:id/mapping — 403', async () => {
      const res = await delegateNoneRequest('PUT', `/api/v1/patients/imports/${PLACEHOLDER_UUID}/mapping`, {
        mapping: { first_name: 'First Name' },
      });
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/patients/imports/:id/commit — 403', async () => {
      const res = await delegateNoneRequest('POST', `/api/v1/patients/imports/${PLACEHOLDER_UUID}/commit`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/patients/imports/:id — 403', async () => {
      const res = await delegateNoneRequest('GET', `/api/v1/patients/imports/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });
  });

  // =========================================================================
  // 4. Internal API access control
  // =========================================================================

  describe('Internal API access control', () => {
    it('GET /api/v1/internal/patients/:id/claim-context without API key returns 401', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/internal/patients/${PLACEHOLDER_UUID}/claim-context?physician_id=${PHYSICIAN_USER_ID}`,
      });
      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('UNAUTHORIZED');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/internal/patients/validate-phn/:phn without API key returns 401', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/internal/patients/validate-phn/123456789?physician_id=${PHYSICIAN_USER_ID}`,
      });
      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('UNAUTHORIZED');
      expect(body.data).toBeUndefined();
    });

    it('regular physician session cannot access internal claim-context route', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/internal/patients/${PLACEHOLDER_UUID}/claim-context?physician_id=${PHYSICIAN_USER_ID}`,
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });
      // Internal routes use API key auth, not session auth — session cookie is irrelevant
      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();
    });

    it('regular physician session cannot access internal validate-phn route', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/internal/patients/validate-phn/123456789?physician_id=${PHYSICIAN_USER_ID}`,
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });
      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();
    });

    it('invalid API key is rejected for internal routes', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/internal/patients/${PLACEHOLDER_UUID}/claim-context?physician_id=${PHYSICIAN_USER_ID}`,
        headers: { 'x-internal-api-key': 'wrong-key-not-matching-at-all!!' },
      });
      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('UNAUTHORIZED');
      expect(body.data).toBeUndefined();
    });

    it('delegate session cannot access internal routes', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/internal/patients/${PLACEHOLDER_UUID}/claim-context?physician_id=${PHYSICIAN_USER_ID}`,
        headers: { cookie: `session=${DELEGATE_VIEW_SESSION_TOKEN}` },
      });
      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();
    });
  });

  // =========================================================================
  // 5. 403 responses do not leak patient data
  // =========================================================================

  describe('403 responses do not leak patient data', () => {
    it('403 on PATIENT_CREATE route does not contain PHI', async () => {
      const res = await delegateViewRequest('POST', '/api/v1/patients', validCreatePatient);
      expect(res.statusCode).toBe(403);
      const rawBody = res.body;
      expect(rawBody).not.toContain('patient_id');
      expect(rawBody).not.toContain(PHYSICIAN_USER_ID);
      expect(rawBody).not.toContain('phn');
      expect(rawBody).not.toContain('first_name');
      expect(rawBody).not.toContain('John');
    });

    it('403 on PATIENT_EDIT route does not contain PHI', async () => {
      const res = await delegateViewRequest('PUT', `/api/v1/patients/${PLACEHOLDER_UUID}`, validUpdatePatient);
      expect(res.statusCode).toBe(403);
      const rawBody = res.body;
      expect(rawBody).not.toContain('patient_id');
      expect(rawBody).not.toContain(PHYSICIAN_USER_ID);
      expect(rawBody).not.toContain('Updated');
    });

    it('403 response has consistent error shape with no extra fields', async () => {
      const res = await delegateNoneRequest('GET', `/api/v1/patients/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
      expect(Object.keys(body.error).sort()).toEqual(['code', 'message']);
    });

    it('403 response does not contain stack traces or internals', async () => {
      const res = await delegateNoneRequest('POST', '/api/v1/patients', validCreatePatient);
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
  // 6. Sanity: physician can access all patient routes (not 403)
  // =========================================================================

  describe('Sanity: physician can access all patient routes', () => {
    it('POST /api/v1/patients — physician is not 403', async () => {
      const res = await physicianRequest('POST', '/api/v1/patients', validCreatePatient);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/patients/:id — physician is not 403', async () => {
      const res = await physicianRequest('GET', `/api/v1/patients/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('PUT /api/v1/patients/:id — physician is not 403', async () => {
      const res = await physicianRequest('PUT', `/api/v1/patients/${PLACEHOLDER_UUID}`, validUpdatePatient);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/patients/search — physician is not 403', async () => {
      const res = await physicianRequest('GET', '/api/v1/patients/search');
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/patients/recent — physician is not 403', async () => {
      const res = await physicianRequest('GET', '/api/v1/patients/recent');
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/patients/:id/deactivate — physician is not 403', async () => {
      const res = await physicianRequest('POST', `/api/v1/patients/${PLACEHOLDER_UUID}/deactivate`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/patients/:id/reactivate — physician is not 403', async () => {
      const res = await physicianRequest('POST', `/api/v1/patients/${PLACEHOLDER_UUID}/reactivate`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/patients/merge/preview — physician is not 403', async () => {
      const res = await physicianRequest('POST', '/api/v1/patients/merge/preview', validMergePreview);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/patients/merge/execute — physician is not 403', async () => {
      const res = await physicianRequest('POST', '/api/v1/patients/merge/execute', validMergeExecute);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/patients/exports — physician is not 403', async () => {
      const res = await physicianRequest('POST', '/api/v1/patients/exports');
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/patients/exports/:id — physician is not 403', async () => {
      const res = await physicianRequest('GET', `/api/v1/patients/exports/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/patients/imports — physician is not 403', async () => {
      const res = await physicianRequest('POST', '/api/v1/patients/imports');
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });
  });
});
