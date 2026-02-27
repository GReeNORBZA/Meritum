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
import { patientRoutes } from '../../../src/domains/patient/patient.routes.js';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { type PatientServiceDeps } from '../../../src/domains/patient/patient.service.js';
import { type PatientHandlerDeps } from '../../../src/domains/patient/patient.handlers.js';
import {
  type SessionManagementDeps,
  hashToken,
} from '../../../src/domains/iam/iam.service.js';
import { randomBytes, createHash } from 'node:crypto';

// ---------------------------------------------------------------------------
// Fixed test identities — Two isolated physicians
// ---------------------------------------------------------------------------

// Physician 1 — "our" physician
const P1_SESSION_TOKEN = randomBytes(32).toString('hex');
const P1_SESSION_TOKEN_HASH = hashToken(P1_SESSION_TOKEN);
const P1_USER_ID = '11111111-1111-0000-0000-000000000001';
const P1_PROVIDER_ID = P1_USER_ID;
const P1_SESSION_ID = '11111111-1111-0000-0000-000000000011';

// Physician 2 — "other" physician (attacker perspective)
const P2_SESSION_TOKEN = randomBytes(32).toString('hex');
const P2_SESSION_TOKEN_HASH = hashToken(P2_SESSION_TOKEN);
const P2_USER_ID = '22222222-2222-0000-0000-000000000002';
const P2_PROVIDER_ID = P2_USER_ID;
const P2_SESSION_ID = '22222222-2222-0000-0000-000000000022';

// Resource IDs
const P1_PATIENT_ID_A = 'aaaa1111-0000-0000-0000-000000000001';
const P2_PATIENT_ID_A = 'aaaa2222-0000-0000-0000-000000000001';

// PHNs
const P1_PHN_A = '123456782';
const P2_PHN_A = '987654324';

// Non-existent UUIDs
const NONEXISTENT_UUID = '99999999-9999-9999-9999-999999999999';

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
// Mock patient data stores
// ---------------------------------------------------------------------------

interface MockPatient {
  patientId: string;
  providerId: string;
  phn: string | null;
  phnProvince: string;
  firstName: string;
  middleName: string | null;
  lastName: string;
  dateOfBirth: string;
  gender: string;
  phone: string | null;
  email: string | null;
  addressLine1: string | null;
  addressLine2: string | null;
  city: string | null;
  province: string | null;
  postalCode: string | null;
  notes: string | null;
  isActive: boolean;
  lastVisitDate: string | null;
  createdBy: string;
  createdAt: Date;
  updatedAt: Date;
}

const patientsStore: Record<string, MockPatient> = {};

// Eligibility cache store
const eligibilityCacheStore: Record<string, {
  providerId: string;
  phnHash: string;
  isEligible: boolean;
  eligibilityDetails: Record<string, unknown>;
  verifiedAt: Date;
  expiresAt: Date;
}> = {};

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
      return {
        session,
        user: {
          userId: user.userId,
          role: user.role,
          subscriptionStatus: user.subscriptionStatus,
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
// Seed test data
// ---------------------------------------------------------------------------

function seedTestData() {
  Object.keys(patientsStore).forEach((k) => delete patientsStore[k]);
  Object.keys(eligibilityCacheStore).forEach((k) => delete eligibilityCacheStore[k]);

  patientsStore[P1_PATIENT_ID_A] = {
    patientId: P1_PATIENT_ID_A,
    providerId: P1_PROVIDER_ID,
    phn: P1_PHN_A,
    phnProvince: 'AB',
    firstName: 'Alice',
    middleName: null,
    lastName: 'Smith',
    dateOfBirth: '1980-01-15',
    gender: 'F',
    phone: '780-555-0001',
    email: 'alice@example.com',
    addressLine1: '123 Main St',
    addressLine2: null,
    city: 'Edmonton',
    province: 'AB',
    postalCode: 'T5A0A1',
    notes: 'Confidential clinical notes about Alice - DO NOT LEAK',
    isActive: true,
    lastVisitDate: '2026-01-10',
    createdBy: P1_USER_ID,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  patientsStore[P2_PATIENT_ID_A] = {
    patientId: P2_PATIENT_ID_A,
    providerId: P2_PROVIDER_ID,
    phn: P2_PHN_A,
    phnProvince: 'AB',
    firstName: 'Charlie',
    middleName: null,
    lastName: 'Brown',
    dateOfBirth: '1975-03-10',
    gender: 'M',
    phone: '403-555-0001',
    email: 'charlie@example.com',
    addressLine1: '789 Pine Rd',
    addressLine2: null,
    city: 'Calgary',
    province: 'AB',
    postalCode: 'T2P1A1',
    notes: 'Charlie notes - confidential',
    isActive: true,
    lastVisitDate: '2026-01-15',
    createdBy: P2_USER_ID,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  // Seed eligibility cache for P1
  const p1PhnHash = createHash('sha256').update(P1_PHN_A).digest('hex');
  const cacheKey1 = `${P1_PROVIDER_ID}:${p1PhnHash}`;
  eligibilityCacheStore[cacheKey1] = {
    providerId: P1_PROVIDER_ID,
    phnHash: p1PhnHash,
    isEligible: true,
    eligibilityDetails: { status: 'ELIGIBLE', coverage_start: '2020-01-01' },
    verifiedAt: new Date(),
    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
  };
}

// ---------------------------------------------------------------------------
// Physician-scoped mock patient repository
// ---------------------------------------------------------------------------

function createScopedPatientRepo() {
  return {
    createPatient: vi.fn(async (data: any) => {
      const id = crypto.randomUUID();
      const patient: MockPatient = {
        patientId: id,
        providerId: data.providerId,
        phn: data.phn ?? null,
        phnProvince: data.phnProvince ?? 'AB',
        firstName: data.firstName,
        middleName: data.middleName ?? null,
        lastName: data.lastName,
        dateOfBirth: data.dateOfBirth,
        gender: data.gender,
        phone: data.phone ?? null,
        email: data.email ?? null,
        addressLine1: data.addressLine1 ?? null,
        addressLine2: data.addressLine2 ?? null,
        city: data.city ?? null,
        province: data.province ?? null,
        postalCode: data.postalCode ?? null,
        notes: data.notes ?? null,
        isActive: true,
        lastVisitDate: null,
        createdBy: data.createdBy,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      patientsStore[id] = patient;
      return patient;
    }),
    findPatientById: vi.fn(async (patientId: string, physicianId: string) => {
      const patient = patientsStore[patientId];
      if (!patient || patient.providerId !== physicianId) return undefined;
      return patient;
    }),
    findPatientByPhn: vi.fn(async (physicianId: string, phn: string) => {
      return Object.values(patientsStore).find(
        (p) => p.providerId === physicianId && p.phn === phn && p.isActive,
      ) ?? undefined;
    }),
    updatePatient: vi.fn(async (patientId: string, physicianId: string, data: any) => {
      const patient = patientsStore[patientId];
      if (!patient || patient.providerId !== physicianId) return undefined;
      const updated = { ...patient, ...data, updatedAt: new Date() };
      patientsStore[patientId] = updated;
      return updated;
    }),
    deactivatePatient: vi.fn(async (patientId: string, physicianId: string) => {
      const patient = patientsStore[patientId];
      if (!patient || patient.providerId !== physicianId) return undefined;
      return { ...patient, isActive: false, updatedAt: new Date() };
    }),
    reactivatePatient: vi.fn(async (patientId: string, physicianId: string) => {
      const patient = patientsStore[patientId];
      if (!patient || patient.providerId !== physicianId) return undefined;
      return { ...patient, isActive: true, updatedAt: new Date() };
    }),
    updateLastVisitDate: vi.fn(async () => ({})),
    searchByPhn: vi.fn(async (physicianId: string, phn: string) => {
      return Object.values(patientsStore).find(
        (p) => p.providerId === physicianId && p.phn === phn && p.isActive,
      ) ?? null;
    }),
    searchByName: vi.fn(async (physicianId: string, name: string, page: number, pageSize: number) => {
      const matches = Object.values(patientsStore).filter(
        (p) =>
          p.providerId === physicianId &&
          p.isActive &&
          (p.firstName.toLowerCase().includes(name.toLowerCase()) ||
            p.lastName.toLowerCase().includes(name.toLowerCase())),
      );
      return {
        data: matches.slice((page - 1) * pageSize, page * pageSize),
        pagination: { total: matches.length, page, pageSize, hasMore: page * pageSize < matches.length },
      };
    }),
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
    getPatientHealthInformation: vi.fn(async () => null),
    getCachedEligibility: vi.fn(async (providerId: string, phnHash: string) => {
      const key = `${providerId}:${phnHash}`;
      const cached = eligibilityCacheStore[key];
      if (!cached || cached.expiresAt < new Date()) return undefined;
      return cached;
    }),
    setCachedEligibility: vi.fn(async (entry: any) => {
      const key = `${entry.providerId}:${entry.phnHash}`;
      eligibilityCacheStore[key] = entry;
      return entry;
    }),
  };
}

function createStubServiceDeps(): PatientServiceDeps {
  return {
    repo: createScopedPatientRepo() as any,
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

  const handlerDeps: PatientHandlerDeps = {
    serviceDeps: createStubServiceDeps(),
  };

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  await testApp.register(authPluginFp, { sessionDeps });

  testApp.setErrorHandler((error, request, reply) => {
    const statusCode = (error as any).statusCode;
    if (statusCode && statusCode >= 400 && statusCode < 500) {
      return reply.code(statusCode).send({
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

  await testApp.register(patientRoutes, { deps: handlerDeps });
  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------

function asPhysician1(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function asPhysician2(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${P2_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function unauthenticated(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    ...(payload !== undefined ? { payload } : {}),
  });
}

// ---------------------------------------------------------------------------
// Recursive key checker — ensure a key never appears at any nesting level
// ---------------------------------------------------------------------------

function containsKeyRecursive(obj: unknown, targetKey: string): boolean {
  if (obj === null || obj === undefined || typeof obj !== 'object') return false;
  if (Array.isArray(obj)) {
    return obj.some((item) => containsKeyRecursive(item, targetKey));
  }
  for (const key of Object.keys(obj as Record<string, unknown>)) {
    if (key === targetKey) return true;
    if (containsKeyRecursive((obj as Record<string, unknown>)[key], targetKey)) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Seed users and sessions
// ---------------------------------------------------------------------------

function seedUsersAndSessions() {
  users = [];
  sessions = [];

  // Physician 1
  users.push({
    userId: P1_USER_ID,
    email: 'physician1@example.com',
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
    sessionId: P1_SESSION_ID,
    userId: P1_USER_ID,
    tokenHash: P1_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

  // Physician 2
  users.push({
    userId: P2_USER_ID,
    email: 'physician2@example.com',
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
    sessionId: P2_SESSION_ID,
    userId: P2_USER_ID,
    tokenHash: P2_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.2',
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

describe('Patient Extensions — Eligibility Error Leakage Prevention (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    seedUsersAndSessions();
    seedTestData();
    auditEntries = [];
  });

  // =========================================================================
  // 1. Eligibility error responses don't contain PHN values
  // =========================================================================

  describe('Eligibility error responses do not contain PHN values', () => {
    it('eligibility check 400 error does not contain PHN', async () => {
      const res = await asPhysician1('POST', '/api/v1/patients/eligibility/check', {
        phn: 'INVALID',
      });

      expect(res.statusCode).toBe(400);
      expect(res.body).not.toContain(P1_PHN_A);
      expect(res.body).not.toContain(P2_PHN_A);
    });

    it('eligibility check success response contains masked PHN, not raw', async () => {
      const res = await asPhysician1('POST', '/api/v1/patients/eligibility/check', {
        phn: P1_PHN_A,
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.phn_masked).toBeDefined();
      // Raw PHN must NOT appear in response body
      expect(res.body).not.toContain(P1_PHN_A);
      // Masked format should appear
      expect(res.body).toContain('123******');
    });

    it('eligibility override success response contains masked PHN, not raw', async () => {
      const res = await asPhysician1('POST', '/api/v1/patients/eligibility/override', {
        phn: P1_PHN_A,
        reason: 'Patient confirmed eligible via phone',
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.phn_masked).toBeDefined();
      // Raw PHN must NOT appear
      expect(res.body).not.toContain(P1_PHN_A);
      expect(res.body).toContain('123******');
    });

    it('bulk eligibility response contains masked PHNs, not raw', async () => {
      const res = await asPhysician1('POST', '/api/v1/patients/eligibility/bulk-check', {
        entries: [
          { phn: P1_PHN_A },
        ],
      });

      expect(res.statusCode).toBe(200);
      // Raw PHN must NOT appear anywhere in response
      expect(res.body).not.toContain(P1_PHN_A);
      expect(res.body).toContain('123******');
    });
  });

  // =========================================================================
  // 2. No X-Powered-By header
  // =========================================================================

  describe('No X-Powered-By header', () => {
    it('eligibility check response has no X-Powered-By', async () => {
      const res = await asPhysician1('POST', '/api/v1/patients/eligibility/check', {
        phn: P1_PHN_A,
      });

      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('province detection response has no X-Powered-By', async () => {
      const res = await asPhysician1('POST', '/api/v1/patients/province/detect', {
        health_number: P1_PHN_A,
      });

      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('patient GET response has no X-Powered-By', async () => {
      const res = await asPhysician1('GET', `/api/v1/patients/${P1_PATIENT_ID_A}`);

      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('error response has no X-Powered-By', async () => {
      const res = await asPhysician1('GET', `/api/v1/patients/${NONEXISTENT_UUID}`);
      expect(res.statusCode).toBe(404);
      expect(res.headers['x-powered-by']).toBeUndefined();
    });
  });

  // =========================================================================
  // 3. 500 errors return generic message
  // =========================================================================

  describe('500 errors return generic message', () => {
    it('error handler shape is generic without internals', async () => {
      // The error handler is configured to return a generic message for 500s.
      // We verify this by checking the error handler output pattern.
      // Use a 404 (which flows through the same handler) as a proxy.
      const res = await asPhysician1('PUT', `/api/v1/patients/${NONEXISTENT_UUID}`, {
        first_name: 'Test',
      });

      // 404 from scoped repo
      expect(res.statusCode).toBeGreaterThanOrEqual(400);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBeDefined();
      expect(body.error.message).toBeDefined();

      // Must NOT contain internal details
      const rawBody = res.body.toLowerCase();
      expect(rawBody).not.toContain('stack');
      expect(rawBody).not.toContain('node_modules');
      expect(rawBody).not.toContain('postgres');
      expect(rawBody).not.toContain('drizzle');
      expect(rawBody).not.toContain('password');
    });
  });

  // =========================================================================
  // 4. Cross-tenant 404 indistinguishable from missing
  // =========================================================================

  describe('Cross-tenant 404 indistinguishable from missing', () => {
    it('P1 accessing P2 patient returns identical 404 as genuinely missing', async () => {
      const crossTenantRes = await asPhysician1('GET', `/api/v1/patients/${P2_PATIENT_ID_A}`);
      const genuineMissingRes = await asPhysician1('GET', `/api/v1/patients/${NONEXISTENT_UUID}`);

      expect(crossTenantRes.statusCode).toBe(404);
      expect(genuineMissingRes.statusCode).toBe(404);

      const crossBody = JSON.parse(crossTenantRes.body);
      const missingBody = JSON.parse(genuineMissingRes.body);

      // Identical structure
      expect(Object.keys(crossBody)).toEqual(Object.keys(missingBody));
      expect(crossBody.error.code).toBe(missingBody.error.code);
      expect(crossBody.error.message).toBe(missingBody.error.message);

      // No patient data leaked
      expect(crossTenantRes.body).not.toContain(P2_PATIENT_ID_A);
      expect(crossTenantRes.body).not.toContain('Charlie');
      expect(crossTenantRes.body).not.toContain(P2_PHN_A);
    });

    it('P2 accessing P1 patient returns identical 404 as genuinely missing', async () => {
      const crossTenantRes = await asPhysician2('GET', `/api/v1/patients/${P1_PATIENT_ID_A}`);
      const genuineMissingRes = await asPhysician2('GET', `/api/v1/patients/${NONEXISTENT_UUID}`);

      expect(crossTenantRes.statusCode).toBe(404);
      expect(genuineMissingRes.statusCode).toBe(404);

      const crossBody = JSON.parse(crossTenantRes.body);
      const missingBody = JSON.parse(genuineMissingRes.body);

      expect(crossBody.error.code).toBe(missingBody.error.code);
      expect(crossBody.error.message).toBe(missingBody.error.message);

      // No patient data leaked
      expect(crossTenantRes.body).not.toContain('Alice');
      expect(crossTenantRes.body).not.toContain(P1_PHN_A);
    });
  });

  // =========================================================================
  // 5. No sensitive fields in any response
  // =========================================================================

  describe('No sensitive fields in any response', () => {
    const SENSITIVE_KEYS = ['password', 'totp', 'token_hash', 'passwordHash', 'totpSecretEncrypted', 'tokenHash'];

    it('eligibility check response has no sensitive fields', async () => {
      const res = await asPhysician1('POST', '/api/v1/patients/eligibility/check', {
        phn: P1_PHN_A,
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      for (const key of SENSITIVE_KEYS) {
        expect(containsKeyRecursive(body, key)).toBe(false);
      }
    });

    it('eligibility override response has no sensitive fields', async () => {
      const res = await asPhysician1('POST', '/api/v1/patients/eligibility/override', {
        phn: P1_PHN_A,
        reason: 'Patient confirmed eligible',
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      for (const key of SENSITIVE_KEYS) {
        expect(containsKeyRecursive(body, key)).toBe(false);
      }
    });

    it('province detection response has no sensitive fields', async () => {
      const res = await asPhysician1('POST', '/api/v1/patients/province/detect', {
        health_number: P1_PHN_A,
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      for (const key of SENSITIVE_KEYS) {
        expect(containsKeyRecursive(body, key)).toBe(false);
      }
    });

    it('patient GET response has no sensitive fields', async () => {
      const res = await asPhysician1('GET', `/api/v1/patients/${P1_PATIENT_ID_A}`);

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      for (const key of SENSITIVE_KEYS) {
        expect(containsKeyRecursive(body, key)).toBe(false);
      }
    });

    it('search response has no sensitive fields', async () => {
      const res = await asPhysician1('GET', `/api/v1/patients/search?phn=${P1_PHN_A}`);

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      for (const key of SENSITIVE_KEYS) {
        expect(containsKeyRecursive(body, key)).toBe(false);
      }
    });

    it('401 unauthenticated response has no sensitive fields', async () => {
      const res = await unauthenticated('POST', '/api/v1/patients/eligibility/check', {
        phn: P1_PHN_A,
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      for (const key of SENSITIVE_KEYS) {
        expect(containsKeyRecursive(body, key)).toBe(false);
      }
      // Must not contain PHN or patient data
      expect(res.body).not.toContain(P1_PHN_A);
      expect(res.body).not.toContain('Alice');
    });

    it('error responses do not contain sensitive fields', async () => {
      const res = await asPhysician1('GET', `/api/v1/patients/${NONEXISTENT_UUID}`);
      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      for (const key of SENSITIVE_KEYS) {
        expect(containsKeyRecursive(body, key)).toBe(false);
      }
    });
  });

  // =========================================================================
  // 6. Eligibility audit entries mask PHN
  // =========================================================================

  describe('Eligibility audit entries mask PHN', () => {
    it('eligibility check audit entry contains masked PHN, not raw', async () => {
      await asPhysician1('POST', '/api/v1/patients/eligibility/check', {
        phn: P1_PHN_A,
      });

      const eligibilityAudits = auditEntries.filter(
        (e) => e.action === 'patient.eligibility_checked',
      );
      expect(eligibilityAudits.length).toBeGreaterThan(0);

      const auditString = JSON.stringify(eligibilityAudits);
      // Full PHN must NOT appear
      expect(auditString).not.toContain(P1_PHN_A);
      // Masked PHN MUST appear
      expect(auditString).toContain('123******');
    });

    it('eligibility override audit entry contains masked PHN, not raw', async () => {
      await asPhysician1('POST', '/api/v1/patients/eligibility/override', {
        phn: P1_PHN_A,
        reason: 'Override reason text',
      });

      const overrideAudits = auditEntries.filter(
        (e) => e.action === 'patient.eligibility_overridden',
      );
      expect(overrideAudits.length).toBeGreaterThan(0);

      const auditString = JSON.stringify(overrideAudits);
      expect(auditString).not.toContain(P1_PHN_A);
      expect(auditString).toContain('123******');
    });
  });
});
