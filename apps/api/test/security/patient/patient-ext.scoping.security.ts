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
const P1_PROVIDER_ID = P1_USER_ID; // 1:1 mapping
const P1_SESSION_ID = '11111111-1111-0000-0000-000000000011';

// Physician 2 — "other" physician (attacker perspective)
const P2_SESSION_TOKEN = randomBytes(32).toString('hex');
const P2_SESSION_TOKEN_HASH = hashToken(P2_SESSION_TOKEN);
const P2_USER_ID = '22222222-2222-0000-0000-000000000002';
const P2_PROVIDER_ID = P2_USER_ID;
const P2_SESSION_ID = '22222222-2222-0000-0000-000000000022';

// ---------------------------------------------------------------------------
// Test data IDs — resources owned by each physician
// ---------------------------------------------------------------------------

// Physician 1's patients
const P1_PATIENT_ID_A = 'aaaa1111-0000-0000-0000-000000000001';
const P1_PATIENT_PHN_A = '123456782'; // valid Luhn

// Physician 2's patients
const P2_PATIENT_ID_A = 'aaaa2222-0000-0000-0000-000000000001';
const P2_PATIENT_PHN_A = '987654324';

// Non-existent UUID
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

// ---------------------------------------------------------------------------
// Mock patient data stores (physician-scoped)
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

// Eligibility cache store (physician-scoped by providerId + phnHash)
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
    appendAuditLog: vi.fn(async () => {}),
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

  // --- Physician 1's patients ---
  patientsStore[P1_PATIENT_ID_A] = {
    patientId: P1_PATIENT_ID_A,
    providerId: P1_PROVIDER_ID,
    phn: P1_PATIENT_PHN_A,
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
    notes: null,
    isActive: true,
    lastVisitDate: '2026-01-10',
    createdBy: P1_USER_ID,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  // --- Physician 2's patients ---
  patientsStore[P2_PATIENT_ID_A] = {
    patientId: P2_PATIENT_ID_A,
    providerId: P2_PROVIDER_ID,
    phn: P2_PATIENT_PHN_A,
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
    notes: null,
    isActive: true,
    lastVisitDate: '2026-01-15',
    createdBy: P2_USER_ID,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  // Seed P1 eligibility cache for P1's patient PHN
  const p1PhnHash = createHash('sha256').update(P1_PATIENT_PHN_A).digest('hex');
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
      const deactivated = { ...patient, isActive: false, updatedAt: new Date() };
      patientsStore[patientId] = deactivated;
      return deactivated;
    }),
    reactivatePatient: vi.fn(async (patientId: string, physicianId: string) => {
      const patient = patientsStore[patientId];
      if (!patient || patient.providerId !== physicianId) return undefined;
      const reactivated = { ...patient, isActive: true, updatedAt: new Date() };
      patientsStore[patientId] = reactivated;
      return reactivated;
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
    searchByDob: vi.fn(async (physicianId: string, dob: Date, page: number, pageSize: number) => {
      const dobStr = dob.toISOString().split('T')[0];
      const matches = Object.values(patientsStore).filter(
        (p) => p.providerId === physicianId && p.isActive && p.dateOfBirth === dobStr,
      );
      return {
        data: matches.slice((page - 1) * pageSize, page * pageSize),
        pagination: { total: matches.length, page, pageSize, hasMore: page * pageSize < matches.length },
      };
    }),
    searchCombined: vi.fn(async (physicianId: string, _filters: any, page: number, pageSize: number) => {
      const matches = Object.values(patientsStore).filter(
        (p) => p.providerId === physicianId && p.isActive,
      );
      return {
        data: matches.slice((page - 1) * pageSize, page * pageSize),
        pagination: { total: matches.length, page, pageSize, hasMore: page * pageSize < matches.length },
      };
    }),
    getRecentPatients: vi.fn(async (physicianId: string, limit: number) => {
      return Object.values(patientsStore)
        .filter((p) => p.providerId === physicianId && p.isActive)
        .sort((a, b) => (b.lastVisitDate ?? '').localeCompare(a.lastVisitDate ?? ''))
        .slice(0, limit);
    }),
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

    // Eligibility cache — scoped to physician
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
        error: { code: 'VALIDATION_ERROR', message: 'Validation failed', details: error.validation },
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

describe('Patient Extensions — Cross-Provider Eligibility Cache Isolation (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    seedUsersAndSessions();
    seedTestData();
  });

  // =========================================================================
  // 1. Patient record isolation via GET /api/v1/patients/:id
  // =========================================================================

  describe('Patient record isolation — GET by ID', () => {
    it('physician1 can retrieve own patient via GET /api/v1/patients/:id', async () => {
      const res = await asPhysician1('GET', `/api/v1/patients/${P1_PATIENT_ID_A}`);
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.patientId).toBe(P1_PATIENT_ID_A);
      expect(body.data.providerId).toBe(P1_PROVIDER_ID);
    });

    it('physician2 CANNOT see physician1 patient — returns 404', async () => {
      const res = await asPhysician2('GET', `/api/v1/patients/${P1_PATIENT_ID_A}`);
      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();
    });

    it('physician1 CANNOT see physician2 patient — returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/patients/${P2_PATIENT_ID_A}`);
      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();
    });
  });

  // =========================================================================
  // 2. Cross-provider 404 is indistinguishable from genuinely missing
  // =========================================================================

  describe('Cross-provider 404 is indistinguishable from genuinely missing', () => {
    it('cross-tenant 404 has identical shape to genuinely missing 404', async () => {
      // P2 tries to access P1's patient (cross-tenant)
      const crossTenantRes = await asPhysician2('GET', `/api/v1/patients/${P1_PATIENT_ID_A}`);
      // P2 accesses a genuinely non-existent patient
      const genuineMissingRes = await asPhysician2('GET', `/api/v1/patients/${NONEXISTENT_UUID}`);

      expect(crossTenantRes.statusCode).toBe(404);
      expect(genuineMissingRes.statusCode).toBe(404);

      const crossBody = JSON.parse(crossTenantRes.body);
      const missingBody = JSON.parse(genuineMissingRes.body);

      // Same error structure — indistinguishable
      expect(Object.keys(crossBody)).toEqual(Object.keys(missingBody));
      expect(crossBody.error.code).toBe(missingBody.error.code);
      expect(crossBody.error.message).toBe(missingBody.error.message);
    });

    it('cross-tenant 404 does not leak any target patient details', async () => {
      const res = await asPhysician2('GET', `/api/v1/patients/${P1_PATIENT_ID_A}`);
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P1_PATIENT_ID_A);
      expect(rawBody).not.toContain(P1_PROVIDER_ID);
      expect(rawBody).not.toContain('Alice');
      expect(rawBody).not.toContain(P1_PATIENT_PHN_A);
      expect(rawBody).not.toContain('Edmonton');
    });
  });

  // =========================================================================
  // 3. Eligibility check scoped to authenticated provider's patients
  // =========================================================================

  describe('Eligibility check scoped to authenticated provider', () => {
    it('physician1 eligibility check for own patient PHN succeeds (cache hit)', async () => {
      const res = await asPhysician1('POST', '/api/v1/patients/eligibility/check', {
        phn: P1_PATIENT_PHN_A,
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toBeDefined();
      expect(body.data.is_eligible).toBe(true);
      expect(body.data.source).toBe('CACHE');
      // Response should contain masked PHN, not raw
      expect(body.data.phn_masked).toBeDefined();
      expect(res.body).not.toContain(P1_PATIENT_PHN_A);
    });

    it('physician2 eligibility check for physician1 patient PHN does NOT hit physician1 cache', async () => {
      // P2 checks eligibility for the same PHN — should NOT see P1's cached result
      const res = await asPhysician2('POST', '/api/v1/patients/eligibility/check', {
        phn: P1_PATIENT_PHN_A,
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toBeDefined();
      // Should come from HLINK (fresh), not from P1's cache
      expect(body.data.source).toBe('HLINK');
    });

    it('physician2 eligibility cache is isolated from physician1 cache', async () => {
      // P2 performs a check — this creates a cache entry scoped to P2
      await asPhysician2('POST', '/api/v1/patients/eligibility/check', {
        phn: P1_PATIENT_PHN_A,
      });

      // Verify P2's cache entry exists under P2's provider scope
      const phnHash = createHash('sha256').update(P1_PATIENT_PHN_A).digest('hex');
      const p2CacheKey = `${P2_PROVIDER_ID}:${phnHash}`;
      const p1CacheKey = `${P1_PROVIDER_ID}:${phnHash}`;

      expect(eligibilityCacheStore[p2CacheKey]).toBeDefined();
      expect(eligibilityCacheStore[p1CacheKey]).toBeDefined();
      expect(eligibilityCacheStore[p2CacheKey]!.providerId).toBe(P2_PROVIDER_ID);
      expect(eligibilityCacheStore[p1CacheKey]!.providerId).toBe(P1_PROVIDER_ID);
    });
  });

  // =========================================================================
  // 4. Search isolation on eligibility-related queries
  // =========================================================================

  describe('Search isolation — PHN search remains scoped', () => {
    it('physician1 searching own PHN returns own patient, not physician2 patient', async () => {
      const res = await asPhysician1('GET', `/api/v1/patients/search?phn=${P1_PATIENT_PHN_A}`);
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBe(1);
      expect(body.data[0].patientId).toBe(P1_PATIENT_ID_A);
      expect(body.data[0].providerId).toBe(P1_PROVIDER_ID);
    });

    it('physician2 searching physician1 PHN returns empty', async () => {
      const res = await asPhysician2('GET', `/api/v1/patients/search?phn=${P1_PATIENT_PHN_A}`);
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBe(0);
    });
  });

  // =========================================================================
  // 5. Province detection does not leak cross-tenant data
  // =========================================================================

  describe('Province detection scoped to authenticated provider', () => {
    it('province detection does not reveal cross-tenant patient info', async () => {
      // Physician2 sends P1's PHN for province detection
      const res = await asPhysician2('POST', '/api/v1/patients/province/detect', {
        health_number: P1_PATIENT_PHN_A,
      });

      // Province detection is based on format, not patient records,
      // so it should succeed but never reveal patient identity
      expect(res.statusCode).toBe(200);
      const rawBody = res.body;
      expect(rawBody).not.toContain('Alice');
      expect(rawBody).not.toContain('Smith');
      expect(rawBody).not.toContain(P1_PATIENT_ID_A);
      expect(rawBody).not.toContain(P1_PROVIDER_ID);
    });
  });
});
