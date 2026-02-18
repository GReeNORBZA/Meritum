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
import { randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Fixed test identities — Two isolated physicians + delegate
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

// Delegate linked to Physician 1 only
const DELEGATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_SESSION_TOKEN_HASH = hashToken(DELEGATE_SESSION_TOKEN);
const DELEGATE_USER_ID = '33333333-3333-0000-0000-000000000003';
const DELEGATE_SESSION_ID = '33333333-3333-0000-0000-000000000033';
const DELEGATE_LINKAGE_ID = '44444444-4444-0000-0000-000000000044';

// Delegate linked to BOTH physicians (for cross-context isolation tests)
const DUAL_DELEGATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DUAL_DELEGATE_SESSION_TOKEN_HASH = hashToken(DUAL_DELEGATE_SESSION_TOKEN);
const DUAL_DELEGATE_USER_ID = '55555555-5555-0000-0000-000000000005';
const DUAL_DELEGATE_SESSION_ID = '55555555-5555-0000-0000-000000000055';

// ---------------------------------------------------------------------------
// Test data IDs — resources owned by each physician
// ---------------------------------------------------------------------------

// Physician 1's patients
const P1_PATIENT_ID_A = 'aaaa1111-0000-0000-0000-000000000001';
const P1_PATIENT_ID_B = 'aaaa1111-0000-0000-0000-000000000002';
const P1_PATIENT_PHN_A = '123456789'; // valid Luhn
const P1_PATIENT_PHN_SHARED = '311111116'; // same PHN on both physicians

// Physician 2's patients
const P2_PATIENT_ID_A = 'aaaa2222-0000-0000-0000-000000000001';
const P2_PATIENT_ID_B = 'aaaa2222-0000-0000-0000-000000000002';
const P2_PATIENT_PHN_A = '987654321';
const P2_PATIENT_PHN_SHARED = P1_PATIENT_PHN_SHARED; // same PHN, different physician

// Import batch IDs
const P1_IMPORT_ID = 'bbbb1111-0000-0000-0000-000000000001';
const P2_IMPORT_ID = 'bbbb2222-0000-0000-0000-000000000002';

// Export IDs
const P1_EXPORT_ID = 'cccc1111-0000-0000-0000-000000000001';
const P2_EXPORT_ID = 'cccc2222-0000-0000-0000-000000000002';

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

interface MockImportBatch {
  importId: string;
  physicianId: string;
  fileName: string;
  fileHash: string;
  totalRows: number;
  status: string;
  createdCount: number;
  updatedCount: number;
  skippedCount: number;
  errorCount: number;
  errorDetails: any;
  createdBy: string;
  createdAt: Date;
  updatedAt: Date;
}

const patientsStore: Record<string, MockPatient> = {};
const importBatchStore: Record<string, MockImportBatch> = {};

// Export store mirrors the service's in-memory export store
const exportTestStore: Record<string, { physicianId: string; status: string; rowCount: number; downloadUrl: string }> = {};

function seedTestData() {
  // Clear stores
  Object.keys(patientsStore).forEach((k) => delete patientsStore[k]);
  Object.keys(importBatchStore).forEach((k) => delete importBatchStore[k]);
  Object.keys(exportTestStore).forEach((k) => delete exportTestStore[k]);

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
  patientsStore[P1_PATIENT_ID_B] = {
    patientId: P1_PATIENT_ID_B,
    providerId: P1_PROVIDER_ID,
    phn: P1_PATIENT_PHN_SHARED,
    phnProvince: 'AB',
    firstName: 'Bob',
    middleName: null,
    lastName: 'Jones',
    dateOfBirth: '1990-06-20',
    gender: 'M',
    phone: '780-555-0002',
    email: null,
    addressLine1: '456 Oak Ave',
    addressLine2: null,
    city: 'Edmonton',
    province: 'AB',
    postalCode: 'T5B1B1',
    notes: null,
    isActive: true,
    lastVisitDate: '2026-02-01',
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
  patientsStore[P2_PATIENT_ID_B] = {
    patientId: P2_PATIENT_ID_B,
    providerId: P2_PROVIDER_ID,
    phn: P2_PATIENT_PHN_SHARED,
    phnProvince: 'AB',
    firstName: 'Diana',
    middleName: null,
    lastName: 'Prince',
    dateOfBirth: '1985-12-01',
    gender: 'F',
    phone: '403-555-0002',
    email: null,
    addressLine1: '321 Elm St',
    addressLine2: null,
    city: 'Calgary',
    province: 'AB',
    postalCode: 'T2R2R2',
    notes: null,
    isActive: true,
    lastVisitDate: '2026-02-05',
    createdBy: P2_USER_ID,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  // --- Import batches ---
  importBatchStore[P1_IMPORT_ID] = {
    importId: P1_IMPORT_ID,
    physicianId: P1_PROVIDER_ID,
    fileName: 'patients_p1.csv',
    fileHash: 'hash-p1',
    totalRows: 10,
    status: 'COMPLETED',
    createdCount: 8,
    updatedCount: 2,
    skippedCount: 0,
    errorCount: 0,
    errorDetails: null,
    createdBy: P1_USER_ID,
    createdAt: new Date(),
    updatedAt: new Date(),
  };
  importBatchStore[P2_IMPORT_ID] = {
    importId: P2_IMPORT_ID,
    physicianId: P2_PROVIDER_ID,
    fileName: 'patients_p2.csv',
    fileHash: 'hash-p2',
    totalRows: 5,
    status: 'COMPLETED',
    createdCount: 5,
    updatedCount: 0,
    skippedCount: 0,
    errorCount: 0,
    errorDetails: null,
    createdBy: P2_USER_ID,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  // --- Exports ---
  exportTestStore[P1_EXPORT_ID] = {
    physicianId: P1_PROVIDER_ID,
    status: 'READY',
    rowCount: 2,
    downloadUrl: `/api/v1/patients/exports/${P1_EXPORT_ID}/download`,
  };
  exportTestStore[P2_EXPORT_ID] = {
    physicianId: P2_PROVIDER_ID,
    status: 'READY',
    rowCount: 2,
    downloadUrl: `/api/v1/patients/exports/${P2_EXPORT_ID}/download`,
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

    updateLastVisitDate: vi.fn(async (patientId: string, physicianId: string) => {
      const patient = patientsStore[patientId];
      if (!patient || patient.providerId !== physicianId) return undefined;
      return patient;
    }),

    // Search — always scoped to physicianId
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
          (`${p.firstName} ${p.lastName}`.toLowerCase().includes(name.toLowerCase()) ||
            p.lastName.toLowerCase().includes(name.toLowerCase()) ||
            p.firstName.toLowerCase().includes(name.toLowerCase())),
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

    searchCombined: vi.fn(async (physicianId: string, filters: any, page: number, pageSize: number) => {
      let matches = Object.values(patientsStore).filter(
        (p) => p.providerId === physicianId && p.isActive,
      );
      if (filters.phn) {
        matches = matches.filter((p) => p.phn === filters.phn);
      }
      if (filters.name) {
        const n = filters.name.toLowerCase();
        matches = matches.filter(
          (p) =>
            p.firstName.toLowerCase().includes(n) ||
            p.lastName.toLowerCase().includes(n),
        );
      }
      if (filters.dob) {
        const dobStr = filters.dob instanceof Date ? filters.dob.toISOString().split('T')[0] : filters.dob;
        matches = matches.filter((p) => p.dateOfBirth === dobStr);
      }
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

    // Import batches — scoped to physicianId
    createImportBatch: vi.fn(async (data: any) => {
      const id = crypto.randomUUID();
      const batch: MockImportBatch = {
        importId: id,
        physicianId: data.physicianId,
        fileName: data.fileName,
        fileHash: data.fileHash,
        totalRows: data.totalRows,
        status: data.status,
        createdCount: 0,
        updatedCount: 0,
        skippedCount: 0,
        errorCount: 0,
        errorDetails: null,
        createdBy: data.createdBy,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      importBatchStore[id] = batch;
      return batch;
    }),

    findImportBatchById: vi.fn(async (importId: string, physicianId: string) => {
      const batch = importBatchStore[importId];
      if (!batch || batch.physicianId !== physicianId) return undefined;
      return batch;
    }),

    findImportByFileHash: vi.fn(async (physicianId: string, fileHash: string) => {
      return Object.values(importBatchStore).find(
        (b) => b.physicianId === physicianId && b.fileHash === fileHash,
      ) ?? undefined;
    }),

    updateImportStatus: vi.fn(async () => {}),

    listImportBatches: vi.fn(async (physicianId: string) => {
      const batches = Object.values(importBatchStore).filter(
        (b) => b.physicianId === physicianId,
      );
      return {
        data: batches,
        pagination: { total: batches.length, page: 1, pageSize: 20, hasMore: false },
      };
    }),

    bulkCreatePatients: vi.fn(async () => []),
    bulkUpsertPatients: vi.fn(async () => ({ created: 0, updated: 0 })),

    // Merge — scoped to physicianId
    getMergePreview: vi.fn(async (physicianId: string, survivingId: string, mergedId: string) => {
      const surviving = patientsStore[survivingId];
      const merged = patientsStore[mergedId];
      if (!surviving || surviving.providerId !== physicianId) return null;
      if (!merged || merged.providerId !== physicianId) return null;
      if (!surviving.isActive || !merged.isActive) return null;
      return {
        surviving,
        merged,
        claimsToTransfer: 3,
        fieldConflicts: surviving.phn !== merged.phn
          ? { phn: { surviving: surviving.phn, merged: merged.phn } }
          : {},
      };
    }),

    executeMerge: vi.fn(async (physicianId: string, survivingId: string, mergedId: string, actorId: string) => {
      const surviving = patientsStore[survivingId];
      const merged = patientsStore[mergedId];
      if (!surviving || surviving.providerId !== physicianId) return null;
      if (!merged || merged.providerId !== physicianId) return null;
      if (!surviving.isActive || !merged.isActive) return null;
      // Deactivate merged patient
      patientsStore[mergedId] = { ...merged, isActive: false, updatedAt: new Date() };
      return {
        mergeId: crypto.randomUUID(),
        claimsTransferred: 3,
        fieldConflicts: surviving.phn !== merged.phn
          ? { phn: { surviving: surviving.phn, merged: merged.phn } }
          : {},
      };
    }),

    listMergeHistory: vi.fn(async (physicianId: string, page: number, pageSize: number) => {
      return { data: [], pagination: { total: 0, page, pageSize, hasMore: false } };
    }),

    // Export — scoped to physicianId
    exportActivePatients: vi.fn(async (physicianId: string) => {
      return Object.values(patientsStore).filter(
        (p) => p.providerId === physicianId && p.isActive,
      );
    }),

    countActivePatients: vi.fn(async (physicianId: string) => {
      return Object.values(patientsStore).filter(
        (p) => p.providerId === physicianId && p.isActive,
      ).length;
    }),

    // Internal API
    getPatientClaimContext: vi.fn(async (patientId: string, physicianId: string) => {
      const patient = patientsStore[patientId];
      if (!patient || patient.providerId !== physicianId) return null;
      return {
        patientId: patient.patientId,
        phn: patient.phn,
        phnProvince: patient.phnProvince,
        firstName: patient.firstName,
        lastName: patient.lastName,
        dateOfBirth: patient.dateOfBirth,
        gender: patient.gender,
      };
    }),

    validatePhnExists: vi.fn(async (physicianId: string, phn: string) => {
      const patient = Object.values(patientsStore).find(
        (p) => p.providerId === physicianId && p.phn === phn && p.isActive,
      );
      return {
        valid: true,
        exists: !!patient,
        patientId: patient?.patientId,
      };
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

function asDelegate(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${DELEGATE_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function asDualDelegateP1(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${DUAL_DELEGATE_SESSION_TOKEN}` },
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

  // Delegate linked to Physician 1 only (with PATIENT_VIEW + PATIENT_EDIT)
  users.push({
    userId: DELEGATE_USER_ID,
    email: 'delegate@example.com',
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    role: 'DELEGATE',
    subscriptionStatus: 'TRIAL',
    delegateContext: {
      delegateUserId: DELEGATE_USER_ID,
      physicianProviderId: P1_PROVIDER_ID,
      permissions: ['PATIENT_VIEW', 'PATIENT_EDIT', 'PATIENT_CREATE', 'PATIENT_IMPORT', 'REPORT_EXPORT'],
      linkageId: DELEGATE_LINKAGE_ID,
    },
  });
  sessions.push({
    sessionId: DELEGATE_SESSION_ID,
    userId: DELEGATE_USER_ID,
    tokenHash: DELEGATE_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.3',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

  // Dual delegate — linked to Physician 1 context currently
  users.push({
    userId: DUAL_DELEGATE_USER_ID,
    email: 'dual-delegate@example.com',
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    role: 'DELEGATE',
    subscriptionStatus: 'TRIAL',
    delegateContext: {
      delegateUserId: DUAL_DELEGATE_USER_ID,
      physicianProviderId: P1_PROVIDER_ID, // Currently in P1 context
      permissions: ['PATIENT_VIEW', 'PATIENT_EDIT', 'PATIENT_CREATE', 'PATIENT_IMPORT', 'REPORT_EXPORT'],
      linkageId: '66666666-6666-0000-0000-000000000066',
    },
  });
  sessions.push({
    sessionId: DUAL_DELEGATE_SESSION_ID,
    userId: DUAL_DELEGATE_USER_ID,
    tokenHash: DUAL_DELEGATE_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.5',
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

describe('Patient Physician Tenant Isolation — MOST CRITICAL (Security)', () => {
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
  // 1. Patient Record Isolation — GET by ID
  // =========================================================================

  describe('Patient record isolation — GET by ID', () => {
    it('physician1 can retrieve own patient via GET /api/v1/patients/:id', async () => {
      const res = await asPhysician1('GET', `/api/v1/patients/${P1_PATIENT_ID_A}`);
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.patientId).toBe(P1_PATIENT_ID_A);
      expect(body.data.providerId).toBe(P1_PROVIDER_ID);
      expect(body.data.firstName).toBe('Alice');
    });

    it('physician2 can retrieve own patient via GET /api/v1/patients/:id', async () => {
      const res = await asPhysician2('GET', `/api/v1/patients/${P2_PATIENT_ID_A}`);
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.patientId).toBe(P2_PATIENT_ID_A);
      expect(body.data.providerId).toBe(P2_PROVIDER_ID);
      expect(body.data.firstName).toBe('Charlie');
    });

    it('physician1 CANNOT retrieve physician2 patient — returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/patients/${P2_PATIENT_ID_A}`);
      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();
    });

    it('physician2 CANNOT retrieve physician1 patient — returns 404', async () => {
      const res = await asPhysician2('GET', `/api/v1/patients/${P1_PATIENT_ID_A}`);
      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();
    });

    it('cross-tenant GET response does not leak target patient details', async () => {
      const res = await asPhysician1('GET', `/api/v1/patients/${P2_PATIENT_ID_A}`);
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_PATIENT_ID_A);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain('Charlie');
      expect(rawBody).not.toContain(P2_PATIENT_PHN_A);
      expect(rawBody).not.toContain('Calgary');
    });
  });

  // =========================================================================
  // 2. Patient Record Isolation — UPDATE
  // =========================================================================

  describe('Patient record isolation — UPDATE', () => {
    it('physician1 CANNOT update physician2 patient via PUT — returns 404', async () => {
      const res = await asPhysician1('PUT', `/api/v1/patients/${P2_PATIENT_ID_A}`, {
        first_name: 'Hijacked',
      });
      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();
    });

    it('physician2 CANNOT update physician1 patient — returns 404', async () => {
      const res = await asPhysician2('PUT', `/api/v1/patients/${P1_PATIENT_ID_A}`, {
        first_name: 'Attacker',
      });
      expect(res.statusCode).toBe(404);
    });

    it('cross-tenant PUT response does not reveal patient info', async () => {
      const res = await asPhysician1('PUT', `/api/v1/patients/${P2_PATIENT_ID_A}`, {
        first_name: 'Hijacked',
      });
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_PATIENT_ID_A);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain('Charlie');
    });
  });

  // =========================================================================
  // 3. Patient Record Isolation — DEACTIVATE
  // =========================================================================

  describe('Patient record isolation — DEACTIVATE', () => {
    it('physician1 CANNOT deactivate physician2 patient — returns 404', async () => {
      const res = await asPhysician1('POST', `/api/v1/patients/${P2_PATIENT_ID_A}/deactivate`);
      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
    });

    it('physician2 CANNOT deactivate physician1 patient — returns 404', async () => {
      const res = await asPhysician2('POST', `/api/v1/patients/${P1_PATIENT_ID_A}/deactivate`);
      expect(res.statusCode).toBe(404);
    });

    it('physician2 patient remains active after physician1 deactivation attempt', async () => {
      await asPhysician1('POST', `/api/v1/patients/${P2_PATIENT_ID_A}/deactivate`);
      // Verify via physician2 that their patient is unchanged
      const res = await asPhysician2('GET', `/api/v1/patients/${P2_PATIENT_ID_A}`);
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.isActive).toBe(true);
    });
  });

  // =========================================================================
  // 4. Patient Record Isolation — REACTIVATE
  // =========================================================================

  describe('Patient record isolation — REACTIVATE', () => {
    it('physician1 CANNOT reactivate physician2 patient — returns 404', async () => {
      const res = await asPhysician1('POST', `/api/v1/patients/${P2_PATIENT_ID_A}/reactivate`);
      expect(res.statusCode).toBe(404);
    });

    it('physician2 CANNOT reactivate physician1 patient — returns 404', async () => {
      const res = await asPhysician2('POST', `/api/v1/patients/${P1_PATIENT_ID_A}/reactivate`);
      expect(res.statusCode).toBe(404);
    });
  });

  // =========================================================================
  // 5. Search Isolation — PHN search
  // =========================================================================

  describe('Search isolation — PHN search', () => {
    it('physician1 searching by own PHN returns own patient', async () => {
      const res = await asPhysician1('GET', `/api/v1/patients/search?phn=${P1_PATIENT_PHN_A}`);
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBe(1);
      expect(body.data[0].patientId).toBe(P1_PATIENT_ID_A);
      expect(body.data[0].providerId).toBe(P1_PROVIDER_ID);
    });

    it('physician1 searching by physician2 PHN returns empty (not physician2 patient)', async () => {
      const res = await asPhysician1('GET', `/api/v1/patients/search?phn=${P2_PATIENT_PHN_A}`);
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBe(0);
    });

    it('shared PHN returns ONLY the authenticated physicians patient', async () => {
      // Both P1 and P2 have a patient with the shared PHN
      const res1 = await asPhysician1('GET', `/api/v1/patients/search?phn=${P1_PATIENT_PHN_SHARED}`);
      expect(res1.statusCode).toBe(200);
      const body1 = JSON.parse(res1.body);
      expect(body1.data.length).toBe(1);
      expect(body1.data[0].providerId).toBe(P1_PROVIDER_ID);
      expect(body1.data[0].patientId).toBe(P1_PATIENT_ID_B);

      const res2 = await asPhysician2('GET', `/api/v1/patients/search?phn=${P2_PATIENT_PHN_SHARED}`);
      expect(res2.statusCode).toBe(200);
      const body2 = JSON.parse(res2.body);
      expect(body2.data.length).toBe(1);
      expect(body2.data[0].providerId).toBe(P2_PROVIDER_ID);
      expect(body2.data[0].patientId).toBe(P2_PATIENT_ID_B);
    });

    it('physician1 PHN search response never contains physician2 data', async () => {
      const res = await asPhysician1('GET', `/api/v1/patients/search?phn=${P1_PATIENT_PHN_SHARED}`);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain(P2_PATIENT_ID_B);
      expect(rawBody).not.toContain('Diana');
      expect(rawBody).not.toContain('Prince');
    });
  });

  // =========================================================================
  // 6. Search Isolation — Name search
  // =========================================================================

  describe('Search isolation — name search', () => {
    it('physician1 searching by name returns only own patients', async () => {
      const res = await asPhysician1('GET', '/api/v1/patients/search?name=Smith');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      body.data.forEach((patient: any) => {
        expect(patient.providerId).toBe(P1_PROVIDER_ID);
      });
    });

    it('physician1 searching by physician2 patient name returns empty', async () => {
      const res = await asPhysician1('GET', '/api/v1/patients/search?name=Brown');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBe(0);
    });

    it('physician2 name search never returns physician1 patients', async () => {
      const res = await asPhysician2('GET', '/api/v1/patients/search?name=Alice');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBe(0);
      expect(res.body).not.toContain(P1_PROVIDER_ID);
    });
  });

  // =========================================================================
  // 7. Search Isolation — DOB search
  // =========================================================================

  describe('Search isolation — DOB search', () => {
    it('physician1 searching by own patient DOB returns own patient only', async () => {
      const res = await asPhysician1('GET', '/api/v1/patients/search?dob=1980-01-15');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      body.data.forEach((patient: any) => {
        expect(patient.providerId).toBe(P1_PROVIDER_ID);
      });
    });

    it('physician1 searching by physician2 patient DOB returns empty', async () => {
      const res = await asPhysician1('GET', '/api/v1/patients/search?dob=1975-03-10');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBe(0);
    });
  });

  // =========================================================================
  // 8. Recent Patients Isolation
  // =========================================================================

  describe('Recent patients isolation', () => {
    it('physician1 recent patients list contains only physician1 patients', async () => {
      const res = await asPhysician1('GET', '/api/v1/patients/recent');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBeGreaterThan(0);
      body.data.forEach((patient: any) => {
        expect(patient.providerId).toBe(P1_PROVIDER_ID);
      });
    });

    it('physician2 recent patients list contains only physician2 patients', async () => {
      const res = await asPhysician2('GET', '/api/v1/patients/recent');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBeGreaterThan(0);
      body.data.forEach((patient: any) => {
        expect(patient.providerId).toBe(P2_PROVIDER_ID);
      });
    });

    it('physician1 recent patients never includes physician2 patients', async () => {
      const res = await asPhysician1('GET', '/api/v1/patients/recent');
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain(P2_PATIENT_ID_A);
      expect(rawBody).not.toContain(P2_PATIENT_ID_B);
      expect(rawBody).not.toContain('Charlie');
      expect(rawBody).not.toContain('Diana');
    });
  });

  // =========================================================================
  // 9. Import Batch Isolation
  // =========================================================================

  describe('Import batch isolation', () => {
    it('physician1 CANNOT access physician2 import batch status — returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/patients/imports/${P2_IMPORT_ID}`);
      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
    });

    it('physician2 CANNOT access physician1 import batch status — returns 404', async () => {
      const res = await asPhysician2('GET', `/api/v1/patients/imports/${P1_IMPORT_ID}`);
      expect(res.statusCode).toBe(404);
    });

    it('physician1 CANNOT access physician2 import preview — returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/patients/imports/${P2_IMPORT_ID}/preview`);
      expect(res.statusCode).toBe(404);
    });

    it('physician1 CANNOT update physician2 import mapping — returns 404', async () => {
      const res = await asPhysician1('PUT', `/api/v1/patients/imports/${P2_IMPORT_ID}/mapping`, {
        mapping: { first_name: 'Name' },
      });
      expect(res.statusCode).toBe(404);
    });

    it('physician1 CANNOT commit physician2 import — returns 404', async () => {
      const res = await asPhysician1('POST', `/api/v1/patients/imports/${P2_IMPORT_ID}/commit`);
      expect(res.statusCode).toBe(404);
    });

    it('cross-tenant import response does not reveal batch details', async () => {
      const res = await asPhysician1('GET', `/api/v1/patients/imports/${P2_IMPORT_ID}`);
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_IMPORT_ID);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain('patients_p2.csv');
    });
  });

  // =========================================================================
  // 10. Merge Isolation
  // =========================================================================

  describe('Merge isolation', () => {
    it('physician1 CANNOT preview merge of physician2 patients — returns 404', async () => {
      const res = await asPhysician1('POST', '/api/v1/patients/merge/preview', {
        surviving_id: P2_PATIENT_ID_A,
        merged_id: P2_PATIENT_ID_B,
      });
      expect(res.statusCode).toBe(404);
    });

    it('physician1 CANNOT execute merge of physician2 patients — returns 404', async () => {
      const res = await asPhysician1('POST', '/api/v1/patients/merge/execute', {
        surviving_id: P2_PATIENT_ID_A,
        merged_id: P2_PATIENT_ID_B,
      });
      expect(res.statusCode).toBe(404);
    });

    it('physician2 CANNOT preview merge of physician1 patients — returns 404', async () => {
      const res = await asPhysician2('POST', '/api/v1/patients/merge/preview', {
        surviving_id: P1_PATIENT_ID_A,
        merged_id: P1_PATIENT_ID_B,
      });
      expect(res.statusCode).toBe(404);
    });

    it('physician2 CANNOT execute merge of physician1 patients — returns 404', async () => {
      const res = await asPhysician2('POST', '/api/v1/patients/merge/execute', {
        surviving_id: P1_PATIENT_ID_A,
        merged_id: P1_PATIENT_ID_B,
      });
      expect(res.statusCode).toBe(404);
    });

    it('CANNOT merge one physician1 patient with one physician2 patient (preview) — returns 404', async () => {
      const res = await asPhysician1('POST', '/api/v1/patients/merge/preview', {
        surviving_id: P1_PATIENT_ID_A,
        merged_id: P2_PATIENT_ID_A,
      });
      expect(res.statusCode).toBe(404);
    });

    it('CANNOT merge one physician1 patient with one physician2 patient (execute) — returns 404', async () => {
      const res = await asPhysician1('POST', '/api/v1/patients/merge/execute', {
        surviving_id: P1_PATIENT_ID_A,
        merged_id: P2_PATIENT_ID_A,
      });
      expect(res.statusCode).toBe(404);
    });

    it('cross-tenant merge preview does not reveal patient details', async () => {
      const res = await asPhysician1('POST', '/api/v1/patients/merge/preview', {
        surviving_id: P2_PATIENT_ID_A,
        merged_id: P2_PATIENT_ID_B,
      });
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain('Charlie');
      expect(rawBody).not.toContain('Diana');
      expect(rawBody).not.toContain(P2_PATIENT_PHN_A);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
    });

    it('physician2 patients remain unchanged after physician1 merge attempt', async () => {
      await asPhysician1('POST', '/api/v1/patients/merge/execute', {
        surviving_id: P2_PATIENT_ID_A,
        merged_id: P2_PATIENT_ID_B,
      });
      // Verify both of physician2's patients remain active and unchanged
      const resA = await asPhysician2('GET', `/api/v1/patients/${P2_PATIENT_ID_A}`);
      expect(resA.statusCode).toBe(200);
      expect(JSON.parse(resA.body).data.isActive).toBe(true);

      const resB = await asPhysician2('GET', `/api/v1/patients/${P2_PATIENT_ID_B}`);
      expect(resB.statusCode).toBe(200);
      expect(JSON.parse(resB.body).data.isActive).toBe(true);
    });
  });

  // =========================================================================
  // 11. Export Isolation
  // =========================================================================

  describe('Export isolation', () => {
    it('physician1 CANNOT access physician2 export status — returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/patients/exports/${P2_EXPORT_ID}`);
      expect(res.statusCode).toBe(404);
    });

    it('physician2 CANNOT access physician1 export status — returns 404', async () => {
      const res = await asPhysician2('GET', `/api/v1/patients/exports/${P1_EXPORT_ID}`);
      expect(res.statusCode).toBe(404);
    });

    it('cross-tenant export response does not leak export info', async () => {
      const res = await asPhysician1('GET', `/api/v1/patients/exports/${P2_EXPORT_ID}`);
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_EXPORT_ID);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain('download');
    });
  });

  // =========================================================================
  // 12. Delegate Cross-Context Isolation
  // =========================================================================

  describe('Delegate cross-context isolation', () => {
    it('delegate linked to physician1 can access physician1 patient', async () => {
      const res = await asDelegate('GET', `/api/v1/patients/${P1_PATIENT_ID_A}`);
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.patientId).toBe(P1_PATIENT_ID_A);
      expect(body.data.providerId).toBe(P1_PROVIDER_ID);
    });

    it('delegate linked to physician1 CANNOT access physician2 patient — returns 404', async () => {
      const res = await asDelegate('GET', `/api/v1/patients/${P2_PATIENT_ID_A}`);
      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
    });

    it('delegate search only returns physician1 patients', async () => {
      const res = await asDelegate('GET', '/api/v1/patients/search?name=Smith');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      body.data.forEach((patient: any) => {
        expect(patient.providerId).toBe(P1_PROVIDER_ID);
      });
      expect(res.body).not.toContain(P2_PROVIDER_ID);
    });

    it('delegate recent patients only returns physician1 patients', async () => {
      const res = await asDelegate('GET', '/api/v1/patients/recent');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      body.data.forEach((patient: any) => {
        expect(patient.providerId).toBe(P1_PROVIDER_ID);
      });
    });

    it('delegate CANNOT update physician2 patient — returns 404', async () => {
      const res = await asDelegate('PUT', `/api/v1/patients/${P2_PATIENT_ID_A}`, {
        first_name: 'Hacked',
      });
      expect(res.statusCode).toBe(404);
    });

    it('delegate CANNOT deactivate physician2 patient — returns 404', async () => {
      const res = await asDelegate('POST', `/api/v1/patients/${P2_PATIENT_ID_A}/deactivate`);
      expect(res.statusCode).toBe(404);
    });
  });

  // =========================================================================
  // 13. Dual-Delegate Cross-Context Isolation
  // =========================================================================

  describe('Dual-delegate in physician1 context does not leak physician2 data', () => {
    it('dual delegate in P1 context sees only P1 patients in search', async () => {
      const res = await asDualDelegateP1('GET', '/api/v1/patients/recent');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      body.data.forEach((patient: any) => {
        expect(patient.providerId).toBe(P1_PROVIDER_ID);
      });
      expect(res.body).not.toContain(P2_PROVIDER_ID);
      expect(res.body).not.toContain(P2_PATIENT_ID_A);
      expect(res.body).not.toContain(P2_PATIENT_ID_B);
    });

    it('dual delegate in P1 context CANNOT access P2 patient by ID — returns 404', async () => {
      const res = await asDualDelegateP1('GET', `/api/v1/patients/${P2_PATIENT_ID_A}`);
      expect(res.statusCode).toBe(404);
    });

    it('dual delegate in P1 context CANNOT update P2 patient — returns 404', async () => {
      const res = await asDualDelegateP1('PUT', `/api/v1/patients/${P2_PATIENT_ID_A}`, {
        first_name: 'CrossContext',
      });
      expect(res.statusCode).toBe(404);
    });

    it('dual delegate shared PHN search in P1 context returns only P1 patient', async () => {
      const res = await asDualDelegateP1(
        'GET',
        `/api/v1/patients/search?phn=${P1_PATIENT_PHN_SHARED}`,
      );
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBe(1);
      expect(body.data[0].providerId).toBe(P1_PROVIDER_ID);
      expect(body.data[0].patientId).toBe(P1_PATIENT_ID_B);
    });
  });

  // =========================================================================
  // 14. Cross-user access always returns 404 (NOT 403)
  // =========================================================================

  describe('Cross-user access returns 404 not 403 (prevents resource enumeration)', () => {
    it('GET patient by cross-tenant ID returns 404 not 403', async () => {
      const res = await asPhysician1('GET', `/api/v1/patients/${P2_PATIENT_ID_A}`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('PUT patient cross-tenant returns 404 not 403', async () => {
      const res = await asPhysician1('PUT', `/api/v1/patients/${P2_PATIENT_ID_A}`, { first_name: 'X' });
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST deactivate cross-tenant returns 404 not 403', async () => {
      const res = await asPhysician1('POST', `/api/v1/patients/${P2_PATIENT_ID_A}/deactivate`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST reactivate cross-tenant returns 404 not 403', async () => {
      const res = await asPhysician1('POST', `/api/v1/patients/${P2_PATIENT_ID_A}/reactivate`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET import batch cross-tenant returns 404 not 403', async () => {
      const res = await asPhysician1('GET', `/api/v1/patients/imports/${P2_IMPORT_ID}`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST merge preview cross-tenant returns 404 not 403', async () => {
      const res = await asPhysician1('POST', '/api/v1/patients/merge/preview', {
        surviving_id: P2_PATIENT_ID_A,
        merged_id: P2_PATIENT_ID_B,
      });
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST merge execute cross-tenant returns 404 not 403', async () => {
      const res = await asPhysician1('POST', '/api/v1/patients/merge/execute', {
        surviving_id: P2_PATIENT_ID_A,
        merged_id: P2_PATIENT_ID_B,
      });
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET export status cross-tenant returns 404 not 403', async () => {
      const res = await asPhysician1('GET', `/api/v1/patients/exports/${P2_EXPORT_ID}`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });
  });

  // =========================================================================
  // 15. 404 responses do not confirm resource existence
  // =========================================================================

  describe('404 responses reveal no information about the target resource', () => {
    it('404 for cross-tenant patient does not contain patient ID or details', async () => {
      const res = await asPhysician1('GET', `/api/v1/patients/${P2_PATIENT_ID_A}`);
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_PATIENT_ID_A);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain('Charlie');
      expect(rawBody).not.toContain('Brown');
      expect(rawBody).not.toContain(P2_PATIENT_PHN_A);
    });

    it('404 for cross-tenant import does not contain batch ID', async () => {
      const res = await asPhysician1('GET', `/api/v1/patients/imports/${P2_IMPORT_ID}`);
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_IMPORT_ID);
      expect(rawBody).not.toContain('patients_p2.csv');
    });

    it('404 for cross-tenant export does not contain export ID', async () => {
      const res = await asPhysician1('GET', `/api/v1/patients/exports/${P2_EXPORT_ID}`);
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_EXPORT_ID);
    });

    it('404 for cross-tenant merge does not contain patient names', async () => {
      const res = await asPhysician1('POST', '/api/v1/patients/merge/preview', {
        surviving_id: P2_PATIENT_ID_A,
        merged_id: P2_PATIENT_ID_B,
      });
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain('Charlie');
      expect(rawBody).not.toContain('Diana');
      expect(rawBody).not.toContain(P2_PATIENT_ID_A);
      expect(rawBody).not.toContain(P2_PATIENT_ID_B);
    });
  });

  // =========================================================================
  // 16. Bidirectional isolation — verify BOTH directions
  // =========================================================================

  describe('Bidirectional isolation (both physicians tested)', () => {
    it('physician1 recent patients contain P1 IDs and not P2 IDs', async () => {
      const res = await asPhysician1('GET', '/api/v1/patients/recent');
      const body = JSON.parse(res.body);
      const ids = body.data.map((p: any) => p.patientId);
      expect(ids).toContain(P1_PATIENT_ID_A);
      expect(ids).toContain(P1_PATIENT_ID_B);
      expect(ids).not.toContain(P2_PATIENT_ID_A);
      expect(ids).not.toContain(P2_PATIENT_ID_B);
    });

    it('physician2 recent patients contain P2 IDs and not P1 IDs', async () => {
      const res = await asPhysician2('GET', '/api/v1/patients/recent');
      const body = JSON.parse(res.body);
      const ids = body.data.map((p: any) => p.patientId);
      expect(ids).toContain(P2_PATIENT_ID_A);
      expect(ids).toContain(P2_PATIENT_ID_B);
      expect(ids).not.toContain(P1_PATIENT_ID_A);
      expect(ids).not.toContain(P1_PATIENT_ID_B);
    });

    it('physician1 can merge own patients while physician2 patients are unaffected', async () => {
      // Physician1 merges own patients
      const mergeRes = await asPhysician1('POST', '/api/v1/patients/merge/preview', {
        surviving_id: P1_PATIENT_ID_A,
        merged_id: P1_PATIENT_ID_B,
      });
      expect(mergeRes.statusCode).toBe(200);
      const mergeBody = JSON.parse(mergeRes.body);
      expect(mergeBody.data.surviving.patientId).toBe(P1_PATIENT_ID_A);
      expect(mergeBody.data.merged.patientId).toBe(P1_PATIENT_ID_B);

      // Physician2 patients remain accessible
      const p2Res = await asPhysician2('GET', `/api/v1/patients/${P2_PATIENT_ID_A}`);
      expect(p2Res.statusCode).toBe(200);
    });
  });

  // =========================================================================
  // 17. Non-existent resource IDs still return 404 (not 500)
  // =========================================================================

  describe('Non-existent resource IDs return 404', () => {
    const NONEXISTENT_UUID = '99999999-9999-9999-9999-999999999999';

    it('GET non-existent patient ID returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/patients/${NONEXISTENT_UUID}`);
      expect(res.statusCode).toBe(404);
    });

    it('PUT non-existent patient ID returns 404', async () => {
      const res = await asPhysician1('PUT', `/api/v1/patients/${NONEXISTENT_UUID}`, { first_name: 'X' });
      expect(res.statusCode).toBe(404);
    });

    it('POST deactivate non-existent patient returns 404', async () => {
      const res = await asPhysician1('POST', `/api/v1/patients/${NONEXISTENT_UUID}/deactivate`);
      expect(res.statusCode).toBe(404);
    });

    it('POST reactivate non-existent patient returns 404', async () => {
      const res = await asPhysician1('POST', `/api/v1/patients/${NONEXISTENT_UUID}/reactivate`);
      expect(res.statusCode).toBe(404);
    });

    it('GET non-existent import batch returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/patients/imports/${NONEXISTENT_UUID}`);
      expect(res.statusCode).toBe(404);
    });

    it('GET non-existent export returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/patients/exports/${NONEXISTENT_UUID}`);
      expect(res.statusCode).toBe(404);
    });

    it('merge preview with non-existent patient IDs returns 404', async () => {
      const res = await asPhysician1('POST', '/api/v1/patients/merge/preview', {
        surviving_id: NONEXISTENT_UUID,
        merged_id: P1_PATIENT_ID_A,
      });
      expect(res.statusCode).toBe(404);
    });

    it('merge execute with non-existent patient IDs returns 404', async () => {
      const res = await asPhysician1('POST', '/api/v1/patients/merge/execute', {
        surviving_id: NONEXISTENT_UUID,
        merged_id: P1_PATIENT_ID_A,
      });
      expect(res.statusCode).toBe(404);
    });
  });

  // =========================================================================
  // 18. Response isolation — physician1 responses never contain P2 identifiers
  // =========================================================================

  describe('Response body never leaks cross-tenant identifiers', () => {
    it('physician1 patient GET response contains no P2 identifiers', async () => {
      const res = await asPhysician1('GET', `/api/v1/patients/${P1_PATIENT_ID_A}`);
      expect(res.statusCode).toBe(200);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain(P2_USER_ID);
      expect(rawBody).not.toContain(P2_PATIENT_ID_A);
      expect(rawBody).not.toContain(P2_PATIENT_ID_B);
    });

    it('physician1 search response contains no P2 identifiers', async () => {
      const res = await asPhysician1('GET', '/api/v1/patients/search?name=Alice');
      expect(res.statusCode).toBe(200);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain(P2_USER_ID);
      expect(rawBody).not.toContain(P2_PATIENT_ID_A);
    });

    it('physician1 recent response contains no P2 identifiers', async () => {
      const res = await asPhysician1('GET', '/api/v1/patients/recent');
      expect(res.statusCode).toBe(200);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain(P2_PATIENT_ID_A);
      expect(rawBody).not.toContain(P2_PATIENT_ID_B);
    });
  });
});
