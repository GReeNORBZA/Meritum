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
import { patientRoutes } from '../../../src/domains/patient/patient.routes.js';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import {
  type PatientServiceDeps,
  _parsedRowsCache,
  _exportStore,
} from '../../../src/domains/patient/patient.service.js';
import { type PatientHandlerDeps } from '../../../src/domains/patient/patient.handlers.js';
import {
  type SessionManagementDeps,
  hashToken,
} from '../../../src/domains/iam/iam.service.js';
import { randomBytes } from 'node:crypto';
import { PatientAuditAction } from '@meritum/shared/constants/patient.constants.js';

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_USER_ID = '22222222-0000-0000-0000-000000000001';
const PHYSICIAN_PROVIDER_ID = PHYSICIAN_USER_ID; // 1:1 mapping
const PHYSICIAN_SESSION_ID = '33333333-0000-0000-0000-000000000001';

// Resource IDs (deterministic)
const PATIENT_ID = 'aaaaaaaa-1111-0000-0000-000000000001';
const PATIENT_ID_2 = 'aaaaaaaa-1111-0000-0000-000000000002';
const IMPORT_BATCH_ID = 'bbbbbbbb-1111-0000-0000-000000000001';
const MERGE_ID = 'cccccccc-1111-0000-0000-000000000001';

// Valid Alberta PHN (passes Luhn): 123456780
const VALID_PHN = '123456780';
const VALID_PHN_2 = '234567891';

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
// In-memory patient store
// ---------------------------------------------------------------------------

let patientStore: Record<string, any> = {};
let importBatchStore: Record<string, any> = {};

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
// Seed helpers
// ---------------------------------------------------------------------------

function seedUsersAndSessions() {
  users.length = 0;
  sessions.length = 0;

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
}

function seedPatientData() {
  patientStore = {};
  importBatchStore = {};

  patientStore[PATIENT_ID] = {
    patientId: PATIENT_ID,
    providerId: PHYSICIAN_PROVIDER_ID,
    phn: VALID_PHN,
    phnProvince: 'AB',
    firstName: 'John',
    middleName: null,
    lastName: 'Smith',
    dateOfBirth: '1990-01-15',
    gender: 'M',
    phone: '780-555-1234',
    email: 'john@example.com',
    addressLine1: '123 Main St',
    addressLine2: null,
    city: 'Edmonton',
    province: 'AB',
    postalCode: 'T5A0A1',
    notes: 'Private clinical notes',
    isActive: true,
    lastVisitDate: null,
    createdBy: PHYSICIAN_USER_ID,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  patientStore[PATIENT_ID_2] = {
    patientId: PATIENT_ID_2,
    providerId: PHYSICIAN_PROVIDER_ID,
    phn: VALID_PHN_2,
    phnProvince: 'AB',
    firstName: 'Jane',
    middleName: null,
    lastName: 'Doe',
    dateOfBirth: '1985-06-20',
    gender: 'F',
    phone: '780-555-5678',
    email: 'jane@example.com',
    addressLine1: '456 Oak Ave',
    addressLine2: null,
    city: 'Calgary',
    province: 'AB',
    postalCode: 'T2A0B2',
    notes: null,
    isActive: true,
    lastVisitDate: null,
    createdBy: PHYSICIAN_USER_ID,
    createdAt: new Date(),
    updatedAt: new Date(),
  };
}

// ---------------------------------------------------------------------------
// Scoped patient repository mock
// ---------------------------------------------------------------------------

function createMockPatientRepo() {
  return {
    createPatient: vi.fn(async (data: any) => {
      const id = data.patientId ?? crypto.randomUUID();
      const patient = {
        patientId: id,
        ...data,
        isActive: true,
        lastVisitDate: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      patientStore[id] = patient;
      return patient;
    }),
    findPatientById: vi.fn(async (patientId: string, physicianId: string) => {
      const p = patientStore[patientId];
      if (!p || p.providerId !== physicianId) return undefined;
      return p;
    }),
    findPatientByPhn: vi.fn(async (physicianId: string, phn: string) => {
      return Object.values(patientStore).find(
        (p: any) => p.providerId === physicianId && p.phn === phn,
      ) ?? undefined;
    }),
    updatePatient: vi.fn(async (patientId: string, physicianId: string, data: any) => {
      const p = patientStore[patientId];
      if (!p || p.providerId !== physicianId) return undefined;
      const updated = { ...p, ...data, updatedAt: new Date() };
      patientStore[patientId] = updated;
      return updated;
    }),
    deactivatePatient: vi.fn(async (patientId: string, physicianId: string) => {
      const p = patientStore[patientId];
      if (!p || p.providerId !== physicianId) return undefined;
      const deactivated = { ...p, isActive: false, updatedAt: new Date() };
      patientStore[patientId] = deactivated;
      return deactivated;
    }),
    reactivatePatient: vi.fn(async (patientId: string, physicianId: string) => {
      const p = patientStore[patientId];
      if (!p || p.providerId !== physicianId) return undefined;
      const reactivated = { ...p, isActive: true, updatedAt: new Date() };
      patientStore[patientId] = reactivated;
      return reactivated;
    }),
    updateLastVisitDate: vi.fn(async () => ({})),
    searchByPhn: vi.fn(async (physicianId: string, phn: string) => {
      return Object.values(patientStore).find(
        (p: any) => p.providerId === physicianId && p.phn === phn && p.isActive,
      ) ?? undefined;
    }),
    searchByName: vi.fn(async (physicianId: string, name: string, page: number, pageSize: number) => {
      const matches = Object.values(patientStore).filter(
        (p: any) =>
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
    createImportBatch: vi.fn(async (data: any) => {
      const id = data.importId ?? IMPORT_BATCH_ID;
      const batch = {
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
      const b = importBatchStore[importId];
      if (!b || b.physicianId !== physicianId) return undefined;
      return b;
    }),
    findImportByFileHash: vi.fn(async () => undefined),
    updateImportStatus: vi.fn(async (importId: string, status: string, counts?: any, errorDetails?: any) => {
      const b = importBatchStore[importId];
      if (!b) return undefined;
      b.status = status;
      if (counts) {
        b.createdCount = counts.created;
        b.updatedCount = counts.updated;
        b.skippedCount = counts.skipped;
        b.errorCount = counts.error;
      }
      if (errorDetails) {
        b.errorDetails = errorDetails;
      }
      return b;
    }),
    listImportBatches: vi.fn(async () => ({ data: [], pagination: { total: 0, page: 1, pageSize: 20, hasMore: false } })),
    bulkCreatePatients: vi.fn(async () => []),
    bulkUpsertPatients: vi.fn(async () => ({ created: 0, updated: 0 })),
    getMergePreview: vi.fn(async (physicianId: string, survivingId: string, mergedId: string) => {
      const surviving = patientStore[survivingId];
      const merged = patientStore[mergedId];
      if (!surviving || !merged) return null;
      if (surviving.providerId !== physicianId || merged.providerId !== physicianId) return null;
      return {
        surviving,
        merged,
        claimsToTransfer: 2,
        fieldConflicts: {
          phn: { surviving: surviving.phn, merged: merged.phn },
          firstName: { surviving: surviving.firstName, merged: merged.firstName },
        },
      };
    }),
    executeMerge: vi.fn(async (physicianId: string, survivingId: string, mergedId: string, actorId: string) => {
      const surviving = patientStore[survivingId];
      const merged = patientStore[mergedId];
      if (!surviving || !merged) return null;
      if (surviving.providerId !== physicianId || merged.providerId !== physicianId) return null;
      // Soft-delete merged patient
      patientStore[mergedId] = { ...merged, isActive: false };
      return {
        mergeId: MERGE_ID,
        claimsTransferred: 2,
        fieldConflicts: {
          phn: { surviving: surviving.phn, merged: merged.phn },
          firstName: { surviving: surviving.firstName, merged: merged.firstName },
        },
      };
    }),
    listMergeHistory: vi.fn(async () => ({ data: [], pagination: { total: 0, page: 1, pageSize: 20, hasMore: false } })),
    exportActivePatients: vi.fn(async (physicianId: string) => {
      return Object.values(patientStore)
        .filter((p: any) => p.providerId === physicianId && p.isActive)
        .map((p: any) => ({
          phn: p.phn,
          firstName: p.firstName,
          lastName: p.lastName,
          dateOfBirth: p.dateOfBirth,
          gender: p.gender,
          phone: p.phone,
          addressLine1: p.addressLine1,
          addressLine2: p.addressLine2,
          city: p.city,
          province: p.province,
          postalCode: p.postalCode,
        }));
    }),
    countActivePatients: vi.fn(async (physicianId: string) => {
      return Object.values(patientStore).filter(
        (p: any) => p.providerId === physicianId && p.isActive,
      ).length;
    }),
    getPatientClaimContext: vi.fn(async () => null),
    validatePhnExists: vi.fn(async () => ({ valid: false, exists: false })),
  };
}

// ---------------------------------------------------------------------------
// Shared service deps ref (accessible to tests for spy inspection)
// ---------------------------------------------------------------------------

let serviceDeps: PatientServiceDeps;

function createStubServiceDeps(): PatientServiceDeps {
  const deps: PatientServiceDeps = {
    repo: createMockPatientRepo() as any,
    auditRepo: createMockAuditRepo(),
    events: createMockEvents(),
  };
  serviceDeps = deps;
  return deps;
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

  const deps = createStubServiceDeps();

  const handlerDeps: PatientHandlerDeps = {
    serviceDeps: deps,
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
// Request helper
// ---------------------------------------------------------------------------

function physicianRequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

// ---------------------------------------------------------------------------
// Audit entry finders
// ---------------------------------------------------------------------------

function findAuditEntry(action: string): Record<string, unknown> | undefined {
  return auditEntries.find((e) => e.action === action);
}

function findAuditEntries(action: string): Array<Record<string, unknown>> {
  return auditEntries.filter((e) => e.action === action);
}

// ---------------------------------------------------------------------------
// Setup / teardown
// ---------------------------------------------------------------------------

beforeAll(async () => {
  app = await buildTestApp();
});

afterAll(async () => {
  await app.close();
});

beforeEach(() => {
  auditEntries.length = 0;
  _parsedRowsCache.clear();
  _exportStore.clear();
  seedUsersAndSessions();
  seedPatientData();
  vi.mocked(serviceDeps.auditRepo.appendAuditLog).mockClear();
});

// ===========================================================================
// AUDIT TRAIL — Patient CRUD Events
// ===========================================================================

describe('Audit Trail — Patient CRUD Events', () => {
  it('create patient produces patient.created audit entry with masked PHN, creator, source=MANUAL', async () => {
    // Use a Luhn-valid PHN not already in the store
    const res = await physicianRequest('POST', '/api/v1/patients', {
      phn: '100000009',
      first_name: 'Alice',
      last_name: 'Test',
      date_of_birth: '1992-05-10',
      gender: 'F',
    });

    expect(res.statusCode).toBe(201);

    const entry = findAuditEntry(PatientAuditAction.CREATED);
    expect(entry).toBeDefined();
    expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
    expect(entry!.action).toBe('patient.created');
    expect(entry!.category).toBe('patient');
    expect(entry!.resourceType).toBe('patient');
    expect(entry!.resourceId).toBeDefined();

    const detail = entry!.detail as Record<string, unknown>;
    expect(detail).toBeDefined();
    expect(detail.phn).toBe('100******');
    expect(detail.firstName).toBe('Alice');
    expect(detail.lastName).toBe('Test');
    expect(detail.source).toBe('MANUAL');
  });

  it('create patient with null PHN records null in audit (not masked)', async () => {
    const res = await physicianRequest('POST', '/api/v1/patients', {
      first_name: 'Baby',
      last_name: 'Newborn',
      date_of_birth: '2026-01-01',
      gender: 'M',
    });

    expect(res.statusCode).toBe(201);

    const entry = findAuditEntry(PatientAuditAction.CREATED);
    expect(entry).toBeDefined();

    const detail = entry!.detail as Record<string, unknown>;
    expect(detail.phn).toBeNull();
    expect(detail.source).toBe('MANUAL');
  });

  it('update patient produces patient.updated audit entry with field-level diff', async () => {
    const res = await physicianRequest('PUT', `/api/v1/patients/${PATIENT_ID}`, {
      first_name: 'Jonathan',
      city: 'Calgary',
    });

    expect(res.statusCode).toBe(200);

    const entry = findAuditEntry(PatientAuditAction.UPDATED);
    expect(entry).toBeDefined();
    expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
    expect(entry!.action).toBe('patient.updated');
    expect(entry!.category).toBe('patient');
    expect(entry!.resourceType).toBe('patient');
    expect(entry!.resourceId).toBe(PATIENT_ID);

    const detail = entry!.detail as Record<string, unknown>;
    expect(detail.changes).toBeDefined();
    const changes = detail.changes as Record<string, { old: unknown; new: unknown }>;
    expect(changes.firstName).toBeDefined();
    expect(changes.firstName.old).toBe('John');
    expect(changes.firstName.new).toBe('Jonathan');
    expect(changes.city).toBeDefined();
    expect(changes.city.old).toBe('Edmonton');
    expect(changes.city.new).toBe('Calgary');
  });

  it('update patient masks PHN values in diff when PHN changes', async () => {
    // Update PHN to a different Luhn-valid PHN not in the store
    const newPhn = '100000017';
    const res = await physicianRequest('PUT', `/api/v1/patients/${PATIENT_ID}`, {
      phn: newPhn,
    });

    expect(res.statusCode).toBe(200);

    const entry = findAuditEntry(PatientAuditAction.UPDATED);
    expect(entry).toBeDefined();

    const detail = entry!.detail as Record<string, unknown>;
    const changes = detail.changes as Record<string, { old: unknown; new: unknown }>;
    expect(changes.phn).toBeDefined();
    // PHN values should be masked
    expect(changes.phn.old).toBe('123******');
    expect(changes.phn.new).toBe('100******');
    // Raw PHN should NOT appear in audit
    expect(JSON.stringify(entry)).not.toContain(VALID_PHN);
    expect(JSON.stringify(entry)).not.toContain('100000017');
  });

  it('update patient excludes notes from audit diff', async () => {
    const res = await physicianRequest('PUT', `/api/v1/patients/${PATIENT_ID}`, {
      notes: 'Updated clinical notes — confidential',
      first_name: 'UpdatedName',
    });

    expect(res.statusCode).toBe(200);

    const entry = findAuditEntry(PatientAuditAction.UPDATED);
    expect(entry).toBeDefined();

    const detail = entry!.detail as Record<string, unknown>;
    const changes = detail.changes as Record<string, { old: unknown; new: unknown }>;
    // firstName should be in changes
    expect(changes.firstName).toBeDefined();
    // notes should NOT be in changes
    expect(changes.notes).toBeUndefined();
    // Verify notes content doesn't appear anywhere in the audit entry
    expect(JSON.stringify(entry)).not.toContain('clinical notes');
    expect(JSON.stringify(entry)).not.toContain('Private clinical notes');
  });

  it('deactivate patient produces patient.deactivated audit entry with patient_id and actor', async () => {
    const res = await physicianRequest('POST', `/api/v1/patients/${PATIENT_ID}/deactivate`);

    expect(res.statusCode).toBe(200);

    const entry = findAuditEntry(PatientAuditAction.DEACTIVATED);
    expect(entry).toBeDefined();
    expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
    expect(entry!.action).toBe('patient.deactivated');
    expect(entry!.category).toBe('patient');
    expect(entry!.resourceType).toBe('patient');
    expect(entry!.resourceId).toBe(PATIENT_ID);

    const detail = entry!.detail as Record<string, unknown>;
    expect(detail.phn).toBe('123******');
    expect(detail.firstName).toBe('John');
    expect(detail.lastName).toBe('Smith');
  });

  it('reactivate patient produces patient.reactivated audit entry with patient_id and actor', async () => {
    // First deactivate
    patientStore[PATIENT_ID].isActive = false;

    const res = await physicianRequest('POST', `/api/v1/patients/${PATIENT_ID}/reactivate`);

    expect(res.statusCode).toBe(200);

    const entry = findAuditEntry(PatientAuditAction.REACTIVATED);
    expect(entry).toBeDefined();
    expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
    expect(entry!.action).toBe('patient.reactivated');
    expect(entry!.category).toBe('patient');
    expect(entry!.resourceType).toBe('patient');
    expect(entry!.resourceId).toBe(PATIENT_ID);

    const detail = entry!.detail as Record<string, unknown>;
    expect(detail.phn).toBe('123******');
    expect(detail.firstName).toBe('John');
    expect(detail.lastName).toBe('Smith');
  });
});

// ===========================================================================
// AUDIT TRAIL — Merge Events
// ===========================================================================

describe('Audit Trail — Merge Events', () => {
  it('execute merge produces patient.merged audit entry with surviving_id, merged_id, claims_transferred, field_conflicts, actor', async () => {
    const res = await physicianRequest('POST', '/api/v1/patients/merge/execute', {
      surviving_id: PATIENT_ID,
      merged_id: PATIENT_ID_2,
    });

    expect(res.statusCode).toBe(200);

    const entry = findAuditEntry(PatientAuditAction.MERGED);
    expect(entry).toBeDefined();
    expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
    expect(entry!.action).toBe('patient.merged');
    expect(entry!.category).toBe('patient');
    expect(entry!.resourceType).toBe('patient');
    expect(entry!.resourceId).toBe(PATIENT_ID);

    const detail = entry!.detail as Record<string, unknown>;
    expect(detail.surviving_patient_id).toBe(PATIENT_ID);
    expect(detail.merged_patient_id).toBe(PATIENT_ID_2);
    expect(detail.claims_transferred).toBe(2);
    expect(detail.field_conflicts).toBeDefined();
  });

  it('merge audit entry masks PHN values in field_conflicts', async () => {
    const res = await physicianRequest('POST', '/api/v1/patients/merge/execute', {
      surviving_id: PATIENT_ID,
      merged_id: PATIENT_ID_2,
    });

    expect(res.statusCode).toBe(200);

    const entry = findAuditEntry(PatientAuditAction.MERGED);
    expect(entry).toBeDefined();

    const detail = entry!.detail as Record<string, unknown>;
    const conflicts = detail.field_conflicts as Record<string, { surviving: unknown; merged: unknown }>;

    // PHN conflicts should be masked
    expect(conflicts.phn).toBeDefined();
    expect(conflicts.phn.surviving).toBe('123******');
    expect(conflicts.phn.merged).toBe('234******');

    // Non-PHN conflicts should be unmasked
    expect(conflicts.firstName).toBeDefined();
    expect(conflicts.firstName.surviving).toBe('John');
    expect(conflicts.firstName.merged).toBe('Jane');

    // Raw PHN values should NOT appear in the audit entry
    const entryStr = JSON.stringify(entry);
    expect(entryStr).not.toContain(VALID_PHN);
    expect(entryStr).not.toContain(VALID_PHN_2);
  });
});

// ===========================================================================
// AUDIT TRAIL — Import Events
// ===========================================================================

describe('Audit Trail — Import Events', () => {
  it('commit import produces patient.import_completed audit entry with import_id, file_hash, counts, actor', async () => {
    // Prepare a CSV file content
    const csvContent = [
      'FirstName,LastName,DOB,Gender',
      'Bob,Builder,1980-03-01,M',
      'Carol,Singer,1975-08-15,F',
    ].join('\n');
    const fileBuffer = Buffer.from(csvContent);

    // Upload file
    const boundary = '----TestBoundary' + Date.now();
    const body = [
      `--${boundary}`,
      'Content-Disposition: form-data; name="file"; filename="patients.csv"',
      'Content-Type: text/csv',
      '',
      csvContent,
      `--${boundary}--`,
    ].join('\r\n');

    const uploadRes = await app.inject({
      method: 'POST',
      url: '/api/v1/patients/imports',
      headers: {
        cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
        'content-type': `multipart/form-data; boundary=${boundary}`,
      },
      payload: body,
    });

    expect(uploadRes.statusCode).toBe(201);
    const importId = uploadRes.json().data.importId;

    // Clear audit entries from upload
    auditEntries.length = 0;

    // Commit the import
    const commitRes = await physicianRequest('POST', `/api/v1/patients/imports/${importId}/commit`);

    expect(commitRes.statusCode).toBe(200);

    const entry = findAuditEntry(PatientAuditAction.IMPORT_COMPLETED);
    expect(entry).toBeDefined();
    expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
    expect(entry!.action).toBe('patient.import_completed');
    expect(entry!.category).toBe('patient');
    expect(entry!.resourceType).toBe('import_batch');
    expect(entry!.resourceId).toBe(importId);

    const detail = entry!.detail as Record<string, unknown>;
    expect(detail.fileName).toBe('patients.csv');
    expect(detail.totalRows).toBe(2);
    expect(typeof detail.created).toBe('number');
    expect(typeof detail.updated).toBe('number');
    expect(typeof detail.skipped).toBe('number');
    expect(typeof detail.errors).toBe('number');
  });

  it('import audit entry does not contain individual patient PHI', async () => {
    const csvContent = [
      'FirstName,LastName,DOB,Gender,PHN',
      'TestPHI,PatientData,1980-03-01,M,123456780',
    ].join('\n');

    const boundary = '----TestBoundary' + Date.now();
    const body = [
      `--${boundary}`,
      'Content-Disposition: form-data; name="file"; filename="phi-test.csv"',
      'Content-Type: text/csv',
      '',
      csvContent,
      `--${boundary}--`,
    ].join('\r\n');

    const uploadRes = await app.inject({
      method: 'POST',
      url: '/api/v1/patients/imports',
      headers: {
        cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
        'content-type': `multipart/form-data; boundary=${boundary}`,
      },
      payload: body,
    });

    expect(uploadRes.statusCode).toBe(201);
    const importId = uploadRes.json().data.importId;

    auditEntries.length = 0;

    await physicianRequest('POST', `/api/v1/patients/imports/${importId}/commit`);

    const entry = findAuditEntry(PatientAuditAction.IMPORT_COMPLETED);
    expect(entry).toBeDefined();

    // Audit entry should NOT contain individual patient names or PHNs
    const entryStr = JSON.stringify(entry);
    expect(entryStr).not.toContain('TestPHI');
    expect(entryStr).not.toContain('PatientData');
    // Only counts, not data
    const detail = entry!.detail as Record<string, unknown>;
    expect(detail.totalRows).toBeDefined();
    expect(detail.created).toBeDefined();
  });
});

// ===========================================================================
// AUDIT TRAIL — Export Events
// ===========================================================================

describe('Audit Trail — Export Events', () => {
  it('request export produces patient.export_requested audit entry with export_id, row_count, actor', async () => {
    const res = await physicianRequest('POST', '/api/v1/patients/exports');

    expect(res.statusCode).toBe(201);

    const entry = findAuditEntry(PatientAuditAction.EXPORT_REQUESTED);
    expect(entry).toBeDefined();
    expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
    expect(entry!.action).toBe('patient.export_requested');
    expect(entry!.category).toBe('patient');
    expect(entry!.resourceType).toBe('patient_export');
    expect(entry!.resourceId).toBeDefined();

    const detail = entry!.detail as Record<string, unknown>;
    expect(typeof detail.rowCount).toBe('number');
    expect(detail.rowCount).toBeGreaterThanOrEqual(0);
  });

  it('export audit entry contains only row count, no PHI', async () => {
    const res = await physicianRequest('POST', '/api/v1/patients/exports');

    expect(res.statusCode).toBe(201);

    const entry = findAuditEntry(PatientAuditAction.EXPORT_REQUESTED);
    expect(entry).toBeDefined();

    const entryStr = JSON.stringify(entry);
    // Should not contain any patient names, PHNs, or addresses
    expect(entryStr).not.toContain('John');
    expect(entryStr).not.toContain('Smith');
    expect(entryStr).not.toContain('Jane');
    expect(entryStr).not.toContain('Doe');
    expect(entryStr).not.toContain(VALID_PHN);
    expect(entryStr).not.toContain(VALID_PHN_2);
    expect(entryStr).not.toContain('Edmonton');
    expect(entryStr).not.toContain('Calgary');
  });

  it('first access to export status produces patient.export_downloaded audit entry', async () => {
    // Create an export first
    const createRes = await physicianRequest('POST', '/api/v1/patients/exports');
    expect(createRes.statusCode).toBe(201);
    const exportId = createRes.json().data.exportId;

    // Clear audit entries
    auditEntries.length = 0;

    // Get export status (first access)
    const statusRes = await physicianRequest('GET', `/api/v1/patients/exports/${exportId}`);
    expect(statusRes.statusCode).toBe(200);

    const entry = findAuditEntry(PatientAuditAction.EXPORT_DOWNLOADED);
    expect(entry).toBeDefined();
    expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
    expect(entry!.action).toBe('patient.export_downloaded');
    expect(entry!.category).toBe('patient');
    expect(entry!.resourceType).toBe('patient_export');
    expect(entry!.resourceId).toBe(exportId);

    const detail = entry!.detail as Record<string, unknown>;
    expect(typeof detail.rowCount).toBe('number');
  });

  it('second access to export status does NOT produce another download audit entry', async () => {
    const createRes = await physicianRequest('POST', '/api/v1/patients/exports');
    expect(createRes.statusCode).toBe(201);
    const exportId = createRes.json().data.exportId;

    // First access
    await physicianRequest('GET', `/api/v1/patients/exports/${exportId}`);

    // Clear audit entries
    auditEntries.length = 0;

    // Second access
    await physicianRequest('GET', `/api/v1/patients/exports/${exportId}`);

    const entries = findAuditEntries(PatientAuditAction.EXPORT_DOWNLOADED);
    expect(entries.length).toBe(0);
  });
});

// ===========================================================================
// AUDIT TRAIL — Search Audit
// ===========================================================================

describe('Audit Trail — Search Audit', () => {
  it('PHN search produces patient.searched audit entry with search_type=PHN_LOOKUP and masked PHN', async () => {
    const res = await physicianRequest('GET', `/api/v1/patients/search?phn=${VALID_PHN}`);

    expect(res.statusCode).toBe(200);

    const entry = findAuditEntry(PatientAuditAction.SEARCHED);
    expect(entry).toBeDefined();
    expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
    expect(entry!.action).toBe('patient.searched');
    expect(entry!.category).toBe('patient');
    expect(entry!.resourceType).toBe('patient');
    expect(entry!.resourceId).toBeNull();

    const detail = entry!.detail as Record<string, unknown>;
    expect(detail.mode).toBe('PHN_LOOKUP');
    // PHN should be masked in audit
    expect(detail.phn).toBe('123******');
    expect(typeof detail.resultCount).toBe('number');
  });

  it('name search produces patient.searched audit entry with search parameters', async () => {
    const res = await physicianRequest('GET', '/api/v1/patients/search?name=Smith');

    expect(res.statusCode).toBe(200);

    const entry = findAuditEntry(PatientAuditAction.SEARCHED);
    expect(entry).toBeDefined();

    const detail = entry!.detail as Record<string, unknown>;
    expect(detail.mode).toBe('NAME_SEARCH');
    expect(detail.name).toBe('Smith');
    expect(typeof detail.resultCount).toBe('number');
  });

  it('search audit entry does NOT contain search results (only parameters)', async () => {
    const res = await physicianRequest('GET', `/api/v1/patients/search?phn=${VALID_PHN}`);

    expect(res.statusCode).toBe(200);

    const entry = findAuditEntry(PatientAuditAction.SEARCHED);
    expect(entry).toBeDefined();

    const entryStr = JSON.stringify(entry);
    // Should not contain patient data from results
    expect(entryStr).not.toContain('John');
    expect(entryStr).not.toContain('Smith');
    expect(entryStr).not.toContain('1990-01-15');
    // Should not contain raw PHN
    expect(entryStr).not.toContain(VALID_PHN);
    // The detail should only have search params
    const detail = entry!.detail as Record<string, unknown>;
    expect(detail).not.toHaveProperty('patients');
    expect(detail).not.toHaveProperty('results');
    expect(detail).not.toHaveProperty('data');
  });

  it('search audit masks PHN in parameters but not name or DOB', async () => {
    const res = await physicianRequest(
      'GET',
      `/api/v1/patients/search?phn=${VALID_PHN}&name=Smith&dob=1990-01-15`,
    );

    expect(res.statusCode).toBe(200);

    const entry = findAuditEntry(PatientAuditAction.SEARCHED);
    expect(entry).toBeDefined();

    const detail = entry!.detail as Record<string, unknown>;
    expect(detail.mode).toBe('COMBINED');
    expect(detail.phn).toBe('123******');
    expect(detail.name).toBe('Smith');
    expect(detail.dob).toBe('1990-01-15');
  });
});

// ===========================================================================
// AUDIT TRAIL — Entry Structure Verification
// ===========================================================================

describe('Audit Trail — Entry Structure', () => {
  it('every audit entry includes action, actor_id, category, resource_type, and detail', async () => {
    await physicianRequest('POST', '/api/v1/patients', {
      first_name: 'Structure',
      last_name: 'Test',
      date_of_birth: '2000-01-01',
      gender: 'M',
    });

    const entry = findAuditEntry(PatientAuditAction.CREATED);
    expect(entry).toBeDefined();

    // Required fields per audit_log schema
    expect(entry!.action).toBeDefined();
    expect(typeof entry!.action).toBe('string');
    expect(entry!.userId).toBeDefined();
    expect(typeof entry!.userId).toBe('string');
    expect(entry!.category).toBeDefined();
    expect(typeof entry!.category).toBe('string');
    expect(entry!.resourceType).toBeDefined();
    expect(entry!.resourceId).toBeDefined();
    expect(entry!.detail).toBeDefined();
    expect(typeof entry!.detail).toBe('object');
  });

  it('actor_id is the authenticated physician, not a system user', async () => {
    await physicianRequest('POST', `/api/v1/patients/${PATIENT_ID}/deactivate`);

    const entry = findAuditEntry(PatientAuditAction.DEACTIVATED);
    expect(entry).toBeDefined();
    expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
    expect(entry!.userId).not.toBe('system');
    expect(entry!.userId).not.toBe('00000000-0000-0000-0000-000000000000');
  });

  it('audit detail is JSONB-compatible (plain object, no functions or class instances)', async () => {
    // Use a Luhn-valid PHN not already in the store
    await physicianRequest('POST', '/api/v1/patients', {
      phn: '100000025',
      first_name: 'Jsonb',
      last_name: 'Test',
      date_of_birth: '2000-01-01',
      gender: 'M',
    });

    const entry = findAuditEntry(PatientAuditAction.CREATED);
    expect(entry).toBeDefined();

    const detail = entry!.detail;
    // Should survive JSON round-trip without loss
    const serialized = JSON.stringify(detail);
    const deserialized = JSON.parse(serialized);
    expect(deserialized).toEqual(detail);
  });
});

// ===========================================================================
// AUDIT TRAIL — Append-Only Integrity
// ===========================================================================

describe('Audit Trail — Append-Only Integrity', () => {
  it('no UPDATE endpoint exists for audit_log in this domain', async () => {
    const res = await physicianRequest('PUT', '/api/v1/patients/audit-log/some-id');
    expect(res.statusCode).toBe(404);
  });

  it('no DELETE endpoint exists for audit_log in this domain', async () => {
    const res = await physicianRequest('DELETE', '/api/v1/patients/audit-log/some-id');
    expect(res.statusCode).toBe(404);
  });

  it('audit log entries accumulate without overwriting previous entries', async () => {
    // Perform multiple CRUD actions
    await physicianRequest('POST', '/api/v1/patients', {
      first_name: 'First',
      last_name: 'Patient',
      date_of_birth: '1990-01-01',
      gender: 'M',
    });

    await physicianRequest('POST', '/api/v1/patients', {
      first_name: 'Second',
      last_name: 'Patient',
      date_of_birth: '1991-02-02',
      gender: 'F',
    });

    const entries = findAuditEntries(PatientAuditAction.CREATED);
    expect(entries.length).toBe(2);

    const detail0 = entries[0].detail as Record<string, unknown>;
    const detail1 = entries[1].detail as Record<string, unknown>;
    expect(detail0.firstName).toBe('First');
    expect(detail1.firstName).toBe('Second');
  });

  it('multiple different audit actions coexist in the log', async () => {
    // Create
    await physicianRequest('POST', '/api/v1/patients', {
      first_name: 'Multi',
      last_name: 'Action',
      date_of_birth: '1990-01-01',
      gender: 'M',
    });

    // Update existing
    await physicianRequest('PUT', `/api/v1/patients/${PATIENT_ID}`, {
      first_name: 'Updated',
    });

    // Deactivate
    await physicianRequest('POST', `/api/v1/patients/${PATIENT_ID}/deactivate`);

    // Verify all three actions were logged
    expect(findAuditEntry(PatientAuditAction.CREATED)).toBeDefined();
    expect(findAuditEntry(PatientAuditAction.UPDATED)).toBeDefined();
    expect(findAuditEntry(PatientAuditAction.DEACTIVATED)).toBeDefined();

    // Total audit entries should be at least 3
    expect(auditEntries.length).toBeGreaterThanOrEqual(3);
  });
});

// ===========================================================================
// AUDIT TRAIL — PHN Masking Completeness
// ===========================================================================

describe('Audit Trail — PHN Masking in All Audit Entries', () => {
  it('no audit entry contains an unmasked 9-digit PHN', async () => {
    const testPhn1 = '100000033';
    const testPhn2 = '100000041';

    // Trigger multiple actions that touch PHN
    await physicianRequest('POST', '/api/v1/patients', {
      phn: testPhn1,
      first_name: 'Phn',
      last_name: 'Test',
      date_of_birth: '1990-01-01',
      gender: 'M',
    });

    await physicianRequest('PUT', `/api/v1/patients/${PATIENT_ID}`, {
      phn: testPhn2,
    });

    await physicianRequest('POST', `/api/v1/patients/${PATIENT_ID}/deactivate`);

    await physicianRequest('GET', `/api/v1/patients/search?phn=${VALID_PHN}`);

    // Scan all audit entries
    for (const entry of auditEntries) {
      const str = JSON.stringify(entry);
      // Should not contain raw 9-digit PHN
      expect(str).not.toContain(testPhn1);
      expect(str).not.toContain(testPhn2);
      expect(str).not.toContain(VALID_PHN);
      expect(str).not.toContain(VALID_PHN_2);
    }
  });

  it('deactivate audit entry masks PHN', async () => {
    await physicianRequest('POST', `/api/v1/patients/${PATIENT_ID}/deactivate`);

    const entry = findAuditEntry(PatientAuditAction.DEACTIVATED);
    expect(entry).toBeDefined();

    const detail = entry!.detail as Record<string, unknown>;
    expect(detail.phn).toBe('123******');
    expect(JSON.stringify(entry)).not.toContain(VALID_PHN);
  });

  it('reactivate audit entry masks PHN', async () => {
    patientStore[PATIENT_ID].isActive = false;

    await physicianRequest('POST', `/api/v1/patients/${PATIENT_ID}/reactivate`);

    const entry = findAuditEntry(PatientAuditAction.REACTIVATED);
    expect(entry).toBeDefined();

    const detail = entry!.detail as Record<string, unknown>;
    expect(detail.phn).toBe('123******');
    expect(JSON.stringify(entry)).not.toContain(VALID_PHN);
  });
});

// ===========================================================================
// AUDIT TRAIL — Sensitive Data Exclusion
// ===========================================================================

describe('Audit Trail — Sensitive Data Exclusion', () => {
  it('no audit entry contains patient notes', async () => {
    // Create with notes
    await physicianRequest('POST', '/api/v1/patients', {
      first_name: 'Notes',
      last_name: 'Test',
      date_of_birth: '1990-01-01',
      gender: 'M',
      notes: 'Secret clinical observation about patient condition',
    });

    // Update notes on existing patient
    await physicianRequest('PUT', `/api/v1/patients/${PATIENT_ID}`, {
      notes: 'Another secret observation',
    });

    for (const entry of auditEntries) {
      const str = JSON.stringify(entry);
      expect(str).not.toContain('Secret clinical observation');
      expect(str).not.toContain('Another secret observation');
      expect(str).not.toContain('Private clinical notes');
    }
  });

  it('no audit entry contains password hashes', async () => {
    await physicianRequest('POST', '/api/v1/patients', {
      first_name: 'Hash',
      last_name: 'Test',
      date_of_birth: '1990-01-01',
      gender: 'M',
    });

    for (const entry of auditEntries) {
      const str = JSON.stringify(entry);
      expect(str).not.toMatch(/passwordHash/i);
      expect(str).not.toMatch(/password_hash/i);
    }
  });

  it('merge audit does not leak raw PHN through field_conflicts', async () => {
    await physicianRequest('POST', '/api/v1/patients/merge/execute', {
      surviving_id: PATIENT_ID,
      merged_id: PATIENT_ID_2,
    });

    const entry = findAuditEntry(PatientAuditAction.MERGED);
    expect(entry).toBeDefined();

    const entryStr = JSON.stringify(entry);
    expect(entryStr).not.toContain(VALID_PHN);
    expect(entryStr).not.toContain(VALID_PHN_2);
  });

  it('export audit does not contain CSV content or patient data', async () => {
    await physicianRequest('POST', '/api/v1/patients/exports');

    const entry = findAuditEntry(PatientAuditAction.EXPORT_REQUESTED);
    expect(entry).toBeDefined();

    const entryStr = JSON.stringify(entry);
    // Should not contain any CSV headers or patient data
    expect(entryStr).not.toContain('first_name');
    expect(entryStr).not.toContain('last_name');
    expect(entryStr).not.toContain('date_of_birth');
    // Detail should only have rowCount
    const detail = entry!.detail as Record<string, unknown>;
    const keys = Object.keys(detail);
    expect(keys).toEqual(['rowCount']);
  });
});
