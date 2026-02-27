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
// Mock @meritum/shared/constants/claim.constants.js
// ---------------------------------------------------------------------------

vi.mock('@meritum/shared/constants/claim.constants.js', () => {
  return {
    ClaimState: {
      DRAFT: 'DRAFT',
      VALIDATED: 'VALIDATED',
      QUEUED: 'QUEUED',
      SUBMITTED: 'SUBMITTED',
      ASSESSED: 'ASSESSED',
      PAID: 'PAID',
      REJECTED: 'REJECTED',
      ADJUSTED: 'ADJUSTED',
      WRITTEN_OFF: 'WRITTEN_OFF',
      EXPIRED: 'EXPIRED',
      DELETED: 'DELETED',
    },
    TERMINAL_STATES: new Set(['PAID', 'ADJUSTED', 'WRITTEN_OFF', 'EXPIRED', 'DELETED']),
    STATE_TRANSITIONS: {},
    CLAIM_AUDIT_ACTIONS: {},
  };
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
// Fixed test identities
// ---------------------------------------------------------------------------

const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_USER_ID = '22222222-0000-0000-0000-000000000001';
const PHYSICIAN_PROVIDER_ID = PHYSICIAN_USER_ID; // 1:1 mapping
const PHYSICIAN_SESSION_ID = '33333333-0000-0000-0000-000000000001';

// Valid Alberta PHN (passes Luhn): 123456782
const VALID_PHN = '123456782';

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
// Eligibility cache store
// ---------------------------------------------------------------------------

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

function seedEligibilityCache() {
  Object.keys(eligibilityCacheStore).forEach((k) => delete eligibilityCacheStore[k]);
}

// ---------------------------------------------------------------------------
// Mock patient repository (stub — audit tests focus on audit entries)
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

// ---------------------------------------------------------------------------
// Shared service deps ref (accessible to tests for spy inspection)
// ---------------------------------------------------------------------------

let serviceDeps: PatientServiceDeps;
let mockAuditRepo: ReturnType<typeof createMockAuditRepo>;

function createStubServiceDeps(): PatientServiceDeps {
  mockAuditRepo = createMockAuditRepo();
  const deps: PatientServiceDeps = {
    repo: createStubPatientRepo() as any,
    auditRepo: mockAuditRepo,
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
  seedUsersAndSessions();
  seedEligibilityCache();
  vi.mocked(serviceDeps.auditRepo.appendAuditLog).mockClear();
});

// ===========================================================================
// AUDIT TRAIL — Eligibility Check Events
// ===========================================================================

describe('Audit Trail — Eligibility Check Events', () => {
  it('eligibility check produces patient.eligibility_checked audit entry', async () => {
    const res = await physicianRequest('POST', '/api/v1/patients/eligibility/check', {
      phn: VALID_PHN,
    });

    expect(res.statusCode).toBe(200);

    const entry = findAuditEntry('patient.eligibility_checked');
    expect(entry).toBeDefined();
    expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
    expect(entry!.action).toBe('patient.eligibility_checked');
    expect(entry!.category).toBe('patient');
    expect(entry!.resourceType).toBe('eligibility');

    const detail = entry!.detail as Record<string, unknown>;
    expect(detail).toBeDefined();
    expect(detail.phn_masked).toBeDefined();
    expect(detail.source).toBeDefined();
  });

  it('eligibility check audit entry contains masked PHN, not raw', async () => {
    const res = await physicianRequest('POST', '/api/v1/patients/eligibility/check', {
      phn: VALID_PHN,
    });

    expect(res.statusCode).toBe(200);

    const entry = findAuditEntry('patient.eligibility_checked');
    expect(entry).toBeDefined();

    const detail = entry!.detail as Record<string, unknown>;
    expect(detail.phn_masked).toBe('123******');

    // Raw PHN must NOT appear anywhere in the audit entry
    const entryStr = JSON.stringify(entry);
    expect(entryStr).not.toContain(VALID_PHN);
  });

  it('eligibility check audit entry records source (HLINK for fresh check)', async () => {
    const res = await physicianRequest('POST', '/api/v1/patients/eligibility/check', {
      phn: VALID_PHN,
    });

    expect(res.statusCode).toBe(200);

    const entry = findAuditEntry('patient.eligibility_checked');
    expect(entry).toBeDefined();

    const detail = entry!.detail as Record<string, unknown>;
    expect(detail.source).toBe('HLINK');
  });

  it('eligibility check with date_of_service records it in audit detail', async () => {
    const res = await physicianRequest('POST', '/api/v1/patients/eligibility/check', {
      phn: VALID_PHN,
      date_of_service: '2026-02-15',
    });

    expect(res.statusCode).toBe(200);

    const entry = findAuditEntry('patient.eligibility_checked');
    expect(entry).toBeDefined();

    const detail = entry!.detail as Record<string, unknown>;
    expect(detail.date_of_service).toBe('2026-02-15');
  });

  it('cached eligibility check produces audit entry with source=CACHE', async () => {
    // First check — populates cache
    await physicianRequest('POST', '/api/v1/patients/eligibility/check', {
      phn: VALID_PHN,
    });

    // Clear audit entries to isolate the second check
    auditEntries.length = 0;

    // Second check — should hit cache
    const res = await physicianRequest('POST', '/api/v1/patients/eligibility/check', {
      phn: VALID_PHN,
    });

    expect(res.statusCode).toBe(200);

    const entries = findAuditEntries('patient.eligibility_checked');
    expect(entries.length).toBeGreaterThan(0);

    const detail = entries[0].detail as Record<string, unknown>;
    expect(detail.source).toBe('CACHE');
    expect(detail.phn_masked).toBe('123******');

    // Raw PHN must NOT appear
    const entryStr = JSON.stringify(entries[0]);
    expect(entryStr).not.toContain(VALID_PHN);
  });
});

// ===========================================================================
// AUDIT TRAIL — Eligibility Override Events
// ===========================================================================

describe('Audit Trail — Eligibility Override Events', () => {
  it('eligibility override produces patient.eligibility_overridden audit entry with reason', async () => {
    const overrideReason = 'Patient confirmed eligible via phone call with AHCIP';

    const res = await physicianRequest('POST', '/api/v1/patients/eligibility/override', {
      phn: VALID_PHN,
      reason: overrideReason,
    });

    expect(res.statusCode).toBe(200);

    const entry = findAuditEntry('patient.eligibility_overridden');
    expect(entry).toBeDefined();
    expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
    expect(entry!.action).toBe('patient.eligibility_overridden');
    expect(entry!.category).toBe('patient');
    expect(entry!.resourceType).toBe('eligibility');

    const detail = entry!.detail as Record<string, unknown>;
    expect(detail).toBeDefined();
    expect(detail.phn_masked).toBe('123******');
    expect(detail.reason).toBe(overrideReason);
  });

  it('eligibility override audit entry does not contain raw PHN', async () => {
    await physicianRequest('POST', '/api/v1/patients/eligibility/override', {
      phn: VALID_PHN,
      reason: 'Patient eligibility confirmed',
    });

    const entry = findAuditEntry('patient.eligibility_overridden');
    expect(entry).toBeDefined();

    // Raw PHN must NOT appear anywhere in the audit entry
    const entryStr = JSON.stringify(entry);
    expect(entryStr).not.toContain(VALID_PHN);
    // Masked PHN must appear
    expect(entryStr).toContain('123******');
  });

  it('eligibility override audit entry records the reason text', async () => {
    const reason = 'Verbal confirmation from AHCIP registry';

    await physicianRequest('POST', '/api/v1/patients/eligibility/override', {
      phn: VALID_PHN,
      reason,
    });

    const entry = findAuditEntry('patient.eligibility_overridden');
    expect(entry).toBeDefined();

    const detail = entry!.detail as Record<string, unknown>;
    expect(detail.reason).toBe(reason);
  });
});

// ===========================================================================
// AUDIT TRAIL — Audit entries never contain raw PHN
// ===========================================================================

describe('Audit entries never contain raw PHN', () => {
  it('all eligibility audit entries mask PHN', async () => {
    // Trigger multiple eligibility operations
    await physicianRequest('POST', '/api/v1/patients/eligibility/check', {
      phn: VALID_PHN,
    });
    await physicianRequest('POST', '/api/v1/patients/eligibility/override', {
      phn: VALID_PHN,
      reason: 'Override test',
    });

    // Scan ALL audit entries for raw PHN
    const allAuditsStr = JSON.stringify(auditEntries);
    expect(allAuditsStr).not.toContain(VALID_PHN);

    // Verify masked format IS present
    expect(allAuditsStr).toContain('123******');
  });

  it('bulk eligibility audit entries do not contain raw PHN', async () => {
    const res = await physicianRequest('POST', '/api/v1/patients/eligibility/bulk-check', {
      entries: [
        { phn: VALID_PHN },
      ],
    });

    expect(res.statusCode).toBe(200);

    // Scan all audit entries for raw PHN
    const allAuditsStr = JSON.stringify(auditEntries);
    expect(allAuditsStr).not.toContain(VALID_PHN);
  });

  it('province detection audit entry does not leak health number', async () => {
    await physicianRequest('POST', '/api/v1/patients/province/detect', {
      health_number: VALID_PHN,
    });

    const entry = findAuditEntry('patient.province_detected');
    expect(entry).toBeDefined();

    // The full health number should NOT appear in the audit
    const entryStr = JSON.stringify(entry);
    expect(entryStr).not.toContain(VALID_PHN);
  });
});

// ===========================================================================
// AUDIT TRAIL — Mock auditRepo captures entries correctly
// ===========================================================================

describe('Mock auditRepo captures entries correctly', () => {
  it('auditRepo.appendAuditLog is called for eligibility check', async () => {
    await physicianRequest('POST', '/api/v1/patients/eligibility/check', {
      phn: VALID_PHN,
    });

    expect(serviceDeps.auditRepo.appendAuditLog).toHaveBeenCalled();
    expect(auditEntries.length).toBeGreaterThan(0);
  });

  it('auditRepo.appendAuditLog is called for eligibility override', async () => {
    await physicianRequest('POST', '/api/v1/patients/eligibility/override', {
      phn: VALID_PHN,
      reason: 'Test reason',
    });

    expect(serviceDeps.auditRepo.appendAuditLog).toHaveBeenCalled();

    const overrideEntries = findAuditEntries('patient.eligibility_overridden');
    expect(overrideEntries.length).toBeGreaterThan(0);
  });

  it('audit entries have required fields: userId, action, category', async () => {
    await physicianRequest('POST', '/api/v1/patients/eligibility/check', {
      phn: VALID_PHN,
    });

    const entry = findAuditEntry('patient.eligibility_checked');
    expect(entry).toBeDefined();
    expect(entry!.userId).toBeDefined();
    expect(entry!.action).toBeDefined();
    expect(entry!.category).toBeDefined();
  });
});
