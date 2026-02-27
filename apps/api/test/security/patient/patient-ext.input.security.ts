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
// Fixed test user/session
// ---------------------------------------------------------------------------

const FIXED_SESSION_TOKEN = randomBytes(32).toString('hex');
const FIXED_SESSION_TOKEN_HASH = hashToken(FIXED_SESSION_TOKEN);
const FIXED_USER_ID = '22222222-0000-0000-0000-000000000001';
const FIXED_PROVIDER_ID = FIXED_USER_ID;
const FIXED_SESSION_ID = '33333333-0000-0000-0000-000000000001';

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
  role?: string;
  subscriptionStatus?: string;
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
// Mock repositories
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    createSession: vi.fn(async () => {
      return { sessionId: '44444444-0000-0000-0000-000000000001' };
    }),
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      const session = sessions.find((s) => s.tokenHash === tokenHash && !s.revoked);
      if (!session) return undefined;
      const user = users.find((u) => u.userId === session.userId);
      if (!user) return undefined;
      return {
        session,
        user: {
          userId: user.userId,
          role: user.role ?? 'PHYSICIAN',
          subscriptionStatus: user.subscriptionStatus ?? 'TRIAL',
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
// Mock patient repository
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
    getCachedEligibility: vi.fn(async () => undefined),
    setCachedEligibility: vi.fn(async () => ({})),
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
let mockSessionRepo: ReturnType<typeof createMockSessionRepo>;

async function buildTestApp(): Promise<FastifyInstance> {
  mockSessionRepo = createMockSessionRepo();

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
  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function authCookie(): string {
  return `session=${FIXED_SESSION_TOKEN}`;
}

async function authedRequest(
  method: 'GET' | 'POST' | 'PUT' | 'DELETE',
  url: string,
  payload?: unknown,
) {
  return app.inject({
    method,
    url,
    headers: { cookie: authCookie() },
    ...(payload !== undefined ? { payload } : {}),
  });
}

/** Verify error response has no internal system details */
function assertNoInternalLeakage(body: string) {
  const lower = (typeof body === 'string' ? body : JSON.stringify(body)).toLowerCase();
  expect(lower).not.toContain('stack');
  expect(lower).not.toContain('node_modules');
  expect(lower).not.toContain('postgres');
  expect(lower).not.toContain('drizzle');
}

// ---------------------------------------------------------------------------
// SQL Injection Payloads
// ---------------------------------------------------------------------------

const SQL_INJECTION_PAYLOADS = [
  "'; DROP TABLE patients;--",
  "' OR 1=1--",
  "1; SELECT * FROM users --",
  "' UNION SELECT * FROM providers --",
  "'; DELETE FROM patients;--",
  "1' OR '1'='1",
  "Robert'); DROP TABLE students;--",
];

// ---------------------------------------------------------------------------
// XSS Payloads
// ---------------------------------------------------------------------------

const XSS_PAYLOADS = [
  '<script>alert("xss")</script>',
  '<img src=x onerror=alert(1)>',
  'javascript:alert(1)',
  '<svg onload=alert(1)>',
  '"><script>alert(document.cookie)</script>',
];

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Patient Extensions — PHN Injection & Input Validation (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    users = [];
    sessions = [];
    auditEntries = [];

    users.push({
      userId: FIXED_USER_ID,
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
      sessionId: FIXED_SESSION_ID,
      userId: FIXED_USER_ID,
      tokenHash: FIXED_SESSION_TOKEN_HASH,
      ipAddress: '127.0.0.1',
      userAgent: 'test-agent',
      createdAt: new Date(),
      lastActiveAt: new Date(),
      revoked: false,
      revokedReason: null,
    });
  });

  // =========================================================================
  // 1. SQL Injection in PHN field — eligibility/check
  // =========================================================================

  describe('SQL Injection — Eligibility Check PHN field', () => {
    for (const payload of SQL_INJECTION_PAYLOADS) {
      it(`rejects SQL injection in eligibility/check phn: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('POST', '/api/v1/patients/eligibility/check', {
          phn: payload,
        });

        // PHN has regex /^\d{9}$/ and length(9) — all SQL payloads are rejected by Zod
        expect(res.statusCode).toBe(400);
        assertNoInternalLeakage(res.body);
      });
    }
  });

  // =========================================================================
  // 2. SQL Injection in PHN field — province/detect
  // =========================================================================

  describe('SQL Injection — Province Detection health_number field', () => {
    for (const payload of SQL_INJECTION_PAYLOADS) {
      it(`handles SQL injection in province/detect safely: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('POST', '/api/v1/patients/province/detect', {
          health_number: payload,
        });

        // health_number has max(12) — longer payloads rejected by Zod.
        // Shorter ones pass Zod and reach service mock safely.
        if (payload.length > 12) {
          expect(res.statusCode).toBe(400);
        }
        assertNoInternalLeakage(res.body);
        expect(res.headers['content-type']).toContain('application/json');
      });
    }
  });

  // =========================================================================
  // 3. XSS in PHN and name fields via eligibility endpoints
  // =========================================================================

  describe('XSS Prevention — Eligibility Check', () => {
    for (const payload of XSS_PAYLOADS) {
      it(`rejects XSS in eligibility/check phn: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('POST', '/api/v1/patients/eligibility/check', {
          phn: payload,
        });

        // PHN is strictly /^\d{9}$/ — all XSS payloads are rejected by Zod
        expect(res.statusCode).toBe(400);
        expect(res.headers['content-type']).toContain('application/json');
      });
    }

    for (const payload of XSS_PAYLOADS) {
      it(`handles XSS in eligibility/override phn safely: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('POST', '/api/v1/patients/eligibility/override', {
          phn: payload,
          reason: 'Test override',
        });

        // PHN is strictly /^\d{9}$/ — all XSS payloads are rejected
        expect(res.statusCode).toBe(400);
        expect(res.headers['content-type']).toContain('application/json');
      });
    }

    for (const payload of XSS_PAYLOADS) {
      it(`handles XSS in override reason safely: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('POST', '/api/v1/patients/eligibility/override', {
          phn: '123456789',
          reason: payload,
        });

        // reason has max(500) — XSS payloads pass Zod but are handled safely.
        // Response must be JSON.
        expect(res.headers['content-type']).toContain('application/json');
        assertNoInternalLeakage(res.body);
      });
    }
  });

  describe('XSS Prevention — Province Detection', () => {
    for (const payload of XSS_PAYLOADS) {
      it(`handles XSS in province/detect health_number: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('POST', '/api/v1/patients/province/detect', {
          health_number: payload,
        });

        // health_number has max(12) — longer payloads rejected.
        if (payload.length > 12) {
          expect(res.statusCode).toBe(400);
        }
        expect(res.headers['content-type']).toContain('application/json');
      });
    }
  });

  // =========================================================================
  // 4. Invalid PHN formats rejected
  // =========================================================================

  describe('Invalid PHN formats rejected', () => {
    it('rejects PHN that is too short (5 digits)', async () => {
      const res = await authedRequest('POST', '/api/v1/patients/eligibility/check', {
        phn: '12345',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects PHN that is too long (12 digits)', async () => {
      const res = await authedRequest('POST', '/api/v1/patients/eligibility/check', {
        phn: '123456789012',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects non-numeric PHN (letters)', async () => {
      const res = await authedRequest('POST', '/api/v1/patients/eligibility/check', {
        phn: 'ABCDEFGHI',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects PHN with mixed alphanumeric', async () => {
      const res = await authedRequest('POST', '/api/v1/patients/eligibility/check', {
        phn: '1234ABCDE',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects PHN with special characters', async () => {
      const res = await authedRequest('POST', '/api/v1/patients/eligibility/check', {
        phn: '12345-678',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects empty PHN', async () => {
      const res = await authedRequest('POST', '/api/v1/patients/eligibility/check', {
        phn: '',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });
  });

  // =========================================================================
  // 5. Type coercion attacks
  // =========================================================================

  describe('Type Coercion — Eligibility Check', () => {
    it('rejects number instead of string for phn in eligibility/check', async () => {
      const res = await authedRequest('POST', '/api/v1/patients/eligibility/check', {
        phn: 123456789,
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects array instead of string for phn in eligibility/check', async () => {
      const res = await authedRequest('POST', '/api/v1/patients/eligibility/check', {
        phn: ['123456789'],
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects object instead of string for phn in eligibility/check', async () => {
      const res = await authedRequest('POST', '/api/v1/patients/eligibility/check', {
        phn: { value: '123456789' },
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects boolean instead of string for phn in eligibility/check', async () => {
      const res = await authedRequest('POST', '/api/v1/patients/eligibility/check', {
        phn: true,
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects number instead of string for phn in eligibility/override', async () => {
      const res = await authedRequest('POST', '/api/v1/patients/eligibility/override', {
        phn: 123456789,
        reason: 'Override reason',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects number instead of string for health_number in province/detect', async () => {
      const res = await authedRequest('POST', '/api/v1/patients/province/detect', {
        health_number: 123456789,
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });
  });

  // =========================================================================
  // 6. UUID validation on patient ID params
  // =========================================================================

  describe('UUID validation on patient ID params', () => {
    it('rejects non-UUID patient ID in GET /api/v1/patients/:id', async () => {
      const res = await authedRequest('GET', '/api/v1/patients/not-a-uuid');
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects SQL injection in patient ID param', async () => {
      const res = await authedRequest('GET', "/api/v1/patients/'; DROP TABLE patients;--");
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects numeric patient ID', async () => {
      const res = await authedRequest('GET', '/api/v1/patients/12345');
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('accepts valid UUID patient ID (returns 404 for missing)', async () => {
      const res = await authedRequest('GET', `/api/v1/patients/${PLACEHOLDER_UUID}`);
      // Valid UUID but patient doesn't exist — returns 404 (not 400)
      expect(res.statusCode).toBe(404);
    });
  });

  // =========================================================================
  // 7. Error responses don't echo malicious input
  // =========================================================================

  describe('Error responses do not echo malicious input', () => {
    it('eligibility check error does not echo SQL injection payload', async () => {
      const maliciousPayload = "'; DROP TABLE patients;--";
      const res = await authedRequest('POST', '/api/v1/patients/eligibility/check', {
        phn: maliciousPayload,
      });

      expect(res.statusCode).toBe(400);
      // The malicious payload should NOT be reflected in the error response
      expect(res.body).not.toContain('DROP TABLE');
      expect(res.body).not.toContain('patients;--');
    });

    it('eligibility check error does not echo XSS payload', async () => {
      const xssPayload = '<script>alert("xss")</script>';
      const res = await authedRequest('POST', '/api/v1/patients/eligibility/check', {
        phn: xssPayload,
      });

      expect(res.statusCode).toBe(400);
      expect(res.body).not.toContain('<script>');
      expect(res.body).not.toContain('alert(');
    });

    it('province detect error does not echo malicious health_number', async () => {
      const malicious = "' UNION SELECT password FROM users --";
      const res = await authedRequest('POST', '/api/v1/patients/province/detect', {
        health_number: malicious,
      });

      // Payload exceeds max(12) — rejected at validation
      expect(res.statusCode).toBe(400);
      expect(res.body).not.toContain('UNION SELECT');
      expect(res.body).not.toContain('password');
    });

    it('patient ID param error does not echo malicious input', async () => {
      const malicious = '<img src=x onerror=alert(1)>';
      const res = await authedRequest('GET', `/api/v1/patients/${encodeURIComponent(malicious)}`);

      expect(res.statusCode).toBe(400);
      expect(res.body).not.toContain('<img');
      expect(res.body).not.toContain('onerror');
    });
  });

  // =========================================================================
  // 8. Bulk eligibility rejects invalid entries
  // =========================================================================

  describe('Bulk Eligibility — Input Validation', () => {
    it('rejects bulk eligibility with SQL injection in PHN entry', async () => {
      const res = await authedRequest('POST', '/api/v1/patients/eligibility/bulk-check', {
        entries: [
          { phn: "'; DROP TABLE patients;--" },
        ],
      });

      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects bulk eligibility with non-numeric PHN entry', async () => {
      const res = await authedRequest('POST', '/api/v1/patients/eligibility/bulk-check', {
        entries: [
          { phn: 'ABCDEFGHI' },
        ],
      });

      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects bulk eligibility with number type PHN entry', async () => {
      const res = await authedRequest('POST', '/api/v1/patients/eligibility/bulk-check', {
        entries: [
          { phn: 123456789 },
        ],
      });

      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });
  });
});
