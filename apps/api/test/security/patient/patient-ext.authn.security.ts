// ============================================================================
// Patient Extensions — Authentication Enforcement (Security)
// Verifies every new patient extension endpoint returns 401 without session.
// Covers: eligibility check/override/bulk, province detection, CSV import.
// ============================================================================

import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);

vi.mock('otplib', () => ({
  authenticator: {
    options: {},
    generateSecret: vi.fn(() => 'JBSWY3DPEHPK3PXP'),
    keyuri: vi.fn(() => 'otpauth://totp/test'),
    verify: vi.fn(() => false),
  },
}));

import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { patientRoutes } from '../../../src/domains/patient/patient.routes.js';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { type PatientHandlerDeps } from '../../../src/domains/patient/patient.handlers.js';
import { hashToken } from '../../../src/domains/iam/iam.service.js';
import { randomBytes } from 'node:crypto';

const VALID_TOKEN = randomBytes(32).toString('hex');
const VALID_TOKEN_HASH = hashToken(VALID_TOKEN);
const VALID_USER_ID = 'aaaa0000-0000-0000-0000-000000000001';
const VALID_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000001';
const EXPIRED_TOKEN = randomBytes(32).toString('hex');
const EXPIRED_TOKEN_HASH = hashToken(EXPIRED_TOKEN);
const EXPIRED_SESSION_ID = 'cccc0000-0000-0000-0000-000000000001';

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

let sessions: MockSession[] = [];
let users: Array<{ userId: string; role: string; subscriptionStatus: string }> = [];

function createMockSessionRepo() {
  return {
    createSession: vi.fn(async () => ({ sessionId: 'new' })),
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      const session = sessions.find((s) => s.tokenHash === tokenHash && !s.revoked);
      if (!session) return undefined;
      const user = users.find((u) => u.userId === session.userId);
      if (!user) return undefined;
      return { session, user };
    }),
    refreshSession: vi.fn(async () => {}),
    listActiveSessions: vi.fn(async () => []),
    revokeSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
  };
}

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

let app: FastifyInstance;

async function buildTestApp(): Promise<FastifyInstance> {
  const sessionDeps = {
    sessionRepo: createMockSessionRepo(),
    auditRepo: { appendAuditLog: vi.fn(async () => {}) },
    events: { emit: vi.fn() },
  };

  const handlerDeps: PatientHandlerDeps = {
    serviceDeps: {
      repo: createStubPatientRepo() as any,
      auditRepo: { appendAuditLog: vi.fn(async () => {}) },
      events: { emit: vi.fn() },
    },
  };

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);
  await testApp.register(authPluginFp, { sessionDeps });

  testApp.setErrorHandler((error, _request, reply) => {
    if (error.statusCode && error.statusCode >= 400 && error.statusCode < 500) {
      return reply.code(error.statusCode).send({
        error: { code: (error as any).code ?? 'ERROR', message: error.message },
      });
    }
    if (error.validation) {
      return reply.code(400).send({ error: { code: 'VALIDATION_ERROR', message: 'Validation failed' } });
    }
    return reply.code(500).send({ error: { code: 'INTERNAL_ERROR', message: 'Internal server error' } });
  });

  await testApp.register(patientRoutes, { deps: handlerDeps });
  await testApp.ready();
  return testApp;
}

function createTamperedCookie(): string {
  return randomBytes(32).toString('hex').replace(/[0-9a-f]$/, 'x');
}

const DUMMY_UUID = '00000000-0000-0000-0000-000000000001';

interface RouteSpec {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  url: string;
  payload?: Record<string, unknown>;
  description: string;
}

const PATIENT_EXT_ROUTES: RouteSpec[] = [
  // Eligibility
  { method: 'POST', url: '/api/v1/patients/eligibility/check', payload: { phn: '123456789', date_of_service: '2026-02-16' }, description: 'Check eligibility' },
  { method: 'POST', url: '/api/v1/patients/eligibility/override', payload: { phn: '123456789', reason: 'Manual override' }, description: 'Override eligibility' },
  { method: 'POST', url: '/api/v1/patients/eligibility/bulk-check', payload: { entries: [{ phn: '123456789' }] }, description: 'Bulk check eligibility' },
  // Province detection
  { method: 'POST', url: '/api/v1/patients/province/detect', payload: { health_number: '123456789' }, description: 'Detect province' },
  // Patient access export
  { method: 'POST', url: `/api/v1/patients/${DUMMY_UUID}/export`, description: 'Patient access export' },
  { method: 'GET', url: `/api/v1/patients/${DUMMY_UUID}/export/${DUMMY_UUID}/download`, description: 'Download patient export' },
  // CSV Import
  { method: 'GET', url: `/api/v1/patients/imports/${DUMMY_UUID}/preview`, description: 'Preview import' },
  { method: 'POST', url: `/api/v1/patients/imports/${DUMMY_UUID}/commit`, description: 'Commit import' },
  { method: 'GET', url: `/api/v1/patients/imports/${DUMMY_UUID}`, description: 'Get import' },
  // Merge
  { method: 'POST', url: '/api/v1/patients/merge/preview', payload: { surviving_id: '00000000-0000-0000-0000-000000000001', merged_id: '00000000-0000-0000-0000-000000000002' }, description: 'Merge preview' },
  { method: 'POST', url: '/api/v1/patients/merge/execute', payload: { surviving_id: '00000000-0000-0000-0000-000000000001', merged_id: '00000000-0000-0000-0000-000000000002' }, description: 'Merge execute' },
  // Correction
  { method: 'PATCH', url: `/api/v1/patients/${DUMMY_UUID}/correct`, payload: { correction_reason: 'Correcting patient data', first_name: 'Jane' }, description: 'Patient correction' },
];

describe('Patient Extensions — Authentication Enforcement (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });
  afterAll(async () => {
    await app.close();
  });
  beforeEach(() => {
    users = [];
    sessions = [];
    users.push({ userId: VALID_USER_ID, role: 'PHYSICIAN', subscriptionStatus: 'TRIAL' });
    sessions.push({
      sessionId: VALID_SESSION_ID, userId: VALID_USER_ID, tokenHash: VALID_TOKEN_HASH,
      ipAddress: '127.0.0.1', userAgent: 'test', createdAt: new Date(), lastActiveAt: new Date(),
      revoked: false, revokedReason: null,
    });
    sessions.push({
      sessionId: EXPIRED_SESSION_ID, userId: VALID_USER_ID, tokenHash: EXPIRED_TOKEN_HASH,
      ipAddress: '127.0.0.1', userAgent: 'test', createdAt: new Date(Date.now() - 25 * 3600000),
      lastActiveAt: new Date(Date.now() - 7200000), revoked: true, revokedReason: 'expired_absolute',
    });
  });

  describe('No session cookie → 401', () => {
    for (const route of PATIENT_EXT_ROUTES) {
      it(`${route.method} ${route.url} — 401`, async () => {
        const res = await app.inject({
          method: route.method,
          url: route.url,
          ...(route.payload ? { payload: route.payload } : {}),
        });
        expect(res.statusCode).toBe(401);
        const body = JSON.parse(res.body);
        expect(body.error).toBeDefined();
        expect(body.error.code).toBe('UNAUTHORIZED');
        expect(body.data).toBeUndefined();
      });
    }
  });

  describe('Expired session → 401', () => {
    for (const route of PATIENT_EXT_ROUTES) {
      it(`${route.method} ${route.url} — 401 expired`, async () => {
        const res = await app.inject({
          method: route.method, url: route.url,
          headers: { cookie: `session=${EXPIRED_TOKEN}` },
          ...(route.payload ? { payload: route.payload } : {}),
        });
        expect(res.statusCode).toBe(401);
      });
    }
  });

  describe('Tampered cookie → 401', () => {
    for (const route of PATIENT_EXT_ROUTES) {
      it(`${route.method} ${route.url} — 401 tampered`, async () => {
        const res = await app.inject({
          method: route.method, url: route.url,
          headers: { cookie: `session=${createTamperedCookie()}` },
          ...(route.payload ? { payload: route.payload } : {}),
        });
        expect(res.statusCode).toBe(401);
      });
    }
  });

  describe('Empty cookie → 401', () => {
    for (const route of PATIENT_EXT_ROUTES) {
      it(`${route.method} ${route.url} — 401 empty`, async () => {
        const res = await app.inject({
          method: route.method, url: route.url,
          headers: { cookie: 'session=' },
          ...(route.payload ? { payload: route.payload } : {}),
        });
        expect(res.statusCode).toBe(401);
      });
    }
  });

  describe('Wrong cookie name → 401', () => {
    it('cookie "token" → 401', async () => {
      const res = await app.inject({
        method: 'POST', url: '/api/v1/patients/eligibility/check',
        headers: { cookie: `token=${VALID_TOKEN}` },
        payload: { phn: '123456789', date_of_service: '2026-02-16' },
      });
      expect(res.statusCode).toBe(401);
    });
  });

  describe('Sanity: valid session accepted', () => {
    it('POST /api/v1/patients/eligibility/check → not 401', async () => {
      const res = await app.inject({
        method: 'POST', url: '/api/v1/patients/eligibility/check',
        headers: { cookie: `session=${VALID_TOKEN}` },
        payload: { phn: '123456789', date_of_service: '2026-02-16' },
      });
      expect(res.statusCode).not.toBe(401);
    });
  });

  describe('401 does not leak info', () => {
    it('no stack trace in 401', async () => {
      const res = await app.inject({ method: 'POST', url: '/api/v1/patients/eligibility/check', payload: { phn: '123456789', date_of_service: '2026-02-16' } });
      expect(res.statusCode).toBe(401);
      expect(res.body).not.toContain('stack');
      expect(res.body).not.toContain('postgres');
    });
  });
});
