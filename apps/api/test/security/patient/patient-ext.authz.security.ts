// ============================================================================
// Patient Extensions — Authorization Enforcement (Security)
// Delegates with/without PATIENT_VIEW/PATIENT_EDIT permissions.
// ============================================================================

import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);

vi.mock('otplib', () => ({
  authenticator: { options: {}, generateSecret: vi.fn(() => 'JBSWY3DPEHPK3PXP'), keyuri: vi.fn(() => 'otpauth://totp/test'), verify: vi.fn(() => false) },
}));

import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { patientRoutes } from '../../../src/domains/patient/patient.routes.js';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { type PatientHandlerDeps } from '../../../src/domains/patient/patient.handlers.js';
import { hashToken } from '../../../src/domains/iam/iam.service.js';
import { randomBytes } from 'node:crypto';

const PHYSICIAN_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_TOKEN_HASH = hashToken(PHYSICIAN_TOKEN);
const PHYSICIAN_USER_ID = 'aaaa0000-0000-0000-0000-000000000001';

const DELEGATE_VIEW_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_VIEW_TOKEN_HASH = hashToken(DELEGATE_VIEW_TOKEN);
const DELEGATE_VIEW_ID = 'bbbb0000-0000-0000-0000-000000000002';

const DELEGATE_NONE_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_NONE_TOKEN_HASH = hashToken(DELEGATE_NONE_TOKEN);
const DELEGATE_NONE_ID = 'cccc0000-0000-0000-0000-000000000003';

interface MockSession { sessionId: string; userId: string; tokenHash: string; ipAddress: string; userAgent: string; createdAt: Date; lastActiveAt: Date; revoked: boolean; revokedReason: string | null; }
interface MockUser { userId: string; role: string; subscriptionStatus: string; delegateContext?: { delegateUserId: string; physicianProviderId: string; permissions: string[]; linkageId: string; }; }

let sessions: MockSession[] = [];
let users: MockUser[] = [];

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
    createPatient: vi.fn(async () => ({})), findPatientById: vi.fn(async () => undefined),
    findPatientByPhn: vi.fn(async () => undefined), updatePatient: vi.fn(async () => ({})),
    deactivatePatient: vi.fn(async () => ({})), reactivatePatient: vi.fn(async () => ({})),
    updateLastVisitDate: vi.fn(async () => ({})), searchByPhn: vi.fn(async () => undefined),
    searchByName: vi.fn(async () => ({ data: [], pagination: { total: 0, page: 1, pageSize: 20, hasMore: false } })),
    searchByDob: vi.fn(async () => ({ data: [], pagination: { total: 0, page: 1, pageSize: 20, hasMore: false } })),
    searchCombined: vi.fn(async () => ({ data: [], pagination: { total: 0, page: 1, pageSize: 20, hasMore: false } })),
    getRecentPatients: vi.fn(async () => []), createImportBatch: vi.fn(async () => ({})),
    findImportBatchById: vi.fn(async () => undefined), findImportByFileHash: vi.fn(async () => undefined),
    updateImportStatus: vi.fn(async () => ({})),
    listImportBatches: vi.fn(async () => ({ data: [], pagination: { total: 0, page: 1, pageSize: 20, hasMore: false } })),
    bulkCreatePatients: vi.fn(async () => []), bulkUpsertPatients: vi.fn(async () => ({ created: 0, updated: 0 })),
    getMergePreview: vi.fn(async () => null), executeMerge: vi.fn(async () => null),
    listMergeHistory: vi.fn(async () => ({ data: [], pagination: { total: 0, page: 1, pageSize: 20, hasMore: false } })),
    exportActivePatients: vi.fn(async () => []), countActivePatients: vi.fn(async () => 0),
    getPatientClaimContext: vi.fn(async () => null), validatePhnExists: vi.fn(async () => ({ valid: false, exists: false })),
  };
}

let app: FastifyInstance;

async function buildTestApp(): Promise<FastifyInstance> {
  const sessionDeps = { sessionRepo: createMockSessionRepo(), auditRepo: { appendAuditLog: vi.fn(async () => {}) }, events: { emit: vi.fn() } };
  const handlerDeps: PatientHandlerDeps = { serviceDeps: { repo: createStubPatientRepo() as any, auditRepo: { appendAuditLog: vi.fn(async () => {}) }, events: { emit: vi.fn() } } };
  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);
  await testApp.register(authPluginFp, { sessionDeps });
  testApp.setErrorHandler((error, _req, reply) => {
    if (error.statusCode && error.statusCode >= 400 && error.statusCode < 500) return reply.code(error.statusCode).send({ error: { code: (error as any).code ?? 'ERROR', message: error.message } });
    if (error.validation) return reply.code(400).send({ error: { code: 'VALIDATION_ERROR', message: 'Validation failed' } });
    return reply.code(500).send({ error: { code: 'INTERNAL_ERROR', message: 'Internal server error' } });
  });
  await testApp.register(patientRoutes, { deps: handlerDeps });
  await testApp.ready();
  return testApp;
}

const DUMMY_UUID = '00000000-0000-0000-0000-000000000001';

function makeSession(sessionId: string, userId: string, tokenHash: string): MockSession {
  return { sessionId, userId, tokenHash, ipAddress: '127.0.0.1', userAgent: 'test', createdAt: new Date(), lastActiveAt: new Date(), revoked: false, revokedReason: null };
}

function asUser(token: string, method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH', url: string, payload?: unknown) {
  return app.inject({ method, url, headers: { cookie: `session=${token}` }, ...(payload !== undefined ? { payload } : {}) });
}

describe('Patient Extensions — Authorization Enforcement (Security)', () => {
  beforeAll(async () => { app = await buildTestApp(); });
  afterAll(async () => { await app.close(); });
  beforeEach(() => {
    users = []; sessions = [];
    users.push({ userId: PHYSICIAN_USER_ID, role: 'PHYSICIAN', subscriptionStatus: 'TRIAL' });
    sessions.push(makeSession('s1', PHYSICIAN_USER_ID, PHYSICIAN_TOKEN_HASH));
    users.push({ userId: DELEGATE_VIEW_ID, role: 'DELEGATE', subscriptionStatus: 'TRIAL', delegateContext: { delegateUserId: DELEGATE_VIEW_ID, physicianProviderId: PHYSICIAN_USER_ID, permissions: ['PATIENT_VIEW'], linkageId: 'link1' } });
    sessions.push(makeSession('s2', DELEGATE_VIEW_ID, DELEGATE_VIEW_TOKEN_HASH));
    users.push({ userId: DELEGATE_NONE_ID, role: 'DELEGATE', subscriptionStatus: 'TRIAL', delegateContext: { delegateUserId: DELEGATE_NONE_ID, physicianProviderId: PHYSICIAN_USER_ID, permissions: [], linkageId: 'link2' } });
    sessions.push(makeSession('s3', DELEGATE_NONE_ID, DELEGATE_NONE_TOKEN_HASH));
  });

  describe('Delegate without PATIENT_EDIT → 403 on write endpoints', () => {
    const WRITE_EPS = [
      { method: 'POST' as const, url: '/api/v1/patients/eligibility/override', payload: { phn: '123456789', reason: 'Manual override' }, desc: 'Override eligibility' },
      { method: 'POST' as const, url: '/api/v1/patients/merge/execute', payload: { surviving_id: '00000000-0000-0000-0000-000000000001', merged_id: '00000000-0000-0000-0000-000000000002' }, desc: 'Merge execute' },
      { method: 'PATCH' as const, url: `/api/v1/patients/${DUMMY_UUID}/correct`, payload: { correction_reason: 'Correcting patient data', first_name: 'Jane' }, desc: 'Patient correction' },
    ];
    for (const ep of WRITE_EPS) {
      it(`${ep.desc} → 403`, async () => {
        const res = await asUser(DELEGATE_VIEW_TOKEN, ep.method, ep.url, ep.payload);
        expect(res.statusCode).toBe(403);
      });
    }
  });

  describe('Delegate with no permissions → 403', () => {
    const ALL_EPS = [
      { method: 'POST' as const, url: '/api/v1/patients/eligibility/check', payload: { phn: '123456789', date_of_service: '2026-02-16' }, desc: 'Check eligibility' },
      { method: 'POST' as const, url: '/api/v1/patients/eligibility/override', payload: { phn: '123456789', reason: 'Manual override' }, desc: 'Override' },
      { method: 'POST' as const, url: '/api/v1/patients/province/detect', payload: { health_number: '123456789' }, desc: 'Province detect' },
    ];
    for (const ep of ALL_EPS) {
      it(`${ep.desc} → 403`, async () => {
        const res = await asUser(DELEGATE_NONE_TOKEN, ep.method, ep.url, ep.payload);
        expect(res.statusCode).toBe(403);
      });
    }
  });

  describe('Delegate with PATIENT_VIEW → allowed on read endpoints', () => {
    it('POST /api/v1/patients/eligibility/check → not 403', async () => {
      const res = await asUser(DELEGATE_VIEW_TOKEN, 'POST', '/api/v1/patients/eligibility/check', { phn: '123456789', date_of_service: '2026-02-16' });
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });
  });

  describe('403 response shape', () => {
    it('403 includes FORBIDDEN code', async () => {
      const res = await asUser(DELEGATE_NONE_TOKEN, 'POST', '/api/v1/patients/eligibility/check', { phn: '123456789', date_of_service: '2026-02-16' });
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });
  });
});
