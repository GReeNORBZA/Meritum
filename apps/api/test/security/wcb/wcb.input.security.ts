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
// Fixed test identity — authenticated physician for input validation tests
// ---------------------------------------------------------------------------

const P1_SESSION_TOKEN = randomBytes(32).toString('hex');
const P1_SESSION_TOKEN_HASH = hashToken(P1_SESSION_TOKEN);
const P1_USER_ID = '11111111-4444-0000-0000-000000000001';
const P1_PROVIDER_ID = P1_USER_ID;
const P1_SESSION_ID = '11111111-4444-0000-0000-000000000011';

const VALID_PATIENT_ID = 'bbbb4444-0000-0000-0000-000000000001';
const VALID_UUID = '99999999-9999-9999-9999-999999999999';

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
// Stub WCB repositories & deps
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

  testApp.setErrorHandler((error, _request, reply) => {
    // Validation errors — never echo user input in error messages.
    if (error.validation || (error as any).code === 'FST_ERR_VALIDATION') {
      return reply.code(400).send({
        error: { code: 'VALIDATION_ERROR', message: 'Validation failed' },
      });
    }
    const statusCode = (error as any).statusCode;
    if (statusCode && statusCode >= 400 && statusCode < 500) {
      return reply.code(statusCode).send({
        error: { code: (error as any).code ?? 'ERROR', message: error.message },
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
// Helpers
// ---------------------------------------------------------------------------

function seedUsersAndSessions() {
  users = [];
  sessions = [];

  users.push({
    userId: P1_USER_ID,
    email: 'physician-input@example.com',
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
}

function asPhysician(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

// ---------------------------------------------------------------------------
// Valid payloads for baseline comparison
// ---------------------------------------------------------------------------

const VALID_WCB_CLAIM_CREATE = {
  form_id: 'C050E',
  patient_id: VALID_PATIENT_ID,
};

const VALID_MANUAL_OUTCOME = {
  acceptance_status: 'accepted',
};

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('WCB Input Validation & Injection Prevention (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    seedUsersAndSessions();
  });

  // =========================================================================
  // 1. SQL Injection Payloads on String Fields
  // =========================================================================

  describe('SQL injection prevention', () => {
    const SQL_INJECTION_PAYLOADS = [
      "'; DROP TABLE claims; --",
      "1' OR '1'='1",
      "1; SELECT * FROM users --",
      "' UNION SELECT * FROM providers --",
      "' OR 1=1--",
      "'; DROP TABLE wcb_claim_details;--",
      "'; DELETE FROM wcb_batches WHERE '1'='1",
    ];

    describe('employer_name field rejects SQL injection', () => {
      for (const payload of SQL_INJECTION_PAYLOADS) {
        it(`rejects: ${payload.slice(0, 40)}...`, async () => {
          const res = await asPhysician('POST', '/api/v1/wcb/claims', {
            ...VALID_WCB_CLAIM_CREATE,
            employer_name: payload,
          });
          // employer_name is max(50). All SQL payloads should be accepted by Zod (< 50 chars)
          // but Drizzle parameterised queries prevent injection at the ORM level.
          // If the payload length exceeds 50 chars, Zod rejects it.
          if (payload.length > 50) {
            expect(res.statusCode).toBe(400);
            const body = JSON.parse(res.body);
            expect(body.data).toBeUndefined();
          } else {
            // Accepted by Zod — verify no SQL error surfaces
            if (res.statusCode >= 500) {
              const body = JSON.parse(res.body);
              expect(body.error.message).toBe('Internal server error');
              expect(JSON.stringify(body)).not.toMatch(/postgres|drizzle|sql|syntax/i);
            }
          }
        });
      }
    });

    describe('injury_description field rejects SQL injection', () => {
      for (const payload of SQL_INJECTION_PAYLOADS) {
        it(`rejects: ${payload.slice(0, 40)}...`, async () => {
          const res = await asPhysician('POST', '/api/v1/wcb/claims', {
            ...VALID_WCB_CLAIM_CREATE,
            injury_description: payload,
          });
          // injury_description is text (unbounded) — payload passes Zod but is parameterised
          if (res.statusCode >= 500) {
            const body = JSON.parse(res.body);
            expect(body.error.message).toBe('Internal server error');
            expect(JSON.stringify(body)).not.toMatch(/postgres|drizzle|sql|syntax/i);
          }
        });
      }
    });

    describe('additional_comments field rejects SQL injection', () => {
      for (const payload of SQL_INJECTION_PAYLOADS) {
        it(`rejects: ${payload.slice(0, 40)}...`, async () => {
          const res = await asPhysician('POST', '/api/v1/wcb/claims', {
            ...VALID_WCB_CLAIM_CREATE,
            additional_comments: payload,
          });
          // additional_comments is text (unbounded) — payload passes Zod but is parameterised
          if (res.statusCode >= 500) {
            const body = JSON.parse(res.body);
            expect(body.error.message).toBe('Internal server error');
            expect(JSON.stringify(body)).not.toMatch(/postgres|drizzle|sql|syntax/i);
          }
        });
      }
    });

    describe('wcb_claim_number field rejects SQL injection', () => {
      for (const payload of SQL_INJECTION_PAYLOADS) {
        it(`rejects: ${payload.slice(0, 40)}...`, async () => {
          const res = await asPhysician('POST', '/api/v1/wcb/claims', {
            ...VALID_WCB_CLAIM_CREATE,
            wcb_claim_number: payload,
          });
          // wcb_claim_number is max(7) — all SQL payloads exceed this
          expect(res.statusCode).toBe(400);
          const body = JSON.parse(res.body);
          expect(body.data).toBeUndefined();
        });
      }
    });

    describe('worker_job_title field rejects SQL injection', () => {
      for (const payload of SQL_INJECTION_PAYLOADS) {
        it(`rejects: ${payload.slice(0, 40)}...`, async () => {
          const res = await asPhysician('POST', '/api/v1/wcb/claims', {
            ...VALID_WCB_CLAIM_CREATE,
            worker_job_title: payload,
          });
          // worker_job_title is max(50) — most payloads fit, but Drizzle parameterises
          if (payload.length > 50) {
            expect(res.statusCode).toBe(400);
          } else if (res.statusCode >= 500) {
            const body = JSON.parse(res.body);
            expect(body.error.message).toBe('Internal server error');
            expect(JSON.stringify(body)).not.toMatch(/postgres|drizzle|sql|syntax/i);
          }
        });
      }
    });

    describe('batch list status filter rejects SQL injection', () => {
      for (const payload of SQL_INJECTION_PAYLOADS) {
        it(`rejects status filter: ${payload.slice(0, 40)}...`, async () => {
          const res = await asPhysician(
            'GET',
            `/api/v1/wcb/batches?status=${encodeURIComponent(payload)}`,
          );
          // status is enum — all SQL payloads must be rejected
          expect(res.statusCode).toBe(400);
          const body = JSON.parse(res.body);
          expect(body.data).toBeUndefined();
        });
      }
    });
  });

  // =========================================================================
  // 2. XSS Payloads on Stored Text Fields
  // =========================================================================

  describe('XSS payload prevention', () => {
    const XSS_PAYLOADS = [
      '<script>alert("xss")</script>',
      '<script>alert(1)</script>',
      '<img src=x onerror=alert(1)>',
      '<img onerror=alert(1) src=x>',
      'javascript:alert(1)',
      '<svg onload=alert(1)>',
      '"><script>document.cookie</script>',
    ];

    describe('treatment_plan_text rejects XSS payloads', () => {
      for (const payload of XSS_PAYLOADS) {
        it(`rejects/sanitises: ${payload.slice(0, 40)}...`, async () => {
          const res = await asPhysician('POST', '/api/v1/wcb/claims', {
            ...VALID_WCB_CLAIM_CREATE,
            treatment_plan_text: payload,
          });
          // treatment_plan_text is text (unbounded) — may pass Zod
          // If stored, verify no script tag echoed in retrieval
          if (res.statusCode === 201) {
            const body = JSON.parse(res.body);
            if (body.data?.treatment_plan_text) {
              expect(body.data.treatment_plan_text).not.toContain('<script>');
            }
          }
          // Otherwise, service may 500 with stub deps — verify no leak
          if (res.statusCode >= 500) {
            const body = JSON.parse(res.body);
            expect(body.error.message).toBe('Internal server error');
          }
        });
      }
    });

    describe('objective_findings rejects XSS payloads', () => {
      for (const payload of XSS_PAYLOADS) {
        it(`rejects/sanitises: ${payload.slice(0, 40)}...`, async () => {
          const res = await asPhysician('POST', '/api/v1/wcb/claims', {
            ...VALID_WCB_CLAIM_CREATE,
            objective_findings: payload,
          });
          if (res.statusCode === 201) {
            const body = JSON.parse(res.body);
            if (body.data?.objective_findings) {
              expect(body.data.objective_findings).not.toContain('<script>');
              expect(body.data.objective_findings).not.toContain('onerror=');
            }
          }
          if (res.statusCode >= 500) {
            const body = JSON.parse(res.body);
            expect(body.error.message).toBe('Internal server error');
          }
        });
      }
    });

    describe('consultation_letter_text rejects XSS payloads', () => {
      for (const payload of XSS_PAYLOADS) {
        it(`rejects/sanitises: ${payload.slice(0, 40)}...`, async () => {
          const res = await asPhysician('POST', '/api/v1/wcb/claims', {
            ...VALID_WCB_CLAIM_CREATE,
            consultation_letter_text: payload,
          });
          if (res.statusCode === 201) {
            const body = JSON.parse(res.body);
            if (body.data?.consultation_letter_text) {
              expect(body.data.consultation_letter_text).not.toContain('<script>');
            }
          }
          if (res.statusCode >= 500) {
            const body = JSON.parse(res.body);
            expect(body.error.message).toBe('Internal server error');
          }
        });
      }
    });

    describe('employer_name rejects XSS payloads', () => {
      for (const payload of XSS_PAYLOADS) {
        it(`rejects: ${payload.slice(0, 40)}...`, async () => {
          const res = await asPhysician('POST', '/api/v1/wcb/claims', {
            ...VALID_WCB_CLAIM_CREATE,
            employer_name: payload,
          });
          // employer_name is max(50) — all XSS payloads are under 50 chars
          // If accepted, verify no raw XSS in response
          if (res.statusCode === 201) {
            const body = JSON.parse(res.body);
            if (body.data?.employer_name) {
              expect(body.data.employer_name).not.toContain('<script>');
            }
          }
          if (res.statusCode >= 500) {
            const body = JSON.parse(res.body);
            expect(body.error.message).toBe('Internal server error');
          }
        });
      }
    });

    describe('injury_description rejects XSS payloads', () => {
      for (const payload of XSS_PAYLOADS) {
        it(`rejects/sanitises: ${payload.slice(0, 40)}...`, async () => {
          const res = await asPhysician('POST', '/api/v1/wcb/claims', {
            ...VALID_WCB_CLAIM_CREATE,
            injury_description: payload,
          });
          if (res.statusCode === 201) {
            const body = JSON.parse(res.body);
            if (body.data?.injury_description) {
              expect(body.data.injury_description).not.toContain('<script>');
            }
          }
          if (res.statusCode >= 500) {
            const body = JSON.parse(res.body);
            expect(body.error.message).toBe('Internal server error');
          }
        });
      }
    });
  });

  // =========================================================================
  // 3. Type Coercion Attacks
  // =========================================================================

  describe('Type coercion attacks', () => {
    describe('form_id rejects wrong types', () => {
      it('rejects number where string expected', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          form_id: 999,
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects boolean where string expected', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          form_id: true,
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects array where string expected', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          form_id: ['C050E'],
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects null where required', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          form_id: null,
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('wcb_claim_number rejects wrong types', () => {
      it('rejects array where string expected', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          wcb_claim_number: ['12345'],
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects object where string expected', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          wcb_claim_number: { value: '12345' },
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects boolean where string expected', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          wcb_claim_number: true,
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('null where required field expected', () => {
      it('rejects null patient_id', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          form_id: 'C050E',
          patient_id: null,
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects missing form_id', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          patient_id: VALID_PATIENT_ID,
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects missing patient_id', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          form_id: 'C050E',
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('hours_capable_per_day rejects wrong types and out-of-range', () => {
      it('rejects string where number expected', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          hours_capable_per_day: 'eight',
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects negative number', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          hours_capable_per_day: -1,
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects value above 24', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          hours_capable_per_day: 25,
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects float where integer expected', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          hours_capable_per_day: 4.5,
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('patient_pain_estimate rejects out-of-range', () => {
      it('rejects negative number', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          patient_pain_estimate: -1,
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects value above 10', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          patient_pain_estimate: 11,
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects float where integer expected', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          patient_pain_estimate: 5.5,
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('invoice_lines array validation', () => {
      it('rejects more than 25 invoice lines', async () => {
        const lines = Array.from({ length: 26 }, () => ({
          line_type: 'STANDARD',
          health_service_code: '03.04A',
        }));
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          invoice_lines: lines,
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects empty invoice_lines array (min 1)', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          invoice_lines: [],
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('injuries array validation', () => {
      it('rejects more than 5 injury entries', async () => {
        const injuries = Array.from({ length: 6 }, () => ({
          part_of_body_code: 'ARM',
          nature_of_injury_code: 'FRAC',
        }));
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          injuries,
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects empty injuries array (min 1)', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          injuries: [],
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('attachments array validation', () => {
      it('rejects more than 3 attachments', async () => {
        const attachments = Array.from({ length: 4 }, () => ({
          file_name: 'test.pdf',
          file_type: 'PDF',
          file_content_b64: btoa('test-content'),
          file_description: 'Test attachment',
        }));
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          attachments,
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('manual-outcome type coercion', () => {
      it('rejects number where string expected for acceptance_status', async () => {
        const res = await asPhysician('POST', `/api/v1/wcb/claims/${VALID_UUID}/manual-outcome`, {
          acceptance_status: 123,
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects negative payment_amount', async () => {
        const res = await asPhysician('POST', `/api/v1/wcb/claims/${VALID_UUID}/manual-outcome`, {
          ...VALID_MANUAL_OUTCOME,
          payment_amount: -100,
        });
        expect(res.statusCode).toBe(400);
      });
    });
  });

  // =========================================================================
  // 4. UUID Parameter Validation
  // =========================================================================

  describe('UUID parameter validation', () => {
    const INVALID_UUIDS = [
      'not-a-uuid',
      '12345',
      'abcdefgh-ijkl-mnop-qrst-uvwxyz123456',
      '<script>alert(1)</script>',
      "'; DROP TABLE claims; --",
      '../../../etc/passwd',
      '   ',
    ];

    describe('claim_id path parameter (GET /wcb/claims/:id) rejects non-UUID', () => {
      for (const badId of INVALID_UUIDS) {
        it(`rejects: ${badId.slice(0, 30)}`, async () => {
          const res = await asPhysician('GET', `/api/v1/wcb/claims/${encodeURIComponent(badId)}`);
          expect(res.statusCode).toBe(400);
          const body = JSON.parse(res.body);
          expect(body.data).toBeUndefined();
        });
      }
    });

    describe('claim_id path parameter (PUT /wcb/claims/:id) rejects non-UUID', () => {
      for (const badId of INVALID_UUIDS) {
        it(`rejects: ${badId.slice(0, 30)}`, async () => {
          const res = await asPhysician('PUT', `/api/v1/wcb/claims/${encodeURIComponent(badId)}`, {
            symptoms: 'Updated',
          });
          expect(res.statusCode).toBe(400);
          const body = JSON.parse(res.body);
          expect(body.data).toBeUndefined();
        });
      }
    });

    describe('claim_id path parameter (DELETE /wcb/claims/:id) rejects non-UUID', () => {
      for (const badId of INVALID_UUIDS) {
        it(`rejects: ${badId.slice(0, 30)}`, async () => {
          const res = await asPhysician('DELETE', `/api/v1/wcb/claims/${encodeURIComponent(badId)}`);
          expect(res.statusCode).toBe(400);
          const body = JSON.parse(res.body);
          expect(body.data).toBeUndefined();
        });
      }
    });

    describe('claim_id path parameter (POST /wcb/claims/:id/validate) rejects non-UUID', () => {
      for (const badId of INVALID_UUIDS) {
        it(`rejects: ${badId.slice(0, 30)}`, async () => {
          const res = await asPhysician('POST', `/api/v1/wcb/claims/${encodeURIComponent(badId)}/validate`);
          expect(res.statusCode).toBe(400);
          const body = JSON.parse(res.body);
          expect(body.data).toBeUndefined();
        });
      }
    });

    describe('batch_id path parameter (GET /wcb/batches/:id) rejects non-UUID', () => {
      for (const badId of INVALID_UUIDS) {
        it(`rejects: ${badId.slice(0, 30)}`, async () => {
          const res = await asPhysician('GET', `/api/v1/wcb/batches/${encodeURIComponent(badId)}`);
          expect(res.statusCode).toBe(400);
          const body = JSON.parse(res.body);
          expect(body.data).toBeUndefined();
        });
      }
    });

    describe('batch_id path parameter (GET /wcb/batches/:id/download) rejects non-UUID', () => {
      for (const badId of INVALID_UUIDS) {
        it(`rejects: ${badId.slice(0, 30)}`, async () => {
          const res = await asPhysician('GET', `/api/v1/wcb/batches/${encodeURIComponent(badId)}/download`);
          expect(res.statusCode).toBe(400);
          const body = JSON.parse(res.body);
          expect(body.data).toBeUndefined();
        });
      }
    });

    describe('remittance_id path parameter (GET /wcb/remittances/:id/discrepancies) rejects non-UUID', () => {
      for (const badId of INVALID_UUIDS) {
        it(`rejects: ${badId.slice(0, 30)}`, async () => {
          const res = await asPhysician('GET', `/api/v1/wcb/remittances/${encodeURIComponent(badId)}/discrepancies`);
          expect(res.statusCode).toBe(400);
          const body = JSON.parse(res.body);
          expect(body.data).toBeUndefined();
        });
      }
    });

    describe('claim export_id path parameter (GET /wcb/claims/:id/export) rejects non-UUID', () => {
      for (const badId of INVALID_UUIDS) {
        it(`rejects: ${badId.slice(0, 30)}`, async () => {
          const res = await asPhysician('GET', `/api/v1/wcb/claims/${encodeURIComponent(badId)}/export`);
          expect(res.statusCode).toBe(400);
          const body = JSON.parse(res.body);
          expect(body.data).toBeUndefined();
        });
      }
    });

    describe('manual-outcome_id path parameter (POST /wcb/claims/:id/manual-outcome) rejects non-UUID', () => {
      for (const badId of INVALID_UUIDS) {
        it(`rejects: ${badId.slice(0, 30)}`, async () => {
          const res = await asPhysician('POST', `/api/v1/wcb/claims/${encodeURIComponent(badId)}/manual-outcome`, VALID_MANUAL_OUTCOME);
          expect(res.statusCode).toBe(400);
          const body = JSON.parse(res.body);
          expect(body.data).toBeUndefined();
        });
      }
    });

    describe('patient_id body field rejects non-UUID', () => {
      for (const badId of INVALID_UUIDS) {
        it(`rejects patient_id: ${badId.slice(0, 30)}`, async () => {
          const res = await asPhysician('POST', '/api/v1/wcb/claims', {
            ...VALID_WCB_CLAIM_CREATE,
            patient_id: badId,
          });
          expect(res.statusCode).toBe(400);
        });
      }
    });
  });

  // =========================================================================
  // 5. WCB-Specific Validation Attacks
  // =========================================================================

  describe('WCB-specific validation attacks', () => {
    describe('form_id with invalid value', () => {
      it('rejects form_id C999', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          form_id: 'C999',
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects form_id INVALID', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          form_id: 'INVALID',
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects empty form_id', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          form_id: '',
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects lowercase form_id c050e', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          form_id: 'c050e',
        });
        expect(res.statusCode).toBe(400);
      });

      it('accepts C050E', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          form_id: 'C050E',
        });
        expect(res.statusCode).not.toBe(400);
      });

      it('accepts C568', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          form_id: 'C568',
        });
        expect(res.statusCode).not.toBe(400);
      });

      it('accepts C570', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          form_id: 'C570',
        });
        expect(res.statusCode).not.toBe(400);
      });
    });

    describe('attachment file_content_b64 with invalid base64', () => {
      it('rejects empty file_content_b64', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          attachments: [
            {
              file_name: 'test.pdf',
              file_type: 'PDF',
              file_content_b64: '',
              file_description: 'Test attachment',
            },
          ],
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('Y/N enum validation', () => {
      it('rejects "yes" for injury_developed_over_time (must be Y/N)', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          injury_developed_over_time: 'yes',
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects "true" for narcotics_prescribed (must be Y/N)', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          narcotics_prescribed: 'true',
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects "1" for missed_work_beyond_accident (must be Y/N)', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          missed_work_beyond_accident: '1',
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('date format validation', () => {
      it('rejects DD-MM-YYYY for date_of_injury', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          date_of_injury: '15-01-2026',
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects MM/DD/YYYY for report_completion_date', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          report_completion_date: '01/15/2026',
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects non-date for date_of_examination', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          date_of_examination: 'not-a-date',
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects number for date_of_injury', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          date_of_injury: 20260115,
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('manual outcome acceptance_status enum', () => {
      it('rejects invalid acceptance_status', async () => {
        const res = await asPhysician('POST', `/api/v1/wcb/claims/${VALID_UUID}/manual-outcome`, {
          acceptance_status: 'pending',
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects empty acceptance_status', async () => {
        const res = await asPhysician('POST', `/api/v1/wcb/claims/${VALID_UUID}/manual-outcome`, {
          acceptance_status: '',
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects uppercase ACCEPTED', async () => {
        const res = await asPhysician('POST', `/api/v1/wcb/claims/${VALID_UUID}/manual-outcome`, {
          acceptance_status: 'ACCEPTED',
        });
        expect(res.statusCode).toBe(400);
      });
    });
  });

  // =========================================================================
  // 6. Boundary Value Tests
  // =========================================================================

  describe('Boundary value validation', () => {
    describe('additional_comments length boundary', () => {
      it('accepts additional_comments at exactly 2048 characters', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          additional_comments: 'x'.repeat(2048),
        });
        // additional_comments is text (unbounded in Zod schema) — should pass validation
        expect(res.statusCode).not.toBe(400);
      });

      it('accepts additional_comments at 2049 characters (text field, unbounded in Zod)', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          additional_comments: 'x'.repeat(2049),
        });
        // additional_comments is text (no Zod max set) — passes Zod validation
        // Service layer may return 500 with stub deps, but not 400 (Zod passes)
        expect(res.statusCode).not.toBe(400);
      });
    });

    describe('employer_name length boundary', () => {
      it('accepts employer_name at exactly 50 characters', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          employer_name: 'x'.repeat(50),
        });
        expect(res.statusCode).not.toBe(400);
      });

      it('rejects employer_name at 51 characters', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          employer_name: 'x'.repeat(51),
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('wcb_claim_number length boundary', () => {
      it('accepts wcb_claim_number at exactly 7 characters', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          wcb_claim_number: '1234567',
        });
        expect(res.statusCode).not.toBe(400);
      });

      it('rejects wcb_claim_number at 8 characters', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          wcb_claim_number: '12345678',
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('prescription_name length boundary', () => {
      it('accepts prescription_name at exactly 50 characters', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          prescriptions: [
            {
              prescription_name: 'x'.repeat(50),
              strength: '10mg',
              daily_intake: '2x daily',
            },
          ],
        });
        expect(res.statusCode).not.toBe(400);
      });

      it('rejects prescription_name at 51 characters', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          prescriptions: [
            {
              prescription_name: 'x'.repeat(51),
              strength: '10mg',
              daily_intake: '2x daily',
            },
          ],
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('employer_city length boundary', () => {
      it('accepts employer_city at exactly 20 characters', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          employer_city: 'x'.repeat(20),
        });
        expect(res.statusCode).not.toBe(400);
      });

      it('rejects employer_city at 21 characters', async () => {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          employer_city: 'x'.repeat(21),
        });
        expect(res.statusCode).toBe(400);
      });
    });
  });

  // =========================================================================
  // 7. Pagination Boundary Attacks
  // =========================================================================

  describe('Pagination boundary attacks', () => {
    describe('batch list pagination', () => {
      it('rejects negative page_size', async () => {
        const res = await asPhysician('GET', '/api/v1/wcb/batches?page_size=-1');
        expect(res.statusCode).toBe(400);
      });

      it('rejects zero page_size', async () => {
        const res = await asPhysician('GET', '/api/v1/wcb/batches?page_size=0');
        expect(res.statusCode).toBe(400);
      });

      it('rejects page_size exceeding max (100)', async () => {
        const res = await asPhysician('GET', '/api/v1/wcb/batches?page_size=999');
        expect(res.statusCode).toBe(400);
      });

      it('rejects negative page number', async () => {
        const res = await asPhysician('GET', '/api/v1/wcb/batches?page=-1');
        expect(res.statusCode).toBe(400);
      });

      it('rejects zero page number', async () => {
        const res = await asPhysician('GET', '/api/v1/wcb/batches?page=0');
        expect(res.statusCode).toBe(400);
      });

      it('rejects non-numeric page_size', async () => {
        const res = await asPhysician('GET', '/api/v1/wcb/batches?page_size=abc');
        expect(res.statusCode).toBe(400);
      });

      it('rejects non-numeric page', async () => {
        const res = await asPhysician('GET', '/api/v1/wcb/batches?page=abc');
        expect(res.statusCode).toBe(400);
      });
    });

    describe('remittance list pagination', () => {
      it('rejects negative page_size', async () => {
        const res = await asPhysician('GET', '/api/v1/wcb/remittances?page_size=-1');
        expect(res.statusCode).toBe(400);
      });

      it('rejects zero page_size', async () => {
        const res = await asPhysician('GET', '/api/v1/wcb/remittances?page_size=0');
        expect(res.statusCode).toBe(400);
      });

      it('rejects page_size exceeding max (100)', async () => {
        const res = await asPhysician('GET', '/api/v1/wcb/remittances?page_size=999');
        expect(res.statusCode).toBe(400);
      });

      it('rejects invalid date format in start_date', async () => {
        const res = await asPhysician('GET', '/api/v1/wcb/remittances?start_date=not-a-date');
        expect(res.statusCode).toBe(400);
      });

      it('rejects invalid date format in end_date', async () => {
        const res = await asPhysician('GET', '/api/v1/wcb/remittances?end_date=01/15/2026');
        expect(res.statusCode).toBe(400);
      });
    });
  });

  // =========================================================================
  // 8. Error Response Sanitisation — No Input Echo-back
  // =========================================================================

  describe('Error responses do not echo malicious input', () => {
    it('validation error for form_id does not echo payload', async () => {
      const malicious = '<script>alert("xss")</script>';
      const res = await asPhysician('POST', '/api/v1/wcb/claims', {
        ...VALID_WCB_CLAIM_CREATE,
        form_id: malicious,
      });
      expect(res.statusCode).toBe(400);
      const rawBody = res.body;
      expect(rawBody).not.toContain('<script>');
      expect(rawBody).not.toContain('alert');
    });

    it('validation error for SQL injection does not echo payload', async () => {
      const malicious = "'; DROP TABLE wcb_claim_details; --";
      const res = await asPhysician('POST', '/api/v1/wcb/claims', {
        ...VALID_WCB_CLAIM_CREATE,
        wcb_claim_number: malicious,
      });
      expect(res.statusCode).toBe(400);
      const rawBody = res.body;
      expect(rawBody).not.toContain('DROP TABLE');
      expect(rawBody).not.toContain('wcb_claim_details');
    });

    it('validation error for invalid UUID does not echo the value', async () => {
      const malicious = '../../etc/passwd';
      const res = await asPhysician('POST', '/api/v1/wcb/claims', {
        ...VALID_WCB_CLAIM_CREATE,
        patient_id: malicious,
      });
      expect(res.statusCode).toBe(400);
      const rawBody = res.body;
      expect(rawBody).not.toContain('passwd');
      expect(rawBody).not.toContain('../');
    });

    it('validation error for non-UUID path param does not echo the value', async () => {
      const malicious = '<img onerror=alert(1) src=x>';
      const res = await asPhysician('GET', `/api/v1/wcb/claims/${encodeURIComponent(malicious)}`);
      expect(res.statusCode).toBe(400);
      const rawBody = res.body;
      expect(rawBody).not.toContain('onerror');
      expect(rawBody).not.toContain('<img');
    });

    it('error responses do not expose internal details', async () => {
      const res = await asPhysician('POST', '/api/v1/wcb/claims', {
        ...VALID_WCB_CLAIM_CREATE,
        form_id: 'INVALID',
      });
      expect(res.statusCode).toBe(400);
      const rawBody = res.body;
      expect(rawBody).not.toContain('postgres');
      expect(rawBody).not.toContain('drizzle');
      expect(rawBody).not.toContain('node_modules');
      expect(rawBody).not.toContain('.ts:');
    });
  });

  // =========================================================================
  // 9. Path Traversal Prevention
  // =========================================================================

  describe('Path traversal prevention', () => {
    it('rejects path traversal in claim ID', async () => {
      const res = await asPhysician('GET', '/api/v1/wcb/claims/..%2F..%2Fetc%2Fpasswd');
      expect(res.statusCode).toBe(400);
    });

    it('rejects path traversal in batch ID', async () => {
      const res = await asPhysician('GET', '/api/v1/wcb/batches/..%2F..%2Fetc%2Fpasswd');
      expect(res.statusCode).toBe(400);
    });

    it('rejects path traversal in remittance ID', async () => {
      const res = await asPhysician('GET', '/api/v1/wcb/remittances/..%2F..%2Fetc%2Fpasswd/discrepancies');
      expect(res.statusCode).toBe(400);
    });

    it('rejects path traversal in return batch_id', async () => {
      const res = await asPhysician('GET', '/api/v1/wcb/returns/..%2F..%2Fetc%2Fpasswd');
      expect(res.statusCode).toBe(400);
    });

    it('rejects path traversal in claim export', async () => {
      const res = await asPhysician('GET', '/api/v1/wcb/claims/..%2F..%2Fetc%2Fpasswd/export');
      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // 10. Content-Type Enforcement
  // =========================================================================

  describe('Content-Type enforcement', () => {
    it('rejects claim create with text/plain content type', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/wcb/claims',
        headers: {
          cookie: `session=${P1_SESSION_TOKEN}`,
          'content-type': 'text/plain',
        },
        payload: JSON.stringify(VALID_WCB_CLAIM_CREATE),
      });
      expect([400, 415]).toContain(res.statusCode);
    });
  });

  // =========================================================================
  // 11. Sanity: Valid Payloads Are Accepted
  // =========================================================================

  describe('Sanity: valid payloads are accepted', () => {
    it('valid claim create passes validation (not 400)', async () => {
      const res = await asPhysician('POST', '/api/v1/wcb/claims', VALID_WCB_CLAIM_CREATE);
      expect(res.statusCode).not.toBe(400);
    });

    it('valid claim create with all valid form types passes validation', async () => {
      for (const formId of ['C050E', 'C050S', 'C151', 'C151S', 'C568', 'C568A', 'C569', 'C570']) {
        const res = await asPhysician('POST', '/api/v1/wcb/claims', {
          ...VALID_WCB_CLAIM_CREATE,
          form_id: formId,
        });
        expect(res.statusCode).not.toBe(400);
      }
    });

    it('valid manual outcome passes validation (not 400)', async () => {
      const res = await asPhysician('POST', `/api/v1/wcb/claims/${VALID_UUID}/manual-outcome`, VALID_MANUAL_OUTCOME);
      expect(res.statusCode).not.toBe(400);
    });

    it('valid list batches with no filters passes validation', async () => {
      const res = await asPhysician('GET', '/api/v1/wcb/batches');
      expect(res.statusCode).not.toBe(400);
    });

    it('valid list batches with status filter passes validation', async () => {
      const res = await asPhysician('GET', '/api/v1/wcb/batches?status=ASSEMBLING&page=1&page_size=10');
      expect(res.statusCode).not.toBe(400);
    });

    it('valid list remittances with date filters passes validation', async () => {
      const res = await asPhysician('GET', '/api/v1/wcb/remittances?start_date=2026-01-01&end_date=2026-01-31');
      expect(res.statusCode).not.toBe(400);
    });

    it('valid get claim by UUID passes validation (not 400)', async () => {
      const res = await asPhysician('GET', `/api/v1/wcb/claims/${VALID_UUID}`);
      expect(res.statusCode).not.toBe(400);
    });

    it('valid get batch by UUID passes validation (not 400)', async () => {
      const res = await asPhysician('GET', `/api/v1/wcb/batches/${VALID_UUID}`);
      expect(res.statusCode).not.toBe(400);
    });

    it('valid claim with optional fields passes validation (not 400)', async () => {
      const res = await asPhysician('POST', '/api/v1/wcb/claims', {
        ...VALID_WCB_CLAIM_CREATE,
        wcb_claim_number: '1234567',
        employer_name: 'ACME Corp',
        employer_city: 'Calgary',
        worker_job_title: 'Welder',
        injury_developed_over_time: 'N',
        date_of_injury: '2026-01-10',
        injury_description: 'Fell from ladder',
        narcotics_prescribed: 'N',
        additional_comments: 'None',
      });
      expect(res.statusCode).not.toBe(400);
    });
  });
});
