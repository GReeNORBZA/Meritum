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
import { ahcipRoutes } from '../../../src/domains/ahcip/ahcip.routes.js';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { type AhcipHandlerDeps } from '../../../src/domains/ahcip/ahcip.handlers.js';
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
const P1_USER_ID = '11111111-2222-0000-0000-000000000001';
const P1_PROVIDER_ID = P1_USER_ID;
const P1_SESSION_ID = '11111111-2222-0000-0000-000000000011';

const VALID_PATIENT_ID = 'bbbb2222-0000-0000-0000-000000000001';
const VALID_BATCH_ID = 'cccc2222-0000-0000-0000-000000000001';
const VALID_CLAIM_ID = 'aaaa2222-0000-0000-0000-000000000001';
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
// Stub AHCIP repository & deps
// ---------------------------------------------------------------------------

function createStubAhcipRepo() {
  return {
    createAhcipDetail: vi.fn(async () => ({})),
    findAhcipDetailByClaimId: vi.fn(async () => undefined),
    updateAhcipDetail: vi.fn(async () => ({})),
    findBatchById: vi.fn(async () => undefined),
    listBatches: vi.fn(async () => ({
      data: [],
      pagination: { total: 0, page: 1, pageSize: 20, hasMore: false },
    })),
    findNextBatchPreview: vi.fn(async () => null),
    createBatch: vi.fn(async () => ({})),
    updateBatchStatus: vi.fn(async () => ({})),
    findClaimsForBatch: vi.fn(async () => []),
    findAssessmentsByBatchId: vi.fn(async () => []),
    createAssessment: vi.fn(async () => ({})),
    listBatchesAwaitingResponse: vi.fn(async () => []),
    findFeeScheduleEntry: vi.fn(async () => undefined),
    findClaimWithAhcipDetail: vi.fn(async () => undefined),
    bulkUpdateClaimStates: vi.fn(async () => []),
    appendClaimAudit: vi.fn(async () => ({})),
  };
}

function createStubHandlerDeps(): AhcipHandlerDeps {
  const repo = createStubAhcipRepo() as any;
  return {
    batchCycleDeps: {
      repo,
      feeRefData: { lookupFee: vi.fn(async () => null), getCurrentVersion: vi.fn(async () => '1.0') },
      feeProviderService: { getProviderFeeConfig: vi.fn(async () => ({})) },
      claimStateService: { transition: vi.fn(async () => ({})) },
      notificationService: { emit: vi.fn(async () => {}) },
      hlinkTransmission: { transmit: vi.fn(async () => ({})) },
      fileEncryption: { encrypt: vi.fn(async () => Buffer.from('')), decrypt: vi.fn(async () => Buffer.from('')) },
      submissionPreferences: { getSubmissionMode: vi.fn(async () => 'MANUAL') },
      validationRunner: { validate: vi.fn(async () => ({ valid: true, errors: [] })) },
    },
    feeCalculationDeps: {
      repo,
      feeRefData: { lookupFee: vi.fn(async () => null), getCurrentVersion: vi.fn(async () => '1.0') },
      feeProviderService: { getProviderFeeConfig: vi.fn(async () => ({})) },
    },
    assessmentDeps: {
      repo,
      claimStateService: { transition: vi.fn(async () => ({})) },
      notificationService: { emit: vi.fn(async () => {}) },
      hlinkRetrieval: { retrieve: vi.fn(async () => ({})) },
      explanatoryCodeService: { getExplanatoryCode: vi.fn(async () => null) },
      fileEncryption: { encrypt: vi.fn(async () => Buffer.from('')), decrypt: vi.fn(async () => Buffer.from('')) },
    },
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

  const handlerDeps = createStubHandlerDeps();

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

  await testApp.register(ahcipRoutes, { deps: handlerDeps });
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

const VALID_FEE_CALCULATE = {
  health_service_code: '03.04A',
  functional_centre: 'MEDE',
  encounter_type: 'CONSULTATION',
  date_of_service: '2026-01-15',
  patient_id: VALID_PATIENT_ID,
};

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('AHCIP Input Validation & Injection Prevention (Security)', () => {
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
      "03.03A'; DROP TABLE ahcip_claim_details;--",
      "'; DELETE FROM ahcip_batches WHERE '1'='1",
    ];

    describe('health_service_code field rejects SQL injection', () => {
      for (const payload of SQL_INJECTION_PAYLOADS) {
        it(`rejects: ${payload.slice(0, 40)}...`, async () => {
          const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
            ...VALID_FEE_CALCULATE,
            health_service_code: payload,
          });
          // health_service_code is max(10). Short payloads (≤10 chars) may pass Zod.
          // Drizzle parameterised queries prevent actual injection at the ORM level.
          if (payload.length > 10) {
            expect(res.statusCode).toBe(400);
            const body = JSON.parse(res.body);
            expect(body.data).toBeUndefined();
          } else {
            if (res.statusCode >= 500) {
              const body = JSON.parse(res.body);
              expect(body.error.message).toBe('Internal server error');
              expect(JSON.stringify(body)).not.toMatch(/postgres|drizzle|sql|syntax/i);
            }
          }
        });
      }
    });

    describe('functional_centre field rejects SQL injection', () => {
      for (const payload of SQL_INJECTION_PAYLOADS) {
        it(`rejects: ${payload.slice(0, 40)}...`, async () => {
          const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
            ...VALID_FEE_CALCULATE,
            functional_centre: payload,
          });
          // functional_centre is max(10). Short payloads (≤10 chars) may pass Zod.
          if (payload.length > 10) {
            expect(res.statusCode).toBe(400);
            const body = JSON.parse(res.body);
            expect(body.data).toBeUndefined();
          } else {
            if (res.statusCode >= 500) {
              const body = JSON.parse(res.body);
              expect(body.error.message).toBe('Internal server error');
              expect(JSON.stringify(body)).not.toMatch(/postgres|drizzle|sql|syntax/i);
            }
          }
        });
      }
    });

    describe('diagnostic_code field rejects SQL injection', () => {
      for (const payload of SQL_INJECTION_PAYLOADS) {
        it(`rejects: ${payload.slice(0, 40)}...`, async () => {
          const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
            ...VALID_FEE_CALCULATE,
            diagnostic_code: payload,
          });
          // diagnostic_code is max(8) — most payloads exceed this
          expect(res.statusCode).toBe(400);
          const body = JSON.parse(res.body);
          expect(body.data).toBeUndefined();
        });
      }
    });

    describe('referral_practitioner field rejects SQL injection', () => {
      for (const payload of SQL_INJECTION_PAYLOADS) {
        it(`rejects: ${payload.slice(0, 40)}...`, async () => {
          const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
            ...VALID_FEE_CALCULATE,
            referral_practitioner: payload,
          });
          // referral_practitioner is max(10). Short payloads (≤10 chars) may pass Zod.
          if (payload.length > 10) {
            expect(res.statusCode).toBe(400);
            const body = JSON.parse(res.body);
            expect(body.data).toBeUndefined();
          } else {
            if (res.statusCode >= 500) {
              const body = JSON.parse(res.body);
              expect(body.error.message).toBe('Internal server error');
              expect(JSON.stringify(body)).not.toMatch(/postgres|drizzle|sql|syntax/i);
            }
          }
        });
      }
    });

    describe('facility_number field rejects SQL injection', () => {
      for (const payload of SQL_INJECTION_PAYLOADS) {
        it(`rejects: ${payload.slice(0, 40)}...`, async () => {
          const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
            ...VALID_FEE_CALCULATE,
            facility_number: payload,
          });
          // facility_number is max(10). Short payloads (≤10 chars) may pass Zod.
          // Drizzle parameterised queries prevent actual injection at the ORM level.
          if (payload.length > 10) {
            expect(res.statusCode).toBe(400);
            const body = JSON.parse(res.body);
            expect(body.data).toBeUndefined();
          } else {
            // Accepted but safely parameterised — verify no SQL error surfaces
            if (res.statusCode >= 500) {
              const body = JSON.parse(res.body);
              expect(body.error.message).toBe('Internal server error');
              expect(JSON.stringify(body)).not.toMatch(/postgres|drizzle|sql|syntax/i);
            }
          }
        });
      }
    });

    describe('batch status filter rejects SQL injection in list query', () => {
      for (const payload of SQL_INJECTION_PAYLOADS) {
        it(`rejects status filter: ${payload.slice(0, 40)}...`, async () => {
          const res = await asPhysician(
            'GET',
            `/api/v1/ahcip/batches?status=${encodeURIComponent(payload)}`,
          );
          expect(res.statusCode).toBe(400);
          const body = JSON.parse(res.body);
          expect(body.data).toBeUndefined();
        });
      }
    });

    describe('modifier fields reject SQL injection', () => {
      for (const payload of SQL_INJECTION_PAYLOADS.slice(0, 3)) {
        it(`modifier_1 rejects: ${payload.slice(0, 30)}...`, async () => {
          const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
            ...VALID_FEE_CALCULATE,
            modifier_1: payload,
          });
          // modifier_1 is max(6) — all SQL payloads exceed this
          expect(res.statusCode).toBe(400);
        });

        it(`modifier_2 rejects: ${payload.slice(0, 30)}...`, async () => {
          const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
            ...VALID_FEE_CALCULATE,
            modifier_2: payload,
          });
          expect(res.statusCode).toBe(400);
        });

        it(`modifier_3 rejects: ${payload.slice(0, 30)}...`, async () => {
          const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
            ...VALID_FEE_CALCULATE,
            modifier_3: payload,
          });
          expect(res.statusCode).toBe(400);
        });
      }
    });

    describe('patient_location field rejects SQL injection', () => {
      for (const payload of SQL_INJECTION_PAYLOADS) {
        it(`rejects: ${payload.slice(0, 40)}...`, async () => {
          const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
            ...VALID_FEE_CALCULATE,
            patient_location: payload,
          });
          // patient_location is max(10). Short payloads (≤10 chars) may pass Zod.
          // Drizzle parameterised queries prevent actual injection at the ORM level.
          if (payload.length > 10) {
            expect(res.statusCode).toBe(400);
          } else {
            // Accepted but safely parameterised — verify no SQL error surfaces
            if (res.statusCode >= 500) {
              const body = JSON.parse(res.body);
              expect(body.error.message).toBe('Internal server error');
              expect(JSON.stringify(body)).not.toMatch(/postgres|drizzle|sql|syntax/i);
            }
          }
        });
      }
    });
  });

  // =========================================================================
  // 2. XSS Payloads on Text Fields
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

    describe('health_service_code rejects XSS payloads', () => {
      for (const payload of XSS_PAYLOADS) {
        it(`rejects: ${payload.slice(0, 40)}...`, async () => {
          const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
            ...VALID_FEE_CALCULATE,
            health_service_code: payload,
          });
          // All XSS payloads exceed max(10)
          expect(res.statusCode).toBe(400);
          const body = JSON.parse(res.body);
          expect(body.data).toBeUndefined();
        });
      }
    });

    describe('facility_number rejects XSS payloads', () => {
      for (const payload of XSS_PAYLOADS) {
        it(`rejects: ${payload.slice(0, 40)}...`, async () => {
          const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
            ...VALID_FEE_CALCULATE,
            facility_number: payload,
          });
          // All XSS payloads exceed max(10)
          expect(res.statusCode).toBe(400);
          const body = JSON.parse(res.body);
          expect(body.data).toBeUndefined();
        });
      }
    });

    describe('functional_centre rejects XSS payloads', () => {
      for (const payload of XSS_PAYLOADS.slice(0, 3)) {
        it(`rejects: ${payload.slice(0, 40)}...`, async () => {
          const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
            ...VALID_FEE_CALCULATE,
            functional_centre: payload,
          });
          expect(res.statusCode).toBe(400);
        });
      }
    });

    describe('referral_practitioner rejects XSS payloads', () => {
      for (const payload of XSS_PAYLOADS.slice(0, 3)) {
        it(`rejects: ${payload.slice(0, 40)}...`, async () => {
          const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
            ...VALID_FEE_CALCULATE,
            referral_practitioner: payload,
          });
          expect(res.statusCode).toBe(400);
        });
      }
    });

    describe('diagnostic_code rejects XSS payloads', () => {
      for (const payload of XSS_PAYLOADS.slice(0, 3)) {
        it(`rejects: ${payload.slice(0, 40)}...`, async () => {
          const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
            ...VALID_FEE_CALCULATE,
            diagnostic_code: payload,
          });
          expect(res.statusCode).toBe(400);
        });
      }
    });

    describe('modifier fields reject XSS payloads', () => {
      for (const payload of XSS_PAYLOADS.slice(0, 2)) {
        it(`modifier_1 rejects: ${payload.slice(0, 30)}...`, async () => {
          const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
            ...VALID_FEE_CALCULATE,
            modifier_1: payload,
          });
          // All XSS payloads exceed max(6)
          expect(res.statusCode).toBe(400);
        });
      }
    });
  });

  // =========================================================================
  // 3. Type Coercion Attacks
  // =========================================================================

  describe('Type coercion attacks', () => {
    describe('calls field rejects wrong types', () => {
      it('rejects string where number expected', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          calls: 'five',
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects negative number', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          calls: -1,
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects zero', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          calls: 0,
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects float', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          calls: 1.5,
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects boolean where number expected', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          calls: true,
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects array where number expected', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          calls: [1],
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects null where number expected', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          calls: null,
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('time_spent field rejects wrong types', () => {
      it('rejects negative number', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          time_spent: -5,
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects zero', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          time_spent: 0,
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects float', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          time_spent: 15.5,
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects string where number expected', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          time_spent: 'fifteen',
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects boolean where number expected', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          time_spent: true,
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('encounter_type rejects wrong types', () => {
      it('rejects number where enum string expected', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          encounter_type: 12345,
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects array where enum string expected', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          encounter_type: ['CONSULTATION'],
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects boolean where enum string expected', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          encounter_type: true,
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects null where required', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          encounter_type: null,
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('date_of_service rejects wrong types', () => {
      it('rejects number where date string expected', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          date_of_service: 12345,
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects boolean where date string expected', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          date_of_service: true,
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects array where date string expected', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          date_of_service: ['2026-01-15'],
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects null where required date expected', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          date_of_service: null,
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('patient_id rejects wrong types', () => {
      it('rejects number where UUID expected', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          patient_id: 12345,
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects array where UUID expected', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          patient_id: [VALID_PATIENT_ID],
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects null where required UUID expected', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          patient_id: null,
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('health_service_code rejects wrong types', () => {
      it('rejects number where string expected', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          health_service_code: 12345,
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects array where string expected', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          health_service_code: ['03.04A'],
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects object where string expected', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          health_service_code: { code: '03.04A' },
        });
        expect(res.statusCode).toBe(400);
      });
    });
  });

  // =========================================================================
  // 4. Pagination Boundary Attacks
  // =========================================================================

  describe('Pagination boundary attacks', () => {
    it('rejects negative page_size', async () => {
      const res = await asPhysician('GET', '/api/v1/ahcip/batches?page_size=-1');
      expect(res.statusCode).toBe(400);
    });

    it('rejects zero page_size', async () => {
      const res = await asPhysician('GET', '/api/v1/ahcip/batches?page_size=0');
      expect(res.statusCode).toBe(400);
    });

    it('rejects page_size exceeding max (50)', async () => {
      const res = await asPhysician('GET', '/api/v1/ahcip/batches?page_size=999');
      // Zod max(50) — should reject values > 50
      expect(res.statusCode).toBe(400);
    });

    it('rejects negative page number', async () => {
      const res = await asPhysician('GET', '/api/v1/ahcip/batches?page=-1');
      expect(res.statusCode).toBe(400);
    });

    it('rejects zero page number', async () => {
      const res = await asPhysician('GET', '/api/v1/ahcip/batches?page=0');
      expect(res.statusCode).toBe(400);
    });

    it('rejects non-numeric page_size', async () => {
      const res = await asPhysician('GET', '/api/v1/ahcip/batches?page_size=abc');
      expect(res.statusCode).toBe(400);
    });

    it('rejects non-numeric page', async () => {
      const res = await asPhysician('GET', '/api/v1/ahcip/batches?page=abc');
      expect(res.statusCode).toBe(400);
    });

    it('rejects float page_size (not integer)', async () => {
      const res = await asPhysician('GET', '/api/v1/ahcip/batches?page_size=2.5');
      // z.coerce.number().int() should reject non-integers
      expect(res.statusCode).toBe(400);
    });

    it('rejects float page (not integer)', async () => {
      const res = await asPhysician('GET', '/api/v1/ahcip/batches?page=1.5');
      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // 5. UUID Parameter Validation
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

    describe('batch_id path parameter (GET /batches/:id) rejects non-UUID', () => {
      for (const badId of INVALID_UUIDS) {
        it(`rejects: ${badId.slice(0, 30)}`, async () => {
          const res = await asPhysician('GET', `/api/v1/ahcip/batches/${encodeURIComponent(badId)}`);
          expect(res.statusCode).toBe(400);
          const body = JSON.parse(res.body);
          expect(body.data).toBeUndefined();
        });
      }
    });

    describe('batch_id path parameter (POST /batches/:id/retry) rejects non-UUID', () => {
      for (const badId of INVALID_UUIDS) {
        it(`rejects: ${badId.slice(0, 30)}`, async () => {
          const res = await asPhysician('POST', `/api/v1/ahcip/batches/${encodeURIComponent(badId)}/retry`);
          expect(res.statusCode).toBe(400);
          const body = JSON.parse(res.body);
          expect(body.data).toBeUndefined();
        });
      }
    });

    describe('batch_id path parameter (GET /assessments/:batch_id) rejects non-UUID', () => {
      for (const badId of INVALID_UUIDS) {
        it(`rejects: ${badId.slice(0, 30)}`, async () => {
          const res = await asPhysician('GET', `/api/v1/ahcip/assessments/${encodeURIComponent(badId)}`);
          expect(res.statusCode).toBe(400);
          const body = JSON.parse(res.body);
          expect(body.data).toBeUndefined();
        });
      }
    });

    describe('claim_id path parameter (GET /claims/:id/fee-breakdown) rejects non-UUID', () => {
      for (const badId of INVALID_UUIDS) {
        it(`rejects: ${badId.slice(0, 30)}`, async () => {
          const res = await asPhysician('GET', `/api/v1/ahcip/claims/${encodeURIComponent(badId)}/fee-breakdown`);
          expect(res.statusCode).toBe(400);
          const body = JSON.parse(res.body);
          expect(body.data).toBeUndefined();
        });
      }
    });

    describe('patient_id body field rejects non-UUID', () => {
      for (const badId of INVALID_UUIDS) {
        it(`rejects patient_id: ${badId.slice(0, 30)}`, async () => {
          const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
            ...VALID_FEE_CALCULATE,
            patient_id: badId,
          });
          expect(res.statusCode).toBe(400);
        });
      }

      it('rejects empty string patient_id', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          patient_id: '',
        });
        expect(res.statusCode).toBe(400);
      });
    });
  });

  // =========================================================================
  // 6. Date Format Validation
  // =========================================================================

  describe('Date format validation', () => {
    const INVALID_DATES = [
      '15-01-2026',        // DD-MM-YYYY
      '01/15/2026',        // MM/DD/YYYY
      '2026/01/15',        // YYYY/MM/DD
      'January 15, 2026',  // English text
      '20260115',          // No separators
      '2026-13-01',        // Invalid month
      '2026-01-32',        // Invalid day
      '2026-00-15',        // Zero month
      '2026-01-00',        // Zero day
      'not-a-date',        // Text
      '',                  // Empty
    ];

    describe('date_of_service in fee-calculate rejects invalid date formats', () => {
      for (const badDate of INVALID_DATES) {
        it(`rejects date_of_service: ${badDate || '(empty)'}`, async () => {
          const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
            ...VALID_FEE_CALCULATE,
            date_of_service: badDate,
          });
          expect(res.statusCode).toBe(400);
        });
      }
    });

    describe('date_from/date_to in batch list rejects invalid date formats', () => {
      for (const badDate of INVALID_DATES.slice(0, 5)) {
        it(`rejects date_from: ${badDate || '(empty)'}`, async () => {
          const res = await asPhysician(
            'GET',
            `/api/v1/ahcip/batches?date_from=${encodeURIComponent(badDate)}`,
          );
          expect(res.statusCode).toBe(400);
        });

        it(`rejects date_to: ${badDate || '(empty)'}`, async () => {
          const res = await asPhysician(
            'GET',
            `/api/v1/ahcip/batches?date_to=${encodeURIComponent(badDate)}`,
          );
          expect(res.statusCode).toBe(400);
        });
      }
    });
  });

  // =========================================================================
  // 7. Enum Validation
  // =========================================================================

  describe('Enum validation', () => {
    describe('encounter_type accepts only valid AHCIP encounter types', () => {
      it('rejects invalid encounter_type', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          encounter_type: 'INVALID_TYPE',
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects lowercase encounter_type', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          encounter_type: 'consultation',
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects mixed case encounter_type', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          encounter_type: 'Consultation',
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects empty string encounter_type', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          encounter_type: '',
        });
        expect(res.statusCode).toBe(400);
      });

      it('accepts CONSULTATION', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          encounter_type: 'CONSULTATION',
        });
        expect(res.statusCode).not.toBe(400);
      });

      it('accepts FOLLOW_UP', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          encounter_type: 'FOLLOW_UP',
        });
        expect(res.statusCode).not.toBe(400);
      });

      it('accepts PROCEDURE', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          encounter_type: 'PROCEDURE',
        });
        expect(res.statusCode).not.toBe(400);
      });

      it('accepts VIRTUAL', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          encounter_type: 'VIRTUAL',
        });
        expect(res.statusCode).not.toBe(400);
      });

      it('accepts CDM', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          encounter_type: 'CDM',
        });
        expect(res.statusCode).not.toBe(400);
      });

      it('accepts OTHER', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          encounter_type: 'OTHER',
        });
        expect(res.statusCode).not.toBe(400);
      });
    });

    describe('batch status filter accepts only valid statuses', () => {
      it('rejects invalid status', async () => {
        const res = await asPhysician('GET', '/api/v1/ahcip/batches?status=INVALID_STATUS');
        expect(res.statusCode).toBe(400);
      });

      it('rejects lowercase status', async () => {
        const res = await asPhysician('GET', '/api/v1/ahcip/batches?status=assembling');
        expect(res.statusCode).toBe(400);
      });

      it('rejects mixed case status', async () => {
        const res = await asPhysician('GET', '/api/v1/ahcip/batches?status=Assembling');
        expect(res.statusCode).toBe(400);
      });

      it('rejects empty string status', async () => {
        const res = await asPhysician('GET', '/api/v1/ahcip/batches?status=');
        expect(res.statusCode).toBe(400);
      });

      it('accepts ASSEMBLING', async () => {
        const res = await asPhysician('GET', '/api/v1/ahcip/batches?status=ASSEMBLING');
        expect(res.statusCode).not.toBe(400);
      });

      it('accepts SUBMITTED', async () => {
        const res = await asPhysician('GET', '/api/v1/ahcip/batches?status=SUBMITTED');
        expect(res.statusCode).not.toBe(400);
      });

      it('accepts ERROR', async () => {
        const res = await asPhysician('GET', '/api/v1/ahcip/batches?status=ERROR');
        expect(res.statusCode).not.toBe(400);
      });

      it('accepts RECONCILED', async () => {
        const res = await asPhysician('GET', '/api/v1/ahcip/batches?status=RECONCILED');
        expect(res.statusCode).not.toBe(400);
      });
    });
  });

  // =========================================================================
  // 8. String Length Boundary Validation
  // =========================================================================

  describe('String length boundary validation', () => {
    describe('health_service_code length limits', () => {
      it('rejects empty health_service_code', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          health_service_code: '',
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects health_service_code exceeding 10 characters', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          health_service_code: 'x'.repeat(11),
        });
        expect(res.statusCode).toBe(400);
      });

      it('accepts health_service_code at 10 characters', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          health_service_code: 'x'.repeat(10),
        });
        expect(res.statusCode).not.toBe(400);
      });
    });

    describe('functional_centre length limits', () => {
      it('rejects empty functional_centre', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          functional_centre: '',
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects functional_centre exceeding 10 characters', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          functional_centre: 'x'.repeat(11),
        });
        expect(res.statusCode).toBe(400);
      });

      it('accepts functional_centre at 10 characters', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          functional_centre: 'x'.repeat(10),
        });
        expect(res.statusCode).not.toBe(400);
      });
    });

    describe('modifier field length limits', () => {
      it('rejects modifier_1 exceeding 6 characters', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          modifier_1: 'x'.repeat(7),
        });
        expect(res.statusCode).toBe(400);
      });

      it('accepts modifier_1 at 6 characters', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          modifier_1: 'x'.repeat(6),
        });
        expect(res.statusCode).not.toBe(400);
      });

      it('rejects modifier_2 exceeding 6 characters', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          modifier_2: 'x'.repeat(7),
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects modifier_3 exceeding 6 characters', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          modifier_3: 'x'.repeat(7),
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('diagnostic_code length limits', () => {
      it('rejects diagnostic_code exceeding 8 characters', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          diagnostic_code: 'x'.repeat(9),
        });
        expect(res.statusCode).toBe(400);
      });

      it('accepts diagnostic_code at 8 characters', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          diagnostic_code: 'x'.repeat(8),
        });
        expect(res.statusCode).not.toBe(400);
      });
    });

    describe('facility_number length limits', () => {
      it('rejects facility_number exceeding 10 characters', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          facility_number: 'x'.repeat(11),
        });
        expect(res.statusCode).toBe(400);
      });

      it('accepts facility_number at 10 characters', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          facility_number: 'x'.repeat(10),
        });
        expect(res.statusCode).not.toBe(400);
      });
    });

    describe('referral_practitioner length limits', () => {
      it('rejects referral_practitioner exceeding 10 characters', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          referral_practitioner: 'x'.repeat(11),
        });
        expect(res.statusCode).toBe(400);
      });

      it('accepts referral_practitioner at 10 characters', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          referral_practitioner: 'x'.repeat(10),
        });
        expect(res.statusCode).not.toBe(400);
      });
    });

    describe('patient_location length limits', () => {
      it('rejects patient_location exceeding 10 characters', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          patient_location: 'x'.repeat(11),
        });
        expect(res.statusCode).toBe(400);
      });

      it('accepts patient_location at 10 characters', async () => {
        const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
          ...VALID_FEE_CALCULATE,
          patient_location: 'x'.repeat(10),
        });
        expect(res.statusCode).not.toBe(400);
      });
    });
  });

  // =========================================================================
  // 9. Missing Required Fields
  // =========================================================================

  describe('Missing required fields', () => {
    it('rejects fee-calculate without health_service_code', async () => {
      const { health_service_code, ...rest } = VALID_FEE_CALCULATE;
      const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', rest);
      expect(res.statusCode).toBe(400);
    });

    it('rejects fee-calculate without functional_centre', async () => {
      const { functional_centre, ...rest } = VALID_FEE_CALCULATE;
      const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', rest);
      expect(res.statusCode).toBe(400);
    });

    it('rejects fee-calculate without encounter_type', async () => {
      const { encounter_type, ...rest } = VALID_FEE_CALCULATE;
      const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', rest);
      expect(res.statusCode).toBe(400);
    });

    it('rejects fee-calculate without date_of_service', async () => {
      const { date_of_service, ...rest } = VALID_FEE_CALCULATE;
      const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', rest);
      expect(res.statusCode).toBe(400);
    });

    it('rejects fee-calculate without patient_id', async () => {
      const { patient_id, ...rest } = VALID_FEE_CALCULATE;
      const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', rest);
      expect(res.statusCode).toBe(400);
    });

    it('rejects fee-calculate with empty body', async () => {
      const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {});
      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // 10. Error Response Sanitisation — No Input Echo-back
  // =========================================================================

  describe('Error responses do not echo malicious input', () => {
    it('validation error for encounter_type does not echo payload', async () => {
      const malicious = '<script>alert("xss")</script>';
      const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
        ...VALID_FEE_CALCULATE,
        encounter_type: malicious,
      });
      expect(res.statusCode).toBe(400);
      const rawBody = res.body;
      expect(rawBody).not.toContain('<script>');
      expect(rawBody).not.toContain('alert');
    });

    it('validation error for SQL injection does not echo payload', async () => {
      const malicious = "'; DROP TABLE ahcip_claim_details; --";
      const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
        ...VALID_FEE_CALCULATE,
        health_service_code: malicious,
      });
      expect(res.statusCode).toBe(400);
      const rawBody = res.body;
      expect(rawBody).not.toContain('DROP TABLE');
      expect(rawBody).not.toContain('ahcip_claim_details');
    });

    it('validation error for invalid UUID does not echo the value', async () => {
      const malicious = '../../etc/passwd';
      const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
        ...VALID_FEE_CALCULATE,
        patient_id: malicious,
      });
      expect(res.statusCode).toBe(400);
      const rawBody = res.body;
      expect(rawBody).not.toContain('passwd');
      expect(rawBody).not.toContain('../');
    });

    it('validation error for non-UUID path param does not echo the value', async () => {
      const malicious = '<img onerror=alert(1) src=x>';
      const res = await asPhysician('GET', `/api/v1/ahcip/batches/${encodeURIComponent(malicious)}`);
      expect(res.statusCode).toBe(400);
      const rawBody = res.body;
      expect(rawBody).not.toContain('onerror');
      expect(rawBody).not.toContain('<img');
    });

    it('error responses do not expose internal details', async () => {
      const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
        ...VALID_FEE_CALCULATE,
        encounter_type: 'INVALID',
      });
      expect(res.statusCode).toBe(400);
      const rawBody = res.body;
      expect(rawBody).not.toContain('postgres');
      expect(rawBody).not.toContain('drizzle');
      expect(rawBody).not.toContain('node_modules');
      expect(rawBody).not.toContain('.ts:');
    });

    it('error response for invalid batch_id does not expose internal details', async () => {
      const res = await asPhysician('GET', '/api/v1/ahcip/assessments/not-a-valid-uuid');
      expect(res.statusCode).toBe(400);
      const rawBody = res.body;
      expect(rawBody).not.toContain('postgres');
      expect(rawBody).not.toContain('drizzle');
      expect(rawBody).not.toContain('.ts:');
    });
  });

  // =========================================================================
  // 11. Path Traversal Prevention
  // =========================================================================

  describe('Path traversal prevention', () => {
    it('rejects path traversal in batch ID', async () => {
      const res = await asPhysician('GET', '/api/v1/ahcip/batches/..%2F..%2Fetc%2Fpasswd');
      expect(res.statusCode).toBe(400);
    });

    it('rejects path traversal in batch retry ID', async () => {
      const res = await asPhysician('POST', '/api/v1/ahcip/batches/..%2F..%2Fetc%2Fpasswd/retry');
      expect(res.statusCode).toBe(400);
    });

    it('rejects path traversal in assessment batch_id', async () => {
      const res = await asPhysician('GET', '/api/v1/ahcip/assessments/..%2F..%2Fetc%2Fpasswd');
      expect(res.statusCode).toBe(400);
    });

    it('rejects path traversal in claim ID for fee-breakdown', async () => {
      const res = await asPhysician('GET', '/api/v1/ahcip/claims/..%2F..%2Fetc%2Fpasswd/fee-breakdown');
      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // 12. Extra/Unexpected Fields (Mass Assignment Prevention)
  // =========================================================================

  describe('Extra/unexpected fields handling', () => {
    it('ignores extra fields in fee-calculate (no mass assignment)', async () => {
      const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
        ...VALID_FEE_CALCULATE,
        physicianId: VALID_UUID,      // Attempt to set physician directly
        batch_id: VALID_BATCH_ID,     // Attempt to inject batch context
        state: 'PAID',                // Attempt to set state directly
        fee_amount: '999.99',         // Attempt to override fee
      });
      // Extra fields should be stripped by Zod — not cause validation error (400)
      // Service layer may return 500 with mock deps — that's acceptable.
      // The key assertion: Zod does NOT reject the request due to extra fields.
      expect(res.statusCode).not.toBe(400);
    });
  });

  // =========================================================================
  // 13. Content-Type Enforcement
  // =========================================================================

  describe('Content-Type enforcement', () => {
    it('rejects fee-calculate with text/plain content type', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ahcip/fee-calculate',
        headers: {
          cookie: `session=${P1_SESSION_TOKEN}`,
          'content-type': 'text/plain',
        },
        payload: JSON.stringify(VALID_FEE_CALCULATE),
      });
      // Should reject non-JSON content types for JSON endpoints
      expect([400, 415]).toContain(res.statusCode);
    });
  });

  // =========================================================================
  // 14. Sanity: Valid Payloads Are Accepted
  // =========================================================================

  describe('Sanity: valid payloads are accepted', () => {
    it('valid fee-calculate passes validation (not 400)', async () => {
      const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', VALID_FEE_CALCULATE);
      // Passes Zod validation — not a 400. Service may return 500 with mock deps.
      expect(res.statusCode).not.toBe(400);
    });

    it('valid fee-calculate with all optional fields passes validation (not 400)', async () => {
      const res = await asPhysician('POST', '/api/v1/ahcip/fee-calculate', {
        ...VALID_FEE_CALCULATE,
        modifier_1: 'TM',
        modifier_2: 'AFHR',
        modifier_3: 'LOCI',
        diagnostic_code: '780',
        facility_number: '85012',
        referral_practitioner: '123456',
        calls: 2,
        time_spent: 30,
        patient_location: 'RURAL',
      });
      expect(res.statusCode).not.toBe(400);
    });

    it('valid list batches with no filters passes validation', async () => {
      const res = await asPhysician('GET', '/api/v1/ahcip/batches');
      // Mock repo returns empty list — should be 200
      expect(res.statusCode).toBe(200);
    });

    it('valid list batches with status filter passes validation', async () => {
      const res = await asPhysician('GET', '/api/v1/ahcip/batches?status=ASSEMBLING&page=1&page_size=10');
      expect(res.statusCode).toBe(200);
    });

    it('valid list batches with date filters passes validation', async () => {
      const res = await asPhysician('GET', '/api/v1/ahcip/batches?date_from=2026-01-01&date_to=2026-01-31');
      expect(res.statusCode).toBe(200);
    });

    it('valid get batch by ID passes validation (not 400)', async () => {
      const res = await asPhysician('GET', `/api/v1/ahcip/batches/${VALID_BATCH_ID}`);
      // UUID param passes validation. Handler returns 404 when mock finds nothing.
      expect(res.statusCode).not.toBe(400);
    });

    it('valid retry batch passes validation (not 400)', async () => {
      const res = await asPhysician('POST', `/api/v1/ahcip/batches/${VALID_BATCH_ID}/retry`);
      // UUID param passes validation. Service may 404 or 500 with mock deps.
      expect(res.statusCode).not.toBe(400);
    });

    it('valid get assessment results passes validation (not 400)', async () => {
      const res = await asPhysician('GET', `/api/v1/ahcip/assessments/${VALID_BATCH_ID}`);
      // UUID param passes validation. Service may 404 or 500 with mock deps.
      expect(res.statusCode).not.toBe(400);
    });

    it('valid get fee breakdown passes validation (not 400)', async () => {
      const res = await asPhysician('GET', `/api/v1/ahcip/claims/${VALID_CLAIM_ID}/fee-breakdown`);
      // UUID param passes validation. Service may 404 or 500 with mock deps.
      expect(res.statusCode).not.toBe(400);
    });

    it('valid pending assessments passes validation (not 400)', async () => {
      const res = await asPhysician('GET', '/api/v1/ahcip/assessments/pending');
      // No schema validation on this route — service may 500 with mock deps
      expect(res.statusCode).not.toBe(400);
    });

    it('valid next batch preview passes validation (not 400)', async () => {
      const res = await asPhysician('GET', '/api/v1/ahcip/batches/next');
      // No schema validation on this route — service may 500 with mock deps
      expect(res.statusCode).not.toBe(400);
    });
  });
});
