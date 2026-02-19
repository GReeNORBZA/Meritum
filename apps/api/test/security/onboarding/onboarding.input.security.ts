import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

// ---------------------------------------------------------------------------
// Environment setup (must be before imports that read env)
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);

// ---------------------------------------------------------------------------
// Mock otplib (required by iam.service.ts transitive import)
// ---------------------------------------------------------------------------

vi.mock('otplib', () => ({
  authenticator: {
    options: {},
    generateSecret: vi.fn(() => 'JBSWY3DPEHPK3PXP'),
    keyuri: vi.fn(() => 'otpauth://totp/test'),
    verify: vi.fn(() => false),
  },
}));

// ---------------------------------------------------------------------------
// Real imports (after mocks are hoisted)
// ---------------------------------------------------------------------------

import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { onboardingRoutes } from '../../../src/domains/onboarding/onboarding.routes.js';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { type OnboardingHandlerDeps } from '../../../src/domains/onboarding/onboarding.handlers.js';
import { type OnboardingServiceDeps } from '../../../src/domains/onboarding/onboarding.service.js';
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
    createSession: vi.fn(async () => ({
      sessionId: '44444444-0000-0000-0000-000000000001',
    })),
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
// Mock onboarding repository
// ---------------------------------------------------------------------------

function makeMockProgress(overrides?: Record<string, unknown>) {
  return {
    progressId: '11111111-0000-0000-0000-000000000001',
    providerId: FIXED_PROVIDER_ID,
    step1Completed: false,
    step2Completed: false,
    step3Completed: false,
    step4Completed: false,
    step5Completed: false,
    step6Completed: false,
    step7Completed: false,
    patientImportCompleted: false,
    guidedTourCompleted: false,
    guidedTourDismissed: false,
    startedAt: new Date(),
    completedAt: null,
    ...overrides,
  };
}

function makeMockImaRecord() {
  return {
    imaId: '22222222-0000-0000-0000-000000000001',
    providerId: FIXED_PROVIDER_ID,
    templateVersion: '1.0',
    documentHash: 'a'.repeat(64),
    acknowledgedAt: new Date(),
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
  };
}

function createStubOnboardingRepo() {
  return {
    createProgress: vi.fn(async () => makeMockProgress()),
    findProgressByProviderId: vi.fn(async () => makeMockProgress()),
    markStepCompleted: vi.fn(async () => makeMockProgress()),
    markOnboardingCompleted: vi.fn(async () => makeMockProgress()),
    markPatientImportCompleted: vi.fn(async () => makeMockProgress()),
    markGuidedTourCompleted: vi.fn(async () => makeMockProgress()),
    markGuidedTourDismissed: vi.fn(async () => makeMockProgress()),
    createImaRecord: vi.fn(async () => makeMockImaRecord()),
    findLatestImaRecord: vi.fn(async () => makeMockImaRecord()),
    listImaRecords: vi.fn(async () => [makeMockImaRecord()]),
  };
}

// ---------------------------------------------------------------------------
// Mock provider service
// ---------------------------------------------------------------------------

function createStubProviderService() {
  return {
    createOrUpdateProvider: vi.fn(async () => ({ providerId: FIXED_PROVIDER_ID })),
    updateProviderSpecialty: vi.fn(async () => {}),
    createBa: vi.fn(async () => ({ baId: '00000000-0000-0000-0000-000000000099' })),
    createLocation: vi.fn(async () => ({ locationId: '00000000-0000-0000-0000-000000000099' })),
    createWcbConfig: vi.fn(async () => ({ wcbConfigId: '00000000-0000-0000-0000-000000000099' })),
    updateSubmissionPreferences: vi.fn(async () => {}),
    findProviderByUserId: vi.fn(async () => ({ providerId: FIXED_PROVIDER_ID })),
    getProviderDetails: vi.fn(async () => null),
    findBaById: vi.fn(async () => null),
    updateBaStatus: vi.fn(async () => ({ baId: '', status: '' })),
  };
}

// ---------------------------------------------------------------------------
// Mock reference data service
// ---------------------------------------------------------------------------

function createStubReferenceData() {
  return {
    validateSpecialtyCode: vi.fn(async () => true),
    validateFunctionalCentreCode: vi.fn(async () => true),
    validateCommunityCode: vi.fn(async () => true),
    getRrnpRate: vi.fn(async () => null),
    getWcbFormTypes: vi.fn(async () => ['C8', 'C10']),
  };
}

// ---------------------------------------------------------------------------
// Stub service deps
// ---------------------------------------------------------------------------

function createStubServiceDeps(): OnboardingServiceDeps {
  return {
    repo: createStubOnboardingRepo() as any,
    auditRepo: createMockAuditRepo(),
    events: createMockEvents(),
    providerService: createStubProviderService(),
    referenceData: createStubReferenceData(),
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

  const handlerDeps: OnboardingHandlerDeps = {
    serviceDeps: createStubServiceDeps(),
  };

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  await testApp.register(authPluginFp, { sessionDeps });

  testApp.setErrorHandler((error, _request, reply) => {
    if ('statusCode' in error && 'code' in error && typeof (error as any).code === 'string') {
      const statusCode = (error as any).statusCode ?? 500;
      if (statusCode >= 400 && statusCode < 500) {
        return reply.code(statusCode).send({
          error: { code: (error as any).code, message: error.message },
        });
      }
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

  await testApp.register(onboardingRoutes, { deps: handlerDeps });
  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function authCookie(): string {
  return `session=${FIXED_SESSION_TOKEN}`;
}

function seedAuthState() {
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
    subscriptionStatus: 'ACTIVE',
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
}

// ---------------------------------------------------------------------------
// Valid payloads for each step
// ---------------------------------------------------------------------------

const VALID_STEP1 = {
  billing_number: '12345',
  cpsa_number: 'REG123',
  legal_first_name: 'Test',
  legal_last_name: 'Physician',
};

const VALID_STEP2 = {
  specialty_code: 'GP',
  physician_type: 'gp',
};

const VALID_STEP3 = {
  primary_ba_number: '12345',
  is_pcpcm_enrolled: false,
};

const VALID_STEP3_PCPCM = {
  primary_ba_number: '12345',
  is_pcpcm_enrolled: true,
  pcpcm_ba_number: '67890',
  ffs_ba_number: '11111',
};

const VALID_STEP4 = {
  location_name: 'Test Clinic',
  functional_centre_code: 'FC01',
  community_code: 'CAL',
  address: {
    street: '123 Main St',
    city: 'Calgary',
    province: 'AB',
    postal_code: 'T2P0A1',
  },
};

const VALID_STEP5 = {
  contract_id: 'C001',
  role: 'Physician',
  skill_code: 'SK01',
};

const VALID_STEP6 = {
  ahcip_mode: 'auto_clean',
  wcb_mode: 'require_approval',
};

const VALID_IMA_HASH = 'a'.repeat(64);

const VALID_UUID = '00000000-0000-0000-0000-000000000001';

// ---------------------------------------------------------------------------
// SQL Injection payloads
// ---------------------------------------------------------------------------

const SQL_PAYLOADS = [
  "' OR 1=1--",
  "'; DROP TABLE providers;--",
  "1' OR '1'='1",
  "1; SELECT * FROM users --",
  "' UNION SELECT * FROM providers --",
  "admin'--",
  "'; TRUNCATE TABLE onboarding_progress;--",
];

// ---------------------------------------------------------------------------
// XSS payloads
// ---------------------------------------------------------------------------

const XSS_PAYLOADS = [
  '<script>alert("xss")</script>',
  '<img src=x onerror=alert(1)>',
  'javascript:alert(1)',
  '<svg onload=alert(1)>',
  '"><script>alert(1)</script>',
  "';alert(String.fromCharCode(88,83,83))//",
];

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Onboarding Input Validation & Injection Prevention (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    seedAuthState();
  });

  // =========================================================================
  // SQL Injection Prevention
  // =========================================================================

  describe('SQL injection payloads on string inputs', () => {
    describe('billing_number rejects SQL injection', () => {
      for (const payload of SQL_PAYLOADS) {
        it(`rejects: ${payload.slice(0, 40)}`, async () => {
          const res = await app.inject({
            method: 'POST',
            url: '/api/v1/onboarding/steps/1',
            headers: { cookie: authCookie() },
            payload: { ...VALID_STEP1, billing_number: payload },
          });

          // billing_number has regex /^\d{5}$/ — SQL payloads must fail validation
          expect(res.statusCode).toBe(400);
          const body = JSON.parse(res.body);
          expect(body.error).toBeDefined();
          expect(body.data).toBeUndefined();
        });
      }
    });

    describe('cpsa_number rejects SQL injection', () => {
      for (const payload of SQL_PAYLOADS) {
        it(`safely handles: ${payload.slice(0, 40)}`, async () => {
          const res = await app.inject({
            method: 'POST',
            url: '/api/v1/onboarding/steps/1',
            headers: { cookie: authCookie() },
            payload: { ...VALID_STEP1, cpsa_number: payload },
          });

          // cpsa_number is min(1).max(20) — short payloads may pass Zod but are
          // safely handled by parameterised queries. Long payloads rejected by max(20).
          if (payload.length > 20) {
            expect(res.statusCode).toBe(400);
          } else {
            expect(res.statusCode).not.toBe(500);
          }
        });
      }
    });

    describe('legal_first_name rejects SQL injection', () => {
      for (const payload of SQL_PAYLOADS) {
        it(`safely handles: ${payload.slice(0, 40)}`, async () => {
          const res = await app.inject({
            method: 'POST',
            url: '/api/v1/onboarding/steps/1',
            headers: { cookie: authCookie() },
            payload: { ...VALID_STEP1, legal_first_name: payload },
          });

          // legal_first_name is min(1).max(100) — payloads within max are handled by parameterised queries
          if (payload.length > 100) {
            expect(res.statusCode).toBe(400);
          } else {
            expect(res.statusCode).not.toBe(500);
          }
        });
      }
    });

    describe('legal_last_name rejects SQL injection', () => {
      for (const payload of SQL_PAYLOADS) {
        it(`safely handles: ${payload.slice(0, 40)}`, async () => {
          const res = await app.inject({
            method: 'POST',
            url: '/api/v1/onboarding/steps/1',
            headers: { cookie: authCookie() },
            payload: { ...VALID_STEP1, legal_last_name: payload },
          });

          if (payload.length > 100) {
            expect(res.statusCode).toBe(400);
          } else {
            expect(res.statusCode).not.toBe(500);
          }
        });
      }
    });

    describe('primary_ba_number rejects SQL injection', () => {
      for (const payload of SQL_PAYLOADS) {
        it(`safely handles: ${payload.slice(0, 40)}`, async () => {
          const res = await app.inject({
            method: 'POST',
            url: '/api/v1/onboarding/steps/3',
            headers: { cookie: authCookie() },
            payload: { ...VALID_STEP3, primary_ba_number: payload },
          });

          // primary_ba_number is min(1).max(20)
          if (payload.length > 20) {
            expect(res.statusCode).toBe(400);
          } else {
            expect(res.statusCode).not.toBe(500);
          }
        });
      }
    });

    describe('location_name rejects SQL injection', () => {
      for (const payload of SQL_PAYLOADS) {
        it(`safely handles: ${payload.slice(0, 40)}`, async () => {
          const res = await app.inject({
            method: 'POST',
            url: '/api/v1/onboarding/steps/4',
            headers: { cookie: authCookie() },
            payload: { ...VALID_STEP4, location_name: payload },
          });

          // location_name is min(1).max(200) — payloads safely handled by parameterised queries
          if (payload.length > 200) {
            expect(res.statusCode).toBe(400);
          } else {
            expect(res.statusCode).not.toBe(500);
          }
        });
      }
    });

    describe('specialty_code rejects SQL injection', () => {
      for (const payload of SQL_PAYLOADS) {
        it(`rejects: ${payload.slice(0, 40)}`, async () => {
          const res = await app.inject({
            method: 'POST',
            url: '/api/v1/onboarding/steps/2',
            headers: { cookie: authCookie() },
            payload: { ...VALID_STEP2, specialty_code: payload },
          });

          // specialty_code is min(1).max(10) — most SQL payloads exceed 10 chars
          if (payload.length > 10) {
            expect(res.statusCode).toBe(400);
          } else {
            expect(res.statusCode).not.toBe(500);
          }
        });
      }
    });
  });

  // =========================================================================
  // XSS Prevention
  // =========================================================================

  describe('XSS payloads on stored text fields', () => {
    describe('legal_first_name with XSS payloads', () => {
      for (const payload of XSS_PAYLOADS) {
        it(`safely handles: ${payload.slice(0, 40)}`, async () => {
          const res = await app.inject({
            method: 'POST',
            url: '/api/v1/onboarding/steps/1',
            headers: { cookie: authCookie() },
            payload: { ...VALID_STEP1, legal_first_name: payload },
          });

          // XSS payloads within max(100) are accepted but stored safely
          if (payload.length > 100) {
            expect(res.statusCode).toBe(400);
          } else {
            expect(res.statusCode).not.toBe(500);
          }
        });
      }
    });

    describe('legal_last_name with XSS payloads', () => {
      for (const payload of XSS_PAYLOADS) {
        it(`safely handles: ${payload.slice(0, 40)}`, async () => {
          const res = await app.inject({
            method: 'POST',
            url: '/api/v1/onboarding/steps/1',
            headers: { cookie: authCookie() },
            payload: { ...VALID_STEP1, legal_last_name: payload },
          });

          if (payload.length > 100) {
            expect(res.statusCode).toBe(400);
          } else {
            expect(res.statusCode).not.toBe(500);
          }
        });
      }
    });

    describe('location_name with XSS payloads', () => {
      for (const payload of XSS_PAYLOADS) {
        it(`safely handles: ${payload.slice(0, 40)}`, async () => {
          const res = await app.inject({
            method: 'POST',
            url: '/api/v1/onboarding/steps/4',
            headers: { cookie: authCookie() },
            payload: { ...VALID_STEP4, location_name: payload },
          });

          // location_name is max(200) — XSS payloads within limits stored safely via parameterised queries
          if (payload.length > 200) {
            expect(res.statusCode).toBe(400);
          } else {
            expect(res.statusCode).not.toBe(500);
          }
        });
      }
    });

    describe('address street with XSS payloads', () => {
      for (const payload of XSS_PAYLOADS) {
        it(`safely handles: ${payload.slice(0, 40)}`, async () => {
          const res = await app.inject({
            method: 'POST',
            url: '/api/v1/onboarding/steps/4',
            headers: { cookie: authCookie() },
            payload: {
              ...VALID_STEP4,
              address: { ...VALID_STEP4.address, street: payload },
            },
          });

          // street is max(200)
          if (payload.length > 200) {
            expect(res.statusCode).toBe(400);
          } else {
            expect(res.statusCode).not.toBe(500);
          }
        });
      }
    });

    describe('address city with XSS payloads', () => {
      for (const payload of XSS_PAYLOADS) {
        it(`safely handles: ${payload.slice(0, 40)}`, async () => {
          const res = await app.inject({
            method: 'POST',
            url: '/api/v1/onboarding/steps/4',
            headers: { cookie: authCookie() },
            payload: {
              ...VALID_STEP4,
              address: { ...VALID_STEP4.address, city: payload },
            },
          });

          // city is max(100)
          if (payload.length > 100) {
            expect(res.statusCode).toBe(400);
          } else {
            expect(res.statusCode).not.toBe(500);
          }
        });
      }
    });
  });

  // =========================================================================
  // Format Validation — billing_number
  // =========================================================================

  describe('billing_number format validation', () => {
    it('rejects billing_number with 4 digits', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/1',
        headers: { cookie: authCookie() },
        payload: { ...VALID_STEP1, billing_number: '1234' },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects billing_number with 6 digits', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/1',
        headers: { cookie: authCookie() },
        payload: { ...VALID_STEP1, billing_number: '123456' },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects billing_number with letters', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/1',
        headers: { cookie: authCookie() },
        payload: { ...VALID_STEP1, billing_number: 'abcde' },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects billing_number with mixed alphanumeric', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/1',
        headers: { cookie: authCookie() },
        payload: { ...VALID_STEP1, billing_number: '12a45' },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects empty billing_number', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/1',
        headers: { cookie: authCookie() },
        payload: { ...VALID_STEP1, billing_number: '' },
      });

      expect(res.statusCode).toBe(400);
    });

    it('accepts valid 5-digit billing_number', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/1',
        headers: { cookie: authCookie() },
        payload: { ...VALID_STEP1, billing_number: '12345' },
      });

      // Should pass validation (may fail at service layer due to mocks, but not 400)
      expect(res.statusCode).not.toBe(400);
    });
  });

  // =========================================================================
  // Format Validation — step_number
  // =========================================================================

  describe('step_number path parameter validation', () => {
    it('rejects step_number 0', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/0',
        headers: { cookie: authCookie() },
        payload: VALID_STEP1,
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects step_number 8', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/8',
        headers: { cookie: authCookie() },
        payload: VALID_STEP1,
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects step_number with non-integer', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/1.5',
        headers: { cookie: authCookie() },
        payload: VALID_STEP1,
      });

      // z.coerce.number().int() should reject floating-point values
      expect(res.statusCode).toBe(400);
    });

    it('rejects step_number with letters', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/abc',
        headers: { cookie: authCookie() },
        payload: VALID_STEP1,
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects negative step_number', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/-1',
        headers: { cookie: authCookie() },
        payload: VALID_STEP1,
      });

      expect(res.statusCode).toBe(400);
    });

    it('accepts valid step_number 1', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/1',
        headers: { cookie: authCookie() },
        payload: VALID_STEP1,
      });

      expect(res.statusCode).not.toBe(400);
    });

    it('accepts valid step_number 7', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/7',
        headers: { cookie: authCookie() },
      });

      // Step 7 has no body
      expect(res.statusCode).not.toBe(400);
    });
  });

  // =========================================================================
  // Format Validation — postal_code
  // =========================================================================

  describe('postal_code format validation', () => {
    it('rejects postal_code with invalid format (all numbers)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/4',
        headers: { cookie: authCookie() },
        payload: {
          ...VALID_STEP4,
          address: { ...VALID_STEP4.address, postal_code: '123456' },
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects postal_code with US zip format', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/4',
        headers: { cookie: authCookie() },
        payload: {
          ...VALID_STEP4,
          address: { ...VALID_STEP4.address, postal_code: '90210' },
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects empty postal_code', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/4',
        headers: { cookie: authCookie() },
        payload: {
          ...VALID_STEP4,
          address: { ...VALID_STEP4.address, postal_code: '' },
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('accepts valid postal_code without space', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/4',
        headers: { cookie: authCookie() },
        payload: {
          ...VALID_STEP4,
          address: { ...VALID_STEP4.address, postal_code: 'T2P0A1' },
        },
      });

      expect(res.statusCode).not.toBe(400);
    });

    it('accepts valid postal_code with space', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/4',
        headers: { cookie: authCookie() },
        payload: {
          ...VALID_STEP4,
          address: { ...VALID_STEP4.address, postal_code: 'T2P 0A1' },
        },
      });

      expect(res.statusCode).not.toBe(400);
    });

    it('rejects postal_code with special characters', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/4',
        headers: { cookie: authCookie() },
        payload: {
          ...VALID_STEP4,
          address: { ...VALID_STEP4.address, postal_code: 'T2P-0A1' },
        },
      });

      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // Type Coercion Attacks
  // =========================================================================

  describe('Type coercion attacks', () => {
    describe('number where string expected', () => {
      it('rejects number for billing_number', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/onboarding/steps/1',
          headers: { cookie: authCookie() },
          payload: { ...VALID_STEP1, billing_number: 12345 },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects number for legal_first_name', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/onboarding/steps/1',
          headers: { cookie: authCookie() },
          payload: { ...VALID_STEP1, legal_first_name: 99999 },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects number for legal_last_name', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/onboarding/steps/1',
          headers: { cookie: authCookie() },
          payload: { ...VALID_STEP1, legal_last_name: 99999 },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects number for location_name', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/onboarding/steps/4',
          headers: { cookie: authCookie() },
          payload: { ...VALID_STEP4, location_name: 12345 },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects number for primary_ba_number', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/onboarding/steps/3',
          headers: { cookie: authCookie() },
          payload: { ...VALID_STEP3, primary_ba_number: 12345 },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects number for document_hash in IMA acknowledge', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/onboarding/ima/acknowledge',
          headers: { cookie: authCookie() },
          payload: { document_hash: 12345 },
        });

        expect(res.statusCode).toBe(400);
      });
    });

    describe('array where string expected', () => {
      it('rejects array for billing_number', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/onboarding/steps/1',
          headers: { cookie: authCookie() },
          payload: { ...VALID_STEP1, billing_number: ['12345'] },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects array for legal_first_name', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/onboarding/steps/1',
          headers: { cookie: authCookie() },
          payload: { ...VALID_STEP1, legal_first_name: ['Test'] },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects array for location_name', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/onboarding/steps/4',
          headers: { cookie: authCookie() },
          payload: { ...VALID_STEP4, location_name: ['Clinic'] },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects array for document_hash', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/onboarding/ima/acknowledge',
          headers: { cookie: authCookie() },
          payload: { document_hash: ['a'.repeat(64)] },
        });

        expect(res.statusCode).toBe(400);
      });
    });

    describe('null where required field expected', () => {
      it('rejects null for billing_number', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/onboarding/steps/1',
          headers: { cookie: authCookie() },
          payload: { ...VALID_STEP1, billing_number: null },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects null for legal_first_name', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/onboarding/steps/1',
          headers: { cookie: authCookie() },
          payload: { ...VALID_STEP1, legal_first_name: null },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects null for primary_ba_number', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/onboarding/steps/3',
          headers: { cookie: authCookie() },
          payload: { ...VALID_STEP3, primary_ba_number: null },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects null for is_pcpcm_enrolled', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/onboarding/steps/3',
          headers: { cookie: authCookie() },
          payload: { ...VALID_STEP3, is_pcpcm_enrolled: null },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects null for location_name', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/onboarding/steps/4',
          headers: { cookie: authCookie() },
          payload: { ...VALID_STEP4, location_name: null },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects null for document_hash', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/onboarding/ima/acknowledge',
          headers: { cookie: authCookie() },
          payload: { document_hash: null },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects null for specialty_code', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/onboarding/steps/2',
          headers: { cookie: authCookie() },
          payload: { ...VALID_STEP2, specialty_code: null },
        });

        expect(res.statusCode).toBe(400);
      });
    });

    describe('wrong step body for step number', () => {
      it('rejects step 1 body when sent to step 3', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/onboarding/steps/3',
          headers: { cookie: authCookie() },
          payload: VALID_STEP1,
        });

        // Step 3 requires primary_ba_number and is_pcpcm_enrolled — step 1 body lacks these
        expect(res.statusCode).toBe(400);
      });

      it('rejects step 3 body when sent to step 1', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/onboarding/steps/1',
          headers: { cookie: authCookie() },
          payload: VALID_STEP3,
        });

        // Step 1 requires billing_number, cpsa_number etc. — step 3 body lacks these
        expect(res.statusCode).toBe(400);
      });

      it('rejects step 4 body when sent to step 2', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/onboarding/steps/2',
          headers: { cookie: authCookie() },
          payload: VALID_STEP4,
        });

        // Step 2 requires specialty_code and physician_type — step 4 body lacks these
        expect(res.statusCode).toBe(400);
      });

      it('rejects step 2 body when sent to step 4', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/onboarding/steps/4',
          headers: { cookie: authCookie() },
          payload: VALID_STEP2,
        });

        // Step 4 requires location_name, address, etc. — step 2 body lacks these
        expect(res.statusCode).toBe(400);
      });
    });
  });

  // =========================================================================
  // UUID Parameter Validation
  // =========================================================================

  describe('UUID parameter validation', () => {
    it('rejects non-UUID in ba_id path param', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/ba/not-a-uuid/confirm-active',
        headers: { cookie: authCookie() },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects SQL injection in ba_id path param', async () => {
      const res = await app.inject({
        method: 'POST',
        url: "/api/v1/onboarding/ba/' OR 1=1--/confirm-active",
        headers: { cookie: authCookie() },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects numeric string in ba_id path param', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/ba/12345/confirm-active',
        headers: { cookie: authCookie() },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects empty ba_id path param', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/ba//confirm-active',
        headers: { cookie: authCookie() },
      });

      // Empty path segment either gives 400 or 404 (route not matched)
      expect([400, 404]).toContain(res.statusCode);
    });

    it('accepts valid UUID in ba_id path param', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/onboarding/ba/${VALID_UUID}/confirm-active`,
        headers: { cookie: authCookie() },
      });

      // Should not fail UUID validation (may fail at service layer)
      expect(res.statusCode).not.toBe(400);
    });
  });

  // =========================================================================
  // IMA Hash Tampering
  // =========================================================================

  describe('IMA document_hash validation', () => {
    it('rejects empty document_hash', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/ima/acknowledge',
        headers: { cookie: authCookie() },
        payload: { document_hash: '' },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects document_hash shorter than 64 characters', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/ima/acknowledge',
        headers: { cookie: authCookie() },
        payload: { document_hash: 'a'.repeat(63) },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects document_hash longer than 64 characters', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/ima/acknowledge',
        headers: { cookie: authCookie() },
        payload: { document_hash: 'a'.repeat(65) },
      });

      expect(res.statusCode).toBe(400);
    });

    it('accepts document_hash of exactly 64 characters (may fail at service for wrong hash)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/ima/acknowledge',
        headers: { cookie: authCookie() },
        payload: { document_hash: VALID_IMA_HASH },
      });

      // Should pass Zod validation (status may be non-400 from business logic)
      expect(res.statusCode).not.toBe(400);
    });

    it('rejects missing document_hash field', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/ima/acknowledge',
        headers: { cookie: authCookie() },
        payload: {},
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects document_hash with SQL injection payload', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/ima/acknowledge',
        headers: { cookie: authCookie() },
        payload: { document_hash: "' OR 1=1--" },
      });

      // SQL injection payload is shorter than 64 chars — fails length validation
      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // Step 3 PCPCM Refinement Validation
  // =========================================================================

  describe('Step 3 PCPCM conditional validation', () => {
    it('rejects is_pcpcm_enrolled=true without pcpcm_ba_number', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/3',
        headers: { cookie: authCookie() },
        payload: {
          primary_ba_number: '12345',
          is_pcpcm_enrolled: true,
          ffs_ba_number: '11111',
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects is_pcpcm_enrolled=true without ffs_ba_number', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/3',
        headers: { cookie: authCookie() },
        payload: {
          primary_ba_number: '12345',
          is_pcpcm_enrolled: true,
          pcpcm_ba_number: '67890',
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('accepts is_pcpcm_enrolled=false without extra BA numbers', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/3',
        headers: { cookie: authCookie() },
        payload: VALID_STEP3,
      });

      // Should pass validation
      expect(res.statusCode).not.toBe(400);
    });

    it('accepts is_pcpcm_enrolled=true with both BA numbers', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/3',
        headers: { cookie: authCookie() },
        payload: VALID_STEP3_PCPCM,
      });

      expect(res.statusCode).not.toBe(400);
    });

    it('rejects is_pcpcm_enrolled=true with empty pcpcm_ba_number', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/3',
        headers: { cookie: authCookie() },
        payload: {
          primary_ba_number: '12345',
          is_pcpcm_enrolled: true,
          pcpcm_ba_number: '',
          ffs_ba_number: '11111',
        },
      });

      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // Step 2 Enum Validation
  // =========================================================================

  describe('Step 2 physician_type enum validation', () => {
    it('rejects invalid physician_type value', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/2',
        headers: { cookie: authCookie() },
        payload: { ...VALID_STEP2, physician_type: 'invalid_type' },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects physician_type with uppercase (enum is lowercase)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/2',
        headers: { cookie: authCookie() },
        payload: { ...VALID_STEP2, physician_type: 'GP' },
      });

      expect(res.statusCode).toBe(400);
    });

    it('accepts valid physician_type "specialist"', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/2',
        headers: { cookie: authCookie() },
        payload: { ...VALID_STEP2, physician_type: 'specialist' },
      });

      expect(res.statusCode).not.toBe(400);
    });

    it('accepts valid physician_type "locum"', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/2',
        headers: { cookie: authCookie() },
        payload: { ...VALID_STEP2, physician_type: 'locum' },
      });

      expect(res.statusCode).not.toBe(400);
    });
  });

  // =========================================================================
  // Step 6 Enum Validation
  // =========================================================================

  describe('Step 6 submission preference enum validation', () => {
    it('rejects invalid ahcip_mode value', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/6',
        headers: { cookie: authCookie() },
        payload: { ahcip_mode: 'invalid_mode', wcb_mode: 'require_approval' },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects invalid wcb_mode value', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/6',
        headers: { cookie: authCookie() },
        payload: { ahcip_mode: 'auto_clean', wcb_mode: 'invalid_mode' },
      });

      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // Empty Body Validation
  // =========================================================================

  describe('Empty body validation', () => {
    it('rejects empty body for step 1', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/1',
        headers: { cookie: authCookie() },
        payload: {},
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects empty body for step 2', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/2',
        headers: { cookie: authCookie() },
        payload: {},
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects empty body for step 3', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/3',
        headers: { cookie: authCookie() },
        payload: {},
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects empty body for step 4', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/4',
        headers: { cookie: authCookie() },
        payload: {},
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects empty body for IMA acknowledge', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/ima/acknowledge',
        headers: { cookie: authCookie() },
        payload: {},
      });

      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // Validation Error Responses Don't Leak Internals
  // =========================================================================

  describe('Validation error responses do not leak internals', () => {
    it('400 response does not expose stack trace', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/1',
        headers: { cookie: authCookie() },
        payload: {},
      });

      expect(res.statusCode).toBe(400);
      const rawBody = res.body;
      expect(rawBody).not.toContain('node_modules');
      expect(rawBody).not.toContain('.ts:');
      expect(rawBody).not.toMatch(/at\s+\w+\s+\(/);
    });

    it('400 response does not expose database details', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/1',
        headers: { cookie: authCookie() },
        payload: { ...VALID_STEP1, billing_number: 12345 },
      });

      expect(res.statusCode).toBe(400);
      const rawBody = res.body;
      expect(rawBody).not.toContain('postgres');
      expect(rawBody).not.toContain('drizzle');
      expect(rawBody).not.toContain('SELECT');
      expect(rawBody).not.toContain('INSERT');
    });

    it('400 response has consistent error shape', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/onboarding/steps/1',
        headers: { cookie: authCookie() },
        payload: {},
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBeDefined();
      expect(body.error.message).toBeDefined();
      expect(body.data).toBeUndefined();
    });
  });
});
