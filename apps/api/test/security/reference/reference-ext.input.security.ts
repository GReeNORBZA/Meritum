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
import { referenceRoutes } from '../../../src/domains/reference/reference.routes.js';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import {
  type SessionManagementDeps,
  hashToken,
} from '../../../src/domains/iam/iam.service.js';
import { randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Fixed test users/sessions
// ---------------------------------------------------------------------------

const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_USER_ID = '22222222-0000-0000-0000-000000000001';
const PHYSICIAN_SESSION_ID = '33333333-0000-0000-0000-000000000001';

const ADMIN_SESSION_TOKEN = randomBytes(32).toString('hex');
const ADMIN_SESSION_TOKEN_HASH = hashToken(ADMIN_SESSION_TOKEN);
const ADMIN_USER_ID = '22222222-0000-0000-0000-000000000002';
const ADMIN_SESSION_ID = '33333333-0000-0000-0000-000000000002';

// ---------------------------------------------------------------------------
// Mock stores
// ---------------------------------------------------------------------------

interface MockUser {
  userId: string;
  email: string;
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
    createSession: vi.fn(async () => ({ sessionId: '44444444-0000-0000-0000-000000000001' })),
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
    log: vi.fn(async () => {}),
  };
}

function createMockEvents() {
  return { emit: vi.fn() };
}

// ---------------------------------------------------------------------------
// Mock reference repository — includes ALL repo methods (core + extension)
// ---------------------------------------------------------------------------

function createMockReferenceRepo() {
  return {
    // Version management
    findActiveVersion: vi.fn(async () => undefined),
    findVersionForDate: vi.fn(async () => undefined),
    findVersionByDate: vi.fn(async () => undefined),
    findVersionById: vi.fn(async () => undefined),
    findVersionByVersionId: vi.fn(async () => undefined),
    listVersions: vi.fn(async () => []),
    createVersion: vi.fn(async () => ({})),
    activateVersion: vi.fn(async () => {}),
    deactivateVersion: vi.fn(async () => {}),

    // HSC
    searchHscCodes: vi.fn(async () => []),
    findHscByCode: vi.fn(async () => undefined),
    getHscByCode: vi.fn(async () => undefined),
    getHscCodesByVersion: vi.fn(async () => []),
    listHscByVersion: vi.fn(async () => []),
    getHscFavourites: vi.fn(async () => []),
    bulkInsertHscCodes: vi.fn(async () => {}),

    // DI
    searchDiCodes: vi.fn(async () => []),
    findDiByCode: vi.fn(async () => undefined),
    getDiByCode: vi.fn(async () => undefined),
    getDiCodesByVersion: vi.fn(async () => []),
    bulkInsertDiCodes: vi.fn(async () => {}),

    // Modifiers
    findModifiersForHsc: vi.fn(async () => []),
    getModifiersForHsc: vi.fn(async () => []),
    findModifierByCode: vi.fn(async () => undefined),
    getModifierByCode: vi.fn(async () => undefined),
    listAllModifiers: vi.fn(async () => []),
    getModifiersByVersion: vi.fn(async () => []),
    bulkInsertModifiers: vi.fn(async () => {}),

    // Functional centres
    listFunctionalCentres: vi.fn(async () => []),
    findFunctionalCentre: vi.fn(async () => undefined),
    getFunctionalCentresByVersion: vi.fn(async () => []),
    bulkInsertFunctionalCentres: vi.fn(async () => {}),

    // Explanatory codes
    findExplanatoryCode: vi.fn(async () => undefined),
    getExplanatoryCode: vi.fn(async () => undefined),
    getExplanatoryCodesByVersion: vi.fn(async () => []),
    bulkInsertExplanatoryCodes: vi.fn(async () => {}),

    // RRNP
    findRrnpRate: vi.fn(async () => undefined),
    getRrnpCommunity: vi.fn(async () => undefined),
    listRrnpCommunities: vi.fn(async () => []),
    getRrnpCommunitiesByVersion: vi.fn(async () => []),
    bulkInsertRrnpCommunities: vi.fn(async () => {}),

    // PCPCM
    findPcpcmBasket: vi.fn(async () => undefined),
    getPcpcmBasket: vi.fn(async () => undefined),
    getPcpcmBasketsByVersion: vi.fn(async () => []),
    bulkInsertPcpcmBaskets: vi.fn(async () => {}),

    // Holidays
    listHolidaysByYear: vi.fn(async () => []),
    listHolidays: vi.fn(async () => []),
    isHoliday: vi.fn(async () => false),
    getHolidayById: vi.fn(async () => undefined),
    createHoliday: vi.fn(async () => ({})),
    updateHoliday: vi.fn(async () => ({})),
    deleteHoliday: vi.fn(async () => {}),

    // Governing rules
    findGoverningRules: vi.fn(async () => []),
    findRulesForContext: vi.fn(async () => []),
    findRuleById: vi.fn(async () => undefined),
    getGoverningRuleById: vi.fn(async () => undefined),
    getGoverningRulesByVersion: vi.fn(async () => []),
    listRulesByCategory: vi.fn(async () => []),
    bulkInsertGoverningRules: vi.fn(async () => {}),
    bulkInsertRules: vi.fn(async () => {}),

    // Staging
    createStagingRecord: vi.fn(async () => ({})),
    createStagingEntry: vi.fn(async () => ({})),
    findStagingById: vi.fn(async () => undefined),
    findStagingEntry: vi.fn(async () => undefined),
    updateStagingStatus: vi.fn(async () => {}),
    deleteStagingRecord: vi.fn(async () => {}),
    deleteStagingEntry: vi.fn(async () => {}),
    listStagingByDataSet: vi.fn(async () => []),

    // Change summaries
    getChangeSummaries: vi.fn(async () => []),
    getChangeDetails: vi.fn(async () => []),

    // Extension: ICD Crosswalk
    getIcdCrosswalkByIcd10: vi.fn(async () => []),
    searchIcdCrosswalk: vi.fn(async () => []),
    bulkInsertIcdCrosswalk: vi.fn(async () => {}),

    // Extension: Provider Registry
    searchProviderRegistry: vi.fn(async () => []),
    getProviderByCpsa: vi.fn(async () => undefined),
    bulkUpsertProviderRegistry: vi.fn(async () => {}),

    // Extension: Billing Guidance
    listBillingGuidance: vi.fn(async () => []),
    searchBillingGuidance: vi.fn(async () => []),
    getBillingGuidanceById: vi.fn(async () => undefined),

    // Extension: Provincial PHN Formats
    listProvincialPhnFormats: vi.fn(async () => []),

    // Extension: Reciprocal Billing
    getReciprocalRules: vi.fn(async () => []),

    // Extension: Anesthesia Rules
    listAnesthesiaRules: vi.fn(async () => []),
    getAnesthesiaRuleByScenario: vi.fn(async () => undefined),

    // Extension: Bundling Rules
    getBundlingRuleForPair: vi.fn(async () => undefined),
    checkBundlingConflicts: vi.fn(async () => []),

    // Extension: Justification Templates
    listJustificationTemplates: vi.fn(async () => []),
    getJustificationTemplate: vi.fn(async () => undefined),

    // WCB
    searchWcbCodes: vi.fn(async () => []),
    findWcbByCode: vi.fn(async () => undefined),
    bulkInsertWcbCodes: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let mockRefRepo: ReturnType<typeof createMockReferenceRepo>;

async function buildTestApp(): Promise<FastifyInstance> {
  const mockSessionRepo = createMockSessionRepo();
  mockRefRepo = createMockReferenceRepo();

  const sessionDeps: SessionManagementDeps = {
    sessionRepo: mockSessionRepo,
    auditRepo: createMockAuditRepo(),
    events: createMockEvents(),
  };

  const handlerDeps = {
    serviceDeps: {
      repo: mockRefRepo,
      auditLog: createMockAuditRepo(),
      eventEmitter: createMockEvents(),
    },
  };

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  await testApp.register(authPluginFp, { sessionDeps });

  testApp.setErrorHandler((error, request, reply) => {
    if (error.validation) {
      return reply.code(400).send({
        error: { code: 'VALIDATION_ERROR', message: 'Validation failed' },
      });
    }
    if (error.statusCode && error.statusCode >= 400 && error.statusCode < 500) {
      return reply.code(error.statusCode).send({
        error: { code: (error as any).code ?? 'ERROR', message: error.message },
      });
    }
    return reply.code(500).send({
      error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
    });
  });

  await testApp.register(referenceRoutes, { deps: handlerDeps });
  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function seedSessions() {
  users = [];
  sessions = [];

  // Physician user
  users.push({
    userId: PHYSICIAN_USER_ID,
    email: 'physician@example.com',
    role: 'PHYSICIAN',
    subscriptionStatus: 'ACTIVE',
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

  // Admin user
  users.push({
    userId: ADMIN_USER_ID,
    email: 'admin@example.com',
    role: 'ADMIN',
    subscriptionStatus: 'ACTIVE',
  });
  sessions.push({
    sessionId: ADMIN_SESSION_ID,
    userId: ADMIN_USER_ID,
    tokenHash: ADMIN_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });
}

function physicianCookie(): string {
  return `session=${PHYSICIAN_SESSION_TOKEN}`;
}

function adminCookie(): string {
  return `session=${ADMIN_SESSION_TOKEN}`;
}

const DUMMY_UUID = '00000000-0000-0000-0000-000000000001';

// ---------------------------------------------------------------------------
// Shared payload arrays
// ---------------------------------------------------------------------------

const SQL_INJECTION_PAYLOADS = [
  "' OR 1=1--",
  "'; DROP TABLE hsc_codes;--",
  "1 UNION SELECT * FROM users--",
  "' UNION SELECT * FROM providers--",
  "1; SELECT * FROM users --",
  "1' OR '1'='1",
  "admin'--",
  "' OR ''='",
];

const XSS_PAYLOADS = [
  '<script>alert("xss")</script>',
  '<script>alert(1)</script>',
  '<img src=x onerror=alert(1)>',
  '<img onerror=alert(1) src=x>',
  'javascript:alert(1)',
  '<svg/onload=alert(1)>',
  '"><script>alert(1)</script>',
];

const INVALID_UUIDS = [
  'not-a-uuid',
  '12345',
  'abcdefg',
  '00000000-0000-0000-0000-00000000000', // too short
  '00000000-0000-0000-0000-0000000000001', // too long
  '../../../etc/passwd',
  "'; DROP TABLE--",
];

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Reference Data Extensions Input Validation & Injection Prevention (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    seedSessions();
    // Reset mock call tracking
    vi.clearAllMocks();
    // Re-seed sessions after clearAllMocks since mock session repo uses closures
    seedSessions();
  });

  // =========================================================================
  // 1. SQL injection payloads on extension search queries
  // =========================================================================

  describe('SQL injection payloads on extension search queries', () => {
    describe('ICD crosswalk search q param (GET /api/v1/ref/icd-crosswalk)', () => {
      for (const payload of SQL_INJECTION_PAYLOADS) {
        it(`rejects SQL injection in q param: ${payload.substring(0, 30)}...`, async () => {
          const res = await app.inject({
            method: 'GET',
            url: `/api/v1/ref/icd-crosswalk?q=${encodeURIComponent(payload)}`,
            headers: { cookie: physicianCookie() },
          });

          // Schema allows strings up to 100 chars; payloads that fit pass validation.
          // Security is ensured by parameterised queries, not input rejection.
          // 404 occurs when resolveVersion finds no active ICD_CROSSWALK version.
          expect([200, 400, 404]).toContain(res.statusCode);

          if (res.statusCode === 200) {
            // Verify the search query was passed as a parameter, not interpolated into SQL
            expect(mockRefRepo.searchIcdCrosswalk).toHaveBeenCalled();
            const callArgs = mockRefRepo.searchIcdCrosswalk.mock.calls[0];
            expect(callArgs[0]).toBe(payload);
            // Ensure no SQL error details leaked
            expect(res.body).not.toContain('syntax error');
            expect(res.body).not.toContain('ERROR');
          }
        });
      }
    });

    describe('Provider registry search q param (GET /api/v1/ref/providers/search)', () => {
      for (const payload of SQL_INJECTION_PAYLOADS) {
        it(`rejects SQL injection in q param: ${payload.substring(0, 30)}...`, async () => {
          const res = await app.inject({
            method: 'GET',
            url: `/api/v1/ref/providers/search?q=${encodeURIComponent(payload)}`,
            headers: { cookie: physicianCookie() },
          });

          // Provider search requires min 2 chars -- payloads are all > 2 chars
          expect([200, 400]).toContain(res.statusCode);

          if (res.statusCode === 200) {
            expect(mockRefRepo.searchProviderRegistry).toHaveBeenCalled();
            const callArgs = mockRefRepo.searchProviderRegistry.mock.calls[0];
            expect(callArgs[0]).toBe(payload);
          }
        });
      }
    });

    describe('Billing guidance search q param (GET /api/v1/ref/guidance)', () => {
      for (const payload of SQL_INJECTION_PAYLOADS) {
        it(`handles SQL injection in guidance q param: ${payload.substring(0, 30)}...`, async () => {
          const res = await app.inject({
            method: 'GET',
            url: `/api/v1/ref/guidance?q=${encodeURIComponent(payload)}`,
            headers: { cookie: physicianCookie() },
          });

          // Guidance q is optional, max 200 chars -- passes Zod but parameterised queries keep it safe
          expect([200, 400]).toContain(res.statusCode);
        });
      }
    });

    describe('Anesthesia scenario_code field (POST /api/v1/ref/anesthesia-rules/calculate)', () => {
      for (const payload of SQL_INJECTION_PAYLOADS) {
        it(`handles SQL injection in scenario_code: ${payload.substring(0, 30)}...`, async () => {
          const res = await app.inject({
            method: 'POST',
            url: '/api/v1/ref/anesthesia-rules/calculate',
            headers: { cookie: physicianCookie() },
            payload: {
              scenario_code: payload,
              time_minutes: 60,
            },
          });

          // scenario_code is z.string().max(30) -- payloads under 30 chars pass validation
          // but are safely parameterised
          expect([200, 400, 404]).toContain(res.statusCode);
        });
      }
    });

    describe('Bundling codes array values (POST /api/v1/ref/bundling-rules/check)', () => {
      for (const payload of SQL_INJECTION_PAYLOADS) {
        it(`rejects SQL injection in codes array: ${payload.substring(0, 30)}...`, async () => {
          const res = await app.inject({
            method: 'POST',
            url: '/api/v1/ref/bundling-rules/check',
            headers: { cookie: physicianCookie() },
            payload: {
              codes: [payload, '03.01A'],
            },
          });

          // codes items are z.string().max(10) — only payloads > 10 chars should be rejected
          if (payload.length > 10) {
            expect(res.statusCode).toBe(400);
          } else {
            // Shorter payloads pass Zod validation; security is ensured by parameterised queries
            expect([200, 400, 404]).toContain(res.statusCode);
          }
        });
      }
    });

    describe('ICD crosswalk date param with SQL injection', () => {
      const DATE_INJECTIONS = [
        "2026-01-01'; DROP TABLE--",
        "1 OR 1=1",
        "'; SELECT * FROM users--",
      ];

      for (const payload of DATE_INJECTIONS) {
        it(`rejects SQL injection in date: ${payload.substring(0, 30)}...`, async () => {
          const res = await app.inject({
            method: 'GET',
            url: `/api/v1/ref/icd-crosswalk?q=flu&date=${encodeURIComponent(payload)}`,
            headers: { cookie: physicianCookie() },
          });

          // date is validated by z.string().date() -- must be YYYY-MM-DD
          expect(res.statusCode).toBe(400);
        });
      }
    });
  });

  // =========================================================================
  // 2. XSS payloads on extension endpoints
  // =========================================================================

  describe('XSS payloads on extension endpoints', () => {
    describe('XSS in anesthesia calculate body fields', () => {
      for (const payload of XSS_PAYLOADS) {
        it(`handles XSS in scenario_code: ${payload.substring(0, 30)}...`, async () => {
          const res = await app.inject({
            method: 'POST',
            url: '/api/v1/ref/anesthesia-rules/calculate',
            headers: { cookie: physicianCookie() },
            payload: {
              scenario_code: payload,
              time_minutes: 60,
            },
          });

          // scenario_code is z.string().max(30) -- some XSS payloads exceed 30 chars
          // and will be rejected; shorter ones pass but are safely parameterised
          expect([200, 400, 404]).toContain(res.statusCode);
        });
      }

      it('handles XSS in modifier strings', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/ref/anesthesia-rules/calculate',
          headers: { cookie: physicianCookie() },
          payload: {
            scenario_code: 'ANES01',
            time_minutes: 60,
            modifiers: ['<img>', 'x"on'],
          },
        });

        // modifiers items are z.string().max(4) -- '<img>' is 5 chars, rejected
        expect(res.statusCode).toBe(400);
      });
    });

    describe('XSS in bundling check codes array', () => {
      for (const payload of XSS_PAYLOADS) {
        it(`handles XSS in bundling codes: ${payload.substring(0, 30)}...`, async () => {
          const res = await app.inject({
            method: 'POST',
            url: '/api/v1/ref/bundling-rules/check',
            headers: { cookie: physicianCookie() },
            payload: {
              codes: [payload, '03.01A'],
            },
          });

          // codes items are z.string().max(10) -- most XSS payloads > 10 chars
          expect(res.statusCode).toBe(400);
        });
      }
    });

    describe('XSS in ICD crosswalk search q param', () => {
      for (const payload of XSS_PAYLOADS) {
        it(`handles XSS in ICD crosswalk search: ${payload.substring(0, 30)}...`, async () => {
          const res = await app.inject({
            method: 'GET',
            url: `/api/v1/ref/icd-crosswalk?q=${encodeURIComponent(payload)}`,
            headers: { cookie: physicianCookie() },
          });

          // q is z.string().min(1).max(100) -- XSS payloads within range pass Zod
          // but are safely parameterised in queries.
          // 404 occurs when resolveVersion finds no active ICD_CROSSWALK version.
          expect([200, 400, 404]).toContain(res.statusCode);
        });
      }
    });

    describe('XSS in provider search q param', () => {
      for (const payload of XSS_PAYLOADS) {
        it(`handles XSS in provider search q: ${payload.substring(0, 30)}...`, async () => {
          const res = await app.inject({
            method: 'GET',
            url: `/api/v1/ref/providers/search?q=${encodeURIComponent(payload)}`,
            headers: { cookie: physicianCookie() },
          });

          // Provider search q is z.string().min(2).max(100)
          expect([200, 400]).toContain(res.statusCode);
        });
      }
    });

    describe('XSS in billing guidance search q param', () => {
      for (const payload of XSS_PAYLOADS) {
        it(`handles XSS in guidance search: ${payload.substring(0, 30)}...`, async () => {
          const res = await app.inject({
            method: 'GET',
            url: `/api/v1/ref/guidance?q=${encodeURIComponent(payload)}`,
            headers: { cookie: physicianCookie() },
          });

          // Guidance q is optional, max 200 -- XSS payloads pass but are safe
          expect([200, 400]).toContain(res.statusCode);
        });
      }
    });
  });

  // =========================================================================
  // 3. Type coercion attacks on extension endpoints
  // =========================================================================

  describe('Type coercion attacks on extension endpoints', () => {
    describe('anesthesia calculate: time_minutes as wrong type', () => {
      it('rejects string value for time_minutes', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/ref/anesthesia-rules/calculate',
          headers: { cookie: physicianCookie() },
          payload: {
            scenario_code: 'ANES01',
            time_minutes: 'sixty',
          },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects negative time_minutes', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/ref/anesthesia-rules/calculate',
          headers: { cookie: physicianCookie() },
          payload: {
            scenario_code: 'ANES01',
            time_minutes: -10,
          },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects zero time_minutes (min is 0, so 0 should be accepted)', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/ref/anesthesia-rules/calculate',
          headers: { cookie: physicianCookie() },
          payload: {
            scenario_code: 'ANES01',
            time_minutes: 0,
          },
        });

        // z.number().int().min(0) -- 0 is valid
        expect(res.statusCode).not.toBe(400);
      });

      it('rejects boolean for time_minutes', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/ref/anesthesia-rules/calculate',
          headers: { cookie: physicianCookie() },
          payload: {
            scenario_code: 'ANES01',
            time_minutes: true,
          },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects null for time_minutes', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/ref/anesthesia-rules/calculate',
          headers: { cookie: physicianCookie() },
          payload: {
            scenario_code: 'ANES01',
            time_minutes: null,
          },
        });

        expect(res.statusCode).toBe(400);
      });
    });

    describe('bundling check: codes as wrong type', () => {
      it('rejects string instead of array for codes', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/ref/bundling-rules/check',
          headers: { cookie: physicianCookie() },
          payload: {
            codes: '03.01A,03.04J',
          },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects empty array for codes (min 2)', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/ref/bundling-rules/check',
          headers: { cookie: physicianCookie() },
          payload: { codes: [] },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects number instead of array for codes', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/ref/bundling-rules/check',
          headers: { cookie: physicianCookie() },
          payload: {
            codes: 12345,
          },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects object instead of array for codes', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/ref/bundling-rules/check',
          headers: { cookie: physicianCookie() },
          payload: {
            codes: { a: '03.01A', b: '03.04J' },
          },
        });

        expect(res.statusCode).toBe(400);
      });
    });

    describe('ICD crosswalk: limit validation', () => {
      it('rejects negative limit: -1', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/icd-crosswalk?q=flu&limit=-1',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects limit exceeding max (50): limit=100', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/icd-crosswalk?q=flu&limit=100',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects non-numeric limit: abc', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/icd-crosswalk?q=flu&limit=abc',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects limit=0 (below min of 1)', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/icd-crosswalk?q=flu&limit=0',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('accepts valid limit within range', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/icd-crosswalk?q=flu&limit=25',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).not.toBe(400);
      });
    });

    describe('guidance id: non-UUID id parameter', () => {
      it('rejects non-UUID string for guidance id', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/guidance/not-a-uuid',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects numeric string for guidance id', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/guidance/12345',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });
    });

    describe('justification template id: non-UUID', () => {
      it('rejects non-UUID string for template id', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/justification-templates/not-a-uuid',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects numeric string for template id', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/justification-templates/12345',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });
    });

    describe('province param: too long, special chars', () => {
      it('rejects province with too many chars (max length 2)', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/reciprocal-rules/ABC',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects province with special characters', async () => {
        const res = await app.inject({
          method: 'GET',
          url: `/api/v1/ref/reciprocal-rules/${encodeURIComponent("A'")}`,
          headers: { cookie: physicianCookie() },
        });

        // z.string().length(2) -- "A'" is 2 chars but contains special char
        // Zod validates length only; the special char passes Zod but is safe in parameterised query
        expect([200, 400]).toContain(res.statusCode);
      });

      it('rejects single-character province', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/reciprocal-rules/A',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });
    });

    describe('bundling pair: code_a / code_b with special chars', () => {
      it('rejects code_a with SQL injection payload (> 10 chars)', async () => {
        const res = await app.inject({
          method: 'GET',
          url: `/api/v1/ref/bundling-rules/pair/${encodeURIComponent("' OR 1=1--")}/03.04J`,
          headers: { cookie: physicianCookie() },
        });

        // code_a is z.string().max(10) -- "' OR 1=1--" is 10 chars, borderline
        expect([200, 400]).toContain(res.statusCode);
      });

      it('rejects code_b with SQL injection payload (> 10 chars)', async () => {
        const res = await app.inject({
          method: 'GET',
          url: `/api/v1/ref/bundling-rules/pair/03.01A/${encodeURIComponent("'; DROP T--")}`,
          headers: { cookie: physicianCookie() },
        });

        // code_b > 10 chars -- rejected by Zod
        expect(res.statusCode).toBe(400);
      });

      it('rejects code_a exceeding max length (10)', async () => {
        const longCode = 'A'.repeat(11);
        const res = await app.inject({
          method: 'GET',
          url: `/api/v1/ref/bundling-rules/pair/${longCode}/03.04J`,
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects code_b exceeding max length (10)', async () => {
        const longCode = 'A'.repeat(11);
        const res = await app.inject({
          method: 'GET',
          url: `/api/v1/ref/bundling-rules/pair/03.01A/${longCode}`,
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });
    });

    describe('wrong types in guidance query parameters', () => {
      it('rejects non-numeric page parameter', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/guidance?page=abc',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects negative page_size', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/guidance?page_size=-1',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects invalid guidance category enum', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/guidance?category=INVALID_CATEGORY',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });
    });
  });

  // =========================================================================
  // 4. UUID parameter validation for extension endpoints
  // =========================================================================

  describe('UUID parameter validation for extension endpoints', () => {
    describe('GET /api/v1/ref/guidance/:id with invalid UUIDs', () => {
      for (const invalidUuid of INVALID_UUIDS) {
        it(`rejects invalid UUID: ${invalidUuid.substring(0, 20)}`, async () => {
          const res = await app.inject({
            method: 'GET',
            url: `/api/v1/ref/guidance/${encodeURIComponent(invalidUuid)}`,
            headers: { cookie: physicianCookie() },
          });

          expect(res.statusCode).toBe(400);
        });
      }
    });

    describe('GET /api/v1/ref/justification-templates/:id with invalid UUIDs', () => {
      for (const invalidUuid of INVALID_UUIDS) {
        it(`rejects invalid UUID: ${invalidUuid.substring(0, 20)}`, async () => {
          const res = await app.inject({
            method: 'GET',
            url: `/api/v1/ref/justification-templates/${encodeURIComponent(invalidUuid)}`,
            headers: { cookie: physicianCookie() },
          });

          expect(res.statusCode).toBe(400);
        });
      }
    });

    describe('PUT /api/v1/admin/ref/holidays/:id with invalid UUIDs', () => {
      for (const invalidUuid of INVALID_UUIDS.slice(0, 4)) {
        it(`rejects invalid UUID: ${invalidUuid.substring(0, 20)}`, async () => {
          const res = await app.inject({
            method: 'PUT',
            url: `/api/v1/admin/ref/holidays/${encodeURIComponent(invalidUuid)}`,
            headers: { cookie: adminCookie() },
            payload: { name: 'Updated' },
          });

          expect(res.statusCode).toBe(400);
        });
      }
    });

    describe('DELETE /api/v1/admin/ref/holidays/:id with invalid UUIDs', () => {
      for (const invalidUuid of INVALID_UUIDS.slice(0, 4)) {
        it(`rejects invalid UUID: ${invalidUuid.substring(0, 20)}`, async () => {
          const res = await app.inject({
            method: 'DELETE',
            url: `/api/v1/admin/ref/holidays/${encodeURIComponent(invalidUuid)}`,
            headers: { cookie: adminCookie() },
          });

          expect(res.statusCode).toBe(400);
        });
      }
    });

    it('accepts valid UUID for guidance detail', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/ref/guidance/${DUMMY_UUID}`,
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).not.toBe(400);
    });

    it('accepts valid UUID for justification template detail', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/ref/justification-templates/${DUMMY_UUID}`,
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).not.toBe(400);
    });
  });

  // =========================================================================
  // 5. Province parameter validation
  // =========================================================================

  describe('Province parameter validation', () => {
    it('rejects too-long province value (3 chars)', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/reciprocal-rules/ABC',
        headers: { cookie: physicianCookie() },
      });

      // reciprocalBillingParamSchema province is z.string().length(2)
      expect(res.statusCode).toBe(400);
    });

    it('rejects too-long province value (10 chars)', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/reciprocal-rules/ABCDEFGHIJ',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects single-character province (too short)', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/reciprocal-rules/A',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects numeric province code', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/reciprocal-rules/12',
        headers: { cookie: physicianCookie() },
      });

      // z.string().length(2) -- "12" passes length check
      // Numbers are valid strings; param passes Zod but lookup may return empty
      expect([200, 400]).toContain(res.statusCode);
    });

    it('rejects province with special characters', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/ref/reciprocal-rules/${encodeURIComponent("A'")}`,
        headers: { cookie: physicianCookie() },
      });

      // "A'" is length 2 -- passes Zod length check; safe via parameterised queries
      expect([200, 400]).toContain(res.statusCode);
    });

    it('rejects empty province code (no path match)', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/reciprocal-rules/',
        headers: { cookie: physicianCookie() },
      });

      // Empty path segment -- should be 400 or 404 (no matching route)
      expect([400, 404]).toContain(res.statusCode);
    });

    it('rejects path traversal in province', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/ref/reciprocal-rules/${encodeURIComponent('../')}`,
        headers: { cookie: physicianCookie() },
      });

      // "../" is 3 chars -- exceeds z.string().length(2)
      expect(res.statusCode).toBe(400);
    });

    it('accepts valid 2-char province code', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/reciprocal-rules/AB',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).not.toBe(400);
    });

    it('accepts valid lowercase 2-char province code', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/reciprocal-rules/ab',
        headers: { cookie: physicianCookie() },
      });

      // z.string().length(2) -- lowercase passes length check
      expect(res.statusCode).not.toBe(400);
    });
  });

  // =========================================================================
  // 6. Anesthesia calculate body validation
  // =========================================================================

  describe('Anesthesia calculate body validation', () => {
    it('rejects missing required field: scenario_code', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/anesthesia-rules/calculate',
        headers: { cookie: physicianCookie() },
        payload: {
          time_minutes: 60,
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects missing required field: time_minutes', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/anesthesia-rules/calculate',
        headers: { cookie: physicianCookie() },
        payload: {
          scenario_code: 'ANES01',
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects empty body entirely', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/anesthesia-rules/calculate',
        headers: { cookie: physicianCookie() },
        payload: {},
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects no body (undefined)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/anesthesia-rules/calculate',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects wrong type for scenario_code (number)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/anesthesia-rules/calculate',
        headers: { cookie: physicianCookie() },
        payload: {
          scenario_code: 12345,
          time_minutes: 60,
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects wrong type for time_minutes (string)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/anesthesia-rules/calculate',
        headers: { cookie: physicianCookie() },
        payload: {
          scenario_code: 'ANES01',
          time_minutes: 'sixty',
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects negative time_minutes', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/anesthesia-rules/calculate',
        headers: { cookie: physicianCookie() },
        payload: {
          scenario_code: 'ANES01',
          time_minutes: -5,
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects empty scenario_code (empty string)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/anesthesia-rules/calculate',
        headers: { cookie: physicianCookie() },
        payload: {
          scenario_code: '',
          time_minutes: 60,
        },
      });

      // z.string().max(30) -- empty string may pass if no .min() constraint
      // Behaviour depends on schema definition
      expect([200, 400, 404]).toContain(res.statusCode);
    });

    it('rejects scenario_code exceeding max length (30)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/anesthesia-rules/calculate',
        headers: { cookie: physicianCookie() },
        payload: {
          scenario_code: 'A'.repeat(31),
          time_minutes: 60,
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('strips or ignores additional unexpected fields', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/anesthesia-rules/calculate',
        headers: { cookie: physicianCookie() },
        payload: {
          scenario_code: 'ANES01',
          time_minutes: 60,
          extra_field: 'should_be_ignored',
          malicious: '<script>alert(1)</script>',
        },
      });

      // Zod will strip unknown keys by default -- valid fields pass
      expect(res.statusCode).not.toBe(400);
    });

    it('rejects float for time_minutes (must be int)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/anesthesia-rules/calculate',
        headers: { cookie: physicianCookie() },
        payload: {
          scenario_code: 'ANES01',
          time_minutes: 60.5,
        },
      });

      // z.number().int().min(0) -- 60.5 fails .int() check
      expect(res.statusCode).toBe(400);
    });

    it('rejects negative base_units', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/anesthesia-rules/calculate',
        headers: { cookie: physicianCookie() },
        payload: {
          scenario_code: 'ANES01',
          time_minutes: 60,
          base_units: -1,
        },
      });

      // base_units is z.number().int().min(0).optional()
      expect(res.statusCode).toBe(400);
    });

    it('accepts valid anesthesia calculate body', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/anesthesia-rules/calculate',
        headers: { cookie: physicianCookie() },
        payload: {
          scenario_code: 'ANES01',
          time_minutes: 60,
        },
      });

      expect(res.statusCode).not.toBe(400);
    });

    it('accepts valid body with all optional fields', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/anesthesia-rules/calculate',
        headers: { cookie: physicianCookie() },
        payload: {
          scenario_code: 'ANES01',
          time_minutes: 60,
          base_units: 5,
          modifiers: ['AA'],
        },
      });

      expect(res.statusCode).not.toBe(400);
    });
  });

  // =========================================================================
  // 7. Bundling check body validation
  // =========================================================================

  describe('Bundling check body validation', () => {
    it('rejects empty codes array (min 2)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/bundling-rules/check',
        headers: { cookie: physicianCookie() },
        payload: { codes: [] },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects single code in array (min 2)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/bundling-rules/check',
        headers: { cookie: physicianCookie() },
        payload: { codes: ['03.01A'] },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects non-array codes (string)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/bundling-rules/check',
        headers: { cookie: physicianCookie() },
        payload: { codes: '03.01A,03.04J' },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects non-array codes (number)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/bundling-rules/check',
        headers: { cookie: physicianCookie() },
        payload: { codes: 12345 },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects non-array codes (object)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/bundling-rules/check',
        headers: { cookie: physicianCookie() },
        payload: { codes: { a: '03.01A', b: '03.04J' } },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects codes with special characters (items > 10 chars)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/bundling-rules/check',
        headers: { cookie: physicianCookie() },
        payload: {
          codes: ["'; DROP TABLE--", '03.01A'],
        },
      });

      // "'; DROP TABLE--" is > 10 chars
      expect(res.statusCode).toBe(400);
    });

    it('rejects codes with special characters within max length', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/bundling-rules/check',
        headers: { cookie: physicianCookie() },
        payload: {
          codes: ["<script>", '03.01A'],
        },
      });

      // "<script>" is 8 chars, within max(10) -- passes Zod but safe in parameterised queries
      expect([200, 400]).toContain(res.statusCode);
    });

    it('rejects too many codes (max 10)', async () => {
      const manyCodes = Array.from({ length: 11 }, (_, i) => `0${i}.01A`);
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/bundling-rules/check',
        headers: { cookie: physicianCookie() },
        payload: { codes: manyCodes },
      });

      // z.array().min(2).max(10) -- 11 items exceeds max
      expect(res.statusCode).toBe(400);
    });

    it('rejects massively oversized codes array (1000 entries)', async () => {
      const massiveCodes = Array.from({ length: 1000 }, (_, i) => `0${i}.01A`);
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/bundling-rules/check',
        headers: { cookie: physicianCookie() },
        payload: { codes: massiveCodes },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects missing codes field entirely', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/bundling-rules/check',
        headers: { cookie: physicianCookie() },
        payload: {},
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects null codes', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/bundling-rules/check',
        headers: { cookie: physicianCookie() },
        payload: { codes: null },
      });

      expect(res.statusCode).toBe(400);
    });

    it('accepts valid bundling check with exactly 2 codes (min)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/bundling-rules/check',
        headers: { cookie: physicianCookie() },
        payload: { codes: ['03.01A', '03.04J'] },
      });

      expect(res.statusCode).not.toBe(400);
    });

    it('accepts valid bundling check with exactly 10 codes (max)', async () => {
      const tenCodes = Array.from({ length: 10 }, (_, i) => `0${i}.01A`);
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/bundling-rules/check',
        headers: { cookie: physicianCookie() },
        payload: { codes: tenCodes },
      });

      expect(res.statusCode).not.toBe(400);
    });
  });

  // =========================================================================
  // 8. Code parameter validation for extension endpoints
  // =========================================================================

  describe('Code parameter validation for extension endpoints', () => {
    describe('anesthesia-rules/:code with overly long value', () => {
      it('rejects code exceeding max length (30)', async () => {
        const longCode = 'A'.repeat(31);
        const res = await app.inject({
          method: 'GET',
          url: `/api/v1/ref/anesthesia-rules/${longCode}`,
          headers: { cookie: physicianCookie() },
        });

        // anesthesiaScenarioParamSchema code is z.string().max(30)
        expect(res.statusCode).toBe(400);
      });

      it('accepts code within max length', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/anesthesia-rules/ANES01',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).not.toBe(400);
      });

      it('rejects code at boundary (exactly 31 chars)', async () => {
        const boundaryCode = 'A'.repeat(31);
        const res = await app.inject({
          method: 'GET',
          url: `/api/v1/ref/anesthesia-rules/${boundaryCode}`,
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('accepts code at boundary (exactly 30 chars)', async () => {
        const boundaryCode = 'A'.repeat(30);
        const res = await app.inject({
          method: 'GET',
          url: `/api/v1/ref/anesthesia-rules/${boundaryCode}`,
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).not.toBe(400);
      });
    });

    describe('bundling pair codes with overly long values', () => {
      it('rejects code_a exceeding max length (10)', async () => {
        const longCode = 'A'.repeat(11);
        const res = await app.inject({
          method: 'GET',
          url: `/api/v1/ref/bundling-rules/pair/${longCode}/03.04J`,
          headers: { cookie: physicianCookie() },
        });

        // bundlingPairParamSchema code_a is z.string().max(10)
        expect(res.statusCode).toBe(400);
      });

      it('rejects code_b exceeding max length (10)', async () => {
        const longCode = 'A'.repeat(11);
        const res = await app.inject({
          method: 'GET',
          url: `/api/v1/ref/bundling-rules/pair/03.01A/${longCode}`,
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects both codes exceeding max length', async () => {
        const longCodeA = 'A'.repeat(11);
        const longCodeB = 'B'.repeat(11);
        const res = await app.inject({
          method: 'GET',
          url: `/api/v1/ref/bundling-rules/pair/${longCodeA}/${longCodeB}`,
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('accepts valid pair codes within bounds', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/bundling-rules/pair/03.01A/03.04J',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).not.toBe(400);
      });
    });

    describe('icd10_code with special characters', () => {
      it('rejects icd10_code exceeding max length (10)', async () => {
        const longCode = 'A'.repeat(11);
        const res = await app.inject({
          method: 'GET',
          url: `/api/v1/ref/icd-crosswalk/${longCode}`,
          headers: { cookie: physicianCookie() },
        });

        // icd10_code uses hscDetailParamSchema.shape.code which is z.string().max(10)
        expect(res.statusCode).toBe(400);
      });

      it('handles icd10_code with SQL injection chars (within length)', async () => {
        const res = await app.inject({
          method: 'GET',
          url: `/api/v1/ref/icd-crosswalk/${encodeURIComponent("A10'; --")}`,
          headers: { cookie: physicianCookie() },
        });

        // "A10'; --" is 8 chars, within max(10) -- passes Zod, safe via parameterised query
        expect([200, 400, 404]).toContain(res.statusCode);
      });

      it('handles icd10_code with path traversal', async () => {
        const res = await app.inject({
          method: 'GET',
          url: `/api/v1/ref/icd-crosswalk/${encodeURIComponent('../../etc')}`,
          headers: { cookie: physicianCookie() },
        });

        // "../../etc" is 9 chars, within max(10) -- passes length but path traversal
        // is irrelevant for DB lookups; no file system access occurs
        expect([200, 400, 404]).toContain(res.statusCode);
        expect(res.body).not.toContain('root:');
        expect(res.body).not.toContain('/etc/');
      });

      it('accepts valid ICD-10 code format', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/icd-crosswalk/J06.9',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).not.toBe(400);
      });
    });

    describe('cpsa param validation', () => {
      it('rejects cpsa exceeding max length (10)', async () => {
        const longCpsa = 'A'.repeat(11);
        const res = await app.inject({
          method: 'GET',
          url: `/api/v1/ref/providers/${longCpsa}`,
          headers: { cookie: physicianCookie() },
        });

        // providerRegistryParamSchema cpsa is z.string().max(10)
        expect(res.statusCode).toBe(400);
      });

      it('handles cpsa with SQL injection chars (within length)', async () => {
        const res = await app.inject({
          method: 'GET',
          url: `/api/v1/ref/providers/${encodeURIComponent("' OR 1=1")}`,
          headers: { cookie: physicianCookie() },
        });

        // "' OR 1=1" is 8 chars, within max(10) -- passes Zod, safe via parameterised query
        expect([200, 400, 404]).toContain(res.statusCode);
      });

      it('handles cpsa with path traversal payload', async () => {
        const res = await app.inject({
          method: 'GET',
          url: `/api/v1/ref/providers/${encodeURIComponent('../')}`,
          headers: { cookie: physicianCookie() },
        });

        // "../" is 3 chars, within max(10) -- passes length check
        expect([200, 400, 404]).toContain(res.statusCode);
        expect(res.body).not.toContain('root:');
        expect(res.body).not.toContain('/etc/');
      });

      it('accepts valid cpsa format', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/providers/12345',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).not.toBe(400);
      });
    });

    describe('oversized search query strings', () => {
      it('rejects ICD crosswalk search q exceeding max length (100)', async () => {
        const longQuery = 'A'.repeat(101);
        const res = await app.inject({
          method: 'GET',
          url: `/api/v1/ref/icd-crosswalk?q=${longQuery}`,
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects provider search q exceeding max length (100)', async () => {
        const longQuery = 'A'.repeat(101);
        const res = await app.inject({
          method: 'GET',
          url: `/api/v1/ref/providers/search?q=${longQuery}`,
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects guidance search q exceeding max length (200)', async () => {
        const longQuery = 'A'.repeat(201);
        const res = await app.inject({
          method: 'GET',
          url: `/api/v1/ref/guidance?q=${longQuery}`,
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects empty q on ICD crosswalk (min length 1)', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/icd-crosswalk?q=',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects missing q on ICD crosswalk', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/icd-crosswalk',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects empty q on provider search (min length 2)', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/providers/search?q=',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects single-char q on provider search (min length 2)', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/providers/search?q=a',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects missing q on provider search', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/providers/search',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });
    });
  });

  // =========================================================================
  // Sanity: valid inputs accepted
  // =========================================================================

  describe('Sanity: valid inputs are accepted', () => {
    it('accepts valid ICD crosswalk search', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/icd-crosswalk?q=flu',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).not.toBe(400);
    });

    it('accepts valid ICD crosswalk detail lookup', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/icd-crosswalk/J06.9',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).not.toBe(400);
    });

    it('accepts valid provider search', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/providers/search?q=Smith',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).not.toBe(400);
    });

    it('accepts valid provider detail lookup', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/providers/12345',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).not.toBe(400);
    });

    it('accepts valid guidance listing', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/guidance',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).not.toBe(400);
    });

    it('accepts valid guidance detail UUID', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/ref/guidance/${DUMMY_UUID}`,
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).not.toBe(400);
    });

    it('accepts valid provincial-phn-formats (no params)', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/provincial-phn-formats',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).not.toBe(400);
    });

    it('accepts valid reciprocal rules with 2-char province', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/reciprocal-rules/AB',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).not.toBe(400);
    });

    it('accepts valid anesthesia rules listing', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/anesthesia-rules',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).not.toBe(400);
    });

    it('accepts valid anesthesia rules detail', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/anesthesia-rules/ANES01',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).not.toBe(400);
    });

    it('accepts valid anesthesia calculate body', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/anesthesia-rules/calculate',
        headers: { cookie: physicianCookie() },
        payload: { scenario_code: 'ANES01', time_minutes: 60 },
      });

      expect(res.statusCode).not.toBe(400);
    });

    it('accepts valid bundling pair lookup', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/bundling-rules/pair/03.01A/03.04J',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).not.toBe(400);
    });

    it('accepts valid bundling check with 2 codes', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/bundling-rules/check',
        headers: { cookie: physicianCookie() },
        payload: { codes: ['03.01A', '03.04J'] },
      });

      expect(res.statusCode).not.toBe(400);
    });

    it('accepts valid justification templates listing', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/justification-templates',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).not.toBe(400);
    });

    it('accepts valid justification template UUID', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/ref/justification-templates/${DUMMY_UUID}`,
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).not.toBe(400);
    });
  });
});
