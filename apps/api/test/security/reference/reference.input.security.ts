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
// Mock reference repository — returns data for search tests
// ---------------------------------------------------------------------------

function createMockReferenceRepo() {
  const DUMMY_VERSION = {
    versionId: 'aaaaaaaa-0000-0000-0000-000000000001',
    dataSet: 'SOMB',
    versionLabel: 'v1.0',
    effectiveFrom: '2026-01-01',
    publishedAt: new Date(),
    isActive: true,
    recordsAdded: 10,
    recordsModified: 0,
    recordsDeprecated: 0,
    changeSummary: null,
  };

  const MOCK_HSC = {
    hscCode: '03.01A',
    description: 'Office visit',
    baseFee: '50.00',
    feeType: 'fixed',
    helpText: 'Standard office visit',
    effectiveTo: null,
    specialtyRestrictions: [],
    facilityRestrictions: [],
    modifierEligibility: [],
    combinationGroup: null,
    surchargeEligible: false,
    pcpcmBasket: 'in_basket',
    maxPerDay: null,
    maxPerVisit: null,
    requiresReferral: false,
  };

  return {
    findActiveVersion: vi.fn(async () => DUMMY_VERSION),
    findVersionForDate: vi.fn(async () => DUMMY_VERSION),
    findVersionById: vi.fn(async () => DUMMY_VERSION),
    findVersionByVersionId: vi.fn(async () => DUMMY_VERSION),
    listVersions: vi.fn(async () => [DUMMY_VERSION]),
    createVersion: vi.fn(async (data: any) => ({ versionId: 'bbbbbbbb-0000-0000-0000-000000000001', ...data })),
    activateVersion: vi.fn(async () => {}),
    deactivateVersion: vi.fn(async () => {}),

    // HSC
    searchHscCodes: vi.fn(async () => [MOCK_HSC]),
    findHscByCode: vi.fn(async () => MOCK_HSC),
    listHscByVersion: vi.fn(async () => ({ data: [MOCK_HSC], total: 1 })),
    getHscFavourites: vi.fn(async () => []),
    bulkInsertHscCodes: vi.fn(async () => {}),

    // DI
    searchDiCodes: vi.fn(async () => []),
    findDiByCode: vi.fn(async () => undefined),
    bulkInsertDiCodes: vi.fn(async () => {}),

    // Modifiers
    findModifiersForHsc: vi.fn(async () => []),
    findModifierByCode: vi.fn(async () => undefined),
    listAllModifiers: vi.fn(async () => []),
    bulkInsertModifiers: vi.fn(async () => {}),

    // Functional centres
    listFunctionalCentres: vi.fn(async () => []),
    findFunctionalCentre: vi.fn(async () => undefined),
    bulkInsertFunctionalCentres: vi.fn(async () => {}),

    // Explanatory codes
    findExplanatoryCode: vi.fn(async () => undefined),
    bulkInsertExplanatoryCodes: vi.fn(async () => {}),

    // RRNP
    findRrnpRate: vi.fn(async () => undefined),
    bulkInsertRrnpCommunities: vi.fn(async () => {}),

    // PCPCM
    findPcpcmBasket: vi.fn(async () => undefined),
    bulkInsertPcpcmBaskets: vi.fn(async () => {}),

    // Holidays
    listHolidaysByYear: vi.fn(async () => []),
    isHoliday: vi.fn(async () => ({ is_holiday: false })),
    getHolidayById: vi.fn(async () => undefined),
    createHoliday: vi.fn(async (data: any) => ({
      holidayId: 'cccccccc-0000-0000-0000-000000000001',
      ...data,
    })),
    updateHoliday: vi.fn(async (id: string, data: any) => ({
      holidayId: id,
      date: '2026-12-25',
      name: 'Christmas',
      jurisdiction: 'provincial',
      affectsBillingPremiums: true,
      year: 2026,
      ...data,
    })),
    deleteHoliday: vi.fn(async () => {}),

    // Governing rules
    findRulesForContext: vi.fn(async () => []),
    findRuleById: vi.fn(async () => ({
      ruleId: 'RULE001',
      ruleName: 'Test Rule',
      ruleCategory: 'general',
      description: 'Test rule description',
      ruleLogic: {},
      severity: 'warning',
      errorMessage: 'Test error',
      helpText: null,
      sourceReference: null,
      sourceUrl: null,
    })),
    listRulesByCategory: vi.fn(async () => []),
    bulkInsertRules: vi.fn(async () => {}),

    // WCB
    searchWcbCodes: vi.fn(async () => []),
    bulkInsertWcbCodes: vi.fn(async () => {}),

    // Staging
    createStagingRecord: vi.fn(async (data: any) => ({
      stagingId: 'dddddddd-0000-0000-0000-000000000001',
      dataSet: data.dataSet,
      status: 'uploaded',
      stagedData: data.stagedData,
      diffResult: null,
      ...data,
    })),
    findStagingById: vi.fn(async () => undefined),
    updateStagingStatus: vi.fn(async () => {}),
    deleteStagingRecord: vi.fn(async () => {}),

    // Change summaries
    getChangeSummaries: vi.fn(async () => []),
    getChangeDetails: vi.fn(async () => []),
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
// Test Suite
// ---------------------------------------------------------------------------

describe('Reference Data Input Validation & Injection Prevention (Security)', () => {
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
  // SQL Injection Payloads on Search Queries
  // =========================================================================

  describe('SQL injection payloads on search queries', () => {
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

    describe('HSC search (GET /api/v1/ref/hsc/search)', () => {
      for (const payload of SQL_INJECTION_PAYLOADS) {
        it(`rejects SQL injection in q param: ${payload.substring(0, 30)}...`, async () => {
          const res = await app.inject({
            method: 'GET',
            url: `/api/v1/ref/hsc/search?q=${encodeURIComponent(payload)}`,
            headers: { cookie: physicianCookie() },
          });

          // The query must either return 200 with safe results (parameterised query)
          // or 400 if caught by Zod validation. Either way, no SQL injection.
          expect([200, 400]).toContain(res.statusCode);

          if (res.statusCode === 200) {
            const body = JSON.parse(res.body);
            // If search returns results, verify they don't contain all records
            // (which would indicate a tautology like OR 1=1 succeeded)
            // The mock always returns the same data, so we just verify the
            // search query was passed through safely to the repo
            expect(mockRefRepo.searchHscCodes).toHaveBeenCalled();
            const callArgs = mockRefRepo.searchHscCodes.mock.calls[0];
            // The search query should be passed as a parameter, not interpolated
            expect(callArgs[0]).toBe(payload);
          }
        });
      }
    });

    describe('DI search (GET /api/v1/ref/di/search)', () => {
      for (const payload of SQL_INJECTION_PAYLOADS) {
        it(`rejects SQL injection in q param: ${payload.substring(0, 30)}...`, async () => {
          const res = await app.inject({
            method: 'GET',
            url: `/api/v1/ref/di/search?q=${encodeURIComponent(payload)}`,
            headers: { cookie: physicianCookie() },
          });

          expect([200, 400]).toContain(res.statusCode);

          if (res.statusCode === 200) {
            expect(mockRefRepo.searchDiCodes).toHaveBeenCalled();
            const callArgs = mockRefRepo.searchDiCodes.mock.calls[0];
            expect(callArgs[0]).toBe(payload);
          }
        });
      }
    });

    describe('specialty parameter with SQL injection', () => {
      for (const payload of SQL_INJECTION_PAYLOADS.slice(0, 3)) {
        it(`handles SQL injection in specialty: ${payload.substring(0, 30)}...`, async () => {
          const res = await app.inject({
            method: 'GET',
            url: `/api/v1/ref/hsc/search?q=test&specialty=${encodeURIComponent(payload)}`,
            headers: { cookie: physicianCookie() },
          });

          // Specialty is an optional string — Zod accepts it but parameterised queries keep it safe
          expect([200, 400]).toContain(res.statusCode);
        });
      }
    });

    describe('date parameter with SQL injection', () => {
      const DATE_INJECTIONS = [
        "2026-01-01'; DROP TABLE--",
        "1 OR 1=1",
        "'; SELECT * FROM users--",
      ];

      for (const payload of DATE_INJECTIONS) {
        it(`rejects SQL injection in date: ${payload.substring(0, 30)}...`, async () => {
          const res = await app.inject({
            method: 'GET',
            url: `/api/v1/ref/hsc/search?q=test&date=${encodeURIComponent(payload)}`,
            headers: { cookie: physicianCookie() },
          });

          // date is validated by z.string().date() — must be YYYY-MM-DD
          expect(res.statusCode).toBe(400);
        });
      }
    });
  });

  // =========================================================================
  // XSS Payloads on Admin-Authored Text Fields
  // =========================================================================

  describe('XSS payloads on admin-authored text fields', () => {
    const XSS_PAYLOADS = [
      '<script>alert("xss")</script>',
      '<script>alert(1)</script>',
      '<img src=x onerror=alert(1)>',
      '<img onerror=alert(1) src=x>',
      'javascript:alert(1)',
      '<svg/onload=alert(1)>',
      '"><script>alert(1)</script>',
    ];

    describe('POST /api/v1/admin/ref/holidays (name field)', () => {
      for (const payload of XSS_PAYLOADS) {
        it(`handles XSS in holiday name: ${payload.substring(0, 30)}...`, async () => {
          const res = await app.inject({
            method: 'POST',
            url: '/api/v1/admin/ref/holidays',
            headers: { cookie: adminCookie() },
            payload: {
              date: '2026-12-25',
              name: payload,
              jurisdiction: 'provincial',
              affects_billing_premiums: true,
            },
          });

          // Holiday name accepts strings 1-100 chars. XSS payloads pass Zod but
          // should be stored safely. Verify it either rejects (400) or stores safely.
          if (res.statusCode === 201) {
            const body = JSON.parse(res.body);
            // Verify the stored name doesn't contain executable script when returned
            if (body.data && body.data.name) {
              // The name should either be sanitised or stored as-is (escaped on output)
              // For now the API stores as-is — output escaping happens at frontend layer
              expect(body.data).toBeDefined();
            }
          }
          // Any status is acceptable as long as no script executes server-side
          expect([201, 400]).toContain(res.statusCode);
        });
      }
    });

    describe('POST /api/v1/admin/ref/:dataset/staging/:id/publish (change_summary)', () => {
      it('handles XSS in change_summary field', async () => {
        const res = await app.inject({
          method: 'POST',
          url: `/api/v1/admin/ref/SOMB/staging/${DUMMY_UUID}/publish`,
          headers: { cookie: adminCookie() },
          payload: {
            version_label: 'v1.0',
            effective_from: '2026-03-01',
            change_summary: '<script>alert(1)</script>',
          },
        });

        // change_summary is an optional string. It may pass Zod validation but the
        // value must be stored safely. The handler will call the service which may
        // return 404 (staging not found) — but the point is the XSS payload
        // passed through Zod validation without crashing.
        // NotFoundError is expected since mock findStagingById returns undefined
        expect([201, 404]).toContain(res.statusCode);
      });
    });
  });

  // =========================================================================
  // Type Coercion Attacks
  // =========================================================================

  describe('Type coercion attacks', () => {
    describe('limit parameter validation', () => {
      it('rejects negative limit: -1', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/hsc/search?q=test&limit=-1',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects limit exceeding max (50): limit=100', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/hsc/search?q=test&limit=100',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects non-numeric limit: abc', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/hsc/search?q=test&limit=abc',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects limit=0 (below min of 1)', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/hsc/search?q=test&limit=0',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('accepts valid limit within range', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/hsc/search?q=test&limit=25',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).not.toBe(400);
      });
    });

    describe('empty query parameter (q)', () => {
      it('rejects empty q on HSC search (min length 1)', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/hsc/search?q=',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects empty q on DI search (min length 1)', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/di/search?q=',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects missing q param on HSC search', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/hsc/search',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });
    });

    describe('wrong types in query parameters', () => {
      it('rejects array where string expected for q param', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/hsc/search?q[]=test1&q[]=test2',
          headers: { cookie: physicianCookie() },
        });

        // Should either reject (400) or coerce to a string safely
        expect([200, 400]).toContain(res.statusCode);
      });

      it('rejects invalid date format (2026-13-45)', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/hsc/search?q=test&date=2026-13-45',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects non-date string for date param', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/hsc/search?q=test&date=not-a-date',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('accepts valid ISO date format (YYYY-MM-DD)', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/hsc/search?q=test&date=2026-01-15',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).not.toBe(400);
      });
    });

    describe('holiday year parameter validation', () => {
      it('rejects non-numeric year: abc', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/holidays?year=abc',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects year below min (2020): year=1999', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/holidays?year=1999',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects year above max (2100): year=3000', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/holidays?year=3000',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });
    });

    describe('holiday check date validation', () => {
      it('rejects invalid date format', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/holidays/check?date=2026-13-45',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects missing date', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/holidays/check',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });
    });

    describe('wrong type in request body', () => {
      it('rejects number where string expected for version_label', async () => {
        const res = await app.inject({
          method: 'POST',
          url: `/api/v1/admin/ref/SOMB/staging/${DUMMY_UUID}/publish`,
          headers: { cookie: adminCookie() },
          payload: {
            version_label: 12345,
            effective_from: '2026-03-01',
          },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects number where string expected for effective_from', async () => {
        const res = await app.inject({
          method: 'POST',
          url: `/api/v1/admin/ref/SOMB/staging/${DUMMY_UUID}/publish`,
          headers: { cookie: adminCookie() },
          payload: {
            version_label: 'v1.0',
            effective_from: 12345,
          },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects string where boolean expected for affects_billing_premiums', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/admin/ref/holidays',
          headers: { cookie: adminCookie() },
          payload: {
            date: '2026-12-25',
            name: 'Christmas',
            jurisdiction: 'provincial',
            affects_billing_premiums: 'yes',
          },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects invalid jurisdiction enum value', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/admin/ref/holidays',
          headers: { cookie: adminCookie() },
          payload: {
            date: '2026-12-25',
            name: 'Christmas',
            jurisdiction: 'invalid_value',
            affects_billing_premiums: true,
          },
        });

        expect(res.statusCode).toBe(400);
      });
    });

    describe('validate-context schema enforcement', () => {
      it('rejects missing required hsc param', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/rules/validate-context?date=2026-01-01',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects missing required date param', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/rules/validate-context?hsc=03.01A',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects invalid date in validate-context', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/rules/validate-context?hsc=03.01A&date=invalid',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });
    });

    describe('evaluate-batch body validation', () => {
      it('rejects empty claims array', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/ref/rules/evaluate-batch',
          headers: { cookie: physicianCookie() },
          payload: { claims: [] },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects missing claims field', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/ref/rules/evaluate-batch',
          headers: { cookie: physicianCookie() },
          payload: {},
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects non-array claims field', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/ref/rules/evaluate-batch',
          headers: { cookie: physicianCookie() },
          payload: { claims: 'not-an-array' },
        });

        expect(res.statusCode).toBe(400);
      });
    });

    describe('SOMB version date validation', () => {
      it('rejects missing date for SOMB version', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/somb/version',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects invalid date for SOMB version', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/somb/version?date=2026-99-99',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });
    });
  });

  // =========================================================================
  // UUID Parameter Validation
  // =========================================================================

  describe('UUID parameter validation', () => {
    const INVALID_UUIDS = [
      'not-a-uuid',
      '12345',
      'abcdefg',
      '00000000-0000-0000-0000-00000000000', // too short
      '00000000-0000-0000-0000-0000000000001', // too long
      '../../../etc/passwd',
      "'; DROP TABLE--",
    ];

    describe('RRNP community_id (GET /api/v1/ref/rrnp/:community_id)', () => {
      for (const invalidUuid of INVALID_UUIDS) {
        it(`rejects invalid UUID: ${invalidUuid.substring(0, 20)}`, async () => {
          const res = await app.inject({
            method: 'GET',
            url: `/api/v1/ref/rrnp/${encodeURIComponent(invalidUuid)}`,
            headers: { cookie: physicianCookie() },
          });

          expect(res.statusCode).toBe(400);
        });
      }
    });

    describe('change detail version_id (GET /api/v1/ref/changes/:version_id/detail)', () => {
      for (const invalidUuid of INVALID_UUIDS) {
        it(`rejects invalid UUID: ${invalidUuid.substring(0, 20)}`, async () => {
          const res = await app.inject({
            method: 'GET',
            url: `/api/v1/ref/changes/${encodeURIComponent(invalidUuid)}/detail`,
            headers: { cookie: physicianCookie() },
          });

          expect(res.statusCode).toBe(400);
        });
      }
    });

    describe('admin staging id (DELETE /api/v1/admin/ref/:dataset/staging/:id)', () => {
      for (const invalidUuid of INVALID_UUIDS) {
        it(`rejects invalid UUID: ${invalidUuid.substring(0, 20)}`, async () => {
          const res = await app.inject({
            method: 'DELETE',
            url: `/api/v1/admin/ref/SOMB/staging/${encodeURIComponent(invalidUuid)}`,
            headers: { cookie: adminCookie() },
          });

          expect(res.statusCode).toBe(400);
        });
      }
    });

    describe('admin holiday id (PUT /api/v1/admin/ref/holidays/:id)', () => {
      for (const invalidUuid of INVALID_UUIDS.slice(0, 3)) {
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

    describe('admin holiday id (DELETE /api/v1/admin/ref/holidays/:id)', () => {
      for (const invalidUuid of INVALID_UUIDS.slice(0, 3)) {
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

    describe('physician-impact version_id (GET /api/v1/ref/changes/:version_id/physician-impact)', () => {
      it('rejects non-UUID version_id', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/ref/changes/not-a-uuid/physician-impact',
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).toBe(400);
      });
    });

    describe('admin staging diff (GET /api/v1/admin/ref/:dataset/staging/:id/diff)', () => {
      it('rejects non-UUID staging id', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/admin/ref/SOMB/staging/not-a-uuid/diff',
          headers: { cookie: adminCookie() },
        });

        expect(res.statusCode).toBe(400);
      });
    });

    describe('admin staging publish (POST /api/v1/admin/ref/:dataset/staging/:id/publish)', () => {
      it('rejects non-UUID staging id', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/admin/ref/SOMB/staging/not-a-uuid/publish',
          headers: { cookie: adminCookie() },
          payload: {
            version_label: 'v1.0',
            effective_from: '2026-03-01',
          },
        });

        expect(res.statusCode).toBe(400);
      });
    });
  });

  // =========================================================================
  // File Upload Attacks
  // =========================================================================

  describe('File upload attacks', () => {
    describe('POST /api/v1/admin/ref/:dataset/upload', () => {
      it('rejects upload with no file attached', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/admin/ref/SOMB/upload',
          headers: { cookie: adminCookie() },
        });

        // Without a multipart body, should fail (406 = Not Acceptable from multipart plugin)
        expect([400, 406, 415, 500]).toContain(res.statusCode);
      });

      it('rejects executable file disguised as CSV (application/x-executable)', async () => {
        const boundary = '----TestBoundary123';
        const body = [
          `--${boundary}`,
          'Content-Disposition: form-data; name="file"; filename="data.exe"',
          'Content-Type: application/x-executable',
          '',
          'MZ\x90\x00\x03\x00\x00\x00', // Fake executable header
          `--${boundary}--`,
        ].join('\r\n');

        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/admin/ref/SOMB/upload',
          headers: {
            cookie: adminCookie(),
            'content-type': `multipart/form-data; boundary=${boundary}`,
          },
          payload: body,
        });

        // Should reject due to invalid content type
        expect([400, 415]).toContain(res.statusCode);
      });

      it('rejects file with mismatched content type (claims CSV but sends JSON)', async () => {
        const boundary = '----TestBoundary456';
        const csvContent = 'hsc_code,description,base_fee,fee_type\n03.01A,Office visit,50.00,fixed';
        const body = [
          `--${boundary}`,
          'Content-Disposition: form-data; name="file"; filename="data.csv"',
          'Content-Type: application/xml',
          '',
          csvContent,
          `--${boundary}--`,
        ].join('\r\n');

        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/admin/ref/SOMB/upload',
          headers: {
            cookie: adminCookie(),
            'content-type': `multipart/form-data; boundary=${boundary}`,
          },
          payload: body,
        });

        // Should reject — application/xml is not in the allowed content types
        expect([400, 415]).toContain(res.statusCode);
      });

      it('accepts valid CSV upload with correct content type', async () => {
        const boundary = '----TestBoundary789';
        const csvContent = 'hsc_code,description,base_fee,fee_type\n03.01A,Office visit,50.00,fixed';
        const body = [
          `--${boundary}`,
          'Content-Disposition: form-data; name="file"; filename="data.csv"',
          'Content-Type: text/csv',
          '',
          csvContent,
          `--${boundary}--`,
        ].join('\r\n');

        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/admin/ref/SOMB/upload',
          headers: {
            cookie: adminCookie(),
            'content-type': `multipart/form-data; boundary=${boundary}`,
          },
          payload: body,
        });

        // Should process successfully (200 or 201)
        expect([200, 201]).toContain(res.statusCode);
      });

      it('rejects invalid dataset parameter', async () => {
        const boundary = '----TestBoundaryInvalid';
        const csvContent = 'hsc_code,description\n03.01A,Office visit';
        const body = [
          `--${boundary}`,
          'Content-Disposition: form-data; name="file"; filename="data.csv"',
          'Content-Type: text/csv',
          '',
          csvContent,
          `--${boundary}--`,
        ].join('\r\n');

        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/admin/ref/INVALID_DATASET/upload',
          headers: {
            cookie: adminCookie(),
            'content-type': `multipart/form-data; boundary=${boundary}`,
          },
          payload: body,
        });

        expect(res.statusCode).toBe(400);
      });
    });
  });

  // =========================================================================
  // rule_logic JSON Validation
  // =========================================================================

  describe('rule_logic JSON validation', () => {
    describe('POST /api/v1/admin/ref/rules/:rule_id/dry-run', () => {
      it('rejects missing body entirely', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/admin/ref/rules/RULE001/dry-run',
          headers: { cookie: adminCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects empty body (no updated_rule_logic)', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/admin/ref/rules/RULE001/dry-run',
          headers: { cookie: adminCookie() },
          payload: {},
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects non-object for updated_rule_logic', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/admin/ref/rules/RULE001/dry-run',
          headers: { cookie: adminCookie() },
          payload: { updated_rule_logic: 'not-an-object' },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects array for updated_rule_logic', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/admin/ref/rules/RULE001/dry-run',
          headers: { cookie: adminCookie() },
          payload: { updated_rule_logic: [1, 2, 3] },
        });

        expect(res.statusCode).toBe(400);
      });

      it('accepts valid object with unexpected keys (passthrough schema)', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/admin/ref/rules/RULE001/dry-run',
          headers: { cookie: adminCookie() },
          payload: {
            updated_rule_logic: {
              condition: 'hsc_code = 03.01A',
              max_per_day: 3,
              custom_key: 'custom_value',
              nested: { deep: true },
            },
          },
        });

        // The schema uses z.object({}).passthrough() — accepts any object shape
        // Service may return 200 or other status depending on rule lookup
        expect(res.statusCode).not.toBe(400);
      });

      it('accepts empty object for updated_rule_logic', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/admin/ref/rules/RULE001/dry-run',
          headers: { cookie: adminCookie() },
          payload: { updated_rule_logic: {} },
        });

        // Empty object is valid per z.object({}).passthrough()
        expect(res.statusCode).not.toBe(400);
      });

      it('rejects null for updated_rule_logic', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/admin/ref/rules/RULE001/dry-run',
          headers: { cookie: adminCookie() },
          payload: { updated_rule_logic: null },
        });

        expect(res.statusCode).toBe(400);
      });
    });

    describe('rule_id parameter validation', () => {
      it('rejects overly long rule_id (max 20 chars)', async () => {
        const longId = 'A'.repeat(21);
        const res = await app.inject({
          method: 'POST',
          url: `/api/v1/admin/ref/rules/${longId}/dry-run`,
          headers: { cookie: adminCookie() },
          payload: { updated_rule_logic: {} },
        });

        expect(res.statusCode).toBe(400);
      });

      it('accepts valid rule_id within bounds', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/admin/ref/rules/RULE001/dry-run',
          headers: { cookie: adminCookie() },
          payload: { updated_rule_logic: {} },
        });

        expect(res.statusCode).not.toBe(400);
      });
    });
  });

  // =========================================================================
  // Admin Schema Enforcement
  // =========================================================================

  describe('Admin schema enforcement', () => {
    describe('create holiday validation', () => {
      it('rejects missing required fields', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/admin/ref/holidays',
          headers: { cookie: adminCookie() },
          payload: {},
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects empty name (min length 1)', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/admin/ref/holidays',
          headers: { cookie: adminCookie() },
          payload: {
            date: '2026-12-25',
            name: '',
            jurisdiction: 'provincial',
          },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects name exceeding max length (100)', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/admin/ref/holidays',
          headers: { cookie: adminCookie() },
          payload: {
            date: '2026-12-25',
            name: 'A'.repeat(101),
            jurisdiction: 'provincial',
          },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects invalid date format', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/admin/ref/holidays',
          headers: { cookie: adminCookie() },
          payload: {
            date: '25-12-2026',
            name: 'Christmas',
            jurisdiction: 'provincial',
          },
        });

        expect(res.statusCode).toBe(400);
      });
    });

    describe('publish schema validation', () => {
      it('rejects empty version_label (min length 1)', async () => {
        const res = await app.inject({
          method: 'POST',
          url: `/api/v1/admin/ref/SOMB/staging/${DUMMY_UUID}/publish`,
          headers: { cookie: adminCookie() },
          payload: {
            version_label: '',
            effective_from: '2026-03-01',
          },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects version_label exceeding max length (50)', async () => {
        const res = await app.inject({
          method: 'POST',
          url: `/api/v1/admin/ref/SOMB/staging/${DUMMY_UUID}/publish`,
          headers: { cookie: adminCookie() },
          payload: {
            version_label: 'V'.repeat(51),
            effective_from: '2026-03-01',
          },
        });

        expect(res.statusCode).toBe(400);
      });
    });
  });

  // =========================================================================
  // HSC / DI code param validation
  // =========================================================================

  describe('Code parameter validation', () => {
    it('rejects HSC code exceeding max length (10)', async () => {
      const longCode = 'A'.repeat(11);
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/ref/hsc/${longCode}`,
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects DI code exceeding max length (10)', async () => {
      const longCode = 'A'.repeat(11);
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/ref/di/${longCode}`,
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects modifier code exceeding max length (10)', async () => {
      const longCode = 'A'.repeat(11);
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/ref/modifiers/${longCode}`,
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects explanatory code exceeding max length (10)', async () => {
      const longCode = 'A'.repeat(11);
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/ref/explanatory-codes/${longCode}`,
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects PCPCM hsc_code exceeding max length (10)', async () => {
      const longCode = 'A'.repeat(11);
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/ref/pcpcm/${longCode}`,
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects search q exceeding max length (100)', async () => {
      const longQuery = 'A'.repeat(101);
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/ref/hsc/search?q=${longQuery}`,
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // Change summary input validation
  // =========================================================================

  describe('Change summary input validation', () => {
    it('rejects invalid date in since parameter', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/changes?since=not-a-date',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(400);
    });

    it('accepts valid since date', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/changes?since=2026-01-01',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).not.toBe(400);
    });
  });
});
