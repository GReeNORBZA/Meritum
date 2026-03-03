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
// Fixed test identities
// ---------------------------------------------------------------------------

const ADMIN_SESSION_TOKEN = randomBytes(32).toString('hex');
const ADMIN_SESSION_TOKEN_HASH = hashToken(ADMIN_SESSION_TOKEN);
const ADMIN_USER_ID = 'aaaa0001-0000-0000-0000-000000000001';
const ADMIN_SESSION_ID = 'aaaa0001-0000-0000-0000-000000000011';

const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_USER_ID = 'aaaa0002-0000-0000-0000-000000000001';
const PHYSICIAN_SESSION_ID = 'aaaa0002-0000-0000-0000-000000000011';

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

// Shared audit store: all audit entries written by the reference service
let auditEntries: Array<{ action: string; adminId: string; details: Record<string, unknown> }> = [];

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
  };
}

function createMockEvents() {
  return { emit: vi.fn() };
}

// ---------------------------------------------------------------------------
// Shared audit logger -- captures all service-level audit entries
// ---------------------------------------------------------------------------

function createSharedAuditLogger() {
  return {
    log: vi.fn(async (entry: { action: string; adminId: string; details: Record<string, unknown> }) => {
      auditEntries.push(entry);
    }),
  };
}

// ---------------------------------------------------------------------------
// Mock data stores for reference data
// ---------------------------------------------------------------------------

const STAGING_ID = 'bbbb0001-0000-0000-0000-000000000001';
const VERSION_ID = 'cccc0001-0000-0000-0000-000000000001';
const PREV_VERSION_ID = 'cccc0001-0000-0000-0000-000000000002';
const HOLIDAY_ID = 'dddd0001-0000-0000-0000-000000000001';
const RULE_ID = 'RULE001';
const RULES_VERSION_ID = 'cccc0001-0000-0000-0000-000000000003';
const ICD_CROSSWALK_VERSION_ID = 'cccc0001-0000-0000-0000-000000000004';
const GUIDANCE_ID = 'eeee0001-0000-0000-0000-000000000001';
const TEMPLATE_ID = 'ffff0001-0000-0000-0000-000000000001';

let stagingRecords: Array<Record<string, unknown>> = [];
let versions: Array<Record<string, unknown>> = [];
let holidays: Array<Record<string, unknown>> = [];

function seedStagingRecord() {
  stagingRecords = [{
    stagingId: STAGING_ID,
    dataSet: 'SOMB',
    uploadedBy: ADMIN_USER_ID,
    fileHash: 'abc123def456',
    recordCount: 5,
    stagedData: [
      { hsc_code: '03.01A', description: 'Office Visit', base_fee: '35.00', fee_type: 'fixed' },
      { hsc_code: '03.01B', description: 'Follow-up Visit', base_fee: '25.00', fee_type: 'fixed' },
    ],
    status: 'diff_generated',
    diffResult: {
      added: [{ hsc_code: '03.01B', description: 'Follow-up Visit' }],
      modified: [],
      deprecated: [],
      summary_stats: { added: 1, modified: 0, deprecated: 0 },
    },
    validationResult: { valid: true, errors: [] },
  }];
}

function seedVersions() {
  versions = [
    {
      versionId: VERSION_ID,
      dataSet: 'SOMB',
      versionLabel: 'v2026.01',
      effectiveFrom: '2026-01-01',
      publishedAt: new Date(),
      publishedBy: ADMIN_USER_ID,
      isActive: true,
      recordsAdded: 100,
      recordsModified: 5,
      recordsDeprecated: 2,
      changeSummary: 'Initial load',
    },
    {
      versionId: PREV_VERSION_ID,
      dataSet: 'SOMB',
      versionLabel: 'v2025.01',
      effectiveFrom: '2025-01-01',
      publishedAt: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000),
      publishedBy: ADMIN_USER_ID,
      isActive: false,
      recordsAdded: 95,
      recordsModified: 0,
      recordsDeprecated: 0,
      changeSummary: 'Previous version',
    },
    {
      versionId: RULES_VERSION_ID,
      dataSet: 'GOVERNING_RULES',
      versionLabel: 'rules-v1',
      effectiveFrom: '2026-01-01',
      publishedAt: new Date(),
      publishedBy: ADMIN_USER_ID,
      isActive: true,
      recordsAdded: 50,
      recordsModified: 0,
      recordsDeprecated: 0,
      changeSummary: 'Initial rules',
    },
    {
      versionId: ICD_CROSSWALK_VERSION_ID,
      dataSet: 'ICD_CROSSWALK',
      versionLabel: 'icd-v1',
      effectiveFrom: '2026-01-01',
      publishedAt: new Date(),
      publishedBy: ADMIN_USER_ID,
      isActive: true,
      recordsAdded: 200,
      recordsModified: 0,
      recordsDeprecated: 0,
      changeSummary: 'Initial ICD crosswalk',
    },
  ];
}

function seedHolidays() {
  holidays = [{
    holidayId: HOLIDAY_ID,
    date: '2026-12-25',
    name: 'Christmas Day',
    jurisdiction: 'provincial',
    affectsBillingPremiums: true,
    year: 2026,
  }];
}

// ---------------------------------------------------------------------------
// Stub reference repository (includes ALL extension methods)
// ---------------------------------------------------------------------------

function createStubReferenceRepo() {
  return {
    // --- Core repo methods ---
    findActiveVersion: vi.fn(async (dataSet: string) => {
      return versions.find((v) => v.dataSet === dataSet && v.isActive) as any;
    }),
    findVersionForDate: vi.fn(async () => undefined),
    findVersionByDate: vi.fn(async () => undefined),
    findVersionById: vi.fn(async () => undefined),
    listVersions: vi.fn(async (dataSet: string) => {
      return versions.filter((v) => v.dataSet === dataSet);
    }),
    createVersion: vi.fn(async (data: any) => ({
      versionId: 'new-version-' + Date.now(),
      ...data,
    })),
    activateVersion: vi.fn(async () => {}),
    deactivateVersion: vi.fn(async () => {}),
    searchHscCodes: vi.fn(async () => []),
    findHscByCode: vi.fn(async () => undefined),
    getHscByCode: vi.fn(async () => undefined),
    listHscByVersion: vi.fn(async () => ({ data: [], total: 0 })),
    getHscCodesByVersion: vi.fn(async () => []),
    bulkInsertHscCodes: vi.fn(async () => {}),
    searchDiCodes: vi.fn(async () => []),
    findDiByCode: vi.fn(async () => undefined),
    getDiByCode: vi.fn(async () => undefined),
    getDiCodesByVersion: vi.fn(async () => []),
    bulkInsertDiCodes: vi.fn(async () => {}),
    findModifiersForHsc: vi.fn(async () => []),
    findModifierEligibilityForHsc: vi.fn(async () => []),
    findHscCodesForModifierType: vi.fn(async () => []),
    getModifiersForHsc: vi.fn(async () => []),
    findModifierByCode: vi.fn(async () => undefined),
    getModifierByCode: vi.fn(async () => undefined),
    listAllModifiers: vi.fn(async () => []),
    getModifiersByVersion: vi.fn(async () => []),
    bulkInsertModifiers: vi.fn(async () => {}),
    listFunctionalCentres: vi.fn(async () => []),
    getFunctionalCentresByVersion: vi.fn(async () => []),
    bulkInsertFunctionalCentres: vi.fn(async () => {}),
    findFunctionalCentre: vi.fn(async () => undefined),
    findExplanatoryCode: vi.fn(async () => undefined),
    getExplanatoryCode: vi.fn(async () => undefined),
    getExplanatoryCodesByVersion: vi.fn(async () => []),
    bulkInsertExplanatoryCodes: vi.fn(async () => {}),
    findRrnpRate: vi.fn(async () => undefined),
    getRrnpCommunity: vi.fn(async () => undefined),
    listRrnpCommunities: vi.fn(async () => []),
    getRrnpCommunitiesByVersion: vi.fn(async () => []),
    bulkInsertRrnpCommunities: vi.fn(async () => {}),
    findPcpcmBasket: vi.fn(async () => undefined),
    getPcpcmBasket: vi.fn(async () => undefined),
    getPcpcmBasketsByVersion: vi.fn(async () => []),
    bulkInsertPcpcmBaskets: vi.fn(async () => {}),
    listHolidaysByYear: vi.fn(async (year: number) => {
      return holidays.filter((h) => (h as any).year === year);
    }),
    listHolidays: vi.fn(async () => holidays),
    isHoliday: vi.fn(async () => ({ is_holiday: false })),
    getHolidayById: vi.fn(async (id: string) => {
      return holidays.find((h) => (h as any).holidayId === id) as any;
    }),
    createHoliday: vi.fn(async (data: any) => ({
      holidayId: 'new-holiday-' + Date.now(),
      ...data,
    })),
    updateHoliday: vi.fn(async (holidayId: string, data: any) => {
      const existing = holidays.find((h) => (h as any).holidayId === holidayId);
      if (!existing) return null;
      return { ...existing, ...data };
    }),
    deleteHoliday: vi.fn(async () => {}),
    findGoverningRules: vi.fn(async () => []),
    findRulesForContext: vi.fn(async () => []),
    findRuleById: vi.fn(async (ruleId: string) => {
      if (ruleId === RULE_ID) {
        return {
          ruleId: RULE_ID,
          ruleName: 'Test Rule',
          ruleCategory: 'visit_limits',
          description: 'Test rule description',
          ruleLogic: { type: 'max_per_day', limit: 3 },
          severity: 'error',
          errorMessage: 'Exceeds daily limit',
          helpText: null,
          sourceReference: null,
          sourceUrl: null,
        };
      }
      return undefined;
    }),
    getGoverningRuleById: vi.fn(async () => undefined),
    getGoverningRulesByVersion: vi.fn(async () => []),
    listRulesByCategory: vi.fn(async () => []),
    bulkInsertGoverningRules: vi.fn(async () => {}),
    bulkInsertRules: vi.fn(async () => {}),
    createStagingRecord: vi.fn(async (data: any) => ({
      stagingId: 'staging-' + Date.now(),
      ...data,
    })),
    createStagingEntry: vi.fn(async (data: any) => ({
      stagingId: 'staging-' + Date.now(),
      ...data,
    })),
    findStagingById: vi.fn(async (stagingId: string) => {
      return stagingRecords.find((s) => (s as any).stagingId === stagingId) as any;
    }),
    findStagingEntry: vi.fn(async (stagingId: string) => {
      return stagingRecords.find((s) => (s as any).stagingId === stagingId) as any;
    }),
    updateStagingStatus: vi.fn(async () => {}),
    deleteStagingRecord: vi.fn(async () => {}),
    deleteStagingEntry: vi.fn(async () => {}),
    listStagingByDataSet: vi.fn(async () => []),
    getHscFavourites: vi.fn(async () => []),
    findVersionByVersionId: vi.fn(async () => undefined),
    getChangeSummaries: vi.fn(async () => []),
    getChangeDetails: vi.fn(async () => []),

    // --- Extension repo methods: ICD Crosswalk ---
    getIcdCrosswalkByIcd10: vi.fn(async () => [{
      icd10Code: 'J09',
      icd9Code: '487',
      description: 'Influenza due to identified novel influenza A virus',
      mappingType: 'one-to-one',
    }]),
    searchIcdCrosswalk: vi.fn(async () => [{
      icd10Code: 'J09',
      description: 'Influenza',
    }]),
    bulkInsertIcdCrosswalk: vi.fn(async () => {}),

    // --- Extension repo methods: Provider Registry ---
    searchProviderRegistry: vi.fn(async () => [{
      cpsa: '12345',
      name: 'Dr. Smith',
      specialty: 'GP',
      city: 'Calgary',
      status: 'active',
    }]),
    getProviderByCpsa: vi.fn(async (cpsa: string) => {
      if (cpsa === '12345') {
        return {
          cpsa: '12345',
          name: 'Dr. Smith',
          specialty: 'GP',
          city: 'Calgary',
          status: 'active',
        };
      }
      return undefined;
    }),
    bulkUpsertProviderRegistry: vi.fn(async () => {}),

    // --- Extension repo methods: Billing Guidance ---
    listBillingGuidance: vi.fn(async () => [{
      id: GUIDANCE_ID,
      title: 'Guide 1',
      category: 'general',
      content: 'Billing guidance content',
    }]),
    searchBillingGuidance: vi.fn(async () => [{
      id: GUIDANCE_ID,
      title: 'Guide 1',
      category: 'general',
    }]),
    getBillingGuidanceById: vi.fn(async (id: string) => {
      if (id === GUIDANCE_ID) {
        return {
          id: GUIDANCE_ID,
          title: 'Guide 1',
          category: 'general',
          content: 'Billing guidance content',
        };
      }
      return undefined;
    }),

    // --- Extension repo methods: Provincial PHN Formats ---
    listProvincialPhnFormats: vi.fn(async () => [
      { province: 'AB', format: '\\d{9}', label: 'Alberta PHN' },
      { province: 'BC', format: '\\d{10}', label: 'British Columbia PHN' },
    ]),

    // --- Extension repo methods: Reciprocal Billing ---
    getReciprocalRules: vi.fn(async () => [
      { province: 'AB', rules: [], description: 'Alberta reciprocal billing' },
    ]),

    // --- Extension repo methods: Anesthesia Rules ---
    listAnesthesiaRules: vi.fn(async () => [
      { code: 'ANES01', description: 'Base anesthesia', baseUnits: 4, timeUnitsPerMinute: 0.1 },
      { code: 'ANES02', description: 'Complex anesthesia', baseUnits: 8, timeUnitsPerMinute: 0.1 },
    ]),
    getAnesthesiaRuleByScenario: vi.fn(async (code: string) => {
      if (code === 'ANES01') {
        return { code: 'ANES01', baseUnits: 4, timeUnits: 1, description: 'Base anesthesia' };
      }
      return undefined;
    }),

    // --- Extension repo methods: Bundling Rules ---
    getBundlingRuleForPair: vi.fn(async () => ({
      codeA: '03.01A',
      codeB: '03.04J',
      bundled: false,
      rule: null,
    })),
    checkBundlingConflicts: vi.fn(async () => []),

    // --- Extension repo methods: Justification Templates ---
    listJustificationTemplates: vi.fn(async () => [{
      id: TEMPLATE_ID,
      title: 'Template 1',
      category: 'clinical',
      content: 'Justification template content',
    }]),
    getJustificationTemplate: vi.fn(async (id: string) => {
      if (id === TEMPLATE_ID) {
        return {
          id: TEMPLATE_ID,
          title: 'Template 1',
          category: 'clinical',
          content: 'Justification template content',
        };
      }
      return undefined;
    }),

    // --- Extension repo methods: WCB ---
    searchWcbCodes: vi.fn(async () => []),
    findWcbByCode: vi.fn(async () => undefined),
    bulkInsertWcbCodes: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let mockSessionRepo: ReturnType<typeof createMockSessionRepo>;
let sharedAuditLogger: ReturnType<typeof createSharedAuditLogger>;

async function buildTestApp(): Promise<FastifyInstance> {
  mockSessionRepo = createMockSessionRepo();
  sharedAuditLogger = createSharedAuditLogger();

  const sessionDeps: SessionManagementDeps = {
    sessionRepo: mockSessionRepo,
    auditRepo: createMockAuditRepo(),
    events: createMockEvents(),
  };

  const handlerDeps = {
    serviceDeps: {
      repo: createStubReferenceRepo(),
      auditLog: sharedAuditLogger,
      eventEmitter: createMockEvents(),
    },
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

  await testApp.register(referenceRoutes, { deps: handlerDeps });
  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function adminCookie(): string {
  return `session=${ADMIN_SESSION_TOKEN}`;
}

function physicianCookie(): string {
  return `session=${PHYSICIAN_SESSION_TOKEN}`;
}

function seedUsers() {
  users.push({
    userId: ADMIN_USER_ID,
    email: 'admin@meritum.ca',
    role: 'ADMIN',
    subscriptionStatus: 'ACTIVE',
  });
  sessions.push({
    sessionId: ADMIN_SESSION_ID,
    userId: ADMIN_USER_ID,
    tokenHash: ADMIN_SESSION_TOKEN_HASH,
    ipAddress: '10.0.0.1',
    userAgent: 'admin-browser',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

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
    ipAddress: '10.0.0.2',
    userAgent: 'physician-browser',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });
}

function findAuditEntry(action: string): { action: string; adminId: string; details: Record<string, unknown> } | undefined {
  return auditEntries.find((e) => e.action === action);
}

function findAllAuditEntries(action: string): Array<{ action: string; adminId: string; details: Record<string, unknown> }> {
  return auditEntries.filter((e) => e.action === action);
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Reference Data Extensions Audit Trail Completeness (Security)', () => {
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
    stagingRecords = [];
    versions = [];
    holidays = [];
    seedUsers();
    seedStagingRecord();
    seedVersions();
    seedHolidays();
    // Reset call counts on the shared audit logger
    sharedAuditLogger.log.mockClear();
  });

  // =========================================================================
  // 1. Extension read endpoints produce NO audit entries
  // =========================================================================

  describe('Extension read endpoints produce NO audit entries', () => {
    it('GET /api/v1/ref/icd-crosswalk?q=flu produces no audit entries', async () => {
      const countBefore = auditEntries.length;

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/icd-crosswalk?q=flu',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBeLessThan(400);
      expect(auditEntries.length).toBe(countBefore);
      expect(sharedAuditLogger.log).not.toHaveBeenCalled();
    });

    it('GET /api/v1/ref/icd-crosswalk/J09 produces no audit entries', async () => {
      const countBefore = auditEntries.length;

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/icd-crosswalk/J09',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBeLessThan(400);
      expect(auditEntries.length).toBe(countBefore);
      expect(sharedAuditLogger.log).not.toHaveBeenCalled();
    });

    it('GET /api/v1/ref/providers/search?q=Smith produces no audit entries', async () => {
      const countBefore = auditEntries.length;

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/providers/search?q=Smith',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBeLessThan(400);
      expect(auditEntries.length).toBe(countBefore);
      expect(sharedAuditLogger.log).not.toHaveBeenCalled();
    });

    it('GET /api/v1/ref/providers/12345 produces no audit entries', async () => {
      const countBefore = auditEntries.length;

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/providers/12345',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBeLessThan(400);
      expect(auditEntries.length).toBe(countBefore);
      expect(sharedAuditLogger.log).not.toHaveBeenCalled();
    });

    it('GET /api/v1/ref/guidance produces no audit entries', async () => {
      const countBefore = auditEntries.length;

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/guidance',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBeLessThan(400);
      expect(auditEntries.length).toBe(countBefore);
      expect(sharedAuditLogger.log).not.toHaveBeenCalled();
    });

    it('GET /api/v1/ref/guidance/:id produces no audit entries', async () => {
      const countBefore = auditEntries.length;

      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/ref/guidance/${GUIDANCE_ID}`,
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBeLessThan(400);
      expect(auditEntries.length).toBe(countBefore);
      expect(sharedAuditLogger.log).not.toHaveBeenCalled();
    });

    it('GET /api/v1/ref/provincial-phn-formats produces no audit entries', async () => {
      const countBefore = auditEntries.length;

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/provincial-phn-formats',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBeLessThan(400);
      expect(auditEntries.length).toBe(countBefore);
      expect(sharedAuditLogger.log).not.toHaveBeenCalled();
    });

    it('GET /api/v1/ref/reciprocal-rules/AB produces no audit entries', async () => {
      const countBefore = auditEntries.length;

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/reciprocal-rules/AB',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBeLessThan(400);
      expect(auditEntries.length).toBe(countBefore);
      expect(sharedAuditLogger.log).not.toHaveBeenCalled();
    });

    it('GET /api/v1/ref/anesthesia-rules produces no audit entries', async () => {
      const countBefore = auditEntries.length;

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/anesthesia-rules',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBeLessThan(400);
      expect(auditEntries.length).toBe(countBefore);
      expect(sharedAuditLogger.log).not.toHaveBeenCalled();
    });

    it('GET /api/v1/ref/anesthesia-rules/ANES01 produces no audit entries', async () => {
      const countBefore = auditEntries.length;

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/anesthesia-rules/ANES01',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBeLessThan(400);
      expect(auditEntries.length).toBe(countBefore);
      expect(sharedAuditLogger.log).not.toHaveBeenCalled();
    });

    it('POST /api/v1/ref/anesthesia-rules/calculate produces no audit entries', async () => {
      const countBefore = auditEntries.length;

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/anesthesia-rules/calculate',
        headers: { cookie: physicianCookie() },
        payload: {
          scenario_code: 'ANES01',
          time_minutes: 60,
        },
      });

      expect(res.statusCode).toBeLessThan(400);
      expect(auditEntries.length).toBe(countBefore);
      expect(sharedAuditLogger.log).not.toHaveBeenCalled();
    });

    it('GET /api/v1/ref/bundling-rules/pair/03.01A/03.04J produces no audit entries', async () => {
      const countBefore = auditEntries.length;

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/bundling-rules/pair/03.01A/03.04J',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBeLessThan(400);
      expect(auditEntries.length).toBe(countBefore);
      expect(sharedAuditLogger.log).not.toHaveBeenCalled();
    });

    it('POST /api/v1/ref/bundling-rules/check produces no audit entries', async () => {
      const countBefore = auditEntries.length;

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/bundling-rules/check',
        headers: { cookie: physicianCookie() },
        payload: { codes: ['03.01A', '03.04J'] },
      });

      expect(res.statusCode).toBeLessThan(400);
      expect(auditEntries.length).toBe(countBefore);
      expect(sharedAuditLogger.log).not.toHaveBeenCalled();
    });

    it('GET /api/v1/ref/justification-templates produces no audit entries', async () => {
      const countBefore = auditEntries.length;

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/justification-templates',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBeLessThan(400);
      expect(auditEntries.length).toBe(countBefore);
      expect(sharedAuditLogger.log).not.toHaveBeenCalled();
    });

    it('GET /api/v1/ref/justification-templates/:id produces no audit entries', async () => {
      const countBefore = auditEntries.length;

      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/ref/justification-templates/${TEMPLATE_ID}`,
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBeLessThan(400);
      expect(auditEntries.length).toBe(countBefore);
      expect(sharedAuditLogger.log).not.toHaveBeenCalled();
    });
  });

  // =========================================================================
  // 2. Admin operations still produce audit entries with extensions present
  // =========================================================================

  describe('Admin operations still produce audit entries with extensions present', () => {
    it('POST /api/v1/admin/ref/holidays produces ref.holiday_created audit entry', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/admin/ref/holidays',
        headers: { cookie: adminCookie() },
        payload: {
          name: 'Family Day',
          date: '2026-02-16',
          jurisdiction: 'provincial',
          affects_billing_premiums: true,
        },
      });

      expect(res.statusCode).toBe(201);

      const entry = findAuditEntry('ref.holiday_created');
      expect(entry).toBeDefined();
      expect(entry!.adminId).toBe(ADMIN_USER_ID);
      expect(entry!.details.name).toBe('Family Day');
      expect(entry!.details.date).toBe('2026-02-16');
      expect(sharedAuditLogger.log).toHaveBeenCalled();
    });

    it('PUT /api/v1/admin/ref/holidays/:id produces ref.holiday_updated audit entry', async () => {
      const res = await app.inject({
        method: 'PUT',
        url: `/api/v1/admin/ref/holidays/${HOLIDAY_ID}`,
        headers: { cookie: adminCookie() },
        payload: {
          name: 'Christmas Day (Updated)',
        },
      });

      expect(res.statusCode).toBe(200);

      const entry = findAuditEntry('ref.holiday_updated');
      expect(entry).toBeDefined();
      expect(entry!.adminId).toBe(ADMIN_USER_ID);
      expect(entry!.details.holiday_id).toBe(HOLIDAY_ID);
      expect(entry!.details.old_values).toBeDefined();
      expect(entry!.details.new_values).toBeDefined();
      expect(sharedAuditLogger.log).toHaveBeenCalled();
    });

    it('DELETE /api/v1/admin/ref/holidays/:id produces ref.holiday_deleted audit entry', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: `/api/v1/admin/ref/holidays/${HOLIDAY_ID}`,
        headers: { cookie: adminCookie() },
      });

      expect(res.statusCode).toBe(200);

      const entry = findAuditEntry('ref.holiday_deleted');
      expect(entry).toBeDefined();
      expect(entry!.adminId).toBe(ADMIN_USER_ID);
      expect(entry!.details.holiday_id).toBe(HOLIDAY_ID);
      expect(sharedAuditLogger.log).toHaveBeenCalled();
    });

    it('DELETE /api/v1/admin/ref/:dataset/staging/:id produces ref.staging_discarded audit entry', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: `/api/v1/admin/ref/SOMB/staging/${STAGING_ID}`,
        headers: { cookie: adminCookie() },
      });

      expect(res.statusCode).toBe(200);

      const entry = findAuditEntry('ref.staging_discarded');
      expect(entry).toBeDefined();
      expect(entry!.adminId).toBe(ADMIN_USER_ID);
      expect(entry!.details.staging_id).toBe(STAGING_ID);
      expect(entry!.details.data_set).toBe('SOMB');
      expect(sharedAuditLogger.log).toHaveBeenCalled();
    });

    it('POST /api/v1/admin/ref/rules/:rule_id/dry-run produces ref.rule_dry_run audit entry', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/admin/ref/rules/${RULE_ID}/dry-run`,
        headers: { cookie: adminCookie() },
        payload: {
          updated_rule_logic: { type: 'max_per_day', limit: 5 },
        },
      });

      expect(res.statusCode).toBe(200);

      const entry = findAuditEntry('ref.rule_dry_run');
      expect(entry).toBeDefined();
      expect(entry!.adminId).toBe(ADMIN_USER_ID);
      expect(entry!.details.rule_id).toBe(RULE_ID);
      expect(typeof entry!.details.claims_sampled).toBe('number');
      expect(sharedAuditLogger.log).toHaveBeenCalled();
    });

    it('POST /api/v1/admin/ref/:dataset/staging/:id/publish produces ref.version_published audit entry', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/admin/ref/SOMB/staging/${STAGING_ID}/publish`,
        headers: { cookie: adminCookie() },
        payload: {
          version_label: 'v2026.02',
          effective_from: '2026-03-01',
          change_summary: 'February update',
        },
      });

      expect(res.statusCode).toBe(201);

      const entry = findAuditEntry('ref.version_published');
      expect(entry).toBeDefined();
      expect(entry!.adminId).toBe(ADMIN_USER_ID);
      expect(entry!.details.data_set).toBe('SOMB');
      expect(entry!.details.effective_from).toBe('2026-03-01');
      expect(entry!.details.version_id).toBeDefined();
      expect(typeof entry!.details.version_id).toBe('string');
      expect(sharedAuditLogger.log).toHaveBeenCalled();
    });
  });

  // =========================================================================
  // 3. Audit entries contain correct admin identity
  // =========================================================================

  describe('Audit entries contain correct admin identity', () => {
    it('every audit entry from holiday operations has adminId matching ADMIN_USER_ID', async () => {
      // Create
      await app.inject({
        method: 'POST',
        url: '/api/v1/admin/ref/holidays',
        headers: { cookie: adminCookie() },
        payload: {
          name: 'Canada Day',
          date: '2026-07-01',
          jurisdiction: 'federal',
          affects_billing_premiums: false,
        },
      });

      // Update
      await app.inject({
        method: 'PUT',
        url: `/api/v1/admin/ref/holidays/${HOLIDAY_ID}`,
        headers: { cookie: adminCookie() },
        payload: { name: 'Updated Christmas' },
      });

      // Delete
      await app.inject({
        method: 'DELETE',
        url: `/api/v1/admin/ref/holidays/${HOLIDAY_ID}`,
        headers: { cookie: adminCookie() },
      });

      expect(auditEntries.length).toBeGreaterThanOrEqual(3);
      for (const entry of auditEntries) {
        expect(entry.adminId).toBe(ADMIN_USER_ID);
      }
    });

    it('staging discard audit entry has adminId from session not request body', async () => {
      await app.inject({
        method: 'DELETE',
        url: `/api/v1/admin/ref/SOMB/staging/${STAGING_ID}`,
        headers: { cookie: adminCookie() },
      });

      const entry = findAuditEntry('ref.staging_discarded');
      expect(entry).toBeDefined();
      expect(entry!.adminId).toBe(ADMIN_USER_ID);
    });

    it('version published audit entry has adminId from session not request body', async () => {
      await app.inject({
        method: 'POST',
        url: `/api/v1/admin/ref/SOMB/staging/${STAGING_ID}/publish`,
        headers: { cookie: adminCookie() },
        payload: {
          version_label: 'v2026.03',
          effective_from: '2026-04-01',
          change_summary: 'Identity test',
        },
      });

      const entry = findAuditEntry('ref.version_published');
      expect(entry).toBeDefined();
      expect(entry!.adminId).toBe(ADMIN_USER_ID);
    });

    it('dry-run audit entry has adminId from session not request body', async () => {
      await app.inject({
        method: 'POST',
        url: `/api/v1/admin/ref/rules/${RULE_ID}/dry-run`,
        headers: { cookie: adminCookie() },
        payload: { updated_rule_logic: { type: 'test' } },
      });

      const entry = findAuditEntry('ref.rule_dry_run');
      expect(entry).toBeDefined();
      expect(entry!.adminId).toBe(ADMIN_USER_ID);
    });

    it('admin identity is never taken from a spoofed userId in the request payload', async () => {
      const spoofedUserId = 'ffff9999-0000-0000-0000-000000000099';

      await app.inject({
        method: 'POST',
        url: '/api/v1/admin/ref/holidays',
        headers: { cookie: adminCookie() },
        payload: {
          name: 'Spoofed Holiday',
          date: '2026-08-15',
          jurisdiction: 'provincial',
          affects_billing_premiums: false,
          userId: spoofedUserId,
          adminId: spoofedUserId,
        },
      });

      const entry = findAuditEntry('ref.holiday_created');
      expect(entry).toBeDefined();
      // The adminId should come from the authenticated session, not the payload
      expect(entry!.adminId).toBe(ADMIN_USER_ID);
      expect(entry!.adminId).not.toBe(spoofedUserId);
    });
  });

  // =========================================================================
  // 4. Failed extension requests do not produce audit entries
  // =========================================================================

  describe('Failed extension requests do not produce audit entries', () => {
    it('unauthenticated request to extension read endpoint produces no audit entry', async () => {
      const countBefore = auditEntries.length;

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/icd-crosswalk?q=flu',
        // No cookie provided — unauthenticated
      });

      expect(res.statusCode).toBe(401);
      expect(auditEntries.length).toBe(countBefore);
      expect(sharedAuditLogger.log).not.toHaveBeenCalled();
    });

    it('unauthenticated request to provider search produces no audit entry', async () => {
      const countBefore = auditEntries.length;

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/providers/search?q=Smith',
      });

      expect(res.statusCode).toBe(401);
      expect(auditEntries.length).toBe(countBefore);
      expect(sharedAuditLogger.log).not.toHaveBeenCalled();
    });

    it('unauthenticated request to bundling check produces no audit entry', async () => {
      const countBefore = auditEntries.length;

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/bundling-rules/check',
        payload: { codes: ['03.01A', '03.04J'] },
      });

      expect(res.statusCode).toBe(401);
      expect(auditEntries.length).toBe(countBefore);
      expect(sharedAuditLogger.log).not.toHaveBeenCalled();
    });

    it('unauthenticated request to anesthesia calculate produces no audit entry', async () => {
      const countBefore = auditEntries.length;

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/anesthesia-rules/calculate',
        payload: { scenario_code: 'ANES01', time_minutes: 60 },
      });

      expect(res.statusCode).toBe(401);
      expect(auditEntries.length).toBe(countBefore);
      expect(sharedAuditLogger.log).not.toHaveBeenCalled();
    });

    it('400 on extension endpoint with bad params produces no audit entry', async () => {
      const countBefore = auditEntries.length;

      // bundling check requires at least 2 codes
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/bundling-rules/check',
        headers: { cookie: physicianCookie() },
        payload: { codes: ['single'] },
      });

      expect(res.statusCode).toBe(400);
      expect(auditEntries.length).toBe(countBefore);
      expect(sharedAuditLogger.log).not.toHaveBeenCalled();
    });

    it('400 on anesthesia calculate with missing required field produces no audit entry', async () => {
      const countBefore = auditEntries.length;

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/ref/anesthesia-rules/calculate',
        headers: { cookie: physicianCookie() },
        payload: {
          // missing time_minutes (required)
          scenario_code: 'ANES01',
        },
      });

      expect(res.statusCode).toBe(400);
      expect(auditEntries.length).toBe(countBefore);
      expect(sharedAuditLogger.log).not.toHaveBeenCalled();
    });

    it('403 on admin holiday create by physician produces no audit entry', async () => {
      const countBefore = auditEntries.length;

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/admin/ref/holidays',
        headers: { cookie: physicianCookie() },
        payload: {
          name: 'Unauthorized Holiday',
          date: '2026-09-01',
          jurisdiction: 'provincial',
          affects_billing_premiums: false,
        },
      });

      expect(res.statusCode).toBe(403);
      expect(auditEntries.length).toBe(countBefore);
      expect(sharedAuditLogger.log).not.toHaveBeenCalled();
    });

    it('403 on admin holiday update by physician produces no audit entry', async () => {
      const countBefore = auditEntries.length;

      const res = await app.inject({
        method: 'PUT',
        url: `/api/v1/admin/ref/holidays/${HOLIDAY_ID}`,
        headers: { cookie: physicianCookie() },
        payload: { name: 'Forbidden Update' },
      });

      expect(res.statusCode).toBe(403);
      expect(auditEntries.length).toBe(countBefore);
      expect(sharedAuditLogger.log).not.toHaveBeenCalled();
    });

    it('403 on admin holiday delete by physician produces no audit entry', async () => {
      const countBefore = auditEntries.length;

      const res = await app.inject({
        method: 'DELETE',
        url: `/api/v1/admin/ref/holidays/${HOLIDAY_ID}`,
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(403);
      expect(auditEntries.length).toBe(countBefore);
      expect(sharedAuditLogger.log).not.toHaveBeenCalled();
    });

    it('403 on admin staging discard by physician produces no audit entry', async () => {
      const countBefore = auditEntries.length;

      const res = await app.inject({
        method: 'DELETE',
        url: `/api/v1/admin/ref/SOMB/staging/${STAGING_ID}`,
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(403);
      expect(auditEntries.length).toBe(countBefore);
      expect(sharedAuditLogger.log).not.toHaveBeenCalled();
    });

    it('403 on admin dry-run by physician produces no audit entry', async () => {
      const countBefore = auditEntries.length;

      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/admin/ref/rules/${RULE_ID}/dry-run`,
        headers: { cookie: physicianCookie() },
        payload: { updated_rule_logic: { type: 'test' } },
      });

      expect(res.statusCode).toBe(403);
      expect(auditEntries.length).toBe(countBefore);
      expect(sharedAuditLogger.log).not.toHaveBeenCalled();
    });

    it('publishing a non-existent staging record does not produce ref.version_published audit entry', async () => {
      const nonExistentStagingId = 'ffffffff-0000-0000-0000-000000000002';

      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/admin/ref/SOMB/staging/${nonExistentStagingId}/publish`,
        headers: { cookie: adminCookie() },
        payload: {
          version_label: 'v-fail',
          effective_from: '2026-12-01',
          change_summary: 'Should fail',
        },
      });

      expect(res.statusCode).toBeGreaterThanOrEqual(400);

      const entry = findAuditEntry('ref.version_published');
      expect(entry).toBeUndefined();
    });

    it('discarding a non-existent staging record does not produce ref.staging_discarded audit entry', async () => {
      const nonExistentStagingId = 'ffffffff-0000-0000-0000-000000000003';

      const res = await app.inject({
        method: 'DELETE',
        url: `/api/v1/admin/ref/SOMB/staging/${nonExistentStagingId}`,
        headers: { cookie: adminCookie() },
      });

      expect(res.statusCode).toBeGreaterThanOrEqual(400);

      const entry = findAuditEntry('ref.staging_discarded');
      expect(entry).toBeUndefined();
    });

    it('updating a non-existent holiday does not produce ref.holiday_updated audit entry', async () => {
      const nonExistentId = 'ffffffff-0000-0000-0000-000000000004';

      const res = await app.inject({
        method: 'PUT',
        url: `/api/v1/admin/ref/holidays/${nonExistentId}`,
        headers: { cookie: adminCookie() },
        payload: { name: 'Ghost Holiday' },
      });

      expect(res.statusCode).toBeGreaterThanOrEqual(400);

      const entry = findAuditEntry('ref.holiday_updated');
      expect(entry).toBeUndefined();
    });
  });

  // =========================================================================
  // 5. Audit entries are append-only
  // =========================================================================

  describe('Audit entries are append-only', () => {
    it('audit log mock is called via .log() and not via any delete or update method', async () => {
      await app.inject({
        method: 'POST',
        url: '/api/v1/admin/ref/holidays',
        headers: { cookie: adminCookie() },
        payload: {
          name: 'Append Test Holiday',
          date: '2026-08-01',
          jurisdiction: 'provincial',
          affects_billing_premiums: true,
        },
      });

      // The shared audit logger should only expose .log()
      expect(sharedAuditLogger.log).toHaveBeenCalled();
      // Verify there is no delete or update method on the logger
      expect((sharedAuditLogger as any).delete).toBeUndefined();
      expect((sharedAuditLogger as any).update).toBeUndefined();
      expect((sharedAuditLogger as any).remove).toBeUndefined();
      expect((sharedAuditLogger as any).clear).toBeUndefined();
    });

    it('sequential operations produce incrementing audit counts', async () => {
      expect(auditEntries.length).toBe(0);

      // 1. Create holiday
      await app.inject({
        method: 'POST',
        url: '/api/v1/admin/ref/holidays',
        headers: { cookie: adminCookie() },
        payload: { name: 'New Year', date: '2027-01-01', jurisdiction: 'federal', affects_billing_premiums: false },
      });
      const afterCreate = auditEntries.length;
      expect(afterCreate).toBeGreaterThan(0);

      // 2. Update holiday
      await app.inject({
        method: 'PUT',
        url: `/api/v1/admin/ref/holidays/${HOLIDAY_ID}`,
        headers: { cookie: adminCookie() },
        payload: { name: 'Updated' },
      });
      const afterUpdate = auditEntries.length;
      expect(afterUpdate).toBeGreaterThan(afterCreate);

      // 3. Delete holiday
      await app.inject({
        method: 'DELETE',
        url: `/api/v1/admin/ref/holidays/${HOLIDAY_ID}`,
        headers: { cookie: adminCookie() },
      });
      const afterDelete = auditEntries.length;
      expect(afterDelete).toBeGreaterThan(afterUpdate);

      // 4. Discard staging
      await app.inject({
        method: 'DELETE',
        url: `/api/v1/admin/ref/SOMB/staging/${STAGING_ID}`,
        headers: { cookie: adminCookie() },
      });
      const afterDiscard = auditEntries.length;
      expect(afterDiscard).toBeGreaterThan(afterDelete);

      // 5. Dry-run
      await app.inject({
        method: 'POST',
        url: `/api/v1/admin/ref/rules/${RULE_ID}/dry-run`,
        headers: { cookie: adminCookie() },
        payload: { updated_rule_logic: { type: 'test' } },
      });
      const afterDryRun = auditEntries.length;
      expect(afterDryRun).toBeGreaterThan(afterDiscard);
    });

    it('earlier entries remain intact after subsequent operations', async () => {
      // 1. Create holiday
      await app.inject({
        method: 'POST',
        url: '/api/v1/admin/ref/holidays',
        headers: { cookie: adminCookie() },
        payload: { name: 'First Operation', date: '2026-06-01', jurisdiction: 'federal', affects_billing_premiums: false },
      });

      const firstEntry = { ...auditEntries[0] };
      expect(firstEntry.action).toBe('ref.holiday_created');

      // 2. Update holiday
      await app.inject({
        method: 'PUT',
        url: `/api/v1/admin/ref/holidays/${HOLIDAY_ID}`,
        headers: { cookie: adminCookie() },
        payload: { name: 'Second Operation' },
      });

      // Verify the first entry is still identical
      expect(auditEntries[0].action).toBe(firstEntry.action);
      expect(auditEntries[0].adminId).toBe(firstEntry.adminId);
      expect(auditEntries[0].details.name).toBe(firstEntry.details.name);

      // 3. Delete holiday
      await app.inject({
        method: 'DELETE',
        url: `/api/v1/admin/ref/holidays/${HOLIDAY_ID}`,
        headers: { cookie: adminCookie() },
      });

      // Verify both earlier entries are still present and intact
      expect(auditEntries[0].action).toBe('ref.holiday_created');
      expect(auditEntries[1].action).toBe('ref.holiday_updated');
      expect(auditEntries[2].action).toBe('ref.holiday_deleted');
    });

    it('interleaving read operations between admin operations does not affect audit count', async () => {
      // Admin operation 1
      await app.inject({
        method: 'POST',
        url: '/api/v1/admin/ref/holidays',
        headers: { cookie: adminCookie() },
        payload: { name: 'Interleave Test', date: '2026-05-01', jurisdiction: 'provincial', affects_billing_premiums: true },
      });
      const afterFirst = auditEntries.length;

      // Several read operations (should not produce any audit entries)
      await app.inject({
        method: 'GET',
        url: '/api/v1/ref/icd-crosswalk?q=test',
        headers: { cookie: physicianCookie() },
      });

      await app.inject({
        method: 'GET',
        url: '/api/v1/ref/providers/search?q=test',
        headers: { cookie: physicianCookie() },
      });

      await app.inject({
        method: 'GET',
        url: '/api/v1/ref/anesthesia-rules',
        headers: { cookie: physicianCookie() },
      });

      await app.inject({
        method: 'GET',
        url: '/api/v1/ref/justification-templates',
        headers: { cookie: physicianCookie() },
      });

      // Audit count should be unchanged after all the reads
      expect(auditEntries.length).toBe(afterFirst);

      // Admin operation 2
      await app.inject({
        method: 'DELETE',
        url: `/api/v1/admin/ref/SOMB/staging/${STAGING_ID}`,
        headers: { cookie: adminCookie() },
      });
      const afterSecond = auditEntries.length;
      expect(afterSecond).toBeGreaterThan(afterFirst);
    });

    it('audit log call count matches sharedAuditLogger.log mock call count', async () => {
      await app.inject({
        method: 'POST',
        url: '/api/v1/admin/ref/holidays',
        headers: { cookie: adminCookie() },
        payload: { name: 'Log Count Test', date: '2026-04-01', jurisdiction: 'federal', affects_billing_premiums: false },
      });

      await app.inject({
        method: 'DELETE',
        url: `/api/v1/admin/ref/SOMB/staging/${STAGING_ID}`,
        headers: { cookie: adminCookie() },
      });

      // The mock call count should exactly match the array length
      expect(sharedAuditLogger.log).toHaveBeenCalledTimes(auditEntries.length);
    });
  });

  // =========================================================================
  // Audit entries have consistent structure
  // =========================================================================

  describe('Audit entries have consistent structure', () => {
    it('all audit entries have action and adminId fields with correct types', async () => {
      await app.inject({
        method: 'POST',
        url: '/api/v1/admin/ref/holidays',
        headers: { cookie: adminCookie() },
        payload: { name: 'Structure Test', date: '2026-09-01', jurisdiction: 'provincial', affects_billing_premiums: false },
      });

      await app.inject({
        method: 'PUT',
        url: `/api/v1/admin/ref/holidays/${HOLIDAY_ID}`,
        headers: { cookie: adminCookie() },
        payload: { name: 'Structure Update' },
      });

      await app.inject({
        method: 'DELETE',
        url: `/api/v1/admin/ref/SOMB/staging/${STAGING_ID}`,
        headers: { cookie: adminCookie() },
      });

      expect(auditEntries.length).toBeGreaterThan(0);
      for (const entry of auditEntries) {
        expect(entry.action).toBeDefined();
        expect(typeof entry.action).toBe('string');
        expect(entry.action.startsWith('ref.')).toBe(true);
        expect(entry.adminId).toBeDefined();
        expect(typeof entry.adminId).toBe('string');
        expect(entry.details).toBeDefined();
        expect(typeof entry.details).toBe('object');
      }
    });

    it('audit entry details do not contain the full staged data payload', async () => {
      await app.inject({
        method: 'POST',
        url: `/api/v1/admin/ref/SOMB/staging/${STAGING_ID}/publish`,
        headers: { cookie: adminCookie() },
        payload: {
          version_label: 'v2026.06',
          effective_from: '2026-07-01',
          change_summary: 'Payload exclusion test',
        },
      });

      const entry = findAuditEntry('ref.version_published');
      expect(entry).toBeDefined();

      // Should not contain raw record data
      const entryStr = JSON.stringify(entry);
      expect(entryStr).not.toContain('Office Visit');
      expect(entryStr).not.toContain('Follow-up Visit');

      // Size should be reasonable (< 10KB)
      const entrySize = Buffer.byteLength(entryStr, 'utf-8');
      expect(entrySize).toBeLessThan(10 * 1024);
    });

    it('version published audit entry contains record counts metadata not full records', async () => {
      await app.inject({
        method: 'POST',
        url: `/api/v1/admin/ref/SOMB/staging/${STAGING_ID}/publish`,
        headers: { cookie: adminCookie() },
        payload: {
          version_label: 'v2026.07',
          effective_from: '2026-08-01',
          change_summary: 'Metadata counts test',
        },
      });

      const entry = findAuditEntry('ref.version_published');
      expect(entry).toBeDefined();
      expect(entry!.details).toHaveProperty('records_added');
      expect(entry!.details).toHaveProperty('records_modified');
      expect(entry!.details).toHaveProperty('records_deprecated');
    });
  });

  // =========================================================================
  // Sanity: test setup validates correctly
  // =========================================================================

  describe('Sanity: test setup validates correctly', () => {
    it('admin session authenticates successfully on admin endpoint', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/admin/ref/SOMB/versions',
        headers: { cookie: adminCookie() },
      });

      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('physician session authenticates successfully on read extension endpoint', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/icd-crosswalk?q=test',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('physician session authenticates on all extension read endpoints', async () => {
      const endpoints = [
        { method: 'GET' as const, url: '/api/v1/ref/icd-crosswalk?q=flu' },
        { method: 'GET' as const, url: '/api/v1/ref/icd-crosswalk/J09' },
        { method: 'GET' as const, url: '/api/v1/ref/providers/search?q=Smith' },
        { method: 'GET' as const, url: '/api/v1/ref/providers/12345' },
        { method: 'GET' as const, url: '/api/v1/ref/guidance' },
        { method: 'GET' as const, url: `/api/v1/ref/guidance/${GUIDANCE_ID}` },
        { method: 'GET' as const, url: '/api/v1/ref/provincial-phn-formats' },
        { method: 'GET' as const, url: '/api/v1/ref/reciprocal-rules/AB' },
        { method: 'GET' as const, url: '/api/v1/ref/anesthesia-rules' },
        { method: 'GET' as const, url: '/api/v1/ref/anesthesia-rules/ANES01' },
        { method: 'GET' as const, url: '/api/v1/ref/bundling-rules/pair/03.01A/03.04J' },
        { method: 'GET' as const, url: '/api/v1/ref/justification-templates' },
        { method: 'GET' as const, url: `/api/v1/ref/justification-templates/${TEMPLATE_ID}` },
      ];

      for (const ep of endpoints) {
        const res = await app.inject({
          method: ep.method,
          url: ep.url,
          headers: { cookie: physicianCookie() },
        });

        expect(res.statusCode).not.toBe(401);
        expect(res.statusCode).not.toBe(403);
      }
    });

    it('shared audit logger captures entries from holiday create service call', async () => {
      await app.inject({
        method: 'POST',
        url: '/api/v1/admin/ref/holidays',
        headers: { cookie: adminCookie() },
        payload: { name: 'Sanity Holiday', date: '2026-10-01', jurisdiction: 'federal', affects_billing_premiums: false },
      });

      expect(findAuditEntry('ref.holiday_created')).toBeDefined();
      expect(sharedAuditLogger.log).toHaveBeenCalledTimes(1);
    });

    it('shared audit logger captures entries from staging discard service call', async () => {
      await app.inject({
        method: 'DELETE',
        url: `/api/v1/admin/ref/SOMB/staging/${STAGING_ID}`,
        headers: { cookie: adminCookie() },
      });

      expect(findAuditEntry('ref.staging_discarded')).toBeDefined();
      expect(sharedAuditLogger.log).toHaveBeenCalledTimes(1);
    });

    it('every mutating admin operation produces at least one audit entry', async () => {
      const operationsBeforeCount = auditEntries.length;

      // 1. Create holiday
      await app.inject({
        method: 'POST',
        url: '/api/v1/admin/ref/holidays',
        headers: { cookie: adminCookie() },
        payload: { name: 'Mutating Check', date: '2026-11-01', jurisdiction: 'provincial', affects_billing_premiums: true },
      });
      expect(auditEntries.length).toBeGreaterThan(operationsBeforeCount);
      const afterCreate = auditEntries.length;

      // 2. Update holiday
      await app.inject({
        method: 'PUT',
        url: `/api/v1/admin/ref/holidays/${HOLIDAY_ID}`,
        headers: { cookie: adminCookie() },
        payload: { name: 'Updated Mutating Check' },
      });
      expect(auditEntries.length).toBeGreaterThan(afterCreate);
      const afterUpdate = auditEntries.length;

      // 3. Delete holiday
      await app.inject({
        method: 'DELETE',
        url: `/api/v1/admin/ref/holidays/${HOLIDAY_ID}`,
        headers: { cookie: adminCookie() },
      });
      expect(auditEntries.length).toBeGreaterThan(afterUpdate);
      const afterDelete = auditEntries.length;

      // 4. Discard staging
      await app.inject({
        method: 'DELETE',
        url: `/api/v1/admin/ref/SOMB/staging/${STAGING_ID}`,
        headers: { cookie: adminCookie() },
      });
      expect(auditEntries.length).toBeGreaterThan(afterDelete);
      const afterDiscard = auditEntries.length;

      // 5. Dry-run
      await app.inject({
        method: 'POST',
        url: `/api/v1/admin/ref/rules/${RULE_ID}/dry-run`,
        headers: { cookie: adminCookie() },
        payload: { updated_rule_logic: { type: 'test' } },
      });
      expect(auditEntries.length).toBeGreaterThan(afterDiscard);
    });
  });

  // =========================================================================
  // Extension audit action types coverage
  // =========================================================================

  describe('Extension audit action types coverage', () => {
    it('covers all expected extension-related audit action identifiers', () => {
      const expectedActions = [
        'ref.holiday_created',
        'ref.holiday_updated',
        'ref.holiday_deleted',
        'ref.version_published',
        'ref.staging_discarded',
        'ref.rule_dry_run',
      ];

      // These are all tested individually in the test cases above.
      // This test documents the complete set for the extension endpoints.
      expect(expectedActions).toHaveLength(6);
    });
  });
});
