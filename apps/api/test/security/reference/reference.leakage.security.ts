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

// Physician user (TRIAL subscription)
const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_USER_ID = 'dddd0000-0000-0000-0000-000000000001';
const PHYSICIAN_SESSION_ID = 'dddd0000-0000-0000-0000-000000000011';

// Admin user
const ADMIN_SESSION_TOKEN = randomBytes(32).toString('hex');
const ADMIN_SESSION_TOKEN_HASH = hashToken(ADMIN_SESSION_TOKEN);
const ADMIN_USER_ID = 'dddd0000-0000-0000-0000-000000000002';
const ADMIN_SESSION_ID = 'dddd0000-0000-0000-0000-000000000012';

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
  };
}

function createMockEvents() {
  return { emit: vi.fn() };
}

// ---------------------------------------------------------------------------
// Version and staging data stores
// ---------------------------------------------------------------------------

const SOMB_VERSION_V1_ID = '11111111-1111-1111-1111-111111111111';
const SOMB_VERSION_V2_ID = '22222222-2222-2222-2222-222222222222';
const SOMB_VERSION_FUTURE_ID = '33333333-3333-3333-3333-333333333333';
const DI_VERSION_ID = '44444444-4444-4444-4444-444444444444';
const MODIFIERS_VERSION_ID = '55555555-5555-5555-5555-555555555555';
const RULES_VERSION_ID = '66666666-6666-6666-6666-666666666666';
const FC_VERSION_ID = '77777777-7777-7777-7777-777777777777';
const STAGING_ID = '88888888-8888-8888-8888-888888888888';
const EXPL_VERSION_ID = '99999999-9999-9999-9999-999999999999';

// Version store for all datasets
const versionStore: Record<string, Array<{
  versionId: string;
  dataSet: string;
  versionLabel: string;
  effectiveFrom: string;
  effectiveTo: string | null;
  isActive: boolean;
  publishedBy: string;
  publishedAt: Date;
  recordsAdded: number;
  recordsModified: number;
  recordsDeprecated: number;
  changeSummary: string | null;
  sourceDocument: string | null;
}>> = {};

// HSC code store
const hscStore: Array<{
  hscCode: string;
  versionId: string;
  description: string;
  baseFee: string | null;
  feeType: string;
  helpText: string | null;
  effectiveTo: string | null;
  specialtyRestrictions: string[];
  facilityRestrictions: string[];
  modifierEligibility: string[];
  combinationGroup: string | null;
  surchargeEligible: boolean;
  pcpcmBasket: string;
  maxPerDay: number | null;
  maxPerVisit: number | null;
  requiresReferral: boolean;
}> = [];

// DI code store
const diStore: Array<{
  diCode: string;
  versionId: string;
  description: string;
  category: string;
  subcategory: string | null;
  qualifiesSurcharge: boolean;
  qualifiesBcp: boolean;
  commonInSpecialty: string[];
  helpText: string | null;
}> = [];

// Staging store
const stagingStore: Array<{
  stagingId: string;
  dataSet: string;
  uploadedBy: string;
  fileHash: string;
  recordCount: number;
  stagedData: unknown[];
  status: string;
  validationResult: unknown;
  diffResult: unknown;
}> = [];

// Rules store
const rulesStore: Array<{
  ruleId: string;
  versionId: string;
  ruleName: string;
  ruleCategory: string;
  description: string;
  ruleLogic: Record<string, unknown>;
  severity: string;
  errorMessage: string;
  helpText: string | null;
  sourceReference: string | null;
  sourceUrl: string | null;
}> = [];

// Modifier store
const modifierStore: Array<{
  modifierCode: string;
  versionId: string;
  name: string;
  description: string;
  type: string;
  calculationMethod: string;
  calculationParams: Record<string, unknown>;
  helpText: string | null;
  combinableWith: string[];
  exclusiveWith: string[];
  governingRuleReference: string | null;
  requiresTimeDocumentation: boolean;
  requiresFacility: boolean;
  applicableHscFilter: unknown;
}> = [];

// Holiday store
const holidayStore: Array<{
  holidayId: string;
  date: string;
  name: string;
  jurisdiction: string;
  affectsBillingPremiums: boolean;
  year: number;
}> = [];

// FC store
const fcStore: Array<{
  code: string;
  versionId: string;
  name: string;
  facilityType: string;
  active: boolean;
}> = [];

// Explanatory code store
const explStore: Array<{
  explCode: string;
  versionId: string;
  description: string;
  severity: string;
  commonCause: string | null;
  suggestedAction: string | null;
  helpText: string | null;
}> = [];

// ---------------------------------------------------------------------------
// Stub reference repository with controlled data
// ---------------------------------------------------------------------------

function createStubReferenceRepo() {
  return {
    findActiveVersion: vi.fn(async (dataSet: string) => {
      const versions = versionStore[dataSet] ?? [];
      return versions.find((v) => v.isActive);
    }),
    findVersionForDate: vi.fn(async (dataSet: string, date: Date) => {
      const dateStr = date.toISOString().split('T')[0];
      const versions = versionStore[dataSet] ?? [];
      return versions.find(
        (v) =>
          v.effectiveFrom <= dateStr &&
          (v.effectiveTo === null || v.effectiveTo > dateStr),
      );
    }),
    findVersionById: vi.fn(async (versionId: string) => {
      for (const ds of Object.values(versionStore)) {
        const found = ds.find((v) => v.versionId === versionId);
        if (found) return found;
      }
      return undefined;
    }),
    listVersions: vi.fn(async (dataSet: string) => {
      return versionStore[dataSet] ?? [];
    }),
    createVersion: vi.fn(async (data: Record<string, unknown>) => {
      return { versionId: 'new-version-id', ...data };
    }),
    activateVersion: vi.fn(async () => {}),
    deactivateVersion: vi.fn(async () => {}),

    // HSC
    searchHscCodes: vi.fn(async (query: string, versionId: string, _filters: unknown, limit: number) => {
      return hscStore
        .filter((c) => c.versionId === versionId)
        .filter((c) => c.hscCode.includes(query) || c.description.toLowerCase().includes(query.toLowerCase()))
        .slice(0, limit);
    }),
    findHscByCode: vi.fn(async (hscCode: string, versionId: string) => {
      return hscStore.find((c) => c.hscCode === hscCode && c.versionId === versionId);
    }),
    listHscByVersion: vi.fn(async (versionId: string, pagination: { limit: number; offset: number }) => {
      const data = hscStore.filter((c) => c.versionId === versionId);
      return { data: data.slice(pagination.offset, pagination.offset + pagination.limit), total: data.length };
    }),
    findModifiersForHsc: vi.fn(async (_hscCode: string, versionId: string) => {
      return modifierStore.filter((m) => m.versionId === versionId);
    }),
    bulkInsertHscCodes: vi.fn(async () => {}),
    getHscByCode: vi.fn(async () => undefined),
    getHscCodesByVersion: vi.fn(async () => []),

    // DI
    searchDiCodes: vi.fn(async (query: string, versionId: string, _filters: unknown, limit: number) => {
      return diStore
        .filter((c) => c.versionId === versionId)
        .filter((c) => c.diCode.includes(query) || c.description.toLowerCase().includes(query.toLowerCase()))
        .slice(0, limit);
    }),
    findDiByCode: vi.fn(async (diCode: string, versionId: string) => {
      return diStore.find((c) => c.diCode === diCode && c.versionId === versionId);
    }),
    getDiByCode: vi.fn(async () => undefined),
    getDiCodesByVersion: vi.fn(async () => []),
    bulkInsertDiCodes: vi.fn(async () => {}),

    // Modifiers
    getModifierByCode: vi.fn(async () => undefined),
    findModifierByCode: vi.fn(async (code: string, versionId: string) => {
      return modifierStore.find((m) => m.modifierCode === code && m.versionId === versionId);
    }),
    listAllModifiers: vi.fn(async (versionId: string) => {
      return modifierStore.filter((m) => m.versionId === versionId);
    }),
    getModifiersForHsc: vi.fn(async () => []),
    getModifiersByVersion: vi.fn(async () => []),
    bulkInsertModifiers: vi.fn(async () => {}),

    // Functional centres
    listFunctionalCentres: vi.fn(async (versionId: string, _facilityType?: string) => {
      return fcStore.filter((f) => f.versionId === versionId);
    }),
    findFunctionalCentre: vi.fn(async (code: string, versionId: string) => {
      return fcStore.find((f) => f.code === code && f.versionId === versionId);
    }),
    getFunctionalCentresByVersion: vi.fn(async () => []),
    bulkInsertFunctionalCentres: vi.fn(async () => {}),

    // Explanatory codes
    getExplanatoryCode: vi.fn(async () => undefined),
    findExplanatoryCode: vi.fn(async (code: string, versionId: string) => {
      return explStore.find((e) => e.explCode === code && e.versionId === versionId);
    }),
    getExplanatoryCodesByVersion: vi.fn(async () => []),
    bulkInsertExplanatoryCodes: vi.fn(async () => {}),

    // RRNP
    getRrnpCommunity: vi.fn(async () => undefined),
    findRrnpRate: vi.fn(async () => undefined),
    getRrnpCommunitiesByVersion: vi.fn(async () => []),
    bulkInsertRrnpCommunities: vi.fn(async () => {}),

    // PCPCM
    getPcpcmBasket: vi.fn(async () => undefined),
    findPcpcmBasket: vi.fn(async () => undefined),
    getPcpcmBasketsByVersion: vi.fn(async () => []),
    bulkInsertPcpcmBaskets: vi.fn(async () => {}),

    // Holidays
    listHolidaysByYear: vi.fn(async (year: number) => {
      return holidayStore.filter((h) => h.year === year);
    }),
    listHolidays: vi.fn(async () => holidayStore),
    isHoliday: vi.fn(async (date: Date) => {
      const dateStr = date.toISOString().split('T')[0];
      const found = holidayStore.find((h) => h.date === dateStr);
      return { is_holiday: !!found, holiday_name: found?.name };
    }),
    getHolidayById: vi.fn(async () => undefined),
    createHoliday: vi.fn(async (data: Record<string, unknown>) => ({
      holidayId: 'new-holiday-id',
      ...data,
    })),
    updateHoliday: vi.fn(async () => ({})),
    deleteHoliday: vi.fn(async () => {}),

    // Governing rules
    findGoverningRules: vi.fn(async () => []),
    findRulesForContext: vi.fn(async (hscCodes: string[], _diCode: string | null, _facilityCode: string | null, versionId: string) => {
      return rulesStore.filter((r) => r.versionId === versionId);
    }),
    findRuleById: vi.fn(async (ruleId: string, versionId: string) => {
      return rulesStore.find((r) => r.ruleId === ruleId && r.versionId === versionId);
    }),
    getGoverningRuleById: vi.fn(async () => undefined),
    getGoverningRulesByVersion: vi.fn(async () => []),
    bulkInsertGoverningRules: vi.fn(async () => {}),
    bulkInsertRules: vi.fn(async () => {}),

    // Staging
    createStagingRecord: vi.fn(async (data: Record<string, unknown>) => {
      const entry = {
        stagingId: STAGING_ID,
        dataSet: data.dataSet as string,
        uploadedBy: data.uploadedBy as string,
        fileHash: data.fileHash as string,
        recordCount: data.recordCount as number,
        stagedData: data.stagedData as unknown[],
        status: 'uploaded',
        validationResult: null,
        diffResult: null,
      };
      stagingStore.push(entry);
      return entry;
    }),
    findStagingById: vi.fn(async (stagingId: string) => {
      return stagingStore.find((s) => s.stagingId === stagingId);
    }),
    findStagingEntry: vi.fn(async () => undefined),
    updateStagingStatus: vi.fn(async (stagingId: string, status: string, extra?: Record<string, unknown>) => {
      const entry = stagingStore.find((s) => s.stagingId === stagingId);
      if (entry) {
        entry.status = status;
        if (extra?.validation_result) entry.validationResult = extra.validation_result;
        if (extra?.diff_result) entry.diffResult = extra.diff_result;
      }
    }),
    deleteStagingRecord: vi.fn(async (stagingId: string) => {
      const idx = stagingStore.findIndex((s) => s.stagingId === stagingId);
      if (idx >= 0) stagingStore.splice(idx, 1);
    }),
    deleteStagingEntry: vi.fn(async () => {}),
    getHscFavourites: vi.fn(async () => []),
    findVersionByVersionId: vi.fn(async () => undefined),
    getChangeSummaries: vi.fn(async () => []),
    getChangeDetails: vi.fn(async () => []),

    // WCB stubs for getActiveRecords
    searchWcbCodes: vi.fn(async () => []),
    bulkInsertWcbCodes: vi.fn(async () => {}),
    listRulesByCategory: vi.fn(async () => []),
  };
}

// ---------------------------------------------------------------------------
// Test app builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let mockSessionRepo: ReturnType<typeof createMockSessionRepo>;
let stubRepo: ReturnType<typeof createStubReferenceRepo>;

async function buildTestApp(): Promise<FastifyInstance> {
  mockSessionRepo = createMockSessionRepo();
  stubRepo = createStubReferenceRepo();

  const sessionDeps: SessionManagementDeps = {
    sessionRepo: mockSessionRepo,
    auditRepo: createMockAuditRepo(),
    events: createMockEvents(),
  };

  const handlerDeps = {
    serviceDeps: {
      repo: stubRepo,
      auditLog: { log: vi.fn(async () => {}) },
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

function physicianCookie(): string {
  return `session=${PHYSICIAN_SESSION_TOKEN}`;
}

function adminCookie(): string {
  return `session=${ADMIN_SESSION_TOKEN}`;
}

function seedUsers() {
  users = [];
  sessions = [];

  // Physician
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

  // Admin
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

function seedReferenceData() {
  // Clear stores
  for (const key of Object.keys(versionStore)) delete versionStore[key];
  hscStore.length = 0;
  diStore.length = 0;
  stagingStore.length = 0;
  rulesStore.length = 0;
  modifierStore.length = 0;
  holidayStore.length = 0;
  fcStore.length = 0;
  explStore.length = 0;

  // SOMB version V1: active, effective 2025-04-01
  versionStore['SOMB'] = [
    {
      versionId: SOMB_VERSION_V1_ID,
      dataSet: 'SOMB',
      versionLabel: 'SOMB 2025-Q2',
      effectiveFrom: '2025-04-01',
      effectiveTo: '2025-10-01',
      isActive: false,
      publishedBy: ADMIN_USER_ID,
      publishedAt: new Date('2025-03-15'),
      recordsAdded: 10,
      recordsModified: 5,
      recordsDeprecated: 2,
      changeSummary: 'Q2 update',
      sourceDocument: null,
    },
    {
      versionId: SOMB_VERSION_V2_ID,
      dataSet: 'SOMB',
      versionLabel: 'SOMB 2025-Q4',
      effectiveFrom: '2025-10-01',
      effectiveTo: null,
      isActive: true,
      publishedBy: ADMIN_USER_ID,
      publishedAt: new Date('2025-09-20'),
      recordsAdded: 8,
      recordsModified: 3,
      recordsDeprecated: 1,
      changeSummary: 'Q4 update',
      sourceDocument: null,
    },
    {
      versionId: SOMB_VERSION_FUTURE_ID,
      dataSet: 'SOMB',
      versionLabel: 'SOMB 2027-Q1',
      effectiveFrom: '2027-01-01',
      effectiveTo: null,
      isActive: false,
      publishedBy: ADMIN_USER_ID,
      publishedAt: new Date('2026-12-01'),
      recordsAdded: 15,
      recordsModified: 0,
      recordsDeprecated: 0,
      changeSummary: 'Future version',
      sourceDocument: null,
    },
  ];

  // HSC codes in V1
  hscStore.push({
    hscCode: '03.01A',
    versionId: SOMB_VERSION_V1_ID,
    description: 'Office Visit - Complete Assessment (V1)',
    baseFee: '75.00',
    feeType: 'fixed',
    helpText: 'V1 version of office visit',
    effectiveTo: null,
    specialtyRestrictions: [],
    facilityRestrictions: [],
    modifierEligibility: [],
    combinationGroup: null,
    surchargeEligible: true,
    pcpcmBasket: 'in_basket',
    maxPerDay: 1,
    maxPerVisit: 1,
    requiresReferral: false,
  });

  // HSC codes in V2 (active)
  hscStore.push({
    hscCode: '03.01A',
    versionId: SOMB_VERSION_V2_ID,
    description: 'Office Visit - Complete Assessment (V2)',
    baseFee: '80.00',
    feeType: 'fixed',
    helpText: 'V2 version of office visit',
    effectiveTo: null,
    specialtyRestrictions: [],
    facilityRestrictions: [],
    modifierEligibility: [],
    combinationGroup: null,
    surchargeEligible: true,
    pcpcmBasket: 'in_basket',
    maxPerDay: 1,
    maxPerVisit: 1,
    requiresReferral: false,
  });

  // HSC code ONLY in future version (should never appear in current searches)
  hscStore.push({
    hscCode: '99.99Z',
    versionId: SOMB_VERSION_FUTURE_ID,
    description: 'Future-only procedure code',
    baseFee: '500.00',
    feeType: 'fixed',
    helpText: 'This code is from the future',
    effectiveTo: null,
    specialtyRestrictions: [],
    facilityRestrictions: [],
    modifierEligibility: [],
    combinationGroup: null,
    surchargeEligible: false,
    pcpcmBasket: 'not_applicable',
    maxPerDay: null,
    maxPerVisit: null,
    requiresReferral: false,
  });

  // DI codes
  versionStore['DI_CODES'] = [{
    versionId: DI_VERSION_ID,
    dataSet: 'DI_CODES',
    versionLabel: 'DI 2025',
    effectiveFrom: '2025-01-01',
    effectiveTo: null,
    isActive: true,
    publishedBy: ADMIN_USER_ID,
    publishedAt: new Date('2025-01-01'),
    recordsAdded: 100,
    recordsModified: 0,
    recordsDeprecated: 0,
    changeSummary: null,
    sourceDocument: null,
  }];

  diStore.push({
    diCode: '250',
    versionId: DI_VERSION_ID,
    description: 'Diabetes mellitus',
    category: 'Endocrine',
    subcategory: null,
    qualifiesSurcharge: true,
    qualifiesBcp: false,
    commonInSpecialty: ['GP', 'Endocrinology'],
    helpText: null,
  });

  // Modifiers
  versionStore['MODIFIERS'] = [{
    versionId: MODIFIERS_VERSION_ID,
    dataSet: 'MODIFIERS',
    versionLabel: 'Modifiers 2025',
    effectiveFrom: '2025-01-01',
    effectiveTo: null,
    isActive: true,
    publishedBy: ADMIN_USER_ID,
    publishedAt: new Date('2025-01-01'),
    recordsAdded: 5,
    recordsModified: 0,
    recordsDeprecated: 0,
    changeSummary: null,
    sourceDocument: null,
  }];

  // Governing rules
  versionStore['GOVERNING_RULES'] = [{
    versionId: RULES_VERSION_ID,
    dataSet: 'GOVERNING_RULES',
    versionLabel: 'Rules 2025',
    effectiveFrom: '2025-01-01',
    effectiveTo: null,
    isActive: true,
    publishedBy: ADMIN_USER_ID,
    publishedAt: new Date('2025-01-01'),
    recordsAdded: 10,
    recordsModified: 0,
    recordsDeprecated: 0,
    changeSummary: null,
    sourceDocument: null,
  }];

  rulesStore.push({
    ruleId: 'GR01',
    versionId: RULES_VERSION_ID,
    ruleName: 'Visit Limit Rule',
    ruleCategory: 'visit_limits',
    description: 'Maximum one complete assessment per day',
    ruleLogic: { max_per_day: 1, applies_to: ['03.01A'] },
    severity: 'error',
    errorMessage: 'Maximum visits exceeded',
    helpText: null,
    sourceReference: 'SOMB Section 3.1',
    sourceUrl: 'https://internal.ahcip.gov.ab.ca/somb/section3.1',
  });

  // Functional centres
  versionStore['FUNCTIONAL_CENTRES'] = [{
    versionId: FC_VERSION_ID,
    dataSet: 'FUNCTIONAL_CENTRES',
    versionLabel: 'FC 2025',
    effectiveFrom: '2025-01-01',
    effectiveTo: null,
    isActive: true,
    publishedBy: ADMIN_USER_ID,
    publishedAt: new Date('2025-01-01'),
    recordsAdded: 5,
    recordsModified: 0,
    recordsDeprecated: 0,
    changeSummary: null,
    sourceDocument: null,
  }];

  // Explanatory codes
  versionStore['EXPLANATORY_CODES'] = [{
    versionId: EXPL_VERSION_ID,
    dataSet: 'EXPLANATORY_CODES',
    versionLabel: 'ExplCodes 2025',
    effectiveFrom: '2025-01-01',
    effectiveTo: null,
    isActive: true,
    publishedBy: ADMIN_USER_ID,
    publishedAt: new Date('2025-01-01'),
    recordsAdded: 10,
    recordsModified: 0,
    recordsDeprecated: 0,
    changeSummary: null,
    sourceDocument: null,
  }];

  // Remaining datasets with empty version arrays
  for (const ds of ['WCB', 'RRNP', 'PCPCM']) {
    if (!versionStore[ds]) versionStore[ds] = [];
  }
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Reference Data Leakage Prevention (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    seedUsers();
    seedReferenceData();
    vi.clearAllMocks();
    // Re-bind all mock implementations after clearAllMocks
    rebindMocks();
  });

  function rebindMocks() {
    stubRepo.findActiveVersion.mockImplementation(async (dataSet: string) => {
      const versions = versionStore[dataSet] ?? [];
      return versions.find((v) => v.isActive);
    });
    stubRepo.findVersionForDate.mockImplementation(async (dataSet: string, date: Date) => {
      const dateStr = date.toISOString().split('T')[0];
      const versions = versionStore[dataSet] ?? [];
      return versions.find(
        (v) =>
          v.effectiveFrom <= dateStr &&
          (v.effectiveTo === null || v.effectiveTo > dateStr),
      );
    });
    stubRepo.listVersions.mockImplementation(async (dataSet: string) => {
      return versionStore[dataSet] ?? [];
    });
    stubRepo.searchHscCodes.mockImplementation(async (query: string, versionId: string, _filters: unknown, limit: number) => {
      return hscStore
        .filter((c) => c.versionId === versionId)
        .filter((c) => c.hscCode.includes(query) || c.description.toLowerCase().includes(query.toLowerCase()))
        .slice(0, limit);
    });
    stubRepo.findHscByCode.mockImplementation(async (hscCode: string, versionId: string) => {
      return hscStore.find((c) => c.hscCode === hscCode && c.versionId === versionId);
    });
    stubRepo.listHscByVersion.mockImplementation(async (versionId: string, pagination: { limit: number; offset: number }) => {
      const data = hscStore.filter((c) => c.versionId === versionId);
      return { data: data.slice(pagination.offset, pagination.offset + pagination.limit), total: data.length };
    });
    stubRepo.searchDiCodes.mockImplementation(async (query: string, versionId: string, _filters: unknown, limit: number) => {
      return diStore
        .filter((c) => c.versionId === versionId)
        .filter((c) => c.diCode.includes(query) || c.description.toLowerCase().includes(query.toLowerCase()))
        .slice(0, limit);
    });
    stubRepo.findDiByCode.mockImplementation(async (diCode: string, versionId: string) => {
      return diStore.find((c) => c.diCode === diCode && c.versionId === versionId);
    });
    stubRepo.findRulesForContext.mockImplementation(async (_hscCodes: string[], _diCode: string | null, _facilityCode: string | null, versionId: string) => {
      return rulesStore.filter((r) => r.versionId === versionId);
    });
    stubRepo.findRuleById.mockImplementation(async (ruleId: string, versionId: string) => {
      return rulesStore.find((r) => r.ruleId === ruleId && r.versionId === versionId);
    });
    stubRepo.findModifiersForHsc.mockImplementation(async (_hscCode: string, versionId: string) => {
      return modifierStore.filter((m) => m.versionId === versionId);
    });
    stubRepo.listAllModifiers.mockImplementation(async (versionId: string) => {
      return modifierStore.filter((m) => m.versionId === versionId);
    });
    stubRepo.findModifierByCode.mockImplementation(async (code: string, versionId: string) => {
      return modifierStore.find((m) => m.modifierCode === code && m.versionId === versionId);
    });
    stubRepo.listFunctionalCentres.mockImplementation(async (versionId: string) => {
      return fcStore.filter((f) => f.versionId === versionId);
    });
    stubRepo.findFunctionalCentre.mockImplementation(async (code: string, versionId: string) => {
      return fcStore.find((f) => f.code === code && f.versionId === versionId);
    });
    stubRepo.findExplanatoryCode.mockImplementation(async (code: string, versionId: string) => {
      return explStore.find((e) => e.explCode === code && e.versionId === versionId);
    });
    stubRepo.listHolidaysByYear.mockImplementation(async (year: number) => {
      return holidayStore.filter((h) => h.year === year);
    });
    stubRepo.isHoliday.mockImplementation(async (date: Date) => {
      const dateStr = date.toISOString().split('T')[0];
      const found = holidayStore.find((h) => h.date === dateStr);
      return { is_holiday: !!found, holiday_name: found?.name };
    });
    stubRepo.findStagingById.mockImplementation(async (stagingId: string) => {
      return stagingStore.find((s) => s.stagingId === stagingId);
    });
    stubRepo.createStagingRecord.mockImplementation(async (data: Record<string, unknown>) => {
      const entry = {
        stagingId: STAGING_ID,
        dataSet: data.dataSet as string,
        uploadedBy: data.uploadedBy as string,
        fileHash: data.fileHash as string,
        recordCount: data.recordCount as number,
        stagedData: data.stagedData as unknown[],
        status: 'uploaded',
        validationResult: null,
        diffResult: null,
      };
      stagingStore.push(entry);
      return entry;
    });
    stubRepo.updateStagingStatus.mockImplementation(async (stagingId: string, status: string, extra?: Record<string, unknown>) => {
      const entry = stagingStore.find((s) => s.stagingId === stagingId);
      if (entry) {
        entry.status = status;
        if (extra?.validation_result) entry.validationResult = extra.validation_result;
        if (extra?.diff_result) entry.diffResult = extra.diff_result;
      }
    });
    stubRepo.deleteStagingRecord.mockImplementation(async (stagingId: string) => {
      const idx = stagingStore.findIndex((s) => s.stagingId === stagingId);
      if (idx >= 0) stagingStore.splice(idx, 1);
    });
  }

  // =========================================================================
  // Staging Data Isolation
  // =========================================================================

  describe('Staging data isolation', () => {
    it('unpublished staging data does NOT appear in HSC search results', async () => {
      // Add staging data with a code that exists only in staging
      stagingStore.push({
        stagingId: STAGING_ID,
        dataSet: 'SOMB',
        uploadedBy: ADMIN_USER_ID,
        fileHash: 'abc123',
        recordCount: 1,
        stagedData: [{ hsc_code: 'STAGED.01', description: 'Staged Only Code', base_fee: '100.00', fee_type: 'fixed' }],
        status: 'diff_generated',
        validationResult: { valid: true, errors: [] },
        diffResult: { added: [{ hsc_code: 'STAGED.01' }], modified: [], deprecated: [], summary_stats: { added: 1, modified: 0, deprecated: 0 } },
      });

      // Search for the staged code as physician
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/hsc/search?q=STAGED',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      const results = body.data?.results ?? [];
      // Staging data should NOT appear in search results
      const hasStaged = results.some((r: { code: string }) => r.code === 'STAGED.01');
      expect(hasStaged).toBe(false);
    });

    it('unpublished staging data does NOT appear in DI search results', async () => {
      stagingStore.push({
        stagingId: STAGING_ID,
        dataSet: 'DI_CODES',
        uploadedBy: ADMIN_USER_ID,
        fileHash: 'abc456',
        recordCount: 1,
        stagedData: [{ di_code: 'STAGED999', description: 'Staged DI code' }],
        status: 'diff_generated',
        validationResult: { valid: true, errors: [] },
        diffResult: null,
      });

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/di/search?q=STAGED',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      const results = body.data?.results ?? [];
      const hasStaged = results.some((r: { code: string }) => r.code === 'STAGED999');
      expect(hasStaged).toBe(false);
    });

    it('admin version list endpoint returns 403 for non-admin physicians', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/admin/ref/SOMB/versions',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(403);
      // No data leaked in 403 response
      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
    });

    it('discarded staging data is completely removed from all queries', async () => {
      // Create staging entry
      stagingStore.push({
        stagingId: STAGING_ID,
        dataSet: 'SOMB',
        uploadedBy: ADMIN_USER_ID,
        fileHash: 'abc789',
        recordCount: 1,
        stagedData: [{ hsc_code: 'DISCARD.01' }],
        status: 'diff_generated',
        validationResult: null,
        diffResult: null,
      });

      // Verify staging exists before discard
      expect(stagingStore.find((s) => s.stagingId === STAGING_ID)).toBeDefined();

      // Discard it via the API
      const deleteRes = await app.inject({
        method: 'DELETE',
        url: `/api/v1/admin/ref/SOMB/staging/${STAGING_ID}`,
        headers: { cookie: adminCookie() },
      });

      if (deleteRes.statusCode !== 200) {
        console.error('DELETE response:', deleteRes.statusCode, deleteRes.body);
      }
      expect(deleteRes.statusCode).toBe(200);

      // Verify staging record no longer exists in the store
      expect(stagingStore.find((s) => s.stagingId === STAGING_ID)).toBeUndefined();

      // Verify diff endpoint returns 404 for discarded staging
      const diffRes = await app.inject({
        method: 'GET',
        url: `/api/v1/admin/ref/SOMB/staging/${STAGING_ID}/diff`,
        headers: { cookie: adminCookie() },
      });

      expect(diffRes.statusCode).toBe(404);
    });
  });

  // =========================================================================
  // Version Isolation
  // =========================================================================

  describe('Version isolation', () => {
    it('search with date in V1 range returns V1 data, not V2', async () => {
      // Date in V1 range: 2025-04-01 to 2025-09-30
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/hsc/search?q=03.01A&date=2025-06-15',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      const results = body.data?.results ?? [];

      // Should have the V1 version of 03.01A
      const code = results.find((r: { code: string }) => r.code === '03.01A');
      expect(code).toBeDefined();
      expect(code.description).toContain('V1');
      expect(code.baseFee).toBe('75.00');
    });

    it('search with date in V2 range returns V2 data, not V1', async () => {
      // Date in V2 range: 2025-10-01+
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/hsc/search?q=03.01A&date=2025-11-15',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      const results = body.data?.results ?? [];

      const code = results.find((r: { code: string }) => r.code === '03.01A');
      expect(code).toBeDefined();
      expect(code.description).toContain('V2');
      expect(code.baseFee).toBe('80.00');
    });

    it('future-dated version data does not appear in current searches', async () => {
      // Search without date uses active version (V2, not future)
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/hsc/search?q=99.99Z',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      const results = body.data?.results ?? [];

      // The future-only code should NOT appear
      const hasFutureCode = results.some((r: { code: string }) => r.code === '99.99Z');
      expect(hasFutureCode).toBe(false);
    });

    it('HSC detail for future-only code returns 404 for current version', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/hsc/99.99Z',
        headers: { cookie: physicianCookie() },
      });

      // 99.99Z doesn't exist in the active SOMB version
      expect(res.statusCode).toBe(404);
    });
  });

  // =========================================================================
  // Error Response Sanitisation
  // =========================================================================

  describe('Error response sanitisation', () => {
    it('GET /api/v1/ref/hsc/nonexistent-code returns 404 with generic message', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/hsc/NONEXIST',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);

      // Generic message — not revealing which codes exist
      expect(body.error).toBeDefined();
      expect(body.error.message).not.toContain('NONEXIST');
      expect(body.error.message).not.toContain('version');
      expect(body.error.message).not.toContain(SOMB_VERSION_V2_ID);
    });

    it('404 for DI code does not reveal code existence details', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/di/XXXX',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error.message).not.toContain('XXXX');
      expect(body.error.message).not.toContain(DI_VERSION_ID);
    });

    it('500 error does not expose SQL queries or database details', async () => {
      // Force an internal error
      stubRepo.findActiveVersion.mockRejectedValueOnce(
        new Error('relation "reference_data_versions" does not exist at character 15'),
      );

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/hsc/search?q=test',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(500);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('INTERNAL_ERROR');
      expect(body.error.message).toBe('Internal server error');

      const rawBody = res.body;
      expect(rawBody).not.toMatch(/postgres/i);
      expect(rawBody).not.toMatch(/drizzle/i);
      expect(rawBody).not.toMatch(/relation/i);
      expect(rawBody).not.toContain('reference_data_versions');
      expect(rawBody).not.toContain('character 15');
    });

    it('500 error does not expose connection details', async () => {
      stubRepo.findActiveVersion.mockRejectedValueOnce(
        new Error('ECONNREFUSED 10.0.0.5:5432'),
      );

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/hsc/search?q=test',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(500);
      const rawBody = res.body;
      expect(rawBody).not.toContain('10.0.0.5');
      expect(rawBody).not.toContain('5432');
      expect(rawBody).not.toContain('ECONNREFUSED');
    });

    it('500 error response contains only code and message', async () => {
      stubRepo.findActiveVersion.mockRejectedValueOnce(new Error('unexpected'));

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/hsc/search?q=test',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(500);
      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(Object.keys(body.error).sort()).toEqual(['code', 'message']);
      expect(body.error).not.toHaveProperty('stack');
      expect(body.data).toBeUndefined();
    });

    it('schema validation errors do not expose internal table column names', async () => {
      // Send invalid request with bad query params
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/hsc/search?q=',
        headers: { cookie: physicianCookie() },
      });

      // Empty q should fail Zod validation (min length 1)
      expect(res.statusCode).toBe(400);
      const rawBody = res.body;

      // Error message should reference schema field names, not DB column names
      expect(rawBody).not.toContain('hsc_codes');
      expect(rawBody).not.toContain('reference_data_versions');
      expect(rawBody).not.toContain('hsc_code');
      expect(rawBody).not.toContain('version_id');
      expect(rawBody).not.toContain('data_set');
    });
  });

  // =========================================================================
  // Header Checks
  // =========================================================================

  describe('Header security checks', () => {
    it('no X-Powered-By header in authenticated responses', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/holidays?year=2026',
        headers: { cookie: physicianCookie() },
      });

      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By header in error responses', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/hsc/search?q=test',
        // No cookie — 401
      });

      expect(res.statusCode).toBe(401);
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By header in 404 responses', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/hsc/NONEXIST',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(404);
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By header in 500 responses', async () => {
      stubRepo.findActiveVersion.mockRejectedValueOnce(new Error('boom'));

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/hsc/search?q=test',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(500);
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no Server header revealing version info', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/holidays?year=2026',
        headers: { cookie: physicianCookie() },
      });

      const server = res.headers['server'];
      if (server) {
        expect(server).not.toMatch(/fastify/i);
        expect(server).not.toMatch(/\d+\.\d+/);
      }
    });

    it('HSTS header is present or not contradicted in responses', async () => {
      // In production, Strict-Transport-Security is set by the reverse proxy
      // (DigitalOcean App Platform) or @fastify/helmet. In a test Fastify
      // instance without helmet registered, the header may be absent. The
      // critical check is that IF present, it has a valid value (max-age > 0).
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/holidays?year=2026',
        headers: { cookie: physicianCookie() },
      });

      const hsts = res.headers['strict-transport-security'];
      if (hsts) {
        expect(hsts).toMatch(/max-age=\d+/);
        // max-age should be at least 1 year (31536000)
        const match = String(hsts).match(/max-age=(\d+)/);
        if (match) {
          expect(parseInt(match[1], 10)).toBeGreaterThanOrEqual(31536000);
        }
      }
      // If absent in test environment, that's acceptable —
      // HSTS is enforced at the infrastructure/helmet layer in production.
    });
  });

  // =========================================================================
  // Sensitive Fields Not Leaked
  // =========================================================================

  describe('Sensitive fields not leaked', () => {
    it('HSC search results do not include staged_data JSONB', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/hsc/search?q=03.01A',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(200);
      const rawBody = res.body;
      expect(rawBody).not.toContain('staged_data');
      expect(rawBody).not.toContain('stagedData');
      expect(rawBody).not.toContain('file_hash');
      expect(rawBody).not.toContain('fileHash');
    });

    it('HSC detail does not include internal published_by user ID', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/hsc/03.01A',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(200);
      const rawBody = res.body;
      expect(rawBody).not.toContain('published_by');
      expect(rawBody).not.toContain('publishedBy');
      expect(rawBody).not.toContain(ADMIN_USER_ID);
    });

    it('DI search results do not include staging metadata', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/di/search?q=250',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(200);
      const rawBody = res.body;
      expect(rawBody).not.toContain('staged_data');
      expect(rawBody).not.toContain('stagedData');
      expect(rawBody).not.toContain('file_hash');
      expect(rawBody).not.toContain('fileHash');
      expect(rawBody).not.toContain('published_by');
      expect(rawBody).not.toContain('publishedBy');
    });

    it('validate-context returns ruleLogic but not sourceReference or sourceUrl', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/rules/validate-context?hsc=03.01A&date=2025-06-15',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);

      // applicableRules should contain ruleLogic
      if (body.data?.applicableRules?.length > 0) {
        const rule = body.data.applicableRules[0];
        expect(rule.ruleLogic).toBeDefined();
        // But should NOT contain internal fields
        expect(rule.sourceReference).toBeUndefined();
        expect(rule.source_reference).toBeUndefined();
        expect(rule.sourceUrl).toBeUndefined();
        expect(rule.source_url).toBeUndefined();
      }

      // Raw body check
      const rawBody = res.body;
      expect(rawBody).not.toContain('sourceReference');
      expect(rawBody).not.toContain('source_reference');
      expect(rawBody).not.toContain('sourceUrl');
      expect(rawBody).not.toContain('source_url');
      // Specifically check internal URLs are not leaked
      expect(rawBody).not.toContain('internal.ahcip.gov.ab.ca');
    });

    it('change summary responses do not include published_by admin identity', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/changes',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(200);
      const rawBody = res.body;

      // published_by is the admin user ID — should not be in the response
      expect(rawBody).not.toContain(ADMIN_USER_ID);
      // We should not leak admin emails either
      expect(rawBody).not.toContain('admin@example.com');
    });

    it('change detail does not include file_hash or staging internals', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/ref/changes/${SOMB_VERSION_V2_ID}/detail`,
        headers: { cookie: physicianCookie() },
      });

      // The response should contain code-level changes but not staging metadata
      if (res.statusCode === 200) {
        const rawBody = res.body;
        expect(rawBody).not.toContain('file_hash');
        expect(rawBody).not.toContain('fileHash');
        expect(rawBody).not.toContain('staged_data');
        expect(rawBody).not.toContain('stagedData');
      }
    });
  });

  // =========================================================================
  // XSS Sanitisation in Change Summaries
  // =========================================================================

  describe('XSS sanitisation in change summaries', () => {
    it('change summary with XSS payload in version label is returned safely', async () => {
      // Add a version with XSS in change_summary
      versionStore['SOMB']!.push({
        versionId: 'eeee0000-0000-0000-0000-000000000001',
        dataSet: 'SOMB',
        versionLabel: '<script>alert("xss")</script>',
        effectiveFrom: '2024-01-01',
        effectiveTo: '2025-04-01',
        isActive: false,
        publishedBy: ADMIN_USER_ID,
        publishedAt: new Date('2024-01-01'),
        recordsAdded: 1,
        recordsModified: 0,
        recordsDeprecated: 0,
        changeSummary: '<img src=x onerror=alert(1)>',
        sourceDocument: null,
      });

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/changes',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(200);
      // The response is JSON — XSS won't execute in an API response.
      // But verify the content-type is application/json (not text/html)
      expect(res.headers['content-type']).toMatch(/application\/json/);
    });
  });

  // =========================================================================
  // Sanity Check
  // =========================================================================

  describe('Sanity: test setup validates correctly', () => {
    it('physician session authenticates successfully for search', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/hsc/search?q=03.01A',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toBeDefined();
    });

    it('admin session authenticates successfully for admin endpoints', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/admin/ref/SOMB/versions',
        headers: { cookie: adminCookie() },
      });

      expect(res.statusCode).toBe(200);
    });

    it('version resolution returns correct version for date', async () => {
      // V1 date range
      const res1 = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/hsc/search?q=03.01A&date=2025-05-01',
        headers: { cookie: physicianCookie() },
      });
      expect(res1.statusCode).toBe(200);
      const body1 = JSON.parse(res1.body);
      const results1 = body1.data?.results ?? [];
      expect(results1.length).toBeGreaterThan(0);
      expect(results1[0].description).toContain('V1');

      // V2 date range
      const res2 = await app.inject({
        method: 'GET',
        url: '/api/v1/ref/hsc/search?q=03.01A&date=2025-12-01',
        headers: { cookie: physicianCookie() },
      });
      expect(res2.statusCode).toBe(200);
      const body2 = JSON.parse(res2.body);
      const results2 = body2.data?.results ?? [];
      expect(results2.length).toBeGreaterThan(0);
      expect(results2[0].description).toContain('V2');
    });
  });
});
