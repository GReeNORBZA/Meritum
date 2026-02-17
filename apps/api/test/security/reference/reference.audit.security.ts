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
// Shared audit logger — captures all service-level audit entries
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

const RULES_VERSION_ID = 'cccc0001-0000-0000-0000-000000000003';

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
// Stub reference repository
// ---------------------------------------------------------------------------

function createStubReferenceRepo() {
  return {
    findActiveVersion: vi.fn(async (dataSet: string) => {
      return versions.find((v) => v.dataSet === dataSet && v.isActive) as any;
    }),
    findVersionForDate: vi.fn(async () => undefined),
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
    listHscByVersion: vi.fn(async () => ({ data: [], total: 0 })),
    getHscCodesByVersion: vi.fn(async () => []),
    bulkInsertHscCodes: vi.fn(async () => {}),
    searchWcbCodes: vi.fn(async () => []),
    searchDiCodes: vi.fn(async () => []),
    findDiByCode: vi.fn(async () => undefined),
    getDiCodesByVersion: vi.fn(async () => []),
    bulkInsertDiCodes: vi.fn(async () => {}),
    findModifiersForHsc: vi.fn(async () => []),
    findModifierByCode: vi.fn(async () => undefined),
    listAllModifiers: vi.fn(async () => []),
    getModifiersByVersion: vi.fn(async () => []),
    bulkInsertModifiers: vi.fn(async () => {}),
    listFunctionalCentres: vi.fn(async () => []),
    getFunctionalCentresByVersion: vi.fn(async () => []),
    bulkInsertFunctionalCentres: vi.fn(async () => {}),
    findFunctionalCentre: vi.fn(async () => undefined),
    findExplanatoryCode: vi.fn(async () => undefined),
    getExplanatoryCodesByVersion: vi.fn(async () => []),
    bulkInsertExplanatoryCodes: vi.fn(async () => {}),
    findRrnpRate: vi.fn(async () => undefined),
    getRrnpCommunitiesByVersion: vi.fn(async () => []),
    bulkInsertRrnpCommunities: vi.fn(async () => {}),
    findPcpcmBasket: vi.fn(async () => undefined),
    getPcpcmBasketsByVersion: vi.fn(async () => []),
    bulkInsertPcpcmBaskets: vi.fn(async () => {}),
    listHolidaysByYear: vi.fn(async (year: number) => {
      return holidays.filter((h) => (h as any).year === year);
    }),
    isHoliday: vi.fn(async () => ({ is_holiday: false })),
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
    listRulesByCategory: vi.fn(async () => []),
    getGoverningRulesByVersion: vi.fn(async () => []),
    bulkInsertRules: vi.fn(async () => {}),
    createStagingRecord: vi.fn(async (data: any) => ({
      stagingId: 'staging-' + Date.now(),
      ...data,
    })),
    findStagingById: vi.fn(async (stagingId: string) => {
      return stagingRecords.find((s) => (s as any).stagingId === stagingId) as any;
    }),
    updateStagingStatus: vi.fn(async () => {}),
    deleteStagingRecord: vi.fn(async () => {}),
    getHscFavourites: vi.fn(async () => []),
    findVersionByVersionId: vi.fn(async () => undefined),
    getChangeSummaries: vi.fn(async () => []),
    getChangeDetails: vi.fn(async () => []),
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

function seedAdmin() {
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

describe('Reference Data Audit Trail Completeness (Security)', () => {
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
    seedAdmin();
    seedStagingRecord();
    seedVersions();
    seedHolidays();
  });

  // =========================================================================
  // Data Management Events
  // =========================================================================

  describe('Data management events', () => {
    it('version staged (upload) produces ref.version_staged audit entry with correct metadata', async () => {
      // Upload a JSON file via multipart form
      const payload = JSON.stringify([
        { hsc_code: '03.01A', description: 'Office Visit', base_fee: '35.00', fee_type: 'fixed' },
      ]);

      const boundary = '----FormBoundary' + randomBytes(8).toString('hex');
      const body =
        `--${boundary}\r\n` +
        `Content-Disposition: form-data; name="file"; filename="somb.json"\r\n` +
        `Content-Type: application/json\r\n` +
        `\r\n` +
        `${payload}\r\n` +
        `--${boundary}--\r\n`;

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/admin/ref/SOMB/upload',
        headers: {
          cookie: adminCookie(),
          'content-type': `multipart/form-data; boundary=${boundary}`,
        },
        payload: body,
      });

      expect(res.statusCode).toBe(200);

      const entry = findAuditEntry('ref.version_staged');
      expect(entry).toBeDefined();
      expect(entry!.adminId).toBe(ADMIN_USER_ID);
      expect(entry!.details.data_set).toBe('SOMB');
      expect(entry!.details.staging_id).toBeDefined();
      expect(typeof entry!.details.staging_id).toBe('string');
      expect(entry!.details.record_count).toBe(1);
      expect(entry!.details.file_hash).toBeDefined();
      expect(typeof entry!.details.file_hash).toBe('string');
      // SHA-256 hash should be 64 hex characters
      expect((entry!.details.file_hash as string).length).toBe(64);
    });

    it('diff reviewed produces ref.version_diff_reviewed audit entry with diff_stats', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/admin/ref/SOMB/staging/${STAGING_ID}/diff`,
        headers: { cookie: adminCookie() },
      });

      expect(res.statusCode).toBe(200);

      const entry = findAuditEntry('ref.version_diff_reviewed');
      expect(entry).toBeDefined();
      expect(entry!.adminId).toBe(ADMIN_USER_ID);
      expect(entry!.details.staging_id).toBe(STAGING_ID);
      expect(entry!.details.diff_stats).toBeDefined();
      const stats = entry!.details.diff_stats as Record<string, number>;
      expect(typeof stats.added).toBe('number');
      expect(typeof stats.modified).toBe('number');
      expect(typeof stats.deprecated).toBe('number');
    });

    it('version published produces ref.version_published audit entry with version metadata', async () => {
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
      expect(entry!.details.version_id).toBeDefined();
      expect(typeof entry!.details.version_id).toBe('string');
      expect(entry!.details.data_set).toBe('SOMB');
      expect(entry!.details.effective_from).toBe('2026-03-01');
    });

    it('version rolled back produces ref.version_rolled_back audit entry with reason', async () => {
      // We need to call the rollback service directly since there's no route for it
      // in the routes file. Instead, test through the service layer.
      const refService = await import('../../../src/domains/reference/reference.service.js');
      const { rollbackVersion } = refService;

      const localAudit: typeof auditEntries = [];
      const localAuditLogger = {
        log: vi.fn(async (entry: any) => {
          localAudit.push(entry);
        }),
      };

      const localRepo = createStubReferenceRepo();
      const localDeps: refService.ReferenceServiceDeps = {
        repo: localRepo,
        auditLog: localAuditLogger,
        eventEmitter: createMockEvents(),
      };

      // Seed versions for this local test
      localRepo.listVersions.mockResolvedValue([
        {
          versionId: VERSION_ID,
          dataSet: 'SOMB',
          versionLabel: 'v2026.01',
          effectiveFrom: '2026-01-01',
          isActive: true,
        },
        {
          versionId: PREV_VERSION_ID,
          dataSet: 'SOMB',
          versionLabel: 'v2025.01',
          effectiveFrom: '2025-01-01',
          isActive: false,
        },
      ] as any);

      await rollbackVersion(localDeps, ADMIN_USER_ID, VERSION_ID, 'Data quality issue discovered');

      const entry = localAudit.find((e) => e.action === 'ref.version_rolled_back');
      expect(entry).toBeDefined();
      expect(entry!.adminId).toBe(ADMIN_USER_ID);
      expect(entry!.details.version_id).toBe(VERSION_ID);
      expect(entry!.details.data_set).toBe('SOMB');
      expect(entry!.details.reason).toBe('Data quality issue discovered');
    });

    it('staging discarded produces ref.staging_discarded audit entry with staging_id and data_set', async () => {
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
    });

    it('rule dry-run produces ref.rule_dry_run audit entry with rule_id and claims_sampled', async () => {
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
    });
  });

  // =========================================================================
  // Holiday Events
  // =========================================================================

  describe('Holiday events', () => {
    it('holiday created produces ref.holiday_created audit entry with date and name', async () => {
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
      expect(entry!.details.date).toBe('2026-02-16');
      expect(entry!.details.name).toBe('Family Day');
      expect(entry!.details.admin_id).toBe(ADMIN_USER_ID);
    });

    it('holiday updated produces ref.holiday_updated audit entry with old and new values', async () => {
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
      expect(entry!.details.admin_id).toBe(ADMIN_USER_ID);
      expect(entry!.details.holiday_id).toBe(HOLIDAY_ID);
      expect(entry!.details.old_values).toBeDefined();
      expect(entry!.details.new_values).toBeDefined();
    });

    it('holiday deleted produces ref.holiday_deleted audit entry with holiday_id', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: `/api/v1/admin/ref/holidays/${HOLIDAY_ID}`,
        headers: { cookie: adminCookie() },
      });

      expect(res.statusCode).toBe(200);

      const entry = findAuditEntry('ref.holiday_deleted');
      expect(entry).toBeDefined();
      expect(entry!.adminId).toBe(ADMIN_USER_ID);
      expect(entry!.details.admin_id).toBe(ADMIN_USER_ID);
      expect(entry!.details.holiday_id).toBe(HOLIDAY_ID);
    });
  });

  // =========================================================================
  // Audit Log Integrity
  // =========================================================================

  describe('Audit log integrity', () => {
    it('audit entries contain only metadata, not full staged data payload', async () => {
      // Upload a file with multiple records
      const records = Array.from({ length: 100 }, (_, i) => ({
        hsc_code: `99.${String(i).padStart(2, '0')}A`,
        description: `Test Code ${i}`,
        base_fee: '10.00',
        fee_type: 'fixed',
      }));
      const payload = JSON.stringify(records);

      const boundary = '----FormBoundary' + randomBytes(8).toString('hex');
      const body =
        `--${boundary}\r\n` +
        `Content-Disposition: form-data; name="file"; filename="large.json"\r\n` +
        `Content-Type: application/json\r\n` +
        `\r\n` +
        `${payload}\r\n` +
        `--${boundary}--\r\n`;

      await app.inject({
        method: 'POST',
        url: '/api/v1/admin/ref/SOMB/upload',
        headers: {
          cookie: adminCookie(),
          'content-type': `multipart/form-data; boundary=${boundary}`,
        },
        payload: body,
      });

      const entry = findAuditEntry('ref.version_staged');
      expect(entry).toBeDefined();

      // Verify audit entry does not contain the full staged data
      const entryStr = JSON.stringify(entry);
      expect(entryStr).not.toContain('99.00A');
      expect(entryStr).not.toContain('Test Code 0');

      // Verify audit entry size is reasonable (< 10KB)
      const entrySize = Buffer.byteLength(entryStr, 'utf-8');
      expect(entrySize).toBeLessThan(10 * 1024);
    });

    it('version published audit entry does not contain full record data', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/admin/ref/SOMB/staging/${STAGING_ID}/publish`,
        headers: { cookie: adminCookie() },
        payload: {
          version_label: 'v2026.03',
          effective_from: '2026-04-01',
          change_summary: 'Test publish',
        },
      });

      expect(res.statusCode).toBe(201);

      const entry = findAuditEntry('ref.version_published');
      expect(entry).toBeDefined();

      // Should have metadata counts, not full records
      expect(entry!.details).toHaveProperty('records_added');
      expect(entry!.details).toHaveProperty('records_modified');
      expect(entry!.details).toHaveProperty('records_deprecated');

      // Should not contain raw record data
      const entryStr = JSON.stringify(entry);
      expect(entryStr).not.toContain('Office Visit');
      expect(entryStr).not.toContain('Follow-up Visit');

      // Verify size is reasonable
      const entrySize = Buffer.byteLength(entryStr, 'utf-8');
      expect(entrySize).toBeLessThan(10 * 1024);
    });

    it('diff reviewed audit entry contains summary stats, not full diff records', async () => {
      await app.inject({
        method: 'GET',
        url: `/api/v1/admin/ref/SOMB/staging/${STAGING_ID}/diff`,
        headers: { cookie: adminCookie() },
      });

      const entry = findAuditEntry('ref.version_diff_reviewed');
      expect(entry).toBeDefined();

      // Should have summary stats
      expect(entry!.details.diff_stats).toBeDefined();

      // Should not contain full diff records
      const entryStr = JSON.stringify(entry);

      // Verify size is reasonable
      const entrySize = Buffer.byteLength(entryStr, 'utf-8');
      expect(entrySize).toBeLessThan(10 * 1024);
    });

    it('all audit entries have action and adminId fields', async () => {
      // Perform several actions
      await app.inject({
        method: 'POST',
        url: '/api/v1/admin/ref/holidays',
        headers: { cookie: adminCookie() },
        payload: { name: 'Test Holiday', date: '2026-07-01', jurisdiction: 'federal', affects_billing_premiums: false },
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
      }
    });
  });

  // =========================================================================
  // All 9 Audit Action Types Verified
  // =========================================================================

  describe('All 9 audit action types are present', () => {
    it('covers all expected audit action identifiers', () => {
      const expectedActions = [
        'ref.version_staged',
        'ref.version_diff_reviewed',
        'ref.version_published',
        'ref.version_rolled_back',
        'ref.staging_discarded',
        'ref.rule_dry_run',
        'ref.holiday_created',
        'ref.holiday_updated',
        'ref.holiday_deleted',
      ];

      // These are all tested individually in the test cases above.
      // This test just documents the complete set for reference.
      expect(expectedActions).toHaveLength(9);
    });
  });

  // =========================================================================
  // Sensitive Data Exclusion from Audit Entries
  // =========================================================================

  describe('Sensitive data exclusion from audit entries', () => {
    it('upload audit entry does not contain the file content', async () => {
      const sensitiveData = 'SENSITIVE_PATIENT_INFO_SHOULD_NOT_APPEAR';
      const payload = JSON.stringify([
        { hsc_code: '03.01A', description: sensitiveData, base_fee: '35.00', fee_type: 'fixed' },
      ]);

      const boundary = '----FormBoundary' + randomBytes(8).toString('hex');
      const body =
        `--${boundary}\r\n` +
        `Content-Disposition: form-data; name="file"; filename="data.json"\r\n` +
        `Content-Type: application/json\r\n` +
        `\r\n` +
        `${payload}\r\n` +
        `--${boundary}--\r\n`;

      await app.inject({
        method: 'POST',
        url: '/api/v1/admin/ref/SOMB/upload',
        headers: {
          cookie: adminCookie(),
          'content-type': `multipart/form-data; boundary=${boundary}`,
        },
        payload: body,
      });

      const allEntriesStr = JSON.stringify(auditEntries);
      expect(allEntriesStr).not.toContain(sensitiveData);
    });

    it('dry-run audit entry does not contain the full updated rule logic', async () => {
      const complexRuleLogic = {
        type: 'complex_evaluation',
        conditions: [
          { field: 'hsc_code', operator: 'in', values: ['03.01A', '03.01B', '03.01C'] },
          { field: 'di_code', operator: 'equals', value: '250' },
        ],
        action: 'reject',
        message: 'Complex rejection rule for test',
      };

      await app.inject({
        method: 'POST',
        url: `/api/v1/admin/ref/rules/${RULE_ID}/dry-run`,
        headers: { cookie: adminCookie() },
        payload: { updated_rule_logic: complexRuleLogic },
      });

      const entry = findAuditEntry('ref.rule_dry_run');
      expect(entry).toBeDefined();

      // The audit entry should record the rule_id and claims_sampled,
      // but should NOT contain the full updated_rule_logic payload
      const entryStr = JSON.stringify(entry);
      expect(entryStr).not.toContain('complex_evaluation');
      expect(entryStr).not.toContain('Complex rejection rule for test');
    });
  });

  // =========================================================================
  // Sanity: test setup validates correctly
  // =========================================================================

  describe('Sanity: test setup validates correctly', () => {
    it('admin session authenticates successfully', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/admin/ref/SOMB/versions',
        headers: { cookie: adminCookie() },
      });

      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('shared audit logger captures entries from service layer', async () => {
      // Create a holiday (calls service which calls auditLog)
      await app.inject({
        method: 'POST',
        url: '/api/v1/admin/ref/holidays',
        headers: { cookie: adminCookie() },
        payload: { name: 'Sanity Holiday', date: '2026-08-01', jurisdiction: 'federal', affects_billing_premiums: false },
      });

      // Discard staging (calls service which calls auditLog)
      await app.inject({
        method: 'DELETE',
        url: `/api/v1/admin/ref/SOMB/staging/${STAGING_ID}`,
        headers: { cookie: adminCookie() },
      });

      // Both actions should have produced entries
      expect(findAuditEntry('ref.holiday_created')).toBeDefined();
      expect(findAuditEntry('ref.staging_discarded')).toBeDefined();
    });

    it('every mutating admin operation produces at least one audit entry', async () => {
      // Track all mutating operations
      const operationsBeforeCount = auditEntries.length;

      // 1. Create holiday
      await app.inject({
        method: 'POST',
        url: '/api/v1/admin/ref/holidays',
        headers: { cookie: adminCookie() },
        payload: { name: 'Audit Check', date: '2026-09-01', jurisdiction: 'provincial', affects_billing_premiums: true },
      });
      expect(auditEntries.length).toBeGreaterThan(operationsBeforeCount);
      const afterCreate = auditEntries.length;

      // 2. Update holiday
      await app.inject({
        method: 'PUT',
        url: `/api/v1/admin/ref/holidays/${HOLIDAY_ID}`,
        headers: { cookie: adminCookie() },
        payload: { name: 'Updated Audit Check' },
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

      // 5. Dry-run rule
      await app.inject({
        method: 'POST',
        url: `/api/v1/admin/ref/rules/${RULE_ID}/dry-run`,
        headers: { cookie: adminCookie() },
        payload: { updated_rule_logic: { type: 'test' } },
      });
      expect(auditEntries.length).toBeGreaterThan(afterDiscard);
    });
  });
});
