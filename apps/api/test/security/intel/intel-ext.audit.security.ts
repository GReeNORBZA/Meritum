// ============================================================================
// Domain 7: Intelligence Extensions — Audit Trail Verification (Security)
// Verifies rule management audit entries, cohort recalculation audit,
// SOMB analysis audit, and rule activation/deactivation audit via mock deps.
// ============================================================================

import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { createHash, randomBytes } from 'node:crypto';

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
// Imports (after mocks)
// ---------------------------------------------------------------------------

import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { intelRoutes } from '../../../src/domains/intel/intel.routes.js';
import { type IntelHandlerDeps } from '../../../src/domains/intel/intel.handlers.js';
import { type AnalyseDeps, type LifecycleDeps, type LearningLoopDeps, type SombChangeDeps } from '../../../src/domains/intel/intel.service.js';
import type { IntelRepository } from '../../../src/domains/intel/intel.repository.js';

// ---------------------------------------------------------------------------
// Helper: hashToken (same SHA-256 used by auth plugin)
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

const ADMIN_TOKEN = randomBytes(32).toString('hex');
const ADMIN_TOKEN_HASH = hashToken(ADMIN_TOKEN);
const ADMIN_USER_ID = 'aaaa0000-0000-0000-0000-000000000099';
const ADMIN_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000099';

const DUMMY_UUID = '00000000-0000-0000-0000-000000000001';
const DUMMY_RULE_ID = '33330000-0000-0000-0000-000000000001';

// ---------------------------------------------------------------------------
// Mock stores
// ---------------------------------------------------------------------------

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

interface MockUser {
  userId: string;
  role: string;
  subscriptionStatus: string;
}

let sessions: MockSession[] = [];
let users: MockUser[] = [];

// ---------------------------------------------------------------------------
// Mock session repository (consumed by auth plugin)
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    createSession: vi.fn(async () => ({ sessionId: 'new-session' })),
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

// ---------------------------------------------------------------------------
// Tracked audit log calls
// ---------------------------------------------------------------------------

interface AuditLogEntry {
  action: string;
  providerId: string;
  details: Record<string, unknown>;
}

let auditLogCalls: AuditLogEntry[] = [];

// ---------------------------------------------------------------------------
// Create handler deps with audit tracking
// ---------------------------------------------------------------------------

function createAuditTrackedIntelHandlerDeps(): IntelHandlerDeps {
  const stubAnalyseDeps: AnalyseDeps = {
    claimContextDeps: {
      getClaim: vi.fn(async () => null),
      getAhcipDetails: vi.fn(async () => null),
      getWcbDetails: vi.fn(async () => null),
      getPatientDemographics: vi.fn(async () => null),
      getProvider: vi.fn(async () => null),
      getDefaultLocation: vi.fn(async () => null),
      getHscCode: vi.fn(async () => null),
      getModifierDefinitions: vi.fn(async () => []),
      getDiCode: vi.fn(async () => null),
      getReferenceSet: vi.fn(async () => []),
      getCrossClaimCount: vi.fn(async () => 0),
      getCrossClaimSum: vi.fn(async () => 0),
      getCrossClaimExists: vi.fn(async () => false),
    },
    tier1Deps: {
      getActiveRulesForClaim: vi.fn(async () => []),
      getProviderLearningForRules: vi.fn(async () => []),
      incrementShown: vi.fn(async () => ({})),
      appendSuggestionEvent: vi.fn(async () => ({})),
    },
    tier2Deps: {
      buildPrompt: vi.fn(),
      callLlm: vi.fn(),
      parseResponse: vi.fn(),
      appendSuggestionEvent: vi.fn(),
    },
    storeSuggestions: vi.fn(),
    notifyTier2Complete: vi.fn(),
  } as unknown as AnalyseDeps;

  const stubLifecycleDeps: LifecycleDeps = {
    getClaimSuggestions: vi.fn(async () => []),
    updateClaimSuggestions: vi.fn(async () => {}),
    applyClaimChanges: vi.fn(async () => {}),
    revalidateClaim: vi.fn(async () => {}),
    appendSuggestionEvent: vi.fn(async () => ({})),
    recordAcceptance: vi.fn(async () => ({})),
    recordDismissal: vi.fn(async () => ({})),
  };

  const stubLearningLoopDeps: LearningLoopDeps = {
    getProviderLearning: vi.fn(async () => null),
    unsuppressRule: vi.fn(async () => null),
    processRejection: vi.fn(async () => ({ processedRuleIds: [] })),
    recalculateAllCohorts: vi.fn(async () => [
      {
        cohortId: 'cohort-1',
        specialtyCode: '00',
        ruleId: DUMMY_RULE_ID,
        physicianCount: 15,
        acceptanceRate: '0.7500',
        medianRevenueImpact: '22.50',
        updatedAt: new Date(),
      },
    ]),
    deleteSmallCohorts: vi.fn(async () => 2),
  } as unknown as LearningLoopDeps;

  const stubSombChangeDeps: SombChangeDeps = {
    getRulesByVersion: vi.fn(async () => []),
    getAffectedProviders: vi.fn(async () => []),
    generateImpactReport: vi.fn(async () => ({
      totalAffectedPhysicians: 5,
      totalAffectedRules: 3,
      impactDetails: [],
    })),
  };

  const stubRepo: IntelRepository = {
    listRules: vi.fn(async () => ({
      data: [],
      pagination: { total: 0, page: 1, pageSize: 20, hasMore: false },
    })),
    getRule: vi.fn(async (id: string) => ({
      ruleId: id,
      name: 'Test Rule',
      category: 'MODIFIER_ADD',
      claimType: 'AHCIP',
      conditions: { type: 'existence', field: 'ahcip.modifier1', operator: 'IS NULL' },
      suggestionTemplate: { title: 'Test', description: 'Test desc', source_reference: 'SOMB' },
      specialtyFilter: null,
      priorityFormula: 'fixed:MEDIUM',
      sombVersion: null,
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    })),
    createRule: vi.fn(async (data: any) => ({
      ruleId: DUMMY_RULE_ID,
      ...data,
      createdAt: new Date(),
      updatedAt: new Date(),
    })),
    updateRule: vi.fn(async (id: string, data: any) => ({
      ruleId: id,
      name: data.name ?? 'Test Rule',
      category: data.category ?? 'MODIFIER_ADD',
      claimType: data.claimType ?? 'AHCIP',
      conditions: data.conditions ?? {},
      suggestionTemplate: data.suggestionTemplate ?? {},
      specialtyFilter: null,
      priorityFormula: 'fixed:MEDIUM',
      sombVersion: null,
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    })),
    activateRule: vi.fn(async (id: string, isActive: boolean) => ({
      ruleId: id,
      name: 'Test Rule',
      category: 'MODIFIER_ADD',
      claimType: 'AHCIP',
      conditions: {},
      suggestionTemplate: {},
      specialtyFilter: null,
      priorityFormula: 'fixed:MEDIUM',
      sombVersion: null,
      isActive,
      createdAt: new Date(),
      updatedAt: new Date(),
    })),
    getRuleStats: vi.fn(async () => ({
      ruleId: DUMMY_RULE_ID,
      totalShown: 100,
      totalAccepted: 60,
      totalDismissed: 40,
      acceptanceRate: 0.6,
      suppressionCount: 2,
    })),
    getLearningStateSummary: vi.fn(async () => ({
      suppressedCount: 1,
      topAcceptedCategories: [],
      totalSuggestionsShown: 50,
      overallAcceptanceRate: 0.65,
    })),
    findClaimIdBySuggestionId: vi.fn(async () => null),
    getActiveRulesForClaim: vi.fn(async () => []),
    getProviderLearningForRules: vi.fn(async () => []),
    incrementShown: vi.fn(async () => ({})),
    appendSuggestionEvent: vi.fn(async () => ({})),
    getClaimSuggestions: vi.fn(async () => null),
    updateClaimSuggestions: vi.fn(async () => {}),
    recordAcceptance: vi.fn(async () => ({})),
    recordDismissal: vi.fn(async () => ({})),
    unsuppressRule: vi.fn(async () => ({})),
    listCohorts: vi.fn(async () => []),
    upsertCohort: vi.fn(async () => null),
    deleteSmallCohorts: vi.fn(async () => 0),
    getProvidersBySpecialty: vi.fn(async () => []),
    getProviderLearningByRule: vi.fn(async () => []),
    listSuggestionEvents: vi.fn(async () => []),
  } as unknown as IntelRepository;

  const auditLog = vi.fn(async (entry: AuditLogEntry) => {
    auditLogCalls.push(entry);
  });

  return {
    analyseDeps: stubAnalyseDeps,
    lifecycleDeps: stubLifecycleDeps,
    learningLoopDeps: stubLearningLoopDeps,
    sombChangeDeps: stubSombChangeDeps,
    repo: stubRepo,
    auditLog,
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let handlerDeps: IntelHandlerDeps;

async function buildTestApp(): Promise<FastifyInstance> {
  const mockSessionRepo = createMockSessionRepo();

  const sessionDeps = {
    sessionRepo: mockSessionRepo,
    auditRepo: { appendAuditLog: vi.fn(async () => {}) },
    events: { emit: vi.fn() },
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
      return reply.code(400).send({
        error: { code: 'VALIDATION_ERROR', message: 'Validation failed', details: error.validation },
      });
    }
    return reply.code(500).send({
      error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
    });
  });

  handlerDeps = createAuditTrackedIntelHandlerDeps();
  await testApp.register(intelRoutes, { deps: handlerDeps });
  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function adminHeaders(): Record<string, string> {
  return { cookie: `session=${ADMIN_TOKEN}` };
}

function seedSessions() {
  sessions = [];
  users = [];

  // Admin
  users.push({
    userId: ADMIN_USER_ID,
    role: 'ADMIN',
    subscriptionStatus: 'ACTIVE',
  });
  sessions.push({
    sessionId: ADMIN_SESSION_ID,
    userId: ADMIN_USER_ID,
    tokenHash: ADMIN_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Intelligence Extensions Audit Trail Verification (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    seedSessions();
    auditLogCalls = [];
  });

  // =========================================================================
  // 1. Rule Activation/Deactivation Audit
  // =========================================================================

  describe('Rule activation audit entries', () => {
    it('activating a rule produces audit record with isActive=true', async () => {
      const res = await app.inject({
        method: 'PUT',
        url: `/api/v1/intelligence/rules/${DUMMY_UUID}/activate`,
        headers: adminHeaders(),
        payload: { is_active: true },
      });

      expect(res.statusCode).toBe(200);

      const ruleToggledAudits = auditLogCalls.filter(
        (a) => a.action === 'intelligence.rule_toggled',
      );
      expect(ruleToggledAudits.length).toBe(1);
      expect(ruleToggledAudits[0].providerId).toBe(ADMIN_USER_ID);
      expect(ruleToggledAudits[0].details.ruleId).toBe(DUMMY_UUID);
      expect(ruleToggledAudits[0].details.isActive).toBe(true);
    });

    it('deactivating a rule produces audit record with isActive=false', async () => {
      const res = await app.inject({
        method: 'PUT',
        url: `/api/v1/intelligence/rules/${DUMMY_UUID}/activate`,
        headers: adminHeaders(),
        payload: { is_active: false },
      });

      expect(res.statusCode).toBe(200);

      const ruleToggledAudits = auditLogCalls.filter(
        (a) => a.action === 'intelligence.rule_toggled',
      );
      expect(ruleToggledAudits.length).toBe(1);
      expect(ruleToggledAudits[0].details.isActive).toBe(false);
    });

    it('rule toggle audit records the admin user ID', async () => {
      await app.inject({
        method: 'PUT',
        url: `/api/v1/intelligence/rules/${DUMMY_UUID}/activate`,
        headers: adminHeaders(),
        payload: { is_active: true },
      });

      expect(auditLogCalls.length).toBeGreaterThanOrEqual(1);
      for (const audit of auditLogCalls) {
        expect(audit.providerId).toBe(ADMIN_USER_ID);
      }
    });
  });

  // =========================================================================
  // 2. Rule Stats (read-only) Should NOT Produce Audit
  // =========================================================================

  describe('Rule stats (read-only) does not produce audit', () => {
    it('GET /intelligence/rules/:id/stats does not produce handler-level audit', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/intelligence/rules/${DUMMY_UUID}/stats`,
        headers: adminHeaders(),
      });

      expect(res.statusCode).toBe(200);
      expect(auditLogCalls.length).toBe(0);
    });
  });

  // =========================================================================
  // 3. Cohort Recalculation Audit
  // =========================================================================

  describe('Cohort recalculation audit entries', () => {
    it('POST /intelligence/cohorts/recalculate produces audit record with counts', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/intelligence/cohorts/recalculate',
        headers: adminHeaders(),
      });

      expect(res.statusCode).toBe(200);

      const cohortAudits = auditLogCalls.filter(
        (a) => a.action === 'intelligence.cohorts_recalculated',
      );
      expect(cohortAudits.length).toBe(1);
      expect(cohortAudits[0].providerId).toBe(ADMIN_USER_ID);
      expect(typeof cohortAudits[0].details.cohortCount).toBe('number');
      expect(typeof cohortAudits[0].details.deletedCount).toBe('number');
    });

    it('cohort recalculation audit includes cohortCount >= 0', async () => {
      await app.inject({
        method: 'POST',
        url: '/api/v1/intelligence/cohorts/recalculate',
        headers: adminHeaders(),
      });

      const cohortAudits = auditLogCalls.filter(
        (a) => a.action === 'intelligence.cohorts_recalculated',
      );
      expect(cohortAudits.length).toBe(1);
      expect(cohortAudits[0].details.cohortCount).toBeGreaterThanOrEqual(0);
    });

    it('cohort recalculation audit includes deletedCount >= 0', async () => {
      await app.inject({
        method: 'POST',
        url: '/api/v1/intelligence/cohorts/recalculate',
        headers: adminHeaders(),
      });

      const cohortAudits = auditLogCalls.filter(
        (a) => a.action === 'intelligence.cohorts_recalculated',
      );
      expect(cohortAudits.length).toBe(1);
      expect(cohortAudits[0].details.deletedCount).toBeGreaterThanOrEqual(0);
    });
  });

  // =========================================================================
  // 4. SOMB Change Analysis Audit
  // =========================================================================

  describe('SOMB change analysis audit entries', () => {
    it('POST /intelligence/somb-change-analysis produces audit record with version info', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/intelligence/somb-change-analysis',
        headers: adminHeaders(),
        payload: { old_version: '2025-12', new_version: '2026-01' },
      });

      expect(res.statusCode).toBe(200);

      const sombAudits = auditLogCalls.filter(
        (a) => a.action === 'intelligence.somb_analysis_triggered',
      );
      expect(sombAudits.length).toBe(1);
      expect(sombAudits[0].providerId).toBe(ADMIN_USER_ID);
      expect(sombAudits[0].details.oldVersion).toBe('2025-12');
      expect(sombAudits[0].details.newVersion).toBe('2026-01');
    });

    it('SOMB analysis audit includes affected counts', async () => {
      await app.inject({
        method: 'POST',
        url: '/api/v1/intelligence/somb-change-analysis',
        headers: adminHeaders(),
        payload: { old_version: '2025-12', new_version: '2026-01' },
      });

      const sombAudits = auditLogCalls.filter(
        (a) => a.action === 'intelligence.somb_analysis_triggered',
      );
      expect(sombAudits.length).toBe(1);
      expect(sombAudits[0].details.affectedPhysicians).toBeDefined();
      expect(sombAudits[0].details.affectedRules).toBeDefined();
    });
  });

  // =========================================================================
  // 5. Rule Management Audit (Create/Update via Admin)
  // =========================================================================

  describe('Rule management audit entries', () => {
    it('creating a rule produces audit record with rule ID and name', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/intelligence/rules',
        headers: adminHeaders(),
        payload: {
          name: 'Audit Extension Test Rule',
          category: 'MODIFIER_ADD',
          claim_type: 'AHCIP',
          conditions: { type: 'existence', field: 'ahcip.modifier1', operator: 'IS NULL' },
          suggestion_template: {
            title: 'Test',
            description: 'Test description',
            source_reference: 'SOMB',
          },
          priority_formula: 'fixed:MEDIUM',
        },
      });

      expect(res.statusCode).toBe(201);

      const ruleCreatedAudits = auditLogCalls.filter(
        (a) => a.action === 'intelligence.rule_created',
      );
      expect(ruleCreatedAudits.length).toBe(1);
      expect(ruleCreatedAudits[0].providerId).toBe(ADMIN_USER_ID);
      expect(ruleCreatedAudits[0].details.ruleId).toBeDefined();
      expect(ruleCreatedAudits[0].details.name).toBe('Audit Extension Test Rule');
    });

    it('updating a rule produces audit record with updated field names', async () => {
      const res = await app.inject({
        method: 'PUT',
        url: `/api/v1/intelligence/rules/${DUMMY_UUID}`,
        headers: adminHeaders(),
        payload: { name: 'Updated Extension Rule Name' },
      });

      expect(res.statusCode).toBe(200);

      const ruleUpdatedAudits = auditLogCalls.filter(
        (a) => a.action === 'intelligence.rule_updated',
      );
      expect(ruleUpdatedAudits.length).toBe(1);
      expect(ruleUpdatedAudits[0].providerId).toBe(ADMIN_USER_ID);
      expect(ruleUpdatedAudits[0].details.ruleId).toBe(DUMMY_UUID);
      expect(ruleUpdatedAudits[0].details.updatedFields).toBeDefined();
      expect(ruleUpdatedAudits[0].details.updatedFields).toContain('name');
    });
  });

  // =========================================================================
  // 6. Every Extension State-Changing Endpoint Produces Audit
  // =========================================================================

  describe('Every extension state-changing endpoint produces audit', () => {
    interface StateChangeRoute {
      method: 'POST' | 'PUT';
      url: string;
      payload?: Record<string, unknown>;
      description: string;
      expectedAuditAction: string;
    }

    const EXTENSION_STATE_ROUTES: StateChangeRoute[] = [
      {
        method: 'PUT',
        url: `/api/v1/intelligence/rules/${DUMMY_UUID}/activate`,
        payload: { is_active: true },
        description: 'Toggle rule active',
        expectedAuditAction: 'intelligence.rule_toggled',
      },
      {
        method: 'POST',
        url: '/api/v1/intelligence/cohorts/recalculate',
        description: 'Recalculate cohorts',
        expectedAuditAction: 'intelligence.cohorts_recalculated',
      },
      {
        method: 'POST',
        url: '/api/v1/intelligence/somb-change-analysis',
        payload: { old_version: '2025-12', new_version: '2026-01' },
        description: 'SOMB change analysis',
        expectedAuditAction: 'intelligence.somb_analysis_triggered',
      },
    ];

    for (const route of EXTENSION_STATE_ROUTES) {
      it(`${route.description} (${route.method} ${route.url}) produces audit record`, async () => {
        auditLogCalls = [];

        const res = await app.inject({
          method: route.method,
          url: route.url,
          headers: adminHeaders(),
          ...(route.payload ? { payload: route.payload } : {}),
        });

        expect(res.statusCode).toBeLessThan(300);

        const matchingAudits = auditLogCalls.filter(
          (a) => a.action === route.expectedAuditAction,
        );
        expect(matchingAudits.length).toBeGreaterThanOrEqual(1);
      });
    }
  });

  // =========================================================================
  // 7. Audit Records Do Not Contain PHI
  // =========================================================================

  describe('Audit records do not contain PHI', () => {
    it('extension audit entries do not contain patient data', async () => {
      // Trigger multiple extension audits
      await app.inject({
        method: 'PUT',
        url: `/api/v1/intelligence/rules/${DUMMY_UUID}/activate`,
        headers: adminHeaders(),
        payload: { is_active: true },
      });

      await app.inject({
        method: 'POST',
        url: '/api/v1/intelligence/cohorts/recalculate',
        headers: adminHeaders(),
      });

      await app.inject({
        method: 'POST',
        url: '/api/v1/intelligence/somb-change-analysis',
        headers: adminHeaders(),
        payload: { old_version: '2025-12', new_version: '2026-01' },
      });

      const allAuditsStr = JSON.stringify(auditLogCalls);

      // No PHI patterns
      expect(allAuditsStr).not.toMatch(/firstName|lastName|patientName/i);
      expect(allAuditsStr).not.toMatch(/dateOfBirth|date_of_birth/i);
      expect(allAuditsStr).not.toContain('phn');
      expect(allAuditsStr).not.toContain('123456789');
    });

    it('cohort recalculation audit does not contain individual provider IDs', async () => {
      await app.inject({
        method: 'POST',
        url: '/api/v1/intelligence/cohorts/recalculate',
        headers: adminHeaders(),
      });

      const cohortAudits = auditLogCalls.filter(
        (a) => a.action === 'intelligence.cohorts_recalculated',
      );
      expect(cohortAudits.length).toBe(1);

      const detailsStr = JSON.stringify(cohortAudits[0].details);
      // Should contain aggregate counts, not individual provider IDs
      expect(detailsStr).not.toMatch(/pppp0000/);
      expect(detailsStr).not.toMatch(/aaaa0000-0000-0000-0000-000000000001/);
    });

    it('SOMB analysis audit contains version info but no patient data', async () => {
      await app.inject({
        method: 'POST',
        url: '/api/v1/intelligence/somb-change-analysis',
        headers: adminHeaders(),
        payload: { old_version: '2025-12', new_version: '2026-01' },
      });

      const sombAudits = auditLogCalls.filter(
        (a) => a.action === 'intelligence.somb_analysis_triggered',
      );
      expect(sombAudits.length).toBe(1);

      const detailsStr = JSON.stringify(sombAudits[0].details);
      // Version info present
      expect(detailsStr).toContain('2025-12');
      expect(detailsStr).toContain('2026-01');
      // No patient data
      expect(detailsStr).not.toMatch(/firstName|lastName|patientName/i);
      expect(detailsStr).not.toMatch(/dateOfBirth/i);
    });
  });

  // =========================================================================
  // 8. Audit Records Record Correct Admin User ID
  // =========================================================================

  describe('Audit records record correct admin user ID', () => {
    it('all extension audit entries record admin user ID', async () => {
      await app.inject({
        method: 'PUT',
        url: `/api/v1/intelligence/rules/${DUMMY_UUID}/activate`,
        headers: adminHeaders(),
        payload: { is_active: true },
      });

      await app.inject({
        method: 'POST',
        url: '/api/v1/intelligence/cohorts/recalculate',
        headers: adminHeaders(),
      });

      await app.inject({
        method: 'POST',
        url: '/api/v1/intelligence/somb-change-analysis',
        headers: adminHeaders(),
        payload: { old_version: '2025-12', new_version: '2026-01' },
      });

      expect(auditLogCalls.length).toBeGreaterThanOrEqual(3);
      for (const audit of auditLogCalls) {
        expect(audit.providerId).toBe(ADMIN_USER_ID);
      }
    });
  });

  // =========================================================================
  // 9. No Audit Modification Endpoints Exist
  // =========================================================================

  describe('No audit modification endpoints exist for extensions', () => {
    it('no DELETE endpoint exists for extension audit logs', async () => {
      const auditPaths = [
        '/api/v1/intelligence/audit',
        '/api/v1/intelligence/audit-log',
        `/api/v1/intelligence/audit/${DUMMY_UUID}`,
      ];

      for (const path of auditPaths) {
        const res = await app.inject({
          method: 'DELETE',
          url: path,
          headers: adminHeaders(),
        });
        expect(res.statusCode).not.toBe(200);
        expect(res.statusCode).not.toBe(204);
      }
    });

    it('no PUT endpoint exists to modify extension audit records', async () => {
      const auditPaths = [
        '/api/v1/intelligence/audit',
        `/api/v1/intelligence/audit/${DUMMY_UUID}`,
      ];

      for (const path of auditPaths) {
        const res = await app.inject({
          method: 'PUT',
          url: path,
          headers: adminHeaders(),
          payload: { action: 'TAMPERED' },
        });
        expect(res.statusCode).not.toBe(200);
      }
    });
  });
});
