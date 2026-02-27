// ============================================================================
// Domain 7: Intelligence Extensions — Input Validation & Injection Prevention
// Verifies SQL injection in analysis claim_id, XSS in rule names,
// UUID validation for extension endpoints, and SOMB version field validation.
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

// Physician (for analyse endpoint)
const PHYSICIAN_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_TOKEN_HASH = hashToken(PHYSICIAN_TOKEN);
const PHYSICIAN_USER_ID = 'aaaa0000-0000-0000-0000-000000000001';
const PHYSICIAN_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000001';

// Admin (for rule management + extension endpoints)
const ADMIN_TOKEN = randomBytes(32).toString('hex');
const ADMIN_TOKEN_HASH = hashToken(ADMIN_TOKEN);
const ADMIN_USER_ID = 'aaaa0000-0000-0000-0000-000000000099';
const ADMIN_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000099';

const DUMMY_UUID = '00000000-0000-0000-0000-000000000001';

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
// Mock session repository
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
// Stub handler deps
// ---------------------------------------------------------------------------

function createStubIntelHandlerDeps(): IntelHandlerDeps {
  const stubRepo: IntelRepository = {
    listRules: vi.fn(async () => ({
      data: [],
      pagination: { total: 0, page: 1, pageSize: 50, hasMore: false },
    })),
    getRule: vi.fn(async () => null),
    createRule: vi.fn(async (data: any) => ({
      ruleId: crypto.randomUUID(),
      ...data,
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    })),
    updateRule: vi.fn(async () => null),
    activateRule: vi.fn(async () => null),
    getRuleStats: vi.fn(async () => null),
    getLearningStateSummary: vi.fn(async () => ({
      suppressedCount: 0,
      topCategories: [],
      acceptanceRate: 0,
      totalSuggestions: 0,
    })),
    findClaimIdBySuggestionId: vi.fn(async () => null),
    getActiveRulesForClaim: vi.fn(async () => []),
    getProviderLearningForRules: vi.fn(async () => []),
    incrementShown: vi.fn(async () => {}),
    appendSuggestionEvent: vi.fn(async () => {}),
    getClaimSuggestions: vi.fn(async () => null),
    updateClaimSuggestions: vi.fn(async () => {}),
    recordAcceptance: vi.fn(async () => {}),
    recordDismissal: vi.fn(async () => {}),
    unsuppressRule: vi.fn(async () => null),
    listCohorts: vi.fn(async () => []),
    upsertCohort: vi.fn(async () => null),
    deleteSmallCohorts: vi.fn(async () => 0),
    getProvidersBySpecialty: vi.fn(async () => []),
    getProviderLearningByRule: vi.fn(async () => []),
    listSuggestionEvents: vi.fn(async () => []),
  } as unknown as IntelRepository;

  const lifecycleDeps = {
    getClaimSuggestions: vi.fn(async () => null),
    updateClaimSuggestions: vi.fn(async () => {}),
    applyClaimChanges: vi.fn(async () => {}),
    revalidateClaim: vi.fn(async () => {}),
    appendSuggestionEvent: vi.fn(async () => {}),
    recordAcceptance: vi.fn(async () => {}),
    recordDismissal: vi.fn(async () => {}),
  };

  const analyseDeps = {
    contextDeps: {
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
      getCrossClaimSum: vi.fn(async () => '0.00'),
      getCrossClaimExists: vi.fn(async () => false),
    },
    tier1Deps: {
      getActiveRulesForClaim: vi.fn(async () => []),
      getProviderLearningForRules: vi.fn(async () => []),
      incrementShown: vi.fn(async () => {}),
      appendSuggestionEvent: vi.fn(async () => {}),
    },
    tier2Deps: {
      buildPrompt: vi.fn(),
      callLlm: vi.fn(),
      parseResponse: vi.fn(),
      appendSuggestionEvent: vi.fn(async () => {}),
    },
    lifecycleDeps,
    auditLog: vi.fn(async () => {}),
    notifyWs: vi.fn(),
  };

  return {
    analyseDeps,
    lifecycleDeps,
    learningLoopDeps: {
      getProviderLearning: vi.fn(async () => null),
      unsuppressRule: vi.fn(async () => null),
      processRejection: vi.fn(async () => {}),
      recalculateAllCohorts: vi.fn(async () => []),
      deleteSmallCohorts: vi.fn(async () => 0),
    },
    sombChangeDeps: {
      getRulesByVersion: vi.fn(async () => []),
      getAffectedProviders: vi.fn(async () => []),
      generateImpactReport: vi.fn(async () => ({
        totalAffectedPhysicians: 0,
        totalAffectedRules: 0,
        impacts: [],
      })),
    },
    repo: stubRepo,
    auditLog: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;

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

  await testApp.register(intelRoutes, { deps: createStubIntelHandlerDeps() });
  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeSession(id: string, userId: string, tokenHash: string): MockSession {
  return {
    sessionId: id,
    userId,
    tokenHash,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  };
}

function seedUsersAndSessions() {
  users = [];
  sessions = [];

  users.push({
    userId: PHYSICIAN_USER_ID,
    role: 'PHYSICIAN',
    subscriptionStatus: 'ACTIVE',
  });
  sessions.push(makeSession(PHYSICIAN_SESSION_ID, PHYSICIAN_USER_ID, PHYSICIAN_TOKEN_HASH));

  users.push({
    userId: ADMIN_USER_ID,
    role: 'ADMIN',
    subscriptionStatus: 'ACTIVE',
  });
  sessions.push(makeSession(ADMIN_SESSION_ID, ADMIN_USER_ID, ADMIN_TOKEN_HASH));
}

function asPhysician(method: 'GET' | 'POST' | 'PUT', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${PHYSICIAN_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function asAdmin(method: 'GET' | 'POST' | 'PUT', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${ADMIN_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

// ---------------------------------------------------------------------------
// Valid payloads
// ---------------------------------------------------------------------------

const VALID_ANALYSE_PAYLOAD = {
  claim_id: DUMMY_UUID,
  claim_context: {
    claim_type: 'AHCIP',
    health_service_code: '03.04A',
    modifiers: [],
    date_of_service: '2026-01-15',
    provider_specialty: 'GP',
    patient_demographics_anonymised: { age_range: '40-50', gender: 'M' },
    diagnostic_codes: [],
  },
};

const VALID_SOMB_CHANGE = {
  old_version: '2025-12',
  new_version: '2026-01',
};

const VALID_CREATE_RULE = {
  name: 'Test Rule',
  category: 'MODIFIER_ADD',
  claim_type: 'AHCIP',
  conditions: { type: 'existence', field: 'ahcip.modifier1', operator: 'IS NULL' },
  suggestion_template: {
    title: 'Add modifier',
    description: 'Consider adding a modifier',
    source_reference: 'SOMB 2026 Section 3.2',
  },
  priority_formula: 'fixed:MEDIUM',
};

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Intelligence Extensions Input Validation & Injection Prevention (Security)', () => {
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
  // 1. SQL Injection in Analysis claim_id
  // =========================================================================

  describe('SQL injection prevention in claim_id (analyse endpoint)', () => {
    const SQL_PAYLOADS = [
      "'; DROP TABLE ai_rules; --",
      "1' OR '1'='1",
      "' UNION SELECT * FROM providers --",
      "' OR 1=1--",
      "'; DELETE FROM ai_suggestion_events WHERE '1'='1",
    ];

    for (const payload of SQL_PAYLOADS) {
      it(`rejects SQL injection in analyse claim_id: ${payload.slice(0, 40)}...`, async () => {
        const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
          ...VALID_ANALYSE_PAYLOAD,
          claim_id: payload,
        });
        // claim_id must be a UUID -- SQL payloads are rejected by Zod
        expect(res.statusCode).toBe(400);
        const body = JSON.parse(res.body);
        expect(body.data).toBeUndefined();
      });
    }
  });

  // =========================================================================
  // 2. SQL Injection in SOMB version fields
  // =========================================================================

  describe('SQL injection prevention in SOMB version fields', () => {
    const SQL_PAYLOADS = [
      "'; DROP TABLE ai_rules; --",
      "1' OR '1'='1",
      "1; SELECT * FROM users --",
    ];

    for (const payload of SQL_PAYLOADS) {
      it(`handles SQL injection in old_version: ${payload.slice(0, 40)}...`, async () => {
        const res = await asAdmin('POST', '/api/v1/intelligence/somb-change-analysis', {
          old_version: payload,
          new_version: '2026-01',
        });
        // old_version is string min 1, max 20
        if (payload.length > 20) {
          expect(res.statusCode).toBe(400);
        } else {
          if (res.statusCode >= 500) {
            const body = JSON.parse(res.body);
            expect(body.error.message).toBe('Internal server error');
            expect(JSON.stringify(body)).not.toMatch(/postgres|drizzle|sql|syntax/i);
          }
        }
      });

      it(`handles SQL injection in new_version: ${payload.slice(0, 40)}...`, async () => {
        const res = await asAdmin('POST', '/api/v1/intelligence/somb-change-analysis', {
          old_version: '2025-12',
          new_version: payload,
        });
        if (payload.length > 20) {
          expect(res.statusCode).toBe(400);
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

  // =========================================================================
  // 3. XSS in rule names (admin create/update endpoints)
  // =========================================================================

  describe('XSS payload prevention in rule names', () => {
    const XSS_PAYLOADS = [
      '<script>alert("xss")</script>',
      '<script>alert(1)</script>',
      '<img src=x onerror=alert(1)>',
      '<svg onload=alert(1)>',
      '"><script>document.cookie</script>',
      'javascript:alert(1)',
    ];

    for (const payload of XSS_PAYLOADS) {
      it(`handles XSS in rule name via create: ${payload.slice(0, 40)}...`, async () => {
        const res = await asAdmin('POST', '/api/v1/intelligence/rules', {
          ...VALID_CREATE_RULE,
          name: payload.slice(0, 100),
        });
        // Name is string min 1, max 100. XSS payloads may pass Zod as valid strings.
        // JSON API responses (application/json) prevent browser rendering as HTML.
        if (res.statusCode === 200 || res.statusCode === 201) {
          const contentType = res.headers['content-type'] as string;
          expect(contentType).toContain('application/json');
        }
      });
    }

    for (const payload of XSS_PAYLOADS.slice(0, 3)) {
      it(`handles XSS in rule name via update: ${payload.slice(0, 40)}...`, async () => {
        const res = await asAdmin('PUT', `/api/v1/intelligence/rules/${DUMMY_UUID}`, {
          name: payload.slice(0, 100),
        });
        if (res.statusCode === 200 || res.statusCode === 201) {
          const contentType = res.headers['content-type'] as string;
          expect(contentType).toContain('application/json');
        }
      });
    }
  });

  // =========================================================================
  // 4. UUID validation for extension endpoints
  // =========================================================================

  describe('UUID parameter validation for extension endpoints', () => {
    const INVALID_UUIDS = [
      'not-a-uuid',
      '12345',
      'abcdefgh-ijkl-mnop-qrst-uvwxyz123456',
      '<script>alert(1)</script>',
      "'; DROP TABLE ai_rules; --",
      '../../../etc/passwd',
      '   ',
    ];

    describe('rule_id in /intelligence/rules/:id/stats', () => {
      for (const badId of INVALID_UUIDS) {
        it(`rejects non-UUID: ${badId.slice(0, 30)}`, async () => {
          const res = await asAdmin(
            'GET',
            `/api/v1/intelligence/rules/${encodeURIComponent(badId)}/stats`,
          );
          expect(res.statusCode).toBe(400);
        });
      }
    });

    describe('rule_id in /intelligence/rules/:id/activate', () => {
      for (const badId of INVALID_UUIDS) {
        it(`rejects non-UUID: ${badId.slice(0, 30)}`, async () => {
          const res = await asAdmin(
            'PUT',
            `/api/v1/intelligence/rules/${encodeURIComponent(badId)}/activate`,
            { is_active: true },
          );
          expect(res.statusCode).toBe(400);
        });
      }
    });
  });

  // =========================================================================
  // 5. Type coercion attacks on extension endpoints
  // =========================================================================

  describe('Type coercion attacks on extension endpoints', () => {
    it('rejects string where boolean expected for is_active in activate', async () => {
      const res = await asAdmin(
        'PUT',
        `/api/v1/intelligence/rules/${DUMMY_UUID}/activate`,
        { is_active: 'true' },
      );
      expect(res.statusCode).toBe(400);
    });

    it('rejects number where boolean expected for is_active in activate', async () => {
      const res = await asAdmin(
        'PUT',
        `/api/v1/intelligence/rules/${DUMMY_UUID}/activate`,
        { is_active: 1 },
      );
      expect(res.statusCode).toBe(400);
    });

    it('rejects null where required boolean for is_active in activate', async () => {
      const res = await asAdmin(
        'PUT',
        `/api/v1/intelligence/rules/${DUMMY_UUID}/activate`,
        { is_active: null },
      );
      expect(res.statusCode).toBe(400);
    });

    it('rejects missing is_active in activate', async () => {
      const res = await asAdmin(
        'PUT',
        `/api/v1/intelligence/rules/${DUMMY_UUID}/activate`,
        {},
      );
      expect(res.statusCode).toBe(400);
    });

    it('rejects number where string expected for old_version in SOMB analysis', async () => {
      const res = await asAdmin('POST', '/api/v1/intelligence/somb-change-analysis', {
        old_version: 202512,
        new_version: '2026-01',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects null where string expected for new_version in SOMB analysis', async () => {
      const res = await asAdmin('POST', '/api/v1/intelligence/somb-change-analysis', {
        old_version: '2025-12',
        new_version: null,
      });
      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // 6. Missing required fields on extension endpoints
  // =========================================================================

  describe('Missing required fields on extension endpoints', () => {
    it('rejects somb-change-analysis without old_version', async () => {
      const res = await asAdmin('POST', '/api/v1/intelligence/somb-change-analysis', {
        new_version: '2026-01',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects somb-change-analysis without new_version', async () => {
      const res = await asAdmin('POST', '/api/v1/intelligence/somb-change-analysis', {
        old_version: '2025-12',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects somb-change-analysis with empty body', async () => {
      const res = await asAdmin('POST', '/api/v1/intelligence/somb-change-analysis', {});
      expect(res.statusCode).toBe(400);
    });

    it('rejects activate rule without is_active', async () => {
      const res = await asAdmin(
        'PUT',
        `/api/v1/intelligence/rules/${DUMMY_UUID}/activate`,
        {},
      );
      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // 7. SOMB version boundary validation
  // =========================================================================

  describe('SOMB version boundary validation', () => {
    it('rejects empty old_version (min 1)', async () => {
      const res = await asAdmin('POST', '/api/v1/intelligence/somb-change-analysis', {
        old_version: '',
        new_version: '2026-01',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects old_version exceeding 20 chars', async () => {
      const res = await asAdmin('POST', '/api/v1/intelligence/somb-change-analysis', {
        old_version: 'x'.repeat(21),
        new_version: '2026-01',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects empty new_version (min 1)', async () => {
      const res = await asAdmin('POST', '/api/v1/intelligence/somb-change-analysis', {
        old_version: '2025-12',
        new_version: '',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects new_version exceeding 20 chars', async () => {
      const res = await asAdmin('POST', '/api/v1/intelligence/somb-change-analysis', {
        old_version: '2025-12',
        new_version: 'x'.repeat(21),
      });
      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // 8. Path traversal prevention
  // =========================================================================

  describe('Path traversal prevention on extension endpoints', () => {
    it('rejects path traversal in rule stats ID', async () => {
      const res = await asAdmin(
        'GET',
        '/api/v1/intelligence/rules/..%2F..%2Fetc%2Fpasswd/stats',
      );
      expect(res.statusCode).toBe(400);
    });

    it('rejects path traversal in rule activate ID', async () => {
      const res = await asAdmin(
        'PUT',
        '/api/v1/intelligence/rules/..%2F..%2Fetc%2Fpasswd/activate',
        { is_active: true },
      );
      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // 9. Error responses do not echo malicious input
  // =========================================================================

  describe('Error responses do not echo malicious input', () => {
    it('validation error for XSS in rule ID does not echo payload', async () => {
      const malicious = '<script>alert(1)</script>';
      const res = await asAdmin(
        'GET',
        `/api/v1/intelligence/rules/${encodeURIComponent(malicious)}/stats`,
      );
      expect(res.statusCode).toBe(400);
      expect(res.body).not.toContain('<script>');
      expect(res.body).not.toContain('alert');
    });

    it('validation error for SQL injection in SOMB does not echo payload', async () => {
      const malicious = "'; DROP TABLE ai_rules; --";
      const res = await asAdmin('POST', '/api/v1/intelligence/somb-change-analysis', {
        old_version: malicious.slice(0, 20),
        new_version: '2026-01',
      });
      // Short enough to pass length validation; verify no SQL in error
      if (res.statusCode >= 500) {
        const body = JSON.parse(res.body);
        expect(body.error.message).toBe('Internal server error');
        expect(JSON.stringify(body)).not.toMatch(/DROP TABLE|ai_rules/i);
      }
    });

    it('error responses do not expose internal details', async () => {
      const res = await asAdmin(
        'PUT',
        `/api/v1/intelligence/rules/${encodeURIComponent('not-a-uuid')}/activate`,
        { is_active: true },
      );
      expect(res.statusCode).toBe(400);
      expect(res.body).not.toContain('postgres');
      expect(res.body).not.toContain('drizzle');
      expect(res.body).not.toContain('node_modules');
      expect(res.body).not.toContain('.ts:');
    });
  });

  // =========================================================================
  // 10. Sanity: Valid payloads are accepted
  // =========================================================================

  describe('Sanity: valid extension payloads are accepted', () => {
    it('valid somb-change-analysis payload is accepted', async () => {
      const res = await asAdmin(
        'POST',
        '/api/v1/intelligence/somb-change-analysis',
        VALID_SOMB_CHANGE,
      );
      expect(res.statusCode).not.toBe(400);
    });

    it('valid activate rule payload is accepted', async () => {
      const res = await asAdmin(
        'PUT',
        `/api/v1/intelligence/rules/${DUMMY_UUID}/activate`,
        { is_active: true },
      );
      expect(res.statusCode).not.toBe(400);
    });

    it('valid deactivate rule payload is accepted', async () => {
      const res = await asAdmin(
        'PUT',
        `/api/v1/intelligence/rules/${DUMMY_UUID}/activate`,
        { is_active: false },
      );
      expect(res.statusCode).not.toBe(400);
    });

    it('valid cohort recalculate is accepted (no body required)', async () => {
      const res = await asAdmin('POST', '/api/v1/intelligence/cohorts/recalculate');
      expect(res.statusCode).not.toBe(400);
    });

    it('valid rule stats request is accepted', async () => {
      const res = await asAdmin('GET', `/api/v1/intelligence/rules/${DUMMY_UUID}/stats`);
      expect(res.statusCode).not.toBe(400);
    });
  });
});
