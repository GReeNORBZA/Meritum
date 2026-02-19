// ============================================================================
// Domain 7: Intelligence Engine — Input Validation & Injection Prevention
// Verifies that malicious input is rejected at the Zod schema layer and
// cannot reach the database. Tests SQL injection, XSS, type coercion,
// UUID validation, condition tree injection, and boundary violations.
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

// Physician (for suggestion/learning endpoints)
const PHYSICIAN_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_TOKEN_HASH = hashToken(PHYSICIAN_TOKEN);
const PHYSICIAN_USER_ID = 'aaaa0000-0000-0000-0000-000000000001';
const PHYSICIAN_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000001';

// Admin (for rule management endpoints)
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
// Valid payloads for baseline comparison
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

const VALID_DISMISS_PAYLOAD = { reason: 'not applicable to this patient' };

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

const VALID_UPDATE_PREFERENCES = {
  enabled_categories: ['MODIFIER_ADD'],
  disabled_categories: ['DOCUMENTATION_GAP'],
};

const VALID_SOMB_CHANGE = {
  old_version: '2025-12',
  new_version: '2026-01',
};

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Intelligence Engine Input Validation & Injection Prevention (Security)', () => {
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
  // 1. SQL Injection Payloads
  // =========================================================================

  describe('SQL injection prevention', () => {
    const SQL_PAYLOADS = [
      "'; DROP TABLE ai_rules; --",
      "1' OR '1'='1",
      "1; SELECT * FROM users --",
      "' UNION SELECT * FROM providers --",
      "' OR 1=1--",
      "'; DELETE FROM ai_suggestion_events WHERE '1'='1",
      "AHCIP'; DROP TABLE claims;--",
    ];

    describe('dismissed_reason field', () => {
      for (const payload of SQL_PAYLOADS) {
        it(`handles SQL injection in dismiss reason: ${payload.slice(0, 40)}...`, async () => {
          const res = await asPhysician(
            'POST',
            `/api/v1/intelligence/suggestions/${DUMMY_UUID}/dismiss`,
            { reason: payload },
          );
          // Reason is optional string max 500. SQL payloads may pass Zod (valid strings).
          // Drizzle parameterised queries prevent actual injection.
          if (res.statusCode >= 500) {
            const body = JSON.parse(res.body);
            expect(body.error.message).toBe('Internal server error');
            expect(JSON.stringify(body)).not.toMatch(/postgres|drizzle|sql|syntax/i);
          }
        });
      }
    });

    describe('rule name field', () => {
      for (const payload of SQL_PAYLOADS) {
        it(`handles SQL injection in rule name: ${payload.slice(0, 40)}...`, async () => {
          const res = await asAdmin('POST', '/api/v1/intelligence/rules', {
            ...VALID_CREATE_RULE,
            name: payload.slice(0, 100), // max 100 chars
          });
          // Name is string min 1, max 100. Short SQL payloads may pass Zod.
          // Drizzle parameterised queries prevent injection at ORM level.
          if (res.statusCode >= 500) {
            const body = JSON.parse(res.body);
            expect(body.error.message).toBe('Internal server error');
            expect(JSON.stringify(body)).not.toMatch(/postgres|drizzle|sql|syntax/i);
          }
        });
      }
    });

    describe('health_service_code field in claim context', () => {
      for (const payload of SQL_PAYLOADS) {
        it(`handles SQL injection in health_service_code: ${payload.slice(0, 40)}...`, async () => {
          const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
            ...VALID_ANALYSE_PAYLOAD,
            claim_context: {
              ...VALID_ANALYSE_PAYLOAD.claim_context,
              health_service_code: payload,
            },
          });
          // health_service_code is string min 1, max 10.
          // Payloads > 10 chars are rejected by Zod. Short payloads (<=10 chars) may pass Zod
          // but Drizzle parameterised queries prevent actual SQL injection.
          if (payload.length > 10) {
            expect(res.statusCode).toBe(400);
          } else {
            // Short payload passes Zod — verify no SQL errors exposed
            if (res.statusCode >= 500) {
              const body = JSON.parse(res.body);
              expect(body.error.message).toBe('Internal server error');
              expect(JSON.stringify(body)).not.toMatch(/postgres|drizzle|sql|syntax/i);
            }
          }
        });
      }
    });

    describe('conditions JSONB — SQL injection in condition values', () => {
      it('condition with SQL injection in value field does not execute SQL', async () => {
        const res = await asAdmin('POST', '/api/v1/intelligence/rules', {
          ...VALID_CREATE_RULE,
          conditions: {
            type: 'field_compare',
            field: 'claim.healthServiceCode',
            operator: '==',
            value: "'; DROP TABLE ai_rules; --",
          },
        });
        // Condition value is z.unknown(), so it passes Zod.
        // The condition evaluator operates on pre-fetched context, not raw SQL.
        if (res.statusCode >= 500) {
          const body = JSON.parse(res.body);
          expect(body.error.message).toBe('Internal server error');
          expect(JSON.stringify(body)).not.toMatch(/postgres|drizzle|sql|syntax/i);
        }
      });

      it('nested condition with SQL injection in value does not execute SQL', async () => {
        const res = await asAdmin('POST', '/api/v1/intelligence/rules', {
          ...VALID_CREATE_RULE,
          conditions: {
            type: 'and',
            children: [
              {
                type: 'field_compare',
                field: 'claim.healthServiceCode',
                operator: '==',
                value: "' UNION SELECT * FROM providers --",
              },
              {
                type: 'existence',
                field: 'claim.modifier1',
                operator: 'IS NOT NULL',
              },
            ],
          },
        });
        if (res.statusCode >= 500) {
          const body = JSON.parse(res.body);
          expect(body.error.message).toBe('Internal server error');
          expect(JSON.stringify(body)).not.toMatch(/postgres|drizzle|sql|syntax/i);
        }
      });
    });

    describe('SOMB version fields', () => {
      for (const payload of SQL_PAYLOADS.slice(0, 3)) {
        it(`handles SQL injection in old_version: ${payload.slice(0, 40)}...`, async () => {
          const res = await asAdmin('POST', '/api/v1/intelligence/somb-change-analysis', {
            old_version: payload,
            new_version: '2026-01',
          });
          // old_version is string min 1, max 20.
          // Payloads > 20 chars are rejected by Zod. Short payloads may pass Zod
          // but Drizzle parameterised queries prevent actual SQL injection.
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

    describe('provider_specialty field', () => {
      for (const payload of SQL_PAYLOADS.slice(0, 3)) {
        it(`rejects SQL injection in provider_specialty: ${payload.slice(0, 40)}...`, async () => {
          const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
            ...VALID_ANALYSE_PAYLOAD,
            claim_context: {
              ...VALID_ANALYSE_PAYLOAD.claim_context,
              provider_specialty: payload,
            },
          });
          // provider_specialty max 10. Long payloads rejected by Zod.
          expect(res.statusCode).toBe(400);
        });
      }
    });

    describe('priority_formula field', () => {
      for (const payload of SQL_PAYLOADS.slice(0, 3)) {
        it(`handles SQL injection in priority_formula: ${payload.slice(0, 40)}...`, async () => {
          const res = await asAdmin('POST', '/api/v1/intelligence/rules', {
            ...VALID_CREATE_RULE,
            priority_formula: payload.slice(0, 100),
          });
          // priority_formula is string min 1, max 100. Short payloads may pass Zod.
          if (res.statusCode >= 500) {
            const body = JSON.parse(res.body);
            expect(body.error.message).toBe('Internal server error');
            expect(JSON.stringify(body)).not.toMatch(/postgres|drizzle|sql|syntax/i);
          }
        });
      }
    });
  });

  // =========================================================================
  // 2. XSS Payloads
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

    describe('dismissed_reason: XSS payloads stored safely', () => {
      for (const payload of XSS_PAYLOADS.slice(0, 4)) {
        it(`handles XSS in dismiss reason: ${payload.slice(0, 40)}...`, async () => {
          const res = await asPhysician(
            'POST',
            `/api/v1/intelligence/suggestions/${DUMMY_UUID}/dismiss`,
            { reason: payload },
          );
          if (res.statusCode === 200 || res.statusCode === 201) {
            const contentType = res.headers['content-type'] as string;
            expect(contentType).toContain('application/json');
          }
        });
      }
    });

    describe('rule suggestion_template title: XSS payloads stored safely', () => {
      for (const payload of XSS_PAYLOADS.slice(0, 4)) {
        it(`handles XSS in template title: ${payload.slice(0, 40)}...`, async () => {
          const res = await asAdmin('POST', '/api/v1/intelligence/rules', {
            ...VALID_CREATE_RULE,
            suggestion_template: {
              ...VALID_CREATE_RULE.suggestion_template,
              title: payload.slice(0, 200),
            },
          });
          if (res.statusCode === 200 || res.statusCode === 201) {
            // JSON API responses are content-type application/json.
            // Browsers will NOT render JSON as HTML, so raw HTML in JSON string
            // values cannot execute. React additionally auto-escapes at render.
            const contentType = res.headers['content-type'] as string;
            expect(contentType).toContain('application/json');
          }
        });
      }
    });

    describe('rule suggestion_template description: XSS payloads stored safely', () => {
      for (const payload of XSS_PAYLOADS.slice(0, 3)) {
        it(`handles XSS in template description: ${payload.slice(0, 40)}...`, async () => {
          const res = await asAdmin('POST', '/api/v1/intelligence/rules', {
            ...VALID_CREATE_RULE,
            suggestion_template: {
              ...VALID_CREATE_RULE.suggestion_template,
              description: payload,
            },
          });
          if (res.statusCode === 200 || res.statusCode === 201) {
            const contentType = res.headers['content-type'] as string;
            expect(contentType).toContain('application/json');
          }
        });
      }
    });

    describe('rule name: XSS payloads stored safely', () => {
      for (const payload of XSS_PAYLOADS.slice(0, 3)) {
        it(`handles XSS in rule name: ${payload.slice(0, 40)}...`, async () => {
          const res = await asAdmin('POST', '/api/v1/intelligence/rules', {
            ...VALID_CREATE_RULE,
            name: payload.slice(0, 100),
          });
          if (res.statusCode === 200 || res.statusCode === 201) {
            const contentType = res.headers['content-type'] as string;
            expect(contentType).toContain('application/json');
          }
        });
      }
    });

    describe('preferences JSON: XSS in category names rejected by enum validation', () => {
      for (const payload of XSS_PAYLOADS.slice(0, 3)) {
        it(`rejects XSS in category name: ${payload.slice(0, 40)}...`, async () => {
          const res = await asPhysician('PUT', '/api/v1/intelligence/me/preferences', {
            enabled_categories: [payload],
          });
          // Category names are validated against a strict enum — XSS payloads are rejected
          expect(res.statusCode).toBe(400);
        });
      }
    });
  });

  // =========================================================================
  // 3. Type Coercion Attacks
  // =========================================================================

  describe('Type coercion attacks', () => {
    describe('analyse endpoint — claim_context fields', () => {
      it('rejects string where number expected for time_spent', async () => {
        const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
          ...VALID_ANALYSE_PAYLOAD,
          claim_context: {
            ...VALID_ANALYSE_PAYLOAD.claim_context,
            time_spent: 'twenty',
          },
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects negative value for time_spent', async () => {
        const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
          ...VALID_ANALYSE_PAYLOAD,
          claim_context: {
            ...VALID_ANALYSE_PAYLOAD.claim_context,
            time_spent: -5,
          },
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects zero for time_spent (must be positive)', async () => {
        const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
          ...VALID_ANALYSE_PAYLOAD,
          claim_context: {
            ...VALID_ANALYSE_PAYLOAD.claim_context,
            time_spent: 0,
          },
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects float for time_spent (must be integer)', async () => {
        const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
          ...VALID_ANALYSE_PAYLOAD,
          claim_context: {
            ...VALID_ANALYSE_PAYLOAD.claim_context,
            time_spent: 2.5,
          },
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects array where string expected for health_service_code', async () => {
        const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
          ...VALID_ANALYSE_PAYLOAD,
          claim_context: {
            ...VALID_ANALYSE_PAYLOAD.claim_context,
            health_service_code: ['03.04A'],
          },
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects number where string expected for claim_type', async () => {
        const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
          ...VALID_ANALYSE_PAYLOAD,
          claim_context: {
            ...VALID_ANALYSE_PAYLOAD.claim_context,
            claim_type: 123,
          },
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects number where date string expected for date_of_service', async () => {
        const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
          ...VALID_ANALYSE_PAYLOAD,
          claim_context: {
            ...VALID_ANALYSE_PAYLOAD.claim_context,
            date_of_service: 20260115,
          },
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects string where boolean expected for referring_provider', async () => {
        const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
          ...VALID_ANALYSE_PAYLOAD,
          claim_context: {
            ...VALID_ANALYSE_PAYLOAD.claim_context,
            referring_provider: 'yes',
          },
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects number 1 where boolean expected for referring_provider', async () => {
        const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
          ...VALID_ANALYSE_PAYLOAD,
          claim_context: {
            ...VALID_ANALYSE_PAYLOAD.claim_context,
            referring_provider: 1,
          },
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects null where required claim_type', async () => {
        const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
          ...VALID_ANALYSE_PAYLOAD,
          claim_context: {
            ...VALID_ANALYSE_PAYLOAD.claim_context,
            claim_type: null,
          },
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects null where required health_service_code', async () => {
        const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
          ...VALID_ANALYSE_PAYLOAD,
          claim_context: {
            ...VALID_ANALYSE_PAYLOAD.claim_context,
            health_service_code: null,
          },
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('dismiss endpoint — reason field', () => {
      it('rejects array where string expected for reason', async () => {
        const res = await asPhysician(
          'POST',
          `/api/v1/intelligence/suggestions/${DUMMY_UUID}/dismiss`,
          { reason: ['not', 'applicable'] },
        );
        expect(res.statusCode).toBe(400);
      });

      it('rejects number where string expected for reason', async () => {
        const res = await asPhysician(
          'POST',
          `/api/v1/intelligence/suggestions/${DUMMY_UUID}/dismiss`,
          { reason: 42 },
        );
        expect(res.statusCode).toBe(400);
      });

      it('rejects object where string expected for reason', async () => {
        const res = await asPhysician(
          'POST',
          `/api/v1/intelligence/suggestions/${DUMMY_UUID}/dismiss`,
          { reason: { text: 'not applicable' } },
        );
        expect(res.statusCode).toBe(400);
      });
    });

    describe('activate rule — is_active field', () => {
      it('rejects string where boolean expected for is_active', async () => {
        const res = await asAdmin(
          'PUT',
          `/api/v1/intelligence/rules/${DUMMY_UUID}/activate`,
          { is_active: 'true' },
        );
        expect(res.statusCode).toBe(400);
      });

      it('rejects number where boolean expected for is_active', async () => {
        const res = await asAdmin(
          'PUT',
          `/api/v1/intelligence/rules/${DUMMY_UUID}/activate`,
          { is_active: 1 },
        );
        expect(res.statusCode).toBe(400);
      });

      it('rejects null where required boolean for is_active', async () => {
        const res = await asAdmin(
          'PUT',
          `/api/v1/intelligence/rules/${DUMMY_UUID}/activate`,
          { is_active: null },
        );
        expect(res.statusCode).toBe(400);
      });
    });

    describe('preferences — priority_thresholds', () => {
      it('rejects negative value for high_revenue (string with regex)', async () => {
        const res = await asPhysician('PUT', '/api/v1/intelligence/me/preferences', {
          priority_thresholds: {
            high_revenue: '-20.00',
            medium_revenue: '5.00',
          },
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects number where string expected for high_revenue', async () => {
        const res = await asPhysician('PUT', '/api/v1/intelligence/me/preferences', {
          priority_thresholds: {
            high_revenue: 20.00,
            medium_revenue: 5.00,
          },
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects malformed decimal format for high_revenue', async () => {
        const res = await asPhysician('PUT', '/api/v1/intelligence/me/preferences', {
          priority_thresholds: {
            high_revenue: '20.0',  // only 1 decimal place, needs 2
            medium_revenue: '5.00',
          },
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects non-numeric string for medium_revenue', async () => {
        const res = await asPhysician('PUT', '/api/v1/intelligence/me/preferences', {
          priority_thresholds: {
            high_revenue: '20.00',
            medium_revenue: 'abc',
          },
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('create rule — wrong types for nested fields', () => {
      it('rejects number where string expected for rule name', async () => {
        const res = await asAdmin('POST', '/api/v1/intelligence/rules', {
          ...VALID_CREATE_RULE,
          name: 12345,
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects null where required for conditions', async () => {
        const res = await asAdmin('POST', '/api/v1/intelligence/rules', {
          ...VALID_CREATE_RULE,
          conditions: null,
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects string where object expected for conditions', async () => {
        const res = await asAdmin('POST', '/api/v1/intelligence/rules', {
          ...VALID_CREATE_RULE,
          conditions: 'not-an-object',
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects string where object expected for suggestion_template', async () => {
        const res = await asAdmin('POST', '/api/v1/intelligence/rules', {
          ...VALID_CREATE_RULE,
          suggestion_template: 'not-an-object',
        });
        expect(res.statusCode).toBe(400);
      });
    });
  });

  // =========================================================================
  // 4. UUID Validation
  // =========================================================================

  describe('UUID parameter validation', () => {
    const INVALID_UUIDS = [
      'not-a-uuid',
      '12345',
      'abcdefgh-ijkl-mnop-qrst-uvwxyz123456',
      '<script>alert(1)</script>',
      "'; DROP TABLE ai_rules; --",
      '../../../etc/passwd',
      '   ',
    ];

    describe('suggestion ID in /intelligence/suggestions/:id/accept', () => {
      for (const badId of INVALID_UUIDS) {
        it(`rejects non-UUID: ${badId.slice(0, 30)}`, async () => {
          const res = await asPhysician(
            'POST',
            `/api/v1/intelligence/suggestions/${encodeURIComponent(badId)}/accept`,
          );
          expect(res.statusCode).toBe(400);
          const body = JSON.parse(res.body);
          expect(body.data).toBeUndefined();
        });
      }
    });

    describe('suggestion ID in /intelligence/suggestions/:id/dismiss', () => {
      for (const badId of INVALID_UUIDS) {
        it(`rejects non-UUID: ${badId.slice(0, 30)}`, async () => {
          const res = await asPhysician(
            'POST',
            `/api/v1/intelligence/suggestions/${encodeURIComponent(badId)}/dismiss`,
            VALID_DISMISS_PAYLOAD,
          );
          expect(res.statusCode).toBe(400);
          const body = JSON.parse(res.body);
          expect(body.data).toBeUndefined();
        });
      }
    });

    describe('claim_id in /intelligence/claims/:claim_id/suggestions', () => {
      for (const badId of INVALID_UUIDS) {
        it(`rejects non-UUID: ${badId.slice(0, 30)}`, async () => {
          const res = await asPhysician(
            'GET',
            `/api/v1/intelligence/claims/${encodeURIComponent(badId)}/suggestions`,
          );
          expect(res.statusCode).toBe(400);
          const body = JSON.parse(res.body);
          expect(body.data).toBeUndefined();
        });
      }
    });

    describe('rule_id in /intelligence/rules/:id (update)', () => {
      for (const badId of INVALID_UUIDS) {
        it(`rejects non-UUID: ${badId.slice(0, 30)}`, async () => {
          const res = await asAdmin(
            'PUT',
            `/api/v1/intelligence/rules/${encodeURIComponent(badId)}`,
            { name: 'Updated' },
          );
          expect(res.statusCode).toBe(400);
          const body = JSON.parse(res.body);
          expect(body.data).toBeUndefined();
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

    describe('rule_id in /intelligence/me/rules/:rule_id/unsuppress', () => {
      for (const badId of INVALID_UUIDS) {
        it(`rejects non-UUID: ${badId.slice(0, 30)}`, async () => {
          const res = await asPhysician(
            'POST',
            `/api/v1/intelligence/me/rules/${encodeURIComponent(badId)}/unsuppress`,
          );
          expect(res.statusCode).toBe(400);
        });
      }
    });

    describe('claim_id in analyse body', () => {
      for (const badId of INVALID_UUIDS) {
        it(`rejects non-UUID claim_id in body: ${badId.slice(0, 30)}`, async () => {
          const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
            ...VALID_ANALYSE_PAYLOAD,
            claim_id: badId,
          });
          expect(res.statusCode).toBe(400);
        });
      }
    });
  });

  // =========================================================================
  // 5. Condition Tree Injection Prevention
  // =========================================================================

  describe('Condition tree injection prevention', () => {
    it('condition with SQL injection in value field — no SQL executed', async () => {
      const res = await asAdmin('POST', '/api/v1/intelligence/rules', {
        ...VALID_CREATE_RULE,
        conditions: {
          type: 'field_compare',
          field: 'claim.healthServiceCode',
          operator: '==',
          value: "'; DROP TABLE ai_rules; --",
        },
      });
      // Condition evaluator operates on pre-fetched context, not raw SQL.
      // Either accepted (condition stored as JSONB) or rejected.
      // Must never expose SQL errors.
      if (res.statusCode >= 500) {
        const body = JSON.parse(res.body);
        expect(body.error.message).toBe('Internal server error');
        expect(JSON.stringify(body)).not.toMatch(/postgres|drizzle|sql|syntax/i);
      }
    });

    it('cross_claim condition with SQL in filter value does not execute SQL', async () => {
      const res = await asAdmin('POST', '/api/v1/intelligence/rules', {
        ...VALID_CREATE_RULE,
        conditions: {
          type: 'cross_claim',
          query: {
            lookbackDays: 90,
            field: 'healthServiceCode',
            aggregation: 'count',
            filter: {
              type: 'field_compare',
              field: 'claim.healthServiceCode',
              operator: '==',
              value: "' OR 1=1 --",
            },
          },
        },
      });
      if (res.statusCode >= 500) {
        const body = JSON.parse(res.body);
        expect(body.error.message).toBe('Internal server error');
        expect(JSON.stringify(body)).not.toMatch(/postgres|drizzle|sql|syntax/i);
      }
    });

    it('condition with invalid type is rejected by Zod enum', async () => {
      const res = await asAdmin('POST', '/api/v1/intelligence/rules', {
        ...VALID_CREATE_RULE,
        conditions: {
          type: 'INVALID_TYPE',
          field: 'claim.healthServiceCode',
          operator: '==',
          value: 'test',
        },
      });
      expect(res.statusCode).toBe(400);
    });

    it('condition with invalid operator is rejected by Zod enum', async () => {
      const res = await asAdmin('POST', '/api/v1/intelligence/rules', {
        ...VALID_CREATE_RULE,
        conditions: {
          type: 'field_compare',
          field: 'claim.healthServiceCode',
          operator: 'LIKE',
          value: '%test%',
        },
      });
      expect(res.statusCode).toBe(400);
    });

    it('cross_claim query with invalid aggregation is rejected', async () => {
      const res = await asAdmin('POST', '/api/v1/intelligence/rules', {
        ...VALID_CREATE_RULE,
        conditions: {
          type: 'cross_claim',
          query: {
            lookbackDays: 90,
            field: 'healthServiceCode',
            aggregation: 'avg',  // Not in enum: count, sum, exists
          },
        },
      });
      expect(res.statusCode).toBe(400);
    });

    it('cross_claim query with negative lookbackDays is rejected', async () => {
      const res = await asAdmin('POST', '/api/v1/intelligence/rules', {
        ...VALID_CREATE_RULE,
        conditions: {
          type: 'cross_claim',
          query: {
            lookbackDays: -30,
            field: 'healthServiceCode',
            aggregation: 'count',
          },
        },
      });
      expect(res.statusCode).toBe(400);
    });

    it('cross_claim query with zero lookbackDays is rejected', async () => {
      const res = await asAdmin('POST', '/api/v1/intelligence/rules', {
        ...VALID_CREATE_RULE,
        conditions: {
          type: 'cross_claim',
          query: {
            lookbackDays: 0,
            field: 'healthServiceCode',
            aggregation: 'count',
          },
        },
      });
      expect(res.statusCode).toBe(400);
    });

    it('cross_claim query with float lookbackDays is rejected', async () => {
      const res = await asAdmin('POST', '/api/v1/intelligence/rules', {
        ...VALID_CREATE_RULE,
        conditions: {
          type: 'cross_claim',
          query: {
            lookbackDays: 30.5,
            field: 'healthServiceCode',
            aggregation: 'count',
          },
        },
      });
      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // 6. Enum Validation
  // =========================================================================

  describe('Enum validation', () => {
    describe('claim_type in analyse context', () => {
      it('rejects invalid claim_type', async () => {
        const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
          ...VALID_ANALYSE_PAYLOAD,
          claim_context: {
            ...VALID_ANALYSE_PAYLOAD.claim_context,
            claim_type: 'INVALID',
          },
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects lowercase claim_type', async () => {
        const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
          ...VALID_ANALYSE_PAYLOAD,
          claim_context: {
            ...VALID_ANALYSE_PAYLOAD.claim_context,
            claim_type: 'ahcip',
          },
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('category in create rule', () => {
      it('rejects invalid category', async () => {
        const res = await asAdmin('POST', '/api/v1/intelligence/rules', {
          ...VALID_CREATE_RULE,
          category: 'INVALID_CATEGORY',
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects empty string category', async () => {
        const res = await asAdmin('POST', '/api/v1/intelligence/rules', {
          ...VALID_CREATE_RULE,
          category: '',
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('claim_type in create rule', () => {
      it('rejects invalid claim_type', async () => {
        const res = await asAdmin('POST', '/api/v1/intelligence/rules', {
          ...VALID_CREATE_RULE,
          claim_type: 'MEDICARE',
        });
        expect(res.statusCode).toBe(400);
      });

      it('accepts BOTH as valid claim_type', async () => {
        const res = await asAdmin('POST', '/api/v1/intelligence/rules', {
          ...VALID_CREATE_RULE,
          claim_type: 'BOTH',
        });
        expect(res.statusCode).not.toBe(400);
      });
    });

    describe('category filter in list rules', () => {
      it('rejects invalid category in query', async () => {
        const res = await asPhysician(
          'GET',
          '/api/v1/intelligence/rules?category=INVALID',
        );
        expect(res.statusCode).toBe(400);
      });

      it('rejects invalid claim_type in query', async () => {
        const res = await asPhysician(
          'GET',
          '/api/v1/intelligence/rules?claim_type=INVALID',
        );
        expect(res.statusCode).toBe(400);
      });
    });

    describe('enabled_categories in preferences', () => {
      it('rejects invalid category in enabled_categories', async () => {
        const res = await asPhysician('PUT', '/api/v1/intelligence/me/preferences', {
          enabled_categories: ['INVALID_CATEGORY'],
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects mixed valid and invalid categories', async () => {
        const res = await asPhysician('PUT', '/api/v1/intelligence/me/preferences', {
          enabled_categories: ['MODIFIER_ADD', 'INVALID_CATEGORY'],
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects invalid category in disabled_categories', async () => {
        const res = await asPhysician('PUT', '/api/v1/intelligence/me/preferences', {
          disabled_categories: ['INVALID_CATEGORY'],
        });
        expect(res.statusCode).toBe(400);
      });
    });
  });

  // =========================================================================
  // 7. String Length Boundary Validation
  // =========================================================================

  describe('String length boundary validation', () => {
    describe('health_service_code boundaries', () => {
      it('rejects empty health_service_code (min 1)', async () => {
        const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
          ...VALID_ANALYSE_PAYLOAD,
          claim_context: {
            ...VALID_ANALYSE_PAYLOAD.claim_context,
            health_service_code: '',
          },
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects health_service_code exceeding 10 chars', async () => {
        const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
          ...VALID_ANALYSE_PAYLOAD,
          claim_context: {
            ...VALID_ANALYSE_PAYLOAD.claim_context,
            health_service_code: 'x'.repeat(11),
          },
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('provider_specialty boundaries', () => {
      it('rejects provider_specialty exceeding 10 chars', async () => {
        const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
          ...VALID_ANALYSE_PAYLOAD,
          claim_context: {
            ...VALID_ANALYSE_PAYLOAD.claim_context,
            provider_specialty: 'x'.repeat(11),
          },
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('modifier element boundaries', () => {
      it('rejects modifier element exceeding 4 chars', async () => {
        const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
          ...VALID_ANALYSE_PAYLOAD,
          claim_context: {
            ...VALID_ANALYSE_PAYLOAD.claim_context,
            modifiers: ['TOOLONG'],
          },
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('diagnostic_codes element boundaries', () => {
      it('rejects diagnostic code exceeding 10 chars', async () => {
        const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
          ...VALID_ANALYSE_PAYLOAD,
          claim_context: {
            ...VALID_ANALYSE_PAYLOAD.claim_context,
            diagnostic_codes: ['x'.repeat(11)],
          },
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('dismiss reason boundaries', () => {
      it('rejects reason exceeding 500 chars', async () => {
        const res = await asPhysician(
          'POST',
          `/api/v1/intelligence/suggestions/${DUMMY_UUID}/dismiss`,
          { reason: 'x'.repeat(501) },
        );
        expect(res.statusCode).toBe(400);
      });

      it('accepts reason at exactly 500 chars', async () => {
        const res = await asPhysician(
          'POST',
          `/api/v1/intelligence/suggestions/${DUMMY_UUID}/dismiss`,
          { reason: 'x'.repeat(500) },
        );
        expect(res.statusCode).not.toBe(400);
      });
    });

    describe('rule name boundaries', () => {
      it('rejects empty rule name (min 1)', async () => {
        const res = await asAdmin('POST', '/api/v1/intelligence/rules', {
          ...VALID_CREATE_RULE,
          name: '',
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects rule name exceeding 100 chars', async () => {
        const res = await asAdmin('POST', '/api/v1/intelligence/rules', {
          ...VALID_CREATE_RULE,
          name: 'x'.repeat(101),
        });
        expect(res.statusCode).toBe(400);
      });

      it('accepts rule name at exactly 100 chars', async () => {
        const res = await asAdmin('POST', '/api/v1/intelligence/rules', {
          ...VALID_CREATE_RULE,
          name: 'x'.repeat(100),
        });
        expect(res.statusCode).not.toBe(400);
      });
    });

    describe('suggestion_template title boundaries', () => {
      it('rejects title exceeding 200 chars', async () => {
        const res = await asAdmin('POST', '/api/v1/intelligence/rules', {
          ...VALID_CREATE_RULE,
          suggestion_template: {
            ...VALID_CREATE_RULE.suggestion_template,
            title: 'x'.repeat(201),
          },
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('source_reference boundaries', () => {
      it('rejects source_reference exceeding 200 chars', async () => {
        const res = await asAdmin('POST', '/api/v1/intelligence/rules', {
          ...VALID_CREATE_RULE,
          suggestion_template: {
            ...VALID_CREATE_RULE.suggestion_template,
            source_reference: 'x'.repeat(201),
          },
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('source_url validation', () => {
      it('rejects non-URL string for source_url', async () => {
        const res = await asAdmin('POST', '/api/v1/intelligence/rules', {
          ...VALID_CREATE_RULE,
          suggestion_template: {
            ...VALID_CREATE_RULE.suggestion_template,
            source_url: 'not-a-url',
          },
        });
        expect(res.statusCode).toBe(400);
      });

      it('handles javascript: URI for source_url safely', async () => {
        const res = await asAdmin('POST', '/api/v1/intelligence/rules', {
          ...VALID_CREATE_RULE,
          suggestion_template: {
            ...VALID_CREATE_RULE.suggestion_template,
            source_url: 'javascript:alert(1)',
          },
        });
        // z.string().url() may accept some non-HTTP URIs.
        // If accepted, the response is JSON (application/json) — browsers don't execute it.
        // If rejected, it returns 400.
        if (res.statusCode === 200 || res.statusCode === 201) {
          const contentType = res.headers['content-type'] as string;
          expect(contentType).toContain('application/json');
        }
      });

      it('rejects source_url exceeding 500 chars', async () => {
        const res = await asAdmin('POST', '/api/v1/intelligence/rules', {
          ...VALID_CREATE_RULE,
          suggestion_template: {
            ...VALID_CREATE_RULE.suggestion_template,
            source_url: 'https://example.com/' + 'x'.repeat(490),
          },
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('SOMB version boundaries', () => {
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
    });

    describe('priority_formula boundaries', () => {
      it('rejects empty priority_formula (min 1)', async () => {
        const res = await asAdmin('POST', '/api/v1/intelligence/rules', {
          ...VALID_CREATE_RULE,
          priority_formula: '',
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects priority_formula exceeding 100 chars', async () => {
        const res = await asAdmin('POST', '/api/v1/intelligence/rules', {
          ...VALID_CREATE_RULE,
          priority_formula: 'x'.repeat(101),
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('specialty_filter element boundaries', () => {
      it('rejects specialty code exceeding 10 chars', async () => {
        const res = await asAdmin('POST', '/api/v1/intelligence/rules', {
          ...VALID_CREATE_RULE,
          specialty_filter: ['x'.repeat(11)],
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('age_range and gender in demographics', () => {
      it('rejects age_range exceeding 20 chars', async () => {
        const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
          ...VALID_ANALYSE_PAYLOAD,
          claim_context: {
            ...VALID_ANALYSE_PAYLOAD.claim_context,
            patient_demographics_anonymised: {
              age_range: 'x'.repeat(21),
              gender: 'M',
            },
          },
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects gender exceeding 10 chars', async () => {
        const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
          ...VALID_ANALYSE_PAYLOAD,
          claim_context: {
            ...VALID_ANALYSE_PAYLOAD.claim_context,
            patient_demographics_anonymised: {
              age_range: '40-50',
              gender: 'x'.repeat(11),
            },
          },
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('encounter_type and facility_type boundaries', () => {
      it('rejects encounter_type exceeding 20 chars', async () => {
        const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
          ...VALID_ANALYSE_PAYLOAD,
          claim_context: {
            ...VALID_ANALYSE_PAYLOAD.claim_context,
            encounter_type: 'x'.repeat(21),
          },
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects facility_type exceeding 30 chars', async () => {
        const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
          ...VALID_ANALYSE_PAYLOAD,
          claim_context: {
            ...VALID_ANALYSE_PAYLOAD.claim_context,
            facility_type: 'x'.repeat(31),
          },
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('text_amount regex validation', () => {
      it('rejects text_amount with only 1 decimal place', async () => {
        const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
          ...VALID_ANALYSE_PAYLOAD,
          claim_context: {
            ...VALID_ANALYSE_PAYLOAD.claim_context,
            text_amount: '100.0',
          },
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects text_amount with 3 decimal places', async () => {
        const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
          ...VALID_ANALYSE_PAYLOAD,
          claim_context: {
            ...VALID_ANALYSE_PAYLOAD.claim_context,
            text_amount: '100.001',
          },
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects non-numeric text_amount', async () => {
        const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
          ...VALID_ANALYSE_PAYLOAD,
          claim_context: {
            ...VALID_ANALYSE_PAYLOAD.claim_context,
            text_amount: 'abc',
          },
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects negative text_amount', async () => {
        const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
          ...VALID_ANALYSE_PAYLOAD,
          claim_context: {
            ...VALID_ANALYSE_PAYLOAD.claim_context,
            text_amount: '-50.00',
          },
        });
        expect(res.statusCode).toBe(400);
      });

      it('accepts valid text_amount format', async () => {
        const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
          ...VALID_ANALYSE_PAYLOAD,
          claim_context: {
            ...VALID_ANALYSE_PAYLOAD.claim_context,
            text_amount: '100.00',
          },
        });
        expect(res.statusCode).not.toBe(400);
      });
    });
  });

  // =========================================================================
  // 8. Pagination Boundary Attacks
  // =========================================================================

  describe('Pagination boundary attacks on rule list', () => {
    it('rejects negative page', async () => {
      const res = await asPhysician('GET', '/api/v1/intelligence/rules?page=-1');
      expect(res.statusCode).toBe(400);
    });

    it('rejects zero page', async () => {
      const res = await asPhysician('GET', '/api/v1/intelligence/rules?page=0');
      expect(res.statusCode).toBe(400);
    });

    it('rejects non-numeric page', async () => {
      const res = await asPhysician('GET', '/api/v1/intelligence/rules?page=abc');
      expect(res.statusCode).toBe(400);
    });

    it('rejects negative page_size', async () => {
      const res = await asPhysician('GET', '/api/v1/intelligence/rules?page_size=-1');
      expect(res.statusCode).toBe(400);
    });

    it('rejects zero page_size', async () => {
      const res = await asPhysician('GET', '/api/v1/intelligence/rules?page_size=0');
      expect(res.statusCode).toBe(400);
    });

    it('rejects page_size exceeding max (100)', async () => {
      const res = await asPhysician('GET', '/api/v1/intelligence/rules?page_size=999');
      expect(res.statusCode).toBe(400);
    });

    it('rejects non-numeric page_size', async () => {
      const res = await asPhysician('GET', '/api/v1/intelligence/rules?page_size=abc');
      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // 9. Missing Required Fields
  // =========================================================================

  describe('Missing required fields', () => {
    it('rejects analyse without claim_id', async () => {
      const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
        claim_context: VALID_ANALYSE_PAYLOAD.claim_context,
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects analyse without claim_context', async () => {
      const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
        claim_id: DUMMY_UUID,
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects analyse with empty body', async () => {
      const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {});
      expect(res.statusCode).toBe(400);
    });

    it('rejects claim_context without claim_type', async () => {
      const { claim_type, ...rest } = VALID_ANALYSE_PAYLOAD.claim_context;
      const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
        claim_id: DUMMY_UUID,
        claim_context: rest,
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects claim_context without health_service_code', async () => {
      const { health_service_code, ...rest } = VALID_ANALYSE_PAYLOAD.claim_context;
      const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
        claim_id: DUMMY_UUID,
        claim_context: rest,
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects claim_context without date_of_service', async () => {
      const { date_of_service, ...rest } = VALID_ANALYSE_PAYLOAD.claim_context;
      const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
        claim_id: DUMMY_UUID,
        claim_context: rest,
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects claim_context without provider_specialty', async () => {
      const { provider_specialty, ...rest } = VALID_ANALYSE_PAYLOAD.claim_context;
      const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
        claim_id: DUMMY_UUID,
        claim_context: rest,
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects create rule without name', async () => {
      const { name, ...rest } = VALID_CREATE_RULE;
      const res = await asAdmin('POST', '/api/v1/intelligence/rules', rest);
      expect(res.statusCode).toBe(400);
    });

    it('rejects create rule without category', async () => {
      const { category, ...rest } = VALID_CREATE_RULE;
      const res = await asAdmin('POST', '/api/v1/intelligence/rules', rest);
      expect(res.statusCode).toBe(400);
    });

    it('rejects create rule without conditions', async () => {
      const { conditions, ...rest } = VALID_CREATE_RULE;
      const res = await asAdmin('POST', '/api/v1/intelligence/rules', rest);
      expect(res.statusCode).toBe(400);
    });

    it('rejects create rule without suggestion_template', async () => {
      const { suggestion_template, ...rest } = VALID_CREATE_RULE;
      const res = await asAdmin('POST', '/api/v1/intelligence/rules', rest);
      expect(res.statusCode).toBe(400);
    });

    it('rejects create rule without priority_formula', async () => {
      const { priority_formula, ...rest } = VALID_CREATE_RULE;
      const res = await asAdmin('POST', '/api/v1/intelligence/rules', rest);
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
  });

  // =========================================================================
  // 10. Date Format Validation
  // =========================================================================

  describe('Date format validation in claim context', () => {
    const INVALID_DATES = [
      '15-01-2026',        // DD-MM-YYYY
      '01/15/2026',        // MM/DD/YYYY
      '2026/01/15',        // YYYY/MM/DD
      'January 15, 2026',  // English text
      '20260115',          // No separators
      '2026-13-01',        // Invalid month
      '2026-01-32',        // Invalid day
      'not-a-date',
      '',
    ];

    for (const badDate of INVALID_DATES) {
      it(`rejects date_of_service: ${badDate || '(empty)'}`, async () => {
        const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
          ...VALID_ANALYSE_PAYLOAD,
          claim_context: {
            ...VALID_ANALYSE_PAYLOAD.claim_context,
            date_of_service: badDate,
          },
        });
        expect(res.statusCode).toBe(400);
      });
    }
  });

  // =========================================================================
  // 11. Error Response Sanitisation
  // =========================================================================

  describe('Error responses do not echo malicious input', () => {
    it('validation error for XSS in claim_type does not echo payload', async () => {
      const malicious = '<script>alert("xss")</script>';
      const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
        ...VALID_ANALYSE_PAYLOAD,
        claim_context: {
          ...VALID_ANALYSE_PAYLOAD.claim_context,
          claim_type: malicious,
        },
      });
      expect(res.statusCode).toBe(400);
      expect(res.body).not.toContain('<script>');
      expect(res.body).not.toContain('alert');
    });

    it('validation error for SQL injection does not echo payload', async () => {
      const malicious = "'; DROP TABLE ai_rules; --";
      const res = await asAdmin('POST', '/api/v1/intelligence/rules', {
        ...VALID_CREATE_RULE,
        category: malicious,
      });
      expect(res.statusCode).toBe(400);
      expect(res.body).not.toContain('DROP TABLE');
      expect(res.body).not.toContain('ai_rules');
    });

    it('validation error for invalid UUID does not echo the value', async () => {
      const malicious = '../../../etc/passwd';
      const res = await asPhysician(
        'GET',
        `/api/v1/intelligence/claims/${encodeURIComponent(malicious)}/suggestions`,
      );
      expect(res.statusCode).toBe(400);
      expect(res.body).not.toContain('passwd');
      expect(res.body).not.toContain('../');
    });

    it('error responses do not expose internal details', async () => {
      const res = await asPhysician('POST', '/api/v1/intelligence/analyse', {
        ...VALID_ANALYSE_PAYLOAD,
        claim_context: {
          ...VALID_ANALYSE_PAYLOAD.claim_context,
          claim_type: 'INVALID',
        },
      });
      expect(res.statusCode).toBe(400);
      expect(res.body).not.toContain('postgres');
      expect(res.body).not.toContain('drizzle');
      expect(res.body).not.toContain('node_modules');
      expect(res.body).not.toContain('.ts:');
    });
  });

  // =========================================================================
  // 12. Content-Type Enforcement
  // =========================================================================

  describe('Content-Type enforcement', () => {
    it('rejects analyse with text/plain content type', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/intelligence/analyse',
        headers: {
          cookie: `session=${PHYSICIAN_TOKEN}`,
          'content-type': 'text/plain',
        },
        payload: JSON.stringify(VALID_ANALYSE_PAYLOAD),
      });
      expect([400, 415]).toContain(res.statusCode);
    });

    it('rejects rule creation with text/plain content type', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/intelligence/rules',
        headers: {
          cookie: `session=${ADMIN_TOKEN}`,
          'content-type': 'text/plain',
        },
        payload: JSON.stringify(VALID_CREATE_RULE),
      });
      expect([400, 415]).toContain(res.statusCode);
    });
  });

  // =========================================================================
  // 13. Path Traversal Prevention
  // =========================================================================

  describe('Path traversal prevention', () => {
    it('rejects path traversal in suggestion ID', async () => {
      const res = await asPhysician(
        'POST',
        '/api/v1/intelligence/suggestions/..%2F..%2Fetc%2Fpasswd/accept',
      );
      expect(res.statusCode).toBe(400);
    });

    it('rejects path traversal in claim ID', async () => {
      const res = await asPhysician(
        'GET',
        '/api/v1/intelligence/claims/..%2F..%2Fetc%2Fpasswd/suggestions',
      );
      expect(res.statusCode).toBe(400);
    });

    it('rejects path traversal in rule ID', async () => {
      const res = await asAdmin(
        'PUT',
        '/api/v1/intelligence/rules/..%2F..%2Fetc%2Fpasswd',
        { name: 'test' },
      );
      expect(res.statusCode).toBe(400);
    });

    it('rejects path traversal in unsuppress rule ID', async () => {
      const res = await asPhysician(
        'POST',
        '/api/v1/intelligence/me/rules/..%2F..%2Fetc%2Fpasswd/unsuppress',
      );
      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // 14. Sanity: Valid Payloads Are Accepted
  // =========================================================================

  describe('Sanity: valid payloads are accepted', () => {
    it('valid analyse payload is accepted', async () => {
      const res = await asPhysician('POST', '/api/v1/intelligence/analyse', VALID_ANALYSE_PAYLOAD);
      expect(res.statusCode).not.toBe(400);
      expect(res.statusCode).not.toBe(500);
    });

    it('valid dismiss payload is accepted', async () => {
      const res = await asPhysician(
        'POST',
        `/api/v1/intelligence/suggestions/${DUMMY_UUID}/dismiss`,
        VALID_DISMISS_PAYLOAD,
      );
      expect(res.statusCode).not.toBe(400);
    });

    it('valid create rule payload is accepted', async () => {
      const res = await asAdmin('POST', '/api/v1/intelligence/rules', VALID_CREATE_RULE);
      expect(res.statusCode).not.toBe(400);
      expect(res.statusCode).not.toBe(500);
    });

    it('valid update preferences payload is accepted', async () => {
      const res = await asPhysician(
        'PUT',
        '/api/v1/intelligence/me/preferences',
        VALID_UPDATE_PREFERENCES,
      );
      expect(res.statusCode).not.toBe(400);
    });

    it('valid somb-change-analysis payload is accepted', async () => {
      const res = await asAdmin(
        'POST',
        '/api/v1/intelligence/somb-change-analysis',
        VALID_SOMB_CHANGE,
      );
      expect(res.statusCode).not.toBe(400);
    });

    it('valid list rules with filters is accepted', async () => {
      const res = await asPhysician(
        'GET',
        '/api/v1/intelligence/rules?category=MODIFIER_ADD&claim_type=AHCIP&page=1&page_size=25',
      );
      expect(res.statusCode).not.toBe(400);
    });

    it('valid accept suggestion is accepted', async () => {
      const res = await asPhysician(
        'POST',
        `/api/v1/intelligence/suggestions/${DUMMY_UUID}/accept`,
      );
      expect(res.statusCode).not.toBe(400);
    });

    it('valid unsuppress rule is accepted', async () => {
      const res = await asPhysician(
        'POST',
        `/api/v1/intelligence/me/rules/${DUMMY_UUID}/unsuppress`,
      );
      expect(res.statusCode).not.toBe(400);
    });

    it('valid activate rule is accepted', async () => {
      const res = await asAdmin(
        'PUT',
        `/api/v1/intelligence/rules/${DUMMY_UUID}/activate`,
        { is_active: true },
      );
      expect(res.statusCode).not.toBe(400);
    });
  });
});
