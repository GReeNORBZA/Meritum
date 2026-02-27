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
import { claimRoutes } from '../../../src/domains/claim/claim.routes.js';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { type ClaimHandlerDeps } from '../../../src/domains/claim/claim.handlers.js';
import {
  type SessionManagementDeps,
  hashToken,
} from '../../../src/domains/iam/iam.service.js';
import { randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Fixed test identity
// ---------------------------------------------------------------------------

const P1_SESSION_TOKEN = randomBytes(32).toString('hex');
const P1_SESSION_TOKEN_HASH = hashToken(P1_SESSION_TOKEN);
const P1_USER_ID = '11111111-1111-0000-0000-000000000001';
const P1_SESSION_ID = '11111111-1111-0000-0000-000000000011';

const VALID_UUID = '99999999-9999-9999-9999-999999999999';
const PLACEHOLDER_UUID = '00000000-0000-0000-0000-000000000001';

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
  return { appendAuditLog: vi.fn(async () => {}) };
}

function createMockEvents() {
  return { emit: vi.fn() };
}

// ---------------------------------------------------------------------------
// Stub claim handler deps
// ---------------------------------------------------------------------------

function createStubHandlerDeps(): ClaimHandlerDeps {
  return {
    serviceDeps: {
      repo: {
        createClaim: vi.fn(async () => ({})),
        findClaimById: vi.fn(async () => undefined),
        updateClaim: vi.fn(async () => ({})),
        softDeleteClaim: vi.fn(async () => false),
        listClaims: vi.fn(async () => ({ data: [], pagination: { total: 0, page: 1, pageSize: 25, hasMore: false } })),
        countClaimsByState: vi.fn(async () => []),
        findClaimsApproachingDeadline: vi.fn(async () => []),
        transitionState: vi.fn(async () => ({})),
        classifyClaim: vi.fn(async () => ({})),
        updateValidationResult: vi.fn(async () => ({})),
        updateAiSuggestions: vi.fn(async () => ({})),
        updateDuplicateAlert: vi.fn(async () => ({})),
        updateFlags: vi.fn(async () => ({})),
        createImportBatch: vi.fn(async () => ({})),
        findImportBatchById: vi.fn(async () => undefined),
        updateImportBatchStatus: vi.fn(async () => ({})),
        findDuplicateImportByHash: vi.fn(async () => undefined),
        listImportBatches: vi.fn(async () => ({ data: [], pagination: { total: 0, page: 1, pageSize: 25, hasMore: false } })),
        findClaimsForBatchAssembly: vi.fn(async () => []),
        bulkTransitionState: vi.fn(async () => []),
        createTemplate: vi.fn(async () => ({})),
        findTemplateById: vi.fn(async () => undefined),
        updateTemplate: vi.fn(async () => ({})),
        deleteTemplate: vi.fn(async () => {}),
        listTemplates: vi.fn(async () => []),
        createShift: vi.fn(async () => ({})),
        findShiftById: vi.fn(async () => undefined),
        updateShiftStatus: vi.fn(async () => ({})),
        updateShiftTimes: vi.fn(async () => ({})),
        incrementEncounterCount: vi.fn(async () => ({})),
        listShifts: vi.fn(async () => ({ data: [], pagination: { total: 0, page: 1, pageSize: 25, hasMore: false } })),
        findClaimsByShift: vi.fn(async () => []),
        createExportRecord: vi.fn(async () => ({})),
        findExportById: vi.fn(async () => undefined),
        updateExportStatus: vi.fn(async () => ({})),
        appendClaimAudit: vi.fn(async () => ({})),
        getClaimAuditHistory: vi.fn(async () => []),
        getClaimAuditHistoryPaginated: vi.fn(async () => ({ data: [], pagination: { total: 0, page: 1, pageSize: 25, hasMore: false } })),
        // Claim template extension methods
        listClaimTemplates: vi.fn(async () => []),
        findClaimTemplateById: vi.fn(async () => undefined),
        createClaimTemplate: vi.fn(async (data: any) => ({ templateId: '00000000-0000-0000-0000-000000000099', ...data })),
        updateClaimTemplate: vi.fn(async () => undefined),
        deleteClaimTemplate: vi.fn(async () => false),
        incrementClaimTemplateUsage: vi.fn(async () => {}),
        // Justification extension methods
        createJustification: vi.fn(async (data: any) => ({ justificationId: '00000000-0000-0000-0000-000000000098', ...data })),
        getJustificationForClaim: vi.fn(async () => null),
        findJustificationById: vi.fn(async () => undefined),
        updateJustification: vi.fn(async () => ({})),
        searchJustificationHistory: vi.fn(async () => ({ data: [], pagination: { total: 0, page: 1, pageSize: 20, hasMore: false } })),
        // Referrer extension methods
        getRecentReferrers: vi.fn(async () => []),
        upsertRecentReferrer: vi.fn(async () => ({})),
        evictOldestReferrers: vi.fn(async () => {}),
      } as any,
      providerCheck: { isActive: vi.fn(async () => true), getRegistrationDate: vi.fn(async () => null) },
      patientCheck: { exists: vi.fn(async () => true) },
      pathwayValidators: {},
      referenceDataVersion: { getCurrentVersion: vi.fn(async () => '1.0') },
      notificationEmitter: { emit: vi.fn(async () => {}) },
      submissionPreference: { getSubmissionMode: vi.fn(async () => 'MANUAL') },
      facilityCheck: { belongsToPhysician: vi.fn(async () => true) },
      afterHoursPremiumCalculators: {},
      explanatoryCodeLookup: { getExplanatoryCode: vi.fn(async () => null) },
    } as any,
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

  await testApp.register(claimRoutes, { deps: handlerDeps });
  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function authedRequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Claim Extension Input Validation (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    users = [];
    sessions = [];

    users.push({
      userId: P1_USER_ID,
      email: 'physician@example.com',
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
  });

  // =========================================================================
  // SQL injection attempts in template names
  // =========================================================================

  describe('SQL injection in template names', () => {
    it('SQL injection in template name is treated as literal string (not rejected by schema)', async () => {
      const res = await authedRequest('POST', '/api/v1/claims/templates', {
        name: "'; DROP TABLE claims; --",
        claim_type: 'AHCIP',
        line_items: [{ health_service_code: '03.04A', calls: 1 }],
      });
      // Should not return 500 (SQL execution) -- either 200/201 (stored as literal) or 400
      expect(res.statusCode).not.toBe(500);
    });

    it('SQL injection in template description', async () => {
      const res = await authedRequest('POST', '/api/v1/claims/templates', {
        name: 'Normal Name',
        description: "1' OR '1'='1",
        claim_type: 'AHCIP',
        line_items: [{ health_service_code: '03.04A', calls: 1 }],
      });
      expect(res.statusCode).not.toBe(500);
    });

    it('SQL UNION injection in template update', async () => {
      const res = await authedRequest('PUT', `/api/v1/claims/templates/${PLACEHOLDER_UUID}`, {
        name: "' UNION SELECT * FROM sessions --",
      });
      expect(res.statusCode).not.toBe(500);
    });
  });

  // =========================================================================
  // SQL injection in search queries
  // =========================================================================

  describe('SQL injection in query parameters', () => {
    it('SQL injection in template_type query param', async () => {
      const res = await authedRequest('GET', "/api/v1/claims/templates?template_type=' OR 1=1 --");
      // Zod enum validation should reject invalid enum value
      expect(res.statusCode).toBe(400);
    });

    it('SQL injection in claim_type query param for templates', async () => {
      const res = await authedRequest('GET', "/api/v1/claims/templates?claim_type=' UNION SELECT --");
      expect(res.statusCode).toBe(400);
    });

    it('SQL injection in scenario query param for justification history', async () => {
      const res = await authedRequest('GET', "/api/v1/claims/justifications/history?scenario='; DROP TABLE justifications; --");
      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // XSS in justification text
  // =========================================================================

  describe('XSS in justification text', () => {
    it('Script tags in justification_text do not cause 500', async () => {
      const res = await authedRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/justification`, {
        claim_id: PLACEHOLDER_UUID,
        scenario: 'UNLISTED_PROCEDURE',
        justification_text: '<script>alert("xss")</script> This is a valid justification text for testing.',
      });
      // Should not cause server error -- either stored as-is (404 for missing claim) or accepted
      expect(res.statusCode).not.toBe(500);
    });

    it('Event handler XSS in justification_text', async () => {
      const res = await authedRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/justification`, {
        claim_id: PLACEHOLDER_UUID,
        scenario: 'ADDITIONAL_COMPENSATION',
        justification_text: '<img onerror="fetch(evil.com)" src=x> This procedure needs extra compensation.',
      });
      expect(res.statusCode).not.toBe(500);
    });

    it('XSS in template name', async () => {
      const res = await authedRequest('POST', '/api/v1/claims/templates', {
        name: '<img src=x onerror=alert(1)>',
        claim_type: 'AHCIP',
        line_items: [{ health_service_code: '03.04A', calls: 1 }],
      });
      expect(res.statusCode).not.toBe(500);
    });

    it('XSS in referrer name', async () => {
      const res = await authedRequest('POST', '/api/v1/claims/referrers/recent', {
        referrer_cpsa: '12345',
        referrer_name: '<script>document.cookie</script>',
      });
      expect(res.statusCode).not.toBe(500);
    });
  });

  // =========================================================================
  // Non-UUID params -> 400
  // =========================================================================

  describe('Non-UUID params return 400', () => {
    it('Non-UUID in template id param (PUT)', async () => {
      const res = await authedRequest('PUT', '/api/v1/claims/templates/not-a-uuid', {
        name: 'Updated',
      });
      expect(res.statusCode).toBe(400);
    });

    it('Non-UUID in template id param (DELETE)', async () => {
      const res = await authedRequest('DELETE', '/api/v1/claims/templates/not-a-uuid');
      expect(res.statusCode).toBe(400);
    });

    it('Non-UUID in template id param (apply)', async () => {
      const res = await authedRequest('POST', '/api/v1/claims/templates/not-a-uuid/apply', {
        patient_id: PLACEHOLDER_UUID,
        date_of_service: '2026-01-15',
      });
      expect(res.statusCode).toBe(400);
    });

    it('Non-UUID in claim id param (justification)', async () => {
      const res = await authedRequest('POST', '/api/v1/claims/not-a-uuid/justification', {
        claim_id: PLACEHOLDER_UUID,
        scenario: 'UNLISTED_PROCEDURE',
        justification_text: 'This procedure requires a justification for test.',
      });
      expect(res.statusCode).toBe(400);
    });

    it('Non-UUID in justification id param (save-personal)', async () => {
      const res = await authedRequest('POST', '/api/v1/claims/justifications/not-a-uuid/save-personal');
      expect(res.statusCode).toBe(400);
    });

    it('Numeric ID instead of UUID in template param', async () => {
      const res = await authedRequest('DELETE', '/api/v1/claims/templates/12345');
      expect(res.statusCode).toBe(400);
    });

    it('Path traversal attempt in template param', async () => {
      const res = await authedRequest('DELETE', '/api/v1/claims/templates/../../../etc/passwd');
      // Either 400 (validation) or 404 (route not found)
      expect([400, 404]).toContain(res.statusCode);
    });
  });

  // =========================================================================
  // Type coercion attacks
  // =========================================================================

  describe('Type coercion attacks', () => {
    it('Array instead of string for template name', async () => {
      const res = await authedRequest('POST', '/api/v1/claims/templates', {
        name: ['evil', 'name'],
        claim_type: 'AHCIP',
        line_items: [{ health_service_code: '03.04A', calls: 1 }],
      });
      expect(res.statusCode).toBe(400);
    });

    it('Number instead of string for referrer_cpsa', async () => {
      const res = await authedRequest('POST', '/api/v1/claims/referrers/recent', {
        referrer_cpsa: 12345,
        referrer_name: 'Dr. Smith',
      });
      // Zod may coerce or reject -- should not be 500
      expect(res.statusCode).not.toBe(500);
    });

    it('Boolean instead of string for justification_text', async () => {
      const res = await authedRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/justification`, {
        claim_id: PLACEHOLDER_UUID,
        scenario: 'UNLISTED_PROCEDURE',
        justification_text: true,
      });
      expect(res.statusCode).toBe(400);
    });

    it('Object instead of array for codes in bundling check', async () => {
      const res = await authedRequest('POST', '/api/v1/claims/bundling/check', {
        codes: { 0: '03.04A', 1: '03.04B' },
        claim_type: 'AHCIP',
      });
      expect(res.statusCode).toBe(400);
    });

    it('Null for required field in create template', async () => {
      const res = await authedRequest('POST', '/api/v1/claims/templates', {
        name: null,
        claim_type: 'AHCIP',
        line_items: [{ health_service_code: '03.04A', calls: 1 }],
      });
      expect(res.statusCode).toBe(400);
    });

    it('Empty array for line_items in create template', async () => {
      const res = await authedRequest('POST', '/api/v1/claims/templates', {
        name: 'Valid Name',
        claim_type: 'AHCIP',
        line_items: [],
      });
      // Zod min(1) constraint on line_items array
      expect(res.statusCode).toBe(400);
    });

    it('Empty array for codes in bundling check', async () => {
      const res = await authedRequest('POST', '/api/v1/claims/bundling/check', {
        codes: [],
        claim_type: 'AHCIP',
      });
      // Zod min(2) constraint on codes array
      expect(res.statusCode).toBe(400);
    });

    it('Single code for bundling check (needs min 2)', async () => {
      const res = await authedRequest('POST', '/api/v1/claims/bundling/check', {
        codes: ['03.04A'],
        claim_type: 'AHCIP',
      });
      expect(res.statusCode).toBe(400);
    });

    it('Empty procedure_codes array for anesthesia', async () => {
      const res = await authedRequest('POST', '/api/v1/claims/anesthesia/calculate', {
        procedure_codes: [],
      });
      // Zod min(1) constraint on procedure_codes array
      expect(res.statusCode).toBe(400);
    });

    it('String instead of number for duration_minutes in anesthesia', async () => {
      const res = await authedRequest('POST', '/api/v1/claims/anesthesia/calculate', {
        procedure_codes: ['20.11A'],
        duration_minutes: 'sixty',
      });
      expect(res.statusCode).toBe(400);
    });

    it('Invalid claim_type enum value', async () => {
      const res = await authedRequest('POST', '/api/v1/claims/templates', {
        name: 'Valid Name',
        claim_type: 'INVALID_TYPE',
        line_items: [{ health_service_code: '03.04A', calls: 1 }],
      });
      expect(res.statusCode).toBe(400);
    });

    it('Invalid scenario enum value for justification', async () => {
      const res = await authedRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/justification`, {
        claim_id: PLACEHOLDER_UUID,
        scenario: 'INVALID_SCENARIO',
        justification_text: 'This is a justification text that is long enough for testing.',
      });
      expect(res.statusCode).toBe(400);
    });

    it('Justification text too short (min 10 chars)', async () => {
      const res = await authedRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/justification`, {
        claim_id: PLACEHOLDER_UUID,
        scenario: 'UNLISTED_PROCEDURE',
        justification_text: 'short',
      });
      expect(res.statusCode).toBe(400);
    });

    it('Template name too long (max 100 chars)', async () => {
      const res = await authedRequest('POST', '/api/v1/claims/templates', {
        name: 'A'.repeat(101),
        claim_type: 'AHCIP',
        line_items: [{ health_service_code: '03.04A', calls: 1 }],
      });
      expect(res.statusCode).toBe(400);
    });

    it('Non-UUID in template_ids array for reorder', async () => {
      const res = await authedRequest('PUT', '/api/v1/claims/templates/reorder', {
        template_ids: ['not-a-uuid'],
      });
      expect(res.statusCode).toBe(400);
    });

    it('Empty template_ids array for reorder', async () => {
      const res = await authedRequest('PUT', '/api/v1/claims/templates/reorder', {
        template_ids: [],
      });
      // Zod min(1) constraint
      expect(res.statusCode).toBe(400);
    });

    it('Non-UUID patient_id in apply template', async () => {
      const res = await authedRequest('POST', `/api/v1/claims/templates/${PLACEHOLDER_UUID}/apply`, {
        patient_id: 'not-a-uuid',
        date_of_service: '2026-01-15',
      });
      expect(res.statusCode).toBe(400);
    });

    it('Invalid date format in apply template', async () => {
      const res = await authedRequest('POST', `/api/v1/claims/templates/${PLACEHOLDER_UUID}/apply`, {
        patient_id: PLACEHOLDER_UUID,
        date_of_service: '15/01/2026',
      });
      expect(res.statusCode).toBe(400);
    });

    it('Invalid time format in anesthesia calculate', async () => {
      const res = await authedRequest('POST', '/api/v1/claims/anesthesia/calculate', {
        procedure_codes: ['20.11A'],
        start_time: '25:00',
        end_time: '26:00',
      });
      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // Prototype pollution prevention
  // =========================================================================

  describe('Prototype pollution prevention', () => {
    it('__proto__ key in template body is ignored or rejected', async () => {
      const res = await authedRequest('POST', '/api/v1/claims/templates', {
        name: 'Normal Template',
        claim_type: 'AHCIP',
        line_items: [{ health_service_code: '03.04A', calls: 1 }],
        __proto__: { isAdmin: true },
      });
      // Should not crash -- Fastify strips __proto__ by default
      expect(res.statusCode).not.toBe(500);
    });

    it('constructor.prototype pollution attempt', async () => {
      const res = await authedRequest('POST', '/api/v1/claims/bundling/check', {
        codes: ['03.04A', '03.04B'],
        claim_type: 'AHCIP',
        constructor: { prototype: { isAdmin: true } },
      });
      expect(res.statusCode).not.toBe(500);
    });
  });
});
