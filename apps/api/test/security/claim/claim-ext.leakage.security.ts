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
// Fixed test identities — Two isolated physicians
// ---------------------------------------------------------------------------

// Physician 1
const P1_SESSION_TOKEN = randomBytes(32).toString('hex');
const P1_SESSION_TOKEN_HASH = hashToken(P1_SESSION_TOKEN);
const P1_USER_ID = '11111111-1111-0000-0000-000000000001';
const P1_PROVIDER_ID = P1_USER_ID;
const P1_SESSION_ID = '11111111-1111-0000-0000-000000000011';

// Physician 2
const P2_SESSION_TOKEN = randomBytes(32).toString('hex');
const P2_SESSION_TOKEN_HASH = hashToken(P2_SESSION_TOKEN);
const P2_USER_ID = '22222222-2222-0000-0000-000000000002';
const P2_PROVIDER_ID = P2_USER_ID;
const P2_SESSION_ID = '22222222-2222-0000-0000-000000000022';

// ---------------------------------------------------------------------------
// Test data IDs
// ---------------------------------------------------------------------------

const P1_CLAIM_ID = 'aaaa1111-0000-0000-0000-000000000001';
const P1_PATIENT_ID = 'bbbb1111-0000-0000-0000-000000000001';
const P1_TEMPLATE_ID = 'dddd1111-0000-0000-0000-000000000001';
const P1_JUSTIFICATION_ID = 'eeee1111-0000-0000-0000-000000000001';

const P2_TEMPLATE_ID = 'dddd2222-0000-0000-0000-000000000001';

const NONEXISTENT_UUID = '99999999-9999-9999-9999-999999999999';

// Sensitive PHI data that must never leak
const P1_PATIENT_PHN = '123456789';
const P1_PATIENT_NAME = 'Alice Smith';

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

// Stores
const claimStore: Record<string, any> = {};
const claimTemplateStore: Record<string, any> = {};
const justificationStore: Record<string, any> = {};

// ---------------------------------------------------------------------------
// Seed test data
// ---------------------------------------------------------------------------

function seedTestData() {
  Object.keys(claimStore).forEach((k) => delete claimStore[k]);
  Object.keys(claimTemplateStore).forEach((k) => delete claimTemplateStore[k]);
  Object.keys(justificationStore).forEach((k) => delete justificationStore[k]);

  claimStore[P1_CLAIM_ID] = {
    claimId: P1_CLAIM_ID,
    physicianId: P1_PROVIDER_ID,
    patientId: P1_PATIENT_ID,
    patientPhn: P1_PATIENT_PHN,
    patientName: P1_PATIENT_NAME,
    claimType: 'AHCIP',
    state: 'DRAFT',
  };

  claimTemplateStore[P1_TEMPLATE_ID] = {
    templateId: P1_TEMPLATE_ID,
    physicianId: P1_PROVIDER_ID,
    name: 'P1 Template',
    claimType: 'AHCIP',
    lineItems: [{ health_service_code: '03.04A', calls: 1 }],
  };

  claimTemplateStore[P2_TEMPLATE_ID] = {
    templateId: P2_TEMPLATE_ID,
    physicianId: P2_PROVIDER_ID,
    name: 'P2 Template',
    claimType: 'AHCIP',
    lineItems: [{ health_service_code: '10.01A', calls: 1 }],
  };

  justificationStore[P1_JUSTIFICATION_ID] = {
    justificationId: P1_JUSTIFICATION_ID,
    claimId: P1_CLAIM_ID,
    physicianId: P1_PROVIDER_ID,
    scenario: 'UNLISTED_PROCEDURE',
    justificationText: 'P1 justification text.',
    createdBy: P1_USER_ID,
  };
}

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
// Scoped claim repo with PHI in some fields
// ---------------------------------------------------------------------------

function createScopedClaimRepo() {
  return {
    createClaim: vi.fn(async () => ({})),
    findClaimById: vi.fn(async (claimId: string, physicianId: string) => {
      const claim = claimStore[claimId];
      if (!claim || claim.physicianId !== physicianId) return undefined;
      return claim;
    }),
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

    // Extension methods
    listClaimTemplates: vi.fn(async (physicianId: string) => {
      return Object.values(claimTemplateStore).filter((t: any) => t.physicianId === physicianId);
    }),
    findClaimTemplateById: vi.fn(async (templateId: string, physicianId: string) => {
      const t = claimTemplateStore[templateId];
      if (!t || t.physicianId !== physicianId) return undefined;
      return t;
    }),
    createClaimTemplate: vi.fn(async (data: any) => ({ templateId: crypto.randomUUID(), ...data })),
    updateClaimTemplate: vi.fn(async (templateId: string, physicianId: string, data: any) => {
      const t = claimTemplateStore[templateId];
      if (!t || t.physicianId !== physicianId) return undefined;
      return { ...t, ...data };
    }),
    deleteClaimTemplate: vi.fn(async (templateId: string, physicianId: string) => {
      const t = claimTemplateStore[templateId];
      if (!t || t.physicianId !== physicianId) return false;
      delete claimTemplateStore[templateId];
      return true;
    }),
    incrementClaimTemplateUsage: vi.fn(async () => {}),

    getJustificationForClaim: vi.fn(async (claimId: string, physicianId: string) => {
      return Object.values(justificationStore).find(
        (j: any) => j.claimId === claimId && j.physicianId === physicianId,
      ) ?? null;
    }),
    createJustification: vi.fn(async (data: any) => ({ justificationId: crypto.randomUUID(), ...data })),
    findJustificationById: vi.fn(async (justificationId: string, physicianId: string) => {
      const j = justificationStore[justificationId];
      if (!j || j.physicianId !== physicianId) return undefined;
      return j;
    }),
    updateJustification: vi.fn(async () => ({})),
    searchJustificationHistory: vi.fn(async (physicianId: string) => {
      const data = Object.values(justificationStore).filter((j: any) => j.physicianId === physicianId);
      return { data, pagination: { total: data.length, page: 1, pageSize: 20, hasMore: false } };
    }),

    getRecentReferrers: vi.fn(async () => []),
    upsertRecentReferrer: vi.fn(async () => ({})),
    evictOldestReferrers: vi.fn(async () => {}),
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

  const handlerDeps: ClaimHandlerDeps = {
    serviceDeps: {
      repo: createScopedClaimRepo() as any,
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

function p1Request(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function p2Request(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${P2_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function seedUsers() {
  users = [];
  sessions = [];

  users.push({
    userId: P1_USER_ID,
    email: 'physician1@example.com',
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

  users.push({
    userId: P2_USER_ID,
    email: 'physician2@example.com',
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
    sessionId: P2_SESSION_ID,
    userId: P2_USER_ID,
    tokenHash: P2_SESSION_TOKEN_HASH,
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

describe('Claim Extension Information Leakage Prevention (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    seedUsers();
    seedTestData();
  });

  // =========================================================================
  // Error responses don't echo PHN
  // =========================================================================

  describe('Error responses do not echo PHN or sensitive PHI', () => {
    it('404 for cross-tenant template does not contain PHN', async () => {
      const res = await p2Request('PUT', `/api/v1/claims/templates/${P1_TEMPLATE_ID}`, {
        name: 'Hijacked',
      });
      expect(res.statusCode).toBe(404);
      expect(res.body).not.toContain(P1_PATIENT_PHN);
      expect(res.body).not.toContain(P1_PATIENT_NAME);
    });

    it('404 for cross-tenant justification does not contain PHN', async () => {
      const res = await p2Request('GET', `/api/v1/claims/${P1_CLAIM_ID}/justification`);
      expect(res.statusCode).toBe(404);
      expect(res.body).not.toContain(P1_PATIENT_PHN);
      expect(res.body).not.toContain(P1_PATIENT_NAME);
    });

    it('400 validation error on bundling does not echo submitted PHN-like data', async () => {
      const res = await p1Request('POST', '/api/v1/claims/bundling/check', {
        codes: [],
        claim_type: 'AHCIP',
        patient_id: P1_PATIENT_PHN, // Not a UUID, should fail validation
      });
      expect(res.statusCode).toBe(400);
      // The error body should not echo back the PHN
      expect(res.body).not.toContain(P1_PATIENT_PHN);
    });

    it('400 validation error on template create does not echo sensitive input', async () => {
      const res = await p1Request('POST', '/api/v1/claims/templates', {
        name: P1_PATIENT_PHN,
        claim_type: 'INVALID',
        line_items: [],
      });
      expect(res.statusCode).toBe(400);
      // Should not echo back the PHN used as name
      expect(res.body).not.toContain(P1_PATIENT_PHN);
    });
  });

  // =========================================================================
  // No technology headers
  // =========================================================================

  describe('No technology-revealing headers', () => {
    it('GET /api/v1/claims/templates does not expose X-Powered-By', async () => {
      const res = await p1Request('GET', '/api/v1/claims/templates');
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('POST /api/v1/claims/bundling/check does not expose X-Powered-By', async () => {
      const res = await p1Request('POST', '/api/v1/claims/bundling/check', {
        codes: ['03.04A', '03.04B'],
        claim_type: 'AHCIP',
      });
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('POST /api/v1/claims/anesthesia/calculate does not expose X-Powered-By', async () => {
      const res = await p1Request('POST', '/api/v1/claims/anesthesia/calculate', {
        procedure_codes: ['20.11A'],
      });
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('404 response does not expose Server header with version info', async () => {
      const res = await p1Request('PUT', `/api/v1/claims/templates/${NONEXISTENT_UUID}`, {
        name: 'Does not exist',
      });
      const serverHeader = res.headers['server'];
      if (serverHeader) {
        expect(String(serverHeader)).not.toMatch(/express|fastify|node/i);
      }
    });
  });

  // =========================================================================
  // Cross-tenant 404 indistinguishable from missing
  // =========================================================================

  describe('Cross-tenant 404 indistinguishable from missing resource', () => {
    it('P2 accessing P1 template vs nonexistent template -- same error shape', async () => {
      const crossTenantRes = await p2Request('PUT', `/api/v1/claims/templates/${P1_TEMPLATE_ID}`, {
        name: 'Hijacked',
      });
      const missingRes = await p2Request('PUT', `/api/v1/claims/templates/${NONEXISTENT_UUID}`, {
        name: 'Missing',
      });

      expect(crossTenantRes.statusCode).toBe(404);
      expect(missingRes.statusCode).toBe(404);

      const crossTenantBody = JSON.parse(crossTenantRes.body);
      const missingBody = JSON.parse(missingRes.body);

      // Same error structure
      expect(Object.keys(crossTenantBody).sort()).toEqual(Object.keys(missingBody).sort());
      expect(crossTenantBody.error.code).toBe(missingBody.error.code);
    });

    it('P2 accessing P1 justification vs nonexistent -- same error shape', async () => {
      const crossTenantRes = await p2Request('GET', `/api/v1/claims/${P1_CLAIM_ID}/justification`);
      const missingRes = await p2Request('GET', `/api/v1/claims/${NONEXISTENT_UUID}/justification`);

      expect(crossTenantRes.statusCode).toBe(404);
      expect(missingRes.statusCode).toBe(404);

      const crossTenantBody = JSON.parse(crossTenantRes.body);
      const missingBody = JSON.parse(missingRes.body);

      expect(crossTenantBody.error.code).toBe(missingBody.error.code);
    });

    it('P2 save-personal for P1 justification vs nonexistent -- same error shape', async () => {
      const crossTenantRes = await p2Request('POST', `/api/v1/claims/justifications/${P1_JUSTIFICATION_ID}/save-personal`);
      const missingRes = await p2Request('POST', `/api/v1/claims/justifications/${NONEXISTENT_UUID}/save-personal`);

      expect(crossTenantRes.statusCode).toBe(404);
      expect(missingRes.statusCode).toBe(404);

      const crossTenantBody = JSON.parse(crossTenantRes.body);
      const missingBody = JSON.parse(missingRes.body);

      expect(crossTenantBody.error.code).toBe(missingBody.error.code);
    });

    it('P2 DELETE P1 template vs nonexistent -- same error shape', async () => {
      const crossTenantRes = await p2Request('DELETE', `/api/v1/claims/templates/${P1_TEMPLATE_ID}`);
      const missingRes = await p2Request('DELETE', `/api/v1/claims/templates/${NONEXISTENT_UUID}`);

      expect(crossTenantRes.statusCode).toBe(404);
      expect(missingRes.statusCode).toBe(404);

      const crossTenantBody = JSON.parse(crossTenantRes.body);
      const missingBody = JSON.parse(missingRes.body);

      expect(crossTenantBody.error.code).toBe(missingBody.error.code);
    });
  });

  // =========================================================================
  // No sensitive field leakage in responses
  // =========================================================================

  describe('No sensitive field leakage', () => {
    it('404 error response does not contain session_id or token_hash', async () => {
      const res = await p1Request('PUT', `/api/v1/claims/templates/${NONEXISTENT_UUID}`, {
        name: 'Does not exist',
      });
      expect(res.statusCode).toBe(404);
      expect(res.body).not.toContain('token_hash');
      expect(res.body).not.toContain('tokenHash');
      expect(res.body).not.toContain('session_id');
      expect(res.body).not.toContain('sessionId');
      expect(res.body).not.toContain('password');
    });

    it('Error response does not contain internal database column names', async () => {
      const res = await p1Request('POST', `/api/v1/claims/justifications/${NONEXISTENT_UUID}/save-personal`);
      expect(res.statusCode).toBe(404);
      expect(res.body).not.toContain('drizzle');
      expect(res.body).not.toContain('postgres');
      expect(res.body).not.toContain('pgTable');
    });

    it('Error response does not contain stack traces', async () => {
      const res = await p2Request('PUT', `/api/v1/claims/templates/${P1_TEMPLATE_ID}`, {
        name: 'Hijacked',
      });
      expect(res.statusCode).toBe(404);
      expect(res.body).not.toContain('at ');
      expect(res.body).not.toContain('.ts:');
      expect(res.body).not.toContain('node_modules');
    });

    it('Bundling check response does not contain patient PHI', async () => {
      const res = await p1Request('POST', '/api/v1/claims/bundling/check', {
        codes: ['03.04A', '03.04B'],
        claim_type: 'AHCIP',
      });
      expect(res.statusCode).toBe(200);
      expect(res.body).not.toContain(P1_PATIENT_PHN);
      expect(res.body).not.toContain(P1_PATIENT_NAME);
    });

    it('Anesthesia calculate response does not contain patient PHI', async () => {
      const res = await p1Request('POST', '/api/v1/claims/anesthesia/calculate', {
        procedure_codes: ['20.11A'],
      });
      expect(res.statusCode).toBe(200);
      expect(res.body).not.toContain(P1_PATIENT_PHN);
      expect(res.body).not.toContain(P1_PATIENT_NAME);
    });

    it('Template list response does not contain physicianId for other physicians', async () => {
      const res = await p2Request('GET', '/api/v1/claims/templates');
      expect(res.statusCode).toBe(200);
      // Should not contain P1 data
      expect(res.body).not.toContain(P1_PROVIDER_ID);
      expect(res.body).not.toContain(P1_TEMPLATE_ID);
    });
  });
});
