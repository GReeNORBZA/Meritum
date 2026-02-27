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

// Physician 1 — "our" physician
const P1_SESSION_TOKEN = randomBytes(32).toString('hex');
const P1_SESSION_TOKEN_HASH = hashToken(P1_SESSION_TOKEN);
const P1_USER_ID = '11111111-1111-0000-0000-000000000001';
const P1_PROVIDER_ID = P1_USER_ID;
const P1_SESSION_ID = '11111111-1111-0000-0000-000000000011';

// Physician 2 — "other" physician (attacker perspective)
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

const P2_CLAIM_ID = 'aaaa2222-0000-0000-0000-000000000001';
const P2_PATIENT_ID = 'bbbb2222-0000-0000-0000-000000000001';
const P2_TEMPLATE_ID = 'dddd2222-0000-0000-0000-000000000001';
const P2_JUSTIFICATION_ID = 'eeee2222-0000-0000-0000-000000000001';

const NONEXISTENT_UUID = '99999999-9999-9999-9999-999999999999';

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

// Claim template store
interface MockClaimTemplate {
  templateId: string;
  physicianId: string;
  name: string;
  description: string | null;
  templateType: string;
  claimType: string;
  lineItems: unknown[];
  specialtyCode: string | null;
  usageCount: number;
  createdAt: Date;
  updatedAt: Date;
}

interface MockJustification {
  justificationId: string;
  claimId: string;
  physicianId: string;
  scenario: string;
  justificationText: string;
  templateId: string | null;
  createdBy: string;
  createdAt: Date;
}

interface MockReferrer {
  physicianId: string;
  referrerCpsa: string;
  referrerName: string;
  lastUsedAt: Date;
}

interface MockClaim {
  claimId: string;
  physicianId: string;
  patientId: string;
  claimType: string;
  state: string;
}

const claimTemplateStore: Record<string, MockClaimTemplate> = {};
const justificationStore: Record<string, MockJustification> = {};
const referrerStore: MockReferrer[] = [];
const claimStore: Record<string, MockClaim> = {};

// ---------------------------------------------------------------------------
// Seed test data
// ---------------------------------------------------------------------------

function seedTestData() {
  Object.keys(claimTemplateStore).forEach((k) => delete claimTemplateStore[k]);
  Object.keys(justificationStore).forEach((k) => delete justificationStore[k]);
  Object.keys(claimStore).forEach((k) => delete claimStore[k]);
  referrerStore.length = 0;

  // Claims
  claimStore[P1_CLAIM_ID] = {
    claimId: P1_CLAIM_ID,
    physicianId: P1_PROVIDER_ID,
    patientId: P1_PATIENT_ID,
    claimType: 'AHCIP',
    state: 'DRAFT',
  };
  claimStore[P2_CLAIM_ID] = {
    claimId: P2_CLAIM_ID,
    physicianId: P2_PROVIDER_ID,
    patientId: P2_PATIENT_ID,
    claimType: 'AHCIP',
    state: 'DRAFT',
  };

  // P1's claim template
  claimTemplateStore[P1_TEMPLATE_ID] = {
    templateId: P1_TEMPLATE_ID,
    physicianId: P1_PROVIDER_ID,
    name: 'P1 Office Visit Template',
    description: 'Standard office visit',
    templateType: 'CUSTOM',
    claimType: 'AHCIP',
    lineItems: [{ health_service_code: '03.04A', calls: 1 }],
    specialtyCode: null,
    usageCount: 5,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  // P2's claim template
  claimTemplateStore[P2_TEMPLATE_ID] = {
    templateId: P2_TEMPLATE_ID,
    physicianId: P2_PROVIDER_ID,
    name: 'P2 Surgery Template',
    description: 'Surgery procedure template',
    templateType: 'CUSTOM',
    claimType: 'AHCIP',
    lineItems: [{ health_service_code: '10.01A', calls: 1 }],
    specialtyCode: null,
    usageCount: 3,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  // P1's justification
  justificationStore[P1_JUSTIFICATION_ID] = {
    justificationId: P1_JUSTIFICATION_ID,
    claimId: P1_CLAIM_ID,
    physicianId: P1_PROVIDER_ID,
    scenario: 'UNLISTED_PROCEDURE',
    justificationText: 'P1 justification for unlisted procedure code.',
    templateId: null,
    createdBy: P1_USER_ID,
    createdAt: new Date(),
  };

  // P2's justification
  justificationStore[P2_JUSTIFICATION_ID] = {
    justificationId: P2_JUSTIFICATION_ID,
    claimId: P2_CLAIM_ID,
    physicianId: P2_PROVIDER_ID,
    scenario: 'ADDITIONAL_COMPENSATION',
    justificationText: 'P2 justification for additional compensation.',
    templateId: null,
    createdBy: P2_USER_ID,
    createdAt: new Date(),
  };

  // P1's referrers
  referrerStore.push(
    { physicianId: P1_PROVIDER_ID, referrerCpsa: 'P1REF1', referrerName: 'Dr. P1 Referrer', lastUsedAt: new Date() },
  );
  // P2's referrers
  referrerStore.push(
    { physicianId: P2_PROVIDER_ID, referrerCpsa: 'P2REF1', referrerName: 'Dr. P2 Referrer', lastUsedAt: new Date() },
  );
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
// Physician-scoped mock claim repository
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

    // Extension methods — physician-scoped
    listClaimTemplates: vi.fn(async (physicianId: string) => {
      return Object.values(claimTemplateStore).filter((t) => t.physicianId === physicianId);
    }),
    findClaimTemplateById: vi.fn(async (templateId: string, physicianId: string) => {
      const template = claimTemplateStore[templateId];
      if (!template || template.physicianId !== physicianId) return undefined;
      return template;
    }),
    createClaimTemplate: vi.fn(async (data: any) => {
      const id = crypto.randomUUID();
      const template: MockClaimTemplate = {
        templateId: id,
        physicianId: data.physicianId,
        name: data.name,
        description: data.description ?? null,
        templateType: data.templateType ?? 'CUSTOM',
        claimType: data.claimType,
        lineItems: data.lineItems,
        specialtyCode: data.specialtyCode ?? null,
        usageCount: 0,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      claimTemplateStore[id] = template;
      return template;
    }),
    updateClaimTemplate: vi.fn(async (templateId: string, physicianId: string, data: any) => {
      const template = claimTemplateStore[templateId];
      if (!template || template.physicianId !== physicianId) return undefined;
      Object.assign(template, data, { updatedAt: new Date() });
      return template;
    }),
    deleteClaimTemplate: vi.fn(async (templateId: string, physicianId: string) => {
      const template = claimTemplateStore[templateId];
      if (!template || template.physicianId !== physicianId) return false;
      delete claimTemplateStore[templateId];
      return true;
    }),
    incrementClaimTemplateUsage: vi.fn(async (templateId: string, physicianId: string) => {
      const template = claimTemplateStore[templateId];
      if (template && template.physicianId === physicianId) template.usageCount++;
    }),

    getJustificationForClaim: vi.fn(async (claimId: string, physicianId: string) => {
      return Object.values(justificationStore).find(
        (j) => j.claimId === claimId && j.physicianId === physicianId,
      ) ?? null;
    }),
    createJustification: vi.fn(async (data: any) => {
      const id = crypto.randomUUID();
      const just: MockJustification = {
        justificationId: id,
        claimId: data.claimId,
        physicianId: data.physicianId,
        scenario: data.scenario,
        justificationText: data.justificationText,
        templateId: data.templateId ?? null,
        createdBy: data.createdBy,
        createdAt: new Date(),
      };
      justificationStore[id] = just;
      return just;
    }),
    findJustificationById: vi.fn(async (justificationId: string, physicianId: string) => {
      const j = justificationStore[justificationId];
      if (!j || j.physicianId !== physicianId) return undefined;
      return j;
    }),
    updateJustification: vi.fn(async () => ({})),
    searchJustificationHistory: vi.fn(async (physicianId: string) => {
      const data = Object.values(justificationStore).filter((j) => j.physicianId === physicianId);
      return { data, pagination: { total: data.length, page: 1, pageSize: 20, hasMore: false } };
    }),

    getRecentReferrers: vi.fn(async (physicianId: string) => {
      return referrerStore.filter((r) => r.physicianId === physicianId);
    }),
    upsertRecentReferrer: vi.fn(async (physicianId: string, cpsa: string, name: string) => {
      const ref = { physicianId, referrerCpsa: cpsa, referrerName: name, lastUsedAt: new Date() };
      referrerStore.push(ref);
      return ref;
    }),
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

  const scopedRepo = createScopedClaimRepo();

  const handlerDeps: ClaimHandlerDeps = {
    serviceDeps: {
      repo: scopedRepo as any,
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
// Request helpers
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

// ---------------------------------------------------------------------------
// Seed users
// ---------------------------------------------------------------------------

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

describe('Claim Extension Tenant Scoping (Security)', () => {
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
  // Templates — cross-physician isolation
  // =========================================================================

  describe('Claim Template cross-physician isolation', () => {
    it('P2 cannot view P1 template via GET /api/v1/claims/templates (only sees own)', async () => {
      const res = await p2Request('GET', '/api/v1/claims/templates');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      const templates = body.data ?? body;
      if (Array.isArray(templates)) {
        const p1Templates = templates.filter((t: any) => t.templateId === P1_TEMPLATE_ID);
        expect(p1Templates.length).toBe(0);
      }
    });

    it('P2 cannot update P1 template via PUT /api/v1/claims/templates/:id', async () => {
      const res = await p2Request('PUT', `/api/v1/claims/templates/${P1_TEMPLATE_ID}`, {
        name: 'HIJACKED',
      });
      // Should be 404 (not found for this physician) — not 200
      expect(res.statusCode).toBe(404);
    });

    it('P2 cannot delete P1 template via DELETE /api/v1/claims/templates/:id', async () => {
      const res = await p2Request('DELETE', `/api/v1/claims/templates/${P1_TEMPLATE_ID}`);
      expect(res.statusCode).toBe(404);
    });

    it('P2 cannot apply P1 template via POST /api/v1/claims/templates/:id/apply', async () => {
      const res = await p2Request('POST', `/api/v1/claims/templates/${P1_TEMPLATE_ID}/apply`, {
        patient_id: P2_PATIENT_ID,
        date_of_service: '2026-01-15',
      });
      expect(res.statusCode).toBe(404);
    });

    it('P1 CAN view own template', async () => {
      const res = await p1Request('GET', '/api/v1/claims/templates');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      const templates = body.data ?? body;
      if (Array.isArray(templates)) {
        const p1Templates = templates.filter((t: any) => t.templateId === P1_TEMPLATE_ID);
        expect(p1Templates.length).toBe(1);
      }
    });
  });

  // =========================================================================
  // Justifications — cross-physician isolation
  // =========================================================================

  describe('Justification cross-physician isolation', () => {
    it('P2 cannot view P1 justification via GET /api/v1/claims/:id/justification', async () => {
      const res = await p2Request('GET', `/api/v1/claims/${P1_CLAIM_ID}/justification`);
      // P2 cannot access P1's claim, so findClaimById returns undefined -> 404
      expect(res.statusCode).toBe(404);
    });

    it('P2 cannot create justification on P1 claim via POST /api/v1/claims/:id/justification', async () => {
      const res = await p2Request('POST', `/api/v1/claims/${P1_CLAIM_ID}/justification`, {
        claim_id: P1_CLAIM_ID,
        scenario: 'UNLISTED_PROCEDURE',
        justification_text: 'Attacker trying to add justification to P1 claim.',
      });
      expect(res.statusCode).toBe(404);
    });

    it('P2 cannot save P1 justification as personal template', async () => {
      const res = await p2Request('POST', `/api/v1/claims/justifications/${P1_JUSTIFICATION_ID}/save-personal`);
      expect(res.statusCode).toBe(404);
    });

    it('P2 justification history does not include P1 justifications', async () => {
      const res = await p2Request('GET', '/api/v1/claims/justifications/history');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      const justifications = body.data ?? [];
      if (Array.isArray(justifications)) {
        const p1Justifications = justifications.filter((j: any) => j.physicianId === P1_PROVIDER_ID);
        expect(p1Justifications.length).toBe(0);
      }
    });

    it('P1 CAN view own justification', async () => {
      const res = await p1Request('GET', `/api/v1/claims/${P1_CLAIM_ID}/justification`);
      expect(res.statusCode).toBe(200);
    });
  });

  // =========================================================================
  // Referrers — cross-physician isolation
  // =========================================================================

  describe('Referrer cross-physician isolation', () => {
    it('P2 recent referrers do not include P1 referrers', async () => {
      const res = await p2Request('GET', '/api/v1/claims/referrers/recent');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      const referrers = body.data ?? body;
      if (Array.isArray(referrers)) {
        const p1Referrers = referrers.filter((r: any) => r.referrerCpsa === 'P1REF1');
        expect(p1Referrers.length).toBe(0);
      }
    });

    it('P1 recent referrers do not include P2 referrers', async () => {
      const res = await p1Request('GET', '/api/v1/claims/referrers/recent');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      const referrers = body.data ?? body;
      if (Array.isArray(referrers)) {
        const p2Referrers = referrers.filter((r: any) => r.referrerCpsa === 'P2REF1');
        expect(p2Referrers.length).toBe(0);
      }
    });
  });

  // =========================================================================
  // Cross-provider GET returns 404 (not 403)
  // =========================================================================

  describe('Cross-provider GET returns 404 (indistinguishable from missing)', () => {
    it('P2 GET /api/v1/claims/:id/justification for P1 claim returns 404', async () => {
      const res = await p2Request('GET', `/api/v1/claims/${P1_CLAIM_ID}/justification`);
      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('NOT_FOUND');
    });

    it('P2 PUT /api/v1/claims/templates/:id for P1 template returns 404', async () => {
      const res = await p2Request('PUT', `/api/v1/claims/templates/${P1_TEMPLATE_ID}`, {
        name: 'Hijacked',
      });
      expect(res.statusCode).toBe(404);
    });

    it('Nonexistent template GET returns same 404 as cross-tenant', async () => {
      const res = await p1Request('PUT', `/api/v1/claims/templates/${NONEXISTENT_UUID}`, {
        name: 'Does not exist',
      });
      expect(res.statusCode).toBe(404);
    });

    it('Nonexistent justification save returns same 404 as cross-tenant', async () => {
      const res = await p1Request('POST', `/api/v1/claims/justifications/${NONEXISTENT_UUID}/save-personal`);
      expect(res.statusCode).toBe(404);
    });
  });
});
