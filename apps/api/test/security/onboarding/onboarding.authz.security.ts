import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

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
// Real imports (after mocks are hoisted)
// ---------------------------------------------------------------------------

import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { onboardingRoutes, onboardingGateFp } from '../../../src/domains/onboarding/onboarding.routes.js';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { type OnboardingHandlerDeps } from '../../../src/domains/onboarding/onboarding.handlers.js';
import { type OnboardingServiceDeps } from '../../../src/domains/onboarding/onboarding.service.js';
import {
  type SessionManagementDeps,
  hashToken,
} from '../../../src/domains/iam/iam.service.js';
import { randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

// Physician session (onboarding INCOMPLETE)
const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_USER_ID = '11111111-0000-0000-0000-000000000001';
const PHYSICIAN_SESSION_ID = '11111111-0000-0000-0000-000000000011';
const PHYSICIAN_PROVIDER_ID = PHYSICIAN_USER_ID;

// Physician session (onboarding COMPLETE)
const COMPLETE_PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const COMPLETE_PHYSICIAN_SESSION_TOKEN_HASH = hashToken(COMPLETE_PHYSICIAN_SESSION_TOKEN);
const COMPLETE_PHYSICIAN_USER_ID = '11111111-0000-0000-0000-000000000002';
const COMPLETE_PHYSICIAN_SESSION_ID = '11111111-0000-0000-0000-000000000012';
const COMPLETE_PHYSICIAN_PROVIDER_ID = COMPLETE_PHYSICIAN_USER_ID;

// Delegate session
const DELEGATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_SESSION_TOKEN_HASH = hashToken(DELEGATE_SESSION_TOKEN);
const DELEGATE_USER_ID = '22222222-0000-0000-0000-000000000002';
const DELEGATE_SESSION_ID = '22222222-0000-0000-0000-000000000022';

// Placeholder UUID for route params
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
  delegateContext?: {
    delegateUserId: string;
    physicianProviderId: string;
    permissions: string[];
    linkageId: string;
  };
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
let auditEntries: Array<Record<string, unknown>> = [];

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
      const result: any = {
        session,
        user: {
          userId: user.userId,
          role: user.role,
          subscriptionStatus: user.subscriptionStatus,
        },
      };
      if (user.delegateContext) {
        result.user.delegateContext = user.delegateContext;
      }
      return result;
    }),
    refreshSession: vi.fn(async () => {}),
    listActiveSessions: vi.fn(async () => []),
    revokeSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
  };
}

function createMockAuditRepo() {
  return {
    appendAuditLog: vi.fn(async (entry: Record<string, unknown>) => {
      auditEntries.push(entry);
    }),
  };
}

function createMockEvents() {
  return { emit: vi.fn() };
}

// ---------------------------------------------------------------------------
// Mock onboarding repository
// ---------------------------------------------------------------------------

function createStubOnboardingRepo() {
  return {
    createProgress: vi.fn(async () => ({})),
    findProgressByProviderId: vi.fn(async (providerId: string) => {
      // Return completed progress for the complete physician
      if (providerId === COMPLETE_PHYSICIAN_PROVIDER_ID) {
        return {
          progressId: '99999999-0000-0000-0000-000000000099',
          providerId: COMPLETE_PHYSICIAN_PROVIDER_ID,
          step1Completed: true,
          step2Completed: true,
          step3Completed: true,
          step4Completed: true,
          step5Completed: true,
          step6Completed: true,
          step7Completed: true,
          patientImportCompleted: true,
          guidedTourCompleted: true,
          guidedTourDismissed: false,
          startedAt: new Date(),
          completedAt: new Date(),
          createdAt: new Date(),
          updatedAt: new Date(),
        };
      }
      // Return incomplete progress for the incomplete physician
      if (providerId === PHYSICIAN_PROVIDER_ID) {
        return {
          progressId: '88888888-0000-0000-0000-000000000088',
          providerId: PHYSICIAN_PROVIDER_ID,
          step1Completed: true,
          step2Completed: false,
          step3Completed: false,
          step4Completed: false,
          step5Completed: false,
          step6Completed: false,
          step7Completed: false,
          patientImportCompleted: false,
          guidedTourCompleted: false,
          guidedTourDismissed: false,
          startedAt: new Date(),
          completedAt: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
      }
      return null;
    }),
    markStepCompleted: vi.fn(async () => ({})),
    markOnboardingCompleted: vi.fn(async () => ({})),
    markPatientImportCompleted: vi.fn(async () => ({})),
    markGuidedTourCompleted: vi.fn(async () => ({})),
    markGuidedTourDismissed: vi.fn(async () => ({})),
    createImaRecord: vi.fn(async () => ({})),
    findLatestImaRecord: vi.fn(async () => null),
    listImaRecords: vi.fn(async () => []),
  };
}

// ---------------------------------------------------------------------------
// Mock provider service
// ---------------------------------------------------------------------------

function createStubProviderService() {
  return {
    createOrUpdateProvider: vi.fn(async () => ({ providerId: PHYSICIAN_USER_ID })),
    updateProviderSpecialty: vi.fn(async () => {}),
    createBa: vi.fn(async () => ({ baId: '00000000-0000-0000-0000-000000000099' })),
    createLocation: vi.fn(async () => ({ locationId: '00000000-0000-0000-0000-000000000099' })),
    createWcbConfig: vi.fn(async () => ({ wcbConfigId: '00000000-0000-0000-0000-000000000099' })),
    updateSubmissionPreferences: vi.fn(async () => {}),
    findProviderByUserId: vi.fn(async (userId: string) => {
      if (userId === PHYSICIAN_USER_ID) {
        return { providerId: PHYSICIAN_PROVIDER_ID };
      }
      if (userId === COMPLETE_PHYSICIAN_USER_ID) {
        return { providerId: COMPLETE_PHYSICIAN_PROVIDER_ID };
      }
      return null;
    }),
    getProviderDetails: vi.fn(async () => null),
    findBaById: vi.fn(async () => null),
    updateBaStatus: vi.fn(async () => ({ baId: '', status: '' })),
  };
}

// ---------------------------------------------------------------------------
// Mock reference data service
// ---------------------------------------------------------------------------

function createStubReferenceData() {
  return {
    validateSpecialtyCode: vi.fn(async () => true),
    validateFunctionalCentreCode: vi.fn(async () => true),
    validateCommunityCode: vi.fn(async () => true),
    getRrnpRate: vi.fn(async () => null),
    getWcbFormTypes: vi.fn(async () => ['C8', 'C10']),
  };
}

// ---------------------------------------------------------------------------
// Stub service deps
// ---------------------------------------------------------------------------

function createStubServiceDeps(): OnboardingServiceDeps {
  return {
    repo: createStubOnboardingRepo() as any,
    auditRepo: createMockAuditRepo(),
    events: createMockEvents(),
    providerService: createStubProviderService(),
    referenceData: createStubReferenceData(),
  };
}

// ---------------------------------------------------------------------------
// Test App Builder (onboarding routes only — for delegate authz tests)
// ---------------------------------------------------------------------------

let app: FastifyInstance;

async function buildTestApp(): Promise<FastifyInstance> {
  const mockSessionRepo = createMockSessionRepo();

  const sessionDeps: SessionManagementDeps = {
    sessionRepo: mockSessionRepo,
    auditRepo: createMockAuditRepo(),
    events: createMockEvents(),
  };

  const handlerDeps: OnboardingHandlerDeps = {
    serviceDeps: createStubServiceDeps(),
  };

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  await testApp.register(authPluginFp, { sessionDeps });

  testApp.setErrorHandler((error, _request, reply) => {
    if ('statusCode' in error && 'code' in error && typeof (error as any).code === 'string') {
      const statusCode = (error as any).statusCode ?? 500;
      if (statusCode >= 400 && statusCode < 500) {
        return reply.code(statusCode).send({
          error: { code: (error as any).code, message: error.message },
        });
      }
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

  await testApp.register(onboardingRoutes, { deps: handlerDeps });
  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Test App Builder with Onboarding Gate (for gate enforcement tests)
// ---------------------------------------------------------------------------

let gateApp: FastifyInstance;

async function buildGateTestApp(): Promise<FastifyInstance> {
  const mockSessionRepo = createMockSessionRepo();

  const sessionDeps: SessionManagementDeps = {
    sessionRepo: mockSessionRepo,
    auditRepo: createMockAuditRepo(),
    events: createMockEvents(),
  };

  const serviceDeps = createStubServiceDeps();

  const handlerDeps: OnboardingHandlerDeps = {
    serviceDeps,
  };

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  await testApp.register(authPluginFp, { sessionDeps });

  // Register the onboarding gate BEFORE other routes
  await testApp.register(onboardingGateFp, { serviceDeps });

  testApp.setErrorHandler((error, _request, reply) => {
    if ('statusCode' in error && 'code' in error && typeof (error as any).code === 'string') {
      const statusCode = (error as any).statusCode ?? 500;
      if (statusCode >= 400 && statusCode < 500) {
        return reply.code(statusCode).send({
          error: { code: (error as any).code, message: error.message },
        });
      }
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

  // Register onboarding routes (bypassed by the gate)
  await testApp.register(onboardingRoutes, { deps: handlerDeps });

  // Register stub non-onboarding routes to test gate enforcement
  testApp.get('/api/v1/claims', {
    preHandler: [testApp.authenticate],
    handler: async (_request, reply) => {
      return reply.code(200).send({ data: [] });
    },
  });

  testApp.get('/api/v1/patients', {
    preHandler: [testApp.authenticate],
    handler: async (_request, reply) => {
      return reply.code(200).send({ data: [] });
    },
  });

  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------

function physicianRequest(
  target: FastifyInstance,
  method: 'GET' | 'POST' | 'PUT' | 'DELETE',
  url: string,
  payload?: unknown,
) {
  return target.inject({
    method,
    url,
    headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function completePhysicianRequest(
  target: FastifyInstance,
  method: 'GET' | 'POST' | 'PUT' | 'DELETE',
  url: string,
  payload?: unknown,
) {
  return target.inject({
    method,
    url,
    headers: { cookie: `session=${COMPLETE_PHYSICIAN_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function delegateRequest(
  target: FastifyInstance,
  method: 'GET' | 'POST' | 'PUT' | 'DELETE',
  url: string,
  payload?: unknown,
) {
  return target.inject({
    method,
    url,
    headers: { cookie: `session=${DELEGATE_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

// ---------------------------------------------------------------------------
// Seed test data
// ---------------------------------------------------------------------------

function seedUsers() {
  users = [];
  sessions = [];
  auditEntries = [];

  // Physician user (onboarding incomplete)
  users.push({
    userId: PHYSICIAN_USER_ID,
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

  // Physician user (onboarding complete)
  users.push({
    userId: COMPLETE_PHYSICIAN_USER_ID,
    email: 'complete-physician@example.com',
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    role: 'PHYSICIAN',
    subscriptionStatus: 'ACTIVE',
  });
  sessions.push({
    sessionId: COMPLETE_PHYSICIAN_SESSION_ID,
    userId: COMPLETE_PHYSICIAN_USER_ID,
    tokenHash: COMPLETE_PHYSICIAN_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

  // Delegate user with CLAIM_VIEW permission
  users.push({
    userId: DELEGATE_USER_ID,
    email: 'delegate@example.com',
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    role: 'DELEGATE',
    subscriptionStatus: 'TRIAL',
    delegateContext: {
      delegateUserId: DELEGATE_USER_ID,
      physicianProviderId: COMPLETE_PHYSICIAN_USER_ID,
      permissions: ['CLAIM_VIEW'],
      linkageId: '44444444-0000-0000-0000-000000000044',
    },
  });
  sessions.push({
    sessionId: DELEGATE_SESSION_ID,
    userId: DELEGATE_USER_ID,
    tokenHash: DELEGATE_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });
}

// ---------------------------------------------------------------------------
// Route specs for all onboarding routes
// ---------------------------------------------------------------------------

interface RouteSpec {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  url: string;
  payload?: Record<string, unknown>;
  description: string;
}

const ALL_ONBOARDING_ROUTES: RouteSpec[] = [
  {
    method: 'GET',
    url: '/api/v1/onboarding/progress',
    description: 'Get onboarding progress',
  },
  {
    method: 'POST',
    url: '/api/v1/onboarding/steps/1',
    payload: {
      billing_number: '123456',
      cpsa_registration_number: 'REG123',
      first_name: 'Test',
      last_name: 'Physician',
    },
    description: 'Complete step 1 (profile)',
  },
  {
    method: 'POST',
    url: '/api/v1/onboarding/steps/2',
    payload: {
      specialty_code: 'GP',
      physician_type: 'GP',
    },
    description: 'Complete step 2 (specialty)',
  },
  {
    method: 'POST',
    url: '/api/v1/onboarding/steps/3',
    payload: {
      ba_number: '12345',
      ba_type: 'FFS',
      is_primary: true,
    },
    description: 'Complete step 3 (BA)',
  },
  {
    method: 'POST',
    url: '/api/v1/onboarding/steps/4',
    payload: {
      location_name: 'Test Clinic',
      address_line_1: '123 Main St',
      city: 'Calgary',
      province: 'AB',
      postal_code: 'T2P0A1',
      functional_centre_code: 'FC01',
    },
    description: 'Complete step 4 (location)',
  },
  {
    method: 'POST',
    url: '/api/v1/onboarding/steps/5',
    payload: {
      wcb_provider_number: 'WCB123',
      wcb_form_types: ['C8'],
    },
    description: 'Complete step 5 (WCB config)',
  },
  {
    method: 'POST',
    url: '/api/v1/onboarding/steps/6',
    payload: {
      default_submission_method: 'HLINK',
      auto_validate: true,
    },
    description: 'Complete step 6 (submission preferences)',
  },
  {
    method: 'POST',
    url: '/api/v1/onboarding/steps/7',
    description: 'Complete step 7 (IMA acknowledgment)',
  },
  {
    method: 'GET',
    url: '/api/v1/onboarding/ima',
    description: 'Get IMA document',
  },
  {
    method: 'POST',
    url: '/api/v1/onboarding/ima/acknowledge',
    payload: { document_hash: 'abc123hash' },
    description: 'Acknowledge IMA',
  },
  {
    method: 'GET',
    url: '/api/v1/onboarding/ima/download',
    description: 'Download IMA PDF',
  },
  {
    method: 'GET',
    url: '/api/v1/onboarding/ahc11236/download',
    description: 'Download AHC11236 form',
  },
  {
    method: 'GET',
    url: '/api/v1/onboarding/pia/download',
    description: 'Download PIA appendix',
  },
  {
    method: 'POST',
    url: '/api/v1/onboarding/guided-tour/complete',
    description: 'Complete guided tour',
  },
  {
    method: 'POST',
    url: '/api/v1/onboarding/guided-tour/dismiss',
    description: 'Dismiss guided tour',
  },
  {
    method: 'POST',
    url: '/api/v1/onboarding/patient-import/complete',
    description: 'Complete patient import',
  },
  {
    method: 'POST',
    url: `/api/v1/onboarding/ba/${PLACEHOLDER_UUID}/confirm-active`,
    description: 'Confirm BA active',
  },
];

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Onboarding Authorization & Role Enforcement (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
    gateApp = await buildGateTestApp();
  });

  afterAll(async () => {
    await app.close();
    await gateApp.close();
  });

  beforeEach(() => {
    seedUsers();
  });

  // =========================================================================
  // 1. Delegate cannot access ANY onboarding routes
  // =========================================================================

  describe('Delegate cannot access onboarding routes', () => {
    for (const route of ALL_ONBOARDING_ROUTES) {
      it(`${route.method} ${route.url} — delegate gets 403 (${route.description})`, async () => {
        const res = await delegateRequest(app, route.method, route.url, route.payload);
        expect(res.statusCode).toBe(403);
        const body = JSON.parse(res.body);
        expect(body.error).toBeDefined();
        expect(body.error.code).toBe('FORBIDDEN');
        expect(body.data).toBeUndefined();
      });
    }
  });

  // =========================================================================
  // 2. 403 responses for delegates do not leak information
  // =========================================================================

  describe('403 responses for delegates contain no sensitive information', () => {
    it('403 response does not contain stack traces', async () => {
      const res = await delegateRequest(app, 'GET', '/api/v1/onboarding/progress');
      expect(res.statusCode).toBe(403);
      const rawBody = res.body;
      expect(rawBody).not.toContain('stack');
      expect(rawBody).not.toContain('node_modules');
      expect(rawBody).not.toContain('.ts:');
    });

    it('403 response does not reveal required role', async () => {
      const res = await delegateRequest(app, 'POST', '/api/v1/onboarding/steps/1', {
        billing_number: '123456',
        cpsa_registration_number: 'REG123',
        first_name: 'Attacker',
        last_name: 'Delegate',
      });
      expect(res.statusCode).toBe(403);
      const rawBody = res.body;
      expect(rawBody).not.toContain('PHYSICIAN');
      expect(rawBody).not.toContain('physician');
    });

    it('403 response has consistent error shape', async () => {
      const res = await delegateRequest(app, 'GET', '/api/v1/onboarding/progress');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
    });

    it('403 response does not contain onboarding progress data', async () => {
      const res = await delegateRequest(app, 'GET', '/api/v1/onboarding/progress');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
      expect(body.progress).toBeUndefined();
    });

    it('403 response on IMA does not contain document content', async () => {
      const res = await delegateRequest(app, 'GET', '/api/v1/onboarding/ima');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
    });
  });

  // =========================================================================
  // 3. Sanity: Physician CAN access onboarding routes
  // =========================================================================

  describe('Sanity: Physician can access onboarding routes', () => {
    it('GET /api/v1/onboarding/progress — physician gets non-403', async () => {
      const res = await physicianRequest(app, 'GET', '/api/v1/onboarding/progress');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST /api/v1/onboarding/steps/7 — physician gets non-403', async () => {
      const res = await physicianRequest(app, 'POST', '/api/v1/onboarding/steps/7');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /api/v1/onboarding/ima — physician gets non-403', async () => {
      const res = await physicianRequest(app, 'GET', '/api/v1/onboarding/ima');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST /api/v1/onboarding/guided-tour/complete — physician gets non-403', async () => {
      const res = await physicianRequest(app, 'POST', '/api/v1/onboarding/guided-tour/complete');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });
  });

  // =========================================================================
  // 4. Onboarding Gate Enforcement
  // =========================================================================

  describe('Onboarding gate blocks incomplete physicians on non-onboarding routes', () => {
    it('physician with incomplete onboarding accessing /api/v1/claims gets 403 with onboarding_required', async () => {
      const res = await physicianRequest(gateApp, 'GET', '/api/v1/claims');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('ONBOARDING_REQUIRED');
      expect(body.error.message).toBe('onboarding_required');
      expect(body.error.current_step).toBeDefined();
      expect(typeof body.error.current_step).toBe('number');
    });

    it('physician with incomplete onboarding accessing /api/v1/patients gets 403 with onboarding_required', async () => {
      const res = await physicianRequest(gateApp, 'GET', '/api/v1/patients');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('ONBOARDING_REQUIRED');
      expect(body.error.message).toBe('onboarding_required');
      expect(body.error.current_step).toBeDefined();
    });

    it('physician with complete onboarding accessing /api/v1/claims is allowed', async () => {
      const res = await completePhysicianRequest(gateApp, 'GET', '/api/v1/claims');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toBeDefined();
    });

    it('physician with complete onboarding accessing /api/v1/patients is allowed', async () => {
      const res = await completePhysicianRequest(gateApp, 'GET', '/api/v1/patients');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toBeDefined();
    });

    it('delegate accessing /api/v1/claims with complete physician context — gate skipped', async () => {
      const res = await delegateRequest(gateApp, 'GET', '/api/v1/claims');
      // Gate skips delegates — they reach the route handler and get 200
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toBeDefined();
    });

    it('delegate accessing /api/v1/patients with complete physician context — gate skipped', async () => {
      const res = await delegateRequest(gateApp, 'GET', '/api/v1/patients');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toBeDefined();
    });

    it('onboarding gate does not block onboarding routes for incomplete physician', async () => {
      const res = await physicianRequest(gateApp, 'GET', '/api/v1/onboarding/progress');
      // Onboarding routes bypass the gate — physician gets through to the handler
      expect(res.statusCode).not.toBe(403);
    });

    it('onboarding gate error response does not leak PHI', async () => {
      const res = await physicianRequest(gateApp, 'GET', '/api/v1/claims');
      expect(res.statusCode).toBe(403);
      const rawBody = res.body;
      expect(rawBody).not.toContain('provider_id');
      expect(rawBody).not.toContain(PHYSICIAN_USER_ID);
      expect(rawBody).not.toContain('postgres');
      expect(rawBody).not.toContain('drizzle');
      expect(rawBody).not.toContain('stack');
    });
  });

  // =========================================================================
  // 5. Step Sequence Not Enforced via Authorization
  // =========================================================================

  describe('Step sequence is not enforced — physicians can navigate freely', () => {
    it('physician can POST /steps/3 then POST /steps/1 (editing earlier step)', async () => {
      // First submit step 3
      const res1 = await physicianRequest(app, 'POST', '/api/v1/onboarding/steps/3', {
        ba_number: '12345',
        ba_type: 'FFS',
        is_primary: true,
      });
      // Should not be 401 or 403 — may be other status depending on service logic
      expect(res1.statusCode).not.toBe(401);
      expect(res1.statusCode).not.toBe(403);

      // Then go back and submit step 1
      const res2 = await physicianRequest(app, 'POST', '/api/v1/onboarding/steps/1', {
        billing_number: '654321',
        cpsa_registration_number: 'REG999',
        first_name: 'Updated',
        last_name: 'Physician',
      });
      expect(res2.statusCode).not.toBe(401);
      expect(res2.statusCode).not.toBe(403);
    });

    it('physician can POST /steps/7 then POST /steps/2 (editing earlier step after last)', async () => {
      // Submit step 7 (no body required)
      const res1 = await physicianRequest(app, 'POST', '/api/v1/onboarding/steps/7');
      expect(res1.statusCode).not.toBe(401);
      expect(res1.statusCode).not.toBe(403);

      // Go back to step 2
      const res2 = await physicianRequest(app, 'POST', '/api/v1/onboarding/steps/2', {
        specialty_code: 'GP',
        physician_type: 'GP',
      });
      expect(res2.statusCode).not.toBe(401);
      expect(res2.statusCode).not.toBe(403);
    });
  });
});
