import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

// ---------------------------------------------------------------------------
// Environment setup (must be before imports that read env)
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);
process.env.INTERNAL_API_KEY = 'test-internal-api-key-32chars-ok';

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
import { providerRoutes, internalProviderRoutes } from '../../../src/domains/provider/provider.routes.js';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import {
  type ProviderServiceDeps,
} from '../../../src/domains/provider/provider.service.js';
import {
  type ProviderHandlerDeps,
  type InternalProviderHandlerDeps,
} from '../../../src/domains/provider/provider.handlers.js';
import {
  type SessionManagementDeps,
  hashToken,
} from '../../../src/domains/iam/iam.service.js';
import { randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

// Physician session
const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_USER_ID = '11111111-0000-0000-0000-000000000001';
const PHYSICIAN_SESSION_ID = '11111111-0000-0000-0000-000000000011';

// Delegate session (with CLAIM_VIEW only)
const DELEGATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_SESSION_TOKEN_HASH = hashToken(DELEGATE_SESSION_TOKEN);
const DELEGATE_USER_ID = '22222222-0000-0000-0000-000000000002';
const DELEGATE_SESSION_ID = '22222222-0000-0000-0000-000000000022';

// Delegate session with PREFERENCE_VIEW only
const DELEGATE_PREFVIEW_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_PREFVIEW_SESSION_TOKEN_HASH = hashToken(DELEGATE_PREFVIEW_SESSION_TOKEN);
const DELEGATE_PREFVIEW_USER_ID = '33333333-0000-0000-0000-000000000003';
const DELEGATE_PREFVIEW_SESSION_ID = '33333333-0000-0000-0000-000000000033';

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
    appendAuditLog: vi.fn(async () => {}),
  };
}

function createMockEvents() {
  return { emit: vi.fn() };
}

// ---------------------------------------------------------------------------
// Mock provider repository (stubs — not exercised in authz tests)
// ---------------------------------------------------------------------------

function createStubProviderRepo() {
  return {
    findProviderById: vi.fn(async () => undefined),
    createProvider: vi.fn(async () => ({})),
    updateProvider: vi.fn(async () => ({})),
    listBas: vi.fn(async () => []),
    findBaById: vi.fn(async () => undefined),
    createBa: vi.fn(async () => ({})),
    updateBa: vi.fn(async () => ({})),
    deactivateBa: vi.fn(async () => {}),
    listLocations: vi.fn(async () => []),
    findLocationById: vi.fn(async () => undefined),
    createLocation: vi.fn(async () => ({})),
    updateLocation: vi.fn(async () => ({})),
    setDefaultLocation: vi.fn(async () => ({})),
    deactivateLocation: vi.fn(async () => {}),
    listWcbConfigs: vi.fn(async () => []),
    findWcbConfigById: vi.fn(async () => undefined),
    createWcbConfig: vi.fn(async () => ({})),
    updateWcbConfig: vi.fn(async () => ({})),
    removeWcbConfig: vi.fn(async () => {}),
    getFormPermissions: vi.fn(async () => []),
    getSubmissionPreferences: vi.fn(async () => undefined),
    upsertSubmissionPreferences: vi.fn(async () => ({})),
    getHlinkConfig: vi.fn(async () => undefined),
    upsertHlinkConfig: vi.fn(async () => ({})),
    listDelegates: vi.fn(async () => []),
    findDelegateRelationship: vi.fn(async () => undefined),
    findDelegateRelationshipById: vi.fn(async () => undefined),
    createDelegateRelationship: vi.fn(async () => ({})),
    updateDelegateRelationshipPermissions: vi.fn(async () => ({})),
    revokeDelegateRelationship: vi.fn(async () => ({})),
    listPhysiciansForDelegate: vi.fn(async () => []),
    findDelegateLinkage: vi.fn(async () => undefined),
    getOnboardingStatus: vi.fn(async () => ({
      hasBillingNumber: false,
      hasCpsaNumber: false,
      hasName: false,
      hasBa: false,
      hasLocation: false,
      isComplete: false,
      missingFields: [],
    })),
    completeOnboarding: vi.fn(async () => ({})),
    getProviderContext: vi.fn(async () => undefined),
    getBaForClaim: vi.fn(async () => undefined),
    findWcbConfigByContractRole: vi.fn(async () => undefined),
    findPcpcmEnrolment: vi.fn(async () => undefined),
    countBas: vi.fn(async () => 0),
    countLocations: vi.fn(async () => 0),
    countWcbConfigs: vi.fn(async () => 0),
  };
}

function createStubServiceDeps(): ProviderServiceDeps {
  return {
    repo: createStubProviderRepo() as any,
    auditRepo: createMockAuditRepo(),
    events: createMockEvents(),
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

  const serviceDeps = createStubServiceDeps();

  const handlerDeps: ProviderHandlerDeps = {
    serviceDeps,
  };

  const internalHandlerDeps: InternalProviderHandlerDeps = {
    serviceDeps,
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

  await testApp.register(providerRoutes, { deps: handlerDeps });
  await testApp.register(internalProviderRoutes, { deps: internalHandlerDeps });
  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------

function physicianRequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function delegateRequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${DELEGATE_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function delegatePrefViewRequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${DELEGATE_PREFVIEW_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

// ---------------------------------------------------------------------------
// Seed test data
// ---------------------------------------------------------------------------

function seedUsers() {
  users = [];
  sessions = [];

  // Physician user
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

  // Delegate user with CLAIM_VIEW only
  users.push({
    userId: DELEGATE_USER_ID,
    email: 'delegate-claim@example.com',
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
      physicianProviderId: PHYSICIAN_USER_ID,
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

  // Delegate user with PREFERENCE_VIEW only
  users.push({
    userId: DELEGATE_PREFVIEW_USER_ID,
    email: 'delegate-pref@example.com',
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    role: 'DELEGATE',
    subscriptionStatus: 'TRIAL',
    delegateContext: {
      delegateUserId: DELEGATE_PREFVIEW_USER_ID,
      physicianProviderId: PHYSICIAN_USER_ID,
      permissions: ['PREFERENCE_VIEW'],
      linkageId: '55555555-0000-0000-0000-000000000055',
    },
  });
  sessions.push({
    sessionId: DELEGATE_PREFVIEW_SESSION_ID,
    userId: DELEGATE_PREFVIEW_USER_ID,
    tokenHash: DELEGATE_PREFVIEW_SESSION_TOKEN_HASH,
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

describe('Provider Authorization & Role Enforcement (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    seedUsers();
  });

  // =========================================================================
  // 1. Delegate cannot access physician-only routes
  // =========================================================================

  describe('Delegate cannot access physician-only routes', () => {
    it('POST /api/v1/providers/me/delegates/invite — delegate gets 403', async () => {
      const res = await delegateRequest('POST', '/api/v1/providers/me/delegates/invite', {
        email: 'new-delegate@example.com',
        permissions: ['CLAIM_VIEW'],
      });
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('PUT /api/v1/providers/me/delegates/:rel_id/permissions — delegate gets 403', async () => {
      const res = await delegateRequest('PUT', `/api/v1/providers/me/delegates/${PLACEHOLDER_UUID}/permissions`, {
        permissions: ['CLAIM_VIEW', 'CLAIM_CREATE'],
      });
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/providers/me/delegates/:rel_id/revoke — delegate gets 403', async () => {
      const res = await delegateRequest('POST', `/api/v1/providers/me/delegates/${PLACEHOLDER_UUID}/revoke`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/providers/me/complete-onboarding — delegate gets 403', async () => {
      const res = await delegateRequest('POST', '/api/v1/providers/me/complete-onboarding', {});
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/providers/me/hlink — delegate gets 403', async () => {
      const res = await delegateRequest('GET', '/api/v1/providers/me/hlink');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('PUT /api/v1/providers/me/hlink — delegate gets 403', async () => {
      const res = await delegateRequest('PUT', '/api/v1/providers/me/hlink', {
        submitter_prefix: 'MER',
      });
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/providers/me/delegates — delegate gets 403', async () => {
      const res = await delegateRequest('GET', '/api/v1/providers/me/delegates');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });
  });

  // =========================================================================
  // 2. Physician cannot access delegate-only routes
  // =========================================================================

  describe('Physician cannot access delegate-only routes', () => {
    it('GET /api/v1/delegates/me/physicians — physician gets 403', async () => {
      const res = await physicianRequest('GET', '/api/v1/delegates/me/physicians');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/delegates/me/switch-context/:id — physician gets 403', async () => {
      const res = await physicianRequest('POST', `/api/v1/delegates/me/switch-context/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });
  });

  // =========================================================================
  // 3. Delegate permission boundary tests
  // =========================================================================

  describe('Delegate permission boundaries', () => {
    // CLAIM_VIEW delegate cannot access PREFERENCE_EDIT routes
    it('delegate with CLAIM_VIEW only cannot POST /api/v1/providers/me/bas (requires PREFERENCE_EDIT)', async () => {
      const res = await delegateRequest('POST', '/api/v1/providers/me/bas', {
        ba_number: '12345',
        ba_type: 'FFS',
      });
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('delegate with CLAIM_VIEW only cannot PUT /api/v1/providers/me (requires PREFERENCE_EDIT)', async () => {
      const res = await delegateRequest('PUT', '/api/v1/providers/me', {
        first_name: 'Attacker',
        last_name: 'Delegate',
      });
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('delegate with CLAIM_VIEW only cannot POST /api/v1/providers/me/locations (requires PREFERENCE_EDIT)', async () => {
      const res = await delegateRequest('POST', '/api/v1/providers/me/locations', {
        name: 'Malicious Clinic',
        functional_centre: 'FC99',
      });
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('delegate with CLAIM_VIEW only cannot POST /api/v1/providers/me/wcb (requires PREFERENCE_EDIT)', async () => {
      const res = await delegateRequest('POST', '/api/v1/providers/me/wcb', {
        contract_id: 'C001',
        role_code: 'R01',
        skill_code: 'S01',
      });
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('delegate with CLAIM_VIEW only cannot PUT /api/v1/providers/me/submission-preferences (requires PREFERENCE_EDIT)', async () => {
      const res = await delegateRequest('PUT', '/api/v1/providers/me/submission-preferences', {
        ahcip_submission_mode: 'AUTO_CLEAN',
      });
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    // PREFERENCE_VIEW delegate cannot access PREFERENCE_EDIT routes
    it('delegate with PREFERENCE_VIEW only cannot PUT /api/v1/providers/me/submission-preferences (requires PREFERENCE_EDIT)', async () => {
      const res = await delegatePrefViewRequest('PUT', '/api/v1/providers/me/submission-preferences', {
        ahcip_submission_mode: 'AUTO_CLEAN',
      });
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('delegate with PREFERENCE_VIEW only cannot PUT /api/v1/providers/me (requires PREFERENCE_EDIT)', async () => {
      const res = await delegatePrefViewRequest('PUT', '/api/v1/providers/me', {
        first_name: 'Attacker',
        last_name: 'Delegate',
      });
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('delegate with PREFERENCE_VIEW only cannot POST /api/v1/providers/me/bas (requires PREFERENCE_EDIT)', async () => {
      const res = await delegatePrefViewRequest('POST', '/api/v1/providers/me/bas', {
        ba_number: '99999',
        ba_type: 'FFS',
      });
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    // CLAIM_VIEW delegate cannot access PROVIDER_VIEW routes (no PROVIDER_VIEW permission)
    it('delegate with CLAIM_VIEW only cannot GET /api/v1/providers/me (requires PROVIDER_VIEW)', async () => {
      const res = await delegateRequest('GET', '/api/v1/providers/me');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('delegate with CLAIM_VIEW only cannot GET /api/v1/providers/me/bas (requires PROVIDER_VIEW)', async () => {
      const res = await delegateRequest('GET', '/api/v1/providers/me/bas');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('delegate with CLAIM_VIEW only cannot GET /api/v1/providers/me/locations (requires PROVIDER_VIEW)', async () => {
      const res = await delegateRequest('GET', '/api/v1/providers/me/locations');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    // PREFERENCE_VIEW delegate cannot access PROVIDER_VIEW routes
    it('delegate with PREFERENCE_VIEW only cannot GET /api/v1/providers/me (requires PROVIDER_VIEW)', async () => {
      const res = await delegatePrefViewRequest('GET', '/api/v1/providers/me');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    // PREFERENCE_VIEW delegate can access PREFERENCE_VIEW routes
    it('delegate with PREFERENCE_VIEW can GET /api/v1/providers/me/submission-preferences', async () => {
      const res = await delegatePrefViewRequest('GET', '/api/v1/providers/me/submission-preferences');
      // Should not be 403 — confirms the delegate has access
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });
  });

  // =========================================================================
  // 4. Internal API access control
  // =========================================================================

  describe('Internal API access control', () => {
    it('GET /api/v1/internal/providers/:id/claim-context without API key returns 401', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/internal/providers/${PLACEHOLDER_UUID}/claim-context`,
      });
      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('UNAUTHORIZED');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/internal/providers/:id/ba-for-claim without API key returns 401', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/internal/providers/${PLACEHOLDER_UUID}/ba-for-claim?claim_type=AHCIP&hsc_code=03.04A`,
      });
      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('UNAUTHORIZED');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/internal/providers/:id/wcb-config-for-form without API key returns 401', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/internal/providers/${PLACEHOLDER_UUID}/wcb-config-for-form?form_id=WCB_PHYSICIAN_FIRST_REPORT`,
      });
      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('UNAUTHORIZED');
      expect(body.data).toBeUndefined();
    });

    it('regular physician session cannot access internal claim-context route', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/internal/providers/${PLACEHOLDER_UUID}/claim-context`,
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });
      // Internal routes use API key auth, not session auth — session cookie is irrelevant
      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();
    });

    it('regular physician session cannot access internal ba-for-claim route', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/internal/providers/${PLACEHOLDER_UUID}/ba-for-claim?claim_type=AHCIP&hsc_code=03.04A`,
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });
      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();
    });

    it('regular physician session cannot access internal wcb-config-for-form route', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/internal/providers/${PLACEHOLDER_UUID}/wcb-config-for-form?form_id=WCB_PHYSICIAN_FIRST_REPORT`,
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });
      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();
    });

    it('invalid API key is rejected for internal routes', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/internal/providers/${PLACEHOLDER_UUID}/claim-context`,
        headers: { 'x-internal-api-key': 'wrong-key-not-matching-at-all!!' },
      });
      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('UNAUTHORIZED');
      expect(body.data).toBeUndefined();
    });

    it('delegate session cannot access internal routes', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/internal/providers/${PLACEHOLDER_UUID}/claim-context`,
        headers: { cookie: `session=${DELEGATE_SESSION_TOKEN}` },
      });
      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();
    });
  });

  // =========================================================================
  // 5. 403 responses do not leak provider data
  // =========================================================================

  describe('403 responses do not leak provider data', () => {
    it('403 on physician-only route does not contain provider details', async () => {
      const res = await delegateRequest('POST', '/api/v1/providers/me/delegates/invite', {
        email: 'delegate@example.com',
        permissions: ['CLAIM_VIEW'],
      });
      expect(res.statusCode).toBe(403);
      const rawBody = res.body;
      expect(rawBody).not.toContain('provider_id');
      expect(rawBody).not.toContain(PHYSICIAN_USER_ID);
      expect(rawBody).not.toContain('billing_number');
      expect(rawBody).not.toContain('cpsa_number');
    });

    it('403 on delegate-only route does not contain delegate details', async () => {
      const res = await physicianRequest('GET', '/api/v1/delegates/me/physicians');
      expect(res.statusCode).toBe(403);
      const rawBody = res.body;
      expect(rawBody).not.toContain('delegate_user_id');
      expect(rawBody).not.toContain(DELEGATE_USER_ID);
      expect(rawBody).not.toContain('CLAIM_VIEW');
      expect(rawBody).not.toContain('PREFERENCE_VIEW');
      expect(rawBody).not.toContain('physicianProviderId');
    });

    it('403 response has consistent error shape with no extra fields', async () => {
      const res = await delegateRequest('PUT', '/api/v1/providers/me/hlink', {
        submitter_prefix: 'MER',
      });
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
      expect(Object.keys(body.error).sort()).toEqual(['code', 'message']);
    });

    it('403 response does not contain stack traces or internals', async () => {
      const res = await delegateRequest('POST', '/api/v1/providers/me/complete-onboarding', {});
      expect(res.statusCode).toBe(403);
      const rawBody = res.body;
      expect(rawBody).not.toContain('stack');
      expect(rawBody).not.toContain('node_modules');
      expect(rawBody).not.toContain('.ts:');
      expect(rawBody).not.toContain('postgres');
      expect(rawBody).not.toContain('drizzle');
    });
  });

  // =========================================================================
  // 6. Sanity: physician can access physician-only routes (not 403)
  // =========================================================================

  describe('Sanity: physician can access physician-only routes', () => {
    it('POST /api/v1/providers/me/complete-onboarding — physician is not 403', async () => {
      const res = await physicianRequest('POST', '/api/v1/providers/me/complete-onboarding', {});
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/providers/me/hlink — physician is not 403', async () => {
      const res = await physicianRequest('GET', '/api/v1/providers/me/hlink');
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/providers/me/delegates — physician is not 403', async () => {
      const res = await physicianRequest('GET', '/api/v1/providers/me/delegates');
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/providers/me/delegates/invite — physician is not 403', async () => {
      const res = await physicianRequest('POST', '/api/v1/providers/me/delegates/invite', {
        email: 'new@example.com',
        permissions: ['CLAIM_VIEW'],
      });
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });
  });
});
