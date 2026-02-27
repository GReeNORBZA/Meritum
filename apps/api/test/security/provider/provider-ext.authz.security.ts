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
import { providerRoutes } from '../../../src/domains/provider/provider.routes.js';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import {
  type ProviderServiceDeps,
} from '../../../src/domains/provider/provider.service.js';
import { type ProviderHandlerDeps } from '../../../src/domains/provider/provider.handlers.js';
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

// Delegate session (with CLAIM_VIEW only -- no PREFERENCE_EDIT, no PROVIDER_VIEW)
const DELEGATE_CLAIMVIEW_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_CLAIMVIEW_SESSION_TOKEN_HASH = hashToken(DELEGATE_CLAIMVIEW_SESSION_TOKEN);
const DELEGATE_CLAIMVIEW_USER_ID = '22222222-0000-0000-0000-000000000002';
const DELEGATE_CLAIMVIEW_SESSION_ID = '22222222-0000-0000-0000-000000000022';

// Delegate session with PROVIDER_VIEW only (no PREFERENCE_EDIT, no CLAIM_VIEW)
const DELEGATE_PROVVIEW_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_PROVVIEW_SESSION_TOKEN_HASH = hashToken(DELEGATE_PROVVIEW_SESSION_TOKEN);
const DELEGATE_PROVVIEW_USER_ID = '33333333-0000-0000-0000-000000000003';
const DELEGATE_PROVVIEW_SESSION_ID = '33333333-0000-0000-0000-000000000033';

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
// Mock provider repository (stubs -- not exercised in authz tests)
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

  const handlerDeps: ProviderHandlerDeps = {
    serviceDeps: createStubServiceDeps(),
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

function delegateClaimViewRequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${DELEGATE_CLAIMVIEW_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function delegateProvViewRequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${DELEGATE_PROVVIEW_SESSION_TOKEN}` },
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

  // Delegate user with CLAIM_VIEW only (no PREFERENCE_EDIT, no PROVIDER_VIEW)
  users.push({
    userId: DELEGATE_CLAIMVIEW_USER_ID,
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
      delegateUserId: DELEGATE_CLAIMVIEW_USER_ID,
      physicianProviderId: PHYSICIAN_USER_ID,
      permissions: ['CLAIM_VIEW'],
      linkageId: '44444444-0000-0000-0000-000000000044',
    },
  });
  sessions.push({
    sessionId: DELEGATE_CLAIMVIEW_SESSION_ID,
    userId: DELEGATE_CLAIMVIEW_USER_ID,
    tokenHash: DELEGATE_CLAIMVIEW_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

  // Delegate user with PROVIDER_VIEW only (no PREFERENCE_EDIT, no CLAIM_VIEW)
  users.push({
    userId: DELEGATE_PROVVIEW_USER_ID,
    email: 'delegate-prov@example.com',
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    role: 'DELEGATE',
    subscriptionStatus: 'TRIAL',
    delegateContext: {
      delegateUserId: DELEGATE_PROVVIEW_USER_ID,
      physicianProviderId: PHYSICIAN_USER_ID,
      permissions: ['PROVIDER_VIEW'],
      linkageId: '55555555-0000-0000-0000-000000000055',
    },
  });
  sessions.push({
    sessionId: DELEGATE_PROVVIEW_SESSION_ID,
    userId: DELEGATE_PROVVIEW_USER_ID,
    tokenHash: DELEGATE_PROVVIEW_SESSION_TOKEN_HASH,
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

describe('Provider Extension Authorization & Role Enforcement (Security)', () => {
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
  // 1. Delegate without PREFERENCE_EDIT cannot PUT routing config
  // =========================================================================

  describe('Delegate without PREFERENCE_EDIT cannot update routing config', () => {
    it('delegate with CLAIM_VIEW only cannot PUT /api/v1/providers/me/routing-config/facilities -- 403', async () => {
      const res = await delegateClaimViewRequest('PUT', '/api/v1/providers/me/routing-config/facilities', { mappings: [{ ba_id: '00000000-0000-0000-0000-000000000001', functional_centre: 'HOSP', priority: 0 }] });
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('delegate with CLAIM_VIEW only cannot PUT /api/v1/providers/me/routing-config/schedule -- 403', async () => {
      const res = await delegateClaimViewRequest('PUT', '/api/v1/providers/me/routing-config/schedule', { mappings: [{ ba_id: '00000000-0000-0000-0000-000000000001', day_of_week: 1, start_time: '08:00', end_time: '17:00', priority: 0 }] });
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('delegate with PROVIDER_VIEW only cannot PUT /api/v1/providers/me/routing-config/facilities -- 403', async () => {
      const res = await delegateProvViewRequest('PUT', '/api/v1/providers/me/routing-config/facilities', { mappings: [{ ba_id: '00000000-0000-0000-0000-000000000001', functional_centre: 'HOSP', priority: 0 }] });
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('delegate with PROVIDER_VIEW only cannot PUT /api/v1/providers/me/routing-config/schedule -- 403', async () => {
      const res = await delegateProvViewRequest('PUT', '/api/v1/providers/me/routing-config/schedule', { mappings: [{ ba_id: '00000000-0000-0000-0000-000000000001', day_of_week: 1, start_time: '08:00', end_time: '17:00', priority: 0 }] });
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });
  });

  // =========================================================================
  // 2. Delegate without PROVIDER_VIEW cannot GET routing config
  // =========================================================================

  describe('Delegate without PROVIDER_VIEW cannot read routing config', () => {
    it('delegate with CLAIM_VIEW only cannot GET /api/v1/providers/me/routing-config -- 403', async () => {
      const res = await delegateClaimViewRequest('GET', '/api/v1/providers/me/routing-config');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });
  });

  // =========================================================================
  // 3. Delegate without CLAIM_VIEW cannot resolve or detect routing conflicts
  // =========================================================================

  describe('Delegate without CLAIM_VIEW cannot access routing resolution', () => {
    it('delegate with PROVIDER_VIEW only cannot POST /api/v1/claims/routing/resolve -- 403', async () => {
      const res = await delegateProvViewRequest('POST', '/api/v1/claims/routing/resolve', { service_code: '03.04A' });
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('delegate with PROVIDER_VIEW only cannot POST /api/v1/claims/routing/conflict -- 403', async () => {
      const res = await delegateProvViewRequest('POST', '/api/v1/claims/routing/conflict', { selected_ba_id: '00000000-0000-0000-0000-000000000001', service_code: '03.04A' });
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });
  });

  // =========================================================================
  // 4. Delegate cannot access Connect Care (physician role required)
  // =========================================================================

  describe('Delegate cannot access Connect Care (physician role required)', () => {
    it('delegate with CLAIM_VIEW cannot GET /api/v1/providers/me/connect-care -- 403', async () => {
      const res = await delegateClaimViewRequest('GET', '/api/v1/providers/me/connect-care');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('delegate with CLAIM_VIEW cannot PUT /api/v1/providers/me/connect-care -- 403', async () => {
      const res = await delegateClaimViewRequest('PUT', '/api/v1/providers/me/connect-care', { is_connect_care: true });
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('delegate with PROVIDER_VIEW cannot GET /api/v1/providers/me/connect-care -- 403', async () => {
      const res = await delegateProvViewRequest('GET', '/api/v1/providers/me/connect-care');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('delegate with PROVIDER_VIEW cannot PUT /api/v1/providers/me/connect-care -- 403', async () => {
      const res = await delegateProvViewRequest('PUT', '/api/v1/providers/me/connect-care', { is_connect_care: true });
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });
  });

  // =========================================================================
  // 5. 403 responses do not leak data
  // =========================================================================

  describe('403 responses do not leak provider data', () => {
    it('403 on routing-config PUT does not contain provider details', async () => {
      const res = await delegateClaimViewRequest('PUT', '/api/v1/providers/me/routing-config/facilities', { mappings: [{ ba_id: '00000000-0000-0000-0000-000000000001', functional_centre: 'HOSP', priority: 0 }] });
      expect(res.statusCode).toBe(403);
      const rawBody = res.body;
      expect(rawBody).not.toContain('provider_id');
      expect(rawBody).not.toContain(PHYSICIAN_USER_ID);
      expect(rawBody).not.toContain('routing');
      expect(rawBody).not.toContain('facility');
    });

    it('403 on connect-care does not contain connect care data', async () => {
      const res = await delegateClaimViewRequest('GET', '/api/v1/providers/me/connect-care');
      expect(res.statusCode).toBe(403);
      const rawBody = res.body;
      expect(rawBody).not.toContain('connect_care');
      expect(rawBody).not.toContain('enabled');
      expect(rawBody).not.toContain(PHYSICIAN_USER_ID);
    });

    it('403 response has consistent error shape with no extra fields', async () => {
      const res = await delegateClaimViewRequest('PUT', '/api/v1/providers/me/routing-config/schedule', { mappings: [{ ba_id: '00000000-0000-0000-0000-000000000001', day_of_week: 1, start_time: '08:00', end_time: '17:00', priority: 0 }] });
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
      expect(Object.keys(body.error).sort()).toEqual(['code', 'message']);
    });

    it('403 response does not contain stack traces or internals', async () => {
      const res = await delegateProvViewRequest('POST', '/api/v1/claims/routing/resolve', { service_code: '03.04A' });
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
  // 6. Sanity: physician can access all extension endpoints (not 403)
  // =========================================================================

  describe('Sanity: physician can access extension endpoints', () => {
    it('GET /api/v1/providers/me/routing-config -- physician is not 403', async () => {
      const res = await physicianRequest('GET', '/api/v1/providers/me/routing-config');
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('PUT /api/v1/providers/me/routing-config/facilities -- physician is not 403', async () => {
      const res = await physicianRequest('PUT', '/api/v1/providers/me/routing-config/facilities', { mappings: [{ ba_id: '00000000-0000-0000-0000-000000000001', functional_centre: 'HOSP', priority: 0 }] });
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('PUT /api/v1/providers/me/routing-config/schedule -- physician is not 403', async () => {
      const res = await physicianRequest('PUT', '/api/v1/providers/me/routing-config/schedule', { mappings: [{ ba_id: '00000000-0000-0000-0000-000000000001', day_of_week: 1, start_time: '08:00', end_time: '17:00', priority: 0 }] });
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/claims/routing/resolve -- physician is not 403', async () => {
      const res = await physicianRequest('POST', '/api/v1/claims/routing/resolve', { service_code: '03.04A' });
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/claims/routing/conflict -- physician is not 403', async () => {
      const res = await physicianRequest('POST', '/api/v1/claims/routing/conflict', { selected_ba_id: '00000000-0000-0000-0000-000000000001', service_code: '03.04A' });
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/providers/me/connect-care -- physician is not 403', async () => {
      const res = await physicianRequest('GET', '/api/v1/providers/me/connect-care');
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('PUT /api/v1/providers/me/connect-care -- physician is not 403', async () => {
      const res = await physicianRequest('PUT', '/api/v1/providers/me/connect-care', { is_connect_care: true });
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });
  });
});
