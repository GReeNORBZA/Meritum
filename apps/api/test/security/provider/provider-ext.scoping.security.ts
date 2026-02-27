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
// Fixed test identities -- Two isolated physicians
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

// Routing config store keyed by providerId
const routingConfigStore: Record<string, any> = {};
// Connect care store keyed by providerId
const connectCareStore: Record<string, any> = {};

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
  return {
    appendAuditLog: vi.fn(async () => {}),
  };
}

function createMockEvents() {
  return { emit: vi.fn() };
}

// ---------------------------------------------------------------------------
// Stub provider repository with routing and connect care support
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
    const statusCode = (error as any).statusCode;
    if (statusCode && statusCode >= 400 && statusCode < 500) {
      return reply.code(statusCode).send({
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

function asPhysician1(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function asPhysician2(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${P2_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

// ---------------------------------------------------------------------------
// Seed users and sessions
// ---------------------------------------------------------------------------

function seedUsersAndSessions() {
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
    ipAddress: '127.0.0.2',
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

describe('Provider Extension /me Scoping -- Tenant Isolation (Security)', () => {
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
  // 1. Routing config is scoped to /me -- each physician sees only their own
  // =========================================================================

  describe('Routing config scoping', () => {
    it('GET /api/v1/providers/me/routing-config as physician1 does not return 401 or 403', async () => {
      const res = await asPhysician1('GET', '/api/v1/providers/me/routing-config');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /api/v1/providers/me/routing-config as physician2 does not return 401 or 403', async () => {
      const res = await asPhysician2('GET', '/api/v1/providers/me/routing-config');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('physician1 routing config response does not contain physician2 identifiers', async () => {
      const res = await asPhysician1('GET', '/api/v1/providers/me/routing-config');
      // Response must not contain physician2's user/provider ID
      expect(res.body).not.toContain(P2_USER_ID);
      expect(res.body).not.toContain(P2_PROVIDER_ID);
    });

    it('physician2 routing config response does not contain physician1 identifiers', async () => {
      const res = await asPhysician2('GET', '/api/v1/providers/me/routing-config');
      expect(res.body).not.toContain(P1_USER_ID);
      expect(res.body).not.toContain(P1_PROVIDER_ID);
    });
  });

  // =========================================================================
  // 2. Connect Care is scoped to /me
  // =========================================================================

  describe('Connect Care scoping', () => {
    it('GET /api/v1/providers/me/connect-care as physician1 does not return 401 or 403', async () => {
      const res = await asPhysician1('GET', '/api/v1/providers/me/connect-care');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /api/v1/providers/me/connect-care as physician2 does not return 401 or 403', async () => {
      const res = await asPhysician2('GET', '/api/v1/providers/me/connect-care');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('physician1 connect-care response does not contain physician2 identifiers', async () => {
      const res = await asPhysician1('GET', '/api/v1/providers/me/connect-care');
      expect(res.body).not.toContain(P2_USER_ID);
      expect(res.body).not.toContain(P2_PROVIDER_ID);
    });

    it('physician2 connect-care response does not contain physician1 identifiers', async () => {
      const res = await asPhysician2('GET', '/api/v1/providers/me/connect-care');
      expect(res.body).not.toContain(P1_USER_ID);
      expect(res.body).not.toContain(P1_PROVIDER_ID);
    });
  });

  // =========================================================================
  // 3. No direct provider ID parameter -- /me only
  // =========================================================================

  describe('Extension endpoints use /me only (no provider ID in URL)', () => {
    it('no route exists for GET /api/v1/providers/:id/routing-config -- returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/providers/${P2_PROVIDER_ID}/routing-config`);
      expect(res.statusCode).toBe(404);
    });

    it('no route exists for GET /api/v1/providers/:id/connect-care -- returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/providers/${P2_PROVIDER_ID}/connect-care`);
      expect(res.statusCode).toBe(404);
    });

    it('no route exists for PUT /api/v1/providers/:id/routing-config/facilities -- returns 404', async () => {
      const res = await asPhysician1('PUT', `/api/v1/providers/${P2_PROVIDER_ID}/routing-config/facilities`, {});
      expect(res.statusCode).toBe(404);
    });

    it('no route exists for PUT /api/v1/providers/:id/connect-care -- returns 404', async () => {
      const res = await asPhysician1('PUT', `/api/v1/providers/${P2_PROVIDER_ID}/connect-care`, {});
      expect(res.statusCode).toBe(404);
    });
  });

  // =========================================================================
  // 4. Routing resolve/conflict -- scoped to authenticated user context
  // =========================================================================

  describe('Routing resolve and conflict scoped to authenticated user', () => {
    it('POST /api/v1/claims/routing/resolve as physician1 does not return 401 or 403', async () => {
      const res = await asPhysician1('POST', '/api/v1/claims/routing/resolve', {});
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST /api/v1/claims/routing/conflict as physician1 does not return 401 or 403', async () => {
      const res = await asPhysician1('POST', '/api/v1/claims/routing/conflict', {});
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('routing resolve response does not leak other provider identifiers', async () => {
      const res = await asPhysician1('POST', '/api/v1/claims/routing/resolve', {});
      expect(res.body).not.toContain(P2_USER_ID);
      expect(res.body).not.toContain(P2_PROVIDER_ID);
    });

    it('routing conflict response does not leak other provider identifiers', async () => {
      const res = await asPhysician1('POST', '/api/v1/claims/routing/conflict', {});
      expect(res.body).not.toContain(P2_USER_ID);
      expect(res.body).not.toContain(P2_PROVIDER_ID);
    });
  });
});
