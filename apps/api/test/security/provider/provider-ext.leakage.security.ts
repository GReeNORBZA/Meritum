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

const P1_SESSION_TOKEN = randomBytes(32).toString('hex');
const P1_SESSION_TOKEN_HASH = hashToken(P1_SESSION_TOKEN);
const P1_USER_ID = '11111111-1111-0000-0000-000000000001';
const P1_PROVIDER_ID = P1_USER_ID;
const P1_SESSION_ID = '11111111-1111-0000-0000-000000000011';

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
    appendAuditLog: vi.fn(async (entry: Record<string, unknown>) => {
      auditEntries.push(entry);
    }),
  };
}

function createMockEvents() {
  return { emit: vi.fn() };
}

// ---------------------------------------------------------------------------
// Mock provider repository
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
        error: { code: 'VALIDATION_ERROR', message: 'Validation failed' },
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

function asPhysician(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function unauthenticated(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
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
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Provider Extension Data Leakage Prevention (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    seedUsersAndSessions();
    auditEntries = [];
  });

  // =========================================================================
  // 1. No PHI in 401 error responses for extension endpoints
  // =========================================================================

  describe('No PHI in 401 error responses for extension endpoints', () => {
    it('401 on GET routing-config contains only error object, no provider data', async () => {
      const res = await unauthenticated('GET', '/api/v1/providers/me/routing-config');
      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);

      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
      expect(body.data).toBeUndefined();

      expect(res.body).not.toContain('providerId');
      expect(res.body).not.toContain('routing');
      expect(res.body).not.toContain('facility');
      expect(res.body).not.toContain('schedule');
    });

    it('401 on PUT facility mappings contains only error object', async () => {
      const res = await unauthenticated('PUT', '/api/v1/providers/me/routing-config/facilities', { mappings: [{ ba_id: '00000000-0000-0000-0000-000000000001', functional_centre: 'HOSP', priority: 0 }] });
      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);

      expect(Object.keys(body)).toEqual(['error']);
      expect(body.data).toBeUndefined();
      expect(res.body).not.toContain('facility');
      expect(res.body).not.toContain('mapping');
    });

    it('401 on PUT schedule mappings contains only error object', async () => {
      const res = await unauthenticated('PUT', '/api/v1/providers/me/routing-config/schedule', { mappings: [{ ba_id: '00000000-0000-0000-0000-000000000001', day_of_week: 1, start_time: '08:00', end_time: '17:00', priority: 0 }] });
      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);

      expect(Object.keys(body)).toEqual(['error']);
      expect(body.data).toBeUndefined();
    });

    it('401 on POST routing resolve contains only error object', async () => {
      const res = await unauthenticated('POST', '/api/v1/claims/routing/resolve', { service_code: '03.04A' });
      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);

      expect(Object.keys(body)).toEqual(['error']);
      expect(body.data).toBeUndefined();
      expect(res.body).not.toContain('claim');
      expect(res.body).not.toContain('patient');
    });

    it('401 on POST routing conflict contains only error object', async () => {
      const res = await unauthenticated('POST', '/api/v1/claims/routing/conflict', { selected_ba_id: '00000000-0000-0000-0000-000000000001', service_code: '03.04A' });
      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);

      expect(Object.keys(body)).toEqual(['error']);
      expect(body.data).toBeUndefined();
    });

    it('401 on GET connect-care contains only error object', async () => {
      const res = await unauthenticated('GET', '/api/v1/providers/me/connect-care');
      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);

      expect(Object.keys(body)).toEqual(['error']);
      expect(body.data).toBeUndefined();
      expect(res.body).not.toContain('connect_care');
      expect(res.body).not.toContain('enabled');
    });

    it('401 on PUT connect-care contains only error object', async () => {
      const res = await unauthenticated('PUT', '/api/v1/providers/me/connect-care', { is_connect_care: true });
      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);

      expect(Object.keys(body)).toEqual(['error']);
      expect(body.data).toBeUndefined();
    });
  });

  // =========================================================================
  // 2. No technology headers in extension responses
  // =========================================================================

  describe('No technology-revealing headers in extension responses', () => {
    it('no X-Powered-By header on authenticated GET routing-config', async () => {
      const res = await asPhysician('GET', '/api/v1/providers/me/routing-config');
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By header on 401 routing-config response', async () => {
      const res = await unauthenticated('GET', '/api/v1/providers/me/routing-config');
      expect(res.statusCode).toBe(401);
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By header on authenticated GET connect-care', async () => {
      const res = await asPhysician('GET', '/api/v1/providers/me/connect-care');
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By header on 401 connect-care response', async () => {
      const res = await unauthenticated('GET', '/api/v1/providers/me/connect-care');
      expect(res.statusCode).toBe(401);
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By header on POST routing resolve (validation error)', async () => {
      const res = await asPhysician('POST', '/api/v1/claims/routing/resolve', {
        invalid_field: 'test',
      });
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no Server header revealing technology on extension endpoints', async () => {
      const res = await asPhysician('GET', '/api/v1/providers/me/routing-config');
      const serverHeader = res.headers['server'];
      if (serverHeader) {
        const lower = (serverHeader as string).toLowerCase();
        expect(lower).not.toContain('fastify');
        expect(lower).not.toContain('node');
        expect(lower).not.toContain('express');
      }
    });
  });

  // =========================================================================
  // 3. Extension responses always use application/json Content-Type
  // =========================================================================

  describe('Extension responses use application/json Content-Type', () => {
    it('GET routing-config returns application/json', async () => {
      const res = await asPhysician('GET', '/api/v1/providers/me/routing-config');
      expect(res.headers['content-type']).toContain('application/json');
    });

    it('GET connect-care returns application/json', async () => {
      const res = await asPhysician('GET', '/api/v1/providers/me/connect-care');
      expect(res.headers['content-type']).toContain('application/json');
    });

    it('401 on extension endpoint returns application/json', async () => {
      const res = await unauthenticated('GET', '/api/v1/providers/me/routing-config');
      expect(res.statusCode).toBe(401);
      expect(res.headers['content-type']).toContain('application/json');
    });

    it('validation error on routing resolve returns application/json', async () => {
      const res = await asPhysician('POST', '/api/v1/claims/routing/resolve', { service_code: '03.04A' });
      expect(res.headers['content-type']).toContain('application/json');
    });

    it('validation error on connect-care update returns application/json', async () => {
      const res = await asPhysician('PUT', '/api/v1/providers/me/connect-care', { is_connect_care: true });
      expect(res.headers['content-type']).toContain('application/json');
    });
  });

  // =========================================================================
  // 4. Error responses do not expose internal details
  // =========================================================================

  describe('Error responses on extension endpoints do not expose internals', () => {
    it('error on routing facility update does not contain stack traces', async () => {
      const res = await asPhysician('PUT', '/api/v1/providers/me/routing-config/facilities', {
        invalid: "'; DROP TABLE routing;--",
      });

      const rawBody = res.body;
      expect(rawBody).not.toContain('node_modules');
      expect(rawBody).not.toMatch(/\.ts:\d+/);
      expect(rawBody).not.toContain('at ');
    });

    it('error on routing schedule update does not contain database details', async () => {
      const res = await asPhysician('PUT', '/api/v1/providers/me/routing-config/schedule', {
        invalid: 'test',
      });

      const lower = res.body.toLowerCase();
      expect(lower).not.toContain('postgres');
      expect(lower).not.toContain('drizzle');
      expect(lower).not.toContain('pg_');
      expect(lower).not.toContain('column');
    });

    it('error on connect-care update does not contain database details', async () => {
      const res = await asPhysician('PUT', '/api/v1/providers/me/connect-care', {
        invalid: 'test',
      });

      const lower = res.body.toLowerCase();
      expect(lower).not.toContain('postgres');
      expect(lower).not.toContain('drizzle');
      expect(lower).not.toContain('pg_');
    });

    it('error on routing resolve does not expose stack traces or internals', async () => {
      const res = await asPhysician('POST', '/api/v1/claims/routing/resolve', {
        bad_field: true,
      });

      const body = JSON.parse(res.body);
      expect(body.error).not.toHaveProperty('stack');
      expect(body.error).not.toHaveProperty('stackTrace');
      expect(JSON.stringify(body)).not.toMatch(/at\s+\w+\s+\(/);
      expect(JSON.stringify(body)).not.toMatch(/\.ts:\d+:\d+/);
      expect(JSON.stringify(body)).not.toContain('node_modules');
    });

    it('error on routing conflict does not expose stack traces or internals', async () => {
      const res = await asPhysician('POST', '/api/v1/claims/routing/conflict', {
        bad_field: true,
      });

      const body = JSON.parse(res.body);
      expect(body.error).not.toHaveProperty('stack');
      expect(JSON.stringify(body)).not.toMatch(/\.ts:\d+/);
      expect(JSON.stringify(body)).not.toContain('node_modules');
    });
  });

  // =========================================================================
  // 5. Sensitive session data never appears in extension error responses
  // =========================================================================

  describe('Session data never appears in extension error responses', () => {
    it('authenticated extension error does not contain session token', async () => {
      const res = await asPhysician('PUT', '/api/v1/providers/me/routing-config/facilities', { mappings: [{ ba_id: '00000000-0000-0000-0000-000000000001', functional_centre: 'HOSP', priority: 0 }] });
      expect(res.body).not.toContain(P1_SESSION_TOKEN);
      expect(res.body).not.toContain(P1_SESSION_TOKEN_HASH);
      expect(res.body).not.toContain('tokenHash');
      expect(res.body).not.toContain('token_hash');
    });

    it('authenticated connect-care error does not contain session data', async () => {
      const res = await asPhysician('PUT', '/api/v1/providers/me/connect-care', { is_connect_care: true });
      expect(res.body).not.toContain(P1_SESSION_TOKEN);
      expect(res.body).not.toContain('sessionId');
      expect(res.body).not.toContain('session_id');
    });

    it('routing resolve error does not contain password hash or TOTP secret', async () => {
      const res = await asPhysician('POST', '/api/v1/claims/routing/resolve', { service_code: '03.04A' });
      expect(res.body).not.toContain('passwordHash');
      expect(res.body).not.toContain('password_hash');
      expect(res.body).not.toContain('totpSecret');
      expect(res.body).not.toContain('JBSWY3DPEHPK3PXP');
    });
  });
});
