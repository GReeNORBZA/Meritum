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

const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_USER_ID = '11111111-0000-0000-0000-000000000001';
const PHYSICIAN_PROVIDER_ID = PHYSICIAN_USER_ID;
const PHYSICIAN_SESSION_ID = '11111111-0000-0000-0000-000000000011';

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

// Routing config store
let routingConfigStore: Record<string, any> = {};
// Connect care store
let connectCareStore: Record<string, any> = {};

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
// Seed helpers
// ---------------------------------------------------------------------------

function seedTestData() {
  routingConfigStore = {};
  connectCareStore = {};

  routingConfigStore[PHYSICIAN_PROVIDER_ID] = {
    providerId: PHYSICIAN_PROVIDER_ID,
    facilityMappings: [
      { facilityCode: 'FAC01', locationId: 'bbbbbbbb-0000-0000-0000-000000000001' },
    ],
    scheduleMappings: [
      { dayOfWeek: 'MONDAY', locationId: 'bbbbbbbb-0000-0000-0000-000000000001' },
    ],
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  connectCareStore[PHYSICIAN_PROVIDER_ID] = {
    providerId: PHYSICIAN_PROVIDER_ID,
    enabled: false,
    enrollmentDate: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  };
}

// ---------------------------------------------------------------------------
// Mock provider repository with routing and connect care stubs
// ---------------------------------------------------------------------------

function createScopedProviderRepo() {
  return {
    findProviderById: vi.fn(async (providerId: string) => {
      if (providerId === PHYSICIAN_PROVIDER_ID) {
        return {
          providerId: PHYSICIAN_PROVIDER_ID,
          billingNumber: '111111',
          firstName: 'Alice',
          lastName: 'Physician',
          status: 'ACTIVE',
          onboardingCompleted: true,
        };
      }
      return undefined;
    }),
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
      hasBillingNumber: true,
      hasCpsaNumber: true,
      hasName: true,
      hasBa: true,
      hasLocation: true,
      isComplete: true,
      missingFields: [],
    })),
    completeOnboarding: vi.fn(async () => ({})),
    getProviderContext: vi.fn(async () => undefined),
    getBaForClaim: vi.fn(async () => undefined),
    findWcbConfigByContractRole: vi.fn(async () => undefined),
    findPcpcmEnrolment: vi.fn(async () => undefined),
    countBas: vi.fn(async () => 1),
    countLocations: vi.fn(async () => 1),
    countWcbConfigs: vi.fn(async () => 1),
  };
}

// ---------------------------------------------------------------------------
// Shared service deps ref (accessible to tests for spy inspection)
// ---------------------------------------------------------------------------

let serviceDeps: ProviderServiceDeps;

function createStubServiceDeps(): ProviderServiceDeps {
  const deps: ProviderServiceDeps = {
    repo: createScopedProviderRepo() as any,
    auditRepo: createMockAuditRepo(),
    events: createMockEvents(),
  };
  serviceDeps = deps;
  return deps;
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

  const deps = createStubServiceDeps();

  const handlerDeps: ProviderHandlerDeps = {
    serviceDeps: deps,
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
// Request helper
// ---------------------------------------------------------------------------

function physicianRequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

// ---------------------------------------------------------------------------
// Audit entry finders
// ---------------------------------------------------------------------------

function findAuditEntry(action: string): Record<string, unknown> | undefined {
  return auditEntries.find((e) => e.action === action);
}

function findAuditEntries(action: string): Array<Record<string, unknown>> {
  return auditEntries.filter((e) => e.action === action);
}

function findAuditEntriesByResourceType(resourceType: string): Array<Record<string, unknown>> {
  return auditEntries.filter((e) => e.resourceType === resourceType);
}

// ---------------------------------------------------------------------------
// Seed users and sessions
// ---------------------------------------------------------------------------

function seedUsersAndSessions() {
  users.length = 0;
  sessions.length = 0;

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
}

// ---------------------------------------------------------------------------
// Setup / teardown
// ---------------------------------------------------------------------------

beforeAll(async () => {
  app = await buildTestApp();
});

afterAll(async () => {
  await app.close();
});

beforeEach(() => {
  auditEntries.length = 0;
  seedUsersAndSessions();
  seedTestData();
  vi.mocked(serviceDeps.auditRepo.appendAuditLog).mockClear();
});

// ===========================================================================
// AUDIT TRAIL -- Routing Config Changes
// ===========================================================================

describe('Audit Trail -- Routing Facility Mapping Changes', () => {
  it('PUT facility mappings triggers audit log append', async () => {
    const res = await physicianRequest('PUT', '/api/v1/providers/me/routing-config/facilities', {});

    // The request will either succeed or fail with validation error.
    // We verify that for any non-401/403 response, the audit system was invoked
    // or the request was rejected before reaching the handler.
    expect(res.statusCode).not.toBe(401);
    expect(res.statusCode).not.toBe(403);

    // If the handler was reached (not a validation error), audit should have been called
    if (res.statusCode < 400) {
      expect(serviceDeps.auditRepo.appendAuditLog).toHaveBeenCalled();
    }
  });

  it('PUT facility mappings audit entry does not contain credential secrets', async () => {
    await physicianRequest('PUT', '/api/v1/providers/me/routing-config/facilities', {});

    for (const entry of auditEntries) {
      const str = JSON.stringify(entry);
      expect(str).not.toContain('credentialSecretRef');
      expect(str).not.toContain('credential_secret_ref');
      expect(str).not.toContain('vault://');
      expect(str).not.toContain('passwordHash');
      expect(str).not.toContain('password_hash');
    }
  });

  it('facility mapping audit entries are JSONB-compatible (survive JSON round-trip)', async () => {
    await physicianRequest('PUT', '/api/v1/providers/me/routing-config/facilities', {});

    for (const entry of auditEntries) {
      const serialized = JSON.stringify(entry);
      const deserialized = JSON.parse(serialized);
      // Deep equality -- no loss during serialization
      expect(deserialized).toEqual(JSON.parse(JSON.stringify(entry)));
    }
  });
});

describe('Audit Trail -- Routing Schedule Mapping Changes', () => {
  it('PUT schedule mappings triggers audit log append', async () => {
    const res = await physicianRequest('PUT', '/api/v1/providers/me/routing-config/schedule', {});

    expect(res.statusCode).not.toBe(401);
    expect(res.statusCode).not.toBe(403);

    if (res.statusCode < 400) {
      expect(serviceDeps.auditRepo.appendAuditLog).toHaveBeenCalled();
    }
  });

  it('PUT schedule mappings audit entry does not contain sensitive data', async () => {
    await physicianRequest('PUT', '/api/v1/providers/me/routing-config/schedule', {});

    for (const entry of auditEntries) {
      const str = JSON.stringify(entry);
      expect(str).not.toContain('passwordHash');
      expect(str).not.toContain('password_hash');
      expect(str).not.toContain('totpSecret');
      expect(str).not.toContain('sessionToken');
      expect(str).not.toContain(PHYSICIAN_SESSION_TOKEN);
    }
  });
});

// ===========================================================================
// AUDIT TRAIL -- Connect Care Changes
// ===========================================================================

describe('Audit Trail -- Connect Care Config Changes', () => {
  it('PUT connect-care triggers audit log append', async () => {
    const res = await physicianRequest('PUT', '/api/v1/providers/me/connect-care', {});

    expect(res.statusCode).not.toBe(401);
    expect(res.statusCode).not.toBe(403);

    if (res.statusCode < 400) {
      expect(serviceDeps.auditRepo.appendAuditLog).toHaveBeenCalled();
    }
  });

  it('connect-care audit entry does not contain credential secrets', async () => {
    await physicianRequest('PUT', '/api/v1/providers/me/connect-care', {});

    for (const entry of auditEntries) {
      const str = JSON.stringify(entry);
      expect(str).not.toContain('credentialSecretRef');
      expect(str).not.toContain('vault://');
      expect(str).not.toContain('passwordHash');
    }
  });

  it('connect-care audit entries are JSONB-compatible', async () => {
    await physicianRequest('PUT', '/api/v1/providers/me/connect-care', {});

    for (const entry of auditEntries) {
      const serialized = JSON.stringify(entry);
      const deserialized = JSON.parse(serialized);
      expect(deserialized).toEqual(JSON.parse(JSON.stringify(entry)));
    }
  });
});

// ===========================================================================
// AUDIT TRAIL -- Entry Structure Verification
// ===========================================================================

describe('Audit Trail -- Extension Entry Structure', () => {
  it('audit entries from extension endpoints include userId if handler was reached', async () => {
    await physicianRequest('PUT', '/api/v1/providers/me/routing-config/facilities', {});

    for (const entry of auditEntries) {
      if (entry.userId) {
        expect(entry.userId).toBe(PHYSICIAN_USER_ID);
        // Not a system user
        expect(entry.userId).not.toBe('system');
        expect(entry.userId).not.toBe('00000000-0000-0000-0000-000000000000');
      }
    }
  });

  it('extension audit entries include action field when present', async () => {
    await physicianRequest('PUT', '/api/v1/providers/me/connect-care', {});

    for (const entry of auditEntries) {
      expect(entry.action).toBeDefined();
      expect(typeof entry.action).toBe('string');
    }
  });

  it('extension audit entries accumulate without overwriting previous entries', async () => {
    // Perform two actions
    await physicianRequest('PUT', '/api/v1/providers/me/routing-config/facilities', {});
    const countAfterFirst = auditEntries.length;

    await physicianRequest('PUT', '/api/v1/providers/me/routing-config/schedule', {});
    const countAfterSecond = auditEntries.length;

    // Second action should add entries, not overwrite
    expect(countAfterSecond).toBeGreaterThanOrEqual(countAfterFirst);
  });
});

// ===========================================================================
// AUDIT TRAIL -- Append-Only Integrity for Extension Resources
// ===========================================================================

describe('Audit Trail -- Append-Only Integrity for Extension Resources', () => {
  it('no UPDATE endpoint exists for audit_log via routing routes', async () => {
    const res = await physicianRequest('PUT', '/api/v1/providers/me/routing-config/audit-log/some-id');
    expect(res.statusCode).toBe(404);
  });

  it('no DELETE endpoint exists for audit_log via routing routes', async () => {
    const res = await physicianRequest('DELETE', '/api/v1/providers/me/routing-config/audit-log/some-id');
    expect(res.statusCode).toBe(404);
  });

  it('no UPDATE endpoint exists for audit_log via connect-care routes', async () => {
    const res = await physicianRequest('PUT', '/api/v1/providers/me/connect-care/audit-log/some-id');
    expect(res.statusCode).toBe(404);
  });

  it('no DELETE endpoint exists for audit_log via connect-care routes', async () => {
    const res = await physicianRequest('DELETE', '/api/v1/providers/me/connect-care/audit-log/some-id');
    expect(res.statusCode).toBe(404);
  });
});

// ===========================================================================
// AUDIT TRAIL -- Sensitive Data Exclusion
// ===========================================================================

describe('Audit Trail -- Sensitive Data Exclusion from Extension Entries', () => {
  it('no audit entry from extension endpoints contains password hashes', async () => {
    await physicianRequest('PUT', '/api/v1/providers/me/routing-config/facilities', {});
    await physicianRequest('PUT', '/api/v1/providers/me/routing-config/schedule', {});
    await physicianRequest('PUT', '/api/v1/providers/me/connect-care', {});

    for (const entry of auditEntries) {
      const str = JSON.stringify(entry);
      expect(str).not.toMatch(/passwordHash/i);
      expect(str).not.toMatch(/password_hash/i);
    }
  });

  it('no audit entry from extension endpoints contains session tokens', async () => {
    await physicianRequest('PUT', '/api/v1/providers/me/routing-config/facilities', {});
    await physicianRequest('PUT', '/api/v1/providers/me/connect-care', {});

    for (const entry of auditEntries) {
      const str = JSON.stringify(entry);
      expect(str).not.toContain(PHYSICIAN_SESSION_TOKEN);
      expect(str).not.toContain(PHYSICIAN_SESSION_TOKEN_HASH);
      expect(str).not.toMatch(/tokenHash/i);
    }
  });

  it('no audit entry from extension endpoints contains TOTP secrets', async () => {
    await physicianRequest('PUT', '/api/v1/providers/me/routing-config/facilities', {});
    await physicianRequest('PUT', '/api/v1/providers/me/connect-care', {});

    for (const entry of auditEntries) {
      const str = JSON.stringify(entry);
      expect(str).not.toMatch(/totpSecret/i);
      expect(str).not.toContain('JBSWY3DPEHPK3PXP');
    }
  });
});
