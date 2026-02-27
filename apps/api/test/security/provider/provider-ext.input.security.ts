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
// Fixed test user/session
// ---------------------------------------------------------------------------

const FIXED_SESSION_TOKEN = randomBytes(32).toString('hex');
const FIXED_SESSION_TOKEN_HASH = hashToken(FIXED_SESSION_TOKEN);
const FIXED_USER_ID = '22222222-0000-0000-0000-000000000001';
const FIXED_SESSION_ID = '33333333-0000-0000-0000-000000000001';

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
  role?: string;
  subscriptionStatus?: string;
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
    createSession: vi.fn(async () => {
      return { sessionId: '44444444-0000-0000-0000-000000000001' };
    }),
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      const session = sessions.find((s) => s.tokenHash === tokenHash && !s.revoked);
      if (!session) return undefined;
      const user = users.find((u) => u.userId === session.userId);
      if (!user) return undefined;
      return {
        session,
        user: {
          userId: user.userId,
          role: user.role ?? 'PHYSICIAN',
          subscriptionStatus: user.subscriptionStatus ?? 'TRIAL',
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
// Helpers
// ---------------------------------------------------------------------------

function authCookie(): string {
  return `session=${FIXED_SESSION_TOKEN}`;
}

async function authedRequest(
  method: 'GET' | 'POST' | 'PUT' | 'DELETE',
  url: string,
  payload?: unknown,
) {
  return app.inject({
    method,
    url,
    headers: { cookie: authCookie() },
    ...(payload !== undefined ? { payload } : {}),
  });
}

/** Verify error response has no internal system details */
function assertNoInternalLeakage(body: string) {
  const lower = body.toLowerCase();
  expect(lower).not.toContain('stack');
  expect(lower).not.toContain('node_modules');
  expect(lower).not.toContain('postgres');
  expect(lower).not.toContain('drizzle');
}

// ---------------------------------------------------------------------------
// SQL Injection Payloads
// ---------------------------------------------------------------------------

const SQL_INJECTION_PAYLOADS = [
  "'; DROP TABLE providers;--",
  "' OR 1=1--",
  "1; SELECT * FROM users --",
  "' UNION SELECT * FROM providers --",
  "'; DELETE FROM routing_configs;--",
  "1' OR '1'='1",
  "Robert'); DROP TABLE students;--",
];

// ---------------------------------------------------------------------------
// XSS Payloads
// ---------------------------------------------------------------------------

const XSS_PAYLOADS = [
  '<script>alert("xss")</script>',
  '<img src=x onerror=alert(1)>',
  'javascript:alert(1)',
  '<svg onload=alert(1)>',
  '"><script>alert(document.cookie)</script>',
];

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Provider Extension Input Validation & Injection Prevention (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    users = [];
    sessions = [];
    auditEntries = [];

    users.push({
      userId: FIXED_USER_ID,
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
      sessionId: FIXED_SESSION_ID,
      userId: FIXED_USER_ID,
      tokenHash: FIXED_SESSION_TOKEN_HASH,
      ipAddress: '127.0.0.1',
      userAgent: 'test-agent',
      createdAt: new Date(),
      lastActiveAt: new Date(),
      revoked: false,
      revokedReason: null,
    });
  });

  // =========================================================================
  // 1. SQL Injection on routing facility mapping fields
  // =========================================================================

  describe('SQL Injection -- Facility Mapping fields', () => {
    for (const payload of SQL_INJECTION_PAYLOADS) {
      it(`rejects or safely handles SQL injection in facility mapping body: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('PUT', '/api/v1/providers/me/routing-config/facilities', {
          facility_code: payload,
          location_id: '00000000-0000-0000-0000-000000000001',
        });

        // Zod schema validation should reject invalid data, or the mock handler returns error.
        // The key point: no 2xx success and no internal leakage.
        expect(res.statusCode).toBeGreaterThanOrEqual(400);
        assertNoInternalLeakage(res.body);
      });
    }
  });

  // =========================================================================
  // 2. SQL Injection on schedule mapping fields
  // =========================================================================

  describe('SQL Injection -- Schedule Mapping fields', () => {
    for (const payload of SQL_INJECTION_PAYLOADS) {
      it(`rejects or safely handles SQL injection in schedule mapping body: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('PUT', '/api/v1/providers/me/routing-config/schedule', {
          day_of_week: payload,
          location_id: '00000000-0000-0000-0000-000000000001',
        });

        expect(res.statusCode).toBeGreaterThanOrEqual(400);
        assertNoInternalLeakage(res.body);
      });
    }
  });

  // =========================================================================
  // 3. SQL Injection on routing resolve fields
  // =========================================================================

  describe('SQL Injection -- Routing Resolve fields', () => {
    for (const payload of SQL_INJECTION_PAYLOADS) {
      it(`rejects or safely handles SQL injection in routing resolve body: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('POST', '/api/v1/claims/routing/resolve', {
          claim_type: payload,
          facility_code: payload,
        });

        expect(res.statusCode).toBeGreaterThanOrEqual(400);
        assertNoInternalLeakage(res.body);
      });
    }
  });

  // =========================================================================
  // 4. SQL Injection on routing conflict detection fields
  // =========================================================================

  describe('SQL Injection -- Routing Conflict Detection fields', () => {
    for (const payload of SQL_INJECTION_PAYLOADS) {
      it(`rejects or safely handles SQL injection in conflict body: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('POST', '/api/v1/claims/routing/conflict', {
          facility_code: payload,
          schedule_key: payload,
        });

        expect(res.statusCode).toBeGreaterThanOrEqual(400);
        assertNoInternalLeakage(res.body);
      });
    }
  });

  // =========================================================================
  // 5. SQL Injection on Connect Care fields
  // =========================================================================

  describe('SQL Injection -- Connect Care fields', () => {
    for (const payload of SQL_INJECTION_PAYLOADS) {
      it(`rejects or safely handles SQL injection in connect-care body: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('PUT', '/api/v1/providers/me/connect-care', {
          enabled: payload,
          provider_id: payload,
        });

        expect(res.statusCode).toBeGreaterThanOrEqual(400);
        assertNoInternalLeakage(res.body);
      });
    }
  });

  // =========================================================================
  // 6. XSS Prevention on extension text fields
  // =========================================================================

  describe('XSS Prevention -- Facility Mapping text fields', () => {
    for (const payload of XSS_PAYLOADS) {
      it(`handles XSS in facility mapping body safely: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('PUT', '/api/v1/providers/me/routing-config/facilities', {
          facility_code: payload,
          notes: payload,
        });

        // Response must always be JSON, never rendered HTML
        expect(res.headers['content-type']).toContain('application/json');
      });
    }
  });

  describe('XSS Prevention -- Schedule Mapping text fields', () => {
    for (const payload of XSS_PAYLOADS) {
      it(`handles XSS in schedule mapping body safely: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('PUT', '/api/v1/providers/me/routing-config/schedule', {
          day_of_week: payload,
          notes: payload,
        });

        expect(res.headers['content-type']).toContain('application/json');
      });
    }
  });

  describe('XSS Prevention -- Connect Care text fields', () => {
    for (const payload of XSS_PAYLOADS) {
      it(`handles XSS in connect-care body safely: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('PUT', '/api/v1/providers/me/connect-care', {
          notes: payload,
          enabled: payload,
        });

        expect(res.headers['content-type']).toContain('application/json');
      });
    }
  });

  describe('XSS Prevention -- Response Content-Type is always JSON', () => {
    it('GET routing-config returns application/json', async () => {
      const res = await authedRequest('GET', '/api/v1/providers/me/routing-config');
      expect(res.headers['content-type']).toContain('application/json');
    });

    it('GET connect-care returns application/json', async () => {
      const res = await authedRequest('GET', '/api/v1/providers/me/connect-care');
      expect(res.headers['content-type']).toContain('application/json');
    });

    it('validation error on routing resolve returns application/json', async () => {
      const res = await authedRequest('POST', '/api/v1/claims/routing/resolve', {
        claim_type: '<script>alert(1)</script>',
      });
      expect(res.headers['content-type']).toContain('application/json');
    });
  });

  // =========================================================================
  // 7. Type Coercion Attacks on extension endpoints
  // =========================================================================

  describe('Type Coercion -- Facility Mappings', () => {
    it('rejects number where object/array expected in facility mappings body', async () => {
      const res = await authedRequest('PUT', '/api/v1/providers/me/routing-config/facilities', 12345 as any);
      expect(res.statusCode).toBeGreaterThanOrEqual(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects string where object expected in facility mappings body', async () => {
      const res = await authedRequest('PUT', '/api/v1/providers/me/routing-config/facilities', 'invalid' as any);
      expect(res.statusCode).toBeGreaterThanOrEqual(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects null body for facility mappings', async () => {
      const res = await authedRequest('PUT', '/api/v1/providers/me/routing-config/facilities', null as any);
      expect(res.statusCode).toBeGreaterThanOrEqual(400);
    });
  });

  describe('Type Coercion -- Schedule Mappings', () => {
    it('rejects number where object expected in schedule mappings body', async () => {
      const res = await authedRequest('PUT', '/api/v1/providers/me/routing-config/schedule', 99999 as any);
      expect(res.statusCode).toBeGreaterThanOrEqual(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects boolean where object expected in schedule mappings body', async () => {
      const res = await authedRequest('PUT', '/api/v1/providers/me/routing-config/schedule', true as any);
      expect(res.statusCode).toBeGreaterThanOrEqual(400);
      assertNoInternalLeakage(res.body);
    });
  });

  describe('Type Coercion -- Routing Resolve', () => {
    it('rejects array where object expected in resolve body', async () => {
      const res = await authedRequest('POST', '/api/v1/claims/routing/resolve', [1, 2, 3] as any);
      expect(res.statusCode).toBeGreaterThanOrEqual(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects string where object expected in resolve body', async () => {
      const res = await authedRequest('POST', '/api/v1/claims/routing/resolve', 'invalid' as any);
      expect(res.statusCode).toBeGreaterThanOrEqual(400);
      assertNoInternalLeakage(res.body);
    });
  });

  describe('Type Coercion -- Routing Conflict', () => {
    it('rejects number where object expected in conflict body', async () => {
      const res = await authedRequest('POST', '/api/v1/claims/routing/conflict', 42 as any);
      expect(res.statusCode).toBeGreaterThanOrEqual(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects boolean where object expected in conflict body', async () => {
      const res = await authedRequest('POST', '/api/v1/claims/routing/conflict', false as any);
      expect(res.statusCode).toBeGreaterThanOrEqual(400);
      assertNoInternalLeakage(res.body);
    });
  });

  describe('Type Coercion -- Connect Care', () => {
    it('rejects number where object expected in connect-care body', async () => {
      const res = await authedRequest('PUT', '/api/v1/providers/me/connect-care', 12345 as any);
      expect(res.statusCode).toBeGreaterThanOrEqual(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects array where object expected in connect-care body', async () => {
      const res = await authedRequest('PUT', '/api/v1/providers/me/connect-care', [true] as any);
      expect(res.statusCode).toBeGreaterThanOrEqual(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects string where object expected in connect-care body', async () => {
      const res = await authedRequest('PUT', '/api/v1/providers/me/connect-care', 'true' as any);
      expect(res.statusCode).toBeGreaterThanOrEqual(400);
      assertNoInternalLeakage(res.body);
    });
  });

  // =========================================================================
  // 8. Error Response Safety
  // =========================================================================

  describe('Error Response Safety', () => {
    it('validation error on facility mappings has consistent shape', async () => {
      const res = await authedRequest('PUT', '/api/v1/providers/me/routing-config/facilities', {
        facility_code: "'; DROP TABLE routing;--",
      });

      expect(res.statusCode).toBeGreaterThanOrEqual(400);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBeDefined();
      expect(body.error.message).toBeDefined();
      expect(body.data).toBeUndefined();
    });

    it('validation error on schedule mappings does not contain SQL keywords', async () => {
      const res = await authedRequest('PUT', '/api/v1/providers/me/routing-config/schedule', {
        day_of_week: "' UNION SELECT * FROM users --",
      });

      expect(res.statusCode).toBeGreaterThanOrEqual(400);
      assertNoInternalLeakage(res.body);
    });

    it('validation error on routing resolve does not expose request body verbatim', async () => {
      const canary = 'UNIQUE_CANARY_ROUTING_99999';
      const res = await authedRequest('POST', '/api/v1/claims/routing/resolve', {
        claim_type: canary,
        extra_field: canary,
      });

      expect(res.statusCode).toBeGreaterThanOrEqual(400);
      const body = JSON.parse(res.body);
      expect(body.error.message).not.toContain(canary);
    });

    it('error on connect-care update does not contain SQL keywords', async () => {
      const res = await authedRequest('PUT', '/api/v1/providers/me/connect-care', {
        enabled: "'; DELETE FROM connect_care;--",
      });

      expect(res.statusCode).toBeGreaterThanOrEqual(400);
      assertNoInternalLeakage(res.body);
    });
  });
});
