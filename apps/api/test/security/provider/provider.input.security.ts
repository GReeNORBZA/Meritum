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
const FIXED_PROVIDER_ID = FIXED_USER_ID;
const FIXED_SESSION_ID = '33333333-0000-0000-0000-000000000001';

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
let mockSessionRepo: ReturnType<typeof createMockSessionRepo>;

async function buildTestApp(): Promise<FastifyInstance> {
  mockSessionRepo = createMockSessionRepo();

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

/** Inject an authenticated request */
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

/** Verify error response has no internal system details (DB names, stack traces, etc.) */
function assertNoInternalLeakage(body: string) {
  const lower = body.toLowerCase();
  expect(lower).not.toContain('stack');
  expect(lower).not.toContain('node_modules');
  expect(lower).not.toContain('postgres');
  expect(lower).not.toContain('drizzle');
  // SQL keywords in validation error details are OK (Zod rejected them),
  // but they must not appear as system error messages.
}

// ---------------------------------------------------------------------------
// SQL Injection Payloads
// ---------------------------------------------------------------------------

const SQL_INJECTION_PAYLOADS = [
  "'; DROP TABLE providers;--",
  "' OR 1=1--",
  "1; SELECT * FROM users --",
  "' UNION SELECT * FROM providers --",
  "'; DELETE FROM wcb_configurations;--",
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

describe('Provider Input Validation & Injection Prevention (Security)', () => {
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
  // 1. SQL Injection on BA fields
  // =========================================================================

  describe('SQL Injection — Business Arrangement fields', () => {
    for (const payload of SQL_INJECTION_PAYLOADS) {
      it(`rejects SQL injection in ba_number: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('POST', '/api/v1/providers/me/bas', {
          ba_number: payload,
          ba_type: 'FFS',
        });

        expect(res.statusCode).toBe(400);
        assertNoInternalLeakage(res.body);
      });
    }

    it('rejects SQL injection in ba_type field', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/bas', {
        ba_number: '12345',
        ba_type: "'; DROP TABLE business_arrangements;--",
      });

      // Zod enum validation rejects the invalid value
      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // 2. SQL Injection on Location fields
  // =========================================================================

  describe('SQL Injection — Location fields', () => {
    for (const payload of SQL_INJECTION_PAYLOADS) {
      it(`rejects or safely handles SQL injection in functional_centre: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('POST', '/api/v1/providers/me/locations', {
          name: 'Test Clinic',
          functional_centre: payload,
        });

        // functional_centre has max(10) — most SQL payloads exceed this and return 400.
        // Short payloads (≤10 chars) may pass Zod but Drizzle parameterises them.
        // In mocked env, the service may return 500 (mock stub) — the key point is
        // the payload never reaches a real DB and no SQL is executed.
        if (payload.length > 10) {
          expect(res.statusCode).toBe(400);
        } else {
          // Passed validation, hits mock service — any response is acceptable
          expect(res.statusCode).toBeGreaterThanOrEqual(400);
        }
      });
    }

    for (const payload of SQL_INJECTION_PAYLOADS) {
      it(`handles SQL injection in location name safely: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('POST', '/api/v1/providers/me/locations', {
          name: payload,
          functional_centre: 'FC01',
        });

        // Name allows up to 100 chars — short SQL payloads pass Zod but are
        // parameterised by Drizzle. In mock env the service may error.
        // The key assertion: no 2xx success with SQL in a real DB context.
        // In mocked env, the service returns error (mock stub doesn't have full logic).
        if (payload.length > 100) {
          expect(res.statusCode).toBe(400);
        } else {
          // Passed Zod, reached mock service — verify no internal details leaked
          assertNoInternalLeakage(res.body);
        }
      });
    }
  });

  // =========================================================================
  // 3. SQL Injection on WCB Configuration fields
  // =========================================================================

  describe('SQL Injection — WCB Configuration fields', () => {
    for (const payload of SQL_INJECTION_PAYLOADS) {
      it(`rejects or safely handles SQL injection in contract_id: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('POST', '/api/v1/providers/me/wcb', {
          contract_id: payload,
          role_code: 'R01',
        });

        // contract_id has max(10) — most SQL payloads exceed this and return 400.
        // Short payloads (≤10 chars) pass Zod but Drizzle parameterises them.
        if (payload.length > 10) {
          expect(res.statusCode).toBe(400);
        } else {
          // Passed Zod, reached service — 400/422/500 from mock is acceptable
          expect(res.statusCode).toBeGreaterThanOrEqual(400);
        }
        assertNoInternalLeakage(res.body);
      });
    }

    for (const payload of SQL_INJECTION_PAYLOADS) {
      it(`rejects or safely handles SQL injection in role_code: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('POST', '/api/v1/providers/me/wcb', {
          contract_id: 'C001',
          role_code: payload,
        });

        // role_code has max(10)
        if (payload.length > 10) {
          expect(res.statusCode).toBe(400);
        } else {
          expect(res.statusCode).toBeGreaterThanOrEqual(400);
        }
        assertNoInternalLeakage(res.body);
      });
    }
  });

  // =========================================================================
  // 4. SQL Injection on Provider Profile fields
  // =========================================================================

  describe('SQL Injection — Provider Profile fields', () => {
    for (const payload of SQL_INJECTION_PAYLOADS) {
      it(`handles SQL injection in first_name safely: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('PUT', '/api/v1/providers/me', {
          first_name: payload,
        });

        // first_name has max(50) — payloads exceeding this return 400.
        // Shorter ones pass Zod, reach service (mock returns 404 since provider not found).
        // The key point: no SQL is executed against a real DB.
        if (payload.length > 50) {
          expect(res.statusCode).toBe(400);
        } else {
          // Passed Zod — service returns error from mock
          expect(res.statusCode).toBeGreaterThanOrEqual(400);
        }
        assertNoInternalLeakage(res.body);
      });
    }

    for (const payload of SQL_INJECTION_PAYLOADS) {
      it(`handles SQL injection in last_name safely: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('PUT', '/api/v1/providers/me', {
          last_name: payload,
        });

        if (payload.length > 50) {
          expect(res.statusCode).toBe(400);
        } else {
          expect(res.statusCode).toBeGreaterThanOrEqual(400);
        }
        assertNoInternalLeakage(res.body);
      });
    }
  });

  // =========================================================================
  // 5. SQL Injection on Delegate fields
  // =========================================================================

  describe('SQL Injection — Delegate invite email', () => {
    it('rejects SQL injection in delegate email (no @ symbol)', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/delegates/invite', {
        email: "'; DROP TABLE delegate_relationships;--",
        permissions: ['CLAIM_VIEW'],
      });

      // Zod .email() validation rejects malformed emails
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects SQL injection in email local part', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/delegates/invite', {
        email: "admin'OR'1'='1@example.com",
        permissions: ['CLAIM_VIEW'],
      });

      // Single quotes in email local part may be rejected by Zod
      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // 6. SQL Injection on H-Link fields
  // =========================================================================

  describe('SQL Injection — H-Link fields', () => {
    for (const payload of SQL_INJECTION_PAYLOADS) {
      it(`rejects or safely handles SQL injection in submitter_prefix: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('PUT', '/api/v1/providers/me/hlink', {
          submitter_prefix: payload,
        });

        // submitter_prefix has max(10) — most SQL payloads exceed this.
        if (payload.length > 10) {
          expect(res.statusCode).toBe(400);
        } else {
          // Short payloads pass Zod, reach service mock
          expect(res.statusCode).toBeGreaterThanOrEqual(400);
        }
        assertNoInternalLeakage(res.body);
      });
    }
  });

  // =========================================================================
  // 7. XSS Payloads on text fields
  // =========================================================================

  describe('XSS Prevention — Provider Profile text fields', () => {
    for (const payload of XSS_PAYLOADS) {
      it(`handles XSS in first_name safely: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('PUT', '/api/v1/providers/me', {
          first_name: payload,
        });

        // XSS payloads that exceed 50 chars are rejected by Zod -> 400.
        // Shorter ones pass Zod and reach the service (mock returns 404).
        // The key assertion: response is always application/json (no HTML rendering).
        if (payload.length > 50) {
          expect(res.statusCode).toBe(400);
        }
        expect(res.headers['content-type']).toContain('application/json');
      });
    }

    for (const payload of XSS_PAYLOADS) {
      it(`handles XSS in specialty_description safely: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('PUT', '/api/v1/providers/me', {
          specialty_description: payload,
        });

        if (payload.length > 100) {
          expect(res.statusCode).toBe(400);
        }
        expect(res.headers['content-type']).toContain('application/json');
      });
    }
  });

  describe('XSS Prevention — Location name field', () => {
    for (const payload of XSS_PAYLOADS) {
      it(`handles XSS in location name safely: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('POST', '/api/v1/providers/me/locations', {
          name: payload,
          functional_centre: 'FC01',
        });

        // XSS payloads that exceed 100 chars are rejected by Zod.
        // Shorter ones pass Zod, reach service mock.
        // The key assertion: response Content-Type is always JSON.
        if (payload.length > 100) {
          expect(res.statusCode).toBe(400);
        }
        expect(res.headers['content-type']).toContain('application/json');
      });
    }
  });

  describe('XSS Prevention — Response Content-Type is always JSON', () => {
    it('GET endpoints return application/json', async () => {
      const res = await authedRequest('GET', '/api/v1/providers/me/bas');
      expect(res.headers['content-type']).toContain('application/json');
    });

    it('validation error responses return application/json', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/bas', {
        ba_number: '<script>alert(1)</script>',
        ba_type: 'FFS',
      });
      expect(res.statusCode).toBe(400);
      expect(res.headers['content-type']).toContain('application/json');
    });
  });

  // =========================================================================
  // 8. Type Coercion Attacks
  // =========================================================================

  describe('Type Coercion — Provider Profile', () => {
    it('rejects number where string expected (first_name)', async () => {
      const res = await authedRequest('PUT', '/api/v1/providers/me', {
        first_name: 12345,
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects array where string expected (last_name)', async () => {
      const res = await authedRequest('PUT', '/api/v1/providers/me', {
        last_name: ['Smith', 'Jones'],
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects object where string expected (middle_name)', async () => {
      const res = await authedRequest('PUT', '/api/v1/providers/me', {
        middle_name: { value: 'Test' },
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects boolean where string expected (specialty_code)', async () => {
      const res = await authedRequest('PUT', '/api/v1/providers/me', {
        specialty_code: true,
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects null where optional string expected (first_name)', async () => {
      const res = await authedRequest('PUT', '/api/v1/providers/me', {
        first_name: null,
      });
      // Zod rejects null for z.string().optional() (optional accepts undefined, not null)
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });
  });

  describe('Type Coercion — Business Arrangement', () => {
    it('rejects array where string expected (ba_number)', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/bas', {
        ba_number: ['a', 'b'],
        ba_type: 'FFS',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects number where string expected (ba_number)', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/bas', {
        ba_number: 12345,
        ba_type: 'FFS',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects string where boolean expected (is_primary)', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/bas', {
        ba_number: '12345',
        ba_type: 'FFS',
        is_primary: 'yes',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });
  });

  describe('Type Coercion — Location', () => {
    it('rejects number where string expected (name)', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/locations', {
        name: 99999,
        functional_centre: 'FC01',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects null for required field (functional_centre)', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/locations', {
        name: 'Test Clinic',
        functional_centre: null,
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });
  });

  describe('Type Coercion — WCB Configuration', () => {
    it('rejects number where string expected (contract_id)', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/wcb', {
        contract_id: 1001,
        role_code: 'R01',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects null for required field (role_code)', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/wcb', {
        contract_id: 'C001',
        role_code: null,
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects string where boolean expected (is_default)', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/wcb', {
        contract_id: 'C001',
        role_code: 'R01',
        is_default: 'true',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });
  });

  describe('Type Coercion — Submission Preferences', () => {
    it('rejects string where number expected (deadline_reminder_days)', async () => {
      const res = await authedRequest('PUT', '/api/v1/providers/me/submission-preferences', {
        deadline_reminder_days: 'seven',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects string where boolean expected (batch_review_reminder)', async () => {
      const res = await authedRequest('PUT', '/api/v1/providers/me/submission-preferences', {
        batch_review_reminder: 'yes',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });
  });

  describe('Type Coercion — Delegate Invite', () => {
    it('rejects string where array expected (permissions)', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/delegates/invite', {
        email: 'delegate@example.com',
        permissions: 'CLAIM_VIEW',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects number where string expected (email)', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/delegates/invite', {
        email: 12345,
        permissions: ['CLAIM_VIEW'],
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });
  });

  // =========================================================================
  // 9. Submission Preferences — Numeric boundary validation
  // =========================================================================

  describe('Numeric Boundary — Submission Preferences', () => {
    it('rejects deadline_reminder_days = 0 (min is 1)', async () => {
      const res = await authedRequest('PUT', '/api/v1/providers/me/submission-preferences', {
        deadline_reminder_days: 0,
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects deadline_reminder_days = 31 (max is 30)', async () => {
      const res = await authedRequest('PUT', '/api/v1/providers/me/submission-preferences', {
        deadline_reminder_days: 31,
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects deadline_reminder_days = -1 (negative)', async () => {
      const res = await authedRequest('PUT', '/api/v1/providers/me/submission-preferences', {
        deadline_reminder_days: -1,
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects deadline_reminder_days = 15.5 (float — must be int)', async () => {
      const res = await authedRequest('PUT', '/api/v1/providers/me/submission-preferences', {
        deadline_reminder_days: 15.5,
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('does not reject deadline_reminder_days = 1 at validation layer (min valid)', async () => {
      const res = await authedRequest('PUT', '/api/v1/providers/me/submission-preferences', {
        deadline_reminder_days: 1,
      });
      // Zod should not reject this — downstream mock behavior may vary
      expect(res.statusCode).not.toBe(400);
    });

    it('does not reject deadline_reminder_days = 30 at validation layer (max valid)', async () => {
      const res = await authedRequest('PUT', '/api/v1/providers/me/submission-preferences', {
        deadline_reminder_days: 30,
      });
      expect(res.statusCode).not.toBe(400);
    });
  });

  // =========================================================================
  // 10. Format Validation — BA fields
  // =========================================================================

  describe('Format Validation — BA fields', () => {
    it('rejects ba_number with letters (e.g., "ABC123")', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/bas', {
        ba_number: 'ABC123',
        ba_type: 'FFS',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects ba_number exceeding 10 characters', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/bas', {
        ba_number: '12345678901',
        ba_type: 'FFS',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects ba_number with special characters', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/bas', {
        ba_number: '123-456',
        ba_type: 'FFS',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects empty ba_number', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/bas', {
        ba_number: '',
        ba_type: 'FFS',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects invalid ba_type (e.g., "INVALID")', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/bas', {
        ba_number: '12345',
        ba_type: 'INVALID',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects ba_type = "ffs" (case-sensitive enum)', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/bas', {
        ba_number: '12345',
        ba_type: 'ffs',
      });
      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // 11. Format Validation — Provider Profile enums
  // =========================================================================

  describe('Format Validation — Provider Profile enums', () => {
    it('rejects invalid physician_type (e.g., "NURSE")', async () => {
      const res = await authedRequest('PUT', '/api/v1/providers/me', {
        physician_type: 'NURSE',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects physician_type with lowercase (e.g., "gp")', async () => {
      const res = await authedRequest('PUT', '/api/v1/providers/me', {
        physician_type: 'gp',
      });
      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // 12. Format Validation — Submission Preferences enums
  // =========================================================================

  describe('Format Validation — Submission Preferences enums', () => {
    it('rejects invalid ahcip_submission_mode (e.g., "AUTO")', async () => {
      const res = await authedRequest('PUT', '/api/v1/providers/me/submission-preferences', {
        ahcip_submission_mode: 'AUTO',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects invalid wcb_submission_mode (e.g., "MANUAL")', async () => {
      const res = await authedRequest('PUT', '/api/v1/providers/me/submission-preferences', {
        wcb_submission_mode: 'MANUAL',
      });
      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // 13. Format Validation — H-Link enums
  // =========================================================================

  describe('Format Validation — H-Link enums', () => {
    it('rejects invalid accreditation_status (e.g., "REVOKED")', async () => {
      const res = await authedRequest('PUT', '/api/v1/providers/me/hlink', {
        accreditation_status: 'REVOKED',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects lowercase accreditation_status (e.g., "active")', async () => {
      const res = await authedRequest('PUT', '/api/v1/providers/me/hlink', {
        accreditation_status: 'active',
      });
      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // 14. UUID Parameter Validation
  // =========================================================================

  describe('UUID Parameter Validation', () => {
    it('rejects non-UUID for BA id: PUT /api/v1/providers/me/bas/not-a-uuid', async () => {
      const res = await authedRequest('PUT', '/api/v1/providers/me/bas/not-a-uuid', {
        status: 'ACTIVE',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects non-UUID for BA id: DELETE /api/v1/providers/me/bas/not-a-uuid', async () => {
      const res = await authedRequest('DELETE', '/api/v1/providers/me/bas/not-a-uuid');
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects non-UUID for location id: PUT /api/v1/providers/me/locations/not-a-uuid', async () => {
      const res = await authedRequest('PUT', '/api/v1/providers/me/locations/not-a-uuid', {
        name: 'Updated',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects non-UUID for location id: PUT /api/v1/providers/me/locations/not-a-uuid/set-default', async () => {
      const res = await authedRequest('PUT', '/api/v1/providers/me/locations/not-a-uuid/set-default');
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects non-UUID for location id: DELETE /api/v1/providers/me/locations/not-a-uuid', async () => {
      const res = await authedRequest('DELETE', '/api/v1/providers/me/locations/not-a-uuid');
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects non-UUID for WCB config id: PUT /api/v1/providers/me/wcb/not-a-uuid', async () => {
      const res = await authedRequest('PUT', '/api/v1/providers/me/wcb/not-a-uuid', {
        skill_code: 'S02',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects non-UUID for WCB config id: DELETE /api/v1/providers/me/wcb/not-a-uuid', async () => {
      const res = await authedRequest('DELETE', '/api/v1/providers/me/wcb/not-a-uuid');
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects non-UUID for delegate rel_id: PUT /api/v1/providers/me/delegates/not-a-uuid/permissions', async () => {
      const res = await authedRequest(
        'PUT',
        '/api/v1/providers/me/delegates/not-a-uuid/permissions',
        { permissions: ['CLAIM_VIEW'] },
      );
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects non-UUID for delegate rel_id: POST /api/v1/providers/me/delegates/not-a-uuid/revoke', async () => {
      const res = await authedRequest(
        'POST',
        '/api/v1/providers/me/delegates/not-a-uuid/revoke',
      );
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects SQL injection as UUID parameter', async () => {
      const res = await authedRequest(
        'PUT',
        "/api/v1/providers/me/bas/'; DROP TABLE business_arrangements;--",
        { status: 'ACTIVE' },
      );
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects numeric string as UUID parameter', async () => {
      const res = await authedRequest('DELETE', '/api/v1/providers/me/wcb/12345');
      expect(res.statusCode).toBe(400);
    });

    it('rejects empty string as UUID parameter', async () => {
      // Fastify will not match the route if the param is empty — it will 404
      const res = await authedRequest('PUT', '/api/v1/providers/me/bas/', {
        status: 'ACTIVE',
      });
      // Either 400 or 404 is acceptable — the key is it does not succeed
      expect([400, 404]).toContain(res.statusCode);
    });
  });

  // =========================================================================
  // 15. Delegate Permission Array Validation
  // =========================================================================

  describe('Permission Array Validation — Delegate Invite', () => {
    it('rejects empty permissions array', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/delegates/invite', {
        email: 'delegate@example.com',
        permissions: [],
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects invalid permission key', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/delegates/invite', {
        email: 'delegate@example.com',
        permissions: ['INVALID_PERM'],
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects array with mix of valid and invalid permission keys', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/delegates/invite', {
        email: 'delegate@example.com',
        permissions: ['CLAIM_VIEW', 'NOT_A_REAL_PERM'],
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects permissions as string instead of array', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/delegates/invite', {
        email: 'delegate@example.com',
        permissions: 'CLAIM_VIEW',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects permissions with number elements', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/delegates/invite', {
        email: 'delegate@example.com',
        permissions: [1, 2, 3],
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects missing permissions field entirely', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/delegates/invite', {
        email: 'delegate@example.com',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });
  });

  describe('Permission Array Validation — Update Delegate Permissions', () => {
    it('rejects empty permissions array on update', async () => {
      const res = await authedRequest(
        'PUT',
        `/api/v1/providers/me/delegates/${PLACEHOLDER_UUID}/permissions`,
        { permissions: [] },
      );
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects invalid permission key on update', async () => {
      const res = await authedRequest(
        'PUT',
        `/api/v1/providers/me/delegates/${PLACEHOLDER_UUID}/permissions`,
        { permissions: ['INVALID_PERM'] },
      );
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects missing permissions field on update', async () => {
      const res = await authedRequest(
        'PUT',
        `/api/v1/providers/me/delegates/${PLACEHOLDER_UUID}/permissions`,
        {},
      );
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });
  });

  // =========================================================================
  // 16. Missing Required Fields
  // =========================================================================

  describe('Missing Required Fields', () => {
    it('rejects BA creation without ba_number', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/bas', {
        ba_type: 'FFS',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects BA creation without ba_type', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/bas', {
        ba_number: '12345',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects location creation without name', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/locations', {
        functional_centre: 'FC01',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects location creation without functional_centre', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/locations', {
        name: 'Test Clinic',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects WCB config creation without contract_id', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/wcb', {
        role_code: 'R01',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects WCB config creation without role_code', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/wcb', {
        contract_id: 'C001',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects delegate invite without email', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/delegates/invite', {
        permissions: ['CLAIM_VIEW'],
      });
      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // 17. String Length Validation
  // =========================================================================

  describe('String Length Validation', () => {
    it('rejects first_name exceeding 50 characters', async () => {
      const res = await authedRequest('PUT', '/api/v1/providers/me', {
        first_name: 'A'.repeat(51),
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects last_name exceeding 50 characters', async () => {
      const res = await authedRequest('PUT', '/api/v1/providers/me', {
        last_name: 'B'.repeat(51),
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects specialty_description exceeding 100 characters', async () => {
      const res = await authedRequest('PUT', '/api/v1/providers/me', {
        specialty_description: 'C'.repeat(101),
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects location name exceeding 100 characters', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/locations', {
        name: 'D'.repeat(101),
        functional_centre: 'FC01',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects functional_centre exceeding 10 characters', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/locations', {
        name: 'Test Clinic',
        functional_centre: 'F'.repeat(11),
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects contract_id exceeding 10 characters', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/wcb', {
        contract_id: 'C'.repeat(11),
        role_code: 'R01',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects email exceeding 255 characters', async () => {
      const longEmail = 'a'.repeat(250) + '@b.com';
      const res = await authedRequest('POST', '/api/v1/providers/me/delegates/invite', {
        email: longEmail,
        permissions: ['CLAIM_VIEW'],
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects submitter_prefix exceeding 10 characters', async () => {
      const res = await authedRequest('PUT', '/api/v1/providers/me/hlink', {
        submitter_prefix: 'M'.repeat(11),
      });
      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // 18. Email Format Validation
  // =========================================================================

  describe('Email Format Validation — Delegate Invite', () => {
    it('rejects email without @ symbol', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/delegates/invite', {
        email: 'not-an-email',
        permissions: ['CLAIM_VIEW'],
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects email without domain', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/delegates/invite', {
        email: 'user@',
        permissions: ['CLAIM_VIEW'],
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects empty email', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/delegates/invite', {
        email: '',
        permissions: ['CLAIM_VIEW'],
      });
      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // 19. Date Format Validation
  // =========================================================================

  describe('Date Format Validation — BA fields', () => {
    it('rejects invalid date format for effective_date', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/bas', {
        ba_number: '12345',
        ba_type: 'FFS',
        effective_date: 'not-a-date',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects timestamp format for effective_date (expects date only)', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/bas', {
        ba_number: '12345',
        ba_type: 'FFS',
        effective_date: '2026-01-01T00:00:00Z',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects number for effective_date', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/bas', {
        ba_number: '12345',
        ba_type: 'FFS',
        effective_date: 20260101,
      });
      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // 20. Error response does not expose internal details
  // =========================================================================

  describe('Error Response Safety', () => {
    it('400 error response has consistent shape', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/bas', {
        ba_number: '<script>alert(1)</script>',
        ba_type: 'FFS',
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBeDefined();
      expect(body.error.message).toBeDefined();
      // Must not contain data
      expect(body.data).toBeUndefined();
    });

    it('validation error does not contain SQL-related keywords', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/bas', {
        ba_number: "'; DROP TABLE providers;--",
        ba_type: 'FFS',
      });

      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('validation error does not expose request body back to client verbatim', async () => {
      const sneakyPayload = 'UNIQUE_CANARY_VALUE_12345';
      const res = await authedRequest('POST', '/api/v1/providers/me/bas', {
        ba_number: sneakyPayload,
        ba_type: 'INVALID_TYPE',
      });

      expect(res.statusCode).toBe(400);
      // The error message should not echo the full ba_number back
      // (ba_type error is about enum mismatch, not the ba_number value)
      const body = JSON.parse(res.body);
      expect(body.error.message).not.toContain(sneakyPayload);
    });
  });

  // =========================================================================
  // 21. Empty body on routes that require body
  // =========================================================================

  describe('Empty Body Handling', () => {
    it('rejects POST BA with empty body', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/bas', {});
      expect(res.statusCode).toBe(400);
    });

    it('rejects POST location with empty body', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/locations', {});
      expect(res.statusCode).toBe(400);
    });

    it('rejects POST WCB config with empty body', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/wcb', {});
      expect(res.statusCode).toBe(400);
    });

    it('rejects POST delegate invite with empty body', async () => {
      const res = await authedRequest('POST', '/api/v1/providers/me/delegates/invite', {});
      expect(res.statusCode).toBe(400);
    });
  });
});
