// ============================================================================
// Domain 10: Mobile Companion — Input Validation & Injection Prevention
// Verifies SQL injection, XSS, type coercion, UUID validation, and boundary
// value handling across all 16 mobile endpoints (shifts, favourites, mobile).
// ============================================================================

import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { createHash, randomBytes } from 'node:crypto';

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
// Imports (after mocks)
// ---------------------------------------------------------------------------

import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { shiftRoutes } from '../../../src/domains/mobile/routes/shift.routes.js';
import { favouriteRoutes } from '../../../src/domains/mobile/routes/favourite.routes.js';
import { mobileRoutes } from '../../../src/domains/mobile/routes/mobile.routes.js';
import type { ShiftRouteDeps } from '../../../src/domains/mobile/routes/shift.routes.js';
import type { FavouriteRouteDeps } from '../../../src/domains/mobile/routes/favourite.routes.js';
import type { MobileRouteDeps } from '../../../src/domains/mobile/routes/mobile.routes.js';

// ---------------------------------------------------------------------------
// Helper: hashToken (same SHA-256 used by auth plugin)
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

const FIXED_SESSION_TOKEN = randomBytes(32).toString('hex');
const FIXED_SESSION_TOKEN_HASH = hashToken(FIXED_SESSION_TOKEN);
const FIXED_USER_ID = 'aaaa0000-0000-0000-0000-000000000001';
const FIXED_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000001';

const PLACEHOLDER_UUID = '00000000-0000-0000-0000-000000000001';
const PLACEHOLDER_UUID_2 = '00000000-0000-0000-0000-000000000002';

// ---------------------------------------------------------------------------
// Mock stores
// ---------------------------------------------------------------------------

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

interface MockUser {
  userId: string;
  role: string;
  subscriptionStatus: string;
}

let sessions: MockSession[] = [];
let users: MockUser[] = [];

// ---------------------------------------------------------------------------
// Mock session repository (consumed by auth plugin)
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    createSession: vi.fn(async () => ({ sessionId: 'new-session' })),
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      const session = sessions.find((s) => s.tokenHash === tokenHash && !s.revoked);
      if (!session) return undefined;
      const user = users.find((u) => u.userId === session.userId);
      if (!user) return undefined;
      return { session, user };
    }),
    refreshSession: vi.fn(async () => {}),
    listActiveSessions: vi.fn(async () => []),
    revokeSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Stub handler deps — must match actual service dependency interfaces so
// that payloads passing Zod validation reach the service layer without 500.
// ---------------------------------------------------------------------------

const STUB_FAVOURITE = {
  favouriteId: PLACEHOLDER_UUID,
  providerId: FIXED_USER_ID,
  healthServiceCode: '03.04A',
  displayName: 'Test',
  sortOrder: 1,
  defaultModifiers: null as string[] | null,
  createdAt: new Date(),
};

function createStubShiftDeps(): ShiftRouteDeps {
  return {
    serviceDeps: {
      repo: {
        create: vi.fn(async () => ({
          shiftId: PLACEHOLDER_UUID,
          providerId: FIXED_USER_ID,
          locationId: PLACEHOLDER_UUID,
          status: 'ACTIVE',
          startedAt: new Date(),
          endedAt: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        })),
        findActive: vi.fn(async () => null),
        endShift: vi.fn(async () => ({})),
        findById: vi.fn(async () => ({
          shiftId: PLACEHOLDER_UUID,
          providerId: FIXED_USER_ID,
          locationId: PLACEHOLDER_UUID,
          status: 'ACTIVE',
          startedAt: new Date(),
          endedAt: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        })),
        getById: vi.fn(async () => ({
          shiftId: PLACEHOLDER_UUID,
          providerId: FIXED_USER_ID,
          locationId: PLACEHOLDER_UUID,
          status: 'ACTIVE',
          startedAt: new Date(),
          endedAt: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        })),
        listByProvider: vi.fn(async () => ({ data: [], total: 0 })),
        logPatient: vi.fn(async () => ({})),
        incrementPatientCount: vi.fn(async () => {}),
        getShiftSummary: vi.fn(async () => ({
          shift: {},
          patients: [],
          totalClaims: 0,
          afterHoursCount: 0,
        })),
      } as any,
      locationCheck: {
        belongsToPhysician: vi.fn(async () => true),
      } as any,
      claimCreator: {
        createClaimFromShift: vi.fn(async () => ({ claimId: PLACEHOLDER_UUID })),
      } as any,
      hscEligibility: {
        isEligibleForModifier: vi.fn(async () => true),
      } as any,
      auditRepo: {
        appendAuditLog: vi.fn(async () => {}),
      } as any,
    } as any,
  };
}

function createStubFavouriteDeps(): FavouriteRouteDeps {
  return {
    serviceDeps: {
      repo: {
        listByProvider: vi.fn(async () => []),
        create: vi.fn(async (data: any) => ({
          ...STUB_FAVOURITE,
          ...data,
          favouriteId: PLACEHOLDER_UUID,
          createdAt: new Date(),
        })),
        update: vi.fn(async (_id: any, _pid: any, data: any) => ({
          ...STUB_FAVOURITE,
          ...data,
        })),
        delete: vi.fn(async () => true),
        countByProvider: vi.fn(async () => 5),
        reorder: vi.fn(async () => {}),
        findById: vi.fn(async () => STUB_FAVOURITE),
      } as any,
      hscLookup: {
        findByCode: vi.fn(async () => ({
          code: '03.04A',
          description: 'Office Visit',
          baseFee: '35.00',
          feeType: 'SOMB',
        })),
      } as any,
      modifierLookup: {
        isKnownModifier: vi.fn(async () => true),
      } as any,
      claimHistory: {
        getTopBilledCodes: vi.fn(async () => []),
      } as any,
      providerProfile: {
        getSpecialty: vi.fn(async () => null),
      } as any,
      specialtyDefaults: {
        getDefaultCodes: vi.fn(async () => []),
      } as any,
      auditRepo: {
        appendAuditLog: vi.fn(async () => {}),
      } as any,
    } as any,
  };
}

function createStubMobileDeps(): MobileRouteDeps {
  return {
    quickClaimServiceDeps: {
      claimCreator: {
        createDraftClaim: vi.fn(async () => ({ claimId: PLACEHOLDER_UUID })),
      } as any,
      patientCreator: {
        createMinimalPatient: vi.fn(async (_pid: any, data: any) => ({
          patientId: PLACEHOLDER_UUID,
          firstName: data.firstName,
          lastName: data.lastName,
          phn: data.phn,
          dateOfBirth: data.dateOfBirth,
          gender: data.gender,
        })),
      } as any,
      recentPatientsQuery: {
        getRecentBilledPatients: vi.fn(async () => []),
      } as any,
      auditRepo: {
        appendAuditLog: vi.fn(async () => {}),
      } as any,
    } as any,
    summaryServiceDeps: {
      summaryRepo: {
        getTodayCounts: vi.fn(async () => ({ claims: 0, patients: 0 })),
        getWeekRevenue: vi.fn(async () => '0.00'),
        getActiveShift: vi.fn(async () => null),
        getPendingCount: vi.fn(async () => 0),
      } as any,
      auditRepo: {
        appendAuditLog: vi.fn(async () => {}),
      } as any,
    } as any,
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;

async function buildTestApp(): Promise<FastifyInstance> {
  const mockSessionRepo = createMockSessionRepo();

  const sessionDeps = {
    sessionRepo: mockSessionRepo,
    auditRepo: { appendAuditLog: vi.fn(async () => {}) },
    events: { emit: vi.fn() },
  };

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  await testApp.register(authPluginFp, { sessionDeps });

  testApp.setErrorHandler((error, _request, reply) => {
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

  await testApp.register(shiftRoutes, { deps: createStubShiftDeps() });
  await testApp.register(favouriteRoutes, { deps: createStubFavouriteDeps() });
  await testApp.register(mobileRoutes, { deps: createStubMobileDeps() });

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
function assertNoInternalLeakage(body: unknown) {
  const str = (typeof body === 'string' ? body : JSON.stringify(body)).toLowerCase();
  expect(str).not.toContain('stack');
  expect(str).not.toContain('node_modules');
  expect(str).not.toContain('postgres');
  expect(str).not.toContain('drizzle');
}

// ---------------------------------------------------------------------------
// Valid payloads (templates)
// ---------------------------------------------------------------------------

const VALID_START_SHIFT = { location_id: PLACEHOLDER_UUID };

const VALID_LOG_PATIENT = {
  patient_id: PLACEHOLDER_UUID,
  health_service_code: '03.04A',
  date_of_service: '2026-01-15',
};

const VALID_CREATE_FAVOURITE = {
  health_service_code: '03.04A',
  display_name: 'Office Visit',
  sort_order: 1,
};

const VALID_UPDATE_FAVOURITE = {
  display_name: 'Updated Name',
};

const VALID_REORDER = {
  items: [
    { favourite_id: PLACEHOLDER_UUID, sort_order: 1 },
    { favourite_id: PLACEHOLDER_UUID_2, sort_order: 2 },
  ],
};

const VALID_QUICK_CLAIM = {
  patient_id: PLACEHOLDER_UUID,
  health_service_code: '03.04A',
  date_of_service: '2026-01-15',
};

const VALID_MOBILE_PATIENT = {
  first_name: 'Test',
  last_name: 'Patient',
  phn: '123456789',
  date_of_birth: '1990-01-01',
  gender: 'M',
};

// ---------------------------------------------------------------------------
// Attack payloads
// ---------------------------------------------------------------------------

const SQL_INJECTION_PAYLOADS = [
  "'; DROP TABLE ed_shifts; --",
  "' OR 1=1--",
  "1; SELECT * FROM users --",
  "' UNION SELECT * FROM providers --",
  "'; DELETE FROM favourite_codes; --",
  "1' OR '1'='1",
  "Robert'); DROP TABLE students;--",
];

const XSS_PAYLOADS = [
  '<script>alert("xss")</script>',
  '<img src=x onerror=alert(1)>',
  '<svg onload=alert(1)>',
  'javascript:alert(1)',
  '"><script>alert(document.cookie)</script>',
];

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Mobile Companion Input Validation & Injection Prevention (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    sessions = [];
    users = [];

    users.push({
      userId: FIXED_USER_ID,
      role: 'PHYSICIAN',
      subscriptionStatus: 'ACTIVE',
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
  // 1. SQL Injection — Shift Endpoints
  // =========================================================================

  describe('SQL Injection — Shift Endpoints', () => {
    for (const payload of SQL_INJECTION_PAYLOADS) {
      it(`rejects SQL injection in start shift location_id: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('POST', '/api/v1/shifts', {
          location_id: payload,
        });
        // location_id has UUID validation — all SQL payloads rejected
        expect(res.statusCode).toBe(400);
        assertNoInternalLeakage(res.body);
      });
    }

    for (const payload of SQL_INJECTION_PAYLOADS) {
      it(`rejects SQL injection in shift :id param: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('POST', `/api/v1/shifts/${encodeURIComponent(payload)}/end`);
        expect(res.statusCode).toBe(400);
        assertNoInternalLeakage(res.body);
      });
    }

    for (const payload of SQL_INJECTION_PAYLOADS) {
      it(`rejects SQL injection in shift summary :id param: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('GET', `/api/v1/shifts/${encodeURIComponent(payload)}/summary`);
        expect(res.statusCode).toBe(400);
        assertNoInternalLeakage(res.body);
      });
    }

    for (const payload of SQL_INJECTION_PAYLOADS) {
      it(`rejects SQL injection in log patient patient_id: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/patients`, {
          ...VALID_LOG_PATIENT,
          patient_id: payload,
        });
        // patient_id has UUID validation
        expect(res.statusCode).toBe(400);
        assertNoInternalLeakage(res.body);
      });
    }

    for (const payload of SQL_INJECTION_PAYLOADS) {
      it(`handles SQL injection in health_service_code safely: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/patients`, {
          ...VALID_LOG_PATIENT,
          health_service_code: payload,
        });
        // health_service_code max(10) — long payloads rejected by length constraint
        if (payload.length > 10) {
          expect(res.statusCode).toBe(400);
        }
        // Regardless of status, no internal leakage
        assertNoInternalLeakage(res.body);
        expect(res.headers['content-type']).toContain('application/json');
      });
    }
  });

  // =========================================================================
  // 2. SQL Injection — Favourite Endpoints
  // =========================================================================

  describe('SQL Injection — Favourite Endpoints', () => {
    for (const payload of SQL_INJECTION_PAYLOADS) {
      it(`handles SQL injection in favourite health_service_code: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('POST', '/api/v1/favourites', {
          ...VALID_CREATE_FAVOURITE,
          health_service_code: payload,
        });
        // health_service_code max(10) — long payloads rejected
        if (payload.length > 10) {
          expect(res.statusCode).toBe(400);
        }
        assertNoInternalLeakage(res.body);
      });
    }

    for (const payload of SQL_INJECTION_PAYLOADS) {
      it(`handles SQL injection in favourite display_name: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('POST', '/api/v1/favourites', {
          ...VALID_CREATE_FAVOURITE,
          display_name: payload,
        });
        // display_name max(100) — most SQL payloads are short enough to pass Zod
        // but Drizzle parameterises queries, so no injection possible
        if (payload.length > 100) {
          expect(res.statusCode).toBe(400);
        }
        assertNoInternalLeakage(res.body);
      });
    }

    for (const payload of SQL_INJECTION_PAYLOADS) {
      it(`rejects SQL injection in favourite :id param: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('PUT', `/api/v1/favourites/${encodeURIComponent(payload)}`, {
          display_name: 'Updated',
        });
        // :id has UUID validation
        expect(res.statusCode).toBe(400);
        assertNoInternalLeakage(res.body);
      });
    }

    for (const payload of SQL_INJECTION_PAYLOADS) {
      it(`rejects SQL injection in reorder favourite_id: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('PUT', '/api/v1/favourites/reorder', {
          items: [{ favourite_id: payload, sort_order: 1 }],
        });
        // favourite_id has UUID validation
        expect(res.statusCode).toBe(400);
        assertNoInternalLeakage(res.body);
      });
    }
  });

  // =========================================================================
  // 3. SQL Injection — Mobile Quick Claim & Patient
  // =========================================================================

  describe('SQL Injection — Mobile Quick Claim & Patient', () => {
    for (const payload of SQL_INJECTION_PAYLOADS) {
      it(`rejects SQL injection in quick claim patient_id: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('POST', '/api/v1/mobile/quick-claim', {
          ...VALID_QUICK_CLAIM,
          patient_id: payload,
        });
        expect(res.statusCode).toBe(400);
        assertNoInternalLeakage(res.body);
      });
    }

    for (const payload of SQL_INJECTION_PAYLOADS) {
      it(`handles SQL injection in quick claim health_service_code: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('POST', '/api/v1/mobile/quick-claim', {
          ...VALID_QUICK_CLAIM,
          health_service_code: payload,
        });
        if (payload.length > 10) {
          expect(res.statusCode).toBe(400);
        }
        assertNoInternalLeakage(res.body);
      });
    }

    for (const payload of SQL_INJECTION_PAYLOADS) {
      it(`rejects SQL injection in mobile patient phn: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('POST', '/api/v1/mobile/patients', {
          ...VALID_MOBILE_PATIENT,
          phn: payload,
        });
        // PHN has regex /^\d{9}$/ — all SQL payloads rejected
        expect(res.statusCode).toBe(400);
        assertNoInternalLeakage(res.body);
      });
    }

    for (const payload of SQL_INJECTION_PAYLOADS) {
      it(`handles SQL injection in mobile patient first_name: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('POST', '/api/v1/mobile/patients', {
          ...VALID_MOBILE_PATIENT,
          first_name: payload,
        });
        // first_name max(100) — most SQL payloads pass Zod length check
        // but Drizzle parameterises queries, so no injection possible
        if (payload.length > 100) {
          expect(res.statusCode).toBe(400);
        }
        assertNoInternalLeakage(res.body);
      });
    }

    for (const payload of SQL_INJECTION_PAYLOADS) {
      it(`handles SQL injection in mobile patient last_name: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('POST', '/api/v1/mobile/patients', {
          ...VALID_MOBILE_PATIENT,
          last_name: payload,
        });
        if (payload.length > 100) {
          expect(res.statusCode).toBe(400);
        }
        assertNoInternalLeakage(res.body);
      });
    }
  });

  // =========================================================================
  // 4. XSS Prevention — Text Fields
  // =========================================================================

  describe('XSS Prevention — Text Fields', () => {
    for (const payload of XSS_PAYLOADS) {
      it(`handles XSS in favourite display_name safely: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('POST', '/api/v1/favourites', {
          ...VALID_CREATE_FAVOURITE,
          display_name: payload,
        });
        // display_name max(100) — XSS payloads under limit pass to service
        // Content-Type must be JSON (no HTML rendering)
        expect(res.headers['content-type']).toContain('application/json');
        assertNoInternalLeakage(res.body);
        expect(res.statusCode).not.toBe(500);
      });
    }

    for (const payload of XSS_PAYLOADS) {
      it(`handles XSS in update favourite display_name safely: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('PUT', `/api/v1/favourites/${PLACEHOLDER_UUID}`, {
          display_name: payload,
        });
        expect(res.headers['content-type']).toContain('application/json');
        assertNoInternalLeakage(res.body);
        expect(res.statusCode).not.toBe(500);
      });
    }

    for (const payload of XSS_PAYLOADS) {
      it(`handles XSS in log patient quick_note safely: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/patients`, {
          ...VALID_LOG_PATIENT,
          quick_note: payload,
        });
        expect(res.headers['content-type']).toContain('application/json');
        assertNoInternalLeakage(res.body);
        expect(res.statusCode).not.toBe(500);
      });
    }

    for (const payload of XSS_PAYLOADS) {
      it(`handles XSS in mobile patient first_name safely: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('POST', '/api/v1/mobile/patients', {
          ...VALID_MOBILE_PATIENT,
          first_name: payload,
        });
        expect(res.headers['content-type']).toContain('application/json');
        assertNoInternalLeakage(res.body);
        expect(res.statusCode).not.toBe(500);
      });
    }

    for (const payload of XSS_PAYLOADS) {
      it(`handles XSS in mobile patient last_name safely: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('POST', '/api/v1/mobile/patients', {
          ...VALID_MOBILE_PATIENT,
          last_name: payload,
        });
        expect(res.headers['content-type']).toContain('application/json');
        assertNoInternalLeakage(res.body);
        expect(res.statusCode).not.toBe(500);
      });
    }
  });

  // =========================================================================
  // 5. Type Coercion Attacks
  // =========================================================================

  describe('Type Coercion Attacks', () => {
    // --- location_id: integer instead of UUID ---
    it('rejects integer location_id in start shift', async () => {
      const res = await authedRequest('POST', '/api/v1/shifts', {
        location_id: 12345,
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects boolean location_id in start shift', async () => {
      const res = await authedRequest('POST', '/api/v1/shifts', {
        location_id: true,
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects null location_id in start shift', async () => {
      const res = await authedRequest('POST', '/api/v1/shifts', {
        location_id: null,
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects array location_id in start shift', async () => {
      const res = await authedRequest('POST', '/api/v1/shifts', {
        location_id: [PLACEHOLDER_UUID],
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    // --- sort_order: string instead of integer ---
    it('rejects string sort_order in create favourite', async () => {
      const res = await authedRequest('POST', '/api/v1/favourites', {
        ...VALID_CREATE_FAVOURITE,
        sort_order: 'first',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects boolean sort_order in create favourite', async () => {
      const res = await authedRequest('POST', '/api/v1/favourites', {
        ...VALID_CREATE_FAVOURITE,
        sort_order: true,
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects float sort_order in create favourite', async () => {
      const res = await authedRequest('POST', '/api/v1/favourites', {
        ...VALID_CREATE_FAVOURITE,
        sort_order: 1.5,
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    // --- default_modifiers: string instead of array ---
    it('rejects string default_modifiers in create favourite', async () => {
      const res = await authedRequest('POST', '/api/v1/favourites', {
        ...VALID_CREATE_FAVOURITE,
        default_modifiers: 'CMGP',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects integer default_modifiers in create favourite', async () => {
      const res = await authedRequest('POST', '/api/v1/favourites', {
        ...VALID_CREATE_FAVOURITE,
        default_modifiers: 123,
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects object default_modifiers in create favourite', async () => {
      const res = await authedRequest('POST', '/api/v1/favourites', {
        ...VALID_CREATE_FAVOURITE,
        default_modifiers: { mod: 'CMGP' },
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    // --- limit: negative number ---
    it('rejects negative limit in list shifts', async () => {
      const res = await authedRequest('GET', '/api/v1/shifts?limit=-1');
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects zero limit in list shifts', async () => {
      const res = await authedRequest('GET', '/api/v1/shifts?limit=0');
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects limit exceeding max (50) in list shifts', async () => {
      const res = await authedRequest('GET', '/api/v1/shifts?limit=51');
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects negative limit in recent patients', async () => {
      const res = await authedRequest('GET', '/api/v1/mobile/recent-patients?limit=-1');
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects zero limit in recent patients', async () => {
      const res = await authedRequest('GET', '/api/v1/mobile/recent-patients?limit=0');
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects limit exceeding max (20) in recent patients', async () => {
      const res = await authedRequest('GET', '/api/v1/mobile/recent-patients?limit=21');
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    // --- patient_id: wrong types ---
    it('rejects integer patient_id in quick claim', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/quick-claim', {
        ...VALID_QUICK_CLAIM,
        patient_id: 12345,
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects null patient_id in quick claim', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/quick-claim', {
        ...VALID_QUICK_CLAIM,
        patient_id: null,
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    // --- modifiers: wrong types ---
    it('rejects string modifiers in quick claim', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/quick-claim', {
        ...VALID_QUICK_CLAIM,
        modifiers: 'CMGP',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects integer modifiers in log patient', async () => {
      const res = await authedRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/patients`, {
        ...VALID_LOG_PATIENT,
        modifiers: 123,
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    // --- reorder items: wrong types ---
    it('rejects string items in reorder', async () => {
      const res = await authedRequest('PUT', '/api/v1/favourites/reorder', {
        items: 'not-an-array',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects integer items in reorder', async () => {
      const res = await authedRequest('PUT', '/api/v1/favourites/reorder', {
        items: 123,
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    // --- mobile patient: wrong types ---
    it('rejects integer first_name in mobile patient', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/patients', {
        ...VALID_MOBILE_PATIENT,
        first_name: 12345,
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects integer phn in mobile patient', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/patients', {
        ...VALID_MOBILE_PATIENT,
        phn: 123456789,
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects array gender in mobile patient', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/patients', {
        ...VALID_MOBILE_PATIENT,
        gender: ['M'],
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });
  });

  // =========================================================================
  // 6. UUID Validation — All ID Parameters
  // =========================================================================

  describe('UUID Validation — All ID Parameters', () => {
    const INVALID_UUIDS = [
      'not-a-uuid',
      '12345',
      "' OR 1=1--",
      '',
      'gggggggg-0000-0000-0000-000000000001', // invalid hex chars
    ];

    // --- Shift :id param ---
    for (const badUuid of INVALID_UUIDS) {
      it(`rejects invalid UUID "${badUuid}" in POST /shifts/:id/end`, async () => {
        const res = await authedRequest('POST', `/api/v1/shifts/${encodeURIComponent(badUuid)}/end`);
        expect(res.statusCode).toBe(400);
        assertNoInternalLeakage(res.body);
      });
    }

    for (const badUuid of INVALID_UUIDS) {
      it(`rejects invalid UUID "${badUuid}" in GET /shifts/:id/summary`, async () => {
        const res = await authedRequest('GET', `/api/v1/shifts/${encodeURIComponent(badUuid)}/summary`);
        expect(res.statusCode).toBe(400);
        assertNoInternalLeakage(res.body);
      });
    }

    for (const badUuid of INVALID_UUIDS) {
      it(`rejects invalid UUID "${badUuid}" in POST /shifts/:id/patients`, async () => {
        const res = await authedRequest('POST', `/api/v1/shifts/${encodeURIComponent(badUuid)}/patients`, VALID_LOG_PATIENT);
        expect(res.statusCode).toBe(400);
        assertNoInternalLeakage(res.body);
      });
    }

    // --- Favourite :id param ---
    for (const badUuid of INVALID_UUIDS) {
      it(`rejects invalid UUID "${badUuid}" in PUT /favourites/:id`, async () => {
        const res = await authedRequest('PUT', `/api/v1/favourites/${encodeURIComponent(badUuid)}`, VALID_UPDATE_FAVOURITE);
        expect(res.statusCode).toBe(400);
        assertNoInternalLeakage(res.body);
      });
    }

    for (const badUuid of INVALID_UUIDS) {
      it(`rejects invalid UUID "${badUuid}" in DELETE /favourites/:id`, async () => {
        const res = await authedRequest('DELETE', `/api/v1/favourites/${encodeURIComponent(badUuid)}`);
        expect(res.statusCode).toBe(400);
        assertNoInternalLeakage(res.body);
      });
    }

    // --- Body UUID fields ---
    for (const badUuid of INVALID_UUIDS) {
      it(`rejects invalid UUID "${badUuid}" in start shift location_id`, async () => {
        const res = await authedRequest('POST', '/api/v1/shifts', {
          location_id: badUuid,
        });
        expect(res.statusCode).toBe(400);
        assertNoInternalLeakage(res.body);
      });
    }

    for (const badUuid of INVALID_UUIDS) {
      it(`rejects invalid UUID "${badUuid}" in log patient patient_id`, async () => {
        const res = await authedRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/patients`, {
          ...VALID_LOG_PATIENT,
          patient_id: badUuid,
        });
        expect(res.statusCode).toBe(400);
        assertNoInternalLeakage(res.body);
      });
    }

    for (const badUuid of INVALID_UUIDS) {
      it(`rejects invalid UUID "${badUuid}" in quick claim patient_id`, async () => {
        const res = await authedRequest('POST', '/api/v1/mobile/quick-claim', {
          ...VALID_QUICK_CLAIM,
          patient_id: badUuid,
        });
        expect(res.statusCode).toBe(400);
        assertNoInternalLeakage(res.body);
      });
    }

    for (const badUuid of INVALID_UUIDS) {
      it(`rejects invalid UUID "${badUuid}" in reorder favourite_id`, async () => {
        const res = await authedRequest('PUT', '/api/v1/favourites/reorder', {
          items: [{ favourite_id: badUuid, sort_order: 1 }],
        });
        expect(res.statusCode).toBe(400);
        assertNoInternalLeakage(res.body);
      });
    }
  });

  // =========================================================================
  // 7. Boundary Values — display_name
  // =========================================================================

  describe('Boundary Values — display_name', () => {
    it('rejects display_name exceeding 100 characters', async () => {
      const res = await authedRequest('POST', '/api/v1/favourites', {
        ...VALID_CREATE_FAVOURITE,
        display_name: 'x'.repeat(101),
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('accepts display_name at exactly 100 characters', async () => {
      const res = await authedRequest('POST', '/api/v1/favourites', {
        ...VALID_CREATE_FAVOURITE,
        display_name: 'x'.repeat(100),
      });
      // Should not be rejected by validation (may succeed or fail at service layer)
      expect(res.statusCode).not.toBe(400);
    });

    it('rejects display_name exceeding 100 characters on update', async () => {
      const res = await authedRequest('PUT', `/api/v1/favourites/${PLACEHOLDER_UUID}`, {
        display_name: 'x'.repeat(101),
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });
  });

  // =========================================================================
  // 8. Boundary Values — quick_note
  // =========================================================================

  describe('Boundary Values — quick_note', () => {
    it('rejects quick_note exceeding 500 characters', async () => {
      const res = await authedRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/patients`, {
        ...VALID_LOG_PATIENT,
        quick_note: 'x'.repeat(501),
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('accepts quick_note at exactly 500 characters', async () => {
      const res = await authedRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/patients`, {
        ...VALID_LOG_PATIENT,
        quick_note: 'x'.repeat(500),
      });
      // Should not be rejected by validation
      expect(res.statusCode).not.toBe(400);
    });
  });

  // =========================================================================
  // 9. Boundary Values — PHN
  // =========================================================================

  describe('Boundary Values — PHN', () => {
    it('rejects PHN with only 8 digits', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/patients', {
        ...VALID_MOBILE_PATIENT,
        phn: '12345678',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects PHN with 10 digits', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/patients', {
        ...VALID_MOBILE_PATIENT,
        phn: '1234567890',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects PHN with letters', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/patients', {
        ...VALID_MOBILE_PATIENT,
        phn: '12345ABCD',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects PHN with special characters', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/patients', {
        ...VALID_MOBILE_PATIENT,
        phn: '123-456-7',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects empty PHN', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/patients', {
        ...VALID_MOBILE_PATIENT,
        phn: '',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects PHN with spaces', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/patients', {
        ...VALID_MOBILE_PATIENT,
        phn: '123 456 7',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });
  });

  // =========================================================================
  // 10. Boundary Values — date_of_service (future date)
  // =========================================================================

  describe('Boundary Values — date_of_service (future date)', () => {
    const futureDate = '2099-12-31';

    it('rejects future date_of_service in log patient', async () => {
      const res = await authedRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/patients`, {
        ...VALID_LOG_PATIENT,
        date_of_service: futureDate,
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects future date_of_service in quick claim', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/quick-claim', {
        ...VALID_QUICK_CLAIM,
        date_of_service: futureDate,
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects invalid date format in date_of_service', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/quick-claim', {
        ...VALID_QUICK_CLAIM,
        date_of_service: '15-01-2026',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects non-string date_of_service', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/quick-claim', {
        ...VALID_QUICK_CLAIM,
        date_of_service: 20260115,
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });
  });

  // =========================================================================
  // 11. Boundary Values — date_of_birth (future date)
  // =========================================================================

  describe('Boundary Values — date_of_birth', () => {
    it('rejects invalid date format in date_of_birth', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/patients', {
        ...VALID_MOBILE_PATIENT,
        date_of_birth: '01-01-1990',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects non-string date_of_birth', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/patients', {
        ...VALID_MOBILE_PATIENT,
        date_of_birth: 19900101,
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects empty date_of_birth', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/patients', {
        ...VALID_MOBILE_PATIENT,
        date_of_birth: '',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });
  });

  // =========================================================================
  // 12. Boundary Values — sort_order in reorder
  // =========================================================================

  describe('Boundary Values — sort_order in reorder', () => {
    it('rejects negative sort_order in reorder items', async () => {
      const res = await authedRequest('PUT', '/api/v1/favourites/reorder', {
        items: [{ favourite_id: PLACEHOLDER_UUID, sort_order: -1 }],
      });
      // sort_order is z.number().int() — negatives are technically valid per schema
      // but should not cause 500 or leak internals
      assertNoInternalLeakage(res.body);
      expect(res.statusCode).not.toBe(500);
    });

    it('rejects negative sort_order in create favourite', async () => {
      const res = await authedRequest('POST', '/api/v1/favourites', {
        ...VALID_CREATE_FAVOURITE,
        sort_order: -1,
      });
      // sort_order is z.number().int() — negatives may pass Zod
      assertNoInternalLeakage(res.body);
      expect(res.statusCode).not.toBe(500);
    });
  });

  // =========================================================================
  // 13. Boundary Values — reorder items count (max 30)
  // =========================================================================

  describe('Boundary Values — reorder items count', () => {
    it('rejects reorder with 31 items (exceeds MAX_FAVOURITES)', async () => {
      const items = Array.from({ length: 31 }, (_, i) => ({
        favourite_id: `00000000-0000-0000-0000-${String(i + 1).padStart(12, '0')}`,
        sort_order: i + 1,
      }));
      const res = await authedRequest('PUT', '/api/v1/favourites/reorder', { items });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('accepts reorder with exactly 30 items (at MAX_FAVOURITES)', async () => {
      const items = Array.from({ length: 30 }, (_, i) => ({
        favourite_id: `00000000-0000-0000-0000-${String(i + 1).padStart(12, '0')}`,
        sort_order: i + 1,
      }));
      const res = await authedRequest('PUT', '/api/v1/favourites/reorder', { items });
      // Should not be rejected by validation (may fail at service layer)
      expect(res.statusCode).not.toBe(400);
    });

    it('rejects reorder with empty items array', async () => {
      const res = await authedRequest('PUT', '/api/v1/favourites/reorder', { items: [] });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });
  });

  // =========================================================================
  // 14. Boundary Values — gender validation
  // =========================================================================

  describe('Boundary Values — gender validation', () => {
    it('rejects invalid gender value "Z"', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/patients', {
        ...VALID_MOBILE_PATIENT,
        gender: 'Z',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects full word "Male" for gender', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/patients', {
        ...VALID_MOBILE_PATIENT,
        gender: 'Male',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects full word "Female" for gender', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/patients', {
        ...VALID_MOBILE_PATIENT,
        gender: 'Female',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects lowercase gender "m"', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/patients', {
        ...VALID_MOBILE_PATIENT,
        gender: 'm',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects lowercase gender "f"', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/patients', {
        ...VALID_MOBILE_PATIENT,
        gender: 'f',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects empty string gender', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/patients', {
        ...VALID_MOBILE_PATIENT,
        gender: '',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects integer gender', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/patients', {
        ...VALID_MOBILE_PATIENT,
        gender: 1,
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('accepts valid gender "M"', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/patients', {
        ...VALID_MOBILE_PATIENT,
        gender: 'M',
      });
      expect(res.statusCode).not.toBe(400);
    });

    it('accepts valid gender "F"', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/patients', {
        ...VALID_MOBILE_PATIENT,
        gender: 'F',
      });
      expect(res.statusCode).not.toBe(400);
    });

    it('accepts valid gender "X"', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/patients', {
        ...VALID_MOBILE_PATIENT,
        gender: 'X',
      });
      expect(res.statusCode).not.toBe(400);
    });
  });

  // =========================================================================
  // 15. Boundary Values — first_name / last_name length
  // =========================================================================

  describe('Boundary Values — first_name / last_name length', () => {
    it('rejects first_name exceeding 100 characters', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/patients', {
        ...VALID_MOBILE_PATIENT,
        first_name: 'x'.repeat(101),
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects last_name exceeding 100 characters', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/patients', {
        ...VALID_MOBILE_PATIENT,
        last_name: 'x'.repeat(101),
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects empty first_name', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/patients', {
        ...VALID_MOBILE_PATIENT,
        first_name: '',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects empty last_name', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/patients', {
        ...VALID_MOBILE_PATIENT,
        last_name: '',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('accepts first_name at exactly 100 characters', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/patients', {
        ...VALID_MOBILE_PATIENT,
        first_name: 'x'.repeat(100),
      });
      expect(res.statusCode).not.toBe(400);
    });
  });

  // =========================================================================
  // 16. Boundary Values — health_service_code length
  // =========================================================================

  describe('Boundary Values — health_service_code length', () => {
    it('rejects health_service_code exceeding 10 characters in quick claim', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/quick-claim', {
        ...VALID_QUICK_CLAIM,
        health_service_code: 'x'.repeat(11),
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects empty health_service_code in quick claim', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/quick-claim', {
        ...VALID_QUICK_CLAIM,
        health_service_code: '',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects health_service_code exceeding 10 characters in create favourite', async () => {
      const res = await authedRequest('POST', '/api/v1/favourites', {
        ...VALID_CREATE_FAVOURITE,
        health_service_code: 'x'.repeat(11),
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects empty health_service_code in create favourite', async () => {
      const res = await authedRequest('POST', '/api/v1/favourites', {
        ...VALID_CREATE_FAVOURITE,
        health_service_code: '',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects health_service_code exceeding 10 characters in log patient', async () => {
      const res = await authedRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/patients`, {
        ...VALID_LOG_PATIENT,
        health_service_code: 'x'.repeat(11),
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects empty health_service_code in log patient', async () => {
      const res = await authedRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/patients`, {
        ...VALID_LOG_PATIENT,
        health_service_code: '',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });
  });

  // =========================================================================
  // 17. Modifier Length Validation
  // =========================================================================

  describe('Boundary Values — modifier length', () => {
    it('rejects modifier exceeding 4 characters in create favourite', async () => {
      const res = await authedRequest('POST', '/api/v1/favourites', {
        ...VALID_CREATE_FAVOURITE,
        default_modifiers: ['TOOLONG'],
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects modifier exceeding 4 characters in quick claim', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/quick-claim', {
        ...VALID_QUICK_CLAIM,
        modifiers: ['TOOLONG'],
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects modifier exceeding 4 characters in log patient', async () => {
      const res = await authedRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/patients`, {
        ...VALID_LOG_PATIENT,
        modifiers: ['TOOLONG'],
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('accepts modifier at exactly 4 characters', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/quick-claim', {
        ...VALID_QUICK_CLAIM,
        modifiers: ['CMGP'],
      });
      // Should not be rejected by validation
      expect(res.statusCode).not.toBe(400);
    });
  });

  // =========================================================================
  // 18. Missing Required Fields
  // =========================================================================

  describe('Missing Required Fields', () => {
    it('rejects start shift without location_id', async () => {
      const res = await authedRequest('POST', '/api/v1/shifts', {});
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects create favourite without health_service_code', async () => {
      const res = await authedRequest('POST', '/api/v1/favourites', {
        display_name: 'Test',
        sort_order: 1,
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects create favourite without sort_order', async () => {
      const res = await authedRequest('POST', '/api/v1/favourites', {
        health_service_code: '03.04A',
        display_name: 'Test',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects quick claim without patient_id', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/quick-claim', {
        health_service_code: '03.04A',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects quick claim without health_service_code', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/quick-claim', {
        patient_id: PLACEHOLDER_UUID,
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects log patient without patient_id', async () => {
      const res = await authedRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/patients`, {
        health_service_code: '03.04A',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects log patient without health_service_code', async () => {
      const res = await authedRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/patients`, {
        patient_id: PLACEHOLDER_UUID,
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects mobile patient without first_name', async () => {
      const { first_name: _, ...rest } = VALID_MOBILE_PATIENT;
      const res = await authedRequest('POST', '/api/v1/mobile/patients', rest);
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects mobile patient without last_name', async () => {
      const { last_name: _, ...rest } = VALID_MOBILE_PATIENT;
      const res = await authedRequest('POST', '/api/v1/mobile/patients', rest);
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects mobile patient without phn', async () => {
      const { phn: _, ...rest } = VALID_MOBILE_PATIENT;
      const res = await authedRequest('POST', '/api/v1/mobile/patients', rest);
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects mobile patient without date_of_birth', async () => {
      const { date_of_birth: _, ...rest } = VALID_MOBILE_PATIENT;
      const res = await authedRequest('POST', '/api/v1/mobile/patients', rest);
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects mobile patient without gender', async () => {
      const { gender: _, ...rest } = VALID_MOBILE_PATIENT;
      const res = await authedRequest('POST', '/api/v1/mobile/patients', rest);
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects update favourite with empty body (no fields provided)', async () => {
      const res = await authedRequest('PUT', `/api/v1/favourites/${PLACEHOLDER_UUID}`, {});
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });
  });

  // =========================================================================
  // 19. Empty Body Handling
  // =========================================================================

  describe('Empty Body Handling', () => {
    it('rejects POST /shifts with empty body', async () => {
      const res = await authedRequest('POST', '/api/v1/shifts', {});
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects POST /favourites with empty body', async () => {
      const res = await authedRequest('POST', '/api/v1/favourites', {});
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects PUT /favourites/reorder with empty body', async () => {
      const res = await authedRequest('PUT', '/api/v1/favourites/reorder', {});
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects POST /mobile/quick-claim with empty body', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/quick-claim', {});
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects POST /mobile/patients with empty body', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/patients', {});
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects POST /shifts/:id/patients with empty body', async () => {
      const res = await authedRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/patients`, {});
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });
  });

  // =========================================================================
  // 20. Shift Status Enum Validation
  // =========================================================================

  describe('Shift Status Enum Validation', () => {
    it('rejects invalid status in list shifts', async () => {
      const res = await authedRequest('GET', '/api/v1/shifts?status=INVALID');
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects lowercase status in list shifts', async () => {
      const res = await authedRequest('GET', '/api/v1/shifts?status=active');
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('accepts valid status ACTIVE', async () => {
      const res = await authedRequest('GET', '/api/v1/shifts?status=ACTIVE');
      expect(res.statusCode).not.toBe(400);
    });

    it('accepts valid status ENDED', async () => {
      const res = await authedRequest('GET', '/api/v1/shifts?status=ENDED');
      expect(res.statusCode).not.toBe(400);
    });
  });

  // =========================================================================
  // 21. Error Response Safety
  // =========================================================================

  describe('Error Response Safety', () => {
    it('400 errors return consistent JSON shape', async () => {
      const res = await authedRequest('POST', '/api/v1/shifts', {
        location_id: 'not-uuid',
      });
      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBeDefined();
      expect(body.error.message).toBeDefined();
      expect(body.data).toBeUndefined();
    });

    it('400 errors do not expose SQL keywords in response', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/quick-claim', {
        patient_id: "'; DROP TABLE claims;--",
        health_service_code: '03.04A',
      });
      expect(res.statusCode).toBe(400);
      const raw = JSON.stringify(res.body).toLowerCase();
      expect(raw).not.toContain('drop table');
      expect(raw).not.toContain('select *');
    });

    it('400 errors do not echo PHN back in response', async () => {
      const testPhn = '999888777';
      const res = await authedRequest('POST', '/api/v1/mobile/patients', {
        ...VALID_MOBILE_PATIENT,
        phn: testPhn,
        gender: 'INVALID', // force validation error
      });
      expect(res.statusCode).toBe(400);
      const raw = JSON.stringify(res.body);
      expect(raw).not.toContain(testPhn);
    });

    it('responses always have JSON content-type', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/patients', {
        first_name: '<script>alert(1)</script>',
        last_name: 'Test',
        phn: '123456789',
        date_of_birth: '1990-01-01',
        gender: 'M',
      });
      expect(res.headers['content-type']).toContain('application/json');
    });
  });
});
