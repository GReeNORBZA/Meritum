// ============================================================================
// Domain 10: Mobile V2 — Input Validation & Injection Prevention (Security)
// Verifies PHN injection, invalid RRULE, XSS in free_text_tag, UUID validation,
// SQL injection, and type coercion attacks across V2 endpoints.
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
import { scheduleRoutes } from '../../../src/domains/mobile/routes/schedule.routes.js';
import type { ShiftRouteDeps } from '../../../src/domains/mobile/routes/shift.routes.js';
import type { ScheduleRouteDeps } from '../../../src/domains/mobile/routes/schedule.routes.js';

// ---------------------------------------------------------------------------
// Helper: hashToken
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
// Stub handler deps
// ---------------------------------------------------------------------------

function createStubShiftDeps(): ShiftRouteDeps {
  return {
    serviceDeps: {
      shiftRepo: { create: vi.fn(), findActive: vi.fn(), endShift: vi.fn(), findById: vi.fn(), listByProvider: vi.fn(), logPatient: vi.fn(), getShiftSummary: vi.fn() } as any,
      claimRepo: { createDraftClaim: vi.fn() } as any,
      auditLog: vi.fn(async () => {}),
    } as any,
    scheduleDeps: {
      scheduleRepo: { create: vi.fn(), getById: vi.fn(), update: vi.fn(), delete: vi.fn(), list: vi.fn() } as any,
      shiftRepo: { create: vi.fn(), getActive: vi.fn() } as any,
      locationCheck: { belongsToPhysician: vi.fn(async () => true) } as any,
      auditRepo: { appendAuditLog: vi.fn(async () => {}) } as any,
    } as any,
    encounterDeps: {
      encounterRepo: { logEncounter: vi.fn(), listEncounters: vi.fn(async () => []), deleteEncounter: vi.fn() } as any,
      auditRepo: { appendAuditLog: vi.fn(async () => {}) } as any,
    } as any,
  };
}

function createStubScheduleDeps(): ScheduleRouteDeps {
  return {
    serviceDeps: {
      scheduleRepo: { create: vi.fn(), getById: vi.fn(), update: vi.fn(), delete: vi.fn(), list: vi.fn(async () => []) } as any,
      shiftRepo: { create: vi.fn(), getActive: vi.fn() } as any,
      locationCheck: { belongsToPhysician: vi.fn(async () => true) } as any,
      auditRepo: { appendAuditLog: vi.fn(async () => {}) } as any,
    } as any,
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;

async function buildTestApp(): Promise<FastifyInstance> {
  const sessionDeps = {
    sessionRepo: createMockSessionRepo(),
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
  await testApp.register(scheduleRoutes, { deps: createStubScheduleDeps() });
  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function authCookie(): string {
  return `session=${FIXED_SESSION_TOKEN}`;
}

async function authedRequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: authCookie() },
    ...(payload !== undefined ? { payload } : {}),
  });
}

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

const VALID_ENCOUNTER = {
  phn: '123456789',
  phn_capture_method: 'MANUAL',
  phn_is_partial: false,
  health_service_code: '03.04A',
  encounter_timestamp: '2026-02-19T10:00:00Z',
};

const VALID_SCHEDULE = {
  location_id: PLACEHOLDER_UUID,
  name: 'Monday AM',
  rrule: 'FREQ=WEEKLY;BYDAY=MO',
  shift_start_time: '08:00',
  shift_duration_minutes: 480,
};

// ---------------------------------------------------------------------------
// Attack payloads
// ---------------------------------------------------------------------------

const SQL_INJECTION_PAYLOADS = [
  "'; DROP TABLE ed_shift_encounters; --",
  "' OR 1=1--",
  "1; SELECT * FROM shift_schedules --",
  "' UNION SELECT phn FROM encounters --",
];

const XSS_PAYLOADS = [
  '<script>alert("xss")</script>',
  '<img src=x onerror=alert(1)>',
  '<svg onload=alert(1)>',
  'javascript:alert(document.cookie)',
];

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Mobile V2 Input Validation & Injection Prevention (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    sessions = [];
    users = [];
    users.push({ userId: FIXED_USER_ID, role: 'PHYSICIAN', subscriptionStatus: 'ACTIVE' });
    sessions.push({
      sessionId: FIXED_SESSION_ID, userId: FIXED_USER_ID, tokenHash: FIXED_SESSION_TOKEN_HASH,
      ipAddress: '127.0.0.1', userAgent: 'test-agent', createdAt: new Date(),
      lastActiveAt: new Date(), revoked: false, revokedReason: null,
    });
  });

  // =========================================================================
  // 1. PHN Injection — Encounter Endpoint
  // =========================================================================

  describe('PHN Injection — Encounter Endpoint', () => {
    for (const payload of SQL_INJECTION_PAYLOADS) {
      it(`rejects SQL injection in encounter phn: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/encounters`, {
          ...VALID_ENCOUNTER,
          phn: payload,
        });
        // PHN has strict regex — all SQL payloads rejected
        expect(res.statusCode).toBe(400);
        assertNoInternalLeakage(res.body);
      });
    }

    it('rejects PHN with letters', async () => {
      const res = await authedRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/encounters`, {
        ...VALID_ENCOUNTER,
        phn: '12345ABCD',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects PHN with 8 digits (too short for full)', async () => {
      const res = await authedRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/encounters`, {
        ...VALID_ENCOUNTER,
        phn: '12345678',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects PHN with 10 digits (too long)', async () => {
      const res = await authedRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/encounters`, {
        ...VALID_ENCOUNTER,
        phn: '1234567890',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects empty PHN with MANUAL capture method', async () => {
      const res = await authedRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/encounters`, {
        ...VALID_ENCOUNTER,
        phn: '',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects 3-digit PHN with LAST_FOUR capture method', async () => {
      const res = await authedRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/encounters`, {
        ...VALID_ENCOUNTER,
        phn: '123',
        phn_capture_method: 'LAST_FOUR',
        phn_is_partial: true,
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects 5-digit PHN with LAST_FOUR capture method', async () => {
      const res = await authedRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/encounters`, {
        ...VALID_ENCOUNTER,
        phn: '12345',
        phn_capture_method: 'LAST_FOUR',
        phn_is_partial: true,
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });
  });

  // =========================================================================
  // 2. Invalid RRULE — Schedule Endpoint
  // =========================================================================

  describe('Invalid RRULE — Schedule Endpoint', () => {
    it('handles SQL injection in rrule safely', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/schedules', {
        ...VALID_SCHEDULE,
        rrule: "'; DROP TABLE shift_schedules; --",
      });
      // Regardless of whether it passes Zod, no internal leakage
      assertNoInternalLeakage(res.body);
      expect(res.statusCode).not.toBe(500);
    });

    it('handles XSS in rrule safely', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/schedules', {
        ...VALID_SCHEDULE,
        rrule: '<script>alert(1)</script>',
      });
      assertNoInternalLeakage(res.body);
      expect(res.headers['content-type']).toContain('application/json');
      expect(res.statusCode).not.toBe(500);
    });

    it('handles empty rrule', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/schedules', {
        ...VALID_SCHEDULE,
        rrule: '',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('handles excessively long rrule', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/schedules', {
        ...VALID_SCHEDULE,
        rrule: 'FREQ=WEEKLY;BYDAY=' + 'MO,'.repeat(500),
      });
      assertNoInternalLeakage(res.body);
      expect(res.statusCode).not.toBe(500);
    });
  });

  // =========================================================================
  // 3. XSS in free_text_tag — Encounter Endpoint
  // =========================================================================

  describe('XSS in free_text_tag — Encounter Endpoint', () => {
    for (const payload of XSS_PAYLOADS) {
      it(`handles XSS in free_text_tag safely: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/encounters`, {
          ...VALID_ENCOUNTER,
          free_text_tag: payload,
        });
        expect(res.headers['content-type']).toContain('application/json');
        assertNoInternalLeakage(res.body);
        expect(res.statusCode).not.toBe(500);
      });
    }

    for (const payload of XSS_PAYLOADS) {
      it(`handles XSS in schedule name safely: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('POST', '/api/v1/mobile/schedules', {
          ...VALID_SCHEDULE,
          name: payload,
        });
        expect(res.headers['content-type']).toContain('application/json');
        assertNoInternalLeakage(res.body);
        expect(res.statusCode).not.toBe(500);
      });
    }
  });

  // =========================================================================
  // 4. UUID Validation — All ID Parameters
  // =========================================================================

  describe('UUID Validation — V2 ID Parameters', () => {
    const INVALID_UUIDS = [
      'not-a-uuid',
      '12345',
      "' OR 1=1--",
      '',
      'gggggggg-0000-0000-0000-000000000001',
    ];

    for (const badUuid of INVALID_UUIDS) {
      it(`rejects invalid UUID "${badUuid}" in GET /shifts/:id`, async () => {
        const res = await authedRequest('GET', `/api/v1/shifts/${encodeURIComponent(badUuid)}`);
        expect(res.statusCode).toBe(400);
        assertNoInternalLeakage(res.body);
      });
    }

    for (const badUuid of INVALID_UUIDS) {
      it(`rejects invalid UUID "${badUuid}" in POST /shifts/:id/encounters`, async () => {
        const res = await authedRequest('POST', `/api/v1/shifts/${encodeURIComponent(badUuid)}/encounters`, VALID_ENCOUNTER);
        expect(res.statusCode).toBe(400);
        assertNoInternalLeakage(res.body);
      });
    }

    for (const badUuid of INVALID_UUIDS) {
      it(`rejects invalid UUID "${badUuid}" in DELETE /shifts/:id/encounters/:eid`, async () => {
        const res = await authedRequest('DELETE', `/api/v1/shifts/${PLACEHOLDER_UUID}/encounters/${encodeURIComponent(badUuid)}`);
        expect(res.statusCode).toBe(400);
        assertNoInternalLeakage(res.body);
      });
    }

    for (const badUuid of INVALID_UUIDS) {
      it(`rejects invalid UUID "${badUuid}" in PUT /schedules/:id`, async () => {
        const res = await authedRequest('PUT', `/api/v1/mobile/schedules/${encodeURIComponent(badUuid)}`, { name: 'X' });
        expect(res.statusCode).toBe(400);
        assertNoInternalLeakage(res.body);
      });
    }

    for (const badUuid of INVALID_UUIDS) {
      it(`rejects invalid UUID "${badUuid}" in DELETE /schedules/:id`, async () => {
        const res = await authedRequest('DELETE', `/api/v1/mobile/schedules/${encodeURIComponent(badUuid)}`);
        expect(res.statusCode).toBe(400);
        assertNoInternalLeakage(res.body);
      });
    }

    for (const badUuid of INVALID_UUIDS) {
      it(`rejects invalid UUID "${badUuid}" in confirm-inferred schedule_id`, async () => {
        const res = await authedRequest('POST', '/api/v1/shifts/confirm-inferred', { schedule_id: badUuid });
        expect(res.statusCode).toBe(400);
        assertNoInternalLeakage(res.body);
      });
    }

    for (const badUuid of INVALID_UUIDS) {
      it(`rejects invalid UUID "${badUuid}" in schedule location_id`, async () => {
        const res = await authedRequest('POST', '/api/v1/mobile/schedules', {
          ...VALID_SCHEDULE,
          location_id: badUuid,
        });
        expect(res.statusCode).toBe(400);
        assertNoInternalLeakage(res.body);
      });
    }
  });

  // =========================================================================
  // 5. SQL Injection — Schedule Text Fields
  // =========================================================================

  describe('SQL Injection — Schedule Text Fields', () => {
    for (const payload of SQL_INJECTION_PAYLOADS) {
      it(`handles SQL injection in schedule name: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('POST', '/api/v1/mobile/schedules', {
          ...VALID_SCHEDULE,
          name: payload,
        });
        assertNoInternalLeakage(res.body);
        expect(res.statusCode).not.toBe(500);
      });
    }

    for (const payload of SQL_INJECTION_PAYLOADS) {
      it(`handles SQL injection in schedule update name: ${payload.slice(0, 30)}...`, async () => {
        const res = await authedRequest('PUT', `/api/v1/mobile/schedules/${PLACEHOLDER_UUID}`, {
          name: payload,
        });
        assertNoInternalLeakage(res.body);
        expect(res.statusCode).not.toBe(500);
      });
    }
  });

  // =========================================================================
  // 6. Type Coercion Attacks
  // =========================================================================

  describe('Type Coercion Attacks', () => {
    it('rejects integer phn in encounter', async () => {
      const res = await authedRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/encounters`, {
        ...VALID_ENCOUNTER,
        phn: 123456789,
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects boolean phn_is_partial as string in encounter', async () => {
      const res = await authedRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/encounters`, {
        ...VALID_ENCOUNTER,
        phn_is_partial: 'true',
      });
      // Should be rejected or coerced — either way no 500
      assertNoInternalLeakage(res.body);
      expect(res.statusCode).not.toBe(500);
    });

    it('rejects string shift_duration_minutes in schedule', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/schedules', {
        ...VALID_SCHEDULE,
        shift_duration_minutes: 'eight-hours',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects negative shift_duration_minutes in schedule', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/schedules', {
        ...VALID_SCHEDULE,
        shift_duration_minutes: -60,
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects array location_id in schedule', async () => {
      const res = await authedRequest('POST', '/api/v1/mobile/schedules', {
        ...VALID_SCHEDULE,
        location_id: [PLACEHOLDER_UUID],
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects null schedule_id in confirm-inferred', async () => {
      const res = await authedRequest('POST', '/api/v1/shifts/confirm-inferred', {
        schedule_id: null,
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });
  });

  // =========================================================================
  // 7. Invalid phn_capture_method — Encounter Endpoint
  // =========================================================================

  describe('Invalid phn_capture_method', () => {
    it('rejects unknown capture method', async () => {
      const res = await authedRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/encounters`, {
        ...VALID_ENCOUNTER,
        phn_capture_method: 'TELEPATHY',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects lowercase capture method', async () => {
      const res = await authedRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/encounters`, {
        ...VALID_ENCOUNTER,
        phn_capture_method: 'manual',
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects integer capture method', async () => {
      const res = await authedRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/encounters`, {
        ...VALID_ENCOUNTER,
        phn_capture_method: 1,
      });
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });
  });

  // =========================================================================
  // 8. Calendar Query Validation
  // =========================================================================

  describe('Calendar Query Validation', () => {
    it('rejects missing from parameter', async () => {
      const res = await authedRequest('GET', '/api/v1/mobile/schedules/calendar?to=2026-02-28');
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects missing to parameter', async () => {
      const res = await authedRequest('GET', '/api/v1/mobile/schedules/calendar?from=2026-02-01');
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects invalid date format in from', async () => {
      const res = await authedRequest('GET', '/api/v1/mobile/schedules/calendar?from=02-01-2026&to=2026-02-28');
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects SQL injection in from parameter', async () => {
      const res = await authedRequest('GET', `/api/v1/mobile/schedules/calendar?from=${encodeURIComponent("'; DROP TABLE shift_schedules;--")}&to=2026-02-28`);
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });
  });

  // =========================================================================
  // 9. Missing Required Fields
  // =========================================================================

  describe('Missing Required Fields', () => {
    it('rejects encounter without phn_capture_method', async () => {
      const { phn_capture_method: _, ...rest } = VALID_ENCOUNTER;
      const res = await authedRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/encounters`, rest);
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects schedule without location_id', async () => {
      const { location_id: _, ...rest } = VALID_SCHEDULE;
      const res = await authedRequest('POST', '/api/v1/mobile/schedules', rest);
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects schedule without rrule', async () => {
      const { rrule: _, ...rest } = VALID_SCHEDULE;
      const res = await authedRequest('POST', '/api/v1/mobile/schedules', rest);
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects schedule without shift_start_time', async () => {
      const { shift_start_time: _, ...rest } = VALID_SCHEDULE;
      const res = await authedRequest('POST', '/api/v1/mobile/schedules', rest);
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });

    it('rejects confirm-inferred without schedule_id', async () => {
      const res = await authedRequest('POST', '/api/v1/shifts/confirm-inferred', {});
      expect(res.statusCode).toBe(400);
      assertNoInternalLeakage(res.body);
    });
  });

  // =========================================================================
  // 10. Error Response Safety
  // =========================================================================

  describe('Error Response Safety', () => {
    it('400 errors return consistent JSON shape', async () => {
      const res = await authedRequest('POST', '/api/v1/shifts/confirm-inferred', { schedule_id: 'not-uuid' });
      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBeDefined();
      expect(body.error.message).toBeDefined();
      expect(body.data).toBeUndefined();
    });

    it('400 errors do not expose SQL keywords in response', async () => {
      const res = await authedRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/encounters`, {
        ...VALID_ENCOUNTER,
        phn: "'; DROP TABLE encounters;--",
      });
      expect(res.statusCode).toBe(400);
      const raw = JSON.stringify(res.body).toLowerCase();
      expect(raw).not.toContain('drop table');
      expect(raw).not.toContain('select *');
    });

    it('responses always have JSON content-type', async () => {
      const res = await authedRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/encounters`, {
        ...VALID_ENCOUNTER,
        free_text_tag: '<script>alert(1)</script>',
      });
      expect(res.headers['content-type']).toContain('application/json');
    });
  });
});
