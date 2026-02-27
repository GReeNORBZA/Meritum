// ============================================================================
// Domain 10: Mobile V2 — Authorization & Role Enforcement (Security)
// Verifies that all Phase 9 endpoints (shift extensions + schedules) enforce
// the PHYSICIAN role check. Delegates are always blocked from these routes
// regardless of permissions (CLAIM_VIEW, CLAIM_CREATE, etc.).
//
// Test identities:
//   - Physician: full access (PHYSICIAN role, all permissions)
//   - Delegate (CLAIM_VIEW + CLAIM_CREATE): blocked by requireRole('PHYSICIAN')
//   - Delegate (no permissions): blocked from everything
//   - Admin: blocked by requireRole('PHYSICIAN') on shift/schedule routes
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
// Helper: hashToken (same SHA-256 used by auth plugin)
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

const PLACEHOLDER_UUID = '00000000-0000-0000-0000-000000000001';
const PLACEHOLDER_UUID_2 = '00000000-0000-0000-0000-000000000002';

// Physician (full access)
const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_USER_ID = '11111111-0000-0000-0000-000000000001';
const PHYSICIAN_SESSION_ID = '11111111-0000-0000-0000-000000000011';

// Delegate with CLAIM_VIEW + CLAIM_CREATE
const DELEGATE_VC_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_VC_SESSION_TOKEN_HASH = hashToken(DELEGATE_VC_SESSION_TOKEN);
const DELEGATE_VC_USER_ID = '22222222-0000-0000-0000-000000000002';
const DELEGATE_VC_SESSION_ID = '22222222-0000-0000-0000-000000000022';

// Delegate with no relevant permissions
const DELEGATE_NONE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_NONE_SESSION_TOKEN_HASH = hashToken(DELEGATE_NONE_SESSION_TOKEN);
const DELEGATE_NONE_USER_ID = '33333333-0000-0000-0000-000000000003';
const DELEGATE_NONE_SESSION_ID = '33333333-0000-0000-0000-000000000033';

// Admin user
const ADMIN_SESSION_TOKEN = randomBytes(32).toString('hex');
const ADMIN_SESSION_TOKEN_HASH = hashToken(ADMIN_SESSION_TOKEN);
const ADMIN_USER_ID = '99999999-0000-0000-0000-000000000009';
const ADMIN_SESSION_ID = '99999999-0000-0000-0000-000000000099';

// ---------------------------------------------------------------------------
// Mock stores
// ---------------------------------------------------------------------------

interface MockUser {
  userId: string;
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
// Mock session repository
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

// ---------------------------------------------------------------------------
// Stub handler deps
// ---------------------------------------------------------------------------

function createStubShiftDeps(): ShiftRouteDeps {
  return {
    serviceDeps: {
      shiftRepo: {
        create: vi.fn(),
        findActive: vi.fn(),
        endShift: vi.fn(),
        findById: vi.fn(),
        listByProvider: vi.fn(),
        logPatient: vi.fn(),
        getShiftSummary: vi.fn(),
      } as any,
      claimRepo: {
        createDraftClaim: vi.fn(),
      } as any,
      auditLog: vi.fn(async () => {}),
    } as any,
    scheduleDeps: {
      scheduleRepo: {
        create: vi.fn(),
        getById: vi.fn(),
        update: vi.fn(),
        delete: vi.fn(),
        list: vi.fn(),
      } as any,
      shiftRepo: {
        create: vi.fn(),
        getActive: vi.fn(),
      } as any,
      locationCheck: {
        belongsToPhysician: vi.fn(async () => true),
      } as any,
      auditRepo: {
        appendAuditLog: vi.fn(async () => {}),
      } as any,
    } as any,
    encounterDeps: {
      encounterRepo: {
        logEncounter: vi.fn(),
        listEncounters: vi.fn(async () => []),
        deleteEncounter: vi.fn(),
      } as any,
      auditRepo: {
        appendAuditLog: vi.fn(async () => {}),
      } as any,
    } as any,
  };
}

function createStubScheduleDeps(): ScheduleRouteDeps {
  return {
    serviceDeps: {
      scheduleRepo: {
        create: vi.fn(),
        getById: vi.fn(),
        update: vi.fn(),
        delete: vi.fn(),
        list: vi.fn(async () => []),
      } as any,
      shiftRepo: {
        create: vi.fn(),
        getActive: vi.fn(),
      } as any,
      locationCheck: {
        belongsToPhysician: vi.fn(async () => true),
      } as any,
      auditRepo: {
        appendAuditLog: vi.fn(async () => {}),
      } as any,
    } as any,
  };
}

// ---------------------------------------------------------------------------
// Seed test data
// ---------------------------------------------------------------------------

function seedUsers() {
  users = [];
  sessions = [];

  // Physician user (full access)
  users.push({
    userId: PHYSICIAN_USER_ID,
    role: 'PHYSICIAN',
    subscriptionStatus: 'ACTIVE',
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

  // Delegate with CLAIM_VIEW + CLAIM_CREATE
  users.push({
    userId: DELEGATE_VC_USER_ID,
    role: 'DELEGATE',
    subscriptionStatus: 'ACTIVE',
    delegateContext: {
      delegateUserId: DELEGATE_VC_USER_ID,
      physicianProviderId: PHYSICIAN_USER_ID,
      permissions: ['CLAIM_VIEW', 'CLAIM_CREATE'],
      linkageId: 'aaaaaaaa-0000-0000-0000-000000000001',
    },
  });
  sessions.push({
    sessionId: DELEGATE_VC_SESSION_ID,
    userId: DELEGATE_VC_USER_ID,
    tokenHash: DELEGATE_VC_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

  // Delegate with no relevant permissions
  users.push({
    userId: DELEGATE_NONE_USER_ID,
    role: 'DELEGATE',
    subscriptionStatus: 'ACTIVE',
    delegateContext: {
      delegateUserId: DELEGATE_NONE_USER_ID,
      physicianProviderId: PHYSICIAN_USER_ID,
      permissions: ['REPORT_VIEW'],
      linkageId: 'bbbbbbbb-0000-0000-0000-000000000002',
    },
  });
  sessions.push({
    sessionId: DELEGATE_NONE_SESSION_ID,
    userId: DELEGATE_NONE_USER_ID,
    tokenHash: DELEGATE_NONE_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

  // Admin user
  users.push({
    userId: ADMIN_USER_ID,
    role: 'ADMIN',
    subscriptionStatus: 'ACTIVE',
  });
  sessions.push({
    sessionId: ADMIN_SESSION_ID,
    userId: ADMIN_USER_ID,
    tokenHash: ADMIN_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });
}

// ---------------------------------------------------------------------------
// Valid payloads
// ---------------------------------------------------------------------------

const validEncounterPayload = {
  phn: '123456789',
  phn_capture_method: 'MANUAL',
  phn_is_partial: false,
  health_service_code: '03.04A',
  encounter_timestamp: '2026-02-19T10:00:00Z',
};

const validSchedulePayload = {
  location_id: PLACEHOLDER_UUID,
  name: 'Monday AM',
  rrule: 'FREQ=WEEKLY;BYDAY=MO',
  shift_start_time: '08:00',
  shift_duration_minutes: 480,
};

const validConfirmInferredPayload = { schedule_id: PLACEHOLDER_UUID };

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
  await testApp.register(scheduleRoutes, { deps: createStubScheduleDeps() });

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

function delegateVCRequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${DELEGATE_VC_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function delegateNoneRequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${DELEGATE_NONE_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function adminRequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Mobile V2 Authorization & Role Enforcement (Security)', () => {
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
  // 1. Physician has full access to all V2 routes
  // =========================================================================

  describe('Physician role — full access to V2 endpoints', () => {
    it('GET /api/v1/shifts/:id — allowed', async () => {
      const res = await physicianRequest('GET', `/api/v1/shifts/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST /api/v1/shifts/confirm-inferred — allowed', async () => {
      const res = await physicianRequest('POST', '/api/v1/shifts/confirm-inferred', validConfirmInferredPayload);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST /api/v1/shifts/:id/encounters — allowed', async () => {
      const res = await physicianRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/encounters`, validEncounterPayload);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /api/v1/shifts/:id/encounters — allowed', async () => {
      const res = await physicianRequest('GET', `/api/v1/shifts/${PLACEHOLDER_UUID}/encounters`);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('DELETE /api/v1/shifts/:id/encounters/:encounterId — allowed', async () => {
      const res = await physicianRequest('DELETE', `/api/v1/shifts/${PLACEHOLDER_UUID}/encounters/${PLACEHOLDER_UUID_2}`);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /api/v1/mobile/schedules/calendar — allowed', async () => {
      const res = await physicianRequest('GET', '/api/v1/mobile/schedules/calendar?from=2026-02-01&to=2026-02-28');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /api/v1/mobile/schedules — allowed', async () => {
      const res = await physicianRequest('GET', '/api/v1/mobile/schedules');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST /api/v1/mobile/schedules — allowed', async () => {
      const res = await physicianRequest('POST', '/api/v1/mobile/schedules', validSchedulePayload);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('PUT /api/v1/mobile/schedules/:id — allowed', async () => {
      const res = await physicianRequest('PUT', `/api/v1/mobile/schedules/${PLACEHOLDER_UUID}`, { name: 'Updated' });
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('DELETE /api/v1/mobile/schedules/:id — allowed', async () => {
      const res = await physicianRequest('DELETE', `/api/v1/mobile/schedules/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });
  });

  // =========================================================================
  // 2. Delegate with CLAIM_VIEW + CLAIM_CREATE — blocked on all V2 routes
  // =========================================================================

  describe('Delegate with CLAIM_VIEW + CLAIM_CREATE — blocked on all V2 routes (physician-only)', () => {
    const v2Routes = [
      { method: 'GET' as const, url: `/api/v1/shifts/${PLACEHOLDER_UUID}`, description: 'get shift details' },
      { method: 'POST' as const, url: '/api/v1/shifts/confirm-inferred', payload: validConfirmInferredPayload, description: 'confirm inferred shift' },
      { method: 'POST' as const, url: `/api/v1/shifts/${PLACEHOLDER_UUID}/encounters`, payload: validEncounterPayload, description: 'log encounter' },
      { method: 'GET' as const, url: `/api/v1/shifts/${PLACEHOLDER_UUID}/encounters`, description: 'list encounters' },
      { method: 'DELETE' as const, url: `/api/v1/shifts/${PLACEHOLDER_UUID}/encounters/${PLACEHOLDER_UUID_2}`, description: 'delete encounter' },
      { method: 'GET' as const, url: '/api/v1/mobile/schedules/calendar?from=2026-02-01&to=2026-02-28', description: 'schedule calendar' },
      { method: 'GET' as const, url: '/api/v1/mobile/schedules', description: 'list schedules' },
      { method: 'POST' as const, url: '/api/v1/mobile/schedules', payload: validSchedulePayload, description: 'create schedule' },
      { method: 'PUT' as const, url: `/api/v1/mobile/schedules/${PLACEHOLDER_UUID}`, payload: { name: 'Updated' }, description: 'update schedule' },
      { method: 'DELETE' as const, url: `/api/v1/mobile/schedules/${PLACEHOLDER_UUID}`, description: 'delete schedule' },
    ];

    for (const route of v2Routes) {
      it(`delegate blocked from ${route.description} (${route.method} ${route.url.split('?')[0]})`, async () => {
        const res = await delegateVCRequest(route.method, route.url, route.payload);
        expect(res.statusCode).toBe(403);
        const body = JSON.parse(res.body);
        expect(body.error).toBeDefined();
        expect(body.error.code).toBe('FORBIDDEN');
        expect(body.data).toBeUndefined();
      });
    }
  });

  // =========================================================================
  // 3. Delegate with no permissions — blocked on all V2 routes
  // =========================================================================

  describe('Delegate with no relevant permissions — blocked on all V2 routes', () => {
    const v2Routes = [
      { method: 'GET' as const, url: `/api/v1/shifts/${PLACEHOLDER_UUID}` },
      { method: 'POST' as const, url: '/api/v1/shifts/confirm-inferred', payload: validConfirmInferredPayload },
      { method: 'POST' as const, url: `/api/v1/shifts/${PLACEHOLDER_UUID}/encounters`, payload: validEncounterPayload },
      { method: 'GET' as const, url: `/api/v1/shifts/${PLACEHOLDER_UUID}/encounters` },
      { method: 'DELETE' as const, url: `/api/v1/shifts/${PLACEHOLDER_UUID}/encounters/${PLACEHOLDER_UUID_2}` },
      { method: 'GET' as const, url: '/api/v1/mobile/schedules/calendar?from=2026-02-01&to=2026-02-28' },
      { method: 'GET' as const, url: '/api/v1/mobile/schedules' },
      { method: 'POST' as const, url: '/api/v1/mobile/schedules', payload: validSchedulePayload },
      { method: 'PUT' as const, url: `/api/v1/mobile/schedules/${PLACEHOLDER_UUID}`, payload: { name: 'X' } },
      { method: 'DELETE' as const, url: `/api/v1/mobile/schedules/${PLACEHOLDER_UUID}` },
    ];

    for (const route of v2Routes) {
      it(`${route.method} ${route.url.split('?')[0]} — 403`, async () => {
        const res = await delegateNoneRequest(route.method, route.url, route.payload);
        expect(res.statusCode).toBe(403);
      });
    }
  });

  // =========================================================================
  // 4. Admin role — blocked by requireRole('PHYSICIAN')
  // =========================================================================

  describe('Admin role — blocked by requireRole(PHYSICIAN) on V2 routes', () => {
    it('admin blocked from GET /api/v1/shifts/:id', async () => {
      const res = await adminRequest('GET', `/api/v1/shifts/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
    });

    it('admin blocked from POST /api/v1/shifts/confirm-inferred', async () => {
      const res = await adminRequest('POST', '/api/v1/shifts/confirm-inferred', validConfirmInferredPayload);
      expect(res.statusCode).toBe(403);
    });

    it('admin blocked from POST /api/v1/shifts/:id/encounters', async () => {
      const res = await adminRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/encounters`, validEncounterPayload);
      expect(res.statusCode).toBe(403);
    });

    it('admin blocked from GET /api/v1/mobile/schedules', async () => {
      const res = await adminRequest('GET', '/api/v1/mobile/schedules');
      expect(res.statusCode).toBe(403);
    });

    it('admin blocked from POST /api/v1/mobile/schedules', async () => {
      const res = await adminRequest('POST', '/api/v1/mobile/schedules', validSchedulePayload);
      expect(res.statusCode).toBe(403);
    });

    it('admin blocked from DELETE /api/v1/mobile/schedules/:id', async () => {
      const res = await adminRequest('DELETE', `/api/v1/mobile/schedules/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
    });
  });

  // =========================================================================
  // 5. 403 response shape — no data leakage on permission denial
  // =========================================================================

  describe('403 response shape — no data leakage', () => {
    it('403 response has consistent error shape with no data field', async () => {
      const res = await delegateVCRequest('GET', `/api/v1/shifts/${PLACEHOLDER_UUID}/encounters`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('403 response does not contain internal identifiers', async () => {
      const res = await delegateVCRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/encounters`, validEncounterPayload);
      expect(res.statusCode).toBe(403);
      const rawBody = res.body;
      expect(rawBody).not.toContain('postgres');
      expect(rawBody).not.toContain('drizzle');
      expect(rawBody).not.toContain('session_id');
      expect(rawBody).not.toContain('provider_id');
      expect(rawBody).not.toContain('stack');
    });

    it('403 does not expose permission names in error details', async () => {
      const res = await delegateNoneRequest('GET', '/api/v1/mobile/schedules');
      expect(res.statusCode).toBe(403);
      const rawBody = res.body;
      expect(rawBody).not.toContain('CLAIM_VIEW');
      expect(rawBody).not.toContain('CLAIM_CREATE');
    });

    it('403 on schedule creation does not leak schedule data', async () => {
      const res = await delegateVCRequest('POST', '/api/v1/mobile/schedules', validSchedulePayload);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.message).not.toContain('schedule');
      expect(body.error.message).not.toContain('rrule');
    });

    it('403 on encounter log does not leak PHN or encounter data', async () => {
      const res = await delegateVCRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/encounters`, validEncounterPayload);
      expect(res.statusCode).toBe(403);
      const rawBody = res.body;
      expect(rawBody).not.toContain('phn');
      expect(rawBody).not.toContain('encounter');
      expect(rawBody).not.toContain('123456789');
    });
  });

  // =========================================================================
  // 6. Permission escalation prevention
  // =========================================================================

  describe('Permission escalation prevention', () => {
    it('delegate cannot bypass role check by having all claim permissions', async () => {
      const res = await delegateVCRequest('POST', '/api/v1/shifts/confirm-inferred', validConfirmInferredPayload);
      expect(res.statusCode).toBe(403);
    });

    it('delegate cannot use encounter endpoints even with CLAIM_CREATE', async () => {
      const res = await delegateVCRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/encounters`, validEncounterPayload);
      expect(res.statusCode).toBe(403);
    });

    it('delegate cannot view schedules even with CLAIM_VIEW', async () => {
      const res = await delegateVCRequest('GET', '/api/v1/mobile/schedules');
      expect(res.statusCode).toBe(403);
    });

    it('delegate cannot create schedules even with CLAIM_CREATE', async () => {
      const res = await delegateVCRequest('POST', '/api/v1/mobile/schedules', validSchedulePayload);
      expect(res.statusCode).toBe(403);
    });

    it('delegate cannot delete encounters even with CLAIM_CREATE', async () => {
      const res = await delegateVCRequest('DELETE', `/api/v1/shifts/${PLACEHOLDER_UUID}/encounters/${PLACEHOLDER_UUID_2}`);
      expect(res.statusCode).toBe(403);
    });

    it('delegate cannot view calendar even with CLAIM_VIEW', async () => {
      const res = await delegateVCRequest('GET', '/api/v1/mobile/schedules/calendar?from=2026-02-01&to=2026-02-28');
      expect(res.statusCode).toBe(403);
    });
  });
});
