// ============================================================================
// Domain 10: Mobile V2 — PHI Leakage Prevention (Security)
//
// Verifies that PHI (specifically PHN) is never exposed through error
// responses, HTTP headers, or cross-tenant 404s for V2 endpoints.
//
// Coverage:
//   - Encounter 422 (PhnValidationError) does not echo submitted PHN
//   - Encounter 404 does not leak encounter/shift data
//   - Schedule 404 does not leak schedule details
//   - Cross-tenant 404s are indistinguishable from missing resources
//   - Response headers: no X-Powered-By, no server version
//   - Error responses: no stack traces, no SQL keywords, no internal state
//   - free_text_tag never appears in error responses
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
import type { SessionManagementDeps } from '../../../src/domains/iam/iam.service.js';

// ---------------------------------------------------------------------------
// Helper: hashToken
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Fixed test identities — Two isolated physicians
// ---------------------------------------------------------------------------

const PA_SESSION_TOKEN = randomBytes(32).toString('hex');
const PA_SESSION_TOKEN_HASH = hashToken(PA_SESSION_TOKEN);
const PA_USER_ID = '11111111-aaaa-0000-0000-000000000001';
const PA_SESSION_ID = '11111111-aaaa-0000-0000-000000000011';

const PB_SESSION_TOKEN = randomBytes(32).toString('hex');
const PB_SESSION_TOKEN_HASH = hashToken(PB_SESSION_TOKEN);
const PB_USER_ID = '22222222-bbbb-0000-0000-000000000002';
const PB_SESSION_ID = '22222222-bbbb-0000-0000-000000000022';

// ---------------------------------------------------------------------------
// Resource IDs
// ---------------------------------------------------------------------------

const PA_SHIFT_ID = 'aaaa0001-0000-0000-0000-000000000001';
const PA_SCHEDULE_ID = 'aaaa0002-0000-0000-0000-000000000001';
const PA_ENCOUNTER_ID = 'aaaa0003-0000-0000-0000-000000000001';
const PA_LOCATION_ID = 'aaaa0004-0000-0000-0000-000000000001';

const PB_SHIFT_ID = 'bbbb0001-0000-0000-0000-000000000001';
const PB_SCHEDULE_ID = 'bbbb0002-0000-0000-0000-000000000001';
const PB_ENCOUNTER_ID = 'bbbb0003-0000-0000-0000-000000000001';
const PB_LOCATION_ID = 'bbbb0004-0000-0000-0000-000000000001';

const NONEXISTENT_UUID = '99999999-9999-9999-9999-999999999999';

// Sensitive PHN values — must never leak in errors
const SUBMITTED_PHN = '123456789';
const PA_PHN = '111222333';
const PB_PHN = '444555666';

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
// In-memory encounter store
// ---------------------------------------------------------------------------

interface MockEncounter {
  encounterId: string;
  shiftId: string;
  providerId: string;
  phn: string | null;
  phnCaptureMethod: string;
  phnIsPartial: boolean;
  healthServiceCode: string | null;
  modifiers: string[] | null;
  diCode: string | null;
  freeTextTag: string | null;
  encounterTimestamp: Date;
  createdAt: Date;
}

interface MockSchedule {
  scheduleId: string;
  providerId: string;
  locationId: string;
  name: string;
  rrule: string;
  shiftStartTime: string;
  shiftDurationMinutes: number;
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}

interface MockShift {
  shiftId: string;
  providerId: string;
  locationId: string;
  shiftStart: Date;
  shiftEnd: Date | null;
  status: string;
  patientCount: number;
  estimatedValue: string;
  createdAt: Date;
  updatedAt: Date;
}

const shiftsStore: Record<string, MockShift> = {};
const encountersStore: Record<string, MockEncounter> = {};
const schedulesStore: Record<string, MockSchedule> = {};

function seedTestData() {
  Object.keys(shiftsStore).forEach((k) => delete shiftsStore[k]);
  Object.keys(encountersStore).forEach((k) => delete encountersStore[k]);
  Object.keys(schedulesStore).forEach((k) => delete schedulesStore[k]);

  // --- PA's shift ---
  shiftsStore[PA_SHIFT_ID] = {
    shiftId: PA_SHIFT_ID,
    providerId: PA_USER_ID,
    locationId: PA_LOCATION_ID,
    shiftStart: new Date('2026-02-19T08:00:00Z'),
    shiftEnd: null,
    status: 'ACTIVE',
    patientCount: 2,
    estimatedValue: '100.00',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  // --- PB's shift ---
  shiftsStore[PB_SHIFT_ID] = {
    shiftId: PB_SHIFT_ID,
    providerId: PB_USER_ID,
    locationId: PB_LOCATION_ID,
    shiftStart: new Date('2026-02-19T09:00:00Z'),
    shiftEnd: null,
    status: 'ACTIVE',
    patientCount: 3,
    estimatedValue: '200.00',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  // --- PA's encounter (with PHN) ---
  encountersStore[PA_ENCOUNTER_ID] = {
    encounterId: PA_ENCOUNTER_ID,
    shiftId: PA_SHIFT_ID,
    providerId: PA_USER_ID,
    phn: PA_PHN,
    phnCaptureMethod: 'MANUAL',
    phnIsPartial: false,
    healthServiceCode: '03.04A',
    modifiers: null,
    diCode: null,
    freeTextTag: 'Confidential note - DO NOT LEAK',
    encounterTimestamp: new Date('2026-02-19T10:00:00Z'),
    createdAt: new Date(),
  };

  // --- PB's encounter (with PHN) ---
  encountersStore[PB_ENCOUNTER_ID] = {
    encounterId: PB_ENCOUNTER_ID,
    shiftId: PB_SHIFT_ID,
    providerId: PB_USER_ID,
    phn: PB_PHN,
    phnCaptureMethod: 'BARCODE',
    phnIsPartial: false,
    healthServiceCode: '08.19A',
    modifiers: null,
    diCode: null,
    freeTextTag: 'PB private note',
    encounterTimestamp: new Date('2026-02-19T11:00:00Z'),
    createdAt: new Date(),
  };

  // --- PA's schedule ---
  schedulesStore[PA_SCHEDULE_ID] = {
    scheduleId: PA_SCHEDULE_ID,
    providerId: PA_USER_ID,
    locationId: PA_LOCATION_ID,
    name: 'PA Monday AM',
    rrule: 'FREQ=WEEKLY;BYDAY=MO',
    shiftStartTime: '08:00',
    shiftDurationMinutes: 480,
    isActive: true,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  // --- PB's schedule ---
  schedulesStore[PB_SCHEDULE_ID] = {
    scheduleId: PB_SCHEDULE_ID,
    providerId: PB_USER_ID,
    locationId: PB_LOCATION_ID,
    name: 'PB Friday PM',
    rrule: 'FREQ=WEEKLY;BYDAY=FR',
    shiftStartTime: '14:00',
    shiftDurationMinutes: 240,
    isActive: true,
    createdAt: new Date(),
    updatedAt: new Date(),
  };
}

// ---------------------------------------------------------------------------
// Mock repositories (provider-scoped)
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

// ---------------------------------------------------------------------------
// Provider-scoped mock shift repo
// ---------------------------------------------------------------------------

function createScopedShiftRepo() {
  return {
    create: vi.fn(async (data: any) => {
      const shift: MockShift = {
        shiftId: crypto.randomUUID(),
        providerId: data.providerId,
        locationId: data.locationId,
        shiftStart: data.shiftStart,
        shiftEnd: null,
        status: 'ACTIVE',
        patientCount: 0,
        estimatedValue: '0.00',
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      shiftsStore[shift.shiftId] = shift;
      return shift;
    }),
    getActive: vi.fn(async (providerId: string) => {
      return (
        Object.values(shiftsStore).find(
          (s) => s.providerId === providerId && s.status === 'ACTIVE',
        ) ?? null
      );
    }),
    getById: vi.fn(async (shiftId: string, providerId: string) => {
      const shift = shiftsStore[shiftId];
      if (!shift || shift.providerId !== providerId) return null;
      return shift;
    }),
    endShift: vi.fn(async (shiftId: string, providerId: string) => {
      const shift = shiftsStore[shiftId];
      if (!shift || shift.providerId !== providerId) return null;
      shift.status = 'COMPLETED';
      shift.shiftEnd = new Date();
      return shift;
    }),
    getSummary: vi.fn(async (shiftId: string, providerId: string) => {
      const shift = shiftsStore[shiftId];
      if (!shift || shift.providerId !== providerId) return null;
      return {
        shiftId: shift.shiftId,
        providerId: shift.providerId,
        locationId: shift.locationId,
        shiftStart: shift.shiftStart,
        shiftEnd: shift.shiftEnd,
        status: shift.status,
        patientCount: shift.patientCount,
        estimatedValue: shift.estimatedValue,
        claims: [],
      };
    }),
    list: vi.fn(async (providerId: string) => {
      const data = Object.values(shiftsStore).filter(
        (s) => s.providerId === providerId,
      );
      return { data, total: data.length };
    }),
    incrementPatientCount: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Provider-scoped mock encounter repo
// ---------------------------------------------------------------------------

function createScopedEncounterRepo() {
  return {
    logEncounter: vi.fn(async (data: any) => {
      // Validate shift is active and belongs to provider
      const shift = shiftsStore[data.shiftId];
      if (!shift || shift.providerId !== data.providerId || shift.status !== 'ACTIVE') {
        const err: any = new Error('Shift not found or not active');
        err.statusCode = 404;
        err.code = 'NOT_FOUND';
        throw err;
      }
      const encounter: MockEncounter = {
        encounterId: crypto.randomUUID(),
        shiftId: data.shiftId,
        providerId: data.providerId,
        phn: data.phn,
        phnCaptureMethod: data.phnCaptureMethod,
        phnIsPartial: data.phnIsPartial,
        healthServiceCode: data.healthServiceCode,
        modifiers: data.modifiers,
        diCode: data.diCode,
        freeTextTag: data.freeTextTag,
        encounterTimestamp: data.encounterTimestamp,
        createdAt: new Date(),
      };
      encountersStore[encounter.encounterId] = encounter;
      return encounter;
    }),
    listEncounters: vi.fn(async (shiftId: string, providerId: string) => {
      return Object.values(encountersStore).filter(
        (e) => e.shiftId === shiftId && e.providerId === providerId,
      );
    }),
    deleteEncounter: vi.fn(async (encounterId: string, shiftId: string, providerId: string) => {
      const enc = encountersStore[encounterId];
      if (!enc || enc.shiftId !== shiftId || enc.providerId !== providerId) return null;
      delete encountersStore[encounterId];
      return enc;
    }),
  };
}

// ---------------------------------------------------------------------------
// Provider-scoped mock schedule repo
// ---------------------------------------------------------------------------

function createScopedScheduleRepo() {
  return {
    create: vi.fn(async (data: any) => {
      const schedule: MockSchedule = {
        scheduleId: crypto.randomUUID(),
        providerId: data.providerId,
        locationId: data.locationId,
        name: data.name,
        rrule: data.rrule,
        shiftStartTime: data.shiftStartTime,
        shiftDurationMinutes: data.shiftDurationMinutes,
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      schedulesStore[schedule.scheduleId] = schedule;
      return schedule;
    }),
    getById: vi.fn(async (scheduleId: string, providerId: string) => {
      const sched = schedulesStore[scheduleId];
      if (!sched || sched.providerId !== providerId) return null;
      return sched;
    }),
    update: vi.fn(async (scheduleId: string, providerId: string, data: any) => {
      const sched = schedulesStore[scheduleId];
      if (!sched || sched.providerId !== providerId) return null;
      if (data.name !== undefined) sched.name = data.name;
      if (data.rrule !== undefined) sched.rrule = data.rrule;
      sched.updatedAt = new Date();
      return sched;
    }),
    delete: vi.fn(async (scheduleId: string, providerId: string) => {
      const sched = schedulesStore[scheduleId];
      if (!sched || sched.providerId !== providerId) return null;
      sched.isActive = false;
      return sched;
    }),
    list: vi.fn(async (providerId: string) => {
      return Object.values(schedulesStore).filter(
        (s) => s.providerId === providerId,
      );
    }),
  };
}

// ---------------------------------------------------------------------------
// Seed users and sessions
// ---------------------------------------------------------------------------

function seedUsers() {
  users = [];
  sessions = [];

  users.push({
    userId: PA_USER_ID,
    email: 'physician-a@example.com',
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    role: 'PHYSICIAN',
    subscriptionStatus: 'ACTIVE',
  });
  sessions.push({
    sessionId: PA_SESSION_ID,
    userId: PA_USER_ID,
    tokenHash: PA_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

  users.push({
    userId: PB_USER_ID,
    email: 'physician-b@example.com',
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    role: 'PHYSICIAN',
    subscriptionStatus: 'ACTIVE',
  });
  sessions.push({
    sessionId: PB_SESSION_ID,
    userId: PB_USER_ID,
    tokenHash: PB_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.2',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });
}

// ---------------------------------------------------------------------------
// Build test dependencies
// ---------------------------------------------------------------------------

function createShiftDeps(): ShiftRouteDeps {
  return {
    serviceDeps: {
      repo: createScopedShiftRepo(),
      locationCheck: {
        belongsToPhysician: vi.fn(async (locationId: string, physicianId: string) => {
          if (locationId === PA_LOCATION_ID && physicianId === PA_USER_ID) return true;
          if (locationId === PB_LOCATION_ID && physicianId === PB_USER_ID) return true;
          return false;
        }),
      },
      claimCreator: {
        createClaimFromShift: vi.fn(async () => ({ claimId: crypto.randomUUID() })),
      },
      auditRepo: createMockAuditRepo(),
    } as any,
    scheduleDeps: {
      scheduleRepo: createScopedScheduleRepo(),
      shiftRepo: createScopedShiftRepo(),
      locationCheck: {
        belongsToPhysician: vi.fn(async (locationId: string, physicianId: string) => {
          if (locationId === PA_LOCATION_ID && physicianId === PA_USER_ID) return true;
          if (locationId === PB_LOCATION_ID && physicianId === PB_USER_ID) return true;
          return false;
        }),
      },
      auditRepo: createMockAuditRepo(),
    } as any,
    encounterDeps: {
      encounterRepo: createScopedEncounterRepo(),
      auditRepo: createMockAuditRepo(),
    } as any,
  };
}

function createScheduleDeps(): ScheduleRouteDeps {
  return {
    serviceDeps: {
      scheduleRepo: createScopedScheduleRepo(),
      shiftRepo: createScopedShiftRepo(),
      locationCheck: {
        belongsToPhysician: vi.fn(async (locationId: string, physicianId: string) => {
          if (locationId === PA_LOCATION_ID && physicianId === PA_USER_ID) return true;
          if (locationId === PB_LOCATION_ID && physicianId === PB_USER_ID) return true;
          return false;
        }),
      },
      auditRepo: createMockAuditRepo(),
    } as any,
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
    events: { emit: vi.fn() },
  };

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  await testApp.register(authPluginFp, { sessionDeps });

  testApp.setErrorHandler((error, _request, reply) => {
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

  await testApp.register(shiftRoutes, { deps: createShiftDeps() });
  await testApp.register(scheduleRoutes, { deps: createScheduleDeps() });

  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------

function physicianARequest(
  method: 'GET' | 'POST' | 'PUT' | 'DELETE',
  url: string,
  payload?: unknown,
) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${PA_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function physicianBRequest(
  method: 'GET' | 'POST' | 'PUT' | 'DELETE',
  url: string,
  payload?: unknown,
) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${PB_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function unauthenticated(
  method: 'GET' | 'POST' | 'PUT' | 'DELETE',
  url: string,
  payload?: unknown,
) {
  return app.inject({
    method,
    url,
    ...(payload !== undefined ? { payload } : {}),
  });
}

// ---------------------------------------------------------------------------
// Utility: recursive key checker
// ---------------------------------------------------------------------------

function containsKeyRecursive(obj: unknown, targetKey: string): boolean {
  if (obj === null || obj === undefined || typeof obj !== 'object') return false;
  if (Array.isArray(obj)) {
    return obj.some((item) => containsKeyRecursive(item, targetKey));
  }
  for (const key of Object.keys(obj as Record<string, unknown>)) {
    if (key === targetKey) return true;
    if (containsKeyRecursive((obj as Record<string, unknown>)[key], targetKey)) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Mobile V2 PHI Leakage Prevention (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    seedUsers();
    seedTestData();
    auditEntries = [];
  });

  // =========================================================================
  // 1. Encounter Error Responses Do Not Echo PHN
  // =========================================================================

  describe('Encounter errors do not echo submitted PHN', () => {
    it('422 PhnValidationError does not echo back the submitted PHN', async () => {
      const badPhn = '12345ABCD';
      const res = await physicianARequest(
        'POST',
        `/api/v1/shifts/${PA_SHIFT_ID}/encounters`,
        {
          phn: badPhn,
          phn_capture_method: 'MANUAL',
          phn_is_partial: false,
          health_service_code: '03.04A',
          encounter_timestamp: '2026-02-19T10:00:00Z',
        },
      );

      // Should be 422 (PhnValidationError) or 400 (schema validation)
      expect([400, 422]).toContain(res.statusCode);
      const rawBody = res.body;

      // The submitted PHN must NOT appear in the response
      expect(rawBody).not.toContain(badPhn);
      expect(rawBody).not.toContain('12345');
    });

    it('422 on Luhn check failure does not echo the full PHN', async () => {
      // 9 digits but fails Luhn check
      const invalidLuhnPhn = '123456780';
      const res = await physicianARequest(
        'POST',
        `/api/v1/shifts/${PA_SHIFT_ID}/encounters`,
        {
          phn: invalidLuhnPhn,
          phn_capture_method: 'MANUAL',
          phn_is_partial: false,
          health_service_code: '03.04A',
          encounter_timestamp: '2026-02-19T10:00:00Z',
        },
      );

      expect([400, 422]).toContain(res.statusCode);
      const rawBody = res.body;
      expect(rawBody).not.toContain(invalidLuhnPhn);
    });

    it('422 on LAST_FOUR with wrong digit count does not echo input', async () => {
      const badLastFour = '123';
      const res = await physicianARequest(
        'POST',
        `/api/v1/shifts/${PA_SHIFT_ID}/encounters`,
        {
          phn: badLastFour,
          phn_capture_method: 'LAST_FOUR',
          phn_is_partial: true,
          health_service_code: '03.04A',
          encounter_timestamp: '2026-02-19T10:00:00Z',
        },
      );

      expect([400, 422]).toContain(res.statusCode);
      expect(res.body).not.toContain(badLastFour);
    });

    it('encounter error response does not contain "phn" key', async () => {
      const res = await physicianARequest(
        'POST',
        `/api/v1/shifts/${PA_SHIFT_ID}/encounters`,
        {
          phn: 'AAABBBCCC',
          phn_capture_method: 'MANUAL',
          phn_is_partial: false,
          health_service_code: '03.04A',
          encounter_timestamp: '2026-02-19T10:00:00Z',
        },
      );

      expect([400, 422]).toContain(res.statusCode);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();
      // No PHN key in the response
      expect(containsKeyRecursive(body, 'phn')).toBe(false);
    });
  });

  // =========================================================================
  // 2. Encounter 404 Does Not Leak Data
  // =========================================================================

  describe('Encounter 404 errors do not leak encounter data', () => {
    it('404 on encounter list for nonexistent shift does not leak encounter details', async () => {
      const res = await physicianARequest(
        'GET',
        `/api/v1/shifts/${NONEXISTENT_UUID}/encounters`,
      );

      // May return 200 with empty array (route does not check shift existence) or 404
      // Either way, PB's data must not appear
      expect(res.body).not.toContain(PB_PHN);
      expect(res.body).not.toContain(PB_ENCOUNTER_ID);
      expect(res.body).not.toContain('PB private note');
      expect(res.body).not.toContain(PA_PHN);
    });

    it('DELETE on nonexistent encounter returns 404 without data', async () => {
      const res = await physicianARequest(
        'DELETE',
        `/api/v1/shifts/${PA_SHIFT_ID}/encounters/${NONEXISTENT_UUID}`,
      );

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();

      // Must not contain PHN or encounter details
      expect(res.body).not.toContain(PA_PHN);
      expect(res.body).not.toContain(PB_PHN);
      expect(res.body).not.toContain('Confidential note');
    });

    it('cross-tenant encounter DELETE returns same 404 as nonexistent', async () => {
      const crossRes = await physicianARequest(
        'DELETE',
        `/api/v1/shifts/${PB_SHIFT_ID}/encounters/${PB_ENCOUNTER_ID}`,
      );
      const missingRes = await physicianARequest(
        'DELETE',
        `/api/v1/shifts/${PA_SHIFT_ID}/encounters/${NONEXISTENT_UUID}`,
      );

      expect(crossRes.statusCode).toBe(404);
      expect(missingRes.statusCode).toBe(404);

      // Identical error shape
      const crossBody = JSON.parse(crossRes.body);
      const missingBody = JSON.parse(missingRes.body);
      expect(crossBody.error.code).toBe(missingBody.error.code);
      expect(crossBody.error.message).toBe(missingBody.error.message);

      // No PB data in cross-tenant response
      expect(crossRes.body).not.toContain(PB_USER_ID);
      expect(crossRes.body).not.toContain(PB_PHN);
      expect(crossRes.body).not.toContain(PB_ENCOUNTER_ID);
    });
  });

  // =========================================================================
  // 3. Schedule 404 Does Not Leak Schedule Details
  // =========================================================================

  describe('Schedule 404 errors do not leak schedule details', () => {
    it('PUT on nonexistent schedule returns 404 without schedule data', async () => {
      const res = await physicianARequest(
        'PUT',
        `/api/v1/mobile/schedules/${NONEXISTENT_UUID}`,
        { name: 'Updated' },
      );

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();

      // No schedule details
      expect(res.body).not.toContain('PA Monday AM');
      expect(res.body).not.toContain('PB Friday PM');
      expect(res.body).not.toContain('FREQ=WEEKLY');
      expect(res.body).not.toContain('rrule');
    });

    it('DELETE on nonexistent schedule returns 404 without schedule data', async () => {
      const res = await physicianARequest(
        'DELETE',
        `/api/v1/mobile/schedules/${NONEXISTENT_UUID}`,
      );

      expect(res.statusCode).toBe(404);
      expect(res.body).not.toContain('PA Monday AM');
      expect(res.body).not.toContain('PB Friday PM');
    });

    it('cross-tenant schedule PUT returns same 404 as nonexistent', async () => {
      const crossRes = await physicianARequest(
        'PUT',
        `/api/v1/mobile/schedules/${PB_SCHEDULE_ID}`,
        { name: 'Hijacked' },
      );
      const missingRes = await physicianARequest(
        'PUT',
        `/api/v1/mobile/schedules/${NONEXISTENT_UUID}`,
        { name: 'Missing' },
      );

      expect(crossRes.statusCode).toBe(404);
      expect(missingRes.statusCode).toBe(404);

      const crossBody = JSON.parse(crossRes.body);
      const missingBody = JSON.parse(missingRes.body);
      expect(crossBody.error.code).toBe(missingBody.error.code);
      expect(crossBody.error.message).toBe(missingBody.error.message);

      // No PB schedule data
      expect(crossRes.body).not.toContain(PB_SCHEDULE_ID);
      expect(crossRes.body).not.toContain('PB Friday PM');
      expect(crossRes.body).not.toContain(PB_LOCATION_ID);
    });

    it('cross-tenant schedule DELETE returns same 404 as nonexistent', async () => {
      const crossRes = await physicianARequest(
        'DELETE',
        `/api/v1/mobile/schedules/${PB_SCHEDULE_ID}`,
      );
      const missingRes = await physicianARequest(
        'DELETE',
        `/api/v1/mobile/schedules/${NONEXISTENT_UUID}`,
      );

      expect(crossRes.statusCode).toBe(404);
      expect(missingRes.statusCode).toBe(404);

      const crossBody = JSON.parse(crossRes.body);
      const missingBody = JSON.parse(missingRes.body);
      expect(crossBody.error.code).toBe(missingBody.error.code);
    });
  });

  // =========================================================================
  // 4. Response Header Security — No Technology Exposure
  // =========================================================================

  describe('Response headers do not leak server internals', () => {
    it('no X-Powered-By header in authenticated encounter response', async () => {
      const res = await physicianARequest(
        'GET',
        `/api/v1/shifts/${PA_SHIFT_ID}/encounters`,
      );
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By header in 401 responses', async () => {
      const res = await unauthenticated(
        'GET',
        `/api/v1/shifts/${PA_SHIFT_ID}/encounters`,
      );
      expect(res.statusCode).toBe(401);
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By header in 400/422 error responses', async () => {
      const res = await physicianARequest(
        'POST',
        `/api/v1/shifts/${PA_SHIFT_ID}/encounters`,
        {
          phn: 'INVALID',
          phn_capture_method: 'MANUAL',
          phn_is_partial: false,
          health_service_code: '03.04A',
        },
      );
      expect([400, 422]).toContain(res.statusCode);
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By header in schedule 404', async () => {
      const res = await physicianARequest(
        'PUT',
        `/api/v1/mobile/schedules/${NONEXISTENT_UUID}`,
        { name: 'Test' },
      );
      expect(res.statusCode).toBe(404);
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no Server header revealing version/technology', async () => {
      const res = await physicianARequest('GET', '/api/v1/mobile/schedules');
      const serverHeader = res.headers['server'];
      if (serverHeader) {
        const lower = (serverHeader as string).toLowerCase();
        expect(lower).not.toContain('fastify');
        expect(lower).not.toContain('node');
        expect(lower).not.toContain('express');
      }
    });

    it('no PHI in response headers for encounter endpoints', async () => {
      const res = await physicianARequest(
        'GET',
        `/api/v1/shifts/${PA_SHIFT_ID}/encounters`,
      );
      const headerStr = JSON.stringify(res.headers);
      expect(headerStr).not.toContain(PA_PHN);
      expect(headerStr).not.toContain(PB_PHN);
      expect(headerStr).not.toContain(SUBMITTED_PHN);
      expect(headerStr).not.toContain('Confidential note');
    });

    it('authenticated responses include Content-Type: application/json', async () => {
      const res = await physicianARequest('GET', '/api/v1/mobile/schedules');
      expect(res.headers['content-type']).toContain('application/json');
    });

    it('error responses include Content-Type: application/json', async () => {
      const res = await unauthenticated('GET', '/api/v1/mobile/schedules');
      expect(res.headers['content-type']).toContain('application/json');
    });
  });

  // =========================================================================
  // 5. Error Responses Are Generic — No Internal State Revealed
  // =========================================================================

  describe('Error responses do not reveal internal state', () => {
    it('error responses never contain SQL-related keywords', async () => {
      const res = await physicianARequest(
        'POST',
        `/api/v1/shifts/${PA_SHIFT_ID}/encounters`,
        {
          phn: "'; DROP TABLE encounters;--",
          phn_capture_method: 'MANUAL',
          phn_is_partial: false,
          health_service_code: '03.04A',
          encounter_timestamp: '2026-02-19T10:00:00Z',
        },
      );

      const lower = res.body.toLowerCase();
      expect(lower).not.toContain('postgres');
      expect(lower).not.toContain('drizzle');
      expect(lower).not.toContain('pg_catalog');
      expect(lower).not.toContain('syntax error');
    });

    it('schedule error responses do not contain SQL keywords', async () => {
      const res = await physicianARequest(
        'POST',
        '/api/v1/mobile/schedules',
        {
          location_id: PA_LOCATION_ID,
          name: "'; DROP TABLE schedules;--",
          rrule: 'FREQ=DAILY',
          shift_start_time: '08:00',
          shift_duration_minutes: 480,
        },
      );

      // May succeed (201) or fail — either way no SQL leakage
      const lower = res.body.toLowerCase();
      expect(lower).not.toContain('postgres');
      expect(lower).not.toContain('drizzle');
      expect(lower).not.toContain('pg_catalog');
    });

    it('500 error returns generic message, no stack trace, no PHI', async () => {
      // Force an unexpected error by hitting a route with bad state
      const res = await physicianARequest(
        'PUT',
        `/api/v1/shifts/${NONEXISTENT_UUID}`,
        {},
      );

      const body = JSON.parse(res.body);
      expect(body.error).not.toHaveProperty('stack');
      expect(body.error).not.toHaveProperty('stackTrace');
      expect(JSON.stringify(body)).not.toMatch(/at\s+\w+\s+\(/);
      expect(JSON.stringify(body)).not.toMatch(/\.ts:\d+:\d+/);
      expect(JSON.stringify(body)).not.toContain('node_modules');
    });

    it('error responses do not expose requested UUIDs in messages', async () => {
      const res = await physicianARequest(
        'DELETE',
        `/api/v1/shifts/${PA_SHIFT_ID}/encounters/${NONEXISTENT_UUID}`,
      );
      expect(res.statusCode).toBe(404);

      const body = JSON.parse(res.body);
      expect(body.error.message).not.toContain(NONEXISTENT_UUID);
    });

    it('all 404 responses on V2 endpoints have consistent error structure', async () => {
      const routes = [
        {
          method: 'PUT' as const,
          url: `/api/v1/mobile/schedules/${NONEXISTENT_UUID}`,
          payload: { name: 'Test' },
        },
        {
          method: 'DELETE' as const,
          url: `/api/v1/mobile/schedules/${NONEXISTENT_UUID}`,
        },
        {
          method: 'DELETE' as const,
          url: `/api/v1/shifts/${PA_SHIFT_ID}/encounters/${NONEXISTENT_UUID}`,
        },
      ];

      for (const route of routes) {
        const res = await physicianARequest(route.method, route.url, route.payload);
        if (res.statusCode === 404) {
          const body = JSON.parse(res.body);
          expect(body.error).toBeDefined();
          expect(body.data).toBeUndefined();
          expect(body.error).toHaveProperty('code');
          expect(body.error).toHaveProperty('message');
          expect(body.error).not.toHaveProperty('stack');
          expect(JSON.stringify(body)).not.toMatch(/\.ts:\d+/);
        }
      }
    });
  });

  // =========================================================================
  // 6. free_text_tag Never Appears in Error Responses
  // =========================================================================

  describe('free_text_tag never leaked in error responses', () => {
    it('free_text_tag is not echoed back in validation error', async () => {
      const sensitiveTag = 'Chest pain with cardiac history';
      const res = await physicianARequest(
        'POST',
        `/api/v1/shifts/${PA_SHIFT_ID}/encounters`,
        {
          phn: 'INVALID',
          phn_capture_method: 'MANUAL',
          phn_is_partial: false,
          health_service_code: '03.04A',
          free_text_tag: sensitiveTag,
          encounter_timestamp: '2026-02-19T10:00:00Z',
        },
      );

      expect([400, 422]).toContain(res.statusCode);
      expect(res.body).not.toContain(sensitiveTag);
      expect(res.body).not.toContain('Chest pain');
      expect(res.body).not.toContain('cardiac');
    });

    it('free_text_tag is not in cross-tenant encounter 404', async () => {
      const res = await physicianARequest(
        'DELETE',
        `/api/v1/shifts/${PB_SHIFT_ID}/encounters/${PB_ENCOUNTER_ID}`,
      );

      expect(res.statusCode).toBe(404);
      expect(res.body).not.toContain('PB private note');
      expect(res.body).not.toContain('Confidential note');
      expect(res.body).not.toContain('freeTextTag');
      expect(res.body).not.toContain('free_text_tag');
    });
  });

  // =========================================================================
  // 7. Cross-Tenant Leakage Prevention
  // =========================================================================

  describe('Cross-tenant data never leaked in V2 endpoints', () => {
    it('encounter list contains only authenticated physician encounters', async () => {
      const res = await physicianARequest(
        'GET',
        `/api/v1/shifts/${PA_SHIFT_ID}/encounters`,
      );

      const rawBody = res.body;
      expect(rawBody).not.toContain(PB_USER_ID);
      expect(rawBody).not.toContain(PB_SHIFT_ID);
      expect(rawBody).not.toContain(PB_PHN);
      expect(rawBody).not.toContain(PB_ENCOUNTER_ID);
      expect(rawBody).not.toContain('PB private note');
    });

    it('schedule list contains only authenticated physician schedules', async () => {
      const res = await physicianARequest('GET', '/api/v1/mobile/schedules');
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain(PB_USER_ID);
      expect(rawBody).not.toContain(PB_SCHEDULE_ID);
      expect(rawBody).not.toContain('PB Friday PM');
      expect(rawBody).not.toContain(PB_LOCATION_ID);
    });

    it('cross-tenant shift detail returns 404 without PB data', async () => {
      const res = await physicianARequest(
        'GET',
        `/api/v1/shifts/${PB_SHIFT_ID}`,
      );

      expect(res.statusCode).toBe(404);
      expect(res.body).not.toContain(PB_USER_ID);
      expect(res.body).not.toContain(PB_LOCATION_ID);
      expect(res.body).not.toContain('200.00');
    });

    it('confirm-inferred with PB schedule returns 404 without PB data', async () => {
      const res = await physicianARequest(
        'POST',
        '/api/v1/shifts/confirm-inferred',
        { schedule_id: PB_SCHEDULE_ID },
      );

      expect(res.statusCode).toBe(404);
      expect(res.body).not.toContain(PB_USER_ID);
      expect(res.body).not.toContain('PB Friday PM');
      expect(res.body).not.toContain(PB_LOCATION_ID);
    });
  });

  // =========================================================================
  // 8. Sensitive Fields Never Leak in Any Response
  // =========================================================================

  describe('Sensitive fields never leak in any V2 response', () => {
    it('encounter responses do not contain password_hash', async () => {
      const res = await physicianARequest(
        'GET',
        `/api/v1/shifts/${PA_SHIFT_ID}/encounters`,
      );
      expect(res.body).not.toContain('passwordHash');
      expect(res.body).not.toContain('password_hash');
    });

    it('schedule responses do not contain session tokens', async () => {
      const res = await physicianARequest('GET', '/api/v1/mobile/schedules');
      expect(res.statusCode).toBe(200);
      expect(res.body).not.toContain('tokenHash');
      expect(res.body).not.toContain('token_hash');
      expect(res.body).not.toContain(PA_SESSION_TOKEN);
      expect(res.body).not.toContain(PA_SESSION_TOKEN_HASH);
    });

    it('encounter responses do not contain TOTP secrets', async () => {
      const res = await physicianARequest(
        'GET',
        `/api/v1/shifts/${PA_SHIFT_ID}/encounters`,
      );
      expect(res.body).not.toContain('totpSecret');
      expect(res.body).not.toContain('totp_secret');
      expect(res.body).not.toContain('JBSWY3DPEHPK3PXP');
    });

    it('shift detail does not contain internal auth fields', async () => {
      const res = await physicianARequest(
        'GET',
        `/api/v1/shifts/${PA_SHIFT_ID}`,
      );
      const rawBody = res.body;
      expect(rawBody).not.toContain('passwordHash');
      expect(rawBody).not.toContain('tokenHash');
      expect(rawBody).not.toContain('totpSecret');
      expect(rawBody).not.toContain(PA_SESSION_TOKEN);
    });
  });
});
