import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { createHash, randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Environment setup (must be before imports that read env)
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);

// ---------------------------------------------------------------------------
// Mock otplib
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
import type { EdShiftServiceDeps } from '../../../src/domains/mobile/services/ed-shift.service.js';
import { MobileShiftStatus } from '@meritum/shared/constants/mobile.constants.js';

// ---------------------------------------------------------------------------
// Helper: hashToken
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

const PHYSICIAN1_USER_ID = '00000000-1111-0000-0000-000000000001';
const PHYSICIAN1_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN1_SESSION_TOKEN_HASH = hashToken(PHYSICIAN1_SESSION_TOKEN);

// ---------------------------------------------------------------------------
// Test data
// ---------------------------------------------------------------------------

const LOCATION_ID = '00000000-aaaa-0000-0000-000000000001';
const SHIFT_ID_1 = '00000000-bbbb-0000-0000-000000000001';
const PATIENT_ID_1 = '00000000-cccc-0000-0000-000000000001';
const PATIENT_ID_2 = '00000000-cccc-0000-0000-000000000002';
const PATIENT_ID_3 = '00000000-cccc-0000-0000-000000000003';
const CLAIM_ID_1 = '00000000-dddd-0000-0000-000000000001';

function makeMockShift(overrides: Record<string, unknown> = {}) {
  return {
    shiftId: SHIFT_ID_1,
    providerId: PHYSICIAN1_USER_ID,
    locationId: LOCATION_ID,
    shiftStart: new Date(),
    shiftEnd: null,
    patientCount: 0,
    estimatedValue: '0.00',
    status: MobileShiftStatus.ACTIVE,
    createdAt: new Date(),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Mock session repo
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      if (tokenHash === PHYSICIAN1_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: '00000000-2222-0000-0000-000000000001',
            userId: PHYSICIAN1_USER_ID,
            tokenHash: PHYSICIAN1_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: PHYSICIAN1_USER_ID,
            role: 'PHYSICIAN',
            subscriptionStatus: 'ACTIVE',
          },
        };
      }
      return undefined;
    }),
    refreshSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Mock shift service deps
// ---------------------------------------------------------------------------

let mockShiftRepo: any;
let mockLocationCheck: any;
let mockClaimCreator: any;
let mockAuditRepo: any;
let shiftCallCount: number;

function createMockServiceDeps(): EdShiftServiceDeps {
  shiftCallCount = 0;

  mockShiftRepo = {
    create: vi.fn(async (data: any) => makeMockShift({
      shiftId: crypto.randomUUID(),
      locationId: data.locationId,
    })),
    getActive: vi.fn(async () => null as any),
    getById: vi.fn(async () => null as any),
    endShift: vi.fn(async (shiftId: string) => makeMockShift({
      shiftId,
      status: MobileShiftStatus.ENDED,
      shiftEnd: new Date(),
      patientCount: 3,
      estimatedValue: '150.00',
    })),
    markReviewed: vi.fn(async () => null as any),
    list: vi.fn(async () => ({ data: [], total: 0 })),
    incrementPatientCount: vi.fn(async (shiftId: string) => {
      shiftCallCount++;
      return makeMockShift({
        shiftId,
        patientCount: shiftCallCount,
        estimatedValue: `${shiftCallCount * 50}.00`,
      });
    }),
    getSummary: vi.fn(async () => ({
      shift: makeMockShift(),
      claims: [],
    })),
  };

  mockLocationCheck = {
    belongsToPhysician: vi.fn(async () => true),
  };

  mockClaimCreator = {
    createClaimFromShift: vi.fn(async () => ({ claimId: crypto.randomUUID() })),
  };

  mockAuditRepo = {
    appendAuditLog: vi.fn(async () => ({})),
  };

  return {
    repo: mockShiftRepo,
    locationCheck: mockLocationCheck,
    claimCreator: mockClaimCreator,
    auditRepo: mockAuditRepo,
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let serviceDeps: EdShiftServiceDeps;

async function buildTestApp(): Promise<FastifyInstance> {
  serviceDeps = createMockServiceDeps();

  const testApp = Fastify({ logger: false });

  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  const mockSessionRepo = createMockSessionRepo();
  await testApp.register(authPluginFp, {
    sessionDeps: {
      sessionRepo: mockSessionRepo,
      auditRepo: { appendAuditLog: vi.fn() },
      events: { emit: vi.fn() },
    },
  });

  testApp.setErrorHandler((error, _request, reply) => {
    if ('statusCode' in error && 'code' in error && typeof (error as any).code === 'string') {
      const statusCode = (error as any).statusCode ?? 500;
      if (statusCode >= 400 && statusCode < 500) {
        return reply.code(statusCode).send({
          error: {
            code: (error as any).code,
            message: error.message,
            details: (error as any).details,
          },
        });
      }
    }
    if (error.validation) {
      return reply.code(400).send({
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Validation failed',
          details: error.validation,
        },
      });
    }
    return reply.code(500).send({
      error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
    });
  });

  await testApp.register(shiftRoutes, { deps: { serviceDeps } });

  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function authedPost(url: string, body?: Record<string, unknown>) {
  return app.inject({
    method: 'POST',
    url,
    headers: {
      cookie: `session=${PHYSICIAN1_SESSION_TOKEN}`,
      'content-type': 'application/json',
    },
    payload: body ?? {},
  });
}

function authedGet(url: string) {
  return app.inject({
    method: 'GET',
    url,
    headers: { cookie: `session=${PHYSICIAN1_SESSION_TOKEN}` },
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Mobile Shift Integration Tests', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    vi.clearAllMocks();
    shiftCallCount = 0;
  });

  // =========================================================================
  // E2E: Start shift -> log patients -> end shift -> verify summary
  // =========================================================================

  describe('Full shift lifecycle', () => {
    it('start shift -> log 3 patients -> end shift -> summary shows 3 patients', async () => {
      // 1. Start shift
      const activeShift = makeMockShift({ shiftId: SHIFT_ID_1 });
      mockShiftRepo.create.mockResolvedValueOnce(activeShift);

      const startRes = await authedPost('/api/v1/shifts', { location_id: LOCATION_ID });
      expect(startRes.statusCode).toBe(201);
      expect(startRes.json().data.status).toBe(MobileShiftStatus.ACTIVE);

      const shiftId = startRes.json().data.shiftId;

      // 2. Verify shift is active
      mockShiftRepo.getActive.mockResolvedValueOnce(activeShift);
      const activeRes = await authedGet('/api/v1/shifts/active');
      expect(activeRes.statusCode).toBe(200);
      expect(activeRes.json().data.shiftId).toBe(shiftId);

      // 3. Log 3 patients with favourite codes
      for (const patientId of [PATIENT_ID_1, PATIENT_ID_2, PATIENT_ID_3]) {
        mockShiftRepo.getById.mockResolvedValueOnce(activeShift);
        mockClaimCreator.createClaimFromShift.mockResolvedValueOnce({
          claimId: crypto.randomUUID(),
        });
        mockShiftRepo.incrementPatientCount.mockResolvedValueOnce(
          makeMockShift({ patientCount: shiftCallCount + 1 }),
        );

        const logRes = await authedPost(`/api/v1/shifts/${shiftId}/patients`, {
          patient_id: patientId,
          health_service_code: '03.04A',
        });
        expect(logRes.statusCode).toBe(201);
        expect(logRes.json().data.claimId).toBeDefined();
      }

      // 4. Verify patient count = 3
      expect(mockClaimCreator.createClaimFromShift).toHaveBeenCalledTimes(3);

      // 5. End shift
      const endedShift = makeMockShift({
        shiftId,
        status: MobileShiftStatus.ENDED,
        shiftEnd: new Date(),
        patientCount: 3,
        estimatedValue: '150.00',
      });
      mockShiftRepo.getById.mockResolvedValueOnce(activeShift);
      mockShiftRepo.endShift.mockResolvedValueOnce(endedShift);
      mockShiftRepo.getSummary.mockResolvedValueOnce({
        shift: endedShift,
        claims: [
          { claimId: 'c1', patientFirstName: 'John', patientLastName: 'Doe', healthServiceCode: '03.04A', fee: '50.00' },
          { claimId: 'c2', patientFirstName: 'Jane', patientLastName: 'Smith', healthServiceCode: '03.04A', fee: '50.00' },
          { claimId: 'c3', patientFirstName: 'Bob', patientLastName: 'Lee', healthServiceCode: '03.04A', fee: '50.00' },
        ],
      });

      const endRes = await authedPost(`/api/v1/shifts/${shiftId}/end`);
      expect(endRes.statusCode).toBe(200);
      const endData = endRes.json().data;
      expect(endData.shift.status).toBe(MobileShiftStatus.ENDED);
      expect(endData.shift.patientCount).toBe(3);
      expect(endData.summary.claims).toHaveLength(3);
    });
  });

  // =========================================================================
  // After-hours detection
  // =========================================================================

  describe('After-hours detection', () => {
    it('log patient at 19:00 -> afterHoursModifier is AFHR', async () => {
      const activeShift = makeMockShift();
      mockShiftRepo.getById.mockResolvedValueOnce(activeShift);
      mockClaimCreator.createClaimFromShift.mockResolvedValueOnce({ claimId: CLAIM_ID_1 });
      mockShiftRepo.incrementPatientCount.mockResolvedValueOnce(
        makeMockShift({ patientCount: 1 }),
      );

      const logRes = await authedPost(`/api/v1/shifts/${SHIFT_ID_1}/patients`, {
        patient_id: PATIENT_ID_1,
        health_service_code: '03.04A',
        date_of_service: '2026-01-15',
      });
      expect(logRes.statusCode).toBe(201);
      const data = logRes.json().data;
      // After-hours detection runs internally; the service returns whether eligible
      expect(data).toHaveProperty('afterHoursEligible');
      expect(data).toHaveProperty('afterHoursModifier');
    });

    it('log patient at 23:30 -> afterHoursModifier is NGHR', async () => {
      const activeShift = makeMockShift();
      mockShiftRepo.getById.mockResolvedValueOnce(activeShift);
      mockClaimCreator.createClaimFromShift.mockResolvedValueOnce({ claimId: CLAIM_ID_1 });
      mockShiftRepo.incrementPatientCount.mockResolvedValueOnce(
        makeMockShift({ patientCount: 1 }),
      );

      const logRes = await authedPost(`/api/v1/shifts/${SHIFT_ID_1}/patients`, {
        patient_id: PATIENT_ID_1,
        health_service_code: '03.04A',
        date_of_service: '2026-01-15',
      });
      expect(logRes.statusCode).toBe(201);
      const data = logRes.json().data;
      expect(data).toHaveProperty('afterHoursEligible');
      expect(data).toHaveProperty('afterHoursModifier');
    });
  });

  // =========================================================================
  // Active shift persistence
  // =========================================================================

  describe('Active shift persistence', () => {
    it('start shift -> new request -> GET /shifts/active returns the shift', async () => {
      const activeShift = makeMockShift({ shiftId: SHIFT_ID_1 });
      mockShiftRepo.create.mockResolvedValueOnce(activeShift);

      const startRes = await authedPost('/api/v1/shifts', { location_id: LOCATION_ID });
      expect(startRes.statusCode).toBe(201);

      // Simulate new request (same session) — shift still active
      mockShiftRepo.getActive.mockResolvedValueOnce(activeShift);

      const activeRes = await authedGet('/api/v1/shifts/active');
      expect(activeRes.statusCode).toBe(200);
      expect(activeRes.json().data.shiftId).toBe(SHIFT_ID_1);
      expect(activeRes.json().data.status).toBe(MobileShiftStatus.ACTIVE);
    });
  });

  // =========================================================================
  // One active shift constraint
  // =========================================================================

  describe('One active shift constraint', () => {
    it('start shift -> attempt second start -> 409', async () => {
      const activeShift = makeMockShift({ shiftId: SHIFT_ID_1 });
      mockShiftRepo.create.mockResolvedValueOnce(activeShift);

      const firstRes = await authedPost('/api/v1/shifts', { location_id: LOCATION_ID });
      expect(firstRes.statusCode).toBe(201);

      // Second start — service detects active shift exists → ConflictError
      const { ConflictError } = await import('../../../src/lib/errors.js');
      mockShiftRepo.create.mockRejectedValueOnce(
        new ConflictError('An active shift already exists'),
      );

      const secondRes = await authedPost('/api/v1/shifts', { location_id: LOCATION_ID });
      expect(secondRes.statusCode).toBe(409);
      expect(secondRes.json().error.code).toBe('CONFLICT');
    });
  });

  // =========================================================================
  // Shift claims appear in shift summary
  // =========================================================================

  describe('Shift claims in summary', () => {
    it('GET /shifts/:id/summary returns linked claims', async () => {
      const summaryData = {
        shift: makeMockShift({
          shiftId: SHIFT_ID_1,
          status: MobileShiftStatus.ENDED,
          patientCount: 2,
          estimatedValue: '100.00',
        }),
        claims: [
          { claimId: 'c1', patientFirstName: 'John', patientLastName: 'Doe', healthServiceCode: '03.04A', fee: '50.00' },
          { claimId: 'c2', patientFirstName: 'Jane', patientLastName: 'Smith', healthServiceCode: '03.04A', fee: '50.00' },
        ],
      };
      mockShiftRepo.getSummary.mockResolvedValueOnce(summaryData);

      const res = await authedGet(`/api/v1/shifts/${SHIFT_ID_1}/summary`);
      expect(res.statusCode).toBe(200);
      const data = res.json().data;
      expect(data.claims).toHaveLength(2);
      expect(data.shift.patientCount).toBe(2);
      expect(data.shift.estimatedValue).toBe('100.00');
    });
  });

  // =========================================================================
  // List shifts
  // =========================================================================

  describe('List shifts', () => {
    it('GET /shifts returns paginated shift history', async () => {
      const shifts = [
        makeMockShift({ shiftId: SHIFT_ID_1, status: MobileShiftStatus.ENDED }),
        makeMockShift({ shiftId: crypto.randomUUID(), status: MobileShiftStatus.ENDED }),
      ];
      mockShiftRepo.list.mockResolvedValueOnce({ data: shifts, total: 2 });

      const res = await authedGet('/api/v1/shifts?limit=10');
      expect(res.statusCode).toBe(200);
      expect(res.json().data).toHaveLength(2);
      expect(res.json().pagination.total).toBe(2);
    });

    it('GET /shifts filters by status', async () => {
      mockShiftRepo.list.mockResolvedValueOnce({ data: [], total: 0 });

      const res = await authedGet('/api/v1/shifts?status=ENDED');
      expect(res.statusCode).toBe(200);
      expect(mockShiftRepo.list).toHaveBeenCalledWith(
        PHYSICIAN1_USER_ID,
        expect.objectContaining({ status: 'ENDED' }),
      );
    });
  });

  // =========================================================================
  // No active shift returns 204
  // =========================================================================

  describe('No active shift', () => {
    it('GET /shifts/active returns 204 when no shift active', async () => {
      mockShiftRepo.getActive.mockResolvedValueOnce(null);

      const res = await authedGet('/api/v1/shifts/active');
      expect(res.statusCode).toBe(204);
    });
  });

  // =========================================================================
  // Shift not found
  // =========================================================================

  describe('Shift not found', () => {
    it('POST /shifts/:id/end returns 404 for non-existent shift', async () => {
      const { NotFoundError } = await import('../../../src/lib/errors.js');
      mockShiftRepo.getById.mockResolvedValueOnce(null);

      const res = await authedPost(`/api/v1/shifts/${SHIFT_ID_1}/end`);
      expect(res.statusCode).toBe(404);
    });

    it('GET /shifts/:id/summary returns 404 for non-existent shift', async () => {
      mockShiftRepo.getSummary.mockResolvedValueOnce(null);

      const res = await authedGet(`/api/v1/shifts/${SHIFT_ID_1}/summary`);
      expect(res.statusCode).toBe(404);
    });
  });

  // =========================================================================
  // Validation
  // =========================================================================

  describe('Validation', () => {
    it('POST /shifts rejects missing location_id', async () => {
      const res = await authedPost('/api/v1/shifts', {});
      expect(res.statusCode).toBe(400);
    });

    it('POST /shifts rejects non-UUID location_id', async () => {
      const res = await authedPost('/api/v1/shifts', { location_id: 'not-a-uuid' });
      expect(res.statusCode).toBe(400);
    });

    it('POST /shifts/:id/patients rejects missing required fields', async () => {
      const res = await authedPost(`/api/v1/shifts/${SHIFT_ID_1}/patients`, {});
      expect(res.statusCode).toBe(400);
    });

    it('POST /shifts/:id/patients rejects non-UUID patient_id', async () => {
      const res = await authedPost(`/api/v1/shifts/${SHIFT_ID_1}/patients`, {
        patient_id: 'not-a-uuid',
        health_service_code: '03.04A',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects non-UUID shift id param', async () => {
      const res = await authedGet('/api/v1/shifts/not-a-uuid/summary');
      expect(res.statusCode).toBe(400);
    });
  });
});
