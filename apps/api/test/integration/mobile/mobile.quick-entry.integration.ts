import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { createHash, randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Environment setup
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
import { mobileRoutes } from '../../../src/domains/mobile/routes/mobile.routes.js';
import type { QuickClaimServiceDeps } from '../../../src/domains/mobile/services/quick-claim.service.js';
import type { MobileSummaryServiceDeps } from '../../../src/domains/mobile/services/mobile-summary.service.js';

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

const PATIENT_ID_1 = '00000000-cccc-0000-0000-000000000001';
const PATIENT_ID_2 = '00000000-cccc-0000-0000-000000000002';
const PATIENT_ID_3 = '00000000-cccc-0000-0000-000000000003';

const VALID_QUICK_CLAIM = {
  patient_id: PATIENT_ID_1,
  health_service_code: '03.04A',
  date_of_service: '2026-01-15',
};

const VALID_PATIENT = {
  first_name: 'John',
  last_name: 'Doe',
  phn: '123456789',
  date_of_birth: '1990-05-15',
  gender: 'M' as const,
};

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
// Mock service deps
// ---------------------------------------------------------------------------

let mockClaimCreator: any;
let mockPatientCreator: any;
let mockRecentPatientsQuery: any;
let mockAuditRepo: any;

function createMockQuickClaimDeps(): QuickClaimServiceDeps {
  mockClaimCreator = {
    createDraftClaim: vi.fn(async (_pid: string, data: any) => ({
      claimId: crypto.randomUUID(),
    })),
  };

  mockPatientCreator = {
    createMinimalPatient: vi.fn(async (_pid: string, data: any) => ({
      patientId: crypto.randomUUID(),
      ...data,
    })),
  };

  mockRecentPatientsQuery = {
    getRecentBilledPatients: vi.fn(async () => []),
  };

  mockAuditRepo = {
    appendAuditLog: vi.fn(async () => ({})),
  };

  return {
    claimCreator: mockClaimCreator,
    patientCreator: mockPatientCreator,
    recentPatientsQuery: mockRecentPatientsQuery,
    auditRepo: mockAuditRepo,
  };
}

function createMockSummaryDeps(): MobileSummaryServiceDeps {
  return {
    claimCounter: {
      countTodayClaims: vi.fn(async () => 0),
      countPendingQueue: vi.fn(async () => 0),
    },
    unreadCounter: {
      countUnread: vi.fn(async () => 0),
    },
    activeShiftLookup: {
      getActive: vi.fn(async () => null),
    },
    auditRepo: {
      appendAuditLog: vi.fn(async () => ({})),
    },
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let quickClaimDeps: QuickClaimServiceDeps;

async function buildTestApp(): Promise<FastifyInstance> {
  quickClaimDeps = createMockQuickClaimDeps();
  const summaryDeps = createMockSummaryDeps();

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

  await testApp.register(mobileRoutes, {
    deps: {
      quickClaimServiceDeps: quickClaimDeps,
      summaryServiceDeps: summaryDeps,
    },
  });

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

function unauthedPost(url: string, body?: Record<string, unknown>) {
  return app.inject({
    method: 'POST',
    url,
    headers: { 'content-type': 'application/json' },
    payload: body ?? {},
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Mobile Quick Entry Integration Tests', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    vi.clearAllMocks();
  });

  // =========================================================================
  // Quick entry flow: create patient -> quick claim -> draft in desktop list
  // =========================================================================

  describe('Quick entry flow', () => {
    it('create minimal patient -> quick claim with patient -> draft claim created', async () => {
      const createdPatientId = crypto.randomUUID();
      mockPatientCreator.createMinimalPatient.mockResolvedValueOnce({
        patientId: createdPatientId,
        ...VALID_PATIENT,
      });

      // Step 1: Create minimal patient
      const patientRes = await authedPost('/api/v1/mobile/patients', VALID_PATIENT);
      expect(patientRes.statusCode).toBe(201);
      expect(patientRes.json().data.patientId).toBe(createdPatientId);

      // Step 2: Quick claim with the created patient
      const claimId = crypto.randomUUID();
      mockClaimCreator.createDraftClaim.mockResolvedValueOnce({ claimId });

      const claimRes = await authedPost('/api/v1/mobile/quick-claim', {
        patient_id: createdPatientId,
        health_service_code: '03.04A',
        date_of_service: '2026-01-15',
      });
      expect(claimRes.statusCode).toBe(201);
      expect(claimRes.json().data.claimId).toBe(claimId);

      // Verify claim was created with correct source and state
      expect(mockClaimCreator.createDraftClaim).toHaveBeenCalledWith(
        PHYSICIAN1_USER_ID,
        expect.objectContaining({
          patientId: createdPatientId,
          healthServiceCode: '03.04A',
          claimType: 'AHCIP',
          state: 'DRAFT',
          source: 'mobile_quick_entry',
        }),
      );
    });
  });

  // =========================================================================
  // Recent patients
  // =========================================================================

  describe('Recent patients', () => {
    it('returns patients ordered by recency', async () => {
      const recentPatients = [
        { patientId: PATIENT_ID_1, firstName: 'Alice', lastName: 'Smith', phn: '111111111' },
        { patientId: PATIENT_ID_2, firstName: 'Bob', lastName: 'Jones', phn: '222222222' },
        { patientId: PATIENT_ID_3, firstName: 'Carol', lastName: 'Lee', phn: '333333333' },
      ];
      mockRecentPatientsQuery.getRecentBilledPatients.mockResolvedValueOnce(recentPatients);

      const res = await authedGet('/api/v1/mobile/recent-patients');
      expect(res.statusCode).toBe(200);
      expect(res.json().data).toHaveLength(3);
      expect(res.json().data[0].patientId).toBe(PATIENT_ID_1);
      expect(res.json().data[2].patientId).toBe(PATIENT_ID_3);
    });

    it('respects limit parameter', async () => {
      mockRecentPatientsQuery.getRecentBilledPatients.mockResolvedValueOnce([
        { patientId: PATIENT_ID_1, firstName: 'Alice', lastName: 'Smith', phn: '111111111' },
      ]);

      const res = await authedGet('/api/v1/mobile/recent-patients?limit=1');
      expect(res.statusCode).toBe(200);
      expect(mockRecentPatientsQuery.getRecentBilledPatients).toHaveBeenCalledWith(
        PHYSICIAN1_USER_ID,
        1,
      );
    });
  });

  // =========================================================================
  // Quick entry AHCIP only
  // =========================================================================

  describe('Quick entry AHCIP only', () => {
    it('creates AHCIP claim with source mobile_quick_entry', async () => {
      const claimId = crypto.randomUUID();
      mockClaimCreator.createDraftClaim.mockResolvedValueOnce({ claimId });

      const res = await authedPost('/api/v1/mobile/quick-claim', VALID_QUICK_CLAIM);
      expect(res.statusCode).toBe(201);

      expect(mockClaimCreator.createDraftClaim).toHaveBeenCalledWith(
        PHYSICIAN1_USER_ID,
        expect.objectContaining({
          claimType: 'AHCIP',
          source: 'mobile_quick_entry',
        }),
      );
    });
  });

  // =========================================================================
  // Validation
  // =========================================================================

  describe('Validation', () => {
    it('rejects quick claim with missing patient_id', async () => {
      const res = await authedPost('/api/v1/mobile/quick-claim', {
        health_service_code: '03.04A',
        date_of_service: '2026-01-15',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects quick claim with non-UUID patient_id', async () => {
      const res = await authedPost('/api/v1/mobile/quick-claim', {
        ...VALID_QUICK_CLAIM,
        patient_id: 'not-a-uuid',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects quick claim with missing health_service_code', async () => {
      const res = await authedPost('/api/v1/mobile/quick-claim', {
        patient_id: PATIENT_ID_1,
        date_of_service: '2026-01-15',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects patient with missing required fields', async () => {
      const res = await authedPost('/api/v1/mobile/patients', {
        first_name: 'John',
        // missing last_name, phn, date_of_birth, gender
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects patient with invalid PHN format', async () => {
      const res = await authedPost('/api/v1/mobile/patients', {
        ...VALID_PATIENT,
        phn: '12345', // Not 9 digits
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects patient with invalid gender', async () => {
      const res = await authedPost('/api/v1/mobile/patients', {
        ...VALID_PATIENT,
        gender: 'INVALID',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects quick claim with future date_of_service', async () => {
      const futureDate = new Date();
      futureDate.setFullYear(futureDate.getFullYear() + 1);
      const futureDateStr = futureDate.toISOString().split('T')[0];

      const res = await authedPost('/api/v1/mobile/quick-claim', {
        ...VALID_QUICK_CLAIM,
        date_of_service: futureDateStr,
      });
      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // Sync endpoint returns 501
  // =========================================================================

  describe('Sync endpoint', () => {
    it('POST /sync/claims returns 501 Not Implemented', async () => {
      const res = await unauthedPost('/api/v1/sync/claims', {});
      expect(res.statusCode).toBe(501);
      expect(res.json().phase).toBe(2);
      expect(res.json().message).toContain('not available');
    });
  });
});
