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
import { shiftRoutes } from '../../../src/domains/mobile/routes/shift.routes.js';
import { favouriteRoutes } from '../../../src/domains/mobile/routes/favourite.routes.js';
import { mobileRoutes } from '../../../src/domains/mobile/routes/mobile.routes.js';
import type { EdShiftServiceDeps } from '../../../src/domains/mobile/services/ed-shift.service.js';
import type { FavouriteCodesServiceDeps } from '../../../src/domains/mobile/services/favourite-codes.service.js';
import type { QuickClaimServiceDeps } from '../../../src/domains/mobile/services/quick-claim.service.js';
import type { MobileSummaryServiceDeps } from '../../../src/domains/mobile/services/mobile-summary.service.js';
import { MobileShiftStatus } from '@meritum/shared/constants/mobile.constants.js';
import { resetAuditRateLimiter } from '../../../src/domains/mobile/services/mobile-summary.service.js';

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

const DELEGATE_USER_ID = '00000000-3333-0000-0000-000000000001';
const DELEGATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_SESSION_TOKEN_HASH = hashToken(DELEGATE_SESSION_TOKEN);

const DELEGATE_VIEW_ONLY_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_VIEW_ONLY_SESSION_TOKEN_HASH = hashToken(DELEGATE_VIEW_ONLY_SESSION_TOKEN);

// ---------------------------------------------------------------------------
// Test data
// ---------------------------------------------------------------------------

const LOCATION_ID = '00000000-aaaa-0000-0000-000000000001';
const SHIFT_ID_1 = '00000000-bbbb-0000-0000-000000000001';
const PATIENT_ID_1 = '00000000-cccc-0000-0000-000000000001';

function makeMockShift(overrides: Record<string, unknown> = {}) {
  return {
    shiftId: SHIFT_ID_1,
    providerId: PHYSICIAN1_USER_ID,
    locationId: LOCATION_ID,
    shiftStart: new Date().toISOString(),
    shiftEnd: null,
    patientCount: 0,
    estimatedValue: '0.00',
    status: MobileShiftStatus.ACTIVE,
    createdAt: new Date(),
    ...overrides,
  };
}

function makeMockFavourite(overrides: Record<string, unknown> = {}) {
  return {
    favouriteId: crypto.randomUUID(),
    providerId: PHYSICIAN1_USER_ID,
    healthServiceCode: '03.04A',
    displayName: null,
    sortOrder: 1,
    defaultModifiers: null,
    createdAt: new Date(),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Mock session repo — supports physician and delegate sessions
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
      // Delegate with CLAIM_VIEW + CLAIM_CREATE + PATIENT_VIEW + PATIENT_CREATE
      if (tokenHash === DELEGATE_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: '00000000-2222-0000-0000-000000000002',
            userId: DELEGATE_USER_ID,
            tokenHash: DELEGATE_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: DELEGATE_USER_ID,
            role: 'DELEGATE',
            subscriptionStatus: 'ACTIVE',
            delegateContext: {
              delegateUserId: DELEGATE_USER_ID,
              physicianProviderId: PHYSICIAN1_USER_ID,
              permissions: ['CLAIM_VIEW', 'CLAIM_CREATE', 'PATIENT_VIEW', 'PATIENT_CREATE'],
              linkageId: '00000000-4444-0000-0000-000000000001',
            },
          },
        };
      }
      // Delegate with CLAIM_VIEW only (no create permissions)
      if (tokenHash === DELEGATE_VIEW_ONLY_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: '00000000-2222-0000-0000-000000000003',
            userId: DELEGATE_USER_ID,
            tokenHash: DELEGATE_VIEW_ONLY_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: DELEGATE_USER_ID,
            role: 'DELEGATE',
            subscriptionStatus: 'ACTIVE',
            delegateContext: {
              delegateUserId: DELEGATE_USER_ID,
              physicianProviderId: PHYSICIAN1_USER_ID,
              permissions: ['CLAIM_VIEW'],
              linkageId: '00000000-4444-0000-0000-000000000002',
            },
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

let mockShiftRepo: any;
let mockFavRepo: any;
let mockClaimCreator: any;

function createMockShiftServiceDeps(): EdShiftServiceDeps {
  mockShiftRepo = {
    create: vi.fn(async () => makeMockShift()),
    getActive: vi.fn(async () => null as any),
    getById: vi.fn(async () => null as any),
    endShift: vi.fn(async () => makeMockShift({ status: MobileShiftStatus.ENDED })),
    markReviewed: vi.fn(async () => null as any),
    list: vi.fn(async () => ({ data: [], total: 0 })),
    incrementPatientCount: vi.fn(async () => makeMockShift({ patientCount: 1 })),
    getSummary: vi.fn(async () => ({ shift: makeMockShift(), claims: [] })),
  };

  return {
    repo: mockShiftRepo,
    locationCheck: { belongsToPhysician: vi.fn(async () => true) },
    claimCreator: { createClaimFromShift: vi.fn(async () => ({ claimId: crypto.randomUUID() })) },
    auditRepo: { appendAuditLog: vi.fn(async () => ({})) },
  };
}

function createMockFavServiceDeps(): FavouriteCodesServiceDeps {
  mockFavRepo = {
    create: vi.fn(async (data: any) => makeMockFavourite(data)),
    getById: vi.fn(async () => null as any),
    update: vi.fn(async () => makeMockFavourite()),
    delete: vi.fn(async () => true),
    listByProvider: vi.fn(async () => []),
    reorder: vi.fn(async () => {}),
    countByProvider: vi.fn(async () => 0),
    bulkCreate: vi.fn(async () => []),
  };

  return {
    repo: mockFavRepo,
    hscLookup: { findByCode: vi.fn(async (code: string) => ({ code, description: 'Test', baseFee: '50.00', feeType: 'FIXED' })) },
    modifierLookup: { isKnownModifier: vi.fn(async () => true) },
    claimHistory: { getTopBilledCodes: vi.fn(async () => []) },
    providerProfile: { getSpecialty: vi.fn(async () => 'GENERAL_PRACTICE') },
    specialtyDefaults: { getDefaultCodes: vi.fn(async () => []) },
    auditRepo: { appendAuditLog: vi.fn(async () => ({})) },
  };
}

function createMockQuickClaimDeps(): QuickClaimServiceDeps {
  mockClaimCreator = {
    createDraftClaim: vi.fn(async () => ({ claimId: crypto.randomUUID() })),
  };
  return {
    claimCreator: mockClaimCreator,
    patientCreator: { createMinimalPatient: vi.fn(async (_pid: string, data: any) => ({ patientId: crypto.randomUUID(), ...data })) },
    recentPatientsQuery: { getRecentBilledPatients: vi.fn(async () => []) },
    auditRepo: { appendAuditLog: vi.fn(async () => ({})) },
  };
}

function createMockSummaryDeps(): MobileSummaryServiceDeps {
  return {
    claimCounter: {
      countTodayClaims: vi.fn(async () => 3),
      countPendingQueue: vi.fn(async () => 1),
    },
    unreadCounter: { countUnread: vi.fn(async () => 0) },
    activeShiftLookup: { getActive: vi.fn(async () => null) },
    auditRepo: { appendAuditLog: vi.fn(async () => ({})) },
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;

async function buildTestApp(): Promise<FastifyInstance> {
  const shiftDeps = createMockShiftServiceDeps();
  const favDeps = createMockFavServiceDeps();
  const quickClaimDeps = createMockQuickClaimDeps();
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

  await testApp.register(shiftRoutes, { deps: { serviceDeps: shiftDeps } });
  await testApp.register(favouriteRoutes, { deps: { serviceDeps: favDeps } });
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

function delegateGet(url: string, token = DELEGATE_SESSION_TOKEN) {
  return app.inject({
    method: 'GET',
    url,
    headers: { cookie: `session=${token}` },
  });
}

function delegatePost(url: string, body?: Record<string, unknown>, token = DELEGATE_SESSION_TOKEN) {
  return app.inject({
    method: 'POST',
    url,
    headers: {
      cookie: `session=${token}`,
      'content-type': 'application/json',
    },
    payload: body ?? {},
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Mobile Delegate Access Integration Tests', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    vi.clearAllMocks();
    resetAuditRateLimiter();
  });

  // =========================================================================
  // Delegate with CLAIM_VIEW can view shifts, favourites, summary
  // =========================================================================

  describe('Delegate with CLAIM_VIEW can view resources', () => {
    it('delegate can view mobile summary', async () => {
      const res = await delegateGet('/api/v1/mobile/summary');
      expect(res.statusCode).toBe(200);
      expect(res.json().data).toHaveProperty('todayClaimsCount');
    });

    it('delegate can view favourites list', async () => {
      mockFavRepo.countByProvider.mockResolvedValueOnce(0);
      mockFavRepo.listByProvider.mockResolvedValueOnce([]);

      const res = await delegateGet('/api/v1/favourites');
      expect(res.statusCode).toBe(200);
    });
  });

  // =========================================================================
  // Delegate cannot start/end shifts (physician-only)
  // =========================================================================

  describe('Delegate cannot manage shifts', () => {
    it('delegate cannot start a shift (physician-only operation)', async () => {
      const res = await delegatePost('/api/v1/shifts', {
        location_id: LOCATION_ID,
      });
      expect(res.statusCode).toBe(403);
      expect(res.json().error.code).toBe('FORBIDDEN');
    });

    it('delegate cannot end a shift', async () => {
      const res = await delegatePost(`/api/v1/shifts/${SHIFT_ID_1}/end`);
      expect(res.statusCode).toBe(403);
    });

    it('delegate cannot log patients in a shift', async () => {
      const res = await delegatePost(`/api/v1/shifts/${SHIFT_ID_1}/patients`, {
        patient_id: PATIENT_ID_1,
        health_service_code: '03.04A',
      });
      expect(res.statusCode).toBe(403);
    });

    it('delegate cannot view active shift (shift routes require PHYSICIAN role)', async () => {
      const res = await delegateGet('/api/v1/shifts/active');
      expect(res.statusCode).toBe(403);
    });

    it('delegate cannot list shifts', async () => {
      const res = await delegateGet('/api/v1/shifts');
      expect(res.statusCode).toBe(403);
    });
  });

  // =========================================================================
  // Delegate with CLAIM_CREATE can create quick claims
  // =========================================================================

  describe('Delegate with CLAIM_CREATE can create quick claims', () => {
    it('delegate creates quick claim on behalf of physician', async () => {
      const claimId = crypto.randomUUID();
      mockClaimCreator.createDraftClaim.mockResolvedValueOnce({ claimId });

      const res = await delegatePost('/api/v1/mobile/quick-claim', {
        patient_id: PATIENT_ID_1,
        health_service_code: '03.04A',
        date_of_service: '2026-01-15',
      });
      expect(res.statusCode).toBe(201);
      expect(res.json().data.claimId).toBe(claimId);

      // Verify claim was created under the physician's provider ID (not delegate's)
      expect(mockClaimCreator.createDraftClaim).toHaveBeenCalledWith(
        PHYSICIAN1_USER_ID,
        expect.objectContaining({
          patientId: PATIENT_ID_1,
          claimType: 'AHCIP',
          source: 'mobile_quick_entry',
        }),
      );
    });
  });

  // =========================================================================
  // Delegate without CLAIM_CREATE cannot create quick claims
  // =========================================================================

  describe('Delegate without CLAIM_CREATE cannot create resources', () => {
    it('view-only delegate cannot create quick claim', async () => {
      const res = await delegatePost(
        '/api/v1/mobile/quick-claim',
        {
          patient_id: PATIENT_ID_1,
          health_service_code: '03.04A',
          date_of_service: '2026-01-15',
        },
        DELEGATE_VIEW_ONLY_SESSION_TOKEN,
      );
      expect(res.statusCode).toBe(403);
      expect(res.json().error.code).toBe('FORBIDDEN');
    });

    it('view-only delegate cannot add favourites', async () => {
      const res = await delegatePost(
        '/api/v1/favourites',
        {
          health_service_code: '03.04A',
          sort_order: 1,
        },
        DELEGATE_VIEW_ONLY_SESSION_TOKEN,
      );
      expect(res.statusCode).toBe(403);
    });
  });

  // =========================================================================
  // Delegate view-only can still view summary and favourites
  // =========================================================================

  describe('View-only delegate can view resources', () => {
    it('view-only delegate can view mobile summary', async () => {
      const res = await delegateGet(
        '/api/v1/mobile/summary',
        DELEGATE_VIEW_ONLY_SESSION_TOKEN,
      );
      expect(res.statusCode).toBe(200);
      expect(res.json().data).toHaveProperty('todayClaimsCount');
    });

    it('view-only delegate can view favourites', async () => {
      mockFavRepo.countByProvider.mockResolvedValueOnce(0);
      mockFavRepo.listByProvider.mockResolvedValueOnce([]);

      const res = await delegateGet(
        '/api/v1/favourites',
        DELEGATE_VIEW_ONLY_SESSION_TOKEN,
      );
      expect(res.statusCode).toBe(200);
    });
  });
});
