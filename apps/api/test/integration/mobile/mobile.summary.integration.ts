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

// ---------------------------------------------------------------------------
// Test data
// ---------------------------------------------------------------------------

const SHIFT_ID_1 = '00000000-bbbb-0000-0000-000000000001';
const LOCATION_ID = '00000000-aaaa-0000-0000-000000000001';

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

let mockClaimCounter: any;
let mockUnreadCounter: any;
let mockActiveShiftLookup: any;
let mockSummaryAuditRepo: any;

function createMockSummaryDeps(): MobileSummaryServiceDeps {
  mockClaimCounter = {
    countTodayClaims: vi.fn(async () => 5),
    countPendingQueue: vi.fn(async () => 3),
  };

  mockUnreadCounter = {
    countUnread: vi.fn(async () => 2),
  };

  mockActiveShiftLookup = {
    getActive: vi.fn(async () => null as any),
  };

  mockSummaryAuditRepo = {
    appendAuditLog: vi.fn(async () => ({})),
  };

  return {
    claimCounter: mockClaimCounter,
    unreadCounter: mockUnreadCounter,
    activeShiftLookup: mockActiveShiftLookup,
    auditRepo: mockSummaryAuditRepo,
  };
}

function createMockQuickClaimDeps(): QuickClaimServiceDeps {
  return {
    claimCreator: { createDraftClaim: vi.fn(async () => ({ claimId: crypto.randomUUID() })) },
    patientCreator: { createMinimalPatient: vi.fn(async () => ({})) },
    recentPatientsQuery: { getRecentBilledPatients: vi.fn(async () => []) },
    auditRepo: { appendAuditLog: vi.fn(async () => ({})) },
  } as any;
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let summaryDeps: MobileSummaryServiceDeps;

async function buildTestApp(): Promise<FastifyInstance> {
  summaryDeps = createMockSummaryDeps();
  const quickClaimDeps = createMockQuickClaimDeps();

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

function unauthedGet(url: string) {
  return app.inject({ method: 'GET', url });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Mobile Summary Integration Tests', () => {
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
  // Summary with active shift
  // =========================================================================

  describe('Summary with active shift and claims', () => {
    it('returns correct counts for all KPIs', async () => {
      mockClaimCounter.countTodayClaims.mockResolvedValueOnce(7);
      mockClaimCounter.countPendingQueue.mockResolvedValueOnce(4);
      mockUnreadCounter.countUnread.mockResolvedValueOnce(3);
      mockActiveShiftLookup.getActive.mockResolvedValueOnce({
        shiftId: SHIFT_ID_1,
        providerId: PHYSICIAN1_USER_ID,
        locationId: LOCATION_ID,
        shiftStart: new Date('2026-01-15T08:00:00Z'),
        shiftEnd: null,
        patientCount: 5,
        estimatedValue: '250.00',
        status: MobileShiftStatus.ACTIVE,
        createdAt: new Date(),
      });

      const res = await authedGet('/api/v1/mobile/summary');
      expect(res.statusCode).toBe(200);

      const data = res.json().data;
      expect(data.todayClaimsCount).toBe(7);
      expect(data.pendingQueueCount).toBe(4);
      expect(data.unreadNotificationsCount).toBe(3);
      expect(data.activeShift).not.toBeNull();
      expect(data.activeShift.shiftId).toBe(SHIFT_ID_1);
      expect(data.activeShift.patientCount).toBe(5);
      expect(data.activeShift.estimatedValue).toBe('250.00');
    });
  });

  // =========================================================================
  // Summary without active shift
  // =========================================================================

  describe('Summary without active shift', () => {
    it('returns null for activeShift when no shift is active', async () => {
      mockClaimCounter.countTodayClaims.mockResolvedValueOnce(2);
      mockClaimCounter.countPendingQueue.mockResolvedValueOnce(0);
      mockUnreadCounter.countUnread.mockResolvedValueOnce(0);
      mockActiveShiftLookup.getActive.mockResolvedValueOnce(null);

      const res = await authedGet('/api/v1/mobile/summary');
      expect(res.statusCode).toBe(200);

      const data = res.json().data;
      expect(data.todayClaimsCount).toBe(2);
      expect(data.pendingQueueCount).toBe(0);
      expect(data.unreadNotificationsCount).toBe(0);
      expect(data.activeShift).toBeNull();
    });
  });

  // =========================================================================
  // Summary with zero counts
  // =========================================================================

  describe('Summary with zero counts', () => {
    it('returns all zeros for new physician', async () => {
      mockClaimCounter.countTodayClaims.mockResolvedValueOnce(0);
      mockClaimCounter.countPendingQueue.mockResolvedValueOnce(0);
      mockUnreadCounter.countUnread.mockResolvedValueOnce(0);
      mockActiveShiftLookup.getActive.mockResolvedValueOnce(null);

      const res = await authedGet('/api/v1/mobile/summary');
      expect(res.statusCode).toBe(200);

      const data = res.json().data;
      expect(data.todayClaimsCount).toBe(0);
      expect(data.pendingQueueCount).toBe(0);
      expect(data.unreadNotificationsCount).toBe(0);
      expect(data.activeShift).toBeNull();
    });
  });

  // =========================================================================
  // Summary requires authentication
  // =========================================================================

  describe('Summary authentication', () => {
    it('GET /mobile/summary returns 401 without session', async () => {
      const res = await unauthedGet('/api/v1/mobile/summary');
      expect(res.statusCode).toBe(401);
      expect(res.json().data).toBeUndefined();
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
    });

    it('GET /sync/claims returns 404 (no GET handler)', async () => {
      const res = await unauthedGet('/api/v1/sync/claims');
      expect(res.statusCode).toBe(404);
    });
  });
});
