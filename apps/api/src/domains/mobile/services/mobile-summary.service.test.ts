import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  getSummary,
  resetAuditRateLimiter,
} from './mobile-summary.service.js';
import type {
  MobileSummaryServiceDeps,
  MobileSummary,
} from './mobile-summary.service.js';
import type { SelectEdShift } from '@meritum/shared/schemas/db/mobile.schema.js';

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const PROVIDER_A = crypto.randomUUID();
const PROVIDER_B = crypto.randomUUID();
const SHIFT_ID = crypto.randomUUID();
const LOCATION_ID = crypto.randomUUID();

// ---------------------------------------------------------------------------
// Mock factories
// ---------------------------------------------------------------------------

function makeActiveShift(overrides: Partial<SelectEdShift> = {}): SelectEdShift {
  return {
    shiftId: overrides.shiftId ?? SHIFT_ID,
    providerId: overrides.providerId ?? PROVIDER_A,
    locationId: overrides.locationId ?? LOCATION_ID,
    shiftStart: overrides.shiftStart ?? new Date('2026-02-19T08:00:00Z'),
    shiftEnd: overrides.shiftEnd ?? null,
    patientCount: overrides.patientCount ?? 3,
    estimatedValue: overrides.estimatedValue ?? '150.00',
    status: overrides.status ?? 'ACTIVE',
    createdAt: overrides.createdAt ?? new Date('2026-02-19T08:00:00Z'),
  };
}

function makeDeps(
  overrides: Partial<MobileSummaryServiceDeps> = {},
): MobileSummaryServiceDeps {
  return {
    claimCounter: {
      countTodayClaims: vi.fn().mockResolvedValue(5),
      countPendingQueue: vi.fn().mockResolvedValue(12),
    },
    unreadCounter: {
      countUnread: vi.fn().mockResolvedValue(3),
    },
    activeShiftLookup: {
      getActive: vi.fn().mockResolvedValue(makeActiveShift()),
    },
    auditRepo: {
      appendAuditLog: vi.fn().mockResolvedValue({}),
    },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('MobileSummaryService', () => {
  beforeEach(() => {
    // Reset the rate limiter before each test to ensure deterministic behavior
    resetAuditRateLimiter();
  });

  // =========================================================================
  // getSummary — correct counts
  // =========================================================================

  describe('getSummary', () => {
    it('returns correct counts with seeded data', async () => {
      const deps = makeDeps();

      const result = await getSummary(deps, PROVIDER_A);

      expect(result.todayClaimsCount).toBe(5);
      expect(result.pendingQueueCount).toBe(12);
      expect(result.unreadNotificationsCount).toBe(3);
    });

    it('returns active shift details when a shift is active', async () => {
      const deps = makeDeps();

      const result = await getSummary(deps, PROVIDER_A);

      expect(result.activeShift).not.toBeNull();
      expect(result.activeShift!.shiftId).toBe(SHIFT_ID);
      expect(result.activeShift!.shiftStart).toBe('2026-02-19T08:00:00.000Z');
      expect(result.activeShift!.patientCount).toBe(3);
      expect(result.activeShift!.estimatedValue).toBe('150.00');
    });

    it('returns null for active shift when no shift is active', async () => {
      const deps = makeDeps({
        activeShiftLookup: {
          getActive: vi.fn().mockResolvedValue(null),
        },
      });

      const result = await getSummary(deps, PROVIDER_A);

      expect(result.activeShift).toBeNull();
    });

    it('returns zero counts when no data exists', async () => {
      const deps = makeDeps({
        claimCounter: {
          countTodayClaims: vi.fn().mockResolvedValue(0),
          countPendingQueue: vi.fn().mockResolvedValue(0),
        },
        unreadCounter: {
          countUnread: vi.fn().mockResolvedValue(0),
        },
        activeShiftLookup: {
          getActive: vi.fn().mockResolvedValue(null),
        },
      });

      const result = await getSummary(deps, PROVIDER_A);

      expect(result.todayClaimsCount).toBe(0);
      expect(result.pendingQueueCount).toBe(0);
      expect(result.unreadNotificationsCount).toBe(0);
      expect(result.activeShift).toBeNull();
    });

    it('contains no PHI — only counts and shift metadata', async () => {
      const deps = makeDeps();

      const result = await getSummary(deps, PROVIDER_A);

      // Verify the shape only contains expected keys (no patient data, no PHN)
      const keys = Object.keys(result);
      expect(keys).toEqual([
        'todayClaimsCount',
        'pendingQueueCount',
        'unreadNotificationsCount',
        'activeShift',
      ]);

      // If active shift is present, verify it has no patient data
      if (result.activeShift) {
        const shiftKeys = Object.keys(result.activeShift);
        expect(shiftKeys).toEqual([
          'shiftId',
          'shiftStart',
          'patientCount',
          'estimatedValue',
        ]);
      }
    });
  });

  // =========================================================================
  // getSummary — physician scoping
  // =========================================================================

  describe('physician scoping', () => {
    it('passes the correct providerId to all dependency calls', async () => {
      const deps = makeDeps();

      await getSummary(deps, PROVIDER_A);

      expect(deps.claimCounter.countTodayClaims).toHaveBeenCalledWith(
        PROVIDER_A,
        expect.any(Date),
      );
      expect(deps.claimCounter.countPendingQueue).toHaveBeenCalledWith(
        PROVIDER_A,
      );
      expect(deps.unreadCounter.countUnread).toHaveBeenCalledWith(PROVIDER_A);
      expect(deps.activeShiftLookup.getActive).toHaveBeenCalledWith(
        PROVIDER_A,
      );
    });

    it('uses different providerId for different physicians', async () => {
      const deps = makeDeps();

      await getSummary(deps, PROVIDER_B);

      expect(deps.claimCounter.countTodayClaims).toHaveBeenCalledWith(
        PROVIDER_B,
        expect.any(Date),
      );
      expect(deps.claimCounter.countPendingQueue).toHaveBeenCalledWith(
        PROVIDER_B,
      );
      expect(deps.unreadCounter.countUnread).toHaveBeenCalledWith(PROVIDER_B);
      expect(deps.activeShiftLookup.getActive).toHaveBeenCalledWith(
        PROVIDER_B,
      );
    });
  });

  // =========================================================================
  // getSummary — parallel execution
  // =========================================================================

  describe('parallel execution', () => {
    it('runs all queries in parallel (not sequentially)', async () => {
      const callOrder: string[] = [];

      const deps = makeDeps({
        claimCounter: {
          countTodayClaims: vi.fn().mockImplementation(async () => {
            callOrder.push('todayClaims:start');
            await new Promise((r) => setTimeout(r, 10));
            callOrder.push('todayClaims:end');
            return 5;
          }),
          countPendingQueue: vi.fn().mockImplementation(async () => {
            callOrder.push('pendingQueue:start');
            await new Promise((r) => setTimeout(r, 10));
            callOrder.push('pendingQueue:end');
            return 12;
          }),
        },
        unreadCounter: {
          countUnread: vi.fn().mockImplementation(async () => {
            callOrder.push('unread:start');
            await new Promise((r) => setTimeout(r, 10));
            callOrder.push('unread:end');
            return 3;
          }),
        },
        activeShiftLookup: {
          getActive: vi.fn().mockImplementation(async () => {
            callOrder.push('activeShift:start');
            await new Promise((r) => setTimeout(r, 10));
            callOrder.push('activeShift:end');
            return null;
          }),
        },
      });

      await getSummary(deps, PROVIDER_A);

      // All starts should come before all ends (parallel execution)
      const startIndices = callOrder
        .map((entry, idx) => (entry.endsWith(':start') ? idx : -1))
        .filter((i) => i >= 0);
      const endIndices = callOrder
        .map((entry, idx) => (entry.endsWith(':end') ? idx : -1))
        .filter((i) => i >= 0);

      // All 4 operations should have started
      expect(startIndices).toHaveLength(4);
      expect(endIndices).toHaveLength(4);

      // In parallel execution, all starts happen before the first end
      const maxStartIdx = Math.max(...startIndices);
      const minEndIdx = Math.min(...endIndices);
      expect(maxStartIdx).toBeLessThan(minEndIdx);
    });
  });

  // =========================================================================
  // getSummary — today_start calculation
  // =========================================================================

  describe('today start calculation', () => {
    it('passes a Date representing start of today (UTC midnight) to countTodayClaims', async () => {
      const deps = makeDeps();

      await getSummary(deps, PROVIDER_A);

      const todayStartArg = (
        deps.claimCounter.countTodayClaims as ReturnType<typeof vi.fn>
      ).mock.calls[0][1] as Date;

      expect(todayStartArg).toBeInstanceOf(Date);
      expect(todayStartArg.getUTCHours()).toBe(0);
      expect(todayStartArg.getUTCMinutes()).toBe(0);
      expect(todayStartArg.getUTCSeconds()).toBe(0);
      expect(todayStartArg.getUTCMilliseconds()).toBe(0);
    });
  });

  // =========================================================================
  // getSummary — audit logging
  // =========================================================================

  describe('audit logging', () => {
    it('logs audit event on first summary view', async () => {
      const deps = makeDeps();

      await getSummary(deps, PROVIDER_A);

      expect(deps.auditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: PROVIDER_A,
          action: 'mobile.summary_viewed',
          category: 'mobile',
          resourceType: 'mobile_summary',
          detail: expect.objectContaining({
            todayClaimsCount: 5,
            pendingQueueCount: 12,
            unreadNotificationsCount: 3,
            hasActiveShift: true,
          }),
        }),
      );
    });

    it('rate-limits audit to max 1 per 10 minutes per physician', async () => {
      const deps = makeDeps();

      // First call — should log
      await getSummary(deps, PROVIDER_A);
      expect(deps.auditRepo.appendAuditLog).toHaveBeenCalledTimes(1);

      // Second call immediately — should NOT log again
      await getSummary(deps, PROVIDER_A);
      expect(deps.auditRepo.appendAuditLog).toHaveBeenCalledTimes(1);

      // Third call immediately — still should NOT log
      await getSummary(deps, PROVIDER_A);
      expect(deps.auditRepo.appendAuditLog).toHaveBeenCalledTimes(1);
    });

    it('rate-limits per physician independently', async () => {
      const deps = makeDeps();

      // First call for provider A — should log
      await getSummary(deps, PROVIDER_A);
      expect(deps.auditRepo.appendAuditLog).toHaveBeenCalledTimes(1);

      // First call for provider B — should ALSO log (different physician)
      await getSummary(deps, PROVIDER_B);
      expect(deps.auditRepo.appendAuditLog).toHaveBeenCalledTimes(2);
    });

    it('does not include hasActiveShift: true when no shift exists', async () => {
      const deps = makeDeps({
        activeShiftLookup: {
          getActive: vi.fn().mockResolvedValue(null),
        },
      });

      await getSummary(deps, PROVIDER_A);

      expect(deps.auditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          detail: expect.objectContaining({
            hasActiveShift: false,
          }),
        }),
      );
    });
  });

  // =========================================================================
  // getSummary — performance
  // =========================================================================

  describe('performance', () => {
    it('completes within 100ms with fast mocked dependencies', async () => {
      const deps = makeDeps();

      const start = performance.now();
      await getSummary(deps, PROVIDER_A);
      const elapsed = performance.now() - start;

      // With mocked dependencies, the service function itself should complete
      // well under 100ms. Real DB performance is validated in integration tests.
      expect(elapsed).toBeLessThan(100);
    });

    it('completes within 100ms even with 10ms simulated DB latency', async () => {
      const deps = makeDeps({
        claimCounter: {
          countTodayClaims: vi.fn().mockImplementation(
            () => new Promise((r) => setTimeout(() => r(5), 10)),
          ),
          countPendingQueue: vi.fn().mockImplementation(
            () => new Promise((r) => setTimeout(() => r(12), 10)),
          ),
        },
        unreadCounter: {
          countUnread: vi.fn().mockImplementation(
            () => new Promise((r) => setTimeout(() => r(3), 10)),
          ),
        },
        activeShiftLookup: {
          getActive: vi.fn().mockImplementation(
            () => new Promise((r) => setTimeout(() => r(null), 10)),
          ),
        },
      });

      const start = performance.now();
      await getSummary(deps, PROVIDER_A);
      const elapsed = performance.now() - start;

      // Parallel execution: ~10ms wall time for 4 x 10ms queries
      // Allow generous margin for test overhead
      expect(elapsed).toBeLessThan(100);
    });
  });

  // =========================================================================
  // getSummary — error propagation
  // =========================================================================

  describe('error propagation', () => {
    it('propagates error from claimCounter.countTodayClaims', async () => {
      const deps = makeDeps({
        claimCounter: {
          countTodayClaims: vi.fn().mockRejectedValue(new Error('DB timeout')),
          countPendingQueue: vi.fn().mockResolvedValue(12),
        },
      });

      await expect(getSummary(deps, PROVIDER_A)).rejects.toThrow('DB timeout');
    });

    it('propagates error from unreadCounter.countUnread', async () => {
      const deps = makeDeps({
        unreadCounter: {
          countUnread: vi.fn().mockRejectedValue(new Error('Notification service down')),
        },
      });

      await expect(getSummary(deps, PROVIDER_A)).rejects.toThrow(
        'Notification service down',
      );
    });

    it('propagates error from activeShiftLookup.getActive', async () => {
      const deps = makeDeps({
        activeShiftLookup: {
          getActive: vi.fn().mockRejectedValue(new Error('Shift query failed')),
        },
      });

      await expect(getSummary(deps, PROVIDER_A)).rejects.toThrow(
        'Shift query failed',
      );
    });
  });

  // =========================================================================
  // getSummary — return shape
  // =========================================================================

  describe('return shape', () => {
    it('returns the expected MobileSummary interface shape', async () => {
      const deps = makeDeps();

      const result: MobileSummary = await getSummary(deps, PROVIDER_A);

      expect(typeof result.todayClaimsCount).toBe('number');
      expect(typeof result.pendingQueueCount).toBe('number');
      expect(typeof result.unreadNotificationsCount).toBe('number');
      expect(result.activeShift === null || typeof result.activeShift === 'object').toBe(true);
    });

    it('active shift shiftStart is ISO 8601 string', async () => {
      const deps = makeDeps();

      const result = await getSummary(deps, PROVIDER_A);

      expect(result.activeShift).not.toBeNull();
      // Validate ISO 8601 format
      const parsed = new Date(result.activeShift!.shiftStart);
      expect(parsed.toISOString()).toBe(result.activeShift!.shiftStart);
    });

    it('active shift estimatedValue is string with decimal format', async () => {
      const deps = makeDeps();

      const result = await getSummary(deps, PROVIDER_A);

      expect(result.activeShift).not.toBeNull();
      expect(typeof result.activeShift!.estimatedValue).toBe('string');
      expect(result.activeShift!.estimatedValue).toBe('150.00');
    });
  });
});
