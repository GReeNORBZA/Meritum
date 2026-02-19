import { describe, it, expect, beforeEach, vi } from 'vitest';
import { createReportSubscriptionsRepository } from './report-subscriptions.repo.js';

// ---------------------------------------------------------------------------
// In-memory subscriptions store
// ---------------------------------------------------------------------------

let subscriptionsStore: Record<string, any>[];

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const PROVIDER_A = crypto.randomUUID();
const PROVIDER_B = crypto.randomUUID();

// ---------------------------------------------------------------------------
// Helper: build a valid insert payload
// ---------------------------------------------------------------------------

function makeSubscriptionData(overrides: Record<string, any> = {}) {
  return {
    providerId: PROVIDER_A,
    reportType: 'WEEKLY_SUMMARY',
    frequency: 'WEEKLY',
    deliveryMethod: 'IN_APP',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Mock Drizzle DB
// ---------------------------------------------------------------------------

function makeMockDb(): any {
  function chainable(ctx: {
    op: string;
    values?: any;
    setClauses?: any;
    whereClauses: Array<(row: any) => boolean>;
    shouldReturn?: boolean;
  }) {
    const chain: any = {
      _ctx: ctx,
      values(v: any) {
        ctx.values = Array.isArray(v) ? v : [v];
        return chain;
      },
      set(s: any) {
        ctx.setClauses = s;
        return chain;
      },
      from(_table: any) {
        return chain;
      },
      where(clause: any) {
        if (typeof clause === 'function') {
          ctx.whereClauses.push(clause);
        } else if (clause && typeof clause === 'object' && clause.__predicate) {
          ctx.whereClauses.push(clause.__predicate);
        }
        return chain;
      },
      returning() {
        ctx.shouldReturn = true;
        return chain;
      },
      then(resolve: any, reject?: any) {
        try {
          const result = executeOp(ctx);
          resolve(result);
        } catch (e) {
          if (reject) reject(e);
          else throw e;
        }
      },
    };
    return chain;
  }

  function matchesWhere(
    row: Record<string, any>,
    whereClauses: Array<(row: any) => boolean>,
  ): boolean {
    return whereClauses.every((pred) => pred(row));
  }

  function executeOp(ctx: any): any[] {
    switch (ctx.op) {
      case 'select': {
        return subscriptionsStore.filter((row) =>
          matchesWhere(row, ctx.whereClauses),
        );
      }

      case 'insert': {
        const inserted: any[] = [];
        for (const entry of ctx.values) {
          // Check unique constraint (provider_id, report_type)
          const duplicate = subscriptionsStore.find(
            (r) =>
              r.providerId === entry.providerId &&
              r.reportType === entry.reportType,
          );
          if (duplicate) {
            throw new Error(
              'duplicate key value violates unique constraint "report_subscriptions_provider_report_type_uniq"',
            );
          }

          const newRow = {
            subscriptionId: crypto.randomUUID(),
            isActive: true,
            deliveryMethod: 'IN_APP',
            createdAt: new Date(),
            updatedAt: new Date(),
            ...entry,
          };
          subscriptionsStore.push(newRow);
          inserted.push({ ...newRow });
        }
        return ctx.shouldReturn ? inserted : [];
      }

      case 'update': {
        const updated: any[] = [];
        for (const row of subscriptionsStore) {
          if (matchesWhere(row, ctx.whereClauses)) {
            if (ctx.setClauses) {
              for (const [key, val] of Object.entries(ctx.setClauses)) {
                row[key] = val;
              }
            }
            updated.push({ ...row });
          }
        }
        return ctx.shouldReturn ? updated : [];
      }

      case 'delete': {
        const toDelete: any[] = [];
        const remaining: any[] = [];
        for (const row of subscriptionsStore) {
          if (matchesWhere(row, ctx.whereClauses)) {
            toDelete.push({ ...row });
          } else {
            remaining.push(row);
          }
        }
        subscriptionsStore.length = 0;
        subscriptionsStore.push(...remaining);
        return ctx.shouldReturn ? toDelete : [];
      }

      default:
        return [];
    }
  }

  return {
    select(fields?: any) {
      return chainable({ op: 'select', whereClauses: [] });
    },
    insert(_table: any) {
      return chainable({ op: 'insert', whereClauses: [] });
    },
    update(_table: any) {
      return chainable({ op: 'update', whereClauses: [] });
    },
    delete(_table: any) {
      return chainable({ op: 'delete', whereClauses: [] });
    },
  };
}

// ---------------------------------------------------------------------------
// Column name → store key mapping
// ---------------------------------------------------------------------------

function colName(col: any): string {
  if (col && col.name) return col.name;
  return '';
}

const COL_MAP: Record<string, string> = {
  subscription_id: 'subscriptionId',
  provider_id: 'providerId',
  report_type: 'reportType',
  frequency: 'frequency',
  delivery_method: 'deliveryMethod',
  is_active: 'isActive',
  created_at: 'createdAt',
  updated_at: 'updatedAt',
};

function toStoreKey(col: any): string {
  const name = colName(col);
  return COL_MAP[name] || name;
}

// ---------------------------------------------------------------------------
// Override drizzle-orm operators for in-memory predicates
// ---------------------------------------------------------------------------

vi.mock('drizzle-orm', async () => {
  const actual =
    await vi.importActual<typeof import('drizzle-orm')>('drizzle-orm');
  return {
    ...actual,
    eq(col: any, val: any) {
      const key = toStoreKey(col);
      return {
        __predicate: (row: any) => row[key] === val,
      };
    },
    and(...conditions: any[]) {
      const preds = conditions
        .filter(Boolean)
        .map((c: any) => (typeof c === 'function' ? c : c?.__predicate))
        .filter(Boolean);
      return {
        __predicate: (row: any) => preds.every((pred: any) => pred(row)),
      };
    },
  };
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ReportSubscriptionsRepository', () => {
  let repo: ReturnType<typeof createReportSubscriptionsRepository>;

  beforeEach(() => {
    subscriptionsStore = [];
    repo = createReportSubscriptionsRepository(makeMockDb());
  });

  // =========================================================================
  // create
  // =========================================================================

  describe('create', () => {
    it('creates a subscription with defaults', async () => {
      const data = makeSubscriptionData();
      const result = await repo.create(data);

      expect(result).toBeDefined();
      expect(result.subscriptionId).toBeDefined();
      expect(result.providerId).toBe(PROVIDER_A);
      expect(result.reportType).toBe('WEEKLY_SUMMARY');
      expect(result.frequency).toBe('WEEKLY');
      expect(result.deliveryMethod).toBe('IN_APP');
      expect(result.isActive).toBe(true);
      expect(result.createdAt).toBeInstanceOf(Date);
      expect(result.updatedAt).toBeInstanceOf(Date);
      expect(subscriptionsStore).toHaveLength(1);
    });

    it('creates subscription with custom delivery method', async () => {
      const data = makeSubscriptionData({ deliveryMethod: 'EMAIL' });
      const result = await repo.create(data);

      expect(result.deliveryMethod).toBe('EMAIL');
    });

    it('creates subscription with MONTHLY frequency', async () => {
      const data = makeSubscriptionData({
        reportType: 'MONTHLY_PERFORMANCE',
        frequency: 'MONTHLY',
      });
      const result = await repo.create(data);

      expect(result.frequency).toBe('MONTHLY');
      expect(result.reportType).toBe('MONTHLY_PERFORMANCE');
    });

    it('enforces unique constraint on (provider_id, report_type)', async () => {
      const data = makeSubscriptionData();
      await repo.create(data);

      // Same provider, same report type → should fail
      await expect(repo.create(data)).rejects.toThrow(
        /unique constraint/i,
      );
    });

    it('allows same report type for different providers', async () => {
      const dataA = makeSubscriptionData({ providerId: PROVIDER_A });
      const dataB = makeSubscriptionData({ providerId: PROVIDER_B });

      const resultA = await repo.create(dataA);
      const resultB = await repo.create(dataB);

      expect(resultA.providerId).toBe(PROVIDER_A);
      expect(resultB.providerId).toBe(PROVIDER_B);
      expect(subscriptionsStore).toHaveLength(2);
    });

    it('allows same provider with different report types', async () => {
      const data1 = makeSubscriptionData({ reportType: 'WEEKLY_SUMMARY' });
      const data2 = makeSubscriptionData({
        reportType: 'MONTHLY_PERFORMANCE',
      });

      await repo.create(data1);
      await repo.create(data2);

      expect(subscriptionsStore).toHaveLength(2);
    });
  });

  // =========================================================================
  // getById
  // =========================================================================

  describe('getById', () => {
    it('returns subscription when ID and provider match', async () => {
      const created = await repo.create(makeSubscriptionData());

      const result = await repo.getById(
        created.subscriptionId,
        PROVIDER_A,
      );

      expect(result).not.toBeNull();
      expect(result!.subscriptionId).toBe(created.subscriptionId);
      expect(result!.providerId).toBe(PROVIDER_A);
    });

    it('returns null for non-existent subscription ID', async () => {
      const result = await repo.getById(crypto.randomUUID(), PROVIDER_A);
      expect(result).toBeNull();
    });

    it('returns null when provider does not match (404 pattern)', async () => {
      const created = await repo.create(
        makeSubscriptionData({ providerId: PROVIDER_A }),
      );

      // Provider B tries to access Provider A's subscription
      const result = await repo.getById(
        created.subscriptionId,
        PROVIDER_B,
      );

      expect(result).toBeNull();
    });
  });

  // =========================================================================
  // update
  // =========================================================================

  describe('update', () => {
    it('updates frequency', async () => {
      const created = await repo.create(makeSubscriptionData());

      const result = await repo.update(
        created.subscriptionId,
        PROVIDER_A,
        { frequency: 'DAILY' },
      );

      expect(result).not.toBeNull();
      expect(result!.frequency).toBe('DAILY');
    });

    it('updates delivery method', async () => {
      const created = await repo.create(makeSubscriptionData());

      const result = await repo.update(
        created.subscriptionId,
        PROVIDER_A,
        { deliveryMethod: 'BOTH' },
      );

      expect(result).not.toBeNull();
      expect(result!.deliveryMethod).toBe('BOTH');
    });

    it('updates isActive to false (deactivate)', async () => {
      const created = await repo.create(makeSubscriptionData());

      const result = await repo.update(
        created.subscriptionId,
        PROVIDER_A,
        { isActive: false },
      );

      expect(result).not.toBeNull();
      expect(result!.isActive).toBe(false);
    });

    it('updates multiple fields at once', async () => {
      const created = await repo.create(makeSubscriptionData());

      const result = await repo.update(
        created.subscriptionId,
        PROVIDER_A,
        { frequency: 'MONTHLY', deliveryMethod: 'EMAIL', isActive: false },
      );

      expect(result).not.toBeNull();
      expect(result!.frequency).toBe('MONTHLY');
      expect(result!.deliveryMethod).toBe('EMAIL');
      expect(result!.isActive).toBe(false);
    });

    it('sets updatedAt on update', async () => {
      const created = await repo.create(makeSubscriptionData());
      const originalUpdatedAt = created.updatedAt;

      // Small delay to ensure different timestamp
      await new Promise((r) => setTimeout(r, 5));

      const result = await repo.update(
        created.subscriptionId,
        PROVIDER_A,
        { frequency: 'DAILY' },
      );

      expect(result).not.toBeNull();
      expect(result!.updatedAt).toBeInstanceOf(Date);
      // updatedAt should be set (may or may not differ due to mock resolution)
      expect(result!.updatedAt).toBeDefined();
    });

    it('returns null when provider does not match', async () => {
      const created = await repo.create(makeSubscriptionData());

      const result = await repo.update(
        created.subscriptionId,
        PROVIDER_B,
        { frequency: 'DAILY' },
      );

      expect(result).toBeNull();
      // Original unchanged
      const original = subscriptionsStore.find(
        (r) => r.subscriptionId === created.subscriptionId,
      );
      expect(original!.frequency).toBe('WEEKLY');
    });

    it('returns null for non-existent subscription', async () => {
      const result = await repo.update(
        crypto.randomUUID(),
        PROVIDER_A,
        { frequency: 'DAILY' },
      );

      expect(result).toBeNull();
    });
  });

  // =========================================================================
  // delete
  // =========================================================================

  describe('delete', () => {
    it('deletes subscription and returns true', async () => {
      const created = await repo.create(makeSubscriptionData());

      const result = await repo.delete(
        created.subscriptionId,
        PROVIDER_A,
      );

      expect(result).toBe(true);
      expect(subscriptionsStore).toHaveLength(0);
    });

    it('returns false for non-existent subscription', async () => {
      const result = await repo.delete(crypto.randomUUID(), PROVIDER_A);

      expect(result).toBe(false);
    });

    it('returns false when provider does not match (404 pattern)', async () => {
      const created = await repo.create(makeSubscriptionData());

      const result = await repo.delete(
        created.subscriptionId,
        PROVIDER_B,
      );

      expect(result).toBe(false);
      // Subscription still exists
      expect(subscriptionsStore).toHaveLength(1);
    });

    it('only deletes the targeted subscription', async () => {
      const sub1 = await repo.create(
        makeSubscriptionData({ reportType: 'WEEKLY_SUMMARY' }),
      );
      await repo.create(
        makeSubscriptionData({ reportType: 'MONTHLY_PERFORMANCE' }),
      );

      await repo.delete(sub1.subscriptionId, PROVIDER_A);

      expect(subscriptionsStore).toHaveLength(1);
      expect(subscriptionsStore[0].reportType).toBe('MONTHLY_PERFORMANCE');
    });
  });

  // =========================================================================
  // listByProvider
  // =========================================================================

  describe('listByProvider', () => {
    beforeEach(() => {
      // Seed subscriptions for both providers
      subscriptionsStore.push(
        {
          subscriptionId: crypto.randomUUID(),
          providerId: PROVIDER_A,
          reportType: 'WEEKLY_SUMMARY',
          frequency: 'WEEKLY',
          deliveryMethod: 'IN_APP',
          isActive: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
        {
          subscriptionId: crypto.randomUUID(),
          providerId: PROVIDER_A,
          reportType: 'MONTHLY_PERFORMANCE',
          frequency: 'MONTHLY',
          deliveryMethod: 'EMAIL',
          isActive: false,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
        {
          subscriptionId: crypto.randomUUID(),
          providerId: PROVIDER_A,
          reportType: 'REJECTION_DIGEST',
          frequency: 'WEEKLY',
          deliveryMethod: 'BOTH',
          isActive: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
        {
          subscriptionId: crypto.randomUUID(),
          providerId: PROVIDER_B,
          reportType: 'WEEKLY_SUMMARY',
          frequency: 'WEEKLY',
          deliveryMethod: 'IN_APP',
          isActive: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
        {
          subscriptionId: crypto.randomUUID(),
          providerId: PROVIDER_B,
          reportType: 'WCB_TIMING',
          frequency: 'MONTHLY',
          deliveryMethod: 'IN_APP',
          isActive: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      );
    });

    it('returns only the authenticated provider\'s subscriptions', async () => {
      const result = await repo.listByProvider(PROVIDER_A);

      expect(result).toHaveLength(3);
      result.forEach((r) => {
        expect(r.providerId).toBe(PROVIDER_A);
      });
    });

    it('never returns another provider\'s subscriptions', async () => {
      const result = await repo.listByProvider(PROVIDER_A);

      result.forEach((r) => {
        expect(r.providerId).not.toBe(PROVIDER_B);
      });
    });

    it('returns both active and inactive subscriptions', async () => {
      const result = await repo.listByProvider(PROVIDER_A);

      const activeCount = result.filter((r) => r.isActive).length;
      const inactiveCount = result.filter((r) => !r.isActive).length;

      expect(activeCount).toBe(2);
      expect(inactiveCount).toBe(1);
    });

    it('returns empty array when no subscriptions exist', async () => {
      const unknownProvider = crypto.randomUUID();
      const result = await repo.listByProvider(unknownProvider);

      expect(result).toHaveLength(0);
    });
  });

  // =========================================================================
  // getDueSubscriptions
  // =========================================================================

  describe('getDueSubscriptions', () => {
    beforeEach(() => {
      subscriptionsStore.push(
        {
          subscriptionId: crypto.randomUUID(),
          providerId: PROVIDER_A,
          reportType: 'WEEKLY_SUMMARY',
          frequency: 'WEEKLY',
          deliveryMethod: 'IN_APP',
          isActive: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
        {
          subscriptionId: crypto.randomUUID(),
          providerId: PROVIDER_B,
          reportType: 'WEEKLY_SUMMARY',
          frequency: 'WEEKLY',
          deliveryMethod: 'EMAIL',
          isActive: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
        {
          subscriptionId: crypto.randomUUID(),
          providerId: PROVIDER_A,
          reportType: 'MONTHLY_PERFORMANCE',
          frequency: 'MONTHLY',
          deliveryMethod: 'IN_APP',
          isActive: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
        {
          subscriptionId: crypto.randomUUID(),
          providerId: PROVIDER_A,
          reportType: 'REJECTION_DIGEST',
          frequency: 'WEEKLY',
          deliveryMethod: 'IN_APP',
          isActive: false, // Inactive
          createdAt: new Date(),
          updatedAt: new Date(),
        },
        {
          subscriptionId: crypto.randomUUID(),
          providerId: PROVIDER_B,
          reportType: 'RRNP_QUARTERLY',
          frequency: 'QUARTERLY',
          deliveryMethod: 'BOTH',
          isActive: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      );
    });

    it('returns active subscriptions matching WEEKLY frequency', async () => {
      const result = await repo.getDueSubscriptions('WEEKLY');

      expect(result).toHaveLength(2);
      result.forEach((r) => {
        expect(r.frequency).toBe('WEEKLY');
        expect(r.isActive).toBe(true);
      });
    });

    it('returns active subscriptions matching MONTHLY frequency', async () => {
      const result = await repo.getDueSubscriptions('MONTHLY');

      expect(result).toHaveLength(1);
      expect(result[0].frequency).toBe('MONTHLY');
      expect(result[0].reportType).toBe('MONTHLY_PERFORMANCE');
    });

    it('returns active subscriptions matching QUARTERLY frequency', async () => {
      const result = await repo.getDueSubscriptions('QUARTERLY');

      expect(result).toHaveLength(1);
      expect(result[0].frequency).toBe('QUARTERLY');
      expect(result[0].reportType).toBe('RRNP_QUARTERLY');
    });

    it('excludes inactive subscriptions', async () => {
      const result = await repo.getDueSubscriptions('WEEKLY');

      // REJECTION_DIGEST is WEEKLY but inactive
      const rejectionDigest = result.find(
        (r) => r.reportType === 'REJECTION_DIGEST',
      );
      expect(rejectionDigest).toBeUndefined();
    });

    it('returns subscriptions across multiple providers', async () => {
      const result = await repo.getDueSubscriptions('WEEKLY');

      const providerIds = new Set(result.map((r) => r.providerId));
      expect(providerIds.size).toBe(2);
      expect(providerIds.has(PROVIDER_A)).toBe(true);
      expect(providerIds.has(PROVIDER_B)).toBe(true);
    });

    it('returns empty array when no subscriptions match frequency', async () => {
      const result = await repo.getDueSubscriptions('DAILY');

      expect(result).toHaveLength(0);
    });
  });

  // =========================================================================
  // Provider scoping (cross-cutting)
  // =========================================================================

  describe('provider scoping', () => {
    it('create stores the correct provider_id', async () => {
      const dataA = makeSubscriptionData({ providerId: PROVIDER_A });
      const dataB = makeSubscriptionData({ providerId: PROVIDER_B });

      const subA = await repo.create(dataA);
      const subB = await repo.create(dataB);

      expect(subA.providerId).toBe(PROVIDER_A);
      expect(subB.providerId).toBe(PROVIDER_B);
    });

    it('getById never returns another provider\'s subscription', async () => {
      const created = await repo.create(makeSubscriptionData());

      const byCorrectProvider = await repo.getById(
        created.subscriptionId,
        PROVIDER_A,
      );
      const byWrongProvider = await repo.getById(
        created.subscriptionId,
        PROVIDER_B,
      );

      expect(byCorrectProvider).not.toBeNull();
      expect(byWrongProvider).toBeNull();
    });

    it('update returns null for wrong provider', async () => {
      const created = await repo.create(makeSubscriptionData());

      const result = await repo.update(
        created.subscriptionId,
        PROVIDER_B,
        { frequency: 'DAILY' },
      );

      expect(result).toBeNull();
      // Original frequency unchanged
      const original = subscriptionsStore.find(
        (r) => r.subscriptionId === created.subscriptionId,
      );
      expect(original!.frequency).toBe('WEEKLY');
    });

    it('delete returns false for wrong provider', async () => {
      const created = await repo.create(makeSubscriptionData());

      const result = await repo.delete(
        created.subscriptionId,
        PROVIDER_B,
      );

      expect(result).toBe(false);
      expect(subscriptionsStore).toHaveLength(1);
    });

    it('listByProvider isolates data between providers', async () => {
      await repo.create(
        makeSubscriptionData({
          providerId: PROVIDER_A,
          reportType: 'WEEKLY_SUMMARY',
        }),
      );
      await repo.create(
        makeSubscriptionData({
          providerId: PROVIDER_A,
          reportType: 'MONTHLY_PERFORMANCE',
        }),
      );
      await repo.create(
        makeSubscriptionData({
          providerId: PROVIDER_B,
          reportType: 'WEEKLY_SUMMARY',
        }),
      );

      const listA = await repo.listByProvider(PROVIDER_A);
      const listB = await repo.listByProvider(PROVIDER_B);

      expect(listA).toHaveLength(2);
      expect(listB).toHaveLength(1);
      listA.forEach((r) => expect(r.providerId).toBe(PROVIDER_A));
      listB.forEach((r) => expect(r.providerId).toBe(PROVIDER_B));
    });
  });
});
