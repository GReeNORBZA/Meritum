import { describe, it, expect, beforeEach } from 'vitest';
import { createAnalyticsCacheRepository } from './analytics-cache.repo.js';

// ---------------------------------------------------------------------------
// In-memory cache store
// ---------------------------------------------------------------------------

let cacheStore: Record<string, any>[];

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const PROVIDER_A = crypto.randomUUID();
const PROVIDER_B = crypto.randomUUID();

// ---------------------------------------------------------------------------
// Mock Drizzle DB
// ---------------------------------------------------------------------------

function makeMockDb(): any {
  function deepEqual(a: any, b: any): boolean {
    if (a === b) return true;
    if (a == null || b == null) return a == b;
    if (typeof a !== typeof b) return false;
    if (typeof a !== 'object') return false;
    const keysA = Object.keys(a);
    const keysB = Object.keys(b);
    if (keysA.length !== keysB.length) return false;
    return keysA.every((k) => deepEqual(a[k], b[k]));
  }

  function findExistingIndex(entry: Record<string, any>): number {
    return cacheStore.findIndex(
      (row) =>
        row.providerId === entry.providerId &&
        row.metricKey === entry.metricKey &&
        row.periodStart === entry.periodStart &&
        row.periodEnd === entry.periodEnd &&
        deepEqual(row.dimensions, entry.dimensions),
    );
  }

  function chainable(ctx: {
    op: string;
    table?: any;
    values?: any;
    setClauses?: any;
    whereClauses: Array<(row: any) => boolean>;
    onConflictConfig?: any;
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
      limit(_n: number) {
        return chain;
      },
      onConflictDoUpdate(config: any) {
        ctx.onConflictConfig = config;
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

  function matchesWhere(row: Record<string, any>, whereClauses: Array<(row: any) => boolean>): boolean {
    return whereClauses.every((pred) => pred(row));
  }

  function executeOp(ctx: any): any[] {
    switch (ctx.op) {
      case 'select': {
        let results = cacheStore.filter((row) => matchesWhere(row, ctx.whereClauses));
        return results;
      }

      case 'insert': {
        const inserted: any[] = [];
        for (const entry of ctx.values) {
          if (ctx.onConflictConfig) {
            const idx = findExistingIndex(entry);
            if (idx >= 0) {
              // Conflict — update existing
              const updateSet = ctx.onConflictConfig.set;
              const existing = cacheStore[idx];
              for (const [key, val] of Object.entries(updateSet)) {
                if (val && typeof val === 'object' && (val as any).__excluded) {
                  // sql`excluded.field` — use the incoming value
                  existing[key] = entry[key];
                } else {
                  existing[key] = val;
                }
              }
              inserted.push({ ...existing });
              continue;
            }
          }
          const newRow = {
            cacheId: crypto.randomUUID(),
            ...entry,
          };
          cacheStore.push(newRow);
          inserted.push({ ...newRow });
        }
        return ctx.shouldReturn ? inserted : [];
      }

      case 'delete': {
        const toDelete: any[] = [];
        const remaining: any[] = [];
        for (const row of cacheStore) {
          if (matchesWhere(row, ctx.whereClauses)) {
            toDelete.push({ ...row });
          } else {
            remaining.push(row);
          }
        }
        cacheStore.length = 0;
        cacheStore.push(...remaining);
        return ctx.shouldReturn ? toDelete : [];
      }

      default:
        return [];
    }
  }

  // Build mock where predicates from drizzle operators
  // We intercept eq, and, inArray, lt, sql at the mock level

  return {
    select() {
      return chainable({ op: 'select', whereClauses: [] });
    },
    insert(_table: any) {
      return chainable({ op: 'insert', whereClauses: [] });
    },
    delete(_table: any) {
      return chainable({ op: 'delete', whereClauses: [] });
    },
  };
}

// ---------------------------------------------------------------------------
// Override drizzle-orm operators to produce in-memory predicates
// ---------------------------------------------------------------------------

// We need to intercept the operators used by the repository.
// Since the repo uses `eq`, `and`, `inArray`, `lt`, `sql` from drizzle-orm,
// we mock the module.

import { vi } from 'vitest';

// Map column objects to their column name
function colName(col: any): string {
  // Drizzle columns have a `.name` property (the SQL column name)
  if (col && col.name) return col.name;
  return '';
}

// Map drizzle column name to our store's camelCase key
const COL_MAP: Record<string, string> = {
  provider_id: 'providerId',
  metric_key: 'metricKey',
  period_start: 'periodStart',
  period_end: 'periodEnd',
  dimensions: 'dimensions',
  computed_at: 'computedAt',
  cache_id: 'cacheId',
  value: 'value',
};

function toStoreKey(col: any): string {
  const name = colName(col);
  return COL_MAP[name] || name;
}

vi.mock('drizzle-orm', async () => {
  const actual = await vi.importActual<typeof import('drizzle-orm')>('drizzle-orm');
  return {
    ...actual,
    eq(col: any, val: any) {
      const key = toStoreKey(col);
      return {
        __predicate: (row: any) => row[key] === val,
      };
    },
    and(...conditions: any[]) {
      const preds = conditions.filter(Boolean).map((c: any) =>
        typeof c === 'function' ? c : c?.__predicate,
      ).filter(Boolean);
      return {
        __predicate: (row: any) => preds.every((pred: any) => pred(row)),
      };
    },
    inArray(col: any, values: any[]) {
      const key = toStoreKey(col);
      return {
        __predicate: (row: any) => values.includes(row[key]),
      };
    },
    lt(col: any, val: any) {
      const key = toStoreKey(col);
      return {
        __predicate: (row: any) => {
          const rowVal = row[key];
          // Handle Date comparisons
          if (rowVal instanceof Date && val instanceof Date) {
            return rowVal.getTime() < val.getTime();
          }
          // Handle Date vs threshold (from sql`NOW() - interval`)
          if (val && typeof val === 'object' && val.__threshold) {
            const rowTime = rowVal instanceof Date ? rowVal.getTime() : new Date(rowVal).getTime();
            return rowTime < val.__threshold;
          }
          // String comparison (for period_end date strings)
          return rowVal < val;
        },
      };
    },
    sql(strings: TemplateStringsArray, ...values: any[]) {
      // Detect NOW() - interval pattern for stale detection
      const fullStr = strings.join('?');
      if (fullStr.includes('NOW()') && fullStr.includes('INTERVAL')) {
        const minutes = values[0];
        return {
          __threshold: Date.now() - minutes * 60 * 1000,
        };
      }
      // Detect @> JSONB containment
      // sql`${column} @> ${jsonString}::jsonb` → values[0]=column, values[1]=jsonString
      if (fullStr.includes('@>')) {
        const jsonStr = values[1] ?? values[0];
        const dims = typeof jsonStr === 'string' ? JSON.parse(jsonStr) : jsonStr;
        return {
          __predicate: (row: any) => {
            if (!row.dimensions) return false;
            return Object.entries(dims).every(
              ([k, v]) => row.dimensions[k] === v,
            );
          },
        };
      }
      // Detect excluded.field references for onConflictDoUpdate
      if (fullStr.includes('excluded.')) {
        return { __excluded: true };
      }
      return {};
    },
  };
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('AnalyticsCacheRepository', () => {
  let repo: ReturnType<typeof createAnalyticsCacheRepository>;

  beforeEach(() => {
    cacheStore = [];
    repo = createAnalyticsCacheRepository(makeMockDb());
  });

  // =========================================================================
  // upsertMetric
  // =========================================================================

  describe('upsertMetric', () => {
    it('creates a new entry when none exists', async () => {
      const result = await repo.upsertMetric(
        PROVIDER_A,
        'REVENUE_MONTHLY',
        '2026-01-01',
        '2026-01-31',
        null,
        { total: '5000.00' },
      );

      expect(result).toBeDefined();
      expect(result.providerId).toBe(PROVIDER_A);
      expect(result.metricKey).toBe('REVENUE_MONTHLY');
      expect(result.periodStart).toBe('2026-01-01');
      expect(result.periodEnd).toBe('2026-01-31');
      expect(result.value).toEqual({ total: '5000.00' });
      expect(result.cacheId).toBeDefined();
      expect(cacheStore).toHaveLength(1);
    });

    it('updates existing entry and refreshes computed_at on conflict', async () => {
      // Seed a row
      const oldComputedAt = new Date('2026-01-01T00:00:00Z');
      cacheStore.push({
        cacheId: crypto.randomUUID(),
        providerId: PROVIDER_A,
        metricKey: 'REVENUE_MONTHLY',
        periodStart: '2026-01-01',
        periodEnd: '2026-01-31',
        dimensions: null,
        value: { total: '3000.00' },
        computedAt: oldComputedAt,
      });

      const before = Date.now();
      const result = await repo.upsertMetric(
        PROVIDER_A,
        'REVENUE_MONTHLY',
        '2026-01-01',
        '2026-01-31',
        null,
        { total: '5000.00' },
      );

      expect(cacheStore).toHaveLength(1); // No new row
      expect(result.value).toEqual({ total: '5000.00' });
      expect(result.computedAt).toBeDefined();
      // computed_at should be refreshed (newer than the old value)
      const updatedTime = result.computedAt instanceof Date
        ? result.computedAt.getTime()
        : new Date(result.computedAt).getTime();
      expect(updatedTime).toBeGreaterThanOrEqual(before);
    });

    it('treats different dimensions as separate entries', async () => {
      await repo.upsertMetric(
        PROVIDER_A,
        'REVENUE_BY_BA',
        '2026-01-01',
        '2026-01-31',
        { ba_number: 'BA001' },
        { total: '2000.00' },
      );

      await repo.upsertMetric(
        PROVIDER_A,
        'REVENUE_BY_BA',
        '2026-01-01',
        '2026-01-31',
        { ba_number: 'BA002' },
        { total: '3000.00' },
      );

      expect(cacheStore).toHaveLength(2);
    });
  });

  // =========================================================================
  // getMetrics
  // =========================================================================

  describe('getMetrics', () => {
    beforeEach(() => {
      // Seed cache for both providers
      cacheStore.push(
        {
          cacheId: crypto.randomUUID(),
          providerId: PROVIDER_A,
          metricKey: 'REVENUE_MONTHLY',
          periodStart: '2026-01-01',
          periodEnd: '2026-01-31',
          dimensions: null,
          value: { total: '5000.00' },
          computedAt: new Date(),
        },
        {
          cacheId: crypto.randomUUID(),
          providerId: PROVIDER_A,
          metricKey: 'CLAIMS_SUBMITTED',
          periodStart: '2026-01-01',
          periodEnd: '2026-01-31',
          dimensions: null,
          value: { count: 42 },
          computedAt: new Date(),
        },
        {
          cacheId: crypto.randomUUID(),
          providerId: PROVIDER_A,
          metricKey: 'REVENUE_BY_BA',
          periodStart: '2026-01-01',
          periodEnd: '2026-01-31',
          dimensions: { ba_number: 'BA001' },
          value: { total: '2000.00' },
          computedAt: new Date(),
        },
        {
          cacheId: crypto.randomUUID(),
          providerId: PROVIDER_B,
          metricKey: 'REVENUE_MONTHLY',
          periodStart: '2026-01-01',
          periodEnd: '2026-01-31',
          dimensions: null,
          value: { total: '9000.00' },
          computedAt: new Date(),
        },
      );
    });

    it('returns metrics matching the keys for the correct provider', async () => {
      const results = await repo.getMetrics(
        PROVIDER_A,
        ['REVENUE_MONTHLY', 'CLAIMS_SUBMITTED'],
        '2026-01-01',
        '2026-01-31',
      );

      expect(results).toHaveLength(2);
      results.forEach((r) => expect(r.providerId).toBe(PROVIDER_A));
      const keys = results.map((r) => r.metricKey);
      expect(keys).toContain('REVENUE_MONTHLY');
      expect(keys).toContain('CLAIMS_SUBMITTED');
    });

    it('never returns another provider\'s data', async () => {
      const results = await repo.getMetrics(
        PROVIDER_A,
        ['REVENUE_MONTHLY'],
        '2026-01-01',
        '2026-01-31',
      );

      expect(results).toHaveLength(1);
      expect(results[0].providerId).toBe(PROVIDER_A);
      expect(results[0].value).toEqual({ total: '5000.00' });
    });

    it('returns empty array when no metrics match', async () => {
      const results = await repo.getMetrics(
        PROVIDER_A,
        ['NON_EXISTENT_METRIC'],
        '2026-01-01',
        '2026-01-31',
      );

      expect(results).toHaveLength(0);
    });

    it('returns empty array for empty metric keys', async () => {
      const results = await repo.getMetrics(
        PROVIDER_A,
        [],
        '2026-01-01',
        '2026-01-31',
      );

      expect(results).toHaveLength(0);
    });

    it('filters by dimensions when provided', async () => {
      const results = await repo.getMetrics(
        PROVIDER_A,
        ['REVENUE_BY_BA'],
        '2026-01-01',
        '2026-01-31',
        { ba_number: 'BA001' },
      );

      expect(results).toHaveLength(1);
      expect(results[0].dimensions).toEqual({ ba_number: 'BA001' });
    });

    it('returns no results when dimensions don\'t match', async () => {
      const results = await repo.getMetrics(
        PROVIDER_A,
        ['REVENUE_BY_BA'],
        '2026-01-01',
        '2026-01-31',
        { ba_number: 'BA999' },
      );

      expect(results).toHaveLength(0);
    });
  });

  // =========================================================================
  // bulkUpsert
  // =========================================================================

  describe('bulkUpsert', () => {
    it('inserts multiple entries in a single operation', async () => {
      const entries = [
        {
          metricKey: 'REVENUE_MONTHLY',
          periodStart: '2026-01-01',
          periodEnd: '2026-01-31',
          dimensions: null,
          value: { total: '5000.00' },
        },
        {
          metricKey: 'CLAIMS_SUBMITTED',
          periodStart: '2026-01-01',
          periodEnd: '2026-01-31',
          dimensions: null,
          value: { count: 42 },
        },
      ];

      const results = await repo.bulkUpsert(PROVIDER_A, entries);

      expect(results).toHaveLength(2);
      expect(cacheStore).toHaveLength(2);
      results.forEach((r) => {
        expect(r.providerId).toBe(PROVIDER_A);
        expect(r.cacheId).toBeDefined();
      });
    });

    it('handles conflict by updating existing entries', async () => {
      // Seed an existing entry
      cacheStore.push({
        cacheId: crypto.randomUUID(),
        providerId: PROVIDER_A,
        metricKey: 'REVENUE_MONTHLY',
        periodStart: '2026-01-01',
        periodEnd: '2026-01-31',
        dimensions: null,
        value: { total: '3000.00' },
        computedAt: new Date('2026-01-01T00:00:00Z'),
      });

      const entries = [
        {
          metricKey: 'REVENUE_MONTHLY',
          periodStart: '2026-01-01',
          periodEnd: '2026-01-31',
          dimensions: null,
          value: { total: '5000.00' },
        },
      ];

      const results = await repo.bulkUpsert(PROVIDER_A, entries);

      expect(cacheStore).toHaveLength(1); // No new row — updated in place
      expect(results).toHaveLength(1);
      // The store should have the updated value
      expect(cacheStore[0].value).toEqual({ total: '5000.00' });
    });

    it('returns empty array for empty entries', async () => {
      const results = await repo.bulkUpsert(PROVIDER_A, []);
      expect(results).toHaveLength(0);
      expect(cacheStore).toHaveLength(0);
    });

    it('stamps all entries with the same provider_id', async () => {
      const entries = [
        {
          metricKey: 'REVENUE_MONTHLY',
          periodStart: '2026-01-01',
          periodEnd: '2026-01-31',
          dimensions: null,
          value: { total: '1000.00' },
        },
        {
          metricKey: 'CLAIMS_SUBMITTED',
          periodStart: '2026-01-01',
          periodEnd: '2026-01-31',
          dimensions: null,
          value: { count: 10 },
        },
      ];

      await repo.bulkUpsert(PROVIDER_A, entries);

      cacheStore.forEach((row) => {
        expect(row.providerId).toBe(PROVIDER_A);
      });
    });
  });

  // =========================================================================
  // getStaleEntries
  // =========================================================================

  describe('getStaleEntries', () => {
    it('returns entries older than maxAgeMinutes', async () => {
      const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60 * 1000);
      const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);

      cacheStore.push(
        {
          cacheId: crypto.randomUUID(),
          providerId: PROVIDER_A,
          metricKey: 'REVENUE_MONTHLY',
          periodStart: '2026-01-01',
          periodEnd: '2026-01-31',
          dimensions: null,
          value: { total: '5000.00' },
          computedAt: twoHoursAgo, // Stale (>60 min)
        },
        {
          cacheId: crypto.randomUUID(),
          providerId: PROVIDER_A,
          metricKey: 'CLAIMS_SUBMITTED',
          periodStart: '2026-01-01',
          periodEnd: '2026-01-31',
          dimensions: null,
          value: { count: 42 },
          computedAt: fiveMinutesAgo, // Fresh (<60 min)
        },
      );

      const stale = await repo.getStaleEntries(PROVIDER_A, 60);

      expect(stale).toHaveLength(1);
      expect(stale[0].metricKey).toBe('REVENUE_MONTHLY');
    });

    it('returns empty when all entries are fresh', async () => {
      const justNow = new Date();
      cacheStore.push({
        cacheId: crypto.randomUUID(),
        providerId: PROVIDER_A,
        metricKey: 'REVENUE_MONTHLY',
        periodStart: '2026-01-01',
        periodEnd: '2026-01-31',
        dimensions: null,
        value: { total: '5000.00' },
        computedAt: justNow,
      });

      const stale = await repo.getStaleEntries(PROVIDER_A, 60);
      expect(stale).toHaveLength(0);
    });

    it('only returns stale entries for the specified provider', async () => {
      const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60 * 1000);

      cacheStore.push(
        {
          cacheId: crypto.randomUUID(),
          providerId: PROVIDER_A,
          metricKey: 'REVENUE_MONTHLY',
          periodStart: '2026-01-01',
          periodEnd: '2026-01-31',
          dimensions: null,
          value: { total: '5000.00' },
          computedAt: twoHoursAgo,
        },
        {
          cacheId: crypto.randomUUID(),
          providerId: PROVIDER_B,
          metricKey: 'REVENUE_MONTHLY',
          periodStart: '2026-01-01',
          periodEnd: '2026-01-31',
          dimensions: null,
          value: { total: '9000.00' },
          computedAt: twoHoursAgo,
        },
      );

      const stale = await repo.getStaleEntries(PROVIDER_A, 60);

      expect(stale).toHaveLength(1);
      expect(stale[0].providerId).toBe(PROVIDER_A);
    });
  });

  // =========================================================================
  // deleteExpiredEntries
  // =========================================================================

  describe('deleteExpiredEntries', () => {
    it('deletes entries with periodEnd older than the cutoff', async () => {
      cacheStore.push(
        {
          cacheId: crypto.randomUUID(),
          providerId: PROVIDER_A,
          metricKey: 'REVENUE_MONTHLY',
          periodStart: '2023-01-01',
          periodEnd: '2023-01-31', // >24 months old
          dimensions: null,
          value: { total: '1000.00' },
          computedAt: new Date(),
        },
        {
          cacheId: crypto.randomUUID(),
          providerId: PROVIDER_A,
          metricKey: 'REVENUE_MONTHLY',
          periodStart: '2026-01-01',
          periodEnd: '2026-01-31', // Recent
          dimensions: null,
          value: { total: '5000.00' },
          computedAt: new Date(),
        },
      );

      const cutoff = new Date('2024-01-01');
      const deleted = await repo.deleteExpiredEntries(PROVIDER_A, cutoff);

      expect(deleted).toBe(1);
      expect(cacheStore).toHaveLength(1);
      expect(cacheStore[0].periodEnd).toBe('2026-01-31');
    });

    it('returns 0 when nothing to delete', async () => {
      cacheStore.push({
        cacheId: crypto.randomUUID(),
        providerId: PROVIDER_A,
        metricKey: 'REVENUE_MONTHLY',
        periodStart: '2026-01-01',
        periodEnd: '2026-01-31',
        dimensions: null,
        value: { total: '5000.00' },
        computedAt: new Date(),
      });

      const cutoff = new Date('2024-01-01');
      const deleted = await repo.deleteExpiredEntries(PROVIDER_A, cutoff);

      expect(deleted).toBe(0);
      expect(cacheStore).toHaveLength(1);
    });

    it('only deletes entries for the specified provider', async () => {
      cacheStore.push(
        {
          cacheId: crypto.randomUUID(),
          providerId: PROVIDER_A,
          metricKey: 'REVENUE_MONTHLY',
          periodStart: '2023-01-01',
          periodEnd: '2023-01-31',
          dimensions: null,
          value: { total: '1000.00' },
          computedAt: new Date(),
        },
        {
          cacheId: crypto.randomUUID(),
          providerId: PROVIDER_B,
          metricKey: 'REVENUE_MONTHLY',
          periodStart: '2023-01-01',
          periodEnd: '2023-01-31',
          dimensions: null,
          value: { total: '2000.00' },
          computedAt: new Date(),
        },
      );

      const cutoff = new Date('2024-01-01');
      const deleted = await repo.deleteExpiredEntries(PROVIDER_A, cutoff);

      expect(deleted).toBe(1);
      expect(cacheStore).toHaveLength(1);
      expect(cacheStore[0].providerId).toBe(PROVIDER_B);
    });
  });
});
