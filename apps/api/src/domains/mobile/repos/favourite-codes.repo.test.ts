import { describe, it, expect, beforeEach, vi } from 'vitest';
import { createFavouriteCodesRepository } from './favourite-codes.repo.js';
import { ConflictError, BusinessRuleError } from '../../../lib/errors.js';
import { MAX_FAVOURITES } from '@meritum/shared/constants/mobile.constants.js';

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const PROVIDER_A = crypto.randomUUID();
const PROVIDER_B = crypto.randomUUID();

// ---------------------------------------------------------------------------
// In-memory store
// ---------------------------------------------------------------------------

let favouriteStore: Record<string, any>[];

// ---------------------------------------------------------------------------
// Column name → camelCase mapping
// ---------------------------------------------------------------------------

const COL_MAP: Record<string, string> = {
  favourite_id: 'favouriteId',
  provider_id: 'providerId',
  health_service_code: 'healthServiceCode',
  display_name: 'displayName',
  sort_order: 'sortOrder',
  default_modifiers: 'defaultModifiers',
  created_at: 'createdAt',
};

function toStoreKey(col: any): string {
  const name = col?.name ?? '';
  return COL_MAP[name] || name;
}

// ---------------------------------------------------------------------------
// Mock Drizzle operators
// ---------------------------------------------------------------------------

vi.mock('drizzle-orm', async () => {
  const actual = await vi.importActual<typeof import('drizzle-orm')>('drizzle-orm');
  return {
    ...actual,
    eq(col: any, val: any) {
      const key = toStoreKey(col);
      return { __predicate: (row: any) => row[key] === val };
    },
    and(...conditions: any[]) {
      const preds = conditions
        .filter(Boolean)
        .map((c: any) => (typeof c === 'function' ? c : c?.__predicate))
        .filter(Boolean);
      return { __predicate: (row: any) => preds.every((p: any) => p(row)) };
    },
    asc(col: any) {
      const key = toStoreKey(col);
      return { __asc: true, key };
    },
    count() {
      return { __count: true };
    },
    inArray(col: any, vals: any[]) {
      const key = toStoreKey(col);
      return { __predicate: (row: any) => vals.includes(row[key]) };
    },
  };
});

// ---------------------------------------------------------------------------
// Table identification helpers
// ---------------------------------------------------------------------------

function identifyTable(tableOrRef: any): string {
  const sym = Object.getOwnPropertySymbols(tableOrRef).find(
    (s) => s.toString() === 'Symbol(drizzle:Name)',
  );
  if (sym) {
    return tableOrRef[sym];
  }
  return 'unknown';
}

function getStoreForTable(tableName: string): Record<string, any>[] {
  switch (tableName) {
    case 'favourite_codes':
      return favouriteStore;
    default:
      return [];
  }
}

// ---------------------------------------------------------------------------
// Mock Drizzle DB
// ---------------------------------------------------------------------------

function makeMockDb(): any {
  function matchesWhere(
    row: Record<string, any>,
    whereClauses: Array<(row: any) => boolean>,
  ): boolean {
    return whereClauses.every((pred) => pred(row));
  }

  function chainable(ctx: {
    op: string;
    targetTable?: string;
    values?: any;
    setClauses?: any;
    whereClauses: Array<(row: any) => boolean>;
    shouldReturn?: boolean;
    selectFields?: any;
    orderBy?: any[];
    limitN?: number;
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
      from(table: any) {
        ctx.targetTable = identifyTable(table);
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
      orderBy(...args: any[]) {
        ctx.orderBy = args;
        return chain;
      },
      limit(n: number) {
        ctx.limitN = n;
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

  function executeOp(ctx: any): any[] {
    const store = ctx.targetTable
      ? getStoreForTable(ctx.targetTable)
      : favouriteStore;

    switch (ctx.op) {
      case 'select': {
        // Check if this is a count query
        if (ctx.selectFields) {
          const hasCount = Object.values(ctx.selectFields).some(
            (v: any) => v && v.__count,
          );
          if (hasCount) {
            const filtered = store.filter((row) =>
              matchesWhere(row, ctx.whereClauses),
            );
            return [{ total: filtered.length }];
          }

          // Select specific fields (e.g. favouriteId only)
          const fieldKeys = Object.keys(ctx.selectFields);
          const filtered = store.filter((row) =>
            matchesWhere(row, ctx.whereClauses),
          );
          return filtered.map((row) => {
            const result: any = {};
            for (const key of fieldKeys) {
              const col = ctx.selectFields[key];
              const storeKey = toStoreKey(col);
              result[key] = row[storeKey];
            }
            return result;
          });
        }

        let results = store.filter((row) =>
          matchesWhere(row, ctx.whereClauses),
        );

        // Sort
        if (ctx.orderBy) {
          for (const order of ctx.orderBy) {
            if (order && order.__asc) {
              results.sort((a: any, b: any) => {
                const va = a[order.key];
                const vb = b[order.key];
                if (typeof va === 'number' && typeof vb === 'number') {
                  return va - vb;
                }
                return String(va).localeCompare(String(vb));
              });
            }
          }
        }

        // Limit
        if (ctx.limitN !== undefined) {
          results = results.slice(0, ctx.limitN);
        }

        return results;
      }

      case 'insert': {
        const inserted: any[] = [];
        for (const entry of ctx.values) {
          // Check unique constraint (provider_id + health_service_code)
          if (ctx.targetTable === 'favourite_codes') {
            const existing = favouriteStore.find(
              (row) =>
                row.providerId === entry.providerId &&
                row.healthServiceCode === entry.healthServiceCode,
            );
            if (existing) {
              const err: any = new Error('unique constraint violation');
              err.code = '23505';
              err.constraint = 'favourite_codes_provider_hsc_unique_idx';
              throw err;
            }
          }

          const newRow = {
            favouriteId: crypto.randomUUID(),
            createdAt: new Date(),
            ...entry,
          };
          favouriteStore.push(newRow);
          inserted.push({ ...newRow });
        }
        return ctx.shouldReturn ? inserted : [];
      }

      case 'update': {
        const updated: any[] = [];
        for (const row of store) {
          if (matchesWhere(row, ctx.whereClauses)) {
            for (const [key, val] of Object.entries(ctx.setClauses)) {
              row[key] = val;
            }
            updated.push({ ...row });
          }
        }
        return ctx.shouldReturn ? updated : [];
      }

      case 'delete': {
        const deleted: any[] = [];
        for (let i = store.length - 1; i >= 0; i--) {
          if (matchesWhere(store[i], ctx.whereClauses)) {
            deleted.push({ ...store[i] });
            store.splice(i, 1);
          }
        }
        return ctx.shouldReturn ? deleted : [];
      }

      default:
        return [];
    }
  }

  return {
    select(fields?: any) {
      return chainable({
        op: 'select',
        whereClauses: [],
        selectFields: fields,
      });
    },
    insert(table: any) {
      return chainable({
        op: 'insert',
        targetTable: identifyTable(table),
        whereClauses: [],
      });
    },
    update(table: any) {
      return chainable({
        op: 'update',
        targetTable: identifyTable(table),
        whereClauses: [],
      });
    },
    delete(table: any) {
      return chainable({
        op: 'delete',
        targetTable: identifyTable(table),
        whereClauses: [],
      });
    },
  };
}

// ---------------------------------------------------------------------------
// Helper: seed a favourite in the store
// ---------------------------------------------------------------------------

function seedFavourite(
  overrides?: Partial<Record<string, any>>,
): Record<string, any> {
  const fav = {
    favouriteId: crypto.randomUUID(),
    providerId: PROVIDER_A,
    healthServiceCode: '03.04A',
    displayName: 'Office Visit',
    sortOrder: 0,
    defaultModifiers: null,
    createdAt: new Date(),
    ...overrides,
  };
  favouriteStore.push(fav);
  return fav;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('FavouriteCodesRepository', () => {
  let repo: ReturnType<typeof createFavouriteCodesRepository>;

  beforeEach(() => {
    favouriteStore = [];
    repo = createFavouriteCodesRepository(makeMockDb());
  });

  // =========================================================================
  // create
  // =========================================================================

  describe('create', () => {
    it('creates a new favourite code', async () => {
      const result = await repo.create({
        providerId: PROVIDER_A,
        healthServiceCode: '03.04A',
        displayName: 'Office Visit',
        sortOrder: 0,
        defaultModifiers: ['CMGP'],
      });

      expect(result).toBeDefined();
      expect(result.favouriteId).toBeDefined();
      expect(result.providerId).toBe(PROVIDER_A);
      expect(result.healthServiceCode).toBe('03.04A');
      expect(result.displayName).toBe('Office Visit');
      expect(result.sortOrder).toBe(0);
      expect(result.defaultModifiers).toEqual(['CMGP']);
      expect(favouriteStore).toHaveLength(1);
    });

    it('creates favourite with null display_name and default_modifiers', async () => {
      const result = await repo.create({
        providerId: PROVIDER_A,
        healthServiceCode: '03.04A',
        sortOrder: 0,
      });

      expect(result.displayName).toBeNull();
      expect(result.defaultModifiers).toBeNull();
    });

    it('throws ConflictError on duplicate health_service_code for same provider', async () => {
      await repo.create({
        providerId: PROVIDER_A,
        healthServiceCode: '03.04A',
        sortOrder: 0,
      });

      await expect(
        repo.create({
          providerId: PROVIDER_A,
          healthServiceCode: '03.04A',
          sortOrder: 1,
        }),
      ).rejects.toThrow(ConflictError);

      expect(favouriteStore).toHaveLength(1);
    });

    it('allows same health_service_code for different providers', async () => {
      await repo.create({
        providerId: PROVIDER_A,
        healthServiceCode: '03.04A',
        sortOrder: 0,
      });

      const result = await repo.create({
        providerId: PROVIDER_B,
        healthServiceCode: '03.04A',
        sortOrder: 0,
      });

      expect(result).toBeDefined();
      expect(result.providerId).toBe(PROVIDER_B);
      expect(favouriteStore).toHaveLength(2);
    });

    it('throws BusinessRuleError when max favourites (30) reached', async () => {
      // Seed 30 favourites
      for (let i = 0; i < MAX_FAVOURITES; i++) {
        seedFavourite({
          healthServiceCode: `CODE${i.toString().padStart(3, '0')}`,
          sortOrder: i,
        });
      }

      await expect(
        repo.create({
          providerId: PROVIDER_A,
          healthServiceCode: 'NEW_CODE',
          sortOrder: 30,
        }),
      ).rejects.toThrow(BusinessRuleError);

      expect(favouriteStore).toHaveLength(MAX_FAVOURITES);
    });

    it('allows create when count is below max', async () => {
      // Seed 29 favourites
      for (let i = 0; i < MAX_FAVOURITES - 1; i++) {
        seedFavourite({
          healthServiceCode: `CODE${i.toString().padStart(3, '0')}`,
          sortOrder: i,
        });
      }

      const result = await repo.create({
        providerId: PROVIDER_A,
        healthServiceCode: 'LAST_ONE',
        sortOrder: 29,
      });

      expect(result).toBeDefined();
      expect(favouriteStore).toHaveLength(MAX_FAVOURITES);
    });

    it('max favourites check is scoped to provider', async () => {
      // Seed 30 favourites for PROVIDER_A
      for (let i = 0; i < MAX_FAVOURITES; i++) {
        seedFavourite({
          healthServiceCode: `CODE${i.toString().padStart(3, '0')}`,
          sortOrder: i,
        });
      }

      // PROVIDER_B should still be able to create
      const result = await repo.create({
        providerId: PROVIDER_B,
        healthServiceCode: '03.04A',
        sortOrder: 0,
      });

      expect(result).toBeDefined();
      expect(result.providerId).toBe(PROVIDER_B);
    });
  });

  // =========================================================================
  // getById
  // =========================================================================

  describe('getById', () => {
    it('returns favourite when owned by the provider', async () => {
      const fav = seedFavourite();

      const result = await repo.getById(fav.favouriteId, PROVIDER_A);

      expect(result).toBeDefined();
      expect(result!.favouriteId).toBe(fav.favouriteId);
      expect(result!.healthServiceCode).toBe('03.04A');
    });

    it('returns null for wrong provider (404 pattern)', async () => {
      const fav = seedFavourite();

      const result = await repo.getById(fav.favouriteId, PROVIDER_B);
      expect(result).toBeNull();
    });

    it('returns null for non-existent favourite', async () => {
      const result = await repo.getById(crypto.randomUUID(), PROVIDER_A);
      expect(result).toBeNull();
    });
  });

  // =========================================================================
  // update
  // =========================================================================

  describe('update', () => {
    it('updates display_name', async () => {
      const fav = seedFavourite();

      const result = await repo.update(fav.favouriteId, PROVIDER_A, {
        displayName: 'Updated Name',
      });

      expect(result).toBeDefined();
      expect(result!.displayName).toBe('Updated Name');
    });

    it('updates default_modifiers', async () => {
      const fav = seedFavourite();

      const result = await repo.update(fav.favouriteId, PROVIDER_A, {
        defaultModifiers: ['AFHR', 'NGHR'],
      });

      expect(result).toBeDefined();
      expect(result!.defaultModifiers).toEqual(['AFHR', 'NGHR']);
    });

    it('updates sort_order', async () => {
      const fav = seedFavourite();

      const result = await repo.update(fav.favouriteId, PROVIDER_A, {
        sortOrder: 5,
      });

      expect(result).toBeDefined();
      expect(result!.sortOrder).toBe(5);
    });

    it('updates multiple fields at once', async () => {
      const fav = seedFavourite();

      const result = await repo.update(fav.favouriteId, PROVIDER_A, {
        displayName: 'New Name',
        sortOrder: 10,
        defaultModifiers: ['TM'],
      });

      expect(result).toBeDefined();
      expect(result!.displayName).toBe('New Name');
      expect(result!.sortOrder).toBe(10);
      expect(result!.defaultModifiers).toEqual(['TM']);
    });

    it('returns null for wrong provider', async () => {
      const fav = seedFavourite();

      const result = await repo.update(fav.favouriteId, PROVIDER_B, {
        displayName: 'Hacked',
      });
      expect(result).toBeNull();
    });

    it('returns null for non-existent favourite', async () => {
      const result = await repo.update(crypto.randomUUID(), PROVIDER_A, {
        displayName: 'Nope',
      });
      expect(result).toBeNull();
    });
  });

  // =========================================================================
  // delete
  // =========================================================================

  describe('delete', () => {
    it('deletes favourite owned by the provider', async () => {
      const fav = seedFavourite();

      const result = await repo.delete(fav.favouriteId, PROVIDER_A);

      expect(result).toBe(true);
      expect(favouriteStore).toHaveLength(0);
    });

    it('returns false for wrong provider', async () => {
      const fav = seedFavourite();

      const result = await repo.delete(fav.favouriteId, PROVIDER_B);

      expect(result).toBe(false);
      expect(favouriteStore).toHaveLength(1);
    });

    it('returns false for non-existent favourite', async () => {
      const result = await repo.delete(crypto.randomUUID(), PROVIDER_A);
      expect(result).toBe(false);
    });
  });

  // =========================================================================
  // listByProvider
  // =========================================================================

  describe('listByProvider', () => {
    it('returns all favourites for the provider ordered by sort_order ASC', async () => {
      seedFavourite({ healthServiceCode: '03.05A', sortOrder: 2 });
      seedFavourite({ healthServiceCode: '03.04A', sortOrder: 0 });
      seedFavourite({ healthServiceCode: '08.19A', sortOrder: 1 });

      const results = await repo.listByProvider(PROVIDER_A);

      expect(results).toHaveLength(3);
      expect(results[0].sortOrder).toBe(0);
      expect(results[1].sortOrder).toBe(1);
      expect(results[2].sortOrder).toBe(2);
      expect(results[0].healthServiceCode).toBe('03.04A');
      expect(results[1].healthServiceCode).toBe('08.19A');
      expect(results[2].healthServiceCode).toBe('03.05A');
    });

    it('returns empty array when provider has no favourites', async () => {
      const results = await repo.listByProvider(PROVIDER_A);
      expect(results).toEqual([]);
    });

    it('never returns another provider\'s favourites', async () => {
      seedFavourite({ providerId: PROVIDER_A, healthServiceCode: '03.04A', sortOrder: 0 });
      seedFavourite({ providerId: PROVIDER_B, healthServiceCode: '03.05A', sortOrder: 0 });

      const results = await repo.listByProvider(PROVIDER_A);

      expect(results).toHaveLength(1);
      results.forEach((fav) => {
        expect(fav.providerId).toBe(PROVIDER_A);
      });
    });
  });

  // =========================================================================
  // reorder
  // =========================================================================

  describe('reorder', () => {
    it('updates sort_order for all specified favourites', async () => {
      const fav1 = seedFavourite({ healthServiceCode: '03.04A', sortOrder: 0 });
      const fav2 = seedFavourite({ healthServiceCode: '03.05A', sortOrder: 1 });
      const fav3 = seedFavourite({ healthServiceCode: '08.19A', sortOrder: 2 });

      await repo.reorder(PROVIDER_A, [
        { favourite_id: fav1.favouriteId, sort_order: 2 },
        { favourite_id: fav2.favouriteId, sort_order: 0 },
        { favourite_id: fav3.favouriteId, sort_order: 1 },
      ]);

      // Verify in-store values
      const store1 = favouriteStore.find((r) => r.favouriteId === fav1.favouriteId);
      const store2 = favouriteStore.find((r) => r.favouriteId === fav2.favouriteId);
      const store3 = favouriteStore.find((r) => r.favouriteId === fav3.favouriteId);

      expect(store1!.sortOrder).toBe(2);
      expect(store2!.sortOrder).toBe(0);
      expect(store3!.sortOrder).toBe(1);
    });

    it('throws BusinessRuleError when favourite_id does not belong to provider', async () => {
      const fav1 = seedFavourite({ providerId: PROVIDER_A, healthServiceCode: '03.04A', sortOrder: 0 });
      const fav2 = seedFavourite({ providerId: PROVIDER_B, healthServiceCode: '03.05A', sortOrder: 0 });

      await expect(
        repo.reorder(PROVIDER_A, [
          { favourite_id: fav1.favouriteId, sort_order: 1 },
          { favourite_id: fav2.favouriteId, sort_order: 0 },
        ]),
      ).rejects.toThrow(BusinessRuleError);
    });

    it('throws BusinessRuleError for non-existent favourite_id', async () => {
      const fav1 = seedFavourite({ healthServiceCode: '03.04A', sortOrder: 0 });

      await expect(
        repo.reorder(PROVIDER_A, [
          { favourite_id: fav1.favouriteId, sort_order: 1 },
          { favourite_id: crypto.randomUUID(), sort_order: 0 },
        ]),
      ).rejects.toThrow(BusinessRuleError);
    });

    it('does nothing for empty items array', async () => {
      await repo.reorder(PROVIDER_A, []);
      // Should not throw
    });

    it('prevents reordering another provider\'s favourites', async () => {
      const fav = seedFavourite({ providerId: PROVIDER_B, healthServiceCode: '03.04A', sortOrder: 0 });

      await expect(
        repo.reorder(PROVIDER_A, [
          { favourite_id: fav.favouriteId, sort_order: 1 },
        ]),
      ).rejects.toThrow(BusinessRuleError);
    });
  });

  // =========================================================================
  // countByProvider
  // =========================================================================

  describe('countByProvider', () => {
    it('returns correct count of favourites', async () => {
      seedFavourite({ healthServiceCode: '03.04A', sortOrder: 0 });
      seedFavourite({ healthServiceCode: '03.05A', sortOrder: 1 });
      seedFavourite({ healthServiceCode: '08.19A', sortOrder: 2 });

      const count = await repo.countByProvider(PROVIDER_A);
      expect(count).toBe(3);
    });

    it('returns 0 when provider has no favourites', async () => {
      const count = await repo.countByProvider(PROVIDER_A);
      expect(count).toBe(0);
    });

    it('counts only the specified provider\'s favourites', async () => {
      seedFavourite({ providerId: PROVIDER_A, healthServiceCode: '03.04A', sortOrder: 0 });
      seedFavourite({ providerId: PROVIDER_A, healthServiceCode: '03.05A', sortOrder: 1 });
      seedFavourite({ providerId: PROVIDER_B, healthServiceCode: '03.04A', sortOrder: 0 });

      const countA = await repo.countByProvider(PROVIDER_A);
      const countB = await repo.countByProvider(PROVIDER_B);

      expect(countA).toBe(2);
      expect(countB).toBe(1);
    });
  });

  // =========================================================================
  // bulkCreate
  // =========================================================================

  describe('bulkCreate', () => {
    it('batch inserts multiple favourites', async () => {
      const items = [
        { healthServiceCode: '03.04A', displayName: 'Office Visit', sortOrder: 0, defaultModifiers: null },
        { healthServiceCode: '03.05A', displayName: 'Consultation', sortOrder: 1, defaultModifiers: ['CMGP'] },
        { healthServiceCode: '08.19A', displayName: 'ED Visit', sortOrder: 2, defaultModifiers: null },
      ];

      const results = await repo.bulkCreate(PROVIDER_A, items);

      expect(results).toHaveLength(3);
      expect(favouriteStore).toHaveLength(3);
      results.forEach((r) => {
        expect(r.providerId).toBe(PROVIDER_A);
        expect(r.favouriteId).toBeDefined();
      });
      expect(results[0].healthServiceCode).toBe('03.04A');
      expect(results[1].healthServiceCode).toBe('03.05A');
      expect(results[2].healthServiceCode).toBe('08.19A');
    });

    it('returns empty array for empty items', async () => {
      const results = await repo.bulkCreate(PROVIDER_A, []);
      expect(results).toEqual([]);
    });

    it('throws BusinessRuleError when bulk insert would exceed max favourites', async () => {
      // Seed 25 favourites
      for (let i = 0; i < 25; i++) {
        seedFavourite({
          healthServiceCode: `CODE${i.toString().padStart(3, '0')}`,
          sortOrder: i,
        });
      }

      const newItems = [];
      for (let i = 0; i < 6; i++) {
        newItems.push({
          healthServiceCode: `NEW${i}`,
          displayName: null,
          sortOrder: 25 + i,
          defaultModifiers: null,
        });
      }

      await expect(repo.bulkCreate(PROVIDER_A, newItems)).rejects.toThrow(
        BusinessRuleError,
      );

      // Store should still have only the original 25
      expect(favouriteStore).toHaveLength(25);
    });

    it('throws ConflictError on duplicate health_service_code in batch', async () => {
      seedFavourite({ healthServiceCode: '03.04A', sortOrder: 0 });

      await expect(
        repo.bulkCreate(PROVIDER_A, [
          { healthServiceCode: '03.04A', displayName: null, sortOrder: 1, defaultModifiers: null },
        ]),
      ).rejects.toThrow(ConflictError);
    });

    it('seeds correctly with auto-seed count (10)', async () => {
      const items = [];
      for (let i = 0; i < 10; i++) {
        items.push({
          healthServiceCode: `SEED${i.toString().padStart(3, '0')}`,
          displayName: `Seed Code ${i}`,
          sortOrder: i,
          defaultModifiers: null,
        });
      }

      const results = await repo.bulkCreate(PROVIDER_A, items);

      expect(results).toHaveLength(10);
      expect(favouriteStore).toHaveLength(10);

      // Verify all belong to the provider
      results.forEach((r) => {
        expect(r.providerId).toBe(PROVIDER_A);
      });
    });

    it('max favourites check for bulk is scoped to provider', async () => {
      // Seed 30 favourites for PROVIDER_A
      for (let i = 0; i < MAX_FAVOURITES; i++) {
        seedFavourite({
          healthServiceCode: `CODE${i.toString().padStart(3, '0')}`,
          sortOrder: i,
        });
      }

      // PROVIDER_B should still be able to bulk create
      const results = await repo.bulkCreate(PROVIDER_B, [
        { healthServiceCode: '03.04A', displayName: null, sortOrder: 0, defaultModifiers: null },
        { healthServiceCode: '03.05A', displayName: null, sortOrder: 1, defaultModifiers: null },
      ]);

      expect(results).toHaveLength(2);
      results.forEach((r) => {
        expect(r.providerId).toBe(PROVIDER_B);
      });
    });
  });

  // =========================================================================
  // Provider scoping (cross-cutting)
  // =========================================================================

  describe('provider scoping', () => {
    it('getById never returns another provider\'s favourite', async () => {
      const fav = seedFavourite({ providerId: PROVIDER_A });
      const result = await repo.getById(fav.favouriteId, PROVIDER_B);
      expect(result).toBeNull();
    });

    it('update never modifies another provider\'s favourite', async () => {
      const fav = seedFavourite({ providerId: PROVIDER_A });
      const result = await repo.update(fav.favouriteId, PROVIDER_B, {
        displayName: 'Hacked',
      });
      expect(result).toBeNull();
      // Original value unchanged
      expect(favouriteStore[0].displayName).toBe('Office Visit');
    });

    it('delete never removes another provider\'s favourite', async () => {
      const fav = seedFavourite({ providerId: PROVIDER_A });
      const result = await repo.delete(fav.favouriteId, PROVIDER_B);
      expect(result).toBe(false);
      expect(favouriteStore).toHaveLength(1);
    });

    it('listByProvider returns only the authenticated provider\'s favourites', async () => {
      seedFavourite({ providerId: PROVIDER_A, healthServiceCode: '03.04A', sortOrder: 0 });
      seedFavourite({ providerId: PROVIDER_A, healthServiceCode: '03.05A', sortOrder: 1 });
      seedFavourite({ providerId: PROVIDER_B, healthServiceCode: '08.19A', sortOrder: 0 });

      const resultsA = await repo.listByProvider(PROVIDER_A);
      const resultsB = await repo.listByProvider(PROVIDER_B);

      expect(resultsA).toHaveLength(2);
      expect(resultsB).toHaveLength(1);
      resultsA.forEach((r) => expect(r.providerId).toBe(PROVIDER_A));
      resultsB.forEach((r) => expect(r.providerId).toBe(PROVIDER_B));
    });

    it('reorder rejects favourite_ids belonging to another provider', async () => {
      const favA = seedFavourite({ providerId: PROVIDER_A, healthServiceCode: '03.04A', sortOrder: 0 });
      const favB = seedFavourite({ providerId: PROVIDER_B, healthServiceCode: '03.05A', sortOrder: 0 });

      await expect(
        repo.reorder(PROVIDER_A, [
          { favourite_id: favA.favouriteId, sort_order: 1 },
          { favourite_id: favB.favouriteId, sort_order: 0 },
        ]),
      ).rejects.toThrow(BusinessRuleError);

      // Original sort orders unchanged
      expect(favouriteStore[0].sortOrder).toBe(0);
      expect(favouriteStore[1].sortOrder).toBe(0);
    });
  });
});
