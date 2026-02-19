import { describe, it, expect, beforeEach, vi } from 'vitest';
import { createEdShiftsRepository } from './ed-shifts.repo.js';
import { ConflictError } from '../../../lib/errors.js';

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const PROVIDER_A = crypto.randomUUID();
const PROVIDER_B = crypto.randomUUID();
const LOCATION_ID = crypto.randomUUID();

// ---------------------------------------------------------------------------
// In-memory stores
// ---------------------------------------------------------------------------

let shiftStore: Record<string, any>[];
let claimStore: Record<string, any>[];
let patientStore: Record<string, any>[];
let ahcipDetailStore: Record<string, any>[];

// ---------------------------------------------------------------------------
// Column name → camelCase mapping
// ---------------------------------------------------------------------------

const COL_MAP: Record<string, string> = {
  shift_id: 'shiftId',
  provider_id: 'providerId',
  location_id: 'locationId',
  shift_start: 'shiftStart',
  shift_end: 'shiftEnd',
  patient_count: 'patientCount',
  estimated_value: 'estimatedValue',
  status: 'status',
  created_at: 'createdAt',
  claim_id: 'claimId',
  physician_id: 'physicianId',
  patient_id: 'patientId',
  first_name: 'firstName',
  last_name: 'lastName',
  health_service_code: 'healthServiceCode',
  submitted_fee: 'submittedFee',
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
    desc(col: any) {
      const key = toStoreKey(col);
      return { __desc: true, key };
    },
    count() {
      return { __count: true };
    },
    sql(strings: TemplateStringsArray, ...values: any[]) {
      const fullStr = strings.join('?');

      // Detect atomic increment: patient_count + 1
      if (fullStr.includes('+ 1')) {
        return { __atomicIncrement: true };
      }

      // Detect atomic decimal add for estimatedValue
      if (fullStr.includes('::decimal +') && fullStr.includes('::decimal)::text')) {
        const feeAmount = values[1]; // second interpolated value
        return { __atomicAdd: true, amount: feeAmount };
      }

      // COALESCE SUM for aggregate queries (endShift recalculation)
      if (fullStr.includes('COALESCE') && fullStr.includes('SUM')) {
        return { __aggregate: 'totalValue' };
      }

      // COALESCE for healthServiceCode in getSummary
      if (fullStr.includes('COALESCE') && fullStr.includes('health_service_code')) {
        return { __field: 'healthServiceCode' };
      }

      // submittedFee cast
      if (fullStr.includes('submitted_fee') || fullStr.includes('::text')) {
        return { __field: 'submittedFee' };
      }

      return {};
    },
  };
});

// ---------------------------------------------------------------------------
// Table identification helpers
// ---------------------------------------------------------------------------

function identifyTable(tableOrRef: any): string {
  // Drizzle table objects have a Symbol with table name info
  // We use the table name from the pgTable definition
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
    case 'ed_shifts':
      return shiftStore;
    case 'claims':
      return claimStore;
    case 'patients':
      return patientStore;
    case 'ahcip_claim_details':
      return ahcipDetailStore;
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
    joins?: Array<{ table: string; on: any }>;
    orderBy?: any[];
    limitN?: number;
    offsetN?: number;
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
      innerJoin(table: any, onClause: any) {
        ctx.joins = ctx.joins || [];
        ctx.joins.push({ table: identifyTable(table), on: onClause });
        return chain;
      },
      leftJoin(table: any, onClause: any) {
        ctx.joins = ctx.joins || [];
        ctx.joins.push({ table: identifyTable(table), on: onClause });
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
      offset(n: number) {
        ctx.offsetN = n;
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
    const store = ctx.targetTable ? getStoreForTable(ctx.targetTable) : shiftStore;

    switch (ctx.op) {
      case 'select': {
        // Handle joined queries (getSummary, endShift aggregate)
        if (ctx.joins && ctx.joins.length > 0) {
          return executeJoinedSelect(ctx, store);
        }

        // Check if this is a count query (e.g., select({ total: count() }))
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
        }

        let results = store.filter((row) =>
          matchesWhere(row, ctx.whereClauses),
        );

        // Sort
        if (ctx.orderBy) {
          for (const order of ctx.orderBy) {
            if (order && order.__desc) {
              results.sort((a: any, b: any) => {
                const va = a[order.key];
                const vb = b[order.key];
                if (va instanceof Date && vb instanceof Date) {
                  return vb.getTime() - va.getTime();
                }
                return String(vb).localeCompare(String(va));
              });
            }
          }
        }

        // Offset
        if (ctx.offsetN !== undefined) {
          results = results.slice(ctx.offsetN);
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
          // Check for unique constraint (one active shift per provider)
          if (
            ctx.targetTable === 'ed_shifts' &&
            entry.status === 'ACTIVE'
          ) {
            const existing = shiftStore.find(
              (row) =>
                row.providerId === entry.providerId &&
                row.status === 'ACTIVE',
            );
            if (existing) {
              const err: any = new Error('unique constraint violation');
              err.code = '23505';
              err.constraint = 'ed_shifts_provider_active_unique_idx';
              throw err;
            }
          }

          const newRow = {
            shiftId: crypto.randomUUID(),
            createdAt: new Date(),
            ...entry,
          };
          shiftStore.push(newRow);
          inserted.push({ ...newRow });
        }
        return ctx.shouldReturn ? inserted : [];
      }

      case 'update': {
        const updated: any[] = [];
        for (const row of store) {
          if (matchesWhere(row, ctx.whereClauses)) {
            for (const [key, val] of Object.entries(ctx.setClauses)) {
              if (val && typeof val === 'object' && (val as any).__atomicIncrement) {
                row[key] = (row[key] ?? 0) + 1;
              } else if (val && typeof val === 'object' && (val as any).__atomicAdd) {
                const current = parseFloat(row[key] ?? '0');
                const addend = parseFloat((val as any).amount);
                row[key] = (current + addend).toFixed(2);
              } else {
                row[key] = val;
              }
            }
            updated.push({ ...row });
          }
        }
        return ctx.shouldReturn ? updated : [];
      }

      default:
        return [];
    }
  }

  function executeJoinedSelect(ctx: any, primaryStore: any[]): any[] {
    const filteredPrimary = primaryStore.filter((row) =>
      matchesWhere(row, ctx.whereClauses),
    );

    // For aggregate queries (endShift recalculation)
    if (ctx.selectFields) {
      const fields = ctx.selectFields;

      // Count + aggregate sum query
      if (fields.claimCount?.__count && fields.totalValue?.__aggregate) {
        let totalFee = 0;
        for (const claim of filteredPrimary) {
          // Look up AHCIP detail for submitted fee
          const detail = ahcipDetailStore.find(
            (d) => d.claimId === claim.claimId,
          );
          if (detail?.submittedFee) {
            totalFee += parseFloat(detail.submittedFee);
          }
        }
        return [
          {
            claimCount: filteredPrimary.length,
            totalValue: totalFee.toFixed(2),
          },
        ];
      }

      // Summary claim rows (joined claims + patients + ahcip details)
      if (fields.claimId) {
        return filteredPrimary.map((claim) => {
          const patient = patientStore.find(
            (p) => p.patientId === claim.patientId,
          );
          const detail = ahcipDetailStore.find(
            (d) => d.claimId === claim.claimId,
          );
          return {
            claimId: claim.claimId,
            patientFirstName: patient?.firstName ?? '',
            patientLastName: patient?.lastName ?? '',
            healthServiceCode: detail?.healthServiceCode ?? '',
            fee: detail?.submittedFee?.toString() ?? null,
          };
        });
      }
    }

    return filteredPrimary;
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
// Tests
// ---------------------------------------------------------------------------

describe('EdShiftsRepository', () => {
  let repo: ReturnType<typeof createEdShiftsRepository>;

  beforeEach(() => {
    shiftStore = [];
    claimStore = [];
    patientStore = [];
    ahcipDetailStore = [];
    repo = createEdShiftsRepository(makeMockDb());
  });

  // =========================================================================
  // create
  // =========================================================================

  describe('create', () => {
    it('creates a new shift with ACTIVE status', async () => {
      const result = await repo.create({
        providerId: PROVIDER_A,
        locationId: LOCATION_ID,
        shiftStart: new Date('2026-02-19T08:00:00Z'),
      });

      expect(result).toBeDefined();
      expect(result.shiftId).toBeDefined();
      expect(result.providerId).toBe(PROVIDER_A);
      expect(result.locationId).toBe(LOCATION_ID);
      expect(result.status).toBe('ACTIVE');
      expect(result.patientCount).toBe(0);
      expect(result.estimatedValue).toBe('0');
      expect(shiftStore).toHaveLength(1);
    });

    it('throws ConflictError when physician already has an active shift', async () => {
      await repo.create({
        providerId: PROVIDER_A,
        locationId: LOCATION_ID,
        shiftStart: new Date('2026-02-19T08:00:00Z'),
      });

      await expect(
        repo.create({
          providerId: PROVIDER_A,
          locationId: LOCATION_ID,
          shiftStart: new Date('2026-02-19T14:00:00Z'),
        }),
      ).rejects.toThrow(ConflictError);

      expect(shiftStore).toHaveLength(1);
    });

    it('allows different physicians to have active shifts simultaneously', async () => {
      await repo.create({
        providerId: PROVIDER_A,
        locationId: LOCATION_ID,
        shiftStart: new Date('2026-02-19T08:00:00Z'),
      });

      const shiftB = await repo.create({
        providerId: PROVIDER_B,
        locationId: LOCATION_ID,
        shiftStart: new Date('2026-02-19T08:00:00Z'),
      });

      expect(shiftB).toBeDefined();
      expect(shiftB.providerId).toBe(PROVIDER_B);
      expect(shiftStore).toHaveLength(2);
    });

    it('allows same physician to create new shift after ending previous one', async () => {
      const shift1 = await repo.create({
        providerId: PROVIDER_A,
        locationId: LOCATION_ID,
        shiftStart: new Date('2026-02-19T08:00:00Z'),
      });

      // Manually end the shift (simulate endShift)
      shiftStore[0].status = 'ENDED';

      const shift2 = await repo.create({
        providerId: PROVIDER_A,
        locationId: LOCATION_ID,
        shiftStart: new Date('2026-02-19T14:00:00Z'),
      });

      expect(shift2).toBeDefined();
      expect(shift2.shiftId).not.toBe(shift1.shiftId);
      expect(shiftStore).toHaveLength(2);
    });
  });

  // =========================================================================
  // getActive
  // =========================================================================

  describe('getActive', () => {
    it('returns the active shift for the provider', async () => {
      const created = await repo.create({
        providerId: PROVIDER_A,
        locationId: LOCATION_ID,
        shiftStart: new Date('2026-02-19T08:00:00Z'),
      });

      const active = await repo.getActive(PROVIDER_A);

      expect(active).toBeDefined();
      expect(active!.shiftId).toBe(created.shiftId);
      expect(active!.status).toBe('ACTIVE');
    });

    it('returns null when no active shift exists', async () => {
      const active = await repo.getActive(PROVIDER_A);
      expect(active).toBeNull();
    });

    it('returns null for ended shifts', async () => {
      await repo.create({
        providerId: PROVIDER_A,
        locationId: LOCATION_ID,
        shiftStart: new Date('2026-02-19T08:00:00Z'),
      });
      shiftStore[0].status = 'ENDED';

      const active = await repo.getActive(PROVIDER_A);
      expect(active).toBeNull();
    });

    it('does not return another provider\'s active shift', async () => {
      await repo.create({
        providerId: PROVIDER_B,
        locationId: LOCATION_ID,
        shiftStart: new Date('2026-02-19T08:00:00Z'),
      });

      const active = await repo.getActive(PROVIDER_A);
      expect(active).toBeNull();
    });
  });

  // =========================================================================
  // getById
  // =========================================================================

  describe('getById', () => {
    it('returns shift when owned by the provider', async () => {
      const created = await repo.create({
        providerId: PROVIDER_A,
        locationId: LOCATION_ID,
        shiftStart: new Date('2026-02-19T08:00:00Z'),
      });

      const result = await repo.getById(created.shiftId, PROVIDER_A);
      expect(result).toBeDefined();
      expect(result!.shiftId).toBe(created.shiftId);
    });

    it('returns null for wrong provider (404 pattern)', async () => {
      const created = await repo.create({
        providerId: PROVIDER_A,
        locationId: LOCATION_ID,
        shiftStart: new Date('2026-02-19T08:00:00Z'),
      });

      const result = await repo.getById(created.shiftId, PROVIDER_B);
      expect(result).toBeNull();
    });

    it('returns null for non-existent shift', async () => {
      const result = await repo.getById(crypto.randomUUID(), PROVIDER_A);
      expect(result).toBeNull();
    });
  });

  // =========================================================================
  // endShift
  // =========================================================================

  describe('endShift', () => {
    it('sets shift_end, status to ENDED, and recalculates totals', async () => {
      const created = await repo.create({
        providerId: PROVIDER_A,
        locationId: LOCATION_ID,
        shiftStart: new Date('2026-02-19T08:00:00Z'),
      });

      // Add linked claims
      const claimId1 = crypto.randomUUID();
      const claimId2 = crypto.randomUUID();
      claimStore.push(
        { claimId: claimId1, physicianId: PROVIDER_A, shiftId: created.shiftId, patientId: 'p1' },
        { claimId: claimId2, physicianId: PROVIDER_A, shiftId: created.shiftId, patientId: 'p2' },
      );
      ahcipDetailStore.push(
        { claimId: claimId1, healthServiceCode: '03.04A', submittedFee: '38.50' },
        { claimId: claimId2, healthServiceCode: '03.05A', submittedFee: '76.25' },
      );

      const ended = await repo.endShift(created.shiftId, PROVIDER_A);

      expect(ended).toBeDefined();
      expect(ended!.status).toBe('ENDED');
      expect(ended!.shiftEnd).toBeInstanceOf(Date);
      expect(ended!.patientCount).toBe(2);
      expect(ended!.estimatedValue).toBe('114.75');
    });

    it('returns null for wrong provider', async () => {
      const created = await repo.create({
        providerId: PROVIDER_A,
        locationId: LOCATION_ID,
        shiftStart: new Date('2026-02-19T08:00:00Z'),
      });

      const result = await repo.endShift(created.shiftId, PROVIDER_B);
      expect(result).toBeNull();
    });

    it('returns null for already ended shift', async () => {
      const created = await repo.create({
        providerId: PROVIDER_A,
        locationId: LOCATION_ID,
        shiftStart: new Date('2026-02-19T08:00:00Z'),
      });
      shiftStore[0].status = 'ENDED';

      const result = await repo.endShift(created.shiftId, PROVIDER_A);
      expect(result).toBeNull();
    });

    it('sets patientCount to 0 and estimatedValue to 0 when no claims linked', async () => {
      const created = await repo.create({
        providerId: PROVIDER_A,
        locationId: LOCATION_ID,
        shiftStart: new Date('2026-02-19T08:00:00Z'),
      });

      const ended = await repo.endShift(created.shiftId, PROVIDER_A);

      expect(ended).toBeDefined();
      expect(ended!.patientCount).toBe(0);
      expect(ended!.estimatedValue).toBe('0.00');
    });
  });

  // =========================================================================
  // markReviewed
  // =========================================================================

  describe('markReviewed', () => {
    it('transitions ENDED shift to REVIEWED', async () => {
      const created = await repo.create({
        providerId: PROVIDER_A,
        locationId: LOCATION_ID,
        shiftStart: new Date('2026-02-19T08:00:00Z'),
      });
      shiftStore[0].status = 'ENDED';

      const reviewed = await repo.markReviewed(created.shiftId, PROVIDER_A);

      expect(reviewed).toBeDefined();
      expect(reviewed!.status).toBe('REVIEWED');
    });

    it('returns null for ACTIVE shift (wrong state)', async () => {
      const created = await repo.create({
        providerId: PROVIDER_A,
        locationId: LOCATION_ID,
        shiftStart: new Date('2026-02-19T08:00:00Z'),
      });

      const result = await repo.markReviewed(created.shiftId, PROVIDER_A);
      expect(result).toBeNull();
    });

    it('returns null for wrong provider', async () => {
      const created = await repo.create({
        providerId: PROVIDER_A,
        locationId: LOCATION_ID,
        shiftStart: new Date('2026-02-19T08:00:00Z'),
      });
      shiftStore[0].status = 'ENDED';

      const result = await repo.markReviewed(created.shiftId, PROVIDER_B);
      expect(result).toBeNull();
    });
  });

  // =========================================================================
  // list
  // =========================================================================

  describe('list', () => {
    beforeEach(async () => {
      // Create shifts for both providers
      shiftStore.push(
        {
          shiftId: crypto.randomUUID(),
          providerId: PROVIDER_A,
          locationId: LOCATION_ID,
          shiftStart: new Date('2026-02-17T08:00:00Z'),
          status: 'ENDED',
          patientCount: 5,
          estimatedValue: '250.00',
          createdAt: new Date('2026-02-17T08:00:00Z'),
        },
        {
          shiftId: crypto.randomUUID(),
          providerId: PROVIDER_A,
          locationId: LOCATION_ID,
          shiftStart: new Date('2026-02-18T08:00:00Z'),
          status: 'ACTIVE',
          patientCount: 2,
          estimatedValue: '100.00',
          createdAt: new Date('2026-02-18T08:00:00Z'),
        },
        {
          shiftId: crypto.randomUUID(),
          providerId: PROVIDER_B,
          locationId: LOCATION_ID,
          shiftStart: new Date('2026-02-18T08:00:00Z'),
          status: 'ACTIVE',
          patientCount: 3,
          estimatedValue: '150.00',
          createdAt: new Date('2026-02-18T08:00:00Z'),
        },
      );
    });

    it('returns only the authenticated provider\'s shifts', async () => {
      const result = await repo.list(PROVIDER_A);

      expect(result.data).toHaveLength(2);
      result.data.forEach((shift) => {
        expect(shift.providerId).toBe(PROVIDER_A);
      });
      expect(result.total).toBe(2);
    });

    it('filters by status', async () => {
      const result = await repo.list(PROVIDER_A, { status: 'ENDED' });

      expect(result.data).toHaveLength(1);
      expect(result.data[0].status).toBe('ENDED');
    });

    it('orders by created_at DESC', async () => {
      const result = await repo.list(PROVIDER_A);

      expect(result.data).toHaveLength(2);
      const dates = result.data.map((s) => new Date(s.createdAt).getTime());
      expect(dates[0]).toBeGreaterThanOrEqual(dates[1]);
    });

    it('applies limit and offset', async () => {
      const result = await repo.list(PROVIDER_A, { limit: 1, offset: 0 });
      expect(result.data).toHaveLength(1);
      expect(result.total).toBe(2); // Total is still 2
    });

    it('never returns another provider\'s shifts', async () => {
      const result = await repo.list(PROVIDER_A);

      result.data.forEach((shift) => {
        expect(shift.providerId).not.toBe(PROVIDER_B);
      });
    });
  });

  // =========================================================================
  // incrementPatientCount
  // =========================================================================

  describe('incrementPatientCount', () => {
    it('atomically increments patient_count by 1 and adds fee', async () => {
      const created = await repo.create({
        providerId: PROVIDER_A,
        locationId: LOCATION_ID,
        shiftStart: new Date('2026-02-19T08:00:00Z'),
      });

      const updated = await repo.incrementPatientCount(
        created.shiftId,
        PROVIDER_A,
        '38.50',
      );

      expect(updated).toBeDefined();
      expect(updated!.patientCount).toBe(1);
      expect(updated!.estimatedValue).toBe('38.50');
    });

    it('accumulates correctly over multiple increments', async () => {
      const created = await repo.create({
        providerId: PROVIDER_A,
        locationId: LOCATION_ID,
        shiftStart: new Date('2026-02-19T08:00:00Z'),
      });

      await repo.incrementPatientCount(created.shiftId, PROVIDER_A, '38.50');
      const result = await repo.incrementPatientCount(
        created.shiftId,
        PROVIDER_A,
        '76.25',
      );

      expect(result).toBeDefined();
      expect(result!.patientCount).toBe(2);
      expect(result!.estimatedValue).toBe('114.75');
    });

    it('returns null for wrong provider', async () => {
      const created = await repo.create({
        providerId: PROVIDER_A,
        locationId: LOCATION_ID,
        shiftStart: new Date('2026-02-19T08:00:00Z'),
      });

      const result = await repo.incrementPatientCount(
        created.shiftId,
        PROVIDER_B,
        '38.50',
      );
      expect(result).toBeNull();
    });

    it('returns null for non-ACTIVE shift', async () => {
      const created = await repo.create({
        providerId: PROVIDER_A,
        locationId: LOCATION_ID,
        shiftStart: new Date('2026-02-19T08:00:00Z'),
      });
      shiftStore[0].status = 'ENDED';

      const result = await repo.incrementPatientCount(
        created.shiftId,
        PROVIDER_A,
        '38.50',
      );
      expect(result).toBeNull();
    });
  });

  // =========================================================================
  // getSummary
  // =========================================================================

  describe('getSummary', () => {
    it('returns shift with linked claim details', async () => {
      const created = await repo.create({
        providerId: PROVIDER_A,
        locationId: LOCATION_ID,
        shiftStart: new Date('2026-02-19T08:00:00Z'),
      });

      const patientId = crypto.randomUUID();
      const claimId = crypto.randomUUID();
      patientStore.push({
        patientId,
        firstName: 'Jane',
        lastName: 'Smith',
        providerId: PROVIDER_A,
      });
      claimStore.push({
        claimId,
        physicianId: PROVIDER_A,
        shiftId: created.shiftId,
        patientId,
      });
      ahcipDetailStore.push({
        claimId,
        healthServiceCode: '03.04A',
        submittedFee: '38.50',
      });

      const summary = await repo.getSummary(created.shiftId, PROVIDER_A);

      expect(summary).toBeDefined();
      expect(summary!.shiftId).toBe(created.shiftId);
      expect(summary!.claims).toHaveLength(1);
      expect(summary!.claims[0].claimId).toBe(claimId);
      expect(summary!.claims[0].patientFirstName).toBe('Jane');
      expect(summary!.claims[0].patientLastName).toBe('Smith');
      expect(summary!.claims[0].healthServiceCode).toBe('03.04A');
      expect(summary!.claims[0].fee).toBe('38.50');
    });

    it('returns null for wrong provider', async () => {
      const created = await repo.create({
        providerId: PROVIDER_A,
        locationId: LOCATION_ID,
        shiftStart: new Date('2026-02-19T08:00:00Z'),
      });

      const result = await repo.getSummary(created.shiftId, PROVIDER_B);
      expect(result).toBeNull();
    });

    it('returns shift with empty claims array when no claims linked', async () => {
      const created = await repo.create({
        providerId: PROVIDER_A,
        locationId: LOCATION_ID,
        shiftStart: new Date('2026-02-19T08:00:00Z'),
      });

      const summary = await repo.getSummary(created.shiftId, PROVIDER_A);

      expect(summary).toBeDefined();
      expect(summary!.claims).toHaveLength(0);
    });

    it('returns null for non-existent shift', async () => {
      const result = await repo.getSummary(crypto.randomUUID(), PROVIDER_A);
      expect(result).toBeNull();
    });
  });
});
