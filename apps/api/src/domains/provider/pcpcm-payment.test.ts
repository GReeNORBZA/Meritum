import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createPcpcmPaymentRepository } from './pcpcm-payment.repository.js';
import {
  recordPcpcmPayment,
  reconcilePcpcmPayments,
  getPcpcmPaymentHistory,
  updatePanelSize,
  type PcpcmServiceDeps,
} from './pcpcm-payment.service.js';
// Zod schemas imported via barrel — uses Vitest alias '@meritum/shared' → packages/shared/src
import {
  createPcpcmPaymentSchema,
  listPcpcmPaymentsQuerySchema,
  updatePanelSizeSchema,
} from '@meritum/shared';

// ---------------------------------------------------------------------------
// In-memory stores
// ---------------------------------------------------------------------------

let paymentStore: Record<string, any>[];
let enrolmentStore: Record<string, any>[];

// ---------------------------------------------------------------------------
// Mock Drizzle DB
// ---------------------------------------------------------------------------

function makeMockDb() {
  function getStoreForTable(table: any): Record<string, any>[] {
    if (table?.__table === 'pcpcm_enrolments') return enrolmentStore;
    return paymentStore;
  }

  function chainable(ctx: {
    op: string;
    table?: any;
    values?: any;
    setClauses?: any;
    selectFields?: any;
    whereClauses: Array<(row: any) => boolean>;
    limitN?: number;
    offsetN?: number;
    orderByFn?: (a: any, b: any) => number;
  }) {
    const chain: any = {
      _ctx: ctx,
      values(v: any) { ctx.values = v; return chain; },
      set(s: any) { ctx.setClauses = s; return chain; },
      from(table: any) { ctx.table = table; return chain; },
      where(clause: any) {
        if (typeof clause === 'function') {
          ctx.whereClauses.push(clause);
        } else if (clause && typeof clause === 'object' && clause.__predicate) {
          ctx.whereClauses.push(clause.__predicate);
        }
        return chain;
      },
      limit(n: number) { ctx.limitN = n; return chain; },
      offset(n: number) { ctx.offsetN = n; return chain; },
      orderBy(orderSpec: any) {
        if (orderSpec && orderSpec.__orderBy) {
          ctx.orderByFn = orderSpec.__orderBy;
        }
        return chain;
      },
      returning() { return chain; },
      then(resolve: any, reject?: any) {
        try {
          resolve(executeOp(ctx));
        } catch (e) {
          if (reject) reject(e); else throw e;
        }
      },
    };
    return chain;
  }

  function insertRow(table: any, values: any): any {
    const store = getStoreForTable(table);

    if (table?.__table === 'pcpcm_payments') {
      const newPayment = {
        paymentId: values.paymentId ?? crypto.randomUUID(),
        providerId: values.providerId,
        enrolmentId: values.enrolmentId,
        paymentPeriodStart: values.paymentPeriodStart,
        paymentPeriodEnd: values.paymentPeriodEnd,
        expectedAmount: values.expectedAmount ?? null,
        actualAmount: values.actualAmount ?? null,
        panelSizeAtPayment: values.panelSizeAtPayment ?? null,
        status: values.status ?? 'EXPECTED',
        reconciledAt: values.reconciledAt ?? null,
        notes: values.notes ?? null,
        createdAt: values.createdAt ?? new Date(),
      };
      store.push(newPayment);
      return newPayment;
    }

    if (table?.__table === 'pcpcm_enrolments') {
      const newEnrolment = {
        enrolmentId: values.enrolmentId ?? crypto.randomUUID(),
        providerId: values.providerId,
        pcpcmBaId: values.pcpcmBaId,
        ffsBaId: values.ffsBaId,
        panelSize: values.panelSize ?? null,
        enrolmentDate: values.enrolmentDate,
        status: values.status ?? 'PENDING',
        createdAt: values.createdAt ?? new Date(),
        updatedAt: values.updatedAt ?? new Date(),
      };
      store.push(newEnrolment);
      return newEnrolment;
    }

    store.push({ ...values });
    return values;
  }

  function executeOp(ctx: any): any[] {
    switch (ctx.op) {
      case 'select': {
        const store = getStoreForTable(ctx.table);
        let matches = store.filter((row) =>
          ctx.whereClauses.every((pred: any) => pred(row)),
        );

        // Handle aggregate select fields
        if (ctx.selectFields) {
          const fields = ctx.selectFields;
          const hasAggregates = Object.values(fields).some(
            (f: any) => f?.__aggregate,
          );
          if (hasAggregates) {
            const result: Record<string, any> = {};
            for (const [key, spec] of Object.entries(fields) as [string, any][]) {
              if (!spec?.__aggregate) {
                result[key] = matches[0]?.[spec?.name] ?? null;
                continue;
              }
              switch (spec.__aggregate) {
                case 'count':
                  result[key] = matches.length;
                  break;
              }
            }
            return [result];
          }
        }

        if (ctx.orderByFn) {
          matches = [...matches].sort(ctx.orderByFn);
        }
        if (ctx.offsetN) {
          matches = matches.slice(ctx.offsetN);
        }
        return ctx.limitN ? matches.slice(0, ctx.limitN) : matches;
      }
      case 'insert': {
        const values = ctx.values;
        if (Array.isArray(values)) {
          return values.map((v: any) => insertRow(ctx.table, v));
        }
        return [insertRow(ctx.table, values)];
      }
      case 'update': {
        const updated: any[] = [];
        const store = getStoreForTable(ctx.table);
        const matches = store.filter((row) =>
          ctx.whereClauses.every((pred: any) => pred(row)),
        );
        for (const row of matches) {
          const setClauses = ctx.setClauses;
          if (!setClauses) continue;
          for (const [key, value] of Object.entries(setClauses)) {
            if (
              typeof value === 'object' &&
              value !== null &&
              (value as any).__sqlExpr
            ) {
              row[key] = (value as any).__sqlExpr({ ...row });
            } else {
              row[key] = value;
            }
          }
          updated.push({ ...row });
        }
        return updated;
      }
      default:
        return [];
    }
  }

  const mockDb: any = {
    insert(table: any) {
      return chainable({ op: 'insert', table, whereClauses: [] });
    },
    select(fields?: any) {
      return chainable({ op: 'select', selectFields: fields, whereClauses: [] });
    },
    update(table: any) {
      return chainable({ op: 'update', table, whereClauses: [] });
    },
  };

  return mockDb;
}

// ---------------------------------------------------------------------------
// Mock drizzle-orm operators
// ---------------------------------------------------------------------------

vi.mock('drizzle-orm', () => {
  return {
    eq: (column: any, value: any) => {
      const colName = column?.name;
      return {
        __predicate: (row: any) => row[colName] === value,
      };
    },
    and: (...conditions: any[]) => {
      const preds = conditions.filter(Boolean);
      return {
        __predicate: (row: any) =>
          preds.every((p: any) => {
            if (p?.__predicate) return p.__predicate(row);
            return true;
          }),
      };
    },
    lte: (column: any, value: any) => {
      const colName = column?.name;
      return {
        __predicate: (row: any) => {
          const rowVal = row[colName];
          if (rowVal == null) return false;
          return rowVal <= value;
        },
      };
    },
    gte: (column: any, value: any) => {
      const colName = column?.name;
      return {
        __predicate: (row: any) => {
          const rowVal = row[colName];
          if (rowVal == null) return false;
          return rowVal >= value;
        },
      };
    },
    desc: (column: any) => {
      const colName = column?.name;
      return {
        __orderBy: (a: any, b: any) => {
          const aVal = a[colName];
          const bVal = b[colName];
          if (aVal < bVal) return 1;
          if (aVal > bVal) return -1;
          return 0;
        },
      };
    },
    inArray: (column: any, values: any[]) => {
      const colName = column?.name;
      return {
        __predicate: (row: any) => values.includes(row[colName]),
      };
    },
    count: () => ({ __aggregate: 'count' }),
    sql: (strings: TemplateStringsArray, ...values: any[]) => {
      return { __sqlExpr: () => null };
    },
  };
});

// ---------------------------------------------------------------------------
// Mock the provider DB schema module
// ---------------------------------------------------------------------------

vi.mock('@meritum/shared/schemas/db/provider.schema.js', () => {
  const makeCol = (name: string) => ({ name });

  const pcpcmPaymentsProxy: any = {
    __table: 'pcpcm_payments',
    paymentId: makeCol('paymentId'),
    providerId: makeCol('providerId'),
    enrolmentId: makeCol('enrolmentId'),
    paymentPeriodStart: makeCol('paymentPeriodStart'),
    paymentPeriodEnd: makeCol('paymentPeriodEnd'),
    expectedAmount: makeCol('expectedAmount'),
    actualAmount: makeCol('actualAmount'),
    panelSizeAtPayment: makeCol('panelSizeAtPayment'),
    status: makeCol('status'),
    reconciledAt: makeCol('reconciledAt'),
    notes: makeCol('notes'),
    createdAt: makeCol('createdAt'),
  };

  const pcpcmEnrolmentsProxy: any = {
    __table: 'pcpcm_enrolments',
    enrolmentId: makeCol('enrolmentId'),
    providerId: makeCol('providerId'),
    pcpcmBaId: makeCol('pcpcmBaId'),
    ffsBaId: makeCol('ffsBaId'),
    panelSize: makeCol('panelSize'),
    enrolmentDate: makeCol('enrolmentDate'),
    status: makeCol('status'),
    createdAt: makeCol('createdAt'),
    updatedAt: makeCol('updatedAt'),
  };

  return {
    pcpcmPayments: pcpcmPaymentsProxy,
    pcpcmEnrolments: pcpcmEnrolmentsProxy,
  };
});

// ---------------------------------------------------------------------------
// Mock constants
// ---------------------------------------------------------------------------

vi.mock('@meritum/shared/constants/provider.constants.js', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return {
    ...actual,
    PcpcmPaymentStatus: {
      EXPECTED: 'EXPECTED',
      RECEIVED: 'RECEIVED',
      RECONCILED: 'RECONCILED',
      DISCREPANCY: 'DISCREPANCY',
    },
  };
});

// ---------------------------------------------------------------------------
// Test IDs
// ---------------------------------------------------------------------------

const PROVIDER_A = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const PROVIDER_B = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
const ENROLMENT_A = 'cccccccc-cccc-cccc-cccc-cccccccccccc';
const ENROLMENT_B = 'dddddddd-dddd-dddd-dddd-dddddddddddd';
const BA_PCPCM_A = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee';
const BA_FFS_A = 'ffffffff-ffff-ffff-ffff-ffffffffffff';
const ACTOR_ID = '11111111-1111-1111-1111-111111111111';

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

let mockDb: any;
let repo: ReturnType<typeof createPcpcmPaymentRepository>;
let serviceDeps: PcpcmServiceDeps;

beforeEach(() => {
  paymentStore = [];
  enrolmentStore = [];
  mockDb = makeMockDb();
  repo = createPcpcmPaymentRepository(mockDb);
  serviceDeps = { pcpcmPaymentRepo: repo };

  // Seed enrolment for Provider A
  enrolmentStore.push({
    enrolmentId: ENROLMENT_A,
    providerId: PROVIDER_A,
    pcpcmBaId: BA_PCPCM_A,
    ffsBaId: BA_FFS_A,
    panelSize: 500,
    enrolmentDate: '2025-01-01',
    status: 'ACTIVE',
    createdAt: new Date(),
    updatedAt: new Date(),
  });
});

// ============================================================================
// D19-021: Repository Tests
// ============================================================================

describe('PcpcmPaymentRepository', () => {
  describe('createPcpcmPayment', () => {
    it('should create a new payment record', async () => {
      const payment = await repo.createPcpcmPayment({
        providerId: PROVIDER_A,
        enrolmentId: ENROLMENT_A,
        paymentPeriodStart: '2025-01-01',
        paymentPeriodEnd: '2025-01-31',
        expectedAmount: '1500.00',
        status: 'EXPECTED',
      });

      expect(payment).toBeDefined();
      expect(payment.paymentId).toBeDefined();
      expect(payment.providerId).toBe(PROVIDER_A);
      expect(payment.enrolmentId).toBe(ENROLMENT_A);
      expect(payment.expectedAmount).toBe('1500.00');
      expect(payment.status).toBe('EXPECTED');
    });
  });

  describe('findPcpcmPaymentById', () => {
    it('should find payment by id scoped to provider', async () => {
      const created = await repo.createPcpcmPayment({
        providerId: PROVIDER_A,
        enrolmentId: ENROLMENT_A,
        paymentPeriodStart: '2025-01-01',
        paymentPeriodEnd: '2025-01-31',
        expectedAmount: '1500.00',
        status: 'EXPECTED',
      });

      const found = await repo.findPcpcmPaymentById(created.paymentId, PROVIDER_A);
      expect(found).toBeDefined();
      expect(found!.paymentId).toBe(created.paymentId);
    });

    it('should NOT find payment for a different provider (tenant isolation)', async () => {
      const created = await repo.createPcpcmPayment({
        providerId: PROVIDER_A,
        enrolmentId: ENROLMENT_A,
        paymentPeriodStart: '2025-01-01',
        paymentPeriodEnd: '2025-01-31',
        expectedAmount: '1500.00',
        status: 'EXPECTED',
      });

      const found = await repo.findPcpcmPaymentById(created.paymentId, PROVIDER_B);
      expect(found).toBeUndefined();
    });

    it('should return undefined for non-existent payment', async () => {
      const found = await repo.findPcpcmPaymentById(
        '00000000-0000-0000-0000-000000000000',
        PROVIDER_A,
      );
      expect(found).toBeUndefined();
    });
  });

  describe('updatePcpcmPayment', () => {
    it('should update payment fields scoped by providerId', async () => {
      const created = await repo.createPcpcmPayment({
        providerId: PROVIDER_A,
        enrolmentId: ENROLMENT_A,
        paymentPeriodStart: '2025-01-01',
        paymentPeriodEnd: '2025-01-31',
        expectedAmount: '1500.00',
        status: 'EXPECTED',
      });

      const updated = await repo.updatePcpcmPayment(created.paymentId, PROVIDER_A, {
        actualAmount: '1500.00',
        status: 'RECEIVED',
      });

      expect(updated).toBeDefined();
      expect(updated!.actualAmount).toBe('1500.00');
      expect(updated!.status).toBe('RECEIVED');
    });

    it('should NOT update payment for a different provider', async () => {
      const created = await repo.createPcpcmPayment({
        providerId: PROVIDER_A,
        enrolmentId: ENROLMENT_A,
        paymentPeriodStart: '2025-01-01',
        paymentPeriodEnd: '2025-01-31',
        expectedAmount: '1500.00',
        status: 'EXPECTED',
      });

      const updated = await repo.updatePcpcmPayment(created.paymentId, PROVIDER_B, {
        actualAmount: '9999.00',
      });

      expect(updated).toBeUndefined();
      // Original should be unchanged
      const original = await repo.findPcpcmPaymentById(created.paymentId, PROVIDER_A);
      expect(original!.actualAmount).toBeNull();
    });
  });

  describe('listPcpcmPaymentsForProvider', () => {
    it('should list payments for a provider with pagination', async () => {
      // Create 3 payments
      for (let i = 1; i <= 3; i++) {
        await repo.createPcpcmPayment({
          providerId: PROVIDER_A,
          enrolmentId: ENROLMENT_A,
          paymentPeriodStart: `2025-0${i}-01`,
          paymentPeriodEnd: `2025-0${i}-28`,
          expectedAmount: `${1000 + i * 100}.00`,
          status: 'EXPECTED',
        });
      }

      const result = await repo.listPcpcmPaymentsForProvider(PROVIDER_A, {
        limit: 2,
        offset: 0,
      });

      expect(result.data.length).toBe(2);
      expect(result.total).toBe(3);
    });

    it('should filter by status', async () => {
      await repo.createPcpcmPayment({
        providerId: PROVIDER_A,
        enrolmentId: ENROLMENT_A,
        paymentPeriodStart: '2025-01-01',
        paymentPeriodEnd: '2025-01-31',
        expectedAmount: '1500.00',
        status: 'EXPECTED',
      });
      await repo.createPcpcmPayment({
        providerId: PROVIDER_A,
        enrolmentId: ENROLMENT_A,
        paymentPeriodStart: '2025-02-01',
        paymentPeriodEnd: '2025-02-28',
        expectedAmount: '1500.00',
        actualAmount: '1500.00',
        status: 'RECONCILED',
      });

      const result = await repo.listPcpcmPaymentsForProvider(PROVIDER_A, {
        status: 'EXPECTED',
      });

      expect(result.total).toBe(1);
      expect(result.data[0].status).toBe('EXPECTED');
    });

    it('should NOT return payments from another provider', async () => {
      await repo.createPcpcmPayment({
        providerId: PROVIDER_A,
        enrolmentId: ENROLMENT_A,
        paymentPeriodStart: '2025-01-01',
        paymentPeriodEnd: '2025-01-31',
        expectedAmount: '1500.00',
        status: 'EXPECTED',
      });

      const result = await repo.listPcpcmPaymentsForProvider(PROVIDER_B);
      expect(result.total).toBe(0);
      expect(result.data.length).toBe(0);
    });
  });

  describe('findUnreconciledPayments', () => {
    it('should return only EXPECTED and RECEIVED payments', async () => {
      await repo.createPcpcmPayment({
        providerId: PROVIDER_A,
        enrolmentId: ENROLMENT_A,
        paymentPeriodStart: '2025-01-01',
        paymentPeriodEnd: '2025-01-31',
        expectedAmount: '1500.00',
        status: 'EXPECTED',
      });
      await repo.createPcpcmPayment({
        providerId: PROVIDER_A,
        enrolmentId: ENROLMENT_A,
        paymentPeriodStart: '2025-02-01',
        paymentPeriodEnd: '2025-02-28',
        expectedAmount: '1500.00',
        actualAmount: '1500.00',
        status: 'RECEIVED',
      });
      await repo.createPcpcmPayment({
        providerId: PROVIDER_A,
        enrolmentId: ENROLMENT_A,
        paymentPeriodStart: '2025-03-01',
        paymentPeriodEnd: '2025-03-31',
        expectedAmount: '1500.00',
        actualAmount: '1500.00',
        status: 'RECONCILED',
      });

      const unreconciled = await repo.findUnreconciledPayments(PROVIDER_A);
      expect(unreconciled.length).toBe(2);
      expect(unreconciled.every((p) => ['EXPECTED', 'RECEIVED'].includes(p.status))).toBe(true);
    });

    it('should NOT return another provider payments', async () => {
      await repo.createPcpcmPayment({
        providerId: PROVIDER_A,
        enrolmentId: ENROLMENT_A,
        paymentPeriodStart: '2025-01-01',
        paymentPeriodEnd: '2025-01-31',
        expectedAmount: '1500.00',
        status: 'EXPECTED',
      });

      const unreconciled = await repo.findUnreconciledPayments(PROVIDER_B);
      expect(unreconciled.length).toBe(0);
    });
  });

  describe('findPaymentsForPeriod', () => {
    it('should find payments within date range', async () => {
      await repo.createPcpcmPayment({
        providerId: PROVIDER_A,
        enrolmentId: ENROLMENT_A,
        paymentPeriodStart: '2025-01-01',
        paymentPeriodEnd: '2025-01-31',
        expectedAmount: '1500.00',
        status: 'EXPECTED',
      });
      await repo.createPcpcmPayment({
        providerId: PROVIDER_A,
        enrolmentId: ENROLMENT_A,
        paymentPeriodStart: '2025-06-01',
        paymentPeriodEnd: '2025-06-30',
        expectedAmount: '1500.00',
        status: 'EXPECTED',
      });

      const results = await repo.findPaymentsForPeriod(
        PROVIDER_A,
        '2025-01-01',
        '2025-03-31',
      );
      expect(results.length).toBe(1);
      expect(results[0].paymentPeriodStart).toBe('2025-01-01');
    });
  });

  describe('updatePaymentStatus', () => {
    it('should update status with reconciledAt and notes', async () => {
      const created = await repo.createPcpcmPayment({
        providerId: PROVIDER_A,
        enrolmentId: ENROLMENT_A,
        paymentPeriodStart: '2025-01-01',
        paymentPeriodEnd: '2025-01-31',
        expectedAmount: '1500.00',
        actualAmount: '1500.00',
        status: 'RECEIVED',
      });

      const now = new Date();
      const updated = await repo.updatePaymentStatus(
        created.paymentId,
        PROVIDER_A,
        'RECONCILED',
        now,
        'Auto-reconciled',
      );

      expect(updated).toBeDefined();
      expect(updated!.status).toBe('RECONCILED');
      expect(updated!.reconciledAt).toBe(now);
      expect(updated!.notes).toBe('Auto-reconciled');
    });

    it('should NOT update status for a different provider', async () => {
      const created = await repo.createPcpcmPayment({
        providerId: PROVIDER_A,
        enrolmentId: ENROLMENT_A,
        paymentPeriodStart: '2025-01-01',
        paymentPeriodEnd: '2025-01-31',
        expectedAmount: '1500.00',
        status: 'EXPECTED',
      });

      const result = await repo.updatePaymentStatus(
        created.paymentId,
        PROVIDER_B,
        'RECONCILED',
      );
      expect(result).toBeUndefined();
    });
  });

  describe('updatePanelSizeOnEnrolment', () => {
    it('should update panel size on enrolment scoped by provider', async () => {
      await repo.updatePanelSizeOnEnrolment(ENROLMENT_A, PROVIDER_A, 650);

      const enrolment = enrolmentStore.find(
        (e) => e.enrolmentId === ENROLMENT_A,
      );
      expect(enrolment!.panelSize).toBe(650);
    });
  });

  describe('findEnrolmentByIdAndProvider', () => {
    it('should find enrolment for correct provider', async () => {
      const found = await repo.findEnrolmentByIdAndProvider(ENROLMENT_A, PROVIDER_A);
      expect(found).toBeDefined();
      expect(found!.enrolmentId).toBe(ENROLMENT_A);
    });

    it('should NOT find enrolment for wrong provider', async () => {
      const found = await repo.findEnrolmentByIdAndProvider(ENROLMENT_A, PROVIDER_B);
      expect(found).toBeUndefined();
    });
  });
});

// ============================================================================
// D19-022: Service Tests
// ============================================================================

describe('PcpcmPaymentService', () => {
  describe('recordPcpcmPayment', () => {
    it('should create EXPECTED payment when only expectedAmount provided', async () => {
      const result = await recordPcpcmPayment(
        serviceDeps,
        PROVIDER_A,
        {
          enrolmentId: ENROLMENT_A,
          paymentPeriodStart: '2025-01-01',
          paymentPeriodEnd: '2025-01-31',
          expectedAmount: 1500.0,
        },
        ACTOR_ID,
      );

      expect(result.status).toBe('EXPECTED');
      expect(result.expectedAmount).toBe('1500');
      expect(result.actualAmount).toBeNull();
    });

    it('should create RECEIVED payment when actualAmount provided', async () => {
      const result = await recordPcpcmPayment(
        serviceDeps,
        PROVIDER_A,
        {
          enrolmentId: ENROLMENT_A,
          paymentPeriodStart: '2025-01-01',
          paymentPeriodEnd: '2025-01-31',
          expectedAmount: 1500.0,
          actualAmount: 1500.0,
        },
        ACTOR_ID,
      );

      expect(result.status).toBe('RECEIVED');
      expect(result.actualAmount).toBe('1500');
    });

    it('should create RECEIVED payment with only actualAmount', async () => {
      const result = await recordPcpcmPayment(
        serviceDeps,
        PROVIDER_A,
        {
          enrolmentId: ENROLMENT_A,
          paymentPeriodStart: '2025-02-01',
          paymentPeriodEnd: '2025-02-28',
          actualAmount: 1200.50,
        },
        ACTOR_ID,
      );

      expect(result.status).toBe('RECEIVED');
      expect(result.actualAmount).toBe('1200.5');
    });

    it('should throw NotFoundError for non-existent enrolment', async () => {
      await expect(
        recordPcpcmPayment(
          serviceDeps,
          PROVIDER_A,
          {
            enrolmentId: '00000000-0000-0000-0000-000000000000',
            paymentPeriodStart: '2025-01-01',
            paymentPeriodEnd: '2025-01-31',
            expectedAmount: 1500.0,
          },
          ACTOR_ID,
        ),
      ).rejects.toThrow('PCPCM enrolment not found');
    });

    it('should throw NotFoundError when enrolment belongs to different provider', async () => {
      await expect(
        recordPcpcmPayment(
          serviceDeps,
          PROVIDER_B,
          {
            enrolmentId: ENROLMENT_A,
            paymentPeriodStart: '2025-01-01',
            paymentPeriodEnd: '2025-01-31',
            expectedAmount: 1500.0,
          },
          ACTOR_ID,
        ),
      ).rejects.toThrow('PCPCM enrolment not found');
    });

    it('should include notes and panelSizeAtPayment when provided', async () => {
      const result = await recordPcpcmPayment(
        serviceDeps,
        PROVIDER_A,
        {
          enrolmentId: ENROLMENT_A,
          paymentPeriodStart: '2025-01-01',
          paymentPeriodEnd: '2025-01-31',
          expectedAmount: 1500.0,
          panelSizeAtPayment: 500,
          notes: 'Q1 capitation',
        },
        ACTOR_ID,
      );

      expect(result.panelSizeAtPayment).toBe(500);
      expect(result.notes).toBe('Q1 capitation');
    });
  });

  // --------------------------------------------------------------------------
  // Reconciliation Tests
  // --------------------------------------------------------------------------

  describe('reconcilePcpcmPayments', () => {
    it('should reconcile payments matching within $0.01 tolerance', async () => {
      await recordPcpcmPayment(
        serviceDeps,
        PROVIDER_A,
        {
          enrolmentId: ENROLMENT_A,
          paymentPeriodStart: '2025-01-01',
          paymentPeriodEnd: '2025-01-31',
          expectedAmount: 1500.0,
          actualAmount: 1500.005,
        },
        ACTOR_ID,
      );

      const result = await reconcilePcpcmPayments(serviceDeps, PROVIDER_A, ACTOR_ID);

      expect(result.reconciled).toBe(1);
      expect(result.discrepancies).toBe(0);
      expect(result.details[0].status).toBe('RECONCILED');
    });

    it('should flag discrepancy when amounts differ by more than $0.01', async () => {
      await recordPcpcmPayment(
        serviceDeps,
        PROVIDER_A,
        {
          enrolmentId: ENROLMENT_A,
          paymentPeriodStart: '2025-01-01',
          paymentPeriodEnd: '2025-01-31',
          expectedAmount: 1500.0,
          actualAmount: 1450.0,
        },
        ACTOR_ID,
      );

      const result = await reconcilePcpcmPayments(serviceDeps, PROVIDER_A, ACTOR_ID);

      expect(result.reconciled).toBe(0);
      expect(result.discrepancies).toBe(1);
      expect(result.details[0].status).toBe('DISCREPANCY');
      expect(result.details[0].difference).toBe(50.0);
    });

    it('should skip payments with only expectedAmount (no actualAmount)', async () => {
      await recordPcpcmPayment(
        serviceDeps,
        PROVIDER_A,
        {
          enrolmentId: ENROLMENT_A,
          paymentPeriodStart: '2025-01-01',
          paymentPeriodEnd: '2025-01-31',
          expectedAmount: 1500.0,
        },
        ACTOR_ID,
      );

      const result = await reconcilePcpcmPayments(serviceDeps, PROVIDER_A, ACTOR_ID);

      expect(result.reconciled).toBe(0);
      expect(result.discrepancies).toBe(0);
      expect(result.details.length).toBe(0);
    });

    it('should skip payments with only actualAmount (no expectedAmount)', async () => {
      await recordPcpcmPayment(
        serviceDeps,
        PROVIDER_A,
        {
          enrolmentId: ENROLMENT_A,
          paymentPeriodStart: '2025-01-01',
          paymentPeriodEnd: '2025-01-31',
          actualAmount: 1500.0,
        },
        ACTOR_ID,
      );

      const result = await reconcilePcpcmPayments(serviceDeps, PROVIDER_A, ACTOR_ID);

      expect(result.reconciled).toBe(0);
      expect(result.discrepancies).toBe(0);
      expect(result.details.length).toBe(0);
    });

    it('should handle multi-period reconciliation (mixed results)', async () => {
      // Period 1: exact match
      await recordPcpcmPayment(
        serviceDeps,
        PROVIDER_A,
        {
          enrolmentId: ENROLMENT_A,
          paymentPeriodStart: '2025-01-01',
          paymentPeriodEnd: '2025-01-31',
          expectedAmount: 1500.0,
          actualAmount: 1500.0,
        },
        ACTOR_ID,
      );

      // Period 2: discrepancy
      await recordPcpcmPayment(
        serviceDeps,
        PROVIDER_A,
        {
          enrolmentId: ENROLMENT_A,
          paymentPeriodStart: '2025-02-01',
          paymentPeriodEnd: '2025-02-28',
          expectedAmount: 1500.0,
          actualAmount: 1400.0,
        },
        ACTOR_ID,
      );

      // Period 3: expected only (skip)
      await recordPcpcmPayment(
        serviceDeps,
        PROVIDER_A,
        {
          enrolmentId: ENROLMENT_A,
          paymentPeriodStart: '2025-03-01',
          paymentPeriodEnd: '2025-03-31',
          expectedAmount: 1500.0,
        },
        ACTOR_ID,
      );

      const result = await reconcilePcpcmPayments(serviceDeps, PROVIDER_A, ACTOR_ID);

      expect(result.reconciled).toBe(1);
      expect(result.discrepancies).toBe(1);
      expect(result.details.length).toBe(2);
    });

    it('should return zeros when no unreconciled payments exist', async () => {
      const result = await reconcilePcpcmPayments(serviceDeps, PROVIDER_A, ACTOR_ID);
      expect(result.reconciled).toBe(0);
      expect(result.discrepancies).toBe(0);
      expect(result.details.length).toBe(0);
    });

    it('should NOT reconcile payments belonging to different provider', async () => {
      // Create payment for Provider A
      await recordPcpcmPayment(
        serviceDeps,
        PROVIDER_A,
        {
          enrolmentId: ENROLMENT_A,
          paymentPeriodStart: '2025-01-01',
          paymentPeriodEnd: '2025-01-31',
          expectedAmount: 1500.0,
          actualAmount: 1500.0,
        },
        ACTOR_ID,
      );

      // Try reconciling as Provider B
      const result = await reconcilePcpcmPayments(serviceDeps, PROVIDER_B, ACTOR_ID);

      expect(result.reconciled).toBe(0);
      expect(result.discrepancies).toBe(0);
    });

    it('should reconcile exactly at $0.01 tolerance boundary', async () => {
      await recordPcpcmPayment(
        serviceDeps,
        PROVIDER_A,
        {
          enrolmentId: ENROLMENT_A,
          paymentPeriodStart: '2025-01-01',
          paymentPeriodEnd: '2025-01-31',
          expectedAmount: 1500.0,
          actualAmount: 1500.01,
        },
        ACTOR_ID,
      );

      const result = await reconcilePcpcmPayments(serviceDeps, PROVIDER_A, ACTOR_ID);
      expect(result.reconciled).toBe(1);
      expect(result.discrepancies).toBe(0);
    });

    it('should flag discrepancy just beyond $0.01 tolerance', async () => {
      await recordPcpcmPayment(
        serviceDeps,
        PROVIDER_A,
        {
          enrolmentId: ENROLMENT_A,
          paymentPeriodStart: '2025-01-01',
          paymentPeriodEnd: '2025-01-31',
          expectedAmount: 1500.0,
          actualAmount: 1500.02,
        },
        ACTOR_ID,
      );

      const result = await reconcilePcpcmPayments(serviceDeps, PROVIDER_A, ACTOR_ID);
      expect(result.reconciled).toBe(0);
      expect(result.discrepancies).toBe(1);
    });
  });

  // --------------------------------------------------------------------------
  // getPcpcmPaymentHistory
  // --------------------------------------------------------------------------

  describe('getPcpcmPaymentHistory', () => {
    it('should return paginated payment history', async () => {
      for (let i = 1; i <= 5; i++) {
        await recordPcpcmPayment(
          serviceDeps,
          PROVIDER_A,
          {
            enrolmentId: ENROLMENT_A,
            paymentPeriodStart: `2025-0${i}-01`,
            paymentPeriodEnd: `2025-0${i}-28`,
            expectedAmount: 1500.0,
          },
          ACTOR_ID,
        );
      }

      const result = await getPcpcmPaymentHistory(serviceDeps, PROVIDER_A, {
        page: 1,
        pageSize: 3,
      });

      expect(result.data.length).toBe(3);
      expect(result.pagination.total).toBe(5);
      expect(result.pagination.page).toBe(1);
      expect(result.pagination.pageSize).toBe(3);
      expect(result.pagination.hasMore).toBe(true);
    });

    it('should return hasMore=false on last page', async () => {
      for (let i = 1; i <= 3; i++) {
        await recordPcpcmPayment(
          serviceDeps,
          PROVIDER_A,
          {
            enrolmentId: ENROLMENT_A,
            paymentPeriodStart: `2025-0${i}-01`,
            paymentPeriodEnd: `2025-0${i}-28`,
            expectedAmount: 1500.0,
          },
          ACTOR_ID,
        );
      }

      const result = await getPcpcmPaymentHistory(serviceDeps, PROVIDER_A, {
        page: 1,
        pageSize: 20,
      });

      expect(result.data.length).toBe(3);
      expect(result.pagination.hasMore).toBe(false);
    });

    it('should filter by status', async () => {
      await recordPcpcmPayment(
        serviceDeps,
        PROVIDER_A,
        {
          enrolmentId: ENROLMENT_A,
          paymentPeriodStart: '2025-01-01',
          paymentPeriodEnd: '2025-01-31',
          expectedAmount: 1500.0,
        },
        ACTOR_ID,
      );
      await recordPcpcmPayment(
        serviceDeps,
        PROVIDER_A,
        {
          enrolmentId: ENROLMENT_A,
          paymentPeriodStart: '2025-02-01',
          paymentPeriodEnd: '2025-02-28',
          actualAmount: 1500.0,
        },
        ACTOR_ID,
      );

      const result = await getPcpcmPaymentHistory(serviceDeps, PROVIDER_A, {
        status: 'EXPECTED',
      });

      expect(result.data.length).toBe(1);
      expect(result.data[0].status).toBe('EXPECTED');
    });

    it('should use default page and pageSize when not provided', async () => {
      const result = await getPcpcmPaymentHistory(serviceDeps, PROVIDER_A);

      expect(result.pagination.page).toBe(1);
      expect(result.pagination.pageSize).toBe(20);
    });
  });

  // --------------------------------------------------------------------------
  // updatePanelSize
  // --------------------------------------------------------------------------

  describe('updatePanelSize', () => {
    it('should update panel size for valid enrolment', async () => {
      await updatePanelSize(serviceDeps, PROVIDER_A, ENROLMENT_A, 650, ACTOR_ID);

      const enrolment = enrolmentStore.find(
        (e) => e.enrolmentId === ENROLMENT_A,
      );
      expect(enrolment!.panelSize).toBe(650);
    });

    it('should throw BusinessRuleError for zero panel size', async () => {
      await expect(
        updatePanelSize(serviceDeps, PROVIDER_A, ENROLMENT_A, 0, ACTOR_ID),
      ).rejects.toThrow('Panel size must be a positive integer');
    });

    it('should throw BusinessRuleError for negative panel size', async () => {
      await expect(
        updatePanelSize(serviceDeps, PROVIDER_A, ENROLMENT_A, -5, ACTOR_ID),
      ).rejects.toThrow('Panel size must be a positive integer');
    });

    it('should throw BusinessRuleError for non-integer panel size', async () => {
      await expect(
        updatePanelSize(serviceDeps, PROVIDER_A, ENROLMENT_A, 3.5, ACTOR_ID),
      ).rejects.toThrow('Panel size must be a positive integer');
    });

    it('should throw NotFoundError for non-existent enrolment', async () => {
      await expect(
        updatePanelSize(
          serviceDeps,
          PROVIDER_A,
          '00000000-0000-0000-0000-000000000000',
          500,
          ACTOR_ID,
        ),
      ).rejects.toThrow('PCPCM enrolment not found');
    });

    it('should throw NotFoundError when enrolment belongs to different provider', async () => {
      await expect(
        updatePanelSize(serviceDeps, PROVIDER_B, ENROLMENT_A, 500, ACTOR_ID),
      ).rejects.toThrow('PCPCM enrolment not found');
    });
  });
});

// ============================================================================
// D19-023: Zod Input Validation Tests
// ============================================================================

describe('PCPCM Zod Schemas', () => {
  describe('createPcpcmPaymentSchema', () => {
    it('should accept valid payment with expectedAmount', () => {
      const result = createPcpcmPaymentSchema.safeParse({
        enrolmentId: ENROLMENT_A,
        paymentPeriodStart: '2025-01-01',
        paymentPeriodEnd: '2025-01-31',
        expectedAmount: 1500.0,
      });
      expect(result.success).toBe(true);
    });

    it('should accept valid payment with actualAmount', () => {
      const result = createPcpcmPaymentSchema.safeParse({
        enrolmentId: ENROLMENT_A,
        paymentPeriodStart: '2025-01-01',
        paymentPeriodEnd: '2025-01-31',
        actualAmount: 1500.0,
      });
      expect(result.success).toBe(true);
    });

    it('should accept both expectedAmount and actualAmount', () => {
      const result = createPcpcmPaymentSchema.safeParse({
        enrolmentId: ENROLMENT_A,
        paymentPeriodStart: '2025-01-01',
        paymentPeriodEnd: '2025-01-31',
        expectedAmount: 1500.0,
        actualAmount: 1500.0,
      });
      expect(result.success).toBe(true);
    });

    it('should reject when neither expectedAmount nor actualAmount provided', () => {
      const result = createPcpcmPaymentSchema.safeParse({
        enrolmentId: ENROLMENT_A,
        paymentPeriodStart: '2025-01-01',
        paymentPeriodEnd: '2025-01-31',
      });
      expect(result.success).toBe(false);
    });

    it('should reject invalid date format', () => {
      const result = createPcpcmPaymentSchema.safeParse({
        enrolmentId: ENROLMENT_A,
        paymentPeriodStart: '01-01-2025',
        paymentPeriodEnd: '2025-01-31',
        expectedAmount: 1500.0,
      });
      expect(result.success).toBe(false);
    });

    it('should reject invalid UUID for enrolmentId', () => {
      const result = createPcpcmPaymentSchema.safeParse({
        enrolmentId: 'not-a-uuid',
        paymentPeriodStart: '2025-01-01',
        paymentPeriodEnd: '2025-01-31',
        expectedAmount: 1500.0,
      });
      expect(result.success).toBe(false);
    });

    it('should reject negative expectedAmount', () => {
      const result = createPcpcmPaymentSchema.safeParse({
        enrolmentId: ENROLMENT_A,
        paymentPeriodStart: '2025-01-01',
        paymentPeriodEnd: '2025-01-31',
        expectedAmount: -100.0,
      });
      expect(result.success).toBe(false);
    });

    it('should reject negative actualAmount', () => {
      const result = createPcpcmPaymentSchema.safeParse({
        enrolmentId: ENROLMENT_A,
        paymentPeriodStart: '2025-01-01',
        paymentPeriodEnd: '2025-01-31',
        actualAmount: -100.0,
      });
      expect(result.success).toBe(false);
    });

    it('should reject zero expectedAmount', () => {
      const result = createPcpcmPaymentSchema.safeParse({
        enrolmentId: ENROLMENT_A,
        paymentPeriodStart: '2025-01-01',
        paymentPeriodEnd: '2025-01-31',
        expectedAmount: 0,
      });
      expect(result.success).toBe(false);
    });

    it('should reject notes exceeding 1000 characters', () => {
      const result = createPcpcmPaymentSchema.safeParse({
        enrolmentId: ENROLMENT_A,
        paymentPeriodStart: '2025-01-01',
        paymentPeriodEnd: '2025-01-31',
        expectedAmount: 1500.0,
        notes: 'x'.repeat(1001),
      });
      expect(result.success).toBe(false);
    });

    it('should accept notes up to 1000 characters', () => {
      const result = createPcpcmPaymentSchema.safeParse({
        enrolmentId: ENROLMENT_A,
        paymentPeriodStart: '2025-01-01',
        paymentPeriodEnd: '2025-01-31',
        expectedAmount: 1500.0,
        notes: 'x'.repeat(1000),
      });
      expect(result.success).toBe(true);
    });

    it('should reject non-integer panelSizeAtPayment', () => {
      const result = createPcpcmPaymentSchema.safeParse({
        enrolmentId: ENROLMENT_A,
        paymentPeriodStart: '2025-01-01',
        paymentPeriodEnd: '2025-01-31',
        expectedAmount: 1500.0,
        panelSizeAtPayment: 3.5,
      });
      expect(result.success).toBe(false);
    });
  });

  describe('listPcpcmPaymentsQuerySchema', () => {
    it('should accept valid query with all filters', () => {
      const result = listPcpcmPaymentsQuerySchema.safeParse({
        status: 'EXPECTED',
        periodStart: '2025-01-01',
        periodEnd: '2025-12-31',
        page: 1,
        pageSize: 10,
      });
      expect(result.success).toBe(true);
    });

    it('should accept empty query (defaults)', () => {
      const result = listPcpcmPaymentsQuerySchema.safeParse({});
      expect(result.success).toBe(true);
      expect(result.data!.page).toBe(1);
      expect(result.data!.pageSize).toBe(20);
    });

    it('should reject invalid status', () => {
      const result = listPcpcmPaymentsQuerySchema.safeParse({
        status: 'INVALID_STATUS',
      });
      expect(result.success).toBe(false);
    });

    it('should reject pageSize exceeding 100', () => {
      const result = listPcpcmPaymentsQuerySchema.safeParse({
        pageSize: 101,
      });
      expect(result.success).toBe(false);
    });

    it('should coerce string page numbers', () => {
      const result = listPcpcmPaymentsQuerySchema.safeParse({
        page: '3',
        pageSize: '10',
      });
      expect(result.success).toBe(true);
      expect(result.data!.page).toBe(3);
      expect(result.data!.pageSize).toBe(10);
    });
  });

  describe('updatePanelSizeSchema', () => {
    it('should accept valid panel size update', () => {
      const result = updatePanelSizeSchema.safeParse({
        enrolmentId: ENROLMENT_A,
        panelSize: 500,
      });
      expect(result.success).toBe(true);
    });

    it('should reject zero panel size', () => {
      const result = updatePanelSizeSchema.safeParse({
        enrolmentId: ENROLMENT_A,
        panelSize: 0,
      });
      expect(result.success).toBe(false);
    });

    it('should reject negative panel size', () => {
      const result = updatePanelSizeSchema.safeParse({
        enrolmentId: ENROLMENT_A,
        panelSize: -10,
      });
      expect(result.success).toBe(false);
    });

    it('should reject non-integer panel size', () => {
      const result = updatePanelSizeSchema.safeParse({
        enrolmentId: ENROLMENT_A,
        panelSize: 3.7,
      });
      expect(result.success).toBe(false);
    });

    it('should reject invalid UUID', () => {
      const result = updatePanelSizeSchema.safeParse({
        enrolmentId: 'not-valid',
        panelSize: 500,
      });
      expect(result.success).toBe(false);
    });

    it('should reject missing panelSize', () => {
      const result = updatePanelSizeSchema.safeParse({
        enrolmentId: ENROLMENT_A,
      });
      expect(result.success).toBe(false);
    });

    it('should reject missing enrolmentId', () => {
      const result = updatePanelSizeSchema.safeParse({
        panelSize: 500,
      });
      expect(result.success).toBe(false);
    });
  });
});

// ============================================================================
// D19-024: Physician Scoping / Tenant Isolation Tests
// ============================================================================

describe('Physician Scoping (Tenant Isolation)', () => {
  it('Provider A cannot see Provider B payments', async () => {
    // Create payment for Provider A
    await recordPcpcmPayment(
      serviceDeps,
      PROVIDER_A,
      {
        enrolmentId: ENROLMENT_A,
        paymentPeriodStart: '2025-01-01',
        paymentPeriodEnd: '2025-01-31',
        expectedAmount: 1500.0,
      },
      ACTOR_ID,
    );

    // Query as Provider B
    const result = await getPcpcmPaymentHistory(serviceDeps, PROVIDER_B);
    expect(result.data.length).toBe(0);
    expect(result.pagination.total).toBe(0);
  });

  it('Provider A cannot reconcile Provider B payments', async () => {
    // Create payment for Provider A
    await recordPcpcmPayment(
      serviceDeps,
      PROVIDER_A,
      {
        enrolmentId: ENROLMENT_A,
        paymentPeriodStart: '2025-01-01',
        paymentPeriodEnd: '2025-01-31',
        expectedAmount: 1500.0,
        actualAmount: 1500.0,
      },
      ACTOR_ID,
    );

    // Try to reconcile as Provider B
    const result = await reconcilePcpcmPayments(serviceDeps, PROVIDER_B, ACTOR_ID);
    expect(result.reconciled).toBe(0);
    expect(result.discrepancies).toBe(0);

    // Provider A's payment should still be RECEIVED (not reconciled)
    const providerAResult = await getPcpcmPaymentHistory(serviceDeps, PROVIDER_A);
    expect(providerAResult.data[0].status).toBe('RECEIVED');
  });

  it('Provider B cannot update Provider A enrolment panel size', async () => {
    await expect(
      updatePanelSize(serviceDeps, PROVIDER_B, ENROLMENT_A, 999, ACTOR_ID),
    ).rejects.toThrow('PCPCM enrolment not found');

    // Verify Provider A's enrolment is unchanged
    const enrolment = enrolmentStore.find(
      (e) => e.enrolmentId === ENROLMENT_A,
    );
    expect(enrolment!.panelSize).toBe(500);
  });

  it('Provider B cannot record payment against Provider A enrolment', async () => {
    await expect(
      recordPcpcmPayment(
        serviceDeps,
        PROVIDER_B,
        {
          enrolmentId: ENROLMENT_A,
          paymentPeriodStart: '2025-01-01',
          paymentPeriodEnd: '2025-01-31',
          expectedAmount: 1500.0,
        },
        ACTOR_ID,
      ),
    ).rejects.toThrow('PCPCM enrolment not found');
  });
});
