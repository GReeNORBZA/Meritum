import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  createReferralCodeRepository,
  createReferralRedemptionRepository,
} from './referral.repository.js';
import {
  generateReferralCode,
  redeemReferralCode,
  checkReferralQualification,
  applyReferralCredit,
  applyDefaultCreditChoice,
  shouldApplyRefereeIncentive,
  type ReferralServiceDeps,
  type Stripe,
} from './referral.service.js';

// ---------------------------------------------------------------------------
// In-memory stores
// ---------------------------------------------------------------------------

let referralCodeStore: Record<string, any>[];
let referralRedemptionStore: Record<string, any>[];

// ---------------------------------------------------------------------------
// Mock Drizzle DB
// ---------------------------------------------------------------------------

function makeMockDb() {
  function getStoreForTable(table: any): Record<string, any>[] {
    if (table?.__table === 'referral_codes') return referralCodeStore;
    if (table?.__table === 'referral_redemptions') return referralRedemptionStore;
    return [];
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

    if (table?.__table === 'referral_codes') {
      const existing = store.find((r) => r.code === values.code);
      if (existing) {
        const err: any = new Error(
          'duplicate key value violates unique constraint "referral_codes_code_idx"',
        );
        err.code = '23505';
        throw err;
      }
      const newCode = {
        referralCodeId: values.referralCodeId ?? crypto.randomUUID(),
        referrerUserId: values.referrerUserId,
        code: values.code,
        isActive: values.isActive ?? true,
        createdAt: values.createdAt ?? new Date(),
      };
      store.push(newCode);
      return newCode;
    }

    if (table?.__table === 'referral_redemptions') {
      const newRedemption = {
        redemptionId: values.redemptionId ?? crypto.randomUUID(),
        referralCodeId: values.referralCodeId,
        referrerUserId: values.referrerUserId,
        referredUserId: values.referredUserId,
        status: values.status ?? 'PENDING',
        creditMonthValueCad: values.creditMonthValueCad ?? null,
        creditAppliedTo: values.creditAppliedTo ?? null,
        creditAppliedAt: values.creditAppliedAt ?? null,
        qualifyingEventAt: values.qualifyingEventAt ?? null,
        anniversaryYear: values.anniversaryYear,
        createdAt: values.createdAt ?? new Date(),
      };
      store.push(newRedemption);
      return newRedemption;
    }

    return values;
  }

  function executeOp(ctx: any): any {
    const store = getStoreForTable(ctx.table);

    switch (ctx.op) {
      case 'insert': {
        const row = insertRow(ctx.table, ctx.values);
        return [row];
      }
      case 'select': {
        let rows = [...store];
        for (const pred of ctx.whereClauses) {
          rows = rows.filter(pred);
        }

        if (ctx.selectFields) {
          const fieldKeys = Object.keys(ctx.selectFields);
          const hasAggregate = fieldKeys.some(
            (k) => ctx.selectFields[k]?.__aggregate,
          );
          if (hasAggregate) {
            const result: Record<string, any> = {};
            for (const key of fieldKeys) {
              const field = ctx.selectFields[key];
              if (field?.__aggregate === 'count') {
                result[key] = rows.length;
              } else if (field?.__aggregate === 'sum') {
                const colName = field.__column;
                result[key] = rows
                  .reduce(
                    (acc: number, r: any) =>
                      acc + parseFloat(r[colName] ?? '0'),
                    0,
                  )
                  .toFixed(2);
              } else if (field?.__aggregate === 'max') {
                const colName = field.__column;
                let maxVal: any = null;
                for (const r of rows) {
                  if (r[colName] != null) {
                    if (maxVal == null || r[colName] > maxVal)
                      maxVal = r[colName];
                  }
                }
                result[key] = maxVal;
              }
            }
            return [result];
          }
        }

        if (ctx.orderByFn) {
          rows.sort(ctx.orderByFn);
        }
        if (ctx.offsetN) {
          rows = rows.slice(ctx.offsetN);
        }
        if (ctx.limitN) {
          rows = rows.slice(0, ctx.limitN);
        }
        return rows;
      }
      case 'update': {
        const updated: any[] = [];
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
    ne: (column: any, value: any) => {
      const colName = column?.name;
      return {
        __predicate: (row: any) => row[colName] !== value,
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
          if (rowVal instanceof Date && value instanceof Date) {
            return rowVal.getTime() <= value.getTime();
          }
          return rowVal <= value;
        },
      };
    },
    desc: (column: any) => {
      const colName = column?.name;
      return {
        __orderBy: (a: any, b: any) => {
          const aVal = a[colName];
          const bVal = b[colName];
          if (aVal instanceof Date && bVal instanceof Date) {
            return bVal.getTime() - aVal.getTime();
          }
          if (aVal < bVal) return 1;
          if (aVal > bVal) return -1;
          return 0;
        },
      };
    },
    asc: (column: any) => {
      const colName = column?.name;
      return {
        __orderBy: (a: any, b: any) => {
          const aVal = a[colName];
          const bVal = b[colName];
          if (aVal instanceof Date && bVal instanceof Date) {
            return aVal.getTime() - bVal.getTime();
          }
          if (typeof aVal === 'number' && typeof bVal === 'number') {
            return aVal - bVal;
          }
          if (aVal < bVal) return -1;
          if (aVal > bVal) return 1;
          return 0;
        },
      };
    },
    count: () => ({ __aggregate: 'count' }),
    sum: (column: any) => ({
      __aggregate: 'sum',
      __column: column?.name,
    }),
    max: (column: any) => ({
      __aggregate: 'max',
      __column: column?.name,
    }),
    inArray: (column: any, values: any[]) => {
      const colName = column?.name;
      return {
        __predicate: (row: any) => values.includes(row[colName]),
      };
    },
    sql: (strings: TemplateStringsArray, ...values: any[]) => {
      const raw = strings.join('__PLACEHOLDER__');

      if (raw.includes('IN (')) {
        const col = values[0];
        const colName = col?.name;
        const inMatch = raw.match(/IN \(([^)]+)\)/);
        if (inMatch) {
          const inValues = inMatch[1]
            .split(',')
            .map((s: string) => s.trim().replace(/'/g, ''));
          return {
            __predicate: (row: any) => inValues.includes(row[colName]),
            __sqlExpr: () => null,
          };
        }
      }

      return { __sqlExpr: () => null };
    },
  };
});

// Mock the schema module
vi.mock('@meritum/shared/schemas/db/platform.schema.js', () => {
  const makeCol = (name: string) => ({ name });

  const referralCodesProxy: any = {
    __table: 'referral_codes',
    referralCodeId: makeCol('referralCodeId'),
    referrerUserId: makeCol('referrerUserId'),
    code: makeCol('code'),
    isActive: makeCol('isActive'),
    createdAt: makeCol('createdAt'),
  };

  const referralRedemptionsProxy: any = {
    __table: 'referral_redemptions',
    redemptionId: makeCol('redemptionId'),
    referralCodeId: makeCol('referralCodeId'),
    referrerUserId: makeCol('referrerUserId'),
    referredUserId: makeCol('referredUserId'),
    status: makeCol('status'),
    creditMonthValueCad: makeCol('creditMonthValueCad'),
    creditAppliedTo: makeCol('creditAppliedTo'),
    creditAppliedAt: makeCol('creditAppliedAt'),
    qualifyingEventAt: makeCol('qualifyingEventAt'),
    anniversaryYear: makeCol('anniversaryYear'),
    createdAt: makeCol('createdAt'),
  };

  return {
    referralCodes: referralCodesProxy,
    referralRedemptions: referralRedemptionsProxy,
  };
});

// Mock constants
vi.mock('@meritum/shared/constants/platform.constants.js', () => ({
  REFERRAL_CODE_LENGTH: 8,
  REFERRAL_MAX_CREDITS_PER_YEAR: 3,
  REFERRAL_CREDIT_CHOICE_DEADLINE_DAYS: 7,
  EARLY_BIRD_CAP: 100,
  SubscriptionPlan: {
    STANDARD_MONTHLY: 'STANDARD_MONTHLY',
    STANDARD_ANNUAL: 'STANDARD_ANNUAL',
    EARLY_BIRD_MONTHLY: 'EARLY_BIRD_MONTHLY',
    EARLY_BIRD_ANNUAL: 'EARLY_BIRD_ANNUAL',
    CLINIC_MONTHLY: 'CLINIC_MONTHLY',
    CLINIC_ANNUAL: 'CLINIC_ANNUAL',
  },
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const DAY_MS = 24 * 60 * 60 * 1000;

function makeReferralCode(overrides: Partial<Record<string, any>> = {}) {
  return {
    referralCodeId: overrides.referralCodeId ?? crypto.randomUUID(),
    referrerUserId: overrides.referrerUserId ?? crypto.randomUUID(),
    code: overrides.code ?? 'ABCD1234',
    isActive: overrides.isActive ?? true,
    createdAt: overrides.createdAt ?? new Date(),
  };
}

function makeRedemption(overrides: Partial<Record<string, any>> = {}) {
  return {
    redemptionId: overrides.redemptionId ?? crypto.randomUUID(),
    referralCodeId: overrides.referralCodeId ?? crypto.randomUUID(),
    referrerUserId: overrides.referrerUserId ?? crypto.randomUUID(),
    referredUserId: overrides.referredUserId ?? crypto.randomUUID(),
    status: overrides.status ?? 'PENDING',
    creditMonthValueCad: overrides.creditMonthValueCad ?? null,
    creditAppliedTo: overrides.creditAppliedTo ?? null,
    creditAppliedAt: overrides.creditAppliedAt ?? null,
    qualifyingEventAt: overrides.qualifyingEventAt ?? null,
    anniversaryYear: overrides.anniversaryYear ?? 1,
    createdAt: overrides.createdAt ?? new Date(),
  };
}

// ---------------------------------------------------------------------------
// Mock deps factory for service tests
// ---------------------------------------------------------------------------

function makeMockDeps(overrides?: Partial<ReferralServiceDeps>): ReferralServiceDeps {
  return {
    referralCodeRepo: {
      createReferralCode: vi.fn(),
      findReferralCodeByCode: vi.fn(),
      findReferralCodeByUserId: vi.fn(),
      deactivateReferralCode: vi.fn(),
    } as any,
    referralRedemptionRepo: {
      createRedemption: vi.fn(),
      findPendingByReferredUser: vi.fn(),
      countQualifiedOrCreditedByReferrerAndYear: vi.fn(),
      updateRedemptionStatus: vi.fn(),
      findRedemptionsByReferrer: vi.fn(),
      findPendingRedemptions: vi.fn(),
      findQualifiedRedemptions: vi.fn(),
      findRedemptionById: vi.fn(),
    } as any,
    subscriptionRepo: {
      findSubscriptionByProviderId: vi.fn(),
      getActivePracticeMembership: vi.fn(),
      countEarlyBirdSubscriptions: vi.fn(),
    } as any,
    paymentRepo: {
      listPaymentsForSubscription: vi.fn(),
    } as any,
    stripe: {
      invoiceItems: {
        create: vi.fn().mockResolvedValue({ id: 'ii_mock' }),
      },
    } as any,
    ...overrides,
  };
}

// ============================================================================
// Repository Tests
// ============================================================================

describe('Referral Code Repository', () => {
  let repo: ReturnType<typeof createReferralCodeRepository>;

  beforeEach(() => {
    referralCodeStore = [];
    referralRedemptionStore = [];
    const db = makeMockDb();
    repo = createReferralCodeRepository(db);
  });

  it('createReferralCode inserts a new referral code', async () => {
    const userId = crypto.randomUUID();
    const result = await repo.createReferralCode(userId, 'TESTCODE');

    expect(result).toBeDefined();
    expect(result.referralCodeId).toBeDefined();
    expect(result.referrerUserId).toBe(userId);
    expect(result.code).toBe('TESTCODE');
    expect(result.isActive).toBe(true);
    expect(referralCodeStore).toHaveLength(1);
  });

  it('createReferralCode throws on duplicate code', async () => {
    const userId1 = crypto.randomUUID();
    const userId2 = crypto.randomUUID();
    await repo.createReferralCode(userId1, 'DUPE1234');

    await expect(
      repo.createReferralCode(userId2, 'DUPE1234'),
    ).rejects.toThrow('duplicate key');
  });

  it('findReferralCodeByCode returns the correct code', async () => {
    const userId = crypto.randomUUID();
    await repo.createReferralCode(userId, 'FIND1234');

    const found = await repo.findReferralCodeByCode('FIND1234');
    expect(found).toBeDefined();
    expect(found!.code).toBe('FIND1234');
    expect(found!.referrerUserId).toBe(userId);
  });

  it('findReferralCodeByCode returns undefined for missing code', async () => {
    const found = await repo.findReferralCodeByCode('NOPE0000');
    expect(found).toBeUndefined();
  });

  it('findReferralCodeByUserId returns active code for user', async () => {
    const userId = crypto.randomUUID();
    await repo.createReferralCode(userId, 'USER1234');

    const found = await repo.findReferralCodeByUserId(userId);
    expect(found).toBeDefined();
    expect(found!.referrerUserId).toBe(userId);
    expect(found!.isActive).toBe(true);
  });

  it('findReferralCodeByUserId returns undefined when code is deactivated', async () => {
    const userId = crypto.randomUUID();
    const created = await repo.createReferralCode(userId, 'DEAC1234');
    await repo.deactivateReferralCode(created.referralCodeId);

    const found = await repo.findReferralCodeByUserId(userId);
    expect(found).toBeUndefined();
  });

  it('deactivateReferralCode sets isActive to false', async () => {
    const userId = crypto.randomUUID();
    const created = await repo.createReferralCode(userId, 'DEACT123');
    const result = await repo.deactivateReferralCode(created.referralCodeId);

    expect(result).toBeDefined();
    expect(result!.isActive).toBe(false);
  });
});

describe('Referral Redemption Repository', () => {
  let repo: ReturnType<typeof createReferralRedemptionRepository>;

  beforeEach(() => {
    referralCodeStore = [];
    referralRedemptionStore = [];
    const db = makeMockDb();
    repo = createReferralRedemptionRepository(db);
  });

  it('createRedemption inserts with PENDING status', async () => {
    const data = {
      referralCodeId: crypto.randomUUID(),
      referrerUserId: crypto.randomUUID(),
      referredUserId: crypto.randomUUID(),
      anniversaryYear: 1,
    };
    const result = await repo.createRedemption(data);

    expect(result).toBeDefined();
    expect(result.redemptionId).toBeDefined();
    expect(result.status).toBe('PENDING');
    expect(result.referralCodeId).toBe(data.referralCodeId);
    expect(result.referrerUserId).toBe(data.referrerUserId);
    expect(result.referredUserId).toBe(data.referredUserId);
    expect(result.anniversaryYear).toBe(1);
    expect(referralRedemptionStore).toHaveLength(1);
  });

  it('findPendingByReferredUser returns PENDING redemption', async () => {
    const referredUserId = crypto.randomUUID();
    await repo.createRedemption({
      referralCodeId: crypto.randomUUID(),
      referrerUserId: crypto.randomUUID(),
      referredUserId,
      anniversaryYear: 1,
    });

    const found = await repo.findPendingByReferredUser(referredUserId);
    expect(found).toBeDefined();
    expect(found!.referredUserId).toBe(referredUserId);
    expect(found!.status).toBe('PENDING');
  });

  it('findPendingByReferredUser returns undefined when no PENDING', async () => {
    const referredUserId = crypto.randomUUID();
    const created = await repo.createRedemption({
      referralCodeId: crypto.randomUUID(),
      referrerUserId: crypto.randomUUID(),
      referredUserId,
      anniversaryYear: 1,
    });
    await repo.updateRedemptionStatus(created.redemptionId, {
      status: 'QUALIFIED',
    });

    const found = await repo.findPendingByReferredUser(referredUserId);
    expect(found).toBeUndefined();
  });

  it('countQualifiedOrCreditedByReferrerAndYear counts correctly', async () => {
    const referrerUserId = crypto.randomUUID();
    const r1 = await repo.createRedemption({
      referralCodeId: crypto.randomUUID(),
      referrerUserId,
      referredUserId: crypto.randomUUID(),
      anniversaryYear: 1,
    });
    await repo.updateRedemptionStatus(r1.redemptionId, {
      status: 'QUALIFIED',
    });

    const r2 = await repo.createRedemption({
      referralCodeId: crypto.randomUUID(),
      referrerUserId,
      referredUserId: crypto.randomUUID(),
      anniversaryYear: 1,
    });
    await repo.updateRedemptionStatus(r2.redemptionId, {
      status: 'CREDITED',
    });

    // PENDING should not be counted
    await repo.createRedemption({
      referralCodeId: crypto.randomUUID(),
      referrerUserId,
      referredUserId: crypto.randomUUID(),
      anniversaryYear: 1,
    });

    const count = await repo.countQualifiedOrCreditedByReferrerAndYear(
      referrerUserId,
      1,
    );
    expect(count).toBe(2);
  });

  it('countQualifiedOrCreditedByReferrerAndYear filters by year', async () => {
    const referrerUserId = crypto.randomUUID();
    const r1 = await repo.createRedemption({
      referralCodeId: crypto.randomUUID(),
      referrerUserId,
      referredUserId: crypto.randomUUID(),
      anniversaryYear: 1,
    });
    await repo.updateRedemptionStatus(r1.redemptionId, {
      status: 'QUALIFIED',
    });

    const r2 = await repo.createRedemption({
      referralCodeId: crypto.randomUUID(),
      referrerUserId,
      referredUserId: crypto.randomUUID(),
      anniversaryYear: 2,
    });
    await repo.updateRedemptionStatus(r2.redemptionId, {
      status: 'QUALIFIED',
    });

    const year1Count =
      await repo.countQualifiedOrCreditedByReferrerAndYear(referrerUserId, 1);
    expect(year1Count).toBe(1);

    const year2Count =
      await repo.countQualifiedOrCreditedByReferrerAndYear(referrerUserId, 2);
    expect(year2Count).toBe(1);
  });

  it('updateRedemptionStatus updates fields correctly', async () => {
    const created = await repo.createRedemption({
      referralCodeId: crypto.randomUUID(),
      referrerUserId: crypto.randomUUID(),
      referredUserId: crypto.randomUUID(),
      anniversaryYear: 1,
    });

    const now = new Date();
    const result = await repo.updateRedemptionStatus(created.redemptionId, {
      status: 'QUALIFIED',
      creditMonthValueCad: '279.00',
      qualifyingEventAt: now,
    });

    expect(result).toBeDefined();
    expect(result!.status).toBe('QUALIFIED');
    expect(result!.creditMonthValueCad).toBe('279.00');
    expect(result!.qualifyingEventAt).toEqual(now);
  });

  it('findRedemptionsByReferrer returns all for referrer', async () => {
    const referrerUserId = crypto.randomUUID();
    await repo.createRedemption({
      referralCodeId: crypto.randomUUID(),
      referrerUserId,
      referredUserId: crypto.randomUUID(),
      anniversaryYear: 1,
    });
    await repo.createRedemption({
      referralCodeId: crypto.randomUUID(),
      referrerUserId,
      referredUserId: crypto.randomUUID(),
      anniversaryYear: 1,
    });

    const results = await repo.findRedemptionsByReferrer(referrerUserId);
    expect(results).toHaveLength(2);
  });

  it('findRedemptionsByReferrer filters by status', async () => {
    const referrerUserId = crypto.randomUUID();
    const r1 = await repo.createRedemption({
      referralCodeId: crypto.randomUUID(),
      referrerUserId,
      referredUserId: crypto.randomUUID(),
      anniversaryYear: 1,
    });
    await repo.updateRedemptionStatus(r1.redemptionId, {
      status: 'QUALIFIED',
    });

    await repo.createRedemption({
      referralCodeId: crypto.randomUUID(),
      referrerUserId,
      referredUserId: crypto.randomUUID(),
      anniversaryYear: 1,
    });

    const qualified = await repo.findRedemptionsByReferrer(referrerUserId, {
      status: 'QUALIFIED',
    });
    expect(qualified).toHaveLength(1);
    expect(qualified[0].status).toBe('QUALIFIED');
  });

  it('findPendingRedemptions returns all PENDING', async () => {
    await repo.createRedemption({
      referralCodeId: crypto.randomUUID(),
      referrerUserId: crypto.randomUUID(),
      referredUserId: crypto.randomUUID(),
      anniversaryYear: 1,
    });
    const r2 = await repo.createRedemption({
      referralCodeId: crypto.randomUUID(),
      referrerUserId: crypto.randomUUID(),
      referredUserId: crypto.randomUUID(),
      anniversaryYear: 1,
    });
    await repo.updateRedemptionStatus(r2.redemptionId, {
      status: 'QUALIFIED',
    });

    const pending = await repo.findPendingRedemptions();
    expect(pending).toHaveLength(1);
    expect(pending[0].status).toBe('PENDING');
  });

  it('findQualifiedRedemptions returns all QUALIFIED', async () => {
    const r1 = await repo.createRedemption({
      referralCodeId: crypto.randomUUID(),
      referrerUserId: crypto.randomUUID(),
      referredUserId: crypto.randomUUID(),
      anniversaryYear: 1,
    });
    await repo.updateRedemptionStatus(r1.redemptionId, {
      status: 'QUALIFIED',
    });

    await repo.createRedemption({
      referralCodeId: crypto.randomUUID(),
      referrerUserId: crypto.randomUUID(),
      referredUserId: crypto.randomUUID(),
      anniversaryYear: 1,
    });

    const qualified = await repo.findQualifiedRedemptions();
    expect(qualified).toHaveLength(1);
    expect(qualified[0].status).toBe('QUALIFIED');
  });

  it('findRedemptionById returns correct redemption', async () => {
    const created = await repo.createRedemption({
      referralCodeId: crypto.randomUUID(),
      referrerUserId: crypto.randomUUID(),
      referredUserId: crypto.randomUUID(),
      anniversaryYear: 1,
    });

    const found = await repo.findRedemptionById(created.redemptionId);
    expect(found).toBeDefined();
    expect(found!.redemptionId).toBe(created.redemptionId);
  });

  it('findRedemptionById returns undefined for missing id', async () => {
    const found = await repo.findRedemptionById(crypto.randomUUID());
    expect(found).toBeUndefined();
  });
});

// ============================================================================
// Service Tests
// ============================================================================

describe('generateReferralCode', () => {
  it('returns existing code if user already has one', async () => {
    const userId = crypto.randomUUID();
    const existingCode = makeReferralCode({
      referrerUserId: userId,
      code: 'EXIST123',
    });
    const deps = makeMockDeps();
    (deps.referralCodeRepo.findReferralCodeByUserId as any).mockResolvedValue(
      existingCode,
    );

    const result = await generateReferralCode(deps, userId);
    expect(result.code).toBe('EXIST123');
    expect(result.referralCodeId).toBe(existingCode.referralCodeId);
    expect(deps.referralCodeRepo.createReferralCode).not.toHaveBeenCalled();
  });

  it('generates a new 8-char code when user has none', async () => {
    const userId = crypto.randomUUID();
    const deps = makeMockDeps();
    (deps.referralCodeRepo.findReferralCodeByUserId as any).mockResolvedValue(
      undefined,
    );
    (deps.referralCodeRepo.findReferralCodeByCode as any).mockResolvedValue(
      undefined,
    );
    (deps.referralCodeRepo.createReferralCode as any).mockImplementation(
      async (_uid: string, code: string) =>
        makeReferralCode({ referrerUserId: _uid, code }),
    );

    const result = await generateReferralCode(deps, userId);
    expect(result.code).toHaveLength(8);
    expect(result.referralCodeId).toBeDefined();

    // Verify code only contains valid characters
    const validChars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    for (const char of result.code) {
      expect(validChars).toContain(char);
    }
  });

  it('retries on collision and succeeds', async () => {
    const userId = crypto.randomUUID();
    const deps = makeMockDeps();
    (deps.referralCodeRepo.findReferralCodeByUserId as any).mockResolvedValue(
      undefined,
    );

    // First call returns collision, second returns no collision
    let callCount = 0;
    (deps.referralCodeRepo.findReferralCodeByCode as any).mockImplementation(
      async () => {
        callCount++;
        if (callCount <= 1) {
          return makeReferralCode(); // collision
        }
        return undefined; // no collision
      },
    );
    (deps.referralCodeRepo.createReferralCode as any).mockImplementation(
      async (_uid: string, code: string) =>
        makeReferralCode({ referrerUserId: _uid, code }),
    );

    const result = await generateReferralCode(deps, userId);
    expect(result.code).toHaveLength(8);
    expect(callCount).toBe(2);
  });

  it('throws after 10 collision retries', async () => {
    const userId = crypto.randomUUID();
    const deps = makeMockDeps();
    (deps.referralCodeRepo.findReferralCodeByUserId as any).mockResolvedValue(
      undefined,
    );
    (deps.referralCodeRepo.findReferralCodeByCode as any).mockResolvedValue(
      makeReferralCode(), // always collision
    );

    await expect(generateReferralCode(deps, userId)).rejects.toThrow(
      'Unable to generate unique referral code',
    );
  });
});

describe('redeemReferralCode', () => {
  it('creates a PENDING redemption for valid code and new user', async () => {
    const referrerUserId = crypto.randomUUID();
    const referredUserId = crypto.randomUUID();
    const code = 'VALID123';
    const referralCode = makeReferralCode({
      referrerUserId,
      code,
    });
    const deps = makeMockDeps();
    (deps.referralCodeRepo.findReferralCodeByCode as any).mockResolvedValue(
      referralCode,
    );
    (deps.subscriptionRepo.findSubscriptionByProviderId as any)
      .mockResolvedValueOnce(undefined) // referred user has no sub
      .mockResolvedValueOnce({
        // referrer sub for anniversary year calc
        subscriptionId: crypto.randomUUID(),
        providerId: referrerUserId,
        createdAt: new Date(),
        status: 'ACTIVE',
      });
    (deps.subscriptionRepo.getActivePracticeMembership as any).mockResolvedValue(
      null,
    );
    (deps.referralRedemptionRepo.findPendingByReferredUser as any).mockResolvedValue(
      undefined,
    );
    (deps.referralRedemptionRepo.createRedemption as any).mockImplementation(
      async (data: any) => makeRedemption(data),
    );

    const result = await redeemReferralCode(deps, code, referredUserId);
    expect(result.redemptionId).toBeDefined();
    expect(deps.referralRedemptionRepo.createRedemption).toHaveBeenCalledWith(
      expect.objectContaining({
        referralCodeId: referralCode.referralCodeId,
        referrerUserId,
        referredUserId,
        anniversaryYear: 1,
      }),
    );
  });

  it('throws for invalid code', async () => {
    const deps = makeMockDeps();
    (deps.referralCodeRepo.findReferralCodeByCode as any).mockResolvedValue(
      undefined,
    );

    await expect(
      redeemReferralCode(deps, 'BADCODE1', crypto.randomUUID()),
    ).rejects.toThrow('Invalid or inactive referral code');
  });

  it('throws for inactive code', async () => {
    const deps = makeMockDeps();
    (deps.referralCodeRepo.findReferralCodeByCode as any).mockResolvedValue(
      makeReferralCode({ isActive: false }),
    );

    await expect(
      redeemReferralCode(deps, 'INACTIVE', crypto.randomUUID()),
    ).rejects.toThrow('Invalid or inactive referral code');
  });

  it('throws if referred user already has a subscription', async () => {
    const referredUserId = crypto.randomUUID();
    const deps = makeMockDeps();
    (deps.referralCodeRepo.findReferralCodeByCode as any).mockResolvedValue(
      makeReferralCode(),
    );
    (deps.subscriptionRepo.findSubscriptionByProviderId as any).mockResolvedValue({
      subscriptionId: crypto.randomUUID(),
      status: 'ACTIVE',
    });

    await expect(
      redeemReferralCode(deps, 'CODE1234', referredUserId),
    ).rejects.toThrow('Referred user already has a subscription');
  });

  it('throws if referrer and referred on same practice', async () => {
    const referrerUserId = crypto.randomUUID();
    const referredUserId = crypto.randomUUID();
    const practiceId = crypto.randomUUID();
    const deps = makeMockDeps();
    (deps.referralCodeRepo.findReferralCodeByCode as any).mockResolvedValue(
      makeReferralCode({ referrerUserId }),
    );
    (deps.subscriptionRepo.findSubscriptionByProviderId as any).mockResolvedValue(
      undefined,
    );
    (deps.subscriptionRepo.getActivePracticeMembership as any)
      .mockResolvedValueOnce({ practiceId }) // referrer
      .mockResolvedValueOnce({ practiceId }); // referred

    await expect(
      redeemReferralCode(deps, 'CODE1234', referredUserId),
    ).rejects.toThrow('Referrer and referred user are in the same practice');
  });

  it('throws if referred user already has pending redemption', async () => {
    const referredUserId = crypto.randomUUID();
    const deps = makeMockDeps();
    (deps.referralCodeRepo.findReferralCodeByCode as any).mockResolvedValue(
      makeReferralCode(),
    );
    (deps.subscriptionRepo.findSubscriptionByProviderId as any).mockResolvedValue(
      undefined,
    );
    (deps.subscriptionRepo.getActivePracticeMembership as any).mockResolvedValue(
      null,
    );
    (deps.referralRedemptionRepo.findPendingByReferredUser as any).mockResolvedValue(
      makeRedemption(),
    );

    await expect(
      redeemReferralCode(deps, 'CODE1234', referredUserId),
    ).rejects.toThrow('Referred user already has a pending referral redemption');
  });

  it('calculates anniversary year correctly for older subscriptions', async () => {
    const referrerUserId = crypto.randomUUID();
    const referredUserId = crypto.randomUUID();
    const deps = makeMockDeps();
    (deps.referralCodeRepo.findReferralCodeByCode as any).mockResolvedValue(
      makeReferralCode({ referrerUserId }),
    );
    (deps.subscriptionRepo.findSubscriptionByProviderId as any)
      .mockResolvedValueOnce(undefined) // referred user has no sub
      .mockResolvedValueOnce({
        subscriptionId: crypto.randomUUID(),
        providerId: referrerUserId,
        createdAt: new Date(Date.now() - 400 * DAY_MS), // ~1.1 years ago
        status: 'ACTIVE',
      });
    (deps.subscriptionRepo.getActivePracticeMembership as any).mockResolvedValue(
      null,
    );
    (deps.referralRedemptionRepo.findPendingByReferredUser as any).mockResolvedValue(
      undefined,
    );
    (deps.referralRedemptionRepo.createRedemption as any).mockImplementation(
      async (data: any) => makeRedemption(data),
    );

    await redeemReferralCode(deps, 'CODE1234', referredUserId);
    expect(deps.referralRedemptionRepo.createRedemption).toHaveBeenCalledWith(
      expect.objectContaining({
        anniversaryYear: 2,
      }),
    );
  });
});

describe('checkReferralQualification', () => {
  it('skips redemptions where referred user has no subscription', async () => {
    const deps = makeMockDeps();
    (deps.referralRedemptionRepo.findPendingRedemptions as any).mockResolvedValue([
      makeRedemption(),
    ]);
    (deps.subscriptionRepo.findSubscriptionByProviderId as any).mockResolvedValue(
      undefined,
    );

    const result = await checkReferralQualification(deps);
    expect(result.skipped).toBe(1);
    expect(result.qualified).toBe(0);
    expect(result.expired).toBe(0);
  });

  it('skips redemptions where referred user has no PAID payment', async () => {
    const deps = makeMockDeps();
    (deps.referralRedemptionRepo.findPendingRedemptions as any).mockResolvedValue([
      makeRedemption(),
    ]);
    (deps.subscriptionRepo.findSubscriptionByProviderId as any).mockResolvedValue({
      subscriptionId: 'sub-1',
      status: 'ACTIVE',
    });
    (deps.paymentRepo.listPaymentsForSubscription as any).mockResolvedValue({
      data: [{ status: 'FAILED' }],
      total: 1,
    });

    const result = await checkReferralQualification(deps);
    expect(result.skipped).toBe(1);
  });

  it('expires redemption if referrer has no active subscription', async () => {
    const redemption = makeRedemption();
    const deps = makeMockDeps();
    (deps.referralRedemptionRepo.findPendingRedemptions as any).mockResolvedValue([
      redemption,
    ]);
    (deps.subscriptionRepo.findSubscriptionByProviderId as any)
      .mockResolvedValueOnce({
        subscriptionId: 'sub-referred',
        status: 'ACTIVE',
      })
      .mockResolvedValueOnce(undefined); // referrer has no sub
    (deps.paymentRepo.listPaymentsForSubscription as any).mockResolvedValue({
      data: [{ status: 'PAID' }],
      total: 1,
    });
    (deps.referralRedemptionRepo.updateRedemptionStatus as any).mockResolvedValue(
      { ...redemption, status: 'EXPIRED' },
    );

    const result = await checkReferralQualification(deps);
    expect(result.expired).toBe(1);
    expect(
      deps.referralRedemptionRepo.updateRedemptionStatus,
    ).toHaveBeenCalledWith(redemption.redemptionId, { status: 'EXPIRED' });
  });

  it('expires redemption if referrer sub is CANCELLED', async () => {
    const redemption = makeRedemption();
    const deps = makeMockDeps();
    (deps.referralRedemptionRepo.findPendingRedemptions as any).mockResolvedValue([
      redemption,
    ]);
    (deps.subscriptionRepo.findSubscriptionByProviderId as any)
      .mockResolvedValueOnce({
        subscriptionId: 'sub-referred',
        status: 'ACTIVE',
      })
      .mockResolvedValueOnce({
        subscriptionId: 'sub-referrer',
        status: 'CANCELLED',
        plan: 'STANDARD_MONTHLY',
      });
    (deps.paymentRepo.listPaymentsForSubscription as any).mockResolvedValue({
      data: [{ status: 'PAID' }],
      total: 1,
    });
    (deps.referralRedemptionRepo.updateRedemptionStatus as any).mockResolvedValue(
      { ...redemption, status: 'EXPIRED' },
    );

    const result = await checkReferralQualification(deps);
    expect(result.expired).toBe(1);
  });

  it('expires redemption when 3-per-year cap is reached', async () => {
    const redemption = makeRedemption();
    const deps = makeMockDeps();
    (deps.referralRedemptionRepo.findPendingRedemptions as any).mockResolvedValue([
      redemption,
    ]);
    (deps.subscriptionRepo.findSubscriptionByProviderId as any)
      .mockResolvedValueOnce({
        subscriptionId: 'sub-referred',
        status: 'ACTIVE',
      })
      .mockResolvedValueOnce({
        subscriptionId: 'sub-referrer',
        status: 'ACTIVE',
        plan: 'STANDARD_MONTHLY',
        stripeCustomerId: 'cus_referrer',
      });
    (deps.paymentRepo.listPaymentsForSubscription as any).mockResolvedValue({
      data: [{ status: 'PAID' }],
      total: 1,
    });
    (deps.referralRedemptionRepo.countQualifiedOrCreditedByReferrerAndYear as any).mockResolvedValue(
      3,
    );
    (deps.referralRedemptionRepo.updateRedemptionStatus as any).mockResolvedValue(
      { ...redemption, status: 'EXPIRED' },
    );

    const result = await checkReferralQualification(deps);
    expect(result.expired).toBe(1);
  });

  it('qualifies clinic plan redemption without auto-applying credit', async () => {
    const redemption = makeRedemption();
    const deps = makeMockDeps();
    (deps.referralRedemptionRepo.findPendingRedemptions as any).mockResolvedValue([
      redemption,
    ]);
    (deps.subscriptionRepo.findSubscriptionByProviderId as any)
      .mockResolvedValueOnce({
        subscriptionId: 'sub-referred',
        status: 'ACTIVE',
      })
      .mockResolvedValueOnce({
        subscriptionId: 'sub-referrer',
        status: 'ACTIVE',
        plan: 'CLINIC_MONTHLY',
        stripeCustomerId: 'cus_referrer',
      });
    (deps.paymentRepo.listPaymentsForSubscription as any).mockResolvedValue({
      data: [{ status: 'PAID' }],
      total: 1,
    });
    (deps.referralRedemptionRepo.countQualifiedOrCreditedByReferrerAndYear as any).mockResolvedValue(
      0,
    );
    (deps.referralRedemptionRepo.updateRedemptionStatus as any).mockResolvedValue(
      { ...redemption, status: 'QUALIFIED' },
    );

    const result = await checkReferralQualification(deps);
    expect(result.qualified).toBe(1);
    // Stripe invoice item should NOT be created for clinic plan (waits for choice)
    expect(deps.stripe.invoiceItems.create).not.toHaveBeenCalled();
    expect(
      deps.referralRedemptionRepo.updateRedemptionStatus,
    ).toHaveBeenCalledWith(
      redemption.redemptionId,
      expect.objectContaining({
        status: 'QUALIFIED',
        creditMonthValueCad: '251.10',
      }),
    );
  });

  it('qualifies and auto-applies credit for individual plan', async () => {
    const redemption = makeRedemption();
    const deps = makeMockDeps();
    (deps.referralRedemptionRepo.findPendingRedemptions as any).mockResolvedValue([
      redemption,
    ]);
    (deps.subscriptionRepo.findSubscriptionByProviderId as any)
      .mockResolvedValueOnce({
        subscriptionId: 'sub-referred',
        status: 'ACTIVE',
      })
      .mockResolvedValueOnce({
        subscriptionId: 'sub-referrer',
        status: 'ACTIVE',
        plan: 'STANDARD_MONTHLY',
        stripeCustomerId: 'cus_referrer',
      });
    (deps.paymentRepo.listPaymentsForSubscription as any).mockResolvedValue({
      data: [{ status: 'PAID' }],
      total: 1,
    });
    (deps.referralRedemptionRepo.countQualifiedOrCreditedByReferrerAndYear as any).mockResolvedValue(
      0,
    );
    (deps.referralRedemptionRepo.updateRedemptionStatus as any).mockResolvedValue(
      { ...redemption, status: 'CREDITED' },
    );

    const result = await checkReferralQualification(deps);
    expect(result.qualified).toBe(1);

    // Should create negative Stripe invoice item
    expect(deps.stripe.invoiceItems.create).toHaveBeenCalledWith({
      customer: 'cus_referrer',
      amount: -27900,
      currency: 'cad',
      description: expect.stringContaining('Referral credit'),
    });

    // Should update to CREDITED after auto-apply
    expect(
      deps.referralRedemptionRepo.updateRedemptionStatus,
    ).toHaveBeenCalledWith(
      redemption.redemptionId,
      expect.objectContaining({ status: 'CREDITED' }),
    );
  });

  it('calculates correct credit value for EARLY_BIRD_MONTHLY', async () => {
    const redemption = makeRedemption();
    const deps = makeMockDeps();
    (deps.referralRedemptionRepo.findPendingRedemptions as any).mockResolvedValue([
      redemption,
    ]);
    (deps.subscriptionRepo.findSubscriptionByProviderId as any)
      .mockResolvedValueOnce({
        subscriptionId: 'sub-referred',
        status: 'ACTIVE',
      })
      .mockResolvedValueOnce({
        subscriptionId: 'sub-referrer',
        status: 'ACTIVE',
        plan: 'EARLY_BIRD_MONTHLY',
        stripeCustomerId: 'cus_referrer',
      });
    (deps.paymentRepo.listPaymentsForSubscription as any).mockResolvedValue({
      data: [{ status: 'PAID' }],
      total: 1,
    });
    (deps.referralRedemptionRepo.countQualifiedOrCreditedByReferrerAndYear as any).mockResolvedValue(
      0,
    );
    (deps.referralRedemptionRepo.updateRedemptionStatus as any).mockResolvedValue(
      { ...redemption, status: 'CREDITED' },
    );

    await checkReferralQualification(deps);

    expect(
      deps.referralRedemptionRepo.updateRedemptionStatus,
    ).toHaveBeenCalledWith(
      redemption.redemptionId,
      expect.objectContaining({
        status: 'QUALIFIED',
        creditMonthValueCad: '199.00',
      }),
    );
    expect(deps.stripe.invoiceItems.create).toHaveBeenCalledWith(
      expect.objectContaining({ amount: -19900 }),
    );
  });

  it('calculates correct credit value for STANDARD_ANNUAL', async () => {
    const redemption = makeRedemption();
    const deps = makeMockDeps();
    (deps.referralRedemptionRepo.findPendingRedemptions as any).mockResolvedValue([
      redemption,
    ]);
    (deps.subscriptionRepo.findSubscriptionByProviderId as any)
      .mockResolvedValueOnce({
        subscriptionId: 'sub-referred',
        status: 'ACTIVE',
      })
      .mockResolvedValueOnce({
        subscriptionId: 'sub-referrer',
        status: 'ACTIVE',
        plan: 'STANDARD_ANNUAL',
        stripeCustomerId: 'cus_referrer',
      });
    (deps.paymentRepo.listPaymentsForSubscription as any).mockResolvedValue({
      data: [{ status: 'PAID' }],
      total: 1,
    });
    (deps.referralRedemptionRepo.countQualifiedOrCreditedByReferrerAndYear as any).mockResolvedValue(
      0,
    );
    (deps.referralRedemptionRepo.updateRedemptionStatus as any).mockResolvedValue(
      { ...redemption, status: 'CREDITED' },
    );

    await checkReferralQualification(deps);

    expect(
      deps.referralRedemptionRepo.updateRedemptionStatus,
    ).toHaveBeenCalledWith(
      redemption.redemptionId,
      expect.objectContaining({
        creditMonthValueCad: '265.08',
      }),
    );
    expect(deps.stripe.invoiceItems.create).toHaveBeenCalledWith(
      expect.objectContaining({ amount: -26508 }),
    );
  });

  it('calculates correct credit value for CLINIC_ANNUAL', async () => {
    const redemption = makeRedemption();
    const deps = makeMockDeps();
    (deps.referralRedemptionRepo.findPendingRedemptions as any).mockResolvedValue([
      redemption,
    ]);
    (deps.subscriptionRepo.findSubscriptionByProviderId as any)
      .mockResolvedValueOnce({
        subscriptionId: 'sub-referred',
        status: 'ACTIVE',
      })
      .mockResolvedValueOnce({
        subscriptionId: 'sub-referrer',
        status: 'ACTIVE',
        plan: 'CLINIC_ANNUAL',
        stripeCustomerId: 'cus_referrer',
      });
    (deps.paymentRepo.listPaymentsForSubscription as any).mockResolvedValue({
      data: [{ status: 'PAID' }],
      total: 1,
    });
    (deps.referralRedemptionRepo.countQualifiedOrCreditedByReferrerAndYear as any).mockResolvedValue(
      0,
    );
    (deps.referralRedemptionRepo.updateRedemptionStatus as any).mockResolvedValue(
      { ...redemption, status: 'QUALIFIED' },
    );

    await checkReferralQualification(deps);

    // Clinic plan should be QUALIFIED only (no auto-apply)
    expect(
      deps.referralRedemptionRepo.updateRedemptionStatus,
    ).toHaveBeenCalledWith(
      redemption.redemptionId,
      expect.objectContaining({
        status: 'QUALIFIED',
        creditMonthValueCad: '238.58',
      }),
    );
    expect(deps.stripe.invoiceItems.create).not.toHaveBeenCalled();
  });

  it('returns correct counts for mixed batch', async () => {
    const r1 = makeRedemption({ referrerUserId: 'referrer-1', referredUserId: 'referred-1' });
    const r2 = makeRedemption({ referrerUserId: 'referrer-2', referredUserId: 'referred-2' });
    const r3 = makeRedemption({ referrerUserId: 'referrer-3', referredUserId: 'referred-3' });

    const deps = makeMockDeps();
    (deps.referralRedemptionRepo.findPendingRedemptions as any).mockResolvedValue([
      r1, r2, r3,
    ]);

    // r1: referred has sub + paid payment, referrer active standard monthly -> qualified+auto-apply
    // r2: referred has no sub -> skipped
    // r3: referred has sub + paid payment, referrer cancelled -> expired
    (deps.subscriptionRepo.findSubscriptionByProviderId as any).mockImplementation(
      async (userId: string) => {
        if (userId === 'referred-1') return { subscriptionId: 'sub-1', status: 'ACTIVE' };
        if (userId === 'referrer-1') return { subscriptionId: 'sub-r1', status: 'ACTIVE', plan: 'STANDARD_MONTHLY', stripeCustomerId: 'cus_r1' };
        if (userId === 'referred-2') return undefined;
        if (userId === 'referred-3') return { subscriptionId: 'sub-3', status: 'ACTIVE' };
        if (userId === 'referrer-3') return { subscriptionId: 'sub-r3', status: 'CANCELLED', plan: 'STANDARD_MONTHLY' };
        return undefined;
      },
    );
    (deps.paymentRepo.listPaymentsForSubscription as any).mockResolvedValue({
      data: [{ status: 'PAID' }],
      total: 1,
    });
    (deps.referralRedemptionRepo.countQualifiedOrCreditedByReferrerAndYear as any).mockResolvedValue(
      0,
    );
    (deps.referralRedemptionRepo.updateRedemptionStatus as any).mockResolvedValue(
      {},
    );

    const result = await checkReferralQualification(deps);
    expect(result.qualified).toBe(1);
    expect(result.skipped).toBe(1);
    expect(result.expired).toBe(1);
  });
});

describe('applyReferralCredit', () => {
  it('throws if redemption not found', async () => {
    const deps = makeMockDeps();
    (deps.referralRedemptionRepo.findRedemptionById as any).mockResolvedValue(
      undefined,
    );

    await expect(
      applyReferralCredit(deps, 'bad-id', 'user-id'),
    ).rejects.toThrow('Redemption not found');
  });

  it('throws if redemption is not QUALIFIED', async () => {
    const deps = makeMockDeps();
    (deps.referralRedemptionRepo.findRedemptionById as any).mockResolvedValue(
      makeRedemption({ status: 'PENDING' }),
    );

    await expect(
      applyReferralCredit(deps, 'red-id', 'user-id'),
    ).rejects.toThrow('Redemption is not in QUALIFIED status');
  });

  it('throws if user does not own the redemption', async () => {
    const deps = makeMockDeps();
    (deps.referralRedemptionRepo.findRedemptionById as any).mockResolvedValue(
      makeRedemption({ status: 'QUALIFIED', referrerUserId: 'other-user' }),
    );

    await expect(
      applyReferralCredit(deps, 'red-id', 'user-id'),
    ).rejects.toThrow('User does not own this redemption');
  });

  it('throws if referrer has no subscription', async () => {
    const userId = crypto.randomUUID();
    const deps = makeMockDeps();
    (deps.referralRedemptionRepo.findRedemptionById as any).mockResolvedValue(
      makeRedemption({
        status: 'QUALIFIED',
        referrerUserId: userId,
        creditMonthValueCad: '279.00',
      }),
    );
    (deps.subscriptionRepo.findSubscriptionByProviderId as any).mockResolvedValue(
      undefined,
    );

    await expect(
      applyReferralCredit(deps, 'red-id', userId),
    ).rejects.toThrow('Referrer has no subscription');
  });

  it('throws if clinic plan and no target specified', async () => {
    const userId = crypto.randomUUID();
    const deps = makeMockDeps();
    (deps.referralRedemptionRepo.findRedemptionById as any).mockResolvedValue(
      makeRedemption({
        status: 'QUALIFIED',
        referrerUserId: userId,
        creditMonthValueCad: '251.10',
      }),
    );
    (deps.subscriptionRepo.findSubscriptionByProviderId as any).mockResolvedValue({
      subscriptionId: 'sub-1',
      plan: 'CLINIC_MONTHLY',
      stripeCustomerId: 'cus_1',
      status: 'ACTIVE',
    });

    await expect(
      applyReferralCredit(deps, 'red-id', userId),
    ).rejects.toThrow('Credit application target is required for clinic plans');
  });

  it('applies credit to practice invoice for clinic plan', async () => {
    const userId = crypto.randomUUID();
    const redemptionId = crypto.randomUUID();
    const deps = makeMockDeps();
    (deps.referralRedemptionRepo.findRedemptionById as any).mockResolvedValue(
      makeRedemption({
        redemptionId,
        status: 'QUALIFIED',
        referrerUserId: userId,
        creditMonthValueCad: '251.10',
      }),
    );
    (deps.subscriptionRepo.findSubscriptionByProviderId as any).mockResolvedValue({
      subscriptionId: 'sub-1',
      plan: 'CLINIC_MONTHLY',
      stripeCustomerId: 'cus_1',
      status: 'ACTIVE',
    });
    (deps.referralRedemptionRepo.updateRedemptionStatus as any).mockResolvedValue(
      {},
    );

    await applyReferralCredit(deps, redemptionId, userId, 'PRACTICE_INVOICE');

    expect(deps.stripe.invoiceItems.create).toHaveBeenCalledWith({
      customer: 'cus_1',
      amount: -25110,
      currency: 'cad',
      description: expect.stringContaining('Referral credit'),
    });
    expect(
      deps.referralRedemptionRepo.updateRedemptionStatus,
    ).toHaveBeenCalledWith(
      redemptionId,
      expect.objectContaining({
        status: 'CREDITED',
        creditAppliedTo: 'PRACTICE_INVOICE',
      }),
    );
  });

  it('stores target for INDIVIDUAL_BANK without creating Stripe item', async () => {
    const userId = crypto.randomUUID();
    const redemptionId = crypto.randomUUID();
    const deps = makeMockDeps();
    (deps.referralRedemptionRepo.findRedemptionById as any).mockResolvedValue(
      makeRedemption({
        redemptionId,
        status: 'QUALIFIED',
        referrerUserId: userId,
        creditMonthValueCad: '251.10',
      }),
    );
    (deps.subscriptionRepo.findSubscriptionByProviderId as any).mockResolvedValue({
      subscriptionId: 'sub-1',
      plan: 'CLINIC_MONTHLY',
      stripeCustomerId: 'cus_1',
      status: 'ACTIVE',
    });
    (deps.referralRedemptionRepo.updateRedemptionStatus as any).mockResolvedValue(
      {},
    );

    await applyReferralCredit(deps, redemptionId, userId, 'INDIVIDUAL_BANK');

    expect(deps.stripe.invoiceItems.create).not.toHaveBeenCalled();
    expect(
      deps.referralRedemptionRepo.updateRedemptionStatus,
    ).toHaveBeenCalledWith(
      redemptionId,
      expect.objectContaining({
        status: 'CREDITED',
        creditAppliedTo: 'INDIVIDUAL_BANK',
      }),
    );
  });

  it('auto-applies credit for individual plan via Stripe', async () => {
    const userId = crypto.randomUUID();
    const redemptionId = crypto.randomUUID();
    const deps = makeMockDeps();
    (deps.referralRedemptionRepo.findRedemptionById as any).mockResolvedValue(
      makeRedemption({
        redemptionId,
        status: 'QUALIFIED',
        referrerUserId: userId,
        creditMonthValueCad: '279.00',
      }),
    );
    (deps.subscriptionRepo.findSubscriptionByProviderId as any).mockResolvedValue({
      subscriptionId: 'sub-1',
      plan: 'STANDARD_MONTHLY',
      stripeCustomerId: 'cus_1',
      status: 'ACTIVE',
    });
    (deps.referralRedemptionRepo.updateRedemptionStatus as any).mockResolvedValue(
      {},
    );

    await applyReferralCredit(deps, redemptionId, userId);

    expect(deps.stripe.invoiceItems.create).toHaveBeenCalledWith({
      customer: 'cus_1',
      amount: -27900,
      currency: 'cad',
      description: expect.stringContaining('Referral credit'),
    });
    expect(
      deps.referralRedemptionRepo.updateRedemptionStatus,
    ).toHaveBeenCalledWith(
      redemptionId,
      expect.objectContaining({ status: 'CREDITED' }),
    );
  });
});

describe('applyDefaultCreditChoice', () => {
  it('auto-applies PRACTICE_INVOICE for old qualified clinic redemptions', async () => {
    const referrerUserId = crypto.randomUUID();
    const redemptionId = crypto.randomUUID();
    const oldDate = new Date(Date.now() - 10 * DAY_MS);

    const deps = makeMockDeps();
    (deps.referralRedemptionRepo.findQualifiedRedemptions as any).mockResolvedValue([
      makeRedemption({
        redemptionId,
        referrerUserId,
        status: 'QUALIFIED',
        creditMonthValueCad: '251.10',
        qualifyingEventAt: oldDate,
      }),
    ]);
    (deps.subscriptionRepo.findSubscriptionByProviderId as any).mockResolvedValue({
      subscriptionId: 'sub-1',
      plan: 'CLINIC_MONTHLY',
      stripeCustomerId: 'cus_1',
      status: 'ACTIVE',
    });
    (deps.referralRedemptionRepo.updateRedemptionStatus as any).mockResolvedValue(
      {},
    );

    const count = await applyDefaultCreditChoice(deps);
    expect(count).toBe(1);
    expect(deps.stripe.invoiceItems.create).toHaveBeenCalledWith(
      expect.objectContaining({
        customer: 'cus_1',
        amount: -25110,
      }),
    );
    expect(
      deps.referralRedemptionRepo.updateRedemptionStatus,
    ).toHaveBeenCalledWith(
      redemptionId,
      expect.objectContaining({
        status: 'CREDITED',
        creditAppliedTo: 'PRACTICE_INVOICE',
      }),
    );
  });

  it('skips qualified redemptions newer than 7 days', async () => {
    const deps = makeMockDeps();
    (deps.referralRedemptionRepo.findQualifiedRedemptions as any).mockResolvedValue([
      makeRedemption({
        status: 'QUALIFIED',
        creditMonthValueCad: '251.10',
        qualifyingEventAt: new Date(), // just now - too fresh
      }),
    ]);

    const count = await applyDefaultCreditChoice(deps);
    expect(count).toBe(0);
    expect(deps.stripe.invoiceItems.create).not.toHaveBeenCalled();
  });

  it('skips non-clinic plan redemptions', async () => {
    const referrerUserId = crypto.randomUUID();
    const oldDate = new Date(Date.now() - 10 * DAY_MS);

    const deps = makeMockDeps();
    (deps.referralRedemptionRepo.findQualifiedRedemptions as any).mockResolvedValue([
      makeRedemption({
        referrerUserId,
        status: 'QUALIFIED',
        creditMonthValueCad: '279.00',
        qualifyingEventAt: oldDate,
      }),
    ]);
    (deps.subscriptionRepo.findSubscriptionByProviderId as any).mockResolvedValue({
      subscriptionId: 'sub-1',
      plan: 'STANDARD_MONTHLY',
      stripeCustomerId: 'cus_1',
      status: 'ACTIVE',
    });

    const count = await applyDefaultCreditChoice(deps);
    expect(count).toBe(0);
    expect(deps.stripe.invoiceItems.create).not.toHaveBeenCalled();
  });

  it('returns 0 when no qualified redemptions exist', async () => {
    const deps = makeMockDeps();
    (deps.referralRedemptionRepo.findQualifiedRedemptions as any).mockResolvedValue(
      [],
    );

    const count = await applyDefaultCreditChoice(deps);
    expect(count).toBe(0);
  });
});

describe('shouldApplyRefereeIncentive', () => {
  it('returns true when pending referral exists, EB window closed, and plan eligible', async () => {
    const referredUserId = crypto.randomUUID();
    const deps = makeMockDeps();
    (deps.referralRedemptionRepo.findPendingByReferredUser as any).mockResolvedValue(
      makeRedemption(),
    );
    (deps.subscriptionRepo.countEarlyBirdSubscriptions as any).mockResolvedValue(
      100,
    );

    const result = await shouldApplyRefereeIncentive(
      deps,
      referredUserId,
      'STANDARD_MONTHLY',
    );
    expect(result).toBe(true);
  });

  it('returns false when no pending referral exists', async () => {
    const deps = makeMockDeps();
    (deps.referralRedemptionRepo.findPendingByReferredUser as any).mockResolvedValue(
      undefined,
    );

    const result = await shouldApplyRefereeIncentive(
      deps,
      crypto.randomUUID(),
      'STANDARD_MONTHLY',
    );
    expect(result).toBe(false);
  });

  it('returns false when early bird window is still open (<100 EB subs)', async () => {
    const deps = makeMockDeps();
    (deps.referralRedemptionRepo.findPendingByReferredUser as any).mockResolvedValue(
      makeRedemption(),
    );
    (deps.subscriptionRepo.countEarlyBirdSubscriptions as any).mockResolvedValue(
      50,
    );

    const result = await shouldApplyRefereeIncentive(
      deps,
      crypto.randomUUID(),
      'STANDARD_MONTHLY',
    );
    expect(result).toBe(false);
  });

  it('returns false for clinic plan', async () => {
    const deps = makeMockDeps();
    (deps.referralRedemptionRepo.findPendingByReferredUser as any).mockResolvedValue(
      makeRedemption(),
    );
    (deps.subscriptionRepo.countEarlyBirdSubscriptions as any).mockResolvedValue(
      100,
    );

    const result = await shouldApplyRefereeIncentive(
      deps,
      crypto.randomUUID(),
      'CLINIC_MONTHLY',
    );
    expect(result).toBe(false);
  });

  it('returns false for CLINIC_ANNUAL plan', async () => {
    const deps = makeMockDeps();
    (deps.referralRedemptionRepo.findPendingByReferredUser as any).mockResolvedValue(
      makeRedemption(),
    );
    (deps.subscriptionRepo.countEarlyBirdSubscriptions as any).mockResolvedValue(
      100,
    );

    const result = await shouldApplyRefereeIncentive(
      deps,
      crypto.randomUUID(),
      'CLINIC_ANNUAL',
    );
    expect(result).toBe(false);
  });

  it('returns false for EARLY_BIRD_MONTHLY plan', async () => {
    const deps = makeMockDeps();
    (deps.referralRedemptionRepo.findPendingByReferredUser as any).mockResolvedValue(
      makeRedemption(),
    );
    (deps.subscriptionRepo.countEarlyBirdSubscriptions as any).mockResolvedValue(
      100,
    );

    const result = await shouldApplyRefereeIncentive(
      deps,
      crypto.randomUUID(),
      'EARLY_BIRD_MONTHLY',
    );
    expect(result).toBe(false);
  });

  it('returns false for EARLY_BIRD_ANNUAL plan', async () => {
    const deps = makeMockDeps();
    (deps.referralRedemptionRepo.findPendingByReferredUser as any).mockResolvedValue(
      makeRedemption(),
    );
    (deps.subscriptionRepo.countEarlyBirdSubscriptions as any).mockResolvedValue(
      100,
    );

    const result = await shouldApplyRefereeIncentive(
      deps,
      crypto.randomUUID(),
      'EARLY_BIRD_ANNUAL',
    );
    expect(result).toBe(false);
  });

  it('returns true for STANDARD_ANNUAL plan when conditions met', async () => {
    const deps = makeMockDeps();
    (deps.referralRedemptionRepo.findPendingByReferredUser as any).mockResolvedValue(
      makeRedemption(),
    );
    (deps.subscriptionRepo.countEarlyBirdSubscriptions as any).mockResolvedValue(
      150,
    );

    const result = await shouldApplyRefereeIncentive(
      deps,
      crypto.randomUUID(),
      'STANDARD_ANNUAL',
    );
    expect(result).toBe(true);
  });
});
