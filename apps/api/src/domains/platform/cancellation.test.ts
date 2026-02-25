import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  createSubscriptionRepository,
  createPaymentRepository,
} from './platform.repository.js';
import {
  handleCancellation,
  refundAnnualSubscription,
  type CancellationServiceDeps,
  type CancellationStripeClient,
} from './cancellation.service.js';

// ---------------------------------------------------------------------------
// In-memory stores
// ---------------------------------------------------------------------------

let subscriptionStore: Record<string, any>[];
let paymentStore: Record<string, any>[];
let componentStore: Record<string, any>[];
let incidentStore: Record<string, any>[];
let incidentUpdateStore: Record<string, any>[];
let practiceMembershipStore: Record<string, any>[];

// ---------------------------------------------------------------------------
// Mock Drizzle DB (same pattern as platform.test.ts)
// ---------------------------------------------------------------------------

function makeMockDb() {
  function getStoreForTable(table: any): Record<string, any>[] {
    if (table?.__table === 'payment_history') return paymentStore;
    if (table?.__table === 'status_components') return componentStore;
    if (table?.__table === 'status_incidents') return incidentStore;
    if (table?.__table === 'incident_updates') return incidentUpdateStore;
    if (table?.__table === 'practice_memberships') return practiceMembershipStore;
    return subscriptionStore;
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

    if (table?.__table === 'subscriptions') {
      const newSub = {
        subscriptionId: values.subscriptionId ?? crypto.randomUUID(),
        providerId: values.providerId,
        stripeCustomerId: values.stripeCustomerId,
        stripeSubscriptionId: values.stripeSubscriptionId,
        plan: values.plan,
        status: values.status ?? 'TRIAL',
        currentPeriodStart: values.currentPeriodStart,
        currentPeriodEnd: values.currentPeriodEnd,
        trialEnd: values.trialEnd ?? null,
        failedPaymentCount: values.failedPaymentCount ?? 0,
        suspendedAt: values.suspendedAt ?? null,
        cancelledAt: values.cancelledAt ?? null,
        deletionScheduledAt: values.deletionScheduledAt ?? null,
        earlyBirdLockedUntil: values.earlyBirdLockedUntil ?? null,
        earlyBirdExpiryNotified: values.earlyBirdExpiryNotified ?? false,
        createdAt: values.createdAt ?? new Date(),
        updatedAt: values.updatedAt ?? new Date(),
      };
      store.push(newSub);
      return newSub;
    }

    if (table?.__table === 'payment_history') {
      const newPayment = {
        paymentId: values.paymentId ?? crypto.randomUUID(),
        subscriptionId: values.subscriptionId,
        stripeInvoiceId: values.stripeInvoiceId,
        amountCad: values.amountCad,
        gstAmount: values.gstAmount,
        totalCad: values.totalCad,
        status: values.status,
        paidAt: values.paidAt ?? null,
        createdAt: values.createdAt ?? new Date(),
      };
      store.push(newPayment);
      return newPayment;
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
                case 'sum': {
                  const vals = matches
                    .map((r) => parseFloat(r[spec.__column] ?? '0'))
                    .filter((v) => !isNaN(v));
                  result[key] = vals.length > 0
                    ? vals.reduce((a: number, b: number) => a + b, 0).toFixed(2)
                    : null;
                  break;
                }
                case 'max': {
                  const dateVals = matches
                    .map((r) => r[spec.__column])
                    .filter((v) => v != null);
                  if (dateVals.length === 0) {
                    result[key] = null;
                  } else {
                    result[key] = dateVals.reduce((a: any, b: any) => {
                      const aTime = a instanceof Date ? a.getTime() : 0;
                      const bTime = b instanceof Date ? b.getTime() : 0;
                      return aTime >= bTime ? a : b;
                    });
                  }
                  break;
                }
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
    sql: (strings: TemplateStringsArray, ...values: any[]) => {
      const raw = strings.join('__PLACEHOLDER__');

      if (raw.includes('+ 1')) {
        const col = values[0];
        return {
          __sqlExpr: (row: any) => (row[col?.name] ?? 0) + 1,
        };
      }

      if (raw.includes('IN (')) {
        const col = values[0];
        const colName = col?.name;
        const inMatch = raw.match(/IN \(([^)]+)\)/);
        if (inMatch) {
          const inValues = inMatch[1].split(',').map((s: string) => s.trim().replace(/'/g, ''));
          return {
            __predicate: (row: any) => inValues.includes(row[colName]),
            __sqlExpr: () => null,
          };
        }
      }

      return { __sqlExpr: () => null };
    },
    isNotNull: (column: any) => {
      const colName = column?.name;
      return {
        __predicate: (row: any) => row[colName] != null,
      };
    },
  };
});

// Mock the schema module
vi.mock('@meritum/shared/schemas/db/platform.schema.js', () => {
  const makeCol = (name: string) => ({ name });

  const subscriptionsProxy: any = {
    __table: 'subscriptions',
    subscriptionId: makeCol('subscriptionId'),
    providerId: makeCol('providerId'),
    stripeCustomerId: makeCol('stripeCustomerId'),
    stripeSubscriptionId: makeCol('stripeSubscriptionId'),
    plan: makeCol('plan'),
    status: makeCol('status'),
    currentPeriodStart: makeCol('currentPeriodStart'),
    currentPeriodEnd: makeCol('currentPeriodEnd'),
    trialEnd: makeCol('trialEnd'),
    failedPaymentCount: makeCol('failedPaymentCount'),
    suspendedAt: makeCol('suspendedAt'),
    cancelledAt: makeCol('cancelledAt'),
    deletionScheduledAt: makeCol('deletionScheduledAt'),
    earlyBirdLockedUntil: makeCol('earlyBirdLockedUntil'),
    earlyBirdExpiryNotified: makeCol('earlyBirdExpiryNotified'),
    createdAt: makeCol('createdAt'),
    updatedAt: makeCol('updatedAt'),
  };

  const practiceMembershipsProxy: any = {
    __table: 'practice_memberships',
    membershipId: makeCol('membershipId'),
    practiceId: makeCol('practiceId'),
    physicianUserId: makeCol('physicianUserId'),
    billingMode: makeCol('billingMode'),
    joinedAt: makeCol('joinedAt'),
    removedAt: makeCol('removedAt'),
    removalEffectiveAt: makeCol('removalEffectiveAt'),
    isActive: makeCol('isActive'),
    createdAt: makeCol('createdAt'),
  };

  const paymentHistoryProxy: any = {
    __table: 'payment_history',
    paymentId: makeCol('paymentId'),
    subscriptionId: makeCol('subscriptionId'),
    stripeInvoiceId: makeCol('stripeInvoiceId'),
    amountCad: makeCol('amountCad'),
    gstAmount: makeCol('gstAmount'),
    totalCad: makeCol('totalCad'),
    status: makeCol('status'),
    paidAt: makeCol('paidAt'),
    createdAt: makeCol('createdAt'),
  };

  const statusComponentsProxy: any = {
    __table: 'status_components',
    componentId: makeCol('componentId'),
    name: makeCol('name'),
    displayName: makeCol('displayName'),
    status: makeCol('status'),
    description: makeCol('description'),
    sortOrder: makeCol('sortOrder'),
    updatedAt: makeCol('updatedAt'),
  };

  const statusIncidentsProxy: any = {
    __table: 'status_incidents',
    incidentId: makeCol('incidentId'),
    title: makeCol('title'),
    status: makeCol('status'),
    severity: makeCol('severity'),
    affectedComponents: makeCol('affectedComponents'),
    resolvedAt: makeCol('resolvedAt'),
    createdAt: makeCol('createdAt'),
    updatedAt: makeCol('updatedAt'),
  };

  const incidentUpdatesProxy: any = {
    __table: 'incident_updates',
    updateId: makeCol('updateId'),
    incidentId: makeCol('incidentId'),
    status: makeCol('status'),
    message: makeCol('message'),
    createdAt: makeCol('createdAt'),
  };

  return {
    subscriptions: subscriptionsProxy,
    paymentHistory: paymentHistoryProxy,
    statusComponents: statusComponentsProxy,
    statusIncidents: statusIncidentsProxy,
    incidentUpdates: incidentUpdatesProxy,
    practiceMemberships: practiceMembershipsProxy,
  };
});

// Mock constants — include all cancellation-related exports
vi.mock('@meritum/shared/constants/platform.constants.js', () => ({
  DUNNING_SUSPENSION_DAY: 14,
  DUNNING_CANCELLATION_DAY: 30,
  EARLY_BIRD_CAP: 100,
  EARLY_BIRD_RATE_LOCK_MONTHS: 12,
  EARLY_BIRD_EXPIRY_WARNING_DAYS: 30,
  ANNUAL_MINIMUM_COMMITMENT_MONTHS: 6,
  ANNUAL_CANCELLATION_FORFEIT_MESSAGE:
    'Annual subscriptions require a 6-month minimum commitment. Your access continues until [period end date].',
  SubscriptionPlan: {
    STANDARD_MONTHLY: 'STANDARD_MONTHLY',
    STANDARD_ANNUAL: 'STANDARD_ANNUAL',
    EARLY_BIRD_MONTHLY: 'EARLY_BIRD_MONTHLY',
    EARLY_BIRD_ANNUAL: 'EARLY_BIRD_ANNUAL',
    CLINIC_MONTHLY: 'CLINIC_MONTHLY',
    CLINIC_ANNUAL: 'CLINIC_ANNUAL',
  },
  SubscriptionPlanPricing: {
    STANDARD_MONTHLY: { plan: 'STANDARD_MONTHLY', amount: '279.00', interval: 'month', label: 'Standard Monthly' },
    STANDARD_ANNUAL: { plan: 'STANDARD_ANNUAL', amount: '3181.00', interval: 'year', label: 'Standard Annual' },
    EARLY_BIRD_MONTHLY: { plan: 'EARLY_BIRD_MONTHLY', amount: '199.00', interval: 'month', label: 'Early Bird Monthly' },
    EARLY_BIRD_ANNUAL: { plan: 'EARLY_BIRD_ANNUAL', amount: '2388.00', interval: 'year', label: 'Early Bird Annual' },
    CLINIC_MONTHLY: { plan: 'CLINIC_MONTHLY', amount: '251.10', interval: 'month', label: 'Clinic Monthly' },
    CLINIC_ANNUAL: { plan: 'CLINIC_ANNUAL', amount: '2863.00', interval: 'year', label: 'Clinic Annual' },
  },
  GST_RATE: 0.05,
  DELETION_GRACE_PERIOD_DAYS: 30,
  PaymentStatus: {
    PAID: 'PAID',
    FAILED: 'FAILED',
    REFUNDED: 'REFUNDED',
  },
  CancellationPolicy: {
    FORFEIT_PERIOD: 'FORFEIT_PERIOD',
    PRORATED_REFUND: 'PRORATED_REFUND',
    MONTHLY_CANCEL: 'MONTHLY_CANCEL',
  },
  determineCancellationPolicy: (plan: string, monthsElapsed: number) => {
    if (plan.includes('MONTHLY')) return 'MONTHLY_CANCEL';
    if (monthsElapsed < 6) return 'FORFEIT_PERIOD';
    return 'PRORATED_REFUND';
  },
  calculateAnnualRefund: (annualAmount: number, monthsUsed: number) => {
    if (monthsUsed < 6) return null;
    const monthlyRate = annualAmount / 12;
    const monthsRemaining = Math.max(0, 12 - monthsUsed);
    const refundAmount = parseFloat((monthsRemaining * monthlyRate).toFixed(2));
    return { refundAmount, monthsRemaining, monthlyRate };
  },
  StripeWebhookEvent: {
    INVOICE_PAID: 'invoice.paid',
    INVOICE_PAYMENT_FAILED: 'invoice.payment_failed',
    INVOICE_CREATED: 'invoice.created',
    SUBSCRIPTION_UPDATED: 'customer.subscription.updated',
    SUBSCRIPTION_DELETED: 'customer.subscription.deleted',
    CHECKOUT_SESSION_COMPLETED: 'checkout.session.completed',
  },
  FeatureAccessMatrix: {
    ACTIVE: ['claim_create', 'claim_view', 'claim_edit'],
    TRIAL: ['claim_create', 'claim_view', 'claim_edit'],
    PAST_DUE: ['claim_create', 'claim_view', 'claim_edit'],
    SUSPENDED: ['claim_view', 'data_export'],
    CANCELLED: ['data_export'],
  },
  Feature: { DATA_EXPORT: 'data_export' },
  StatusComponent: {},
  ComponentHealth: {},
  IncidentStatus: {},
}));

vi.mock('@meritum/shared/constants/iam.constants.js', () => ({
  SubscriptionStatus: {
    TRIAL: 'TRIAL',
    ACTIVE: 'ACTIVE',
    PAST_DUE: 'PAST_DUE',
    SUSPENDED: 'SUSPENDED',
    CANCELLED: 'CANCELLED',
  },
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const DAY_MS = 24 * 60 * 60 * 1000;

function makeSubscription(overrides: Partial<Record<string, any>> = {}) {
  return {
    subscriptionId: overrides.subscriptionId ?? crypto.randomUUID(),
    providerId: overrides.providerId ?? crypto.randomUUID(),
    stripeCustomerId: overrides.stripeCustomerId ?? `cus_${crypto.randomUUID().slice(0, 14)}`,
    stripeSubscriptionId: overrides.stripeSubscriptionId ?? `sub_${crypto.randomUUID().slice(0, 14)}`,
    plan: overrides.plan ?? 'STANDARD_MONTHLY',
    status: overrides.status ?? 'ACTIVE',
    currentPeriodStart: overrides.currentPeriodStart ?? new Date(),
    currentPeriodEnd: overrides.currentPeriodEnd ?? new Date(Date.now() + 365 * DAY_MS),
    trialEnd: overrides.trialEnd ?? null,
    failedPaymentCount: overrides.failedPaymentCount ?? 0,
    suspendedAt: overrides.suspendedAt ?? null,
    cancelledAt: overrides.cancelledAt ?? null,
    deletionScheduledAt: overrides.deletionScheduledAt ?? null,
    earlyBirdLockedUntil: overrides.earlyBirdLockedUntil ?? null,
    earlyBirdExpiryNotified: overrides.earlyBirdExpiryNotified ?? false,
    createdAt: overrides.createdAt ?? new Date(),
    updatedAt: overrides.updatedAt ?? new Date(),
  };
}

function makePayment(overrides: Partial<Record<string, any>> = {}) {
  return {
    paymentId: overrides.paymentId ?? crypto.randomUUID(),
    subscriptionId: overrides.subscriptionId ?? crypto.randomUUID(),
    stripeInvoiceId: overrides.stripeInvoiceId ?? `in_${crypto.randomUUID().slice(0, 14)}`,
    amountCad: overrides.amountCad ?? '3181.00',
    gstAmount: overrides.gstAmount ?? '159.05',
    totalCad: overrides.totalCad ?? '3340.05',
    status: overrides.status ?? 'PAID',
    paidAt: overrides.paidAt ?? new Date(),
    createdAt: overrides.createdAt ?? new Date(),
  };
}

function createMockStripe(): CancellationStripeClient {
  return {
    subscriptions: {
      update: vi.fn(async () => ({ id: 'sub_test', status: 'active' })),
    },
    refunds: {
      create: vi.fn(async (params) => ({
        id: `re_${crypto.randomUUID().slice(0, 14)}`,
        amount: params.amount,
        status: 'succeeded',
      })),
    },
  };
}

function makeDeps(): {
  deps: CancellationServiceDeps;
  stripe: CancellationStripeClient;
} {
  const db = makeMockDb();
  const subscriptionRepo = createSubscriptionRepository(db);
  const paymentRepo = createPaymentRepository(db);
  const stripe = createMockStripe();

  return {
    deps: { subscriptionRepo, paymentRepo, stripe },
    stripe,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('D19-002/003: Cancellation Service', () => {
  beforeEach(() => {
    subscriptionStore = [];
    paymentStore = [];
    componentStore = [];
    incidentStore = [];
    incidentUpdateStore = [];
    practiceMembershipStore = [];
  });

  // -------------------------------------------------------------------------
  // Monthly plan: cancels at period end, no refund
  // -------------------------------------------------------------------------

  it('monthly plan: cancels at period end with no refund', async () => {
    const { deps, stripe } = makeDeps();
    const userId = crypto.randomUUID();

    // Create a monthly subscription
    const sub = makeSubscription({
      providerId: userId,
      plan: 'STANDARD_MONTHLY',
      status: 'ACTIVE',
      currentPeriodStart: new Date(),
      currentPeriodEnd: new Date(Date.now() + 30 * DAY_MS),
    });
    subscriptionStore.push(sub);

    const result = await handleCancellation(deps, userId);

    expect(result.policy).toBe('MONTHLY_CANCEL');
    expect(result.refundAmount).toBeNull();
    expect(result.periodEnd).toBeDefined();
    expect(result.message).toContain('Monthly subscription');
    expect(stripe.subscriptions.update).toHaveBeenCalledWith(
      sub.stripeSubscriptionId,
      { cancel_at_period_end: true },
    );

    // Local subscription should be updated to CANCELLED
    const updated = subscriptionStore.find((s) => s.providerId === userId);
    expect(updated?.status).toBe('CANCELLED');
    expect(updated?.cancelledAt).toBeDefined();
  });

  // -------------------------------------------------------------------------
  // Annual plan, month 3: forfeit period, no refund, access continues
  // -------------------------------------------------------------------------

  it('annual plan month 3: forfeit period, no refund, access continues', async () => {
    const { deps, stripe } = makeDeps();
    const userId = crypto.randomUUID();

    // Create annual subscription started 3 months ago
    const threeMonthsAgo = new Date(Date.now() - 90 * DAY_MS);
    const sub = makeSubscription({
      providerId: userId,
      plan: 'STANDARD_ANNUAL',
      status: 'ACTIVE',
      currentPeriodStart: threeMonthsAgo,
      currentPeriodEnd: new Date(threeMonthsAgo.getTime() + 365 * DAY_MS),
    });
    subscriptionStore.push(sub);

    const result = await handleCancellation(deps, userId);

    expect(result.policy).toBe('FORFEIT_PERIOD');
    expect(result.refundAmount).toBeNull();
    expect(result.message).toContain('6-month minimum commitment');
    expect(result.message).toContain('access continues');
    expect(stripe.subscriptions.update).toHaveBeenCalledWith(
      sub.stripeSubscriptionId,
      { cancel_at_period_end: true },
    );
    expect(stripe.refunds.create).not.toHaveBeenCalled();
  });

  // -------------------------------------------------------------------------
  // Annual plan, month 8: prorated refund for 4 remaining months
  // -------------------------------------------------------------------------

  it('annual plan month 8: prorated refund for 4 remaining months', async () => {
    const { deps, stripe } = makeDeps();
    const userId = crypto.randomUUID();

    // Create annual subscription started 8 months ago
    const eightMonthsAgo = new Date(Date.now() - 240 * DAY_MS);
    const subId = crypto.randomUUID();
    const sub = makeSubscription({
      subscriptionId: subId,
      providerId: userId,
      plan: 'STANDARD_ANNUAL',
      status: 'ACTIVE',
      currentPeriodStart: eightMonthsAgo,
      currentPeriodEnd: new Date(eightMonthsAgo.getTime() + 365 * DAY_MS),
    });
    subscriptionStore.push(sub);

    // Add a PAID payment for refund lookup
    const payment = makePayment({
      subscriptionId: subId,
      amountCad: '3181.00',
      status: 'PAID',
    });
    paymentStore.push(payment);

    const result = await handleCancellation(deps, userId);

    expect(result.policy).toBe('PRORATED_REFUND');
    // 4 remaining months: 4 * (3181 / 12) = 4 * 265.0833... = 1060.33
    expect(result.refundAmount).toBeCloseTo(1060.33, 1);
    expect(result.message).toContain('Refund');
    expect(result.message).toContain('4 remaining month(s)');
    expect(stripe.refunds.create).toHaveBeenCalled();

    // Verify the refund was created with correct cents amount
    const refundCall = (stripe.refunds.create as any).mock.calls[0][0];
    expect(refundCall.amount).toBe(Math.round(1060.33 * 100));

    expect(stripe.subscriptions.update).toHaveBeenCalledWith(
      sub.stripeSubscriptionId,
      { cancel_at_period_end: true },
    );
  });

  // -------------------------------------------------------------------------
  // Annual plan, month 12: zero refund (no remaining months)
  // -------------------------------------------------------------------------

  it('annual plan month 12: zero refund (no remaining months)', async () => {
    const { deps, stripe } = makeDeps();
    const userId = crypto.randomUUID();

    // Create annual subscription started 12 months ago
    const twelveMonthsAgo = new Date(Date.now() - 360 * DAY_MS);
    const subId = crypto.randomUUID();
    const sub = makeSubscription({
      subscriptionId: subId,
      providerId: userId,
      plan: 'STANDARD_ANNUAL',
      status: 'ACTIVE',
      currentPeriodStart: twelveMonthsAgo,
      currentPeriodEnd: new Date(twelveMonthsAgo.getTime() + 365 * DAY_MS),
    });
    subscriptionStore.push(sub);

    const result = await handleCancellation(deps, userId);

    expect(result.policy).toBe('PRORATED_REFUND');
    expect(result.refundAmount).toBe(0);
    expect(result.message).toContain('No refund');
    expect(result.message).toContain('fully used');
    // No Stripe refund should be created for zero amount
    expect(stripe.refunds.create).not.toHaveBeenCalled();
  });

  // -------------------------------------------------------------------------
  // Already cancelled: throws error
  // -------------------------------------------------------------------------

  it('already cancelled: throws BusinessRuleError', async () => {
    const { deps } = makeDeps();
    const userId = crypto.randomUUID();

    const sub = makeSubscription({
      providerId: userId,
      status: 'CANCELLED',
      cancelledAt: new Date(),
    });
    subscriptionStore.push(sub);

    await expect(handleCancellation(deps, userId)).rejects.toThrow(
      'Subscription is already cancelled',
    );
  });

  // -------------------------------------------------------------------------
  // No subscription: throws error
  // -------------------------------------------------------------------------

  it('no subscription: throws BusinessRuleError', async () => {
    const { deps } = makeDeps();
    const userId = crypto.randomUUID();

    await expect(handleCancellation(deps, userId)).rejects.toThrow(
      'No active subscription found',
    );
  });

  // -------------------------------------------------------------------------
  // Stripe refund creation with correct amount in cents
  // -------------------------------------------------------------------------

  it('refundAnnualSubscription creates Stripe refund with correct cents amount', async () => {
    const { deps, stripe } = makeDeps();
    const subId = crypto.randomUUID();

    // Add a PAID payment
    const payment = makePayment({
      subscriptionId: subId,
      amountCad: '3181.00',
      status: 'PAID',
    });
    paymentStore.push(payment);

    const refundAmountCad = 1060.33;
    const result = await refundAnnualSubscription(deps, subId, refundAmountCad);

    expect(result.refundId).toBeDefined();
    expect(result.amount).toBe(1060.33);
    expect(result.status).toBe('succeeded');

    // Verify Stripe was called with correct cents
    expect(stripe.refunds.create).toHaveBeenCalledWith({
      payment_intent: payment.stripeInvoiceId,
      amount: Math.round(1060.33 * 100),
    });

    // Verify refund was recorded in payment store with negative amount
    const refundPayment = paymentStore.find((p) => p.status === 'REFUNDED');
    expect(refundPayment).toBeDefined();
    expect(parseFloat(refundPayment!.amountCad)).toBeLessThan(0);
    expect(parseFloat(refundPayment!.totalCad)).toBeLessThan(0);
  });
});
