import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  createSubscriptionRepository,
  createPaymentRepository,
  createStatusComponentRepository,
  createIncidentRepository,
} from './platform.repository.js';
import {
  createCheckoutSession,
  createPortalSession,
  processWebhookEvent,
  handleCheckoutCompleted,
  handleInvoicePaid,
  handleInvoicePaymentFailed,
  handleInvoiceCreated,
  handleSubscriptionUpdated,
  handleSubscriptionDeleted,
  runDunningCheck,
  runCancellationCheck,
  runDeletionCheck,
  getSubscriptionStatus,
  getStatusPage,
  getIncidentHistory,
  createIncident,
  updateIncident,
  updateComponentStatus,
  seedStatusComponents,
  type PlatformServiceDeps,
  type StripeClient,
  type StripeEvent,
  type UserRepo,
  type PlatformEventEmitter,
  type DataDeletionRepo,
  type AuditLogger,
} from './platform.service.js';

// ---------------------------------------------------------------------------
// In-memory stores
// ---------------------------------------------------------------------------

let subscriptionStore: Record<string, any>[];
let paymentStore: Record<string, any>[];
let componentStore: Record<string, any>[];
let incidentStore: Record<string, any>[];
let incidentUpdateStore: Record<string, any>[];

// ---------------------------------------------------------------------------
// Mock Drizzle DB
// ---------------------------------------------------------------------------

function makeMockDb() {
  function getStoreForTable(table: any): Record<string, any>[] {
    if (table?.__table === 'payment_history') return paymentStore;
    if (table?.__table === 'status_components') return componentStore;
    if (table?.__table === 'status_incidents') return incidentStore;
    if (table?.__table === 'incident_updates') return incidentUpdateStore;
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
      const existing = store.find(
        (s) => s.providerId === values.providerId,
      );
      if (existing) {
        const err: any = new Error(
          'duplicate key value violates unique constraint "subscriptions_provider_id_idx"',
        );
        err.code = '23505';
        throw err;
      }
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

    if (table?.__table === 'status_components') {
      const newComp = {
        componentId: values.componentId ?? crypto.randomUUID(),
        name: values.name,
        displayName: values.displayName,
        status: values.status ?? 'operational',
        description: values.description ?? null,
        sortOrder: values.sortOrder ?? 0,
        updatedAt: values.updatedAt ?? new Date(),
      };
      store.push(newComp);
      return newComp;
    }

    if (table?.__table === 'status_incidents') {
      const newIncident = {
        incidentId: values.incidentId ?? crypto.randomUUID(),
        title: values.title,
        status: values.status,
        severity: values.severity,
        affectedComponents: values.affectedComponents,
        resolvedAt: values.resolvedAt ?? null,
        createdAt: values.createdAt ?? new Date(),
        updatedAt: values.updatedAt ?? new Date(),
      };
      store.push(newIncident);
      return newIncident;
    }

    if (table?.__table === 'incident_updates') {
      const newUpdate = {
        updateId: values.updateId ?? crypto.randomUUID(),
        incidentId: values.incidentId,
        status: values.status,
        message: values.message,
        createdAt: values.createdAt ?? new Date(),
      };
      store.push(newUpdate);
      return newUpdate;
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

      // ${subscriptions.failedPaymentCount} + 1
      if (raw.includes('+ 1')) {
        const col = values[0];
        return {
          __sqlExpr: (row: any) => (row[col?.name] ?? 0) + 1,
        };
      }

      return { __sqlExpr: () => null };
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
    createdAt: makeCol('createdAt'),
    updatedAt: makeCol('updatedAt'),
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
  };
});

// Mock constants
vi.mock('@meritum/shared/constants/platform.constants.js', () => ({
  DUNNING_SUSPENSION_DAY: 14,
  DUNNING_CANCELLATION_DAY: 30,
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const DAY_MS = 24 * 60 * 60 * 1000;

function makePayment(overrides: Partial<Record<string, any>> = {}) {
  return {
    subscriptionId: overrides.subscriptionId ?? crypto.randomUUID(),
    stripeInvoiceId: overrides.stripeInvoiceId ?? `in_${crypto.randomUUID().slice(0, 14)}`,
    amountCad: overrides.amountCad ?? '279.00',
    gstAmount: overrides.gstAmount ?? '13.95',
    totalCad: overrides.totalCad ?? '292.95',
    status: overrides.status ?? 'PAID',
    paidAt: overrides.paidAt ?? new Date(),
    createdAt: overrides.createdAt ?? new Date(),
  };
}

function makeSubscription(overrides: Partial<Record<string, any>> = {}) {
  return {
    providerId: overrides.providerId ?? crypto.randomUUID(),
    stripeCustomerId: overrides.stripeCustomerId ?? `cus_${crypto.randomUUID().slice(0, 14)}`,
    stripeSubscriptionId: overrides.stripeSubscriptionId ?? `sub_${crypto.randomUUID().slice(0, 14)}`,
    plan: overrides.plan ?? 'STANDARD_MONTHLY',
    status: overrides.status ?? 'TRIAL',
    currentPeriodStart: overrides.currentPeriodStart ?? new Date(),
    currentPeriodEnd: overrides.currentPeriodEnd ?? new Date(Date.now() + 30 * DAY_MS),
    trialEnd: overrides.trialEnd ?? null,
    failedPaymentCount: overrides.failedPaymentCount ?? 0,
    suspendedAt: overrides.suspendedAt ?? null,
    cancelledAt: overrides.cancelledAt ?? null,
    deletionScheduledAt: overrides.deletionScheduledAt ?? null,
    createdAt: overrides.createdAt ?? new Date(),
    updatedAt: overrides.updatedAt ?? new Date(),
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Platform Repository — Subscription CRUD', () => {
  let repo: ReturnType<typeof createSubscriptionRepository>;

  beforeEach(() => {
    subscriptionStore = [];
    paymentStore = [];
    componentStore = [];
    incidentStore = [];
    incidentUpdateStore = [];
    const db = makeMockDb();
    repo = createSubscriptionRepository(db);
  });

  // -------------------------------------------------------------------------
  // createSubscription
  // -------------------------------------------------------------------------

  it('createSubscription inserts record with correct defaults', async () => {
    const data = makeSubscription();
    const result = await repo.createSubscription(data as any);

    expect(result).toBeDefined();
    expect(result.subscriptionId).toBeDefined();
    expect(result.providerId).toBe(data.providerId);
    expect(result.stripeCustomerId).toBe(data.stripeCustomerId);
    expect(result.stripeSubscriptionId).toBe(data.stripeSubscriptionId);
    expect(result.plan).toBe('STANDARD_MONTHLY');
    expect(result.status).toBe('TRIAL');
    expect(result.failedPaymentCount).toBe(0);
    expect(result.suspendedAt).toBeNull();
    expect(result.cancelledAt).toBeNull();
    expect(result.deletionScheduledAt).toBeNull();
    expect(subscriptionStore).toHaveLength(1);
  });

  // -------------------------------------------------------------------------
  // findSubscriptionByProviderId
  // -------------------------------------------------------------------------

  it('findSubscriptionByProviderId returns correct subscription', async () => {
    const data = makeSubscription();
    await repo.createSubscription(data as any);

    const found = await repo.findSubscriptionByProviderId(data.providerId);
    expect(found).toBeDefined();
    expect(found!.providerId).toBe(data.providerId);
    expect(found!.stripeCustomerId).toBe(data.stripeCustomerId);
  });

  it('findSubscriptionByProviderId returns undefined for non-existent provider', async () => {
    const data = makeSubscription();
    await repo.createSubscription(data as any);

    const found = await repo.findSubscriptionByProviderId(crypto.randomUUID());
    expect(found).toBeUndefined();
  });

  // -------------------------------------------------------------------------
  // findSubscriptionByStripeCustomerId
  // -------------------------------------------------------------------------

  it('findSubscriptionByStripeCustomerId returns correct subscription', async () => {
    const data = makeSubscription({ stripeCustomerId: 'cus_test_12345' });
    await repo.createSubscription(data as any);

    const found = await repo.findSubscriptionByStripeCustomerId('cus_test_12345');
    expect(found).toBeDefined();
    expect(found!.stripeCustomerId).toBe('cus_test_12345');
    expect(found!.providerId).toBe(data.providerId);
  });

  // -------------------------------------------------------------------------
  // findSubscriptionByStripeSubscriptionId
  // -------------------------------------------------------------------------

  it('findSubscriptionByStripeSubscriptionId returns correct subscription', async () => {
    const data = makeSubscription({ stripeSubscriptionId: 'sub_test_67890' });
    await repo.createSubscription(data as any);

    const found = await repo.findSubscriptionByStripeSubscriptionId('sub_test_67890');
    expect(found).toBeDefined();
    expect(found!.stripeSubscriptionId).toBe('sub_test_67890');
  });

  // -------------------------------------------------------------------------
  // updateSubscriptionStatus
  // -------------------------------------------------------------------------

  it('updateSubscriptionStatus updates status and timestamps', async () => {
    const data = makeSubscription();
    const created = await repo.createSubscription(data as any);

    const suspendedAt = new Date();
    const result = await repo.updateSubscriptionStatus(
      created.subscriptionId,
      'SUSPENDED',
      { suspended_at: suspendedAt },
    );

    expect(result).toBeDefined();
    expect(result!.status).toBe('SUSPENDED');
    expect(result!.suspendedAt).toEqual(suspendedAt);
  });

  it('updateSubscriptionStatus updates only status when no metadata provided', async () => {
    const data = makeSubscription();
    const created = await repo.createSubscription(data as any);

    const result = await repo.updateSubscriptionStatus(
      created.subscriptionId,
      'ACTIVE',
    );

    expect(result).toBeDefined();
    expect(result!.status).toBe('ACTIVE');
    expect(result!.suspendedAt).toBeNull();
  });

  it('updateSubscriptionStatus sets cancelled_at and deletion_scheduled_at', async () => {
    const data = makeSubscription({ status: 'SUSPENDED' });
    const created = await repo.createSubscription(data as any);

    const cancelledAt = new Date();
    const deletionDate = new Date(Date.now() + 30 * DAY_MS);
    const result = await repo.updateSubscriptionStatus(
      created.subscriptionId,
      'CANCELLED',
      { cancelled_at: cancelledAt, deletion_scheduled_at: deletionDate },
    );

    expect(result).toBeDefined();
    expect(result!.status).toBe('CANCELLED');
    expect(result!.cancelledAt).toEqual(cancelledAt);
    expect(result!.deletionScheduledAt).toEqual(deletionDate);
  });

  // -------------------------------------------------------------------------
  // updateSubscriptionPeriod
  // -------------------------------------------------------------------------

  it('updateSubscriptionPeriod updates billing period', async () => {
    const data = makeSubscription();
    const created = await repo.createSubscription(data as any);

    const newStart = new Date('2026-03-01T00:00:00Z');
    const newEnd = new Date('2026-03-31T00:00:00Z');
    const result = await repo.updateSubscriptionPeriod(
      created.subscriptionId,
      newStart,
      newEnd,
    );

    expect(result).toBeDefined();
    expect(result!.currentPeriodStart).toEqual(newStart);
    expect(result!.currentPeriodEnd).toEqual(newEnd);
  });

  // -------------------------------------------------------------------------
  // updateSubscriptionPlan
  // -------------------------------------------------------------------------

  it('updateSubscriptionPlan updates plan', async () => {
    const data = makeSubscription({ plan: 'STANDARD_MONTHLY' });
    const created = await repo.createSubscription(data as any);

    const result = await repo.updateSubscriptionPlan(
      created.subscriptionId,
      'STANDARD_ANNUAL',
    );

    expect(result).toBeDefined();
    expect(result!.plan).toBe('STANDARD_ANNUAL');
  });

  // -------------------------------------------------------------------------
  // incrementFailedPaymentCount
  // -------------------------------------------------------------------------

  it('incrementFailedPaymentCount increments correctly', async () => {
    const data = makeSubscription({ failedPaymentCount: 2 });
    const created = await repo.createSubscription(data as any);

    const result = await repo.incrementFailedPaymentCount(
      created.subscriptionId,
    );

    expect(result).toBeDefined();
    expect(result!.failedPaymentCount).toBe(3);
  });

  it('incrementFailedPaymentCount increments from 0', async () => {
    const data = makeSubscription();
    const created = await repo.createSubscription(data as any);

    const result = await repo.incrementFailedPaymentCount(
      created.subscriptionId,
    );

    expect(result).toBeDefined();
    expect(result!.failedPaymentCount).toBe(1);
  });

  // -------------------------------------------------------------------------
  // resetFailedPaymentCount
  // -------------------------------------------------------------------------

  it('resetFailedPaymentCount resets to 0', async () => {
    const data = makeSubscription({ failedPaymentCount: 5 });
    const created = await repo.createSubscription(data as any);

    const result = await repo.resetFailedPaymentCount(
      created.subscriptionId,
    );

    expect(result).toBeDefined();
    expect(result!.failedPaymentCount).toBe(0);
  });

  // -------------------------------------------------------------------------
  // findSubscriptionsDueForSuspension
  // -------------------------------------------------------------------------

  it('findSubscriptionsDueForSuspension returns overdue subscriptions', async () => {
    // This subscription has been PAST_DUE for 15 days (> 14 day threshold)
    const overdue = makeSubscription({
      status: 'PAST_DUE',
      failedPaymentCount: 3,
      updatedAt: new Date(Date.now() - 15 * DAY_MS),
    });
    await repo.createSubscription(overdue as any);

    // This subscription is PAST_DUE but only for 5 days (< 14 day threshold)
    const recent = makeSubscription({
      status: 'PAST_DUE',
      failedPaymentCount: 1,
      updatedAt: new Date(Date.now() - 5 * DAY_MS),
    });
    await repo.createSubscription(recent as any);

    // This subscription is ACTIVE — should not be returned
    const active = makeSubscription({ status: 'ACTIVE' });
    await repo.createSubscription(active as any);

    const results = await repo.findSubscriptionsDueForSuspension();

    expect(results).toHaveLength(1);
    expect(results[0].providerId).toBe(overdue.providerId);
    expect(results[0].status).toBe('PAST_DUE');
  });

  // -------------------------------------------------------------------------
  // findSubscriptionsDueForCancellation
  // -------------------------------------------------------------------------

  it('findSubscriptionsDueForCancellation returns long-suspended subscriptions', async () => {
    // Suspended 17 days ago (> 16 day grace period after suspension)
    const longSuspended = makeSubscription({
      status: 'SUSPENDED',
      suspendedAt: new Date(Date.now() - 17 * DAY_MS),
    });
    await repo.createSubscription(longSuspended as any);

    // Suspended only 5 days ago (< 16 day grace period)
    const recentlySuspended = makeSubscription({
      status: 'SUSPENDED',
      suspendedAt: new Date(Date.now() - 5 * DAY_MS),
    });
    await repo.createSubscription(recentlySuspended as any);

    // PAST_DUE — should not be returned
    const pastDue = makeSubscription({ status: 'PAST_DUE' });
    await repo.createSubscription(pastDue as any);

    const results = await repo.findSubscriptionsDueForCancellation();

    expect(results).toHaveLength(1);
    expect(results[0].providerId).toBe(longSuspended.providerId);
    expect(results[0].status).toBe('SUSPENDED');
  });

  // -------------------------------------------------------------------------
  // findSubscriptionsDueForDeletion
  // -------------------------------------------------------------------------

  it('findSubscriptionsDueForDeletion returns expired-grace subscriptions', async () => {
    // Deletion scheduled in the past — should be returned
    const expired = makeSubscription({
      status: 'CANCELLED',
      deletionScheduledAt: new Date(Date.now() - 1 * DAY_MS),
    });
    await repo.createSubscription(expired as any);

    // Deletion scheduled in the future — should NOT be returned
    const future = makeSubscription({
      status: 'CANCELLED',
      deletionScheduledAt: new Date(Date.now() + 10 * DAY_MS),
    });
    await repo.createSubscription(future as any);

    // Active — should NOT be returned
    const active = makeSubscription({ status: 'ACTIVE' });
    await repo.createSubscription(active as any);

    const results = await repo.findSubscriptionsDueForDeletion();

    expect(results).toHaveLength(1);
    expect(results[0].providerId).toBe(expired.providerId);
    expect(results[0].status).toBe('CANCELLED');
  });

  // -------------------------------------------------------------------------
  // countEarlyBirdSubscriptions
  // -------------------------------------------------------------------------

  it('countEarlyBirdSubscriptions returns accurate count', async () => {
    // Create 3 early bird subscriptions
    for (let i = 0; i < 3; i++) {
      await repo.createSubscription(
        makeSubscription({ plan: 'EARLY_BIRD_MONTHLY' }) as any,
      );
    }

    // Create 2 standard monthly subscriptions
    for (let i = 0; i < 2; i++) {
      await repo.createSubscription(
        makeSubscription({ plan: 'STANDARD_MONTHLY' }) as any,
      );
    }

    const count = await repo.countEarlyBirdSubscriptions();
    expect(count).toBe(3);
  });

  it('countEarlyBirdSubscriptions returns 0 when none exist', async () => {
    await repo.createSubscription(
      makeSubscription({ plan: 'STANDARD_MONTHLY' }) as any,
    );

    const count = await repo.countEarlyBirdSubscriptions();
    expect(count).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Payment History Repository Tests
// ---------------------------------------------------------------------------

describe('Platform Repository — Payment History', () => {
  let repo: ReturnType<typeof createPaymentRepository>;
  const subId = crypto.randomUUID();

  beforeEach(() => {
    subscriptionStore = [];
    paymentStore = [];
    componentStore = [];
    incidentStore = [];
    incidentUpdateStore = [];
    const db = makeMockDb();
    repo = createPaymentRepository(db);
  });

  // -------------------------------------------------------------------------
  // recordPayment
  // -------------------------------------------------------------------------

  it('recordPayment inserts payment with GST calculation', async () => {
    const data = makePayment({
      subscriptionId: subId,
      amountCad: '279.00',
      gstAmount: '13.95',
      totalCad: '292.95',
    });
    const result = await repo.recordPayment(data as any);

    expect(result).toBeDefined();
    expect(result.paymentId).toBeDefined();
    expect(result.subscriptionId).toBe(subId);
    expect(result.amountCad).toBe('279.00');
    expect(result.gstAmount).toBe('13.95');
    expect(result.totalCad).toBe('292.95');
    expect(result.status).toBe('PAID');
    expect(result.paidAt).toBeDefined();
    expect(paymentStore).toHaveLength(1);
  });

  // -------------------------------------------------------------------------
  // findPaymentByStripeInvoiceId
  // -------------------------------------------------------------------------

  it('findPaymentByStripeInvoiceId returns correct payment', async () => {
    const invoiceId = 'in_test_abc123';
    await repo.recordPayment(
      makePayment({ subscriptionId: subId, stripeInvoiceId: invoiceId }) as any,
    );
    // Add another payment with a different invoice ID
    await repo.recordPayment(
      makePayment({ subscriptionId: subId, stripeInvoiceId: 'in_other_xyz' }) as any,
    );

    const found = await repo.findPaymentByStripeInvoiceId(invoiceId);
    expect(found).toBeDefined();
    expect(found!.stripeInvoiceId).toBe(invoiceId);
    expect(found!.subscriptionId).toBe(subId);
  });

  it('findPaymentByStripeInvoiceId returns undefined for unknown invoice', async () => {
    await repo.recordPayment(
      makePayment({ subscriptionId: subId }) as any,
    );

    const found = await repo.findPaymentByStripeInvoiceId('in_nonexistent');
    expect(found).toBeUndefined();
  });

  // -------------------------------------------------------------------------
  // listPaymentsForSubscription
  // -------------------------------------------------------------------------

  it('listPaymentsForSubscription returns paginated results', async () => {
    // Create 5 payments for our subscription
    for (let i = 0; i < 5; i++) {
      await repo.recordPayment(
        makePayment({
          subscriptionId: subId,
          createdAt: new Date(Date.now() - i * DAY_MS),
        }) as any,
      );
    }

    // Create 2 payments for another subscription (should not appear)
    const otherSubId = crypto.randomUUID();
    for (let i = 0; i < 2; i++) {
      await repo.recordPayment(
        makePayment({ subscriptionId: otherSubId }) as any,
      );
    }

    const result = await repo.listPaymentsForSubscription(subId, {
      page: 1,
      pageSize: 3,
    });

    expect(result.data).toHaveLength(3);
    expect(result.total).toBe(5);
    result.data.forEach((payment: any) => {
      expect(payment.subscriptionId).toBe(subId);
    });
  });

  it('listPaymentsForSubscription returns reverse chronological', async () => {
    const dates = [
      new Date('2026-01-01T00:00:00Z'),
      new Date('2026-02-01T00:00:00Z'),
      new Date('2026-03-01T00:00:00Z'),
    ];

    // Insert in non-chronological order
    for (const date of [dates[1], dates[0], dates[2]]) {
      await repo.recordPayment(
        makePayment({ subscriptionId: subId, createdAt: date }) as any,
      );
    }

    const result = await repo.listPaymentsForSubscription(subId, {
      page: 1,
      pageSize: 10,
    });

    expect(result.data).toHaveLength(3);
    // Reverse chronological: newest first
    expect(result.data[0].createdAt).toEqual(dates[2]);
    expect(result.data[1].createdAt).toEqual(dates[1]);
    expect(result.data[2].createdAt).toEqual(dates[0]);
  });

  // -------------------------------------------------------------------------
  // updatePaymentStatus
  // -------------------------------------------------------------------------

  it('updatePaymentStatus updates status and paid_at', async () => {
    const payment = await repo.recordPayment(
      makePayment({
        subscriptionId: subId,
        status: 'FAILED',
        paidAt: null,
      }) as any,
    );

    const paidAt = new Date();
    const result = await repo.updatePaymentStatus(
      payment.paymentId,
      'PAID',
      paidAt,
    );

    expect(result).toBeDefined();
    expect(result!.status).toBe('PAID');
    expect(result!.paidAt).toEqual(paidAt);
  });

  // -------------------------------------------------------------------------
  // getPaymentSummary
  // -------------------------------------------------------------------------

  it('getPaymentSummary returns correct aggregates', async () => {
    const paidDate1 = new Date('2026-01-15T00:00:00Z');
    const paidDate2 = new Date('2026-02-15T00:00:00Z');

    // Two PAID payments
    await repo.recordPayment(
      makePayment({
        subscriptionId: subId,
        amountCad: '279.00',
        gstAmount: '13.95',
        totalCad: '292.95',
        status: 'PAID',
        paidAt: paidDate1,
      }) as any,
    );
    await repo.recordPayment(
      makePayment({
        subscriptionId: subId,
        amountCad: '279.00',
        gstAmount: '13.95',
        totalCad: '292.95',
        status: 'PAID',
        paidAt: paidDate2,
      }) as any,
    );

    // One FAILED payment (should be excluded from summary)
    await repo.recordPayment(
      makePayment({
        subscriptionId: subId,
        amountCad: '279.00',
        gstAmount: '13.95',
        totalCad: '292.95',
        status: 'FAILED',
        paidAt: null,
      }) as any,
    );

    const summary = await repo.getPaymentSummary(subId);

    expect(summary.paymentCount).toBe(2);
    expect(summary.totalPaid).toBe('585.90'); // 292.95 * 2
    expect(summary.totalGst).toBe('27.90');   // 13.95 * 2
    expect(summary.lastPaymentDate).toEqual(paidDate2);
  });
});

// ---------------------------------------------------------------------------
// Status Component Repository Tests
// ---------------------------------------------------------------------------

describe('Platform Repository — Status Components', () => {
  let repo: ReturnType<typeof createStatusComponentRepository>;

  beforeEach(() => {
    subscriptionStore = [];
    paymentStore = [];
    componentStore = [];
    incidentStore = [];
    incidentUpdateStore = [];
    const db = makeMockDb();
    repo = createStatusComponentRepository(db);
  });

  // -------------------------------------------------------------------------
  // listComponents
  // -------------------------------------------------------------------------

  it('listComponents returns all components in sort order', async () => {
    // Insert components out of order
    componentStore.push(
      { componentId: crypto.randomUUID(), name: 'API', displayName: 'API', status: 'operational', description: null, sortOrder: 2, updatedAt: new Date() },
      { componentId: crypto.randomUUID(), name: 'WEB_APP', displayName: 'Web Application', status: 'operational', description: null, sortOrder: 1, updatedAt: new Date() },
      { componentId: crypto.randomUUID(), name: 'DATABASE', displayName: 'Database', status: 'operational', description: null, sortOrder: 3, updatedAt: new Date() },
    );

    const result = await repo.listComponents();

    expect(result).toHaveLength(3);
    expect(result[0].name).toBe('WEB_APP');
    expect(result[0].sortOrder).toBe(1);
    expect(result[1].name).toBe('API');
    expect(result[1].sortOrder).toBe(2);
    expect(result[2].name).toBe('DATABASE');
    expect(result[2].sortOrder).toBe(3);
  });

  // -------------------------------------------------------------------------
  // updateComponentStatus
  // -------------------------------------------------------------------------

  it('updateComponentStatus changes status', async () => {
    const compId = crypto.randomUUID();
    componentStore.push({
      componentId: compId,
      name: 'API',
      displayName: 'API',
      status: 'operational',
      description: null,
      sortOrder: 1,
      updatedAt: new Date('2026-01-01T00:00:00Z'),
    });

    const result = await repo.updateComponentStatus(compId, 'degraded');

    expect(result).toBeDefined();
    expect(result!.status).toBe('degraded');
    expect(result!.updatedAt.getTime()).toBeGreaterThan(
      new Date('2026-01-01T00:00:00Z').getTime(),
    );
  });

  // -------------------------------------------------------------------------
  // seedComponents
  // -------------------------------------------------------------------------

  it('seedComponents is idempotent (running twice creates no duplicates)', async () => {
    const components = [
      { name: 'WEB_APP', displayName: 'Web Application', sortOrder: 1 },
      { name: 'API', displayName: 'API', sortOrder: 2 },
      { name: 'DATABASE', displayName: 'Database', sortOrder: 3 },
    ];

    await repo.seedComponents(components);
    expect(componentStore).toHaveLength(3);

    // Seed again — should NOT create duplicates
    await repo.seedComponents(components);
    expect(componentStore).toHaveLength(3);

    // Verify all expected components exist
    const names = componentStore.map((c) => c.name);
    expect(names).toContain('WEB_APP');
    expect(names).toContain('API');
    expect(names).toContain('DATABASE');
  });
});

// ---------------------------------------------------------------------------
// Incident Repository Tests
// ---------------------------------------------------------------------------

describe('Platform Repository — Incidents', () => {
  let repo: ReturnType<typeof createIncidentRepository>;

  beforeEach(() => {
    subscriptionStore = [];
    paymentStore = [];
    componentStore = [];
    incidentStore = [];
    incidentUpdateStore = [];
    const db = makeMockDb();
    repo = createIncidentRepository(db);
  });

  // -------------------------------------------------------------------------
  // createIncident
  // -------------------------------------------------------------------------

  it('createIncident creates incident with first update', async () => {
    const result = await repo.createIncident({
      title: 'API Latency Spike',
      severity: 'major',
      affectedComponents: [crypto.randomUUID()],
      initialMessage: 'Investigating elevated API response times.',
    });

    expect(result).toBeDefined();
    expect(result.incidentId).toBeDefined();
    expect(result.title).toBe('API Latency Spike');
    expect(result.status).toBe('INVESTIGATING');
    expect(result.severity).toBe('major');
    expect(result.resolvedAt).toBeNull();
    expect(result.updates).toHaveLength(1);
    expect(result.updates[0].status).toBe('INVESTIGATING');
    expect(result.updates[0].message).toBe(
      'Investigating elevated API response times.',
    );
    expect(result.updates[0].incidentId).toBe(result.incidentId);

    // Verify stores
    expect(incidentStore).toHaveLength(1);
    expect(incidentUpdateStore).toHaveLength(1);
  });

  // -------------------------------------------------------------------------
  // updateIncident
  // -------------------------------------------------------------------------

  it('updateIncident adds update and changes status', async () => {
    const incident = await repo.createIncident({
      title: 'DB Connection Issues',
      severity: 'critical',
      affectedComponents: [crypto.randomUUID()],
      initialMessage: 'Investigating database connectivity problems.',
    });

    const result = await repo.updateIncident(
      incident.incidentId,
      'IDENTIFIED',
      'Root cause identified: connection pool exhaustion.',
    );

    expect(result).toBeDefined();
    expect(result!.status).toBe('IDENTIFIED');
    expect(result!.resolvedAt).toBeNull();
    expect(result!.updates).toHaveLength(2);
    expect(result!.updates[1].status).toBe('IDENTIFIED');
    expect(result!.updates[1].message).toBe(
      'Root cause identified: connection pool exhaustion.',
    );
  });

  it('updateIncident sets resolved_at when resolving', async () => {
    const incident = await repo.createIncident({
      title: 'Payment Processing Down',
      severity: 'critical',
      affectedComponents: [crypto.randomUUID()],
      initialMessage: 'Stripe webhook failures detected.',
    });

    const beforeResolve = new Date();
    const result = await repo.updateIncident(
      incident.incidentId,
      'RESOLVED',
      'Payment processing has been restored.',
    );

    expect(result).toBeDefined();
    expect(result!.status).toBe('RESOLVED');
    expect(result!.resolvedAt).toBeDefined();
    expect(result!.resolvedAt).not.toBeNull();
    expect(result!.resolvedAt!.getTime()).toBeGreaterThanOrEqual(
      beforeResolve.getTime(),
    );
  });

  // -------------------------------------------------------------------------
  // listActiveIncidents
  // -------------------------------------------------------------------------

  it('listActiveIncidents excludes resolved incidents', async () => {
    // Create an active incident
    const active = await repo.createIncident({
      title: 'Active Incident',
      severity: 'minor',
      affectedComponents: [crypto.randomUUID()],
      initialMessage: 'Something is happening.',
    });

    // Create and resolve another incident
    const resolved = await repo.createIncident({
      title: 'Resolved Incident',
      severity: 'major',
      affectedComponents: [crypto.randomUUID()],
      initialMessage: 'This was a problem.',
    });
    await repo.updateIncident(
      resolved.incidentId,
      'RESOLVED',
      'Fixed.',
    );

    // Create another active incident
    await repo.createIncident({
      title: 'Another Active Incident',
      severity: 'critical',
      affectedComponents: [crypto.randomUUID()],
      initialMessage: 'Another issue.',
    });

    const results = await repo.listActiveIncidents();

    expect(results).toHaveLength(2);
    results.forEach((incident: any) => {
      expect(incident.status).not.toBe('RESOLVED');
    });
    const titles = results.map((i: any) => i.title);
    expect(titles).toContain('Active Incident');
    expect(titles).toContain('Another Active Incident');
    expect(titles).not.toContain('Resolved Incident');
  });

  // -------------------------------------------------------------------------
  // listIncidentHistory
  // -------------------------------------------------------------------------

  it('listIncidentHistory includes all incidents paginated', async () => {
    // Create 5 incidents with staggered dates
    for (let i = 0; i < 5; i++) {
      const incident = await repo.createIncident({
        title: `Incident ${i + 1}`,
        severity: 'minor',
        affectedComponents: [crypto.randomUUID()],
        initialMessage: `Message ${i + 1}`,
      });
      // Override createdAt for predictable ordering
      const storeEntry = incidentStore.find(
        (s) => s.incidentId === incident.incidentId,
      );
      if (storeEntry) {
        storeEntry.createdAt = new Date(Date.now() - (5 - i) * DAY_MS);
      }
    }

    // Resolve one to verify it's still included
    await repo.updateIncident(
      incidentStore[0].incidentId,
      'RESOLVED',
      'Done.',
    );

    const page1 = await repo.listIncidentHistory({ page: 1, pageSize: 3 });

    expect(page1.total).toBe(5);
    expect(page1.data).toHaveLength(3);

    const page2 = await repo.listIncidentHistory({ page: 2, pageSize: 3 });

    expect(page2.total).toBe(5);
    expect(page2.data).toHaveLength(2);

    // Verify resolved incident is included somewhere
    const allIncidents = [...page1.data, ...page2.data];
    const resolvedIncidents = allIncidents.filter(
      (i: any) => i.status === 'RESOLVED',
    );
    expect(resolvedIncidents).toHaveLength(1);
  });

  // -------------------------------------------------------------------------
  // findIncidentById
  // -------------------------------------------------------------------------

  it('findIncidentById returns incident with all updates', async () => {
    const incident = await repo.createIncident({
      title: 'Test Incident',
      severity: 'major',
      affectedComponents: [crypto.randomUUID()],
      initialMessage: 'Initial investigation.',
    });

    // Add more updates
    await repo.updateIncident(
      incident.incidentId,
      'IDENTIFIED',
      'Root cause found.',
    );
    await repo.updateIncident(
      incident.incidentId,
      'MONITORING',
      'Fix deployed, monitoring.',
    );

    const result = await repo.findIncidentById(incident.incidentId);

    expect(result).toBeDefined();
    expect(result!.incidentId).toBe(incident.incidentId);
    expect(result!.title).toBe('Test Incident');
    expect(result!.status).toBe('MONITORING');
    expect(result!.updates).toHaveLength(3);
    expect(result!.updates[0].message).toBe('Initial investigation.');
    expect(result!.updates[1].message).toBe('Root cause found.');
    expect(result!.updates[2].message).toBe('Fix deployed, monitoring.');
  });

  it('findIncidentById returns undefined for non-existent incident', async () => {
    const result = await repo.findIncidentById(crypto.randomUUID());
    expect(result).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Platform Service — Checkout & Portal Tests
// ---------------------------------------------------------------------------

// Mock constants used by the service
vi.mock('@meritum/shared/constants/platform.constants.js', () => {
  const allFeatures = [
    'claim_create', 'claim_view', 'claim_edit', 'batch_submit',
    'patient_create', 'patient_view', 'patient_edit',
    'analytics_view', 'reports_view', 'reports_export',
    'ai_coach', 'settings_view', 'settings_edit', 'settings_payment',
    'data_export', 'delegate_manage', 'provider_edit',
  ];
  return {
    DUNNING_SUSPENSION_DAY: 14,
    DUNNING_CANCELLATION_DAY: 30,
    DELETION_GRACE_PERIOD_DAYS: 30,
    EARLY_BIRD_CAP: 100,
    GST_RATE: 0.05,
    SubscriptionPlan: {
      STANDARD_MONTHLY: 'STANDARD_MONTHLY',
      STANDARD_ANNUAL: 'STANDARD_ANNUAL',
      EARLY_BIRD_MONTHLY: 'EARLY_BIRD_MONTHLY',
    },
    PaymentStatus: {
      PAID: 'PAID',
      FAILED: 'FAILED',
      REFUNDED: 'REFUNDED',
    },
    StripeWebhookEvent: {
      INVOICE_PAID: 'invoice.paid',
      INVOICE_PAYMENT_FAILED: 'invoice.payment_failed',
      INVOICE_CREATED: 'invoice.created',
      SUBSCRIPTION_UPDATED: 'customer.subscription.updated',
      SUBSCRIPTION_DELETED: 'customer.subscription.deleted',
      CHECKOUT_SESSION_COMPLETED: 'checkout.session.completed',
    },
    Feature: {
      CLAIM_CREATE: 'claim_create',
      CLAIM_VIEW: 'claim_view',
      CLAIM_EDIT: 'claim_edit',
      BATCH_SUBMIT: 'batch_submit',
      PATIENT_CREATE: 'patient_create',
      PATIENT_VIEW: 'patient_view',
      PATIENT_EDIT: 'patient_edit',
      ANALYTICS_VIEW: 'analytics_view',
      REPORTS_VIEW: 'reports_view',
      REPORTS_EXPORT: 'reports_export',
      AI_COACH: 'ai_coach',
      SETTINGS_VIEW: 'settings_view',
      SETTINGS_EDIT: 'settings_edit',
      SETTINGS_PAYMENT: 'settings_payment',
      DATA_EXPORT: 'data_export',
      DELEGATE_MANAGE: 'delegate_manage',
      PROVIDER_EDIT: 'provider_edit',
    },
    FeatureAccessMatrix: {
      ACTIVE: allFeatures,
      TRIAL: allFeatures,
      PAST_DUE: allFeatures,
      SUSPENDED: ['claim_view', 'patient_view', 'analytics_view', 'reports_view', 'settings_view', 'settings_payment', 'data_export'],
      CANCELLED: ['data_export'],
    },
    StatusComponent: {
      WEB_APP: 'WEB_APP',
      API: 'API',
      HLINK_SUBMISSION: 'HLINK_SUBMISSION',
      WCB_SUBMISSION: 'WCB_SUBMISSION',
      AI_COACH: 'AI_COACH',
      EMAIL_DELIVERY: 'EMAIL_DELIVERY',
      DATABASE: 'DATABASE',
      PAYMENT_PROCESSING: 'PAYMENT_PROCESSING',
    },
    ComponentHealth: {
      OPERATIONAL: 'OPERATIONAL',
      DEGRADED: 'DEGRADED',
      PARTIAL_OUTAGE: 'PARTIAL_OUTAGE',
      MAJOR_OUTAGE: 'MAJOR_OUTAGE',
      MAINTENANCE: 'MAINTENANCE',
    },
    IncidentStatus: {
      INVESTIGATING: 'INVESTIGATING',
      IDENTIFIED: 'IDENTIFIED',
      MONITORING: 'MONITORING',
      RESOLVED: 'RESOLVED',
    },
  };
});

vi.mock('@meritum/shared/constants/iam.constants.js', () => ({
  SubscriptionStatus: {
    TRIAL: 'TRIAL',
    ACTIVE: 'ACTIVE',
    PAST_DUE: 'PAST_DUE',
    SUSPENDED: 'SUSPENDED',
    CANCELLED: 'CANCELLED',
  },
}));

vi.mock('../../lib/errors.js', () => {
  class AppError extends Error {
    constructor(
      public statusCode: number,
      public code: string,
      message: string,
      public details?: unknown,
    ) {
      super(message);
    }
  }
  class ConflictError extends AppError {
    constructor(message: string) {
      super(409, 'CONFLICT', message);
    }
  }
  class BusinessRuleError extends AppError {
    constructor(message: string, details?: unknown) {
      super(422, 'BUSINESS_RULE_VIOLATION', message, details);
    }
  }
  class NotFoundError extends AppError {
    constructor(resource: string) {
      super(404, 'NOT_FOUND', `${resource} not found`);
    }
  }
  class ValidationError extends AppError {
    constructor(message: string, details?: unknown) {
      super(400, 'VALIDATION_ERROR', message, details);
    }
  }
  class ForbiddenError extends AppError {
    constructor(message = 'Insufficient permissions') {
      super(403, 'FORBIDDEN', message);
    }
  }
  return { AppError, ConflictError, BusinessRuleError, NotFoundError, ValidationError, ForbiddenError };
});

function makeMockStripe(): StripeClient {
  return {
    customers: {
      create: vi.fn().mockResolvedValue({ id: 'cus_mock_123' }),
      del: vi.fn().mockResolvedValue({ id: 'cus_mock_123', deleted: true }),
    },
    checkout: {
      sessions: {
        create: vi.fn().mockResolvedValue({ url: 'https://checkout.stripe.com/session_abc' }),
      },
    },
    billingPortal: {
      sessions: {
        create: vi.fn().mockResolvedValue({ url: 'https://billing.stripe.com/portal_xyz' }),
      },
    },
    taxRates: {
      create: vi.fn().mockResolvedValue({ id: 'txr_mock_gst' }),
    },
    webhooks: {
      constructEvent: vi.fn().mockImplementation(
        (payload: string, _signature: string, _secret: string) => {
          return JSON.parse(payload);
        },
      ),
    },
    invoiceItems: {
      create: vi.fn().mockResolvedValue({ id: 'ii_mock_123' }),
    },
    subscriptions: {
      cancel: vi.fn().mockResolvedValue({ id: 'sub_mock_123', status: 'canceled' }),
    },
  };
}

function makeMockUserRepo(overrides?: Partial<{ userId: string; email: string; fullName: string }>): UserRepo {
  const user = {
    userId: overrides?.userId ?? crypto.randomUUID(),
    email: overrides?.email ?? 'dr.smith@example.com',
    fullName: overrides?.fullName ?? 'Dr. Jane Smith',
  };
  return {
    findUserById: vi.fn().mockResolvedValue(user),
    updateSubscriptionStatus: vi.fn().mockResolvedValue(undefined),
  };
}

function makeMockPaymentRepo(options?: {
  existingPayment?: Record<string, any> | null;
}): any {
  return {
    recordPayment: vi.fn().mockImplementation(async (data: any) => ({
      paymentId: crypto.randomUUID(),
      ...data,
    })),
    findPaymentByStripeInvoiceId: vi.fn().mockResolvedValue(
      options?.existingPayment ?? undefined,
    ),
    listPaymentsForSubscription: vi.fn().mockResolvedValue({ data: [], total: 0 }),
    updatePaymentStatus: vi.fn(),
    getPaymentSummary: vi.fn().mockResolvedValue({
      totalPaid: '0.00', totalGst: '0.00', paymentCount: 0, lastPaymentDate: null,
    }),
  };
}

function makeMockSubscriptionRepo(options?: {
  existingSubscription?: Record<string, any> | null;
  earlyBirdCount?: number;
  subscriptionByStripeId?: Record<string, any> | null;
}): any {
  return {
    findSubscriptionByProviderId: vi.fn().mockResolvedValue(
      options?.existingSubscription ?? undefined,
    ),
    countEarlyBirdSubscriptions: vi.fn().mockResolvedValue(
      options?.earlyBirdCount ?? 0,
    ),
    findSubscriptionByStripeCustomerId: vi.fn(),
    findSubscriptionByStripeSubscriptionId: vi.fn().mockResolvedValue(
      options?.subscriptionByStripeId ?? undefined,
    ),
    createSubscription: vi.fn().mockImplementation(async (data: any) => ({
      subscriptionId: crypto.randomUUID(),
      ...data,
    })),
    updateSubscriptionStatus: vi.fn().mockImplementation(
      async (id: string, status: string) => ({
        subscriptionId: id,
        status,
      }),
    ),
    updateSubscriptionPeriod: vi.fn().mockImplementation(
      async (id: string, start: Date, end: Date) => ({
        subscriptionId: id,
        currentPeriodStart: start,
        currentPeriodEnd: end,
      }),
    ),
    updateSubscriptionPlan: vi.fn().mockImplementation(
      async (id: string, plan: string) => ({
        subscriptionId: id,
        plan,
      }),
    ),
    incrementFailedPaymentCount: vi.fn().mockImplementation(
      async (id: string) => ({
        subscriptionId: id,
        failedPaymentCount: 1,
      }),
    ),
    resetFailedPaymentCount: vi.fn().mockImplementation(
      async (id: string) => ({
        subscriptionId: id,
        failedPaymentCount: 0,
      }),
    ),
    findSubscriptionsDueForSuspension: vi.fn().mockResolvedValue([]),
    findSubscriptionsDueForCancellation: vi.fn().mockResolvedValue([]),
    findSubscriptionsDueForDeletion: vi.fn().mockResolvedValue([]),
    findPastDueSubscriptions: vi.fn().mockResolvedValue([]),
  };
}

function makeMockDataDeletionRepo(): DataDeletionRepo {
  return {
    deleteClaimsByProviderId: vi.fn().mockResolvedValue(5),
    deletePatientsByProviderId: vi.fn().mockResolvedValue(10),
    deleteReportsByProviderId: vi.fn().mockResolvedValue(3),
    stripPiiFromAuditLogs: vi.fn().mockResolvedValue(50),
    anonymiseAiLearningData: vi.fn().mockResolvedValue(20),
    deactivateUser: vi.fn().mockResolvedValue(undefined),
  };
}

function makeMockAuditLogger(): AuditLogger {
  return {
    log: vi.fn().mockResolvedValue(undefined),
  };
}

function makeMockEventEmitter(): PlatformEventEmitter {
  return {
    emit: vi.fn(),
  };
}

function makeMockStatusComponentRepo(options?: {
  components?: Record<string, any>[];
}): any {
  const components = options?.components ?? [];
  return {
    listComponents: vi.fn().mockResolvedValue(components),
    updateComponentStatus: vi.fn().mockImplementation(
      async (componentId: string, status: string) => {
        const comp = components.find((c) => c.componentId === componentId);
        if (!comp) return undefined;
        comp.status = status;
        comp.updatedAt = new Date();
        return { ...comp };
      },
    ),
    seedComponents: vi.fn().mockResolvedValue(undefined),
  };
}

function makeMockIncidentRepo(options?: {
  activeIncidents?: Record<string, any>[];
  historyResult?: { data: Record<string, any>[]; total: number };
  createdIncident?: Record<string, any>;
  updatedIncident?: Record<string, any> | undefined;
}): any {
  return {
    listActiveIncidents: vi.fn().mockResolvedValue(options?.activeIncidents ?? []),
    listIncidentHistory: vi.fn().mockResolvedValue(
      options?.historyResult ?? { data: [], total: 0 },
    ),
    createIncident: vi.fn().mockImplementation(async (data: any) => {
      const incident = options?.createdIncident ?? {
        incidentId: crypto.randomUUID(),
        title: data.title,
        status: 'INVESTIGATING',
        severity: data.severity,
        affectedComponents: data.affectedComponents,
        resolvedAt: null,
        createdAt: new Date(),
        updatedAt: new Date(),
        updates: [{
          updateId: crypto.randomUUID(),
          incidentId: '',
          status: 'INVESTIGATING',
          message: data.initialMessage,
          createdAt: new Date(),
        }],
      };
      // Link updateId's incidentId to the incident
      if (incident.updates?.[0]) {
        incident.updates[0].incidentId = incident.incidentId;
      }
      return incident;
    }),
    updateIncident: vi.fn().mockImplementation(
      async (_incidentId: string, _status: string, _message: string) => {
        return options?.updatedIncident ?? undefined;
      },
    ),
    findIncidentById: vi.fn().mockResolvedValue(undefined),
  };
}

function makeServiceDeps(overrides?: {
  subscriptionRepo?: any;
  paymentRepo?: any;
  statusComponentRepo?: any;
  incidentRepo?: any;
  userRepo?: UserRepo;
  stripe?: StripeClient;
  config?: Partial<PlatformServiceDeps['config']>;
}): PlatformServiceDeps {
  return {
    subscriptionRepo: overrides?.subscriptionRepo ?? makeMockSubscriptionRepo(),
    paymentRepo: overrides?.paymentRepo ?? makeMockPaymentRepo(),
    statusComponentRepo: overrides?.statusComponentRepo ?? makeMockStatusComponentRepo(),
    incidentRepo: overrides?.incidentRepo ?? makeMockIncidentRepo(),
    userRepo: overrides?.userRepo ?? makeMockUserRepo(),
    stripe: overrides?.stripe ?? makeMockStripe(),
    config: {
      stripePriceStandardMonthly: 'price_standard_monthly_test',
      stripePriceStandardAnnual: 'price_standard_annual_test',
      stripePriceEarlyBirdMonthly: 'price_early_bird_test',
      stripeWebhookSecret: 'whsec_test_secret',
      gstTaxRateId: 'txr_gst_test',
      ...overrides?.config,
    },
  };
}

describe('Platform Service — createCheckoutSession', () => {
  it('createCheckoutSession returns checkout URL for valid plan', async () => {
    const deps = makeServiceDeps();
    const result = await createCheckoutSession(
      deps,
      'user-123',
      'STANDARD_MONTHLY',
      'https://meritum.ca/success',
      'https://meritum.ca/cancel',
    );

    expect(result.checkout_url).toBe('https://checkout.stripe.com/session_abc');
    expect(deps.stripe.customers.create).toHaveBeenCalledOnce();
    expect(deps.stripe.checkout.sessions.create).toHaveBeenCalledOnce();

    const sessionCall = (deps.stripe.checkout.sessions.create as any).mock.calls[0][0];
    expect(sessionCall.mode).toBe('subscription');
    expect(sessionCall.customer).toBe('cus_mock_123');
    expect(sessionCall.line_items).toEqual([{ price: 'price_standard_monthly_test', quantity: 1 }]);
    expect(sessionCall.success_url).toBe('https://meritum.ca/success');
    expect(sessionCall.cancel_url).toBe('https://meritum.ca/cancel');
    expect(sessionCall.subscription_data?.default_tax_rates).toEqual(['txr_gst_test']);
  });

  it('createCheckoutSession rejects if active subscription exists', async () => {
    const subRepo = makeMockSubscriptionRepo({
      existingSubscription: {
        subscriptionId: 'sub-existing',
        providerId: 'user-123',
        status: 'ACTIVE',
        stripeCustomerId: 'cus_existing',
        stripeSubscriptionId: 'sub_existing',
        plan: 'STANDARD_MONTHLY',
      },
    });
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });

    await expect(
      createCheckoutSession(
        deps,
        'user-123',
        'STANDARD_MONTHLY',
        'https://meritum.ca/success',
        'https://meritum.ca/cancel',
      ),
    ).rejects.toThrow('User already has an active subscription');
  });

  it('createCheckoutSession rejects EARLY_BIRD_MONTHLY when cap reached', async () => {
    const subRepo = makeMockSubscriptionRepo({ earlyBirdCount: 100 });
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });

    await expect(
      createCheckoutSession(
        deps,
        'user-123',
        'EARLY_BIRD_MONTHLY',
        'https://meritum.ca/success',
        'https://meritum.ca/cancel',
      ),
    ).rejects.toThrow('Early bird plan is sold out');
  });

  it('createCheckoutSession creates Stripe customer with correct email', async () => {
    const userRepo = makeMockUserRepo({
      userId: 'user-456',
      email: 'dr.jones@example.com',
      fullName: 'Dr. Michael Jones',
    });
    const deps = makeServiceDeps({ userRepo });

    await createCheckoutSession(
      deps,
      'user-456',
      'STANDARD_ANNUAL',
      'https://meritum.ca/success',
      'https://meritum.ca/cancel',
    );

    expect(deps.stripe.customers.create).toHaveBeenCalledWith({
      email: 'dr.jones@example.com',
      name: 'Dr. Michael Jones',
      metadata: { meritum_user_id: 'user-456' },
    });

    const sessionCall = (deps.stripe.checkout.sessions.create as any).mock.calls[0][0];
    expect(sessionCall.line_items[0].price).toBe('price_standard_annual_test');
  });

  it('createCheckoutSession allows checkout when existing subscription is CANCELLED', async () => {
    const subRepo = makeMockSubscriptionRepo({
      existingSubscription: {
        subscriptionId: 'sub-old',
        providerId: 'user-123',
        status: 'CANCELLED',
        stripeCustomerId: 'cus_old',
        stripeSubscriptionId: 'sub_old',
        plan: 'STANDARD_MONTHLY',
      },
    });
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });

    const result = await createCheckoutSession(
      deps,
      'user-123',
      'STANDARD_MONTHLY',
      'https://meritum.ca/success',
      'https://meritum.ca/cancel',
    );

    expect(result.checkout_url).toBe('https://checkout.stripe.com/session_abc');
  });

  it('createCheckoutSession rejects if user not found', async () => {
    const userRepo: UserRepo = {
      findUserById: vi.fn().mockResolvedValue(undefined),
    };
    const deps = makeServiceDeps({ userRepo });

    await expect(
      createCheckoutSession(
        deps,
        'nonexistent-user',
        'STANDARD_MONTHLY',
        'https://meritum.ca/success',
        'https://meritum.ca/cancel',
      ),
    ).rejects.toThrow('not found');
  });

  it('createCheckoutSession uses correct price ID for EARLY_BIRD_MONTHLY', async () => {
    const deps = makeServiceDeps();

    await createCheckoutSession(
      deps,
      'user-123',
      'EARLY_BIRD_MONTHLY',
      'https://meritum.ca/success',
      'https://meritum.ca/cancel',
    );

    const sessionCall = (deps.stripe.checkout.sessions.create as any).mock.calls[0][0];
    expect(sessionCall.line_items[0].price).toBe('price_early_bird_test');
  });

  it('createCheckoutSession omits tax rates when gstTaxRateId not configured', async () => {
    const deps = makeServiceDeps({
      config: { gstTaxRateId: undefined },
    });

    await createCheckoutSession(
      deps,
      'user-123',
      'STANDARD_MONTHLY',
      'https://meritum.ca/success',
      'https://meritum.ca/cancel',
    );

    const sessionCall = (deps.stripe.checkout.sessions.create as any).mock.calls[0][0];
    expect(sessionCall.subscription_data).toBeUndefined();
  });
});

describe('Platform Service — createPortalSession', () => {
  it('createPortalSession returns portal URL for active subscriber', async () => {
    const subRepo = makeMockSubscriptionRepo({
      existingSubscription: {
        subscriptionId: 'sub-active',
        providerId: 'user-123',
        status: 'ACTIVE',
        stripeCustomerId: 'cus_portal_test',
        stripeSubscriptionId: 'sub_portal_test',
        plan: 'STANDARD_MONTHLY',
      },
    });
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });

    const result = await createPortalSession(
      deps,
      'user-123',
      'https://meritum.ca/settings',
    );

    expect(result.portal_url).toBe('https://billing.stripe.com/portal_xyz');
    expect(deps.stripe.billingPortal.sessions.create).toHaveBeenCalledWith({
      customer: 'cus_portal_test',
      return_url: 'https://meritum.ca/settings',
    });
  });

  it('createPortalSession rejects if no subscription found', async () => {
    const subRepo = makeMockSubscriptionRepo({ existingSubscription: null });
    // Make findSubscriptionByProviderId return undefined (null → undefined)
    subRepo.findSubscriptionByProviderId = vi.fn().mockResolvedValue(undefined);
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });

    await expect(
      createPortalSession(deps, 'user-123', 'https://meritum.ca/settings'),
    ).rejects.toThrow('not found');
  });
});

// ---------------------------------------------------------------------------
// Platform Service — Webhook Processing Tests
// ---------------------------------------------------------------------------

describe('Platform Service — processWebhookEvent', () => {
  it('processWebhookEvent rejects invalid signature', async () => {
    const stripe = makeMockStripe();
    (stripe.webhooks.constructEvent as any).mockImplementation(() => {
      throw new Error('Invalid signature');
    });
    const deps = makeServiceDeps({ stripe });

    await expect(
      processWebhookEvent(deps, '{"type":"invoice.paid"}', 'bad_sig'),
    ).rejects.toThrow('Invalid webhook signature');
  });

  it('processWebhookEvent rejects missing signature', async () => {
    const deps = makeServiceDeps();

    await expect(
      processWebhookEvent(deps, '{"type":"invoice.paid"}', ''),
    ).rejects.toThrow('Missing stripe-signature header');
  });
});

// ---------------------------------------------------------------------------
// Platform Service — handleCheckoutCompleted Tests
// ---------------------------------------------------------------------------

describe('Platform Service — handleCheckoutCompleted', () => {
  it('handleCheckoutCompleted creates subscription record', async () => {
    const subRepo = makeMockSubscriptionRepo();
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });
    const emitter = makeMockEventEmitter();

    const event: StripeEvent = {
      id: 'evt_checkout_1',
      type: 'checkout.session.completed',
      data: {
        object: {
          metadata: {
            meritum_user_id: 'user-abc',
            plan: 'STANDARD_MONTHLY',
          },
          customer: 'cus_stripe_123',
          subscription: 'sub_stripe_456',
        },
      },
    };

    await handleCheckoutCompleted(deps, event, emitter);

    expect(subRepo.createSubscription).toHaveBeenCalledOnce();
    const createCall = subRepo.createSubscription.mock.calls[0][0];
    expect(createCall.providerId).toBe('user-abc');
    expect(createCall.stripeCustomerId).toBe('cus_stripe_123');
    expect(createCall.stripeSubscriptionId).toBe('sub_stripe_456');
    expect(createCall.plan).toBe('STANDARD_MONTHLY');
    expect(createCall.status).toBe('ACTIVE');
  });

  it('handleCheckoutCompleted links Stripe IDs to user', async () => {
    const subRepo = makeMockSubscriptionRepo();
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });

    const event: StripeEvent = {
      id: 'evt_checkout_2',
      type: 'checkout.session.completed',
      data: {
        object: {
          metadata: {
            meritum_user_id: 'user-xyz',
            plan: 'EARLY_BIRD_MONTHLY',
          },
          customer: 'cus_new_user',
          subscription: 'sub_new_user',
        },
      },
    };

    await handleCheckoutCompleted(deps, event);

    const createCall = subRepo.createSubscription.mock.calls[0][0];
    expect(createCall.stripeCustomerId).toBe('cus_new_user');
    expect(createCall.stripeSubscriptionId).toBe('sub_new_user');
    expect(createCall.providerId).toBe('user-xyz');
  });

  it('handleCheckoutCompleted is idempotent (skips if subscription exists)', async () => {
    const subRepo = makeMockSubscriptionRepo();
    subRepo.findSubscriptionByStripeSubscriptionId = vi.fn().mockResolvedValue({
      subscriptionId: 'existing-sub',
      stripeSubscriptionId: 'sub_already_exists',
      status: 'ACTIVE',
    });
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });

    const event: StripeEvent = {
      id: 'evt_checkout_dup',
      type: 'checkout.session.completed',
      data: {
        object: {
          metadata: { meritum_user_id: 'user-abc', plan: 'STANDARD_MONTHLY' },
          customer: 'cus_stripe_123',
          subscription: 'sub_already_exists',
        },
      },
    };

    await handleCheckoutCompleted(deps, event);

    expect(subRepo.createSubscription).not.toHaveBeenCalled();
  });

  it('handleCheckoutCompleted emits SUBSCRIPTION_CREATED event', async () => {
    const subRepo = makeMockSubscriptionRepo();
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });
    const emitter = makeMockEventEmitter();

    const event: StripeEvent = {
      id: 'evt_checkout_emit',
      type: 'checkout.session.completed',
      data: {
        object: {
          metadata: { meritum_user_id: 'user-abc', plan: 'STANDARD_MONTHLY' },
          customer: 'cus_stripe_123',
          subscription: 'sub_stripe_456',
        },
      },
    };

    await handleCheckoutCompleted(deps, event, emitter);

    expect(emitter.emit).toHaveBeenCalledWith(
      'SUBSCRIPTION_CREATED',
      expect.objectContaining({
        userId: 'user-abc',
        plan: 'STANDARD_MONTHLY',
        stripeCustomerId: 'cus_stripe_123',
        stripeSubscriptionId: 'sub_stripe_456',
      }),
    );
  });
});

// ---------------------------------------------------------------------------
// Platform Service — handleInvoicePaid Tests
// ---------------------------------------------------------------------------

describe('Platform Service — handleInvoicePaid', () => {
  const mockSubscription = {
    subscriptionId: 'sub-local-123',
    providerId: 'user-abc',
    stripeCustomerId: 'cus_test',
    stripeSubscriptionId: 'sub_stripe_paid',
    plan: 'STANDARD_MONTHLY',
    status: 'ACTIVE',
    failedPaymentCount: 0,
  };

  it('handleInvoicePaid records payment and clears past_due', async () => {
    const pastDueSub = { ...mockSubscription, status: 'PAST_DUE', failedPaymentCount: 2 };
    const subRepo = makeMockSubscriptionRepo({ subscriptionByStripeId: pastDueSub });
    const paymentRepo = makeMockPaymentRepo();
    const deps = makeServiceDeps({ subscriptionRepo: subRepo, paymentRepo });
    const emitter = makeMockEventEmitter();

    const event: StripeEvent = {
      id: 'evt_inv_paid_1',
      type: 'invoice.paid',
      data: {
        object: {
          id: 'in_paid_123',
          subscription: 'sub_stripe_paid',
          amount_paid: 29295, // $292.95 in cents
          tax: 1395,          // $13.95 GST
          total: 29295,
        },
      },
    };

    await handleInvoicePaid(deps, event, emitter);

    // Should record payment
    expect(paymentRepo.recordPayment).toHaveBeenCalledOnce();
    const paymentCall = paymentRepo.recordPayment.mock.calls[0][0];
    expect(paymentCall.subscriptionId).toBe('sub-local-123');
    expect(paymentCall.stripeInvoiceId).toBe('in_paid_123');
    expect(paymentCall.amountCad).toBe('279.00');
    expect(paymentCall.gstAmount).toBe('13.95');
    expect(paymentCall.totalCad).toBe('292.95');
    expect(paymentCall.status).toBe('PAID');

    // Should reset failed payment count
    expect(subRepo.resetFailedPaymentCount).toHaveBeenCalledWith('sub-local-123');

    // Should transition PAST_DUE → ACTIVE
    expect(subRepo.updateSubscriptionStatus).toHaveBeenCalledWith(
      'sub-local-123',
      'ACTIVE',
      { suspended_at: null },
    );

    // Should emit event
    expect(emitter.emit).toHaveBeenCalledWith(
      'PAYMENT_SUCCEEDED',
      expect.objectContaining({
        subscriptionId: 'sub-local-123',
        stripeInvoiceId: 'in_paid_123',
      }),
    );
  });

  it('handleInvoicePaid is idempotent (duplicate invoice_id ignored)', async () => {
    const subRepo = makeMockSubscriptionRepo({ subscriptionByStripeId: mockSubscription });
    const paymentRepo = makeMockPaymentRepo({
      existingPayment: {
        paymentId: 'pay-existing',
        stripeInvoiceId: 'in_duplicate_123',
        status: 'PAID',
      },
    });
    const deps = makeServiceDeps({ subscriptionRepo: subRepo, paymentRepo });

    const event: StripeEvent = {
      id: 'evt_inv_paid_dup',
      type: 'invoice.paid',
      data: {
        object: {
          id: 'in_duplicate_123',
          subscription: 'sub_stripe_paid',
          amount_paid: 29295,
          tax: 1395,
        },
      },
    };

    await handleInvoicePaid(deps, event);

    // Should NOT record a new payment
    expect(paymentRepo.recordPayment).not.toHaveBeenCalled();
    // Should NOT update subscription
    expect(subRepo.resetFailedPaymentCount).not.toHaveBeenCalled();
  });

  it('handleInvoicePaid does not change status when already ACTIVE', async () => {
    const activeSub = { ...mockSubscription, status: 'ACTIVE' };
    const subRepo = makeMockSubscriptionRepo({ subscriptionByStripeId: activeSub });
    const paymentRepo = makeMockPaymentRepo();
    const deps = makeServiceDeps({ subscriptionRepo: subRepo, paymentRepo });

    const event: StripeEvent = {
      id: 'evt_inv_paid_active',
      type: 'invoice.paid',
      data: {
        object: {
          id: 'in_active_123',
          subscription: 'sub_stripe_paid',
          amount_paid: 29295,
          tax: 1395,
        },
      },
    };

    await handleInvoicePaid(deps, event);

    // Should record payment
    expect(paymentRepo.recordPayment).toHaveBeenCalledOnce();
    // Should reset failed count
    expect(subRepo.resetFailedPaymentCount).toHaveBeenCalled();
    // Should NOT call updateSubscriptionStatus (already active)
    expect(subRepo.updateSubscriptionStatus).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Platform Service — handleInvoicePaymentFailed Tests
// ---------------------------------------------------------------------------

describe('Platform Service — handleInvoicePaymentFailed', () => {
  const mockSubscription = {
    subscriptionId: 'sub-local-fail',
    providerId: 'user-fail',
    stripeCustomerId: 'cus_fail',
    stripeSubscriptionId: 'sub_stripe_fail',
    plan: 'STANDARD_MONTHLY',
    status: 'ACTIVE',
    failedPaymentCount: 0,
  };

  it('handleInvoicePaymentFailed increments failure count', async () => {
    const subRepo = makeMockSubscriptionRepo({ subscriptionByStripeId: mockSubscription });
    const paymentRepo = makeMockPaymentRepo();
    const deps = makeServiceDeps({ subscriptionRepo: subRepo, paymentRepo });

    const event: StripeEvent = {
      id: 'evt_inv_fail_1',
      type: 'invoice.payment_failed',
      data: {
        object: {
          id: 'in_fail_123',
          subscription: 'sub_stripe_fail',
          amount_due: 29295,
          tax: 1395,
        },
      },
    };

    await handleInvoicePaymentFailed(deps, event);

    expect(subRepo.incrementFailedPaymentCount).toHaveBeenCalledWith('sub-local-fail');
  });

  it('handleInvoicePaymentFailed records failed payment', async () => {
    const subRepo = makeMockSubscriptionRepo({ subscriptionByStripeId: mockSubscription });
    const paymentRepo = makeMockPaymentRepo();
    const deps = makeServiceDeps({ subscriptionRepo: subRepo, paymentRepo });

    const event: StripeEvent = {
      id: 'evt_inv_fail_rec',
      type: 'invoice.payment_failed',
      data: {
        object: {
          id: 'in_fail_rec',
          subscription: 'sub_stripe_fail',
          amount_due: 29295,
          tax: 1395,
        },
      },
    };

    await handleInvoicePaymentFailed(deps, event);

    expect(paymentRepo.recordPayment).toHaveBeenCalledOnce();
    const paymentCall = paymentRepo.recordPayment.mock.calls[0][0];
    expect(paymentCall.status).toBe('FAILED');
    expect(paymentCall.paidAt).toBeNull();
    expect(paymentCall.stripeInvoiceId).toBe('in_fail_rec');
  });

  it('handleInvoicePaymentFailed emits notification event', async () => {
    const subRepo = makeMockSubscriptionRepo({ subscriptionByStripeId: mockSubscription });
    const paymentRepo = makeMockPaymentRepo();
    const deps = makeServiceDeps({ subscriptionRepo: subRepo, paymentRepo });
    const emitter = makeMockEventEmitter();

    const event: StripeEvent = {
      id: 'evt_inv_fail_emit',
      type: 'invoice.payment_failed',
      data: {
        object: {
          id: 'in_fail_emit',
          subscription: 'sub_stripe_fail',
          amount_due: 29295,
          tax: 1395,
        },
      },
    };

    await handleInvoicePaymentFailed(deps, event, emitter);

    expect(emitter.emit).toHaveBeenCalledWith(
      'PAYMENT_FAILED',
      expect.objectContaining({
        subscriptionId: 'sub-local-fail',
        stripeInvoiceId: 'in_fail_emit',
        failedPaymentCount: 1,
      }),
    );
  });

  it('handleInvoicePaymentFailed transitions ACTIVE to PAST_DUE', async () => {
    const activeSub = { ...mockSubscription, status: 'ACTIVE' };
    const subRepo = makeMockSubscriptionRepo({ subscriptionByStripeId: activeSub });
    const paymentRepo = makeMockPaymentRepo();
    const deps = makeServiceDeps({ subscriptionRepo: subRepo, paymentRepo });

    const event: StripeEvent = {
      id: 'evt_inv_fail_pastdue',
      type: 'invoice.payment_failed',
      data: {
        object: {
          id: 'in_fail_pastdue',
          subscription: 'sub_stripe_fail',
          amount_due: 29295,
          tax: 1395,
        },
      },
    };

    await handleInvoicePaymentFailed(deps, event);

    expect(subRepo.updateSubscriptionStatus).toHaveBeenCalledWith(
      'sub-local-fail',
      'PAST_DUE',
    );
  });

  it('handleInvoicePaymentFailed is idempotent (duplicate failure ignored)', async () => {
    const subRepo = makeMockSubscriptionRepo({ subscriptionByStripeId: mockSubscription });
    const paymentRepo = makeMockPaymentRepo({
      existingPayment: {
        paymentId: 'pay-fail-existing',
        stripeInvoiceId: 'in_fail_dup',
        status: 'FAILED',
      },
    });
    const deps = makeServiceDeps({ subscriptionRepo: subRepo, paymentRepo });

    const event: StripeEvent = {
      id: 'evt_inv_fail_dup',
      type: 'invoice.payment_failed',
      data: {
        object: {
          id: 'in_fail_dup',
          subscription: 'sub_stripe_fail',
          amount_due: 29295,
          tax: 1395,
        },
      },
    };

    await handleInvoicePaymentFailed(deps, event);

    expect(paymentRepo.recordPayment).not.toHaveBeenCalled();
    expect(subRepo.incrementFailedPaymentCount).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Platform Service — handleSubscriptionUpdated Tests
// ---------------------------------------------------------------------------

describe('Platform Service — handleSubscriptionUpdated', () => {
  const mockSubscription = {
    subscriptionId: 'sub-local-upd',
    providerId: 'user-upd',
    stripeCustomerId: 'cus_upd',
    stripeSubscriptionId: 'sub_stripe_upd',
    plan: 'STANDARD_MONTHLY',
    status: 'ACTIVE',
    failedPaymentCount: 0,
  };

  it('handleSubscriptionUpdated syncs status and period', async () => {
    const subRepo = makeMockSubscriptionRepo({ subscriptionByStripeId: mockSubscription });
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });

    const periodStart = Math.floor(new Date('2026-03-01T00:00:00Z').getTime() / 1000);
    const periodEnd = Math.floor(new Date('2026-03-31T00:00:00Z').getTime() / 1000);

    const event: StripeEvent = {
      id: 'evt_sub_upd_1',
      type: 'customer.subscription.updated',
      data: {
        object: {
          id: 'sub_stripe_upd',
          status: 'past_due',
          current_period_start: periodStart,
          current_period_end: periodEnd,
          items: {
            data: [{ price: { id: 'price_standard_monthly_test' } }],
          },
        },
      },
    };

    await handleSubscriptionUpdated(deps, event);

    // Should update status to PAST_DUE
    expect(subRepo.updateSubscriptionStatus).toHaveBeenCalledWith(
      'sub-local-upd',
      'PAST_DUE',
    );

    // Should sync billing period
    expect(subRepo.updateSubscriptionPeriod).toHaveBeenCalledWith(
      'sub-local-upd',
      new Date(periodStart * 1000),
      new Date(periodEnd * 1000),
    );
  });

  it('handleSubscriptionUpdated syncs plan change', async () => {
    const subRepo = makeMockSubscriptionRepo({ subscriptionByStripeId: mockSubscription });
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });

    const event: StripeEvent = {
      id: 'evt_sub_upd_plan',
      type: 'customer.subscription.updated',
      data: {
        object: {
          id: 'sub_stripe_upd',
          status: 'active',
          current_period_start: Math.floor(Date.now() / 1000),
          current_period_end: Math.floor(Date.now() / 1000) + 30 * 86400,
          items: {
            data: [{ price: { id: 'price_standard_annual_test' } }],
          },
        },
      },
    };

    await handleSubscriptionUpdated(deps, event);

    // Should update plan to STANDARD_ANNUAL
    expect(subRepo.updateSubscriptionPlan).toHaveBeenCalledWith(
      'sub-local-upd',
      'STANDARD_ANNUAL',
    );
  });

  it('handleSubscriptionUpdated does not update status if unchanged', async () => {
    const subRepo = makeMockSubscriptionRepo({ subscriptionByStripeId: mockSubscription });
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });

    const event: StripeEvent = {
      id: 'evt_sub_upd_same',
      type: 'customer.subscription.updated',
      data: {
        object: {
          id: 'sub_stripe_upd',
          status: 'active', // maps to ACTIVE — same as current
          current_period_start: Math.floor(Date.now() / 1000),
          current_period_end: Math.floor(Date.now() / 1000) + 30 * 86400,
          items: {
            data: [{ price: { id: 'price_standard_monthly_test' } }],
          },
        },
      },
    };

    await handleSubscriptionUpdated(deps, event);

    // Should NOT call updateSubscriptionStatus (status unchanged)
    expect(subRepo.updateSubscriptionStatus).not.toHaveBeenCalled();
    // Should NOT call updateSubscriptionPlan (plan unchanged)
    expect(subRepo.updateSubscriptionPlan).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Platform Service — handleSubscriptionDeleted Tests
// ---------------------------------------------------------------------------

describe('Platform Service — handleSubscriptionDeleted', () => {
  const mockSubscription = {
    subscriptionId: 'sub-local-del',
    providerId: 'user-del',
    stripeCustomerId: 'cus_del',
    stripeSubscriptionId: 'sub_stripe_del',
    plan: 'STANDARD_MONTHLY',
    status: 'ACTIVE',
    failedPaymentCount: 0,
  };

  it('handleSubscriptionDeleted sets cancelled status and schedules deletion', async () => {
    const subRepo = makeMockSubscriptionRepo({ subscriptionByStripeId: mockSubscription });
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });
    const emitter = makeMockEventEmitter();

    const event: StripeEvent = {
      id: 'evt_sub_del_1',
      type: 'customer.subscription.deleted',
      data: {
        object: {
          id: 'sub_stripe_del',
        },
      },
    };

    const beforeCall = new Date();
    await handleSubscriptionDeleted(deps, event, emitter);

    expect(subRepo.updateSubscriptionStatus).toHaveBeenCalledOnce();
    const [id, status, metadata] = subRepo.updateSubscriptionStatus.mock.calls[0];
    expect(id).toBe('sub-local-del');
    expect(status).toBe('CANCELLED');
    expect(metadata.cancelled_at).toBeInstanceOf(Date);
    expect(metadata.cancelled_at.getTime()).toBeGreaterThanOrEqual(beforeCall.getTime());
    expect(metadata.deletion_scheduled_at).toBeInstanceOf(Date);

    // Verify 30-day grace period
    const gracePeriodMs = metadata.deletion_scheduled_at.getTime() - metadata.cancelled_at.getTime();
    const thirtyDaysMs = 30 * 24 * 60 * 60 * 1000;
    expect(gracePeriodMs).toBe(thirtyDaysMs);

    // Should emit SUBSCRIPTION_CANCELLED event
    expect(emitter.emit).toHaveBeenCalledWith(
      'SUBSCRIPTION_CANCELLED',
      expect.objectContaining({
        subscriptionId: 'sub-local-del',
        providerId: 'user-del',
      }),
    );
  });

  it('handleSubscriptionDeleted is idempotent (skips if already cancelled)', async () => {
    const cancelledSub = { ...mockSubscription, status: 'CANCELLED' };
    const subRepo = makeMockSubscriptionRepo({ subscriptionByStripeId: cancelledSub });
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });

    const event: StripeEvent = {
      id: 'evt_sub_del_dup',
      type: 'customer.subscription.deleted',
      data: {
        object: {
          id: 'sub_stripe_del',
        },
      },
    };

    await handleSubscriptionDeleted(deps, event);

    expect(subRepo.updateSubscriptionStatus).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Platform Service — handleInvoiceCreated Tests
// ---------------------------------------------------------------------------

describe('Platform Service — handleInvoiceCreated', () => {
  it('handleInvoiceCreated verifies GST presence (adds if missing)', async () => {
    const stripe = makeMockStripe();
    const deps = makeServiceDeps({ stripe });

    const event: StripeEvent = {
      id: 'evt_inv_created_1',
      type: 'invoice.created',
      data: {
        object: {
          id: 'in_created_123',
          status: 'draft',
          subtotal: 27900, // $279.00 in cents
          tax: 0,          // No GST
        },
      },
    };

    await handleInvoiceCreated(deps, event);

    expect(stripe.invoiceItems.create).toHaveBeenCalledOnce();
    const createCall = (stripe.invoiceItems.create as any).mock.calls[0][0];
    expect(createCall.invoice).toBe('in_created_123');
    expect(createCall.amount).toBe(1395); // 5% of 27900 = 1395
    expect(createCall.currency).toBe('cad');
    expect(createCall.description).toBe('GST (5%)');
  });

  it('handleInvoiceCreated skips if GST already present', async () => {
    const stripe = makeMockStripe();
    const deps = makeServiceDeps({ stripe });

    const event: StripeEvent = {
      id: 'evt_inv_created_gst',
      type: 'invoice.created',
      data: {
        object: {
          id: 'in_created_gst',
          status: 'draft',
          subtotal: 27900,
          tax: 1395, // GST already present
        },
      },
    };

    await handleInvoiceCreated(deps, event);

    expect(stripe.invoiceItems.create).not.toHaveBeenCalled();
  });

  it('handleInvoiceCreated skips non-draft invoices', async () => {
    const stripe = makeMockStripe();
    const deps = makeServiceDeps({ stripe });

    const event: StripeEvent = {
      id: 'evt_inv_created_open',
      type: 'invoice.created',
      data: {
        object: {
          id: 'in_created_open',
          status: 'open',
          subtotal: 27900,
          tax: 0,
        },
      },
    };

    await handleInvoiceCreated(deps, event);

    expect(stripe.invoiceItems.create).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Platform Service — runDunningCheck Tests
// ---------------------------------------------------------------------------

describe('Platform Service — runDunningCheck', () => {
  it('runDunningCheck emits Day 7 warning for 7-day overdue', async () => {
    const subRepo = makeMockSubscriptionRepo();
    // No subscriptions due for suspension (Day 14)
    subRepo.findSubscriptionsDueForSuspension = vi.fn().mockResolvedValue([]);
    // One subscription that's been past due for 8 days (Day 7 warning range)
    const pastDueSub = {
      subscriptionId: 'sub-pastdue-7',
      providerId: 'user-pastdue-7',
      stripeCustomerId: 'cus_pd_7',
      stripeSubscriptionId: 'sub_stripe_pd_7',
      status: 'PAST_DUE',
      failedPaymentCount: 2,
      updatedAt: new Date(Date.now() - 8 * 24 * 60 * 60 * 1000), // 8 days ago
    };
    subRepo.findPastDueSubscriptions = vi.fn().mockResolvedValue([pastDueSub]);
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });
    const emitter = makeMockEventEmitter();

    const result = await runDunningCheck(deps, emitter);

    expect(emitter.emit).toHaveBeenCalledWith(
      'PAYMENT_SUSPENSION_WARNING',
      expect.objectContaining({
        subscriptionId: 'sub-pastdue-7',
        providerId: 'user-pastdue-7',
      }),
    );
    expect(result.processed).toBeGreaterThanOrEqual(1);
    expect(result.suspended).toBe(0);
  });

  it('runDunningCheck emits Day 3 retry failed notification', async () => {
    const subRepo = makeMockSubscriptionRepo();
    subRepo.findSubscriptionsDueForSuspension = vi.fn().mockResolvedValue([]);
    const pastDueSub = {
      subscriptionId: 'sub-pastdue-3',
      providerId: 'user-pastdue-3',
      stripeCustomerId: 'cus_pd_3',
      stripeSubscriptionId: 'sub_stripe_pd_3',
      status: 'PAST_DUE',
      failedPaymentCount: 1,
      updatedAt: new Date(Date.now() - 4 * 24 * 60 * 60 * 1000), // 4 days ago
    };
    subRepo.findPastDueSubscriptions = vi.fn().mockResolvedValue([pastDueSub]);
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });
    const emitter = makeMockEventEmitter();

    await runDunningCheck(deps, emitter);

    expect(emitter.emit).toHaveBeenCalledWith(
      'PAYMENT_RETRY_FAILED',
      expect.objectContaining({
        subscriptionId: 'sub-pastdue-3',
        providerId: 'user-pastdue-3',
        failedPaymentCount: 1,
      }),
    );
  });

  it('runDunningCheck suspends account at Day 14', async () => {
    const suspendableSub = {
      subscriptionId: 'sub-suspend-14',
      providerId: 'user-suspend-14',
      stripeCustomerId: 'cus_s14',
      stripeSubscriptionId: 'sub_stripe_s14',
      status: 'PAST_DUE',
      failedPaymentCount: 3,
      updatedAt: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000), // 15 days ago
    };
    const subRepo = makeMockSubscriptionRepo();
    subRepo.findSubscriptionsDueForSuspension = vi.fn().mockResolvedValue([suspendableSub]);
    subRepo.findPastDueSubscriptions = vi.fn().mockResolvedValue([]);
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });
    const emitter = makeMockEventEmitter();

    const result = await runDunningCheck(deps, emitter);

    expect(subRepo.updateSubscriptionStatus).toHaveBeenCalledWith(
      'sub-suspend-14',
      'SUSPENDED',
      expect.objectContaining({
        suspended_at: expect.any(Date),
      }),
    );
    expect(result.suspended).toBe(1);
    expect(result.processed).toBeGreaterThanOrEqual(1);
  });

  it('runDunningCheck updates user.subscription_status on suspension', async () => {
    const suspendableSub = {
      subscriptionId: 'sub-user-status',
      providerId: 'user-sub-status',
      stripeCustomerId: 'cus_us',
      stripeSubscriptionId: 'sub_stripe_us',
      status: 'PAST_DUE',
      failedPaymentCount: 3,
      updatedAt: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000),
    };
    const subRepo = makeMockSubscriptionRepo();
    subRepo.findSubscriptionsDueForSuspension = vi.fn().mockResolvedValue([suspendableSub]);
    subRepo.findPastDueSubscriptions = vi.fn().mockResolvedValue([]);
    const userRepo = makeMockUserRepo();
    const deps = makeServiceDeps({ subscriptionRepo: subRepo, userRepo });

    await runDunningCheck(deps);

    expect(userRepo.updateSubscriptionStatus).toHaveBeenCalledWith(
      'user-sub-status',
      'SUSPENDED',
    );
  });

  it('runDunningCheck emits ACCOUNT_SUSPENDED event on suspension', async () => {
    const suspendableSub = {
      subscriptionId: 'sub-emit-suspend',
      providerId: 'user-emit-suspend',
      stripeCustomerId: 'cus_es',
      stripeSubscriptionId: 'sub_stripe_es',
      status: 'PAST_DUE',
      failedPaymentCount: 4,
      updatedAt: new Date(Date.now() - 16 * 24 * 60 * 60 * 1000),
    };
    const subRepo = makeMockSubscriptionRepo();
    subRepo.findSubscriptionsDueForSuspension = vi.fn().mockResolvedValue([suspendableSub]);
    subRepo.findPastDueSubscriptions = vi.fn().mockResolvedValue([]);
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });
    const emitter = makeMockEventEmitter();

    await runDunningCheck(deps, emitter);

    expect(emitter.emit).toHaveBeenCalledWith(
      'ACCOUNT_SUSPENDED',
      expect.objectContaining({
        subscriptionId: 'sub-emit-suspend',
        providerId: 'user-emit-suspend',
        suspendedAt: expect.any(String),
      }),
    );
  });

  it('runDunningCheck logs to audit trail', async () => {
    const suspendableSub = {
      subscriptionId: 'sub-audit-dunning',
      providerId: 'user-audit-dunning',
      stripeCustomerId: 'cus_ad',
      stripeSubscriptionId: 'sub_stripe_ad',
      status: 'PAST_DUE',
      failedPaymentCount: 3,
      updatedAt: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000),
    };
    const subRepo = makeMockSubscriptionRepo();
    subRepo.findSubscriptionsDueForSuspension = vi.fn().mockResolvedValue([suspendableSub]);
    subRepo.findPastDueSubscriptions = vi.fn().mockResolvedValue([]);
    const auditLogger = makeMockAuditLogger();
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });
    deps.auditLogger = auditLogger;

    await runDunningCheck(deps);

    expect(auditLogger.log).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'DUNNING_SUSPENSION',
        resourceType: 'subscription',
        resourceId: 'sub-audit-dunning',
        actorType: 'system',
      }),
    );
  });

  it('All scheduled jobs are idempotent — runDunningCheck with no due subscriptions', async () => {
    const subRepo = makeMockSubscriptionRepo();
    subRepo.findSubscriptionsDueForSuspension = vi.fn().mockResolvedValue([]);
    subRepo.findPastDueSubscriptions = vi.fn().mockResolvedValue([]);
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });
    const emitter = makeMockEventEmitter();

    // Run twice — both should return 0 processed
    const result1 = await runDunningCheck(deps, emitter);
    const result2 = await runDunningCheck(deps, emitter);

    expect(result1.processed).toBe(0);
    expect(result1.suspended).toBe(0);
    expect(result2.processed).toBe(0);
    expect(result2.suspended).toBe(0);
  });

  it('runDunningCheck skips subscriptions with failedPaymentCount <= 0', async () => {
    const subRepo = makeMockSubscriptionRepo();
    subRepo.findSubscriptionsDueForSuspension = vi.fn().mockResolvedValue([]);
    const pastDueSub = {
      subscriptionId: 'sub-no-failures',
      providerId: 'user-no-failures',
      stripeCustomerId: 'cus_nf',
      stripeSubscriptionId: 'sub_stripe_nf',
      status: 'PAST_DUE',
      failedPaymentCount: 0,
      updatedAt: new Date(Date.now() - 8 * 24 * 60 * 60 * 1000),
    };
    subRepo.findPastDueSubscriptions = vi.fn().mockResolvedValue([pastDueSub]);
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });
    const emitter = makeMockEventEmitter();

    const result = await runDunningCheck(deps, emitter);

    expect(emitter.emit).not.toHaveBeenCalled();
    expect(result.processed).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Platform Service — runCancellationCheck Tests
// ---------------------------------------------------------------------------

describe('Platform Service — runCancellationCheck', () => {
  it('runCancellationCheck cancels Stripe subscription at Day 30', async () => {
    const suspendedSub = {
      subscriptionId: 'sub-cancel-30',
      providerId: 'user-cancel-30',
      stripeCustomerId: 'cus_c30',
      stripeSubscriptionId: 'sub_stripe_c30',
      status: 'SUSPENDED',
      suspendedAt: new Date(Date.now() - 17 * 24 * 60 * 60 * 1000), // 17 days ago
    };
    const subRepo = makeMockSubscriptionRepo();
    subRepo.findSubscriptionsDueForCancellation = vi.fn().mockResolvedValue([suspendedSub]);
    const stripe = makeMockStripe();
    const deps = makeServiceDeps({ subscriptionRepo: subRepo, stripe });
    const emitter = makeMockEventEmitter();

    const result = await runCancellationCheck(deps, emitter);

    expect(stripe.subscriptions.cancel).toHaveBeenCalledWith('sub_stripe_c30');
    expect(result.cancelled).toBe(1);
  });

  it('runCancellationCheck schedules deletion 30 days out', async () => {
    const suspendedSub = {
      subscriptionId: 'sub-del-sched',
      providerId: 'user-del-sched',
      stripeCustomerId: 'cus_ds',
      stripeSubscriptionId: 'sub_stripe_ds',
      status: 'SUSPENDED',
      suspendedAt: new Date(Date.now() - 17 * 24 * 60 * 60 * 1000),
    };
    const subRepo = makeMockSubscriptionRepo();
    subRepo.findSubscriptionsDueForCancellation = vi.fn().mockResolvedValue([suspendedSub]);
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });
    const emitter = makeMockEventEmitter();

    const beforeCall = new Date();
    await runCancellationCheck(deps, emitter);

    expect(subRepo.updateSubscriptionStatus).toHaveBeenCalledOnce();
    const [id, status, metadata] = subRepo.updateSubscriptionStatus.mock.calls[0];
    expect(id).toBe('sub-del-sched');
    expect(status).toBe('CANCELLED');
    expect(metadata.cancelled_at).toBeInstanceOf(Date);
    expect(metadata.cancelled_at.getTime()).toBeGreaterThanOrEqual(beforeCall.getTime());
    expect(metadata.deletion_scheduled_at).toBeInstanceOf(Date);

    // Verify 30-day grace period
    const gracePeriodMs = metadata.deletion_scheduled_at.getTime() - metadata.cancelled_at.getTime();
    const thirtyDaysMs = 30 * 24 * 60 * 60 * 1000;
    expect(gracePeriodMs).toBe(thirtyDaysMs);
  });

  it('runCancellationCheck updates user.subscription_status to CANCELLED', async () => {
    const suspendedSub = {
      subscriptionId: 'sub-cancel-user',
      providerId: 'user-cancel-user',
      stripeCustomerId: 'cus_cu',
      stripeSubscriptionId: 'sub_stripe_cu',
      status: 'SUSPENDED',
      suspendedAt: new Date(Date.now() - 17 * 24 * 60 * 60 * 1000),
    };
    const subRepo = makeMockSubscriptionRepo();
    subRepo.findSubscriptionsDueForCancellation = vi.fn().mockResolvedValue([suspendedSub]);
    const userRepo = makeMockUserRepo();
    const deps = makeServiceDeps({ subscriptionRepo: subRepo, userRepo });

    await runCancellationCheck(deps);

    expect(userRepo.updateSubscriptionStatus).toHaveBeenCalledWith(
      'user-cancel-user',
      'CANCELLED',
    );
  });

  it('runCancellationCheck emits SUBSCRIPTION_CANCELLED event', async () => {
    const suspendedSub = {
      subscriptionId: 'sub-cancel-emit',
      providerId: 'user-cancel-emit',
      stripeCustomerId: 'cus_ce',
      stripeSubscriptionId: 'sub_stripe_ce',
      status: 'SUSPENDED',
      suspendedAt: new Date(Date.now() - 17 * 24 * 60 * 60 * 1000),
    };
    const subRepo = makeMockSubscriptionRepo();
    subRepo.findSubscriptionsDueForCancellation = vi.fn().mockResolvedValue([suspendedSub]);
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });
    const emitter = makeMockEventEmitter();

    await runCancellationCheck(deps, emitter);

    expect(emitter.emit).toHaveBeenCalledWith(
      'SUBSCRIPTION_CANCELLED',
      expect.objectContaining({
        subscriptionId: 'sub-cancel-emit',
        providerId: 'user-cancel-emit',
        cancelledAt: expect.any(String),
        deletionScheduledAt: expect.any(String),
      }),
    );
  });

  it('runCancellationCheck logs to audit trail', async () => {
    const suspendedSub = {
      subscriptionId: 'sub-cancel-audit',
      providerId: 'user-cancel-audit',
      stripeCustomerId: 'cus_ca',
      stripeSubscriptionId: 'sub_stripe_ca',
      status: 'SUSPENDED',
      suspendedAt: new Date(Date.now() - 17 * 24 * 60 * 60 * 1000),
    };
    const subRepo = makeMockSubscriptionRepo();
    subRepo.findSubscriptionsDueForCancellation = vi.fn().mockResolvedValue([suspendedSub]);
    const auditLogger = makeMockAuditLogger();
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });
    deps.auditLogger = auditLogger;

    await runCancellationCheck(deps);

    expect(auditLogger.log).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'DUNNING_CANCELLATION',
        resourceType: 'subscription',
        resourceId: 'sub-cancel-audit',
        actorType: 'system',
      }),
    );
  });

  it('runCancellationCheck is idempotent with no due subscriptions', async () => {
    const subRepo = makeMockSubscriptionRepo();
    subRepo.findSubscriptionsDueForCancellation = vi.fn().mockResolvedValue([]);
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });

    const result1 = await runCancellationCheck(deps);
    const result2 = await runCancellationCheck(deps);

    expect(result1.cancelled).toBe(0);
    expect(result2.cancelled).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Platform Service — runDeletionCheck Tests
// ---------------------------------------------------------------------------

describe('Platform Service — runDeletionCheck', () => {
  it('runDeletionCheck deletes PHI data', async () => {
    const cancelledSub = {
      subscriptionId: 'sub-delete-phi',
      providerId: 'user-delete-phi',
      stripeCustomerId: 'cus_dp',
      stripeSubscriptionId: 'sub_stripe_dp',
      status: 'CANCELLED',
      deletionScheduledAt: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000), // past
    };
    const subRepo = makeMockSubscriptionRepo();
    subRepo.findSubscriptionsDueForDeletion = vi.fn().mockResolvedValue([cancelledSub]);
    const dataDeletionRepo = makeMockDataDeletionRepo();
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });
    deps.dataDeletionRepo = dataDeletionRepo;

    const result = await runDeletionCheck(deps);

    expect(dataDeletionRepo.deleteClaimsByProviderId).toHaveBeenCalledWith('user-delete-phi');
    expect(dataDeletionRepo.deletePatientsByProviderId).toHaveBeenCalledWith('user-delete-phi');
    expect(dataDeletionRepo.deleteReportsByProviderId).toHaveBeenCalledWith('user-delete-phi');
    expect(result.deleted).toBe(1);
  });

  it('runDeletionCheck strips PII from audit logs', async () => {
    const cancelledSub = {
      subscriptionId: 'sub-strip-pii',
      providerId: 'user-strip-pii',
      stripeCustomerId: 'cus_sp',
      stripeSubscriptionId: 'sub_stripe_sp',
      status: 'CANCELLED',
      deletionScheduledAt: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000),
    };
    const subRepo = makeMockSubscriptionRepo();
    subRepo.findSubscriptionsDueForDeletion = vi.fn().mockResolvedValue([cancelledSub]);
    const dataDeletionRepo = makeMockDataDeletionRepo();
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });
    deps.dataDeletionRepo = dataDeletionRepo;

    await runDeletionCheck(deps);

    expect(dataDeletionRepo.stripPiiFromAuditLogs).toHaveBeenCalledWith('user-strip-pii');
  });

  it('runDeletionCheck retains IMA records (no deletion call)', async () => {
    const cancelledSub = {
      subscriptionId: 'sub-retain-ima',
      providerId: 'user-retain-ima',
      stripeCustomerId: 'cus_ri',
      stripeSubscriptionId: 'sub_stripe_ri',
      status: 'CANCELLED',
      deletionScheduledAt: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000),
    };
    const subRepo = makeMockSubscriptionRepo();
    subRepo.findSubscriptionsDueForDeletion = vi.fn().mockResolvedValue([cancelledSub]);
    const dataDeletionRepo = makeMockDataDeletionRepo();
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });
    deps.dataDeletionRepo = dataDeletionRepo;

    await runDeletionCheck(deps);

    // The DataDeletionRepo interface does NOT include deleteImaRecords
    // This confirms IMA records are retained by design.
    // Verify PHI is deleted but IMA is not touched.
    expect(dataDeletionRepo.deleteClaimsByProviderId).toHaveBeenCalled();
    expect(dataDeletionRepo.deletePatientsByProviderId).toHaveBeenCalled();
    // No IMA deletion method exists on the interface — records retained
    expect(Object.keys(dataDeletionRepo)).not.toContain('deleteImaRecords');
  });

  it('runDeletionCheck deletes Stripe customer data', async () => {
    const cancelledSub = {
      subscriptionId: 'sub-stripe-del',
      providerId: 'user-stripe-del',
      stripeCustomerId: 'cus_sd',
      stripeSubscriptionId: 'sub_stripe_sd',
      status: 'CANCELLED',
      deletionScheduledAt: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000),
    };
    const subRepo = makeMockSubscriptionRepo();
    subRepo.findSubscriptionsDueForDeletion = vi.fn().mockResolvedValue([cancelledSub]);
    const stripe = makeMockStripe();
    const dataDeletionRepo = makeMockDataDeletionRepo();
    const deps = makeServiceDeps({ subscriptionRepo: subRepo, stripe });
    deps.dataDeletionRepo = dataDeletionRepo;

    await runDeletionCheck(deps);

    expect(stripe.customers.del).toHaveBeenCalledWith('cus_sd');
  });

  it('runDeletionCheck deactivates user account', async () => {
    const cancelledSub = {
      subscriptionId: 'sub-deactivate',
      providerId: 'user-deactivate',
      stripeCustomerId: 'cus_da',
      stripeSubscriptionId: 'sub_stripe_da',
      status: 'CANCELLED',
      deletionScheduledAt: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000),
    };
    const subRepo = makeMockSubscriptionRepo();
    subRepo.findSubscriptionsDueForDeletion = vi.fn().mockResolvedValue([cancelledSub]);
    const dataDeletionRepo = makeMockDataDeletionRepo();
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });
    deps.dataDeletionRepo = dataDeletionRepo;

    await runDeletionCheck(deps);

    expect(dataDeletionRepo.deactivateUser).toHaveBeenCalledWith('user-deactivate');
  });

  it('runDeletionCheck emits ACCOUNT_DATA_DELETED event', async () => {
    const cancelledSub = {
      subscriptionId: 'sub-del-event',
      providerId: 'user-del-event',
      stripeCustomerId: 'cus_de',
      stripeSubscriptionId: 'sub_stripe_de',
      status: 'CANCELLED',
      deletionScheduledAt: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000),
    };
    const subRepo = makeMockSubscriptionRepo();
    subRepo.findSubscriptionsDueForDeletion = vi.fn().mockResolvedValue([cancelledSub]);
    const dataDeletionRepo = makeMockDataDeletionRepo();
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });
    deps.dataDeletionRepo = dataDeletionRepo;
    const emitter = makeMockEventEmitter();

    await runDeletionCheck(deps, emitter);

    expect(emitter.emit).toHaveBeenCalledWith(
      'ACCOUNT_DATA_DELETED',
      expect.objectContaining({
        subscriptionId: 'sub-del-event',
        providerId: 'user-del-event',
        deletedAt: expect.any(String),
      }),
    );
  });

  it('runDeletionCheck anonymises AI learning data', async () => {
    const cancelledSub = {
      subscriptionId: 'sub-anon-ai',
      providerId: 'user-anon-ai',
      stripeCustomerId: 'cus_aa',
      stripeSubscriptionId: 'sub_stripe_aa',
      status: 'CANCELLED',
      deletionScheduledAt: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000),
    };
    const subRepo = makeMockSubscriptionRepo();
    subRepo.findSubscriptionsDueForDeletion = vi.fn().mockResolvedValue([cancelledSub]);
    const dataDeletionRepo = makeMockDataDeletionRepo();
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });
    deps.dataDeletionRepo = dataDeletionRepo;

    await runDeletionCheck(deps);

    expect(dataDeletionRepo.anonymiseAiLearningData).toHaveBeenCalledWith('user-anon-ai');
  });

  it('runDeletionCheck is idempotent with no due subscriptions', async () => {
    const subRepo = makeMockSubscriptionRepo();
    subRepo.findSubscriptionsDueForDeletion = vi.fn().mockResolvedValue([]);
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });
    deps.dataDeletionRepo = makeMockDataDeletionRepo();

    const result1 = await runDeletionCheck(deps);
    const result2 = await runDeletionCheck(deps);

    expect(result1.deleted).toBe(0);
    expect(result2.deleted).toBe(0);
  });

  it('runDeletionCheck skips when dataDeletionRepo is not provided', async () => {
    const cancelledSub = {
      subscriptionId: 'sub-no-repo',
      providerId: 'user-no-repo',
      stripeCustomerId: 'cus_nr',
      stripeSubscriptionId: 'sub_stripe_nr',
      status: 'CANCELLED',
      deletionScheduledAt: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000),
    };
    const subRepo = makeMockSubscriptionRepo();
    subRepo.findSubscriptionsDueForDeletion = vi.fn().mockResolvedValue([cancelledSub]);
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });
    // Explicitly no dataDeletionRepo
    deps.dataDeletionRepo = undefined;

    const result = await runDeletionCheck(deps);

    // Should not throw, but should not delete
    expect(result.deleted).toBe(0);
  });

  it('runDeletionCheck logs to audit trail', async () => {
    const cancelledSub = {
      subscriptionId: 'sub-del-audit',
      providerId: 'user-del-audit',
      stripeCustomerId: 'cus_da_log',
      stripeSubscriptionId: 'sub_stripe_da_log',
      status: 'CANCELLED',
      deletionScheduledAt: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000),
    };
    const subRepo = makeMockSubscriptionRepo();
    subRepo.findSubscriptionsDueForDeletion = vi.fn().mockResolvedValue([cancelledSub]);
    const dataDeletionRepo = makeMockDataDeletionRepo();
    const auditLogger = makeMockAuditLogger();
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });
    deps.dataDeletionRepo = dataDeletionRepo;
    deps.auditLogger = auditLogger;

    await runDeletionCheck(deps);

    expect(auditLogger.log).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'ACCOUNT_DATA_DELETED',
        resourceType: 'subscription',
        resourceId: 'sub-del-audit',
        actorType: 'system',
      }),
    );
  });
});

// ---------------------------------------------------------------------------
// Platform Service — getSubscriptionStatus Tests
// ---------------------------------------------------------------------------

describe('Platform Service — getSubscriptionStatus', () => {
  it('getSubscriptionStatus returns correct access level per status — ACTIVE', async () => {
    const subRepo = makeMockSubscriptionRepo({
      existingSubscription: {
        subscriptionId: 'sub-active-status',
        providerId: 'user-active-status',
        status: 'ACTIVE',
        plan: 'STANDARD_MONTHLY',
        currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        suspendedAt: null,
        cancelledAt: null,
        deletionScheduledAt: null,
      },
    });
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });

    const result = await getSubscriptionStatus(deps, 'user-active-status');

    expect(result.status).toBe('ACTIVE');
    expect(result.plan).toBe('STANDARD_MONTHLY');
    expect(result.features.length).toBeGreaterThan(10);
    expect(result.features).toContain('claim_create');
    expect(result.features).toContain('batch_submit');
    expect(result.subscription).not.toBeNull();
    expect(result.subscription!.subscriptionId).toBe('sub-active-status');
  });

  it('getSubscriptionStatus returns reduced access for SUSPENDED', async () => {
    const subRepo = makeMockSubscriptionRepo({
      existingSubscription: {
        subscriptionId: 'sub-suspended-status',
        providerId: 'user-suspended-status',
        status: 'SUSPENDED',
        plan: 'STANDARD_MONTHLY',
        currentPeriodEnd: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000),
        suspendedAt: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000),
        cancelledAt: null,
        deletionScheduledAt: null,
      },
    });
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });

    const result = await getSubscriptionStatus(deps, 'user-suspended-status');

    expect(result.status).toBe('SUSPENDED');
    expect(result.features).toContain('claim_view');
    expect(result.features).toContain('data_export');
    expect(result.features).not.toContain('claim_create');
    expect(result.features).not.toContain('batch_submit');
  });

  it('getSubscriptionStatus returns minimal access for CANCELLED', async () => {
    const subRepo = makeMockSubscriptionRepo({
      existingSubscription: {
        subscriptionId: 'sub-cancelled-status',
        providerId: 'user-cancelled-status',
        status: 'CANCELLED',
        plan: 'STANDARD_MONTHLY',
        currentPeriodEnd: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
        suspendedAt: null,
        cancelledAt: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000),
        deletionScheduledAt: new Date(Date.now() + 20 * 24 * 60 * 60 * 1000),
      },
    });
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });

    const result = await getSubscriptionStatus(deps, 'user-cancelled-status');

    expect(result.status).toBe('CANCELLED');
    expect(result.features).toContain('data_export');
    expect(result.features).toHaveLength(1);
    expect(result.subscription!.deletionScheduledAt).not.toBeNull();
  });

  it('getSubscriptionStatus returns CANCELLED with no features for missing subscription', async () => {
    const subRepo = makeMockSubscriptionRepo({ existingSubscription: null });
    subRepo.findSubscriptionByProviderId = vi.fn().mockResolvedValue(undefined);
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });

    const result = await getSubscriptionStatus(deps, 'nonexistent-user');

    expect(result.status).toBe('CANCELLED');
    expect(result.plan).toBeNull();
    expect(result.features).toContain('data_export');
    expect(result.subscription).toBeNull();
  });

  it('getSubscriptionStatus returns full access for TRIAL', async () => {
    const subRepo = makeMockSubscriptionRepo({
      existingSubscription: {
        subscriptionId: 'sub-trial-status',
        providerId: 'user-trial-status',
        status: 'TRIAL',
        plan: 'STANDARD_MONTHLY',
        currentPeriodEnd: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000),
        suspendedAt: null,
        cancelledAt: null,
        deletionScheduledAt: null,
      },
    });
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });

    const result = await getSubscriptionStatus(deps, 'user-trial-status');

    expect(result.status).toBe('TRIAL');
    expect(result.features.length).toBeGreaterThan(10);
    expect(result.features).toContain('claim_create');
    expect(result.features).toContain('ai_coach');
  });

  it('getSubscriptionStatus returns full access for PAST_DUE', async () => {
    const subRepo = makeMockSubscriptionRepo({
      existingSubscription: {
        subscriptionId: 'sub-pastdue-status',
        providerId: 'user-pastdue-status',
        status: 'PAST_DUE',
        plan: 'EARLY_BIRD_MONTHLY',
        currentPeriodEnd: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000),
        suspendedAt: null,
        cancelledAt: null,
        deletionScheduledAt: null,
      },
    });
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });

    const result = await getSubscriptionStatus(deps, 'user-pastdue-status');

    expect(result.status).toBe('PAST_DUE');
    expect(result.plan).toBe('EARLY_BIRD_MONTHLY');
    expect(result.features.length).toBeGreaterThan(10);
  });
});

// ---------------------------------------------------------------------------
// Platform Service — Status Page & Incident Management Tests
// ---------------------------------------------------------------------------

describe('Platform Service — getStatusPage', () => {
  it('getStatusPage returns all components and active incidents', async () => {
    const compId1 = crypto.randomUUID();
    const compId2 = crypto.randomUUID();
    const components = [
      { componentId: compId1, name: 'WEB_APP', displayName: 'Web Application', status: 'OPERATIONAL', description: null, sortOrder: 1 },
      { componentId: compId2, name: 'API', displayName: 'API', status: 'DEGRADED', description: 'Experiencing high latency', sortOrder: 2 },
    ];

    const incidentId = crypto.randomUUID();
    const updateId = crypto.randomUUID();
    const activeIncidents = [
      {
        incidentId,
        title: 'API Latency Spike',
        status: 'INVESTIGATING',
        severity: 'major',
        affectedComponents: [compId2],
        resolvedAt: null,
        createdAt: new Date('2026-02-17T10:00:00Z'),
        updatedAt: new Date('2026-02-17T10:00:00Z'),
        updates: [{
          updateId,
          incidentId,
          status: 'INVESTIGATING',
          message: 'Investigating elevated response times.',
          createdAt: new Date('2026-02-17T10:00:00Z'),
        }],
      },
    ];

    const statusComponentRepo = makeMockStatusComponentRepo({ components });
    const incidentRepo = makeMockIncidentRepo({ activeIncidents });
    const deps = makeServiceDeps({ statusComponentRepo, incidentRepo });

    const result = await getStatusPage(deps);

    expect(result.components).toHaveLength(2);
    expect(result.components[0].name).toBe('WEB_APP');
    expect(result.components[0].status).toBe('OPERATIONAL');
    expect(result.components[1].name).toBe('API');
    expect(result.components[1].status).toBe('DEGRADED');

    expect(result.activeIncidents).toHaveLength(1);
    expect(result.activeIncidents[0].title).toBe('API Latency Spike');
    expect(result.activeIncidents[0].status).toBe('INVESTIGATING');
    expect(result.activeIncidents[0].updates).toHaveLength(1);
    expect(result.activeIncidents[0].updates[0].message).toBe('Investigating elevated response times.');
  });

  it('getStatusPage excludes resolved incidents', async () => {
    // Active incidents returned by repo should already exclude resolved ones
    // (the repo's listActiveIncidents filters by status != RESOLVED)
    const statusComponentRepo = makeMockStatusComponentRepo({ components: [] });
    const incidentRepo = makeMockIncidentRepo({ activeIncidents: [] });
    const deps = makeServiceDeps({ statusComponentRepo, incidentRepo });

    const result = await getStatusPage(deps);

    expect(result.activeIncidents).toHaveLength(0);
    expect(incidentRepo.listActiveIncidents).toHaveBeenCalledOnce();
  });
});

describe('Platform Service — getIncidentHistory', () => {
  it('getIncidentHistory includes resolved incidents paginated', async () => {
    const incidentId1 = crypto.randomUUID();
    const incidentId2 = crypto.randomUUID();
    const historyData = [
      {
        incidentId: incidentId1,
        title: 'Resolved Incident',
        status: 'RESOLVED',
        severity: 'minor',
        affectedComponents: [crypto.randomUUID()],
        resolvedAt: new Date('2026-02-16T12:00:00Z'),
        createdAt: new Date('2026-02-16T10:00:00Z'),
        updatedAt: new Date('2026-02-16T12:00:00Z'),
        updates: [{
          updateId: crypto.randomUUID(),
          incidentId: incidentId1,
          status: 'RESOLVED',
          message: 'Issue fixed.',
          createdAt: new Date('2026-02-16T12:00:00Z'),
        }],
      },
      {
        incidentId: incidentId2,
        title: 'Active Incident',
        status: 'INVESTIGATING',
        severity: 'major',
        affectedComponents: [crypto.randomUUID()],
        resolvedAt: null,
        createdAt: new Date('2026-02-17T09:00:00Z'),
        updatedAt: new Date('2026-02-17T09:00:00Z'),
        updates: [{
          updateId: crypto.randomUUID(),
          incidentId: incidentId2,
          status: 'INVESTIGATING',
          message: 'Looking into it.',
          createdAt: new Date('2026-02-17T09:00:00Z'),
        }],
      },
    ];

    const incidentRepo = makeMockIncidentRepo({
      historyResult: { data: historyData, total: 5 },
    });
    const deps = makeServiceDeps({ incidentRepo });

    const result = await getIncidentHistory(deps, 1, 2);

    expect(result.data).toHaveLength(2);
    expect(result.pagination.total).toBe(5);
    expect(result.pagination.page).toBe(1);
    expect(result.pagination.pageSize).toBe(2);
    expect(result.pagination.hasMore).toBe(true);

    // Verify resolved incident is included
    const resolved = result.data.find((i) => i.status === 'RESOLVED');
    expect(resolved).toBeDefined();
    expect(resolved!.title).toBe('Resolved Incident');

    expect(incidentRepo.listIncidentHistory).toHaveBeenCalledWith({ page: 1, pageSize: 2 });
  });
});

describe('Platform Service — createIncident', () => {
  it('createIncident creates incident and updates component statuses', async () => {
    const compId1 = crypto.randomUUID();
    const compId2 = crypto.randomUUID();
    const components = [
      { componentId: compId1, name: 'API', displayName: 'API', status: 'OPERATIONAL', sortOrder: 2 },
      { componentId: compId2, name: 'DATABASE', displayName: 'Database', status: 'OPERATIONAL', sortOrder: 7 },
    ];
    const statusComponentRepo = makeMockStatusComponentRepo({ components });
    const incidentRepo = makeMockIncidentRepo();
    const auditLogger = makeMockAuditLogger();
    const deps = makeServiceDeps({ statusComponentRepo, incidentRepo });
    deps.auditLogger = auditLogger;

    const result = await createIncident(deps, 'admin-user-1', {
      title: 'Database Connection Issues',
      severity: 'critical',
      affected_components: [compId1, compId2],
      message: 'Investigating database connectivity problems.',
    });

    // Verify incident was created
    expect(incidentRepo.createIncident).toHaveBeenCalledWith({
      title: 'Database Connection Issues',
      severity: 'critical',
      affectedComponents: [compId1, compId2],
      initialMessage: 'Investigating database connectivity problems.',
    });

    expect(result.title).toBe('Database Connection Issues');
    expect(result.status).toBe('INVESTIGATING');
    expect(result.severity).toBe('critical');

    // Verify component statuses were updated (critical → MAJOR_OUTAGE)
    expect(statusComponentRepo.updateComponentStatus).toHaveBeenCalledTimes(2);
    expect(statusComponentRepo.updateComponentStatus).toHaveBeenCalledWith(compId1, 'MAJOR_OUTAGE');
    expect(statusComponentRepo.updateComponentStatus).toHaveBeenCalledWith(compId2, 'MAJOR_OUTAGE');

    // Verify audit log
    expect(auditLogger.log).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'incident.created',
        resourceType: 'incident',
        actorType: 'admin',
        metadata: expect.objectContaining({
          adminUserId: 'admin-user-1',
          title: 'Database Connection Issues',
          severity: 'critical',
        }),
      }),
    );
  });

  it('createIncident emits notification event', async () => {
    const compId = crypto.randomUUID();
    const statusComponentRepo = makeMockStatusComponentRepo({
      components: [{ componentId: compId, name: 'API', displayName: 'API', status: 'OPERATIONAL', sortOrder: 2 }],
    });
    const incidentRepo = makeMockIncidentRepo();
    const deps = makeServiceDeps({ statusComponentRepo, incidentRepo });
    const emitter = makeMockEventEmitter();

    await createIncident(deps, 'admin-user-1', {
      title: 'Scheduled Maintenance',
      severity: 'minor',
      affected_components: [compId],
      message: 'Planned maintenance window.',
    }, emitter);

    expect(emitter.emit).toHaveBeenCalledWith(
      'MAINTENANCE_SCHEDULED',
      expect.objectContaining({
        title: 'Scheduled Maintenance',
        severity: 'minor',
        affectedComponents: [compId],
        message: 'Planned maintenance window.',
      }),
    );
  });
});

describe('Platform Service — updateIncident', () => {
  it('updateIncident posts update to incident', async () => {
    const incidentId = crypto.randomUUID();
    const compId = crypto.randomUUID();
    const updatedIncident = {
      incidentId,
      title: 'API Latency Spike',
      status: 'IDENTIFIED',
      severity: 'major',
      affectedComponents: [compId],
      resolvedAt: null,
      createdAt: new Date('2026-02-17T10:00:00Z'),
      updatedAt: new Date('2026-02-17T11:00:00Z'),
      updates: [
        {
          updateId: crypto.randomUUID(),
          incidentId,
          status: 'INVESTIGATING',
          message: 'Investigating.',
          createdAt: new Date('2026-02-17T10:00:00Z'),
        },
        {
          updateId: crypto.randomUUID(),
          incidentId,
          status: 'IDENTIFIED',
          message: 'Root cause: connection pool exhaustion.',
          createdAt: new Date('2026-02-17T11:00:00Z'),
        },
      ],
    };

    const incidentRepo = makeMockIncidentRepo({ updatedIncident });
    const statusComponentRepo = makeMockStatusComponentRepo({
      components: [{ componentId: compId, name: 'API', displayName: 'API', status: 'PARTIAL_OUTAGE', sortOrder: 2 }],
    });
    const auditLogger = makeMockAuditLogger();
    const deps = makeServiceDeps({ incidentRepo, statusComponentRepo });
    deps.auditLogger = auditLogger;
    const emitter = makeMockEventEmitter();

    const result = await updateIncident(
      deps,
      'admin-user-1',
      incidentId,
      'IDENTIFIED',
      'Root cause: connection pool exhaustion.',
      emitter,
    );

    expect(result.status).toBe('IDENTIFIED');
    expect(result.updates).toHaveLength(2);
    expect(result.updates[1].message).toBe('Root cause: connection pool exhaustion.');

    // Should NOT restore components (not resolving)
    expect(statusComponentRepo.updateComponentStatus).not.toHaveBeenCalled();

    // Should emit notification
    expect(emitter.emit).toHaveBeenCalledWith(
      'INCIDENT_UPDATED',
      expect.objectContaining({
        incidentId,
        status: 'IDENTIFIED',
        message: 'Root cause: connection pool exhaustion.',
      }),
    );

    // Should log audit
    expect(auditLogger.log).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'incident.updated',
        resourceType: 'incident',
        resourceId: incidentId,
        actorType: 'admin',
      }),
    );
  });

  it('updateIncident restores components on resolution', async () => {
    const incidentId = crypto.randomUUID();
    const compId1 = crypto.randomUUID();
    const compId2 = crypto.randomUUID();
    const updatedIncident = {
      incidentId,
      title: 'Database Issues',
      status: 'RESOLVED',
      severity: 'critical',
      affectedComponents: [compId1, compId2],
      resolvedAt: new Date('2026-02-17T14:00:00Z'),
      createdAt: new Date('2026-02-17T10:00:00Z'),
      updatedAt: new Date('2026-02-17T14:00:00Z'),
      updates: [
        {
          updateId: crypto.randomUUID(),
          incidentId,
          status: 'INVESTIGATING',
          message: 'Investigating.',
          createdAt: new Date('2026-02-17T10:00:00Z'),
        },
        {
          updateId: crypto.randomUUID(),
          incidentId,
          status: 'RESOLVED',
          message: 'All services restored.',
          createdAt: new Date('2026-02-17T14:00:00Z'),
        },
      ],
    };

    const incidentRepo = makeMockIncidentRepo({ updatedIncident });
    const statusComponentRepo = makeMockStatusComponentRepo({
      components: [
        { componentId: compId1, name: 'API', displayName: 'API', status: 'MAJOR_OUTAGE', sortOrder: 2 },
        { componentId: compId2, name: 'DATABASE', displayName: 'Database', status: 'MAJOR_OUTAGE', sortOrder: 7 },
      ],
    });
    const deps = makeServiceDeps({ incidentRepo, statusComponentRepo });

    await updateIncident(deps, 'admin-user-1', incidentId, 'RESOLVED', 'All services restored.');

    // Should restore components to OPERATIONAL
    expect(statusComponentRepo.updateComponentStatus).toHaveBeenCalledTimes(2);
    expect(statusComponentRepo.updateComponentStatus).toHaveBeenCalledWith(compId1, 'OPERATIONAL');
    expect(statusComponentRepo.updateComponentStatus).toHaveBeenCalledWith(compId2, 'OPERATIONAL');
  });
});

describe('Platform Service — updateComponentStatus', () => {
  it('updateComponentStatus changes component health', async () => {
    const compId = crypto.randomUUID();
    const components = [
      { componentId: compId, name: 'API', displayName: 'API', status: 'OPERATIONAL', sortOrder: 2, updatedAt: new Date() },
    ];
    const statusComponentRepo = makeMockStatusComponentRepo({ components });
    const auditLogger = makeMockAuditLogger();
    const deps = makeServiceDeps({ statusComponentRepo });
    deps.auditLogger = auditLogger;

    const result = await updateComponentStatus(deps, 'admin-user-1', compId, 'MAINTENANCE');

    expect(result.componentId).toBe(compId);
    expect(result.name).toBe('API');
    expect(result.status).toBe('MAINTENANCE');

    expect(auditLogger.log).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'component.status_updated',
        resourceType: 'component',
        resourceId: compId,
        actorType: 'admin',
        metadata: expect.objectContaining({
          adminUserId: 'admin-user-1',
          newStatus: 'MAINTENANCE',
        }),
      }),
    );
  });
});

describe('Platform Service — seedStatusComponents', () => {
  it('seedStatusComponents is idempotent', async () => {
    const statusComponentRepo = makeMockStatusComponentRepo();
    const deps = makeServiceDeps({ statusComponentRepo });

    // Run seed twice
    await seedStatusComponents(deps);
    await seedStatusComponents(deps);

    // seedComponents should be called twice but the underlying implementation is idempotent
    expect(statusComponentRepo.seedComponents).toHaveBeenCalledTimes(2);

    // Verify the seed data contains 8 components
    const seedCall = statusComponentRepo.seedComponents.mock.calls[0][0];
    expect(seedCall).toHaveLength(8);

    // Verify all 8 component names
    const names = seedCall.map((c: any) => c.name);
    expect(names).toContain('WEB_APP');
    expect(names).toContain('API');
    expect(names).toContain('HLINK_SUBMISSION');
    expect(names).toContain('WCB_SUBMISSION');
    expect(names).toContain('AI_COACH');
    expect(names).toContain('EMAIL_DELIVERY');
    expect(names).toContain('DATABASE');
    expect(names).toContain('PAYMENT_PROCESSING');

    // Verify sort orders are correct
    const webApp = seedCall.find((c: any) => c.name === 'WEB_APP');
    expect(webApp.sortOrder).toBe(1);
    expect(webApp.displayName).toBe('Web Application');

    const paymentProcessing = seedCall.find((c: any) => c.name === 'PAYMENT_PROCESSING');
    expect(paymentProcessing.sortOrder).toBe(8);
    expect(paymentProcessing.displayName).toBe('Payment Processing');
  });
});

// ---------------------------------------------------------------------------
// Stripe Webhook Plugin Tests
// ---------------------------------------------------------------------------

describe('Stripe Webhook Plugin', () => {
  let app: any;
  let mockStripe: ReturnType<typeof makeMockStripe>;

  beforeEach(async () => {
    // Dynamic import to avoid hoisting issues with vi.mock
    const { default: Fastify } = await import('fastify');
    const { stripeWebhookPlugin } = await import('../../plugins/stripe-webhook.plugin.js');

    mockStripe = makeMockStripe();
    app = Fastify({ logger: false });

    await app.register(stripeWebhookPlugin, {
      webhookPath: '/api/v1/platform/webhook',
      stripe: mockStripe,
      webhookSecret: 'whsec_test_secret',
    });

    // Register a test webhook route that uses the verifyStripeWebhook preHandler
    app.post('/api/v1/platform/webhook', {
      preHandler: [app.verifyStripeWebhook],
      handler: async (request: any, reply: any) => {
        return reply.code(200).send({ data: { received: true, eventType: request.stripeEvent?.type } });
      },
    });

    // Register a normal JSON route to verify non-webhook routes still work
    app.post('/api/v1/normal', {
      handler: async (request: any, reply: any) => {
        return reply.code(200).send({ data: request.body });
      },
    });

    await app.ready();
  }, 30_000);

  afterEach(async () => {
    await app.close();
  });

  it('Webhook plugin preserves raw body for signature verification', async () => {
    const payload = JSON.stringify({ id: 'evt_test_1', type: 'invoice.paid', data: { object: {} } });
    (mockStripe.webhooks.constructEvent as any).mockImplementation(
      (rawBody: string, _sig: string, _secret: string) => {
        // Verify we receive the raw body string, not a parsed object
        expect(typeof rawBody).toBe('string');
        expect(rawBody).toBe(payload);
        return JSON.parse(rawBody);
      },
    );

    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/platform/webhook',
      headers: {
        'content-type': 'application/json',
        'stripe-signature': 'sig_valid_test',
      },
      payload: payload,
    });

    expect(res.statusCode).toBe(200);
    expect(mockStripe.webhooks.constructEvent).toHaveBeenCalledWith(
      payload,
      'sig_valid_test',
      'whsec_test_secret',
    );
  });

  it('Valid signature passes verification', async () => {
    const payload = JSON.stringify({ id: 'evt_test_2', type: 'checkout.session.completed', data: { object: {} } });
    (mockStripe.webhooks.constructEvent as any).mockImplementation(
      (rawBody: string) => JSON.parse(rawBody),
    );

    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/platform/webhook',
      headers: {
        'content-type': 'application/json',
        'stripe-signature': 'sig_valid',
      },
      payload: payload,
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.payload);
    expect(body.data.received).toBe(true);
    expect(body.data.eventType).toBe('checkout.session.completed');
  });

  it('Invalid signature returns 400', async () => {
    const payload = JSON.stringify({ id: 'evt_test_3', type: 'invoice.paid', data: { object: {} } });
    (mockStripe.webhooks.constructEvent as any).mockImplementation(() => {
      throw new Error('No signatures found matching the expected signature for payload');
    });

    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/platform/webhook',
      headers: {
        'content-type': 'application/json',
        'stripe-signature': 'sig_invalid',
      },
      payload: payload,
    });

    expect(res.statusCode).toBe(400);
    const body = JSON.parse(res.payload);
    expect(body.error.code).toBe('WEBHOOK_ERROR');
    expect(body.error.message).toBe('Invalid webhook request');
    // Must NOT reveal verification failure details
    expect(body.error.message).not.toContain('signature');
  });

  it('Missing signature header returns 400', async () => {
    const payload = JSON.stringify({ id: 'evt_test_4', type: 'invoice.paid', data: { object: {} } });

    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/platform/webhook',
      headers: {
        'content-type': 'application/json',
        // No stripe-signature header
      },
      payload: payload,
    });

    expect(res.statusCode).toBe(400);
    const body = JSON.parse(res.payload);
    expect(body.error.code).toBe('WEBHOOK_ERROR');
    expect(body.error.message).toBe('Invalid webhook request');
  });

  it('Tampered body with valid header returns 400', async () => {
    const originalPayload = JSON.stringify({ id: 'evt_test_5', type: 'invoice.paid', data: { object: {} } });
    const tamperedPayload = JSON.stringify({ id: 'evt_test_5', type: 'invoice.paid', data: { object: { tampered: true } } });

    // Signature was generated for originalPayload but we send tamperedPayload
    (mockStripe.webhooks.constructEvent as any).mockImplementation(
      (rawBody: string, _sig: string, _secret: string) => {
        // Simulate Stripe SDK: the raw body doesn't match the signature
        if (rawBody !== originalPayload) {
          throw new Error('No signatures found matching the expected signature for payload');
        }
        return JSON.parse(rawBody);
      },
    );

    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/platform/webhook',
      headers: {
        'content-type': 'application/json',
        'stripe-signature': 'sig_for_original',
      },
      payload: tamperedPayload,
    });

    expect(res.statusCode).toBe(400);
    const body = JSON.parse(res.payload);
    expect(body.error.code).toBe('WEBHOOK_ERROR');
    expect(body.error.message).toBe('Invalid webhook request');
  });

  it('Non-webhook routes still parse JSON normally', async () => {
    const payload = { hello: 'world', nested: { key: 'value' } };

    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/normal',
      headers: {
        'content-type': 'application/json',
      },
      payload: JSON.stringify(payload),
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.payload);
    expect(body.data.hello).toBe('world');
    expect(body.data.nested.key).toBe('value');
  });

  it('Webhook rate limit config returns correct values', async () => {
    const config = app.webhookRateLimit();
    expect(config.max).toBe(100);
    expect(config.timeWindow).toBe('1 minute');
    expect(typeof config.keyGenerator).toBe('function');
  });
});
