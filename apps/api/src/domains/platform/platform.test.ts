import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  createSubscriptionRepository,
  createPaymentRepository,
  createStatusComponentRepository,
  createIncidentRepository,
  createAmendmentRepository,
  createBreachRepository,
} from './platform.repository.js';
import { createExportRepository } from './export.repository.js';
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
  runExportWindowReminders,
  getSubscriptionStatus,
  getStatusPage,
  getIncidentHistory,
  createIncident,
  updateIncident,
  updateComponentStatus,
  seedStatusComponents,
  checkEarlyBirdExpiry,
  createAmendment,
  acknowledgeAmendment,
  respondToAmendment,
  getBlockingAmendments,
  runAmendmentReminders,
  createBreach,
  sendBreachNotifications,
  addBreachUpdate,
  resolveBreach,
  checkBreachDeadlines,
  runDestructionConfirmation,
  markBackupPurged,
  type PlatformServiceDeps,
  type StripeClient,
  type StripeEvent,
  type UserRepo,
  type PlatformEventEmitter,
  type DataDeletionRepo,
  type AuditLogger,
  type ActiveProviderRepo,
} from './platform.service.js';
import { type SpacesFileClient } from '../../lib/spaces.js';

// ---------------------------------------------------------------------------
// In-memory stores
// ---------------------------------------------------------------------------

let subscriptionStore: Record<string, any>[];
let paymentStore: Record<string, any>[];
let componentStore: Record<string, any>[];
let incidentStore: Record<string, any>[];
let incidentUpdateStore: Record<string, any>[];
let practiceMembershipStore: Record<string, any>[];
let amendmentStore: Record<string, any>[];
let amendmentResponseStore: Record<string, any>[];
let breachRecordStore: Record<string, any>[];
let breachAffectedCustodianStore: Record<string, any>[];
let breachUpdateStore: Record<string, any>[];

// Export repository stores (IMA-050)
let exportPatientStore: Record<string, any>[];
let exportClaimStore: Record<string, any>[];
let exportClaimAuditStore: Record<string, any>[];
let exportShiftStore: Record<string, any>[];
let exportClaimExportStore: Record<string, any>[];
let exportAhcipDetailStore: Record<string, any>[];
let exportAhcipBatchStore: Record<string, any>[];
let exportWcbDetailStore: Record<string, any>[];
let exportWcbBatchStore: Record<string, any>[];
let exportWcbRemittanceStore: Record<string, any>[];
let exportProviderStore: Record<string, any>[];
let exportBaStore: Record<string, any>[];
let exportLocationStore: Record<string, any>[];
let exportWcbConfigStore: Record<string, any>[];
let exportDelegateStore: Record<string, any>[];
let exportSubmPrefStore: Record<string, any>[];
let exportHlinkStore: Record<string, any>[];
let exportPcpcmEnrolmentStore: Record<string, any>[];
let exportPcpcmPaymentStore: Record<string, any>[];
let exportPcpcmPanelStore: Record<string, any>[];
let exportAnalyticsCacheStore: Record<string, any>[];
let exportReportStore: Record<string, any>[];
let exportReportSubStore: Record<string, any>[];
let exportAiLearningStore: Record<string, any>[];
let exportAiSuggestionStore: Record<string, any>[];
let exportEdShiftStore: Record<string, any>[];
let exportFavCodeStore: Record<string, any>[];
let exportAuditLogStore: Record<string, any>[];

// ---------------------------------------------------------------------------
// Mock Drizzle DB
// ---------------------------------------------------------------------------

function makeMockDb() {
  function getStoreForTable(table: any): Record<string, any>[] {
    if (table?.__table === 'payment_history') return paymentStore;
    if (table?.__table === 'status_components') return componentStore;
    if (table?.__table === 'status_incidents') return incidentStore;
    if (table?.__table === 'incident_updates') return incidentUpdateStore;
    if (table?.__table === 'practice_memberships') return practiceMembershipStore;
    if (table?.__table === 'ima_amendments') return amendmentStore;
    if (table?.__table === 'ima_amendment_responses') return amendmentResponseStore;
    if (table?.__table === 'breach_records') return breachRecordStore;
    if (table?.__table === 'breach_affected_custodians') return breachAffectedCustodianStore;
    if (table?.__table === 'breach_updates') return breachUpdateStore;
    // Export repository tables (IMA-050)
    if (table?.__table === 'patients') return exportPatientStore;
    if (table?.__table === 'claims') return exportClaimStore;
    if (table?.__table === 'claim_audit_history') return exportClaimAuditStore;
    if (table?.__table === 'shifts') return exportShiftStore;
    if (table?.__table === 'claim_exports') return exportClaimExportStore;
    if (table?.__table === 'ahcip_claim_details') return exportAhcipDetailStore;
    if (table?.__table === 'ahcip_batches') return exportAhcipBatchStore;
    if (table?.__table === 'wcb_claim_details') return exportWcbDetailStore;
    if (table?.__table === 'wcb_batches') return exportWcbBatchStore;
    if (table?.__table === 'wcb_remittance_imports') return exportWcbRemittanceStore;
    if (table?.__table === 'providers') return exportProviderStore;
    if (table?.__table === 'business_arrangements') return exportBaStore;
    if (table?.__table === 'practice_locations') return exportLocationStore;
    if (table?.__table === 'wcb_configurations') return exportWcbConfigStore;
    if (table?.__table === 'delegate_relationships') return exportDelegateStore;
    if (table?.__table === 'submission_preferences') return exportSubmPrefStore;
    if (table?.__table === 'hlink_configurations') return exportHlinkStore;
    if (table?.__table === 'pcpcm_enrolments') return exportPcpcmEnrolmentStore;
    if (table?.__table === 'pcpcm_payments') return exportPcpcmPaymentStore;
    if (table?.__table === 'pcpcm_panel_estimates') return exportPcpcmPanelStore;
    if (table?.__table === 'analytics_cache') return exportAnalyticsCacheStore;
    if (table?.__table === 'generated_reports') return exportReportStore;
    if (table?.__table === 'report_subscriptions') return exportReportSubStore;
    if (table?.__table === 'ai_provider_learning') return exportAiLearningStore;
    if (table?.__table === 'ai_suggestion_events') return exportAiSuggestionStore;
    if (table?.__table === 'ed_shifts') return exportEdShiftStore;
    if (table?.__table === 'favourite_codes') return exportFavCodeStore;
    if (table?.__table === 'audit_log') return exportAuditLogStore;
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
    joinTable?: any;
    joinPredicate?: { left: any; right: any };
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
      innerJoin(joinTable: any, condition: any) {
        ctx.joinTable = joinTable;
        if (condition && condition.__predicate) {
          // The join condition acts as a where clause on the joined result
          ctx.joinPredicate = condition;
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

    if (table?.__table === 'ima_amendments') {
      const newAmendment = {
        amendmentId: values.amendmentId ?? crypto.randomUUID(),
        amendmentType: values.amendmentType,
        title: values.title,
        description: values.description,
        documentHash: values.documentHash,
        noticeDate: values.noticeDate,
        effectiveDate: values.effectiveDate,
        createdBy: values.createdBy,
        createdAt: values.createdAt ?? new Date(),
      };
      store.push(newAmendment);
      return newAmendment;
    }

    if (table?.__table === 'ima_amendment_responses') {
      const existing = amendmentResponseStore.find(
        (r) =>
          r.amendmentId === values.amendmentId &&
          r.providerId === values.providerId,
      );
      if (existing) {
        const err: any = new Error(
          'duplicate key value violates unique constraint "ima_responses_unique_idx"',
        );
        err.code = '23505';
        throw err;
      }
      const newResponse = {
        responseId: values.responseId ?? crypto.randomUUID(),
        amendmentId: values.amendmentId,
        providerId: values.providerId,
        responseType: values.responseType,
        respondedAt: values.respondedAt ?? new Date(),
        ipAddress: values.ipAddress,
        userAgent: values.userAgent,
      };
      store.push(newResponse);
      return newResponse;
    }

    if (table?.__table === 'breach_records') {
      const newBreach = {
        breachId: values.breachId ?? crypto.randomUUID(),
        breachDescription: values.breachDescription,
        breachDate: values.breachDate,
        awarenessDate: values.awarenessDate,
        hiDescription: values.hiDescription,
        includesIihi: values.includesIihi,
        affectedCount: values.affectedCount ?? null,
        riskAssessment: values.riskAssessment ?? null,
        mitigationSteps: values.mitigationSteps ?? null,
        contactName: values.contactName,
        contactEmail: values.contactEmail,
        status: values.status ?? 'INVESTIGATING',
        evidenceHoldUntil: values.evidenceHoldUntil ?? null,
        createdBy: values.createdBy,
        createdAt: values.createdAt ?? new Date(),
        updatedAt: values.updatedAt ?? new Date(),
        resolvedAt: values.resolvedAt ?? null,
      };
      store.push(newBreach);
      return newBreach;
    }

    if (table?.__table === 'breach_affected_custodians') {
      const newCustodian = {
        id: values.id ?? crypto.randomUUID(),
        breachId: values.breachId,
        providerId: values.providerId,
        initialNotifiedAt: values.initialNotifiedAt ?? null,
        notificationMethod: values.notificationMethod ?? null,
      };
      store.push(newCustodian);
      return newCustodian;
    }

    if (table?.__table === 'breach_updates') {
      const newUpdate = {
        updateId: values.updateId ?? crypto.randomUUID(),
        breachId: values.breachId,
        updateType: values.updateType,
        content: values.content,
        sentAt: values.sentAt ?? new Date(),
        createdBy: values.createdBy,
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
        let store = getStoreForTable(ctx.table);

        // Handle innerJoin: create cross-product filtered by join predicate
        if (ctx.joinTable) {
          const joinStore = getStoreForTable(ctx.joinTable);
          const joined: any[] = [];
          for (const leftRow of store) {
            for (const joinRow of joinStore) {
              // Merge the rows — for the join predicate check
              const merged = { ...leftRow, ...joinRow };
              // Check the join predicate if it exists
              if (ctx.joinPredicate?.__predicate) {
                if (ctx.joinPredicate.__predicate(merged)) {
                  joined.push(merged);
                }
              } else {
                joined.push(merged);
              }
            }
          }
          store = joined;
        }

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
    isNotNull: (column: any) => {
      const colName = column?.name;
      return {
        __predicate: (row: any) => row[colName] != null,
      };
    },
    isNull: (column: any) => {
      const colName = column?.name;
      return {
        __predicate: (row: any) => row[colName] == null,
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

      // ${column} IN ('VALUE1', 'VALUE2', ...)
      if (raw.includes('IN (')) {
        const col = values[0];
        const colName = col?.name;
        // Extract values from the IN list in the template string
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

  const imaAmendmentsProxy: any = {
    __table: 'ima_amendments',
    amendmentId: makeCol('amendmentId'),
    amendmentType: makeCol('amendmentType'),
    title: makeCol('title'),
    description: makeCol('description'),
    documentHash: makeCol('documentHash'),
    noticeDate: makeCol('noticeDate'),
    effectiveDate: makeCol('effectiveDate'),
    createdBy: makeCol('createdBy'),
    createdAt: makeCol('createdAt'),
  };

  const imaAmendmentResponsesProxy: any = {
    __table: 'ima_amendment_responses',
    responseId: makeCol('responseId'),
    amendmentId: makeCol('amendmentId'),
    providerId: makeCol('providerId'),
    responseType: makeCol('responseType'),
    respondedAt: makeCol('respondedAt'),
    ipAddress: makeCol('ipAddress'),
    userAgent: makeCol('userAgent'),
  };

  const breachRecordsProxy: any = {
    __table: 'breach_records',
    breachId: makeCol('breachId'),
    breachDescription: makeCol('breachDescription'),
    breachDate: makeCol('breachDate'),
    awarenessDate: makeCol('awarenessDate'),
    hiDescription: makeCol('hiDescription'),
    includesIihi: makeCol('includesIihi'),
    affectedCount: makeCol('affectedCount'),
    riskAssessment: makeCol('riskAssessment'),
    mitigationSteps: makeCol('mitigationSteps'),
    contactName: makeCol('contactName'),
    contactEmail: makeCol('contactEmail'),
    status: makeCol('status'),
    evidenceHoldUntil: makeCol('evidenceHoldUntil'),
    createdBy: makeCol('createdBy'),
    createdAt: makeCol('createdAt'),
    updatedAt: makeCol('updatedAt'),
    resolvedAt: makeCol('resolvedAt'),
  };

  const breachAffectedCustodiansProxy: any = {
    __table: 'breach_affected_custodians',
    id: makeCol('id'),
    breachId: makeCol('breachId'),
    providerId: makeCol('providerId'),
    initialNotifiedAt: makeCol('initialNotifiedAt'),
    notificationMethod: makeCol('notificationMethod'),
  };

  const breachUpdatesProxy: any = {
    __table: 'breach_updates',
    updateId: makeCol('updateId'),
    breachId: makeCol('breachId'),
    updateType: makeCol('updateType'),
    content: makeCol('content'),
    sentAt: makeCol('sentAt'),
    createdBy: makeCol('createdBy'),
  };

  return {
    subscriptions: subscriptionsProxy,
    paymentHistory: paymentHistoryProxy,
    statusComponents: statusComponentsProxy,
    statusIncidents: statusIncidentsProxy,
    incidentUpdates: incidentUpdatesProxy,
    practiceMemberships: practiceMembershipsProxy,
    imaAmendments: imaAmendmentsProxy,
    imaAmendmentResponses: imaAmendmentResponsesProxy,
    breachRecords: breachRecordsProxy,
    breachAffectedCustodians: breachAffectedCustodiansProxy,
    breachUpdates: breachUpdatesProxy,
  };
});

// Mock constants
vi.mock('@meritum/shared/constants/platform.constants.js', () => ({
  DUNNING_SUSPENSION_DAY: 14,
  DUNNING_CANCELLATION_DAY: 30,
  EARLY_BIRD_CAP: 100,
  EARLY_BIRD_RATE_LOCK_MONTHS: 12,
  EARLY_BIRD_EXPIRY_WARNING_DAYS: 30,
  BACKUP_PURGE_DEADLINE_DAYS: 90,
  SubscriptionPlan: {
    STANDARD_MONTHLY: 'STANDARD_MONTHLY',
    STANDARD_ANNUAL: 'STANDARD_ANNUAL',
    EARLY_BIRD_MONTHLY: 'EARLY_BIRD_MONTHLY',
    EARLY_BIRD_ANNUAL: 'EARLY_BIRD_ANNUAL',
    CLINIC_MONTHLY: 'CLINIC_MONTHLY',
    CLINIC_ANNUAL: 'CLINIC_ANNUAL',
  },
  GST_RATE: 0.05,
  DELETION_GRACE_PERIOD_DAYS: 45,
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
  FeatureAccessMatrix: {
    ACTIVE: ['claim_create', 'claim_view', 'claim_edit'],
    TRIAL: ['claim_create', 'claim_view', 'claim_edit'],
    PAST_DUE: ['claim_create', 'claim_view', 'claim_edit'],
    SUSPENDED: ['claim_view', 'data_export'],
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
  PlatformAuditAction: {
    DESTRUCTION_ACTIVE_DELETED: 'destruction.active_deleted',
    DESTRUCTION_FILES_DELETED: 'destruction.files_deleted',
    DESTRUCTION_BACKUP_PURGED: 'destruction.backup_purged',
    DESTRUCTION_CONFIRMED: 'destruction.confirmed',
    AMENDMENT_CREATED: 'amendment.created',
    AMENDMENT_ACKNOWLEDGED: 'amendment.acknowledged',
    AMENDMENT_ACCEPTED: 'amendment.accepted',
    AMENDMENT_REJECTED: 'amendment.rejected',
    BREACH_CREATED: 'breach.created',
    BREACH_NOTIFICATION_SENT: 'breach.notification_sent',
    BREACH_UPDATED: 'breach.updated',
    BREACH_RESOLVED: 'breach.resolved',
    BREACH_EVIDENCE_HOLD_SET: 'breach.evidence_hold_set',
    EXPORT_FULL_HI_REQUESTED: 'export.full_hi_requested',
    EXPORT_FULL_HI_READY: 'export.full_hi_ready',
    EXPORT_PATIENT_ACCESS_REQUESTED: 'export.patient_access_requested',
    EXPORT_PATIENT_ACCESS_READY: 'export.patient_access_ready',
    PATIENT_CORRECTION_APPLIED: 'patient.correction_applied',
  },
}));

// Mock schema modules used by export.repository.ts
function makeSchemaTable(tableName: string, columns: string[]) {
  const proxy: any = { __table: tableName };
  for (const col of columns) {
    proxy[col] = { name: col };
  }
  return proxy;
}

vi.mock('@meritum/shared/schemas/db/patient.schema.js', () => ({
  patients: makeSchemaTable('patients', ['providerId', 'patientId', 'isActive']),
  patientImportBatches: makeSchemaTable('patient_import_batches', ['physicianId']),
  patientMergeHistory: makeSchemaTable('patient_merge_history', ['physicianId']),
}));

vi.mock('@meritum/shared/schemas/db/claim.schema.js', () => ({
  claims: makeSchemaTable('claims', ['physicianId', 'claimId', 'status']),
  claimAuditHistory: makeSchemaTable('claim_audit_history', ['auditId', 'claimId', 'fieldName', 'oldValue', 'newValue', 'changedBy', 'changedAt']),
  fieldMappingTemplates: makeSchemaTable('field_mapping_templates', ['physicianId']),
  importBatches: makeSchemaTable('import_batches', ['physicianId']),
  shifts: makeSchemaTable('shifts', ['physicianId']),
  claimExports: makeSchemaTable('claim_exports', ['physicianId']),
}));

vi.mock('@meritum/shared/schemas/db/ahcip.schema.js', () => ({
  ahcipClaimDetails: makeSchemaTable('ahcip_claim_details', ['claimId']),
  ahcipBatches: makeSchemaTable('ahcip_batches', ['physicianId']),
}));

vi.mock('@meritum/shared/schemas/db/wcb.schema.js', () => ({
  wcbClaimDetails: makeSchemaTable('wcb_claim_details', ['claimId']),
  wcbBatches: makeSchemaTable('wcb_batches', ['physicianId']),
  wcbRemittanceImports: makeSchemaTable('wcb_remittance_imports', ['physicianId']),
  wcbInjuries: makeSchemaTable('wcb_injuries', []),
  wcbPrescriptions: makeSchemaTable('wcb_prescriptions', []),
  wcbConsultations: makeSchemaTable('wcb_consultations', []),
  wcbWorkRestrictions: makeSchemaTable('wcb_work_restrictions', []),
  wcbInvoiceLines: makeSchemaTable('wcb_invoice_lines', []),
  wcbAttachments: makeSchemaTable('wcb_attachments', []),
  wcbReturnRecords: makeSchemaTable('wcb_return_records', []),
  wcbReturnInvoiceLines: makeSchemaTable('wcb_return_invoice_lines', []),
  wcbRemittanceRecords: makeSchemaTable('wcb_remittance_records', []),
}));

vi.mock('@meritum/shared/schemas/db/provider.schema.js', () => ({
  providers: makeSchemaTable('providers', ['providerId']),
  businessArrangements: makeSchemaTable('business_arrangements', ['providerId']),
  pcpcmEnrolments: makeSchemaTable('pcpcm_enrolments', ['providerId']),
  practiceLocations: makeSchemaTable('practice_locations', ['providerId']),
  wcbConfigurations: makeSchemaTable('wcb_configurations', ['providerId']),
  delegateRelationships: makeSchemaTable('delegate_relationships', ['physicianId']),
  submissionPreferences: makeSchemaTable('submission_preferences', ['providerId']),
  hlinkConfigurations: makeSchemaTable('hlink_configurations', ['providerId']),
  pcpcmPayments: makeSchemaTable('pcpcm_payments', ['providerId']),
  pcpcmPanelEstimates: makeSchemaTable('pcpcm_panel_estimates', ['providerId']),
}));

vi.mock('@meritum/shared/schemas/db/analytics.schema.js', () => ({
  analyticsCache: makeSchemaTable('analytics_cache', ['providerId']),
  generatedReports: makeSchemaTable('generated_reports', ['providerId']),
  reportSubscriptions: makeSchemaTable('report_subscriptions', ['providerId']),
}));

vi.mock('@meritum/shared/schemas/db/intelligence.schema.js', () => ({
  aiRules: makeSchemaTable('ai_rules', []),
  aiProviderLearning: makeSchemaTable('ai_provider_learning', ['providerId']),
  aiSpecialtyCohorts: makeSchemaTable('ai_specialty_cohorts', []),
  aiSuggestionEvents: makeSchemaTable('ai_suggestion_events', ['providerId']),
}));

vi.mock('@meritum/shared/schemas/db/mobile.schema.js', () => ({
  edShifts: makeSchemaTable('ed_shifts', ['providerId']),
  favouriteCodes: makeSchemaTable('favourite_codes', ['providerId']),
}));

vi.mock('@meritum/shared/schemas/db/iam.schema.js', () => ({
  users: makeSchemaTable('users', ['userId']),
  recoveryCodes: makeSchemaTable('recovery_codes', []),
  sessions: makeSchemaTable('sessions', []),
  invitationTokens: makeSchemaTable('invitation_tokens', []),
  delegateLinkages: makeSchemaTable('delegate_linkages', []),
  auditLog: makeSchemaTable('audit_log', ['userId']),
}));

// Mock pricing utils
vi.mock('@meritum/shared/utils/pricing.utils.js', () => ({
  isEarlyBirdRate: (plan: string) => plan.includes('EARLY_BIRD'),
  calculateEffectiveRate: () => ({ monthlyRate: 279, annualRate: null, appliedDiscounts: [], totalDiscountPercent: 0 }),
  getEarlyBirdRate: () => ({ monthlyRate: 199, annualRate: null, appliedDiscounts: [], totalDiscountPercent: 0 }),
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
    earlyBirdLockedUntil: overrides.earlyBirdLockedUntil ?? null,
    earlyBirdExpiryNotified: overrides.earlyBirdExpiryNotified ?? false,
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
    practiceMembershipStore = [];
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
    // Create 3 early bird monthly subscriptions
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

  it('countEarlyBirdSubscriptions counts both EARLY_BIRD_MONTHLY and EARLY_BIRD_ANNUAL', async () => {
    // Create 2 early bird monthly
    for (let i = 0; i < 2; i++) {
      await repo.createSubscription(
        makeSubscription({ plan: 'EARLY_BIRD_MONTHLY' }) as any,
      );
    }

    // Create 3 early bird annual
    for (let i = 0; i < 3; i++) {
      await repo.createSubscription(
        makeSubscription({ plan: 'EARLY_BIRD_ANNUAL' }) as any,
      );
    }

    // Create 1 standard (should not be counted)
    await repo.createSubscription(
      makeSubscription({ plan: 'STANDARD_MONTHLY' }) as any,
    );

    const count = await repo.countEarlyBirdSubscriptions();
    expect(count).toBe(5);
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
    practiceMembershipStore = [];
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
    practiceMembershipStore = [];
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
    practiceMembershipStore = [];
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
    DELETION_GRACE_PERIOD_DAYS: 45,
    EARLY_BIRD_CAP: 100,
    GST_RATE: 0.05,
    SubscriptionPlan: {
      STANDARD_MONTHLY: 'STANDARD_MONTHLY',
      STANDARD_ANNUAL: 'STANDARD_ANNUAL',
      EARLY_BIRD_MONTHLY: 'EARLY_BIRD_MONTHLY',
      EARLY_BIRD_ANNUAL: 'EARLY_BIRD_ANNUAL',
      CLINIC_MONTHLY: 'CLINIC_MONTHLY',
      CLINIC_ANNUAL: 'CLINIC_ANNUAL',
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
    EARLY_BIRD_RATE_LOCK_MONTHS: 12,
    EARLY_BIRD_EXPIRY_WARNING_DAYS: 30,
    CLINIC_MINIMUM_PHYSICIANS: 5,
    BreachStatus: {
      INVESTIGATING: 'INVESTIGATING',
      NOTIFYING: 'NOTIFYING',
      MONITORING: 'MONITORING',
      RESOLVED: 'RESOLVED',
    },
    BreachUpdateType: {
      INITIAL: 'INITIAL',
      SUPPLEMENTARY: 'SUPPLEMENTARY',
    },
    BACKUP_PURGE_DEADLINE_DAYS: 90,
    PlatformAuditAction: {
      DESTRUCTION_ACTIVE_DELETED: 'destruction.active_deleted',
      DESTRUCTION_FILES_DELETED: 'destruction.files_deleted',
      DESTRUCTION_BACKUP_PURGED: 'destruction.backup_purged',
      DESTRUCTION_CONFIRMED: 'destruction.confirmed',
      AMENDMENT_CREATED: 'amendment.created',
      AMENDMENT_ACKNOWLEDGED: 'amendment.acknowledged',
      AMENDMENT_ACCEPTED: 'amendment.accepted',
      AMENDMENT_REJECTED: 'amendment.rejected',
      BREACH_CREATED: 'breach.created',
      BREACH_NOTIFICATION_SENT: 'breach.notification_sent',
      BREACH_UPDATED: 'breach.updated',
      BREACH_RESOLVED: 'breach.resolved',
      BREACH_EVIDENCE_HOLD_SET: 'breach.evidence_hold_set',
      EXPORT_FULL_HI_REQUESTED: 'export.full_hi_requested',
      EXPORT_FULL_HI_READY: 'export.full_hi_ready',
      EXPORT_PATIENT_ACCESS_REQUESTED: 'export.patient_access_requested',
      EXPORT_PATIENT_ACCESS_READY: 'export.patient_access_ready',
      PATIENT_CORRECTION_APPLIED: 'patient.correction_applied',
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
      update: vi.fn().mockResolvedValue({ id: 'sub_mock_123', status: 'active', items: { data: [{ id: 'si_mock', price: { id: 'price_standard_monthly_test' } }] } }),
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
  hasEverHadEarlyBird?: boolean;
  expiringEarlyBirdSubs?: Record<string, any>[];
  expiredEarlyBirdSubs?: Record<string, any>[];
  activePracticeMembership?: Record<string, any> | null;
  earlyBirdMembersInPractice?: Array<{ physicianUserId: string; earlyBirdExpiryNotified: boolean }>;
  cancelledSubsInExportWindow?: Record<string, any>[];
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
    // D17-010: updateSubscription
    updateSubscription: vi.fn().mockImplementation(
      async (id: string, data: any) => ({
        subscriptionId: id,
        ...data,
      }),
    ),
    // D17-011: hasEverHadEarlyBird
    hasEverHadEarlyBird: vi.fn().mockResolvedValue(
      options?.hasEverHadEarlyBird ?? false,
    ),
    // D17-012: findExpiringEarlyBirdSubscriptions
    findExpiringEarlyBirdSubscriptions: vi.fn().mockResolvedValue(
      options?.expiringEarlyBirdSubs ?? [],
    ),
    // D17-012: findExpiredEarlyBirdSubscriptions
    findExpiredEarlyBirdSubscriptions: vi.fn().mockResolvedValue(
      options?.expiredEarlyBirdSubs ?? [],
    ),
    // D17-012: getActivePracticeMembership
    getActivePracticeMembership: vi.fn().mockResolvedValue(
      options?.activePracticeMembership ?? null,
    ),
    // D17-012: updatePracticeMembershipBillingMode
    updatePracticeMembershipBillingMode: vi.fn().mockResolvedValue(undefined),
    // D17-014: getEarlyBirdMembersInPractice
    getEarlyBirdMembersInPractice: vi.fn().mockResolvedValue(
      options?.earlyBirdMembersInPractice ?? [],
    ),
    // IMA-012: findCancelledSubscriptionsInExportWindow
    findCancelledSubscriptionsInExportWindow: vi.fn().mockResolvedValue(
      options?.cancelledSubsInExportWindow ?? [],
    ),
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

function makeMockAmendmentRepo(options?: {
  amendments?: Array<Record<string, any>>;
  responses?: Array<Record<string, any>>;
}): any {
  const amendments = options?.amendments ?? [];
  const responses = options?.responses ?? [];

  return {
    createAmendment: vi.fn().mockImplementation(async (data: any) => ({
      amendmentId: crypto.randomUUID(),
      amendmentType: data.amendmentType,
      title: data.title,
      description: data.description,
      documentHash: 'mock_hash_' + Date.now(),
      noticeDate: new Date(),
      effectiveDate: data.effectiveDate,
      createdBy: data.createdBy,
      createdAt: new Date(),
    })),
    findAmendmentById: vi.fn().mockImplementation(async (id: string) => {
      const found = amendments.find((a) => a.amendmentId === id);
      if (!found) return undefined;
      return { ...found, responseCounts: { total: 0, acknowledged: 0, accepted: 0, rejected: 0 } };
    }),
    listAmendments: vi.fn().mockImplementation(async (filters: any) => {
      const now = new Date();
      const withStatus = amendments.map((a) => ({
        ...a,
        derivedStatus: now < a.effectiveDate ? 'PENDING' : 'ACTIVE',
      }));
      const filtered = filters.status
        ? withStatus.filter((a: any) => a.derivedStatus === filters.status)
        : withStatus;
      const offset = (filters.page - 1) * filters.pageSize;
      return {
        data: filtered.slice(offset, offset + filters.pageSize),
        total: filtered.length,
      };
    }),
    findPendingAmendmentsForProvider: vi.fn().mockImplementation(async (providerId: string) => {
      const now = new Date();
      const pastEffective = amendments.filter((a) => a.effectiveDate <= now);
      const respondedIds = new Set(
        responses.filter((r) => r.providerId === providerId).map((r) => r.amendmentId),
      );
      return pastEffective.filter((a) => !respondedIds.has(a.amendmentId));
    }),
    createAmendmentResponse: vi.fn().mockImplementation(async (data: any) => ({
      responseId: crypto.randomUUID(),
      amendmentId: data.amendmentId,
      providerId: data.providerId,
      responseType: data.responseType,
      respondedAt: new Date(),
      ipAddress: data.ipAddress,
      userAgent: data.userAgent,
    })),
    getAmendmentResponse: vi.fn().mockImplementation(async (amendmentId: string, providerId: string) => {
      return responses.find((r) => r.amendmentId === amendmentId && r.providerId === providerId) ?? undefined;
    }),
    countUnrespondedAmendments: vi.fn().mockResolvedValue(0),
  };
}

function makeMockActiveProviderRepo(providerIds?: string[]): ActiveProviderRepo {
  return {
    findActiveProviderIds: vi.fn().mockResolvedValue(providerIds ?? []),
  };
}

function makeMockBreachRepo(options?: {
  breaches?: Array<Record<string, any>>;
  custodians?: Array<Record<string, any>>;
  updates?: Array<Record<string, any>>;
}): any {
  const breaches = options?.breaches ?? [];
  const custodians = options?.custodians ?? [];
  const updates = options?.updates ?? [];

  return {
    createBreachRecord: vi.fn().mockImplementation(async (data: any) => {
      const breach = {
        breachId: crypto.randomUUID(),
        breachDescription: data.breachDescription,
        breachDate: data.breachDate,
        awarenessDate: data.awarenessDate,
        hiDescription: data.hiDescription,
        includesIihi: data.includesIihi,
        affectedCount: data.affectedCount,
        riskAssessment: data.riskAssessment,
        mitigationSteps: data.mitigationSteps,
        contactName: data.contactName,
        contactEmail: data.contactEmail,
        evidenceHoldUntil: new Date(new Date(data.awarenessDate).getTime() + 365 * 24 * 60 * 60 * 1000),
        status: 'INVESTIGATING',
        resolvedAt: null,
        createdBy: data.createdBy,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      breaches.push(breach);
      return breach;
    }),
    findBreachById: vi.fn().mockImplementation(async (breachId: string) => {
      const found = breaches.find((b) => b.breachId === breachId);
      if (!found) return undefined;
      const bCustodians = custodians.filter((c) => c.breachId === breachId);
      const bUpdates = updates.filter((u) => u.breachId === breachId);
      return {
        ...found,
        affectedCustodianCount: bCustodians.length,
        updates: bUpdates,
      };
    }),
    addAffectedCustodian: vi.fn().mockImplementation(async (breachId: string, providerId: string) => {
      const custodian = {
        affectedCustodianId: crypto.randomUUID(),
        breachId,
        providerId,
        initialNotifiedAt: null,
        notificationMethod: null,
      };
      custodians.push(custodian);
      return custodian;
    }),
    getUnnotifiedCustodians: vi.fn().mockImplementation(async (breachId: string) => {
      return custodians.filter((c) => c.breachId === breachId && !c.initialNotifiedAt);
    }),
    markCustodianNotified: vi.fn().mockImplementation(async (breachId: string, providerId: string, method: string) => {
      const found = custodians.find((c) => c.breachId === breachId && c.providerId === providerId);
      if (!found) return undefined;
      found.initialNotifiedAt = new Date();
      found.notificationMethod = method;
      return { ...found };
    }),
    createBreachUpdate: vi.fn().mockImplementation(async (breachId: string, data: any) => {
      const update = {
        updateId: crypto.randomUUID(),
        breachId,
        updateType: data.updateType,
        content: data.content,
        createdBy: data.createdBy,
        sentAt: new Date(),
      };
      updates.push(update);
      return update;
    }),
    updateBreachStatus: vi.fn().mockImplementation(async (breachId: string, status: string, resolvedAt?: Date) => {
      const found = breaches.find((b) => b.breachId === breachId);
      if (!found) return undefined;
      found.status = status;
      found.updatedAt = new Date();
      if (status === 'RESOLVED') {
        found.resolvedAt = resolvedAt ?? new Date();
      }
      return { ...found };
    }),
    getOverdueBreaches: vi.fn().mockResolvedValue([]),
    listBreaches: vi.fn().mockResolvedValue({ data: [], total: 0 }),
    listBreachUpdates: vi.fn().mockResolvedValue([]),
  };
}

function makeMockDestructionTrackingRepo() {
  const store: Record<string, any>[] = [];

  return {
    _store: store,
    createTrackingRecord: vi.fn().mockImplementation(async (data: any) => {
      const record = {
        trackingId: crypto.randomUUID(),
        providerId: data.providerId,
        lastKnownEmail: data.lastKnownEmail ?? null,
        activeDeletedAt: data.activeDeletedAt ?? null,
        filesDeletedAt: data.filesDeletedAt ?? null,
        backupPurgeDeadline: data.backupPurgeDeadline ?? null,
        backupPurgedAt: data.backupPurgedAt ?? null,
        confirmationSentAt: data.confirmationSentAt ?? null,
        createdAt: new Date(),
      };
      store.push(record);
      return record;
    }),
    findByProviderId: vi.fn().mockImplementation(async (providerId: string) => {
      return store.find((r) => r.providerId === providerId) ?? undefined;
    }),
    updateActiveDeletedAt: vi.fn().mockImplementation(
      async (providerId: string, activeDeletedAt: Date, backupPurgeDeadline: Date) => {
        const record = store.find((r) => r.providerId === providerId);
        if (record) {
          record.activeDeletedAt = activeDeletedAt;
          record.backupPurgeDeadline = backupPurgeDeadline;
        }
        return record;
      },
    ),
    updateFilesDeletedAt: vi.fn().mockImplementation(
      async (providerId: string, filesDeletedAt: Date) => {
        const record = store.find((r) => r.providerId === providerId);
        if (record) record.filesDeletedAt = filesDeletedAt;
        return record;
      },
    ),
    updateBackupPurgedAt: vi.fn().mockImplementation(
      async (providerId: string, backupPurgedAt: Date) => {
        const record = store.find((r) => r.providerId === providerId);
        if (record) record.backupPurgedAt = backupPurgedAt;
        return record;
      },
    ),
    updateConfirmationSentAt: vi.fn().mockImplementation(
      async (providerId: string, confirmationSentAt: Date) => {
        const record = store.find((r) => r.providerId === providerId);
        if (record) record.confirmationSentAt = confirmationSentAt;
        return record;
      },
    ),
    findPendingConfirmations: vi.fn().mockImplementation(async () => {
      return store.filter(
        (r) => r.backupPurgedAt !== null && r.confirmationSentAt === null,
      );
    }),
    findOverdueBackupPurges: vi.fn().mockImplementation(async () => {
      const now = new Date();
      return store.filter(
        (r) =>
          r.backupPurgedAt === null &&
          r.backupPurgeDeadline !== null &&
          new Date(r.backupPurgeDeadline) <= now,
      );
    }),
  };
}

function makeMockSpacesFileClient(): SpacesFileClient & { deleteProviderFiles: ReturnType<typeof vi.fn> } {
  return {
    deleteProviderFiles: vi.fn().mockResolvedValue({
      totalDeleted: 15,
      prefixes: { exports: 5, reports: 5, uploads: 5 },
    }),
  };
}

function makeServiceDeps(overrides?: {
  subscriptionRepo?: any;
  paymentRepo?: any;
  statusComponentRepo?: any;
  incidentRepo?: any;
  amendmentRepo?: any;
  breachRepo?: any;
  activeProviderRepo?: ActiveProviderRepo;
  userRepo?: UserRepo;
  stripe?: StripeClient;
  config?: Partial<PlatformServiceDeps['config']>;
  auditLogger?: AuditLogger;
  dataDeletionRepo?: DataDeletionRepo;
  destructionTrackingRepo?: ReturnType<typeof makeMockDestructionTrackingRepo>;
  spacesFileClient?: SpacesFileClient;
}): PlatformServiceDeps {
  return {
    subscriptionRepo: overrides?.subscriptionRepo ?? makeMockSubscriptionRepo(),
    paymentRepo: overrides?.paymentRepo ?? makeMockPaymentRepo(),
    statusComponentRepo: overrides?.statusComponentRepo ?? makeMockStatusComponentRepo(),
    incidentRepo: overrides?.incidentRepo ?? makeMockIncidentRepo(),
    amendmentRepo: overrides?.amendmentRepo,
    breachRepo: overrides?.breachRepo,
    activeProviderRepo: overrides?.activeProviderRepo,
    userRepo: overrides?.userRepo ?? makeMockUserRepo(),
    stripe: overrides?.stripe ?? makeMockStripe(),
    config: {
      stripePriceStandardMonthly: 'price_standard_monthly_test',
      stripePriceStandardAnnual: 'price_standard_annual_test',
      stripePriceEarlyBirdMonthly: 'price_early_bird_test',
      stripePriceEarlyBirdAnnual: 'price_early_bird_annual_test',
      stripePriceClinicMonthly: 'price_clinic_monthly_test',
      stripePriceClinicAnnual: 'price_clinic_annual_test',
      stripeWebhookSecret: 'whsec_test_secret',
      gstTaxRateId: 'txr_gst_test',
      ...overrides?.config,
    },
    auditLogger: overrides?.auditLogger,
    dataDeletionRepo: overrides?.dataDeletionRepo,
    destructionTrackingRepo: overrides?.destructionTrackingRepo,
    spacesFileClient: overrides?.spacesFileClient,
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
      updateSubscriptionStatus: vi.fn().mockResolvedValue(undefined),
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

  it('createCheckoutSession returns checkout URL for EARLY_BIRD_ANNUAL plan', async () => {
    const deps = makeServiceDeps();

    const result = await createCheckoutSession(
      deps,
      'user-123',
      'EARLY_BIRD_ANNUAL',
      'https://meritum.ca/success',
      'https://meritum.ca/cancel',
    );

    expect(result.checkout_url).toBe('https://checkout.stripe.com/session_abc');
    const sessionCall = (deps.stripe.checkout.sessions.create as any).mock.calls[0][0];
    expect(sessionCall.line_items[0].price).toBe('price_early_bird_annual_test');
  });

  it('createCheckoutSession rejects EARLY_BIRD_ANNUAL when combined early bird cap reached', async () => {
    const subRepo = makeMockSubscriptionRepo({ earlyBirdCount: 100 });
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });

    await expect(
      createCheckoutSession(
        deps,
        'user-123',
        'EARLY_BIRD_ANNUAL',
        'https://meritum.ca/success',
        'https://meritum.ca/cancel',
      ),
    ).rejects.toThrow('Early bird plan is sold out');
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

    // Verify 45-day grace period (IMA-001)
    const gracePeriodMs = metadata.deletion_scheduled_at.getTime() - metadata.cancelled_at.getTime();
    const fortyFiveDaysMs = 45 * 24 * 60 * 60 * 1000;
    expect(gracePeriodMs).toBe(fortyFiveDaysMs);

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

  it('runCancellationCheck schedules deletion 45 days out (IMA-001)', async () => {
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

    // Verify 45-day grace period (IMA-001)
    const gracePeriodMs = metadata.deletion_scheduled_at.getTime() - metadata.cancelled_at.getTime();
    const fortyFiveDaysMs = 45 * 24 * 60 * 60 * 1000;
    expect(gracePeriodMs).toBe(fortyFiveDaysMs);
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
// D17-010: Early bird rate lock on checkout completion
// ---------------------------------------------------------------------------

describe('Early bird rate lock (B2-2)', () => {
  it('sets early_bird_locked_until to created_at + 12 months on EARLY_BIRD_MONTHLY checkout', async () => {
    const subRepo = makeMockSubscriptionRepo();
    const auditLogger = makeMockAuditLogger();
    const deps = makeServiceDeps({ subscriptionRepo: subRepo, auditLogger });

    const event: StripeEvent = {
      id: 'evt_test_eb_monthly',
      type: 'checkout.session.completed',
      data: {
        object: {
          metadata: { meritum_user_id: 'user-eb-1', plan: 'EARLY_BIRD_MONTHLY' },
          customer: 'cus_eb_1',
          subscription: 'sub_eb_1',
        },
      },
    };

    await handleCheckoutCompleted(deps, event);

    expect(subRepo.createSubscription).toHaveBeenCalledOnce();
    expect(subRepo.updateSubscription).toHaveBeenCalledOnce();

    const updateCall = subRepo.updateSubscription.mock.calls[0];
    const lockedUntil = updateCall[1].earlyBirdLockedUntil;
    expect(lockedUntil).toBeInstanceOf(Date);

    // lockedUntil should be ~12 months from now
    const now = new Date();
    const expected = new Date(now);
    expected.setMonth(expected.getMonth() + 12);
    // Allow 5 seconds tolerance
    expect(Math.abs(lockedUntil.getTime() - expected.getTime())).toBeLessThan(5000);
  });

  it('sets early_bird_locked_until to created_at + 12 months on EARLY_BIRD_ANNUAL checkout', async () => {
    const subRepo = makeMockSubscriptionRepo();
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });

    const event: StripeEvent = {
      id: 'evt_test_eb_annual',
      type: 'checkout.session.completed',
      data: {
        object: {
          metadata: { meritum_user_id: 'user-eb-2', plan: 'EARLY_BIRD_ANNUAL' },
          customer: 'cus_eb_2',
          subscription: 'sub_eb_2',
        },
      },
    };

    await handleCheckoutCompleted(deps, event);

    expect(subRepo.updateSubscription).toHaveBeenCalledOnce();
    const updateCall = subRepo.updateSubscription.mock.calls[0];
    expect(updateCall[1].earlyBirdLockedUntil).toBeInstanceOf(Date);
  });

  it('does NOT set early_bird_locked_until for STANDARD_MONTHLY checkout', async () => {
    const subRepo = makeMockSubscriptionRepo();
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });

    const event: StripeEvent = {
      id: 'evt_test_std_monthly',
      type: 'checkout.session.completed',
      data: {
        object: {
          metadata: { meritum_user_id: 'user-std-1', plan: 'STANDARD_MONTHLY' },
          customer: 'cus_std_1',
          subscription: 'sub_std_1',
        },
      },
    };

    await handleCheckoutCompleted(deps, event);

    expect(subRepo.createSubscription).toHaveBeenCalledOnce();
    expect(subRepo.updateSubscription).not.toHaveBeenCalled();
  });

  it('does NOT set early_bird_locked_until for STANDARD_ANNUAL checkout', async () => {
    const subRepo = makeMockSubscriptionRepo();
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });

    const event: StripeEvent = {
      id: 'evt_test_std_annual',
      type: 'checkout.session.completed',
      data: {
        object: {
          metadata: { meritum_user_id: 'user-std-2', plan: 'STANDARD_ANNUAL' },
          customer: 'cus_std_2',
          subscription: 'sub_std_2',
        },
      },
    };

    await handleCheckoutCompleted(deps, event);

    expect(subRepo.updateSubscription).not.toHaveBeenCalled();
  });

  it('does NOT set early_bird_locked_until for CLINIC_MONTHLY checkout', async () => {
    const subRepo = makeMockSubscriptionRepo();
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });

    const event: StripeEvent = {
      id: 'evt_test_clinic_monthly',
      type: 'checkout.session.completed',
      data: {
        object: {
          metadata: { meritum_user_id: 'user-clinic-1', plan: 'CLINIC_MONTHLY' },
          customer: 'cus_clinic_1',
          subscription: 'sub_clinic_1',
        },
      },
    };

    await handleCheckoutCompleted(deps, event);

    expect(subRepo.updateSubscription).not.toHaveBeenCalled();
  });

  it('does NOT set early_bird_locked_until for CLINIC_ANNUAL checkout', async () => {
    const subRepo = makeMockSubscriptionRepo();
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });

    const event: StripeEvent = {
      id: 'evt_test_clinic_annual',
      type: 'checkout.session.completed',
      data: {
        object: {
          metadata: { meritum_user_id: 'user-clinic-2', plan: 'CLINIC_ANNUAL' },
          customer: 'cus_clinic_2',
          subscription: 'sub_clinic_2',
        },
      },
    };

    await handleCheckoutCompleted(deps, event);

    expect(subRepo.updateSubscription).not.toHaveBeenCalled();
  });

  it('leaves earlyBirdExpiryNotified as false after checkout', async () => {
    const subRepo = makeMockSubscriptionRepo();
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });

    const event: StripeEvent = {
      id: 'evt_test_eb_notified',
      type: 'checkout.session.completed',
      data: {
        object: {
          metadata: { meritum_user_id: 'user-eb-notified', plan: 'EARLY_BIRD_MONTHLY' },
          customer: 'cus_eb_notified',
          subscription: 'sub_eb_notified',
        },
      },
    };

    await handleCheckoutCompleted(deps, event);

    // The updateSubscription call should NOT set earlyBirdExpiryNotified
    const updateCall = subRepo.updateSubscription.mock.calls[0];
    expect(updateCall[1].earlyBirdExpiryNotified).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// D17-011: Early bird re-signup prevention
// ---------------------------------------------------------------------------

describe('Early bird re-signup prevention (B2-3)', () => {
  it('allows first-time early bird signup', async () => {
    const subRepo = makeMockSubscriptionRepo({ hasEverHadEarlyBird: false });
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });

    const result = await createCheckoutSession(
      deps,
      'user-first-eb',
      'EARLY_BIRD_MONTHLY',
      'https://meritum.ca/success',
      'https://meritum.ca/cancel',
    );

    expect(result.checkout_url).toBeDefined();
  });

  it('rejects early bird signup if user has an active early bird subscription', async () => {
    const subRepo = makeMockSubscriptionRepo({ hasEverHadEarlyBird: true });
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });

    await expect(
      createCheckoutSession(
        deps,
        'user-active-eb',
        'EARLY_BIRD_MONTHLY',
        'https://meritum.ca/success',
        'https://meritum.ca/cancel',
      ),
    ).rejects.toThrow('Early bird rate does not survive cancellation');
  });

  it('rejects early bird signup if user has a cancelled early bird subscription', async () => {
    const subRepo = makeMockSubscriptionRepo({ hasEverHadEarlyBird: true });
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });

    await expect(
      createCheckoutSession(
        deps,
        'user-cancelled-eb',
        'EARLY_BIRD_MONTHLY',
        'https://meritum.ca/success',
        'https://meritum.ca/cancel',
      ),
    ).rejects.toThrow('Early bird rate does not survive cancellation');
  });

  it('rejects early bird signup if user previously had EARLY_BIRD_MONTHLY and now requests EARLY_BIRD_ANNUAL', async () => {
    const subRepo = makeMockSubscriptionRepo({ hasEverHadEarlyBird: true });
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });

    await expect(
      createCheckoutSession(
        deps,
        'user-cross-eb',
        'EARLY_BIRD_ANNUAL',
        'https://meritum.ca/success',
        'https://meritum.ca/cancel',
      ),
    ).rejects.toThrow('Early bird rate does not survive cancellation');
  });

  it('rejects early bird signup if user previously had EARLY_BIRD_ANNUAL and now requests EARLY_BIRD_MONTHLY', async () => {
    const subRepo = makeMockSubscriptionRepo({ hasEverHadEarlyBird: true });
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });

    await expect(
      createCheckoutSession(
        deps,
        'user-cross-eb-2',
        'EARLY_BIRD_MONTHLY',
        'https://meritum.ca/success',
        'https://meritum.ca/cancel',
      ),
    ).rejects.toThrow('Early bird rate does not survive cancellation');
  });

  it('allows standard plan signup for user with prior early bird subscription', async () => {
    const subRepo = makeMockSubscriptionRepo({ hasEverHadEarlyBird: true });
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });

    const result = await createCheckoutSession(
      deps,
      'user-std-after-eb',
      'STANDARD_MONTHLY',
      'https://meritum.ca/success',
      'https://meritum.ca/cancel',
    );

    expect(result.checkout_url).toBeDefined();
  });

  it('allows clinic plan signup for user with prior early bird subscription', async () => {
    const subRepo = makeMockSubscriptionRepo({ hasEverHadEarlyBird: true });
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });

    const result = await createCheckoutSession(
      deps,
      'user-clinic-after-eb',
      'CLINIC_MONTHLY',
      'https://meritum.ca/success',
      'https://meritum.ca/cancel',
    );

    expect(result.checkout_url).toBeDefined();
  });

  it('returns EARLY_BIRD_INELIGIBLE error code', async () => {
    const subRepo = makeMockSubscriptionRepo({ hasEverHadEarlyBird: true });
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });

    try {
      await createCheckoutSession(
        deps,
        'user-code-check',
        'EARLY_BIRD_MONTHLY',
        'https://meritum.ca/success',
        'https://meritum.ca/cancel',
      );
      expect.unreachable('Should have thrown');
    } catch (err: any) {
      expect(err.details).toEqual({ code: 'EARLY_BIRD_INELIGIBLE' });
    }
  });

  it('does not decrement early bird cap on rejected re-signup attempt', async () => {
    const subRepo = makeMockSubscriptionRepo({ hasEverHadEarlyBird: true });
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });

    try {
      await createCheckoutSession(
        deps,
        'user-cap-check',
        'EARLY_BIRD_MONTHLY',
        'https://meritum.ca/success',
        'https://meritum.ca/cancel',
      );
    } catch {
      // expected
    }

    // The cap check (countEarlyBirdSubscriptions) should NOT have been called
    // because hasEverHadEarlyBird check runs first
    expect(subRepo.countEarlyBirdSubscriptions).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// D17-012: checkEarlyBirdExpiry scheduled job
// ---------------------------------------------------------------------------

describe('checkEarlyBirdExpiry (B2-2)', () => {
  describe('30-day warning', () => {
    it('emits EARLY_BIRD_EXPIRING for subscription expiring within 30 days', async () => {
      const subId = crypto.randomUUID();
      const providerId = crypto.randomUUID();
      const expiringSubData = {
        subscriptionId: subId,
        providerId,
        plan: 'EARLY_BIRD_MONTHLY',
        status: 'ACTIVE',
        earlyBirdLockedUntil: new Date(Date.now() + 15 * DAY_MS),
        earlyBirdExpiryNotified: false,
        stripeSubscriptionId: 'sub_expiring_1',
        stripeCustomerId: 'cus_expiring_1',
      };

      const subRepo = makeMockSubscriptionRepo({
        expiringEarlyBirdSubs: [expiringSubData],
      });
      const deps = makeServiceDeps({ subscriptionRepo: subRepo });
      const emitter = makeMockEventEmitter();

      await checkEarlyBirdExpiry(deps, emitter);

      expect(emitter.emit).toHaveBeenCalledWith(
        'EARLY_BIRD_EXPIRING',
        expect.objectContaining({
          subscriptionId: subId,
          providerId,
        }),
      );
    });

    it('sets early_bird_expiry_notified to true after warning', async () => {
      const subId = crypto.randomUUID();
      const subRepo = makeMockSubscriptionRepo({
        expiringEarlyBirdSubs: [{
          subscriptionId: subId,
          providerId: crypto.randomUUID(),
          plan: 'EARLY_BIRD_MONTHLY',
          status: 'ACTIVE',
          earlyBirdLockedUntil: new Date(Date.now() + 15 * DAY_MS),
          earlyBirdExpiryNotified: false,
          stripeSubscriptionId: 'sub_notified_1',
        }],
      });
      const deps = makeServiceDeps({ subscriptionRepo: subRepo });
      const emitter = makeMockEventEmitter();

      await checkEarlyBirdExpiry(deps, emitter);

      expect(subRepo.updateSubscription).toHaveBeenCalledWith(
        subId,
        { earlyBirdExpiryNotified: true },
      );
    });

    it('does NOT re-notify if early_bird_expiry_notified is already true', async () => {
      // findExpiringEarlyBirdSubscriptions already filters notified=false
      // So if notified=true, the sub won't be in the results
      const subRepo = makeMockSubscriptionRepo({
        expiringEarlyBirdSubs: [], // no results because all are already notified
      });
      const deps = makeServiceDeps({ subscriptionRepo: subRepo });
      const emitter = makeMockEventEmitter();

      await checkEarlyBirdExpiry(deps, emitter);

      expect(emitter.emit).not.toHaveBeenCalledWith(
        'EARLY_BIRD_EXPIRING',
        expect.anything(),
      );
    });

    it('does NOT warn for subscriptions expiring more than 30 days out', async () => {
      // These subs won't be returned by findExpiringEarlyBirdSubscriptions
      const subRepo = makeMockSubscriptionRepo({
        expiringEarlyBirdSubs: [],
      });
      const deps = makeServiceDeps({ subscriptionRepo: subRepo });
      const emitter = makeMockEventEmitter();

      await checkEarlyBirdExpiry(deps, emitter);

      expect(emitter.emit).not.toHaveBeenCalledWith(
        'EARLY_BIRD_EXPIRING',
        expect.anything(),
      );
    });

    it('does NOT warn for non-early-bird subscriptions', async () => {
      const subRepo = makeMockSubscriptionRepo({
        expiringEarlyBirdSubs: [],
      });
      const deps = makeServiceDeps({ subscriptionRepo: subRepo });
      const emitter = makeMockEventEmitter();

      await checkEarlyBirdExpiry(deps, emitter);

      expect(emitter.emit).not.toHaveBeenCalledWith(
        'EARLY_BIRD_EXPIRING',
        expect.anything(),
      );
    });

    it('does NOT warn for cancelled subscriptions', async () => {
      const subRepo = makeMockSubscriptionRepo({
        expiringEarlyBirdSubs: [],
      });
      const deps = makeServiceDeps({ subscriptionRepo: subRepo });
      const emitter = makeMockEventEmitter();

      await checkEarlyBirdExpiry(deps, emitter);

      expect(emitter.emit).not.toHaveBeenCalledWith(
        'EARLY_BIRD_EXPIRING',
        expect.anything(),
      );
    });
  });

  describe('Expiry transition - physician in practice (Path A)', () => {
    const practiceId = crypto.randomUUID();
    const membershipId = crypto.randomUUID();
    const providerId = crypto.randomUUID();
    const subId = crypto.randomUUID();

    function makePathADeps() {
      const expiredSub = {
        subscriptionId: subId,
        providerId,
        plan: 'EARLY_BIRD_MONTHLY',
        status: 'ACTIVE',
        earlyBirdLockedUntil: new Date(Date.now() - DAY_MS),
        earlyBirdExpiryNotified: true,
        stripeSubscriptionId: 'sub_expired_a',
        stripeCustomerId: 'cus_expired_a',
      };

      const subRepo = makeMockSubscriptionRepo({
        expiredEarlyBirdSubs: [expiredSub],
        activePracticeMembership: {
          membershipId,
          practiceId,
          billingMode: 'INDIVIDUAL_EARLY_BIRD',
          physicianUserId: providerId,
        },
        earlyBirdMembersInPractice: [], // after transition, no more early bird
      });

      const auditLogger = makeMockAuditLogger();
      const stripe = makeMockStripe();
      const deps = makeServiceDeps({ subscriptionRepo: subRepo, auditLogger, stripe });

      return { deps, subRepo, auditLogger, stripe };
    }

    it('cancels individual early bird Stripe subscription', async () => {
      const { deps, stripe } = makePathADeps();
      const emitter = makeMockEventEmitter();

      await checkEarlyBirdExpiry(deps, emitter);

      expect(stripe.subscriptions.cancel).toHaveBeenCalledWith('sub_expired_a');
    });

    it('transitions membership billing_mode to PRACTICE_CONSOLIDATED', async () => {
      const { deps, subRepo } = makePathADeps();
      const emitter = makeMockEventEmitter();

      await checkEarlyBirdExpiry(deps, emitter);

      expect(subRepo.updatePracticeMembershipBillingMode).toHaveBeenCalledWith(
        membershipId,
        'PRACTICE_CONSOLIDATED',
      );
    });

    it('emits EARLY_BIRD_EXPIRED to physician', async () => {
      const { deps } = makePathADeps();
      const emitter = makeMockEventEmitter();

      await checkEarlyBirdExpiry(deps, emitter);

      expect(emitter.emit).toHaveBeenCalledWith(
        'EARLY_BIRD_EXPIRED',
        expect.objectContaining({
          subscriptionId: subId,
          providerId,
          path: 'A',
          transitionedTo: 'PRACTICE_CONSOLIDATED',
        }),
      );
    });

    it('emits PRACTICE_MEMBER_TRANSITIONED to practice admin', async () => {
      const { deps } = makePathADeps();
      const emitter = makeMockEventEmitter();

      await checkEarlyBirdExpiry(deps, emitter);

      expect(emitter.emit).toHaveBeenCalledWith(
        'PRACTICE_MEMBER_TRANSITIONED',
        expect.objectContaining({
          practiceId,
          providerId,
        }),
      );
    });

    it('audit logs the transition', async () => {
      const { deps, auditLogger } = makePathADeps();
      const emitter = makeMockEventEmitter();

      await checkEarlyBirdExpiry(deps, emitter);

      expect(auditLogger.log).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'EARLY_BIRD_EXPIRED_PATH_A',
          resourceType: 'subscription',
          resourceId: subId,
        }),
      );
    });
  });

  describe('Expiry transition - physician NOT in practice (Path B)', () => {
    it('transitions EARLY_BIRD_MONTHLY to STANDARD_MONTHLY via Stripe price change', async () => {
      const subId = crypto.randomUUID();
      const expiredSub = {
        subscriptionId: subId,
        providerId: crypto.randomUUID(),
        plan: 'EARLY_BIRD_MONTHLY',
        status: 'ACTIVE',
        earlyBirdLockedUntil: new Date(Date.now() - DAY_MS),
        earlyBirdExpiryNotified: true,
        stripeSubscriptionId: 'sub_expired_b_monthly',
        stripeCustomerId: 'cus_expired_b',
      };

      const subRepo = makeMockSubscriptionRepo({
        expiredEarlyBirdSubs: [expiredSub],
        activePracticeMembership: null,
      });
      const stripe = makeMockStripe();
      const deps = makeServiceDeps({ subscriptionRepo: subRepo, stripe });
      const emitter = makeMockEventEmitter();

      await checkEarlyBirdExpiry(deps, emitter);

      expect(stripe.subscriptions.update).toHaveBeenCalledWith(
        'sub_expired_b_monthly',
        expect.objectContaining({
          items: [{ price: 'price_standard_monthly_test' }],
        }),
      );
    });

    it('transitions EARLY_BIRD_ANNUAL to STANDARD_ANNUAL via Stripe price change', async () => {
      const subId = crypto.randomUUID();
      const expiredSub = {
        subscriptionId: subId,
        providerId: crypto.randomUUID(),
        plan: 'EARLY_BIRD_ANNUAL',
        status: 'ACTIVE',
        earlyBirdLockedUntil: new Date(Date.now() - DAY_MS),
        earlyBirdExpiryNotified: true,
        stripeSubscriptionId: 'sub_expired_b_annual',
        stripeCustomerId: 'cus_expired_b_annual',
      };

      const subRepo = makeMockSubscriptionRepo({
        expiredEarlyBirdSubs: [expiredSub],
        activePracticeMembership: null,
      });
      const stripe = makeMockStripe();
      const deps = makeServiceDeps({ subscriptionRepo: subRepo, stripe });
      const emitter = makeMockEventEmitter();

      await checkEarlyBirdExpiry(deps, emitter);

      expect(stripe.subscriptions.update).toHaveBeenCalledWith(
        'sub_expired_b_annual',
        expect.objectContaining({
          items: [{ price: 'price_standard_annual_test' }],
        }),
      );
    });

    it('updates subscription plan column to new plan', async () => {
      const subId = crypto.randomUUID();
      const expiredSub = {
        subscriptionId: subId,
        providerId: crypto.randomUUID(),
        plan: 'EARLY_BIRD_MONTHLY',
        status: 'ACTIVE',
        earlyBirdLockedUntil: new Date(Date.now() - DAY_MS),
        earlyBirdExpiryNotified: true,
        stripeSubscriptionId: 'sub_expired_plan_update',
        stripeCustomerId: 'cus_expired_plan',
      };

      const subRepo = makeMockSubscriptionRepo({
        expiredEarlyBirdSubs: [expiredSub],
        activePracticeMembership: null,
      });
      const deps = makeServiceDeps({ subscriptionRepo: subRepo });
      const emitter = makeMockEventEmitter();

      await checkEarlyBirdExpiry(deps, emitter);

      expect(subRepo.updateSubscription).toHaveBeenCalledWith(
        subId,
        expect.objectContaining({
          plan: 'STANDARD_MONTHLY',
          earlyBirdLockedUntil: null,
        }),
      );
    });

    it('clears early_bird_locked_until after transition', async () => {
      const subId = crypto.randomUUID();
      const expiredSub = {
        subscriptionId: subId,
        providerId: crypto.randomUUID(),
        plan: 'EARLY_BIRD_ANNUAL',
        status: 'ACTIVE',
        earlyBirdLockedUntil: new Date(Date.now() - DAY_MS),
        earlyBirdExpiryNotified: true,
        stripeSubscriptionId: 'sub_expired_clear_lock',
        stripeCustomerId: 'cus_expired_clear',
      };

      const subRepo = makeMockSubscriptionRepo({
        expiredEarlyBirdSubs: [expiredSub],
        activePracticeMembership: null,
      });
      const deps = makeServiceDeps({ subscriptionRepo: subRepo });
      const emitter = makeMockEventEmitter();

      await checkEarlyBirdExpiry(deps, emitter);

      expect(subRepo.updateSubscription).toHaveBeenCalledWith(
        subId,
        expect.objectContaining({
          earlyBirdLockedUntil: null,
        }),
      );
    });

    it('emits EARLY_BIRD_EXPIRED notification with new rate', async () => {
      const subId = crypto.randomUUID();
      const providerId = crypto.randomUUID();
      const expiredSub = {
        subscriptionId: subId,
        providerId,
        plan: 'EARLY_BIRD_MONTHLY',
        status: 'ACTIVE',
        earlyBirdLockedUntil: new Date(Date.now() - DAY_MS),
        earlyBirdExpiryNotified: true,
        stripeSubscriptionId: 'sub_expired_notify',
        stripeCustomerId: 'cus_expired_notify',
      };

      const subRepo = makeMockSubscriptionRepo({
        expiredEarlyBirdSubs: [expiredSub],
        activePracticeMembership: null,
      });
      const deps = makeServiceDeps({ subscriptionRepo: subRepo });
      const emitter = makeMockEventEmitter();

      await checkEarlyBirdExpiry(deps, emitter);

      expect(emitter.emit).toHaveBeenCalledWith(
        'EARLY_BIRD_EXPIRED',
        expect.objectContaining({
          subscriptionId: subId,
          providerId,
          path: 'B',
          transitionedTo: 'STANDARD_MONTHLY',
        }),
      );
    });

    it('audit logs the transition', async () => {
      const subId = crypto.randomUUID();
      const expiredSub = {
        subscriptionId: subId,
        providerId: crypto.randomUUID(),
        plan: 'EARLY_BIRD_MONTHLY',
        status: 'ACTIVE',
        earlyBirdLockedUntil: new Date(Date.now() - DAY_MS),
        earlyBirdExpiryNotified: true,
        stripeSubscriptionId: 'sub_expired_audit',
        stripeCustomerId: 'cus_expired_audit',
      };

      const subRepo = makeMockSubscriptionRepo({
        expiredEarlyBirdSubs: [expiredSub],
        activePracticeMembership: null,
      });
      const auditLogger = makeMockAuditLogger();
      const deps = makeServiceDeps({ subscriptionRepo: subRepo, auditLogger });
      const emitter = makeMockEventEmitter();

      await checkEarlyBirdExpiry(deps, emitter);

      expect(auditLogger.log).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'EARLY_BIRD_EXPIRED_PATH_B',
          resourceType: 'subscription',
          resourceId: subId,
        }),
      );
    });
  });

  describe('Edge cases', () => {
    it('does not process already-cancelled subscriptions', async () => {
      // findExpiredEarlyBirdSubscriptions filters by status=ACTIVE
      const subRepo = makeMockSubscriptionRepo({
        expiredEarlyBirdSubs: [],
      });
      const deps = makeServiceDeps({ subscriptionRepo: subRepo });
      const emitter = makeMockEventEmitter();

      const result = await checkEarlyBirdExpiry(deps, emitter);

      expect(result.transitioned).toBe(0);
    });

    it('handles concurrent expiries for multiple physicians in same practice', async () => {
      const practiceId = crypto.randomUUID();
      const sub1 = {
        subscriptionId: crypto.randomUUID(),
        providerId: crypto.randomUUID(),
        plan: 'EARLY_BIRD_MONTHLY',
        status: 'ACTIVE',
        earlyBirdLockedUntil: new Date(Date.now() - DAY_MS),
        earlyBirdExpiryNotified: true,
        stripeSubscriptionId: 'sub_concurrent_1',
        stripeCustomerId: 'cus_concurrent_1',
      };
      const sub2 = {
        subscriptionId: crypto.randomUUID(),
        providerId: crypto.randomUUID(),
        plan: 'EARLY_BIRD_ANNUAL',
        status: 'ACTIVE',
        earlyBirdLockedUntil: new Date(Date.now() - DAY_MS),
        earlyBirdExpiryNotified: true,
        stripeSubscriptionId: 'sub_concurrent_2',
        stripeCustomerId: 'cus_concurrent_2',
      };

      const subRepo = makeMockSubscriptionRepo({
        expiredEarlyBirdSubs: [sub1, sub2],
      });

      // Mock getActivePracticeMembership to return membership for both
      let callCount = 0;
      subRepo.getActivePracticeMembership.mockImplementation(async (userId: string) => ({
        membershipId: crypto.randomUUID(),
        practiceId,
        billingMode: 'INDIVIDUAL_EARLY_BIRD',
        physicianUserId: userId,
      }));

      subRepo.getEarlyBirdMembersInPractice.mockResolvedValue([]);

      const stripe = makeMockStripe();
      const deps = makeServiceDeps({ subscriptionRepo: subRepo, stripe });
      const emitter = makeMockEventEmitter();

      const result = await checkEarlyBirdExpiry(deps, emitter);

      expect(result.transitioned).toBe(2);
      expect(stripe.subscriptions.cancel).toHaveBeenCalledTimes(2);
    });

    it('handles expiry when practice has exactly 5 members (no dissolution risk)', async () => {
      const subId = crypto.randomUUID();
      const expiredSub = {
        subscriptionId: subId,
        providerId: crypto.randomUUID(),
        plan: 'EARLY_BIRD_MONTHLY',
        status: 'ACTIVE',
        earlyBirdLockedUntil: new Date(Date.now() - DAY_MS),
        earlyBirdExpiryNotified: true,
        stripeSubscriptionId: 'sub_five_members',
        stripeCustomerId: 'cus_five_members',
      };

      const subRepo = makeMockSubscriptionRepo({
        expiredEarlyBirdSubs: [expiredSub],
        activePracticeMembership: {
          membershipId: crypto.randomUUID(),
          practiceId: crypto.randomUUID(),
          billingMode: 'INDIVIDUAL_EARLY_BIRD',
          physicianUserId: expiredSub.providerId,
        },
        earlyBirdMembersInPractice: [],
      });

      const deps = makeServiceDeps({ subscriptionRepo: subRepo });
      const emitter = makeMockEventEmitter();

      const result = await checkEarlyBirdExpiry(deps, emitter);

      expect(result.transitioned).toBe(1);
    });
  });
});

// ---------------------------------------------------------------------------
// D17-014: Proactive transition notifications
// ---------------------------------------------------------------------------

describe('Proactive transition notifications (B2-5)', () => {
  describe('First physician approaching expiry', () => {
    it('notifies practice admin when first member early bird is expiring within 30 days', async () => {
      const practiceId = crypto.randomUUID();
      const providerId = crypto.randomUUID();

      const subRepo = makeMockSubscriptionRepo({
        expiringEarlyBirdSubs: [{
          subscriptionId: crypto.randomUUID(),
          providerId,
          plan: 'EARLY_BIRD_MONTHLY',
          status: 'ACTIVE',
          earlyBirdLockedUntil: new Date(Date.now() + 15 * DAY_MS),
          earlyBirdExpiryNotified: false,
          stripeSubscriptionId: 'sub_first_expiry',
        }],
        activePracticeMembership: {
          membershipId: crypto.randomUUID(),
          practiceId,
          billingMode: 'INDIVIDUAL_EARLY_BIRD',
          physicianUserId: providerId,
        },
        earlyBirdMembersInPractice: [
          { physicianUserId: providerId, earlyBirdExpiryNotified: false },
        ],
      });

      const deps = makeServiceDeps({ subscriptionRepo: subRepo });
      const emitter = makeMockEventEmitter();

      await checkEarlyBirdExpiry(deps, emitter);

      expect(emitter.emit).toHaveBeenCalledWith(
        'PRACTICE_EARLY_BIRD_TRANSITION_STARTING',
        expect.objectContaining({
          practiceId,
        }),
      );
    });

    it('does NOT notify practice admin again when second member early bird expires', async () => {
      const practiceId = crypto.randomUUID();
      const providerId = crypto.randomUUID();
      const otherProviderId = crypto.randomUUID();

      const subRepo = makeMockSubscriptionRepo({
        expiringEarlyBirdSubs: [{
          subscriptionId: crypto.randomUUID(),
          providerId,
          plan: 'EARLY_BIRD_MONTHLY',
          status: 'ACTIVE',
          earlyBirdLockedUntil: new Date(Date.now() + 15 * DAY_MS),
          earlyBirdExpiryNotified: false,
          stripeSubscriptionId: 'sub_second_expiry',
        }],
        activePracticeMembership: {
          membershipId: crypto.randomUUID(),
          practiceId,
          billingMode: 'INDIVIDUAL_EARLY_BIRD',
          physicianUserId: providerId,
        },
        earlyBirdMembersInPractice: [
          { physicianUserId: providerId, earlyBirdExpiryNotified: false },
          { physicianUserId: otherProviderId, earlyBirdExpiryNotified: true }, // already notified
        ],
      });

      const deps = makeServiceDeps({ subscriptionRepo: subRepo });
      const emitter = makeMockEventEmitter();

      await checkEarlyBirdExpiry(deps, emitter);

      // Should NOT emit PRACTICE_EARLY_BIRD_TRANSITION_STARTING because another member was already notified
      expect(emitter.emit).not.toHaveBeenCalledWith(
        'PRACTICE_EARLY_BIRD_TRANSITION_STARTING',
        expect.anything(),
      );
    });

    it('notification does NOT include physician name or billing amount', async () => {
      const practiceId = crypto.randomUUID();
      const providerId = crypto.randomUUID();

      const subRepo = makeMockSubscriptionRepo({
        expiringEarlyBirdSubs: [{
          subscriptionId: crypto.randomUUID(),
          providerId,
          plan: 'EARLY_BIRD_MONTHLY',
          status: 'ACTIVE',
          earlyBirdLockedUntil: new Date(Date.now() + 15 * DAY_MS),
          earlyBirdExpiryNotified: false,
          stripeSubscriptionId: 'sub_privacy_check',
        }],
        activePracticeMembership: {
          membershipId: crypto.randomUUID(),
          practiceId,
          billingMode: 'INDIVIDUAL_EARLY_BIRD',
          physicianUserId: providerId,
        },
        earlyBirdMembersInPractice: [
          { physicianUserId: providerId, earlyBirdExpiryNotified: false },
        ],
      });

      const deps = makeServiceDeps({ subscriptionRepo: subRepo });
      const emitter = makeMockEventEmitter();

      await checkEarlyBirdExpiry(deps, emitter);

      const emitCalls = (emitter.emit as any).mock.calls;
      const transitionCall = emitCalls.find((c: any) => c[0] === 'PRACTICE_EARLY_BIRD_TRANSITION_STARTING');
      expect(transitionCall).toBeDefined();

      const notificationData = transitionCall[1];
      // Should not include providerId, physician name, or billing amount in the admin notification
      expect(notificationData.providerId).toBeUndefined();
      expect(notificationData.physicianName).toBeUndefined();
      expect(notificationData.billingAmount).toBeUndefined();
    });

    it('does NOT send notification if physician is not in a practice', async () => {
      const subRepo = makeMockSubscriptionRepo({
        expiringEarlyBirdSubs: [{
          subscriptionId: crypto.randomUUID(),
          providerId: crypto.randomUUID(),
          plan: 'EARLY_BIRD_MONTHLY',
          status: 'ACTIVE',
          earlyBirdLockedUntil: new Date(Date.now() + 15 * DAY_MS),
          earlyBirdExpiryNotified: false,
          stripeSubscriptionId: 'sub_no_practice',
        }],
        activePracticeMembership: null,
      });

      const deps = makeServiceDeps({ subscriptionRepo: subRepo });
      const emitter = makeMockEventEmitter();

      await checkEarlyBirdExpiry(deps, emitter);

      expect(emitter.emit).not.toHaveBeenCalledWith(
        'PRACTICE_EARLY_BIRD_TRANSITION_STARTING',
        expect.anything(),
      );
    });
  });

  describe('All members post-early-bird', () => {
    it('notifies practice admin when last early bird member transitions', async () => {
      const practiceId = crypto.randomUUID();
      const providerId = crypto.randomUUID();

      const subRepo = makeMockSubscriptionRepo({
        expiredEarlyBirdSubs: [{
          subscriptionId: crypto.randomUUID(),
          providerId,
          plan: 'EARLY_BIRD_MONTHLY',
          status: 'ACTIVE',
          earlyBirdLockedUntil: new Date(Date.now() - DAY_MS),
          earlyBirdExpiryNotified: true,
          stripeSubscriptionId: 'sub_last_eb',
          stripeCustomerId: 'cus_last_eb',
        }],
        activePracticeMembership: {
          membershipId: crypto.randomUUID(),
          practiceId,
          billingMode: 'INDIVIDUAL_EARLY_BIRD',
          physicianUserId: providerId,
        },
        earlyBirdMembersInPractice: [], // after transition, no more early bird
      });

      const deps = makeServiceDeps({ subscriptionRepo: subRepo });
      const emitter = makeMockEventEmitter();

      await checkEarlyBirdExpiry(deps, emitter);

      expect(emitter.emit).toHaveBeenCalledWith(
        'PRACTICE_ALL_MEMBERS_POST_EARLY_BIRD',
        expect.objectContaining({
          practiceId,
        }),
      );
    });

    it('does NOT notify when some members are still on early bird', async () => {
      const practiceId = crypto.randomUUID();
      const providerId = crypto.randomUUID();

      const subRepo = makeMockSubscriptionRepo({
        expiredEarlyBirdSubs: [{
          subscriptionId: crypto.randomUUID(),
          providerId,
          plan: 'EARLY_BIRD_MONTHLY',
          status: 'ACTIVE',
          earlyBirdLockedUntil: new Date(Date.now() - DAY_MS),
          earlyBirdExpiryNotified: true,
          stripeSubscriptionId: 'sub_still_eb',
          stripeCustomerId: 'cus_still_eb',
        }],
        activePracticeMembership: {
          membershipId: crypto.randomUUID(),
          practiceId,
          billingMode: 'INDIVIDUAL_EARLY_BIRD',
          physicianUserId: providerId,
        },
        earlyBirdMembersInPractice: [
          { physicianUserId: crypto.randomUUID(), earlyBirdExpiryNotified: false },
        ], // still has an early bird member
      });

      const deps = makeServiceDeps({ subscriptionRepo: subRepo });
      const emitter = makeMockEventEmitter();

      await checkEarlyBirdExpiry(deps, emitter);

      expect(emitter.emit).not.toHaveBeenCalledWith(
        'PRACTICE_ALL_MEMBERS_POST_EARLY_BIRD',
        expect.anything(),
      );
    });

    it('does NOT send notification for single-physician practices', async () => {
      // If a physician is not in a practice, Path B applies - no practice admin notification
      const subRepo = makeMockSubscriptionRepo({
        expiredEarlyBirdSubs: [{
          subscriptionId: crypto.randomUUID(),
          providerId: crypto.randomUUID(),
          plan: 'EARLY_BIRD_MONTHLY',
          status: 'ACTIVE',
          earlyBirdLockedUntil: new Date(Date.now() - DAY_MS),
          earlyBirdExpiryNotified: true,
          stripeSubscriptionId: 'sub_single',
          stripeCustomerId: 'cus_single',
        }],
        activePracticeMembership: null,
      });

      const deps = makeServiceDeps({ subscriptionRepo: subRepo });
      const emitter = makeMockEventEmitter();

      await checkEarlyBirdExpiry(deps, emitter);

      expect(emitter.emit).not.toHaveBeenCalledWith(
        'PRACTICE_ALL_MEMBERS_POST_EARLY_BIRD',
        expect.anything(),
      );
    });
  });

  describe('Edge cases', () => {
    it('handles practice with all members expiring on same day', async () => {
      const practiceId = crypto.randomUUID();
      const sub1 = {
        subscriptionId: crypto.randomUUID(),
        providerId: crypto.randomUUID(),
        plan: 'EARLY_BIRD_MONTHLY',
        status: 'ACTIVE',
        earlyBirdLockedUntil: new Date(Date.now() - DAY_MS),
        earlyBirdExpiryNotified: true,
        stripeSubscriptionId: 'sub_same_day_1',
        stripeCustomerId: 'cus_same_day_1',
      };
      const sub2 = {
        subscriptionId: crypto.randomUUID(),
        providerId: crypto.randomUUID(),
        plan: 'EARLY_BIRD_MONTHLY',
        status: 'ACTIVE',
        earlyBirdLockedUntil: new Date(Date.now() - DAY_MS),
        earlyBirdExpiryNotified: true,
        stripeSubscriptionId: 'sub_same_day_2',
        stripeCustomerId: 'cus_same_day_2',
      };

      const subRepo = makeMockSubscriptionRepo({
        expiredEarlyBirdSubs: [sub1, sub2],
      });

      subRepo.getActivePracticeMembership.mockImplementation(async (userId: string) => ({
        membershipId: crypto.randomUUID(),
        practiceId,
        billingMode: 'INDIVIDUAL_EARLY_BIRD',
        physicianUserId: userId,
      }));

      // After first transition, one remains; after second, none remain
      let ebCallCount = 0;
      subRepo.getEarlyBirdMembersInPractice.mockImplementation(async () => {
        ebCallCount++;
        if (ebCallCount === 1) {
          return [{ physicianUserId: sub2.providerId, earlyBirdExpiryNotified: true }];
        }
        return [];
      });

      const deps = makeServiceDeps({ subscriptionRepo: subRepo });
      const emitter = makeMockEventEmitter();

      const result = await checkEarlyBirdExpiry(deps, emitter);

      expect(result.transitioned).toBe(2);
      // Should emit PRACTICE_ALL_MEMBERS_POST_EARLY_BIRD only after the last one
      const allPostEBCalls = (emitter.emit as any).mock.calls.filter(
        (c: any) => c[0] === 'PRACTICE_ALL_MEMBERS_POST_EARLY_BIRD',
      );
      expect(allPostEBCalls).toHaveLength(1);
    });

    it('handles practice where admin is the early bird physician', async () => {
      const practiceId = crypto.randomUUID();
      const adminId = crypto.randomUUID();

      const subRepo = makeMockSubscriptionRepo({
        expiredEarlyBirdSubs: [{
          subscriptionId: crypto.randomUUID(),
          providerId: adminId,
          plan: 'EARLY_BIRD_MONTHLY',
          status: 'ACTIVE',
          earlyBirdLockedUntil: new Date(Date.now() - DAY_MS),
          earlyBirdExpiryNotified: true,
          stripeSubscriptionId: 'sub_admin_eb',
          stripeCustomerId: 'cus_admin_eb',
        }],
        activePracticeMembership: {
          membershipId: crypto.randomUUID(),
          practiceId,
          billingMode: 'INDIVIDUAL_EARLY_BIRD',
          physicianUserId: adminId,
        },
        earlyBirdMembersInPractice: [],
      });

      const deps = makeServiceDeps({ subscriptionRepo: subRepo });
      const emitter = makeMockEventEmitter();

      const result = await checkEarlyBirdExpiry(deps, emitter);

      expect(result.transitioned).toBe(1);
      // Should still transition the admin physician
      expect(emitter.emit).toHaveBeenCalledWith(
        'EARLY_BIRD_EXPIRED',
        expect.objectContaining({ path: 'A' }),
      );
    });
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

// ---------------------------------------------------------------------------
// IMA-012: Export Window Notification Tests
// ---------------------------------------------------------------------------

describe('IMA-012 — Export Window Notifications', () => {
  // -----------------------------------------------------------------------
  // EXPORT_WINDOW_STARTED — emitted on cancellation
  // -----------------------------------------------------------------------

  it('cancellation emits EXPORT_WINDOW_STARTED notification', async () => {
    const suspendedSub = {
      subscriptionId: 'sub-export-start',
      providerId: 'user-export-start',
      stripeSubscriptionId: 'sub_stripe_es',
      stripeCustomerId: 'cus_es',
      status: 'SUSPENDED',
      suspendedAt: new Date(Date.now() - 17 * 24 * 60 * 60 * 1000),
      failedPaymentCount: 3,
    };

    const subRepo = makeMockSubscriptionRepo();
    subRepo.findSubscriptionsDueForCancellation = vi.fn().mockResolvedValue([suspendedSub]);
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });
    const emitter = makeMockEventEmitter();

    await runCancellationCheck(deps, emitter);

    expect(emitter.emit).toHaveBeenCalledWith(
      'EXPORT_WINDOW_STARTED',
      expect.objectContaining({
        subscriptionId: 'sub-export-start',
        providerId: 'user-export-start',
        exportWindowDays: 45,
      }),
    );
  });

  it('handleSubscriptionDeleted emits EXPORT_WINDOW_STARTED notification', async () => {
    const existingSub = {
      subscriptionId: 'sub-hsd-export',
      providerId: 'user-hsd-export',
      stripeSubscriptionId: 'sub_stripe_hsd',
      stripeCustomerId: 'cus_hsd',
      status: 'ACTIVE',
    };

    const subRepo = makeMockSubscriptionRepo({ subscriptionByStripeId: existingSub });
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });
    const emitter = makeMockEventEmitter();

    const event: StripeEvent = {
      id: 'evt_hsd_export',
      type: 'customer.subscription.deleted',
      data: {
        object: {
          id: 'sub_stripe_hsd',
        },
      },
    };

    await handleSubscriptionDeleted(deps, event, emitter);

    expect(emitter.emit).toHaveBeenCalledWith(
      'EXPORT_WINDOW_STARTED',
      expect.objectContaining({
        subscriptionId: 'sub-hsd-export',
        providerId: 'user-hsd-export',
        exportWindowDays: 45,
      }),
    );
  });

  it('export window uses 45-day period, not 30', async () => {
    const suspendedSub = {
      subscriptionId: 'sub-45-days',
      providerId: 'user-45-days',
      stripeSubscriptionId: 'sub_stripe_45d',
      stripeCustomerId: 'cus_45d',
      status: 'SUSPENDED',
      suspendedAt: new Date(Date.now() - 17 * 24 * 60 * 60 * 1000),
      failedPaymentCount: 3,
    };

    const subRepo = makeMockSubscriptionRepo();
    subRepo.findSubscriptionsDueForCancellation = vi.fn().mockResolvedValue([suspendedSub]);
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });
    const emitter = makeMockEventEmitter();

    const beforeCall = new Date();
    await runCancellationCheck(deps, emitter);

    // Verify the deletion_scheduled_at is ~45 days from now
    const updateCall = subRepo.updateSubscriptionStatus.mock.calls[0];
    const metadata = updateCall[2];
    const deletionDate = metadata.deletion_scheduled_at;
    const daysDiff = Math.round((deletionDate.getTime() - beforeCall.getTime()) / (24 * 60 * 60 * 1000));
    expect(daysDiff).toBe(45);
  });

  // -----------------------------------------------------------------------
  // EXPORT_WINDOW_REMINDER — emitted at 15 days remaining
  // -----------------------------------------------------------------------

  it('export window reminder emitted at 15 days remaining', async () => {
    const DAY_MS = 24 * 60 * 60 * 1000;
    const cancelledSub = {
      subscriptionId: 'sub-reminder-15',
      providerId: 'user-reminder-15',
      status: 'CANCELLED',
      deletionScheduledAt: new Date(Date.now() + 15 * DAY_MS),
    };

    const subRepo = makeMockSubscriptionRepo({
      cancelledSubsInExportWindow: [cancelledSub],
    });
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });
    const emitter = makeMockEventEmitter();

    const result = await runExportWindowReminders(deps, emitter);

    expect(result.reminded).toBe(1);
    expect(emitter.emit).toHaveBeenCalledWith(
      'EXPORT_WINDOW_REMINDER',
      expect.objectContaining({
        subscriptionId: 'sub-reminder-15',
        providerId: 'user-reminder-15',
        daysRemaining: 15,
      }),
    );
  });

  // -----------------------------------------------------------------------
  // EXPORT_WINDOW_CLOSING — emitted at 7 days remaining
  // -----------------------------------------------------------------------

  it('export window closing emitted at 7 days remaining', async () => {
    const DAY_MS = 24 * 60 * 60 * 1000;
    const cancelledSub = {
      subscriptionId: 'sub-closing-7',
      providerId: 'user-closing-7',
      status: 'CANCELLED',
      deletionScheduledAt: new Date(Date.now() + 7 * DAY_MS),
    };

    const subRepo = makeMockSubscriptionRepo({
      cancelledSubsInExportWindow: [cancelledSub],
    });
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });
    const emitter = makeMockEventEmitter();

    const result = await runExportWindowReminders(deps, emitter);

    expect(result.reminded).toBe(1);
    expect(emitter.emit).toHaveBeenCalledWith(
      'EXPORT_WINDOW_CLOSING',
      expect.objectContaining({
        subscriptionId: 'sub-closing-7',
        providerId: 'user-closing-7',
        daysRemaining: 7,
      }),
    );
  });

  // -----------------------------------------------------------------------
  // EXPORT_WINDOW_CLOSING — emitted at 1 day remaining (final warning)
  // -----------------------------------------------------------------------

  it('export window closing emitted at 1 day remaining (final warning)', async () => {
    const DAY_MS = 24 * 60 * 60 * 1000;
    const cancelledSub = {
      subscriptionId: 'sub-closing-1',
      providerId: 'user-closing-1',
      status: 'CANCELLED',
      deletionScheduledAt: new Date(Date.now() + 1 * DAY_MS),
    };

    const subRepo = makeMockSubscriptionRepo({
      cancelledSubsInExportWindow: [cancelledSub],
    });
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });
    const emitter = makeMockEventEmitter();

    const result = await runExportWindowReminders(deps, emitter);

    expect(result.reminded).toBe(1);
    expect(emitter.emit).toHaveBeenCalledWith(
      'EXPORT_WINDOW_CLOSING',
      expect.objectContaining({
        subscriptionId: 'sub-closing-1',
        providerId: 'user-closing-1',
        daysRemaining: 1,
      }),
    );
  });

  // -----------------------------------------------------------------------
  // EXPORT_WINDOW_CLOSED — emitted when deletion begins
  // -----------------------------------------------------------------------

  it('EXPORT_WINDOW_CLOSED emitted when deletion begins', async () => {
    const cancelledSub = {
      subscriptionId: 'sub-window-closed',
      providerId: 'user-window-closed',
      stripeCustomerId: 'cus_wc',
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
      'EXPORT_WINDOW_CLOSED',
      expect.objectContaining({
        subscriptionId: 'sub-window-closed',
        providerId: 'user-window-closed',
      }),
    );
    // Verify EXPORT_WINDOW_CLOSED was emitted before ACCOUNT_DATA_DELETED
    const emitCalls = vi.mocked(emitter.emit).mock.calls;
    const closedIdx = emitCalls.findIndex((c: any) => c[0] === 'EXPORT_WINDOW_CLOSED');
    const deletedIdx = emitCalls.findIndex((c: any) => c[0] === 'ACCOUNT_DATA_DELETED');
    expect(closedIdx).toBeLessThan(deletedIdx);
  });

  // -----------------------------------------------------------------------
  // No reminder for subscriptions not at a checkpoint
  // -----------------------------------------------------------------------

  it('no reminder emitted when days remaining does not match a checkpoint', async () => {
    const DAY_MS = 24 * 60 * 60 * 1000;
    const cancelledSub = {
      subscriptionId: 'sub-no-remind',
      providerId: 'user-no-remind',
      status: 'CANCELLED',
      deletionScheduledAt: new Date(Date.now() + 20 * DAY_MS),
    };

    const subRepo = makeMockSubscriptionRepo({
      cancelledSubsInExportWindow: [cancelledSub],
    });
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });
    const emitter = makeMockEventEmitter();

    const result = await runExportWindowReminders(deps, emitter);

    expect(result.reminded).toBe(0);
    expect(emitter.emit).not.toHaveBeenCalled();
  });

  it('runExportWindowReminders is idempotent with no cancelled subscriptions', async () => {
    const subRepo = makeMockSubscriptionRepo({ cancelledSubsInExportWindow: [] });
    const deps = makeServiceDeps({ subscriptionRepo: subRepo });
    const emitter = makeMockEventEmitter();

    const result = await runExportWindowReminders(deps, emitter);

    expect(result.reminded).toBe(0);
    expect(emitter.emit).not.toHaveBeenCalled();
  });
});

// ===========================================================================
// Amendment Service Tests
// ===========================================================================

describe('Platform Service — createAmendment', () => {
  it('createAmendment is admin-only', async () => {
    const amendmentRepo = makeMockAmendmentRepo();
    const deps = makeServiceDeps({ amendmentRepo });
    const nonAdminCtx = { userId: 'user-123', role: 'physician' };

    await expect(
      createAmendment(deps, nonAdminCtx, {
        amendmentType: 'MATERIAL',
        title: 'Test Amendment',
        description: 'Test description',
        documentText: 'Test document',
        effectiveDate: new Date(Date.now() + 30 * DAY_MS),
      }),
    ).rejects.toThrow('Only administrators can create amendments');
  });

  it('createAmendment succeeds with admin context', async () => {
    const amendmentRepo = makeMockAmendmentRepo();
    const auditLogger = makeMockAuditLogger();
    const deps = makeServiceDeps({ amendmentRepo, auditLogger });
    const adminCtx = { userId: 'admin-1', role: 'admin' };

    const result = await createAmendment(deps, adminCtx, {
      amendmentType: 'MATERIAL',
      title: 'IMA Update v2',
      description: 'Material change to IMA',
      documentText: 'Full amendment text here',
      effectiveDate: new Date(Date.now() + 30 * DAY_MS),
    });

    expect(result).toBeDefined();
    expect(result.amendmentId).toBeDefined();
    expect(result.amendmentType).toBe('MATERIAL');
    expect(result.title).toBe('IMA Update v2');
    expect(amendmentRepo.createAmendment).toHaveBeenCalledOnce();
  });

  it('createAmendment emits notification to all active physicians', async () => {
    const providerIds = ['prov-1', 'prov-2', 'prov-3'];
    const amendmentRepo = makeMockAmendmentRepo();
    const activeProviderRepo = makeMockActiveProviderRepo(providerIds);
    const auditLogger = makeMockAuditLogger();
    const deps = makeServiceDeps({ amendmentRepo, activeProviderRepo, auditLogger });
    const adminCtx = { userId: 'admin-1', role: 'admin' };
    const emitter = makeMockEventEmitter();

    await createAmendment(deps, adminCtx, {
      amendmentType: 'NON_MATERIAL',
      title: 'Privacy Policy Update',
      description: 'Minor update',
      documentText: 'Document text',
      effectiveDate: new Date(Date.now() + 14 * DAY_MS),
    }, emitter);

    expect(emitter.emit).toHaveBeenCalledWith(
      'IMA_AMENDMENT_NOTICE',
      expect.objectContaining({
        amendmentType: 'NON_MATERIAL',
        title: 'Privacy Policy Update',
        recipientProviderIds: providerIds,
      }),
    );
  });

  it('createAmendment emits audit event amendment.created', async () => {
    const amendmentRepo = makeMockAmendmentRepo();
    const auditLogger = makeMockAuditLogger();
    const deps = makeServiceDeps({ amendmentRepo, auditLogger });
    const adminCtx = { userId: 'admin-1', role: 'admin' };

    await createAmendment(deps, adminCtx, {
      amendmentType: 'MATERIAL',
      title: 'Test',
      description: 'Test',
      documentText: 'Text',
      effectiveDate: new Date(Date.now() + 30 * DAY_MS),
    });

    expect(auditLogger.log).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'amendment.created',
        resourceType: 'ima_amendment',
        actorType: 'admin',
        metadata: expect.objectContaining({
          adminUserId: 'admin-1',
          amendmentType: 'MATERIAL',
        }),
      }),
    );
  });

  it('createAmendment does not fail if notification emitter throws', async () => {
    const amendmentRepo = makeMockAmendmentRepo();
    const activeProviderRepo: ActiveProviderRepo = {
      findActiveProviderIds: vi.fn().mockRejectedValue(new Error('notification service down')),
    };
    const auditLogger = makeMockAuditLogger();
    const deps = makeServiceDeps({ amendmentRepo, activeProviderRepo, auditLogger });
    const adminCtx = { userId: 'admin-1', role: 'admin' };
    const emitter = makeMockEventEmitter();

    // Should not throw despite notification failure
    const result = await createAmendment(deps, adminCtx, {
      amendmentType: 'MATERIAL',
      title: 'Test',
      description: 'Test',
      documentText: 'Text',
      effectiveDate: new Date(Date.now() + 30 * DAY_MS),
    }, emitter);

    expect(result).toBeDefined();
    expect(result.amendmentId).toBeDefined();
  });
});

describe('Platform Service — acknowledgeAmendment', () => {
  it('acknowledgeAmendment records ACKNOWLEDGED response', async () => {
    const amendmentId = crypto.randomUUID();
    const amendmentRepo = makeMockAmendmentRepo({
      amendments: [{
        amendmentId,
        amendmentType: 'NON_MATERIAL',
        title: 'Privacy Update',
        description: 'Minor change',
        effectiveDate: new Date(Date.now() - DAY_MS),
        createdBy: 'admin-1',
        createdAt: new Date(),
      }],
    });
    const auditLogger = makeMockAuditLogger();
    const deps = makeServiceDeps({ amendmentRepo, auditLogger });

    const ctx = {
      userId: 'user-1',
      providerId: 'prov-1',
      ipAddress: '10.0.0.1',
      userAgent: 'Test/1.0',
    };

    await acknowledgeAmendment(deps, ctx, amendmentId);

    expect(amendmentRepo.createAmendmentResponse).toHaveBeenCalledWith({
      amendmentId,
      providerId: 'prov-1',
      responseType: 'ACKNOWLEDGED',
      ipAddress: '10.0.0.1',
      userAgent: 'Test/1.0',
    });
  });

  it('acknowledgeAmendment emits audit event amendment.acknowledged', async () => {
    const amendmentId = crypto.randomUUID();
    const amendmentRepo = makeMockAmendmentRepo({
      amendments: [{
        amendmentId,
        amendmentType: 'NON_MATERIAL',
        title: 'Test',
        description: 'Test',
        effectiveDate: new Date(Date.now() - DAY_MS),
        createdBy: 'admin-1',
        createdAt: new Date(),
      }],
    });
    const auditLogger = makeMockAuditLogger();
    const deps = makeServiceDeps({ amendmentRepo, auditLogger });

    const ctx = {
      userId: 'user-1',
      providerId: 'prov-1',
      ipAddress: '10.0.0.1',
      userAgent: 'Test/1.0',
    };

    await acknowledgeAmendment(deps, ctx, amendmentId);

    expect(auditLogger.log).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'amendment.acknowledged',
        resourceType: 'ima_amendment',
        resourceId: amendmentId,
        actorType: 'physician',
        metadata: expect.objectContaining({
          userId: 'user-1',
          providerId: 'prov-1',
        }),
      }),
    );
  });

  it('acknowledgeAmendment throws NotFound for non-existent amendment', async () => {
    const amendmentRepo = makeMockAmendmentRepo({ amendments: [] });
    const deps = makeServiceDeps({ amendmentRepo });

    const ctx = {
      userId: 'user-1',
      providerId: 'prov-1',
      ipAddress: '10.0.0.1',
      userAgent: 'Test/1.0',
    };

    await expect(
      acknowledgeAmendment(deps, ctx, crypto.randomUUID()),
    ).rejects.toThrow('Amendment not found');
  });
});

describe('Platform Service — respondToAmendment', () => {
  it('respondToAmendment records ACCEPTED response', async () => {
    const amendmentId = crypto.randomUUID();
    const amendmentRepo = makeMockAmendmentRepo({
      amendments: [{
        amendmentId,
        amendmentType: 'MATERIAL',
        title: 'Material Change',
        description: 'Significant update',
        effectiveDate: new Date(Date.now() + 30 * DAY_MS),
        createdBy: 'admin-1',
        createdAt: new Date(),
      }],
    });
    const auditLogger = makeMockAuditLogger();
    const deps = makeServiceDeps({ amendmentRepo, auditLogger });

    const ctx = {
      userId: 'user-1',
      providerId: 'prov-1',
      ipAddress: '10.0.0.1',
      userAgent: 'Test/1.0',
    };

    await respondToAmendment(deps, ctx, amendmentId, 'ACCEPTED');

    expect(amendmentRepo.createAmendmentResponse).toHaveBeenCalledWith({
      amendmentId,
      providerId: 'prov-1',
      responseType: 'ACCEPTED',
      ipAddress: '10.0.0.1',
      userAgent: 'Test/1.0',
    });
  });

  it('respondToAmendment records REJECTED response', async () => {
    const amendmentId = crypto.randomUUID();
    const amendmentRepo = makeMockAmendmentRepo({
      amendments: [{
        amendmentId,
        amendmentType: 'MATERIAL',
        title: 'Material Change',
        description: 'Significant update',
        effectiveDate: new Date(Date.now() + 30 * DAY_MS),
        createdBy: 'admin-1',
        createdAt: new Date(),
      }],
    });
    const auditLogger = makeMockAuditLogger();
    const deps = makeServiceDeps({ amendmentRepo, auditLogger });

    const ctx = {
      userId: 'user-1',
      providerId: 'prov-1',
      ipAddress: '10.0.0.1',
      userAgent: 'Test/1.0',
    };

    await respondToAmendment(deps, ctx, amendmentId, 'REJECTED');

    expect(amendmentRepo.createAmendmentResponse).toHaveBeenCalledWith({
      amendmentId,
      providerId: 'prov-1',
      responseType: 'REJECTED',
      ipAddress: '10.0.0.1',
      userAgent: 'Test/1.0',
    });
  });

  it('respondToAmendment emits audit event amendment.accepted', async () => {
    const amendmentId = crypto.randomUUID();
    const amendmentRepo = makeMockAmendmentRepo({
      amendments: [{
        amendmentId,
        amendmentType: 'MATERIAL',
        title: 'Test',
        description: 'Test',
        effectiveDate: new Date(Date.now() + 30 * DAY_MS),
        createdBy: 'admin-1',
        createdAt: new Date(),
      }],
    });
    const auditLogger = makeMockAuditLogger();
    const deps = makeServiceDeps({ amendmentRepo, auditLogger });

    const ctx = {
      userId: 'user-1',
      providerId: 'prov-1',
      ipAddress: '10.0.0.1',
      userAgent: 'Test/1.0',
    };

    await respondToAmendment(deps, ctx, amendmentId, 'ACCEPTED');

    expect(auditLogger.log).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'amendment.accepted',
        resourceType: 'ima_amendment',
        resourceId: amendmentId,
        metadata: expect.objectContaining({
          responseType: 'ACCEPTED',
        }),
      }),
    );
  });

  it('respondToAmendment emits audit event amendment.rejected', async () => {
    const amendmentId = crypto.randomUUID();
    const amendmentRepo = makeMockAmendmentRepo({
      amendments: [{
        amendmentId,
        amendmentType: 'MATERIAL',
        title: 'Test',
        description: 'Test',
        effectiveDate: new Date(Date.now() + 30 * DAY_MS),
        createdBy: 'admin-1',
        createdAt: new Date(),
      }],
    });
    const auditLogger = makeMockAuditLogger();
    const deps = makeServiceDeps({ amendmentRepo, auditLogger });

    const ctx = {
      userId: 'user-1',
      providerId: 'prov-1',
      ipAddress: '10.0.0.1',
      userAgent: 'Test/1.0',
    };

    await respondToAmendment(deps, ctx, amendmentId, 'REJECTED');

    expect(auditLogger.log).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'amendment.rejected',
        metadata: expect.objectContaining({
          responseType: 'REJECTED',
        }),
      }),
    );
  });

  it('respondToAmendment throws NotFound for non-existent amendment', async () => {
    const amendmentRepo = makeMockAmendmentRepo({ amendments: [] });
    const deps = makeServiceDeps({ amendmentRepo });

    const ctx = {
      userId: 'user-1',
      providerId: 'prov-1',
      ipAddress: '10.0.0.1',
      userAgent: 'Test/1.0',
    };

    await expect(
      respondToAmendment(deps, ctx, crypto.randomUUID(), 'ACCEPTED'),
    ).rejects.toThrow('Amendment not found');
  });
});

describe('Platform Service — getBlockingAmendments', () => {
  it('getBlockingAmendments returns only unacknowledged non-material past effective date', async () => {
    const nonMaterialPast = {
      amendmentId: 'amend-1',
      amendmentType: 'NON_MATERIAL',
      title: 'Privacy Update',
      description: 'Test',
      effectiveDate: new Date(Date.now() - DAY_MS),
      createdBy: 'admin-1',
      createdAt: new Date(),
    };
    const materialPast = {
      amendmentId: 'amend-2',
      amendmentType: 'MATERIAL',
      title: 'Material Change',
      description: 'Test',
      effectiveDate: new Date(Date.now() - DAY_MS),
      createdBy: 'admin-1',
      createdAt: new Date(),
    };
    const nonMaterialFuture = {
      amendmentId: 'amend-3',
      amendmentType: 'NON_MATERIAL',
      title: 'Future Update',
      description: 'Test',
      effectiveDate: new Date(Date.now() + 30 * DAY_MS),
      createdBy: 'admin-1',
      createdAt: new Date(),
    };

    const amendmentRepo = makeMockAmendmentRepo({
      amendments: [nonMaterialPast, materialPast, nonMaterialFuture],
    });
    const deps = makeServiceDeps({ amendmentRepo });

    const blocking = await getBlockingAmendments(deps, 'prov-1');

    // Only the past NON_MATERIAL amendment should block
    expect(blocking).toHaveLength(1);
    expect(blocking[0].amendmentId).toBe('amend-1');
    expect(blocking[0].title).toBe('Privacy Update');
  });

  it('material amendments do not block access', async () => {
    const materialPast = {
      amendmentId: 'amend-2',
      amendmentType: 'MATERIAL',
      title: 'Material Change',
      description: 'Test',
      effectiveDate: new Date(Date.now() - DAY_MS),
      createdBy: 'admin-1',
      createdAt: new Date(),
    };

    const amendmentRepo = makeMockAmendmentRepo({
      amendments: [materialPast],
    });
    const deps = makeServiceDeps({ amendmentRepo });

    const blocking = await getBlockingAmendments(deps, 'prov-1');

    expect(blocking).toHaveLength(0);
  });

  it('getBlockingAmendments returns empty when provider has acknowledged all', async () => {
    const nonMaterialPast = {
      amendmentId: 'amend-1',
      amendmentType: 'NON_MATERIAL',
      title: 'Privacy Update',
      description: 'Test',
      effectiveDate: new Date(Date.now() - DAY_MS),
      createdBy: 'admin-1',
      createdAt: new Date(),
    };

    const amendmentRepo = makeMockAmendmentRepo({
      amendments: [nonMaterialPast],
      responses: [{
        responseId: crypto.randomUUID(),
        amendmentId: 'amend-1',
        providerId: 'prov-1',
        responseType: 'ACKNOWLEDGED',
      }],
    });
    const deps = makeServiceDeps({ amendmentRepo });

    const blocking = await getBlockingAmendments(deps, 'prov-1');

    expect(blocking).toHaveLength(0);
  });

  it('getBlockingAmendments returns empty when no amendment repo configured', async () => {
    const deps = makeServiceDeps();
    // No amendmentRepo — should not throw

    const blocking = await getBlockingAmendments(deps, 'prov-1');

    expect(blocking).toHaveLength(0);
  });
});

describe('Platform Service — runAmendmentReminders', () => {
  it('reminder job finds amendments approaching deadline at 30 days', async () => {
    const materialAmendment30 = {
      amendmentId: 'amend-30',
      amendmentType: 'MATERIAL',
      title: 'Material 30-day',
      description: 'Test',
      effectiveDate: new Date(Date.now() + 30 * DAY_MS),
      createdBy: 'admin-1',
      createdAt: new Date(),
    };

    const amendmentRepo = makeMockAmendmentRepo({
      amendments: [materialAmendment30],
    });
    const activeProviderRepo = makeMockActiveProviderRepo(['prov-1', 'prov-2']);
    const deps = makeServiceDeps({ amendmentRepo, activeProviderRepo });
    const emitter = makeMockEventEmitter();

    const result = await runAmendmentReminders(deps, emitter);

    expect(result.reminded).toBe(2);
    expect(emitter.emit).toHaveBeenCalledWith(
      'IMA_AMENDMENT_REMINDER',
      expect.objectContaining({
        amendmentId: 'amend-30',
        providerId: 'prov-1',
        daysUntilEffective: 30,
      }),
    );
    expect(emitter.emit).toHaveBeenCalledWith(
      'IMA_AMENDMENT_REMINDER',
      expect.objectContaining({
        amendmentId: 'amend-30',
        providerId: 'prov-2',
        daysUntilEffective: 30,
      }),
    );
  });

  it('reminder job finds amendments approaching deadline at 7 days', async () => {
    const materialAmendment7 = {
      amendmentId: 'amend-7',
      amendmentType: 'MATERIAL',
      title: 'Material 7-day',
      description: 'Test',
      effectiveDate: new Date(Date.now() + 7 * DAY_MS),
      createdBy: 'admin-1',
      createdAt: new Date(),
    };

    const amendmentRepo = makeMockAmendmentRepo({
      amendments: [materialAmendment7],
    });
    const activeProviderRepo = makeMockActiveProviderRepo(['prov-1']);
    const deps = makeServiceDeps({ amendmentRepo, activeProviderRepo });
    const emitter = makeMockEventEmitter();

    const result = await runAmendmentReminders(deps, emitter);

    expect(result.reminded).toBe(1);
    expect(emitter.emit).toHaveBeenCalledWith(
      'IMA_AMENDMENT_REMINDER',
      expect.objectContaining({
        amendmentId: 'amend-7',
        providerId: 'prov-1',
        daysUntilEffective: 7,
      }),
    );
  });

  it('reminder job skips providers who have already responded', async () => {
    const materialAmendment = {
      amendmentId: 'amend-30r',
      amendmentType: 'MATERIAL',
      title: 'Material Responded',
      description: 'Test',
      effectiveDate: new Date(Date.now() + 30 * DAY_MS),
      createdBy: 'admin-1',
      createdAt: new Date(),
    };

    const amendmentRepo = makeMockAmendmentRepo({
      amendments: [materialAmendment],
      responses: [{
        responseId: crypto.randomUUID(),
        amendmentId: 'amend-30r',
        providerId: 'prov-1',
        responseType: 'ACCEPTED',
      }],
    });
    const activeProviderRepo = makeMockActiveProviderRepo(['prov-1', 'prov-2']);
    const deps = makeServiceDeps({ amendmentRepo, activeProviderRepo });
    const emitter = makeMockEventEmitter();

    const result = await runAmendmentReminders(deps, emitter);

    // prov-1 already responded, only prov-2 should get reminder
    expect(result.reminded).toBe(1);
    expect(emitter.emit).toHaveBeenCalledWith(
      'IMA_AMENDMENT_REMINDER',
      expect.objectContaining({
        providerId: 'prov-2',
      }),
    );
  });

  it('reminder job skips NON_MATERIAL amendments', async () => {
    const nonMaterialAmendment = {
      amendmentId: 'amend-nm',
      amendmentType: 'NON_MATERIAL',
      title: 'Non-Material',
      description: 'Test',
      effectiveDate: new Date(Date.now() + 30 * DAY_MS),
      createdBy: 'admin-1',
      createdAt: new Date(),
    };

    const amendmentRepo = makeMockAmendmentRepo({
      amendments: [nonMaterialAmendment],
    });
    const activeProviderRepo = makeMockActiveProviderRepo(['prov-1']);
    const deps = makeServiceDeps({ amendmentRepo, activeProviderRepo });
    const emitter = makeMockEventEmitter();

    const result = await runAmendmentReminders(deps, emitter);

    expect(result.reminded).toBe(0);
    expect(emitter.emit).not.toHaveBeenCalled();
  });

  it('reminder job returns 0 when no repos configured', async () => {
    const deps = makeServiceDeps();
    const emitter = makeMockEventEmitter();

    const result = await runAmendmentReminders(deps, emitter);

    expect(result.reminded).toBe(0);
  });
});

// ===========================================================================
// Amendment Repository Tests
// ===========================================================================

describe('Amendment Repository', () => {
  let repo: ReturnType<typeof createAmendmentRepository>;

  beforeEach(() => {
    subscriptionStore = [];
    paymentStore = [];
    componentStore = [];
    incidentStore = [];
    incidentUpdateStore = [];
    practiceMembershipStore = [];
    amendmentStore = [];
    amendmentResponseStore = [];
    const db = makeMockDb();
    repo = createAmendmentRepository(db);
  });

  // -------------------------------------------------------------------------
  // createAmendment
  // -------------------------------------------------------------------------

  it('createAmendment stores amendment with computed document hash', async () => {
    const documentText = 'This is the IMA amendment document text.';
    const { createHash } = await import('node:crypto');
    const expectedHash = createHash('sha256').update(documentText).digest('hex');

    const result = await repo.createAmendment({
      amendmentType: 'MATERIAL',
      title: 'Test Amendment',
      description: 'A test amendment',
      documentText,
      effectiveDate: new Date('2026-04-01T00:00:00Z'),
      createdBy: 'admin-user-id',
    });

    expect(result.documentHash).toBe(expectedHash);
    expect(result.documentHash).toHaveLength(64);
    expect(result.amendmentType).toBe('MATERIAL');
    expect(result.title).toBe('Test Amendment');
    expect(result.description).toBe('A test amendment');
    expect(result.noticeDate).toBeInstanceOf(Date);
    expect(result.effectiveDate).toEqual(new Date('2026-04-01T00:00:00Z'));
    expect(result.createdBy).toBe('admin-user-id');
    expect(result.amendmentId).toBeDefined();
    // noticeDate should be approximately now
    const diff = Math.abs(Date.now() - result.noticeDate.getTime());
    expect(diff).toBeLessThan(5000);
  });

  // -------------------------------------------------------------------------
  // findAmendmentById
  // -------------------------------------------------------------------------

  it('findAmendmentById returns amendment with response count summary', async () => {
    const amendment = await repo.createAmendment({
      amendmentType: 'NON_MATERIAL',
      title: 'Find Test',
      description: 'Test',
      documentText: 'doc text',
      effectiveDate: new Date('2026-03-01T00:00:00Z'),
      createdBy: 'admin-1',
    });

    // Add some responses directly to the store
    amendmentResponseStore.push(
      {
        responseId: crypto.randomUUID(),
        amendmentId: amendment.amendmentId,
        providerId: 'prov-1',
        responseType: 'ACKNOWLEDGED',
        respondedAt: new Date(),
        ipAddress: '10.0.0.1',
        userAgent: 'Test/1.0',
      },
      {
        responseId: crypto.randomUUID(),
        amendmentId: amendment.amendmentId,
        providerId: 'prov-2',
        responseType: 'ACCEPTED',
        respondedAt: new Date(),
        ipAddress: '10.0.0.2',
        userAgent: 'Test/1.0',
      },
      {
        responseId: crypto.randomUUID(),
        amendmentId: amendment.amendmentId,
        providerId: 'prov-3',
        responseType: 'REJECTED',
        respondedAt: new Date(),
        ipAddress: '10.0.0.3',
        userAgent: 'Test/1.0',
      },
    );

    const found = await repo.findAmendmentById(amendment.amendmentId);
    expect(found).toBeDefined();
    expect(found!.amendmentId).toBe(amendment.amendmentId);
    expect(found!.responseCounts).toEqual({
      total: 3,
      acknowledged: 1,
      accepted: 1,
      rejected: 1,
    });
  });

  it('findAmendmentById returns undefined for non-existent amendment', async () => {
    const found = await repo.findAmendmentById(crypto.randomUUID());
    expect(found).toBeUndefined();
  });

  // -------------------------------------------------------------------------
  // listAmendments
  // -------------------------------------------------------------------------

  it('listAmendments returns paginated list with derived status', async () => {
    // Create a PENDING amendment (effective date in future)
    await repo.createAmendment({
      amendmentType: 'MATERIAL',
      title: 'Future Amendment',
      description: 'Pending',
      documentText: 'future doc',
      effectiveDate: new Date(Date.now() + 86400000 * 30),
      createdBy: 'admin-1',
    });

    // Create an ACTIVE amendment (effective date in past)
    await repo.createAmendment({
      amendmentType: 'NON_MATERIAL',
      title: 'Active Amendment',
      description: 'Active',
      documentText: 'active doc',
      effectiveDate: new Date(Date.now() - 86400000),
      createdBy: 'admin-1',
    });

    const all = await repo.listAmendments({ page: 1, pageSize: 50 });
    expect(all.data).toHaveLength(2);
    expect(all.total).toBe(2);

    const pending = await repo.listAmendments({ status: 'PENDING', page: 1, pageSize: 50 });
    expect(pending.data).toHaveLength(1);
    expect(pending.data[0].title).toBe('Future Amendment');
    expect(pending.data[0].derivedStatus).toBe('PENDING');

    const active = await repo.listAmendments({ status: 'ACTIVE', page: 1, pageSize: 50 });
    expect(active.data).toHaveLength(1);
    expect(active.data[0].title).toBe('Active Amendment');
    expect(active.data[0].derivedStatus).toBe('ACTIVE');
  });

  // -------------------------------------------------------------------------
  // findPendingAmendmentsForProvider
  // -------------------------------------------------------------------------

  it('findPendingAmendmentsForProvider returns amendments awaiting response', async () => {
    const providerId = 'prov-pending-1';

    // Create an amendment with effective_date in the past
    const amendment1 = await repo.createAmendment({
      amendmentType: 'MATERIAL',
      title: 'Past Amendment',
      description: 'Should appear',
      documentText: 'past doc',
      effectiveDate: new Date(Date.now() - 86400000),
      createdBy: 'admin-1',
    });

    // Create another past amendment
    const amendment2 = await repo.createAmendment({
      amendmentType: 'NON_MATERIAL',
      title: 'Another Past',
      description: 'Also should appear',
      documentText: 'another past doc',
      effectiveDate: new Date(Date.now() - 86400000 * 2),
      createdBy: 'admin-1',
    });

    // Create a future amendment (should NOT appear)
    await repo.createAmendment({
      amendmentType: 'MATERIAL',
      title: 'Future Amendment',
      description: 'Should not appear',
      documentText: 'future doc',
      effectiveDate: new Date(Date.now() + 86400000 * 30),
      createdBy: 'admin-1',
    });

    // Verify both past amendments appear
    let pending = await repo.findPendingAmendmentsForProvider(providerId);
    expect(pending).toHaveLength(2);

    // Respond to amendment1
    await repo.createAmendmentResponse({
      amendmentId: amendment1.amendmentId,
      providerId,
      responseType: 'ACKNOWLEDGED',
      ipAddress: '10.0.0.1',
      userAgent: 'Test/1.0',
    });

    // Verify only amendment2 appears now
    pending = await repo.findPendingAmendmentsForProvider(providerId);
    expect(pending).toHaveLength(1);
    expect(pending[0].amendmentId).toBe(amendment2.amendmentId);
  });

  // -------------------------------------------------------------------------
  // createAmendmentResponse
  // -------------------------------------------------------------------------

  it('createAmendmentResponse stores acknowledgement', async () => {
    const amendment = await repo.createAmendment({
      amendmentType: 'MATERIAL',
      title: 'Response Test',
      description: 'Test',
      documentText: 'response doc',
      effectiveDate: new Date(Date.now() - 86400000),
      createdBy: 'admin-1',
    });

    const response = await repo.createAmendmentResponse({
      amendmentId: amendment.amendmentId,
      providerId: 'prov-resp-1',
      responseType: 'ACCEPTED',
      ipAddress: '192.168.1.1',
      userAgent: 'Mozilla/5.0',
    });

    expect(response.responseId).toBeDefined();
    expect(response.amendmentId).toBe(amendment.amendmentId);
    expect(response.providerId).toBe('prov-resp-1');
    expect(response.responseType).toBe('ACCEPTED');
    expect(response.ipAddress).toBe('192.168.1.1');
    expect(response.userAgent).toBe('Mozilla/5.0');
    expect(response.respondedAt).toBeInstanceOf(Date);
  });

  it('createAmendmentResponse rejects duplicate response', async () => {
    const amendment = await repo.createAmendment({
      amendmentType: 'MATERIAL',
      title: 'Dup Test',
      description: 'Test',
      documentText: 'dup doc',
      effectiveDate: new Date(Date.now() - 86400000),
      createdBy: 'admin-1',
    });

    await repo.createAmendmentResponse({
      amendmentId: amendment.amendmentId,
      providerId: 'prov-dup-1',
      responseType: 'ACKNOWLEDGED',
      ipAddress: '10.0.0.1',
      userAgent: 'Test/1.0',
    });

    await expect(
      repo.createAmendmentResponse({
        amendmentId: amendment.amendmentId,
        providerId: 'prov-dup-1',
        responseType: 'ACCEPTED',
        ipAddress: '10.0.0.2',
        userAgent: 'Test/2.0',
      }),
    ).rejects.toThrow('Provider has already responded to this amendment');
  });

  // -------------------------------------------------------------------------
  // getAmendmentResponse
  // -------------------------------------------------------------------------

  it('getAmendmentResponse returns response when exists', async () => {
    const amendment = await repo.createAmendment({
      amendmentType: 'NON_MATERIAL',
      title: 'Get Test',
      description: 'Test',
      documentText: 'get doc',
      effectiveDate: new Date(Date.now() - 86400000),
      createdBy: 'admin-1',
    });

    await repo.createAmendmentResponse({
      amendmentId: amendment.amendmentId,
      providerId: 'prov-get-1',
      responseType: 'REJECTED',
      ipAddress: '10.0.0.1',
      userAgent: 'Test/1.0',
    });

    const found = await repo.getAmendmentResponse(
      amendment.amendmentId,
      'prov-get-1',
    );
    expect(found).toBeDefined();
    expect(found!.responseType).toBe('REJECTED');
  });

  it('getAmendmentResponse returns undefined when no response exists', async () => {
    const amendment = await repo.createAmendment({
      amendmentType: 'MATERIAL',
      title: 'No Response',
      description: 'Test',
      documentText: 'no resp doc',
      effectiveDate: new Date(Date.now() - 86400000),
      createdBy: 'admin-1',
    });

    const found = await repo.getAmendmentResponse(
      amendment.amendmentId,
      'prov-nonexistent',
    );
    expect(found).toBeUndefined();
  });

  // -------------------------------------------------------------------------
  // countUnrespondedAmendments
  // -------------------------------------------------------------------------

  it('countUnrespondedAmendments returns correct count', async () => {
    const providerId = 'prov-count-1';

    // Create 3 amendments with effective_date in the past
    const a1 = await repo.createAmendment({
      amendmentType: 'MATERIAL',
      title: 'Count 1',
      description: 'Test',
      documentText: 'count doc 1',
      effectiveDate: new Date(Date.now() - 86400000 * 3),
      createdBy: 'admin-1',
    });

    await repo.createAmendment({
      amendmentType: 'MATERIAL',
      title: 'Count 2',
      description: 'Test',
      documentText: 'count doc 2',
      effectiveDate: new Date(Date.now() - 86400000 * 2),
      createdBy: 'admin-1',
    });

    await repo.createAmendment({
      amendmentType: 'NON_MATERIAL',
      title: 'Count 3',
      description: 'Test',
      documentText: 'count doc 3',
      effectiveDate: new Date(Date.now() - 86400000),
      createdBy: 'admin-1',
    });

    // Create a future amendment (should NOT count)
    await repo.createAmendment({
      amendmentType: 'MATERIAL',
      title: 'Future',
      description: 'Test',
      documentText: 'future doc',
      effectiveDate: new Date(Date.now() + 86400000 * 30),
      createdBy: 'admin-1',
    });

    // All 3 past amendments should be unresponded
    let unresponded = await repo.countUnrespondedAmendments(providerId);
    expect(unresponded).toBe(3);

    // Respond to one
    await repo.createAmendmentResponse({
      amendmentId: a1.amendmentId,
      providerId,
      responseType: 'ACKNOWLEDGED',
      ipAddress: '10.0.0.1',
      userAgent: 'Test/1.0',
    });

    // Now only 2 unresponded
    unresponded = await repo.countUnrespondedAmendments(providerId);
    expect(unresponded).toBe(2);
  });

  it('countUnrespondedAmendments returns 0 when all responded', async () => {
    const providerId = 'prov-all-resp';

    const a1 = await repo.createAmendment({
      amendmentType: 'MATERIAL',
      title: 'Resp All',
      description: 'Test',
      documentText: 'all resp doc',
      effectiveDate: new Date(Date.now() - 86400000),
      createdBy: 'admin-1',
    });

    await repo.createAmendmentResponse({
      amendmentId: a1.amendmentId,
      providerId,
      responseType: 'ACCEPTED',
      ipAddress: '10.0.0.1',
      userAgent: 'Test/1.0',
    });

    const count = await repo.countUnrespondedAmendments(providerId);
    expect(count).toBe(0);
  });
});

// ===========================================================================
// Breach Service Tests
// ===========================================================================

function makeBreachInput(overrides?: Partial<Record<string, any>>) {
  return {
    breachDescription: overrides?.breachDescription ?? 'Unauthorized access to patient records',
    breachDate: overrides?.breachDate ?? new Date('2026-01-15T10:00:00Z'),
    awarenessDate: overrides?.awarenessDate ?? new Date('2026-01-16T08:00:00Z'),
    hiDescription: overrides?.hiDescription ?? 'Patient demographics and PHN data',
    includesIihi: overrides?.includesIihi ?? true,
    affectedCount: overrides?.affectedCount ?? 50,
    riskAssessment: overrides?.riskAssessment ?? 'High risk — PHN exposed',
    mitigationSteps: overrides?.mitigationSteps ?? 'Passwords reset, access revoked',
    contactName: overrides?.contactName ?? 'Privacy Officer',
    contactEmail: overrides?.contactEmail ?? 'privacy@meritum.ca',
    affectedProviderIds: overrides?.affectedProviderIds ?? ['prov-1', 'prov-2'],
  };
}

describe('Platform Service — createBreach', () => {
  it('createBreach is admin-only', async () => {
    const breachRepo = makeMockBreachRepo();
    const deps = makeServiceDeps({ breachRepo });
    const nonAdminCtx = { userId: 'user-123', role: 'physician' };

    await expect(
      createBreach(deps, nonAdminCtx, makeBreachInput()),
    ).rejects.toThrow('Only administrators can create breach records');
  });

  it('createBreach adds affected custodians', async () => {
    const breachRepo = makeMockBreachRepo();
    const auditLogger = makeMockAuditLogger();
    const deps = makeServiceDeps({ breachRepo, auditLogger });
    const adminCtx = { userId: 'admin-1', role: 'admin' };

    const input = makeBreachInput({ affectedProviderIds: ['prov-a', 'prov-b', 'prov-c'] });
    const result = await createBreach(deps, adminCtx, input);

    expect(result).toBeDefined();
    expect(result.breachId).toBeDefined();
    expect(result.breachDescription).toBe(input.breachDescription);
    expect(breachRepo.createBreachRecord).toHaveBeenCalledOnce();
    expect(breachRepo.addAffectedCustodian).toHaveBeenCalledTimes(3);
    expect(breachRepo.addAffectedCustodian).toHaveBeenCalledWith(result.breachId, 'prov-a');
    expect(breachRepo.addAffectedCustodian).toHaveBeenCalledWith(result.breachId, 'prov-b');
    expect(breachRepo.addAffectedCustodian).toHaveBeenCalledWith(result.breachId, 'prov-c');
  });

  it('createBreach emits audit event breach.created', async () => {
    const breachRepo = makeMockBreachRepo();
    const auditLogger = makeMockAuditLogger();
    const deps = makeServiceDeps({ breachRepo, auditLogger });
    const adminCtx = { userId: 'admin-1', role: 'admin' };

    const result = await createBreach(deps, adminCtx, makeBreachInput());

    expect(auditLogger.log).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'breach.created',
        resourceType: 'breach_record',
        resourceId: result.breachId,
        actorType: 'admin',
        metadata: expect.objectContaining({
          adminUserId: 'admin-1',
          affectedProviderCount: 2,
        }),
      }),
    );
  });
});

describe('Platform Service — sendBreachNotifications', () => {
  it('sendBreachNotifications sends to both primary and secondary email', async () => {
    const breachRepo = makeMockBreachRepo();
    const auditLogger = makeMockAuditLogger();
    const deps = makeServiceDeps({ breachRepo, auditLogger });
    const adminCtx = { userId: 'admin-1', role: 'admin' };
    const emitter = makeMockEventEmitter();

    // Create breach and add custodians
    const breach = await createBreach(deps, adminCtx, makeBreachInput({
      affectedProviderIds: ['prov-1', 'prov-2'],
    }));

    const result = await sendBreachNotifications(deps, adminCtx, breach.breachId, emitter);

    expect(result.notified).toBe(2);
    // Dual-delivery happens automatically via notification service for BREACH_INITIAL_NOTIFICATION
    expect(emitter.emit).toHaveBeenCalledTimes(2);
    expect(emitter.emit).toHaveBeenCalledWith(
      'BREACH_INITIAL_NOTIFICATION',
      expect.objectContaining({
        breachId: breach.breachId,
        providerId: 'prov-1',
      }),
    );
    expect(emitter.emit).toHaveBeenCalledWith(
      'BREACH_INITIAL_NOTIFICATION',
      expect.objectContaining({
        breachId: breach.breachId,
        providerId: 'prov-2',
      }),
    );
  });

  it('sendBreachNotifications marks custodians as notified', async () => {
    const breachRepo = makeMockBreachRepo();
    const auditLogger = makeMockAuditLogger();
    const deps = makeServiceDeps({ breachRepo, auditLogger });
    const adminCtx = { userId: 'admin-1', role: 'admin' };
    const emitter = makeMockEventEmitter();

    const breach = await createBreach(deps, adminCtx, makeBreachInput({
      affectedProviderIds: ['prov-1'],
    }));

    await sendBreachNotifications(deps, adminCtx, breach.breachId, emitter);

    expect(breachRepo.markCustodianNotified).toHaveBeenCalledWith(
      breach.breachId,
      'prov-1',
      'EMAIL',
    );
  });

  it('sendBreachNotifications creates INITIAL breach update', async () => {
    const breachRepo = makeMockBreachRepo();
    const auditLogger = makeMockAuditLogger();
    const deps = makeServiceDeps({ breachRepo, auditLogger });
    const adminCtx = { userId: 'admin-1', role: 'admin' };
    const emitter = makeMockEventEmitter();

    const breach = await createBreach(deps, adminCtx, makeBreachInput());

    await sendBreachNotifications(deps, adminCtx, breach.breachId, emitter);

    expect(breachRepo.createBreachUpdate).toHaveBeenCalledWith(
      breach.breachId,
      expect.objectContaining({
        updateType: 'INITIAL',
        createdBy: 'admin-1',
      }),
    );
  });

  it('sendBreachNotifications updates breach status to NOTIFYING', async () => {
    const breachRepo = makeMockBreachRepo();
    const auditLogger = makeMockAuditLogger();
    const deps = makeServiceDeps({ breachRepo, auditLogger });
    const adminCtx = { userId: 'admin-1', role: 'admin' };
    const emitter = makeMockEventEmitter();

    const breach = await createBreach(deps, adminCtx, makeBreachInput());

    await sendBreachNotifications(deps, adminCtx, breach.breachId, emitter);

    expect(breachRepo.updateBreachStatus).toHaveBeenCalledWith(
      breach.breachId,
      'NOTIFYING',
    );
  });

  it('sendBreachNotifications is admin-only', async () => {
    const breachRepo = makeMockBreachRepo();
    const deps = makeServiceDeps({ breachRepo });
    const nonAdminCtx = { userId: 'user-123', role: 'physician' };

    await expect(
      sendBreachNotifications(deps, nonAdminCtx, 'some-breach-id'),
    ).rejects.toThrow('Only administrators can send breach notifications');
  });

  it('sendBreachNotifications throws NotFoundError for non-existent breach', async () => {
    const breachRepo = makeMockBreachRepo();
    const deps = makeServiceDeps({ breachRepo });
    const adminCtx = { userId: 'admin-1', role: 'admin' };

    await expect(
      sendBreachNotifications(deps, adminCtx, crypto.randomUUID()),
    ).rejects.toThrow('not found');
  });

  it('sendBreachNotifications emits audit event breach.notification_sent', async () => {
    const breachRepo = makeMockBreachRepo();
    const auditLogger = makeMockAuditLogger();
    const deps = makeServiceDeps({ breachRepo, auditLogger });
    const adminCtx = { userId: 'admin-1', role: 'admin' };
    const emitter = makeMockEventEmitter();

    const breach = await createBreach(deps, adminCtx, makeBreachInput());

    await sendBreachNotifications(deps, adminCtx, breach.breachId, emitter);

    expect(auditLogger.log).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'breach.notification_sent',
        resourceType: 'breach_record',
        resourceId: breach.breachId,
        actorType: 'admin',
        metadata: expect.objectContaining({
          adminUserId: 'admin-1',
          notifiedCount: 2,
        }),
      }),
    );
  });

  it('sendBreachNotifications does not re-notify already-notified custodians', async () => {
    const breachRepo = makeMockBreachRepo();
    const auditLogger = makeMockAuditLogger();
    const deps = makeServiceDeps({ breachRepo, auditLogger });
    const adminCtx = { userId: 'admin-1', role: 'admin' };
    const emitter = makeMockEventEmitter();

    const breach = await createBreach(deps, adminCtx, makeBreachInput({
      affectedProviderIds: ['prov-1', 'prov-2'],
    }));

    // First notification run
    await sendBreachNotifications(deps, adminCtx, breach.breachId, emitter);
    expect(emitter.emit).toHaveBeenCalledTimes(2);

    // Reset emitter to track second run
    (emitter.emit as any).mockClear();

    // Second notification run — all custodians already notified
    const result2 = await sendBreachNotifications(deps, adminCtx, breach.breachId, emitter);
    expect(result2.notified).toBe(0);
    expect(emitter.emit).not.toHaveBeenCalled();
  });
});

describe('Platform Service — addBreachUpdate', () => {
  it('addBreachUpdate creates SUPPLEMENTARY record', async () => {
    const breachRepo = makeMockBreachRepo();
    const auditLogger = makeMockAuditLogger();
    const deps = makeServiceDeps({ breachRepo, auditLogger });
    const adminCtx = { userId: 'admin-1', role: 'admin' };
    const emitter = makeMockEventEmitter();

    const breach = await createBreach(deps, adminCtx, makeBreachInput());

    const update = await addBreachUpdate(
      deps, adminCtx, breach.breachId, 'Root cause identified: compromised credentials.', emitter,
    );

    expect(update).toBeDefined();
    expect(update.updateId).toBeDefined();
    expect(update.updateType).toBe('SUPPLEMENTARY');
    expect(update.content).toBe('Root cause identified: compromised credentials.');
    expect(breachRepo.createBreachUpdate).toHaveBeenCalledWith(
      breach.breachId,
      expect.objectContaining({
        updateType: 'SUPPLEMENTARY',
        content: 'Root cause identified: compromised credentials.',
        createdBy: 'admin-1',
      }),
    );
  });

  it('addBreachUpdate emits BREACH_UPDATE notification', async () => {
    const breachRepo = makeMockBreachRepo();
    const auditLogger = makeMockAuditLogger();
    const deps = makeServiceDeps({ breachRepo, auditLogger });
    const adminCtx = { userId: 'admin-1', role: 'admin' };
    const emitter = makeMockEventEmitter();

    const breach = await createBreach(deps, adminCtx, makeBreachInput());

    await addBreachUpdate(deps, adminCtx, breach.breachId, 'Update content', emitter);

    expect(emitter.emit).toHaveBeenCalledWith(
      'BREACH_UPDATE',
      expect.objectContaining({
        breachId: breach.breachId,
        content: 'Update content',
      }),
    );
  });

  it('addBreachUpdate is admin-only', async () => {
    const breachRepo = makeMockBreachRepo();
    const deps = makeServiceDeps({ breachRepo });
    const nonAdminCtx = { userId: 'user-123', role: 'physician' };

    await expect(
      addBreachUpdate(deps, nonAdminCtx, 'some-breach-id', 'content'),
    ).rejects.toThrow('Only administrators can add breach updates');
  });

  it('addBreachUpdate emits audit event breach.updated', async () => {
    const breachRepo = makeMockBreachRepo();
    const auditLogger = makeMockAuditLogger();
    const deps = makeServiceDeps({ breachRepo, auditLogger });
    const adminCtx = { userId: 'admin-1', role: 'admin' };

    const breach = await createBreach(deps, adminCtx, makeBreachInput());

    await addBreachUpdate(deps, adminCtx, breach.breachId, 'New details');

    expect(auditLogger.log).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'breach.updated',
        resourceType: 'breach_record',
        resourceId: breach.breachId,
        actorType: 'admin',
        metadata: expect.objectContaining({
          adminUserId: 'admin-1',
          updateType: 'SUPPLEMENTARY',
        }),
      }),
    );
  });
});

describe('Platform Service — resolveBreach', () => {
  it('resolveBreach sets status and timestamp', async () => {
    const breachRepo = makeMockBreachRepo();
    const auditLogger = makeMockAuditLogger();
    const deps = makeServiceDeps({ breachRepo, auditLogger });
    const adminCtx = { userId: 'admin-1', role: 'admin' };

    const breach = await createBreach(deps, adminCtx, makeBreachInput());

    const resolved = await resolveBreach(deps, adminCtx, breach.breachId);

    expect(resolved).toBeDefined();
    expect(resolved!.status).toBe('RESOLVED');
    expect(resolved!.resolvedAt).toBeDefined();
    expect(breachRepo.updateBreachStatus).toHaveBeenCalledWith(
      breach.breachId,
      'RESOLVED',
      expect.any(Date),
    );
  });

  it('resolveBreach is admin-only', async () => {
    const breachRepo = makeMockBreachRepo();
    const deps = makeServiceDeps({ breachRepo });
    const nonAdminCtx = { userId: 'user-123', role: 'physician' };

    await expect(
      resolveBreach(deps, nonAdminCtx, 'some-breach-id'),
    ).rejects.toThrow('Only administrators can resolve breach records');
  });

  it('resolveBreach throws ConflictError if already resolved', async () => {
    const breachRepo = makeMockBreachRepo();
    const auditLogger = makeMockAuditLogger();
    const deps = makeServiceDeps({ breachRepo, auditLogger });
    const adminCtx = { userId: 'admin-1', role: 'admin' };

    const breach = await createBreach(deps, adminCtx, makeBreachInput());

    // Resolve first time
    await resolveBreach(deps, adminCtx, breach.breachId);

    // Resolve second time — should throw
    await expect(
      resolveBreach(deps, adminCtx, breach.breachId),
    ).rejects.toThrow('already resolved');
  });

  it('resolveBreach emits audit event breach.resolved', async () => {
    const breachRepo = makeMockBreachRepo();
    const auditLogger = makeMockAuditLogger();
    const deps = makeServiceDeps({ breachRepo, auditLogger });
    const adminCtx = { userId: 'admin-1', role: 'admin' };

    const breach = await createBreach(deps, adminCtx, makeBreachInput());

    await resolveBreach(deps, adminCtx, breach.breachId);

    expect(auditLogger.log).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'breach.resolved',
        resourceType: 'breach_record',
        resourceId: breach.breachId,
        actorType: 'admin',
        metadata: expect.objectContaining({
          adminUserId: 'admin-1',
        }),
      }),
    );
  });
});

describe('Platform Service — checkBreachDeadlines', () => {
  it('checkBreachDeadlines identifies overdue notifications', async () => {
    const overdueBreaches = [
      {
        breachId: 'breach-overdue-1',
        awarenessDate: new Date(Date.now() - 4 * 24 * 60 * 60 * 1000),
        status: 'INVESTIGATING',
      },
      {
        breachId: 'breach-overdue-2',
        awarenessDate: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000),
        status: 'NOTIFYING',
      },
    ];
    const breachRepo = makeMockBreachRepo();
    breachRepo.getOverdueBreaches.mockResolvedValue(overdueBreaches);
    const deps = makeServiceDeps({ breachRepo });

    const result = await checkBreachDeadlines(deps);

    expect(result.overdueBreaches).toHaveLength(2);
    expect(result.overdueBreaches[0].breachId).toBe('breach-overdue-1');
    expect(result.overdueBreaches[1].breachId).toBe('breach-overdue-2');
  });

  it('checkBreachDeadlines returns empty when no overdue breaches', async () => {
    const breachRepo = makeMockBreachRepo();
    breachRepo.getOverdueBreaches.mockResolvedValue([]);
    const deps = makeServiceDeps({ breachRepo });

    const result = await checkBreachDeadlines(deps);

    expect(result.overdueBreaches).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Breach Repository Tests
// ---------------------------------------------------------------------------

const DAY_MS_BREACH = 24 * 60 * 60 * 1000;
const HOUR_MS = 60 * 60 * 1000;

function makeBreachData(overrides: Partial<Record<string, any>> = {}) {
  return {
    breachDescription: overrides.breachDescription ?? 'Unauthorized access to patient records',
    breachDate: overrides.breachDate ?? new Date('2026-01-15T10:00:00Z'),
    awarenessDate: overrides.awarenessDate ?? new Date('2026-01-16T08:00:00Z'),
    hiDescription: overrides.hiDescription ?? 'Patient demographic data including PHN',
    includesIihi: overrides.includesIihi ?? true,
    affectedCount: overrides.affectedCount ?? 5,
    riskAssessment: overrides.riskAssessment ?? 'High risk due to IIHI exposure',
    mitigationSteps: overrides.mitigationSteps ?? 'Access revoked, credentials rotated',
    contactName: overrides.contactName ?? 'Jane Admin',
    contactEmail: overrides.contactEmail ?? 'admin@meritum.ca',
    createdBy: overrides.createdBy ?? 'admin-user-1',
  };
}

describe('Breach Repository — createBreachRecord', () => {
  let repo: ReturnType<typeof createBreachRepository>;

  beforeEach(() => {
    subscriptionStore = [];
    paymentStore = [];
    componentStore = [];
    incidentStore = [];
    incidentUpdateStore = [];
    practiceMembershipStore = [];
    amendmentStore = [];
    amendmentResponseStore = [];
    breachRecordStore = [];
    breachAffectedCustodianStore = [];
    breachUpdateStore = [];
    const db = makeMockDb();
    repo = createBreachRepository(db);
  });

  it('createBreachRecord sets evidenceHoldUntil to awarenessDate + 12 months', async () => {
    const awarenessDate = new Date('2026-03-01T12:00:00Z');
    const data = makeBreachData({ awarenessDate });

    const result = await repo.createBreachRecord(data);

    expect(result).toBeDefined();
    expect(result.breachId).toBeDefined();
    expect(result.breachDescription).toBe(data.breachDescription);
    expect(result.awarenessDate).toEqual(awarenessDate);
    expect(result.status).toBe('INVESTIGATING');

    // evidenceHoldUntil should be awarenessDate + 12 months
    const expectedHold = new Date(awarenessDate);
    expectedHold.setMonth(expectedHold.getMonth() + 12);
    expect(result.evidenceHoldUntil).toEqual(expectedHold);
  });

  it('createBreachRecord stores all fields correctly', async () => {
    const data = makeBreachData();
    const result = await repo.createBreachRecord(data);

    expect(result.breachDescription).toBe(data.breachDescription);
    expect(result.breachDate).toEqual(data.breachDate);
    expect(result.hiDescription).toBe(data.hiDescription);
    expect(result.includesIihi).toBe(true);
    expect(result.affectedCount).toBe(5);
    expect(result.riskAssessment).toBe(data.riskAssessment);
    expect(result.mitigationSteps).toBe(data.mitigationSteps);
    expect(result.contactName).toBe(data.contactName);
    expect(result.contactEmail).toBe(data.contactEmail);
    expect(result.createdBy).toBe(data.createdBy);
    expect(result.resolvedAt).toBeNull();
    expect(breachRecordStore).toHaveLength(1);
  });
});

describe('Breach Repository — findBreachById', () => {
  let repo: ReturnType<typeof createBreachRepository>;

  beforeEach(() => {
    subscriptionStore = [];
    paymentStore = [];
    componentStore = [];
    incidentStore = [];
    incidentUpdateStore = [];
    practiceMembershipStore = [];
    amendmentStore = [];
    amendmentResponseStore = [];
    breachRecordStore = [];
    breachAffectedCustodianStore = [];
    breachUpdateStore = [];
    const db = makeMockDb();
    repo = createBreachRepository(db);
  });

  it('findBreachById returns breach with custodian count and updates', async () => {
    const breach = await repo.createBreachRecord(makeBreachData());

    await repo.addAffectedCustodian(breach.breachId, 'prov-1');
    await repo.addAffectedCustodian(breach.breachId, 'prov-2');

    await repo.createBreachUpdate(breach.breachId, {
      updateType: 'INITIAL',
      content: 'Initial notification sent',
      createdBy: 'admin-user-1',
    });

    const found = await repo.findBreachById(breach.breachId);

    expect(found).toBeDefined();
    expect(found!.breachId).toBe(breach.breachId);
    expect(found!.affectedCustodianCount).toBe(2);
    expect(found!.updates).toHaveLength(1);
    expect(found!.updates[0].updateType).toBe('INITIAL');
  });

  it('findBreachById returns undefined for non-existent breach', async () => {
    const found = await repo.findBreachById(crypto.randomUUID());
    expect(found).toBeUndefined();
  });
});

describe('Breach Repository — listBreaches', () => {
  let repo: ReturnType<typeof createBreachRepository>;

  beforeEach(() => {
    subscriptionStore = [];
    paymentStore = [];
    componentStore = [];
    incidentStore = [];
    incidentUpdateStore = [];
    practiceMembershipStore = [];
    amendmentStore = [];
    amendmentResponseStore = [];
    breachRecordStore = [];
    breachAffectedCustodianStore = [];
    breachUpdateStore = [];
    const db = makeMockDb();
    repo = createBreachRepository(db);
  });

  it('listBreaches returns paginated results', async () => {
    await repo.createBreachRecord(makeBreachData({ breachDescription: 'Breach 1' }));
    await repo.createBreachRecord(makeBreachData({ breachDescription: 'Breach 2' }));
    await repo.createBreachRecord(makeBreachData({ breachDescription: 'Breach 3' }));

    const page1 = await repo.listBreaches({ page: 1, pageSize: 2 });
    expect(page1.data).toHaveLength(2);
    expect(page1.total).toBe(3);

    const page2 = await repo.listBreaches({ page: 2, pageSize: 2 });
    expect(page2.data).toHaveLength(1);
    expect(page2.total).toBe(3);
  });

  it('listBreaches filters by status', async () => {
    const b1 = await repo.createBreachRecord(makeBreachData());
    await repo.createBreachRecord(makeBreachData());
    await repo.updateBreachStatus(b1.breachId, 'RESOLVED');

    const investigating = await repo.listBreaches({ status: 'INVESTIGATING', page: 1, pageSize: 10 });
    expect(investigating.data).toHaveLength(1);
    expect(investigating.total).toBe(1);

    const resolved = await repo.listBreaches({ status: 'RESOLVED', page: 1, pageSize: 10 });
    expect(resolved.data).toHaveLength(1);
    expect(resolved.total).toBe(1);
  });
});

describe('Breach Repository — updateBreachStatus', () => {
  let repo: ReturnType<typeof createBreachRepository>;

  beforeEach(() => {
    subscriptionStore = [];
    paymentStore = [];
    componentStore = [];
    incidentStore = [];
    incidentUpdateStore = [];
    practiceMembershipStore = [];
    amendmentStore = [];
    amendmentResponseStore = [];
    breachRecordStore = [];
    breachAffectedCustodianStore = [];
    breachUpdateStore = [];
    const db = makeMockDb();
    repo = createBreachRepository(db);
  });

  it('updateBreachStatus sets resolvedAt when status is RESOLVED', async () => {
    const breach = await repo.createBreachRecord(makeBreachData());

    const beforeResolve = new Date();
    const updated = await repo.updateBreachStatus(breach.breachId, 'RESOLVED');

    expect(updated).toBeDefined();
    expect(updated!.status).toBe('RESOLVED');
    expect(updated!.resolvedAt).toBeDefined();
    expect(updated!.resolvedAt).not.toBeNull();
    expect(updated!.resolvedAt!.getTime()).toBeGreaterThanOrEqual(beforeResolve.getTime());
  });

  it('updateBreachStatus does not set resolvedAt for non-RESOLVED status', async () => {
    const breach = await repo.createBreachRecord(makeBreachData());

    const updated = await repo.updateBreachStatus(breach.breachId, 'NOTIFICATION_SENT');

    expect(updated).toBeDefined();
    expect(updated!.status).toBe('NOTIFICATION_SENT');
    expect(updated!.resolvedAt).toBeNull();
  });
});

describe('Breach Repository — affected custodians', () => {
  let repo: ReturnType<typeof createBreachRepository>;

  beforeEach(() => {
    subscriptionStore = [];
    paymentStore = [];
    componentStore = [];
    incidentStore = [];
    incidentUpdateStore = [];
    practiceMembershipStore = [];
    amendmentStore = [];
    amendmentResponseStore = [];
    breachRecordStore = [];
    breachAffectedCustodianStore = [];
    breachUpdateStore = [];
    const db = makeMockDb();
    repo = createBreachRepository(db);
  });

  it('addAffectedCustodian links provider to breach', async () => {
    const breach = await repo.createBreachRecord(makeBreachData());

    const custodian = await repo.addAffectedCustodian(breach.breachId, 'provider-123');

    expect(custodian).toBeDefined();
    expect(custodian.id).toBeDefined();
    expect(custodian.breachId).toBe(breach.breachId);
    expect(custodian.providerId).toBe('provider-123');
    expect(custodian.initialNotifiedAt).toBeNull();
    expect(custodian.notificationMethod).toBeNull();
  });

  it('markCustodianNotified sets timestamp and method', async () => {
    const breach = await repo.createBreachRecord(makeBreachData());
    await repo.addAffectedCustodian(breach.breachId, 'provider-456');

    const beforeNotify = new Date();
    const notified = await repo.markCustodianNotified(
      breach.breachId,
      'provider-456',
      'EMAIL',
    );

    expect(notified).toBeDefined();
    expect(notified!.initialNotifiedAt).toBeInstanceOf(Date);
    expect(notified!.initialNotifiedAt!.getTime()).toBeGreaterThanOrEqual(beforeNotify.getTime());
    expect(notified!.notificationMethod).toBe('EMAIL');
  });

  it('getUnnotifiedCustodians returns only unnotified', async () => {
    const breach = await repo.createBreachRecord(makeBreachData());

    await repo.addAffectedCustodian(breach.breachId, 'prov-notified');
    await repo.addAffectedCustodian(breach.breachId, 'prov-unnotified-1');
    await repo.addAffectedCustodian(breach.breachId, 'prov-unnotified-2');

    // Notify one custodian
    await repo.markCustodianNotified(breach.breachId, 'prov-notified', 'EMAIL');

    const unnotified = await repo.getUnnotifiedCustodians(breach.breachId);

    expect(unnotified).toHaveLength(2);
    const providerIds = unnotified.map((c) => c.providerId);
    expect(providerIds).toContain('prov-unnotified-1');
    expect(providerIds).toContain('prov-unnotified-2');
    expect(providerIds).not.toContain('prov-notified');
  });

  it('getUnnotifiedCustodians returns empty when all notified', async () => {
    const breach = await repo.createBreachRecord(makeBreachData());

    await repo.addAffectedCustodian(breach.breachId, 'prov-a');
    await repo.markCustodianNotified(breach.breachId, 'prov-a', 'IN_APP');

    const unnotified = await repo.getUnnotifiedCustodians(breach.breachId);
    expect(unnotified).toHaveLength(0);
  });
});

describe('Breach Repository — breach updates', () => {
  let repo: ReturnType<typeof createBreachRepository>;

  beforeEach(() => {
    subscriptionStore = [];
    paymentStore = [];
    componentStore = [];
    incidentStore = [];
    incidentUpdateStore = [];
    practiceMembershipStore = [];
    amendmentStore = [];
    amendmentResponseStore = [];
    breachRecordStore = [];
    breachAffectedCustodianStore = [];
    breachUpdateStore = [];
    const db = makeMockDb();
    repo = createBreachRepository(db);
  });

  it('createBreachUpdate appends to history', async () => {
    const breach = await repo.createBreachRecord(makeBreachData());

    const update1 = await repo.createBreachUpdate(breach.breachId, {
      updateType: 'INITIAL',
      content: 'Initial notification to OIPC',
      createdBy: 'admin-user-1',
    });

    expect(update1).toBeDefined();
    expect(update1.updateId).toBeDefined();
    expect(update1.breachId).toBe(breach.breachId);
    expect(update1.updateType).toBe('INITIAL');
    expect(update1.content).toBe('Initial notification to OIPC');
    expect(update1.sentAt).toBeInstanceOf(Date);

    const update2 = await repo.createBreachUpdate(breach.breachId, {
      updateType: 'SUPPLEMENTARY',
      content: 'Additional affected individuals identified',
      createdBy: 'admin-user-1',
    });

    expect(update2.updateType).toBe('SUPPLEMENTARY');

    // Verify both updates are in the store
    expect(breachUpdateStore).toHaveLength(2);
  });

  it('listBreachUpdates returns all updates ordered by sentAt', async () => {
    const breach = await repo.createBreachRecord(makeBreachData());

    await repo.createBreachUpdate(breach.breachId, {
      updateType: 'INITIAL',
      content: 'First update',
      createdBy: 'admin-1',
    });

    await repo.createBreachUpdate(breach.breachId, {
      updateType: 'SUPPLEMENTARY',
      content: 'Second update',
      createdBy: 'admin-1',
    });

    await repo.createBreachUpdate(breach.breachId, {
      updateType: 'SUPPLEMENTARY',
      content: 'Third update',
      createdBy: 'admin-1',
    });

    const updates = await repo.listBreachUpdates(breach.breachId);

    expect(updates).toHaveLength(3);
    expect(updates[0].content).toBe('First update');
    expect(updates[1].content).toBe('Second update');
    expect(updates[2].content).toBe('Third update');
  });

  it('listBreachUpdates returns empty for breach with no updates', async () => {
    const breach = await repo.createBreachRecord(makeBreachData());
    const updates = await repo.listBreachUpdates(breach.breachId);
    expect(updates).toHaveLength(0);
  });
});

describe('Breach Repository — getOverdueBreaches', () => {
  let repo: ReturnType<typeof createBreachRepository>;

  beforeEach(() => {
    subscriptionStore = [];
    paymentStore = [];
    componentStore = [];
    incidentStore = [];
    incidentUpdateStore = [];
    practiceMembershipStore = [];
    amendmentStore = [];
    amendmentResponseStore = [];
    breachRecordStore = [];
    breachAffectedCustodianStore = [];
    breachUpdateStore = [];
    const db = makeMockDb();
    repo = createBreachRepository(db);
  });

  it('getOverdueBreaches returns breaches past 72h with unnotified custodians', async () => {
    // Breach awareness 4 days ago — well past 72h
    const awarenessDate = new Date(Date.now() - 4 * DAY_MS_BREACH);
    const breach = await repo.createBreachRecord(
      makeBreachData({ awarenessDate }),
    );

    // Add unnotified custodian
    await repo.addAffectedCustodian(breach.breachId, 'prov-overdue');

    const overdue = await repo.getOverdueBreaches();

    expect(overdue).toHaveLength(1);
    expect(overdue[0].breachId).toBe(breach.breachId);
  });

  it('getOverdueBreaches excludes resolved breaches', async () => {
    const awarenessDate = new Date(Date.now() - 4 * DAY_MS_BREACH);
    const breach = await repo.createBreachRecord(
      makeBreachData({ awarenessDate }),
    );
    await repo.addAffectedCustodian(breach.breachId, 'prov-resolved');

    // Resolve the breach
    await repo.updateBreachStatus(breach.breachId, 'RESOLVED');

    const overdue = await repo.getOverdueBreaches();
    expect(overdue).toHaveLength(0);
  });

  it('getOverdueBreaches excludes breaches where all custodians are notified', async () => {
    const awarenessDate = new Date(Date.now() - 4 * DAY_MS_BREACH);
    const breach = await repo.createBreachRecord(
      makeBreachData({ awarenessDate }),
    );
    await repo.addAffectedCustodian(breach.breachId, 'prov-all-notified');
    await repo.markCustodianNotified(breach.breachId, 'prov-all-notified', 'EMAIL');

    const overdue = await repo.getOverdueBreaches();
    expect(overdue).toHaveLength(0);
  });

  it('getOverdueBreaches excludes breaches within 72h window', async () => {
    // Breach awareness 1 day ago — within 72h
    const awarenessDate = new Date(Date.now() - 1 * DAY_MS_BREACH);
    const breach = await repo.createBreachRecord(
      makeBreachData({ awarenessDate }),
    );
    await repo.addAffectedCustodian(breach.breachId, 'prov-within-window');

    const overdue = await repo.getOverdueBreaches();
    expect(overdue).toHaveLength(0);
  });

  it('getOverdueBreaches handles mixed scenarios correctly', async () => {
    // Breach 1: overdue, unnotified — should be returned
    const b1 = await repo.createBreachRecord(
      makeBreachData({
        awarenessDate: new Date(Date.now() - 5 * DAY_MS_BREACH),
        breachDescription: 'Overdue breach',
      }),
    );
    await repo.addAffectedCustodian(b1.breachId, 'prov-b1');

    // Breach 2: overdue, but all notified — should NOT be returned
    const b2 = await repo.createBreachRecord(
      makeBreachData({
        awarenessDate: new Date(Date.now() - 4 * DAY_MS_BREACH),
        breachDescription: 'Notified breach',
      }),
    );
    await repo.addAffectedCustodian(b2.breachId, 'prov-b2');
    await repo.markCustodianNotified(b2.breachId, 'prov-b2', 'EMAIL');

    // Breach 3: within 72h, unnotified — should NOT be returned
    const b3 = await repo.createBreachRecord(
      makeBreachData({
        awarenessDate: new Date(Date.now() - 2 * HOUR_MS),
        breachDescription: 'Recent breach',
      }),
    );
    await repo.addAffectedCustodian(b3.breachId, 'prov-b3');

    // Breach 4: resolved — should NOT be returned
    const b4 = await repo.createBreachRecord(
      makeBreachData({
        awarenessDate: new Date(Date.now() - 10 * DAY_MS_BREACH),
        breachDescription: 'Resolved breach',
      }),
    );
    await repo.addAffectedCustodian(b4.breachId, 'prov-b4');
    await repo.updateBreachStatus(b4.breachId, 'RESOLVED');

    const overdue = await repo.getOverdueBreaches();

    expect(overdue).toHaveLength(1);
    expect(overdue[0].breachId).toBe(b1.breachId);
  });
});

// ===========================================================================
// Export Repository — IMA-050: Complete Health Information Export
// ===========================================================================

function resetAllExportStores() {
  exportPatientStore = [];
  exportClaimStore = [];
  exportClaimAuditStore = [];
  exportShiftStore = [];
  exportClaimExportStore = [];
  exportAhcipDetailStore = [];
  exportAhcipBatchStore = [];
  exportWcbDetailStore = [];
  exportWcbBatchStore = [];
  exportWcbRemittanceStore = [];
  exportProviderStore = [];
  exportBaStore = [];
  exportLocationStore = [];
  exportWcbConfigStore = [];
  exportDelegateStore = [];
  exportSubmPrefStore = [];
  exportHlinkStore = [];
  exportPcpcmEnrolmentStore = [];
  exportPcpcmPaymentStore = [];
  exportPcpcmPanelStore = [];
  exportAnalyticsCacheStore = [];
  exportReportStore = [];
  exportReportSubStore = [];
  exportAiLearningStore = [];
  exportAiSuggestionStore = [];
  exportEdShiftStore = [];
  exportFavCodeStore = [];
  exportAuditLogStore = [];
}

function resetAllStoresForExport() {
  subscriptionStore = [];
  paymentStore = [];
  componentStore = [];
  incidentStore = [];
  incidentUpdateStore = [];
  practiceMembershipStore = [];
  amendmentStore = [];
  amendmentResponseStore = [];
  breachRecordStore = [];
  breachAffectedCustodianStore = [];
  breachUpdateStore = [];
  resetAllExportStores();
}

describe('Export Repository — getCompleteHealthInformation (IMA-050)', () => {
  let repo: ReturnType<typeof createExportRepository>;
  const PROVIDER_ID = 'provider-export-001';
  const OTHER_PROVIDER_ID = 'provider-export-002';

  beforeEach(() => {
    resetAllStoresForExport();
    const db = makeMockDb();
    repo = createExportRepository(db);
  });

  it('getCompleteHealthInformation returns all entity types', async () => {
    // Seed data for our provider
    exportPatientStore.push({ patientId: 'p1', providerId: PROVIDER_ID, isActive: true });
    exportClaimStore.push({ claimId: 'c1', physicianId: PROVIDER_ID, status: 'DRAFT' });
    exportShiftStore.push({ shiftId: 's1', physicianId: PROVIDER_ID });
    exportClaimExportStore.push({ exportId: 'e1', physicianId: PROVIDER_ID });
    exportAhcipBatchStore.push({ batchId: 'ab1', physicianId: PROVIDER_ID });
    exportWcbBatchStore.push({ batchId: 'wb1', physicianId: PROVIDER_ID });
    exportWcbRemittanceStore.push({ importId: 'wr1', physicianId: PROVIDER_ID });
    exportProviderStore.push({ providerId: PROVIDER_ID, fullName: 'Dr. Export' });
    exportBaStore.push({ baId: 'ba1', providerId: PROVIDER_ID });
    exportLocationStore.push({ locationId: 'loc1', providerId: PROVIDER_ID });
    exportWcbConfigStore.push({ configId: 'wc1', providerId: PROVIDER_ID });
    exportDelegateStore.push({ relationshipId: 'dr1', physicianId: PROVIDER_ID });
    exportSubmPrefStore.push({ preferenceId: 'sp1', providerId: PROVIDER_ID });
    exportHlinkStore.push({ configId: 'hl1', providerId: PROVIDER_ID });
    exportPcpcmEnrolmentStore.push({ enrolmentId: 'pe1', providerId: PROVIDER_ID });
    exportPcpcmPaymentStore.push({ paymentId: 'pp1', providerId: PROVIDER_ID });
    exportPcpcmPanelStore.push({ estimateId: 'pn1', providerId: PROVIDER_ID });
    exportAnalyticsCacheStore.push({ cacheId: 'ac1', providerId: PROVIDER_ID });
    exportReportStore.push({ reportId: 'r1', providerId: PROVIDER_ID });
    exportReportSubStore.push({ subscriptionId: 'rs1', providerId: PROVIDER_ID });
    exportAiLearningStore.push({ learningId: 'al1', providerId: PROVIDER_ID });
    exportAiSuggestionStore.push({ eventId: 'as1', providerId: PROVIDER_ID });
    exportEdShiftStore.push({ shiftId: 'es1', providerId: PROVIDER_ID });
    exportFavCodeStore.push({ favouriteId: 'fc1', providerId: PROVIDER_ID });
    subscriptionStore.push({
      subscriptionId: 'sub1',
      providerId: PROVIDER_ID,
      plan: 'STANDARD_MONTHLY',
      status: 'ACTIVE',
    });
    amendmentResponseStore.push({ responseId: 'ar1', providerId: PROVIDER_ID, amendmentId: 'a1' });
    exportAuditLogStore.push({ logId: 'log1', userId: PROVIDER_ID, action: 'LOGIN' });

    const result = await repo.getCompleteHealthInformation(PROVIDER_ID);

    // Verify all entity types are present
    expect(result.patients).toHaveLength(1);
    expect(result.claims).toHaveLength(1);
    expect(result.shifts).toHaveLength(1);
    expect(result.claimExports).toHaveLength(1);
    expect(result.ahcipBatches).toHaveLength(1);
    expect(result.wcbBatches).toHaveLength(1);
    expect(result.wcbRemittanceImports).toHaveLength(1);
    expect(result.provider).not.toBeNull();
    expect(result.businessArrangements).toHaveLength(1);
    expect(result.practiceLocations).toHaveLength(1);
    expect(result.wcbConfigurations).toHaveLength(1);
    expect(result.delegateRelationships).toHaveLength(1);
    expect(result.submissionPreferences).toHaveLength(1);
    expect(result.hlinkConfigurations).toHaveLength(1);
    expect(result.pcpcmEnrolments).toHaveLength(1);
    expect(result.pcpcmPayments).toHaveLength(1);
    expect(result.pcpcmPanelEstimates).toHaveLength(1);
    expect(result.analyticsCache).toHaveLength(1);
    expect(result.generatedReports).toHaveLength(1);
    expect(result.reportSubscriptions).toHaveLength(1);
    expect(result.aiProviderLearning).toHaveLength(1);
    expect(result.aiSuggestionEvents).toHaveLength(1);
    expect(result.edShifts).toHaveLength(1);
    expect(result.favouriteCodes).toHaveLength(1);
    expect(result.subscription).not.toBeNull();
    expect(result.imaAmendmentResponses).toHaveLength(1);
    expect(result.auditLog).toHaveLength(1);
  });

  it('all queries scoped to the specified providerId', async () => {
    // Seed data for BOTH providers
    exportPatientStore.push(
      { patientId: 'p1', providerId: PROVIDER_ID, isActive: true },
      { patientId: 'p2', providerId: OTHER_PROVIDER_ID, isActive: true },
    );
    exportClaimStore.push(
      { claimId: 'c1', physicianId: PROVIDER_ID, status: 'SUBMITTED' },
      { claimId: 'c2', physicianId: OTHER_PROVIDER_ID, status: 'DRAFT' },
    );
    exportProviderStore.push(
      { providerId: PROVIDER_ID, fullName: 'Dr. Ours' },
      { providerId: OTHER_PROVIDER_ID, fullName: 'Dr. Theirs' },
    );
    exportBaStore.push(
      { baId: 'ba1', providerId: PROVIDER_ID },
      { baId: 'ba2', providerId: OTHER_PROVIDER_ID },
    );
    exportEdShiftStore.push(
      { shiftId: 'es1', providerId: PROVIDER_ID },
      { shiftId: 'es2', providerId: OTHER_PROVIDER_ID },
    );
    exportFavCodeStore.push(
      { favouriteId: 'fc1', providerId: PROVIDER_ID },
      { favouriteId: 'fc2', providerId: OTHER_PROVIDER_ID },
    );
    exportAiSuggestionStore.push(
      { eventId: 'as1', providerId: PROVIDER_ID },
      { eventId: 'as2', providerId: OTHER_PROVIDER_ID },
    );
    subscriptionStore.push(
      { subscriptionId: 'sub1', providerId: PROVIDER_ID, status: 'ACTIVE' },
      { subscriptionId: 'sub2', providerId: OTHER_PROVIDER_ID, status: 'ACTIVE' },
    );
    exportAuditLogStore.push(
      { logId: 'log1', userId: PROVIDER_ID, action: 'LOGIN' },
      { logId: 'log2', userId: OTHER_PROVIDER_ID, action: 'LOGIN' },
    );

    const result = await repo.getCompleteHealthInformation(PROVIDER_ID);

    // Verify ONLY provider's own data is returned
    expect(result.patients).toHaveLength(1);
    expect((result.patients[0] as any).providerId).toBe(PROVIDER_ID);

    expect(result.claims).toHaveLength(1);
    expect((result.claims[0] as any).physicianId).toBe(PROVIDER_ID);

    expect((result.provider as any).providerId).toBe(PROVIDER_ID);

    expect(result.businessArrangements).toHaveLength(1);
    expect((result.businessArrangements[0] as any).providerId).toBe(PROVIDER_ID);

    expect(result.edShifts).toHaveLength(1);
    expect((result.edShifts[0] as any).providerId).toBe(PROVIDER_ID);

    expect(result.favouriteCodes).toHaveLength(1);
    expect((result.favouriteCodes[0] as any).providerId).toBe(PROVIDER_ID);

    expect(result.aiSuggestionEvents).toHaveLength(1);
    expect((result.aiSuggestionEvents[0] as any).providerId).toBe(PROVIDER_ID);

    expect((result.subscription as any).providerId).toBe(PROVIDER_ID);

    expect(result.auditLog).toHaveLength(1);
    expect((result.auditLog[0] as any).userId).toBe(PROVIDER_ID);
  });

  it('includes inactive/soft-deleted patients', async () => {
    exportPatientStore.push(
      { patientId: 'p-active', providerId: PROVIDER_ID, isActive: true },
      { patientId: 'p-inactive', providerId: PROVIDER_ID, isActive: false },
    );

    const result = await repo.getCompleteHealthInformation(PROVIDER_ID);

    // Both active and inactive patients must be included
    expect(result.patients).toHaveLength(2);
    const patientIds = result.patients.map((p: any) => p.patientId);
    expect(patientIds).toContain('p-active');
    expect(patientIds).toContain('p-inactive');
  });

  it('includes claims in all states', async () => {
    const states = ['DRAFT', 'VALIDATED', 'QUEUED', 'SUBMITTED', 'ASSESSED', 'PAID', 'REJECTED', 'CANCELLED'];
    for (const status of states) {
      exportClaimStore.push({
        claimId: `claim-${status.toLowerCase()}`,
        physicianId: PROVIDER_ID,
        status,
      });
    }

    const result = await repo.getCompleteHealthInformation(PROVIDER_ID);

    expect(result.claims).toHaveLength(states.length);
    const returnedStatuses = result.claims.map((c: any) => c.status);
    for (const status of states) {
      expect(returnedStatuses).toContain(status);
    }
  });

  it('returns empty arrays for entity types with no data', async () => {
    // Don't seed any data
    const result = await repo.getCompleteHealthInformation(PROVIDER_ID);

    expect(result.patients).toEqual([]);
    expect(result.claims).toEqual([]);
    expect(result.claimAuditHistory).toEqual([]);
    expect(result.shifts).toEqual([]);
    expect(result.claimExports).toEqual([]);
    expect(result.ahcipClaimDetails).toEqual([]);
    expect(result.ahcipBatches).toEqual([]);
    expect(result.wcbClaimDetails).toEqual([]);
    expect(result.wcbBatches).toEqual([]);
    expect(result.wcbRemittanceImports).toEqual([]);
    expect(result.provider).toBeNull();
    expect(result.businessArrangements).toEqual([]);
    expect(result.practiceLocations).toEqual([]);
    expect(result.wcbConfigurations).toEqual([]);
    expect(result.delegateRelationships).toEqual([]);
    expect(result.submissionPreferences).toEqual([]);
    expect(result.hlinkConfigurations).toEqual([]);
    expect(result.pcpcmEnrolments).toEqual([]);
    expect(result.pcpcmPayments).toEqual([]);
    expect(result.pcpcmPanelEstimates).toEqual([]);
    expect(result.analyticsCache).toEqual([]);
    expect(result.generatedReports).toEqual([]);
    expect(result.reportSubscriptions).toEqual([]);
    expect(result.aiProviderLearning).toEqual([]);
    expect(result.aiSuggestionEvents).toEqual([]);
    expect(result.edShifts).toEqual([]);
    expect(result.favouriteCodes).toEqual([]);
    expect(result.subscription).toBeNull();
    expect(result.imaAmendmentResponses).toEqual([]);
    expect(result.auditLog).toEqual([]);
  });
});

// ===========================================================================
// IMA-060: Data Destruction Pipeline Tests
// ===========================================================================

describe('Data Destruction Pipeline — IMA-060', () => {
  function makeDeletionDeps() {
    const cancelledSub = {
      subscriptionId: 'sub-destruction-060',
      providerId: 'user-destruction-060',
      stripeCustomerId: 'cus_dest_060',
      stripeSubscriptionId: 'sub_stripe_dest_060',
      status: 'CANCELLED',
      deletionScheduledAt: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000),
    };

    const subRepo = makeMockSubscriptionRepo();
    subRepo.findSubscriptionsDueForDeletion = vi.fn().mockResolvedValue([cancelledSub]);

    const dataDeletionRepo = makeMockDataDeletionRepo();
    const auditLogger = makeMockAuditLogger();
    const destructionTrackingRepo = makeMockDestructionTrackingRepo();
    const spacesFileClient = makeMockSpacesFileClient();
    const emitter = makeMockEventEmitter();

    const deps = makeServiceDeps({
      subscriptionRepo: subRepo,
      auditLogger,
      dataDeletionRepo,
      destructionTrackingRepo,
      spacesFileClient,
    });

    return { deps, cancelledSub, dataDeletionRepo, auditLogger, destructionTrackingRepo, spacesFileClient, emitter };
  }

  it('runDeletionCheck creates destruction tracking record', async () => {
    const { deps, destructionTrackingRepo, emitter } = makeDeletionDeps();

    await runDeletionCheck(deps, emitter);

    expect(destructionTrackingRepo.createTrackingRecord).toHaveBeenCalledWith(
      expect.objectContaining({
        providerId: 'user-destruction-060',
        activeDeletedAt: expect.any(Date),
        backupPurgeDeadline: expect.any(Date),
      }),
    );
  });

  it('deletion cleans up DO Spaces files', async () => {
    const { deps, spacesFileClient, emitter } = makeDeletionDeps();

    await runDeletionCheck(deps, emitter);

    expect(spacesFileClient.deleteProviderFiles).toHaveBeenCalledWith('user-destruction-060');
  });

  it('backupPurgeDeadline set to activeDeletedAt + 90 days', async () => {
    const { deps, destructionTrackingRepo, emitter } = makeDeletionDeps();

    await runDeletionCheck(deps, emitter);

    const call = destructionTrackingRepo.createTrackingRecord.mock.calls[0][0];
    const activeDeletedAt = call.activeDeletedAt as Date;
    const backupPurgeDeadline = call.backupPurgeDeadline as Date;

    const diffMs = backupPurgeDeadline.getTime() - activeDeletedAt.getTime();
    const diffDays = Math.round(diffMs / (24 * 60 * 60 * 1000));
    expect(diffDays).toBe(90);
  });

  it('deletion records filesDeletedAt after Spaces cleanup', async () => {
    const { deps, destructionTrackingRepo, emitter } = makeDeletionDeps();

    await runDeletionCheck(deps, emitter);

    expect(destructionTrackingRepo.updateFilesDeletedAt).toHaveBeenCalledWith(
      'user-destruction-060',
      expect.any(Date),
    );
  });

  it('deletion stores lastKnownEmail from user record before deactivation', async () => {
    const { deps, destructionTrackingRepo, emitter } = makeDeletionDeps();

    await runDeletionCheck(deps, emitter);

    const call = destructionTrackingRepo.createTrackingRecord.mock.calls[0][0];
    expect(call.lastKnownEmail).toBe('dr.smith@example.com');
  });

  it('deletion emits audit for active deletion and files deletion', async () => {
    const { deps, auditLogger, emitter } = makeDeletionDeps();

    await runDeletionCheck(deps, emitter);

    expect(auditLogger.log).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'destruction.active_deleted',
        resourceType: 'destruction_tracking',
        resourceId: 'user-destruction-060',
      }),
    );
    expect(auditLogger.log).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'destruction.files_deleted',
        resourceType: 'destruction_tracking',
        resourceId: 'user-destruction-060',
      }),
    );
  });

  it('markBackupPurged sets timestamp', async () => {
    const destructionTrackingRepo = makeMockDestructionTrackingRepo();
    // Pre-seed a tracking record
    await destructionTrackingRepo.createTrackingRecord({
      providerId: 'provider-purge',
      lastKnownEmail: 'test@meritum.ca',
      activeDeletedAt: new Date(),
      backupPurgeDeadline: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000),
    });

    const auditLogger = makeMockAuditLogger();
    const deps = makeServiceDeps({ auditLogger, destructionTrackingRepo });

    const result = await markBackupPurged(
      deps,
      { userId: 'admin-1', role: 'ADMIN' },
      'provider-purge',
    );

    expect(result.backupPurgedAt).toBeInstanceOf(Date);
    expect(destructionTrackingRepo.updateBackupPurgedAt).toHaveBeenCalledWith(
      'provider-purge',
      expect.any(Date),
    );
    expect(auditLogger.log).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'destruction.backup_purged',
        resourceType: 'destruction_tracking',
        resourceId: 'provider-purge',
        actorType: 'admin',
      }),
    );
  });

  it('markBackupPurged rejects non-admin', async () => {
    const destructionTrackingRepo = makeMockDestructionTrackingRepo();
    const deps = makeServiceDeps({ destructionTrackingRepo });

    await expect(
      markBackupPurged(
        deps,
        { userId: 'physician-1', role: 'PHYSICIAN' },
        'provider-123',
      ),
    ).rejects.toThrow('Only admin can mark backup purges');
  });

  it('markBackupPurged rejects when already purged', async () => {
    const destructionTrackingRepo = makeMockDestructionTrackingRepo();
    await destructionTrackingRepo.createTrackingRecord({
      providerId: 'provider-already-purged',
      lastKnownEmail: 'test@meritum.ca',
      activeDeletedAt: new Date(),
      backupPurgeDeadline: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000),
    });
    // Manually mark as purged
    destructionTrackingRepo._store[0].backupPurgedAt = new Date();

    const deps = makeServiceDeps({ destructionTrackingRepo });

    await expect(
      markBackupPurged(
        deps,
        { userId: 'admin-1', role: 'ADMIN' },
        'provider-already-purged',
      ),
    ).rejects.toThrow('Backup already marked as purged');
  });

  it('markBackupPurged rejects when tracking record not found', async () => {
    const destructionTrackingRepo = makeMockDestructionTrackingRepo();
    const deps = makeServiceDeps({ destructionTrackingRepo });

    await expect(
      markBackupPurged(
        deps,
        { userId: 'admin-1', role: 'ADMIN' },
        'nonexistent-provider',
      ),
    ).rejects.toThrow('not found');
  });

  it('runDestructionConfirmation sends email when backup purged', async () => {
    const destructionTrackingRepo = makeMockDestructionTrackingRepo();
    await destructionTrackingRepo.createTrackingRecord({
      providerId: 'provider-confirm',
      lastKnownEmail: 'physician@clinic.ca',
      activeDeletedAt: new Date(Date.now() - 100 * 24 * 60 * 60 * 1000),
      backupPurgeDeadline: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000),
    });
    // Mark backup as purged
    destructionTrackingRepo._store[0].backupPurgedAt = new Date();

    const auditLogger = makeMockAuditLogger();
    const deps = makeServiceDeps({ auditLogger, destructionTrackingRepo });
    const emitter = makeMockEventEmitter();

    const result = await runDestructionConfirmation(deps, emitter);

    expect(result.confirmed).toBe(1);
    expect(emitter.emit).toHaveBeenCalledWith(
      'DATA_DESTRUCTION_CONFIRMED',
      expect.objectContaining({
        providerId: 'provider-confirm',
        email: 'physician@clinic.ca',
      }),
    );
    expect(destructionTrackingRepo.updateConfirmationSentAt).toHaveBeenCalledWith(
      'provider-confirm',
      expect.any(Date),
    );
    expect(auditLogger.log).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'destruction.confirmed',
      }),
    );
  });

  it('runDestructionConfirmation alerts admin when deadline passed without purge', async () => {
    const destructionTrackingRepo = makeMockDestructionTrackingRepo();
    await destructionTrackingRepo.createTrackingRecord({
      providerId: 'provider-overdue',
      lastKnownEmail: 'overdue@clinic.ca',
      activeDeletedAt: new Date(Date.now() - 100 * 24 * 60 * 60 * 1000),
      backupPurgeDeadline: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000), // past deadline
    });
    // backupPurgedAt remains null (not purged)

    const deps = makeServiceDeps({ destructionTrackingRepo });
    const emitter = makeMockEventEmitter();

    const result = await runDestructionConfirmation(deps, emitter);

    expect(result.overdueAlerts).toBe(1);
    expect(emitter.emit).toHaveBeenCalledWith(
      'DESTRUCTION_BACKUP_OVERDUE',
      expect.objectContaining({
        providerId: 'provider-overdue',
      }),
    );
  });

  it('confirmation not sent twice (idempotent)', async () => {
    const destructionTrackingRepo = makeMockDestructionTrackingRepo();
    await destructionTrackingRepo.createTrackingRecord({
      providerId: 'provider-idempotent',
      lastKnownEmail: 'idempotent@clinic.ca',
      activeDeletedAt: new Date(Date.now() - 100 * 24 * 60 * 60 * 1000),
      backupPurgeDeadline: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000),
    });
    // Mark as purged and already confirmed
    destructionTrackingRepo._store[0].backupPurgedAt = new Date();
    destructionTrackingRepo._store[0].confirmationSentAt = new Date();

    const deps = makeServiceDeps({ destructionTrackingRepo });
    const emitter = makeMockEventEmitter();

    const result = await runDestructionConfirmation(deps, emitter);

    // findPendingConfirmations filters for confirmationSentAt === null,
    // so this record should NOT appear
    expect(result.confirmed).toBe(0);
    expect(emitter.emit).not.toHaveBeenCalledWith(
      'DATA_DESTRUCTION_CONFIRMED',
      expect.anything(),
    );
  });

  it('runDestructionConfirmation returns 0 when no tracking repo configured', async () => {
    const deps = makeServiceDeps();
    // destructionTrackingRepo is undefined by default
    const result = await runDestructionConfirmation(deps);

    expect(result.confirmed).toBe(0);
    expect(result.overdueAlerts).toBe(0);
  });
});
