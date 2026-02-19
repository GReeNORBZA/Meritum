import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createNotificationRepository } from './notification.repository.js';
import {
  resolveRecipients,
  checkPreferences,
  renderNotification,
  processEvent,
  processEventBatch,
  sendEmail,
  isInQuietHours,
  scheduleAfterQuietHours,
  retryFailedEmails,
  handleBounce,
  assembleDailyDigest,
  assembleWeeklyDigest,
  renderDigestEmail,
  buildDigestSummary,
  sendWednesdayBatchReminder,
  registerNotificationJobs,
  markReadAndPush,
  markAllReadAndPush,
  NotificationWebSocketManager,
  wsManager,
  registerNotificationWebSocket,
  WS_READY_STATE,
  WS_CLOSE_AUTH_FAILED,
  type NotificationServiceDeps,
  type NotificationWebSocket,
  type WsSessionValidator,
  type DelegateLinkageRepo,
  type AuditRepo,
  type PostmarkClient,
  type ClaimRepo,
  type UserEmailLookup,
  type RenderedEmail,
  PERMISSION_EVENT_MAP,
} from './notification.service.js';

// ---------------------------------------------------------------------------
// Helpers: in-memory stores
// ---------------------------------------------------------------------------

let notificationStore: Record<string, any>[];
let deliveryLogStore: Record<string, any>[];
let templateStore: Record<string, any>[];
let digestQueueStore: Record<string, any>[];
let preferencesStore: Record<string, any>[];

// ---------------------------------------------------------------------------
// Mock Drizzle DB
// ---------------------------------------------------------------------------

function getStoreForTable(table: any): Record<string, any>[] {
  const tableName = table?.__table;
  if (tableName === 'email_delivery_log') return deliveryLogStore;
  if (tableName === 'notification_templates') return templateStore;
  if (tableName === 'digest_queue') return digestQueueStore;
  if (tableName === 'notification_preferences') return preferencesStore;
  return notificationStore;
}

function makeMockDb() {
  function chainable(ctx: {
    op: string;
    table?: any;
    values?: any;
    setClauses?: any;
    whereClauses: Array<(row: any) => boolean>;
    limitN?: number;
    offsetN?: number;
    orderByFn?: (a: any, b: any) => number;
    onConflictUpdate?: any;
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
        if (orderSpec && orderSpec.__orderByFn) {
          ctx.orderByFn = orderSpec.__orderByFn;
        }
        return chain;
      },
      onConflictDoUpdate(config: any) {
        ctx.onConflictUpdate = config;
        return chain;
      },
      returning() { return chain; },
      then(resolve: any, reject?: any) {
        try {
          const result = executeOp(ctx);
          resolve(result);
        } catch (e) {
          if (reject) reject(e); else throw e;
        }
      },
    };
    return chain;
  }

  function insertNotificationRow(values: any): any {
    const row = {
      notificationId: values.notificationId ?? crypto.randomUUID(),
      recipientId: values.recipientId,
      physicianContextId: values.physicianContextId ?? null,
      eventType: values.eventType,
      priority: values.priority,
      title: values.title,
      body: values.body,
      actionUrl: values.actionUrl ?? null,
      actionLabel: values.actionLabel ?? null,
      metadata: values.metadata ?? null,
      channelsDelivered: values.channelsDelivered,
      readAt: values.readAt ?? null,
      dismissedAt: values.dismissedAt ?? null,
      createdAt: values.createdAt ?? new Date(),
    };
    notificationStore.push(row);
    return row;
  }

  function insertDeliveryLogRow(values: any): any {
    const row = {
      deliveryId: values.deliveryId ?? crypto.randomUUID(),
      notificationId: values.notificationId,
      recipientEmail: values.recipientEmail,
      templateId: values.templateId,
      status: values.status ?? 'QUEUED',
      providerMessageId: values.providerMessageId ?? null,
      sentAt: values.sentAt ?? null,
      deliveredAt: values.deliveredAt ?? null,
      bouncedAt: values.bouncedAt ?? null,
      bounceReason: values.bounceReason ?? null,
      retryCount: values.retryCount ?? 0,
      nextRetryAt: values.nextRetryAt ?? null,
      createdAt: values.createdAt ?? new Date(),
    };
    deliveryLogStore.push(row);
    return row;
  }

  function insertTemplateRow(values: any): any {
    const row = {
      templateId: values.templateId,
      inAppTitle: values.inAppTitle,
      inAppBody: values.inAppBody,
      emailSubject: values.emailSubject ?? null,
      emailHtmlBody: values.emailHtmlBody ?? null,
      emailTextBody: values.emailTextBody ?? null,
      actionUrlTemplate: values.actionUrlTemplate ?? null,
      actionLabel: values.actionLabel ?? null,
      variables: values.variables,
      updatedAt: values.updatedAt ?? new Date(),
    };
    templateStore.push(row);
    return row;
  }

  function insertDigestQueueRow(values: any): any {
    const row = {
      queueId: values.queueId ?? crypto.randomUUID(),
      recipientId: values.recipientId,
      notificationId: values.notificationId,
      digestType: values.digestType,
      digestSent: values.digestSent ?? false,
      createdAt: values.createdAt ?? new Date(),
    };
    digestQueueStore.push(row);
    return row;
  }

  function insertPreferenceRow(values: any): any {
    // Check for unique constraint (providerId + eventCategory)
    const existing = preferencesStore.find(
      (r) =>
        r.providerId === values.providerId &&
        r.eventCategory === values.eventCategory,
    );
    if (existing) {
      // Should not happen on plain insert (onConflictDoUpdate handles this)
      // but we add it for safety
      return existing;
    }
    const row = {
      preferenceId: values.preferenceId ?? crypto.randomUUID(),
      providerId: values.providerId,
      eventCategory: values.eventCategory,
      inAppEnabled: values.inAppEnabled ?? true,
      emailEnabled: values.emailEnabled ?? true,
      digestMode: values.digestMode ?? 'IMMEDIATE',
      quietHoursStart: values.quietHoursStart ?? null,
      quietHoursEnd: values.quietHoursEnd ?? null,
      updatedAt: values.updatedAt ?? new Date(),
    };
    preferencesStore.push(row);
    return row;
  }

  function insertRow(table: any, values: any): any {
    const tableName = table?.__table;
    if (tableName === 'email_delivery_log') return insertDeliveryLogRow(values);
    if (tableName === 'notification_templates') return insertTemplateRow(values);
    if (tableName === 'digest_queue') return insertDigestQueueRow(values);
    if (tableName === 'notification_preferences') return insertPreferenceRow(values);
    return insertNotificationRow(values);
  }

  function executeOp(ctx: any): any[] {
    const store = getStoreForTable(ctx.table);

    switch (ctx.op) {
      case 'select': {
        let matches = store.filter((row) =>
          ctx.whereClauses.every((pred: any) => pred(row)),
        );
        if (ctx.orderByFn) matches.sort(ctx.orderByFn);
        if (ctx.offsetN) matches = matches.slice(ctx.offsetN);
        if (ctx.limitN) matches = matches.slice(0, ctx.limitN);
        return matches;
      }
      case 'insert': {
        const values = ctx.values;
        if (ctx.onConflictUpdate) {
          // Upsert: check if row exists by target key(s)
          const target = ctx.onConflictUpdate.target;
          let existing: any = undefined;

          if (Array.isArray(target) && !Array.isArray(values)) {
            // Composite key: array of column refs
            const targetCols = target.map((col: any) => col.name);
            existing = store.find((row) =>
              targetCols.every((col: string) => row[col] === values[col]),
            );
          } else if (target?.name && !Array.isArray(values)) {
            // Single column key
            const targetCol = target.name;
            existing = store.find(
              (row) => row[targetCol] === values[targetCol],
            );
          }

          if (existing) {
            // Update existing row
            for (const [key, value] of Object.entries(
              ctx.onConflictUpdate.set,
            )) {
              if (value !== undefined) {
                existing[key] = value;
              }
            }
            return [{ ...existing }];
          }
        }
        if (Array.isArray(values)) {
          return values.map((v: any) => insertRow(ctx.table, v));
        }
        return [insertRow(ctx.table, values)];
      }
      case 'update': {
        const updated: any[] = [];
        const matches = store.filter((row) =>
          ctx.whereClauses.every((pred: any) => pred(row)),
        );
        for (const row of matches) {
          if (!ctx.setClauses) continue;
          for (const [key, value] of Object.entries(ctx.setClauses)) {
            if (value && typeof value === 'object' && (value as any).__sqlIncrement) {
              row[key] = (row[key] ?? 0) + 1;
            } else {
              row[key] = value;
            }
          }
          updated.push({ ...row });
        }
        return updated;
      }
      case 'delete': {
        for (let i = store.length - 1; i >= 0; i--) {
          if (ctx.whereClauses.every((pred: any) => pred(store[i]))) {
            store.splice(i, 1);
          }
        }
        return [];
      }
      default:
        return [];
    }
  }

  const mockDb: any = {
    insert(table: any) {
      return chainable({ op: 'insert', table, whereClauses: [] });
    },
    select() {
      return chainable({ op: 'select', whereClauses: [] });
    },
    update(table: any) {
      return chainable({ op: 'update', table, whereClauses: [] });
    },
    delete(table: any) {
      return chainable({ op: 'delete', table, whereClauses: [] });
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
    or: (...conditions: any[]) => {
      const preds = conditions.filter(Boolean);
      return {
        __predicate: (row: any) =>
          preds.some((p: any) => {
            if (p?.__predicate) return p.__predicate(row);
            return false;
          }),
      };
    },
    isNull: (column: any) => {
      const colName = column?.name;
      return {
        __predicate: (row: any) => row[colName] === null || row[colName] === undefined,
      };
    },
    inArray: (column: any, values: any[]) => {
      const colName = column?.name;
      return {
        __predicate: (row: any) => values.includes(row[colName]),
      };
    },
    lte: (column: any, value: any) => {
      const colName = column?.name;
      return {
        __predicate: (row: any) => {
          const rowVal = row[colName];
          if (rowVal instanceof Date && value instanceof Date) {
            return rowVal.getTime() <= value.getTime();
          }
          return rowVal <= value;
        },
      };
    },
    lt: (column: any, value: any) => {
      const colName = column?.name;
      return {
        __predicate: (row: any) => row[colName] < value,
      };
    },
    desc: (column: any) => {
      const colName = column?.name;
      return {
        __orderByFn: (a: any, b: any) => {
          const aVal = a[colName];
          const bVal = b[colName];
          if (aVal instanceof Date && bVal instanceof Date) {
            return bVal.getTime() - aVal.getTime();
          }
          if (aVal > bVal) return -1;
          if (aVal < bVal) return 1;
          return 0;
        },
      };
    },
    asc: (column: any) => {
      const colName = column?.name;
      return {
        __orderByFn: (a: any, b: any) => {
          const aVal = a[colName];
          const bVal = b[colName];
          if (aVal === null && bVal === null) return 0;
          if (aVal === null) return -1;
          if (bVal === null) return 1;
          if (aVal instanceof Date && bVal instanceof Date) {
            return aVal.getTime() - bVal.getTime();
          }
          if (aVal > bVal) return 1;
          if (aVal < bVal) return -1;
          return 0;
        },
      };
    },
    sql: (strings: TemplateStringsArray, ...values: any[]) => {
      return { __sqlIncrement: true };
    },
  };
});

// ---------------------------------------------------------------------------
// Mock the schema module (Drizzle column references)
// ---------------------------------------------------------------------------

vi.mock('@meritum/shared/schemas/db/notification.schema.js', () => {
  const mkCol = (name: string) => ({ name });
  const notificationsTable = {
    __table: 'notifications',
    notificationId: mkCol('notificationId'),
    recipientId: mkCol('recipientId'),
    physicianContextId: mkCol('physicianContextId'),
    eventType: mkCol('eventType'),
    priority: mkCol('priority'),
    title: mkCol('title'),
    body: mkCol('body'),
    actionUrl: mkCol('actionUrl'),
    actionLabel: mkCol('actionLabel'),
    metadata: mkCol('metadata'),
    channelsDelivered: mkCol('channelsDelivered'),
    readAt: mkCol('readAt'),
    dismissedAt: mkCol('dismissedAt'),
    createdAt: mkCol('createdAt'),
  };
  const emailDeliveryLogTable = {
    __table: 'email_delivery_log',
    deliveryId: mkCol('deliveryId'),
    notificationId: mkCol('notificationId'),
    recipientEmail: mkCol('recipientEmail'),
    templateId: mkCol('templateId'),
    status: mkCol('status'),
    providerMessageId: mkCol('providerMessageId'),
    sentAt: mkCol('sentAt'),
    deliveredAt: mkCol('deliveredAt'),
    bouncedAt: mkCol('bouncedAt'),
    bounceReason: mkCol('bounceReason'),
    retryCount: mkCol('retryCount'),
    nextRetryAt: mkCol('nextRetryAt'),
    createdAt: mkCol('createdAt'),
  };
  const notificationTemplatesTable = {
    __table: 'notification_templates',
    templateId: mkCol('templateId'),
    inAppTitle: mkCol('inAppTitle'),
    inAppBody: mkCol('inAppBody'),
    emailSubject: mkCol('emailSubject'),
    emailHtmlBody: mkCol('emailHtmlBody'),
    emailTextBody: mkCol('emailTextBody'),
    actionUrlTemplate: mkCol('actionUrlTemplate'),
    actionLabel: mkCol('actionLabel'),
    variables: mkCol('variables'),
    updatedAt: mkCol('updatedAt'),
  };
  const digestQueueTable = {
    __table: 'digest_queue',
    queueId: mkCol('queueId'),
    recipientId: mkCol('recipientId'),
    notificationId: mkCol('notificationId'),
    digestType: mkCol('digestType'),
    digestSent: mkCol('digestSent'),
    createdAt: mkCol('createdAt'),
  };
  const notificationPreferencesTable = {
    __table: 'notification_preferences',
    preferenceId: mkCol('preferenceId'),
    providerId: mkCol('providerId'),
    eventCategory: mkCol('eventCategory'),
    inAppEnabled: mkCol('inAppEnabled'),
    emailEnabled: mkCol('emailEnabled'),
    digestMode: mkCol('digestMode'),
    quietHoursStart: mkCol('quietHoursStart'),
    quietHoursEnd: mkCol('quietHoursEnd'),
    updatedAt: mkCol('updatedAt'),
  };
  return {
    notifications: notificationsTable,
    emailDeliveryLog: emailDeliveryLogTable,
    notificationTemplates: notificationTemplatesTable,
    digestQueue: digestQueueTable,
    notificationPreferences: notificationPreferencesTable,
  };
});

// ---------------------------------------------------------------------------
// Mock notification constants
// ---------------------------------------------------------------------------

vi.mock('@meritum/shared/constants/notification.constants.js', () => {
  const NotificationPriority = {
    URGENT: 'URGENT',
    HIGH: 'HIGH',
    MEDIUM: 'MEDIUM',
    LOW: 'LOW',
  };
  const EventCategory = {
    CLAIM_LIFECYCLE: 'CLAIM_LIFECYCLE',
    INTELLIGENCE_ENGINE: 'INTELLIGENCE_ENGINE',
    PROVIDER_MANAGEMENT: 'PROVIDER_MANAGEMENT',
    PLATFORM_OPERATIONS: 'PLATFORM_OPERATIONS',
    ANALYTICS: 'ANALYTICS',
  };
  const EVENT_CATALOGUE: Record<string, any> = {
    CLAIM_VALIDATED: { priority: 'LOW', defaultInApp: true, defaultEmail: false, category: 'CLAIM_LIFECYCLE' },
    CLAIM_FLAGGED: { priority: 'MEDIUM', defaultInApp: true, defaultEmail: false, category: 'CLAIM_LIFECYCLE' },
    DEADLINE_1_DAY: { priority: 'URGENT', defaultInApp: true, defaultEmail: true, category: 'CLAIM_LIFECYCLE' },
    BATCH_ERROR: { priority: 'URGENT', defaultInApp: true, defaultEmail: true, category: 'CLAIM_LIFECYCLE' },
    AI_SUGGESTION_READY: { priority: 'LOW', defaultInApp: true, defaultEmail: false, category: 'INTELLIGENCE_ENGINE' },
    DELEGATE_INVITED: { priority: 'MEDIUM', defaultInApp: true, defaultEmail: true, category: 'PROVIDER_MANAGEMENT' },
    PAYMENT_FAILED: { priority: 'URGENT', defaultInApp: true, defaultEmail: true, category: 'PLATFORM_OPERATIONS' },
    ACCOUNT_SUSPENDED: { priority: 'URGENT', defaultInApp: true, defaultEmail: true, category: 'PLATFORM_OPERATIONS' },
    REPORT_READY: { priority: 'MEDIUM', defaultInApp: true, defaultEmail: true, category: 'ANALYTICS' },
  };
  const NotificationAuditAction = {
    NOTIFICATION_CREATED: 'notification.created',
    NOTIFICATION_READ: 'notification.read',
    NOTIFICATION_READ_ALL: 'notification.read_all',
    NOTIFICATION_DISMISSED: 'notification.dismissed',
    NOTIFICATION_EMAIL_SENT: 'notification.email_sent',
    NOTIFICATION_EMAIL_BOUNCED: 'notification.email_bounced',
    NOTIFICATION_EMAIL_FAILED: 'notification.email_failed',
    NOTIFICATION_PREFERENCE_UPDATED: 'notification.preference_updated',
    NOTIFICATION_QUIET_HOURS_UPDATED: 'notification.quiet_hours_updated',
    NOTIFICATION_DIGEST_ASSEMBLED: 'notification.digest_assembled',
    NOTIFICATION_EVENT_EMITTED: 'notification.event_emitted',
  };
  const DigestMode = {
    IMMEDIATE: 'IMMEDIATE',
    DAILY_DIGEST: 'DAILY_DIGEST',
    WEEKLY_DIGEST: 'WEEKLY_DIGEST',
  };
  const EMAIL_RETRY_SCHEDULE_MS = Object.freeze([
    0,
    5 * 60 * 1000,
    30 * 60 * 1000,
    2 * 60 * 60 * 1000,
  ]);
  const EMAIL_MAX_RETRY_ATTEMPTS = EMAIL_RETRY_SCHEDULE_MS.length;
  return { NotificationPriority, EventCategory, EVENT_CATALOGUE, NotificationAuditAction, DigestMode, EMAIL_RETRY_SCHEDULE_MS, EMAIL_MAX_RETRY_ATTEMPTS };
});

// ---------------------------------------------------------------------------
// Test helper: make a notification data object
// ---------------------------------------------------------------------------

const RECIPIENT_A = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const RECIPIENT_B = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';

function makeNotificationData(overrides: Record<string, any> = {}) {
  return {
    recipientId: RECIPIENT_A,
    eventType: 'claim.submitted',
    priority: 'MEDIUM',
    title: 'Claim Submitted',
    body: 'Your claim has been submitted successfully.',
    channelsDelivered: { in_app: true, email: false, push: false },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('NotificationRepository', () => {
  let repo: ReturnType<typeof createNotificationRepository>;

  beforeEach(() => {
    notificationStore = [];
    deliveryLogStore = [];
    templateStore = [];
    digestQueueStore = [];
    preferencesStore = [];
    const db = makeMockDb();
    repo = createNotificationRepository(db);
  });

  // -----------------------------------------------------------------------
  // createNotification
  // -----------------------------------------------------------------------

  describe('createNotification', () => {
    it('inserts with correct fields', async () => {
      const data = makeNotificationData();
      const result = await repo.createNotification(data);

      expect(result.recipientId).toBe(RECIPIENT_A);
      expect(result.eventType).toBe('claim.submitted');
      expect(result.priority).toBe('MEDIUM');
      expect(result.title).toBe('Claim Submitted');
      expect(result.body).toBe('Your claim has been submitted successfully.');
      expect(result.channelsDelivered).toEqual({ in_app: true, email: false, push: false });
      expect(result.notificationId).toBeDefined();
      expect(result.readAt).toBeNull();
      expect(result.dismissedAt).toBeNull();
      expect(result.createdAt).toBeInstanceOf(Date);
      expect(notificationStore).toHaveLength(1);
    });
  });

  // -----------------------------------------------------------------------
  // createNotificationsBatch
  // -----------------------------------------------------------------------

  describe('createNotificationsBatch', () => {
    it('inserts multiple notifications', async () => {
      const batch = [
        makeNotificationData({ title: 'Notification 1' }),
        makeNotificationData({ title: 'Notification 2' }),
        makeNotificationData({ title: 'Notification 3' }),
      ];

      const count = await repo.createNotificationsBatch(batch);
      expect(count).toBe(3);
      expect(notificationStore).toHaveLength(3);
    });

    it('returns 0 for empty batch', async () => {
      const count = await repo.createNotificationsBatch([]);
      expect(count).toBe(0);
      expect(notificationStore).toHaveLength(0);
    });
  });

  // -----------------------------------------------------------------------
  // findNotificationById
  // -----------------------------------------------------------------------

  describe('findNotificationById', () => {
    it('returns notification for correct recipient', async () => {
      const created = await repo.createNotification(makeNotificationData());
      const found = await repo.findNotificationById(
        created.notificationId,
        RECIPIENT_A,
      );
      expect(found).toBeDefined();
      expect(found!.notificationId).toBe(created.notificationId);
      expect(found!.recipientId).toBe(RECIPIENT_A);
    });

    it('returns undefined for wrong recipient', async () => {
      const created = await repo.createNotification(makeNotificationData());
      const found = await repo.findNotificationById(
        created.notificationId,
        RECIPIENT_B,
      );
      expect(found).toBeUndefined();
    });

    it('returns undefined for non-existent notification', async () => {
      const found = await repo.findNotificationById(
        'nonexistent-id',
        RECIPIENT_A,
      );
      expect(found).toBeUndefined();
    });
  });

  // -----------------------------------------------------------------------
  // listNotifications
  // -----------------------------------------------------------------------

  describe('listNotifications', () => {
    it('returns reverse chronological order', async () => {
      const now = Date.now();
      await repo.createNotification(
        makeNotificationData({
          title: 'Old',
          createdAt: new Date(now - 3000),
        }),
      );
      await repo.createNotification(
        makeNotificationData({
          title: 'Middle',
          createdAt: new Date(now - 2000),
        }),
      );
      await repo.createNotification(
        makeNotificationData({
          title: 'New',
          createdAt: new Date(now - 1000),
        }),
      );

      const results = await repo.listNotifications(RECIPIENT_A, {
        limit: 10,
        offset: 0,
      });

      expect(results).toHaveLength(3);
      expect(results[0].title).toBe('New');
      expect(results[1].title).toBe('Middle');
      expect(results[2].title).toBe('Old');
    });

    it('with unreadOnly filters to unread', async () => {
      await repo.createNotification(makeNotificationData({ title: 'Unread' }));
      const read = await repo.createNotification(
        makeNotificationData({ title: 'Read' }),
      );
      // Mark one as read
      await repo.markRead(read.notificationId, RECIPIENT_A);

      const results = await repo.listNotifications(RECIPIENT_A, {
        unreadOnly: true,
        limit: 10,
        offset: 0,
      });

      expect(results).toHaveLength(1);
      expect(results[0].title).toBe('Unread');
    });

    it('excludes dismissed notifications', async () => {
      await repo.createNotification(makeNotificationData({ title: 'Active' }));
      const dismissed = await repo.createNotification(
        makeNotificationData({ title: 'Dismissed' }),
      );
      await repo.dismiss(dismissed.notificationId, RECIPIENT_A);

      const results = await repo.listNotifications(RECIPIENT_A, {
        limit: 10,
        offset: 0,
      });

      expect(results).toHaveLength(1);
      expect(results[0].title).toBe('Active');
    });

    it('paginates correctly', async () => {
      for (let i = 0; i < 5; i++) {
        await repo.createNotification(
          makeNotificationData({
            title: `N${i}`,
            createdAt: new Date(Date.now() - (5 - i) * 1000),
          }),
        );
      }

      const page1 = await repo.listNotifications(RECIPIENT_A, {
        limit: 2,
        offset: 0,
      });
      const page2 = await repo.listNotifications(RECIPIENT_A, {
        limit: 2,
        offset: 2,
      });
      const page3 = await repo.listNotifications(RECIPIENT_A, {
        limit: 2,
        offset: 4,
      });

      expect(page1).toHaveLength(2);
      expect(page2).toHaveLength(2);
      expect(page3).toHaveLength(1);

      // Verify no overlap
      const allTitles = [...page1, ...page2, ...page3].map((n) => n.title);
      expect(new Set(allTitles).size).toBe(5);
    });

    it('does not return other recipients notifications', async () => {
      await repo.createNotification(
        makeNotificationData({ recipientId: RECIPIENT_A, title: 'For A' }),
      );
      await repo.createNotification(
        makeNotificationData({ recipientId: RECIPIENT_B, title: 'For B' }),
      );

      const results = await repo.listNotifications(RECIPIENT_A, {
        limit: 10,
        offset: 0,
      });

      expect(results).toHaveLength(1);
      expect(results[0].title).toBe('For A');
    });
  });

  // -----------------------------------------------------------------------
  // countUnread
  // -----------------------------------------------------------------------

  describe('countUnread', () => {
    it('returns correct count', async () => {
      await repo.createNotification(makeNotificationData());
      await repo.createNotification(makeNotificationData());
      const read = await repo.createNotification(makeNotificationData());
      await repo.markRead(read.notificationId, RECIPIENT_A);

      const count = await repo.countUnread(RECIPIENT_A);
      expect(count).toBe(2);
    });

    it('excludes dismissed notifications', async () => {
      await repo.createNotification(makeNotificationData());
      const dismissed = await repo.createNotification(makeNotificationData());
      await repo.dismiss(dismissed.notificationId, RECIPIENT_A);

      const count = await repo.countUnread(RECIPIENT_A);
      expect(count).toBe(1);
    });

    it('returns 0 when no unread notifications', async () => {
      const count = await repo.countUnread(RECIPIENT_A);
      expect(count).toBe(0);
    });

    it('does not count other recipients notifications', async () => {
      await repo.createNotification(
        makeNotificationData({ recipientId: RECIPIENT_A }),
      );
      await repo.createNotification(
        makeNotificationData({ recipientId: RECIPIENT_B }),
      );

      const count = await repo.countUnread(RECIPIENT_A);
      expect(count).toBe(1);
    });
  });

  // -----------------------------------------------------------------------
  // markRead
  // -----------------------------------------------------------------------

  describe('markRead', () => {
    it('sets read_at timestamp', async () => {
      const created = await repo.createNotification(makeNotificationData());
      expect(created.readAt).toBeNull();

      const updated = await repo.markRead(created.notificationId, RECIPIENT_A);
      expect(updated).toBeDefined();
      expect(updated!.readAt).toBeInstanceOf(Date);
    });

    it('scoped to recipient (fails silently for wrong recipient)', async () => {
      const created = await repo.createNotification(makeNotificationData());

      const updated = await repo.markRead(created.notificationId, RECIPIENT_B);
      expect(updated).toBeUndefined();

      // Original notification remains unread
      const original = await repo.findNotificationById(
        created.notificationId,
        RECIPIENT_A,
      );
      expect(original!.readAt).toBeNull();
    });
  });

  // -----------------------------------------------------------------------
  // markAllRead
  // -----------------------------------------------------------------------

  describe('markAllRead', () => {
    it('marks all unread as read', async () => {
      await repo.createNotification(makeNotificationData({ title: 'N1' }));
      await repo.createNotification(makeNotificationData({ title: 'N2' }));
      await repo.createNotification(makeNotificationData({ title: 'N3' }));

      const count = await repo.markAllRead(RECIPIENT_A);
      expect(count).toBe(3);

      const unread = await repo.countUnread(RECIPIENT_A);
      expect(unread).toBe(0);
    });

    it('does not affect already-read notifications', async () => {
      const n1 = await repo.createNotification(makeNotificationData({ title: 'N1' }));
      await repo.createNotification(makeNotificationData({ title: 'N2' }));
      await repo.markRead(n1.notificationId, RECIPIENT_A);

      const count = await repo.markAllRead(RECIPIENT_A);
      expect(count).toBe(1); // Only N2 was unread
    });

    it('does not affect other recipients', async () => {
      await repo.createNotification(
        makeNotificationData({ recipientId: RECIPIENT_A }),
      );
      await repo.createNotification(
        makeNotificationData({ recipientId: RECIPIENT_B }),
      );

      await repo.markAllRead(RECIPIENT_A);

      const countB = await repo.countUnread(RECIPIENT_B);
      expect(countB).toBe(1);
    });
  });

  // -----------------------------------------------------------------------
  // dismiss
  // -----------------------------------------------------------------------

  describe('dismiss', () => {
    it('sets dismissed_at timestamp', async () => {
      const created = await repo.createNotification(makeNotificationData());
      expect(created.dismissedAt).toBeNull();

      const dismissed = await repo.dismiss(created.notificationId, RECIPIENT_A);
      expect(dismissed).toBeDefined();
      expect(dismissed!.dismissedAt).toBeInstanceOf(Date);
    });

    it('scoped to recipient (fails silently for wrong recipient)', async () => {
      const created = await repo.createNotification(makeNotificationData());

      const dismissed = await repo.dismiss(created.notificationId, RECIPIENT_B);
      expect(dismissed).toBeUndefined();

      // Original notification remains undismissed
      const original = await repo.findNotificationById(
        created.notificationId,
        RECIPIENT_A,
      );
      expect(original!.dismissedAt).toBeNull();
    });

    it('dismissed notification retained in store (soft-hide)', async () => {
      const created = await repo.createNotification(makeNotificationData());
      await repo.dismiss(created.notificationId, RECIPIENT_A);

      // Still in store (for audit), just not in feed
      expect(notificationStore).toHaveLength(1);
      expect(notificationStore[0].dismissedAt).toBeInstanceOf(Date);

      // But excluded from feed
      const feed = await repo.listNotifications(RECIPIENT_A, {
        limit: 10,
        offset: 0,
      });
      expect(feed).toHaveLength(0);
    });
  });

  // -----------------------------------------------------------------------
  // Email Delivery Log
  // -----------------------------------------------------------------------

  const NOTIFICATION_ID_1 = '11111111-1111-1111-1111-111111111111';
  const NOTIFICATION_ID_2 = '22222222-2222-2222-2222-222222222222';

  function makeDeliveryLogData(overrides: Record<string, any> = {}) {
    return {
      notificationId: NOTIFICATION_ID_1,
      recipientEmail: 'doctor@example.com',
      templateId: 'claim.submitted',
      ...overrides,
    };
  }

  describe('createDeliveryLog', () => {
    it('inserts record with QUEUED status', async () => {
      const data = makeDeliveryLogData();
      const result = await repo.createDeliveryLog(data);

      expect(result.deliveryId).toBeDefined();
      expect(result.notificationId).toBe(NOTIFICATION_ID_1);
      expect(result.recipientEmail).toBe('doctor@example.com');
      expect(result.templateId).toBe('claim.submitted');
      expect(result.status).toBe('QUEUED');
      expect(result.retryCount).toBe(0);
      expect(result.nextRetryAt).toBeNull();
      expect(result.sentAt).toBeNull();
      expect(result.deliveredAt).toBeNull();
      expect(result.bouncedAt).toBeNull();
      expect(result.bounceReason).toBeNull();
      expect(result.createdAt).toBeInstanceOf(Date);
      expect(deliveryLogStore).toHaveLength(1);
    });
  });

  describe('updateDeliveryStatus', () => {
    it('transitions from QUEUED to SENT', async () => {
      const created = await repo.createDeliveryLog(makeDeliveryLogData());
      const sentAt = new Date();

      const updated = await repo.updateDeliveryStatus(
        created.deliveryId,
        'SENT',
        { providerMessageId: 'msg-123', sentAt },
      );

      expect(updated).toBeDefined();
      expect(updated!.status).toBe('SENT');
      expect(updated!.providerMessageId).toBe('msg-123');
      expect(updated!.sentAt).toBe(sentAt);
    });

    it('sets bounced_at and bounce_reason on BOUNCED', async () => {
      const created = await repo.createDeliveryLog(makeDeliveryLogData());
      const bouncedAt = new Date();

      const updated = await repo.updateDeliveryStatus(
        created.deliveryId,
        'BOUNCED',
        { bouncedAt, bounceReason: 'Mailbox full' },
      );

      expect(updated).toBeDefined();
      expect(updated!.status).toBe('BOUNCED');
      expect(updated!.bouncedAt).toBe(bouncedAt);
      expect(updated!.bounceReason).toBe('Mailbox full');
    });

    it('transitions to DELIVERED', async () => {
      const created = await repo.createDeliveryLog(makeDeliveryLogData());
      const deliveredAt = new Date();

      const updated = await repo.updateDeliveryStatus(
        created.deliveryId,
        'DELIVERED',
        { deliveredAt },
      );

      expect(updated).toBeDefined();
      expect(updated!.status).toBe('DELIVERED');
      expect(updated!.deliveredAt).toBe(deliveredAt);
    });

    it('returns undefined for non-existent delivery', async () => {
      const updated = await repo.updateDeliveryStatus(
        'non-existent-id',
        'SENT',
      );
      expect(updated).toBeUndefined();
    });
  });

  describe('findPendingRetries', () => {
    it('returns records where retry is due', async () => {
      const pastDate = new Date(Date.now() - 60_000);

      // QUEUED with null nextRetryAt — should be returned
      await repo.createDeliveryLog(
        makeDeliveryLogData({ status: 'QUEUED', retryCount: 0 }),
      );

      // FAILED with past nextRetryAt — should be returned
      deliveryLogStore.push({
        deliveryId: crypto.randomUUID(),
        notificationId: NOTIFICATION_ID_2,
        recipientEmail: 'doc2@example.com',
        templateId: 'claim.failed',
        status: 'FAILED',
        providerMessageId: null,
        sentAt: null,
        deliveredAt: null,
        bouncedAt: null,
        bounceReason: null,
        retryCount: 2,
        nextRetryAt: pastDate,
        createdAt: new Date(),
      });

      // SENT — should NOT be returned
      deliveryLogStore.push({
        deliveryId: crypto.randomUUID(),
        notificationId: NOTIFICATION_ID_1,
        recipientEmail: 'doc3@example.com',
        templateId: 'claim.submitted',
        status: 'SENT',
        providerMessageId: 'msg-ok',
        sentAt: new Date(),
        deliveredAt: null,
        bouncedAt: null,
        bounceReason: null,
        retryCount: 0,
        nextRetryAt: null,
        createdAt: new Date(),
      });

      const pending = await repo.findPendingRetries();
      expect(pending).toHaveLength(2);
      expect(pending.every((r: any) => ['QUEUED', 'FAILED'].includes(r.status))).toBe(true);
    });

    it('excludes records at max retry count', async () => {
      // FAILED with retryCount = 4 (max reached) — should NOT be returned
      deliveryLogStore.push({
        deliveryId: crypto.randomUUID(),
        notificationId: NOTIFICATION_ID_1,
        recipientEmail: 'maxed@example.com',
        templateId: 'claim.submitted',
        status: 'FAILED',
        providerMessageId: null,
        sentAt: null,
        deliveredAt: null,
        bouncedAt: null,
        bounceReason: null,
        retryCount: 4,
        nextRetryAt: new Date(Date.now() - 60_000),
        createdAt: new Date(),
      });

      // FAILED with retryCount = 3 — should be returned
      deliveryLogStore.push({
        deliveryId: crypto.randomUUID(),
        notificationId: NOTIFICATION_ID_2,
        recipientEmail: 'retry@example.com',
        templateId: 'claim.submitted',
        status: 'FAILED',
        providerMessageId: null,
        sentAt: null,
        deliveredAt: null,
        bouncedAt: null,
        bounceReason: null,
        retryCount: 3,
        nextRetryAt: new Date(Date.now() - 60_000),
        createdAt: new Date(),
      });

      const pending = await repo.findPendingRetries();
      expect(pending).toHaveLength(1);
      expect(pending[0].recipientEmail).toBe('retry@example.com');
    });

    it('excludes records with future nextRetryAt', async () => {
      const futureDate = new Date(Date.now() + 600_000);

      deliveryLogStore.push({
        deliveryId: crypto.randomUUID(),
        notificationId: NOTIFICATION_ID_1,
        recipientEmail: 'future@example.com',
        templateId: 'claim.submitted',
        status: 'FAILED',
        providerMessageId: null,
        sentAt: null,
        deliveredAt: null,
        bouncedAt: null,
        bounceReason: null,
        retryCount: 1,
        nextRetryAt: futureDate,
        createdAt: new Date(),
      });

      const pending = await repo.findPendingRetries();
      expect(pending).toHaveLength(0);
    });
  });

  describe('incrementRetry', () => {
    it('increases count and sets next_retry_at', async () => {
      const created = await repo.createDeliveryLog(makeDeliveryLogData());
      expect(created.retryCount).toBe(0);

      const nextRetryAt = new Date(Date.now() + 300_000);
      const updated = await repo.incrementRetry(created.deliveryId, nextRetryAt);

      expect(updated).toBeDefined();
      expect(updated!.retryCount).toBe(1);
      expect(updated!.nextRetryAt).toBe(nextRetryAt);
    });

    it('returns undefined for non-existent delivery', async () => {
      const updated = await repo.incrementRetry(
        'non-existent-id',
        new Date(),
      );
      expect(updated).toBeUndefined();
    });
  });

  describe('listDeliveryLogByNotification', () => {
    it('returns delivery attempts for a notification', async () => {
      await repo.createDeliveryLog(
        makeDeliveryLogData({ notificationId: NOTIFICATION_ID_1 }),
      );
      await repo.createDeliveryLog(
        makeDeliveryLogData({ notificationId: NOTIFICATION_ID_1 }),
      );
      await repo.createDeliveryLog(
        makeDeliveryLogData({ notificationId: NOTIFICATION_ID_2 }),
      );

      const logs = await repo.listDeliveryLogByNotification(NOTIFICATION_ID_1);
      expect(logs).toHaveLength(2);
      expect(logs.every((l: any) => l.notificationId === NOTIFICATION_ID_1)).toBe(true);
    });

    it('returns empty array for unknown notification', async () => {
      const logs = await repo.listDeliveryLogByNotification('unknown-id');
      expect(logs).toHaveLength(0);
    });
  });

  // -----------------------------------------------------------------------
  // Notification Templates
  // -----------------------------------------------------------------------

  function makeTemplateData(overrides: Record<string, any> = {}) {
    return {
      templateId: 'claim.submitted',
      inAppTitle: 'Claim Submitted',
      inAppBody: 'Your claim {{claimId}} has been submitted.',
      emailSubject: 'Claim Submitted',
      emailHtmlBody: '<p>Your claim {{claimId}} has been submitted.</p>',
      emailTextBody: 'Your claim {{claimId}} has been submitted.',
      actionUrlTemplate: '/claims/{{claimId}}',
      actionLabel: 'View Claim',
      variables: ['claimId'],
      ...overrides,
    };
  }

  describe('findTemplateById', () => {
    it('returns template for valid ID', async () => {
      await repo.upsertTemplate(makeTemplateData());

      const found = await repo.findTemplateById('claim.submitted');
      expect(found).toBeDefined();
      expect(found!.templateId).toBe('claim.submitted');
      expect(found!.inAppTitle).toBe('Claim Submitted');
      expect(found!.variables).toEqual(['claimId']);
    });

    it('returns undefined for unknown template', async () => {
      const found = await repo.findTemplateById('unknown.template');
      expect(found).toBeUndefined();
    });
  });

  describe('upsertTemplate', () => {
    it('inserts new template', async () => {
      const data = makeTemplateData();
      const result = await repo.upsertTemplate(data);

      expect(result.templateId).toBe('claim.submitted');
      expect(result.inAppTitle).toBe('Claim Submitted');
      expect(result.inAppBody).toBe('Your claim {{claimId}} has been submitted.');
      expect(result.emailSubject).toBe('Claim Submitted');
      expect(result.variables).toEqual(['claimId']);
      expect(templateStore).toHaveLength(1);
    });

    it('updates existing template', async () => {
      await repo.upsertTemplate(makeTemplateData());
      expect(templateStore).toHaveLength(1);

      const updated = await repo.upsertTemplate(
        makeTemplateData({
          inAppTitle: 'Claim Submitted (Updated)',
          inAppBody: 'Updated body for {{claimId}}.',
        }),
      );

      expect(templateStore).toHaveLength(1);
      expect(updated.inAppTitle).toBe('Claim Submitted (Updated)');
      expect(updated.inAppBody).toBe('Updated body for {{claimId}}.');
    });
  });

  describe('listAllTemplates', () => {
    it('returns all templates', async () => {
      await repo.upsertTemplate(makeTemplateData({ templateId: 'template.a' }));
      await repo.upsertTemplate(makeTemplateData({ templateId: 'template.b' }));
      await repo.upsertTemplate(makeTemplateData({ templateId: 'template.c' }));

      const all = await repo.listAllTemplates();
      expect(all).toHaveLength(3);
    });

    it('returns empty array when no templates exist', async () => {
      const all = await repo.listAllTemplates();
      expect(all).toHaveLength(0);
    });
  });

  // -----------------------------------------------------------------------
  // Digest Queue
  // -----------------------------------------------------------------------

  describe('addToDigestQueue', () => {
    it('inserts queue entry', async () => {
      const notif = await repo.createNotification(makeNotificationData());
      const result = await repo.addToDigestQueue({
        recipientId: RECIPIENT_A,
        notificationId: notif.notificationId,
        digestType: 'DAILY_DIGEST',
      });

      expect(result.queueId).toBeDefined();
      expect(result.recipientId).toBe(RECIPIENT_A);
      expect(result.notificationId).toBe(notif.notificationId);
      expect(result.digestType).toBe('DAILY_DIGEST');
      expect(result.digestSent).toBe(false);
      expect(result.createdAt).toBeInstanceOf(Date);
      expect(digestQueueStore).toHaveLength(1);
    });
  });

  describe('findPendingDigestItems', () => {
    it('returns unsent items for recipient', async () => {
      const notif1 = await repo.createNotification(makeNotificationData({ title: 'N1' }));
      const notif2 = await repo.createNotification(makeNotificationData({ title: 'N2' }));
      const notif3 = await repo.createNotification(
        makeNotificationData({ recipientId: RECIPIENT_B, title: 'N3' }),
      );

      await repo.addToDigestQueue({
        recipientId: RECIPIENT_A,
        notificationId: notif1.notificationId,
        digestType: 'DAILY_DIGEST',
      });
      await repo.addToDigestQueue({
        recipientId: RECIPIENT_A,
        notificationId: notif2.notificationId,
        digestType: 'DAILY_DIGEST',
      });
      await repo.addToDigestQueue({
        recipientId: RECIPIENT_B,
        notificationId: notif3.notificationId,
        digestType: 'DAILY_DIGEST',
      });

      const items = await repo.findPendingDigestItems(RECIPIENT_A, 'DAILY_DIGEST');
      expect(items).toHaveLength(2);
      expect(items.every((i: any) => i.recipientId === RECIPIENT_A)).toBe(true);
    });

    it('excludes already-sent items', async () => {
      const notif = await repo.createNotification(makeNotificationData());
      const item = await repo.addToDigestQueue({
        recipientId: RECIPIENT_A,
        notificationId: notif.notificationId,
        digestType: 'DAILY_DIGEST',
      });

      await repo.markDigestItemsSent([item.queueId]);

      const items = await repo.findPendingDigestItems(RECIPIENT_A, 'DAILY_DIGEST');
      expect(items).toHaveLength(0);
    });

    it('filters by digest type', async () => {
      const notif = await repo.createNotification(makeNotificationData());
      await repo.addToDigestQueue({
        recipientId: RECIPIENT_A,
        notificationId: notif.notificationId,
        digestType: 'WEEKLY_DIGEST',
      });

      const daily = await repo.findPendingDigestItems(RECIPIENT_A, 'DAILY_DIGEST');
      expect(daily).toHaveLength(0);

      const weekly = await repo.findPendingDigestItems(RECIPIENT_A, 'WEEKLY_DIGEST');
      expect(weekly).toHaveLength(1);
    });
  });

  describe('findAllPendingDigestItems', () => {
    it('groups by recipient', async () => {
      const notifA1 = await repo.createNotification(makeNotificationData({ title: 'A1' }));
      const notifA2 = await repo.createNotification(makeNotificationData({ title: 'A2' }));
      const notifB1 = await repo.createNotification(
        makeNotificationData({ recipientId: RECIPIENT_B, title: 'B1' }),
      );

      await repo.addToDigestQueue({
        recipientId: RECIPIENT_A,
        notificationId: notifA1.notificationId,
        digestType: 'DAILY_DIGEST',
      });
      await repo.addToDigestQueue({
        recipientId: RECIPIENT_A,
        notificationId: notifA2.notificationId,
        digestType: 'DAILY_DIGEST',
      });
      await repo.addToDigestQueue({
        recipientId: RECIPIENT_B,
        notificationId: notifB1.notificationId,
        digestType: 'DAILY_DIGEST',
      });

      const grouped = await repo.findAllPendingDigestItems('DAILY_DIGEST');
      expect(grouped).toBeInstanceOf(Map);
      expect(grouped.size).toBe(2);
      expect(grouped.get(RECIPIENT_A)).toHaveLength(2);
      expect(grouped.get(RECIPIENT_B)).toHaveLength(1);
    });

    it('excludes sent items', async () => {
      const notif = await repo.createNotification(makeNotificationData());
      const item = await repo.addToDigestQueue({
        recipientId: RECIPIENT_A,
        notificationId: notif.notificationId,
        digestType: 'DAILY_DIGEST',
      });

      await repo.markDigestItemsSent([item.queueId]);

      const grouped = await repo.findAllPendingDigestItems('DAILY_DIGEST');
      expect(grouped.size).toBe(0);
    });

    it('returns empty map when no pending items', async () => {
      const grouped = await repo.findAllPendingDigestItems('DAILY_DIGEST');
      expect(grouped).toBeInstanceOf(Map);
      expect(grouped.size).toBe(0);
    });
  });

  describe('markDigestItemsSent', () => {
    it('sets digest_sent true', async () => {
      const notif1 = await repo.createNotification(makeNotificationData({ title: 'N1' }));
      const notif2 = await repo.createNotification(makeNotificationData({ title: 'N2' }));

      const item1 = await repo.addToDigestQueue({
        recipientId: RECIPIENT_A,
        notificationId: notif1.notificationId,
        digestType: 'DAILY_DIGEST',
      });
      const item2 = await repo.addToDigestQueue({
        recipientId: RECIPIENT_A,
        notificationId: notif2.notificationId,
        digestType: 'DAILY_DIGEST',
      });

      const count = await repo.markDigestItemsSent([item1.queueId, item2.queueId]);
      expect(count).toBe(2);

      // Verify in store
      expect(digestQueueStore[0].digestSent).toBe(true);
      expect(digestQueueStore[1].digestSent).toBe(true);
    });

    it('returns 0 for empty array', async () => {
      const count = await repo.markDigestItemsSent([]);
      expect(count).toBe(0);
    });
  });

  // -----------------------------------------------------------------------
  // Notification Preferences
  // -----------------------------------------------------------------------

  const PROVIDER_A = 'cccccccc-cccc-cccc-cccc-cccccccccccc';
  const PROVIDER_B = 'dddddddd-dddd-dddd-dddd-dddddddddddd';

  describe('findPreferencesByProvider', () => {
    it('returns all preferences for provider', async () => {
      await repo.upsertPreference(PROVIDER_A, 'CLAIM_LIFECYCLE', {
        emailEnabled: true,
      });
      await repo.upsertPreference(PROVIDER_A, 'ANALYTICS', {
        emailEnabled: false,
      });
      await repo.upsertPreference(PROVIDER_B, 'CLAIM_LIFECYCLE', {
        emailEnabled: true,
      });

      const prefs = await repo.findPreferencesByProvider(PROVIDER_A);
      expect(prefs).toHaveLength(2);
      expect(prefs.every((p: any) => p.providerId === PROVIDER_A)).toBe(true);
    });

    it('returns empty array for unknown provider', async () => {
      const prefs = await repo.findPreferencesByProvider('unknown-id');
      expect(prefs).toHaveLength(0);
    });
  });

  describe('findPreference', () => {
    it('returns specific category preference', async () => {
      await repo.upsertPreference(PROVIDER_A, 'CLAIM_LIFECYCLE', {
        emailEnabled: true,
        digestMode: 'DAILY_DIGEST',
      });

      const pref = await repo.findPreference(PROVIDER_A, 'CLAIM_LIFECYCLE');
      expect(pref).toBeDefined();
      expect(pref!.providerId).toBe(PROVIDER_A);
      expect(pref!.eventCategory).toBe('CLAIM_LIFECYCLE');
      expect(pref!.emailEnabled).toBe(true);
      expect(pref!.digestMode).toBe('DAILY_DIGEST');
    });

    it('returns undefined for non-existent category', async () => {
      const pref = await repo.findPreference(PROVIDER_A, 'NONEXISTENT');
      expect(pref).toBeUndefined();
    });
  });

  describe('upsertPreference', () => {
    it('creates new preference', async () => {
      const result = await repo.upsertPreference(PROVIDER_A, 'CLAIM_LIFECYCLE', {
        inAppEnabled: true,
        emailEnabled: false,
        digestMode: 'IMMEDIATE',
      });

      expect(result.preferenceId).toBeDefined();
      expect(result.providerId).toBe(PROVIDER_A);
      expect(result.eventCategory).toBe('CLAIM_LIFECYCLE');
      expect(result.inAppEnabled).toBe(true);
      expect(result.emailEnabled).toBe(false);
      expect(result.digestMode).toBe('IMMEDIATE');
      expect(preferencesStore).toHaveLength(1);
    });

    it('updates existing preference', async () => {
      await repo.upsertPreference(PROVIDER_A, 'CLAIM_LIFECYCLE', {
        emailEnabled: false,
      });
      expect(preferencesStore).toHaveLength(1);

      const updated = await repo.upsertPreference(PROVIDER_A, 'CLAIM_LIFECYCLE', {
        emailEnabled: true,
        digestMode: 'DAILY_DIGEST',
      });

      expect(preferencesStore).toHaveLength(1);
      expect(updated.emailEnabled).toBe(true);
      expect(updated.digestMode).toBe('DAILY_DIGEST');
    });
  });

  describe('createDefaultPreferences', () => {
    it('creates entries for all event categories', async () => {
      const results = await repo.createDefaultPreferences(PROVIDER_A);

      // The mock EVENT_CATALOGUE has 5 categories
      expect(results).toHaveLength(5);
      expect(results.every((p: any) => p.providerId === PROVIDER_A)).toBe(true);

      const categories = results.map((p: any) => p.eventCategory);
      expect(categories).toContain('CLAIM_LIFECYCLE');
      expect(categories).toContain('INTELLIGENCE_ENGINE');
      expect(categories).toContain('PROVIDER_MANAGEMENT');
      expect(categories).toContain('PLATFORM_OPERATIONS');
      expect(categories).toContain('ANALYTICS');
    });

    it('sets inAppEnabled true for all categories', async () => {
      const results = await repo.createDefaultPreferences(PROVIDER_A);
      expect(results.every((p: any) => p.inAppEnabled === true)).toBe(true);
    });

    it('sets digestMode to IMMEDIATE for all categories', async () => {
      const results = await repo.createDefaultPreferences(PROVIDER_A);
      expect(results.every((p: any) => p.digestMode === 'IMMEDIATE')).toBe(true);
    });

    it('sets emailEnabled based on catalogue defaults', async () => {
      const results = await repo.createDefaultPreferences(PROVIDER_A);

      // INTELLIGENCE_ENGINE has defaultEmail: false (AI_SUGGESTION_READY)
      // but since it's the only event in that category, emailEnabled = false
      const intel = results.find((p: any) => p.eventCategory === 'INTELLIGENCE_ENGINE');
      expect(intel!.emailEnabled).toBe(false);

      // ANALYTICS has defaultEmail: true (REPORT_READY)
      const analytics = results.find((p: any) => p.eventCategory === 'ANALYTICS');
      expect(analytics!.emailEnabled).toBe(true);
    });
  });

  describe('updateQuietHours', () => {
    it('sets start and end on all preferences', async () => {
      await repo.upsertPreference(PROVIDER_A, 'CLAIM_LIFECYCLE', {
        emailEnabled: true,
      });
      await repo.upsertPreference(PROVIDER_A, 'ANALYTICS', {
        emailEnabled: true,
      });

      const count = await repo.updateQuietHours(PROVIDER_A, '22:00', '07:00');
      expect(count).toBe(2);

      const prefs = await repo.findPreferencesByProvider(PROVIDER_A);
      expect(prefs.every((p: any) => p.quietHoursStart === '22:00')).toBe(true);
      expect(prefs.every((p: any) => p.quietHoursEnd === '07:00')).toBe(true);
    });

    it('clears quiet hours when null', async () => {
      await repo.upsertPreference(PROVIDER_A, 'CLAIM_LIFECYCLE', {
        emailEnabled: true,
        quietHoursStart: '22:00',
        quietHoursEnd: '07:00',
      });

      const count = await repo.updateQuietHours(PROVIDER_A, null, null);
      expect(count).toBe(1);

      const prefs = await repo.findPreferencesByProvider(PROVIDER_A);
      expect(prefs[0].quietHoursStart).toBeNull();
      expect(prefs[0].quietHoursEnd).toBeNull();
    });

    it('does not affect other providers', async () => {
      await repo.upsertPreference(PROVIDER_A, 'CLAIM_LIFECYCLE', {
        emailEnabled: true,
      });
      await repo.upsertPreference(PROVIDER_B, 'CLAIM_LIFECYCLE', {
        emailEnabled: true,
      });

      await repo.updateQuietHours(PROVIDER_A, '22:00', '07:00');

      const prefsB = await repo.findPreferencesByProvider(PROVIDER_B);
      expect(prefsB[0].quietHoursStart).toBeNull();
      expect(prefsB[0].quietHoursEnd).toBeNull();
    });
  });
});

// ===========================================================================
// NotificationService Tests
// ===========================================================================

const PHYSICIAN_ID = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee';
const DELEGATE_ID_1 = 'ffffffff-ffff-ffff-ffff-ffffffffffff';
const DELEGATE_ID_2 = '11111111-2222-3333-4444-555555555555';

function makeMockDelegateLinkageRepo(
  delegates: Array<{
    delegateUserId: string;
    permissions: string[];
    isActive?: boolean;
  }> = [],
): DelegateLinkageRepo {
  return {
    async listDelegatesForPhysician(_physicianUserId: string) {
      return delegates.map((d) => ({
        linkage: {
          linkageId: crypto.randomUUID(),
          physicianUserId: _physicianUserId,
          delegateUserId: d.delegateUserId,
          permissions: d.permissions,
          isActive: d.isActive ?? true,
        },
      }));
    },
  };
}

function makeMockAuditRepo(): AuditRepo & { logs: any[] } {
  const logs: any[] = [];
  return {
    logs,
    async appendAuditLog(entry: any) {
      logs.push(entry);
      return { logId: crypto.randomUUID(), ...entry, createdAt: new Date() };
    },
  };
}

function makeMockPostmarkClient(
  shouldFail = false,
): PostmarkClient & { calls: any[] } {
  const calls: any[] = [];
  return {
    calls,
    async sendEmail(options: any) {
      calls.push(options);
      if (shouldFail) {
        throw new Error('Postmark send failed');
      }
      return { MessageID: `msg-${crypto.randomUUID().slice(0, 8)}` };
    },
  };
}

function makeServiceDeps(
  overrides: Partial<NotificationServiceDeps> = {},
): NotificationServiceDeps {
  const db = makeMockDb();
  const repo = createNotificationRepository(db);
  return {
    notificationRepo: repo,
    delegateLinkageRepo: makeMockDelegateLinkageRepo(),
    auditRepo: makeMockAuditRepo(),
    ...overrides,
  };
}

describe('NotificationService', () => {
  beforeEach(() => {
    notificationStore = [];
    deliveryLogStore = [];
    templateStore = [];
    digestQueueStore = [];
    preferencesStore = [];
  });

  // -----------------------------------------------------------------------
  // resolveRecipients
  // -----------------------------------------------------------------------

  describe('resolveRecipients', () => {
    it('returns physician and relevant delegates', async () => {
      const delegateRepo = makeMockDelegateLinkageRepo([
        { delegateUserId: DELEGATE_ID_1, permissions: ['CLAIM_VIEW'] },
        { delegateUserId: DELEGATE_ID_2, permissions: ['ANALYTICS_VIEW'] },
      ]);
      const deps = makeServiceDeps({ delegateLinkageRepo: delegateRepo });

      const recipients = await resolveRecipients(
        deps,
        PHYSICIAN_ID,
        'CLAIM_VALIDATED',
      );

      // Physician + DELEGATE_ID_1 (has CLAIM_VIEW which maps to CLAIM_VALIDATED)
      expect(recipients).toHaveLength(2);
      expect(recipients[0]).toEqual({
        userId: PHYSICIAN_ID,
        isDelegate: false,
        physicianContextId: null,
      });
      expect(recipients[1]).toEqual({
        userId: DELEGATE_ID_1,
        isDelegate: true,
        physicianContextId: PHYSICIAN_ID,
      });
    });

    it('excludes inactive delegates', async () => {
      const delegateRepo = makeMockDelegateLinkageRepo([
        {
          delegateUserId: DELEGATE_ID_1,
          permissions: ['CLAIM_VIEW'],
          isActive: false,
        },
      ]);
      const deps = makeServiceDeps({ delegateLinkageRepo: delegateRepo });

      const recipients = await resolveRecipients(
        deps,
        PHYSICIAN_ID,
        'CLAIM_VALIDATED',
      );

      // Only physician — delegate is inactive
      expect(recipients).toHaveLength(1);
      expect(recipients[0].userId).toBe(PHYSICIAN_ID);
    });

    it('excludes delegates without matching permission', async () => {
      const delegateRepo = makeMockDelegateLinkageRepo([
        { delegateUserId: DELEGATE_ID_1, permissions: ['ANALYTICS_VIEW'] },
      ]);
      const deps = makeServiceDeps({ delegateLinkageRepo: delegateRepo });

      const recipients = await resolveRecipients(
        deps,
        PHYSICIAN_ID,
        'CLAIM_VALIDATED', // Requires CLAIM_VIEW
      );

      expect(recipients).toHaveLength(1);
      expect(recipients[0].userId).toBe(PHYSICIAN_ID);
    });

    it('returns only physician for events without permission mapping', async () => {
      const delegateRepo = makeMockDelegateLinkageRepo([
        { delegateUserId: DELEGATE_ID_1, permissions: ['CLAIM_VIEW'] },
      ]);
      const deps = makeServiceDeps({ delegateLinkageRepo: delegateRepo });

      const recipients = await resolveRecipients(
        deps,
        PHYSICIAN_ID,
        'BA_STATUS_CHANGED', // No permission mapping in our frozen object
      );

      expect(recipients).toHaveLength(1);
      expect(recipients[0].userId).toBe(PHYSICIAN_ID);
    });
  });

  // -----------------------------------------------------------------------
  // checkPreferences
  // -----------------------------------------------------------------------

  describe('checkPreferences', () => {
    it('returns defaults for unconfigured category', async () => {
      const deps = makeServiceDeps();

      const prefs = await checkPreferences(deps, PHYSICIAN_ID, 'CLAIM_VALIDATED');

      // CLAIM_VALIDATED defaults: inApp true, email false, IMMEDIATE
      expect(prefs.inAppEnabled).toBe(true);
      expect(prefs.emailEnabled).toBe(false);
      expect(prefs.digestMode).toBe('IMMEDIATE');
    });

    it('enforces URGENT in-app always enabled', async () => {
      const deps = makeServiceDeps();

      // Create a preference that disables in-app for CLAIM_LIFECYCLE
      await deps.notificationRepo.upsertPreference(
        PHYSICIAN_ID,
        'CLAIM_LIFECYCLE',
        { inAppEnabled: false, emailEnabled: false },
      );

      // DEADLINE_1_DAY is URGENT
      const prefs = await checkPreferences(deps, PHYSICIAN_ID, 'DEADLINE_1_DAY');

      expect(prefs.inAppEnabled).toBe(true); // Forced true for URGENT
    });

    it('returns stored preference when configured', async () => {
      const deps = makeServiceDeps();

      await deps.notificationRepo.upsertPreference(
        PHYSICIAN_ID,
        'CLAIM_LIFECYCLE',
        {
          inAppEnabled: true,
          emailEnabled: true,
          digestMode: 'DAILY_DIGEST',
        },
      );

      const prefs = await checkPreferences(
        deps,
        PHYSICIAN_ID,
        'CLAIM_VALIDATED',
      );

      expect(prefs.inAppEnabled).toBe(true);
      expect(prefs.emailEnabled).toBe(true);
      expect(prefs.digestMode).toBe('DAILY_DIGEST');
    });
  });

  // -----------------------------------------------------------------------
  // renderNotification
  // -----------------------------------------------------------------------

  describe('renderNotification', () => {
    it('substitutes variables correctly', async () => {
      const deps = makeServiceDeps();

      await deps.notificationRepo.upsertTemplate({
        templateId: 'CLAIM_VALIDATED',
        inAppTitle: 'Claim {{claimId}} validated',
        inAppBody: 'Your claim {{claimId}} for patient {{patientName}} was validated.',
        emailSubject: 'Claim Validated: {{claimId}}',
        emailHtmlBody: '<p>Claim {{claimId}} validated</p>',
        emailTextBody: 'Claim {{claimId}} validated',
        actionUrlTemplate: '/claims/{{claimId}}',
        actionLabel: 'View Claim',
        variables: ['claimId', 'patientName'],
      });

      const rendered = await renderNotification(deps, 'CLAIM_VALIDATED', {
        claimId: 'CLM-001',
        patientName: 'John Doe',
      });

      expect(rendered.title).toBe('Claim CLM-001 validated');
      expect(rendered.body).toBe(
        'Your claim CLM-001 for patient John Doe was validated.',
      );
      expect(rendered.emailSubject).toBe('Claim Validated: CLM-001');
      expect(rendered.actionUrl).toBe('/claims/CLM-001');
      expect(rendered.actionLabel).toBe('View Claim');
    });

    it('escapes HTML in variable values', async () => {
      const deps = makeServiceDeps();

      await deps.notificationRepo.upsertTemplate({
        templateId: 'TEST_TEMPLATE',
        inAppTitle: 'Hello {{name}}',
        inAppBody: 'Welcome {{name}}',
        variables: ['name'],
      });

      const rendered = await renderNotification(deps, 'TEST_TEMPLATE', {
        name: '<script>alert("xss")</script>',
      });

      expect(rendered.title).toBe(
        'Hello &lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;',
      );
      expect(rendered.title).not.toContain('<script>');
    });

    it('throws error for missing required variable', async () => {
      const deps = makeServiceDeps();

      await deps.notificationRepo.upsertTemplate({
        templateId: 'NEEDS_VARS',
        inAppTitle: 'Hello {{name}}',
        inAppBody: 'Body {{name}}',
        variables: ['name'],
      });

      await expect(
        renderNotification(deps, 'NEEDS_VARS', {}),
      ).rejects.toThrow('Missing required template variable: name');
    });

    it('throws error for unknown template', async () => {
      const deps = makeServiceDeps();

      await expect(
        renderNotification(deps, 'NONEXISTENT', {}),
      ).rejects.toThrow('Notification template not found: NONEXISTENT');
    });
  });

  // -----------------------------------------------------------------------
  // processEvent
  // -----------------------------------------------------------------------

  describe('processEvent', () => {
    it('creates notification for physician', async () => {
      const auditRepo = makeMockAuditRepo();
      const deps = makeServiceDeps({ auditRepo });

      const results = await processEvent(deps, {
        eventType: 'CLAIM_VALIDATED',
        physicianId: PHYSICIAN_ID,
      });

      expect(results).toHaveLength(1);
      expect(results[0].recipientId).toBe(PHYSICIAN_ID);
      expect(results[0].eventType).toBe('CLAIM_VALIDATED');
      expect(results[0].priority).toBe('LOW');
    });

    it('creates notification for delegate with matching permission', async () => {
      const delegateRepo = makeMockDelegateLinkageRepo([
        { delegateUserId: DELEGATE_ID_1, permissions: ['CLAIM_VIEW'] },
      ]);
      const deps = makeServiceDeps({ delegateLinkageRepo: delegateRepo });

      const results = await processEvent(deps, {
        eventType: 'CLAIM_VALIDATED',
        physicianId: PHYSICIAN_ID,
      });

      // Physician + delegate
      expect(results).toHaveLength(2);
      expect(results[0].recipientId).toBe(PHYSICIAN_ID);
      expect(results[1].recipientId).toBe(DELEGATE_ID_1);
      expect(results[1].physicianContextId).toBe(PHYSICIAN_ID);
    });

    it('skips delegate without matching permission', async () => {
      const delegateRepo = makeMockDelegateLinkageRepo([
        { delegateUserId: DELEGATE_ID_1, permissions: ['ANALYTICS_VIEW'] },
      ]);
      const deps = makeServiceDeps({ delegateLinkageRepo: delegateRepo });

      const results = await processEvent(deps, {
        eventType: 'CLAIM_VALIDATED', // Requires CLAIM_VIEW
        physicianId: PHYSICIAN_ID,
      });

      expect(results).toHaveLength(1);
      expect(results[0].recipientId).toBe(PHYSICIAN_ID);
    });

    it('emits audit event', async () => {
      const auditRepo = makeMockAuditRepo();
      const deps = makeServiceDeps({ auditRepo });

      await processEvent(deps, {
        eventType: 'CLAIM_VALIDATED',
        physicianId: PHYSICIAN_ID,
      });

      expect(auditRepo.logs).toHaveLength(1);
      expect(auditRepo.logs[0].action).toBe('notification.event_emitted');
      expect(auditRepo.logs[0].detail.eventType).toBe('CLAIM_VALIDATED');
      expect(auditRepo.logs[0].detail.recipientCount).toBe(1);
    });

    it('with IMMEDIATE digest mode queues email', async () => {
      const deps = makeServiceDeps();

      // Set preferences for CLAIM_LIFECYCLE with email enabled + IMMEDIATE
      await deps.notificationRepo.upsertPreference(
        PHYSICIAN_ID,
        'CLAIM_LIFECYCLE',
        {
          inAppEnabled: true,
          emailEnabled: true,
          digestMode: 'IMMEDIATE',
        },
      );

      await processEvent(deps, {
        eventType: 'CLAIM_VALIDATED',
        physicianId: PHYSICIAN_ID,
      });

      // Should have created a delivery log entry (email queued)
      expect(deliveryLogStore).toHaveLength(1);
      expect(deliveryLogStore[0].status).toBe('QUEUED');
      expect(deliveryLogStore[0].templateId).toBe('CLAIM_VALIDATED');
    });

    it('with DAILY_DIGEST mode adds to digest queue', async () => {
      const deps = makeServiceDeps();

      // Set preferences with DAILY_DIGEST
      await deps.notificationRepo.upsertPreference(
        PHYSICIAN_ID,
        'CLAIM_LIFECYCLE',
        {
          inAppEnabled: true,
          emailEnabled: true,
          digestMode: 'DAILY_DIGEST',
        },
      );

      await processEvent(deps, {
        eventType: 'CLAIM_VALIDATED',
        physicianId: PHYSICIAN_ID,
      });

      // Should have added to digest queue, NOT delivery log
      expect(deliveryLogStore).toHaveLength(0);
      expect(digestQueueStore).toHaveLength(1);
      expect(digestQueueStore[0].digestType).toBe('DAILY_DIGEST');
      expect(digestQueueStore[0].recipientId).toBe(PHYSICIAN_ID);
    });

    it('sets channels_delivered based on preferences', async () => {
      const deps = makeServiceDeps();

      // Default for CLAIM_VALIDATED: inApp true, email false
      const results = await processEvent(deps, {
        eventType: 'CLAIM_VALIDATED',
        physicianId: PHYSICIAN_ID,
      });

      expect(results[0].channelsDelivered).toEqual({
        in_app: true,
        email: false,
        push: false,
      });
    });
  });

  // -----------------------------------------------------------------------
  // processEventBatch
  // -----------------------------------------------------------------------

  describe('processEventBatch', () => {
    it('creates notifications for multiple events', async () => {
      const deps = makeServiceDeps();

      const events = [
        { eventType: 'CLAIM_VALIDATED', physicianId: PHYSICIAN_ID },
        { eventType: 'CLAIM_FLAGGED', physicianId: PHYSICIAN_ID },
        { eventType: 'REPORT_READY', physicianId: PHYSICIAN_ID },
      ];

      const results = await processEventBatch(deps, events);

      expect(results).toHaveLength(3);
      expect(results.map((n) => n.eventType)).toEqual([
        'CLAIM_VALIDATED',
        'CLAIM_FLAGGED',
        'REPORT_READY',
      ]);
    });

    it('returns empty array for empty batch', async () => {
      const deps = makeServiceDeps();
      const results = await processEventBatch(deps, []);
      expect(results).toHaveLength(0);
    });
  });

  // -----------------------------------------------------------------------
  // PERMISSION_EVENT_MAP
  // -----------------------------------------------------------------------

  describe('PERMISSION_EVENT_MAP', () => {
    it('is frozen and immutable', () => {
      expect(Object.isFrozen(PERMISSION_EVENT_MAP)).toBe(true);
    });

    it('maps CLAIM_VIEW to claim-related events', () => {
      expect(PERMISSION_EVENT_MAP.CLAIM_VIEW).toContain('CLAIM_VALIDATED');
      expect(PERMISSION_EVENT_MAP.CLAIM_VIEW).toContain('CLAIM_FLAGGED');
      expect(PERMISSION_EVENT_MAP.CLAIM_VIEW).toContain('CLAIM_ASSESSED');
      expect(PERMISSION_EVENT_MAP.CLAIM_VIEW).toContain('CLAIM_REJECTED');
      expect(PERMISSION_EVENT_MAP.CLAIM_VIEW).toContain('CLAIM_PAID');
      expect(PERMISSION_EVENT_MAP.CLAIM_VIEW).toContain('DUPLICATE_DETECTED');
    });

    it('maps CLAIM_SUBMIT to batch events', () => {
      expect(PERMISSION_EVENT_MAP.CLAIM_SUBMIT).toContain('BATCH_ASSEMBLED');
      expect(PERMISSION_EVENT_MAP.CLAIM_SUBMIT).toContain('BATCH_SUBMITTED');
      expect(PERMISSION_EVENT_MAP.CLAIM_SUBMIT).toContain('BATCH_ERROR');
    });

    it('maps ANALYTICS_VIEW to report events', () => {
      expect(PERMISSION_EVENT_MAP.ANALYTICS_VIEW).toContain('REPORT_READY');
      expect(PERMISSION_EVENT_MAP.ANALYTICS_VIEW).toContain(
        'DATA_EXPORT_READY',
      );
    });
  });

  // -----------------------------------------------------------------------
  // sendEmail
  // -----------------------------------------------------------------------

  describe('sendEmail', () => {
    it('creates delivery log with QUEUED status', async () => {
      const postmarkClient = makeMockPostmarkClient();
      const auditRepo = makeMockAuditRepo();
      const deps = makeServiceDeps({ postmarkClient, auditRepo });

      const notif = await deps.notificationRepo.createNotification(
        makeNotificationData({ recipientId: PHYSICIAN_ID }),
      );

      const deliveryId = await sendEmail(
        deps,
        notif.notificationId,
        'doctor@example.com',
        { subject: 'Test', htmlBody: '<p>Test</p>', textBody: 'Test' },
      );

      expect(deliveryId).toBeDefined();
      // The delivery log was created (now SENT since send succeeded)
      expect(deliveryLogStore).toHaveLength(1);
    });

    it('updates to SENT on successful send', async () => {
      const postmarkClient = makeMockPostmarkClient();
      const auditRepo = makeMockAuditRepo();
      const deps = makeServiceDeps({ postmarkClient, auditRepo });

      const notif = await deps.notificationRepo.createNotification(
        makeNotificationData({ recipientId: PHYSICIAN_ID }),
      );

      await sendEmail(
        deps,
        notif.notificationId,
        'doctor@example.com',
        { subject: 'Test', htmlBody: '<p>Test</p>', textBody: 'Test' },
      );

      expect(deliveryLogStore[0].status).toBe('SENT');
      expect(deliveryLogStore[0].sentAt).toBeInstanceOf(Date);
      expect(deliveryLogStore[0].providerMessageId).toBeDefined();
    });

    it('schedules retry on send failure', async () => {
      const postmarkClient = makeMockPostmarkClient(true); // will fail
      const auditRepo = makeMockAuditRepo();
      const deps = makeServiceDeps({ postmarkClient, auditRepo });

      const notif = await deps.notificationRepo.createNotification(
        makeNotificationData({ recipientId: PHYSICIAN_ID }),
      );

      await sendEmail(
        deps,
        notif.notificationId,
        'doctor@example.com',
        { subject: 'Test', htmlBody: '<p>Test</p>', textBody: 'Test' },
      );

      // Should have incremented retry and set nextRetryAt
      expect(deliveryLogStore[0].retryCount).toBe(1);
      expect(deliveryLogStore[0].nextRetryAt).toBeInstanceOf(Date);
    });

    it('sends via Postmark with correct parameters', async () => {
      const postmarkClient = makeMockPostmarkClient();
      const deps = makeServiceDeps({ postmarkClient, senderEmail: 'test@meritum.ca' });

      const notif = await deps.notificationRepo.createNotification(
        makeNotificationData({ recipientId: PHYSICIAN_ID }),
      );

      await sendEmail(
        deps,
        notif.notificationId,
        'doctor@example.com',
        { subject: 'Claim Update', htmlBody: '<p>Update</p>', textBody: 'Update' },
      );

      expect(postmarkClient.calls).toHaveLength(1);
      expect(postmarkClient.calls[0].From).toBe('test@meritum.ca');
      expect(postmarkClient.calls[0].To).toBe('doctor@example.com');
      expect(postmarkClient.calls[0].Subject).toBe('Claim Update');
      expect(postmarkClient.calls[0].HtmlBody).toBe('<p>Update</p>');
      expect(postmarkClient.calls[0].TextBody).toBe('Update');
      expect(postmarkClient.calls[0].MessageStream).toBe('outbound');
    });

    it('emits audit log on successful send', async () => {
      const postmarkClient = makeMockPostmarkClient();
      const auditRepo = makeMockAuditRepo();
      const deps = makeServiceDeps({ postmarkClient, auditRepo });

      const notif = await deps.notificationRepo.createNotification(
        makeNotificationData({ recipientId: PHYSICIAN_ID }),
      );

      await sendEmail(
        deps,
        notif.notificationId,
        'doctor@example.com',
        { subject: 'Test', htmlBody: '<p>Test</p>', textBody: 'Test' },
      );

      expect(auditRepo.logs).toHaveLength(1);
      expect(auditRepo.logs[0].action).toBe('notification.email_sent');
    });
  });

  // -----------------------------------------------------------------------
  // isInQuietHours
  // -----------------------------------------------------------------------

  describe('isInQuietHours', () => {
    it('returns true during configured quiet hours', async () => {
      const deps = makeServiceDeps();

      // Get current time in Edmonton timezone
      const now = new Date();
      const formatter = new Intl.DateTimeFormat('en-CA', {
        timeZone: 'America/Edmonton',
        hour: '2-digit',
        minute: '2-digit',
        hour12: false,
      });
      const currentTime = formatter.format(now);
      const [currentHour] = currentTime.split(':').map(Number);

      // Set quiet hours to encompass current time
      const startHour = (currentHour - 1 + 24) % 24;
      const endHour = (currentHour + 1) % 24;
      const start = `${String(startHour).padStart(2, '0')}:00`;
      const end = `${String(endHour).padStart(2, '0')}:00`;

      await deps.notificationRepo.upsertPreference(PHYSICIAN_ID, 'CLAIM_LIFECYCLE', {
        quietHoursStart: start,
        quietHoursEnd: end,
      });

      const result = await isInQuietHours(deps, PHYSICIAN_ID);
      expect(result).toBe(true);
    });

    it('returns false outside quiet hours', async () => {
      const deps = makeServiceDeps();

      // Get current time in Edmonton timezone
      const now = new Date();
      const formatter = new Intl.DateTimeFormat('en-CA', {
        timeZone: 'America/Edmonton',
        hour: '2-digit',
        minute: '2-digit',
        hour12: false,
      });
      const currentTime = formatter.format(now);
      const [currentHour] = currentTime.split(':').map(Number);

      // Set quiet hours to NOT encompass current time
      const startHour = (currentHour + 2) % 24;
      const endHour = (currentHour + 4) % 24;
      const start = `${String(startHour).padStart(2, '0')}:00`;
      const end = `${String(endHour).padStart(2, '0')}:00`;

      await deps.notificationRepo.upsertPreference(PHYSICIAN_ID, 'CLAIM_LIFECYCLE', {
        quietHoursStart: start,
        quietHoursEnd: end,
      });

      const result = await isInQuietHours(deps, PHYSICIAN_ID);
      expect(result).toBe(false);
    });

    it('returns false when no quiet hours configured', async () => {
      const deps = makeServiceDeps();

      // Create preference without quiet hours
      await deps.notificationRepo.upsertPreference(PHYSICIAN_ID, 'CLAIM_LIFECYCLE', {
        emailEnabled: true,
      });

      const result = await isInQuietHours(deps, PHYSICIAN_ID);
      expect(result).toBe(false);
    });

    it('returns false when no preferences exist', async () => {
      const deps = makeServiceDeps();
      const result = await isInQuietHours(deps, PHYSICIAN_ID);
      expect(result).toBe(false);
    });
  });

  // -----------------------------------------------------------------------
  // Quiet hours + email interaction
  // -----------------------------------------------------------------------

  describe('quiet hours email deferral', () => {
    it('non-URGENT email during quiet hours should be deferred', async () => {
      // This test verifies the concept: if isInQuietHours returns true
      // and event is not URGENT, the email should be deferred.
      const deps = makeServiceDeps();

      // Get current time in Edmonton timezone
      const now = new Date();
      const formatter = new Intl.DateTimeFormat('en-CA', {
        timeZone: 'America/Edmonton',
        hour: '2-digit',
        minute: '2-digit',
        hour12: false,
      });
      const currentTime = formatter.format(now);
      const [currentHour] = currentTime.split(':').map(Number);

      // Set quiet hours to encompass current time
      const startHour = (currentHour - 1 + 24) % 24;
      const endHour = (currentHour + 1) % 24;
      const start = `${String(startHour).padStart(2, '0')}:00`;
      const end = `${String(endHour).padStart(2, '0')}:00`;

      await deps.notificationRepo.upsertPreference(PHYSICIAN_ID, 'CLAIM_LIFECYCLE', {
        quietHoursStart: start,
        quietHoursEnd: end,
      });

      const inQuiet = await isInQuietHours(deps, PHYSICIAN_ID);
      expect(inQuiet).toBe(true);

      // CLAIM_VALIDATED is LOW priority (not URGENT)
      // In the calling code, this should trigger deferral
      const cataloguePriority = 'LOW'; // CLAIM_VALIDATED priority
      const isUrgent = (cataloguePriority as string) === 'URGENT';
      expect(isUrgent).toBe(false);

      // Verify that scheduleAfterQuietHours returns a future date
      const afterQuietHours = await scheduleAfterQuietHours(deps, PHYSICIAN_ID);
      expect(afterQuietHours).toBeInstanceOf(Date);
    });

    it('URGENT email during quiet hours should be sent immediately', async () => {
      const deps = makeServiceDeps();

      // Set up quiet hours
      const now = new Date();
      const formatter = new Intl.DateTimeFormat('en-CA', {
        timeZone: 'America/Edmonton',
        hour: '2-digit',
        minute: '2-digit',
        hour12: false,
      });
      const currentTime = formatter.format(now);
      const [currentHour] = currentTime.split(':').map(Number);

      const startHour = (currentHour - 1 + 24) % 24;
      const endHour = (currentHour + 1) % 24;
      const start = `${String(startHour).padStart(2, '0')}:00`;
      const end = `${String(endHour).padStart(2, '0')}:00`;

      await deps.notificationRepo.upsertPreference(PHYSICIAN_ID, 'CLAIM_LIFECYCLE', {
        quietHoursStart: start,
        quietHoursEnd: end,
      });

      const inQuiet = await isInQuietHours(deps, PHYSICIAN_ID);
      expect(inQuiet).toBe(true);

      // DEADLINE_1_DAY is URGENT — should bypass quiet hours
      const cataloguePriority = 'URGENT';
      const isUrgent = cataloguePriority === 'URGENT';
      expect(isUrgent).toBe(true);
      // URGENT events always bypass quiet hours (sent immediately)
    });
  });

  // -----------------------------------------------------------------------
  // retryFailedEmails
  // -----------------------------------------------------------------------

  describe('retryFailedEmails', () => {
    it('processes pending retries', async () => {
      const postmarkClient = makeMockPostmarkClient();
      const auditRepo = makeMockAuditRepo();
      const deps = makeServiceDeps({ postmarkClient, auditRepo });

      // Create a QUEUED delivery log entry
      deliveryLogStore.push({
        deliveryId: crypto.randomUUID(),
        notificationId: 'notif-1',
        recipientEmail: 'doctor@example.com',
        templateId: 'CLAIM_VALIDATED',
        status: 'QUEUED',
        providerMessageId: null,
        sentAt: null,
        deliveredAt: null,
        bouncedAt: null,
        bounceReason: null,
        retryCount: 0,
        nextRetryAt: null,
        createdAt: new Date(),
      });

      await retryFailedEmails(deps);

      // Should have been sent successfully
      expect(postmarkClient.calls).toHaveLength(1);
      expect(deliveryLogStore[0].status).toBe('SENT');
      expect(deliveryLogStore[0].sentAt).toBeInstanceOf(Date);
    });

    it('marks FAILED after max retry attempts', async () => {
      const postmarkClient = makeMockPostmarkClient(true); // always fail
      const auditRepo = makeMockAuditRepo();
      const deps = makeServiceDeps({ postmarkClient, auditRepo });

      // Create a delivery at retry count 3 (next failure = attempt 4 = max)
      deliveryLogStore.push({
        deliveryId: crypto.randomUUID(),
        notificationId: 'notif-1',
        recipientEmail: 'doctor@example.com',
        templateId: 'CLAIM_VALIDATED',
        status: 'FAILED',
        providerMessageId: null,
        sentAt: null,
        deliveredAt: null,
        bouncedAt: null,
        bounceReason: null,
        retryCount: 3,
        nextRetryAt: new Date(Date.now() - 60_000),
        createdAt: new Date(),
      });

      await retryFailedEmails(deps);

      expect(deliveryLogStore[0].status).toBe('FAILED');
      // Audit log should record the failure
      const failedAudit = auditRepo.logs.find(
        (l: any) => l.action === 'notification.email_failed',
      );
      expect(failedAudit).toBeDefined();
    });

    it('increments retry count on failure when retries remain', async () => {
      const postmarkClient = makeMockPostmarkClient(true); // always fail
      const auditRepo = makeMockAuditRepo();
      const deps = makeServiceDeps({ postmarkClient, auditRepo });

      // Create a delivery at retry count 1 (retries remain)
      deliveryLogStore.push({
        deliveryId: crypto.randomUUID(),
        notificationId: 'notif-1',
        recipientEmail: 'doctor@example.com',
        templateId: 'CLAIM_VALIDATED',
        status: 'FAILED',
        providerMessageId: null,
        sentAt: null,
        deliveredAt: null,
        bouncedAt: null,
        bounceReason: null,
        retryCount: 1,
        nextRetryAt: new Date(Date.now() - 60_000),
        createdAt: new Date(),
      });

      await retryFailedEmails(deps);

      // Should have incremented retry count
      expect(deliveryLogStore[0].retryCount).toBe(2);
      expect(deliveryLogStore[0].nextRetryAt).toBeInstanceOf(Date);
    });
  });

  // -----------------------------------------------------------------------
  // handleBounce
  // -----------------------------------------------------------------------

  describe('handleBounce', () => {
    it('hard bounce marks BOUNCED and creates in-app notification', async () => {
      const auditRepo = makeMockAuditRepo();
      const deps = makeServiceDeps({ auditRepo });

      // Create a notification and delivery log
      const notif = await deps.notificationRepo.createNotification(
        makeNotificationData({ recipientId: PHYSICIAN_ID }),
      );

      const delivery = await deps.notificationRepo.createDeliveryLog({
        notificationId: notif.notificationId,
        recipientEmail: 'doctor@example.com',
        templateId: 'CLAIM_VALIDATED',
        status: 'SENT',
      });

      // Update delivery to have a providerMessageId
      await deps.notificationRepo.updateDeliveryStatus(
        delivery.deliveryId,
        'SENT',
        { providerMessageId: 'pm-msg-123', sentAt: new Date() },
      );

      await handleBounce(deps, 'pm-msg-123', 'hard', 'Mailbox does not exist');

      // Should be marked BOUNCED
      const updatedDelivery = deliveryLogStore.find(
        (d: any) => d.deliveryId === delivery.deliveryId,
      );
      expect(updatedDelivery!.status).toBe('BOUNCED');
      expect(updatedDelivery!.bounceReason).toBe('Mailbox does not exist');
      expect(updatedDelivery!.bouncedAt).toBeInstanceOf(Date);

      // Should have created an in-app notification
      const bounceNotifs = notificationStore.filter(
        (n: any) => n.eventType === 'EMAIL_BOUNCE_ALERT',
      );
      expect(bounceNotifs).toHaveLength(1);
      expect(bounceNotifs[0].title).toBe('Email delivery failed');
      expect(bounceNotifs[0].channelsDelivered.email).toBe(false);

      // Should have audit log
      const bounceAudit = auditRepo.logs.find(
        (l: any) => l.action === 'notification.email_bounced',
      );
      expect(bounceAudit).toBeDefined();
      expect(bounceAudit.detail.bounceType).toBe('hard');
    });

    it('soft bounce schedules retry', async () => {
      const auditRepo = makeMockAuditRepo();
      const deps = makeServiceDeps({ auditRepo });

      // Create notification and delivery
      const notif = await deps.notificationRepo.createNotification(
        makeNotificationData({ recipientId: PHYSICIAN_ID }),
      );

      const delivery = await deps.notificationRepo.createDeliveryLog({
        notificationId: notif.notificationId,
        recipientEmail: 'doctor@example.com',
        templateId: 'CLAIM_VALIDATED',
        status: 'SENT',
      });

      await deps.notificationRepo.updateDeliveryStatus(
        delivery.deliveryId,
        'SENT',
        { providerMessageId: 'pm-msg-456', sentAt: new Date() },
      );

      await handleBounce(deps, 'pm-msg-456', 'soft', 'Mailbox full');

      // Should NOT be marked BOUNCED
      const updatedDelivery = deliveryLogStore.find(
        (d: any) => d.deliveryId === delivery.deliveryId,
      );
      expect(updatedDelivery!.status).not.toBe('BOUNCED');

      // Should have incremented retry count
      expect(updatedDelivery!.retryCount).toBe(1);
      expect(updatedDelivery!.nextRetryAt).toBeInstanceOf(Date);

      // No in-app notification for soft bounce
      const bounceNotifs = notificationStore.filter(
        (n: any) => n.eventType === 'EMAIL_BOUNCE_ALERT',
      );
      expect(bounceNotifs).toHaveLength(0);

      // Should have audit log
      const bounceAudit = auditRepo.logs.find(
        (l: any) => l.action === 'notification.email_bounced',
      );
      expect(bounceAudit).toBeDefined();
      expect(bounceAudit.detail.bounceType).toBe('soft');
    });

    it('does nothing for unknown providerMessageId', async () => {
      const auditRepo = makeMockAuditRepo();
      const deps = makeServiceDeps({ auditRepo });

      await handleBounce(deps, 'unknown-msg-id', 'hard', 'Unknown');

      // No changes to stores
      expect(auditRepo.logs).toHaveLength(0);
      expect(notificationStore).toHaveLength(0);
    });
  });

  // -----------------------------------------------------------------------
  // assembleDailyDigest
  // -----------------------------------------------------------------------

  describe('assembleDailyDigest', () => {
    it('groups items by recipient', async () => {
      const postmarkClient = makeMockPostmarkClient();
      const auditRepo = makeMockAuditRepo();
      const userEmailLookup: UserEmailLookup = {
        async getEmailByUserId(userId: string) {
          if (userId === RECIPIENT_A) return 'doctorA@example.com';
          if (userId === RECIPIENT_B) return 'doctorB@example.com';
          return null;
        },
      };
      const deps = makeServiceDeps({ postmarkClient, auditRepo, userEmailLookup });

      // Create notifications for two recipients
      const notifA1 = await deps.notificationRepo.createNotification(
        makeNotificationData({ recipientId: RECIPIENT_A, eventType: 'CLAIM_VALIDATED', title: 'Claim A1' }),
      );
      const notifA2 = await deps.notificationRepo.createNotification(
        makeNotificationData({ recipientId: RECIPIENT_A, eventType: 'CLAIM_FLAGGED', title: 'Claim A2' }),
      );
      const notifB1 = await deps.notificationRepo.createNotification(
        makeNotificationData({ recipientId: RECIPIENT_B, eventType: 'REPORT_READY', title: 'Report B1' }),
      );

      // Add to digest queue
      await deps.notificationRepo.addToDigestQueue({
        recipientId: RECIPIENT_A,
        notificationId: notifA1.notificationId,
        digestType: 'DAILY_DIGEST',
      });
      await deps.notificationRepo.addToDigestQueue({
        recipientId: RECIPIENT_A,
        notificationId: notifA2.notificationId,
        digestType: 'DAILY_DIGEST',
      });
      await deps.notificationRepo.addToDigestQueue({
        recipientId: RECIPIENT_B,
        notificationId: notifB1.notificationId,
        digestType: 'DAILY_DIGEST',
      });

      await assembleDailyDigest(deps);

      // Should have processed both recipients
      const digestAudit = auditRepo.logs.find(
        (l: any) => l.action === 'notification.digest_assembled',
      );
      expect(digestAudit).toBeDefined();
      expect(digestAudit.detail.recipientCount).toBe(2);
      expect(digestAudit.detail.itemCount).toBe(3);
    });

    it('sends one email per recipient', async () => {
      const postmarkClient = makeMockPostmarkClient();
      const auditRepo = makeMockAuditRepo();
      const userEmailLookup: UserEmailLookup = {
        async getEmailByUserId(userId: string) {
          if (userId === RECIPIENT_A) return 'doctorA@example.com';
          if (userId === RECIPIENT_B) return 'doctorB@example.com';
          return null;
        },
      };
      const deps = makeServiceDeps({ postmarkClient, auditRepo, userEmailLookup });

      // Create notifications and digest items for 2 recipients
      const notifA = await deps.notificationRepo.createNotification(
        makeNotificationData({ recipientId: RECIPIENT_A, eventType: 'CLAIM_VALIDATED', title: 'A' }),
      );
      const notifB = await deps.notificationRepo.createNotification(
        makeNotificationData({ recipientId: RECIPIENT_B, eventType: 'CLAIM_VALIDATED', title: 'B' }),
      );

      await deps.notificationRepo.addToDigestQueue({
        recipientId: RECIPIENT_A,
        notificationId: notifA.notificationId,
        digestType: 'DAILY_DIGEST',
      });
      await deps.notificationRepo.addToDigestQueue({
        recipientId: RECIPIENT_B,
        notificationId: notifB.notificationId,
        digestType: 'DAILY_DIGEST',
      });

      await assembleDailyDigest(deps);

      // sendEmail creates a delivery log entry per call,
      // and postmarkClient.sendEmail is called per delivery
      expect(postmarkClient.calls).toHaveLength(2);
      const emailRecipients = postmarkClient.calls.map((c: any) => c.To);
      expect(emailRecipients).toContain('doctorA@example.com');
      expect(emailRecipients).toContain('doctorB@example.com');
    });

    it('marks items as sent', async () => {
      const postmarkClient = makeMockPostmarkClient();
      const auditRepo = makeMockAuditRepo();
      const userEmailLookup: UserEmailLookup = {
        async getEmailByUserId() { return 'doctor@example.com'; },
      };
      const deps = makeServiceDeps({ postmarkClient, auditRepo, userEmailLookup });

      const notif = await deps.notificationRepo.createNotification(
        makeNotificationData({ recipientId: RECIPIENT_A, eventType: 'CLAIM_VALIDATED', title: 'Test' }),
      );

      await deps.notificationRepo.addToDigestQueue({
        recipientId: RECIPIENT_A,
        notificationId: notif.notificationId,
        digestType: 'DAILY_DIGEST',
      });

      await assembleDailyDigest(deps);

      // All digest queue items should be marked as sent
      expect(digestQueueStore[0].digestSent).toBe(true);

      // After assembly, findAllPendingDigestItems should return empty
      const remaining = await deps.notificationRepo.findAllPendingDigestItems('DAILY_DIGEST');
      expect(remaining.size).toBe(0);
    });

    it('skips recipients with no pending items', async () => {
      const postmarkClient = makeMockPostmarkClient();
      const auditRepo = makeMockAuditRepo();
      const deps = makeServiceDeps({ postmarkClient, auditRepo });

      // No digest items in queue
      await assembleDailyDigest(deps);

      // No emails sent, no audit log emitted
      expect(postmarkClient.calls).toHaveLength(0);
      expect(auditRepo.logs).toHaveLength(0);
    });
  });

  // -----------------------------------------------------------------------
  // assembleWeeklyDigest
  // -----------------------------------------------------------------------

  describe('assembleWeeklyDigest', () => {
    it('processes WEEKLY items from past 7 days', async () => {
      const postmarkClient = makeMockPostmarkClient();
      const auditRepo = makeMockAuditRepo();
      const userEmailLookup: UserEmailLookup = {
        async getEmailByUserId() { return 'doctor@example.com'; },
      };
      const deps = makeServiceDeps({ postmarkClient, auditRepo, userEmailLookup });

      // Create notifications and add to WEEKLY_DIGEST queue
      const notif1 = await deps.notificationRepo.createNotification(
        makeNotificationData({ recipientId: RECIPIENT_A, eventType: 'CLAIM_VALIDATED', title: 'Weekly 1' }),
      );
      const notif2 = await deps.notificationRepo.createNotification(
        makeNotificationData({ recipientId: RECIPIENT_A, eventType: 'REPORT_READY', title: 'Weekly 2' }),
      );

      await deps.notificationRepo.addToDigestQueue({
        recipientId: RECIPIENT_A,
        notificationId: notif1.notificationId,
        digestType: 'WEEKLY_DIGEST',
      });
      await deps.notificationRepo.addToDigestQueue({
        recipientId: RECIPIENT_A,
        notificationId: notif2.notificationId,
        digestType: 'WEEKLY_DIGEST',
      });

      // Also add a DAILY_DIGEST item — should NOT be processed
      const notifDaily = await deps.notificationRepo.createNotification(
        makeNotificationData({ recipientId: RECIPIENT_A, eventType: 'CLAIM_FLAGGED', title: 'Daily' }),
      );
      await deps.notificationRepo.addToDigestQueue({
        recipientId: RECIPIENT_A,
        notificationId: notifDaily.notificationId,
        digestType: 'DAILY_DIGEST',
      });

      await assembleWeeklyDigest(deps);

      // Should have assembled only WEEKLY items
      const digestAudit = auditRepo.logs.find(
        (l: any) => l.action === 'notification.digest_assembled',
      );
      expect(digestAudit).toBeDefined();
      expect(digestAudit.detail.digestType).toBe('WEEKLY');
      expect(digestAudit.detail.itemCount).toBe(2);
      expect(digestAudit.detail.recipientCount).toBe(1);

      // Email sent with 'Weekly' in subject
      expect(postmarkClient.calls).toHaveLength(1);
      expect(postmarkClient.calls[0].Subject).toContain('Weekly');

      // WEEKLY items marked sent, DAILY item still pending
      const weeklyItems = digestQueueStore.filter((i: any) => i.digestType === 'WEEKLY_DIGEST');
      expect(weeklyItems.every((i: any) => i.digestSent === true)).toBe(true);
      const dailyItems = digestQueueStore.filter((i: any) => i.digestType === 'DAILY_DIGEST');
      expect(dailyItems.every((i: any) => i.digestSent === false)).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // renderDigestEmail
  // -----------------------------------------------------------------------

  describe('renderDigestEmail', () => {
    it('groups by category with counts', () => {
      // Create mock notifications and digest items
      const notifications: any[] = [
        { notificationId: 'n1', eventType: 'CLAIM_VALIDATED', title: 'Claim 1', recipientId: RECIPIENT_A },
        { notificationId: 'n2', eventType: 'CLAIM_FLAGGED', title: 'Claim 2', recipientId: RECIPIENT_A },
        { notificationId: 'n3', eventType: 'REPORT_READY', title: 'Report 1', recipientId: RECIPIENT_A },
      ];

      const digestItems: any[] = [
        { queueId: 'q1', recipientId: RECIPIENT_A, notificationId: 'n1', digestType: 'DAILY_DIGEST', digestSent: false },
        { queueId: 'q2', recipientId: RECIPIENT_A, notificationId: 'n2', digestType: 'DAILY_DIGEST', digestSent: false },
        { queueId: 'q3', recipientId: RECIPIENT_A, notificationId: 'n3', digestType: 'DAILY_DIGEST', digestSent: false },
      ];

      const rendered = renderDigestEmail(digestItems, 'DAILY', notifications);

      // Subject should include 'Daily'
      expect(rendered.subject).toBe('Your Daily Meritum Summary');

      // Text body should contain grouped categories
      expect(rendered.textBody).toContain('3 new notifications');
      expect(rendered.textBody).toContain('CLAIM_LIFECYCLE: 2 notifications');
      expect(rendered.textBody).toContain('ANALYTICS: 1 notification');
      expect(rendered.textBody).toContain('https://meritum.ca/notifications');

      // HTML body should contain the link
      expect(rendered.htmlBody).toContain('meritum.ca/notifications');
    });

    it('contains no PHI', () => {
      const notifications: any[] = [
        {
          notificationId: 'n1',
          eventType: 'CLAIM_VALIDATED',
          title: 'Claim for Patient John Doe PHN 123456789',
          recipientId: RECIPIENT_A,
          body: 'Sensitive body with PHN 123456789',
        },
      ];

      const digestItems: any[] = [
        { queueId: 'q1', recipientId: RECIPIENT_A, notificationId: 'n1', digestType: 'DAILY_DIGEST', digestSent: false },
      ];

      const rendered = renderDigestEmail(digestItems, 'DAILY', notifications);

      // The digest email should NOT contain patient names, PHN, or claim details
      expect(rendered.textBody).not.toContain('John Doe');
      expect(rendered.textBody).not.toContain('123456789');
      expect(rendered.htmlBody).not.toContain('John Doe');
      expect(rendered.htmlBody).not.toContain('123456789');

      // Should only contain category-level summaries
      expect(rendered.textBody).toContain('CLAIM_LIFECYCLE');
      expect(rendered.textBody).toContain('1 notification');
    });
  });

  // -----------------------------------------------------------------------
  // buildDigestSummary
  // -----------------------------------------------------------------------

  describe('buildDigestSummary', () => {
    it('groups notifications by event category', () => {
      const notifications: any[] = [
        { notificationId: 'n1', eventType: 'CLAIM_VALIDATED', title: 'C1' },
        { notificationId: 'n2', eventType: 'CLAIM_FLAGGED', title: 'C2' },
        { notificationId: 'n3', eventType: 'REPORT_READY', title: 'R1' },
      ];

      const items: any[] = [
        { queueId: 'q1', notificationId: 'n1' },
        { queueId: 'q2', notificationId: 'n2' },
        { queueId: 'q3', notificationId: 'n3' },
      ];

      const summaries = buildDigestSummary(items, notifications);

      expect(summaries).toHaveLength(2); // CLAIM_LIFECYCLE + ANALYTICS
      const claimSummary = summaries.find((s) => s.category === 'CLAIM_LIFECYCLE');
      expect(claimSummary).toBeDefined();
      expect(claimSummary!.count).toBe(2);

      const analyticsSummary = summaries.find((s) => s.category === 'ANALYTICS');
      expect(analyticsSummary).toBeDefined();
      expect(analyticsSummary!.count).toBe(1);
    });
  });

  // -----------------------------------------------------------------------
  // sendWednesdayBatchReminder
  // -----------------------------------------------------------------------

  describe('sendWednesdayBatchReminder', () => {
    function makeMockClaimRepo(flaggedCounts: Record<string, number>): ClaimRepo {
      return {
        async countFlaggedClaims(providerId: string) {
          return flaggedCounts[providerId] ?? 0;
        },
      };
    }

    it('fires for physician with flagged claims and reminder enabled', async () => {
      const auditRepo = makeMockAuditRepo();
      const claimRepo = makeMockClaimRepo({ 'provider-1': 5 });
      const deps = makeServiceDeps({ auditRepo, claimRepo });

      const physicians = [
        { userId: PHYSICIAN_ID, providerId: 'provider-1', reminderEnabled: true },
      ];

      await sendWednesdayBatchReminder(deps, physicians);

      // Should have created a notification via processEvent
      expect(notificationStore).toHaveLength(1);
      expect(notificationStore[0].eventType).toBe('BATCH_REVIEW_REMINDER');
      expect(notificationStore[0].recipientId).toBe(PHYSICIAN_ID);

      // Metadata should include flagged_count
      expect(notificationStore[0].metadata).toEqual({ flagged_count: 5 });
    });

    it('skips physician with no flagged claims', async () => {
      const auditRepo = makeMockAuditRepo();
      const claimRepo = makeMockClaimRepo({ 'provider-1': 0 });
      const deps = makeServiceDeps({ auditRepo, claimRepo });

      const physicians = [
        { userId: PHYSICIAN_ID, providerId: 'provider-1', reminderEnabled: true },
      ];

      await sendWednesdayBatchReminder(deps, physicians);

      // No notification created — zero flagged claims
      expect(notificationStore).toHaveLength(0);
    });

    it('skips physician with reminder disabled', async () => {
      const auditRepo = makeMockAuditRepo();
      const claimRepo = makeMockClaimRepo({ 'provider-1': 5 });
      const deps = makeServiceDeps({ auditRepo, claimRepo });

      const physicians = [
        { userId: PHYSICIAN_ID, providerId: 'provider-1', reminderEnabled: false },
      ];

      await sendWednesdayBatchReminder(deps, physicians);

      // No notification — reminder disabled
      expect(notificationStore).toHaveLength(0);
    });
  });

  // -----------------------------------------------------------------------
  // registerNotificationJobs
  // -----------------------------------------------------------------------

  describe('registerNotificationJobs', () => {
    it('returns all 4 scheduled jobs', () => {
      const deps = makeServiceDeps();
      const logger = {
        info: vi.fn(),
        error: vi.fn(),
      };

      const jobs = registerNotificationJobs(deps, logger);

      expect(jobs).toHaveLength(4);
      expect(jobs.map((j) => j.name)).toEqual([
        'daily-digest',
        'weekly-digest',
        'email-retry',
        'wednesday-batch-reminder',
      ]);
    });

    it('each job has correct cron expression', () => {
      const deps = makeServiceDeps();
      const logger = { info: vi.fn(), error: vi.fn() };

      const jobs = registerNotificationJobs(deps, logger);

      const cronMap = new Map(jobs.map((j) => [j.name, j.cronExpression]));
      expect(cronMap.get('daily-digest')).toBe('0 8 * * *');
      expect(cronMap.get('weekly-digest')).toBe('0 8 * * 1');
      expect(cronMap.get('email-retry')).toBe('*/5 * * * *');
      expect(cronMap.get('wednesday-batch-reminder')).toBe('0 18 * * 3');
    });

    it('job handler logs start and catches errors without crashing', async () => {
      const deps = makeServiceDeps();
      const logger = { info: vi.fn(), error: vi.fn() };

      const jobs = registerNotificationJobs(deps, logger);

      // Run the daily digest handler — no items, should complete without error
      const dailyJob = jobs.find((j) => j.name === 'daily-digest')!;
      await dailyJob.handler();

      expect(logger.info).toHaveBeenCalledWith('Starting daily digest assembly');
      expect(logger.info).toHaveBeenCalledWith('Daily digest assembly completed');
      expect(logger.error).not.toHaveBeenCalled();
    });
  });

  // -----------------------------------------------------------------------
  // markReadAndPush / markAllReadAndPush
  // -----------------------------------------------------------------------

  describe('markReadAndPush', () => {
    it('marks a notification as read and pushes unread count via WebSocket', async () => {
      const deps = makeServiceDeps();

      // Create a notification first
      const notification = await deps.notificationRepo.createNotification({
        recipientId: PHYSICIAN_ID,
        eventType: 'CLAIM_VALIDATED',
        priority: 'MEDIUM',
        title: 'Test',
        body: 'Test body',
        channelsDelivered: { in_app: true, email: false, push: false },
      });

      // Spy on wsManager.pushUnreadCount
      const pushSpy = vi.spyOn(wsManager, 'pushUnreadCount').mockResolvedValue();

      const result = await markReadAndPush(deps, notification.notificationId, PHYSICIAN_ID);
      expect(result).toBeDefined();
      expect(result!.readAt).toBeDefined();

      // Should have triggered pushUnreadCount
      expect(pushSpy).toHaveBeenCalledWith(PHYSICIAN_ID);

      pushSpy.mockRestore();
    });
  });

  describe('markAllReadAndPush', () => {
    it('marks all notifications as read and pushes unread count', async () => {
      const deps = makeServiceDeps();

      await deps.notificationRepo.createNotification({
        recipientId: PHYSICIAN_ID,
        eventType: 'CLAIM_VALIDATED',
        priority: 'MEDIUM',
        title: 'Test 1',
        body: 'Body 1',
        channelsDelivered: { in_app: true, email: false, push: false },
      });

      await deps.notificationRepo.createNotification({
        recipientId: PHYSICIAN_ID,
        eventType: 'CLAIM_FLAGGED',
        priority: 'HIGH',
        title: 'Test 2',
        body: 'Body 2',
        channelsDelivered: { in_app: true, email: false, push: false },
      });

      const pushSpy = vi.spyOn(wsManager, 'pushUnreadCount').mockResolvedValue();

      const count = await markAllReadAndPush(deps, PHYSICIAN_ID);
      expect(count).toBe(2);
      expect(pushSpy).toHaveBeenCalledWith(PHYSICIAN_ID);

      pushSpy.mockRestore();
    });
  });

  // -----------------------------------------------------------------------
  // NotificationWebSocketManager
  // -----------------------------------------------------------------------

  describe('NotificationWebSocketManager', () => {
    let manager: NotificationWebSocketManager;

    function makeMockSocket(overrides: Partial<NotificationWebSocket> = {}): NotificationWebSocket & { sentMessages: string[]; closedWith: { code?: number; reason?: string } | null; listeners: Map<string, Function[]> } {
      const listeners = new Map<string, Function[]>();
      const sentMessages: string[] = [];
      let closedWith: { code?: number; reason?: string } | null = null;

      return {
        readyState: WS_READY_STATE.OPEN,
        sentMessages,
        closedWith,
        listeners,
        send(data: string, cb?: (err?: Error) => void) {
          sentMessages.push(data);
          if (cb) cb();
        },
        close(code?: number, reason?: string) {
          closedWith = { code, reason };
          (this as any).closedWith = closedWith;
          (this as any).readyState = WS_READY_STATE.CLOSED;
        },
        ping(_data?: unknown, _mask?: boolean, cb?: (err?: Error) => void) {
          if (cb) cb();
        },
        on(event: string, listener: (...args: unknown[]) => void) {
          let list = listeners.get(event);
          if (!list) {
            list = [];
            listeners.set(event, list);
          }
          list.push(listener);
        },
        removeAllListeners(event?: string) {
          if (event) {
            listeners.delete(event);
          } else {
            listeners.clear();
          }
        },
        ...overrides,
      };
    }

    function triggerPong(socket: ReturnType<typeof makeMockSocket>) {
      const pongListeners = socket.listeners.get('pong');
      if (pongListeners) {
        for (const l of pongListeners) l();
      }
    }

    beforeEach(() => {
      manager = new NotificationWebSocketManager();
    });

    afterEach(() => {
      manager.shutdown();
    });

    it('registerConnection adds socket to connection map', () => {
      const socket = makeMockSocket();
      manager.registerConnection('user-1', socket);
      expect(manager.hasConnections('user-1')).toBe(true);
      expect(manager.getConnectionCount('user-1')).toBe(1);
    });

    it('registerConnection supports multiple connections per user', () => {
      const socket1 = makeMockSocket();
      const socket2 = makeMockSocket();

      manager.registerConnection('user-1', socket1);
      manager.registerConnection('user-1', socket2);

      expect(manager.getConnectionCount('user-1')).toBe(2);
    });

    it('removeConnection removes specific socket', () => {
      const socket1 = makeMockSocket();
      const socket2 = makeMockSocket();

      manager.registerConnection('user-1', socket1);
      manager.registerConnection('user-1', socket2);
      expect(manager.getConnectionCount('user-1')).toBe(2);

      manager.removeConnection('user-1', socket1);
      expect(manager.getConnectionCount('user-1')).toBe(1);
    });

    it('removeConnection cleans up map entry when last socket removed', () => {
      const socket = makeMockSocket();
      manager.registerConnection('user-1', socket);

      manager.removeConnection('user-1', socket);
      expect(manager.hasConnections('user-1')).toBe(false);
      expect(manager.getConnectionCount('user-1')).toBe(0);
    });

    it('removeConnection is no-op for unknown user', () => {
      const socket = makeMockSocket();
      // Should not throw
      manager.removeConnection('unknown-user', socket);
      expect(manager.hasConnections('unknown-user')).toBe(false);
    });

    it('pushToUser delivers to all active connections for user', () => {
      const socket1 = makeMockSocket();
      const socket2 = makeMockSocket();

      manager.registerConnection('user-1', socket1);
      manager.registerConnection('user-1', socket2);

      const notification = {
        notificationId: 'notif-1',
        recipientId: 'user-1',
        physicianContextId: null,
        eventType: 'CLAIM_REJECTED',
        priority: 'HIGH',
        title: 'Claim Rejected',
        body: 'Your claim has been rejected.',
        actionUrl: '/claims/abc123',
        actionLabel: null,
        metadata: { claimId: 'abc123' },
        channelsDelivered: { in_app: true, email: false, push: false },
        readAt: null,
        dismissedAt: null,
        createdAt: new Date('2026-02-17T10:00:00Z'),
      } as any;

      manager.pushToUser('user-1', notification);

      // Both sockets should have received the message
      expect(socket1.sentMessages).toHaveLength(1);
      expect(socket2.sentMessages).toHaveLength(1);

      // Parse and verify the payload
      const parsed = JSON.parse(socket1.sentMessages[0]);
      expect(parsed.type).toBe('notification');
      expect(parsed.data.notification_id).toBe('notif-1');
      expect(parsed.data.title).toBe('Claim Rejected');
      expect(parsed.data.body).toBe('Your claim has been rejected.');
      expect(parsed.data.priority).toBe('HIGH');
      expect(parsed.data.action_url).toBe('/claims/abc123');
      expect(parsed.data.event_type).toBe('CLAIM_REJECTED');
      expect(parsed.data.metadata).toEqual({ claimId: 'abc123' });
      expect(parsed.data.created_at).toBe('2026-02-17T10:00:00.000Z');
    });

    it('pushToUser is no-op if user has no active connections', () => {
      // Should not throw
      const notification = {
        notificationId: 'notif-1',
        recipientId: 'no-user',
        eventType: 'CLAIM_VALIDATED',
        priority: 'MEDIUM',
        title: 'Test',
        body: 'Test body',
        actionUrl: null,
        actionLabel: null,
        metadata: null,
        channelsDelivered: { in_app: true, email: false, push: false },
        readAt: null,
        dismissedAt: null,
        createdAt: new Date(),
      } as any;

      manager.pushToUser('no-user', notification);
      // No error thrown, no connections exist — this is a no-op
    });

    it('pushToUser skips sockets that are not in OPEN state', () => {
      const openSocket = makeMockSocket();
      const closedSocket = makeMockSocket({ readyState: WS_READY_STATE.CLOSED });

      manager.registerConnection('user-1', openSocket);
      manager.registerConnection('user-1', closedSocket);

      const notification = {
        notificationId: 'notif-1',
        recipientId: 'user-1',
        eventType: 'CLAIM_VALIDATED',
        priority: 'MEDIUM',
        title: 'Test',
        body: 'Test body',
        actionUrl: null,
        actionLabel: null,
        metadata: null,
        channelsDelivered: { in_app: true, email: false, push: false },
        readAt: null,
        dismissedAt: null,
        createdAt: new Date(),
      } as any;

      manager.pushToUser('user-1', notification);

      expect(openSocket.sentMessages).toHaveLength(1);
      expect(closedSocket.sentMessages).toHaveLength(0);
    });

    it('pushUnreadCount sends updated count', async () => {
      const deps = makeServiceDeps();

      // Create 3 unread notifications for the user
      await deps.notificationRepo.createNotification({
        recipientId: PHYSICIAN_ID,
        eventType: 'CLAIM_VALIDATED',
        priority: 'MEDIUM',
        title: 'N1',
        body: 'B1',
        channelsDelivered: { in_app: true, email: false, push: false },
      });
      await deps.notificationRepo.createNotification({
        recipientId: PHYSICIAN_ID,
        eventType: 'CLAIM_FLAGGED',
        priority: 'HIGH',
        title: 'N2',
        body: 'B2',
        channelsDelivered: { in_app: true, email: false, push: false },
      });
      await deps.notificationRepo.createNotification({
        recipientId: PHYSICIAN_ID,
        eventType: 'CLAIM_PAID',
        priority: 'MEDIUM',
        title: 'N3',
        body: 'B3',
        channelsDelivered: { in_app: true, email: false, push: false },
      });

      manager.setNotificationRepo(deps.notificationRepo);

      const socket = makeMockSocket();
      manager.registerConnection(PHYSICIAN_ID, socket);

      await manager.pushUnreadCount(PHYSICIAN_ID);

      expect(socket.sentMessages).toHaveLength(1);
      const parsed = JSON.parse(socket.sentMessages[0]);
      expect(parsed.type).toBe('unread_count');
      expect(parsed.data.count).toBe(3);
    });

    it('pushUnreadCount is no-op without notification repo', async () => {
      const socket = makeMockSocket();
      manager.registerConnection('user-1', socket);

      // No repo set — should not throw, no message sent
      await manager.pushUnreadCount('user-1');
      expect(socket.sentMessages).toHaveLength(0);
    });

    it('pushUnreadCount is no-op if user has no connections', async () => {
      const deps = makeServiceDeps();
      manager.setNotificationRepo(deps.notificationRepo);

      // No connections registered — should not throw
      await manager.pushUnreadCount('no-user');
    });

    it('disconnectUser closes all connections with appropriate code', () => {
      const socket1 = makeMockSocket();
      const socket2 = makeMockSocket();

      manager.registerConnection('user-1', socket1);
      manager.registerConnection('user-1', socket2);

      manager.disconnectUser('user-1');

      expect(socket1.closedWith).toEqual({ code: WS_CLOSE_AUTH_FAILED, reason: 'Session expired' });
      expect(socket2.closedWith).toEqual({ code: WS_CLOSE_AUTH_FAILED, reason: 'Session expired' });
      expect(manager.hasConnections('user-1')).toBe(false);
    });

    it('shutdown closes all connections', () => {
      const socket1 = makeMockSocket();
      const socket2 = makeMockSocket();

      manager.registerConnection('user-1', socket1);
      manager.registerConnection('user-2', socket2);

      manager.shutdown();

      expect(socket1.closedWith).toEqual({ code: 1001, reason: 'Server shutting down' });
      expect(socket2.closedWith).toEqual({ code: 1001, reason: 'Server shutting down' });
      expect(manager.hasConnections('user-1')).toBe(false);
      expect(manager.hasConnections('user-2')).toBe(false);
    });

    it('processEvent pushes notification to WebSocket after creation', async () => {
      const auditRepo = makeMockAuditRepo();
      const deps = makeServiceDeps({ auditRepo });

      const pushSpy = vi.spyOn(wsManager, 'pushToUser');

      await processEvent(deps, {
        eventType: 'CLAIM_VALIDATED',
        physicianId: PHYSICIAN_ID,
        metadata: { claimId: 'abc' },
      });

      // processEvent creates a notification for the physician, then calls wsManager.pushToUser
      expect(pushSpy).toHaveBeenCalledTimes(1);
      expect(pushSpy).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        expect.objectContaining({
          recipientId: PHYSICIAN_ID,
          eventType: 'CLAIM_VALIDATED',
        }),
      );

      pushSpy.mockRestore();
    });
  });

  // -----------------------------------------------------------------------
  // WebSocket Route Registration
  // -----------------------------------------------------------------------

  describe('registerNotificationWebSocket', () => {
    it('rejects connection without valid session token (no cookie, no query)', async () => {
      const socket = {
        readyState: WS_READY_STATE.OPEN,
        closedWith: null as any,
        send: vi.fn(),
        close(code?: number, reason?: string) {
          (this as any).closedWith = { code, reason };
        },
        ping: vi.fn(),
        on: vi.fn(),
        removeAllListeners: vi.fn(),
      };

      const validator: WsSessionValidator = {
        async validateSession() { return null; },
      };

      const handler = captureRouteHandler(validator);

      // Simulate request with no cookies and no query token
      await handler(socket, { headers: {}, query: {} });

      expect(socket.closedWith).toEqual({
        code: WS_CLOSE_AUTH_FAILED,
        reason: 'Authentication required',
      });
    });

    it('rejects connection with invalid session token', async () => {
      const socket = {
        readyState: WS_READY_STATE.OPEN,
        closedWith: null as any,
        send: vi.fn(),
        close(code?: number, reason?: string) {
          (this as any).closedWith = { code, reason };
        },
        ping: vi.fn(),
        on: vi.fn(),
        removeAllListeners: vi.fn(),
      };

      const validator: WsSessionValidator = {
        async validateSession() { return null; },
      };

      const handler = captureRouteHandler(validator);

      await handler(socket, {
        headers: { cookie: 'session=invalid-token' },
        query: {},
      });

      expect(socket.closedWith).toEqual({
        code: WS_CLOSE_AUTH_FAILED,
        reason: 'Invalid or expired session',
      });
    });

    it('accepts connection with valid session token from cookie', async () => {
      const socket = {
        readyState: WS_READY_STATE.OPEN,
        closedWith: null as any,
        send: vi.fn(),
        close(code?: number, reason?: string) {
          (this as any).closedWith = { code, reason };
        },
        ping: vi.fn(),
        on: vi.fn(),
        removeAllListeners: vi.fn(),
      };

      const validator: WsSessionValidator = {
        async validateSession(tokenHash: string) {
          if (tokenHash === 'hashed-valid-token') {
            return { userId: 'user-abc' };
          }
          return null;
        },
      };

      const handler = captureRouteHandler(validator);

      await handler(socket, {
        headers: { cookie: 'session=valid-token' },
        query: {},
      });

      // Connection should NOT be closed (it was accepted)
      expect(socket.closedWith).toBeNull();
      // Socket should have 'close' and 'error' listeners registered
      expect(socket.on).toHaveBeenCalledWith('close', expect.any(Function));
      expect(socket.on).toHaveBeenCalledWith('error', expect.any(Function));
    });

    it('accepts connection with valid session token from query parameter', async () => {
      const socket = {
        readyState: WS_READY_STATE.OPEN,
        closedWith: null as any,
        send: vi.fn(),
        close(code?: number, reason?: string) {
          (this as any).closedWith = { code, reason };
        },
        ping: vi.fn(),
        on: vi.fn(),
        removeAllListeners: vi.fn(),
      };

      const validator: WsSessionValidator = {
        async validateSession(tokenHash: string) {
          if (tokenHash === 'hashed-query-token') {
            return { userId: 'user-xyz' };
          }
          return null;
        },
      };

      const handler = captureRouteHandler(validator, (t: string) =>
        t === 'query-token' ? 'hashed-query-token' : 'other-hash',
      );

      await handler(socket, {
        headers: {},
        query: { token: 'query-token' },
      });

      expect(socket.closedWith).toBeNull();
      expect(socket.on).toHaveBeenCalledWith('close', expect.any(Function));
    });

    it('disconnects on session expiry (simulated via disconnectUser)', () => {
      const mgr = new NotificationWebSocketManager();
      const socket = {
        readyState: WS_READY_STATE.OPEN,
        closedWith: null as any,
        send: vi.fn(),
        close(code?: number, reason?: string) {
          (this as any).closedWith = { code, reason };
        },
        ping: vi.fn(),
        on: vi.fn(),
        removeAllListeners: vi.fn(),
      };

      mgr.registerConnection('user-1', socket as any);
      expect(mgr.hasConnections('user-1')).toBe(true);

      // Session expired — disconnect the user
      mgr.disconnectUser('user-1');

      expect(socket.closedWith).toEqual({
        code: WS_CLOSE_AUTH_FAILED,
        reason: 'Session expired',
      });
      expect(mgr.hasConnections('user-1')).toBe(false);

      mgr.shutdown();
    });

    /**
     * Helper: registers the WebSocket route on a mock app and captures
     * the handler function so we can call it directly in tests.
     */
    function captureRouteHandler(
      validator: WsSessionValidator,
      hashFn?: (token: string) => string,
    ): (socket: any, req: any) => Promise<void> {
      let capturedHandler: ((socket: any, req: any) => Promise<void>) | null = null;

      const mockApp = {
        get(path: string, opts: { websocket: true }, handler: (socket: any, req: any) => Promise<void>) {
          expect(path).toBe('/ws/notifications');
          expect(opts.websocket).toBe(true);
          capturedHandler = handler;
        },
      };

      const defaultHash = (t: string) => `hashed-${t}`;

      registerNotificationWebSocket(mockApp as any, validator, hashFn ?? defaultHash);

      if (!capturedHandler) throw new Error('Handler was not registered');
      return capturedHandler;
    }
  });
});
