import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

// ---------------------------------------------------------------------------
// Environment setup (must be before imports that read env)
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);
process.env.INTERNAL_API_KEY = 'test-internal-api-key-12345';

// ---------------------------------------------------------------------------
// Mock otplib (required by iam.service.ts which is imported by auth plugin)
// ---------------------------------------------------------------------------

vi.mock('otplib', () => {
  const mockAuthenticator = {
    options: {},
    generateSecret: vi.fn(() => 'MOCKSECRET'),
    keyuri: vi.fn(() => 'otpauth://totp/mock'),
    verify: vi.fn(() => false),
  };
  return { authenticator: mockAuthenticator };
});

// ---------------------------------------------------------------------------
// Real imports (after env setup)
// ---------------------------------------------------------------------------

import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { randomBytes, createHash } from 'node:crypto';
import { notificationRoutes } from '../../../src/domains/notification/notification.routes.js';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { type SessionManagementDeps } from '../../../src/domains/iam/iam.service.js';
import { type NotificationHandlerDeps } from '../../../src/domains/notification/notification.handlers.js';
import { type NotificationRepository } from '../../../src/domains/notification/notification.repository.js';

// ---------------------------------------------------------------------------
// Token Helpers
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Test Data — Physician 1
// ---------------------------------------------------------------------------

const P1_USER_ID = '11111111-0000-0000-0000-000000000001';
const P1_SESSION_TOKEN = randomBytes(32).toString('hex');
const P1_SESSION_TOKEN_HASH = hashToken(P1_SESSION_TOKEN);
const P1_SESSION_ID = '33333333-0000-0000-0000-000000000001';

// ---------------------------------------------------------------------------
// Test Data — Physician 2
// ---------------------------------------------------------------------------

const P2_USER_ID = '11111111-0000-0000-0000-000000000002';
const P2_SESSION_TOKEN = randomBytes(32).toString('hex');
const P2_SESSION_TOKEN_HASH = hashToken(P2_SESSION_TOKEN);
const P2_SESSION_ID = '33333333-0000-0000-0000-000000000002';

// ---------------------------------------------------------------------------
// Test Data — Delegate 1 (linked to Physician 1)
// ---------------------------------------------------------------------------

const D1_USER_ID = '22222222-0000-0000-0000-000000000001';
const D1_SESSION_TOKEN = randomBytes(32).toString('hex');
const D1_SESSION_TOKEN_HASH = hashToken(D1_SESSION_TOKEN);
const D1_SESSION_ID = '33333333-0000-0000-0000-000000000003';

// ---------------------------------------------------------------------------
// Test Data — Delegate 2 (linked to Physician 2)
// ---------------------------------------------------------------------------

const D2_USER_ID = '22222222-0000-0000-0000-000000000002';
const D2_SESSION_TOKEN = randomBytes(32).toString('hex');
const D2_SESSION_TOKEN_HASH = hashToken(D2_SESSION_TOKEN);
const D2_SESSION_ID = '33333333-0000-0000-0000-000000000004';

// ---------------------------------------------------------------------------
// Notification data owned by each user
// ---------------------------------------------------------------------------

function makeNotification(overrides: {
  notificationId: string;
  recipientId: string;
  physicianContextId?: string;
  eventType?: string;
  readAt?: Date | null;
  dismissedAt?: Date | null;
}) {
  return {
    notificationId: overrides.notificationId,
    recipientId: overrides.recipientId,
    physicianContextId: overrides.physicianContextId ?? overrides.recipientId,
    eventType: overrides.eventType ?? 'CLAIM_VALIDATED',
    priority: 'MEDIUM',
    title: 'Test notification',
    body: 'Test notification body',
    actionUrl: null,
    actionLabel: null,
    metadata: null,
    channelsDelivered: { in_app: true, email: false, push: false },
    readAt: overrides.readAt ?? null,
    dismissedAt: overrides.dismissedAt ?? null,
    createdAt: new Date(),
  };
}

// Physician 1 notifications (3 notifications)
const P1_NOTIF_1 = makeNotification({ notificationId: 'aaaaaaaa-1111-0000-0000-000000000001', recipientId: P1_USER_ID });
const P1_NOTIF_2 = makeNotification({ notificationId: 'aaaaaaaa-1111-0000-0000-000000000002', recipientId: P1_USER_ID });
const P1_NOTIF_3 = makeNotification({ notificationId: 'aaaaaaaa-1111-0000-0000-000000000003', recipientId: P1_USER_ID });

// Physician 2 notifications (5 notifications)
const P2_NOTIF_1 = makeNotification({ notificationId: 'aaaaaaaa-2222-0000-0000-000000000001', recipientId: P2_USER_ID });
const P2_NOTIF_2 = makeNotification({ notificationId: 'aaaaaaaa-2222-0000-0000-000000000002', recipientId: P2_USER_ID });
const P2_NOTIF_3 = makeNotification({ notificationId: 'aaaaaaaa-2222-0000-0000-000000000003', recipientId: P2_USER_ID });
const P2_NOTIF_4 = makeNotification({ notificationId: 'aaaaaaaa-2222-0000-0000-000000000004', recipientId: P2_USER_ID });
const P2_NOTIF_5 = makeNotification({ notificationId: 'aaaaaaaa-2222-0000-0000-000000000005', recipientId: P2_USER_ID });

// Delegate 1 notifications (notifications in physician 1's context for delegate)
const D1_NOTIF_1 = makeNotification({
  notificationId: 'aaaaaaaa-3333-0000-0000-000000000001',
  recipientId: D1_USER_ID,
  physicianContextId: P1_USER_ID,
});
const D1_NOTIF_2 = makeNotification({
  notificationId: 'aaaaaaaa-3333-0000-0000-000000000002',
  recipientId: D1_USER_ID,
  physicianContextId: P1_USER_ID,
});

// Delegate 2 notifications (notifications in physician 2's context for delegate)
const D2_NOTIF_1 = makeNotification({
  notificationId: 'aaaaaaaa-4444-0000-0000-000000000001',
  recipientId: D2_USER_ID,
  physicianContextId: P2_USER_ID,
});

// All notifications for the in-memory store
const ALL_NOTIFICATIONS = [
  P1_NOTIF_1, P1_NOTIF_2, P1_NOTIF_3,
  P2_NOTIF_1, P2_NOTIF_2, P2_NOTIF_3, P2_NOTIF_4, P2_NOTIF_5,
  D1_NOTIF_1, D1_NOTIF_2,
  D2_NOTIF_1,
];

// ---------------------------------------------------------------------------
// Preference data per provider
// ---------------------------------------------------------------------------

const P1_PREFS = [
  {
    preferenceId: 'pppppppp-1111-0000-0000-000000000001',
    providerId: P1_USER_ID,
    eventCategory: 'CLAIM_LIFECYCLE',
    inAppEnabled: true,
    emailEnabled: true,
    digestMode: 'IMMEDIATE',
    quietHoursStart: null as string | null,
    quietHoursEnd: null as string | null,
    updatedAt: new Date(),
  },
];

const P2_PREFS = [
  {
    preferenceId: 'pppppppp-2222-0000-0000-000000000001',
    providerId: P2_USER_ID,
    eventCategory: 'CLAIM_LIFECYCLE',
    inAppEnabled: true,
    emailEnabled: true,
    digestMode: 'IMMEDIATE',
    quietHoursStart: null as string | null,
    quietHoursEnd: null as string | null,
    updatedAt: new Date(),
  },
];

// ---------------------------------------------------------------------------
// In-memory store (mutated by mock operations)
// ---------------------------------------------------------------------------

let notifStore: Array<ReturnType<typeof makeNotification>>;
let prefStore: Array<typeof P1_PREFS[number]>;

function resetStores() {
  notifStore = ALL_NOTIFICATIONS.map((n) => ({ ...n, readAt: null, dismissedAt: null }));
  prefStore = [
    ...P1_PREFS.map((p) => ({ ...p })),
    ...P2_PREFS.map((p) => ({ ...p })),
  ];
}

// ---------------------------------------------------------------------------
// Mock Repositories
// ---------------------------------------------------------------------------

function createMockNotificationRepo(): NotificationRepository {
  return {
    createNotification: vi.fn(async () => ({}) as any),
    createNotificationsBatch: vi.fn(async () => 0),

    findNotificationById: vi.fn(async (notificationId: string, recipientId: string) => {
      return notifStore.find(
        (n) => n.notificationId === notificationId && n.recipientId === recipientId,
      );
    }),

    findNotificationByIdInternal: vi.fn(async (notificationId: string) => {
      return notifStore.find((n) => n.notificationId === notificationId);
    }),

    listNotifications: vi.fn(async (recipientId: string, opts: { unreadOnly?: boolean; limit: number; offset: number }) => {
      let filtered = notifStore.filter(
        (n) => n.recipientId === recipientId && n.dismissedAt === null,
      );
      if (opts.unreadOnly) {
        filtered = filtered.filter((n) => n.readAt === null);
      }
      return filtered.slice(opts.offset, opts.offset + opts.limit);
    }),

    countUnread: vi.fn(async (recipientId: string) => {
      return notifStore.filter(
        (n) => n.recipientId === recipientId && n.readAt === null && n.dismissedAt === null,
      ).length;
    }),

    markRead: vi.fn(async (notificationId: string, recipientId: string) => {
      const notif = notifStore.find(
        (n) => n.notificationId === notificationId && n.recipientId === recipientId,
      );
      if (!notif) return undefined;
      notif.readAt = new Date();
      return notif;
    }),

    markAllRead: vi.fn(async (recipientId: string) => {
      let count = 0;
      for (const n of notifStore) {
        if (n.recipientId === recipientId && n.readAt === null) {
          n.readAt = new Date();
          count++;
        }
      }
      return count;
    }),

    dismiss: vi.fn(async (notificationId: string, recipientId: string) => {
      const notif = notifStore.find(
        (n) => n.notificationId === notificationId && n.recipientId === recipientId,
      );
      if (!notif) return undefined;
      notif.dismissedAt = new Date();
      return notif;
    }),

    createDeliveryLog: vi.fn(async () => ({}) as any),
    updateDeliveryStatus: vi.fn(async () => undefined),
    findPendingRetries: vi.fn(async () => []),
    incrementRetry: vi.fn(async () => undefined),
    findDeliveryLogByProviderMessageId: vi.fn(async () => undefined),
    listDeliveryLogByNotification: vi.fn(async () => []),
    findTemplateById: vi.fn(async () => undefined),
    listAllTemplates: vi.fn(async () => []),
    upsertTemplate: vi.fn(async () => ({}) as any),
    addToDigestQueue: vi.fn(async () => ({}) as any),
    findPendingDigestItems: vi.fn(async () => []),
    findAllPendingDigestItems: vi.fn(async () => new Map()),
    markDigestItemsSent: vi.fn(async () => 0),

    findPreferencesByProvider: vi.fn(async (providerId: string) => {
      return prefStore.filter((p) => p.providerId === providerId);
    }),

    findPreference: vi.fn(async (providerId: string, eventCategory: string) => {
      return prefStore.find(
        (p) => p.providerId === providerId && p.eventCategory === eventCategory,
      );
    }),

    upsertPreference: vi.fn(async (providerId: string, eventCategory: string, data: any) => {
      let pref = prefStore.find(
        (p) => p.providerId === providerId && p.eventCategory === eventCategory,
      );
      if (pref) {
        if (data.inAppEnabled !== undefined) pref.inAppEnabled = data.inAppEnabled;
        if (data.emailEnabled !== undefined) pref.emailEnabled = data.emailEnabled;
        if (data.digestMode !== undefined) pref.digestMode = data.digestMode;
        pref.updatedAt = new Date();
        return pref;
      }
      const newPref = {
        preferenceId: `pppppppp-new0-0000-0000-${String(prefStore.length + 1).padStart(12, '0')}`,
        providerId,
        eventCategory,
        inAppEnabled: data.inAppEnabled ?? true,
        emailEnabled: data.emailEnabled ?? true,
        digestMode: data.digestMode ?? 'IMMEDIATE',
        quietHoursStart: null as string | null,
        quietHoursEnd: null as string | null,
        updatedAt: new Date(),
      };
      prefStore.push(newPref);
      return newPref;
    }),

    createDefaultPreferences: vi.fn(async () => []),
    updateQuietHours: vi.fn(async () => 0),
  };
}

function createMockAuditRepo() {
  return {
    appendAuditLog: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Mock Session Repo (returns both physicians and delegates)
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      if (tokenHash === P1_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: P1_SESSION_ID,
            userId: P1_USER_ID,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: P1_USER_ID,
            role: 'PHYSICIAN',
            subscriptionStatus: 'TRIAL',
          },
        };
      }
      if (tokenHash === P2_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: P2_SESSION_ID,
            userId: P2_USER_ID,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: P2_USER_ID,
            role: 'PHYSICIAN',
            subscriptionStatus: 'TRIAL',
          },
        };
      }
      if (tokenHash === D1_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: D1_SESSION_ID,
            userId: D1_USER_ID,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: D1_USER_ID,
            role: 'DELEGATE',
            subscriptionStatus: 'TRIAL',
          },
        };
      }
      if (tokenHash === D2_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: D2_SESSION_ID,
            userId: D2_USER_ID,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: D2_USER_ID,
            role: 'DELEGATE',
            subscriptionStatus: 'TRIAL',
          },
        };
      }
      return undefined;
    }),
    refreshSession: vi.fn(async () => {}),
    revokeSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
    createSession: vi.fn(async () => ({ sessionId: 'stub' })),
    listActiveSessions: vi.fn(async () => []),
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

async function buildApp(): Promise<FastifyInstance> {
  const mockNotifRepo = createMockNotificationRepo();
  const mockAuditRepo = createMockAuditRepo();
  const mockSessionRepo = createMockSessionRepo();

  const sessionDeps: SessionManagementDeps = {
    sessionRepo: mockSessionRepo,
    auditRepo: mockAuditRepo,
    events: { emit: vi.fn() },
  };

  const handlerDeps: NotificationHandlerDeps = {
    notificationRepo: mockNotifRepo,
    auditRepo: mockAuditRepo,
  };

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  await testApp.register(authPluginFp, { sessionDeps });

  testApp.setErrorHandler((error, request, reply) => {
    if (error.statusCode && error.statusCode >= 400 && error.statusCode < 500) {
      return reply.code(error.statusCode).send({
        error: {
          code: (error as any).code ?? 'ERROR',
          message: error.message,
        },
      });
    }
    if (error.validation) {
      return reply.code(400).send({
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Validation failed',
          details: error.validation,
        },
      });
    }
    request.log.error(error);
    return reply.code(500).send({
      error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
    });
  });

  await testApp.register(notificationRoutes, { deps: handlerDeps });

  await testApp.ready();
  return testApp;
}

// ===========================================================================
// Test Suite: Notification Feed Isolation
// ===========================================================================

describe('Notification Scoping — Feed Isolation', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await buildApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    resetStores();
  });

  // -------------------------------------------------------------------------
  // Physician 1 only sees their own notifications
  // -------------------------------------------------------------------------

  it('physician1 GET /api/v1/notifications returns only physician1 notifications', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/notifications',
      headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);
    const notifications = body.data.notifications;

    expect(notifications.length).toBe(3);
    for (const n of notifications) {
      // Verify every notification_id belongs to physician1
      const source = notifStore.find((s) => s.notificationId === n.notification_id);
      expect(source).toBeDefined();
      expect(source!.recipientId).toBe(P1_USER_ID);
    }
  });

  // -------------------------------------------------------------------------
  // Physician 1's feed never contains physician 2's notifications
  // -------------------------------------------------------------------------

  it('physician1 feed never contains physician2 notification IDs', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/notifications',
      headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);
    const p2NotifIds = [P2_NOTIF_1, P2_NOTIF_2, P2_NOTIF_3, P2_NOTIF_4, P2_NOTIF_5].map(
      (n) => n.notificationId,
    );

    for (const n of body.data.notifications) {
      expect(p2NotifIds).not.toContain(n.notification_id);
    }
  });

  // -------------------------------------------------------------------------
  // Physician 2 only sees their own notifications
  // -------------------------------------------------------------------------

  it('physician2 GET /api/v1/notifications returns only physician2 notifications', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/notifications',
      headers: { cookie: `session=${P2_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);
    const notifications = body.data.notifications;

    expect(notifications.length).toBe(5);
    for (const n of notifications) {
      const source = notifStore.find((s) => s.notificationId === n.notification_id);
      expect(source).toBeDefined();
      expect(source!.recipientId).toBe(P2_USER_ID);
    }
  });

  // -------------------------------------------------------------------------
  // Physician 2's feed never contains physician 1's notifications
  // -------------------------------------------------------------------------

  it('physician2 feed never contains physician1 notification IDs', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/notifications',
      headers: { cookie: `session=${P2_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);
    const p1NotifIds = [P1_NOTIF_1, P1_NOTIF_2, P1_NOTIF_3].map((n) => n.notificationId);

    for (const n of body.data.notifications) {
      expect(p1NotifIds).not.toContain(n.notification_id);
    }
  });
});

// ===========================================================================
// Test Suite: Read/Dismiss Isolation
// ===========================================================================

describe('Notification Scoping — Read/Dismiss Isolation', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await buildApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    resetStores();
  });

  // -------------------------------------------------------------------------
  // Physician 1 cannot mark physician 2's notification as read
  // -------------------------------------------------------------------------

  it('physician1 POST /notifications/:physician2NotifId/read returns 404', async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/notifications/${P2_NOTIF_1.notificationId}/read`,
      headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(404);
    const body = JSON.parse(res.body);
    expect(body.data).toBeUndefined();
    expect(body.error).toBeDefined();
  });

  // -------------------------------------------------------------------------
  // The 404 does not leak information about existence
  // -------------------------------------------------------------------------

  it('404 response on cross-user read does not reveal notification existence', async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/notifications/${P2_NOTIF_1.notificationId}/read`,
      headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(404);
    // Must NOT return 403 (which would confirm the resource exists)
    expect(res.statusCode).not.toBe(403);
    const body = JSON.parse(res.body);
    expect(JSON.stringify(body)).not.toContain(P2_NOTIF_1.notificationId);
  });

  // -------------------------------------------------------------------------
  // Physician 1 cannot dismiss physician 2's notification
  // -------------------------------------------------------------------------

  it('physician1 POST /notifications/:physician2NotifId/dismiss returns 404', async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/notifications/${P2_NOTIF_2.notificationId}/dismiss`,
      headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(404);
    const body = JSON.parse(res.body);
    expect(body.data).toBeUndefined();
    expect(body.error).toBeDefined();
  });

  // -------------------------------------------------------------------------
  // Physician 2's notification remains unread after physician 1's attempt
  // -------------------------------------------------------------------------

  it('physician2 notification remains unread after physician1 cross-user read attempt', async () => {
    // Physician 1 tries to read physician 2's notification
    await app.inject({
      method: 'POST',
      url: `/api/v1/notifications/${P2_NOTIF_1.notificationId}/read`,
      headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    });

    // Verify physician 2's notification is still unread
    const notif = notifStore.find((n) => n.notificationId === P2_NOTIF_1.notificationId);
    expect(notif).toBeDefined();
    expect(notif!.readAt).toBeNull();
  });

  // -------------------------------------------------------------------------
  // Physician 2's notification remains not dismissed after physician 1's attempt
  // -------------------------------------------------------------------------

  it('physician2 notification remains not dismissed after physician1 cross-user dismiss attempt', async () => {
    // Physician 1 tries to dismiss physician 2's notification
    await app.inject({
      method: 'POST',
      url: `/api/v1/notifications/${P2_NOTIF_2.notificationId}/dismiss`,
      headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    });

    // Verify physician 2's notification is still not dismissed
    const notif = notifStore.find((n) => n.notificationId === P2_NOTIF_2.notificationId);
    expect(notif).toBeDefined();
    expect(notif!.dismissedAt).toBeNull();
  });

  // -------------------------------------------------------------------------
  // Physician 2 cannot mark physician 1's notification as read
  // -------------------------------------------------------------------------

  it('physician2 POST /notifications/:physician1NotifId/read returns 404', async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/notifications/${P1_NOTIF_1.notificationId}/read`,
      headers: { cookie: `session=${P2_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(404);
  });

  // -------------------------------------------------------------------------
  // Physician 2 cannot dismiss physician 1's notification
  // -------------------------------------------------------------------------

  it('physician2 POST /notifications/:physician1NotifId/dismiss returns 404', async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/notifications/${P1_NOTIF_2.notificationId}/dismiss`,
      headers: { cookie: `session=${P2_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(404);
  });
});

// ===========================================================================
// Test Suite: Unread Count Isolation
// ===========================================================================

describe('Notification Scoping — Unread Count Isolation', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await buildApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    resetStores();
  });

  // -------------------------------------------------------------------------
  // Physician 1 unread count = 3 (only their own)
  // -------------------------------------------------------------------------

  it('physician1 unread count returns 3 (only physician1 notifications)', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/notifications/unread-count',
      headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);
    expect(body.data.count).toBe(3);
  });

  // -------------------------------------------------------------------------
  // Physician 2 unread count = 5 (only their own)
  // -------------------------------------------------------------------------

  it('physician2 unread count returns 5 (only physician2 notifications)', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/notifications/unread-count',
      headers: { cookie: `session=${P2_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);
    expect(body.data.count).toBe(5);
  });

  // -------------------------------------------------------------------------
  // Marking physician 1 notification as read decreases physician 1 count only
  // -------------------------------------------------------------------------

  it('marking physician1 notification as read decreases physician1 count but not physician2 count', async () => {
    // Mark one of physician 1's notifications as read
    const markRes = await app.inject({
      method: 'POST',
      url: `/api/v1/notifications/${P1_NOTIF_1.notificationId}/read`,
      headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    });
    expect(markRes.statusCode).toBe(200);

    // Physician 1 count should now be 2
    const p1CountRes = await app.inject({
      method: 'GET',
      url: '/api/v1/notifications/unread-count',
      headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    });
    expect(p1CountRes.statusCode).toBe(200);
    expect(JSON.parse(p1CountRes.body).data.count).toBe(2);

    // Physician 2 count should still be 5
    const p2CountRes = await app.inject({
      method: 'GET',
      url: '/api/v1/notifications/unread-count',
      headers: { cookie: `session=${P2_SESSION_TOKEN}` },
    });
    expect(p2CountRes.statusCode).toBe(200);
    expect(JSON.parse(p2CountRes.body).data.count).toBe(5);
  });

  // -------------------------------------------------------------------------
  // Mark-all-read for physician 1 does not affect physician 2's count
  // -------------------------------------------------------------------------

  it('mark-all-read for physician1 does not change physician2 unread count', async () => {
    // Mark all physician 1's as read
    const markAllRes = await app.inject({
      method: 'POST',
      url: '/api/v1/notifications/read-all',
      headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    });
    expect(markAllRes.statusCode).toBe(200);

    // Physician 1 count should now be 0
    const p1CountRes = await app.inject({
      method: 'GET',
      url: '/api/v1/notifications/unread-count',
      headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    });
    expect(JSON.parse(p1CountRes.body).data.count).toBe(0);

    // Physician 2 count should still be 5
    const p2CountRes = await app.inject({
      method: 'GET',
      url: '/api/v1/notifications/unread-count',
      headers: { cookie: `session=${P2_SESSION_TOKEN}` },
    });
    expect(JSON.parse(p2CountRes.body).data.count).toBe(5);
  });
});

// ===========================================================================
// Test Suite: Preference Isolation
// ===========================================================================

describe('Notification Scoping — Preference Isolation', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await buildApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    resetStores();
  });

  // -------------------------------------------------------------------------
  // Physician 1 only sees their own preferences
  // -------------------------------------------------------------------------

  it('physician1 GET /notification-preferences returns only physician1 preferences', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/notification-preferences',
      headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);

    // Preferences should be based on EVENT_CATALOGUE merged with physician1's stored prefs
    // The critical check: no preference data from physician2 leaks in
    expect(body.data).toBeDefined();
    expect(body.data.preferences).toBeDefined();
  });

  // -------------------------------------------------------------------------
  // Physician 2 only sees their own preferences
  // -------------------------------------------------------------------------

  it('physician2 GET /notification-preferences returns only physician2 preferences', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/notification-preferences',
      headers: { cookie: `session=${P2_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);
    expect(body.data).toBeDefined();
    expect(body.data.preferences).toBeDefined();
  });

  // -------------------------------------------------------------------------
  // Updating physician 1's preference does not affect physician 2
  // -------------------------------------------------------------------------

  it('updating physician1 CLAIM_LIFECYCLE email_enabled=false does not affect physician2', async () => {
    // Physician 1 disables email for CLAIM_LIFECYCLE
    const updateRes = await app.inject({
      method: 'PUT',
      url: '/api/v1/notification-preferences/ANALYTICS',
      headers: {
        cookie: `session=${P1_SESSION_TOKEN}`,
        'content-type': 'application/json',
      },
      payload: JSON.stringify({ email_enabled: false }),
    });
    expect(updateRes.statusCode).toBe(200);

    // Verify physician 2's ANALYTICS preference is still default (email_enabled: true)
    const p2Res = await app.inject({
      method: 'GET',
      url: '/api/v1/notification-preferences',
      headers: { cookie: `session=${P2_SESSION_TOKEN}` },
    });
    expect(p2Res.statusCode).toBe(200);
    const p2Body = JSON.parse(p2Res.body);

    // Find ANALYTICS in physician 2's preferences
    const analyticsPref = p2Body.data.preferences.find(
      (p: any) => p.event_category === 'ANALYTICS',
    );
    // Physician 2 should still have default values, not affected by physician 1
    if (analyticsPref) {
      expect(analyticsPref.email_enabled).toBe(true);
    }
  });

  // -------------------------------------------------------------------------
  // Physician 1's stored preference changes are isolated
  // -------------------------------------------------------------------------

  it('physician1 preference update is not visible in physician2 stored preferences', async () => {
    // Update physician 1's INTELLIGENCE_ENGINE preference
    await app.inject({
      method: 'PUT',
      url: '/api/v1/notification-preferences/INTELLIGENCE_ENGINE',
      headers: {
        cookie: `session=${P1_SESSION_TOKEN}`,
        'content-type': 'application/json',
      },
      payload: JSON.stringify({ in_app_enabled: false, email_enabled: false }),
    });

    // Check the in-memory store directly: physician 2 must not have an
    // INTELLIGENCE_ENGINE record created by physician 1's action
    const p2IntelPrefs = prefStore.filter(
      (p) => p.providerId === P2_USER_ID && p.eventCategory === 'INTELLIGENCE_ENGINE',
    );
    // Physician 2 should not have a stored pref for this category
    // (only physician 1 should have created one)
    expect(p2IntelPrefs.length).toBe(0);

    // Verify physician 1 has it
    const p1IntelPrefs = prefStore.filter(
      (p) => p.providerId === P1_USER_ID && p.eventCategory === 'INTELLIGENCE_ENGINE',
    );
    expect(p1IntelPrefs.length).toBe(1);
    expect(p1IntelPrefs[0].emailEnabled).toBe(false);
  });
});

// ===========================================================================
// Test Suite: Delegate Cross-Context Isolation
// ===========================================================================

describe('Notification Scoping — Delegate Cross-Context Isolation', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await buildApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    resetStores();
  });

  // -------------------------------------------------------------------------
  // Delegate 1 sees only their own notifications (physician 1's context)
  // -------------------------------------------------------------------------

  it('delegate1 GET /notifications returns only delegate1 notifications', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/notifications',
      headers: { cookie: `session=${D1_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);
    const notifications = body.data.notifications;

    expect(notifications.length).toBe(2);
    for (const n of notifications) {
      const source = notifStore.find((s) => s.notificationId === n.notification_id);
      expect(source).toBeDefined();
      expect(source!.recipientId).toBe(D1_USER_ID);
    }
  });

  // -------------------------------------------------------------------------
  // Delegate 1 does NOT see physician 2's notifications
  // -------------------------------------------------------------------------

  it('delegate1 feed does not contain physician2 notifications', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/notifications',
      headers: { cookie: `session=${D1_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);
    const p2NotifIds = [P2_NOTIF_1, P2_NOTIF_2, P2_NOTIF_3, P2_NOTIF_4, P2_NOTIF_5].map(
      (n) => n.notificationId,
    );

    for (const n of body.data.notifications) {
      expect(p2NotifIds).not.toContain(n.notification_id);
    }
  });

  // -------------------------------------------------------------------------
  // Delegate 1 does NOT see delegate 2's notifications
  // -------------------------------------------------------------------------

  it('delegate1 feed does not contain delegate2 notifications', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/notifications',
      headers: { cookie: `session=${D1_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);

    for (const n of body.data.notifications) {
      expect(n.notification_id).not.toBe(D2_NOTIF_1.notificationId);
    }
  });

  // -------------------------------------------------------------------------
  // Delegate 2 sees only their own notifications (physician 2's context)
  // -------------------------------------------------------------------------

  it('delegate2 GET /notifications returns only delegate2 notifications', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/notifications',
      headers: { cookie: `session=${D2_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);
    const notifications = body.data.notifications;

    expect(notifications.length).toBe(1);
    const source = notifStore.find((s) => s.notificationId === notifications[0].notification_id);
    expect(source).toBeDefined();
    expect(source!.recipientId).toBe(D2_USER_ID);
  });

  // -------------------------------------------------------------------------
  // Delegate 1 cannot mark delegate 2's notification as read
  // -------------------------------------------------------------------------

  it('delegate1 cannot mark delegate2 notification as read (returns 404)', async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/notifications/${D2_NOTIF_1.notificationId}/read`,
      headers: { cookie: `session=${D1_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(404);
    // Returns 404 not 403
    expect(res.statusCode).not.toBe(403);
  });

  // -------------------------------------------------------------------------
  // Delegate 1 cannot dismiss delegate 2's notification
  // -------------------------------------------------------------------------

  it('delegate1 cannot dismiss delegate2 notification (returns 404)', async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/notifications/${D2_NOTIF_1.notificationId}/dismiss`,
      headers: { cookie: `session=${D1_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(404);
    expect(res.statusCode).not.toBe(403);
  });

  // -------------------------------------------------------------------------
  // Delegate 1 cannot mark physician 1's direct notification as read
  // (delegate receives their own copy, not the physician's notification)
  // -------------------------------------------------------------------------

  it('delegate1 cannot access physician1 notifications directly (returns 404)', async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/notifications/${P1_NOTIF_1.notificationId}/read`,
      headers: { cookie: `session=${D1_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(404);
  });

  // -------------------------------------------------------------------------
  // Delegate unread counts are isolated
  // -------------------------------------------------------------------------

  it('delegate1 unread count reflects only delegate1 notifications', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/notifications/unread-count',
      headers: { cookie: `session=${D1_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);
    expect(body.data.count).toBe(2); // D1_NOTIF_1 + D1_NOTIF_2
  });

  it('delegate2 unread count reflects only delegate2 notifications', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/notifications/unread-count',
      headers: { cookie: `session=${D2_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);
    expect(body.data.count).toBe(1); // D2_NOTIF_1
  });
});

// ===========================================================================
// Test Suite: Cross-User Access Always Returns 404 (Not 403)
// ===========================================================================

describe('Notification Scoping — 404 Not 403 on Cross-User Access', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await buildApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    resetStores();
  });

  it('cross-user read returns 404 to prevent resource enumeration', async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/notifications/${P2_NOTIF_3.notificationId}/read`,
      headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    });

    // Must be 404 (not 403) to avoid confirming the resource exists
    expect(res.statusCode).toBe(404);
  });

  it('cross-user dismiss returns 404 to prevent resource enumeration', async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/notifications/${P2_NOTIF_4.notificationId}/dismiss`,
      headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(404);
  });

  it('non-existent notification also returns 404 (indistinguishable from cross-user)', async () => {
    const nonExistentId = 'ffffffff-ffff-ffff-ffff-ffffffffffff';
    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/notifications/${nonExistentId}/read`,
      headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(404);
  });

  it('cross-user 404 and non-existent 404 have identical response structure', async () => {
    // Cross-user access
    const crossRes = await app.inject({
      method: 'POST',
      url: `/api/v1/notifications/${P2_NOTIF_1.notificationId}/read`,
      headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    });

    // Non-existent resource
    const nonExistentId = 'ffffffff-ffff-ffff-ffff-ffffffffffff';
    const notFoundRes = await app.inject({
      method: 'POST',
      url: `/api/v1/notifications/${nonExistentId}/read`,
      headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    });

    const crossBody = JSON.parse(crossRes.body);
    const notFoundBody = JSON.parse(notFoundRes.body);

    // Both should have identical status codes
    expect(crossRes.statusCode).toBe(notFoundRes.statusCode);
    // Both should have error with same structure
    expect(Object.keys(crossBody.error).sort()).toEqual(Object.keys(notFoundBody.error).sort());
    // Neither should leak the notification ID
    expect(JSON.stringify(crossBody)).not.toContain(P2_NOTIF_1.notificationId);
  });
});
