import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

// ---------------------------------------------------------------------------
// Environment setup (must be before imports that read env)
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);

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
// Test Data
// ---------------------------------------------------------------------------

const USER1_ID = '11111111-0000-0000-0000-000000000001';
const USER2_ID = '22222222-0000-0000-0000-000000000002';

const USER1_SESSION_TOKEN = randomBytes(32).toString('hex');
const USER1_SESSION_TOKEN_HASH = hashToken(USER1_SESSION_TOKEN);
const USER1_SESSION_ID = '33333333-0000-0000-0000-000000000001';

const USER2_SESSION_TOKEN = randomBytes(32).toString('hex');
const USER2_SESSION_TOKEN_HASH = hashToken(USER2_SESSION_TOKEN);
const USER2_SESSION_ID = '33333333-0000-0000-0000-000000000002';

// ---------------------------------------------------------------------------
// Mock Notification Store
// ---------------------------------------------------------------------------

interface MockNotification {
  notificationId: string;
  recipientId: string;
  physicianContextId: string | null;
  eventType: string;
  priority: string;
  title: string;
  body: string;
  actionUrl: string | null;
  actionLabel: string | null;
  metadata: Record<string, unknown> | null;
  channelsDelivered: { in_app: boolean; email: boolean; push: boolean };
  readAt: Date | null;
  dismissedAt: Date | null;
  createdAt: Date;
}

let notificationStore: MockNotification[];
let nextNotifId = 1;
let auditEntries: Array<Record<string, unknown>>;

function newNotifId() {
  return `aaaaaaaa-0000-0000-0000-${String(nextNotifId++).padStart(12, '0')}`;
}

function createMockNotification(
  recipientId: string,
  overrides: Partial<MockNotification> = {},
): MockNotification {
  const notif: MockNotification = {
    notificationId: newNotifId(),
    recipientId,
    physicianContextId: null,
    eventType: 'CLAIM_VALIDATED',
    priority: 'LOW',
    title: 'Test notification',
    body: 'Test body',
    actionUrl: null,
    actionLabel: null,
    metadata: null,
    channelsDelivered: { in_app: true, email: false, push: false },
    readAt: null,
    dismissedAt: null,
    createdAt: new Date(),
    ...overrides,
  };
  notificationStore.push(notif);
  return notif;
}

// ---------------------------------------------------------------------------
// Mock Repositories
// ---------------------------------------------------------------------------

function createMockNotificationRepo(): NotificationRepository {
  return {
    createNotification: vi.fn(async (data: any) => {
      const notif: MockNotification = {
        notificationId: newNotifId(),
        recipientId: data.recipientId,
        physicianContextId: data.physicianContextId ?? null,
        eventType: data.eventType,
        priority: data.priority,
        title: data.title,
        body: data.body,
        actionUrl: data.actionUrl ?? null,
        actionLabel: data.actionLabel ?? null,
        metadata: data.metadata ?? null,
        channelsDelivered: data.channelsDelivered,
        readAt: null,
        dismissedAt: null,
        createdAt: new Date(),
      };
      notificationStore.push(notif);
      return notif;
    }),
    createNotificationsBatch: vi.fn(async () => 0),
    findNotificationById: vi.fn(async (notifId: string, recipientId: string) => {
      return notificationStore.find(
        (n) => n.notificationId === notifId && n.recipientId === recipientId,
      );
    }),
    findNotificationByIdInternal: vi.fn(async (notifId: string) => {
      return notificationStore.find((n) => n.notificationId === notifId);
    }),
    listNotifications: vi.fn(async (recipientId: string, opts: any) => {
      let results = notificationStore.filter(
        (n) => n.recipientId === recipientId && n.dismissedAt === null,
      );
      if (opts.unreadOnly) {
        results = results.filter((n) => n.readAt === null);
      }
      results.sort(
        (a, b) => b.createdAt.getTime() - a.createdAt.getTime(),
      );
      return results.slice(opts.offset, opts.offset + opts.limit);
    }),
    countUnread: vi.fn(async (recipientId: string) => {
      return notificationStore.filter(
        (n) =>
          n.recipientId === recipientId &&
          n.readAt === null &&
          n.dismissedAt === null,
      ).length;
    }),
    markRead: vi.fn(async (notifId: string, recipientId: string) => {
      const notif = notificationStore.find(
        (n) => n.notificationId === notifId && n.recipientId === recipientId,
      );
      if (!notif) return undefined;
      notif.readAt = new Date();
      return notif;
    }),
    markAllRead: vi.fn(async (recipientId: string) => {
      let count = 0;
      for (const n of notificationStore) {
        if (n.recipientId === recipientId && n.readAt === null) {
          n.readAt = new Date();
          count++;
        }
      }
      return count;
    }),
    dismiss: vi.fn(async (notifId: string, recipientId: string) => {
      const notif = notificationStore.find(
        (n) => n.notificationId === notifId && n.recipientId === recipientId,
      );
      if (!notif) return undefined;
      notif.dismissedAt = new Date();
      return notif;
    }),
    // Unused in feed tests — stubs
    createDeliveryLog: vi.fn(async () => ({} as any)),
    updateDeliveryStatus: vi.fn(async () => undefined),
    findPendingRetries: vi.fn(async () => []),
    incrementRetry: vi.fn(async () => undefined),
    findDeliveryLogByProviderMessageId: vi.fn(async () => undefined),
    listDeliveryLogByNotification: vi.fn(async () => []),
    findTemplateById: vi.fn(async () => undefined),
    listAllTemplates: vi.fn(async () => []),
    upsertTemplate: vi.fn(async () => ({} as any)),
    addToDigestQueue: vi.fn(async () => ({} as any)),
    findPendingDigestItems: vi.fn(async () => []),
    findAllPendingDigestItems: vi.fn(async () => new Map()),
    markDigestItemsSent: vi.fn(async () => 0),
    findPreferencesByProvider: vi.fn(async () => []),
    findPreference: vi.fn(async () => undefined),
    upsertPreference: vi.fn(async () => ({} as any)),
    createDefaultPreferences: vi.fn(async () => []),
    updateQuietHours: vi.fn(async () => 0),
  };
}

function createMockAuditRepo() {
  return {
    appendAuditLog: vi.fn(async (entry: Record<string, unknown>) => {
      auditEntries.push(entry);
    }),
  };
}

// ---------------------------------------------------------------------------
// Mock Session Repo (for auth plugin)
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      if (tokenHash === USER1_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: USER1_SESSION_ID,
            userId: USER1_ID,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: USER1_ID,
            role: 'PHYSICIAN',
            subscriptionStatus: 'TRIAL',
          },
        };
      }
      if (tokenHash === USER2_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: USER2_SESSION_ID,
            userId: USER2_ID,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: USER2_ID,
            role: 'PHYSICIAN',
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

let app: FastifyInstance;
let mockNotifRepo: ReturnType<typeof createMockNotificationRepo>;
let mockAuditRepo: ReturnType<typeof createMockAuditRepo>;

async function buildTestApp(): Promise<FastifyInstance> {
  mockNotifRepo = createMockNotificationRepo();
  mockAuditRepo = createMockAuditRepo();

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

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Notification Feed Integration Tests', () => {
  beforeAll(async () => {
    notificationStore = [];
    auditEntries = [];
    nextNotifId = 1;
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    notificationStore = [];
    auditEntries = [];
    nextNotifId = 1;
  });

  // =========================================================================
  // GET /api/v1/notifications
  // =========================================================================

  describe('GET /api/v1/notifications', () => {
    it('returns feed for authenticated user', async () => {
      createMockNotification(USER1_ID, { title: 'User1 Notif 1' });
      createMockNotification(USER1_ID, { title: 'User1 Notif 2' });

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/notifications',
        headers: { cookie: `session=${USER1_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.notifications).toHaveLength(2);
      expect(body.data.notifications[0].title).toBeDefined();
      expect(body.data.notifications[0].notification_id).toBeDefined();
    });

    it('returns 401 without session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/notifications',
      });

      expect(res.statusCode).toBe(401);
      expect(JSON.parse(res.body).data).toBeUndefined();
    });

    it('with unread_only=true filters to unread notifications', async () => {
      createMockNotification(USER1_ID, { title: 'Unread', readAt: null });
      createMockNotification(USER1_ID, {
        title: 'Read',
        readAt: new Date(),
      });

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/notifications?unread_only=true',
        headers: { cookie: `session=${USER1_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.notifications).toHaveLength(1);
      expect(body.data.notifications[0].title).toBe('Unread');
    });

    it('respects limit and offset', async () => {
      for (let i = 0; i < 5; i++) {
        createMockNotification(USER1_ID, {
          title: `Notif ${i}`,
          createdAt: new Date(Date.now() - i * 1000),
        });
      }

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/notifications?limit=2&offset=1',
        headers: { cookie: `session=${USER1_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.notifications).toHaveLength(2);
    });

    it('excludes dismissed notifications', async () => {
      createMockNotification(USER1_ID, { title: 'Active' });
      createMockNotification(USER1_ID, {
        title: 'Dismissed',
        dismissedAt: new Date(),
      });

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/notifications',
        headers: { cookie: `session=${USER1_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.notifications).toHaveLength(1);
      expect(body.data.notifications[0].title).toBe('Active');
    });

    it('does not return another user\'s notifications', async () => {
      createMockNotification(USER1_ID, { title: 'User1 Only' });
      createMockNotification(USER2_ID, { title: 'User2 Only' });

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/notifications',
        headers: { cookie: `session=${USER1_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.notifications).toHaveLength(1);
      expect(body.data.notifications[0].title).toBe('User1 Only');
    });

    it('returns 400 for invalid query params', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/notifications?limit=-1',
        headers: { cookie: `session=${USER1_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // GET /api/v1/notifications/unread-count
  // =========================================================================

  describe('GET /api/v1/notifications/unread-count', () => {
    it('returns correct unread count', async () => {
      createMockNotification(USER1_ID, { readAt: null });
      createMockNotification(USER1_ID, { readAt: null });
      createMockNotification(USER1_ID, { readAt: new Date() });

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/notifications/unread-count',
        headers: { cookie: `session=${USER1_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.count).toBe(2);
    });

    it('returns 401 without session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/notifications/unread-count',
      });

      expect(res.statusCode).toBe(401);
    });

    it('returns 0 when no unread notifications', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/notifications/unread-count',
        headers: { cookie: `session=${USER1_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.count).toBe(0);
    });
  });

  // =========================================================================
  // POST /api/v1/notifications/:id/read
  // =========================================================================

  describe('POST /api/v1/notifications/:id/read', () => {
    it('marks notification as read', async () => {
      const notif = createMockNotification(USER1_ID);

      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/notifications/${notif.notificationId}/read`,
        headers: { cookie: `session=${USER1_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.success).toBe(true);

      // Verify the notification was marked as read
      expect(notif.readAt).not.toBeNull();
    });

    it('returns 404 for other user\'s notification', async () => {
      const notif = createMockNotification(USER2_ID);

      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/notifications/${notif.notificationId}/read`,
        headers: { cookie: `session=${USER1_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(404);
    });

    it('returns 404 for non-existent notification', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/notifications/00000000-0000-0000-0000-000000000099/read',
        headers: { cookie: `session=${USER1_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(404);
    });

    it('returns 400 for invalid UUID', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/notifications/not-a-uuid/read',
        headers: { cookie: `session=${USER1_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without session', async () => {
      const notif = createMockNotification(USER1_ID);

      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/notifications/${notif.notificationId}/read`,
      });

      expect(res.statusCode).toBe(401);
    });

    it('creates an audit entry', async () => {
      const notif = createMockNotification(USER1_ID);

      await app.inject({
        method: 'POST',
        url: `/api/v1/notifications/${notif.notificationId}/read`,
        headers: { cookie: `session=${USER1_SESSION_TOKEN}` },
      });

      const auditEntry = auditEntries.find(
        (e) => e.action === 'notification.read' && e.resourceId === notif.notificationId,
      );
      expect(auditEntry).toBeDefined();
      expect(auditEntry!.userId).toBe(USER1_ID);
    });
  });

  // =========================================================================
  // POST /api/v1/notifications/read-all
  // =========================================================================

  describe('POST /api/v1/notifications/read-all', () => {
    it('marks all unread notifications as read', async () => {
      createMockNotification(USER1_ID, { readAt: null });
      createMockNotification(USER1_ID, { readAt: null });
      createMockNotification(USER1_ID, { readAt: new Date() });

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/notifications/read-all',
        headers: { cookie: `session=${USER1_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.success).toBe(true);
      expect(body.data.count).toBe(2);
    });

    it('returns count 0 when no unread notifications', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/notifications/read-all',
        headers: { cookie: `session=${USER1_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.count).toBe(0);
    });

    it('returns 401 without session', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/notifications/read-all',
      });

      expect(res.statusCode).toBe(401);
    });

    it('creates an audit entry with count', async () => {
      createMockNotification(USER1_ID, { readAt: null });
      createMockNotification(USER1_ID, { readAt: null });

      await app.inject({
        method: 'POST',
        url: '/api/v1/notifications/read-all',
        headers: { cookie: `session=${USER1_SESSION_TOKEN}` },
      });

      const auditEntry = auditEntries.find(
        (e) => e.action === 'notification.read_all',
      );
      expect(auditEntry).toBeDefined();
      expect(auditEntry!.userId).toBe(USER1_ID);
      expect((auditEntry!.detail as any)?.count).toBe(2);
    });
  });

  // =========================================================================
  // POST /api/v1/notifications/:id/dismiss
  // =========================================================================

  describe('POST /api/v1/notifications/:id/dismiss', () => {
    it('dismisses notification and hides from feed', async () => {
      const notif = createMockNotification(USER1_ID);

      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/notifications/${notif.notificationId}/dismiss`,
        headers: { cookie: `session=${USER1_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.success).toBe(true);

      // Verify notification is dismissed
      expect(notif.dismissedAt).not.toBeNull();

      // Verify it no longer appears in the feed
      const feedRes = await app.inject({
        method: 'GET',
        url: '/api/v1/notifications',
        headers: { cookie: `session=${USER1_SESSION_TOKEN}` },
      });
      const feedBody = JSON.parse(feedRes.body);
      expect(feedBody.data.notifications).toHaveLength(0);
    });

    it('returns 404 for other user\'s notification', async () => {
      const notif = createMockNotification(USER2_ID);

      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/notifications/${notif.notificationId}/dismiss`,
        headers: { cookie: `session=${USER1_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(404);
    });

    it('returns 400 for invalid UUID', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/notifications/not-a-uuid/dismiss',
        headers: { cookie: `session=${USER1_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without session', async () => {
      const notif = createMockNotification(USER1_ID);

      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/notifications/${notif.notificationId}/dismiss`,
      });

      expect(res.statusCode).toBe(401);
    });

    it('creates an audit entry', async () => {
      const notif = createMockNotification(USER1_ID);

      await app.inject({
        method: 'POST',
        url: `/api/v1/notifications/${notif.notificationId}/dismiss`,
        headers: { cookie: `session=${USER1_SESSION_TOKEN}` },
      });

      const auditEntry = auditEntries.find(
        (e) => e.action === 'notification.dismissed' && e.resourceId === notif.notificationId,
      );
      expect(auditEntry).toBeDefined();
      expect(auditEntry!.userId).toBe(USER1_ID);
    });
  });

  // =========================================================================
  // Delegate sees notifications from physician context
  // =========================================================================

  describe('Delegate notification access', () => {
    it('delegate sees notifications scoped to their own recipient ID', async () => {
      // Notifications are scoped by recipientId, not physician context.
      // When a delegate is a recipient, they see their own notifications.
      // This is handled at the processEvent level where delegates are added as recipients.
      // Here we just verify that the feed returns only the authenticated user's notifications.

      createMockNotification(USER1_ID, { title: 'For User1' });
      createMockNotification(USER2_ID, { title: 'For User2' });

      const res1 = await app.inject({
        method: 'GET',
        url: '/api/v1/notifications',
        headers: { cookie: `session=${USER1_SESSION_TOKEN}` },
      });

      const body1 = JSON.parse(res1.body);
      expect(body1.data.notifications).toHaveLength(1);
      expect(body1.data.notifications[0].title).toBe('For User1');

      const res2 = await app.inject({
        method: 'GET',
        url: '/api/v1/notifications',
        headers: { cookie: `session=${USER2_SESSION_TOKEN}` },
      });

      const body2 = JSON.parse(res2.body);
      expect(body2.data.notifications).toHaveLength(1);
      expect(body2.data.notifications[0].title).toBe('For User2');
    });
  });
});
