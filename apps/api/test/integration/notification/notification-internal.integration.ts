import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

// ---------------------------------------------------------------------------
// Environment setup (must be before imports that read env)
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);
process.env.INTERNAL_API_KEY = 'test-internal-api-key-12345';
process.env.POSTMARK_WEBHOOK_SECRET = 'test-postmark-webhook-secret';

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
import { randomBytes, createHash, createHmac } from 'node:crypto';
import {
  internalNotificationRoutes,
  postmarkWebhookRoutes,
  notificationWebSocketRoutes,
} from '../../../src/domains/notification/notification.routes.js';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { type SessionManagementDeps } from '../../../src/domains/iam/iam.service.js';
import {
  type InternalNotificationHandlerDeps,
  type PostmarkWebhookHandlerDeps,
} from '../../../src/domains/notification/notification.handlers.js';
import { type NotificationRepository } from '../../../src/domains/notification/notification.repository.js';
import { type NotificationServiceDeps } from '../../../src/domains/notification/notification.service.js';

// ---------------------------------------------------------------------------
// Token Helpers
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

function postmarkSign(body: string, secret: string): string {
  return createHmac('sha256', secret).update(body).digest('base64');
}

// ---------------------------------------------------------------------------
// Test Data
// ---------------------------------------------------------------------------

const VALID_API_KEY = 'test-internal-api-key-12345';
const USER1_ID = '11111111-0000-0000-0000-000000000001';
const USER1_SESSION_TOKEN = randomBytes(32).toString('hex');
const USER1_SESSION_TOKEN_HASH = hashToken(USER1_SESSION_TOKEN);
const USER1_SESSION_ID = '33333333-0000-0000-0000-000000000001';

const PHYSICIAN_ID = '44444444-0000-0000-0000-000000000001';
const WEBHOOK_SECRET = 'test-postmark-webhook-secret';

// ---------------------------------------------------------------------------
// Mock Stores
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

interface MockDeliveryLog {
  deliveryId: string;
  notificationId: string;
  recipientEmail: string;
  templateId: string;
  status: string;
  providerMessageId: string | null;
  sentAt: Date | null;
  deliveredAt: Date | null;
  bouncedAt: Date | null;
  bounceReason: string | null;
  retryCount: number;
  nextRetryAt: Date | null;
  createdAt: Date;
}

let notificationStore: MockNotification[];
let deliveryLogStore: MockDeliveryLog[];
let nextNotifId = 1;
let nextDeliveryId = 1;
let auditEntries: Array<Record<string, unknown>>;

function newNotifId() {
  return `aaaaaaaa-0000-0000-0000-${String(nextNotifId++).padStart(12, '0')}`;
}

function newDeliveryId() {
  return `dddddddd-0000-0000-0000-${String(nextDeliveryId++).padStart(12, '0')}`;
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
      results.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
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
    createDeliveryLog: vi.fn(async (data: any) => {
      const log: MockDeliveryLog = {
        deliveryId: newDeliveryId(),
        notificationId: data.notificationId,
        recipientEmail: data.recipientEmail ?? '',
        templateId: data.templateId ?? '',
        status: data.status ?? 'QUEUED',
        providerMessageId: null,
        sentAt: null,
        deliveredAt: null,
        bouncedAt: null,
        bounceReason: null,
        retryCount: 0,
        nextRetryAt: null,
        createdAt: new Date(),
      };
      deliveryLogStore.push(log);
      return log;
    }),
    updateDeliveryStatus: vi.fn(
      async (deliveryId: string, status: string, details?: any) => {
        const log = deliveryLogStore.find((l) => l.deliveryId === deliveryId);
        if (!log) return undefined;
        log.status = status;
        if (details?.providerMessageId) log.providerMessageId = details.providerMessageId;
        if (details?.sentAt) log.sentAt = details.sentAt;
        if (details?.deliveredAt) log.deliveredAt = details.deliveredAt;
        if (details?.bouncedAt) log.bouncedAt = details.bouncedAt;
        if (details?.bounceReason) log.bounceReason = details.bounceReason;
        return log;
      },
    ),
    findPendingRetries: vi.fn(async () => []),
    incrementRetry: vi.fn(async (deliveryId: string, nextRetryAt: Date) => {
      const log = deliveryLogStore.find((l) => l.deliveryId === deliveryId);
      if (!log) return undefined;
      log.retryCount += 1;
      log.nextRetryAt = nextRetryAt;
      return log;
    }),
    findDeliveryLogByProviderMessageId: vi.fn(async (providerMessageId: string) => {
      return deliveryLogStore.find(
        (l) => l.providerMessageId === providerMessageId,
      );
    }),
    listDeliveryLogByNotification: vi.fn(async () => []),
    findTemplateById: vi.fn(async () => undefined),
    listAllTemplates: vi.fn(async () => []),
    upsertTemplate: vi.fn(async () => ({}) as any),
    addToDigestQueue: vi.fn(async () => ({}) as any),
    findPendingDigestItems: vi.fn(async () => []),
    findAllPendingDigestItems: vi.fn(async () => new Map()),
    markDigestItemsSent: vi.fn(async () => 0),
    findPreferencesByProvider: vi.fn(async () => []),
    findPreference: vi.fn(async () => undefined),
    upsertPreference: vi.fn(async () => ({}) as any),
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

function createMockDelegateLinkageRepo() {
  return {
    listDelegatesForPhysician: vi.fn(async () => []),
  };
}

// ---------------------------------------------------------------------------
// Mock Session Repo (for auth plugin and WebSocket validation)
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
// Test App Builders
// ---------------------------------------------------------------------------

let internalApp: FastifyInstance;
let webhookApp: FastifyInstance;
let wsApp: FastifyInstance;
let mockNotifRepo: ReturnType<typeof createMockNotificationRepo>;
let mockAuditRepo: ReturnType<typeof createMockAuditRepo>;
let mockDelegateLinkageRepo: ReturnType<typeof createMockDelegateLinkageRepo>;

async function buildInternalApp(): Promise<FastifyInstance> {
  mockNotifRepo = createMockNotificationRepo();
  mockAuditRepo = createMockAuditRepo();
  mockDelegateLinkageRepo = createMockDelegateLinkageRepo();

  const serviceDeps: NotificationServiceDeps = {
    notificationRepo: mockNotifRepo,
    auditRepo: mockAuditRepo,
    delegateLinkageRepo: mockDelegateLinkageRepo,
  };

  const internalDeps: InternalNotificationHandlerDeps = {
    serviceDeps,
  };

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

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

  await testApp.register(internalNotificationRoutes, { deps: internalDeps });

  await testApp.ready();
  return testApp;
}

async function buildWebhookApp(): Promise<FastifyInstance> {
  mockNotifRepo = createMockNotificationRepo();
  mockAuditRepo = createMockAuditRepo();
  mockDelegateLinkageRepo = createMockDelegateLinkageRepo();

  const serviceDeps: NotificationServiceDeps = {
    notificationRepo: mockNotifRepo,
    auditRepo: mockAuditRepo,
    delegateLinkageRepo: mockDelegateLinkageRepo,
  };

  const webhookDeps: PostmarkWebhookHandlerDeps = {
    serviceDeps,
    webhookSecret: WEBHOOK_SECRET,
  };

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  testApp.setErrorHandler((error, request, reply) => {
    if (error.statusCode && error.statusCode >= 400 && error.statusCode < 500) {
      return reply.code(error.statusCode).send({
        error: {
          code: (error as any).code ?? 'ERROR',
          message: error.message,
        },
      });
    }
    request.log.error(error);
    return reply.code(500).send({
      error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
    });
  });

  await testApp.register(postmarkWebhookRoutes, { deps: webhookDeps });

  await testApp.ready();
  return testApp;
}

async function buildWsApp(): Promise<FastifyInstance> {
  const mockSessionRepo = createMockSessionRepo();

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  // Register @fastify/websocket
  const websocketPlugin = await import('@fastify/websocket');
  await testApp.register(websocketPlugin.default ?? websocketPlugin);

  const sessionValidator = {
    validateSession: async (tokenHash: string) => {
      const result = await mockSessionRepo.findSessionByTokenHash(tokenHash);
      if (!result) return null;
      return { userId: result.session.userId };
    },
  };

  await testApp.register(notificationWebSocketRoutes, {
    sessionValidator,
    hashTokenFn: hashToken,
  });

  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Notification Internal Endpoints Integration Tests', () => {
  beforeAll(async () => {
    notificationStore = [];
    deliveryLogStore = [];
    auditEntries = [];
    nextNotifId = 1;
    nextDeliveryId = 1;
    internalApp = await buildInternalApp();
  });

  afterAll(async () => {
    await internalApp.close();
  });

  beforeEach(() => {
    notificationStore = [];
    deliveryLogStore = [];
    auditEntries = [];
    nextNotifId = 1;
    nextDeliveryId = 1;
    vi.clearAllMocks();
    // Re-wire the mock notification repo references
    mockNotifRepo = (internalApp as any)[Symbol.for('test-notif-repo')] ?? mockNotifRepo;
  });

  // =========================================================================
  // POST /api/v1/internal/notifications/emit
  // =========================================================================

  describe('POST /api/v1/internal/notifications/emit', () => {
    it('creates notification with valid API key', async () => {
      const res = await internalApp.inject({
        method: 'POST',
        url: '/api/v1/internal/notifications/emit',
        headers: {
          'x-internal-api-key': VALID_API_KEY,
          'content-type': 'application/json',
        },
        payload: JSON.stringify({
          event_type: 'CLAIM_VALIDATED',
          physician_id: PHYSICIAN_ID,
          metadata: { claim_id: 'test-claim-123' },
        }),
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.notification_ids).toBeDefined();
      expect(Array.isArray(body.data.notification_ids)).toBe(true);
      expect(body.data.notification_ids.length).toBeGreaterThan(0);
    });

    it('returns 401 without API key', async () => {
      const res = await internalApp.inject({
        method: 'POST',
        url: '/api/v1/internal/notifications/emit',
        headers: { 'content-type': 'application/json' },
        payload: JSON.stringify({
          event_type: 'CLAIM_VALIDATED',
          physician_id: PHYSICIAN_ID,
        }),
      });

      expect(res.statusCode).toBe(401);
      expect(JSON.parse(res.body).data).toBeUndefined();
    });

    it('returns 401 with invalid API key', async () => {
      const res = await internalApp.inject({
        method: 'POST',
        url: '/api/v1/internal/notifications/emit',
        headers: {
          'x-internal-api-key': 'wrong-key-wrong-key-wrong',
          'content-type': 'application/json',
        },
        payload: JSON.stringify({
          event_type: 'CLAIM_VALIDATED',
          physician_id: PHYSICIAN_ID,
        }),
      });

      expect(res.statusCode).toBe(401);
    });

    it('returns 400 for invalid event_type (empty string)', async () => {
      const res = await internalApp.inject({
        method: 'POST',
        url: '/api/v1/internal/notifications/emit',
        headers: {
          'x-internal-api-key': VALID_API_KEY,
          'content-type': 'application/json',
        },
        payload: JSON.stringify({
          event_type: '',
          physician_id: PHYSICIAN_ID,
        }),
      });

      expect(res.statusCode).toBe(400);
    });

    it('returns 400 for invalid physician_id (not UUID)', async () => {
      const res = await internalApp.inject({
        method: 'POST',
        url: '/api/v1/internal/notifications/emit',
        headers: {
          'x-internal-api-key': VALID_API_KEY,
          'content-type': 'application/json',
        },
        payload: JSON.stringify({
          event_type: 'CLAIM_VALIDATED',
          physician_id: 'not-a-uuid',
        }),
      });

      expect(res.statusCode).toBe(400);
    });

    it('returns 400 for missing required fields', async () => {
      const res = await internalApp.inject({
        method: 'POST',
        url: '/api/v1/internal/notifications/emit',
        headers: {
          'x-internal-api-key': VALID_API_KEY,
          'content-type': 'application/json',
        },
        payload: JSON.stringify({}),
      });

      expect(res.statusCode).toBe(400);
    });

    it('works without optional metadata', async () => {
      const res = await internalApp.inject({
        method: 'POST',
        url: '/api/v1/internal/notifications/emit',
        headers: {
          'x-internal-api-key': VALID_API_KEY,
          'content-type': 'application/json',
        },
        payload: JSON.stringify({
          event_type: 'CLAIM_VALIDATED',
          physician_id: PHYSICIAN_ID,
        }),
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.notification_ids.length).toBeGreaterThan(0);
    });
  });

  // =========================================================================
  // POST /api/v1/internal/notifications/emit-batch
  // =========================================================================

  describe('POST /api/v1/internal/notifications/emit-batch', () => {
    it('creates multiple notifications from batch', async () => {
      const res = await internalApp.inject({
        method: 'POST',
        url: '/api/v1/internal/notifications/emit-batch',
        headers: {
          'x-internal-api-key': VALID_API_KEY,
          'content-type': 'application/json',
        },
        payload: JSON.stringify({
          events: [
            {
              event_type: 'CLAIM_VALIDATED',
              physician_id: PHYSICIAN_ID,
              metadata: { claim_id: 'c1' },
            },
            {
              event_type: 'CLAIM_FLAGGED',
              physician_id: PHYSICIAN_ID,
              metadata: { claim_id: 'c2' },
            },
          ],
        }),
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.created_count).toBeGreaterThanOrEqual(2);
    });

    it('returns 401 without API key', async () => {
      const res = await internalApp.inject({
        method: 'POST',
        url: '/api/v1/internal/notifications/emit-batch',
        headers: { 'content-type': 'application/json' },
        payload: JSON.stringify({
          events: [
            {
              event_type: 'CLAIM_VALIDATED',
              physician_id: PHYSICIAN_ID,
            },
          ],
        }),
      });

      expect(res.statusCode).toBe(401);
    });

    it('returns 400 for empty events array', async () => {
      const res = await internalApp.inject({
        method: 'POST',
        url: '/api/v1/internal/notifications/emit-batch',
        headers: {
          'x-internal-api-key': VALID_API_KEY,
          'content-type': 'application/json',
        },
        payload: JSON.stringify({ events: [] }),
      });

      expect(res.statusCode).toBe(400);
    });

    it('returns 400 for invalid event in batch', async () => {
      const res = await internalApp.inject({
        method: 'POST',
        url: '/api/v1/internal/notifications/emit-batch',
        headers: {
          'x-internal-api-key': VALID_API_KEY,
          'content-type': 'application/json',
        },
        payload: JSON.stringify({
          events: [
            {
              event_type: 'CLAIM_VALIDATED',
              physician_id: 'not-a-uuid',
            },
          ],
        }),
      });

      expect(res.statusCode).toBe(400);
    });
  });
});

// ===========================================================================
// Postmark Webhook Tests
// ===========================================================================

describe('Postmark Webhook Integration Tests', () => {
  beforeAll(async () => {
    notificationStore = [];
    deliveryLogStore = [];
    auditEntries = [];
    nextNotifId = 1;
    nextDeliveryId = 1;
    webhookApp = await buildWebhookApp();
  });

  afterAll(async () => {
    await webhookApp.close();
  });

  beforeEach(() => {
    notificationStore = [];
    deliveryLogStore = [];
    auditEntries = [];
    nextNotifId = 1;
    nextDeliveryId = 1;
    vi.clearAllMocks();
  });

  describe('POST /api/v1/webhooks/postmark', () => {
    it('processes delivery confirmation', async () => {
      // Pre-create a delivery log with a known provider message ID
      const deliveryLog: MockDeliveryLog = {
        deliveryId: newDeliveryId(),
        notificationId: 'aaaaaaaa-0000-0000-0000-000000000001',
        recipientEmail: 'doc@example.com',
        templateId: 'CLAIM_VALIDATED',
        status: 'SENT',
        providerMessageId: 'pm-msg-001',
        sentAt: new Date(),
        deliveredAt: null,
        bouncedAt: null,
        bounceReason: null,
        retryCount: 0,
        nextRetryAt: null,
        createdAt: new Date(),
      };
      deliveryLogStore.push(deliveryLog);

      const payload = {
        RecordType: 'Delivery',
        MessageID: 'pm-msg-001',
        DeliveredAt: '2026-02-17T10:00:00Z',
      };

      const payloadStr = JSON.stringify(payload);
      const signature = postmarkSign(payloadStr, WEBHOOK_SECRET);

      const res = await webhookApp.inject({
        method: 'POST',
        url: '/api/v1/webhooks/postmark',
        headers: {
          'content-type': 'application/json',
          'x-postmark-signature': signature,
        },
        payload: payloadStr,
      });

      expect(res.statusCode).toBe(200);

      // Verify updateDeliveryStatus was called
      expect(mockNotifRepo.updateDeliveryStatus).toHaveBeenCalledWith(
        deliveryLog.deliveryId,
        'DELIVERED',
        expect.objectContaining({ deliveredAt: expect.any(Date) }),
      );
    });

    it('processes bounce event', async () => {
      // Pre-create a delivery log and notification for bounce handling
      const notif: MockNotification = {
        notificationId: newNotifId(),
        recipientId: USER1_ID,
        physicianContextId: null,
        eventType: 'CLAIM_VALIDATED',
        priority: 'LOW',
        title: 'Test',
        body: 'Test body',
        actionUrl: null,
        actionLabel: null,
        metadata: null,
        channelsDelivered: { in_app: true, email: true, push: false },
        readAt: null,
        dismissedAt: null,
        createdAt: new Date(),
      };
      notificationStore.push(notif);

      const deliveryLog: MockDeliveryLog = {
        deliveryId: newDeliveryId(),
        notificationId: notif.notificationId,
        recipientEmail: 'doc@example.com',
        templateId: 'CLAIM_VALIDATED',
        status: 'SENT',
        providerMessageId: 'pm-msg-bounce-001',
        sentAt: new Date(),
        deliveredAt: null,
        bouncedAt: null,
        bounceReason: null,
        retryCount: 0,
        nextRetryAt: null,
        createdAt: new Date(),
      };
      deliveryLogStore.push(deliveryLog);

      const payload = {
        RecordType: 'Bounce',
        MessageID: 'pm-msg-bounce-001',
        TypeCode: 1,
        Description: 'Hard bounce - address does not exist',
      };

      const payloadStr = JSON.stringify(payload);
      const signature = postmarkSign(payloadStr, WEBHOOK_SECRET);

      const res = await webhookApp.inject({
        method: 'POST',
        url: '/api/v1/webhooks/postmark',
        headers: {
          'content-type': 'application/json',
          'x-postmark-signature': signature,
        },
        payload: payloadStr,
      });

      expect(res.statusCode).toBe(200);

      // Verify hard bounce was processed - updateDeliveryStatus called with BOUNCED
      expect(mockNotifRepo.updateDeliveryStatus).toHaveBeenCalledWith(
        deliveryLog.deliveryId,
        'BOUNCED',
        expect.objectContaining({
          bouncedAt: expect.any(Date),
          bounceReason: 'Hard bounce - address does not exist',
        }),
      );
    });

    it('rejects invalid signature', async () => {
      const payload = {
        RecordType: 'Delivery',
        MessageID: 'pm-msg-002',
        DeliveredAt: '2026-02-17T10:00:00Z',
      };

      const payloadStr = JSON.stringify(payload);

      const res = await webhookApp.inject({
        method: 'POST',
        url: '/api/v1/webhooks/postmark',
        headers: {
          'content-type': 'application/json',
          'x-postmark-signature': 'invalid-signature',
        },
        payload: payloadStr,
      });

      expect(res.statusCode).toBe(401);
    });

    it('rejects request without signature header', async () => {
      const payload = {
        RecordType: 'Delivery',
        MessageID: 'pm-msg-003',
      };

      const res = await webhookApp.inject({
        method: 'POST',
        url: '/api/v1/webhooks/postmark',
        headers: { 'content-type': 'application/json' },
        payload: JSON.stringify(payload),
      });

      expect(res.statusCode).toBe(401);
    });

    it('returns 200 for unknown RecordType (acknowledge receipt)', async () => {
      const payload = {
        RecordType: 'SpamComplaint',
        MessageID: 'pm-msg-004',
      };

      const payloadStr = JSON.stringify(payload);
      const signature = postmarkSign(payloadStr, WEBHOOK_SECRET);

      const res = await webhookApp.inject({
        method: 'POST',
        url: '/api/v1/webhooks/postmark',
        headers: {
          'content-type': 'application/json',
          'x-postmark-signature': signature,
        },
        payload: payloadStr,
      });

      expect(res.statusCode).toBe(200);
    });

    it('handles soft bounce with retry scheduling', async () => {
      const notif: MockNotification = {
        notificationId: newNotifId(),
        recipientId: USER1_ID,
        physicianContextId: null,
        eventType: 'CLAIM_VALIDATED',
        priority: 'LOW',
        title: 'Test',
        body: 'Test body',
        actionUrl: null,
        actionLabel: null,
        metadata: null,
        channelsDelivered: { in_app: true, email: true, push: false },
        readAt: null,
        dismissedAt: null,
        createdAt: new Date(),
      };
      notificationStore.push(notif);

      const deliveryLog: MockDeliveryLog = {
        deliveryId: newDeliveryId(),
        notificationId: notif.notificationId,
        recipientEmail: 'doc@example.com',
        templateId: 'CLAIM_VALIDATED',
        status: 'SENT',
        providerMessageId: 'pm-msg-soft-bounce-001',
        sentAt: new Date(),
        deliveredAt: null,
        bouncedAt: null,
        bounceReason: null,
        retryCount: 0,
        nextRetryAt: null,
        createdAt: new Date(),
      };
      deliveryLogStore.push(deliveryLog);

      const payload = {
        RecordType: 'Bounce',
        MessageID: 'pm-msg-soft-bounce-001',
        TypeCode: 2,
        Description: 'Soft bounce - mailbox full',
      };

      const payloadStr = JSON.stringify(payload);
      const signature = postmarkSign(payloadStr, WEBHOOK_SECRET);

      const res = await webhookApp.inject({
        method: 'POST',
        url: '/api/v1/webhooks/postmark',
        headers: {
          'content-type': 'application/json',
          'x-postmark-signature': signature,
        },
        payload: payloadStr,
      });

      expect(res.statusCode).toBe(200);

      // Soft bounce should schedule a retry, not mark as BOUNCED
      expect(mockNotifRepo.incrementRetry).toHaveBeenCalledWith(
        deliveryLog.deliveryId,
        expect.any(Date),
      );
    });
  });
});

// ===========================================================================
// WebSocket Tests (using Fastify injectWS)
// ===========================================================================

describe('WebSocket /ws/notifications Integration Tests', () => {
  beforeAll(async () => {
    notificationStore = [];
    deliveryLogStore = [];
    auditEntries = [];
    nextNotifId = 1;
    nextDeliveryId = 1;
    wsApp = await buildWsApp();
  });

  afterAll(async () => {
    await wsApp.close();
  });

  beforeEach(() => {
    notificationStore = [];
    deliveryLogStore = [];
    auditEntries = [];
  });

  describe('WS /ws/notifications', () => {
    it('connects with valid session token via cookie', async () => {
      const ws = await wsApp.injectWS('/ws/notifications', {
        headers: { cookie: `session=${USER1_SESSION_TOKEN}` },
      });

      // If we reach here without being closed, the connection succeeded
      expect(ws).toBeDefined();

      // Wait briefly and check it remains open
      await new Promise((r) => setTimeout(r, 50));

      ws.terminate();
    });

    it('connects with valid session token via query parameter', async () => {
      const ws = await wsApp.injectWS(
        `/ws/notifications?token=${USER1_SESSION_TOKEN}`,
      );

      expect(ws).toBeDefined();
      await new Promise((r) => setTimeout(r, 50));

      ws.terminate();
    });

    it('rejects connection without session token', async () => {
      const ws = await wsApp.injectWS('/ws/notifications');

      const closeCode = await new Promise<number>((resolve) => {
        const timeout = setTimeout(() => {
          ws.terminate();
          resolve(-1);
        }, 3000);

        ws.on('close', (code: number) => {
          clearTimeout(timeout);
          resolve(code);
        });
      });

      expect(closeCode).toBe(4001);
    });

    it('rejects connection with invalid session token', async () => {
      const invalidToken = randomBytes(32).toString('hex');
      const ws = await wsApp.injectWS(
        `/ws/notifications?token=${invalidToken}`,
      );

      const closeCode = await new Promise<number>((resolve) => {
        const timeout = setTimeout(() => {
          ws.terminate();
          resolve(-1);
        }, 3000);

        ws.on('close', (code: number) => {
          clearTimeout(timeout);
          resolve(code);
        });
      });

      expect(closeCode).toBe(4001);
    });
  });
});
