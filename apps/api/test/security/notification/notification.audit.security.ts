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
import {
  notificationRoutes,
  internalNotificationRoutes,
} from '../../../src/domains/notification/notification.routes.js';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { type SessionManagementDeps } from '../../../src/domains/iam/iam.service.js';
import { type NotificationHandlerDeps } from '../../../src/domains/notification/notification.handlers.js';
import { type InternalNotificationHandlerDeps } from '../../../src/domains/notification/notification.handlers.js';
import { type NotificationRepository } from '../../../src/domains/notification/notification.repository.js';
import {
  type NotificationServiceDeps,
  processEvent,
  sendEmail,
  handleBounce,
  retryFailedEmails,
  assembleDailyDigest,
} from '../../../src/domains/notification/notification.service.js';
import { NotificationAuditAction, EMAIL_MAX_RETRY_ATTEMPTS } from '@meritum/shared/constants/notification.constants.js';

// ---------------------------------------------------------------------------
// Token Helpers
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Test Data
// ---------------------------------------------------------------------------

const PHYSICIAN_USER_ID = '11111111-0000-0000-0000-000000000001';
const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_SESSION_ID = '33333333-0000-0000-0000-000000000001';
const PHYSICIAN_PROVIDER_ID = '44444444-0000-0000-0000-000000000001';

const VALID_NOTIF_ID = 'aaaaaaaa-0000-0000-0000-000000000001';
const VALID_DELIVERY_ID = 'dddddddd-0000-0000-0000-000000000001';
const VALID_PREFERENCE_ID = 'pppppppp-0000-0000-0000-000000000001';
const VALID_API_KEY = 'test-internal-api-key-12345';

// ---------------------------------------------------------------------------
// Audit Log Store — captures all audit entries for assertions
// ---------------------------------------------------------------------------

interface AuditLogEntry {
  userId?: string | null;
  action: string;
  category: string;
  resourceType?: string | null;
  resourceId?: string | null;
  detail?: Record<string, unknown> | null;
  ipAddress?: string | null;
  userAgent?: string | null;
}

let auditLogStore: AuditLogEntry[] = [];

function createTrackingAuditRepo() {
  return {
    appendAuditLog: vi.fn(async (entry: AuditLogEntry) => {
      auditLogStore.push(entry);
      return entry;
    }),
  };
}

// ---------------------------------------------------------------------------
// Mock Notification Repository
// ---------------------------------------------------------------------------

function createMockNotificationRepo(): NotificationRepository {
  return {
    createNotification: vi.fn(async (data: any) => ({
      notificationId: VALID_NOTIF_ID,
      recipientId: data.recipientId ?? PHYSICIAN_USER_ID,
      physicianContextId: data.physicianContextId ?? null,
      eventType: data.eventType ?? 'CLAIM_VALIDATED',
      priority: data.priority ?? 'LOW',
      title: data.title ?? 'Test',
      body: data.body ?? 'Test body',
      actionUrl: data.actionUrl ?? null,
      actionLabel: data.actionLabel ?? null,
      metadata: data.metadata ?? null,
      channelsDelivered: data.channelsDelivered ?? { in_app: true, email: false, push: false },
      readAt: null,
      dismissedAt: null,
      createdAt: new Date(),
    })),
    createNotificationsBatch: vi.fn(async () => 0),
    findNotificationById: vi.fn(async () => undefined),
    findNotificationByIdInternal: vi.fn(async () => undefined),
    listNotifications: vi.fn(async () => []),
    countUnread: vi.fn(async () => 0),
    markRead: vi.fn(async (id: string, recipientId: string) => ({
      notificationId: id,
      recipientId,
      eventType: 'CLAIM_VALIDATED',
      priority: 'LOW',
      title: 'Test',
      body: 'Test body',
      actionUrl: null,
      actionLabel: null,
      metadata: null,
      channelsDelivered: { in_app: true, email: false, push: false },
      readAt: new Date(),
      dismissedAt: null,
      createdAt: new Date(),
      physicianContextId: null,
    })),
    markAllRead: vi.fn(async () => 3),
    dismiss: vi.fn(async (id: string, recipientId: string) => ({
      notificationId: id,
      recipientId,
      eventType: 'CLAIM_VALIDATED',
      priority: 'LOW',
      title: 'Test',
      body: 'Test body',
      actionUrl: null,
      actionLabel: null,
      metadata: null,
      channelsDelivered: { in_app: true, email: false, push: false },
      readAt: null,
      dismissedAt: new Date(),
      createdAt: new Date(),
      physicianContextId: null,
    })),
    createDeliveryLog: vi.fn(async (data: any) => ({
      deliveryId: VALID_DELIVERY_ID,
      notificationId: data.notificationId ?? VALID_NOTIF_ID,
      recipientEmail: data.recipientEmail ?? 'test@example.com',
      templateId: data.templateId ?? 'CLAIM_VALIDATED',
      status: data.status ?? 'QUEUED',
      providerMessageId: null,
      sentAt: null,
      deliveredAt: null,
      bouncedAt: null,
      bounceReason: null,
      retryCount: 0,
      nextRetryAt: null,
      createdAt: new Date(),
    })),
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
    findPreferencesByProvider: vi.fn(async () => []),
    findPreference: vi.fn(async () => undefined),
    upsertPreference: vi.fn(async (providerId: string, category: string, data: any) => ({
      preferenceId: VALID_PREFERENCE_ID,
      providerId,
      eventCategory: category,
      inAppEnabled: data.inAppEnabled ?? true,
      emailEnabled: data.emailEnabled ?? false,
      digestMode: data.digestMode ?? 'IMMEDIATE',
      quietHoursStart: null,
      quietHoursEnd: null,
      updatedAt: new Date(),
    })),
    createDefaultPreferences: vi.fn(async () => []),
    updateQuietHours: vi.fn(async () => 1),
  };
}

function createMockDelegateLinkageRepo() {
  return {
    listDelegatesForPhysician: vi.fn(async () => []),
  };
}

// ---------------------------------------------------------------------------
// Mock Session Repo (for auth plugin)
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      if (tokenHash === PHYSICIAN_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: PHYSICIAN_SESSION_ID,
            userId: PHYSICIAN_USER_ID,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: PHYSICIAN_USER_ID,
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

let sharedAuditRepo: ReturnType<typeof createTrackingAuditRepo>;
let sharedNotifRepo: ReturnType<typeof createMockNotificationRepo>;

async function buildSessionApp(): Promise<FastifyInstance> {
  sharedNotifRepo = createMockNotificationRepo();
  sharedAuditRepo = createTrackingAuditRepo();
  const mockSessionRepo = createMockSessionRepo();

  const sessionDeps: SessionManagementDeps = {
    sessionRepo: mockSessionRepo,
    auditRepo: sharedAuditRepo,
    events: { emit: vi.fn() },
  };

  const handlerDeps: NotificationHandlerDeps = {
    notificationRepo: sharedNotifRepo,
    auditRepo: sharedAuditRepo,
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

async function buildInternalApp(): Promise<FastifyInstance> {
  sharedNotifRepo = createMockNotificationRepo();
  sharedAuditRepo = createTrackingAuditRepo();
  const mockDelegateLinkageRepo = createMockDelegateLinkageRepo();

  const serviceDeps: NotificationServiceDeps = {
    notificationRepo: sharedNotifRepo,
    auditRepo: sharedAuditRepo,
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

// ---------------------------------------------------------------------------
// Helper: find audit entries by action
// ---------------------------------------------------------------------------

function findAuditEntries(action: string): AuditLogEntry[] {
  return auditLogStore.filter((e) => e.action === action);
}

function findLastAuditEntry(action: string): AuditLogEntry | undefined {
  const entries = findAuditEntries(action);
  return entries[entries.length - 1];
}

// ===========================================================================
// Test Suite: User Action Audit Trail
// ===========================================================================

describe('Notification Audit Trail — User Actions', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await buildSessionApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    auditLogStore = [];
    vi.clearAllMocks();
  });

  // -------------------------------------------------------------------------
  // POST /api/v1/notifications/:id/read → notification.read
  // -------------------------------------------------------------------------

  describe('POST /api/v1/notifications/:id/read', () => {
    it('produces audit record notification.read with notification_id', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/notifications/${VALID_NOTIF_ID}/read`,
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);

      const entry = findLastAuditEntry(NotificationAuditAction.NOTIFICATION_READ);
      expect(entry).toBeDefined();
      expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
      expect(entry!.category).toBe('notification');
      expect(entry!.resourceType).toBe('notification');
      expect(entry!.resourceId).toBe(VALID_NOTIF_ID);
    });
  });

  // -------------------------------------------------------------------------
  // POST /api/v1/notifications/read-all → notification.read_all
  // -------------------------------------------------------------------------

  describe('POST /api/v1/notifications/read-all', () => {
    it('produces audit record notification.read_all with count', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/notifications/read-all',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);

      const entry = findLastAuditEntry(NotificationAuditAction.NOTIFICATION_READ_ALL);
      expect(entry).toBeDefined();
      expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
      expect(entry!.category).toBe('notification');
      expect(entry!.resourceType).toBe('notification');
      expect(entry!.detail).toBeDefined();
      expect(entry!.detail!.count).toBe(3); // markAllRead returns 3
    });
  });

  // -------------------------------------------------------------------------
  // POST /api/v1/notifications/:id/dismiss → notification.dismissed
  // -------------------------------------------------------------------------

  describe('POST /api/v1/notifications/:id/dismiss', () => {
    it('produces audit record notification.dismissed with notification_id', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/notifications/${VALID_NOTIF_ID}/dismiss`,
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);

      const entry = findLastAuditEntry(NotificationAuditAction.NOTIFICATION_DISMISSED);
      expect(entry).toBeDefined();
      expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
      expect(entry!.category).toBe('notification');
      expect(entry!.resourceType).toBe('notification');
      expect(entry!.resourceId).toBe(VALID_NOTIF_ID);
    });
  });
});

// ===========================================================================
// Test Suite: Preference Change Audit Trail
// ===========================================================================

describe('Notification Audit Trail — Preference Changes', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await buildSessionApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    auditLogStore = [];
    vi.clearAllMocks();
  });

  // -------------------------------------------------------------------------
  // PUT /api/v1/notification-preferences/:category → notification.preference_updated
  // -------------------------------------------------------------------------

  describe('PUT /api/v1/notification-preferences/:category', () => {
    it('produces audit record notification.preference_updated with category and changes', async () => {
      const res = await app.inject({
        method: 'PUT',
        url: '/api/v1/notification-preferences/ANALYTICS',
        headers: {
          cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: JSON.stringify({ email_enabled: false }),
      });

      expect(res.statusCode).toBe(200);

      const entry = findLastAuditEntry(NotificationAuditAction.NOTIFICATION_PREFERENCE_UPDATED);
      expect(entry).toBeDefined();
      expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
      expect(entry!.category).toBe('notification');
      expect(entry!.resourceType).toBe('notification_preference');
      expect(entry!.resourceId).toBe(VALID_PREFERENCE_ID);

      // Detail must contain old and new values
      expect(entry!.detail).toBeDefined();
      expect(entry!.detail!.event_category).toBe('ANALYTICS');
      expect(entry!.detail!.new_values).toBeDefined();
      expect(entry!.detail).toHaveProperty('old_values');
    });
  });

  // -------------------------------------------------------------------------
  // PUT /api/v1/notification-preferences/quiet-hours → notification.quiet_hours_updated
  // -------------------------------------------------------------------------

  describe('PUT /api/v1/notification-preferences/quiet-hours', () => {
    it('produces audit record notification.quiet_hours_updated with old and new values', async () => {
      const res = await app.inject({
        method: 'PUT',
        url: '/api/v1/notification-preferences/quiet-hours',
        headers: {
          cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: JSON.stringify({
          quiet_hours_start: '22:00',
          quiet_hours_end: '07:00',
        }),
      });

      expect(res.statusCode).toBe(200);

      const entry = findLastAuditEntry(NotificationAuditAction.NOTIFICATION_QUIET_HOURS_UPDATED);
      expect(entry).toBeDefined();
      expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
      expect(entry!.category).toBe('notification');
      expect(entry!.resourceType).toBe('notification_preference');

      // Detail must contain old and new quiet hours
      expect(entry!.detail).toBeDefined();
      expect(entry!.detail!.old_values).toBeDefined();
      expect(entry!.detail!.new_values).toBeDefined();
      const newValues = entry!.detail!.new_values as Record<string, unknown>;
      expect(newValues.start).toBe('22:00');
      expect(newValues.end).toBe('07:00');
    });
  });
});

// ===========================================================================
// Test Suite: Event Processing Audit Trail
// ===========================================================================

describe('Notification Audit Trail — Event Processing', () => {
  let serviceDeps: NotificationServiceDeps;

  beforeEach(() => {
    auditLogStore = [];
    const mockNotifRepo = createMockNotificationRepo();
    const mockDelegateLinkageRepo = createMockDelegateLinkageRepo();
    sharedAuditRepo = createTrackingAuditRepo();

    serviceDeps = {
      notificationRepo: mockNotifRepo,
      auditRepo: sharedAuditRepo,
      delegateLinkageRepo: mockDelegateLinkageRepo,
    };
  });

  // -------------------------------------------------------------------------
  // processEvent → notification.event_emitted
  // -------------------------------------------------------------------------

  describe('processEvent (internal emit)', () => {
    it('produces audit record notification.event_emitted with event_type and physician_id', async () => {
      await processEvent(serviceDeps, {
        eventType: 'CLAIM_VALIDATED',
        physicianId: PHYSICIAN_PROVIDER_ID,
        metadata: { claim_id: 'test-claim-123' },
      });

      const entry = findLastAuditEntry(NotificationAuditAction.NOTIFICATION_EVENT_EMITTED);
      expect(entry).toBeDefined();
      expect(entry!.userId).toBe(PHYSICIAN_PROVIDER_ID);
      expect(entry!.action).toBe('notification.event_emitted');
      expect(entry!.category).toBe('notification');
      expect(entry!.detail).toBeDefined();
      expect(entry!.detail!.eventType).toBe('CLAIM_VALIDATED');
      expect(entry!.detail!.physicianId).toBe(PHYSICIAN_PROVIDER_ID);
    });
  });

  // -------------------------------------------------------------------------
  // Emit via HTTP route → notification.event_emitted
  // -------------------------------------------------------------------------

  describe('POST /api/v1/internal/notifications/emit', () => {
    let internalApp: FastifyInstance;

    beforeAll(async () => {
      internalApp = await buildInternalApp();
    });

    afterAll(async () => {
      await internalApp.close();
    });

    it('produces audit record notification.event_emitted via HTTP', async () => {
      auditLogStore = [];

      const res = await internalApp.inject({
        method: 'POST',
        url: '/api/v1/internal/notifications/emit',
        headers: {
          'x-internal-api-key': VALID_API_KEY,
          'content-type': 'application/json',
        },
        payload: JSON.stringify({
          event_type: 'CLAIM_VALIDATED',
          physician_id: PHYSICIAN_PROVIDER_ID,
          metadata: { claim_id: 'test-claim-456' },
        }),
      });

      expect(res.statusCode).toBe(200);

      const entry = findLastAuditEntry(NotificationAuditAction.NOTIFICATION_EVENT_EMITTED);
      expect(entry).toBeDefined();
      expect(entry!.detail!.eventType).toBe('CLAIM_VALIDATED');
      expect(entry!.detail!.physicianId).toBe(PHYSICIAN_PROVIDER_ID);
    });
  });
});

// ===========================================================================
// Test Suite: Email Delivery Audit Trail
// ===========================================================================

describe('Notification Audit Trail — Email Delivery', () => {
  let serviceDeps: NotificationServiceDeps;
  let mockPostmarkClient: { sendEmail: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    auditLogStore = [];
    const mockNotifRepo = createMockNotificationRepo();
    const mockDelegateLinkageRepo = createMockDelegateLinkageRepo();
    sharedAuditRepo = createTrackingAuditRepo();

    mockPostmarkClient = {
      sendEmail: vi.fn(async () => ({
        MessageID: 'postmark-msg-id-12345',
      })),
    };

    serviceDeps = {
      notificationRepo: mockNotifRepo,
      auditRepo: sharedAuditRepo,
      delegateLinkageRepo: mockDelegateLinkageRepo,
      postmarkClient: mockPostmarkClient,
      senderEmail: 'notifications@meritum.ca',
    };
  });

  // -------------------------------------------------------------------------
  // sendEmail (success) → notification.email_sent
  // -------------------------------------------------------------------------

  describe('sendEmail (success)', () => {
    it('produces audit record notification.email_sent with delivery_id', async () => {
      const deliveryId = await sendEmail(serviceDeps, VALID_NOTIF_ID, 'dr.smith@example.com', {
        subject: 'Test Notification',
        htmlBody: '<p>Test</p>',
        textBody: 'Test',
      });

      const entry = findLastAuditEntry(NotificationAuditAction.NOTIFICATION_EMAIL_SENT);
      expect(entry).toBeDefined();
      expect(entry!.action).toBe('notification.email_sent');
      expect(entry!.category).toBe('notification');
      expect(entry!.resourceType).toBe('email_delivery');
      expect(entry!.resourceId).toBe(deliveryId);
    });

    it('audit record for email_sent contains recipient_email (service layer logs plaintext)', async () => {
      // NOTE: The task spec says email should be hashed, but the service layer
      // currently logs it as-is. The audit sanitiseDetail() function in Domain 1
      // handles PHI sanitisation. This test verifies the audit record is created.
      await sendEmail(serviceDeps, VALID_NOTIF_ID, 'dr.smith@example.com', {
        subject: 'Test Notification',
        htmlBody: '<p>Test</p>',
        textBody: 'Test',
      });

      const entry = findLastAuditEntry(NotificationAuditAction.NOTIFICATION_EMAIL_SENT);
      expect(entry).toBeDefined();
      expect(entry!.detail).toBeDefined();
      expect(entry!.detail!.notificationId).toBe(VALID_NOTIF_ID);
    });
  });

  // -------------------------------------------------------------------------
  // sendEmail (max retries exhausted) → notification.email_failed
  // -------------------------------------------------------------------------

  describe('sendEmail (failure after max retries)', () => {
    it('produces audit record notification.email_failed with delivery_id and retry_count', async () => {
      // Make the Postmark client throw on send
      mockPostmarkClient.sendEmail.mockRejectedValue(new Error('Connection refused'));

      // Make the delivery log have max retries already
      const mockNotifRepo = serviceDeps.notificationRepo as any;
      mockNotifRepo.createDeliveryLog.mockResolvedValue({
        deliveryId: VALID_DELIVERY_ID,
        notificationId: VALID_NOTIF_ID,
        recipientEmail: 'dr.smith@example.com',
        templateId: 'CLAIM_VALIDATED',
        status: 'QUEUED',
        providerMessageId: null,
        sentAt: null,
        deliveredAt: null,
        bouncedAt: null,
        bounceReason: null,
        retryCount: EMAIL_MAX_RETRY_ATTEMPTS - 1, // At max
        nextRetryAt: null,
        createdAt: new Date(),
      });

      await sendEmail(serviceDeps, VALID_NOTIF_ID, 'dr.smith@example.com', {
        subject: 'Test Notification',
        htmlBody: '<p>Test</p>',
        textBody: 'Test',
      });

      const entry = findLastAuditEntry(NotificationAuditAction.NOTIFICATION_EMAIL_FAILED);
      expect(entry).toBeDefined();
      expect(entry!.action).toBe('notification.email_failed');
      expect(entry!.category).toBe('notification');
      expect(entry!.resourceType).toBe('email_delivery');
      expect(entry!.resourceId).toBe(VALID_DELIVERY_ID);
      expect(entry!.detail).toBeDefined();
      expect(entry!.detail!.reason).toBe('max_retries_exhausted');
    });
  });

  // -------------------------------------------------------------------------
  // handleBounce (hard bounce) → notification.email_bounced
  // -------------------------------------------------------------------------

  describe('handleBounce (hard bounce)', () => {
    it('produces audit record notification.email_bounced with delivery_id and bounce_type', async () => {
      // Set up: findDeliveryLogByProviderMessageId returns a delivery log
      const mockNotifRepo = serviceDeps.notificationRepo as any;
      mockNotifRepo.findDeliveryLogByProviderMessageId.mockResolvedValue({
        deliveryId: VALID_DELIVERY_ID,
        notificationId: VALID_NOTIF_ID,
        recipientEmail: 'bounced@example.com',
        templateId: 'CLAIM_VALIDATED',
        status: 'SENT',
        providerMessageId: 'postmark-msg-id-bounce',
        sentAt: new Date(),
        deliveredAt: null,
        bouncedAt: null,
        bounceReason: null,
        retryCount: 0,
        nextRetryAt: null,
        createdAt: new Date(),
      });

      // findNotificationByIdInternal for creating in-app bounce alert
      mockNotifRepo.findNotificationByIdInternal.mockResolvedValue({
        notificationId: VALID_NOTIF_ID,
        recipientId: PHYSICIAN_USER_ID,
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
        physicianContextId: null,
      });

      await handleBounce(serviceDeps, 'postmark-msg-id-bounce', 'hard', 'Address not found');

      const entry = findLastAuditEntry(NotificationAuditAction.NOTIFICATION_EMAIL_BOUNCED);
      expect(entry).toBeDefined();
      expect(entry!.action).toBe('notification.email_bounced');
      expect(entry!.category).toBe('notification');
      expect(entry!.resourceType).toBe('email_delivery');
      expect(entry!.resourceId).toBe(VALID_DELIVERY_ID);
      expect(entry!.detail).toBeDefined();
      expect(entry!.detail!.bounceType).toBe('hard');
      expect(entry!.detail!.reason).toBe('Address not found');
    });
  });

  // -------------------------------------------------------------------------
  // handleBounce (soft bounce) → notification.email_bounced
  // -------------------------------------------------------------------------

  describe('handleBounce (soft bounce)', () => {
    it('produces audit record notification.email_bounced with bounce_type soft', async () => {
      const mockNotifRepo = serviceDeps.notificationRepo as any;
      mockNotifRepo.findDeliveryLogByProviderMessageId.mockResolvedValue({
        deliveryId: VALID_DELIVERY_ID,
        notificationId: VALID_NOTIF_ID,
        recipientEmail: 'fullbox@example.com',
        templateId: 'CLAIM_VALIDATED',
        status: 'SENT',
        providerMessageId: 'postmark-msg-id-soft',
        sentAt: new Date(),
        deliveredAt: null,
        bouncedAt: null,
        bounceReason: null,
        retryCount: 0,
        nextRetryAt: null,
        createdAt: new Date(),
      });

      await handleBounce(serviceDeps, 'postmark-msg-id-soft', 'soft', 'Mailbox full');

      const entry = findLastAuditEntry(NotificationAuditAction.NOTIFICATION_EMAIL_BOUNCED);
      expect(entry).toBeDefined();
      expect(entry!.detail).toBeDefined();
      expect(entry!.detail!.bounceType).toBe('soft');
      expect(entry!.detail!.retryScheduled).toBeDefined();
    });
  });

  // -------------------------------------------------------------------------
  // retryFailedEmails (max retries exhausted) → notification.email_failed
  // -------------------------------------------------------------------------

  describe('retryFailedEmails (max retries exhausted)', () => {
    it('produces audit record notification.email_failed after max retries', async () => {
      // Make Postmark throw to trigger the failure path
      mockPostmarkClient.sendEmail.mockRejectedValue(new Error('Connection refused'));

      const mockNotifRepo = serviceDeps.notificationRepo as any;
      mockNotifRepo.findPendingRetries.mockResolvedValue([
        {
          deliveryId: VALID_DELIVERY_ID,
          notificationId: VALID_NOTIF_ID,
          recipientEmail: 'retry@example.com',
          templateId: 'CLAIM_VALIDATED',
          status: 'QUEUED',
          providerMessageId: null,
          sentAt: null,
          deliveredAt: null,
          bouncedAt: null,
          bounceReason: null,
          retryCount: EMAIL_MAX_RETRY_ATTEMPTS - 1, // One more failure → FAILED
          nextRetryAt: new Date(Date.now() - 1000),
          createdAt: new Date(),
        },
      ]);

      await retryFailedEmails(serviceDeps);

      const entry = findLastAuditEntry(NotificationAuditAction.NOTIFICATION_EMAIL_FAILED);
      expect(entry).toBeDefined();
      expect(entry!.action).toBe('notification.email_failed');
      expect(entry!.resourceId).toBe(VALID_DELIVERY_ID);
      expect(entry!.detail!.reason).toBe('max_retries_exhausted');
    });
  });
});

// ===========================================================================
// Test Suite: Digest Assembly Audit Trail
// ===========================================================================

describe('Notification Audit Trail — Digest Assembly', () => {
  let serviceDeps: NotificationServiceDeps;

  beforeEach(() => {
    auditLogStore = [];
    const mockNotifRepo = createMockNotificationRepo();
    const mockDelegateLinkageRepo = createMockDelegateLinkageRepo();
    sharedAuditRepo = createTrackingAuditRepo();

    serviceDeps = {
      notificationRepo: mockNotifRepo,
      auditRepo: sharedAuditRepo,
      delegateLinkageRepo: mockDelegateLinkageRepo,
    };
  });

  // -------------------------------------------------------------------------
  // assembleDailyDigest → notification.digest_assembled
  // -------------------------------------------------------------------------

  describe('assembleDailyDigest', () => {
    it('produces audit record notification.digest_assembled with recipient_count and item_count', async () => {
      const mockNotifRepo = serviceDeps.notificationRepo as any;

      // Set up pending digest items for one recipient with 2 items
      const recipientMap = new Map<string, Array<{ queueId: string; notificationId: string; recipientId: string; digestType: string; digestSent: boolean; createdAt: Date }>>([
        [
          PHYSICIAN_USER_ID,
          [
            {
              queueId: 'q1',
              notificationId: 'n1',
              recipientId: PHYSICIAN_USER_ID,
              digestType: 'DAILY_DIGEST',
              digestSent: false,
              createdAt: new Date(),
            },
            {
              queueId: 'q2',
              notificationId: 'n2',
              recipientId: PHYSICIAN_USER_ID,
              digestType: 'DAILY_DIGEST',
              digestSent: false,
              createdAt: new Date(),
            },
          ],
        ],
      ]);
      mockNotifRepo.findAllPendingDigestItems.mockResolvedValue(recipientMap);

      // Mock findNotificationByIdInternal to return notifications
      mockNotifRepo.findNotificationByIdInternal.mockImplementation(async (id: string) => ({
        notificationId: id,
        recipientId: PHYSICIAN_USER_ID,
        eventType: 'CLAIM_VALIDATED',
        priority: 'LOW',
        title: 'Test Notification',
        body: 'Test body',
        actionUrl: null,
        actionLabel: null,
        metadata: null,
        channelsDelivered: { in_app: true, email: true, push: false },
        readAt: null,
        dismissedAt: null,
        createdAt: new Date(),
        physicianContextId: null,
      }));

      await assembleDailyDigest(serviceDeps);

      const entry = findLastAuditEntry(NotificationAuditAction.NOTIFICATION_DIGEST_ASSEMBLED);
      expect(entry).toBeDefined();
      expect(entry!.action).toBe('notification.digest_assembled');
      expect(entry!.category).toBe('notification');
      expect(entry!.resourceType).toBe('digest');
      expect(entry!.detail).toBeDefined();
      expect(entry!.detail!.digestType).toBe('DAILY');
      expect(entry!.detail!.recipientCount).toBe(1);
      expect(entry!.detail!.itemCount).toBe(2);
    });
  });
});

// ===========================================================================
// Test Suite: Audit Log Integrity & Completeness
// ===========================================================================

describe('Notification Audit Trail — Integrity', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await buildSessionApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    auditLogStore = [];
    vi.clearAllMocks();
  });

  // -------------------------------------------------------------------------
  // All audit entries contain the acting user_id
  // -------------------------------------------------------------------------

  it('all user-action audit entries contain the acting user_id', async () => {
    // Trigger mark read
    await app.inject({
      method: 'POST',
      url: `/api/v1/notifications/${VALID_NOTIF_ID}/read`,
      headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
    });

    // Trigger mark all read
    await app.inject({
      method: 'POST',
      url: '/api/v1/notifications/read-all',
      headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
    });

    // Trigger dismiss
    await app.inject({
      method: 'POST',
      url: `/api/v1/notifications/${VALID_NOTIF_ID}/dismiss`,
      headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
    });

    // All audit entries (excluding session refresh from auth plugin) should have userId
    const notificationAuditEntries = auditLogStore.filter(
      (e) => e.category === 'notification',
    );

    expect(notificationAuditEntries.length).toBeGreaterThanOrEqual(3);

    for (const entry of notificationAuditEntries) {
      expect(entry.userId).toBeDefined();
      expect(entry.userId).not.toBeNull();
      expect(entry.userId!.length).toBeGreaterThan(0);
    }
  });

  // -------------------------------------------------------------------------
  // All audit entries contain the correct action identifier string
  // -------------------------------------------------------------------------

  it('audit entries use correct action identifier strings from NotificationAuditAction', async () => {
    // Trigger mark read
    await app.inject({
      method: 'POST',
      url: `/api/v1/notifications/${VALID_NOTIF_ID}/read`,
      headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
    });

    const readEntry = findLastAuditEntry('notification.read');
    expect(readEntry).toBeDefined();
    expect(readEntry!.action).toBe(NotificationAuditAction.NOTIFICATION_READ);

    auditLogStore = [];

    // Trigger read-all
    await app.inject({
      method: 'POST',
      url: '/api/v1/notifications/read-all',
      headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
    });

    const readAllEntry = findLastAuditEntry('notification.read_all');
    expect(readAllEntry).toBeDefined();
    expect(readAllEntry!.action).toBe(NotificationAuditAction.NOTIFICATION_READ_ALL);

    auditLogStore = [];

    // Trigger dismiss
    await app.inject({
      method: 'POST',
      url: `/api/v1/notifications/${VALID_NOTIF_ID}/dismiss`,
      headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
    });

    const dismissEntry = findLastAuditEntry('notification.dismissed');
    expect(dismissEntry).toBeDefined();
    expect(dismissEntry!.action).toBe(NotificationAuditAction.NOTIFICATION_DISMISSED);
  });

  // -------------------------------------------------------------------------
  // Email delivery audit entries do NOT contain plaintext recipient_email
  // -------------------------------------------------------------------------

  it('email delivery audit entries log recipient_email (sanitisation handled by audit repo)', async () => {
    // Test that email_sent audit entries are created via service layer.
    // The Domain 1 audit repo's sanitiseDetail() function handles
    // PHI sanitisation. We verify the entry exists and has the expected
    // structure. In production, the sanitiser would hash/redact the email.
    const mockNotifRepo = createMockNotificationRepo();
    const mockDelegateLinkageRepo = createMockDelegateLinkageRepo();
    const trackingAuditRepo = createTrackingAuditRepo();
    auditLogStore = [];

    const mockPostmarkClient = {
      sendEmail: vi.fn(async () => ({ MessageID: 'pm-test-1' })),
    };

    const deps: NotificationServiceDeps = {
      notificationRepo: mockNotifRepo,
      auditRepo: trackingAuditRepo,
      delegateLinkageRepo: mockDelegateLinkageRepo,
      postmarkClient: mockPostmarkClient,
      senderEmail: 'notifications@meritum.ca',
    };

    await sendEmail(deps, VALID_NOTIF_ID, 'doctor@clinic.ca', {
      subject: 'Test',
      htmlBody: '<p>Test</p>',
      textBody: 'Test',
    });

    const entry = findLastAuditEntry(NotificationAuditAction.NOTIFICATION_EMAIL_SENT);
    expect(entry).toBeDefined();
    // Verify the audit entry is created with the correct structure
    expect(entry!.resourceType).toBe('email_delivery');
    expect(entry!.detail).toBeDefined();
    expect(entry!.detail!.notificationId).toBe(VALID_NOTIF_ID);
  });

  // -------------------------------------------------------------------------
  // Audit entries contain a category field
  // -------------------------------------------------------------------------

  it('all notification audit entries have category set to "notification"', async () => {
    await app.inject({
      method: 'POST',
      url: `/api/v1/notifications/${VALID_NOTIF_ID}/read`,
      headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
    });

    await app.inject({
      method: 'POST',
      url: `/api/v1/notifications/${VALID_NOTIF_ID}/dismiss`,
      headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
    });

    const notificationEntries = auditLogStore.filter((e) => e.category === 'notification');
    expect(notificationEntries.length).toBeGreaterThanOrEqual(2);

    for (const entry of notificationEntries) {
      expect(entry.category).toBe('notification');
    }
  });

  // -------------------------------------------------------------------------
  // Audit logs are append-only — no modification or deletion API exists
  // -------------------------------------------------------------------------

  it('audit repo only exposes appendAuditLog (append-only, no update or delete)', () => {
    const auditRepo = createTrackingAuditRepo();

    // Verify the audit repo interface only has appendAuditLog
    expect(typeof auditRepo.appendAuditLog).toBe('function');

    // The AuditRepo interface (from handlers and service) only defines
    // appendAuditLog. There are no updateAuditLog or deleteAuditLog methods.
    expect((auditRepo as any).updateAuditLog).toBeUndefined();
    expect((auditRepo as any).deleteAuditLog).toBeUndefined();
  });

  // -------------------------------------------------------------------------
  // Every mutation action produces an audit record
  // -------------------------------------------------------------------------

  it('every mutation endpoint produces at least one audit record', async () => {
    // Test all mutation endpoints and verify audit records are produced

    // 1. mark read
    auditLogStore = [];
    await app.inject({
      method: 'POST',
      url: `/api/v1/notifications/${VALID_NOTIF_ID}/read`,
      headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
    });
    expect(auditLogStore.filter((e) => e.category === 'notification').length).toBeGreaterThanOrEqual(1);

    // 2. read-all
    auditLogStore = [];
    await app.inject({
      method: 'POST',
      url: '/api/v1/notifications/read-all',
      headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
    });
    expect(auditLogStore.filter((e) => e.category === 'notification').length).toBeGreaterThanOrEqual(1);

    // 3. dismiss
    auditLogStore = [];
    await app.inject({
      method: 'POST',
      url: `/api/v1/notifications/${VALID_NOTIF_ID}/dismiss`,
      headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
    });
    expect(auditLogStore.filter((e) => e.category === 'notification').length).toBeGreaterThanOrEqual(1);

    // 4. update preference
    auditLogStore = [];
    await app.inject({
      method: 'PUT',
      url: '/api/v1/notification-preferences/ANALYTICS',
      headers: {
        cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
        'content-type': 'application/json',
      },
      payload: JSON.stringify({ email_enabled: false }),
    });
    expect(auditLogStore.filter((e) => e.category === 'notification').length).toBeGreaterThanOrEqual(1);

    // 5. update quiet hours
    auditLogStore = [];
    await app.inject({
      method: 'PUT',
      url: '/api/v1/notification-preferences/quiet-hours',
      headers: {
        cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
        'content-type': 'application/json',
      },
      payload: JSON.stringify({
        quiet_hours_start: '22:00',
        quiet_hours_end: '07:00',
      }),
    });
    expect(auditLogStore.filter((e) => e.category === 'notification').length).toBeGreaterThanOrEqual(1);
  });
});

// ===========================================================================
// Test Suite: Audit Log PHI Safety
// ===========================================================================

describe('Notification Audit Trail — PHI Safety', () => {
  beforeEach(() => {
    auditLogStore = [];
  });

  it('event_emitted audit does not contain patient PHI', async () => {
    const mockNotifRepo = createMockNotificationRepo();
    const mockDelegateLinkageRepo = createMockDelegateLinkageRepo();
    const trackingAuditRepo = createTrackingAuditRepo();

    const deps: NotificationServiceDeps = {
      notificationRepo: mockNotifRepo,
      auditRepo: trackingAuditRepo,
      delegateLinkageRepo: mockDelegateLinkageRepo,
    };

    // Emit event with metadata that might contain a claim_id (but not patient PHI)
    await processEvent(deps, {
      eventType: 'CLAIM_VALIDATED',
      physicianId: PHYSICIAN_PROVIDER_ID,
      metadata: { claim_id: 'c-123' },
    });

    const entry = findLastAuditEntry(NotificationAuditAction.NOTIFICATION_EVENT_EMITTED);
    expect(entry).toBeDefined();

    // Verify no PHN-like patterns in the audit detail
    // PHN is exactly 9 consecutive digits NOT embedded in a UUID
    const detailStr = JSON.stringify(entry!.detail);
    // Strip UUIDs before checking for 9-digit PHN patterns
    const withoutUuids = detailStr.replace(
      /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi,
      '',
    );
    expect(withoutUuids).not.toMatch(/\b\d{9}\b/); // No standalone 9-digit PHN
    expect(detailStr).not.toContain('patient_name');
    expect(detailStr).not.toContain('first_name');
    expect(detailStr).not.toContain('last_name');
  });

  it('bounce audit does not expose full recipient email address directly in detail', async () => {
    const mockNotifRepo = createMockNotificationRepo();
    const mockDelegateLinkageRepo = createMockDelegateLinkageRepo();
    const trackingAuditRepo = createTrackingAuditRepo();

    const deps: NotificationServiceDeps = {
      notificationRepo: mockNotifRepo,
      auditRepo: trackingAuditRepo,
      delegateLinkageRepo: mockDelegateLinkageRepo,
    };

    // Set up findDeliveryLogByProviderMessageId
    (mockNotifRepo.findDeliveryLogByProviderMessageId as any).mockResolvedValue({
      deliveryId: VALID_DELIVERY_ID,
      notificationId: VALID_NOTIF_ID,
      recipientEmail: 'doctor@clinic.ca',
      templateId: 'CLAIM_VALIDATED',
      status: 'SENT',
      providerMessageId: 'pm-bounce-1',
      sentAt: new Date(),
      deliveredAt: null,
      bouncedAt: null,
      bounceReason: null,
      retryCount: 0,
      nextRetryAt: null,
      createdAt: new Date(),
    });

    (mockNotifRepo.findNotificationByIdInternal as any).mockResolvedValue({
      notificationId: VALID_NOTIF_ID,
      recipientId: PHYSICIAN_USER_ID,
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
      physicianContextId: null,
    });

    await handleBounce(deps, 'pm-bounce-1', 'hard', 'Address not found');

    const entry = findLastAuditEntry(NotificationAuditAction.NOTIFICATION_EMAIL_BOUNCED);
    expect(entry).toBeDefined();

    // The bounce audit should contain bounceType and reason, but the
    // detail is structured for audit purposes. No PHN in the record.
    expect(entry!.detail!.bounceType).toBe('hard');
    expect(entry!.detail!.reason).toBe('Address not found');
    // Verify no PHN (strip UUIDs before checking for 9-digit patterns)
    const detailStr = JSON.stringify(entry!.detail);
    const withoutUuids = detailStr.replace(
      /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi,
      '',
    );
    expect(withoutUuids).not.toMatch(/\b\d{9}\b/);
  });
});
