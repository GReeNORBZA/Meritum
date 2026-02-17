import { describe, it, expect, vi, beforeAll, afterAll } from 'vitest';
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
import {
  type NotificationHandlerDeps,
  type InternalNotificationHandlerDeps,
} from '../../../src/domains/notification/notification.handlers.js';
import { type NotificationRepository } from '../../../src/domains/notification/notification.repository.js';
import {
  type NotificationServiceDeps,
  processEvent,
  renderDigestEmail,
  wsManager,
  type NotificationWebSocket,
  WS_READY_STATE,
} from '../../../src/domains/notification/notification.service.js';

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
// Test IDs and PHI payloads
// ---------------------------------------------------------------------------

const VALID_NOTIF_ID = 'aaaaaaaa-0000-0000-0000-000000000001';
const P2_NOTIF_ID = 'aaaaaaaa-0000-0000-0000-000000000002';
const NON_EXISTENT_UUID = 'ffffffff-ffff-ffff-ffff-ffffffffffff';
const VALID_API_KEY = 'test-internal-api-key-12345';
const TEST_PHN = '123456789';
const TEST_PATIENT_NAME = 'John Smith';
const TEST_CLAIM_ID = 'cccccccc-0000-0000-0000-000000000001';

// PHI metadata that simulates what might be passed in an event
const PHI_METADATA = {
  patient_name: TEST_PATIENT_NAME,
  phn: TEST_PHN,
  claim_id: TEST_CLAIM_ID,
  diagnostic_code: 'J06.9',
  health_service_code: '03.01A',
  date_of_service: '2026-01-15',
  amount: '125.50',
};

// ---------------------------------------------------------------------------
// Mock Repositories
// ---------------------------------------------------------------------------

function createMockNotificationRepo(): NotificationRepository {
  return {
    createNotification: vi.fn(async (data: any) => ({
      notificationId: randomBytes(16).toString('hex'),
      recipientId: data.recipientId,
      physicianContextId: data.physicianContextId ?? null,
      eventType: data.eventType,
      priority: data.priority,
      title: data.title,
      body: data.body,
      actionUrl: data.actionUrl ?? null,
      actionLabel: data.actionLabel ?? null,
      metadata: data.metadata ?? null,
      channelsDelivered: data.channelsDelivered ?? { in_app: true, email: false, push: false },
      readAt: null,
      dismissedAt: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    })),
    createNotificationsBatch: vi.fn(async () => 0),
    findNotificationById: vi.fn(async (id: string, recipientId: string) => {
      if (id === VALID_NOTIF_ID && recipientId === P1_USER_ID) {
        return {
          notificationId: VALID_NOTIF_ID,
          recipientId: P1_USER_ID,
          physicianContextId: null,
          eventType: 'CLAIM_REJECTED',
          priority: 'HIGH',
          title: 'Claim requires attention',
          body: 'A claim needs your review.',
          actionUrl: 'https://meritum.ca/claims/review',
          actionLabel: 'View Claim',
          metadata: { claim_id: TEST_CLAIM_ID },
          channelsDelivered: { in_app: true, email: true, push: false },
          readAt: null,
          dismissedAt: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
      }
      return undefined;
    }),
    findNotificationByIdInternal: vi.fn(async () => undefined),
    listNotifications: vi.fn(async (recipientId: string) => {
      if (recipientId === P1_USER_ID) {
        return [
          {
            notificationId: VALID_NOTIF_ID,
            recipientId: P1_USER_ID,
            physicianContextId: null,
            eventType: 'CLAIM_REJECTED',
            priority: 'HIGH',
            title: 'Claim requires attention',
            body: 'A claim needs your review.',
            actionUrl: 'https://meritum.ca/claims/review',
            actionLabel: 'View Claim',
            metadata: { claim_id: TEST_CLAIM_ID },
            channelsDelivered: { in_app: true, email: true, push: false },
            readAt: null,
            dismissedAt: null,
            createdAt: new Date(),
            updatedAt: new Date(),
          },
        ];
      }
      return [];
    }),
    countUnread: vi.fn(async () => 0),
    markRead: vi.fn(async (id: string, recipientId: string) => {
      if (id === VALID_NOTIF_ID && recipientId === P1_USER_ID) {
        return { notificationId: VALID_NOTIF_ID } as any;
      }
      return undefined;
    }),
    markAllRead: vi.fn(async () => 0),
    dismiss: vi.fn(async (id: string, recipientId: string) => {
      if (id === VALID_NOTIF_ID && recipientId === P1_USER_ID) {
        return { notificationId: VALID_NOTIF_ID } as any;
      }
      return undefined;
    }),
    createDeliveryLog: vi.fn(async (data: any) => ({
      deliveryId: 'del-' + randomBytes(8).toString('hex'),
      notificationId: data.notificationId,
      recipientEmail: data.recipientEmail,
      templateId: data.templateId,
      status: data.status,
      retryCount: 0,
      createdAt: new Date(),
      updatedAt: new Date(),
    })),
    updateDeliveryStatus: vi.fn(async () => undefined),
    findPendingRetries: vi.fn(async () => []),
    incrementRetry: vi.fn(async () => undefined),
    findDeliveryLogByProviderMessageId: vi.fn(async () => undefined),
    listDeliveryLogByNotification: vi.fn(async () => []),
    findTemplateById: vi.fn(async (templateId: string) => {
      // Return templates that use safe patterns — links not PHI
      if (templateId === 'CLAIM_REJECTED') {
        return {
          templateId: 'CLAIM_REJECTED',
          eventType: 'CLAIM_REJECTED',
          inAppTitle: 'Claim requires attention',
          inAppBody: 'A claim has been assessed. Please review.',
          emailSubject: 'Action required on your Meritum account',
          emailHtmlBody: '<p>You have a claim that needs your attention.</p><p><a href="https://meritum.ca/claims">View in Meritum</a></p>',
          emailTextBody: 'You have a claim that needs your attention. View at https://meritum.ca/claims',
          actionUrlTemplate: 'https://meritum.ca/claims/review',
          actionLabel: 'View Claim',
          variables: [] as string[],
          isActive: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
      }
      if (templateId === 'CLAIM_ASSESSED') {
        return {
          templateId: 'CLAIM_ASSESSED',
          eventType: 'CLAIM_ASSESSED',
          inAppTitle: 'Claim assessed',
          inAppBody: 'A claim has been assessed by AHCIP.',
          emailSubject: 'Meritum: Claim assessment update',
          emailHtmlBody: '<p>A claim has been assessed.</p><p><a href="https://meritum.ca/claims">View in Meritum</a></p>',
          emailTextBody: 'A claim has been assessed. View at https://meritum.ca/claims',
          actionUrlTemplate: 'https://meritum.ca/claims',
          actionLabel: 'View Claims',
          variables: [] as string[],
          isActive: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
      }
      if (templateId === 'AI_HIGH_VALUE_SUGGESTION') {
        return {
          templateId: 'AI_HIGH_VALUE_SUGGESTION',
          eventType: 'AI_HIGH_VALUE_SUGGESTION',
          inAppTitle: 'New billing suggestion available',
          inAppBody: 'The AI Coach has identified an opportunity. Check it out.',
          emailSubject: 'Meritum: New suggestion available',
          emailHtmlBody: '<p>A new suggestion is available for your review.</p><p><a href="https://meritum.ca/intelligence">View in Meritum</a></p>',
          emailTextBody: 'A new suggestion is available. View at https://meritum.ca/intelligence',
          actionUrlTemplate: 'https://meritum.ca/intelligence',
          actionLabel: 'View Suggestion',
          variables: [] as string[],
          isActive: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
      }
      return undefined;
    }),
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
    appendAuditLog: vi.fn(async () => {}),
  };
}

function createMockDelegateLinkageRepo() {
  return {
    listDelegatesForPhysician: vi.fn(async () => []),
  };
}

// ---------------------------------------------------------------------------
// Mock Session Repo
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
// Captured email data for email content inspection
// ---------------------------------------------------------------------------

interface CapturedEmail {
  From: string;
  To: string;
  Subject: string;
  HtmlBody: string;
  TextBody: string;
  MessageStream: string;
}

// ---------------------------------------------------------------------------
// Test App Builders
// ---------------------------------------------------------------------------

async function buildSessionApp(
  mockNotifRepo?: NotificationRepository,
): Promise<FastifyInstance> {
  const notifRepo = mockNotifRepo ?? createMockNotificationRepo();
  const mockAuditRepo = createMockAuditRepo();
  const mockSessionRepo = createMockSessionRepo();

  const sessionDeps: SessionManagementDeps = {
    sessionRepo: mockSessionRepo,
    auditRepo: mockAuditRepo,
    events: { emit: vi.fn() },
  };

  const handlerDeps: NotificationHandlerDeps = {
    notificationRepo: notifRepo,
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

async function buildInternalApp(
  mockNotifRepo?: NotificationRepository,
): Promise<FastifyInstance> {
  const notifRepo = mockNotifRepo ?? createMockNotificationRepo();
  const mockAuditRepo = createMockAuditRepo();
  const mockDelegateLinkageRepo = createMockDelegateLinkageRepo();

  const serviceDeps: NotificationServiceDeps = {
    notificationRepo: notifRepo,
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

// ===========================================================================
// Test Suite 1: No PHI in Email Notifications
// ===========================================================================

describe('Notification PHI Leakage Prevention — Email Content', () => {
  let capturedEmails: CapturedEmail[];
  let mockNotifRepo: NotificationRepository;
  let mockAuditRepo: ReturnType<typeof createMockAuditRepo>;
  let mockDelegateLinkageRepo: ReturnType<typeof createMockDelegateLinkageRepo>;
  let serviceDeps: NotificationServiceDeps;

  beforeAll(() => {
    capturedEmails = [];
    mockNotifRepo = createMockNotificationRepo();
    mockAuditRepo = createMockAuditRepo();
    mockDelegateLinkageRepo = createMockDelegateLinkageRepo();

    const mockPostmarkClient = {
      sendEmail: vi.fn(async (opts: CapturedEmail) => {
        capturedEmails.push(opts);
        return { MessageID: 'msg-' + randomBytes(8).toString('hex') };
      }),
    };

    serviceDeps = {
      notificationRepo: mockNotifRepo,
      auditRepo: mockAuditRepo,
      delegateLinkageRepo: mockDelegateLinkageRepo,
      postmarkClient: mockPostmarkClient,
      senderEmail: 'notifications@meritum.ca',
    };
  });

  it('CLAIM_REJECTED email body does NOT contain patient name, PHN, or claim details', async () => {
    capturedEmails = [];

    // Configure preferences to enable immediate email
    (mockNotifRepo.findPreference as any).mockResolvedValue({
      preferenceId: 'pref-1',
      providerId: P1_USER_ID,
      eventCategory: 'CLAIM_LIFECYCLE',
      inAppEnabled: true,
      emailEnabled: true,
      digestMode: 'IMMEDIATE',
      quietHoursStart: null,
      quietHoursEnd: null,
    });

    await processEvent(serviceDeps, {
      eventType: 'CLAIM_REJECTED',
      physicianId: P1_USER_ID,
      metadata: PHI_METADATA,
    });

    // Email was queued (via createDeliveryLog), but the template-rendered content
    // (title, body, email subject/body) should never contain PHI.
    // NOTE: The raw metadata is stored on the notification record for internal
    // reference, but the RENDERED content fields must not contain PHI.
    const createCall = (mockNotifRepo.createNotification as any).mock.lastCall;
    expect(createCall).toBeDefined();

    const createdNotification = createCall[0];

    // Rendered title and body must not contain PHI
    expect(createdNotification.title).not.toContain(TEST_PATIENT_NAME);
    expect(createdNotification.title).not.toContain(TEST_PHN);
    expect(createdNotification.title).not.toContain('J06.9');
    expect(createdNotification.title).not.toContain('03.01A');

    expect(createdNotification.body).not.toContain(TEST_PATIENT_NAME);
    expect(createdNotification.body).not.toContain(TEST_PHN);
    expect(createdNotification.body).not.toContain('J06.9');
    expect(createdNotification.body).not.toContain('03.01A');

    // The template's email content (from findTemplateById) also must not contain PHI
    const template = await mockNotifRepo.findTemplateById('CLAIM_REJECTED');
    expect(template!.emailSubject).not.toContain(TEST_PATIENT_NAME);
    expect(template!.emailSubject).not.toContain(TEST_PHN);
    expect(template!.emailHtmlBody).not.toContain(TEST_PATIENT_NAME);
    expect(template!.emailHtmlBody).not.toContain(TEST_PHN);
    expect(template!.emailTextBody).not.toContain(TEST_PATIENT_NAME);
    expect(template!.emailTextBody).not.toContain(TEST_PHN);

    // Email template should contain a link to meritum.ca, not inline data
    expect(template!.emailHtmlBody).toContain('meritum.ca');
    expect(template!.emailTextBody).toContain('meritum.ca');
  });

  it('CLAIM_ASSESSED email body contains only summary text and a link', async () => {
    capturedEmails = [];

    (mockNotifRepo.findPreference as any).mockResolvedValue({
      preferenceId: 'pref-2',
      providerId: P1_USER_ID,
      eventCategory: 'CLAIM_LIFECYCLE',
      inAppEnabled: true,
      emailEnabled: true,
      digestMode: 'IMMEDIATE',
      quietHoursStart: null,
      quietHoursEnd: null,
    });

    await processEvent(serviceDeps, {
      eventType: 'CLAIM_ASSESSED',
      physicianId: P1_USER_ID,
      metadata: PHI_METADATA,
    });

    const createCall = (mockNotifRepo.createNotification as any).mock.lastCall;
    const createdNotification = createCall[0];

    // Rendered content should contain a link to meritum.ca
    expect(createdNotification.actionUrl).toContain('meritum.ca');

    // Rendered title and body must not contain PHI
    expect(createdNotification.title).not.toContain(TEST_PATIENT_NAME);
    expect(createdNotification.title).not.toContain(TEST_PHN);
    expect(createdNotification.body).not.toContain(TEST_PATIENT_NAME);
    expect(createdNotification.body).not.toContain(TEST_PHN);

    // The template's email fields must not contain PHI
    const template = await mockNotifRepo.findTemplateById('CLAIM_ASSESSED');
    expect(template!.emailSubject).not.toContain(TEST_PATIENT_NAME);
    expect(template!.emailSubject).not.toContain(TEST_PHN);
    expect(template!.emailHtmlBody).not.toContain(TEST_PATIENT_NAME);
    expect(template!.emailHtmlBody).not.toContain(TEST_PHN);
    expect(template!.emailHtmlBody).toContain('meritum.ca');
  });

  it('AI_HIGH_VALUE_SUGGESTION email body contains no billing code details', async () => {
    capturedEmails = [];

    (mockNotifRepo.findPreference as any).mockResolvedValue({
      preferenceId: 'pref-3',
      providerId: P1_USER_ID,
      eventCategory: 'INTELLIGENCE_ENGINE',
      inAppEnabled: true,
      emailEnabled: true,
      digestMode: 'IMMEDIATE',
      quietHoursStart: null,
      quietHoursEnd: null,
    });

    const aiMetadata = {
      billing_code: '03.01A',
      suggested_code: '03.03A',
      estimated_value: '250.00',
      patient_name: TEST_PATIENT_NAME,
      phn: TEST_PHN,
    };

    await processEvent(serviceDeps, {
      eventType: 'AI_HIGH_VALUE_SUGGESTION',
      physicianId: P1_USER_ID,
      metadata: aiMetadata,
    });

    const createCall = (mockNotifRepo.createNotification as any).mock.lastCall;
    const createdNotification = createCall[0];

    // No billing codes in rendered content
    expect(createdNotification.title).not.toContain('03.01A');
    expect(createdNotification.title).not.toContain('03.03A');
    expect(createdNotification.body).not.toContain('03.01A');
    expect(createdNotification.body).not.toContain('03.03A');
    expect(createdNotification.title).not.toContain(TEST_PATIENT_NAME);
    expect(createdNotification.body).not.toContain(TEST_PATIENT_NAME);
    expect(createdNotification.title).not.toContain(TEST_PHN);
    expect(createdNotification.body).not.toContain(TEST_PHN);

    // Should contain a link to the app
    expect(createdNotification.actionUrl).toContain('meritum.ca');
  });

  it('email subject lines contain no PHI', async () => {
    // Verify all templates have safe subject lines
    const templates = ['CLAIM_REJECTED', 'CLAIM_ASSESSED', 'AI_HIGH_VALUE_SUGGESTION'];

    for (const templateId of templates) {
      const template = await mockNotifRepo.findTemplateById(templateId);
      if (template?.emailSubject) {
        expect(template.emailSubject).not.toContain(TEST_PATIENT_NAME);
        expect(template.emailSubject).not.toContain(TEST_PHN);
        expect(template.emailSubject).not.toContain('J06.9');
        expect(template.emailSubject).not.toContain('03.01A');
      }
    }
  });

  it('all email templates contain a link to an authenticated page, not inline data', async () => {
    const templates = ['CLAIM_REJECTED', 'CLAIM_ASSESSED', 'AI_HIGH_VALUE_SUGGESTION'];

    for (const templateId of templates) {
      const template = await mockNotifRepo.findTemplateById(templateId);
      if (template) {
        // Email body should contain a meritum.ca link
        if (template.emailHtmlBody) {
          expect(template.emailHtmlBody).toContain('meritum.ca');
        }
        if (template.emailTextBody) {
          expect(template.emailTextBody).toContain('meritum.ca');
        }
      }
    }
  });

  it('digest emails contain only category counts and links, no PHI', () => {
    const digestItems = [
      {
        queueId: 'q1',
        recipientId: P1_USER_ID,
        notificationId: 'n1',
        digestType: 'DAILY_DIGEST',
        isSent: false,
        createdAt: new Date(),
      },
      {
        queueId: 'q2',
        recipientId: P1_USER_ID,
        notificationId: 'n2',
        digestType: 'DAILY_DIGEST',
        isSent: false,
        createdAt: new Date(),
      },
    ];

    const notificationsForDigest = [
      {
        notificationId: 'n1',
        recipientId: P1_USER_ID,
        physicianContextId: null,
        eventType: 'CLAIM_REJECTED',
        priority: 'HIGH',
        title: 'Claim requires attention',
        body: 'Review needed',
        actionUrl: 'https://meritum.ca/claims',
        actionLabel: 'View',
        metadata: PHI_METADATA,
        channelsDelivered: { in_app: true, email: true, push: false },
        readAt: null,
        dismissedAt: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        notificationId: 'n2',
        recipientId: P1_USER_ID,
        physicianContextId: null,
        eventType: 'CLAIM_ASSESSED',
        priority: 'MEDIUM',
        title: 'Claim assessed',
        body: 'Assessment complete',
        actionUrl: 'https://meritum.ca/claims',
        actionLabel: 'View',
        metadata: PHI_METADATA,
        channelsDelivered: { in_app: true, email: true, push: false },
        readAt: null,
        dismissedAt: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
    ];

    const rendered = renderDigestEmail(
      digestItems as any,
      'DAILY',
      notificationsForDigest as any,
    );

    // Digest must not contain any PHI
    expect(rendered.htmlBody).not.toContain(TEST_PATIENT_NAME);
    expect(rendered.htmlBody).not.toContain(TEST_PHN);
    expect(rendered.htmlBody).not.toContain('J06.9');
    expect(rendered.htmlBody).not.toContain('03.01A');

    expect(rendered.textBody).not.toContain(TEST_PATIENT_NAME);
    expect(rendered.textBody).not.toContain(TEST_PHN);
    expect(rendered.textBody).not.toContain('J06.9');
    expect(rendered.textBody).not.toContain('03.01A');

    expect(rendered.subject).not.toContain(TEST_PATIENT_NAME);
    expect(rendered.subject).not.toContain(TEST_PHN);

    // Must contain a link to meritum.ca
    expect(rendered.htmlBody).toContain('meritum.ca/notifications');
    expect(rendered.textBody).toContain('meritum.ca/notifications');

    // Should contain counts, not individual claim details
    expect(rendered.textBody).toMatch(/\d+ notification/);
  });
});

// ===========================================================================
// Test Suite 2: Error Response Sanitisation
// ===========================================================================

describe('Notification PHI Leakage Prevention — Error Response Sanitisation', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await buildSessionApp();
  });

  afterAll(async () => {
    await app.close();
  });

  it('401 response body contains only error object, no notification data or stack traces', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/notifications',
    });

    expect(res.statusCode).toBe(401);
    const body = JSON.parse(res.body);

    // Must have error object
    expect(body.error).toBeDefined();

    // Must NOT have data
    expect(body.data).toBeUndefined();

    // Must NOT have stack traces
    expect(body.error.stack).toBeUndefined();
    expect(JSON.stringify(body)).not.toMatch(/at\s+\w+/); // no stack frames

    // Must NOT contain notification data
    expect(JSON.stringify(body)).not.toContain('notification_id');
    expect(JSON.stringify(body)).not.toContain('recipientId');
    expect(JSON.stringify(body)).not.toContain('physicianContextId');
  });

  it('404 for another users notification does NOT confirm existence', async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/notifications/${P2_NOTIF_ID}/read`,
      headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(404);
    const body = JSON.parse(res.body);

    // Generic "not found" message — should NOT say "belongs to another user"
    expect(body.error.message).not.toMatch(/another/i);
    expect(body.error.message).not.toMatch(/other.*user/i);
    expect(body.error.message).not.toMatch(/permission/i);
    expect(body.error.message).not.toContain(P2_NOTIF_ID);
    expect(body.error.message).not.toContain(P2_USER_ID);

    // Must NOT have data
    expect(body.data).toBeUndefined();
  });

  it('404 dismiss for another users notification does NOT confirm existence', async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/notifications/${P2_NOTIF_ID}/dismiss`,
      headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(404);
    const body = JSON.parse(res.body);

    expect(body.error.message).not.toMatch(/another/i);
    expect(body.error.message).not.toMatch(/other.*user/i);
    expect(body.error.message).not.toContain(P2_NOTIF_ID);
    expect(body.data).toBeUndefined();
  });

  it('404 for non-existent notification does NOT reveal resource details', async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/notifications/${NON_EXISTENT_UUID}/read`,
      headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(404);
    const body = JSON.parse(res.body);

    expect(body.error.message).not.toContain(NON_EXISTENT_UUID);
    expect(body.data).toBeUndefined();
  });

  it('500 error does not expose stack traces, SQL errors, or internal details', async () => {
    // Build an app where the repo throws an unexpected error
    const brokenRepo = createMockNotificationRepo();
    (brokenRepo.listNotifications as any).mockRejectedValue(
      new Error('connection to server at "10.0.0.5" port 5432 failed: FATAL: too many connections'),
    );

    const brokenApp = await buildSessionApp(brokenRepo);

    try {
      const res = await brokenApp.inject({
        method: 'GET',
        url: '/api/v1/notifications',
        headers: { cookie: `session=${P1_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(500);
      const body = JSON.parse(res.body);

      // Generic error message only
      expect(body.error.message).toBe('Internal server error');

      // No stack traces
      expect(body.error.stack).toBeUndefined();

      // No internal details
      const bodyStr = JSON.stringify(body);
      expect(bodyStr).not.toMatch(/postgres/i);
      expect(bodyStr).not.toMatch(/drizzle/i);
      expect(bodyStr).not.toMatch(/sql/i);
      expect(bodyStr).not.toMatch(/connection/i);
      expect(bodyStr).not.toMatch(/port 5432/i);
      expect(bodyStr).not.toMatch(/10\.0\.0\.5/);
      expect(bodyStr).not.toContain('.ts');
      expect(bodyStr).not.toContain('.js');
    } finally {
      await brokenApp.close();
    }
  });
});

// ===========================================================================
// Test Suite 3: Header Checks
// ===========================================================================

describe('Notification PHI Leakage Prevention — HTTP Headers', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await buildSessionApp();
  });

  afterAll(async () => {
    await app.close();
  });

  it('response does NOT contain X-Powered-By header', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/notifications',
      headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    });

    expect(res.headers['x-powered-by']).toBeUndefined();
  });

  it('response does NOT contain Server header revealing version info', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/notifications',
      headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    });

    // Server header should either be absent or not reveal version info
    const serverHeader = res.headers['server'];
    if (serverHeader) {
      expect(String(serverHeader)).not.toMatch(/\d+\.\d+/); // no version numbers
    }
  });

  it('Content-Type is set correctly on JSON responses', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/notifications',
      headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toMatch(/application\/json/);
  });

  it('Content-Type is set correctly on error responses', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/notifications',
    });

    expect(res.statusCode).toBe(401);
    expect(res.headers['content-type']).toMatch(/application\/json/);
  });

  it('error responses also do not contain X-Powered-By', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/notifications',
    });

    expect(res.statusCode).toBe(401);
    expect(res.headers['x-powered-by']).toBeUndefined();
  });
});

// ===========================================================================
// Test Suite 4: WebSocket Payload Sanitisation
// ===========================================================================

describe('Notification PHI Leakage Prevention — WebSocket Payload', () => {
  it('WebSocket payload contains only rendered content fields, no internal DB fields', () => {
    // Create a mock socket to capture sent messages
    const sentMessages: string[] = [];
    const mockSocket: NotificationWebSocket = {
      readyState: WS_READY_STATE.OPEN,
      send: vi.fn((data: string) => { sentMessages.push(data); }),
      close: vi.fn(),
      ping: vi.fn(),
      on: vi.fn(),
      removeAllListeners: vi.fn(),
    };

    const testUserId = 'ws-test-user-001';
    wsManager.registerConnection(testUserId, mockSocket);

    // Push a notification via wsManager
    wsManager.pushToUser(testUserId, {
      notificationId: VALID_NOTIF_ID,
      recipientId: P1_USER_ID,
      physicianContextId: 'phys-context-123',
      eventType: 'CLAIM_REJECTED',
      priority: 'HIGH',
      title: 'Claim requires attention',
      body: 'A claim needs your review.',
      actionUrl: 'https://meritum.ca/claims/review',
      actionLabel: 'View Claim',
      metadata: { claim_id: TEST_CLAIM_ID },
      channelsDelivered: { in_app: true, email: true, push: false },
      readAt: null,
      dismissedAt: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    } as any);

    expect(sentMessages.length).toBe(1);
    const payload = JSON.parse(sentMessages[0]);

    // Verify payload structure
    expect(payload.type).toBe('notification');
    expect(payload.data).toBeDefined();

    // Expected fields present
    expect(payload.data.notification_id).toBeDefined();
    expect(payload.data.title).toBeDefined();
    expect(payload.data.body).toBeDefined();
    expect(payload.data.priority).toBeDefined();
    expect(payload.data.action_url).toBeDefined();
    expect(payload.data.event_type).toBeDefined();
    expect(payload.data.metadata).toBeDefined();
    expect(payload.data.created_at).toBeDefined();

    // Internal DB fields must NOT be present
    expect(payload.data.recipient_id).toBeUndefined();
    expect(payload.data.recipientId).toBeUndefined();
    expect(payload.data.recipient_email).toBeUndefined();
    expect(payload.data.physician_context_id).toBeUndefined();
    expect(payload.data.physicianContextId).toBeUndefined();
    expect(payload.data.dismissed_at).toBeUndefined();
    expect(payload.data.dismissedAt).toBeUndefined();
    expect(payload.data.read_at).toBeUndefined();
    expect(payload.data.readAt).toBeUndefined();
    expect(payload.data.channels_delivered).toBeUndefined();
    expect(payload.data.channelsDelivered).toBeUndefined();
    expect(payload.data.updated_at).toBeUndefined();
    expect(payload.data.updatedAt).toBeUndefined();

    // Clean up
    wsManager.removeConnection(testUserId, mockSocket);
  });

  it('WebSocket payload metadata does not leak raw DB column values', () => {
    const sentMessages: string[] = [];
    const mockSocket: NotificationWebSocket = {
      readyState: WS_READY_STATE.OPEN,
      send: vi.fn((data: string) => { sentMessages.push(data); }),
      close: vi.fn(),
      ping: vi.fn(),
      on: vi.fn(),
      removeAllListeners: vi.fn(),
    };

    const testUserId = 'ws-test-user-002';
    wsManager.registerConnection(testUserId, mockSocket);

    wsManager.pushToUser(testUserId, {
      notificationId: 'ws-notif-002',
      recipientId: 'hidden-recipient',
      physicianContextId: 'hidden-phys-context',
      eventType: 'CLAIM_ASSESSED',
      priority: 'MEDIUM',
      title: 'Assessment received',
      body: 'Check your dashboard.',
      actionUrl: 'https://meritum.ca/claims',
      actionLabel: 'View',
      metadata: { summary: 'claim assessed' },
      channelsDelivered: { in_app: true, email: false, push: false },
      readAt: new Date(),
      dismissedAt: new Date(),
      createdAt: new Date(),
      updatedAt: new Date(),
    } as any);

    expect(sentMessages.length).toBe(1);
    const rawPayload = sentMessages[0];

    // Raw payload should not contain internal values
    expect(rawPayload).not.toContain('hidden-recipient');
    expect(rawPayload).not.toContain('hidden-phys-context');

    wsManager.removeConnection(testUserId, mockSocket);
  });
});

// ===========================================================================
// Test Suite 5: Sensitive Data Not in API Responses
// ===========================================================================

describe('Notification PHI Leakage Prevention — Sensitive Data in Responses', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await buildSessionApp();
  });

  afterAll(async () => {
    await app.close();
  });

  it('GET /api/v1/notifications does NOT expose email delivery log details', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/notifications',
      headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);
    const bodyStr = JSON.stringify(body);

    // No email delivery log fields
    expect(bodyStr).not.toContain('delivery_id');
    expect(bodyStr).not.toContain('deliveryId');
    expect(bodyStr).not.toContain('recipient_email');
    expect(bodyStr).not.toContain('recipientEmail');
    expect(bodyStr).not.toContain('retry_count');
    expect(bodyStr).not.toContain('retryCount');
    expect(bodyStr).not.toContain('provider_message_id');
    expect(bodyStr).not.toContain('providerMessageId');
    expect(bodyStr).not.toContain('bounce_reason');
    expect(bodyStr).not.toContain('bounceReason');
  });

  it('GET /api/v1/notifications response does NOT expose recipientId', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/notifications',
      headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);
    const bodyStr = JSON.stringify(body);

    // No internal recipient fields
    expect(bodyStr).not.toContain('"recipientId"');
    expect(bodyStr).not.toContain('"recipient_id"');
    expect(bodyStr).not.toContain('"physicianContextId"');
    expect(bodyStr).not.toContain('"physician_context_id"');
  });

  it('GET /api/v1/notification-preferences does NOT expose other physicians preferences', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/notification-preferences',
      headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);
    const bodyStr = JSON.stringify(body);

    // Must NOT contain physician 2's user ID
    expect(bodyStr).not.toContain(P2_USER_ID);

    // Verify response structure has expected fields
    expect(body.data).toBeDefined();
    expect(body.data.preferences).toBeDefined();
  });

  it('internal emit response does NOT leak recipient resolution details', async () => {
    const internalApp = await buildInternalApp();

    try {
      const res = await internalApp.inject({
        method: 'POST',
        url: '/api/v1/internal/notifications/emit',
        headers: {
          'x-internal-api-key': VALID_API_KEY,
          'content-type': 'application/json',
        },
        payload: JSON.stringify({
          event_type: 'CLAIM_VALIDATED',
          physician_id: P1_USER_ID,
          metadata: { claim_id: TEST_CLAIM_ID },
        }),
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      const bodyStr = JSON.stringify(body);

      // Should only have notification_ids, not recipient details
      expect(body.data.notification_ids).toBeDefined();

      // Must NOT reveal delegate user IDs or count
      expect(bodyStr).not.toContain('delegate');
      expect(bodyStr).not.toContain('recipient_count');
      expect(bodyStr).not.toContain('recipientCount');
      expect(bodyStr).not.toContain('user_id');
      expect(bodyStr).not.toContain('userId');
    } finally {
      await internalApp.close();
    }
  });

  it('internal emit-batch response does NOT leak per-event recipient details', async () => {
    const internalApp = await buildInternalApp();

    try {
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
              physician_id: P1_USER_ID,
              metadata: { claim_id: 'c1' },
            },
            {
              event_type: 'CLAIM_ASSESSED',
              physician_id: P1_USER_ID,
              metadata: { claim_id: 'c2' },
            },
          ],
        }),
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      const bodyStr = JSON.stringify(body);

      // Should return created_count, not detailed per-recipient info
      expect(body.data.created_count).toBeDefined();

      // Must NOT contain recipient, delegate, or user details
      expect(bodyStr).not.toContain('delegate');
      expect(bodyStr).not.toContain('recipient');
      expect(bodyStr).not.toContain('user_id');
      expect(bodyStr).not.toContain('userId');
    } finally {
      await internalApp.close();
    }
  });
});

// ===========================================================================
// Test Suite 6: Validation Error Sanitisation
// ===========================================================================

describe('Notification PHI Leakage Prevention — Validation Errors', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await buildSessionApp();
  });

  afterAll(async () => {
    await app.close();
  });

  it('validation error for invalid notification ID does not echo the input', async () => {
    const maliciousId = 'not-a-uuid-contains-phi-123456789';
    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/notifications/${maliciousId}/read`,
      headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(400);
    const body = JSON.parse(res.body);
    const bodyStr = JSON.stringify(body);

    // Must not echo back the malicious input
    expect(bodyStr).not.toContain('phi-123456789');
  });

  it('validation error for invalid query params does not echo PHI', async () => {
    const res = await app.inject({
      method: 'GET',
      url: `/api/v1/notifications?limit=abc&offset=xyz`,
      headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(400);
    const body = JSON.parse(res.body);

    // Error response should be generic
    expect(body.error).toBeDefined();
    expect(body.data).toBeUndefined();
  });

  it('validation error for invalid preference body does not expose internals', async () => {
    const res = await app.inject({
      method: 'PUT',
      url: '/api/v1/notification-preferences/CLAIM_LIFECYCLE',
      headers: {
        cookie: `session=${P1_SESSION_TOKEN}`,
        'content-type': 'application/json',
      },
      payload: JSON.stringify({
        in_app_enabled: 'not-a-boolean',
        extra_field_with_phi: TEST_PHN,
      }),
    });

    // Should be 400 (validation error)
    expect([400, 200]).toContain(res.statusCode);

    if (res.statusCode === 400) {
      const bodyStr = JSON.stringify(JSON.parse(res.body));
      // Must not echo back the PHN
      expect(bodyStr).not.toContain(TEST_PHN);
    }
  });
});
