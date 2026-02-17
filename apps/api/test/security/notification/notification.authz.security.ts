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
import { type NotificationHandlerDeps } from '../../../src/domains/notification/notification.handlers.js';
import { type InternalNotificationHandlerDeps } from '../../../src/domains/notification/notification.handlers.js';
import { type NotificationRepository } from '../../../src/domains/notification/notification.repository.js';
import { type NotificationServiceDeps } from '../../../src/domains/notification/notification.service.js';

// ---------------------------------------------------------------------------
// Token Helpers
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Test Data — Physician
// ---------------------------------------------------------------------------

const PHYSICIAN_USER_ID = '11111111-0000-0000-0000-000000000001';
const PHYSICIAN_PROVIDER_ID = '44444444-0000-0000-0000-000000000001';
const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_SESSION_ID = '33333333-0000-0000-0000-000000000001';

// ---------------------------------------------------------------------------
// Test Data — Delegate
// ---------------------------------------------------------------------------

const DELEGATE_USER_ID = '22222222-0000-0000-0000-000000000002';
const DELEGATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_SESSION_TOKEN_HASH = hashToken(DELEGATE_SESSION_TOKEN);
const DELEGATE_SESSION_ID = '33333333-0000-0000-0000-000000000002';

// ---------------------------------------------------------------------------
// Shared IDs
// ---------------------------------------------------------------------------

const VALID_NOTIF_ID = 'aaaaaaaa-0000-0000-0000-000000000001';
const VALID_API_KEY = 'test-internal-api-key-12345';

// ---------------------------------------------------------------------------
// Mock Repositories
// ---------------------------------------------------------------------------

function createMockNotificationRepo(): NotificationRepository {
  return {
    createNotification: vi.fn(async () => ({}) as any),
    createNotificationsBatch: vi.fn(async () => 0),
    findNotificationById: vi.fn(async () => undefined),
    findNotificationByIdInternal: vi.fn(async () => undefined),
    listNotifications: vi.fn(async () => []),
    countUnread: vi.fn(async () => 0),
    markRead: vi.fn(async () => ({ notificationId: VALID_NOTIF_ID }) as any),
    markAllRead: vi.fn(async () => 0),
    dismiss: vi.fn(async () => ({ notificationId: VALID_NOTIF_ID }) as any),
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
    findPreferencesByProvider: vi.fn(async () => []),
    findPreference: vi.fn(async () => undefined),
    upsertPreference: vi.fn(async () => ({
      preferenceId: 'pppp-0000-0000-0000-000000000001',
      providerId: PHYSICIAN_USER_ID,
      eventCategory: 'CLAIM_LIFECYCLE',
      inAppEnabled: true,
      emailEnabled: false,
      digestMode: 'IMMEDIATE',
      quietHoursStart: null,
      quietHoursEnd: null,
    }) as any),
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
// Mock Session Repo (returns both physician and delegate sessions)
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
      if (tokenHash === DELEGATE_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: DELEGATE_SESSION_ID,
            userId: DELEGATE_USER_ID,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: DELEGATE_USER_ID,
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

async function buildInternalApp(): Promise<FastifyInstance> {
  const mockNotifRepo = createMockNotificationRepo();
  const mockAuditRepo = createMockAuditRepo();
  const mockDelegateLinkageRepo = createMockDelegateLinkageRepo();

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

// ===========================================================================
// Test Suite: Preference Management — Delegate Restriction
// ===========================================================================

describe('Notification Authorization — Preference Management Restricted to Physicians', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await buildApp();
  });

  afterAll(async () => {
    await app.close();
  });

  // -------------------------------------------------------------------------
  // PUT /api/v1/notification-preferences/:category as delegate → 403
  // -------------------------------------------------------------------------

  it('PUT /api/v1/notification-preferences/:category as delegate returns 403', async () => {
    const res = await app.inject({
      method: 'PUT',
      url: '/api/v1/notification-preferences/CLAIM_LIFECYCLE',
      headers: {
        cookie: `session=${DELEGATE_SESSION_TOKEN}`,
        'content-type': 'application/json',
      },
      payload: JSON.stringify({ email_enabled: false }),
    });

    expect(res.statusCode).toBe(403);
    const body = JSON.parse(res.body);
    expect(body.error).toBeDefined();
    expect(body.data).toBeUndefined();
  });

  // -------------------------------------------------------------------------
  // PUT /api/v1/notification-preferences/quiet-hours as delegate → 403
  // -------------------------------------------------------------------------

  it('PUT /api/v1/notification-preferences/quiet-hours as delegate returns 403', async () => {
    const res = await app.inject({
      method: 'PUT',
      url: '/api/v1/notification-preferences/quiet-hours',
      headers: {
        cookie: `session=${DELEGATE_SESSION_TOKEN}`,
        'content-type': 'application/json',
      },
      payload: JSON.stringify({
        quiet_hours_start: '22:00',
        quiet_hours_end: '07:00',
      }),
    });

    expect(res.statusCode).toBe(403);
    const body = JSON.parse(res.body);
    expect(body.error).toBeDefined();
    expect(body.data).toBeUndefined();
  });

  // -------------------------------------------------------------------------
  // GET /api/v1/notification-preferences as delegate → 403
  // -------------------------------------------------------------------------

  it('GET /api/v1/notification-preferences as delegate returns 403', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/notification-preferences',
      headers: { cookie: `session=${DELEGATE_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(403);
    const body = JSON.parse(res.body);
    expect(body.error).toBeDefined();
    expect(body.data).toBeUndefined();
  });

  // -------------------------------------------------------------------------
  // 403 response body contains only error, no preference data
  // -------------------------------------------------------------------------

  it('403 response body from preference endpoints contains no preference data', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/notification-preferences',
      headers: { cookie: `session=${DELEGATE_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(403);
    const body = JSON.parse(res.body);
    const bodyStr = JSON.stringify(body);

    // Must not contain any preference data fields (error message mentioning
    // "preferences" in context is fine — it's the data we must not leak)
    expect(body.data).toBeUndefined();
    expect(bodyStr).not.toContain('in_app_enabled');
    expect(bodyStr).not.toContain('email_enabled');
    expect(bodyStr).not.toContain('digest_mode');
    expect(bodyStr).not.toContain('quiet_hours');
    expect(bodyStr).not.toContain('event_category');
    expect(bodyStr).not.toContain('preference_id');
  });
});

// ===========================================================================
// Test Suite: Delegate Notification Access (Positive Tests)
// ===========================================================================

describe('Notification Authorization — Delegate Notification Access', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await buildApp();
  });

  afterAll(async () => {
    await app.close();
  });

  // -------------------------------------------------------------------------
  // Delegate CAN access notification feed
  // -------------------------------------------------------------------------

  it('delegate can access GET /api/v1/notifications', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/notifications',
      headers: { cookie: `session=${DELEGATE_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(200);
  });

  // -------------------------------------------------------------------------
  // Delegate CAN mark single notification as read
  // -------------------------------------------------------------------------

  it('delegate can POST /api/v1/notifications/:id/read', async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/notifications/${VALID_NOTIF_ID}/read`,
      headers: { cookie: `session=${DELEGATE_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(200);
  });

  // -------------------------------------------------------------------------
  // Delegate CAN mark all notifications as read
  // -------------------------------------------------------------------------

  it('delegate can POST /api/v1/notifications/read-all', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/notifications/read-all',
      headers: { cookie: `session=${DELEGATE_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(200);
  });

  // -------------------------------------------------------------------------
  // Delegate CAN dismiss a notification
  // -------------------------------------------------------------------------

  it('delegate can POST /api/v1/notifications/:id/dismiss', async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/notifications/${VALID_NOTIF_ID}/dismiss`,
      headers: { cookie: `session=${DELEGATE_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(200);
  });

  // -------------------------------------------------------------------------
  // Delegate CAN access unread count
  // -------------------------------------------------------------------------

  it('delegate can access GET /api/v1/notifications/unread-count', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/notifications/unread-count',
      headers: { cookie: `session=${DELEGATE_SESSION_TOKEN}` },
    });

    expect(res.statusCode).toBe(200);
  });
});

// ===========================================================================
// Test Suite: URGENT Preference Enforcement
// ===========================================================================

describe('Notification Authorization — URGENT Preference Enforcement', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await buildApp();
  });

  afterAll(async () => {
    await app.close();
  });

  // -------------------------------------------------------------------------
  // CLAIM_LIFECYCLE has URGENT events (DEADLINE_1_DAY, BATCH_ERROR)
  // Cannot disable in_app for this category
  // -------------------------------------------------------------------------

  it('PUT CLAIM_LIFECYCLE with in_app_enabled=false returns 400 (URGENT enforcement)', async () => {
    const res = await app.inject({
      method: 'PUT',
      url: '/api/v1/notification-preferences/CLAIM_LIFECYCLE',
      headers: {
        cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
        'content-type': 'application/json',
      },
      payload: JSON.stringify({ in_app_enabled: false }),
    });

    expect(res.statusCode).toBe(400);
    const body = JSON.parse(res.body);
    expect(body.error).toBeDefined();
    expect(body.error.message).toMatch(/urgent/i);
    expect(body.error.message).toMatch(/in-app/i);
  });

  // -------------------------------------------------------------------------
  // PLATFORM_OPERATIONS has URGENT events (PAYMENT_FAILED, ACCOUNT_SUSPENDED)
  // Cannot disable in_app for this category
  // -------------------------------------------------------------------------

  it('PUT PLATFORM_OPERATIONS with in_app_enabled=false returns 400 (URGENT enforcement)', async () => {
    const res = await app.inject({
      method: 'PUT',
      url: '/api/v1/notification-preferences/PLATFORM_OPERATIONS',
      headers: {
        cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
        'content-type': 'application/json',
      },
      payload: JSON.stringify({ in_app_enabled: false }),
    });

    expect(res.statusCode).toBe(400);
    const body = JSON.parse(res.body);
    expect(body.error).toBeDefined();
    expect(body.error.message).toMatch(/urgent/i);
    expect(body.error.message).toMatch(/in-app/i);
  });

  // -------------------------------------------------------------------------
  // email_enabled CAN be changed for URGENT event categories
  // -------------------------------------------------------------------------

  it('email_enabled CAN be changed for URGENT categories (CLAIM_LIFECYCLE)', async () => {
    const res = await app.inject({
      method: 'PUT',
      url: '/api/v1/notification-preferences/CLAIM_LIFECYCLE',
      headers: {
        cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
        'content-type': 'application/json',
      },
      payload: JSON.stringify({ email_enabled: false }),
    });

    expect(res.statusCode).toBe(200);
  });

  it('email_enabled CAN be changed for URGENT categories (PLATFORM_OPERATIONS)', async () => {
    const res = await app.inject({
      method: 'PUT',
      url: '/api/v1/notification-preferences/PLATFORM_OPERATIONS',
      headers: {
        cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
        'content-type': 'application/json',
      },
      payload: JSON.stringify({ email_enabled: false }),
    });

    expect(res.statusCode).toBe(200);
  });

  // -------------------------------------------------------------------------
  // Non-URGENT categories CAN have in_app_enabled set to false
  // -------------------------------------------------------------------------

  it('non-URGENT category (ANALYTICS) CAN have in_app_enabled=false', async () => {
    const res = await app.inject({
      method: 'PUT',
      url: '/api/v1/notification-preferences/ANALYTICS',
      headers: {
        cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
        'content-type': 'application/json',
      },
      payload: JSON.stringify({ in_app_enabled: false }),
    });

    expect(res.statusCode).toBe(200);
  });

  it('non-URGENT category (INTELLIGENCE_ENGINE) CAN have in_app_enabled=false', async () => {
    const res = await app.inject({
      method: 'PUT',
      url: '/api/v1/notification-preferences/INTELLIGENCE_ENGINE',
      headers: {
        cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
        'content-type': 'application/json',
      },
      payload: JSON.stringify({ in_app_enabled: false }),
    });

    expect(res.statusCode).toBe(200);
  });

  it('non-URGENT category (PROVIDER_MANAGEMENT) CAN have in_app_enabled=false', async () => {
    const res = await app.inject({
      method: 'PUT',
      url: '/api/v1/notification-preferences/PROVIDER_MANAGEMENT',
      headers: {
        cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
        'content-type': 'application/json',
      },
      payload: JSON.stringify({ in_app_enabled: false }),
    });

    expect(res.statusCode).toBe(200);
  });
});

// ===========================================================================
// Test Suite: Internal Endpoint Authorization
// ===========================================================================

describe('Notification Authorization — Internal Endpoint Authorization', () => {
  let internalApp: FastifyInstance;

  const validEmitPayload = {
    event_type: 'CLAIM_VALIDATED',
    physician_id: PHYSICIAN_PROVIDER_ID,
    metadata: { claim_id: 'test-claim-123' },
  };

  const validBatchPayload = {
    events: [
      {
        event_type: 'CLAIM_VALIDATED',
        physician_id: PHYSICIAN_PROVIDER_ID,
        metadata: { claim_id: 'test-claim-123' },
      },
    ],
  };

  beforeAll(async () => {
    internalApp = await buildInternalApp();
  });

  afterAll(async () => {
    await internalApp.close();
  });

  // -------------------------------------------------------------------------
  // Emit with regular session cookie (no API key) → 401
  // -------------------------------------------------------------------------

  it('POST /api/v1/internal/notifications/emit with session cookie (no API key) returns 401', async () => {
    const res = await internalApp.inject({
      method: 'POST',
      url: '/api/v1/internal/notifications/emit',
      headers: {
        cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
        'content-type': 'application/json',
      },
      payload: JSON.stringify(validEmitPayload),
    });

    expect(res.statusCode).toBe(401);
    const body = JSON.parse(res.body);
    expect(body.data).toBeUndefined();
    expect(body.error).toBeDefined();
  });

  // -------------------------------------------------------------------------
  // Emit with wrong API key → 401
  // -------------------------------------------------------------------------

  it('POST /api/v1/internal/notifications/emit with wrong API key returns 401', async () => {
    const res = await internalApp.inject({
      method: 'POST',
      url: '/api/v1/internal/notifications/emit',
      headers: {
        'x-internal-api-key': 'wrong-key-completely-invalid',
        'content-type': 'application/json',
      },
      payload: JSON.stringify(validEmitPayload),
    });

    expect(res.statusCode).toBe(401);
    const body = JSON.parse(res.body);
    expect(body.data).toBeUndefined();
    expect(body.error).toBeDefined();
  });

  // -------------------------------------------------------------------------
  // Emit-batch with regular session cookie (no API key) → 401
  // -------------------------------------------------------------------------

  it('POST /api/v1/internal/notifications/emit-batch with session cookie (no API key) returns 401', async () => {
    const res = await internalApp.inject({
      method: 'POST',
      url: '/api/v1/internal/notifications/emit-batch',
      headers: {
        cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
        'content-type': 'application/json',
      },
      payload: JSON.stringify(validBatchPayload),
    });

    expect(res.statusCode).toBe(401);
    const body = JSON.parse(res.body);
    expect(body.data).toBeUndefined();
    expect(body.error).toBeDefined();
  });

  // -------------------------------------------------------------------------
  // Internal endpoints do not leak data in rejection responses
  // -------------------------------------------------------------------------

  it('internal endpoint 401 responses contain no notification data', async () => {
    const res = await internalApp.inject({
      method: 'POST',
      url: '/api/v1/internal/notifications/emit',
      headers: { 'content-type': 'application/json' },
      payload: JSON.stringify(validEmitPayload),
    });

    expect(res.statusCode).toBe(401);
    const body = JSON.parse(res.body);
    expect(body.data).toBeUndefined();
    expect(body.notification_ids).toBeUndefined();
    expect(body.created_count).toBeUndefined();
    expect(JSON.stringify(body)).not.toContain('notification_id');
  });
});
