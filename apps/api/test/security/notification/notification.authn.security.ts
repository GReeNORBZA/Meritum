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
  notificationWebSocketRoutes,
} from '../../../src/domains/notification/notification.routes.js';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { type SessionManagementDeps } from '../../../src/domains/iam/iam.service.js';
import { type NotificationHandlerDeps } from '../../../src/domains/notification/notification.handlers.js';
import { type InternalNotificationHandlerDeps } from '../../../src/domains/notification/notification.handlers.js';
import { type NotificationRepository } from '../../../src/domains/notification/notification.repository.js';
import {
  type NotificationServiceDeps,
  type WsSessionValidator,
} from '../../../src/domains/notification/notification.service.js';

// ---------------------------------------------------------------------------
// Token Helpers
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Test Data
// ---------------------------------------------------------------------------

const USER_ID = '11111111-0000-0000-0000-000000000001';
const SESSION_TOKEN = randomBytes(32).toString('hex');
const SESSION_TOKEN_HASH = hashToken(SESSION_TOKEN);
const SESSION_ID = '33333333-0000-0000-0000-000000000001';

const EXPIRED_SESSION_TOKEN = randomBytes(32).toString('hex');
const EXPIRED_SESSION_TOKEN_HASH = hashToken(EXPIRED_SESSION_TOKEN);
const EXPIRED_SESSION_ID = '33333333-0000-0000-0000-000000000099';

const TAMPERED_SESSION_TOKEN = randomBytes(32).toString('hex');

const VALID_NOTIF_ID = 'aaaaaaaa-0000-0000-0000-000000000001';
const PHYSICIAN_ID = '44444444-0000-0000-0000-000000000001';
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
    markRead: vi.fn(async () => undefined),
    markAllRead: vi.fn(async () => 0),
    dismiss: vi.fn(async () => undefined),
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
// Mock Session Repo (for auth plugin)
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      // Only the valid session token resolves to a session.
      // The real repository filters out expired/revoked sessions at the DB level,
      // returning undefined for them. Our mock matches that behavior:
      // - EXPIRED_SESSION_TOKEN_HASH → undefined (repo would filter it out)
      // - TAMPERED_SESSION_TOKEN hash → undefined (not in DB at all)
      if (tokenHash === SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: SESSION_ID,
            userId: USER_ID,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: USER_ID,
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

async function buildSessionApp(): Promise<FastifyInstance> {
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

async function buildWsApp(): Promise<FastifyInstance> {
  const mockSessionRepo = createMockSessionRepo();

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  const websocketPlugin = await import('@fastify/websocket');
  await testApp.register(websocketPlugin.default ?? websocketPlugin);

  const sessionValidator: WsSessionValidator = {
    validateSession: async (tokenHash: string) => {
      const result = await mockSessionRepo.findSessionByTokenHash(tokenHash);
      if (!result || result.session.revoked) return null;
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
// Shared assertion helpers
// ---------------------------------------------------------------------------

function assertNo401DataLeakage(body: any) {
  expect(body.data).toBeUndefined();
  expect(body.error).toBeDefined();
}

function assertNoSetCookieHeader(headers: Record<string, string | string[] | undefined>) {
  expect(headers['set-cookie']).toBeUndefined();
}

// ===========================================================================
// Test Suite: Authentication Enforcement on Session-Authenticated Routes
// ===========================================================================

describe('Notification Authentication Enforcement (Session Routes)', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await buildSessionApp();
  });

  afterAll(async () => {
    await app.close();
  });

  // =========================================================================
  // GET /api/v1/notifications
  // =========================================================================

  describe('GET /api/v1/notifications', () => {
    it('returns 401 without session cookie', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/notifications',
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      assertNo401DataLeakage(body);
      assertNoSetCookieHeader(res.headers);
    });

    it('returns 401 with expired/revoked session cookie', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/notifications',
        headers: { cookie: `session=${EXPIRED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      assertNo401DataLeakage(body);
      assertNoSetCookieHeader(res.headers);
    });

    it('returns 401 with tampered session cookie', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/notifications',
        headers: { cookie: `session=${TAMPERED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      assertNo401DataLeakage(body);
      assertNoSetCookieHeader(res.headers);
    });
  });

  // =========================================================================
  // GET /api/v1/notifications/unread-count
  // =========================================================================

  describe('GET /api/v1/notifications/unread-count', () => {
    it('returns 401 without session cookie', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/notifications/unread-count',
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      assertNo401DataLeakage(body);
      assertNoSetCookieHeader(res.headers);
    });

    it('returns 401 with expired/revoked session cookie', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/notifications/unread-count',
        headers: { cookie: `session=${EXPIRED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      assertNo401DataLeakage(body);
      assertNoSetCookieHeader(res.headers);
    });
  });

  // =========================================================================
  // POST /api/v1/notifications/:id/read
  // =========================================================================

  describe('POST /api/v1/notifications/:id/read', () => {
    it('returns 401 without session cookie', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/notifications/${VALID_NOTIF_ID}/read`,
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      assertNo401DataLeakage(body);
      assertNoSetCookieHeader(res.headers);
    });

    it('returns 401 with expired/revoked session cookie', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/notifications/${VALID_NOTIF_ID}/read`,
        headers: { cookie: `session=${EXPIRED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      assertNo401DataLeakage(body);
      assertNoSetCookieHeader(res.headers);
    });
  });

  // =========================================================================
  // POST /api/v1/notifications/read-all
  // =========================================================================

  describe('POST /api/v1/notifications/read-all', () => {
    it('returns 401 without session cookie', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/notifications/read-all',
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      assertNo401DataLeakage(body);
      assertNoSetCookieHeader(res.headers);
    });

    it('returns 401 with expired/revoked session cookie', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/notifications/read-all',
        headers: { cookie: `session=${EXPIRED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      assertNo401DataLeakage(body);
      assertNoSetCookieHeader(res.headers);
    });
  });

  // =========================================================================
  // POST /api/v1/notifications/:id/dismiss
  // =========================================================================

  describe('POST /api/v1/notifications/:id/dismiss', () => {
    it('returns 401 without session cookie', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/notifications/${VALID_NOTIF_ID}/dismiss`,
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      assertNo401DataLeakage(body);
      assertNoSetCookieHeader(res.headers);
    });

    it('returns 401 with expired/revoked session cookie', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/notifications/${VALID_NOTIF_ID}/dismiss`,
        headers: { cookie: `session=${EXPIRED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      assertNo401DataLeakage(body);
      assertNoSetCookieHeader(res.headers);
    });
  });

  // =========================================================================
  // GET /api/v1/notification-preferences
  // =========================================================================

  describe('GET /api/v1/notification-preferences', () => {
    it('returns 401 without session cookie', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/notification-preferences',
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      assertNo401DataLeakage(body);
      assertNoSetCookieHeader(res.headers);
    });

    it('returns 401 with expired/revoked session cookie', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/notification-preferences',
        headers: { cookie: `session=${EXPIRED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      assertNo401DataLeakage(body);
      assertNoSetCookieHeader(res.headers);
    });
  });

  // =========================================================================
  // PUT /api/v1/notification-preferences/:category
  // =========================================================================

  describe('PUT /api/v1/notification-preferences/:category', () => {
    it('returns 401 without session cookie', async () => {
      const res = await app.inject({
        method: 'PUT',
        url: '/api/v1/notification-preferences/CLAIM_LIFECYCLE',
        headers: { 'content-type': 'application/json' },
        payload: JSON.stringify({ email_enabled: false }),
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      assertNo401DataLeakage(body);
      assertNoSetCookieHeader(res.headers);
    });
  });

  // =========================================================================
  // PUT /api/v1/notification-preferences/quiet-hours
  // =========================================================================

  describe('PUT /api/v1/notification-preferences/quiet-hours', () => {
    it('returns 401 without session cookie', async () => {
      const res = await app.inject({
        method: 'PUT',
        url: '/api/v1/notification-preferences/quiet-hours',
        headers: { 'content-type': 'application/json' },
        payload: JSON.stringify({
          quiet_hours_start: '22:00',
          quiet_hours_end: '07:00',
        }),
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      assertNo401DataLeakage(body);
      assertNoSetCookieHeader(res.headers);
    });
  });

  // =========================================================================
  // Verify authenticated requests succeed (sanity check)
  // =========================================================================

  describe('Authenticated requests succeed (sanity check)', () => {
    it('GET /api/v1/notifications with valid session returns 200', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/notifications',
        headers: { cookie: `session=${SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
    });

    it('GET /api/v1/notifications/unread-count with valid session returns 200', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/notifications/unread-count',
        headers: { cookie: `session=${SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
    });
  });
});

// ===========================================================================
// Test Suite: Authentication Enforcement on Internal API Key Routes
// ===========================================================================

describe('Notification Authentication Enforcement (Internal Routes)', () => {
  let internalApp: FastifyInstance;

  const validEmitPayload = {
    event_type: 'CLAIM_VALIDATED',
    physician_id: PHYSICIAN_ID,
    metadata: { claim_id: 'test-claim-123' },
  };

  const validBatchPayload = {
    events: [
      {
        event_type: 'CLAIM_VALIDATED',
        physician_id: PHYSICIAN_ID,
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

  // =========================================================================
  // POST /api/v1/internal/notifications/emit
  // =========================================================================

  describe('POST /api/v1/internal/notifications/emit', () => {
    it('returns 401 without X-Internal-API-Key header', async () => {
      const res = await internalApp.inject({
        method: 'POST',
        url: '/api/v1/internal/notifications/emit',
        headers: { 'content-type': 'application/json' },
        payload: JSON.stringify(validEmitPayload),
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      assertNo401DataLeakage(body);
    });

    it('returns 401 with wrong API key', async () => {
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
      assertNo401DataLeakage(body);
    });

    it('returns 401 with empty API key', async () => {
      const res = await internalApp.inject({
        method: 'POST',
        url: '/api/v1/internal/notifications/emit',
        headers: {
          'x-internal-api-key': '',
          'content-type': 'application/json',
        },
        payload: JSON.stringify(validEmitPayload),
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      assertNo401DataLeakage(body);
    });

    it('does not leak notification data in 401 response', async () => {
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
      expect(JSON.stringify(body)).not.toContain('notification_id');
    });
  });

  // =========================================================================
  // POST /api/v1/internal/notifications/emit-batch
  // =========================================================================

  describe('POST /api/v1/internal/notifications/emit-batch', () => {
    it('returns 401 without X-Internal-API-Key header', async () => {
      const res = await internalApp.inject({
        method: 'POST',
        url: '/api/v1/internal/notifications/emit-batch',
        headers: { 'content-type': 'application/json' },
        payload: JSON.stringify(validBatchPayload),
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      assertNo401DataLeakage(body);
    });

    it('returns 401 with wrong API key', async () => {
      const res = await internalApp.inject({
        method: 'POST',
        url: '/api/v1/internal/notifications/emit-batch',
        headers: {
          'x-internal-api-key': 'wrong-key-completely-invalid',
          'content-type': 'application/json',
        },
        payload: JSON.stringify(validBatchPayload),
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      assertNo401DataLeakage(body);
    });

    it('does not leak notification data in 401 response', async () => {
      const res = await internalApp.inject({
        method: 'POST',
        url: '/api/v1/internal/notifications/emit-batch',
        headers: { 'content-type': 'application/json' },
        payload: JSON.stringify(validBatchPayload),
      });

      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
      expect(body.created_count).toBeUndefined();
      expect(JSON.stringify(body)).not.toContain('created_count');
    });
  });

  // =========================================================================
  // Sanity check: valid API key works
  // =========================================================================

  describe('Valid API key succeeds (sanity check)', () => {
    it('POST /api/v1/internal/notifications/emit with valid key returns 200', async () => {
      const res = await internalApp.inject({
        method: 'POST',
        url: '/api/v1/internal/notifications/emit',
        headers: {
          'x-internal-api-key': VALID_API_KEY,
          'content-type': 'application/json',
        },
        payload: JSON.stringify(validEmitPayload),
      });

      expect(res.statusCode).toBe(200);
    });
  });
});

// ===========================================================================
// Test Suite: WebSocket Authentication Enforcement
// ===========================================================================

describe('Notification Authentication Enforcement (WebSocket)', () => {
  let wsApp: FastifyInstance;

  beforeAll(async () => {
    wsApp = await buildWsApp();
  });

  afterAll(async () => {
    await wsApp.close();
  });

  describe('WS /ws/notifications', () => {
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

    it('rejects connection with expired/revoked session token', async () => {
      const ws = await wsApp.injectWS(
        `/ws/notifications?token=${EXPIRED_SESSION_TOKEN}`,
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

    it('rejects connection with tampered session token', async () => {
      const ws = await wsApp.injectWS(
        `/ws/notifications?token=${TAMPERED_SESSION_TOKEN}`,
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

    it('does not send notification data before auth completes', async () => {
      const ws = await wsApp.injectWS('/ws/notifications');

      const messages: string[] = [];
      ws.on('message', (data: Buffer) => {
        messages.push(data.toString());
      });

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
      // No notification data should have been sent
      expect(messages.length).toBe(0);
    });

    it('accepts connection with valid session token via query param', async () => {
      const ws = await wsApp.injectWS(
        `/ws/notifications?token=${SESSION_TOKEN}`,
      );

      expect(ws).toBeDefined();
      await new Promise((r) => setTimeout(r, 50));
      ws.terminate();
    });

    it('accepts connection with valid session token via cookie', async () => {
      const ws = await wsApp.injectWS('/ws/notifications', {
        headers: { cookie: `session=${SESSION_TOKEN}` },
      });

      expect(ws).toBeDefined();
      await new Promise((r) => setTimeout(r, 50));
      ws.terminate();
    });
  });
});
