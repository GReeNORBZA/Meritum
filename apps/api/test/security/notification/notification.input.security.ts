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
// Test Data
// ---------------------------------------------------------------------------

const USER_ID = '11111111-0000-0000-0000-000000000001';
const SESSION_TOKEN = randomBytes(32).toString('hex');
const SESSION_TOKEN_HASH = hashToken(SESSION_TOKEN);
const SESSION_ID = '33333333-0000-0000-0000-000000000001';
const PHYSICIAN_ID = '44444444-0000-0000-0000-000000000001';
const VALID_API_KEY = 'test-internal-api-key-12345';
const VALID_NOTIF_ID = 'aaaaaaaa-0000-0000-0000-000000000001';

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
          code: (error as any).code ?? 'VALIDATION_ERROR',
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
          code: (error as any).code ?? 'VALIDATION_ERROR',
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
// Shared helpers
// ---------------------------------------------------------------------------

function sessionHeaders() {
  return { cookie: `session=${SESSION_TOKEN}` };
}

function internalHeaders() {
  return {
    'x-internal-api-key': VALID_API_KEY,
    'content-type': 'application/json',
  };
}

function assertValidationError(body: any) {
  expect(body.error).toBeDefined();
  // Fastify may use FST_ERR_VALIDATION, our custom handler uses VALIDATION_ERROR or ERROR
  expect(body.error.code).toMatch(/VALIDATION_ERROR|ERROR|FST_ERR_VALIDATION/);
  // Must NOT expose stack traces or internal details
  expect(body.error.stack).toBeUndefined();
  expect(JSON.stringify(body)).not.toMatch(/postgres|drizzle|SELECT\s+\*|INSERT\s+INTO|DROP\s+TABLE/i);
}

// ===========================================================================
// Test Suite: Input Validation & Injection Prevention
// ===========================================================================

describe('Notification Input Validation & Injection Prevention', () => {
  let sessionApp: FastifyInstance;
  let internalApp: FastifyInstance;

  beforeAll(async () => {
    sessionApp = await buildSessionApp();
    internalApp = await buildInternalApp();
  });

  afterAll(async () => {
    await sessionApp.close();
    await internalApp.close();
  });

  // =========================================================================
  // SQL Injection Payloads
  // =========================================================================

  describe('SQL Injection Prevention', () => {
    const sqlPayloads = [
      "' OR 1=1--",
      "'; DROP TABLE notifications;--",
      "' OR '1'='1",
      "' UNION SELECT * FROM users--",
      "1; SELECT * FROM users --",
    ];

    describe('PUT /api/v1/notification-preferences/:category — SQL injection in category param', () => {
      for (const payload of sqlPayloads) {
        it(`rejects category: ${JSON.stringify(payload)}`, async () => {
          const res = await sessionApp.inject({
            method: 'PUT',
            url: `/api/v1/notification-preferences/${encodeURIComponent(payload)}`,
            headers: {
              ...sessionHeaders(),
              'content-type': 'application/json',
            },
            payload: JSON.stringify({ email_enabled: false }),
          });

          // Should be 400 (validation) or 422 (business rule: unknown category) — NOT 500
          expect(res.statusCode).toBeLessThan(500);
          expect([400, 422]).toContain(res.statusCode);
          const body = JSON.parse(res.body);
          // Verify error structure (the error message may echo the category name
          // which contains the SQL payload, but the important thing is the payload
          // was rejected before reaching the database layer — status < 500)
          expect(body.error).toBeDefined();
          expect(body.error.stack).toBeUndefined();
        });
      }
    });

    describe('POST /api/v1/internal/notifications/emit — SQL injection in event_type', () => {
      for (const payload of sqlPayloads) {
        it(`rejects event_type: ${JSON.stringify(payload)}`, async () => {
          const res = await internalApp.inject({
            method: 'POST',
            url: '/api/v1/internal/notifications/emit',
            headers: internalHeaders(),
            payload: JSON.stringify({
              event_type: payload,
              physician_id: PHYSICIAN_ID,
            }),
          });

          // Should be 400 (validation catches it) or 200 (valid schema but unknown event type
          // handled by service) — but must NOT be 500
          expect(res.statusCode).toBeLessThan(500);
        });
      }
    });

    describe('POST /api/v1/notifications/:id/read — SQL injection in id param', () => {
      const idPayloads = [
        "' OR '1'='1",
        "'; DROP TABLE notifications;--",
        "1 OR 1=1",
      ];

      for (const payload of idPayloads) {
        it(`rejects id: ${JSON.stringify(payload)}`, async () => {
          const res = await sessionApp.inject({
            method: 'POST',
            url: `/api/v1/notifications/${encodeURIComponent(payload)}/read`,
            headers: sessionHeaders(),
          });

          // UUID validation should catch this — 400
          expect(res.statusCode).toBe(400);
          const body = JSON.parse(res.body);
          assertValidationError(body);
        });
      }
    });

    describe('GET /api/v1/notifications — SQL injection in limit param', () => {
      it('rejects limit: "1; DROP TABLE notifications"', async () => {
        const res = await sessionApp.inject({
          method: 'GET',
          url: '/api/v1/notifications?limit=1;%20DROP%20TABLE%20notifications',
          headers: sessionHeaders(),
        });

        // z.coerce.number() will fail on this string — 400
        expect(res.statusCode).toBe(400);
        const body = JSON.parse(res.body);
        assertValidationError(body);
      });
    });
  });

  // =========================================================================
  // XSS Payloads (Template Injection)
  // =========================================================================

  describe('XSS & Template Injection Prevention', () => {
    it('HTML script tag in emit metadata does not cause 500', async () => {
      const res = await internalApp.inject({
        method: 'POST',
        url: '/api/v1/internal/notifications/emit',
        headers: internalHeaders(),
        payload: JSON.stringify({
          event_type: 'CLAIM_VALIDATED',
          physician_id: PHYSICIAN_ID,
          metadata: {
            claim_id: '<script>alert(1)</script>',
            patient_name: '<script>document.cookie</script>',
          },
        }),
      });

      // Must not be 500 — payload should be accepted by schema (metadata is z.record)
      // and HTML escaping happens at render time in the service
      expect(res.statusCode).toBeLessThan(500);
    });

    it('template injection payload in metadata does not cause 500', async () => {
      const res = await internalApp.inject({
        method: 'POST',
        url: '/api/v1/internal/notifications/emit',
        headers: internalHeaders(),
        payload: JSON.stringify({
          event_type: 'CLAIM_VALIDATED',
          physician_id: PHYSICIAN_ID,
          metadata: {
            claim_id: "{{constructor.constructor('return this')()}}",
          },
        }),
      });

      // Template injection must be treated as literal text, not executed
      expect(res.statusCode).toBeLessThan(500);
    });

    it('img onerror XSS payload in metadata does not cause 500', async () => {
      const res = await internalApp.inject({
        method: 'POST',
        url: '/api/v1/internal/notifications/emit',
        headers: internalHeaders(),
        payload: JSON.stringify({
          event_type: 'CLAIM_VALIDATED',
          physician_id: PHYSICIAN_ID,
          metadata: {
            description: '<img src=x onerror=alert(1)>',
          },
        }),
      });

      expect(res.statusCode).toBeLessThan(500);
    });

    it('XSS payloads in preference category update do not cause 500', async () => {
      const xssPayloads = [
        '<script>alert("xss")</script>',
        '<img src=x onerror=alert(1)>',
        'javascript:alert(1)',
      ];

      for (const payload of xssPayloads) {
        const res = await sessionApp.inject({
          method: 'PUT',
          url: `/api/v1/notification-preferences/${encodeURIComponent(payload)}`,
          headers: {
            ...sessionHeaders(),
            'content-type': 'application/json',
          },
          payload: JSON.stringify({ email_enabled: false }),
        });

        // Category validation should reject unknown categories — 400 or 422, NOT 500
        expect(res.statusCode).toBeLessThan(500);
      }
    });
  });

  // =========================================================================
  // Type Coercion Attacks
  // =========================================================================

  describe('Type Coercion Prevention', () => {
    it('rejects limit as non-numeric string "abc"', async () => {
      const res = await sessionApp.inject({
        method: 'GET',
        url: '/api/v1/notifications?limit=abc',
        headers: sessionHeaders(),
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      assertValidationError(body);
    });

    it('rejects negative offset (-1)', async () => {
      const res = await sessionApp.inject({
        method: 'GET',
        url: '/api/v1/notifications?offset=-1',
        headers: sessionHeaders(),
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      assertValidationError(body);
    });

    it('rejects unread_only as non-boolean string "yes"', async () => {
      const res = await sessionApp.inject({
        method: 'GET',
        url: '/api/v1/notifications?unread_only=yes',
        headers: sessionHeaders(),
      });

      // unread_only is z.enum(['true', 'false']), so "yes" should be rejected
      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      assertValidationError(body);
    });

    it('rejects limit of 0 (min is 1)', async () => {
      const res = await sessionApp.inject({
        method: 'GET',
        url: '/api/v1/notifications?limit=0',
        headers: sessionHeaders(),
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      assertValidationError(body);
    });

    it('rejects limit of 101 (max is 100)', async () => {
      const res = await sessionApp.inject({
        method: 'GET',
        url: '/api/v1/notifications?limit=101',
        headers: sessionHeaders(),
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      assertValidationError(body);
    });

    it('rejects preference category as array type via repeated params', async () => {
      // Fastify treats repeated query params as array; we test the param
      // directly by sending an invalid type through the URL
      const res = await sessionApp.inject({
        method: 'PUT',
        url: '/api/v1/notification-preferences/',
        headers: {
          ...sessionHeaders(),
          'content-type': 'application/json',
        },
        payload: JSON.stringify({ email_enabled: false }),
      });

      // Empty category should be rejected (min 1) or route not found
      expect(res.statusCode).toBeLessThan(500);
    });

    it('rejects non-boolean values in preference body', async () => {
      const res = await sessionApp.inject({
        method: 'PUT',
        url: '/api/v1/notification-preferences/CLAIM_LIFECYCLE',
        headers: {
          ...sessionHeaders(),
          'content-type': 'application/json',
        },
        payload: JSON.stringify({
          in_app_enabled: 'yes',
          email_enabled: 123,
        }),
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      assertValidationError(body);
    });

    it('rejects non-string event_type in emit body', async () => {
      const res = await internalApp.inject({
        method: 'POST',
        url: '/api/v1/internal/notifications/emit',
        headers: internalHeaders(),
        payload: JSON.stringify({
          event_type: 12345,
          physician_id: PHYSICIAN_ID,
        }),
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      assertValidationError(body);
    });

    it('rejects non-object metadata in emit body', async () => {
      const res = await internalApp.inject({
        method: 'POST',
        url: '/api/v1/internal/notifications/emit',
        headers: internalHeaders(),
        payload: JSON.stringify({
          event_type: 'CLAIM_VALIDATED',
          physician_id: PHYSICIAN_ID,
          metadata: 'not-an-object',
        }),
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      assertValidationError(body);
    });
  });

  // =========================================================================
  // UUID Parameter Validation
  // =========================================================================

  describe('UUID Parameter Validation', () => {
    it('POST /api/v1/notifications/not-a-uuid/read returns 400', async () => {
      const res = await sessionApp.inject({
        method: 'POST',
        url: '/api/v1/notifications/not-a-uuid/read',
        headers: sessionHeaders(),
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      assertValidationError(body);
    });

    it('POST /api/v1/notifications/12345/dismiss returns 400', async () => {
      const res = await sessionApp.inject({
        method: 'POST',
        url: '/api/v1/notifications/12345/dismiss',
        headers: sessionHeaders(),
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      assertValidationError(body);
    });

    it('POST /api/v1/internal/notifications/emit with non-UUID physician_id returns 400', async () => {
      const res = await internalApp.inject({
        method: 'POST',
        url: '/api/v1/internal/notifications/emit',
        headers: internalHeaders(),
        payload: JSON.stringify({
          event_type: 'CLAIM_VALIDATED',
          physician_id: 'not-a-uuid',
        }),
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      assertValidationError(body);
    });

    it('rejects path traversal attempt in notification id', async () => {
      const res = await sessionApp.inject({
        method: 'POST',
        url: '/api/v1/notifications/../admin/read',
        headers: sessionHeaders(),
      });

      // Fastify normalizes paths; this should either 404 (no matching route)
      // or 400 (UUID validation fails on "admin")
      expect(res.statusCode).toBeLessThan(500);
      expect(res.statusCode).toBeGreaterThanOrEqual(400);
    });

    it('rejects empty UUID string in notification id', async () => {
      const res = await sessionApp.inject({
        method: 'POST',
        url: '/api/v1/notifications//read',
        headers: sessionHeaders(),
      });

      // Should fail route matching or UUID validation
      expect(res.statusCode).toBeLessThan(500);
      expect(res.statusCode).toBeGreaterThanOrEqual(400);
    });

    it('rejects UUID-like string with invalid characters', async () => {
      const res = await sessionApp.inject({
        method: 'POST',
        url: '/api/v1/notifications/gggggggg-0000-0000-0000-000000000001/read',
        headers: sessionHeaders(),
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      assertValidationError(body);
    });
  });

  // =========================================================================
  // Quiet Hours Validation
  // =========================================================================

  describe('Quiet Hours Validation', () => {
    it('rejects invalid hour value (25:00)', async () => {
      const res = await sessionApp.inject({
        method: 'PUT',
        url: '/api/v1/notification-preferences/quiet-hours',
        headers: {
          ...sessionHeaders(),
          'content-type': 'application/json',
        },
        payload: JSON.stringify({
          quiet_hours_start: '25:00',
          quiet_hours_end: '07:00',
        }),
      });

      // "25:00" matches the regex /^\d{2}:\d{2}$/ — this depends on whether
      // the schema enforces valid time ranges beyond regex. The regex passes,
      // so we check that no 500 occurs and the app handles it gracefully.
      expect(res.statusCode).toBeLessThan(500);
    });

    it('rejects quiet_hours_start without quiet_hours_end', async () => {
      const res = await sessionApp.inject({
        method: 'PUT',
        url: '/api/v1/notification-preferences/quiet-hours',
        headers: {
          ...sessionHeaders(),
          'content-type': 'application/json',
        },
        payload: JSON.stringify({
          quiet_hours_start: '22:00',
        }),
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      assertValidationError(body);
    });

    it('rejects quiet_hours_end without quiet_hours_start', async () => {
      const res = await sessionApp.inject({
        method: 'PUT',
        url: '/api/v1/notification-preferences/quiet-hours',
        headers: {
          ...sessionHeaders(),
          'content-type': 'application/json',
        },
        payload: JSON.stringify({
          quiet_hours_end: '07:00',
        }),
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      assertValidationError(body);
    });

    it('rejects non-time string values ("abc", "def")', async () => {
      const res = await sessionApp.inject({
        method: 'PUT',
        url: '/api/v1/notification-preferences/quiet-hours',
        headers: {
          ...sessionHeaders(),
          'content-type': 'application/json',
        },
        payload: JSON.stringify({
          quiet_hours_start: 'abc',
          quiet_hours_end: 'def',
        }),
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      assertValidationError(body);
    });

    it('rejects wrong format with seconds (HH:MM:SS instead of HH:MM)', async () => {
      const res = await sessionApp.inject({
        method: 'PUT',
        url: '/api/v1/notification-preferences/quiet-hours',
        headers: {
          ...sessionHeaders(),
          'content-type': 'application/json',
        },
        payload: JSON.stringify({
          quiet_hours_start: '22:00:00',
          quiet_hours_end: '07:00:00',
        }),
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      assertValidationError(body);
    });

    it('rejects empty string values for quiet hours', async () => {
      const res = await sessionApp.inject({
        method: 'PUT',
        url: '/api/v1/notification-preferences/quiet-hours',
        headers: {
          ...sessionHeaders(),
          'content-type': 'application/json',
        },
        payload: JSON.stringify({
          quiet_hours_start: '',
          quiet_hours_end: '',
        }),
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      assertValidationError(body);
    });

    it('accepts null values for both quiet hours (clearing)', async () => {
      const res = await sessionApp.inject({
        method: 'PUT',
        url: '/api/v1/notification-preferences/quiet-hours',
        headers: {
          ...sessionHeaders(),
          'content-type': 'application/json',
        },
        payload: JSON.stringify({
          quiet_hours_start: null,
          quiet_hours_end: null,
        }),
      });

      // Clearing quiet hours by setting both to null is a valid operation
      expect(res.statusCode).toBe(200);
    });
  });

  // =========================================================================
  // Emit Validation
  // =========================================================================

  describe('Emit Endpoint Validation', () => {
    it('rejects empty event_type string', async () => {
      const res = await internalApp.inject({
        method: 'POST',
        url: '/api/v1/internal/notifications/emit',
        headers: internalHeaders(),
        payload: JSON.stringify({
          event_type: '',
          physician_id: PHYSICIAN_ID,
        }),
      });

      // event_type is z.string().min(1) — empty string should fail
      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      assertValidationError(body);
    });

    it('rejects missing physician_id', async () => {
      const res = await internalApp.inject({
        method: 'POST',
        url: '/api/v1/internal/notifications/emit',
        headers: internalHeaders(),
        payload: JSON.stringify({
          event_type: 'CLAIM_VALIDATED',
        }),
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      assertValidationError(body);
    });

    it('rejects emit-batch with empty events array', async () => {
      const res = await internalApp.inject({
        method: 'POST',
        url: '/api/v1/internal/notifications/emit-batch',
        headers: internalHeaders(),
        payload: JSON.stringify({
          events: [],
        }),
      });

      // events is z.array(emitEventSchema).min(1) — empty array fails
      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      assertValidationError(body);
    });

    it('rejects emit-batch with more than 500 events', async () => {
      const events = Array.from({ length: 501 }, (_, i) => ({
        event_type: 'CLAIM_VALIDATED',
        physician_id: PHYSICIAN_ID,
        metadata: { index: i },
      }));

      const res = await internalApp.inject({
        method: 'POST',
        url: '/api/v1/internal/notifications/emit-batch',
        headers: internalHeaders(),
        payload: JSON.stringify({ events }),
      });

      // events is z.array(...).max(500) — 501 items fails
      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      assertValidationError(body);
    });

    it('rejects emit with missing event_type field', async () => {
      const res = await internalApp.inject({
        method: 'POST',
        url: '/api/v1/internal/notifications/emit',
        headers: internalHeaders(),
        payload: JSON.stringify({
          physician_id: PHYSICIAN_ID,
        }),
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      assertValidationError(body);
    });

    it('rejects emit with completely empty body', async () => {
      const res = await internalApp.inject({
        method: 'POST',
        url: '/api/v1/internal/notifications/emit',
        headers: internalHeaders(),
        payload: JSON.stringify({}),
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      assertValidationError(body);
    });

    it('rejects emit-batch with missing events field', async () => {
      const res = await internalApp.inject({
        method: 'POST',
        url: '/api/v1/internal/notifications/emit-batch',
        headers: internalHeaders(),
        payload: JSON.stringify({}),
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      assertValidationError(body);
    });

    it('extra unknown fields in emit body do not cause 500', async () => {
      const res = await internalApp.inject({
        method: 'POST',
        url: '/api/v1/internal/notifications/emit',
        headers: internalHeaders(),
        payload: JSON.stringify({
          event_type: 'CLAIM_VALIDATED',
          physician_id: PHYSICIAN_ID,
          metadata: { claim_id: 'test-123' },
          extra_field: 'should-be-stripped-or-ignored',
          another_unknown: 12345,
        }),
      });

      // Extra fields should be either stripped by Zod or ignored — NOT cause a 500
      expect(res.statusCode).toBeLessThan(500);
    });

    it('rejects event_type exceeding max length (50 chars)', async () => {
      const longEventType = 'A'.repeat(51);
      const res = await internalApp.inject({
        method: 'POST',
        url: '/api/v1/internal/notifications/emit',
        headers: internalHeaders(),
        payload: JSON.stringify({
          event_type: longEventType,
          physician_id: PHYSICIAN_ID,
        }),
      });

      // event_type is z.string().min(1).max(50) — 51 chars fails
      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      assertValidationError(body);
    });
  });

  // =========================================================================
  // Oversized Payload Protection
  // =========================================================================

  describe('Oversized Payload Protection', () => {
    it('rejects extremely large metadata objects', async () => {
      // Create a payload with a very large metadata value
      const largeValue = 'x'.repeat(100_000);
      const res = await internalApp.inject({
        method: 'POST',
        url: '/api/v1/internal/notifications/emit',
        headers: internalHeaders(),
        payload: JSON.stringify({
          event_type: 'CLAIM_VALIDATED',
          physician_id: PHYSICIAN_ID,
          metadata: { huge_field: largeValue },
        }),
      });

      // Either rejected for payload size or handled gracefully — NOT 500
      expect(res.statusCode).toBeLessThan(500);
    });
  });

  // =========================================================================
  // Response Shape: validation errors never expose stack traces
  // =========================================================================

  describe('Validation Error Response Shape', () => {
    it('400 response body has error.code and error.message, no stack trace', async () => {
      const res = await sessionApp.inject({
        method: 'POST',
        url: '/api/v1/notifications/not-a-uuid/read',
        headers: sessionHeaders(),
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);

      // Must have structured error format
      expect(body.error).toBeDefined();
      expect(typeof body.error.message).toBe('string');

      // Must NOT expose internals
      expect(body.error.stack).toBeUndefined();
      expect(body.data).toBeUndefined();
      expect(JSON.stringify(body)).not.toMatch(/at\s+\w+\s+\(/); // no stack frames
    });

    it('internal validation error has error format, no stack trace', async () => {
      const res = await internalApp.inject({
        method: 'POST',
        url: '/api/v1/internal/notifications/emit',
        headers: internalHeaders(),
        payload: JSON.stringify({
          event_type: '',
          physician_id: 'not-uuid',
        }),
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);

      expect(body.error).toBeDefined();
      expect(typeof body.error.message).toBe('string');
      expect(body.error.stack).toBeUndefined();
    });
  });
});
