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
import { EVENT_CATALOGUE, EventCategory } from '@meritum/shared/constants/notification.constants.js';

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
const DELEGATE_USER_ID = '22222222-0000-0000-0000-000000000002';

const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_SESSION_ID = '33333333-0000-0000-0000-000000000001';

const DELEGATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_SESSION_TOKEN_HASH = hashToken(DELEGATE_SESSION_TOKEN);
const DELEGATE_SESSION_ID = '33333333-0000-0000-0000-000000000002';

// ---------------------------------------------------------------------------
// Mock Preference Store
// ---------------------------------------------------------------------------

interface MockPreference {
  preferenceId: string;
  providerId: string;
  eventCategory: string;
  inAppEnabled: boolean;
  emailEnabled: boolean;
  digestMode: string;
  quietHoursStart: string | null;
  quietHoursEnd: string | null;
  updatedAt: Date;
}

let preferenceStore: MockPreference[];
let nextPrefId = 1;
let auditEntries: Array<Record<string, unknown>>;

function newPrefId() {
  return `bbbbbbbb-0000-0000-0000-${String(nextPrefId++).padStart(12, '0')}`;
}

// ---------------------------------------------------------------------------
// Mock Repositories
// ---------------------------------------------------------------------------

function createMockNotificationRepo(): NotificationRepository {
  return {
    // Notification stubs (not used in preference tests)
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

    // Preference methods — real implementations backed by in-memory store
    findPreferencesByProvider: vi.fn(async (providerId: string) => {
      return preferenceStore.filter((p) => p.providerId === providerId);
    }),

    findPreference: vi.fn(async (providerId: string, eventCategory: string) => {
      return preferenceStore.find(
        (p) => p.providerId === providerId && p.eventCategory === eventCategory,
      );
    }),

    upsertPreference: vi.fn(
      async (
        providerId: string,
        eventCategory: string,
        data: Partial<MockPreference>,
      ) => {
        const existing = preferenceStore.find(
          (p) => p.providerId === providerId && p.eventCategory === eventCategory,
        );

        if (existing) {
          if (data.inAppEnabled !== undefined) existing.inAppEnabled = data.inAppEnabled;
          if (data.emailEnabled !== undefined) existing.emailEnabled = data.emailEnabled;
          if (data.digestMode !== undefined) existing.digestMode = data.digestMode;
          existing.updatedAt = new Date();
          return existing;
        }

        const newPref: MockPreference = {
          preferenceId: newPrefId(),
          providerId,
          eventCategory,
          inAppEnabled: data.inAppEnabled ?? true,
          emailEnabled: data.emailEnabled ?? true,
          digestMode: data.digestMode ?? 'IMMEDIATE',
          quietHoursStart: null,
          quietHoursEnd: null,
          updatedAt: new Date(),
        };
        preferenceStore.push(newPref);
        return newPref;
      },
    ),

    createDefaultPreferences: vi.fn(async () => []),

    updateQuietHours: vi.fn(
      async (providerId: string, start: string | null, end: string | null) => {
        let count = 0;
        for (const pref of preferenceStore) {
          if (pref.providerId === providerId) {
            pref.quietHoursStart = start;
            pref.quietHoursEnd = end;
            pref.updatedAt = new Date();
            count++;
          }
        }
        return count;
      },
    ),
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

describe('Notification Preferences Integration Tests', () => {
  beforeAll(async () => {
    preferenceStore = [];
    auditEntries = [];
    nextPrefId = 1;
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    preferenceStore = [];
    auditEntries = [];
    nextPrefId = 1;
  });

  // =========================================================================
  // GET /api/v1/notification-preferences
  // =========================================================================

  describe('GET /api/v1/notification-preferences', () => {
    it('returns all preferences for authenticated physician', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/notification-preferences',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.preferences).toBeDefined();
      expect(Array.isArray(body.data.preferences)).toBe(true);
      expect(body.data.preferences.length).toBeGreaterThan(0);
      expect(body.data.quiet_hours).toBeDefined();
    });

    it('includes defaults for unconfigured categories', async () => {
      // No preferences stored yet — should return all EVENT_CATALOGUE categories with defaults
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/notification-preferences',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);

      // Collect expected categories from EVENT_CATALOGUE
      const expectedCategories = new Set<string>();
      for (const [, entry] of Object.entries(EVENT_CATALOGUE)) {
        expectedCategories.add(entry.category);
      }

      const returnedCategories = new Set(
        body.data.preferences.map((p: any) => p.event_category),
      );

      for (const cat of expectedCategories) {
        expect(returnedCategories.has(cat)).toBe(true);
      }
    });

    it('merges stored preferences with defaults', async () => {
      // Store a preference for one category
      preferenceStore.push({
        preferenceId: newPrefId(),
        providerId: PHYSICIAN_USER_ID,
        eventCategory: EventCategory.CLAIM_LIFECYCLE,
        inAppEnabled: true,
        emailEnabled: false,
        digestMode: 'DAILY_DIGEST',
        quietHoursStart: null,
        quietHoursEnd: null,
        updatedAt: new Date(),
      });

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/notification-preferences',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);

      const claimPref = body.data.preferences.find(
        (p: any) => p.event_category === EventCategory.CLAIM_LIFECYCLE,
      );
      expect(claimPref).toBeDefined();
      expect(claimPref.email_enabled).toBe(false);
      expect(claimPref.digest_mode).toBe('DAILY_DIGEST');
    });

    it('returns quiet hours from stored preferences', async () => {
      preferenceStore.push({
        preferenceId: newPrefId(),
        providerId: PHYSICIAN_USER_ID,
        eventCategory: EventCategory.CLAIM_LIFECYCLE,
        inAppEnabled: true,
        emailEnabled: true,
        digestMode: 'IMMEDIATE',
        quietHoursStart: '22:00',
        quietHoursEnd: '07:00',
        updatedAt: new Date(),
      });

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/notification-preferences',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.quiet_hours.start).toBe('22:00');
      expect(body.data.quiet_hours.end).toBe('07:00');
    });

    it('returns 401 without session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/notification-preferences',
      });

      expect(res.statusCode).toBe(401);
    });

    it('returns 403 for delegate', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/notification-preferences',
        headers: { cookie: `session=${DELEGATE_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(403);
    });
  });

  // =========================================================================
  // PUT /api/v1/notification-preferences/:category
  // =========================================================================

  describe('PUT /api/v1/notification-preferences/:category', () => {
    it('updates email_enabled for a category', async () => {
      const res = await app.inject({
        method: 'PUT',
        url: `/api/v1/notification-preferences/${EventCategory.CLAIM_LIFECYCLE}`,
        headers: {
          cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: JSON.stringify({ email_enabled: false }),
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.email_enabled).toBe(false);
      expect(body.data.event_category).toBe(EventCategory.CLAIM_LIFECYCLE);
    });

    it('updates digest_mode for a category', async () => {
      const res = await app.inject({
        method: 'PUT',
        url: `/api/v1/notification-preferences/${EventCategory.ANALYTICS}`,
        headers: {
          cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: JSON.stringify({ digest_mode: 'DAILY_DIGEST' }),
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.digest_mode).toBe('DAILY_DIGEST');
    });

    it('rejects disabling in_app for URGENT event category', async () => {
      // CLAIM_LIFECYCLE has URGENT events (DEADLINE_1_DAY, BATCH_ERROR)
      const res = await app.inject({
        method: 'PUT',
        url: `/api/v1/notification-preferences/${EventCategory.CLAIM_LIFECYCLE}`,
        headers: {
          cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: JSON.stringify({ in_app_enabled: false }),
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.error.message).toContain('Cannot disable in-app notifications for urgent events');
    });

    it('rejects unknown category', async () => {
      const res = await app.inject({
        method: 'PUT',
        url: '/api/v1/notification-preferences/UNKNOWN_CATEGORY',
        headers: {
          cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: JSON.stringify({ email_enabled: false }),
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.error.message).toContain('Unknown event category');
    });

    it('creates audit entry with old and new values', async () => {
      // First, store an existing preference
      preferenceStore.push({
        preferenceId: newPrefId(),
        providerId: PHYSICIAN_USER_ID,
        eventCategory: EventCategory.ANALYTICS,
        inAppEnabled: true,
        emailEnabled: true,
        digestMode: 'IMMEDIATE',
        quietHoursStart: null,
        quietHoursEnd: null,
        updatedAt: new Date(),
      });

      await app.inject({
        method: 'PUT',
        url: `/api/v1/notification-preferences/${EventCategory.ANALYTICS}`,
        headers: {
          cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: JSON.stringify({ email_enabled: false }),
      });

      const auditEntry = auditEntries.find(
        (e) => e.action === 'notification.preference_updated',
      );
      expect(auditEntry).toBeDefined();
      expect(auditEntry!.userId).toBe(PHYSICIAN_USER_ID);
      expect((auditEntry!.detail as any).event_category).toBe(EventCategory.ANALYTICS);
      expect((auditEntry!.detail as any).old_values).not.toBeNull();
      expect((auditEntry!.detail as any).new_values).toBeDefined();
    });

    it('returns 401 without session', async () => {
      const res = await app.inject({
        method: 'PUT',
        url: `/api/v1/notification-preferences/${EventCategory.CLAIM_LIFECYCLE}`,
        headers: { 'content-type': 'application/json' },
        payload: JSON.stringify({ email_enabled: false }),
      });

      expect(res.statusCode).toBe(401);
    });

    it('returns 403 for delegate', async () => {
      const res = await app.inject({
        method: 'PUT',
        url: `/api/v1/notification-preferences/${EventCategory.CLAIM_LIFECYCLE}`,
        headers: {
          cookie: `session=${DELEGATE_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: JSON.stringify({ email_enabled: false }),
      });

      expect(res.statusCode).toBe(403);
    });

    it('allows disabling in_app for non-urgent category', async () => {
      // INTELLIGENCE_ENGINE has no URGENT priority events
      // Check: AI_SUGGESTION_READY is LOW, AI_HIGH_VALUE_SUGGESTION is HIGH, SOMB_CHANGE_IMPACT is MEDIUM
      const res = await app.inject({
        method: 'PUT',
        url: `/api/v1/notification-preferences/${EventCategory.INTELLIGENCE_ENGINE}`,
        headers: {
          cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: JSON.stringify({ in_app_enabled: false }),
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.in_app_enabled).toBe(false);
    });
  });

  // =========================================================================
  // PUT /api/v1/notification-preferences/quiet-hours
  // =========================================================================

  describe('PUT /api/v1/notification-preferences/quiet-hours', () => {
    it('sets start and end quiet hours', async () => {
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
      const body = JSON.parse(res.body);
      expect(body.data.success).toBe(true);
      expect(body.data.quiet_hours.start).toBe('22:00');
      expect(body.data.quiet_hours.end).toBe('07:00');
    });

    it('with null values clears quiet hours', async () => {
      const res = await app.inject({
        method: 'PUT',
        url: '/api/v1/notification-preferences/quiet-hours',
        headers: {
          cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: JSON.stringify({
          quiet_hours_start: null,
          quiet_hours_end: null,
        }),
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.success).toBe(true);
      expect(body.data.quiet_hours.start).toBeNull();
      expect(body.data.quiet_hours.end).toBeNull();
    });

    it('rejects start without end', async () => {
      const res = await app.inject({
        method: 'PUT',
        url: '/api/v1/notification-preferences/quiet-hours',
        headers: {
          cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: JSON.stringify({
          quiet_hours_start: '22:00',
          quiet_hours_end: null,
        }),
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects end without start', async () => {
      const res = await app.inject({
        method: 'PUT',
        url: '/api/v1/notification-preferences/quiet-hours',
        headers: {
          cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: JSON.stringify({
          quiet_hours_start: null,
          quiet_hours_end: '07:00',
        }),
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects invalid time format', async () => {
      const res = await app.inject({
        method: 'PUT',
        url: '/api/v1/notification-preferences/quiet-hours',
        headers: {
          cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: JSON.stringify({
          quiet_hours_start: '10PM',
          quiet_hours_end: '7AM',
        }),
      });

      expect(res.statusCode).toBe(400);
    });

    it('creates audit entry with old and new values', async () => {
      await app.inject({
        method: 'PUT',
        url: '/api/v1/notification-preferences/quiet-hours',
        headers: {
          cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: JSON.stringify({
          quiet_hours_start: '23:00',
          quiet_hours_end: '06:00',
        }),
      });

      const auditEntry = auditEntries.find(
        (e) => e.action === 'notification.quiet_hours_updated',
      );
      expect(auditEntry).toBeDefined();
      expect(auditEntry!.userId).toBe(PHYSICIAN_USER_ID);
      expect((auditEntry!.detail as any).new_values).toBeDefined();
      expect((auditEntry!.detail as any).new_values.start).toBe('23:00');
      expect((auditEntry!.detail as any).new_values.end).toBe('06:00');
    });

    it('returns 401 without session', async () => {
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
    });

    it('returns 403 for delegate', async () => {
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
    });
  });
});
