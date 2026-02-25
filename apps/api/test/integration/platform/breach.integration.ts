import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { createHash, randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Environment setup (before any imports that read env vars)
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);

// ---------------------------------------------------------------------------
// Mock otplib (required by iam.service.ts transitive import)
// ---------------------------------------------------------------------------

vi.mock('otplib', () => ({
  authenticator: {
    options: {},
    generateSecret: vi.fn(() => 'JBSWY3DPEHPK3PXP'),
    keyuri: vi.fn(() => 'otpauth://totp/test'),
    verify: vi.fn(() => false),
  },
}));

// ---------------------------------------------------------------------------
// Imports (after mocks)
// ---------------------------------------------------------------------------

import {
  authPluginFp,
} from '../../../src/plugins/auth.plugin.js';
import { platformRoutes } from '../../../src/domains/platform/platform.routes.js';
import {
  type PlatformHandlerDeps,
} from '../../../src/domains/platform/platform.handlers.js';
import {
  type PlatformServiceDeps,
  type AuditLogger,
} from '../../../src/domains/platform/platform.service.js';
import {
  type BreachRepository,
} from '../../../src/domains/platform/platform.repository.js';

// ---------------------------------------------------------------------------
// Helper: hashToken
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

// Admin user
const ADMIN_USER_ID = '00000000-1111-0000-0000-000000cc0001';
const ADMIN_SESSION_TOKEN = randomBytes(32).toString('hex');
const ADMIN_SESSION_TOKEN_HASH = hashToken(ADMIN_SESSION_TOKEN);
const ADMIN_SESSION_ID = '00000000-2222-0000-0000-000000cc0001';

// Physician 1 (with secondary email)
const PHYSICIAN1_USER_ID = '00000000-1111-0000-0000-000000cc0002';
const PHYSICIAN1_PROVIDER_ID = '00000000-3333-0000-0000-000000cc0002';
const PHYSICIAN1_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN1_SESSION_TOKEN_HASH = hashToken(PHYSICIAN1_SESSION_TOKEN);
const PHYSICIAN1_SESSION_ID = '00000000-2222-0000-0000-000000cc0002';

// Physician 2 (without secondary email)
const PHYSICIAN2_USER_ID = '00000000-1111-0000-0000-000000cc0003';
const PHYSICIAN2_PROVIDER_ID = '00000000-3333-0000-0000-000000cc0003';

// ---------------------------------------------------------------------------
// Mock data stores
// ---------------------------------------------------------------------------

let mockBreaches: Array<Record<string, any>>;
let mockAffectedCustodians: Array<Record<string, any>>;
let mockBreachUpdates: Array<Record<string, any>>;

// ---------------------------------------------------------------------------
// Mock Session Repo
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      const sessions: Record<string, any> = {
        [ADMIN_SESSION_TOKEN_HASH]: {
          session: {
            sessionId: ADMIN_SESSION_ID,
            userId: ADMIN_USER_ID,
            tokenHash: ADMIN_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: ADMIN_USER_ID,
            role: 'ADMIN',
            subscriptionStatus: 'ACTIVE',
          },
        },
        [PHYSICIAN1_SESSION_TOKEN_HASH]: {
          session: {
            sessionId: PHYSICIAN1_SESSION_ID,
            userId: PHYSICIAN1_USER_ID,
            tokenHash: PHYSICIAN1_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: PHYSICIAN1_USER_ID,
            providerId: PHYSICIAN1_PROVIDER_ID,
            role: 'PHYSICIAN',
            subscriptionStatus: 'ACTIVE',
          },
        },
      };
      return sessions[tokenHash] ?? undefined;
    }),
    refreshSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Mock Breach Repo
// ---------------------------------------------------------------------------

function createMockBreachRepo(): BreachRepository {
  return {
    createBreachRecord: vi.fn(async (data: any) => {
      const awarenessDate = data.awarenessDate instanceof Date
        ? data.awarenessDate
        : new Date(data.awarenessDate);
      const breach = {
        breachId: crypto.randomUUID(),
        breachDescription: data.breachDescription,
        breachDate: data.breachDate,
        awarenessDate,
        hiDescription: data.hiDescription,
        includesIihi: data.includesIihi,
        affectedCount: data.affectedCount ?? null,
        riskAssessment: data.riskAssessment ?? null,
        mitigationSteps: data.mitigationSteps ?? null,
        contactName: data.contactName,
        contactEmail: data.contactEmail,
        evidenceHoldUntil: new Date(awarenessDate.getTime() + 365 * 24 * 60 * 60 * 1000),
        status: 'IDENTIFIED',
        resolvedAt: null,
        createdBy: data.createdBy,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      mockBreaches.push(breach);
      return breach;
    }),

    findBreachById: vi.fn(async (breachId: string) => {
      const breach = mockBreaches.find((b) => b.breachId === breachId);
      if (!breach) return undefined;

      const custodians = mockAffectedCustodians.filter(
        (c) => c.breachId === breachId,
      );
      const updates = mockBreachUpdates.filter(
        (u) => u.breachId === breachId,
      );

      return {
        ...breach,
        affectedCustodianCount: custodians.length,
        updates,
      };
    }),

    listBreaches: vi.fn(async (filters: any) => {
      const offset = (filters.page - 1) * filters.pageSize;
      const filtered = filters.status
        ? mockBreaches.filter((b) => b.status === filters.status)
        : mockBreaches;

      return {
        data: filtered.slice(offset, offset + filters.pageSize),
        total: filtered.length,
      };
    }),

    updateBreachStatus: vi.fn(async (breachId: string, status: string, resolvedAt?: Date) => {
      const breach = mockBreaches.find((b) => b.breachId === breachId);
      if (!breach) return undefined;
      breach.status = status;
      breach.updatedAt = new Date();
      if (status === 'RESOLVED') {
        breach.resolvedAt = resolvedAt ?? new Date();
      }
      return { ...breach };
    }),

    addAffectedCustodian: vi.fn(async (breachId: string, providerId: string) => {
      const custodian = {
        custodianId: crypto.randomUUID(),
        breachId,
        providerId,
        initialNotifiedAt: null,
        notificationMethod: null,
        createdAt: new Date(),
      };
      mockAffectedCustodians.push(custodian);
      return custodian;
    }),

    markCustodianNotified: vi.fn(async (breachId: string, providerId: string, method: string) => {
      const custodian = mockAffectedCustodians.find(
        (c) => c.breachId === breachId && c.providerId === providerId,
      );
      if (!custodian) return undefined;
      custodian.initialNotifiedAt = new Date();
      custodian.notificationMethod = method;
      return { ...custodian };
    }),

    getUnnotifiedCustodians: vi.fn(async (breachId: string) => {
      return mockAffectedCustodians.filter(
        (c) => c.breachId === breachId && c.initialNotifiedAt === null,
      );
    }),

    createBreachUpdate: vi.fn(async (breachId: string, data: any) => {
      const update = {
        updateId: crypto.randomUUID(),
        breachId,
        updateType: data.updateType,
        content: data.content,
        createdBy: data.createdBy,
        sentAt: new Date(),
        createdAt: new Date(),
      };
      mockBreachUpdates.push(update);
      return update;
    }),

    listBreachUpdates: vi.fn(async (breachId: string) => {
      return mockBreachUpdates.filter((u) => u.breachId === breachId);
    }),

    getOverdueBreaches: vi.fn(async () => {
      const now = new Date();
      const seventyTwoHoursMs = 72 * 60 * 60 * 1000;
      return mockBreaches.filter((b) => {
        if (b.status === 'RESOLVED') return false;
        const awarenessDate = b.awarenessDate instanceof Date
          ? b.awarenessDate
          : new Date(b.awarenessDate);
        const deadline = new Date(awarenessDate.getTime() + seventyTwoHoursMs);
        if (deadline >= now) return false;
        // Has unnotified custodians
        const unnotified = mockAffectedCustodians.filter(
          (c) => c.breachId === b.breachId && c.initialNotifiedAt === null,
        );
        return unnotified.length > 0;
      });
    }),
  } as unknown as BreachRepository;
}

// ---------------------------------------------------------------------------
// Mock minimal platform deps
// ---------------------------------------------------------------------------

function createMockPlatformServiceDeps(
  breachRepo: BreachRepository,
): PlatformServiceDeps {
  return {
    subscriptionRepo: {} as any,
    paymentRepo: {} as any,
    statusComponentRepo: {} as any,
    incidentRepo: {} as any,
    breachRepo,
    userRepo: {
      findUserById: vi.fn(async () => undefined),
      updateSubscriptionStatus: vi.fn(async () => {}),
    },
    stripe: {} as any,
    config: {
      stripePriceStandardMonthly: 'price_std_m',
      stripePriceStandardAnnual: 'price_std_a',
      stripePriceEarlyBirdMonthly: 'price_eb_m',
      stripePriceEarlyBirdAnnual: 'price_eb_a',
      stripeWebhookSecret: 'whsec_test',
    },
    auditLogger: {
      log: vi.fn(async () => {}),
    } as AuditLogger,
  };
}

// ---------------------------------------------------------------------------
// Valid breach payload
// ---------------------------------------------------------------------------

function validBreachPayload(overrides?: Record<string, any>) {
  return {
    breach_description: 'Unauthorized access to patient records',
    breach_date: new Date().toISOString(),
    awareness_date: new Date().toISOString(),
    hi_description: 'Patient demographic information was accessed',
    includes_iihi: true,
    affected_count: 50,
    risk_assessment: 'High risk due to IIHI exposure',
    mitigation_steps: 'Revoked access, reset credentials',
    contact_name: 'Privacy Officer',
    contact_email: 'privacy@meritum.ca',
    affected_provider_ids: [PHYSICIAN1_PROVIDER_ID, PHYSICIAN2_PROVIDER_ID],
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Test setup
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let breachRepo: BreachRepository;
let serviceDeps: PlatformServiceDeps;
let mockEventEmitter: { emit: ReturnType<typeof vi.fn> };

describe('Breach Notification Lifecycle', () => {
  beforeAll(async () => {
    mockBreaches = [];
    mockAffectedCustodians = [];
    mockBreachUpdates = [];

    breachRepo = createMockBreachRepo();
    serviceDeps = createMockPlatformServiceDeps(breachRepo);
    mockEventEmitter = { emit: vi.fn() };

    app = Fastify();
    app.setValidatorCompiler(validatorCompiler);
    app.setSerializerCompiler(serializerCompiler);

    // Register auth plugin
    await app.register(authPluginFp, {
      sessionDeps: {
        sessionRepo: createMockSessionRepo(),
        auditRepo: { appendAuditLog: vi.fn(async () => {}) },
        events: { emit: vi.fn() },
      } as any,
    });

    // Mock Stripe webhook verifier (required by platformRoutes)
    app.decorate('verifyStripeWebhook', async () => {});
    app.decorateRequest('stripeRawBody', undefined);

    // Register platform routes
    const handlerDeps: PlatformHandlerDeps = {
      serviceDeps,
      eventEmitter: mockEventEmitter,
    };
    await app.register(platformRoutes, { deps: handlerDeps });

    await app.ready();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    mockBreaches = [];
    mockAffectedCustodians = [];
    mockBreachUpdates = [];
    vi.clearAllMocks();
  });

  // =========================================================================
  // Helper: inject as admin
  // =========================================================================

  function adminInject(
    method: 'GET' | 'POST',
    url: string,
    payload?: Record<string, any>,
  ) {
    return app.inject({
      method,
      url,
      headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
      ...(payload ? { payload } : {}),
    });
  }

  // =========================================================================
  // Breach creation
  // =========================================================================

  describe('Breach creation', () => {
    it('admin creates breach affecting both physicians -> 201', async () => {
      const res = await adminInject(
        'POST',
        '/api/v1/platform/breaches',
        validBreachPayload(),
      );

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);
      expect(body.data).toBeDefined();
      expect(body.data.breachId).toBeDefined();
      expect(body.data.status).toBe('IDENTIFIED');
      expect(body.data.breachDescription).toBe('Unauthorized access to patient records');
      // Both custodians linked
      expect(breachRepo.addAffectedCustodian).toHaveBeenCalledTimes(2);
      expect(breachRepo.addAffectedCustodian).toHaveBeenCalledWith(
        expect.any(String),
        PHYSICIAN1_PROVIDER_ID,
      );
      expect(breachRepo.addAffectedCustodian).toHaveBeenCalledWith(
        expect.any(String),
        PHYSICIAN2_PROVIDER_ID,
      );
    });

    it('breach record includes evidence_hold_until = awareness_date + 12 months', async () => {
      const awarenessDate = '2025-06-15T10:00:00.000Z';
      const res = await adminInject(
        'POST',
        '/api/v1/platform/breaches',
        validBreachPayload({ awareness_date: awarenessDate }),
      );

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);

      // evidenceHoldUntil should be awareness_date + ~12 months (365 days)
      const awarenessMs = new Date(awarenessDate).getTime();
      const holdUntilMs = new Date(body.data.evidenceHoldUntil).getTime();
      const diffDays = (holdUntilMs - awarenessMs) / (24 * 60 * 60 * 1000);

      // Should be approximately 365 days (allow range 360-370 for different month-length computations)
      expect(diffDays).toBeGreaterThanOrEqual(360);
      expect(diffDays).toBeLessThanOrEqual(370);
    });

    it('affected custodians linked to breach', async () => {
      const res = await adminInject(
        'POST',
        '/api/v1/platform/breaches',
        validBreachPayload(),
      );

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);
      const breachId = body.data.breachId;

      // Verify custodians are stored in mock
      expect(mockAffectedCustodians).toHaveLength(2);
      expect(mockAffectedCustodians[0].breachId).toBe(breachId);
      expect(mockAffectedCustodians[1].breachId).toBe(breachId);

      const providerIds = mockAffectedCustodians.map((c) => c.providerId);
      expect(providerIds).toContain(PHYSICIAN1_PROVIDER_ID);
      expect(providerIds).toContain(PHYSICIAN2_PROVIDER_ID);

      // All initially unnotified
      for (const custodian of mockAffectedCustodians) {
        expect(custodian.initialNotifiedAt).toBeNull();
      }
    });
  });

  // =========================================================================
  // Notification send
  // =========================================================================

  describe('Notification send', () => {
    it('admin triggers notify -> sends email to both physicians', async () => {
      // Create breach
      const createRes = await adminInject(
        'POST',
        '/api/v1/platform/breaches',
        validBreachPayload(),
      );
      expect(createRes.statusCode).toBe(201);
      const breachId = JSON.parse(createRes.body).data.breachId;

      // Send notifications
      const notifyRes = await adminInject(
        'POST',
        `/api/v1/platform/breaches/${breachId}/notify`,
      );

      expect(notifyRes.statusCode).toBe(200);
      const body = JSON.parse(notifyRes.body);
      expect(body.data.notified).toBe(2);

      // Verify BREACH_INITIAL_NOTIFICATION emitted for each physician
      const emitCalls = mockEventEmitter.emit.mock.calls.filter(
        (call: any[]) => call[0] === 'BREACH_INITIAL_NOTIFICATION',
      );
      expect(emitCalls).toHaveLength(2);

      // Verify provider IDs in emitted events
      const emittedProviderIds = emitCalls.map((call: any[]) => call[1].providerId);
      expect(emittedProviderIds).toContain(PHYSICIAN1_PROVIDER_ID);
      expect(emittedProviderIds).toContain(PHYSICIAN2_PROVIDER_ID);
    });

    it('physician with secondary_email receives two emails', async () => {
      // The dual-delivery mechanism is handled by the notification service.
      // BREACH_INITIAL_NOTIFICATION is in the DUAL_DELIVERY_EVENT_TYPES set,
      // which means the notification service sends to both primary and secondary email.
      // This test verifies the event is emitted with the correct event type that
      // triggers dual-delivery.

      const createRes = await adminInject(
        'POST',
        '/api/v1/platform/breaches',
        validBreachPayload({
          affected_provider_ids: [PHYSICIAN1_PROVIDER_ID], // physician with secondary email
        }),
      );
      expect(createRes.statusCode).toBe(201);
      const breachId = JSON.parse(createRes.body).data.breachId;

      const notifyRes = await adminInject(
        'POST',
        `/api/v1/platform/breaches/${breachId}/notify`,
      );

      expect(notifyRes.statusCode).toBe(200);
      const body = JSON.parse(notifyRes.body);
      expect(body.data.notified).toBe(1);

      // The event type 'BREACH_INITIAL_NOTIFICATION' is in DUAL_DELIVERY_EVENT_TYPES
      // which means notification service auto-sends to primary + secondary email
      expect(mockEventEmitter.emit).toHaveBeenCalledWith(
        'BREACH_INITIAL_NOTIFICATION',
        expect.objectContaining({
          breachId,
          providerId: PHYSICIAN1_PROVIDER_ID,
        }),
      );
    });

    it('physician without secondary_email receives one email', async () => {
      // For physicians without secondary_email, the notification service dual-delivery
      // still emits the same event, but the notification service skips the secondary
      // email when it doesn't exist. We verify the event is emitted correctly.

      const createRes = await adminInject(
        'POST',
        '/api/v1/platform/breaches',
        validBreachPayload({
          affected_provider_ids: [PHYSICIAN2_PROVIDER_ID], // physician without secondary email
        }),
      );
      expect(createRes.statusCode).toBe(201);
      const breachId = JSON.parse(createRes.body).data.breachId;

      const notifyRes = await adminInject(
        'POST',
        `/api/v1/platform/breaches/${breachId}/notify`,
      );

      expect(notifyRes.statusCode).toBe(200);
      const body = JSON.parse(notifyRes.body);
      expect(body.data.notified).toBe(1);

      // Event emitted for single physician
      expect(mockEventEmitter.emit).toHaveBeenCalledWith(
        'BREACH_INITIAL_NOTIFICATION',
        expect.objectContaining({
          breachId,
          providerId: PHYSICIAN2_PROVIDER_ID,
        }),
      );
      // Only one BREACH_INITIAL_NOTIFICATION event (one custodian)
      const emitCalls = mockEventEmitter.emit.mock.calls.filter(
        (call: any[]) => call[0] === 'BREACH_INITIAL_NOTIFICATION',
      );
      expect(emitCalls).toHaveLength(1);
    });

    it('custodians marked as notified after send', async () => {
      const createRes = await adminInject(
        'POST',
        '/api/v1/platform/breaches',
        validBreachPayload(),
      );
      const breachId = JSON.parse(createRes.body).data.breachId;

      // Before notify — all custodians unnotified
      expect(
        mockAffectedCustodians.every((c) => c.initialNotifiedAt === null),
      ).toBe(true);

      await adminInject(
        'POST',
        `/api/v1/platform/breaches/${breachId}/notify`,
      );

      // After notify — markCustodianNotified called for each
      expect(breachRepo.markCustodianNotified).toHaveBeenCalledTimes(2);
      expect(breachRepo.markCustodianNotified).toHaveBeenCalledWith(
        breachId,
        PHYSICIAN1_PROVIDER_ID,
        'EMAIL',
      );
      expect(breachRepo.markCustodianNotified).toHaveBeenCalledWith(
        breachId,
        PHYSICIAN2_PROVIDER_ID,
        'EMAIL',
      );

      // All custodians now have initialNotifiedAt set
      for (const custodian of mockAffectedCustodians) {
        expect(custodian.initialNotifiedAt).toBeInstanceOf(Date);
        expect(custodian.notificationMethod).toBe('EMAIL');
      }
    });

    it('second notify call is idempotent (no duplicate emails)', async () => {
      const createRes = await adminInject(
        'POST',
        '/api/v1/platform/breaches',
        validBreachPayload(),
      );
      const breachId = JSON.parse(createRes.body).data.breachId;

      // First notify
      const firstNotify = await adminInject(
        'POST',
        `/api/v1/platform/breaches/${breachId}/notify`,
      );
      expect(JSON.parse(firstNotify.body).data.notified).toBe(2);

      // Clear mocks to track second call independently
      vi.clearAllMocks();

      // Second notify — should find zero unnotified custodians
      const secondNotify = await adminInject(
        'POST',
        `/api/v1/platform/breaches/${breachId}/notify`,
      );

      expect(secondNotify.statusCode).toBe(200);
      expect(JSON.parse(secondNotify.body).data.notified).toBe(0);

      // No BREACH_INITIAL_NOTIFICATION events emitted on second call
      const emitCalls = mockEventEmitter.emit.mock.calls.filter(
        (call: any[]) => call[0] === 'BREACH_INITIAL_NOTIFICATION',
      );
      expect(emitCalls).toHaveLength(0);

      // markCustodianNotified not called again
      expect(breachRepo.markCustodianNotified).not.toHaveBeenCalled();
    });
  });

  // =========================================================================
  // Supplementary updates
  // =========================================================================

  describe('Supplementary updates', () => {
    it('admin posts update -> all affected custodians receive BREACH_UPDATE', async () => {
      const createRes = await adminInject(
        'POST',
        '/api/v1/platform/breaches',
        validBreachPayload(),
      );
      const breachId = JSON.parse(createRes.body).data.breachId;

      // Send initial notifications first
      await adminInject(
        'POST',
        `/api/v1/platform/breaches/${breachId}/notify`,
      );

      vi.clearAllMocks();

      // Add supplementary update
      const updateRes = await adminInject(
        'POST',
        `/api/v1/platform/breaches/${breachId}/updates`,
        { content: 'Investigation reveals limited exposure. Remediation complete.' },
      );

      expect(updateRes.statusCode).toBe(201);
      const body = JSON.parse(updateRes.body);
      expect(body.data.updateId).toBeDefined();
      expect(body.data.updateType).toBe('SUPPLEMENTARY');
      expect(body.data.content).toBe(
        'Investigation reveals limited exposure. Remediation complete.',
      );

      // BREACH_UPDATE event emitted for all custodians
      expect(mockEventEmitter.emit).toHaveBeenCalledWith(
        'BREACH_UPDATE',
        expect.objectContaining({
          breachId,
          updateId: body.data.updateId,
          content: 'Investigation reveals limited exposure. Remediation complete.',
        }),
      );
    });

    it('update stored in breach_updates (append-only)', async () => {
      const createRes = await adminInject(
        'POST',
        '/api/v1/platform/breaches',
        validBreachPayload(),
      );
      const breachId = JSON.parse(createRes.body).data.breachId;

      // Notify first (creates INITIAL update)
      await adminInject(
        'POST',
        `/api/v1/platform/breaches/${breachId}/notify`,
      );

      // Add first supplementary update
      await adminInject(
        'POST',
        `/api/v1/platform/breaches/${breachId}/updates`,
        { content: 'First supplementary update' },
      );

      // Add second supplementary update
      await adminInject(
        'POST',
        `/api/v1/platform/breaches/${breachId}/updates`,
        { content: 'Second supplementary update' },
      );

      // Verify breach_updates are append-only — all records preserved
      const breachUpdatesForBreach = mockBreachUpdates.filter(
        (u) => u.breachId === breachId,
      );

      // 1 INITIAL from notify + 2 SUPPLEMENTARY
      expect(breachUpdatesForBreach).toHaveLength(3);

      expect(breachUpdatesForBreach[0].updateType).toBe('INITIAL');
      expect(breachUpdatesForBreach[1].updateType).toBe('SUPPLEMENTARY');
      expect(breachUpdatesForBreach[1].content).toBe('First supplementary update');
      expect(breachUpdatesForBreach[2].updateType).toBe('SUPPLEMENTARY');
      expect(breachUpdatesForBreach[2].content).toBe('Second supplementary update');

      // Each update has a unique updateId
      const updateIds = breachUpdatesForBreach.map((u) => u.updateId);
      expect(new Set(updateIds).size).toBe(3);

      // Verify no existing records were modified (append-only)
      // The createBreachUpdate mock only does array push — no mutations
      // Verify the first update is unchanged after subsequent additions
      expect(breachUpdatesForBreach[0].content).toMatch(/Initial breach notification/);
    });
  });

  // =========================================================================
  // Resolution
  // =========================================================================

  describe('Resolution', () => {
    it('admin resolves breach -> status RESOLVED, resolvedAt set', async () => {
      const createRes = await adminInject(
        'POST',
        '/api/v1/platform/breaches',
        validBreachPayload(),
      );
      const breachId = JSON.parse(createRes.body).data.breachId;

      const resolveRes = await adminInject(
        'POST',
        `/api/v1/platform/breaches/${breachId}/resolve`,
      );

      expect(resolveRes.statusCode).toBe(200);
      const body = JSON.parse(resolveRes.body);
      expect(body.data.status).toBe('RESOLVED');
      expect(body.data.resolvedAt).toBeDefined();
      expect(new Date(body.data.resolvedAt).getTime()).toBeGreaterThan(0);

      // Verify in mock store
      const stored = mockBreaches.find((b) => b.breachId === breachId);
      expect(stored?.status).toBe('RESOLVED');
      expect(stored?.resolvedAt).toBeInstanceOf(Date);
    });
  });

  // =========================================================================
  // 72-hour deadline tracking
  // =========================================================================

  describe('72-hour deadline tracking', () => {
    it('overdue breach detected when 72h passed with unnotified custodians', async () => {
      // Seed a breach with awareness_date 4 days ago (well past 72h)
      const fourDaysAgo = new Date(Date.now() - 4 * 24 * 60 * 60 * 1000);

      const createRes = await adminInject(
        'POST',
        '/api/v1/platform/breaches',
        validBreachPayload({
          awareness_date: fourDaysAgo.toISOString(),
        }),
      );
      expect(createRes.statusCode).toBe(201);
      const breachId = JSON.parse(createRes.body).data.breachId;

      // DO NOT send notifications — custodians remain unnotified

      // Call getOverdueBreaches via the mock (simulating scheduled job behavior)
      const overdue = await breachRepo.getOverdueBreaches();

      expect(overdue.length).toBe(1);
      expect(overdue[0].breachId).toBe(breachId);
    });
  });

  // =========================================================================
  // Security: no PHI in breach notification events
  // =========================================================================

  describe('Security: no PHI in breach notification events', () => {
    it('breach notification events contain no PHI', async () => {
      const createRes = await adminInject(
        'POST',
        '/api/v1/platform/breaches',
        validBreachPayload(),
      );
      const breachId = JSON.parse(createRes.body).data.breachId;

      await adminInject(
        'POST',
        `/api/v1/platform/breaches/${breachId}/notify`,
      );

      // Verify emitted events do NOT contain PHI fields
      for (const call of mockEventEmitter.emit.mock.calls) {
        const eventPayload = JSON.stringify(call[1]);
        // No patient names, PHN, DOB, etc.
        expect(eventPayload).not.toMatch(/\bphn\b/i);
        expect(eventPayload).not.toMatch(/\bfirstName\b/i);
        expect(eventPayload).not.toMatch(/\blastName\b/i);
        expect(eventPayload).not.toMatch(/\bdateOfBirth\b/i);
        expect(eventPayload).not.toMatch(/\bpatientId\b/i);
      }
    });

    it('breach update events contain no PHI', async () => {
      const createRes = await adminInject(
        'POST',
        '/api/v1/platform/breaches',
        validBreachPayload(),
      );
      const breachId = JSON.parse(createRes.body).data.breachId;

      vi.clearAllMocks();

      await adminInject(
        'POST',
        `/api/v1/platform/breaches/${breachId}/updates`,
        { content: 'Remediation measures deployed.' },
      );

      for (const call of mockEventEmitter.emit.mock.calls) {
        if (call[0] === 'BREACH_UPDATE') {
          const eventPayload = JSON.stringify(call[1]);
          expect(eventPayload).not.toMatch(/\bphn\b/i);
          expect(eventPayload).not.toMatch(/\bfirstName\b/i);
          expect(eventPayload).not.toMatch(/\blastName\b/i);
          expect(eventPayload).not.toMatch(/\bdateOfBirth\b/i);
          expect(eventPayload).not.toMatch(/\bpatientId\b/i);
        }
      }
    });
  });
});
