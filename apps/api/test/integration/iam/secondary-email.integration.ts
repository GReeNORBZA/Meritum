import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

// ---------------------------------------------------------------------------
// Environment setup (must be before imports that read env)
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);

// ---------------------------------------------------------------------------
// Mock otplib
// ---------------------------------------------------------------------------

const MOCK_TOTP_SECRET = 'JBSWY3DPEHPK3PXP';
const VALID_TOTP_CODE = '123456';

vi.mock('otplib', () => {
  const mockAuthenticator = {
    options: {},
    generateSecret: vi.fn(() => MOCK_TOTP_SECRET),
    keyuri: vi.fn(
      (email: string, issuer: string, secret: string) =>
        `otpauth://totp/${issuer}:${email}?secret=${secret}&issuer=${issuer}`,
    ),
    verify: vi.fn(({ token }: { token: string }) => token === VALID_TOTP_CODE),
  };
  return { authenticator: mockAuthenticator };
});

// ---------------------------------------------------------------------------
// Real imports
// ---------------------------------------------------------------------------

import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { iamAuthRoutes } from '../../../src/domains/iam/iam.routes.js';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import {
  type ServiceDeps,
  type MfaServiceDeps,
  type LoginServiceDeps,
  type PasswordResetDeps,
  type SessionManagementDeps,
  type DelegateServiceDeps,
  type AccountServiceDeps,
  type AuditLogServiceDeps,
  type SecondaryEmailServiceDeps,
} from '../../../src/domains/iam/iam.service.js';
import { type AuthHandlerDeps } from '../../../src/domains/iam/iam.handlers.js';
import { randomBytes } from 'node:crypto';
import {
  hashToken,
  encryptTotpSecret,
} from '../../../src/domains/iam/iam.service.js';

// ---------------------------------------------------------------------------
// Mock stores
// ---------------------------------------------------------------------------

interface MockUser {
  userId: string;
  email: string;
  passwordHash: string;
  mfaConfigured: boolean;
  totpSecretEncrypted: string | null;
  failedLoginCount: number;
  lockedUntil: Date | null;
  isActive: boolean;
  fullName?: string;
  phone?: string | null;
  role?: string;
  subscriptionStatus?: string;
  secondaryEmail?: string | null;
}

interface MockSession {
  sessionId: string;
  userId: string;
  tokenHash: string;
  ipAddress: string;
  userAgent: string;
  createdAt: Date;
  lastActiveAt: Date;
  revoked: boolean;
  revokedReason: string | null;
}

let users: MockUser[] = [];
let sessions: MockSession[] = [];
let auditEntries: Array<Record<string, unknown>> = [];

// Fixed physician
const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_USER_ID = '22222222-0000-0000-0000-000000000001';
const PHYSICIAN_SESSION_ID = '33333333-0000-0000-0000-000000000001';

// ---------------------------------------------------------------------------
// Mock repositories
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    createSession: vi.fn(),
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      const session = sessions.find((s) => s.tokenHash === tokenHash && !s.revoked);
      if (!session) return undefined;
      const user = users.find((u) => u.userId === session.userId);
      if (!user) return undefined;
      return {
        session,
        user: {
          userId: user.userId,
          role: user.role ?? 'PHYSICIAN',
          subscriptionStatus: user.subscriptionStatus ?? 'TRIAL',
        },
      };
    }),
    refreshSession: vi.fn(async (sessionId: string) => {
      const session = sessions.find((s) => s.sessionId === sessionId);
      if (session) session.lastActiveAt = new Date();
    }),
    listActiveSessions: vi.fn(async (userId: string) => {
      return sessions.filter((s) => s.userId === userId && !s.revoked);
    }),
    revokeSession: vi.fn(),
    revokeAllUserSessions: vi.fn(),
  };
}

function createMockAccountUserRepo() {
  return {
    findUserById: vi.fn(async (userId: string) => {
      return users.find((u) => u.userId === userId && u.isActive);
    }),
    updateUser: vi.fn(async (userId: string, data: any) => {
      const user = users.find((u) => u.userId === userId);
      if (!user) return undefined;
      if (data.fullName !== undefined) user.fullName = data.fullName;
      if (data.phone !== undefined) user.phone = data.phone;
      return { userId };
    }),
    deactivateUser: vi.fn(),
  };
}

function createMockSecondaryEmailUserRepo() {
  return {
    findUserById: vi.fn(async (userId: string) => {
      const user = users.find((u) => u.userId === userId);
      if (!user) return undefined;
      return {
        userId: user.userId,
        email: user.email,
        secondaryEmail: user.secondaryEmail ?? null,
      };
    }),
    updateSecondaryEmail: vi.fn(async (userId: string, email: string | null) => {
      const user = users.find((u) => u.userId === userId);
      if (user) user.secondaryEmail = email;
    }),
    getSecondaryEmail: vi.fn(async (userId: string) => {
      const user = users.find((u) => u.userId === userId);
      return user?.secondaryEmail ?? null;
    }),
  };
}

function createMockMfaUserRepo() {
  return {
    findUserById: vi.fn(async (userId: string) => {
      return users.find((u) => u.userId === userId && u.isActive);
    }),
    setMfaSecret: vi.fn(),
    setMfaConfigured: vi.fn(),
  };
}

function createMockRecoveryCodeRepo() {
  return {
    createRecoveryCodes: vi.fn(async (_userId: string, _codeHashes: string[]) => {
      return _codeHashes.map((hash, i) => ({
        codeId: `code-${_userId}-${i}`,
        codeHash: hash,
        used: false,
        userId: _userId,
      }));
    }),
    findUnusedRecoveryCodes: vi.fn(async () => []),
    markRecoveryCodeUsed: vi.fn(),
    countRemainingCodes: vi.fn(async () => 0),
  };
}

function createMockAccountLinkageRepo() {
  return {
    listDelegatesForPhysician: vi.fn(async () => []),
    deactivateLinkage: vi.fn(),
  };
}

function createMockAuditRepo() {
  return {
    appendAuditLog: vi.fn(async (entry: Record<string, unknown>) => {
      auditEntries.push(entry);
    }),
  };
}

function createMockAuditLogQueryRepo() {
  return {
    queryAuditLog: vi.fn(async () => ({ data: [], total: 0 })),
  };
}

function createMockEvents() {
  return { emit: vi.fn() };
}

// Stubs for deps not used in secondary email tests
function createStubServiceDeps(): ServiceDeps {
  return {
    userRepo: { createUser: vi.fn(), findUserByEmail: vi.fn(), updateUser: vi.fn() },
    verificationTokenRepo: { createVerificationToken: vi.fn(), findVerificationTokenByHash: vi.fn(), markVerificationTokenUsed: vi.fn() },
    auditRepo: createMockAuditRepo(),
    events: createMockEvents(),
  };
}

function createStubLoginDeps(): LoginServiceDeps {
  return {
    userRepo: { findUserByEmail: vi.fn(), findUserById: vi.fn(), incrementFailedLogin: vi.fn(), resetFailedLogin: vi.fn() },
    sessionRepo: { createSession: vi.fn() },
    recoveryCodeRepo: { findUnusedRecoveryCodes: vi.fn(), markRecoveryCodeUsed: vi.fn(), countRemainingCodes: vi.fn() },
    auditRepo: createMockAuditRepo(),
    events: createMockEvents(),
  };
}

function createStubPasswordResetDeps(): PasswordResetDeps {
  return {
    userRepo: { findUserByEmail: vi.fn(), setPasswordHash: vi.fn() },
    tokenRepo: { createPasswordResetToken: vi.fn(), findPasswordResetTokenByHash: vi.fn(), markPasswordResetTokenUsed: vi.fn() },
    sessionRepo: { revokeAllUserSessions: vi.fn() },
    auditRepo: createMockAuditRepo(),
    events: createMockEvents(),
  };
}

function createStubDelegateDeps(): DelegateServiceDeps {
  return {
    userRepo: { findUserByEmail: vi.fn(), findUserById: vi.fn(), createUser: vi.fn() },
    invitationRepo: { createInvitation: vi.fn(), findInvitationByTokenHash: vi.fn(), markInvitationAccepted: vi.fn() },
    linkageRepo: {
      createDelegateLinkage: vi.fn(), findLinkage: vi.fn(), findLinkageById: vi.fn(),
      listDelegatesForPhysician: vi.fn(async () => []),
      listPhysiciansForDelegate: vi.fn(async () => []),
      updateLinkagePermissions: vi.fn(), deactivateLinkage: vi.fn(),
    },
    sessionRepo: { revokeAllUserSessions: vi.fn() },
    auditRepo: createMockAuditRepo(),
    events: createMockEvents(),
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let mockSessionRepo: ReturnType<typeof createMockSessionRepo>;
let mockAccountUserRepo: ReturnType<typeof createMockAccountUserRepo>;
let mockSecondaryEmailUserRepo: ReturnType<typeof createMockSecondaryEmailUserRepo>;
let mockAuditRepo: ReturnType<typeof createMockAuditRepo>;
let mockEvents: ReturnType<typeof createMockEvents>;

async function buildTestApp(): Promise<FastifyInstance> {
  mockSessionRepo = createMockSessionRepo();
  mockAccountUserRepo = createMockAccountUserRepo();
  mockSecondaryEmailUserRepo = createMockSecondaryEmailUserRepo();
  mockAuditRepo = createMockAuditRepo();
  mockEvents = createMockEvents();

  const sessionDeps: SessionManagementDeps = {
    sessionRepo: mockSessionRepo,
    auditRepo: mockAuditRepo,
    events: mockEvents,
  };

  const accountDeps: AccountServiceDeps = {
    userRepo: mockAccountUserRepo,
    sessionRepo: mockSessionRepo,
    linkageRepo: createMockAccountLinkageRepo(),
    auditRepo: mockAuditRepo,
    events: mockEvents,
  };

  const secondaryEmailDeps: SecondaryEmailServiceDeps = {
    userRepo: mockSecondaryEmailUserRepo,
    auditRepo: mockAuditRepo,
    events: mockEvents,
  };

  const mfaDeps: MfaServiceDeps = {
    userRepo: createMockMfaUserRepo(),
    recoveryCodeRepo: createMockRecoveryCodeRepo(),
    auditRepo: mockAuditRepo,
    events: mockEvents,
  };

  const auditLogDeps: AuditLogServiceDeps = {
    auditLogRepo: createMockAuditLogQueryRepo(),
    auditRepo: mockAuditRepo,
  };

  const handlerDeps: AuthHandlerDeps = {
    serviceDeps: createStubServiceDeps(),
    mfaDeps,
    loginDeps: createStubLoginDeps(),
    passwordResetDeps: createStubPasswordResetDeps(),
    sessionDeps,
    delegateDeps: createStubDelegateDeps(),
    accountDeps,
    auditLogDeps,
    secondaryEmailDeps,
  };

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);
  await testApp.register(authPluginFp, { sessionDeps });

  testApp.setErrorHandler((error, request, reply) => {
    if (error.statusCode && error.statusCode >= 400 && error.statusCode < 500) {
      return reply.code(error.statusCode).send({
        error: { code: (error as any).code ?? 'ERROR', message: error.message },
      });
    }
    if (error.validation) {
      return reply.code(400).send({
        error: { code: 'VALIDATION_ERROR', message: 'Validation failed', details: error.validation },
      });
    }
    return reply.code(500).send({
      error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
    });
  });

  await testApp.register(iamAuthRoutes, { deps: handlerDeps });
  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Seed helpers
// ---------------------------------------------------------------------------

function seedPhysician() {
  users.push({
    userId: PHYSICIAN_USER_ID,
    email: 'physician@example.com',
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: encryptTotpSecret(MOCK_TOTP_SECRET),
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    fullName: 'Dr. Physician',
    phone: '+14035551234',
    role: 'PHYSICIAN',
    subscriptionStatus: 'TRIAL',
    secondaryEmail: null,
  });
  sessions.push({
    sessionId: PHYSICIAN_SESSION_ID,
    userId: PHYSICIAN_USER_ID,
    tokenHash: PHYSICIAN_SESSION_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Secondary Email Integration Tests', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    users = [];
    sessions = [];
    auditEntries = [];

    mockAuditRepo.appendAuditLog.mockClear();
    mockEvents.emit.mockClear();
    mockAccountUserRepo.findUserById.mockClear();
    mockSecondaryEmailUserRepo.findUserById.mockClear();
    mockSecondaryEmailUserRepo.updateSecondaryEmail.mockClear();
    mockSecondaryEmailUserRepo.getSecondaryEmail.mockClear();

    seedPhysician();
  });

  // =========================================================================
  // PUT /api/v1/account/secondary-email
  // =========================================================================

  describe('PUT /api/v1/account/secondary-email', () => {
    it('sets the secondary email', async () => {
      const res = await app.inject({
        method: 'PUT',
        url: '/api/v1/account/secondary-email',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
        payload: { secondary_email: 'backup@example.com' },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.secondary_email).toBe('backup@example.com');
      expect(mockSecondaryEmailUserRepo.updateSecondaryEmail).toHaveBeenCalledWith(
        PHYSICIAN_USER_ID,
        'backup@example.com',
      );
    });

    it('with null clears it', async () => {
      // Set a secondary email first
      const physician = users.find((u) => u.userId === PHYSICIAN_USER_ID)!;
      physician.secondaryEmail = 'old@example.com';

      const res = await app.inject({
        method: 'PUT',
        url: '/api/v1/account/secondary-email',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
        payload: { secondary_email: null },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.secondary_email).toBeNull();
      expect(mockSecondaryEmailUserRepo.updateSecondaryEmail).toHaveBeenCalledWith(
        PHYSICIAN_USER_ID,
        null,
      );
    });

    it('rejects same as primary', async () => {
      const res = await app.inject({
        method: 'PUT',
        url: '/api/v1/account/secondary-email',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
        payload: { secondary_email: 'physician@example.com' },
      });

      expect(res.statusCode).toBe(422);
    });

    it('returns 401 without session', async () => {
      const res = await app.inject({
        method: 'PUT',
        url: '/api/v1/account/secondary-email',
        payload: { secondary_email: 'backup@example.com' },
      });

      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // GET /api/v1/account includes secondary_email
  // =========================================================================

  describe('GET /api/v1/account', () => {
    it('includes secondary_email in response', async () => {
      // Set secondary email on the mock user
      const physician = users.find((u) => u.userId === PHYSICIAN_USER_ID)!;
      physician.secondaryEmail = 'secondary@example.com';

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/account',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.secondaryEmail).toBe('secondary@example.com');
    });
  });

  // =========================================================================
  // Breach notification dual-delivery
  // =========================================================================

  describe('Breach notification dual-delivery', () => {
    it('breach notification is delivered to both primary and secondary email', async () => {
      // This test verifies the notification service dual-delivery logic
      // by directly calling the processEvent function
      const { processEvent } = await import(
        '../../../src/domains/notification/notification.service.js'
      );

      const createdDeliveryLogs: Array<Record<string, unknown>> = [];
      const mockNotificationRepo = {
        findPreference: vi.fn(async () => null),
        createNotification: vi.fn(async (data: any) => ({
          notificationId: 'notif-001',
          recipientId: data.recipientId,
          eventType: data.eventType,
          title: data.title,
          body: data.body,
          priority: data.priority,
          actionUrl: data.actionUrl,
          actionLabel: data.actionLabel,
          metadata: data.metadata,
          channelsDelivered: data.channelsDelivered,
          createdAt: new Date(),
          readAt: null,
          dismissedAt: null,
          physicianContextId: null,
        })),
        createDeliveryLog: vi.fn(async (data: any) => {
          const log = { deliveryId: `del-${createdDeliveryLogs.length}`, ...data, retryCount: 0 };
          createdDeliveryLogs.push(log);
          return log;
        }),
        addToDigestQueue: vi.fn(),
      } as any;

      const mockDelegateLinkageRepo = {
        listDelegatesForPhysician: vi.fn(async () => []),
      };

      const mockAudit = {
        appendAuditLog: vi.fn(),
      };

      const mockSecondaryLookup = {
        getSecondaryEmail: vi.fn(async () => 'backup@physician.com'),
      };

      const notifications = await processEvent(
        {
          notificationRepo: mockNotificationRepo,
          delegateLinkageRepo: mockDelegateLinkageRepo,
          auditRepo: mockAudit,
          secondaryEmailLookup: mockSecondaryLookup,
        },
        {
          eventType: 'BREACH_INITIAL_NOTIFICATION',
          physicianId: PHYSICIAN_USER_ID,
          metadata: { breach_id: 'BR-001' },
        },
      );

      expect(notifications.length).toBe(1);

      // Should have 2 delivery log entries — primary + secondary
      expect(mockNotificationRepo.createDeliveryLog).toHaveBeenCalledTimes(2);

      // First call: primary email (empty string resolved later)
      expect(mockNotificationRepo.createDeliveryLog).toHaveBeenNthCalledWith(1, {
        notificationId: 'notif-001',
        recipientEmail: '',
        templateId: 'BREACH_INITIAL_NOTIFICATION',
        status: 'QUEUED',
      });

      // Second call: secondary email
      expect(mockNotificationRepo.createDeliveryLog).toHaveBeenNthCalledWith(2, {
        notificationId: 'notif-001',
        recipientEmail: 'backup@physician.com',
        templateId: 'BREACH_INITIAL_NOTIFICATION',
        status: 'QUEUED',
      });
    });
  });
});
