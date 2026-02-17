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
} from '../../../src/domains/iam/iam.service.js';
import { type AuthHandlerDeps } from '../../../src/domains/iam/iam.handlers.js';
import { randomBytes } from 'node:crypto';
import { hash as argon2Hash } from '@node-rs/argon2';
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

interface MockAuditEntry {
  logId: string;
  userId: string | null;
  action: string;
  category: string;
  resourceType: string | null;
  resourceId: string | null;
  detail: Record<string, unknown> | null;
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: Date;
}

let users: MockUser[] = [];
let sessions: MockSession[] = [];
let linkages: Array<{ linkageId: string; delegateUserId: string; isActive: boolean }> = [];
let auditEntries: Array<Record<string, unknown>> = [];
let mockAuditLogEntries: MockAuditEntry[] = [];

// Fixed physician
const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_USER_ID = '22222222-0000-0000-0000-000000000001';
const PHYSICIAN_SESSION_ID = '33333333-0000-0000-0000-000000000001';

// Fixed delegate
const DELEGATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_SESSION_HASH = hashToken(DELEGATE_SESSION_TOKEN);
const DELEGATE_USER_ID = '22222222-0000-0000-0000-000000000002';
const DELEGATE_SESSION_ID = '33333333-0000-0000-0000-000000000002';

let nextAuditId = 1;
function newAuditId() {
  return `aaaa0000-0000-0000-0000-${String(nextAuditId++).padStart(12, '0')}`;
}

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
    revokeAllUserSessions: vi.fn(async (userId: string, exceptId: string | undefined, reason: string) => {
      for (const session of sessions) {
        if (session.userId === userId && session.sessionId !== exceptId) {
          session.revoked = true;
          session.revokedReason = reason;
        }
      }
    }),
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
    deactivateUser: vi.fn(async (userId: string) => {
      const user = users.find((u) => u.userId === userId);
      if (user) user.isActive = false;
    }),
  };
}

function createMockMfaUserRepo() {
  return {
    findUserById: vi.fn(async (userId: string) => {
      return users.find((u) => u.userId === userId && u.isActive);
    }),
    setMfaSecret: vi.fn(async (userId: string, secret: string) => {
      const user = users.find((u) => u.userId === userId);
      if (user) user.totpSecretEncrypted = secret;
    }),
    setMfaConfigured: vi.fn(async (userId: string) => {
      const user = users.find((u) => u.userId === userId);
      if (user) user.mfaConfigured = true;
    }),
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
    listDelegatesForPhysician: vi.fn(async (physicianUserId: string) => {
      return linkages
        .filter((l) => l.isActive)
        .map((l) => ({
          linkage: l,
          user: { userId: l.delegateUserId, fullName: 'Test', email: 'test@test.com' },
          lastLogin: null,
        }));
    }),
    deactivateLinkage: vi.fn(async (linkageId: string) => {
      const l = linkages.find((x) => x.linkageId === linkageId);
      if (l) l.isActive = false;
      return l ? { linkageId } : undefined;
    }),
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
    queryAuditLog: vi.fn(async (userId: string, filters?: any) => {
      const userEntries = mockAuditLogEntries.filter((e) => e.userId === userId);
      const page = filters?.page ?? 1;
      const pageSize = filters?.pageSize ?? 50;
      const start = (page - 1) * pageSize;
      return {
        data: userEntries.slice(start, start + pageSize),
        total: userEntries.length,
      };
    }),
  };
}

function createMockEvents() {
  return { emit: vi.fn() };
}

// Stubs for non-account deps
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
let mockMfaUserRepo: ReturnType<typeof createMockMfaUserRepo>;
let mockRecoveryCodeRepo: ReturnType<typeof createMockRecoveryCodeRepo>;
let mockAccountLinkageRepo: ReturnType<typeof createMockAccountLinkageRepo>;
let mockAuditRepo: ReturnType<typeof createMockAuditRepo>;
let mockAuditLogQueryRepo: ReturnType<typeof createMockAuditLogQueryRepo>;
let mockEvents: ReturnType<typeof createMockEvents>;

async function buildTestApp(): Promise<FastifyInstance> {
  mockSessionRepo = createMockSessionRepo();
  mockAccountUserRepo = createMockAccountUserRepo();
  mockMfaUserRepo = createMockMfaUserRepo();
  mockRecoveryCodeRepo = createMockRecoveryCodeRepo();
  mockAccountLinkageRepo = createMockAccountLinkageRepo();
  mockAuditRepo = createMockAuditRepo();
  mockAuditLogQueryRepo = createMockAuditLogQueryRepo();
  mockEvents = createMockEvents();

  const sessionDeps: SessionManagementDeps = {
    sessionRepo: mockSessionRepo,
    auditRepo: mockAuditRepo,
    events: mockEvents,
  };

  const accountDeps: AccountServiceDeps = {
    userRepo: mockAccountUserRepo,
    sessionRepo: mockSessionRepo,
    linkageRepo: mockAccountLinkageRepo,
    auditRepo: mockAuditRepo,
    events: mockEvents,
  };

  const mfaDeps: MfaServiceDeps = {
    userRepo: mockMfaUserRepo,
    recoveryCodeRepo: mockRecoveryCodeRepo,
    auditRepo: mockAuditRepo,
    events: mockEvents,
  };

  const auditLogDeps: AuditLogServiceDeps = {
    auditLogRepo: mockAuditLogQueryRepo,
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

let testPasswordHash: string;

async function seedPhysician() {
  const password = 'SecurePass123!';
  testPasswordHash = await argon2Hash(password, {
    memoryCost: 19456,
    timeCost: 2,
    parallelism: 1,
  });
  const encryptedSecret = encryptTotpSecret(MOCK_TOTP_SECRET);

  users.push({
    userId: PHYSICIAN_USER_ID,
    email: 'physician@example.com',
    passwordHash: testPasswordHash,
    mfaConfigured: true,
    totpSecretEncrypted: encryptedSecret,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    fullName: 'Dr. Physician',
    phone: '+14035551234',
    role: 'PHYSICIAN',
    subscriptionStatus: 'TRIAL',
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

function seedDelegate() {
  users.push({
    userId: DELEGATE_USER_ID,
    email: 'delegate@example.com',
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    fullName: 'Del E. Gate',
    role: 'DELEGATE',
    subscriptionStatus: 'TRIAL',
  });
  sessions.push({
    sessionId: DELEGATE_SESSION_ID,
    userId: DELEGATE_USER_ID,
    tokenHash: DELEGATE_SESSION_HASH,
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

describe('IAM Account Integration Tests', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(async () => {
    users = [];
    sessions = [];
    linkages = [];
    auditEntries = [];
    mockAuditLogEntries = [];
    nextAuditId = 1;

    mockAuditRepo.appendAuditLog.mockClear();
    mockEvents.emit.mockClear();
    mockAccountUserRepo.findUserById.mockClear();
    mockAccountUserRepo.updateUser.mockClear();
    mockAccountUserRepo.deactivateUser.mockClear();
    mockSessionRepo.revokeAllUserSessions.mockClear();
    mockAccountLinkageRepo.listDelegatesForPhysician.mockClear();
    mockAccountLinkageRepo.deactivateLinkage.mockClear();
    mockAuditLogQueryRepo.queryAuditLog.mockClear();
    mockMfaUserRepo.findUserById.mockClear();
    mockMfaUserRepo.setMfaSecret.mockClear();
    mockMfaUserRepo.setMfaConfigured.mockClear();
    mockRecoveryCodeRepo.createRecoveryCodes.mockClear();

    await seedPhysician();
    seedDelegate();
  });

  // =========================================================================
  // GET /api/v1/account
  // =========================================================================

  describe('GET /api/v1/account', () => {
    it('returns account info', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/account',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.userId).toBe(PHYSICIAN_USER_ID);
      expect(body.data.email).toBe('physician@example.com');
      expect(body.data.fullName).toBe('Dr. Physician');
      expect(body.data.role).toBe('PHYSICIAN');
      expect(body.data.mfaConfigured).toBe(true);
      // Should not expose sensitive fields
      expect(body.data.passwordHash).toBeUndefined();
      expect(body.data.totpSecretEncrypted).toBeUndefined();
    });

    it('returns 401 without session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/account',
      });

      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // PATCH /api/v1/account
  // =========================================================================

  describe('PATCH /api/v1/account', () => {
    it('updates name and phone', async () => {
      const res = await app.inject({
        method: 'PATCH',
        url: '/api/v1/account',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
        payload: {
          full_name: 'Dr. Updated Name',
          phone: '+14035559999',
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.userId).toBe(PHYSICIAN_USER_ID);
    });

    it('returns 401 without session', async () => {
      const res = await app.inject({
        method: 'PATCH',
        url: '/api/v1/account',
        payload: { full_name: 'Hacker' },
      });

      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // POST /api/v1/account/mfa/regenerate-codes
  // =========================================================================

  describe('POST /api/v1/account/mfa/regenerate-codes', () => {
    it('with valid TOTP returns new recovery codes', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/account/mfa/regenerate-codes',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
        payload: { totp_code: VALID_TOTP_CODE },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.recovery_codes).toBeDefined();
      expect(Array.isArray(body.data.recovery_codes)).toBe(true);
      expect(body.data.recovery_codes.length).toBe(10);
    });

    it('with invalid TOTP returns 422', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/account/mfa/regenerate-codes',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
        payload: { totp_code: '000000' },
      });

      expect(res.statusCode).toBe(422);
    });

    it('returns 401 without session', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/account/mfa/regenerate-codes',
        payload: { totp_code: '123456' },
      });

      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // POST /api/v1/account/mfa/reconfigure
  // =========================================================================

  describe('POST /api/v1/account/mfa/reconfigure', () => {
    it('with valid current TOTP returns new QR code', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/account/mfa/reconfigure',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
        payload: { current_totp_code: VALID_TOTP_CODE },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.qr_code_uri).toBeDefined();
      expect(body.data.manual_key).toBeDefined();
    });

    it('with invalid TOTP code format returns 400', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/account/mfa/reconfigure',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
        payload: { current_totp_code: 'abc' },
      });

      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // POST /api/v1/account/delete
  // =========================================================================

  describe('POST /api/v1/account/delete', () => {
    it('with valid 3-factor confirmation succeeds', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/account/delete',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
        payload: {
          password: 'SecurePass123!',
          totp_code: VALID_TOTP_CODE,
          confirmation: 'DELETE',
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.scheduledDeletionDate).toBeDefined();
    });

    it('with wrong password returns 422', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/account/delete',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
        payload: {
          password: 'WrongPassword123!',
          totp_code: VALID_TOTP_CODE,
          confirmation: 'DELETE',
        },
      });

      expect(res.statusCode).toBe(422);
    });

    it('with wrong TOTP returns 422', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/account/delete',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
        payload: {
          password: 'SecurePass123!',
          totp_code: '000000',
          confirmation: 'DELETE',
        },
      });

      expect(res.statusCode).toBe(422);
    });

    it('with wrong confirmation returns 400', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/account/delete',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
        payload: {
          password: 'SecurePass123!',
          totp_code: VALID_TOTP_CODE,
          confirmation: 'WRONG',
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('as delegate returns 403', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/account/delete',
        headers: { cookie: `session=${DELEGATE_SESSION_TOKEN}` },
        payload: {
          password: 'SecurePass123!',
          totp_code: VALID_TOTP_CODE,
          confirmation: 'DELETE',
        },
      });

      expect(res.statusCode).toBe(403);
    });
  });

  // =========================================================================
  // GET /api/v1/account/audit-log
  // =========================================================================

  describe('GET /api/v1/account/audit-log', () => {
    it('returns paginated log', async () => {
      // Seed some audit entries
      mockAuditLogEntries.push(
        {
          logId: newAuditId(),
          userId: PHYSICIAN_USER_ID,
          action: 'auth.login_success',
          category: 'auth',
          resourceType: 'user',
          resourceId: PHYSICIAN_USER_ID,
          detail: null,
          ipAddress: '127.0.0.1',
          userAgent: 'test',
          createdAt: new Date(),
        },
        {
          logId: newAuditId(),
          userId: PHYSICIAN_USER_ID,
          action: 'auth.mfa_setup',
          category: 'auth',
          resourceType: 'user',
          resourceId: PHYSICIAN_USER_ID,
          detail: null,
          ipAddress: '127.0.0.1',
          userAgent: 'test',
          createdAt: new Date(),
        },
      );

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/account/audit-log?page=1&page_size=10',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toBeDefined();
      expect(Array.isArray(body.data)).toBe(true);
      expect(body.data.length).toBe(2);
      expect(body.pagination).toBeDefined();
      expect(body.pagination.total).toBe(2);
      expect(body.pagination.page).toBe(1);
      expect(body.pagination.hasMore).toBe(false);
    });

    it('as delegate returns 403', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/account/audit-log',
        headers: { cookie: `session=${DELEGATE_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(403);
    });

    it('returns 401 without session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/account/audit-log',
      });

      expect(res.statusCode).toBe(401);
    });
  });
});
