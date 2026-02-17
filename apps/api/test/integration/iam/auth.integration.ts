import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

// ---------------------------------------------------------------------------
// Environment setup (must be before imports that read env)
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);

// ---------------------------------------------------------------------------
// Mock otplib (v13 does not export `authenticator` — service expects v12 API)
// ---------------------------------------------------------------------------

const MOCK_TOTP_SECRET = 'JBSWY3DPEHPK3PXP';
const VALID_TOTP_CODE = '123456';

vi.mock('otplib', () => {
  const mockAuthenticator = {
    options: {},
    generateSecret: vi.fn(() => MOCK_TOTP_SECRET),
    keyuri: vi.fn(
      (email: string, issuer: string, secret: string) =>
        `otpauth://totp/${issuer}:${email}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`,
    ),
    verify: vi.fn(({ token }: { token: string; secret: string }) => {
      return token === VALID_TOTP_CODE;
    }),
  };
  return { authenticator: mockAuthenticator };
});

// ---------------------------------------------------------------------------
// Real imports (after mocks are hoisted)
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
  type AuthContext,
} from '../../../src/domains/iam/iam.service.js';
import { type AuthHandlerDeps } from '../../../src/domains/iam/iam.handlers.js';

// ---------------------------------------------------------------------------
// Mock stores
// ---------------------------------------------------------------------------

let createdUsers: Array<{
  userId: string;
  email: string;
  passwordHash: string;
  mfaConfigured: boolean;
  totpSecretEncrypted: string | null;
  failedLoginCount: number;
  lockedUntil: Date | null;
  isActive: boolean;
}>;

let createdSessions: Array<{
  sessionId: string;
  userId: string;
  tokenHash: string;
  ipAddress: string;
  userAgent: string;
  createdAt: Date;
  lastActiveAt: Date;
  revoked: boolean;
  revokedReason: string | null;
}>;

let verificationTokens: Array<{
  userId: string;
  tokenHash: string;
  expiresAt: Date;
  used: boolean;
}>;

let passwordResetTokens: Array<{
  userId: string;
  tokenHash: string;
  expiresAt: Date;
  used: boolean;
}>;

let recoveryCodes: Array<{
  codeId: string;
  codeHash: string;
  used: boolean;
  userId: string;
}>;

let auditEntries: Array<Record<string, unknown>>;

// ---------------------------------------------------------------------------
// Deterministic IDs
// ---------------------------------------------------------------------------

let nextUserId = 1;
function newUserId() {
  return `00000000-0000-0000-0000-${String(nextUserId++).padStart(12, '0')}`;
}

let nextSessionId = 1;
function newSessionId() {
  return `11111111-0000-0000-0000-${String(nextSessionId++).padStart(12, '0')}`;
}

// ---------------------------------------------------------------------------
// Valid session token for authenticated routes
// ---------------------------------------------------------------------------

// We use a fixed raw token and hash it with SHA-256 to look it up in the session store.
import { createHash, randomBytes } from 'node:crypto';
import { hash as argon2Hash } from '@node-rs/argon2';
import {
  encryptTotpSecret,
  createMfaSessionToken,
  hashToken,
} from '../../../src/domains/iam/iam.service.js';

const FIXED_SESSION_TOKEN = randomBytes(32).toString('hex');
const FIXED_SESSION_TOKEN_HASH = hashToken(FIXED_SESSION_TOKEN);
const FIXED_USER_ID = '22222222-0000-0000-0000-000000000001';
const FIXED_SESSION_ID = '33333333-0000-0000-0000-000000000001';

// ---------------------------------------------------------------------------
// Mock repositories
// ---------------------------------------------------------------------------

function createMockUserRepo() {
  return {
    createUser: vi.fn(async (data: any) => {
      const existing = createdUsers.find((u) => u.email === data.email.toLowerCase());
      if (existing) {
        const err = new Error('duplicate key') as any;
        err.code = '23505';
        throw err;
      }
      const user = {
        userId: newUserId(),
        email: data.email.toLowerCase(),
        passwordHash: data.passwordHash,
        mfaConfigured: false,
        totpSecretEncrypted: null,
        failedLoginCount: 0,
        lockedUntil: null,
        isActive: true,
      };
      createdUsers.push(user);
      return { userId: user.userId, email: user.email };
    }),
    findUserByEmail: vi.fn(async (email: string) => {
      return createdUsers.find((u) => u.email === email.toLowerCase() && u.isActive);
    }),
    findUserById: vi.fn(async (userId: string) => {
      return createdUsers.find((u) => u.userId === userId && u.isActive);
    }),
    updateUser: vi.fn(async (userId: string, data: any) => {
      const user = createdUsers.find((u) => u.userId === userId);
      if (!user) return undefined;
      Object.assign(user, data);
      return { userId };
    }),
    setMfaSecret: vi.fn(async (userId: string, secret: string) => {
      const user = createdUsers.find((u) => u.userId === userId);
      if (user) user.totpSecretEncrypted = secret;
    }),
    setMfaConfigured: vi.fn(async (userId: string) => {
      const user = createdUsers.find((u) => u.userId === userId);
      if (user) user.mfaConfigured = true;
    }),
    incrementFailedLogin: vi.fn(async (userId: string) => {
      const user = createdUsers.find((u) => u.userId === userId);
      if (user) {
        user.failedLoginCount++;
        if (user.failedLoginCount >= 10) {
          user.lockedUntil = new Date(Date.now() + 30 * 60 * 1000);
        }
      }
    }),
    resetFailedLogin: vi.fn(async (userId: string) => {
      const user = createdUsers.find((u) => u.userId === userId);
      if (user) {
        user.failedLoginCount = 0;
        user.lockedUntil = null;
      }
    }),
    setPasswordHash: vi.fn(async (userId: string, hash: string) => {
      const user = createdUsers.find((u) => u.userId === userId);
      if (user) user.passwordHash = hash;
    }),
  };
}

function createMockVerificationTokenRepo() {
  return {
    createVerificationToken: vi.fn(async (data: any) => {
      verificationTokens.push({
        userId: data.userId,
        tokenHash: data.tokenHash,
        expiresAt: data.expiresAt,
        used: false,
      });
      return { tokenHash: data.tokenHash };
    }),
    findVerificationTokenByHash: vi.fn(async (tokenHash: string) => {
      return verificationTokens.find((t) => t.tokenHash === tokenHash);
    }),
    markVerificationTokenUsed: vi.fn(async (tokenHash: string) => {
      const token = verificationTokens.find((t) => t.tokenHash === tokenHash);
      if (token) token.used = true;
    }),
  };
}

function createMockSessionRepo() {
  return {
    createSession: vi.fn(async (data: any) => {
      const session = {
        sessionId: newSessionId(),
        userId: data.userId,
        tokenHash: data.tokenHash,
        ipAddress: data.ipAddress,
        userAgent: data.userAgent,
        createdAt: new Date(),
        lastActiveAt: new Date(),
        revoked: false,
        revokedReason: null,
      };
      createdSessions.push(session);
      return { sessionId: session.sessionId };
    }),
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      const session = createdSessions.find(
        (s) => s.tokenHash === tokenHash && !s.revoked,
      );
      if (!session) return undefined;
      const user = createdUsers.find((u) => u.userId === session.userId);
      if (!user) return undefined;
      return {
        session,
        user: {
          userId: user.userId,
          role: 'PHYSICIAN',
          subscriptionStatus: 'TRIAL',
        },
      };
    }),
    refreshSession: vi.fn(async (sessionId: string) => {
      const session = createdSessions.find((s) => s.sessionId === sessionId);
      if (session) session.lastActiveAt = new Date();
    }),
    listActiveSessions: vi.fn(async (userId: string) => {
      return createdSessions.filter(
        (s) => s.userId === userId && !s.revoked,
      );
    }),
    revokeSession: vi.fn(async (sessionId: string, reason: string) => {
      const session = createdSessions.find((s) => s.sessionId === sessionId);
      if (session) {
        session.revoked = true;
        session.revokedReason = reason;
      }
    }),
    revokeAllUserSessions: vi.fn(async (userId: string, exceptId: string | undefined, reason: string) => {
      for (const session of createdSessions) {
        if (session.userId === userId && session.sessionId !== exceptId) {
          session.revoked = true;
          session.revokedReason = reason;
        }
      }
    }),
  };
}

function createMockRecoveryCodeRepo() {
  return {
    createRecoveryCodes: vi.fn(async (userId: string, codeHashes: string[]) => {
      // Delete old codes
      recoveryCodes = recoveryCodes.filter((c) => c.userId !== userId || c.used);
      const newCodes = codeHashes.map((hash, i) => ({
        codeId: `code-${userId}-${i}`,
        codeHash: hash,
        used: false,
        userId,
      }));
      recoveryCodes.push(...newCodes);
      return newCodes;
    }),
    findUnusedRecoveryCodes: vi.fn(async (userId: string) => {
      return recoveryCodes.filter((c) => c.userId === userId && !c.used);
    }),
    markRecoveryCodeUsed: vi.fn(async (codeId: string) => {
      const code = recoveryCodes.find((c) => c.codeId === codeId);
      if (code) code.used = true;
    }),
    countRemainingCodes: vi.fn(async (userId: string) => {
      return recoveryCodes.filter((c) => c.userId === userId && !c.used).length;
    }),
  };
}

function createMockPasswordResetTokenRepo() {
  return {
    createPasswordResetToken: vi.fn(async (data: any) => {
      passwordResetTokens.push({
        userId: data.userId,
        tokenHash: data.tokenHash,
        expiresAt: data.expiresAt,
        used: false,
      });
      return { tokenHash: data.tokenHash };
    }),
    findPasswordResetTokenByHash: vi.fn(async (tokenHash: string) => {
      return passwordResetTokens.find((t) => t.tokenHash === tokenHash);
    }),
    markPasswordResetTokenUsed: vi.fn(async (tokenHash: string) => {
      const token = passwordResetTokens.find((t) => t.tokenHash === tokenHash);
      if (token) token.used = true;
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

function createMockEvents() {
  return {
    emit: vi.fn(),
  };
}

// ---------------------------------------------------------------------------
// Stub delegate/account/auditLog deps (not exercised in auth tests)
// ---------------------------------------------------------------------------

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
    auditRepo: { appendAuditLog: vi.fn() },
    events: { emit: vi.fn() },
  };
}

function createStubAccountDeps(): AccountServiceDeps {
  return {
    userRepo: {
      findUserById: vi.fn(),
      updateUser: vi.fn(),
      deactivateUser: vi.fn(),
    },
    sessionRepo: { revokeAllUserSessions: vi.fn() },
    linkageRepo: {
      listDelegatesForPhysician: vi.fn(async () => []),
      deactivateLinkage: vi.fn(),
    },
    auditRepo: { appendAuditLog: vi.fn() },
    events: { emit: vi.fn() },
  };
}

function createStubAuditLogDeps(): AuditLogServiceDeps {
  return {
    auditLogRepo: {
      queryAuditLog: vi.fn(async () => ({ data: [], total: 0 })),
    },
    auditRepo: { appendAuditLog: vi.fn() },
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let mockUserRepo: ReturnType<typeof createMockUserRepo>;
let mockVerifTokenRepo: ReturnType<typeof createMockVerificationTokenRepo>;
let mockSessionRepo: ReturnType<typeof createMockSessionRepo>;
let mockRecoveryRepo: ReturnType<typeof createMockRecoveryCodeRepo>;
let mockPwResetTokenRepo: ReturnType<typeof createMockPasswordResetTokenRepo>;
let mockAuditRepo: ReturnType<typeof createMockAuditRepo>;
let mockEvents: ReturnType<typeof createMockEvents>;

async function buildTestApp(): Promise<FastifyInstance> {
  mockUserRepo = createMockUserRepo();
  mockVerifTokenRepo = createMockVerificationTokenRepo();
  mockSessionRepo = createMockSessionRepo();
  mockRecoveryRepo = createMockRecoveryCodeRepo();
  mockPwResetTokenRepo = createMockPasswordResetTokenRepo();
  mockAuditRepo = createMockAuditRepo();
  mockEvents = createMockEvents();

  const serviceDeps: ServiceDeps = {
    userRepo: mockUserRepo,
    verificationTokenRepo: mockVerifTokenRepo,
    auditRepo: mockAuditRepo,
    events: mockEvents,
  };

  const mfaDeps: MfaServiceDeps = {
    userRepo: mockUserRepo,
    recoveryCodeRepo: mockRecoveryRepo,
    auditRepo: mockAuditRepo,
    events: mockEvents,
  };

  const loginDeps: LoginServiceDeps = {
    userRepo: mockUserRepo,
    sessionRepo: mockSessionRepo,
    recoveryCodeRepo: mockRecoveryRepo,
    auditRepo: mockAuditRepo,
    events: mockEvents,
  };

  const passwordResetDeps: PasswordResetDeps = {
    userRepo: mockUserRepo,
    tokenRepo: mockPwResetTokenRepo,
    sessionRepo: mockSessionRepo,
    auditRepo: mockAuditRepo,
    events: mockEvents,
  };

  const sessionDeps: SessionManagementDeps = {
    sessionRepo: mockSessionRepo,
    auditRepo: mockAuditRepo,
    events: mockEvents,
  };

  const handlerDeps: AuthHandlerDeps = {
    serviceDeps,
    mfaDeps,
    loginDeps,
    passwordResetDeps,
    sessionDeps,
    delegateDeps: createStubDelegateDeps(),
    accountDeps: createStubAccountDeps(),
    auditLogDeps: createStubAuditLogDeps(),
  };

  const testApp = Fastify({ logger: false });

  // Configure Zod validation and serialization for Fastify
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  // Register auth plugin (provides app.authenticate)
  await testApp.register(authPluginFp, { sessionDeps });

  // Register error handler for AppError
  testApp.setErrorHandler((error, request, reply) => {
    if (error.statusCode && error.statusCode >= 400 && error.statusCode < 500) {
      return reply.code(error.statusCode).send({
        error: {
          code: (error as any).code ?? 'ERROR',
          message: error.message,
        },
      });
    }
    // Zod validation errors from Fastify
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

  // Register auth routes
  await testApp.register(iamAuthRoutes, { deps: handlerDeps });

  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('IAM Auth Integration Tests', () => {
  beforeAll(async () => {
    // Reset stores
    createdUsers = [];
    createdSessions = [];
    verificationTokens = [];
    passwordResetTokens = [];
    recoveryCodes = [];
    auditEntries = [];
    nextUserId = 1;
    nextSessionId = 1;

    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    // Reset stores between tests
    createdUsers = [];
    createdSessions = [];
    verificationTokens = [];
    passwordResetTokens = [];
    recoveryCodes = [];
    auditEntries = [];
    nextUserId = 1;
    nextSessionId = 1;

    // Clear mock call histories so find() picks up only current test's calls
    mockUserRepo.createUser.mockClear();
    mockUserRepo.findUserByEmail.mockClear();
    mockUserRepo.findUserById.mockClear();
    mockUserRepo.updateUser.mockClear();
    mockUserRepo.setMfaSecret.mockClear();
    mockUserRepo.setMfaConfigured.mockClear();
    mockUserRepo.incrementFailedLogin.mockClear();
    mockUserRepo.resetFailedLogin.mockClear();
    mockUserRepo.setPasswordHash.mockClear();
    mockVerifTokenRepo.createVerificationToken.mockClear();
    mockVerifTokenRepo.findVerificationTokenByHash.mockClear();
    mockVerifTokenRepo.markVerificationTokenUsed.mockClear();
    mockSessionRepo.createSession.mockClear();
    mockSessionRepo.findSessionByTokenHash.mockClear();
    mockSessionRepo.refreshSession.mockClear();
    mockSessionRepo.revokeSession.mockClear();
    mockSessionRepo.revokeAllUserSessions.mockClear();
    mockRecoveryRepo.createRecoveryCodes.mockClear();
    mockRecoveryRepo.findUnusedRecoveryCodes.mockClear();
    mockRecoveryRepo.markRecoveryCodeUsed.mockClear();
    mockRecoveryRepo.countRemainingCodes.mockClear();
    mockPwResetTokenRepo.createPasswordResetToken.mockClear();
    mockPwResetTokenRepo.findPasswordResetTokenByHash.mockClear();
    mockPwResetTokenRepo.markPasswordResetTokenUsed.mockClear();
    mockAuditRepo.appendAuditLog.mockClear();
    mockEvents.emit.mockClear();

    // Seed the fixed authenticated user and session
    createdUsers.push({
      userId: FIXED_USER_ID,
      email: 'authed@example.com',
      passwordHash: 'hashed',
      mfaConfigured: false,
      totpSecretEncrypted: null,
      failedLoginCount: 0,
      lockedUntil: null,
      isActive: true,
    });
    createdSessions.push({
      sessionId: FIXED_SESSION_ID,
      userId: FIXED_USER_ID,
      tokenHash: FIXED_SESSION_TOKEN_HASH,
      ipAddress: '127.0.0.1',
      userAgent: 'test-agent',
      createdAt: new Date(),
      lastActiveAt: new Date(),
      revoked: false,
      revokedReason: null,
    });
  });

  // =========================================================================
  // Registration
  // =========================================================================

  describe('POST /api/v1/auth/register', () => {
    it('with valid data returns 201', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/register',
        payload: {
          email: 'dr.smith@example.com',
          password: 'SecurePass123!',
          full_name: 'Dr. Jane Smith',
          phone: '+14035551234',
        },
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);
      expect(body.data).toBeDefined();
      expect(body.data.userId).toBeDefined();
    });

    it('with invalid email returns 400', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/register',
        payload: {
          email: 'not-an-email',
          password: 'SecurePass123!',
          full_name: 'Dr. Jane Smith',
        },
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
    });

    it('with weak password returns 400', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/register',
        payload: {
          email: 'dr.smith@example.com',
          password: 'weak',
          full_name: 'Dr. Jane Smith',
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('with missing full_name returns 400', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/register',
        payload: {
          email: 'dr.smith@example.com',
          password: 'SecurePass123!',
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('with duplicate email still returns 201 (anti-enumeration)', async () => {
      // First registration
      await app.inject({
        method: 'POST',
        url: '/api/v1/auth/register',
        payload: {
          email: 'duplicate@example.com',
          password: 'SecurePass123!',
          full_name: 'Dr. First',
        },
      });

      // Second registration with same email
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/register',
        payload: {
          email: 'duplicate@example.com',
          password: 'SecurePass123!',
          full_name: 'Dr. Second',
        },
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);
      expect(body.data.userId).toBeDefined();
    });
  });

  // =========================================================================
  // Email Verification
  // =========================================================================

  describe('POST /api/v1/auth/verify-email', () => {
    it('with valid token returns 200', async () => {
      // Register first to get a verification token
      await app.inject({
        method: 'POST',
        url: '/api/v1/auth/register',
        payload: {
          email: 'verify@example.com',
          password: 'SecurePass123!',
          full_name: 'Dr. Verify',
        },
      });

      // The mock emits an event with the raw token
      const emitCall = mockEvents.emit.mock.calls.find(
        (c: any[]) => c[0] === 'USER_REGISTERED',
      );
      expect(emitCall).toBeDefined();
      const rawToken = emitCall![1].verificationToken as string;

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/verify-email',
        payload: { token: rawToken },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.mfa_setup_required).toBe(true);
    });

    it('with invalid token returns 422', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/verify-email',
        payload: { token: '00000000-0000-0000-0000-000000000099' },
      });

      expect(res.statusCode).toBe(422);
    });

    it('with non-UUID token returns 400', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/verify-email',
        payload: { token: 'not-a-uuid' },
      });

      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // Login Step 1
  // =========================================================================

  describe('POST /api/v1/auth/login', () => {
    it('with valid credentials returns mfa_session_token', async () => {
      const password = 'SecurePass123!';
      const passwordHash = await argon2Hash(password, {
        memoryCost: 19456,
        timeCost: 2,
        parallelism: 1,
      });

      // Seed user with MFA configured
      const encryptedSecret = encryptTotpSecret(MOCK_TOTP_SECRET);

      createdUsers.push({
        userId: newUserId(),
        email: 'login@example.com',
        passwordHash,
        mfaConfigured: true,
        totpSecretEncrypted: encryptedSecret,
        failedLoginCount: 0,
        lockedUntil: null,
        isActive: true,
      });

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        payload: {
          email: 'login@example.com',
          password,
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.mfa_required).toBe(true);
      expect(body.data.mfa_session_token).toBeDefined();
      expect(typeof body.data.mfa_session_token).toBe('string');
    });

    it('with wrong password returns 422', async () => {
      const passwordHash = await argon2Hash('CorrectPass123!', {
        memoryCost: 19456,
        timeCost: 2,
        parallelism: 1,
      });

      createdUsers.push({
        userId: newUserId(),
        email: 'wrongpw@example.com',
        passwordHash,
        mfaConfigured: true,
        totpSecretEncrypted: null,
        failedLoginCount: 0,
        lockedUntil: null,
        isActive: true,
      });

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        payload: {
          email: 'wrongpw@example.com',
          password: 'WrongPass456!',
        },
      });

      expect(res.statusCode).toBe(422);
    });

    it('with non-existent email returns 422 (anti-enumeration)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        payload: {
          email: 'nonexistent@example.com',
          password: 'SomePass123!',
        },
      });

      expect(res.statusCode).toBe(422);
    });

    it('with missing fields returns 400', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        payload: {
          email: 'test@example.com',
        },
      });

      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // Login Step 2 — MFA (TOTP)
  // =========================================================================

  describe('POST /api/v1/auth/login/mfa', () => {
    it('with valid TOTP sets session cookie', async () => {
      const password = 'SecurePass123!';
      const passwordHash = await argon2Hash(password, {
        memoryCost: 19456,
        timeCost: 2,
        parallelism: 1,
      });
      const encryptedSecret = encryptTotpSecret(MOCK_TOTP_SECRET);
      const userId = newUserId();

      createdUsers.push({
        userId,
        email: 'mfa@example.com',
        passwordHash,
        mfaConfigured: true,
        totpSecretEncrypted: encryptedSecret,
        failedLoginCount: 0,
        lockedUntil: null,
        isActive: true,
      });

      // Step 1: login to get mfa_session_token
      const loginRes = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        payload: { email: 'mfa@example.com', password },
      });
      const mfaSessionToken = JSON.parse(loginRes.body).data.mfa_session_token;

      // Step 2: verify TOTP with the code our mock accepts
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login/mfa',
        payload: {
          mfa_session_token: mfaSessionToken,
          totp_code: VALID_TOTP_CODE,
        },
      });

      expect(res.statusCode).toBe(200);

      // Verify Set-Cookie header
      const setCookie = res.headers['set-cookie'] as string;
      expect(setCookie).toBeDefined();
      expect(setCookie).toContain('session=');
      expect(setCookie).toContain('HttpOnly');
      expect(setCookie).toContain('Secure');
      expect(setCookie).toContain('SameSite=Lax');
      expect(setCookie).toContain('Path=/');
      expect(setCookie).toContain('Max-Age=86400');
    });

    it('with invalid TOTP returns 422', async () => {
      const mfaSessionToken = createMfaSessionToken(FIXED_USER_ID);

      // Seed user with MFA
      const fixedUser = createdUsers.find((u) => u.userId === FIXED_USER_ID);
      if (fixedUser) {
        fixedUser.totpSecretEncrypted = encryptTotpSecret(MOCK_TOTP_SECRET);
        fixedUser.mfaConfigured = true;
      }

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login/mfa',
        payload: {
          mfa_session_token: mfaSessionToken,
          totp_code: '000000',
        },
      });

      expect(res.statusCode).toBe(422);
    });

    it('with expired MFA session token returns 422', async () => {
      // Create an expired token by manipulating time
      const payload = JSON.stringify({
        userId: FIXED_USER_ID,
        exp: Date.now() - 1000, // already expired
      });
      const payloadB64 = Buffer.from(payload).toString('base64url');
      const { createHmac } = await import('node:crypto');
      const sig = createHmac('sha256', process.env.SESSION_SECRET!)
        .update(payloadB64)
        .digest('base64url');
      const expiredToken = `${payloadB64}.${sig}`;

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login/mfa',
        payload: {
          mfa_session_token: expiredToken,
          totp_code: '123456',
        },
      });

      expect(res.statusCode).toBe(422);
    });
  });

  // =========================================================================
  // Login Step 2 — Recovery Code
  // =========================================================================

  describe('POST /api/v1/auth/login/recovery', () => {
    it('with valid code sets session cookie', async () => {
      const password = 'SecurePass123!';
      const passwordHash = await argon2Hash(password, {
        memoryCost: 19456,
        timeCost: 2,
        parallelism: 1,
      });
      const encryptedSecret = encryptTotpSecret(MOCK_TOTP_SECRET);
      const userId = newUserId();

      createdUsers.push({
        userId,
        email: 'recovery@example.com',
        passwordHash,
        mfaConfigured: true,
        totpSecretEncrypted: encryptedSecret,
        failedLoginCount: 0,
        lockedUntil: null,
        isActive: true,
      });

      // Create a recovery code for this user
      const recoveryPlaintext = 'ABCD1234';
      const recoveryHash = await argon2Hash(recoveryPlaintext, {
        memoryCost: 19456,
        timeCost: 2,
        parallelism: 1,
      });
      recoveryCodes.push({
        codeId: `recovery-code-${userId}`,
        codeHash: recoveryHash,
        used: false,
        userId,
      });

      // Step 1: login
      const loginRes = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        payload: { email: 'recovery@example.com', password },
      });
      const mfaSessionToken = JSON.parse(loginRes.body).data.mfa_session_token;

      // Step 2: use recovery code (with dash for realism)
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login/recovery',
        payload: {
          mfa_session_token: mfaSessionToken,
          recovery_code: 'ABCD-1234',
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.message).toBe('Login successful');
      expect(typeof body.data.remaining_codes).toBe('number');

      // Verify Set-Cookie header
      const setCookie = res.headers['set-cookie'] as string;
      expect(setCookie).toBeDefined();
      expect(setCookie).toContain('session=');
      expect(setCookie).toContain('HttpOnly');
    });

    it('with invalid recovery code returns 422', async () => {
      const mfaSessionToken = createMfaSessionToken(FIXED_USER_ID);

      const fixedUser = createdUsers.find((u) => u.userId === FIXED_USER_ID);
      if (fixedUser) {
        fixedUser.mfaConfigured = true;
        fixedUser.totpSecretEncrypted = encryptTotpSecret(MOCK_TOTP_SECRET);
      }

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login/recovery',
        payload: {
          mfa_session_token: mfaSessionToken,
          recovery_code: 'INVALID-CODE',
        },
      });

      expect(res.statusCode).toBe(422);
    });
  });

  // =========================================================================
  // Password Reset
  // =========================================================================

  describe('POST /api/v1/auth/password/reset-request', () => {
    it('always returns 200 (anti-enumeration)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/password/reset-request',
        payload: { email: 'nobody@example.com' },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.message).toBeDefined();
    });

    it('returns 200 for existing user too', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/password/reset-request',
        payload: { email: 'authed@example.com' },
      });

      expect(res.statusCode).toBe(200);
    });

    it('with invalid email returns 400', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/password/reset-request',
        payload: { email: 'not-an-email' },
      });

      expect(res.statusCode).toBe(400);
    });
  });

  describe('POST /api/v1/auth/password/reset', () => {
    it('with valid token resets password', async () => {
      // Request a password reset for the seeded user
      await app.inject({
        method: 'POST',
        url: '/api/v1/auth/password/reset-request',
        payload: { email: 'authed@example.com' },
      });

      // Get the emitted event to extract the raw token
      const emitCall = mockEvents.emit.mock.calls.find(
        (c: any[]) => c[0] === 'USER_PASSWORD_RESET_REQUESTED',
      );
      expect(emitCall).toBeDefined();
      const rawToken = emitCall![1].resetToken as string;

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/password/reset',
        payload: {
          token: rawToken,
          new_password: 'NewSecurePass123!',
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.message).toContain('Password has been reset');
    });

    it('with invalid token returns 422', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/password/reset',
        payload: {
          token: '00000000-0000-0000-0000-000000000099',
          new_password: 'NewSecurePass123!',
        },
      });

      expect(res.statusCode).toBe(422);
    });

    it('with weak new password returns 400', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/password/reset',
        payload: {
          token: '00000000-0000-0000-0000-000000000099',
          new_password: 'weak',
        },
      });

      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // MFA Setup (authenticated)
  // =========================================================================

  describe('POST /api/v1/auth/mfa/setup', () => {
    it('returns QR code URI and manual key when authenticated', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/mfa/setup',
        headers: {
          cookie: `session=${FIXED_SESSION_TOKEN}`,
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.qr_code_uri).toBeDefined();
      expect(body.data.manual_key).toBeDefined();
      expect(body.data.qr_code_uri).toContain('otpauth://');
    });

    it('returns 401 without session cookie', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/mfa/setup',
      });

      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // MFA Confirm (authenticated)
  // =========================================================================

  describe('POST /api/v1/auth/mfa/confirm', () => {
    it('with valid TOTP returns recovery codes', async () => {
      // First, initiate MFA setup
      await app.inject({
        method: 'POST',
        url: '/api/v1/auth/mfa/setup',
        headers: { cookie: `session=${FIXED_SESSION_TOKEN}` },
      });

      // The mock authenticator returns MOCK_TOTP_SECRET and accepts VALID_TOTP_CODE
      const user = createdUsers.find((u) => u.userId === FIXED_USER_ID);
      expect(user?.totpSecretEncrypted).toBeDefined();

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/mfa/confirm',
        headers: { cookie: `session=${FIXED_SESSION_TOKEN}` },
        payload: { totp_code: VALID_TOTP_CODE },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.recovery_codes).toBeDefined();
      expect(Array.isArray(body.data.recovery_codes)).toBe(true);
      expect(body.data.recovery_codes.length).toBe(10);
    });

    it('returns 401 without session cookie', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/mfa/confirm',
        payload: { totp_code: '123456' },
      });

      expect(res.statusCode).toBe(401);
    });

    it('with invalid TOTP code format returns 400', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/mfa/confirm',
        headers: { cookie: `session=${FIXED_SESSION_TOKEN}` },
        payload: { totp_code: 'abc' },
      });

      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // Logout (authenticated)
  // =========================================================================

  describe('POST /api/v1/auth/logout', () => {
    it('clears session cookie', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/logout',
        headers: {
          cookie: `session=${FIXED_SESSION_TOKEN}`,
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.message).toContain('Logged out');

      // Verify Set-Cookie clears the session
      const setCookie = res.headers['set-cookie'] as string;
      expect(setCookie).toBeDefined();
      expect(setCookie).toContain('session=;');
      expect(setCookie).toContain('Max-Age=0');
    });

    it('returns 401 without session cookie', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/logout',
      });

      expect(res.statusCode).toBe(401);
    });
  });
});
