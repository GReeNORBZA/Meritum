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
} from '../../../src/domains/iam/iam.service.js';
import { type AuthHandlerDeps } from '../../../src/domains/iam/iam.handlers.js';
import { randomBytes } from 'node:crypto';
import { hashToken } from '../../../src/domains/iam/iam.service.js';

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

let users: MockUser[] = [];
let sessions: MockSession[] = [];
let auditEntries: Array<Record<string, unknown>> = [];

// Fixed test user/session
const FIXED_SESSION_TOKEN = randomBytes(32).toString('hex');
const FIXED_SESSION_TOKEN_HASH = hashToken(FIXED_SESSION_TOKEN);
const FIXED_USER_ID = '22222222-0000-0000-0000-000000000001';
const FIXED_SESSION_ID = '33333333-0000-0000-0000-000000000001';

let nextSessionId = 1;
function newSessionId() {
  return `44444444-0000-0000-0000-${String(nextSessionId++).padStart(12, '0')}`;
}

// ---------------------------------------------------------------------------
// Mock repositories
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    createSession: vi.fn(async (data: any) => {
      const session: MockSession = {
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
      sessions.push(session);
      return { sessionId: session.sessionId };
    }),
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
    revokeSession: vi.fn(async (sessionId: string, reason: string) => {
      const session = sessions.find((s) => s.sessionId === sessionId);
      if (session) {
        session.revoked = true;
        session.revokedReason = reason;
      }
    }),
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

function createMockAuditRepo() {
  return {
    appendAuditLog: vi.fn(async (entry: Record<string, unknown>) => {
      auditEntries.push(entry);
    }),
  };
}

function createMockEvents() {
  return { emit: vi.fn() };
}

// Stubs for deps not exercised in session tests
function createStubServiceDeps(): ServiceDeps {
  return {
    userRepo: { createUser: vi.fn(), findUserByEmail: vi.fn(), updateUser: vi.fn() },
    verificationTokenRepo: { createVerificationToken: vi.fn(), findVerificationTokenByHash: vi.fn(), markVerificationTokenUsed: vi.fn() },
    auditRepo: createMockAuditRepo(),
    events: createMockEvents(),
  };
}

function createStubMfaDeps(): MfaServiceDeps {
  return {
    userRepo: { findUserById: vi.fn(), setMfaSecret: vi.fn(), setMfaConfigured: vi.fn() },
    recoveryCodeRepo: { createRecoveryCodes: vi.fn() },
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

function createStubAccountDeps(): AccountServiceDeps {
  return {
    userRepo: { findUserById: vi.fn(), updateUser: vi.fn(), deactivateUser: vi.fn() },
    sessionRepo: { revokeAllUserSessions: vi.fn() },
    linkageRepo: { listDelegatesForPhysician: vi.fn(async () => []), deactivateLinkage: vi.fn() },
    auditRepo: createMockAuditRepo(),
    events: createMockEvents(),
  };
}

function createStubAuditLogDeps(): AuditLogServiceDeps {
  return {
    auditLogRepo: { queryAuditLog: vi.fn(async () => ({ data: [], total: 0 })) },
    auditRepo: createMockAuditRepo(),
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let mockSessionRepo: ReturnType<typeof createMockSessionRepo>;
let mockAuditRepo: ReturnType<typeof createMockAuditRepo>;

async function buildTestApp(): Promise<FastifyInstance> {
  mockSessionRepo = createMockSessionRepo();
  mockAuditRepo = createMockAuditRepo();
  const mockEvents = createMockEvents();

  const sessionDeps: SessionManagementDeps = {
    sessionRepo: mockSessionRepo,
    auditRepo: mockAuditRepo,
    events: mockEvents,
  };

  const handlerDeps: AuthHandlerDeps = {
    serviceDeps: createStubServiceDeps(),
    mfaDeps: createStubMfaDeps(),
    loginDeps: createStubLoginDeps(),
    passwordResetDeps: createStubPasswordResetDeps(),
    sessionDeps,
    delegateDeps: createStubDelegateDeps(),
    accountDeps: createStubAccountDeps(),
    auditLogDeps: createStubAuditLogDeps(),
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
// Tests
// ---------------------------------------------------------------------------

describe('IAM Sessions Integration Tests', () => {
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
    nextSessionId = 1;

    // Seed the authenticated user and session
    users.push({
      userId: FIXED_USER_ID,
      email: 'authed@example.com',
      passwordHash: 'hashed',
      mfaConfigured: true,
      totpSecretEncrypted: null,
      failedLoginCount: 0,
      lockedUntil: null,
      isActive: true,
      role: 'PHYSICIAN',
      subscriptionStatus: 'TRIAL',
    });
    sessions.push({
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
  // GET /api/v1/sessions
  // =========================================================================

  describe('GET /api/v1/sessions', () => {
    it('returns active sessions for authenticated user', async () => {
      // Add a second session for the user
      sessions.push({
        sessionId: newSessionId(),
        userId: FIXED_USER_ID,
        tokenHash: 'other-hash',
        ipAddress: '10.0.0.1',
        userAgent: 'chrome',
        createdAt: new Date(),
        lastActiveAt: new Date(),
        revoked: false,
        revokedReason: null,
      });

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/sessions',
        headers: { cookie: `session=${FIXED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toBeDefined();
      expect(Array.isArray(body.data)).toBe(true);
      expect(body.data.length).toBe(2);
      expect(body.data[0].sessionId).toBeDefined();
      expect(body.data[0].ipAddress).toBeDefined();
      expect(body.data[0].userAgent).toBeDefined();
    });

    it('returns 401 without session cookie', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/sessions',
      });

      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // DELETE /api/v1/sessions/:id
  // =========================================================================

  describe('DELETE /api/v1/sessions/:id', () => {
    it('revokes specific session', async () => {
      // Add a second session to revoke
      const secondSession: MockSession = {
        sessionId: newSessionId(),
        userId: FIXED_USER_ID,
        tokenHash: 'revoke-hash',
        ipAddress: '10.0.0.1',
        userAgent: 'chrome',
        createdAt: new Date(),
        lastActiveAt: new Date(),
        revoked: false,
        revokedReason: null,
      };
      sessions.push(secondSession);

      const res = await app.inject({
        method: 'DELETE',
        url: `/api/v1/sessions/${secondSession.sessionId}`,
        headers: { cookie: `session=${FIXED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(204);

      // Verify the session was revoked
      expect(mockSessionRepo.revokeSession).toHaveBeenCalledWith(
        secondSession.sessionId,
        'revoked_remote',
      );
    });

    it('returns 422 for non-existent session', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: '/api/v1/sessions/00000000-0000-0000-0000-000000000099',
        headers: { cookie: `session=${FIXED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(422);
    });

    it('returns 400 for non-UUID param', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: '/api/v1/sessions/not-a-uuid',
        headers: { cookie: `session=${FIXED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without session cookie', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: '/api/v1/sessions/00000000-0000-0000-0000-000000000099',
      });

      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // DELETE /api/v1/sessions
  // =========================================================================

  describe('DELETE /api/v1/sessions', () => {
    it('revokes all other sessions except current', async () => {
      // Add two more sessions
      sessions.push({
        sessionId: newSessionId(),
        userId: FIXED_USER_ID,
        tokenHash: 'other1',
        ipAddress: '10.0.0.1',
        userAgent: 'chrome',
        createdAt: new Date(),
        lastActiveAt: new Date(),
        revoked: false,
        revokedReason: null,
      });
      sessions.push({
        sessionId: newSessionId(),
        userId: FIXED_USER_ID,
        tokenHash: 'other2',
        ipAddress: '10.0.0.2',
        userAgent: 'firefox',
        createdAt: new Date(),
        lastActiveAt: new Date(),
        revoked: false,
        revokedReason: null,
      });

      const res = await app.inject({
        method: 'DELETE',
        url: '/api/v1/sessions',
        headers: { cookie: `session=${FIXED_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.message).toContain('revoked');

      // Verify revokeAllUserSessions was called with the current session excluded
      expect(mockSessionRepo.revokeAllUserSessions).toHaveBeenCalledWith(
        FIXED_USER_ID,
        FIXED_SESSION_ID,
        'revoked_remote',
      );
    });

    it('returns 401 without session cookie', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: '/api/v1/sessions',
      });

      expect(res.statusCode).toBe(401);
    });
  });
});
