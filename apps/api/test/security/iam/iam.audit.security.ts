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

vi.mock('otplib', () => {
  const mockAuthenticator = {
    options: {},
    generateSecret: vi.fn(() => 'JBSWY3DPEHPK3PXP'),
    keyuri: vi.fn(
      (email: string, issuer: string, secret: string) =>
        `otpauth://totp/${issuer}:${email}?secret=${secret}&issuer=${issuer}`,
    ),
    verify: vi.fn(({ token }: { token: string }) => token === '123456'),
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
  hashToken,
  encryptTotpSecret,
  createMfaSessionToken,
} from '../../../src/domains/iam/iam.service.js';
import { type AuthHandlerDeps } from '../../../src/domains/iam/iam.handlers.js';
import { AuditAction, AuditCategory } from '@meritum/shared/constants/iam.constants.js';
import { randomBytes } from 'node:crypto';
import { hash as argon2Hash } from '@node-rs/argon2';

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_USER_ID = '11111111-0000-0000-0000-000000000001';
const PHYSICIAN_SESSION_ID = '11111111-0000-0000-0000-000000000011';
const PHYSICIAN_EXTRA_SESSION_ID = '11111111-0000-0000-0000-000000000022';

// Tokens that pass UUID validation
const VALID_VERIFICATION_TOKEN = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee01';
const VALID_RESET_TOKEN = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee02';
const VALID_INVITE_TOKEN = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee03';
const LINKAGE_ID = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee04';
const DELEGATE_USER_ID = 'dddd4444-0000-0000-0000-000000000001';

// ---------------------------------------------------------------------------
// Mock stores
// ---------------------------------------------------------------------------

interface MockUser {
  userId: string;
  email: string;
  passwordHash: string;
  fullName: string;
  phone: string | null;
  mfaConfigured: boolean;
  totpSecretEncrypted: string | null;
  failedLoginCount: number;
  lockedUntil: Date | null;
  isActive: boolean;
  role: string;
  subscriptionStatus: string;
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

interface MockLinkage {
  linkageId: string;
  physicianUserId: string;
  delegateUserId: string;
  permissions: string[];
  canApproveBatches: boolean;
  isActive: boolean;
}

let users: MockUser[] = [];
let sessions: MockSession[] = [];
let linkages: MockLinkage[] = [];

// Shared audit store: all deps write to this single array
let auditEntries: Array<Record<string, unknown>> = [];

// Track createUser calls
let createUserShouldFail = false;

// ---------------------------------------------------------------------------
// Mock repositories
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    createSession: vi.fn(async (data: any) => {
      return { sessionId: '44444444-0000-0000-0000-000000000001' };
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
          role: user.role,
          subscriptionStatus: user.subscriptionStatus,
        },
      };
    }),
    refreshSession: vi.fn(async () => {}),
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
    revokeAllUserSessions: vi.fn(async (userId: string, exceptSessionId?: string) => {
      for (const s of sessions) {
        if (s.userId === userId && s.sessionId !== exceptSessionId) {
          s.revoked = true;
        }
      }
    }),
  };
}

function createSharedAuditRepo() {
  return {
    appendAuditLog: vi.fn(async (entry: Record<string, unknown>) => {
      auditEntries.push(entry);
    }),
  };
}

function createMockEvents() {
  return { emit: vi.fn() };
}

// ---------------------------------------------------------------------------
// Test App Builder — all deps share the same auditRepo
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let sharedAuditRepo: ReturnType<typeof createSharedAuditRepo>;
let mockSessionRepo: ReturnType<typeof createMockSessionRepo>;

// Argon2 options matching service
const ARGON2_OPTIONS = { memoryCost: 19456, timeCost: 2, parallelism: 1 };

// Pre-hashed password for test user
let physicianPasswordHash: string;

async function buildTestApp(): Promise<FastifyInstance> {
  // Pre-compute the password hash once
  physicianPasswordHash = await argon2Hash('SecurePass123!@#', ARGON2_OPTIONS);

  mockSessionRepo = createMockSessionRepo();
  sharedAuditRepo = createSharedAuditRepo();
  const sharedEvents = createMockEvents();

  const sessionDeps: SessionManagementDeps = {
    sessionRepo: mockSessionRepo,
    auditRepo: sharedAuditRepo,
    events: sharedEvents,
  };

  const serviceDeps: ServiceDeps = {
    userRepo: {
      createUser: vi.fn(async (data: any) => {
        if (createUserShouldFail) {
          const error = new Error('duplicate key') as any;
          error.code = '23505';
          throw error;
        }
        return { userId: 'new-user-id-001', email: data.email };
      }),
      findUserByEmail: vi.fn(async (email: string) => {
        const user = users.find((u) => u.email === email.toLowerCase());
        if (!user) return undefined;
        return { userId: user.userId, email: user.email };
      }),
      updateUser: vi.fn(async () => ({ userId: PHYSICIAN_USER_ID })),
    },
    verificationTokenRepo: {
      createVerificationToken: vi.fn(async () => ({ tokenHash: 'hash' })),
      findVerificationTokenByHash: vi.fn(async (tokenHash: string) => {
        if (tokenHash === hashToken(VALID_VERIFICATION_TOKEN)) {
          return {
            userId: PHYSICIAN_USER_ID,
            tokenHash,
            expiresAt: new Date(Date.now() + 86400000),
            used: false,
          };
        }
        return undefined;
      }),
      markVerificationTokenUsed: vi.fn(async () => {}),
    },
    auditRepo: sharedAuditRepo,
    events: sharedEvents,
  };

  const mfaDeps: MfaServiceDeps = {
    userRepo: {
      findUserById: vi.fn(async (userId: string) => {
        const user = users.find((u) => u.userId === userId);
        if (!user) return undefined;
        return {
          userId: user.userId,
          email: user.email,
          totpSecretEncrypted: user.totpSecretEncrypted,
          mfaConfigured: user.mfaConfigured,
        };
      }),
      setMfaSecret: vi.fn(async () => {}),
      setMfaConfigured: vi.fn(async () => {}),
    },
    recoveryCodeRepo: {
      createRecoveryCodes: vi.fn(async () => []),
    },
    auditRepo: sharedAuditRepo,
    events: sharedEvents,
  };

  const loginDeps: LoginServiceDeps = {
    userRepo: {
      findUserByEmail: vi.fn(async (email: string) => {
        const user = users.find((u) => u.email === email.toLowerCase());
        if (!user) return undefined;
        return {
          userId: user.userId,
          email: user.email,
          passwordHash: user.passwordHash,
          mfaConfigured: user.mfaConfigured,
          totpSecretEncrypted: user.totpSecretEncrypted,
          failedLoginCount: user.failedLoginCount,
          lockedUntil: user.lockedUntil,
          isActive: user.isActive,
        };
      }),
      findUserById: vi.fn(async (userId: string) => {
        const user = users.find((u) => u.userId === userId);
        if (!user) return undefined;
        return {
          userId: user.userId,
          email: user.email,
          passwordHash: user.passwordHash,
          mfaConfigured: user.mfaConfigured,
          totpSecretEncrypted: user.totpSecretEncrypted,
          failedLoginCount: user.failedLoginCount,
          lockedUntil: user.lockedUntil,
          isActive: user.isActive,
        };
      }),
      incrementFailedLogin: vi.fn(async () => {}),
      resetFailedLogin: vi.fn(async () => {}),
    },
    sessionRepo: {
      createSession: vi.fn(async () => ({ sessionId: 'login-session-001' })),
    },
    recoveryCodeRepo: {
      findUnusedRecoveryCodes: vi.fn(async (userId: string) => {
        // Return one valid code that matches 'ABCD-EFGH' when normalized
        return [
          {
            codeId: 'code-id-001',
            codeHash: await argon2Hash('ABCDEFGH', ARGON2_OPTIONS),
            used: false,
          },
        ];
      }),
      markRecoveryCodeUsed: vi.fn(async () => {}),
      countRemainingCodes: vi.fn(async () => 9),
    },
    auditRepo: sharedAuditRepo,
    events: sharedEvents,
  };

  const passwordResetDeps: PasswordResetDeps = {
    userRepo: {
      findUserByEmail: vi.fn(async (email: string) => {
        const user = users.find((u) => u.email === email.toLowerCase());
        if (!user) return undefined;
        return { userId: user.userId, email: user.email };
      }),
      setPasswordHash: vi.fn(async () => {}),
    },
    tokenRepo: {
      createPasswordResetToken: vi.fn(async () => ({ tokenHash: 'hash' })),
      findPasswordResetTokenByHash: vi.fn(async (tokenHash: string) => {
        if (tokenHash === hashToken(VALID_RESET_TOKEN)) {
          return {
            userId: PHYSICIAN_USER_ID,
            tokenHash,
            expiresAt: new Date(Date.now() + 3600000),
            used: false,
          };
        }
        return undefined;
      }),
      markPasswordResetTokenUsed: vi.fn(async () => {}),
    },
    sessionRepo: { revokeAllUserSessions: vi.fn(async () => {}) },
    auditRepo: sharedAuditRepo,
    events: sharedEvents,
  };

  const delegateDeps: DelegateServiceDeps = {
    userRepo: {
      findUserByEmail: vi.fn(async (email: string) => {
        const user = users.find((u) => u.email === email.toLowerCase());
        if (!user) return undefined;
        return { userId: user.userId, email: user.email, role: user.role };
      }),
      findUserById: vi.fn(async (userId: string) => {
        const user = users.find((u) => u.userId === userId);
        if (!user) return undefined;
        return { userId: user.userId, email: user.email, role: user.role };
      }),
      createUser: vi.fn(async (data: any) => {
        return { userId: 'new-delegate-id-001', email: data.email };
      }),
    },
    invitationRepo: {
      createInvitation: vi.fn(async () => ({ invitationId: 'invitation-001' })),
      findInvitationByTokenHash: vi.fn(async (tokenHash: string) => {
        if (tokenHash === hashToken(VALID_INVITE_TOKEN)) {
          return {
            invitationId: 'invitation-001',
            physicianUserId: PHYSICIAN_USER_ID,
            delegateEmail: 'newdelegate@example.com',
            tokenHash,
            permissions: ['CLAIM_VIEW', 'CLAIM_CREATE'],
            expiresAt: new Date(Date.now() + 86400000),
            accepted: false,
          };
        }
        return undefined;
      }),
      markInvitationAccepted: vi.fn(async () => {}),
    },
    linkageRepo: {
      createDelegateLinkage: vi.fn(async (data: any) => ({
        linkageId: 'linkage-new-001',
        physicianUserId: data.physicianUserId,
        delegateUserId: data.delegateUserId,
        permissions: data.permissions,
        canApproveBatches: data.canApproveBatches,
        isActive: true,
      })),
      findLinkage: vi.fn(async (physicianUserId: string, delegateUserId: string) => {
        return linkages.find(
          (l) => l.physicianUserId === physicianUserId && l.delegateUserId === delegateUserId,
        ) ?? null;
      }),
      findLinkageById: vi.fn(async (linkageId: string) => {
        return linkages.find((l) => l.linkageId === linkageId) ?? null;
      }),
      listDelegatesForPhysician: vi.fn(async (physicianUserId: string) => {
        return linkages
          .filter((l) => l.physicianUserId === physicianUserId && l.isActive)
          .map((l) => {
            const delegateUser = users.find((u) => u.userId === l.delegateUserId);
            return {
              linkage: l,
              user: {
                userId: l.delegateUserId,
                fullName: delegateUser?.fullName ?? 'Unknown',
                email: delegateUser?.email ?? 'unknown@example.com',
              },
              lastLogin: null,
            };
          });
      }),
      listPhysiciansForDelegate: vi.fn(async () => []),
      updateLinkagePermissions: vi.fn(async (linkageId: string, permissions: string[], canApproveBatches: boolean) => {
        const linkage = linkages.find((l) => l.linkageId === linkageId);
        if (!linkage) return null;
        linkage.permissions = permissions;
        linkage.canApproveBatches = canApproveBatches;
        return { linkageId };
      }),
      deactivateLinkage: vi.fn(async (linkageId: string) => {
        const linkage = linkages.find((l) => l.linkageId === linkageId);
        if (!linkage) return null;
        linkage.isActive = false;
        return { linkageId };
      }),
    },
    sessionRepo: { revokeAllUserSessions: vi.fn(async () => {}) },
    auditRepo: sharedAuditRepo,
    events: sharedEvents,
  };

  const accountDeps: AccountServiceDeps = {
    userRepo: {
      findUserById: vi.fn(async (userId: string) => {
        const user = users.find((u) => u.userId === userId);
        if (!user) return undefined;
        return {
          userId: user.userId,
          email: user.email,
          fullName: user.fullName,
          phone: user.phone,
          role: user.role,
          subscriptionStatus: user.subscriptionStatus,
          mfaConfigured: user.mfaConfigured,
          passwordHash: user.passwordHash,
          totpSecretEncrypted: user.totpSecretEncrypted,
          isActive: user.isActive,
        };
      }),
      updateUser: vi.fn(async () => ({ userId: PHYSICIAN_USER_ID })),
      deactivateUser: vi.fn(async () => {}),
    },
    sessionRepo: { revokeAllUserSessions: vi.fn(async () => {}) },
    linkageRepo: {
      listDelegatesForPhysician: vi.fn(async () => []),
      deactivateLinkage: vi.fn(async () => ({ linkageId: 'mock' })),
    },
    auditRepo: sharedAuditRepo,
    events: sharedEvents,
  };

  const auditLogDeps: AuditLogServiceDeps = {
    auditLogRepo: {
      queryAuditLog: vi.fn(async () => ({ data: [], total: 0 })),
    },
    auditRepo: sharedAuditRepo,
  };

  const handlerDeps: AuthHandlerDeps = {
    serviceDeps,
    mfaDeps,
    loginDeps,
    passwordResetDeps,
    sessionDeps: sessionDeps,
    delegateDeps,
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
// Helpers
// ---------------------------------------------------------------------------

function physicianCookie(): string {
  return `session=${PHYSICIAN_SESSION_TOKEN}`;
}

function seedPhysician() {
  users.push({
    userId: PHYSICIAN_USER_ID,
    email: 'physician@example.com',
    passwordHash: physicianPasswordHash,
    fullName: 'Dr. Test Physician',
    phone: '+14035551234',
    mfaConfigured: true,
    totpSecretEncrypted: encryptTotpSecret('JBSWY3DPEHPK3PXP'),
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    role: 'PHYSICIAN',
    subscriptionStatus: 'TRIAL',
  });
  sessions.push({
    sessionId: PHYSICIAN_SESSION_ID,
    userId: PHYSICIAN_USER_ID,
    tokenHash: PHYSICIAN_SESSION_TOKEN_HASH,
    ipAddress: '10.0.0.1',
    userAgent: 'physician-browser',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });
  // Extra session for revocation tests
  sessions.push({
    sessionId: PHYSICIAN_EXTRA_SESSION_ID,
    userId: PHYSICIAN_USER_ID,
    tokenHash: 'extra-session-hash',
    ipAddress: '10.0.0.2',
    userAgent: 'physician-mobile',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });
}

function seedLinkage() {
  users.push({
    userId: DELEGATE_USER_ID,
    email: 'delegate@example.com',
    passwordHash: 'hashed',
    fullName: 'Test Delegate',
    phone: null,
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    role: 'DELEGATE',
    subscriptionStatus: 'TRIAL',
  });
  linkages.push({
    linkageId: LINKAGE_ID,
    physicianUserId: PHYSICIAN_USER_ID,
    delegateUserId: DELEGATE_USER_ID,
    permissions: ['CLAIM_VIEW', 'CLAIM_CREATE'],
    canApproveBatches: false,
    isActive: true,
  });
}

function findAuditEntry(action: string): Record<string, unknown> | undefined {
  return auditEntries.find((e) => e.action === action);
}

function findAllAuditEntries(action: string): Array<Record<string, unknown>> {
  return auditEntries.filter((e) => e.action === action);
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('IAM Audit Trail Completeness (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    users = [];
    sessions = [];
    linkages = [];
    auditEntries = [];
    createUserShouldFail = false;
    seedPhysician();
  });

  // =========================================================================
  // Authentication Events
  // =========================================================================

  describe('Authentication events', () => {
    it('successful login (step 1) produces auth.login_success audit entry with ip_address', async () => {
      await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        payload: { email: 'physician@example.com', password: 'SecurePass123!@#' },
      });

      const entry = findAuditEntry(AuditAction.AUTH_LOGIN_SUCCESS);
      expect(entry).toBeDefined();
      expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
      expect(entry!.category).toBe(AuditCategory.AUTH);
      expect(entry!.ipAddress).toBeDefined();
    });

    it('failed login produces auth.login_failed audit entry with ip_address', async () => {
      await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        payload: { email: 'physician@example.com', password: 'WrongPassword123!' },
      });

      const entry = findAuditEntry(AuditAction.AUTH_LOGIN_FAILED);
      expect(entry).toBeDefined();
      expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
      expect(entry!.category).toBe(AuditCategory.AUTH);
      expect(entry!.ipAddress).toBeDefined();
      expect((entry!.detail as any).reason).toBe('invalid_password');
    });

    it('MFA success (step 2 TOTP) produces auth.login_mfa_success audit entry', async () => {
      // Step 1: get mfa_session_token
      const step1Res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        payload: { email: 'physician@example.com', password: 'SecurePass123!@#' },
      });
      const { mfa_session_token } = JSON.parse(step1Res.body).data;

      auditEntries = []; // Clear step 1 audit entries

      // Step 2: verify TOTP
      await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login/mfa',
        payload: { mfa_session_token, totp_code: '123456' },
      });

      const entry = findAuditEntry(AuditAction.AUTH_LOGIN_MFA_SUCCESS);
      expect(entry).toBeDefined();
      expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
      expect(entry!.category).toBe(AuditCategory.AUTH);
      expect((entry!.detail as any).method).toBe('totp');
      expect(entry!.ipAddress).toBeDefined();
    });

    it('recovery code used produces auth.login_recovery_used with remaining count', async () => {
      // Step 1: get mfa_session_token
      const step1Res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        payload: { email: 'physician@example.com', password: 'SecurePass123!@#' },
      });
      const { mfa_session_token } = JSON.parse(step1Res.body).data;

      auditEntries = [];

      // Step 2: use recovery code
      await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login/recovery',
        payload: { mfa_session_token, recovery_code: 'ABCD-EFGH' },
      });

      const entry = findAuditEntry(AuditAction.AUTH_LOGIN_RECOVERY_USED);
      expect(entry).toBeDefined();
      expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
      expect(entry!.category).toBe(AuditCategory.AUTH);
      expect((entry!.detail as any).remaining_codes).toBe(9);
    });

    it('logout produces auth.logout audit entry', async () => {
      await app.inject({
        method: 'POST',
        url: '/api/v1/auth/logout',
        headers: { cookie: physicianCookie() },
      });

      const entry = findAuditEntry(AuditAction.AUTH_LOGOUT);
      expect(entry).toBeDefined();
      expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
      expect(entry!.category).toBe(AuditCategory.AUTH);
      expect(entry!.resourceType).toBe('session');
      expect(entry!.resourceId).toBe(PHYSICIAN_SESSION_ID);
    });

    it('session revoked produces auth.session_revoked audit entry', async () => {
      await app.inject({
        method: 'DELETE',
        url: `/api/v1/sessions/${PHYSICIAN_EXTRA_SESSION_ID}`,
        headers: { cookie: physicianCookie() },
      });

      const entry = findAuditEntry(AuditAction.AUTH_SESSION_REVOKED);
      expect(entry).toBeDefined();
      expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
      expect(entry!.category).toBe(AuditCategory.AUTH);
      expect(entry!.resourceType).toBe('session');
      expect(entry!.resourceId).toBe(PHYSICIAN_EXTRA_SESSION_ID);
    });

    it('revoke all sessions produces auth.session_revoked_all audit entry', async () => {
      await app.inject({
        method: 'DELETE',
        url: '/api/v1/sessions',
        headers: { cookie: physicianCookie() },
      });

      const entry = findAuditEntry(AuditAction.AUTH_SESSION_REVOKED_ALL);
      expect(entry).toBeDefined();
      expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
      expect(entry!.category).toBe(AuditCategory.AUTH);
      expect(entry!.resourceType).toBe('session');
    });

    it('user registration produces auth.registered audit entry', async () => {
      await app.inject({
        method: 'POST',
        url: '/api/v1/auth/register',
        payload: {
          email: 'newuser@example.com',
          password: 'SecurePass123!@#',
          full_name: 'New User',
          phone: '+14035559999',
        },
      });

      const entry = findAuditEntry(AuditAction.AUTH_REGISTERED);
      expect(entry).toBeDefined();
      expect(entry!.category).toBe(AuditCategory.AUTH);
      expect(entry!.resourceType).toBe('user');
      expect((entry!.detail as any).email).toBe('newuser@example.com');
    });

    it('email verification produces auth.email_verified audit entry', async () => {
      await app.inject({
        method: 'POST',
        url: '/api/v1/auth/verify-email',
        payload: { token: VALID_VERIFICATION_TOKEN },
      });

      const entry = findAuditEntry(AuditAction.AUTH_EMAIL_VERIFIED);
      expect(entry).toBeDefined();
      expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
      expect(entry!.category).toBe(AuditCategory.AUTH);
      expect(entry!.resourceType).toBe('user');
    });

    it('password reset request produces auth.password_reset_requested audit entry', async () => {
      await app.inject({
        method: 'POST',
        url: '/api/v1/auth/password/reset-request',
        payload: { email: 'physician@example.com' },
      });

      const entry = findAuditEntry(AuditAction.AUTH_PASSWORD_RESET_REQUESTED);
      expect(entry).toBeDefined();
      expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
      expect(entry!.category).toBe(AuditCategory.AUTH);
    });

    it('password reset completion produces auth.password_reset_completed audit entry', async () => {
      await app.inject({
        method: 'POST',
        url: '/api/v1/auth/password/reset',
        payload: {
          token: VALID_RESET_TOKEN,
          new_password: 'NewSecurePass456!@#',
        },
      });

      const entry = findAuditEntry(AuditAction.AUTH_PASSWORD_RESET_COMPLETED);
      expect(entry).toBeDefined();
      expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
      expect(entry!.category).toBe(AuditCategory.AUTH);
    });

    it('failed MFA (step 2) produces auth.login_mfa_failed audit entry', async () => {
      // Step 1: get mfa_session_token
      const step1Res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        payload: { email: 'physician@example.com', password: 'SecurePass123!@#' },
      });
      const { mfa_session_token } = JSON.parse(step1Res.body).data;

      auditEntries = [];

      // Step 2: wrong TOTP code
      await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login/mfa',
        payload: { mfa_session_token, totp_code: '999999' },
      });

      const entry = findAuditEntry(AuditAction.AUTH_LOGIN_MFA_FAILED);
      expect(entry).toBeDefined();
      expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
      expect(entry!.category).toBe(AuditCategory.AUTH);
      expect((entry!.detail as any).method).toBe('totp');
    });
  });

  // =========================================================================
  // Delegate Events
  // =========================================================================

  describe('Delegate events', () => {
    it('delegate invited produces delegate.invited audit entry with delegate_email', async () => {
      await app.inject({
        method: 'POST',
        url: '/api/v1/delegates/invite',
        headers: { cookie: physicianCookie() },
        payload: { email: 'newdelegate@example.com', permissions: ['CLAIM_VIEW'] },
      });

      const entry = findAuditEntry(AuditAction.DELEGATE_INVITED);
      expect(entry).toBeDefined();
      expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
      expect(entry!.category).toBe(AuditCategory.DELEGATE);
      expect(entry!.resourceType).toBe('invitation');
      expect((entry!.detail as any).delegateEmail).toBe('newdelegate@example.com');
      expect((entry!.detail as any).permissions).toContain('CLAIM_VIEW');
    });

    it('invitation accepted produces delegate.accepted audit entry', async () => {
      await app.inject({
        method: 'POST',
        url: '/api/v1/delegates/accept',
        payload: {
          token: VALID_INVITE_TOKEN,
          full_name: 'New Delegate',
          password: 'DelegatePass123!@#',
        },
      });

      const entry = findAuditEntry(AuditAction.DELEGATE_ACCEPTED);
      expect(entry).toBeDefined();
      expect(entry!.category).toBe(AuditCategory.DELEGATE);
      expect(entry!.resourceType).toBe('delegate_linkage');
      expect((entry!.detail as any).physicianUserId).toBe(PHYSICIAN_USER_ID);
      expect((entry!.detail as any).permissions).toBeDefined();
    });

    it('delegate permissions updated produces delegate.permissions_updated with old/new permissions', async () => {
      seedLinkage();

      await app.inject({
        method: 'PATCH',
        url: `/api/v1/delegates/${LINKAGE_ID}/permissions`,
        headers: { cookie: physicianCookie() },
        payload: { permissions: ['CLAIM_VIEW', 'PATIENT_VIEW'] },
      });

      const entry = findAuditEntry(AuditAction.DELEGATE_PERMISSIONS_UPDATED);
      expect(entry).toBeDefined();
      expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
      expect(entry!.category).toBe(AuditCategory.DELEGATE);
      expect(entry!.resourceType).toBe('delegate_linkage');
      expect(entry!.resourceId).toBe(LINKAGE_ID);
      expect((entry!.detail as any).permissions).toEqual(['CLAIM_VIEW', 'PATIENT_VIEW']);
    });

    it('delegate revoked produces delegate.revoked audit entry', async () => {
      seedLinkage();

      await app.inject({
        method: 'DELETE',
        url: `/api/v1/delegates/${LINKAGE_ID}`,
        headers: { cookie: physicianCookie() },
      });

      const entry = findAuditEntry(AuditAction.DELEGATE_REVOKED);
      expect(entry).toBeDefined();
      expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
      expect(entry!.category).toBe(AuditCategory.DELEGATE);
      expect(entry!.resourceType).toBe('delegate_linkage');
      expect(entry!.resourceId).toBe(LINKAGE_ID);
      expect((entry!.detail as any).delegateUserId).toBe(DELEGATE_USER_ID);
    });
  });

  // =========================================================================
  // Account Events
  // =========================================================================

  describe('Account events', () => {
    it('account updated produces account.updated with changed fields', async () => {
      await app.inject({
        method: 'PATCH',
        url: '/api/v1/account',
        headers: { cookie: physicianCookie() },
        payload: { full_name: 'Dr. Updated Name', phone: '+14035559999' },
      });

      const entry = findAuditEntry(AuditAction.ACCOUNT_UPDATED);
      expect(entry).toBeDefined();
      expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
      expect(entry!.category).toBe(AuditCategory.ACCOUNT);
      expect(entry!.resourceType).toBe('user');
      expect(entry!.resourceId).toBe(PHYSICIAN_USER_ID);
      expect((entry!.detail as any).fields).toContain('fullName');
      expect((entry!.detail as any).fields).toContain('phone');
    });

    it('MFA setup confirmation produces auth.mfa_setup audit entry', async () => {
      // First initiate MFA setup
      await app.inject({
        method: 'POST',
        url: '/api/v1/auth/mfa/setup',
        headers: { cookie: physicianCookie() },
      });

      auditEntries = [];

      // Confirm MFA with valid TOTP
      await app.inject({
        method: 'POST',
        url: '/api/v1/auth/mfa/confirm',
        headers: { cookie: physicianCookie() },
        payload: { totp_code: '123456' },
      });

      const entry = findAuditEntry(AuditAction.AUTH_MFA_SETUP);
      expect(entry).toBeDefined();
      expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
      expect(entry!.category).toBe(AuditCategory.AUTH);
      expect(entry!.resourceType).toBe('user');
    });

    it('MFA reconfigured produces account.mfa_reconfigured audit entry', async () => {
      await app.inject({
        method: 'POST',
        url: '/api/v1/account/mfa/reconfigure',
        headers: { cookie: physicianCookie() },
        payload: { current_totp_code: '123456' },
      });

      const entry = findAuditEntry(AuditAction.ACCOUNT_MFA_RECONFIGURED);
      expect(entry).toBeDefined();
      expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
      expect(entry!.category).toBe(AuditCategory.ACCOUNT);
      expect(entry!.resourceType).toBe('user');
      expect(entry!.resourceId).toBe(PHYSICIAN_USER_ID);
    });

    it('recovery codes regenerated produces account.recovery_codes_regenerated audit entry', async () => {
      await app.inject({
        method: 'POST',
        url: '/api/v1/account/mfa/regenerate-codes',
        headers: { cookie: physicianCookie() },
        payload: { totp_code: '123456' },
      });

      const entry = findAuditEntry(AuditAction.ACCOUNT_RECOVERY_CODES_REGENERATED);
      expect(entry).toBeDefined();
      expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
      expect(entry!.category).toBe(AuditCategory.ACCOUNT);
      expect(entry!.resourceType).toBe('user');
      expect(entry!.resourceId).toBe(PHYSICIAN_USER_ID);
    });

    it('account deletion requested produces account.deletion_requested audit entry', async () => {
      await app.inject({
        method: 'POST',
        url: '/api/v1/account/delete',
        headers: { cookie: physicianCookie() },
        payload: {
          password: 'SecurePass123!@#',
          totp_code: '123456',
          confirmation: 'DELETE',
        },
      });

      const entry = findAuditEntry(AuditAction.ACCOUNT_DELETION_REQUESTED);
      expect(entry).toBeDefined();
      expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
      expect(entry!.category).toBe(AuditCategory.ACCOUNT);
      expect(entry!.resourceType).toBe('user');
      expect(entry!.resourceId).toBe(PHYSICIAN_USER_ID);
      expect((entry!.detail as any).scheduledDeletionDate).toBeDefined();
    });
  });

  // =========================================================================
  // Audit Log Integrity
  // =========================================================================

  describe('Audit log integrity', () => {
    it('no UPDATE endpoints exist for audit_log', async () => {
      // Attempt PUT and PATCH on audit-log endpoint — should return 404 (not registered)
      const putRes = await app.inject({
        method: 'PUT',
        url: '/api/v1/account/audit-log',
        headers: { cookie: physicianCookie() },
        payload: { action: 'tampered' },
      });
      // Fastify returns 404 for unregistered routes
      expect(putRes.statusCode).toBe(404);

      const patchRes = await app.inject({
        method: 'PATCH',
        url: '/api/v1/account/audit-log',
        headers: { cookie: physicianCookie() },
        payload: { action: 'tampered' },
      });
      expect(patchRes.statusCode).toBe(404);
    });

    it('no DELETE endpoints exist for audit_log', async () => {
      const deleteRes = await app.inject({
        method: 'DELETE',
        url: '/api/v1/account/audit-log',
        headers: { cookie: physicianCookie() },
      });
      expect(deleteRes.statusCode).toBe(404);

      // Also try with an ID parameter
      const deleteIdRes = await app.inject({
        method: 'DELETE',
        url: '/api/v1/account/audit-log/some-log-id',
        headers: { cookie: physicianCookie() },
      });
      expect(deleteIdRes.statusCode).toBe(404);
    });

    it('querying the audit log produces audit.queried entry', async () => {
      await app.inject({
        method: 'GET',
        url: '/api/v1/account/audit-log',
        headers: { cookie: physicianCookie() },
      });

      const entry = findAuditEntry(AuditAction.AUDIT_QUERIED);
      expect(entry).toBeDefined();
      expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
      expect(entry!.category).toBe(AuditCategory.AUDIT);
      expect(entry!.resourceType).toBe('audit_log');
    });

    it('querying audit log with filters records those filters in audit detail', async () => {
      await app.inject({
        method: 'GET',
        url: '/api/v1/account/audit-log?action=auth.login_success&category=auth',
        headers: { cookie: physicianCookie() },
      });

      const entry = findAuditEntry(AuditAction.AUDIT_QUERIED);
      expect(entry).toBeDefined();
      const detail = entry!.detail as any;
      expect(detail.filters).toBeDefined();
      expect(detail.filters.action).toBe('auth.login_success');
      expect(detail.filters.category).toBe('auth');
    });
  });

  // =========================================================================
  // Audit Entry Field Completeness
  // =========================================================================

  describe('Audit entry field completeness', () => {
    it('all audit entries have action and category fields', async () => {
      // Perform several actions
      await app.inject({
        method: 'POST',
        url: '/api/v1/auth/register',
        payload: {
          email: 'audittest@example.com',
          password: 'SecurePass123!@#',
          full_name: 'Audit Test',
          phone: '+14035559999',
        },
      });

      await app.inject({
        method: 'POST',
        url: '/api/v1/auth/logout',
        headers: { cookie: physicianCookie() },
      });

      expect(auditEntries.length).toBeGreaterThan(0);
      for (const entry of auditEntries) {
        expect(entry.action).toBeDefined();
        expect(typeof entry.action).toBe('string');
        expect(entry.category).toBeDefined();
        expect(typeof entry.category).toBe('string');
      }
    });

    it('state-changing audit entries include resourceType and resourceId', async () => {
      await app.inject({
        method: 'PATCH',
        url: '/api/v1/account',
        headers: { cookie: physicianCookie() },
        payload: { full_name: 'Dr. Field Check' },
      });

      const entry = findAuditEntry(AuditAction.ACCOUNT_UPDATED);
      expect(entry).toBeDefined();
      expect(entry!.resourceType).toBe('user');
      expect(entry!.resourceId).toBe(PHYSICIAN_USER_ID);
    });

    it('login audit entries include ipAddress', async () => {
      await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        payload: { email: 'physician@example.com', password: 'WrongPassword!' },
      });

      const entry = findAuditEntry(AuditAction.AUTH_LOGIN_FAILED);
      expect(entry).toBeDefined();
      expect(entry!.ipAddress).toBeDefined();
      expect(typeof entry!.ipAddress).toBe('string');
    });
  });

  // =========================================================================
  // Sensitive Data Exclusion in Audit Entries
  // =========================================================================

  describe('Sensitive data exclusion from audit entries', () => {
    it('registration audit entry does not contain plaintext password', async () => {
      await app.inject({
        method: 'POST',
        url: '/api/v1/auth/register',
        payload: {
          email: 'senstest@example.com',
          password: 'SecurePass123!@#',
          full_name: 'Sensitive Test',
          phone: '+14035559999',
        },
      });

      const auditString = JSON.stringify(auditEntries);
      expect(auditString).not.toContain('SecurePass123!@#');
    });

    it('login audit entries do not contain plaintext password', async () => {
      await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        payload: { email: 'physician@example.com', password: 'SecurePass123!@#' },
      });

      const auditString = JSON.stringify(auditEntries);
      expect(auditString).not.toContain('SecurePass123!@#');
    });

    it('password reset audit entry does not contain token or new password', async () => {
      await app.inject({
        method: 'POST',
        url: '/api/v1/auth/password/reset',
        payload: {
          token: VALID_RESET_TOKEN,
          new_password: 'NewSecurePass456!@#',
        },
      });

      const auditString = JSON.stringify(auditEntries);
      expect(auditString).not.toContain(VALID_RESET_TOKEN);
      expect(auditString).not.toContain('NewSecurePass456!@#');
    });

    it('account deletion audit entry does not contain password or TOTP code', async () => {
      await app.inject({
        method: 'POST',
        url: '/api/v1/account/delete',
        headers: { cookie: physicianCookie() },
        payload: {
          password: 'SecurePass123!@#',
          totp_code: '123456',
          confirmation: 'DELETE',
        },
      });

      const deletionEntry = findAuditEntry(AuditAction.ACCOUNT_DELETION_REQUESTED);
      expect(deletionEntry).toBeDefined();
      const entryStr = JSON.stringify(deletionEntry);
      expect(entryStr).not.toContain('SecurePass123!@#');
      // The totp_code '123456' is also used as a mock verify token; only check it's not in detail explicitly
      expect(deletionEntry!.detail).not.toHaveProperty('password');
      expect(deletionEntry!.detail).not.toHaveProperty('totp_code');
    });

    it('delegate invitation audit entry does not contain invitation token', async () => {
      await app.inject({
        method: 'POST',
        url: '/api/v1/delegates/invite',
        headers: { cookie: physicianCookie() },
        payload: { email: 'secdelegate@example.com', permissions: ['CLAIM_VIEW'] },
      });

      const entry = findAuditEntry(AuditAction.DELEGATE_INVITED);
      expect(entry).toBeDefined();
      // The invitation token should not appear in the audit entry
      expect(entry!.detail).not.toHaveProperty('token');
      expect(entry!.detail).not.toHaveProperty('invitationToken');
    });

    it('MFA reconfiguration audit entry does not contain TOTP secret', async () => {
      await app.inject({
        method: 'POST',
        url: '/api/v1/account/mfa/reconfigure',
        headers: { cookie: physicianCookie() },
        payload: { current_totp_code: '123456' },
      });

      const entry = findAuditEntry(AuditAction.ACCOUNT_MFA_RECONFIGURED);
      expect(entry).toBeDefined();
      const entryStr = JSON.stringify(entry);
      expect(entryStr).not.toContain('JBSWY3DPEHPK3PXP');
      // detail may be undefined or an object — either way it must not contain secrets
      if (entry!.detail && typeof entry!.detail === 'object') {
        expect(entry!.detail).not.toHaveProperty('totpSecret');
        expect(entry!.detail).not.toHaveProperty('secret');
      }
    });
  });

  // =========================================================================
  // Sanity: test setup validates correctly
  // =========================================================================

  describe('Sanity: test setup validates correctly', () => {
    it('physician session authenticates successfully', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/sessions',
        headers: { cookie: physicianCookie() },
      });

      expect(res.statusCode).not.toBe(401);
    });

    it('shared audit repo captures entries from all service layers', async () => {
      // Registration (via serviceDeps)
      await app.inject({
        method: 'POST',
        url: '/api/v1/auth/register',
        payload: {
          email: 'sanity@example.com',
          password: 'SecurePass123!@#',
          full_name: 'Sanity Check',
          phone: '+14035559999',
        },
      });

      // Logout (via sessionDeps)
      await app.inject({
        method: 'POST',
        url: '/api/v1/auth/logout',
        headers: { cookie: physicianCookie() },
      });

      // Should have entries from both service layers in the same array
      expect(findAuditEntry(AuditAction.AUTH_REGISTERED)).toBeDefined();
      expect(findAuditEntry(AuditAction.AUTH_LOGOUT)).toBeDefined();
    });
  });
});
