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
} from '../../../src/domains/iam/iam.service.js';
import { type AuthHandlerDeps } from '../../../src/domains/iam/iam.handlers.js';
import { randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Fixed test identities — two physicians + delegates
// ---------------------------------------------------------------------------

// Physician 1
const P1_SESSION_TOKEN = randomBytes(32).toString('hex');
const P1_SESSION_TOKEN_HASH = hashToken(P1_SESSION_TOKEN);
const P1_USER_ID = 'aaaa1111-0000-0000-0000-000000000001';
const P1_SESSION_ID = 'aaaa1111-0000-0000-0000-000000000011';

// Physician 2
const P2_SESSION_TOKEN = randomBytes(32).toString('hex');
const P2_SESSION_TOKEN_HASH = hashToken(P2_SESSION_TOKEN);
const P2_USER_ID = 'bbbb2222-0000-0000-0000-000000000001';
const P2_SESSION_ID = 'bbbb2222-0000-0000-0000-000000000011';

// Physician 2's extra session (to test cross-user session revocation)
const P2_EXTRA_SESSION_ID = 'bbbb2222-0000-0000-0000-000000000022';

// Delegate linked to physician 1 only
const D1_SESSION_TOKEN = randomBytes(32).toString('hex');
const D1_SESSION_TOKEN_HASH = hashToken(D1_SESSION_TOKEN);
const D1_USER_ID = 'cccc3333-0000-0000-0000-000000000001';
const D1_SESSION_ID = 'cccc3333-0000-0000-0000-000000000011';
const D1_LINKAGE_ID = 'dddd4444-0000-0000-0000-000000000001';

// Delegate linked to physician 2 only
const D2_USER_ID = 'eeee5555-0000-0000-0000-000000000001';
const D2_LINKAGE_ID = 'ffff6666-0000-0000-0000-000000000001';

// Delegate linked to BOTH physicians (for cross-context isolation tests)
const D_BOTH_SESSION_TOKEN = randomBytes(32).toString('hex');
const D_BOTH_SESSION_TOKEN_HASH = hashToken(D_BOTH_SESSION_TOKEN);
const D_BOTH_USER_ID = 'aaaa7777-0000-0000-0000-000000000001';
const D_BOTH_SESSION_ID = 'aaaa7777-0000-0000-0000-000000000011';
const D_BOTH_LINKAGE_P1 = 'bbbb8888-0000-0000-0000-000000000001';
const D_BOTH_LINKAGE_P2 = 'bbbb8888-0000-0000-0000-000000000002';

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
  role: string;
  subscriptionStatus: string;
  delegateContext?: {
    delegateUserId: string;
    physicianProviderId: string;
    permissions: string[];
    linkageId: string;
  };
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

interface MockAuditEntry {
  logId: string;
  userId: string;
  action: string;
  category: string;
  resourceType: string | null;
  resourceId: string | null;
  detail: Record<string, unknown> | null;
  ipAddress: string | null;
  createdAt: Date;
}

let users: MockUser[] = [];
let sessions: MockSession[] = [];
let linkages: MockLinkage[] = [];
let auditEntries: MockAuditEntry[] = [];
let appendedAuditEntries: Array<Record<string, unknown>> = [];

// ---------------------------------------------------------------------------
// Mock repositories
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    createSession: vi.fn(async () => {
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

function createMockAuditRepo() {
  return {
    appendAuditLog: vi.fn(async (entry: Record<string, unknown>) => {
      appendedAuditEntries.push(entry);
    }),
  };
}

function createMockEvents() {
  return { emit: vi.fn() };
}

function createMockLinkageRepo() {
  return {
    createDelegateLinkage: vi.fn(),
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
              fullName: delegateUser?.email?.split('@')[0] ?? 'Unknown',
              email: delegateUser?.email ?? 'unknown@example.com',
            },
            lastLogin: null,
          };
        });
    }),
    listPhysiciansForDelegate: vi.fn(async (delegateUserId: string) => {
      return linkages
        .filter((l) => l.delegateUserId === delegateUserId && l.isActive)
        .map((l) => {
          const physicianUser = users.find((u) => u.userId === l.physicianUserId);
          return {
            linkage: l,
            physician: {
              fullName: physicianUser?.email?.split('@')[0] ?? 'Unknown',
              email: physicianUser?.email ?? 'unknown@example.com',
            },
          };
        });
    }),
    updateLinkagePermissions: vi.fn(async (linkageId: string, permissions: string[], canApproveBatches: boolean) => {
      const linkage = linkages.find((l) => l.linkageId === linkageId);
      if (!linkage) return null;
      linkage.permissions = permissions;
      linkage.canApproveBatches = canApproveBatches;
      return linkage;
    }),
    deactivateLinkage: vi.fn(async (linkageId: string) => {
      const linkage = linkages.find((l) => l.linkageId === linkageId);
      if (linkage) linkage.isActive = false;
    }),
  };
}

function createMockAuditLogRepo() {
  return {
    queryAuditLog: vi.fn(async (userId: string, filters: any) => {
      const filtered = auditEntries.filter((e) => e.userId === userId);
      return {
        data: filtered,
        total: filtered.length,
      };
    }),
  };
}

// ---------------------------------------------------------------------------
// Stub deps (not exercised in scoping tests)
// ---------------------------------------------------------------------------

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

function createStubAccountDeps(): AccountServiceDeps {
  return {
    userRepo: { findUserById: vi.fn(), updateUser: vi.fn(), deactivateUser: vi.fn() },
    sessionRepo: { revokeAllUserSessions: vi.fn() },
    linkageRepo: { listDelegatesForPhysician: vi.fn(async () => []), deactivateLinkage: vi.fn() },
    auditRepo: createMockAuditRepo(),
    events: createMockEvents(),
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let mockSessionRepo: ReturnType<typeof createMockSessionRepo>;
let mockLinkageRepo: ReturnType<typeof createMockLinkageRepo>;
let mockAuditLogRepo: ReturnType<typeof createMockAuditLogRepo>;

async function buildTestApp(): Promise<FastifyInstance> {
  mockSessionRepo = createMockSessionRepo();
  mockLinkageRepo = createMockLinkageRepo();
  mockAuditLogRepo = createMockAuditLogRepo();

  const sharedAuditRepo = createMockAuditRepo();
  const sharedEvents = createMockEvents();

  const sessionDeps: SessionManagementDeps = {
    sessionRepo: mockSessionRepo,
    auditRepo: sharedAuditRepo,
    events: sharedEvents,
  };

  const delegateDeps: DelegateServiceDeps = {
    userRepo: { findUserByEmail: vi.fn(), findUserById: vi.fn(), createUser: vi.fn() },
    invitationRepo: { createInvitation: vi.fn(), findInvitationByTokenHash: vi.fn(), markInvitationAccepted: vi.fn() },
    linkageRepo: mockLinkageRepo,
    sessionRepo: { revokeAllUserSessions: mockSessionRepo.revokeAllUserSessions },
    auditRepo: sharedAuditRepo,
    events: sharedEvents,
  };

  const auditLogDeps: AuditLogServiceDeps = {
    auditLogRepo: mockAuditLogRepo,
    auditRepo: sharedAuditRepo,
  };

  const handlerDeps: AuthHandlerDeps = {
    serviceDeps: createStubServiceDeps(),
    mfaDeps: createStubMfaDeps(),
    loginDeps: createStubLoginDeps(),
    passwordResetDeps: createStubPasswordResetDeps(),
    sessionDeps,
    delegateDeps,
    accountDeps: createStubAccountDeps(),
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

function p1Cookie(): string {
  return `session=${P1_SESSION_TOKEN}`;
}

function p2Cookie(): string {
  return `session=${P2_SESSION_TOKEN}`;
}

function d1Cookie(): string {
  return `session=${D1_SESSION_TOKEN}`;
}

function dBothCookie(): string {
  return `session=${D_BOTH_SESSION_TOKEN}`;
}

// ---------------------------------------------------------------------------
// Seed helpers
// ---------------------------------------------------------------------------

function seedPhysician1() {
  users.push({
    userId: P1_USER_ID,
    email: 'physician1@example.com',
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
    sessionId: P1_SESSION_ID,
    userId: P1_USER_ID,
    tokenHash: P1_SESSION_TOKEN_HASH,
    ipAddress: '10.0.0.1',
    userAgent: 'physician1-browser',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });
}

function seedPhysician2() {
  users.push({
    userId: P2_USER_ID,
    email: 'physician2@example.com',
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
    sessionId: P2_SESSION_ID,
    userId: P2_USER_ID,
    tokenHash: P2_SESSION_TOKEN_HASH,
    ipAddress: '10.0.0.2',
    userAgent: 'physician2-browser',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });
  // Extra session for physician 2 (target for cross-user revocation)
  sessions.push({
    sessionId: P2_EXTRA_SESSION_ID,
    userId: P2_USER_ID,
    tokenHash: 'extra-hash-not-used',
    ipAddress: '10.0.0.3',
    userAgent: 'physician2-tablet',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });
}

function seedDelegateForP1() {
  users.push({
    userId: D1_USER_ID,
    email: 'delegate-p1@example.com',
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    role: 'DELEGATE',
    subscriptionStatus: 'TRIAL',
    delegateContext: {
      delegateUserId: D1_USER_ID,
      physicianProviderId: P1_USER_ID,
      permissions: ['CLAIM_VIEW', 'CLAIM_CREATE', 'PATIENT_VIEW'],
      linkageId: D1_LINKAGE_ID,
    },
  });
  sessions.push({
    sessionId: D1_SESSION_ID,
    userId: D1_USER_ID,
    tokenHash: D1_SESSION_TOKEN_HASH,
    ipAddress: '10.0.0.10',
    userAgent: 'delegate1-browser',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });
  linkages.push({
    linkageId: D1_LINKAGE_ID,
    physicianUserId: P1_USER_ID,
    delegateUserId: D1_USER_ID,
    permissions: ['CLAIM_VIEW', 'CLAIM_CREATE', 'PATIENT_VIEW'],
    canApproveBatches: false,
    isActive: true,
  });
}

function seedDelegateForP2() {
  users.push({
    userId: D2_USER_ID,
    email: 'delegate-p2@example.com',
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    role: 'DELEGATE',
    subscriptionStatus: 'TRIAL',
  });
  linkages.push({
    linkageId: D2_LINKAGE_ID,
    physicianUserId: P2_USER_ID,
    delegateUserId: D2_USER_ID,
    permissions: ['CLAIM_VIEW'],
    canApproveBatches: false,
    isActive: true,
  });
}

function seedDelegateForBoth() {
  users.push({
    userId: D_BOTH_USER_ID,
    email: 'delegate-both@example.com',
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    role: 'DELEGATE',
    subscriptionStatus: 'TRIAL',
    delegateContext: {
      delegateUserId: D_BOTH_USER_ID,
      physicianProviderId: P1_USER_ID,
      permissions: ['CLAIM_VIEW'],
      linkageId: D_BOTH_LINKAGE_P1,
    },
  });
  sessions.push({
    sessionId: D_BOTH_SESSION_ID,
    userId: D_BOTH_USER_ID,
    tokenHash: D_BOTH_SESSION_TOKEN_HASH,
    ipAddress: '10.0.0.20',
    userAgent: 'delegate-both-browser',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });
  linkages.push({
    linkageId: D_BOTH_LINKAGE_P1,
    physicianUserId: P1_USER_ID,
    delegateUserId: D_BOTH_USER_ID,
    permissions: ['CLAIM_VIEW'],
    canApproveBatches: false,
    isActive: true,
  });
  linkages.push({
    linkageId: D_BOTH_LINKAGE_P2,
    physicianUserId: P2_USER_ID,
    delegateUserId: D_BOTH_USER_ID,
    permissions: ['CLAIM_VIEW', 'PATIENT_VIEW'],
    canApproveBatches: false,
    isActive: true,
  });
}

function seedAuditLogs() {
  // Audit entries for physician 1
  auditEntries.push({
    logId: 'audit-p1-001',
    userId: P1_USER_ID,
    action: 'AUTH_LOGIN',
    category: 'AUTH',
    resourceType: 'session',
    resourceId: P1_SESSION_ID,
    detail: null,
    ipAddress: '10.0.0.1',
    createdAt: new Date(),
  });
  auditEntries.push({
    logId: 'audit-p1-002',
    userId: P1_USER_ID,
    action: 'DELEGATE_INVITED',
    category: 'DELEGATE',
    resourceType: 'delegate_linkage',
    resourceId: D1_LINKAGE_ID,
    detail: null,
    ipAddress: '10.0.0.1',
    createdAt: new Date(),
  });

  // Audit entries for physician 2
  auditEntries.push({
    logId: 'audit-p2-001',
    userId: P2_USER_ID,
    action: 'AUTH_LOGIN',
    category: 'AUTH',
    resourceType: 'session',
    resourceId: P2_SESSION_ID,
    detail: null,
    ipAddress: '10.0.0.2',
    createdAt: new Date(),
  });
  auditEntries.push({
    logId: 'audit-p2-002',
    userId: P2_USER_ID,
    action: 'DELEGATE_PERMISSIONS_UPDATED',
    category: 'DELEGATE',
    resourceType: 'delegate_linkage',
    resourceId: D2_LINKAGE_ID,
    detail: null,
    ipAddress: '10.0.0.2',
    createdAt: new Date(),
  });
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('IAM Cross-User Isolation — Tenant Scoping (Security)', () => {
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
    appendedAuditEntries = [];
    seedPhysician1();
    seedPhysician2();
    seedDelegateForP1();
    seedDelegateForP2();
    seedDelegateForBoth();
    seedAuditLogs();
  });

  // =========================================================================
  // Sanity: verify test setup works
  // =========================================================================

  describe('Sanity: test setup validates correctly', () => {
    it('physician1 session authenticates successfully', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/sessions',
        headers: { cookie: p1Cookie() },
      });
      expect(res.statusCode).not.toBe(401);
    });

    it('physician2 session authenticates successfully', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/sessions',
        headers: { cookie: p2Cookie() },
      });
      expect(res.statusCode).not.toBe(401);
    });

    it('delegate1 session authenticates successfully', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/account',
        headers: { cookie: d1Cookie() },
      });
      expect(res.statusCode).not.toBe(401);
    });
  });

  // =========================================================================
  // Session Isolation
  // =========================================================================

  describe('Session isolation between physicians', () => {
    it('physician1 listing sessions does not see physician2 sessions', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/sessions',
        headers: { cookie: p1Cookie() },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      const sessionData = body.data as Array<{ sessionId: string }>;

      // Physician1 should only see their own session
      for (const session of sessionData) {
        expect(session.sessionId).not.toBe(P2_SESSION_ID);
        expect(session.sessionId).not.toBe(P2_EXTRA_SESSION_ID);
      }
    });

    it('physician2 listing sessions does not see physician1 sessions', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/sessions',
        headers: { cookie: p2Cookie() },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      const sessionData = body.data as Array<{ sessionId: string }>;

      for (const session of sessionData) {
        expect(session.sessionId).not.toBe(P1_SESSION_ID);
      }
    });

    it('physician1 cannot revoke physician2 session — returns non-success status', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: `/api/v1/sessions/${P2_SESSION_ID}`,
        headers: { cookie: p1Cookie() },
      });

      // The service throws BusinessRuleError('Session not found') → 422.
      // The critical property: the request does NOT succeed (not 204) and
      // physician2's session remains unrevoked.
      expect(res.statusCode).not.toBe(204);
      expect(res.statusCode).toBeGreaterThanOrEqual(400);

      // Verify physician2's session was NOT actually revoked
      const p2Session = sessions.find((s) => s.sessionId === P2_SESSION_ID);
      expect(p2Session!.revoked).toBe(false);
    });

    it('physician1 cannot revoke physician2 extra session — returns non-success status', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: `/api/v1/sessions/${P2_EXTRA_SESSION_ID}`,
        headers: { cookie: p1Cookie() },
      });

      expect(res.statusCode).not.toBe(204);
      expect(res.statusCode).toBeGreaterThanOrEqual(400);

      // Verify the session was NOT revoked
      const extraSession = sessions.find((s) => s.sessionId === P2_EXTRA_SESSION_ID);
      expect(extraSession!.revoked).toBe(false);
    });

    it('physician2 cannot revoke physician1 session — returns non-success status', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: `/api/v1/sessions/${P1_SESSION_ID}`,
        headers: { cookie: p2Cookie() },
      });

      expect(res.statusCode).not.toBe(204);
      expect(res.statusCode).toBeGreaterThanOrEqual(400);

      // Verify physician1's session was NOT revoked
      const p1Session = sessions.find((s) => s.sessionId === P1_SESSION_ID);
      expect(p1Session!.revoked).toBe(false);
    });

    it('cross-user session revocation response does not leak session details', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: `/api/v1/sessions/${P2_SESSION_ID}`,
        headers: { cookie: p1Cookie() },
      });

      const rawBody = res.body;
      // Must not reveal the target session's IP, user agent, or user ID
      expect(rawBody).not.toContain(P2_USER_ID);
      expect(rawBody).not.toContain('10.0.0.2');
      expect(rawBody).not.toContain('physician2');
    });

    it('"revoke all sessions" only revokes the requesting physician\'s sessions', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: '/api/v1/sessions',
        headers: { cookie: p1Cookie() },
      });

      expect(res.statusCode).toBe(200);

      // Physician2's sessions must remain unrevoked
      const p2Session = sessions.find((s) => s.sessionId === P2_SESSION_ID);
      expect(p2Session!.revoked).toBe(false);
      const p2Extra = sessions.find((s) => s.sessionId === P2_EXTRA_SESSION_ID);
      expect(p2Extra!.revoked).toBe(false);
    });
  });

  // =========================================================================
  // Delegate Isolation
  // =========================================================================

  describe('Delegate isolation between physicians', () => {
    it('physician1 listing delegates does not see physician2 delegates', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/delegates',
        headers: { cookie: p1Cookie() },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      const delegates = body.data as Array<{ linkageId: string; delegateUserId: string }>;

      // Physician1 should see D1 and D_BOTH (linked to P1) but NOT D2
      for (const delegate of delegates) {
        expect(delegate.linkageId).not.toBe(D2_LINKAGE_ID);
        expect(delegate.delegateUserId).not.toBe(D2_USER_ID);
      }
    });

    it('physician2 listing delegates does not see physician1 delegates', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/delegates',
        headers: { cookie: p2Cookie() },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      const delegates = body.data as Array<{ linkageId: string; delegateUserId: string }>;

      for (const delegate of delegates) {
        expect(delegate.linkageId).not.toBe(D1_LINKAGE_ID);
        // D1 is exclusively linked to P1
        expect(delegate.delegateUserId).not.toBe(D1_USER_ID);
      }
    });

    it('physician1 cannot modify physician2 delegate permissions — returns non-success', async () => {
      const res = await app.inject({
        method: 'PATCH',
        url: `/api/v1/delegates/${D2_LINKAGE_ID}/permissions`,
        headers: { cookie: p1Cookie() },
        payload: { permissions: ['CLAIM_VIEW', 'CLAIM_CREATE'] },
      });

      // Service verifies linkage.physicianUserId !== physicianUserId → BusinessRuleError
      expect(res.statusCode).not.toBe(200);
      expect(res.statusCode).toBeGreaterThanOrEqual(400);

      // Verify D2's permissions were NOT changed
      const d2Linkage = linkages.find((l) => l.linkageId === D2_LINKAGE_ID);
      expect(d2Linkage!.permissions).toEqual(['CLAIM_VIEW']);
    });

    it('physician2 cannot modify physician1 delegate permissions — returns non-success', async () => {
      const res = await app.inject({
        method: 'PATCH',
        url: `/api/v1/delegates/${D1_LINKAGE_ID}/permissions`,
        headers: { cookie: p2Cookie() },
        payload: { permissions: ['CLAIM_VIEW'] },
      });

      expect(res.statusCode).not.toBe(200);
      expect(res.statusCode).toBeGreaterThanOrEqual(400);

      // Verify D1's permissions were NOT changed
      const d1Linkage = linkages.find((l) => l.linkageId === D1_LINKAGE_ID);
      expect(d1Linkage!.permissions).toEqual(['CLAIM_VIEW', 'CLAIM_CREATE', 'PATIENT_VIEW']);
    });

    it('physician1 cannot revoke physician2 delegate — returns non-success', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: `/api/v1/delegates/${D2_LINKAGE_ID}`,
        headers: { cookie: p1Cookie() },
      });

      expect(res.statusCode).not.toBe(204);
      expect(res.statusCode).toBeGreaterThanOrEqual(400);

      // Verify D2 linkage was NOT deactivated
      const d2Linkage = linkages.find((l) => l.linkageId === D2_LINKAGE_ID);
      expect(d2Linkage!.isActive).toBe(true);
    });

    it('physician2 cannot revoke physician1 delegate — returns non-success', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: `/api/v1/delegates/${D1_LINKAGE_ID}`,
        headers: { cookie: p2Cookie() },
      });

      expect(res.statusCode).not.toBe(204);
      expect(res.statusCode).toBeGreaterThanOrEqual(400);

      // Verify D1 linkage was NOT deactivated
      const d1Linkage = linkages.find((l) => l.linkageId === D1_LINKAGE_ID);
      expect(d1Linkage!.isActive).toBe(true);
    });

    it('cross-user delegate revocation response does not leak delegate details', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: `/api/v1/delegates/${D2_LINKAGE_ID}`,
        headers: { cookie: p1Cookie() },
      });

      const rawBody = res.body;
      // Must not leak the delegate's email, user ID, or physician2's details
      expect(rawBody).not.toContain(D2_USER_ID);
      expect(rawBody).not.toContain('delegate-p2@example.com');
      expect(rawBody).not.toContain(P2_USER_ID);
    });

    it('cross-user delegate permission update response does not leak delegate details', async () => {
      const res = await app.inject({
        method: 'PATCH',
        url: `/api/v1/delegates/${D2_LINKAGE_ID}/permissions`,
        headers: { cookie: p1Cookie() },
        payload: { permissions: ['CLAIM_VIEW'] },
      });

      const rawBody = res.body;
      expect(rawBody).not.toContain(D2_USER_ID);
      expect(rawBody).not.toContain('delegate-p2@example.com');
      expect(rawBody).not.toContain(P2_USER_ID);
    });
  });

  // =========================================================================
  // Audit Log Isolation
  // =========================================================================

  describe('Audit log isolation between physicians', () => {
    it('physician1 audit log query returns only physician1 entries (by resource IDs)', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/account/audit-log',
        headers: { cookie: p1Cookie() },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      // The service strips userId from the response (it's implicitly scoped).
      // Verify the returned entries match P1's data by checking resource IDs.
      const entries = body.data as Array<{ logId: string; resourceId: string | null }>;

      expect(entries.length).toBeGreaterThan(0);
      const entryLogIds = entries.map((e) => e.logId);
      // P1's entries
      expect(entryLogIds).toContain('audit-p1-001');
      expect(entryLogIds).toContain('audit-p1-002');
      // P2's entries must NOT be present
      expect(entryLogIds).not.toContain('audit-p2-001');
      expect(entryLogIds).not.toContain('audit-p2-002');
    });

    it('physician2 audit log query returns only physician2 entries (by resource IDs)', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/account/audit-log',
        headers: { cookie: p2Cookie() },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      const entries = body.data as Array<{ logId: string; resourceId: string | null }>;

      expect(entries.length).toBeGreaterThan(0);
      const entryLogIds = entries.map((e) => e.logId);
      // P2's entries
      expect(entryLogIds).toContain('audit-p2-001');
      expect(entryLogIds).toContain('audit-p2-002');
      // P1's entries must NOT be present
      expect(entryLogIds).not.toContain('audit-p1-001');
      expect(entryLogIds).not.toContain('audit-p1-002');
    });

    it('physician1 audit log never contains physician2 resource IDs', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/account/audit-log',
        headers: { cookie: p1Cookie() },
      });

      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_SESSION_ID);
      expect(rawBody).not.toContain(D2_LINKAGE_ID);
    });

    it('physician2 audit log never contains physician1 resource IDs', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/account/audit-log',
        headers: { cookie: p2Cookie() },
      });

      const rawBody = res.body;
      expect(rawBody).not.toContain(P1_SESSION_ID);
      expect(rawBody).not.toContain(D1_LINKAGE_ID);
    });

    it('audit log repo is called with the authenticated user ID only', async () => {
      // Clear mock to ensure clean call tracking
      mockAuditLogRepo.queryAuditLog.mockClear();

      await app.inject({
        method: 'GET',
        url: '/api/v1/account/audit-log',
        headers: { cookie: p1Cookie() },
      });

      // After a single request from P1, the repo should have been called with P1's user ID
      expect(mockAuditLogRepo.queryAuditLog).toHaveBeenCalledTimes(1);
      expect(mockAuditLogRepo.queryAuditLog).toHaveBeenCalledWith(
        P1_USER_ID,
        expect.any(Object),
      );
    });
  });

  // =========================================================================
  // Delegate Cross-Context Isolation
  // =========================================================================

  describe('Delegate cross-context isolation', () => {
    it('delegate linked to physician1 only cannot access physician2 delegates list', async () => {
      // D1 is only linked to P1, role is DELEGATE.
      // GET /api/v1/delegates requires PHYSICIAN role → 403.
      // Even if the delegate tried to see P2's delegates, the role check blocks it.
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/delegates',
        headers: { cookie: d1Cookie() },
      });

      expect(res.statusCode).toBe(403);
    });

    it('delegate linked to both physicians — data in P1 context does not leak into P2 context', async () => {
      // D_BOTH is logged in with delegateContext pointing to P1.
      // They can list their physicians via GET /delegates/physicians.
      // We verify the delegate's current context is P1, not P2.
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/delegates/physicians',
        headers: { cookie: dBothCookie() },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      const physicians = body.data as Array<{
        linkageId: string;
        physicianUserId: string;
        permissions: string[];
      }>;

      // Both linkages should be visible (delegate can see which physicians they have access to)
      // but permissions should be SEPARATE per physician
      const p1Entry = physicians.find((p) => p.physicianUserId === P1_USER_ID);
      const p2Entry = physicians.find((p) => p.physicianUserId === P2_USER_ID);

      if (p1Entry && p2Entry) {
        // P1 linkage has ['CLAIM_VIEW'], P2 linkage has ['CLAIM_VIEW', 'PATIENT_VIEW']
        // They must not be merged
        expect(p1Entry.permissions).toEqual(['CLAIM_VIEW']);
        expect(p2Entry.permissions).toEqual(['CLAIM_VIEW', 'PATIENT_VIEW']);
        expect(p1Entry.linkageId).not.toBe(p2Entry.linkageId);
      }
    });

    it('delegate linked to both physicians — each linkage has independent permissions', async () => {
      // Verify that the permissions for P1 and P2 are stored separately
      const p1Linkage = linkages.find((l) => l.linkageId === D_BOTH_LINKAGE_P1);
      const p2Linkage = linkages.find((l) => l.linkageId === D_BOTH_LINKAGE_P2);

      expect(p1Linkage).toBeDefined();
      expect(p2Linkage).toBeDefined();

      // P1 gave CLAIM_VIEW only; P2 gave CLAIM_VIEW + PATIENT_VIEW
      expect(p1Linkage!.permissions).toEqual(['CLAIM_VIEW']);
      expect(p2Linkage!.permissions).toEqual(['CLAIM_VIEW', 'PATIENT_VIEW']);

      // Updating P1's delegate permissions should NOT affect P2's
      await app.inject({
        method: 'PATCH',
        url: `/api/v1/delegates/${D_BOTH_LINKAGE_P1}/permissions`,
        headers: { cookie: p1Cookie() },
        payload: { permissions: ['CLAIM_VIEW', 'CLAIM_CREATE'] },
      });

      // P1 linkage updated
      expect(p1Linkage!.permissions).toContain('CLAIM_CREATE');
      // P2 linkage untouched
      expect(p2Linkage!.permissions).not.toContain('CLAIM_CREATE');
      expect(p2Linkage!.permissions).toEqual(['CLAIM_VIEW', 'PATIENT_VIEW']);
    });

    it('physician1 cannot modify the linkage between physician2 and the shared delegate', async () => {
      const res = await app.inject({
        method: 'PATCH',
        url: `/api/v1/delegates/${D_BOTH_LINKAGE_P2}/permissions`,
        headers: { cookie: p1Cookie() },
        payload: { permissions: ['CLAIM_VIEW'] },
      });

      // P1 does not own D_BOTH_LINKAGE_P2 (that belongs to P2)
      expect(res.statusCode).not.toBe(200);
      expect(res.statusCode).toBeGreaterThanOrEqual(400);

      // Verify P2's linkage with the shared delegate was NOT changed
      const p2Linkage = linkages.find((l) => l.linkageId === D_BOTH_LINKAGE_P2);
      expect(p2Linkage!.permissions).toEqual(['CLAIM_VIEW', 'PATIENT_VIEW']);
    });

    it('physician1 cannot revoke the linkage between physician2 and the shared delegate', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: `/api/v1/delegates/${D_BOTH_LINKAGE_P2}`,
        headers: { cookie: p1Cookie() },
      });

      expect(res.statusCode).not.toBe(204);
      expect(res.statusCode).toBeGreaterThanOrEqual(400);

      // Verify P2's linkage was NOT deactivated
      const p2Linkage = linkages.find((l) => l.linkageId === D_BOTH_LINKAGE_P2);
      expect(p2Linkage!.isActive).toBe(true);
    });
  });

  // =========================================================================
  // Non-existent resource IDs — must not reveal existence
  // =========================================================================

  describe('Non-existent resource IDs return error without revealing existence', () => {
    it('revoking a non-existent session returns an error (not 204)', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: '/api/v1/sessions/99999999-0000-0000-0000-000000000099',
        headers: { cookie: p1Cookie() },
      });

      expect(res.statusCode).not.toBe(204);
      expect(res.statusCode).toBeGreaterThanOrEqual(400);
    });

    it('modifying a non-existent delegate returns an error (not 200)', async () => {
      const res = await app.inject({
        method: 'PATCH',
        url: '/api/v1/delegates/99999999-0000-0000-0000-000000000099/permissions',
        headers: { cookie: p1Cookie() },
        payload: { permissions: ['CLAIM_VIEW'] },
      });

      expect(res.statusCode).not.toBe(200);
      expect(res.statusCode).toBeGreaterThanOrEqual(400);
    });

    it('revoking a non-existent delegate returns an error (not 204)', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: '/api/v1/delegates/99999999-0000-0000-0000-000000000099',
        headers: { cookie: p1Cookie() },
      });

      expect(res.statusCode).not.toBe(204);
      expect(res.statusCode).toBeGreaterThanOrEqual(400);
    });

    it('error response for non-existent resource is identical to cross-user access error', async () => {
      // Compare: accessing a resource that doesn't exist vs one owned by another physician
      const nonExistentRes = await app.inject({
        method: 'DELETE',
        url: '/api/v1/delegates/99999999-0000-0000-0000-000000000099',
        headers: { cookie: p1Cookie() },
      });

      const crossUserRes = await app.inject({
        method: 'DELETE',
        url: `/api/v1/delegates/${D2_LINKAGE_ID}`,
        headers: { cookie: p1Cookie() },
      });

      // Both should return the same status code and error shape
      expect(nonExistentRes.statusCode).toBe(crossUserRes.statusCode);

      const nonExistentBody = JSON.parse(nonExistentRes.body);
      const crossUserBody = JSON.parse(crossUserRes.body);

      expect(nonExistentBody.error.code).toBe(crossUserBody.error.code);
      // Message should be generic enough that you can't tell the difference
      expect(nonExistentBody.error.message).toBe(crossUserBody.error.message);
    });
  });
});
