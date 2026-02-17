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
import { randomBytes, randomUUID } from 'node:crypto';
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

interface MockInvitation {
  invitationId: string;
  physicianUserId: string;
  delegateEmail: string;
  tokenHash: string;
  permissions: string[];
  expiresAt: Date;
  accepted: boolean;
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
let invitations: MockInvitation[] = [];
let linkages: MockLinkage[] = [];
let auditEntries: Array<Record<string, unknown>> = [];

// Fixed physician user/session
const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_USER_ID = '22222222-0000-0000-0000-000000000001';
const PHYSICIAN_SESSION_ID = '33333333-0000-0000-0000-000000000001';

// Fixed delegate user/session
const DELEGATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_SESSION_HASH = hashToken(DELEGATE_SESSION_TOKEN);
const DELEGATE_USER_ID = '22222222-0000-0000-0000-000000000002';
const DELEGATE_SESSION_ID = '33333333-0000-0000-0000-000000000002';

let nextUserId = 100;
function newUserId() {
  return `55555555-0000-0000-0000-${String(nextUserId++).padStart(12, '0')}`;
}

let nextInvitationId = 1;
function newInvitationId() {
  return `66666666-0000-0000-0000-${String(nextInvitationId++).padStart(12, '0')}`;
}

let nextLinkageId = 1;
function newLinkageId() {
  return `77777777-0000-0000-0000-${String(nextLinkageId++).padStart(12, '0')}`;
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
    revokeAllUserSessions: vi.fn(),
  };
}

function createMockDelegateUserRepo() {
  return {
    findUserByEmail: vi.fn(async (email: string) => {
      return users.find((u) => u.email === email.toLowerCase() && u.isActive);
    }),
    findUserById: vi.fn(async (userId: string) => {
      return users.find((u) => u.userId === userId && u.isActive);
    }),
    createUser: vi.fn(async (data: any) => {
      const user: MockUser = {
        userId: newUserId(),
        email: data.email.toLowerCase(),
        passwordHash: data.passwordHash,
        mfaConfigured: false,
        totpSecretEncrypted: null,
        failedLoginCount: 0,
        lockedUntil: null,
        isActive: true,
        fullName: data.fullName,
        role: data.role ?? 'DELEGATE',
        subscriptionStatus: 'TRIAL',
      };
      users.push(user);
      return { userId: user.userId, email: user.email };
    }),
  };
}

function createMockInvitationRepo() {
  return {
    createInvitation: vi.fn(async (data: any) => {
      const inv: MockInvitation = {
        invitationId: newInvitationId(),
        physicianUserId: data.physicianUserId,
        delegateEmail: data.delegateEmail,
        tokenHash: data.tokenHash,
        permissions: data.permissions,
        expiresAt: data.expiresAt,
        accepted: false,
      };
      invitations.push(inv);
      return { invitationId: inv.invitationId };
    }),
    findInvitationByTokenHash: vi.fn(async (tokenHash: string) => {
      return invitations.find((i) => i.tokenHash === tokenHash && !i.accepted);
    }),
    markInvitationAccepted: vi.fn(async (invitationId: string) => {
      const inv = invitations.find((i) => i.invitationId === invitationId);
      if (inv) inv.accepted = true;
    }),
  };
}

function createMockLinkageRepo() {
  return {
    createDelegateLinkage: vi.fn(async (data: any) => {
      const linkage: MockLinkage = {
        linkageId: newLinkageId(),
        physicianUserId: data.physicianUserId,
        delegateUserId: data.delegateUserId,
        permissions: data.permissions,
        canApproveBatches: data.canApproveBatches,
        isActive: true,
      };
      linkages.push(linkage);
      return linkage;
    }),
    findLinkage: vi.fn(async (physicianUserId: string, delegateUserId: string) => {
      return linkages.find(
        (l) => l.physicianUserId === physicianUserId && l.delegateUserId === delegateUserId && l.isActive,
      );
    }),
    findLinkageById: vi.fn(async (linkageId: string) => {
      return linkages.find((l) => l.linkageId === linkageId);
    }),
    listDelegatesForPhysician: vi.fn(async (physicianUserId: string) => {
      return linkages
        .filter((l) => l.physicianUserId === physicianUserId)
        .map((l) => {
          const user = users.find((u) => u.userId === l.delegateUserId);
          return {
            linkage: l,
            user: { userId: l.delegateUserId, fullName: user?.fullName ?? 'Test', email: user?.email ?? 'test@test.com' },
            lastLogin: null,
          };
        });
    }),
    listPhysiciansForDelegate: vi.fn(async (delegateUserId: string) => {
      return linkages
        .filter((l) => l.delegateUserId === delegateUserId && l.isActive)
        .map((l) => {
          const physician = users.find((u) => u.userId === l.physicianUserId);
          return {
            linkage: l,
            physician: { userId: l.physicianUserId, fullName: physician?.fullName ?? 'Dr. Test', email: physician?.email ?? 'dr@test.com' },
          };
        });
    }),
    updateLinkagePermissions: vi.fn(async (linkageId: string, permissions: string[], canApproveBatches: boolean) => {
      const linkage = linkages.find((l) => l.linkageId === linkageId);
      if (!linkage) return undefined;
      linkage.permissions = permissions;
      linkage.canApproveBatches = canApproveBatches;
      return { linkageId };
    }),
    deactivateLinkage: vi.fn(async (linkageId: string) => {
      const linkage = linkages.find((l) => l.linkageId === linkageId);
      if (!linkage) return undefined;
      linkage.isActive = false;
      return { linkageId };
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

// Stubs for deps not exercised in delegate tests
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
let mockInvitationRepo: ReturnType<typeof createMockInvitationRepo>;
let mockLinkageRepo: ReturnType<typeof createMockLinkageRepo>;
let mockDelegateUserRepo: ReturnType<typeof createMockDelegateUserRepo>;
let mockAuditRepo: ReturnType<typeof createMockAuditRepo>;
let mockEvents: ReturnType<typeof createMockEvents>;

async function buildTestApp(): Promise<FastifyInstance> {
  mockSessionRepo = createMockSessionRepo();
  mockInvitationRepo = createMockInvitationRepo();
  mockLinkageRepo = createMockLinkageRepo();
  mockDelegateUserRepo = createMockDelegateUserRepo();
  mockAuditRepo = createMockAuditRepo();
  mockEvents = createMockEvents();

  const sessionDeps: SessionManagementDeps = {
    sessionRepo: mockSessionRepo,
    auditRepo: mockAuditRepo,
    events: mockEvents,
  };

  const delegateDeps: DelegateServiceDeps = {
    userRepo: mockDelegateUserRepo,
    invitationRepo: mockInvitationRepo,
    linkageRepo: mockLinkageRepo,
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
    delegateDeps,
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
// Seed helpers
// ---------------------------------------------------------------------------

function seedPhysicianAndSession() {
  users.push({
    userId: PHYSICIAN_USER_ID,
    email: 'physician@example.com',
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    fullName: 'Dr. Physician',
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

function seedDelegateAndSession() {
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

describe('IAM Delegates Integration Tests', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    users = [];
    sessions = [];
    invitations = [];
    linkages = [];
    auditEntries = [];
    nextUserId = 100;
    nextInvitationId = 1;
    nextLinkageId = 1;

    mockSessionRepo.createSession.mockClear();
    mockSessionRepo.revokeSession.mockClear();
    mockSessionRepo.revokeAllUserSessions.mockClear();
    mockInvitationRepo.createInvitation.mockClear();
    mockInvitationRepo.findInvitationByTokenHash.mockClear();
    mockInvitationRepo.markInvitationAccepted.mockClear();
    mockLinkageRepo.createDelegateLinkage.mockClear();
    mockLinkageRepo.findLinkageById.mockClear();
    mockLinkageRepo.updateLinkagePermissions.mockClear();
    mockLinkageRepo.deactivateLinkage.mockClear();
    mockDelegateUserRepo.findUserByEmail.mockClear();
    mockDelegateUserRepo.createUser.mockClear();
    mockAuditRepo.appendAuditLog.mockClear();
    mockEvents.emit.mockClear();

    seedPhysicianAndSession();
    seedDelegateAndSession();
  });

  // =========================================================================
  // POST /api/v1/delegates/invite
  // =========================================================================

  describe('POST /api/v1/delegates/invite', () => {
    it('creates invitation as physician', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/delegates/invite',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
        payload: {
          email: 'new-delegate@example.com',
          permissions: ['CLAIM_VIEW', 'PATIENT_VIEW'],
        },
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);
      expect(body.data.invitationId).toBeDefined();
      expect(body.data.token).toBeDefined();
    });

    it('as delegate returns 403', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/delegates/invite',
        headers: { cookie: `session=${DELEGATE_SESSION_TOKEN}` },
        payload: {
          email: 'new-delegate@example.com',
          permissions: ['CLAIM_VIEW'],
        },
      });

      expect(res.statusCode).toBe(403);
    });

    it('returns 401 without auth', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/delegates/invite',
        payload: {
          email: 'new-delegate@example.com',
          permissions: ['CLAIM_VIEW'],
        },
      });

      expect(res.statusCode).toBe(401);
    });

    it('rejects forbidden permissions (DELEGATE_MANAGE)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/delegates/invite',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
        payload: {
          email: 'new-delegate@example.com',
          permissions: ['DELEGATE_MANAGE'],
        },
      });

      expect(res.statusCode).toBe(422);
    });

    it('rejects empty permissions array', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/delegates/invite',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
        payload: {
          email: 'new-delegate@example.com',
          permissions: [],
        },
      });

      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // POST /api/v1/delegates/accept
  // =========================================================================

  describe('POST /api/v1/delegates/accept', () => {
    it('with valid token creates linkage for existing user', async () => {
      // Create an invitation first
      const inviteRes = await app.inject({
        method: 'POST',
        url: '/api/v1/delegates/invite',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
        payload: {
          email: 'delegate@example.com',
          permissions: ['CLAIM_VIEW', 'PATIENT_VIEW'],
        },
      });
      const inviteToken = JSON.parse(inviteRes.body).data.token;

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/delegates/accept',
        payload: { token: inviteToken },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.linkageId).toBeDefined();
    });

    it('with valid token and registration data creates new user', async () => {
      // Invite a non-existent email
      const inviteRes = await app.inject({
        method: 'POST',
        url: '/api/v1/delegates/invite',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
        payload: {
          email: 'brand-new@example.com',
          permissions: ['CLAIM_VIEW'],
        },
      });
      const inviteToken = JSON.parse(inviteRes.body).data.token;

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/delegates/accept',
        payload: {
          token: inviteToken,
          full_name: 'New Delegate',
          password: 'SecurePass123!',
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.linkageId).toBeDefined();
    });

    it('with invalid token returns 422', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/delegates/accept',
        payload: { token: 'invalid-token' },
      });

      expect(res.statusCode).toBe(422);
    });
  });

  // =========================================================================
  // GET /api/v1/delegates
  // =========================================================================

  describe('GET /api/v1/delegates', () => {
    it('returns delegates for physician', async () => {
      // Create a linkage
      linkages.push({
        linkageId: newLinkageId(),
        physicianUserId: PHYSICIAN_USER_ID,
        delegateUserId: DELEGATE_USER_ID,
        permissions: ['CLAIM_VIEW'],
        canApproveBatches: false,
        isActive: true,
      });

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/delegates',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(Array.isArray(body.data)).toBe(true);
      expect(body.data.length).toBe(1);
      expect(body.data[0].delegateUserId).toBe(DELEGATE_USER_ID);
    });

    it('as delegate returns 403', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/delegates',
        headers: { cookie: `session=${DELEGATE_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(403);
    });
  });

  // =========================================================================
  // GET /api/v1/delegates/physicians
  // =========================================================================

  describe('GET /api/v1/delegates/physicians', () => {
    it('returns linked physicians for delegate', async () => {
      linkages.push({
        linkageId: newLinkageId(),
        physicianUserId: PHYSICIAN_USER_ID,
        delegateUserId: DELEGATE_USER_ID,
        permissions: ['CLAIM_VIEW'],
        canApproveBatches: false,
        isActive: true,
      });

      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/delegates/physicians',
        headers: { cookie: `session=${DELEGATE_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(Array.isArray(body.data)).toBe(true);
      expect(body.data.length).toBe(1);
      expect(body.data[0].physicianUserId).toBe(PHYSICIAN_USER_ID);
    });

    it('as physician returns 403', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/delegates/physicians',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(403);
    });
  });

  // =========================================================================
  // PATCH /api/v1/delegates/:id/permissions
  // =========================================================================

  describe('PATCH /api/v1/delegates/:id/permissions', () => {
    it('updates permissions', async () => {
      const linkage: MockLinkage = {
        linkageId: newLinkageId(),
        physicianUserId: PHYSICIAN_USER_ID,
        delegateUserId: DELEGATE_USER_ID,
        permissions: ['CLAIM_VIEW'],
        canApproveBatches: false,
        isActive: true,
      };
      linkages.push(linkage);

      const res = await app.inject({
        method: 'PATCH',
        url: `/api/v1/delegates/${linkage.linkageId}/permissions`,
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
        payload: {
          permissions: ['CLAIM_VIEW', 'CLAIM_CREATE', 'PATIENT_VIEW'],
        },
      });

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.linkageId).toBe(linkage.linkageId);
    });

    it('with non-UUID param returns 400', async () => {
      const res = await app.inject({
        method: 'PATCH',
        url: '/api/v1/delegates/not-a-uuid/permissions',
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
        payload: { permissions: ['CLAIM_VIEW'] },
      });

      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // DELETE /api/v1/delegates/:id
  // =========================================================================

  describe('DELETE /api/v1/delegates/:id', () => {
    it('revokes delegate', async () => {
      const linkage: MockLinkage = {
        linkageId: newLinkageId(),
        physicianUserId: PHYSICIAN_USER_ID,
        delegateUserId: DELEGATE_USER_ID,
        permissions: ['CLAIM_VIEW'],
        canApproveBatches: false,
        isActive: true,
      };
      linkages.push(linkage);

      const res = await app.inject({
        method: 'DELETE',
        url: `/api/v1/delegates/${linkage.linkageId}`,
        headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(204);
    });

    it('as delegate returns 403', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: `/api/v1/delegates/00000000-0000-0000-0000-000000000099`,
        headers: { cookie: `session=${DELEGATE_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(403);
    });
  });
});
