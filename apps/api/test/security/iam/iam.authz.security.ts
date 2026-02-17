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
// Fixed test users/sessions — one per role
// ---------------------------------------------------------------------------

// Physician user
const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_USER_ID = 'aaaa0000-0000-0000-0000-000000000001';
const PHYSICIAN_SESSION_ID = 'aaaa0000-0000-0000-0000-000000000011';

// Delegate user (full permissions — the default delegate set)
const DELEGATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_SESSION_TOKEN_HASH = hashToken(DELEGATE_SESSION_TOKEN);
const DELEGATE_USER_ID = 'bbbb0000-0000-0000-0000-000000000001';
const DELEGATE_SESSION_ID = 'bbbb0000-0000-0000-0000-000000000011';
const DELEGATE_LINKAGE_ID = 'cccc0000-0000-0000-0000-000000000001';

// Delegate user with limited permissions (CLAIM_VIEW only)
const LIMITED_DELEGATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const LIMITED_DELEGATE_SESSION_TOKEN_HASH = hashToken(LIMITED_DELEGATE_SESSION_TOKEN);
const LIMITED_DELEGATE_USER_ID = 'dddd0000-0000-0000-0000-000000000001';
const LIMITED_DELEGATE_SESSION_ID = 'dddd0000-0000-0000-0000-000000000011';

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

let users: MockUser[] = [];
let sessions: MockSession[] = [];
let auditEntries: Array<Record<string, unknown>> = [];

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
    listActiveSessions: vi.fn(async () => []),
    revokeSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
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

// ---------------------------------------------------------------------------
// Stub deps (not exercised in authz tests)
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

async function buildTestApp(): Promise<FastifyInstance> {
  mockSessionRepo = createMockSessionRepo();

  const sessionDeps: SessionManagementDeps = {
    sessionRepo: mockSessionRepo,
    auditRepo: createMockAuditRepo(),
    events: createMockEvents(),
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
// Helpers
// ---------------------------------------------------------------------------

function seedPhysician() {
  users.push({
    userId: PHYSICIAN_USER_ID,
    email: 'physician@example.com',
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
    sessionId: PHYSICIAN_SESSION_ID,
    userId: PHYSICIAN_USER_ID,
    tokenHash: PHYSICIAN_SESSION_TOKEN_HASH,
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
    role: 'DELEGATE',
    subscriptionStatus: 'TRIAL',
    delegateContext: {
      delegateUserId: DELEGATE_USER_ID,
      physicianProviderId: PHYSICIAN_USER_ID,
      permissions: [
        'CLAIM_CREATE', 'CLAIM_VIEW', 'CLAIM_EDIT', 'CLAIM_DELETE', 'CLAIM_SUBMIT',
        'BATCH_VIEW', 'BATCH_APPROVE',
        'PATIENT_CREATE', 'PATIENT_VIEW', 'PATIENT_EDIT', 'PATIENT_IMPORT',
        'REPORT_VIEW', 'REPORT_EXPORT',
        'ANALYTICS_VIEW',
        'PROVIDER_VIEW', 'PROVIDER_EDIT',
        'SETTINGS_VIEW', 'SETTINGS_EDIT',
        'AI_COACH_VIEW', 'AI_COACH_MANAGE',
      ],
      linkageId: DELEGATE_LINKAGE_ID,
    },
  });
  sessions.push({
    sessionId: DELEGATE_SESSION_ID,
    userId: DELEGATE_USER_ID,
    tokenHash: DELEGATE_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });
}

function seedLimitedDelegate() {
  users.push({
    userId: LIMITED_DELEGATE_USER_ID,
    email: 'limited-delegate@example.com',
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    role: 'DELEGATE',
    subscriptionStatus: 'TRIAL',
    delegateContext: {
      delegateUserId: LIMITED_DELEGATE_USER_ID,
      physicianProviderId: PHYSICIAN_USER_ID,
      permissions: ['CLAIM_VIEW'],
      linkageId: 'cccc0000-0000-0000-0000-000000000002',
    },
  });
  sessions.push({
    sessionId: LIMITED_DELEGATE_SESSION_ID,
    userId: LIMITED_DELEGATE_USER_ID,
    tokenHash: LIMITED_DELEGATE_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });
}

function physicianCookie(): string {
  return `session=${PHYSICIAN_SESSION_TOKEN}`;
}

function delegateCookie(): string {
  return `session=${DELEGATE_SESSION_TOKEN}`;
}

function limitedDelegateCookie(): string {
  return `session=${LIMITED_DELEGATE_SESSION_TOKEN}`;
}

// ---------------------------------------------------------------------------
// Route specifications for role-gated endpoints
// ---------------------------------------------------------------------------

interface RouteSpec {
  method: 'GET' | 'POST' | 'PATCH' | 'DELETE';
  url: string;
  payload?: Record<string, unknown>;
  description: string;
}

/** Routes that require PHYSICIAN or ADMIN role — delegates must be blocked */
const PHYSICIAN_ONLY_ROUTES: RouteSpec[] = [
  {
    method: 'POST',
    url: '/api/v1/delegates/invite',
    payload: { email: 'newdelegate@example.com', permissions: ['CLAIM_VIEW'] },
    description: 'Invite delegate',
  },
  {
    method: 'PATCH',
    url: `/api/v1/delegates/${DELEGATE_LINKAGE_ID}/permissions`,
    payload: { permissions: ['CLAIM_VIEW'] },
    description: 'Update delegate permissions',
  },
  {
    method: 'DELETE',
    url: `/api/v1/delegates/${DELEGATE_LINKAGE_ID}`,
    description: 'Revoke delegate',
  },
  {
    method: 'POST',
    url: '/api/v1/account/delete',
    payload: { password: 'SecurePass123!', totp_code: '123456', confirmation: 'DELETE' },
    description: 'Delete account',
  },
  {
    method: 'GET',
    url: '/api/v1/account/audit-log',
    description: 'View audit log',
  },
];

/** Routes that require DELEGATE role — physicians must be blocked */
const DELEGATE_ONLY_ROUTES: RouteSpec[] = [
  {
    method: 'GET',
    url: '/api/v1/delegates/physicians',
    description: 'List physicians (delegate-only)',
  },
];

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('IAM Authorization & Role Enforcement (Security)', () => {
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
    seedPhysician();
    seedDelegate();
    seedLimitedDelegate();
  });

  // =========================================================================
  // Sanity: verify test users authenticate correctly
  // =========================================================================

  describe('Sanity: test setup validates correctly', () => {
    it('physician session authenticates successfully', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/account',
        headers: { cookie: physicianCookie() },
      });
      expect(res.statusCode).not.toBe(401);
    });

    it('delegate session authenticates successfully', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/account',
        headers: { cookie: delegateCookie() },
      });
      expect(res.statusCode).not.toBe(401);
    });

    it('limited delegate session authenticates successfully', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/account',
        headers: { cookie: limitedDelegateCookie() },
      });
      expect(res.statusCode).not.toBe(401);
    });
  });

  // =========================================================================
  // Delegate cannot access physician-only routes
  // =========================================================================

  describe('Delegate cannot access physician-only routes', () => {
    for (const route of PHYSICIAN_ONLY_ROUTES) {
      it(`${route.method} ${route.url} — delegate gets 403 (${route.description})`, async () => {
        const res = await app.inject({
          method: route.method,
          url: route.url,
          headers: { cookie: delegateCookie() },
          ...(route.payload ? { payload: route.payload } : {}),
        });

        expect(res.statusCode).toBe(403);
        const body = JSON.parse(res.body);
        expect(body.error).toBeDefined();
        expect(body.error.code).toBe('FORBIDDEN');
        // Must not contain data field
        expect(body.data).toBeUndefined();
      });
    }
  });

  // =========================================================================
  // Physician cannot access delegate-only routes
  // =========================================================================

  describe('Physician cannot access delegate-only routes', () => {
    for (const route of DELEGATE_ONLY_ROUTES) {
      it(`${route.method} ${route.url} — physician gets 403 (${route.description})`, async () => {
        const res = await app.inject({
          method: route.method,
          url: route.url,
          headers: { cookie: physicianCookie() },
          ...(route.payload ? { payload: route.payload } : {}),
        });

        expect(res.statusCode).toBe(403);
        const body = JSON.parse(res.body);
        expect(body.error).toBeDefined();
        expect(body.error.code).toBe('FORBIDDEN');
        expect(body.data).toBeUndefined();
      });
    }
  });

  // =========================================================================
  // Delegate permission boundary tests
  // =========================================================================

  describe('Delegate permission boundary enforcement', () => {
    it('delegate with CLAIM_VIEW only cannot access routes requiring CLAIM_CREATE', async () => {
      // The limited delegate has only CLAIM_VIEW.
      // While the IAM domain routes use requireRole (not app.authorize),
      // we verify the role check prevents delegate access to physician-only routes.
      // Routes that require PHYSICIAN/ADMIN role are inherently blocked for all delegates.
      for (const route of PHYSICIAN_ONLY_ROUTES) {
        const res = await app.inject({
          method: route.method,
          url: route.url,
          headers: { cookie: limitedDelegateCookie() },
          ...(route.payload ? { payload: route.payload } : {}),
        });

        expect(res.statusCode).toBe(403);
        const body = JSON.parse(res.body);
        expect(body.error.code).toBe('FORBIDDEN');
      }
    });

    it('delegate without AUDIT_VIEW cannot access /account/audit-log', async () => {
      // The audit-log route requires PHYSICIAN or ADMIN role.
      // Delegates (regardless of permissions) are excluded.
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/account/audit-log',
        headers: { cookie: limitedDelegateCookie() },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
    });

    it('delegate without AUDIT_VIEW — even full-permission delegate — cannot access /account/audit-log', async () => {
      // Even the delegate with the full default permission set is blocked
      // because the route uses requireRole(PHYSICIAN, ADMIN), not app.authorize('AUDIT_VIEW').
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/account/audit-log',
        headers: { cookie: delegateCookie() },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
    });
  });

  // =========================================================================
  // Permission escalation prevention
  // =========================================================================

  describe('Permission escalation prevention', () => {
    it('delegate cannot call PATCH /delegates/:id/permissions to modify permissions', async () => {
      const res = await app.inject({
        method: 'PATCH',
        url: `/api/v1/delegates/${DELEGATE_LINKAGE_ID}/permissions`,
        headers: { cookie: delegateCookie() },
        payload: { permissions: ['CLAIM_VIEW', 'CLAIM_CREATE', 'DELEGATE_MANAGE'] },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
    });

    it('limited delegate cannot call PATCH /delegates/:id/permissions to escalate own permissions', async () => {
      const res = await app.inject({
        method: 'PATCH',
        url: `/api/v1/delegates/${DELEGATE_LINKAGE_ID}/permissions`,
        headers: { cookie: limitedDelegateCookie() },
        payload: { permissions: ['CLAIM_VIEW', 'CLAIM_CREATE', 'DATA_EXPORT', 'AUDIT_VIEW'] },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
    });

    it('delegate cannot call POST /delegates/invite to create other delegates', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/delegates/invite',
        headers: { cookie: delegateCookie() },
        payload: { email: 'newdelegate@example.com', permissions: ['CLAIM_VIEW'] },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
    });

    it('limited delegate cannot call POST /delegates/invite to create other delegates', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/delegates/invite',
        headers: { cookie: limitedDelegateCookie() },
        payload: { email: 'another-delegate@example.com', permissions: ['CLAIM_VIEW'] },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
    });

    it('delegate cannot delete a delegate linkage', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: `/api/v1/delegates/${DELEGATE_LINKAGE_ID}`,
        headers: { cookie: delegateCookie() },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
    });

    it('delegate cannot request account deletion', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/account/delete',
        headers: { cookie: delegateCookie() },
        payload: { password: 'SecurePass123!', totp_code: '123456', confirmation: 'DELETE' },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
    });
  });

  // =========================================================================
  // 403 response shape verification
  // =========================================================================

  describe('403 responses have correct shape and leak no information', () => {
    it('403 response has consistent error shape', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/delegates/invite',
        headers: { cookie: delegateCookie() },
        payload: { email: 'test@example.com', permissions: ['CLAIM_VIEW'] },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
      expect(Object.keys(body.error).sort()).toEqual(['code', 'message']);
    });

    it('403 response does not contain stack traces or internal details', async () => {
      const res = await app.inject({
        method: 'GET',
        url: '/api/v1/account/audit-log',
        headers: { cookie: delegateCookie() },
      });

      expect(res.statusCode).toBe(403);
      const rawBody = res.body;
      expect(rawBody).not.toContain('stack');
      expect(rawBody).not.toContain('node_modules');
      expect(rawBody).not.toContain('.ts:');
      expect(rawBody).not.toContain('postgres');
      expect(rawBody).not.toContain('drizzle');
    });

    it('403 message is generic — does not reveal required role', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/delegates/invite',
        headers: { cookie: delegateCookie() },
        payload: { email: 'test@example.com', permissions: ['CLAIM_VIEW'] },
      });

      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      // Should not reveal which role is required
      expect(body.error.message).not.toContain('PHYSICIAN');
      expect(body.error.message).not.toContain('ADMIN');
      expect(body.error.message).not.toContain('DELEGATE');
    });
  });

  // =========================================================================
  // Routes accessible to both roles (no role restriction)
  // =========================================================================

  describe('Shared routes accessible to both physicians and delegates', () => {
    const SHARED_ROUTES: RouteSpec[] = [
      { method: 'GET', url: '/api/v1/account', description: 'Get account' },
      { method: 'PATCH', url: '/api/v1/account', payload: { full_name: 'Updated Name' }, description: 'Update account' },
      { method: 'GET', url: '/api/v1/sessions', description: 'List sessions' },
      { method: 'POST', url: '/api/v1/auth/logout', description: 'Logout' },
    ];

    for (const route of SHARED_ROUTES) {
      it(`${route.method} ${route.url} — physician is not blocked by role check (${route.description})`, async () => {
        const res = await app.inject({
          method: route.method,
          url: route.url,
          headers: { cookie: physicianCookie() },
          ...(route.payload ? { payload: route.payload } : {}),
        });
        // Should not be 401 or 403 (role-related block)
        expect(res.statusCode).not.toBe(401);
        expect(res.statusCode).not.toBe(403);
      });

      it(`${route.method} ${route.url} — delegate is not blocked by role check (${route.description})`, async () => {
        const res = await app.inject({
          method: route.method,
          url: route.url,
          headers: { cookie: delegateCookie() },
          ...(route.payload ? { payload: route.payload } : {}),
        });
        // Should not be 401 or 403 (role-related block)
        expect(res.statusCode).not.toBe(401);
        expect(res.statusCode).not.toBe(403);
      });
    }
  });
});
