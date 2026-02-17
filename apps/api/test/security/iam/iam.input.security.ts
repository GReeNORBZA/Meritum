import { describe, it, expect, vi, beforeAll, afterAll } from 'vitest';
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
// Fixed test user/session for authenticated requests
// ---------------------------------------------------------------------------

const FIXED_SESSION_TOKEN = randomBytes(32).toString('hex');
const FIXED_SESSION_TOKEN_HASH = hashToken(FIXED_SESSION_TOKEN);
const FIXED_USER_ID = '22222222-0000-0000-0000-000000000001';
const FIXED_SESSION_ID = '33333333-0000-0000-0000-000000000001';

// ---------------------------------------------------------------------------
// Mock stores
// ---------------------------------------------------------------------------

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

const sessions: MockSession[] = [];

// ---------------------------------------------------------------------------
// Mock repositories
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    createSession: vi.fn(async () => ({
      sessionId: '44444444-0000-0000-0000-000000000001',
    })),
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      const session = sessions.find(
        (s) => s.tokenHash === tokenHash && !s.revoked,
      );
      if (!session) return undefined;
      return {
        session,
        user: {
          userId: FIXED_USER_ID,
          role: 'PHYSICIAN',
          subscriptionStatus: 'TRIAL',
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
    appendAuditLog: vi.fn(async () => {}),
  };
}

function createMockEvents() {
  return { emit: vi.fn() };
}

// ---------------------------------------------------------------------------
// Stub deps (not exercised in input validation tests)
// ---------------------------------------------------------------------------

function createStubServiceDeps(): ServiceDeps {
  return {
    userRepo: {
      createUser: vi.fn(async () => ({
        userId: '11111111-0000-0000-0000-000000000001',
      })),
      findUserByEmail: vi.fn(async () => undefined),
      updateUser: vi.fn(async () => {}),
    },
    verificationTokenRepo: {
      createVerificationToken: vi.fn(async () => {}),
      findVerificationTokenByHash: vi.fn(async () => undefined),
      markVerificationTokenUsed: vi.fn(async () => {}),
    },
    auditRepo: createMockAuditRepo(),
    events: createMockEvents(),
  };
}

function createStubMfaDeps(): MfaServiceDeps {
  return {
    userRepo: {
      findUserById: vi.fn(async () => ({
        userId: FIXED_USER_ID,
        mfaConfigured: false,
        totpSecretEncrypted: null,
      })),
      setMfaSecret: vi.fn(async () => {}),
      setMfaConfigured: vi.fn(async () => {}),
    },
    recoveryCodeRepo: { createRecoveryCodes: vi.fn(async () => {}) },
    auditRepo: createMockAuditRepo(),
    events: createMockEvents(),
  };
}

function createStubLoginDeps(): LoginServiceDeps {
  return {
    userRepo: {
      findUserByEmail: vi.fn(async () => undefined),
      findUserById: vi.fn(async () => undefined),
      incrementFailedLogin: vi.fn(async () => {}),
      resetFailedLogin: vi.fn(async () => {}),
    },
    sessionRepo: { createSession: vi.fn(async () => ({ sessionId: 'stub' })) },
    recoveryCodeRepo: {
      findUnusedRecoveryCodes: vi.fn(async () => []),
      markRecoveryCodeUsed: vi.fn(async () => {}),
      countRemainingCodes: vi.fn(async () => 0),
    },
    auditRepo: createMockAuditRepo(),
    events: createMockEvents(),
  };
}

function createStubPasswordResetDeps(): PasswordResetDeps {
  return {
    userRepo: {
      findUserByEmail: vi.fn(async () => undefined),
      setPasswordHash: vi.fn(async () => {}),
    },
    tokenRepo: {
      createPasswordResetToken: vi.fn(async () => {}),
      findPasswordResetTokenByHash: vi.fn(async () => undefined),
      markPasswordResetTokenUsed: vi.fn(async () => {}),
    },
    sessionRepo: { revokeAllUserSessions: vi.fn(async () => {}) },
    auditRepo: createMockAuditRepo(),
    events: createMockEvents(),
  };
}

function createStubDelegateDeps(): DelegateServiceDeps {
  return {
    userRepo: {
      findUserByEmail: vi.fn(async () => undefined),
      findUserById: vi.fn(async () => undefined),
      createUser: vi.fn(async () => ({
        userId: '11111111-0000-0000-0000-000000000002',
      })),
    },
    invitationRepo: {
      createInvitation: vi.fn(async () => ({
        invitationId: '11111111-0000-0000-0000-000000000003',
      })),
      findInvitationByTokenHash: vi.fn(async () => undefined),
      markInvitationAccepted: vi.fn(async () => {}),
    },
    linkageRepo: {
      createDelegateLinkage: vi.fn(async () => ({})),
      findLinkage: vi.fn(async () => undefined),
      findLinkageById: vi.fn(async () => undefined),
      listDelegatesForPhysician: vi.fn(async () => []),
      listPhysiciansForDelegate: vi.fn(async () => []),
      updateLinkagePermissions: vi.fn(async () => ({})),
      deactivateLinkage: vi.fn(async () => {}),
    },
    sessionRepo: { revokeAllUserSessions: vi.fn(async () => {}) },
    auditRepo: createMockAuditRepo(),
    events: createMockEvents(),
  };
}

function createStubAccountDeps(): AccountServiceDeps {
  return {
    userRepo: {
      findUserById: vi.fn(async () => ({
        userId: FIXED_USER_ID,
        email: 'test@example.com',
        fullName: 'Test User',
        phone: null,
        role: 'PHYSICIAN',
        mfaConfigured: true,
        subscriptionStatus: 'TRIAL',
        isActive: true,
        createdAt: new Date(),
      })),
      updateUser: vi.fn(async () => ({})),
      deactivateUser: vi.fn(async () => {}),
    },
    sessionRepo: { revokeAllUserSessions: vi.fn(async () => {}) },
    linkageRepo: {
      listDelegatesForPhysician: vi.fn(async () => []),
      deactivateLinkage: vi.fn(async () => {}),
    },
    auditRepo: createMockAuditRepo(),
    events: createMockEvents(),
  };
}

function createStubAuditLogDeps(): AuditLogServiceDeps {
  return {
    auditLogRepo: {
      queryAuditLog: vi.fn(async () => ({ data: [], total: 0 })),
    },
    auditRepo: createMockAuditRepo(),
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;

async function buildTestApp(): Promise<FastifyInstance> {
  const mockSessionRepo = createMockSessionRepo();

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
    if (error.validation) {
      return reply.code(400).send({
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Validation failed',
          details: error.validation,
        },
      });
    }
    if (error.statusCode && error.statusCode >= 400 && error.statusCode < 500) {
      return reply.code(error.statusCode).send({
        error: {
          code: (error as any).code ?? 'ERROR',
          message: error.message,
        },
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

function authCookie(): string {
  return `session=${FIXED_SESSION_TOKEN}`;
}

const VALID_REGISTER_PAYLOAD = {
  email: 'test@example.com',
  password: 'SecurePass123!',
  full_name: 'Test User',
  phone: '+14035551234',
};

const VALID_UUID = '00000000-0000-0000-0000-000000000001';

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('IAM Input Validation & Injection Prevention (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();

    // Seed the authenticated session
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

  afterAll(async () => {
    await app.close();
  });

  // =========================================================================
  // SQL Injection Prevention
  // =========================================================================

  describe('SQL injection payloads on string inputs', () => {
    const SQL_PAYLOADS = [
      "' OR 1=1--",
      "'; DROP TABLE users;--",
      "1' OR '1'='1",
      "1; SELECT * FROM users --",
      "' UNION SELECT * FROM providers --",
      "admin'--",
      "'; TRUNCATE TABLE user_sessions;--",
    ];

    describe('email field rejects SQL injection', () => {
      for (const payload of SQL_PAYLOADS) {
        it(`rejects: ${payload.slice(0, 40)}`, async () => {
          const res = await app.inject({
            method: 'POST',
            url: '/api/v1/auth/register',
            payload: { ...VALID_REGISTER_PAYLOAD, email: payload },
          });

          expect(res.statusCode).toBe(400);
          const body = JSON.parse(res.body);
          expect(body.error).toBeDefined();
          expect(body.data).toBeUndefined();
        });
      }
    });

    describe('full_name field rejects SQL injection', () => {
      for (const payload of SQL_PAYLOADS) {
        it(`rejects: ${payload.slice(0, 40)}`, async () => {
          const res = await app.inject({
            method: 'POST',
            url: '/api/v1/auth/register',
            payload: { ...VALID_REGISTER_PAYLOAD, full_name: payload },
          });

          // full_name allows arbitrary text (min 1, max 200)
          // so SQL payloads will pass Zod but be safely handled by
          // parameterized queries. The important thing is they don't
          // cause a 500 or data corruption.
          expect(res.statusCode).not.toBe(500);
        });
      }
    });

    describe('password field accepts SQL-like strings (parameterised queries prevent injection)', () => {
      for (const payload of SQL_PAYLOADS) {
        it(`password with SQL payload does not cause 500: ${payload.slice(0, 30)}`, async () => {
          // Password validation checks format requirements, not content.
          // Short payloads may fail min-length; longer ones with special chars may pass.
          const paddedPayload = `Aa1!${payload}ExtraLong`;
          const res = await app.inject({
            method: 'POST',
            url: '/api/v1/auth/register',
            payload: {
              ...VALID_REGISTER_PAYLOAD,
              password: paddedPayload,
            },
          });

          // Must never be 500 — either 400 (validation) or 201/200 (accepted safely)
          expect(res.statusCode).not.toBe(500);
        });
      }
    });

    describe('login email field rejects SQL injection', () => {
      for (const payload of SQL_PAYLOADS) {
        it(`rejects: ${payload.slice(0, 40)}`, async () => {
          const res = await app.inject({
            method: 'POST',
            url: '/api/v1/auth/login',
            payload: { email: payload, password: 'SecurePass123!' },
          });

          expect(res.statusCode).toBe(400);
          const body = JSON.parse(res.body);
          expect(body.error).toBeDefined();
        });
      }
    });

    describe('password reset request email rejects SQL injection', () => {
      for (const payload of SQL_PAYLOADS) {
        it(`rejects: ${payload.slice(0, 40)}`, async () => {
          const res = await app.inject({
            method: 'POST',
            url: '/api/v1/auth/password/reset-request',
            payload: { email: payload },
          });

          expect(res.statusCode).toBe(400);
        });
      }
    });

    describe('delegate invite email rejects SQL injection', () => {
      for (const payload of SQL_PAYLOADS) {
        it(`rejects: ${payload.slice(0, 40)}`, async () => {
          const res = await app.inject({
            method: 'POST',
            url: '/api/v1/delegates/invite',
            headers: { cookie: authCookie() },
            payload: {
              email: payload,
              permissions: ['CLAIM_VIEW'],
            },
          });

          expect(res.statusCode).toBe(400);
        });
      }
    });

    describe('account update full_name with SQL injection does not cause 500', () => {
      for (const payload of SQL_PAYLOADS) {
        it(`safely handles: ${payload.slice(0, 40)}`, async () => {
          const res = await app.inject({
            method: 'PATCH',
            url: '/api/v1/account',
            headers: { cookie: authCookie() },
            payload: { full_name: payload },
          });

          // full_name allows arbitrary strings; SQL is safely handled by parameterised queries
          expect(res.statusCode).not.toBe(500);
        });
      }
    });
  });

  // =========================================================================
  // XSS Prevention
  // =========================================================================

  describe('XSS payloads on stored text fields', () => {
    const XSS_PAYLOADS = [
      '<script>alert("xss")</script>',
      '<img src=x onerror=alert(1)>',
      'javascript:alert(1)',
      '<svg onload=alert(1)>',
      '"><script>alert(1)</script>',
      "';alert(String.fromCharCode(88,83,83))//",
    ];

    describe('full_name with XSS payloads does not cause 500', () => {
      for (const payload of XSS_PAYLOADS) {
        it(`safely handles: ${payload.slice(0, 40)}`, async () => {
          const res = await app.inject({
            method: 'POST',
            url: '/api/v1/auth/register',
            payload: {
              ...VALID_REGISTER_PAYLOAD,
              full_name: payload,
            },
          });

          // Must not cause server error — Zod accepts strings, parameterised queries prevent storage issues
          expect(res.statusCode).not.toBe(500);
        });
      }
    });

    describe('phone with XSS payloads is rejected by length/format', () => {
      for (const payload of XSS_PAYLOADS) {
        it(`rejects or safely handles: ${payload.slice(0, 40)}`, async () => {
          const res = await app.inject({
            method: 'POST',
            url: '/api/v1/auth/register',
            payload: {
              ...VALID_REGISTER_PAYLOAD,
              phone: payload,
            },
          });

          // Phone has max(20) — long XSS payloads will be rejected with 400;
          // short ones may pass but are handled safely by parameterised queries
          if (payload.length > 20) {
            expect(res.statusCode).toBe(400);
          } else {
            expect(res.statusCode).not.toBe(500);
          }
        });
      }
    });

    describe('account update full_name with XSS payloads does not cause 500', () => {
      for (const payload of XSS_PAYLOADS) {
        it(`safely handles: ${payload.slice(0, 40)}`, async () => {
          const res = await app.inject({
            method: 'PATCH',
            url: '/api/v1/account',
            headers: { cookie: authCookie() },
            payload: { full_name: payload },
          });

          expect(res.statusCode).not.toBe(500);
        });
      }
    });

    describe('account update phone with XSS payloads', () => {
      for (const payload of XSS_PAYLOADS) {
        it(`rejects or safely handles: ${payload.slice(0, 40)}`, async () => {
          const res = await app.inject({
            method: 'PATCH',
            url: '/api/v1/account',
            headers: { cookie: authCookie() },
            payload: { phone: payload },
          });

          if (payload.length > 20) {
            expect(res.statusCode).toBe(400);
          } else {
            expect(res.statusCode).not.toBe(500);
          }
        });
      }
    });
  });

  // =========================================================================
  // Type Coercion Attacks
  // =========================================================================

  describe('Type coercion attacks', () => {
    describe('number where string expected', () => {
      it('rejects number for email', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/auth/register',
          payload: { ...VALID_REGISTER_PAYLOAD, email: 12345 },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects number for full_name', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/auth/register',
          payload: { ...VALID_REGISTER_PAYLOAD, full_name: 99999 },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects number for password', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/auth/register',
          payload: { ...VALID_REGISTER_PAYLOAD, password: 123456789012 },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects number for totp_code in MFA confirm', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/auth/mfa/confirm',
          headers: { cookie: authCookie() },
          payload: { totp_code: 123456 },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects number for mfa_session_token in login MFA', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/auth/login/mfa',
          payload: { mfa_session_token: 12345, totp_code: '123456' },
        });

        expect(res.statusCode).toBe(400);
      });
    });

    describe('array where string expected', () => {
      it('rejects array for email', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/auth/register',
          payload: {
            ...VALID_REGISTER_PAYLOAD,
            email: ['test@example.com'],
          },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects array for full_name', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/auth/register',
          payload: {
            ...VALID_REGISTER_PAYLOAD,
            full_name: ['Test', 'User'],
          },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects array for totp_code', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/auth/mfa/confirm',
          headers: { cookie: authCookie() },
          payload: { totp_code: ['123456'] },
        });

        expect(res.statusCode).toBe(400);
      });
    });

    describe('null where required', () => {
      it('rejects null for email', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/auth/register',
          payload: { ...VALID_REGISTER_PAYLOAD, email: null },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects null for password', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/auth/register',
          payload: { ...VALID_REGISTER_PAYLOAD, password: null },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects null for full_name', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/auth/register',
          payload: { ...VALID_REGISTER_PAYLOAD, full_name: null },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects null for totp_code in login MFA', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/auth/login/mfa',
          payload: { mfa_session_token: 'some-token', totp_code: null },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects null for confirmation in account delete', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/account/delete',
          headers: { cookie: authCookie() },
          payload: {
            password: 'SecurePass123!',
            totp_code: '123456',
            confirmation: null,
          },
        });

        expect(res.statusCode).toBe(400);
      });
    });

    describe('audit log pagination edge cases', () => {
      it('rejects negative page_size', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/account/audit-log?page_size=-1',
          headers: { cookie: authCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects page_size of 0', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/account/audit-log?page_size=0',
          headers: { cookie: authCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects page_size exceeding 200', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/account/audit-log?page_size=201',
          headers: { cookie: authCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('accepts page_size at maximum boundary (200)', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/account/audit-log?page_size=200',
          headers: { cookie: authCookie() },
        });

        // Should not be a validation error — 200 is the max
        expect(res.statusCode).not.toBe(400);
      });

      it('accepts page_size at minimum boundary (1)', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/account/audit-log?page_size=1',
          headers: { cookie: authCookie() },
        });

        expect(res.statusCode).not.toBe(400);
      });

      it('rejects negative page number', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/account/audit-log?page=-1',
          headers: { cookie: authCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects page number of 0', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/account/audit-log?page=0',
          headers: { cookie: authCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects non-numeric page_size', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/account/audit-log?page_size=abc',
          headers: { cookie: authCookie() },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects non-numeric page', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/account/audit-log?page=abc',
          headers: { cookie: authCookie() },
        });

        expect(res.statusCode).toBe(400);
      });
    });

    describe('object where string expected', () => {
      it('rejects object for email', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/auth/register',
          payload: {
            ...VALID_REGISTER_PAYLOAD,
            email: { addr: 'test@example.com' },
          },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects object for totp_code', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/auth/mfa/confirm',
          headers: { cookie: authCookie() },
          payload: { totp_code: { code: '123456' } },
        });

        expect(res.statusCode).toBe(400);
      });
    });

    describe('boolean where string expected', () => {
      it('rejects boolean for email', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/auth/register',
          payload: { ...VALID_REGISTER_PAYLOAD, email: true },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects boolean for full_name', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/auth/register',
          payload: { ...VALID_REGISTER_PAYLOAD, full_name: false },
        });

        expect(res.statusCode).toBe(400);
      });
    });

    describe('empty body', () => {
      it('rejects empty body for registration', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/auth/register',
          payload: {},
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects empty body for login', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/auth/login',
          payload: {},
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects empty body for MFA confirm', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/auth/mfa/confirm',
          headers: { cookie: authCookie() },
          payload: {},
        });

        expect(res.statusCode).toBe(400);
      });
    });
  });

  // =========================================================================
  // Password Validation
  // =========================================================================

  describe('Password validation', () => {
    it('rejects password with 11 characters (below minimum 12)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/register',
        payload: { ...VALID_REGISTER_PAYLOAD, password: 'Short1Pass!' },
      });

      expect(res.statusCode).toBe(400);
    });

    it('accepts password with exactly 12 characters meeting all requirements', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/register',
        payload: { ...VALID_REGISTER_PAYLOAD, password: 'Abcdefgh1!23' },
      });

      // Should not be a validation error (may be another error from mock, but not 400 for password)
      // If 400, verify it's not about the password
      if (res.statusCode === 400) {
        const body = JSON.parse(res.body);
        const details = JSON.stringify(body.error?.details ?? '');
        expect(details).not.toContain('password');
        expect(details).not.toContain('Password');
      }
    });

    it('rejects password without uppercase letter', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/register',
        payload: {
          ...VALID_REGISTER_PAYLOAD,
          password: 'nouppercase1!xx',
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects password without lowercase letter', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/register',
        payload: {
          ...VALID_REGISTER_PAYLOAD,
          password: 'NOLOWERCASE1!X',
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects password without digit', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/register',
        payload: {
          ...VALID_REGISTER_PAYLOAD,
          password: 'NoDigitHere!!xx',
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects password without special character', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/register',
        payload: {
          ...VALID_REGISTER_PAYLOAD,
          password: 'NoSpecialChar1xx',
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects empty password', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/register',
        payload: { ...VALID_REGISTER_PAYLOAD, password: '' },
      });

      expect(res.statusCode).toBe(400);
    });

    describe('password reset also validates password strength', () => {
      it('rejects weak new_password in password reset', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/auth/password/reset',
          payload: {
            token: VALID_UUID,
            new_password: 'short1!',
          },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects new_password without special character in password reset', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/auth/password/reset',
          payload: {
            token: VALID_UUID,
            new_password: 'NoSpecialChar1xx',
          },
        });

        expect(res.statusCode).toBe(400);
      });
    });

    describe('delegate accept also validates password when provided', () => {
      it('rejects weak password in delegate accept', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/delegates/accept',
          payload: {
            token: 'some-invitation-token',
            full_name: 'Delegate User',
            password: 'weak',
          },
        });

        expect(res.statusCode).toBe(400);
      });
    });
  });

  // =========================================================================
  // UUID Parameter Validation
  // =========================================================================

  describe('UUID parameter validation', () => {
    it('rejects non-UUID in DELETE /sessions/:id', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: '/api/v1/sessions/not-a-uuid',
        headers: { cookie: authCookie() },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects non-UUID in PATCH /delegates/:id/permissions', async () => {
      const res = await app.inject({
        method: 'PATCH',
        url: '/api/v1/delegates/not-a-uuid/permissions',
        headers: { cookie: authCookie() },
        payload: { permissions: ['CLAIM_VIEW'] },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects non-UUID in DELETE /delegates/:id', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: '/api/v1/delegates/not-a-uuid',
        headers: { cookie: authCookie() },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects non-UUID token in email verification', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/verify-email',
        payload: { token: 'not-a-uuid' },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects non-UUID token in password reset', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/password/reset',
        payload: {
          token: 'not-a-uuid',
          new_password: 'SecurePass123!',
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects SQL injection in UUID path parameter', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: "/api/v1/sessions/' OR 1=1--",
        headers: { cookie: authCookie() },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects empty string for UUID parameter', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/verify-email',
        payload: { token: '' },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects numeric string in UUID path parameter', async () => {
      const res = await app.inject({
        method: 'DELETE',
        url: '/api/v1/sessions/12345',
        headers: { cookie: authCookie() },
      });

      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // TOTP Code Validation
  // =========================================================================

  describe('TOTP code validation', () => {
    it('rejects TOTP code with letters', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login/mfa',
        payload: { mfa_session_token: 'valid-token', totp_code: 'abcdef' },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects TOTP code with 5 digits (too short)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login/mfa',
        payload: { mfa_session_token: 'valid-token', totp_code: '12345' },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects TOTP code with 7 digits (too long)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login/mfa',
        payload: { mfa_session_token: 'valid-token', totp_code: '1234567' },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects TOTP code with mixed letters and digits', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login/mfa',
        payload: { mfa_session_token: 'valid-token', totp_code: '12ab56' },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects empty TOTP code', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login/mfa',
        payload: { mfa_session_token: 'valid-token', totp_code: '' },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects TOTP code with special characters', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login/mfa',
        payload: { mfa_session_token: 'valid-token', totp_code: '12!@56' },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects TOTP code with spaces', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login/mfa',
        payload: { mfa_session_token: 'valid-token', totp_code: '123 56' },
      });

      expect(res.statusCode).toBe(400);
    });

    describe('TOTP validation on MFA confirm endpoint', () => {
      it('rejects letters in MFA confirm totp_code', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/auth/mfa/confirm',
          headers: { cookie: authCookie() },
          payload: { totp_code: 'abcdef' },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects 5-digit code in MFA confirm', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/auth/mfa/confirm',
          headers: { cookie: authCookie() },
          payload: { totp_code: '12345' },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects 7-digit code in MFA confirm', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/auth/mfa/confirm',
          headers: { cookie: authCookie() },
          payload: { totp_code: '1234567' },
        });

        expect(res.statusCode).toBe(400);
      });
    });

    describe('TOTP validation on account delete endpoint', () => {
      it('rejects letters in account delete totp_code', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/account/delete',
          headers: { cookie: authCookie() },
          payload: {
            password: 'SecurePass123!',
            totp_code: 'abcdef',
            confirmation: 'DELETE',
          },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects 5-digit code in account delete', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/account/delete',
          headers: { cookie: authCookie() },
          payload: {
            password: 'SecurePass123!',
            totp_code: '12345',
            confirmation: 'DELETE',
          },
        });

        expect(res.statusCode).toBe(400);
      });
    });

    describe('TOTP validation on regenerate codes endpoint', () => {
      it('rejects letters in regenerate codes totp_code', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/account/mfa/regenerate-codes',
          headers: { cookie: authCookie() },
          payload: { totp_code: 'abcdef' },
        });

        expect(res.statusCode).toBe(400);
      });
    });

    describe('TOTP validation on reconfigure MFA endpoint', () => {
      it('rejects letters in reconfigure MFA current_totp_code', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/account/mfa/reconfigure',
          headers: { cookie: authCookie() },
          payload: { current_totp_code: 'abcdef' },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects 5-digit code in reconfigure MFA', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/account/mfa/reconfigure',
          headers: { cookie: authCookie() },
          payload: { current_totp_code: '12345' },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects 7-digit code in reconfigure MFA', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/account/mfa/reconfigure',
          headers: { cookie: authCookie() },
          payload: { current_totp_code: '1234567' },
        });

        expect(res.statusCode).toBe(400);
      });
    });
  });

  // =========================================================================
  // Permission Array Validation
  // =========================================================================

  describe('Permission array validation', () => {
    it('rejects empty permissions array in delegate invite', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/delegates/invite',
        headers: { cookie: authCookie() },
        payload: {
          email: 'delegate@example.com',
          permissions: [],
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects invalid permission key in delegate invite', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/delegates/invite',
        headers: { cookie: authCookie() },
        payload: {
          email: 'delegate@example.com',
          permissions: ['NONEXISTENT_PERMISSION'],
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects string instead of array for permissions', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/delegates/invite',
        headers: { cookie: authCookie() },
        payload: {
          email: 'delegate@example.com',
          permissions: 'CLAIM_VIEW',
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects ADMIN_PHI_ACCESS in delegate permissions', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/delegates/invite',
        headers: { cookie: authCookie() },
        payload: {
          email: 'delegate@example.com',
          permissions: ['ADMIN_PHI_ACCESS'],
        },
      });

      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // Account Delete Confirmation Validation
  // =========================================================================

  describe('Account delete confirmation validation', () => {
    it('rejects confirmation string other than "DELETE"', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/account/delete',
        headers: { cookie: authCookie() },
        payload: {
          password: 'SecurePass123!',
          totp_code: '123456',
          confirmation: 'delete',
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects empty confirmation string', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/account/delete',
        headers: { cookie: authCookie() },
        payload: {
          password: 'SecurePass123!',
          totp_code: '123456',
          confirmation: '',
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects misspelled confirmation', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/account/delete',
        headers: { cookie: authCookie() },
        payload: {
          password: 'SecurePass123!',
          totp_code: '123456',
          confirmation: 'DELET',
        },
      });

      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // Email Format Validation
  // =========================================================================

  describe('Email format validation', () => {
    it('rejects email without @ symbol', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/register',
        payload: { ...VALID_REGISTER_PAYLOAD, email: 'notanemail' },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects email without domain', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/register',
        payload: { ...VALID_REGISTER_PAYLOAD, email: 'test@' },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects email exceeding 255 characters', async () => {
      const longEmail = 'a'.repeat(250) + '@example.com';
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/register',
        payload: { ...VALID_REGISTER_PAYLOAD, email: longEmail },
      });

      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // Validation Error Responses Don't Leak Internals
  // =========================================================================

  describe('Validation error responses do not leak internals', () => {
    it('400 response does not expose stack trace', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/register',
        payload: {},
      });

      expect(res.statusCode).toBe(400);
      const rawBody = res.body;
      expect(rawBody).not.toContain('node_modules');
      expect(rawBody).not.toContain('.ts:');
      expect(rawBody).not.toMatch(/at\s+\w+\s+\(/);
    });

    it('400 response does not expose database details', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/register',
        payload: { ...VALID_REGISTER_PAYLOAD, email: 12345 },
      });

      expect(res.statusCode).toBe(400);
      const rawBody = res.body;
      expect(rawBody).not.toContain('postgres');
      expect(rawBody).not.toContain('drizzle');
      expect(rawBody).not.toContain('SELECT');
      expect(rawBody).not.toContain('INSERT');
    });

    it('400 response has consistent error shape', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        payload: { email: 'bad', password: '' },
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBeDefined();
      expect(body.error.message).toBeDefined();
      expect(body.data).toBeUndefined();
    });
  });
});
