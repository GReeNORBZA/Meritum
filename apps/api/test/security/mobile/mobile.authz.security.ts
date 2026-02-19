// ============================================================================
// Domain 10: Mobile Companion — Authorization & Permission Enforcement (Security)
// Verifies role-based and permission-based access control across all 15
// authenticated mobile domain routes (6 shift + 5 favourite + 4 mobile).
//
// Test identities:
//   - Physician: full access (all permissions, PHYSICIAN role)
//   - Delegate (CLAIM_VIEW only): can view shifts/favourites/summary, blocked
//     from creating claims, patients, favourites, or managing shifts
//   - Delegate (CLAIM_CREATE only): can create quick claims, blocked from views
//   - Delegate (PATIENT_CREATE only): can create patients, blocked from claims/views
//   - Delegate (no permissions): blocked from everything
//   - Admin: passes all permission checks
//
// Shift routes require PHYSICIAN role — delegates are always blocked from
// shift management (start, end, log patient) regardless of permissions.
// ============================================================================

import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Environment setup (must be before imports that read env)
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
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { shiftRoutes } from '../../../src/domains/mobile/routes/shift.routes.js';
import { favouriteRoutes } from '../../../src/domains/mobile/routes/favourite.routes.js';
import { mobileRoutes } from '../../../src/domains/mobile/routes/mobile.routes.js';
import type { ShiftRouteDeps } from '../../../src/domains/mobile/routes/shift.routes.js';
import type { FavouriteRouteDeps } from '../../../src/domains/mobile/routes/favourite.routes.js';
import type { MobileRouteDeps } from '../../../src/domains/mobile/routes/mobile.routes.js';
import {
  type SessionManagementDeps,
  hashToken,
} from '../../../src/domains/iam/iam.service.js';

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

// Physician (full access — PHYSICIAN role, all permissions)
const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_USER_ID = '11111111-0000-0000-0000-000000000001';
const PHYSICIAN_SESSION_ID = '11111111-0000-0000-0000-000000000011';

// Delegate with CLAIM_VIEW only
const DELEGATE_VIEW_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_VIEW_SESSION_TOKEN_HASH = hashToken(DELEGATE_VIEW_SESSION_TOKEN);
const DELEGATE_VIEW_USER_ID = '22222222-0000-0000-0000-000000000002';
const DELEGATE_VIEW_SESSION_ID = '22222222-0000-0000-0000-000000000022';

// Delegate with CLAIM_CREATE only
const DELEGATE_CREATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_CREATE_SESSION_TOKEN_HASH = hashToken(DELEGATE_CREATE_SESSION_TOKEN);
const DELEGATE_CREATE_USER_ID = '33333333-0000-0000-0000-000000000003';
const DELEGATE_CREATE_SESSION_ID = '33333333-0000-0000-0000-000000000033';

// Delegate with PATIENT_CREATE only
const DELEGATE_PATIENT_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_PATIENT_SESSION_TOKEN_HASH = hashToken(DELEGATE_PATIENT_SESSION_TOKEN);
const DELEGATE_PATIENT_USER_ID = '44444444-0000-0000-0000-000000000004';
const DELEGATE_PATIENT_SESSION_ID = '44444444-0000-0000-0000-000000000044';

// Delegate with CLAIM_VIEW + CLAIM_CREATE (tests boundary between view+create)
const DELEGATE_VIEW_CREATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_VIEW_CREATE_SESSION_TOKEN_HASH = hashToken(DELEGATE_VIEW_CREATE_SESSION_TOKEN);
const DELEGATE_VIEW_CREATE_USER_ID = '55555555-0000-0000-0000-000000000005';
const DELEGATE_VIEW_CREATE_SESSION_ID = '55555555-0000-0000-0000-000000000055';

// Delegate with no relevant permissions (only has an irrelevant permission)
const DELEGATE_NONE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_NONE_SESSION_TOKEN_HASH = hashToken(DELEGATE_NONE_SESSION_TOKEN);
const DELEGATE_NONE_USER_ID = '77777777-0000-0000-0000-000000000007';
const DELEGATE_NONE_SESSION_ID = '77777777-0000-0000-0000-000000000077';

// Admin user
const ADMIN_SESSION_TOKEN = randomBytes(32).toString('hex');
const ADMIN_SESSION_TOKEN_HASH = hashToken(ADMIN_SESSION_TOKEN);
const ADMIN_USER_ID = '99999999-0000-0000-0000-000000000009';
const ADMIN_SESSION_ID = '99999999-0000-0000-0000-000000000099';

// Placeholder UUID for route params
const PLACEHOLDER_UUID = '00000000-0000-0000-0000-000000000001';

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

// ---------------------------------------------------------------------------
// Mock repositories
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    createSession: vi.fn(async () => ({ sessionId: 'new-session-id' })),
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      const session = sessions.find((s) => s.tokenHash === tokenHash && !s.revoked);
      if (!session) return undefined;
      const user = users.find((u) => u.userId === session.userId);
      if (!user) return undefined;
      const result: any = {
        session,
        user: {
          userId: user.userId,
          role: user.role,
          subscriptionStatus: user.subscriptionStatus,
        },
      };
      if (user.delegateContext) {
        result.user.delegateContext = user.delegateContext;
      }
      return result;
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
// Stub handler deps (not exercised — authz tests stop before reaching handlers)
// ---------------------------------------------------------------------------

function createStubShiftDeps(): ShiftRouteDeps {
  return {
    serviceDeps: {
      shiftRepo: {
        create: vi.fn(),
        findActive: vi.fn(),
        endShift: vi.fn(),
        findById: vi.fn(),
        listByProvider: vi.fn(),
        logPatient: vi.fn(),
        getShiftSummary: vi.fn(),
      } as any,
      claimRepo: {
        createDraftClaim: vi.fn(),
      } as any,
      auditLog: vi.fn(async () => {}),
    } as any,
  };
}

function createStubFavouriteDeps(): FavouriteRouteDeps {
  return {
    serviceDeps: {
      favouriteRepo: {
        listByProvider: vi.fn(),
        create: vi.fn(),
        update: vi.fn(),
        delete: vi.fn(),
        countByProvider: vi.fn(),
        reorder: vi.fn(),
        findById: vi.fn(),
      } as any,
      referenceRepo: {
        findByCode: vi.fn(),
      } as any,
      auditLog: vi.fn(async () => {}),
    } as any,
  };
}

function createStubMobileDeps(): MobileRouteDeps {
  return {
    quickClaimServiceDeps: {
      claimRepo: { createDraftClaim: vi.fn() } as any,
      patientRepo: {
        create: vi.fn(),
        findByProvider: vi.fn(),
        findById: vi.fn(),
        getRecentByProvider: vi.fn(),
      } as any,
      referenceRepo: { findByCode: vi.fn() } as any,
      auditLog: vi.fn(async () => {}),
    } as any,
    summaryServiceDeps: {
      summaryRepo: {
        getTodayCounts: vi.fn(),
        getWeekRevenue: vi.fn(),
        getActiveShift: vi.fn(),
        getPendingCount: vi.fn(),
      } as any,
      auditLog: vi.fn(async () => {}),
    } as any,
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

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  await testApp.register(authPluginFp, { sessionDeps });

  testApp.setErrorHandler((error, _request, reply) => {
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

  await testApp.register(shiftRoutes, { deps: createStubShiftDeps() });
  await testApp.register(favouriteRoutes, { deps: createStubFavouriteDeps() });
  await testApp.register(mobileRoutes, { deps: createStubMobileDeps() });

  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------

function physicianRequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function delegateViewRequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${DELEGATE_VIEW_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function delegateCreateRequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${DELEGATE_CREATE_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function delegatePatientRequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${DELEGATE_PATIENT_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function delegateViewCreateRequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${DELEGATE_VIEW_CREATE_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function delegateNoneRequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${DELEGATE_NONE_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function adminRequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${ADMIN_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

// ---------------------------------------------------------------------------
// Seed test data
// ---------------------------------------------------------------------------

function seedUsers() {
  users = [];
  sessions = [];

  // Physician user (full access)
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

  // Delegate with CLAIM_VIEW only
  users.push({
    userId: DELEGATE_VIEW_USER_ID,
    email: 'delegate-view@example.com',
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    role: 'DELEGATE',
    subscriptionStatus: 'TRIAL',
    delegateContext: {
      delegateUserId: DELEGATE_VIEW_USER_ID,
      physicianProviderId: PHYSICIAN_USER_ID,
      permissions: ['CLAIM_VIEW'],
      linkageId: 'aaaaaaaa-0000-0000-0000-000000000001',
    },
  });
  sessions.push({
    sessionId: DELEGATE_VIEW_SESSION_ID,
    userId: DELEGATE_VIEW_USER_ID,
    tokenHash: DELEGATE_VIEW_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

  // Delegate with CLAIM_CREATE only
  users.push({
    userId: DELEGATE_CREATE_USER_ID,
    email: 'delegate-create@example.com',
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    role: 'DELEGATE',
    subscriptionStatus: 'TRIAL',
    delegateContext: {
      delegateUserId: DELEGATE_CREATE_USER_ID,
      physicianProviderId: PHYSICIAN_USER_ID,
      permissions: ['CLAIM_CREATE'],
      linkageId: 'bbbbbbbb-0000-0000-0000-000000000002',
    },
  });
  sessions.push({
    sessionId: DELEGATE_CREATE_SESSION_ID,
    userId: DELEGATE_CREATE_USER_ID,
    tokenHash: DELEGATE_CREATE_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

  // Delegate with PATIENT_CREATE only
  users.push({
    userId: DELEGATE_PATIENT_USER_ID,
    email: 'delegate-patient@example.com',
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    role: 'DELEGATE',
    subscriptionStatus: 'TRIAL',
    delegateContext: {
      delegateUserId: DELEGATE_PATIENT_USER_ID,
      physicianProviderId: PHYSICIAN_USER_ID,
      permissions: ['PATIENT_CREATE'],
      linkageId: 'cccccccc-0000-0000-0000-000000000003',
    },
  });
  sessions.push({
    sessionId: DELEGATE_PATIENT_SESSION_ID,
    userId: DELEGATE_PATIENT_USER_ID,
    tokenHash: DELEGATE_PATIENT_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

  // Delegate with CLAIM_VIEW + CLAIM_CREATE
  users.push({
    userId: DELEGATE_VIEW_CREATE_USER_ID,
    email: 'delegate-viewcreate@example.com',
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    role: 'DELEGATE',
    subscriptionStatus: 'TRIAL',
    delegateContext: {
      delegateUserId: DELEGATE_VIEW_CREATE_USER_ID,
      physicianProviderId: PHYSICIAN_USER_ID,
      permissions: ['CLAIM_VIEW', 'CLAIM_CREATE'],
      linkageId: 'dddddddd-0000-0000-0000-000000000004',
    },
  });
  sessions.push({
    sessionId: DELEGATE_VIEW_CREATE_SESSION_ID,
    userId: DELEGATE_VIEW_CREATE_USER_ID,
    tokenHash: DELEGATE_VIEW_CREATE_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

  // Delegate with no relevant permissions
  users.push({
    userId: DELEGATE_NONE_USER_ID,
    email: 'delegate-none@example.com',
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    role: 'DELEGATE',
    subscriptionStatus: 'TRIAL',
    delegateContext: {
      delegateUserId: DELEGATE_NONE_USER_ID,
      physicianProviderId: PHYSICIAN_USER_ID,
      permissions: ['REPORT_VIEW'],
      linkageId: 'ffffffff-0000-0000-0000-000000000006',
    },
  });
  sessions.push({
    sessionId: DELEGATE_NONE_SESSION_ID,
    userId: DELEGATE_NONE_USER_ID,
    tokenHash: DELEGATE_NONE_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

  // Admin user (passes all permission checks per auth plugin)
  users.push({
    userId: ADMIN_USER_ID,
    email: 'admin@meritum.ca',
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    role: 'ADMIN',
    subscriptionStatus: 'ACTIVE',
  });
  sessions.push({
    sessionId: ADMIN_SESSION_ID,
    userId: ADMIN_USER_ID,
    tokenHash: ADMIN_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });
}

// ---------------------------------------------------------------------------
// Valid payloads (for POST/PUT routes that require body)
// ---------------------------------------------------------------------------

const validShiftPayload = { location_id: PLACEHOLDER_UUID };

const validLogPatientPayload = {
  patient_id: PLACEHOLDER_UUID,
  health_service_code: '03.04A',
  date_of_service: '2026-02-19',
};

const validQuickClaimPayload = {
  patient_id: PLACEHOLDER_UUID,
  health_service_code: '03.04A',
  date_of_service: '2026-02-19',
};

const validMobilePatientPayload = {
  first_name: 'Test',
  last_name: 'Patient',
  phn: '123456789',
  date_of_birth: '1990-01-01',
  gender: 'M',
};

const validFavouritePayload = {
  health_service_code: '03.04A',
  display_name: 'Office Visit',
  sort_order: 1,
};

const validReorderPayload = {
  items: [{ favourite_id: PLACEHOLDER_UUID, sort_order: 1 }],
};

const validUpdateFavouritePayload = { display_name: 'Updated' };

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Mobile Companion Authorization & Permission Enforcement (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    seedUsers();
  });

  // =========================================================================
  // 1. Physician has full access to all routes
  // =========================================================================

  describe('Physician role — full access', () => {
    // --- Shift routes (PHYSICIAN role required) ---
    it('POST /api/v1/shifts — allowed', async () => {
      const res = await physicianRequest('POST', '/api/v1/shifts', validShiftPayload);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /api/v1/shifts/active — allowed', async () => {
      const res = await physicianRequest('GET', '/api/v1/shifts/active');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST /api/v1/shifts/:id/end — allowed', async () => {
      const res = await physicianRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/end`);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /api/v1/shifts/:id/summary — allowed', async () => {
      const res = await physicianRequest('GET', `/api/v1/shifts/${PLACEHOLDER_UUID}/summary`);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /api/v1/shifts — allowed', async () => {
      const res = await physicianRequest('GET', '/api/v1/shifts');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST /api/v1/shifts/:id/patients — allowed', async () => {
      const res = await physicianRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/patients`, validLogPatientPayload);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    // --- Favourite routes ---
    it('GET /api/v1/favourites — allowed', async () => {
      const res = await physicianRequest('GET', '/api/v1/favourites');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST /api/v1/favourites — allowed', async () => {
      const res = await physicianRequest('POST', '/api/v1/favourites', validFavouritePayload);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('PUT /api/v1/favourites/:id — allowed', async () => {
      const res = await physicianRequest('PUT', `/api/v1/favourites/${PLACEHOLDER_UUID}`, validUpdateFavouritePayload);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('DELETE /api/v1/favourites/:id — allowed', async () => {
      const res = await physicianRequest('DELETE', `/api/v1/favourites/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('PUT /api/v1/favourites/reorder — allowed', async () => {
      const res = await physicianRequest('PUT', '/api/v1/favourites/reorder', validReorderPayload);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    // --- Mobile routes ---
    it('POST /api/v1/mobile/quick-claim — allowed', async () => {
      const res = await physicianRequest('POST', '/api/v1/mobile/quick-claim', validQuickClaimPayload);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST /api/v1/mobile/patients — allowed', async () => {
      const res = await physicianRequest('POST', '/api/v1/mobile/patients', validMobilePatientPayload);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /api/v1/mobile/recent-patients — allowed', async () => {
      const res = await physicianRequest('GET', '/api/v1/mobile/recent-patients');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /api/v1/mobile/summary — allowed', async () => {
      const res = await physicianRequest('GET', '/api/v1/mobile/summary');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });
  });

  // =========================================================================
  // 2. Shift routes — physician-only (delegates always blocked)
  // =========================================================================

  describe('Shift routes — physician-only (delegates blocked regardless of permissions)', () => {
    it('delegate with CLAIM_VIEW cannot start shift (POST /api/v1/shifts)', async () => {
      const res = await delegateViewRequest('POST', '/api/v1/shifts', validShiftPayload);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('delegate with CLAIM_VIEW cannot view active shift (GET /api/v1/shifts/active)', async () => {
      const res = await delegateViewRequest('GET', '/api/v1/shifts/active');
      expect(res.statusCode).toBe(403);
    });

    it('delegate with CLAIM_VIEW cannot end shift (POST /api/v1/shifts/:id/end)', async () => {
      const res = await delegateViewRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/end`);
      expect(res.statusCode).toBe(403);
    });

    it('delegate with CLAIM_VIEW cannot get shift summary (GET /api/v1/shifts/:id/summary)', async () => {
      const res = await delegateViewRequest('GET', `/api/v1/shifts/${PLACEHOLDER_UUID}/summary`);
      expect(res.statusCode).toBe(403);
    });

    it('delegate with CLAIM_VIEW cannot list shifts (GET /api/v1/shifts)', async () => {
      const res = await delegateViewRequest('GET', '/api/v1/shifts');
      expect(res.statusCode).toBe(403);
    });

    it('delegate with CLAIM_VIEW cannot log patient in shift (POST /api/v1/shifts/:id/patients)', async () => {
      const res = await delegateViewRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/patients`, validLogPatientPayload);
      expect(res.statusCode).toBe(403);
    });

    it('delegate with CLAIM_CREATE cannot start shift', async () => {
      const res = await delegateCreateRequest('POST', '/api/v1/shifts', validShiftPayload);
      expect(res.statusCode).toBe(403);
    });

    it('delegate with CLAIM_CREATE cannot end shift', async () => {
      const res = await delegateCreateRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/end`);
      expect(res.statusCode).toBe(403);
    });

    it('delegate with CLAIM_CREATE cannot log patient in shift', async () => {
      const res = await delegateCreateRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/patients`, validLogPatientPayload);
      expect(res.statusCode).toBe(403);
    });

    it('delegate with CLAIM_VIEW + CLAIM_CREATE cannot start shift', async () => {
      const res = await delegateViewCreateRequest('POST', '/api/v1/shifts', validShiftPayload);
      expect(res.statusCode).toBe(403);
    });

    it('delegate with no permissions cannot access any shift route', async () => {
      const shiftRoutes = [
        { method: 'POST' as const, url: '/api/v1/shifts', payload: validShiftPayload },
        { method: 'GET' as const, url: '/api/v1/shifts/active' },
        { method: 'POST' as const, url: `/api/v1/shifts/${PLACEHOLDER_UUID}/end` },
        { method: 'GET' as const, url: `/api/v1/shifts/${PLACEHOLDER_UUID}/summary` },
        { method: 'GET' as const, url: '/api/v1/shifts' },
        { method: 'POST' as const, url: `/api/v1/shifts/${PLACEHOLDER_UUID}/patients`, payload: validLogPatientPayload },
      ];

      for (const route of shiftRoutes) {
        const res = await delegateNoneRequest(route.method, route.url, route.payload);
        expect(res.statusCode).toBe(403);
      }
    });
  });

  // =========================================================================
  // 3. Delegate with CLAIM_VIEW only — favourite & mobile route access
  // =========================================================================

  describe('Delegate with CLAIM_VIEW only', () => {
    // Allowed: CLAIM_VIEW routes
    it('GET /api/v1/favourites — allowed (has CLAIM_VIEW)', async () => {
      const res = await delegateViewRequest('GET', '/api/v1/favourites');
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/mobile/summary — allowed (has CLAIM_VIEW)', async () => {
      const res = await delegateViewRequest('GET', '/api/v1/mobile/summary');
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    // Denied: CLAIM_CREATE routes
    it('POST /api/v1/mobile/quick-claim — 403 (requires CLAIM_CREATE)', async () => {
      const res = await delegateViewRequest('POST', '/api/v1/mobile/quick-claim', validQuickClaimPayload);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/favourites — 403 (requires CLAIM_CREATE)', async () => {
      const res = await delegateViewRequest('POST', '/api/v1/favourites', validFavouritePayload);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('PUT /api/v1/favourites/:id — 403 (requires CLAIM_CREATE)', async () => {
      const res = await delegateViewRequest('PUT', `/api/v1/favourites/${PLACEHOLDER_UUID}`, validUpdateFavouritePayload);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('DELETE /api/v1/favourites/:id — 403 (requires CLAIM_CREATE)', async () => {
      const res = await delegateViewRequest('DELETE', `/api/v1/favourites/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('PUT /api/v1/favourites/reorder — 403 (requires CLAIM_CREATE)', async () => {
      const res = await delegateViewRequest('PUT', '/api/v1/favourites/reorder', validReorderPayload);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    // Denied: PATIENT_CREATE routes
    it('POST /api/v1/mobile/patients — 403 (requires PATIENT_CREATE)', async () => {
      const res = await delegateViewRequest('POST', '/api/v1/mobile/patients', validMobilePatientPayload);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    // Denied: PATIENT_VIEW routes (delegate only has CLAIM_VIEW)
    it('GET /api/v1/mobile/recent-patients — 403 (requires PATIENT_VIEW)', async () => {
      const res = await delegateViewRequest('GET', '/api/v1/mobile/recent-patients');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });
  });

  // =========================================================================
  // 4. Delegate with CLAIM_CREATE only — can create quick claims
  // =========================================================================

  describe('Delegate with CLAIM_CREATE only', () => {
    // Allowed: CLAIM_CREATE routes
    it('POST /api/v1/mobile/quick-claim — allowed (has CLAIM_CREATE)', async () => {
      const res = await delegateCreateRequest('POST', '/api/v1/mobile/quick-claim', validQuickClaimPayload);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/favourites — allowed (has CLAIM_CREATE)', async () => {
      const res = await delegateCreateRequest('POST', '/api/v1/favourites', validFavouritePayload);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('PUT /api/v1/favourites/:id — allowed (has CLAIM_CREATE)', async () => {
      const res = await delegateCreateRequest('PUT', `/api/v1/favourites/${PLACEHOLDER_UUID}`, validUpdateFavouritePayload);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('DELETE /api/v1/favourites/:id — allowed (has CLAIM_CREATE)', async () => {
      const res = await delegateCreateRequest('DELETE', `/api/v1/favourites/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('PUT /api/v1/favourites/reorder — allowed (has CLAIM_CREATE)', async () => {
      const res = await delegateCreateRequest('PUT', '/api/v1/favourites/reorder', validReorderPayload);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    // Denied: CLAIM_VIEW routes
    it('GET /api/v1/favourites — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateCreateRequest('GET', '/api/v1/favourites');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('GET /api/v1/mobile/summary — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegateCreateRequest('GET', '/api/v1/mobile/summary');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    // Denied: PATIENT_VIEW routes
    it('GET /api/v1/mobile/recent-patients — 403 (requires PATIENT_VIEW)', async () => {
      const res = await delegateCreateRequest('GET', '/api/v1/mobile/recent-patients');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    // Denied: PATIENT_CREATE routes
    it('POST /api/v1/mobile/patients — 403 (requires PATIENT_CREATE)', async () => {
      const res = await delegateCreateRequest('POST', '/api/v1/mobile/patients', validMobilePatientPayload);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });
  });

  // =========================================================================
  // 5. Delegate with PATIENT_CREATE only — can create mobile patients
  // =========================================================================

  describe('Delegate with PATIENT_CREATE only', () => {
    // Allowed: PATIENT_CREATE route
    it('POST /api/v1/mobile/patients — allowed (has PATIENT_CREATE)', async () => {
      const res = await delegatePatientRequest('POST', '/api/v1/mobile/patients', validMobilePatientPayload);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    // Denied: CLAIM_CREATE routes
    it('POST /api/v1/mobile/quick-claim — 403 (requires CLAIM_CREATE)', async () => {
      const res = await delegatePatientRequest('POST', '/api/v1/mobile/quick-claim', validQuickClaimPayload);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('POST /api/v1/favourites — 403 (requires CLAIM_CREATE)', async () => {
      const res = await delegatePatientRequest('POST', '/api/v1/favourites', validFavouritePayload);
      expect(res.statusCode).toBe(403);
    });

    // Denied: CLAIM_VIEW routes
    it('GET /api/v1/favourites — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegatePatientRequest('GET', '/api/v1/favourites');
      expect(res.statusCode).toBe(403);
    });

    it('GET /api/v1/mobile/summary — 403 (requires CLAIM_VIEW)', async () => {
      const res = await delegatePatientRequest('GET', '/api/v1/mobile/summary');
      expect(res.statusCode).toBe(403);
    });

    // Denied: PATIENT_VIEW routes
    it('GET /api/v1/mobile/recent-patients — 403 (requires PATIENT_VIEW)', async () => {
      const res = await delegatePatientRequest('GET', '/api/v1/mobile/recent-patients');
      expect(res.statusCode).toBe(403);
    });
  });

  // =========================================================================
  // 6. Delegate with CLAIM_VIEW + CLAIM_CREATE — combined permissions
  // =========================================================================

  describe('Delegate with CLAIM_VIEW + CLAIM_CREATE', () => {
    // Allowed: CLAIM_VIEW routes
    it('GET /api/v1/favourites — allowed (has CLAIM_VIEW)', async () => {
      const res = await delegateViewCreateRequest('GET', '/api/v1/favourites');
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('GET /api/v1/mobile/summary — allowed (has CLAIM_VIEW)', async () => {
      const res = await delegateViewCreateRequest('GET', '/api/v1/mobile/summary');
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    // Allowed: CLAIM_CREATE routes
    it('POST /api/v1/mobile/quick-claim — allowed (has CLAIM_CREATE)', async () => {
      const res = await delegateViewCreateRequest('POST', '/api/v1/mobile/quick-claim', validQuickClaimPayload);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    it('POST /api/v1/favourites — allowed (has CLAIM_CREATE)', async () => {
      const res = await delegateViewCreateRequest('POST', '/api/v1/favourites', validFavouritePayload);
      expect(res.statusCode).not.toBe(403);
      expect(res.statusCode).not.toBe(401);
    });

    // Still denied: PATIENT_CREATE routes (doesn't have PATIENT_CREATE)
    it('POST /api/v1/mobile/patients — 403 (requires PATIENT_CREATE)', async () => {
      const res = await delegateViewCreateRequest('POST', '/api/v1/mobile/patients', validMobilePatientPayload);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    // Still denied: PATIENT_VIEW routes (doesn't have PATIENT_VIEW)
    it('GET /api/v1/mobile/recent-patients — 403 (requires PATIENT_VIEW)', async () => {
      const res = await delegateViewCreateRequest('GET', '/api/v1/mobile/recent-patients');
      expect(res.statusCode).toBe(403);
    });

    // Still denied: shift routes (physician-only)
    it('POST /api/v1/shifts — 403 (physician-only)', async () => {
      const res = await delegateViewCreateRequest('POST', '/api/v1/shifts', validShiftPayload);
      expect(res.statusCode).toBe(403);
    });
  });

  // =========================================================================
  // 7. Delegate with no relevant permissions — all routes denied
  // =========================================================================

  describe('Delegate with no relevant permissions — all denied', () => {
    const allNonShiftRoutes = [
      { method: 'GET' as const, url: '/api/v1/favourites', description: 'list favourites' },
      { method: 'POST' as const, url: '/api/v1/favourites', payload: validFavouritePayload, description: 'add favourite' },
      { method: 'PUT' as const, url: `/api/v1/favourites/${PLACEHOLDER_UUID}`, payload: validUpdateFavouritePayload, description: 'update favourite' },
      { method: 'DELETE' as const, url: `/api/v1/favourites/${PLACEHOLDER_UUID}`, description: 'delete favourite' },
      { method: 'PUT' as const, url: '/api/v1/favourites/reorder', payload: validReorderPayload, description: 'reorder favourites' },
      { method: 'POST' as const, url: '/api/v1/mobile/quick-claim', payload: validQuickClaimPayload, description: 'quick claim' },
      { method: 'POST' as const, url: '/api/v1/mobile/patients', payload: validMobilePatientPayload, description: 'create patient' },
      { method: 'GET' as const, url: '/api/v1/mobile/recent-patients', description: 'recent patients' },
      { method: 'GET' as const, url: '/api/v1/mobile/summary', description: 'mobile summary' },
    ];

    for (const route of allNonShiftRoutes) {
      it(`${route.method} ${route.url} — 403 (${route.description})`, async () => {
        const res = await delegateNoneRequest(route.method, route.url, route.payload);
        expect(res.statusCode).toBe(403);
        const body = JSON.parse(res.body);
        expect(body.error.code).toBe('FORBIDDEN');
        expect(body.data).toBeUndefined();
      });
    }
  });

  // =========================================================================
  // 8. Admin role — passes authorization for all non-shift routes
  //    (shift routes use requireRole('PHYSICIAN') which excludes admin)
  // =========================================================================

  describe('Admin role — access control', () => {
    // Favourite routes — admin passes authorize() checks
    it('GET /api/v1/favourites — admin passes authorization', async () => {
      const res = await adminRequest('GET', '/api/v1/favourites');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST /api/v1/favourites — admin passes authorization', async () => {
      const res = await adminRequest('POST', '/api/v1/favourites', validFavouritePayload);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('PUT /api/v1/favourites/:id — admin passes authorization', async () => {
      const res = await adminRequest('PUT', `/api/v1/favourites/${PLACEHOLDER_UUID}`, validUpdateFavouritePayload);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('DELETE /api/v1/favourites/:id — admin passes authorization', async () => {
      const res = await adminRequest('DELETE', `/api/v1/favourites/${PLACEHOLDER_UUID}`);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('PUT /api/v1/favourites/reorder — admin passes authorization', async () => {
      const res = await adminRequest('PUT', '/api/v1/favourites/reorder', validReorderPayload);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    // Mobile routes — admin passes authorize() checks
    it('POST /api/v1/mobile/quick-claim — admin passes authorization', async () => {
      const res = await adminRequest('POST', '/api/v1/mobile/quick-claim', validQuickClaimPayload);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST /api/v1/mobile/patients — admin passes authorization', async () => {
      const res = await adminRequest('POST', '/api/v1/mobile/patients', validMobilePatientPayload);
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /api/v1/mobile/recent-patients — admin passes authorization', async () => {
      const res = await adminRequest('GET', '/api/v1/mobile/recent-patients');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET /api/v1/mobile/summary — admin passes authorization', async () => {
      const res = await adminRequest('GET', '/api/v1/mobile/summary');
      expect(res.statusCode).not.toBe(401);
      expect(res.statusCode).not.toBe(403);
    });

    // Shift routes — admin role vs requireRole('PHYSICIAN')
    // shift.routes.ts uses a local requireRole that only accepts PHYSICIAN,
    // so admin may be blocked by the role check. But authorize() still passes.
    it('shift routes block ADMIN via requireRole (physician-only)', async () => {
      const res = await adminRequest('POST', '/api/v1/shifts', validShiftPayload);
      // Admin is blocked by the requireRole('PHYSICIAN') guard — returns 403
      expect(res.statusCode).toBe(403);
    });
  });

  // =========================================================================
  // 9. 403 response shape — no data leakage on permission denial
  // =========================================================================

  describe('403 response shape — no data leakage', () => {
    it('403 response has consistent error shape with no data field', async () => {
      const res = await delegateNoneRequest('GET', '/api/v1/favourites');
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.data).toBeUndefined();
    });

    it('403 response does not contain internal identifiers', async () => {
      const res = await delegateNoneRequest('POST', '/api/v1/mobile/quick-claim', validQuickClaimPayload);
      expect(res.statusCode).toBe(403);
      const rawBody = res.body;
      expect(rawBody).not.toContain('postgres');
      expect(rawBody).not.toContain('drizzle');
      expect(rawBody).not.toContain('session_id');
      expect(rawBody).not.toContain('provider_id');
      expect(rawBody).not.toContain('physician_id');
      expect(rawBody).not.toContain('stack');
    });

    it('403 response does not contain route handler details', async () => {
      const res = await delegateNoneRequest('POST', '/api/v1/mobile/patients', validMobilePatientPayload);
      expect(res.statusCode).toBe(403);
      const rawBody = res.body;
      expect(rawBody).not.toContain('handler');
      expect(rawBody).not.toContain('service');
      expect(rawBody).not.toContain('repository');
    });

    it('403 on shift start does not leak shift existence', async () => {
      const res = await delegateViewRequest('POST', '/api/v1/shifts', validShiftPayload);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.message).not.toContain('shift');
      expect(body.error.message).not.toContain(PLACEHOLDER_UUID);
    });

    it('403 on favourite modification does not leak favourite data', async () => {
      const res = await delegateViewRequest('PUT', `/api/v1/favourites/${PLACEHOLDER_UUID}`, validUpdateFavouritePayload);
      expect(res.statusCode).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error.message).not.toContain('favourite');
      expect(body.error.message).not.toContain(PLACEHOLDER_UUID);
    });

    it('403 does not expose permission names in error details', async () => {
      const res = await delegateNoneRequest('GET', '/api/v1/mobile/summary');
      expect(res.statusCode).toBe(403);
      const rawBody = res.body;
      expect(rawBody).not.toContain('CLAIM_VIEW');
      expect(rawBody).not.toContain('CLAIM_CREATE');
      expect(rawBody).not.toContain('PATIENT_CREATE');
      expect(rawBody).not.toContain('PATIENT_VIEW');
    });
  });

  // =========================================================================
  // 10. Permission escalation prevention
  // =========================================================================

  describe('Permission escalation prevention', () => {
    it('delegate with CLAIM_VIEW cannot create quick claims by crafting POST', async () => {
      const res = await delegateViewRequest('POST', '/api/v1/mobile/quick-claim', validQuickClaimPayload);
      expect(res.statusCode).toBe(403);
    });

    it('delegate with CLAIM_CREATE cannot view summary by crafting GET', async () => {
      const res = await delegateCreateRequest('GET', '/api/v1/mobile/summary');
      expect(res.statusCode).toBe(403);
    });

    it('delegate with PATIENT_CREATE cannot create claims', async () => {
      const res = await delegatePatientRequest('POST', '/api/v1/mobile/quick-claim', validQuickClaimPayload);
      expect(res.statusCode).toBe(403);
    });

    it('delegate with CLAIM_VIEW cannot use shift log-patient to create claims under physician identity', async () => {
      const res = await delegateViewRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/patients`, validLogPatientPayload);
      expect(res.statusCode).toBe(403);
    });

    it('delegate with CLAIM_CREATE cannot use shift management to create claims via patient logging', async () => {
      const res = await delegateCreateRequest('POST', `/api/v1/shifts/${PLACEHOLDER_UUID}/patients`, validLogPatientPayload);
      expect(res.statusCode).toBe(403);
    });

    it('delegate cannot bypass role check by having all permissions', async () => {
      // Even with CLAIM_VIEW + CLAIM_CREATE, shifts require PHYSICIAN role
      const res = await delegateViewCreateRequest('GET', '/api/v1/shifts/active');
      expect(res.statusCode).toBe(403);
    });

    it('delegate with no permissions cannot access any route in the mobile domain', async () => {
      const allRoutes = [
        // Shift routes
        { method: 'POST' as const, url: '/api/v1/shifts', payload: validShiftPayload },
        { method: 'GET' as const, url: '/api/v1/shifts/active' },
        { method: 'POST' as const, url: `/api/v1/shifts/${PLACEHOLDER_UUID}/end` },
        { method: 'GET' as const, url: `/api/v1/shifts/${PLACEHOLDER_UUID}/summary` },
        { method: 'GET' as const, url: '/api/v1/shifts' },
        { method: 'POST' as const, url: `/api/v1/shifts/${PLACEHOLDER_UUID}/patients`, payload: validLogPatientPayload },
        // Favourite routes
        { method: 'GET' as const, url: '/api/v1/favourites' },
        { method: 'POST' as const, url: '/api/v1/favourites', payload: validFavouritePayload },
        { method: 'PUT' as const, url: `/api/v1/favourites/${PLACEHOLDER_UUID}`, payload: validUpdateFavouritePayload },
        { method: 'DELETE' as const, url: `/api/v1/favourites/${PLACEHOLDER_UUID}` },
        { method: 'PUT' as const, url: '/api/v1/favourites/reorder', payload: validReorderPayload },
        // Mobile routes
        { method: 'POST' as const, url: '/api/v1/mobile/quick-claim', payload: validQuickClaimPayload },
        { method: 'POST' as const, url: '/api/v1/mobile/patients', payload: validMobilePatientPayload },
        { method: 'GET' as const, url: '/api/v1/mobile/recent-patients' },
        { method: 'GET' as const, url: '/api/v1/mobile/summary' },
      ];

      for (const route of allRoutes) {
        const res = await delegateNoneRequest(route.method, route.url, route.payload);
        expect(res.statusCode).toBe(403);
      }
    });
  });
});
