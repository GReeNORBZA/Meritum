import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { createHash, randomBytes } from 'node:crypto';

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
import { providerRoutes } from '../../../src/domains/provider/provider.routes.js';
import { type ProviderHandlerDeps } from '../../../src/domains/provider/provider.handlers.js';
import { type ProviderServiceDeps } from '../../../src/domains/provider/provider.service.js';
import { DelegatePermission } from '@meritum/shared/constants/provider.constants.js';

// ---------------------------------------------------------------------------
// Helper: hashToken
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

const PHYSICIAN_USER_ID = '00000000-1111-0000-0000-000000000001';
const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_SESSION_ID = '00000000-2222-0000-0000-000000000001';

const DELEGATE_USER_ID = '00000000-1111-0000-0000-000000000002';
const DELEGATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_SESSION_TOKEN_HASH = hashToken(DELEGATE_SESSION_TOKEN);
const DELEGATE_SESSION_ID = '00000000-2222-0000-0000-000000000002';

const RELATIONSHIP_ID = '00000000-3333-0000-0000-000000000001';
const OTHER_PROVIDER_ID = '00000000-4444-0000-0000-000000000001';

// ---------------------------------------------------------------------------
// Test data
// ---------------------------------------------------------------------------

const MOCK_DELEGATE_RELATIONSHIP = {
  relationshipId: RELATIONSHIP_ID,
  physicianId: PHYSICIAN_USER_ID,
  delegateUserId: DELEGATE_USER_ID,
  permissions: [DelegatePermission.CLAIM_VIEW, DelegatePermission.CLAIM_CREATE],
  status: 'INVITED',
  invitedAt: new Date(),
  acceptedAt: null,
  revokedAt: null,
  revokedBy: null,
  createdAt: new Date(),
  updatedAt: new Date(),
};

const MOCK_ACTIVE_RELATIONSHIP = {
  ...MOCK_DELEGATE_RELATIONSHIP,
  status: 'ACTIVE',
  acceptedAt: new Date(),
};

const MOCK_DELEGATE_LIST_ITEM = {
  relationshipId: RELATIONSHIP_ID,
  physicianId: PHYSICIAN_USER_ID,
  delegateUserId: DELEGATE_USER_ID,
  permissions: [DelegatePermission.CLAIM_VIEW, DelegatePermission.CLAIM_CREATE],
  status: 'ACTIVE',
  invitedAt: new Date(),
  acceptedAt: new Date(),
  delegateEmail: 'delegate@example.com',
  delegateFirstName: 'Del',
  delegateLastName: 'Egate',
};

const MOCK_PHYSICIAN_FOR_DELEGATE = {
  relationshipId: RELATIONSHIP_ID,
  physicianId: PHYSICIAN_USER_ID,
  permissions: [DelegatePermission.CLAIM_VIEW, DelegatePermission.CLAIM_CREATE],
  status: 'ACTIVE',
  physicianFirstName: 'Jane',
  physicianLastName: 'Smith',
  billingNumber: '123456',
};

const INVITATION_RAW_TOKEN = randomBytes(32).toString('hex');
const INVITATION_TOKEN_HASH = hashToken(INVITATION_RAW_TOKEN);

// ---------------------------------------------------------------------------
// Mock session repo
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      if (tokenHash === PHYSICIAN_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: PHYSICIAN_SESSION_ID,
            userId: PHYSICIAN_USER_ID,
            tokenHash: PHYSICIAN_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: PHYSICIAN_USER_ID,
            role: 'PHYSICIAN',
            subscriptionStatus: 'ACTIVE',
          },
        };
      }
      if (tokenHash === DELEGATE_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: DELEGATE_SESSION_ID,
            userId: DELEGATE_USER_ID,
            tokenHash: DELEGATE_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: DELEGATE_USER_ID,
            role: 'DELEGATE',
            subscriptionStatus: 'ACTIVE',
          },
        };
      }
      return undefined;
    }),
    refreshSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Mock provider repository
// ---------------------------------------------------------------------------

function createMockProviderRepo() {
  return {
    // Profile/context stubs (needed for route registration)
    getFullProviderContext: vi.fn(async () => undefined),
    findProviderById: vi.fn(async () => undefined),
    updateProvider: vi.fn(),
    getOnboardingStatus: vi.fn(async () => undefined),
    listActiveBasForProvider: vi.fn(async () => []),
    listActiveLocationsForProvider: vi.fn(async () => []),
    listBasForProvider: vi.fn(async () => []),
    listLocationsForProvider: vi.fn(async () => []),
    countActiveBasForProvider: vi.fn(async () => 0),
    findBaByNumber: vi.fn(async () => undefined),
    createBa: vi.fn(),
    findBaById: vi.fn(),
    updateBa: vi.fn(),
    deactivateBa: vi.fn(),
    createLocation: vi.fn(),
    findLocationById: vi.fn(),
    updateLocation: vi.fn(),
    setDefaultLocation: vi.fn(),
    deactivateLocation: vi.fn(),
    getDefaultLocation: vi.fn(),
    findPcpcmEnrolmentForProvider: vi.fn(),
    createPcpcmEnrolment: vi.fn(),
    updatePcpcmEnrolment: vi.fn(),
    // WCB stubs
    createWcbConfig: vi.fn(),
    findWcbConfigById: vi.fn(),
    listWcbConfigsForProvider: vi.fn(async () => []),
    updateWcbConfig: vi.fn(),
    deleteWcbConfig: vi.fn(),
    setDefaultWcbConfig: vi.fn(),
    getAggregatedFormPermissions: vi.fn(async () => []),
    getWcbConfigForForm: vi.fn(),
    // Preferences & H-Link stubs
    createSubmissionPreferences: vi.fn(),
    findSubmissionPreferences: vi.fn(async () => undefined),
    updateSubmissionPreferences: vi.fn(),
    createHlinkConfig: vi.fn(),
    findHlinkConfig: vi.fn(async () => undefined),
    updateHlinkConfig: vi.fn(),
    updateLastTransmission: vi.fn(),
    // Delegate-specific mocks
    createDelegateRelationship: vi.fn(async () => ({ ...MOCK_DELEGATE_RELATIONSHIP })),
    findRelationshipById: vi.fn(async (relId: string, physicianId: string) => {
      if (relId === RELATIONSHIP_ID && physicianId === PHYSICIAN_USER_ID) {
        return { ...MOCK_ACTIVE_RELATIONSHIP };
      }
      return undefined;
    }),
    findActiveRelationship: vi.fn(async (physicianId: string, delegateUserId: string) => {
      if (physicianId === PHYSICIAN_USER_ID && delegateUserId === DELEGATE_USER_ID) {
        return { ...MOCK_ACTIVE_RELATIONSHIP };
      }
      return undefined;
    }),
    listDelegatesForPhysician: vi.fn(async (physicianId: string) => {
      if (physicianId === PHYSICIAN_USER_ID) {
        return [{ ...MOCK_DELEGATE_LIST_ITEM }];
      }
      return [];
    }),
    listPhysiciansForDelegate: vi.fn(async (delegateUserId: string) => {
      if (delegateUserId === DELEGATE_USER_ID) {
        return [{ ...MOCK_PHYSICIAN_FOR_DELEGATE }];
      }
      return [];
    }),
    updateDelegatePermissions: vi.fn(async (relId: string, physicianId: string, permissions: string[]) => {
      if (relId === RELATIONSHIP_ID && physicianId === PHYSICIAN_USER_ID) {
        return { ...MOCK_ACTIVE_RELATIONSHIP, permissions, updatedAt: new Date() };
      }
      return undefined;
    }),
    acceptRelationship: vi.fn(async (relId: string) => {
      if (relId === RELATIONSHIP_ID) {
        return { ...MOCK_ACTIVE_RELATIONSHIP };
      }
      return undefined;
    }),
    revokeRelationship: vi.fn(async (relId: string, physicianId: string) => {
      if (relId === RELATIONSHIP_ID && physicianId === PHYSICIAN_USER_ID) {
        return {
          ...MOCK_ACTIVE_RELATIONSHIP,
          status: 'REVOKED',
          revokedAt: new Date(),
          revokedBy: PHYSICIAN_USER_ID,
        };
      }
      return undefined;
    }),
  };
}

// ---------------------------------------------------------------------------
// Mock token store
// ---------------------------------------------------------------------------

function createMockTokenStore() {
  return {
    storeTokenHash: vi.fn(async () => {}),
    getTokenHash: vi.fn(async (relId: string) => {
      if (relId === RELATIONSHIP_ID) {
        return {
          tokenHash: INVITATION_TOKEN_HASH,
          expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days from now
        };
      }
      return null;
    }),
    deleteToken: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let mockRepo: ReturnType<typeof createMockProviderRepo>;
let mockAuditRepo: { appendAuditLog: ReturnType<typeof vi.fn> };
let mockEvents: { emit: ReturnType<typeof vi.fn> };
let mockTokenStore: ReturnType<typeof createMockTokenStore>;

async function buildTestApp(): Promise<FastifyInstance> {
  mockRepo = createMockProviderRepo();
  mockAuditRepo = { appendAuditLog: vi.fn() };
  mockEvents = { emit: vi.fn() };
  mockTokenStore = createMockTokenStore();

  const serviceDeps: ProviderServiceDeps = {
    repo: mockRepo as any,
    auditRepo: mockAuditRepo,
    events: mockEvents,
    tokenStore: mockTokenStore,
  };

  const handlerDeps: ProviderHandlerDeps = {
    serviceDeps,
  };

  const testApp = Fastify({ logger: false });

  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  // Register auth plugin
  const mockSessionRepo = createMockSessionRepo();
  await testApp.register(authPluginFp, {
    sessionDeps: {
      sessionRepo: mockSessionRepo,
      auditRepo: { appendAuditLog: vi.fn() },
      events: { emit: vi.fn() },
    },
  });

  // Error handler
  testApp.setErrorHandler((error, _request, reply) => {
    if ('statusCode' in error && 'code' in error && typeof (error as any).code === 'string') {
      const statusCode = (error as any).statusCode ?? 500;
      if (statusCode >= 400 && statusCode < 500) {
        return reply.code(statusCode).send({
          error: {
            code: (error as any).code,
            message: error.message,
            details: (error as any).details,
          },
        });
      }
    }
    if (error.validation) {
      return reply.code(400).send({
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Validation failed',
          details: error.validation,
        },
      });
    }
    return reply.code(500).send({
      error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
    });
  });

  // Register provider routes
  await testApp.register(providerRoutes, { deps: handlerDeps });

  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function physicianGet(url: string) {
  return app.inject({
    method: 'GET',
    url,
    headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
  });
}

function physicianPost(url: string, body?: Record<string, unknown>) {
  return app.inject({
    method: 'POST',
    url,
    headers: {
      cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
      'content-type': 'application/json',
    },
    payload: body ?? {},
  });
}

function physicianPut(url: string, body: Record<string, unknown>) {
  return app.inject({
    method: 'PUT',
    url,
    headers: {
      cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
      'content-type': 'application/json',
    },
    payload: body,
  });
}

function delegateGet(url: string) {
  return app.inject({
    method: 'GET',
    url,
    headers: { cookie: `session=${DELEGATE_SESSION_TOKEN}` },
  });
}

function delegatePost(url: string, body?: Record<string, unknown>) {
  return app.inject({
    method: 'POST',
    url,
    headers: {
      cookie: `session=${DELEGATE_SESSION_TOKEN}`,
      'content-type': 'application/json',
    },
    payload: body ?? {},
  });
}

function unauthedPost(url: string, body?: Record<string, unknown>) {
  return app.inject({
    method: 'POST',
    url,
    headers: { 'content-type': 'application/json' },
    payload: body ?? {},
  });
}

function unauthedGet(url: string) {
  return app.inject({
    method: 'GET',
    url,
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Delegate Management Integration Tests', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    vi.clearAllMocks();
    // Re-wire default delegate mocks after clearAllMocks
    mockRepo.listDelegatesForPhysician.mockImplementation(async (physicianId: string) => {
      if (physicianId === PHYSICIAN_USER_ID) {
        return [{ ...MOCK_DELEGATE_LIST_ITEM }];
      }
      return [];
    });
    mockRepo.createDelegateRelationship.mockImplementation(async () => ({ ...MOCK_DELEGATE_RELATIONSHIP }));
    mockRepo.findRelationshipById.mockImplementation(async (relId: string, physicianId: string) => {
      if (relId === RELATIONSHIP_ID && physicianId === PHYSICIAN_USER_ID) {
        return { ...MOCK_ACTIVE_RELATIONSHIP };
      }
      return undefined;
    });
    mockRepo.findActiveRelationship.mockImplementation(async (physicianId: string, delegateUserId: string) => {
      if (physicianId === PHYSICIAN_USER_ID && delegateUserId === DELEGATE_USER_ID) {
        return { ...MOCK_ACTIVE_RELATIONSHIP };
      }
      return undefined;
    });
    mockRepo.listPhysiciansForDelegate.mockImplementation(async (delegateUserId: string) => {
      if (delegateUserId === DELEGATE_USER_ID) {
        return [{ ...MOCK_PHYSICIAN_FOR_DELEGATE }];
      }
      return [];
    });
    mockRepo.updateDelegatePermissions.mockImplementation(async (relId: string, physicianId: string, permissions: string[]) => {
      if (relId === RELATIONSHIP_ID && physicianId === PHYSICIAN_USER_ID) {
        return { ...MOCK_ACTIVE_RELATIONSHIP, permissions, updatedAt: new Date() };
      }
      return undefined;
    });
    mockRepo.acceptRelationship.mockImplementation(async (relId: string) => {
      if (relId === RELATIONSHIP_ID) {
        return { ...MOCK_ACTIVE_RELATIONSHIP };
      }
      return undefined;
    });
    mockRepo.revokeRelationship.mockImplementation(async (relId: string, physicianId: string) => {
      if (relId === RELATIONSHIP_ID && physicianId === PHYSICIAN_USER_ID) {
        return {
          ...MOCK_ACTIVE_RELATIONSHIP,
          status: 'REVOKED',
          revokedAt: new Date(),
          revokedBy: PHYSICIAN_USER_ID,
        };
      }
      return undefined;
    });
    mockTokenStore.getTokenHash.mockImplementation(async (relId: string) => {
      if (relId === RELATIONSHIP_ID) {
        return {
          tokenHash: INVITATION_TOKEN_HASH,
          expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        };
      }
      return null;
    });
    mockTokenStore.storeTokenHash.mockImplementation(async () => {});
    mockTokenStore.deleteToken.mockImplementation(async () => {});
  });

  // =========================================================================
  // Physician Delegate Management
  // =========================================================================

  describe('GET /api/v1/providers/me/delegates', () => {
    it('returns all delegate relationships for authenticated physician', async () => {
      const res = await physicianGet('/api/v1/providers/me/delegates');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(Array.isArray(body.data)).toBe(true);
      expect(body.data.length).toBe(1);
      expect(body.data[0].relationshipId).toBe(RELATIONSHIP_ID);
      expect(body.data[0].delegateUserId).toBe(DELEGATE_USER_ID);
      expect(mockRepo.listDelegatesForPhysician).toHaveBeenCalledWith(PHYSICIAN_USER_ID);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedGet('/api/v1/providers/me/delegates');
      expect(res.statusCode).toBe(401);
      expect(res.json().data).toBeUndefined();
    });

    it('returns 403 when called by delegate role', async () => {
      const res = await delegateGet('/api/v1/providers/me/delegates');
      expect(res.statusCode).toBe(403);
    });
  });

  describe('POST /api/v1/providers/me/delegates/invite', () => {
    it('creates invitation and returns relationship data', async () => {
      const res = await physicianPost('/api/v1/providers/me/delegates/invite', {
        email: 'newdelegate@example.com',
        permissions: [DelegatePermission.CLAIM_VIEW, DelegatePermission.CLAIM_CREATE],
      });
      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.relationshipId).toBe(RELATIONSHIP_ID);
      expect(body.data.status).toBe('INVITED');
    });

    it('returns 403 when called by delegate role', async () => {
      const res = await delegatePost('/api/v1/providers/me/delegates/invite', {
        email: 'newdelegate@example.com',
        permissions: [DelegatePermission.CLAIM_VIEW],
      });
      expect(res.statusCode).toBe(403);
    });

    it('returns 400 for invalid email', async () => {
      const res = await physicianPost('/api/v1/providers/me/delegates/invite', {
        email: 'not-an-email',
        permissions: [DelegatePermission.CLAIM_VIEW],
      });
      expect(res.statusCode).toBe(400);
    });

    it('returns 400 for empty permissions array', async () => {
      const res = await physicianPost('/api/v1/providers/me/delegates/invite', {
        email: 'valid@example.com',
        permissions: [],
      });
      expect(res.statusCode).toBe(400);
    });

    it('returns 400 for invalid permission key', async () => {
      const res = await physicianPost('/api/v1/providers/me/delegates/invite', {
        email: 'valid@example.com',
        permissions: ['INVALID_PERMISSION'],
      });
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedPost('/api/v1/providers/me/delegates/invite', {
        email: 'test@example.com',
        permissions: [DelegatePermission.CLAIM_VIEW],
      });
      expect(res.statusCode).toBe(401);
    });
  });

  describe('PUT /api/v1/providers/me/delegates/:rel_id/permissions', () => {
    it('updates permissions for an existing relationship', async () => {
      const newPermissions = [DelegatePermission.CLAIM_VIEW, DelegatePermission.PATIENT_VIEW];
      const res = await physicianPut(
        `/api/v1/providers/me/delegates/${RELATIONSHIP_ID}/permissions`,
        { permissions: newPermissions },
      );
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.permissions).toEqual(newPermissions);
    });

    it('returns 400 for empty permissions', async () => {
      const res = await physicianPut(
        `/api/v1/providers/me/delegates/${RELATIONSHIP_ID}/permissions`,
        { permissions: [] },
      );
      expect(res.statusCode).toBe(400);
    });

    it('returns 400 for non-UUID rel_id', async () => {
      const res = await physicianPut(
        '/api/v1/providers/me/delegates/not-a-uuid/permissions',
        { permissions: [DelegatePermission.CLAIM_VIEW] },
      );
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without authentication', async () => {
      const res = app.inject({
        method: 'PUT',
        url: `/api/v1/providers/me/delegates/${RELATIONSHIP_ID}/permissions`,
        headers: { 'content-type': 'application/json' },
        payload: { permissions: [DelegatePermission.CLAIM_VIEW] },
      });
      expect((await res).statusCode).toBe(401);
    });

    it('returns 403 when called by delegate role', async () => {
      const res = app.inject({
        method: 'PUT',
        url: `/api/v1/providers/me/delegates/${RELATIONSHIP_ID}/permissions`,
        headers: {
          cookie: `session=${DELEGATE_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: { permissions: [DelegatePermission.CLAIM_VIEW] },
      });
      expect((await res).statusCode).toBe(403);
    });
  });

  describe('POST /api/v1/providers/me/delegates/:rel_id/revoke', () => {
    it('revokes delegate and sets REVOKED status', async () => {
      const res = await physicianPost(
        `/api/v1/providers/me/delegates/${RELATIONSHIP_ID}/revoke`,
      );
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.status).toBe('REVOKED');
    });

    it('returns 400 for non-UUID rel_id', async () => {
      const res = await physicianPost(
        '/api/v1/providers/me/delegates/not-a-uuid/revoke',
      );
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedPost(
        `/api/v1/providers/me/delegates/${RELATIONSHIP_ID}/revoke`,
      );
      expect(res.statusCode).toBe(401);
    });

    it('returns 403 when called by delegate role', async () => {
      const res = await delegatePost(
        `/api/v1/providers/me/delegates/${RELATIONSHIP_ID}/revoke`,
      );
      expect(res.statusCode).toBe(403);
    });
  });

  // =========================================================================
  // Delegate Self-Service
  // =========================================================================

  describe('GET /api/v1/delegates/me/physicians', () => {
    it('returns linked physicians for authenticated delegate', async () => {
      const res = await delegateGet('/api/v1/delegates/me/physicians');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(Array.isArray(body.data)).toBe(true);
      expect(body.data.length).toBe(1);
      expect(body.data[0].physicianId).toBe(PHYSICIAN_USER_ID);
      expect(body.data[0].permissions).toEqual(
        expect.arrayContaining([DelegatePermission.CLAIM_VIEW]),
      );
      expect(mockRepo.listPhysiciansForDelegate).toHaveBeenCalledWith(DELEGATE_USER_ID);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedGet('/api/v1/delegates/me/physicians');
      expect(res.statusCode).toBe(401);
    });

    it('returns 403 when called by physician role', async () => {
      const res = await physicianGet('/api/v1/delegates/me/physicians');
      expect(res.statusCode).toBe(403);
    });
  });

  describe('POST /api/v1/delegates/me/switch-context/:provider_id', () => {
    it('succeeds with active relationship and returns context', async () => {
      const res = await delegatePost(
        `/api/v1/delegates/me/switch-context/${PHYSICIAN_USER_ID}`,
      );
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.physicianId).toBe(PHYSICIAN_USER_ID);
      expect(body.data.delegateUserId).toBe(DELEGATE_USER_ID);
      expect(body.data.permissions).toEqual(
        expect.arrayContaining([DelegatePermission.CLAIM_VIEW]),
      );
    });

    it('fails without active relationship (404)', async () => {
      const res = await delegatePost(
        `/api/v1/delegates/me/switch-context/${OTHER_PROVIDER_ID}`,
      );
      expect(res.statusCode).toBe(404);
    });

    it('returns 400 for non-UUID provider_id', async () => {
      const res = await delegatePost(
        '/api/v1/delegates/me/switch-context/not-a-uuid',
      );
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedPost(
        `/api/v1/delegates/me/switch-context/${PHYSICIAN_USER_ID}`,
      );
      expect(res.statusCode).toBe(401);
    });

    it('returns 403 when called by physician role', async () => {
      const res = await physicianPost(
        `/api/v1/delegates/me/switch-context/${PHYSICIAN_USER_ID}`,
      );
      expect(res.statusCode).toBe(403);
    });
  });

  // =========================================================================
  // Invitation Acceptance (unauthenticated)
  // =========================================================================

  describe('POST /api/v1/delegates/invitations/:token/accept', () => {
    it('activates relationship with valid token', async () => {
      const res = await unauthedPost(
        `/api/v1/delegates/invitations/${RELATIONSHIP_ID}/accept`,
        { token: INVITATION_RAW_TOKEN },
      );
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.relationshipId).toBe(RELATIONSHIP_ID);
      expect(body.data.status).toBe('ACTIVE');
      expect(mockTokenStore.getTokenHash).toHaveBeenCalledWith(RELATIONSHIP_ID);
      expect(mockRepo.acceptRelationship).toHaveBeenCalledWith(RELATIONSHIP_ID);
      expect(mockTokenStore.deleteToken).toHaveBeenCalledWith(RELATIONSHIP_ID);
    });

    it('rejects expired token', async () => {
      mockTokenStore.getTokenHash.mockResolvedValueOnce({
        tokenHash: INVITATION_TOKEN_HASH,
        expiresAt: new Date(Date.now() - 1000), // expired 1 second ago
      });

      const res = await unauthedPost(
        `/api/v1/delegates/invitations/${RELATIONSHIP_ID}/accept`,
        { token: INVITATION_RAW_TOKEN },
      );
      expect(res.statusCode).toBe(422);
      const body = res.json();
      expect(body.error.code).toBe('BUSINESS_RULE_VIOLATION');
      expect(body.error.message).toContain('expired');
    });

    it('rejects invalid token', async () => {
      const res = await unauthedPost(
        `/api/v1/delegates/invitations/${RELATIONSHIP_ID}/accept`,
        { token: 'wrong-token-value' },
      );
      expect(res.statusCode).toBe(422);
    });

    it('returns 404 for unknown relationship', async () => {
      const unknownRelId = '00000000-9999-0000-0000-000000000001';
      const res = await unauthedPost(
        `/api/v1/delegates/invitations/${unknownRelId}/accept`,
        { token: INVITATION_RAW_TOKEN },
      );
      expect(res.statusCode).toBe(404);
    });

    it('returns 400 with empty token in body', async () => {
      const res = await unauthedPost(
        `/api/v1/delegates/invitations/${RELATIONSHIP_ID}/accept`,
        { token: '' },
      );
      expect(res.statusCode).toBe(400);
    });
  });
});
