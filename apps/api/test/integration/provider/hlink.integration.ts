import { describe, it, expect, vi, beforeAll, afterAll } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { createHash, randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Environment setup
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);

// ---------------------------------------------------------------------------
// Mock otplib
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
// Imports
// ---------------------------------------------------------------------------

import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { providerRoutes } from '../../../src/domains/provider/provider.routes.js';
import { type ProviderHandlerDeps } from '../../../src/domains/provider/provider.handlers.js';
import { type ProviderServiceDeps } from '../../../src/domains/provider/provider.service.js';

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Fixed identities
// ---------------------------------------------------------------------------

const PHYSICIAN_USER_ID = '00000000-a100-0000-0000-000000000001';
const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_SESSION_ID = '00000000-a100-0000-0000-000000000002';

const DELEGATE_USER_ID = '00000000-a100-0000-0000-000000000010';
const DELEGATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_SESSION_TOKEN_HASH = hashToken(DELEGATE_SESSION_TOKEN);
const DELEGATE_SESSION_ID = '00000000-a100-0000-0000-000000000011';

// ---------------------------------------------------------------------------
// Test data
// ---------------------------------------------------------------------------

const MOCK_PROVIDER = {
  providerId: PHYSICIAN_USER_ID,
  billingNumber: '123456',
  cpsaRegistrationNumber: 'CPSA12345',
  firstName: 'Jane',
  middleName: null,
  lastName: 'Smith',
  specialtyCode: 'GP',
  specialtyDescription: 'General Practice',
  subSpecialtyCode: null,
  physicianType: 'GP',
  status: 'ACTIVE',
  onboardingCompleted: true,
  createdAt: new Date(),
  updatedAt: new Date(),
};

const HLINK_CONFIG_ID = '00000000-a100-0000-0000-000000000020';

const MOCK_HLINK_CONFIG = {
  hlinkConfigId: HLINK_CONFIG_ID,
  providerId: PHYSICIAN_USER_ID,
  submitterPrefix: 'MRT001',
  credentialSecretRef: 'vault://hlink/credentials/abc123',
  accreditationStatus: 'ACTIVE',
  accreditationDate: '2026-01-01',
  lastSuccessfulTransmission: new Date('2026-02-10T14:30:00Z'),
  createdAt: new Date(),
  updatedAt: new Date(),
};

// ---------------------------------------------------------------------------
// Mocks
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

function createMockProviderRepo() {
  return {
    // Provider
    findProviderById: vi.fn(async (providerId: string) => {
      if (providerId === PHYSICIAN_USER_ID) return { ...MOCK_PROVIDER };
      return undefined;
    }),
    getFullProviderContext: vi.fn(async () => undefined),
    updateProvider: vi.fn(),
    getOnboardingStatus: vi.fn(),
    createProvider: vi.fn(),

    // BAs (stubs)
    listBasForProvider: vi.fn(async () => []),
    listActiveBasForProvider: vi.fn(async () => []),
    countActiveBasForProvider: vi.fn(async () => 0),
    findBaByNumber: vi.fn(async () => undefined),
    createBa: vi.fn(),
    findBaById: vi.fn(),
    updateBa: vi.fn(),
    deactivateBa: vi.fn(),

    // Locations (stubs)
    listLocationsForProvider: vi.fn(async () => []),
    listActiveLocationsForProvider: vi.fn(async () => []),
    createLocation: vi.fn(),
    findLocationById: vi.fn(),
    updateLocation: vi.fn(),
    setDefaultLocation: vi.fn(),
    deactivateLocation: vi.fn(),
    getDefaultLocation: vi.fn(),

    // PCPCM (stubs)
    findPcpcmEnrolmentForProvider: vi.fn(async () => undefined),
    createPcpcmEnrolment: vi.fn(),
    updatePcpcmEnrolment: vi.fn(),

    // WCB configs (stubs)
    listWcbConfigsForProvider: vi.fn(async () => []),
    createWcbConfig: vi.fn(),
    findWcbConfigById: vi.fn(),
    updateWcbConfig: vi.fn(),
    deleteWcbConfig: vi.fn(),
    getAggregatedFormPermissions: vi.fn(async () => []),
    getWcbConfigForForm: vi.fn(),

    // Delegates (stubs)
    createDelegateRelationship: vi.fn(),
    findRelationshipById: vi.fn(),
    acceptRelationship: vi.fn(),
    listDelegatesForPhysician: vi.fn(async () => []),
    updateDelegatePermissions: vi.fn(),
    revokeRelationship: vi.fn(),
    listPhysiciansForDelegate: vi.fn(async () => []),
    findActiveRelationship: vi.fn(),

    // Submission preferences (stubs)
    findSubmissionPreferences: vi.fn(async () => undefined),
    createSubmissionPreferences: vi.fn(),
    updateSubmissionPreferences: vi.fn(),

    // H-Link
    findHlinkConfig: vi.fn(async (providerId: string) => {
      if (providerId === PHYSICIAN_USER_ID) return { ...MOCK_HLINK_CONFIG };
      return undefined;
    }),
    createHlinkConfig: vi.fn(),
    updateHlinkConfig: vi.fn(async (providerId: string, data: Record<string, unknown>) => {
      if (providerId === PHYSICIAN_USER_ID) {
        return { ...MOCK_HLINK_CONFIG, ...data, updatedAt: new Date() };
      }
      return undefined;
    }),

    // Internal
    getBaForClaim: vi.fn(),
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let mockRepo: ReturnType<typeof createMockProviderRepo>;
let mockAuditRepo: { appendAuditLog: ReturnType<typeof vi.fn> };
let mockEvents: { emit: ReturnType<typeof vi.fn> };

async function buildTestApp(): Promise<FastifyInstance> {
  mockRepo = createMockProviderRepo();
  mockAuditRepo = { appendAuditLog: vi.fn() };
  mockEvents = { emit: vi.fn() };

  const serviceDeps: ProviderServiceDeps = {
    repo: mockRepo as any,
    auditRepo: mockAuditRepo,
    events: mockEvents,
  };

  const handlerDeps: ProviderHandlerDeps = { serviceDeps };

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  const mockSessionRepo = createMockSessionRepo();
  await testApp.register(authPluginFp, {
    sessionDeps: {
      sessionRepo: mockSessionRepo,
      auditRepo: { appendAuditLog: vi.fn() },
      events: { emit: vi.fn() },
    },
  });

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

  await testApp.register(providerRoutes, { deps: handlerDeps });
  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function authedGet(url: string, sessionToken = PHYSICIAN_SESSION_TOKEN) {
  return app.inject({
    method: 'GET',
    url,
    headers: { cookie: `session=${sessionToken}` },
  });
}

function authedPut(url: string, body: Record<string, unknown>, sessionToken = PHYSICIAN_SESSION_TOKEN) {
  return app.inject({
    method: 'PUT',
    url,
    headers: {
      cookie: `session=${sessionToken}`,
      'content-type': 'application/json',
    },
    payload: body,
  });
}

function unauthedGet(url: string) {
  return app.inject({ method: 'GET', url });
}

function unauthedPut(url: string, body: Record<string, unknown>) {
  return app.inject({
    method: 'PUT',
    url,
    headers: { 'content-type': 'application/json' },
    payload: body,
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('H-Link Configuration Integration Tests', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  // =========================================================================
  // GET /api/v1/providers/me/hlink
  // =========================================================================

  describe('GET /api/v1/providers/me/hlink', () => {
    it('returns H-Link config without credential_secret_ref', async () => {
      const res = await authedGet('/api/v1/providers/me/hlink');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.submitterPrefix).toBe('MRT001');
      expect(body.data.accreditationStatus).toBe('ACTIVE');
      expect(body.data.accreditationDate).toBe('2026-01-01');
      expect(body.data.lastSuccessfulTransmission).toBeDefined();

      // SECURITY: credential_secret_ref must never appear in response
      expect(body.data.credentialSecretRef).toBeUndefined();
      expect(body.data.credential_secret_ref).toBeUndefined();
      const responseJson = JSON.stringify(body);
      expect(responseJson).not.toContain('vault://');
      expect(responseJson).not.toContain('credentialSecretRef');
      expect(responseJson).not.toContain('credential_secret_ref');
    });

    it('returns null when H-Link not configured', async () => {
      mockRepo.findHlinkConfig.mockResolvedValueOnce(undefined);

      const res = await authedGet('/api/v1/providers/me/hlink');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeNull();
    });

    it('returns 401 without session', async () => {
      const res = await unauthedGet('/api/v1/providers/me/hlink');
      expect(res.statusCode).toBe(401);
    });

    it('returns 403 for delegate role (physician only)', async () => {
      const res = await authedGet('/api/v1/providers/me/hlink', DELEGATE_SESSION_TOKEN);
      expect(res.statusCode).toBe(403);
    });
  });

  // =========================================================================
  // PUT /api/v1/providers/me/hlink
  // =========================================================================

  describe('PUT /api/v1/providers/me/hlink', () => {
    it('updates submitter prefix', async () => {
      const res = await authedPut('/api/v1/providers/me/hlink', {
        submitter_prefix: 'MRT002',
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.submitterPrefix).toBe('MRT002');

      // SECURITY: credential_secret_ref must never appear in response
      expect(body.data.credentialSecretRef).toBeUndefined();
      const responseJson = JSON.stringify(body);
      expect(responseJson).not.toContain('vault://');
    });

    it('updates accreditation status', async () => {
      const res = await authedPut('/api/v1/providers/me/hlink', {
        accreditation_status: 'PENDING',
      });
      expect(res.statusCode).toBe(200);
    });

    it('rejects invalid accreditation status', async () => {
      const res = await authedPut('/api/v1/providers/me/hlink', {
        accreditation_status: 'INVALID',
      });
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without session', async () => {
      const res = await unauthedPut('/api/v1/providers/me/hlink', {
        submitter_prefix: 'MRT002',
      });
      expect(res.statusCode).toBe(401);
    });

    it('returns 403 for delegate role (physician only)', async () => {
      const res = await authedPut('/api/v1/providers/me/hlink', {
        submitter_prefix: 'MRT002',
      }, DELEGATE_SESSION_TOKEN);
      expect(res.statusCode).toBe(403);
    });

    it('emits audit log on update', async () => {
      await authedPut('/api/v1/providers/me/hlink', {
        submitter_prefix: 'MRT003',
      });
      expect(mockAuditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'hlink_config.updated',
          resourceType: 'hlink_configuration',
        }),
      );
    });

    it('does not accept credential values in body', async () => {
      // The schema should only accept submitter_prefix and accreditation_status
      // Any extra fields should be silently stripped by Zod
      const res = await authedPut('/api/v1/providers/me/hlink', {
        submitter_prefix: 'MRT004',
        credential_secret_ref: 'vault://hacked',
        credential_secret: 'password123',
      });
      // Should succeed, extra fields ignored
      expect(res.statusCode).toBe(200);

      // Verify the repo was NOT called with credential values
      if (mockRepo.updateHlinkConfig.mock.calls.length > 0) {
        const lastCallPayload = mockRepo.updateHlinkConfig.mock.calls.at(-1);
        if (lastCallPayload) {
          const payload = lastCallPayload[1] as Record<string, unknown>;
          expect(payload).not.toHaveProperty('credentialSecretRef');
          expect(payload).not.toHaveProperty('credential_secret_ref');
          expect(payload).not.toHaveProperty('credentialSecret');
          expect(payload).not.toHaveProperty('credential_secret');
        }
      }
    });
  });
});
