import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
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

const PHYSICIAN_USER_ID = '00000000-ba01-0000-0000-000000000001';
const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_SESSION_ID = '00000000-ba02-0000-0000-000000000001';

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

const BA_ID_1 = '00000000-ba10-0000-0000-000000000001';
const BA_ID_2 = '00000000-ba10-0000-0000-000000000002';

const MOCK_BA_1 = {
  baId: BA_ID_1,
  providerId: PHYSICIAN_USER_ID,
  baNumber: '111111',
  baType: 'FFS',
  isPrimary: true,
  status: 'ACTIVE',
  effectiveDate: '2026-01-01',
  endDate: null,
  createdAt: new Date(),
  updatedAt: new Date(),
};

const MOCK_BA_2 = {
  baId: BA_ID_2,
  providerId: PHYSICIAN_USER_ID,
  baNumber: '222222',
  baType: 'FFS',
  isPrimary: false,
  status: 'ACTIVE',
  effectiveDate: '2026-01-01',
  endDate: null,
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

    // BAs
    listBasForProvider: vi.fn(async (providerId: string) => {
      if (providerId === PHYSICIAN_USER_ID) return [MOCK_BA_1];
      return [];
    }),
    listActiveBasForProvider: vi.fn(async (providerId: string) => {
      if (providerId === PHYSICIAN_USER_ID) return [MOCK_BA_1];
      return [];
    }),
    countActiveBasForProvider: vi.fn(async (providerId: string) => {
      if (providerId === PHYSICIAN_USER_ID) return 1;
      return 0;
    }),
    findBaByNumber: vi.fn(async () => undefined),
    createBa: vi.fn(async (data: any) => ({
      baId: '00000000-ba10-0000-0000-000000000099',
      ...data,
      status: data.status ?? 'PENDING',
      createdAt: new Date(),
      updatedAt: new Date(),
    })),
    findBaById: vi.fn(async (baId: string, providerId: string) => {
      if (baId === BA_ID_1 && providerId === PHYSICIAN_USER_ID) return { ...MOCK_BA_1 };
      return undefined;
    }),
    updateBa: vi.fn(async (baId: string, _providerId: string, data: Record<string, unknown>) => {
      if (baId === BA_ID_1) return { ...MOCK_BA_1, ...data, updatedAt: new Date() };
      return undefined;
    }),
    deactivateBa: vi.fn(async (baId: string, providerId: string) => {
      if (baId === BA_ID_1 && providerId === PHYSICIAN_USER_ID) {
        return { ...MOCK_BA_1, status: 'INACTIVE', endDate: new Date().toISOString().split('T')[0] };
      }
      return undefined;
    }),

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

function authedGet(url: string) {
  return app.inject({
    method: 'GET',
    url,
    headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
  });
}

function authedPost(url: string, body?: Record<string, unknown>) {
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

function authedPut(url: string, body: Record<string, unknown>) {
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

function authedDelete(url: string) {
  return app.inject({
    method: 'DELETE',
    url,
    headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Business Arrangement Integration Tests', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  describe('GET /api/v1/providers/me/bas', () => {
    it('returns all BAs for authenticated physician', async () => {
      const res = await authedGet('/api/v1/providers/me/bas');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(Array.isArray(body.data)).toBe(true);
      expect(body.data.length).toBeGreaterThan(0);
      expect(body.data[0].baNumber).toBe('111111');
    });
  });

  describe('POST /api/v1/providers/me/bas', () => {
    it('creates BA with valid data', async () => {
      const res = await authedPost('/api/v1/providers/me/bas', {
        ba_number: '333333',
        ba_type: 'FFS',
        effective_date: '2026-03-01',
      });
      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.baNumber).toBe('333333');
      expect(mockRepo.createBa).toHaveBeenCalled();
    });

    it('rejects third active BA', async () => {
      // Override to simulate 2 already active
      mockRepo.countActiveBasForProvider.mockResolvedValueOnce(2);

      const res = await authedPost('/api/v1/providers/me/bas', {
        ba_number: '444444',
        ba_type: 'FFS',
      });
      expect(res.statusCode).toBe(422);
      const body = res.json();
      expect(body.error.code).toBe('BUSINESS_RULE_VIOLATION');
      expect(body.error.message).toContain('Maximum');
    });

    it('rejects invalid ba_type', async () => {
      const res = await authedPost('/api/v1/providers/me/bas', {
        ba_number: '555555',
        ba_type: 'INVALID',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects ba_number that is already in use', async () => {
      mockRepo.findBaByNumber.mockResolvedValueOnce({ ...MOCK_BA_1 });

      const res = await authedPost('/api/v1/providers/me/bas', {
        ba_number: '111111',
        ba_type: 'FFS',
      });
      expect(res.statusCode).toBe(409);
    });
  });

  describe('PUT /api/v1/providers/me/bas/:id', () => {
    it('updates BA with valid data', async () => {
      const res = await authedPut(`/api/v1/providers/me/bas/${BA_ID_1}`, {
        effective_date: '2026-06-01',
      });
      expect(res.statusCode).toBe(200);
    });

    it('rejects non-UUID id', async () => {
      const res = await authedPut('/api/v1/providers/me/bas/not-a-uuid', {
        effective_date: '2026-06-01',
      });
      expect(res.statusCode).toBe(400);
    });
  });

  describe('DELETE /api/v1/providers/me/bas/:id', () => {
    it('deactivates BA', async () => {
      const res = await authedDelete(`/api/v1/providers/me/bas/${BA_ID_1}`);
      expect(res.statusCode).toBe(204);
    });

    it('returns 404 for non-existent BA', async () => {
      mockRepo.findBaById.mockResolvedValueOnce(undefined);

      const res = await authedDelete('/api/v1/providers/me/bas/00000000-0000-0000-0000-000000000099');
      expect(res.statusCode).toBe(404);
    });
  });
});
