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

const PHYSICIAN_USER_ID = '00000000-a0c1-0000-0000-000000000001';
const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_SESSION_ID = '00000000-a0c2-0000-0000-000000000001';

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

const LOCATION_ID_1 = '00000000-a0c3-0000-0000-000000000001';
const LOCATION_ID_2 = '00000000-a0c3-0000-0000-000000000002';

const MOCK_LOCATION_1 = {
  locationId: LOCATION_ID_1,
  providerId: PHYSICIAN_USER_ID,
  name: 'Main Clinic',
  functionalCentre: 'FC001',
  facilityNumber: 'FAC001',
  addressLine1: '123 Main St',
  addressLine2: null,
  city: 'Calgary',
  province: 'AB',
  postalCode: 'T2P1A1',
  communityCode: 'CAL01',
  rrnpEligible: false,
  rrnpRate: null,
  isDefault: true,
  isActive: true,
  createdAt: new Date(),
  updatedAt: new Date(),
};

const MOCK_LOCATION_2 = {
  locationId: LOCATION_ID_2,
  providerId: PHYSICIAN_USER_ID,
  name: 'Satellite Clinic',
  functionalCentre: 'FC002',
  facilityNumber: null,
  addressLine1: '456 Rural Rd',
  addressLine2: null,
  city: 'Milk River',
  province: 'AB',
  postalCode: 'T0K1M0',
  communityCode: 'MLK01',
  rrnpEligible: true,
  rrnpRate: '25.00',
  isDefault: false,
  isActive: true,
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

    // BAs (stubs)
    listBasForProvider: vi.fn(async () => []),
    listActiveBasForProvider: vi.fn(async () => []),
    countActiveBasForProvider: vi.fn(async () => 0),
    findBaByNumber: vi.fn(async () => undefined),
    createBa: vi.fn(),
    findBaById: vi.fn(),
    updateBa: vi.fn(),
    deactivateBa: vi.fn(),

    // Locations
    listLocationsForProvider: vi.fn(async (providerId: string) => {
      if (providerId === PHYSICIAN_USER_ID) return [MOCK_LOCATION_1, MOCK_LOCATION_2];
      return [];
    }),
    listActiveLocationsForProvider: vi.fn(async (providerId: string) => {
      if (providerId === PHYSICIAN_USER_ID) return [MOCK_LOCATION_1, MOCK_LOCATION_2];
      return [];
    }),
    createLocation: vi.fn(async (data: any) => ({
      locationId: '00000000-a0c3-0000-0000-000000000099',
      ...data,
      rrnpEligible: false,
      rrnpRate: null,
      isDefault: false,
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    })),
    findLocationById: vi.fn(async (locationId: string, providerId: string) => {
      if (locationId === LOCATION_ID_1 && providerId === PHYSICIAN_USER_ID) return { ...MOCK_LOCATION_1 };
      if (locationId === LOCATION_ID_2 && providerId === PHYSICIAN_USER_ID) return { ...MOCK_LOCATION_2 };
      return undefined;
    }),
    updateLocation: vi.fn(async (locationId: string, _providerId: string, data: Record<string, unknown>) => {
      if (locationId === LOCATION_ID_1) return { ...MOCK_LOCATION_1, ...data, updatedAt: new Date() };
      if (locationId === LOCATION_ID_2) return { ...MOCK_LOCATION_2, ...data, updatedAt: new Date() };
      return undefined;
    }),
    setDefaultLocation: vi.fn(async (locationId: string, providerId: string) => {
      if (providerId === PHYSICIAN_USER_ID && locationId === LOCATION_ID_2) {
        return { ...MOCK_LOCATION_2, isDefault: true };
      }
      return undefined;
    }),
    deactivateLocation: vi.fn(async (locationId: string, providerId: string) => {
      if (locationId === LOCATION_ID_2 && providerId === PHYSICIAN_USER_ID) {
        return { ...MOCK_LOCATION_2, isActive: false };
      }
      return undefined;
    }),
    getDefaultLocation: vi.fn(async (providerId: string) => {
      if (providerId === PHYSICIAN_USER_ID) return { ...MOCK_LOCATION_1 };
      return undefined;
    }),

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
let mockReferenceData: {
  getRrnpRate: ReturnType<typeof vi.fn>;
};

async function buildTestApp(): Promise<FastifyInstance> {
  mockRepo = createMockProviderRepo();
  mockAuditRepo = { appendAuditLog: vi.fn() };
  mockEvents = { emit: vi.fn() };
  mockReferenceData = {
    getRrnpRate: vi.fn(async () => ({ communityName: 'Milk River', rrnpPercentage: '25.00' })),
  };

  const serviceDeps: ProviderServiceDeps = {
    repo: mockRepo as any,
    auditRepo: mockAuditRepo,
    events: mockEvents,
    referenceData: mockReferenceData,
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

function authedPut(url: string, body?: Record<string, unknown>) {
  return app.inject({
    method: 'PUT',
    url,
    headers: {
      cookie: `session=${PHYSICIAN_SESSION_TOKEN}`,
      'content-type': 'application/json',
    },
    payload: body ?? {},
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

describe('Practice Location Integration Tests', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  describe('GET /api/v1/providers/me/locations', () => {
    it('returns all locations for authenticated physician', async () => {
      const res = await authedGet('/api/v1/providers/me/locations');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(Array.isArray(body.data)).toBe(true);
      expect(body.data.length).toBe(2);
      expect(body.data[0].name).toBe('Main Clinic');
    });
  });

  describe('POST /api/v1/providers/me/locations', () => {
    it('creates location with RRNP lookup', async () => {
      // Mock to simulate first location (auto-default)
      mockRepo.listActiveLocationsForProvider.mockResolvedValueOnce([]);

      const res = await authedPost('/api/v1/providers/me/locations', {
        name: 'New Clinic',
        functional_centre: 'FC003',
        city: 'Milk River',
        province: 'AB',
        community_code: 'MLK01',
      });
      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(mockRepo.createLocation).toHaveBeenCalled();
    });

    it('rejects missing required fields', async () => {
      const res = await authedPost('/api/v1/providers/me/locations', {
        city: 'Calgary',
      });
      expect(res.statusCode).toBe(400);
    });
  });

  describe('PUT /api/v1/providers/me/locations/:id', () => {
    it('updates location with valid data', async () => {
      const res = await authedPut(`/api/v1/providers/me/locations/${LOCATION_ID_1}`, {
        name: 'Updated Clinic Name',
      });
      expect(res.statusCode).toBe(200);
    });

    it('rejects non-UUID id', async () => {
      const res = await authedPut('/api/v1/providers/me/locations/not-a-uuid', {
        name: 'Test',
      });
      expect(res.statusCode).toBe(400);
    });
  });

  describe('PUT /api/v1/providers/me/locations/:id/set-default', () => {
    it('swaps default location', async () => {
      const res = await authedPut(`/api/v1/providers/me/locations/${LOCATION_ID_2}/set-default`);
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
    });

    it('returns 404 for non-existent location', async () => {
      mockRepo.findLocationById.mockResolvedValueOnce(undefined);

      const res = await authedPut('/api/v1/providers/me/locations/00000000-0000-0000-0000-000000000099/set-default');
      expect(res.statusCode).toBe(404);
    });
  });

  describe('DELETE /api/v1/providers/me/locations/:id', () => {
    it('deactivates location', async () => {
      const res = await authedDelete(`/api/v1/providers/me/locations/${LOCATION_ID_2}`);
      expect(res.statusCode).toBe(204);
    });

    it('returns 404 for non-existent location', async () => {
      mockRepo.findLocationById.mockResolvedValueOnce(undefined);

      const res = await authedDelete('/api/v1/providers/me/locations/00000000-0000-0000-0000-000000000099');
      expect(res.statusCode).toBe(404);
    });
  });
});
