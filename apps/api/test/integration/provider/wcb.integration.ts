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

const PHYSICIAN_USER_ID = '00000000-a301-0000-0000-000000000001';
const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_SESSION_ID = '00000000-a302-0000-0000-000000000001';

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

const WCB_CONFIG_ID_1 = '00000000-0cb3-0000-0000-000000000001';
const WCB_CONFIG_ID_2 = '00000000-0cb3-0000-0000-000000000002';

const MOCK_WCB_CONFIG_1 = {
  wcbConfigId: WCB_CONFIG_ID_1,
  providerId: PHYSICIAN_USER_ID,
  contractId: 'C001',
  roleCode: 'R01',
  skillCode: null,
  permittedFormTypes: ['C001_R01_FORM_A', 'C001_R01_FORM_B'],
  isDefault: true,
  createdAt: new Date(),
  updatedAt: new Date(),
};

const MOCK_WCB_CONFIG_2 = {
  wcbConfigId: WCB_CONFIG_ID_2,
  providerId: PHYSICIAN_USER_ID,
  contractId: 'C002',
  roleCode: 'R02',
  skillCode: 'SK01',
  permittedFormTypes: ['C002_R02_FORM_C'],
  isDefault: false,
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

    // WCB configs
    listWcbConfigsForProvider: vi.fn(async (providerId: string) => {
      if (providerId === PHYSICIAN_USER_ID) return [MOCK_WCB_CONFIG_1, MOCK_WCB_CONFIG_2];
      return [];
    }),
    createWcbConfig: vi.fn(async (data: any) => ({
      wcbConfigId: '00000000-0cb3-0000-0000-000000000099',
      ...data,
      createdAt: new Date(),
      updatedAt: new Date(),
    })),
    findWcbConfigById: vi.fn(async (wcbConfigId: string, providerId: string) => {
      if (wcbConfigId === WCB_CONFIG_ID_1 && providerId === PHYSICIAN_USER_ID) return { ...MOCK_WCB_CONFIG_1 };
      if (wcbConfigId === WCB_CONFIG_ID_2 && providerId === PHYSICIAN_USER_ID) return { ...MOCK_WCB_CONFIG_2 };
      return undefined;
    }),
    updateWcbConfig: vi.fn(async (wcbConfigId: string, _providerId: string, data: Record<string, unknown>) => {
      if (wcbConfigId === WCB_CONFIG_ID_1) return { ...MOCK_WCB_CONFIG_1, ...data, updatedAt: new Date() };
      return undefined;
    }),
    deleteWcbConfig: vi.fn(async (wcbConfigId: string, providerId: string) => {
      if (wcbConfigId === WCB_CONFIG_ID_1 && providerId === PHYSICIAN_USER_ID) return true;
      return false;
    }),
    getAggregatedFormPermissions: vi.fn(async (providerId: string) => {
      if (providerId === PHYSICIAN_USER_ID) return ['C001_R01_FORM_A', 'C001_R01_FORM_B', 'C002_R02_FORM_C'];
      return [];
    }),
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

    // H-Link (stubs)
    findHlinkConfig: vi.fn(async () => undefined),
    createHlinkConfig: vi.fn(),
    updateHlinkConfig: vi.fn(),

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
let mockReferenceData: {
  getRrnpRate: ReturnType<typeof vi.fn>;
  getWcbMatrixEntry: ReturnType<typeof vi.fn>;
};

async function buildTestApp(): Promise<FastifyInstance> {
  mockRepo = createMockProviderRepo();
  mockAuditRepo = { appendAuditLog: vi.fn() };
  mockEvents = { emit: vi.fn() };
  mockReferenceData = {
    getRrnpRate: vi.fn(async () => null),
    getWcbMatrixEntry: vi.fn(async (contractId: string, roleCode: string) => {
      // Valid matrix entries
      const matrix: Record<string, { contractId: string; roleCode: string; permittedFormTypes: string[] }> = {
        'C001:R01': { contractId: 'C001', roleCode: 'R01', permittedFormTypes: ['C001_R01_FORM_A', 'C001_R01_FORM_B'] },
        'C002:R02': { contractId: 'C002', roleCode: 'R02', permittedFormTypes: ['C002_R02_FORM_C'] },
        'C003:R03': { contractId: 'C003', roleCode: 'R03', permittedFormTypes: ['C003_R03_FORM_D'] },
      };
      return matrix[`${contractId}:${roleCode}`] ?? null;
    }),
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

function unauthedGet(url: string) {
  return app.inject({ method: 'GET', url });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('WCB Configuration Integration Tests', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  // =========================================================================
  // GET /api/v1/providers/me/wcb
  // =========================================================================

  describe('GET /api/v1/providers/me/wcb', () => {
    it('returns all WCB configs for authenticated physician', async () => {
      const res = await authedGet('/api/v1/providers/me/wcb');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(Array.isArray(body.data)).toBe(true);
      expect(body.data.length).toBe(2);
      expect(body.data[0].contractId).toBe('C001');
      expect(body.data[1].contractId).toBe('C002');
    });

    it('returns 401 without session', async () => {
      const res = await unauthedGet('/api/v1/providers/me/wcb');
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // POST /api/v1/providers/me/wcb
  // =========================================================================

  describe('POST /api/v1/providers/me/wcb', () => {
    it('creates WCB config with valid data and validates against WCB matrix', async () => {
      const res = await authedPost('/api/v1/providers/me/wcb', {
        contract_id: 'C003',
        role_code: 'R03',
      });
      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.contractId).toBe('C003');
      expect(body.data.roleCode).toBe('R03');
      expect(mockRepo.createWcbConfig).toHaveBeenCalled();
    });

    it('auto-populates permitted_form_types from WCB matrix', async () => {
      const res = await authedPost('/api/v1/providers/me/wcb', {
        contract_id: 'C003',
        role_code: 'R03',
      });
      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.data.permittedFormTypes).toEqual(['C003_R03_FORM_D']);
    });

    it('rejects invalid contract_id/role_code combination', async () => {
      const res = await authedPost('/api/v1/providers/me/wcb', {
        contract_id: 'INVALID',
        role_code: 'INVALID',
      });
      expect(res.statusCode).toBe(422);
      const body = res.json();
      expect(body.error.code).toBe('BUSINESS_RULE_VIOLATION');
    });

    it('rejects missing contract_id', async () => {
      const res = await authedPost('/api/v1/providers/me/wcb', {
        role_code: 'R01',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects missing role_code', async () => {
      const res = await authedPost('/api/v1/providers/me/wcb', {
        contract_id: 'C001',
      });
      expect(res.statusCode).toBe(400);
    });

    it('passes optional skill_code to service', async () => {
      const res = await authedPost('/api/v1/providers/me/wcb', {
        contract_id: 'C001',
        role_code: 'R01',
        skill_code: 'SK99',
      });
      expect(res.statusCode).toBe(201);
      const createCall = mockRepo.createWcbConfig.mock.calls.at(-1)![0];
      expect(createCall.skillCode).toBe('SK99');
    });
  });

  // =========================================================================
  // PUT /api/v1/providers/me/wcb/:id
  // =========================================================================

  describe('PUT /api/v1/providers/me/wcb/:id', () => {
    it('updates WCB config with valid data', async () => {
      const res = await authedPut(`/api/v1/providers/me/wcb/${WCB_CONFIG_ID_1}`, {
        skill_code: 'SK50',
        is_default: false,
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
    });

    it('rejects non-UUID id', async () => {
      const res = await authedPut('/api/v1/providers/me/wcb/not-a-uuid', {
        skill_code: 'SK50',
      });
      expect(res.statusCode).toBe(400);
    });

    it('returns 404 for non-existent config', async () => {
      const nonExistentId = '00000000-0000-0000-0000-000000000099';
      const res = await authedPut(`/api/v1/providers/me/wcb/${nonExistentId}`, {
        skill_code: 'SK50',
      });
      expect(res.statusCode).toBe(404);
    });
  });

  // =========================================================================
  // DELETE /api/v1/providers/me/wcb/:id
  // =========================================================================

  describe('DELETE /api/v1/providers/me/wcb/:id', () => {
    it('removes WCB config', async () => {
      const res = await authedDelete(`/api/v1/providers/me/wcb/${WCB_CONFIG_ID_1}`);
      expect(res.statusCode).toBe(204);
    });

    it('returns 404 for non-existent config', async () => {
      mockRepo.findWcbConfigById.mockResolvedValueOnce(undefined);

      const res = await authedDelete('/api/v1/providers/me/wcb/00000000-0000-0000-0000-000000000099');
      expect(res.statusCode).toBe(404);
    });

    it('rejects non-UUID id', async () => {
      const res = await authedDelete('/api/v1/providers/me/wcb/not-a-uuid');
      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // GET /api/v1/providers/me/wcb/form-permissions
  // =========================================================================

  describe('GET /api/v1/providers/me/wcb/form-permissions', () => {
    it('returns aggregated form permissions', async () => {
      const res = await authedGet('/api/v1/providers/me/wcb/form-permissions');
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(Array.isArray(body.data)).toBe(true);
      expect(body.data).toContain('C001_R01_FORM_A');
      expect(body.data).toContain('C001_R01_FORM_B');
      expect(body.data).toContain('C002_R02_FORM_C');
    });

    it('returns 401 without session', async () => {
      const res = await unauthedGet('/api/v1/providers/me/wcb/form-permissions');
      expect(res.statusCode).toBe(401);
    });
  });
});
