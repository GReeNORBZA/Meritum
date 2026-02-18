import { describe, it, expect, vi, beforeAll, afterAll } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

// ---------------------------------------------------------------------------
// Environment setup (must be before imports that read env)
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);
process.env.INTERNAL_API_KEY = 'test-internal-api-key-for-integration';

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
import { internalProviderRoutes } from '../../../src/domains/provider/provider.routes.js';
import { type InternalProviderHandlerDeps } from '../../../src/domains/provider/provider.handlers.js';
import { type ProviderServiceDeps } from '../../../src/domains/provider/provider.service.js';

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

const PROVIDER_ID = '00000000-1111-0000-0000-000000000001';
const UNKNOWN_PROVIDER_ID = '00000000-1111-0000-0000-000000000099';

// ---------------------------------------------------------------------------
// Test data
// ---------------------------------------------------------------------------

const MOCK_PROVIDER_CONTEXT = {
  provider_id: PROVIDER_ID,
  billing_number: '123456',
  specialty_code: 'GP',
  physician_type: 'GP',
  bas: [
    {
      ba_id: '00000000-3333-0000-0000-000000000001',
      ba_number: '12345',
      ba_type: 'FFS',
      is_primary: true,
      status: 'ACTIVE',
    },
  ],
  default_location: {
    location_id: '00000000-4444-0000-0000-000000000001',
    name: 'Main Clinic',
    functional_centre: 'FC01',
    facility_number: 'FAC01',
  },
  all_locations: [
    {
      location_id: '00000000-4444-0000-0000-000000000001',
      name: 'Main Clinic',
      functional_centre: 'FC01',
      is_active: true,
    },
  ],
  pcpcm_enrolled: false,
  pcpcm_ba_number: null,
  ffs_ba_number: '12345',
  wcb_configs: [
    {
      wcb_config_id: '00000000-5555-0000-0000-000000000001',
      contract_id: 'WCB001',
      role_code: 'PHYS',
      permitted_form_types: ['C8', 'C8-1', 'C9'],
    },
  ],
  default_wcb_config: {
    wcb_config_id: '00000000-5555-0000-0000-000000000001',
    contract_id: 'WCB001',
    role_code: 'PHYS',
  },
  submission_preferences: {
    ahcip_submission_mode: 'AUTO_CLEAN',
    wcb_submission_mode: 'REQUIRE_APPROVAL',
    batch_review_reminder: true,
    deadline_reminder_days: 7,
  },
  hlink_accreditation_status: 'ACTIVE',
  hlink_submitter_prefix: 'MER',
  onboarding_completed: true,
  status: 'ACTIVE',
};

const PCPCM_BA = {
  ba_id: '00000000-3333-0000-0000-000000000002',
  ba_number: '67890',
  ba_type: 'PCPCM',
  is_primary: false,
  status: 'ACTIVE',
};

const MOCK_PCPCM_CONTEXT = {
  ...MOCK_PROVIDER_CONTEXT,
  pcpcm_enrolled: true,
  pcpcm_ba_number: '67890',
  bas: [
    ...MOCK_PROVIDER_CONTEXT.bas,
    PCPCM_BA,
  ],
};

// ---------------------------------------------------------------------------
// Mock provider repository
// ---------------------------------------------------------------------------

function createMockProviderRepo() {
  return {
    getFullProviderContext: vi.fn(async (providerId: string) => {
      if (providerId === PROVIDER_ID) return { ...MOCK_PROVIDER_CONTEXT };
      return undefined;
    }),
    getBaForClaim: vi.fn(async (
      providerId: string,
      claimType: string,
      _hscCode?: string,
      _dateOfService?: string,
    ) => {
      if (providerId !== PROVIDER_ID) return null;

      if (claimType === 'WCB') {
        return {
          baNumber: '12345',
          baType: 'FFS',
          routing: 'PRIMARY' as const,
        };
      }

      // AHCIP: return FFS BA by default
      return {
        baNumber: '12345',
        baType: 'FFS',
        routing: 'FFS' as const,
      };
    }),
    listWcbConfigsForProvider: vi.fn(async (providerId: string) => {
      if (providerId !== PROVIDER_ID) return [];
      return [
        {
          wcbConfigId: '00000000-5555-0000-0000-000000000001',
          providerId: PROVIDER_ID,
          contractId: 'WCB001',
          roleCode: 'PHYS',
          skillCode: null,
          permittedFormTypes: ['C8', 'C8-1', 'C9'],
          isDefault: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      ];
    }),
    getWcbConfigForForm: vi.fn(async (providerId: string, formId: string) => {
      if (providerId !== PROVIDER_ID) return null;
      if (['C8', 'C8-1', 'C9'].includes(formId)) {
        return {
          wcbConfigId: '00000000-5555-0000-0000-000000000001',
          contractId: 'WCB001',
          roleCode: 'PHYS',
        };
      }
      return null;
    }),
    findPcpcmEnrolmentForProvider: vi.fn(async () => undefined),
    // Stubs for unused repo methods
    findProviderById: vi.fn(),
    updateProvider: vi.fn(),
    getOnboardingStatus: vi.fn(),
    createProvider: vi.fn(),
    completeOnboarding: vi.fn(),
    createBa: vi.fn(),
    findBaById: vi.fn(),
    listBasForProvider: vi.fn(),
    listActiveBasForProvider: vi.fn(),
    updateBa: vi.fn(),
    deactivateBa: vi.fn(),
    countActiveBasForProvider: vi.fn(),
    findBaByNumber: vi.fn(),
    createLocation: vi.fn(),
    findLocationById: vi.fn(),
    listLocationsForProvider: vi.fn(),
    listActiveLocationsForProvider: vi.fn(),
    updateLocation: vi.fn(),
    setDefaultLocation: vi.fn(),
    deactivateLocation: vi.fn(),
    getDefaultLocation: vi.fn(),
    createPcpcmEnrolment: vi.fn(),
    updatePcpcmEnrolment: vi.fn(),
    createWcbConfig: vi.fn(),
    findWcbConfigById: vi.fn(),
    updateWcbConfig: vi.fn(),
    deleteWcbConfig: vi.fn(),
    setDefaultWcbConfig: vi.fn(),
    getAggregatedFormPermissions: vi.fn(),
    createDelegateRelationship: vi.fn(),
    findRelationshipById: vi.fn(),
    findActiveRelationship: vi.fn(),
    listDelegatesForPhysician: vi.fn(),
    listPhysiciansForDelegate: vi.fn(),
    updateDelegatePermissions: vi.fn(),
    acceptRelationship: vi.fn(),
    revokeRelationship: vi.fn(),
    createSubmissionPreferences: vi.fn(),
    findSubmissionPreferences: vi.fn(),
    updateSubmissionPreferences: vi.fn(),
    createHlinkConfig: vi.fn(),
    findHlinkConfig: vi.fn(),
    updateHlinkConfig: vi.fn(),
    updateLastTransmission: vi.fn(),
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

  const handlerDeps: InternalProviderHandlerDeps = {
    serviceDeps,
  };

  const testApp = Fastify({ logger: false });

  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

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

  // Register internal provider routes (no auth plugin needed — internal API key auth)
  await testApp.register(internalProviderRoutes, { deps: handlerDeps });

  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const VALID_API_KEY = 'test-internal-api-key-for-integration';

function internalGet(url: string, apiKey?: string) {
  const headers: Record<string, string> = {};
  if (apiKey !== undefined) {
    headers['x-internal-api-key'] = apiKey;
  }
  return app.inject({
    method: 'GET',
    url,
    headers,
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Internal Provider Context API', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  // =========================================================================
  // Authentication: Internal API key enforcement
  // =========================================================================

  describe('Internal API key authentication', () => {
    it('rejects requests without X-Internal-API-Key header', async () => {
      const res = await internalGet(
        `/api/v1/internal/providers/${PROVIDER_ID}/claim-context`,
      );
      expect(res.statusCode).toBe(401);
      expect(res.json().data).toBeUndefined();
      expect(res.json().error.code).toBe('UNAUTHORIZED');
    });

    it('rejects requests with invalid API key', async () => {
      const res = await internalGet(
        `/api/v1/internal/providers/${PROVIDER_ID}/claim-context`,
        'wrong-key',
      );
      expect(res.statusCode).toBe(401);
      expect(res.json().data).toBeUndefined();
    });

    it('rejects requests with empty API key', async () => {
      const res = await internalGet(
        `/api/v1/internal/providers/${PROVIDER_ID}/claim-context`,
        '',
      );
      expect(res.statusCode).toBe(401);
    });

    it('accepts requests with valid API key', async () => {
      const res = await internalGet(
        `/api/v1/internal/providers/${PROVIDER_ID}/claim-context`,
        VALID_API_KEY,
      );
      expect(res.statusCode).toBe(200);
    });
  });

  // =========================================================================
  // GET /api/v1/internal/providers/:id/claim-context
  // =========================================================================

  describe('GET /api/v1/internal/providers/:id/claim-context', () => {
    it('returns full ProviderContext for known provider', async () => {
      const res = await internalGet(
        `/api/v1/internal/providers/${PROVIDER_ID}/claim-context`,
        VALID_API_KEY,
      );
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.provider_id).toBe(PROVIDER_ID);
      expect(body.data.billing_number).toBe('123456');
      expect(body.data.specialty_code).toBe('GP');
      expect(body.data.physician_type).toBe('GP');
      expect(body.data.bas).toHaveLength(1);
      expect(body.data.default_location).toBeDefined();
      expect(body.data.all_locations).toHaveLength(1);
      expect(body.data.pcpcm_enrolled).toBe(false);
      expect(body.data.wcb_configs).toHaveLength(1);
      expect(body.data.submission_preferences).toBeDefined();
      expect(body.data.onboarding_completed).toBe(true);
      expect(body.data.status).toBe('ACTIVE');
    });

    it('returns 404 for unknown provider', async () => {
      const res = await internalGet(
        `/api/v1/internal/providers/${UNKNOWN_PROVIDER_ID}/claim-context`,
        VALID_API_KEY,
      );
      expect(res.statusCode).toBe(404);
      expect(res.json().error.code).toBe('NOT_FOUND');
      // Should not leak resource details
      expect(res.json().error.message).not.toContain(UNKNOWN_PROVIDER_ID);
    });

    it('returns 400 for non-UUID provider id', async () => {
      const res = await internalGet(
        '/api/v1/internal/providers/not-a-uuid/claim-context',
        VALID_API_KEY,
      );
      expect(res.statusCode).toBe(400);
    });

    it('rejects request without internal API key', async () => {
      const res = await internalGet(
        `/api/v1/internal/providers/${PROVIDER_ID}/claim-context`,
      );
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // GET /api/v1/internal/providers/:id/ba-for-claim
  // =========================================================================

  describe('GET /api/v1/internal/providers/:id/ba-for-claim', () => {
    it('returns correct BA for AHCIP claim (non-PCPCM)', async () => {
      const res = await internalGet(
        `/api/v1/internal/providers/${PROVIDER_ID}/ba-for-claim?claim_type=AHCIP`,
        VALID_API_KEY,
      );
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.ba_number).toBe('12345');
      expect(body.data.ba_type).toBe('FFS');
      expect(body.data.routing_reason).toBe('NON_PCPCM');
    });

    it('returns PCPCM BA for in-basket code when PCPCM enrolled', async () => {
      // Mock PCPCM enrollment and repo returning PCPCM routing
      mockRepo.findPcpcmEnrolmentForProvider.mockResolvedValueOnce({
        enrolmentId: 'enr-1',
        providerId: PROVIDER_ID,
        pcpcmBaId: PCPCM_BA.ba_id,
        ffsBaId: MOCK_PROVIDER_CONTEXT.bas[0].ba_id,
        status: 'ACTIVE',
        enrolmentDate: new Date().toISOString(),
        panelSize: 500,
        createdAt: new Date(),
        updatedAt: new Date(),
      });
      mockRepo.getBaForClaim.mockResolvedValueOnce({
        baNumber: '67890',
        baType: 'PCPCM',
        routing: 'PCPCM' as const,
      });

      const res = await internalGet(
        `/api/v1/internal/providers/${PROVIDER_ID}/ba-for-claim?claim_type=AHCIP&hsc_code=03.01A`,
        VALID_API_KEY,
      );
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.ba_number).toBe('67890');
      expect(body.data.ba_type).toBe('PCPCM');
      expect(body.data.routing_reason).toBe('IN_BASKET');
    });

    it('returns FFS BA for out-of-basket code when PCPCM enrolled', async () => {
      // Mock PCPCM enrollment but FFS routing (out of basket)
      mockRepo.findPcpcmEnrolmentForProvider.mockResolvedValueOnce({
        enrolmentId: 'enr-1',
        providerId: PROVIDER_ID,
        pcpcmBaId: PCPCM_BA.ba_id,
        ffsBaId: MOCK_PROVIDER_CONTEXT.bas[0].ba_id,
        status: 'ACTIVE',
        enrolmentDate: new Date().toISOString(),
        panelSize: 500,
        createdAt: new Date(),
        updatedAt: new Date(),
      });
      mockRepo.getBaForClaim.mockResolvedValueOnce({
        baNumber: '12345',
        baType: 'FFS',
        routing: 'FFS' as const,
      });

      const res = await internalGet(
        `/api/v1/internal/providers/${PROVIDER_ID}/ba-for-claim?claim_type=AHCIP&hsc_code=99.99Z`,
        VALID_API_KEY,
      );
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.ba_number).toBe('12345');
      expect(body.data.ba_type).toBe('FFS');
      expect(body.data.routing_reason).toBe('OUT_OF_BASKET');
    });

    it('returns 400 when claim_type is missing', async () => {
      const res = await internalGet(
        `/api/v1/internal/providers/${PROVIDER_ID}/ba-for-claim`,
        VALID_API_KEY,
      );
      expect(res.statusCode).toBe(400);
    });

    it('returns 400 for invalid claim_type', async () => {
      const res = await internalGet(
        `/api/v1/internal/providers/${PROVIDER_ID}/ba-for-claim?claim_type=INVALID`,
        VALID_API_KEY,
      );
      expect(res.statusCode).toBe(400);
    });

    it('returns 404 for unknown provider', async () => {
      const res = await internalGet(
        `/api/v1/internal/providers/${UNKNOWN_PROVIDER_ID}/ba-for-claim?claim_type=AHCIP`,
        VALID_API_KEY,
      );
      expect(res.statusCode).toBe(404);
    });

    it('rejects request without internal API key', async () => {
      const res = await internalGet(
        `/api/v1/internal/providers/${PROVIDER_ID}/ba-for-claim?claim_type=AHCIP`,
      );
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // GET /api/v1/internal/providers/:id/wcb-config-for-form
  // =========================================================================

  describe('GET /api/v1/internal/providers/:id/wcb-config-for-form', () => {
    it('returns matching WCB config for permitted form type', async () => {
      const res = await internalGet(
        `/api/v1/internal/providers/${PROVIDER_ID}/wcb-config-for-form?form_id=C8`,
        VALID_API_KEY,
      );
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.wcbConfigId).toBe('00000000-5555-0000-0000-000000000001');
      expect(body.data.contractId).toBe('WCB001');
      expect(body.data.roleCode).toBe('PHYS');
    });

    it('returns 422 for non-permitted form type', async () => {
      const res = await internalGet(
        `/api/v1/internal/providers/${PROVIDER_ID}/wcb-config-for-form?form_id=UNKNOWN_FORM`,
        VALID_API_KEY,
      );
      expect(res.statusCode).toBe(422);
      expect(res.json().error.code).toBe('BUSINESS_RULE_VIOLATION');
    });

    it('returns 400 when form_id is missing', async () => {
      const res = await internalGet(
        `/api/v1/internal/providers/${PROVIDER_ID}/wcb-config-for-form`,
        VALID_API_KEY,
      );
      expect(res.statusCode).toBe(400);
    });

    it('returns 422 for unknown provider (no WCB configs)', async () => {
      const res = await internalGet(
        `/api/v1/internal/providers/${UNKNOWN_PROVIDER_ID}/wcb-config-for-form?form_id=C8`,
        VALID_API_KEY,
      );
      // Unknown provider has no WCB configs, so getWcbConfigForFormOrThrow throws BusinessRuleError
      expect(res.statusCode).toBe(422);
    });

    it('rejects request without internal API key', async () => {
      const res = await internalGet(
        `/api/v1/internal/providers/${PROVIDER_ID}/wcb-config-for-form?form_id=C8`,
      );
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // UUID validation for all internal routes
  // =========================================================================

  describe('UUID parameter validation', () => {
    it('rejects non-UUID for claim-context', async () => {
      const res = await internalGet(
        '/api/v1/internal/providers/not-a-uuid/claim-context',
        VALID_API_KEY,
      );
      expect(res.statusCode).toBe(400);
    });

    it('rejects non-UUID for ba-for-claim', async () => {
      const res = await internalGet(
        '/api/v1/internal/providers/not-a-uuid/ba-for-claim?claim_type=AHCIP',
        VALID_API_KEY,
      );
      expect(res.statusCode).toBe(400);
    });

    it('rejects non-UUID for wcb-config-for-form', async () => {
      const res = await internalGet(
        '/api/v1/internal/providers/not-a-uuid/wcb-config-for-form?form_id=C8',
        VALID_API_KEY,
      );
      expect(res.statusCode).toBe(400);
    });
  });
});
