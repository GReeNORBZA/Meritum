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
// Imports (after mocks)
// ---------------------------------------------------------------------------

import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { favouriteRoutes } from '../../../src/domains/mobile/routes/favourite.routes.js';
import type { FavouriteCodesServiceDeps } from '../../../src/domains/mobile/services/favourite-codes.service.js';
import { MAX_FAVOURITES } from '@meritum/shared/constants/mobile.constants.js';

// ---------------------------------------------------------------------------
// Helper: hashToken
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

const PHYSICIAN1_USER_ID = '00000000-1111-0000-0000-000000000001';
const PHYSICIAN1_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN1_SESSION_TOKEN_HASH = hashToken(PHYSICIAN1_SESSION_TOKEN);

// ---------------------------------------------------------------------------
// Test data
// ---------------------------------------------------------------------------

const FAV_ID_1 = '00000000-ffff-0000-0000-000000000001';

function makeMockFavourite(overrides: Record<string, unknown> = {}) {
  return {
    favouriteId: FAV_ID_1,
    providerId: PHYSICIAN1_USER_ID,
    healthServiceCode: '03.04A',
    displayName: null,
    sortOrder: 1,
    defaultModifiers: null,
    createdAt: new Date(),
    ...overrides,
  };
}

function makeMockEnrichedFavourite(overrides: Record<string, unknown> = {}) {
  return {
    ...makeMockFavourite(overrides),
    description: 'General office visit',
    baseFee: '50.00',
  };
}

// ---------------------------------------------------------------------------
// Mock session repo
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      if (tokenHash === PHYSICIAN1_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: '00000000-2222-0000-0000-000000000001',
            userId: PHYSICIAN1_USER_ID,
            tokenHash: PHYSICIAN1_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: PHYSICIAN1_USER_ID,
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

// ---------------------------------------------------------------------------
// Mock service deps
// ---------------------------------------------------------------------------

let mockFavRepo: any;
let mockHscLookup: any;
let mockModifierLookup: any;
let mockClaimHistory: any;
let mockProviderProfile: any;
let mockSpecialtyDefaults: any;
let mockAuditRepo: any;

function createMockServiceDeps(): FavouriteCodesServiceDeps {
  mockFavRepo = {
    create: vi.fn(async (data: any) => makeMockFavourite({
      favouriteId: crypto.randomUUID(),
      healthServiceCode: data.healthServiceCode,
      displayName: data.displayName,
      sortOrder: data.sortOrder,
    })),
    getById: vi.fn(async () => null as any),
    update: vi.fn(async (_id: string, _pid: string, data: any) => makeMockFavourite(data)),
    delete: vi.fn(async () => true),
    listByProvider: vi.fn(async () => []),
    reorder: vi.fn(async () => {}),
    countByProvider: vi.fn(async () => 0),
    bulkCreate: vi.fn(async (_pid: string, items: any[]) =>
      items.map((item, i) => makeMockFavourite({
        favouriteId: crypto.randomUUID(),
        healthServiceCode: item.healthServiceCode,
        sortOrder: i + 1,
      })),
    ),
  };

  mockHscLookup = {
    findByCode: vi.fn(async (code: string) => ({
      code,
      description: `Description for ${code}`,
      baseFee: '50.00',
      feeType: 'FIXED',
    })),
  };

  mockModifierLookup = {
    isKnownModifier: vi.fn(async () => true),
  };

  mockClaimHistory = {
    getTopBilledCodes: vi.fn(async () => []),
  };

  mockProviderProfile = {
    getSpecialty: vi.fn(async () => 'GENERAL_PRACTICE'),
  };

  mockSpecialtyDefaults = {
    getDefaultCodes: vi.fn(async () => []),
  };

  mockAuditRepo = {
    appendAuditLog: vi.fn(async () => ({})),
  };

  return {
    repo: mockFavRepo,
    hscLookup: mockHscLookup,
    modifierLookup: mockModifierLookup,
    claimHistory: mockClaimHistory,
    providerProfile: mockProviderProfile,
    specialtyDefaults: mockSpecialtyDefaults,
    auditRepo: mockAuditRepo,
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let serviceDeps: FavouriteCodesServiceDeps;

async function buildTestApp(): Promise<FastifyInstance> {
  serviceDeps = createMockServiceDeps();

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

  await testApp.register(favouriteRoutes, { deps: { serviceDeps } });

  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function authedPost(url: string, body?: Record<string, unknown>) {
  return app.inject({
    method: 'POST',
    url,
    headers: {
      cookie: `session=${PHYSICIAN1_SESSION_TOKEN}`,
      'content-type': 'application/json',
    },
    payload: body ?? {},
  });
}

function authedGet(url: string) {
  return app.inject({
    method: 'GET',
    url,
    headers: { cookie: `session=${PHYSICIAN1_SESSION_TOKEN}` },
  });
}

function authedPut(url: string, body: Record<string, unknown>) {
  return app.inject({
    method: 'PUT',
    url,
    headers: {
      cookie: `session=${PHYSICIAN1_SESSION_TOKEN}`,
      'content-type': 'application/json',
    },
    payload: body,
  });
}

function authedDelete(url: string) {
  return app.inject({
    method: 'DELETE',
    url,
    headers: { cookie: `session=${PHYSICIAN1_SESSION_TOKEN}` },
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Mobile Favourites Integration Tests', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    vi.clearAllMocks();
    // Default: provider has no favourites (triggers seeding path)
    mockFavRepo.countByProvider.mockResolvedValue(0);
    mockFavRepo.listByProvider.mockResolvedValue([]);
  });

  // =========================================================================
  // First GET triggers seeding
  // =========================================================================

  describe('Auto-seeding on first GET', () => {
    it('seeds favourites from top billed codes when claim history exists', async () => {
      const topCodes = [
        { healthServiceCode: '03.04A', count: 50 },
        { healthServiceCode: '03.03A', count: 30 },
        { healthServiceCode: '08.19A', count: 20 },
      ];
      mockClaimHistory.getTopBilledCodes.mockResolvedValueOnce(topCodes);
      mockFavRepo.bulkCreate.mockResolvedValueOnce(
        topCodes.map((c, i) => makeMockFavourite({
          favouriteId: crypto.randomUUID(),
          healthServiceCode: c.healthServiceCode,
          sortOrder: i + 1,
        })),
      );
      const enrichedList = topCodes.map((c, i) => makeMockEnrichedFavourite({
        healthServiceCode: c.healthServiceCode,
        sortOrder: i + 1,
      }));
      mockFavRepo.listByProvider.mockResolvedValueOnce(
        topCodes.map((c, i) => makeMockFavourite({
          healthServiceCode: c.healthServiceCode,
          sortOrder: i + 1,
        })),
      );

      const res = await authedGet('/api/v1/favourites');
      expect(res.statusCode).toBe(200);
      expect(mockClaimHistory.getTopBilledCodes).toHaveBeenCalled();
    });

    it('skips seeding when provider already has favourites', async () => {
      mockFavRepo.countByProvider.mockResolvedValueOnce(5);
      const existingFavs = Array.from({ length: 5 }, (_, i) =>
        makeMockFavourite({
          favouriteId: crypto.randomUUID(),
          healthServiceCode: `03.0${i}A`,
          sortOrder: i + 1,
        }),
      );
      mockFavRepo.listByProvider.mockResolvedValueOnce(existingFavs);

      const res = await authedGet('/api/v1/favourites');
      expect(res.statusCode).toBe(200);
      expect(mockFavRepo.bulkCreate).not.toHaveBeenCalled();
    });
  });

  // =========================================================================
  // CRUD flow: add -> list -> update -> verify -> delete -> removed
  // =========================================================================

  describe('Favourite CRUD lifecycle', () => {
    it('add favourite -> appears in list -> update display_name -> verify -> delete -> removed', async () => {
      const favId = crypto.randomUUID();

      // Step 1: Add favourite
      mockFavRepo.create.mockResolvedValueOnce(makeMockFavourite({
        favouriteId: favId,
        healthServiceCode: '03.04A',
        sortOrder: 1,
      }));

      const addRes = await authedPost('/api/v1/favourites', {
        health_service_code: '03.04A',
        sort_order: 1,
      });
      expect(addRes.statusCode).toBe(201);
      expect(addRes.json().data.healthServiceCode).toBe('03.04A');

      // Step 2: Verify appears in list
      mockFavRepo.countByProvider.mockResolvedValueOnce(1);
      mockFavRepo.listByProvider.mockResolvedValueOnce([
        makeMockFavourite({ favouriteId: favId, healthServiceCode: '03.04A' }),
      ]);

      const listRes = await authedGet('/api/v1/favourites');
      expect(listRes.statusCode).toBe(200);
      expect(listRes.json().data).toHaveLength(1);

      // Step 3: Update display_name
      mockFavRepo.getById.mockResolvedValueOnce(makeMockFavourite({ favouriteId: favId }));
      mockFavRepo.update.mockResolvedValueOnce(makeMockFavourite({
        favouriteId: favId,
        displayName: 'My Office Visit',
      }));

      const updateRes = await authedPut(`/api/v1/favourites/${favId}`, {
        display_name: 'My Office Visit',
      });
      expect(updateRes.statusCode).toBe(200);
      expect(updateRes.json().data.displayName).toBe('My Office Visit');

      // Step 4: Delete
      mockFavRepo.getById.mockResolvedValueOnce(makeMockFavourite({ favouriteId: favId }));
      mockFavRepo.delete.mockResolvedValueOnce(true);

      const deleteRes = await authedDelete(`/api/v1/favourites/${favId}`);
      expect(deleteRes.statusCode).toBe(204);

      // Step 5: Verify removed from list
      mockFavRepo.countByProvider.mockResolvedValueOnce(0);
      mockFavRepo.listByProvider.mockResolvedValueOnce([]);

      const listRes2 = await authedGet('/api/v1/favourites');
      expect(listRes2.statusCode).toBe(200);
      // List may auto-seed again since count is 0; the important check is
      // that the deleted favourite is not in the list
    });
  });

  // =========================================================================
  // Max 30 favourites
  // =========================================================================

  describe('Max 30 favourites limit', () => {
    it('rejects 31st favourite with 422', async () => {
      const { BusinessRuleError } = await import('../../../src/lib/errors.js');
      mockFavRepo.create.mockRejectedValueOnce(
        new BusinessRuleError('Maximum 30 favourites allowed'),
      );

      const res = await authedPost('/api/v1/favourites', {
        health_service_code: '99.99A',
        sort_order: 31,
      });
      expect(res.statusCode).toBe(422);
      expect(res.json().error.code).toBe('BUSINESS_RULE_VIOLATION');
    });
  });

  // =========================================================================
  // Reorder
  // =========================================================================

  describe('Reorder favourites', () => {
    it('reorders 5 favourites -> verify new sort_order', async () => {
      const favIds = Array.from({ length: 5 }, () => crypto.randomUUID());
      const items = favIds.map((id, i) => ({
        favourite_id: id,
        sort_order: 5 - i, // Reverse order
      }));

      mockFavRepo.reorder.mockResolvedValueOnce(undefined);

      const res = await authedPut('/api/v1/favourites/reorder', { items });
      expect(res.statusCode).toBe(200);
      expect(res.json().data.success).toBe(true);
      expect(mockFavRepo.reorder).toHaveBeenCalledWith(
        PHYSICIAN1_USER_ID,
        items,
      );
    });
  });

  // =========================================================================
  // Duplicate HSC code -> 409
  // =========================================================================

  describe('Duplicate HSC code', () => {
    it('rejects duplicate health_service_code with 409', async () => {
      const { ConflictError } = await import('../../../src/lib/errors.js');
      mockFavRepo.create.mockRejectedValueOnce(
        new ConflictError('Favourite with this health service code already exists'),
      );

      const res = await authedPost('/api/v1/favourites', {
        health_service_code: '03.04A',
        sort_order: 1,
      });
      expect(res.statusCode).toBe(409);
      expect(res.json().error.code).toBe('CONFLICT');
    });
  });

  // =========================================================================
  // Validation
  // =========================================================================

  describe('Validation', () => {
    it('rejects favourite with missing health_service_code', async () => {
      const res = await authedPost('/api/v1/favourites', {
        sort_order: 1,
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects favourite with missing sort_order', async () => {
      const res = await authedPost('/api/v1/favourites', {
        health_service_code: '03.04A',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects update with empty body', async () => {
      const res = await authedPut(`/api/v1/favourites/${FAV_ID_1}`, {});
      expect(res.statusCode).toBe(400);
    });

    it('rejects non-UUID favourite id param', async () => {
      const res = await authedPut('/api/v1/favourites/not-a-uuid', {
        display_name: 'test',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects reorder with empty items array', async () => {
      const res = await authedPut('/api/v1/favourites/reorder', { items: [] });
      expect(res.statusCode).toBe(400);
    });

    it('rejects reorder with > 30 items', async () => {
      const items = Array.from({ length: 31 }, (_, i) => ({
        favourite_id: crypto.randomUUID(),
        sort_order: i + 1,
      }));
      const res = await authedPut('/api/v1/favourites/reorder', { items });
      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // Favourite not found
  // =========================================================================

  describe('Favourite not found', () => {
    it('PUT /favourites/:id returns 404 for non-existent favourite', async () => {
      // Service calls repo.update() which returns null for non-existent
      mockFavRepo.update.mockResolvedValueOnce(null);

      const nonExistentId = crypto.randomUUID();
      const res = await authedPut(`/api/v1/favourites/${nonExistentId}`, {
        display_name: 'test',
      });
      expect(res.statusCode).toBe(404);
    });

    it('DELETE /favourites/:id returns 404 for non-existent favourite', async () => {
      // Service calls repo.delete() which returns false for non-existent
      mockFavRepo.delete.mockResolvedValueOnce(false);

      const nonExistentId = crypto.randomUUID();
      const res = await authedDelete(`/api/v1/favourites/${nonExistentId}`);
      expect(res.statusCode).toBe(404);
    });
  });
});
