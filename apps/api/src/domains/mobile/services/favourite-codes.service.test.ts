import { describe, it, expect, vi } from 'vitest';
import {
  addFavourite,
  updateFavourite,
  removeFavourite,
  reorderFavourites,
  listFavourites,
  seedFavourites,
} from './favourite-codes.service.js';
import type { FavouriteCodesServiceDeps } from './favourite-codes.service.js';
import {
  NotFoundError,
  BusinessRuleError,
  ValidationError,
} from '../../../lib/errors.js';

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const PROVIDER_A = crypto.randomUUID();
const PROVIDER_B = crypto.randomUUID();
const FAVOURITE_ID = crypto.randomUUID();
const HSC_CODE = '03.04A';
const HSC_CODE_2 = '03.05A';

// ---------------------------------------------------------------------------
// Mock factories
// ---------------------------------------------------------------------------

function makeFavourite(overrides: Record<string, unknown> = {}) {
  return {
    favouriteId: overrides.favouriteId ?? FAVOURITE_ID,
    providerId: overrides.providerId ?? PROVIDER_A,
    healthServiceCode: overrides.healthServiceCode ?? HSC_CODE,
    displayName: overrides.displayName ?? null,
    sortOrder: overrides.sortOrder ?? 1,
    defaultModifiers: overrides.defaultModifiers ?? null,
    createdAt: overrides.createdAt ?? new Date('2026-02-19T10:00:00Z'),
  };
}

function makeHscDetail(overrides: Record<string, unknown> = {}) {
  return {
    code: overrides.code ?? HSC_CODE,
    description: overrides.description ?? 'General assessment',
    baseFee: overrides.baseFee ?? '38.50',
    feeType: overrides.feeType ?? 'fixed',
  };
}

function makeDeps(
  overrides: Partial<FavouriteCodesServiceDeps> = {},
): FavouriteCodesServiceDeps {
  return {
    repo: {
      create: vi.fn().mockResolvedValue(makeFavourite()),
      getById: vi.fn().mockResolvedValue(makeFavourite()),
      update: vi.fn().mockResolvedValue(makeFavourite()),
      delete: vi.fn().mockResolvedValue(true),
      listByProvider: vi
        .fn()
        .mockResolvedValue([makeFavourite()]),
      reorder: vi.fn().mockResolvedValue(undefined),
      countByProvider: vi.fn().mockResolvedValue(0),
      bulkCreate: vi.fn().mockResolvedValue([makeFavourite()]),
    } as any,
    hscLookup: {
      findByCode: vi.fn().mockResolvedValue(makeHscDetail()),
    },
    modifierLookup: {
      isKnownModifier: vi.fn().mockResolvedValue(true),
    },
    claimHistory: {
      getTopBilledCodes: vi.fn().mockResolvedValue([]),
    },
    providerProfile: {
      getSpecialty: vi.fn().mockResolvedValue('GP'),
    },
    specialtyDefaults: {
      getDefaultCodes: vi.fn().mockResolvedValue([]),
    },
    auditRepo: {
      appendAuditLog: vi.fn().mockResolvedValue({}),
    },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests: addFavourite
// ---------------------------------------------------------------------------

describe('FavouriteCodesService', () => {
  describe('addFavourite', () => {
    it('creates a favourite when HSC code is valid', async () => {
      const deps = makeDeps();

      const result = await addFavourite(deps, PROVIDER_A, {
        healthServiceCode: HSC_CODE,
        sortOrder: 1,
      });

      expect(result).toBeDefined();
      expect(result.favouriteId).toBe(FAVOURITE_ID);
      expect(result.description).toBe('General assessment');
      expect(result.baseFee).toBe('38.50');
      expect(deps.hscLookup.findByCode).toHaveBeenCalledWith(HSC_CODE);
      expect(deps.repo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          providerId: PROVIDER_A,
          healthServiceCode: HSC_CODE,
          sortOrder: 1,
        }),
      );
    });

    it('validates HSC code exists in reference data', async () => {
      const deps = makeDeps({
        hscLookup: {
          findByCode: vi.fn().mockResolvedValue(null),
        },
      });

      await expect(
        addFavourite(deps, PROVIDER_A, {
          healthServiceCode: 'INVALID_CODE',
          sortOrder: 1,
        }),
      ).rejects.toThrow(ValidationError);

      expect(deps.repo.create).not.toHaveBeenCalled();
    });

    it('validates modifiers are known codes', async () => {
      const deps = makeDeps({
        modifierLookup: {
          isKnownModifier: vi
            .fn()
            .mockResolvedValueOnce(true)
            .mockResolvedValueOnce(false),
        },
      });

      await expect(
        addFavourite(deps, PROVIDER_A, {
          healthServiceCode: HSC_CODE,
          sortOrder: 1,
          defaultModifiers: ['CMGP', 'INVALID_MOD'],
        }),
      ).rejects.toThrow(ValidationError);

      expect(deps.repo.create).not.toHaveBeenCalled();
    });

    it('enforces max 30 (delegates to repo BusinessRuleError)', async () => {
      const deps = makeDeps({
        repo: {
          ...makeDeps().repo,
          create: vi
            .fn()
            .mockRejectedValue(
              new BusinessRuleError(
                'Maximum of 30 favourite codes allowed per physician',
              ),
            ),
        } as any,
      });

      await expect(
        addFavourite(deps, PROVIDER_A, {
          healthServiceCode: HSC_CODE,
          sortOrder: 31,
        }),
      ).rejects.toThrow(BusinessRuleError);
    });

    it('passes display name and modifiers to repo', async () => {
      const deps = makeDeps();

      await addFavourite(deps, PROVIDER_A, {
        healthServiceCode: HSC_CODE,
        displayName: 'My Code',
        defaultModifiers: ['CMGP'],
        sortOrder: 2,
      });

      expect(deps.repo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          displayName: 'My Code',
          defaultModifiers: ['CMGP'],
          sortOrder: 2,
        }),
      );
    });

    it('logs audit event on successful add', async () => {
      const deps = makeDeps();

      await addFavourite(deps, PROVIDER_A, {
        healthServiceCode: HSC_CODE,
        sortOrder: 1,
      });

      expect(deps.auditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: PROVIDER_A,
          action: 'mobile.favourite_added',
          category: 'mobile',
          resourceType: 'favourite_code',
          resourceId: FAVOURITE_ID,
          detail: expect.objectContaining({
            healthServiceCode: HSC_CODE,
          }),
        }),
      );
    });

    it('does not log audit event when validation fails', async () => {
      const deps = makeDeps({
        hscLookup: {
          findByCode: vi.fn().mockResolvedValue(null),
        },
      });

      await expect(
        addFavourite(deps, PROVIDER_A, {
          healthServiceCode: 'INVALID',
          sortOrder: 1,
        }),
      ).rejects.toThrow();

      expect(deps.auditRepo.appendAuditLog).not.toHaveBeenCalled();
    });

    it('skips modifier validation when none provided', async () => {
      const deps = makeDeps();

      await addFavourite(deps, PROVIDER_A, {
        healthServiceCode: HSC_CODE,
        sortOrder: 1,
      });

      expect(deps.modifierLookup.isKnownModifier).not.toHaveBeenCalled();
    });
  });

  // =========================================================================
  // updateFavourite
  // =========================================================================

  describe('updateFavourite', () => {
    it('updates favourite fields and returns enriched result', async () => {
      const updatedFav = makeFavourite({ displayName: 'Updated Name' });
      const deps = makeDeps({
        repo: {
          ...makeDeps().repo,
          update: vi.fn().mockResolvedValue(updatedFav),
        } as any,
      });

      const result = await updateFavourite(deps, PROVIDER_A, FAVOURITE_ID, {
        displayName: 'Updated Name',
      });

      expect(result.displayName).toBe('Updated Name');
      expect(result.description).toBe('General assessment');
      expect(deps.repo.update).toHaveBeenCalledWith(
        FAVOURITE_ID,
        PROVIDER_A,
        expect.objectContaining({ displayName: 'Updated Name' }),
      );
    });

    it('throws NotFoundError when favourite does not exist', async () => {
      const deps = makeDeps({
        repo: {
          ...makeDeps().repo,
          update: vi.fn().mockResolvedValue(null),
        } as any,
      });

      await expect(
        updateFavourite(deps, PROVIDER_A, FAVOURITE_ID, {
          displayName: 'New Name',
        }),
      ).rejects.toThrow(NotFoundError);
    });

    it('throws NotFoundError when favourite belongs to another provider', async () => {
      const deps = makeDeps({
        repo: {
          ...makeDeps().repo,
          update: vi.fn().mockResolvedValue(null),
        } as any,
      });

      await expect(
        updateFavourite(deps, PROVIDER_B, FAVOURITE_ID, {
          displayName: 'Stolen',
        }),
      ).rejects.toThrow(NotFoundError);
    });

    it('validates modifiers on update', async () => {
      const deps = makeDeps({
        modifierLookup: {
          isKnownModifier: vi.fn().mockResolvedValue(false),
        },
      });

      await expect(
        updateFavourite(deps, PROVIDER_A, FAVOURITE_ID, {
          defaultModifiers: ['UNKNOWN'],
        }),
      ).rejects.toThrow(ValidationError);

      expect(deps.repo.update).not.toHaveBeenCalled();
    });
  });

  // =========================================================================
  // removeFavourite
  // =========================================================================

  describe('removeFavourite', () => {
    it('deletes favourite and logs audit event', async () => {
      const deps = makeDeps();

      await removeFavourite(deps, PROVIDER_A, FAVOURITE_ID);

      expect(deps.repo.delete).toHaveBeenCalledWith(FAVOURITE_ID, PROVIDER_A);
      expect(deps.auditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: PROVIDER_A,
          action: 'mobile.favourite_removed',
          category: 'mobile',
          resourceType: 'favourite_code',
          resourceId: FAVOURITE_ID,
        }),
      );
    });

    it('throws NotFoundError when favourite does not exist', async () => {
      const deps = makeDeps({
        repo: {
          ...makeDeps().repo,
          delete: vi.fn().mockResolvedValue(false),
        } as any,
      });

      await expect(
        removeFavourite(deps, PROVIDER_A, FAVOURITE_ID),
      ).rejects.toThrow(NotFoundError);
    });

    it('throws NotFoundError for another provider\'s favourite', async () => {
      const deps = makeDeps({
        repo: {
          ...makeDeps().repo,
          delete: vi.fn().mockResolvedValue(false),
        } as any,
      });

      await expect(
        removeFavourite(deps, PROVIDER_B, FAVOURITE_ID),
      ).rejects.toThrow(NotFoundError);

      expect(deps.auditRepo.appendAuditLog).not.toHaveBeenCalled();
    });
  });

  // =========================================================================
  // reorderFavourites
  // =========================================================================

  describe('reorderFavourites', () => {
    it('reorders favourites and logs audit event', async () => {
      const deps = makeDeps();
      const items = [
        { favourite_id: crypto.randomUUID(), sort_order: 1 },
        { favourite_id: crypto.randomUUID(), sort_order: 2 },
      ];

      await reorderFavourites(deps, PROVIDER_A, items);

      expect(deps.repo.reorder).toHaveBeenCalledWith(PROVIDER_A, items);
      expect(deps.auditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: PROVIDER_A,
          action: 'mobile.favourite_reordered',
          category: 'mobile',
          resourceType: 'favourite_code',
          detail: expect.objectContaining({
            itemCount: 2,
          }),
        }),
      );
    });

    it('validates ownership (delegates to repo BusinessRuleError)', async () => {
      const deps = makeDeps({
        repo: {
          ...makeDeps().repo,
          reorder: vi
            .fn()
            .mockRejectedValue(
              new BusinessRuleError(
                'One or more favourite IDs do not belong to this physician',
              ),
            ),
        } as any,
      });

      await expect(
        reorderFavourites(deps, PROVIDER_A, [
          { favourite_id: crypto.randomUUID(), sort_order: 1 },
        ]),
      ).rejects.toThrow(BusinessRuleError);

      expect(deps.auditRepo.appendAuditLog).not.toHaveBeenCalled();
    });
  });

  // =========================================================================
  // listFavourites
  // =========================================================================

  describe('listFavourites', () => {
    it('returns enriched list of favourites', async () => {
      const deps = makeDeps({
        repo: {
          ...makeDeps().repo,
          listByProvider: vi
            .fn()
            .mockResolvedValue([
              makeFavourite({ healthServiceCode: HSC_CODE }),
              makeFavourite({
                favouriteId: crypto.randomUUID(),
                healthServiceCode: HSC_CODE_2,
                sortOrder: 2,
              }),
            ]),
        } as any,
      });

      const result = await listFavourites(deps, PROVIDER_A);

      expect(result).toHaveLength(2);
      expect(result[0].description).toBe('General assessment');
      expect(result[0].baseFee).toBe('38.50');
      expect(deps.repo.listByProvider).toHaveBeenCalledWith(PROVIDER_A);
    });

    it('returns empty list when no favourites exist', async () => {
      const deps = makeDeps({
        repo: {
          ...makeDeps().repo,
          listByProvider: vi.fn().mockResolvedValue([]),
        } as any,
      });

      const result = await listFavourites(deps, PROVIDER_A);

      expect(result).toHaveLength(0);
    });

    it('handles missing HSC detail gracefully', async () => {
      const deps = makeDeps({
        hscLookup: {
          findByCode: vi.fn().mockResolvedValue(null),
        },
      });

      const result = await listFavourites(deps, PROVIDER_A);

      expect(result).toHaveLength(1);
      expect(result[0].description).toBe('');
      expect(result[0].baseFee).toBeNull();
    });
  });

  // =========================================================================
  // seedFavourites
  // =========================================================================

  describe('seedFavourites', () => {
    it('skips seeding when favourites already exist', async () => {
      const deps = makeDeps({
        repo: {
          ...makeDeps().repo,
          countByProvider: vi.fn().mockResolvedValue(5),
        } as any,
      });

      const count = await seedFavourites(deps, PROVIDER_A);

      expect(count).toBe(0);
      expect(deps.claimHistory.getTopBilledCodes).not.toHaveBeenCalled();
      expect(deps.repo.bulkCreate).not.toHaveBeenCalled();
    });

    it('seeds from claim history when available', async () => {
      const topCodes = [
        { healthServiceCode: '03.04A', count: 50 },
        { healthServiceCode: '03.05A', count: 30 },
        { healthServiceCode: '08.19A', count: 20 },
      ];
      const deps = makeDeps({
        claimHistory: {
          getTopBilledCodes: vi.fn().mockResolvedValue(topCodes),
        },
      });

      const count = await seedFavourites(deps, PROVIDER_A);

      expect(count).toBe(3);
      expect(deps.repo.bulkCreate).toHaveBeenCalledWith(
        PROVIDER_A,
        expect.arrayContaining([
          expect.objectContaining({
            healthServiceCode: '03.04A',
            sortOrder: 1,
          }),
          expect.objectContaining({
            healthServiceCode: '03.05A',
            sortOrder: 2,
          }),
          expect.objectContaining({
            healthServiceCode: '08.19A',
            sortOrder: 3,
          }),
        ]),
      );
    });

    it('seeds from specialty defaults when no claim history', async () => {
      const deps = makeDeps({
        claimHistory: {
          getTopBilledCodes: vi.fn().mockResolvedValue([]),
        },
        providerProfile: {
          getSpecialty: vi.fn().mockResolvedValue('GP'),
        },
        specialtyDefaults: {
          getDefaultCodes: vi
            .fn()
            .mockResolvedValue(['03.04A', '08.19A']),
        },
      });

      const count = await seedFavourites(deps, PROVIDER_A);

      expect(count).toBe(2);
      expect(deps.providerProfile.getSpecialty).toHaveBeenCalledWith(
        PROVIDER_A,
      );
      expect(deps.specialtyDefaults.getDefaultCodes).toHaveBeenCalledWith('GP');
      expect(deps.repo.bulkCreate).toHaveBeenCalledWith(
        PROVIDER_A,
        expect.arrayContaining([
          expect.objectContaining({
            healthServiceCode: '03.04A',
            sortOrder: 1,
          }),
          expect.objectContaining({
            healthServiceCode: '08.19A',
            sortOrder: 2,
          }),
        ]),
      );
    });

    it('returns 0 when no claim history and no specialty', async () => {
      const deps = makeDeps({
        claimHistory: {
          getTopBilledCodes: vi.fn().mockResolvedValue([]),
        },
        providerProfile: {
          getSpecialty: vi.fn().mockResolvedValue(null),
        },
      });

      const count = await seedFavourites(deps, PROVIDER_A);

      expect(count).toBe(0);
      expect(deps.repo.bulkCreate).not.toHaveBeenCalled();
    });

    it('returns 0 when no claim history and no specialty defaults', async () => {
      const deps = makeDeps({
        claimHistory: {
          getTopBilledCodes: vi.fn().mockResolvedValue([]),
        },
        providerProfile: {
          getSpecialty: vi.fn().mockResolvedValue('GP'),
        },
        specialtyDefaults: {
          getDefaultCodes: vi.fn().mockResolvedValue([]),
        },
      });

      const count = await seedFavourites(deps, PROVIDER_A);

      expect(count).toBe(0);
      expect(deps.repo.bulkCreate).not.toHaveBeenCalled();
    });

    it('caps specialty defaults at AUTO_SEED_COUNT', async () => {
      const manyCodes = Array.from({ length: 20 }, (_, i) => `CODE_${i}`);
      const deps = makeDeps({
        claimHistory: {
          getTopBilledCodes: vi.fn().mockResolvedValue([]),
        },
        providerProfile: {
          getSpecialty: vi.fn().mockResolvedValue('GP'),
        },
        specialtyDefaults: {
          getDefaultCodes: vi.fn().mockResolvedValue(manyCodes),
        },
      });

      const count = await seedFavourites(deps, PROVIDER_A);

      expect(count).toBe(10); // AUTO_SEED_COUNT = 10
      const bulkCreateCall = (deps.repo.bulkCreate as ReturnType<typeof vi.fn>)
        .mock.calls[0];
      expect(bulkCreateCall[1]).toHaveLength(10);
    });

    it('logs audit event for claim history seeding', async () => {
      const deps = makeDeps({
        claimHistory: {
          getTopBilledCodes: vi
            .fn()
            .mockResolvedValue([
              { healthServiceCode: '03.04A', count: 10 },
            ]),
        },
      });

      await seedFavourites(deps, PROVIDER_A);

      expect(deps.auditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: PROVIDER_A,
          action: 'mobile.favourite_added',
          category: 'mobile',
          resourceType: 'favourite_code',
          detail: expect.objectContaining({
            seedSource: 'claim_history',
            count: 1,
          }),
        }),
      );
    });

    it('logs audit event for specialty defaults seeding', async () => {
      const deps = makeDeps({
        claimHistory: {
          getTopBilledCodes: vi.fn().mockResolvedValue([]),
        },
        providerProfile: {
          getSpecialty: vi.fn().mockResolvedValue('GP'),
        },
        specialtyDefaults: {
          getDefaultCodes: vi.fn().mockResolvedValue(['03.04A']),
        },
      });

      await seedFavourites(deps, PROVIDER_A);

      expect(deps.auditRepo.appendAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: PROVIDER_A,
          action: 'mobile.favourite_added',
          category: 'mobile',
          resourceType: 'favourite_code',
          detail: expect.objectContaining({
            seedSource: 'specialty_defaults',
            specialty: 'GP',
            count: 1,
          }),
        }),
      );
    });

    it('does not log audit event when seeding is skipped', async () => {
      const deps = makeDeps({
        repo: {
          ...makeDeps().repo,
          countByProvider: vi.fn().mockResolvedValue(5),
        } as any,
      });

      await seedFavourites(deps, PROVIDER_A);

      expect(deps.auditRepo.appendAuditLog).not.toHaveBeenCalled();
    });

    it('claim history seeding scoped to provider_id', async () => {
      const deps = makeDeps({
        claimHistory: {
          getTopBilledCodes: vi.fn().mockResolvedValue([]),
        },
      });

      await seedFavourites(deps, PROVIDER_A);

      expect(deps.claimHistory.getTopBilledCodes).toHaveBeenCalledWith(
        PROVIDER_A,
        10,
      );
    });
  });

  // =========================================================================
  // Security: ownership validation
  // =========================================================================

  describe('Security: ownership validation', () => {
    it('update scoped to provider (returns NotFoundError for other physician)', async () => {
      const deps = makeDeps({
        repo: {
          ...makeDeps().repo,
          update: vi.fn().mockResolvedValue(null),
        } as any,
      });

      await expect(
        updateFavourite(deps, PROVIDER_B, FAVOURITE_ID, {
          displayName: 'Stolen',
        }),
      ).rejects.toThrow(NotFoundError);
    });

    it('delete scoped to provider (returns NotFoundError for other physician)', async () => {
      const deps = makeDeps({
        repo: {
          ...makeDeps().repo,
          delete: vi.fn().mockResolvedValue(false),
        } as any,
      });

      await expect(
        removeFavourite(deps, PROVIDER_B, FAVOURITE_ID),
      ).rejects.toThrow(NotFoundError);

      expect(deps.auditRepo.appendAuditLog).not.toHaveBeenCalled();
    });

    it('reorder validates all IDs belong to provider', async () => {
      const deps = makeDeps({
        repo: {
          ...makeDeps().repo,
          reorder: vi
            .fn()
            .mockRejectedValue(
              new BusinessRuleError(
                'One or more favourite IDs do not belong to this physician',
              ),
            ),
        } as any,
      });

      await expect(
        reorderFavourites(deps, PROVIDER_B, [
          { favourite_id: FAVOURITE_ID, sort_order: 1 },
        ]),
      ).rejects.toThrow(BusinessRuleError);
    });
  });
});
