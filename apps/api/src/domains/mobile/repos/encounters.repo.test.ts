import { describe, it, expect, beforeEach, vi } from 'vitest';

vi.mock('drizzle-orm', () => ({
  eq: (col: any, val: any) => ({ type: 'eq', col, val }),
  and: (...args: any[]) => ({ type: 'and', args }),
  desc: (col: any) => ({ type: 'desc', col }),
}));

vi.mock('@meritum/shared/schemas/db/mobile.schema.js', () => {
  return {
    edShiftEncounters: {
      encounterId: 'encounterId',
      shiftId: 'shiftId',
      providerId: 'providerId',
      phn: 'phn',
      phnCaptureMethod: 'phnCaptureMethod',
      phnIsPartial: 'phnIsPartial',
      healthServiceCode: 'healthServiceCode',
      modifiers: 'modifiers',
      diCode: 'diCode',
      freeTextTag: 'freeTextTag',
      matchedClaimId: 'matchedClaimId',
      encounterTimestamp: 'encounterTimestamp',
      createdAt: 'createdAt',
    },
    edShifts: {
      shiftId: 'shiftId',
      providerId: 'providerId',
      status: 'status',
    },
  };
});

vi.mock('@meritum/shared/constants/mobile.constants.js', () => ({
  MobileShiftStatus: { ACTIVE: 'ACTIVE', ENDED: 'ENDED', REVIEWED: 'REVIEWED' },
}));

import { createEncountersRepository } from './encounters.repo.js';
import { BusinessRuleError, NotFoundError } from '../../../lib/errors.js';

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const PROVIDER_A = crypto.randomUUID();
const SHIFT_ID = crypto.randomUUID();
const ENCOUNTER_ID = crypto.randomUUID();

function makeEncounter(overrides: Record<string, any> = {}) {
  return {
    encounterId: overrides.encounterId ?? ENCOUNTER_ID,
    shiftId: overrides.shiftId ?? SHIFT_ID,
    providerId: overrides.providerId ?? PROVIDER_A,
    phn: overrides.phn ?? '123456789',
    phnCaptureMethod: overrides.phnCaptureMethod ?? 'BARCODE',
    phnIsPartial: overrides.phnIsPartial ?? false,
    healthServiceCode: overrides.healthServiceCode ?? '03.04A',
    modifiers: overrides.modifiers ?? null,
    diCode: overrides.diCode ?? null,
    freeTextTag: overrides.freeTextTag ?? 'chest pain',
    matchedClaimId: overrides.matchedClaimId ?? null,
    encounterTimestamp: overrides.encounterTimestamp ?? new Date(),
    createdAt: overrides.createdAt ?? new Date(),
  };
}

function makeActiveShift() {
  return { shiftId: SHIFT_ID, providerId: PROVIDER_A, status: 'ACTIVE' };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('EncountersRepository', () => {
  describe('logEncounter', () => {
    it('should insert encounter when shift is active', async () => {
      const expected = makeEncounter();
      const chain = {
        from: vi.fn().mockReturnThis(),
        where: vi.fn().mockReturnThis(),
        limit: vi.fn().mockResolvedValue([makeActiveShift()]),
        values: vi.fn().mockReturnThis(),
        returning: vi.fn().mockResolvedValue([expected]),
      };
      const db = {
        select: vi.fn().mockReturnValue(chain),
        insert: vi.fn().mockReturnValue(chain),
      } as any;

      const repo = createEncountersRepository(db);
      const result = await repo.logEncounter({
        shiftId: SHIFT_ID,
        providerId: PROVIDER_A,
        phn: '123456789',
        phnCaptureMethod: 'BARCODE',
        phnIsPartial: false,
        encounterTimestamp: new Date(),
      });

      expect(result).toEqual(expected);
    });

    it('should throw NotFoundError when shift not found', async () => {
      const chain = {
        from: vi.fn().mockReturnThis(),
        where: vi.fn().mockReturnThis(),
        limit: vi.fn().mockResolvedValue([]),
      };
      const db = { select: vi.fn().mockReturnValue(chain) } as any;
      const repo = createEncountersRepository(db);

      await expect(
        repo.logEncounter({
          shiftId: SHIFT_ID,
          providerId: PROVIDER_A,
          phn: '123456789',
          phnCaptureMethod: 'BARCODE',
          phnIsPartial: false,
          encounterTimestamp: new Date(),
        }),
      ).rejects.toThrow(NotFoundError);
    });

    it('should throw BusinessRuleError when shift is not active', async () => {
      const endedShift = { ...makeActiveShift(), status: 'ENDED' };
      const chain = {
        from: vi.fn().mockReturnThis(),
        where: vi.fn().mockReturnThis(),
        limit: vi.fn().mockResolvedValue([endedShift]),
      };
      const db = { select: vi.fn().mockReturnValue(chain) } as any;
      const repo = createEncountersRepository(db);

      await expect(
        repo.logEncounter({
          shiftId: SHIFT_ID,
          providerId: PROVIDER_A,
          phn: '123456789',
          phnCaptureMethod: 'BARCODE',
          phnIsPartial: false,
          encounterTimestamp: new Date(),
        }),
      ).rejects.toThrow(BusinessRuleError);
    });
  });

  describe('listEncounters', () => {
    it('should return encounters ordered by timestamp desc', async () => {
      const encounters = [makeEncounter(), makeEncounter({ encounterId: crypto.randomUUID() })];
      const chain = {
        from: vi.fn().mockReturnThis(),
        where: vi.fn().mockReturnThis(),
        orderBy: vi.fn().mockResolvedValue(encounters),
      };
      const db = { select: vi.fn().mockReturnValue(chain) } as any;
      const repo = createEncountersRepository(db);

      const result = await repo.listEncounters(SHIFT_ID, PROVIDER_A);
      expect(result).toHaveLength(2);
    });
  });

  describe('deleteEncounter', () => {
    it('should delete and return encounter when found', async () => {
      const enc = makeEncounter();
      const selectChain = {
        from: vi.fn().mockReturnThis(),
        where: vi.fn().mockReturnThis(),
        limit: vi.fn().mockResolvedValue([enc]),
      };
      const deleteChain = {
        where: vi.fn().mockReturnThis(),
        returning: vi.fn().mockResolvedValue([enc]),
      };
      const db = {
        select: vi.fn().mockReturnValue(selectChain),
        delete: vi.fn().mockReturnValue(deleteChain),
      } as any;
      const repo = createEncountersRepository(db);

      const result = await repo.deleteEncounter(ENCOUNTER_ID, SHIFT_ID, PROVIDER_A);
      expect(result).toEqual(enc);
    });

    it('should return null when encounter not found', async () => {
      const selectChain = {
        from: vi.fn().mockReturnThis(),
        where: vi.fn().mockReturnThis(),
        limit: vi.fn().mockResolvedValue([]),
      };
      const db = { select: vi.fn().mockReturnValue(selectChain) } as any;
      const repo = createEncountersRepository(db);

      const result = await repo.deleteEncounter('non-existent', SHIFT_ID, PROVIDER_A);
      expect(result).toBeNull();
    });
  });

  describe('getById', () => {
    it('should return encounter by ID scoped to provider', async () => {
      const enc = makeEncounter();
      const chain = {
        from: vi.fn().mockReturnThis(),
        where: vi.fn().mockReturnThis(),
        limit: vi.fn().mockResolvedValue([enc]),
      };
      const db = { select: vi.fn().mockReturnValue(chain) } as any;
      const repo = createEncountersRepository(db);

      const result = await repo.getById(ENCOUNTER_ID, PROVIDER_A);
      expect(result).toEqual(enc);
    });

    it('should return null for wrong provider', async () => {
      const chain = {
        from: vi.fn().mockReturnThis(),
        where: vi.fn().mockReturnThis(),
        limit: vi.fn().mockResolvedValue([]),
      };
      const db = { select: vi.fn().mockReturnValue(chain) } as any;
      const repo = createEncountersRepository(db);

      const result = await repo.getById(ENCOUNTER_ID, 'wrong-provider');
      expect(result).toBeNull();
    });
  });
});
