import { describe, it, expect, beforeEach, vi } from 'vitest';

vi.mock('@meritum/shared/constants/mobile.constants.js', () => ({
  PhnCaptureMethod: {
    BARCODE: 'BARCODE',
    SEARCH: 'SEARCH',
    MANUAL: 'MANUAL',
    LAST_FOUR: 'LAST_FOUR',
  },
  MobileAuditAction: {
    PATIENT_LOGGED: 'mobile.patient_logged',
  },
}));

import {
  logEncounter,
  deleteEncounter,
  listEncounters,
  validatePhn,
  validatePhnLuhn,
  PhnValidationError,
  EncounterNotFoundError,
} from './encounter.service.js';
import type { EncounterServiceDeps } from './encounter.service.js';

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

function makeDeps(overrides: Partial<EncounterServiceDeps> = {}): EncounterServiceDeps {
  return {
    encounterRepo: {
      logEncounter: vi.fn().mockResolvedValue(makeEncounter()),
      listEncounters: vi.fn().mockResolvedValue([makeEncounter()]),
      deleteEncounter: vi.fn().mockResolvedValue(makeEncounter()),
      getById: vi.fn().mockResolvedValue(makeEncounter()),
    } as any,
    auditRepo: {
      appendAuditLog: vi.fn().mockResolvedValue({}),
    },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// PHN Validation
// ---------------------------------------------------------------------------

describe('validatePhnLuhn', () => {
  it('should return true for valid Luhn PHN', () => {
    // 123456782 is a valid Luhn sequence
    expect(validatePhnLuhn('123456782')).toBe(true);
  });

  it('should return false for invalid Luhn PHN', () => {
    expect(validatePhnLuhn('123456789')).toBe(false);
  });

  it('should return false for non-9-digit strings', () => {
    expect(validatePhnLuhn('12345')).toBe(false);
    expect(validatePhnLuhn('abcdefghi')).toBe(false);
    expect(validatePhnLuhn('')).toBe(false);
  });
});

describe('validatePhn', () => {
  it('should validate full PHN for BARCODE capture', () => {
    const result = validatePhn('123456782', 'BARCODE');
    expect(result.phn).toBe('123456782');
    expect(result.isPartial).toBe(false);
  });

  it('should validate full PHN for SEARCH capture', () => {
    const result = validatePhn('123456782', 'SEARCH');
    expect(result.phn).toBe('123456782');
    expect(result.isPartial).toBe(false);
  });

  it('should validate full PHN for MANUAL capture', () => {
    const result = validatePhn('123456782', 'MANUAL');
    expect(result.phn).toBe('123456782');
    expect(result.isPartial).toBe(false);
  });

  it('should accept 4-digit partial for LAST_FOUR capture', () => {
    const result = validatePhn('6789', 'LAST_FOUR');
    expect(result.phn).toBe('6789');
    expect(result.isPartial).toBe(true);
  });

  it('should throw for invalid LAST_FOUR (not 4 digits)', () => {
    expect(() => validatePhn('123', 'LAST_FOUR')).toThrow(PhnValidationError);
    expect(() => validatePhn('12345', 'LAST_FOUR')).toThrow(PhnValidationError);
    expect(() => validatePhn(undefined, 'LAST_FOUR')).toThrow(PhnValidationError);
  });

  it('should return null PHN when not provided for full capture methods', () => {
    const result = validatePhn(undefined, 'BARCODE');
    expect(result.phn).toBeNull();
    expect(result.isPartial).toBe(false);
  });

  it('should throw for non-9-digit full PHN', () => {
    expect(() => validatePhn('12345', 'BARCODE')).toThrow(PhnValidationError);
  });

  it('should throw for invalid Luhn on full PHN', () => {
    expect(() => validatePhn('123456789', 'BARCODE')).toThrow(PhnValidationError);
  });
});

// ---------------------------------------------------------------------------
// logEncounter
// ---------------------------------------------------------------------------

describe('logEncounter', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should log encounter with valid BARCODE PHN', async () => {
    const deps = makeDeps();
    const result = await logEncounter(deps, PROVIDER_A, SHIFT_ID, {
      phn: '123456782',
      phnCaptureMethod: 'BARCODE',
    });

    expect(result.encounterId).toBe(ENCOUNTER_ID);
    expect(deps.encounterRepo.logEncounter).toHaveBeenCalledWith(
      expect.objectContaining({
        shiftId: SHIFT_ID,
        providerId: PROVIDER_A,
        phn: '123456782',
        phnCaptureMethod: 'BARCODE',
        phnIsPartial: false,
      }),
    );
  });

  it('should log encounter with LAST_FOUR partial PHN', async () => {
    const deps = makeDeps();
    await logEncounter(deps, PROVIDER_A, SHIFT_ID, {
      phn: '6789',
      phnCaptureMethod: 'LAST_FOUR',
    });

    expect(deps.encounterRepo.logEncounter).toHaveBeenCalledWith(
      expect.objectContaining({
        phn: '6789',
        phnIsPartial: true,
      }),
    );
  });

  it('should log encounter without PHN', async () => {
    const deps = makeDeps();
    await logEncounter(deps, PROVIDER_A, SHIFT_ID, {
      phnCaptureMethod: 'SEARCH',
    });

    expect(deps.encounterRepo.logEncounter).toHaveBeenCalledWith(
      expect.objectContaining({
        phn: null,
        phnIsPartial: false,
      }),
    );
  });

  it('should include free text tag and HSC', async () => {
    const deps = makeDeps();
    await logEncounter(deps, PROVIDER_A, SHIFT_ID, {
      phnCaptureMethod: 'MANUAL',
      healthServiceCode: '03.04A',
      freeTextTag: 'chest pain',
    });

    expect(deps.encounterRepo.logEncounter).toHaveBeenCalledWith(
      expect.objectContaining({
        healthServiceCode: '03.04A',
        freeTextTag: 'chest pain',
      }),
    );
  });

  it('should use provided encounterTimestamp', async () => {
    const deps = makeDeps();
    const ts = '2026-02-16T10:30:00.000Z';
    await logEncounter(deps, PROVIDER_A, SHIFT_ID, {
      phnCaptureMethod: 'BARCODE',
      encounterTimestamp: ts,
    });

    const call = vi.mocked(deps.encounterRepo.logEncounter).mock.calls[0][0];
    expect(call.encounterTimestamp).toEqual(new Date(ts));
  });

  it('should audit log the encounter', async () => {
    const deps = makeDeps();
    await logEncounter(deps, PROVIDER_A, SHIFT_ID, {
      phnCaptureMethod: 'BARCODE',
    });

    expect(deps.auditRepo.appendAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'mobile.patient_logged',
        resourceType: 'ed_shift_encounter',
        resourceId: ENCOUNTER_ID,
      }),
    );
  });

  it('should throw PhnValidationError for invalid Luhn', async () => {
    const deps = makeDeps();
    await expect(
      logEncounter(deps, PROVIDER_A, SHIFT_ID, {
        phn: '123456789',
        phnCaptureMethod: 'BARCODE',
      }),
    ).rejects.toThrow(PhnValidationError);
  });
});

// ---------------------------------------------------------------------------
// deleteEncounter
// ---------------------------------------------------------------------------

describe('deleteEncounter', () => {
  it('should delete and return the encounter', async () => {
    const deps = makeDeps();
    const result = await deleteEncounter(deps, PROVIDER_A, SHIFT_ID, ENCOUNTER_ID);

    expect(result.encounterId).toBe(ENCOUNTER_ID);
    expect(deps.auditRepo.appendAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'mobile.encounter_deleted' }),
    );
  });

  it('should throw EncounterNotFoundError when not found', async () => {
    const deps = makeDeps({
      encounterRepo: {
        ...makeDeps().encounterRepo,
        deleteEncounter: vi.fn().mockResolvedValue(null),
      } as any,
    });

    await expect(
      deleteEncounter(deps, PROVIDER_A, SHIFT_ID, 'non-existent'),
    ).rejects.toThrow(EncounterNotFoundError);
  });
});

// ---------------------------------------------------------------------------
// listEncounters
// ---------------------------------------------------------------------------

describe('listEncounters', () => {
  it('should return encounters for a shift', async () => {
    const deps = makeDeps();
    const result = await listEncounters(deps, PROVIDER_A, SHIFT_ID);
    expect(result).toHaveLength(1);
  });
});
