// ============================================================================
// Connect Care Reconciliation Service — Unit Tests (MOB-002 §10.1)
// ============================================================================

import { describe, it, expect, beforeEach, vi } from 'vitest';

vi.mock('@meritum/shared/constants/mobile.constants.js', () => ({
  ReconciliationMatchCategory: {
    FULL_MATCH: 'FULL_MATCH',
    UNMATCHED_SCC: 'UNMATCHED_SCC',
    UNMATCHED_ENCOUNTER: 'UNMATCHED_ENCOUNTER',
    SHIFT_ONLY: 'SHIFT_ONLY',
  },
}));

import {
  matchRows,
  detectModifierEligibility,
  partialPhnMatches,
  reconcileImportWithShift,
  confirmReconciliation,
  resolveUnmatchedTime,
  resolvePartialPhn,
  ReconciliationError,
  type ReconciliationDeps,
  type SccImportRow,
  type EncounterRow,
  type ReconciliationResult,
} from './reconciliation.service.js';

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const PROVIDER_A = crypto.randomUUID();
const BATCH_ID = crypto.randomUUID();
const SHIFT_ID = crypto.randomUUID();
const CLAIM_ID_1 = crypto.randomUUID();
const CLAIM_ID_2 = crypto.randomUUID();
const CLAIM_ID_3 = crypto.randomUUID();
const ENCOUNTER_ID_1 = crypto.randomUUID();
const ENCOUNTER_ID_2 = crypto.randomUUID();
const ENCOUNTER_ID_3 = crypto.randomUUID();

// ---------------------------------------------------------------------------
// Mock factories
// ---------------------------------------------------------------------------

function makeSccRow(overrides: Partial<SccImportRow> = {}): SccImportRow {
  return {
    rowNumber: 1,
    claimId: CLAIM_ID_1,
    patientUli: '123456782',
    encounterDate: '2026-02-16',
    serviceCode: '03.04A',
    classification: 'VALID',
    ...overrides,
  };
}

function makeEncounter(overrides: Partial<EncounterRow> = {}): EncounterRow {
  return {
    encounterId: ENCOUNTER_ID_1,
    shiftId: SHIFT_ID,
    providerId: PROVIDER_A,
    phn: '123456782',
    phnIsPartial: false,
    phnCaptureMethod: 'BARCODE',
    healthServiceCode: '03.04A',
    encounterTimestamp: new Date('2026-02-16T10:30:00'),
    freeTextTag: null,
    matchedClaimId: null,
    ...overrides,
  };
}

function makeReconcResult(overrides: Partial<ReconciliationResult> = {}): ReconciliationResult {
  return {
    batchId: BATCH_ID,
    shiftId: SHIFT_ID,
    status: 'PENDING',
    matches: [],
    summary: {
      totalSccRows: 0,
      totalEncounters: 0,
      fullMatches: 0,
      unmatchedScc: 0,
      unmatchedEncounters: 0,
      shiftOnly: 0,
      needsResolution: 0,
    },
    ...overrides,
  };
}

function makeDeps(overrides: Partial<ReconciliationDeps> = {}): ReconciliationDeps {
  return {
    getImportBatch: vi.fn().mockResolvedValue({
      importBatchId: BATCH_ID,
      physicianId: PROVIDER_A,
      status: 'COMPLETED',
      confirmationStatus: 'CONFIRMED',
    }),
    getImportBatchRows: vi.fn().mockResolvedValue([makeSccRow()]),
    findMatchingShift: vi.fn().mockResolvedValue({
      shiftId: SHIFT_ID,
      providerId: PROVIDER_A,
      locationId: crypto.randomUUID(),
      shiftStart: new Date('2026-02-16T08:00:00'),
      shiftEnd: new Date('2026-02-16T16:00:00'),
    }),
    getShiftEncounters: vi.fn().mockResolvedValue([makeEncounter()]),
    updateClaimTimestamp: vi.fn().mockResolvedValue(undefined),
    linkEncounterToClaim: vi.fn().mockResolvedValue(undefined),
    emitNotification: vi.fn().mockResolvedValue(undefined),
    auditLog: vi.fn().mockResolvedValue(undefined),
    saveReconciliationResult: vi.fn().mockResolvedValue(undefined),
    getReconciliationResult: vi.fn().mockResolvedValue(makeReconcResult()),
    updateReconciliationStatus: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  };
}

// ============================================================================
// detectModifierEligibility
// ============================================================================

describe('detectModifierEligibility', () => {
  it('should return null for standard weekday hours (10:30)', () => {
    const ts = new Date('2026-02-16T10:30:00'); // Monday 10:30
    expect(detectModifierEligibility(ts)).toBeNull();
  });

  it('should return AFHR for weekday evening (18:00)', () => {
    const ts = new Date('2026-02-16T18:00:00'); // Monday 18:00
    expect(detectModifierEligibility(ts)).toBe('AFHR');
  });

  it('should return AFHR for weekday 22:59', () => {
    const ts = new Date('2026-02-16T22:59:00');
    expect(detectModifierEligibility(ts)).toBe('AFHR');
  });

  it('should return NGHT for weekday 23:00', () => {
    const ts = new Date('2026-02-16T23:00:00');
    expect(detectModifierEligibility(ts)).toBe('NGHT');
  });

  it('should return NGHT for weekday 03:00', () => {
    const ts = new Date('2026-02-17T03:00:00'); // Tuesday 03:00
    expect(detectModifierEligibility(ts)).toBe('NGHT');
  });

  it('should return NGHT for weekday 07:59', () => {
    const ts = new Date('2026-02-16T07:59:00');
    expect(detectModifierEligibility(ts)).toBe('NGHT');
  });

  it('should return WKND for Saturday', () => {
    const ts = new Date('2026-02-21T10:00:00'); // Saturday
    expect(detectModifierEligibility(ts)).toBe('WKND');
  });

  it('should return WKND for Sunday', () => {
    const ts = new Date('2026-02-15T14:00:00'); // Sunday
    expect(detectModifierEligibility(ts)).toBe('WKND');
  });

  it('should return null for weekday 08:00 boundary', () => {
    const ts = new Date('2026-02-16T08:00:00');
    expect(detectModifierEligibility(ts)).toBeNull();
  });

  it('should return null for weekday 16:59', () => {
    const ts = new Date('2026-02-16T16:59:00');
    expect(detectModifierEligibility(ts)).toBeNull();
  });
});

// ============================================================================
// partialPhnMatches
// ============================================================================

describe('partialPhnMatches', () => {
  it('should match when last 4 digits match', () => {
    expect(partialPhnMatches('6782', '123456782')).toBe(true);
  });

  it('should not match when last 4 digits differ', () => {
    expect(partialPhnMatches('9999', '123456782')).toBe(false);
  });

  it('should return false for empty inputs', () => {
    expect(partialPhnMatches('', '123456782')).toBe(false);
    expect(partialPhnMatches('6782', '')).toBe(false);
  });

  it('should return false for non-4-digit partial', () => {
    expect(partialPhnMatches('67', '123456782')).toBe(false);
  });
});

// ============================================================================
// matchRows
// ============================================================================

describe('matchRows', () => {
  it('should produce FULL_MATCH when PHN + date match', () => {
    const sccRows = [makeSccRow()];
    const encounters = [makeEncounter()];

    const matches = matchRows(sccRows, encounters);
    expect(matches).toHaveLength(1);
    expect(matches[0].category).toBe('FULL_MATCH');
    expect(matches[0].claimId).toBe(CLAIM_ID_1);
    expect(matches[0].confidence).toBe(1.0);
    expect(matches[0].inferredServiceTime).toBeDefined();
  });

  it('should produce UNMATCHED_SCC when no encounter matches', () => {
    const sccRows = [makeSccRow()];
    const encounters: EncounterRow[] = [];

    const matches = matchRows(sccRows, encounters);
    expect(matches).toHaveLength(1);
    expect(matches[0].category).toBe('UNMATCHED_SCC');
    expect(matches[0].resolutionNeeded).toBe('TIME');
  });

  it('should produce UNMATCHED_ENCOUNTER for encounter with no SCC row', () => {
    const sccRows: SccImportRow[] = [];
    const encounters = [makeEncounter()];

    const matches = matchRows(sccRows, encounters);
    expect(matches).toHaveLength(1);
    expect(matches[0].category).toBe('UNMATCHED_ENCOUNTER');
  });

  it('should handle partial PHN unique match', () => {
    const sccRows = [makeSccRow({ patientUli: '123456782' })];
    const encounters = [
      makeEncounter({
        phn: '6782',
        phnIsPartial: true,
        phnCaptureMethod: 'LAST_FOUR',
      }),
    ];

    const matches = matchRows(sccRows, encounters);
    expect(matches).toHaveLength(1);
    expect(matches[0].category).toBe('FULL_MATCH');
    expect(matches[0].confidence).toBe(0.8);
  });

  it('should flag PARTIAL_PHN resolution needed for ambiguous match', () => {
    const sccRows = [
      makeSccRow({ rowNumber: 1, claimId: CLAIM_ID_1, patientUli: '123456782' }),
    ];
    const encounters = [
      makeEncounter({
        encounterId: ENCOUNTER_ID_1,
        phn: '6782',
        phnIsPartial: true,
      }),
      makeEncounter({
        encounterId: ENCOUNTER_ID_2,
        phn: '6782',
        phnIsPartial: true,
        encounterTimestamp: new Date('2026-02-16T11:00:00'),
      }),
    ];

    const matches = matchRows(sccRows, encounters);
    // Should get UNMATCHED_SCC with PARTIAL_PHN resolution + 2 UNMATCHED_ENCOUNTER
    const partial = matches.find((m) => m.resolutionNeeded === 'PARTIAL_PHN');
    expect(partial).toBeDefined();
    expect(partial!.category).toBe('UNMATCHED_SCC');
  });

  it('should not double-match an encounter', () => {
    const sccRows = [
      makeSccRow({ rowNumber: 1, claimId: CLAIM_ID_1, patientUli: '123456782' }),
      makeSccRow({ rowNumber: 2, claimId: CLAIM_ID_2, patientUli: '123456782' }),
    ];
    const encounters = [makeEncounter()];

    const matches = matchRows(sccRows, encounters);
    const fullMatches = matches.filter((m) => m.category === 'FULL_MATCH');
    expect(fullMatches).toHaveLength(1);
    // Second SCC row should be UNMATCHED_SCC
    const unmatchedScc = matches.filter((m) => m.category === 'UNMATCHED_SCC');
    expect(unmatchedScc).toHaveLength(1);
  });

  it('should not match when dates differ', () => {
    const sccRows = [makeSccRow({ encounterDate: '2026-02-17' })];
    const encounters = [
      makeEncounter({ encounterTimestamp: new Date('2026-02-16T10:30:00') }),
    ];

    const matches = matchRows(sccRows, encounters);
    expect(matches.some((m) => m.category === 'FULL_MATCH')).toBe(false);
  });

  it('should detect AFHR modifier for evening encounters', () => {
    const sccRows = [makeSccRow()];
    const encounters = [
      makeEncounter({ encounterTimestamp: new Date('2026-02-16T19:30:00') }),
    ];

    const matches = matchRows(sccRows, encounters);
    expect(matches[0].modifiers).toEqual(['AFHR']);
  });

  it('should detect NGHT modifier for night encounters', () => {
    const sccRows = [makeSccRow()];
    const encounters = [
      makeEncounter({ encounterTimestamp: new Date('2026-02-16T23:30:00') }),
    ];

    const matches = matchRows(sccRows, encounters);
    expect(matches[0].modifiers).toEqual(['NGHT']);
  });

  it('should handle multi-row same timestamp matching', () => {
    const sccRows = [
      makeSccRow({ rowNumber: 1, claimId: CLAIM_ID_1, patientUli: '111111118' }),
      makeSccRow({ rowNumber: 2, claimId: CLAIM_ID_2, patientUli: '222222226' }),
      makeSccRow({ rowNumber: 3, claimId: CLAIM_ID_3, patientUli: '333333334' }),
    ];
    const encounters = [
      makeEncounter({ encounterId: ENCOUNTER_ID_1, phn: '111111118' }),
      makeEncounter({ encounterId: ENCOUNTER_ID_2, phn: '222222226', encounterTimestamp: new Date('2026-02-16T11:00:00') }),
      makeEncounter({ encounterId: ENCOUNTER_ID_3, phn: '333333334', encounterTimestamp: new Date('2026-02-16T12:00:00') }),
    ];

    const matches = matchRows(sccRows, encounters);
    const fullMatches = matches.filter((m) => m.category === 'FULL_MATCH');
    expect(fullMatches).toHaveLength(3);
  });
});

// ============================================================================
// reconcileImportWithShift
// ============================================================================

describe('reconcileImportWithShift', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should reconcile batch with matching shift and encounters', async () => {
    const deps = makeDeps();
    const result = await reconcileImportWithShift(deps, PROVIDER_A, BATCH_ID);

    expect(result.batchId).toBe(BATCH_ID);
    expect(result.shiftId).toBe(SHIFT_ID);
    expect(result.status).toBe('PENDING');
    expect(result.summary.fullMatches).toBe(1);
    expect(deps.saveReconciliationResult).toHaveBeenCalled();
    expect(deps.auditLog).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'reconciliation.completed' }),
    );
  });

  it('should produce SHIFT_ONLY when no matching shift found', async () => {
    const deps = makeDeps({
      findMatchingShift: vi.fn().mockResolvedValue(null),
    });

    const result = await reconcileImportWithShift(deps, PROVIDER_A, BATCH_ID);

    expect(result.shiftId).toBeNull();
    expect(result.summary.shiftOnly).toBe(1);
    expect(result.summary.fullMatches).toBe(0);
  });

  it('should throw when batch not found', async () => {
    const deps = makeDeps({
      getImportBatch: vi.fn().mockResolvedValue(null),
    });

    await expect(
      reconcileImportWithShift(deps, PROVIDER_A, BATCH_ID),
    ).rejects.toThrow(ReconciliationError);
  });

  it('should throw when no rows in batch', async () => {
    const deps = makeDeps({
      getImportBatchRows: vi.fn().mockResolvedValue([]),
    });

    await expect(
      reconcileImportWithShift(deps, PROVIDER_A, BATCH_ID),
    ).rejects.toThrow(ReconciliationError);
  });
});

// ============================================================================
// confirmReconciliation
// ============================================================================

describe('confirmReconciliation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should apply inferred times and modifiers to full matches', async () => {
    const reconcResult = makeReconcResult({
      matches: [
        {
          category: 'FULL_MATCH',
          sccRow: makeSccRow(),
          encounter: makeEncounter(),
          claimId: CLAIM_ID_1,
          inferredServiceTime: '2026-02-16T10:30:00.000Z',
          modifiers: undefined,
          confidence: 1.0,
        },
      ],
      summary: { totalSccRows: 1, totalEncounters: 1, fullMatches: 1, unmatchedScc: 0, unmatchedEncounters: 0, shiftOnly: 0, needsResolution: 0 },
    });

    const deps = makeDeps({
      getReconciliationResult: vi.fn().mockResolvedValue(reconcResult),
    });

    const result = await confirmReconciliation(deps, PROVIDER_A, BATCH_ID);

    expect(result.confirmed).toBe(1);
    expect(result.missed).toBe(0);
    expect(deps.updateClaimTimestamp).toHaveBeenCalledWith(
      CLAIM_ID_1,
      PROVIDER_A,
      expect.objectContaining({ inferredServiceTime: '2026-02-16T10:30:00.000Z' }),
    );
    expect(deps.linkEncounterToClaim).toHaveBeenCalledWith(
      ENCOUNTER_ID_1,
      CLAIM_ID_1,
    );
  });

  it('should emit missed billing notifications for unmatched encounters', async () => {
    const reconcResult = makeReconcResult({
      matches: [
        {
          category: 'UNMATCHED_ENCOUNTER',
          encounter: makeEncounter({ freeTextTag: 'chest pain' }),
          confidence: 0,
        },
      ],
      summary: { totalSccRows: 0, totalEncounters: 1, fullMatches: 0, unmatchedScc: 0, unmatchedEncounters: 1, shiftOnly: 0, needsResolution: 0 },
    });

    const deps = makeDeps({
      getReconciliationResult: vi.fn().mockResolvedValue(reconcResult),
    });

    const result = await confirmReconciliation(deps, PROVIDER_A, BATCH_ID);

    expect(result.missed).toBe(1);
    expect(deps.emitNotification).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'MISSED_BILLING_DETECTED',
        physicianId: PROVIDER_A,
      }),
    );
  });

  it('should throw when result not found', async () => {
    const deps = makeDeps({
      getReconciliationResult: vi.fn().mockResolvedValue(null),
    });

    await expect(
      confirmReconciliation(deps, PROVIDER_A, BATCH_ID),
    ).rejects.toThrow(ReconciliationError);
  });

  it('should throw when already confirmed', async () => {
    const deps = makeDeps({
      getReconciliationResult: vi.fn().mockResolvedValue(
        makeReconcResult({ status: 'CONFIRMED' }),
      ),
    });

    await expect(
      confirmReconciliation(deps, PROVIDER_A, BATCH_ID),
    ).rejects.toThrow(ReconciliationError);
  });

  it('should update status to CONFIRMED after success', async () => {
    const reconcResult = makeReconcResult({ matches: [] });
    const deps = makeDeps({
      getReconciliationResult: vi.fn().mockResolvedValue(reconcResult),
    });

    await confirmReconciliation(deps, PROVIDER_A, BATCH_ID);

    expect(deps.updateReconciliationStatus).toHaveBeenCalledWith(
      BATCH_ID,
      PROVIDER_A,
      'CONFIRMED',
    );
  });
});

// ============================================================================
// resolveUnmatchedTime
// ============================================================================

describe('resolveUnmatchedTime', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should resolve unmatched SCC row with provided time', async () => {
    const reconcResult = makeReconcResult({
      matches: [
        {
          category: 'UNMATCHED_SCC',
          sccRow: makeSccRow(),
          claimId: CLAIM_ID_1,
          confidence: 0,
          resolutionNeeded: 'TIME',
        },
      ],
    });

    const deps = makeDeps({
      getReconciliationResult: vi.fn().mockResolvedValue(reconcResult),
    });

    await resolveUnmatchedTime(
      deps,
      PROVIDER_A,
      BATCH_ID,
      CLAIM_ID_1,
      '2026-02-16T19:30:00.000Z',
    );

    expect(deps.updateClaimTimestamp).toHaveBeenCalledWith(
      CLAIM_ID_1,
      PROVIDER_A,
      expect.objectContaining({
        inferredServiceTime: '2026-02-16T19:30:00.000Z',
        modifiers: ['AFHR'],
      }),
    );
    // Verify the match was updated
    expect(reconcResult.matches[0].category).toBe('FULL_MATCH');
    expect(reconcResult.matches[0].confidence).toBe(0.9);
  });

  it('should throw when result not found', async () => {
    const deps = makeDeps({
      getReconciliationResult: vi.fn().mockResolvedValue(null),
    });

    await expect(
      resolveUnmatchedTime(deps, PROVIDER_A, BATCH_ID, CLAIM_ID_1, '2026-02-16T10:00:00Z'),
    ).rejects.toThrow(ReconciliationError);
  });

  it('should throw when no matching unresolved claim', async () => {
    const deps = makeDeps({
      getReconciliationResult: vi.fn().mockResolvedValue(
        makeReconcResult({ matches: [] }),
      ),
    });

    await expect(
      resolveUnmatchedTime(deps, PROVIDER_A, BATCH_ID, CLAIM_ID_1, '2026-02-16T10:00:00Z'),
    ).rejects.toThrow(ReconciliationError);
  });

  it('should detect NGHT modifier for night time resolution', async () => {
    const reconcResult = makeReconcResult({
      matches: [
        {
          category: 'UNMATCHED_SCC',
          sccRow: makeSccRow(),
          claimId: CLAIM_ID_1,
          confidence: 0,
          resolutionNeeded: 'TIME',
        },
      ],
    });

    const deps = makeDeps({
      getReconciliationResult: vi.fn().mockResolvedValue(reconcResult),
    });

    await resolveUnmatchedTime(
      deps,
      PROVIDER_A,
      BATCH_ID,
      CLAIM_ID_1,
      '2026-02-17T02:00:00.000Z',
    );

    expect(deps.updateClaimTimestamp).toHaveBeenCalledWith(
      CLAIM_ID_1,
      PROVIDER_A,
      expect.objectContaining({ modifiers: ['NGHT'] }),
    );
  });
});

// ============================================================================
// resolvePartialPhn
// ============================================================================

describe('resolvePartialPhn', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should resolve partial PHN match by linking encounter to claim', async () => {
    const reconcResult = makeReconcResult({
      matches: [
        {
          category: 'UNMATCHED_SCC',
          sccRow: makeSccRow(),
          claimId: CLAIM_ID_1,
          confidence: 0,
          resolutionNeeded: 'PARTIAL_PHN',
        },
        {
          category: 'UNMATCHED_ENCOUNTER',
          encounter: makeEncounter({ encounterId: ENCOUNTER_ID_1 }),
          confidence: 0,
        },
      ],
    });

    const deps = makeDeps({
      getReconciliationResult: vi.fn().mockResolvedValue(reconcResult),
    });

    await resolvePartialPhn(
      deps,
      PROVIDER_A,
      BATCH_ID,
      ENCOUNTER_ID_1,
      CLAIM_ID_1,
    );

    expect(deps.linkEncounterToClaim).toHaveBeenCalledWith(
      ENCOUNTER_ID_1,
      CLAIM_ID_1,
    );
    expect(deps.updateClaimTimestamp).toHaveBeenCalled();
    expect(reconcResult.matches[0].category).toBe('FULL_MATCH');
    expect(reconcResult.matches[0].confidence).toBe(0.85);
  });

  it('should throw when result not found', async () => {
    const deps = makeDeps({
      getReconciliationResult: vi.fn().mockResolvedValue(null),
    });

    await expect(
      resolvePartialPhn(deps, PROVIDER_A, BATCH_ID, ENCOUNTER_ID_1, CLAIM_ID_1),
    ).rejects.toThrow(ReconciliationError);
  });

  it('should throw when no matching partial PHN resolution needed', async () => {
    const deps = makeDeps({
      getReconciliationResult: vi.fn().mockResolvedValue(
        makeReconcResult({ matches: [] }),
      ),
    });

    await expect(
      resolvePartialPhn(deps, PROVIDER_A, BATCH_ID, ENCOUNTER_ID_1, CLAIM_ID_1),
    ).rejects.toThrow(ReconciliationError);
  });
});
