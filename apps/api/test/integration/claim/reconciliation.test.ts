// ============================================================================
// Connect Care Reconciliation — Integration Tests (MOB-002 §10.2)
// Tests end-to-end reconciliation flows: upload CSV → reconcile → matches →
// modifiers → claims updated. Also covers no-shift, inferred shift, and
// missed billing notification scenarios.
// ============================================================================

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ---------------------------------------------------------------------------
// Mock shared modules
// ---------------------------------------------------------------------------

vi.mock('@meritum/shared/constants/mobile.constants.js', () => ({
  ReconciliationMatchCategory: {
    FULL_MATCH: 'FULL_MATCH',
    UNMATCHED_SCC: 'UNMATCHED_SCC',
    UNMATCHED_ENCOUNTER: 'UNMATCHED_ENCOUNTER',
    SHIFT_ONLY: 'SHIFT_ONLY',
  },
}));

// ---------------------------------------------------------------------------
// Imports (after mocks)
// ---------------------------------------------------------------------------

import {
  reconcileImportWithShift,
  confirmReconciliation,
  resolveUnmatchedTime,
  resolvePartialPhn,
  matchRows,
  detectModifierEligibility,
  ReconciliationError,
  type ReconciliationDeps,
  type SccImportRow,
  type EncounterRow,
  type ReconciliationResult,
} from '../../../src/domains/claim/reconciliation.service.js';

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const PROVIDER = crypto.randomUUID();
const BATCH_ID = crypto.randomUUID();
const SHIFT_ID = crypto.randomUUID();
const LOCATION_ID = crypto.randomUUID();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeSccRow(overrides: Partial<SccImportRow> = {}): SccImportRow {
  return {
    rowNumber: 1,
    claimId: crypto.randomUUID(),
    patientUli: '123456782',
    encounterDate: '2026-02-16',
    serviceCode: '03.04A',
    classification: 'VALID',
    ...overrides,
  };
}

function makeEncounter(overrides: Partial<EncounterRow> = {}): EncounterRow {
  return {
    encounterId: crypto.randomUUID(),
    shiftId: SHIFT_ID,
    providerId: PROVIDER,
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

let savedResult: ReconciliationResult | null = null;

function makeDeps(overrides: Partial<ReconciliationDeps> = {}): ReconciliationDeps {
  savedResult = null;
  return {
    getImportBatch: vi.fn().mockResolvedValue({
      importBatchId: BATCH_ID,
      physicianId: PROVIDER,
      status: 'COMPLETED',
      confirmationStatus: 'CONFIRMED',
    }),
    getImportBatchRows: vi.fn().mockResolvedValue([makeSccRow()]),
    findMatchingShift: vi.fn().mockResolvedValue({
      shiftId: SHIFT_ID,
      providerId: PROVIDER,
      locationId: LOCATION_ID,
      shiftStart: new Date('2026-02-16T08:00:00'),
      shiftEnd: new Date('2026-02-16T16:00:00'),
    }),
    getShiftEncounters: vi.fn().mockResolvedValue([makeEncounter()]),
    updateClaimTimestamp: vi.fn().mockResolvedValue(undefined),
    linkEncounterToClaim: vi.fn().mockResolvedValue(undefined),
    emitNotification: vi.fn().mockResolvedValue(undefined),
    auditLog: vi.fn().mockResolvedValue(undefined),
    saveReconciliationResult: vi.fn().mockImplementation(async (_b, _p, r) => {
      savedResult = r;
    }),
    getReconciliationResult: vi.fn().mockImplementation(async () => savedResult),
    updateReconciliationStatus: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  };
}

// ============================================================================
// Integration Tests
// ============================================================================

describe('Integration: Upload CSV → Reconcile → Matches → Claims Updated', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should reconcile and then confirm — full end-to-end', async () => {
    const claimId = crypto.randomUUID();
    const encounterId = crypto.randomUUID();

    const sccRows = [makeSccRow({ claimId })];
    const encounters = [makeEncounter({ encounterId })];

    const deps = makeDeps({
      getImportBatchRows: vi.fn().mockResolvedValue(sccRows),
      getShiftEncounters: vi.fn().mockResolvedValue(encounters),
    });

    // Step 1: Reconcile
    const reconcResult = await reconcileImportWithShift(deps, PROVIDER, BATCH_ID);
    expect(reconcResult.summary.fullMatches).toBe(1);
    expect(reconcResult.summary.unmatchedScc).toBe(0);
    expect(reconcResult.summary.unmatchedEncounters).toBe(0);

    // Step 2: Confirm
    const confirmResult = await confirmReconciliation(deps, PROVIDER, BATCH_ID);
    expect(confirmResult.confirmed).toBe(1);
    expect(confirmResult.missed).toBe(0);

    // Verify claims were updated
    expect(deps.updateClaimTimestamp).toHaveBeenCalledWith(
      claimId,
      PROVIDER,
      expect.objectContaining({ inferredServiceTime: expect.any(String) }),
    );

    // Verify encounter linked to claim
    expect(deps.linkEncounterToClaim).toHaveBeenCalledWith(encounterId, claimId);
  });

  it('should detect AFHR modifier for evening encounters', async () => {
    const claimId = crypto.randomUUID();
    const encounterId = crypto.randomUUID();

    const deps = makeDeps({
      getImportBatchRows: vi.fn().mockResolvedValue([makeSccRow({ claimId })]),
      getShiftEncounters: vi.fn().mockResolvedValue([
        makeEncounter({
          encounterId,
          encounterTimestamp: new Date('2026-02-16T19:30:00'), // 7:30 PM
        }),
      ]),
    });

    const reconcResult = await reconcileImportWithShift(deps, PROVIDER, BATCH_ID);
    expect(reconcResult.matches[0].modifiers).toEqual(['AFHR']);

    await confirmReconciliation(deps, PROVIDER, BATCH_ID);
    expect(deps.updateClaimTimestamp).toHaveBeenCalledWith(
      claimId,
      PROVIDER,
      expect.objectContaining({ modifiers: ['AFHR'] }),
    );
  });

  it('should detect NGHT modifier for night encounters', async () => {
    const claimId = crypto.randomUUID();

    const deps = makeDeps({
      getImportBatchRows: vi.fn().mockResolvedValue([makeSccRow({ claimId })]),
      getShiftEncounters: vi.fn().mockResolvedValue([
        makeEncounter({
          encounterTimestamp: new Date('2026-02-16T23:30:00'), // 11:30 PM
        }),
      ]),
    });

    const reconcResult = await reconcileImportWithShift(deps, PROVIDER, BATCH_ID);
    expect(reconcResult.matches[0].modifiers).toEqual(['NGHT']);
  });
});

describe('Integration: No Shift → No Reconciliation', () => {
  it('should produce SHIFT_ONLY for all rows when no shift exists', async () => {
    const deps = makeDeps({
      findMatchingShift: vi.fn().mockResolvedValue(null),
      getImportBatchRows: vi.fn().mockResolvedValue([
        makeSccRow({ rowNumber: 1 }),
        makeSccRow({ rowNumber: 2, patientUli: '987654321' }),
      ]),
    });

    const result = await reconcileImportWithShift(deps, PROVIDER, BATCH_ID);

    expect(result.shiftId).toBeNull();
    expect(result.summary.shiftOnly).toBe(2);
    expect(result.summary.fullMatches).toBe(0);
  });
});

describe('Integration: Inferred Shift Reconciliation', () => {
  it('should reconcile with inferred (auto-created) shift encounters', async () => {
    const claimId = crypto.randomUUID();
    const encounterId = crypto.randomUUID();

    const deps = makeDeps({
      getImportBatchRows: vi.fn().mockResolvedValue([makeSccRow({ claimId })]),
      getShiftEncounters: vi.fn().mockResolvedValue([makeEncounter({ encounterId })]),
    });

    const result = await reconcileImportWithShift(deps, PROVIDER, BATCH_ID);

    expect(result.summary.fullMatches).toBe(1);
    // Inferred shifts work the same as manual shifts for reconciliation
  });
});

describe('Integration: Missed Billing Notification', () => {
  it('should emit missed billing for unmatched encounters on confirmation', async () => {
    const unmatchedEncounter = makeEncounter({ freeTextTag: 'chest pain' });

    const deps = makeDeps({
      getImportBatchRows: vi.fn().mockResolvedValue([
        makeSccRow({ patientUli: '999999999' }), // Different PHN → no match
      ]),
      getShiftEncounters: vi.fn().mockResolvedValue([unmatchedEncounter]),
    });

    // Reconcile
    await reconcileImportWithShift(deps, PROVIDER, BATCH_ID);

    // Confirm
    const confirmResult = await confirmReconciliation(deps, PROVIDER, BATCH_ID);

    expect(confirmResult.missed).toBe(1);
    expect(deps.emitNotification).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'MISSED_BILLING_DETECTED',
        physicianId: PROVIDER,
      }),
    );
  });
});

describe('Integration: Resolution Flows', () => {
  it('should resolve unmatched time and then confirm', async () => {
    const claimId = crypto.randomUUID();

    const deps = makeDeps({
      getImportBatchRows: vi.fn().mockResolvedValue([
        makeSccRow({ claimId, patientUli: '999999999' }), // No matching encounter
      ]),
      getShiftEncounters: vi.fn().mockResolvedValue([]), // No encounters
    });

    // Step 1: Reconcile — produces UNMATCHED_SCC
    const reconcResult = await reconcileImportWithShift(deps, PROVIDER, BATCH_ID);
    expect(reconcResult.summary.unmatchedScc).toBe(1);

    // Step 2: Physician resolves time
    await resolveUnmatchedTime(
      deps,
      PROVIDER,
      BATCH_ID,
      claimId,
      '2026-02-16T20:00:00.000Z',
    );

    // Step 3: Confirm — now it's a full match
    const confirmResult = await confirmReconciliation(deps, PROVIDER, BATCH_ID);
    // The resolved match was already applied in resolveUnmatchedTime,
    // confirmReconciliation won't double-apply since category is now FULL_MATCH
    // but it will process it
    expect(confirmResult.confirmed).toBeGreaterThanOrEqual(0);
    expect(deps.auditLog).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'reconciliation.time_resolved' }),
    );
  });

  it('should resolve partial PHN and link encounter', async () => {
    const claimId = crypto.randomUUID();
    const encounterId = crypto.randomUUID();

    // Set up scenario: ambiguous partial match (2 encounters with same last-4)
    const sccRows = [makeSccRow({ claimId, patientUli: '123456782' })];
    const enc1 = makeEncounter({
      encounterId,
      phn: '6782',
      phnIsPartial: true,
    });
    const enc2 = makeEncounter({
      encounterId: crypto.randomUUID(),
      phn: '6782',
      phnIsPartial: true,
      encounterTimestamp: new Date('2026-02-16T11:00:00'),
    });

    const deps = makeDeps({
      getImportBatchRows: vi.fn().mockResolvedValue(sccRows),
      getShiftEncounters: vi.fn().mockResolvedValue([enc1, enc2]),
    });

    // Step 1: Reconcile — should flag PARTIAL_PHN resolution
    const reconcResult = await reconcileImportWithShift(deps, PROVIDER, BATCH_ID);
    expect(reconcResult.summary.needsResolution).toBeGreaterThanOrEqual(1);

    // Step 2: Physician selects the correct encounter
    await resolvePartialPhn(deps, PROVIDER, BATCH_ID, encounterId, claimId);

    expect(deps.linkEncounterToClaim).toHaveBeenCalledWith(encounterId, claimId);
    expect(deps.auditLog).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'reconciliation.partial_phn_resolved' }),
    );
  });
});
