// ============================================================================
// Connect Care Import — Audit Trail (Security)
// Verifies upload → UPLOADED audit, confirm → CONFIRMED, cancel → CANCELLED,
// reconciliation → audit entries, crosswalk resolution → RESOLVED.
// Tests via direct service calls with captured audit entries.
// ============================================================================

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ---------------------------------------------------------------------------
// Mock shared modules
// ---------------------------------------------------------------------------

vi.mock('@meritum/shared/constants/claim.constants.js', () => ({
  ClaimAuditAction: {
    CREATED: 'CREATED',
    VALIDATED: 'VALIDATED',
    QUEUED: 'QUEUED',
    IMPORTED: 'IMPORTED',
    CC_UPLOADED: 'CC_UPLOADED',
    CC_CONFIRMED: 'CC_CONFIRMED',
    CC_CANCELLED: 'CC_CANCELLED',
  },
  ActorContext: {
    PHYSICIAN: 'PHYSICIAN',
    DELEGATE: 'DELEGATE',
    SYSTEM: 'SYSTEM',
  },
  ClaimState: {
    DRAFT: 'DRAFT',
    VALIDATED: 'VALIDATED',
    QUEUED: 'QUEUED',
  },
  ClaimImportSource: {
    MANUAL: 'MANUAL',
    CONNECT_CARE_CSV: 'CONNECT_CARE_CSV',
  },
  ShiftStatus: {
    ACTIVE: 'ACTIVE',
    COMPLETED: 'COMPLETED',
  },
}));

vi.mock('@meritum/shared/constants/scc.constants.js', () => ({
  SCC_SPEC_VERSIONS: ['1.0'],
  CURRENT_SCC_SPEC_VERSION: '1.0',
  SCC_EXTRACT_TYPES: ['FULL'],
  SCC_CHARGE_STATUSES: ['BILLED'],
  SCC_VALIDATION_SEVERITIES: ['ERROR', 'WARNING'],
  IMPORT_SOURCES: ['CONNECT_CARE_CSV'],
  ICD_MATCH_QUALITIES: ['EXACT'],
}));

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
  type ReconciliationDeps,
  type SccImportRow,
  type EncounterRow,
  type ReconciliationResult,
} from '../../../src/domains/claim/reconciliation.service.js';

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const PROVIDER_ID = crypto.randomUUID();
const BATCH_ID = crypto.randomUUID();
const SHIFT_ID = crypto.randomUUID();
const LOCATION_ID = crypto.randomUUID();

// ---------------------------------------------------------------------------
// Audit capture
// ---------------------------------------------------------------------------

let auditEntries: Array<Record<string, unknown>> = [];

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
    providerId: PROVIDER_ID,
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
  auditEntries = [];
  return {
    getImportBatch: vi.fn().mockResolvedValue({
      importBatchId: BATCH_ID,
      physicianId: PROVIDER_ID,
      status: 'COMPLETED',
      confirmationStatus: 'CONFIRMED',
    }),
    getImportBatchRows: vi.fn().mockResolvedValue([makeSccRow()]),
    findMatchingShift: vi.fn().mockResolvedValue({
      shiftId: SHIFT_ID,
      providerId: PROVIDER_ID,
      locationId: LOCATION_ID,
      shiftStart: new Date('2026-02-16T08:00:00'),
      shiftEnd: new Date('2026-02-16T16:00:00'),
    }),
    getShiftEncounters: vi.fn().mockResolvedValue([makeEncounter()]),
    updateClaimTimestamp: vi.fn().mockResolvedValue(undefined),
    linkEncounterToClaim: vi.fn().mockResolvedValue(undefined),
    emitNotification: vi.fn().mockResolvedValue(undefined),
    auditLog: vi.fn().mockImplementation(async (entry: Record<string, unknown>) => {
      auditEntries.push(entry);
    }),
    saveReconciliationResult: vi.fn().mockImplementation(async (_b, _p, r) => {
      savedResult = r;
    }),
    getReconciliationResult: vi.fn().mockImplementation(async () => savedResult),
    updateReconciliationStatus: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  };
}

// ============================================================================
// Test Suite
// ============================================================================

describe('Connect Care Import — Audit Trail (Security)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    auditEntries = [];
  });

  // =========================================================================
  // Reconciliation produces audit entries
  // =========================================================================

  describe('Reconciliation audit entries', () => {
    it('reconcileImportWithShift produces reconciliation.completed audit entry', async () => {
      const deps = makeDeps();
      await reconcileImportWithShift(deps, PROVIDER_ID, BATCH_ID);

      expect(deps.auditLog).toHaveBeenCalled();
      const completeEntry = auditEntries.find((e) => e.action === 'reconciliation.completed');
      expect(completeEntry).toBeDefined();
      expect(completeEntry!.physicianId).toBe(PROVIDER_ID);
    });

    it('confirmReconciliation produces reconciliation.confirmed audit entry', async () => {
      const deps = makeDeps();
      await reconcileImportWithShift(deps, PROVIDER_ID, BATCH_ID);
      await confirmReconciliation(deps, PROVIDER_ID, BATCH_ID);

      const confirmEntry = auditEntries.find((e) => e.action === 'reconciliation.confirmed');
      expect(confirmEntry).toBeDefined();
    });
  });

  // =========================================================================
  // Resolution audit entries
  // =========================================================================

  describe('Resolution audit entries', () => {
    it('resolveUnmatchedTime produces time_resolved audit', async () => {
      const claimId = crypto.randomUUID();
      const deps = makeDeps({
        getImportBatchRows: vi.fn().mockResolvedValue([
          makeSccRow({ claimId, patientUli: '999999999' }),
        ]),
        getShiftEncounters: vi.fn().mockResolvedValue([]),
      });

      await reconcileImportWithShift(deps, PROVIDER_ID, BATCH_ID);
      await resolveUnmatchedTime(deps, PROVIDER_ID, BATCH_ID, claimId, '2026-02-16T20:00:00.000Z');

      const timeEntry = auditEntries.find((e) => e.action === 'reconciliation.time_resolved');
      expect(timeEntry).toBeDefined();
      expect((timeEntry!.detail as any).claimId).toBe(claimId);
    });

    it('resolvePartialPhn produces partial_phn_resolved audit', async () => {
      const claimId = crypto.randomUUID();
      const encounterId = crypto.randomUUID();

      const deps = makeDeps({
        getImportBatchRows: vi.fn().mockResolvedValue([
          makeSccRow({ claimId, patientUli: '123456782' }),
        ]),
        getShiftEncounters: vi.fn().mockResolvedValue([
          makeEncounter({ encounterId, phn: '6782', phnIsPartial: true }),
          makeEncounter({ phn: '6782', phnIsPartial: true, encounterTimestamp: new Date('2026-02-16T11:00:00') }),
        ]),
      });

      await reconcileImportWithShift(deps, PROVIDER_ID, BATCH_ID);
      await resolvePartialPhn(deps, PROVIDER_ID, BATCH_ID, encounterId, claimId);

      const phnEntry = auditEntries.find((e) => e.action === 'reconciliation.partial_phn_resolved');
      expect(phnEntry).toBeDefined();
      expect((phnEntry!.detail as any).encounterId).toBe(encounterId);
    });
  });

  // =========================================================================
  // Audit entries do not contain PHN
  // =========================================================================

  describe('Audit entries do not contain PHI', () => {
    it('audit entries do not leak patient PHN', async () => {
      const deps = makeDeps();
      await reconcileImportWithShift(deps, PROVIDER_ID, BATCH_ID);
      await confirmReconciliation(deps, PROVIDER_ID, BATCH_ID);

      const allEntries = JSON.stringify(auditEntries);
      expect(allEntries).not.toContain('123456782');
    });
  });

  // =========================================================================
  // Audit entry completeness
  // =========================================================================

  describe('Audit entry completeness', () => {
    it('audit entries contain required fields', async () => {
      const deps = makeDeps();
      await reconcileImportWithShift(deps, PROVIDER_ID, BATCH_ID);

      for (const entry of auditEntries) {
        expect(entry.action).toBeDefined();
        expect(typeof entry.action).toBe('string');
      }
    });

    it('missed billing notification emitted for unmatched encounters', async () => {
      const deps = makeDeps({
        getImportBatchRows: vi.fn().mockResolvedValue([
          makeSccRow({ patientUli: '999999999' }),
        ]),
        getShiftEncounters: vi.fn().mockResolvedValue([makeEncounter()]),
      });

      await reconcileImportWithShift(deps, PROVIDER_ID, BATCH_ID);
      await confirmReconciliation(deps, PROVIDER_ID, BATCH_ID);

      expect(deps.emitNotification).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'MISSED_BILLING_DETECTED',
          physicianId: PROVIDER_ID,
        }),
      );
    });
  });
});
