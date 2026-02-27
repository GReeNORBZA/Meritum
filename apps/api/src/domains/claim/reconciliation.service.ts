// ============================================================================
// Connect Care Reconciliation Service (MOB-002 §5.1–5.9)
// ============================================================================
//
// Reconciles imported SCC rows with encounter logs from the mobile app.
// Matches on PHN + date + facility, resolves partial PHNs, computes modifier
// eligibility (AFHR, NGHT), and classifies into 4 categories.

import { ReconciliationMatchCategory } from '@meritum/shared/constants/mobile.constants.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ReconciliationDeps {
  /** Retrieve import batch details */
  getImportBatch: (batchId: string, physicianId: string) => Promise<ImportBatchRow | null>;

  /** Retrieve parsed rows from an import batch */
  getImportBatchRows: (batchId: string) => Promise<SccImportRow[]>;

  /** Find matching shift for the import (by date + facility) */
  findMatchingShift: (
    physicianId: string,
    facilityId: string,
    date: string,
  ) => Promise<ShiftRow | null>;

  /** Get encounters logged during a shift */
  getShiftEncounters: (
    shiftId: string,
    physicianId: string,
  ) => Promise<EncounterRow[]>;

  /** Update claim with inferred service time and modifiers */
  updateClaimTimestamp: (
    claimId: string,
    physicianId: string,
    data: { inferredServiceTime: string; modifiers?: string[] },
  ) => Promise<void>;

  /** Link an encounter to a claim */
  linkEncounterToClaim: (
    encounterId: string,
    claimId: string,
  ) => Promise<void>;

  /** Emit a notification event */
  emitNotification?: (event: {
    type: string;
    physicianId: string;
    payload: Record<string, unknown>;
  }) => Promise<void>;

  /** Audit log */
  auditLog?: (entry: {
    action: string;
    physicianId: string;
    detail: Record<string, unknown>;
  }) => Promise<void>;

  /** Save reconciliation result */
  saveReconciliationResult: (
    batchId: string,
    physicianId: string,
    result: ReconciliationResult,
  ) => Promise<void>;

  /** Retrieve saved reconciliation result */
  getReconciliationResult: (
    batchId: string,
    physicianId: string,
  ) => Promise<ReconciliationResult | null>;

  /** Update reconciliation result status */
  updateReconciliationStatus: (
    batchId: string,
    physicianId: string,
    status: string,
  ) => Promise<void>;
}

export interface ImportBatchRow {
  importBatchId: string;
  physicianId: string;
  status: string;
  confirmationStatus: string;
  facilityId?: string;
  importDate?: string;
}

export interface SccImportRow {
  rowNumber: number;
  claimId?: string;
  patientUli: string;
  encounterDate: string;
  serviceCode: string;
  modifiers?: string[];
  facilityId?: string;
  classification: string;
}

export interface ShiftRow {
  shiftId: string;
  providerId: string;
  locationId: string;
  shiftStart: Date;
  shiftEnd: Date | null;
}

export interface EncounterRow {
  encounterId: string;
  shiftId: string;
  providerId: string;
  phn: string | null;
  phnIsPartial: boolean;
  phnCaptureMethod: string;
  healthServiceCode: string | null;
  encounterTimestamp: Date;
  freeTextTag: string | null;
  matchedClaimId: string | null;
}

// ---------------------------------------------------------------------------
// Match result types
// ---------------------------------------------------------------------------

export interface ReconciliationMatch {
  category: string;
  sccRow?: SccImportRow;
  encounter?: EncounterRow;
  claimId?: string;
  inferredServiceTime?: string;
  modifiers?: string[];
  confidence: number;
  resolutionNeeded?: 'TIME' | 'PARTIAL_PHN';
}

export interface ReconciliationResult {
  batchId: string;
  shiftId: string | null;
  status: string;
  matches: ReconciliationMatch[];
  summary: ReconciliationSummary;
}

export interface ReconciliationSummary {
  totalSccRows: number;
  totalEncounters: number;
  fullMatches: number;
  unmatchedScc: number;
  unmatchedEncounters: number;
  shiftOnly: number;
  needsResolution: number;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const RECONCILIATION_STATUS = {
  PENDING: 'PENDING',
  COMPLETED: 'COMPLETED',
  CONFIRMED: 'CONFIRMED',
} as const;

/** After-hours bracket boundaries (Alberta) */
const AFTER_HOURS_BRACKETS = {
  STANDARD_START: 8,
  STANDARD_END: 17,
  EVENING_END: 23,
} as const;

// ---------------------------------------------------------------------------
// After-hours detection (pure)
// ---------------------------------------------------------------------------

/**
 * Determine after-hours modifier based on encounter timestamp.
 *
 * Alberta rules:
 * - Weekday 08:00–16:59: Standard (no modifier)
 * - Weekday 17:00–22:59: AFHR
 * - Weekday 23:00–07:59: NGHT
 * - Weekend/Holiday: WKND
 */
export function detectModifierEligibility(
  encounterTimestamp: Date,
): string | null {
  const day = encounterTimestamp.getDay();

  // Weekend check
  if (day === 0 || day === 6) {
    return 'WKND';
  }

  const hour = encounterTimestamp.getHours();

  if (hour >= AFTER_HOURS_BRACKETS.STANDARD_END && hour < AFTER_HOURS_BRACKETS.EVENING_END) {
    return 'AFHR';
  }

  if (hour >= AFTER_HOURS_BRACKETS.EVENING_END || hour < AFTER_HOURS_BRACKETS.STANDARD_START) {
    return 'NGHT';
  }

  return null;
}

// ---------------------------------------------------------------------------
// PHN matching
// ---------------------------------------------------------------------------

/**
 * Check if a partial PHN (last 4 digits) matches a full PHN.
 */
export function partialPhnMatches(partialPhn: string, fullPhn: string): boolean {
  if (!partialPhn || !fullPhn) return false;
  if (partialPhn.length !== 4) return false;
  return fullPhn.endsWith(partialPhn);
}

/**
 * Normalize PHN for comparison (strip any formatting).
 */
function normalizePhn(phn: string | null | undefined): string {
  if (!phn) return '';
  return phn.replace(/\D/g, '');
}

// ---------------------------------------------------------------------------
// Core matching algorithm
// ---------------------------------------------------------------------------

/**
 * Match SCC import rows against shift encounters.
 *
 * Matching criteria:
 * 1. Full PHN match: SCC patientUli === encounter.phn (9-digit)
 * 2. Partial PHN match: encounter.phn (last 4) matches SCC ULI last 4
 * 3. Date match: SCC encounterDate === encounter timestamp date
 *
 * Classification:
 * - FULL_MATCH: SCC row matched to an encounter with full PHN
 * - UNMATCHED_SCC: SCC row with no matching encounter
 * - UNMATCHED_ENCOUNTER: Encounter with no matching SCC row (potential missed billing)
 * - SHIFT_ONLY: Encounter logged during shift but no SCC data at all
 */
export function matchRows(
  sccRows: SccImportRow[],
  encounters: EncounterRow[],
): ReconciliationMatch[] {
  const matches: ReconciliationMatch[] = [];
  const matchedEncounterIds = new Set<string>();
  const matchedSccRowNumbers = new Set<number>();

  // Phase 1: Full PHN matches
  for (const sccRow of sccRows) {
    const sccPhn = normalizePhn(sccRow.patientUli);
    const sccDate = sccRow.encounterDate;

    if (!sccPhn) continue;

    for (const encounter of encounters) {
      if (matchedEncounterIds.has(encounter.encounterId)) continue;

      const encPhn = normalizePhn(encounter.phn);
      if (!encPhn || encounter.phnIsPartial) continue;

      const encDate = encounter.encounterTimestamp.toISOString().split('T')[0];

      if (sccPhn === encPhn && sccDate === encDate) {
        const modifier = detectModifierEligibility(encounter.encounterTimestamp);
        matches.push({
          category: ReconciliationMatchCategory.FULL_MATCH,
          sccRow,
          encounter,
          claimId: sccRow.claimId,
          inferredServiceTime: encounter.encounterTimestamp.toISOString(),
          modifiers: modifier ? [modifier] : undefined,
          confidence: 1.0,
        });
        matchedEncounterIds.add(encounter.encounterId);
        matchedSccRowNumbers.add(sccRow.rowNumber);
        break;
      }
    }
  }

  // Phase 2: Partial PHN matches (for LAST_FOUR encounters)
  for (const sccRow of sccRows) {
    if (matchedSccRowNumbers.has(sccRow.rowNumber)) continue;

    const sccPhn = normalizePhn(sccRow.patientUli);
    if (!sccPhn) continue;

    const sccDate = sccRow.encounterDate;
    const partialMatches: EncounterRow[] = [];

    for (const encounter of encounters) {
      if (matchedEncounterIds.has(encounter.encounterId)) continue;
      if (!encounter.phn || !encounter.phnIsPartial) continue;

      const encDate = encounter.encounterTimestamp.toISOString().split('T')[0];
      if (sccDate !== encDate) continue;

      if (partialPhnMatches(encounter.phn, sccPhn)) {
        partialMatches.push(encounter);
      }
    }

    if (partialMatches.length === 1) {
      // Unique partial match — treat as full match with lower confidence
      const encounter = partialMatches[0];
      const modifier = detectModifierEligibility(encounter.encounterTimestamp);
      matches.push({
        category: ReconciliationMatchCategory.FULL_MATCH,
        sccRow,
        encounter,
        claimId: sccRow.claimId,
        inferredServiceTime: encounter.encounterTimestamp.toISOString(),
        modifiers: modifier ? [modifier] : undefined,
        confidence: 0.8,
      });
      matchedEncounterIds.add(encounter.encounterId);
      matchedSccRowNumbers.add(sccRow.rowNumber);
    } else if (partialMatches.length > 1) {
      // Ambiguous partial match — needs physician resolution
      matches.push({
        category: ReconciliationMatchCategory.UNMATCHED_SCC,
        sccRow,
        claimId: sccRow.claimId,
        confidence: 0,
        resolutionNeeded: 'PARTIAL_PHN',
      });
      matchedSccRowNumbers.add(sccRow.rowNumber);
    }
  }

  // Phase 3: Remaining unmatched SCC rows
  for (const sccRow of sccRows) {
    if (matchedSccRowNumbers.has(sccRow.rowNumber)) continue;

    matches.push({
      category: ReconciliationMatchCategory.UNMATCHED_SCC,
      sccRow,
      claimId: sccRow.claimId,
      confidence: 0,
      resolutionNeeded: 'TIME',
    });
  }

  // Phase 4: Remaining unmatched encounters (potential missed billing)
  for (const encounter of encounters) {
    if (matchedEncounterIds.has(encounter.encounterId)) continue;

    matches.push({
      category: ReconciliationMatchCategory.UNMATCHED_ENCOUNTER,
      encounter,
      confidence: 0,
    });
  }

  return matches;
}

// ---------------------------------------------------------------------------
// Reconciliation Orchestrator (MOB-002 §5.1)
// ---------------------------------------------------------------------------

/**
 * Reconcile an import batch with shift encounters.
 *
 * Steps:
 * 1. Retrieve import batch and its SCC rows
 * 2. Find matching shift by date + facility
 * 3. Get encounters for the shift
 * 4. Run matching algorithm
 * 5. Build and save reconciliation result
 */
export async function reconcileImportWithShift(
  deps: ReconciliationDeps,
  physicianId: string,
  batchId: string,
): Promise<ReconciliationResult> {
  // 1. Retrieve import batch
  const batch = await deps.getImportBatch(batchId, physicianId);
  if (!batch) {
    throw new ReconciliationError('Import batch not found');
  }

  // 2. Get SCC rows
  const sccRows = await deps.getImportBatchRows(batchId);
  if (sccRows.length === 0) {
    throw new ReconciliationError('No import rows found for batch');
  }

  // 3. Find matching shift
  const encounterDate = sccRows[0].encounterDate;
  const facilityId = batch.facilityId ?? sccRows[0].facilityId ?? '';

  const shift = await deps.findMatchingShift(physicianId, facilityId, encounterDate);

  let encounters: EncounterRow[] = [];
  if (shift) {
    encounters = await deps.getShiftEncounters(shift.shiftId, physicianId);
  }

  // 4. Run matching
  const matches = shift
    ? matchRows(sccRows, encounters)
    : sccRows.map((row) => ({
        category: ReconciliationMatchCategory.SHIFT_ONLY as string,
        sccRow: row,
        claimId: row.claimId,
        confidence: 0,
      }));

  // 5. Build summary
  const summary = buildSummary(matches, sccRows.length, encounters.length);

  const result: ReconciliationResult = {
    batchId,
    shiftId: shift?.shiftId ?? null,
    status: RECONCILIATION_STATUS.PENDING,
    matches,
    summary,
  };

  // 6. Save result
  await deps.saveReconciliationResult(batchId, physicianId, result);

  // 7. Audit
  if (deps.auditLog) {
    await deps.auditLog({
      action: 'reconciliation.completed',
      physicianId,
      detail: {
        batchId,
        shiftId: shift?.shiftId ?? null,
        ...summary,
      },
    });
  }

  return result;
}

// ---------------------------------------------------------------------------
// Confirmation (MOB-002 §5.4)
// ---------------------------------------------------------------------------

/**
 * Confirm reconciliation — apply inferred times and modifiers to claims.
 *
 * Steps:
 * 1. Apply inferred_service_time to matched claims
 * 2. Apply modifiers (Tier A deterministic)
 * 3. Link encounters to claims
 * 4. Generate missed billing notifications for unmatched encounters
 * 5. Audit log
 */
export async function confirmReconciliation(
  deps: ReconciliationDeps,
  physicianId: string,
  batchId: string,
): Promise<{ confirmed: number; missed: number }> {
  const result = await deps.getReconciliationResult(batchId, physicianId);
  if (!result) {
    throw new ReconciliationError('Reconciliation result not found');
  }

  if (result.status === RECONCILIATION_STATUS.CONFIRMED) {
    throw new ReconciliationError('Reconciliation already confirmed');
  }

  let confirmed = 0;
  let missed = 0;

  for (const match of result.matches) {
    if (
      match.category === ReconciliationMatchCategory.FULL_MATCH &&
      match.claimId &&
      match.inferredServiceTime
    ) {
      // Apply inferred service time and modifiers
      await deps.updateClaimTimestamp(match.claimId, physicianId, {
        inferredServiceTime: match.inferredServiceTime,
        modifiers: match.modifiers,
      });

      // Link encounter to claim
      if (match.encounter) {
        await deps.linkEncounterToClaim(match.encounter.encounterId, match.claimId);
      }

      confirmed++;
    }

    if (match.category === ReconciliationMatchCategory.UNMATCHED_ENCOUNTER) {
      missed++;

      // Emit missed billing notification
      if (deps.emitNotification && match.encounter) {
        await deps.emitNotification({
          type: 'MISSED_BILLING_DETECTED',
          physicianId,
          payload: {
            batchId,
            encounterId: match.encounter.encounterId,
            encounterTimestamp: match.encounter.encounterTimestamp.toISOString(),
            freeTextTag: match.encounter.freeTextTag,
          },
        });
      }
    }
  }

  // Update status
  await deps.updateReconciliationStatus(
    batchId,
    physicianId,
    RECONCILIATION_STATUS.CONFIRMED,
  );

  // Audit
  if (deps.auditLog) {
    await deps.auditLog({
      action: 'reconciliation.confirmed',
      physicianId,
      detail: { batchId, confirmed, missed },
    });
  }

  return { confirmed, missed };
}

// ---------------------------------------------------------------------------
// Resolution (MOB-002 §5.5, §5.9)
// ---------------------------------------------------------------------------

/**
 * Resolve an unmatched SCC row by providing an inferred service time.
 * Physician provides the time for a row that had no encounter match.
 */
export async function resolveUnmatchedTime(
  deps: ReconciliationDeps,
  physicianId: string,
  batchId: string,
  claimId: string,
  inferredServiceTime: string,
): Promise<void> {
  const result = await deps.getReconciliationResult(batchId, physicianId);
  if (!result) {
    throw new ReconciliationError('Reconciliation result not found');
  }

  // Find the match for this claim
  const match = result.matches.find(
    (m) =>
      m.claimId === claimId &&
      m.category === ReconciliationMatchCategory.UNMATCHED_SCC &&
      m.resolutionNeeded === 'TIME',
  );

  if (!match) {
    throw new ReconciliationError('No unmatched SCC row found for this claim');
  }

  // Detect modifier from the provided time
  const ts = new Date(inferredServiceTime);
  const modifier = detectModifierEligibility(ts);

  // Apply to claim
  await deps.updateClaimTimestamp(claimId, physicianId, {
    inferredServiceTime,
    modifiers: modifier ? [modifier] : undefined,
  });

  // Update match in result
  match.category = ReconciliationMatchCategory.FULL_MATCH;
  match.inferredServiceTime = inferredServiceTime;
  match.modifiers = modifier ? [modifier] : undefined;
  match.confidence = 0.9; // physician-resolved
  match.resolutionNeeded = undefined;

  await deps.saveReconciliationResult(batchId, physicianId, result);

  if (deps.auditLog) {
    await deps.auditLog({
      action: 'reconciliation.time_resolved',
      physicianId,
      detail: { batchId, claimId, inferredServiceTime },
    });
  }
}

/**
 * Resolve a partial PHN match by selecting the correct patient ULI.
 * When a LAST_FOUR encounter matches multiple SCC rows, the physician
 * picks the correct one.
 */
export async function resolvePartialPhn(
  deps: ReconciliationDeps,
  physicianId: string,
  batchId: string,
  encounterId: string,
  selectedClaimId: string,
): Promise<void> {
  const result = await deps.getReconciliationResult(batchId, physicianId);
  if (!result) {
    throw new ReconciliationError('Reconciliation result not found');
  }

  // Find the match needing partial PHN resolution for this claim
  const match = result.matches.find(
    (m) =>
      m.claimId === selectedClaimId &&
      m.resolutionNeeded === 'PARTIAL_PHN',
  );

  if (!match) {
    throw new ReconciliationError('No partial PHN match found for this claim');
  }

  // Find the encounter from unmatched encounters
  const encounterMatch = result.matches.find(
    (m) =>
      m.encounter?.encounterId === encounterId &&
      (m.category === ReconciliationMatchCategory.UNMATCHED_ENCOUNTER ||
       m.category === ReconciliationMatchCategory.UNMATCHED_SCC),
  );

  // Link encounter to claim
  await deps.linkEncounterToClaim(encounterId, selectedClaimId);

  // Detect modifiers if we have the encounter
  let modifier: string | null = null;
  if (encounterMatch?.encounter) {
    modifier = detectModifierEligibility(encounterMatch.encounter.encounterTimestamp);

    // Apply inferred service time
    await deps.updateClaimTimestamp(selectedClaimId, physicianId, {
      inferredServiceTime: encounterMatch.encounter.encounterTimestamp.toISOString(),
      modifiers: modifier ? [modifier] : undefined,
    });
  }

  // Update match
  match.category = ReconciliationMatchCategory.FULL_MATCH;
  match.confidence = 0.85; // physician-resolved partial
  match.resolutionNeeded = undefined;

  // Remove the encounter from unmatched if it was there
  if (encounterMatch) {
    encounterMatch.category = ReconciliationMatchCategory.FULL_MATCH;
    encounterMatch.claimId = selectedClaimId;
    encounterMatch.confidence = 0.85;
  }

  await deps.saveReconciliationResult(batchId, physicianId, result);

  if (deps.auditLog) {
    await deps.auditLog({
      action: 'reconciliation.partial_phn_resolved',
      physicianId,
      detail: { batchId, encounterId, selectedClaimId },
    });
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildSummary(
  matches: ReconciliationMatch[],
  totalSccRows: number,
  totalEncounters: number,
): ReconciliationSummary {
  let fullMatches = 0;
  let unmatchedScc = 0;
  let unmatchedEncounters = 0;
  let shiftOnly = 0;
  let needsResolution = 0;

  for (const match of matches) {
    switch (match.category) {
      case ReconciliationMatchCategory.FULL_MATCH:
        fullMatches++;
        break;
      case ReconciliationMatchCategory.UNMATCHED_SCC:
        unmatchedScc++;
        break;
      case ReconciliationMatchCategory.UNMATCHED_ENCOUNTER:
        unmatchedEncounters++;
        break;
      case ReconciliationMatchCategory.SHIFT_ONLY:
        shiftOnly++;
        break;
    }
    if (match.resolutionNeeded) {
      needsResolution++;
    }
  }

  return {
    totalSccRows,
    totalEncounters,
    fullMatches,
    unmatchedScc,
    unmatchedEncounters,
    shiftOnly,
    needsResolution,
  };
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class ReconciliationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ReconciliationError';
  }
}
