// ============================================================================
// Domain 10: Mobile Companion — Encounter Logging Service (MOB-002 §4.2)
// ============================================================================
//
// Business logic for encounter logging during ED shifts. Supports 4 PHN
// capture methods: BARCODE, SEARCH, MANUAL, LAST_FOUR. Validates PHN format,
// records with timestamp, and logs audit events.

import type { EncountersRepository } from '../repos/encounters.repo.js';
import type { SelectEdShiftEncounter } from '@meritum/shared/schemas/db/mobile.schema.js';
import {
  PhnCaptureMethod,
  MobileAuditAction,
} from '@meritum/shared/constants/mobile.constants.js';

// ---------------------------------------------------------------------------
// Dependency interfaces
// ---------------------------------------------------------------------------

export interface AuditRepo {
  appendAuditLog(entry: {
    userId?: string | null;
    action: string;
    category: string;
    resourceType?: string | null;
    resourceId?: string | null;
    detail?: Record<string, unknown> | null;
    ipAddress?: string | null;
    userAgent?: string | null;
  }): Promise<unknown>;
}

export interface EncounterServiceDeps {
  encounterRepo: EncountersRepository;
  auditRepo: AuditRepo;
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface LogEncounterInput {
  phn?: string;
  phnCaptureMethod: string;
  phnIsPartial?: boolean;
  healthServiceCode?: string;
  modifiers?: string[];
  diCode?: string;
  freeTextTag?: string;
  encounterTimestamp?: string;
}

// ---------------------------------------------------------------------------
// PHN Validation
// ---------------------------------------------------------------------------

/**
 * Validate a full 9-digit Alberta PHN using the Luhn algorithm.
 * Returns true if valid, false otherwise.
 */
export function validatePhnLuhn(phn: string): boolean {
  if (!/^\d{9}$/.test(phn)) return false;

  let sum = 0;
  for (let i = 0; i < 9; i++) {
    let digit = parseInt(phn[i], 10);
    // Double every second digit from the right (0-indexed from left: positions 7, 5, 3, 1)
    if ((9 - i) % 2 === 0) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
  }
  return sum % 10 === 0;
}

/**
 * Validate PHN based on capture method.
 *
 * - BARCODE / SEARCH / MANUAL: Full 9-digit PHN required, Luhn validated.
 * - LAST_FOUR: Only last 4 digits, marked as partial.
 *
 * Throws on invalid PHN.
 */
export function validatePhn(
  phn: string | undefined,
  captureMethod: string,
): { phn: string | null; isPartial: boolean } {
  if (captureMethod === PhnCaptureMethod.LAST_FOUR) {
    if (!phn || !/^\d{4}$/.test(phn)) {
      throw new PhnValidationError('LAST_FOUR capture method requires exactly 4 digits');
    }
    return { phn, isPartial: true };
  }

  // Full PHN capture methods
  if (!phn) {
    // PHN is optional — encounter can be logged without it
    return { phn: null, isPartial: false };
  }

  if (!/^\d{9}$/.test(phn)) {
    throw new PhnValidationError('PHN must be exactly 9 digits');
  }

  if (!validatePhnLuhn(phn)) {
    throw new PhnValidationError('PHN failed Luhn check digit validation');
  }

  return { phn, isPartial: false };
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class PhnValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PhnValidationError';
  }
}

// ---------------------------------------------------------------------------
// Service functions
// ---------------------------------------------------------------------------

/**
 * Log a patient encounter during an active ED shift.
 *
 * Validates PHN format based on capture method, records with timestamp,
 * and logs an audit event.
 */
export async function logEncounter(
  deps: EncounterServiceDeps,
  providerId: string,
  shiftId: string,
  input: LogEncounterInput,
): Promise<SelectEdShiftEncounter> {
  // 1. Validate PHN
  const { phn, isPartial } = validatePhn(input.phn, input.phnCaptureMethod);

  // 2. Determine encounter timestamp
  const encounterTimestamp = input.encounterTimestamp
    ? new Date(input.encounterTimestamp)
    : new Date();

  // 3. Log the encounter (repo validates active shift)
  const encounter = await deps.encounterRepo.logEncounter({
    shiftId,
    providerId,
    phn,
    phnCaptureMethod: input.phnCaptureMethod,
    phnIsPartial: isPartial,
    healthServiceCode: input.healthServiceCode ?? null,
    modifiers: input.modifiers ?? null,
    diCode: input.diCode ?? null,
    freeTextTag: input.freeTextTag ?? null,
    encounterTimestamp,
  });

  // 4. Audit log
  await deps.auditRepo.appendAuditLog({
    userId: providerId,
    action: MobileAuditAction.PATIENT_LOGGED,
    category: 'mobile',
    resourceType: 'ed_shift_encounter',
    resourceId: encounter.encounterId,
    detail: {
      shiftId,
      phnCaptureMethod: input.phnCaptureMethod,
      phnIsPartial: isPartial,
      healthServiceCode: input.healthServiceCode ?? null,
      freeTextTag: input.freeTextTag ?? null,
    },
  });

  return encounter;
}

/**
 * Delete an encounter from a shift. Returns the deleted encounter.
 */
export async function deleteEncounter(
  deps: EncounterServiceDeps,
  providerId: string,
  shiftId: string,
  encounterId: string,
): Promise<SelectEdShiftEncounter> {
  const deleted = await deps.encounterRepo.deleteEncounter(
    encounterId,
    shiftId,
    providerId,
  );

  if (!deleted) {
    throw new EncounterNotFoundError('Encounter not found');
  }

  await deps.auditRepo.appendAuditLog({
    userId: providerId,
    action: 'mobile.encounter_deleted',
    category: 'mobile',
    resourceType: 'ed_shift_encounter',
    resourceId: encounterId,
    detail: { shiftId },
  });

  return deleted;
}

/**
 * List all encounters for a shift.
 */
export async function listEncounters(
  deps: EncounterServiceDeps,
  providerId: string,
  shiftId: string,
): Promise<SelectEdShiftEncounter[]> {
  return deps.encounterRepo.listEncounters(shiftId, providerId);
}

// ---------------------------------------------------------------------------
// Additional Errors
// ---------------------------------------------------------------------------

export class EncounterNotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EncounterNotFoundError';
  }
}
