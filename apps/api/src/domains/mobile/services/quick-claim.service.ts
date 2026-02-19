import {
  MobileAuditAction,
  QUICK_ENTRY_INITIAL_STATE,
  RECENT_PATIENTS_COUNT,
} from '@meritum/shared/constants/mobile.constants.js';

// ---------------------------------------------------------------------------
// Dependency interfaces (injected by handler / test)
// ---------------------------------------------------------------------------

export interface ClaimCreator {
  createDraftClaim(
    providerId: string,
    data: {
      patientId: string;
      healthServiceCode: string;
      modifiers?: string[];
      dateOfService: string;
      claimType: string;
      state: string;
      source: string;
    },
  ): Promise<{ claimId: string }>;
}

export interface PatientCreator {
  createMinimalPatient(
    providerId: string,
    data: {
      firstName: string;
      lastName: string;
      phn: string;
      dateOfBirth: string;
      gender: string;
    },
  ): Promise<{
    patientId: string;
    firstName: string;
    lastName: string;
    phn: string;
    dateOfBirth: string;
    gender: string;
  }>;
}

export interface RecentPatientsQuery {
  getRecentBilledPatients(
    providerId: string,
    limit: number,
  ): Promise<
    Array<{
      patientId: string;
      firstName: string;
      lastName: string;
      phn: string;
    }>
  >;
}

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

export interface QuickClaimServiceDeps {
  claimCreator: ClaimCreator;
  patientCreator: PatientCreator;
  recentPatientsQuery: RecentPatientsQuery;
  auditRepo: AuditRepo;
}

// ---------------------------------------------------------------------------
// Input types
// ---------------------------------------------------------------------------

export interface QuickClaimInput {
  patientId: string;
  healthServiceCode: string;
  modifiers?: string[];
  dateOfService?: string;
}

export interface MobilePatientInput {
  firstName: string;
  lastName: string;
  phn: string;
  dateOfBirth: string;
  gender: string;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const AUDIT_CATEGORY = 'mobile';
const MOBILE_SOURCE = 'mobile_quick_entry';
const AHCIP_CLAIM_TYPE = 'AHCIP';

// ---------------------------------------------------------------------------
// Service functions
// ---------------------------------------------------------------------------

/**
 * Create a draft AHCIP claim from mobile quick entry.
 *
 * - Only AHCIP claims are allowed (WCB via mobile is out of scope).
 * - Claim is created in DRAFT state with source='mobile_quick_entry'.
 * - No full validation run on mobile — desktop handles validation.
 * - Diagnostic codes are optional; physician completes on desktop.
 */
export async function createQuickClaim(
  deps: QuickClaimServiceDeps,
  providerId: string,
  data: QuickClaimInput,
): Promise<{ claimId: string }> {
  const dateOfService =
    data.dateOfService ?? new Date().toISOString().split('T')[0];

  const result = await deps.claimCreator.createDraftClaim(providerId, {
    patientId: data.patientId,
    healthServiceCode: data.healthServiceCode,
    modifiers: data.modifiers,
    dateOfService,
    claimType: AHCIP_CLAIM_TYPE,
    state: QUICK_ENTRY_INITIAL_STATE,
    source: MOBILE_SOURCE,
  });

  await deps.auditRepo.appendAuditLog({
    userId: providerId,
    action: MobileAuditAction.QUICK_CLAIM_CREATED,
    category: AUDIT_CATEGORY,
    resourceType: 'claim',
    resourceId: result.claimId,
    detail: {
      patientId: data.patientId,
      healthServiceCode: data.healthServiceCode,
      modifiers: data.modifiers ?? null,
      dateOfService,
      source: MOBILE_SOURCE,
    },
  });

  return result;
}

/**
 * Create a patient with minimal fields from mobile.
 *
 * For mobile quick-add when patient is not yet in the registry.
 * Full patient profile editing happens on desktop.
 */
export async function createMinimalPatient(
  deps: QuickClaimServiceDeps,
  providerId: string,
  data: MobilePatientInput,
): Promise<{
  patientId: string;
  firstName: string;
  lastName: string;
  phn: string;
  dateOfBirth: string;
  gender: string;
}> {
  return deps.patientCreator.createMinimalPatient(providerId, {
    firstName: data.firstName,
    lastName: data.lastName,
    phn: data.phn,
    dateOfBirth: data.dateOfBirth,
    gender: data.gender,
  });
}

/**
 * Get the most recently billed patients for the physician.
 *
 * Returns the last N patients this physician has billed (by most recent
 * claim date_of_service). Used for the 'recent patients' list in quick entry.
 */
export async function getRecentPatients(
  deps: QuickClaimServiceDeps,
  providerId: string,
  limit?: number,
): Promise<
  Array<{
    patientId: string;
    firstName: string;
    lastName: string;
    phn: string;
  }>
> {
  return deps.recentPatientsQuery.getRecentBilledPatients(
    providerId,
    limit ?? RECENT_PATIENTS_COUNT,
  );
}
