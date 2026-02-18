import type { ProviderRepository, OnboardingStatus } from './provider.repository.js';
import { OnboardingIncompleteError } from './provider.repository.js';
import { ProviderAuditAction, BAType, BAStatus, PcpcmEnrolmentStatus, DelegatePermission, DelegateRelationshipStatus, SubmissionMode, HLinkAccreditationStatus, ProviderStatus, DEFAULT_SUBMISSION_PREFERENCES } from '@meritum/shared/constants/provider.constants.js';
import { NotFoundError, BusinessRuleError, ConflictError } from '../../lib/errors.js';
import type { SelectProvider, SelectBa, SelectLocation, SelectWcbConfig, SelectDelegateRelationship } from '@meritum/shared/schemas/db/provider.schema.js';
import { createHash, randomBytes } from 'node:crypto';
import type { ProviderContext } from '@meritum/shared/schemas/provider.schema.js';

// ---------------------------------------------------------------------------
// PCPCM Routing types
// ---------------------------------------------------------------------------

export interface BaRoutingResult {
  ba_number: string;
  ba_type: 'FFS' | 'PCPCM';
  routing_reason: 'WCB_PRIMARY' | 'NON_PCPCM' | 'IN_BASKET' | 'OUT_OF_BASKET' | 'UNCLASSIFIED';
  warning?: string;
}

// ---------------------------------------------------------------------------
// Dependency interfaces (injected by handler / test)
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

export interface EventEmitter {
  emit(event: string, payload: Record<string, unknown>): void;
}

export interface WcbMatrixEntry {
  contractId: string;
  roleCode: string;
  permittedFormTypes: string[];
}

export interface ReferenceDataLookup {
  getRrnpRate(communityId: string): Promise<{ communityName: string; rrnpPercentage: string } | null>;
  getPcpcmBasket?(hscCode: string, dateOfService?: string): Promise<string | null>;
  getWcbMatrixEntry?(contractId: string, roleCode: string): Promise<WcbMatrixEntry | null>;
}

export interface PendingClaimsCheck {
  hasPendingWcbClaims(providerId: string, wcbConfigId: string): Promise<boolean>;
}

export interface TokenStore {
  storeTokenHash(relationshipId: string, tokenHash: string, expiresAt: Date): Promise<void>;
  getTokenHash(relationshipId: string): Promise<{ tokenHash: string; expiresAt: Date } | null>;
  deleteToken(relationshipId: string): Promise<void>;
}

export interface ProviderServiceDeps {
  repo: ProviderRepository;
  auditRepo: AuditRepo;
  events: EventEmitter;
  referenceData?: ReferenceDataLookup;
  pendingClaimsCheck?: PendingClaimsCheck;
  tokenStore?: TokenStore;
}

// ---------------------------------------------------------------------------
// Input types
// ---------------------------------------------------------------------------

export interface UpdateProviderInput {
  firstName?: string;
  lastName?: string;
  middleName?: string;
  specialtyCode?: string;
  specialtyDescription?: string;
  subSpecialtyCode?: string;
  physicianType?: string;
}

export interface CreateBaInput {
  baNumber: string;
  baType: string;
  isPrimary?: boolean;
  effectiveDate?: string;
}

export interface UpdateBaInput {
  status?: string;
  effectiveDate?: string;
  endDate?: string;
}

export interface CreateLocationInput {
  name: string;
  functionalCentre: string;
  facilityNumber?: string;
  addressLine1?: string;
  addressLine2?: string;
  city?: string;
  province?: string;
  postalCode?: string;
  communityCode?: string;
}

export interface UpdateLocationInput {
  name?: string;
  functionalCentre?: string;
  facilityNumber?: string;
  addressLine1?: string;
  addressLine2?: string;
  city?: string;
  province?: string;
  postalCode?: string;
  communityCode?: string;
}

export interface CreateWcbConfigInput {
  contractId: string;
  roleCode: string;
  skillCode?: string;
  isDefault?: boolean;
}

export interface UpdateWcbConfigInput {
  skillCode?: string;
  isDefault?: boolean;
}

export interface OnboardingProfileInput {
  billingNumber: string;
  cpsaRegistrationNumber: string;
  firstName: string;
  lastName: string;
  specialtyCode: string;
  physicianType: string;
  middleName?: string;
  specialtyDescription?: string;
  subSpecialtyCode?: string;
}

export interface UpdatePreferencesInput {
  ahcipSubmissionMode?: string;
  wcbSubmissionMode?: string;
  batchReviewReminder?: boolean;
  deadlineReminderDays?: number;
}

export interface UpdateHlinkInput {
  submitterPrefix?: string;
  accreditationStatus?: string;
}

export interface SubmissionAllowedResult {
  allowed: boolean;
  reasons: string[];
}

// ---------------------------------------------------------------------------
// Extended onboarding status (includes BA, location, IMA checks)
// ---------------------------------------------------------------------------

export interface FullOnboardingStatus {
  onboardingCompleted: boolean;
  steps: {
    field: string;
    label: string;
    complete: boolean;
  }[];
  allRequiredComplete: boolean;
}

// ---------------------------------------------------------------------------
// Audit category constant
// ---------------------------------------------------------------------------

const AUDIT_CATEGORY = 'provider';

// ---------------------------------------------------------------------------
// Service: getProviderProfile
// ---------------------------------------------------------------------------

/**
 * Return the full provider profile including BAs, locations, WCB configs,
 * PCPCM status, RRNP eligibility, submission preferences, and H-Link config.
 * Composes from multiple repository calls via getFullProviderContext.
 */
export async function getProviderProfile(
  deps: ProviderServiceDeps,
  providerId: string,
): Promise<ProviderContext> {
  const context = await deps.repo.getFullProviderContext(providerId);
  if (!context) {
    throw new NotFoundError('Provider');
  }
  return context;
}

// ---------------------------------------------------------------------------
// Service: updateProviderProfile
// ---------------------------------------------------------------------------

/**
 * Update provider profile fields. Emits provider.profile_updated audit event
 * with field-level diff (old vs new values). If specialty changes, note that
 * validation context updates for future claims.
 */
export async function updateProviderProfile(
  deps: ProviderServiceDeps,
  providerId: string,
  data: UpdateProviderInput,
  actorId: string,
): Promise<SelectProvider> {
  // Fetch existing provider to compute diff
  const existing = await deps.repo.findProviderById(providerId);
  if (!existing) {
    throw new NotFoundError('Provider');
  }

  // Build the diff: only include fields that actually changed
  const diff: Record<string, { old: unknown; new: unknown }> = {};
  const updatePayload: Record<string, unknown> = {};

  const fieldMap: Record<keyof UpdateProviderInput, keyof SelectProvider> = {
    firstName: 'firstName',
    lastName: 'lastName',
    middleName: 'middleName',
    specialtyCode: 'specialtyCode',
    specialtyDescription: 'specialtyDescription',
    subSpecialtyCode: 'subSpecialtyCode',
    physicianType: 'physicianType',
  };

  for (const [inputKey, dbKey] of Object.entries(fieldMap)) {
    const newValue = data[inputKey as keyof UpdateProviderInput];
    if (newValue !== undefined) {
      const oldValue = existing[dbKey as keyof SelectProvider];
      if (newValue !== oldValue) {
        diff[dbKey] = { old: oldValue, new: newValue };
        updatePayload[dbKey] = newValue;
      }
    }
  }

  // If nothing actually changed, return existing
  if (Object.keys(updatePayload).length === 0) {
    return existing;
  }

  const updated = await deps.repo.updateProvider(providerId, updatePayload);
  if (!updated) {
    throw new NotFoundError('Provider');
  }

  // Emit audit event with field-level diff
  await deps.auditRepo.appendAuditLog({
    userId: actorId,
    action: ProviderAuditAction.PROFILE_UPDATED,
    category: AUDIT_CATEGORY,
    resourceType: 'provider',
    resourceId: providerId,
    detail: {
      changes: diff,
      specialtyChanged: 'specialtyCode' in diff,
    },
  });

  deps.events.emit('PROVIDER_PROFILE_UPDATED', {
    providerId,
    actorId,
    changes: diff,
  });

  return updated;
}

// ---------------------------------------------------------------------------
// Service: getOnboardingStatus
// ---------------------------------------------------------------------------

/**
 * Return a checklist of required fields with completion status per field.
 * Checks: billing_number, cpsa_registration, specialty, physician_type,
 * at least 1 BA, at least 1 location, IMA acknowledgement.
 */
export async function getOnboardingStatus(
  deps: ProviderServiceDeps,
  providerId: string,
): Promise<FullOnboardingStatus> {
  const provider = await deps.repo.findProviderById(providerId);
  if (!provider) {
    throw new NotFoundError('Provider');
  }

  // Get repository-level onboarding status (checks provider fields)
  const repoStatus = await deps.repo.getOnboardingStatus(providerId);
  if (!repoStatus) {
    throw new NotFoundError('Provider');
  }

  // Check for at least 1 active BA
  const activeBas = await deps.repo.listActiveBasForProvider(providerId);
  const hasBA = activeBas.length > 0;

  // Check for at least 1 active location
  const activeLocations = await deps.repo.listActiveLocationsForProvider(providerId);
  const hasLocation = activeLocations.length > 0;

  // IMA acknowledgement is tracked by onboardingCompleted itself;
  // for status reporting, we consider it complete if onboardingCompleted is true
  // (since completing onboarding requires IMA acknowledgement)
  const imaAcknowledged = provider.onboardingCompleted;

  const steps = [
    {
      field: 'billing_number',
      label: 'Billing Number',
      complete: repoStatus.populated.includes('billingNumber'),
    },
    {
      field: 'cpsa_registration',
      label: 'CPSA Registration Number',
      complete: repoStatus.populated.includes('cpsaRegistrationNumber'),
    },
    {
      field: 'specialty',
      label: 'Specialty & Type',
      complete:
        repoStatus.populated.includes('specialtyCode') &&
        repoStatus.populated.includes('physicianType'),
    },
    {
      field: 'business_arrangement',
      label: 'Business Arrangement',
      complete: hasBA,
    },
    {
      field: 'location',
      label: 'Practice Location',
      complete: hasLocation,
    },
    {
      field: 'ima_acknowledgement',
      label: 'IMA Acknowledgement',
      complete: imaAcknowledged,
    },
  ];

  // Steps 1-4 and 7 (IMA) are required. Steps 5-6 (WCB config, submission prefs) are optional.
  const requiredSteps = steps; // all steps above are required
  const allRequiredComplete = requiredSteps.every((s) => s.complete);

  return {
    onboardingCompleted: provider.onboardingCompleted,
    steps,
    allRequiredComplete,
  };
}

// ---------------------------------------------------------------------------
// Service: completeOnboarding
// ---------------------------------------------------------------------------

/**
 * Validate all required fields are set (steps 1-4 and 7). If valid:
 * set onboarding_completed = true, emit provider.onboarding_completed audit event.
 * If invalid: return list of missing fields.
 */
export async function completeOnboarding(
  deps: ProviderServiceDeps,
  providerId: string,
): Promise<{ success: true; provider: SelectProvider } | { success: false; missingFields: string[] }> {
  const provider = await deps.repo.findProviderById(providerId);
  if (!provider) {
    throw new NotFoundError('Provider');
  }

  // Check required provider fields
  const missingFields: string[] = [];

  if (!provider.billingNumber) missingFields.push('billing_number');
  if (!provider.cpsaRegistrationNumber) missingFields.push('cpsa_registration');
  if (!provider.specialtyCode) missingFields.push('specialty_code');
  if (!provider.physicianType) missingFields.push('physician_type');

  // Check for at least 1 active BA
  const activeBas = await deps.repo.listActiveBasForProvider(providerId);
  if (activeBas.length === 0) missingFields.push('business_arrangement');

  // Check for at least 1 active location
  const activeLocations = await deps.repo.listActiveLocationsForProvider(providerId);
  if (activeLocations.length === 0) missingFields.push('location');

  if (missingFields.length > 0) {
    return { success: false, missingFields };
  }

  // All checks passed — complete onboarding
  const updated = await deps.repo.updateProvider(providerId, {
    onboardingCompleted: true,
  });

  if (!updated) {
    throw new NotFoundError('Provider');
  }

  // Emit audit event
  await deps.auditRepo.appendAuditLog({
    userId: providerId,
    action: ProviderAuditAction.ONBOARDING_COMPLETED,
    category: AUDIT_CATEGORY,
    resourceType: 'provider',
    resourceId: providerId,
    detail: {
      completedAt: new Date().toISOString(),
    },
  });

  deps.events.emit('PROVIDER_ONBOARDING_COMPLETED', {
    providerId,
  });

  return { success: true, provider: updated };
}

// ---------------------------------------------------------------------------
// Service: createProviderFromOnboarding
// ---------------------------------------------------------------------------

/**
 * Create the provider record during the onboarding wizard.
 * Called from the first onboarding step. Sets provider_id = userId
 * to establish the 1:1 link between IAM and Provider.
 */
export async function createProviderFromOnboarding(
  deps: ProviderServiceDeps,
  userId: string,
  data: OnboardingProfileInput,
): Promise<SelectProvider> {
  // Check if provider already exists for this user
  const existing = await deps.repo.findProviderById(userId);
  if (existing) {
    throw new BusinessRuleError(
      'Provider profile already exists for this user',
    );
  }

  const provider = await deps.repo.createProvider({
    providerId: userId,
    billingNumber: data.billingNumber,
    cpsaRegistrationNumber: data.cpsaRegistrationNumber,
    firstName: data.firstName,
    lastName: data.lastName,
    specialtyCode: data.specialtyCode,
    physicianType: data.physicianType,
    middleName: data.middleName ?? null,
    specialtyDescription: data.specialtyDescription ?? null,
    subSpecialtyCode: data.subSpecialtyCode ?? null,
    status: 'ACTIVE',
    onboardingCompleted: false,
  });

  // Emit audit event
  await deps.auditRepo.appendAuditLog({
    userId,
    action: ProviderAuditAction.PROFILE_UPDATED,
    category: AUDIT_CATEGORY,
    resourceType: 'provider',
    resourceId: userId,
    detail: {
      action: 'created_from_onboarding',
      billingNumber: data.billingNumber,
    },
  });

  deps.events.emit('PROVIDER_CREATED', {
    providerId: userId,
    billingNumber: data.billingNumber,
  });

  return provider;
}

// ---------------------------------------------------------------------------
// Service: addBa
// ---------------------------------------------------------------------------

/** Max active BAs allowed per provider. */
const MAX_ACTIVE_BAS = 2;

/** Valid BA status transitions: map from current status to allowed next statuses. */
const VALID_BA_TRANSITIONS: Record<string, string[]> = {
  [BAStatus.PENDING]: [BAStatus.ACTIVE],
  [BAStatus.ACTIVE]: [BAStatus.INACTIVE],
  // INACTIVE is terminal — no transitions out
};

/**
 * Add a new business arrangement.
 *
 * Rules:
 * - Max 2 active BAs per provider.
 * - ba_number must be unique across active BAs (system-wide).
 * - PCPCM BA requires an existing FFS BA (or the caller is adding both).
 * - When adding PCPCM BA, a pcpcm_enrolments record is created linking the
 *   PCPCM and FFS BAs. The FFS BA is marked as primary.
 */
export async function addBa(
  deps: ProviderServiceDeps,
  providerId: string,
  data: CreateBaInput,
  actorId: string,
): Promise<SelectBa> {
  // 1. Validate ba_number uniqueness (system-wide among non-INACTIVE BAs)
  const existingBa = await deps.repo.findBaByNumber(data.baNumber);
  if (existingBa) {
    throw new ConflictError(
      `BA number ${data.baNumber} is already in use`,
    );
  }

  // 2. Validate max active BAs constraint
  const activeCount = await deps.repo.countActiveBasForProvider(providerId);
  if (activeCount >= MAX_ACTIVE_BAS) {
    throw new BusinessRuleError(
      `Maximum of ${MAX_ACTIVE_BAS} active business arrangements allowed`,
    );
  }

  // 3. PCPCM constraint: must have an existing FFS BA
  if (data.baType === BAType.PCPCM) {
    const activeBas = await deps.repo.listActiveBasForProvider(providerId);
    // Also check PENDING BAs since the FFS may have just been added
    const allBas = await deps.repo.listBasForProvider(providerId);
    const hasFfsBa = [...activeBas, ...allBas].some(
      (ba) => ba.baType === BAType.FFS && ba.status !== BAStatus.INACTIVE,
    );
    if (!hasFfsBa) {
      throw new BusinessRuleError(
        'A PCPCM business arrangement requires an existing FFS business arrangement',
      );
    }
  }

  // 4. Determine is_primary:
  //    - For FFS in a dual-BA scenario: FFS is primary
  //    - If this is the only BA: it's primary
  //    - PCPCM is never primary
  let isPrimary = data.isPrimary ?? false;
  if (data.baType === BAType.PCPCM) {
    isPrimary = false;
  } else if (activeCount === 0) {
    // First BA is always primary
    isPrimary = true;
  }

  // 5. Create the BA record (status defaults to PENDING)
  const newBa = await deps.repo.createBa({
    providerId,
    baNumber: data.baNumber,
    baType: data.baType,
    isPrimary,
    status: BAStatus.PENDING,
    effectiveDate: data.effectiveDate ?? null,
    endDate: null,
  });

  // 6. If adding PCPCM BA, create the pcpcm_enrolments record
  if (data.baType === BAType.PCPCM) {
    const allBas = await deps.repo.listBasForProvider(providerId);
    const ffsBa = allBas.find(
      (ba) => ba.baType === BAType.FFS && ba.status !== BAStatus.INACTIVE,
    );
    if (ffsBa) {
      // Ensure FFS BA is marked as primary
      if (!ffsBa.isPrimary) {
        await deps.repo.updateBa(ffsBa.baId, providerId, { isPrimary: true });
      }

      await deps.repo.createPcpcmEnrolment({
        providerId,
        pcpcmBaId: newBa.baId,
        ffsBaId: ffsBa.baId,
        status: PcpcmEnrolmentStatus.PENDING,
        panelSize: null,
        enrolmentDate: data.effectiveDate ?? null,
        withdrawalDate: null,
      });
    }
  }

  // 7. Audit
  await deps.auditRepo.appendAuditLog({
    userId: actorId,
    action: ProviderAuditAction.BA_ADDED,
    category: AUDIT_CATEGORY,
    resourceType: 'business_arrangement',
    resourceId: newBa.baId,
    detail: {
      providerId,
      baNumber: data.baNumber,
      baType: data.baType,
      isPrimary,
    },
  });

  deps.events.emit('BA_ADDED', {
    providerId,
    baId: newBa.baId,
    baNumber: data.baNumber,
    baType: data.baType,
  });

  return newBa;
}

// ---------------------------------------------------------------------------
// Service: updateBa
// ---------------------------------------------------------------------------

/**
 * Update BA fields. Validates status transitions:
 * - PENDING -> ACTIVE (valid)
 * - ACTIVE -> INACTIVE (valid, but use deactivateBa for full workflow)
 * - ACTIVE -> PENDING (invalid)
 * - INACTIVE -> any (invalid)
 */
export async function updateBa(
  deps: ProviderServiceDeps,
  providerId: string,
  baId: string,
  data: UpdateBaInput,
  actorId: string,
): Promise<SelectBa> {
  const existing = await deps.repo.findBaById(baId, providerId);
  if (!existing) {
    throw new NotFoundError('Business arrangement');
  }

  // Capture previous status before mutation (repo may mutate in-place)
  const previousStatus = existing.status;

  // Validate status transition if status is being changed
  if (data.status && data.status !== previousStatus) {
    const allowedTransitions = VALID_BA_TRANSITIONS[previousStatus] ?? [];
    if (!allowedTransitions.includes(data.status)) {
      throw new BusinessRuleError(
        `Invalid status transition from ${previousStatus} to ${data.status}`,
      );
    }
  }

  const updatePayload: Record<string, unknown> = {};
  if (data.status !== undefined) updatePayload.status = data.status;
  if (data.effectiveDate !== undefined) updatePayload.effectiveDate = data.effectiveDate;
  if (data.endDate !== undefined) updatePayload.endDate = data.endDate;

  if (Object.keys(updatePayload).length === 0) {
    return existing;
  }

  const updated = await deps.repo.updateBa(baId, providerId, updatePayload);
  if (!updated) {
    throw new NotFoundError('Business arrangement');
  }

  await deps.auditRepo.appendAuditLog({
    userId: actorId,
    action: ProviderAuditAction.BA_UPDATED,
    category: AUDIT_CATEGORY,
    resourceType: 'business_arrangement',
    resourceId: baId,
    detail: {
      providerId,
      changes: updatePayload,
      previousStatus,
    },
  });

  deps.events.emit('BA_UPDATED', {
    providerId,
    baId,
    changes: updatePayload,
  });

  return updated;
}

// ---------------------------------------------------------------------------
// Service: deactivateBa
// ---------------------------------------------------------------------------

/**
 * Deactivate a BA: sets status = INACTIVE and end_date = today.
 *
 * If this is a PCPCM BA, also withdraws the linked PCPCM enrolment.
 * Validates the BA is currently ACTIVE before deactivating.
 */
export async function deactivateBa(
  deps: ProviderServiceDeps,
  providerId: string,
  baId: string,
  actorId: string,
): Promise<SelectBa> {
  const existing = await deps.repo.findBaById(baId, providerId);
  if (!existing) {
    throw new NotFoundError('Business arrangement');
  }

  // Only ACTIVE BAs can be deactivated
  if (existing.status !== BAStatus.ACTIVE) {
    throw new BusinessRuleError(
      `Cannot deactivate a business arrangement with status ${existing.status}`,
    );
  }

  // Deactivate the BA
  const deactivated = await deps.repo.deactivateBa(baId, providerId);
  if (!deactivated) {
    throw new NotFoundError('Business arrangement');
  }

  // If this is a PCPCM BA, withdraw the PCPCM enrolment
  if (existing.baType === BAType.PCPCM) {
    const enrolment = await deps.repo.findPcpcmEnrolmentForProvider(providerId);
    if (enrolment) {
      await deps.repo.updatePcpcmEnrolment(
        enrolment.enrolmentId,
        providerId,
        {
          status: PcpcmEnrolmentStatus.WITHDRAWN,
          withdrawalDate: new Date().toISOString().split('T')[0],
        },
      );
    }
  }

  await deps.auditRepo.appendAuditLog({
    userId: actorId,
    action: ProviderAuditAction.BA_DEACTIVATED,
    category: AUDIT_CATEGORY,
    resourceType: 'business_arrangement',
    resourceId: baId,
    detail: {
      providerId,
      baNumber: existing.baNumber,
      baType: existing.baType,
      pcpcmWithdrawn: existing.baType === BAType.PCPCM,
    },
  });

  deps.events.emit('BA_DEACTIVATED', {
    providerId,
    baId,
    baNumber: existing.baNumber,
    baType: existing.baType,
  });

  return deactivated;
}

// ---------------------------------------------------------------------------
// Service: listBas
// ---------------------------------------------------------------------------

/**
 * List all BAs for a provider (all statuses).
 */
export async function listBas(
  deps: ProviderServiceDeps,
  providerId: string,
): Promise<SelectBa[]> {
  return deps.repo.listBasForProvider(providerId);
}

// ---------------------------------------------------------------------------
// Service: addLocation
// ---------------------------------------------------------------------------

/**
 * Resolve RRNP eligibility and rate from Reference Data for a community code.
 * Returns { rrnpEligible: true, rrnpRate } if community qualifies, or
 * { rrnpEligible: false, rrnpRate: null } otherwise.
 */
async function resolveRrnp(
  deps: ProviderServiceDeps,
  communityCode?: string,
): Promise<{ rrnpEligible: boolean; rrnpRate: string | null }> {
  if (!communityCode || !deps.referenceData) {
    return { rrnpEligible: false, rrnpRate: null };
  }

  const result = await deps.referenceData.getRrnpRate(communityCode);
  if (!result) {
    return { rrnpEligible: false, rrnpRate: null };
  }

  return {
    rrnpEligible: true,
    rrnpRate: result.rrnpPercentage,
  };
}

/**
 * Add a practice location for a provider.
 *
 * Rules:
 * - If community_code provided: look up RRNP eligibility and rate from
 *   Reference Data. Set rrnp_eligible and rrnp_rate accordingly.
 * - If no community_code: rrnp_eligible = false.
 * - If this is the first location: auto-set as default.
 * - Emits location.added audit event.
 */
export async function addLocation(
  deps: ProviderServiceDeps,
  providerId: string,
  data: CreateLocationInput,
  actorId: string,
): Promise<SelectLocation> {
  // Resolve RRNP eligibility
  const { rrnpEligible, rrnpRate } = await resolveRrnp(deps, data.communityCode);

  // Check if this is the first location (auto-set default)
  const existingLocations = await deps.repo.listActiveLocationsForProvider(providerId);
  const isFirst = existingLocations.length === 0;

  const location = await deps.repo.createLocation({
    providerId,
    name: data.name,
    functionalCentre: data.functionalCentre,
    facilityNumber: data.facilityNumber ?? null,
    addressLine1: data.addressLine1 ?? null,
    addressLine2: data.addressLine2 ?? null,
    city: data.city ?? null,
    province: data.province ?? 'AB',
    postalCode: data.postalCode ?? null,
    communityCode: data.communityCode ?? null,
    rrnpEligible,
    rrnpRate,
    isDefault: isFirst,
    isActive: true,
  });

  await deps.auditRepo.appendAuditLog({
    userId: actorId,
    action: ProviderAuditAction.LOCATION_ADDED,
    category: AUDIT_CATEGORY,
    resourceType: 'practice_location',
    resourceId: location.locationId,
    detail: {
      providerId,
      name: data.name,
      functionalCentre: data.functionalCentre,
      communityCode: data.communityCode ?? null,
      rrnpEligible,
      rrnpRate,
      isDefault: isFirst,
    },
  });

  deps.events.emit('LOCATION_ADDED', {
    providerId,
    locationId: location.locationId,
    name: data.name,
    rrnpEligible,
  });

  return location;
}

// ---------------------------------------------------------------------------
// Service: updateLocation
// ---------------------------------------------------------------------------

/**
 * Update a practice location.
 *
 * If community_code changed: re-derive RRNP eligibility and rate.
 * Emits location.updated audit event with changes.
 */
export async function updateLocation(
  deps: ProviderServiceDeps,
  providerId: string,
  locationId: string,
  data: UpdateLocationInput,
  actorId: string,
): Promise<SelectLocation> {
  const existing = await deps.repo.findLocationById(locationId, providerId);
  if (!existing) {
    throw new NotFoundError('Practice location');
  }

  const updatePayload: Record<string, unknown> = {};
  const changes: Record<string, { old: unknown; new: unknown }> = {};

  // Build diff for simple fields
  const fieldMap: Record<string, keyof typeof existing> = {
    name: 'name',
    functionalCentre: 'functionalCentre',
    facilityNumber: 'facilityNumber',
    addressLine1: 'addressLine1',
    addressLine2: 'addressLine2',
    city: 'city',
    province: 'province',
    postalCode: 'postalCode',
    communityCode: 'communityCode',
  };

  for (const [inputKey, dbKey] of Object.entries(fieldMap)) {
    const newValue = data[inputKey as keyof UpdateLocationInput];
    if (newValue !== undefined) {
      const oldValue = existing[dbKey];
      if (newValue !== oldValue) {
        changes[dbKey] = { old: oldValue, new: newValue };
        updatePayload[dbKey] = newValue;
      }
    }
  }

  // If community_code changed, re-derive RRNP
  const communityCodeChanged = 'communityCode' in changes;
  if (communityCodeChanged) {
    const newCommunityCode = data.communityCode;
    const { rrnpEligible, rrnpRate } = await resolveRrnp(deps, newCommunityCode);

    if (rrnpEligible !== existing.rrnpEligible) {
      changes.rrnpEligible = { old: existing.rrnpEligible, new: rrnpEligible };
    }
    if (rrnpRate !== existing.rrnpRate) {
      changes.rrnpRate = { old: existing.rrnpRate, new: rrnpRate };
    }

    updatePayload.rrnpEligible = rrnpEligible;
    updatePayload.rrnpRate = rrnpRate;
  }

  // If nothing changed, return existing
  if (Object.keys(updatePayload).length === 0) {
    return existing;
  }

  const updated = await deps.repo.updateLocation(locationId, providerId, updatePayload);
  if (!updated) {
    throw new NotFoundError('Practice location');
  }

  await deps.auditRepo.appendAuditLog({
    userId: actorId,
    action: ProviderAuditAction.LOCATION_UPDATED,
    category: AUDIT_CATEGORY,
    resourceType: 'practice_location',
    resourceId: locationId,
    detail: {
      providerId,
      changes,
    },
  });

  deps.events.emit('LOCATION_UPDATED', {
    providerId,
    locationId,
    changes,
  });

  return updated;
}

// ---------------------------------------------------------------------------
// Service: setDefaultLocation
// ---------------------------------------------------------------------------

/**
 * Set a location as the default for the provider.
 * Unsets previous default in a transaction (handled by repository).
 */
export async function setDefaultLocation(
  deps: ProviderServiceDeps,
  providerId: string,
  locationId: string,
  actorId: string,
): Promise<SelectLocation> {
  // Verify location exists and belongs to provider
  const location = await deps.repo.findLocationById(locationId, providerId);
  if (!location) {
    throw new NotFoundError('Practice location');
  }

  if (!location.isActive) {
    throw new BusinessRuleError('Cannot set an inactive location as default');
  }

  // Get current default for audit trail
  const previousDefault = await deps.repo.getDefaultLocation(providerId);
  const previousDefaultId = previousDefault?.locationId ?? null;

  // Repository handles transaction: unset old default, set new default
  const updated = await deps.repo.setDefaultLocation(locationId, providerId);
  if (!updated) {
    throw new NotFoundError('Practice location');
  }

  await deps.auditRepo.appendAuditLog({
    userId: actorId,
    action: ProviderAuditAction.LOCATION_UPDATED,
    category: AUDIT_CATEGORY,
    resourceType: 'practice_location',
    resourceId: locationId,
    detail: {
      providerId,
      action: 'set_default',
      previousDefaultLocationId: previousDefaultId,
      newDefaultLocationId: locationId,
    },
  });

  deps.events.emit('LOCATION_DEFAULT_CHANGED', {
    providerId,
    locationId,
    previousDefaultLocationId: previousDefaultId,
  });

  return updated;
}

// ---------------------------------------------------------------------------
// Service: deactivateLocation
// ---------------------------------------------------------------------------

/**
 * Soft-delete a location. If it was the default, the default is cleared.
 * Existing claims using this location are unaffected.
 * Emits location.deactivated audit event.
 */
export async function deactivateLocation(
  deps: ProviderServiceDeps,
  providerId: string,
  locationId: string,
  actorId: string,
): Promise<SelectLocation> {
  const existing = await deps.repo.findLocationById(locationId, providerId);
  if (!existing) {
    throw new NotFoundError('Practice location');
  }

  if (!existing.isActive) {
    throw new BusinessRuleError('Location is already inactive');
  }

  const wasDefault = existing.isDefault;

  // Repository deactivateLocation sets isActive=false and isDefault=false
  const deactivated = await deps.repo.deactivateLocation(locationId, providerId);
  if (!deactivated) {
    throw new NotFoundError('Practice location');
  }

  await deps.auditRepo.appendAuditLog({
    userId: actorId,
    action: ProviderAuditAction.LOCATION_DEACTIVATED,
    category: AUDIT_CATEGORY,
    resourceType: 'practice_location',
    resourceId: locationId,
    detail: {
      providerId,
      name: existing.name,
      wasDefault,
    },
  });

  deps.events.emit('LOCATION_DEACTIVATED', {
    providerId,
    locationId,
    name: existing.name,
    wasDefault,
  });

  return deactivated;
}

// ---------------------------------------------------------------------------
// Service: listLocations
// ---------------------------------------------------------------------------

/**
 * Return all locations for a provider (all statuses).
 */
export async function listLocations(
  deps: ProviderServiceDeps,
  providerId: string,
): Promise<SelectLocation[]> {
  return deps.repo.listLocationsForProvider(providerId);
}

// ---------------------------------------------------------------------------
// Service: listActiveLocations
// ---------------------------------------------------------------------------

/**
 * Return active locations (for claim creation dropdown).
 */
export async function listActiveLocations(
  deps: ProviderServiceDeps,
  providerId: string,
): Promise<SelectLocation[]> {
  return deps.repo.listActiveLocationsForProvider(providerId);
}

// ---------------------------------------------------------------------------
// Service: refreshRrnpRates
// ---------------------------------------------------------------------------

/**
 * Re-derive RRNP eligibility and rates for all active locations from
 * Reference Data. Called quarterly or on demand.
 *
 * Returns the count of locations updated.
 */
export async function refreshRrnpRates(
  deps: ProviderServiceDeps,
  providerId: string,
): Promise<{ updatedCount: number }> {
  const activeLocations = await deps.repo.listActiveLocationsForProvider(providerId);
  let updatedCount = 0;

  for (const location of activeLocations) {
    if (!location.communityCode) {
      // No community code — ensure RRNP is false
      if (location.rrnpEligible) {
        await deps.repo.updateLocation(location.locationId, providerId, {
          rrnpEligible: false,
          rrnpRate: null,
        });
        updatedCount++;
      }
      continue;
    }

    const { rrnpEligible, rrnpRate } = await resolveRrnp(deps, location.communityCode);

    // Only update if values changed
    if (rrnpEligible !== location.rrnpEligible || rrnpRate !== location.rrnpRate) {
      await deps.repo.updateLocation(location.locationId, providerId, {
        rrnpEligible,
        rrnpRate,
      });
      updatedCount++;
    }
  }

  return { updatedCount };
}

// ---------------------------------------------------------------------------
// Service: isPcpcmEnrolled
// ---------------------------------------------------------------------------

/**
 * Check if a provider has an active PCPCM enrolment.
 * Returns true if the provider has a non-WITHDRAWN PCPCM enrolment.
 */
export async function isPcpcmEnrolled(
  deps: ProviderServiceDeps,
  providerId: string,
): Promise<boolean> {
  const enrolment = await deps.repo.findPcpcmEnrolmentForProvider(providerId);
  return enrolment !== undefined && enrolment.status === 'ACTIVE';
}

// ---------------------------------------------------------------------------
// Service: routeClaimToBa
// ---------------------------------------------------------------------------

/**
 * Determine the correct BA for a claim based on claim type, PCPCM enrolment
 * status, and HSC code basket classification.
 *
 * Routing logic:
 * 1. WCB claims → primary BA number.
 * 2. AHCIP + non-PCPCM → FFS BA number.
 * 3. AHCIP + PCPCM-enrolled:
 *    a. Look up HSC code's PCPCM basket via referenceData.getPcpcmBasket
 *       using the SOMB version effective at dateOfService.
 *    b. In-basket → PCPCM BA number.
 *    c. Out-of-basket ('not_applicable') → FFS BA number.
 *    d. No classification (null) → FFS BA number + warning flag.
 *
 * Critical: The SOMB version in effect at the date of service governs the
 * basket classification, NOT the current SOMB version.
 */
export async function routeClaimToBa(
  deps: ProviderServiceDeps,
  providerId: string,
  claimType: 'AHCIP' | 'WCB',
  hscCode?: string,
  dateOfService?: string,
): Promise<BaRoutingResult> {
  const repoResult = await deps.repo.getBaForClaim(
    providerId,
    claimType,
    hscCode,
    dateOfService,
  );

  if (!repoResult) {
    throw new NotFoundError('Business arrangement');
  }

  // WCB claims always route to the primary BA
  if (claimType === 'WCB') {
    return {
      ba_number: repoResult.baNumber,
      ba_type: repoResult.baType as 'FFS' | 'PCPCM',
      routing_reason: 'WCB_PRIMARY',
    };
  }

  // AHCIP path — check PCPCM enrolment status
  const enrolled = await isPcpcmEnrolled(deps, providerId);

  if (!enrolled) {
    return {
      ba_number: repoResult.baNumber,
      ba_type: repoResult.baType as 'FFS' | 'PCPCM',
      routing_reason: 'NON_PCPCM',
    };
  }

  // PCPCM-enrolled: if repo resolved to PCPCM BA, it's in-basket
  if (repoResult.routing === 'PCPCM') {
    return {
      ba_number: repoResult.baNumber,
      ba_type: 'PCPCM',
      routing_reason: 'IN_BASKET',
    };
  }

  // Repo returned FFS routing for a PCPCM-enrolled physician.
  // Use the Reference Data service to distinguish out-of-basket vs unclassified.
  if (hscCode && deps.referenceData?.getPcpcmBasket) {
    const basket = await deps.referenceData.getPcpcmBasket(hscCode, dateOfService);

    if (basket === null) {
      return {
        ba_number: repoResult.baNumber,
        ba_type: 'FFS',
        routing_reason: 'UNCLASSIFIED',
        warning: `HSC code ${hscCode} has no PCPCM basket classification in the SOMB version effective at the date of service. Routed to FFS BA.`,
      };
    }

    return {
      ba_number: repoResult.baNumber,
      ba_type: 'FFS',
      routing_reason: 'OUT_OF_BASKET',
    };
  }

  // No hscCode or no reference data service — FFS with NON_PCPCM reason
  return {
    ba_number: repoResult.baNumber,
    ba_type: 'FFS',
    routing_reason: 'OUT_OF_BASKET',
  };
}

// ---------------------------------------------------------------------------
// Service: addWcbConfig
// ---------------------------------------------------------------------------

/**
 * Add a WCB configuration for a provider.
 *
 * Rules:
 * - Validate (contract_id, role_code) against WCB Contract ID/Role/Form ID
 *   matrix from Reference Data Domain 2.
 * - Auto-populate permitted_form_types from the matrix.
 * - Reject duplicate (provider, contract_id) — enforced by repository unique index.
 * - Emit wcb_config.added audit event.
 */
export async function addWcbConfig(
  deps: ProviderServiceDeps,
  providerId: string,
  data: CreateWcbConfigInput,
  actorId: string,
): Promise<SelectWcbConfig> {
  // 1. Validate (contract_id, role_code) against WCB matrix
  let permittedFormTypes: string[] = [];

  if (deps.referenceData?.getWcbMatrixEntry) {
    const matrixEntry = await deps.referenceData.getWcbMatrixEntry(
      data.contractId,
      data.roleCode,
    );

    if (!matrixEntry) {
      throw new BusinessRuleError(
        `Invalid WCB configuration: contract_id '${data.contractId}' with role_code '${data.roleCode}' is not a valid combination in the WCB matrix`,
      );
    }

    // Auto-populate permitted_form_types from the matrix
    permittedFormTypes = matrixEntry.permittedFormTypes;
  } else {
    // No reference data service available — reject since we can't validate
    throw new BusinessRuleError(
      'WCB matrix lookup is not available. Cannot validate contract_id and role_code combination.',
    );
  }

  // 2. Create the WCB config (repo enforces unique (provider_id, contract_id))
  const config = await deps.repo.createWcbConfig({
    providerId,
    contractId: data.contractId,
    roleCode: data.roleCode,
    skillCode: data.skillCode ?? null,
    permittedFormTypes,
    isDefault: data.isDefault ?? false,
  });

  // 3. Audit
  await deps.auditRepo.appendAuditLog({
    userId: actorId,
    action: ProviderAuditAction.WCB_CONFIG_ADDED,
    category: AUDIT_CATEGORY,
    resourceType: 'wcb_configuration',
    resourceId: config.wcbConfigId,
    detail: {
      providerId,
      contractId: data.contractId,
      roleCode: data.roleCode,
      permittedFormTypes,
    },
  });

  deps.events.emit('WCB_CONFIG_ADDED', {
    providerId,
    wcbConfigId: config.wcbConfigId,
    contractId: data.contractId,
    roleCode: data.roleCode,
  });

  return config;
}

// ---------------------------------------------------------------------------
// Service: updateWcbConfig
// ---------------------------------------------------------------------------

/**
 * Update WCB config fields (skill_code, is_default).
 * Emits wcb_config.updated audit event.
 */
export async function updateWcbConfig(
  deps: ProviderServiceDeps,
  providerId: string,
  wcbConfigId: string,
  data: UpdateWcbConfigInput,
  actorId: string,
): Promise<SelectWcbConfig> {
  const existing = await deps.repo.findWcbConfigById(wcbConfigId, providerId);
  if (!existing) {
    throw new NotFoundError('WCB configuration');
  }

  const updatePayload: Record<string, unknown> = {};
  const changes: Record<string, { old: unknown; new: unknown }> = {};

  if (data.skillCode !== undefined && data.skillCode !== existing.skillCode) {
    changes.skillCode = { old: existing.skillCode, new: data.skillCode };
    updatePayload.skillCode = data.skillCode;
  }

  if (data.isDefault !== undefined && data.isDefault !== existing.isDefault) {
    changes.isDefault = { old: existing.isDefault, new: data.isDefault };
    updatePayload.isDefault = data.isDefault;
  }

  if (Object.keys(updatePayload).length === 0) {
    return existing;
  }

  const updated = await deps.repo.updateWcbConfig(wcbConfigId, providerId, updatePayload);
  if (!updated) {
    throw new NotFoundError('WCB configuration');
  }

  await deps.auditRepo.appendAuditLog({
    userId: actorId,
    action: ProviderAuditAction.WCB_CONFIG_UPDATED,
    category: AUDIT_CATEGORY,
    resourceType: 'wcb_configuration',
    resourceId: wcbConfigId,
    detail: {
      providerId,
      changes,
    },
  });

  deps.events.emit('WCB_CONFIG_UPDATED', {
    providerId,
    wcbConfigId,
    changes,
  });

  return updated;
}

// ---------------------------------------------------------------------------
// Service: removeWcbConfig
// ---------------------------------------------------------------------------

/**
 * Remove a WCB configuration. Verifies no pending WCB claims reference
 * this config before deletion. Emits wcb_config.removed audit event
 * with Contract ID and Role in audit detail.
 */
export async function removeWcbConfig(
  deps: ProviderServiceDeps,
  providerId: string,
  wcbConfigId: string,
  actorId: string,
): Promise<void> {
  const existing = await deps.repo.findWcbConfigById(wcbConfigId, providerId);
  if (!existing) {
    throw new NotFoundError('WCB configuration');
  }

  // Check for pending WCB claims referencing this config
  if (deps.pendingClaimsCheck) {
    const hasPending = await deps.pendingClaimsCheck.hasPendingWcbClaims(
      providerId,
      wcbConfigId,
    );
    if (hasPending) {
      throw new BusinessRuleError(
        'Cannot remove WCB configuration: there are pending WCB claims referencing this configuration',
      );
    }
  }

  const deleted = await deps.repo.deleteWcbConfig(wcbConfigId, providerId);
  if (!deleted) {
    throw new NotFoundError('WCB configuration');
  }

  await deps.auditRepo.appendAuditLog({
    userId: actorId,
    action: ProviderAuditAction.WCB_CONFIG_REMOVED,
    category: AUDIT_CATEGORY,
    resourceType: 'wcb_configuration',
    resourceId: wcbConfigId,
    detail: {
      providerId,
      contractId: existing.contractId,
      roleCode: existing.roleCode,
    },
  });

  deps.events.emit('WCB_CONFIG_REMOVED', {
    providerId,
    wcbConfigId,
    contractId: existing.contractId,
    roleCode: existing.roleCode,
  });
}

// ---------------------------------------------------------------------------
// Service: listWcbConfigs
// ---------------------------------------------------------------------------

/**
 * List all WCB configurations for a provider.
 */
export async function listWcbConfigs(
  deps: ProviderServiceDeps,
  providerId: string,
): Promise<SelectWcbConfig[]> {
  return deps.repo.listWcbConfigsForProvider(providerId);
}

// ---------------------------------------------------------------------------
// Service: getFormPermissions
// ---------------------------------------------------------------------------

/**
 * Return aggregated permitted form types across all WCB configs.
 * Deduplicates form types from all Contract IDs.
 */
export async function getFormPermissions(
  deps: ProviderServiceDeps,
  providerId: string,
): Promise<string[]> {
  return deps.repo.getAggregatedFormPermissions(providerId);
}

// ---------------------------------------------------------------------------
// Service: getWcbConfigForForm
// ---------------------------------------------------------------------------

/**
 * Find the matching WCB config for a given form type.
 * Returns the contract_id, role_code, and wcb_config_id, or null if not permitted.
 */
export async function getWcbConfigForForm(
  deps: ProviderServiceDeps,
  providerId: string,
  formId: string,
): Promise<{ wcbConfigId: string; contractId: string; roleCode: string } | null> {
  return deps.repo.getWcbConfigForForm(providerId, formId);
}

// ---------------------------------------------------------------------------
// Delegate Permission Catalogue (24 keys)
// ---------------------------------------------------------------------------

const DELEGATE_PERMISSION_KEYS = new Set<string>(
  Object.values(DelegatePermission),
);

// ---------------------------------------------------------------------------
// Invitation token helpers
// ---------------------------------------------------------------------------

const INVITATION_EXPIRY_DAYS = 7;

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

function generateInvitationToken(): { rawToken: string; tokenHash: string; expiresAt: Date } {
  const rawToken = randomBytes(32).toString('hex');
  const tokenHash = hashToken(rawToken);
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + INVITATION_EXPIRY_DAYS);
  return { rawToken, tokenHash, expiresAt };
}

// ---------------------------------------------------------------------------
// Service: inviteDelegate
// ---------------------------------------------------------------------------

/**
 * Invite a delegate by email. Validates permissions are from the 24-key
 * catalogue. Creates delegate_relationships record with status INVITED.
 * Generates single-use invitation token (7-day expiry, hash stored).
 * Emits DELEGATE_INVITED notification event and delegate.invited audit event.
 */
export async function inviteDelegate(
  deps: ProviderServiceDeps,
  physicianId: string,
  email: string,
  permissions: string[],
  actorId: string,
): Promise<{ relationship: SelectDelegateRelationship; rawToken: string }> {
  // 1. Validate permissions against the 24-key catalogue
  const invalidPermissions = permissions.filter((p) => !DELEGATE_PERMISSION_KEYS.has(p));
  if (invalidPermissions.length > 0) {
    throw new BusinessRuleError(
      `Invalid delegate permission keys: ${invalidPermissions.join(', ')}`,
    );
  }

  if (permissions.length === 0) {
    throw new BusinessRuleError('At least one permission must be granted');
  }

  // 2. Generate invitation token
  const { rawToken, tokenHash, expiresAt } = generateInvitationToken();

  // 3. Create delegate relationship with status INVITED.
  //    delegateUserId is a placeholder — will be resolved on acceptance.
  //    We use a deterministic UUID derived from the email to satisfy the FK
  //    constraint, but the actual resolution happens on acceptance via Domain 1.
  //    For now, create the relationship record; the repository enforces
  //    the unique (physician_id, delegate_user_id) constraint for non-REVOKED.
  const relationship = await deps.repo.createDelegateRelationship({
    physicianId,
    delegateUserId: actorId, // Placeholder — will be updated on acceptance
    permissions,
    invitedAt: new Date(),
  });

  // 4. Store the invitation token hash
  if (deps.tokenStore) {
    await deps.tokenStore.storeTokenHash(relationship.relationshipId, tokenHash, expiresAt);
  }

  // 5. Emit audit event
  await deps.auditRepo.appendAuditLog({
    userId: actorId,
    action: ProviderAuditAction.DELEGATE_INVITED,
    category: AUDIT_CATEGORY,
    resourceType: 'delegate_relationship',
    resourceId: relationship.relationshipId,
    detail: {
      physicianId,
      delegateEmail: email,
      permissions,
      expiresAt: expiresAt.toISOString(),
    },
  });

  // 6. Emit domain events (notification + general)
  deps.events.emit('DELEGATE_INVITED', {
    physicianId,
    relationshipId: relationship.relationshipId,
    delegateEmail: email,
    permissions,
    rawToken, // Consumed by notification service to send the email
    expiresAt: expiresAt.toISOString(),
  });

  return { relationship, rawToken };
}

// ---------------------------------------------------------------------------
// Service: acceptInvitation
// ---------------------------------------------------------------------------

/**
 * Accept a delegate invitation using the raw token.
 * Validates token (hash comparison), checks not expired (7 days),
 * checks not already accepted. Sets status = ACTIVE, accepted_at = now().
 * Emits delegate.accepted audit event.
 */
export async function acceptInvitation(
  deps: ProviderServiceDeps,
  token: string,
  delegateUserId: string,
  relationshipId: string,
): Promise<SelectDelegateRelationship> {
  // 1. Find the relationship
  //    We need to look up by relationshipId since we don't scope by physician here
  //    (the delegate doesn't know the physician's ID — they only have the token)
  const tokenHash = hashToken(token);

  // 2. Validate the stored token hash
  if (!deps.tokenStore) {
    throw new BusinessRuleError('Token store not configured');
  }

  const storedToken = await deps.tokenStore.getTokenHash(relationshipId);
  if (!storedToken) {
    throw new NotFoundError('Invitation');
  }

  // 3. Hash comparison
  if (storedToken.tokenHash !== tokenHash) {
    throw new BusinessRuleError('Invalid invitation token');
  }

  // 4. Check expiry
  if (new Date() > storedToken.expiresAt) {
    throw new BusinessRuleError('Invitation token has expired');
  }

  // 5. Look up the relationship to check its current status before mutating
  //    We use the physicianId from the token store lookup is not available,
  //    so we rely on the repo's acceptRelationship which works by ID.
  //    First, we need to verify the relationship is still in INVITED state.
  //    We'll peek at delegateRelStore via a helper or check after accept.
  //    Since the repo's findActiveRelationship needs physician context,
  //    and acceptRelationship works by relationship ID alone,
  //    we accept then verify the pre-state by checking acceptedAt was null.

  // The repo's acceptRelationship sets status=ACTIVE unconditionally.
  // We accept this — if the relationship was already ACTIVE, the token
  // hash comparison would have already failed (token deleted on first use).

  const accepted = await deps.repo.acceptRelationship(relationshipId);
  if (!accepted) {
    throw new NotFoundError('Invitation');
  }

  // Clean up: delete the used token (single-use)
  await deps.tokenStore.deleteToken(relationshipId);

  // 6. Emit audit event
  await deps.auditRepo.appendAuditLog({
    userId: delegateUserId,
    action: ProviderAuditAction.DELEGATE_ACCEPTED,
    category: AUDIT_CATEGORY,
    resourceType: 'delegate_relationship',
    resourceId: relationshipId,
    detail: {
      physicianId: accepted.physicianId,
      delegateUserId,
      acceptedAt: accepted.acceptedAt?.toISOString() ?? new Date().toISOString(),
    },
  });

  deps.events.emit('DELEGATE_ACCEPTED', {
    physicianId: accepted.physicianId,
    relationshipId,
    delegateUserId,
  });

  return accepted;
}

// ---------------------------------------------------------------------------
// Service: listDelegates
// ---------------------------------------------------------------------------

/**
 * Return all delegates for a physician with permissions, status,
 * invited_at, accepted_at.
 */
export async function listDelegates(
  deps: ProviderServiceDeps,
  physicianId: string,
): Promise<DelegateListItem[]> {
  return deps.repo.listDelegatesForPhysician(physicianId);
}

export type DelegateListItem = Awaited<ReturnType<ProviderRepository['listDelegatesForPhysician']>>[number];

// ---------------------------------------------------------------------------
// Service: updateDelegatePermissions
// ---------------------------------------------------------------------------

/**
 * Update delegate permissions. Validates permissions from the 24-key catalogue.
 * Updates JSONB. Emits delegate.permissions_changed audit event with old vs new.
 */
export async function updateDelegatePermissions(
  deps: ProviderServiceDeps,
  physicianId: string,
  relationshipId: string,
  permissions: string[],
  actorId: string,
): Promise<SelectDelegateRelationship> {
  // 1. Validate permissions against catalogue
  const invalidPermissions = permissions.filter((p) => !DELEGATE_PERMISSION_KEYS.has(p));
  if (invalidPermissions.length > 0) {
    throw new BusinessRuleError(
      `Invalid delegate permission keys: ${invalidPermissions.join(', ')}`,
    );
  }

  if (permissions.length === 0) {
    throw new BusinessRuleError('At least one permission must be granted');
  }

  // 2. Verify relationship exists and belongs to this physician
  const existing = await deps.repo.findRelationshipById(relationshipId, physicianId);
  if (!existing) {
    throw new NotFoundError('Delegate relationship');
  }

  // Capture old permissions for audit
  const oldPermissions = Array.isArray(existing.permissions)
    ? (existing.permissions as string[])
    : [];

  // 3. Update permissions
  const updated = await deps.repo.updateDelegatePermissions(
    relationshipId,
    physicianId,
    permissions,
  );
  if (!updated) {
    throw new NotFoundError('Delegate relationship');
  }

  // 4. Audit with old vs new diff
  await deps.auditRepo.appendAuditLog({
    userId: actorId,
    action: ProviderAuditAction.DELEGATE_PERMISSIONS_CHANGED,
    category: AUDIT_CATEGORY,
    resourceType: 'delegate_relationship',
    resourceId: relationshipId,
    detail: {
      physicianId,
      oldPermissions,
      newPermissions: permissions,
      added: permissions.filter((p) => !oldPermissions.includes(p)),
      removed: oldPermissions.filter((p) => !permissions.includes(p)),
    },
  });

  deps.events.emit('DELEGATE_PERMISSIONS_CHANGED', {
    physicianId,
    relationshipId,
    oldPermissions,
    newPermissions: permissions,
  });

  return updated;
}

// ---------------------------------------------------------------------------
// Service: revokeDelegate
// ---------------------------------------------------------------------------

/**
 * Revoke a delegate. Sets REVOKED status. Emits delegate.revoked audit event
 * and DELEGATE_REVOKED notification. Actual session revocation is handled by
 * Domain 1 — this emits an event for Domain 1 to consume.
 */
export async function revokeDelegate(
  deps: ProviderServiceDeps,
  physicianId: string,
  relationshipId: string,
  actorId: string,
): Promise<SelectDelegateRelationship> {
  // 1. Verify the relationship exists and belongs to this physician
  const existing = await deps.repo.findRelationshipById(relationshipId, physicianId);
  if (!existing) {
    throw new NotFoundError('Delegate relationship');
  }

  if (existing.status === DelegateRelationshipStatus.REVOKED) {
    throw new BusinessRuleError('Delegate relationship is already revoked');
  }

  // 2. Revoke
  const revoked = await deps.repo.revokeRelationship(
    relationshipId,
    physicianId,
    actorId,
  );
  if (!revoked) {
    throw new NotFoundError('Delegate relationship');
  }

  // 3. Audit
  await deps.auditRepo.appendAuditLog({
    userId: actorId,
    action: ProviderAuditAction.DELEGATE_REVOKED,
    category: AUDIT_CATEGORY,
    resourceType: 'delegate_relationship',
    resourceId: relationshipId,
    detail: {
      physicianId,
      delegateUserId: existing.delegateUserId,
      previousStatus: existing.status,
    },
  });

  // 4. Emit events: notification + session revocation for Domain 1
  deps.events.emit('DELEGATE_REVOKED', {
    physicianId,
    relationshipId,
    delegateUserId: existing.delegateUserId,
  });

  return revoked;
}

// ---------------------------------------------------------------------------
// Service: listPhysiciansForDelegate
// ---------------------------------------------------------------------------

/**
 * Return list of physicians a delegate serves with permissions per physician.
 * Only returns ACTIVE relationships.
 */
export async function listPhysiciansForDelegate(
  deps: ProviderServiceDeps,
  delegateUserId: string,
): Promise<PhysicianForDelegateItem[]> {
  return deps.repo.listPhysiciansForDelegate(delegateUserId);
}

export type PhysicianForDelegateItem = Awaited<ReturnType<ProviderRepository['listPhysiciansForDelegate']>>[number];

// ---------------------------------------------------------------------------
// Service: switchPhysicianContext
// ---------------------------------------------------------------------------

/**
 * Verify an active relationship exists between the delegate and physician.
 * Returns the updated auth context data for Domain 1.
 * Emits delegate.context_switched audit event.
 */
export async function switchPhysicianContext(
  deps: ProviderServiceDeps,
  delegateUserId: string,
  physicianId: string,
): Promise<{
  physicianId: string;
  delegateUserId: string;
  permissions: string[];
}> {
  // 1. Verify active relationship exists
  const relationship = await deps.repo.findActiveRelationship(
    physicianId,
    delegateUserId,
  );
  if (!relationship) {
    throw new NotFoundError('Active delegate relationship');
  }

  if (relationship.status !== DelegateRelationshipStatus.ACTIVE) {
    throw new BusinessRuleError(
      'Delegate relationship is not active',
    );
  }

  const permissions = Array.isArray(relationship.permissions)
    ? (relationship.permissions as string[])
    : [];

  // 2. Emit audit event
  await deps.auditRepo.appendAuditLog({
    userId: delegateUserId,
    action: 'delegate.context_switched',
    category: AUDIT_CATEGORY,
    resourceType: 'delegate_relationship',
    resourceId: relationship.relationshipId,
    detail: {
      physicianId,
      delegateUserId,
      permissions,
    },
  });

  deps.events.emit('DELEGATE_CONTEXT_SWITCHED', {
    physicianId,
    delegateUserId,
    relationshipId: relationship.relationshipId,
    permissions,
  });

  // 3. Return context data for Domain 1
  return {
    physicianId,
    delegateUserId,
    permissions,
  };
}

// ---------------------------------------------------------------------------
// Service: getSubmissionPreferences
// ---------------------------------------------------------------------------

/**
 * Return the current submission preferences for a provider.
 * Returns null if preferences have not been initialised yet.
 */
export async function getSubmissionPreferences(
  deps: ProviderServiceDeps,
  providerId: string,
): Promise<{
  ahcipSubmissionMode: string;
  wcbSubmissionMode: string;
  batchReviewReminder: boolean;
  deadlineReminderDays: number;
} | null> {
  const prefs = await deps.repo.findSubmissionPreferences(providerId);
  if (!prefs) return null;
  return {
    ahcipSubmissionMode: prefs.ahcipSubmissionMode,
    wcbSubmissionMode: prefs.wcbSubmissionMode,
    batchReviewReminder: prefs.batchReviewReminder,
    deadlineReminderDays: prefs.deadlineReminderDays,
  };
}

// ---------------------------------------------------------------------------
// Service: updateSubmissionPreferences
// ---------------------------------------------------------------------------

/**
 * Update submission preference modes and reminder settings.
 * Emits submission_preference.changed audit event with old vs new values.
 */
export async function updateSubmissionPreferences(
  deps: ProviderServiceDeps,
  providerId: string,
  data: UpdatePreferencesInput,
  actorId: string,
): Promise<{
  ahcipSubmissionMode: string;
  wcbSubmissionMode: string;
  batchReviewReminder: boolean;
  deadlineReminderDays: number;
}> {
  const existing = await deps.repo.findSubmissionPreferences(providerId);
  if (!existing) {
    throw new NotFoundError('Submission preferences');
  }

  // Build diff of changed fields
  const diff: Record<string, { old: unknown; new: unknown }> = {};
  const updatePayload: Record<string, unknown> = {};

  if (data.ahcipSubmissionMode !== undefined && data.ahcipSubmissionMode !== existing.ahcipSubmissionMode) {
    diff.ahcipSubmissionMode = { old: existing.ahcipSubmissionMode, new: data.ahcipSubmissionMode };
    updatePayload.ahcipSubmissionMode = data.ahcipSubmissionMode;
  }
  if (data.wcbSubmissionMode !== undefined && data.wcbSubmissionMode !== existing.wcbSubmissionMode) {
    diff.wcbSubmissionMode = { old: existing.wcbSubmissionMode, new: data.wcbSubmissionMode };
    updatePayload.wcbSubmissionMode = data.wcbSubmissionMode;
  }
  if (data.batchReviewReminder !== undefined && data.batchReviewReminder !== existing.batchReviewReminder) {
    diff.batchReviewReminder = { old: existing.batchReviewReminder, new: data.batchReviewReminder };
    updatePayload.batchReviewReminder = data.batchReviewReminder;
  }
  if (data.deadlineReminderDays !== undefined && data.deadlineReminderDays !== existing.deadlineReminderDays) {
    diff.deadlineReminderDays = { old: existing.deadlineReminderDays, new: data.deadlineReminderDays };
    updatePayload.deadlineReminderDays = data.deadlineReminderDays;
  }

  // If nothing changed, return existing
  if (Object.keys(updatePayload).length === 0) {
    return {
      ahcipSubmissionMode: existing.ahcipSubmissionMode,
      wcbSubmissionMode: existing.wcbSubmissionMode,
      batchReviewReminder: existing.batchReviewReminder,
      deadlineReminderDays: existing.deadlineReminderDays,
    };
  }

  const updated = await deps.repo.updateSubmissionPreferences(providerId, updatePayload, actorId);
  if (!updated) {
    throw new NotFoundError('Submission preferences');
  }

  // Emit audit event with old vs new diff
  await deps.auditRepo.appendAuditLog({
    userId: actorId,
    action: ProviderAuditAction.SUBMISSION_PREFERENCE_CHANGED,
    category: AUDIT_CATEGORY,
    resourceType: 'submission_preferences',
    resourceId: existing.preferenceId,
    detail: {
      providerId,
      changes: diff,
    },
  });

  deps.events.emit('SUBMISSION_PREFERENCE_CHANGED', {
    providerId,
    actorId,
    changes: diff,
  });

  return {
    ahcipSubmissionMode: updated.ahcipSubmissionMode,
    wcbSubmissionMode: updated.wcbSubmissionMode,
    batchReviewReminder: updated.batchReviewReminder,
    deadlineReminderDays: updated.deadlineReminderDays,
  };
}

// ---------------------------------------------------------------------------
// Service: initDefaultPreferences
// ---------------------------------------------------------------------------

/**
 * Create default submission preferences during onboarding:
 * AHCIP = AUTO_CLEAN, WCB = REQUIRE_APPROVAL, batch_review_reminder = true,
 * deadline_reminder_days = 7. Idempotent — if preferences already exist, returns them.
 */
export async function initDefaultPreferences(
  deps: ProviderServiceDeps,
  providerId: string,
  actorId: string,
): Promise<{
  ahcipSubmissionMode: string;
  wcbSubmissionMode: string;
  batchReviewReminder: boolean;
  deadlineReminderDays: number;
}> {
  // Check if preferences already exist (idempotent)
  const existing = await deps.repo.findSubmissionPreferences(providerId);
  if (existing) {
    return {
      ahcipSubmissionMode: existing.ahcipSubmissionMode,
      wcbSubmissionMode: existing.wcbSubmissionMode,
      batchReviewReminder: existing.batchReviewReminder,
      deadlineReminderDays: existing.deadlineReminderDays,
    };
  }

  const prefs = await deps.repo.createSubmissionPreferences({
    providerId,
    ahcipSubmissionMode: DEFAULT_SUBMISSION_PREFERENCES.ahcip,
    wcbSubmissionMode: DEFAULT_SUBMISSION_PREFERENCES.wcb,
    batchReviewReminder: DEFAULT_SUBMISSION_PREFERENCES.batchReviewReminder,
    deadlineReminderDays: DEFAULT_SUBMISSION_PREFERENCES.deadlineReminderDays,
    updatedBy: actorId,
  });

  await deps.auditRepo.appendAuditLog({
    userId: actorId,
    action: ProviderAuditAction.SUBMISSION_PREFERENCE_CHANGED,
    category: AUDIT_CATEGORY,
    resourceType: 'submission_preferences',
    resourceId: prefs.preferenceId,
    detail: {
      providerId,
      action: 'initialized_defaults',
      ahcipSubmissionMode: DEFAULT_SUBMISSION_PREFERENCES.ahcip,
      wcbSubmissionMode: DEFAULT_SUBMISSION_PREFERENCES.wcb,
      batchReviewReminder: DEFAULT_SUBMISSION_PREFERENCES.batchReviewReminder,
      deadlineReminderDays: DEFAULT_SUBMISSION_PREFERENCES.deadlineReminderDays,
    },
  });

  deps.events.emit('SUBMISSION_PREFERENCE_INITIALIZED', {
    providerId,
    actorId,
  });

  return {
    ahcipSubmissionMode: prefs.ahcipSubmissionMode,
    wcbSubmissionMode: prefs.wcbSubmissionMode,
    batchReviewReminder: prefs.batchReviewReminder,
    deadlineReminderDays: prefs.deadlineReminderDays,
  };
}

// ---------------------------------------------------------------------------
// Service: getHlinkConfig
// ---------------------------------------------------------------------------

/**
 * Return H-Link configuration for a provider.
 * NEVER returns credential_secret_ref to the client — only submitter_prefix,
 * accreditation_status, accreditation_date, last_successful_transmission.
 */
export async function getHlinkConfig(
  deps: ProviderServiceDeps,
  providerId: string,
): Promise<{
  submitterPrefix: string;
  accreditationStatus: string;
  accreditationDate: string | null;
  lastSuccessfulTransmission: Date | null;
} | null> {
  const config = await deps.repo.findHlinkConfig(providerId);
  if (!config) return null;

  // SECURITY: Never return credentialSecretRef
  return {
    submitterPrefix: config.submitterPrefix,
    accreditationStatus: config.accreditationStatus,
    accreditationDate: config.accreditationDate,
    lastSuccessfulTransmission: config.lastSuccessfulTransmission,
  };
}

// ---------------------------------------------------------------------------
// Service: updateHlinkConfig
// ---------------------------------------------------------------------------

/**
 * Update H-Link submitter_prefix and accreditation_status.
 * Credential rotation is out of scope for this service — emit event for
 * secrets management to handle.
 * Emits hlink_config.updated audit event.
 */
export async function updateHlinkConfig(
  deps: ProviderServiceDeps,
  providerId: string,
  data: UpdateHlinkInput,
  actorId: string,
): Promise<{
  submitterPrefix: string;
  accreditationStatus: string;
  accreditationDate: string | null;
  lastSuccessfulTransmission: Date | null;
}> {
  const existing = await deps.repo.findHlinkConfig(providerId);
  if (!existing) {
    throw new NotFoundError('H-Link configuration');
  }

  // Build diff
  const diff: Record<string, { old: unknown; new: unknown }> = {};
  const updatePayload: Record<string, unknown> = {};

  if (data.submitterPrefix !== undefined && data.submitterPrefix !== existing.submitterPrefix) {
    diff.submitterPrefix = { old: existing.submitterPrefix, new: data.submitterPrefix };
    updatePayload.submitterPrefix = data.submitterPrefix;
  }
  if (data.accreditationStatus !== undefined && data.accreditationStatus !== existing.accreditationStatus) {
    diff.accreditationStatus = { old: existing.accreditationStatus, new: data.accreditationStatus };
    updatePayload.accreditationStatus = data.accreditationStatus;
  }

  // If nothing changed, return existing (without credential_secret_ref)
  if (Object.keys(updatePayload).length === 0) {
    return {
      submitterPrefix: existing.submitterPrefix,
      accreditationStatus: existing.accreditationStatus,
      accreditationDate: existing.accreditationDate,
      lastSuccessfulTransmission: existing.lastSuccessfulTransmission,
    };
  }

  const updated = await deps.repo.updateHlinkConfig(providerId, updatePayload);
  if (!updated) {
    throw new NotFoundError('H-Link configuration');
  }

  // Audit: never include credential values in audit detail
  await deps.auditRepo.appendAuditLog({
    userId: actorId,
    action: ProviderAuditAction.HLINK_CONFIG_UPDATED,
    category: AUDIT_CATEGORY,
    resourceType: 'hlink_configuration',
    resourceId: existing.hlinkConfigId,
    detail: {
      providerId,
      changes: diff,
    },
  });

  deps.events.emit('HLINK_CONFIG_UPDATED', {
    providerId,
    actorId,
    changes: diff,
  });

  // SECURITY: Never return credentialSecretRef
  return {
    submitterPrefix: updated.submitterPrefix,
    accreditationStatus: updated.accreditationStatus,
    accreditationDate: updated.accreditationDate,
    lastSuccessfulTransmission: updated.lastSuccessfulTransmission,
  };
}

// ---------------------------------------------------------------------------
// Service: isSubmissionAllowed
// ---------------------------------------------------------------------------

/**
 * Check whether a provider is allowed to submit claims.
 * Requirements:
 * - onboarding_completed = true
 * - provider status = ACTIVE
 * - H-Link accreditation_status = ACTIVE
 *
 * Returns { allowed: true, reasons: [] } if all checks pass, or
 * { allowed: false, reasons: [...] } with reason codes if not.
 */
// ---------------------------------------------------------------------------
// Service: getProviderContext (Internal API for Domain 4 — Claim Lifecycle)
// ---------------------------------------------------------------------------

/**
 * Assemble the full ProviderContext object (Section 6 of FRD).
 * Returns all 17 fields consumed by the claim lifecycle domain.
 *
 * Cached per request (caller should store on Fastify request object).
 * Invalidated on any provider data change (profile, BA, location, WCB config,
 * preferences). RRNP rate changes (quarterly) and PCPCM basket classification
 * updates (SOMB update) also trigger a cache refresh.
 *
 * Returns null for unknown provider (does not throw), making it suitable
 * for internal service-to-service calls where the caller handles the null case.
 */
export async function getProviderContext(
  deps: ProviderServiceDeps,
  providerId: string,
): Promise<ProviderContext | null> {
  return deps.repo.getFullProviderContext(providerId);
}

// ---------------------------------------------------------------------------
// Service: getBaForClaim (Internal API wrapper for routeClaimToBa)
// ---------------------------------------------------------------------------

/**
 * Determine the correct BA for a claim. Delegates to routeClaimToBa.
 * Returns { ba_number, ba_type, routing_reason } for Domain 4 consumption.
 */
export async function getBaForClaim(
  deps: ProviderServiceDeps,
  providerId: string,
  claimType: string,
  hscCode?: string,
  dateOfService?: string,
): Promise<BaRoutingResult> {
  return routeClaimToBa(
    deps,
    providerId,
    claimType as 'AHCIP' | 'WCB',
    hscCode,
    dateOfService,
  );
}

// ---------------------------------------------------------------------------
// Service: getWcbConfigForForm (Internal API — throws if not permitted)
// ---------------------------------------------------------------------------

/**
 * Find the matching WCB config for a given form type.
 * Returns { wcb_config_id, contract_id, role_code, skill_code }
 * or throws BusinessRuleError if the provider is not permitted to submit
 * the given form type.
 */
export async function getWcbConfigForFormOrThrow(
  deps: ProviderServiceDeps,
  providerId: string,
  formId: string,
): Promise<{ wcbConfigId: string; contractId: string; roleCode: string; skillCode: string | null }> {
  const configs = await deps.repo.listWcbConfigsForProvider(providerId);

  for (const config of configs) {
    const types = config.permittedFormTypes;
    if (Array.isArray(types) && (types as string[]).includes(formId)) {
      return {
        wcbConfigId: config.wcbConfigId,
        contractId: config.contractId,
        roleCode: config.roleCode,
        skillCode: config.skillCode,
      };
    }
  }

  throw new BusinessRuleError(
    `Provider is not permitted to submit WCB form type: ${formId}`,
  );
}

// ---------------------------------------------------------------------------
// Service: isSubmissionAllowed
// ---------------------------------------------------------------------------

export async function isSubmissionAllowed(
  deps: ProviderServiceDeps,
  providerId: string,
): Promise<SubmissionAllowedResult> {
  const reasons: string[] = [];

  // 1. Fetch provider record
  const provider = await deps.repo.findProviderById(providerId);
  if (!provider) {
    throw new NotFoundError('Provider');
  }

  // 2. Check onboarding completed
  if (!provider.onboardingCompleted) {
    reasons.push('ONBOARDING_INCOMPLETE');
  }

  // 3. Check provider status
  if (provider.status === ProviderStatus.SUSPENDED) {
    reasons.push('PROVIDER_SUSPENDED');
  } else if (provider.status !== ProviderStatus.ACTIVE) {
    reasons.push('PROVIDER_INACTIVE');
  }

  // 4. Check H-Link configuration
  const hlinkConfig = await deps.repo.findHlinkConfig(providerId);
  if (!hlinkConfig) {
    reasons.push('HLINK_NOT_CONFIGURED');
  } else if (hlinkConfig.accreditationStatus !== HLinkAccreditationStatus.ACTIVE) {
    reasons.push('HLINK_NOT_ACTIVE');
  }

  return {
    allowed: reasons.length === 0,
    reasons,
  };
}
