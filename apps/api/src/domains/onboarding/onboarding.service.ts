import { createHash } from 'node:crypto';
import type { OnboardingRepository } from './onboarding.repository.js';
import type { SelectOnboardingProgress } from '@meritum/shared/schemas/db/onboarding.schema.js';
import type {
  OnboardingStep1,
  OnboardingStep2,
  OnboardingStep3,
  OnboardingStep4,
  OnboardingStep5,
  OnboardingStep6,
} from '@meritum/shared/schemas/onboarding.schema.js';
import {
  REQUIRED_ONBOARDING_STEPS,
  OnboardingStep,
  OnboardingAuditAction,
  BALinkageStatus,
  IMA_TEMPLATE_VERSION,
} from '@meritum/shared/constants/onboarding.constants.js';
import { ValidationError, BusinessRuleError, NotFoundError } from '../../lib/errors.js';

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

export interface ProviderService {
  createOrUpdateProvider(providerId: string, data: {
    billingNumber: string;
    cpsaRegistrationNumber: string;
    firstName: string;
    lastName: string;
  }): Promise<{ providerId: string }>;
  updateProviderSpecialty(providerId: string, data: {
    specialtyCode: string;
    physicianType: string;
  }): Promise<void>;
  createBa(providerId: string, data: {
    baNumber: string;
    baType: string;
    isPrimary: boolean;
    status: string;
  }): Promise<{ baId: string }>;
  createLocation(providerId: string, data: {
    name: string;
    functionalCentre: string;
    facilityNumber: string | null;
    addressLine1: string;
    addressLine2: string | null;
    city: string;
    province: string;
    postalCode: string;
    communityCode: string;
    rrnpEligible: boolean;
    rrnpRate: string | null;
    isDefault: boolean;
  }): Promise<{ locationId: string }>;
  createWcbConfig(providerId: string, data: {
    contractId: string;
    roleCode: string;
    skillCode: string | null;
    permittedFormTypes: string[];
  }): Promise<{ wcbConfigId: string }>;
  updateSubmissionPreferences(providerId: string, data: {
    ahcipSubmissionMode: string;
    wcbSubmissionMode: string;
  }): Promise<void>;
  findProviderByUserId(userId: string): Promise<{ providerId: string } | null>;
  getProviderDetails(providerId: string): Promise<{
    billingNumber: string;
    cpsaRegistrationNumber: string;
    firstName: string;
    lastName: string;
    baNumbers: string[];
  } | null>;
  findBaById(baId: string, providerId: string): Promise<{
    baId: string;
    providerId: string;
    status: string;
  } | null>;
  updateBaStatus(
    providerId: string,
    baId: string,
    status: string,
    actorId: string,
  ): Promise<{ baId: string; status: string }>;
}

export interface ReferenceDataService {
  validateSpecialtyCode(code: string): Promise<boolean>;
  validateFunctionalCentreCode(code: string): Promise<boolean>;
  validateCommunityCode(code: string): Promise<boolean>;
  getRrnpRate(communityCode: string): Promise<{ rrnpPercentage: string } | null>;
  getWcbFormTypes(role: string, skillCode: string): Promise<string[]>;
}

export interface TemplateRenderer {
  render(template: string, data: Record<string, unknown>): string;
}

export interface PdfGenerator {
  htmlToPdf(html: string): Promise<Buffer>;
  generateAhc11236(data: {
    billingNumber: string;
    baNumber: string;
    submitterPrefix: string;
    physicianName: string;
  }): Promise<Buffer>;
}

export interface FileStorage {
  store(key: string, data: Buffer, contentType: string): Promise<void>;
  retrieve(key: string): Promise<Buffer>;
}

export interface OnboardingServiceDeps {
  repo: OnboardingRepository;
  auditRepo: AuditRepo;
  events: EventEmitter;
  providerService: ProviderService;
  referenceData: ReferenceDataService;
  templateRenderer?: TemplateRenderer;
  pdfGenerator?: PdfGenerator;
  fileStorage?: FileStorage;
  imaTemplate?: string;
  piaPdfBuffer?: Buffer;
  submitterPrefix?: string;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const AUDIT_CATEGORY = 'onboarding';

// Step column mapping for computed fields
const stepColumnMap: Record<number, keyof SelectOnboardingProgress> = {
  1: 'step1Completed',
  2: 'step2Completed',
  3: 'step3Completed',
  4: 'step4Completed',
  5: 'step5Completed',
  6: 'step6Completed',
  7: 'step7Completed',
};

// ---------------------------------------------------------------------------
// Computed progress fields
// ---------------------------------------------------------------------------

export interface ComputedProgress {
  progress: SelectOnboardingProgress;
  current_step: number | null;
  is_complete: boolean;
  required_steps_remaining: number;
}

function computeProgressFields(progress: SelectOnboardingProgress): ComputedProgress {
  const requiredSteps = Array.from(REQUIRED_ONBOARDING_STEPS);

  let firstIncomplete: number | null = null;
  let remainingCount = 0;

  for (const step of requiredSteps) {
    const col = stepColumnMap[step];
    if (col && !progress[col]) {
      remainingCount++;
      if (firstIncomplete === null) {
        firstIncomplete = step;
      }
    }
  }

  return {
    progress,
    current_step: firstIncomplete,
    is_complete: remainingCount === 0,
    required_steps_remaining: remainingCount,
  };
}

// ---------------------------------------------------------------------------
// Service: getOrCreateProgress
// ---------------------------------------------------------------------------

export async function getOrCreateProgress(
  deps: OnboardingServiceDeps,
  providerId: string,
): Promise<ComputedProgress> {
  let progress = await deps.repo.findProgressByProviderId(providerId);

  if (!progress) {
    progress = await deps.repo.createProgress(providerId);

    await deps.auditRepo.appendAuditLog({
      action: OnboardingAuditAction.STARTED,
      category: AUDIT_CATEGORY,
      resourceType: 'onboarding_progress',
      resourceId: progress.progressId,
      detail: { provider_id: providerId },
    });
  }

  return computeProgressFields(progress);
}

// ---------------------------------------------------------------------------
// Service: getOnboardingStatus
// ---------------------------------------------------------------------------

export interface OnboardingStatus {
  has_provider: boolean;
  progress: SelectOnboardingProgress | null;
  is_complete: boolean;
  ba_status: string | null;
}

export async function getOnboardingStatus(
  deps: OnboardingServiceDeps,
  userId: string,
): Promise<OnboardingStatus> {
  const provider = await deps.providerService.findProviderByUserId(userId);

  if (!provider) {
    return {
      has_provider: false,
      progress: null,
      is_complete: false,
      ba_status: null,
    };
  }

  const progress = await deps.repo.findProgressByProviderId(provider.providerId);

  if (!progress) {
    return {
      has_provider: true,
      progress: null,
      is_complete: false,
      ba_status: null,
    };
  }

  const isComplete = progress.completedAt !== null;

  return {
    has_provider: true,
    progress,
    is_complete: isComplete,
    ba_status: null,
  };
}

// ---------------------------------------------------------------------------
// Service: completeStep1 — Professional Identity
// ---------------------------------------------------------------------------

export async function completeStep1(
  deps: OnboardingServiceDeps,
  providerId: string,
  data: OnboardingStep1,
): Promise<ComputedProgress> {
  // Validate billing number format (5-digit numeric)
  if (!/^\d{5}$/.test(data.billing_number)) {
    throw new ValidationError(
      'Billing number must be exactly 5 digits',
      { field: 'billing_number' },
    );
  }

  // Create or update provider record in Provider Management
  await deps.providerService.createOrUpdateProvider(providerId, {
    billingNumber: data.billing_number,
    cpsaRegistrationNumber: data.cpsa_number,
    firstName: data.legal_first_name,
    lastName: data.legal_last_name,
  });

  // Mark step 1 complete
  const progress = await deps.repo.markStepCompleted(
    providerId,
    OnboardingStep.PROFESSIONAL_IDENTITY,
  );

  // Emit audit event
  await deps.auditRepo.appendAuditLog({
    action: OnboardingAuditAction.STEP_COMPLETED,
    category: AUDIT_CATEGORY,
    resourceType: 'onboarding_progress',
    resourceId: progress.progressId,
    detail: { provider_id: providerId, step_number: 1 },
  });

  deps.events.emit(OnboardingAuditAction.STEP_COMPLETED, {
    providerId,
    stepNumber: 1,
  });

  return computeProgressFields(progress);
}

// ---------------------------------------------------------------------------
// Service: completeStep2 — Specialty & Type
// ---------------------------------------------------------------------------

export async function completeStep2(
  deps: OnboardingServiceDeps,
  providerId: string,
  data: OnboardingStep2,
): Promise<ComputedProgress> {
  // Validate specialty_code against Reference Data
  const validSpecialty = await deps.referenceData.validateSpecialtyCode(
    data.specialty_code,
  );
  if (!validSpecialty) {
    throw new ValidationError(
      'Invalid specialty code',
      { field: 'specialty_code', value: data.specialty_code },
    );
  }

  // Update provider with specialty and physician_type
  await deps.providerService.updateProviderSpecialty(providerId, {
    specialtyCode: data.specialty_code,
    physicianType: data.physician_type,
  });

  // Mark step 2 complete
  const progress = await deps.repo.markStepCompleted(
    providerId,
    OnboardingStep.SPECIALTY_TYPE,
  );

  await deps.auditRepo.appendAuditLog({
    action: OnboardingAuditAction.STEP_COMPLETED,
    category: AUDIT_CATEGORY,
    resourceType: 'onboarding_progress',
    resourceId: progress.progressId,
    detail: { provider_id: providerId, step_number: 2 },
  });

  deps.events.emit(OnboardingAuditAction.STEP_COMPLETED, {
    providerId,
    stepNumber: 2,
  });

  return computeProgressFields(progress);
}

// ---------------------------------------------------------------------------
// Service: completeStep3 — Business Arrangement
// ---------------------------------------------------------------------------

export async function completeStep3(
  deps: OnboardingServiceDeps,
  providerId: string,
  data: OnboardingStep3,
): Promise<ComputedProgress> {
  // If PCPCM enrolled, enforce dual-BA present
  if (data.is_pcpcm_enrolled) {
    if (!data.pcpcm_ba_number || !data.ffs_ba_number) {
      throw new BusinessRuleError(
        'PCPCM enrolment requires both pcpcm_ba_number and ffs_ba_number',
        { field: 'pcpcm_ba_number' },
      );
    }
  }

  // Create primary BA record with PENDING status
  await deps.providerService.createBa(providerId, {
    baNumber: data.primary_ba_number,
    baType: 'FFS',
    isPrimary: true,
    status: BALinkageStatus.PENDING,
  });

  // If PCPCM enrolled, create the additional BA records
  if (data.is_pcpcm_enrolled && data.pcpcm_ba_number && data.ffs_ba_number) {
    // Create FFS BA if different from primary
    if (data.ffs_ba_number !== data.primary_ba_number) {
      await deps.providerService.createBa(providerId, {
        baNumber: data.ffs_ba_number,
        baType: 'FFS',
        isPrimary: false,
        status: BALinkageStatus.PENDING,
      });
    }

    // Create PCPCM BA
    await deps.providerService.createBa(providerId, {
      baNumber: data.pcpcm_ba_number,
      baType: 'PCPCM',
      isPrimary: false,
      status: BALinkageStatus.PENDING,
    });
  }

  // Mark step 3 complete
  const progress = await deps.repo.markStepCompleted(
    providerId,
    OnboardingStep.BUSINESS_ARRANGEMENT,
  );

  await deps.auditRepo.appendAuditLog({
    action: OnboardingAuditAction.STEP_COMPLETED,
    category: AUDIT_CATEGORY,
    resourceType: 'onboarding_progress',
    resourceId: progress.progressId,
    detail: {
      provider_id: providerId,
      step_number: 3,
      is_pcpcm_enrolled: data.is_pcpcm_enrolled,
    },
  });

  deps.events.emit(OnboardingAuditAction.STEP_COMPLETED, {
    providerId,
    stepNumber: 3,
  });

  return computeProgressFields(progress);
}

// ---------------------------------------------------------------------------
// Service: completeStep4 — Practice Location
// ---------------------------------------------------------------------------

export async function completeStep4(
  deps: OnboardingServiceDeps,
  providerId: string,
  data: OnboardingStep4,
): Promise<ComputedProgress> {
  // Validate functional_centre_code against Reference Data
  const validFcc = await deps.referenceData.validateFunctionalCentreCode(
    data.functional_centre_code,
  );
  if (!validFcc) {
    throw new ValidationError(
      'Invalid functional centre code',
      { field: 'functional_centre_code', value: data.functional_centre_code },
    );
  }

  // Validate community_code against Reference Data
  const validCommunity = await deps.referenceData.validateCommunityCode(
    data.community_code,
  );
  if (!validCommunity) {
    throw new ValidationError(
      'Invalid community code',
      { field: 'community_code', value: data.community_code },
    );
  }

  // Calculate RRNP eligibility from community code
  const rrnpResult = await deps.referenceData.getRrnpRate(data.community_code);
  const rrnpEligible = rrnpResult !== null;
  const rrnpRate = rrnpResult?.rrnpPercentage ?? null;

  // Create practice location in Provider Management
  await deps.providerService.createLocation(providerId, {
    name: data.location_name,
    functionalCentre: data.functional_centre_code,
    facilityNumber: data.facility_number ?? null,
    addressLine1: data.address.street,
    addressLine2: null,
    city: data.address.city,
    province: data.address.province,
    postalCode: data.address.postal_code,
    communityCode: data.community_code,
    rrnpEligible,
    rrnpRate,
    isDefault: true,
  });

  // Mark step 4 complete
  const progress = await deps.repo.markStepCompleted(
    providerId,
    OnboardingStep.PRACTICE_LOCATION,
  );

  await deps.auditRepo.appendAuditLog({
    action: OnboardingAuditAction.STEP_COMPLETED,
    category: AUDIT_CATEGORY,
    resourceType: 'onboarding_progress',
    resourceId: progress.progressId,
    detail: {
      provider_id: providerId,
      step_number: 4,
      rrnp_eligible: rrnpEligible,
    },
  });

  deps.events.emit(OnboardingAuditAction.STEP_COMPLETED, {
    providerId,
    stepNumber: 4,
  });

  return computeProgressFields(progress);
}

// ---------------------------------------------------------------------------
// Service: completeStep5 — WCB Configuration (optional)
// ---------------------------------------------------------------------------

export async function completeStep5(
  deps: OnboardingServiceDeps,
  providerId: string,
  data: OnboardingStep5,
): Promise<ComputedProgress> {
  // Auto-populate permitted form types from role/skill
  const permittedFormTypes = await deps.referenceData.getWcbFormTypes(
    data.role,
    data.skill_code,
  );

  // Create WCB configuration in Provider Management
  await deps.providerService.createWcbConfig(providerId, {
    contractId: data.contract_id,
    roleCode: data.role,
    skillCode: data.skill_code ?? null,
    permittedFormTypes,
  });

  // Mark step 5 complete
  const progress = await deps.repo.markStepCompleted(
    providerId,
    OnboardingStep.WCB_CONFIGURATION,
  );

  await deps.auditRepo.appendAuditLog({
    action: OnboardingAuditAction.STEP_COMPLETED,
    category: AUDIT_CATEGORY,
    resourceType: 'onboarding_progress',
    resourceId: progress.progressId,
    detail: { provider_id: providerId, step_number: 5 },
  });

  deps.events.emit(OnboardingAuditAction.STEP_COMPLETED, {
    providerId,
    stepNumber: 5,
  });

  return computeProgressFields(progress);
}

// ---------------------------------------------------------------------------
// Service: completeStep6 — Submission Preferences (optional)
// ---------------------------------------------------------------------------

export async function completeStep6(
  deps: OnboardingServiceDeps,
  providerId: string,
  data: OnboardingStep6,
): Promise<ComputedProgress> {
  // Set submission preferences in Provider Management
  await deps.providerService.updateSubmissionPreferences(providerId, {
    ahcipSubmissionMode: data.ahcip_mode,
    wcbSubmissionMode: data.wcb_mode,
  });

  // Mark step 6 complete
  const progress = await deps.repo.markStepCompleted(
    providerId,
    OnboardingStep.SUBMISSION_PREFERENCES,
  );

  await deps.auditRepo.appendAuditLog({
    action: OnboardingAuditAction.STEP_COMPLETED,
    category: AUDIT_CATEGORY,
    resourceType: 'onboarding_progress',
    resourceId: progress.progressId,
    detail: { provider_id: providerId, step_number: 6 },
  });

  deps.events.emit(OnboardingAuditAction.STEP_COMPLETED, {
    providerId,
    stepNumber: 6,
  });

  return computeProgressFields(progress);
}

// ---------------------------------------------------------------------------
// Service: completeStep7 — IMA Acknowledgement
// ---------------------------------------------------------------------------

export async function completeStep7(
  deps: OnboardingServiceDeps,
  providerId: string,
  ipAddress: string,
  userAgent: string,
): Promise<ComputedProgress> {
  // Mark step 7 complete
  const progress = await deps.repo.markStepCompleted(
    providerId,
    OnboardingStep.IMA_ACKNOWLEDGEMENT,
  );

  await deps.auditRepo.appendAuditLog({
    action: OnboardingAuditAction.STEP_COMPLETED,
    category: AUDIT_CATEGORY,
    resourceType: 'onboarding_progress',
    resourceId: progress.progressId,
    detail: { provider_id: providerId, step_number: 7 },
    ipAddress,
    userAgent,
  });

  deps.events.emit(OnboardingAuditAction.STEP_COMPLETED, {
    providerId,
    stepNumber: 7,
  });

  // Check if all required steps are now done
  const computed = computeProgressFields(progress);
  if (computed.is_complete) {
    await markOnboardingCompleted(deps, providerId);
  }

  return computed;
}

// ---------------------------------------------------------------------------
// Internal: markOnboardingCompleted
// ---------------------------------------------------------------------------

async function markOnboardingCompleted(
  deps: OnboardingServiceDeps,
  providerId: string,
): Promise<void> {
  const updatedProgress = await deps.repo.markOnboardingCompleted(providerId);

  await deps.auditRepo.appendAuditLog({
    action: OnboardingAuditAction.COMPLETED,
    category: AUDIT_CATEGORY,
    resourceType: 'onboarding_progress',
    resourceId: updatedProgress.progressId,
    detail: { provider_id: providerId },
  });

  deps.events.emit(OnboardingAuditAction.COMPLETED, {
    providerId,
  });
}

// ---------------------------------------------------------------------------
// Constants for IMA / documents
// ---------------------------------------------------------------------------

const MERITUM_COMPANY_NAME = 'Meritum Health Technologies Inc.';
const MERITUM_COMPANY_ADDRESS = 'Toronto, Ontario, Canada';

// ---------------------------------------------------------------------------
// Helper: SHA-256 hash of content
// ---------------------------------------------------------------------------

function sha256(content: string): string {
  return createHash('sha256').update(content, 'utf-8').digest('hex');
}

// ---------------------------------------------------------------------------
// Helper: Storage key for IMA PDFs
// ---------------------------------------------------------------------------

function imaStorageKey(providerId: string, imaId: string): string {
  return `ima/${providerId}/${imaId}.pdf`;
}

// ---------------------------------------------------------------------------
// Service: renderIma — Generate IMA document from template
// ---------------------------------------------------------------------------

export interface RenderedIma {
  html: string;
  hash: string;
  templateVersion: string;
}

export async function renderIma(
  deps: OnboardingServiceDeps,
  providerId: string,
): Promise<RenderedIma> {
  if (!deps.templateRenderer) {
    throw new BusinessRuleError('Template renderer not configured');
  }
  if (!deps.imaTemplate) {
    throw new BusinessRuleError('IMA template not loaded');
  }

  const providerDetails = await deps.providerService.getProviderDetails(providerId);
  if (!providerDetails) {
    throw new NotFoundError('Provider');
  }

  const templateData = {
    physician_first_name: providerDetails.firstName,
    physician_last_name: providerDetails.lastName,
    cpsa_number: providerDetails.cpsaRegistrationNumber,
    ba_numbers: providerDetails.baNumbers.join(', '),
    company_name: MERITUM_COMPANY_NAME,
    company_address: MERITUM_COMPANY_ADDRESS,
    effective_date: new Date().toISOString().split('T')[0],
    template_version: IMA_TEMPLATE_VERSION,
  };

  const html = deps.templateRenderer.render(deps.imaTemplate, templateData);
  const hash = sha256(html);

  return {
    html,
    hash,
    templateVersion: IMA_TEMPLATE_VERSION,
  };
}

// ---------------------------------------------------------------------------
// Service: acknowledgeIma — Verify hash, create record, store PDF
// ---------------------------------------------------------------------------

export interface AcknowledgeImaResult {
  imaId: string;
  documentHash: string;
  templateVersion: string;
  acknowledgedAt: Date;
}

export async function acknowledgeIma(
  deps: OnboardingServiceDeps,
  providerId: string,
  clientHash: string,
  ipAddress: string,
  userAgent: string,
): Promise<AcknowledgeImaResult> {
  if (!deps.pdfGenerator) {
    throw new BusinessRuleError('PDF generator not configured');
  }
  if (!deps.fileStorage) {
    throw new BusinessRuleError('File storage not configured');
  }

  // Render IMA server-side and compute hash
  const rendered = await renderIma(deps, providerId);

  // Verify client hash matches server hash — prevents tampering
  if (clientHash !== rendered.hash) {
    throw new BusinessRuleError(
      'Document hash mismatch: the document may have been modified since it was rendered',
    );
  }

  // Create IMA record in database
  const imaRecord = await deps.repo.createImaRecord({
    providerId,
    templateVersion: rendered.templateVersion,
    documentHash: rendered.hash,
    ipAddress,
    userAgent,
  });

  // Generate PDF from rendered HTML
  const pdfBuffer = await deps.pdfGenerator.htmlToPdf(rendered.html);

  // Store PDF immutably in DigitalOcean Spaces
  const storageKey = imaStorageKey(providerId, imaRecord.imaId);
  await deps.fileStorage.store(storageKey, pdfBuffer, 'application/pdf');

  // Complete step 7 (IMA acknowledgement)
  await completeStep7(deps, providerId, ipAddress, userAgent);

  // Emit audit event
  await deps.auditRepo.appendAuditLog({
    action: OnboardingAuditAction.IMA_ACKNOWLEDGED,
    category: AUDIT_CATEGORY,
    resourceType: 'ima_record',
    resourceId: imaRecord.imaId,
    detail: {
      provider_id: providerId,
      template_version: rendered.templateVersion,
      document_hash: rendered.hash,
    },
    ipAddress,
    userAgent,
  });

  deps.events.emit(OnboardingAuditAction.IMA_ACKNOWLEDGED, {
    providerId,
    imaId: imaRecord.imaId,
    templateVersion: rendered.templateVersion,
  });

  return {
    imaId: imaRecord.imaId,
    documentHash: imaRecord.documentHash,
    templateVersion: imaRecord.templateVersion,
    acknowledgedAt: imaRecord.acknowledgedAt,
  };
}

// ---------------------------------------------------------------------------
// Service: downloadImaPdf — Retrieve stored IMA PDF
// ---------------------------------------------------------------------------

export async function downloadImaPdf(
  deps: OnboardingServiceDeps,
  providerId: string,
): Promise<Buffer> {
  if (!deps.fileStorage) {
    throw new BusinessRuleError('File storage not configured');
  }

  // Find latest IMA record for this provider
  const imaRecord = await deps.repo.findLatestImaRecord(providerId);
  if (!imaRecord) {
    throw new NotFoundError('IMA record');
  }

  // Retrieve PDF from storage
  const storageKey = imaStorageKey(providerId, imaRecord.imaId);
  const pdfBuffer = await deps.fileStorage.retrieve(storageKey);

  // Emit audit event
  await deps.auditRepo.appendAuditLog({
    action: OnboardingAuditAction.IMA_DOWNLOADED,
    category: AUDIT_CATEGORY,
    resourceType: 'ima_record',
    resourceId: imaRecord.imaId,
    detail: { provider_id: providerId },
  });

  return pdfBuffer;
}

// ---------------------------------------------------------------------------
// Service: checkImaCurrentVersion — Check if IMA needs re-acknowledgement
// ---------------------------------------------------------------------------

export interface ImaVersionCheck {
  is_current: boolean;
  needs_reacknowledgement: boolean;
}

export async function checkImaCurrentVersion(
  deps: OnboardingServiceDeps,
  providerId: string,
): Promise<ImaVersionCheck> {
  const latestRecord = await deps.repo.findLatestImaRecord(providerId);

  if (!latestRecord) {
    return {
      is_current: false,
      needs_reacknowledgement: true,
    };
  }

  const isCurrent = latestRecord.templateVersion === IMA_TEMPLATE_VERSION;

  return {
    is_current: isCurrent,
    needs_reacknowledgement: !isCurrent,
  };
}

// ---------------------------------------------------------------------------
// Service: generateAhc11236Pdf — Pre-fill AHC11236 form
// ---------------------------------------------------------------------------

export async function generateAhc11236Pdf(
  deps: OnboardingServiceDeps,
  providerId: string,
): Promise<Buffer> {
  if (!deps.pdfGenerator) {
    throw new BusinessRuleError('PDF generator not configured');
  }

  const providerDetails = await deps.providerService.getProviderDetails(providerId);
  if (!providerDetails) {
    throw new NotFoundError('Provider');
  }

  const submitterPrefix = deps.submitterPrefix ?? '';

  const pdfBuffer = await deps.pdfGenerator.generateAhc11236({
    billingNumber: providerDetails.billingNumber,
    baNumber: providerDetails.baNumbers[0] ?? '',
    submitterPrefix,
    physicianName: `Dr. ${providerDetails.firstName} ${providerDetails.lastName}`,
  });

  // Emit audit event
  await deps.auditRepo.appendAuditLog({
    action: OnboardingAuditAction.AHC11236_DOWNLOADED,
    category: AUDIT_CATEGORY,
    resourceType: 'ahc11236',
    resourceId: providerId,
    detail: { provider_id: providerId },
  });

  return pdfBuffer;
}

// ---------------------------------------------------------------------------
// Service: downloadPiaPdf — Return static PIA document
// ---------------------------------------------------------------------------

export async function downloadPiaPdf(
  deps: OnboardingServiceDeps,
): Promise<Buffer> {
  if (!deps.piaPdfBuffer) {
    throw new BusinessRuleError('PIA document not configured');
  }

  // Emit audit event
  await deps.auditRepo.appendAuditLog({
    action: OnboardingAuditAction.PIA_DOWNLOADED,
    category: AUDIT_CATEGORY,
    resourceType: 'pia',
    detail: {},
  });

  return deps.piaPdfBuffer;
}

// ---------------------------------------------------------------------------
// Service: completeGuidedTour — Mark guided tour as completed
// ---------------------------------------------------------------------------

export async function completeGuidedTour(
  deps: OnboardingServiceDeps,
  providerId: string,
): Promise<void> {
  const progress = await deps.repo.findProgressByProviderId(providerId);
  if (!progress) {
    throw new NotFoundError('Onboarding progress');
  }

  // Idempotent: if already completed, do nothing
  if (progress.guidedTourCompleted) {
    return;
  }

  await deps.repo.markGuidedTourCompleted(providerId);

  await deps.auditRepo.appendAuditLog({
    action: OnboardingAuditAction.GUIDED_TOUR_COMPLETED,
    category: AUDIT_CATEGORY,
    resourceType: 'onboarding_progress',
    resourceId: progress.progressId,
    detail: { provider_id: providerId },
  });

  deps.events.emit(OnboardingAuditAction.GUIDED_TOUR_COMPLETED, {
    providerId,
  });
}

// ---------------------------------------------------------------------------
// Service: dismissGuidedTour — Mark guided tour as dismissed
// ---------------------------------------------------------------------------

export async function dismissGuidedTour(
  deps: OnboardingServiceDeps,
  providerId: string,
): Promise<void> {
  const progress = await deps.repo.findProgressByProviderId(providerId);
  if (!progress) {
    throw new NotFoundError('Onboarding progress');
  }

  // Idempotent: if already dismissed, do nothing
  if (progress.guidedTourDismissed) {
    return;
  }

  await deps.repo.markGuidedTourDismissed(providerId);

  await deps.auditRepo.appendAuditLog({
    action: OnboardingAuditAction.GUIDED_TOUR_DISMISSED,
    category: AUDIT_CATEGORY,
    resourceType: 'onboarding_progress',
    resourceId: progress.progressId,
    detail: { provider_id: providerId },
  });

  deps.events.emit(OnboardingAuditAction.GUIDED_TOUR_DISMISSED, {
    providerId,
  });
}

// ---------------------------------------------------------------------------
// Service: shouldShowGuidedTour — Check if guided tour should be shown
// ---------------------------------------------------------------------------

export async function shouldShowGuidedTour(
  deps: OnboardingServiceDeps,
  providerId: string,
): Promise<boolean> {
  const progress = await deps.repo.findProgressByProviderId(providerId);
  if (!progress) {
    return false;
  }

  // Only show if onboarding is complete AND tour is neither completed nor dismissed
  const isOnboardingComplete = progress.completedAt !== null;
  return isOnboardingComplete && !progress.guidedTourCompleted && !progress.guidedTourDismissed;
}

// ---------------------------------------------------------------------------
// Service: completePatientImport — Track patient import completion
// ---------------------------------------------------------------------------

export async function completePatientImport(
  deps: OnboardingServiceDeps,
  providerId: string,
): Promise<void> {
  const progress = await deps.repo.findProgressByProviderId(providerId);
  if (!progress) {
    throw new NotFoundError('Onboarding progress');
  }

  await deps.repo.markPatientImportCompleted(providerId);

  await deps.auditRepo.appendAuditLog({
    action: OnboardingAuditAction.PATIENT_IMPORT_COMPLETED,
    category: AUDIT_CATEGORY,
    resourceType: 'onboarding_progress',
    resourceId: progress.progressId,
    detail: { provider_id: providerId },
  });

  deps.events.emit(OnboardingAuditAction.PATIENT_IMPORT_COMPLETED, {
    providerId,
  });
}

// ---------------------------------------------------------------------------
// Service: confirmBaActive — Update BA status from PENDING to ACTIVE
// ---------------------------------------------------------------------------

export async function confirmBaActive(
  deps: OnboardingServiceDeps,
  providerId: string,
  baId: string,
): Promise<void> {
  // Look up the BA to verify ownership and current status
  const ba = await deps.providerService.findBaById(baId, providerId);
  if (!ba) {
    throw new NotFoundError('Business arrangement');
  }

  if (ba.status !== BALinkageStatus.PENDING) {
    throw new BusinessRuleError(
      `Cannot confirm BA: current status is ${ba.status}, expected PENDING`,
    );
  }

  // Update BA status via Provider Management
  await deps.providerService.updateBaStatus(providerId, baId, BALinkageStatus.ACTIVE, providerId);

  await deps.auditRepo.appendAuditLog({
    action: OnboardingAuditAction.BA_STATUS_UPDATED,
    category: AUDIT_CATEGORY,
    resourceType: 'business_arrangement',
    resourceId: baId,
    detail: {
      provider_id: providerId,
      previous_status: BALinkageStatus.PENDING,
      new_status: BALinkageStatus.ACTIVE,
    },
  });

  deps.events.emit(OnboardingAuditAction.BA_STATUS_UPDATED, {
    providerId,
    baId,
    previousStatus: BALinkageStatus.PENDING,
    newStatus: BALinkageStatus.ACTIVE,
  });
}
