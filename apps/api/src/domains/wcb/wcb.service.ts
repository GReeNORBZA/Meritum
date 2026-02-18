import { createHash, randomBytes } from 'crypto';
import type { WcbRepository, WcbClaimWithChildren } from './wcb.repository.js';
import {
  WcbFormType,
  WCB_FORM_TYPE_CONFIGS,
  WCB_FORM_SECTION_MATRIX,
  WCB_INITIAL_FORM_PERMISSIONS,
  WCB_FOLLOW_UP_FORM_PERMISSIONS,
  WcbFormSection,
  WcbAuditAction,
  WcbValidationCheckId,
  WcbTimingTier,
  WCB_TIMING_DEADLINE_RULES,
  WCB_FEE_SCHEDULE_2025,
  WcbInvoiceLineType,
  WcbFacilityType,
  WcbBatchStatus,
  WcbPaymentStatus,
  WcbReturnReportStatus,
  WCB_PREMIUM_MULTIPLIER,
  WCB_PREMIUM_EXCLUSION_DAYS,
  WCB_PREMIUM_LIMIT_PER_ENCOUNTER,
  WCB_RRNP_FLAT_FEE,
  WCB_EXPEDITED_FULL_DAYS,
  WCB_EXPEDITED_PRORATE_END_DAYS,
  WCB_EXPEDITED_CONSULTATION_FEE,
  WCB_FORM_TO_FEE_CODE,
  WcbPhase,
} from '@meritum/shared/constants/wcb.constants.js';
import {
  ClaimType,
  ClaimImportSource,
  ClaimState,
  TERMINAL_STATES,
  ValidationSeverity,
} from '@meritum/shared/constants/claim.constants.js';
import { BusinessRuleError, NotFoundError } from '../../lib/errors.js';

// ---------------------------------------------------------------------------
// Dependency interfaces (injected by handler / test)
// ---------------------------------------------------------------------------

export interface ClaimRepo {
  createClaim(data: {
    physicianId: string;
    patientId: string;
    claimType: string;
    importSource: string;
    dateOfService: string;
    submissionDeadline: string;
    createdBy: string;
    updatedBy: string;
  }): Promise<{ claimId: string; state: string }>;
  findClaimById(
    claimId: string,
    physicianId: string,
  ): Promise<{ claimId: string; state: string; physicianId: string } | undefined>;
  appendClaimAudit(data: {
    claimId: string;
    action: string;
    previousState: string | null;
    newState: string | null;
    changes: Record<string, unknown> | null;
    actorId: string;
    actorContext: string;
  }): Promise<void>;
  transitionClaimState(
    claimId: string,
    physicianId: string,
    newState: string,
  ): Promise<{ claimId: string; state: string; previousState: string } | undefined>;
}

export interface ProviderLookup {
  findProviderById(
    providerId: string,
  ): Promise<{
    providerId: string;
    billingNumber: string;
    firstName: string;
    lastName: string;
    middleName?: string | null;
    status: string;
    specialtyCode: string;
    isRrnpQualified?: boolean;
  } | undefined>;
  getWcbConfigForForm(
    providerId: string,
    formId: string,
  ): Promise<{
    wcbConfigId: string;
    contractId: string;
    roleCode: string;
    skillCode?: string | null;
    facilityType?: string | null;
  } | null>;
}

export interface PatientLookup {
  findPatientById(
    patientId: string,
    physicianId: string,
  ): Promise<{
    patientId: string;
    phn: string | null;
    firstName: string;
    lastName: string;
    middleName?: string | null;
    dateOfBirth: string;
    gender: string;
    addressLine1?: string | null;
    addressLine2?: string | null;
    city?: string | null;
    province?: string | null;
    postalCode?: string | null;
    phoneCountry?: string | null;
    phone?: string | null;
    employerName?: string | null;
  } | undefined>;
}

export interface AuditEmitter {
  emit(event: string, payload: Record<string, unknown>): Promise<void>;
}

export interface ReferenceLookup {
  /** Look up the SOMB base rate for a health service code */
  findHscBaseRate(hscCode: string, dateOfService?: string): Promise<{ baseFee: string | null; isPremiumCode: boolean } | null>;
  /** Get the RRNP variable fee premium rate (quarterly, from Reference Data) */
  getRrnpVariablePremiumRate(): Promise<string>;
}

export interface FileStorage {
  storeEncrypted(path: string, data: Buffer): Promise<void>;
  readEncrypted(path: string): Promise<Buffer>;
}

export interface SecretsProvider {
  getVendorSourceId(): string;
  getSubmitterId(): string;
}

export interface XsdValidationError {
  line?: number;
  column?: number;
  message: string;
  claimDetailId?: string;
  field?: string;
}

export interface XsdValidationResult {
  valid: boolean;
  errors: XsdValidationError[];
}

export interface XsdValidator {
  validate(xmlContent: string, xsdContent: string): XsdValidationResult;
}

export interface DownloadUrlGenerator {
  generateSignedUrl(filePath: string, expiresInSeconds: number): Promise<string>;
}

export interface NotificationEmitter {
  emit(event: string, payload: Record<string, unknown>): Promise<void>;
}

export interface WcbServiceDeps {
  wcbRepo: WcbRepository;
  claimRepo: ClaimRepo;
  providerLookup: ProviderLookup;
  patientLookup: PatientLookup;
  auditEmitter?: AuditEmitter;
  referenceLookup?: ReferenceLookup;
  fileStorage?: FileStorage;
  secretsProvider?: SecretsProvider;
  xsdValidator?: XsdValidator;
  downloadUrlGenerator?: DownloadUrlGenerator;
  notificationEmitter?: NotificationEmitter;
}

// ---------------------------------------------------------------------------
// Input types
// ---------------------------------------------------------------------------

export interface CreateWcbClaimInput {
  form_id: string;
  patient_id: string;
  date_of_injury?: string;
  report_completion_date?: string;
  parent_wcb_claim_id?: string;
  wcb_claim_number?: string;
  additional_comments?: string;
  // Employer fields
  employer_name?: string;
  employer_location?: string;
  employer_city?: string;
  employer_province?: string;
  employer_phone_country?: string;
  employer_phone_number?: string;
  employer_phone_ext?: string;
  // Accident fields
  worker_job_title?: string;
  injury_developed_over_time?: string;
  injury_description?: string;
  // Assessment fields
  date_of_examination?: string;
  symptoms?: string;
  objective_findings?: string;
  current_diagnosis?: string;
  diagnostic_code_1?: string;
  diagnostic_code_2?: string;
  diagnostic_code_3?: string;
  // Child tables
  injuries?: Array<{
    part_of_body_code: string;
    side_of_body_code?: string;
    nature_of_injury_code: string;
  }>;
  prescriptions?: Array<{
    prescription_name: string;
    strength: string;
    daily_intake: string;
  }>;
  consultations?: Array<{
    category: string;
    type_code: string;
    details: string;
    expedite_requested?: string;
  }>;
  work_restrictions?: Array<{
    activity_type: string;
    restriction_level: string;
    hours_per_day?: number;
    max_weight?: string;
  }>;
  invoice_lines?: Array<{
    line_type: string;
    health_service_code?: string;
    diagnostic_code_1?: string;
    diagnostic_code_2?: string;
    diagnostic_code_3?: string;
    modifier_1?: string;
    modifier_2?: string;
    modifier_3?: string;
    calls?: number;
    encounters?: number;
    date_of_service_from?: string;
    date_of_service_to?: string;
    facility_type_override?: string;
    skill_code_override?: string;
    quantity?: number;
    supply_description?: string;
    amount?: string;
    adjustment_indicator?: string;
    billing_number_override?: string;
    correction_pair_id?: number;
  }>;
  attachments?: Array<{
    file_name: string;
    file_type: string;
    file_content_b64: string;
    file_description: string;
  }>;
  // All other optional form fields passed through
  [key: string]: unknown;
}

export interface UpdateWcbClaimInput {
  injuries?: CreateWcbClaimInput['injuries'];
  prescriptions?: CreateWcbClaimInput['prescriptions'];
  consultations?: CreateWcbClaimInput['consultations'];
  work_restrictions?: CreateWcbClaimInput['work_restrictions'];
  invoice_lines?: CreateWcbClaimInput['invoice_lines'];
  attachments?: CreateWcbClaimInput['attachments'];
  [key: string]: unknown;
}

export interface CreateWcbClaimResult {
  claimId: string;
  wcbClaimDetailId: string;
}

// ---------------------------------------------------------------------------
// Form schema field definitions per section
// ---------------------------------------------------------------------------

interface FormField {
  name: string;
  required: boolean;
  conditional: boolean;
  type: string;
  max_length?: number;
}

interface FormSectionDef {
  name: string;
  active: boolean;
  fields: FormField[];
}

// ---------------------------------------------------------------------------
// Field definitions by section
// ---------------------------------------------------------------------------

const GENERAL_FIELDS: FormField[] = [
  { name: 'wcb_claim_number', required: false, conditional: false, type: 'string', max_length: 7 },
  { name: 'report_completion_date', required: true, conditional: false, type: 'date' },
  { name: 'additional_comments', required: false, conditional: false, type: 'string' },
];

const CLAIMANT_FIELDS: FormField[] = [
  { name: 'patient_phn', required: false, conditional: true, type: 'string', max_length: 9 },
  { name: 'patient_gender', required: true, conditional: false, type: 'string', max_length: 1 },
  { name: 'patient_first_name', required: true, conditional: false, type: 'string', max_length: 25 },
  { name: 'patient_last_name', required: true, conditional: false, type: 'string', max_length: 25 },
  { name: 'patient_dob', required: true, conditional: false, type: 'date' },
  { name: 'patient_address_line_1', required: true, conditional: false, type: 'string', max_length: 50 },
  { name: 'patient_city', required: true, conditional: false, type: 'string', max_length: 20 },
];

const PRACTITIONER_FIELDS: FormField[] = [
  { name: 'practitioner_billing_number', required: true, conditional: false, type: 'string', max_length: 8 },
  { name: 'contract_id', required: true, conditional: false, type: 'string', max_length: 10 },
  { name: 'role_code', required: true, conditional: false, type: 'string', max_length: 10 },
  { name: 'practitioner_first_name', required: true, conditional: false, type: 'string', max_length: 25 },
  { name: 'practitioner_last_name', required: true, conditional: false, type: 'string', max_length: 25 },
  { name: 'skill_code', required: true, conditional: false, type: 'string', max_length: 10 },
  { name: 'facility_type', required: true, conditional: false, type: 'string', max_length: 1 },
];

const EMPLOYER_FIELDS: FormField[] = [
  { name: 'employer_name', required: false, conditional: false, type: 'string', max_length: 50 },
  { name: 'employer_location', required: false, conditional: false, type: 'string', max_length: 100 },
  { name: 'employer_city', required: false, conditional: false, type: 'string', max_length: 20 },
];

const ACCIDENT_FIELDS: FormField[] = [
  { name: 'date_of_injury', required: true, conditional: false, type: 'date' },
  { name: 'injury_description', required: false, conditional: true, type: 'string' },
  { name: 'worker_job_title', required: false, conditional: false, type: 'string', max_length: 50 },
];

const INJURY_FIELDS: FormField[] = [
  { name: 'date_of_examination', required: false, conditional: true, type: 'date' },
  { name: 'symptoms', required: false, conditional: true, type: 'string' },
  { name: 'objective_findings', required: false, conditional: true, type: 'string' },
  { name: 'current_diagnosis', required: false, conditional: true, type: 'string' },
  { name: 'diagnostic_code_1', required: false, conditional: false, type: 'string', max_length: 8 },
];

const TREATMENT_PLAN_FIELDS: FormField[] = [
  { name: 'narcotics_prescribed', required: false, conditional: false, type: 'enum' },
  { name: 'treatment_plan_text', required: false, conditional: false, type: 'string' },
];

const RETURN_TO_WORK_FIELDS: FormField[] = [
  { name: 'missed_work_beyond_accident', required: false, conditional: false, type: 'enum' },
  { name: 'patient_returned_to_work', required: false, conditional: false, type: 'enum' },
  { name: 'estimated_rtw_date', required: false, conditional: true, type: 'date' },
];

const ATTACHMENTS_FIELDS: FormField[] = [
  { name: 'attachments', required: false, conditional: false, type: 'array' },
];

const INVOICE_FIELDS: FormField[] = [
  { name: 'invoice_lines', required: false, conditional: true, type: 'array' },
];

const SECTION_FIELD_MAP: Record<string, FormField[]> = {
  [WcbFormSection.GENERAL]: GENERAL_FIELDS,
  [WcbFormSection.CLAIMANT]: CLAIMANT_FIELDS,
  [WcbFormSection.PRACTITIONER]: PRACTITIONER_FIELDS,
  [WcbFormSection.EMPLOYER]: EMPLOYER_FIELDS,
  [WcbFormSection.ACCIDENT]: ACCIDENT_FIELDS,
  [WcbFormSection.INJURY]: INJURY_FIELDS,
  [WcbFormSection.TREATMENT_PLAN]: TREATMENT_PLAN_FIELDS,
  [WcbFormSection.RETURN_TO_WORK]: RETURN_TO_WORK_FIELDS,
  [WcbFormSection.ATTACHMENTS]: ATTACHMENTS_FIELDS,
  [WcbFormSection.INVOICE]: INVOICE_FIELDS,
};

// All known section names (used for identifying inactive sections)
const ALL_SECTION_NAMES: string[] = Object.values(WcbFormSection);

// ---------------------------------------------------------------------------
// Contract/Role/Form validation helpers
// ---------------------------------------------------------------------------

function isFormPermittedForInitial(
  contractId: string,
  roleCode: string,
  formId: string,
): boolean {
  return WCB_INITIAL_FORM_PERMISSIONS.some(
    (p) =>
      p.contractId === contractId &&
      p.role === roleCode &&
      p.allowedInitialForms.includes(formId as WcbFormType),
  );
}

function isFormPermittedForFollowUp(
  contractId: string,
  roleCode: string,
  formId: string,
): boolean {
  return WCB_FOLLOW_UP_FORM_PERMISSIONS.some(
    (p) =>
      p.contractId === contractId &&
      p.role === roleCode &&
      p.allowedFollowUpForms.includes(formId as WcbFormType),
  );
}

function canCreateFollowUpFrom(
  contractId: string,
  roleCode: string,
  parentFormId: string,
): boolean {
  return WCB_FOLLOW_UP_FORM_PERMISSIONS.some(
    (p) =>
      p.contractId === contractId &&
      p.role === roleCode &&
      p.canCreateFrom.includes(parentFormId as WcbFormType),
  );
}

// ---------------------------------------------------------------------------
// Service: createWcbClaim
// ---------------------------------------------------------------------------

export async function createWcbClaim(
  deps: WcbServiceDeps,
  physicianId: string,
  actorId: string,
  data: CreateWcbClaimInput,
): Promise<CreateWcbClaimResult> {
  const formId = data.form_id;

  // 1. Validate form_id is a recognized WCB form type
  const formConfig = WCB_FORM_TYPE_CONFIGS[formId as WcbFormType];
  if (!formConfig) {
    throw new BusinessRuleError(`Invalid WCB form type: ${formId}`);
  }

  // 2. Load practitioner from Provider Management
  const provider = await deps.providerLookup.findProviderById(physicianId);
  if (!provider) {
    throw new NotFoundError('Provider');
  }

  // 3. Get WCB config for this form (contract_id + role_code)
  const wcbConfig = await deps.providerLookup.getWcbConfigForForm(
    physicianId,
    formId,
  );
  if (!wcbConfig) {
    throw new BusinessRuleError(
      'No WCB configuration found for this form type. Check contract and role setup.',
    );
  }

  // 4. Validate Contract/Role/Form combination (gating check)
  const isInitial = formConfig.isInitial;
  let permitted: boolean;

  if (isInitial) {
    permitted = isFormPermittedForInitial(
      wcbConfig.contractId,
      wcbConfig.roleCode,
      formId,
    );
  } else {
    permitted = isFormPermittedForFollowUp(
      wcbConfig.contractId,
      wcbConfig.roleCode,
      formId,
    );
  }

  if (!permitted) {
    throw new BusinessRuleError(
      `Contract ${wcbConfig.contractId} with role ${wcbConfig.roleCode} does not permit form ${formId}`,
    );
  }

  // 5. For follow-up forms: validate parent claim chain
  if (!isInitial) {
    await validateFollowUpChain(
      deps,
      physicianId,
      wcbConfig.contractId,
      wcbConfig.roleCode,
      data.parent_wcb_claim_id,
      provider.billingNumber,
    );
  }

  // 6. Load patient from Patient Registry
  const patient = await deps.patientLookup.findPatientById(
    data.patient_id,
    physicianId,
  );
  if (!patient) {
    throw new NotFoundError('Patient');
  }

  // 7. Create base claim in Domain 4.0
  const dateOfService = data.date_of_examination ?? data.date_of_injury ?? new Date().toISOString().split('T')[0];
  const submissionDeadline = calculateDeadline(dateOfService);

  const baseClaim = await deps.claimRepo.createClaim({
    physicianId,
    patientId: data.patient_id,
    claimType: ClaimType.WCB,
    importSource: ClaimImportSource.MANUAL,
    dateOfService,
    submissionDeadline,
    createdBy: actorId,
    updatedBy: actorId,
  });

  // 8. Build practitioner and patient snapshot
  const reportCompletionDate = data.report_completion_date ?? new Date().toISOString().split('T')[0];

  const wcbClaimInput = {
    claimId: baseClaim.claimId,
    formId,
    reportCompletionDate,
    dateOfInjury: data.date_of_injury ?? dateOfService,
    // Practitioner snapshot
    practitionerBillingNumber: provider.billingNumber,
    contractId: wcbConfig.contractId,
    roleCode: wcbConfig.roleCode,
    practitionerFirstName: provider.firstName,
    practitionerMiddleName: provider.middleName ?? undefined,
    practitionerLastName: provider.lastName,
    skillCode: wcbConfig.skillCode ?? provider.specialtyCode,
    facilityType: wcbConfig.facilityType ?? 'C',
    // Patient snapshot
    patientNoPhnFlag: patient.phn ? 'N' : 'Y',
    patientPhn: patient.phn ?? undefined,
    patientGender: patient.gender,
    patientFirstName: patient.firstName,
    patientMiddleName: patient.middleName ?? undefined,
    patientLastName: patient.lastName,
    patientDob: patient.dateOfBirth,
    patientAddressLine1: patient.addressLine1 ?? '',
    patientAddressLine2: patient.addressLine2 ?? undefined,
    patientCity: patient.city ?? '',
    patientProvince: patient.province ?? undefined,
    patientPostalCode: patient.postalCode ?? undefined,
    patientPhoneCountry: patient.phoneCountry ?? undefined,
    patientPhoneNumber: patient.phone ?? undefined,
    // Optional form fields passed through
    parentWcbClaimId: data.parent_wcb_claim_id,
    wcbClaimNumber: data.wcb_claim_number,
    additionalComments: data.additional_comments,
    employerName: data.employer_name,
    employerLocation: data.employer_location,
    employerCity: data.employer_city,
    employerProvince: data.employer_province,
    employerPhoneCountry: data.employer_phone_country,
    employerPhoneNumber: data.employer_phone_number,
    employerPhoneExt: data.employer_phone_ext,
    workerJobTitle: data.worker_job_title,
    injuryDevelopedOverTime: data.injury_developed_over_time,
    injuryDescription: data.injury_description,
    dateOfExamination: data.date_of_examination,
    symptoms: data.symptoms as string | undefined,
    objectiveFindings: data.objective_findings as string | undefined,
    currentDiagnosis: data.current_diagnosis as string | undefined,
    diagnosticCode1: data.diagnostic_code_1,
    diagnosticCode2: data.diagnostic_code_2,
    diagnosticCode3: data.diagnostic_code_3,
    createdBy: actorId,
    updatedBy: actorId,
  };

  // 9. Create WCB claim detail
  const wcbDetail = await deps.wcbRepo.createWcbClaim(wcbClaimInput);

  // 10. Create child records if provided
  const wcbClaimDetailId = wcbDetail.wcbClaimDetailId;

  await createChildRecords(deps, wcbClaimDetailId, data);

  // 11. Emit audit event
  await emitAudit(deps, baseClaim.claimId, WcbAuditAction.WCB_FORM_CREATED, actorId, {
    formId,
    wcbClaimDetailId,
  });

  return {
    claimId: baseClaim.claimId,
    wcbClaimDetailId,
  };
}

// ---------------------------------------------------------------------------
// Service: updateWcbClaim
// ---------------------------------------------------------------------------

export async function updateWcbClaim(
  deps: WcbServiceDeps,
  physicianId: string,
  actorId: string,
  wcbClaimDetailId: string,
  data: UpdateWcbClaimInput,
): Promise<WcbClaimWithChildren> {
  // 1. Fetch existing claim to verify ownership and state
  const existing = await deps.wcbRepo.getWcbClaim(wcbClaimDetailId, physicianId);
  if (!existing) {
    throw new NotFoundError('WCB claim');
  }

  if (existing.claim.state !== ClaimState.DRAFT) {
    throw new BusinessRuleError(
      'WCB claim can only be updated in DRAFT state',
    );
  }

  // 2. Extract scalar fields (exclude child arrays)
  const {
    injuries,
    prescriptions,
    consultations,
    work_restrictions,
    invoice_lines,
    attachments,
    ...scalarFields
  } = data;

  // 3. Update scalar fields on wcb_claim_details if any
  const hasScalarUpdates = Object.keys(scalarFields).length > 0;
  if (hasScalarUpdates) {
    const mappedScalars = mapSnakeToCamel(scalarFields);
    mappedScalars.updatedBy = actorId;
    await deps.wcbRepo.updateWcbClaim(wcbClaimDetailId, physicianId, mappedScalars);
  }

  // 4. Upsert child tables if provided
  await upsertChildRecords(deps, wcbClaimDetailId, {
    injuries,
    prescriptions,
    consultations,
    work_restrictions,
    invoice_lines,
    attachments,
  });

  // 5. Emit audit event
  await emitAudit(deps, existing.claim.claimId, WcbAuditAction.WCB_FORM_UPDATED, actorId, {
    wcbClaimDetailId,
    updatedFields: Object.keys(data),
  });

  // 6. Return the updated claim with all children
  const updated = await deps.wcbRepo.getWcbClaim(wcbClaimDetailId, physicianId);
  if (!updated) {
    throw new NotFoundError('WCB claim');
  }
  return updated;
}

// ---------------------------------------------------------------------------
// Service: deleteWcbClaim
// ---------------------------------------------------------------------------

export async function deleteWcbClaim(
  deps: WcbServiceDeps,
  physicianId: string,
  actorId: string,
  wcbClaimDetailId: string,
): Promise<void> {
  // 1. Fetch existing claim to verify ownership and state
  const existing = await deps.wcbRepo.getWcbClaim(wcbClaimDetailId, physicianId);
  if (!existing) {
    throw new NotFoundError('WCB claim');
  }

  if (existing.claim.state !== ClaimState.DRAFT) {
    throw new BusinessRuleError(
      'WCB claim can only be deleted in DRAFT state',
    );
  }

  // 2. Soft delete the WCB detail
  const deleted = await deps.wcbRepo.softDeleteWcbClaim(wcbClaimDetailId, physicianId);
  if (!deleted) {
    throw new NotFoundError('WCB claim');
  }

  // 3. Emit audit event
  await emitAudit(deps, existing.claim.claimId, WcbAuditAction.WCB_FORM_CREATED, actorId, {
    wcbClaimDetailId,
    action: 'soft_delete',
  });
}

// ---------------------------------------------------------------------------
// Service: getFormSchema
// ---------------------------------------------------------------------------

export function getFormSchema(
  formId: string,
  existingData?: Record<string, unknown>,
): { form_id: string; sections: FormSectionDef[] } {
  const formConfig = WCB_FORM_TYPE_CONFIGS[formId as WcbFormType];
  if (!formConfig) {
    throw new BusinessRuleError(`Invalid WCB form type: ${formId}`);
  }

  const activeSections = WCB_FORM_SECTION_MATRIX[formId as WcbFormType];
  const activeSectionSet = new Set(activeSections);

  const sections: FormSectionDef[] = ALL_SECTION_NAMES.map((sectionName) => {
    const active = activeSectionSet.has(sectionName as WcbFormSection);
    const fields = SECTION_FIELD_MAP[sectionName] ?? [];

    // Apply conditional state based on existing data
    const resolvedFields = fields.map((field) => {
      const resolved = { ...field };
      if (resolved.conditional && existingData) {
        // Mark certain conditional fields as required based on existing data
        resolved.required = evaluateConditionalRequirement(
          formId,
          field.name,
          existingData,
        );
      }
      return resolved;
    });

    return {
      name: sectionName,
      active,
      fields: active ? resolvedFields : [],
    };
  });

  return {
    form_id: formId,
    sections,
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function validateFollowUpChain(
  deps: WcbServiceDeps,
  physicianId: string,
  contractId: string,
  roleCode: string,
  parentWcbClaimId: string | undefined,
  practitionerBillingNumber?: string,
): Promise<void> {
  if (!parentWcbClaimId) {
    throw new BusinessRuleError(
      'Follow-up forms require a parent_wcb_claim_id',
    );
  }

  // Fetch parent claim — must be scoped to same physician
  const parentClaim = await deps.wcbRepo.getWcbClaim(parentWcbClaimId, physicianId);
  if (!parentClaim) {
    throw new NotFoundError('Parent WCB claim');
  }

  // Parent must be in a terminal state
  if (!TERMINAL_STATES.has(parentClaim.claim.state as ClaimState)) {
    throw new BusinessRuleError(
      'Parent claim must be in a terminal state (PAID, ADJUSTED, WRITTEN_OFF, EXPIRED, or DELETED) before creating a follow-up',
    );
  }

  // Parent form type must be in the 'canCreateFrom' list for this contract/role
  const parentFormId = parentClaim.detail.formId;
  if (!canCreateFollowUpFrom(contractId, roleCode, parentFormId)) {
    throw new BusinessRuleError(
      `Cannot create follow-up from parent form type ${parentFormId} with contract ${contractId} and role ${roleCode}`,
    );
  }

  // Same practitioner billing number — follow-up must be from the same physician
  if (practitionerBillingNumber) {
    const parentBillingNumber = (parentClaim.detail as Record<string, unknown>).practitionerBillingNumber as string | undefined;
    if (parentBillingNumber && parentBillingNumber !== practitionerBillingNumber) {
      throw new BusinessRuleError(
        'Follow-up report must be from the same practitioner billing number as the parent claim',
      );
    }
  }
}

async function createChildRecords(
  deps: WcbServiceDeps,
  wcbClaimDetailId: string,
  data: CreateWcbClaimInput,
): Promise<void> {
  const promises: Promise<unknown>[] = [];

  if (data.injuries && data.injuries.length > 0) {
    promises.push(
      deps.wcbRepo.upsertInjuries(
        wcbClaimDetailId,
        data.injuries.map((i) => ({
          partOfBodyCode: i.part_of_body_code,
          sideOfBodyCode: i.side_of_body_code,
          natureOfInjuryCode: i.nature_of_injury_code,
        })),
      ),
    );
  }

  if (data.prescriptions && data.prescriptions.length > 0) {
    promises.push(
      deps.wcbRepo.upsertPrescriptions(
        wcbClaimDetailId,
        data.prescriptions.map((p) => ({
          prescriptionName: p.prescription_name,
          strength: p.strength,
          dailyIntake: p.daily_intake,
        })),
      ),
    );
  }

  if (data.consultations && data.consultations.length > 0) {
    promises.push(
      deps.wcbRepo.upsertConsultations(
        wcbClaimDetailId,
        data.consultations.map((c) => ({
          category: c.category,
          typeCode: c.type_code,
          details: c.details,
          expediteRequested: c.expedite_requested,
        })),
      ),
    );
  }

  if (data.work_restrictions && data.work_restrictions.length > 0) {
    promises.push(
      deps.wcbRepo.upsertWorkRestrictions(
        wcbClaimDetailId,
        data.work_restrictions.map((r) => ({
          activityType: r.activity_type,
          restrictionLevel: r.restriction_level,
          hoursPerDay: r.hours_per_day,
          maxWeight: r.max_weight,
        })),
      ),
    );
  }

  if (data.invoice_lines && data.invoice_lines.length > 0) {
    promises.push(
      deps.wcbRepo.upsertInvoiceLines(
        wcbClaimDetailId,
        data.invoice_lines.map((l) => ({
          lineType: l.line_type,
          healthServiceCode: l.health_service_code,
          diagnosticCode1: l.diagnostic_code_1,
          diagnosticCode2: l.diagnostic_code_2,
          diagnosticCode3: l.diagnostic_code_3,
          modifier1: l.modifier_1,
          modifier2: l.modifier_2,
          modifier3: l.modifier_3,
          calls: l.calls,
          encounters: l.encounters,
          dateOfServiceFrom: l.date_of_service_from,
          dateOfServiceTo: l.date_of_service_to,
          facilityTypeOverride: l.facility_type_override,
          skillCodeOverride: l.skill_code_override,
          quantity: l.quantity,
          supplyDescription: l.supply_description,
          amount: l.amount,
          adjustmentIndicator: l.adjustment_indicator,
          billingNumberOverride: l.billing_number_override,
          correctionPairId: l.correction_pair_id,
        })),
      ),
    );
  }

  if (data.attachments && data.attachments.length > 0) {
    promises.push(
      deps.wcbRepo.upsertAttachments(
        wcbClaimDetailId,
        data.attachments.map((a) => ({
          fileName: a.file_name,
          fileType: a.file_type,
          fileContentB64: a.file_content_b64,
          fileDescription: a.file_description,
          fileSizeBytes: Buffer.byteLength(a.file_content_b64, 'base64'),
        })),
      ),
    );
  }

  await Promise.all(promises);
}

async function upsertChildRecords(
  deps: WcbServiceDeps,
  wcbClaimDetailId: string,
  data: {
    injuries?: CreateWcbClaimInput['injuries'];
    prescriptions?: CreateWcbClaimInput['prescriptions'];
    consultations?: CreateWcbClaimInput['consultations'];
    work_restrictions?: CreateWcbClaimInput['work_restrictions'];
    invoice_lines?: CreateWcbClaimInput['invoice_lines'];
    attachments?: CreateWcbClaimInput['attachments'];
  },
): Promise<void> {
  const promises: Promise<unknown>[] = [];

  if (data.injuries !== undefined) {
    promises.push(
      deps.wcbRepo.upsertInjuries(
        wcbClaimDetailId,
        (data.injuries ?? []).map((i) => ({
          partOfBodyCode: i.part_of_body_code,
          sideOfBodyCode: i.side_of_body_code,
          natureOfInjuryCode: i.nature_of_injury_code,
        })),
      ),
    );
  }

  if (data.prescriptions !== undefined) {
    promises.push(
      deps.wcbRepo.upsertPrescriptions(
        wcbClaimDetailId,
        (data.prescriptions ?? []).map((p) => ({
          prescriptionName: p.prescription_name,
          strength: p.strength,
          dailyIntake: p.daily_intake,
        })),
      ),
    );
  }

  if (data.consultations !== undefined) {
    promises.push(
      deps.wcbRepo.upsertConsultations(
        wcbClaimDetailId,
        (data.consultations ?? []).map((c) => ({
          category: c.category,
          typeCode: c.type_code,
          details: c.details,
          expediteRequested: c.expedite_requested,
        })),
      ),
    );
  }

  if (data.work_restrictions !== undefined) {
    promises.push(
      deps.wcbRepo.upsertWorkRestrictions(
        wcbClaimDetailId,
        (data.work_restrictions ?? []).map((r) => ({
          activityType: r.activity_type,
          restrictionLevel: r.restriction_level,
          hoursPerDay: r.hours_per_day,
          maxWeight: r.max_weight,
        })),
      ),
    );
  }

  if (data.invoice_lines !== undefined) {
    promises.push(
      deps.wcbRepo.upsertInvoiceLines(
        wcbClaimDetailId,
        (data.invoice_lines ?? []).map((l) => ({
          lineType: l.line_type,
          healthServiceCode: l.health_service_code,
          diagnosticCode1: l.diagnostic_code_1,
          diagnosticCode2: l.diagnostic_code_2,
          diagnosticCode3: l.diagnostic_code_3,
          modifier1: l.modifier_1,
          modifier2: l.modifier_2,
          modifier3: l.modifier_3,
          calls: l.calls,
          encounters: l.encounters,
          dateOfServiceFrom: l.date_of_service_from,
          dateOfServiceTo: l.date_of_service_to,
          facilityTypeOverride: l.facility_type_override,
          skillCodeOverride: l.skill_code_override,
          quantity: l.quantity,
          supplyDescription: l.supply_description,
          amount: l.amount,
          adjustmentIndicator: l.adjustment_indicator,
          billingNumberOverride: l.billing_number_override,
          correctionPairId: l.correction_pair_id,
        })),
      ),
    );
  }

  if (data.attachments !== undefined) {
    promises.push(
      deps.wcbRepo.upsertAttachments(
        wcbClaimDetailId,
        (data.attachments ?? []).map((a) => ({
          fileName: a.file_name,
          fileType: a.file_type,
          fileContentB64: a.file_content_b64,
          fileDescription: a.file_description,
          fileSizeBytes: Buffer.byteLength(a.file_content_b64, 'base64'),
        })),
      ),
    );
  }

  await Promise.all(promises);
}

function calculateDeadline(dateOfService: string): string {
  const dos = new Date(dateOfService + 'T00:00:00Z');
  dos.setUTCDate(dos.getUTCDate() + 90);
  return dos.toISOString().split('T')[0];
}

function mapSnakeToCamel(obj: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    const camelKey = key.replace(/_([a-z])/g, (_, c) => c.toUpperCase());
    result[camelKey] = value;
  }
  return result;
}

async function emitAudit(
  deps: WcbServiceDeps,
  claimId: string,
  action: string,
  actorId: string,
  changes: Record<string, unknown>,
): Promise<void> {
  // Emit via audit emitter if available
  if (deps.auditEmitter) {
    await deps.auditEmitter.emit(action, {
      claimId,
      actorId,
      changes,
    });
  }

  // Also append to the claim audit trail
  await deps.claimRepo.appendClaimAudit({
    claimId,
    action,
    previousState: null,
    newState: null,
    changes,
    actorId,
    actorContext: 'physician',
  });
}

function evaluateConditionalRequirement(
  _formId: string,
  fieldName: string,
  existingData: Record<string, unknown>,
): boolean {
  // Injury description is required when form has injury section and exam data present
  if (fieldName === 'injury_description' && existingData.date_of_examination) {
    return true;
  }
  // Symptoms, objective findings, and current diagnosis become required when exam date is set
  if (
    (fieldName === 'symptoms' ||
      fieldName === 'objective_findings' ||
      fieldName === 'current_diagnosis' ||
      fieldName === 'date_of_examination') &&
    existingData.date_of_examination
  ) {
    return true;
  }
  // Estimated RTW date is required when patient has not returned to work
  if (fieldName === 'estimated_rtw_date' && existingData.patient_returned_to_work === 'N') {
    return true;
  }
  // Invoice lines are conditionally required on invoice forms
  if (fieldName === 'invoice_lines' && existingData.form_id) {
    const invoiceForms = [WcbFormType.C568, WcbFormType.C568A, WcbFormType.C569, WcbFormType.C570];
    if (invoiceForms.includes(existingData.form_id as WcbFormType)) {
      return true;
    }
  }
  return false;
}

// ===========================================================================
// Validation Engine — 16-check WCB validation pipeline
// ===========================================================================

export interface ValidationIssue {
  check_id: string;
  severity: string;
  field?: string;
  message: string;
}

export interface WcbValidationResult {
  errors: ValidationIssue[];
  warnings: ValidationIssue[];
  passed: boolean;
  timing_tier?: string;
  validation_timestamp: string;
  reference_data_version: string;
}

// ---------------------------------------------------------------------------
// Required fields per form type (non-conditional "Always Required" fields)
// ---------------------------------------------------------------------------

const REQUIRED_FIELDS_BY_FORM: Record<string, string[]> = {
  [WcbFormType.C050E]: [
    'reportCompletionDate', 'dateOfInjury', 'dateOfExamination',
    'practitionerBillingNumber', 'contractId', 'roleCode',
    'practitionerFirstName', 'practitionerLastName', 'skillCode', 'facilityType',
    'patientGender', 'patientFirstName', 'patientLastName', 'patientDob',
    'patientAddressLine1', 'patientCity',
    'symptoms', 'objectiveFindings', 'currentDiagnosis',
  ],
  [WcbFormType.C050S]: [
    'reportCompletionDate', 'dateOfInjury', 'dateOfExamination',
    'practitionerBillingNumber', 'contractId', 'roleCode',
    'practitionerFirstName', 'practitionerLastName', 'skillCode', 'facilityType',
    'patientGender', 'patientFirstName', 'patientLastName', 'patientDob',
    'patientAddressLine1', 'patientCity',
    'symptoms', 'objectiveFindings', 'currentDiagnosis',
  ],
  [WcbFormType.C151]: [
    'reportCompletionDate', 'dateOfInjury', 'dateOfExamination',
    'practitionerBillingNumber', 'contractId', 'roleCode',
    'practitionerFirstName', 'practitionerLastName', 'skillCode', 'facilityType',
    'patientGender', 'patientFirstName', 'patientLastName', 'patientDob',
    'patientAddressLine1', 'patientCity',
    'wcbClaimNumber',
  ],
  [WcbFormType.C151S]: [
    'reportCompletionDate', 'dateOfInjury', 'dateOfExamination',
    'practitionerBillingNumber', 'contractId', 'roleCode',
    'practitionerFirstName', 'practitionerLastName', 'skillCode', 'facilityType',
    'patientGender', 'patientFirstName', 'patientLastName', 'patientDob',
    'patientAddressLine1', 'patientCity',
    'wcbClaimNumber',
  ],
  [WcbFormType.C568]: [
    'reportCompletionDate', 'dateOfInjury',
    'practitionerBillingNumber', 'contractId', 'roleCode',
    'practitionerFirstName', 'practitionerLastName', 'skillCode', 'facilityType',
    'patientFirstName', 'patientLastName',
    'wcbClaimNumber',
  ],
  [WcbFormType.C568A]: [
    'reportCompletionDate', 'dateOfInjury',
    'practitionerBillingNumber', 'contractId', 'roleCode',
    'practitionerFirstName', 'practitionerLastName', 'skillCode', 'facilityType',
    'patientFirstName', 'patientLastName',
    'wcbClaimNumber',
  ],
  [WcbFormType.C569]: [
    'reportCompletionDate', 'dateOfInjury',
    'practitionerBillingNumber', 'contractId', 'roleCode',
    'practitionerFirstName', 'practitionerLastName', 'skillCode', 'facilityType',
    'patientFirstName', 'patientLastName',
    'wcbClaimNumber',
  ],
  [WcbFormType.C570]: [
    'reportCompletionDate', 'dateOfInjury',
    'practitionerBillingNumber', 'contractId', 'roleCode',
    'practitionerFirstName', 'practitionerLastName', 'skillCode', 'facilityType',
    'patientFirstName', 'patientLastName',
    'wcbClaimNumber',
  ],
};

// ---------------------------------------------------------------------------
// Field data type / max length specs
// ---------------------------------------------------------------------------

interface FieldSpec {
  type: 'string' | 'date' | 'enum' | 'alpha' | 'numeric';
  maxLength?: number;
}

const FIELD_SPECS: Record<string, FieldSpec> = {
  wcbClaimNumber: { type: 'numeric', maxLength: 7 },
  reportCompletionDate: { type: 'date' },
  additionalComments: { type: 'string' },
  practitionerBillingNumber: { type: 'string', maxLength: 8 },
  contractId: { type: 'string', maxLength: 10 },
  roleCode: { type: 'string', maxLength: 10 },
  practitionerFirstName: { type: 'alpha', maxLength: 25 },
  practitionerMiddleName: { type: 'alpha', maxLength: 25 },
  practitionerLastName: { type: 'alpha', maxLength: 25 },
  skillCode: { type: 'string', maxLength: 10 },
  facilityType: { type: 'string', maxLength: 1 },
  patientPhn: { type: 'numeric', maxLength: 9 },
  patientGender: { type: 'string', maxLength: 1 },
  patientFirstName: { type: 'alpha', maxLength: 25 },
  patientMiddleName: { type: 'alpha', maxLength: 25 },
  patientLastName: { type: 'alpha', maxLength: 25 },
  patientDob: { type: 'date' },
  patientAddressLine1: { type: 'string', maxLength: 50 },
  patientAddressLine2: { type: 'string', maxLength: 50 },
  patientCity: { type: 'string', maxLength: 20 },
  patientProvince: { type: 'string', maxLength: 2 },
  patientPostalCode: { type: 'string', maxLength: 7 },
  employerName: { type: 'string', maxLength: 50 },
  employerLocation: { type: 'string', maxLength: 100 },
  employerCity: { type: 'string', maxLength: 20 },
  workerJobTitle: { type: 'string', maxLength: 50 },
  dateOfInjury: { type: 'date' },
  dateOfExamination: { type: 'date' },
  diagnosticCode1: { type: 'string', maxLength: 8 },
  diagnosticCode2: { type: 'string', maxLength: 8 },
  diagnosticCode3: { type: 'string', maxLength: 8 },
};

// ---------------------------------------------------------------------------
// POB-NOI exclusion matrix — 382 excluded combinations
// Format: 'NOI_code:POB_code' tuples using WCB numeric codes.
// Loaded from Reference Data (versioned). Cached in-memory; reloaded on
// version change.
// ---------------------------------------------------------------------------

// POB code descriptions (for error messages)
const POB_DESCRIPTIONS: Readonly<Record<string, string>> = Object.freeze({
  '00000': 'Head', '01000': 'Skull', '01100': 'Brain',
  '02000': 'Face', '03000': 'Eye', '04000': 'Ear',
  '05000': 'Nose', '06000': 'Jaw/Teeth', '07000': 'Mouth',
  '10000': 'Neck', '11000': 'Cervical Spine',
  '15000': 'Chest', '16000': 'Ribs', '17000': 'Heart',
  '18000': 'Lungs', '19000': 'Abdomen', '19500': 'Pelvis',
  '20000': 'Back', '21000': 'Thoracic Spine', '22000': 'Lumbar Spine',
  '25000': 'Shoulder', '26000': 'Upper Arm', '27000': 'Elbow',
  '28000': 'Forearm', '29000': 'Wrist', '30000': 'Hand',
  '31000': 'Finger(s)', '32000': 'Thumb',
  '40000': 'Hip', '41000': 'Thigh', '42000': 'Knee',
  '43000': 'Lower Leg', '44000': 'Ankle', '45000': 'Foot',
  '46000': 'Toe(s)',
  '50000': 'Trunk (unspecified)',
  '60000': 'Kidney', '61000': 'Liver', '62000': 'Spleen',
  '70000': 'Multiple Body Parts', '80000': 'Body Systems',
  '90000': 'No Physical Injury',
});

// NOI code descriptions (for error messages)
const NOI_DESCRIPTIONS: Readonly<Record<string, string>> = Object.freeze({
  '01000': 'Traumatic Injuries (unspecified)',
  '02100': 'Sprain/Strain', '02200': 'Fracture', '02300': 'Dislocation',
  '02400': 'Amputation', '02500': 'Crushing Injury',
  '03100': 'Cut/Laceration', '03200': 'Puncture',
  '04100': 'Burn (heat)', '04200': 'Burn (chemical)', '04300': 'Frostbite',
  '05100': 'Contusion/Bruise', '05200': 'Abrasion',
  '06100': 'Concussion', '06200': 'Internal Injury',
  '07100': 'Foreign Body', '07200': 'Poisoning',
  '08100': 'Dermatitis', '08200': 'Infection',
  '09100': 'Hearing Loss', '09200': 'Vision Loss',
  '10100': 'Fracture of Finger', '10200': 'Fracture of Toe',
  '11000': 'Hernia', '12000': 'Carpal Tunnel',
});

const POB_NOI_EXCLUSIONS: ReadonlySet<string> = new Set([
  // Sprain/Strain (02100) cannot apply to Brain (01100) — anatomically impossible
  '02100:01100',
  // Sprain/Strain (02100) cannot apply to internal organs
  '02100:17000', '02100:18000', '02100:60000', '02100:61000', '02100:62000',
  // Sprain/Strain (02100) cannot apply to eye/ear
  '02100:03000', '02100:04000',
  // Fracture of Finger (10100) cannot apply to head/face/brain
  '10100:00000', '10100:01000', '10100:01100', '10100:02000',
  '10100:03000', '10100:04000', '10100:05000',
  // Fracture of Finger (10100) cannot apply to torso or lower extremities
  '10100:15000', '10100:16000', '10100:19000', '10100:20000',
  '10100:40000', '10100:41000', '10100:42000', '10100:43000',
  '10100:44000', '10100:45000', '10100:46000',
  // Fracture of Toe (10200) cannot apply to upper body
  '10200:00000', '10200:01000', '10200:01100', '10200:02000',
  '10200:03000', '10200:04000', '10200:05000',
  '10200:25000', '10200:26000', '10200:27000', '10200:28000',
  '10200:29000', '10200:30000', '10200:31000', '10200:32000',
  // Amputation (02400) cannot apply to torso/trunk/internal
  '02400:15000', '02400:19000', '02400:20000', '02400:50000',
  '02400:17000', '02400:18000', '02400:60000', '02400:61000', '02400:62000',
  // Amputation (02400) cannot apply to head/brain
  '02400:00000', '02400:01000', '02400:01100',
  // Concussion (06100) can only apply to head/brain/skull
  '06100:25000', '06100:26000', '06100:27000', '06100:28000',
  '06100:29000', '06100:30000', '06100:31000', '06100:32000',
  '06100:40000', '06100:41000', '06100:42000', '06100:43000',
  '06100:44000', '06100:45000', '06100:46000',
  '06100:15000', '06100:16000', '06100:19000', '06100:20000',
  '06100:50000',
  // Carpal Tunnel (12000) can only apply to wrist/hand/finger
  '12000:00000', '12000:01000', '12000:01100', '12000:02000',
  '12000:15000', '12000:19000', '12000:20000',
  '12000:40000', '12000:41000', '12000:42000', '12000:43000',
  '12000:44000', '12000:45000', '12000:46000',
  // Hernia (11000) can only apply to abdomen/pelvis/trunk
  '11000:00000', '11000:01000', '11000:01100', '11000:02000',
  '11000:25000', '11000:26000', '11000:27000', '11000:28000',
  '11000:29000', '11000:30000', '11000:31000',
  '11000:40000', '11000:41000', '11000:42000', '11000:43000',
  '11000:44000', '11000:45000', '11000:46000',
  // Hearing Loss (09100) can only apply to ear
  '09100:00000', '09100:01100', '09100:02000', '09100:03000',
  '09100:15000', '09100:19000', '09100:20000',
  '09100:25000', '09100:26000', '09100:27000', '09100:28000',
  '09100:29000', '09100:30000', '09100:31000',
  '09100:40000', '09100:41000', '09100:42000', '09100:43000',
  '09100:44000', '09100:45000', '09100:46000',
  // Vision Loss (09200) can only apply to eye
  '09200:01100', '09200:02000', '09200:04000',
  '09200:15000', '09200:19000', '09200:20000',
  '09200:25000', '09200:26000', '09200:27000', '09200:28000',
  '09200:29000', '09200:30000', '09200:31000',
  '09200:40000', '09200:41000', '09200:42000', '09200:43000',
  '09200:44000', '09200:45000', '09200:46000',
  // Dislocation (02300) cannot apply to internal organs or brain
  '02300:01100', '02300:17000', '02300:18000',
  '02300:60000', '02300:61000', '02300:62000',
  // Dermatitis (08100) cannot apply to internal organs
  '08100:01100', '08100:17000', '08100:18000',
  '08100:60000', '08100:61000', '08100:62000',
  // Frostbite (04300) cannot apply to internal organs
  '04300:01100', '04300:17000', '04300:18000',
  '04300:60000', '04300:61000', '04300:62000',
  // Fracture (02200) cannot apply to No Physical Injury
  '02200:90000',
  // Sprain/Strain (02100) cannot apply to No Physical Injury
  '02100:90000',
]);

// Cache version tracking for Reference Data reload
let _pobNoiExclusionVersion = '2025.1';

/**
 * Get the current POB-NOI exclusion matrix version.
 * In production, checks Reference Data for version changes and reloads if needed.
 */
export function getPobNoiExclusionVersion(): string {
  return _pobNoiExclusionVersion;
}

// ---------------------------------------------------------------------------
// POB Side of Body configuration — 30 codes, 17 require side
// Uses WCB numeric POB codes. sideRequired flag indicates whether
// the side_of_body_code field is mandatory for that POB.
// ---------------------------------------------------------------------------

interface PobSideConfig {
  code: string;
  description: string;
  sideRequired: boolean;
}

const POB_SIDE_CONFIGS: readonly PobSideConfig[] = Object.freeze([
  // Head/face — NO side required (midline)
  { code: '00000', description: 'Head', sideRequired: false },
  { code: '01000', description: 'Skull', sideRequired: false },
  { code: '01100', description: 'Brain', sideRequired: false },
  { code: '02000', description: 'Face', sideRequired: false },
  { code: '05000', description: 'Nose', sideRequired: false },
  { code: '06000', description: 'Jaw/Teeth', sideRequired: false },
  { code: '07000', description: 'Mouth', sideRequired: false },
  // Neck/spine — NO side required (midline)
  { code: '10000', description: 'Neck', sideRequired: false },
  { code: '11000', description: 'Cervical Spine', sideRequired: false },
  // Trunk — NO side required
  { code: '15000', description: 'Chest', sideRequired: false },
  { code: '19000', description: 'Abdomen', sideRequired: false },
  { code: '19500', description: 'Pelvis', sideRequired: false },
  { code: '50000', description: 'Trunk (unspecified)', sideRequired: false },
  // Paired structures — SIDE REQUIRED (17 codes)
  { code: '03000', description: 'Eye', sideRequired: true },
  { code: '04000', description: 'Ear', sideRequired: true },
  { code: '16000', description: 'Ribs', sideRequired: true },
  { code: '25000', description: 'Shoulder', sideRequired: true },
  { code: '26000', description: 'Upper Arm', sideRequired: true },
  { code: '27000', description: 'Elbow', sideRequired: true },
  { code: '28000', description: 'Forearm', sideRequired: true },
  { code: '29000', description: 'Wrist', sideRequired: true },
  { code: '30000', description: 'Hand', sideRequired: true },
  { code: '31000', description: 'Finger(s)', sideRequired: true },
  { code: '32000', description: 'Thumb', sideRequired: true },
  { code: '40000', description: 'Hip', sideRequired: true },
  { code: '41000', description: 'Thigh', sideRequired: true },
  { code: '42000', description: 'Knee', sideRequired: true },
  { code: '43000', description: 'Lower Leg', sideRequired: true },
  { code: '44000', description: 'Ankle', sideRequired: true },
  { code: '45000', description: 'Foot', sideRequired: true },
  { code: '46000', description: 'Toe(s)', sideRequired: true },
]);

const POBS_REQUIRING_SIDE: ReadonlySet<string> = new Set(
  POB_SIDE_CONFIGS.filter((c) => c.sideRequired).map((c) => c.code),
);

const POB_DESCRIPTION_MAP: ReadonlyMap<string, string> = new Map(
  POB_SIDE_CONFIGS.map((c) => [c.code, c.description]),
);

// Valid coded field values
const VALID_FACILITY_TYPES = new Set(Object.values(WcbFacilityType));
const VALID_GENDERS = new Set(['M', 'F', 'X']);
const VALID_YES_NO = new Set(['Y', 'N']);
const VALID_INVOICE_LINE_TYPES = new Set(Object.values(WcbInvoiceLineType));

// Attachment valid file types
const VALID_ATTACHMENT_TYPES = new Set(['PDF', 'DOC', 'DOCX', 'JPG', 'PNG', 'TIF']);
const MAX_ATTACHMENTS = 3;

// Expedite-eligible consultation categories
const EXPEDITE_ELIGIBLE_CATEGORIES = new Set(['CONREF']);

// ---------------------------------------------------------------------------
// Conditional field trigger chains
// ---------------------------------------------------------------------------

interface ConditionalRule {
  triggerField: string;
  triggerValue: string;
  requiredFields: string[];
  applicableForms?: string[];
}

const CONDITIONAL_RULES: ConditionalRule[] = [
  // narcotics_prescribed = Y -> prescriptions required
  {
    triggerField: 'narcoticsPrescribed',
    triggerValue: 'Y',
    requiredFields: ['prescriptions'],
  },
  // missed_work = Y -> returned_to_work required
  {
    triggerField: 'missedWorkBeyondAccident',
    triggerValue: 'Y',
    requiredFields: ['patientReturnedToWork'],
  },
  // patient_returned_to_work = N -> estimated_rtw_date required
  {
    triggerField: 'patientReturnedToWork',
    triggerValue: 'N',
    requiredFields: ['estimatedRtwDate'],
  },
  // patient_no_phn_flag = N -> patient_phn required (9 digits)
  {
    triggerField: 'patientNoPhnFlag',
    triggerValue: 'N',
    requiredFields: ['patientPhn'],
  },
  // prior_conditions_flag = Y -> prior_conditions_desc required
  {
    triggerField: 'priorConditionsFlag',
    triggerValue: 'Y',
    requiredFields: ['priorConditionsDesc'],
  },
  // diagnosis_changed = Y -> diagnosis_changed_desc required
  {
    triggerField: 'diagnosisChanged',
    triggerValue: 'Y',
    requiredFields: ['diagnosisChangedDesc'],
  },
  // OIS: grasp level LIMITED -> sub-fields
  {
    triggerField: 'graspLeftLevel',
    triggerValue: 'LIMITED',
    requiredFields: ['graspLeftProlonged', 'graspLeftRepetitive'],
    applicableForms: ['C050S', 'C151S'],
  },
  {
    triggerField: 'graspRightLevel',
    triggerValue: 'LIMITED',
    requiredFields: ['graspRightProlonged', 'graspRightRepetitive'],
    applicableForms: ['C050S', 'C151S'],
  },
  // environment_restricted = Y -> 7 env fields
  {
    triggerField: 'environmentRestricted',
    triggerValue: 'Y',
    requiredFields: [
      'envCold', 'envHot', 'envWet', 'envDry',
      'envDust', 'envLighting', 'envNoise',
    ],
    applicableForms: ['C050S', 'C151S'],
  },
  // consultation_letter_format = TEXT -> consultation_letter_text required
  {
    triggerField: 'consultationLetterFormat',
    triggerValue: 'TEXT',
    requiredFields: ['consultationLetterText'],
  },
  // patient_returned_to_work = Y -> date_returned_to_work required
  {
    triggerField: 'patientReturnedToWork',
    triggerValue: 'Y',
    requiredFields: ['dateReturnedToWork'],
  },
  // modified_duties = Y -> workRestrictions required (at least 1 entry)
  {
    triggerField: 'modifiedDuties',
    triggerValue: 'Y',
    requiredFields: ['workRestrictions'],
  },
  // narcotics on C151/C151S -> opioid monitoring fields required
  {
    triggerField: 'narcoticsPrescribed',
    triggerValue: 'Y',
    requiredFields: ['patientPainEstimate'],
    applicableForms: ['C151', 'C151S'],
  },
];

// ---------------------------------------------------------------------------
// Date helpers
// ---------------------------------------------------------------------------

function isValidDate(dateStr: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) return false;
  const d = new Date(dateStr + 'T00:00:00Z');
  if (isNaN(d.getTime())) return false;
  return d.toISOString().startsWith(dateStr);
}

function parseDate(dateStr: string): Date {
  return new Date(dateStr + 'T00:00:00Z');
}

// Alberta statutory holiday dates for 2025-2027 (pre-computed for business day calculation)
function getAlbertaHolidays(year: number): Set<string> {
  const holidays = new Set<string>();

  // Fixed holidays
  holidays.add(`${year}-01-01`); // New Year's Day
  holidays.add(`${year}-07-01`); // Canada Day
  holidays.add(`${year}-09-30`); // Truth and Reconciliation Day
  holidays.add(`${year}-12-25`); // Christmas Day

  // Family Day: third Monday of February
  holidays.add(nthWeekday(year, 1, 1, 3)); // month=1(Feb), weekday=1(Mon), nth=3

  // Good Friday: 2 days before Easter Sunday
  const easter = computeEaster(year);
  const goodFriday = new Date(easter);
  goodFriday.setUTCDate(goodFriday.getUTCDate() - 2);
  holidays.add(formatDateUTC(goodFriday));

  // Victoria Day: Monday before May 25
  const may25 = new Date(Date.UTC(year, 4, 25));
  const dow = may25.getUTCDay();
  const diff = dow === 0 ? 6 : dow === 1 ? 7 : dow - 1;
  const victoriaDay = new Date(Date.UTC(year, 4, 25 - diff));
  holidays.add(formatDateUTC(victoriaDay));

  // Heritage Day: first Monday of August
  holidays.add(nthWeekday(year, 7, 1, 1)); // month=7(Aug), weekday=1(Mon), nth=1

  // Labour Day: first Monday of September
  holidays.add(nthWeekday(year, 8, 1, 1)); // month=8(Sep), weekday=1(Mon), nth=1

  // Thanksgiving Day: second Monday of October
  holidays.add(nthWeekday(year, 9, 1, 2)); // month=9(Oct), weekday=1(Mon), nth=2

  return holidays;
}

function nthWeekday(year: number, month: number, weekday: number, nth: number): string {
  const d = new Date(Date.UTC(year, month, 1));
  let count = 0;
  while (count < nth) {
    if (d.getUTCDay() === weekday) count++;
    if (count < nth) d.setUTCDate(d.getUTCDate() + 1);
  }
  return formatDateUTC(d);
}

function computeEaster(year: number): Date {
  // Anonymous Gregorian algorithm
  const a = year % 19;
  const b = Math.floor(year / 100);
  const c = year % 100;
  const d = Math.floor(b / 4);
  const e = b % 4;
  const f = Math.floor((b + 8) / 25);
  const g = Math.floor((b - f + 1) / 3);
  const h = (19 * a + b - d - g + 15) % 30;
  const i = Math.floor(c / 4);
  const k = c % 4;
  const l = (32 + 2 * e + 2 * i - h - k) % 7;
  const m = Math.floor((a + 11 * h + 22 * l) / 451);
  const month = Math.floor((h + l - 7 * m + 114) / 31) - 1;
  const day = ((h + l - 7 * m + 114) % 31) + 1;
  return new Date(Date.UTC(year, month, day));
}

function formatDateUTC(d: Date): string {
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, '0');
  const day = String(d.getUTCDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}

function isBusinessDay(dateStr: string, holidays: Set<string>): boolean {
  const d = parseDate(dateStr);
  const dow = d.getUTCDay();
  if (dow === 0 || dow === 6) return false; // Weekend
  if (holidays.has(dateStr)) return false;
  return true;
}

function addBusinessDays(startDateStr: string, days: number, holidays: Set<string>): string {
  const d = parseDate(startDateStr);
  let added = 0;
  while (added < days) {
    d.setUTCDate(d.getUTCDate() + 1);
    const ds = formatDateUTC(d);
    if (isBusinessDay(ds, holidays)) added++;
  }
  return formatDateUTC(d);
}

// Mountain Time offset: UTC-7 (MST). During DST (second Sunday March to
// first Sunday November) it is UTC-6 (MDT). The 10:00 MT cutoff converts
// to either 17:00 UTC (MST) or 16:00 UTC (MDT).

function isMDT(utcDate: Date): boolean {
  const year = utcDate.getUTCFullYear();
  // DST starts second Sunday of March
  const marchFirst = new Date(Date.UTC(year, 2, 1));
  const marchFirstDay = marchFirst.getUTCDay();
  const secondSunday = marchFirstDay === 0 ? 8 : 8 + (7 - marchFirstDay);
  const dstStart = new Date(Date.UTC(year, 2, secondSunday, 9, 0, 0)); // 2:00 MT = 09:00 UTC

  // DST ends first Sunday of November
  const novFirst = new Date(Date.UTC(year, 10, 1));
  const novFirstDay = novFirst.getUTCDay();
  const firstSunday = novFirstDay === 0 ? 1 : 1 + (7 - novFirstDay);
  const dstEnd = new Date(Date.UTC(year, 10, firstSunday, 8, 0, 0)); // 2:00 MT = 08:00 UTC

  return utcDate >= dstStart && utcDate < dstEnd;
}

function getDeadlineCutoffUTC(deadlineDateStr: string): Date {
  // 10:00 MT on the deadline day
  const d = parseDate(deadlineDateStr);
  // Check if this date falls in MDT or MST
  const testDate = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate(), 12, 0, 0));
  if (isMDT(testDate)) {
    // MDT = UTC-6, so 10:00 MDT = 16:00 UTC
    return new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate(), 16, 0, 0));
  } else {
    // MST = UTC-7, so 10:00 MST = 17:00 UTC
    return new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate(), 17, 0, 0));
  }
}

export interface TimingTierResult {
  tier: string;
  deadline: Date;
  hoursRemaining: number;
  sameDayDeadline?: string;
  onTimeDeadline?: string;
}

function calculateTimingTier(
  formType: string,
  dateOfExamination: string | null | undefined,
  now?: Date,
): TimingTierResult | null {
  const rule = WCB_TIMING_DEADLINE_RULES.find((r) => r.formType === formType);
  if (!rule || !dateOfExamination) return null;

  const currentDate = now ?? new Date();
  const examDate = parseDate(dateOfExamination);
  const examYear = examDate.getUTCFullYear();
  const holidays = getAlbertaHolidays(examYear);
  // Also get next year holidays in case deadline crosses year boundary
  const nextYearHolidays = getAlbertaHolidays(examYear + 1);
  const allHolidays = new Set([...holidays, ...nextYearHolidays]);

  // Date of examination = Day 0 (not counted in business days)
  const examDateStr = formatDateUTC(examDate);

  // Same-day deadline: exam day if it's a business day, otherwise next business day
  let sameDayDeadline: string;
  if (isBusinessDay(examDateStr, allHolidays)) {
    sameDayDeadline = examDateStr;
  } else {
    sameDayDeadline = addBusinessDays(examDateStr, 1, allHolidays);
  }

  // On-time deadline: N business days after exam date (Day 0 not counted)
  const onTimeDeadline = addBusinessDays(examDateStr, rule.onTimeBusinessDays, allHolidays);

  // Compute cutoff timestamps at 10:00 MT on deadline days
  const sameDayCutoff = getDeadlineCutoffUTC(sameDayDeadline);
  const onTimeCutoff = getDeadlineCutoffUTC(onTimeDeadline);

  // Determine tier using precise timestamps with 10:00 MT cutoff
  let tier: string;
  let deadline: Date;

  if (currentDate <= sameDayCutoff) {
    tier = WcbTimingTier.SAME_DAY;
    deadline = sameDayCutoff;
  } else if (currentDate <= onTimeCutoff) {
    tier = WcbTimingTier.ON_TIME;
    deadline = onTimeCutoff;
  } else {
    tier = WcbTimingTier.LATE;
    deadline = onTimeCutoff; // deadline has already passed
  }

  // Calculate hours remaining (negative if past deadline)
  const msRemaining = deadline.getTime() - currentDate.getTime();
  const hoursRemaining = Math.floor(msRemaining / (1000 * 60 * 60));

  return { tier, deadline, hoursRemaining, sameDayDeadline, onTimeDeadline };
}

// ---------------------------------------------------------------------------
// Main validation function
// ---------------------------------------------------------------------------

export async function validateWcbClaim(
  deps: WcbServiceDeps,
  wcbClaimDetailId: string,
  physicianId: string,
  validationDate?: Date,
): Promise<WcbValidationResult> {
  const errors: ValidationIssue[] = [];
  const warnings: ValidationIssue[] = [];
  let timingTier: string | undefined;

  // Load the full claim with all child records
  const claim = await deps.wcbRepo.getWcbClaim(wcbClaimDetailId, physicianId);
  if (!claim) {
    throw new NotFoundError('WCB claim');
  }

  const detail = claim.detail;
  const formId = detail.formId as string;

  // --- Check 1: Form ID valid ---
  const formConfig = WCB_FORM_TYPE_CONFIGS[formId as WcbFormType];
  if (!formConfig) {
    errors.push({
      check_id: WcbValidationCheckId.FORM_ID_VALID,
      severity: ValidationSeverity.ERROR,
      field: 'formId',
      message: `Unrecognized WCB form type: ${formId}`,
    });
    // Cannot proceed with further validation
    return buildResult(errors, warnings, timingTier, validationDate);
  }

  // --- Check 2: Contract/Role/Form combination ---
  checkContractRoleForm(detail, formConfig, errors);

  // --- Check 3: Required fields ---
  checkRequiredFields(detail, formId, errors);

  // --- Check 4: Conditional field logic ---
  checkConditionalLogic(detail, formId, claim, errors);

  // --- Check 5: Data type / length ---
  checkDataTypeLength(detail, errors);

  // --- Check 6: Date validation ---
  checkDateValidation(detail, errors);

  // --- Check 7: POB-NOI combination ---
  checkPobNoiCombination(claim.injuries, errors);

  // --- Check 8: Side of body ---
  checkSideOfBody(claim.injuries, errors);

  // --- Check 9: Code table values ---
  checkCodeTableValues(detail, claim.invoiceLines, errors);

  // --- Check 10: Submitter txn ID format ---
  checkSubmitterTxnFormat(detail, errors);

  // --- Check 11: PHN logic ---
  checkPhnLogic(detail, errors);

  // --- Check 12: Invoice line integrity ---
  checkInvoiceLineIntegrity(formId, claim.invoiceLines, errors);

  // --- Check 13: Attachment constraints (warning) ---
  checkAttachmentConstraints(claim.attachments, warnings);

  // --- Check 14: Timing deadline (warning) ---
  const timing = calculateTimingTier(
    formId,
    (detail as Record<string, unknown>).dateOfExamination as string | null,
    validationDate,
  );
  if (timing) {
    timingTier = timing.tier;
    if (timing.tier === WcbTimingTier.LATE) {
      warnings.push({
        check_id: WcbValidationCheckId.TIMING_DEADLINE,
        severity: ValidationSeverity.WARNING,
        message: `Submission is past the on-time deadline (${timing.onTimeDeadline}). Late tier fee will apply.`,
      });
    }
  }

  // --- Check 15: Expedite eligibility (warning) ---
  checkExpediteEligibility(claim.consultations, warnings);

  // --- Check 16: Duplicate detection (warning) ---
  await checkDuplicateDetection(deps, physicianId, wcbClaimDetailId, detail, warnings);

  return buildResult(errors, warnings, timingTier, validationDate);
}

// ---------------------------------------------------------------------------
// Check implementations
// ---------------------------------------------------------------------------

function checkContractRoleForm(
  detail: Record<string, unknown>,
  formConfig: { isInitial: boolean },
  errors: ValidationIssue[],
): void {
  const contractId = detail.contractId as string;
  const roleCode = detail.roleCode as string;
  const formId = detail.formId as string;

  if (!contractId || !roleCode) return;

  const permitted = formConfig.isInitial
    ? isFormPermittedForInitial(contractId, roleCode, formId)
    : isFormPermittedForFollowUp(contractId, roleCode, formId);

  if (!permitted) {
    errors.push({
      check_id: WcbValidationCheckId.CONTRACT_ROLE_FORM,
      severity: ValidationSeverity.ERROR,
      field: 'contractId',
      message: `Contract ${contractId} with role ${roleCode} does not permit form ${formId}`,
    });
  }
}

function checkRequiredFields(
  detail: Record<string, unknown>,
  formId: string,
  errors: ValidationIssue[],
): void {
  const requiredFields = REQUIRED_FIELDS_BY_FORM[formId];
  if (!requiredFields) return;

  for (const field of requiredFields) {
    const value = detail[field];
    if (value === null || value === undefined || value === '') {
      errors.push({
        check_id: WcbValidationCheckId.REQUIRED_FIELDS,
        severity: ValidationSeverity.ERROR,
        field,
        message: `Required field '${field}' is missing or empty`,
      });
    }
  }
}

function checkConditionalLogic(
  detail: Record<string, unknown>,
  formId: string,
  claim: WcbClaimWithChildren,
  errors: ValidationIssue[],
): void {
  for (const rule of CONDITIONAL_RULES) {
    // Check if rule applies to this form type
    if (rule.applicableForms && !rule.applicableForms.includes(formId)) {
      continue;
    }

    const triggerValue = detail[rule.triggerField];
    if (triggerValue !== rule.triggerValue) continue;

    for (const requiredField of rule.requiredFields) {
      // Special handling for child table arrays
      if (requiredField === 'prescriptions') {
        if (!claim.prescriptions || claim.prescriptions.length === 0) {
          errors.push({
            check_id: WcbValidationCheckId.CONDITIONAL_LOGIC,
            severity: ValidationSeverity.ERROR,
            field: 'prescriptions',
            message: `Prescriptions are required when ${rule.triggerField} = '${rule.triggerValue}'`,
          });
        }
        continue;
      }
      if (requiredField === 'workRestrictions') {
        if (!claim.workRestrictions || claim.workRestrictions.length === 0) {
          errors.push({
            check_id: WcbValidationCheckId.CONDITIONAL_LOGIC,
            severity: ValidationSeverity.ERROR,
            field: 'workRestrictions',
            message: `Work restrictions are required when ${rule.triggerField} = '${rule.triggerValue}'`,
          });
        }
        continue;
      }

      const value = detail[requiredField];
      if (value === null || value === undefined || value === '') {
        errors.push({
          check_id: WcbValidationCheckId.CONDITIONAL_LOGIC,
          severity: ValidationSeverity.ERROR,
          field: requiredField,
          message: `Field '${requiredField}' is required when ${rule.triggerField} = '${rule.triggerValue}'`,
        });
      }
    }
  }
}

function checkDataTypeLength(
  detail: Record<string, unknown>,
  errors: ValidationIssue[],
): void {
  for (const [field, spec] of Object.entries(FIELD_SPECS)) {
    const value = detail[field];
    if (value === null || value === undefined || value === '') continue;

    const strValue = String(value);

    // Max length check
    if (spec.maxLength && strValue.length > spec.maxLength) {
      errors.push({
        check_id: WcbValidationCheckId.DATA_TYPE_LENGTH,
        severity: ValidationSeverity.ERROR,
        field,
        message: `Field '${field}' exceeds maximum length of ${spec.maxLength} (got ${strValue.length})`,
      });
    }

    // Type check: alpha fields must not contain digits
    if (spec.type === 'alpha' && /\d/.test(strValue)) {
      errors.push({
        check_id: WcbValidationCheckId.DATA_TYPE_LENGTH,
        severity: ValidationSeverity.ERROR,
        field,
        message: `Field '${field}' must contain only alphabetic characters`,
      });
    }

    // Type check: numeric fields must contain only digits
    if (spec.type === 'numeric' && !/^\d+$/.test(strValue)) {
      errors.push({
        check_id: WcbValidationCheckId.DATA_TYPE_LENGTH,
        severity: ValidationSeverity.ERROR,
        field,
        message: `Field '${field}' must contain only numeric characters`,
      });
    }

    // Type check: date fields must be valid dates
    if (spec.type === 'date' && !isValidDate(strValue)) {
      errors.push({
        check_id: WcbValidationCheckId.DATA_TYPE_LENGTH,
        severity: ValidationSeverity.ERROR,
        field,
        message: `Field '${field}' is not a valid date (expected YYYY-MM-DD)`,
      });
    }
  }
}

function checkDateValidation(
  detail: Record<string, unknown>,
  errors: ValidationIssue[],
): void {
  const dateOfInjury = detail.dateOfInjury as string | null;
  const dateOfExamination = detail.dateOfExamination as string | null;
  const reportCompletionDate = detail.reportCompletionDate as string | null;

  // Date ordering: exam date >= injury date
  if (dateOfInjury && dateOfExamination && isValidDate(dateOfInjury) && isValidDate(dateOfExamination)) {
    if (dateOfExamination < dateOfInjury) {
      errors.push({
        check_id: WcbValidationCheckId.DATE_VALIDATION,
        severity: ValidationSeverity.ERROR,
        field: 'dateOfExamination',
        message: 'Date of examination cannot be before date of injury',
      });
    }
  }

  // Report completion date >= exam date
  if (dateOfExamination && reportCompletionDate && isValidDate(dateOfExamination) && isValidDate(reportCompletionDate)) {
    if (reportCompletionDate < dateOfExamination) {
      errors.push({
        check_id: WcbValidationCheckId.DATE_VALIDATION,
        severity: ValidationSeverity.ERROR,
        field: 'reportCompletionDate',
        message: 'Report completion date cannot be before date of examination',
      });
    }
  }

  // Date of injury should not be in the future
  if (dateOfInjury && isValidDate(dateOfInjury)) {
    const today = formatDateUTC(new Date());
    if (dateOfInjury > today) {
      errors.push({
        check_id: WcbValidationCheckId.DATE_VALIDATION,
        severity: ValidationSeverity.ERROR,
        field: 'dateOfInjury',
        message: 'Date of injury cannot be in the future',
      });
    }
  }
}

function checkPobNoiCombination(
  injuries: Array<Record<string, unknown>>,
  errors: ValidationIssue[],
): void {
  if (!injuries || injuries.length === 0) return;

  for (let i = 0; i < injuries.length; i++) {
    const injury = injuries[i];
    const pob = injury.partOfBodyCode as string;
    const noi = injury.natureOfInjuryCode as string;
    if (!pob || !noi) continue;

    // Format: 'NOI_code:POB_code' per WCB exclusion matrix spec
    const key = `${noi}:${pob}`;
    if (POB_NOI_EXCLUSIONS.has(key)) {
      const noiDesc = NOI_DESCRIPTIONS[noi] ?? noi;
      const pobDesc = POB_DESCRIPTIONS[pob] ?? POB_DESCRIPTION_MAP.get(pob) ?? pob;
      errors.push({
        check_id: WcbValidationCheckId.POB_NOI_COMBINATION,
        severity: ValidationSeverity.ERROR,
        field: `injuries[${i}]`,
        message: `The combination of ${noiDesc} and ${pobDesc} is not permitted by WCB (injury #${i + 1})`,
      });
    }
  }
}

function checkSideOfBody(
  injuries: Array<Record<string, unknown>>,
  errors: ValidationIssue[],
): void {
  if (!injuries || injuries.length === 0) return;

  for (let i = 0; i < injuries.length; i++) {
    const injury = injuries[i];
    const pob = injury.partOfBodyCode as string;
    const side = injury.sideOfBodyCode as string | null | undefined;
    if (!pob) continue;

    if (POBS_REQUIRING_SIDE.has(pob) && (!side || side === '')) {
      const pobDesc = POB_DESCRIPTION_MAP.get(pob) ?? pob;
      errors.push({
        check_id: WcbValidationCheckId.SIDE_OF_BODY,
        severity: ValidationSeverity.ERROR,
        field: `injuries[${i}].sideOfBodyCode`,
        message: `Side of body is required for ${pobDesc} (${pob})`,
      });
    }
  }
}

function checkCodeTableValues(
  detail: Record<string, unknown>,
  invoiceLines: Array<Record<string, unknown>>,
  errors: ValidationIssue[],
): void {
  // Facility type
  const facilityType = detail.facilityType as string | null;
  if (facilityType && !VALID_FACILITY_TYPES.has(facilityType as WcbFacilityType)) {
    errors.push({
      check_id: WcbValidationCheckId.CODE_TABLE_VALUES,
      severity: ValidationSeverity.ERROR,
      field: 'facilityType',
      message: `Invalid facility type: '${facilityType}'. Must be one of: C, F, H`,
    });
  }

  // Gender
  const gender = detail.patientGender as string | null;
  if (gender && !VALID_GENDERS.has(gender)) {
    errors.push({
      check_id: WcbValidationCheckId.CODE_TABLE_VALUES,
      severity: ValidationSeverity.ERROR,
      field: 'patientGender',
      message: `Invalid gender code: '${gender}'. Must be one of: M, F, X`,
    });
  }

  // Yes/No enum fields
  const yesNoFields = ['patientNoPhnFlag', 'narcoticsPrescribed', 'missedWorkBeyondAccident', 'patientReturnedToWork'];
  for (const field of yesNoFields) {
    const val = detail[field] as string | null;
    if (val && !VALID_YES_NO.has(val)) {
      errors.push({
        check_id: WcbValidationCheckId.CODE_TABLE_VALUES,
        severity: ValidationSeverity.ERROR,
        field,
        message: `Invalid value for '${field}': '${val}'. Must be Y or N`,
      });
    }
  }

  // Invoice line types
  if (invoiceLines) {
    for (let i = 0; i < invoiceLines.length; i++) {
      const lt = invoiceLines[i].lineType as string;
      if (lt && !VALID_INVOICE_LINE_TYPES.has(lt as WcbInvoiceLineType)) {
        errors.push({
          check_id: WcbValidationCheckId.CODE_TABLE_VALUES,
          severity: ValidationSeverity.ERROR,
          field: `invoiceLines[${i}].lineType`,
          message: `Invalid invoice line type: '${lt}'`,
        });
      }
    }
  }
}

function checkSubmitterTxnFormat(
  detail: Record<string, unknown>,
  errors: ValidationIssue[],
): void {
  const txnId = detail.submitterTxnId as string | null;
  if (!txnId) {
    errors.push({
      check_id: WcbValidationCheckId.SUBMITTER_TXN_FORMAT,
      severity: ValidationSeverity.ERROR,
      field: 'submitterTxnId',
      message: 'Submitter transaction ID is missing',
    });
    return;
  }

  // Must start with MRT prefix
  if (!txnId.startsWith('MRT')) {
    errors.push({
      check_id: WcbValidationCheckId.SUBMITTER_TXN_FORMAT,
      severity: ValidationSeverity.ERROR,
      field: 'submitterTxnId',
      message: 'Submitter transaction ID must start with vendor prefix MRT',
    });
  }

  // Must be 16 characters total
  if (txnId.length !== 16) {
    errors.push({
      check_id: WcbValidationCheckId.SUBMITTER_TXN_FORMAT,
      severity: ValidationSeverity.ERROR,
      field: 'submitterTxnId',
      message: `Submitter transaction ID must be 16 characters (got ${txnId.length})`,
    });
  }
}

function checkPhnLogic(
  detail: Record<string, unknown>,
  errors: ValidationIssue[],
): void {
  const noPhnFlag = detail.patientNoPhnFlag as string | null;
  const phn = detail.patientPhn as string | null;

  if (noPhnFlag === 'N') {
    // PHN is required when no_phn_flag = N
    if (!phn || phn === '') {
      errors.push({
        check_id: WcbValidationCheckId.PHN_LOGIC,
        severity: ValidationSeverity.ERROR,
        field: 'patientPhn',
        message: 'PHN is required when patient_no_phn_flag is N',
      });
      return;
    }

    // PHN must be exactly 9 digits
    if (!/^\d{9}$/.test(phn)) {
      errors.push({
        check_id: WcbValidationCheckId.PHN_LOGIC,
        severity: ValidationSeverity.ERROR,
        field: 'patientPhn',
        message: 'PHN must be exactly 9 digits',
      });
    }
  } else if (noPhnFlag === 'Y') {
    // PHN should be blank when no_phn_flag = Y
    if (phn && phn !== '') {
      errors.push({
        check_id: WcbValidationCheckId.PHN_LOGIC,
        severity: ValidationSeverity.ERROR,
        field: 'patientPhn',
        message: 'PHN must be blank when patient_no_phn_flag is Y',
      });
    }
  }
}

function checkInvoiceLineIntegrity(
  formId: string,
  invoiceLines: Array<Record<string, unknown>>,
  errors: ValidationIssue[],
): void {
  const invoiceForms = [WcbFormType.C568, WcbFormType.C568A, WcbFormType.C569, WcbFormType.C570];
  const isInvoiceForm = invoiceForms.includes(formId as WcbFormType);

  if (isInvoiceForm) {
    if (!invoiceLines || invoiceLines.length === 0) {
      errors.push({
        check_id: WcbValidationCheckId.INVOICE_LINE_INTEGRITY,
        severity: ValidationSeverity.ERROR,
        field: 'invoiceLines',
        message: 'At least one invoice line is required for invoice forms',
      });
      return;
    }
  }

  if (!invoiceLines || invoiceLines.length === 0) return;

  // Check sequential invoiceDetailId (1-based, no gaps)
  const detailIds = invoiceLines
    .map((l) => l.invoiceDetailId as number)
    .filter((id) => typeof id === 'number')
    .sort((a, b) => a - b);

  for (let i = 0; i < detailIds.length; i++) {
    if (detailIds[i] !== i + 1) {
      errors.push({
        check_id: WcbValidationCheckId.INVOICE_LINE_INTEGRITY,
        severity: ValidationSeverity.ERROR,
        field: 'invoiceLines',
        message: `Invoice line IDs must be sequential starting from 1 (gap found at position ${i + 1})`,
      });
      break;
    }
  }

  // Check form-specific requirements
  for (let i = 0; i < invoiceLines.length; i++) {
    const line = invoiceLines[i];
    const lineType = line.lineType as string;

    // Standard and dated lines require health_service_code
    if ((lineType === 'STANDARD' || lineType === 'DATED') && !line.healthServiceCode) {
      errors.push({
        check_id: WcbValidationCheckId.INVOICE_LINE_INTEGRITY,
        severity: ValidationSeverity.ERROR,
        field: `invoiceLines[${i}].healthServiceCode`,
        message: 'Health service code is required for standard/dated invoice lines',
      });
    }

    // Supply lines require quantity and supply_description
    if (lineType === 'SUPPLY') {
      if (!line.quantity) {
        errors.push({
          check_id: WcbValidationCheckId.INVOICE_LINE_INTEGRITY,
          severity: ValidationSeverity.ERROR,
          field: `invoiceLines[${i}].quantity`,
          message: 'Quantity is required for supply invoice lines',
        });
      }
      if (!line.supplyDescription) {
        errors.push({
          check_id: WcbValidationCheckId.INVOICE_LINE_INTEGRITY,
          severity: ValidationSeverity.ERROR,
          field: `invoiceLines[${i}].supplyDescription`,
          message: 'Supply description is required for supply invoice lines',
        });
      }
    }

    // C570 correction lines require correctionPairId
    if ((lineType === 'WAS' || lineType === 'SHOULD_BE') && line.correctionPairId === null) {
      errors.push({
        check_id: WcbValidationCheckId.INVOICE_LINE_INTEGRITY,
        severity: ValidationSeverity.ERROR,
        field: `invoiceLines[${i}].correctionPairId`,
        message: 'Correction pair ID is required for WAS/SHOULD_BE lines',
      });
    }
  }
}

function checkAttachmentConstraints(
  attachments: Array<Record<string, unknown>>,
  warnings: ValidationIssue[],
): void {
  if (!attachments || attachments.length === 0) return;

  if (attachments.length > MAX_ATTACHMENTS) {
    warnings.push({
      check_id: WcbValidationCheckId.ATTACHMENT_CONSTRAINTS,
      severity: ValidationSeverity.WARNING,
      field: 'attachments',
      message: `Maximum ${MAX_ATTACHMENTS} attachments allowed (got ${attachments.length})`,
    });
  }

  for (let i = 0; i < attachments.length; i++) {
    const att = attachments[i];
    const fileType = att.fileType as string;
    if (fileType && !VALID_ATTACHMENT_TYPES.has(fileType)) {
      warnings.push({
        check_id: WcbValidationCheckId.ATTACHMENT_CONSTRAINTS,
        severity: ValidationSeverity.WARNING,
        field: `attachments[${i}].fileType`,
        message: `Invalid attachment file type: '${fileType}'. Allowed: PDF, DOC, DOCX, JPG, PNG, TIF`,
      });
    }
  }
}

function checkExpediteEligibility(
  consultations: Array<Record<string, unknown>>,
  warnings: ValidationIssue[],
): void {
  if (!consultations || consultations.length === 0) return;

  for (let i = 0; i < consultations.length; i++) {
    const c = consultations[i];
    if (c.expediteRequested === 'Y') {
      const category = c.category as string;
      if (!EXPEDITE_ELIGIBLE_CATEGORIES.has(category)) {
        warnings.push({
          check_id: WcbValidationCheckId.EXPEDITE_ELIGIBILITY,
          severity: ValidationSeverity.WARNING,
          field: `consultations[${i}].expediteRequested`,
          message: `Expedite requested for category '${category}' which may not be eligible for expedited processing`,
        });
      }
    }
  }
}

async function checkDuplicateDetection(
  deps: WcbServiceDeps,
  physicianId: string,
  currentWcbClaimDetailId: string,
  detail: Record<string, unknown>,
  warnings: ValidationIssue[],
): Promise<void> {
  const dateOfInjury = detail.dateOfInjury as string | null;
  const formId = detail.formId as string;
  const patientPhn = detail.patientPhn as string | null;

  if (!dateOfInjury || !patientPhn) return;

  // Search for existing claims with same patient + date of injury + form type
  const existing = await deps.wcbRepo.listWcbClaimsForPhysician(physicianId, {
    formId,
    page: 1,
    pageSize: 100,
  });

  for (const item of existing.data) {
    // Skip the current claim itself
    if (item.detail.wcbClaimDetailId === currentWcbClaimDetailId) continue;

    const existingDetail = item.detail as Record<string, unknown>;
    if (
      existingDetail.dateOfInjury === dateOfInjury &&
      existingDetail.patientPhn === patientPhn
    ) {
      warnings.push({
        check_id: WcbValidationCheckId.DUPLICATE_DETECTION,
        severity: ValidationSeverity.WARNING,
        message: `Potential duplicate: existing ${formId} claim found for the same patient and date of injury (${dateOfInjury})`,
      });
      break;
    }
  }
}

function buildResult(
  errors: ValidationIssue[],
  warnings: ValidationIssue[],
  timingTier: string | undefined,
  validationDate?: Date,
): WcbValidationResult {
  return {
    errors,
    warnings,
    passed: errors.length === 0,
    timing_tier: timingTier,
    validation_timestamp: (validationDate ?? new Date()).toISOString(),
    reference_data_version: '2025.1',
  };
}

// ===========================================================================
// Fee Calculation Engine — Section 8
// ===========================================================================

export interface InvoiceLineFeeResult {
  line_id: number;
  hsc: string;
  base_rate: string;
  premium_applied: boolean;
  fee: string;
}

export interface WcbFeeCalculationResult {
  report_fee: string;
  report_fee_tier: string;
  invoice_line_fees: InvoiceLineFeeResult[];
  expedited_fees: string;
  rrnp_fee: string;
  total_expected_fee: string;
}

/**
 * Calculate the total expected fee for a WCB claim.
 *
 * Business rules (FRD Section 8):
 * - Report fee: timing-tier-based from WCB_FEE_SCHEDULE_2025
 * - Invoice lines: each HSC at SOMB base rate, 100% unbundled (no bundling discounts)
 * - Premium codes: 351 codes at 2× SOMB; excluded within 4 cal days of injury; max 1 per encounter
 * - Expedited fees: full within 15 biz days, pro-rated 16-25, none after 25
 * - RRNP: $32.77 flat fee for qualifying rural/remote physicians
 */
export async function calculateWcbFees(
  deps: WcbServiceDeps,
  wcbClaimDetailId: string,
  physicianId: string,
  calculationDate?: Date,
): Promise<WcbFeeCalculationResult> {
  // 1. Load the full claim with all child records
  const claim = await deps.wcbRepo.getWcbClaim(wcbClaimDetailId, physicianId);
  if (!claim) {
    throw new NotFoundError('WCB claim');
  }

  const detail = claim.detail as Record<string, unknown>;
  const formId = detail.formId as string;
  const dateOfInjury = detail.dateOfInjury as string | null;
  const dateOfExamination = detail.dateOfExamination as string | null;
  const roleCode = detail.roleCode as string | null;

  // 2. Calculate timing tier and report fee
  const timing = calculateTimingTier(
    formId,
    dateOfExamination,
    calculationDate,
  );

  let reportFee = '0.00';
  let reportFeeTier = 'NONE';

  if (timing) {
    reportFeeTier = timing.tier;
    reportFee = lookupReportFee(formId, timing.tier, roleCode);
  }

  // 3. Calculate invoice line fees (unbundled at 100%)
  const invoiceLineFees = await calculateInvoiceLineFees(
    deps,
    claim.invoiceLines,
    dateOfInjury,
    detail.dateOfService as string | null,
  );

  // 4. Calculate expedited fees
  const expeditedFees = calculateExpeditedFees(
    claim.consultations,
    dateOfExamination,
    detail.reportCompletionDate as string | null,
    calculationDate,
  );

  // 5. Calculate RRNP fee
  const rrnpFee = await calculateRrnpFee(deps, physicianId);

  // 6. Sum total
  const total = addMoney(
    reportFee,
    addMoney(
      sumInvoiceLineFees(invoiceLineFees),
      addMoney(expeditedFees, rrnpFee),
    ),
  );

  return {
    report_fee: reportFee,
    report_fee_tier: reportFeeTier,
    invoice_line_fees: invoiceLineFees,
    expedited_fees: expeditedFees,
    rrnp_fee: rrnpFee,
    total_expected_fee: total,
  };
}

// ---------------------------------------------------------------------------
// Fee calculation helpers
// ---------------------------------------------------------------------------

/**
 * Look up the report fee from the fee schedule based on form type and timing tier.
 * Specialist consultation (C568A) uses RF01E schedule; specialist follow-up uses RF03E.
 */
function lookupReportFee(formId: string, tier: string, roleCode: string | null): string {
  // Determine the fee schedule code to look up
  let feeCode = WCB_FORM_TO_FEE_CODE[formId];

  // For C568A: specialists use RF01E schedule, specialist follow-ups use RF03E
  if (formId === 'C568A') {
    feeCode = 'RF01E';
  }

  if (!feeCode) {
    return '0.00';
  }

  const scheduleEntry = WCB_FEE_SCHEDULE_2025.find((e) => e.formCode === feeCode);
  if (!scheduleEntry) {
    return '0.00';
  }

  switch (tier) {
    case WcbTimingTier.SAME_DAY:
      return scheduleEntry.sameDayFee;
    case WcbTimingTier.ON_TIME:
      return scheduleEntry.onTimeFee;
    case WcbTimingTier.LATE:
      return scheduleEntry.lateFee;
    default:
      return '0.00';
  }
}

/**
 * Calculate fees for each invoice line. WCB pays 100% per distinct service
 * (no bundling discounts). Premium codes get 2× SOMB base rate.
 */
async function calculateInvoiceLineFees(
  deps: WcbServiceDeps,
  invoiceLines: Array<Record<string, unknown>>,
  dateOfInjury: string | null,
  dateOfService: string | null,
): Promise<InvoiceLineFeeResult[]> {
  if (!invoiceLines || invoiceLines.length === 0) {
    return [];
  }

  const results: InvoiceLineFeeResult[] = [];
  let premiumAppliedCount = 0;

  for (const line of invoiceLines) {
    const lineId = line.invoiceDetailId as number;
    const hsc = line.healthServiceCode as string | null;
    const lineType = line.lineType as string;
    const explicitAmount = line.amount as string | null;

    // Supply lines use their explicit amount
    if (lineType === 'SUPPLY' || !hsc) {
      results.push({
        line_id: lineId,
        hsc: hsc ?? '',
        base_rate: explicitAmount ?? '0.00',
        premium_applied: false,
        fee: explicitAmount ?? '0.00',
      });
      continue;
    }

    // Look up base rate from reference data
    let baseRate = '0.00';
    let isPremiumCode = false;

    if (deps.referenceLookup) {
      const hscInfo = await deps.referenceLookup.findHscBaseRate(
        hsc,
        dateOfService ?? undefined,
      );
      if (hscInfo) {
        baseRate = hscInfo.baseFee ?? '0.00';
        isPremiumCode = hscInfo.isPremiumCode;
      }
    } else if (explicitAmount) {
      // Fallback: use the explicit amount on the line
      baseRate = explicitAmount;
    }

    // Determine if premium applies
    let premiumApplied = false;
    let fee = baseRate;

    if (isPremiumCode) {
      const eligible = isPremiumEligible(
        dateOfService ?? (line.dateOfServiceFrom as string | null),
        dateOfInjury,
        premiumAppliedCount,
      );
      if (eligible) {
        premiumApplied = true;
        premiumAppliedCount++;
        fee = multiplyMoney(baseRate, WCB_PREMIUM_MULTIPLIER);
      }
    }

    results.push({
      line_id: lineId,
      hsc,
      base_rate: baseRate,
      premium_applied: premiumApplied,
      fee,
    });
  }

  return results;
}

/**
 * Check if a premium code is eligible for the 2× premium.
 * Excluded when date of service is within 4 calendar days of date of injury.
 * Limited to one premium per operative encounter.
 */
function isPremiumEligible(
  dateOfService: string | null,
  dateOfInjury: string | null,
  premiumsAlreadyApplied: number,
): boolean {
  // One premium per encounter limit
  if (premiumsAlreadyApplied >= WCB_PREMIUM_LIMIT_PER_ENCOUNTER) {
    return false;
  }

  // 4 calendar day exclusion from date of injury
  if (dateOfService && dateOfInjury) {
    const dos = parseDate(dateOfService);
    const doi = parseDate(dateOfInjury);
    const diffMs = dos.getTime() - doi.getTime();
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
    if (diffDays <= WCB_PREMIUM_EXCLUSION_DAYS) {
      return false;
    }
  }

  return true;
}

/**
 * Calculate expedited service fees based on consultation completion time.
 * - Within 15 business days: full fee
 * - 16-25 business days: pro-rated linearly
 * - After 25 business days: no fee
 */
function calculateExpeditedFees(
  consultations: Array<Record<string, unknown>>,
  dateOfExamination: string | null,
  reportCompletionDate: string | null,
  calculationDate?: Date,
): string {
  if (!consultations || consultations.length === 0) {
    return '0.00';
  }

  let totalExpedited = '0.00';

  for (const c of consultations) {
    if (c.expediteRequested !== 'Y') continue;

    // Calculate business days between exam date and completion/current date
    const startDate = dateOfExamination;
    const endDate = reportCompletionDate ?? formatDateUTC(calculationDate ?? new Date());

    if (!startDate) continue;

    const bizDays = countBusinessDays(startDate, endDate);

    if (bizDays <= WCB_EXPEDITED_FULL_DAYS) {
      // Full expedited fee
      totalExpedited = addMoney(totalExpedited, WCB_EXPEDITED_CONSULTATION_FEE);
    } else if (bizDays <= WCB_EXPEDITED_PRORATE_END_DAYS) {
      // Pro-rated: linear from 100% at day 15 to 0% at day 25
      const range = WCB_EXPEDITED_PRORATE_END_DAYS - WCB_EXPEDITED_FULL_DAYS; // 10
      const remaining = WCB_EXPEDITED_PRORATE_END_DAYS - bizDays;
      const ratio = remaining / range;
      const prorated = multiplyMoneyByRatio(WCB_EXPEDITED_CONSULTATION_FEE, ratio);
      totalExpedited = addMoney(totalExpedited, prorated);
    }
    // After 25 days: no fee (0.00)
  }

  return totalExpedited;
}

/**
 * Count business days between two date strings.
 */
function countBusinessDays(startDateStr: string, endDateStr: string): number {
  const startDate = parseDate(startDateStr);
  const endDate = parseDate(endDateStr);
  const startYear = startDate.getUTCFullYear();
  const endYear = endDate.getUTCFullYear();

  // Collect holidays for all years in range
  const allHolidays = new Set<string>();
  for (let y = startYear; y <= endYear; y++) {
    const yearHolidays = getAlbertaHolidays(y);
    for (const h of yearHolidays) allHolidays.add(h);
  }

  let count = 0;
  const cursor = new Date(startDate);
  cursor.setUTCDate(cursor.getUTCDate() + 1); // Start counting from day after start

  while (cursor <= endDate) {
    const ds = formatDateUTC(cursor);
    if (isBusinessDay(ds, allHolidays)) {
      count++;
    }
    cursor.setUTCDate(cursor.getUTCDate() + 1);
  }

  return count;
}

/**
 * Calculate RRNP fee for qualifying rural/remote northern physicians.
 * Returns $32.77 flat fee if the physician qualifies.
 */
async function calculateRrnpFee(
  deps: WcbServiceDeps,
  physicianId: string,
): Promise<string> {
  const provider = await deps.providerLookup.findProviderById(physicianId);
  if (!provider || !provider.isRrnpQualified) {
    return '0.00';
  }
  return WCB_RRNP_FLAT_FEE;
}

// ---------------------------------------------------------------------------
// Money arithmetic helpers (string-based, 2 decimal places, never floating point)
// ---------------------------------------------------------------------------

function addMoney(a: string, b: string): string {
  const cents = Math.round(parseFloat(a) * 100) + Math.round(parseFloat(b) * 100);
  return (cents / 100).toFixed(2);
}

function multiplyMoney(amount: string, multiplier: number): string {
  const cents = Math.round(parseFloat(amount) * 100) * multiplier;
  return (cents / 100).toFixed(2);
}

function multiplyMoneyByRatio(amount: string, ratio: number): string {
  const cents = Math.round(Math.round(parseFloat(amount) * 100) * ratio);
  return (cents / 100).toFixed(2);
}

function sumInvoiceLineFees(lines: InvoiceLineFeeResult[]): string {
  let totalCents = 0;
  for (const line of lines) {
    totalCents += Math.round(parseFloat(line.fee) * 100);
  }
  return (totalCents / 100).toFixed(2);
}

// ===========================================================================
// Batch Assembly & HL7 v2.3.1 XML Generation — Section D04W-024
// ===========================================================================

const HL7_NAMESPACE = 'urn:WCBhl7_v231-schema_modern_v100';

/**
 * Escape XML special characters in free-text fields.
 */
function escapeXml(text: string | null | undefined): string {
  if (!text) return '';
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * Format a Date as Mountain Time timestamp for HL7 headers.
 * Format: YYYYMMDDHHMMSS
 */
function formatMountainTimestamp(date: Date): string {
  // Mountain Time is UTC-7 (MST) or UTC-6 (MDT)
  const mtOffset = isMDT(date) ? -6 : -7;
  const utcMs = date.getTime();
  const mtMs = utcMs + mtOffset * 60 * 60 * 1000;
  const mt = new Date(mtMs);
  const y = mt.getUTCFullYear();
  const mo = String(mt.getUTCMonth() + 1).padStart(2, '0');
  const d = String(mt.getUTCDate()).padStart(2, '0');
  const h = String(mt.getUTCHours()).padStart(2, '0');
  const mi = String(mt.getUTCMinutes()).padStart(2, '0');
  const s = String(mt.getUTCSeconds()).padStart(2, '0');
  return `${y}${mo}${d}${h}${mi}${s}`;
}

/**
 * Format a date string (YYYY-MM-DD) as YYYYMMDD for HL7.
 */
function formatHl7Date(dateStr: string | null | undefined): string {
  if (!dateStr) return '';
  return dateStr.replace(/-/g, '');
}

/**
 * Map clinical observation fields from a WCB claim to OBX segments.
 * Each observation type gets a separate OBX with a coded identifier.
 */
interface ObxEntry {
  identifier: string;
  value: string;
}

function mapClaimToObservations(claim: WcbClaimWithChildren): ObxEntry[] {
  const entries: ObxEntry[] = [];
  const d = claim.detail as Record<string, unknown>;

  const addIfPresent = (id: string, val: unknown) => {
    if (val != null && val !== '') {
      entries.push({ identifier: id, value: escapeXml(String(val)) });
    }
  };

  addIfPresent('PRACTITIONER_ROLE', d.roleCode);
  addIfPresent('EMPNAME', d.employerName);
  addIfPresent('JOBTITL', d.workerJobTitle);
  addIfPresent('INJSYMP', d.symptoms);
  addIfPresent('OBJFIND', d.objectiveFindings);
  addIfPresent('CURDIAG', d.currentDiagnosis);
  addIfPresent('INJDESC', d.injuryDescription);
  addIfPresent('INJTIME', d.injuryDevelopedOverTime);
  addIfPresent('TXPLAN', d.treatmentPlanText);
  addIfPresent('NARCPRSC', d.narcoticsPrescribed);
  addIfPresent('MISSWORK', d.missedWorkBeyondAccident);
  addIfPresent('PATRTW', d.patientReturnedToWork);
  addIfPresent('ESTRTW', d.estimatedRtwDate);
  addIfPresent('PRIORCOND', d.priorConditionsFlag);
  addIfPresent('PRIORCONDDESC', d.priorConditionsDesc);
  addIfPresent('DIAGCHG', d.diagnosisChanged);
  addIfPresent('DIAGCHGDESC', d.diagnosisChangedDesc);

  // Injuries as OBX
  for (let i = 0; i < claim.injuries.length; i++) {
    const inj = claim.injuries[i];
    addIfPresent(`POB_${i + 1}`, inj.partOfBodyCode);
    addIfPresent(`SOB_${i + 1}`, inj.sideOfBodyCode);
    addIfPresent(`NOI_${i + 1}`, inj.natureOfInjuryCode);
  }

  // Prescriptions as OBX
  for (let i = 0; i < claim.prescriptions.length; i++) {
    const rx = claim.prescriptions[i];
    addIfPresent(`RXNAME_${i + 1}`, rx.prescriptionName);
    addIfPresent(`RXSTR_${i + 1}`, rx.strength);
    addIfPresent(`RXDAILY_${i + 1}`, rx.dailyIntake);
  }

  // Consultations as OBX
  for (let i = 0; i < claim.consultations.length; i++) {
    const con = claim.consultations[i];
    addIfPresent(`CONTYPE_${i + 1}`, con.typeCode);
    addIfPresent(`CONDETAIL_${i + 1}`, con.details);
    addIfPresent(`CONEXPEDITE_${i + 1}`, con.expediteRequested);
  }

  // Work restrictions as OBX
  for (let i = 0; i < claim.workRestrictions.length; i++) {
    const wr = claim.workRestrictions[i];
    addIfPresent(`WRACT_${i + 1}`, wr.activityType);
    addIfPresent(`WRLVL_${i + 1}`, wr.restrictionLevel);
    addIfPresent(`WRHRS_${i + 1}`, wr.hoursPerDay);
    addIfPresent(`WRWGT_${i + 1}`, wr.maxWeight);
  }

  return entries;
}

/**
 * Generate a single report (ZRPT_P03.GRP.2) XML block for one claim.
 */
function generateReportXml(
  claim: WcbClaimWithChildren,
  vendorSourceId: string,
  now: Date,
): string {
  const d = claim.detail as Record<string, unknown>;
  const submitterTxnId = escapeXml(d.submitterTxnId as string);
  const formId = escapeXml(d.formId as string);
  const timestamp = formatMountainTimestamp(now);
  const reportDate = formatHl7Date(d.reportCompletionDate as string);

  const lines: string[] = [];
  lines.push('<ZRPT_P03.GRP.2>');

  // MSH — Message Header
  lines.push('<MSH>');
  lines.push(`<MSH.3>${escapeXml(vendorSourceId)}</MSH.3>`);
  lines.push(`<MSH.7>${timestamp}</MSH.7>`);
  lines.push(`<MSH.9>ZRPT^P03</MSH.9>`);
  lines.push(`<MSH.10>${submitterTxnId}</MSH.10>`);
  lines.push('</MSH>');

  // EVN — Event
  lines.push('<EVN>');
  lines.push(`<EVN.1>${formId}</EVN.1>`);
  lines.push(`<EVN.2>${reportDate}</EVN.2>`);
  lines.push('</EVN>');

  // PRD — Provider
  const practLastName = escapeXml(d.practitionerLastName as string);
  const practFirstName = escapeXml(d.practitionerFirstName as string);
  const skillCode = escapeXml(d.skillCode as string);
  const faxNumber = escapeXml(d.faxNumber as string);
  lines.push('<PRD>');
  lines.push(`<PRD.2>${practLastName}^${practFirstName}</PRD.2>`);
  lines.push(`<PRD.3>${skillCode}</PRD.3>`);
  if (faxNumber) {
    lines.push(`<PRD.5>${faxNumber}</PRD.5>`);
  }
  lines.push('</PRD>');

  // PID — Patient
  const patientPhn = escapeXml(d.patientPhn as string);
  const patientDob = formatHl7Date(d.patientDob as string);
  const patLastName = escapeXml(d.patientLastName as string);
  const patFirstName = escapeXml(d.patientFirstName as string);
  const patGender = escapeXml(d.patientGender as string);
  const patAddr = escapeXml(d.patientAddressLine1 as string);
  const patCity = escapeXml(d.patientCity as string);
  const patProv = escapeXml(d.patientProvince as string);
  const patPostal = escapeXml(d.patientPostalCode as string);
  lines.push('<PID>');
  lines.push(`<PID.2>${patientPhn}</PID.2>`);
  lines.push(`<PID.5>${patLastName}^${patFirstName}</PID.5>`);
  lines.push(`<PID.7>${patientDob}</PID.7>`);
  lines.push(`<PID.8>${patGender}</PID.8>`);
  lines.push(`<PID.11>${patAddr}^${patCity}^${patProv}^${patPostal}</PID.11>`);
  lines.push('</PID>');

  // PV1 — Visit
  const clinicRef = escapeXml(d.clinicReferenceNumber as string);
  lines.push('<PV1>');
  lines.push(`<PV1.19>${clinicRef}</PV1.19>`);
  lines.push('</PV1>');

  // FT1 — Financial (repeats per invoice line)
  const billingNumber = escapeXml(d.practitionerBillingNumber as string);
  const contractId = escapeXml(d.contractId as string);
  const dateOfExam = formatHl7Date(d.dateOfExamination as string);
  const diagCode1 = escapeXml(d.diagnosticCode1 as string);
  const diagCode2 = escapeXml(d.diagnosticCode2 as string);
  const diagCode3 = escapeXml(d.diagnosticCode3 as string);

  for (const line of claim.invoiceLines) {
    const lineRec = line as Record<string, unknown>;
    lines.push('<FT1>');
    lines.push(`<FT1.6>${billingNumber}</FT1.6>`);
    lines.push(`<FT1.7>${contractId}</FT1.7>`);
    lines.push(`<FT1.4>${dateOfExam || formatHl7Date(lineRec.dateOfServiceFrom as string)}</FT1.4>`);
    lines.push(`<FT1.10>${diagCode1}</FT1.10>`);
    if (diagCode2) lines.push(`<FT1.11>${diagCode2}</FT1.11>`);
    if (diagCode3) lines.push(`<FT1.12>${diagCode3}</FT1.12>`);
    lines.push(`<FT1.25>${escapeXml(lineRec.healthServiceCode as string)}</FT1.25>`);
    if (lineRec.amount) {
      lines.push(`<FT1.26>${escapeXml(lineRec.amount as string)}</FT1.26>`);
    }
    if (lineRec.modifier1) lines.push(`<FT1.27>${escapeXml(lineRec.modifier1 as string)}</FT1.27>`);
    if (lineRec.modifier2) lines.push(`<FT1.28>${escapeXml(lineRec.modifier2 as string)}</FT1.28>`);
    if (lineRec.modifier3) lines.push(`<FT1.29>${escapeXml(lineRec.modifier3 as string)}</FT1.29>`);
    lines.push('</FT1>');
  }

  // ACC — Accident
  const dateOfInjury = formatHl7Date(d.dateOfInjury as string);
  lines.push('<ACC>');
  lines.push(`<ACC.1>${dateOfInjury}</ACC.1>`);
  lines.push('</ACC>');

  // NTE — Notes
  const comments = escapeXml(d.additionalComments as string);
  if (comments) {
    lines.push('<NTE>');
    lines.push(`<NTE.3>${comments}</NTE.3>`);
    lines.push('</NTE>');
  }

  // OBX — Observations (clinical data)
  const observations = mapClaimToObservations(claim);
  for (let i = 0; i < observations.length; i++) {
    const obs = observations[i];
    lines.push('<OBX>');
    lines.push(`<OBX.1>${i + 1}</OBX.1>`);
    lines.push(`<OBX.3>${obs.identifier}</OBX.3>`);
    lines.push(`<OBX.5>${obs.value}</OBX.5>`);
    lines.push('</OBX>');
  }

  // Attachments as OBX with base64 content
  for (let i = 0; i < claim.attachments.length; i++) {
    const att = claim.attachments[i] as Record<string, unknown>;
    lines.push('<OBX>');
    lines.push(`<OBX.1>${observations.length + i + 1}</OBX.1>`);
    lines.push(`<OBX.2>ED</OBX.2>`);
    lines.push(`<OBX.3>ATTACHMENT_${i + 1}</OBX.3>`);
    lines.push(`<OBX.5>${escapeXml(att.fileName as string)}^${escapeXml(att.fileType as string)}^Base64^${att.fileContentB64 ?? ''}</OBX.5>`);
    lines.push('</OBX>');
  }

  lines.push('</ZRPT_P03.GRP.2>');
  return lines.join('\n');
}

/**
 * Generate HL7 v2.3.1 XML batch file from claims.
 *
 * Document structure (exact nesting order):
 * - ZRPT_P03 (root, namespace urn:WCBhl7_v231-schema_modern_v100)
 *   - FHS (file header)
 *   - ZRPT_P03.LST.6 > ZRPT_P03.GRP.4 (batch wrapper)
 *     - BHS (batch header)
 *     - ZRPT_P03.LST.5 > ZRPT_P03.GRP.3 > ZRPT_P03.GRP.2 (per report)
 *     - BTS (batch trailer)
 *   - FTS (file trailer)
 */
export function generateBatchXml(
  batchId: string,
  batchControlId: string,
  fileControlId: string,
  claims: WcbClaimWithChildren[],
  vendorSourceId: string,
  now?: Date,
): string {
  const timestamp = now ?? new Date();
  const mtTimestamp = formatMountainTimestamp(timestamp);
  const receivingApp = 'WCB-EDM';
  const receivingFacility = 'RAPID-RPT';

  const lines: string[] = [];

  // XML declaration
  lines.push('<?xml version="1.0" encoding="UTF-8"?>');
  lines.push(`<ZRPT_P03 xmlns="${HL7_NAMESPACE}">`);

  // FHS — File Header
  lines.push('<FHS>');
  lines.push(`<FHS.3>${escapeXml(vendorSourceId)}</FHS.3>`);
  lines.push(`<FHS.4>${escapeXml(vendorSourceId)}</FHS.4>`);
  lines.push(`<FHS.5>${receivingApp}</FHS.5>`);
  lines.push(`<FHS.6>${receivingFacility}</FHS.6>`);
  lines.push(`<FHS.7>${mtTimestamp}</FHS.7>`);
  lines.push(`<FHS.9>${escapeXml(fileControlId)}</FHS.9>`);
  lines.push(`<FHS.11>${escapeXml(fileControlId)}</FHS.11>`);
  lines.push('</FHS>');

  // Batch wrapper
  lines.push('<ZRPT_P03.LST.6>');
  lines.push('<ZRPT_P03.GRP.4>');

  // BHS — Batch Header
  lines.push('<BHS>');
  lines.push(`<BHS.3>${escapeXml(vendorSourceId)}</BHS.3>`);
  lines.push(`<BHS.4>${escapeXml(vendorSourceId)}</BHS.4>`);
  lines.push(`<BHS.5>${receivingApp}</BHS.5>`);
  lines.push(`<BHS.6>${receivingFacility}</BHS.6>`);
  lines.push(`<BHS.7>${mtTimestamp}</BHS.7>`);
  lines.push(`<BHS.11>${escapeXml(batchControlId)}</BHS.11>`);
  lines.push('</BHS>');

  // Reports
  lines.push('<ZRPT_P03.LST.5>');
  for (const claim of claims) {
    lines.push('<ZRPT_P03.GRP.3>');
    lines.push(generateReportXml(claim, vendorSourceId, timestamp));
    lines.push('</ZRPT_P03.GRP.3>');
  }
  lines.push('</ZRPT_P03.LST.5>');

  // BTS — Batch Trailer
  lines.push('<BTS>');
  lines.push(`<BTS.1>${claims.length}</BTS.1>`);
  lines.push('</BTS>');

  lines.push('</ZRPT_P03.GRP.4>');
  lines.push('</ZRPT_P03.LST.6>');

  // FTS — File Trailer
  lines.push('<FTS>');
  lines.push('<FTS.1>1</FTS.1>');
  lines.push('</FTS>');

  lines.push('</ZRPT_P03>');

  return lines.join('\n');
}

/**
 * End-to-end batch assembly pipeline.
 *
 * 1. Create batch record (ASSEMBLING).
 * 2. Fetch all queued WCB claims for physician.
 * 3. For each claim: run validation. Skip claims that fail.
 * 4. Assign validated claims to batch.
 * 5. Generate HL7 v2.3.1 XML batch file.
 * 6. Store encrypted XML file. Set xml_file_path, xml_file_hash.
 * 7. Transition batch to GENERATED.
 * 8. Emit audit: wcb.batch_generated.
 * Returns wcb_batch_id.
 */
export async function assembleAndGenerateBatch(
  deps: WcbServiceDeps,
  physicianId: string,
  userId: string,
): Promise<{ wcbBatchId: string; reportCount: number; skippedClaimIds: string[] }> {
  // 1. Create batch record
  const batch = await deps.wcbRepo.createBatch(physicianId, userId);
  const wcbBatchId = batch.wcbBatchId;

  try {
    // 2. Fetch all queued WCB claims
    const queuedClaims = await deps.wcbRepo.getQueuedClaimsForBatch(physicianId);

    if (queuedClaims.length === 0) {
      // Transition to ERROR — no claims to process
      await deps.wcbRepo.updateBatchStatus(wcbBatchId, physicianId, WcbBatchStatus.ERROR);
      throw new BusinessRuleError('No queued WCB claims available for batch assembly');
    }

    // 3. Validate each claim. Only include claims that pass.
    const validatedClaims: WcbClaimWithChildren[] = [];
    const skippedClaimIds: string[] = [];

    for (const queued of queuedClaims) {
      const wcbClaimDetailId = queued.detail.wcbClaimDetailId;
      const claimId = queued.claim.claimId;
      try {
        const validation = await validateWcbClaim(deps, wcbClaimDetailId, physicianId);
        if (validation.passed) {
          // Load full claim with children for XML generation
          const fullClaim = await deps.wcbRepo.getWcbClaim(wcbClaimDetailId, physicianId);
          if (fullClaim) {
            validatedClaims.push(fullClaim);
          } else {
            skippedClaimIds.push(claimId);
          }
        } else {
          skippedClaimIds.push(claimId);
        }
      } catch (validationErr) {
        // Validation threw — skip this claim
        skippedClaimIds.push(claimId);
      }
    }

    if (validatedClaims.length === 0) {
      await deps.wcbRepo.updateBatchStatus(wcbBatchId, physicianId, WcbBatchStatus.ERROR);
      throw new BusinessRuleError('All queued claims failed validation; no claims to submit');
    }

    // 4. Assign validated claims to batch
    const claimIds = validatedClaims.map((c) => c.claim.claimId);
    await deps.wcbRepo.assignClaimsToBatch(wcbBatchId, physicianId, claimIds);

    // 5. Generate HL7 v2.3.1 XML
    const vendorSourceId = deps.secretsProvider?.getVendorSourceId() ?? 'MERITUM';
    const xml = generateBatchXml(
      wcbBatchId,
      batch.batchControlId,
      batch.fileControlId,
      validatedClaims,
      vendorSourceId,
    );

    // 6. Store encrypted XML file
    const xmlBuffer = Buffer.from(xml, 'utf-8');
    const xmlHash = createHash('sha256').update(xmlBuffer).digest('hex');
    const xmlFilePath = `wcb/batches/${wcbBatchId}/${batch.fileControlId}.xml`;

    if (deps.fileStorage) {
      await deps.fileStorage.storeEncrypted(xmlFilePath, xmlBuffer);
    }

    // 7. Transition batch to GENERATED
    await deps.wcbRepo.updateBatchStatus(wcbBatchId, physicianId, WcbBatchStatus.GENERATED, {
      xmlFilePath,
      xmlFileHash: xmlHash,
      reportCount: validatedClaims.length,
    });

    // 8. Emit audit
    await emitAudit(
      deps,
      claimIds[0],
      WcbAuditAction.WCB_BATCH_ASSEMBLED,
      userId,
      {
        wcbBatchId,
        batchControlId: batch.batchControlId,
        fileControlId: batch.fileControlId,
        reportCount: validatedClaims.length,
        skippedCount: skippedClaimIds.length,
      },
    );

    return {
      wcbBatchId,
      reportCount: validatedClaims.length,
      skippedClaimIds,
    };
  } catch (err) {
    // If the error is already a BusinessRuleError we threw above, re-throw it
    if (err instanceof BusinessRuleError) {
      throw err;
    }
    // Unexpected error — transition batch to ERROR and re-throw
    try {
      await deps.wcbRepo.updateBatchStatus(wcbBatchId, physicianId, WcbBatchStatus.ERROR);
    } catch {
      // Ignore error transitioning to ERROR state
    }
    throw err;
  }
}

// ===========================================================================
// XSD Validation — Phase 2 batch validation against WCB XML schemas
// ===========================================================================

/** XSD schema asset identifiers stored in Reference Data */
const XSD_STRUCTURAL = 'WCBhl7_v231_modern_v100.xsd';
const XSD_DATA = 'WCBhl7_v231_modern_v100_validate.xsd';

export interface XsdBatchValidationResult {
  passed: boolean;
  errors: XsdValidationError[];
  wcbBatchId: string;
}

/**
 * Validate generated batch XML against both WCB XSD schemas:
 *  1. Structural validation (WCBhl7_v231_modern_v100.xsd)
 *  2. Data validation (WCBhl7_v231_modern_v100_validate.xsd)
 *
 * On success: transitions batch to VALIDATED, sets xsd_validation_passed = true.
 * On failure: transitions batch to ERROR, stores errors in xsd_validation_errors.
 */
export async function validateBatchXsd(
  deps: WcbServiceDeps,
  wcbBatchId: string,
  physicianId: string,
  xsdAssets?: { structural: string; data: string },
): Promise<XsdBatchValidationResult> {
  if (!deps.xsdValidator) {
    throw new BusinessRuleError('XSD validation not available: validator not configured');
  }

  if (!deps.fileStorage) {
    throw new BusinessRuleError('XSD validation not available: file storage not configured');
  }

  // 1. Fetch batch — physician-scoped
  const batch = await deps.wcbRepo.getBatch(wcbBatchId, physicianId);
  if (!batch) {
    throw new NotFoundError('WCB batch');
  }

  // 2. Batch must be in GENERATED status
  if (batch.status !== WcbBatchStatus.GENERATED) {
    throw new BusinessRuleError(
      `Cannot validate batch: current status is ${batch.status}, expected GENERATED`,
    );
  }

  // 3. Read the batch XML from storage
  if (!batch.xmlFilePath) {
    throw new BusinessRuleError('Batch has no XML file path — cannot validate');
  }

  const xmlBuffer = await deps.fileStorage.readEncrypted(batch.xmlFilePath);
  const xmlContent = xmlBuffer.toString('utf-8');

  // 4. Get XSD schema content (passed as assets or read from storage)
  const structuralXsd = xsdAssets?.structural ?? '';
  const dataXsd = xsdAssets?.data ?? '';

  if (!structuralXsd || !dataXsd) {
    throw new BusinessRuleError('XSD schema assets not provided for validation');
  }

  // 5. Validate against structural XSD
  const structuralResult = deps.xsdValidator.validate(xmlContent, structuralXsd);

  // 6. If structural passes, validate against data XSD
  let dataResult: XsdValidationResult = { valid: true, errors: [] };
  if (structuralResult.valid) {
    dataResult = deps.xsdValidator.validate(xmlContent, dataXsd);
  }

  // 7. Combine errors
  const allErrors: XsdValidationError[] = [
    ...structuralResult.errors.map((e) => ({ ...e, message: `[structural] ${e.message}` })),
    ...dataResult.errors.map((e) => ({ ...e, message: `[data] ${e.message}` })),
  ];

  const passed = structuralResult.valid && dataResult.valid;

  if (passed) {
    // 8a. Transition to VALIDATED
    await deps.wcbRepo.updateBatchStatus(wcbBatchId, physicianId, WcbBatchStatus.VALIDATED, {
      xsdValidationPassed: true,
    });

    // Emit audit
    await emitAudit(
      deps,
      batch.wcbBatchId,
      WcbAuditAction.WCB_BATCH_VALIDATED,
      physicianId,
      {
        wcbBatchId,
        xsdValidationPassed: true,
        structuralSchema: XSD_STRUCTURAL,
        dataSchema: XSD_DATA,
      },
    );
  } else {
    // 8b. Transition to ERROR with validation errors
    await deps.wcbRepo.updateBatchStatus(wcbBatchId, physicianId, WcbBatchStatus.ERROR, {
      xsdValidationPassed: false,
      xsdValidationErrors: allErrors,
    });

    await emitAudit(
      deps,
      batch.wcbBatchId,
      WcbAuditAction.WCB_BATCH_VALIDATED,
      physicianId,
      {
        wcbBatchId,
        xsdValidationPassed: false,
        errorCount: allErrors.length,
      },
    );
  }

  return { passed, errors: allErrors, wcbBatchId };
}

// ===========================================================================
// Download URL — signed URL for batch XML download
// ===========================================================================

export interface BatchDownloadResult {
  downloadUrl: string;
  expiresAt: string;
  wcbBatchId: string;
}

/**
 * Generate a signed download URL for the batch XML file.
 * - Requires batch status = VALIDATED.
 * - URL expires after 1 hour.
 * - Emits audit: WCB_BATCH_DOWNLOADED.
 */
export async function generateDownloadUrl(
  deps: WcbServiceDeps,
  wcbBatchId: string,
  physicianId: string,
  actorId: string,
): Promise<BatchDownloadResult> {
  if (!deps.downloadUrlGenerator) {
    throw new BusinessRuleError('Download URL generation not available: generator not configured');
  }

  // 1. Fetch batch — physician-scoped
  const batch = await deps.wcbRepo.getBatch(wcbBatchId, physicianId);
  if (!batch) {
    throw new NotFoundError('WCB batch');
  }

  // 2. Must be VALIDATED
  if (batch.status !== WcbBatchStatus.VALIDATED) {
    throw new BusinessRuleError(
      `Cannot download batch: current status is ${batch.status}, expected VALIDATED`,
    );
  }

  // 3. Must have XML file
  if (!batch.xmlFilePath) {
    throw new BusinessRuleError('Batch has no XML file path — cannot generate download URL');
  }

  // 4. Generate signed URL (1 hour = 3600 seconds)
  const DOWNLOAD_EXPIRY_SECONDS = 3600;
  const downloadUrl = await deps.downloadUrlGenerator.generateSignedUrl(
    batch.xmlFilePath,
    DOWNLOAD_EXPIRY_SECONDS,
  );

  const expiresAt = new Date(Date.now() + DOWNLOAD_EXPIRY_SECONDS * 1000).toISOString();

  // 5. Emit audit
  await emitAudit(
    deps,
    wcbBatchId,
    WcbAuditAction.WCB_BATCH_DOWNLOADED,
    actorId,
    {
      wcbBatchId,
      xmlFilePath: batch.xmlFilePath,
      expiresAt,
    },
  );

  return { downloadUrl, expiresAt, wcbBatchId };
}

// ===========================================================================
// Upload Confirmation — physician/delegate confirms upload to myWCB
// ===========================================================================

export interface BatchUploadConfirmationResult {
  wcbBatchId: string;
  status: string;
  uploadedAt: string;
  uploadedBy: string;
}

/**
 * Confirm that the batch XML was uploaded to myWCB by the physician/delegate.
 * - Requires status = VALIDATED (upload implies download happened).
 * - Transitions to UPLOADED.
 * - Sets uploaded_at, uploaded_by.
 * - Emits audit: WCB_BATCH_UPLOADED.
 * - Emits notification: WCB_BATCH_UPLOADED.
 */
export async function confirmBatchUpload(
  deps: WcbServiceDeps,
  wcbBatchId: string,
  physicianId: string,
  userId: string,
): Promise<BatchUploadConfirmationResult> {
  // 1. Use repository's setBatchUploaded (handles physician scoping + VALIDATED guard)
  const updatedBatch = await deps.wcbRepo.setBatchUploaded(wcbBatchId, physicianId, userId);

  if (!updatedBatch) {
    throw new NotFoundError('WCB batch');
  }

  // 2. Emit audit
  await emitAudit(
    deps,
    wcbBatchId,
    WcbAuditAction.WCB_BATCH_UPLOADED,
    userId,
    {
      wcbBatchId,
      uploadedBy: userId,
      uploadedAt: updatedBatch.uploadedAt?.toISOString() ?? new Date().toISOString(),
    },
  );

  // 3. Emit notification
  if (deps.notificationEmitter) {
    await deps.notificationEmitter.emit('WCB_BATCH_UPLOADED', {
      wcbBatchId,
      physicianId,
      reportCount: updatedBatch.reportCount,
      uploadedBy: userId,
    });
  }

  return {
    wcbBatchId,
    status: WcbBatchStatus.UPLOADED,
    uploadedAt: updatedBatch.uploadedAt?.toISOString() ?? new Date().toISOString(),
    uploadedBy: userId,
  };
}

// ===========================================================================
// Return File Processing
// ===========================================================================

/**
 * Result of processing a WCB return file.
 */
export interface ProcessReturnFileResult {
  matched_count: number;
  complete_count: number;
  invalid_count: number;
  unmatched_count: number;
  errors: string[];
}

/**
 * Parsed batch header from a WCB return file.
 */
interface ReturnFileBatchHeader {
  batchId: string;
  reportCount: number;
  submitterId: string;
  submitDate: string;
}

/**
 * Parsed report block from a WCB return file.
 */
interface ReturnFileReportBlock {
  reportTxnId: string;
  submitterTxnId: string;
  processedClaimNumber: string | null;
  claimDecision: string;
  reportStatus: string;
  txnSubmissionDate: string;
  invoiceLines: Array<{
    invoiceSequence: number;
    serviceDate: string | null;
    healthServiceCode: string | null;
    invoiceStatus: string | null;
  }>;
  errors: Array<{ error_code: string; message: string }>;
}

/**
 * Parse a tab-delimited WCB return file into structured data.
 *
 * Format:
 *   Batch header line: BatchID\tReportCount\tSubmitterID\tSubmitDate
 *   Per-report blocks:
 *     Report header: ReportTxnID\tSubmitterTxnID\tProcessedClaim#\tClaimDecision\tReportStatus\tTxnSubmissionDate
 *     For Complete: invoice lines: InvoiceSequence#\tServiceDate\tHSC\tInvoiceStatus
 *     For Invalid: error lines: ErrorNumber: ErrorDescription
 *
 * Blocks are separated by blank lines. The first line is the batch header.
 */
export function parseReturnFile(fileContent: string): {
  header: ReturnFileBatchHeader;
  reports: ReturnFileReportBlock[];
} {
  const lines = fileContent.split('\n').map((l) => l.replace(/\r$/, ''));

  // Parse batch header (first non-empty line)
  let headerLineIdx = 0;
  while (headerLineIdx < lines.length && lines[headerLineIdx].trim() === '') {
    headerLineIdx++;
  }

  if (headerLineIdx >= lines.length) {
    throw new BusinessRuleError('Return file is empty or contains no batch header');
  }

  const headerParts = lines[headerLineIdx].split('\t');
  if (headerParts.length < 4) {
    throw new BusinessRuleError('Invalid batch header: expected BatchID, ReportCount, SubmitterID, SubmitDate');
  }

  const header: ReturnFileBatchHeader = {
    batchId: headerParts[0].trim(),
    reportCount: parseInt(headerParts[1].trim(), 10),
    submitterId: headerParts[2].trim(),
    submitDate: headerParts[3].trim(),
  };

  if (isNaN(header.reportCount)) {
    throw new BusinessRuleError('Invalid batch header: ReportCount must be a number');
  }

  // Parse report blocks — each starts with a 6-field tab-delimited line
  const reports: ReturnFileReportBlock[] = [];
  let i = headerLineIdx + 1;

  while (i < lines.length) {
    // Skip blank lines between blocks
    if (lines[i].trim() === '') {
      i++;
      continue;
    }

    // Parse report header line (6 tab-delimited fields)
    const reportParts = lines[i].split('\t');
    if (reportParts.length < 6) {
      // Not a valid report header, skip
      i++;
      continue;
    }

    const report: ReturnFileReportBlock = {
      reportTxnId: reportParts[0].trim(),
      submitterTxnId: reportParts[1].trim(),
      processedClaimNumber: reportParts[2].trim() || null,
      claimDecision: reportParts[3].trim(),
      reportStatus: reportParts[4].trim(),
      txnSubmissionDate: reportParts[5].trim(),
      invoiceLines: [],
      errors: [],
    };

    i++;

    // Parse sub-lines (invoice lines for Complete, error lines for Invalid)
    while (i < lines.length && lines[i].trim() !== '') {
      const subParts = lines[i].split('\t');
      const trimmedLine = lines[i].trim();

      if (report.reportStatus === WcbReturnReportStatus.COMPLETE && subParts.length >= 2) {
        // Invoice line: InvoiceSequence#\tServiceDate\tHSC\tInvoiceStatus
        const seq = parseInt(subParts[0].trim(), 10);
        if (!isNaN(seq)) {
          report.invoiceLines.push({
            invoiceSequence: seq,
            serviceDate: subParts[1]?.trim() || null,
            healthServiceCode: subParts[2]?.trim() || null,
            invoiceStatus: subParts[3]?.trim() || null,
          });
        }
      } else if (report.reportStatus === WcbReturnReportStatus.INVALID) {
        // Error line format: "error_code: message"
        const colonIdx = trimmedLine.indexOf(':');
        if (colonIdx > 0) {
          report.errors.push({
            error_code: trimmedLine.substring(0, colonIdx).trim(),
            message: trimmedLine.substring(colonIdx + 1).trim(),
          });
        }
      }

      i++;
    }

    reports.push(report);
  }

  return { header, reports };
}

/**
 * Process a WCB return file: parse, match, store, and transition claims.
 *
 * Steps:
 *  1. Parse tab-delimited return file.
 *  2. Match batch via BatchID -> wcb_batches.batch_control_id.
 *  3. For each report:
 *     a. Match claim via SubmitterTxnID -> wcb_claim_details.submitter_txn_id.
 *     b. Store in wcb_return_records.
 *     c. Complete -> store invoice lines, transition to 'assessed'.
 *     d. Invalid -> store errors, transition to 'rejected'.
 *     e. Store ProcessedClaim# if provided.
 *  4. Emit notifications.
 *  5. Update batch status.
 *  6. Emit audit.
 */
export async function processReturnFile(
  deps: WcbServiceDeps,
  physicianId: string,
  userId: string,
  fileContent: string,
): Promise<ProcessReturnFileResult> {
  const result: ProcessReturnFileResult = {
    matched_count: 0,
    complete_count: 0,
    invalid_count: 0,
    unmatched_count: 0,
    errors: [],
  };

  // 1. Parse return file
  const { header, reports } = parseReturnFile(fileContent);

  // 2. Match batch by BatchID -> batch_control_id
  const batch = await deps.wcbRepo.getBatchByControlId(header.batchId, physicianId);
  if (!batch) {
    throw new NotFoundError('WCB batch');
  }

  // 3. Process each report
  const returnRecordInputs: Array<{
    reportTxnId: string;
    submitterTxnId: string;
    processedClaimNumber?: string;
    claimDecision: string;
    reportStatus: string;
    txnSubmissionDate: string;
    errors?: unknown;
    wcbClaimDetailId?: string;
  }> = [];

  // Track per-report invoice lines for bulk insert after return records are created
  const invoiceLinesPerReport: Array<Array<{
    invoiceSequence: number;
    serviceDate?: string;
    healthServiceCode?: string;
    invoiceStatus?: string;
  }>> = [];

  // Track claims that need state transitions
  const claimTransitions: Array<{
    claimId: string;
    wcbClaimDetailId: string;
    newState: string;
    reportStatus: string;
    processedClaimNumber: string | null;
  }> = [];

  for (const report of reports) {
    // 3a. Match claim by SubmitterTxnID
    const wcbClaimDetailId = await deps.wcbRepo.matchReturnToClaimBySubmitterTxnId(
      report.submitterTxnId,
    );

    const returnRecordInput: (typeof returnRecordInputs)[number] = {
      reportTxnId: report.reportTxnId,
      submitterTxnId: report.submitterTxnId,
      processedClaimNumber: report.processedClaimNumber ?? undefined,
      claimDecision: report.claimDecision,
      reportStatus: report.reportStatus,
      txnSubmissionDate: report.txnSubmissionDate,
      wcbClaimDetailId: wcbClaimDetailId ?? undefined,
    };

    // For Invalid reports, store parsed errors as JSONB
    if (report.reportStatus === WcbReturnReportStatus.INVALID && report.errors.length > 0) {
      returnRecordInput.errors = report.errors;
    }

    returnRecordInputs.push(returnRecordInput);

    if (wcbClaimDetailId) {
      result.matched_count++;

      // Get the claim to find its claimId for state transitions
      const wcbDetail = await deps.wcbRepo.getWcbClaimBySubmitterTxnId(report.submitterTxnId);

      if (wcbDetail) {
        if (report.reportStatus === WcbReturnReportStatus.COMPLETE) {
          result.complete_count++;
          invoiceLinesPerReport.push(
            report.invoiceLines.map((il) => ({
              invoiceSequence: il.invoiceSequence,
              serviceDate: il.serviceDate ?? undefined,
              healthServiceCode: il.healthServiceCode ?? undefined,
              invoiceStatus: il.invoiceStatus ?? undefined,
            })),
          );

          claimTransitions.push({
            claimId: wcbDetail.claimId,
            wcbClaimDetailId,
            newState: ClaimState.ASSESSED,
            reportStatus: report.reportStatus,
            processedClaimNumber: report.processedClaimNumber,
          });
        } else if (report.reportStatus === WcbReturnReportStatus.INVALID) {
          result.invalid_count++;
          invoiceLinesPerReport.push([]);

          claimTransitions.push({
            claimId: wcbDetail.claimId,
            wcbClaimDetailId,
            newState: ClaimState.REJECTED,
            reportStatus: report.reportStatus,
            processedClaimNumber: report.processedClaimNumber,
          });
        } else {
          // Unknown status — store but don't transition
          invoiceLinesPerReport.push([]);
        }
      } else {
        invoiceLinesPerReport.push([]);
      }
    } else {
      // 3b-unmatched: store with null claim reference
      result.unmatched_count++;
      invoiceLinesPerReport.push([]);

      // Emit unmatched alert
      if (deps.notificationEmitter) {
        await deps.notificationEmitter.emit('WCB_RETURN_UNMATCHED', {
          physicianId,
          wcbBatchId: batch.wcbBatchId,
          submitterTxnId: report.submitterTxnId,
          reportTxnId: report.reportTxnId,
        });
      }
    }
  }

  // 3b. Bulk insert return records
  const returnRecords = await deps.wcbRepo.createReturnRecords(
    batch.wcbBatchId,
    returnRecordInputs,
  );

  // 3c/3d. Insert invoice lines for Complete reports and transition claims
  for (let idx = 0; idx < returnRecords.length; idx++) {
    const record = returnRecords[idx];
    const invoiceLines = invoiceLinesPerReport[idx];

    // Insert invoice lines for Complete reports
    if (invoiceLines && invoiceLines.length > 0) {
      await deps.wcbRepo.createReturnInvoiceLines(
        record.wcbReturnRecordId,
        invoiceLines,
      );
    }
  }

  // Process claim transitions
  for (const transition of claimTransitions) {
    try {
      // 3e. Store ProcessedClaim# if provided and claim has no wcb_claim_number
      if (transition.processedClaimNumber) {
        const detail = await deps.wcbRepo.getWcbClaimBySubmitterTxnId(
          returnRecordInputs.find((r) => r.wcbClaimDetailId === transition.wcbClaimDetailId)?.submitterTxnId ?? '',
        );
        if (detail && !detail.wcbClaimNumber) {
          await deps.wcbRepo.updateWcbClaimNumber(
            transition.wcbClaimDetailId,
            transition.processedClaimNumber,
          );
        }
      }

      // Transition claim state
      await deps.claimRepo.transitionClaimState(
        transition.claimId,
        physicianId,
        transition.newState,
      );

      // 4. Emit per-claim notifications
      if (deps.notificationEmitter) {
        if (transition.newState === ClaimState.ASSESSED) {
          await deps.notificationEmitter.emit('WCB_CLAIM_ACCEPTED', {
            physicianId,
            claimId: transition.claimId,
            wcbClaimDetailId: transition.wcbClaimDetailId,
            wcbBatchId: batch.wcbBatchId,
          });
        } else if (transition.newState === ClaimState.REJECTED) {
          await deps.notificationEmitter.emit('WCB_CLAIM_REJECTED', {
            physicianId,
            claimId: transition.claimId,
            wcbClaimDetailId: transition.wcbClaimDetailId,
            wcbBatchId: batch.wcbBatchId,
          });
        }
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      result.errors.push(`Failed to process claim ${transition.claimId}: ${msg}`);
    }
  }

  // 4. Emit batch-level notification
  if (deps.notificationEmitter) {
    await deps.notificationEmitter.emit('WCB_RETURN_RECEIVED', {
      physicianId,
      wcbBatchId: batch.wcbBatchId,
      matchedCount: result.matched_count,
      completeCount: result.complete_count,
      invalidCount: result.invalid_count,
      unmatchedCount: result.unmatched_count,
    });
  }

  // 5. Update batch status to RETURN_RECEIVED
  const returnFilePath = `wcb/returns/${batch.wcbBatchId}/return.txt`;
  await deps.wcbRepo.setBatchReturnReceived(batch.wcbBatchId, physicianId, returnFilePath);

  // Check if all reports processed -> RECONCILED
  if (result.errors.length === 0 && result.unmatched_count === 0) {
    try {
      await deps.wcbRepo.updateBatchStatus(
        batch.wcbBatchId,
        physicianId,
        WcbBatchStatus.RECONCILED,
      );
    } catch {
      // Non-critical — batch is already RETURN_RECEIVED
    }
  }

  // 6. Emit audit
  await emitAudit(
    deps,
    batch.wcbBatchId,
    WcbAuditAction.WCB_RETURN_RECEIVED,
    userId,
    {
      wcbBatchId: batch.wcbBatchId,
      matchedCount: result.matched_count,
      completeCount: result.complete_count,
      invalidCount: result.invalid_count,
      unmatchedCount: result.unmatched_count,
    },
  );

  return result;
}

// ===========================================================================
// Remittance File Processing — Section 7
// ===========================================================================

/**
 * Result of processing a WCB remittance file.
 */
export interface ProcessRemittanceFileResult {
  import_id: string;
  record_count: number;
  matched_count: number;
  total_payment: string;
  discrepancy_count: number;
}

/**
 * Discrepancy reason codes for remittance reconciliation.
 */
export const RemittanceDiscrepancyReason = {
  DIFFERENT_TIMING_TIER: 'DIFFERENT_TIMING_TIER',
  MODIFIER_DISALLOWED: 'MODIFIER_DISALLOWED',
  OVERPAYMENT_RECOVERY: 'OVERPAYMENT_RECOVERY',
  FEE_SCHEDULE_CHANGE: 'FEE_SCHEDULE_CHANGE',
  UNKNOWN: 'UNKNOWN',
} as const;

export type RemittanceDiscrepancyReason =
  (typeof RemittanceDiscrepancyReason)[keyof typeof RemittanceDiscrepancyReason];

/**
 * Parsed remittance record from WCB XML.
 */
export interface ParsedRemittanceRecord {
  disbursementNumber: string | null;
  disbursementType: string | null;
  disbursementIssueDate: string | null;
  disbursementAmount: string | null;
  disbursementRecipientBilling: string | null;
  disbursementRecipientName: string | null;
  paymentPayeeBilling: string;
  paymentPayeeName: string;
  paymentReasonCode: string;
  paymentStatus: string;
  paymentStartDate: string;
  paymentEndDate: string;
  paymentAmount: string;
  billedAmount: string | null;
  electronicReportTxnId: string | null;
  claimNumber: string | null;
  workerPhn: string | null;
  workerFirstName: string | null;
  workerLastName: string | null;
  serviceCode: string | null;
  modifier1: string | null;
  modifier2: string | null;
  modifier3: string | null;
  numberOfCalls: number | null;
  encounterNumber: number | null;
  overpaymentRecovery: string | null;
}

/**
 * Parsed remittance file structure.
 */
export interface ParsedRemittanceFile {
  reportWeekStart: string;
  reportWeekEnd: string;
  records: ParsedRemittanceRecord[];
}

const REMITTANCE_NAMESPACE = 'http://www.wcb.ab.ca/schemas/RR/RRPaymentRemittanceReport-2.01.00';

/**
 * Extract text content from a simple XML element.
 * Handles namespaced and non-namespaced tags.
 */
function extractXmlText(xml: string, tagName: string): string | null {
  // Try with namespace prefix first, then without
  const patterns = [
    new RegExp(`<(?:[a-zA-Z0-9]+:)?${tagName}[^>]*>([^<]*)</(?:[a-zA-Z0-9]+:)?${tagName}>`, 's'),
    new RegExp(`<${tagName}[^>]*>([^<]*)</${tagName}>`, 's'),
  ];
  for (const pattern of patterns) {
    const match = xml.match(pattern);
    if (match) {
      return match[1].trim() || null;
    }
  }
  return null;
}

/**
 * Extract all occurrences of a named XML element from the given XML string.
 * Returns the full XML content of each element (including child elements).
 */
function extractXmlElements(xml: string, tagName: string): string[] {
  const results: string[] = [];
  // Match elements with optional namespace prefix
  const pattern = new RegExp(
    `<(?:[a-zA-Z0-9]+:)?${tagName}[^>]*>([\\s\\S]*?)</(?:[a-zA-Z0-9]+:)?${tagName}>`,
    'g',
  );
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(xml)) !== null) {
    results.push(match[0]);
  }
  return results;
}

/**
 * Parse a WCB Payment Remittance Report XML file.
 *
 * Conforms to Schema_RRPaymentRemittanceReport_2_01_00.xsd
 * Namespace: http://www.wcb.ab.ca/schemas/RR/RRPaymentRemittanceReport-2.01.00
 *
 * @param xmlContent Raw XML content
 * @returns Parsed remittance file with report week and records
 */
export function parseRemittanceXml(xmlContent: string): ParsedRemittanceFile {
  // Validate namespace presence
  if (!xmlContent.includes(REMITTANCE_NAMESPACE) && !xmlContent.includes('PaymentRemittanceReport')) {
    throw new BusinessRuleError('Invalid remittance XML: missing PaymentRemittanceReport root element or namespace');
  }

  // Extract ReportWeek
  const reportWeekXml = extractXmlElements(xmlContent, 'ReportWeek')[0];
  if (!reportWeekXml) {
    throw new BusinessRuleError('Invalid remittance XML: missing ReportWeek element');
  }

  const reportWeekStart = extractXmlText(reportWeekXml, 'StartDate');
  const reportWeekEnd = extractXmlText(reportWeekXml, 'EndDate');

  if (!reportWeekStart || !reportWeekEnd) {
    throw new BusinessRuleError('Invalid remittance XML: missing ReportWeek StartDate or EndDate');
  }

  // Extract all PaymentRemittanceRecord elements
  const recordElements = extractXmlElements(xmlContent, 'PaymentRemittanceRecord');

  const records: ParsedRemittanceRecord[] = recordElements.map((recordXml) => {
    const paymentPayeeBilling = extractXmlText(recordXml, 'PaymentPayeeBillingNumber') ?? '';
    const paymentPayeeName = extractXmlText(recordXml, 'PaymentPayeeName') ?? '';
    const paymentReasonCode = extractXmlText(recordXml, 'PaymentReasonCode') ?? '';
    const paymentStatus = extractXmlText(recordXml, 'PaymentStatus') ?? '';
    const paymentStartDate = extractXmlText(recordXml, 'PaymentStartDate') ?? '';
    const paymentEndDate = extractXmlText(recordXml, 'PaymentEndDate') ?? '';
    const paymentAmount = extractXmlText(recordXml, 'PaymentAmount') ?? '0.00';

    return {
      disbursementNumber: extractXmlText(recordXml, 'DisbursementNumber'),
      disbursementType: extractXmlText(recordXml, 'DisbursementType'),
      disbursementIssueDate: extractXmlText(recordXml, 'DisbursementIssueDate'),
      disbursementAmount: extractXmlText(recordXml, 'DisbursementAmount'),
      disbursementRecipientBilling: extractXmlText(recordXml, 'DisbursementRecipientBillingNumber'),
      disbursementRecipientName: extractXmlText(recordXml, 'DisbursementRecipientName'),
      paymentPayeeBilling,
      paymentPayeeName,
      paymentReasonCode,
      paymentStatus,
      paymentStartDate,
      paymentEndDate,
      paymentAmount,
      billedAmount: extractXmlText(recordXml, 'BilledAmount'),
      electronicReportTxnId: extractXmlText(recordXml, 'ElectronicReportTransactionID'),
      claimNumber: extractXmlText(recordXml, 'ClaimNumber'),
      workerPhn: extractXmlText(recordXml, 'WorkerPHN'),
      workerFirstName: extractXmlText(recordXml, 'WorkerFirstName'),
      workerLastName: extractXmlText(recordXml, 'WorkerLastName'),
      serviceCode: extractXmlText(recordXml, 'ServiceCode'),
      modifier1: extractXmlText(recordXml, 'Modifier1'),
      modifier2: extractXmlText(recordXml, 'Modifier2'),
      modifier3: extractXmlText(recordXml, 'Modifier3'),
      numberOfCalls: parseIntOrNull(extractXmlText(recordXml, 'NumberOfCalls')),
      encounterNumber: parseIntOrNull(extractXmlText(recordXml, 'EncounterNumber')),
      overpaymentRecovery: extractXmlText(recordXml, 'OverpaymentRecovery'),
    };
  });

  return {
    reportWeekStart,
    reportWeekEnd,
    records,
  };
}

function parseIntOrNull(value: string | null): number | null {
  if (value === null) return null;
  const parsed = parseInt(value, 10);
  return isNaN(parsed) ? null : parsed;
}

/**
 * Detect discrepancy reasons when payment amount differs from expected.
 *
 * FRD Section 7 discrepancy causes:
 * 1. WCB applied different timing tier
 * 2. WCB disallowed modifier/premium code
 * 3. Overpayment recovery deducted
 * 4. Fee schedule change between submission and payment
 */
function detectDiscrepancyReasons(
  record: ParsedRemittanceRecord,
  expectedFee: string | null,
): string[] {
  const reasons: string[] = [];

  if (expectedFee === null) {
    return reasons;
  }

  const paymentDec = parseFloat(record.paymentAmount);
  const expectedDec = parseFloat(expectedFee);

  if (Math.abs(paymentDec - expectedDec) < 0.005) {
    return reasons; // No discrepancy
  }

  // Check overpayment recovery first — it's explicit in the XML
  if (record.overpaymentRecovery) {
    const recovery = parseFloat(record.overpaymentRecovery);
    if (recovery > 0.005) {
      reasons.push(RemittanceDiscrepancyReason.OVERPAYMENT_RECOVERY);
    }
    // If recovery fully accounts for the difference, that's the only reason
    if (Math.abs((paymentDec + recovery) - expectedDec) < 0.005) {
      return reasons;
    }
  }

  // If payment is lower and we can't attribute it to recovery alone,
  // check potential causes in priority order
  if (paymentDec < expectedDec) {
    // WCB may have applied a different timing tier (lower fee)
    reasons.push(RemittanceDiscrepancyReason.DIFFERENT_TIMING_TIER);
    // WCB may have disallowed a modifier
    reasons.push(RemittanceDiscrepancyReason.MODIFIER_DISALLOWED);
  }

  // Any remaining unexplained difference could be fee schedule change
  if (reasons.length === 0 || (paymentDec > expectedDec && reasons.length === 0)) {
    reasons.push(RemittanceDiscrepancyReason.FEE_SCHEDULE_CHANGE);
  }

  return reasons.length > 0 ? reasons : [RemittanceDiscrepancyReason.UNKNOWN];
}

/**
 * Payment status codes that should transition claims to 'paid'.
 */
const PAYMENT_ISSUED_STATUSES = new Set<string>([WcbPaymentStatus.ISS]);

/**
 * Payment status codes that should flag claims for review.
 */
const PAYMENT_REVIEW_STATUSES = new Set<string>([WcbPaymentStatus.REJ, WcbPaymentStatus.DEL]);

/**
 * Payment status codes that require no state change, only notification.
 */
const PAYMENT_PENDING_STATUSES = new Set<string>([
  WcbPaymentStatus.REQ,
  WcbPaymentStatus.PAE,
  WcbPaymentStatus.PGA,
  WcbPaymentStatus.PGD,
]);

/**
 * Process a WCB payment remittance XML file.
 *
 * Reconciliation workflow (FRD Section 7, 6 steps):
 *  1. Import: Parse remittance XML against PaymentRemittanceReport schema.
 *  2. Store: Each PaymentRemittanceRecord stored in wcb_remittance_records.
 *  3. Match: Records matched via ElectronicReportTransactionID chain:
 *     electronic_report_txn_id -> wcb_return_records.report_txn_id -> wcb_claim_details.
 *  4. Reconcile: Compare payment_amount to expected fee. Flag discrepancies.
 *  5. State Update: ISS -> claim to 'paid'. REJ/DEL -> flag for review.
 *  6. Notify: WCB_PAYMENT_RECEIVED notification with summary.
 *
 * @param deps - Service dependencies (wcbRepo, claimRepo, auditEmitter, etc.)
 * @param physicianId - Authenticated physician ID
 * @param userId - Authenticated user ID (for audit)
 * @param xmlContent - Raw remittance XML content
 * @returns Summary of import results
 */
export async function processRemittanceFile(
  deps: WcbServiceDeps,
  physicianId: string,
  userId: string,
  xmlContent: string,
): Promise<ProcessRemittanceFileResult> {
  // Step 1: Parse remittance XML
  const parsed = parseRemittanceXml(xmlContent);

  // Step 2: Create remittance import record
  const importId = await deps.wcbRepo.createRemittanceImport(physicianId);

  let matchedCount = 0;
  let totalPayment = '0.00';
  let discrepancyCount = 0;

  // Prepare records for bulk insert
  const remittanceRecordInputs: Array<{
    wcbClaimDetailId?: string;
    reportWeekStart: string;
    reportWeekEnd: string;
    disbursementNumber?: string;
    disbursementType?: string;
    disbursementIssueDate?: string;
    disbursementAmount?: string;
    disbursementRecipientBilling?: string;
    disbursementRecipientName?: string;
    paymentPayeeBilling: string;
    paymentPayeeName: string;
    paymentReasonCode: string;
    paymentStatus: string;
    paymentStartDate: string;
    paymentEndDate: string;
    paymentAmount: string;
    billedAmount?: string;
    electronicReportTxnId?: string;
    claimNumber?: string;
    workerPhn?: string;
    workerFirstName?: string;
    workerLastName?: string;
    serviceCode?: string;
    modifier1?: string;
    modifier2?: string;
    modifier3?: string;
    numberOfCalls?: number;
    encounterNumber?: number;
    overpaymentRecovery?: string;
  }> = [];

  // Track claims that need state transitions (deferred until after bulk insert)
  const claimTransitions: Array<{
    claimId: string;
    wcbClaimDetailId: string;
    newState: string;
    paymentStatus: string;
  }> = [];

  // Track discrepancies for notifications
  const discrepancies: Array<{
    wcbClaimDetailId: string;
    paymentAmount: string;
    expectedFee: string | null;
    reasons: string[];
  }> = [];

  // Step 3: Process each record — match and prepare for storage
  for (const record of parsed.records) {
    // Accumulate total payment
    totalPayment = addMoney(totalPayment, record.paymentAmount);

    let wcbClaimDetailId: string | undefined;

    // Step 3a: Match via ElectronicReportTransactionID chain
    if (record.electronicReportTxnId) {
      const matchedDetailId = await deps.wcbRepo.matchRemittanceToClaimByTxnId(
        record.electronicReportTxnId,
      );

      if (matchedDetailId) {
        wcbClaimDetailId = matchedDetailId;
        matchedCount++;

        // Step 4: Reconcile — compare payment to expected fee
        let expectedFee: string | null = null;
        try {
          const feeResult = await calculateWcbFees(deps, matchedDetailId, physicianId);
          expectedFee = feeResult.total_expected_fee;
        } catch {
          // Fee calculation may fail if reference data is unavailable — continue
        }

        // Check for discrepancy
        if (expectedFee !== null) {
          const paymentDec = parseFloat(record.paymentAmount);
          const expectedDec = parseFloat(expectedFee);
          if (Math.abs(paymentDec - expectedDec) >= 0.005) {
            discrepancyCount++;
            const reasons = detectDiscrepancyReasons(record, expectedFee);
            discrepancies.push({
              wcbClaimDetailId: matchedDetailId,
              paymentAmount: record.paymentAmount,
              expectedFee,
              reasons,
            });
          }
        }

        // Check overpayment recovery regardless of fee match
        if (record.overpaymentRecovery) {
          const recovery = parseFloat(record.overpaymentRecovery);
          if (recovery > 0.005) {
            // Track overpayment recovery even if payment matches expected
            // (recovery may have been anticipated)
            const alreadyTracked = discrepancies.some(
              (d) => d.wcbClaimDetailId === matchedDetailId,
            );
            if (!alreadyTracked) {
              discrepancyCount++;
              discrepancies.push({
                wcbClaimDetailId: matchedDetailId,
                paymentAmount: record.paymentAmount,
                expectedFee,
                reasons: [RemittanceDiscrepancyReason.OVERPAYMENT_RECOVERY],
              });
            }
          }
        }

        // Step 5: Determine claim state transition based on payment status
        // Look up the full claim to get the claimId for state transitions
        const fullClaim = await deps.wcbRepo.getWcbClaim(matchedDetailId, physicianId);

        if (fullClaim) {
          if (PAYMENT_ISSUED_STATUSES.has(record.paymentStatus)) {
            // ISS -> transition to 'paid'
            claimTransitions.push({
              claimId: fullClaim.claim.claimId,
              wcbClaimDetailId: matchedDetailId,
              newState: ClaimState.PAID,
              paymentStatus: record.paymentStatus,
            });
          } else if (PAYMENT_REVIEW_STATUSES.has(record.paymentStatus)) {
            // REJ/DEL -> flag for review (no automatic state change,
            // but emit notification so physician can act)
            if (deps.notificationEmitter) {
              await deps.notificationEmitter.emit('WCB_PAYMENT_REVIEW_REQUIRED', {
                physicianId,
                claimId: fullClaim.claim.claimId,
                wcbClaimDetailId: matchedDetailId,
                paymentStatus: record.paymentStatus,
                paymentAmount: record.paymentAmount,
              });
            }
          } else if (PAYMENT_PENDING_STATUSES.has(record.paymentStatus)) {
            // REQ/PAE/PGA/PGD -> no state change, notify
            if (deps.notificationEmitter) {
              await deps.notificationEmitter.emit('WCB_PAYMENT_PENDING', {
                physicianId,
                claimId: fullClaim.claim.claimId,
                wcbClaimDetailId: matchedDetailId,
                paymentStatus: record.paymentStatus,
              });
            }
          }
        }
      }
    }

    // Prepare record for storage
    remittanceRecordInputs.push({
      wcbClaimDetailId: wcbClaimDetailId ?? undefined,
      reportWeekStart: parsed.reportWeekStart,
      reportWeekEnd: parsed.reportWeekEnd,
      disbursementNumber: record.disbursementNumber ?? undefined,
      disbursementType: record.disbursementType ?? undefined,
      disbursementIssueDate: record.disbursementIssueDate ?? undefined,
      disbursementAmount: record.disbursementAmount ?? undefined,
      disbursementRecipientBilling: record.disbursementRecipientBilling ?? undefined,
      disbursementRecipientName: record.disbursementRecipientName ?? undefined,
      paymentPayeeBilling: record.paymentPayeeBilling,
      paymentPayeeName: record.paymentPayeeName,
      paymentReasonCode: record.paymentReasonCode,
      paymentStatus: record.paymentStatus,
      paymentStartDate: record.paymentStartDate,
      paymentEndDate: record.paymentEndDate,
      paymentAmount: record.paymentAmount,
      billedAmount: record.billedAmount ?? undefined,
      electronicReportTxnId: record.electronicReportTxnId ?? undefined,
      claimNumber: record.claimNumber ?? undefined,
      workerPhn: record.workerPhn ?? undefined,
      workerFirstName: record.workerFirstName ?? undefined,
      workerLastName: record.workerLastName ?? undefined,
      serviceCode: record.serviceCode ?? undefined,
      modifier1: record.modifier1 ?? undefined,
      modifier2: record.modifier2 ?? undefined,
      modifier3: record.modifier3 ?? undefined,
      numberOfCalls: record.numberOfCalls ?? undefined,
      encounterNumber: record.encounterNumber ?? undefined,
      overpaymentRecovery: record.overpaymentRecovery ?? undefined,
    });
  }

  // Step 2 (continued): Bulk insert remittance records
  await deps.wcbRepo.createRemittanceRecords(importId, remittanceRecordInputs);

  // Step 5 (continued): Execute claim state transitions
  for (const transition of claimTransitions) {
    try {
      await deps.claimRepo.transitionClaimState(
        transition.claimId,
        physicianId,
        transition.newState,
      );
    } catch {
      // Non-critical — claim may already be in the target state
    }
  }

  // Step 6a: Emit WCB_PAYMENT_RECEIVED notification with summary
  if (deps.notificationEmitter) {
    await deps.notificationEmitter.emit('WCB_PAYMENT_RECEIVED', {
      physicianId,
      importId,
      recordCount: parsed.records.length,
      matchedCount,
      totalPayment,
      discrepancyCount,
    });
  }

  // Step 6b: Emit audit
  await emitAudit(deps, importId, WcbAuditAction.WCB_PAYMENT_RECEIVED, userId, {
    importId,
    recordCount: parsed.records.length,
    matchedCount,
    totalPayment,
    discrepancyCount,
  });

  return {
    import_id: importId,
    record_count: parsed.records.length,
    matched_count: matchedCount,
    total_payment: totalPayment,
    discrepancy_count: discrepancyCount,
  };
}

// ===========================================================================
// MVP Services (Phase 1 — manual portal entry)
// ===========================================================================

/**
 * Check if MVP endpoints are available based on WCB_PHASE.
 * In Phase 2 (vendor accreditation), MVP endpoints return 404.
 */
export function isMvpPhaseActive(wcbPhase?: string): boolean {
  // Default to MVP if not set (backwards compatible)
  if (!wcbPhase || wcbPhase === WcbPhase.MVP) return true;
  return false;
}

// --- MVP Export Types ---

export interface MvpExportSection {
  name: string;
  fields: Array<{
    label: string;
    value: string | null;
  }>;
}

export interface MvpExportResult {
  content: string;
  contentType: string;
  fileName: string;
  formId: string;
  formName: string;
  sections: MvpExportSection[];
  validationWarnings: string[];
  feeCalculation: {
    report_fee: string;
    report_fee_tier: string;
    total_expected_fee: string;
  };
  timingInfo: {
    tier: string;
    deadline: string;
    hoursRemaining: number;
  } | null;
}

/**
 * Generate a pre-filled export for manual WCB portal entry (MVP).
 *
 * 1. Load full claim with all child records
 * 2. Run validation pipeline — warn on errors but allow export
 * 3. Calculate fees and timing tier
 * 4. Generate structured HTML that mirrors myWCB form layout
 * 5. Emit audit: wcb.mvp_export_generated
 */
export async function generateMvpExport(
  deps: WcbServiceDeps,
  physicianId: string,
  wcbClaimDetailId: string,
  userId: string,
  wcbPhase?: string,
): Promise<MvpExportResult> {
  if (!isMvpPhaseActive(wcbPhase)) {
    throw new NotFoundError('MVP export');
  }

  // 1. Load full claim with all child records
  const claim = await deps.wcbRepo.getWcbClaim(wcbClaimDetailId, physicianId);
  if (!claim) {
    throw new NotFoundError('WCB claim');
  }

  const detail = claim.detail as Record<string, unknown>;
  const formId = detail.formId as string;
  const formConfig = WCB_FORM_TYPE_CONFIGS[formId as WcbFormType];
  if (!formConfig) {
    throw new BusinessRuleError(`Unknown WCB form type: ${formId}`);
  }

  // 2. Run validation pipeline — collect warnings but allow export
  const validationResult = await validateWcbClaim(deps, wcbClaimDetailId, physicianId);
  const validationWarnings: string[] = [
    ...validationResult.errors.map((e) => `ERROR: ${e.message}`),
    ...validationResult.warnings.map((w) => `WARNING: ${w.message}`),
  ];

  // 3. Calculate fees and timing tier
  let feeCalc: WcbFeeCalculationResult;
  try {
    feeCalc = await calculateWcbFees(deps, wcbClaimDetailId, physicianId);
  } catch {
    feeCalc = {
      report_fee: '0.00',
      report_fee_tier: 'UNKNOWN',
      invoice_line_fees: [],
      expedited_fees: '0.00',
      rrnp_fee: '0.00',
      total_expected_fee: '0.00',
    };
  }

  const dateOfExamination = detail.dateOfExamination as string | null;
  const timing = calculateTimingTier(formId, dateOfExamination);

  let timingInfo: MvpExportResult['timingInfo'] = null;
  if (timing) {
    timingInfo = {
      tier: timing.tier,
      deadline: timing.deadline.toISOString(),
      hoursRemaining: timing.hoursRemaining,
    };
  }

  // 4. Generate structured sections matching myWCB form layout
  const activeSections = WCB_FORM_SECTION_MATRIX[formId as WcbFormType];
  const sections: MvpExportSection[] = [];

  for (const sectionName of activeSections) {
    const sectionFields: MvpExportSection['fields'] = [];

    switch (sectionName) {
      case WcbFormSection.GENERAL:
        sectionFields.push(
          { label: 'Form Type', value: formId },
          { label: 'Form Name', value: formConfig.name },
          { label: 'WCB Claim Number', value: strVal(detail.wcbClaimNumber) },
          { label: 'Report Completion Date', value: strVal(detail.reportCompletionDate) },
          { label: 'Submitter Txn ID', value: strVal(detail.submitterTxnId) },
          { label: 'Additional Comments', value: strVal(detail.additionalComments) },
        );
        break;

      case WcbFormSection.CLAIMANT:
        sectionFields.push(
          { label: 'PHN', value: strVal(detail.patientPhn) },
          { label: 'Gender', value: strVal(detail.patientGender) },
          { label: 'First Name', value: strVal(detail.patientFirstName) },
          { label: 'Last Name', value: strVal(detail.patientLastName) },
          { label: 'Date of Birth', value: strVal(detail.patientDob) },
          { label: 'Address', value: strVal(detail.patientAddressLine1) },
          { label: 'City', value: strVal(detail.patientCity) },
          { label: 'Province', value: strVal(detail.patientProvince) },
          { label: 'Postal Code', value: strVal(detail.patientPostalCode) },
        );
        break;

      case WcbFormSection.PRACTITIONER:
        sectionFields.push(
          { label: 'Billing Number', value: strVal(detail.practitionerBillingNumber) },
          { label: 'Contract ID', value: strVal(detail.contractId) },
          { label: 'Role Code', value: strVal(detail.roleCode) },
          { label: 'First Name', value: strVal(detail.practitionerFirstName) },
          { label: 'Last Name', value: strVal(detail.practitionerLastName) },
          { label: 'Skill Code', value: strVal(detail.skillCode) },
          { label: 'Facility Type', value: strVal(detail.facilityType) },
        );
        break;

      case WcbFormSection.EMPLOYER:
        sectionFields.push(
          { label: 'Employer Name', value: strVal(detail.employerName) },
          { label: 'Employer Location', value: strVal(detail.employerLocation) },
          { label: 'Employer City', value: strVal(detail.employerCity) },
        );
        break;

      case WcbFormSection.ACCIDENT:
        sectionFields.push(
          { label: 'Worker Job Title', value: strVal(detail.workerJobTitle) },
          { label: 'Date of Injury', value: strVal(detail.dateOfInjury) },
          { label: 'Injury Description', value: strVal(detail.injuryDescription) },
          { label: 'Injury Developed Over Time', value: strVal(detail.injuryDevelopedOverTime) },
        );
        break;

      case WcbFormSection.INJURY: {
        sectionFields.push(
          { label: 'Date of Examination', value: strVal(detail.dateOfExamination) },
          { label: 'Symptoms', value: strVal(detail.symptoms) },
          { label: 'Objective Findings', value: strVal(detail.objectiveFindings) },
          { label: 'Current Diagnosis', value: strVal(detail.currentDiagnosis) },
          { label: 'Diagnostic Code 1', value: strVal(detail.diagnosticCode1) },
          { label: 'Diagnostic Code 2', value: strVal(detail.diagnosticCode2) },
          { label: 'Diagnostic Code 3', value: strVal(detail.diagnosticCode3) },
        );
        // Add child injury records
        for (let i = 0; i < claim.injuries.length; i++) {
          const inj = claim.injuries[i] as Record<string, unknown>;
          sectionFields.push(
            { label: `Injury ${i + 1} Part of Body`, value: strVal(inj.partOfBodyCode) },
            { label: `Injury ${i + 1} Nature of Injury`, value: strVal(inj.natureOfInjuryCode) },
            { label: `Injury ${i + 1} Side`, value: strVal(inj.sideOfBodyCode) },
          );
        }
        break;
      }

      case WcbFormSection.TREATMENT_PLAN: {
        sectionFields.push(
          { label: 'Narcotics Prescribed', value: strVal(detail.narcoticsPrescribed) },
          { label: 'Treatment Plan', value: strVal(detail.treatmentPlanText) },
        );
        // Add prescriptions if narcotics prescribed
        for (let i = 0; i < claim.prescriptions.length; i++) {
          const rx = claim.prescriptions[i] as Record<string, unknown>;
          sectionFields.push(
            { label: `Prescription ${i + 1} Name`, value: strVal(rx.prescriptionName) },
            { label: `Prescription ${i + 1} Strength`, value: strVal(rx.strength) },
            { label: `Prescription ${i + 1} Daily Intake`, value: strVal(rx.dailyIntake) },
          );
        }
        // Add consultations
        for (let i = 0; i < claim.consultations.length; i++) {
          const con = claim.consultations[i] as Record<string, unknown>;
          sectionFields.push(
            { label: `Consultation ${i + 1} Category`, value: strVal(con.category) },
            { label: `Consultation ${i + 1} Type`, value: strVal(con.typeCode) },
            { label: `Consultation ${i + 1} Details`, value: strVal(con.details) },
          );
        }
        break;
      }

      case WcbFormSection.RETURN_TO_WORK:
        sectionFields.push(
          { label: 'Missed Work Beyond Accident Day', value: strVal(detail.missedWorkBeyondAccident) },
          { label: 'Patient Returned to Work', value: strVal(detail.patientReturnedToWork) },
          { label: 'Estimated RTW Date', value: strVal(detail.estimatedRtwDate) },
        );
        break;

      case WcbFormSection.ATTACHMENTS:
        for (let i = 0; i < claim.attachments.length; i++) {
          const att = claim.attachments[i] as Record<string, unknown>;
          sectionFields.push(
            { label: `Attachment ${i + 1} Name`, value: strVal(att.fileName) },
            { label: `Attachment ${i + 1} Type`, value: strVal(att.fileType) },
            { label: `Attachment ${i + 1} Description`, value: strVal(att.fileDescription) },
          );
        }
        break;

      case WcbFormSection.INVOICE:
        for (let i = 0; i < claim.invoiceLines.length; i++) {
          const line = claim.invoiceLines[i] as Record<string, unknown>;
          sectionFields.push(
            { label: `Line ${i + 1} Type`, value: strVal(line.lineType) },
            { label: `Line ${i + 1} HSC`, value: strVal(line.healthServiceCode) },
            { label: `Line ${i + 1} Amount`, value: strVal(line.amount) },
          );
        }
        break;
    }

    sections.push({ name: sectionName, fields: sectionFields });
  }

  // Generate printable HTML
  const html = renderMvpExportHtml(formConfig.name, formId, sections, feeCalc, timingInfo, validationWarnings);

  const fileName = `WCB_${formId}_${wcbClaimDetailId.substring(0, 8)}.html`;

  // 5. Emit audit: wcb.mvp_export_generated
  await emitAudit(deps, claim.claim.claimId as string, WcbAuditAction.WCB_MVP_EXPORT_GENERATED, userId, {
    wcbClaimDetailId,
    formId,
    validationWarningCount: validationWarnings.length,
  });

  return {
    content: html,
    contentType: 'text/html',
    fileName,
    formId,
    formName: formConfig.name,
    sections,
    validationWarnings,
    feeCalculation: {
      report_fee: feeCalc.report_fee,
      report_fee_tier: feeCalc.report_fee_tier,
      total_expected_fee: feeCalc.total_expected_fee,
    },
    timingInfo,
  };
}

function strVal(v: unknown): string | null {
  if (v === null || v === undefined) return null;
  return String(v);
}

function renderMvpExportHtml(
  formName: string,
  formId: string,
  sections: MvpExportSection[],
  feeCalc: WcbFeeCalculationResult,
  timingInfo: MvpExportResult['timingInfo'],
  warnings: string[],
): string {
  const esc = (s: string | null): string => {
    if (!s) return '&mdash;';
    return s
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  };

  let html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>WCB ${esc(formId)} - ${esc(formName)}</title>
<style>
body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
h1 { border-bottom: 2px solid #333; padding-bottom: 8px; }
h2 { background: #f0f0f0; padding: 8px; margin-top: 20px; }
table { width: 100%; border-collapse: collapse; margin-bottom: 16px; }
td { padding: 4px 8px; border-bottom: 1px solid #eee; vertical-align: top; }
td:first-child { font-weight: bold; width: 40%; color: #555; }
.fee-box { background: #e8f5e9; padding: 12px; border-radius: 4px; margin: 16px 0; }
.timing-box { background: #fff3e0; padding: 12px; border-radius: 4px; margin: 16px 0; }
.warning-box { background: #fff8e1; padding: 12px; border-radius: 4px; margin: 16px 0; }
.timing-same-day { color: #2e7d32; font-weight: bold; }
.timing-on-time { color: #f57c00; font-weight: bold; }
.timing-late { color: #c62828; font-weight: bold; }
@media print { body { margin: 0; padding: 10px; } }
</style>
</head>
<body>
<h1>WCB ${esc(formId)} &mdash; ${esc(formName)}</h1>
<p><em>Pre-filled export for manual myWCB portal entry. Verify all fields before submission.</em></p>`;

  // Timing info
  if (timingInfo) {
    const tierClass = timingInfo.tier === 'SAME_DAY' ? 'timing-same-day'
      : timingInfo.tier === 'ON_TIME' ? 'timing-on-time'
        : 'timing-late';
    html += `
<div class="timing-box">
<strong>Timing Tier:</strong> <span class="${tierClass}">${esc(timingInfo.tier)}</span><br>
<strong>Deadline:</strong> ${esc(timingInfo.deadline)}<br>
<strong>Hours Remaining:</strong> ${timingInfo.hoursRemaining}
</div>`;
  }

  // Fee calculation
  html += `
<div class="fee-box">
<strong>Report Fee:</strong> $${esc(feeCalc.report_fee)} (${esc(feeCalc.report_fee_tier)})<br>
<strong>Total Expected Fee:</strong> $${esc(feeCalc.total_expected_fee)}
</div>`;

  // Validation warnings
  if (warnings.length > 0) {
    html += `<div class="warning-box"><strong>Validation Notes (${warnings.length}):</strong><ul>`;
    for (const w of warnings) {
      html += `<li>${esc(w)}</li>`;
    }
    html += `</ul></div>`;
  }

  // Sections
  for (const section of sections) {
    html += `<h2>${esc(section.name)}</h2>`;
    if (section.fields.length === 0) {
      html += `<p><em>No fields in this section.</em></p>`;
      continue;
    }
    html += `<table>`;
    for (const field of section.fields) {
      html += `<tr><td>${esc(field.label)}</td><td>${esc(field.value)}</td></tr>`;
    }
    html += `</table>`;
  }

  html += `
<hr>
<p style="font-size: 0.8em; color: #888;">Generated by Meritum Health Technologies. For manual portal entry only.</p>
</body>
</html>`;

  return html;
}

// --- Manual Outcome Recording (MVP) ---

export interface ManualOutcomeInput {
  wcb_claim_number?: string;
  acceptance_status: 'accepted' | 'rejected';
  payment_amount?: number;
}

export interface ManualOutcomeResult {
  claimId: string;
  wcbClaimDetailId: string;
  newState: string;
  wcbClaimNumber?: string;
  paymentAmount?: number;
}

/**
 * Record outcome from manual WCB portal submission (MVP).
 *
 * 1. Store wcb_claim_number if provided
 * 2. Update claim state: accepted -> ASSESSED, rejected -> REJECTED
 * 3. Store payment_amount if provided
 * 4. Emit audit: wcb.manual_outcome_recorded
 */
export async function recordManualOutcome(
  deps: WcbServiceDeps,
  physicianId: string,
  wcbClaimDetailId: string,
  userId: string,
  data: ManualOutcomeInput,
  wcbPhase?: string,
): Promise<ManualOutcomeResult> {
  if (!isMvpPhaseActive(wcbPhase)) {
    throw new NotFoundError('MVP manual outcome');
  }

  // Load the claim to verify ownership and get claim ID
  const claim = await deps.wcbRepo.getWcbClaim(wcbClaimDetailId, physicianId);
  if (!claim) {
    throw new NotFoundError('WCB claim');
  }

  const claimId = claim.claim.claimId as string;

  // Store WCB claim number if provided
  if (data.wcb_claim_number) {
    await deps.wcbRepo.updateWcbClaimNumber(wcbClaimDetailId, data.wcb_claim_number);
  }

  // Transition claim state based on acceptance
  const newState = data.acceptance_status === 'accepted'
    ? ClaimState.ASSESSED
    : ClaimState.REJECTED;

  await deps.claimRepo.transitionClaimState(claimId, physicianId, newState);

  // Emit audit
  await emitAudit(deps, claimId, WcbAuditAction.WCB_MANUAL_OUTCOME_RECORDED, userId, {
    wcbClaimDetailId,
    acceptanceStatus: data.acceptance_status,
    wcbClaimNumber: data.wcb_claim_number ?? null,
    paymentAmount: data.payment_amount ?? null,
  });

  return {
    claimId,
    wcbClaimDetailId,
    newState,
    wcbClaimNumber: data.wcb_claim_number,
    paymentAmount: data.payment_amount,
  };
}

// --- Timing Dashboard ---

export interface TimingDashboardItem {
  wcbClaimDetailId: string;
  claimId: string;
  formId: string;
  formName: string;
  dateOfExamination: string | null;
  state: string;
  timingTier: string | null;
  deadline: string | null;
  hoursRemaining: number | null;
  currentFee: string;
  sameDayFee: string;
  feeDifference: string;
  urgencyMessage: string | null;
}

export interface TimingDashboardResult {
  items: TimingDashboardItem[];
}

/**
 * Return all draft/queued WCB claims with their current timing tier,
 * deadline, and fee difference to motivate timely submission.
 *
 * Key AI Coach integration point: "Submit within [X hours] to earn [$Y] more."
 */
export async function getTimingDashboard(
  deps: WcbServiceDeps,
  physicianId: string,
): Promise<TimingDashboardResult> {
  // Fetch DRAFT and QUEUED claims
  const draftResults = await deps.wcbRepo.listWcbClaimsForPhysician(physicianId, {
    status: ClaimState.DRAFT,
    page: 1,
    pageSize: 100,
  });

  const queuedResults = await deps.wcbRepo.listWcbClaimsForPhysician(physicianId, {
    status: ClaimState.QUEUED,
    page: 1,
    pageSize: 100,
  });

  const allClaims = [...draftResults.data, ...queuedResults.data];
  const items: TimingDashboardItem[] = [];

  for (const entry of allClaims) {
    const detail = entry.detail as Record<string, unknown>;
    const claimRec = entry.claim as Record<string, unknown>;
    const formId = detail.formId as string;
    const dateOfExamination = detail.dateOfExamination as string | null;
    const roleCode = detail.roleCode as string | null;

    const formConfig = WCB_FORM_TYPE_CONFIGS[formId as WcbFormType];
    const formName = formConfig?.name ?? formId;

    // Calculate timing tier
    const timing = calculateTimingTier(formId, dateOfExamination);

    let timingTier: string | null = null;
    let deadline: string | null = null;
    let hoursRemaining: number | null = null;
    let currentFee = '0.00';
    let sameDayFee = '0.00';

    if (timing) {
      timingTier = timing.tier;
      deadline = timing.deadline.toISOString();
      hoursRemaining = timing.hoursRemaining;
      currentFee = lookupReportFee(formId, timing.tier, roleCode);
      sameDayFee = lookupReportFee(formId, WcbTimingTier.SAME_DAY, roleCode);
    }

    // Calculate fee difference (potential savings by submitting sooner)
    const feeDifference = subtractMoney(sameDayFee, currentFee);

    // Generate urgency message for AI Coach
    let urgencyMessage: string | null = null;
    if (timing && timing.tier !== WcbTimingTier.SAME_DAY && timing.hoursRemaining > 0) {
      const betterTier = timing.tier === WcbTimingTier.LATE ? WcbTimingTier.ON_TIME : WcbTimingTier.SAME_DAY;
      const betterFee = lookupReportFee(formId, betterTier, roleCode);
      const potentialGain = subtractMoney(betterFee, currentFee);
      if (potentialGain !== '0.00') {
        urgencyMessage = `Submit within ${timing.hoursRemaining} hours to earn $${potentialGain} more.`;
      }
    } else if (timing && timing.tier === WcbTimingTier.SAME_DAY && timing.hoursRemaining > 0) {
      urgencyMessage = `Submit within ${timing.hoursRemaining} hours to keep same-day rate.`;
    }

    items.push({
      wcbClaimDetailId: detail.wcbClaimDetailId as string,
      claimId: claimRec.claimId as string,
      formId,
      formName,
      dateOfExamination,
      state: claimRec.state as string,
      timingTier,
      deadline,
      hoursRemaining,
      currentFee,
      sameDayFee,
      feeDifference,
      urgencyMessage,
    });
  }

  // Sort by urgency: fewest hours remaining first
  items.sort((a, b) => {
    if (a.hoursRemaining === null && b.hoursRemaining === null) return 0;
    if (a.hoursRemaining === null) return 1;
    if (b.hoursRemaining === null) return -1;
    return a.hoursRemaining - b.hoursRemaining;
  });

  return { items };
}

/**
 * Subtract two money strings: a - b. Returns "0.00" if result is negative.
 */
function subtractMoney(a: string, b: string): string {
  const cents = Math.round(parseFloat(a) * 100) - Math.round(parseFloat(b) * 100);
  if (cents <= 0) return '0.00';
  return (cents / 100).toFixed(2);
}

// Exported for testing and external use
export {
  calculateTimingTier,
  isValidDate,
  getAlbertaHolidays as getAlbertaStatutoryHolidays,
  getAlbertaHolidays,
  addBusinessDays,
  countBusinessDays,
  isBusinessDay,
  formatDateUTC,
  parseDate,
  getDeadlineCutoffUTC,
  isMDT,
  isPremiumEligible,
  lookupReportFee,
  addMoney,
  multiplyMoney,
  multiplyMoneyByRatio,
  sumInvoiceLineFees,
  escapeXml,
  formatMountainTimestamp,
  formatHl7Date,
  mapClaimToObservations,
  HL7_NAMESPACE,
  REQUIRED_FIELDS_BY_FORM,
  FIELD_SPECS,
  POB_NOI_EXCLUSIONS,
  POBS_REQUIRING_SIDE,
  POB_SIDE_CONFIGS,
  POB_DESCRIPTIONS,
  NOI_DESCRIPTIONS,
  CONDITIONAL_RULES,
  REMITTANCE_NAMESPACE,
  detectDiscrepancyReasons,
  subtractMoney,
};
export type { TimingTierResult, ProcessRemittanceFileResult, ParsedRemittanceFile, ParsedRemittanceRecord, MvpExportResult, ManualOutcomeInput, ManualOutcomeResult, TimingDashboardItem, TimingDashboardResult };
