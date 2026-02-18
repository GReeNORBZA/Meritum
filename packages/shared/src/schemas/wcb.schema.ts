// ============================================================================
// Domain 4.2: WCB Pathway — Zod Validation Schemas
// ============================================================================

import { z } from 'zod';
import {
  WcbFormType,
  WcbBatchStatus,
  WcbInvoiceLineType,
  WcbConsultationCategory,
} from '../constants/wcb.constants.js';
import { ValidationSeverity } from '../constants/claim.constants.js';

// --- Enum Value Arrays ---

const WCB_FORM_TYPES = [
  WcbFormType.C050E,
  WcbFormType.C050S,
  WcbFormType.C151,
  WcbFormType.C151S,
  WcbFormType.C568,
  WcbFormType.C568A,
  WcbFormType.C569,
  WcbFormType.C570,
] as const;

const WCB_BATCH_STATUSES = [
  WcbBatchStatus.ASSEMBLING,
  WcbBatchStatus.GENERATED,
  WcbBatchStatus.VALIDATED,
  WcbBatchStatus.UPLOADED,
  WcbBatchStatus.RETURN_RECEIVED,
  WcbBatchStatus.RECONCILED,
  WcbBatchStatus.ERROR,
] as const;

const WCB_INVOICE_LINE_TYPES = [
  WcbInvoiceLineType.STANDARD,
  WcbInvoiceLineType.DATED,
  WcbInvoiceLineType.SUPPLY,
  WcbInvoiceLineType.WAS,
  WcbInvoiceLineType.SHOULD_BE,
] as const;

const WCB_CORRECTION_LINE_TYPES = [
  WcbInvoiceLineType.WAS,
  WcbInvoiceLineType.SHOULD_BE,
] as const;

const WCB_CONSULTATION_CATEGORIES = [
  WcbConsultationCategory.CONREF,
  WcbConsultationCategory.INVE,
] as const;

const VALIDATION_SEVERITIES = [
  ValidationSeverity.ERROR,
  ValidationSeverity.WARNING,
  ValidationSeverity.INFO,
] as const;

const WCB_ATTACHMENT_FILE_TYPES = [
  'PDF',
  'DOC',
  'DOCX',
  'JPG',
  'PNG',
  'TIF',
] as const;

const WCB_MVP_ACCEPTANCE_STATUSES = ['accepted', 'rejected'] as const;

const YES_NO = ['Y', 'N'] as const;

// ============================================================================
// Sub-Schemas: Child Table Entities
// ============================================================================

// --- Injury Sub-Schema (1-5 per claim with Injury section) ---

export const wcbInjurySchema = z.object({
  part_of_body_code: z.string().min(1).max(10),
  side_of_body_code: z.string().max(10).optional(),
  nature_of_injury_code: z.string().min(1).max(10),
});

export type WcbInjury = z.infer<typeof wcbInjurySchema>;

// --- Prescription Sub-Schema (1-5 when narcotics prescribed) ---

export const wcbPrescriptionSchema = z.object({
  prescription_name: z.string().min(1).max(50),
  strength: z.string().min(1).max(30),
  daily_intake: z.string().min(1).max(30),
});

export type WcbPrescription = z.infer<typeof wcbPrescriptionSchema>;

// --- Consultation Sub-Schema (1-5 per claim with Treatment Plan) ---

export const wcbConsultationSchema = z.object({
  category: z.enum(WCB_CONSULTATION_CATEGORIES),
  type_code: z.string().min(1).max(10),
  details: z.string().min(1).max(50),
  expedite_requested: z.enum(YES_NO).optional(),
});

export type WcbConsultation = z.infer<typeof wcbConsultationSchema>;

// --- Work Restriction Sub-Schema (up to 11 activity types) ---

export const wcbWorkRestrictionSchema = z.object({
  activity_type: z.string().min(1).max(20),
  restriction_level: z.string().min(1).max(10),
  hours_per_day: z.number().int().min(0).max(24).optional(),
  max_weight: z.string().max(10).optional(),
});

export type WcbWorkRestriction = z.infer<typeof wcbWorkRestrictionSchema>;

// --- Attachment Sub-Schema (max 3 per claim) ---

export const wcbAttachmentSchema = z.object({
  file_name: z.string().min(1).max(255),
  file_type: z.enum(WCB_ATTACHMENT_FILE_TYPES),
  file_content_b64: z.string().min(1),
  file_description: z.string().min(1).max(60),
});

export type WcbAttachment = z.infer<typeof wcbAttachmentSchema>;

// ============================================================================
// Invoice Line Sub-Schemas (by line_type)
// ============================================================================

// --- Standard Invoice Line (C568/A basic) ---

export const wcbInvoiceLineStandardSchema = z.object({
  line_type: z.literal(WcbInvoiceLineType.STANDARD),
  health_service_code: z.string().min(1).max(7),
  diagnostic_code_1: z.string().max(8).optional(),
  diagnostic_code_2: z.string().max(8).optional(),
  diagnostic_code_3: z.string().max(8).optional(),
  modifier_1: z.string().max(6).optional(),
  modifier_2: z.string().max(6).optional(),
  modifier_3: z.string().max(6).optional(),
  calls: z.number().int().min(1).optional(),
  encounters: z.number().int().min(1).optional(),
});

export type WcbInvoiceLineStandard = z.infer<typeof wcbInvoiceLineStandardSchema>;

// --- Dated Invoice Line (C568/A with date range) ---

export const wcbInvoiceLineDatedSchema = z.object({
  line_type: z.literal(WcbInvoiceLineType.DATED),
  health_service_code: z.string().min(1).max(7),
  diagnostic_code_1: z.string().max(8).optional(),
  diagnostic_code_2: z.string().max(8).optional(),
  diagnostic_code_3: z.string().max(8).optional(),
  modifier_1: z.string().max(6).optional(),
  modifier_2: z.string().max(6).optional(),
  modifier_3: z.string().max(6).optional(),
  calls: z.number().int().min(1).optional(),
  encounters: z.number().int().min(1).optional(),
  date_of_service_from: z.string().date(),
  date_of_service_to: z.string().date(),
  facility_type_override: z.string().max(1).optional(),
  skill_code_override: z.string().max(10).optional(),
  amount: z.string().regex(/^\d+\.\d{2}$/).optional(),
});

export type WcbInvoiceLineDated = z.infer<typeof wcbInvoiceLineDatedSchema>;

// --- Supply Invoice Line (C569) ---

export const wcbInvoiceLineSupplySchema = z.object({
  line_type: z.literal(WcbInvoiceLineType.SUPPLY),
  quantity: z.number().int().min(1),
  supply_description: z.string().min(1).max(50),
  amount: z.string().regex(/^\d+\.\d{2}$/),
});

export type WcbInvoiceLineSupply = z.infer<typeof wcbInvoiceLineSupplySchema>;

// --- Correction Invoice Line (C570 WAS/SHOULD_BE pairs) ---

export const wcbInvoiceLineCorrectionSchema = z.object({
  line_type: z.enum(WCB_CORRECTION_LINE_TYPES),
  correction_pair_id: z.number().int().min(1),
  adjustment_indicator: z.string().max(10).optional(),
  billing_number_override: z.string().max(8).optional(),
  health_service_code: z.string().min(1).max(7).optional(),
  diagnostic_code_1: z.string().max(8).optional(),
  diagnostic_code_2: z.string().max(8).optional(),
  diagnostic_code_3: z.string().max(8).optional(),
  modifier_1: z.string().max(6).optional(),
  modifier_2: z.string().max(6).optional(),
  modifier_3: z.string().max(6).optional(),
  calls: z.number().int().min(1).optional(),
  encounters: z.number().int().min(1).optional(),
  amount: z.string().regex(/^\d+\.\d{2}$/).optional(),
});

export type WcbInvoiceLineCorrection = z.infer<typeof wcbInvoiceLineCorrectionSchema>;

// --- Discriminated Union for Invoice Lines ---

export const wcbInvoiceLineSchema = z.discriminatedUnion('line_type', [
  wcbInvoiceLineStandardSchema,
  wcbInvoiceLineDatedSchema,
  wcbInvoiceLineSupplySchema,
  wcbInvoiceLineCorrectionSchema,
]);

export type WcbInvoiceLine = z.infer<typeof wcbInvoiceLineSchema>;

// ============================================================================
// WCB Claim CRUD
// ============================================================================

// --- Create WCB Claim ---
// form_id and patient_id are required; all other form-section fields are optional
// at the Zod layer. The service layer enforces form-specific required fields.

export const wcbClaimCreateSchema = z.object({
  // --- Required ---
  form_id: z.enum(WCB_FORM_TYPES),
  patient_id: z.string().uuid(),

  // --- General Fields ---
  wcb_claim_number: z.string().max(7).optional(),
  parent_wcb_claim_id: z.string().uuid().optional(),
  report_completion_date: z.string().date().optional(),
  additional_comments: z.string().optional(),

  // --- Employer Fields ---
  employer_name: z.string().max(50).optional(),
  employer_location: z.string().max(100).optional(),
  employer_city: z.string().max(20).optional(),
  employer_province: z.string().max(10).optional(),
  employer_phone_country: z.string().max(10).optional(),
  employer_phone_number: z.string().max(24).optional(),
  employer_phone_ext: z.string().max(6).optional(),

  // --- Accident Fields ---
  worker_job_title: z.string().max(50).optional(),
  injury_developed_over_time: z.enum(YES_NO).optional(),
  date_of_injury: z.string().date().optional(),
  injury_description: z.string().optional(),

  // --- Injury Assessment Fields (scalar) ---
  date_of_examination: z.string().date().optional(),
  symptoms: z.string().optional(),
  objective_findings: z.string().optional(),
  current_diagnosis: z.string().optional(),
  previous_diagnosis: z.string().optional(),
  diagnosis_changed: z.enum(YES_NO).optional(),
  diagnosis_changed_desc: z.string().optional(),
  diagnostic_code_1: z.string().max(8).optional(),
  diagnostic_code_2: z.string().max(8).optional(),
  diagnostic_code_3: z.string().max(8).optional(),
  additional_injuries_desc: z.string().optional(),
  dominant_hand: z.string().max(10).optional(),
  prior_conditions_flag: z.enum(YES_NO).optional(),
  prior_conditions_desc: z.string().optional(),
  referring_physician_name: z.string().max(50).optional(),
  date_of_referral: z.string().date().optional(),

  // --- Treatment Plan Fields ---
  narcotics_prescribed: z.enum(YES_NO).optional(),
  treatment_plan_text: z.string().optional(),
  case_conf_wcb_manager: z.enum(YES_NO).optional(),
  case_conf_wcb_physician: z.enum(YES_NO).optional(),
  referral_rtw_provider: z.enum(YES_NO).optional(),
  consultation_letter_format: z.string().max(5).optional(),
  consultation_letter_text: z.string().optional(),

  // --- Return to Work Fields ---
  missed_work_beyond_accident: z.enum(YES_NO).optional(),
  patient_returned_to_work: z.enum(YES_NO).optional(),
  date_returned_to_work: z.string().date().optional(),
  modified_hours: z.enum(YES_NO).optional(),
  hours_capable_per_day: z.number().int().min(0).max(24).optional(),
  modified_duties: z.enum(YES_NO).optional(),
  rtw_hospitalized: z.enum(YES_NO).optional(),
  rtw_self_reported_pain: z.enum(YES_NO).optional(),
  rtw_opioid_side_effects: z.enum(YES_NO).optional(),
  rtw_other_restrictions: z.string().optional(),
  estimated_rtw_date: z.string().date().optional(),
  rtw_status_changed: z.enum(YES_NO).optional(),

  // --- Invoice Correction Fields (C570 Only) ---
  reassessment_comments: z.string().optional(),

  // --- OIS Hand Grasping Assessment (C050S/C151S) ---
  grasp_right_level: z.string().max(10).optional(),
  grasp_right_prolonged: z.enum(YES_NO).optional(),
  grasp_right_repetitive: z.enum(YES_NO).optional(),
  grasp_right_vibration: z.enum(YES_NO).optional(),
  grasp_right_specify: z.enum(YES_NO).optional(),
  grasp_right_specific_desc: z.string().optional(),
  grasp_left_level: z.string().max(10).optional(),
  grasp_left_prolonged: z.enum(YES_NO).optional(),
  grasp_left_repetitive: z.enum(YES_NO).optional(),
  grasp_left_vibration: z.enum(YES_NO).optional(),
  grasp_left_specify: z.enum(YES_NO).optional(),
  grasp_left_specific_desc: z.string().optional(),

  // --- OIS Zone-Specific Lifting ---
  lift_floor_to_waist: z.string().max(10).optional(),
  lift_floor_to_waist_max: z.string().max(10).optional(),
  lift_waist_to_shoulder: z.string().max(10).optional(),
  lift_waist_to_shoulder_max: z.string().max(10).optional(),
  lift_above_shoulder: z.string().max(10).optional(),
  lift_above_shoulder_max: z.string().max(10).optional(),

  // --- OIS Directional Reaching ---
  reach_above_right_shoulder: z.string().max(10).optional(),
  reach_below_right_shoulder: z.string().max(10).optional(),
  reach_above_left_shoulder: z.string().max(10).optional(),
  reach_below_left_shoulder: z.string().max(10).optional(),

  // --- OIS Environmental Restrictions ---
  environment_restricted: z.enum(YES_NO).optional(),
  env_cold: z.enum(YES_NO).optional(),
  env_hot: z.enum(YES_NO).optional(),
  env_wet: z.enum(YES_NO).optional(),
  env_dry: z.enum(YES_NO).optional(),
  env_dust: z.enum(YES_NO).optional(),
  env_lighting: z.enum(YES_NO).optional(),
  env_noise: z.enum(YES_NO).optional(),

  // --- OIS Assessment Summary ---
  ois_reviewed_with_patient: z.enum(YES_NO).optional(),
  ois_fitness_assessment: z.string().max(10).optional(),
  ois_estimated_rtw_date: z.string().date().optional(),
  ois_rtw_level: z.string().max(10).optional(),
  ois_followup_required: z.enum(YES_NO).optional(),
  ois_followup_date: z.string().date().optional(),
  ois_emp_modified_work_required: z.enum(YES_NO).optional(),
  ois_emp_modified_from_date: z.string().date().optional(),
  ois_emp_modified_to_date: z.string().date().optional(),
  ois_emp_modified_available: z.enum(YES_NO).optional(),
  ois_emp_available_from_date: z.string().date().optional(),
  ois_emp_available_to_date: z.string().date().optional(),
  ois_emp_comments: z.string().optional(),
  ois_worker_rtw_date: z.string().date().optional(),
  ois_worker_modified_duration: z.string().max(50).optional(),
  ois_worker_diagnosis_plan: z.string().optional(),
  ois_worker_self_care: z.enum(YES_NO).optional(),
  ois_worker_comments: z.string().optional(),
  ois_has_family_physician: z.enum(YES_NO).optional(),
  ois_family_physician_name: z.string().max(50).optional(),
  ois_family_physician_phone_country: z.string().max(10).optional(),
  ois_family_physician_phone: z.string().max(24).optional(),
  ois_family_physician_plan: z.string().optional(),
  ois_family_physician_support: z.string().max(10).optional(),
  ois_family_physician_rtw_date: z.string().date().optional(),
  ois_family_physician_treatment: z.string().max(10).optional(),
  ois_family_physician_modified: z.string().max(10).optional(),
  ois_family_physician_comments: z.string().optional(),

  // --- Opioid Management Fields (C151/C151S only) ---
  surgery_past_60_days: z.enum(YES_NO).optional(),
  treating_malignant_pain: z.enum(YES_NO).optional(),
  wcb_advised_no_mmr: z.enum(YES_NO).optional(),
  side_effect_nausea: z.enum(YES_NO).optional(),
  side_effect_sleep: z.enum(YES_NO).optional(),
  side_effect_constipation: z.enum(YES_NO).optional(),
  side_effect_endocrine: z.enum(YES_NO).optional(),
  side_effect_sweating: z.enum(YES_NO).optional(),
  side_effect_cognitive: z.enum(YES_NO).optional(),
  side_effect_dry_mouth: z.enum(YES_NO).optional(),
  side_effect_fatigue: z.enum(YES_NO).optional(),
  side_effect_depression: z.enum(YES_NO).optional(),
  side_effect_worsening_pain: z.enum(YES_NO).optional(),
  abuse_social_deterioration: z.enum(YES_NO).optional(),
  abuse_unsanctioned_use: z.enum(YES_NO).optional(),
  abuse_altered_route: z.enum(YES_NO).optional(),
  abuse_opioid_seeking: z.enum(YES_NO).optional(),
  abuse_other_sources: z.enum(YES_NO).optional(),
  abuse_withdrawal: z.enum(YES_NO).optional(),
  patient_pain_estimate: z.number().int().min(0).max(10).optional(),
  opioid_reducing_pain: z.enum(YES_NO).optional(),
  pain_reduction_desc: z.string().optional(),
  clinician_function_estimate: z.number().int().min(0).max(10).optional(),

  // --- Child Tables (arrays) ---
  injuries: z.array(wcbInjurySchema).min(1).max(5).optional(),
  prescriptions: z.array(wcbPrescriptionSchema).min(1).max(5).optional(),
  consultations: z.array(wcbConsultationSchema).min(1).max(5).optional(),
  work_restrictions: z.array(wcbWorkRestrictionSchema).max(11).optional(),
  invoice_lines: z.array(wcbInvoiceLineSchema).min(1).max(25).optional(),
  attachments: z.array(wcbAttachmentSchema).max(3).optional(),
});

export type WcbClaimCreate = z.infer<typeof wcbClaimCreateSchema>;

// --- Update WCB Claim ---
// All fields optional (partial update). Service validates form-specific requirements.

export const wcbClaimUpdateSchema = wcbClaimCreateSchema
  .omit({ form_id: true, patient_id: true })
  .partial();

export type WcbClaimUpdate = z.infer<typeof wcbClaimUpdateSchema>;

// --- WCB Claim ID Parameter ---

export const wcbClaimIdParamSchema = z.object({
  id: z.string().uuid(),
});

export type WcbClaimIdParam = z.infer<typeof wcbClaimIdParamSchema>;

// ============================================================================
// Validation Response
// ============================================================================

// --- Validation Message ---

const wcbValidationMessageSchema = z.object({
  check_id: z.string(),
  severity: z.enum(VALIDATION_SEVERITIES),
  message: z.string(),
  field: z.string().optional(),
});

// --- Timing Deadline Info ---

const wcbDeadlineInfoSchema = z.object({
  same_day_deadline: z.string().datetime().optional(),
  on_time_deadline: z.string().datetime().optional(),
  is_past_deadline: z.boolean(),
  business_days_remaining: z.number().int().optional(),
});

// --- Validate Response ---

export const wcbClaimValidateResponseSchema = z.object({
  errors: z.array(wcbValidationMessageSchema),
  warnings: z.array(wcbValidationMessageSchema),
  info: z.array(wcbValidationMessageSchema),
  passed: z.boolean(),
  timing_tier: z.string().optional(),
  deadline_info: wcbDeadlineInfoSchema.optional(),
});

export type WcbClaimValidateResponse = z.infer<typeof wcbClaimValidateResponseSchema>;

// ============================================================================
// Form Schema Response (dynamic form field definitions)
// ============================================================================

const wcbFormFieldSchema = z.object({
  name: z.string(),
  required: z.boolean(),
  conditional: z.boolean(),
  type: z.string(),
  max_length: z.number().int().optional(),
});

const wcbFormSectionSchema = z.object({
  name: z.string(),
  active: z.boolean(),
  fields: z.array(wcbFormFieldSchema),
});

export const wcbFormSchemaResponseSchema = z.object({
  form_id: z.enum(WCB_FORM_TYPES),
  sections: z.array(wcbFormSectionSchema),
});

export type WcbFormSchemaResponse = z.infer<typeof wcbFormSchemaResponseSchema>;

// ============================================================================
// WCB Batch Management
// ============================================================================

// --- Create Batch (auto-selects queued claims for authenticated physician) ---

export const wcbBatchCreateSchema = z.object({});

export type WcbBatchCreate = z.infer<typeof wcbBatchCreateSchema>;

// --- Batch ID Parameter ---

export const wcbBatchIdParamSchema = z.object({
  id: z.string().uuid(),
});

export type WcbBatchIdParam = z.infer<typeof wcbBatchIdParamSchema>;

// --- Confirm Upload (POST with auth — batch ID in URL) ---

export const wcbBatchConfirmUploadSchema = z.object({});

export type WcbBatchConfirmUpload = z.infer<typeof wcbBatchConfirmUploadSchema>;

// --- List Batches Query ---

export const wcbBatchListQuerySchema = z.object({
  status: z.enum(WCB_BATCH_STATUSES).optional(),
  page: z.coerce.number().int().min(1).default(1),
  page_size: z.coerce.number().int().min(1).max(100).default(20),
});

export type WcbBatchListQuery = z.infer<typeof wcbBatchListQuerySchema>;

// ============================================================================
// Return File / Remittance
// ============================================================================

// --- Return File Upload ---
// File upload handled via multipart; this schema validates metadata only.

export const wcbReturnFileUploadSchema = z.object({});

export type WcbReturnFileUpload = z.infer<typeof wcbReturnFileUploadSchema>;

// --- Remittance Upload ---
// XML file upload handled via multipart; this schema validates metadata only.

export const wcbRemittanceUploadSchema = z.object({});

export type WcbRemittanceUpload = z.infer<typeof wcbRemittanceUploadSchema>;

// --- Remittance List Query ---

export const wcbRemittanceListQuerySchema = z.object({
  start_date: z.string().date().optional(),
  end_date: z.string().date().optional(),
  page: z.coerce.number().int().min(1).default(1),
  page_size: z.coerce.number().int().min(1).max(100).default(20),
});

export type WcbRemittanceListQuery = z.infer<typeof wcbRemittanceListQuerySchema>;

// --- Remittance ID Parameter ---

export const wcbRemittanceIdParamSchema = z.object({
  id: z.string().uuid(),
});

export type WcbRemittanceIdParam = z.infer<typeof wcbRemittanceIdParamSchema>;

// ============================================================================
// MVP Endpoints
// ============================================================================

// --- Manual Outcome (MVP manual acceptance/rejection for WCB claims) ---

export const wcbManualOutcomeSchema = z.object({
  wcb_claim_number: z.string().max(7).optional(),
  acceptance_status: z.enum(WCB_MVP_ACCEPTANCE_STATUSES),
  payment_amount: z.number().min(0).optional(),
});

export type WcbManualOutcome = z.infer<typeof wcbManualOutcomeSchema>;
