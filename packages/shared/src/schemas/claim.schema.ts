// ============================================================================
// Domain 4.0: Claim Lifecycle Core — Zod Validation Schemas
// ============================================================================

import { z } from 'zod';
import {
  ClaimType,
  ClaimImportSource,
  ClaimState,
  AutoSubmissionMode,
  JustificationScenario,
  ClaimTemplateType,
} from '../constants/claim.constants.js';

// --- Enum Value Arrays ---

const CLAIM_TYPES = [ClaimType.AHCIP, ClaimType.WCB] as const;

const IMPORT_SOURCES = [
  ClaimImportSource.MANUAL,
  ClaimImportSource.EMR_IMPORT,
  ClaimImportSource.ED_SHIFT,
  ClaimImportSource.CONNECT_CARE_CSV,
  ClaimImportSource.CONNECT_CARE_SFTP,
  ClaimImportSource.EMR_GENERIC,
] as const;

const CLAIM_STATES = [
  ClaimState.DRAFT,
  ClaimState.VALIDATED,
  ClaimState.QUEUED,
  ClaimState.SUBMITTED,
  ClaimState.ASSESSED,
  ClaimState.PAID,
  ClaimState.REJECTED,
  ClaimState.ADJUSTED,
  ClaimState.WRITTEN_OFF,
  ClaimState.EXPIRED,
  ClaimState.DELETED,
] as const;

// ============================================================================
// Claim CRUD
// ============================================================================

// --- Create Claim ---

export const createClaimSchema = z.object({
  claim_type: z.enum(CLAIM_TYPES),
  patient_id: z.string().uuid(),
  date_of_service: z.string().date(),
  import_source: z.enum(IMPORT_SOURCES).default('MANUAL'),
});

export type CreateClaim = z.infer<typeof createClaimSchema>;

// --- Update Claim ---
// claim_type is NOT editable after creation.
// Only fields that can be modified in DRAFT/REJECTED states.

export const updateClaimSchema = z.object({
  patient_id: z.string().uuid().optional(),
  date_of_service: z.string().date().optional(),
  import_source: z.enum(IMPORT_SOURCES).optional(),
});

export type UpdateClaim = z.infer<typeof updateClaimSchema>;

// --- Claim ID Parameter ---

export const claimIdParamSchema = z.object({
  id: z.string().uuid(),
});

export type ClaimIdParam = z.infer<typeof claimIdParamSchema>;

// ============================================================================
// Claim Query / List
// ============================================================================

// --- List Claims Query ---

export const listClaimsSchema = z.object({
  state: z.enum(CLAIM_STATES).optional(),
  claim_type: z.enum(CLAIM_TYPES).optional(),
  date_from: z.string().date().optional(),
  date_to: z.string().date().optional(),
  patient_id: z.string().uuid().optional(),
  is_clean: z.coerce.boolean().optional(),
  page: z.coerce.number().int().min(1).default(1),
  page_size: z.coerce.number().int().min(1).max(100).default(25),
});

export type ListClaims = z.infer<typeof listClaimsSchema>;

// ============================================================================
// State Transitions
// ============================================================================

// --- Queue Claim (no body, claim_id from path) ---

export const queueClaimSchema = z.object({});

export type QueueClaim = z.infer<typeof queueClaimSchema>;

// --- Write Off Claim ---

export const writeOffClaimSchema = z.object({
  reason: z.string().min(1).max(500),
});

export type WriteOffClaim = z.infer<typeof writeOffClaimSchema>;

// --- Resubmit Claim (no body, revalidates and requeues) ---

export const resubmitClaimSchema = z.object({});

export type ResubmitClaim = z.infer<typeof resubmitClaimSchema>;

// ============================================================================
// AI Coach
// ============================================================================

// --- Dismiss Suggestion ---

export const dismissSuggestionSchema = z.object({
  reason: z.string().max(500).optional(),
});

export type DismissSuggestion = z.infer<typeof dismissSuggestionSchema>;

// --- Suggestion ID Parameter ---

export const suggestionIdParamSchema = z.object({
  sug_id: z.string().uuid(),
});

export type SuggestionIdParam = z.infer<typeof suggestionIdParamSchema>;

// ============================================================================
// EMR Import
// ============================================================================

// --- Create Import (file uploaded via multipart; body only carries optional template ref) ---

export const createImportSchema = z.object({
  field_mapping_template_id: z.string().uuid().optional(),
});

export type CreateImport = z.infer<typeof createImportSchema>;

// --- Commit Import (no body, import_batch_id from path) ---

export const commitImportSchema = z.object({});

export type CommitImport = z.infer<typeof commitImportSchema>;

// --- Import Batch ID Parameter ---

export const claimImportIdParamSchema = z.object({
  id: z.string().uuid(),
});

export type ClaimImportIdParam = z.infer<typeof claimImportIdParamSchema>;

// ============================================================================
// Field Mapping Templates
// ============================================================================

// --- Field Mapping Entry ---

const fieldMappingEntrySchema = z.object({
  source_column: z.string().min(1),
  target_field: z.string().min(1),
  transform: z.string().optional(),
});

// --- Create Template ---

export const createTemplateSchema = z.object({
  name: z.string().min(1).max(100),
  emr_type: z.string().max(50).optional(),
  mappings: z.array(fieldMappingEntrySchema).min(1),
  delimiter: z.string().max(5).optional(),
  has_header_row: z.boolean(),
  date_format: z.string().max(20).optional(),
});

export type CreateTemplate = z.infer<typeof createTemplateSchema>;

// --- Update Template (all fields optional) ---

export const updateTemplateSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  emr_type: z.string().max(50).optional(),
  mappings: z.array(fieldMappingEntrySchema).min(1).optional(),
  delimiter: z.string().max(5).optional(),
  has_header_row: z.boolean().optional(),
  date_format: z.string().max(20).optional(),
});

export type UpdateTemplate = z.infer<typeof updateTemplateSchema>;

// --- Template ID Parameter ---

export const templateIdParamSchema = z.object({
  id: z.string().uuid(),
});

export type TemplateIdParam = z.infer<typeof templateIdParamSchema>;

// ============================================================================
// ED Shift
// ============================================================================

// --- Create Shift ---

export const createShiftSchema = z.object({
  facility_id: z.string().uuid(),
  shift_date: z.string().date(),
  start_time: z.string().regex(/^([01]\d|2[0-3]):[0-5]\d(:[0-5]\d)?$/).optional(),
  end_time: z.string().regex(/^([01]\d|2[0-3]):[0-5]\d(:[0-5]\d)?$/).optional(),
});

export type CreateShift = z.infer<typeof createShiftSchema>;

// --- Add Encounter to Shift ---

export const addEncounterSchema = z.object({
  patient_id: z.string().uuid(),
  date_of_service: z.string().date(),
  claim_type: z.enum(CLAIM_TYPES),
});

export type AddEncounter = z.infer<typeof addEncounterSchema>;

// --- Shift ID Parameter ---

export const shiftIdParamSchema = z.object({
  id: z.string().uuid(),
});

export type ShiftIdParam = z.infer<typeof shiftIdParamSchema>;

// ============================================================================
// Data Export
// ============================================================================

const EXPORT_FORMATS = ['CSV', 'JSON'] as const;

// --- Create Export ---

export const createExportSchema = z.object({
  date_from: z.string().date(),
  date_to: z.string().date(),
  claim_type: z.enum(CLAIM_TYPES).optional(),
  format: z.enum(EXPORT_FORMATS).default('CSV'),
});

export type CreateExport = z.infer<typeof createExportSchema>;

// --- Export ID Parameter ---

export const claimExportIdParamSchema = z.object({
  id: z.string().uuid(),
});

export type ClaimExportIdParam = z.infer<typeof claimExportIdParamSchema>;

// ============================================================================
// Submission Preferences
// ============================================================================

const SUBMISSION_MODES = [
  AutoSubmissionMode.AUTO_CLEAN,
  AutoSubmissionMode.AUTO_ALL,
  AutoSubmissionMode.REQUIRE_APPROVAL,
] as const;

// --- Update Preferences ---

export const updateSubmissionModeSchema = z.object({
  mode: z.enum(SUBMISSION_MODES),
});

export type UpdateSubmissionMode = z.infer<typeof updateSubmissionModeSchema>;

// ============================================================================
// Claim Templates (FRD MVPADD-001 §B3)
// ============================================================================

const CLAIM_TEMPLATE_TYPES = [
  ClaimTemplateType.CUSTOM,
  ClaimTemplateType.SPECIALTY_STARTER,
] as const;

// --- Template Line Item ---

const templateLineItemSchema = z.object({
  health_service_code: z.string().min(1).max(10),
  modifiers: z.array(z.string().max(4)).optional(),
  diagnostic_code: z.string().max(10).optional(),
  calls: z.number().int().min(1).default(1),
});

// --- Create Claim Template ---

export const createClaimTemplateSchema = z.object({
  name: z.string().min(1).max(100),
  description: z.string().max(500).optional(),
  template_type: z.enum(CLAIM_TEMPLATE_TYPES).default('CUSTOM'),
  claim_type: z.enum(CLAIM_TYPES),
  line_items: z.array(templateLineItemSchema).min(1),
  specialty_code: z.string().max(10).optional(),
});

export type CreateClaimTemplate = z.infer<typeof createClaimTemplateSchema>;

// --- Update Claim Template ---

export const updateClaimTemplateSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  description: z.string().max(500).optional(),
  line_items: z.array(templateLineItemSchema).min(1).optional(),
});

export type UpdateClaimTemplate = z.infer<typeof updateClaimTemplateSchema>;

// --- Template ID Parameter ---

export const claimTemplateIdParamSchema = z.object({
  id: z.string().uuid(),
});

export type ClaimTemplateIdParam = z.infer<typeof claimTemplateIdParamSchema>;

// --- List Templates Query ---

export const listClaimTemplatesQuerySchema = z.object({
  template_type: z.enum(CLAIM_TEMPLATE_TYPES).optional(),
  claim_type: z.enum(CLAIM_TYPES).optional(),
  page: z.coerce.number().int().min(1).default(1),
  page_size: z.coerce.number().int().min(1).max(50).default(20),
});

export type ListClaimTemplatesQuery = z.infer<typeof listClaimTemplatesQuerySchema>;

// ============================================================================
// Text Justifications (FRD MVPADD-001 §B11)
// ============================================================================

const JUSTIFICATION_SCENARIOS = [
  JustificationScenario.UNLISTED_PROCEDURE,
  JustificationScenario.ADDITIONAL_COMPENSATION,
  JustificationScenario.PRE_OP_CONSERVATIVE,
  JustificationScenario.POST_OP_COMPLICATION,
  JustificationScenario.WCB_NARRATIVE,
] as const;

// --- Create Justification ---

export const createJustificationSchema = z.object({
  claim_id: z.string().uuid(),
  scenario: z.enum(JUSTIFICATION_SCENARIOS),
  justification_text: z.string().min(10).max(5000),
  template_id: z.string().uuid().optional(),
});

export type CreateJustification = z.infer<typeof createJustificationSchema>;

// --- Update Justification ---

export const updateJustificationSchema = z.object({
  justification_text: z.string().min(10).max(5000),
});

export type UpdateJustification = z.infer<typeof updateJustificationSchema>;

// --- Justification ID Parameter ---

export const justificationIdParamSchema = z.object({
  id: z.string().uuid(),
});

export type JustificationIdParam = z.infer<typeof justificationIdParamSchema>;

// --- Justification History Query ---

export const justificationHistoryQuerySchema = z.object({
  scenario: z.enum(JUSTIFICATION_SCENARIOS).optional(),
  page: z.coerce.number().int().min(1).default(1),
  page_size: z.coerce.number().int().min(1).max(50).default(20),
});

export type JustificationHistoryQuery = z.infer<typeof justificationHistoryQuerySchema>;

// ============================================================================
// Recent Referrers (FRD MVPADD-001 §2.1.2)
// ============================================================================

// --- Record Recent Referrer ---

export const recordRecentReferrerSchema = z.object({
  referrer_cpsa: z.string().min(1).max(10),
  referrer_name: z.string().min(1).max(100),
});

export type RecordRecentReferrer = z.infer<typeof recordRecentReferrerSchema>;

// ============================================================================
// Bundling Check (FRD MVPADD-001 §4.3.2)
// ============================================================================

export const bundlingCheckSchema = z.object({
  codes: z.array(z.string().min(1).max(10)).min(2),
  claim_type: z.enum(CLAIM_TYPES),
  patient_id: z.string().uuid().optional(),
  date_of_service: z.string().date().optional(),
});

export type BundlingCheck = z.infer<typeof bundlingCheckSchema>;

// ============================================================================
// Anesthesia Calculator (FRD MVPADD-001 §4.2.2)
// ============================================================================

export const anesthesiaCalculateSchema = z.object({
  procedure_codes: z.array(z.string().min(1).max(10)).min(1),
  start_time: z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/).optional(),
  end_time: z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/).optional(),
  duration_minutes: z.number().int().min(0).optional(),
});

export type AnesthesiaCalculate = z.infer<typeof anesthesiaCalculateSchema>;

// ============================================================================
// Template Application (FRD MVPADD-001 §4.1.3)
// ============================================================================

export const applyClaimTemplateSchema = z.object({
  patient_id: z.string().uuid(),
  date_of_service: z.string().date(),
  auto_submit: z.boolean().optional().default(false),
});

export type ApplyClaimTemplate = z.infer<typeof applyClaimTemplateSchema>;

// --- Reorder Templates ---

export const reorderClaimTemplatesSchema = z.object({
  template_ids: z.array(z.string().uuid()).min(1),
});

export type ReorderClaimTemplates = z.infer<typeof reorderClaimTemplatesSchema>;
