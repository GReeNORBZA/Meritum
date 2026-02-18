// ============================================================================
// Domain 4.0: Claim Lifecycle Core — Zod Validation Schemas
// ============================================================================

import { z } from 'zod';
import {
  ClaimType,
  ClaimImportSource,
  ClaimState,
  AutoSubmissionMode,
} from '../constants/claim.constants.js';

// --- Enum Value Arrays ---

const CLAIM_TYPES = [ClaimType.AHCIP, ClaimType.WCB] as const;

const IMPORT_SOURCES = [
  ClaimImportSource.MANUAL,
  ClaimImportSource.EMR_IMPORT,
  ClaimImportSource.ED_SHIFT,
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
