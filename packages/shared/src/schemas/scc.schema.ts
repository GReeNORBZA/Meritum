// ============================================================================
// Connect Care / SCC Integration — Zod Validation Schemas
// ============================================================================

import { z } from 'zod';
import {
  SccExtractType,
  SccChargeStatus,
  SccRowClassification,
  ConnectCareImportStatus,
  IcdMatchQuality,
  CURRENT_SCC_SPEC_VERSION,
} from '../constants/scc.constants.js';

// --- Enum Value Arrays ---

const SCC_EXTRACT_TYPES = [
  SccExtractType.AHCIP,
  SccExtractType.WCB,
] as const;

const SCC_CHARGE_STATUSES = [
  SccChargeStatus.ACTIVE,
  SccChargeStatus.MODIFIED,
  SccChargeStatus.DELETED,
] as const;

const SCC_ROW_CLASSIFICATIONS = [
  SccRowClassification.VALID,
  SccRowClassification.WARNING,
  SccRowClassification.ERROR,
  SccRowClassification.DELETED,
  SccRowClassification.DUPLICATE,
] as const;

const CC_IMPORT_STATUSES = [
  ConnectCareImportStatus.PENDING,
  ConnectCareImportStatus.CONFIRMED,
  ConnectCareImportStatus.CANCELLED,
] as const;

const ICD_MATCH_QUALITIES = [
  IcdMatchQuality.EXACT,
  IcdMatchQuality.CLOSE,
  IcdMatchQuality.APPROXIMATE,
  IcdMatchQuality.BROAD,
] as const;

// ============================================================================
// SCC Import Upload
// ============================================================================

// --- Upload SCC Extract (multipart file, metadata in body) ---

export const uploadSccExtractSchema = z.object({
  extract_type: z.enum(SCC_EXTRACT_TYPES).optional(),
  spec_version: z.string().max(20).default(CURRENT_SCC_SPEC_VERSION),
});

export type UploadSccExtract = z.infer<typeof uploadSccExtractSchema>;

// --- SCC Import ID Parameter ---

export const sccImportIdParamSchema = z.object({
  id: z.string().uuid(),
});

export type SccImportIdParam = z.infer<typeof sccImportIdParamSchema>;

// ============================================================================
// SCC Import Confirmation
// ============================================================================

// --- Confirm / Cancel Import ---

export const confirmSccImportSchema = z.object({
  action: z.enum(['CONFIRMED', 'CANCELLED'] as const),
  excluded_row_ids: z.array(z.string().uuid()).optional(),
});

export type ConfirmSccImport = z.infer<typeof confirmSccImportSchema>;

// ============================================================================
// SCC Import List
// ============================================================================

export const listSccImportsQuerySchema = z.object({
  status: z.enum(CC_IMPORT_STATUSES).optional(),
  page: z.coerce.number().int().min(1).default(1),
  page_size: z.coerce.number().int().min(1).max(100).default(25),
});

export type ListSccImportsQuery = z.infer<typeof listSccImportsQuerySchema>;

// ============================================================================
// SCC Parsed Row (validation shape for parsed CSV rows)
// ============================================================================

export const sccParsedRowSchema = z.object({
  row_number: z.number().int().positive(),
  extract_type: z.enum(SCC_EXTRACT_TYPES),
  charge_status: z.enum(SCC_CHARGE_STATUSES),
  classification: z.enum(SCC_ROW_CLASSIFICATIONS),
  patient_uli: z.string().max(9).optional(),
  patient_name: z.string().max(100).optional(),
  encounter_date: z.string().date(),
  service_code: z.string().max(10),
  modifiers: z.array(z.string().max(4)).optional(),
  diagnostic_code: z.string().max(10).optional(),
  icd10_source_code: z.string().max(10).optional(),
  icd9_mapped_code: z.string().max(10).optional(),
  icd_match_quality: z.enum(ICD_MATCH_QUALITIES).optional(),
  functional_centre: z.string().max(10).optional(),
  billing_provider_id: z.string().max(10).optional(),
  referring_provider: z.string().max(100).optional(),
  fee_submitted: z.string().regex(/^\d+\.\d{2}$/).optional(),
  validation_messages: z.array(z.object({
    severity: z.enum(['BLOCKING', 'WARNING', 'INFORMATIONAL'] as const),
    code: z.string().max(30),
    message: z.string(),
  })).default([]),
  // WCB-specific fields
  wcb_claim_number: z.string().max(20).optional(),
  employer_name: z.string().max(200).optional(),
  injury_date: z.string().date().optional(),
});

export type SccParsedRow = z.infer<typeof sccParsedRowSchema>;

// ============================================================================
// SCC Import Summary Response
// ============================================================================

export const sccImportSummarySchema = z.object({
  import_batch_id: z.string().uuid(),
  extract_type: z.enum(SCC_EXTRACT_TYPES),
  spec_version: z.string(),
  file_name: z.string(),
  total_rows: z.number().int(),
  valid_count: z.number().int(),
  warning_count: z.number().int(),
  error_count: z.number().int(),
  duplicate_count: z.number().int(),
  deleted_count: z.number().int(),
  confirmation_status: z.enum(CC_IMPORT_STATUSES),
});

export type SccImportSummary = z.infer<typeof sccImportSummarySchema>;

// ============================================================================
// ICD Crosswalk Lookup
// ============================================================================

// --- Crosswalk Lookup Param ---

export const icdCrosswalkParamSchema = z.object({
  icd10_code: z.string().max(10),
});

export type IcdCrosswalkParam = z.infer<typeof icdCrosswalkParamSchema>;

// --- Crosswalk Search Query ---

export const icdCrosswalkSearchSchema = z.object({
  q: z.string().min(1).max(100),
  limit: z.coerce.number().int().min(1).max(50).default(10),
});

export type IcdCrosswalkSearch = z.infer<typeof icdCrosswalkSearchSchema>;

// --- Crosswalk Result ---

export const icdCrosswalkResultSchema = z.object({
  icd10_code: z.string(),
  icd10_description: z.string(),
  icd9_code: z.string(),
  icd9_description: z.string(),
  match_quality: z.enum(ICD_MATCH_QUALITIES),
  is_preferred: z.boolean(),
});

export type IcdCrosswalkResult = z.infer<typeof icdCrosswalkResultSchema>;
