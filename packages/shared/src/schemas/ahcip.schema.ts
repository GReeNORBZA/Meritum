// ============================================================================
// Domain 4.1: AHCIP Pathway — Zod Validation Schemas
// ============================================================================

import { z } from 'zod';
import {
  AhcipEncounterType,
  AhcipBatchStatus,
} from '../constants/ahcip.constants.js';

// --- Enum Value Arrays ---

const ENCOUNTER_TYPES = [
  AhcipEncounterType.CONSULTATION,
  AhcipEncounterType.FOLLOW_UP,
  AhcipEncounterType.PROCEDURE,
  AhcipEncounterType.SURGICAL,
  AhcipEncounterType.DIAGNOSTIC_IMAGING,
  AhcipEncounterType.OBSTETRIC,
  AhcipEncounterType.CDM,
  AhcipEncounterType.VIRTUAL,
  AhcipEncounterType.OTHER,
] as const;

const BATCH_STATUSES = [
  AhcipBatchStatus.ASSEMBLING,
  AhcipBatchStatus.GENERATED,
  AhcipBatchStatus.SUBMITTED,
  AhcipBatchStatus.RESPONSE_RECEIVED,
  AhcipBatchStatus.RECONCILED,
  AhcipBatchStatus.ERROR,
] as const;

// ============================================================================
// AHCIP Claim Detail CRUD
// ============================================================================

// --- Create AHCIP Detail ---

export const createAhcipDetailSchema = z.object({
  health_service_code: z.string().min(1).max(10),
  functional_centre: z.string().min(1).max(10),
  encounter_type: z.enum(ENCOUNTER_TYPES),
  modifier_1: z.string().max(6).optional(),
  modifier_2: z.string().max(6).optional(),
  modifier_3: z.string().max(6).optional(),
  diagnostic_code: z.string().max(8).optional(),
  facility_number: z.string().max(10).optional(),
  referral_practitioner: z.string().max(10).optional(),
  calls: z.number().int().min(1).default(1),
  time_spent: z.number().int().min(1).optional(),
  patient_location: z.string().max(10).optional(),
});

export type CreateAhcipDetail = z.infer<typeof createAhcipDetailSchema>;

// --- Update AHCIP Detail ---
// All fields optional (partial update). health_service_code is editable.

export const updateAhcipDetailSchema = z.object({
  health_service_code: z.string().min(1).max(10).optional(),
  functional_centre: z.string().min(1).max(10).optional(),
  encounter_type: z.enum(ENCOUNTER_TYPES).optional(),
  modifier_1: z.string().max(6).optional(),
  modifier_2: z.string().max(6).optional(),
  modifier_3: z.string().max(6).optional(),
  diagnostic_code: z.string().max(8).optional(),
  facility_number: z.string().max(10).optional(),
  referral_practitioner: z.string().max(10).optional(),
  calls: z.number().int().min(1).optional(),
  time_spent: z.number().int().min(1).optional(),
  patient_location: z.string().max(10).optional(),
});

export type UpdateAhcipDetail = z.infer<typeof updateAhcipDetailSchema>;

// ============================================================================
// Batch Management
// ============================================================================

// --- List Batches Query ---

export const listBatchesSchema = z.object({
  status: z.enum(BATCH_STATUSES).optional(),
  date_from: z.string().date().optional(),
  date_to: z.string().date().optional(),
  page: z.coerce.number().int().min(1).default(1),
  page_size: z.coerce.number().int().min(1).max(50).default(20),
});

export type ListBatches = z.infer<typeof listBatchesSchema>;

// --- Batch ID Parameter ---

export const batchIdParamSchema = z.object({
  id: z.string().uuid(),
});

export type BatchIdParam = z.infer<typeof batchIdParamSchema>;

// ============================================================================
// Fee Calculation
// ============================================================================

// --- Fee Calculate (preview without saving) ---

export const feeCalculateSchema = z.object({
  health_service_code: z.string().min(1).max(10),
  functional_centre: z.string().min(1).max(10),
  encounter_type: z.enum(ENCOUNTER_TYPES),
  modifier_1: z.string().max(6).optional(),
  modifier_2: z.string().max(6).optional(),
  modifier_3: z.string().max(6).optional(),
  diagnostic_code: z.string().max(8).optional(),
  facility_number: z.string().max(10).optional(),
  referral_practitioner: z.string().max(10).optional(),
  calls: z.number().int().min(1).default(1),
  time_spent: z.number().int().min(1).optional(),
  patient_location: z.string().max(10).optional(),
  date_of_service: z.string().date(),
  patient_id: z.string().uuid(),
});

export type FeeCalculate = z.infer<typeof feeCalculateSchema>;

// ============================================================================
// Assessment Query
// ============================================================================

// --- Batch Assessment Parameter ---

export const batchAssessmentParamSchema = z.object({
  batch_id: z.string().uuid(),
});

export type BatchAssessmentParam = z.infer<typeof batchAssessmentParamSchema>;
