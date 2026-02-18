// ============================================================================
// Domain 6: Patient Registry — Zod Validation Schemas
// ============================================================================

import { z } from 'zod';
import { Gender, ProvinceCode } from '../constants/patient.constants.js';

// --- Enum Value Arrays ---

const GENDERS = [Gender.MALE, Gender.FEMALE, Gender.OTHER] as const;

const PROVINCE_CODES = [
  ProvinceCode.AB,
  ProvinceCode.BC,
  ProvinceCode.SK,
  ProvinceCode.MB,
  ProvinceCode.ON,
  ProvinceCode.QC,
  ProvinceCode.NB,
  ProvinceCode.NS,
  ProvinceCode.PE,
  ProvinceCode.NL,
  ProvinceCode.YT,
  ProvinceCode.NT,
  ProvinceCode.NU,
] as const;

// ============================================================================
// Patient CRUD
// ============================================================================

// --- Create Patient ---

export const createPatientSchema = z.object({
  phn: z
    .string()
    .length(9)
    .regex(/^\d{9}$/)
    .optional()
    .nullable(),
  phn_province: z.enum(PROVINCE_CODES).default('AB').optional(),
  first_name: z.string().min(1).max(50),
  middle_name: z.string().max(50).optional(),
  last_name: z.string().min(1).max(50),
  date_of_birth: z.string().date(),
  gender: z.enum(GENDERS),
  phone: z.string().max(24).optional(),
  email: z.string().email().max(100).optional(),
  address_line_1: z.string().max(100).optional(),
  address_line_2: z.string().max(100).optional(),
  city: z.string().max(50).optional(),
  province: z.enum(PROVINCE_CODES).optional(),
  postal_code: z.string().max(7).optional(),
  notes: z.string().optional(),
});

export type CreatePatient = z.infer<typeof createPatientSchema>;

// --- Update Patient ---

export const updatePatientSchema = z.object({
  phn: z
    .string()
    .length(9)
    .regex(/^\d{9}$/)
    .optional()
    .nullable(),
  phn_province: z.enum(PROVINCE_CODES).optional(),
  first_name: z.string().min(1).max(50).optional(),
  middle_name: z.string().max(50).optional(),
  last_name: z.string().min(1).max(50).optional(),
  date_of_birth: z.string().date().optional(),
  gender: z.enum(GENDERS).optional(),
  phone: z.string().max(24).optional(),
  email: z.string().email().max(100).optional(),
  address_line_1: z.string().max(100).optional(),
  address_line_2: z.string().max(100).optional(),
  city: z.string().max(50).optional(),
  province: z.enum(PROVINCE_CODES).optional(),
  postal_code: z.string().max(7).optional(),
  notes: z.string().optional(),
});

export type UpdatePatient = z.infer<typeof updatePatientSchema>;

// --- Patient ID Parameter ---

export const patientIdParamSchema = z.object({
  id: z.string().uuid(),
});

export type PatientIdParam = z.infer<typeof patientIdParamSchema>;

// ============================================================================
// Patient Search
// ============================================================================

// --- Patient Search Query ---

export const patientSearchQuerySchema = z.object({
  phn: z.string().optional(),
  name: z.string().min(2).optional(),
  dob: z.string().date().optional(),
  page: z.coerce.number().int().min(1).default(1),
  page_size: z.coerce.number().int().min(1).max(100).default(20),
});

export type PatientSearchQuery = z.infer<typeof patientSearchQuerySchema>;

// --- Recent Patients Query ---

export const recentPatientsQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(50).default(20),
});

export type RecentPatientsQuery = z.infer<typeof recentPatientsQuerySchema>;

// ============================================================================
// CSV Import
// ============================================================================

// --- Import Column Mapping ---

export const importMappingSchema = z.object({
  mapping: z.record(z.string(), z.string().nullable()),
});

export type ImportMapping = z.infer<typeof importMappingSchema>;

// --- Import ID Parameter ---

export const importIdParamSchema = z.object({
  id: z.string().uuid(),
});

export type ImportIdParam = z.infer<typeof importIdParamSchema>;

// ============================================================================
// Patient Merge
// ============================================================================

// --- Merge Preview ---

export const mergePreviewSchema = z.object({
  surviving_id: z.string().uuid(),
  merged_id: z.string().uuid(),
});

export type MergePreview = z.infer<typeof mergePreviewSchema>;

// --- Merge Execute ---

export const mergeExecuteSchema = z.object({
  surviving_id: z.string().uuid(),
  merged_id: z.string().uuid(),
});

export type MergeExecute = z.infer<typeof mergeExecuteSchema>;

// ============================================================================
// Patient Export
// ============================================================================

// --- Export ID Parameter ---

export const exportIdParamSchema = z.object({
  id: z.string().uuid(),
});

export type ExportIdParam = z.infer<typeof exportIdParamSchema>;

// ============================================================================
// Internal API
// ============================================================================

// --- Internal Patient ID Parameter ---

export const internalPatientIdParamSchema = z.object({
  id: z.string().uuid(),
});

export type InternalPatientIdParam = z.infer<typeof internalPatientIdParamSchema>;

// --- Validate PHN Parameter ---

export const validatePhnParamSchema = z.object({
  phn: z.string().length(9).regex(/^\d{9}$/),
});

export type ValidatePhnParam = z.infer<typeof validatePhnParamSchema>;
