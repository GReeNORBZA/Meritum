// ============================================================================
// Compliance & IMA Legal — Zod Validation Schemas
// ============================================================================

import { z } from 'zod';
import {
  ImaAmendmentType,
  ImaAmendmentResponseType,
} from '../constants/platform.constants.js';

// --- IMA Amendment: Create (admin-only) ---

const AMENDMENT_TYPES = [
  ImaAmendmentType.NON_MATERIAL,
  ImaAmendmentType.MATERIAL,
] as const;

export const createAmendmentSchema = z.object({
  amendment_type: z.enum(AMENDMENT_TYPES),
  title: z.string().min(1).max(500),
  description: z.string().min(1).max(10000),
  document_text: z.string().min(1),
  effective_date: z.string().datetime(),
});

export type CreateAmendment = z.infer<typeof createAmendmentSchema>;

// --- IMA Amendment: Physician Response ---

const AMENDMENT_RESPONSE_TYPES = [
  ImaAmendmentResponseType.ACKNOWLEDGED,
  ImaAmendmentResponseType.ACCEPTED,
  ImaAmendmentResponseType.REJECTED,
] as const;

export const amendmentResponseSchema = z.object({
  response_type: z.enum(AMENDMENT_RESPONSE_TYPES),
});

export type AmendmentResponse = z.infer<typeof amendmentResponseSchema>;

// --- IMA Amendment: ID Parameter ---

export const amendmentIdParamSchema = z.object({
  id: z.string().uuid(),
});

export type AmendmentIdParam = z.infer<typeof amendmentIdParamSchema>;

// --- IMA Amendment: List Query ---

const AMENDMENT_LIST_STATUSES = ['PENDING', 'ACTIVE', 'EXPIRED'] as const;

export const listAmendmentsQuerySchema = z.object({
  status: z.enum(AMENDMENT_LIST_STATUSES).optional(),
  page: z.coerce.number().int().min(1).default(1),
  page_size: z.coerce.number().int().min(1).max(100).default(50),
});

export type ListAmendmentsQuery = z.infer<typeof listAmendmentsQuerySchema>;

// --- Breach Notification: Create (admin-only) ---

export const createBreachSchema = z.object({
  breach_description: z.string().min(1).max(10000),
  breach_date: z.string().datetime(),
  awareness_date: z.string().datetime(),
  hi_description: z.string().min(1).max(5000),
  includes_iihi: z.boolean(),
  affected_count: z.number().int().positive().optional(),
  risk_assessment: z.string().max(5000).optional(),
  mitigation_steps: z.string().max(5000).optional(),
  contact_name: z.string().min(1).max(200),
  contact_email: z.string().email().max(100),
  affected_provider_ids: z.array(z.string().uuid()).min(1),
});

export type CreateBreach = z.infer<typeof createBreachSchema>;

// --- Breach Notification: Update ---

export const breachUpdateSchema = z.object({
  content: z.string().min(1).max(10000),
});

export type BreachUpdate = z.infer<typeof breachUpdateSchema>;

// --- Breach Notification: ID Parameter ---

export const breachIdParamSchema = z.object({
  id: z.string().uuid(),
});

export type BreachIdParam = z.infer<typeof breachIdParamSchema>;

// --- Breach Notification: List Query ---

const BREACH_LIST_STATUSES = ['IDENTIFIED', 'NOTIFYING', 'MONITORING', 'RESOLVED'] as const;

export const listBreachesQuerySchema = z.object({
  status: z.enum(BREACH_LIST_STATUSES).optional(),
  page: z.coerce.number().int().min(1).default(1),
  page_size: z.coerce.number().int().min(1).max(100).default(50),
});

export type ListBreachesQuery = z.infer<typeof listBreachesQuerySchema>;

// --- Patient Access Export: Patient ID Parameter ---

export const patientExportParamSchema = z.object({
  id: z.string().uuid(),
});

export type PatientExportParam = z.infer<typeof patientExportParamSchema>;

// --- Patient Correction (extends patient update with mandatory reason) ---

export const patientCorrectionSchema = z
  .object({
    correction_reason: z.string().min(1).max(2000),
    first_name: z.string().min(1).max(50).optional(),
    last_name: z.string().min(1).max(50).optional(),
    middle_name: z.string().max(50).optional(),
    date_of_birth: z.string().date().optional(),
    gender: z.string().length(1).optional(),
    phn: z.string().length(9).optional(),
    phone: z.string().max(24).optional(),
    email: z.string().email().max(100).optional(),
    address_line1: z.string().max(100).optional(),
    address_line2: z.string().max(100).optional(),
    city: z.string().max(50).optional(),
    province: z.string().length(2).optional(),
    postal_code: z.string().max(10).optional(),
    notes: z.string().max(2000).optional(),
  })
  .refine(
    (data) => {
      const { correction_reason: _reason, ...fields } = data;
      return Object.values(fields).some((v) => v !== undefined);
    },
    { message: 'At least one field to correct must be provided' },
  );

export type PatientCorrection = z.infer<typeof patientCorrectionSchema>;

// --- Secondary Email Update ---

export const updateSecondaryEmailSchema = z.object({
  secondary_email: z.string().email().max(100).nullable(),
});

export type UpdateSecondaryEmail = z.infer<typeof updateSecondaryEmailSchema>;

// --- Full HI Export ---

const HI_EXPORT_FORMATS = ['csv', 'json'] as const;

export const fullHiExportSchema = z.object({
  format: z.enum(HI_EXPORT_FORMATS).default('csv'),
});

export type FullHiExport = z.infer<typeof fullHiExportSchema>;
