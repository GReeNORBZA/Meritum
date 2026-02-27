// ============================================================================
// Domain 10: Mobile Companion — Zod Validation Schemas
// ============================================================================

import { z } from 'zod';
import {
  MobileShiftStatus,
  MAX_FAVOURITES,
  ShiftSource,
  PhnCaptureMethod,
  ReconciliationMatchCategory,
} from '../../constants/mobile.constants.js';
import { Gender } from '../../constants/patient.constants.js';

// --- Enum Value Arrays ---

const SHIFT_STATUSES = [
  MobileShiftStatus.ACTIVE,
  MobileShiftStatus.ENDED,
  MobileShiftStatus.REVIEWED,
] as const;

const MOBILE_GENDERS = [Gender.MALE, Gender.FEMALE, Gender.OTHER] as const;

// --- Helpers ---

const isoDateString = z.string().regex(
  /^\d{4}-\d{2}-\d{2}$/,
  'Must be an ISO 8601 date (YYYY-MM-DD)',
);

function notFutureDate(dateStr: string): boolean {
  const date = new Date(dateStr);
  if (isNaN(date.getTime())) return true; // let regex handle format
  const today = new Date();
  today.setHours(23, 59, 59, 999);
  return date <= today;
}

// ============================================================================
// Shift Management
// ============================================================================

// --- Start Shift ---

export const startShiftSchema = z.object({
  location_id: z.string().uuid(),
});

export type StartShift = z.infer<typeof startShiftSchema>;

// --- Shift ID Param ---

export const mobileShiftIdParamSchema = z.object({
  id: z.string().uuid(),
});

export type MobileShiftIdParam = z.infer<typeof mobileShiftIdParamSchema>;

// --- List Shifts Query ---

export const listShiftsQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(50).default(10),
  status: z.enum(SHIFT_STATUSES).optional(),
});

export type ListShiftsQuery = z.infer<typeof listShiftsQuerySchema>;

// ============================================================================
// Shift Patient Logging
// ============================================================================

// --- Log Patient ---

export const logPatientSchema = z
  .object({
    patient_id: z.string().uuid(),
    health_service_code: z.string().min(1).max(10),
    modifiers: z.array(z.string().max(4)).optional(),
    date_of_service: isoDateString.optional(),
    quick_note: z.string().max(500).optional(),
  })
  .refine(
    (data) => !data.date_of_service || notFutureDate(data.date_of_service),
    {
      message: 'date_of_service cannot be in the future',
      path: ['date_of_service'],
    },
  );

export type LogPatient = z.infer<typeof logPatientSchema>;

// ============================================================================
// Favourite Codes
// ============================================================================

// --- Create Favourite ---

export const createFavouriteSchema = z.object({
  health_service_code: z.string().min(1).max(10),
  display_name: z.string().max(100).optional(),
  default_modifiers: z.array(z.string().max(4)).optional(),
  sort_order: z.number().int(),
});

export type CreateFavourite = z.infer<typeof createFavouriteSchema>;

// --- Update Favourite ---

export const updateFavouriteSchema = z
  .object({
    display_name: z.string().max(100).optional(),
    default_modifiers: z.array(z.string().max(4)).optional(),
    sort_order: z.number().int().optional(),
  })
  .refine(
    (data) =>
      data.display_name !== undefined ||
      data.default_modifiers !== undefined ||
      data.sort_order !== undefined,
    { message: 'At least one field must be provided' },
  );

export type UpdateFavourite = z.infer<typeof updateFavouriteSchema>;

// --- Favourite ID Param ---

export const favouriteIdParamSchema = z.object({
  id: z.string().uuid(),
});

export type FavouriteIdParam = z.infer<typeof favouriteIdParamSchema>;

// --- Reorder Favourites ---

export const reorderFavouritesSchema = z.object({
  items: z
    .array(
      z.object({
        favourite_id: z.string().uuid(),
        sort_order: z.number().int(),
      }),
    )
    .min(1)
    .max(MAX_FAVOURITES),
});

export type ReorderFavourites = z.infer<typeof reorderFavouritesSchema>;

// ============================================================================
// Quick Claim Entry
// ============================================================================

// --- Quick Claim ---

export const quickClaimSchema = z
  .object({
    patient_id: z.string().uuid(),
    health_service_code: z.string().min(1).max(10),
    modifiers: z.array(z.string().max(4)).optional(),
    date_of_service: isoDateString.optional(),
  })
  .refine(
    (data) => !data.date_of_service || notFutureDate(data.date_of_service),
    {
      message: 'date_of_service cannot be in the future',
      path: ['date_of_service'],
    },
  );

export type QuickClaim = z.infer<typeof quickClaimSchema>;

// ============================================================================
// Mobile Patient Create (Minimal)
// ============================================================================

// --- Mobile Patient ---

export const mobilePatientSchema = z.object({
  first_name: z.string().min(1).max(100),
  last_name: z.string().min(1).max(100),
  phn: z.string().length(9).regex(/^\d{9}$/, 'PHN must be exactly 9 digits'),
  date_of_birth: isoDateString,
  gender: z.enum(MOBILE_GENDERS),
});

export type MobilePatient = z.infer<typeof mobilePatientSchema>;

// ============================================================================
// Shift Scheduling (FRD MOB-002 §3.1)
// ============================================================================

const SHIFT_SOURCES = [ShiftSource.MANUAL, ShiftSource.INFERRED] as const;

// --- Create Shift Schedule ---

export const createShiftScheduleSchema = z.object({
  location_id: z.string().uuid(),
  name: z.string().min(1).max(100),
  rrule: z.string().min(1).max(500),
  shift_start_time: z.string().regex(
    /^([01]\d|2[0-3]):[0-5]\d$/,
    'Must be HH:mm format',
  ),
  shift_duration_minutes: z.number().int().min(30).max(1440),
});

export type CreateShiftSchedule = z.infer<typeof createShiftScheduleSchema>;

// --- Update Shift Schedule ---

export const updateShiftScheduleSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  rrule: z.string().min(1).max(500).optional(),
  shift_start_time: z.string().regex(
    /^([01]\d|2[0-3]):[0-5]\d$/,
    'Must be HH:mm format',
  ).optional(),
  shift_duration_minutes: z.number().int().min(30).max(1440).optional(),
  is_active: z.boolean().optional(),
});

export type UpdateShiftSchedule = z.infer<typeof updateShiftScheduleSchema>;

// --- Schedule ID Parameter ---

export const scheduleIdParamSchema = z.object({
  id: z.string().uuid(),
});

export type ScheduleIdParam = z.infer<typeof scheduleIdParamSchema>;

// ============================================================================
// Encounter Logging (FRD MOB-002 §4.1)
// ============================================================================

const PHN_CAPTURE_METHODS = [
  PhnCaptureMethod.BARCODE,
  PhnCaptureMethod.SEARCH,
  PhnCaptureMethod.MANUAL,
  PhnCaptureMethod.LAST_FOUR,
] as const;

// --- Log Encounter (enhanced from logPatientSchema) ---

export const logEncounterSchema = z.object({
  phn: z.string().max(9).optional(),
  phn_capture_method: z.enum(PHN_CAPTURE_METHODS),
  phn_is_partial: z.boolean().default(false),
  health_service_code: z.string().min(1).max(10).optional(),
  modifiers: z.array(z.string().max(4)).optional(),
  di_code: z.string().max(10).optional(),
  free_text_tag: z.string().max(100).optional(),
  encounter_timestamp: z.string().datetime().optional(),
});

export type LogEncounter = z.infer<typeof logEncounterSchema>;

// --- Encounter ID Parameter ---

export const encounterIdParamSchema = z.object({
  id: z.string().uuid(),
});

export type EncounterIdParam = z.infer<typeof encounterIdParamSchema>;

// ============================================================================
// Reconciliation (FRD MOB-002 §5.1)
// ============================================================================

const RECONCILIATION_CATEGORIES = [
  ReconciliationMatchCategory.FULL_MATCH,
  ReconciliationMatchCategory.UNMATCHED_SCC,
  ReconciliationMatchCategory.UNMATCHED_ENCOUNTER,
  ReconciliationMatchCategory.SHIFT_ONLY,
] as const;

// --- Reconciliation Query ---

export const reconciliationQuerySchema = z.object({
  shift_id: z.string().uuid(),
  category: z.enum(RECONCILIATION_CATEGORIES).optional(),
});

export type ReconciliationQuery = z.infer<typeof reconciliationQuerySchema>;

// --- Manual Match ---

export const manualMatchSchema = z.object({
  encounter_id: z.string().uuid(),
  claim_id: z.string().uuid(),
});

export type ManualMatch = z.infer<typeof manualMatchSchema>;
