// ============================================================================
// Domain 10: Mobile Companion — Zod Validation Schemas
// ============================================================================

import { z } from 'zod';
import { MobileShiftStatus, MAX_FAVOURITES } from '../../constants/mobile.constants.js';
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
