// ============================================================================
// Domain 9: Notification Service — Zod Validation Schemas
// ============================================================================

import { z } from 'zod';
import { DigestMode } from '../constants/notification.constants.js';

// --- Digest Mode Enum Values ---

const DIGEST_MODES = [
  DigestMode.IMMEDIATE,
  DigestMode.DAILY_DIGEST,
  DigestMode.WEEKLY_DIGEST,
] as const;

// ============================================================================
// Notification Feed
// ============================================================================

// --- Feed Query ---

export const notificationFeedQuerySchema = z.object({
  unread_only: z
    .enum(['true', 'false'])
    .transform((v) => v === 'true')
    .optional()
    .default('false'),
  limit: z.coerce.number().int().min(1).max(100).default(20),
  offset: z.coerce.number().int().min(0).default(0),
});

export type NotificationFeedQuery = z.infer<typeof notificationFeedQuerySchema>;

// --- Notification ID Parameter ---

export const notificationIdParamSchema = z.object({
  id: z.string().uuid(),
});

export type NotificationIdParam = z.infer<typeof notificationIdParamSchema>;

// ============================================================================
// Preferences
// ============================================================================

// --- Update Preference (per-category) ---

export const updatePreferenceSchema = z.object({
  in_app_enabled: z.boolean().optional(),
  email_enabled: z.boolean().optional(),
  digest_mode: z.enum(DIGEST_MODES).optional(),
});

export type UpdatePreference = z.infer<typeof updatePreferenceSchema>;

// --- Preference Category Parameter ---

export const preferenceCategoryParamSchema = z.object({
  category: z.string().min(1).max(50),
});

export type PreferenceCategoryParam = z.infer<typeof preferenceCategoryParamSchema>;

// --- Quiet Hours ---
// Both start and end must be set together, or both null to clear.

export const quietHoursSchema = z
  .object({
    quiet_hours_start: z
      .string()
      .regex(/^\d{2}:\d{2}$/, 'Must be in HH:MM format')
      .nullable(),
    quiet_hours_end: z
      .string()
      .regex(/^\d{2}:\d{2}$/, 'Must be in HH:MM format')
      .nullable(),
  })
  .refine(
    (data) =>
      (data.quiet_hours_start === null && data.quiet_hours_end === null) ||
      (data.quiet_hours_start !== null && data.quiet_hours_end !== null),
    {
      message:
        'Both quiet_hours_start and quiet_hours_end must be set together, or both null to clear',
    },
  );

export type QuietHours = z.infer<typeof quietHoursSchema>;

// ============================================================================
// Internal Event Ingestion
// ============================================================================

// --- Single Event ---

export const emitEventSchema = z.object({
  event_type: z.string().min(1).max(50),
  physician_id: z.string().uuid(),
  metadata: z.record(z.string(), z.unknown()).optional(),
});

export type EmitEvent = z.infer<typeof emitEventSchema>;

// --- Batch Events ---

export const emitBatchEventSchema = z.object({
  events: z.array(emitEventSchema).min(1).max(500),
});

export type EmitBatchEvent = z.infer<typeof emitBatchEventSchema>;

// ============================================================================
// Response Schemas
// ============================================================================

// --- Notification Response ---

export const notificationResponseSchema = z.object({
  notification_id: z.string().uuid(),
  event_type: z.string(),
  priority: z.string(),
  title: z.string(),
  body: z.string(),
  action_url: z.string().nullable(),
  action_label: z.string().nullable(),
  metadata: z.record(z.string(), z.unknown()).nullable(),
  channels_delivered: z.object({
    in_app: z.boolean(),
    email: z.boolean(),
    push: z.boolean(),
  }),
  read_at: z.string().nullable(),
  dismissed_at: z.string().nullable(),
  created_at: z.string(),
});

export type NotificationResponse = z.infer<typeof notificationResponseSchema>;

// --- Unread Count Response ---

export const unreadCountResponseSchema = z.object({
  count: z.number().int().min(0),
});

export type UnreadCountResponse = z.infer<typeof unreadCountResponseSchema>;

// --- Preference Response ---

export const preferenceResponseSchema = z.object({
  preference_id: z.string().uuid(),
  event_category: z.string(),
  in_app_enabled: z.boolean(),
  email_enabled: z.boolean(),
  digest_mode: z.string(),
  quiet_hours_start: z.string().nullable(),
  quiet_hours_end: z.string().nullable(),
});

export type PreferenceResponse = z.infer<typeof preferenceResponseSchema>;
