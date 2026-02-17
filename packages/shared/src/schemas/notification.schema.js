"use strict";
// ============================================================================
// Domain 9: Notification Service — Zod Validation Schemas
// ============================================================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.preferenceResponseSchema = exports.unreadCountResponseSchema = exports.notificationResponseSchema = exports.emitBatchEventSchema = exports.emitEventSchema = exports.quietHoursSchema = exports.preferenceCategoryParamSchema = exports.updatePreferenceSchema = exports.notificationIdParamSchema = exports.notificationFeedQuerySchema = void 0;
const zod_1 = require("zod");
const notification_constants_js_1 = require("../constants/notification.constants.js");
// --- Digest Mode Enum Values ---
const DIGEST_MODES = [
    notification_constants_js_1.DigestMode.IMMEDIATE,
    notification_constants_js_1.DigestMode.DAILY_DIGEST,
    notification_constants_js_1.DigestMode.WEEKLY_DIGEST,
];
// ============================================================================
// Notification Feed
// ============================================================================
// --- Feed Query ---
exports.notificationFeedQuerySchema = zod_1.z.object({
    unread_only: zod_1.z
        .enum(['true', 'false'])
        .transform((v) => v === 'true')
        .optional()
        .default('false'),
    limit: zod_1.z.coerce.number().int().min(1).max(100).default(20),
    offset: zod_1.z.coerce.number().int().min(0).default(0),
});
// --- Notification ID Parameter ---
exports.notificationIdParamSchema = zod_1.z.object({
    id: zod_1.z.string().uuid(),
});
// ============================================================================
// Preferences
// ============================================================================
// --- Update Preference (per-category) ---
exports.updatePreferenceSchema = zod_1.z.object({
    in_app_enabled: zod_1.z.boolean().optional(),
    email_enabled: zod_1.z.boolean().optional(),
    digest_mode: zod_1.z.enum(DIGEST_MODES).optional(),
});
// --- Preference Category Parameter ---
exports.preferenceCategoryParamSchema = zod_1.z.object({
    category: zod_1.z.string().min(1).max(50),
});
// --- Quiet Hours ---
// Both start and end must be set together, or both null to clear.
exports.quietHoursSchema = zod_1.z
    .object({
    quiet_hours_start: zod_1.z
        .string()
        .regex(/^\d{2}:\d{2}$/, 'Must be in HH:MM format')
        .nullable(),
    quiet_hours_end: zod_1.z
        .string()
        .regex(/^\d{2}:\d{2}$/, 'Must be in HH:MM format')
        .nullable(),
})
    .refine((data) => (data.quiet_hours_start === null && data.quiet_hours_end === null) ||
    (data.quiet_hours_start !== null && data.quiet_hours_end !== null), {
    message: 'Both quiet_hours_start and quiet_hours_end must be set together, or both null to clear',
});
// ============================================================================
// Internal Event Ingestion
// ============================================================================
// --- Single Event ---
exports.emitEventSchema = zod_1.z.object({
    event_type: zod_1.z.string().min(1).max(50),
    physician_id: zod_1.z.string().uuid(),
    metadata: zod_1.z.record(zod_1.z.string(), zod_1.z.unknown()).optional(),
});
// --- Batch Events ---
exports.emitBatchEventSchema = zod_1.z.object({
    events: zod_1.z.array(exports.emitEventSchema).min(1).max(500),
});
// ============================================================================
// Response Schemas
// ============================================================================
// --- Notification Response ---
exports.notificationResponseSchema = zod_1.z.object({
    notification_id: zod_1.z.string().uuid(),
    event_type: zod_1.z.string(),
    priority: zod_1.z.string(),
    title: zod_1.z.string(),
    body: zod_1.z.string(),
    action_url: zod_1.z.string().nullable(),
    action_label: zod_1.z.string().nullable(),
    metadata: zod_1.z.record(zod_1.z.string(), zod_1.z.unknown()).nullable(),
    channels_delivered: zod_1.z.object({
        in_app: zod_1.z.boolean(),
        email: zod_1.z.boolean(),
        push: zod_1.z.boolean(),
    }),
    read_at: zod_1.z.string().nullable(),
    dismissed_at: zod_1.z.string().nullable(),
    created_at: zod_1.z.string(),
});
// --- Unread Count Response ---
exports.unreadCountResponseSchema = zod_1.z.object({
    count: zod_1.z.number().int().min(0),
});
// --- Preference Response ---
exports.preferenceResponseSchema = zod_1.z.object({
    preference_id: zod_1.z.string().uuid(),
    event_category: zod_1.z.string(),
    in_app_enabled: zod_1.z.boolean(),
    email_enabled: zod_1.z.boolean(),
    digest_mode: zod_1.z.string(),
    quiet_hours_start: zod_1.z.string().nullable(),
    quiet_hours_end: zod_1.z.string().nullable(),
});
//# sourceMappingURL=notification.schema.js.map