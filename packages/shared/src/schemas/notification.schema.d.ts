import { z } from 'zod';
export declare const notificationFeedQuerySchema: z.ZodObject<{
    unread_only: z.ZodDefault<z.ZodOptional<z.ZodEffects<z.ZodEnum<["true", "false"]>, boolean, "true" | "false">>>;
    limit: z.ZodDefault<z.ZodNumber>;
    offset: z.ZodDefault<z.ZodNumber>;
}, "strip", z.ZodTypeAny, {
    limit: number;
    offset: number;
    unread_only: boolean;
}, {
    limit?: number | undefined;
    offset?: number | undefined;
    unread_only?: "true" | "false" | undefined;
}>;
export type NotificationFeedQuery = z.infer<typeof notificationFeedQuerySchema>;
export declare const notificationIdParamSchema: z.ZodObject<{
    id: z.ZodString;
}, "strip", z.ZodTypeAny, {
    id: string;
}, {
    id: string;
}>;
export type NotificationIdParam = z.infer<typeof notificationIdParamSchema>;
export declare const updatePreferenceSchema: z.ZodObject<{
    in_app_enabled: z.ZodOptional<z.ZodBoolean>;
    email_enabled: z.ZodOptional<z.ZodBoolean>;
    digest_mode: z.ZodOptional<z.ZodEnum<["IMMEDIATE", "DAILY_DIGEST", "WEEKLY_DIGEST"]>>;
}, "strip", z.ZodTypeAny, {
    in_app_enabled?: boolean | undefined;
    email_enabled?: boolean | undefined;
    digest_mode?: "IMMEDIATE" | "DAILY_DIGEST" | "WEEKLY_DIGEST" | undefined;
}, {
    in_app_enabled?: boolean | undefined;
    email_enabled?: boolean | undefined;
    digest_mode?: "IMMEDIATE" | "DAILY_DIGEST" | "WEEKLY_DIGEST" | undefined;
}>;
export type UpdatePreference = z.infer<typeof updatePreferenceSchema>;
export declare const preferenceCategoryParamSchema: z.ZodObject<{
    category: z.ZodString;
}, "strip", z.ZodTypeAny, {
    category: string;
}, {
    category: string;
}>;
export type PreferenceCategoryParam = z.infer<typeof preferenceCategoryParamSchema>;
export declare const quietHoursSchema: z.ZodEffects<z.ZodObject<{
    quiet_hours_start: z.ZodNullable<z.ZodString>;
    quiet_hours_end: z.ZodNullable<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    quiet_hours_start: string | null;
    quiet_hours_end: string | null;
}, {
    quiet_hours_start: string | null;
    quiet_hours_end: string | null;
}>, {
    quiet_hours_start: string | null;
    quiet_hours_end: string | null;
}, {
    quiet_hours_start: string | null;
    quiet_hours_end: string | null;
}>;
export type QuietHours = z.infer<typeof quietHoursSchema>;
export declare const emitEventSchema: z.ZodObject<{
    event_type: z.ZodString;
    physician_id: z.ZodString;
    metadata: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodUnknown>>;
}, "strip", z.ZodTypeAny, {
    event_type: string;
    physician_id: string;
    metadata?: Record<string, unknown> | undefined;
}, {
    event_type: string;
    physician_id: string;
    metadata?: Record<string, unknown> | undefined;
}>;
export type EmitEvent = z.infer<typeof emitEventSchema>;
export declare const emitBatchEventSchema: z.ZodObject<{
    events: z.ZodArray<z.ZodObject<{
        event_type: z.ZodString;
        physician_id: z.ZodString;
        metadata: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodUnknown>>;
    }, "strip", z.ZodTypeAny, {
        event_type: string;
        physician_id: string;
        metadata?: Record<string, unknown> | undefined;
    }, {
        event_type: string;
        physician_id: string;
        metadata?: Record<string, unknown> | undefined;
    }>, "many">;
}, "strip", z.ZodTypeAny, {
    events: {
        event_type: string;
        physician_id: string;
        metadata?: Record<string, unknown> | undefined;
    }[];
}, {
    events: {
        event_type: string;
        physician_id: string;
        metadata?: Record<string, unknown> | undefined;
    }[];
}>;
export type EmitBatchEvent = z.infer<typeof emitBatchEventSchema>;
export declare const notificationResponseSchema: z.ZodObject<{
    notification_id: z.ZodString;
    event_type: z.ZodString;
    priority: z.ZodString;
    title: z.ZodString;
    body: z.ZodString;
    action_url: z.ZodNullable<z.ZodString>;
    action_label: z.ZodNullable<z.ZodString>;
    metadata: z.ZodNullable<z.ZodRecord<z.ZodString, z.ZodUnknown>>;
    channels_delivered: z.ZodObject<{
        in_app: z.ZodBoolean;
        email: z.ZodBoolean;
        push: z.ZodBoolean;
    }, "strip", z.ZodTypeAny, {
        email: boolean;
        push: boolean;
        in_app: boolean;
    }, {
        email: boolean;
        push: boolean;
        in_app: boolean;
    }>;
    read_at: z.ZodNullable<z.ZodString>;
    dismissed_at: z.ZodNullable<z.ZodString>;
    created_at: z.ZodString;
}, "strip", z.ZodTypeAny, {
    body: string;
    created_at: string;
    event_type: string;
    metadata: Record<string, unknown> | null;
    notification_id: string;
    priority: string;
    title: string;
    action_url: string | null;
    action_label: string | null;
    channels_delivered: {
        email: boolean;
        push: boolean;
        in_app: boolean;
    };
    read_at: string | null;
    dismissed_at: string | null;
}, {
    body: string;
    created_at: string;
    event_type: string;
    metadata: Record<string, unknown> | null;
    notification_id: string;
    priority: string;
    title: string;
    action_url: string | null;
    action_label: string | null;
    channels_delivered: {
        email: boolean;
        push: boolean;
        in_app: boolean;
    };
    read_at: string | null;
    dismissed_at: string | null;
}>;
export type NotificationResponse = z.infer<typeof notificationResponseSchema>;
export declare const unreadCountResponseSchema: z.ZodObject<{
    count: z.ZodNumber;
}, "strip", z.ZodTypeAny, {
    count: number;
}, {
    count: number;
}>;
export type UnreadCountResponse = z.infer<typeof unreadCountResponseSchema>;
export declare const preferenceResponseSchema: z.ZodObject<{
    preference_id: z.ZodString;
    event_category: z.ZodString;
    in_app_enabled: z.ZodBoolean;
    email_enabled: z.ZodBoolean;
    digest_mode: z.ZodString;
    quiet_hours_start: z.ZodNullable<z.ZodString>;
    quiet_hours_end: z.ZodNullable<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    in_app_enabled: boolean;
    email_enabled: boolean;
    digest_mode: string;
    quiet_hours_start: string | null;
    quiet_hours_end: string | null;
    preference_id: string;
    event_category: string;
}, {
    in_app_enabled: boolean;
    email_enabled: boolean;
    digest_mode: string;
    quiet_hours_start: string | null;
    quiet_hours_end: string | null;
    preference_id: string;
    event_category: string;
}>;
export type PreferenceResponse = z.infer<typeof preferenceResponseSchema>;
//# sourceMappingURL=notification.schema.d.ts.map