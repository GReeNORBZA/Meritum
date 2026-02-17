import { z } from 'zod';
export declare const createCheckoutSessionSchema: z.ZodObject<{
    plan: z.ZodEnum<["STANDARD_MONTHLY", "STANDARD_ANNUAL", "EARLY_BIRD_MONTHLY"]>;
    success_url: z.ZodString;
    cancel_url: z.ZodString;
}, "strip", z.ZodTypeAny, {
    plan: "STANDARD_MONTHLY" | "STANDARD_ANNUAL" | "EARLY_BIRD_MONTHLY";
    success_url: string;
    cancel_url: string;
}, {
    plan: "STANDARD_MONTHLY" | "STANDARD_ANNUAL" | "EARLY_BIRD_MONTHLY";
    success_url: string;
    cancel_url: string;
}>;
export type CreateCheckoutSession = z.infer<typeof createCheckoutSessionSchema>;
export declare const createPortalSessionSchema: z.ZodObject<{
    return_url: z.ZodString;
}, "strip", z.ZodTypeAny, {
    return_url: string;
}, {
    return_url: string;
}>;
export type CreatePortalSession = z.infer<typeof createPortalSessionSchema>;
export declare const stripeWebhookHeaderSchema: z.ZodObject<{
    'stripe-signature': z.ZodString;
}, "strip", z.ZodTypeAny, {
    'stripe-signature': string;
}, {
    'stripe-signature': string;
}>;
export type StripeWebhookHeader = z.infer<typeof stripeWebhookHeaderSchema>;
export declare const statusPageQuerySchema: z.ZodObject<{}, "strip", z.ZodTypeAny, {}, {}>;
export type StatusPageQuery = z.infer<typeof statusPageQuerySchema>;
export declare const incidentHistoryQuerySchema: z.ZodObject<{
    page: z.ZodDefault<z.ZodNumber>;
    page_size: z.ZodDefault<z.ZodNumber>;
}, "strip", z.ZodTypeAny, {
    page: number;
    page_size: number;
}, {
    page?: number | undefined;
    page_size?: number | undefined;
}>;
export type IncidentHistoryQuery = z.infer<typeof incidentHistoryQuerySchema>;
export declare const createIncidentSchema: z.ZodObject<{
    title: z.ZodString;
    severity: z.ZodEnum<["minor", "major", "critical"]>;
    affected_components: z.ZodArray<z.ZodString, "many">;
    message: z.ZodString;
}, "strip", z.ZodTypeAny, {
    message: string;
    title: string;
    severity: "minor" | "major" | "critical";
    affected_components: string[];
}, {
    message: string;
    title: string;
    severity: "minor" | "major" | "critical";
    affected_components: string[];
}>;
export type CreateIncident = z.infer<typeof createIncidentSchema>;
export declare const updateIncidentSchema: z.ZodObject<{
    status: z.ZodEnum<["investigating", "identified", "monitoring", "resolved"]>;
    message: z.ZodString;
}, "strip", z.ZodTypeAny, {
    status: "investigating" | "identified" | "monitoring" | "resolved";
    message: string;
}, {
    status: "investigating" | "identified" | "monitoring" | "resolved";
    message: string;
}>;
export type UpdateIncident = z.infer<typeof updateIncidentSchema>;
export declare const updateComponentStatusSchema: z.ZodObject<{
    status: z.ZodEnum<["operational", "degraded", "partial_outage", "major_outage", "maintenance"]>;
}, "strip", z.ZodTypeAny, {
    status: "operational" | "degraded" | "partial_outage" | "major_outage" | "maintenance";
}, {
    status: "operational" | "degraded" | "partial_outage" | "major_outage" | "maintenance";
}>;
export type UpdateComponentStatus = z.infer<typeof updateComponentStatusSchema>;
export declare const adminSubscriptionQuerySchema: z.ZodObject<{
    status: z.ZodOptional<z.ZodEnum<["TRIAL", "ACTIVE", "PAST_DUE", "SUSPENDED", "CANCELLED"]>>;
    page: z.ZodDefault<z.ZodNumber>;
    page_size: z.ZodDefault<z.ZodNumber>;
}, "strip", z.ZodTypeAny, {
    page: number;
    page_size: number;
    status?: "TRIAL" | "ACTIVE" | "PAST_DUE" | "SUSPENDED" | "CANCELLED" | undefined;
}, {
    status?: "TRIAL" | "ACTIVE" | "PAST_DUE" | "SUSPENDED" | "CANCELLED" | undefined;
    page?: number | undefined;
    page_size?: number | undefined;
}>;
export type AdminSubscriptionQuery = z.infer<typeof adminSubscriptionQuerySchema>;
//# sourceMappingURL=platform.schema.d.ts.map