"use strict";
// ============================================================================
// Domain 12: Platform Operations — Zod Validation Schemas
// ============================================================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.adminSubscriptionQuerySchema = exports.updateComponentStatusSchema = exports.updateIncidentSchema = exports.createIncidentSchema = exports.incidentHistoryQuerySchema = exports.statusPageQuerySchema = exports.stripeWebhookHeaderSchema = exports.createPortalSessionSchema = exports.createCheckoutSessionSchema = void 0;
const zod_1 = require("zod");
const platform_constants_js_1 = require("../constants/platform.constants.js");
const iam_constants_js_1 = require("../constants/iam.constants.js");
// --- Subscription: Checkout Session ---
exports.createCheckoutSessionSchema = zod_1.z.object({
    plan: zod_1.z.enum([
        platform_constants_js_1.SubscriptionPlan.STANDARD_MONTHLY,
        platform_constants_js_1.SubscriptionPlan.STANDARD_ANNUAL,
        platform_constants_js_1.SubscriptionPlan.EARLY_BIRD_MONTHLY,
    ]),
    success_url: zod_1.z.string().url(),
    cancel_url: zod_1.z.string().url(),
});
// --- Subscription: Customer Portal Session ---
exports.createPortalSessionSchema = zod_1.z.object({
    return_url: zod_1.z.string().url(),
});
// --- Webhook: Stripe Signature Header ---
exports.stripeWebhookHeaderSchema = zod_1.z.object({
    'stripe-signature': zod_1.z.string(),
});
// --- Status Page: Public Query (no required fields) ---
exports.statusPageQuerySchema = zod_1.z.object({});
// --- Status Page: Incident History Query ---
exports.incidentHistoryQuerySchema = zod_1.z.object({
    page: zod_1.z.coerce.number().int().min(1).default(1),
    page_size: zod_1.z.coerce.number().int().min(1).max(50).default(20),
});
// --- Admin: Create Incident ---
const INCIDENT_SEVERITY = ['minor', 'major', 'critical'];
exports.createIncidentSchema = zod_1.z.object({
    title: zod_1.z.string().min(1).max(200),
    severity: zod_1.z.enum(INCIDENT_SEVERITY),
    affected_components: zod_1.z.array(zod_1.z.string().uuid()).min(1),
    message: zod_1.z.string().min(1),
});
// --- Admin: Update Incident ---
const INCIDENT_UPDATE_STATUS = [
    'investigating',
    'identified',
    'monitoring',
    'resolved',
];
exports.updateIncidentSchema = zod_1.z.object({
    status: zod_1.z.enum(INCIDENT_UPDATE_STATUS),
    message: zod_1.z.string().min(1),
});
// --- Admin: Update Component Status ---
const COMPONENT_STATUS = [
    'operational',
    'degraded',
    'partial_outage',
    'major_outage',
    'maintenance',
];
exports.updateComponentStatusSchema = zod_1.z.object({
    status: zod_1.z.enum(COMPONENT_STATUS),
});
// --- Admin: Subscription Query ---
const SUBSCRIPTION_STATUSES = [
    iam_constants_js_1.SubscriptionStatus.TRIAL,
    iam_constants_js_1.SubscriptionStatus.ACTIVE,
    iam_constants_js_1.SubscriptionStatus.PAST_DUE,
    iam_constants_js_1.SubscriptionStatus.SUSPENDED,
    iam_constants_js_1.SubscriptionStatus.CANCELLED,
];
exports.adminSubscriptionQuerySchema = zod_1.z.object({
    status: zod_1.z.enum(SUBSCRIPTION_STATUSES).optional(),
    page: zod_1.z.coerce.number().int().min(1).default(1),
    page_size: zod_1.z.coerce.number().int().min(1).max(100).default(50),
});
//# sourceMappingURL=platform.schema.js.map