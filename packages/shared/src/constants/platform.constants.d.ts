export declare const SubscriptionPlan: {
    readonly STANDARD_MONTHLY: "STANDARD_MONTHLY";
    readonly STANDARD_ANNUAL: "STANDARD_ANNUAL";
    readonly EARLY_BIRD_MONTHLY: "EARLY_BIRD_MONTHLY";
};
export type SubscriptionPlan = (typeof SubscriptionPlan)[keyof typeof SubscriptionPlan];
export declare const SubscriptionPlanPricing: {
    readonly STANDARD_MONTHLY: {
        readonly plan: "STANDARD_MONTHLY";
        readonly amount: "279.00";
        readonly interval: "month";
        readonly label: "Standard Monthly";
    };
    readonly STANDARD_ANNUAL: {
        readonly plan: "STANDARD_ANNUAL";
        readonly amount: "2790.00";
        readonly interval: "year";
        readonly label: "Standard Annual";
    };
    readonly EARLY_BIRD_MONTHLY: {
        readonly plan: "EARLY_BIRD_MONTHLY";
        readonly amount: "199.00";
        readonly interval: "month";
        readonly label: "Early Bird Monthly";
    };
};
export declare const PaymentStatus: {
    readonly PAID: "PAID";
    readonly FAILED: "FAILED";
    readonly REFUNDED: "REFUNDED";
};
export type PaymentStatus = (typeof PaymentStatus)[keyof typeof PaymentStatus];
export declare const DunningStep: {
    readonly STEP_1: "STEP_1";
    readonly STEP_2: "STEP_2";
    readonly STEP_3: "STEP_3";
    readonly STEP_4: "STEP_4";
    readonly STEP_5: "STEP_5";
};
export type DunningStep = (typeof DunningStep)[keyof typeof DunningStep];
export declare const DunningStepConfig: {
    readonly STEP_1: {
        readonly step: "STEP_1";
        readonly day: 0;
        readonly action: "payment_failed_notification";
        readonly description: "Payment failed notification, Stripe auto-retry in 3 days";
    };
    readonly STEP_2: {
        readonly step: "STEP_2";
        readonly day: 3;
        readonly action: "second_notification";
        readonly description: "Second notification if retry fails";
    };
    readonly STEP_3: {
        readonly step: "STEP_3";
        readonly day: 7;
        readonly action: "suspension_warning";
        readonly description: "Warning: suspension in 7 days";
    };
    readonly STEP_4: {
        readonly step: "STEP_4";
        readonly day: 14;
        readonly action: "account_suspended";
        readonly description: "Account SUSPENDED, submission blocked, read-only access";
    };
    readonly STEP_5: {
        readonly step: "STEP_5";
        readonly day: 30;
        readonly action: "subscription_cancelled";
        readonly description: "Subscription cancelled, 30-day deletion grace period";
    };
};
export declare const StripeWebhookEvent: {
    readonly INVOICE_PAID: "invoice.paid";
    readonly INVOICE_PAYMENT_FAILED: "invoice.payment_failed";
    readonly INVOICE_CREATED: "invoice.created";
    readonly SUBSCRIPTION_UPDATED: "customer.subscription.updated";
    readonly SUBSCRIPTION_DELETED: "customer.subscription.deleted";
    readonly CHECKOUT_SESSION_COMPLETED: "checkout.session.completed";
};
export type StripeWebhookEvent = (typeof StripeWebhookEvent)[keyof typeof StripeWebhookEvent];
export declare const Feature: {
    readonly CLAIM_CREATE: "claim_create";
    readonly CLAIM_VIEW: "claim_view";
    readonly CLAIM_EDIT: "claim_edit";
    readonly BATCH_SUBMIT: "batch_submit";
    readonly PATIENT_CREATE: "patient_create";
    readonly PATIENT_VIEW: "patient_view";
    readonly PATIENT_EDIT: "patient_edit";
    readonly ANALYTICS_VIEW: "analytics_view";
    readonly REPORTS_VIEW: "reports_view";
    readonly REPORTS_EXPORT: "reports_export";
    readonly AI_COACH: "ai_coach";
    readonly SETTINGS_VIEW: "settings_view";
    readonly SETTINGS_EDIT: "settings_edit";
    readonly SETTINGS_PAYMENT: "settings_payment";
    readonly DATA_EXPORT: "data_export";
    readonly DELEGATE_MANAGE: "delegate_manage";
    readonly PROVIDER_EDIT: "provider_edit";
};
export type Feature = (typeof Feature)[keyof typeof Feature];
export declare const FeatureAccessMatrix: Readonly<Record<string, readonly Feature[]>>;
export declare const IncidentStatus: {
    readonly INVESTIGATING: "INVESTIGATING";
    readonly IDENTIFIED: "IDENTIFIED";
    readonly MONITORING: "MONITORING";
    readonly RESOLVED: "RESOLVED";
};
export type IncidentStatus = (typeof IncidentStatus)[keyof typeof IncidentStatus];
export declare const StatusComponent: {
    readonly WEB_APP: "WEB_APP";
    readonly API: "API";
    readonly HLINK_SUBMISSION: "HLINK_SUBMISSION";
    readonly WCB_SUBMISSION: "WCB_SUBMISSION";
    readonly AI_COACH: "AI_COACH";
    readonly EMAIL_DELIVERY: "EMAIL_DELIVERY";
    readonly DATABASE: "DATABASE";
    readonly PAYMENT_PROCESSING: "PAYMENT_PROCESSING";
};
export type StatusComponent = (typeof StatusComponent)[keyof typeof StatusComponent];
export declare const ComponentHealth: {
    readonly OPERATIONAL: "OPERATIONAL";
    readonly DEGRADED: "DEGRADED";
    readonly PARTIAL_OUTAGE: "PARTIAL_OUTAGE";
    readonly MAJOR_OUTAGE: "MAJOR_OUTAGE";
    readonly MAINTENANCE: "MAINTENANCE";
};
export type ComponentHealth = (typeof ComponentHealth)[keyof typeof ComponentHealth];
export declare const GST_RATE = 0.05;
export declare const EARLY_BIRD_CAP = 100;
export declare const DELETION_GRACE_PERIOD_DAYS = 30;
export declare const DUNNING_SUSPENSION_DAY = 14;
export declare const DUNNING_CANCELLATION_DAY = 30;
//# sourceMappingURL=platform.constants.d.ts.map