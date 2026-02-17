CREATE TABLE "incident_updates" (
	"update_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"incident_id" uuid NOT NULL,
	"status" varchar(20) NOT NULL,
	"message" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "payment_history" (
	"payment_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"subscription_id" uuid NOT NULL,
	"stripe_invoice_id" varchar(50) NOT NULL,
	"amount_cad" numeric(10, 2) NOT NULL,
	"gst_amount" numeric(10, 2) NOT NULL,
	"total_cad" numeric(10, 2) NOT NULL,
	"status" varchar(20) NOT NULL,
	"paid_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "referral_codes" (
	"referral_code_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"physician_user_id" uuid NOT NULL,
	"code" varchar(20) NOT NULL,
	"redemption_count" integer DEFAULT 0 NOT NULL,
	"max_redemptions" integer DEFAULT 10 NOT NULL,
	"is_active" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "referral_redemptions" (
	"redemption_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"referral_code_id" uuid NOT NULL,
	"referred_user_id" uuid NOT NULL,
	"credit_amount_cad" numeric(10, 2) DEFAULT '50.00' NOT NULL,
	"credit_applied" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "status_components" (
	"component_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" varchar(50) NOT NULL,
	"display_name" varchar(100) NOT NULL,
	"status" varchar(20) DEFAULT 'operational' NOT NULL,
	"description" text,
	"sort_order" integer DEFAULT 0 NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "status_incidents" (
	"incident_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"title" varchar(200) NOT NULL,
	"status" varchar(20) NOT NULL,
	"severity" varchar(20) NOT NULL,
	"affected_components" jsonb NOT NULL,
	"resolved_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "subscriptions" (
	"subscription_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"provider_id" uuid NOT NULL,
	"stripe_customer_id" varchar(50) NOT NULL,
	"stripe_subscription_id" varchar(50) NOT NULL,
	"plan" varchar(30) NOT NULL,
	"status" varchar(20) DEFAULT 'TRIAL' NOT NULL,
	"current_period_start" timestamp with time zone NOT NULL,
	"current_period_end" timestamp with time zone NOT NULL,
	"trial_end" timestamp with time zone,
	"failed_payment_count" integer DEFAULT 0 NOT NULL,
	"suspended_at" timestamp with time zone,
	"cancelled_at" timestamp with time zone,
	"deletion_scheduled_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "incident_updates" ADD CONSTRAINT "incident_updates_incident_id_status_incidents_incident_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."status_incidents"("incident_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "payment_history" ADD CONSTRAINT "payment_history_subscription_id_subscriptions_subscription_id_fk" FOREIGN KEY ("subscription_id") REFERENCES "public"."subscriptions"("subscription_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "referral_codes" ADD CONSTRAINT "referral_codes_physician_user_id_users_user_id_fk" FOREIGN KEY ("physician_user_id") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "referral_redemptions" ADD CONSTRAINT "referral_redemptions_referral_code_id_referral_codes_referral_code_id_fk" FOREIGN KEY ("referral_code_id") REFERENCES "public"."referral_codes"("referral_code_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "referral_redemptions" ADD CONSTRAINT "referral_redemptions_referred_user_id_users_user_id_fk" FOREIGN KEY ("referred_user_id") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "subscriptions" ADD CONSTRAINT "subscriptions_provider_id_users_user_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "incident_updates_incident_created_idx" ON "incident_updates" USING btree ("incident_id","created_at");--> statement-breakpoint
CREATE INDEX "payment_history_subscription_created_idx" ON "payment_history" USING btree ("subscription_id","created_at");--> statement-breakpoint
CREATE INDEX "payment_history_stripe_invoice_id_idx" ON "payment_history" USING btree ("stripe_invoice_id");--> statement-breakpoint
CREATE UNIQUE INDEX "referral_codes_code_idx" ON "referral_codes" USING btree ("code");--> statement-breakpoint
CREATE INDEX "referral_codes_physician_user_id_idx" ON "referral_codes" USING btree ("physician_user_id");--> statement-breakpoint
CREATE INDEX "referral_redemptions_referral_code_id_idx" ON "referral_redemptions" USING btree ("referral_code_id");--> statement-breakpoint
CREATE INDEX "referral_redemptions_referred_user_id_idx" ON "referral_redemptions" USING btree ("referred_user_id");--> statement-breakpoint
CREATE UNIQUE INDEX "status_components_name_idx" ON "status_components" USING btree ("name");--> statement-breakpoint
CREATE INDEX "status_incidents_status_created_idx" ON "status_incidents" USING btree ("status","created_at");--> statement-breakpoint
CREATE INDEX "status_incidents_created_at_idx" ON "status_incidents" USING btree ("created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "subscriptions_provider_id_idx" ON "subscriptions" USING btree ("provider_id");--> statement-breakpoint
CREATE INDEX "subscriptions_stripe_customer_id_idx" ON "subscriptions" USING btree ("stripe_customer_id");--> statement-breakpoint
CREATE INDEX "subscriptions_stripe_subscription_id_idx" ON "subscriptions" USING btree ("stripe_subscription_id");--> statement-breakpoint
CREATE INDEX "subscriptions_status_idx" ON "subscriptions" USING btree ("status");--> statement-breakpoint
CREATE INDEX "subscriptions_deletion_scheduled_at_idx" ON "subscriptions" USING btree ("deletion_scheduled_at");