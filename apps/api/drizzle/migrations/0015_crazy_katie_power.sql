CREATE TABLE "breach_affected_custodians" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"breach_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
	"initial_notified_at" timestamp with time zone,
	"notification_method" varchar(50)
);
--> statement-breakpoint
CREATE TABLE "breach_records" (
	"breach_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"breach_description" text NOT NULL,
	"breach_date" timestamp with time zone NOT NULL,
	"awareness_date" timestamp with time zone NOT NULL,
	"hi_description" text NOT NULL,
	"includes_iihi" boolean NOT NULL,
	"affected_count" integer,
	"risk_assessment" text,
	"mitigation_steps" text,
	"contact_name" varchar(200) NOT NULL,
	"contact_email" varchar(100) NOT NULL,
	"status" varchar(20) DEFAULT 'INVESTIGATING' NOT NULL,
	"evidence_hold_until" timestamp with time zone,
	"created_by" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"resolved_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "breach_updates" (
	"update_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"breach_id" uuid NOT NULL,
	"update_type" varchar(20) NOT NULL,
	"content" text NOT NULL,
	"sent_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by" uuid NOT NULL
);
--> statement-breakpoint
CREATE TABLE "data_destruction_tracking" (
	"tracking_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"provider_id" uuid NOT NULL,
	"active_deleted_at" timestamp with time zone,
	"files_deleted_at" timestamp with time zone,
	"backup_purge_deadline" timestamp with time zone,
	"backup_purged_at" timestamp with time zone,
	"confirmation_sent_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "data_destruction_tracking_provider_id_unique" UNIQUE("provider_id")
);
--> statement-breakpoint
CREATE TABLE "ima_amendment_responses" (
	"response_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"amendment_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
	"response_type" varchar(20) NOT NULL,
	"responded_at" timestamp with time zone DEFAULT now() NOT NULL,
	"ip_address" varchar(45) NOT NULL,
	"user_agent" varchar(500) NOT NULL
);
--> statement-breakpoint
CREATE TABLE "ima_amendments" (
	"amendment_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"amendment_type" varchar(20) NOT NULL,
	"title" text NOT NULL,
	"description" text NOT NULL,
	"document_hash" varchar(64) NOT NULL,
	"notice_date" timestamp with time zone NOT NULL,
	"effective_date" timestamp with time zone NOT NULL,
	"created_by" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "pcpcm_panel_estimates" (
	"estimate_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"provider_id" uuid NOT NULL,
	"enrolment_id" uuid NOT NULL,
	"estimation_method" varchar(30) NOT NULL,
	"estimated_panel_size" integer NOT NULL,
	"unique_patients_12m" integer,
	"confidence" varchar(10),
	"period_start" date NOT NULL,
	"period_end" date NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "pcpcm_payments" (
	"payment_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"provider_id" uuid NOT NULL,
	"enrolment_id" uuid NOT NULL,
	"payment_period_start" date NOT NULL,
	"payment_period_end" date NOT NULL,
	"expected_amount" numeric(10, 2),
	"actual_amount" numeric(10, 2),
	"panel_size_at_payment" integer,
	"status" varchar(20) DEFAULT 'EXPECTED' NOT NULL,
	"reconciled_at" timestamp with time zone,
	"notes" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "referral_codes" DROP CONSTRAINT "referral_codes_physician_user_id_users_user_id_fk";
--> statement-breakpoint
DROP INDEX "referral_codes_physician_user_id_idx";--> statement-breakpoint
ALTER TABLE "referral_codes" ALTER COLUMN "is_active" SET DEFAULT true;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "secondary_email" varchar(100);--> statement-breakpoint
ALTER TABLE "referral_codes" ADD COLUMN "referrer_user_id" uuid NOT NULL;--> statement-breakpoint
ALTER TABLE "referral_redemptions" ADD COLUMN "referrer_user_id" uuid NOT NULL;--> statement-breakpoint
ALTER TABLE "referral_redemptions" ADD COLUMN "status" varchar(20) DEFAULT 'PENDING' NOT NULL;--> statement-breakpoint
ALTER TABLE "referral_redemptions" ADD COLUMN "credit_month_value_cad" numeric(10, 2);--> statement-breakpoint
ALTER TABLE "referral_redemptions" ADD COLUMN "credit_applied_to" varchar(20);--> statement-breakpoint
ALTER TABLE "referral_redemptions" ADD COLUMN "credit_applied_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "referral_redemptions" ADD COLUMN "qualifying_event_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "referral_redemptions" ADD COLUMN "anniversary_year" integer NOT NULL;--> statement-breakpoint
ALTER TABLE "subscriptions" ADD COLUMN "early_bird_locked_until" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "subscriptions" ADD COLUMN "early_bird_expiry_notified" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "breach_affected_custodians" ADD CONSTRAINT "breach_affected_custodians_breach_id_breach_records_breach_id_fk" FOREIGN KEY ("breach_id") REFERENCES "public"."breach_records"("breach_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "breach_affected_custodians" ADD CONSTRAINT "breach_affected_custodians_provider_id_providers_provider_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "breach_records" ADD CONSTRAINT "breach_records_created_by_users_user_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "breach_updates" ADD CONSTRAINT "breach_updates_breach_id_breach_records_breach_id_fk" FOREIGN KEY ("breach_id") REFERENCES "public"."breach_records"("breach_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "breach_updates" ADD CONSTRAINT "breach_updates_created_by_users_user_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "data_destruction_tracking" ADD CONSTRAINT "data_destruction_tracking_provider_id_providers_provider_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ima_amendment_responses" ADD CONSTRAINT "ima_amendment_responses_amendment_id_ima_amendments_amendment_id_fk" FOREIGN KEY ("amendment_id") REFERENCES "public"."ima_amendments"("amendment_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ima_amendment_responses" ADD CONSTRAINT "ima_amendment_responses_provider_id_providers_provider_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ima_amendments" ADD CONSTRAINT "ima_amendments_created_by_users_user_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "pcpcm_panel_estimates" ADD CONSTRAINT "pcpcm_panel_estimates_provider_id_providers_provider_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "pcpcm_panel_estimates" ADD CONSTRAINT "pcpcm_panel_estimates_enrolment_id_pcpcm_enrolments_enrolment_id_fk" FOREIGN KEY ("enrolment_id") REFERENCES "public"."pcpcm_enrolments"("enrolment_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "pcpcm_payments" ADD CONSTRAINT "pcpcm_payments_provider_id_providers_provider_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "pcpcm_payments" ADD CONSTRAINT "pcpcm_payments_enrolment_id_pcpcm_enrolments_enrolment_id_fk" FOREIGN KEY ("enrolment_id") REFERENCES "public"."pcpcm_enrolments"("enrolment_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "breach_affected_breach_idx" ON "breach_affected_custodians" USING btree ("breach_id");--> statement-breakpoint
CREATE UNIQUE INDEX "breach_affected_unique_idx" ON "breach_affected_custodians" USING btree ("breach_id","provider_id");--> statement-breakpoint
CREATE INDEX "breach_records_status_idx" ON "breach_records" USING btree ("status");--> statement-breakpoint
CREATE INDEX "breach_records_awareness_date_idx" ON "breach_records" USING btree ("awareness_date");--> statement-breakpoint
CREATE INDEX "breach_updates_breach_idx" ON "breach_updates" USING btree ("breach_id");--> statement-breakpoint
CREATE INDEX "destruction_tracking_deadline_idx" ON "data_destruction_tracking" USING btree ("backup_purge_deadline");--> statement-breakpoint
CREATE INDEX "ima_responses_amendment_idx" ON "ima_amendment_responses" USING btree ("amendment_id");--> statement-breakpoint
CREATE INDEX "ima_responses_provider_idx" ON "ima_amendment_responses" USING btree ("provider_id");--> statement-breakpoint
CREATE UNIQUE INDEX "ima_responses_unique_idx" ON "ima_amendment_responses" USING btree ("amendment_id","provider_id");--> statement-breakpoint
CREATE INDEX "ima_amendments_type_idx" ON "ima_amendments" USING btree ("amendment_type");--> statement-breakpoint
CREATE INDEX "ima_amendments_effective_date_idx" ON "ima_amendments" USING btree ("effective_date");--> statement-breakpoint
CREATE INDEX "pcpcm_panel_estimates_provider_period_idx" ON "pcpcm_panel_estimates" USING btree ("provider_id","period_end");--> statement-breakpoint
CREATE INDEX "pcpcm_payments_provider_id_idx" ON "pcpcm_payments" USING btree ("provider_id");--> statement-breakpoint
CREATE INDEX "pcpcm_payments_enrolment_id_idx" ON "pcpcm_payments" USING btree ("enrolment_id");--> statement-breakpoint
CREATE INDEX "pcpcm_payments_provider_period_idx" ON "pcpcm_payments" USING btree ("provider_id","payment_period_end");--> statement-breakpoint
CREATE INDEX "pcpcm_payments_status_idx" ON "pcpcm_payments" USING btree ("status");--> statement-breakpoint
ALTER TABLE "referral_codes" ADD CONSTRAINT "referral_codes_referrer_user_id_users_user_id_fk" FOREIGN KEY ("referrer_user_id") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "referral_redemptions" ADD CONSTRAINT "referral_redemptions_referrer_user_id_users_user_id_fk" FOREIGN KEY ("referrer_user_id") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "referral_codes_referrer_user_id_idx" ON "referral_codes" USING btree ("referrer_user_id");--> statement-breakpoint
CREATE INDEX "referral_redemptions_referrer_user_id_idx" ON "referral_redemptions" USING btree ("referrer_user_id");--> statement-breakpoint
CREATE INDEX "referral_redemptions_status_idx" ON "referral_redemptions" USING btree ("status");--> statement-breakpoint
CREATE INDEX "referral_redemptions_referrer_anniversary_idx" ON "referral_redemptions" USING btree ("referrer_user_id","anniversary_year");--> statement-breakpoint
CREATE INDEX "subscriptions_early_bird_locked_until_idx" ON "subscriptions" USING btree ("early_bird_locked_until");--> statement-breakpoint
ALTER TABLE "referral_codes" DROP COLUMN "physician_user_id";--> statement-breakpoint
ALTER TABLE "referral_codes" DROP COLUMN "redemption_count";--> statement-breakpoint
ALTER TABLE "referral_codes" DROP COLUMN "max_redemptions";--> statement-breakpoint
ALTER TABLE "referral_redemptions" DROP COLUMN "credit_amount_cad";--> statement-breakpoint
ALTER TABLE "referral_redemptions" DROP COLUMN "credit_applied";