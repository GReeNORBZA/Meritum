CREATE TABLE "ahcip_batches" (
	"ahcip_batch_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"physician_id" uuid NOT NULL,
	"ba_number" varchar(10) NOT NULL,
	"batch_week" date NOT NULL,
	"status" varchar(20) NOT NULL,
	"claim_count" integer NOT NULL,
	"total_submitted_value" numeric(12, 2) NOT NULL,
	"file_path" varchar(255),
	"file_hash" varchar(64),
	"submission_reference" varchar(50),
	"submitted_at" timestamp with time zone,
	"response_received_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by" uuid NOT NULL
);
--> statement-breakpoint
CREATE TABLE "ahcip_claim_details" (
	"ahcip_detail_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"claim_id" uuid NOT NULL,
	"ba_number" varchar(10) NOT NULL,
	"functional_centre" varchar(10) NOT NULL,
	"health_service_code" varchar(10) NOT NULL,
	"modifier_1" varchar(6),
	"modifier_2" varchar(6),
	"modifier_3" varchar(6),
	"diagnostic_code" varchar(8),
	"facility_number" varchar(10),
	"referral_practitioner" varchar(10),
	"encounter_type" varchar(10) NOT NULL,
	"calls" smallint DEFAULT 1 NOT NULL,
	"time_spent" smallint,
	"patient_location" varchar(10),
	"shadow_billing_flag" boolean DEFAULT false NOT NULL,
	"pcpcm_basket_flag" boolean DEFAULT false NOT NULL,
	"after_hours_flag" boolean DEFAULT false NOT NULL,
	"after_hours_type" varchar(20),
	"submitted_fee" numeric(10, 2),
	"assessed_fee" numeric(10, 2),
	"assessment_explanatory_codes" jsonb,
	CONSTRAINT "ahcip_claim_details_claim_id_unique" UNIQUE("claim_id")
);
--> statement-breakpoint
CREATE TABLE "claim_exports" (
	"export_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"physician_id" uuid NOT NULL,
	"date_from" date NOT NULL,
	"date_to" date NOT NULL,
	"claim_type" varchar(10),
	"format" varchar(10) NOT NULL,
	"status" varchar(20) DEFAULT 'PENDING' NOT NULL,
	"file_path" varchar(500),
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "ahcip_batches" ADD CONSTRAINT "ahcip_batches_physician_id_providers_provider_id_fk" FOREIGN KEY ("physician_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ahcip_batches" ADD CONSTRAINT "ahcip_batches_created_by_users_user_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ahcip_claim_details" ADD CONSTRAINT "ahcip_claim_details_claim_id_claims_claim_id_fk" FOREIGN KEY ("claim_id") REFERENCES "public"."claims"("claim_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "claim_exports" ADD CONSTRAINT "claim_exports_physician_id_providers_provider_id_fk" FOREIGN KEY ("physician_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "ahcip_batches_physician_week_idx" ON "ahcip_batches" USING btree ("physician_id","batch_week");--> statement-breakpoint
CREATE INDEX "ahcip_batches_status_idx" ON "ahcip_batches" USING btree ("status");--> statement-breakpoint
CREATE UNIQUE INDEX "ahcip_batches_physician_ba_week_uniq" ON "ahcip_batches" USING btree ("physician_id","ba_number","batch_week");--> statement-breakpoint
CREATE INDEX "ahcip_claim_details_ba_hsc_idx" ON "ahcip_claim_details" USING btree ("ba_number","health_service_code");--> statement-breakpoint
CREATE INDEX "ahcip_claim_details_pcpcm_flag_idx" ON "ahcip_claim_details" USING btree ("pcpcm_basket_flag");--> statement-breakpoint
CREATE INDEX "claim_exports_physician_created_idx" ON "claim_exports" USING btree ("physician_id","created_at");