CREATE TABLE "business_arrangements" (
	"ba_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"provider_id" uuid NOT NULL,
	"ba_number" varchar(10) NOT NULL,
	"ba_type" varchar(10) NOT NULL,
	"is_primary" boolean NOT NULL,
	"status" varchar(20) DEFAULT 'PENDING' NOT NULL,
	"effective_date" date,
	"end_date" date,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "delegate_relationships" (
	"relationship_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"physician_id" uuid NOT NULL,
	"delegate_user_id" uuid NOT NULL,
	"permissions" jsonb NOT NULL,
	"status" varchar(20) DEFAULT 'INVITED' NOT NULL,
	"invited_at" timestamp with time zone NOT NULL,
	"accepted_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	"revoked_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "hlink_configurations" (
	"hlink_config_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"provider_id" uuid NOT NULL,
	"submitter_prefix" varchar(10) NOT NULL,
	"credential_secret_ref" varchar(100) NOT NULL,
	"accreditation_status" varchar(20) DEFAULT 'PENDING' NOT NULL,
	"accreditation_date" date,
	"last_successful_transmission" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "hlink_configurations_provider_id_unique" UNIQUE("provider_id")
);
--> statement-breakpoint
CREATE TABLE "pcpcm_enrolments" (
	"enrolment_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"provider_id" uuid NOT NULL,
	"pcpcm_ba_id" uuid NOT NULL,
	"ffs_ba_id" uuid NOT NULL,
	"panel_size" integer,
	"enrolment_date" date NOT NULL,
	"status" varchar(20) DEFAULT 'PENDING' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "practice_locations" (
	"location_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"provider_id" uuid NOT NULL,
	"name" varchar(100) NOT NULL,
	"functional_centre" varchar(10) NOT NULL,
	"facility_number" varchar(10),
	"address_line_1" varchar(100),
	"address_line_2" varchar(100),
	"city" varchar(50),
	"province" varchar(2) DEFAULT 'AB',
	"postal_code" varchar(7),
	"community_code" varchar(10),
	"rrnp_eligible" boolean DEFAULT false NOT NULL,
	"rrnp_rate" numeric(8, 2),
	"is_default" boolean DEFAULT false NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "providers" (
	"provider_id" uuid PRIMARY KEY NOT NULL,
	"billing_number" varchar(10) NOT NULL,
	"cpsa_registration_number" varchar(10) NOT NULL,
	"first_name" varchar(50) NOT NULL,
	"middle_name" varchar(50),
	"last_name" varchar(50) NOT NULL,
	"specialty_code" varchar(10) NOT NULL,
	"specialty_description" varchar(100),
	"sub_specialty_code" varchar(10),
	"physician_type" varchar(20) NOT NULL,
	"status" varchar(20) DEFAULT 'ACTIVE' NOT NULL,
	"onboarding_completed" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "submission_preferences" (
	"preference_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"provider_id" uuid NOT NULL,
	"ahcip_submission_mode" varchar(20) DEFAULT 'AUTO_CLEAN' NOT NULL,
	"wcb_submission_mode" varchar(20) DEFAULT 'REQUIRE_APPROVAL' NOT NULL,
	"batch_review_reminder" boolean DEFAULT true NOT NULL,
	"deadline_reminder_days" integer DEFAULT 7 NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_by" uuid NOT NULL,
	CONSTRAINT "submission_preferences_provider_id_unique" UNIQUE("provider_id")
);
--> statement-breakpoint
CREATE TABLE "wcb_configurations" (
	"wcb_config_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"provider_id" uuid NOT NULL,
	"contract_id" varchar(10) NOT NULL,
	"role_code" varchar(10) NOT NULL,
	"skill_code" varchar(10),
	"permitted_form_types" jsonb NOT NULL,
	"is_default" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "business_arrangements" ADD CONSTRAINT "business_arrangements_provider_id_providers_provider_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "delegate_relationships" ADD CONSTRAINT "delegate_relationships_physician_id_providers_provider_id_fk" FOREIGN KEY ("physician_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "delegate_relationships" ADD CONSTRAINT "delegate_relationships_delegate_user_id_users_user_id_fk" FOREIGN KEY ("delegate_user_id") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "delegate_relationships" ADD CONSTRAINT "delegate_relationships_revoked_by_users_user_id_fk" FOREIGN KEY ("revoked_by") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hlink_configurations" ADD CONSTRAINT "hlink_configurations_provider_id_providers_provider_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "pcpcm_enrolments" ADD CONSTRAINT "pcpcm_enrolments_provider_id_providers_provider_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "pcpcm_enrolments" ADD CONSTRAINT "pcpcm_enrolments_pcpcm_ba_id_business_arrangements_ba_id_fk" FOREIGN KEY ("pcpcm_ba_id") REFERENCES "public"."business_arrangements"("ba_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "pcpcm_enrolments" ADD CONSTRAINT "pcpcm_enrolments_ffs_ba_id_business_arrangements_ba_id_fk" FOREIGN KEY ("ffs_ba_id") REFERENCES "public"."business_arrangements"("ba_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "practice_locations" ADD CONSTRAINT "practice_locations_provider_id_providers_provider_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "providers" ADD CONSTRAINT "providers_provider_id_users_user_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "submission_preferences" ADD CONSTRAINT "submission_preferences_provider_id_providers_provider_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "submission_preferences" ADD CONSTRAINT "submission_preferences_updated_by_users_user_id_fk" FOREIGN KEY ("updated_by") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wcb_configurations" ADD CONSTRAINT "wcb_configurations_provider_id_providers_provider_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "ba_provider_id_status_idx" ON "business_arrangements" USING btree ("provider_id","status");--> statement-breakpoint
CREATE UNIQUE INDEX "ba_number_active_unique_idx" ON "business_arrangements" USING btree ("ba_number") WHERE status != 'INACTIVE';--> statement-breakpoint
CREATE INDEX "delegate_relationships_physician_status_idx" ON "delegate_relationships" USING btree ("physician_id","status");--> statement-breakpoint
CREATE INDEX "delegate_relationships_delegate_status_idx" ON "delegate_relationships" USING btree ("delegate_user_id","status");--> statement-breakpoint
CREATE UNIQUE INDEX "delegate_relationships_active_unique_idx" ON "delegate_relationships" USING btree ("physician_id","delegate_user_id") WHERE status != 'REVOKED';--> statement-breakpoint
CREATE INDEX "pcpcm_enrolments_provider_id_status_idx" ON "pcpcm_enrolments" USING btree ("provider_id","status");--> statement-breakpoint
CREATE UNIQUE INDEX "pcpcm_enrolments_one_active_per_provider_idx" ON "pcpcm_enrolments" USING btree ("provider_id") WHERE status != 'WITHDRAWN';--> statement-breakpoint
CREATE INDEX "practice_locations_provider_id_is_active_idx" ON "practice_locations" USING btree ("provider_id","is_active");--> statement-breakpoint
CREATE INDEX "practice_locations_provider_id_is_default_idx" ON "practice_locations" USING btree ("provider_id","is_default");--> statement-breakpoint
CREATE UNIQUE INDEX "providers_billing_number_idx" ON "providers" USING btree ("billing_number");--> statement-breakpoint
CREATE UNIQUE INDEX "providers_cpsa_registration_number_idx" ON "providers" USING btree ("cpsa_registration_number");--> statement-breakpoint
CREATE INDEX "providers_specialty_code_idx" ON "providers" USING btree ("specialty_code");--> statement-breakpoint
CREATE INDEX "providers_status_idx" ON "providers" USING btree ("status");--> statement-breakpoint
CREATE INDEX "wcb_configurations_provider_id_idx" ON "wcb_configurations" USING btree ("provider_id");--> statement-breakpoint
CREATE UNIQUE INDEX "wcb_configurations_provider_contract_idx" ON "wcb_configurations" USING btree ("provider_id","contract_id");