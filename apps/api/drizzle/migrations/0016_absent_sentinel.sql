CREATE TABLE "claim_justifications" (
	"justification_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"claim_id" uuid NOT NULL,
	"physician_id" uuid NOT NULL,
	"scenario" varchar(40) NOT NULL,
	"justification_text" text NOT NULL,
	"template_id" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by" uuid NOT NULL
);
--> statement-breakpoint
CREATE TABLE "claim_templates" (
	"template_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"physician_id" uuid NOT NULL,
	"name" varchar(100) NOT NULL,
	"description" text,
	"template_type" varchar(30) NOT NULL,
	"claim_type" varchar(10) NOT NULL,
	"line_items" jsonb NOT NULL,
	"specialty_code" varchar(10),
	"usage_count" integer DEFAULT 0 NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "recent_referrers" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"physician_id" uuid NOT NULL,
	"referrer_cpsa" varchar(10) NOT NULL,
	"referrer_name" varchar(100) NOT NULL,
	"use_count" integer DEFAULT 1 NOT NULL,
	"last_used_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "ed_shift_encounters" (
	"encounter_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"shift_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
	"phn" varchar(9),
	"phn_capture_method" varchar(20) NOT NULL,
	"phn_is_partial" boolean DEFAULT false NOT NULL,
	"health_service_code" varchar(10),
	"modifiers" jsonb,
	"di_code" varchar(10),
	"free_text_tag" varchar(100),
	"matched_claim_id" uuid,
	"encounter_timestamp" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "shift_schedules" (
	"schedule_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"provider_id" uuid NOT NULL,
	"location_id" uuid NOT NULL,
	"name" varchar(100) NOT NULL,
	"rrule" text NOT NULL,
	"shift_start_time" varchar(5) NOT NULL,
	"shift_duration_minutes" integer NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"last_expanded_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "eligibility_cache" (
	"cache_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"provider_id" uuid NOT NULL,
	"phn_hash" varchar(64) NOT NULL,
	"is_eligible" boolean NOT NULL,
	"eligibility_details" jsonb,
	"verified_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "ba_facility_mappings" (
	"mapping_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"ba_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
	"functional_centre" varchar(10) NOT NULL,
	"priority" integer DEFAULT 0 NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "ba_schedule_mappings" (
	"mapping_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"ba_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
	"day_of_week" integer NOT NULL,
	"start_time" varchar(5) NOT NULL,
	"end_time" varchar(5) NOT NULL,
	"priority" integer DEFAULT 0 NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "anesthesia_rules" (
	"rule_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"scenario_code" varchar(30) NOT NULL,
	"scenario_label" varchar(100) NOT NULL,
	"description" text NOT NULL,
	"base_units" integer,
	"time_unit_minutes" integer,
	"calculation_formula" text NOT NULL,
	"applicable_modifiers" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"source_reference" varchar(100),
	"sort_order" integer DEFAULT 0 NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "billing_guidance" (
	"guidance_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"category" varchar(30) NOT NULL,
	"title" varchar(200) NOT NULL,
	"content" text NOT NULL,
	"applicable_specialties" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"applicable_hsc_codes" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"source_reference" varchar(200),
	"source_url" text,
	"sort_order" integer DEFAULT 0 NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "bundling_rules" (
	"rule_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"code_a" varchar(10) NOT NULL,
	"code_b" varchar(10) NOT NULL,
	"relationship" varchar(30) NOT NULL,
	"description" text,
	"override_allowed" boolean DEFAULT false NOT NULL,
	"source_reference" varchar(100),
	"is_active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "hsc_modifier_eligibility" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"hsc_code" varchar(10) NOT NULL,
	"modifier_type" varchar(10) NOT NULL,
	"sub_code" varchar(20) NOT NULL,
	"calls" varchar(20),
	"explicit" boolean DEFAULT false NOT NULL,
	"action" varchar(50) NOT NULL,
	"amount" varchar(20) NOT NULL,
	"version_id" uuid NOT NULL,
	"effective_from" date NOT NULL,
	"effective_to" date
);
--> statement-breakpoint
CREATE TABLE "icd_crosswalk" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"icd10_code" varchar(10) NOT NULL,
	"icd10_description" text NOT NULL,
	"icd9_code" varchar(10) NOT NULL,
	"icd9_description" text NOT NULL,
	"match_quality" varchar(20) NOT NULL,
	"is_preferred" boolean DEFAULT false NOT NULL,
	"notes" text,
	"version_id" uuid NOT NULL,
	"effective_from" date NOT NULL,
	"effective_to" date
);
--> statement-breakpoint
CREATE TABLE "justification_templates" (
	"template_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"scenario" varchar(40) NOT NULL,
	"name" varchar(200) NOT NULL,
	"template_text" text NOT NULL,
	"placeholders" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"applicable_specialties" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"sort_order" integer DEFAULT 0 NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "provider_registry" (
	"registry_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"cpsa" varchar(10) NOT NULL,
	"first_name" varchar(50) NOT NULL,
	"last_name" varchar(50) NOT NULL,
	"specialty_code" varchar(10) NOT NULL,
	"specialty_description" varchar(100),
	"city" varchar(100),
	"facility_name" varchar(200),
	"phone" varchar(24),
	"fax" varchar(24),
	"is_active" boolean DEFAULT true NOT NULL,
	"last_synced_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "provincial_phn_formats" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"province_code" varchar(2) NOT NULL,
	"province_name" varchar(50) NOT NULL,
	"phn_length" integer NOT NULL,
	"phn_regex" varchar(100) NOT NULL,
	"validation_algorithm" varchar(30),
	"notes" text
);
--> statement-breakpoint
CREATE TABLE "reciprocal_billing_rules" (
	"rule_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"source_province" varchar(2) NOT NULL,
	"claim_type" varchar(10) NOT NULL,
	"submission_method" varchar(30) NOT NULL,
	"fee_schedule_source" varchar(30) NOT NULL,
	"deadline_days" integer NOT NULL,
	"notes" text,
	"is_active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
DROP INDEX "hsc_codes_hsc_code_version_id_idx";--> statement-breakpoint
ALTER TABLE "claims" ADD COLUMN "raw_file_reference" varchar(500);--> statement-breakpoint
ALTER TABLE "claims" ADD COLUMN "scc_charge_status" varchar(20);--> statement-breakpoint
ALTER TABLE "claims" ADD COLUMN "icd_conversion_flag" boolean DEFAULT false;--> statement-breakpoint
ALTER TABLE "claims" ADD COLUMN "icd10_source_code" varchar(10);--> statement-breakpoint
ALTER TABLE "claims" ADD COLUMN "routing_ba_id" uuid;--> statement-breakpoint
ALTER TABLE "claims" ADD COLUMN "routing_reason" varchar(30);--> statement-breakpoint
ALTER TABLE "import_batches" ADD COLUMN "import_source" varchar(30);--> statement-breakpoint
ALTER TABLE "import_batches" ADD COLUMN "scc_spec_version" varchar(20);--> statement-breakpoint
ALTER TABLE "import_batches" ADD COLUMN "raw_row_count" integer;--> statement-breakpoint
ALTER TABLE "import_batches" ADD COLUMN "valid_row_count" integer;--> statement-breakpoint
ALTER TABLE "import_batches" ADD COLUMN "warning_count" integer;--> statement-breakpoint
ALTER TABLE "import_batches" ADD COLUMN "duplicate_count" integer;--> statement-breakpoint
ALTER TABLE "import_batches" ADD COLUMN "confirmation_status" varchar(20);--> statement-breakpoint
ALTER TABLE "import_batches" ADD COLUMN "confirmed_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "import_batches" ADD COLUMN "confirmed_by" uuid;--> statement-breakpoint
ALTER TABLE "ai_provider_learning" ADD COLUMN "auto_applied_count" integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE "ai_provider_learning" ADD COLUMN "pre_applied_count" integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE "ai_provider_learning" ADD COLUMN "pre_applied_removed_count" integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE "ai_rules" ADD COLUMN "is_bedside_contingent" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "ai_rules" ADD COLUMN "confidence_tier_overrides" jsonb;--> statement-breakpoint
ALTER TABLE "ed_shifts" ADD COLUMN "shift_source" varchar(20) DEFAULT 'MANUAL' NOT NULL;--> statement-breakpoint
ALTER TABLE "ed_shifts" ADD COLUMN "inferred_confirmed" boolean DEFAULT false;--> statement-breakpoint
ALTER TABLE "ed_shifts" ADD COLUMN "schedule_id" uuid;--> statement-breakpoint
ALTER TABLE "data_destruction_tracking" ADD COLUMN "last_known_email" varchar(320);--> statement-breakpoint
ALTER TABLE "business_arrangements" ADD COLUMN "ba_subtype" varchar(20);--> statement-breakpoint
ALTER TABLE "providers" ADD COLUMN "is_connect_care_user" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "providers" ADD COLUMN "connect_care_enabled_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "governing_rules" ADD COLUMN "description_html" text;--> statement-breakpoint
ALTER TABLE "hsc_codes" ADD COLUMN "category" varchar(100);--> statement-breakpoint
ALTER TABLE "hsc_codes" ADD COLUMN "governing_rule_references" jsonb DEFAULT '[]'::jsonb NOT NULL;--> statement-breakpoint
ALTER TABLE "hsc_codes" ADD COLUMN "self_referral_blocked" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "hsc_codes" ADD COLUMN "age_restriction" jsonb;--> statement-breakpoint
ALTER TABLE "hsc_codes" ADD COLUMN "frequency_restriction" jsonb;--> statement-breakpoint
ALTER TABLE "hsc_codes" ADD COLUMN "requires_anesthesia" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "hsc_codes" ADD COLUMN "facility_designation" varchar(20);--> statement-breakpoint
ALTER TABLE "hsc_codes" ADD COLUMN "billing_tips" text;--> statement-breakpoint
ALTER TABLE "hsc_codes" ADD COLUMN "common_terms" jsonb DEFAULT '[]'::jsonb NOT NULL;--> statement-breakpoint
ALTER TABLE "claim_justifications" ADD CONSTRAINT "claim_justifications_claim_id_claims_claim_id_fk" FOREIGN KEY ("claim_id") REFERENCES "public"."claims"("claim_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "claim_justifications" ADD CONSTRAINT "claim_justifications_physician_id_providers_provider_id_fk" FOREIGN KEY ("physician_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "claim_justifications" ADD CONSTRAINT "claim_justifications_created_by_users_user_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "claim_templates" ADD CONSTRAINT "claim_templates_physician_id_providers_provider_id_fk" FOREIGN KEY ("physician_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "recent_referrers" ADD CONSTRAINT "recent_referrers_physician_id_providers_provider_id_fk" FOREIGN KEY ("physician_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ed_shift_encounters" ADD CONSTRAINT "ed_shift_encounters_shift_id_ed_shifts_shift_id_fk" FOREIGN KEY ("shift_id") REFERENCES "public"."ed_shifts"("shift_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ed_shift_encounters" ADD CONSTRAINT "ed_shift_encounters_provider_id_providers_provider_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ed_shift_encounters" ADD CONSTRAINT "ed_shift_encounters_matched_claim_id_claims_claim_id_fk" FOREIGN KEY ("matched_claim_id") REFERENCES "public"."claims"("claim_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "shift_schedules" ADD CONSTRAINT "shift_schedules_provider_id_providers_provider_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "shift_schedules" ADD CONSTRAINT "shift_schedules_location_id_practice_locations_location_id_fk" FOREIGN KEY ("location_id") REFERENCES "public"."practice_locations"("location_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "eligibility_cache" ADD CONSTRAINT "eligibility_cache_provider_id_providers_provider_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ba_facility_mappings" ADD CONSTRAINT "ba_facility_mappings_ba_id_business_arrangements_ba_id_fk" FOREIGN KEY ("ba_id") REFERENCES "public"."business_arrangements"("ba_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ba_facility_mappings" ADD CONSTRAINT "ba_facility_mappings_provider_id_providers_provider_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ba_schedule_mappings" ADD CONSTRAINT "ba_schedule_mappings_ba_id_business_arrangements_ba_id_fk" FOREIGN KEY ("ba_id") REFERENCES "public"."business_arrangements"("ba_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ba_schedule_mappings" ADD CONSTRAINT "ba_schedule_mappings_provider_id_providers_provider_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hsc_modifier_eligibility" ADD CONSTRAINT "hsc_modifier_eligibility_version_id_reference_data_versions_version_id_fk" FOREIGN KEY ("version_id") REFERENCES "public"."reference_data_versions"("version_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hsc_modifier_eligibility" ADD CONSTRAINT "hsc_modifier_eligibility_hsc_code_version_id_hsc_codes_hsc_code_version_id_fk" FOREIGN KEY ("hsc_code","version_id") REFERENCES "public"."hsc_codes"("hsc_code","version_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "icd_crosswalk" ADD CONSTRAINT "icd_crosswalk_version_id_reference_data_versions_version_id_fk" FOREIGN KEY ("version_id") REFERENCES "public"."reference_data_versions"("version_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "claim_justifications_claim_idx" ON "claim_justifications" USING btree ("claim_id");--> statement-breakpoint
CREATE INDEX "claim_justifications_physician_scenario_idx" ON "claim_justifications" USING btree ("physician_id","scenario");--> statement-breakpoint
CREATE INDEX "claim_templates_physician_active_idx" ON "claim_templates" USING btree ("physician_id","is_active");--> statement-breakpoint
CREATE INDEX "claim_templates_specialty_type_idx" ON "claim_templates" USING btree ("specialty_code","template_type");--> statement-breakpoint
CREATE UNIQUE INDEX "recent_referrers_physician_cpsa_unique_idx" ON "recent_referrers" USING btree ("physician_id","referrer_cpsa");--> statement-breakpoint
CREATE INDEX "recent_referrers_physician_last_used_idx" ON "recent_referrers" USING btree ("physician_id","last_used_at");--> statement-breakpoint
CREATE INDEX "ed_shift_encounters_shift_idx" ON "ed_shift_encounters" USING btree ("shift_id");--> statement-breakpoint
CREATE INDEX "ed_shift_encounters_provider_created_idx" ON "ed_shift_encounters" USING btree ("provider_id","created_at");--> statement-breakpoint
CREATE INDEX "ed_shift_encounters_phn_idx" ON "ed_shift_encounters" USING btree ("phn");--> statement-breakpoint
CREATE INDEX "ed_shift_encounters_matched_claim_idx" ON "ed_shift_encounters" USING btree ("matched_claim_id");--> statement-breakpoint
CREATE INDEX "shift_schedules_provider_active_idx" ON "shift_schedules" USING btree ("provider_id","is_active");--> statement-breakpoint
CREATE UNIQUE INDEX "eligibility_cache_provider_phn_hash_idx" ON "eligibility_cache" USING btree ("provider_id","phn_hash");--> statement-breakpoint
CREATE INDEX "eligibility_cache_expires_at_idx" ON "eligibility_cache" USING btree ("expires_at");--> statement-breakpoint
CREATE UNIQUE INDEX "ba_facility_mappings_ba_fc_unique_idx" ON "ba_facility_mappings" USING btree ("ba_id","functional_centre");--> statement-breakpoint
CREATE INDEX "ba_facility_mappings_provider_active_idx" ON "ba_facility_mappings" USING btree ("provider_id","is_active");--> statement-breakpoint
CREATE INDEX "ba_schedule_mappings_provider_active_idx" ON "ba_schedule_mappings" USING btree ("provider_id","is_active");--> statement-breakpoint
CREATE INDEX "ba_schedule_mappings_ba_day_idx" ON "ba_schedule_mappings" USING btree ("ba_id","day_of_week");--> statement-breakpoint
CREATE UNIQUE INDEX "anesthesia_rules_scenario_unique_idx" ON "anesthesia_rules" USING btree ("scenario_code");--> statement-breakpoint
CREATE INDEX "anesthesia_rules_active_sort_idx" ON "anesthesia_rules" USING btree ("is_active","sort_order");--> statement-breakpoint
CREATE INDEX "billing_guidance_category_active_idx" ON "billing_guidance" USING btree ("category","is_active");--> statement-breakpoint
CREATE INDEX "billing_guidance_content_gin_idx" ON "billing_guidance" USING gin (to_tsvector('english', "content"));--> statement-breakpoint
CREATE UNIQUE INDEX "bundling_rules_code_pair_unique_idx" ON "bundling_rules" USING btree ("code_a","code_b");--> statement-breakpoint
CREATE INDEX "bundling_rules_code_a_active_idx" ON "bundling_rules" USING btree ("code_a","is_active");--> statement-breakpoint
CREATE INDEX "bundling_rules_code_b_active_idx" ON "bundling_rules" USING btree ("code_b","is_active");--> statement-breakpoint
CREATE INDEX "hsc_modifier_elig_hsc_code_version_id_idx" ON "hsc_modifier_eligibility" USING btree ("hsc_code","version_id");--> statement-breakpoint
CREATE INDEX "hsc_modifier_elig_type_version_id_idx" ON "hsc_modifier_eligibility" USING btree ("modifier_type","version_id");--> statement-breakpoint
CREATE UNIQUE INDEX "hsc_modifier_elig_code_type_sub_calls_version_idx" ON "hsc_modifier_eligibility" USING btree ("hsc_code","modifier_type","sub_code","calls","version_id");--> statement-breakpoint
CREATE INDEX "icd_crosswalk_icd10_code_version_idx" ON "icd_crosswalk" USING btree ("icd10_code","version_id");--> statement-breakpoint
CREATE INDEX "icd_crosswalk_icd9_code_version_idx" ON "icd_crosswalk" USING btree ("icd9_code","version_id");--> statement-breakpoint
CREATE INDEX "icd_crosswalk_version_id_idx" ON "icd_crosswalk" USING btree ("version_id");--> statement-breakpoint
CREATE INDEX "justification_templates_scenario_active_idx" ON "justification_templates" USING btree ("scenario","is_active");--> statement-breakpoint
CREATE UNIQUE INDEX "provider_registry_cpsa_unique_idx" ON "provider_registry" USING btree ("cpsa");--> statement-breakpoint
CREATE INDEX "provider_registry_specialty_idx" ON "provider_registry" USING btree ("specialty_code");--> statement-breakpoint
CREATE INDEX "provider_registry_city_idx" ON "provider_registry" USING btree ("city");--> statement-breakpoint
CREATE INDEX "provider_registry_name_trgm_idx" ON "provider_registry" USING gin ((last_name || ' ' || first_name) gin_trgm_ops);--> statement-breakpoint
CREATE UNIQUE INDEX "provincial_phn_formats_province_unique_idx" ON "provincial_phn_formats" USING btree ("province_code");--> statement-breakpoint
CREATE UNIQUE INDEX "reciprocal_billing_rules_province_type_idx" ON "reciprocal_billing_rules" USING btree ("source_province","claim_type");--> statement-breakpoint
ALTER TABLE "import_batches" ADD CONSTRAINT "import_batches_confirmed_by_users_user_id_fk" FOREIGN KEY ("confirmed_by") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ed_shifts" ADD CONSTRAINT "ed_shifts_schedule_id_shift_schedules_schedule_id_fk" FOREIGN KEY ("schedule_id") REFERENCES "public"."shift_schedules"("schedule_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "import_batches_confirmation_status_idx" ON "import_batches" USING btree ("physician_id","confirmation_status");--> statement-breakpoint
CREATE INDEX "ed_shifts_schedule_idx" ON "ed_shifts" USING btree ("schedule_id");--> statement-breakpoint
CREATE UNIQUE INDEX "hsc_codes_hsc_code_version_id_unique_idx" ON "hsc_codes" USING btree ("hsc_code","version_id");