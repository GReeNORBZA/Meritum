CREATE TABLE "di_codes" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"di_code" varchar(10) NOT NULL,
	"description" text NOT NULL,
	"category" varchar(100) NOT NULL,
	"subcategory" varchar(100),
	"qualifies_surcharge" boolean DEFAULT false NOT NULL,
	"qualifies_bcp" boolean DEFAULT false NOT NULL,
	"common_in_specialty" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"help_text" text,
	"version_id" uuid NOT NULL,
	"effective_from" date NOT NULL,
	"effective_to" date
);
--> statement-breakpoint
CREATE TABLE "explanatory_codes" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"expl_code" varchar(10) NOT NULL,
	"description" text NOT NULL,
	"severity" varchar(10) NOT NULL,
	"common_cause" text,
	"suggested_action" text,
	"help_text" text,
	"version_id" uuid NOT NULL,
	"effective_from" date NOT NULL,
	"effective_to" date
);
--> statement-breakpoint
CREATE TABLE "functional_centres" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"code" varchar(10) NOT NULL,
	"name" varchar(200) NOT NULL,
	"facility_type" varchar(30) NOT NULL,
	"location_city" varchar(100),
	"location_region" varchar(50),
	"rrnp_community_id" uuid,
	"active" boolean DEFAULT true NOT NULL,
	"version_id" uuid NOT NULL,
	"effective_from" date NOT NULL,
	"effective_to" date
);
--> statement-breakpoint
CREATE TABLE "governing_rules" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"rule_id" varchar(20) NOT NULL,
	"rule_name" varchar(200) NOT NULL,
	"rule_category" varchar(30) NOT NULL,
	"description" text NOT NULL,
	"rule_logic" jsonb NOT NULL,
	"severity" varchar(10) NOT NULL,
	"error_message" text NOT NULL,
	"help_text" text,
	"source_reference" varchar(100),
	"source_url" text,
	"version_id" uuid NOT NULL,
	"effective_from" date NOT NULL,
	"effective_to" date
);
--> statement-breakpoint
CREATE TABLE "hsc_codes" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"hsc_code" varchar(10) NOT NULL,
	"description" text NOT NULL,
	"base_fee" numeric(10, 2),
	"fee_type" varchar(20) NOT NULL,
	"specialty_restrictions" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"facility_restrictions" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"max_per_day" integer,
	"max_per_visit" integer,
	"requires_referral" boolean DEFAULT false NOT NULL,
	"referral_validity_days" integer,
	"combination_group" varchar(20),
	"modifier_eligibility" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"surcharge_eligible" boolean DEFAULT false NOT NULL,
	"pcpcm_basket" varchar(20) DEFAULT 'not_applicable' NOT NULL,
	"shadow_billing_eligible" boolean DEFAULT false NOT NULL,
	"notes" text,
	"help_text" text,
	"version_id" uuid NOT NULL,
	"effective_from" date NOT NULL,
	"effective_to" date
);
--> statement-breakpoint
CREATE TABLE "modifier_definitions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"modifier_code" varchar(10) NOT NULL,
	"name" varchar(100) NOT NULL,
	"description" text NOT NULL,
	"type" varchar(20) NOT NULL,
	"calculation_method" varchar(20) NOT NULL,
	"calculation_params" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"applicable_hsc_filter" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"requires_time_documentation" boolean DEFAULT false NOT NULL,
	"requires_facility" boolean DEFAULT false NOT NULL,
	"combinable_with" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"exclusive_with" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"governing_rule_reference" varchar(20),
	"help_text" text,
	"version_id" uuid NOT NULL,
	"effective_from" date NOT NULL,
	"effective_to" date
);
--> statement-breakpoint
CREATE TABLE "pcpcm_baskets" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"hsc_code" varchar(10) NOT NULL,
	"basket" varchar(20) NOT NULL,
	"notes" text,
	"version_id" uuid NOT NULL,
	"effective_from" date NOT NULL,
	"effective_to" date
);
--> statement-breakpoint
CREATE TABLE "reference_data_staging" (
	"staging_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"data_set" varchar(30) NOT NULL,
	"status" varchar(20) DEFAULT 'uploaded' NOT NULL,
	"uploaded_by" uuid NOT NULL,
	"uploaded_at" timestamp with time zone NOT NULL,
	"file_hash" varchar(64) NOT NULL,
	"record_count" integer NOT NULL,
	"validation_result" jsonb,
	"diff_result" jsonb,
	"staged_data" jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "reference_data_versions" (
	"version_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"data_set" varchar(30) NOT NULL,
	"version_label" varchar(50) NOT NULL,
	"effective_from" date NOT NULL,
	"effective_to" date,
	"published_by" uuid NOT NULL,
	"published_at" timestamp with time zone NOT NULL,
	"source_document" text,
	"change_summary" text,
	"records_added" integer DEFAULT 0 NOT NULL,
	"records_modified" integer DEFAULT 0 NOT NULL,
	"records_deprecated" integer DEFAULT 0 NOT NULL,
	"is_active" boolean DEFAULT false NOT NULL
);
--> statement-breakpoint
CREATE TABLE "rrnp_communities" (
	"community_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"community_name" varchar(200) NOT NULL,
	"rrnp_percentage" numeric(5, 2) NOT NULL,
	"rrnp_tier" varchar(20),
	"region" varchar(100),
	"version_id" uuid NOT NULL,
	"effective_from" date NOT NULL,
	"effective_to" date
);
--> statement-breakpoint
CREATE TABLE "statutory_holidays" (
	"holiday_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"date" date NOT NULL,
	"name" varchar(100) NOT NULL,
	"jurisdiction" varchar(20) NOT NULL,
	"affects_billing_premiums" boolean DEFAULT true NOT NULL,
	"year" integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE "wcb_codes" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"wcb_code" varchar(10) NOT NULL,
	"description" text NOT NULL,
	"base_fee" numeric(10, 2) NOT NULL,
	"fee_type" varchar(20) NOT NULL,
	"requires_claim_number" boolean DEFAULT true NOT NULL,
	"requires_employer" boolean DEFAULT false NOT NULL,
	"documentation_requirements" text,
	"help_text" text,
	"version_id" uuid NOT NULL,
	"effective_from" date NOT NULL,
	"effective_to" date
);
--> statement-breakpoint
ALTER TABLE "di_codes" ADD CONSTRAINT "di_codes_version_id_reference_data_versions_version_id_fk" FOREIGN KEY ("version_id") REFERENCES "public"."reference_data_versions"("version_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "explanatory_codes" ADD CONSTRAINT "explanatory_codes_version_id_reference_data_versions_version_id_fk" FOREIGN KEY ("version_id") REFERENCES "public"."reference_data_versions"("version_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "functional_centres" ADD CONSTRAINT "functional_centres_rrnp_community_id_rrnp_communities_community_id_fk" FOREIGN KEY ("rrnp_community_id") REFERENCES "public"."rrnp_communities"("community_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "functional_centres" ADD CONSTRAINT "functional_centres_version_id_reference_data_versions_version_id_fk" FOREIGN KEY ("version_id") REFERENCES "public"."reference_data_versions"("version_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "governing_rules" ADD CONSTRAINT "governing_rules_version_id_reference_data_versions_version_id_fk" FOREIGN KEY ("version_id") REFERENCES "public"."reference_data_versions"("version_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hsc_codes" ADD CONSTRAINT "hsc_codes_version_id_reference_data_versions_version_id_fk" FOREIGN KEY ("version_id") REFERENCES "public"."reference_data_versions"("version_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "modifier_definitions" ADD CONSTRAINT "modifier_definitions_version_id_reference_data_versions_version_id_fk" FOREIGN KEY ("version_id") REFERENCES "public"."reference_data_versions"("version_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "pcpcm_baskets" ADD CONSTRAINT "pcpcm_baskets_version_id_reference_data_versions_version_id_fk" FOREIGN KEY ("version_id") REFERENCES "public"."reference_data_versions"("version_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "reference_data_staging" ADD CONSTRAINT "reference_data_staging_uploaded_by_users_user_id_fk" FOREIGN KEY ("uploaded_by") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "reference_data_versions" ADD CONSTRAINT "reference_data_versions_published_by_users_user_id_fk" FOREIGN KEY ("published_by") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rrnp_communities" ADD CONSTRAINT "rrnp_communities_version_id_reference_data_versions_version_id_fk" FOREIGN KEY ("version_id") REFERENCES "public"."reference_data_versions"("version_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wcb_codes" ADD CONSTRAINT "wcb_codes_version_id_reference_data_versions_version_id_fk" FOREIGN KEY ("version_id") REFERENCES "public"."reference_data_versions"("version_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "di_codes_di_code_version_id_idx" ON "di_codes" USING btree ("di_code","version_id");--> statement-breakpoint
CREATE INDEX "di_codes_di_code_trgm_idx" ON "di_codes" USING gin ("di_code" gin_trgm_ops);--> statement-breakpoint
CREATE INDEX "di_codes_description_trgm_idx" ON "di_codes" USING gin ("description" gin_trgm_ops);--> statement-breakpoint
CREATE INDEX "di_codes_description_gin_idx" ON "di_codes" USING gin (to_tsvector('english', "description"));--> statement-breakpoint
CREATE INDEX "explanatory_codes_expl_code_version_id_idx" ON "explanatory_codes" USING btree ("expl_code","version_id");--> statement-breakpoint
CREATE INDEX "functional_centres_code_version_id_idx" ON "functional_centres" USING btree ("code","version_id");--> statement-breakpoint
CREATE INDEX "functional_centres_facility_type_version_id_idx" ON "functional_centres" USING btree ("facility_type","version_id");--> statement-breakpoint
CREATE INDEX "governing_rules_rule_id_version_id_idx" ON "governing_rules" USING btree ("rule_id","version_id");--> statement-breakpoint
CREATE INDEX "governing_rules_rule_category_version_id_idx" ON "governing_rules" USING btree ("rule_category","version_id");--> statement-breakpoint
CREATE INDEX "hsc_codes_hsc_code_version_id_idx" ON "hsc_codes" USING btree ("hsc_code","version_id");--> statement-breakpoint
CREATE INDEX "hsc_codes_version_id_idx" ON "hsc_codes" USING btree ("version_id");--> statement-breakpoint
CREATE INDEX "hsc_codes_description_gin_idx" ON "hsc_codes" USING gin (to_tsvector('english', "description"));--> statement-breakpoint
CREATE INDEX "hsc_codes_hsc_code_trgm_idx" ON "hsc_codes" USING gin ("hsc_code" gin_trgm_ops);--> statement-breakpoint
CREATE INDEX "hsc_codes_description_trgm_idx" ON "hsc_codes" USING gin ("description" gin_trgm_ops);--> statement-breakpoint
CREATE INDEX "modifier_definitions_code_version_id_idx" ON "modifier_definitions" USING btree ("modifier_code","version_id");--> statement-breakpoint
CREATE INDEX "modifier_definitions_version_id_idx" ON "modifier_definitions" USING btree ("version_id");--> statement-breakpoint
CREATE INDEX "pcpcm_baskets_hsc_code_version_id_idx" ON "pcpcm_baskets" USING btree ("hsc_code","version_id");--> statement-breakpoint
CREATE INDEX "reference_data_staging_data_set_status_idx" ON "reference_data_staging" USING btree ("data_set","status");--> statement-breakpoint
CREATE INDEX "ref_versions_data_set_is_active_idx" ON "reference_data_versions" USING btree ("data_set","is_active");--> statement-breakpoint
CREATE INDEX "ref_versions_data_set_effective_from_idx" ON "reference_data_versions" USING btree ("data_set");--> statement-breakpoint
CREATE UNIQUE INDEX "ref_versions_one_active_per_dataset_idx" ON "reference_data_versions" USING btree ("data_set") WHERE is_active = true;--> statement-breakpoint
CREATE INDEX "rrnp_communities_name_version_id_idx" ON "rrnp_communities" USING btree ("community_name","version_id");--> statement-breakpoint
CREATE UNIQUE INDEX "statutory_holidays_date_idx" ON "statutory_holidays" USING btree ("date");--> statement-breakpoint
CREATE INDEX "statutory_holidays_year_idx" ON "statutory_holidays" USING btree ("year");--> statement-breakpoint
CREATE INDEX "wcb_codes_wcb_code_version_id_idx" ON "wcb_codes" USING btree ("wcb_code","version_id");--> statement-breakpoint
CREATE INDEX "wcb_codes_version_id_idx" ON "wcb_codes" USING btree ("version_id");--> statement-breakpoint
CREATE INDEX "wcb_codes_wcb_code_trgm_idx" ON "wcb_codes" USING gin ("wcb_code" gin_trgm_ops);--> statement-breakpoint
CREATE INDEX "wcb_codes_description_trgm_idx" ON "wcb_codes" USING gin ("description" gin_trgm_ops);