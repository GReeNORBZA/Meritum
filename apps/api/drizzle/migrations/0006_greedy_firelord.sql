CREATE TABLE "claim_audit_history" (
	"audit_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"claim_id" uuid NOT NULL,
	"action" varchar(30) NOT NULL,
	"previous_state" varchar(20),
	"new_state" varchar(20),
	"changes" jsonb,
	"actor_id" uuid NOT NULL,
	"actor_context" varchar(20) NOT NULL,
	"reason" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "claims" (
	"claim_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"physician_id" uuid NOT NULL,
	"patient_id" uuid NOT NULL,
	"claim_type" varchar(10) NOT NULL,
	"state" varchar(20) DEFAULT 'DRAFT' NOT NULL,
	"is_clean" boolean,
	"import_source" varchar(20) NOT NULL,
	"import_batch_id" uuid,
	"shift_id" uuid,
	"date_of_service" date NOT NULL,
	"submission_deadline" date NOT NULL,
	"submitted_batch_id" uuid,
	"validation_result" jsonb,
	"validation_timestamp" timestamp with time zone,
	"reference_data_version" varchar(20),
	"ai_coach_suggestions" jsonb,
	"duplicate_alert" jsonb,
	"flags" jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by" uuid NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_by" uuid NOT NULL,
	"deleted_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "field_mapping_templates" (
	"template_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"physician_id" uuid NOT NULL,
	"name" varchar(100) NOT NULL,
	"emr_type" varchar(50),
	"mappings" jsonb NOT NULL,
	"delimiter" varchar(5),
	"has_header_row" boolean NOT NULL,
	"date_format" varchar(20),
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "import_batches" (
	"import_batch_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"physician_id" uuid NOT NULL,
	"file_name" varchar(255) NOT NULL,
	"file_hash" varchar(64) NOT NULL,
	"field_mapping_template_id" uuid,
	"total_rows" integer NOT NULL,
	"success_count" integer NOT NULL,
	"error_count" integer NOT NULL,
	"error_details" jsonb,
	"status" varchar(20) NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by" uuid NOT NULL
);
--> statement-breakpoint
CREATE TABLE "shifts" (
	"shift_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"physician_id" uuid NOT NULL,
	"facility_id" uuid NOT NULL,
	"shift_date" date NOT NULL,
	"start_time" time,
	"end_time" time,
	"status" varchar(20) NOT NULL,
	"encounter_count" integer DEFAULT 0 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "claim_audit_history" ADD CONSTRAINT "claim_audit_history_claim_id_claims_claim_id_fk" FOREIGN KEY ("claim_id") REFERENCES "public"."claims"("claim_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "claim_audit_history" ADD CONSTRAINT "claim_audit_history_actor_id_users_user_id_fk" FOREIGN KEY ("actor_id") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "claims" ADD CONSTRAINT "claims_physician_id_providers_provider_id_fk" FOREIGN KEY ("physician_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "claims" ADD CONSTRAINT "claims_patient_id_patients_patient_id_fk" FOREIGN KEY ("patient_id") REFERENCES "public"."patients"("patient_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "claims" ADD CONSTRAINT "claims_created_by_users_user_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "claims" ADD CONSTRAINT "claims_updated_by_users_user_id_fk" FOREIGN KEY ("updated_by") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "field_mapping_templates" ADD CONSTRAINT "field_mapping_templates_physician_id_providers_provider_id_fk" FOREIGN KEY ("physician_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "import_batches" ADD CONSTRAINT "import_batches_physician_id_providers_provider_id_fk" FOREIGN KEY ("physician_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "import_batches" ADD CONSTRAINT "import_batches_field_mapping_template_id_field_mapping_templates_template_id_fk" FOREIGN KEY ("field_mapping_template_id") REFERENCES "public"."field_mapping_templates"("template_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "import_batches" ADD CONSTRAINT "import_batches_created_by_users_user_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "shifts" ADD CONSTRAINT "shifts_physician_id_providers_provider_id_fk" FOREIGN KEY ("physician_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "claim_audit_history_claim_created_idx" ON "claim_audit_history" USING btree ("claim_id","created_at");--> statement-breakpoint
CREATE INDEX "claim_audit_history_actor_created_idx" ON "claim_audit_history" USING btree ("actor_id","created_at");--> statement-breakpoint
CREATE INDEX "claims_physician_state_idx" ON "claims" USING btree ("physician_id","state");--> statement-breakpoint
CREATE INDEX "claims_patient_dos_idx" ON "claims" USING btree ("patient_id","date_of_service");--> statement-breakpoint
CREATE INDEX "claims_state_type_clean_idx" ON "claims" USING btree ("state","claim_type","is_clean");--> statement-breakpoint
CREATE INDEX "claims_submission_deadline_idx" ON "claims" USING btree ("submission_deadline");--> statement-breakpoint
CREATE INDEX "field_mapping_templates_physician_idx" ON "field_mapping_templates" USING btree ("physician_id");--> statement-breakpoint
CREATE INDEX "import_batches_physician_created_idx" ON "import_batches" USING btree ("physician_id","created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "import_batches_physician_file_hash_idx" ON "import_batches" USING btree ("physician_id","file_hash");--> statement-breakpoint
CREATE INDEX "shifts_physician_shift_date_idx" ON "shifts" USING btree ("physician_id","shift_date");