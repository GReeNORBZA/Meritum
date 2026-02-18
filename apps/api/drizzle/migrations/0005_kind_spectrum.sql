CREATE TABLE "patient_import_batches" (
	"import_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"physician_id" uuid NOT NULL,
	"file_name" varchar(255) NOT NULL,
	"file_hash" varchar(64) NOT NULL,
	"total_rows" integer DEFAULT 0 NOT NULL,
	"created_count" integer DEFAULT 0 NOT NULL,
	"updated_count" integer DEFAULT 0 NOT NULL,
	"skipped_count" integer DEFAULT 0 NOT NULL,
	"error_count" integer DEFAULT 0 NOT NULL,
	"error_details" jsonb,
	"status" varchar(20) DEFAULT 'PENDING' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by" uuid NOT NULL
);
--> statement-breakpoint
CREATE TABLE "patient_merge_history" (
	"merge_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"physician_id" uuid NOT NULL,
	"surviving_patient_id" uuid NOT NULL,
	"merged_patient_id" uuid NOT NULL,
	"claims_transferred" integer NOT NULL,
	"field_conflicts" jsonb,
	"merged_at" timestamp with time zone DEFAULT now() NOT NULL,
	"merged_by" uuid NOT NULL
);
--> statement-breakpoint
CREATE TABLE "patients" (
	"patient_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"provider_id" uuid NOT NULL,
	"phn" varchar(9),
	"phn_province" varchar(2) DEFAULT 'AB',
	"first_name" varchar(50) NOT NULL,
	"middle_name" varchar(50),
	"last_name" varchar(50) NOT NULL,
	"date_of_birth" date NOT NULL,
	"gender" varchar(1) NOT NULL,
	"phone" varchar(24),
	"email" varchar(100),
	"address_line_1" varchar(100),
	"address_line_2" varchar(100),
	"city" varchar(50),
	"province" varchar(2),
	"postal_code" varchar(7),
	"notes" text,
	"is_active" boolean DEFAULT true NOT NULL,
	"last_visit_date" date,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by" uuid NOT NULL
);
--> statement-breakpoint
ALTER TABLE "patient_import_batches" ADD CONSTRAINT "patient_import_batches_physician_id_providers_provider_id_fk" FOREIGN KEY ("physician_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "patient_import_batches" ADD CONSTRAINT "patient_import_batches_created_by_users_user_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "patient_merge_history" ADD CONSTRAINT "patient_merge_history_physician_id_providers_provider_id_fk" FOREIGN KEY ("physician_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "patient_merge_history" ADD CONSTRAINT "patient_merge_history_surviving_patient_id_patients_patient_id_fk" FOREIGN KEY ("surviving_patient_id") REFERENCES "public"."patients"("patient_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "patient_merge_history" ADD CONSTRAINT "patient_merge_history_merged_patient_id_patients_patient_id_fk" FOREIGN KEY ("merged_patient_id") REFERENCES "public"."patients"("patient_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "patient_merge_history" ADD CONSTRAINT "patient_merge_history_merged_by_users_user_id_fk" FOREIGN KEY ("merged_by") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "patients" ADD CONSTRAINT "patients_provider_id_providers_provider_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "patients" ADD CONSTRAINT "patients_created_by_users_user_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "patient_import_batches_physician_created_idx" ON "patient_import_batches" USING btree ("physician_id","created_at");--> statement-breakpoint
CREATE INDEX "patient_import_batches_physician_hash_idx" ON "patient_import_batches" USING btree ("physician_id","file_hash");--> statement-breakpoint
CREATE INDEX "patient_merge_history_physician_merged_at_idx" ON "patient_merge_history" USING btree ("physician_id","merged_at");--> statement-breakpoint
CREATE INDEX "patient_merge_history_surviving_idx" ON "patient_merge_history" USING btree ("surviving_patient_id");--> statement-breakpoint
CREATE INDEX "patient_merge_history_merged_idx" ON "patient_merge_history" USING btree ("merged_patient_id");--> statement-breakpoint
CREATE UNIQUE INDEX "patients_provider_phn_unique_idx" ON "patients" USING btree ("provider_id","phn") WHERE phn IS NOT NULL;--> statement-breakpoint
CREATE INDEX "patients_provider_name_idx" ON "patients" USING btree ("provider_id","last_name","first_name");--> statement-breakpoint
CREATE INDEX "patients_provider_dob_idx" ON "patients" USING btree ("provider_id","date_of_birth");--> statement-breakpoint
CREATE INDEX "patients_provider_last_visit_idx" ON "patients" USING btree ("provider_id","last_visit_date");--> statement-breakpoint
CREATE INDEX "patients_provider_is_active_idx" ON "patients" USING btree ("provider_id","is_active");--> statement-breakpoint
CREATE INDEX "patients_name_trgm_idx" ON "patients" USING gin ((last_name || ' ' || first_name) gin_trgm_ops);