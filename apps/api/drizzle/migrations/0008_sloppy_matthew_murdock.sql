CREATE TABLE "wcb_attachments" (
	"wcb_attachment_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"wcb_claim_detail_id" uuid NOT NULL,
	"ordinal" smallint NOT NULL,
	"file_name" varchar(255) NOT NULL,
	"file_type" varchar(10) NOT NULL,
	"file_content_b64" text NOT NULL,
	"file_description" varchar(60) NOT NULL,
	"file_size_bytes" integer NOT NULL,
	CONSTRAINT "wcb_attachments_detail_ordinal_uniq" UNIQUE("wcb_claim_detail_id","ordinal"),
	CONSTRAINT "wcb_attachments_ordinal_check" CHECK ("wcb_attachments"."ordinal" BETWEEN 1 AND 3)
);
--> statement-breakpoint
CREATE TABLE "wcb_batches" (
	"wcb_batch_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"physician_id" uuid NOT NULL,
	"batch_control_id" varchar(50) NOT NULL,
	"file_control_id" varchar(50) NOT NULL,
	"status" varchar(20) NOT NULL,
	"report_count" integer NOT NULL,
	"xml_file_path" varchar(255),
	"xml_file_hash" varchar(64),
	"xsd_validation_passed" boolean,
	"xsd_validation_errors" jsonb,
	"uploaded_at" timestamp with time zone,
	"uploaded_by" uuid,
	"return_file_received_at" timestamp with time zone,
	"return_file_path" varchar(255),
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by" uuid NOT NULL
);
--> statement-breakpoint
CREATE TABLE "wcb_claim_details" (
	"wcb_claim_detail_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"claim_id" uuid NOT NULL,
	"form_id" varchar(5) NOT NULL,
	"submitter_txn_id" varchar(16) NOT NULL,
	"wcb_claim_number" varchar(7),
	"report_completion_date" date NOT NULL,
	"additional_comments" text,
	"parent_wcb_claim_id" uuid,
	"practitioner_billing_number" varchar(8) NOT NULL,
	"contract_id" varchar(10) NOT NULL,
	"role_code" varchar(10) NOT NULL,
	"practitioner_first_name" varchar(11) NOT NULL,
	"practitioner_middle_name" varchar(11),
	"practitioner_last_name" varchar(21) NOT NULL,
	"skill_code" varchar(10) NOT NULL,
	"facility_type" varchar(1) NOT NULL,
	"clinic_reference_number" varchar(8),
	"billing_contact_name" varchar(30),
	"fax_country_code" varchar(10),
	"fax_number" varchar(24),
	"patient_no_phn_flag" varchar(1) NOT NULL,
	"patient_phn" varchar(9),
	"patient_gender" varchar(1) NOT NULL,
	"patient_first_name" varchar(11) NOT NULL,
	"patient_middle_name" varchar(11),
	"patient_last_name" varchar(21) NOT NULL,
	"patient_dob" date NOT NULL,
	"patient_address_line1" varchar(30) NOT NULL,
	"patient_address_line2" varchar(30),
	"patient_city" varchar(20) NOT NULL,
	"patient_province" varchar(10),
	"patient_postal_code" varchar(9),
	"patient_phone_country" varchar(10),
	"patient_phone_number" varchar(24),
	"employer_name" varchar(50),
	"employer_location" varchar(100),
	"employer_city" varchar(20),
	"employer_province" varchar(10),
	"employer_phone_country" varchar(10),
	"employer_phone_number" varchar(24),
	"employer_phone_ext" varchar(6),
	"worker_job_title" varchar(50),
	"injury_developed_over_time" varchar(1),
	"date_of_injury" date NOT NULL,
	"injury_description" text,
	"date_of_examination" date,
	"symptoms" text,
	"objective_findings" text,
	"current_diagnosis" text,
	"previous_diagnosis" text,
	"diagnosis_changed" varchar(1),
	"diagnosis_changed_desc" text,
	"diagnostic_code_1" varchar(8),
	"diagnostic_code_2" varchar(8),
	"diagnostic_code_3" varchar(8),
	"additional_injuries_desc" text,
	"dominant_hand" varchar(10),
	"prior_conditions_flag" varchar(1),
	"prior_conditions_desc" text,
	"referring_physician_name" varchar(50),
	"date_of_referral" date,
	"narcotics_prescribed" varchar(1),
	"treatment_plan_text" text,
	"case_conf_wcb_manager" varchar(1),
	"case_conf_wcb_physician" varchar(1),
	"referral_rtw_provider" varchar(1),
	"consultation_letter_format" varchar(5),
	"consultation_letter_text" text,
	"missed_work_beyond_accident" varchar(1),
	"patient_returned_to_work" varchar(1),
	"date_returned_to_work" date,
	"modified_hours" varchar(1),
	"hours_capable_per_day" smallint,
	"modified_duties" varchar(1),
	"rtw_hospitalized" varchar(1),
	"rtw_self_reported_pain" varchar(1),
	"rtw_opioid_side_effects" varchar(1),
	"rtw_other_restrictions" text,
	"estimated_rtw_date" date,
	"rtw_status_changed" varchar(1),
	"reassessment_comments" text,
	"grasp_right_level" varchar(10),
	"grasp_right_prolonged" varchar(1),
	"grasp_right_repetitive" varchar(1),
	"grasp_right_vibration" varchar(1),
	"grasp_right_specify" varchar(1),
	"grasp_right_specific_desc" text,
	"grasp_left_level" varchar(10),
	"grasp_left_prolonged" varchar(1),
	"grasp_left_repetitive" varchar(1),
	"grasp_left_vibration" varchar(1),
	"grasp_left_specify" varchar(1),
	"grasp_left_specific_desc" text,
	"lift_floor_to_waist" varchar(10),
	"lift_floor_to_waist_max" varchar(10),
	"lift_waist_to_shoulder" varchar(10),
	"lift_waist_to_shoulder_max" varchar(10),
	"lift_above_shoulder" varchar(10),
	"lift_above_shoulder_max" varchar(10),
	"reach_above_right_shoulder" varchar(10),
	"reach_below_right_shoulder" varchar(10),
	"reach_above_left_shoulder" varchar(10),
	"reach_below_left_shoulder" varchar(10),
	"environment_restricted" varchar(1),
	"env_cold" varchar(1),
	"env_hot" varchar(1),
	"env_wet" varchar(1),
	"env_dry" varchar(1),
	"env_dust" varchar(1),
	"env_lighting" varchar(1),
	"env_noise" varchar(1),
	"ois_reviewed_with_patient" varchar(1),
	"ois_fitness_assessment" varchar(10),
	"ois_estimated_rtw_date" date,
	"ois_rtw_level" varchar(10),
	"ois_followup_required" varchar(1),
	"ois_followup_date" date,
	"ois_emp_modified_work_required" varchar(1),
	"ois_emp_modified_from_date" date,
	"ois_emp_modified_to_date" date,
	"ois_emp_modified_available" varchar(1),
	"ois_emp_available_from_date" date,
	"ois_emp_available_to_date" date,
	"ois_emp_comments" text,
	"ois_worker_rtw_date" date,
	"ois_worker_modified_duration" varchar(50),
	"ois_worker_diagnosis_plan" text,
	"ois_worker_self_care" varchar(1),
	"ois_worker_comments" text,
	"ois_has_family_physician" varchar(1),
	"ois_family_physician_name" varchar(50),
	"ois_family_physician_phone_country" varchar(10),
	"ois_family_physician_phone" varchar(24),
	"ois_family_physician_plan" text,
	"ois_family_physician_support" varchar(10),
	"ois_family_physician_rtw_date" date,
	"ois_family_physician_treatment" varchar(10),
	"ois_family_physician_modified" varchar(10),
	"ois_family_physician_comments" text,
	"surgery_past_60_days" varchar(1),
	"treating_malignant_pain" varchar(1),
	"wcb_advised_no_mmr" varchar(1),
	"side_effect_nausea" varchar(1),
	"side_effect_sleep" varchar(1),
	"side_effect_constipation" varchar(1),
	"side_effect_endocrine" varchar(1),
	"side_effect_sweating" varchar(1),
	"side_effect_cognitive" varchar(1),
	"side_effect_dry_mouth" varchar(1),
	"side_effect_fatigue" varchar(1),
	"side_effect_depression" varchar(1),
	"side_effect_worsening_pain" varchar(1),
	"abuse_social_deterioration" varchar(1),
	"abuse_unsanctioned_use" varchar(1),
	"abuse_altered_route" varchar(1),
	"abuse_opioid_seeking" varchar(1),
	"abuse_other_sources" varchar(1),
	"abuse_withdrawal" varchar(1),
	"patient_pain_estimate" smallint,
	"opioid_reducing_pain" varchar(1),
	"pain_reduction_desc" text,
	"clinician_function_estimate" smallint,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by" uuid NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_by" uuid NOT NULL,
	"deleted_at" timestamp with time zone,
	CONSTRAINT "wcb_claim_details_claim_id_unique" UNIQUE("claim_id")
);
--> statement-breakpoint
CREATE TABLE "wcb_consultations" (
	"wcb_consultation_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"wcb_claim_detail_id" uuid NOT NULL,
	"ordinal" smallint NOT NULL,
	"category" varchar(10) NOT NULL,
	"type_code" varchar(10) NOT NULL,
	"details" varchar(50) NOT NULL,
	"expedite_requested" varchar(1),
	CONSTRAINT "wcb_consultations_detail_ordinal_uniq" UNIQUE("wcb_claim_detail_id","ordinal"),
	CONSTRAINT "wcb_consultations_ordinal_check" CHECK ("wcb_consultations"."ordinal" BETWEEN 1 AND 5)
);
--> statement-breakpoint
CREATE TABLE "wcb_injuries" (
	"wcb_injury_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"wcb_claim_detail_id" uuid NOT NULL,
	"ordinal" smallint NOT NULL,
	"part_of_body_code" varchar(10) NOT NULL,
	"side_of_body_code" varchar(10),
	"nature_of_injury_code" varchar(10) NOT NULL,
	CONSTRAINT "wcb_injuries_detail_ordinal_uniq" UNIQUE("wcb_claim_detail_id","ordinal"),
	CONSTRAINT "wcb_injuries_ordinal_check" CHECK ("wcb_injuries"."ordinal" BETWEEN 1 AND 5)
);
--> statement-breakpoint
CREATE TABLE "wcb_invoice_lines" (
	"wcb_invoice_line_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"wcb_claim_detail_id" uuid NOT NULL,
	"invoice_detail_id" smallint NOT NULL,
	"line_type" varchar(10) NOT NULL,
	"health_service_code" varchar(7),
	"diagnostic_code_1" varchar(8),
	"diagnostic_code_2" varchar(8),
	"diagnostic_code_3" varchar(8),
	"modifier_1" varchar(6),
	"modifier_2" varchar(6),
	"modifier_3" varchar(6),
	"calls" smallint,
	"encounters" smallint,
	"date_of_service_from" date,
	"date_of_service_to" date,
	"facility_type_override" varchar(1),
	"skill_code_override" varchar(10),
	"invoice_detail_type_code" varchar(10),
	"invoice_detail_desc" varchar(50),
	"quantity" smallint,
	"supply_description" varchar(50),
	"amount" numeric(10, 2),
	"adjustment_indicator" varchar(10),
	"billing_number_override" varchar(8),
	"correction_pair_id" smallint,
	CONSTRAINT "wcb_invoice_lines_detail_line_uniq" UNIQUE("wcb_claim_detail_id","invoice_detail_id"),
	CONSTRAINT "wcb_invoice_lines_detail_id_check" CHECK ("wcb_invoice_lines"."invoice_detail_id" BETWEEN 1 AND 25)
);
--> statement-breakpoint
CREATE TABLE "wcb_prescriptions" (
	"wcb_prescription_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"wcb_claim_detail_id" uuid NOT NULL,
	"ordinal" smallint NOT NULL,
	"prescription_name" varchar(50) NOT NULL,
	"strength" varchar(30) NOT NULL,
	"daily_intake" varchar(30) NOT NULL,
	CONSTRAINT "wcb_prescriptions_detail_ordinal_uniq" UNIQUE("wcb_claim_detail_id","ordinal"),
	CONSTRAINT "wcb_prescriptions_ordinal_check" CHECK ("wcb_prescriptions"."ordinal" BETWEEN 1 AND 5)
);
--> statement-breakpoint
CREATE TABLE "wcb_remittance_records" (
	"wcb_remittance_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"remittance_import_id" uuid NOT NULL,
	"wcb_claim_detail_id" uuid,
	"report_week_start" date NOT NULL,
	"report_week_end" date NOT NULL,
	"disbursement_number" varchar(8),
	"disbursement_type" varchar(3),
	"disbursement_issue_date" date,
	"disbursement_amount" numeric(11, 2),
	"disbursement_recipient_billing" varchar(8),
	"disbursement_recipient_name" varchar(40),
	"payment_payee_billing" varchar(8) NOT NULL,
	"payment_payee_name" varchar(40) NOT NULL,
	"payment_reason_code" varchar(3) NOT NULL,
	"payment_status" varchar(3) NOT NULL,
	"payment_start_date" date NOT NULL,
	"payment_end_date" date NOT NULL,
	"payment_amount" numeric(11, 2) NOT NULL,
	"billed_amount" numeric(10, 2),
	"electronic_report_txn_id" varchar(20),
	"claim_number" varchar(7),
	"worker_phn" varchar(11),
	"worker_first_name" varchar(11),
	"worker_last_name" varchar(21),
	"service_code" varchar(7),
	"modifier_1" varchar(6),
	"modifier_2" varchar(6),
	"modifier_3" varchar(6),
	"number_of_calls" smallint,
	"encounter_number" smallint,
	"overpayment_recovery" numeric(10, 2)
);
--> statement-breakpoint
CREATE TABLE "wcb_return_invoice_lines" (
	"wcb_return_invoice_line_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"wcb_return_record_id" uuid NOT NULL,
	"invoice_sequence" smallint NOT NULL,
	"service_date" date,
	"health_service_code" varchar(7),
	"invoice_status" varchar(20)
);
--> statement-breakpoint
CREATE TABLE "wcb_return_records" (
	"wcb_return_record_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"wcb_batch_id" uuid NOT NULL,
	"wcb_claim_detail_id" uuid,
	"report_txn_id" varchar(20) NOT NULL,
	"submitter_txn_id" varchar(16) NOT NULL,
	"processed_claim_number" varchar(7),
	"claim_decision" varchar(20) NOT NULL,
	"report_status" varchar(20) NOT NULL,
	"txn_submission_date" date NOT NULL,
	"errors" jsonb
);
--> statement-breakpoint
CREATE TABLE "wcb_work_restrictions" (
	"wcb_restriction_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"wcb_claim_detail_id" uuid NOT NULL,
	"activity_type" varchar(20) NOT NULL,
	"restriction_level" varchar(10) NOT NULL,
	"hours_per_day" smallint,
	"max_weight" varchar(10),
	CONSTRAINT "wcb_work_restrictions_detail_activity_uniq" UNIQUE("wcb_claim_detail_id","activity_type")
);
--> statement-breakpoint
ALTER TABLE "wcb_attachments" ADD CONSTRAINT "wcb_attachments_wcb_claim_detail_id_wcb_claim_details_wcb_claim_detail_id_fk" FOREIGN KEY ("wcb_claim_detail_id") REFERENCES "public"."wcb_claim_details"("wcb_claim_detail_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wcb_batches" ADD CONSTRAINT "wcb_batches_physician_id_providers_provider_id_fk" FOREIGN KEY ("physician_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wcb_batches" ADD CONSTRAINT "wcb_batches_uploaded_by_users_user_id_fk" FOREIGN KEY ("uploaded_by") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wcb_batches" ADD CONSTRAINT "wcb_batches_created_by_users_user_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wcb_claim_details" ADD CONSTRAINT "wcb_claim_details_claim_id_claims_claim_id_fk" FOREIGN KEY ("claim_id") REFERENCES "public"."claims"("claim_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wcb_claim_details" ADD CONSTRAINT "wcb_claim_details_parent_wcb_claim_id_wcb_claim_details_wcb_claim_detail_id_fk" FOREIGN KEY ("parent_wcb_claim_id") REFERENCES "public"."wcb_claim_details"("wcb_claim_detail_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wcb_claim_details" ADD CONSTRAINT "wcb_claim_details_created_by_users_user_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wcb_claim_details" ADD CONSTRAINT "wcb_claim_details_updated_by_users_user_id_fk" FOREIGN KEY ("updated_by") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wcb_consultations" ADD CONSTRAINT "wcb_consultations_wcb_claim_detail_id_wcb_claim_details_wcb_claim_detail_id_fk" FOREIGN KEY ("wcb_claim_detail_id") REFERENCES "public"."wcb_claim_details"("wcb_claim_detail_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wcb_injuries" ADD CONSTRAINT "wcb_injuries_wcb_claim_detail_id_wcb_claim_details_wcb_claim_detail_id_fk" FOREIGN KEY ("wcb_claim_detail_id") REFERENCES "public"."wcb_claim_details"("wcb_claim_detail_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wcb_invoice_lines" ADD CONSTRAINT "wcb_invoice_lines_wcb_claim_detail_id_wcb_claim_details_wcb_claim_detail_id_fk" FOREIGN KEY ("wcb_claim_detail_id") REFERENCES "public"."wcb_claim_details"("wcb_claim_detail_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wcb_prescriptions" ADD CONSTRAINT "wcb_prescriptions_wcb_claim_detail_id_wcb_claim_details_wcb_claim_detail_id_fk" FOREIGN KEY ("wcb_claim_detail_id") REFERENCES "public"."wcb_claim_details"("wcb_claim_detail_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wcb_remittance_records" ADD CONSTRAINT "wcb_remittance_records_wcb_claim_detail_id_wcb_claim_details_wcb_claim_detail_id_fk" FOREIGN KEY ("wcb_claim_detail_id") REFERENCES "public"."wcb_claim_details"("wcb_claim_detail_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wcb_return_invoice_lines" ADD CONSTRAINT "wcb_return_invoice_lines_wcb_return_record_id_wcb_return_records_wcb_return_record_id_fk" FOREIGN KEY ("wcb_return_record_id") REFERENCES "public"."wcb_return_records"("wcb_return_record_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wcb_return_records" ADD CONSTRAINT "wcb_return_records_wcb_batch_id_wcb_batches_wcb_batch_id_fk" FOREIGN KEY ("wcb_batch_id") REFERENCES "public"."wcb_batches"("wcb_batch_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wcb_return_records" ADD CONSTRAINT "wcb_return_records_wcb_claim_detail_id_wcb_claim_details_wcb_claim_detail_id_fk" FOREIGN KEY ("wcb_claim_detail_id") REFERENCES "public"."wcb_claim_details"("wcb_claim_detail_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wcb_work_restrictions" ADD CONSTRAINT "wcb_work_restrictions_wcb_claim_detail_id_wcb_claim_details_wcb_claim_detail_id_fk" FOREIGN KEY ("wcb_claim_detail_id") REFERENCES "public"."wcb_claim_details"("wcb_claim_detail_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "wcb_attachments_claim_detail_id_idx" ON "wcb_attachments" USING btree ("wcb_claim_detail_id");--> statement-breakpoint
CREATE INDEX "wcb_batches_physician_status_idx" ON "wcb_batches" USING btree ("physician_id","status");--> statement-breakpoint
CREATE UNIQUE INDEX "wcb_batches_batch_control_id_uniq" ON "wcb_batches" USING btree ("batch_control_id");--> statement-breakpoint
CREATE UNIQUE INDEX "wcb_batches_file_control_id_uniq" ON "wcb_batches" USING btree ("file_control_id");--> statement-breakpoint
CREATE UNIQUE INDEX "wcb_claim_details_submitter_txn_id_uniq" ON "wcb_claim_details" USING btree ("submitter_txn_id");--> statement-breakpoint
CREATE INDEX "wcb_claim_details_claim_id_idx" ON "wcb_claim_details" USING btree ("claim_id");--> statement-breakpoint
CREATE INDEX "wcb_claim_details_form_claim_number_idx" ON "wcb_claim_details" USING btree ("form_id","wcb_claim_number");--> statement-breakpoint
CREATE INDEX "wcb_claim_details_parent_wcb_claim_id_idx" ON "wcb_claim_details" USING btree ("parent_wcb_claim_id");--> statement-breakpoint
CREATE INDEX "wcb_consultations_claim_detail_id_idx" ON "wcb_consultations" USING btree ("wcb_claim_detail_id");--> statement-breakpoint
CREATE INDEX "wcb_injuries_claim_detail_id_idx" ON "wcb_injuries" USING btree ("wcb_claim_detail_id");--> statement-breakpoint
CREATE INDEX "wcb_invoice_lines_claim_detail_id_idx" ON "wcb_invoice_lines" USING btree ("wcb_claim_detail_id");--> statement-breakpoint
CREATE INDEX "wcb_prescriptions_claim_detail_id_idx" ON "wcb_prescriptions" USING btree ("wcb_claim_detail_id");--> statement-breakpoint
CREATE INDEX "wcb_remittance_records_electronic_report_txn_id_idx" ON "wcb_remittance_records" USING btree ("electronic_report_txn_id");--> statement-breakpoint
CREATE INDEX "wcb_remittance_records_import_id_idx" ON "wcb_remittance_records" USING btree ("remittance_import_id");--> statement-breakpoint
CREATE INDEX "wcb_remittance_records_claim_number_idx" ON "wcb_remittance_records" USING btree ("claim_number");--> statement-breakpoint
CREATE INDEX "wcb_return_invoice_lines_return_record_id_idx" ON "wcb_return_invoice_lines" USING btree ("wcb_return_record_id");--> statement-breakpoint
CREATE INDEX "wcb_return_records_batch_id_idx" ON "wcb_return_records" USING btree ("wcb_batch_id");--> statement-breakpoint
CREATE INDEX "wcb_return_records_submitter_txn_id_idx" ON "wcb_return_records" USING btree ("submitter_txn_id");--> statement-breakpoint
CREATE INDEX "wcb_work_restrictions_claim_detail_id_idx" ON "wcb_work_restrictions" USING btree ("wcb_claim_detail_id");