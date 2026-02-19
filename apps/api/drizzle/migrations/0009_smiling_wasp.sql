CREATE TABLE "ai_provider_learning" (
	"learning_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"provider_id" uuid NOT NULL,
	"rule_id" uuid NOT NULL,
	"times_shown" integer DEFAULT 0 NOT NULL,
	"times_accepted" integer DEFAULT 0 NOT NULL,
	"times_dismissed" integer DEFAULT 0 NOT NULL,
	"consecutive_dismissals" integer DEFAULT 0 NOT NULL,
	"is_suppressed" boolean DEFAULT false NOT NULL,
	"priority_adjustment" integer DEFAULT 0 NOT NULL,
	"last_shown_at" timestamp with time zone,
	"last_feedback_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "ai_provider_learning_provider_rule_uniq" UNIQUE("provider_id","rule_id")
);
--> statement-breakpoint
CREATE TABLE "ai_rules" (
	"rule_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" varchar(100) NOT NULL,
	"category" varchar(30) NOT NULL,
	"claim_type" varchar(10) NOT NULL,
	"conditions" jsonb NOT NULL,
	"suggestion_template" jsonb NOT NULL,
	"specialty_filter" jsonb,
	"priority_formula" varchar(100) NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"somb_version" varchar(20),
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "ai_specialty_cohorts" (
	"cohort_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"specialty_code" varchar(10) NOT NULL,
	"rule_id" uuid NOT NULL,
	"physician_count" integer NOT NULL,
	"acceptance_rate" numeric(5, 4) NOT NULL,
	"median_revenue_impact" numeric(10, 2),
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "ai_specialty_cohorts_specialty_rule_uniq" UNIQUE("specialty_code","rule_id")
);
--> statement-breakpoint
CREATE TABLE "ai_suggestion_events" (
	"event_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"claim_id" uuid NOT NULL,
	"suggestion_id" uuid NOT NULL,
	"rule_id" uuid,
	"provider_id" uuid NOT NULL,
	"event_type" varchar(20) NOT NULL,
	"tier" integer NOT NULL,
	"category" varchar(30) NOT NULL,
	"revenue_impact" numeric(10, 2),
	"dismissed_reason" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "wcb_remittance_imports" (
	"remittance_import_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"physician_id" uuid NOT NULL,
	"record_count" integer DEFAULT 0 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "ai_provider_learning" ADD CONSTRAINT "ai_provider_learning_rule_id_ai_rules_rule_id_fk" FOREIGN KEY ("rule_id") REFERENCES "public"."ai_rules"("rule_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ai_specialty_cohorts" ADD CONSTRAINT "ai_specialty_cohorts_rule_id_ai_rules_rule_id_fk" FOREIGN KEY ("rule_id") REFERENCES "public"."ai_rules"("rule_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ai_suggestion_events" ADD CONSTRAINT "ai_suggestion_events_claim_id_claims_claim_id_fk" FOREIGN KEY ("claim_id") REFERENCES "public"."claims"("claim_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ai_suggestion_events" ADD CONSTRAINT "ai_suggestion_events_rule_id_ai_rules_rule_id_fk" FOREIGN KEY ("rule_id") REFERENCES "public"."ai_rules"("rule_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ai_suggestion_events" ADD CONSTRAINT "ai_suggestion_events_provider_id_providers_provider_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "wcb_remittance_imports" ADD CONSTRAINT "wcb_remittance_imports_physician_id_providers_provider_id_fk" FOREIGN KEY ("physician_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "ai_provider_learning_provider_suppressed_idx" ON "ai_provider_learning" USING btree ("provider_id","is_suppressed");--> statement-breakpoint
CREATE INDEX "ai_provider_learning_rule_idx" ON "ai_provider_learning" USING btree ("rule_id");--> statement-breakpoint
CREATE INDEX "ai_rules_category_active_idx" ON "ai_rules" USING btree ("category","is_active");--> statement-breakpoint
CREATE INDEX "ai_rules_claim_type_active_idx" ON "ai_rules" USING btree ("claim_type","is_active");--> statement-breakpoint
CREATE INDEX "ai_rules_somb_version_idx" ON "ai_rules" USING btree ("somb_version");--> statement-breakpoint
CREATE INDEX "ai_specialty_cohorts_specialty_idx" ON "ai_specialty_cohorts" USING btree ("specialty_code");--> statement-breakpoint
CREATE INDEX "ai_suggestion_events_claim_idx" ON "ai_suggestion_events" USING btree ("claim_id");--> statement-breakpoint
CREATE INDEX "ai_suggestion_events_provider_created_idx" ON "ai_suggestion_events" USING btree ("provider_id","created_at");--> statement-breakpoint
CREATE INDEX "ai_suggestion_events_rule_event_idx" ON "ai_suggestion_events" USING btree ("rule_id","event_type");--> statement-breakpoint
CREATE INDEX "ai_suggestion_events_category_created_idx" ON "ai_suggestion_events" USING btree ("category","created_at");--> statement-breakpoint
CREATE INDEX "wcb_remittance_imports_physician_id_idx" ON "wcb_remittance_imports" USING btree ("physician_id");--> statement-breakpoint
ALTER TABLE "wcb_remittance_records" ADD CONSTRAINT "wcb_remittance_records_remittance_import_id_wcb_remittance_imports_remittance_import_id_fk" FOREIGN KEY ("remittance_import_id") REFERENCES "public"."wcb_remittance_imports"("remittance_import_id") ON DELETE no action ON UPDATE no action;