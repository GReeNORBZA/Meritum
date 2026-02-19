CREATE TABLE "ima_records" (
	"ima_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"provider_id" uuid NOT NULL,
	"template_version" varchar(20) NOT NULL,
	"document_hash" varchar(64) NOT NULL,
	"acknowledged_at" timestamp with time zone NOT NULL,
	"ip_address" varchar(45) NOT NULL,
	"user_agent" varchar(500) NOT NULL
);
--> statement-breakpoint
CREATE TABLE "onboarding_progress" (
	"progress_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"provider_id" uuid NOT NULL,
	"step_1_completed" boolean DEFAULT false NOT NULL,
	"step_2_completed" boolean DEFAULT false NOT NULL,
	"step_3_completed" boolean DEFAULT false NOT NULL,
	"step_4_completed" boolean DEFAULT false NOT NULL,
	"step_5_completed" boolean DEFAULT false NOT NULL,
	"step_6_completed" boolean DEFAULT false NOT NULL,
	"step_7_completed" boolean DEFAULT false NOT NULL,
	"patient_import_completed" boolean DEFAULT false NOT NULL,
	"guided_tour_completed" boolean DEFAULT false NOT NULL,
	"guided_tour_dismissed" boolean DEFAULT false NOT NULL,
	"started_at" timestamp with time zone DEFAULT now() NOT NULL,
	"completed_at" timestamp with time zone,
	CONSTRAINT "onboarding_progress_provider_id_unique" UNIQUE("provider_id")
);
--> statement-breakpoint
ALTER TABLE "ima_records" ADD CONSTRAINT "ima_records_provider_id_providers_provider_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "onboarding_progress" ADD CONSTRAINT "onboarding_progress_provider_id_providers_provider_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "ima_records_provider_acknowledged_idx" ON "ima_records" USING btree ("provider_id","acknowledged_at");--> statement-breakpoint
CREATE UNIQUE INDEX "onboarding_progress_provider_id_idx" ON "onboarding_progress" USING btree ("provider_id");