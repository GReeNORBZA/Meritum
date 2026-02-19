CREATE TABLE "ed_shifts" (
	"shift_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"provider_id" uuid NOT NULL,
	"location_id" uuid NOT NULL,
	"shift_start" timestamp with time zone NOT NULL,
	"shift_end" timestamp with time zone,
	"patient_count" integer DEFAULT 0 NOT NULL,
	"estimated_value" numeric(10, 2) DEFAULT '0' NOT NULL,
	"status" varchar(20) DEFAULT 'ACTIVE' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "favourite_codes" (
	"favourite_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"provider_id" uuid NOT NULL,
	"health_service_code" varchar(10) NOT NULL,
	"display_name" varchar(100),
	"sort_order" integer NOT NULL,
	"default_modifiers" jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "ed_shifts" ADD CONSTRAINT "ed_shifts_provider_id_providers_provider_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ed_shifts" ADD CONSTRAINT "ed_shifts_location_id_practice_locations_location_id_fk" FOREIGN KEY ("location_id") REFERENCES "public"."practice_locations"("location_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "favourite_codes" ADD CONSTRAINT "favourite_codes_provider_id_providers_provider_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "ed_shifts_provider_active_unique_idx" ON "ed_shifts" USING btree ("provider_id") WHERE status = 'ACTIVE';--> statement-breakpoint
CREATE INDEX "ed_shifts_provider_status_idx" ON "ed_shifts" USING btree ("provider_id","status");--> statement-breakpoint
CREATE INDEX "ed_shifts_provider_created_idx" ON "ed_shifts" USING btree ("provider_id","created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "favourite_codes_provider_hsc_unique_idx" ON "favourite_codes" USING btree ("provider_id","health_service_code");--> statement-breakpoint
CREATE INDEX "favourite_codes_provider_sort_idx" ON "favourite_codes" USING btree ("provider_id","sort_order");