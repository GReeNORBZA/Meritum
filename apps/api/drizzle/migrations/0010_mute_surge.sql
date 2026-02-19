CREATE TABLE "analytics_cache" (
	"cache_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"provider_id" uuid NOT NULL,
	"metric_key" varchar(50) NOT NULL,
	"period_start" date NOT NULL,
	"period_end" date NOT NULL,
	"dimensions" jsonb,
	"value" jsonb NOT NULL,
	"computed_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "analytics_cache_provider_metric_period_dims_uniq" UNIQUE("provider_id","metric_key","period_start","period_end","dimensions")
);
--> statement-breakpoint
CREATE TABLE "generated_reports" (
	"report_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"provider_id" uuid NOT NULL,
	"report_type" varchar(50) NOT NULL,
	"format" varchar(10) NOT NULL,
	"period_start" date,
	"period_end" date,
	"file_path" varchar(255) NOT NULL,
	"file_size_bytes" bigint NOT NULL,
	"download_link_expires_at" timestamp with time zone NOT NULL,
	"downloaded" boolean DEFAULT false NOT NULL,
	"scheduled" boolean DEFAULT false NOT NULL,
	"status" varchar(20) DEFAULT 'pending' NOT NULL,
	"error_message" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "report_subscriptions" (
	"subscription_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"provider_id" uuid NOT NULL,
	"report_type" varchar(50) NOT NULL,
	"frequency" varchar(20) NOT NULL,
	"delivery_method" varchar(20) DEFAULT 'IN_APP' NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "report_subscriptions_provider_report_type_uniq" UNIQUE("provider_id","report_type")
);
--> statement-breakpoint
ALTER TABLE "analytics_cache" ADD CONSTRAINT "analytics_cache_provider_id_providers_provider_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "generated_reports" ADD CONSTRAINT "generated_reports_provider_id_providers_provider_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "report_subscriptions" ADD CONSTRAINT "report_subscriptions_provider_id_providers_provider_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "analytics_cache_provider_metric_idx" ON "analytics_cache" USING btree ("provider_id","metric_key");--> statement-breakpoint
CREATE INDEX "analytics_cache_computed_at_idx" ON "analytics_cache" USING btree ("computed_at");--> statement-breakpoint
CREATE INDEX "generated_reports_provider_type_idx" ON "generated_reports" USING btree ("provider_id","report_type");--> statement-breakpoint
CREATE INDEX "generated_reports_provider_created_idx" ON "generated_reports" USING btree ("provider_id","created_at");--> statement-breakpoint
CREATE INDEX "generated_reports_expires_at_idx" ON "generated_reports" USING btree ("download_link_expires_at");--> statement-breakpoint
CREATE INDEX "generated_reports_status_idx" ON "generated_reports" USING btree ("status");--> statement-breakpoint
CREATE INDEX "report_subscriptions_active_frequency_idx" ON "report_subscriptions" USING btree ("is_active","frequency");