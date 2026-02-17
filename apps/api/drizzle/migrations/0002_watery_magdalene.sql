CREATE TABLE "digest_queue" (
	"queue_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"recipient_id" uuid NOT NULL,
	"notification_id" uuid NOT NULL,
	"digest_type" varchar(20) NOT NULL,
	"digest_sent" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "email_delivery_log" (
	"delivery_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"notification_id" uuid NOT NULL,
	"recipient_email" varchar(100) NOT NULL,
	"template_id" varchar(50) NOT NULL,
	"status" varchar(20) DEFAULT 'QUEUED' NOT NULL,
	"provider_message_id" varchar(100),
	"sent_at" timestamp with time zone,
	"delivered_at" timestamp with time zone,
	"bounced_at" timestamp with time zone,
	"bounce_reason" text,
	"retry_count" integer DEFAULT 0 NOT NULL,
	"next_retry_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "notification_preferences" (
	"preference_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"provider_id" uuid NOT NULL,
	"event_category" varchar(50) NOT NULL,
	"in_app_enabled" boolean DEFAULT true NOT NULL,
	"email_enabled" boolean NOT NULL,
	"digest_mode" varchar(20) DEFAULT 'IMMEDIATE' NOT NULL,
	"quiet_hours_start" time,
	"quiet_hours_end" time,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "notification_templates" (
	"template_id" varchar(50) PRIMARY KEY NOT NULL,
	"in_app_title" varchar(200) NOT NULL,
	"in_app_body" text NOT NULL,
	"email_subject" varchar(200),
	"email_html_body" text,
	"email_text_body" text,
	"action_url_template" varchar(500),
	"action_label" varchar(50),
	"variables" jsonb NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "notifications" (
	"notification_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"recipient_id" uuid NOT NULL,
	"physician_context_id" uuid,
	"event_type" varchar(50) NOT NULL,
	"priority" varchar(10) NOT NULL,
	"title" varchar(200) NOT NULL,
	"body" text NOT NULL,
	"action_url" varchar(500),
	"action_label" varchar(50),
	"metadata" jsonb,
	"channels_delivered" jsonb NOT NULL,
	"read_at" timestamp with time zone,
	"dismissed_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "digest_queue" ADD CONSTRAINT "digest_queue_recipient_id_users_user_id_fk" FOREIGN KEY ("recipient_id") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "digest_queue" ADD CONSTRAINT "digest_queue_notification_id_notifications_notification_id_fk" FOREIGN KEY ("notification_id") REFERENCES "public"."notifications"("notification_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "email_delivery_log" ADD CONSTRAINT "email_delivery_log_notification_id_notifications_notification_id_fk" FOREIGN KEY ("notification_id") REFERENCES "public"."notifications"("notification_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "notification_preferences" ADD CONSTRAINT "notification_preferences_provider_id_users_user_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "notifications" ADD CONSTRAINT "notifications_recipient_id_users_user_id_fk" FOREIGN KEY ("recipient_id") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "digest_queue_recipient_sent_type_idx" ON "digest_queue" USING btree ("recipient_id","digest_sent","digest_type");--> statement-breakpoint
CREATE INDEX "digest_queue_created_at_idx" ON "digest_queue" USING btree ("created_at");--> statement-breakpoint
CREATE INDEX "email_delivery_log_notification_id_idx" ON "email_delivery_log" USING btree ("notification_id");--> statement-breakpoint
CREATE INDEX "email_delivery_log_status_next_retry_at_idx" ON "email_delivery_log" USING btree ("status","next_retry_at");--> statement-breakpoint
CREATE INDEX "email_delivery_log_recipient_email_created_at_idx" ON "email_delivery_log" USING btree ("recipient_email","created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "notification_preferences_provider_category_idx" ON "notification_preferences" USING btree ("provider_id","event_category");--> statement-breakpoint
CREATE INDEX "notification_preferences_provider_id_idx" ON "notification_preferences" USING btree ("provider_id");--> statement-breakpoint
CREATE INDEX "notifications_recipient_read_at_idx" ON "notifications" USING btree ("recipient_id","read_at");--> statement-breakpoint
CREATE INDEX "notifications_recipient_created_at_idx" ON "notifications" USING btree ("recipient_id","created_at");--> statement-breakpoint
CREATE INDEX "notifications_event_type_created_at_idx" ON "notifications" USING btree ("event_type","created_at");