CREATE TABLE "audit_log" (
	"log_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid,
	"action" varchar(50) NOT NULL,
	"category" varchar(20) NOT NULL,
	"resource_type" varchar(50),
	"resource_id" uuid,
	"detail" jsonb,
	"ip_address" varchar(45),
	"user_agent" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "delegate_linkages" (
	"linkage_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"physician_user_id" uuid NOT NULL,
	"delegate_user_id" uuid NOT NULL,
	"permissions" jsonb NOT NULL,
	"can_approve_batches" boolean DEFAULT false NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "invitation_tokens" (
	"invitation_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"physician_user_id" uuid NOT NULL,
	"delegate_email" varchar(255) NOT NULL,
	"token_hash" varchar(255) NOT NULL,
	"permissions" jsonb NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"accepted" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "recovery_codes" (
	"code_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"code_hash" varchar(255) NOT NULL,
	"used" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "sessions" (
	"session_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"token_hash" varchar(255) NOT NULL,
	"ip_address" varchar(45) NOT NULL,
	"user_agent" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_active_at" timestamp with time zone DEFAULT now() NOT NULL,
	"revoked" boolean DEFAULT false NOT NULL,
	"revoked_reason" varchar(30)
);
--> statement-breakpoint
CREATE TABLE "users" (
	"user_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"email" varchar(255) NOT NULL,
	"password_hash" varchar(255) NOT NULL,
	"full_name" varchar(200) NOT NULL,
	"phone" varchar(20),
	"role" varchar(20) DEFAULT 'physician' NOT NULL,
	"email_verified" boolean DEFAULT false NOT NULL,
	"mfa_configured" boolean DEFAULT false NOT NULL,
	"totp_secret_encrypted" text,
	"subscription_status" varchar(20) DEFAULT 'trial' NOT NULL,
	"failed_login_count" integer DEFAULT 0 NOT NULL,
	"locked_until" timestamp with time zone,
	"is_active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "audit_log" ADD CONSTRAINT "audit_log_user_id_users_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "delegate_linkages" ADD CONSTRAINT "delegate_linkages_physician_user_id_users_user_id_fk" FOREIGN KEY ("physician_user_id") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "delegate_linkages" ADD CONSTRAINT "delegate_linkages_delegate_user_id_users_user_id_fk" FOREIGN KEY ("delegate_user_id") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "invitation_tokens" ADD CONSTRAINT "invitation_tokens_physician_user_id_users_user_id_fk" FOREIGN KEY ("physician_user_id") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "recovery_codes" ADD CONSTRAINT "recovery_codes_user_id_users_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_user_id_users_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "audit_log_user_id_created_at_idx" ON "audit_log" USING btree ("user_id","created_at");--> statement-breakpoint
CREATE INDEX "audit_log_action_created_at_idx" ON "audit_log" USING btree ("action","created_at");--> statement-breakpoint
CREATE INDEX "audit_log_resource_type_resource_id_created_at_idx" ON "audit_log" USING btree ("resource_type","resource_id","created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "delegate_linkages_physician_delegate_idx" ON "delegate_linkages" USING btree ("physician_user_id","delegate_user_id");--> statement-breakpoint
CREATE INDEX "delegate_linkages_delegate_is_active_idx" ON "delegate_linkages" USING btree ("delegate_user_id","is_active");--> statement-breakpoint
CREATE UNIQUE INDEX "invitation_tokens_token_hash_idx" ON "invitation_tokens" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "invitation_tokens_physician_accepted_idx" ON "invitation_tokens" USING btree ("physician_user_id","accepted");--> statement-breakpoint
CREATE INDEX "recovery_codes_user_id_used_idx" ON "recovery_codes" USING btree ("user_id","used");--> statement-breakpoint
CREATE UNIQUE INDEX "sessions_token_hash_idx" ON "sessions" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "sessions_user_id_revoked_idx" ON "sessions" USING btree ("user_id","revoked");--> statement-breakpoint
CREATE INDEX "sessions_last_active_at_idx" ON "sessions" USING btree ("last_active_at");--> statement-breakpoint
CREATE UNIQUE INDEX "users_email_idx" ON "users" USING btree ("email");--> statement-breakpoint
CREATE INDEX "users_role_is_active_idx" ON "users" USING btree ("role","is_active");--> statement-breakpoint
CREATE INDEX "users_subscription_status_idx" ON "users" USING btree ("subscription_status");