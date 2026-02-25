CREATE TABLE "practice_invitations" (
	"invitation_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"practice_id" uuid NOT NULL,
	"invited_email" varchar(255) NOT NULL,
	"invited_by_user_id" uuid NOT NULL,
	"status" varchar(20) DEFAULT 'PENDING' NOT NULL,
	"token_hash" varchar(128) NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "practice_memberships" (
	"membership_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"practice_id" uuid NOT NULL,
	"physician_user_id" uuid NOT NULL,
	"billing_mode" varchar(30) DEFAULT 'PRACTICE_CONSOLIDATED' NOT NULL,
	"joined_at" timestamp with time zone DEFAULT now() NOT NULL,
	"removed_at" timestamp with time zone,
	"removal_effective_at" timestamp with time zone,
	"is_active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "practices" (
	"practice_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" varchar(200) NOT NULL,
	"admin_user_id" uuid NOT NULL,
	"stripe_customer_id" varchar(50),
	"stripe_subscription_id" varchar(50),
	"billing_frequency" varchar(10) NOT NULL,
	"status" varchar(20) DEFAULT 'ACTIVE' NOT NULL,
	"current_period_start" timestamp with time zone NOT NULL,
	"current_period_end" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "subscriptions" ADD COLUMN "practice_id" uuid;--> statement-breakpoint
ALTER TABLE "practice_invitations" ADD CONSTRAINT "practice_invitations_practice_id_practices_practice_id_fk" FOREIGN KEY ("practice_id") REFERENCES "public"."practices"("practice_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "practice_invitations" ADD CONSTRAINT "practice_invitations_invited_by_user_id_users_user_id_fk" FOREIGN KEY ("invited_by_user_id") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "practice_memberships" ADD CONSTRAINT "practice_memberships_practice_id_practices_practice_id_fk" FOREIGN KEY ("practice_id") REFERENCES "public"."practices"("practice_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "practice_memberships" ADD CONSTRAINT "practice_memberships_physician_user_id_users_user_id_fk" FOREIGN KEY ("physician_user_id") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "practices" ADD CONSTRAINT "practices_admin_user_id_users_user_id_fk" FOREIGN KEY ("admin_user_id") REFERENCES "public"."users"("user_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "practice_invitations_practice_id_idx" ON "practice_invitations" USING btree ("practice_id");--> statement-breakpoint
CREATE INDEX "practice_invitations_token_hash_idx" ON "practice_invitations" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "practice_invitations_invited_email_idx" ON "practice_invitations" USING btree ("invited_email");--> statement-breakpoint
CREATE INDEX "practice_invitations_status_idx" ON "practice_invitations" USING btree ("status");--> statement-breakpoint
CREATE UNIQUE INDEX "practice_memberships_practice_physician_active_idx" ON "practice_memberships" USING btree ("practice_id","physician_user_id") WHERE "practice_memberships"."is_active" = true;--> statement-breakpoint
CREATE UNIQUE INDEX "practice_memberships_physician_active_idx" ON "practice_memberships" USING btree ("physician_user_id") WHERE "practice_memberships"."is_active" = true;--> statement-breakpoint
CREATE INDEX "practice_memberships_practice_active_idx" ON "practice_memberships" USING btree ("practice_id") WHERE "practice_memberships"."is_active" = true;--> statement-breakpoint
CREATE INDEX "practices_admin_user_id_idx" ON "practices" USING btree ("admin_user_id");--> statement-breakpoint
CREATE INDEX "practices_stripe_customer_id_idx" ON "practices" USING btree ("stripe_customer_id");--> statement-breakpoint
CREATE INDEX "practices_status_idx" ON "practices" USING btree ("status");--> statement-breakpoint
ALTER TABLE "subscriptions" ADD CONSTRAINT "subscriptions_practice_id_practices_practice_id_fk" FOREIGN KEY ("practice_id") REFERENCES "public"."practices"("practice_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "subscriptions_practice_id_idx" ON "subscriptions" USING btree ("practice_id");