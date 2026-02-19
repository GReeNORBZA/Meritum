CREATE TABLE "article_feedback" (
	"feedback_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"article_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
	"is_helpful" boolean NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "help_articles" (
	"article_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"slug" varchar(200) NOT NULL,
	"title" varchar(200) NOT NULL,
	"category" varchar(50) NOT NULL,
	"content" text NOT NULL,
	"summary" varchar(500),
	"search_vector" "tsvector" NOT NULL,
	"related_codes" jsonb,
	"somb_version" varchar(20),
	"is_published" boolean DEFAULT false NOT NULL,
	"helpful_count" integer DEFAULT 0 NOT NULL,
	"not_helpful_count" integer DEFAULT 0 NOT NULL,
	"sort_order" integer DEFAULT 0 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "help_articles_slug_unique" UNIQUE("slug")
);
--> statement-breakpoint
CREATE TABLE "support_tickets" (
	"ticket_id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"provider_id" uuid NOT NULL,
	"subject" varchar(200) NOT NULL,
	"description" text NOT NULL,
	"context_url" varchar(500),
	"context_metadata" jsonb,
	"category" varchar(50),
	"priority" varchar(10) DEFAULT 'MEDIUM' NOT NULL,
	"status" varchar(20) DEFAULT 'OPEN' NOT NULL,
	"assigned_to" varchar(100),
	"resolution_notes" text,
	"resolved_at" timestamp with time zone,
	"satisfaction_rating" integer,
	"satisfaction_comment" text,
	"screenshot_path" varchar(255),
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "article_feedback" ADD CONSTRAINT "article_feedback_article_id_help_articles_article_id_fk" FOREIGN KEY ("article_id") REFERENCES "public"."help_articles"("article_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "article_feedback" ADD CONSTRAINT "article_feedback_provider_id_providers_provider_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "support_tickets" ADD CONSTRAINT "support_tickets_provider_id_providers_provider_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."providers"("provider_id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "article_feedback_article_provider_unique_idx" ON "article_feedback" USING btree ("article_id","provider_id");--> statement-breakpoint
CREATE INDEX "article_feedback_article_idx" ON "article_feedback" USING btree ("article_id");--> statement-breakpoint
CREATE INDEX "help_articles_search_vector_gin_idx" ON "help_articles" USING gin ("search_vector");--> statement-breakpoint
CREATE INDEX "help_articles_category_published_sort_idx" ON "help_articles" USING btree ("category","is_published","sort_order");--> statement-breakpoint
CREATE INDEX "help_articles_related_codes_gin_idx" ON "help_articles" USING gin ("related_codes");--> statement-breakpoint
CREATE INDEX "support_tickets_provider_status_idx" ON "support_tickets" USING btree ("provider_id","status");--> statement-breakpoint
CREATE INDEX "support_tickets_provider_created_idx" ON "support_tickets" USING btree ("provider_id","created_at");--> statement-breakpoint
CREATE INDEX "support_tickets_status_priority_idx" ON "support_tickets" USING btree ("status","priority");--> statement-breakpoint
CREATE INDEX "support_tickets_assigned_status_idx" ON "support_tickets" USING btree ("assigned_to","status");--> statement-breakpoint
CREATE OR REPLACE FUNCTION update_article_search_vector() RETURNS trigger AS $$
BEGIN
  NEW.search_vector := to_tsvector('english', COALESCE(NEW.title, '') || ' ' || COALESCE(NEW.content, ''));
  RETURN NEW;
END
$$ LANGUAGE plpgsql;--> statement-breakpoint
CREATE TRIGGER articles_search_vector_update
  BEFORE INSERT OR UPDATE ON help_articles
  FOR EACH ROW EXECUTE FUNCTION update_article_search_vector();