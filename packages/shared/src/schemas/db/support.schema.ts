// ============================================================================
// Domain 13: Support System — Drizzle DB Schema
// ============================================================================

import {
  pgTable,
  uuid,
  varchar,
  text,
  boolean,
  timestamp,
  integer,
  jsonb,
  index,
  uniqueIndex,
  customType,
} from 'drizzle-orm/pg-core';

import { providers } from './provider.schema.js';

// --- Custom Type: PostgreSQL tsvector ---
// Drizzle has no built-in tsvector column type. We define a custom one
// so the column can be used in schema definitions and GIN indexes.

const tsvector = customType<{ data: string }>({
  dataType() {
    return 'tsvector';
  },
});

// --- Support Tickets Table ---
// Physician-submitted support requests. Physician-scoped: every query MUST
// filter by provider_id from auth context. description may contain PHI if
// the physician describes a specific patient issue — treat as sensitive.
// context_metadata may contain claim_id / batch_id (PHI-adjacent, encrypted
// at rest). screenshot_path points to encrypted storage — never expose in
// API responses.

export const supportTickets = pgTable(
  'support_tickets',
  {
    ticketId: uuid('ticket_id').primaryKey().defaultRandom(),
    providerId: uuid('provider_id')
      .notNull()
      .references(() => providers.providerId),
    subject: varchar('subject', { length: 200 }).notNull(),
    description: text('description').notNull(),
    contextUrl: varchar('context_url', { length: 500 }),
    contextMetadata: jsonb('context_metadata').$type<{
      claim_id?: string;
      batch_id?: string;
      error_codes?: string[];
      browser_info?: string;
    } | null>(),
    category: varchar('category', { length: 50 }),
    priority: varchar('priority', { length: 10 }).notNull().default('MEDIUM'),
    status: varchar('status', { length: 20 }).notNull().default('OPEN'),
    assignedTo: varchar('assigned_to', { length: 100 }),
    resolutionNotes: text('resolution_notes'),
    resolvedAt: timestamp('resolved_at', { withTimezone: true }),
    satisfactionRating: integer('satisfaction_rating'),
    satisfactionComment: text('satisfaction_comment'),
    screenshotPath: varchar('screenshot_path', { length: 255 }),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    // Physician's ticket list filtered by status
    index('support_tickets_provider_status_idx').on(
      table.providerId,
      table.status,
    ),

    // Recent tickets for a physician (descending by creation)
    index('support_tickets_provider_created_idx').on(
      table.providerId,
      table.createdAt,
    ),

    // Support team triage queue: open/urgent tickets first
    index('support_tickets_status_priority_idx').on(
      table.status,
      table.priority,
    ),

    // Agent workload: tickets assigned to a specific agent by status
    index('support_tickets_assigned_status_idx').on(
      table.assignedTo,
      table.status,
    ),
  ],
);

// --- Inferred Types ---

export type InsertSupportTicket = typeof supportTickets.$inferInsert;
export type SelectSupportTicket = typeof supportTickets.$inferSelect;

// --- Help Articles Table ---
// Public knowledge base content for the help centre. NOT PHI — articles are
// shared across all physicians and served on help.meritum.ca for SEO.
// No provider_id scoping needed. is_published controls draft vs live visibility.
// search_vector enables PostgreSQL full-text search on title + content.
// related_codes links articles to HSC, explanatory, or error codes for
// context-aware help (e.g. rejection code lookups).

export const helpArticles = pgTable(
  'help_articles',
  {
    articleId: uuid('article_id').primaryKey().defaultRandom(),
    slug: varchar('slug', { length: 200 }).notNull().unique(),
    title: varchar('title', { length: 200 }).notNull(),
    category: varchar('category', { length: 50 }).notNull(),
    content: text('content').notNull(),
    summary: varchar('summary', { length: 500 }),
    searchVector: tsvector('search_vector').notNull(),
    relatedCodes: jsonb('related_codes').$type<string[] | null>(),
    sombVersion: varchar('somb_version', { length: 20 }),
    isPublished: boolean('is_published').notNull().default(false),
    helpfulCount: integer('helpful_count').notNull().default(0),
    notHelpfulCount: integer('not_helpful_count').notNull().default(0),
    sortOrder: integer('sort_order').notNull().default(0),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    // GIN index on search_vector for full-text search
    index('help_articles_search_vector_gin_idx').using(
      'gin',
      table.searchVector,
    ),

    // Category listing: published articles sorted by display order
    index('help_articles_category_published_sort_idx').on(
      table.category,
      table.isPublished,
      table.sortOrder,
    ),

    // GIN index on related_codes for code-specific lookups
    index('help_articles_related_codes_gin_idx').using(
      'gin',
      table.relatedCodes,
    ),
  ],
);

// --- Inferred Types ---

export type InsertHelpArticle = typeof helpArticles.$inferInsert;
export type SelectHelpArticle = typeof helpArticles.$inferSelect;

// --- Article Feedback Table ---
// "Was this helpful?" votes per physician per article. Physician-scoped via
// provider_id. One vote per physician per article enforced by unique constraint.
// Used to aggregate helpful/not_helpful counts for article prioritisation.

export const articleFeedback = pgTable(
  'article_feedback',
  {
    feedbackId: uuid('feedback_id').primaryKey().defaultRandom(),
    articleId: uuid('article_id')
      .notNull()
      .references(() => helpArticles.articleId),
    providerId: uuid('provider_id')
      .notNull()
      .references(() => providers.providerId),
    isHelpful: boolean('is_helpful').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    // One feedback per physician per article
    uniqueIndex('article_feedback_article_provider_unique_idx')
      .on(table.articleId, table.providerId),

    // Aggregate counts per article
    index('article_feedback_article_idx').on(table.articleId),
  ],
);

// --- Inferred Types ---

export type InsertArticleFeedback = typeof articleFeedback.$inferInsert;
export type SelectArticleFeedback = typeof articleFeedback.$inferSelect;
