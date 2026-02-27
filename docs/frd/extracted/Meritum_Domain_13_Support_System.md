# Meritum_Domain_13_Support_System

MERITUM

Functional Requirements

Support System

Domain 13 of 13  |  Help & Support Infrastructure

Meritum Health Technologies Inc.

Version 2.0  |  February 2026

CONFIDENTIAL

# Table of Contents

1. [Domain Overview](#1-domain-overview)
2. [Help Centre](#2-help-centre)
3. [Email Support (MVP)](#3-email-support-mvp)
4. [AI Support Chat (Phase 1.5)](#4-ai-support-chat-phase-15)
5. [User Stories & Acceptance Criteria](#5-user-stories--acceptance-criteria)
6. [API Contracts](#6-api-contracts)
7. [Data Model](#7-data-model)
8. [Article Content System](#8-article-content-system)
9. [Module Architecture](#9-module-architecture)
10. [Testing Requirements](#10-testing-requirements)
11. [Open Questions](#11-open-questions)
12. [Document Control](#12-document-control)

# 1. Domain Overview

## 1.1 Purpose

The Support System domain provides physicians with help when the contextual help, tooltips, and AI Coach are not sufficient. It operates in two phases: email-based support at MVP, and AI-assisted support chat at Phase 1.5 after real support queries have been collected to calibrate the system.

The strategic approach is deliberately conservative: launch with humans answering questions, collect the questions, use the data to build an AI support layer that answers the questions physicians actually ask -- not the questions we think they'll ask.

## 1.2 Scope

Help centre: structured knowledge base with 43 articles across 6 categories covering common billing scenarios, platform features, and troubleshooting.

Email support: support@meritum.ca for questions not answered by help centre or contextual help.

Support ticket tracking: physician-facing ticket creation, listing, and satisfaction rating. Internal support team triage queue with SLA breach detection.

In-app support access: 'Help' button accessible from every page, context-aware (passes current page URL and metadata to support). Context-aware routing maps page URLs to relevant help categories and rejection/explanatory codes to related articles.

FAQ surfacing: common questions identified from support tickets promoted to help centre.

Article feedback: 'Was this helpful?' on every article. Per-physician feedback tracked with aggregate helpful/not-helpful counters for article prioritisation.

Full-text search: PostgreSQL tsvector-based full-text search across all articles with GIN index and ts_rank relevance ordering.

AI support chat (Phase 1.5): RAG-based chat using same self-hosted LLM as AI Coach, trained on help centre content and historical support queries. Constants defined but feature disabled (`AI_CHAT_ENABLED = false`).

## 1.3 Out of Scope

Phone support (not viable at Meritum's scale and price point).

Live chat with human agents (Phase 2+ consideration).

Community forums (Phase 2+ consideration; requires critical mass of users).

Clinical billing advice (Meritum provides platform support, not billing consulting).

## 1.4 Domain Dependencies

| Domain | Direction | Interface |
| --- | --- | --- |
| 1 Identity & Access | Consumed | User authentication for in-app support access. Support tickets linked to user accounts. Feedback submission requires authentication. |
| 2 Reference Data | Consumed | Help centre content references SOMB sections, governing rules. Tooltip content sourced from Reference Data. Articles linked to HSC and explanatory codes via `related_codes`. |
| 5 Provider Management | Consumed | `provider_id` foreign key on `support_tickets` and `article_feedback` tables. Physician scoping on all ticket queries. |
| 7 Intelligence Engine | Infrastructure shared | Same self-hosted LLM infrastructure used for AI support chat (Phase 1.5). AI chat confidence threshold set at 0.70. |
| 9 Notification Service | Consumed | Support ticket status updates delivered via notification (ticket created, resolved, status changed). |
| 12 Platform Operations | Consumed | Screenshot file upload to DigitalOcean Spaces via file storage interface. |

# 2. Help Centre

## 2.1 Content Structure

The help centre is a structured knowledge base accessible from within Meritum and as a public web page (help.meritum.ca). Content is organised by category. The implementation supports 7 categories in the database schema (via `HelpCategory` constants) and 6 categories in the article file system:

**Database categories** (used for API filtering and context-aware routing):

| Category Constant | Description |
| --- | --- |
| `GETTING_STARTED` | Onboarding, profile setup, first submission |
| `AHCIP_BILLING` | AHCIP claim creation, editing, submission |
| `WCB_BILLING` | WCB claim workflows, timing tiers |
| `MODIFIERS_AND_RULES` | Modifiers, governing rules, time premiums |
| `AI_COACH` | AI Coach features, suggestions, confidence |
| `ACCOUNT_AND_BILLING` | Subscription, payment, delegates, data export |
| `TROUBLESHOOTING` | Common errors, batch failures, assessments |

**Article file system categories** (43 articles across 6 directories):

| Category | Articles | Example Topics |
| --- | --- | --- |
| getting-started | 7 | Setting up your professional profile, Adding BA numbers, Configuring practice locations, Setting up WCB billing, Inviting a delegate, Choosing submission preferences, Your first Thursday submission |
| submitting-claims | 9 | Importing encounters from EMR, Mobile claim entry, Creating claims manually, Understanding flags and suggestions, How the rules engine works, How the advice engine works, Thursday submission cycle, Submission preferences, Submitting WCB claims |
| after-submission | 4 | Understanding assessment results, Reading rejection codes, Correcting and resubmitting refused claims, Tracking rejection patterns |
| billing-reference | 10 | AHCIP fee-for-service billing, Thursday submission cycle explained, Understanding the SOMB, RRNP, PCPCM, WCB Alberta billing, After-hours billing and time premiums, Common explanatory codes, Business arrangements, H-Link explained |
| your-account | 8 | Understanding your subscription, Switching billing plans, Managing your practice account, Referral program, Cancelling subscription, Exporting data, Updating profile, Managing delegates |
| security-compliance | 5 | How Meritum protects your data, HIA compliance and IMA, Canadian data residency, Delegate access and data separation, Practice admin access boundaries |

## 2.2 Content Principles

Plain language: No jargon without explanation. Written for physicians, not billing consultants.

Task-oriented: Articles answer 'How do I...' questions. Steps are numbered.

Searchable: Full-text search across all articles using PostgreSQL `tsvector` with GIN index. Search results ranked by `ts_rank` relevance. Search queries sanitised to strip tsquery special characters (`& | ! ( ) : * < >`), trimmed, and limited to 200 characters.

Versioned: Articles reference SOMB versions (stored in `somb_version` column) and are updated when rules change.

Feedback loop: 'Was this helpful?' on every article. Per-physician feedback stored in `article_feedback` table (one vote per physician per article, upsert on conflict). Aggregate `helpful_count` and `not_helpful_count` maintained on the article record. Low-rated articles prioritised for rewrite.

Code-linked: Articles can be linked to HSC, explanatory, or error codes via the `related_codes` JSONB array. This enables rejection code lookups -- when a physician views a rejected claim, the system can surface articles explaining that specific code.

## 2.3 Context-Aware Help

When a physician clicks 'Help' from within Meritum, the help centre opens with context. The implementation uses a URL pattern matching system defined in `CONTEXT_HELP_MAPPINGS`:

| URL Pattern | Mapped Category | Description |
| --- | --- | --- |
| `/claims/new` | `AHCIP_BILLING` | New claim creation |
| `/claims/*/edit` | `AHCIP_BILLING` | Claim editing |
| `/claims/*/rejected` | *(code lookup)* | Rejected claim -- search by rejection code from `context_metadata` |
| `/wcb/*` | `WCB_BILLING` | WCB billing pages |
| `/settings/*` | `ACCOUNT_AND_BILLING` | Account settings |
| `/analytics/*` | `GETTING_STARTED` | Analytics help |
| `/onboarding/*` | `GETTING_STARTED` | Onboarding help |

The resolution algorithm:

1. Match `contextUrl` against `CONTEXT_HELP_MAPPINGS` patterns (wildcard `*` matches one or more path segments).
2. If matched to a category: return published articles in that category, ordered by `sort_order`.
3. If `contextMetadata` contains a `rejection_code`, `explanatory_code`, or `error_codes`: search articles by `related_codes` JSONB containment (`@>`).
4. If no match: return search page URL (`/help/search`).

Context is passed via URL parameter. If no specific context is available, the help centre opens to the search page.

# 3. Email Support (MVP)

## 3.1 Support Email Flow

Physician clicks 'Contact Support' from help centre or in-app help button.

Support form opens with context pre-filled: current page URL (`context_url`), optional auto-captured metadata (`context_metadata` containing `claim_id`, `batch_id`, `error_codes`, `browser_info`).

Physician enters subject (max 200 characters) and description (max 5,000 characters, HTML tags stripped server-side). Optional screenshot upload (PNG, JPEG, or WebP; max 5 MB; validated via magic bytes detection, not client-declared MIME type).

Support ticket created with status `OPEN` and default priority `MEDIUM`. If `context_metadata` indicates a batch failure (presence of `batch_error` key, or `batch_id` with `error_codes` or `error`), priority is auto-escalated to `URGENT`.

Confirmation notification sent to physician (email + in-app) via Notification Service. Notification contains ticket ID and subject only -- no PHI.

Support team triages via admin triage queue (filterable by status, priority, category, assigned agent). Agent updates ticket status, category, priority, assignment, and resolution notes.

Resolution tracked. Physician notified of status changes and resolution via notification. `resolved_at` timestamp auto-set when status transitions to `RESOLVED`.

After resolution, physician prompted for 1--5 star satisfaction rating with optional comment (max 1,000 characters).

## 3.2 Support Ticket Model

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| `ticket_id` | UUID | No | Primary key (auto-generated) |
| `provider_id` | UUID FK | No | FK to `providers`. All physician queries scoped by this column. |
| `subject` | VARCHAR(200) | No | Subject line (auto-generated from context or physician-entered) |
| `description` | TEXT | No | Physician's description of the issue. HTML tags stripped. May contain PHI. |
| `context_url` | VARCHAR(500) | Yes | Page URL where 'Help' was clicked. Must be HTTPS. |
| `context_metadata` | JSONB | Yes | Auto-captured context: `claim_id`, `batch_id`, `error_codes`, `browser_info` |
| `category` | VARCHAR(50) | Yes | Categorised by support team: `BILLING`, `TECHNICAL`, `ACCOUNT`, `FEATURE_REQUEST` |
| `priority` | VARCHAR(10) | No | `LOW`, `MEDIUM`, `HIGH`, `URGENT`. Default: `MEDIUM`. Auto-escalated to `URGENT` for batch failures. |
| `status` | VARCHAR(20) | No | `OPEN`, `IN_PROGRESS`, `WAITING_ON_CUSTOMER`, `RESOLVED`, `CLOSED` |
| `assigned_to` | VARCHAR(100) | Yes | Support team member handling the ticket |
| `resolution_notes` | TEXT | Yes | How the issue was resolved. HTML tags stripped. |
| `resolved_at` | TIMESTAMPTZ | Yes | Auto-set when status transitions to `RESOLVED` |
| `satisfaction_rating` | INTEGER | Yes | 1--5 star rating from physician after resolution |
| `satisfaction_comment` | TEXT | Yes | Optional comment accompanying the satisfaction rating |
| `screenshot_path` | VARCHAR(255) | Yes | Path to uploaded screenshot in encrypted storage. Never exposed in API responses. |
| `created_at` | TIMESTAMPTZ | No | Ticket creation timestamp |
| `updated_at` | TIMESTAMPTZ | No | Last modification timestamp |

**Database indexes:**

- `support_tickets_provider_status_idx` on (`provider_id`, `status`) -- physician ticket list
- `support_tickets_provider_created_idx` on (`provider_id`, `created_at`) -- recent tickets
- `support_tickets_status_priority_idx` on (`status`, `priority`) -- triage queue
- `support_tickets_assigned_status_idx` on (`assigned_to`, `status`) -- agent workload

## 3.3 Ticket Status Workflow

```
OPEN --> IN_PROGRESS --> WAITING_ON_CUSTOMER --> IN_PROGRESS (cycle)
                    |                       |
                    +--> RESOLVED ----------+--> RESOLVED --> CLOSED
```

Valid transitions enforced by the service layer:

| Current Status | Allowed Next Statuses |
| --- | --- |
| `OPEN` | `IN_PROGRESS` |
| `IN_PROGRESS` | `WAITING_ON_CUSTOMER`, `RESOLVED` |
| `WAITING_ON_CUSTOMER` | `IN_PROGRESS`, `RESOLVED` |
| `RESOLVED` | `CLOSED` |
| `CLOSED` | *(terminal -- no transitions)* |

Invalid transitions return HTTP 422 (Business Rule Violation).

## 3.4 SLA Targets

Business hours: Monday--Friday 08:00--18:00 MT. Thursday extended hours (06:00--22:00 MT) to cover batch submission cycle.

SLA calculations use business minutes computed by iterating through calendar time, counting only minutes within business hours for the applicable day. Weekend and after-hours periods are excluded.

| Priority | First Response | Resolution Target |
| --- | --- | --- |
| `URGENT` | < 2 hours (120 business minutes) | < 4 hours (240 business minutes). Batch failures and submission-blocking issues. |
| `HIGH` | < 4 hours (240 business minutes) | < 1 business day (600 business minutes) |
| `MEDIUM` | < 1 business day (600 business minutes) | < 3 business days (1,800 business minutes) |
| `LOW` | < 2 business days (1,200 business minutes) | < 5 business days (3,000 business minutes) |

**SLA breach detection:** The repository provides a `getSlaBreach()` method that scans all non-closed, non-resolved tickets and compares elapsed business minutes against SLA targets. Breach types are reported as `first_response` (ticket still in `OPEN` status past first response target) or `resolution` (any active ticket past resolution target).

## 3.5 Screenshot Handling

Screenshots are validated at two levels:

1. **Route-level validation** (multipart upload): magic bytes detection for PNG (`89 50 4E 47`), JPEG (`FF D8 FF`), and WebP (`RIFF....WEBP`). Client-declared MIME type is ignored -- server determines type from file content. Maximum 5 MB.

2. **Service-level validation**: redundant check of MIME type and file size before storage.

Screenshots are uploaded to DigitalOcean Spaces at path `support-tickets/{ticket_id}/screenshot.{ext}`. The `screenshot_path` column is never included in API responses -- the route layer and service layer both strip this field from all ticket responses as defense-in-depth.

# 4. AI Support Chat (Phase 1.5)

After 3--6 months of email support operation, Meritum will have collected enough real physician questions to calibrate an AI support chat. This chat uses the same self-hosted LLM infrastructure as the AI Coach (Domain 7). The feature is defined in constants (`AI_CHAT_CONFIDENCE_THRESHOLD = 0.70`, `AI_CHAT_ENABLED = false`) but not yet implemented.

## 4.1 Architecture

RAG (Retrieval-Augmented Generation): Help centre articles indexed as vector embeddings. Physician question matched to relevant articles. LLM generates answer grounded in retrieved content.

Historical query training: Common support ticket questions and their resolutions used to fine-tune or few-shot the LLM for platform-specific terminology.

Escalation path: If the AI cannot answer confidently (confidence < 0.70 or physician indicates dissatisfaction), the conversation is escalated to email support with full chat history attached.

No PHI in chat: AI support chat does not access the physician's claims, patients, or billing data. It answers 'How do I...' and 'What does X mean?' questions. For account-specific issues, the AI directs the physician to email support.

## 4.2 Chat Capabilities

Platform how-to: 'How do I add a modifier?' 'How does the Thursday batch work?'

Billing concept explanation: 'What is GR 3?' 'What does explanatory code 101 mean?'

Troubleshooting guidance: 'My claim was rejected with code X. What should I do?'

Feature discovery: 'Can I import patients from a CSV?' 'Does Meritum support WCB?'

Not in scope: 'Why was my specific claim rejected?' (requires PHI access), 'Should I bill code X or Y for this patient?' (clinical advice).

## 4.3 MVP Accommodations for Phase 1.5

Chat UI component designed and placeholder visible in navigation (greyed out with 'Coming soon' label).

Support ticket categorisation captures data for future training.

Help centre article structure supports vector embedding generation (full-text `content` column, `search_vector` tsvector, `related_codes` for semantic linking).

LLM infrastructure from Domain 7 includes capacity for support chat workload.

# 5. User Stories & Acceptance Criteria

| ID | Story | Acceptance Criteria |
| --- | --- | --- |
| SUP-001 | As a physician, I want to search the help centre for answers | Search bar on help centre. Full-text search via `tsvector` with `ts_rank` relevance ordering. Results include `articleId`, `slug`, `title`, `category`, `summary`, and `rank`. Clickable articles. Search queries sanitised (special characters stripped, max 200 chars). |
| SUP-002 | As a physician, I want context-aware help when I click the help button | Help button on every page. Opens help centre filtered to relevant category based on current page URL matching against `CONTEXT_HELP_MAPPINGS`. Rejected claim pages search by rejection code via `related_codes`. Falls back to search page if no match. |
| SUP-003 | As a physician, I want to contact support when the help centre doesn't answer my question | Support form from help centre. Context pre-filled (`context_url`, `context_metadata`). Subject (max 200 chars) + description (max 5,000 chars, HTML stripped) + optional screenshot (PNG/JPEG/WebP, max 5 MB, magic bytes validated). Confirmation notification sent. Ticket created with status `OPEN`. Batch failures auto-escalated to `URGENT`. |
| SUP-004 | As a physician, I want to know when my support ticket is resolved | In-app notification + email when status changes to `RESOLVED`. Separate notifications for other status transitions. Notifications contain ticket ID and subject only -- no PHI. |
| SUP-005 | As a physician, I want to rate the support I received | After ticket resolution (`RESOLVED` or `CLOSED` status), prompt for 1--5 star rating. Optional comment (max 1,000 chars). Stored on ticket. Rating submission on non-resolved/closed tickets returns 400. |
| SUP-006 | As a physician, I want to look up what a rejection code means | Help centre search for rejection/explanatory code returns articles where `related_codes` JSONB array contains the code. Context-aware help automatically searches by code from `context_metadata`. |
| SUP-007 | As a physician, I want to list my support tickets | Paginated list of own tickets filtered by status. Ordered by `created_at` descending. `screenshot_path` stripped from responses. |
| SUP-008 | As a physician, I want to provide feedback on help articles | 'Was this helpful?' button on every article. One vote per physician per article (upsert). Aggregate counters updated atomically. Requires authentication. |

# 6. API Contracts

## 6.1 Help Centre Endpoints

| Method | Endpoint | Auth | Description |
| --- | --- | --- | --- |
| GET | `/api/v1/help/articles` | Public | List or search help centre articles. Query params: `category` (enum), `search` (string, max 200), `limit` (1--50, default 20), `offset` (min 0, default 0). Returns `{ data: ArticleListItem[] }` or `{ data: ArticleSearchResult[] }`. Requires at least `category` or `search`; returns empty array if neither provided. |
| GET | `/api/v1/help/articles/:slug` | Public | Get article content by slug. Slug validated as lowercase alphanumeric with hyphens. Returns `{ data: HelpArticle }` or 404. |
| POST | `/api/v1/help/articles/:slug/feedback` | Authenticated | Submit 'Was this helpful?' feedback. Body: `{ is_helpful: boolean }`. Returns `{ data: { success: true } }` or 404 if article not found. |

**Article Search Result shape:**

```typescript
{
  articleId: string;   // UUID
  slug: string;
  title: string;
  category: string;
  summary: string | null;
  rank: number;        // ts_rank relevance score
}
```

**Article List Item shape:**

```typescript
{
  articleId: string;   // UUID
  slug: string;
  title: string;
  summary: string | null;
}
```

## 6.2 Support Ticket Endpoints

| Method | Endpoint | Auth | Description |
| --- | --- | --- | --- |
| POST | `/api/v1/support/tickets` | Authenticated | Create a support ticket. Accepts JSON or multipart/form-data (for screenshot upload). Body: `{ subject, description, context_url?, context_metadata?, priority? }`. Optional `screenshot` file field in multipart. Returns `{ data: Ticket }` (201). `screenshot_path` stripped from response. |
| GET | `/api/v1/support/tickets` | Authenticated | List physician's support tickets. Query params: `status` (enum), `limit` (1--50, default 20), `offset` (min 0, default 0). Returns `{ data: Ticket[], pagination: { total, page, pageSize, hasMore } }`. `screenshot_path` stripped. |
| GET | `/api/v1/support/tickets/:id` | Authenticated | Get ticket details by UUID. Returns `{ data: Ticket }` or 404. `screenshot_path` stripped. Returns 404 for other physicians' tickets (no existence confirmation). |
| POST | `/api/v1/support/tickets/:id/rating` | Authenticated | Submit satisfaction rating. Body: `{ rating: 1-5, comment?: string }`. Requires ticket in `RESOLVED` or `CLOSED` status (400 otherwise). Returns `{ data: Ticket }` or 404. |

**Ticket response shape** (screenshot_path always omitted):

```typescript
{
  ticketId: string;
  providerId: string;
  subject: string;
  description: string;
  contextUrl: string | null;
  contextMetadata: object | null;
  category: string | null;
  priority: string;
  status: string;
  assignedTo: string | null;
  resolutionNotes: string | null;
  resolvedAt: string | null;
  satisfactionRating: number | null;
  satisfactionComment: string | null;
  createdAt: string;
  updatedAt: string;
}
```

## 6.3 Internal/Admin Endpoints

The following operations are available via the service layer for the support team (admin-only, no external API routes exposed at MVP):

- **Update ticket**: Change status (enforces valid transitions), category, priority, assignment, resolution notes. Sends notification to physician on status change.
- **Close ticket**: Transition from `RESOLVED` to `CLOSED`. Returns 422 if current status is not `RESOLVED`.
- **Triage queue**: List all tickets with filters (status, priority, category, assigned agent). No provider scoping.
- **SLA breach detection**: Fetch tickets exceeding SLA targets with breach type and elapsed/target business minutes.

# 7. Data Model

## 7.1 Support Tickets Table

See Section 3.2 for full column specification.

## 7.2 Help Articles Table

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| `article_id` | UUID | No | Primary key (auto-generated) |
| `slug` | VARCHAR(200) | No | URL-friendly unique identifier. Auto-generated from title if not provided. |
| `title` | VARCHAR(200) | No | Article title |
| `category` | VARCHAR(50) | No | Help category (e.g. `GETTING_STARTED`, `AHCIP_BILLING`) |
| `content` | TEXT | No | Full article content (markdown) |
| `summary` | VARCHAR(500) | Yes | Short description for search results |
| `search_vector` | TSVECTOR | No | PostgreSQL full-text search vector. Auto-generated from `to_tsvector('english', title || ' ' || content)`. Updated when title or content change. |
| `related_codes` | JSONB | Yes | Array of HSC, explanatory, or error codes linked to this article. Used for rejection code lookups via `@>` containment. |
| `somb_version` | VARCHAR(20) | Yes | SOMB version this article references |
| `is_published` | BOOLEAN | No | `false` = draft, `true` = live. Only published articles returned by public queries. Default: `false`. |
| `helpful_count` | INTEGER | No | Aggregate count of 'helpful' votes. Default: 0. Atomically incremented. |
| `not_helpful_count` | INTEGER | No | Aggregate count of 'not helpful' votes. Default: 0. Atomically incremented. |
| `sort_order` | INTEGER | No | Display order within category. Default: 0. |
| `created_at` | TIMESTAMPTZ | No | Article creation timestamp |
| `updated_at` | TIMESTAMPTZ | No | Last modification timestamp |

**Database indexes:**

- `help_articles_search_vector_gin_idx` GIN index on `search_vector` -- full-text search
- `help_articles_category_published_sort_idx` on (`category`, `is_published`, `sort_order`) -- category listing
- `help_articles_related_codes_gin_idx` GIN index on `related_codes` -- code-specific lookups

## 7.3 Article Feedback Table

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| `feedback_id` | UUID | No | Primary key (auto-generated) |
| `article_id` | UUID FK | No | FK to `help_articles` |
| `provider_id` | UUID FK | No | FK to `providers` |
| `is_helpful` | BOOLEAN | No | `true` = helpful, `false` = not helpful |
| `created_at` | TIMESTAMPTZ | No | Feedback submission timestamp |

**Database indexes:**

- `article_feedback_article_provider_unique_idx` unique on (`article_id`, `provider_id`) -- one vote per physician per article
- `article_feedback_article_idx` on (`article_id`) -- aggregate counts per article

# 8. Article Content System

## 8.1 Article File Format

Help centre articles are stored as markdown files in `help-centre/{category}/{slug}.md`. Each article includes YAML front matter with required metadata fields:

```yaml
---
title: "Article Title"
category: getting-started
slug: setting-up-your-professional-profile
description: "Short description for search results and SEO"
priority: 1
last_reviewed: 2026-02-15
review_cycle: quarterly
type: procedural
---

Article body content in markdown...
```

**Required front matter fields:** `title`, `category`, `slug`, `description`, `priority`, `last_reviewed`, `review_cycle`, `type`.

## 8.2 Article Validation Rules

Two validation scripts enforce content quality:

**`scripts/validate-article.js`** -- Single article validation:

- File exists and is non-empty.
- Starts with YAML front matter delimiter (`---`).
- All required front matter fields present.
- Category is one of: `getting-started`, `submitting-claims`, `after-submission`, `billing-reference`, `your-account`, `security-compliance`.
- Priority is `1`, `2`, or `3`.
- Review cycle is `quarterly`, `annual`, or `on-change`.
- Article type is `procedural` or `reference`.
- Word count within bounds: procedural articles 300--600 words, reference articles 600--1,000 words.
- No em dash characters (U+2014) or `--` used as em dash -- use semicolons or colons instead.
- No placeholder language (`coming soon`, `to be determined`, `TBD`, `placeholder`, `more details to follow`).
- Article body is non-empty.

**`scripts/validate-all-articles.js`** -- Comprehensive suite:

1. Verify all 43 expected articles exist and are non-empty.
2. Run `validate-article.js` on every article.
3. Check that all cross-links (`/help-centre/...`) resolve to existing files.
4. Report summary: total found, validated, missing, broken links, total word count per category.

## 8.3 Article Types

| Type | Word Count | Purpose |
| --- | --- | --- |
| `procedural` | 300--600 words | Step-by-step instructions ('How do I...') |
| `reference` | 600--1,000 words | Explanatory content ('What is...', 'Understanding...') |

## 8.4 Review Cycle

| Cycle | Frequency | Applies To |
| --- | --- | --- |
| `quarterly` | Every 3 months | Articles referencing SOMB rules, fee schedules, regulatory content |
| `annual` | Every 12 months | General platform feature articles |
| `on-change` | When referenced feature changes | Articles tied to specific platform features |

# 9. Module Architecture

The Support System domain uses a **subdirectory structure** rather than the standard 5-file flat pattern. This accommodates the domain's two distinct subsystems (help centre and support tickets) with separate repositories, services, and routes.

```
apps/api/src/domains/support/
├── repos/
│   ├── help-articles.repo.ts         # Help article queries (search, CRUD, feedback)
│   ├── help-articles.repo.test.ts    # Repository unit tests
│   ├── support-tickets.repo.ts       # Ticket queries (CRUD, SLA, admin queue)
│   └── support-tickets.repo.test.ts  # Repository unit tests
├── routes/
│   ├── help.routes.ts                # Help centre endpoints (public + authenticated)
│   ├── help.routes.test.ts           # Route integration tests
│   ├── ticket.routes.ts              # Ticket endpoints (all authenticated)
│   └── ticket.routes.test.ts         # Route integration tests
└── services/
    ├── help-centre.service.ts        # Search, context-aware routing, feedback
    ├── help-centre.service.test.ts   # Service unit tests
    ├── support-ticket.service.ts     # Ticket lifecycle, notifications, SLA
    └── support-ticket.service.test.ts # Service unit tests
```

**Shared package files:**

- `packages/shared/src/constants/support.constants.ts` -- Ticket status, priority, category enums. SLA targets and business hours. Help category constants. Context-aware help mappings. Audit action constants. Phase 1.5 AI chat placeholders.
- `packages/shared/src/schemas/db/support.schema.ts` -- Drizzle schema for `support_tickets`, `help_articles`, and `article_feedback` tables with indexes and inferred types.
- `packages/shared/src/schemas/validation/support.validation.ts` -- Zod validation schemas for all API inputs (article queries, feedback, ticket creation, ticket listing, ticket rating, admin ticket updates).

**Dependency injection:** Both services use factory functions (`createHelpCentreService`, `createSupportTicketService`) that receive dependencies (repositories, audit repo, notification service, file storage) as parameters. Routes receive services via an options object.

## 9.1 Audit Logging

All security-relevant actions produce audit records via the injected `auditRepo.appendAuditLog()` interface:

| Audit Action | Trigger | Rate Limited |
| --- | --- | --- |
| `support.ticket_created` | Ticket creation | No |
| `support.ticket_updated` | Admin ticket field changes | No |
| `support.ticket_resolved` | Status transition to RESOLVED | No |
| `support.ticket_closed` | Status transition to CLOSED | No |
| `support.ticket_rated` | Satisfaction rating submitted | No |
| `support.article_viewed` | Article retrieved by slug | Yes (1/min per provider) |
| `support.article_feedback` | Helpful/not helpful submitted | No |
| `support.help_searched` | Full-text search executed | Yes (1/min per provider) |

Rate limiting on high-frequency audit actions (search, article view) uses an in-memory per-provider timestamp map with a 1-minute window to prevent audit log flooding.

# 10. Testing Requirements

Help centre search: query matches relevant articles. No results for empty or sanitised-away queries. Search query sanitisation strips tsquery special characters.

Context-aware help: URL pattern matching maps page URLs to categories. Rejection code metadata maps to related articles. Unmatched URLs return search page fallback.

Support ticket creation: context auto-captured. Confirmation notification sent. Ticket appears in physician's list. Batch failure auto-escalated to `URGENT`. HTML tags stripped from description.

Ticket lifecycle: `OPEN` -> `IN_PROGRESS` -> `RESOLVED` -> `CLOSED`. Invalid transitions rejected with 422. Notifications at status transitions. `resolved_at` auto-set.

Satisfaction rating: stored on ticket (1--5 with optional comment). Only allowed on `RESOLVED` or `CLOSED` tickets. Returns 400 for invalid status.

Screenshot upload: file validated via magic bytes (PNG/JPEG/WebP). Max 5 MB. Stored securely. Path never exposed in API responses. Double-stripped at route and service layers.

Rejection code search: help centre returns articles where `related_codes` contains the queried code.

Article feedback: per-physician upsert. Aggregate counters updated. Audit logged.

SLA breach detection: business minutes calculated correctly including Thursday extended hours. Breach detection identifies first-response and resolution breaches.

Physician scoping: ticket queries always filtered by `provider_id` from auth context. Delegate context resolves to the physician's `provider_id`. Other physicians' tickets return 404 (not 403).

# 11. Open Questions

| # | Question | Context |
| --- | --- | --- |
| 1 | Should help centre articles be publicly accessible or require authentication? | Implementation: article listing and retrieval are public (no auth required). Feedback requires authentication. This hybrid approach increases SEO and helps prospects evaluate the product. |
| 2 | Who authors help centre content initially? | Meritum team at launch. 43 articles authored across 6 categories. Validation scripts enforce quality. Future: physician contributors for community knowledge. Need editorial review process. |
| 3 | When should Phase 1.5 AI chat launch? | Depends on support query volume. Target: 3--6 months after launch, or 200+ unique support queries collected. Infrastructure constants defined (`AI_CHAT_CONFIDENCE_THRESHOLD = 0.70`, `AI_CHAT_ENABLED = false`). |
| 4 | Should the support system integrate with a third-party helpdesk tool? | Current implementation: lightweight internal tracking with triage queue, SLA breach detection, and status workflow. Third-party adds cost but provides agent tooling, macros, reporting. Decision deferred. |

# 12. Document Control

This is the final domain in the Meritum functional requirements suite. It provides the help and support infrastructure that ensures physicians can get answers when contextual help and the AI Coach are insufficient.

| Item | Value |
| --- | --- |
| Parent document | Meritum PRD v1.3 |
| Domain | Support System (Domain 13 of 13) |
| Build sequence position | Parallel (help centre content authored alongside feature development; email support from Day 1) |
| Dependencies | Domain 1 (IAM), Domain 2 (Reference Data for help content), Domain 5 (Provider Management for ticket scoping), Domain 7 (shared LLM for Phase 1.5), Domain 9 (ticket notifications), Domain 12 (file storage) |
| Version | 2.0 |
| Date | February 2026 |
| Change history | v1.0: Initial specification. v2.0: Synced with implementation -- subdirectory module architecture, 43 articles across 6 file-system categories, PostgreSQL tsvector full-text search with GIN index, context-aware help URL pattern matching, ticket status workflow with valid transition enforcement, SLA breach detection with business minutes calculation, screenshot magic bytes validation, article feedback with per-physician upsert, article validation scripts, rate-limited audit logging, Zod validation schemas with HTML stripping. |
