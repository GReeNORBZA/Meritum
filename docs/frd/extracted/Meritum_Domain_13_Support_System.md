# Meritum_Domain_13_Support_System

MERITUM

Functional Requirements

Support System

Domain 13 of 13  |  Help & Support Infrastructure

Meritum Health Technologies Inc.

Version 1.0  |  February 2026

CONFIDENTIAL

# Table of Contents

# 1. Domain Overview

## 1.1 Purpose

The Support System domain provides physicians with help when the contextual help, tooltips, and AI Coach are not sufficient. It operates in two phases: email-based support at MVP, and AI-assisted support chat at Phase 1.5 after real support queries have been collected to calibrate the system.

The strategic approach is deliberately conservative: launch with humans answering questions, collect the questions, use the data to build an AI support layer that answers the questions physicians actually ask — not the questions we think they'll ask.

## 1.2 Scope

Help centre: structured knowledge base with articles covering common billing scenarios, platform features, and troubleshooting

Email support: support@meritum.ca for questions not answered by help centre or contextual help

Support ticket tracking: internal tracking of support requests, resolution time, categorisation

In-app support access: 'Help' button accessible from every page, context-aware (passes current page URL to support)

FAQ surfacing: common questions identified from support tickets promoted to help centre

AI support chat (Phase 1.5): RAG-based chat using same self-hosted LLM as AI Coach, trained on help centre content and historical support queries

## 1.3 Out of Scope

Phone support (not viable at Meritum's scale and price point)

Live chat with human agents (Phase 2+ consideration)

Community forums (Phase 2+ consideration; requires critical mass of users)

Clinical billing advice (Meritum provides platform support, not billing consulting)

## 1.4 Domain Dependencies

# 2. Help Centre

## 2.1 Content Structure

The help centre is a structured knowledge base accessible from within Meritum and as a public web page (help.meritum.ca). Content is organised by category:

## 2.2 Content Principles

Plain language: No jargon without explanation. Written for physicians, not billing consultants.

Task-oriented: Articles answer 'How do I...' questions. Steps are numbered. Screenshots included.

Searchable: Full-text search across all articles. Search results ranked by relevance.

Versioned: Articles reference SOMB versions and are updated when rules change.

Feedback loop: 'Was this helpful?' on every article. Low-rated articles prioritised for rewrite.

## 2.3 Context-Aware Help

When a physician clicks 'Help' from within Meritum, the help centre opens with context:

If on the claim creation page → help centre opens to AHCIP Billing or WCB Billing category

If on a rejected claim → help centre searches for the specific rejection/explanatory code

If on settings → help centre opens to Account & Billing category

Context is passed via URL parameter. If no specific context is available, the help centre opens to the search page.

# 3. Email Support (MVP)

## 3.1 Support Email Flow

Physician clicks 'Contact Support' from help centre or in-app help button.

Support form opens with context pre-filled: current page, physician name, subscription status, recent errors (if applicable).

Physician describes their issue in free text. Optional screenshot upload.

Support ticket created internally. Confirmation email sent to physician.

Support team triages and responds via email.

Resolution tracked. Physician notified of resolution via email and in-app notification.

## 3.2 Support Ticket Tracking

## 3.3 SLA Targets

Business hours: Monday–Friday 08:00–18:00 MT. Thursday extended hours (06:00–22:00 MT) to cover batch submission cycle.

# 4. AI Support Chat (Phase 1.5)

After 3–6 months of email support operation, Meritum will have collected enough real physician questions to calibrate an AI support chat. This chat uses the same self-hosted LLM infrastructure as the AI Coach (Domain 7).

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

Chat UI component designed and placeholder visible in navigation (greyed out with 'Coming soon' label)

Support ticket categorisation captures data for future training

Help centre article structure supports vector embedding generation

LLM infrastructure from Domain 7 includes capacity for support chat workload

# 5. User Stories & Acceptance Criteria

# 6. API Contracts

# 7. Testing Requirements

Help centre search: query matches relevant articles. No results for nonsense queries.

Context-aware help: clicking help from claim page → billing articles. From settings → account articles.

Support ticket creation: context auto-captured. Confirmation email sent. Ticket appears in physician's list.

Ticket lifecycle: OPEN → IN_PROGRESS → RESOLVED → CLOSED. Notifications at each transition.

Satisfaction rating: stored on ticket. Aggregate rating calculable for SLA reporting.

Screenshot upload: file stored securely. Viewable by support team. Not accessible by other physicians.

Rejection code search: help centre returns corrective action article for common AHCIP explanatory codes.

# 8. Open Questions

# 9. Document Control

This is the final domain in the Meritum functional requirements suite. It provides the help and support infrastructure that ensures physicians can get answers when contextual help and the AI Coach are insufficient.

| Domain | Direction | Interface |
| --- | --- | --- |
| 1 Identity & Access | Consumed | User authentication for in-app support access. Support tickets linked to user accounts. |
| 2 Reference Data | Consumed | Help centre content references SOMB sections, governing rules. Tooltip content sourced from Reference Data. |
| 7 Intelligence Engine | Infrastructure shared | Same self-hosted LLM infrastructure used for AI support chat (Phase 1.5). |
| 9 Notification Service | Consumed | Support ticket status updates delivered via notification. |

| Category | Example Articles |
| --- | --- |
| Getting Started | How to complete onboarding, Understanding your BA number, Setting up your first practice location, Importing patients from CSV |
| AHCIP Billing | How the Thursday batch cycle works, Understanding assessment results, Common rejection codes and fixes, PCPCM dual-BA routing explained |
| WCB Billing | Creating your first WCB claim, Understanding timing tiers, Completing the C050E form, WCB return file results |
| Modifiers & Rules | When to use CMGP, After-hours billing explained, Understanding governing rules, RRNP eligibility and rates |
| AI Coach | How the AI Coach works, Accepting and dismissing suggestions, Managing suppressed rules, Understanding confidence levels |
| Account & Billing | Managing your subscription, Updating payment method, Inviting a delegate, Exporting your data |
| Troubleshooting | Claim stuck in queue, Batch submission failed, Assessment not received, Payment failed |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| ticket_id | UUID | No | Primary key |
| provider_id | UUID FK | No | FK to providers |
| subject | VARCHAR(200) | No | Subject line (auto-generated from context or physician-entered) |
| description | TEXT | No | Physician's description of the issue |
| context_url | VARCHAR(500) | Yes | Page URL where 'Help' was clicked |
| context_metadata | JSONB | Yes | Auto-captured context: claim_id, batch_id, error codes, browser info |
| category | VARCHAR(50) | Yes | Categorised by support team: BILLING, TECHNICAL, ACCOUNT, FEATURE_REQUEST |
| priority | VARCHAR(10) | No | LOW, MEDIUM, HIGH, URGENT. Default: MEDIUM. URGENT for batch submission failures. |
| status | VARCHAR(20) | No | OPEN, IN_PROGRESS, WAITING_ON_CUSTOMER, RESOLVED, CLOSED |
| assigned_to | VARCHAR(100) | Yes | Support team member handling the ticket |
| resolution_notes | TEXT | Yes | How the issue was resolved |
| resolved_at | TIMESTAMPTZ | Yes | When the ticket was resolved |
| satisfaction_rating | INTEGER | Yes | 1–5 star rating from physician after resolution |
| created_at | TIMESTAMPTZ | No |  |
| updated_at | TIMESTAMPTZ | No |  |

| Priority | First Response | Resolution Target |
| --- | --- | --- |
| URGENT | < 2 hours (business hours) | < 4 hours. Batch failures and submission-blocking issues. |
| HIGH | < 4 hours (business hours) | < 1 business day |
| MEDIUM | < 1 business day | < 3 business days |
| LOW | < 2 business days | < 5 business days |

| ID | Story | Acceptance Criteria |
| --- | --- | --- |
| SUP-001 | As a physician, I want to search the help centre for answers | Search bar on help centre. Full-text search. Results ranked by relevance. Clickable articles. |
| SUP-002 | As a physician, I want context-aware help when I click the help button | Help button on every page. Opens help centre filtered to relevant category based on current page. |
| SUP-003 | As a physician, I want to contact support when the help centre doesn't answer my question | Support form from help centre. Context pre-filled. Free text + screenshot. Confirmation email. Ticket created. |
| SUP-004 | As a physician, I want to know when my support ticket is resolved | In-app notification + email when status changes. Resolution notes included. |
| SUP-005 | As a physician, I want to rate the support I received | After ticket resolution, prompt for 1–5 star rating. Optional comment. Stored on ticket. |
| SUP-006 | As a physician, I want to look up what a rejection code means | Help centre search for rejection/explanatory code returns article explaining the code and corrective action. |

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/help/articles | List help centre articles. Params: category, search query. |
| GET | /api/v1/help/articles/{slug} | Get article content by slug. |
| POST | /api/v1/help/articles/{slug}/feedback | Submit 'Was this helpful?' feedback. |
| POST | /api/v1/support/tickets | Create a support ticket. Body: subject, description, context_url, context_metadata, screenshot. |
| GET | /api/v1/support/tickets | List physician's support tickets. Filterable by status. |
| GET | /api/v1/support/tickets/{id} | Get ticket details and history. |
| POST | /api/v1/support/tickets/{id}/rating | Submit satisfaction rating. Body: rating (1–5), comment. |

| # | Question | Context |
| --- | --- | --- |
| 1 | Should help centre articles be publicly accessible or require authentication? | Public increases SEO and helps prospects evaluate the product. Gated protects proprietary content. Hybrid: getting started articles public, advanced articles gated. |
| 2 | Who authors help centre content initially? | Meritum team at launch. Future: physician contributors for community knowledge. Need editorial review process. |
| 3 | When should Phase 1.5 AI chat launch? | Depends on support query volume. Target: 3–6 months after launch, or 200+ unique support queries collected. |
| 4 | Should the support system integrate with a third-party helpdesk tool? | Candidates: Freshdesk, Zendesk, Intercom. Or build lightweight internal tracking (current spec). Third-party adds cost but provides agent tooling, macros, reporting. |

| Item | Value |
| --- | --- |
| Parent document | Meritum PRD v1.3 |
| Domain | Support System (Domain 13 of 13) |
| Build sequence position | Parallel (help centre content authored alongside feature development; email support from Day 1) |
| Dependencies | Domain 1 (IAM), Domain 2 (Reference Data for help content), Domain 7 (shared LLM for Phase 1.5), Domain 9 (ticket notifications) |
| Version | 1.0 |
| Date | February 2026 |

