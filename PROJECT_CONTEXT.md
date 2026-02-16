# Meritum Health Technologies — Project Context

> This document provides full project context for Claude Code sessions. It supplements CLAUDE.md (which contains operational instructions and coding conventions). Read this document to understand what Meritum is, why decisions were made, and how the domains fit together.

---

## 1. Business Overview

### What Meritum Is

Meritum is a self-serve medical billing platform for Alberta physicians. It handles the submission of fee-for-service claims to two payers:

1. **AHCIP (Alberta Health Care Insurance Plan):** Government health insurance. Claims submitted via H-Link (Alberta Health's electronic submission system). ~95% of a typical physician's billing volume.
2. **WCB Alberta (Workers' Compensation Board):** Workplace injury claims. Submitted via Electronic Injury Reporting using HL7 v2.3.1 XML batch files. ~5% of billing volume but higher per-claim value.

### Who It Serves

- **Primary users:** Rural GPs and specialists in Alberta who are underserved by existing billing solutions (Med Access, Wolf Medical, Accuro).
- **Secondary users:** Billing delegates — administrative staff who manage claims on behalf of one or more physicians.
- **Scale at MVP:** Target first 100 physicians. Architecture supports 1,000+.

### Business Model

| Item | Detail |
|------|--------|
| Standard monthly | $279/month CAD |
| Standard annual | $2,790/year (~$232.50/month, ~17% savings) |
| Early bird monthly | $199/month for first 12 months (first 100 physicians) |
| GST | 5% added on invoice (Meritum is GST-registered) |
| Payment | Credit card via Stripe. CAD only. |

### Corporate Structure

Meritum Health Technologies Inc. is a separate legal entity from SigOct (the founder's infosec consulting business). The founder (Ian) is a solo developer with deep security expertise.

---

## 2. Regulatory Environment

### Health Information Act (HIA) — Alberta

The HIA governs the collection, use, and disclosure of health information in Alberta. Key implications for Meritum:

- **Custodian:** The physician is the custodian of their patients' health information.
- **Information Manager:** Meritum acts as the information manager under HIA s.66. This requires an Information Manager Agreement (IMA) between each physician and Meritum before any PHI processing.
- **Privacy Impact Assessment (PIA):** Required before Meritum processes PHI. Filed with the OIPC (Office of the Information and Privacy Commissioner of Alberta).
- **Canadian data residency:** All PHI must remain in Canada. DigitalOcean Toronto (tor1) satisfies this.
- **Breach notification:** Mandatory notification to OIPC and affected custodians within "without unreasonable delay."
- **Audit trail:** All access to PHI must be logged. Retention: 10 years for claim-related audit data, 7 years for auth audit data.
- **No PHI in email:** Email bodies must not contain individually identifying health information. Meritum sends notification links, not data.

### FOIP (Freedom of Information and Protection of Privacy Act)

Applies to how Meritum handles personal information of physicians (not patients — that's HIA). Standard PIPEDA-equivalent privacy obligations.

### AHCIP Regulatory Framework

- **SOMB (Schedule of Medical Benefits):** The fee schedule published by Alberta Health. Defines every billable health service code (HSC), its base fee, eligible modifiers, and governing rules. Updated periodically (usually April 1).
- **Business Arrangement (BA):** A billing entity registered with Alberta Health. A physician may have multiple BAs (e.g., one for FFS billing, one for PCPCM capitation).
- **AHC11236 form:** The Alberta Health form to link a BA to an accredited submitter (Meritum). Requires wet signature and mail/fax to Alberta Health. 2–4 week processing.
- **H-Link:** Alberta Health's electronic claims submission system. HL7 v2 format. Batches submitted, assessments returned with explanatory codes.
- **Thursday submission cycle:** AHCIP claims are batched weekly on Thursday. This is Meritum's core billing rhythm.
- **PCPCM (Primary Care Network Patient Medical Home):** A payment model where GPs receive capitation payments alongside FFS. Requires dual BAs (PCPCM BA + FFS BA) with intelligent claim routing.
- **RRNP (Rural and Remote Northern Program):** Incentive payments for physicians in eligible rural communities. Auto-calculated from community code and AHCIP specialty.

### WCB Alberta Regulatory Framework

- **Electronic Injury Reporting:** WCB's electronic submission system. HL7 v2.3.1 XML format.
- **8 form types:** C050E (initial short), C050S (initial comprehensive), C053E/S (progress short/comprehensive), C086 (surgery), C137 (return to work assessment), C138 (fitness to work), C139 (specialist referral).
- **Timing tiers:** Fee multipliers based on days from date of injury. Tier 1 (0–24 days): 1.0x. Tier 2 (25–56 days): 0.85x. Tier 3 (57–112 days): 0.70x. Tier 4 (113+ days): 0.55x.
- **OIS (Occupation and Industry Standard):** Detailed employer and injury data required on initial claims. 45+ fields.
- **Contract ID:** WCB vendor accreditation number assigned to each physician.

---

## 3. Architecture Overview

### System Architecture

```
┌─────────────────────┐    ┌─────────────────────┐
│   Next.js Frontend   │    │   Fastify API        │
│   (App Router)       │◄──►│   (REST + WebSocket) │
│   apps/web/          │    │   apps/api/          │
└─────────────────────┘    └──────────┬──────────┘
                                      │
                    ┌─────────────────┼─────────────────┐
                    │                 │                   │
              ┌─────▼─────┐   ┌──────▼──────┐   ┌──────▼──────┐
              │ PostgreSQL │   │ DO Spaces   │   │ Postmark    │
              │ (Managed)  │   │ (Files)     │   │ (Email)     │
              │ Toronto    │   │ Toronto     │   │             │
              └───────────┘   └─────────────┘   └─────────────┘
                    │
              ┌─────▼─────┐
              │ Stripe     │   (Subscription billing — no PHI)
              └───────────┘
```

### Monorepo Structure

```
meritum/
├── CLAUDE.md                  # Operational instructions for Claude Code
├── PROJECT_CONTEXT.md         # This file
├── turbo.json
├── apps/
│   ├── api/                   # Fastify backend (all 13 domain modules)
│   └── web/                   # Next.js frontend
├── packages/
│   └── shared/                # Drizzle schema, Zod schemas, constants, types
├── scripts/
│   ├── task-runner.sh         # Build orchestrator
│   ├── generate-tasks.js      # Task manifest generator
│   └── tasks/                 # Manifests and prompt files
├── configs/                   # Domain config JSON files for generator
└── docs/
    └── frd/                   # Functional Requirements Documents (15 .docx files)
```

### Domain Architecture (14 domains in 15 FRDs)

Meritum is decomposed into 14 functional domains, each with a dedicated module in the API:

| # | Domain | Module Path | Role |
|---|--------|-------------|------|
| 1 | Identity & Access | `domains/iam/` | Auth, sessions, RBAC, delegates, audit |
| 2 | Reference Data | `domains/reference/` | SOMB codes, rules, fee schedules (read-heavy) |
| 3/9 | Notification Service | `domains/notify/` | Event bus, in-app + email, preferences |
| 4.0 | Claim Lifecycle Core | `domains/claims/` | State machine, validation, batches |
| 4.1 | AHCIP Pathway | `domains/ahcip/` | H-Link submission, assessments |
| 4.2 | WCB Pathway | `domains/wcb/` | WCB forms, HL7 XML, timing tiers |
| 5 | Provider Management | `domains/providers/` | Physician profiles, BAs, locations |
| 6 | Patient Registry | `domains/patients/` | Patient demographics, PHN, CSV import |
| 7 | Intelligence Engine | `domains/intel/` | AI Coach, rules engine, LLM |
| 8 | Analytics & Reporting | `domains/analytics/` | Dashboards, reports, exports |
| 10 | Mobile Companion | (frontend only) | Responsive web, ED shifts, favourites |
| 11 | Onboarding | `domains/onboarding/` | First-run wizard, IMA, AHC11236 |
| 12 | Platform Operations | `domains/platform/` | Stripe, status page, monitoring |
| 13 | Support System | `domains/support/` | Help centre, tickets, AI chat (Phase 1.5) |

---

## 4. Tech Stack Decisions and Rationale

### Backend: Fastify 5 + TypeScript

**Chosen over:** NestJS, Express.

**Rationale:** Best JSON serialization performance (2–3x Express), schema-based validation via fastify-type-provider-zod maps directly to FRD validation rules, plugin architecture provides structure without NestJS's boilerplate overhead. For a solo developer using Claude Code, Fastify's lighter weight produces faster iteration than NestJS, while providing more structure than Express (which would require CLAUDE.md to be even more prescriptive about project layout).

### ORM: Drizzle ORM

**Chosen over:** Prisma, Knex + raw pg.

**Rationale:** Type-safe SQL-like syntax with full TypeScript inference. First-class JSONB support (critical — the data model uses JSONB extensively: permissions, ai_coach_suggestions, permitted_form_types, conditions, modifier arrays). Transparent SQL generation means debugging is straightforward. Prisma struggles with complex JSONB operations and its query engine adds an opaque abstraction layer. Knex provides maximum control but no type safety without manual effort. Drizzle hits the sweet spot.

### Frontend: Next.js 15 (App Router)

**Chosen over:** SvelteKit, Remix.

**Rationale:** Claude Code produces highest-quality output with React/Next.js (largest training corpus). Richest component ecosystem — shadcn/ui for the dashboard and form components, Recharts for analytics charts. Well-documented deployment on DigitalOcean (Docker container on App Platform). SvelteKit would produce smaller bundles (beneficial for mobile companion), but the ecosystem and Claude Code familiarity trade-off favours Next.js.

### Auth: Lucia + Custom IAM

**Chosen over:** NextAuth, Auth0, Clerk, fully custom.

**Rationale:** Domain 1 FRD specifies highly custom behaviour: delegate context switching (one user acting on behalf of multiple physicians), configurable permission matrices per delegation, mandatory TOTP MFA with recovery codes, 7-year audit logging, subscription-gated access tiers. No off-the-shelf auth library covers this. Lucia provides the session management plumbing (cookie handling, CSRF, session storage in PostgreSQL) while the IAM logic is built to spec. Password hashing: Argon2id via @node-rs/argon2 (native binding, fastest option).

### Monorepo: Turborepo + pnpm

**Rationale:** Build caching pays off immediately when Claude Code iterates on one domain without rebuilding everything. The `packages/shared` workspace containing Drizzle schema and Zod validators ensures type safety flows from database to API to frontend. Turborepo's clear workspace boundaries (`apps/api`, `apps/web`, `packages/shared`) give Claude Code explicit scope — "work in apps/api" — reducing cross-cutting changes.

### Testing: Vitest + Supertest + Playwright

**Rationale:** Vitest is fast, natively TypeScript, and compatible with the Vite ecosystem. Supertest provides HTTP-level integration testing against the Fastify instance. Playwright handles E2E browser tests (onboarding wizard, mobile responsive, claim submission flows). The test strategy includes 6 mandatory security test categories per domain (see Section 8).

### Email: Postmark

**Chosen over:** AWS SES (ca-central-1), SendGrid.

**Rationale:** Best deliverability in the industry at MVP scale (<100 physicians, ~5,000 emails/month = ~$6/month). No configuration burden (SES requires sender verification, dedicated IP management). Transactional-only (no marketing capabilities, which is what Meritum needs). Migration to SES viable at scale (50,000+ emails/month) if cost becomes relevant.

### Storage: DigitalOcean Spaces (Toronto)

**Rationale:** S3-compatible object storage in the same Toronto region as the database and compute. Encrypted at rest. $5/month for 250GB. Presigned URLs for time-limited report downloads. Keeps all infrastructure on a single provider for operational simplicity.

### Deployment: DigitalOcean App Platform

**Chosen over:** DO Droplets + Docker Compose.

**Rationale:** Solo developer building a product, not managing servers. App Platform provides automated deploys from GitHub, built-in SSL, health checks, and horizontal scaling. Combined with Managed PostgreSQL and Spaces, the entire infrastructure is managed — zero ops burden. Droplets would save ~30% on compute cost but add significant ops tax (SSL cert management, process monitoring, OS updates, security patching).

### WebSocket: @fastify/websocket

**Chosen over:** Socket.IO.

**Rationale:** The notification model is 1:1 (server → specific authenticated user). No rooms, no broadcasting, no complex pub/sub. @fastify/websocket provides native WebSocket support in the existing API server with no additional dependencies. Socket.IO's auto-reconnection is useful but not worth the dependency at MVP scale. Reconsider if notification patterns become more complex.

---

## 5. Cross-Domain Interfaces

### Auth Context (Domain 1 → All Domains)

Every authenticated API request carries this object, populated by auth middleware:

```typescript
interface AuthContext {
  userId: string;
  providerId: string | null;    // null for admin users
  role: 'physician' | 'delegate' | 'admin';
  email: string;
  fullName: string;
  subscriptionStatus: 'trial' | 'active' | 'past_due' | 'suspended' | 'cancelled';
  delegateContext?: {
    delegateUserId: string;
    physicianProviderId: string;
    permissions: Permission[];
  };
}
```

### Provider Context (Domain 5 → Domain 4)

The claim lifecycle consumes a provider context object when creating/validating claims:

```typescript
interface ProviderContext {
  providerId: string;
  billingNumber: string;          // 5-digit AHCIP practitioner ID
  specialty: string;              // AHCIP specialty code
  physicianType: 'GP' | 'SPECIALIST' | 'LOCUM';
  businessArrangements: {
    baId: string;
    baNumber: string;
    baType: 'FFS' | 'PCPCM' | 'LOCUM';
    status: 'PENDING' | 'ACTIVE' | 'INACTIVE';
    isPrimary: boolean;
  }[];
  practiceLocations: {
    locationId: string;
    name: string;
    functionalCentre: string;
    communityCode: string;
    rrnpEligible: boolean;
    rrnpRate: number | null;
  }[];
  submissionPreferences: {
    ahcipMode: 'AUTO_CLEAN' | 'REQUIRE_APPROVAL';
    wcbMode: 'AUTO_CLEAN' | 'REQUIRE_APPROVAL';
  };
  wcbConfig?: {
    contractId: string;
    role: string;
    skill: string;
    permittedFormTypes: string[];
  };
}
```

### Notification Events (All Domains → Domain 9)

Domains emit events consumed by the Notification Service:

```typescript
interface NotificationEvent {
  eventType: string;          // e.g., 'CLAIM_VALIDATED', 'PAYMENT_FAILED'
  physicianProviderId: string;
  metadata: Record<string, any>;
  priority: 'URGENT' | 'HIGH' | 'MEDIUM' | 'LOW';
}
```

30+ event types across 5 categories: Claim Lifecycle (13), Intelligence Engine (3), Provider Management (5), Platform Operations (5), Analytics (2).

### Subscription Status (Domain 12 → Domain 1)

Stripe webhooks update subscription status. Domain 1 middleware gates access:

| Status | Claim Create | Batch Submit | Dashboards | Data Export |
|--------|-------------|-------------|------------|-------------|
| ACTIVE | ✓ | ✓ | ✓ | ✓ |
| PAST_DUE | ✓ | ✓ | ✓ | ✓ |
| SUSPENDED | ✗ | ✗ | Read-only | ✓ |
| CANCELLED | ✗ | ✗ | ✗ | ✓ (30 days) |

---

## 6. Domain Summaries

### Domain 1: Identity & Access Management

**Tables:** users, recovery_codes, sessions, delegate_linkages, invitation_tokens, audit_log (append-only, partitioned by month, 7-year retention).

**Key features:** Email/password registration → mandatory TOTP MFA → session management. Delegate invitation with configurable permission matrix (24 permission keys). Account lockout (10 failures → 30 min). Anti-enumeration on all auth endpoints. Session: 24h absolute expiry, 60min idle expiry, sliding window.

**API groups:** Authentication (10 endpoints), Sessions (3), Delegates (6), Account (6).

**28 audit action identifiers** across 5 categories tracked in append-only log.

### Domain 2: Reference Data

**Tables:** health_service_codes, diagnostic_codes, modifiers, governing_rules, fee_schedules, rrnp_communities, wcb_fee_schedules, specialty_codes, functional_centres.

**Key features:** SOMB fee schedule with effective dates and versioning. Governing rules linked to HSC codes (e.g., "GR 3: requires referral for specialist claims"). Modifier eligibility rules per code. RRNP rate lookup by community code + specialty. Read-heavy, admin-managed. Seeded from SOMB data import.

**Consumed by:** Every claim-related domain (4.0, 4.1, 4.2), Intelligence Engine (7), Analytics (8), Onboarding (11).

### Domain 4.0: Claim Lifecycle Core

**Tables:** claims, claim_validations, claim_line_items, batches, batch_claims, assessments, assessment_line_items, payments, duplicate_detection_log.

**Claim state machine (10 states):** DRAFT → VALIDATED → FLAGGED → QUEUED → BATCHED → SUBMITTED → ASSESSED → REJECTED → RESUBMITTED → PAID.

**Validation engine:** Runs all applicable rules on claim save: code existence, modifier eligibility, governing rule compliance, date constraints, diagnostic code requirements, fee calculation, duplicate detection. Produces structured validation results with severity (ERROR blocks submission, WARNING allows with physician review, INFO is advisory).

**Thursday batch cycle:** Wednesday reminder → Thursday 12:00 MT cutoff → batch assembly → H-Link/WCB submission → Friday assessment retrieval.

### Domain 4.1: AHCIP Claim Pathway

**Key features:** H-Link HL7 v2 message generation from claims. Batch file assembly (up to 100 claims per batch, configurable). Submission to Alberta Health via secure channel. Assessment retrieval and parsing — maps explanatory codes to human-readable reasons. PCPCM routing: determines whether a claim routes to PCPCM BA (capitation) or FFS BA based on service type, patient panel status, and code eligibility. Reciprocal claim handling for cross-panel patients.

### Domain 4.2: WCB Claim Pathway

**Tables:** wcb_claims (extends claims), wcb_form_data (JSONB per form type), wcb_batches, wcb_return_files, wcb_payments, wcb_timing_tier_history.

**8 form types** with varying complexity (C050E: ~30 fields, C050S: ~80 fields including OIS). Timing tier auto-calculation from date of injury. HL7 v2.3.1 XML batch generation per WCB specification. Return file parsing (acceptance, rejection, payment). Fee calculation with tier multipliers.

### Domain 5: Provider Management

**Tables:** providers, business_arrangements, practice_locations, pcpcm_enrolments, delegate_relationships, wcb_configurations, submission_preferences, hlink_configurations.

**Key features:** Physician profile with billing number, CPSA registration, specialty. Dual-BA enforcement for PCPCM (must have both PCPCM BA and FFS BA). Practice location with functional centre and community code (drives RRNP lookup). Delegate permission matrix (separate from Domain 1 auth — Domain 5 manages which data delegates can see, Domain 1 manages authentication). Provider context object (see Section 5) consumed by all claim domains.

### Domain 6: Patient Registry

**Tables:** patients (with PHN, demographics, gender code per AHCIP spec).

**Key features:** PHN validation (Alberta format: 9-digit with Luhn check). Patient search using pg_trgm for fuzzy name matching. CSV import with column mapping, conflict resolution (update existing on PHN match), and error reporting. All patients scoped to the owning physician (no cross-physician patient sharing at MVP). Province stored as 2-char code (AB default).

### Domain 7: Intelligence Engine (AI Coach)

**Tables:** ai_suggestions, ai_rules, ai_suppressed_rules, ai_learning_events.

**Three-tier architecture:**
- **Tier 1 (Rules Engine):** Deterministic rules derived from SOMB governing rules and common billing patterns. Runs on every claim validation. Zero latency. Examples: "You used 03.04A — did you consider 03.04B (complex visit modifier CMGP)?", "After-hours modifier AFHR eligible based on time of service."
- **Tier 2 (Self-hosted LLM):** For ambiguous cases where rules aren't sufficient. Runs asynchronously post-save. Returns suggestions with confidence scores. Model: self-hosted (not API-dependent) for PHI containment.
- **Tier 3 (Physician Review):** AI never auto-modifies claims. Every suggestion requires physician acceptance. Learning loop: accepted suggestions reinforce the pattern, dismissed suggestions reduce confidence, suppressed rules never fire again for that physician.

**Suggestion lifecycle:** PENDING → ACCEPTED / DISMISSED / SUPPRESSED / EXPIRED.

### Domain 8: Analytics & Reporting

**Tables:** report_definitions, generated_reports, analytics_cache.

**Dashboards:** Revenue summary (this month, trend, by code), submission analytics (success rates, rejection reasons), AI Coach performance (acceptance rate, revenue impact), comparative benchmarks (physician vs specialty cohort — anonymised).

**Reports:** Scheduled (weekly/monthly PDF/CSV), on-demand, accountant export package (revenue summary + claim detail + GST report as ZIP). Data portability export: complete claim history + patient registry + provider profile as structured ZIP.

### Domain 9: Notification Service

**Tables:** notifications, email_delivery_log, notification_templates, digest_queue.

**30+ event types** across 5 categories. Each notification: in-app (always, WebSocket push) + optional email (Postmark). Priority-based preferences: URGENT always delivered (cannot disable), HIGH/MEDIUM configurable, LOW defaults to daily digest. Quiet hours suppress non-urgent emails.

**Thursday submission sequence:** 6 coordinated notifications from Wednesday evening through Friday payment confirmation.

**Delegate notification routing:** Filtered by permissions from Domain 5. Multi-physician delegates receive separate feeds per physician context.

### Domain 10: Mobile Companion

**Tables:** ed_shifts, favourite_codes.

**Responsive web** (not native apps). ED shift workflow: start shift → log patients with timestamps → end shift → shift summary → desktop review. Quick claim entry: patient → code → save as draft (<5 taps for repeat patient + favourite code). Favourite codes: physician-curated list, auto-seeded from billing history, max 30, with default modifiers per favourite.

**Design principles:** Thumb-zone optimisation, minimal input (selection over typing), speed over completeness (mobile captures, desktop reviews).

### Domain 11: Onboarding

**Tables:** onboarding_progress, ima_records.

**7-step wizard (~10 minutes):** Professional identity → Specialty & type → Business arrangement (with PCPCM dual-BA flow) → Practice location → WCB config (optional) → Submission preferences (optional) → IMA acknowledgement. Steps 1–4 and 7 required. Platform blocks claim creation until onboarding_completed = true.

**IMA generation:** Per HIA s.66. Pre-filled from physician data. Digital acknowledgement stored with SHA-256 hash of rendered document, timestamp, IP, user agent. PDF stored immutably.

**AHC11236 pre-fill:** Pre-fills the Alberta Health BA linkage form with physician + Meritum submitter details. Downloaded as PDF for wet signature and mail/fax.

### Domain 12: Platform Operations

**Tables:** subscriptions, payment_history.

**Stripe integration:** 3 pricing tiers. Customer Portal for self-service. Webhook-driven subscription status management.

**Dunning sequence:** Day 0 (payment fails, notification) → Day 3 (retry 1) → Day 7 (retry 2, warning) → Day 14 (SUSPENDED, submission blocked) → Day 30 (CANCELLED, 30-day deletion grace).

**Status page:** status.meritum.ca. 8 monitored components. Incident management (Investigating → Identified → Monitoring → Resolved).

### Domain 13: Support System

**Tables:** support_tickets, help_articles.

**Help centre:** 7 categories. Context-aware opening (help from claim page → billing articles). Full-text search. Article feedback.

**Email support:** support@meritum.ca. Ticket tracking with auto-captured context (page URL, claim ID, error codes). SLA: URGENT <2h, HIGH <4h, MEDIUM <1 business day.

**Phase 1.5 AI chat:** RAG over help articles + historical support queries. Same self-hosted LLM as AI Coach. Escalation to email if confidence <0.70.

---

## 7. Critical Security Architecture

### Physician Tenant Isolation (THE #1 Security Control)

Every database query that touches PHI includes `WHERE provider_id = :authenticatedProviderId`. This is enforced at the repository layer — the provider_id is extracted from the AuthContext inside the repository function, never passed as a handler parameter.

Cross-tenant access attempts return 404 (not 403) to avoid confirming resource existence.

### PHI Handling Rules

- **No PHI in email bodies.** Emails contain links to authenticated pages, not data.
- **No PHI in error responses.** Generic error messages only. No patient names, PHNs, or claim details in 4xx/5xx responses.
- **No PHI in logs.** PHN masked as `123******` in all log output. Patient names never logged.
- **No PHI in Stripe.** Stripe Customer objects contain only physician name and email. Zero claim/patient data.
- **PHI encrypted at rest.** DigitalOcean Managed PostgreSQL and Spaces provide encryption at rest.
- **PHI encrypted in transit.** TLS 1.3 (1.2 fallback). HSTS enforced.
- **TOTP secrets encrypted with AES-256-GCM.** Encryption key in environment variable, never in database.
- **All tokens stored as hashes.** Session tokens (SHA-256), invitation tokens (SHA-256), recovery codes (Argon2id).

### Mandatory Security Testing (6 Categories Per Domain)

Every domain must include passing tests for:

1. **authn** — Every authenticated route returns 401 without session
2. **authz** — Every permission-gated action tested positive and negative
3. **scoping** — Physician tenant isolation verified for every query path (list, get, update, delete, search, aggregate)
4. **input** — SQL injection, XSS, type coercion, UUID validation on all input fields
5. **leakage** — Error responses sanitised, headers stripped, PHN masked, no PHI in emails
6. **audit** — Every state change produces audit record, audit log is append-only

---

## 8. Build System

### Task Runner

`scripts/task-runner.sh` orchestrates Claude Code invocations. Each task gets a fresh context window with only CLAUDE.md + a scoped task prompt. The runner:

1. Reads a `.tasks` manifest (one per domain)
2. For each task: invokes `claude -p "[TASK] {prompt}"` with a 10-minute timeout
3. Runs a verify command (usually a test suite)
4. If verify fails: captures last 50 lines of test output, retries with `[RETRY]` prefix (up to 2 retries)
5. Logs results. Supports `--resume` to continue after failure.

### Task Manifests

Each domain has ~20–30 tasks across 6 layers:

| Range | Layer | Description |
|-------|-------|-------------|
| 001–009 | Schema | Constants, Drizzle tables, Zod schemas, migration |
| 010–019 | Repository | Database access functions |
| 020–029 | Service | Business logic |
| 030–039 | Routes | Middleware, handlers, integration tests |
| 040–049 | Security | 6 mandatory security test categories |
| 099 | Validation | Full suite run |

### Build Order (Critical Path)

1. Domain 1 (IAM) — foundation
2. Domain 12 (Platform Ops) — Stripe needed before onboarding
3. Domain 2 (Reference Data) — codes/rules consumed by everything
4. Domain 5 (Provider Management) — provider context consumed by claims
5. Domain 6 (Patient Registry) — patients consumed by claims
6. Domain 11 (Onboarding) — writes to Domains 5 + 6
7. Domain 9 (Notifications) — event bus consumed by Domains 4+
8. Domain 4.0 (Claim Core) — state machine, validation, batches
9. Domain 4.1 (AHCIP) — H-Link submission
10. Domain 4.2 (WCB) — WCB submission
11. Domain 7 (Intelligence) — AI Coach
12. Domain 8 (Analytics) — dashboards, reports
13. Domain 10 (Mobile) — responsive UI layer
14. Domain 13 (Support) — help + tickets

---

## 9. Key Patterns and Conventions

### Domain Module Pattern

Every domain module follows the same 5-file structure. See CLAUDE.md for details. The key rule: **handlers never call repositories directly** (always through service), **repositories never contain business logic** (only data access), **services receive dependencies via function parameters** (testable).

### Zod Schema Sharing

All Zod schemas live in `packages/shared/src/schemas/` and are consumed by both the API (request validation via fastify-type-provider-zod) and the frontend (form validation). This ensures validation rules are defined once and enforced consistently.

### Audit Logging

Every state change on claims, providers, patients, delegates, and subscriptions produces an audit record. Auth events (login, logout, MFA, failed attempts) are logged. The audit_log table is **append-only** — no update or delete operations exist. Retention: 7 years for auth events, 10 years for claim-related events.

### Money Handling

All monetary values are `DECIMAL(10,2)` in the database and `string` in API responses (e.g., `"279.00"`). Never floating point. Fee calculations use the SOMB-published rates with banker's rounding.

### Date/Time Handling

All timestamps are `TIMESTAMPTZ` in the database and ISO 8601 strings in API responses. The Thursday submission cycle uses Mountain Time (MT) for cutoffs. After-hours detection (for modifier eligibility) uses the encounter timestamp in MT.

---

## 10. Open Architectural Decisions

These decisions were intentionally deferred and should be revisited during implementation:

1. **Email provider migration:** Postmark at MVP. Evaluate SES (ca-central-1) at 50,000+ emails/month.
2. **Native mobile apps:** Responsive web at MVP. Evaluate native (React Native or Flutter) after 12–18 months based on user demand and offline requirements.
3. **AI model selection:** Self-hosted LLM for Tier 2 AI Coach. Specific model TBD during Domain 7 implementation. Must run on CPU (no GPU requirement at MVP scale).
4. **H-Link integration specifics:** Connection method, credential format, and test environment details require Alberta Health vendor accreditation completion.
5. **Status page tooling:** Build lightweight or use hosted (Statuspage.io, Instatus). Decision deferred to Domain 12 implementation.
6. **Monitoring stack:** Grafana + Prometheus (self-hosted) vs Datadog (managed) vs DO Monitoring (limited). Decision deferred to Domain 12 implementation.
7. **Help desk tooling:** Build lightweight ticket tracking (current spec) vs integrate Freshdesk/Zendesk. Decision deferred to Domain 13 implementation.
