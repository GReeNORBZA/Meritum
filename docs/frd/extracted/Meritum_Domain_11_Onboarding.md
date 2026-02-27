# Meritum_Domain_11_Onboarding

MERITUM

Functional Requirements

Onboarding

Domain 11 of 13  |  First-Run Experience

Meritum Health Technologies Inc.

Version 2.0  |  February 2026

CONFIDENTIAL

# Table of Contents

1. Domain Overview
2. Onboarding Flow
3. IMA Generation
4. AHC11236 Form Pre-Fill
5. Optional Patient Import
6. Post-Onboarding Guided Tour
7. Connect Care Onboarding
8. Onboarding Gate Middleware
9. Data Model
10. User Stories & Acceptance Criteria
11. API Contracts
12. Audit Events
13. Testing Requirements
14. Open Questions
15. Document Control

# 1. Domain Overview

## 1.1 Purpose

The Onboarding domain orchestrates the first-run experience for new Meritum physicians. It bridges account creation (Domain 1) and full platform usage by guiding the physician through a sequence of steps that configure their billing identity, satisfy regulatory requirements, and prepare the platform for claim creation.

The target: a physician should go from 'I just signed up' to 'I can create my first claim' in under 10 minutes. Every step is essential — the platform is unusable for billing until onboarding is complete — but the experience should feel lightweight and purposeful, not bureaucratic.

## 1.2 Scope

- Guided onboarding wizard (7 steps, ~10 minutes)
- IMA (Information Manager Agreement) generation per HIA s.66, rendered from a Handlebars template
- IMA version tracking and re-acknowledgement prompts on template update
- PIA (Privacy Impact Assessment) appendix download
- AHC11236 form pre-fill (BA linkage to Meritum submitter prefix)
- BA status tracking during AHCIP processing (2–4 weeks) with manual PENDING → ACTIVE confirmation
- Optional patient CSV import during onboarding
- Onboarding progress persistence (resume on abandon/return)
- Post-onboarding guided tour of the platform (6 stops)
- Connect Care user detection for physicians using Connect Care clinical documentation
- Onboarding gate middleware blocking non-onboarded physicians from platform endpoints

## 1.3 Out of Scope

- Account creation and authentication (Domain 1 Identity & Access)
- Stripe subscription setup (Domain 12 Platform Operations; payment setup happens before onboarding)
- Provider profile management post-onboarding (Domain 5 Provider Management)
- WCB vendor accreditation (external process; Meritum captures the resulting Contract ID)
- IMA amendment workflow (planned — see `scripts/tasks/ima-legal-requirements.tasks` phases 4–8 for amendment system, breach notification, and data destruction pipeline)
- Connect Care import reconciliation (Domain 10 Mobile Companion v2)

## 1.4 Domain Dependencies

| Domain | Direction | Interface |
| --- | --- | --- |
| 1 Identity & Access | Consumed | Account exists before onboarding starts. Onboarding creates the provider profile linked to the user. |
| 2 Reference Data | Consumed | AHCIP specialty codes, functional centre codes, community codes for RRNP lookup, WCB form types by role/skill. |
| 5 Provider Management | Produces | Onboarding creates provider profile, BA records, practice locations, WCB config, submission preferences. |
| 6 Patient Registry | Produces | Optional CSV patient import during onboarding. |
| 10 Mobile Companion | Produces | Sets `is_connect_care_user` flag on provider record when Connect Care is indicated during onboarding. |
| 12 Platform Operations | Consumed | Subscription must be active (or in trial) before onboarding proceeds. |

# 2. Onboarding Flow

## 2.1 Step Sequence

Steps 1–4 and 7 are required for onboarding completion. Steps 5–6 are optional and can be deferred. The platform blocks claim creation until `onboarding_completed = true` (set when all required steps are finished and `completed_at` is populated).

| # | Step | Required | Description |
| --- | --- | --- | --- |
| 1 | Professional Identity | Yes | Billing number (AHCIP practitioner ID, 5-digit numeric), CPSA registration number, legal first and last name. Format validation: billing number must match `^\d{5}$`. This data creates or updates the `providers` record via Provider Management. |
| 2 | Specialty & Type | Yes | Select specialty from AHCIP specialty code list (validated against Reference Data). Select physician type: `gp`, `specialist`, or `locum`. Determines default workflow and validation context. Updates provider specialty via Provider Management. |
| 3 | Business Arrangement | Yes | Enter primary BA number. If PCPCM enrolled, guided flow to add both PCPCM BA and FFS BA (enforced: both must be present). All BAs created with status `PENDING`. Pre-fills AHC11236 form for download. |
| 4 | Practice Location | Yes | Add primary practice location: name, functional centre code (validated against Reference Data), optional facility number, address (street, city, province defaulting to AB, postal code), community code (validated against Reference Data). RRNP eligibility and rate auto-calculated from community code via Reference Data lookup. Location set as default. |
| 5 | WCB Configuration | No | If physician bills WCB: add Contract ID, Role, and Skill code. Permitted form types auto-populated from Reference Data based on role and skill code. Can be skipped and configured later from settings. |
| 6 | Submission Preferences | No | Review and accept defaults (Auto Clean for AHCIP, Require Approval for WCB) or customise. Two modes available: `auto_clean` and `require_approval` for each of AHCIP and WCB. Can be changed later. |
| 7 | IMA Acknowledgement | Yes | Information Manager Agreement generated from Handlebars template with physician's details pre-filled. Physician reviews in scrollable viewer and digitally acknowledges. SHA-256 hash of rendered document verified between client and server. Acknowledgement timestamp, hash, IP address, and user agent stored. PDF generated and stored immutably in DigitalOcean Spaces. PIA appendix available for download. |

Required steps: {1, 2, 3, 4, 7}. Defined in `REQUIRED_ONBOARDING_STEPS` constant.

## 2.2 Progress Persistence

If the physician abandons onboarding mid-flow (closes browser, loses connectivity, gets interrupted):

- All completed steps are saved to the `onboarding_progress` record immediately on step completion. Each step completion is an independent database write.
- On next login, the physician is returned to the first incomplete required step (computed by scanning required steps in order).
- A progress indicator shows completed vs remaining steps.
- The physician can navigate back to review or edit completed steps. Re-completing a step updates the provider data via Provider Management (idempotent step marking in repository).
- The onboarding gate middleware returns HTTP 403 with error code `ONBOARDING_REQUIRED` and `current_step` for any non-bypass endpoint, directing the frontend to the appropriate step.

## 2.3 Onboarding Completion

When all required steps are marked complete, the service calls `markOnboardingCompleted` which sets `completed_at` on the progress record. The repository validates that all required steps are true before allowing this — a `BusinessRuleError` is thrown if any required step is incomplete.

Completion triggers:
- Audit log entry: `onboarding.completed`
- Event emission: `onboarding.completed` with `providerId`
- Onboarding gate stops blocking the physician

# 3. IMA Generation

## 3.1 Regulatory Context

Under the Health Information Act (HIA) s.66, a custodian who uses an information manager to collect, use, or disclose individually identifying health information must enter into an Information Manager Agreement (IMA) with that information manager. Meritum acts as the information manager; the physician is the custodian. The IMA must be in place before Meritum processes any PHI on the physician's behalf.

## 3.2 IMA Template

The IMA is rendered from a Handlebars template located at `apps/api/src/domains/onboarding/templates/ima.hbs`. The template produces a full HTML document styled for formal legal presentation (Times New Roman, serif, 12pt) and is pre-filled with:

- Physician's legal first and last name (from Step 1)
- CPSA registration number
- Business Arrangement number(s) (comma-separated)
- Meritum Health Technologies Inc. corporate name and address
- Effective date (date of acknowledgement, ISO format)
- Template version (from `IMA_TEMPLATE_VERSION` constant, currently `1.0.0`)

Template variables use Handlebars syntax: `{{physician_first_name}}`, `{{physician_last_name}}`, `{{cpsa_number}}`, `{{ba_numbers}}`, `{{company_name}}`, `{{company_address}}`, `{{effective_date}}`, `{{template_version}}`.

## 3.3 IMA Content Sections

The IMA document contains the following sections:

1. **Recitals** — Establishes the Custodian (physician) and Information Manager (Meritum) roles under the Act.
2. **Definitions** — Terms defined per the Act.
3. **Scope of Services** — Electronic claims submission and billing management for AHCIP and WCB Alberta.
4. **Compliance with the Act** — Information Manager shall comply with HIA and all regulations.
5. **Safeguards** — Encryption at rest and in transit, access controls, audit logging, Canadian data residency.
6. **Canadian Data Residency** — All health information stored exclusively in Canadian data centres. No international transfer without written consent.
7. **Subcontractors** — No subcontractor engagement without prior written consent.
8. **Breach Notification** — 24-hour notification of any breach or suspected breach.
9. **Return and Destruction** — On termination, return or securely destroy all health information with written confirmation.
10. **Audit Rights** — Custodian and OIPC Alberta may audit compliance.
11. **Term and Termination** — Continues for duration of active subscription. 30-day termination notice.
12. **Limitation of Liability** — No liability for indirect/consequential damages except gross negligence or wilful misconduct.
13. **Governing Law** — Province of Alberta and federal laws of Canada.
14. **Acknowledgement Block** — Digital acknowledgement clause with physician name, CPSA number, and date.

## 3.4 Digital Acknowledgement

The physician reviews the IMA in-app (scrollable document viewer) and clicks 'I Acknowledge and Agree'. This is not a signature in the legal sense — it is a digital acknowledgement. The acknowledgement flow:

1. Frontend requests rendered IMA via `GET /api/v1/onboarding/ima`, receiving the HTML content, SHA-256 hash, and template version.
2. Physician reviews the document.
3. Frontend sends `POST /api/v1/onboarding/ima/acknowledge` with the `document_hash` received in step 1.
4. Server re-renders the IMA and computes the hash. If the client hash does not match the server hash, the request is rejected with a `BusinessRuleError` (prevents tampering between render and acknowledge).
5. On match: IMA record is created in `ima_records` (append-only), PDF is generated from the HTML via `htmlToPdf`, and the PDF is stored immutably in DigitalOcean Spaces at key `ima/{providerId}/{imaId}.pdf`.
6. Step 7 (IMA Acknowledgement) is marked complete. If all required steps are now done, onboarding is completed.

Stored data per acknowledgement:

| Field | Type | Description |
| --- | --- | --- |
| ima_id | UUID | Primary key |
| provider_id | UUID FK | FK to providers |
| template_version | VARCHAR(20) | IMA template version used (e.g. `1.0.0`) |
| document_hash | VARCHAR(64) | SHA-256 hash of the rendered HTML at time of acknowledgement |
| acknowledged_at | TIMESTAMPTZ | Timestamp of acknowledgement |
| ip_address | VARCHAR(45) | IP address at time of acknowledgement |
| user_agent | VARCHAR(500) | Browser user agent at time of acknowledgement |

## 3.5 IMA Version Tracking and Re-Acknowledgement

The system tracks IMA template versions via the `IMA_TEMPLATE_VERSION` constant. When the IMA template is updated (constant bumped to a new version), the `checkImaCurrentVersion` service function compares the physician's latest IMA record's `templateVersion` against the current `IMA_TEMPLATE_VERSION`.

If the versions differ, `needs_reacknowledgement` is set to `true`. Existing physicians are prompted to re-acknowledge on next login. The `ima_records` table supports multiple rows per provider — each re-acknowledgement creates a new record without modifying the original.

The IMA amendment workflow (IMA-020 through IMA-024 in `scripts/tasks/ima-legal-requirements.tasks`) extends this with formal amendment records, accept/reject flows, and a blocking gate middleware.

## 3.6 PIA Appendix

Alongside the IMA, Meritum provides a Privacy Impact Assessment (PIA) summary appendix for the physician's records. This is a downloadable static PDF that describes Meritum's privacy safeguards in physician-friendly language. It is informational — no acknowledgement required. Available from the IMA step during onboarding and from settings post-onboarding via `GET /api/v1/onboarding/pia/download`.

# 4. AHC11236 Form Pre-Fill

The AHC11236 is the Alberta Health form for linking a Business Arrangement to an accredited submitter. The physician must submit this form to Alberta Health to authorise Meritum to submit claims on their behalf. Processing takes 2–4 weeks.

## 4.1 Pre-Fill Strategy

Meritum pre-fills the AHC11236 with:

- Physician's name (formatted as `Dr. {firstName} {lastName}`) and billing number (from Step 1)
- BA number (first BA from provider's BA list, from Step 3)
- Meritum's submitter prefix (from `submitterPrefix` configuration, e.g. `MRT`)
- Accredited submitter details

The pre-filled form is generated as a PDF via `pdfGenerator.generateAhc11236()`. The physician downloads it, prints, signs with a wet signature (Alberta Health currently requires a physical signature), and mails or faxes it to Alberta Health. Meritum cannot submit this form electronically on the physician's behalf.

## 4.2 BA Linkage Status Tracking

After the physician submits the AHC11236, the BA status in Meritum is `PENDING`. The three BA linkage statuses are:

| Status | Meaning |
| --- | --- |
| PENDING | AHC11236 submitted to Alberta Health. Waiting for processing. Claims can be created and validated but not transmitted via H-Link. |
| ACTIVE | Alberta Health confirmed linkage. Claims can be submitted via H-Link. |
| INACTIVE | BA deactivated (physician request, Alberta Health action, or end date reached). |

The physician manually confirms linkage activation via `POST /api/v1/onboarding/ba/{ba_id}/confirm-active`. This endpoint:
1. Verifies the BA belongs to the authenticated physician (tenant isolation via Provider Management's `findBaById`).
2. Validates the BA is currently in `PENDING` status — rejects if already `ACTIVE` or `INACTIVE`.
3. Updates status to `ACTIVE` via Provider Management's `updateBaStatus`.
4. Emits an audit event with previous and new status.

While BA status is `PENDING`, the physician can create and validate claims but cannot submit batches. This allows them to start using Meritum immediately while waiting for Alberta Health processing.

# 5. Optional Patient Import

After required onboarding steps, the physician is offered an optional patient import step. This is the same CSV import functionality specified in Domain 6 (Patient Registry) Section 5, surfaced as a convenience during onboarding.

- If the physician imports patients now, they have a populated patient registry ready for claim creation.
- If they skip, they can import later from the Patient Registry settings or add patients individually during claim creation.
- The onboarding flow shows a summary of import results (created, updated, skipped, errors) before proceeding.
- Completion is tracked via the `patient_import_completed` flag on the onboarding progress record and recorded via `POST /api/v1/onboarding/patient-import/complete`.

# 6. Post-Onboarding Guided Tour

After onboarding completes, the physician is offered an optional guided tour of the platform. The tour highlights key features with overlay tooltips across 6 stops:

| Stop | Constant | Tooltip Content |
| --- | --- | --- |
| Dashboard overview | `DASHBOARD_OVERVIEW` | 'This is your billing dashboard. You can see your revenue, pending claims, and recent activity here.' |
| Create a claim | `CREATE_CLAIM` | 'Tap here to create your first claim. Select a patient, enter a code, and save.' |
| AI Coach | `AI_COACH` | 'After you save a claim, the AI Coach may suggest optimisations. You can accept or dismiss suggestions.' |
| Thursday batch | `THURSDAY_BATCH` | 'Your claims are submitted every Thursday. You can review the queue before submission.' |
| Notifications | `NOTIFICATIONS` | 'Important events appear here — rejections, deadlines, and assessment results.' |
| Help | `HELP` | 'Hover over any field to see a tooltip. Complex billing rules are explained in plain language.' |

Tour stops are defined in the `GuidedTourStop` constant enumeration.

The `shouldShowGuidedTour` service function returns `true` only when:
- Onboarding is complete (`completedAt` is not null)
- Tour has not been completed (`guidedTourCompleted = false`)
- Tour has not been dismissed (`guidedTourDismissed = false`)

The tour is dismissible at any point. It does not re-appear after completion or dismissal. Both actions are idempotent — repeating a complete or dismiss call when already in that state is a no-op. A 'Replay tour' option is available in settings.

# 7. Connect Care Onboarding

For physicians who use Connect Care for clinical documentation, the onboarding flow collects an additional flag indicating Connect Care usage. This is specified in Domain 10 Mobile Companion v2 (MHT-FRD-MOB-002, Section 6).

## 7.1 Detection

During onboarding or via provider settings post-onboarding, the physician indicates whether they use Connect Care. This sets the `is_connect_care_user` flag on the `providers` table (defined in Domain 5).

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| is_connect_care_user | BOOLEAN | No | Whether physician uses Connect Care. Default false. |
| connect_care_enabled_at | TIMESTAMPTZ | Yes | When Connect Care mode was first enabled. |

## 7.2 Mode Activation

When `is_connect_care_user = true`:
- The mobile app defaults to shift-focused view (upcoming shifts, active shift, recent reconciliation).
- The "Connect Care Import" navigation item is shown.
- Quick claim entry is available via a secondary menu item for non-CC clinic days.

When the physician later enables or disables Connect Care, the mobile app transitions gracefully. Existing favourite codes and templates remain available in both modes.

## 7.3 SCC Export Guidance

An in-app help article is provided explaining how to export "My Billing Codes" and "My WCB Codes" from Connect Care. This is linked from the import page and the help centre (Domain 13).

# 8. Onboarding Gate Middleware

The onboarding gate is a Fastify `onRequest` hook registered as a plugin (`onboarding-gate`, depending on `auth-plugin`). It enforces that physician users cannot access platform endpoints until onboarding is complete.

## 8.1 Behaviour

For each incoming request:

1. **Bypass check:** requests to paths starting with `/api/v1/onboarding`, `/api/v1/auth`, `/api/v1/platform/subscriptions`, `/api/v1/platform/webhooks`, or `/health` bypass the gate.
2. **Authentication:** the gate attempts to populate `request.authContext` by calling `app.authenticate`. If authentication fails, the gate skips silently — the route's own `authenticate` preHandler will return 401.
3. **Role check:** delegates and admins bypass the gate (delegates do not go through onboarding; admins are exempt). Only `PHYSICIAN` role users are gated.
4. **Onboarding status check:** the gate calls `getOnboardingStatus` to determine if onboarding is complete. If complete, the request proceeds.
5. **Block:** if onboarding is incomplete, the gate returns HTTP 403 with:

```json
{
  "error": {
    "code": "ONBOARDING_REQUIRED",
    "message": "onboarding_required",
    "current_step": 1
  }
}
```

The `current_step` value indicates the first incomplete required step, allowing the frontend to redirect to the correct step.

# 9. Data Model

Onboarding writes primarily to Provider Management tables (Domain 5) and tracks onboarding-specific state in two owned tables:

## 9.1 Onboarding Progress Table (onboarding_progress)

One row per provider. Unique constraint on `provider_id`. Tracks per-step completion through the onboarding wizard.

| Column | Type | Nullable | Default | Description |
| --- | --- | --- | --- | --- |
| progress_id | UUID | No | `gen_random_uuid()` | Primary key |
| provider_id | UUID FK | No | — | FK to `providers`. Unique constraint. |
| step_1_completed | BOOLEAN | No | false | Professional Identity |
| step_2_completed | BOOLEAN | No | false | Specialty & Type |
| step_3_completed | BOOLEAN | No | false | Business Arrangement |
| step_4_completed | BOOLEAN | No | false | Practice Location |
| step_5_completed | BOOLEAN | No | false | WCB Configuration (optional) |
| step_6_completed | BOOLEAN | No | false | Submission Preferences (optional) |
| step_7_completed | BOOLEAN | No | false | IMA Acknowledgement |
| patient_import_completed | BOOLEAN | No | false | Optional patient import completed |
| guided_tour_completed | BOOLEAN | No | false | Post-onboarding tour completed |
| guided_tour_dismissed | BOOLEAN | No | false | Tour dismissed without completing |
| started_at | TIMESTAMPTZ | No | `now()` | When onboarding began |
| completed_at | TIMESTAMPTZ | Yes | NULL | When onboarding completed (all required steps done) |

**Indexes:** `onboarding_progress_provider_id_idx` (unique) on `provider_id`.

**Drizzle schema:** `packages/shared/src/schemas/db/onboarding.schema.ts`

## 9.2 IMA Records Table (ima_records)

One row per IMA acknowledgement. A provider can have multiple rows if they re-acknowledge after a template version update. Rows are immutable once written — the repository exposes no update or delete operations for IMA records (append-only).

| Column | Type | Nullable | Default | Description |
| --- | --- | --- | --- | --- |
| ima_id | UUID | No | `gen_random_uuid()` | Primary key |
| provider_id | UUID FK | No | — | FK to `providers` |
| template_version | VARCHAR(20) | No | — | IMA template version used (e.g. `1.0.0`) |
| document_hash | VARCHAR(64) | No | — | SHA-256 hash of the rendered IMA HTML at time of acknowledgement |
| acknowledged_at | TIMESTAMPTZ | No | — | Timestamp of acknowledgement |
| ip_address | VARCHAR(45) | No | — | IP address at time of acknowledgement |
| user_agent | VARCHAR(500) | No | — | Browser user agent at time of acknowledgement |

**Indexes:** `ima_records_provider_acknowledged_idx` on `(provider_id, acknowledged_at)` for efficient latest-record lookup.

**Drizzle schema:** `packages/shared/src/schemas/db/onboarding.schema.ts`

## 9.3 BA Linkage Status

BA status is stored on the Business Arrangements table (Domain 5). The onboarding domain manages status transitions during and after onboarding:

| Status | Meaning |
| --- | --- |
| PENDING | AHC11236 submitted to Alberta Health. Waiting for processing (2–4 weeks). Claims can be created and validated but not transmitted via H-Link. |
| ACTIVE | Alberta Health confirmed linkage. Claims can be submitted via H-Link. |
| INACTIVE | BA deactivated (physician request, Alberta Health action, or end date reached). |

Defined in `BALinkageStatus` constant.

# 10. User Stories & Acceptance Criteria

| ID | Story | Acceptance Criteria |
| --- | --- | --- |
| ONB-001 | As a new physician, I want to set up my billing profile in under 10 minutes | 7-step wizard. Progress indicator. Required fields clearly marked. Format validation on entry (billing number 5-digit, postal code, specialty code against Reference Data). Total time < 10 minutes for required steps. |
| ONB-002 | As a new physician, I want to acknowledge the IMA so I'm compliant with HIA | IMA rendered from Handlebars template with my details. Scrollable viewer. Acknowledge button. SHA-256 hash verified between client and server. Timestamp, hash, IP, and user agent recorded. PDF stored immutably in DigitalOcean Spaces. |
| ONB-003 | As a new physician, I want a pre-filled AHC11236 to send to Alberta Health | PDF generated with my name, billing number, BA number, and Meritum's submitter prefix. Download button. Instructions for submission (mail/fax). |
| ONB-004 | As a new physician, I want to import my patient list during setup | CSV upload offered after required steps. Column mapping preview. Import summary. Skippable. Completion tracked on onboarding progress. |
| ONB-005 | As a new physician, I want to resume onboarding if I get interrupted | Close browser mid-flow. Log in again. Onboarding gate detects incomplete status. Returned to first incomplete required step. All prior steps preserved. Re-completing a step updates provider data. |
| ONB-006 | As a new physician, I want a tour of the platform after setup | Guided tour with overlay tooltips. 6 stops (Dashboard, Create Claim, AI Coach, Thursday Batch, Notifications, Help). Dismissible. Does not reappear after completion or dismissal. Replay from settings. |
| ONB-007 | As a physician, I want to know when my BA is active with Alberta Health | BA status visible in settings and onboarding summary. PENDING badge visible. Physician can manually confirm ACTIVE via `confirm-active` endpoint. Rejects if BA not in PENDING state. |
| ONB-008 | As a physician with a PCPCM arrangement, I want the onboarding to guide me through dual-BA setup | When PCPCM enrolled, wizard enforces dual-BA requirement. Both `pcpcm_ba_number` and `ffs_ba_number` must be present. Primary BA, FFS BA (if different), and PCPCM BA all created with PENDING status. |
| ONB-009 | As a physician who uses Connect Care, I want onboarding to detect my Connect Care usage | During onboarding, physician indicates Connect Care usage. `is_connect_care_user` flag set on provider profile. Mobile app adjusts to shift-focused view. SCC export guidance provided. |
| ONB-010 | As a physician, I want to be prompted to re-acknowledge the IMA when the template is updated | System compares latest IMA record's template version against current `IMA_TEMPLATE_VERSION`. If outdated, `needs_reacknowledgement` is flagged. Physician prompted on next login. |

# 11. API Contracts

All onboarding endpoints require authentication and the `PHYSICIAN` role. Access is controlled via `app.authenticate` and a `requireRole('PHYSICIAN')` preHandler.

| Method | Endpoint | Description | Request Body |
| --- | --- | --- | --- |
| GET | /api/v1/onboarding/progress | Get current onboarding progress. Returns step completion status, `current_step`, `is_complete`, and `required_steps_remaining`. | — |
| POST | /api/v1/onboarding/steps/{step_number} | Complete a step (1–7). Body is step-specific (see Zod schemas). Writes to Provider Management tables. Returns updated progress. | Step-specific (see below) |
| GET | /api/v1/onboarding/ima | Get rendered IMA document. Returns HTML content, SHA-256 hash, and template version. | — |
| POST | /api/v1/onboarding/ima/acknowledge | Record IMA acknowledgement. Verifies document hash, creates IMA record, generates and stores PDF, completes step 7. | `{ document_hash: string }` (64-char hex) |
| GET | /api/v1/onboarding/ima/download | Download acknowledged IMA as PDF. Retrieves from DigitalOcean Spaces. Returns `application/pdf`. | — |
| GET | /api/v1/onboarding/ahc11236/download | Download pre-filled AHC11236 form as PDF. Returns `application/pdf`. | — |
| GET | /api/v1/onboarding/pia/download | Download PIA appendix PDF (static document). Returns `application/pdf`. | — |
| POST | /api/v1/onboarding/guided-tour/complete | Mark guided tour as completed. Idempotent. | — |
| POST | /api/v1/onboarding/guided-tour/dismiss | Mark guided tour as dismissed. Idempotent. | — |
| POST | /api/v1/onboarding/patient-import/complete | Mark patient import as completed during onboarding. | — |
| POST | /api/v1/onboarding/ba/{ba_id}/confirm-active | Confirm BA linkage activation. Transitions BA from PENDING to ACTIVE. Rejects if not PENDING. | — (ba_id in path, UUID validated) |

## 11.1 Step-Specific Request Bodies

**Step 1 — Professional Identity:**
```json
{
  "billing_number": "12345",
  "cpsa_number": "CPSA-001",
  "legal_first_name": "John",
  "legal_last_name": "Smith"
}
```

**Step 2 — Specialty & Type:**
```json
{
  "specialty_code": "01",
  "physician_type": "gp"
}
```
`physician_type` enum: `gp`, `specialist`, `locum`.

**Step 3 — Business Arrangement:**
```json
{
  "primary_ba_number": "BA-001",
  "is_pcpcm_enrolled": false,
  "pcpcm_ba_number": "PCPCM-001",
  "ffs_ba_number": "FFS-001"
}
```
When `is_pcpcm_enrolled = true`, both `pcpcm_ba_number` and `ffs_ba_number` are required (Zod refinement enforced).

**Step 4 — Practice Location:**
```json
{
  "location_name": "Main Clinic",
  "functional_centre_code": "FC01",
  "facility_number": "FAC-001",
  "address": {
    "street": "123 Main St",
    "city": "Calgary",
    "province": "AB",
    "postal_code": "T2P1A1"
  },
  "community_code": "COM01"
}
```

**Step 5 — WCB Configuration:**
```json
{
  "contract_id": "WCB-001",
  "role": "attending_physician",
  "skill_code": "GP"
}
```

**Step 6 — Submission Preferences:**
```json
{
  "ahcip_mode": "auto_clean",
  "wcb_mode": "require_approval"
}
```
Defaults: `ahcip_mode = "auto_clean"`, `wcb_mode = "require_approval"`.

**Step 7 — IMA Acknowledgement:** No request body. IP address and user agent captured from the request headers.

## 11.2 Progress Response Format

All step completion endpoints and the progress GET endpoint return:

```json
{
  "data": {
    "progress_id": "uuid",
    "provider_id": "uuid",
    "step_1_completed": true,
    "step_2_completed": true,
    "step_3_completed": false,
    "step_4_completed": false,
    "step_5_completed": false,
    "step_6_completed": false,
    "step_7_completed": false,
    "patient_import_completed": false,
    "guided_tour_completed": false,
    "guided_tour_dismissed": false,
    "started_at": "2026-02-13T14:30:00.000Z",
    "completed_at": null,
    "current_step": 3,
    "is_complete": false,
    "required_steps_remaining": 3
  }
}
```

## 11.3 IMA Response Format

**GET /api/v1/onboarding/ima:**
```json
{
  "data": {
    "content": "<html>...rendered IMA HTML...</html>",
    "hash": "a1b2c3d4...64-char-hex",
    "template_version": "1.0.0"
  }
}
```

**POST /api/v1/onboarding/ima/acknowledge (201):**
```json
{
  "data": {
    "ima_id": "uuid",
    "document_hash": "a1b2c3d4...64-char-hex",
    "template_version": "1.0.0",
    "acknowledged_at": "2026-02-13T14:30:00.000Z"
  }
}
```

## 11.4 Zod Validation Schemas

All Zod schemas are defined in `packages/shared/src/schemas/onboarding.schema.ts`:

- `onboardingStep1Schema` — billing_number (5-digit regex), cpsa_number, legal_first_name, legal_last_name
- `onboardingStep2Schema` — specialty_code, physician_type enum
- `onboardingStep3Schema` — primary_ba_number, is_pcpcm_enrolled, optional pcpcm/ffs BA numbers with refinement
- `onboardingStep4Schema` — location_name, functional_centre_code, facility_number, address (nested), community_code
- `onboardingStep5Schema` — contract_id, role, skill_code
- `onboardingStep6Schema` — ahcip_mode enum, wcb_mode enum with defaults
- `stepNumberParamSchema` — coerced integer 1–7 for path parameter validation
- `imaAcknowledgeSchema` — document_hash (exactly 64 characters)
- `onboardingProgressResponseSchema` — response shape validation

# 12. Audit Events

All state changes in the onboarding domain produce audit log entries via the `auditRepo.appendAuditLog` interface. Audit entries include `action`, `category` (`onboarding`), `resourceType`, `resourceId`, and `detail`.

| Audit Action | Constant | Trigger | Resource Type |
| --- | --- | --- | --- |
| `onboarding.started` | `STARTED` | Onboarding progress record created for a new provider | `onboarding_progress` |
| `onboarding.step_completed` | `STEP_COMPLETED` | Any step marked as completed. Detail includes `step_number`. | `onboarding_progress` |
| `onboarding.completed` | `COMPLETED` | All required steps finished, `completed_at` set | `onboarding_progress` |
| `onboarding.ima_acknowledged` | `IMA_ACKNOWLEDGED` | IMA acknowledgement recorded. Detail includes template_version and document_hash. IP and user agent captured. | `ima_record` |
| `onboarding.ima_downloaded` | `IMA_DOWNLOADED` | IMA PDF downloaded | `ima_record` |
| `onboarding.ahc11236_downloaded` | `AHC11236_DOWNLOADED` | AHC11236 PDF downloaded | `ahc11236` |
| `onboarding.pia_downloaded` | `PIA_DOWNLOADED` | PIA appendix PDF downloaded | `pia` |
| `onboarding.patient_import_completed` | `PATIENT_IMPORT_COMPLETED` | Patient import marked complete during onboarding | `onboarding_progress` |
| `onboarding.guided_tour_completed` | `GUIDED_TOUR_COMPLETED` | Guided tour completed | `onboarding_progress` |
| `onboarding.guided_tour_dismissed` | `GUIDED_TOUR_DISMISSED` | Guided tour dismissed | `onboarding_progress` |
| `onboarding.ba_status_updated` | `BA_STATUS_UPDATED` | BA status changed (e.g. PENDING → ACTIVE). Detail includes previous and new status. | `business_arrangement` |

Audit action constants are defined in `OnboardingAuditAction` in `packages/shared/src/constants/onboarding.constants.ts`.

# 13. Testing Requirements

## 13.1 Unit Tests

Located in `apps/api/src/domains/onboarding/onboarding.test.ts`. Coverage:

**Repository layer:**
- `createProgress` creates record with all steps false
- `createProgress` rejects duplicate `provider_id` (unique constraint → `ConflictError`)
- `findProgressByProviderId` returns progress for existing provider, null for non-existent
- `markStepCompleted` sets specific step to true, is idempotent, rejects invalid step numbers
- `markOnboardingCompleted` sets `completed_at` when required steps done, throws `BusinessRuleError` when required steps incomplete, does not require optional steps
- `markGuidedTourCompleted`, `markGuidedTourDismissed`, `markPatientImportCompleted` — correct flag set
- `createImaRecord` inserts with correct fields and `acknowledged_at`
- `findLatestImaRecord` returns most recent, null for no records
- `listImaRecords` returns all records in reverse chronological order
- IMA records repository has no update or delete functions (append-only verification)

**Service layer:**
- `getOrCreateProgress` creates new progress on first call, returns existing on subsequent
- `getOnboardingStatus` returns correct state for incomplete, complete, and no-provider scenarios
- `completeStep1` creates provider record, validates billing number format (rejects non-5-digit)
- `completeStep2` validates specialty_code against Reference Data, rejects invalid
- `completeStep3` creates BA with PENDING status, enforces dual-BA for PCPCM, allows single BA without PCPCM
- `completeStep4` validates functional_centre_code and community_code, calculates RRNP eligibility
- `completeStep5` creates WCB config with auto-populated form types
- `completeStep6` sets submission preferences
- Completing steps 1, 2, 3, 4, 7 triggers `markOnboardingCompleted`; missing step 7 does not
- Re-completing a step updates provider data (idempotent)

**IMA document operations:**
- `renderIma` pre-fills physician details correctly, returns consistent SHA-256 hash, throws for missing provider/renderer/template
- `acknowledgeIma` verifies client hash, rejects mismatch, creates IMA record, stores PDF to Spaces, triggers step 7 completion
- `downloadImaPdf` returns stored PDF, throws 404 when no IMA record
- `checkImaCurrentVersion` detects current/outdated template versions and no-IMA scenarios
- `generateAhc11236Pdf` pre-fills physician and submitter details, throws for missing provider/generator
- `downloadPiaPdf` returns static PIA document, throws when not configured

**Guided tour, patient import, and BA status:**
- `completeGuidedTour` marks tour completed, is idempotent
- `dismissGuidedTour` marks tour dismissed
- `shouldShowGuidedTour` returns true only when onboarding complete and tour not done/dismissed
- `completePatientImport` marks import completed
- `confirmBaActive` updates from PENDING to ACTIVE, rejects non-PENDING, throws 404 for unowned BA

## 13.2 Integration Tests

- Complete all 7 steps in sequence → `onboarding_completed = true`, claims can be created
- Complete steps 1–4 and 7, skip 5–6 → `onboarding_completed = true`
- Complete steps 1–3 only → `onboarding_completed = false`, claim creation blocked by onboarding gate
- Abandon after step 2, return → resume at step 3, steps 1–2 data preserved
- PCPCM flow: select PCPCM enrolled at step 3 → dual-BA entry enforced, three BA records created
- IMA acknowledgement: timestamp, hash, IP stored. PDF downloadable and matches displayed content.
- IMA hash mismatch: tampered hash rejected with `BusinessRuleError`
- AHC11236 PDF: correct physician details, correct Meritum submitter prefix, downloadable
- Patient import during onboarding: same behaviour as Domain 6 CSV import, completion tracked
- Guided tour: completes all 6 stops. Dismiss mid-tour. Does not reappear. `shouldShowGuidedTour` returns false after.
- BA status: PENDING after step 3. Manual confirm to ACTIVE via endpoint. Rejects if already ACTIVE. Claims submittable only when ACTIVE.
- Onboarding gate: non-onboarded physician receives 403 with `ONBOARDING_REQUIRED` on protected endpoints. Onboarded physician passes through.
- Full onboarding → create first claim → validate → queue: end-to-end integration test

## 13.3 Security Tests

Per CLAUDE.md mandatory security test categories:

**Authentication enforcement (`authn.security.ts`):**
- One 401 test per route (11 routes total)

**Authorization (`authz.security.ts`):**
- Delegate users cannot access onboarding endpoints (PHYSICIAN role required)
- Admin users bypass onboarding gate

**Tenant isolation (`scoping.security.ts`):**
- Physician 1 cannot access physician 2's onboarding progress
- Physician 1 cannot download physician 2's IMA PDF
- Physician 1 cannot confirm physician 2's BA as active (returns 404)

**Input validation (`input.security.ts`):**
- SQL injection in string fields (billing_number, cpsa_number, location_name) → rejected by Zod
- XSS in text fields → rejected or sanitised
- Non-UUID ba_id path parameter → 400
- Invalid step_number (0, 8, non-integer) → 400
- Invalid document_hash length → 400

**Data leakage (`leakage.security.ts`):**
- Error responses do not echo physician details
- 404 responses do not reveal resource existence
- Server headers stripped

**Audit trail (`audit.security.ts`):**
- Each step completion produces audit record
- IMA acknowledgement produces audit record with IP and user agent
- BA status change produces audit record with previous and new status
- Onboarding completion produces audit record

# 14. Open Questions

| # | Question | Context |
| --- | --- | --- |
| 1 | Can the AHC11236 be submitted electronically by the physician? | Currently requires wet signature and mail/fax. Alberta Health may accept electronic submission in future. Monitor. |
| 2 | Should Meritum auto-detect BA linkage activation via H-Link test? | Could eliminate manual PENDING → ACTIVE confirmation. Requires H-Link test submission capability and interpretation of response. |
| 3 | Should IMA re-acknowledgement be blocking? | When IMA template updates, should the physician be blocked from platform use until re-acknowledged? The IMA amendment system (planned) will implement a blocking gate middleware for formal amendments. |
| 4 | Should onboarding offer a trial period before payment? | Current: payment setup before onboarding. Alternative: 14-day trial with full onboarding, payment required to continue. Business decision. |
| 5 | At which onboarding step should Connect Care usage be collected? | Currently specified as a provider settings toggle and onboarding question. Should it be a sub-question within Step 2 (Specialty & Type) or a separate step? |

# 15. Document Control

| Item | Value |
| --- | --- |
| Parent document | Meritum PRD v1.3 |
| Domain | Onboarding (Domain 11 of 13) |
| Build sequence position | Parallel with core domains (UI layer on top of Provider Management and Patient Registry) |
| Dependencies | Domain 1 (IAM), Domain 2 (Reference Data), Domain 5 (Provider Management), Domain 6 (Patient Registry), Domain 10 (Mobile Companion), Domain 12 (Platform Ops) |
| Version | 2.0 |
| Date | February 2026 |
| Changelog | v2.0: Added IMA Handlebars template details (Section 3.2–3.3), IMA version tracking and re-acknowledgement (Section 3.5), Connect Care onboarding (Section 7), onboarding gate middleware (Section 8), BA confirm-active endpoint, patient-import-complete endpoint, audit event catalogue (Section 12), detailed Zod schema documentation (Section 11.4), expanded data model with column defaults and indexes (Section 9), and implementation-aligned API contracts. |
