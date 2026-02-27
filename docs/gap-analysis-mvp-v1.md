# Meritum MVP Gap Analysis

**Document ID:** MHT-GAP-MVP-001
**Version:** 1.0 DRAFT
**Date:** 25 February 2026
**Author:** Engineering
**Sources:** MHT-FUNC-CC-001 (Connect Care Integration), MHT-FUNC-MVP-002 (MVP Feature Set), codebase review (25 Feb 2026)
**Classification:** Internal

---

## 1. Purpose

This document identifies functional gaps between the Meritum codebase (as of 25 February 2026) and the requirements defined in MHT-FUNC-CC-001 (Connect Care / SCC Integration) and MHT-FUNC-MVP-002 (MVP Feature Set v2). It also includes revised requirements for the Mobile Companion (Domain 10) based on architectural decisions made during the Connect Care workflow analysis.

The document is organised in three parts:

- **Part A:** Gaps against MHT-FUNC-CC-001 (Connect Care)
- **Part B:** Gaps against MHT-FUNC-MVP-002 (MVP Features)
- **Part C:** Mobile Companion revisions (Domain 10) including shift scheduling and Connect Care reconciliation

---

## PART A: CONNECT CARE / SCC INTEGRATION GAPS

### A1. SCC-Specific CSV Parser

**Status:** NOT IMPLEMENTED
**Priority:** P0 (MVP — Phase 1)
**Depends on:** Claim lifecycle (Domain 4.0), Provider Management (Domain 5)

**What exists:** A generic EMR import pipeline (`/api/v1/imports`) with CSV/TSV parsing, delimiter detection, and field mapping templates. This pipeline does not understand the AHS Physician Service Code Extract Specification.

**What is needed:**

- A dedicated SCC extract parser module (standalone service/utility within the claims domain) that accepts a CSV string, file stream, or buffer.
- Auto-detection of extract type: "My Billing Codes" (AHCIP) vs "My WCB Codes" (WCB) based on the presence of WCB-specific columns (WCB Claim Number, Employer Name, Injury Date).
- Parsing of all 21 AHCIP fields and all 13 WCB fields as defined in the AHS extract specification (December 2025 revision), including fields Meritum does not directly use for claim submission (to preserve data fidelity).
- Provider identity validation: Billing Provider ID and Business Arrangement Number in the extract must match the authenticated provider's profile. Reject on mismatch with a clear error.
- Versioned parser: track which version of the AHS extract specification is implemented. Support multiple specification versions simultaneously during transitions.
- Stateless: all validation performed against file data and provider profile. No external API calls during parsing.
- Input agnostic: shared between Feature 1 (CSV upload) and Feature 2 (sFTP file drop).

**Files to create/modify:**
- `apps/api/src/domains/claim/scc-parser.service.ts` (new)
- `packages/shared/src/schemas/scc-extract.schema.ts` (new — Zod schemas for both extract types)
- `packages/shared/src/constants/scc.constants.ts` (new — field definitions, version identifiers)

---

### A2. Connect Care Import Workflow

**Status:** NOT IMPLEMENTED (generic import exists but not CC-specific)
**Priority:** P0 (MVP — Phase 1)
**Depends on:** A1 (SCC Parser)

**What is needed:**

- Upload endpoint accessible from main navigation under "Connect Care Import" or equivalent.
- Accept `.csv`, `.CSV` file extensions. Also attempt to parse `.xlsx` and `.xls` files (converting to CSV internally) since the SCC export may be saved as a password-protected spreadsheet.
- 10 MB file size limit.
- Drag-and-drop upload support (frontend).
- Server-side processing with raw file retained in encrypted storage (DO Spaces, Toronto) for audit. Configurable retention period (default: 12 months), then purged.
- Validation rules per MHT-FUNC-CC-001 Section 3.5.2:
  - **Blocking errors:** Missing Patient ULI, invalid ULI format, missing service code, encounter date in the future.
  - **Non-blocking warnings:** Unrecognised SOMB code, ICD conversion flag set, missing referring provider (specialist claim), encounter date > 90 days old.
  - **Informational:** Charge Status = Deleted (flags/removes prior drafts), duplicate detection.
- Import Summary screen showing: total rows, rows parsed, rows with warnings (itemised), rows rejected (itemised), potential duplicates, date range covered.
- Physician confirms before claims are created.
- Created claims tagged with `importSource: 'CONNECT_CARE_CSV'` metadata.
- Claims with non-blocking warnings appear in the Unsubmitted queue with a warning indicator.
- Claims from "My WCB Codes" extract routed to WCB pipeline based on Patient Insurer and WCB-specific fields.
- Audit log entry for every import event: timestamp, user ID, filename, row counts, raw file reference.

---

### A3. ICD-10-CA to ICD-9 Crosswalk

**Status:** NOT IMPLEMENTED
**Priority:** P1 (required for Connect Care import)
**Depends on:** Reference Data (Domain 2)

**What exists:** ICD-9 diagnostic code validation only. No ICD-10-CA storage, no crosswalk table, no conversion flag detection.

**What is needed:**

- ICD-10-CA to ICD-9 crosswalk table in reference data (`packages/shared/src/schemas/db/reference.schema.ts`). Fields: ICD-10-CA code, ICD-10-CA description, candidate ICD-9 codes (array), confidence/match quality.
- When the SCC extract's ICD Conversion Flag is set, the draft claim is created with the ICD-9 field blank and the ICD-10-CA source code preserved.
- Resolution interface: displays the original ICD-10-CA code + description, a list of candidate ICD-9 codes from the crosswalk, and full ICD-9 search if no candidate is appropriate.
- Claim cannot be submitted until the ICD-9 code is resolved.
- Shared between CSV-imported and sFTP-imported claims.

**Files to create/modify:**
- `packages/shared/src/schemas/db/reference.schema.ts` (add `icd_crosswalk` table)
- `apps/api/src/domains/reference/reference.repository.ts` (add crosswalk queries)
- `apps/api/src/domains/reference/reference.routes.ts` (add crosswalk lookup endpoint)
- `packages/shared/src/schemas/claim.schema.ts` (add `icdConversionFlag`, `icd10SourceCode` fields)

---

### A4. Row-Level Duplicate Detection

**Status:** PARTIAL
**Priority:** P1 (required for Connect Care import)
**Depends on:** A1 (SCC Parser), Claim lifecycle (Domain 4.0)

**What exists:** File-level SHA-256 hash deduplication (prevents re-import of the same file).

**What is needed:**

- Row-level composite key matching: Patient ULI + Encounter Date + Service Code + Billing Provider ID.
- If an identical claim exists in Meritum (from a prior import or manual entry), the row is flagged as a potential duplicate in the import summary.
- Physician decides whether to skip or create.
- Near-duplicates (same patient and date but different service codes) are NOT flagged.

---

### A5. Correction and Deletion Handling

**Status:** NOT IMPLEMENTED
**Priority:** P1 (required for Connect Care import)
**Depends on:** A1 (SCC Parser)

**What is needed:**

- When processing an imported file, if a row has Charge Status = "Deleted", the system checks for a matching draft claim from a prior import (matching on Patient ULI, encounter date, original service code, provider).
- If found and claim is still in Unsubmitted/Draft status: automatically remove or flag for review.
- If the claim has already been submitted to Alberta Health: log the deletion indicator and surface to the physician as a reconciliation alert.
- Charge Status = "Modified" rows replace the prior version if the claim is still in Draft.

---

### A6. Claim Data Model Extensions

**Status:** PARTIAL
**Priority:** P1 (required for Connect Care import)
**Depends on:** Claim lifecycle (Domain 4.0)

**What is needed (metadata fields on claims table):**

- `import_source`: 'MANUAL' | 'CONNECT_CARE_CSV' | 'CONNECT_CARE_SFTP' | 'EMR_GENERIC' (partially exists)
- `import_batch_id`: links all claims from a single file (exists)
- `raw_file_reference`: pointer to the archived source file in DO Spaces
- `scc_charge_status`: 'ACTIVE' | 'MODIFIED' | 'DELETED'
- `icd_conversion_flag`: boolean
- `icd10_source_code`: string (preserved alongside the ICD-9 billing code)
- `shift_id`: foreign key to ED shift log (new — see Part C)

---

### A7. sFTP Integration (Phase 2 — Post-MVP)

**Status:** NOT IMPLEMENTED (expected)
**Priority:** Phase 2 (begin AHS application process at H-Link accreditation)

**What is needed (documented for planning, not MVP-blocking):**

- Dedicated sFTP server on DO Toronto infrastructure (SSH2, port 22, AHS IP whitelisting, encryption at rest).
- Separate production and test accounts.
- SSH public key exchange with AHS Technology Services.
- Automated file processing pipeline: detection (15 min latency), validation, provider routing, parsing (shared with A1), claim creation, notification, archival.
- Correction/deletion handling per A5.
- Monitoring: missed delivery detection (alert if no file by 06:00 MST), file integrity validation, SSH key expiry tracking, pipeline health (alert if processing > 30 min).

---

## PART B: MVP FEATURE SET GAPS

### B1. Referral Provider Search

**Status:** NOT IMPLEMENTED
**Priority:** P1 (build first — specialists cannot bill consultations without this)
**Depends on:** Reference Data (Domain 2), Provider Management (Domain 5)

**What exists:** Referring practitioner ID field on claims. AHCIP validation (GR 8) checks for its presence. No searchable registry.

**What is needed:**

- Provider registry reference data set (sourced from Alberta Health Provider Registry via H-Link inquiry or periodic data refresh).
- Searchable endpoint: search by last name, first name, Practitioner ID (partial/full), city, specialty.
- Results display: full name, Practitioner ID, practice discipline, primary city, registration status (active/inactive). Only active physicians in default results.
- Auto-populate Practitioner ID and name into claim fields on selection.
- "Recent Referrers" list per provider (last 20 used), displayed as quick-select above search.
- Monthly minimum data refresh. Display data currency date in UI.
- Validation: block submission if SOMB code requires referral and field is blank.
- Manual entry fallback for newly registered physicians not yet in reference data (flagged for review, not blocked).

**Files to create/modify:**
- `packages/shared/src/schemas/db/reference.schema.ts` (add `provider_registry` table)
- `apps/api/src/domains/reference/` (add registry repository, service, endpoints)
- `packages/shared/src/schemas/reference.schema.ts` (add search/result Zod schemas)

---

### B2. PHN / Eligibility Verification

**Status:** PARTIAL (format validation only)
**Priority:** P1 (gateway to claim accuracy)
**Depends on:** H-Link accreditation, Patient Registry (Domain 6)

**What exists:** Alberta PHN Luhn check validation. Out-of-province PHN acceptance (9-12 digits, no Luhn).

**What is needed:**

- Real-time H-Link eligibility inquiry when a valid-format PHN is entered. Returns coverage status for the claim's date of service.
- Inline display: "Eligible" (green), "Not Currently Eligible" (red + guidance), "Query Failed" (amber + retry).
- Guidance on ineligibility: common reasons (lapsed coverage, out-of-province, opted out) and options (verify with patient, reciprocal billing, direct billing).
- Cache eligibility results for PHN + date of service for 24 hours (avoid redundant H-Link calls for same-patient claims).
- Physician override of failed eligibility with logged warning (Alberta Good Faith Policy).
- Background eligibility checks on bulk imports (Connect Care import, EMR import) — flag ineligible claims without blocking.
- 90-day patient record cache: cached status with "Last verified: [date]" indicator and one-click re-check.
- Fallback mode (if H-Link eligibility inquiry unavailable at launch): format validation only + prompt to verify via Netcare or IVR + "I have verified this PHN" checkbox.

---

### B3. Invoice Templates and Favourites (Desktop)

**Status:** PARTIAL (mobile favourites only)
**Priority:** P1 (highest-impact usability feature for daily engagement)
**Depends on:** Claim lifecycle (Domain 4.0), Reference Data (Domain 2)

**What exists:** Mobile favourite codes (`/api/v1/favourites`) with CRUD and auto-seeding from billing history. Mobile-only.

**What is needed:**

- **Favourites on desktop claim form** (not just mobile): quick-access panel at top of service code selection. Ordered by usage frequency (default), manual drag-and-drop reordering. Each favourite stores: code, optional physician-defined label, commonly-used modifiers.
- **Auto-suggest after 5+ billings** without the code being favourited. Non-intrusive prompt.
- **Claim templates:** save a complete or partial claim as a named template. Captures: service code(s), modifiers, diagnostic code(s), facility code, and other claim fields except patient-specific data.
- **"New Claim from Template"** action. Selecting a template pre-populates all stored fields.
- **Multi-line templates:** single template with multiple service codes (e.g. consultation + procedure + time modifier).
- **Specialty-based starter templates** seeded during onboarding (e.g. Family Medicine: 03.03A Standard Office Visit, 03.04A Complete Physical, 03.01F Phone Consult).
- **Fee display on templates:** current SOMB fee for each included code, auto-updating on SOMB revision.
- **"Quick Bill" workflow:** select template + select patient (from recent or search) → create and optionally auto-submit. Two-click billing target for routine work.

---

### B4. Revenue Optimisation Alerts — Remaining Gaps

**Status:** MOSTLY BUILT (105 Tier 1 rules)
**Priority:** P2 (launch with highest-impact rules, expand continuously)
**Depends on:** Intelligence Engine (Domain 7)

**What exists:** ~105 Tier 1 rules covering modifiers, rejection prevention, WCB timing, pattern-based opportunities. Learning loop, provider personalisation, cohort data.

**What is still needed:**

- **"Unbilled WCB Opportunity" alert:** cross_claim condition — patient has active WCB claim number in Meritum + AHCIP claim submitted. Surface: "This patient has an active WCB claim. Should this service be billed to WCB instead?"
- **Periodic summary digests:** scheduled job aggregating suggestions across all claims for the billing period. Weekly email digest and dashboard summary.
- **Estimated revenue impact display:** per-alert revenue impact is already computed via `revenue_impact_formula` but needs to surface in the UI alongside each alert.
- **One-click apply from alert:** the `POST /suggestions/:id/accept` endpoint exists and applies `suggested_changes`. Needs frontend integration — inline "Apply" button on each suggestion.
- **Confidence-tiered firing** for bedside-contingent rules (see B4a below).

#### B4a. Bedside-Contingent Rule Enhancement

The ~12 rules that depend on clinical context captured at the bedside (BMI, COMP, BILAT, URGN, AFHR, NGHT, ASST, CMXP, CALD, Multiple Calls, Facility Surcharge, Counselling Add-On) currently fire on bare eligibility with soft "may apply" language. This creates alert fatigue.

**Revised approach — three confidence tiers:**

| Tier | Condition | Behaviour |
|---|---|---|
| **A — Deterministic** | System has enough data to know the answer (shift timestamps, weekend/holiday date, Connect Care multi-row encounter). | Auto-apply modifier. Show in import summary as "applied." |
| **B — High-confidence** | Physician's historical acceptance rate for this rule > 70% AND timesShown >= 5 (from `provider_learning_states`). | Pre-apply modifier as opt-out recommendation. Physician removes if inapplicable. |
| **C — Low-confidence** | Acceptance rate 30-70%, or insufficient history. | Surface as suggestion (current behaviour). |
| **Don't fire** | Acceptance rate < 30% AND timesShown >= 10. | Suppress entirely (stronger than current 5-dismissal threshold for these specific rules). |

**Implementation:** modify the rule evaluation flow in `intel.service.ts` to check `claim.importSource` and `claim.shiftId` for Tier A signals, then fall back to learning state thresholds for Tier B/C. The rule conditions in `intel.seed.ts` gain an optional `confidenceTierOverrides` field that maps data availability signals to tier assignments.

---

### B5. ARP/APP Shadow Billing — Remaining Gaps

**Status:** MOSTLY BUILT
**Priority:** P1 (data model requirement — must be architected from the start)
**Depends on:** Provider Management (Domain 5), Analytics (Domain 8)

**What exists:** TM modifier handling, ARP physician detection, shadow billing flag, $0 fee override, ARP S-code references.

**What is still needed:**

- ARP-specific dashboard section/filter in analytics: total ARP claims, total TM units, rejection rate, assessment results (filtered separately from FFS).
- TM summary report per billing period: total time units by date and service type. Supports physician's ARP program reporting obligations.
- Explicit ARP BA type labelling during onboarding (Domain 11): "FFS", "ARP Annualised", "ARP Sessional", "ARP BCM".
- ARP S-code restriction: S-codes only available when the selected BA is an ARP BA.

---

### B6. In-App Billing Guidance

**Status:** PARTIAL (help text in validation only)
**Priority:** P2 (launch with top-20 codes, expand incrementally)
**Depends on:** Reference Data (Domain 2)

**What exists:** Validation checks include `help_text` for corrective guidance. HSC code details available via reference domain.

**What is still needed:**

- **SOMB Code Tooltips** on code selection/search: official description, current fee, applicable modifiers and fee impact, common pairing codes, governing rules/restrictions.
- **Rejection Prevention Hints** per code: shown only for codes with rejection rate above configurable threshold (default: 5%). Sourced from reference data.
- **Modifier Guidance:** contextual prompts when modifiers are added or omitted.
- **ICD-9 Code Assistance:** description, common SOMB associations, flags for commonly-questioned codes.
- **Persistent "Billing Help" search** accessible from any screen.
- **"New-to-Practice" mode:** enhanced guidance for new graduates or new-to-Alberta physicians. Disableable.
- **Progressive disclosure:** minimal for experienced users (icon indicators expanding on hover/click), expanded by default for new users.
- **Usage tracking:** which guidance elements accessed vs dismissed, informing content prioritisation.
- All guidance content stored as structured reference data, updateable without code deployment.

---

### B7. Anesthesia Benefit Calculations

**Status:** PARTIAL (time validation only)
**Priority:** P2 (narrower user segment but high value per user)
**Depends on:** Reference Data (Domain 2), Claim lifecycle (Domain 4.0)

**What exists:** Anaesthesia time validation (time modifier required, 8-hour limit check). Anaesthesia codes reference data set.

**What is still needed:**

- Multi-step benefit calculator activated when billing physician's specialty is anaesthesia or anesthesia-category code is selected.
- Automatic identification of major procedure (highest listed anaesthetic benefit) when multiple surgical codes entered.
- Reduced-rate calculation for each additional procedure per SOMB.
- Conditional prompts: redo procedure (125/150%), compound fracture debridement (50% uplift), open reduction with skeletal fixation (full rate per fracture).
- Time-based claim entry: start time, end time, and/or duration. Real-time benefit display.
- Transparent calculation breakdown showing each component.
- Skin lesion single-benefit cap for procedures under 35 minutes.
- All calculation rules stored as structured reference data (GR 12), versioned and updateable without code deployment.
- Manual override logging if physician changes the calculated value.

---

### B8. Reciprocal (Out-of-Province) Billing

**Status:** PARTIAL (basic PHN acceptance only)
**Priority:** P1 (required for any ED physician seeing out-of-province patients)
**Depends on:** Patient Registry (Domain 6), Reference Data (Domain 2)

**What exists:** Out-of-province PHN validation (accepts 9-12 digits, no Luhn). GR 9 reciprocal billing restriction rule. Reciprocal restricted codes reference set.

**What is still needed:**

- **Provincial health number format definitions** as reference data (11 provinces/territories):
  - Alberta: 9 digits, Luhn variant
  - BC: 10 digits
  - Saskatchewan: 9 digits
  - Manitoba: 6 digits + optional check letter, or 9 digits (newer)
  - Ontario: 10 digits (XXXX-XXX-XXX)
  - Quebec: 4 letters + 8 digits (RAMC) — triggers private billing redirect
  - New Brunswick: 9 digits
  - Nova Scotia: 10 digits
  - PEI: 8 digits (may include leading zeros)
  - Newfoundland: 12 digits (older) or MCP format
  - Territories (YT, NT, NU): 7-9 digits variable
- **Auto-detection of province** from health number format on entry.
- **Reciprocal billing mode** on claim form: display identified province, suppress Alberta PHN validation, apply province-specific format validation.
- **Quebec detection** → redirect to private billing workflow with explanation.
- **Reciprocal billing exclusion flags** on service codes with warnings.
- **Reciprocal claim tagging** with home province. Separate reporting: volume, acceptance rate, province-specific rejection patterns.
- **Manual province override** for ambiguous or territory health numbers.
- **Card expiry handling:** prompt physician to verify coverage if entered details suggest expiry.

---

### B9. Multi-Procedure Bundling and Unbundling

**Status:** PARTIAL (warning-only detection)
**Priority:** P1 (affects claim accuracy for every multi-procedure claim from day one)
**Depends on:** Reference Data (Domain 2), Claim lifecycle (Domain 4.0)

**What exists:** A19 bundling check detects multiple same-patient same-DOS claims. Intel rule for "Bundled services — common pair same day."

**What is still needed:**

- **Structured bundling rules matrix** as reference data: code-pair matrix defining which procedures are bundled (only higher-value payable), independently billable, or intrinsically linked. Separate columns for AHCIP and WCB applicability.
- **Automatic identification** of the higher-value code when a bundled pair is detected. Recommend removing or replacing the lower-value code.
- **WCB unbundling logic:** each distinct procedure billable at 100% unless intrinsically linked. Display per-procedure fee and total.
- **Inclusive care period enforcement:** alert when a visit claim falls within the inclusive care window of a surgical claim for the same patient. Two exceptions: pre-operative conservative measures and post-operative complications (both require text justification — see B11).
- **Multiple procedure reduction schedule:** automatic application of correct reduction for secondary procedures (e.g. 50%).
- **Modifier combination validation** against SOMB rules.
- **Audit logging** of every bundling/unbundling decision (including physician overrides).
- All rules stored as structured reference data, versioned, updateable without code deployment.

---

### B10. Mixed FFS/ARP Smart Routing

**Status:** PARTIAL (PCPCM code-based routing only)
**Priority:** P1 (prevents costly mis-routing from day one for mixed-practice physicians)
**Depends on:** Provider Management (Domain 5)

**What exists:** PCPCM basket classification (in_basket/out_of_basket). BA routing by claim type. Routing reasons tracked.

**What is still needed:**

- **Facility-based routing:** during onboarding, physician maps each BA to facility codes / practice locations. Claim facility code drives BA default.
- **Time-based routing:** physician optionally defines a weekly schedule associating days/time ranges with BAs (e.g. "ARP applies Monday/Wednesday/Friday").
- **Routing priority:** (1) service code type (ARP S-code → ARP BA), (2) facility code mapping, (3) schedule mapping, (4) primary BA as fallback.
- **Prominent BA display** on claim form with one-click change.
- **Routing conflict warning:** if physician manually selects a BA that conflicts with contextual routing logic.
- **Weekly mis-routing summary alert:** FFS claims at ARP-mapped facilities or vice versa.
- Routing configuration editable at any time. Changes apply to new claims only.

---

### B11. Text Justification Templates

**Status:** NOT IMPLEMENTED
**Priority:** P2 (can launch with 3-4 core templates and expand)
**Depends on:** Claim lifecycle (Domain 4.0), Reference Data (Domain 2)

**What is needed:**

- **5 justification scenarios:** unlisted procedures, additional compensation (GR 2.6), pre-operative conservative measures, post-operative complications, WCB detailed narrative.
- **Auto-detection** of when justification is required based on service code and claim context.
- **Structured prompted fields** per scenario (e.g. post-op complication: original procedure code [auto-populated], original procedure date [auto-populated], nature of complication [free text], clinical findings [free text], treatment provided [free text]).
- **Formatted text generation** combining prompted fields into the structure Alberta Health assessors expect. Editable by physician before submission.
- **Required field validation** before submission.
- **Personal template saving:** physician saves completed justification for reuse in similar future cases.
- **Auto-population** from linked claims for complication visits and inclusive care period overrides.
- **Template definitions** stored as reference data, updateable without code deployment.
- **Justification history** searchable by scenario type and service code.

---

### B12. Shared Reference Data Dependencies

The following reference data sets are required by the features above but are not yet confirmed as fully loaded:

| Data Set | Required By | Status |
|---|---|---|
| Provider Registry (Practitioner IDs, names, specialties, locations) | B1 (Referral Search) | NOT LOADED |
| Provincial Health Number format definitions (11 provinces) | B8 (Reciprocal Billing) | NOT LOADED |
| ICD-10-CA to ICD-9 crosswalk table | A3 (ICD Crosswalk) | NOT LOADED |
| Structured bundling rules matrix (code-pairs, AHCIP + WCB columns) | B9 (Bundling) | NOT LOADED |
| Text justification template definitions (5 scenarios) | B11 (Text Justification) | NOT LOADED |
| Reciprocal billing rules (coverage per province, exclusions) | B8 (Reciprocal Billing) | PARTIAL (restricted codes exist, no per-province rules) |
| ARP S-code set | B5 (ARP Billing) | PARTIAL (referenced, unconfirmed if fully loaded) |
| SOMB Governing Rules — GR 12 structured (anesthesia calculations) | B7 (Anesthesia Calc) | NOT LOADED |
| SOMB Governing Rules — GR 2.6 structured (additional compensation) | B11 (Text Justification) | NOT LOADED |
| Inclusive care period data per surgical code | B9 (Bundling) | NOT LOADED |
| Rejection reason reference (action codes + plain-language guidance) | B6 (Billing Guidance) | NOT CONFIRMED |

---

## PART C: MOBILE COMPANION REVISIONS (DOMAIN 10)

### C1. Revised Mobile App Role for Connect Care Physicians

**Context:** When Connect Care integration is active, the physician documents clinical encounters and captures billing codes in SCC. The SCC extract provides all billing data (service codes, modifiers, diagnostic codes, patient details, facility, BA). The one critical gap in SCC data is **clock time of service** — the extract contains only the encounter date.

The mobile app's primary role for Connect Care physicians shifts from **billing data capture** to **shift timing context**. This changes the mobile companion's architecture and feature set.

**Current mobile app features (Domain 10 as built):**
- Quick claim entry (patient + code + save as draft)
- Favourite codes CRUD with auto-seeding
- ED shift management (start shift, log encounters, end shift, summary)
- Mobile patient creation
- Recent patients
- Summary KPIs
- Sync endpoint

**Revised feature set by user context:**

| Feature | Connect Care user | Non-Connect Care user |
|---|---|---|
| **Shift scheduling** (new — C2) | PRIMARY — drives reminders, auto-context, timestamp inference | USEFUL — drives reminders |
| **Shift encounter logging** (PHN scan + timestamp) | PRIMARY — fills the SCC time gap, enables reconciliation | PRIMARY — timestamps for billing |
| **Quick claim entry** | NOT USED — SCC provides billing data | PRIMARY — manual billing capture |
| **Favourite codes** | NOT USED during shift — used for non-CC clinic days | PRIMARY |
| **Mobile patient creation** | NOT USED — patients come from SCC extract | USEFUL for new patients |
| **Recent patients** | USEFUL for reconciliation reference | PRIMARY |
| **Connect Care reconciliation** (new — C4) | PRIMARY | N/A |

---

### C2. Shift Scheduling

**Status:** NOT IMPLEMENTED
**Priority:** P1 (enables proactive reminders, auto-context, fallback inference)

**Context:** Physicians typically receive their ED shift schedules weeks or months in advance. Chantelle (example user) knows her ED shift dates and times for at least the next month, often the next three months. If Meritum knows the schedule, three capabilities unlock:

1. **Proactive reminders** before shifts ("Your ED shift starts in 30 minutes — tap to start logging").
2. **Automatic shift context** even when the physician forgets to tap "Start Shift" — Meritum knows where they are and which BA applies.
3. **Fallback timestamp inference** — if the physician forgets to log individual encounters, the scheduled shift window provides approximate time-of-service for after-hours modifier determination.

#### C2.1 Functional Requirements: Shift Schedule Entry

- The physician shall be able to enter a recurring or one-off shift schedule via a calendar interface (mobile or desktop).
- Each scheduled shift captures: date, start time, end time, facility/location, BA for this shift.
- Bulk entry support: paste or import a shift roster (e.g. "every Tuesday and Thursday 18:00-02:00 at Foothills ED for March-May"). The minimum viable version is a repeating-pattern builder; a text/CSV paste is a stretch goal.
- Shifts are editable and deletable. Changes to future shifts do not affect past shift logs.
- The schedule is visible as a calendar view on both mobile and desktop, showing upcoming shifts with facility and BA labels.

#### C2.2 Functional Requirements: Shift Reminders

- The system shall send a push notification (in-app) and optionally an email reminder before each scheduled shift.
- Default reminder: 30 minutes before shift start. Configurable per physician (15 min, 30 min, 1 hour, 2 hours).
- Reminder content: "Your ED shift at [Facility] starts at [time]. Tap to start shift logging."
- Tapping the reminder opens the mobile app directly to the "Start Shift" screen with the facility and BA pre-populated from the schedule.
- If the physician does not start a shift within 15 minutes of the scheduled start time, a follow-up reminder fires: "Your shift at [Facility] started 15 minutes ago. Start logging to capture encounter timestamps."

#### C2.3 Functional Requirements: Forgotten Shift Handling

When a physician has a scheduled shift but never taps "Start Shift":

- The system creates an **implicit shift record** based on the schedule: start time = scheduled start, end time = scheduled end, facility = scheduled facility, BA = scheduled BA, status = 'INFERRED'.
- When the Connect Care import arrives and contains claims with encounter dates matching the implicit shift's date AND the facility code matches: the claims are linked to the implicit shift.
- The physician sees a reconciliation prompt: "You had a scheduled shift at [Facility] on [date] but didn't start shift logging. [N] claims from Connect Care match this shift. Apply shift times for after-hours modifier calculation?"
- If confirmed, the system applies the scheduled shift window as the time-of-service range. All encounters within this window are eligible for AFHR/NGHT based on the scheduled times.
- If the physician started the shift late (e.g. tapped "Start Shift" at 19:00 for an 18:00 scheduled start), the system uses the **earlier** of scheduled start and actual start for the shift boundary. This ensures encounters in the gap aren't lost.

#### C2.4 Data Model

New table: `shift_schedules`

| Column | Type | Description |
|---|---|---|
| schedule_id | UUID PK | |
| provider_id | UUID FK | Physician who owns this schedule |
| facility_id | UUID FK | Linked practice location |
| ba_id | UUID FK | Business arrangement for this shift |
| start_time | TIME | Shift start time (e.g. 18:00) |
| end_time | TIME | Shift end time (e.g. 02:00, interpreted as next day if < start) |
| recurrence_rule | TEXT | iCal RRULE format for recurring shifts, NULL for one-off |
| effective_from | DATE | First date this schedule applies |
| effective_until | DATE NULL | Last date (NULL = indefinite) |
| reminder_minutes_before | INT | Reminder lead time (default 30) |
| is_active | BOOLEAN | Soft delete |
| created_at | TIMESTAMPTZ | |
| updated_at | TIMESTAMPTZ | |

Modify existing `ed_shifts` table to add:

| Column | Type | Description |
|---|---|---|
| schedule_id | UUID FK NULL | Linked schedule entry (NULL for ad-hoc shifts) |
| shift_source | TEXT | 'MANUAL' (physician tapped Start) or 'INFERRED' (created from schedule) |
| inferred_confirmed | BOOLEAN NULL | Physician confirmed the inferred shift (NULL if MANUAL) |

---

### C3. Shift Encounter Logging (PHN-Based)

**Status:** EXISTS (ED shift management) — needs revision for PHN-based encounter capture
**Priority:** P1
**Depends on:** C2 (Shift Scheduling)

**Current behaviour:** The shift workflow captures encounter details (patient selection, service code, etc.) alongside timestamps. This is full billing data entry — redundant when Connect Care provides the billing data.

**Revised behaviour:** The encounter log captures **patient identity + timestamp** only. No service codes, no modifiers, no diagnostic codes. The billing data comes from the SCC import. The mobile app's job is to record *who was seen and when*.

#### C3.1 Encounter Capture Methods (in order of preference)

**Method 1: Wristband barcode scan (lowest friction, ~2 seconds)**

Hospital inpatients and ED registrations at AHS facilities receive a wristband with a barcode encoding their ULI (PHN). The mobile app uses the device camera to scan the barcode:

- Physician points phone at patient's wristband.
- App decodes the barcode, extracts the PHN, validates format (9-digit Alberta, or out-of-province format per B8 definitions).
- Records: PHN + current timestamp + active shift ID.
- Confirmation: brief haptic feedback + "Patient logged ✓ 18:32".
- No further input required. Physician moves to next patient.

This is the target interaction for hospital-based encounters. The gesture mirrors wristband scanning for medication administration, which physicians are already accustomed to in AHS facilities.

**Method 2: Quick patient search (~5 seconds)**

For patients already in Meritum's registry (common for repeat patients at rural EDs):

- Physician taps "Log Encounter" and types 2-3 characters of patient last name.
- App shows matching patients from the physician's patient registry (scoped to provider).
- Physician taps the patient. PHN is captured from the existing record.
- Records: PHN + current timestamp + active shift ID.

This is the fallback for situations where wristband scanning is impractical (e.g. patient wristband obscured, outpatient encounters, phone camera issue).

**Method 3: Manual PHN entry (~10 seconds)**

For patients not yet in Meritum's registry and where scanning is unavailable:

- Physician taps "Log Encounter" and enters the PHN manually (numeric keypad).
- App validates the format (Luhn check for Alberta, format check for out-of-province).
- Records: PHN + current timestamp + active shift ID.

This is the least preferred method but necessary for first-visit patients in non-barcode scenarios.

**Method 4: Last-4-digits shorthand (~5 seconds)**

For rapid logging in high-volume ED environments:

- Physician enters only the last 4 digits of the PHN.
- App records the partial identifier + timestamp + shift ID.
- During reconciliation (C4), the last-4 match is resolved against the full PHNs in the SCC import. Within a single shift, a 4-digit suffix is sufficient to disambiguate (the probability of two patients sharing the same last 4 digits in one ED shift is negligible).
- If an ambiguous match occurs (two patients with the same last 4 digits in the same shift), the reconciliation step prompts the physician to clarify.

#### C3.2 Non-Connect Care Users

For physicians who do not use Connect Care, the existing behaviour is preserved: encounter logging includes patient selection, service code, modifiers, and timestamp. The PHN-based logging described above is activated when the physician's profile has Connect Care integration enabled (see C5).

#### C3.3 Privacy and Security

The shift encounter log now contains PHI (PHN + timestamp). This is subject to the same controls as all other PHI in Meritum:

- **Physician scoping:** encounter logs are scoped to the authenticated provider via `provider_id`. No cross-tenant access.
- **Encryption at rest:** stored in the same PostgreSQL instance (DO Managed, Toronto) with encryption at rest.
- **PHN masking in logs:** application logs mask PHN as `123******` per existing convention.
- **Audit trail:** encounter log creation is an auditable event.
- **Retention:** encounter log entries follow the same retention policy as claim data.
- **No PHI in push notifications or emails:** shift reminders (C2.2) contain facility and time only, never patient data.

#### C3.4 Data Model Changes

Modify existing `ed_shift_encounters` table (or equivalent):

| Column | Type | Description |
|---|---|---|
| encounter_id | UUID PK | |
| shift_id | UUID FK | Parent shift |
| provider_id | UUID FK | Physician (redundant with shift, but enforces scoping) |
| patient_phn | TEXT | Full PHN (encrypted at rest) or last-4 shorthand |
| phn_capture_method | TEXT | 'BARCODE_SCAN', 'PATIENT_SEARCH', 'MANUAL_ENTRY', 'LAST_4' |
| phn_is_partial | BOOLEAN | True if only last-4 digits captured |
| logged_at | TIMESTAMPTZ | Encounter timestamp |
| matched_claim_id | UUID FK NULL | Populated during reconciliation (C4) |
| free_text_tag | TEXT NULL | Optional memory aid (bed number, initials). NOT treated as PHI — physician discretion. Excluded from exports and reports. |
| created_at | TIMESTAMPTZ | |

---

### C4. Connect Care Import Reconciliation

**Status:** NOT IMPLEMENTED
**Priority:** P1 (bridges mobile timestamps with SCC import data)
**Depends on:** A1 (SCC Parser), C2 (Shift Scheduling), C3 (Shift Encounter Logging)

**What is needed:**

When a Connect Care CSV import is processed and the physician has an active, manual, or inferred shift for the same date and facility, the system performs PHN-based matching between the SCC import rows and the shift encounter log.

#### C4.1 Matching Logic

The matching key is: **Patient PHN + Encounter Date + Facility Code**.

1. For each SCC import row, extract the Patient ULI (PHN), Encounter Date, and Facility Code.
2. Query the shift encounter log for entries where:
   - `shift.date` matches the SCC Encounter Date
   - `shift.facility_id` matches the SCC Facility Code (resolved via facility code → location mapping)
   - `encounter.patient_phn` matches the SCC Patient ULI (full match), OR `encounter.patient_phn` matches the last 4 digits of the SCC Patient ULI (if `phn_is_partial = true`)
3. On match: assign the encounter's `logged_at` timestamp to the SCC import row as the inferred time-of-service. Link the encounter to the created claim via `matched_claim_id`.
4. Multi-row encounters (multiple SCC rows for the same patient on the same date, e.g. multiple service codes): all rows receive the same timestamp from the single encounter log entry. This is correct — the physician saw the patient once and billed multiple codes.

#### C4.2 Match Categories

After matching, each SCC row and each encounter log entry falls into one of four categories:

| Category | SCC Row | Encounter Log | Meaning |
|---|---|---|---|
| **Full match** | Has matching encounter | Has matching SCC row | Timestamp assigned. Modifier inference possible. |
| **Unmatched SCC row** | No matching encounter | — | Billing code exists but no shift timestamp. Physician didn't log this encounter. |
| **Unmatched encounter** | — | No matching SCC row | Physician logged seeing a patient but no billing code in SCC. Potential missed billing. |
| **Shift-only** | Encounter date matches shift, no per-encounter log | — | No encounter logging was done during the shift. Fall back to shift window. |

#### C4.3 Handling Each Category

**Full match — timestamp assigned:**
- The claim receives `inferred_service_time = encounter.logged_at`.
- Time-based modifier rules evaluate against this timestamp:
  - Weekday 17:00-23:00 → AFHR auto-applied
  - Any day 22:00-07:00 → NGHT auto-applied
  - Weekend/holiday → AFHR auto-applied (already deterministic from date alone, but timestamp confirms)
- Show in import summary: "Timestamp 18:32 from shift log → after-hours modifier applied."

**Unmatched SCC row — no encounter log entry:**
- The physician didn't scan/log this patient during the shift.
- **If the shift window is entirely within one modifier bracket** (e.g. 22:00-06:00 = all NGHT): apply the modifier based on shift window alone. No per-encounter timestamp needed.
- **If the shift window crosses modifier boundaries** (e.g. 15:00-23:00): the system cannot determine the exact time. Prompt the physician: "1 claim could not be matched to an encounter timestamp. Your shift crossed the after-hours boundary at 17:00. Was this encounter before or after 17:00?" Offer a quick time picker defaulting to the shift midpoint.
- **If no shift exists at all** (physician didn't schedule or start a shift): no timestamp inference possible. Claim is created without time-of-service metadata. Standard Tier C intel rules fire ("Consider after-hours modifier").

**Unmatched encounter — missed billing alert:**
- The physician scanned a patient wristband but no SCC row exists for that PHN on that date.
- Surface as a **missed billing alert** in the import summary: "You logged [N] encounter(s) during your shift that have no matching billing code in Connect Care. Did you forget to capture these in SCC?"
- Display the timestamp and (if available) the free-text tag for each unmatched encounter to help the physician recall.
- The physician can: (a) go back to Connect Care and add the missing SCC entries, then re-import; or (b) create a manual claim directly in Meritum using the encounter timestamp.
- **Revenue signal:** this is one of the highest-value features of the reconciliation. Physicians missing even 1-2 encounters per shift at $30-100/encounter adds up to significant lost revenue over a month.

**Shift-only — no per-encounter logging:**
- The physician started (or has an inferred) shift but never logged individual encounters during the shift.
- All SCC rows matching the shift date + facility are linked to the shift.
- Time-of-service is inferred from the shift window:
  - If entirely after-hours: auto-apply appropriate modifier to all claims.
  - If boundary-crossing: prompt physician for approximate time per claim, or apply the conservative (lower-value) modifier and flag for review.
- Missed billing detection is not possible (no encounter log to compare against).
- The import summary encourages future encounter logging: "Logging encounters during your shift enables automatic after-hours modifier application and missed billing detection."

#### C4.4 Reconciliation Summary Display

```
Connect Care Import — 14 Feb 2026
  Source: My Billing Codes CSV
  SCC extract: 12 claims (10 patients)
  ED shift: 18:00–02:00 at Foothills ED (started manually)
  Encounter log: 11 patients scanned

  ✓ Matched: 9 patients (11 claims) — timestamps assigned
     • 5 claims: AFHR auto-applied (encounters 18:32–21:45)
     • 3 claims: NGHT auto-applied (encounters 22:15–01:30)
     • 3 claims: standard hours modifiers unchanged

  ⚠ Unmatched SCC rows: 1 patient (1 claim) — no encounter log
     • PHN ***456789, code 03.03A — shift was after-hours,
       AFHR applied based on shift window

  ⚠ Unmatched encounters: 2 patients — no SCC billing code
     • Scanned at 19:45 (tag: "bed 4") — missing from SCC?
     • Scanned at 23:30 (tag: "chest pain") — missing from SCC?

  Modifiers applied: 8 (5 AFHR, 3 NGHT)
  Estimated additional revenue from modifiers: $255.00

  [Confirm Import]  [Review Details]
```

#### C4.5 Partial PHN Resolution

When an encounter was logged with only the last 4 digits (Method 4 from C3.1):

1. During matching, the system finds all SCC rows where the Patient ULI ends with the logged 4 digits.
2. If exactly one match: resolve automatically. Link the encounter to the claim. Update `phn_is_partial` context for audit.
3. If zero matches: the partial PHN doesn't correspond to any patient in the import. Surface as an unmatched encounter (possible missed billing, or the patient was seen but billed under a different provider).
4. If multiple matches (rare — two patients with same last 4 digits in one shift): prompt the physician to select the correct patient from the matching candidates, displaying patient name and encounter details from the SCC extract to aid identification.

---

### C5. Connect Care User Onboarding

**Status:** NOT IMPLEMENTED
**Priority:** P2 (can be added post-launch with a profile settings update)

**What is needed:**

- During onboarding (Domain 11) or via provider settings, the physician indicates whether they use Connect Care for clinical documentation.
- If yes: the system enables the simplified shift clock (C3), shows the "Connect Care Import" navigation item, and adjusts the mobile app's default view to shift-focused rather than claim-entry-focused.
- If the physician later enables Connect Care: the mobile app transitions gracefully. Existing favourite codes and templates remain available for non-CC clinic days.
- Guidance on the SCC export process: a help article / in-app walkthrough explaining how to export "My Billing Codes" and "My WCB Codes" from Connect Care. Linked from the import page.
- Phase 2 (sFTP): guidance on submitting the AHS Service Code Capture Request Form to nominate Meritum as their billing software vendor.

---

## APPENDIX: IMPLEMENTATION PRIORITY SUMMARY

### P0 — Blocks MVP launch

| ID | Feature | Domain(s) |
|---|---|---|
| A1 | SCC Extract Parser | Claims |
| A2 | Connect Care Import Workflow | Claims, Frontend |

### P1 — Must be built before launch (build order matters)

| ID | Feature | Domain(s) | Build After |
|---|---|---|---|
| A3 | ICD-10/ICD-9 Crosswalk | Reference | A1 |
| A4 | Row-Level Duplicate Detection | Claims | A1 |
| A5 | Correction/Deletion Handling | Claims | A1 |
| A6 | Claim Data Model Extensions | Claims, Shared | — |
| B1 | Referral Provider Search | Reference, Provider | — |
| B2 | PHN/Eligibility Verification | Patient, H-Link | — |
| B3 | Invoice Templates & Favourites (Desktop) | Claims, Frontend | — |
| B5 | ARP Shadow Billing (remaining) | Provider, Analytics | — |
| B8 | Reciprocal Billing | Patient, Claims, Reference | — |
| B9 | Bundling/Unbundling | Claims, Reference | B12 (bundling matrix) |
| B10 | Mixed FFS/ARP Smart Routing | Provider, Claims | B5 |
| B12 | Shared Reference Data Loading | Reference | — |
| C2 | Shift Scheduling | Mobile | — |
| C3 | Shift Encounter Logging (PHN-Based) | Mobile | C2 |
| C4 | Connect Care Import Reconciliation | Claims, Mobile | A1, C2, C3 |

### P2 — Build second (additive, layer onto P1 foundation)

| ID | Feature | Domain(s) |
|---|---|---|
| B4 | Revenue Optimisation Alerts (remaining) | Intelligence |
| B4a | Bedside-Contingent Rule Enhancement | Intelligence |
| B6 | In-App Billing Guidance | Reference, Frontend |
| B7 | Anesthesia Benefit Calculations | Claims, Reference |
| B11 | Text Justification Templates | Claims, Reference |
| C5 | Connect Care User Onboarding | Onboarding, Mobile |

### Phase 2 — Post-MVP (begin process early)

| ID | Feature | Domain(s) |
|---|---|---|
| A7 | sFTP Integration | Infrastructure, Claims |

---

*End of Document*
