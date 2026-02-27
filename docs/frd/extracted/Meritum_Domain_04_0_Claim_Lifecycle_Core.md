# Meritum_Domain_04_0_Claim_Lifecycle_Core

MERITUM

Functional Requirements

Claim Lifecycle Core

Domain 4.0 of 13  |  Critical Path: Position 4

Meritum Health Technologies Inc.

Version 2.0  |  February 2026

CONFIDENTIAL

# Table of Contents

1. [Domain Overview](#1-domain-overview)
2. [Claim State Machine](#2-claim-state-machine)
3. [Base Data Model](#3-base-data-model)
4. [Validation Engine Architecture](#4-validation-engine-architecture)
5. [User Stories & Acceptance Criteria](#5-user-stories--acceptance-criteria)
6. [Shared API Contracts](#6-shared-api-contracts)
7. [Connect Care SCC Import](#7-connect-care-scc-import)
8. [Reconciliation (Shift Encounter ↔ SCC Import)](#8-reconciliation-shift-encounter--scc-import)
9. [Claim Templates & Favourites](#9-claim-templates--favourites)
10. [Anesthesia Benefit Calculations](#10-anesthesia-benefit-calculations)
11. [Multi-Procedure Bundling Engine](#11-multi-procedure-bundling-engine)
12. [Text Justification Templates](#12-text-justification-templates)
13. [Interface Contracts with Other Domains](#13-interface-contracts-with-other-domains)
14. [Security & Audit Requirements](#14-security--audit-requirements)
15. [Testing Strategy](#15-testing-strategy)
16. [Open Questions](#16-open-questions)
17. [Document Control](#17-document-control)

# 1. Domain Overview

## 1.1 Purpose

The Claim Lifecycle Core defines the shared infrastructure that underpins both the AHCIP (H-Link) and WCB (EIR) submission pathways. It owns the claim state machine, the base data model, the validation engine architecture, the clean/flagged classification system, the tiered auto-submission model, and the cross-pathway user stories and API patterns.

Every claim in Meritum — regardless of whether it is destined for Alberta Health or WCB Alberta — begins life in the same claims table, follows the same state machine, passes through the same validation pipeline structure, and is subject to the same audit and security framework. The pathway-specific logic (file formats, submission mechanisms, response processing, fee schedules) is specified in the sub-domain documents: Domain 4.1 (AHCIP) and Domain 4.2 (WCB).

Beyond core claim CRUD and state management, this domain encompasses Connect Care SCC import with duplicate detection and correction handling, reconciliation of shift encounters against SCC imports, claim templates and favourites for rapid billing, anesthesia benefit calculations per GR 12, multi-procedure bundling enforcement, and structured text justification for special billing scenarios.

## 1.2 Scope

Claim state machine: 11 states (6 non-terminal, 5 terminal) with 14 defined transitions including system-initiated expiry

Clean/flagged classification and tiered auto-submission model

Base claims table and pathway-agnostic data model (import batches, field mapping templates, ED shifts, claim templates, claim justifications, recent referrers, audit history)

Validation engine architecture: pipeline structure, result format, tiered severity model

Connect Care SCC import: SCC file parsing (21-field AHCIP, 13-field WCB), import batch workflow, row-level duplicate detection, correction/deletion handling, ICD-10-CA to ICD-9 crosswalk integration

Reconciliation service: matching mobile shift encounters against Connect Care SCC imports by PHN + date + facility, inferred service times, after-hours modifier detection, partial PHN resolution

Claim templates and favourites: pre-built and custom claim templates, quick-bill workflow, specialty starter templates

Anesthesia benefit calculations: GR 12 rule engine integration with claim validation (base units, time units, modifiers, concurrent procedure rules)

Multi-procedure bundling engine: code-pair matrix enforcement during claim validation, inclusive care period checks, WCB-specific unbundling exceptions

Text justification templates: structured justification text for 5 scenarios (unlisted procedures, additional compensation, pre-op conservative, post-op complication, WCB narrative)

Pathway-agnostic user stories: claim creation (manual, EMR import, Connect Care import, ED workflow), validation, monitoring, data portability

Shared API patterns: claim CRUD, EMR import, Connect Care import, reconciliation, templates, justifications, bundling checks, anesthesia calculations, ED shift workflow, rejection management, AI Coach interactions, data export, submission preferences

Interface contracts with consumed domains (Reference Data, Intelligence Engine, Provider Management, Patient Registry, Notification Service)

Security and audit requirements applicable to all claim types

Testing strategy framework (pathway-specific test suites are in 4.1 and 4.2)

## 1.3 Out of Scope

AHCIP-specific: H-Link file generation, Thursday batch cycle, AHCIP claim data elements, AHCIP assessment ingestion, AHCIP fee calculation, governing rules (Domain 4.1)

WCB-specific: HL7 v2.3.1 XML generation, WCB form types, WCB return file processing, WCB remittance reconciliation, WCB fee tiers, OIS forms (Domain 4.2)

AI Coach suggestion logic (Domain 7 Intelligence Engine)

Reference data management — ICD crosswalk table, anesthesia rules, bundling rules, and justification templates are defined in Domain 2 (Reference Data) and consumed by this domain

Notification delivery mechanics (Domain 3/9)

Mobile companion UI and shift scheduling (Domain 10)

## 1.4 Document Family

Domain 4 (Claim Lifecycle) comprises three sub-domain documents that should be read together:

| Document | Title | Content |
| --- | --- | --- |
| Domain 4.0 (this) | Claim Lifecycle Core | Shared state machine, base data model, validation architecture, Connect Care import, reconciliation, templates, anesthesia, bundling, justifications, cross-pathway API patterns, security, audit |
| Domain 4.1 | AHCIP Claim Pathway (H-Link) | AHCIP claim data elements, Thursday batch cycle, H-Link file generation, assessment ingestion, AHCIP validation and fee rules |
| Domain 4.2 | WCB Claim Pathway (EIR) | 8 WCB form types, HL7 XML batch submission, return file processing, remittance reconciliation, WCB validation and fee rules |

Supporting specifications folded into this document:

| Specification | Sections Incorporated |
| --- | --- |
| MHT-FRD-CC-001 Connect Care Integration | SCC parser, import workflow, duplicate detection, correction/deletion handling, ICD crosswalk integration (Sections 7, 8) |
| MHT-FRD-MVPADD-001 MVP Features Addendum | B3 Invoice Templates (Section 9), B7 Anesthesia (Section 10), B9 Bundling (Section 11), B11 Justifications (Section 12) |
| MHT-FRD-MOB-002 Mobile Companion v2 | Reconciliation matching (Section 8) |

## 1.5 Domain Dependencies

| Domain | Dependency Type | Key Interfaces |
| --- | --- | --- |
| 1 Identity & Access | Consumed | Authentication, RBAC, delegate permissions, audit logging middleware |
| 2 Reference Data | Consumed | HSC codes, governing rules, modifiers, fee schedules, DI codes, RRNP rates, stat holidays, explanatory codes, ICD crosswalk, anesthesia rules, bundling rules, justification templates |
| 3/9 Notification Service | Consumed | Deadline reminders, submission confirmations, assessment alerts, rejection notifications, payment notifications, missed billing alerts, reconciliation events |
| 5 Provider Management | Consumed | Physician BA number(s), specialty, functional centres, PCPCM status, RRNP eligibility, submission preferences |
| 6 Patient Registry | Consumed | Patient PHN, name, DOB, gender for claim creation and age-based calculations |
| 7 Intelligence Engine | Consumed | AI Coach suggestions for billing optimisation, code review, modifier recommendations |
| 10 Mobile Companion | Consumed | ED shift encounters, PHN capture, shift scheduling data for reconciliation |
| 4.1 AHCIP Pathway | Child | Extends this core with AHCIP-specific submission, validation, and fee logic |
| 4.2 WCB Pathway | Child | Extends this core with WCB-specific submission, validation, and fee logic |

# 2. Claim State Machine

Every claim in Meritum exists in exactly one state at any time. The state machine governs what actions are possible and what transitions are allowed. It applies identically to AHCIP and WCB claims — only the submission mechanism and response processing differ between pathways.

## 2.1 States

| State | Terminal? | Description |
| --- | --- | --- |
| DRAFT | No | Claim created but not yet validated. May be incomplete. The physician or delegate is actively entering data. |
| VALIDATED | No | Claim has passed validation with zero errors. May have warnings (flagged) or zero warnings (clean). Ready to be queued. |
| QUEUED | No | Claim is in the submission queue. Clean claims may auto-submit per physician preference. Flagged claims await approval. |
| SUBMITTED | No | Claim has been included in a batch file and transmitted to AHCIP (H-Link) or uploaded to WCB (myWCB portal). Awaiting response. |
| ASSESSED | No | Response received from payer. For AHCIP: assessment file processed. For WCB: return file processed. Claim accepted by payer. |
| PAID | Yes | Payment confirmed. For AHCIP: payment received in Friday deposit. For WCB: remittance record matched. |
| REJECTED | No | Payer rejected the claim. AHCIP: explanatory code(s) received. WCB: error code(s) in return file. Requires physician review. |
| ADJUSTED | Yes | Claim was paid at a different amount than submitted. Payment received but with adjustments (partial payment, modifier disallowed, etc.). |
| WRITTEN_OFF | Yes | Physician has reviewed a rejected claim and decided not to resubmit. Manual terminal state. |
| EXPIRED | Yes | Claim passed the submission window without being submitted. AHCIP: 90 calendar days from DOS. WCB: form-specific deadlines. |
| DELETED | Yes | Soft-deleted by physician. Only allowed from DRAFT state. Retained for audit but hidden from UI. |

## 2.2 State Transitions

| From | To | Trigger / Conditions |
| --- | --- | --- |
| (new) | DRAFT | Claim created via manual entry, EMR import, Connect Care SCC import, or ED shift workflow |
| DRAFT | VALIDATED | Validation engine runs with zero errors. Automatic on save if all required fields present. |
| DRAFT | DELETED | Physician explicitly deletes. Only from DRAFT. |
| VALIDATED | DRAFT | Physician edits a field that invalidates the claim, or new reference data version invalidates previously valid data. |
| VALIDATED | QUEUED | Physician explicitly queues, or auto-queue on validation pass per submission preferences. |
| QUEUED | VALIDATED | Physician unqueues (removes from submission queue). Claim returns to VALIDATED. |
| QUEUED | SUBMITTED | Batch assembly includes this claim. For AHCIP: Thursday batch. For WCB: on-demand batch. |
| SUBMITTED | ASSESSED | Payer response received and matched. Claim accepted. |
| SUBMITTED | REJECTED | Payer response received. Claim rejected with error/explanatory codes. |
| ASSESSED | PAID | Payment confirmed (AHCIP: Friday deposit; WCB: remittance XML matched). |
| ASSESSED | ADJUSTED | Payment received but at different amount than expected. |
| REJECTED | DRAFT | Physician edits claim to correct rejection reason. Returns to DRAFT for revalidation. |
| REJECTED | QUEUED | One-click resubmission: physician confirms correction and requeues directly. |
| REJECTED | WRITTEN_OFF | Physician decides not to resubmit. |
| any non-terminal | EXPIRED | Submission deadline passed. System-initiated transition via scheduled job. |

The EXPIRED transition from any non-terminal state is handled separately as a system-initiated operation, not user-triggered. The scheduled expiry job pre-fetches claims past their deadline and calls `expireClaimWithContext` with the claim's physician context.

## 2.3 Clean vs Flagged Classification

When a claim enters the QUEUED state, the system classifies it as clean or flagged. This classification drives the tiered auto-submission model.

### 2.3.1 Clean Claim

A claim is clean when all of the following are true:

- Passed all validation rules with zero warnings
- Zero AI Coach suggestions pending review (all accepted or dismissed)
- Zero unresolved flags
- No duplicate detection alerts (or all acknowledged)
- The physician has reviewed and saved the claim during individual entry

Clean claims are eligible for automatic submission per the physician's submission preference mode.

### 2.3.2 Flagged Claim

A claim is flagged when it has one or more of:

- Active AI Coach suggestions the physician has not accepted or dismissed
- Validation warnings (not errors) that require physician judgement
- Duplicate detection alert requiring confirmation
- Approaching submission deadline with incomplete information
- Any anomaly the system cannot resolve automatically

Classification is re-evaluated whenever a flagged claim is updated. If the physician addresses all flags, the claim transitions from flagged to clean. This can happen at any time before the batch cutoff. The `reclassifyQueuedClaim` service function handles re-evaluation for claims already in QUEUED state.

## 2.4 Tiered Auto-Submission Model

Each physician configures a submission preference mode that determines how their queued claims enter batches:

| Mode | Behaviour |
| --- | --- |
| AUTO_CLEAN | Clean claims are automatically included in the next batch. Flagged claims require explicit physician/delegate approval. Default for new physicians. |
| AUTO_ALL | Both clean and flagged claims are automatically included. Physician trusts the system and reviews by exception. |
| REQUIRE_APPROVAL | All claims require explicit approval before batch inclusion. No automatic submission. Suitable for physicians who prefer manual review of every claim. |

Delegates can approve flagged claims on behalf of a physician if the physician has granted the CLAIM_APPROVE delegate permission. The delegate's approval action is audit-logged with both the delegate's identity and the physician context.

The `getClaimsForAutoSubmission` service function implements batch assembly logic based on these modes, filtering QUEUED claims by is_clean status per the physician's configured preference.

# 3. Base Data Model

The base data model defines tables shared across both submission pathways. Pathway-specific extension tables (AHCIP claim elements, WCB form details, etc.) are defined in their respective sub-domain documents and linked to the base claims table via foreign key.

## 3.1 Claims Table (claims)

The central table of the platform. One row per claim regardless of pathway. The claim_type column determines which pathway-specific extension table is linked.

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| claim_id | UUID | No | Primary key |
| physician_id | UUID FK | No | FK to providers. The HIA custodian for this claim's PHI. |
| patient_id | UUID FK | No | FK to patients. |
| claim_type | VARCHAR(10) | No | AHCIP or WCB. Determines which extension tables apply and which submission pathway is used. |
| state | VARCHAR(20) | No | Current state per state machine (Section 2.1). Default: DRAFT. |
| is_clean | BOOLEAN | Yes | Null until queued. True = clean, False = flagged. |
| import_source | VARCHAR(20) | No | MANUAL, EMR_IMPORT, ED_SHIFT, CONNECT_CARE_CSV, CONNECT_CARE_SFTP, EMR_GENERIC. How the claim was created. |
| import_batch_id | UUID FK | Yes | FK to import_batches. Populated for EMR_IMPORT and Connect Care claims. |
| shift_id | UUID FK | Yes | FK to shifts. Populated for ED_SHIFT claims. |
| raw_file_reference | VARCHAR(500) | Yes | DigitalOcean Spaces path to archived source file. Populated for Connect Care imports. |
| scc_charge_status | VARCHAR(20) | Yes | ACTIVE, MODIFIED, or DELETED. From SCC extract charge status field. Null for non-Connect Care claims. |
| icd_conversion_flag | BOOLEAN | No | Default false. True when ICD-10-CA to ICD-9 conversion failed during SCC import. Blocks submission until resolved via crosswalk. |
| icd10_source_code | VARCHAR(10) | Yes | Original ICD-10-CA code from SCC extract. Retained for audit trail even after ICD-9 resolution. |
| routing_ba_id | UUID FK | Yes | Business arrangement to route claim to, if different from default. Set by PCPCM routing or manual override. |
| routing_reason | VARCHAR(30) | Yes | Reason for non-default BA routing (e.g., PCPCM_BASKET, MANUAL_OVERRIDE). |
| date_of_service | DATE | No | Date of service. Central to validation, fee calculation, and submission deadlines. |
| submission_deadline | DATE | No | Calculated deadline for this claim. AHCIP: DOS + 90 calendar days. WCB: form-specific per timing rules. |
| submitted_batch_id | UUID FK | Yes | FK to the pathway-specific batch table. Populated when claim enters SUBMITTED state. |
| validation_result | JSONB | Yes | Structured validation result (Section 4.2). Updated on each validation run. |
| validation_timestamp | TIMESTAMPTZ | Yes | When validation was last run. |
| reference_data_version | VARCHAR(20) | Yes | SOMB/WCB version used for validation. For audit traceability. |
| ai_coach_suggestions | JSONB | Yes | Array of AI Coach suggestions with status (pending, accepted, dismissed). |
| duplicate_alert | JSONB | Yes | Duplicate detection result if flagged. |
| flags | JSONB | Yes | Array of active flags causing the claim to be classified as flagged. |
| created_at | TIMESTAMPTZ | No | Creation timestamp |
| created_by | UUID FK | No | Creator (physician or delegate) |
| updated_at | TIMESTAMPTZ | No | Last update timestamp |
| updated_by | UUID FK | No | Last updater |
| deleted_at | TIMESTAMPTZ | Yes | Soft-delete timestamp. Null if active. |

Indexes: `(physician_id, state)` for dashboard queries, `(patient_id, date_of_service)` for duplicate detection, `(state, claim_type, is_clean)` for batch assembly queries, `(submission_deadline)` for expiry monitoring.

## 3.2 Import Batches Table (import_batches)

Tracks file imports (both traditional EMR and Connect Care SCC) for traceability and re-processing. A single table serves both import paths, with Connect Care extension columns populated only for SCC imports.

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| import_batch_id | UUID | No | Primary key |
| physician_id | UUID FK | No | FK to providers |
| file_name | VARCHAR(255) | No | Original uploaded filename |
| file_hash | VARCHAR(64) | No | SHA-256 hash for deduplication |
| field_mapping_template_id | UUID FK | Yes | FK to field_mapping_templates. Null if manual mapping or Connect Care import. |
| total_rows | INTEGER | No | Total rows in the import file |
| success_count | INTEGER | No | Rows successfully imported as claims |
| error_count | INTEGER | No | Rows that failed parsing or validation |
| error_details | JSONB | Yes | Per-row error details for failed rows |
| status | VARCHAR(20) | No | PENDING, PROCESSING, COMPLETED, FAILED |
| import_source | VARCHAR(30) | Yes | CONNECT_CARE_CSV, CONNECT_CARE_SFTP, EMR_GENERIC. Null for legacy EMR imports. |
| scc_spec_version | VARCHAR(20) | Yes | SCC specification version (e.g., "2025-12"). Null for non-SCC imports. |
| raw_row_count | INTEGER | Yes | Total rows in raw file before filtering. Connect Care specific. |
| valid_row_count | INTEGER | Yes | Rows passing validation. Connect Care specific. |
| warning_count | INTEGER | Yes | Rows with non-blocking warnings. Connect Care specific. |
| duplicate_count | INTEGER | Yes | Rows flagged as duplicates. Connect Care specific. |
| confirmation_status | VARCHAR(20) | Yes | PENDING, CONFIRMED, CANCELLED. Connect Care specific. |
| confirmed_at | TIMESTAMPTZ | Yes | When physician confirmed import. Connect Care specific. |
| confirmed_by | UUID FK | Yes | User ID who confirmed. Connect Care specific. |
| created_at | TIMESTAMPTZ | No | Upload timestamp |
| created_by | UUID FK | No | Uploader |

Indexes: `(physician_id, created_at)` for listing imports, unique `(physician_id, file_hash)` for deduplication, `(physician_id, confirmation_status)` for Connect Care status queries.

## 3.3 Field Mapping Templates Table (field_mapping_templates)

Stores per-physician (or per-EMR) column-to-field mappings for batch import. Reusable across imports so the physician only maps their EMR export format once.

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| template_id | UUID | No | Primary key |
| physician_id | UUID FK | No | FK to providers. Templates are physician-scoped. |
| name | VARCHAR(100) | No | Physician-assigned template name (e.g., 'Wolf EMR Export', 'Med Access Format') |
| emr_type | VARCHAR(50) | Yes | EMR system identifier if known |
| mappings | JSONB | No | Array of {source_column, target_field, transform?}. Defines how import columns map to Meritum claim fields. |
| delimiter | VARCHAR(5) | Yes | File delimiter if CSV/TSV. Auto-detected if null. |
| has_header_row | BOOLEAN | No | Whether the import file has a header row |
| date_format | VARCHAR(20) | Yes | Expected date format (e.g., YYYY-MM-DD, DD/MM/YYYY). Auto-detected if null. |
| created_at | TIMESTAMPTZ | No | |
| updated_at | TIMESTAMPTZ | No | |

## 3.4 Shifts Table (shifts) — ED Workflow

Emergency department physicians often bill for an entire shift as a batch. The shifts table groups encounters for a single ED session.

Individual patient encounters during the shift are claims in the claims table with import_source = ED_SHIFT and shift_id pointing here.

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| shift_id | UUID | No | Primary key |
| physician_id | UUID FK | No | FK to providers |
| facility_id | UUID FK | No | FK to provider's functional centre / facility |
| shift_date | DATE | No | Date of the ED shift |
| start_time | TIME | Yes | Shift start (for after-hours premium calculation) |
| end_time | TIME | Yes | Shift end |
| status | VARCHAR(20) | No | IN_PROGRESS, COMPLETED, SUBMITTED |
| encounter_count | INTEGER | No | Number of encounters (claims) in this shift. Default 0. |
| created_at | TIMESTAMPTZ | No | |
| updated_at | TIMESTAMPTZ | No | |

Indexes: `(physician_id, shift_date)` for dashboard queries.

## 3.5 Claim Templates Table (claim_templates)

Physician-specific reusable claim templates for rapid billing. Templates can be custom (physician-created) or specialty starters (seeded during onboarding).

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| template_id | UUID | No | Primary key |
| physician_id | UUID FK | No | FK to providers. Templates are physician-scoped. |
| name | VARCHAR(100) | No | Template display name |
| description | TEXT | Yes | Optional description |
| template_type | VARCHAR(30) | No | CUSTOM or SPECIALTY_STARTER |
| claim_type | VARCHAR(10) | No | AHCIP or WCB |
| line_items | JSONB | No | Array of TemplateLineItem objects |
| specialty_code | VARCHAR(10) | Yes | For specialty starters: the specialty code this template targets |
| usage_count | INTEGER | No | Times this template has been used. Default 0. Drives sort order. |
| is_active | BOOLEAN | No | Soft delete. Default true. |
| created_at | TIMESTAMPTZ | No | |
| updated_at | TIMESTAMPTZ | No | |

The `line_items` JSONB stores an array of objects with the following structure:

```typescript
interface TemplateLineItem {
  health_service_code: string;  // SOMB code
  modifiers?: string[];         // Default modifiers for this code
  diagnostic_code?: string;     // Default diagnostic code
  calls?: number;               // Number of calls (default 1)
}
```

Indexes: `(physician_id, is_active)` for listing templates, `(specialty_code, template_type)` for specialty lookups.

## 3.6 Claim Justifications Table (claim_justifications)

Per-claim text justifications attached to claims requiring narrative support for special billing scenarios.

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| justification_id | UUID | No | Primary key |
| claim_id | UUID FK | No | FK to claims |
| physician_id | UUID FK | No | FK to providers. Physician scoping. |
| scenario | VARCHAR(40) | No | Justification scenario type (see Section 12.1) |
| justification_text | TEXT | No | The justification narrative text |
| template_id | UUID FK | Yes | FK to justification_templates (Reference Data). Null if manually composed. |
| created_at | TIMESTAMPTZ | No | |
| updated_at | TIMESTAMPTZ | No | |
| created_by | UUID FK | No | User who created |

Indexes: `(claim_id)` for claim detail lookups, `(physician_id, scenario)` for history queries.

## 3.7 Recent Referrers Table (recent_referrers)

Tracks recently used referring physicians per provider for quick selection during claim creation.

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| id | UUID | No | Primary key |
| physician_id | UUID FK | No | FK to providers. Physician-scoped. |
| referrer_cpsa | VARCHAR(10) | No | CPSA number of the referring physician |
| referrer_name | VARCHAR(100) | No | Display name of the referring physician |
| use_count | INTEGER | No | Times this referrer has been used. Default 1. |
| last_used_at | TIMESTAMPTZ | No | Most recent use timestamp |

Constraints: unique `(physician_id, referrer_cpsa)`. Indexes: `(physician_id, last_used_at)` for MRU listing.

## 3.8 Claim Exports Table (claim_exports)

Tracks data export requests and their generated files.

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| export_id | UUID | No | Primary key |
| physician_id | UUID FK | No | FK to providers. Physician-scoped. |
| date_from | DATE | No | Export date range start |
| date_to | DATE | No | Export date range end |
| claim_type | VARCHAR(10) | Yes | Optional filter by claim type |
| format | VARCHAR(10) | No | CSV or JSON |
| status | VARCHAR(20) | No | PENDING, PROCESSING, COMPLETED, FAILED |
| file_path | VARCHAR(500) | Yes | DigitalOcean Spaces object key for generated file |
| created_at | TIMESTAMPTZ | No | |
| updated_at | TIMESTAMPTZ | No | |

## 3.9 Claim Audit History Table (claim_audit_history)

Every state change and significant edit to a claim is recorded. This is separate from the system-wide audit log (Domain 1) and provides claim-level traceability that supports both clinical audit and billing dispute resolution.

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| audit_id | UUID | No | Primary key |
| claim_id | UUID FK | No | FK to claims |
| action | VARCHAR(30) | No | See action enum below |
| previous_state | VARCHAR(20) | Yes | State before the action (null for CREATED) |
| new_state | VARCHAR(20) | Yes | State after the action |
| changes | JSONB | Yes | For EDITED: field-level diff {field, old_value, new_value}. For AI actions: suggestion details. |
| actor_id | UUID FK | No | Who performed the action (physician, delegate, or SYSTEM) |
| actor_context | VARCHAR(20) | No | PHYSICIAN, DELEGATE, SYSTEM. SYSTEM for automated transitions (expiry, batch assembly). |
| reason | TEXT | Yes | Optional reason (e.g., write-off justification, AI suggestion dismissal reason) |
| created_at | TIMESTAMPTZ | No | When the action occurred |

Audit action values (25 actions):

| Action | Description |
| --- | --- |
| claim.created | Claim created (with import_source) |
| claim.edited | Claim fields modified (changes JSONB contains diff) |
| claim.validated | Claim passed validation |
| claim.queued | Claim entered submission queue |
| claim.unqueued | Claim removed from queue |
| claim.submitted | Claim included in batch |
| claim.assessed | Payer response received |
| claim.rejected | Payer rejected claim |
| claim.resubmitted | Rejected claim requeued after correction |
| claim.written_off | Physician wrote off rejected claim |
| claim.deleted | Soft-deleted by physician |
| claim.expired | System-initiated deadline expiry |
| claim.ai_suggestion_accepted | AI Coach suggestion accepted |
| claim.ai_suggestion_dismissed | AI Coach suggestion dismissed |
| claim.duplicate_acknowledged | Duplicate detection acknowledged |
| shift.created | ED shift created |
| shift.completed | ED shift completed |
| claim.template_created | Claim template created |
| claim.template_updated | Claim template updated |
| claim.template_deleted | Claim template deleted |
| claim.justification_created | Justification attached to claim |
| claim.justification_updated | Justification text modified |
| claim.bundling_override | Physician overrode bundling restriction |
| claim.anesthesia_override | Physician overrode calculated anesthesia benefit |
| claim.routing_override | Physician overrode BA routing |

Retention: Claim audit history is retained for the lifetime of the claim plus 10 years (Alberta HIA custodian retention requirement). The audit log is append-only — no UPDATE or DELETE operations are permitted. The repository exposes only an insert method.

Indexes: `(claim_id, created_at)` for timeline view, `(actor_id, created_at)` for actor activity log.

# 4. Validation Engine Architecture

The validation engine is the quality gate of Meritum. It evaluates every claim against all applicable rules before the claim can be queued for submission. The engine is pathway-aware: after running shared structural checks, it delegates to the AHCIP validation module (Domain 4.1) or the WCB validation module (Domain 4.2) based on claim_type.

## 4.1 Pipeline Structure

Validation runs as an ordered pipeline of checks. Earlier checks may short-circuit later ones (e.g., if claim_type is invalid, no further checks run). The pipeline structure is:

1. Shared structural checks (this document): claim_type valid, required base fields present, date_of_service valid, patient exists, physician exists

2. Submission deadline check: is the claim within its submission window?

3. Duplicate detection: same patient + same DOS + same primary code within configurable window

4. ICD conversion check: if `icd_conversion_flag = true` and `diagnostic_code IS NULL`, the claim cannot proceed to submission (Connect Care specific)

5. Bundling check: if multiple codes on same DOS for same patient, run bundling matrix lookup and flag conflicts (Section 11)

6. Pathway delegation: route to AHCIP module (Domain 4.1, Section 5) or WCB module (Domain 4.2, Section 4) based on claim_type

7. AI Coach analysis: after validation, send claim context to Intelligence Engine for suggestions (non-blocking; suggestions are advisory)

## 4.2 Validation Result Structure

The validation result is a structured object stored on the claim's validation_result JSONB field:

```typescript
interface ValidationResult {
  errors: ValidationEntry[];     // Blocks queuing
  warnings: ValidationEntry[];   // Causes flagged classification
  info: ValidationEntry[];       // Advisory, no impact
  passed: boolean;               // True if zero errors
  validation_timestamp: string;  // ISO 8601
  reference_data_version: string; // SOMB/WCB version used
}

interface ValidationEntry {
  check: string;          // Check ID (e.g., S1_CLAIM_TYPE_VALID)
  rule_reference: string; // FRD section reference
  message: string;        // Human-readable description
  help_text: string;      // Corrective guidance
  field_affected?: string; // Which field(s) triggered this
}
```

## 4.3 Shared Validation Checks

These checks run for all claims regardless of pathway:

| # | Check ID | Severity | Description |
| --- | --- | --- | --- |
| S1 | S1_CLAIM_TYPE_VALID | Error | claim_type is AHCIP or WCB |
| S2 | S2_REQUIRED_BASE_FIELDS | Error | physician_id, patient_id, date_of_service are present |
| S3 | S3_PATIENT_EXISTS | Error | patient_id resolves to a valid patient record in physician's registry |
| S4 | S4_PHYSICIAN_ACTIVE | Error | physician_id resolves to an active provider with valid BA/billing number |
| S5 | S5_DOS_VALID | Error | date_of_service is a valid date, not in the future, not before physician's registration date |
| S6 | S6_SUBMISSION_WINDOW | Error/Warn | AHCIP: DOS within 90 calendar days. WCB: form-specific. Error if expired; Warning if within 7 days of deadline. |
| S7 | S7_DUPLICATE_DETECTION | Warning | Same patient + same DOS + same primary service code found in existing non-deleted claims. Warning, not error — intentional duplicates are valid in some scenarios (e.g., radiology). |

After shared checks pass, the pipeline delegates to the pathway-specific module. If S1 fails (invalid claim_type), all subsequent checks are skipped.

## 4.4 Validation Timing

On save: Validation runs automatically when the physician saves a claim (after every field change in the guided form). Results update in real-time in the UI.

On queue: Full re-validation before the claim enters the queue. If new errors appear (e.g., reference data updated), the claim cannot be queued.

Pre-batch: Final validation before batch assembly. Claims that have become invalid since queuing are removed from the batch and returned to VALIDATED state with notification.

Reference data version: Validation always uses the current reference data version. The version used is recorded on the claim for audit.

The `runValidationChecks` function provides a non-state-mutating validation path used by the resubmit workflow — it runs the same pipeline without altering the claim's state.

# 5. User Stories & Acceptance Criteria

These user stories cover pathway-agnostic claim lifecycle interactions. AHCIP-specific stories (Thursday batch, H-Link) are in Domain 4.1. WCB-specific stories (form type selection, XML generation) are in Domain 4.2.

## 5.1 Claim Creation

| ID | Story | Acceptance Criteria |
| --- | --- | --- |
| CLM-001 | As a physician, I want to create a new claim via a guided form so that I can bill for a patient encounter | Guided form shows fields relevant to selected claim_type. Required fields are visually indicated. Validation runs on save. Claim enters DRAFT state. AI Coach suggestions appear after initial validation. |
| CLM-002 | As a physician, I want to import claims from my EMR export so that I can avoid double-entry | Upload CSV/delimited file. Apply saved field mapping template or create new one. Preview mapped data before import. Validation runs on each row. Success/error count displayed. Failed rows with specific error messages. |
| CLM-003 | As an ED physician, I want to add patient encounters during my shift so that I can bill them as a batch at shift end | Create shift with facility and date. Add encounters during shift. Review all encounters at shift end. Queue entire shift as a batch. After-hours premiums auto-calculated from shift times. |
| CLM-004 | As a delegate, I want to create claims on behalf of my physician so that I can support their billing workflow | Delegate creates claim in physician context. Claim is owned by the physician (HIA custodian). Delegate's identity recorded in audit trail. Delegate permissions checked per RBAC. |
| CLM-016 | As a physician, I want to import claims from Connect Care SCC extracts so that billing codes from my hospital shifts are captured automatically | Upload SCC CSV. Parser auto-detects AHCIP vs WCB format. Preview parsed rows with validation messages. Confirm to create DRAFT claims. Duplicate rows flagged. Correction/deletion rows handled. ICD conversion flags surfaced. |
| CLM-017 | As a physician, I want to apply a saved claim template for rapid billing of common encounters | Select template from favourites. Specify patient and date of service. System creates claims from template line items. Claims enter DRAFT state. Template usage count incremented. |

## 5.2 Validation & Queue

| ID | Story | Acceptance Criteria |
| --- | --- | --- |
| CLM-005 | As a physician, I want real-time validation feedback so that I can fix errors before submission | Validation runs on save. Errors displayed inline next to affected fields. Warnings displayed as non-blocking alerts. Error count shown in claim header. |
| CLM-006 | As a physician, I want to queue validated claims for submission | Only validated claims (zero errors) can be queued. Clean/flagged classification applied at queue time. Physician sees classification status. |
| CLM-007 | As a physician, I want AI Coach suggestions to help me optimise my billing | After validation, AI Coach suggestions appear as actionable cards. Each suggestion shows: what to change, expected revenue impact, confidence level. Accept or dismiss with optional reason. |
| CLM-018 | As a physician, I want bundling conflicts detected before I submit | When multiple procedure codes are billed for the same patient on the same DOS, bundling check runs automatically. Conflicting code pairs flagged with relationship type and recommendation. Physician can override with justification. |
| CLM-019 | As an anesthesiologist, I want benefits calculated correctly for my procedures | Enter procedure codes and anaesthesia duration. System applies GR 12 rules: identifies major procedure, applies reduced rates for additional procedures, handles special scenarios (redo cardiac, compound fractures). Calculated benefit displayed with breakdown. |

## 5.3 Submission & Batch

| ID | Story | Acceptance Criteria |
| --- | --- | --- |
| CLM-008 | As a physician, I want my clean claims to auto-submit per my preference | Per tiered auto-submission model. Auto Clean: clean claims included automatically. Auto All: all queued claims. Require Approval: none without explicit approval. |
| CLM-009 | As a delegate, I want to approve flagged claims for submission | Delegate sees flagged claims with their flags. Can review each flag, then approve or return to physician. Approval logged with delegate identity. |

## 5.4 Assessment & Rejection

| ID | Story | Acceptance Criteria |
| --- | --- | --- |
| CLM-010 | As a physician, I want to see assessment results when they arrive | Notification emitted when assessment processed. Claim state updated. Assessed claims show acceptance confirmation. |
| CLM-011 | As a physician, I want to understand why a claim was rejected and how to fix it | Rejected claims show: explanatory/error code(s), human-readable description, corrective guidance (system-generated from Reference Data), one-click resubmit after correction. |
| CLM-012 | As a physician, I want to write off a rejected claim I don't intend to resubmit | Write-off action available on rejected claims. Requires confirmation and reason text (1–500 characters). Write-off reason recorded in audit. Claim enters terminal WRITTEN_OFF state. |

## 5.5 Monitoring & Portability

| ID | Story | Acceptance Criteria |
| --- | --- | --- |
| CLM-013 | As a physician, I want to see claims approaching their submission deadline | Dashboard widget shows claims within 7 days of deadline. Sorted by urgency. Notification emitted at 7, 3, and 1 day(s) before deadline. |
| CLM-014 | As a physician, I want to export my complete claim history | Export all claims as CSV or JSON. Includes all fields, states, audit trail. Downloadable via authenticated link. Supports date range and claim type filtering. |
| CLM-015 | As a physician, I want to see potential duplicate claims before I submit them | Duplicate detection runs during validation. Matching criteria: same patient + same DOS + same primary code. Alert shows the existing claim for comparison. Physician can acknowledge (intentional) or merge. |

## 5.6 Justifications

| ID | Story | Acceptance Criteria |
| --- | --- | --- |
| CLM-020 | As a physician, I want to attach a structured justification to a claim when required | Select justification scenario. Fill in template fields or write free-form narrative. Justification attached to claim. Text included in submission where pathway supports it. |
| CLM-021 | As a physician, I want to search my past justifications so I can reuse effective wording | Search justification history by scenario type. View past justifications with outcomes. Save as personal reusable template. |

# 6. Shared API Contracts

All endpoints require authentication via Domain 1 (Identity & Access). All state-changing operations are audit-logged. Physician endpoints are scoped to the authenticated physician or the delegate's physician context. Pathway-specific endpoints (AHCIP batch, WCB batch, etc.) are defined in their respective sub-domain documents.

## 6.1 Claim CRUD

| Method | Endpoint | Permission | Description |
| --- | --- | --- | --- |
| POST | /api/v1/claims | CLAIM_CREATE | Create a claim. Body includes claim_type (AHCIP or WCB). |
| GET | /api/v1/claims | CLAIM_VIEW | List claims with filtering: state, claim_type, date range, patient, is_clean. Paginated. |
| GET | /api/v1/claims/{id} | CLAIM_VIEW | Retrieve claim with all details, validation result, AI suggestions, flags. |
| PUT | /api/v1/claims/{id} | CLAIM_EDIT | Update claim. Triggers revalidation. Partial updates supported. |
| DELETE | /api/v1/claims/{id} | CLAIM_DELETE | Soft-delete. Only from DRAFT state. Returns 409 CONFLICT if claim is not in DRAFT. |
| POST | /api/v1/claims/{id}/validate | CLAIM_EDIT | Run validation pipeline and return results. Transitions DRAFT→VALIDATED if zero errors. |
| POST | /api/v1/claims/{id}/queue | CLAIM_SUBMIT | Queue a validated claim for submission. Re-validates, classifies clean/flagged. |
| POST | /api/v1/claims/{id}/unqueue | CLAIM_SUBMIT | Remove from submission queue. Returns to VALIDATED state. |
| POST | /api/v1/claims/{id}/write-off | CLAIM_EDIT | Write off a rejected claim. Body: `{ reason: string }`. Terminal. |
| POST | /api/v1/claims/{id}/resubmit | CLAIM_SUBMIT | One-click resubmission after correction. Revalidates and requeues REJECTED→QUEUED. |
| GET | /api/v1/claims/{id}/audit | CLAIM_VIEW | Get claim audit history timeline. |

## 6.2 EMR Import

| Method | Endpoint | Permission | Description |
| --- | --- | --- | --- |
| POST | /api/v1/imports | CLAIM_CREATE | Upload EMR export file. Optionally specify field_mapping_template_id. |
| GET | /api/v1/imports/{id} | CLAIM_VIEW | Get import status, success/error counts, error details. |
| GET | /api/v1/imports/{id}/preview | CLAIM_VIEW | Preview mapped data before committing import. |
| POST | /api/v1/imports/{id}/commit | CLAIM_CREATE | Commit previewed import. Creates claims from successfully mapped rows. |

## 6.3 Field Mapping Templates

| Method | Endpoint | Permission | Description |
| --- | --- | --- | --- |
| POST | /api/v1/field-mapping-templates | CLAIM_CREATE | Create a new field mapping template. |
| GET | /api/v1/field-mapping-templates | CLAIM_VIEW | List templates for the authenticated physician. |
| PUT | /api/v1/field-mapping-templates/{id} | CLAIM_EDIT | Update a template. |
| DELETE | /api/v1/field-mapping-templates/{id} | CLAIM_DELETE | Delete a template. |

## 6.4 ED Shift Workflow

| Method | Endpoint | Permission | Description |
| --- | --- | --- | --- |
| POST | /api/v1/shifts | CLAIM_CREATE | Create a new ED shift. Verifies facility belongs to physician. |
| POST | /api/v1/shifts/{id}/encounters | CLAIM_CREATE | Add an encounter (claim) to the shift. Shift must be IN_PROGRESS. |
| PUT | /api/v1/shifts/{id}/complete | CLAIM_EDIT | Complete the shift. Triggers after-hours premium calculation for all encounters. |
| GET | /api/v1/shifts/{id} | CLAIM_VIEW | Get shift details with all linked encounters/claims. |

## 6.5 Rejection Management

| Method | Endpoint | Permission | Description |
| --- | --- | --- | --- |
| GET | /api/v1/claims/rejected | CLAIM_VIEW | List rejected claims with explanatory codes and corrective guidance. Paginated. |
| GET | /api/v1/claims/{id}/rejection-details | CLAIM_VIEW | Get detailed rejection info: codes, descriptions, suggested corrections, resubmission eligibility. |
| POST | /api/v1/claims/{id}/resubmit | CLAIM_SUBMIT | One-click resubmission after correction. |

## 6.6 AI Coach Interactions

| Method | Endpoint | Permission | Description |
| --- | --- | --- | --- |
| GET | /api/v1/claims/{id}/suggestions | CLAIM_VIEW | Get AI Coach suggestions for this claim. |
| POST | /api/v1/claims/{id}/suggestions/{sug_id}/accept | CLAIM_EDIT | Accept a suggestion. Applies the suggested change to the claim. |
| POST | /api/v1/claims/{id}/suggestions/{sug_id}/dismiss | CLAIM_EDIT | Dismiss a suggestion. Body: `{ reason?: string }`. Clears the suggestion flag. |

## 6.7 Data Export

| Method | Endpoint | Permission | Description |
| --- | --- | --- | --- |
| POST | /api/v1/exports | CLAIM_VIEW | Request a claim history export. Parameters: date range, claim_type filter, format (CSV, JSON). |
| GET | /api/v1/exports/{id} | CLAIM_VIEW | Check export status and download when ready. |

## 6.8 Submission Preferences

| Method | Endpoint | Permission | Description |
| --- | --- | --- | --- |
| GET | /api/v1/submission-preferences | CLAIM_VIEW | Get current auto-submission mode for the physician. |
| PUT | /api/v1/submission-preferences | CLAIM_EDIT | Update auto-submission mode. Body: `{ mode: "AUTO_CLEAN" | "AUTO_ALL" | "REQUIRE_APPROVAL" }`. Audit-logged. |

## 6.9 Claim Templates

| Method | Endpoint | Permission | Description |
| --- | --- | --- | --- |
| GET | /api/v1/claims/templates | CLAIM_VIEW | List templates. Filterable by template_type (CUSTOM, SPECIALTY_STARTER) and claim_type. Paginated. |
| POST | /api/v1/claims/templates | CLAIM_CREATE | Create a new claim template with line items. |
| PUT | /api/v1/claims/templates/{id} | CLAIM_EDIT | Update template name, description, or line items. |
| DELETE | /api/v1/claims/templates/{id} | CLAIM_DELETE | Soft-delete template. |
| POST | /api/v1/claims/templates/{id}/apply | CLAIM_CREATE | Apply template to create claims. Body: `{ patient_id, date_of_service, auto_submit? }`. |
| PUT | /api/v1/claims/templates/reorder | CLAIM_EDIT | Reorder templates. Body: `{ template_ids: string[] }`. |

## 6.10 Claim Justifications

| Method | Endpoint | Permission | Description |
| --- | --- | --- | --- |
| POST | /api/v1/claims/{id}/justification | CLAIM_EDIT | Create justification for a claim. Body: `{ scenario, justification_text, template_id? }`. |
| GET | /api/v1/claims/{id}/justification | CLAIM_VIEW | Get justification for a specific claim. |
| GET | /api/v1/claims/justifications/history | CLAIM_VIEW | Search justification history. Filterable by scenario. Paginated. |
| POST | /api/v1/claims/justifications/{id}/save-personal | CLAIM_EDIT | Save justification as personal reusable template. |

## 6.11 Recent Referrers

| Method | Endpoint | Permission | Description |
| --- | --- | --- | --- |
| GET | /api/v1/claims/referrers/recent | CLAIM_VIEW | List recently used referring physicians, ordered by last_used_at. |
| POST | /api/v1/claims/referrers/recent | CLAIM_CREATE | Record use of a referring physician. Body: `{ referrer_cpsa, referrer_name }`. Upserts on physician+CPSA unique constraint. |

## 6.12 Bundling Check

| Method | Endpoint | Permission | Description |
| --- | --- | --- | --- |
| POST | /api/v1/claims/bundling/check | CLAIM_VIEW | Check bundling conflicts for a set of codes. Body: `{ codes: string[], claim_type, patient_id?, date_of_service? }`. Returns conflict analysis per code pair. |

## 6.13 Anesthesia Calculator

| Method | Endpoint | Permission | Description |
| --- | --- | --- | --- |
| POST | /api/v1/claims/anesthesia/calculate | CLAIM_VIEW | Calculate anesthesia benefit. Body: `{ procedure_codes: string[], start_time?, end_time?, duration_minutes? }`. Returns breakdown with per-procedure values and total benefit. |

# 7. Connect Care SCC Import

This section specifies the Connect Care integration subsystem for importing claims from SCC (Sunrise Clinical Coordinator) extracts. This is an alternative claim creation path alongside manual entry and traditional EMR import.

## 7.1 Overview

Connect Care is Alberta Health Services' province-wide clinical information system. Physicians working in AHS facilities generate billing codes through Connect Care, which can be exported as structured CSV files. Meritum parses these files, validates each row, detects duplicates and corrections, and creates DRAFT claims for physician review.

The import workflow follows a preview-then-confirm pattern: the physician uploads a file, reviews parsed rows with validation messages, and explicitly confirms before claims are created.

## 7.2 SCC Extract Specifications

### 7.2.1 AHCIP Extract ("My Billing Codes") — 21 Fields

| # | Field | Description |
| --- | --- | --- |
| 1 | Encounter Date | Date of service (YYYY-MM-DD) |
| 2 | Patient ULI | Alberta PHN (9 digits) |
| 3 | Patient Name | Full name |
| 4 | Patient DOB | Date of birth |
| 5 | Patient Gender | M/F/X |
| 6 | Patient Insurer | Insurance provider |
| 7 | Coverage Status | Coverage validity |
| 8 | Service Code | SOMB code |
| 9 | Service Code Description | SOMB description |
| 10 | Modifier(s) | Comma or pipe-delimited modifier codes |
| 11 | Diagnostic Code (ICD-9) | ICD-9 diagnostic code (may be blank if ICD-10 conversion failed) |
| 12 | ICD-10-CA Source Code | Original ICD-10-CA code from Connect Care |
| 13 | ICD Conversion Flag | Boolean: true if ICD-10→ICD-9 conversion was unsuccessful |
| 14 | Referring Provider ID | CPSA number of referring physician |
| 15 | Referring Provider Name | Name of referring physician |
| 16 | Billing Provider ID | CPSA number of billing physician |
| 17 | Business Arrangement Number | BA number |
| 18 | Facility Code | AHS facility code |
| 19 | Functional Centre | Functional centre code |
| 20 | Encounter Type | OFFICE, HOSPITAL, ED, VIRTUAL, FACILITY |
| 21 | Charge Status | ACTIVE, MODIFIED, DELETED |

### 7.2.2 WCB Extract ("My WCB Codes") — 13 Fields

| # | Field | Description |
| --- | --- | --- |
| 1 | WCB Claim Number | WCB case identifier |
| 2 | Employer Name | Employer |
| 3 | Injury Date | Date of injury |
| 4 | Date of Service | Encounter date |
| 5 | Patient ULI | Alberta PHN |
| 6 | Patient Name | Full name |
| 7 | Patient DOB | Date of birth |
| 8 | Patient Gender | M/F/X |
| 9 | Service Code | SOMB or WCB-specific code |
| 10 | Diagnostic Code | ICD-9 diagnostic code |
| 11 | Billing Provider ID / BA Number | Combined provider + BA |
| 12 | Facility Code | AHS facility code |
| 13 | Charge Status | ACTIVE, MODIFIED, DELETED |

The parser auto-detects AHCIP vs WCB format by checking for WCB-specific column headers (WCB Claim Number, Employer Name, Injury Date).

## 7.3 SCC Parser

The SCC parser (`scc-parser.service.ts`) processes CSV content with the following capabilities:

**Delimiter detection:** Auto-detects comma, tab, or pipe delimiter from the first line.

**Extract type detection:** Classifies AHCIP vs WCB based on presence of WCB-specific headers.

**Provider identity validation:** Verifies that the billing provider ID and BA number in the extract match the authenticated physician's profile. If mismatch, the entire file is rejected.

**Header mapping:** Case-insensitive, flexible mapping of column headers to internal field names. Supports common variations (e.g., "Service Code (SOMB)" maps to serviceCode).

**Modifier parsing:** Parses comma-delimited or pipe-delimited modifier strings into arrays.

**Row validation:** 3-tier severity model:

| Severity | Handling | Examples |
| --- | --- | --- |
| BLOCKING | Row rejected, not importable | Missing Patient ULI, invalid ULI format, missing service code, future encounter date |
| WARNING | Claim created with warning indicator | Unrecognised SOMB code, ICD conversion flag set, encounter >90 days old, missing referring provider for specialist |
| INFORMATIONAL | Logged for awareness | Charge status = DELETED, potential duplicate detected |

**Row classification:** Each parsed row receives a classification: VALID, WARNING, ERROR, DELETED, or DUPLICATE.

**Parse result structure:**

```typescript
interface ParseResult {
  extractType: 'AHCIP' | 'WCB';
  specVersion: string;
  fileName: string;
  totalRows: number;
  validCount: number;
  warningCount: number;
  errorCount: number;
  duplicateCount: number;
  deletedCount: number;
  rows: ParsedRow[];
}
```

Current SCC specification version: `2025-12` (21 AHCIP fields, 13 WCB fields).

## 7.4 Import Workflow

### 7.4.1 Upload and Parse

**Endpoint:** `POST /api/v1/claims/connect-care/import`

**Request:** Multipart file upload (CSV/XLSX/XLS, max 10 MB, max 10,000 rows). Body includes optional `extract_type` and `spec_version`.

**Processing:**

1. Validate file extension (.csv, .CSV, .xlsx, .xls) and size (≤ 10 MB)
2. Compute SHA-256 file hash for deduplication
3. Parse via `parseSccExtract()` with provider context validation
4. Run `detectRowDuplicates()` — matches against existing claims by composite key (Patient ULI + Encounter Date + Service Code + Billing Provider ID)
5. Run `handleCorrections()` — processes DELETED and MODIFIED charge status rows
6. Archive raw file to DigitalOcean Spaces at `imports/{provider_id}/{yyyy-mm}/{uuid}.{ext}`
7. Create import_batches record with status=PENDING, confirmation_status=PENDING
8. Audit log: connect_care.import_uploaded
9. Return importBatchId + ParseResult + rawFilePath

### 7.4.2 Review Import

**Endpoint:** `GET /api/v1/claims/connect-care/import/{id}`

Returns the import batch with full parsed row data, validation messages, duplicate flags, and summary statistics.

### 7.4.3 Confirm Import

**Endpoint:** `POST /api/v1/claims/connect-care/import/{id}/confirm`

**Request Body:** `{ action: "CONFIRMED" | "CANCELLED", excluded_row_ids?: string[] }`

**Processing (on CONFIRMED):**

1. Verify batch exists and is in PENDING status
2. Iterate rows in ParseResult:
   - Skip excluded rows
   - Skip ERROR rows
   - Skip DUPLICATE rows (unless explicitly included)
   - Skip DELETED rows
   - Create DRAFT claim for all VALID and WARNING rows
3. Tag each created claim with: import_source = CONNECT_CARE_CSV, import_batch_id, raw_file_reference, scc_charge_status, icd_conversion_flag, icd10_source_code
4. Calculate submission_deadline per claim (AHCIP: DOS + 90 days; WCB: form-specific)
5. Update batch status to CONFIRMED
6. Audit log: connect_care.import_confirmed

### 7.4.4 Cancel Import

**Endpoint:** `POST /api/v1/claims/connect-care/import/{id}/cancel`

Sets confirmation_status to CANCELLED. No claims created. Raw file retained for audit.

### 7.4.5 Import History

**Endpoint:** `GET /api/v1/claims/connect-care/import/history`

Returns paginated list of import batches scoped to the authenticated physician. Filterable by confirmation status.

## 7.5 Duplicate Detection

### 7.5.1 Composite Key

Duplicates are detected using the composite key: **Patient ULI + Encounter Date + Service Code + Billing Provider ID**.

Same patient on the same date with different service codes is normal multi-code billing and is not flagged as a duplicate.

### 7.5.2 Handling

- Physician sees duplicate flag in import preview with reference to existing claim
- Physician can choose to skip (default) or create anyway
- Duplicate claims that are created carry a duplicate_alert JSONB on the claim record
- The duplicate check runs both within the import file (intra-file duplicates) and against existing claims in the database (cross-import duplicates)

## 7.6 Correction and Deletion Handling

SCC extracts include a charge_status field indicating whether a billing code has been modified or deleted in Connect Care after the original entry.

### 7.6.1 DELETED Rows

1. Search for matching draft claim by (patient_uli, encounter_date, service_code)
2. If found and claim in DRAFT or VALIDATED state: mark claim for removal; display in summary as "Prior draft removed due to SCC correction"
3. If found and claim in SUBMITTED or later state: do not remove; surface reconciliation alert "A billing code you already submitted was deleted in Connect Care"
4. If no matching claim found: no action

### 7.6.2 MODIFIED Rows

1. Search for matching draft claim
2. If found and claim in DRAFT state: replace claim data with modified row data; display in summary as "Prior draft updated from SCC correction"
3. If found and claim advanced past DRAFT: create a new draft with modified data; alert physician
4. If no matching claim found: create new draft normally

## 7.7 ICD-10-CA to ICD-9 Crosswalk Integration

When a parsed row has `icd_conversion_flag = true`, the ICD-10-CA source code could not be automatically converted to ICD-9 within Connect Care. The created claim will have:

- `icd_conversion_flag = true`
- `icd10_source_code` populated with the original ICD-10-CA code
- `diagnostic_code` left blank

The claim cannot be submitted until the physician resolves the ICD code via the crosswalk interface (Domain 2 Reference Data). Upon resolution, the claim's diagnostic_code is populated and icd_conversion_flag is cleared. The icd10_source_code is retained permanently for audit trail.

## 7.8 Connect Care API Contracts

| Method | Endpoint | Permission | Description |
| --- | --- | --- | --- |
| POST | /api/v1/claims/connect-care/import | CLAIM_CREATE | Upload and parse SCC extract file |
| GET | /api/v1/claims/connect-care/import/history | CLAIM_VIEW | List import batches. Paginated, filterable by status. |
| GET | /api/v1/claims/connect-care/import/{id} | CLAIM_VIEW | Get import batch detail with parsed rows |
| POST | /api/v1/claims/connect-care/import/{id}/confirm | CLAIM_CREATE | Confirm import and create claims |
| POST | /api/v1/claims/connect-care/import/{id}/cancel | CLAIM_EDIT | Cancel import |

# 8. Reconciliation (Shift Encounter ↔ SCC Import)

This section specifies the reconciliation service that matches mobile shift encounters (logged via Domain 10 Mobile Companion) against Connect Care SCC imports. Reconciliation enriches imported claims with service timestamps and after-hours modifier eligibility derived from the physician's shift log.

## 8.1 Matching Algorithm

For each SCC import row, the reconciliation engine:

1. Extracts Patient PHN, Encounter Date, and Facility Code
2. Queries the shift encounter log where:
   - Shift date matches SCC encounter date
   - Shift facility matches SCC facility code
   - Encounter patient PHN matches SCC PHN (full match) or last 4 digits match (partial PHN)
3. On match: assigns encounter.logged_at as the inferred service time for the claim
4. Multi-row encounters (same patient, same date, different codes) all receive the same timestamp

## 8.2 Match Categories

| Category | SCC Row | Encounter | Handling |
| --- | --- | --- | --- |
| FULL_MATCH | Has match | Has match | Timestamp assigned from encounter log; after-hours modifier detected |
| UNMATCHED_SCC | No encounter match | — | Fall back to shift window inference or prompt physician for timestamp |
| UNMATCHED_ENCOUNTER | — | No SCC match | Missed billing alert generated (HIGH priority notification) |
| SHIFT_ONLY | Date matches shift | No per-encounter log | Fall back to shift start/end window for time inference |

## 8.3 After-Hours Modifier Detection

When a claim is matched to an encounter with a timestamp, the system detects after-hours modifier eligibility:

| Time Window | Day Type | Modifier |
| --- | --- | --- |
| 08:00–16:59 | Weekday | Standard (no modifier) |
| 17:00–22:59 | Weekday | AFHR (after-hours) |
| 23:00–07:59 | Weekday | NGHT (night) |
| Any time | Weekend/Holiday | WKND (weekend) |

Modifiers are auto-applied as Tier A deterministic suggestions. The import summary displays: "Timestamp {HH:MM} from shift log → {MODIFIER} modifier applied".

## 8.4 Partial PHN Resolution

When an encounter was logged with only the last 4 digits of the PHN (capture method LAST_4):

1. Find all SCC rows where PHN ends with those 4 digits
2. **Exactly one match:** auto-resolve and link encounter to claim
3. **Zero matches:** surface as unmatched encounter (missed billing alert)
4. **Multiple matches:** prompt physician to select correct patient from candidates (display patient name from SCC data)

## 8.5 Reconciliation Result Structure

```typescript
interface ReconciliationResult {
  batchId: string;
  shiftId: string | null;
  status: 'PENDING' | 'COMPLETED' | 'CONFIRMED';
  matches: ReconciliationMatch[];
  summary: ReconciliationSummary;
}

interface ReconciliationMatch {
  category: 'FULL_MATCH' | 'UNMATCHED_SCC' | 'UNMATCHED_ENCOUNTER' | 'SHIFT_ONLY';
  sccRow?: object;
  encounter?: object;
  claimId?: string;
  inferredServiceTime?: string;
  modifiers?: string[];
  confidence: number;               // 1.0 = full PHN match, 0.8 = partial, etc.
  resolutionNeeded?: 'TIME' | 'PARTIAL_PHN';
}

interface ReconciliationSummary {
  totalSccRows: number;
  totalEncounters: number;
  fullMatches: number;
  unmatchedScc: number;
  unmatchedEncounters: number;
  shiftOnly: number;
  needsResolution: number;
}
```

## 8.6 Reconciliation API Contracts

| Method | Endpoint | Permission | Description |
| --- | --- | --- | --- |
| POST | /api/v1/claims/connect-care/reconcile | CLAIM_CREATE | Trigger reconciliation for import batch. Body: `{ batch_id }`. |
| GET | /api/v1/claims/connect-care/reconcile/{batchId} | CLAIM_VIEW | Get reconciliation result with match details and summary. |
| POST | /api/v1/claims/connect-care/reconcile/{batchId}/confirm | CLAIM_CREATE | Confirm reconciliation: apply timestamps and modifiers to matched claims. |
| POST | /api/v1/claims/connect-care/reconcile/{batchId}/resolve-time | CLAIM_CREATE | Resolve unmatched SCC row. Body: `{ claim_id, inferred_service_time }`. |
| POST | /api/v1/claims/connect-care/reconcile/{batchId}/resolve-partial | CLAIM_CREATE | Resolve ambiguous partial PHN. Body: `{ encounter_id, claim_id }`. |

# 9. Claim Templates & Favourites

Claim templates enable rapid billing by pre-configuring sets of service codes, modifiers, and diagnostic codes that a physician frequently uses together. Templates reduce the time to create claims for common encounter types.

## 9.1 Template Types

| Type | Description | Origin |
| --- | --- | --- |
| CUSTOM | Physician-created template based on their billing patterns | Created by physician via API or UI |
| SPECIALTY_STARTER | Pre-built templates seeded during onboarding based on physician's specialty | System-generated during Domain 11 Onboarding |

## 9.2 Template Line Items

Each template contains one or more line items, each representing a service code to be billed:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| health_service_code | STRING | Yes | SOMB code (e.g., "03.03A") |
| modifiers | STRING[] | No | Default modifiers for this code |
| diagnostic_code | STRING | No | Default diagnostic code |
| calls | INTEGER | No | Number of calls (default 1) |

## 9.3 Quick-Bill Workflow

When a physician applies a template:

1. Select template from list (sorted by usage_count descending, then sort_order)
2. Specify patient_id and date_of_service
3. Optionally set auto_submit = true for immediate queuing
4. System creates one DRAFT claim per line item in the template
5. Each claim is tagged with the standard import_source = MANUAL
6. Template usage_count is incremented
7. If auto_submit: claims proceed through validation and queue automatically

## 9.4 Template API

See Section 6.9 for full API contracts.

# 10. Anesthesia Benefit Calculations

Anesthesia benefit calculations implement the SOMB Governing Rule 12 (GR 12) for determining the correct anaesthetic benefit when a physician provides anaesthesia for one or more procedures. The calculation engine is consumed by the claim validation pipeline and also exposed as a standalone calculator endpoint.

## 10.1 Calculation Scenarios

| Scenario | Rule | Logic |
| --- | --- | --- |
| Single Procedure | GR 12 base | Anaesthetic benefit = listed anaesthetic value from SOMB. Direct lookup. |
| Multiple Procedures | GR 12 multi | Major procedure (highest listed value) at full rate. Each additional at SOMB-defined reduced rate (typically 50%). System auto-identifies major. |
| Compound Fractures | GR 12.x | 50% uplift on listed anaesthetic benefit when extensive debridement required. |
| Multiple Closed-Reduction | GR 12.x | Major at full rate + 50% for each additional closed-reduction fracture. |
| Open-Reduction Fractures | GR 12.x | Each fracture requiring open reduction/traction/fixation at full benefit, plus major at full rate. |
| Redo Cardiac/Thoracic/Vascular | GR 12.x | 150% if entirely through previous incision; 125% if partly. Physician prompted. |
| Sequential Unrelated | GR 12.x | Major at full rate, additional at reduced rate. |
| Time-Based | GR 12 fallback | Unlisted or no listed value → time-based calculation using SOMB time rate. |
| Oral Surgery | GR 6.9 | Separate rate table. Follows oral surgery-specific rules. |
| Skin Lesion Cap | GR 12 cap | Multiple benign skin lesions with <35 min anaesthesia → single benefit cap. |

## 10.2 Calculator API

**Endpoint:** `POST /api/v1/claims/anesthesia/calculate`

**Request:**

```json
{
  "procedure_codes": ["25.09", "25.08"],
  "start_time": "14:00",
  "end_time": "16:30",
  "duration_minutes": 150
}
```

**Response:**

```json
{
  "data": {
    "totalBenefit": "1250.00",
    "breakdown": [
      {
        "procedureCode": "25.09",
        "listedValue": "750.00",
        "multiplier": 1.0,
        "componentValue": "750.00"
      },
      {
        "procedureCode": "25.08",
        "listedValue": "500.00",
        "multiplier": 1.0,
        "componentValue": "500.00"
      }
    ]
  }
}
```

The anesthesia rules table and rate data are managed by Domain 2 (Reference Data). The calculator consumes these rules via a service interface.

# 11. Multi-Procedure Bundling Engine

The bundling engine enforces code-pair billing rules during claim validation. When a physician bills multiple procedure codes for the same patient on the same date of service, the engine checks whether those codes are bundled (only one payable), independent (both payable), or intrinsically linked (special rules apply).

## 11.1 Bundling Relationships

| Relationship | Description |
| --- | --- |
| BUNDLED | Higher-value code only — the lower-value code is not separately payable. Full bundle. |
| INDEPENDENT | Both codes payable at full rate. No bundling applies. |
| INTRINSICALLY_LINKED | Special rules apply. May require modifier validation or specific billing sequence. |

## 11.2 Pathway-Specific Rules

Bundling relationships can differ between AHCIP and WCB pathways for the same code pair:

| AHCIP Relationship | WCB Relationship | Handling |
| --- | --- | --- |
| BUNDLED | BUNDLED | Higher-value code only for both pathways |
| BUNDLED | INDEPENDENT | AHCIP: higher-value only; WCB: each at 100% |
| INDEPENDENT | INDEPENDENT | Both at full rate for both pathways |
| INTRINSICALLY_LINKED | INTRINSICALLY_LINKED | Special rules for both |

The bundling rules matrix is managed by Domain 2 (Reference Data) with columns for both ahcip_relationship and wcb_relationship per code pair.

## 11.3 Inclusive Care Period Enforcement

When a visit claim is created for a patient who has a surgical claim within the inclusive care window (pre-operative or post-operative days defined per code pair):

- Alert displayed: "This visit falls within the inclusive care period for {surgicalCode} on {date}. Not separately billable unless pre-operative conservative measures or post-operative complication."
- Physician can override with a text justification (Section 12) selecting the PRE_OP_CONSERVATIVE or POST_OP_COMPLICATION scenario

## 11.4 Bundling Check API

**Endpoint:** `POST /api/v1/claims/bundling/check`

**Request:**

```json
{
  "codes": ["25.09", "25.08"],
  "claim_type": "AHCIP",
  "patient_id": "uuid",
  "date_of_service": "2026-02-14"
}
```

**Response:**

```json
{
  "data": {
    "bundlingAnalysis": [
      {
        "codeA": "25.08",
        "codeB": "25.09",
        "relationship": "BUNDLED",
        "higherValueCode": "25.09",
        "recommendation": "These procedures bundle. Only the higher-value code (25.09) is separately payable.",
        "inclusiveCarePeriod": null
      }
    ]
  }
}
```

# 12. Text Justification Templates

Structured text justification supports claims that require narrative explanation for special billing scenarios. The justification system provides scenario-specific templates with guided fields, reducing physician effort while ensuring compliant documentation.

## 12.1 Justification Scenarios

| Scenario | Trigger | Description |
| --- | --- | --- |
| UNLISTED_PROCEDURE | Unlisted procedure code selected | Justification for billing an unlisted procedure: procedure performed, clinical indication, comparable listed code, time involved, requested benefit |
| ADDITIONAL_COMPENSATION | Physician manually invokes (GR 2.6) | Nature of additional complexity, additional time, distinguishing circumstances |
| PRE_OP_CONSERVATIVE | Visit during surgical inclusive care period + pre-op exception | Conservative treatment attempted, clinical decision to proceed, pre-op visit dates |
| POST_OP_COMPLICATION | Visit during surgical inclusive care period + complication exception | Original procedure (auto-populated), original date (auto-populated), nature of complication, clinical findings, treatment provided |
| WCB_NARRATIVE | WCB claim for complex case | Treatment description, progress notes, work capacity assessment |

## 12.2 Justification Workflow

1. System detects a scenario trigger (e.g., unlisted code, inclusive care period overlap) or physician manually invokes
2. Physician selects scenario type
3. System presents scenario-specific template with guided fields
4. Physician fills in fields and/or writes free-form narrative (minimum 10 characters, maximum 5,000 characters)
5. Justification is attached to the claim record
6. Justification text is included in the submission where the pathway supports it
7. Physician can search past justifications by scenario type and save effective ones as personal reusable templates

## 12.3 Justification API

See Section 6.10 for full API contracts.

# 13. Interface Contracts with Other Domains

## 13.1 Reference Data (Consumed)

Claim Lifecycle is the primary consumer of Reference Data. It calls Reference Data APIs on every claim creation, edit, and validation. Key interfaces:

- HSC search/lookup (by DOS for version awareness)
- Validation context: all applicable governing rules for a claim's code/modifier/facility/specialty combination
- Modifier eligibility and calculation parameters
- DI code lookup with surcharge/BCP qualification flags
- Functional centre lookup
- RRNP rate by community
- PCPCM basket classification for BA routing
- Stat holiday check for after-hours calculations
- Explanatory code resolution for rejection management
- ICD-10-CA to ICD-9 crosswalk lookup and search (Connect Care integration)
- Anesthesia rules and rate tables (GR 12 calculation engine)
- Bundling rules matrix (code-pair relationships, inclusive care periods)
- Justification templates (scenario-specific field definitions and output formats)
- WCB-specific: POB/NOI codes, POB-NOI exclusion matrix, Contract ID/Role/Form ID matrix, WCB fee schedule, skill codes (consumed by Domain 4.2)

## 13.2 Intelligence Engine (Consumed)

After validation, Claim Lifecycle sends the claim context to the Intelligence Engine for AI Coach analysis. The Intelligence Engine returns suggestions which are stored on the claim's ai_coach_suggestions field. Claim Lifecycle displays these suggestions and tracks acceptance/dismissal. The AI Coach's analysis is advisory — it never blocks submission.

## 13.3 Provider Management (Consumed)

Claim Lifecycle reads provider context: BA number(s), specialty, practice locations (functional centres), PCPCM enrolment status, RRNP eligibility, submission preferences, WCB Contract ID/Role, registration date. This data determines default values, routing, validation context, and fee calculation parameters.

## 13.4 Patient Registry (Consumed)

Claim Lifecycle references patients for PHN, name, DOB, and gender. Patient lookup/search is performed during claim creation. Patient DOB is required for age-based modifier calculations. For WCB claims, additional patient demographics (address, employer) are captured.

## 13.5 Notification Service (Events Emitted)

Claim Lifecycle emits events to the Notification Service at key lifecycle moments:

| Event | Trigger |
| --- | --- |
| CLAIM_VALIDATED | Claim passes validation (both pathways) |
| CLAIM_FLAGGED | Claim classified as flagged during queue |
| DEADLINE_APPROACHING | Claim within 7, 3, 1 day(s) of submission deadline |
| DEADLINE_EXPIRED | Claim passed submission deadline without submission |
| BATCH_ASSEMBLED | Batch generation complete (AHCIP or WCB) |
| BATCH_SUBMITTED | Batch file transmitted/uploaded |
| CLAIM_ASSESSED | Payer response received and claim assessed |
| CLAIM_REJECTED | Claim rejected with error/explanatory codes |
| CLAIM_PAID | Payment confirmed for assessed claim |
| DUPLICATE_DETECTED | Potential duplicate claim identified |
| AI_SUGGESTION_READY | AI Coach suggestions available for review |

## 13.6 Mobile Companion (Consumed)

Claim Lifecycle consumes shift encounter data from the Mobile Companion domain for the reconciliation service (Section 8). Key data consumed:

- ED shift records (shift_id, facility, date, start/end times)
- Shift encounter log (PHN, timestamp, PHN capture method, partial PHN flag)
- Schedule data for inferred shift creation

# 14. Security & Audit Requirements

These requirements apply to all claims regardless of pathway. Pathway-specific security requirements (WCB vendor credentials, H-Link file security) are in their respective sub-domain documents.

## 14.1 Data Protection

Claims contain PHI (patient PHN, DOB, diagnoses, services). All claim data encrypted at rest (AES-256) and in transit (TLS 1.3).

Claim data is scoped to the physician (HIA custodian). Delegates access only claims for physicians they serve, per configured permissions.

Admin cannot view individual claims without explicit physician-granted PHI access (time-limited, logged per IAM admin access rules).

Exported claim files are generated on Meritum infrastructure (DigitalOcean Toronto, Canadian data residency) and delivered via authenticated download. Files are not emailed.

EMR import files are processed in memory where possible. Uploaded files are stored temporarily (encrypted), processed, and deleted after import confirmation. Retained only for audit reference if configured.

Connect Care SCC import files are archived to DigitalOcean Spaces (encrypted, Toronto region) with a configurable retention period (default 12 months). The raw_file_reference column on claims provides traceability from claim to source file.

## 14.2 Physician Tenant Isolation

All queries are enforced at the repository layer with `WHERE physician_id = :authenticatedPhysicianId`. Tables with physician_id that require tenant isolation enforcement:

- claims
- import_batches
- field_mapping_templates
- shifts
- claim_templates
- claim_justifications
- recent_referrers
- claim_exports

Cross-physician resource access returns 404 (not 403) to avoid confirming resource existence.

## 14.3 Input Validation

- Zod schemas enforce types at the request entry point for all endpoints
- SQL injection prevented by Drizzle's parameterized queries; Zod validates at the schema layer first
- XSS payloads in text fields either rejected by Zod string constraints or stored safely (no script execution on retrieval)
- File uploads restricted: extension whitelist (.csv, .CSV, .xlsx, .xls), size limit (10 MB), max 10,000 rows
- UUID format validation on all path parameters
- Money values validated as string with 2 decimal places — never floating point

## 14.4 PHI Handling

- PHN masking in logs: first 3 digits visible, rest replaced with asterisks (123******)
- No PHI in email bodies — only links to authenticated pages
- No PHI in error messages or API error responses
- Validation errors reference row numbers and field names, not patient data
- Uploaded files encrypted in DigitalOcean Spaces, purged after configurable retention

## 14.5 Audit Trail

Every claim state change, edit, and significant action is recorded in both the claim audit history table (Section 3.9) and the system audit log (via Identity & Access middleware). Key audited actions:

Claim created (with import_source), edited (field-level changes), validated, queued, unqueued, submitted, assessed, resubmitted, written off, deleted, expired

AI Coach suggestion accepted or dismissed (with reason if provided)

Duplicate detection acknowledged

Batch approved (by whom: physician or delegate), batch submitted, batch execution details

Assessment/return ingested, rejection reviewed

Data export requested and downloaded

Submission preference changed

Connect Care import uploaded, confirmed, or cancelled

Connect Care correction/deletion processed

ICD crosswalk resolved

Claim template created, updated, or deleted

Justification created or updated

Bundling override applied

Anesthesia override applied

Routing override applied

Reconciliation executed, confirmed, missed billing detected

# 15. Testing Strategy

This section covers shared test requirements. Pathway-specific test suites (AHCIP billing scenarios, WCB form tests, XML generation tests) are in their respective sub-domain documents.

## 15.1 State Machine Tests

All valid transitions succeed (every From → To pair in Section 2.2)

All invalid transitions are rejected (e.g., DRAFT → SUBMITTED, PAID → DRAFT)

Terminal states cannot be transitioned from (PAID, ADJUSTED, WRITTEN_OFF, EXPIRED, DELETED)

Clean/flagged classification correctly applied based on validation results, AI suggestions, and duplicate alerts

Classification re-evaluation: flagged claim becomes clean when all flags addressed

## 15.2 Auto-Submission Mode Tests

Auto Clean mode: clean claim auto-included, flagged claim excluded

Auto All mode: both clean and flagged claims included

Require Approval mode: no claims included without explicit approval

Delegate approval of flagged claim: included in next batch

Mode change mid-batch-cycle: existing queued claims respect new mode

## 15.3 Validation Pipeline Tests

Each shared check (S1–S7) with positive and negative cases

Pipeline short-circuit: invalid claim_type skips all subsequent checks

Pathway delegation: AHCIP claim routes to AHCIP module, WCB claim routes to WCB module

Reference data version recorded correctly on validation result

Validation runs on save, on queue, and pre-batch

ICD conversion blocking: claim with icd_conversion_flag=true and no diagnostic_code cannot proceed

Bundling check integration: conflicting codes flagged during validation

## 15.4 EMR Import Tests

CSV with various delimiters (comma, tab, pipe)

Header row vs no header row

Multiple date formats (YYYY-MM-DD, DD/MM/YYYY, MM/DD/YYYY)

Partial failures: some rows succeed, some fail, correct counts reported

Field mapping template reuse across imports

Duplicate file detection via SHA-256 hash

## 15.5 Connect Care Import Tests

AHCIP CSV parsing with 21 fields

WCB CSV parsing with 13 fields

Auto-detection of extract type (AHCIP vs WCB)

Provider identity validation (mismatch rejects entire file)

Row validation: all BLOCKING, WARNING, and INFORMATIONAL rules

Duplicate detection: within-file and cross-import

Correction handling: DELETED rows remove matching drafts

Correction handling: MODIFIED rows update matching drafts or create new

ICD conversion flag propagation to claim record

Confirm → claims created in DRAFT with correct metadata

Cancel → no claims created, batch status updated

Import history scoped to authenticated physician

File hash deduplication (same file cannot be imported twice)

## 15.6 Reconciliation Tests

PHN matching: full match (9-digit) assigns timestamp

PHN matching: partial match (last-4) with single candidate auto-resolves

PHN matching: partial match with multiple candidates prompts physician

After-hours modifier detection: weekday evening → AFHR, night → NGHT, weekend → WKND

Unmatched encounter → missed billing alert generated

Shift-only matching: falls back to shift window for time inference

Reconciliation result structure with summary counts

Confirm reconciliation applies timestamps and modifiers to claims

## 15.7 Template & Favourites Tests

Create, update, delete claim template

Apply template creates correct number of claims

Usage count incremented on apply

Specialty starter templates seeded during onboarding

Template soft-delete (is_active = false)

Recent referrer tracking: upsert on physician+CPSA, usage count

## 15.8 Anesthesia & Bundling Tests

Single procedure: direct SOMB lookup

Multiple procedures: major at full rate, additional at reduced rate

Bundling check: BUNDLED pair returns conflict

Bundling check: INDEPENDENT pair returns no conflict

Inclusive care period: visit within window flagged

Pathway-specific bundling: same code pair, different relationship per pathway

## 15.9 Justification Tests

Create justification with each scenario type

Minimum 10 characters, maximum 5,000 characters validation

Search justification history by scenario

Save as personal template

## 15.10 Integration Tests

Full lifecycle: create → validate → queue → batch → submit → assess → paid (both pathways)

Rejection lifecycle: submit → rejected → review → resubmit → paid

ED shift workflow: start shift → add encounters → complete → review → queue → submit

Connect Care: upload → parse → preview → confirm → claims created → reconcile → confirm

90-day expiry: create claim with old DOS → verify deadline notifications → verify expiry

Data export: request → generation → download → verify completeness

Template quick-bill: select template → apply → claims created → validate → queue

# 16. Open Questions

| # | Question | Context |
| --- | --- | --- |
| 1 | Should the duplicate detection window be configurable per physician, or system-wide? | Some physicians (radiologists) routinely bill the same code for the same patient on the same day. Others never should. |
| 2 | What is the maximum batch size (number of claims) before performance becomes a concern? | Radiologists may queue 100+ claims per batch cycle. Need to validate batch assembly and file generation performance. |
| 3 | Should claim audit history support field-level rollback, or is it view-only? | Currently specified as view-only audit trail. Rollback would add significant complexity but may be requested by physicians. |
| 4 | Should the AI Coach suggestions count toward the 'flagged' classification, or should they be advisory-only? | Current implementation: pending suggestions = flagged. Some physicians may find this annoying if they prefer to review suggestions post-submission. |

# 17. Document Control

| Item | Value |
| --- | --- |
| Parent document | Meritum PRD v1.3 |
| Domain | Claim Lifecycle Core (Domain 4.0 of 13) |
| Build sequence position | 4th (foundation for 4.1 and 4.2) |
| Dependencies | Domain 1 (IAM), Domain 2 (Reference Data), Domain 3/9 (Notifications) |
| Consumes | Domain 5 (Provider Mgmt), Domain 6 (Patient Registry), Domain 7 (Intelligence Engine), Domain 10 (Mobile Companion) |
| Child domains | Domain 4.1 (AHCIP Claim Pathway), Domain 4.2 (WCB Claim Pathway) |
| Supplementary specs | MHT-FRD-CC-001 Connect Care Integration, MHT-FRD-MVPADD-001 MVP Features Addendum (B3/B7/B9/B11), MHT-FRD-MOB-002 Mobile Companion v2 |
| Version | 2.0 |
| Date | February 2026 |

This document specifies the shared infrastructure for the Claim Lifecycle. It should be read in conjunction with Domain 4.1 (AHCIP Claim Pathway) and Domain 4.2 (WCB Claim Pathway), which extend these foundations with pathway-specific logic.
