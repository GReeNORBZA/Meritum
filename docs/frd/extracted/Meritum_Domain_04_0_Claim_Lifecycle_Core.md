# Meritum_Domain_04_0_Claim_Lifecycle_Core

MERITUM

Functional Requirements

Claim Lifecycle Core

Domain 4.0 of 13  |  Critical Path: Position 4

Meritum Health Technologies Inc.

Version 1.0  |  February 2026

CONFIDENTIAL

# Table of Contents

# 1. Domain Overview

## 1.1 Purpose

The Claim Lifecycle Core defines the shared infrastructure that underpins both the AHCIP (H-Link) and WCB (EIR) submission pathways. It owns the claim state machine, the base data model, the validation engine architecture, the clean/flagged classification system, the tiered auto-submission model, and the cross-pathway user stories and API patterns.

Every claim in Meritum — regardless of whether it is destined for Alberta Health or WCB Alberta — begins life in the same claims table, follows the same state machine, passes through the same validation pipeline structure, and is subject to the same audit and security framework. The pathway-specific logic (file formats, submission mechanisms, response processing, fee schedules) is specified in the sub-domain documents: Domain 4.1 (AHCIP) and Domain 4.2 (WCB).

## 1.2 Scope

Claim state machine: draft → validated → queued → submitted → assessed → paid/rejected/adjusted

Clean/flagged classification and tiered auto-submission model

Base claims table and pathway-agnostic data model (import batches, field mapping templates, ED shifts, audit history)

Validation engine architecture: pipeline structure, result format, tiered severity model

Pathway-agnostic user stories: claim creation (manual, EMR import, ED workflow), validation, monitoring, data portability

Shared API patterns: claim CRUD, EMR import, ED shift workflow, rejection management, AI Coach interactions, data export, submission preferences

Interface contracts with consumed domains (Reference Data, Intelligence Engine, Provider Management, Patient Registry, Notification Service)

Security and audit requirements applicable to all claim types

Testing strategy framework (pathway-specific test suites are in 4.1 and 4.2)

## 1.3 Out of Scope

AHCIP-specific: H-Link file generation, Thursday batch cycle, AHCIP claim data elements, AHCIP assessment ingestion, AHCIP fee calculation, governing rules (Domain 4.1)

WCB-specific: HL7 v2.3.1 XML generation, WCB form types, WCB return file processing, WCB remittance reconciliation, WCB fee tiers, OIS forms (Domain 4.2)

AI Coach suggestion logic (Domain 7 Intelligence Engine)

Reference data management (Domain 2)

Notification delivery mechanics (Domain 3)

## 1.4 Document Family

Domain 4 (Claim Lifecycle) comprises three sub-domain documents that should be read together:

## 1.5 Domain Dependencies

# 2. Claim State Machine

Every claim in Meritum exists in exactly one state at any time. The state machine governs what actions are possible and what transitions are allowed. It applies identically to AHCIP and WCB claims — only the submission mechanism and response processing differ between pathways.

## 2.1 States

## 2.2 State Transitions

## 2.3 Clean vs Flagged Classification

When a claim enters the queued state, the system classifies it as clean or flagged. This classification drives the tiered auto-submission model.

### 2.3.1 Clean Claim

A claim is clean when all of the following are true:

Passed all validation rules with zero warnings

Zero AI Coach suggestions pending review (all accepted or dismissed)

Zero unresolved flags

No duplicate detection alerts

The physician has reviewed and saved the claim during individual entry

Clean claims are eligible for automatic submission per the physician's submission preference mode.

### 2.3.2 Flagged Claim

A claim is flagged when it has one or more of:

Active AI Coach suggestions the physician has not accepted or dismissed

Validation warnings (not errors) that require physician judgement

Duplicate detection alert requiring confirmation

Approaching submission deadline with incomplete information

Any anomaly the system cannot resolve automatically

Classification is re-evaluated whenever a flagged claim is updated. If the physician addresses all flags, the claim transitions from flagged to clean. This can happen at any time before the batch cutoff.

## 2.4 Tiered Auto-Submission Model

Each physician configures a submission preference mode that determines how their queued claims enter batches:

Delegates can approve flagged claims on behalf of a physician if the physician has granted the CLAIM_APPROVE delegate permission. The delegate's approval action is audit-logged with both the delegate's identity and the physician context.

# 3. Base Data Model

The base data model defines tables shared across both submission pathways. Pathway-specific extension tables (AHCIP claim elements, WCB form details, etc.) are defined in their respective sub-domain documents and linked to the base claims table via foreign key.

## 3.1 Claims Table (claims)

The central table of the platform. One row per claim regardless of pathway. The claim_type column determines which pathway-specific extension table is linked.

Indexes: (physician_id, state), (patient_id, date_of_service), (state, claim_type, is_clean) for batch assembly queries, (submission_deadline) for expiry monitoring.

## 3.2 Import Batches Table (import_batches)

Tracks EMR batch imports for traceability and re-processing.

## 3.3 Field Mapping Templates Table (field_mapping_templates)

Stores per-physician (or per-EMR) column-to-field mappings for batch import. Reusable across imports so the physician only maps their EMR export format once.

## 3.4 Shifts Table (shifts) — ED Workflow

Emergency department physicians often bill for an entire shift as a batch. The shifts table groups encounters for a single ED session.

Individual patient encounters during the shift are claims in the claims table with import_source = ED_SHIFT and shift_id pointing here.

## 3.5 Claim Audit History Table (claim_audit_history)

Every state change and significant edit to a claim is recorded. This is separate from the system-wide audit log (Domain 1) and provides claim-level traceability that supports both clinical audit and billing dispute resolution.

Retention: Claim audit history is retained for the lifetime of the claim plus 10 years (Alberta HIA custodian retention requirement).

# 4. Validation Engine Architecture

The validation engine is the quality gate of Meritum. It evaluates every claim against all applicable rules before the claim can be queued for submission. The engine is pathway-aware: after running shared structural checks, it delegates to the AHCIP validation module (Domain 4.1) or the WCB validation module (Domain 4.2) based on claim_type.

## 4.1 Pipeline Structure

Validation runs as an ordered pipeline of checks. Earlier checks may short-circuit later ones (e.g., if claim_type is invalid, no further checks run). The pipeline structure is:

Shared structural checks (this document): claim_type valid, required base fields present, date_of_service valid, patient exists, physician exists

Submission deadline check: is the claim within its submission window?

Duplicate detection: same patient + same DOS + same primary code within configurable window

Pathway delegation: route to AHCIP module (Domain 4.1, Section 5) or WCB module (Domain 4.2, Section 4) based on claim_type

AI Coach analysis: after validation, send claim context to Intelligence Engine for suggestions (non-blocking; suggestions are advisory)

## 4.2 Validation Result Structure

The validation result is a structured object stored on the claim's validation_result JSONB field:

errors: Array of { check, rule_reference, message, help_text, field_affected }. Any error blocks the claim from being queued.

warnings: Array of same structure. Warnings do not block but cause the claim to be flagged.

info: Array of { check, rule_reference, message, help_text }. Advisory information; no impact on state.

passed: Boolean. True if zero errors.

validation_timestamp: When validation was run.

reference_data_version: SOMB/WCB version used. For audit traceability — if a claim was validated against SOMB v4.2 and later SOMB v4.3 changes a rule, the audit trail shows which version was in effect.

## 4.3 Shared Validation Checks

These checks run for all claims regardless of pathway:

After shared checks pass, the pipeline delegates to the pathway-specific module. If S1 fails (invalid claim_type), all subsequent checks are skipped.

## 4.4 Validation Timing

On save: Validation runs automatically when the physician saves a claim (after every field change in the guided form). Results update in real-time in the UI.

On queue: Full re-validation before the claim enters the queue. If new errors appear (e.g., reference data updated), the claim cannot be queued.

Pre-batch: Final validation before batch assembly. Claims that have become invalid since queuing are removed from the batch and returned to validated state with notification.

Reference data version: Validation always uses the current reference data version. The version used is recorded on the claim for audit.

# 5. User Stories & Acceptance Criteria

These user stories cover pathway-agnostic claim lifecycle interactions. AHCIP-specific stories (Thursday batch, H-Link) are in Domain 4.1. WCB-specific stories (form type selection, XML generation) are in Domain 4.2.

## 5.1 Claim Creation

## 5.2 Validation & Queue

## 5.3 Submission & Batch

## 5.4 Assessment & Rejection

## 5.5 Monitoring & Portability

# 6. Shared API Contracts

All endpoints require authentication via Domain 1 (Identity & Access). All state-changing operations are audit-logged. Physician endpoints are scoped to the authenticated physician or the delegate's physician context. Pathway-specific endpoints (AHCIP batch, WCB batch, etc.) are defined in their respective sub-domain documents.

## 6.1 Claim CRUD

## 6.2 EMR Import

## 6.3 Field Mapping Templates

## 6.4 ED Shift Workflow

## 6.5 Rejection Management

## 6.6 AI Coach Interactions

## 6.7 Data Export

## 6.8 Submission Preferences

# 7. Interface Contracts with Other Domains

## 7.1 Reference Data (Consumed)

Claim Lifecycle is the primary consumer of Reference Data. It calls Reference Data APIs on every claim creation, edit, and validation. Key interfaces:

HSC search/lookup (by DOS for version awareness)

Validation context: all applicable governing rules for a claim's code/modifier/facility/specialty combination

Modifier eligibility and calculation parameters

DI code lookup with surcharge/BCP qualification flags

Functional centre lookup

RRNP rate by community

PCPCM basket classification for BA routing

Stat holiday check for after-hours calculations

Explanatory code resolution for rejection management

WCB-specific: POB/NOI codes, POB-NOI exclusion matrix, Contract ID/Role/Form ID matrix, WCB fee schedule, skill codes (consumed by Domain 4.2)

## 7.2 Intelligence Engine (Consumed)

After validation, Claim Lifecycle sends the claim context to the Intelligence Engine for AI Coach analysis. The Intelligence Engine returns suggestions which are stored on the claim's ai_coach_suggestions field. Claim Lifecycle displays these suggestions and tracks acceptance/dismissal. The AI Coach's analysis is advisory — it never blocks submission.

## 7.3 Provider Management (Consumed)

Claim Lifecycle reads provider context: BA number(s), specialty, practice locations (functional centres), PCPCM enrolment status, RRNP eligibility, submission preferences, WCB Contract ID/Role. This data determines default values, routing, validation context, and fee calculation parameters.

## 7.4 Patient Registry (Consumed)

Claim Lifecycle references patients for PHN, name, DOB, and gender. Patient lookup/search is performed during claim creation. Patient DOB is required for age-based modifier calculations. For WCB claims, additional patient demographics (address, employer) are captured.

## 7.5 Notification Service (Events Emitted)

Claim Lifecycle emits events to the Notification Service at key lifecycle moments:

# 8. Security & Audit Requirements

These requirements apply to all claims regardless of pathway. Pathway-specific security requirements (WCB vendor credentials, H-Link file security) are in their respective sub-domain documents.

## 8.1 Data Protection

Claims contain PHI (patient PHN, DOB, diagnoses, services). All claim data encrypted at rest (AES-256) and in transit (TLS 1.3).

Claim data is scoped to the physician (HIA custodian). Delegates access only claims for physicians they serve, per configured permissions.

Admin cannot view individual claims without explicit physician-granted PHI access (time-limited, logged per IAM admin access rules).

Exported claim files are generated on Meritum infrastructure (DigitalOcean Toronto, Canadian data residency) and delivered via authenticated download. Files are not emailed.

EMR import files are processed in memory where possible. Uploaded files are stored temporarily (encrypted), processed, and deleted after import confirmation. Retained only for audit reference if configured.

## 8.2 Audit Trail

Every claim state change, edit, and significant action is recorded in both the claim audit history table (Section 3.5) and the system audit log (via Identity & Access middleware). Key audited actions:

Claim created (with import_source), edited (field-level changes), validated, queued, unqueued, submitted, assessed, resubmitted, written off, deleted, expired

AI Coach suggestion accepted or dismissed (with reason if provided)

Duplicate detection acknowledged

Batch approved (by whom: physician or delegate), batch submitted, batch execution details

Assessment/return ingested, rejection reviewed

Data export requested and downloaded

Submission preference changed

# 9. Testing Strategy

This section covers shared test requirements. Pathway-specific test suites (AHCIP billing scenarios, WCB form tests, XML generation tests) are in their respective sub-domain documents.

## 9.1 State Machine Tests

All valid transitions succeed (every From → To pair in Section 2.2)

All invalid transitions are rejected (e.g., draft → submitted, paid → draft)

Terminal states cannot be transitioned from (paid, adjusted, written_off, expired, deleted)

Clean/flagged classification correctly applied based on validation results, AI suggestions, and duplicate alerts

Classification re-evaluation: flagged claim becomes clean when all flags addressed

## 9.2 Auto-Submission Mode Tests

Auto Clean mode: clean claim auto-included, flagged claim excluded

Auto All mode: both clean and flagged claims included

Require Approval mode: no claims included without explicit approval

Delegate approval of flagged claim: included in next batch

Mode change mid-batch-cycle: existing queued claims respect new mode

## 9.3 Validation Pipeline Tests

Each shared check (S1–S7) with positive and negative cases

Pipeline short-circuit: invalid claim_type skips all subsequent checks

Pathway delegation: AHCIP claim routes to AHCIP module, WCB claim routes to WCB module

Reference data version recorded correctly on validation result

Validation runs on save, on queue, and pre-batch

## 9.4 EMR Import Tests

CSV with various delimiters (comma, tab, pipe)

Header row vs no header row

Multiple date formats (YYYY-MM-DD, DD/MM/YYYY, MM/DD/YYYY)

Partial failures: some rows succeed, some fail, correct counts reported

Field mapping template reuse across imports

Duplicate file detection via SHA-256 hash

## 9.5 Integration Tests

Full lifecycle: create → validate → queue → batch → submit → assess → paid (both pathways)

Rejection lifecycle: submit → rejected → review → resubmit → paid

ED shift workflow: start shift → add encounters → complete → review → queue → submit

90-day expiry: create claim with old DOS → verify deadline notifications → verify expiry

Data export: request → generation → download → verify completeness

# 10. Open Questions

# 11. Document Control

This document specifies the shared infrastructure for the Claim Lifecycle. It should be read in conjunction with Domain 4.1 (AHCIP Claim Pathway) and Domain 4.2 (WCB Claim Pathway), which extend these foundations with pathway-specific logic.

| Document | Title | Content |
| --- | --- | --- |
| Domain 4.0 (this) | Claim Lifecycle Core | Shared state machine, base data model, validation architecture, cross-pathway API patterns, security, audit |
| Domain 4.1 | AHCIP Claim Pathway (H-Link) | AHCIP claim data elements, Thursday batch cycle, H-Link file generation, assessment ingestion, AHCIP validation and fee rules |
| Domain 4.2 | WCB Claim Pathway (EIR) | 8 WCB form types, HL7 XML batch submission, return file processing, remittance reconciliation, WCB validation and fee rules |

| Domain | Dependency Type | Key Interfaces |
| --- | --- | --- |
| 1 Identity & Access | Consumed | Authentication, RBAC, delegate permissions, audit logging middleware |
| 2 Reference Data | Consumed | HSC codes, governing rules, modifiers, fee schedules, DI codes, RRNP rates, stat holidays, explanatory codes |
| 3 Notification Service | Consumed | Deadline reminders, submission confirmations, assessment alerts, rejection notifications, payment notifications |
| 5 Provider Management | Consumed | Physician BA number(s), specialty, functional centres, PCPCM status, RRNP eligibility, submission preferences |
| 6 Patient Registry | Consumed | Patient PHN, name, DOB, gender for claim creation and age-based calculations |
| 7 Intelligence Engine | Consumed | AI Coach suggestions for billing optimisation, code review, modifier recommendations |
| 4.1 AHCIP Pathway | Child | Extends this core with AHCIP-specific submission, validation, and fee logic |
| 4.2 WCB Pathway | Child | Extends this core with WCB-specific submission, validation, and fee logic |

| State | Terminal? | Description |
| --- | --- | --- |
| draft | No | Claim created but not yet validated. May be incomplete. The physician or delegate is actively entering data. |
| validated | No | Claim has passed validation with zero errors. May have warnings (flagged) or zero warnings (clean). Ready to be queued. |
| queued | No | Claim is in the submission queue. Clean claims may auto-submit per physician preference. Flagged claims await approval. |
| submitted | No | Claim has been included in a batch file and transmitted to AHCIP (H-Link) or uploaded to WCB (myWCB portal). Awaiting response. |
| assessed | No | Response received from payer. For AHCIP: assessment file processed. For WCB: return file processed. Claim accepted by payer. |
| paid | Yes | Payment confirmed. For AHCIP: payment received in Friday deposit. For WCB: remittance record matched. |
| rejected | No | Payer rejected the claim. AHCIP: explanatory code(s) received. WCB: error code(s) in return file. Requires physician review. |
| adjusted | Yes | Claim was paid at a different amount than submitted. Payment received but with adjustments (partial payment, modifier disallowed, etc.). |
| written_off | Yes | Physician has reviewed a rejected claim and decided not to resubmit. Manual terminal state. |
| expired | Yes | Claim passed the submission window without being submitted. AHCIP: 90 calendar days from DOS. WCB: form-specific deadlines. |
| deleted | Yes | Soft-deleted by physician. Only allowed from draft state. Retained for audit but hidden from UI. |

| From | To | Trigger / Conditions |
| --- | --- | --- |
| (new) | draft | Claim created via manual entry, EMR import, or ED shift workflow |
| draft | validated | Validation engine runs with zero errors. Automatic on save if all required fields present. |
| draft | deleted | Physician explicitly deletes. Only from draft. |
| validated | draft | Physician edits a field that invalidates the claim, or new reference data version invalidates previously valid data. |
| validated | queued | Physician explicitly queues, or auto-queue on validation pass per submission preferences. |
| queued | validated | Physician unqueues (removes from submission queue). Claim returns to validated. |
| queued | submitted | Batch assembly includes this claim. For AHCIP: Thursday batch. For WCB: on-demand batch. |
| submitted | assessed | Payer response received and matched. Claim accepted. |
| submitted | rejected | Payer response received. Claim rejected with error/explanatory codes. |
| assessed | paid | Payment confirmed (AHCIP: Friday deposit; WCB: remittance XML matched). |
| assessed | adjusted | Payment received but at different amount than expected. |
| rejected | draft | Physician edits claim to correct rejection reason. Returns to draft for revalidation. |
| rejected | queued | One-click resubmission: physician confirms correction and requeues directly. |
| rejected | written_off | Physician decides not to resubmit. |
| any non-terminal | expired | Submission deadline passed. System-initiated transition. |

| Mode | Behaviour |
| --- | --- |
| Auto Clean | Clean claims are automatically included in the next batch. Flagged claims require explicit physician/delegate approval. Default for new physicians. |
| Auto All | Both clean and flagged claims are automatically included. Physician trusts the system and reviews by exception. |
| Require Approval | All claims require explicit approval before batch inclusion. No automatic submission. Suitable for physicians who prefer manual review of every claim. |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| claim_id | UUID | No | Primary key |
| physician_id | UUID FK | No | FK to providers. The HIA custodian for this claim's PHI. |
| patient_id | UUID FK | No | FK to patients. |
| claim_type | VARCHAR(10) | No | AHCIP or WCB. Determines which extension tables apply and which submission pathway is used. |
| state | VARCHAR(20) | No | Current state per state machine (Section 2.1). |
| is_clean | BOOLEAN | Yes | Null until queued. True = clean, False = flagged. |
| import_source | VARCHAR(20) | No | MANUAL, EMR_IMPORT, ED_SHIFT. How the claim was created. |
| import_batch_id | UUID FK | Yes | FK to import_batches. Populated for EMR_IMPORT claims. |
| shift_id | UUID FK | Yes | FK to shifts. Populated for ED_SHIFT claims. |
| date_of_service | DATE | No | Date of service. Central to validation, fee calculation, and submission deadlines. |
| submission_deadline | DATE | No | Calculated deadline for this claim. AHCIP: DOS + 90 calendar days. WCB: form-specific per timing rules. |
| submitted_batch_id | UUID FK | Yes | FK to the pathway-specific batch table. Populated when claim enters submitted state. |
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

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| import_batch_id | UUID | No | Primary key |
| physician_id | UUID FK | No | FK to providers |
| file_name | VARCHAR(255) | No | Original uploaded filename |
| file_hash | VARCHAR(64) | No | SHA-256 hash for deduplication |
| field_mapping_template_id | UUID FK | Yes | FK to field_mapping_templates. Null if manual mapping. |
| total_rows | INTEGER | No | Total rows in the import file |
| success_count | INTEGER | No | Rows successfully imported as claims |
| error_count | INTEGER | No | Rows that failed parsing or validation |
| error_details | JSONB | Yes | Per-row error details for failed rows |
| status | VARCHAR(20) | No | PENDING, PROCESSING, COMPLETED, FAILED |
| created_at | TIMESTAMPTZ | No | Upload timestamp |
| created_by | UUID FK | No | Uploader |

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
| created_at | TIMESTAMPTZ | No |  |
| updated_at | TIMESTAMPTZ | No |  |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| shift_id | UUID | No | Primary key |
| physician_id | UUID FK | No | FK to providers |
| facility_id | UUID FK | No | FK to provider's functional centre / facility |
| shift_date | DATE | No | Date of the ED shift |
| start_time | TIME | Yes | Shift start (for after-hours premium calculation) |
| end_time | TIME | Yes | Shift end |
| status | VARCHAR(20) | No | IN_PROGRESS, COMPLETED, SUBMITTED |
| encounter_count | INTEGER | No | Number of encounters (claims) in this shift |
| created_at | TIMESTAMPTZ | No |  |
| updated_at | TIMESTAMPTZ | No |  |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| audit_id | UUID | No | Primary key |
| claim_id | UUID FK | No | FK to claims |
| action | VARCHAR(30) | No | CREATED, EDITED, VALIDATED, QUEUED, UNQUEUED, SUBMITTED, ASSESSED, REJECTED, RESUBMITTED, WRITTEN_OFF, DELETED, EXPIRED, AI_SUGGESTION_ACCEPTED, AI_SUGGESTION_DISMISSED, DUPLICATE_ACKNOWLEDGED |
| previous_state | VARCHAR(20) | Yes | State before the action (null for CREATED) |
| new_state | VARCHAR(20) | Yes | State after the action |
| changes | JSONB | Yes | For EDITED: field-level diff {field, old_value, new_value}. For AI actions: suggestion details. |
| actor_id | UUID FK | No | Who performed the action (physician or delegate) |
| actor_context | VARCHAR(20) | No | PHYSICIAN, DELEGATE, SYSTEM. SYSTEM for automated transitions (expiry, batch assembly). |
| reason | TEXT | Yes | Optional reason (e.g., write-off justification, AI suggestion dismissal reason) |
| created_at | TIMESTAMPTZ | No | When the action occurred |

| # | Check | Severity | Description |
| --- | --- | --- | --- |
| S1 | Claim Type Valid | Error | claim_type is AHCIP or WCB |
| S2 | Required Base Fields | Error | physician_id, patient_id, date_of_service are present |
| S3 | Patient Exists | Error | patient_id resolves to a valid patient record |
| S4 | Physician Active | Error | physician_id resolves to an active provider with valid BA/billing number |
| S5 | DOS Valid | Error | date_of_service is a valid date, not in the future, not before physician's registration date |
| S6 | Submission Window | Error/Warn | AHCIP: DOS within 90 calendar days. WCB: form-specific. Error if expired; Warning if within 7 days of deadline. |
| S7 | Duplicate Detection | Warning | Same patient + same DOS + same primary service code found in existing non-deleted claims. Warning, not error — intentional duplicates are valid in some scenarios. |

| ID | Story | Acceptance Criteria |
| --- | --- | --- |
| CLM-001 | As a physician, I want to create a new claim via a guided form so that I can bill for a patient encounter | Guided form shows fields relevant to selected claim_type. Required fields are visually indicated. Validation runs on save. Claim enters draft state. AI Coach suggestions appear after initial validation. |
| CLM-002 | As a physician, I want to import claims from my EMR export so that I can avoid double-entry | Upload CSV/delimited file. Apply saved field mapping template or create new one. Preview mapped data before import. Validation runs on each row. Success/error count displayed. Failed rows with specific error messages. |
| CLM-003 | As an ED physician, I want to add patient encounters during my shift so that I can bill them as a batch at shift end | Create shift with facility and date. Add encounters during shift. Review all encounters at shift end. Queue entire shift as a batch. After-hours premiums auto-calculated from shift times. |
| CLM-004 | As a delegate, I want to create claims on behalf of my physician so that I can support their billing workflow | Delegate creates claim in physician context. Claim is owned by the physician (HIA custodian). Delegate's identity recorded in audit trail. Delegate permissions checked per RBAC. |

| ID | Story | Acceptance Criteria |
| --- | --- | --- |
| CLM-005 | As a physician, I want real-time validation feedback so that I can fix errors before submission | Validation runs on save. Errors displayed inline next to affected fields. Warnings displayed as non-blocking alerts. Error count shown in claim header. |
| CLM-006 | As a physician, I want to queue validated claims for submission | Only validated claims (zero errors) can be queued. Clean/flagged classification applied at queue time. Physician sees classification status. |
| CLM-007 | As a physician, I want AI Coach suggestions to help me optimise my billing | After validation, AI Coach suggestions appear as actionable cards. Each suggestion shows: what to change, expected revenue impact, confidence level. Accept or dismiss with optional reason. |

| ID | Story | Acceptance Criteria |
| --- | --- | --- |
| CLM-008 | As a physician, I want my clean claims to auto-submit per my preference | Per tiered auto-submission model. Auto Clean: clean claims included automatically. Auto All: all queued claims. Require Approval: none without explicit approval. |
| CLM-009 | As a delegate, I want to approve flagged claims for submission | Delegate sees flagged claims with their flags. Can review each flag, then approve or return to physician. Approval logged with delegate identity. |

| ID | Story | Acceptance Criteria |
| --- | --- | --- |
| CLM-010 | As a physician, I want to see assessment results when they arrive | Notification emitted when assessment processed. Claim state updated. Assessed claims show acceptance confirmation. |
| CLM-011 | As a physician, I want to understand why a claim was rejected and how to fix it | Rejected claims show: explanatory/error code(s), human-readable description, corrective guidance (system-generated), one-click resubmit after correction. |
| CLM-012 | As a physician, I want to write off a rejected claim I don't intend to resubmit | Write-off action available on rejected claims. Requires confirmation. Write-off reason recorded in audit. Claim enters terminal written_off state. |

| ID | Story | Acceptance Criteria |
| --- | --- | --- |
| CLM-013 | As a physician, I want to see claims approaching their submission deadline | Dashboard widget shows claims within 7 days of deadline. Sorted by urgency. Notification emitted at 7, 3, and 1 day(s) before deadline. |
| CLM-014 | As a physician, I want to export my complete claim history | Export all claims as CSV or structured format. Includes all fields, states, audit trail. Downloadable via authenticated link. Supports date range filtering. |
| CLM-015 | As a physician, I want to see potential duplicate claims before I submit them | Duplicate detection runs during validation. Matching criteria: same patient + same DOS + same primary code. Alert shows the existing claim for comparison. Physician can acknowledge (intentional) or merge. |

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | /api/v1/claims | Create a claim. Body includes claim_type (AHCIP or WCB). Routes to appropriate extension table creation. |
| GET | /api/v1/claims/{id} | Retrieve claim with all pathway-specific details, validation result, AI suggestions, flags. |
| PUT | /api/v1/claims/{id} | Update claim. Triggers revalidation. Partial updates supported. |
| DELETE | /api/v1/claims/{id} | Soft-delete. Only from draft state. |
| GET | /api/v1/claims | List claims with filtering: state, claim_type, date range, patient, is_clean. Paginated. |
| POST | /api/v1/claims/{id}/validate | Run validation pipeline and return results without state change. |
| POST | /api/v1/claims/{id}/queue | Queue a validated claim for submission. |
| POST | /api/v1/claims/{id}/unqueue | Remove from submission queue. Returns to validated state. |
| POST | /api/v1/claims/{id}/write-off | Write off a rejected claim. Requires reason. Terminal. |

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | /api/v1/imports | Upload EMR export file. Optionally specify field_mapping_template_id. |
| GET | /api/v1/imports/{id} | Get import status, success/error counts, error details. |
| GET | /api/v1/imports/{id}/preview | Preview mapped data before committing import. |
| POST | /api/v1/imports/{id}/commit | Commit previewed import. Creates claims from successfully mapped rows. |

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | /api/v1/field-mapping-templates | Create a new field mapping template. |
| GET | /api/v1/field-mapping-templates | List templates for the authenticated physician. |
| PUT | /api/v1/field-mapping-templates/{id} | Update a template. |
| DELETE | /api/v1/field-mapping-templates/{id} | Delete a template. |

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | /api/v1/shifts | Create a new ED shift. |
| POST | /api/v1/shifts/{id}/encounters | Add an encounter (claim) to the shift. |
| PUT | /api/v1/shifts/{id}/complete | Complete the shift. Triggers after-hours calculation for all encounters. |
| GET | /api/v1/shifts/{id} | Get shift details with all encounters. |

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/claims/rejected | List rejected claims for the physician. Includes explanatory codes and corrective guidance. |
| GET | /api/v1/claims/{id}/rejection-details | Get detailed rejection info: codes, descriptions, suggested corrections, resubmission eligibility. |
| POST | /api/v1/claims/{id}/resubmit | One-click resubmission after correction. Revalidates and requeues. |

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/claims/{id}/suggestions | Get AI Coach suggestions for this claim. |
| POST | /api/v1/claims/{id}/suggestions/{sug_id}/accept | Accept a suggestion. Applies the suggested change to the claim. |
| POST | /api/v1/claims/{id}/suggestions/{sug_id}/dismiss | Dismiss a suggestion. Optional reason. Clears the suggestion flag. |

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | /api/v1/exports | Request a claim history export. Parameters: date range, claim_type filter, format (CSV, JSON). |
| GET | /api/v1/exports/{id} | Check export status and download when ready. |

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/submission-preferences | Get current auto-submission mode for the physician. |
| PUT | /api/v1/submission-preferences | Update auto-submission mode. Audit-logged. |

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

| # | Question | Context |
| --- | --- | --- |
| 1 | Should the duplicate detection window be configurable per physician, or system-wide? | Some physicians (radiologists) routinely bill the same code for the same patient on the same day. Others never should. |
| 2 | What is the maximum batch size (number of claims) before performance becomes a concern? | Radiologists may queue 100+ claims per batch cycle. Need to validate batch assembly and file generation performance. |
| 3 | Should claim audit history support field-level rollback, or is it view-only? | Currently specified as view-only audit trail. Rollback would add significant complexity but may be requested by physicians. |
| 4 | Should the AI Coach suggestions count toward the 'flagged' classification, or should they be advisory-only? | Current spec: pending suggestions = flagged. Some physicians may find this annoying if they prefer to review suggestions post-submission. |

| Item | Value |
| --- | --- |
| Parent document | Meritum PRD v1.3 |
| Domain | Claim Lifecycle Core (Domain 4.0 of 13) |
| Build sequence position | 4th (foundation for 4.1 and 4.2) |
| Dependencies | Domain 1 (IAM), Domain 2 (Reference Data), Domain 3 (Notifications) |
| Consumes | Domain 5 (Provider Mgmt), Domain 6 (Patient Registry), Domain 7 (Intelligence Engine) |
| Child domains | Domain 4.1 (AHCIP Claim Pathway), Domain 4.2 (WCB Claim Pathway) |
| Version | 1.0 |
| Date | February 2026 |

