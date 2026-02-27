# Meritum_Domain_04_Claim_Lifecycle

MERITUM

Functional Requirements

Claim Lifecycle

Domain 4 of 13  |  Critical Path: Position 4

Meritum Health Technologies Inc.

Version 1.0  |  February 2026

CONFIDENTIAL

# Table of Contents

# 1. Domain Overview

## 1.1 Purpose

The Claim Lifecycle domain is the operational core of Meritum. It manages the complete journey of a billing claim from initial creation through validation, submission to Alberta Health (AHCIP via H-Link) or WCB Alberta, assessment processing, rejection management, and reconciliation. Every dollar of physician revenue flows through this domain.

This is the largest domain in Meritum by scope and complexity. It orchestrates interactions with Reference Data (validation rules), Intelligence Engine (AI Coach suggestions), Notification Service (deadline alerts, submission confirmations), Provider Management (physician BA routing), and Patient Registry (patient demographics for claims). It owns the claim state machine, the validation engine, the batch assembly logic, and the tiered auto-submission model.

## 1.2 Scope

Claim creation: manual entry (guided form), ED shift workflow entry, and batch import from EMR exports

Claim validation engine: real-time validation against governing rules, modifiers, code combinations, and billing constraints

Claim state machine: draft → validated → queued → submitted → assessed → paid/rejected/adjusted

Tiered auto-submission: clean/flagged classification, physician preference modes, delegate batch approval

Thursday batch assembly and H-Link file generation

WCB claim assembly and WCB submission file generation

Assessment/remittance ingestion and reconciliation

Rejection management: explanatory code display, corrective guidance, one-click resubmission

Claim aging monitoring: flagging unresolved claims beyond expected timelines

Duplicate detection: identifying potential duplicate claims before submission

Fee calculation: base fee + modifier adjustments + premiums

90-day submission window enforcement

Data portability: full claim history export

EMR batch import with configurable field mapping

## 1.3 Out of Scope

AI Coach suggestion logic (Intelligence Engine domain; Claim Lifecycle receives and displays suggestions)

Reference data management (Reference Data domain; Claim Lifecycle consumes via API)

Notification delivery (Notification Service; Claim Lifecycle emits events)

Patient demographic management (Patient Registry domain; Claim Lifecycle references patients)

Physician profile and BA configuration (Provider Management; Claim Lifecycle reads provider context)

Payment processing and subscription management (Platform Operations / Stripe)

## 1.4 Domain Dependencies

# 2. Claim State Machine

Every claim in Meritum exists in exactly one state at any time. The state machine governs what actions are possible and what transitions are allowed.

## 2.1 States

## 2.2 State Transitions

## 2.3 Clean vs Flagged Classification

When a claim enters the queued state, the system classifies it as clean or flagged. This classification drives the tiered auto-submission model (PRD Section 5.2).

Clean claim: Passed all validation rules with zero warnings. Zero AI Coach suggestions pending review. Zero unresolved flags. No duplicate detection alerts. The physician has already reviewed and saved the claim during individual entry. Ready for automatic submission.

Flagged claim: Has one or more of the following: active AI Coach suggestions the physician has not accepted or dismissed; validation warnings (not errors) that require physician judgment; duplicate detection alert requiring confirmation; approaching 90-day deadline with incomplete information; any anomaly the system cannot resolve automatically.

Classification is re-evaluated whenever a flagged claim is updated. If the physician addresses all flags (accepts/dismisses AI Coach suggestions, acknowledges warnings, confirms duplicate is intentional), the claim transitions from flagged to clean. This can happen at any time before the Thursday cutoff.

# 3. Data Model

The Claim Lifecycle data model is the most complex in the platform. It must capture every data element required for H-Link submission, WCB submission, fee calculation, validation context, and audit history.

## 3.1 Claims Table

## 3.2 WCB-Specific Fields

WCB claims carry additional fields not required for AHCIP claims. These are stored in a separate table linked to the claim.

## 3.3 Batches Table

Each Thursday submission is a batch. Batches group claims for H-Link file generation and tracking.

## 3.4 Import Batches Table

Tracks EMR batch imports for traceability and field mapping.

## 3.5 Field Mapping Templates Table

Stores per-physician (or per-EMR) column-to-field mappings for batch import. Reusable across imports.

## 3.6 Shifts Table (ED Workflow)

## 3.7 Claim Audit History Table

Every state change and significant edit to a claim is recorded. This is separate from the system-wide audit log and provides claim-level traceability.

# 4. User Stories & Acceptance Criteria

## 4.1 Claim Creation

## 4.2 Validation

## 4.3 Submission & Batch Management

## 4.4 Assessment & Rejection Management

## 4.5 Claim Monitoring

## 4.6 Fee Calculation

## 4.7 Data Portability

# 5. Validation Engine Specification

The validation engine is the quality gate of Meritum. It evaluates every claim against all applicable rules from Reference Data before the claim can be queued for submission.

## 5.1 Validation Pipeline

Validation runs as an ordered pipeline of checks. Earlier checks may short-circuit later ones (e.g., if the HSC code doesn’t exist, modifier checks are skipped).

## 5.2 Validation Result Structure

The validation result is a structured object stored on the claim:

errors: array of { check, rule_reference, message, help_text, field_affected }. Any error blocks the claim from being queued.

warnings: array of { check, rule_reference, message, help_text, field_affected }. Warnings do not block but cause the claim to be flagged.

info: array of { check, rule_reference, message, help_text }. Advisory information; no impact on state.

passed: boolean (true if zero errors).

validation_timestamp: when validation was run.

reference_data_version: SOMB version used for validation (for audit traceability).

# 6. H-Link Integration Specification

Claims are submitted to AHCIP via H-Link in a defined file format per the Electronic Claims Submission Specifications Manual. This section specifies how Meritum constructs the submission file from claim data.

## 6.1 Claim Data Elements (H-Link Format)

## 6.2 File Generation

Batch execution (CLM-008) generates the H-Link file for each physician’s batch.

File format follows the Electronic Claims Submission Specifications Manual: fixed-width or delimited fields per AHCIP specification.

Each claim is a record in the file. Records are ordered by date of service (ascending).

File header includes: submitter prefix, batch date, record count. File trailer includes: record count (verification), total claim value.

Generated file is stored securely (encrypted at rest) with the batch record for audit and resubmission capability.

Transmission method: determined during H-Link accreditation process. Likely SFTP or API-based per AHCIP connectivity specification.

## 6.3 WCB Submission

WCB claims follow a separate submission pathway. The exact format is TBD pending WCB electronic submission specification research (PRD action item). The architecture supports:

Separate batch generation for WCB claims (not mixed with AHCIP batches).

WCB-specific file format per WCB submission specifications.

WCB submission may be: direct electronic submission (if WCB supports it) or formatted file for physician manual upload to WCB portal (MVP fallback).

WCB assessment responses follow a different timeline and format than AHCIP. Assessment ingestion (CLM-009) handles both pathways.

## 6.4 Assessment Response Ingestion

H-Link assessment files are received on a defined schedule (typically Friday following Thursday submission).

Meritum polls for or receives the assessment file. Retrieval method: SFTP pull or API-based per H-Link connectivity spec.

Assessment file is parsed per H-Link response format. Each record contains: original claim reference, payment status, amount paid, explanatory code(s).

Records are matched to submitted claims by submission reference.

Claim states are updated and notifications emitted per CLM-009.

# 7. API Contracts

All endpoints require authentication. All state-changing operations are audit-logged. Physician endpoints are scoped to the authenticated physician (or delegate’s physician context).

## 7.1 Claim CRUD

## 7.2 Submission & Batch

## 7.3 EMR Import

## 7.4 ED Shift Workflow

## 7.5 Rejection Management

## 7.6 AI Coach Interactions

## 7.7 Data Export

## 7.8 Submission Preferences

# 8. Interface Contracts with Other Domains

## 8.1 Reference Data (Consumed)

Claim Lifecycle is the primary consumer of Reference Data. It calls Reference Data APIs on every claim creation, edit, and validation. Key interfaces:

HSC search/lookup (by DOS for version awareness)

Validation context: all applicable governing rules for a claim’s code/modifier/facility/specialty combination

Modifier eligibility and calculation parameters

DI code lookup with surcharge/BCP qualification flags

Functional centre lookup

RRNP rate by community

PCPCM basket classification for BA routing

Stat holiday check for after-hours calculations

Explanatory code resolution for rejection management

## 8.2 Intelligence Engine (Consumed)

After validation, Claim Lifecycle sends the claim context to the Intelligence Engine for AI Coach analysis. The Intelligence Engine returns suggestions which are stored on the claim’s ai_coach_suggestions field. Claim Lifecycle displays these suggestions and tracks acceptance/dismissal.

## 8.3 Provider Management (Consumed)

Claim Lifecycle reads provider context: BA number(s), specialty, practice locations (functional centres), PCPCM enrolment status, RRNP eligibility, submission preferences. This data determines default values, routing, and validation context.

## 8.4 Patient Registry (Consumed)

Claim Lifecycle references patients for PHN, name, DOB, and gender. Patient lookup/search is performed during claim creation. Patient DOB is required for age-based modifier calculations.

## 8.5 Notification Service (Events Emitted)

# 9. Security & Audit Requirements

## 9.1 Data Protection

Claims contain PHI (patient PHN, DOB, diagnoses, services). All claim data encrypted at rest (AES-256) and in transit (TLS 1.3).

Claim data is scoped to the physician (HIA custodian). Delegates access only claims for physicians they serve, per configured permissions.

Admin cannot view individual claims without explicit physician-granted PHI access (time-limited, logged per IAM admin access rules).

Exported claim files are generated on Meritum infrastructure and delivered via authenticated download. Files are not emailed.

EMR import files are processed in memory where possible. Uploaded files are stored temporarily (encrypted), processed, and deleted after import confirmation. Retained only for audit reference if configured.

## 9.2 Audit Trail

Every claim state change, edit, and significant action is recorded in both the claim audit history table (Section 3.7) and the system audit log (via Identity & Access middleware). Key audited actions:

Claim created (with import_source), edited (field-level changes), validated, queued, unqueued, submitted, assessed, resubmitted, written off, deleted, expired

AI Coach suggestion accepted or dismissed (with reason if provided)

Duplicate detection acknowledged

Batch approved (by whom: physician or delegate), batch submitted, batch execution details

Assessment ingested, rejection reviewed

Data export requested and downloaded

Submission preference changed

## 9.3 H-Link File Security

Generated H-Link submission files are encrypted at rest and transmitted via secure channel (SFTP/TLS).

H-Link credentials (submitter prefix, transmission credentials) stored in secrets management system, never in application code or database.

H-Link transmission is logged: timestamp, file reference, record count, transmission result.

Assessment response files are retrieved via secure channel and processed immediately. Raw files retained for audit.

# 10. Testing Requirements

## 10.1 Unit Tests

State machine: all valid transitions succeed, all invalid transitions are rejected

Clean/flagged classification: correctly classifies based on validation results, AI Coach suggestions, and duplicate alerts

Fee calculation: base fee + each modifier type + each premium type for representative HSC codes

Validation pipeline: each of the 19 validation checks with positive and negative cases

H-Link file generation: output matches Electronic Claims Submission Specifications Manual format

Assessment parsing: correctly maps assessment records to submitted claims

90-day window calculation: boundary cases (exactly 90 days, 91 days, DST transitions)

Duplicate detection: same patient/DOS/HSC detected; different patient/DOS not flagged

PCPCM routing: in-basket codes route to PCPCM BA, out-of-basket to FFS BA

After-hours calculation: standard evenings, weekends, stat holidays (including Alberta-specific)

EMR import parsing: CSV with various delimiters, header/no-header, date formats, partial failures

## 10.2 Integration Tests

Full claim lifecycle: create → validate → queue → Thursday batch → submit → assessment → paid

Rejection lifecycle: submit → rejected → review → resubmit → paid

Auto-submission modes: test each mode (auto clean, auto all, require approval) with clean and flagged claims

Delegate batch approval: delegate approves flagged claims → included in batch → physician notified

EMR import end-to-end: upload CSV → map fields → validate → AI Coach suggestions → queue → submit

ED shift workflow: start shift → add encounters → complete shift → review → queue → submit

PCPCM dual-BA: PCPCM physician creates in-basket and out-of-basket claims → separate batches generated

WCB claim lifecycle: create WCB claim → validate WCB fields → separate batch → submit

90-day expiry: create claim with old DOS → verify deadline notifications → verify expiry

Data export: request export → generation → download → verify completeness

## 10.3 Billing Scenario Tests

Each billing scenario from the PRD (Section 7) must be tested end-to-end:

FFS clinic visit with CMGP, after-hours premium, and RRNP

Shadow billing (ARP with TM modifier)

PCPCM hybrid (dual-BA routing)

WCB initial assessment + follow-up

ED shift with surcharge (13.99H), after-hours (AFHR), and CMGP

Hospital inpatient with GR 3 visit limits

Specialist consultation with GR 8 referral

Obstetric delivery with multiple codes and modifiers

Virtual care visit

Reciprocal/out-of-province billing

Locum physician (different functional centres in same month)

Radiologist high-volume batch (50+ claims per day)

# 11. Open Questions

# 12. Document Control

Parent document: Meritum PRD v1.3

Domain: Claim Lifecycle (Domain 4 of 13)

Build sequence position: 4th (depends on Identity & Access, Reference Data, Notification Service; consumes Provider Management, Patient Registry, Intelligence Engine)

This is the largest and most complex domain. It contains the core revenue-generating functionality of the platform. Build priority is the highest after its dependencies are in place.

Next domain in critical path: Provider Management (Domain 5)

| Depends On | Provides To | Interface Type |
| --- | --- | --- |
| Reference Data | Intelligence Engine | HSC codes, fees, modifiers, governing rules, DI codes, functional centres, RRNP, PCPCM baskets, stat holidays, explanatory codes — all version-aware by date of service |
| Provider Management | Analytics & Reporting | Physician BA number(s), specialty, practice locations, submission preferences, PCPCM enrolment status |
| Patient Registry | Notification Service | Patient PHN, name, DOB, gender for claim construction; patient lookup/search |
| Identity & Access | Mobile Companion | Auth context (user_id, role, permissions, physician_id); subscription gating |
| Notification Service | H-Link Integration | Event emission for all claim lifecycle notifications; consumes nothing from Notification Service |
| Intelligence Engine | — | AI Coach suggestions attached to claims; Claim Lifecycle displays and tracks suggestion acceptance/dismissal |

| State | Description | Allowed Actions |
| --- | --- | --- |
| draft | Claim created but incomplete or not yet validated. The physician is still working on it. | Edit, validate, delete |
| validated | Claim has passed validation. May have warnings or AI Coach suggestions, but no blocking errors. | Edit (returns to draft), queue for submission, delete |
| queued | Claim is in the submission queue for the next Thursday batch. Classified as clean or flagged. | Unqueue (returns to validated), review/accept/dismiss AI Coach suggestions, approve (for flagged claims) |
| submitted | Claim has been included in a Thursday H-Link batch (or WCB submission). Awaiting assessment. | View only; no edits. Track submission reference. |
| assessed_paid | AHCIP assessment received: claim paid in full at expected amount. | View, export, archive |
| assessed_adjusted | AHCIP assessment received: claim paid at a different amount than expected (partial payment, fee adjustment). | View, acknowledge adjustment, dispute (creates note), export |
| assessed_rejected | AHCIP assessment received: claim rejected with explanatory code(s). | View rejection detail, review corrective guidance, edit and resubmit (creates new claim linked to original), write off, export |
| resubmitted | A corrected version of a previously rejected claim has been created and queued. | Same as queued state; linked to original rejected claim |
| written_off | Physician has decided not to pursue a rejected claim. Revenue counted as lost. | View only |
| expired | Claim passed the 90-day submission window without being submitted. Cannot be recovered. | View only |
| deleted | Soft-deleted by physician. Not visible in normal views. Retained for audit. | View in audit log only; permanent deletion follows account deletion schedule |

| From | To | Trigger | Conditions |
| --- | --- | --- | --- |
| (new) | draft | Claim created (manual entry, shift workflow, or batch import) | Valid physician context; active subscription |
| draft | validated | Validation engine runs; no blocking errors | All required fields populated; no error-severity rule violations |
| draft | deleted | Physician deletes draft | Physician or delegate with permission |
| validated | draft | Physician edits a validated claim | Any field change invalidates the claim; must re-validate |
| validated | queued | Physician or system queues claim for submission | Claim is validated; within 90-day window |
| validated | deleted | Physician deletes validated claim |  |
| queued | validated | Physician unqueues a claim (removes from batch) | Before Thursday 12:00 MT cutoff |
| queued | submitted | Thursday batch execution or manual batch approval | Thursday 12:00 MT cutoff reached; claim meets auto-submission criteria OR physician/delegate approved |
| queued | queued (next week) | Flagged claim not reviewed by Thursday cutoff | Rolls to next week’s batch; notification sent |
| submitted | assessed_paid | H-Link assessment received: paid | Assessment file parsed; claim matched |
| submitted | assessed_adjusted | H-Link assessment received: adjusted | Assessment file parsed; amount differs from expected |
| submitted | assessed_rejected | H-Link assessment received: rejected | Assessment file parsed; explanatory code indicates rejection |
| assessed_rejected | resubmitted | Physician corrects and resubmits | New claim created with corrections; linked to original |
| assessed_rejected | written_off | Physician writes off rejected claim | Explicit physician action |
| draft/validated | expired | 90-day window passed without submission | System job detects expiry; irreversible |
| deleted | (purged) | Account deletion after 30-day grace period | IAM-012 account deletion process |

| Field | Type | Constraints | Notes |
| --- | --- | --- | --- |
| id | UUID | PK | Internal claim identifier |
| physician_id | UUID | FK → users.id, NOT NULL | Physician who owns this claim |
| patient_id | UUID | FK → patients.id, NOT NULL | Patient this claim is for |
| claim_type | ENUM | NOT NULL | ahcip, wcb |
| state | ENUM | NOT NULL, DEFAULT draft | Current state per state machine (Section 2) |
| classification | ENUM | NULLABLE | clean, flagged — set when state = queued |
| ba_number | VARCHAR(10) | NOT NULL | Billing Arrangement number for submission (may differ per PCPCM routing) |
| prac_id | VARCHAR(10) | NOT NULL | Physician PRAC ID |
| date_of_service | DATE | NOT NULL | When the service was provided |
| time_of_service | TIME | NULLABLE | Start time (required for after-hours, CMGP) |
| time_end | TIME | NULLABLE | End time (required for CMGP/LSCD time calculation) |
| functional_centre | VARCHAR(10) | NULLABLE (conditional) | Required for hospital, ED, auxiliary settings; from Reference Data |
| hsc_codes | JSONB | NOT NULL | Array of up to 3 HSCs: [{ code, fee, sequence }] |
| modifiers | JSONB | NULLABLE | Array of up to 3 modifiers: [{ code, type, value_applied }] |
| di_codes | JSONB | NOT NULL | Array of up to 3 ICD-9 codes: [{ code, sequence }] |
| referring_prac_id | VARCHAR(10) | NULLABLE | Required when GR 8 referral rules apply |
| calls | INTEGER | NULLABLE | Number of calls (for call-in codes) |
| text_field | VARCHAR(400) | NULLABLE | Optional text field per H-Link spec |
| calculated_fee | DECIMAL(10,2) | NULLABLE | System-calculated total fee (base + modifiers + premiums) |
| fee_breakdown | JSONB | NULLABLE | Detailed fee calculation: { base: $, modifiers: [{code, amount}], premiums: [{type, amount}], total: $ } |
| submission_preference_mode | ENUM | NOT NULL | auto_clean_hold_flagged, auto_all, require_approval — snapshot of physician preference at queue time |
| validation_result | JSONB | NULLABLE | Last validation result: { errors: [], warnings: [], info: [] } |
| ai_coach_suggestions | JSONB | NULLABLE | Pending AI Coach suggestions: [{ id, type, description, status: pending|accepted|dismissed }] |
| flag_reasons | JSONB | NULLABLE | Why this claim is flagged: [{ type, description }] |
| batch_id | UUID | NULLABLE | FK to batches table; set when included in a batch |
| submission_reference | VARCHAR(50) | NULLABLE | H-Link or WCB submission tracking reference |
| assessment_result | JSONB | NULLABLE | Assessment response: { status, amount_paid, explanatory_codes: [], adjustment_reason } |
| original_claim_id | UUID | NULLABLE | FK self-reference for resubmissions; links to the original rejected claim |
| import_source | ENUM | NULLABLE | manual, emr_import, shift_workflow — how the claim was created |
| import_batch_id | UUID | NULLABLE | FK to import_batches table for EMR-imported claims |
| shift_id | UUID | NULLABLE | FK to shifts table for ED shift workflow claims |
| created_at | TIMESTAMP | NOT NULL |  |
| updated_at | TIMESTAMP | NOT NULL |  |
| queued_at | TIMESTAMP | NULLABLE | When claim entered queued state |
| submitted_at | TIMESTAMP | NULLABLE | When claim was submitted to H-Link/WCB |
| assessed_at | TIMESTAMP | NULLABLE | When assessment was received |
| deleted_at | TIMESTAMP | NULLABLE | Soft delete timestamp |
| expires_at | DATE | NOT NULL | date_of_service + 90 days; calculated on creation |

| Field | Type | Constraints | Notes |
| --- | --- | --- | --- |
| id | UUID | PK |  |
| claim_id | UUID | FK → claims.id, UNIQUE, NOT NULL | One-to-one with parent claim |
| wcb_claim_number | VARCHAR(20) | NOT NULL | WCB Alberta claim number |
| employer_name | VARCHAR(200) | NULLABLE | Employer of the injured worker |
| employer_id | VARCHAR(20) | NULLABLE | WCB employer account number |
| injury_date | DATE | NOT NULL | Date of workplace injury |
| injury_nature | TEXT | NULLABLE | Description of injury |
| body_part | VARCHAR(100) | NULLABLE | Affected body part(s) |
| treatment_type | ENUM | NULLABLE | initial_assessment, follow_up, surgery, report, other |
| wcb_report_attached | BOOLEAN | NOT NULL, DEFAULT false | Whether required WCB report is attached/completed |

| Field | Type | Constraints | Notes |
| --- | --- | --- | --- |
| id | UUID | PK |  |
| physician_id | UUID | FK → users.id, NOT NULL |  |
| batch_type | ENUM | NOT NULL | ahcip, wcb |
| ba_number | VARCHAR(10) | NOT NULL | BA this batch is submitted under |
| submission_date | DATE | NOT NULL | Thursday date |
| cutoff_time | TIMESTAMP | NOT NULL | Thursday 12:00 MT in UTC |
| claim_count | INTEGER | NOT NULL | Number of claims in this batch |
| total_expected_amount | DECIMAL(12,2) | NOT NULL | Sum of calculated fees for all claims |
| claims_auto_submitted | INTEGER | NOT NULL | Clean claims that auto-submitted |
| claims_approved | INTEGER | NOT NULL, DEFAULT 0 | Flagged claims approved by physician/delegate |
| claims_held | INTEGER | NOT NULL, DEFAULT 0 | Flagged claims held (rolled to next week) |
| approved_by | UUID | NULLABLE | FK to users.id; physician or delegate who approved batch |
| state | ENUM | NOT NULL, DEFAULT assembling | assembling, submitted, assessment_received, reconciled |
| hlink_file_reference | VARCHAR(100) | NULLABLE | H-Link submission file identifier |
| assessment_file_reference | VARCHAR(100) | NULLABLE | Assessment response file identifier |
| total_paid | DECIMAL(12,2) | NULLABLE | Total amount paid per assessment |
| total_rejected | DECIMAL(12,2) | NULLABLE | Total amount rejected |
| total_adjusted | DECIMAL(12,2) | NULLABLE | Total amount adjusted |
| created_at | TIMESTAMP | NOT NULL |  |
| submitted_at | TIMESTAMP | NULLABLE |  |
| assessed_at | TIMESTAMP | NULLABLE |  |

| Field | Type | Constraints | Notes |
| --- | --- | --- | --- |
| id | UUID | PK |  |
| physician_id | UUID | FK → users.id, NOT NULL |  |
| filename | VARCHAR(255) | NOT NULL | Original uploaded filename |
| file_hash | VARCHAR(64) | NOT NULL | SHA-256 hash for deduplication and audit |
| emr_source | VARCHAR(50) | NULLABLE | Identified or physician-declared EMR (e.g., MedAccess, Wolf) |
| mapping_template_id | UUID | NULLABLE | FK to saved mapping template |
| total_rows | INTEGER | NOT NULL | Rows in uploaded file |
| rows_imported | INTEGER | NOT NULL | Successfully imported as claims |
| rows_failed | INTEGER | NOT NULL | Failed parsing or validation |
| failed_rows_detail | JSONB | NULLABLE | [{ row_number, fields, error }] |
| state | ENUM | NOT NULL | uploaded, mapped, validated, imported, partially_imported |
| created_at | TIMESTAMP | NOT NULL |  |
| imported_at | TIMESTAMP | NULLABLE |  |

| Field | Type | Constraints | Notes |
| --- | --- | --- | --- |
| id | UUID | PK |  |
| physician_id | UUID | FK → users.id, NULLABLE | NULL for system-provided EMR templates |
| template_name | VARCHAR(100) | NOT NULL | e.g., “My MedAccess export” or “MedAccess Standard” |
| emr_type | VARCHAR(50) | NULLABLE | medaccess, wolf, ps_suite, accuro, other, custom |
| column_mappings | JSONB | NOT NULL | { source_column: target_field } e.g., { “Service Code”: “hsc_codes[0].code”, “Patient PHN”: “patient_phn”, ... } |
| delimiter | ENUM | NOT NULL, DEFAULT comma | comma, tab, pipe, fixed_width |
| has_header_row | BOOLEAN | NOT NULL, DEFAULT true |  |
| date_format | VARCHAR(20) | NOT NULL, DEFAULT YYYY-MM-DD | Expected date format in the file |
| is_system_template | BOOLEAN | NOT NULL, DEFAULT false | True for pre-built EMR templates |
| created_at | TIMESTAMP | NOT NULL |  |
| updated_at | TIMESTAMP | NOT NULL |  |

| Field | Type | Constraints | Notes |
| --- | --- | --- | --- |
| id | UUID | PK |  |
| physician_id | UUID | FK → users.id, NOT NULL |  |
| shift_date | DATE | NOT NULL |  |
| start_time | TIME | NOT NULL |  |
| end_time | TIME | NOT NULL |  |
| functional_centre | VARCHAR(10) | NOT NULL | ED functional centre code |
| state | ENUM | NOT NULL, DEFAULT active | active, completed, claims_reviewed |
| claim_count | INTEGER | NOT NULL, DEFAULT 0 | Claims entered during this shift |
| created_at | TIMESTAMP | NOT NULL |  |
| completed_at | TIMESTAMP | NULLABLE |  |

| Field | Type | Constraints | Notes |
| --- | --- | --- | --- |
| id | UUID | PK | Append-only |
| claim_id | UUID | FK → claims.id, NOT NULL |  |
| timestamp | TIMESTAMP | NOT NULL |  |
| actor_user_id | UUID | FK → users.id, NOT NULL | Who made this change (physician, delegate, system) |
| action | VARCHAR(50) | NOT NULL | created, edited, validated, queued, unqueued, submitted, assessed, resubmitted, written_off, deleted, suggestion_accepted, suggestion_dismissed, flag_resolved |
| previous_state | ENUM | NULLABLE | State before transition |
| new_state | ENUM | NULLABLE | State after transition |
| changes | JSONB | NULLABLE | Field-level change detail for edits: { field: { old, new } } |
| notes | TEXT | NULLABLE | Optional notes (e.g., write-off reason, resubmission notes) |

| CLM-001 | Manual Claim Entry (Guided Form) |
| --- | --- |
| User Story | As a physician, I want to create a claim by entering service details in a guided form so that I can bill for services I’ve provided. |
| Acceptance Criteria | • Claim form presents fields in logical billing order: patient → date of service → practice setting/functional centre → HSC code(s) → diagnostic code(s) → modifiers → referring physician (if required) → additional fields. • Patient lookup: search by PHN, name, or recent patients. If patient not found, quick-add option (PHN + name minimum). • Date of service defaults to today but is editable. System warns if date is >85 days ago (approaching 90-day window). • Practice setting selection drives: which functional centre is required, which after-hours rules apply, which codes are available. • HSC code entry uses Reference Data search (REF-001): autocomplete, specialty filtering, favourites palette. • Up to 3 HSC codes per claim per H-Link spec. Each code shows its base fee on selection. • Diagnostic code entry uses Reference Data search (REF-003). Up to 3 DI codes. System flags surcharge/BCP qualification. • Modifier selection: explicit modifiers shown as toggleable options filtered by HSC eligibility. Implicit modifiers (AFHR, BCP, RRNP, age) shown as read-only indicators with explanatory tooltips. • Semi-implicit modifiers (CMGP): if time documentation indicates eligibility, system suggests with one-click accept. • Referring PRAC ID field appears conditionally when GR 8 applies to the selected HSC. • Fee is calculated in real-time as fields are populated: base fee + modifiers + premiums = total. • On save: claim enters draft state. Validation runs automatically (CLM-004). • All fields have contextual help tooltips from Reference Data. |

| CLM-002 | ED Shift Workflow |
| --- | --- |
| User Story | As an ED physician, I want to log patient encounters during my shift and batch-review them afterward so that I can focus on patient care during the shift. |
| Acceptance Criteria | • Physician starts a shift: selects date, ED functional centre, shift start/end times. A shift record is created. • For each patient encounter during the shift: quick patient lookup (PHN scan or name search), primary HSC code from favourites palette (top 20 ED codes one-tap accessible), time auto-stamped (adjustable), DI code selection. • Encounter entry is minimal: optimised for speed. 4–6 taps per patient target. • System automatically calculates time between patient entries and prompts CMGP if encounter duration exceeds threshold. • After-hours premiums (AFHR) applied automatically based on encounter time vs standard hours and stat holiday calendar. • ED surcharge (13.99H/13.99HA) automatically prompted when qualifying DI code from Attachment G is selected. • On shift end: batch review screen displays all encounters with AI Coach suggestions. Physician reviews, modifies, or confirms each encounter. Confirmed encounters become validated claims queued for submission. • Shift can be left open and completed later (e.g., next day for overnight shifts). • Multiple shifts per day supported (e.g., split shifts). • Claims created via shift workflow have import_source = shift_workflow and shift_id linked. |

| CLM-003 | EMR Batch Import |
| --- | --- |
| User Story | As a physician who generates billing in my EMR, I want to import my EMR’s billing export into Meritum so that I can run it through the intelligence layer without re-entering data. |
| Acceptance Criteria | • Physician uploads a CSV/flat file from Settings → Import Claims or from the claims dashboard. • If first import: physician selects EMR type (MedAccess, Wolf, PS Suite, other) and maps columns to Meritum fields using the field mapping UI. System provides pre-built templates for known EMRs. Mapping is saved for future imports. • If returning import with saved mapping: system auto-applies the saved template. Physician can review and adjust. • System parses the file using the mapping configuration. For each row: map fields to claim structure, look up patient by PHN (create placeholder if not found), validate HSC codes and DI codes against Reference Data. • Parsing results displayed: rows successfully parsed, rows with errors (with error detail per row). Physician can fix errors inline or skip failed rows. • Successfully parsed rows are created as draft claims. Validation engine runs on all imports (CLM-004). • AI Coach analyses all imported claims (CLM-005). Suggestions displayed on the import review screen. • Import review screen shows: imported claims with validation results and AI Coach suggestions. Clean claims highlighted in green. Flagged claims highlighted in amber with flag reasons. • Physician can accept, modify, or dismiss suggestions. On confirm: claims are queued for submission. • Duplicate detection (CLM-010) runs against existing claims to prevent re-importing previously submitted billing. • Import metadata tracked: filename, file hash (prevents duplicate file upload), row counts, EMR source, mapping template used. • Partial imports supported: valid rows imported, invalid rows returned with error detail for correction and re-upload. |

| CLM-004 | Real-Time Claim Validation |
| --- | --- |
| User Story | As a physician, I want my claims validated against all applicable rules in real-time so that I can fix issues before submission and avoid rejections. |
| Acceptance Criteria | • Validation runs automatically on save and can be triggered manually. • Validation queries Reference Data for all applicable rules based on the claim’s date of service, HSC codes, DI codes, modifiers, functional centre, and physician specialty. • Validation results are categorised: errors (blocking: claim cannot be queued), warnings (non-blocking: claim can be queued but may be rejected), info (advisory: suggestions for optimisation). • Each validation result includes: rule reference (e.g., GR 5(3)(b)), plain-language explanation, severity, and suggested corrective action. • Validation checks include: PHN format validity (9 digits, check digit), HSC code exists in current SOMB version for DOS, HSC specialty restriction (physician can bill this code), modifier compatibility (selected modifiers valid for selected HSC), modifier exclusion (conflicting modifiers not combined), code combination rules (GR 5: prohibited combinations detected), visit limit rules (GR 3: max visits per patient per day), referral requirement (GR 8: referring PRAC ID present when required), facility rule (GR 11: functional centre valid for selected codes), surcharge eligibility (13.99H/HA: qualifying DI + qualifying base code), 90-day window (date of service within submission window), duplicate detection (same patient, same DOS, same codes in existing claims), PCPCM basket routing (correct BA for in-basket vs out-of-basket codes), time documentation completeness (CMGP/LSCD require start/end time), after-hours eligibility (time of service + stat holiday check), WCB-specific field completeness (claim number, injury date for WCB claims). • Validation response time: <500ms for individual claim, <5 seconds for batch of 50 claims. • Validation result stored on the claim record for display and classification purposes. |

| CLM-005 | AI Coach Integration |
| --- | --- |
| User Story | As a physician, I want the AI Billing Coach to suggest optimisations on my claims so that I don’t miss revenue opportunities. |
| Acceptance Criteria | • After validation, the Intelligence Engine analyses the claim and attaches suggestions to the claim’s ai_coach_suggestions field. • Suggestions are displayed inline on the claim: each suggestion shows what the AI Coach recommends, why, the estimated revenue impact, and the governing rule or SOMB reference. • Suggestion types include: missed modifier (e.g., “This encounter exceeded 25 minutes. Consider adding CMGP for an estimated additional $[X].”), missed code (e.g., “You billed 03.03A but the encounter also qualifies for 08.19A.”), missed surcharge (“DI code qualifies for ED surcharge 13.99H.”), missed premium (“This community qualifies for RRNP at [X]%.”), WCB documentation reminder (“WCB claims for this injury type typically require a First Report. Has this been submitted?”). • Each suggestion has three actions: Accept (applies the suggestion to the claim), Dismiss (removes the suggestion; logged), Review Later (leaves suggestion pending). • Accepted suggestions modify the claim (add modifier, add code, etc.) and trigger re-validation. • Dismissed suggestions are logged with reason (optional) for Intelligence Engine learning. • Pending (unreviewed) suggestions cause the claim to be classified as flagged when queued. • Suggestion acceptance rate tracked per physician for analytics. |

| CLM-006 | Queue Claim for Submission |
| --- | --- |
| User Story | As a physician, I want to queue validated claims for the next Thursday submission so that they are included in the weekly batch. |
| Acceptance Criteria | • Physician clicks “Queue for submission” on a validated claim (or bulk-selects multiple claims). • System checks: claim is validated (no blocking errors), date of service within 90-day window, subscription is active. • Claim state transitions to queued. Classification (clean/flagged) is computed. • Queued claims appear in the “Queued for Thursday” view with clean/flagged status visible. • Physician can unqueue a claim before the Thursday cutoff (returns to validated state). • PCPCM routing: if physician has PCPCM enrolment, claims are automatically routed to the correct BA (in-basket → PCPCM BA, out-of-basket → FFS BA) based on Reference Data PCPCM classification. |

| CLM-007 | Pre-Submission Batch Review |
| --- | --- |
| User Story | As a physician, I want to review everything about to be submitted before the Thursday cutoff so that I can catch any last-minute issues. |
| Acceptance Criteria | • Batch review screen accessible from the dashboard and via notification deep links. • Shows: all queued claims for this Thursday, grouped by BA number. For each claim: patient, DOS, HSC codes, modifiers, calculated fee, classification (clean/flagged), flag reasons if any. • Summary bar at top: total claims, total clean, total flagged, total expected value, submission preference mode. • Flagged claims are highlighted with expandable flag detail: each flag reason, AI Coach suggestions with accept/dismiss actions, validation warnings with context. • Physician can take action on flagged claims directly from the review screen: accept suggestions, dismiss suggestions, edit claim (navigates to claim form, returns to review after save). • For “auto-submit clean, hold flagged” mode: green indicator on clean claims (“Will auto-submit”), amber on flagged (“Requires your review”). • For “require approval for all” mode: all claims show “Requires approval” until physician clicks “Approve batch.” • Approve batch button: approves all displayed claims (or selected subset). Approval is logged. • If delegate has batch approval authority: same screen, same actions, same audit trail. |

| CLM-008 | Thursday Batch Execution |
| --- | --- |
| User Story | As the system, I want to execute the Thursday batch at 12:00 PM MT so that claims are submitted to H-Link on the weekly schedule. |
| Acceptance Criteria | • At Thursday 12:00 MT, the batch execution job runs for each physician with queued claims. • For each physician, the system evaluates their submission preference: “Auto-submit clean, hold flagged” (default): all clean claims are included in the batch. Flagged claims that have been approved (by physician or delegate) are included. Unapproved flagged claims are held (state remains queued; rolled to next week). “Auto-submit all validated”: all queued claims (clean and flagged) are included. Warnings logged but not blocking. “Require approval for all”: only claims explicitly approved are included. Unapproved claims held. • Batch record created with claim count, expected amount, auto-submitted count, approved count, held count. • For included claims: generate H-Link submission file per Electronic Claims Submission Specifications Manual format. Each claim’s data elements are formatted according to H-Link field specifications. • For PCPCM physicians with dual BAs: separate batches generated per BA number. • For WCB claims: separate batch generated in WCB submission format. • Submission file transmitted to H-Link (or WCB portal). Transmission result logged. • Included claims transition to submitted state. Held claims remain queued. • Notification emitted: batch.submitted with results (NTF-004). • If H-Link transmission fails: batch state = failed. Claims remain queued. Critical notification emitted. Admin alerted. Retry mechanism triggered. • All batch execution actions logged in claim audit history and system audit log. |

| CLM-009 | Assessment Ingestion |
| --- | --- |
| User Story | As the system, I want to process AHCIP assessment responses so that physicians can see what was paid, adjusted, or rejected. |
| Acceptance Criteria | • System polls for or receives H-Link assessment response file (typically Friday following Thursday submission). • Assessment file is parsed according to H-Link response format. Each claim response is matched to the corresponding submitted claim by submission reference. • For each assessed claim, state transitions to: assessed_paid (paid at expected amount), assessed_adjusted (paid at different amount), assessed_rejected (rejected with explanatory code(s)). • Assessment result stored on claim record: status, amount paid, explanatory codes, adjustment details. • For adjusted claims: fee_breakdown is compared to assessment amount; difference highlighted. • For rejected claims: each explanatory code is resolved against Reference Data explanatory codes table. Plain-language explanation and suggested corrective action are attached. • Batch record updated: total_paid, total_rejected, total_adjusted. Batch state transitions to assessment_received. • Notification emitted: assessment.received (NTF-005). If rejections present: claim.rejected event per rejected claim (NTF-008). • Unmatched assessment records (no corresponding claim found) are logged as anomalies for Admin investigation. |

| CLM-010 | Rejection Review & Resubmission |
| --- | --- |
| User Story | As a physician, I want to review why a claim was rejected and resubmit a corrected version so that I can recover the revenue. |
| Acceptance Criteria | • Rejected claims are accessible from: the assessment notification, the dashboard rejection summary, and the claims list filtered by state = assessed_rejected. • Rejection detail view shows: original claim data, explanatory code(s), plain-language explanation of each code, suggested corrective action from Reference Data, AI Coach analysis of rejection pattern (if applicable). • One-click resubmit: creates a new claim pre-populated with the original claim’s data. The physician makes corrections (modifying the field that caused rejection). The new claim is linked to the original via original_claim_id. • The new claim goes through the standard lifecycle: draft → validated → queued → submitted. • Write-off option: physician can mark a rejected claim as written_off if they choose not to pursue it. Write-off requires a reason (optional) and is logged. • Rejection analytics: dashboard shows rejection rate by explanatory code, by HSC, by time period. Trend analysis helps physicians identify systematic billing issues. • Resubmission must still be within the 90-day window from the original date of service. If the window has passed, the claim cannot be resubmitted and is flagged as expired. |

| CLM-011 | Duplicate Detection |
| --- | --- |
| User Story | As a physician, I want the system to detect potential duplicate claims before submission so that I avoid rejections for duplicate billing. |
| Acceptance Criteria | • On claim creation and on queue: system checks for existing claims with the same patient, same date of service, and same primary HSC code. • If a potential duplicate is found, the claim is flagged with a duplicate detection alert showing the existing claim’s details. • Physician must acknowledge the duplicate alert: confirm it is intentional (e.g., two distinct visits on the same day with different DI codes) or cancel the duplicate. • Acknowledged-intentional duplicates have the flag resolved and are classified as clean (if no other flags). • Duplicate detection also runs during EMR batch import (CLM-003) to prevent re-importing previously submitted billing. • Duplicate detection scope: checks against all claims in states draft through assessed_paid (not deleted or expired). |

| CLM-012 | 90-Day Window Enforcement |
| --- | --- |
| User Story | As the system, I want to enforce the 90-day submission window so that physicians don’t lose revenue to expired claims. |
| Acceptance Criteria | • On claim creation: expires_at = date_of_service + 90 days is calculated and stored. • Daily system job scans for draft/validated claims where expires_at is within 14, 7, or 3 days. Notification emitted: claim.deadline_approaching (NTF-006). • Claims that pass expires_at without reaching submitted state are transitioned to expired. This is irreversible. • Expired claims are visible in the claims list (filtered by state = expired) with an explanation of what happened. • Dashboard metric: claims expired this month / this quarter. |

| CLM-013 | Claim Aging |
| --- | --- |
| User Story | As a physician, I want to know when submitted claims haven’t received an assessment within the expected timeframe so that I can investigate. |
| Acceptance Criteria | • Weekly system job scans submitted claims older than the expected assessment window (default: 14 days). • Aging claims are flagged and a notification emitted: claim.aging_alert (NTF-007). • Aging claims view: filtered list showing submitted claims without assessment, sorted by days aging. • Re-alerts weekly until the claim receives an assessment or the physician marks it for manual follow-up. |

| CLM-014 | Real-Time Fee Calculation |
| --- | --- |
| User Story | As a physician, I want to see the calculated fee for my claim in real-time so that I know the expected revenue before submitting. |
| Acceptance Criteria | • Fee calculation runs on every field change that affects the fee: HSC code selection, modifier changes, time documentation, practice location. • Calculation order: start with HSC base fee from Reference Data (version-aware by DOS), apply explicit modifiers (e.g., CMGP units, LSCD, ANE), apply implicit modifiers (AFHR premium based on time + stat holidays, BCP based on DI code, RRNP based on practice location, age premium based on patient DOB), sum multiple HSC codes if applicable. • Fee breakdown displayed: base fee per HSC, each modifier contribution, each premium contribution, total. • For WCB claims: WCB fee schedule used instead of SOMB. Calculation method per WCB code (some are flat, some are time-based, some are report-based). • For shadow billing (ARP with TM modifier): fee shows the notional value (what FFS would pay) for tracking purposes. • Calculation result stored in calculated_fee and fee_breakdown fields on the claim. |

| CLM-015 | Full Claim History Export |
| --- | --- |
| User Story | As a physician, I want to export my complete claim history so that I have my data if I leave Meritum. |
| Acceptance Criteria | • Physician navigates to Settings → Export Data. • Export options: all claims (complete history), date range, specific states (e.g., all assessed claims). • Export formats: CSV (machine-readable, re-importable), PDF (human-readable report with summary statistics). • CSV export includes all claim fields: patient PHN, DOS, HSC codes, modifiers, DI codes, fees, state, assessment result, explanatory codes, submission dates. • PDF export includes: claim summary table, financial summary (total billed, total paid, total rejected, total adjusted), monthly/quarterly breakdowns. • Export generation runs asynchronously for large data sets. Physician is notified when the export is ready for download. • Export includes a data dictionary explaining each field. • No data is withheld: the physician is the HIA custodian and owns all their data. • Accountant export variant: financial summaries only (no PHI). Suitable for sharing with accountant/bookkeeper for tax purposes. |

| Order | Check | Severity | Description |
| --- | --- | --- | --- |
| 1 | Required fields | Error | All mandatory fields populated: patient, DOS, at least 1 HSC, at least 1 DI code, BA number |
| 2 | PHN format | Error | Patient PHN is valid 9-digit format with correct check digit |
| 3 | HSC code validity | Error | Each HSC code exists in SOMB for the claim’s DOS (version-aware) |
| 4 | HSC specialty restriction | Error | Physician’s specialty is authorised to bill each HSC code |
| 5 | 90-day window | Error | DOS is within 90 days of current date |
| 6 | Functional centre | Error | If HSC requires a facility context (GR 11), functional centre is present and valid |
| 7 | Referral requirement | Error | If HSC requires referral (GR 8), referring PRAC ID is present |
| 8 | Code combinations (GR 5) | Error/Warning | Prohibited code combinations detected. Some combinations are hard errors (always rejected); others are warnings (may be rejected depending on context) |
| 9 | Visit limits (GR 3) | Warning | Same patient, same day, same code exceeds maximum. Warning because GR 3 has exceptions for distinct diagnoses |
| 10 | Modifier compatibility | Error | Selected modifiers are valid for the selected HSC codes |
| 11 | Modifier exclusions | Error | Mutually exclusive modifiers are not combined |
| 12 | CMGP time check | Warning | If CMGP modifier selected, start/end time must be documented and duration must exceed threshold |
| 13 | After-hours eligibility | Info | Checks time of service against standard hours and stat holiday calendar. Info if premium is being applied; warning if time is borderline |
| 14 | Surcharge eligibility | Info | If DI code qualifies for 13.99H/HA and surcharge is not included, info suggestion |
| 15 | RRNP eligibility | Info | If physician’s practice location is RRNP-eligible and RRNP modifier not applied |
| 16 | PCPCM routing | Warning | If PCPCM physician, validates BA routing matches basket classification |
| 17 | Duplicate detection | Warning | Potential duplicate found (same patient, DOS, primary HSC) |
| 18 | WCB field completeness | Error | For WCB claims: claim number, injury date present |
| 19 | WCB documentation | Warning | For WCB claims: documentation requirements for the injury type |

| H-Link Field | Source | Notes |
| --- | --- | --- |
| Action Code | System-generated | 1 = new claim, 4 = adjustment, 6 = cancellation |
| Submitter Prefix | Platform config | Meritum’s assigned H-Link submitter prefix |
| Billing Arrangement Number | claim.ba_number | Physician’s BA; may vary per PCPCM routing |
| Practitioner ID | claim.prac_id | Physician’s PRAC ID |
| Patient PHN | patient.phn (via Patient Registry) | 9-digit Alberta PHN |
| Health Service Code(s) | claim.hsc_codes | Up to 3 HSC codes in sequence |
| Modifier(s) | claim.modifiers | Up to 3 modifiers in sequence |
| Diagnostic Code(s) | claim.di_codes | Up to 3 ICD-9 codes in sequence |
| Service Date | claim.date_of_service | YYYYMMDD format |
| Service Time | claim.time_of_service | HHMM format; required for time-dependent billing |
| Functional Centre | claim.functional_centre | Conditional: required for facility-based services |
| Referring Practitioner ID | claim.referring_prac_id | Conditional: required when GR 8 applies |
| Calls | claim.calls | Conditional: number of calls for call-in codes |
| Text Field | claim.text_field | Optional: up to 400 characters of supporting text |

| Method | Endpoint | Description | Auth |
| --- | --- | --- | --- |
| POST | /api/v1/claims | Create a new claim. Body: { patient_id, date_of_service, hsc_codes, di_codes, ... }. Runs validation on save. Returns: { claim_id, state, validation_result }. | Yes |
| GET | /api/v1/claims?state={s}&page={n}&from={date}&to={date} | List claims with filters: state, date range, patient. Paginated. Returns: [Claim summary]. | Yes |
| GET | /api/v1/claims/{id} | Get full claim detail including validation result, AI Coach suggestions, fee breakdown, audit history. | Yes |
| PUT | /api/v1/claims/{id} | Update claim fields. Claim must be in draft or validated state. Re-validates on save. Returns to draft if was validated. | Yes |
| DELETE | /api/v1/claims/{id} | Soft-delete claim. Must be in draft or validated state. Sets deleted_at. Returns 204. | Yes |
| POST | /api/v1/claims/{id}/validate | Manually trigger validation. Returns: { validation_result }. | Yes |
| GET | /api/v1/claims/{id}/fee-breakdown | Get detailed fee calculation for a claim. | Yes |
| GET | /api/v1/claims/{id}/audit-history | Get claim-level audit trail. Returns: [ClaimAuditEntry]. | Yes |

| Method | Endpoint | Description | Auth |
| --- | --- | --- | --- |
| POST | /api/v1/claims/queue | Queue one or more claims. Body: { claim_ids: [...] }. Validates each, classifies clean/flagged. Returns: { queued, failed_validation: [...] }. | Yes |
| POST | /api/v1/claims/{id}/unqueue | Remove claim from submission queue. Returns to validated state. | Yes |
| GET | /api/v1/batches/pending | Get pending batch review: all queued claims for this Thursday. Returns: { claims: [...], summary: { total, clean, flagged, expected_amount } }. | Yes |
| POST | /api/v1/batches/approve | Approve pending batch (or selected claims). Body: { claim_ids?: [...] } (empty = approve all). Logs approver. Returns: { approved_count }. | Yes (Physician or Delegate w/ batch authority) |
| GET | /api/v1/batches?page={n} | List historical batches with summary. Paginated, reverse chronological. | Yes |
| GET | /api/v1/batches/{id} | Get batch detail: claims included, submission result, assessment summary. | Yes |
| GET | /api/v1/batches/{id}/assessment | Get detailed assessment for a batch: per-claim payment/rejection/adjustment. | Yes |

| Method | Endpoint | Description | Auth |
| --- | --- | --- | --- |
| POST | /api/v1/imports/upload | Upload EMR export file. Body: multipart file + { emr_type?, mapping_template_id? }. Returns: { import_batch_id, parsed_rows, failed_rows, requires_mapping: bool }. | Yes |
| GET | /api/v1/imports/{id}/preview | Preview parsed and validated claims from import. Returns: { claims: [...with validation + AI suggestions], failed_rows: [...] }. | Yes |
| POST | /api/v1/imports/{id}/mapping | Submit field mapping for an import. Body: { column_mappings, save_template: bool, template_name? }. Reparse with new mapping. Returns updated preview. | Yes |
| POST | /api/v1/imports/{id}/confirm | Confirm import: create claims from valid rows, queue validated claims. Returns: { claims_created, claims_queued, claims_draft }. | Yes |
| GET | /api/v1/imports | List import history. Returns: [{ import_batch_id, filename, date, rows, result }]. | Yes |
| GET | /api/v1/imports/templates | List saved mapping templates. Returns: [{ id, name, emr_type }]. | Yes |
| DELETE | /api/v1/imports/templates/{id} | Delete a saved mapping template. | Yes |

| Method | Endpoint | Description | Auth |
| --- | --- | --- | --- |
| POST | /api/v1/shifts | Start a shift. Body: { date, functional_centre, start_time, end_time }. Returns: { shift_id }. | Yes |
| POST | /api/v1/shifts/{id}/encounters | Add patient encounter to shift. Body: { patient_id, hsc_code, di_code, time }. Minimal fields for speed. Returns: { claim_id }. | Yes |
| GET | /api/v1/shifts/{id} | Get shift detail with all encounters/claims. | Yes |
| POST | /api/v1/shifts/{id}/complete | End shift. Triggers batch validation and AI Coach analysis on all shift claims. Returns: { claims: [...with suggestions] }. | Yes |
| POST | /api/v1/shifts/{id}/confirm | Confirm shift review: queue all reviewed claims. Returns: { queued_count }. | Yes |
| GET | /api/v1/shifts?page={n} | List shift history. | Yes |

| Method | Endpoint | Description | Auth |
| --- | --- | --- | --- |
| GET | /api/v1/claims/rejected?page={n} | List rejected claims with explanatory codes and corrective guidance. Paginated. | Yes |
| POST | /api/v1/claims/{id}/resubmit | Create corrected copy of rejected claim. Pre-populates from original. Returns: { new_claim_id }. | Yes |
| POST | /api/v1/claims/{id}/write-off | Write off a rejected claim. Body: { reason? }. Returns 204. | Yes |
| GET | /api/v1/claims/aging | List submitted claims beyond expected assessment timeline. | Yes |

| Method | Endpoint | Description | Auth |
| --- | --- | --- | --- |
| POST | /api/v1/claims/{id}/suggestions/{sug_id}/accept | Accept an AI Coach suggestion. Applies the suggested change to the claim. Re-validates. | Yes |
| POST | /api/v1/claims/{id}/suggestions/{sug_id}/dismiss | Dismiss an AI Coach suggestion. Body: { reason? }. Logged for learning. | Yes |
| GET | /api/v1/ai-coach/summary | Weekly AI Coach summary: suggestions made, accepted, dismissed, revenue impact. | Yes |

| Method | Endpoint | Description | Auth |
| --- | --- | --- | --- |
| POST | /api/v1/exports/claims | Request claim history export. Body: { format: csv|pdf, date_from?, date_to?, states?: [...] }. Async. Returns: { export_id }. | Yes (Physician only) |
| GET | /api/v1/exports/{id}/status | Check export status. Returns: { status: processing|ready|failed }. | Yes |
| GET | /api/v1/exports/{id}/download | Download completed export file. | Yes |
| POST | /api/v1/exports/accountant | Request accountant-friendly export (financial summary, no PHI). Body: { format, date_range }. | Yes (Physician only) |

| Method | Endpoint | Description | Auth |
| --- | --- | --- | --- |
| GET | /api/v1/submission-preferences | Get physician’s current submission preference mode. | Yes |
| PUT | /api/v1/submission-preferences | Update submission preference. Body: { mode: auto_clean_hold_flagged | auto_all | require_approval }. | Yes (Physician only) |

| Event | Trigger | Payload |
| --- | --- | --- |
| claim.deadline_approaching | Daily scan: draft/validated claims within 14/7/3 days of 90-day expiry | { physician_id, claims: [{ id, dos, expires_at }], threshold_days } |
| claim.aging_alert | Weekly scan: submitted claims past expected assessment timeline | { physician_id, claims: [{ id, dos, submitted_at, days_aging }] } |
| batch.submitted | Thursday batch execution completes | { physician_id, batch_id, claims_submitted, claims_held, total_amount } |
| assessment.received | Assessment file ingested and parsed | { physician_id, batch_id, paid_count, rejected_count, adjusted_count, total_paid, total_rejected } |
| claim.rejected | Individual claim rejection within assessment | { physician_id, claim_id, hsc_codes, dos, explanatory_codes, corrective_guidance } |
| claim.expired | Claim passed 90-day window | { physician_id, claim_id, dos } |

| Question | Options | Decision Criteria |
| --- | --- | --- |
| H-Link file format specifics | Fixed-width vs delimited; exact field positions and lengths | Determined during H-Link accreditation process. Must obtain Electronic Claims Submission Specifications Manual from AHCIP. |
| H-Link transmission method | SFTP vs API vs other secure channel | Determined during accreditation. Architecture supports any method via abstraction layer. |
| WCB electronic submission format | Direct electronic submission vs formatted file for manual upload | Research required (PRD action item). Design WCB batch generation with interface abstraction to support either path. |
| Assessment file retrieval | Push (AHCIP sends) vs pull (Meritum polls) vs API | Determined during accreditation. Architecture supports all via scheduled job with configurable retrieval method. |
| Claim data archival | Keep all claims in primary table vs archive assessed claims to cold storage after N months | At MVP scale, no archival needed. Evaluate when data volume exceeds performance thresholds. |
| EMR import: real-time validation vs batch validation | Validate each row as parsed vs validate all after parsing | Batch validation after parsing is simpler and allows cross-claim checks (duplicates, visit limits). Individual row validation provides faster feedback. Recommend batch with progressive display. |

| Version | Date | Author | Changes |
| --- | --- | --- | --- |
| 1.0 | February 12, 2026 | Ian Sharland | Initial Claim Lifecycle functional requirements |

