# Meritum_Domain_04_1_AHCIP_Claim_Pathway

MERITUM

Functional Requirements

AHCIP Claim Pathway (H-Link)

Domain 4.1 of 13  |  Critical Path: Position 4

Meritum Health Technologies Inc.

Version 1.0  |  February 2026

CONFIDENTIAL

# Table of Contents

# 1. Domain Overview

## 1.1 Purpose

The AHCIP Claim Pathway specifies how Meritum submits physician billing claims to Alberta Health via the H-Link electronic claims submission system. This is the primary revenue pathway for the vast majority of Meritum's target users — rural Alberta GPs billing fee-for-service, shadow billing (ARP), and PCPCM hybrid arrangements.

This domain covers AHCIP-specific claim data elements, the Thursday weekly batch cycle, H-Link file generation per the Electronic Claims Submission Specifications Manual, assessment response ingestion, AHCIP-specific validation rules (governing rules, modifier checks, PCPCM routing, 90-day window enforcement), and AHCIP fee calculation.

## 1.2 Scope

AHCIP claim data elements per H-Link file format specification

Thursday weekly batch cycle: cutoff, assembly, file generation, transmission

H-Link file generation: fixed-width/delimited format per Electronic Claims Submission Specifications Manual

H-Link transmission: secure channel (SFTP/API, determined during accreditation)

Assessment response ingestion: Friday response file parsing, claim matching, state transitions

AHCIP-specific validation: 19+ validation checks including governing rules, modifier eligibility, code combinations, DI surcharges, PCPCM routing, 90-day window

AHCIP fee calculation: base fee, modifier adjustments, premiums (CMGP, after-hours, surcharge, RRNP), shadow billing (ARP/TM)

AHCIP-specific API endpoints (batch management, assessment ingestion)

AHCIP billing scenario tests

## 1.3 Out of Scope

Shared claim state machine, base data model, validation architecture (Domain 4.0 Core)

WCB submission pathway (Domain 4.2)

Reference data management — SOMB schedule, governing rules (Domain 2 Reference Data)

H-Link accreditation process itself (administrative; separate from this spec)

## 1.4 Domain Dependencies

## 1.5 Relationship to Domain 4.0 and 4.2

An AHCIP claim in Meritum is a record in the shared claims table (Domain 4.0) with claim_type = 'AHCIP', linked to AHCIP-specific extension data defined in this document. The claim follows the state machine from 4.0 identically. This document specifies only the AHCIP-specific data, validation, submission, and fee logic.

# 2. AHCIP Claim Data Elements

AHCIP claims require specific data elements per the Electronic Claims Submission Specifications Manual. These elements map to H-Link file fields and are stored as an extension to the base claims table.

## 2.1 AHCIP Claim Details Table (ahcip_claim_details)

One row per AHCIP claim, linked 1:1 to the base claims table. Contains all fields required for H-Link file generation that are not already in the base claims table.

## 2.2 AHCIP Batches Table (ahcip_batches)

AHCIP batches follow the weekly Thursday cycle. Each batch groups claims for a single physician (or physician + BA combination for PCPCM dual-BA physicians).

# 3. Thursday Batch Cycle

AHCIP claims are submitted weekly on Thursdays. The batch cycle is the heartbeat of the AHCIP submission pathway.

## 3.1 Cycle Timeline

## 3.2 Batch Assembly Rules

Claims are grouped by physician_id + ba_number. A PCPCM physician with both a FFS BA and a PCPCM BA generates two separate batches.

Only claims in queued state with claim_type = 'AHCIP' are included.

Clean/flagged classification and auto-submission mode determine which claims are included (per Domain 4.0, Section 2.4).

Pre-submission validation runs one final time. Claims that fail are removed from the batch, returned to validated state, and the physician is notified.

Claims are ordered by date_of_service (ascending) within the batch file.

Each batch generates a single H-Link file with header, claim records, and trailer.

## 3.3 Late and Off-Cycle Submissions

There is no off-cycle submission for AHCIP. Claims queued after Thursday 12:00 MT are held until the following Thursday. The system displays a countdown to the next Thursday cutoff in the UI to set physician expectations.

Exception: If a batch transmission fails (network error, AHCIP downtime), the system retries automatically with exponential backoff. If all retries fail, the batch status is set to ERROR, claims remain in submitted state, and the physician/delegate is notified for manual resolution.

# 4. H-Link File Generation

Meritum generates H-Link submission files per the Electronic Claims Submission Specifications Manual. The file format is fixed-width or delimited (exact format determined during H-Link accreditation, likely AHC2210 format).

## 4.1 File Structure

The H-Link file has three sections:

File header: Submitter prefix, batch date, record count, software vendor ID, file format version.

Claim records: One record per claim. Fields ordered per H-Link specification. Each claim maps from ahcip_claim_details to the fixed-width field positions.

File trailer: Record count (verification against header), total claim value (sum of all submitted fees for integrity check).

## 4.2 Key Field Mappings

The following table maps key Meritum fields to their H-Link positions. The complete field-level mapping will be finalised during H-Link accreditation when the exact file format version is confirmed.

## 4.3 Transmission

Method: Determined during H-Link accreditation. Likely SFTP or API-based per AHCIP connectivity specification.

Credentials: H-Link submitter prefix and transmission credentials stored in secrets management system (not in database or code).

Security: Transmission via secure channel (SFTP with key-based auth or TLS 1.3 API). File content is PHI.

Logging: Transmission logged: timestamp, file reference, record count, transmission result, response code.

Retry: On transmission failure, automatic retry with exponential backoff (1 min, 5 min, 15 min, 1 hour). After 4 failures, status = ERROR and manual intervention required.

Generated files: Stored encrypted at rest (AES-256) with the batch record for audit and resubmission capability.

# 5. AHCIP Validation Rules

The AHCIP validation module is invoked by the shared validation pipeline (Domain 4.0, Section 4) when claim_type = 'AHCIP'. It runs after the shared structural checks pass. All checks reference rules from the SOMB schedule and governing rules maintained in Reference Data (Domain 2).

## 5.1 AHCIP Validation Pipeline

## 5.2 Governing Rules Overview

Governing rules (GRs) are the core of AHCIP validation. They are maintained in Reference Data (Domain 2) and referenced by HSC code. Key governing rules:

The complete governing rule set comprises 20+ rules. Each is a complex conditional tree. The full specification is maintained in Domain 2 (Reference Data). The AHCIP validation module evaluates all applicable GRs for each claim's HSC code.

# 6. AHCIP Fee Calculation

AHCIP fee calculation determines the submitted_fee for each claim. The fee is calculated from the SOMB base rate for the HSC code, modified by applicable premiums, modifiers, and adjustments.

## 6.1 Fee Formula

The general AHCIP fee formula is:

submitted_fee = base_fee × calls + modifier_adjustments + premiums

base_fee: From SOMB schedule for the HSC code, version-aware by DOS.

calls: Number of calls billed (typically 1).

modifier_adjustments: Each modifier may increase, decrease, or have no effect on the fee. Some modifiers are percentage-based (e.g., 50% reduction for assistant), some are additive.

premiums: CMGP, after-hours, RRNP, surcharge — each calculated independently and summed.

## 6.2 Modifier Fee Impact

The complete modifier fee impact matrix is maintained in Reference Data (Domain 2). The fee calculation engine applies each modifier in sequence per the SOMB-defined priority order.

## 6.3 RRNP Premium

Rural and Remote Northern Physician (RRNP) premium is an additional payment for physicians practising in qualifying communities. The rate varies by community and is set quarterly by Alberta Health.

Eligibility determined by physician's practice location (from Provider Management).

RRNP rate per claim looked up from Reference Data by community code.

Applied as a flat addition to the claim fee. Does not compound with other modifiers.

## 6.4 PCPCM Fee Routing

PCPCM (Patient's Choice Primary Care Model) physicians have dual billing arrangements: a PCPCM BA and a FFS BA. The HSC code's basket classification determines which BA the claim routes to:

In-basket codes: Route to PCPCM BA. These are capitated — the fee is paid from the PCPCM panel funding, not as individual FFS payments.

Out-of-basket codes: Route to FFS BA. Billed and paid as standard FFS claims.

The basket classification is maintained in Reference Data and may change with SOMB updates. The fee calculation engine tags each claim with pcpcm_basket_flag, and batch assembly routes to the correct BA.

## 6.5 After-Hours Calculation

After-hours premiums are determined by when the service was performed:

For ED shift workflow, the shift start/end times determine the after-hours classification automatically. For individual claims, the time of service is inferred from the claim context or manually specified.

Statutory holidays use the same 10-holiday list as WCB (Domain 4.2, Section 4.5.2) and are maintained in Reference Data.

# 7. Assessment Response Ingestion

After AHCIP processes a Thursday batch, it returns an assessment file (typically available Friday). Meritum ingests this file to update claim states.

## 7.1 Assessment File Retrieval

H-Link assessment files are received on a defined schedule (typically Friday following Thursday submission).

Meritum polls for or receives the assessment file. Retrieval method: SFTP pull or API-based per H-Link connectivity spec (determined during accreditation).

Assessment file is parsed per H-Link response format. Each record contains: original claim reference, payment status, amount paid, explanatory code(s).

## 7.2 Ingestion Workflow

Retrieve assessment file from H-Link.

Parse file per H-Link response format.

Match each record to submitted claims by submission reference.

For accepted claims: transition to assessed state, store assessed_fee.

For rejected claims: transition to rejected state, store assessment_explanatory_codes.

For adjusted claims: transition to assessed state with assessed_fee different from submitted_fee. Flag for review.

Emit notifications: CLAIM_ASSESSED, CLAIM_REJECTED per Domain 4.0 notification events.

Update batch status to RESPONSE_RECEIVED.

When payment confirmed (same Friday deposit): transition assessed claims to paid state. Batch status to RECONCILED.

## 7.3 Explanatory Codes

AHCIP returns explanatory codes for rejected and adjusted claims. These codes explain why a claim was not paid as submitted. Meritum resolves each code to a human-readable description and corrective guidance using the explanatory code lookup in Reference Data (Domain 2).

Common explanatory code categories:

Claim errors: Missing/invalid data, expired submission window, invalid HSC code

Governing rule violations: Visit limit exceeded, referral missing, bundling applied

Payment adjustments: Fee reduced per schedule, modifier disallowed, duplicate payment prevention

Administrative: Patient eligibility issue, provider status issue

The corrective guidance for each code is maintained in Reference Data. For common rejections, Meritum provides one-click corrective actions (e.g., 'Add referral practitioner' for GR 8 violations).

# 8. AHCIP API Endpoints

AHCIP-specific endpoints extend the shared API patterns defined in Domain 4.0 Core. Authentication, authorisation, and audit logging follow the same patterns. Endpoints are prefixed with /api/v1/ahcip/.

## 8.1 Batch Management

## 8.2 Assessment

## 8.3 Fee Calculation

# 9. H-Link Security

Generated H-Link submission files are encrypted at rest (AES-256) and transmitted via secure channel (SFTP with key-based auth or TLS 1.3).

H-Link credentials (submitter prefix, transmission credentials) stored in secrets management system, never in application code or database.

H-Link transmission is logged: timestamp, file reference, record count, transmission result.

Assessment response files are retrieved via secure channel and processed immediately. Raw files retained encrypted for audit.

All H-Link files contain PHI (patient PHN, DOB, diagnoses). Generated and stored on Meritum infrastructure (DigitalOcean Toronto) within Canadian data residency.

# 10. Testing Requirements

## 10.1 Validation Tests

Each AHCIP validation check (A1–A19) with positive and negative cases

Governing rule tests: representative HSC codes for each GR (GR 1, 3, 5, 8, 10, 14, 18)

Modifier eligibility: valid and invalid modifiers for representative codes

Modifier combinations: valid pairs, mutually exclusive pairs

90-day window: boundary cases (exactly 90 days, 91 days, DST transitions)

PCPCM routing: in-basket and out-of-basket codes route to correct BA

After-hours: standard, evening, weekend, stat holiday, DST transition

DI surcharge: eligible and ineligible codes, facility requirements

## 10.2 Fee Calculation Tests

Base fee calculation for representative HSC codes

Each modifier type's fee impact (TM = $0, AFHR = premium, CMGP = premium, etc.)

RRNP premium for qualifying and non-qualifying communities

PCPCM in-basket vs out-of-basket fee routing

Shadow billing: TM modifier produces $0 fee

Bundling: multiple services same patient same DOS with GR-based bundling discount

## 10.3 H-Link File Tests

File generation: output matches Electronic Claims Submission Specifications Manual format

File header: correct submitter prefix, batch date, record count

File trailer: record count matches header, total value correct

Field positioning: each field at correct offset/position in fixed-width format

Special character handling in patient names, diagnostic descriptions

Empty optional fields: correctly padded/omitted per spec

## 10.4 Assessment Ingestion Tests

Parse successful assessment: all claims matched, states updated to assessed/paid

Parse rejected assessment: explanatory codes extracted, claims matched, states updated to rejected

Adjusted claims: assessed_fee differs from submitted_fee, flagged for review

Unmatched records: graceful handling and alert

Mixed results: some accepted, some rejected, some adjusted in same batch

## 10.5 Billing Scenario Tests (End-to-End)

Each billing scenario from the PRD must be tested end-to-end through the AHCIP pathway:

FFS clinic visit with CMGP, after-hours premium, and RRNP

Shadow billing (ARP with TM modifier) — fee = $0, claim recorded

PCPCM hybrid (dual-BA routing) — in-basket to PCPCM BA, out-of-basket to FFS BA

ED shift with surcharge (13.99H), after-hours (AFHR), and CMGP

Hospital inpatient with GR 3 visit limits

Specialist consultation with GR 8 referral requirement

Obstetric delivery with multiple codes and modifiers (GR 14)

Virtual care visit

Reciprocal/out-of-province billing

Locum physician (different functional centres in same month)

Radiologist high-volume batch (50+ claims per day)

Rejected claim → correct → resubmit → paid

90-day deadline approaching → notification → submit → accepted

# 11. Open Questions

# 12. Document Control

This document specifies the AHCIP H-Link submission pathway. It should be read in conjunction with Domain 4.0 (Claim Lifecycle Core) for the shared state machine, base data model, and validation architecture, and Domain 4.2 (WCB Claim Pathway) for the WCB EIR submission pathway.

| Domain | Dependency Type | Key Interfaces |
| --- | --- | --- |
| 4.0 Claim Lifecycle Core | Parent | State machine, base claims table, validation pipeline, audit history, shared API patterns |
| 1 Identity & Access | Consumed | Auth, RBAC, delegate permissions, audit logging |
| 2 Reference Data | Consumed | SOMB schedule (HSC codes, governing rules, modifiers, fees), DI codes, functional centres, RRNP rates, stat holidays, explanatory codes |
| 3 Notification Service | Consumed | Thursday batch notifications, assessment alerts, rejection notifications, deadline reminders |
| 5 Provider Management | Consumed | Physician BA number(s), specialty, functional centres, PCPCM status, RRNP eligibility, submitter prefix |
| 6 Patient Registry | Consumed | Patient PHN, name, DOB, gender |
| 7 Intelligence Engine | Consumed | AI Coach suggestions for AHCIP-specific billing optimisation |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| ahcip_detail_id | UUID | No | Primary key |
| claim_id | UUID FK | No | FK to claims.claim_id (Domain 4.0) |
| ba_number | VARCHAR(10) | No | Business Arrangement number for this claim. Resolved from Provider Management based on PCPCM routing rules. |
| functional_centre | VARCHAR(10) | No | Functional centre code (hospital, clinic, community). Determines some governing rules. |
| health_service_code | VARCHAR(10) | No | Primary HSC code from SOMB schedule |
| modifier_1 | VARCHAR(6) | Yes | Primary modifier code (e.g., AFHR, TM, CMGP) |
| modifier_2 | VARCHAR(6) | Yes | Secondary modifier |
| modifier_3 | VARCHAR(6) | Yes | Tertiary modifier |
| diagnostic_code | VARCHAR(8) | Yes | ICD-9 diagnostic code (required for certain HSC categories) |
| facility_number | VARCHAR(10) | Yes | Facility number (required for hospital-based claims) |
| referral_practitioner | VARCHAR(10) | Yes | Referring physician billing number (required for specialist referrals per GR 8) |
| encounter_type | VARCHAR(10) | No | Consultation, follow-up, procedure, etc. per SOMB encounter definitions. |
| calls | SMALLINT | No | Number of calls (default 1). Relevant for multiple-call visit codes. |
| time_spent | SMALLINT | Yes | Time in minutes. Required for time-based HSC codes. |
| patient_location | VARCHAR(10) | Yes | Inpatient, outpatient, community, virtual, etc. |
| shadow_billing_flag | BOOLEAN | No | True for ARP claims billed with TM modifier. Shadow billed at $0 but recorded for tracking. |
| pcpcm_basket_flag | BOOLEAN | No | True if HSC is in the PCPCM basket (routes to PCPCM BA). False routes to FFS BA. |
| after_hours_flag | BOOLEAN | No | True if service was performed during after-hours (evenings, weekends, stat holidays). Auto-calculated. |
| after_hours_type | VARCHAR(20) | Yes | EVENING, WEEKEND, STAT_HOLIDAY. Determines which after-hours premium applies. |
| submitted_fee | DECIMAL(10,2) | Yes | Calculated fee at time of submission. Stored for reconciliation. |
| assessed_fee | DECIMAL(10,2) | Yes | Fee returned in assessment. Populated by assessment ingestion. |
| assessment_explanatory_codes | JSONB | Yes | Array of explanatory codes from assessment response. |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| ahcip_batch_id | UUID | No | Primary key |
| physician_id | UUID FK | No | FK to providers |
| ba_number | VARCHAR(10) | No | BA number for this batch. PCPCM physicians may have 2 batches (FFS BA + PCPCM BA). |
| batch_week | DATE | No | Thursday date for this batch cycle |
| status | VARCHAR(20) | No | ASSEMBLING, GENERATED, SUBMITTED, RESPONSE_RECEIVED, RECONCILED, ERROR |
| claim_count | INTEGER | No | Number of claims in the batch |
| total_submitted_value | DECIMAL(12,2) | No | Sum of submitted fees for all claims |
| file_path | VARCHAR(255) | Yes | Path to generated H-Link file (encrypted at rest) |
| file_hash | VARCHAR(64) | Yes | SHA-256 hash of generated file |
| submission_reference | VARCHAR(50) | Yes | H-Link submission reference for tracking |
| submitted_at | TIMESTAMPTZ | Yes | When file was transmitted to AHCIP |
| response_received_at | TIMESTAMPTZ | Yes | When assessment response was processed |
| created_at | TIMESTAMPTZ | No | Batch creation timestamp |
| created_by | UUID FK | No | Who initiated the batch (SYSTEM for auto, delegate/physician for manual) |

| Event | Details |
| --- | --- |
| Thursday 12:00 MT | Batch cutoff. All queued AHCIP claims are frozen for batch assembly. Claims queued after cutoff go into next week's batch. |
| Thursday 12:00–14:00 MT | Batch assembly window. System groups queued claims by physician + BA. Generates H-Link files. Runs final pre-submission validation. |
| Thursday 14:00+ MT | Batch transmission. H-Link files transmitted to AHCIP via secure channel. |
| Thursday evening | Submission confirmation. Physician notified that batch was transmitted with claim count and total value. |
| Friday (following) | Assessment response. AHCIP processes claims and returns assessment file. Meritum ingests and updates claim states. |
| Friday (following) | Payment. AHCIP deposits payment for assessed claims. Meritum records payment confirmation. |

| Meritum Column | H-Link Field | Notes |
| --- | --- | --- |
| ba_number | Practitioner BA# | From Provider Management, routed by PCPCM basket flag |
| patient PHN (from Patient Registry) | Patient PHN | 9-digit Alberta PHN |
| date_of_service | Service Date | YYYYMMDD format |
| health_service_code | HSC | SOMB code, version-aware |
| modifier_1 / modifier_2 / modifier_3 | Modifier fields | Up to 3 modifiers per claim |
| diagnostic_code | Diagnostic Code | ICD-9, required for certain HSC categories |
| facility_number | Facility # | Hospital/clinic facility number |
| referral_practitioner | Referring Practitioner | Required for specialist referrals (GR 8) |
| calls | Calls | Number of calls billed |
| functional_centre | Functional Centre | Determines some governing rule applicability |
| encounter_type | Encounter Type | Mapped to H-Link encounter codes |
| submitted_fee | Claimed Amount | Calculated fee amount |

| # | Check | Severity | Description |
| --- | --- | --- | --- |
| A1 | HSC Code Valid | Error | health_service_code exists in current SOMB schedule (version-aware by DOS). Cross-references Reference Data. |
| A2 | HSC Active on DOS | Error | HSC was active (not retired/added-after) on the date_of_service. SOMB codes have effective date ranges. |
| A3 | BA Number Valid | Error | ba_number is a valid, active BA for this physician. Cross-references Provider Management. |
| A4 | Governing Rules (GR) | Error | Claim satisfies all applicable governing rules for the HSC code. GRs vary by code — GR 1 (general), GR 3 (visit limits), GR 5 (diagnostic imaging), GR 8 (referrals), etc. |
| A5 | Modifier Eligibility | Error | Each modifier is valid for the HSC code and encounter context. Some modifiers are exclusive; some require specific conditions. |
| A6 | Modifier Combination | Error | Modifier combinations are valid. Some pairs are mutually exclusive (e.g., certain time modifiers cannot combine with call modifiers). |
| A7 | Diagnostic Code Required | Error | If the HSC category requires a diagnostic code, one must be present and valid in ICD-9. |
| A8 | Facility Required | Error | If encounter is hospital-based, facility_number must be present and valid. |
| A9 | Referral Required (GR 8) | Error | Specialist consultations require a referring practitioner billing number. |
| A10 | DI Surcharge Eligibility | Warning | If HSC is a DI code eligible for surcharge, validates surcharge conditions (equipment type, certification). |
| A11 | PCPCM Routing | Warning | If physician is PCPCM-enrolled, validates basket classification. In-basket codes to PCPCM BA, out-of-basket to FFS BA. |
| A12 | After-Hours Eligibility | Warning | If after_hours_flag is set, validates that the HSC code permits after-hours premium and the time qualifies. |
| A13 | 90-Day Window | Error/Warn | DOS is within 90 calendar days. Error if expired. Warning if within 7 days. |
| A14 | Time-Based Code Duration | Error | If HSC is time-based, time_spent must be present and within valid range for the code. |
| A15 | Call Count Valid | Error | calls value is within the valid range for the HSC code (typically 1 unless multiple-call code). |
| A16 | Shadow Billing Consistency | Warning | If shadow_billing_flag = true, modifier TM should be present and fee should be $0. |
| A17 | RRNP Eligibility | Info | If physician qualifies for RRNP, calculates and notes the RRNP premium amount. |
| A18 | Premium Eligibility (351) | Info | Checks if HSC is in the 351 premium code list and notes any premium conditions (AHCIP premiums are different from WCB's 2× model). |
| A19 | Bundling Check | Warning | Checks for potential bundling with other claims for same patient on same DOS. Unlike WCB (100% unbundled), AHCIP has complex bundling rules per governing rules. |

| GR | Name | Summary |
| --- | --- | --- |
| GR 1 | General | Applies to all codes. Basic requirements: valid date, valid patient, valid provider. |
| GR 3 | Visit Limits | Limits on number of visits per patient per time period. Hospital visits: typically 1/day per physician. Office visits: varies by code. |
| GR 5 | Diagnostic Imaging | Special rules for DI codes. Facility requirements, surcharge eligibility, BCP qualification. |
| GR 8 | Referrals | Specialist consultations require a valid referring practitioner. Referral must be within specified timeframe. |
| GR 10 | Surgical | Operating room codes. Anaesthesia requirements, assistant rules, post-operative visit windows. |
| GR 14 | Obstetric | Obstetric package rules. Global fee vs unbundled services. Gestational age requirements. |
| GR 18 | Chronic Disease Management | Requirements for CDM billing codes. Documentation, care plan, team-based care. |

| Modifier | Name | Fee Impact |
| --- | --- | --- |
| TM | Shadow Billing (ARP) | Fee = $0.00. Claim is recorded for panel tracking but no payment. |
| AFHR | After-Hours | Adds after-hours premium. Amount varies by HSC category and time slot (evening, weekend, holiday). |
| CMGP | Comprehensive Care | Adds CMGP premium to qualifying office visit codes. |
| LOCI | Locum | No fee impact. Identifies the claim as billed by a locum on behalf of the regular physician. |
| 13.99H | ED Surcharge | Adds emergency department surcharge for qualifying ED visits. |
| BMI | Body Mass Index | Percentage modifier for certain procedural codes based on patient BMI category. |

| Time Slot | Definition | Premium Behaviour |
| --- | --- | --- |
| Standard hours | Monday–Friday, 08:00–17:00 (excl. holidays) | No premium |
| Evening | Monday–Friday, 17:00–23:00 | Evening after-hours rate |
| Night | 23:00–08:00 any day | Night after-hours rate |
| Weekend | Saturday/Sunday full day | Weekend after-hours rate |
| Statutory holiday | 10 named Alberta statutory holidays | Stat holiday rate (highest premium) |

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/ahcip/batches | List AHCIP batches for the physician with status filtering and date range. |
| GET | /api/v1/ahcip/batches/{id} | Get batch details: status, claim count, total value, claims in batch. |
| GET | /api/v1/ahcip/batches/next | Preview next Thursday's batch: which claims will be included based on current queue and auto-submission mode. |
| POST | /api/v1/ahcip/batches/{id}/retry | Retry a failed batch transmission. Only from ERROR status. |

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/ahcip/assessments/{batch_id} | Get assessment results for a specific batch. |
| GET | /api/v1/ahcip/assessments/pending | List batches awaiting assessment response. |

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | /api/v1/ahcip/fee-calculate | Calculate fee for a claim without saving. Used for preview/estimation. |
| GET | /api/v1/ahcip/claims/{id}/fee-breakdown | Get detailed fee breakdown: base, modifiers, premiums, total. |

| # | Question | Context |
| --- | --- | --- |
| 1 | What is the exact H-Link file format version (AHC2210 or newer)? | To be confirmed during H-Link accreditation. Affects field positions and format details. |
| 2 | Is H-Link transmission SFTP-based or API-based? | Both are referenced in AHCIP documentation. Exact method determined during accreditation. |
| 3 | What is the assessment response file format and delivery mechanism? | Need exact field definitions and delivery method (push vs pull) from H-Link spec. |
| 4 | Are there H-Link test environments available for development? | Important for integration testing prior to production accreditation. |
| 5 | What is the H-Link batch size limit? | Need to confirm maximum claims per batch file for performance planning. |
| 6 | How does AHCIP handle batch resubmission for failed transmissions? | Need to confirm whether the same submission reference can be reused or must be regenerated. |
| 7 | What is the exact Thursday cutoff time recognised by AHCIP? | We use 12:00 MT as internal cutoff. Need to confirm AHCIP's actual processing window. |

| Item | Value |
| --- | --- |
| Parent document | Meritum PRD v1.3 |
| Domain | AHCIP Claim Pathway (Domain 4.1 of 13) |
| Build sequence position | 4th (sub-domain of Claim Lifecycle) |
| Dependencies | Domain 4.0 (Core), Domain 1 (IAM), Domain 2 (Reference Data), Domain 3 (Notifications) |
| Consumes | Domain 5 (Provider Mgmt), Domain 6 (Patient Registry), Domain 7 (Intelligence Engine) |
| Authoritative AHCIP reference | Electronic Claims Submission Specifications Manual, H-Link accreditation package |
| Version | 1.0 |
| Date | February 2026 |
| Next domain in critical path | Domain 5 (Provider Management) |

