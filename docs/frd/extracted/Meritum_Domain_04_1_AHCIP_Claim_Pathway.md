# Meritum_Domain_04_1_AHCIP_Claim_Pathway

MERITUM

Functional Requirements

AHCIP Claim Pathway (H-Link)

Domain 4.1 of 13  |  Critical Path: Position 4

Meritum Health Technologies Inc.

Version 2.0  |  February 2026

CONFIDENTIAL

# Table of Contents

# 1. Domain Overview

## 1.1 Purpose

The AHCIP Claim Pathway specifies how Meritum submits physician billing claims to Alberta Health via the H-Link electronic claims submission system. This is the primary revenue pathway for the vast majority of Meritum's target users — rural Alberta GPs billing fee-for-service, shadow billing (ARP), and PCPCM hybrid arrangements.

This domain covers AHCIP-specific claim data elements, the Thursday weekly batch cycle, H-Link file generation per the Electronic Claims Submission Specifications Manual, assessment response ingestion, AHCIP-specific validation rules (governing rules, modifier checks, PCPCM routing, 90-day window enforcement), and AHCIP fee calculation.

## 1.2 Scope

AHCIP claim data elements per H-Link file format specification

Thursday weekly batch cycle: cutoff, assembly, file generation, transmission

H-Link file generation: pipe-delimited format per Electronic Claims Submission Specifications Manual

H-Link transmission: secure channel (SFTP/API, determined during accreditation) with exponential backoff retry (4 attempts)

Assessment response ingestion: Friday response file parsing, claim matching, state transitions, explanatory code resolution, one-click corrective actions

AHCIP-specific validation: 19 validation checks (A1–A19) including governing rules, modifier eligibility, modifier combination exclusivity, code combinations, DI surcharges, PCPCM routing, 90-day window with dual severity (ERROR when expired, WARNING within 7 days)

AHCIP fee calculation: base fee × calls + modifier adjustments (percentage, additive, override) + premiums (CMGP, after-hours, ED surcharge, RRNP) with shadow billing override ($0.00)

After-hours auto-detection: statutory holiday check, weekend detection, time-slot classification (evening/night), ED shift time derivation

AHCIP-specific API endpoints (batch management, assessment ingestion, fee calculation/preview)

Payment reconciliation: Friday deposit confirmation, ASSESSED → PAID state transition, batch RECONCILED status

Connect Care SCC import integration: 21-field AHCIP extract format, ICD-10-CA to ICD-9 crosswalk resolution

ARP/APP shadow billing: ARP BA type labelling, S-code restrictions, TM modifier detection

Reciprocal billing: out-of-province patient claim submission with province-specific PHN validation

Mixed FFS/ARP smart routing: facility-BA mapping, time-based routing schedules

AHCIP billing scenario tests

## 1.3 Out of Scope

Shared claim state machine, base data model, validation architecture (Domain 4.0 Core)

WCB submission pathway (Domain 4.2)

Reference data management — SOMB schedule, governing rules (Domain 2 Reference Data)

H-Link accreditation process itself (administrative; separate from this spec)

## 1.4 Domain Dependencies

| Domain | Dependency Type | Key Interfaces |
| --- | --- | --- |
| 4.0 Claim Lifecycle Core | Parent | State machine, base claims table, validation pipeline, audit history, shared API patterns |
| 1 Identity & Access | Consumed | Auth, RBAC, delegate permissions, audit logging |
| 2 Reference Data | Consumed | SOMB schedule (HSC codes, governing rules, modifiers, fees), DI codes, functional centres, RRNP rates, stat holidays, explanatory codes, PCPCM basket classification, ICD crosswalk |
| 3/9 Notification Service | Consumed | Thursday batch notifications, assessment alerts, rejection notifications, deadline reminders, validation failure alerts, payment confirmation, routing mis-route summary |
| 5 Provider Management | Consumed | Physician BA number(s), BA type/subtype, specialty, functional centres, PCPCM status, RRNP eligibility, auto-submission mode, facility-BA mappings, schedule-BA mappings |
| 6 Patient Registry | Consumed | Patient PHN, name, DOB, gender, province detection for reciprocal billing |
| 7 Intelligence Engine | Consumed | AI Coach suggestions for AHCIP-specific billing optimisation |

## 1.5 Relationship to Domain 4.0 and 4.2

An AHCIP claim in Meritum is a record in the shared claims table (Domain 4.0) with claim_type = 'AHCIP', linked to AHCIP-specific extension data defined in this document. The claim follows the state machine from 4.0 identically. This document specifies only the AHCIP-specific data, validation, submission, and fee logic.

# 2. AHCIP Claim Data Elements

AHCIP claims require specific data elements per the Electronic Claims Submission Specifications Manual. These elements map to H-Link file fields and are stored as an extension to the base claims table.

## 2.1 AHCIP Claim Details Table (ahcip_claim_details)

One row per AHCIP claim, linked 1:1 to the base claims table. Contains all fields required for H-Link file generation that are not already in the base claims table. Physician scoping is enforced via JOIN to the claims table — there is no direct `physician_id` column on this table.

Defined in `packages/shared/src/schemas/db/ahcip.schema.ts`.

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| ahcip_detail_id | UUID | No | Primary key. Auto-generated (defaultRandom). |
| claim_id | UUID FK | No | FK to claims.claim_id (Domain 4.0). Unique constraint enforces 1:1 relationship. |
| ba_number | VARCHAR(10) | No | Business Arrangement number for this claim. Resolved from Provider Management based on PCPCM routing rules, facility-BA mapping, or schedule-BA mapping. |
| functional_centre | VARCHAR(10) | No | Functional centre code (hospital, clinic, community). Determines some governing rules. |
| health_service_code | VARCHAR(10) | No | Primary HSC code from SOMB schedule. |
| modifier_1 | VARCHAR(6) | Yes | Primary modifier code (e.g., AFHR, TM, CMGP). |
| modifier_2 | VARCHAR(6) | Yes | Secondary modifier. |
| modifier_3 | VARCHAR(6) | Yes | Tertiary modifier. |
| diagnostic_code | VARCHAR(8) | Yes | ICD-9 diagnostic code (required for certain HSC categories). |
| facility_number | VARCHAR(10) | Yes | Facility number (required for hospital-based claims). |
| referral_practitioner | VARCHAR(10) | Yes | Referring physician billing number (required for specialist referrals per GR 8). |
| encounter_type | VARCHAR(10) | No | Encounter type per SOMB encounter definitions. Values: CONSULTATION, FOLLOW_UP, PROCEDURE, SURGICAL, DIAGNOSTIC_IMAGING, OBSTETRIC, CDM, VIRTUAL, OTHER. |
| calls | SMALLINT | No | Number of calls (default 1). Relevant for multiple-call visit codes. |
| time_spent | SMALLINT | Yes | Time in minutes. Required for time-based HSC codes. |
| patient_location | VARCHAR(10) | Yes | Inpatient, outpatient, community, virtual, etc. |
| shadow_billing_flag | BOOLEAN | No | True for ARP claims billed with TM modifier. Shadow billed at $0.00 but recorded for tracking. Auto-detected from TM modifier in any of the three modifier slots. Default false. |
| pcpcm_basket_flag | BOOLEAN | No | True if HSC is in the PCPCM basket (routes to PCPCM BA). Derived from Reference Data basket classification and Provider Management routing result, not from user input. Default false. |
| after_hours_flag | BOOLEAN | No | True if service was performed during after-hours (evenings, weekends, stat holidays). Auto-calculated from date/time context. Default false. |
| after_hours_type | VARCHAR(20) | Yes | EVENING, WEEKEND, NIGHT, STAT_HOLIDAY. Determines which after-hours premium applies. |
| submitted_fee | DECIMAL(10,2) | Yes | Calculated fee at time of submission. Stored for reconciliation. Shadow billing claims store $0.00. |
| assessed_fee | DECIMAL(10,2) | Yes | Fee returned in assessment. Populated by assessment ingestion. |
| assessment_explanatory_codes | JSONB | Yes | Array of resolved explanatory codes from assessment response. Each entry contains code, description, category, and corrective guidance. |

**Indexes:**
- Unique index on `claim_id` (enforces 1:1 relationship).
- Composite index on `(ba_number, health_service_code)` for batch assembly and reporting queries.
- Index on `pcpcm_basket_flag` for PCPCM routing queries.

## 2.2 AHCIP Batches Table (ahcip_batches)

AHCIP batches follow the weekly Thursday cycle. Each batch groups claims for a single physician + BA number combination. A PCPCM physician with both a FFS BA and a PCPCM BA generates two separate batches per week.

Defined in `packages/shared/src/schemas/db/ahcip.schema.ts`.

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| ahcip_batch_id | UUID | No | Primary key. Auto-generated (defaultRandom). |
| physician_id | UUID FK | No | FK to providers.provider_id. |
| ba_number | VARCHAR(10) | No | BA number for this batch. PCPCM physicians may have 2 batches (FFS BA + PCPCM BA). |
| batch_week | DATE | No | Thursday date for this batch cycle. Stored as string mode. |
| status | VARCHAR(20) | No | ASSEMBLING, GENERATED, SUBMITTED, RESPONSE_RECEIVED, RECONCILED, ERROR. |
| claim_count | INTEGER | No | Number of claims in the batch. |
| total_submitted_value | DECIMAL(12,2) | No | Sum of submitted fees for all claims. |
| file_path | VARCHAR(255) | Yes | Path to generated H-Link file (encrypted at rest via AES-256). |
| file_hash | VARCHAR(64) | Yes | SHA-256 hash of generated file (first 16 hex characters used for trailer checksum). |
| submission_reference | VARCHAR(50) | Yes | H-Link submission reference for tracking. |
| submitted_at | TIMESTAMPTZ | Yes | When file was transmitted to AHCIP. |
| response_received_at | TIMESTAMPTZ | Yes | When assessment response was processed. |
| created_at | TIMESTAMPTZ | No | Batch creation timestamp. Default now(). |
| created_by | UUID FK | No | Who initiated the batch (SYSTEM for auto, delegate/physician for manual). FK to users.user_id. |

**Indexes:**
- Composite index on `(physician_id, batch_week)` for dashboard and batch history.
- Index on `status` for batch lifecycle queries.
- Unique index on `(physician_id, ba_number, batch_week)` preventing duplicate batches per physician + BA + week.

# 3. Thursday Batch Cycle

AHCIP claims are submitted weekly on Thursdays. The batch cycle is the heartbeat of the AHCIP submission pathway.

## 3.1 Cycle Timeline

| Event | Details |
| --- | --- |
| Thursday 12:00 MT | Batch cutoff. All queued AHCIP claims are frozen for batch assembly. Claims queued after cutoff go into next week's batch. |
| Thursday 12:00–14:00 MT | Batch assembly window. System groups queued claims by physician + BA. Runs final pre-submission validation. Calculates fees for each valid claim. Generates H-Link files. |
| Thursday 14:00+ MT | Batch transmission. H-Link files transmitted to AHCIP via secure channel. |
| Thursday evening | Submission confirmation. Physician notified that batch was transmitted with claim count and total value (BATCH_ASSEMBLED event). |
| Friday (following) | Assessment response. AHCIP processes claims and returns assessment file. Meritum ingests and updates claim states. |
| Friday (following) | Payment. AHCIP deposits payment for assessed claims. Meritum reconciles payment and transitions ASSESSED claims to PAID. Batch status set to RECONCILED. |

**Batch cycle constants** (defined in `packages/shared/src/constants/ahcip.constants.ts`):
- `BATCH_CUTOFF_DAY = 4` (Thursday, per JS Date.getDay() convention).
- `BATCH_CUTOFF_HOUR = 12` (12:00 MT).

## 3.2 Batch Assembly Rules

The `assembleBatch` service function orchestrates batch assembly:

1. **Auto-submission mode check.** The physician's auto-submission preference is retrieved from Provider Management:
   - `AUTO_CLEAN`: Only claims flagged as clean are included.
   - `AUTO_ALL`: All queued AHCIP claims are included (clean and flagged).
   - `REQUIRE_APPROVAL`: Physician must explicitly approve — batch assembly skips this physician.

2. **Grouping.** Claims are grouped by physician_id + ba_number. A PCPCM physician with both a FFS BA and a PCPCM BA generates two separate batches.

3. **Claim selection.** Only claims in QUEUED state with claim_type = 'AHCIP' are candidates. Filtered by BA number and optional isClean flag based on auto-submission mode.

4. **Pre-submission validation.** Each claim undergoes final validation via the BatchValidationRunner (combined shared S1–S7 and AHCIP-specific A1–A19 checks). Claims that fail are:
   - Returned to VALIDATED state via the ClaimStateService.
   - Removed from the batch.
   - The physician is notified via a CLAIM_VALIDATION_FAILED_PRE_BATCH event.

5. **Fee calculation.** Each passing claim has its fee computed via the fee engine (Section 6) and persisted to `submitted_fee`.

6. **Batch record creation.** An `ahcip_batches` record is created with status ASSEMBLING, claim count, and total submitted value.

7. **Claim linking.** Claims are linked to the batch by setting `submitted_batch_id` on the base claims table.

8. **State transition.** Each valid claim is transitioned from QUEUED to SUBMITTED.

9. **Notification.** A BATCH_ASSEMBLED event is emitted with batch details (per-BA counts and totals) and the count of removed claims.

Claims are ordered by date_of_service (ascending) within the batch file.

## 3.3 Late and Off-Cycle Submissions

There is no off-cycle submission for AHCIP. Claims queued after Thursday 12:00 MT are held until the following Thursday. The system displays a countdown to the next Thursday cutoff in the UI to set physician expectations. The `getNextThursday` function computes the next batch date.

Exception: If a batch transmission fails (network error, AHCIP downtime), the system retries automatically with exponential backoff. If all retries fail, the batch status is set to ERROR, claims remain in SUBMITTED state, and the physician is notified via a BATCH_TRANSMISSION_FAILED event for manual resolution.

# 4. H-Link File Generation

Meritum generates H-Link submission files per the Electronic Claims Submission Specifications Manual. The implemented format is pipe-delimited.

## 4.1 File Structure

The H-Link file has three sections:

**Header** (`formatHlinkHeader`):
```
H|{submitter_prefix}|{batch_date}|{record_count_padded_6}|{vendor_id}
```
- `submitter_prefix`: From HLINK_SUBMITTER_PREFIX environment variable (default: 'MERITUM').
- `batch_date`: The batch_week date (Thursday's date, YYYY-MM-DD).
- `record_count`: Zero-padded to 6 digits.
- `vendor_id`: 'MERITUM_V1'.

**Claim records** (`formatHlinkClaimRecord`):
```
C|{ba_number}|{hsc_code}|{dos}|{mod1}|{mod2}|{mod3}|{diag}|{facility}|{referral}|{calls}|{time}|{fee}
```
One record per claim, ordered by date_of_service ascending. Optional fields are empty strings when null.

**Trailer** (`formatHlinkTrailer`):
```
T|{record_count_padded_6}|{total_value}|{checksum}
```
- `record_count`: Matches header count (verification).
- `total_value`: Sum of all submitted fees formatted as decimal string.
- `checksum`: SHA-256 hash of header + all records concatenated with newlines, truncated to first 16 hex characters.

## 4.2 Key Field Mappings

| Meritum Column | H-Link Field | Notes |
| --- | --- | --- |
| ba_number | Practitioner BA# | From Provider Management, routed by PCPCM basket flag, facility-BA mapping, or schedule-BA mapping |
| patient PHN (from Patient Registry) | Patient PHN | 9-digit Alberta PHN (or out-of-province health number for reciprocal billing) |
| date_of_service | Service Date | YYYY-MM-DD format |
| health_service_code | HSC | SOMB code, version-aware |
| modifier_1 / modifier_2 / modifier_3 | Modifier fields | Up to 3 modifiers per claim |
| diagnostic_code | Diagnostic Code | ICD-9, required for certain HSC categories |
| facility_number | Facility # | Hospital/clinic facility number |
| referral_practitioner | Referring Practitioner | Required for specialist referrals (GR 8) |
| calls | Calls | Number of calls billed |
| functional_centre | Functional Centre | Determines some governing rule applicability |
| encounter_type | Encounter Type | Mapped to H-Link encounter codes |
| submitted_fee | Claimed Amount | Calculated fee amount |

## 4.3 File Generation Process

The `generateHlinkFile` service function performs file generation:

1. Verify batch ownership (physician scoping) and status (must be ASSEMBLING).
2. Fetch linked claims for the batch, filtered by BA number and submitted_batch_id match.
3. Sort claims by date_of_service ascending.
4. Generate header, claim records, and trailer.
5. Compute SHA-256 checksum of header + records for trailer integrity verification.
6. Encrypt file content via AES-256 and store to file system (via FileEncryptionService).
7. Update batch status to GENERATED with file_path and file_hash.
8. Return structured file content (header, records, trailer, raw buffer).

File naming convention: `hlink_{ba_number}_{batch_date}_{batch_id}.dat`

## 4.4 Transmission

The `transmitBatch` service function handles H-Link transmission:

**Method:** Determined during H-Link accreditation. Abstracted behind an `HlinkTransmissionService` interface supporting SFTP or API-based channels.

**Credentials:** H-Link submitter prefix and transmission credentials stored in environment variables (HLINK_SUBMITTER_PREFIX, HLINK_CREDENTIAL_ID, HLINK_CREDENTIAL_SECRET), never in database or code.

**Security:** Transmission via secure channel (SFTP with key-based auth or TLS 1.3 API). File content is PHI.

**Logging:** Transmission logged: timestamp, file reference, record count, transmission result, response code.

**Retry:** On transmission failure, automatic retry with exponential backoff: 60s, 300s, 900s, 3600s (`BATCH_RETRY_INTERVALS_S`). Maximum 4 attempts (`BATCH_MAX_RETRIES`). After 4 failures, status = ERROR and a BATCH_TRANSMISSION_FAILED notification is emitted for manual intervention.

**Retry of ERROR batches:** The `retryFailedBatch` service function resets an ERROR batch to GENERATED status and re-invokes `transmitBatch`. Only batches in ERROR status can be retried.

**Transmit state flow:**
- GENERATED or ERROR → attempt transmission → success: SUBMITTED (with submitted_at and submission_reference)
- GENERATED or ERROR → all retries exhausted → ERROR

**Generated files:** Stored encrypted at rest (AES-256) with the batch record for audit and resubmission capability.

# 5. AHCIP Validation Rules

The AHCIP validation module is invoked by the shared validation pipeline (Domain 4.0, Section 4) when claim_type = 'AHCIP'. It runs after the shared structural checks pass. All checks reference rules from the SOMB schedule and governing rules maintained in Reference Data (Domain 2).

## 5.1 AHCIP Validation Pipeline

The `validateAhcipClaim` service function implements the AHCIP-specific validation pipeline. It receives an `AhcipClaimForValidation` object and returns `AhcipValidationResult` containing validation entries and the Reference Data version for audit traceability.

**Validation flow:**
1. Fetch reference data context (version-aware by DOS) in parallel: HSC detail, applicable modifiers, applicable governing rules, reference data version.
2. If HSC code is not found (A1 fails), return immediately — most subsequent checks require a valid HSC code.
3. Execute checks A2–A19 sequentially, collecting validation entries.
4. Return all entries with the reference data version string.

**Dependency interfaces for validation:**
- `AhcipValidationRefData`: Version-aware HSC code, modifier, and governing rule lookups from Reference Data.
- `AhcipValidationProviderService`: BA validation and RRNP eligibility checks from Provider Management.
- `AhcipValidationClaimLookup`: Same-patient same-DOS claim lookup for bundling checks.

**Validation check configuration** is defined in `packages/shared/src/constants/ahcip.constants.ts` as `AHCIP_VALIDATION_CHECKS`, mapping each check ID to its default severity and description.

## 5.2 Validation Checks (A1–A19)

| # | Check | Severity | Description | Implementation |
| --- | --- | --- | --- | --- |
| A1 | HSC Code Valid | Error | health_service_code exists in current SOMB schedule (version-aware by DOS). Cross-references Reference Data. | Returns immediately if HSC not found — subsequent checks require a valid HSC. |
| A2 | HSC Active on DOS | Error | HSC was active (not retired/added-after) on the date_of_service. SOMB codes have effective date ranges. | Checks `hscDetail.isActive`. |
| A3 | BA Number Valid | Error | ba_number is a valid, active BA for this physician. Cross-references Provider Management. | Calls `providerService.validateBa()`. |
| A4 | Governing Rules (GR) | Error | Claim satisfies all applicable governing rules for the HSC code. GRs vary by code — GR 1 (general), GR 3 (visit limits), GR 5 (DI), GR 8 (referrals), etc. | Iterates all applicable rules via `evaluateGoverningRule()`. |
| A5 | Modifier Eligibility | Error | Each modifier is valid for the HSC code and encounter context. Some modifiers are exclusive; some require specific conditions. | Checks each modifier against `applicableModifiers` set. |
| A6 | Modifier Combination | Error | Modifier combinations are valid. Some pairs are mutually exclusive. | Checks `exclusiveWith` arrays via `checkModifierCombinations()`. Only runs when 2+ modifiers present. |
| A7 | Diagnostic Code Required | Error | If the HSC category requires a diagnostic code, one must be present and valid in ICD-9. | Checks `hscDetail.requiresDiagnosticCode`. |
| A8 | Facility Required | Error | If encounter is hospital-based, facility_number must be present and valid. | Checks `hscDetail.requiresFacility`. |
| A9 | Referral Required (GR 8) | Error | Specialist consultations require a referring practitioner billing number. | Checks `hscDetail.requiresReferral`. |
| A10 | DI Surcharge Eligibility | Warning | If HSC is a DI code eligible for surcharge, validates surcharge conditions (equipment type, certification). | Checks `hscDetail.surchargeEligible`. |
| A11 | PCPCM Routing | Warning | If physician is PCPCM-enrolled, validates basket classification. In-basket codes to PCPCM BA, out-of-basket to FFS BA. | Compares `hscDetail.pcpcmBasket` against `claim.pcpcmBasketFlag`. |
| A12 | After-Hours Eligibility | Warning | If after_hours_flag is set, validates that the HSC code permits after-hours premium and the time qualifies. | Checks `hscDetail.afterHoursEligible` when `claim.afterHoursFlag` is set. |
| A13 | 90-Day Window | Error/Warn | DOS is within 90 calendar days. Error if expired. Warning if within 7 days (`DEADLINE_WARNING_DAYS`). | Computes days remaining from `claim.submissionDeadline`. Dual severity: ERROR when past deadline, WARNING when ≤ 7 days remain. |
| A14 | Time-Based Code Duration | Error | If HSC is time-based, time_spent must be present and within valid range (minTime–maxTime) for the code. | Checks `hscDetail.isTimeBased`, validates against `hscDetail.minTime` and `hscDetail.maxTime`. |
| A15 | Call Count Valid | Error | calls value is within the valid range (minCalls–maxCalls) for the HSC code (typically 1 unless multiple-call code). | Validates against `hscDetail.minCalls` and `hscDetail.maxCalls`. |
| A16 | Shadow Billing Consistency | Warning | If shadow_billing_flag = true, modifier TM should be present and fee should be $0. Conversely, if TM modifier is present, shadow_billing_flag should be set. | Checks bidirectional consistency between `shadowBillingFlag` and TM modifier presence. |
| A17 | RRNP Eligibility | Info | If physician qualifies for RRNP, calculates and notes the RRNP premium amount. | Calls `providerService.isRrnpEligible()`. |
| A18 | Premium Eligibility (351) | Info | Checks if HSC is in the 351 premium code list and notes any premium conditions. | Checks `hscDetail.premium351Eligible`. |
| A19 | Bundling Check | Warning | Checks for potential bundling with other claims for same patient on same DOS. Unlike WCB (100% unbundled), AHCIP has complex bundling rules per governing rules. | Calls `claimLookup.findClaimsForPatientOnDate()` and reports matching claims. |

## 5.3 Governing Rules Overview

Governing rules (GRs) are the core of AHCIP validation. They are maintained in Reference Data (Domain 2) and referenced by HSC code. The `evaluateGoverningRule` function evaluates each rule's `ruleLogic` JSON against the claim.

| GR | Name | Summary | Rule Logic Keys |
| --- | --- | --- | --- |
| GR 1 | General | Applies to all codes. Basic requirements: valid date, valid patient, valid provider. | — |
| GR 3 | Visit Limits | Limits on number of visits per patient per time period. Hospital visits: typically 1/day per physician. Office visits: varies by code. | `maxVisitsPerDay` |
| GR 5 | Diagnostic Imaging | Special rules for DI codes. Facility requirements, surcharge eligibility, BCP qualification. | `requiresFacility` |
| GR 8 | Referrals | Specialist consultations require a valid referring practitioner. Referral must be within specified timeframe. | `requiresReferral` |
| GR 10 | Surgical | Operating room codes. Anaesthesia requirements, assistant rules, post-operative visit windows. | `requiresTimeDocumentation` |
| GR 14 | Obstetric | Obstetric package rules. Global fee vs unbundled services. Gestational age requirements. | `maxCallsPerEncounter` |
| GR 18 | Chronic Disease Management | Requirements for CDM billing codes. Documentation, care plan, team-based care. | — |

The complete governing rule set comprises 20+ rules. Each is a complex conditional tree. The full specification is maintained in Domain 2 (Reference Data). The AHCIP validation module evaluates all applicable GRs for each claim's HSC code.

## 5.4 Validation Entry Format

Each validation finding is returned as a `ValidationEntry`:

```typescript
interface ValidationEntry {
  check: string;          // Check ID (e.g., 'A1_HSC_CODE_VALID')
  severity: 'ERROR' | 'WARNING' | 'INFO';
  rule_reference: string; // FRD reference (e.g., 'FRD 4.1 S5.1 A1')
  message: string;        // Human-readable description
  help_text: string;      // Corrective guidance
  field_affected?: string; // Which field(s) triggered the finding
}
```

# 6. AHCIP Fee Calculation

AHCIP fee calculation determines the submitted_fee for each claim. The fee is calculated from the SOMB base rate for the HSC code, modified by applicable premiums, modifiers, and adjustments.

## 6.1 Fee Formula

The general AHCIP fee formula, implemented in `computeFeeBreakdown`:

```
submitted_fee = (base_fee × calls) + modifier_adjustments + premiums + rrnp_premium
```

- **base_fee**: From SOMB schedule for the HSC code, version-aware by DOS. Fetched via `FeeReferenceDataService.getHscDetail()`.
- **calls**: Number of calls billed (default 1, per `DEFAULT_CALL_COUNT` constant).
- **modifier_adjustments**: Applied in SOMB-defined priority order. Each modifier has a `calculationMethod` and `value`:
  - `PERCENTAGE`: `amount = base_fee × value` (e.g., 0.15 for 15%).
  - `ADDITIVE`: `amount = value` (flat dollar amount added).
  - `OVERRIDE`: `amount = value - base_fee` (replaces the base fee).
- **premiums**: CMGP, after-hours, ED surcharge — each calculated independently and summed.
- **rrnp_premium**: Flat addition based on physician eligibility and community code.
- **Minimum**: Total is floored at $0.00 (non-negative).

**Shadow billing override:** If `shadowBillingFlag = true`, the total fee is forced to `$0.00` (`SHADOW_BILLING_FEE` constant). The full breakdown is still computed for tracking purposes.

All calculations use string-based decimal representation for money (`parseDecimal` / `formatDecimal`), formatted to 2 decimal places.

## 6.2 Modifier Fee Impact

Modifiers are processed by `computeModifierAdjustments`. The TM modifier is skipped (handled by shadow billing override). The AFHR modifier is skipped (handled as a premium, not a modifier adjustment). All other modifiers are fetched via `FeeReferenceDataService.getModifierFeeImpact()` and sorted by SOMB-defined priority order (lower priority number = applied first).

**Well-known modifier codes** (defined in `packages/shared/src/constants/ahcip.constants.ts` as `AhcipModifierCode`):

| Modifier | Name | Fee Impact |
| --- | --- | --- |
| TM | Shadow Billing (ARP) | Fee = $0.00. Claim is recorded for panel tracking but no payment. |
| AFHR | After-Hours | Adds after-hours premium. Amount varies by HSC category and time slot (evening, weekend, night, holiday). |
| CMGP | Comprehensive Care | Adds CMGP premium to qualifying office visit codes. |
| LOCI | Locum | No fee impact. Identifies the claim as billed by a locum on behalf of the regular physician. |
| 13.99H | ED Surcharge | Adds emergency department surcharge for qualifying ED visits. |
| BMI | Body Mass Index | Percentage modifier for certain procedural codes based on patient BMI category. |

## 6.3 Premiums

Premiums are computed by `computePremiums` independently of modifier adjustments:

**CMGP premium:** Applied when the CMGP modifier is present. Amount fetched from `FeeReferenceDataService.getCmgpPremium()` for the HSC code and DOS.

**After-hours premium:** Applied when `afterHoursFlag = true`, `afterHoursType` is set, and the HSC code is eligible (`hscDetail.afterHoursEligible`). Amount fetched from `FeeReferenceDataService.getAfterHoursPremium()` parameterised by HSC code, after-hours type, and DOS. Premium type recorded as `AFTER_HOURS_{type}` (e.g., AFTER_HOURS_EVENING).

**ED surcharge (13.99H):** Applied when the 13.99H modifier is present and the HSC code is surcharge-eligible (`hscDetail.surchargeEligible`). Amount fetched from `FeeReferenceDataService.getEdSurcharge()`.

## 6.4 RRNP Premium

Rural and Remote Northern Physician (RRNP) premium is computed separately by `computeRrnpPremium`:

1. Check physician eligibility via `FeeProviderService.isRrnpEligible()`.
2. If eligible, look up the premium rate via `FeeReferenceDataService.getRrnpPremium()` parameterised by physician ID (for community code) and DOS.
3. Applied as a flat addition to the claim fee. Does not compound with other modifiers.

## 6.5 PCPCM Fee Routing

PCPCM (Patient's Choice Primary Care Model) physicians have dual billing arrangements: a PCPCM BA and a FFS BA. The HSC code's basket classification determines which BA the claim routes to:

- **In-basket codes** (`routing_reason = 'IN_BASKET'`): Route to PCPCM BA. These are capitated — the fee is paid from the PCPCM panel funding, not as individual FFS payments.
- **Out-of-basket codes** (`routing_reason = 'OUT_OF_BASKET'`): Route to FFS BA. Billed and paid as standard FFS claims.

The basket classification is derived from Provider Management's `routeClaimToBa()` method, which consults Reference Data's PCPCM basket classification. The `pcpcmBasketFlag` is set automatically during claim creation based on the routing result. Batch assembly routes to the correct BA via the `ba_number` stored on the AHCIP detail.

## 6.6 After-Hours Detection

After-hours detection is performed automatically by the `resolveAfterHours` function during claim creation. The detection follows a priority chain:

1. **Statutory holiday check** (highest priority): Calls `ReferenceDataService.isHoliday()` for the date of service. If the date is a statutory holiday, the entire day is classified as `STAT_HOLIDAY` after-hours. Alberta's 10 named statutory holidays are: New Year's Day, Family Day, Good Friday, Victoria Day, Canada Day, Heritage Day, Labour Day, Thanksgiving Day, Remembrance Day, Christmas Day.

2. **Weekend check**: If the day of week is Saturday (6) or Sunday (0), classified as `WEEKEND` after-hours.

3. **Time-based classification** (if service time available): The `classifyHour` function classifies based on Mountain Time hour boundaries:

| Time Slot | Definition | Premium Behaviour |
| --- | --- | --- |
| Standard hours | Monday–Friday, 08:00–17:00 (excl. holidays) | No premium |
| Evening | Monday–Friday, 17:00–23:00 | Evening after-hours rate |
| Night | 23:00–08:00 any day | Night after-hours rate |
| Weekend | Saturday/Sunday full day | Weekend after-hours rate |
| Statutory holiday | 10 named Alberta statutory holidays | Stat holiday rate (highest premium) |

**Time slot boundary constants** (defined in `packages/shared/src/constants/ahcip.constants.ts`):
- `STANDARD_HOURS_START = 8` (08:00 MT)
- `STANDARD_HOURS_END = 17` (17:00 MT)
- `EVENING_HOURS_END = 23` (23:00 MT)

**ED shift derivation:** For ED shift claims, the `resolveAfterHoursFromShift` function uses the shift's `start_time` to determine the after-hours classification, since the shift start represents when the physician began the service. Applies the same holiday → weekend → time-slot priority chain.

4. **No time context available**: If no service time or shift context is available, after-hours defaults to false.

## 6.7 Fee Breakdown Response

The fee calculation returns a structured `FeeBreakdown` object:

```typescript
interface FeeBreakdown {
  base_fee: string;                    // SOMB base fee (e.g., "85.00")
  calls: number;                       // Call count
  modifier_adjustments: Array<{
    modifier: string;                  // Modifier code
    effect: string;                    // Description (e.g., "15% of base fee")
    amount: string;                    // Dollar adjustment
  }>;
  premiums: Array<{
    type: string;                      // Premium type (e.g., "CMGP", "AFTER_HOURS_EVENING")
    amount: string;                    // Dollar amount
  }>;
  rrnp_premium: string | null;        // RRNP flat premium or null
  total_fee: string;                   // Final calculated fee
}
```

# 7. Assessment Response Ingestion

After AHCIP processes a Thursday batch, it returns an assessment file (typically available Friday). Meritum ingests this file to update claim states.

## 7.1 Assessment File Format

The assessment response file mirrors the submission format with pipe-delimited records:

**Header:**
```
H|{submission_reference}|{batch_date}|{record_count}
```

**Records:**
```
R|{claim_reference}|{status}|{assessed_fee}|{explanatory_code1;code2;...}
```
- `status`: ACCEPTED, REJECTED, or ADJUSTED.
- `assessed_fee`: Fee as assessed by AHCIP.
- `explanatory_codes`: Semicolon-delimited codes, present for rejected/adjusted claims.

**Trailer:**
```
T|{record_count}|{total_assessed_value}
```

The `parseAssessmentFile` function parses raw file content into a `ParsedAssessmentFile` structure.

## 7.2 Assessment File Retrieval

H-Link assessment files are received on a defined schedule (typically Friday following Thursday submission).

Meritum retrieves the assessment file via the `HlinkAssessmentRetrievalService` interface (SFTP pull or API-based per H-Link connectivity spec). The raw file is stored encrypted for audit before processing.

## 7.3 Ingestion Workflow

The `ingestAssessmentFile` service function orchestrates ingestion:

1. Verify batch exists and is in SUBMITTED status (physician-scoped).
2. Retrieve assessment file from H-Link via secure channel.
3. Store raw file encrypted for audit trail (filename: `assessment_{batchId}_{timestamp}.dat`).
4. Parse file per H-Link response format.
5. Match each record to submitted claims by claim reference (physician-scoped via repository).
6. Process each record via `processAssessmentRecord`:
   - **Accepted claims:** Transition SUBMITTED → ASSESSED, store assessed_fee and resolved explanatory codes.
   - **Rejected claims:** Transition SUBMITTED → REJECTED, store explanatory codes, emit CLAIM_REJECTED notification with corrective actions.
   - **Adjusted claims:** Transition SUBMITTED → ASSESSED with assessed_fee different from submitted_fee. Emit CLAIM_ASSESSED notification with `isAdjusted = true` and explanatory codes.
7. Track unmatched records (no matching submitted claim found) — logged for manual resolution. No silent data loss.
8. Update batch status to RESPONSE_RECEIVED with response_received_at timestamp.

**Ingestion result:**
```typescript
interface AssessmentIngestionResult {
  batchId: string;
  totalRecords: number;
  accepted: number;
  rejected: number;
  adjusted: number;
  unmatched: number;
  unmatchedRecords: Array<{ claimReference: string; reason: string }>;
  results: AssessmentRecordResult[];
}
```

## 7.4 Explanatory Codes

AHCIP returns explanatory codes for rejected and adjusted claims. These codes explain why a claim was not paid as submitted. Meritum resolves each code to a human-readable description and corrective guidance using the `ExplanatoryCodeService` interface backed by Reference Data (Domain 2).

**Resolved explanatory code structure:**
```typescript
interface ResolvedExplanatoryCode {
  code: string;             // Raw AHCIP explanatory code
  description: string;      // Human-readable description
  category: string;         // Category (e.g., MISSING_REFERRAL, INVALID_HSC)
  correctiveGuidance: string | null;  // Guidance text
}
```

Unknown codes are still recorded with `category: 'UNKNOWN'` and a default description.

Common explanatory code categories:

- **Claim errors:** Missing/invalid data, expired submission window, invalid HSC code
- **Governing rule violations:** Visit limit exceeded, referral missing, bundling applied
- **Payment adjustments:** Fee reduced per schedule, modifier disallowed, duplicate payment prevention
- **Administrative:** Patient eligibility issue, provider status issue

## 7.5 One-Click Corrective Actions

For common rejections, Meritum generates one-click corrective actions via `generateCorrectiveActions`. Each action maps an explanatory code category to a specific fix:

| Category | Action Type | Label | Field | Description |
| --- | --- | --- | --- | --- |
| MISSING_REFERRAL | ADD_REFERRAL | Add referring practitioner | referral_practitioner | Add the referring practitioner billing number to satisfy GR 8. |
| MISSING_DIAGNOSTIC | ADD_DIAGNOSTIC_CODE | Add diagnostic code | diagnostic_code | Add a valid ICD-9 diagnostic code for this service. |
| MISSING_FACILITY | ADD_FACILITY | Add facility number | facility_number | Add the facility number where the service was provided. |
| INVALID_HSC | UPDATE_HSC | Update service code | health_service_code | The HSC code was rejected. Review and update the service code. |
| EXPIRED_SUBMISSION | WRITE_OFF | Write off claim | state | The submission window has expired. Consider writing off this claim. |
| DUPLICATE_CLAIM | REVIEW_DUPLICATE | Review duplicate | claim_id | This claim was flagged as a duplicate. Review and resolve. |

## 7.6 Payment Reconciliation

When Friday deposit is confirmed, the `reconcilePayment` service function completes the cycle:

1. Verify batch exists and is in RESPONSE_RECEIVED status (physician-scoped).
2. Find all claims linked to the batch (any state).
3. Transition each claim in ASSESSED state to PAID (terminal state).
4. Emit CLAIM_PAID notification for each reconciled claim.
5. Update batch status to RECONCILED.

Returns the count of reconciled claims.

# 8. AHCIP Claim Creation

The `createAhcipClaim` service function orchestrates AHCIP claim creation:

1. **Create base claim** via Domain 4.0 createClaim (state = DRAFT, claim_type = 'AHCIP').
2. **Resolve BA number** via Provider Management's `routeClaimToBa()`. The physician cannot specify an arbitrary BA — it is resolved from:
   - Service code type (ARP S-code → ARP BA)
   - Facility code mapping (claim facility → ba_facility_mappings)
   - Schedule mapping (date/time → ba_schedule_mappings)
   - Primary BA fallback
3. **Determine pcpcm_basket_flag** from the routing result (`routing_reason === 'IN_BASKET'`).
4. **Detect shadow billing** from TM modifier. If any of modifier_1, modifier_2, or modifier_3 equals 'TM', `shadowBillingFlag = true` and fee is set to $0.00.
5. **Auto-detect after-hours** via `resolveAfterHours()` using date of service, optional service time, and holiday calendar.
6. **Calculate submission deadline** = DOS + 90 calendar days (`AHCIP_DEADLINE_DAYS`).
7. **Determine submitted fee**: Shadow billing overrides to $0.00; otherwise uses provided fee or null for later calculation.
8. **Create AHCIP extension row** in ahcip_claim_details with all resolved fields.

**Security:**
- BA resolution comes from Provider Management — physician cannot specify arbitrary BA.
- pcpcm_basket_flag derived from Reference Data, not user input.
- Shadow billing detection is automatic from TM modifier.

**Input types:**
- `CreateClaimInput`: claimType, patientId, dateOfService, importSource.
- `CreateAhcipDetailInput`: healthServiceCode, functionalCentre, encounterType, modifiers, diagnosticCode, facilityNumber, referralPractitioner, calls, timeSpent, patientLocation, submittedFee, serviceTime.

# 9. AHCIP API Endpoints

AHCIP-specific endpoints extend the shared API patterns defined in Domain 4.0 Core. Authentication, authorisation, and audit logging follow the same patterns. Endpoints are prefixed with `/api/v1/ahcip/`.

All routes are defined in `apps/api/src/domains/ahcip/ahcip.routes.ts`.

## 9.1 Batch Management

| Method | Endpoint | Permission | Schema | Description |
| --- | --- | --- | --- | --- |
| GET | /api/v1/ahcip/batches | CLAIM_VIEW | querystring: `listBatchesSchema` | List AHCIP batches for the physician with status filtering and date range. Paginated. |
| GET | /api/v1/ahcip/batches/next | CLAIM_VIEW | — | Preview next Thursday's batch: which claims will be included based on current queue and auto-submission mode. |
| GET | /api/v1/ahcip/batches/:id | CLAIM_VIEW | params: `batchIdParamSchema` (UUID) | Get batch details: status, claim count, total value, claims in batch. Returns 404 if not found or wrong physician. |
| POST | /api/v1/ahcip/batches/:id/retry | CLAIM_SUBMIT | params: `batchIdParamSchema` (UUID) | Retry a failed batch transmission. Only from ERROR status. Returns 409 if batch is not in ERROR status. |

## 9.2 Assessment

| Method | Endpoint | Permission | Schema | Description |
| --- | --- | --- | --- | --- |
| GET | /api/v1/ahcip/assessments/pending | CLAIM_VIEW | — | List batches awaiting assessment response (SUBMITTED status). |
| GET | /api/v1/ahcip/assessments/:batch_id | CLAIM_VIEW | params: `batchAssessmentParamSchema` (UUID) | Get assessment results for a specific batch: per-claim status, fees, explanatory codes, corrective actions. |

## 9.3 Fee Calculation

| Method | Endpoint | Permission | Schema | Description |
| --- | --- | --- | --- | --- |
| POST | /api/v1/ahcip/fee-calculate | CLAIM_VIEW | body: `feeCalculateSchema` | Calculate fee for a claim without saving. Used for preview/estimation. Requires health_service_code, functional_centre, encounter_type, date_of_service, patient_id. |
| GET | /api/v1/ahcip/claims/:id/fee-breakdown | CLAIM_VIEW | params: `claimIdParamSchema` (UUID) | Get detailed fee breakdown for an existing claim: base, modifiers, premiums, RRNP, total. Re-computes from current Reference Data. |

## 9.4 Request/Response Schemas

All Zod validation schemas are defined in `packages/shared/src/schemas/ahcip.schema.ts` and re-exported via `apps/api/src/domains/ahcip/ahcip.schema.ts`.

**Fee Calculate schema:**
```typescript
feeCalculateSchema = z.object({
  health_service_code: z.string().min(1).max(10),
  functional_centre: z.string().min(1).max(10),
  encounter_type: z.enum([...ENCOUNTER_TYPES]),
  modifier_1: z.string().max(6).optional(),
  modifier_2: z.string().max(6).optional(),
  modifier_3: z.string().max(6).optional(),
  diagnostic_code: z.string().max(8).optional(),
  facility_number: z.string().max(10).optional(),
  referral_practitioner: z.string().max(10).optional(),
  calls: z.number().int().min(1).default(1),
  time_spent: z.number().int().min(1).optional(),
  patient_location: z.string().max(10).optional(),
  date_of_service: z.string().date(),
  patient_id: z.string().uuid(),
})
```

**List Batches schema:**
```typescript
listBatchesSchema = z.object({
  status: z.enum([...BATCH_STATUSES]).optional(),
  date_from: z.string().date().optional(),
  date_to: z.string().date().optional(),
  page: z.coerce.number().int().min(1).default(1),
  page_size: z.coerce.number().int().min(1).max(50).default(20),
})
```

**Error responses** follow the standard pattern: `{ error: { code: string, message: string } }`. 404 responses use generic "Resource not found" to avoid leaking batch/claim existence across physicians.

# 10. ARP/APP Shadow Billing

## 10.1 ARP BA Type Labelling

During onboarding (Domain 11), the physician labels each BA with its type. The `business_arrangements` table includes:
- `ba_type`: Extended to include 'ARP' alongside 'FFS', 'PCPCM', 'LOCUM'.
- `ba_subtype`: For ARP BAs: ANNUALISED, SESSIONAL, or BCM. NULL for non-ARP.

| ba_type | ba_subtype | Label |
| --- | --- | --- |
| FFS | NULL | FFS |
| ARP | ANNUALISED | ARP Annualised |
| ARP | SESSIONAL | ARP Sessional |
| ARP | BCM | ARP BCM |
| PCPCM | NULL | PCPCM |
| LOCUM | NULL | Locum |

## 10.2 ARP S-Code Restriction

ARP S-codes are only available when the selected BA is an ARP BA:
- Service code search/lookup filters: if selected BA has `ba_type = 'ARP'`, include S-codes in results. Otherwise, exclude S-codes.
- If physician manually enters an S-code with a non-ARP BA selected → validation error: "S-codes are only available under an ARP Business Arrangement."

## 10.3 Shadow Billing Detection

Shadow billing is auto-detected by the `isShadowBilling` helper: if any of `modifier_1`, `modifier_2`, or `modifier_3` equals 'TM', the claim is flagged as shadow billing with `shadowBillingFlag = true` and `submittedFee = '0.00'`.

Validation check A16 (Shadow Billing Consistency) enforces bidirectional consistency:
- If `shadowBillingFlag = true` but TM modifier is missing → WARNING.
- If TM modifier is present but `shadowBillingFlag = false` → WARNING.

# 11. Reciprocal (Out-of-Province) Billing

## 11.1 Overview

Out-of-province patients can have claims submitted through AHCIP using reciprocal billing. When a non-Alberta health number is entered, the system auto-detects the patient's home province from the number format.

## 11.2 Province Auto-Detection

Province detection logic uses format patterns to identify the health number's province:
- Quebec (4 letters + 8 digits RAMC format) triggers redirect to private billing workflow: "Quebec does not participate in reciprocal physician billing."
- For ambiguous formats (e.g., 9-digit shared by AB, SK, NB), the system displays the top candidate and offers a province selector for manual correction.

## 11.3 Reciprocal Billing Rules

Province-specific rules (stored in `reciprocal_billing_rules` reference table) determine:
- Service codes with known reciprocal billing exclusions display a warning.
- Claims are tagged with the patient's home province for separate reporting.
- Coverage verification prompts for potentially expired health numbers.

## 11.4 Impact on AHCIP Claim

Reciprocal claims follow the same AHCIP pathway (validation, batch assembly, H-Link submission) with the patient's out-of-province health number in the PHN field. Province-specific format validation replaces Alberta PHN validation.

# 12. Mixed FFS/ARP Smart Routing

## 12.1 Facility-BA Mapping

Physicians map each BA to facility codes / practice locations via `ba_facility_mappings` table. Constraint: unique `(provider_id, location_id)` — one location maps to one BA at a time.

## 12.2 Time-Based Routing Schedule

The `ba_schedule_mappings` table allows time-based routing: each entry maps a BA to a day-of-week and optional time window. Claims are routed based on the facility and time context.

## 12.3 Routing Priority

During claim creation, the BA is auto-selected using this priority chain (implemented in Provider Management's `routeClaimToBa()`):

1. **Service code type:** ARP S-code → force ARP BA. No override.
2. **Facility code mapping:** claim facility code → lookup ba_facility_mappings → select mapped BA.
3. **Schedule mapping:** claim date of service → day-of-week + time → lookup ba_schedule_mappings → select mapped BA.
4. **Primary BA fallback:** physician's designated primary BA.

The `BaRoutingResult` returned includes:
- `ba_number`: The resolved BA number.
- `ba_type`: 'FFS' or 'PCPCM'.
- `routing_reason`: 'WCB_PRIMARY', 'NON_PCPCM', 'IN_BASKET', 'OUT_OF_BASKET', or 'UNCLASSIFIED'.
- `warning`: Optional warning if routing conflict detected.

## 12.4 Routing Conflict Warning

If physician manually selects a BA that conflicts with contextual routing logic (e.g., FFS BA for a claim at an ARP-mapped facility), the system displays a warning and requires confirmation.

# 13. Connect Care SCC Import Integration

## 13.1 21-Field AHCIP SCC Extract Format

Connect Care's "My Billing Codes" extract provides AHCIP billing data in a 21-field format:

| # | Field Name | AHCIP Mapping |
| --- | --- | --- |
| 1 | Encounter Date | date_of_service |
| 2 | Patient ULI | Patient PHN (9-digit Alberta or out-of-province) |
| 3 | Patient Name | Display/verification only |
| 4 | Patient DOB | Age-based billing rules |
| 5 | Patient Gender | Sex-specific service code validation |
| 6 | Patient Insurer | Determines claim routing (AHCIP vs private) |
| 7 | Coverage Status | Eligibility validation |
| 8 | Service Code (SOMB) | health_service_code |
| 9 | Service Code Description | Display only |
| 10 | Modifier(s) | modifier_1, modifier_2, modifier_3 (comma/pipe-delimited) |
| 11 | Diagnostic Code (ICD-9) | diagnostic_code |
| 12 | ICD-10-CA Source Code | Preserved for audit trail |
| 13 | ICD Conversion Flag | Requires manual ICD-9 confirmation if true |
| 14 | Referring Provider ID | referral_practitioner |
| 15 | Referring Provider Name | Display/verification only |
| 16 | Billing Provider ID | Must match authenticated provider |
| 17 | Business Arrangement Number | ba_number (validated against provider profile) |
| 18 | Facility Code | facility_number |
| 19 | Functional Centre | functional_centre |
| 20 | Encounter Type | encounter_type |
| 21 | Charge Status | ACTIVE, MODIFIED, or DELETED |

## 13.2 AHCIP-Specific Import Validation

Each imported row is classified using a three-tier severity model:

| Validation Rule | Severity | Handling |
| --- | --- | --- |
| Missing Patient ULI | Blocking | Row rejected. Cannot create claim without patient identifier. |
| Invalid ULI format | Blocking | Row rejected with format error. Out-of-province formats accepted per reciprocal billing rules. |
| Missing Service Code | Blocking | Row rejected. No billable service to create. |
| Encounter Date in the future | Blocking | Row rejected. Likely data error. |
| Unrecognised SOMB code | Warning | Claim created with warning flag. Physician prompted to verify code. |
| ICD Conversion Flag set | Warning | Claim created. ICD-9 field left blank. Physician must manually select ICD-9 code via crosswalk before submission. |
| Missing Referring Provider ID | Warning | Claim created with warning. Required before submission if SOMB code mandates referral (GR 8). |
| Encounter Date > 90 days old | Warning | Claim created with warning. Approaching AHCIP submission deadline. |
| Charge Status = Deleted | Informational | Correction/deletion indicator. |
| Duplicate detection | Informational | Same patient + date + code + provider flagged. Physician decides skip or create. |

## 13.3 ICD-10-CA to ICD-9 Crosswalk

Connect Care documents in ICD-10-CA but Alberta Health bills in ICD-9. When the ICD Conversion Flag is set, the claim's diagnostic_code is left blank and the physician must select the correct ICD-9 code using the crosswalk reference table (`icd_crosswalk` in Reference Data):

- Candidates displayed with match quality indicator: EXACT, CLOSE, APPROXIMATE, BROAD.
- Ordered by `sort_order` (1 = best match).
- Full ICD-9 code search available if no candidates are appropriate.
- Claim retains `icd10_source_code` for audit trail.
- Claim cannot be submitted until ICD-9 code is resolved.

# 14. H-Link Security

Generated H-Link submission files are encrypted at rest (AES-256) and transmitted via secure channel (SFTP with key-based auth or TLS 1.3).

H-Link credentials (submitter prefix, transmission credentials) stored in environment variables (HLINK_SUBMITTER_PREFIX, HLINK_CREDENTIAL_ID, HLINK_CREDENTIAL_SECRET), never in application code or database.

H-Link transmission is logged: timestamp, file reference, record count, transmission result.

Assessment response files are retrieved via secure channel and processed immediately. Raw files retained encrypted for audit.

All H-Link files contain PHI (patient PHN, DOB, diagnoses). Generated and stored on Meritum infrastructure (DigitalOcean Toronto) within Canadian data residency.

Physician scoping is enforced at every level: batch ownership checks in service functions, physician_id joins in repository queries.

# 15. Testing Requirements

## 15.1 Unit Tests

Unit tests are located in `apps/api/src/domains/ahcip/ahcip.test.ts`. They use a mock Drizzle database supporting multi-table joins and verify:
- Repository operations (CRUD, batch management, physician scoping).
- Service layer functions (claim creation, validation, fee calculation, batch assembly).
- H-Link file generation (format, field positioning, checksum).
- Assessment file parsing and ingestion.

## 15.2 Validation Tests

Each AHCIP validation check (A1–A19) with positive and negative cases

Governing rule tests: representative HSC codes for each GR (GR 1, 3, 5, 8, 10, 14, 18)

Modifier eligibility: valid and invalid modifiers for representative codes

Modifier combinations: valid pairs, mutually exclusive pairs

90-day window: boundary cases (exactly 90 days, 91 days, DST transitions, 7-day warning threshold)

PCPCM routing: in-basket and out-of-basket codes route to correct BA

After-hours: standard, evening, night, weekend, stat holiday, DST transition

DI surcharge: eligible and ineligible codes, facility requirements

Shadow billing consistency: bidirectional TM modifier / flag checks

## 15.3 Fee Calculation Tests

Base fee calculation for representative HSC codes

Each modifier type's fee impact: PERCENTAGE (e.g., BMI), ADDITIVE (e.g., CMGP), OVERRIDE

TM modifier = shadow billing override ($0.00 total, full breakdown still computed)

AFHR modifier handled as premium, not modifier adjustment

RRNP premium for qualifying and non-qualifying communities

PCPCM in-basket vs out-of-basket fee routing

Shadow billing: TM modifier produces $0.00 fee

Bundling: multiple services same patient same DOS with GR-based bundling discount

Non-negative total floor

## 15.4 H-Link File Tests

File generation: output matches pipe-delimited format

File header: correct submitter prefix, batch date, zero-padded record count, vendor ID

File trailer: record count matches header, total value correct, SHA-256 checksum (16 hex chars)

Field positioning: each field at correct position in pipe-delimited format

Claim record format: `C|ba|hsc|dos|mod1|mod2|mod3|diag|facility|referral|calls|time|fee`

Empty optional fields: empty string in pipe-delimited record

File naming convention: `hlink_{ba}_{date}_{batchId}.dat`

## 15.5 Assessment Ingestion Tests

Parse successful assessment: all claims matched, states updated to ASSESSED

Parse rejected assessment: explanatory codes extracted, resolved against Reference Data, claims matched, states updated to REJECTED

Adjusted claims: assessed_fee differs from submitted_fee, CLAIM_ASSESSED notification with isAdjusted flag

Unmatched records: graceful handling (logged, no silent data loss), counted in result

Mixed results: some accepted, some rejected, some adjusted in same batch

Payment reconciliation: ASSESSED → PAID state transitions, batch RECONCILED status

Corrective action generation: common categories mapped to one-click actions

## 15.6 Batch Assembly Tests

Auto-submission mode handling: AUTO_CLEAN (clean only), AUTO_ALL (all), REQUIRE_APPROVAL (skip)

Pre-submission validation: failed claims returned to VALIDATED, notification emitted

PCPCM dual-BA: separate batches per BA

Fee calculation during assembly

Batch record creation with correct counts and totals

Claim linking to batch

State transitions QUEUED → SUBMITTED

Notification emission (BATCH_ASSEMBLED, CLAIM_VALIDATION_FAILED_PRE_BATCH)

## 15.7 Billing Scenario Tests (End-to-End)

Each billing scenario from the PRD must be tested end-to-end through the AHCIP pathway:

FFS clinic visit with CMGP, after-hours premium, and RRNP

Shadow billing (ARP with TM modifier) — fee = $0.00, claim recorded

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

Connect Care SCC import → ICD crosswalk resolution → submit → assessed

# 16. Open Questions

| # | Question | Context |
| --- | --- | --- |
| 1 | What is the exact H-Link file format version (AHC2210 or newer)? | To be confirmed during H-Link accreditation. Current implementation uses pipe-delimited format. |
| 2 | Is H-Link transmission SFTP-based or API-based? | Both are referenced in AHCIP documentation. Abstracted behind HlinkTransmissionService interface. |
| 3 | What is the assessment response file format and delivery mechanism? | Current implementation assumes pipe-delimited format mirroring submission. To be confirmed during accreditation. |
| 4 | Are there H-Link test environments available for development? | Important for integration testing prior to production accreditation. |
| 5 | What is the H-Link batch size limit? | Need to confirm maximum claims per batch file for performance planning. |
| 6 | How does AHCIP handle batch resubmission for failed transmissions? | Current implementation resets ERROR → GENERATED and re-transmits. Need to confirm whether AHCIP requires new submission reference. |
| 7 | What is the exact Thursday cutoff time recognised by AHCIP? | We use 12:00 MT as internal cutoff. Need to confirm AHCIP's actual processing window. |

# 17. Document Control

This document specifies the AHCIP H-Link submission pathway. It should be read in conjunction with Domain 4.0 (Claim Lifecycle Core) for the shared state machine, base data model, and validation architecture, and Domain 4.2 (WCB Claim Pathway) for the WCB EIR submission pathway.

| Item | Value |
| --- | --- |
| Parent document | Meritum PRD v1.3 |
| Domain | AHCIP Claim Pathway (Domain 4.1 of 13) |
| Build sequence position | 4th (sub-domain of Claim Lifecycle) |
| Dependencies | Domain 4.0 (Core), Domain 1 (IAM), Domain 2 (Reference Data), Domain 3/9 (Notifications) |
| Consumes | Domain 5 (Provider Mgmt), Domain 6 (Patient Registry), Domain 7 (Intelligence Engine) |
| Authoritative AHCIP reference | Electronic Claims Submission Specifications Manual, H-Link accreditation package |
| Related supplementary specs | MVP Features Addendum (B5, B8, B10), Connect Care Integration |
| Version | 2.0 |
| Date | February 2026 |
| Next domain in critical path | Domain 4.2 (WCB Claim Pathway) |
