# Meritum_Domain_02_Reference_Data

MERITUM

Functional Requirements

Reference Data Domain

Domain 2 of 13  |  Critical Path: Position 2

Meritum Health Technologies Inc.

Version 1.0  |  February 2026

CONFIDENTIAL

# Table of Contents

# 1. Domain Overview

## 1.1 Purpose

The Reference Data domain is the knowledge foundation of Meritum. It stores, versions, and serves every external data set the platform depends on: the Schedule of Medical Benefits (SOMB) fee schedule, WCB Alberta fee schedule, governing rules, modifier definitions, diagnostic codes, functional centre codes, RRNP community rates, PCPCM basket classifications, and the Alberta statutory holiday calendar. It also houses the contextual help content (tooltips and plain-language explanations) that surfaces throughout the UI.

Every claim validation decision, every AI Coach suggestion, every modifier prompt, and every rejection prevention check traces back to data in this domain. If Reference Data is wrong, everything downstream is wrong. Accuracy, currency, and versioning are existential requirements.

## 1.2 Scope

SOMB fee schedule: all Health Service Codes (HSCs), descriptions, base fees, rules, and specialty restrictions

WCB Alberta fee schedule: all WCB-specific codes, descriptions, and fees

Modifier definitions: type (explicit/implicit), applicability rules, rate calculations

Governing rules: GR 1, 3, 5, 6, 8, 11, 13, surcharge rules — encoded as machine-readable validation rules

Functional centre codes and their facility type mappings

Diagnostic codes (ICD-9) used in Alberta billing

RRNP community rate table (community → percentage)

PCPCM basket classification (HSC → in-basket / out-of-basket / facility)

Alberta statutory holiday calendar (current year + next year)

Explanatory codes (AHCIP rejection/assessment response codes)

Effective-date versioning for all data sets (supporting mid-year SOMB updates)

SOMB change summary generation (diff between versions)

Contextual help content: plain-language tooltips for codes, modifiers, governing rules, and billing concepts

Code search and autocomplete APIs consumed by Claim Lifecycle and Mobile Companion

## 1.3 Out of Scope

Claim validation logic (Claim Lifecycle domain; consumes Reference Data via API)

AI Coach reasoning (Intelligence Engine domain; consumes Reference Data for rule basis)

Patient data (Patient Registry domain)

Physician profile and specialty data (Provider Management domain)

EMR field mapping templates (Claim Lifecycle domain)

## 1.4 Domain Dependencies

## 1.5 Critical Design Constraint: Effective-Date Versioning

Alberta Health publishes SOMB updates (typically quarterly, occasionally mid-quarter). When a fee schedule change takes effect, there is a transition period where claims for dates of service before the change use old rates and claims for dates of service after the change use new rates. The 90-day submission window means a physician could be submitting claims spanning two fee schedule versions simultaneously.

Therefore, all reference data must be versioned with effective dates. When a claim is validated, the system must select the reference data version that was in effect on the claim’s date of service, not the current date. This applies to: HSC codes and fees, modifier rates, governing rules, WCB fee schedule, RRNP rates, and PCPCM basket classifications.

Implementation: Each data set has a versions table tracking version ID, effective_from date, effective_to date (NULL for current), and publication metadata. Every record in the data set carries a version_id foreign key. Queries always filter by the version that was effective on the date of service.

# 2. Reference Data Sets

This section catalogues every data set managed by the Reference Data domain, its source, update frequency, and structure.

## 2.1 SOMB Fee Schedule

Source: Alberta Health — Schedule of Medical Benefits (SOMB), published as PDF with periodic bulletins

Update frequency: Quarterly (April 1, July 1, October 1, January 1) with occasional mid-quarter bulletins

Record count: ~6,000+ Health Service Codes

Ingestion method: Manual by Admin. SOMB is published as PDF; data must be extracted, validated against previous version, and loaded. Automated PDF parsing is a future enhancement; MVP relies on structured manual entry or semi-automated extraction with Admin verification.

Key fields per HSC record:

## 2.2 WCB Alberta Fee Schedule

Source: WCB Alberta — Physician Fee Schedule and Billing Guide

Update frequency: Typically annual; occasional mid-year updates

Ingestion method: Manual by Admin, same process as SOMB

## 2.3 Modifier Definitions

Source: SOMB governing rules, AHCIP policy documents

Modifiers alter the fee or meaning of a claim. Some are explicit (physician must select them), some are implicit (system applies them automatically based on claim context).

### Modifier Reference (MVP)

## 2.4 Governing Rules

Source: SOMB Preamble and Governing Rules section

Governing rules are the validation logic that determines whether a claim is valid before submission. They are encoded as machine-readable rule definitions that the Claim Lifecycle domain’s validation engine evaluates. The Reference Data domain stores the rule definitions; the Claim Lifecycle domain executes them.

### 2.4.1 Rule Logic Schema

Each governing rule is encoded as a JSON object that the validation engine can evaluate against a claim context. The schema supports composable conditions:

Design note: The rule_logic JSONB field is not free-form. It follows a strict schema per rule_category. The validation engine in the Claim Lifecycle domain has a handler per category that knows how to evaluate the schema. This keeps the rules data-driven (updatable by Admin without code deployment) while ensuring the evaluation logic is well-defined and testable.

## 2.5 Functional Centre Codes

Source: AHCIP Electronic Claims Submission Specifications Manual

## 2.6 Diagnostic Codes (ICD-9)

Source: ICD-9-CM as used by AHCIP (Alberta uses a subset with local extensions)

## 2.7 RRNP Community Rate Table

Source: Alberta Health — Rural Remote Northern Program rate schedules

Update frequency: Annual or as negotiated

## 2.8 PCPCM Basket Classification

Source: Alberta Health — PCPCM program documentation

The PCPCM classification determines which billing arrangement (BA) a claim is routed to for physicians enrolled in PCPCM. In-basket codes route to the capitation BA; out-of-basket and facility codes route to the FFS BA.

## 2.9 Alberta Statutory Holiday Calendar

Source: Alberta Employment Standards; federal holiday calendar

Update frequency: Annual (loaded for current year + next year)

The statutory holiday calendar is consumed by the rules engine for after-hours premium calculations. Some premiums differ on statutory holidays vs. regular evenings/weekends. The calendar must include both Alberta provincial statutory holidays and federally observed holidays that affect healthcare scheduling.

Alberta statutory holidays for reference: New Year’s Day, Family Day (3rd Monday February), Good Friday, Victoria Day, Canada Day, Heritage Day (1st Monday August), Labour Day, National Day for Truth and Reconciliation (September 30), Thanksgiving, Remembrance Day, Christmas Day.

## 2.10 Explanatory Codes

Source: AHCIP assessment response specifications

Explanatory codes are returned by AHCIP in assessment responses to explain why a claim was paid, adjusted, or rejected. They are essential for the rejection management workflow.

## 2.11 Version Management Tables

Each data set has its own versions table tracking publication history and effective date ranges.

# 3. User Stories & Acceptance Criteria

## 3.1 Code Search & Lookup

## 3.2 Data Management (Admin)

## 3.3 SOMB Change Summaries

## 3.4 Contextual Help

# 4. API Contracts

All endpoints require authentication (via Identity & Access middleware). Admin endpoints require the admin role. Physician/delegate endpoints require active subscription.

## 4.1 Code Search & Lookup

## 4.2 Validation Support (Internal)

These endpoints are consumed by the Claim Lifecycle domain’s validation engine, not directly by the UI. They return the raw rule data needed for claim validation.

## 4.3 Admin Data Management

## 4.4 Change Summary Endpoints

# 5. Search Architecture

Code search is a critical UX path. Physicians searching for an HSC code during claim entry expect autocomplete-speed responses (<200ms). The search architecture must support this.

## 5.1 Search Requirements

Full-text search across HSC codes, descriptions, and aliases (common names physicians use that don’t match the SOMB description exactly)

Prefix matching on code numbers (e.g., “03.04” matches all 03.04* codes)

Fuzzy matching for typos (e.g., “consultatoin” matches “consultation”)

Specialty filtering: exclude codes the physician cannot bill, or deprioritise them

Frequency weighting: codes the physician has billed recently are ranked higher

Version-aware: search results reflect the SOMB version effective on the claim’s date of service

Performance: <200ms for the first page of results under normal load

## 5.2 Implementation Options

Decision deferred to tech stack selection. Options:

PostgreSQL full-text search (pg_trgm + ts_vector): Simplest. No additional infrastructure. At ~6,000 HSC records, PostgreSQL FTS is more than adequate for performance. Trigram indexing handles fuzzy matching. Frequency weighting via a join to usage stats.

Meilisearch / Typesense: Purpose-built search engines with typo tolerance, prefix matching, and faceted filtering out of the box. Adds infrastructure but provides better UX for autocomplete. Small memory footprint.

In-memory cache: At 6,000 records, the entire SOMB can be loaded into application memory (~5–10 MB). Search becomes a filtered array scan with zero database overhead. Version switching is a cache swap. The simplest high-performance option for MVP scale.

Recommendation: Start with in-memory cache or PostgreSQL FTS. Evaluate Meilisearch if search UX feedback indicates the need for better fuzzy matching. At MVP scale, the data set is small enough that any approach works.

# 6. Data Ingestion Process

Reference data ingestion is the highest-risk operational process in Meritum. Incorrect data means incorrect validation, which means incorrect claims. The ingestion process is designed with multiple safety gates.

## 6.1 SOMB Ingestion Workflow

1. Alberta Health publishes SOMB update (PDF + potentially structured data).

2. Admin extracts data into Meritum’s structured format (CSV/JSON). For MVP, this is a manual or semi-automated process. The Admin is responsible for accuracy.

3. Admin uploads via the staging endpoint (REF-005). System validates schema and data integrity.

4. System generates diff report. Admin reviews every change, paying special attention to fee changes, new codes, and deprecated codes.

5. Admin authors the change summary narrative and sets the effective date.

6. Admin publishes. The version goes live for claims with dates of service on or after the effective date.

7. Notification Service delivers SOMB change summary to all physicians.

## 6.2 Safety Gates

Schema validation: Uploaded data must match expected field types, required fields, and format constraints. Rejects invalid uploads before staging.

Diff review: Admin must review the diff report before publishing. Large unexpected changes (e.g., >500 modified records, >100 deprecated codes) trigger an additional confirmation: “This is an unusually large change. Please confirm you have reviewed the diff carefully.”

Staging state: Data is loaded into a staging table, not the live table. It only becomes live on explicit publication. This allows Admin to review, test, and discard if needed.

Dry-run validation: Admin can run the new version against a sample of recent real claims to see how it would affect validation results. This catches rule encoding errors before they affect production.

Rollback: If a published version is found to contain errors, Admin can “rollback” by re-activating the previous version and setting the erroneous version’s effective_to to the rollback date. Claims submitted against the erroneous version during the window can be flagged for review.

Audit trail: Every staging, publication, and rollback action is logged with admin_id, timestamp, and affected version.

## 6.3 Initial Data Load (Pre-Launch)

Before launch, the complete current SOMB, WCB fee schedule, all governing rules, modifier definitions, functional centres, DI codes, RRNP rates, PCPCM baskets, and statutory holidays must be loaded and verified. This is a one-time effort that establishes the baseline.

SOMB: complete extraction from current published schedule. Estimated: 2–4 weeks of effort for initial structuring.

WCB: complete extraction from WCB Physician Fee Schedule.

Governing rules: manual encoding of each rule into the rule_logic JSON schema. The most labour-intensive task. Estimated: 2–3 weeks.

Modifiers: manual definition of each modifier with calculation parameters and applicability rules.

All other data sets: extraction from published Alberta Health sources.

Verification: test physician (Dr. Chantelle Scrutton) validates the reference data by entering real billing scenarios and confirming validation results match expected outcomes.

# 7. Interface Contracts with Other Domains

## 7.1 Claim Lifecycle (Primary Consumer)

The Claim Lifecycle domain is the primary consumer of Reference Data. It consumes:

HSC code details for claim creation and fee calculation

Governing rule definitions for pre-submission validation

Modifier definitions for eligibility checking and fee adjustment

Functional centre data for facility validation

DI codes for diagnostic code validation and surcharge/BCP qualification

RRNP rates for premium calculation

PCPCM basket classification for BA routing

Statutory holidays for premium calculation

Explanatory codes for rejection management

Contract: Claim Lifecycle passes a date of service with every Reference Data query. Reference Data returns data from the version effective on that date. Claim Lifecycle never caches Reference Data beyond the current request (ensures version currency). The validate-context endpoint (Section 4.2) is the primary interface for batch validation.

## 7.2 Intelligence Engine

The Intelligence Engine (AI Billing Coach) consumes Reference Data for:

Rule definitions that drive the deterministic Tier 1 engine

Modifier applicability data for suggestion generation

Code combination data for missed billing detection

Help text and source references for Tier 2 LLM explanations and Tier 3 “review recommended” citations

Contract: Intelligence Engine queries Reference Data the same way Claim Lifecycle does. It additionally consumes the source_reference and source_url fields for citation generation. The help_text fields are used to generate natural-language explanations without LLM involvement where possible.

## 7.3 Provider Management

Provider Management consumes Reference Data for:

Specialty code validation (physician’s declared specialty must be a valid specialty in SOMB)

Functional centre lookup for practice location configuration

RRNP community lookup for practice location RRNP eligibility

## 7.4 Notification Service

Reference Data emits events consumed by the Notification Service:

## 7.5 Analytics & Reporting

Analytics consumes Reference Data for code descriptions, category labels, and fee information when generating reports and dashboards. All analytics queries pass through the same version-aware API to ensure historical accuracy (revenue reports for a past period use the fee schedule that was in effect during that period).

## 7.6 Support System (Phase 1.5)

The help_text, description, source_reference, and source_url fields across all data sets form the knowledge corpus for the AI-assisted support system. When the support system is built, it embeds this content into a vector store for RAG. Reference Data version updates trigger re-indexing of the support knowledge base.

# 8. Security & Audit Requirements

## 8.1 Access Control

Read access (search, lookup, help text): all authenticated users with active subscription.

Write access (upload, publish, edit, rollback): Admin role only.

Staging operations (upload, diff review, dry-run, discard): Admin role only.

Audit log queries related to Reference Data: Admin only.

## 8.2 Audit Events

## 8.3 Data Integrity

All reference data tables have version_id foreign keys with cascading constraints.

Published versions are immutable: once published, individual records cannot be edited. Corrections require a new version.

Staging data is isolated from live data (separate staging tables or a staging flag).

Version activation is atomic: all records in a version become active simultaneously.

Database constraints enforce that at most one version per data set is active (is_active = true) at any time.

# 9. Testing Requirements

## 9.1 Unit Tests

Version-aware query logic: given a date of service, correct version is selected across all data sets

Version boundary: claim on effective_from date uses new version; claim on day before uses old version

HSC search: keyword match, code prefix match, fuzzy match, specialty filtering, frequency weighting

DI code search: keyword match, code prefix match, specialty weighting, surcharge/BCP flag accuracy

Modifier applicability: given an HSC + context, correct modifiers returned; incompatible modifiers excluded

Governing rule logic parsing: each rule_category handler correctly evaluates its JSON schema

RRNP rate lookup: correct percentage returned for community + date of service

PCPCM basket classification: correct basket returned for HSC + date of service

Statutory holiday check: dates correctly identified as holidays; non-holidays return false

Diff generation: correctly identifies added, modified, and deprecated records between versions

Schema validation: rejects invalid uploads with clear error messages

## 9.2 Integration Tests

Full ingestion workflow: upload → staging → diff → publish → verify live data

Version transition: publish new version, verify claims for old DOS use old version, claims for new DOS use new version

Rollback: publish → rollback → verify previous version is active

SOMB change notification: publish triggers event, Notification Service delivers change summary

Claim Lifecycle integration: create claim → Reference Data supplies correct validation rules → validation result accurate

Search performance: <200ms response time with full SOMB dataset loaded

Concurrent version queries: simultaneous requests for different dates of service return correct versions

## 9.3 Data Accuracy Tests

Sample verification: randomly select 100 HSC codes from published SOMB, verify all fields match

Governing rule accuracy: for each encoded governing rule, verify against 5+ known claim scenarios with expected outcomes

RRNP rate verification: verify rates for 10+ communities against published Alberta Health rates

Statutory holiday verification: verify all holidays for current year match published Alberta calendar

Cross-reference consistency: HSC codes referenced in governing rules, modifier definitions, and PCPCM baskets all exist in the SOMB data set

# 10. Open Questions for Tech Stack Selection

# 11. Initial Data Load Estimate

The pre-launch data load is the most time-consuming preparation task for the Reference Data domain. This section provides effort estimates for the initial baseline load.

# 12. Document Control

Parent document: Meritum PRD v1.3

Domain: Reference Data (Domain 2 of 13)

Build sequence position: 2nd (depends on Identity & Access for auth context and Admin role; no other Meritum domain dependencies)

Downstream consumers: Claim Lifecycle, Intelligence Engine, Analytics & Reporting, Mobile Companion, Provider Management, Onboarding, Support System

| Depends On | Provides To | Interface Type |
| --- | --- | --- |
| Alberta Health (external) | Claim Lifecycle | SOMB publications → manual data ingestion by Admin; Reference Data serves validated fee schedule, rules, and modifiers via API |
| WCB Alberta (external) | Intelligence Engine | WCB fee schedule publications → manual data ingestion; Reference Data serves WCB codes and rates via API |
| Identity & Access | Analytics & Reporting | Admin auth required for data management; API auth for all queries |
| Notification Service | Mobile Companion | Reference Data emits events on version updates; Notification Service delivers SOMB change summaries to physicians |
| — | Onboarding | Specialty-specific defaults during physician setup |
| — | Support System | Help content serves as knowledge base for AI support (Phase 1.5) |

| Field | Type | Description |
| --- | --- | --- |
| hsc_code | VARCHAR(10) | Health Service Code (e.g., “03.04A”). Primary lookup field. |
| description | TEXT | Official SOMB description of the service |
| base_fee | DECIMAL(10,2) | Base fee in CAD. NULL for codes that are modifier-dependent or calculated. |
| fee_type | ENUM | fixed, calculated, time_based, unit_based |
| specialty_restrictions | JSONB | Array of specialty codes that can bill this HSC. Empty array = all specialties. |
| facility_restrictions | JSONB | Array of functional centre types where this code is valid. Empty = all. |
| max_per_day | INTEGER | Maximum times this code can be billed per patient per day (GR 3). NULL = no limit. |
| max_per_visit | INTEGER | Maximum per visit. NULL = no limit. |
| requires_referral | BOOLEAN | Whether GR 8 referral requirements apply |
| referral_validity_days | INTEGER | How long a referral is valid for this code. NULL = standard (12 months). |
| combination_group | VARCHAR(20) | GR 5 combination group identifier. Codes in the same group have combination restrictions. |
| modifier_eligibility | JSONB | Array of modifier codes applicable to this HSC with conditions |
| surcharge_eligible | BOOLEAN | Whether 13.99H/13.99HA surcharge can be billed with this code |
| pcpcm_basket | ENUM | in_basket, out_of_basket, facility, not_applicable |
| shadow_billing_eligible | BOOLEAN | Whether this code can be shadow-billed with TM modifier under ARP |
| notes | TEXT | Additional billing notes from SOMB (e.g., special conditions, documentation requirements) |
| help_text | TEXT | Plain-language tooltip explanation for physicians (Meritum-authored) |
| version_id | UUID | FK to somb_versions table |
| effective_from | DATE | Denormalised from version for query performance |
| effective_to | DATE | NULL for current version |

| Field | Type | Description |
| --- | --- | --- |
| wcb_code | VARCHAR(10) | WCB service code. Many overlap with SOMB HSC codes but fees differ. |
| description | TEXT | WCB description of the service |
| base_fee | DECIMAL(10,2) | WCB fee in CAD |
| fee_type | ENUM | fixed, calculated, time_based, report_based |
| requires_claim_number | BOOLEAN | Whether WCB claim number is mandatory (most are) |
| requires_employer | BOOLEAN | Whether employer information is mandatory |
| documentation_requirements | TEXT | WCB-specific documentation notes (surfaced by AI Coach) |
| help_text | TEXT | Plain-language tooltip |
| version_id | UUID | FK to wcb_versions table |
| effective_from | DATE |  |
| effective_to | DATE | NULL for current |

| Field | Type | Description |
| --- | --- | --- |
| modifier_code | VARCHAR(10) | Modifier identifier (e.g., CMGP, LSCD, AFHR, TM, BCP, RRNP, ANE, AST) |
| name | VARCHAR(100) | Human-readable name |
| description | TEXT | Official definition |
| type | ENUM | explicit (physician selects), implicit (system applies), semi_implicit (system suggests, physician confirms) |
| calculation_method | ENUM | percentage, fixed_amount, time_based_units, multiplier, none |
| calculation_params | JSONB | Parameters for calculation: { percentage: 0.15, unit_minutes: 15, base_units: 1, ... } |
| applicable_hsc_filter | JSONB | Rules for which HSCs this modifier applies to: specialty, facility type, code patterns |
| requires_time_documentation | BOOLEAN | Whether start/end time must be recorded |
| requires_facility | BOOLEAN | Whether a specific functional centre is required |
| combinable_with | JSONB | Array of modifier codes this can be combined with |
| exclusive_with | JSONB | Array of modifier codes this cannot be combined with (mutually exclusive) |
| governing_rule_reference | VARCHAR(20) | Which GR defines this modifier (e.g., GR 6) |
| help_text | TEXT | Plain-language tooltip |
| version_id | UUID | FK to modifier_versions |
| effective_from | DATE |  |
| effective_to | DATE |  |

| Modifier | Type | Calculation | Key Rules |
| --- | --- | --- | --- |
| CMGP | Semi-implicit | Time-based units (15 min increments after initial period) | Requires documented start/end time; not applicable to virtual care codes; GR 6 |
| LSCD | Explicit | Prolonged service add-on | Requires CMGP to be present; minimum threshold duration; GR 6 |
| AFHR | Implicit | Percentage premium on base fee | Applied automatically based on time of service vs. standard hours; stat holiday calendar aware; GR 6 |
| BCP | Implicit | Percentage premium on base fee | Bone and joint care premium; applied based on DI code (musculoskeletal); GR 6 |
| RRNP | Implicit | Community-specific percentage premium | Applied based on physician’s practice location matching RRNP community table; rates vary by community (7%–30%+) |
| TM | Explicit | 5-minute allotment units | Shadow billing for ARP physicians; applied to all codes; time documentation required |
| ANE | Explicit | Anaesthesia modifier | For GPs providing anaesthesia in rural settings; specific fee calculation; GR 6 |
| AST | Explicit | Anaesthesia assist | For GPs assisting anaesthesia; GR 6 |
| Age modifiers | Implicit | Fee adjustment based on patient age | Applied automatically from patient DOB; different thresholds per code group (e.g., <2, <28 days, >65, >75) |
| Call-in codes | Explicit | Fixed fee codes (03.03KA/LA/MC/MD) | Separate billable codes for being called in; time-of-day dependent; stat holiday variants |

| Field | Type | Description |
| --- | --- | --- |
| rule_id | VARCHAR(20) | Governing rule identifier (e.g., GR3, GR5_3b, GR8, SURCHG_1399H) |
| rule_name | VARCHAR(200) | Human-readable rule name |
| rule_category | ENUM | visit_limits, code_combinations, modifier_rules, referral_rules, facility_rules, surcharge_rules, time_rules, general |
| description | TEXT | Official rule text from SOMB |
| rule_logic | JSONB | Machine-readable rule definition (see Section 2.4.1 for schema) |
| severity | ENUM | error (claim will be rejected), warning (claim may be rejected or suboptimal), info (advisory) |
| error_message | TEXT | Message displayed when rule is violated |
| help_text | TEXT | Plain-language explanation of what this rule means and why it matters |
| source_reference | VARCHAR(100) | Exact SOMB section reference (e.g., “SOMB Preamble, GR 5(3)(b)”) |
| source_url | TEXT | Link to authoritative source document (for “Review recommended” citations) |
| version_id | UUID | FK to governing_rule_versions |
| effective_from | DATE |  |
| effective_to | DATE |  |

| Rule | Category | Logic Pattern | Example |
| --- | --- | --- | --- |
| GR 1 | General | Global billing constraints | Maximum billable amount per day per physician; documentation requirements |
| GR 3 | Visit limits | { max_per_patient_per_day: N, hsc_group: [...], exceptions: [...] } | Office visits: max 1 per patient per day except with distinct DI codes |
| GR 5 | Code combinations | { hsc_a: pattern, hsc_b: pattern, relationship: allowed|prohibited|conditional, conditions: {...} } | 03.03A cannot be billed with 03.04A on same patient same day |
| GR 6 | Modifier rules | { modifier: code, requires: { time_documented: bool, min_duration: mins, facility_type: [...] }, conflicts: [...] } | CMGP requires documented time > 15 min; cannot combine with certain procedure codes |
| GR 8 | Referral rules | { hsc_pattern: regex, requires_referral: bool, referral_validity: days, exemptions: [...] } | Specialist consultations require valid referral < 12 months; GP self-referral exempt |
| GR 11 | Facility rules | { hsc_pattern: regex, required_facility_types: [...], prohibited_facility_types: [...] } | Hospital admission codes require hospital functional centre |
| GR 13 | Payment rules | Payment calculation rules and caps | Maximum payable amounts, holdback percentages |
| Surcharge 13.99H | Surcharge | { base_code: pattern, qualifying_di_codes: [...attachment_g...], surcharge_code: “13.99H” } | ED surcharge: qualifying DI from Attachment G + qualifying base code |
| Surcharge 13.99HA | Surcharge | { base_code: pattern, qualifying_di_codes: [...], surcharge_code: “13.99HA” } | Higher-acuity ED surcharge variant |
| PCPCM basket | Basket | { hsc: code, basket: in|out|facility, billing_route: ba_number } | In-basket codes route to PCPCM BA; out-of-basket to FFS BA |

| Field | Type | Description |
| --- | --- | --- |
| code | VARCHAR(10) | Functional centre code |
| name | VARCHAR(200) | Facility name or description |
| facility_type | ENUM | office, hospital_inpatient, hospital_outpatient, emergency, auxiliary_hospital, nursing_home, telehealth, community_health, other |
| location_city | VARCHAR(100) | City/town |
| location_region | VARCHAR(50) | Health zone or region |
| rrnp_community_id | UUID | FK to RRNP community table (NULL if not RRNP-eligible) |
| active | BOOLEAN | Whether this centre is currently operational |
| version_id | UUID |  |
| effective_from | DATE |  |
| effective_to | DATE |  |

| Field | Type | Description |
| --- | --- | --- |
| di_code | VARCHAR(10) | ICD-9 code (e.g., 786.5) |
| description | TEXT | Diagnosis description |
| category | VARCHAR(100) | Broad category (e.g., Respiratory, Musculoskeletal) |
| subcategory | VARCHAR(100) | Subcategory |
| qualifies_surcharge | BOOLEAN | Whether this DI code appears in Attachment G (ED surcharge qualifying) |
| qualifies_bcp | BOOLEAN | Whether this DI code qualifies for bone and joint care premium (BCP) |
| common_in_specialty | JSONB | Array of specialty codes where this DI is frequently used (for search optimisation) |
| help_text | TEXT | Plain-language tooltip |
| version_id | UUID |  |
| effective_from | DATE |  |
| effective_to | DATE |  |

| Field | Type | Description |
| --- | --- | --- |
| community_id | UUID | PK |
| community_name | VARCHAR(200) | Name of community |
| rrnp_percentage | DECIMAL(5,2) | Premium percentage (e.g., 15.00 for 15%) |
| rrnp_tier | VARCHAR(20) | RRNP classification tier if applicable |
| region | VARCHAR(100) | Health zone |
| version_id | UUID |  |
| effective_from | DATE |  |
| effective_to | DATE |  |

| Field | Type | Description |
| --- | --- | --- |
| hsc_code | VARCHAR(10) | FK reference to SOMB HSC code |
| basket | ENUM | in_basket, out_of_basket, facility |
| notes | TEXT | Special routing notes or conditions |
| version_id | UUID |  |
| effective_from | DATE |  |
| effective_to | DATE |  |

| Field | Type | Description |
| --- | --- | --- |
| holiday_id | UUID | PK |
| date | DATE | Holiday date |
| name | VARCHAR(100) | Holiday name (e.g., Family Day, Heritage Day, Canada Day) |
| jurisdiction | ENUM | provincial, federal, both |
| affects_billing_premiums | BOOLEAN | Whether this holiday triggers stat holiday premium rates (vs. regular after-hours) |
| year | INTEGER | Calendar year (for easy filtering) |

| Field | Type | Description |
| --- | --- | --- |
| expl_code | VARCHAR(10) | AHCIP explanatory code |
| description | TEXT | Official AHCIP description |
| severity | ENUM | paid, adjusted, rejected |
| common_cause | TEXT | Meritum-authored plain-language explanation of what typically causes this code |
| suggested_action | TEXT | Meritum-authored guidance on how to resolve (for rejection management workflow) |
| help_text | TEXT | Tooltip text |
| version_id | UUID |  |
| effective_from | DATE |  |
| effective_to | DATE |  |

| Field | Type | Description |
| --- | --- | --- |
| version_id | UUID | PK |
| data_set | ENUM | somb, wcb, modifiers, governing_rules, functional_centres, di_codes, rrnp, pcpcm, explanatory_codes |
| version_label | VARCHAR(50) | Human-readable label (e.g., “2026-Q1”, “2026-04-01 Bulletin”) |
| effective_from | DATE | Date this version takes effect |
| effective_to | DATE | NULL for current; set when superseded |
| published_by | UUID | FK to users.id (Admin who loaded this version) |
| published_at | TIMESTAMP | When this version was loaded into Meritum |
| source_document | TEXT | Reference to the source publication (e.g., “SOMB April 2026 Update”) |
| change_summary | TEXT | Human-readable summary of what changed (Meritum-authored) |
| records_added | INTEGER | Count of new records in this version |
| records_modified | INTEGER | Count of changed records |
| records_deprecated | INTEGER | Count of records no longer valid |
| is_active | BOOLEAN | Whether this is the current version (at most one active per data_set) |

| REF-001 | HSC Code Search |
| --- | --- |
| User Story | As a physician entering a claim, I want to search for HSC codes by keyword, code number, or description so that I can quickly find the correct code without memorising the SOMB. |
| Acceptance Criteria | • Search accepts partial code match (e.g., “03.04” matches 03.04A, 03.04B, 03.04C) and keyword match against description (e.g., “consultation” returns all consultation codes). • Results are ranked by relevance, with the physician’s most frequently used codes weighted higher (personalisation data from Claim Lifecycle). • Results are filtered by the physician’s specialty: codes restricted to other specialties are excluded or shown greyed with an explanation. • Results are filtered by the currently selected practice setting/functional centre if context is available. • Each result displays: HSC code, description, base fee, and a one-line help tooltip. Clicking a result populates the claim form. • Search response time: <200ms for the first 10 results (autocomplete must feel instantaneous). • Search operates against the version of the SOMB effective on the claim’s date of service. • If a code exists in a previous version but has been deprecated in the current version, it is flagged: “This code was deprecated effective [date]. Consider [replacement] instead.” |

| REF-002 | Favourite / Most-Used Codes Palette |
| --- | --- |
| User Story | As an ED physician, I want my most-used codes available as a one-tap palette so that I can enter claims during a shift without searching. |
| Acceptance Criteria | • The system tracks the physician’s top N codes by frequency (N configurable, default 20). • Favourite codes are displayed as a quick-access palette on the claim entry screen and the ED shift workflow screen. • The palette is ordered by frequency (most used first) and can be manually reordered by the physician. • Physicians can pin/unpin codes to the palette manually, overriding frequency-based ordering. • Palette contents update automatically as billing patterns change (recalculated weekly). • Palette is specialty-aware: a radiologist’s palette shows imaging interpretation codes; an ED physician’s shows emergency visit codes. |

| REF-003 | Diagnostic Code Search |
| --- | --- |
| User Story | As a physician, I want to search for ICD-9 diagnostic codes by keyword or code number so that I can quickly assign the correct diagnosis to a claim. |
| Acceptance Criteria | • Search accepts partial code match and keyword match against description and category. • Results weighted by the physician’s specialty (common DI codes for their specialty ranked higher). • Results show: DI code, description, category, and any special flags (surcharge-qualifying, BCP-qualifying). • Search response time: <200ms. • If the selected DI code qualifies for a surcharge (Attachment G) or BCP modifier, a tooltip indicates this: “This diagnosis qualifies for the ED surcharge (13.99H).” The AI Coach in Claim Lifecycle acts on this, but the tooltip provides immediate context. |

| REF-004 | Modifier Lookup |
| --- | --- |
| User Story | As a physician, I want to understand what a modifier means and when it applies so that I can make informed billing decisions. |
| Acceptance Criteria | • Every modifier displayed in the claim entry UI has a tooltip accessible via an info icon. • Tooltip shows: modifier name, plain-language description, when it applies, how it affects the fee, and the governing rule reference. • Clicking “Learn more” expands to full explanation with the source SOMB/GR reference and a link to the authoritative document. • Implicit modifiers (AFHR, BCP, RRNP, age) are explained with “This modifier is applied automatically based on [time of service / diagnosis / location / patient age].” • Semi-implicit modifiers (CMGP) are explained with “Meritum will suggest this modifier when your encounter exceeds [threshold]. You can accept or dismiss the suggestion.” |

| REF-005 | Load New SOMB Version |
| --- | --- |
| User Story | As an Admin, I want to load a new version of the SOMB fee schedule so that the platform reflects the latest Alberta Health publications. |
| Acceptance Criteria | • Admin uploads a structured data file (CSV or JSON) containing the new SOMB version’s HSC records. • System validates the upload against the expected schema: required fields present, data types correct, HSC codes properly formatted, fees non-negative. • System generates a diff report comparing the new version against the current active version: new codes added, codes modified (with field-level changes highlighted), codes deprecated/removed. • Admin reviews the diff report and enters: version label, effective_from date, source document reference, and a human-readable change summary. • Admin confirms publication. System sets the new version as active (effective_from = specified date), sets the previous version’s effective_to to the day before. • System emits a reference_data.version_published event consumed by the Notification Service to generate SOMB change summary notifications for physicians. • The change summary includes: count of new codes, modified codes, deprecated codes, plus the Admin-authored narrative summary. • All operations are audit-logged: admin_id, version_id, action, timestamp. • The upload can be performed in a staging state (version loaded but not published) to allow Admin to review before making it live. |

| REF-006 | Load WCB Fee Schedule Update |
| --- | --- |
| User Story | As an Admin, I want to load a new WCB Alberta fee schedule so that WCB claim validation reflects current rates. |
| Acceptance Criteria | • Same workflow as REF-005 but for the WCB data set. • Diff report highlights fee changes, new codes, and deprecated codes. • WCB version publishing emits a separate event for WCB-specific change notifications. |

| REF-007 | Update Governing Rules |
| --- | --- |
| User Story | As an Admin, I want to update governing rules when Alberta Health publishes changes so that claim validation remains accurate. |
| Acceptance Criteria | • Admin selects the governing rule to update and modifies the rule_logic JSON, description, help_text, or any other fields. • System validates the rule_logic JSON against the schema for the rule’s category (see Section 2.4.1). Invalid JSON is rejected with a descriptive error. • A new version of the governing rules data set is created. The old version’s effective_to is set. • Admin can preview the effect of the rule change by running it against a sample of recent claims (dry run): “If this rule had been in effect, [X] claims would have been flagged differently.” • Publication follows the same staging → review → publish workflow as SOMB updates. |

| REF-008 | Manage Statutory Holiday Calendar |
| --- | --- |
| User Story | As an Admin, I want to manage the statutory holiday calendar so that after-hours premiums are calculated correctly. |
| Acceptance Criteria | • Admin can view current year and next year’s statutory holidays. • Admin can add, edit, or remove holidays. Standard Alberta holidays are pre-populated; Admin maintains them year-to-year. • Each holiday entry includes: date, name, jurisdiction, and whether it affects billing premiums. • Changes take effect immediately (no versioning needed; holidays are date-specific). • System alerts Admin annually (November) if next year’s calendar has not been populated. |

| REF-009 | SOMB Change Summary Notification |
| --- | --- |
| User Story | As a physician, I want to be notified when the fee schedule or governing rules change so that I can adjust my billing practices. |
| Acceptance Criteria | • When a new SOMB version is published (REF-005), the Notification Service delivers a change summary to all active physicians. • The notification includes: version label, effective date, Admin-authored narrative summary, counts of new/modified/deprecated codes. • Physicians can click through to a detailed change view in the platform showing the full diff relevant to their specialty (codes they’ve billed or could bill). • Deprecated codes that the physician has billed in the last 12 months are highlighted with urgency: “Code [X] which you billed [N] times is being deprecated effective [date]. Replacement: [Y].” • Fee changes are summarised with impact: “Code [X] fee changed from $[old] to $[new] ([+/-]%).” • The same mechanism applies to WCB fee schedule updates and governing rule changes. • Change summaries are archived and accessible from the Analytics dashboard. |

| REF-010 | Contextual Help System |
| --- | --- |
| User Story | As a physician or delegate, I want plain-language tooltips on every billing concept I encounter so that I can learn as I work without leaving the application. |
| Acceptance Criteria | • Every HSC code, modifier, governing rule reference, explanatory code, and billing concept in the UI has an associated help_text field served by Reference Data. • Tooltips are written in plain language (not SOMB legalese): e.g., “CMGP: Add this when your visit took longer than 15 minutes. It adds time-based units to your claim, increasing the fee.” • Tooltips include: what it is, when it applies, how it affects the fee, and the authoritative source reference. • Clicking “View source” opens the relevant SOMB section, governing rule, or WCB policy document (external link or embedded reference). • Help content is part of the Reference Data data set and updated alongside SOMB/GR updates. When a rule changes, its tooltip changes. • Help content is also consumed by the AI Support System (Phase 1.5) as part of the RAG knowledge corpus. |

| Method | Endpoint | Description | Auth |
| --- | --- | --- | --- |
| GET | /api/v1/ref/hsc/search?q={query}&specialty={code}&facility={type}&date={dos}&limit={n} | Search HSC codes. Returns: [{ hsc_code, description, base_fee, help_text, deprecated }]. Version-aware: uses SOMB version effective on date of service. | Yes |
| GET | /api/v1/ref/hsc/{code}?date={dos} | Get full HSC detail including modifiers, restrictions, combination rules, help text. Version-aware. | Yes |
| GET | /api/v1/ref/hsc/favourites | Get current user’s top-N favourite codes (from usage data in Claim Lifecycle). Returns: [{ hsc_code, description, base_fee, frequency }]. | Yes |
| GET | /api/v1/ref/di/search?q={query}&specialty={code}&limit={n} | Search diagnostic codes. Returns: [{ di_code, description, category, qualifies_surcharge, qualifies_bcp }]. | Yes |
| GET | /api/v1/ref/di/{code} | Get full DI code detail. | Yes |
| GET | /api/v1/ref/modifiers?hsc={code}&date={dos} | Get applicable modifiers for an HSC on a date. Returns: [{ modifier_code, name, type, calculation_method, help_text }]. | Yes |
| GET | /api/v1/ref/modifiers/{code} | Get full modifier detail. | Yes |
| GET | /api/v1/ref/functional-centres?facility_type={type} | List functional centres, optionally filtered by facility type. | Yes |
| GET | /api/v1/ref/explanatory-codes/{code} | Get explanatory code detail with common cause and suggested action. | Yes |
| GET | /api/v1/ref/rrnp/{community_id}?date={dos} | Get RRNP rate for a community on a date. Returns: { community_name, rrnp_percentage }. | Yes |
| GET | /api/v1/ref/pcpcm/{hsc_code}?date={dos} | Get PCPCM basket classification for an HSC. Returns: { basket, notes }. | Yes |
| GET | /api/v1/ref/holidays?year={year} | Get statutory holidays for a year. Returns: [{ date, name, affects_billing }]. | Yes |
| GET | /api/v1/ref/holidays/check?date={date} | Check if a specific date is a statutory holiday. Returns: { is_holiday, holiday_name? }. | Yes |

| Method | Endpoint | Description | Auth |
| --- | --- | --- | --- |
| GET | /api/v1/ref/rules/validate-context?hsc={codes}&di={code}&facility={fc}&date={dos}&modifiers={codes} | Returns all applicable governing rules for a claim context. Response includes the rule_logic JSON for each rule, enabling the Claim Lifecycle validation engine to evaluate them. | Internal |
| GET | /api/v1/ref/rules/{rule_id}?date={dos} | Get a specific governing rule’s full detail including rule_logic. | Internal |
| GET | /api/v1/ref/somb/version?date={dos} | Get the SOMB version effective on a date. Returns: { version_id, version_label, effective_from }. | Internal |
| POST | /api/v1/ref/rules/evaluate-batch | Evaluate a batch of claims against all applicable rules. Body: [{ claim_context }]. Returns: [{ claim_id, violations: [...], warnings: [...] }]. Used for batch import validation. | Internal |

| Method | Endpoint | Description | Auth |
| --- | --- | --- | --- |
| POST | /api/v1/admin/ref/{dataset}/upload | Upload new version data. Body: multipart file (CSV/JSON). Returns: { staging_id, validation_result, record_count }. | Admin |
| GET | /api/v1/admin/ref/{dataset}/staging/{id}/diff | Get diff between staged version and current active version. Returns: { added: [...], modified: [...], deprecated: [...], summary_stats }. | Admin |
| POST | /api/v1/admin/ref/{dataset}/staging/{id}/publish | Publish staged version. Body: { version_label, effective_from, source_document, change_summary }. Returns: { version_id }. | Admin |
| DELETE | /api/v1/admin/ref/{dataset}/staging/{id} | Discard staged version. | Admin |
| GET | /api/v1/admin/ref/{dataset}/versions | List all versions for a data set with history. | Admin |
| POST | /api/v1/admin/ref/holidays | Add statutory holiday. Body: { date, name, jurisdiction, affects_billing }. | Admin |
| PUT | /api/v1/admin/ref/holidays/{id} | Update holiday. | Admin |
| DELETE | /api/v1/admin/ref/holidays/{id} | Remove holiday. | Admin |
| POST | /api/v1/admin/ref/rules/{rule_id}/dry-run | Dry-run a rule change against recent claims. Body: { updated_rule_logic }. Returns: { claims_affected, sample_results: [...] }. | Admin |

| Method | Endpoint | Description | Auth |
| --- | --- | --- | --- |
| GET | /api/v1/ref/changes?dataset={ds}&since={date} | Get change summaries since a date. Returns: [{ version_label, effective_from, change_summary, stats }]. | Yes |
| GET | /api/v1/ref/changes/{version_id}/detail?specialty={code} | Get detailed diff filtered by physician’s specialty. Returns: { added: [...], modified: [...], deprecated: [...], impact_summary }. | Yes |
| GET | /api/v1/ref/changes/{version_id}/physician-impact | Get personalised impact: codes the physician has billed that changed. Returns: { deprecated_codes_used: [...], fee_changes: [...], new_codes_relevant: [...] }. | Yes |

| Event | Payload | Consumer Action |
| --- | --- | --- |
| reference_data.version_published | { data_set, version_id, version_label, effective_from, change_summary, records_added, records_modified, records_deprecated } | Generate and deliver SOMB/WCB/rule change summary notifications to all active physicians |
| reference_data.code_deprecated | { data_set, codes: [{ code, description, effective_to, replacement_code? }] } | Generate targeted notifications to physicians who have billed deprecated codes in the last 12 months |
| reference_data.holiday_calendar_reminder | { year, message } | Remind Admin to populate next year’s holiday calendar (emitted annually in November) |

| Action | Detail Logged |
| --- | --- |
| ref.version_staged | admin_id, data_set, staging_id, record_count, file_hash |
| ref.version_diff_reviewed | admin_id, staging_id, diff_stats |
| ref.version_published | admin_id, version_id, data_set, effective_from, change_summary_hash |
| ref.version_rolled_back | admin_id, version_id, data_set, reason |
| ref.staging_discarded | admin_id, staging_id, data_set |
| ref.rule_dry_run | admin_id, rule_id, claims_sampled, results_summary |
| ref.holiday_created | admin_id, holiday_date, holiday_name |
| ref.holiday_updated | admin_id, holiday_id, old_values, new_values |
| ref.holiday_deleted | admin_id, holiday_id, holiday_date |

| Question | Options | Decision Criteria |
| --- | --- | --- |
| Code search implementation | PostgreSQL FTS (pg_trgm + ts_vector) vs. Meilisearch/Typesense vs. in-memory cache | At 6,000 records, all options work. In-memory is simplest and fastest. PG FTS requires no additional infrastructure. Meilisearch adds typo tolerance. Start simple, upgrade if search UX feedback warrants it. |
| SOMB PDF parsing | Manual extraction (MVP) vs. semi-automated PDF parsing with LLM assistance vs. OCR pipeline | SOMB is published as PDF with inconsistent formatting. Manual extraction is reliable but labour-intensive. LLM-assisted extraction (feed PDF pages to model, output structured JSON) could reduce effort 80% but needs verification. Evaluate post-launch. |
| Rule logic storage | JSONB in PostgreSQL vs. DSL (domain-specific language) compiled to validation functions | JSONB is flexible and queryable but rule evaluation requires a JSON interpreter. A DSL compiled to functions is faster but requires a compiler. JSONB is simpler for MVP; DSL is a performance optimisation if rule evaluation becomes a bottleneck. |
| Caching strategy | Application-level in-memory cache vs. Redis cache vs. no cache (direct DB queries) | Reference data changes infrequently (quarterly). In-memory cache with invalidation on version publish is simple and effective. Redis adds distribution for future multi-server scenarios. At single-server MVP, in-memory is sufficient. |
| Help text authoring tool | Admin panel text editor vs. Markdown files in repository vs. separate CMS | Help text must be versioned with reference data. Storing in the same database tables (help_text field per record) is simplest. A rich text editor in the admin panel allows formatting. Markdown in repo is developer-friendly but disconnected from data. |

| Data Set | Approximate Volume | Effort Estimate | Notes |
| --- | --- | --- | --- |
| SOMB fee schedule | ~6,000+ HSC records | 2–4 weeks | Largest dataset; PDF extraction is primary bottleneck; LLM-assisted extraction could accelerate |
| WCB fee schedule | ~500–1,000 records | 3–5 days | Many codes overlap with SOMB; WCB-specific codes are the delta |
| Governing rules | ~50–80 individual rules across GR 1–13 + surcharge rules | 2–3 weeks | Most intellectually demanding task; each rule must be encoded as machine-readable JSON and verified against known scenarios |
| Modifier definitions | ~15–20 modifiers | 3–5 days | Includes calculation parameters and applicability rules |
| Functional centres | ~2,000–3,000 codes | 3–5 days | Published by AHCIP; relatively clean source data |
| ICD-9 diagnostic codes | ~14,000 codes (Alberta subset) | 1 week | Published reference; bulk importable; adding surcharge/BCP flags requires cross-referencing Attachment G |
| RRNP community rates | ~100–200 communities | 1–2 days | Published by Alberta Health |
| PCPCM baskets | ~3,000–4,000 HSC classifications | 3–5 days | Cross-reference with SOMB; published by Alberta Health |
| Statutory holidays | ~11 holidays/year | 1 hour | Standard list; populate current + next year |
| Explanatory codes | ~100–200 codes | 2–3 days | Published by AHCIP; plain-language help text must be authored |
| Help text / tooltips | All records across all datasets | Ongoing (parallel with other loads) | Authored incrementally as each data set is loaded; priority on high-use codes and modifiers |
| TOTAL |  | 6–10 weeks | Critical path item; can partially overlap with application development |

| Version | Date | Author | Changes |
| --- | --- | --- | --- |
| 1.0 | February 12, 2026 | Ian Sharland | Initial Reference Data functional requirements |

