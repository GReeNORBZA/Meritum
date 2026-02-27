# Meritum_Domain_02_Reference_Data

MERITUM

Functional Requirements

Reference Data Domain

Domain 2 of 13  |  Critical Path: Position 2

Meritum Health Technologies Inc.

Version 2.0  |  February 2026

CONFIDENTIAL

# Table of Contents

# 1. Domain Overview

## 1.1 Purpose

The Reference Data domain is the knowledge foundation of Meritum. It stores, versions, and serves every external data set the platform depends on: the Schedule of Medical Benefits (SOMB) fee schedule, WCB Alberta fee schedule, governing rules, modifier definitions, diagnostic codes, functional centre codes, RRNP community rates, PCPCM basket classifications, the Alberta statutory holiday calendar, ICD-10-CA to ICD-9 crosswalk mappings, the Alberta Health provider registry for referral lookups, provincial PHN format definitions for reciprocal billing, structured billing guidance content, anesthesia benefit calculation rules (GR 12), multi-procedure bundling rules, reciprocal billing rules per province, and text justification templates. It also houses the contextual help content (tooltips and plain-language explanations) that surfaces throughout the UI.

Every claim validation decision, every AI Coach suggestion, every modifier prompt, and every rejection prevention check traces back to data in this domain. If Reference Data is wrong, everything downstream is wrong. Accuracy, currency, and versioning are existential requirements.

## 1.2 Scope

SOMB fee schedule: all Health Service Codes (HSCs), descriptions, base fees, rules, and specialty restrictions

WCB Alberta fee schedule: all WCB-specific codes, descriptions, and fees

Modifier definitions: type (explicit/implicit), applicability rules, rate calculations

Governing rules: GR 1, 3, 5, 6, 8, 11, 12, 13, surcharge rules — encoded as machine-readable validation rules

Functional centre codes and their facility type mappings

Diagnostic codes (ICD-9) used in Alberta billing

ICD-10-CA to ICD-9 crosswalk: many-to-many mapping with match quality scores for Connect Care import resolution

RRNP community rate table (community → percentage)

PCPCM basket classification (HSC → in-basket / out-of-basket / facility)

Alberta statutory holiday calendar (current year + next year)

Explanatory codes (AHCIP rejection/assessment response codes)

Alberta Health provider registry: searchable directory of practitioners for referral lookups (GR 8)

Provincial PHN format definitions: validation rules (length, regex, Luhn check) per province/territory for reciprocal billing

Reciprocal billing rules: per-province submission requirements, fee schedule sources, deadline days

Billing guidance: structured reference data for in-app tooltips — SOMB code descriptions, common rejection reasons, modifier eligibility hints, governing rule summaries

Anesthesia benefit calculation rules (GR 12): 10+ calculation scenarios with base units, time units, modifiers, concurrent procedure rules

Multi-procedure bundling rules: code-pair matrix defining bundled, independent, and intrinsically linked procedure combinations with AHCIP and WCB-specific relationships

Text justification templates: 5 scenario templates (unlisted procedure, additional compensation, pre-op conservative, post-op complication, WCB narrative) with variable interpolation

Effective-date versioning for all versioned data sets (supporting mid-year SOMB updates)

SOMB change summary generation (diff between versions)

Contextual help content: plain-language tooltips for codes, modifiers, governing rules, and billing concepts

Code search and autocomplete APIs consumed by Claim Lifecycle and Mobile Companion

Admin staging/versioning workflow for reference data updates before publishing

## 1.3 Out of Scope

Claim validation logic (Claim Lifecycle domain; consumes Reference Data via API)

AI Coach reasoning (Intelligence Engine domain; consumes Reference Data for rule basis)

Patient data (Patient Registry domain)

Physician profile and specialty data (Provider Management domain)

EMR field mapping templates (Claim Lifecycle domain)

Recent referrers per physician (Provider Management domain; consumes provider_registry from Reference Data)

Eligibility cache for PHN verification (Patient Registry domain; consumes provincial_phn_formats from Reference Data)

Claim justifications (Claim Lifecycle domain; consumes justification_templates from Reference Data)

## 1.4 Domain Dependencies

| Depends On | Provides To |
| --- | --- |
| Alberta Health (external) — SOMB publications, provider registry | Claim Lifecycle (Domain 4.0) |
| WCB Alberta (external) — WCB fee schedule | Intelligence Engine (Domain 7) |
| Identity & Access (Domain 1) — Admin auth | Analytics & Reporting (Domain 8) |
| CIHI (external) — ICD-10/ICD-9 crosswalk source | Mobile Companion (Domain 10) |
| Provincial ministries (external) — PHN format rules | Provider Management (Domain 5) |
| Notification Service (Domain 9) — event delivery | Onboarding (Domain 11) |
| — | Patient Registry (Domain 6) |
| — | Support System (Domain 13) |

## 1.5 Critical Design Constraint: Effective-Date Versioning

Alberta Health publishes SOMB updates (typically quarterly, occasionally mid-quarter). When a fee schedule change takes effect, there is a transition period where claims for dates of service before the change use old rates and claims for dates of service after the change use new rates. The 90-day submission window means a physician could be submitting claims spanning two fee schedule versions simultaneously.

Therefore, all versioned reference data must be versioned with effective dates. When a claim is validated, the system must select the reference data version that was in effect on the claim's date of service, not the current date. This applies to: HSC codes and fees, modifier rates, governing rules, WCB fee schedule, RRNP rates, PCPCM basket classifications, and the ICD crosswalk.

Implementation: Each data set has a versions table tracking version ID, effective_from date, effective_to date (NULL for current), and publication metadata. Every record in the data set carries a version_id foreign key. Queries always filter by the version that was effective on the date of service.

Non-versioned data sets: Statutory holidays (date-specific, not versioned), provider registry (live directory with last_synced_at), provincial PHN formats (static seed data), reciprocal billing rules (updated in-place), billing guidance (active/inactive toggle), anesthesia rules (active/inactive toggle), bundling rules (active/inactive toggle), and justification templates (active/inactive toggle) are managed without versioning. These data sets change infrequently and do not require date-of-service lookups.

# 2. Reference Data Sets

This section catalogues every data set managed by the Reference Data domain, its source, update frequency, and structure.

## 2.1 SOMB Fee Schedule

Source: Alberta Health — Schedule of Medical Benefits (SOMB), published as PDF with periodic bulletins

Update frequency: Quarterly (April 1, July 1, October 1, January 1) with occasional mid-quarter bulletins

Record count: ~6,000+ Health Service Codes

Ingestion method: Manual by Admin. SOMB is published as PDF; data must be extracted, validated against previous version, and loaded. Automated PDF parsing is a future enhancement; MVP relies on structured manual entry or semi-automated extraction with Admin verification.

Key fields per HSC record:

| Field | Type | Description |
| --- | --- | --- |
| hsc_code | VARCHAR(10) | Health Service Code (e.g., "03.04A"). Primary lookup field. |
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
| version_id | UUID | FK to reference_data_versions table |
| effective_from | DATE | Denormalised from version for query performance |
| effective_to | DATE | NULL for current version |

## 2.2 WCB Alberta Fee Schedule

Source: WCB Alberta — Physician Fee Schedule and Billing Guide

Update frequency: Typically annual; occasional mid-year updates

Ingestion method: Manual by Admin, same process as SOMB

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
| effective_from | DATE | |
| effective_to | DATE | NULL for current |

## 2.3 Modifier Definitions

Source: SOMB governing rules, AHCIP policy documents

Modifiers alter the fee or meaning of a claim. Some are explicit (physician must select them), some are implicit (system applies them automatically based on claim context).

| Field | Type | Description |
| --- | --- | --- |
| modifier_code | VARCHAR(10) | Modifier identifier (e.g., CMGP, LSCD, AFHR, TM, BCP, RRNP, ANE, AST) |
| name | VARCHAR(100) | Human-readable name |
| description | TEXT | Official definition |
| type | ENUM | explicit (physician selects), implicit (system applies), semi_implicit (system suggests, physician confirms) |
| calculation_method | ENUM | percentage, fixed_amount, time_based_units, multiplier, none |
| calculation_params | JSONB | Parameters for calculation: { percentage: 0.15, unit_minutes: 15, base_units: 1, ... } |
| applicable_hsc_filter | JSONB | Rules for which HSCs this modifier applies to: specialty, facility type, code patterns. Supports { all: true }, { codes: [...] }, and { prefixes: [...] } matching. |
| requires_time_documentation | BOOLEAN | Whether start/end time must be recorded |
| requires_facility | BOOLEAN | Whether a specific functional centre is required |
| combinable_with | JSONB | Array of modifier codes this can be combined with |
| exclusive_with | JSONB | Array of modifier codes this cannot be combined with (mutually exclusive) |
| governing_rule_reference | VARCHAR(20) | Which GR defines this modifier (e.g., GR 6) |
| help_text | TEXT | Plain-language tooltip |
| version_id | UUID | FK to modifier_versions |
| effective_from | DATE | |
| effective_to | DATE | |

### Modifier Reference (MVP)

| Modifier | Type | Calculation | Key Rules |
| --- | --- | --- | --- |
| CMGP | Semi-implicit | Time-based units (15 min increments after initial period) | Requires documented start/end time; not applicable to virtual care codes; GR 6 |
| LSCD | Explicit | Prolonged service add-on | Requires CMGP to be present; minimum threshold duration; GR 6 |
| AFHR | Implicit | Percentage premium on base fee | Applied automatically based on time of service vs. standard hours; stat holiday calendar aware; GR 6 |
| BCP | Implicit | Percentage premium on base fee | Bone and joint care premium; applied based on DI code (musculoskeletal); GR 6 |
| RRNP | Implicit | Community-specific percentage premium | Applied based on physician's practice location matching RRNP community table; rates vary by community (7%–30%+) |
| TM | Explicit | 5-minute allotment units | Shadow billing for ARP physicians; applied to all codes; time documentation required |
| ANE | Explicit | Anaesthesia modifier | For GPs providing anaesthesia in rural settings; specific fee calculation; GR 6 |
| AST | Explicit | Anaesthesia assist | For GPs assisting anaesthesia; GR 6 |
| Age modifiers | Implicit | Fee adjustment based on patient age | Applied automatically from patient DOB; different thresholds per code group (e.g., <2, <28 days, >65, >75) |
| Call-in codes | Explicit | Fixed fee codes (03.03KA/LA/MC/MD) | Separate billable codes for being called in; time-of-day dependent; stat holiday variants |

## 2.4 Governing Rules

Source: SOMB Preamble and Governing Rules section

Governing rules are the validation logic that determines whether a claim is valid before submission. They are encoded as machine-readable rule definitions that the Claim Lifecycle domain's validation engine evaluates. The Reference Data domain stores the rule definitions; the Claim Lifecycle domain executes them.

| Field | Type | Description |
| --- | --- | --- |
| rule_id | VARCHAR(20) | Governing rule identifier (e.g., GR3, GR5_3b, GR8, GR12, SURCHG_1399H) |
| rule_name | VARCHAR(200) | Human-readable rule name |
| rule_category | ENUM | visit_limits, code_combinations, modifier_rules, referral_rules, facility_rules, surcharge_rules, time_rules, general |
| description | TEXT | Official rule text from SOMB |
| rule_logic | JSONB | Machine-readable rule definition (see Section 2.4.1 for schema) |
| severity | ENUM | error (claim will be rejected), warning (claim may be rejected or suboptimal), info (advisory) |
| error_message | TEXT | Message displayed when rule is violated |
| help_text | TEXT | Plain-language explanation of what this rule means and why it matters |
| source_reference | VARCHAR(100) | Exact SOMB section reference (e.g., "SOMB Preamble, GR 5(3)(b)") |
| source_url | TEXT | Link to authoritative source document (for "Review recommended" citations) |
| version_id | UUID | FK to governing_rule_versions |
| effective_from | DATE | |
| effective_to | DATE | |

### 2.4.1 Rule Logic Schema

Each governing rule is encoded as a JSON object that the validation engine can evaluate against a claim context. The schema supports composable conditions:

| Rule | Category | Logic Pattern | Example |
| --- | --- | --- | --- |
| GR 1 | General | Global billing constraints | Maximum billable amount per day per physician; documentation requirements |
| GR 3 | Visit limits | { max_per_patient_per_day: N, hsc_group: [...], exceptions: [...] } | Office visits: max 1 per patient per day except with distinct DI codes |
| GR 5 | Code combinations | { hsc_a: pattern, hsc_b: pattern, relationship: allowed\|prohibited\|conditional, conditions: {...} } | 03.03A cannot be billed with 03.04A on same patient same day |
| GR 6 | Modifier rules | { modifier: code, requires: { time_documented: bool, min_duration: mins, facility_type: [...] }, conflicts: [...] } | CMGP requires documented time > 15 min; cannot combine with certain procedure codes |
| GR 8 | Referral rules | { hsc_pattern: regex, requires_referral: bool, referral_validity: days, exemptions: [...] } | Specialist consultations require valid referral < 12 months; GP self-referral exempt |
| GR 11 | Facility rules | { hsc_pattern: regex, required_facility_types: [...], prohibited_facility_types: [...] } | Hospital admission codes require hospital functional centre |
| GR 12 | Modifier rules | { scenario: code, base_units: N, time_unit_minutes: M, formula: expression } | Anesthesia benefit calculations — see Section 2.15 for detailed scenarios |
| GR 13 | Payment rules | Payment calculation rules and caps | Maximum payable amounts, holdback percentages |
| Surcharge 13.99H | Surcharge | { base_code: pattern, qualifying_di_codes: [...attachment_g...], surcharge_code: "13.99H" } | ED surcharge: qualifying DI from Attachment G + qualifying base code |
| Surcharge 13.99HA | Surcharge | { base_code: pattern, qualifying_di_codes: [...], surcharge_code: "13.99HA" } | Higher-acuity ED surcharge variant |
| PCPCM basket | Basket | { hsc: code, basket: in\|out\|facility, billing_route: ba_number } | In-basket codes route to PCPCM BA; out-of-basket to FFS BA |

Design note: The rule_logic JSONB field is not free-form. It follows a strict schema per rule_category. The validation engine in the Claim Lifecycle domain has a handler per category that knows how to evaluate the schema. This keeps the rules data-driven (updatable by Admin without code deployment) while ensuring the evaluation logic is well-defined and testable.

## 2.5 Functional Centre Codes

Source: AHCIP Electronic Claims Submission Specifications Manual

| Field | Type | Description |
| --- | --- | --- |
| code | VARCHAR(10) | Functional centre code |
| name | VARCHAR(200) | Facility name or description |
| facility_type | ENUM | office, hospital_inpatient, hospital_outpatient, emergency, auxiliary_hospital, nursing_home, telehealth, community_health, other |
| location_city | VARCHAR(100) | City/town |
| location_region | VARCHAR(50) | Health zone or region |
| rrnp_community_id | UUID | FK to RRNP community table (NULL if not RRNP-eligible) |
| active | BOOLEAN | Whether this centre is currently operational |
| version_id | UUID | |
| effective_from | DATE | |
| effective_to | DATE | |

## 2.6 Diagnostic Codes (ICD-9)

Source: ICD-9-CM as used by AHCIP (Alberta uses a subset with local extensions)

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
| version_id | UUID | |
| effective_from | DATE | |
| effective_to | DATE | |

## 2.7 RRNP Community Rate Table

Source: Alberta Health — Rural Remote Northern Program rate schedules

Update frequency: Annual or as negotiated

| Field | Type | Description |
| --- | --- | --- |
| community_id | UUID | PK |
| community_name | VARCHAR(200) | Name of community |
| rrnp_percentage | DECIMAL(5,2) | Premium percentage (e.g., 15.00 for 15%) |
| rrnp_tier | VARCHAR(20) | RRNP classification tier if applicable |
| region | VARCHAR(100) | Health zone |
| version_id | UUID | |
| effective_from | DATE | |
| effective_to | DATE | |

## 2.8 PCPCM Basket Classification

Source: Alberta Health — PCPCM program documentation

The PCPCM classification determines which billing arrangement (BA) a claim is routed to for physicians enrolled in PCPCM. In-basket codes route to the capitation BA; out-of-basket and facility codes route to the FFS BA.

| Field | Type | Description |
| --- | --- | --- |
| hsc_code | VARCHAR(10) | FK reference to SOMB HSC code |
| basket | ENUM | in_basket, out_of_basket, facility |
| notes | TEXT | Special routing notes or conditions |
| version_id | UUID | |
| effective_from | DATE | |
| effective_to | DATE | |

## 2.9 Alberta Statutory Holiday Calendar

Source: Alberta Employment Standards; federal holiday calendar

Update frequency: Annual (loaded for current year + next year)

The statutory holiday calendar is consumed by the rules engine for after-hours premium calculations. Some premiums differ on statutory holidays vs. regular evenings/weekends. The calendar must include both Alberta provincial statutory holidays and federally observed holidays that affect healthcare scheduling.

Alberta statutory holidays for reference: New Year's Day, Family Day (3rd Monday February), Good Friday, Victoria Day, Canada Day, Heritage Day (1st Monday August), Labour Day, National Day for Truth and Reconciliation (September 30), Thanksgiving, Remembrance Day, Christmas Day.

| Field | Type | Description |
| --- | --- | --- |
| holiday_id | UUID | PK |
| date | DATE | Holiday date (unique per date) |
| name | VARCHAR(100) | Holiday name (e.g., Family Day, Heritage Day, Canada Day) |
| jurisdiction | ENUM | provincial, federal, both |
| affects_billing_premiums | BOOLEAN | Whether this holiday triggers stat holiday premium rates (vs. regular after-hours) |
| year | INTEGER | Calendar year (for easy filtering) |

## 2.10 Explanatory Codes

Source: AHCIP assessment response specifications

Explanatory codes are returned by AHCIP in assessment responses to explain why a claim was paid, adjusted, or rejected. They are essential for the rejection management workflow.

| Field | Type | Description |
| --- | --- | --- |
| expl_code | VARCHAR(10) | AHCIP explanatory code |
| description | TEXT | Official AHCIP description |
| severity | ENUM | paid, adjusted, rejected |
| common_cause | TEXT | Meritum-authored plain-language explanation of what typically causes this code |
| suggested_action | TEXT | Meritum-authored guidance on how to resolve (for rejection management workflow) |
| help_text | TEXT | Tooltip text |
| version_id | UUID | |
| effective_from | DATE | |
| effective_to | DATE | |

## 2.11 Version Management Tables

Each versioned data set has its own entry in a unified versions table tracking publication history and effective date ranges.

| Field | Type | Description |
| --- | --- | --- |
| version_id | UUID | PK |
| data_set | ENUM | somb, wcb, modifiers, governing_rules, functional_centres, di_codes, rrnp, pcpcm, explanatory_codes, icd_crosswalk |
| version_label | VARCHAR(50) | Human-readable label (e.g., "2026-Q1", "2026-04-01 Bulletin") |
| effective_from | DATE | Date this version takes effect |
| effective_to | DATE | NULL for current; set when superseded |
| published_by | UUID | FK to users.id (Admin who loaded this version) |
| published_at | TIMESTAMP | When this version was loaded into Meritum |
| source_document | TEXT | Reference to the source publication (e.g., "SOMB April 2026 Update") |
| change_summary | TEXT | Human-readable summary of what changed (Meritum-authored) |
| records_added | INTEGER | Count of new records in this version |
| records_modified | INTEGER | Count of changed records |
| records_deprecated | INTEGER | Count of records no longer valid |
| is_active | BOOLEAN | Whether this is the current version (at most one active per data_set, enforced by partial unique index) |

## 2.12 ICD-10-CA to ICD-9 Crosswalk

Source: CIHI ICD-10-CA to ICD-9-CM crosswalk distribution, supplemented with Alberta-specific clinical mappings

Update frequency: Annually or on CIHI updates

Record count: ~100 initial seed entries covering top diagnoses; expandable to ~2,000+ mappings

Purpose: Alberta AHCIP claims require ICD-9 diagnostic codes, but Connect Care (AHS EMR) records diagnoses in ICD-10-CA. When a Connect Care SCC extract is imported and Connect Care's automatic ICD conversion fails (indicated by `icd_conversion_flag = true`), the crosswalk provides candidate ICD-9 codes for manual physician resolution. The mapping is many-to-many: one ICD-10 code may map to multiple ICD-9 candidates, and one ICD-9 code may be the target of multiple ICD-10 codes. Each mapping includes a match quality indicator and a preferred flag.

| Field | Type | Description |
| --- | --- | --- |
| id | UUID | PK |
| icd10_code | VARCHAR(10) | ICD-10-CA code (e.g., "J06.9") |
| icd10_description | TEXT | ICD-10-CA description |
| icd9_code | VARCHAR(10) | ICD-9-CM code (e.g., "465") |
| icd9_description | TEXT | ICD-9-CM description |
| match_quality | VARCHAR(20) | EXACT, APPROXIMATE, PARTIAL, MANY_TO_ONE — confidence of the mapping |
| is_preferred | BOOLEAN | Whether this is the recommended default mapping for the ICD-10 code |
| notes | TEXT | Clinical notes on the mapping (e.g., "ICD-9 599.0 is more specific") |
| version_id | UUID | FK to reference_data_versions (data_set = ICD_CROSSWALK) |
| effective_from | DATE | Denormalised from version |
| effective_to | DATE | NULL for current |

Seed data source: `apps/api/src/domains/reference/icd-crosswalk.seed.ts` — contains top 100 ICD-10-CA to ICD-9 mappings commonly encountered in Alberta Connect Care SCC extract conversions, covering primary care, musculoskeletal, cardiovascular, respiratory, gastrointestinal, endocrine, dermatological, genitourinary, neurological, ophthalmological, ENT, injury/trauma, mental health, obstetric, neoplasm, infectious disease, hematological, symptoms/signs, screening/preventive, renal, and WCB-common injury categories.

Consumed by: Domain 4.0 (Claim Lifecycle) — when `icd_conversion_flag = true` on imported claims, the claim form presents crosswalk candidates for physician selection. Domain 7 (Intelligence Engine) — for ICD code suggestion logic.

## 2.13 Alberta Health Provider Registry

Source: Alberta Health Provider Registry / CPSA registration data / H-Link inquiry

Update frequency: Monthly minimum refresh

Record count: ~10,000+ active practitioners

Purpose: Searchable directory of Alberta Health registered practitioners for referral lookups during claim entry. When an SOMB code requires a referring provider (per GR 8), the physician can search by name, CPSA registration number, specialty, or city. The registry is system-wide reference data — not physician-scoped.

| Field | Type | Description |
| --- | --- | --- |
| registry_id | UUID | PK |
| cpsa | VARCHAR(10) | CPSA registration number. Unique. Primary lookup field. |
| first_name | VARCHAR(50) | Practitioner first name |
| last_name | VARCHAR(50) | Practitioner last name |
| specialty_code | VARCHAR(10) | Practice discipline/specialty code |
| specialty_description | VARCHAR(100) | Human-readable specialty description |
| city | VARCHAR(100) | Primary city |
| facility_name | VARCHAR(200) | Primary facility/practice name |
| phone | VARCHAR(24) | Contact phone |
| fax | VARCHAR(24) | Contact fax |
| is_active | BOOLEAN | Soft delete flag (default true) |
| last_synced_at | TIMESTAMPTZ | When this record was last refreshed from the source |
| created_at | TIMESTAMPTZ | |
| updated_at | TIMESTAMPTZ | |

Indexes: Unique B-tree on `cpsa`. Trigram GIN index on `(last_name || ' ' || first_name)` for fuzzy/prefix name search. B-tree on `specialty_code`. B-tree on `city`.

Consumed by: Domain 4.0 (Claim Lifecycle) — referring provider search on the claim form for SOMB codes requiring referral per GR 8. Domain 5 (Provider Management) — recent referrers tracking per physician.

## 2.14 Billing Guidance

Source: Meritum-authored content derived from SOMB, WCB Physician's Resource Guide, AHCIP assessor expectations, and operational billing expertise

Update frequency: Ongoing — initial launch content covers top 20 most-billed SOMB codes, expanded incrementally

Purpose: Structured, updateable billing guidance content displayed as in-app tooltips during claim entry. Provides contextual help without requiring the physician to leave the application. Categories include SOMB code interpretations, common rejection reasons with thresholds, modifier guidance, ICD assistance, governing rule summaries, and new-to-practice extended explanations.

| Field | Type | Description |
| --- | --- | --- |
| guidance_id | UUID | PK |
| category | VARCHAR(30) | SOMB_INTERPRETATION, MODIFIER_GUIDANCE, WCB_GUIDANCE, CODING_TIPS, REGULATORY_UPDATE, BEST_PRACTICE |
| title | VARCHAR(200) | Short descriptive title |
| content | TEXT | Full guidance content (Markdown supported) |
| applicable_specialties | JSONB | Array of specialty codes this guidance applies to. Empty = all specialties. |
| applicable_hsc_codes | JSONB | Array of SOMB codes this guidance is associated with. Empty = general guidance. |
| source_reference | VARCHAR(200) | SOMB section, GR number, or policy document reference |
| source_url | TEXT | Link to authoritative source |
| sort_order | INTEGER | Display ordering within category |
| is_active | BOOLEAN | Active/inactive toggle (default true) |
| created_at | TIMESTAMPTZ | |
| updated_at | TIMESTAMPTZ | |

Indexes: Composite B-tree on `(category, is_active)`. GIN full-text search index on `content` for keyword search.

Consumed by: Domain 4.0 (Claim Lifecycle) — inline display on the claim form based on selected SOMB code, modifier, or diagnostic code. Global search results. Domain 7 (Intelligence Engine) — AI Coach consumes guidance content as part of its rule explanations.

## 2.15 Anesthesia Benefit Calculation Rules (GR 12)

Source: SOMB Governing Rule 12 — Anesthesia Benefits

Update frequency: With SOMB updates

Purpose: Structured rule definitions for the 10+ anesthesia calculation scenarios defined in GR 12. Used by the claim form's anesthesia calculator to compute total anesthetic benefit based on procedure type, duration, and modifiers. Replaces manual GR 12 interpretation with an automated calculation engine.

| Field | Type | Description |
| --- | --- | --- |
| rule_id | UUID | PK |
| scenario_code | VARCHAR(30) | Unique scenario identifier (e.g., SINGLE_PROCEDURE, MULTIPLE_PROCEDURE, COMPOUND_FRACTURE). Unique. |
| scenario_label | VARCHAR(100) | Human-readable scenario name |
| description | TEXT | Full description of the calculation scenario |
| base_units | INTEGER | Base anesthetic units for this scenario (NULL for time-based-only scenarios) |
| time_unit_minutes | INTEGER | Minutes per time unit (NULL for non-time-based scenarios) |
| calculation_formula | TEXT | Formula expression describing the computation (e.g., "base_units + ceil(duration / time_unit_minutes)") |
| applicable_modifiers | JSONB | Array of modifier codes that interact with this scenario |
| source_reference | VARCHAR(100) | SOMB GR 12 section reference |
| sort_order | INTEGER | Display ordering |
| is_active | BOOLEAN | Active/inactive toggle (default true) |
| created_at | TIMESTAMPTZ | |
| updated_at | TIMESTAMPTZ | |

Calculation scenarios:

| Scenario Code | Description | Calculation |
| --- | --- | --- |
| SINGLE_PROCEDURE | Single surgical procedure with anesthesia | Listed anesthetic value (base_units) |
| MULTIPLE_PROCEDURE | Multiple procedures under one anesthetic | Major at full rate, each additional at 50% |
| COMPOUND_FRACTURE | Compound fracture anesthesia | 50% uplift on base value |
| CLOSED_REDUCTION | Multiple closed-reduction fractures | Major + 50% each additional fracture |
| OPEN_REDUCTION | Open-reduction fractures | Each fracture at full rate + major at full |
| REDO_CARDIAC | Redo cardiac/thoracic/vascular | 150% through previous incision, 125% partly |
| SEQUENTIAL | Sequential unrelated procedures | Major + reduced rate for additional |
| TIME_BASED | Unlisted codes — time rate | SOMB time rate × duration |
| ORAL_SURGERY | Oral surgery under GR 6.9 | Separate rate table per GR 6.9 |
| SKIN_LESION_CAP | Skin lesion anesthesia cap | <35 min → single benefit regardless of lesion count |

Consumed by: Domain 4.0 (Claim Lifecycle) — claim form anesthesia calculator. Domain 7 (Intelligence Engine) — AI Coach anesthesia-related rules.

## 2.16 Multi-Procedure Bundling Rules

Source: SOMB governing rules + WCB Physician's Reference Guide

Update frequency: With SOMB/WCB updates

Purpose: Code-pair matrix defining bundling relationships between procedure codes. When a physician bills multiple procedure codes on the same patient on the same date, the bundling rules determine whether codes are billed independently at full rate, bundled (higher-value at full, secondary at reduced rate), or intrinsically linked (only one billable). AHCIP and WCB have different bundling rules for the same code pairs in some cases.

| Field | Type | Description |
| --- | --- | --- |
| rule_id | UUID | PK |
| code_a | VARCHAR(10) | First procedure code (canonical ordering: code_a < code_b) |
| code_b | VARCHAR(10) | Second procedure code |
| relationship | VARCHAR(30) | BUNDLED, INDEPENDENT, INTRINSICALLY_LINKED |
| description | TEXT | Human-readable description of the bundling relationship |
| override_allowed | BOOLEAN | Whether the physician can override the bundling decision with justification |
| source_reference | VARCHAR(100) | SOMB section or WCB reference |
| is_active | BOOLEAN | Active/inactive toggle (default true) |
| created_at | TIMESTAMPTZ | |
| updated_at | TIMESTAMPTZ | |

Constraints: Unique composite index on `(code_a, code_b)`. Canonical ordering enforced: code_a < code_b to avoid duplicate pairs. Separate B-tree indexes on `code_a` and `code_b` for pair lookups.

Consumed by: Domain 4.0 (Claim Lifecycle) — bundling check on multi-code claims, pre-submission validation. Domain 7 (Intelligence Engine) — AI Coach bundling rules for missed billing detection.

## 2.17 Provincial PHN Format Definitions

Source: Provincial ministry of health guidelines, CIHI standards

Update frequency: Annually or on provincial format changes

Purpose: PHN validation rules for all 13 Canadian provinces and territories. Enables reciprocal (out-of-province) billing by detecting the patient's home province from their health number format, validating the PHN against province-specific rules (length, regex pattern, check digit algorithm), and routing the claim appropriately. Alberta is the home province; all others trigger the reciprocal billing workflow. Quebec does not participate in reciprocal billing.

| Field | Type | Description |
| --- | --- | --- |
| id | UUID | PK |
| province_code | VARCHAR(2) | Two-letter province code (AB, BC, SK, MB, ON, QC, NB, NS, PE, NL, YT, NT, NU). Unique. |
| province_name | VARCHAR(50) | Full province name |
| phn_length | INTEGER | Expected digit count |
| phn_regex | VARCHAR(100) | Validation regular expression |
| validation_algorithm | VARCHAR(30) | Check digit algorithm (e.g., LUHN_VARIANT). NULL if no check digit. |
| notes | TEXT | Additional format notes |

Seed data source: `apps/api/src/domains/reference/provincial-phn-formats.seed.ts` — contains format definitions for all 13 provinces/territories with regex patterns, lengths, and reciprocal billing eligibility flags.

Provincial PHN format summary:

| Province | PHN Length | Format | Reciprocal Eligible |
| --- | --- | --- | --- |
| AB | 9 | 9 digits, Luhn check digit | N/A (home province) |
| BC | 10 | 10 digits starting with 9 | Yes |
| SK | 9 | 9 digits | Yes |
| MB | 9 | 9 digits | Yes |
| ON | 10 | 10 digits (NNNN-NNN-NNN), optional 2-letter version code | Yes |
| QC | 12 | 4 letters + 8 digits (RAMQ) | No (private billing only) |
| NB | 9 | 9 digits | Yes |
| NS | 10 | 10 digits | Yes |
| PE | 8 | 8 digits | Yes |
| NL | 12 | 12 digits (MCP) | Yes |
| YT | 9 | 9 digits | Yes |
| NT | 8 | 1 letter + 7 digits | Yes |
| NU | 9 | 9 digits | Yes |

Consumed by: Domain 6 (Patient Registry) — province auto-detection from PHN format, validation before saving. Domain 4.0 (Claim Lifecycle) — reciprocal billing flag on claim form.

## 2.18 Reciprocal Billing Rules

Source: Interprovincial Health Insurance Agreements, Alberta Health reciprocal billing policies

Update frequency: Annually or on agreement changes

Purpose: Per-province rules governing out-of-province patient billing. Defines the submission method (H-Link reciprocal, paper, private), fee schedule source (Alberta rates, home province rates), submission deadline, and any province-specific exclusions or special handling requirements.

| Field | Type | Description |
| --- | --- | --- |
| rule_id | UUID | PK |
| source_province | VARCHAR(2) | Patient's home province code |
| claim_type | VARCHAR(10) | AHCIP or WCB |
| submission_method | VARCHAR(30) | H-Link reciprocal, paper, private billing |
| fee_schedule_source | VARCHAR(30) | Which fee schedule to use (ALBERTA, HOME_PROVINCE) |
| deadline_days | INTEGER | Submission deadline in days from date of service |
| notes | TEXT | Province-specific instructions or exceptions |
| is_active | BOOLEAN | Active/inactive toggle (default true) |
| created_at | TIMESTAMPTZ | |
| updated_at | TIMESTAMPTZ | |

Constraints: Unique composite index on `(source_province, claim_type)`.

Consumed by: Domain 4.0 (Claim Lifecycle) — reciprocal billing validation and routing. Domain 6 (Patient Registry) — display province-specific billing guidance when out-of-province patient detected. Domain 8 (Analytics) — reciprocal billing volume reporting.

## 2.19 Text Justification Templates

Source: Meritum-authored from SOMB requirements, GR 2.6 (Additional Compensation), and Alberta Health assessor expectations

Update frequency: As needed

Purpose: Reusable structured text templates for the 5 justification scenarios that require narrative text on claims. Each template defines named fields (some auto-populated from claim context, some physician-entered), an output format for combining fields into the final justification text, and placeholders for variable interpolation. The physician fills in the fields; the system generates formatted justification text that can be edited before submission.

| Field | Type | Description |
| --- | --- | --- |
| template_id | UUID | PK |
| scenario | VARCHAR(40) | UNLISTED_PROCEDURE, ADDITIONAL_COMPENSATION, PRE_OP_CONSERVATIVE, POST_OP_COMPLICATION, WCB_NARRATIVE |
| name | VARCHAR(200) | Template display name |
| template_text | TEXT | Template text with `{{placeholder}}` markers for variable interpolation |
| placeholders | JSONB | Array of placeholder names corresponding to fields the physician must complete |
| applicable_specialties | JSONB | Array of specialty codes. Empty = all specialties. |
| sort_order | INTEGER | Display ordering within scenario |
| is_active | BOOLEAN | Active/inactive toggle (default true) |
| created_at | TIMESTAMPTZ | |
| updated_at | TIMESTAMPTZ | |

Justification scenarios:

| Scenario | Trigger | Key Fields |
| --- | --- | --- |
| UNLISTED_PROCEDURE | Unlisted SOMB code selected | Procedure description, indication, comparable listed code, time spent, requested benefit amount |
| ADDITIONAL_COMPENSATION | Physician invokes GR 2.6 | Nature of complexity, additional time, distinguishing circumstances |
| PRE_OP_CONSERVATIVE | Visit during surgical inclusive care period (pre-op) | Conservative treatment attempted, clinical decision rationale, pre-op visit dates |
| POST_OP_COMPLICATION | Visit during surgical inclusive care period (post-op) | Original procedure (auto), original date (auto), complication nature, clinical findings, treatment |
| WCB_NARRATIVE | WCB complex case | Treatment description, progress notes, work capacity assessment, return-to-work plan |

Consumed by: Domain 4.0 (Claim Lifecycle) — justification UI on the claim form. Generated text is attached to the claim as a `claim_justification` record.

## 2.20 Reference Data Staging Table

Staging area for versioned reference data uploads before validation and publishing. Supports the admin workflow: upload → validate → diff → publish/discard.

| Field | Type | Description |
| --- | --- | --- |
| staging_id | UUID | PK |
| data_set | VARCHAR(30) | Which reference data set this staging record belongs to |
| status | VARCHAR(20) | uploaded, validated, diff_generated, published, discarded |
| uploaded_by | UUID | FK to users.id (Admin who uploaded) |
| uploaded_at | TIMESTAMPTZ | Upload timestamp |
| file_hash | VARCHAR(64) | SHA-256 hash of the uploaded file for deduplication and audit |
| record_count | INTEGER | Number of records in the uploaded file |
| validation_result | JSONB | Validation results: { valid: boolean, errors: [...] } |
| diff_result | JSONB | Diff against active version: { added: [...], modified: [...], deprecated: [...], summary_stats } |
| staged_data | JSONB | Full parsed records from the uploaded file |
| created_at | TIMESTAMPTZ | |

# 3. User Stories & Acceptance Criteria

## 3.1 Code Search & Lookup

| REF-001 | HSC Code Search |
| --- | --- |
| User Story | As a physician entering a claim, I want to search for HSC codes by keyword, code number, or description so that I can quickly find the correct code without memorising the SOMB. |
| Acceptance Criteria | • Search accepts partial code match (e.g., "03.04" matches 03.04A, 03.04B, 03.04C) and keyword match against description (e.g., "consultation" returns all consultation codes). • Results are ranked by relevance, with the physician's most frequently used codes weighted higher (personalisation data from Claim Lifecycle). • Results are filtered by the physician's specialty: codes restricted to other specialties are excluded or shown greyed with an explanation. • Results are filtered by the currently selected practice setting/functional centre if context is available. • Each result displays: HSC code, description, base fee, and a one-line help tooltip. Clicking a result populates the claim form. • Search response time: <200ms for the first 10 results (autocomplete must feel instantaneous). • Search operates against the version of the SOMB effective on the claim's date of service. • If a code exists in a previous version but has been deprecated in the current version, it is flagged: "This code was deprecated effective [date]. Consider [replacement] instead." |

| REF-002 | Favourite / Most-Used Codes Palette |
| --- | --- |
| User Story | As an ED physician, I want my most-used codes available as a one-tap palette so that I can enter claims during a shift without searching. |
| Acceptance Criteria | • The system tracks the physician's top N codes by frequency (N configurable, default 20). • Favourite codes are displayed as a quick-access palette on the claim entry screen and the ED shift workflow screen. • The palette is ordered by frequency (most used first) and can be manually reordered by the physician. • Physicians can pin/unpin codes to the palette manually, overriding frequency-based ordering. • Palette contents update automatically as billing patterns change (recalculated weekly). • Palette is specialty-aware: a radiologist's palette shows imaging interpretation codes; an ED physician's shows emergency visit codes. |

| REF-003 | Diagnostic Code Search |
| --- | --- |
| User Story | As a physician, I want to search for ICD-9 diagnostic codes by keyword or code number so that I can quickly assign the correct diagnosis to a claim. |
| Acceptance Criteria | • Search accepts partial code match and keyword match against description and category. • Results weighted by the physician's specialty (common DI codes for their specialty ranked higher). • Results show: DI code, description, category, and any special flags (surcharge-qualifying, BCP-qualifying). • Search response time: <200ms. • If the selected DI code qualifies for a surcharge (Attachment G) or BCP modifier, a tooltip indicates this: "This diagnosis qualifies for the ED surcharge (13.99H)." The AI Coach in Claim Lifecycle acts on this, but the tooltip provides immediate context. |

| REF-004 | Modifier Lookup |
| --- | --- |
| User Story | As a physician, I want to understand what a modifier means and when it applies so that I can make informed billing decisions. |
| Acceptance Criteria | • Every modifier displayed in the claim entry UI has a tooltip accessible via an info icon. • Tooltip shows: modifier name, plain-language description, when it applies, how it affects the fee, and the governing rule reference. • Clicking "Learn more" expands to full explanation with the source SOMB/GR reference and a link to the authoritative document. • Implicit modifiers (AFHR, BCP, RRNP, age) are explained with "This modifier is applied automatically based on [time of service / diagnosis / location / patient age]." • Semi-implicit modifiers (CMGP) are explained with "Meritum will suggest this modifier when your encounter exceeds [threshold]. You can accept or dismiss the suggestion." |

## 3.2 Data Management (Admin)

| REF-005 | Load New SOMB Version |
| --- | --- |
| User Story | As an Admin, I want to load a new version of the SOMB fee schedule so that the platform reflects the latest Alberta Health publications. |
| Acceptance Criteria | • Admin uploads a structured data file (CSV or JSON) containing the new SOMB version's HSC records. • System validates the upload against the expected schema: required fields present, data types correct, HSC codes properly formatted, fees non-negative. • System generates a diff report comparing the new version against the current active version: new codes added, codes modified (with field-level changes highlighted), codes deprecated/removed. • Admin reviews the diff report and enters: version label, effective_from date, source document reference, and a human-readable change summary. • Admin confirms publication. System sets the new version as active (effective_from = specified date), sets the previous version's effective_to to the day before. • System emits a reference_data.version_published event consumed by the Notification Service to generate SOMB change summary notifications for physicians. • The change summary includes: count of new codes, modified codes, deprecated codes, plus the Admin-authored narrative summary. • All operations are audit-logged: admin_id, version_id, action, timestamp. • The upload can be performed in a staging state (version loaded but not published) to allow Admin to review before making it live. • Large change safety gate: if >500 modified or >100 deprecated records, system requires explicit confirmation before proceeding. |

| REF-006 | Load WCB Fee Schedule Update |
| --- | --- |
| User Story | As an Admin, I want to load a new WCB Alberta fee schedule so that WCB claim validation reflects current rates. |
| Acceptance Criteria | • Same workflow as REF-005 but for the WCB data set. • Diff report highlights fee changes, new codes, and deprecated codes. • WCB version publishing emits a separate event for WCB-specific change notifications. |

| REF-007 | Update Governing Rules |
| --- | --- |
| User Story | As an Admin, I want to update governing rules when Alberta Health publishes changes so that claim validation remains accurate. |
| Acceptance Criteria | • Admin selects the governing rule to update and modifies the rule_logic JSON, description, help_text, or any other fields. • System validates the rule_logic JSON against the schema for the rule's category (see Section 2.4.1). Invalid JSON is rejected with a descriptive error. • A new version of the governing rules data set is created. The old version's effective_to is set. • Admin can preview the effect of the rule change by running it against a sample of recent claims (dry run): "If this rule had been in effect, [X] claims would have been flagged differently." • Publication follows the same staging → review → publish workflow as SOMB updates. |

| REF-008 | Manage Statutory Holiday Calendar |
| --- | --- |
| User Story | As an Admin, I want to manage the statutory holiday calendar so that after-hours premiums are calculated correctly. |
| Acceptance Criteria | • Admin can view current year and next year's statutory holidays. • Admin can add, edit, or remove holidays. Standard Alberta holidays are pre-populated; Admin maintains them year-to-year. • Each holiday entry includes: date, name, jurisdiction, and whether it affects billing premiums. • Changes take effect immediately (no versioning needed; holidays are date-specific). • System alerts Admin annually (November) if next year's calendar has not been populated. |

## 3.3 SOMB Change Summaries

| REF-009 | SOMB Change Summary Notification |
| --- | --- |
| User Story | As a physician, I want to be notified when the fee schedule or governing rules change so that I can adjust my billing practices. |
| Acceptance Criteria | • When a new SOMB version is published (REF-005), the Notification Service delivers a change summary to all active physicians. • The notification includes: version label, effective date, Admin-authored narrative summary, counts of new/modified/deprecated codes. • Physicians can click through to a detailed change view in the platform showing the full diff relevant to their specialty (codes they've billed or could bill). • Deprecated codes that the physician has billed in the last 12 months are highlighted with urgency: "Code [X] which you billed [N] times is being deprecated effective [date]. Replacement: [Y]." • Fee changes are summarised with impact: "Code [X] fee changed from $[old] to $[new] ([+/-]%)." • The same mechanism applies to WCB fee schedule updates and governing rule changes. • Change summaries are archived and accessible from the Analytics dashboard. |

## 3.4 Contextual Help

| REF-010 | Contextual Help System |
| --- | --- |
| User Story | As a physician or delegate, I want plain-language tooltips on every billing concept I encounter so that I can learn as I work without leaving the application. |
| Acceptance Criteria | • Every HSC code, modifier, governing rule reference, explanatory code, and billing concept in the UI has an associated help_text field served by Reference Data. • Tooltips are written in plain language (not SOMB legalese): e.g., "CMGP: Add this when your visit took longer than 15 minutes. It adds time-based units to your claim, increasing the fee." • Tooltips include: what it is, when it applies, how it affects the fee, and the authoritative source reference. • Clicking "View source" opens the relevant SOMB section, governing rule, or WCB policy document (external link or embedded reference). • Help content is part of the Reference Data data set and updated alongside SOMB/GR updates. When a rule changes, its tooltip changes. • Help content is also consumed by the AI Support System (Phase 1.5) as part of the RAG knowledge corpus. |

## 3.5 ICD Crosswalk Resolution

| REF-011 | ICD-10 to ICD-9 Code Resolution |
| --- | --- |
| User Story | As a physician reviewing a Connect Care import, I want to resolve ICD-10-CA codes to their ICD-9 equivalents so that my AHCIP claims have valid diagnostic codes. |
| Acceptance Criteria | • When a claim is imported from Connect Care with `icd_conversion_flag = true`, the claim form presents a list of candidate ICD-9 codes from the crosswalk, ordered by match quality (EXACT first) and preferred flag. • The physician selects one ICD-9 code or enters a different one via the standard DI code search. • The selected ICD-9 code is stored on the claim; the original ICD-10-CA code is preserved in `icd10_source_code` for audit. • Crosswalk search supports code prefix matching and description keyword search. • The crosswalk is version-aware: results reflect the version effective on the claim's date of service. |

## 3.6 Referral Provider Search

| REF-012 | Referring Provider Lookup |
| --- | --- |
| User Story | As a physician entering a claim that requires a referring provider (GR 8), I want to search the Alberta provider registry by name, specialty, or location so that I can find the correct referrer quickly. |
| Acceptance Criteria | • Search accepts name (prefix and fuzzy match via pg_trgm), CPSA registration number (exact match), specialty code, and city filters. • Results display: name, CPSA number, specialty, city, facility. • Search response time: <200ms. • Selecting a provider populates the claim form's referring provider field. • The physician's 20 most recently used referrers are displayed above search results for quick access (managed by Provider Management domain). |

## 3.7 Billing Guidance

| REF-013 | In-App Billing Guidance |
| --- | --- |
| User Story | As a physician, I want contextual billing guidance to appear when I am entering a claim so that I can avoid common rejection reasons and bill optimally. |
| Acceptance Criteria | • When the physician selects a SOMB code on the claim form, any applicable billing guidance entries are displayed in a side panel. • Guidance categories: SOMB interpretation, modifier guidance, WCB-specific guidance, coding tips, regulatory updates, best practices. • Guidance entries can be filtered by specialty and searched by keyword. • Full-text search across guidance content is available. • Guidance entries include source references and links to authoritative documents. |

## 3.8 Anesthesia Calculator

| REF-014 | Anesthesia Benefit Calculator |
| --- | --- |
| User Story | As a GP providing anesthesia in a rural setting, I want an automated anesthesia benefit calculator so that I can correctly bill complex GR 12 scenarios without manual calculation errors. |
| Acceptance Criteria | • The calculator accepts: scenario code, procedure duration in minutes, and optional modifiers. • It returns: base units, time units, total units, and the formula used. • All 10 GR 12 scenarios are supported (see Section 2.15). • The calculator is version-aware and uses the current active anesthesia rules. • Results are displayed on the claim form alongside the fee calculation. |

## 3.9 Bundling Check

| REF-015 | Multi-Procedure Bundling Check |
| --- | --- |
| User Story | As a physician billing multiple procedures on the same date, I want the system to check for bundling conflicts so that my claim is not rejected for bundling violations. |
| Acceptance Criteria | • When two or more procedure codes are entered on a claim, the bundling rules are checked for all code pairs. • If a BUNDLED relationship exists, the system warns the physician: "Code [A] and Code [B] are bundled. [A] at full rate, [B] at [reduction_rate]% reduced rate." • If an INTRINSICALLY_LINKED relationship exists, the system warns: "Code [A] and Code [B] are intrinsically linked. Only the higher-value code is billable." • The physician can override the bundling decision with justification (if override_allowed = true). • Pair lookup uses canonical ordering (code_a < code_b) automatically. |

## 3.10 Reciprocal Billing

| REF-016 | Out-of-Province Billing Rules |
| --- | --- |
| User Story | As a physician treating an out-of-province patient, I want to know the reciprocal billing rules for their home province so that I submit the claim correctly. |
| Acceptance Criteria | • When an out-of-province patient is detected (via PHN format matching), the system displays the applicable reciprocal billing rules: submission method, fee schedule to use, deadline. • Quebec patients are flagged for private billing (no reciprocal agreement). • Provincial PHN format validation catches invalid health numbers before claim submission. • The rules are displayed on both the patient registry and the claim form. |

## 3.11 Justification Templates

| REF-017 | Text Justification Templates |
| --- | --- |
| User Story | As a physician, I want pre-built justification text templates so that I can quickly provide the required narrative text for claims that need justification. |
| Acceptance Criteria | • Templates are available for all 5 justification scenarios (unlisted procedure, additional compensation, pre-op conservative, post-op complication, WCB narrative). • Each template presents named fields — some auto-populated from claim context (e.g., original procedure date), some physician-entered. • The system generates formatted justification text from the field values using the template's output format. • The physician can edit the generated text before attaching it to the claim. • Templates can be filtered by scenario and specialty. |

# 4. API Contracts

All endpoints require authentication (via Identity & Access middleware). Admin endpoints require the admin role. Physician/delegate endpoints require active subscription (TRIAL, ACTIVE, or SUSPENDED).

## 4.1 Code Search & Lookup

| Method | Endpoint | Description | Auth |
| --- | --- | --- | --- |
| GET | /api/v1/ref/hsc/search?q={query}&specialty={code}&facility={type}&date={dos}&limit={n} | Search HSC codes. Returns: [{ hsc_code, description, base_fee, help_text, deprecated }]. Version-aware: uses SOMB version effective on date of service. | CLAIM_VIEW |
| GET | /api/v1/ref/hsc/{code}?date={dos} | Get full HSC detail including modifiers, restrictions, combination rules, help text. Version-aware. | CLAIM_VIEW |
| GET | /api/v1/ref/hsc/favourites | Get current user's top-N favourite codes (from usage data in Claim Lifecycle). Returns: [{ hsc_code, description, base_fee, frequency }]. | CLAIM_VIEW |
| GET | /api/v1/ref/di/search?q={query}&specialty={code}&limit={n} | Search diagnostic codes. Returns: [{ di_code, description, category, qualifies_surcharge, qualifies_bcp }]. | CLAIM_VIEW |
| GET | /api/v1/ref/di/{code} | Get full DI code detail. | CLAIM_VIEW |
| GET | /api/v1/ref/modifiers?hsc={code}&date={dos} | Get applicable modifiers for an HSC on a date. Returns: [{ modifier_code, name, type, calculation_method, help_text }]. If no HSC specified, returns all modifiers from active version. | CLAIM_VIEW |
| GET | /api/v1/ref/modifiers/{code} | Get full modifier detail. | CLAIM_VIEW |
| GET | /api/v1/ref/functional-centres?facility_type={type} | List functional centres, optionally filtered by facility type. | CLAIM_VIEW |
| GET | /api/v1/ref/explanatory-codes/{code} | Get explanatory code detail with common cause and suggested action. | CLAIM_VIEW |
| GET | /api/v1/ref/rrnp/{community_id}?date={dos} | Get RRNP rate for a community on a date. Returns: { community_name, rrnp_percentage }. | CLAIM_VIEW |
| GET | /api/v1/ref/pcpcm/{hsc_code}?date={dos} | Get PCPCM basket classification for an HSC. Returns: { basket, notes }. | CLAIM_VIEW |
| GET | /api/v1/ref/holidays?year={year} | Get statutory holidays for a year. Returns: [{ date, name, affects_billing }]. | CLAIM_VIEW |
| GET | /api/v1/ref/holidays/check?date={date} | Check if a specific date is a statutory holiday. Returns: { is_holiday, holiday_name? }. | CLAIM_VIEW |

## 4.2 ICD Crosswalk

| Method | Endpoint | Description | Auth |
| --- | --- | --- | --- |
| GET | /api/v1/ref/icd-crosswalk/{icd10_code}?date={dos} | Get candidate ICD-9 codes for an ICD-10-CA code. Returns: [{ icd10_code, icd10_description, icd9_code, icd9_description, match_quality, is_preferred, notes }]. Version-aware. Ordered by is_preferred DESC, match_quality. | CLAIM_VIEW |
| GET | /api/v1/ref/icd-crosswalk?q={query}&limit={n}&date={dos} | Search ICD crosswalk entries by code or description. Version-aware. | CLAIM_VIEW |

## 4.3 Provider Registry

| Method | Endpoint | Description | Auth |
| --- | --- | --- | --- |
| GET | /api/v1/ref/providers/search?q={query}&specialty={code}&city={city}&limit={n} | Search Alberta provider registry by name (fuzzy), specialty, or city. Returns: [{ registry_id, cpsa, first_name, last_name, specialty_code, specialty_description, city, facility_name }]. | CLAIM_VIEW |
| GET | /api/v1/ref/providers/{cpsa} | Get full provider registry detail by CPSA number. | CLAIM_VIEW |

## 4.4 Billing Guidance

| Method | Endpoint | Description | Auth |
| --- | --- | --- | --- |
| GET | /api/v1/ref/guidance?category={cat}&specialty={code}&hsc={code}&q={search}&page={n}&page_size={n} | List/search billing guidance entries. Supports category filtering, specialty filtering, HSC code filtering, and full-text search via `q` parameter. Paginated. | CLAIM_VIEW |
| GET | /api/v1/ref/guidance/{id} | Get full billing guidance entry by ID. | CLAIM_VIEW |

## 4.5 Provincial PHN Formats & Reciprocal Billing

| Method | Endpoint | Description | Auth |
| --- | --- | --- | --- |
| GET | /api/v1/ref/provincial-phn-formats | List all provincial PHN format definitions. Returns: [{ province_code, province_name, phn_length, phn_regex, validation_algorithm }]. | CLAIM_VIEW |
| GET | /api/v1/ref/reciprocal-rules/{province} | Get reciprocal billing rules for a source province. Returns: [{ rule_id, source_province, claim_type, submission_method, fee_schedule_source, deadline_days, notes }]. | CLAIM_VIEW |

## 4.6 Anesthesia Rules

| Method | Endpoint | Description | Auth |
| --- | --- | --- | --- |
| GET | /api/v1/ref/anesthesia-rules | List all active anesthesia rule scenarios. Returns: [{ rule_id, scenario_code, scenario_label, description, base_units, time_unit_minutes, calculation_formula }]. | CLAIM_VIEW |
| GET | /api/v1/ref/anesthesia-rules/{code} | Get full detail for a specific anesthesia scenario by scenario_code. | CLAIM_VIEW |
| POST | /api/v1/ref/anesthesia-rules/calculate | Calculate anesthesia benefit. Body: { scenario_code, time_minutes, base_units?, modifiers? }. Returns: { scenario_code, base_units, time_units, total_units, formula }. | CLAIM_VIEW |

## 4.7 Bundling Rules

| Method | Endpoint | Description | Auth |
| --- | --- | --- | --- |
| GET | /api/v1/ref/bundling-rules/pair/{code_a}/{code_b} | Get bundling rule for a specific code pair. Canonical ordering applied automatically. Returns: { rule_id, code_a, code_b, relationship, description, override_allowed, source_reference } or null if no rule exists. | CLAIM_VIEW |
| POST | /api/v1/ref/bundling-rules/check | Check a set of codes for bundling conflicts. Body: { codes: string[] }. Returns: { conflicts: [{ rule_id, code_a, code_b, relationship, description }] }. | CLAIM_VIEW |

## 4.8 Justification Templates

| Method | Endpoint | Description | Auth |
| --- | --- | --- | --- |
| GET | /api/v1/ref/justification-templates?scenario={scenario} | List active justification templates, optionally filtered by scenario. Returns: [{ template_id, scenario, name, template_text, placeholders, sort_order }]. | CLAIM_VIEW |
| GET | /api/v1/ref/justification-templates/{id} | Get full template detail by ID. | CLAIM_VIEW |

## 4.9 Validation Support (Internal)

These endpoints are consumed by the Claim Lifecycle domain's validation engine, not directly by the UI. They return the raw rule data needed for claim validation.

| Method | Endpoint | Description | Auth |
| --- | --- | --- | --- |
| GET | /api/v1/ref/rules/validate-context?hsc={codes}&di={code}&facility={fc}&date={dos}&modifiers={codes} | Returns all applicable governing rules for a claim context. Response includes the rule_logic JSON for each rule, enabling the Claim Lifecycle validation engine to evaluate them. Also returns HSC details, modifier applicability, facility validation, and version info. | Authenticated |
| GET | /api/v1/ref/rules/{rule_id}?date={dos} | Get a specific governing rule's full detail including rule_logic. | Authenticated |
| GET | /api/v1/ref/somb/version?date={dos} | Get the SOMB version effective on a date. Returns: { version_id, version_label, effective_from }. | Authenticated |
| POST | /api/v1/ref/rules/evaluate-batch | Return applicable rules for a batch of claims (up to 500). Body: { claims: [{ hscCodes, diCode?, facilityCode?, dateOfService, modifiers? }] }. Returns: [{ claimIndex, applicableRules }]. Groups claims by date to minimise version lookups. | Authenticated |

## 4.10 Admin Data Management

| Method | Endpoint | Description | Auth |
| --- | --- | --- | --- |
| POST | /api/v1/admin/ref/{dataset}/upload | Upload new version data. Body: multipart file (CSV/JSON, max 50 MB). Returns: { staging_id, validation_result, record_count, status }. Accepts text/csv, application/json, application/octet-stream. | Admin |
| GET | /api/v1/admin/ref/{dataset}/staging/{id}/diff | Get diff between staged version and current active version. Returns: { added: [...], modified: [...], deprecated: [...], summary_stats }. | Admin |
| POST | /api/v1/admin/ref/{dataset}/staging/{id}/publish | Publish staged version. Body: { version_label, effective_from, source_document, change_summary }. Returns: { version_id }. Large change safety gate applies. | Admin |
| DELETE | /api/v1/admin/ref/{dataset}/staging/{id} | Discard staged version. | Admin |
| GET | /api/v1/admin/ref/{dataset}/versions | List all versions for a data set with history. | Admin |
| POST | /api/v1/admin/ref/holidays | Add statutory holiday. Body: { date, name, jurisdiction, affects_billing_premiums }. | Admin |
| PUT | /api/v1/admin/ref/holidays/{id} | Update holiday. | Admin |
| DELETE | /api/v1/admin/ref/holidays/{id} | Remove holiday. | Admin |
| POST | /api/v1/admin/ref/rules/{rule_id}/dry-run | Dry-run a rule change against recent claims. Body: { updated_rule_logic }. Returns: { claims_affected, sample_results: [...] }. | Admin |

## 4.11 Change Summary Endpoints

| Method | Endpoint | Description | Auth |
| --- | --- | --- | --- |
| GET | /api/v1/ref/changes?dataset={ds}&since={date} | Get change summaries since a date. Returns: [{ version_label, effective_from, change_summary, stats }]. | Authenticated |
| GET | /api/v1/ref/changes/{version_id}/detail?specialty={code} | Get detailed diff filtered by physician's specialty. Returns: { added: [...], modified: [...], deprecated: [...], impact_summary }. | Authenticated |
| GET | /api/v1/ref/changes/{version_id}/physician-impact | Get personalised impact: codes the physician has billed that changed. Returns: { deprecated_codes_used: [...], fee_changes: [...], new_codes_relevant: [...] }. | Authenticated |

# 5. Search Architecture

Code search is a critical UX path. Physicians searching for an HSC code during claim entry expect autocomplete-speed responses (<200ms). The search architecture must support this.

## 5.1 Search Requirements

Full-text search across HSC codes, descriptions, and aliases (common names physicians use that don't match the SOMB description exactly)

Prefix matching on code numbers (e.g., "03.04" matches all 03.04* codes)

Fuzzy matching for typos (e.g., "consultatoin" matches "consultation")

Specialty filtering: exclude codes the physician cannot bill, or deprioritise them

Frequency weighting: codes the physician has billed recently are ranked higher

Version-aware: search results reflect the SOMB version effective on the claim's date of service

Performance: <200ms for the first page of results under normal load

Provider registry search: fuzzy name matching via pg_trgm for referral provider lookups

ICD crosswalk search: code prefix matching and description keyword search for ICD-10 to ICD-9 resolution

Billing guidance search: full-text search across guidance content for keyword discovery

## 5.2 Implementation

The implementation uses PostgreSQL full-text search (pg_trgm + ts_vector). At ~6,000 HSC records and ~14,000 DI codes, PostgreSQL FTS is more than adequate for performance:

HSC codes: GIN indexes on `to_tsvector('english', description)` for full-text search, plus `gin_trgm_ops` indexes on both `hsc_code` and `description` for fuzzy matching. Search combines ILIKE pattern matching, tsvector full-text, and trigram similarity scoring. Results are ranked by `GREATEST(similarity(hsc_code, query), similarity(description, query), ts_rank(...))`.

DI codes: Same indexing strategy as HSC codes, with additional specialty weighting: when a specialty filter is provided, codes with `common_in_specialty` containing the specialty are boosted.

WCB codes: Same search strategy as HSC codes.

Provider registry: Trigram GIN index on `(last_name || ' ' || first_name)` for fuzzy name search. B-tree indexes on `cpsa`, `specialty_code`, and `city` for filtered lookups.

ICD crosswalk: B-tree indexes on `(icd10_code, version_id)` and `(icd9_code, version_id)` for direct lookups.

Billing guidance: GIN index on `to_tsvector('english', content)` for full-text search.

# 6. Data Ingestion Process

Reference data ingestion is the highest-risk operational process in Meritum. Incorrect data means incorrect validation, which means incorrect claims. The ingestion process is designed with multiple safety gates.

## 6.1 SOMB Ingestion Workflow

1. Alberta Health publishes SOMB update (PDF + potentially structured data).

2. Admin extracts data into Meritum's structured format (CSV/JSON). For MVP, this is a manual or semi-automated process. The Admin is responsible for accuracy.

3. Admin uploads via the staging endpoint (REF-005). System validates schema (per-data-set validators check required fields, data types, allowed enum values, non-negative fees) and computes SHA-256 file hash. If validation passes, system auto-generates diff.

4. System generates diff report by comparing staged records against the active version using the data set's key field (e.g., hsc_code for SOMB, wcb_code for WCB). Admin reviews every change, paying special attention to fee changes, new codes, and deprecated codes.

5. Admin authors the change summary narrative and sets the effective date.

6. Admin publishes. The version goes live for claims with dates of service on or after the effective date. Previous version's effective_to is set to the day before the new version's effective_from.

7. Notification Service delivers SOMB change summary to all physicians via reference_data.version_published event. If deprecated codes were billed recently, a reference_data.code_deprecated event is emitted for targeted notifications.

## 6.2 Safety Gates

Schema validation: Per-data-set validators check required fields, data types (alphanumeric codes, non-negative fees, valid enum values, JSON arrays), and format constraints. Rejects invalid uploads before staging.

Diff review: Admin must review the diff report before publishing. Large unexpected changes trigger an additional confirmation gate:
- >500 modified records: "This is an unusually large change. Please confirm you have reviewed the diff carefully."
- >100 deprecated codes: Same confirmation required.
- The publish endpoint returns HTTP 409 Conflict if confirmLargeChange is not set.

Staging state: Data is loaded into a staging table with status progression: uploaded → validated → diff_generated → published (or discarded). It only becomes live on explicit publication. This allows Admin to review, test, and discard if needed.

Dry-run validation: Admin can run the new version against a sample of recent real claims to see how it would affect validation results. This catches rule encoding errors before they affect production.

Rollback: If a published version is found to contain errors, Admin can "rollback" by deactivating the erroneous version and re-activating the previous version. The erroneous version is preserved in the versions table for audit trail. Claims submitted against the erroneous version during the window can be flagged for review.

Audit trail: Every staging, publication, rollback, and discard action is logged with admin_id, timestamp, data_set, version_id, and affected record counts.

## 6.3 Initial Data Load (Pre-Launch)

Before launch, the complete current SOMB, WCB fee schedule, all governing rules, modifier definitions, functional centres, DI codes, RRNP rates, PCPCM baskets, statutory holidays, explanatory codes, ICD crosswalk seed data, provider registry, provincial PHN formats, and billing guidance content must be loaded and verified. This is a one-time effort that establishes the baseline.

SOMB: complete extraction from current published schedule. Estimated: 2–4 weeks of effort for initial structuring.

WCB: complete extraction from WCB Physician Fee Schedule.

Governing rules: manual encoding of each rule into the rule_logic JSON schema. The most labour-intensive task. Estimated: 2–3 weeks.

Modifiers: manual definition of each modifier with calculation parameters and applicability rules.

ICD crosswalk: seed data from `icd-crosswalk.seed.ts` (100 entries). Expanded from CIHI crosswalk distribution.

Provider registry: initial bulk load from Alberta Health Provider Registry. Monthly refresh cycle established.

Provincial PHN formats: seed data from `provincial-phn-formats.seed.ts` (13 entries). Static unless provincial format changes.

Billing guidance: initial content for top 20 most-billed SOMB codes. Expanded incrementally post-launch.

Anesthesia rules: manual encoding of all 10 GR 12 scenarios with calculation formulas.

Bundling rules: extraction from SOMB governing rules + WCB Physician's Reference Guide.

Reciprocal billing rules: extraction from Interprovincial Health Insurance Agreements.

Justification templates: authored from SOMB requirements and assessor expectations.

All other data sets: extraction from published Alberta Health sources.

Verification: test physician validates the reference data by entering real billing scenarios and confirming validation results match expected outcomes.

# 7. Interface Contracts with Other Domains

## 7.1 Claim Lifecycle (Primary Consumer)

The Claim Lifecycle domain is the primary consumer of Reference Data. It consumes:

HSC code details for claim creation and fee calculation

Governing rule definitions for pre-submission validation

Modifier definitions for eligibility checking and fee adjustment

Functional centre data for facility validation

DI codes for diagnostic code validation and surcharge/BCP qualification

ICD crosswalk for Connect Care import resolution (ICD-10 to ICD-9 mapping)

RRNP rates for premium calculation

PCPCM basket classification for BA routing

Statutory holidays for premium calculation

Explanatory codes for rejection management

Provider registry for referring provider lookups (GR 8)

Billing guidance for contextual help on the claim form

Anesthesia rules for GR 12 benefit calculation

Bundling rules for multi-procedure conflict detection

Reciprocal billing rules for out-of-province claim routing

Justification templates for structured narrative text generation

Provincial PHN formats for reciprocal billing province detection

Contract: Claim Lifecycle passes a date of service with every Reference Data query. Reference Data returns data from the version effective on that date. Claim Lifecycle never caches Reference Data beyond the current request (ensures version currency). The validate-context endpoint (Section 4.9) is the primary interface for batch validation.

## 7.2 Intelligence Engine

The Intelligence Engine (AI Billing Coach) consumes Reference Data for:

Rule definitions that drive the deterministic Tier 1 engine

Modifier applicability data for suggestion generation

Code combination data for missed billing detection

Help text and source references for Tier 2 LLM explanations and Tier 3 "review recommended" citations

Anesthesia rules for GR 12 scenario evaluation

Bundling rules for bundling/unbundling suggestions

Billing guidance content for AI Coach explanations

Contract: Intelligence Engine queries Reference Data the same way Claim Lifecycle does. It additionally consumes the source_reference and source_url fields for citation generation. The help_text fields are used to generate natural-language explanations without LLM involvement where possible.

## 7.3 Provider Management

Provider Management consumes Reference Data for:

Specialty code validation (physician's declared specialty must be a valid specialty in SOMB)

Functional centre lookup for practice location configuration

RRNP community lookup for practice location RRNP eligibility

Provider registry for recent referrers tracking (Domain 5 stores per-physician recent referrer usage; registry data comes from Domain 2)

## 7.4 Notification Service

Reference Data emits events consumed by the Notification Service:

| Event | Payload | Consumer Action |
| --- | --- | --- |
| reference_data.version_published | { data_set, version_id, version_label, effective_from, change_summary, records_added, records_modified, records_deprecated } | Generate and deliver SOMB/WCB/rule change summary notifications to all active physicians |
| reference_data.code_deprecated | { data_set, version_id, deprecated_codes, deprecated_count } | Generate targeted notifications to physicians who have billed deprecated codes in the last 12 months |
| reference_data.holiday_calendar_reminder | { year, message } | Remind Admin to populate next year's holiday calendar (emitted annually in November) |

## 7.5 Analytics & Reporting

Analytics consumes Reference Data for code descriptions, category labels, and fee information when generating reports and dashboards. All analytics queries pass through the same version-aware API to ensure historical accuracy (revenue reports for a past period use the fee schedule that was in effect during that period). Reciprocal billing volume is reported using reciprocal billing rules.

## 7.6 Patient Registry

Patient Registry consumes Reference Data for:

Provincial PHN format definitions for PHN validation and province auto-detection when registering out-of-province patients

Reciprocal billing rules for displaying province-specific billing guidance

## 7.7 Onboarding

Onboarding consumes Reference Data for specialty-specific defaults during physician setup, including specialty-appropriate code palettes and billing guidance content.

## 7.8 Support System (Phase 1.5)

The help_text, description, source_reference, and source_url fields across all data sets form the knowledge corpus for the AI-assisted support system. When the support system is built, it embeds this content into a vector store for RAG. Reference Data version updates trigger re-indexing of the support knowledge base. Billing guidance content is a primary corpus for the support system.

# 8. Security & Audit Requirements

## 8.1 Access Control

Read access (search, lookup, help text, crosswalk, guidance, templates): all authenticated users with active subscription (TRIAL, ACTIVE, SUSPENDED). Permission: CLAIM_VIEW.

Write access (upload, publish, edit, rollback): Admin role only.

Staging operations (upload, diff review, dry-run, discard): Admin role only.

Audit log queries related to Reference Data: Admin only.

Note: Reference Data tables do not contain PHI. All data is public reference data (fee schedules, codes, rules, provider registry). No physician scoping is required on Reference Data queries.

## 8.2 Audit Events

| Action | Detail Logged |
| --- | --- |
| ref.version_staged | admin_id, data_set, staging_id, record_count, file_hash, validation_passed |
| ref.version_diff_reviewed | admin_id, staging_id, diff_stats |
| ref.version_published | admin_id, version_id, data_set, effective_from, records_added, records_modified, records_deprecated |
| ref.version_rolled_back | admin_id, version_id, data_set, reason, previous_version_id |
| ref.staging_discarded | admin_id, staging_id, data_set |
| ref.rule_dry_run | admin_id, rule_id, claims_sampled, claims_affected |
| ref.holiday_created | admin_id, holiday_date, holiday_name |
| ref.holiday_updated | admin_id, holiday_id, old_values, new_values |
| ref.holiday_deleted | admin_id, holiday_id, holiday_date |

## 8.3 Data Integrity

All versioned reference data tables have version_id foreign keys with cascading constraints.

Published versions are immutable: once published, individual records cannot be edited. Corrections require a new version.

Staging data is isolated from live data (separate staging table with status progression).

Version activation is atomic: all records in a version become active simultaneously. Deactivation of previous version occurs before activation of new version.

Database constraints enforce that at most one version per data set is active (is_active = true) at any time (enforced by partial unique index on `(data_set) WHERE is_active = true`).

Non-versioned tables (provider_registry, billing_guidance, anesthesia_rules, bundling_rules, justification_templates) use `is_active` boolean for soft deletes and content management.

Canonical ordering constraint on bundling_rules: `code_a < code_b` enforced by unique index to prevent duplicate pairs.

# 9. Testing Requirements

## 9.1 Unit Tests

Version-aware query logic: given a date of service, correct version is selected across all data sets

Version boundary: claim on effective_from date uses new version; claim on day before uses old version

HSC search: keyword match, code prefix match, fuzzy match, specialty filtering, frequency weighting

DI code search: keyword match, code prefix match, specialty weighting, surcharge/BCP flag accuracy

Modifier applicability: given an HSC + context, correct modifiers returned; incompatible modifiers excluded. Filter matching: { all: true }, { codes: [...] }, { prefixes: [...] }

Governing rule logic parsing: each rule_category handler correctly evaluates its JSON schema

RRNP rate lookup: correct percentage returned for community + date of service

PCPCM basket classification: correct basket returned for HSC + date of service

Statutory holiday check: dates correctly identified as holidays; non-holidays return false

Diff generation: correctly identifies added, modified, and deprecated records between versions. Field-level changes captured accurately.

Schema validation: per-data-set validators reject invalid uploads with clear field-level error messages

ICD crosswalk lookup: given an ICD-10 code, correct ICD-9 candidates returned ordered by match quality and preferred flag

ICD crosswalk search: code prefix and description keyword search return relevant results

Provider registry search: name fuzzy match, CPSA exact match, specialty and city filtering

Billing guidance: category filtering, specialty filtering, HSC code filtering, full-text search

Anesthesia calculation: each of the 10 scenarios returns correct base_units + time_units + total_units for given durations

Bundling pair lookup: canonical ordering applied automatically; correct relationship returned

Bundling conflict check: given a set of codes, all pairwise conflicts identified

Provincial PHN format: correct regex and length validation per province

Reciprocal billing rules: correct rules returned for each source province

Justification templates: correct template returned for scenario; placeholder list matches template_text markers

CSV parsing: correctly handles headers, data types, boolean coercion, JSON arrays, numeric values

## 9.2 Integration Tests

Full ingestion workflow: upload → staging → diff → publish → verify live data

Version transition: publish new version, verify claims for old DOS use old version, claims for new DOS use new version

Rollback: publish → rollback → verify previous version is active

SOMB change notification: publish triggers event, Notification Service delivers change summary

Claim Lifecycle integration: create claim → Reference Data supplies correct validation rules → validation result accurate

Search performance: <200ms response time with full SOMB dataset loaded

Concurrent version queries: simultaneous requests for different dates of service return correct versions

Large change safety gate: verify 409 returned when thresholds exceeded without confirmation

ICD crosswalk resolution: import with icd_conversion_flag → crosswalk candidates presented → selection persisted

Provider registry search: fuzzy name match returns expected results; CPSA exact match works

Anesthesia calculator: end-to-end calculation via POST endpoint returns correct results

Bundling check: multi-code submission triggers appropriate bundling warnings

## 9.3 Data Accuracy Tests

Sample verification: randomly select 100 HSC codes from published SOMB, verify all fields match

Governing rule accuracy: for each encoded governing rule, verify against 5+ known claim scenarios with expected outcomes

RRNP rate verification: verify rates for 10+ communities against published Alberta Health rates

Statutory holiday verification: verify all holidays for current year match published Alberta calendar

Cross-reference consistency: HSC codes referenced in governing rules, modifier definitions, and PCPCM baskets all exist in the SOMB data set

ICD crosswalk accuracy: verify top 50 mappings against CIHI crosswalk source

Provincial PHN format accuracy: verify regex patterns correctly validate and reject sample PHNs for each province

# 10. Consumed-By Dependency Map

This section summarises which domains consume which reference data sets for implementation planning.

| Reference Data Set | Consumed By | Interface |
| --- | --- | --- |
| SOMB Fee Schedule | Claim Lifecycle, Intelligence Engine, Analytics, Mobile Companion | HSC search/detail API, validate-context |
| WCB Fee Schedule | Claim Lifecycle, Intelligence Engine, Analytics | WCB search/detail API |
| Modifier Definitions | Claim Lifecycle, Intelligence Engine | Modifier lookup API, validate-context |
| Governing Rules | Claim Lifecycle, Intelligence Engine | validate-context, evaluate-batch, rule detail API |
| Functional Centres | Claim Lifecycle, Provider Management, Onboarding | FC list API, validate-context |
| Diagnostic Codes (ICD-9) | Claim Lifecycle, Intelligence Engine, Analytics | DI search/detail API |
| ICD Crosswalk | Claim Lifecycle (Connect Care import) | Crosswalk lookup/search API |
| RRNP Communities | Claim Lifecycle, Provider Management | RRNP rate API |
| PCPCM Baskets | Claim Lifecycle | PCPCM basket API |
| Statutory Holidays | Claim Lifecycle (premium calc) | Holiday check API |
| Explanatory Codes | Claim Lifecycle (rejection management) | Explanatory code detail API |
| Provider Registry | Claim Lifecycle (referral), Provider Management (recent referrers) | Provider search API |
| Billing Guidance | Claim Lifecycle (inline help), Intelligence Engine, Support System | Guidance list/search API |
| Provincial PHN Formats | Patient Registry (validation), Claim Lifecycle (reciprocal) | PHN formats list API |
| Reciprocal Billing Rules | Claim Lifecycle, Patient Registry, Analytics | Reciprocal rules API |
| Anesthesia Rules | Claim Lifecycle (calculator), Intelligence Engine | Anesthesia rules/calculate API |
| Bundling Rules | Claim Lifecycle (validation), Intelligence Engine | Bundling pair/check API |
| Justification Templates | Claim Lifecycle (justification UI) | Templates list/detail API |

# 11. Initial Data Load Estimate

The pre-launch data load is the most time-consuming preparation task for the Reference Data domain. This section provides effort estimates for the initial baseline load.

| Data Set | Approximate Volume | Effort Estimate | Notes |
| --- | --- | --- | --- |
| SOMB fee schedule | ~6,000+ HSC records | 2–4 weeks | Largest dataset; PDF extraction is primary bottleneck; LLM-assisted extraction could accelerate |
| WCB fee schedule | ~500–1,000 records | 3–5 days | Many codes overlap with SOMB; WCB-specific codes are the delta |
| Governing rules | ~50–80 individual rules across GR 1–13 + surcharge rules | 2–3 weeks | Most intellectually demanding task; each rule must be encoded as machine-readable JSON and verified against known scenarios |
| Modifier definitions | ~15–20 modifiers | 3–5 days | Includes calculation parameters and applicability rules |
| Functional centres | ~2,000–3,000 codes | 3–5 days | Published by AHCIP; relatively clean source data |
| ICD-9 diagnostic codes | ~14,000 codes (Alberta subset) | 1 week | Published reference; bulk importable; adding surcharge/BCP flags requires cross-referencing Attachment G |
| ICD-10 to ICD-9 crosswalk | ~100 seed entries (expandable to ~2,000+) | 2–3 days | Seed data pre-built in icd-crosswalk.seed.ts; CIHI crosswalk expansion TBD |
| RRNP community rates | ~100–200 communities | 1–2 days | Published by Alberta Health |
| PCPCM baskets | ~3,000–4,000 HSC classifications | 3–5 days | Cross-reference with SOMB; published by Alberta Health |
| Statutory holidays | ~11 holidays/year | 1 hour | Standard list; populate current + next year |
| Explanatory codes | ~100–200 codes | 2–3 days | Published by AHCIP; plain-language help text must be authored |
| Provider registry | ~10,000+ practitioners | 2–3 days | Bulk load from Alberta Health; monthly refresh cycle |
| Provincial PHN formats | 13 provinces/territories | 1 hour | Seed data pre-built in provincial-phn-formats.seed.ts |
| Reciprocal billing rules | ~12 province-specific rule sets | 1–2 days | Extracted from Interprovincial Health Insurance Agreements |
| Billing guidance | Top 20 SOMB codes initially | 3–5 days | Meritum-authored content; expanded incrementally post-launch |
| Anesthesia rules (GR 12) | 10 calculation scenarios | 2–3 days | Manual encoding from SOMB GR 12; calculation formulas require verification |
| Bundling rules | ~200–500 code pairs | 3–5 days | Extracted from SOMB governing rules + WCB Physician's Reference Guide |
| Justification templates | 5 scenario templates | 1–2 days | Meritum-authored from SOMB and assessor expectations |
| Help text / tooltips | All records across all datasets | Ongoing (parallel with other loads) | Authored incrementally as each data set is loaded; priority on high-use codes and modifiers |
| TOTAL | | 8–14 weeks | Critical path item; can partially overlap with application development |

# 12. Document Control

Parent document: Meritum PRD v1.3

Domain: Reference Data (Domain 2 of 13)

Build sequence position: 2nd (depends on Identity & Access for auth context and Admin role; no other Meritum domain dependencies)

Downstream consumers: Claim Lifecycle, Intelligence Engine, Analytics & Reporting, Mobile Companion, Provider Management, Onboarding, Patient Registry, Support System

| Version | Date | Author | Changes |
| --- | --- | --- | --- |
| 1.0 | February 12, 2026 | Ian Sharland | Initial Reference Data functional requirements |
| 2.0 | February 27, 2026 | Ian Sharland | Added ICD-10-CA to ICD-9 crosswalk (CC-001), provider registry (B1), billing guidance (B6), anesthesia rules GR 12 (B7), provincial PHN formats and reciprocal billing rules (B8), multi-procedure bundling rules (B9), text justification templates (B11), staging table specification, search implementation details, expanded API contracts, consumed-by dependency map, updated data load estimates |
