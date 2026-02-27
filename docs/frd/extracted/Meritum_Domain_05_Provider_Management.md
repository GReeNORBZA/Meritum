# Meritum_Domain_05_Provider_Management

MERITUM

Functional Requirements

Provider Management

Domain 5 of 13  |  Critical Path: Position 5

Meritum Health Technologies Inc.

Version 2.0  |  February 2026

CONFIDENTIAL

# Table of Contents

1. [Domain Overview](#1-domain-overview)
2. [Data Model](#2-data-model)
3. [Delegate Permission Model](#3-delegate-permission-model)
4. [PCPCM Routing Logic](#4-pcpcm-routing-logic)
5. [Mixed FFS/ARP Smart Routing](#5-mixed-ffsarp-smart-routing)
6. [PCPCM Payment Reconciliation](#6-pcpcm-payment-reconciliation)
7. [Connect Care User Support](#7-connect-care-user-support)
8. [User Stories & Acceptance Criteria](#8-user-stories--acceptance-criteria)
9. [API Contracts](#9-api-contracts)
10. [Provider Context Object](#10-provider-context-object)
11. [Locum Support](#11-locum-support)
12. [Onboarding Workflow](#12-onboarding-workflow)
13. [Security & Audit](#13-security--audit)
14. [Testing Requirements](#14-testing-requirements)
15. [Open Questions](#15-open-questions)
16. [Document Control](#16-document-control)

# 1. Domain Overview

## 1.1 Purpose

The Provider Management domain owns the physician's professional identity within Meritum. It is the authoritative source for everything the platform needs to know about a physician's billing configuration: their Business Arrangement (BA) numbers and subtypes (FFS, ARP, PCPCM), specialty, practice locations, PCPCM enrolment and payment reconciliation status, RRNP eligibility, WCB Contract ID and Role, delegate relationships, submission preferences, Connect Care user status, and smart routing configuration.

Every claim created in the Claim Lifecycle (Domain 4) inherits context from this domain — the BA number it routes to (resolved via the four-level smart routing priority chain), the functional centre it bills from, the governing rules that apply, the fee modifiers that are eligible, and the auto-submission mode that determines how it enters a batch. Provider Management is the second most consumed domain in the platform after Reference Data.

## 1.2 Scope

Physician professional profile: name, CPSA registration, specialty, billing numbers, Connect Care user flag

Business Arrangement (BA) management: single-BA and multi-BA configurations (FFS, ARP, PCPCM), BA subtypes (ANNUALISED, SESSIONAL, BCM for ARP), BA status tracking

Practice locations: functional centres, multi-site support, locum arrangements

Facility-BA mapping: maps practice locations to BAs for smart claim routing

Time-based routing schedules: schedule mappings defining which BA is active by day-of-week and time-of-day windows

PCPCM enrolment management: basket classification routing, panel size tracking, dual-BA configuration

PCPCM payment reconciliation: capitation payment recording, expected vs actual reconciliation, panel size updates, payment history

RRNP eligibility: community-based qualification, rate lookup

WCB configuration: Contract ID, Role code, permitted form types

Delegate relationships: invitation, permission granting, physician-delegate linkage (operational; auth enforcement is Domain 1)

Submission preferences: auto-submission mode, batch review settings

H-Link configuration: submitter prefix, transmission credentials reference

Provider onboarding: profile setup during registration, guided BA configuration, IMA generation triggers

## 1.3 Out of Scope

Authentication, session management, MFA (Domain 1 Identity & Access)

Delegate RBAC enforcement at the API layer (Domain 1; this domain manages the relationship, Domain 1 enforces it)

SOMB schedule, governing rules, fee schedules (Domain 2 Reference Data; this domain references them)

Claim creation and processing (Domain 4 Claim Lifecycle; consumes provider context from here)

Patient demographics (Domain 6 Patient Registry)

Stripe subscription and payment management (Platform Operations)

Shift scheduling and encounter logging (Domain 10 Mobile Companion; consumes Connect Care flag from here)

## 1.4 Domain Dependencies

| Domain | Direction | Interface |
| --- | --- | --- |
| 1 Identity & Access | Consumed | User account linkage (one user = one provider). Auth context carries provider_id. Delegate permission enforcement. |
| 2 Reference Data | Consumed | RRNP rate lookup by community. PCPCM basket classification. Specialty-specific governing rule applicability. WCB Contract ID/Role/Form ID matrix. ARP S-code set. |
| 3 Notification Service | Consumed | BA status change alerts, delegate invitation notifications, accreditation reminders, PCPCM payment discrepancy alerts, routing mis-route summaries. |
| 4.0 Claim Lifecycle Core | Consumed by | BA number, functional centre, specialty, PCPCM status, RRNP eligibility, submission preferences, WCB config, smart routing resolution. |
| 4.1 AHCIP Pathway | Consumed by | BA number(s), submitter prefix, H-Link credentials reference, PCPCM basket routing. |
| 4.2 WCB Pathway | Consumed by | WCB Contract ID, Role code, permitted form types, billing number, skill code. |
| 7 Intelligence Engine | Consumed by | Physician specialty, practice patterns, location context for AI Coach calibration. |
| 8 Analytics | Consumed by | Multi-site breakdown dimensions, BA-level revenue attribution, ARP-specific analytics (TM units, shadow billing). |
| 10 Mobile Companion | Consumed by | Connect Care user flag, practice locations for shift scheduling. |
| 11 Onboarding | Consumed by | BA type/subtype labelling, facility-BA mapping during onboarding. |

# 2. Data Model

## 2.1 Providers Table (providers)

The central table of this domain. One row per physician. Linked 1:1 to the users table in Domain 1 (Identity & Access).

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| provider_id | UUID | No | Primary key. Same value as user_id in Domain 1 users table. |
| billing_number | VARCHAR(10) | No | AHCIP practitioner ID (prac ID). Unique to each physician. Used in H-Link submissions. |
| cpsa_registration_number | VARCHAR(10) | No | College of Physicians & Surgeons of Alberta registration. Verified during onboarding. |
| first_name | VARCHAR(50) | No | Legal first name |
| middle_name | VARCHAR(50) | Yes | Legal middle name |
| last_name | VARCHAR(50) | No | Legal last name |
| specialty_code | VARCHAR(10) | No | Primary specialty. Maps to AHCIP specialty codes. Determines governing rule applicability. |
| specialty_description | VARCHAR(100) | Yes | Human-readable specialty name |
| sub_specialty_code | VARCHAR(10) | Yes | Sub-specialty if applicable |
| physician_type | VARCHAR(20) | No | GP, SPECIALIST, LOCUM. Determines UI workflow and default validation context. |
| status | VARCHAR(20) | No | ACTIVE, SUSPENDED, INACTIVE. SUSPENDED when subscription lapses (claims preserved, submission blocked). |
| onboarding_completed | BOOLEAN | No | True when profile setup wizard is complete. Claims cannot be created until true. |
| is_connect_care_user | BOOLEAN | No | Whether the physician uses Connect Care for clinical documentation. Default false. Controls mobile app mode (shift-first vs claim-first). |
| connect_care_enabled_at | TIMESTAMPTZ | Yes | When Connect Care mode was first enabled. Null if never enabled. |
| created_at | TIMESTAMPTZ | No | |
| updated_at | TIMESTAMPTZ | No | |

Indexes: (billing_number) unique, (cpsa_registration_number) unique, (specialty_code), (status).

## 2.2 Business Arrangements Table (business_arrangements)

A physician may have one or more active BAs. Standard FFS physicians have one. PCPCM-enrolled physicians have two: a PCPCM BA and a FFS BA. Mixed FFS/ARP physicians have two: an ARP BA and a FFS BA. The BA number determines which claims batch together and where payment is deposited.

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| ba_id | UUID | No | Primary key |
| provider_id | UUID FK | No | FK to providers |
| ba_number | VARCHAR(10) | No | Business Arrangement number assigned by Alberta Health |
| ba_type | VARCHAR(10) | No | FFS, PCPCM, ARP. Determines fee routing and claim handling. |
| ba_subtype | VARCHAR(20) | Yes | For ARP BAs: ANNUALISED, SESSIONAL, BCM. Null for FFS and PCPCM. Determines ARP-specific billing rules and analytics grouping. |
| is_primary | BOOLEAN | No | True for the primary BA. For dual-BA physicians, the FFS BA is primary. |
| status | VARCHAR(20) | No | ACTIVE, PENDING, INACTIVE. PENDING during initial setup before Alberta Health confirms linkage. |
| effective_date | DATE | Yes | When the BA became active |
| end_date | DATE | Yes | When the BA was deactivated (null if active) |
| created_at | TIMESTAMPTZ | No | |
| updated_at | TIMESTAMPTZ | No | |

Constraints: Maximum 2 active BAs per provider. If ba_type = PCPCM, a second BA with ba_type = FFS must exist. ba_number unique across active (non-INACTIVE) records via partial unique index.

Indexes: (provider_id, status), partial unique on (ba_number) where status != 'INACTIVE'.

## 2.3 PCPCM Enrolments Table (pcpcm_enrolments)

Tracks PCPCM enrolment details for physicians participating in the Patient's Choice Primary Care Model. Only applicable to physicians with a PCPCM-type BA. Links the PCPCM BA to its paired FFS BA.

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| enrolment_id | UUID | No | Primary key |
| provider_id | UUID FK | No | FK to providers |
| pcpcm_ba_id | UUID FK | No | FK to business_arrangements (the PCPCM BA) |
| ffs_ba_id | UUID FK | No | FK to business_arrangements (the paired FFS BA) |
| panel_size | INTEGER | Yes | Current PCPCM panel size. Updated from Alberta Health quarterly Panel Attribution Reports. |
| enrolment_date | DATE | No | When the physician enrolled in PCPCM |
| status | VARCHAR(20) | No | ACTIVE, PENDING, WITHDRAWN |
| created_at | TIMESTAMPTZ | No | |
| updated_at | TIMESTAMPTZ | No | |

Constraints: One active (non-WITHDRAWN) enrolment per provider via partial unique index.

Indexes: (provider_id, status), partial unique on (provider_id) where status != 'WITHDRAWN'.

## 2.4 PCPCM Payments Table (pcpcm_payments)

Tracks PCPCM capitation payments received from Alberta Health and reconciliation against expected amounts based on panel size. Physician-scoped via provider_id FK.

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| payment_id | UUID | No | Primary key |
| provider_id | UUID FK | No | FK to providers. Physician receiving the payment. |
| enrolment_id | UUID FK | No | FK to pcpcm_enrolments. PCPCM enrolment reference. |
| payment_period_start | DATE | No | Start of payment period |
| payment_period_end | DATE | No | End of payment period |
| expected_amount | DECIMAL(10,2) | Yes | Expected capitation based on panel size |
| actual_amount | DECIMAL(10,2) | Yes | Actual amount received from Alberta Health |
| panel_size_at_payment | INTEGER | Yes | Panel size at time of payment |
| status | VARCHAR(20) | No | EXPECTED, RECEIVED, RECONCILED, DISCREPANCY. Default: EXPECTED. |
| reconciled_at | TIMESTAMPTZ | Yes | When reconciliation was performed |
| notes | TEXT | Yes | Reconciliation notes, discrepancy details |
| created_at | TIMESTAMPTZ | No | |

Indexes: (provider_id), (enrolment_id), (provider_id, payment_period_end), (status).

## 2.5 PCPCM Panel Estimates Table (pcpcm_panel_estimates) — Schema Only (Post-MVP)

Schema scaffolding for future panel size estimation from Meritum claim data. Not actively used at MVP. Future implementation will estimate panel size from claim history as a sanity check alongside the manual entry from Alberta Health quarterly Panel Attribution Reports.

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| estimate_id | UUID | No | Primary key |
| provider_id | UUID FK | No | FK to providers |
| enrolment_id | UUID FK | No | FK to pcpcm_enrolments |
| estimation_method | VARCHAR(30) | No | CLAIM_HISTORY, AH_REPORT_PARSED, MANUAL |
| estimated_panel_size | INTEGER | No | Estimated number of attributed patients |
| unique_patients_12m | INTEGER | Yes | Distinct patients seen in rolling 12 months (for CLAIM_HISTORY method) |
| confidence | VARCHAR(10) | Yes | HIGH, MEDIUM, LOW — how closely estimate matches known panel methodology |
| period_start | DATE | No | Start of estimation period |
| period_end | DATE | No | End of estimation period |
| created_at | TIMESTAMPTZ | No | |

Indexes: (provider_id, period_end).

## 2.6 Practice Locations Table (practice_locations)

A physician may practise at multiple locations (multi-site) or different locations in different months (locum). Each location maps to an AHCIP functional centre, which affects governing rule applicability and RRNP eligibility.

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| location_id | UUID | No | Primary key |
| provider_id | UUID FK | No | FK to providers |
| name | VARCHAR(100) | No | Physician-assigned name (e.g., 'Main Clinic', 'Edson Hospital', 'Locum - Whitecourt') |
| functional_centre | VARCHAR(10) | No | AHCIP functional centre code. Determines governing rule applicability. |
| facility_number | VARCHAR(10) | Yes | Facility number for hospital-based locations |
| address_line_1 | VARCHAR(100) | Yes | Street address |
| address_line_2 | VARCHAR(100) | Yes | |
| city | VARCHAR(50) | Yes | |
| province | VARCHAR(2) | Yes | Default: AB |
| postal_code | VARCHAR(7) | Yes | |
| community_code | VARCHAR(10) | Yes | Community code for RRNP eligibility lookup |
| rrnp_eligible | BOOLEAN | No | Whether this location qualifies for RRNP. Derived from community_code via Reference Data lookup. |
| rrnp_rate | DECIMAL(8,2) | Yes | Current RRNP rate for this community. Cached from Reference Data, refreshed quarterly. |
| is_default | BOOLEAN | No | True for the physician's primary practice location. Used as default on new claims. |
| is_active | BOOLEAN | No | Active locations appear in claim creation dropdown. |
| created_at | TIMESTAMPTZ | No | |
| updated_at | TIMESTAMPTZ | No | |

Constraints: Exactly one default location per provider (where is_active = true). Community_code is validated against Reference Data.

Indexes: (provider_id, is_active), (provider_id, is_default).

## 2.7 BA Facility Mappings Table (ba_facility_mappings)

Maps business arrangements to facility/functional centre codes. Used by the smart routing engine (Section 5) to match claims to the correct BA based on practice location.

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| mapping_id | UUID | No | Primary key |
| ba_id | UUID FK | No | FK to business_arrangements |
| provider_id | UUID FK | No | FK to providers. Redundant for scoping enforcement. |
| functional_centre | VARCHAR(10) | No | Functional centre code this mapping applies to |
| priority | INTEGER | No | Routing priority. Higher takes precedence. Default 0. |
| is_active | BOOLEAN | No | Soft delete. Default true. |
| created_at | TIMESTAMPTZ | No | |
| updated_at | TIMESTAMPTZ | No | |

Constraints: Unique (ba_id, functional_centre).

Indexes: (provider_id, is_active).

## 2.8 BA Schedule Mappings Table (ba_schedule_mappings)

Maps business arrangements to time-of-day/day-of-week windows. Used by the smart routing engine (Section 5) for schedule-based BA selection.

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| mapping_id | UUID | No | Primary key |
| ba_id | UUID FK | No | FK to business_arrangements |
| provider_id | UUID FK | No | FK to providers. Redundant for scoping enforcement. |
| day_of_week | INTEGER | No | 0 (Sunday) through 6 (Saturday) |
| start_time | VARCHAR(5) | No | Start of BA-applicable window in HH:MM format |
| end_time | VARCHAR(5) | No | End of BA-applicable window in HH:MM format |
| priority | INTEGER | No | Routing priority. Higher takes precedence. Default 0. |
| is_active | BOOLEAN | No | Soft delete. Default true. |
| created_at | TIMESTAMPTZ | No | |
| updated_at | TIMESTAMPTZ | No | |

Indexes: (provider_id, is_active), (ba_id, day_of_week).

## 2.9 WCB Configuration Table (wcb_configurations)

Stores the physician's WCB billing identity. A physician may have multiple Contract IDs (e.g., GP billing under 000001 and OIS under 000053). Each Contract ID maps to a Role and a set of permitted form types per the WCB Contract ID/Role/Form ID matrix (Domain 4.2, Section 2.3).

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| wcb_config_id | UUID | No | Primary key |
| provider_id | UUID FK | No | FK to providers |
| contract_id | VARCHAR(10) | No | WCB Contract ID (e.g., 000001, 000006, 000053). Determines available form types. |
| role_code | VARCHAR(10) | No | WCB Role code (e.g., GP, SP, OR, OIS). Paired with Contract ID. |
| skill_code | VARCHAR(10) | Yes | WCB Skill code. Defaults based on specialty but may be overridden. |
| permitted_form_types | JSONB | No | Array of form IDs this Contract ID/Role can create (e.g., ['C050E','C151','C568']). Derived from WCB matrix, stored for fast lookup. |
| is_default | BOOLEAN | No | Default WCB config for this provider. Used when creating WCB claims. |
| created_at | TIMESTAMPTZ | No | |
| updated_at | TIMESTAMPTZ | No | |

Constraints: (provider_id, contract_id) unique. At most one default per provider.

Indexes: (provider_id), unique (provider_id, contract_id).

## 2.10 Delegate Relationships Table (delegate_relationships)

Manages the physician-delegate linkage and the specific permissions granted. A delegate is a user (Domain 1) who acts on behalf of one or more physicians. The permissions here define what the delegate can do; Domain 1's RBAC middleware enforces them at the API layer.

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| relationship_id | UUID | No | Primary key |
| physician_id | UUID FK | No | FK to providers. The physician granting delegation. |
| delegate_user_id | UUID FK | No | FK to Domain 1 users. The delegate receiving permissions. |
| permissions | JSONB | No | Array of permission keys granted. Subset of the full permission set (Section 3.1). |
| status | VARCHAR(20) | No | ACTIVE, INVITED, REVOKED. INVITED until delegate accepts. |
| invited_at | TIMESTAMPTZ | No | When the invitation was sent |
| accepted_at | TIMESTAMPTZ | Yes | When the delegate accepted |
| revoked_at | TIMESTAMPTZ | Yes | When the physician revoked access |
| revoked_by | UUID FK | Yes | Who revoked (physician or admin) |
| created_at | TIMESTAMPTZ | No | |
| updated_at | TIMESTAMPTZ | No | |

Constraints: (physician_id, delegate_user_id) unique for non-REVOKED relationships via partial unique index. A delegate can serve multiple physicians with independent permission sets.

Indexes: (physician_id, status), (delegate_user_id, status).

## 2.11 Submission Preferences Table (submission_preferences)

Stores the physician's auto-submission configuration. One row per physician. Referenced by the batch assembly process (Domain 4.0, Section 2.4).

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| preference_id | UUID | No | Primary key |
| provider_id | UUID FK | No | FK to providers. Unique. |
| ahcip_submission_mode | VARCHAR(20) | No | AUTO_CLEAN, AUTO_ALL, REQUIRE_APPROVAL. Default: AUTO_CLEAN. |
| wcb_submission_mode | VARCHAR(20) | No | AUTO_CLEAN, AUTO_ALL, REQUIRE_APPROVAL. Default: REQUIRE_APPROVAL (WCB timing is more sensitive). |
| batch_review_reminder | BOOLEAN | No | True = remind physician to review flagged claims before Thursday cutoff. Default: true. |
| deadline_reminder_days | INTEGER | No | Days before submission deadline to send first reminder. Default: 7. |
| updated_at | TIMESTAMPTZ | No | |
| updated_by | UUID FK | No | Who last changed preferences |

## 2.12 H-Link Configuration Table (hlink_configurations)

Stores the physician's H-Link submission identity. One row per physician. Credentials are references to secrets management — actual values are never stored in the database.

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| hlink_config_id | UUID | No | Primary key |
| provider_id | UUID FK | No | FK to providers. Unique. |
| submitter_prefix | VARCHAR(10) | No | H-Link submitter prefix assigned during accreditation |
| credential_secret_ref | VARCHAR(100) | No | Reference to H-Link transmission credentials in secrets management (DigitalOcean encrypted secrets). NOT the credentials themselves. |
| accreditation_status | VARCHAR(20) | No | PENDING, ACTIVE, SUSPENDED. Claims cannot be submitted until ACTIVE. |
| accreditation_date | DATE | Yes | When H-Link accreditation was granted |
| last_successful_transmission | TIMESTAMPTZ | Yes | Last successful batch transmission timestamp |
| created_at | TIMESTAMPTZ | No | |
| updated_at | TIMESTAMPTZ | No | |

# 3. Delegate Permission Model

Delegates are non-physician users who perform billing tasks on behalf of one or more physicians. The physician grants a specific subset of permissions to each delegate. This domain manages the permissions; Domain 1 (Identity & Access) enforces them at the API middleware layer.

## 3.1 Permission Catalogue

| Permission Key | Category | Description |
| --- | --- | --- |
| CLAIM_CREATE | Claims | Create claims on behalf of the physician |
| CLAIM_EDIT | Claims | Edit existing claims in draft or validated state |
| CLAIM_VIEW | Claims | View claim details and history |
| CLAIM_DELETE | Claims | Soft-delete draft claims |
| CLAIM_QUEUE | Claims | Queue validated claims for submission |
| CLAIM_APPROVE | Claims | Approve flagged claims for batch inclusion |
| CLAIM_RESUBMIT | Claims | Resubmit corrected rejected claims |
| CLAIM_WRITE_OFF | Claims | Write off rejected claims |
| BATCH_VIEW | Batches | View batch details and submission history |
| BATCH_DOWNLOAD | Batches | Download WCB batch files for manual upload |
| BATCH_CONFIRM_UPLOAD | Batches | Confirm WCB batch upload to myWCB |
| IMPORT_EMR | Import | Upload and process EMR import files |
| IMPORT_MANAGE_TEMPLATES | Import | Create and edit field mapping templates |
| PATIENT_VIEW | Patients | View patient records (PHI access) |
| PATIENT_CREATE | Patients | Create new patient records |
| PATIENT_EDIT | Patients | Edit patient demographics |
| PATIENT_IMPORT | Patients | Bulk import patients from CSV |
| SHIFT_MANAGE | ED Shifts | Create and manage ED shift sessions |
| REPORT_VIEW | Reports | View analytics dashboards and reports |
| REPORT_EXPORT | Reports | Export reports and claim data |
| AI_COACH_REVIEW | AI Coach | Review and act on AI Coach suggestions |
| REJECTION_MANAGE | Rejections | View rejections and initiate corrections |
| PREFERENCE_VIEW | Settings | View physician's submission preferences |
| PREFERENCE_EDIT | Settings | Modify submission preferences |

## 3.2 Default Permission Sets

When inviting a delegate, the physician can select from preset templates or configure granularly:

| Template | Permissions Included |
| --- | --- |
| Full Access | All 24 permissions. For trusted billing agents who manage the entire workflow. |
| Billing Entry | CLAIM_CREATE, CLAIM_EDIT, CLAIM_VIEW, CLAIM_QUEUE, IMPORT_EMR, PATIENT_VIEW, PATIENT_CREATE, SHIFT_MANAGE, AI_COACH_REVIEW. For data entry staff. |
| Review & Submit | CLAIM_VIEW, CLAIM_APPROVE, BATCH_VIEW, BATCH_DOWNLOAD, BATCH_CONFIRM_UPLOAD, REJECTION_MANAGE, REPORT_VIEW. For billing managers who review and submit but don't enter data. |
| View Only | CLAIM_VIEW, BATCH_VIEW, PATIENT_VIEW, REPORT_VIEW. For accountants or auditors. |
| Custom | Physician selects individual permissions. |

Permission changes are audit-logged and take effect immediately. The physician can modify a delegate's permissions at any time.

## 3.3 Multi-Physician Delegation

A single delegate user can serve multiple physicians. Each physician-delegate relationship has its own independent permission set. When a delegate logs in, they select which physician context to work in. The selected physician_id is carried in the auth context (Domain 1) and scopes all subsequent API calls.

A delegate cannot access data across physicians in a single request. Context switching is explicit and logged.

# 4. PCPCM Routing Logic

PCPCM (Patient's Choice Primary Care Model) creates a dual-BA arrangement that requires intelligent claim routing. This section specifies the routing logic that Domain 4.1 invokes via the internal provider context API.

## 4.1 Routing Decision

When a PCPCM-enrolled physician creates an AHCIP claim, the BA is determined by:

1. Look up the HSC code's PCPCM basket classification in Reference Data (Domain 2).
2. If the code is in-basket: route to the PCPCM BA.
3. If the code is out-of-basket: route to the FFS BA.
4. If the code has no basket classification (rare edge case): route to FFS BA and flag as warning.

The routing decision is made at claim creation time and stored on the AHCIP claim detail. It does not change if the basket classification is updated in a later SOMB version — the version in effect at the DOS governs.

## 4.2 Batch Assembly Impact

PCPCM physicians generate two separate AHCIP batches per Thursday cycle:

Batch 1: All in-basket claims → submitted under PCPCM BA

Batch 2: All out-of-basket claims → submitted under FFS BA

The batch assembly process (Domain 4.1) groups by provider_id + ba_number, which naturally separates these into two files.

## 4.3 Display in UI

The claim creation form shows the routed BA alongside the HSC code. If the physician changes the HSC code, the BA updates in real-time. A visual indicator (badge or colour) distinguishes PCPCM-routed claims from FFS-routed claims. The physician can override the BA routing if needed (with a warning that this may affect payment).

# 5. Mixed FFS/ARP Smart Routing

Physicians who hold both FFS and ARP business arrangements require intelligent claim routing that selects the correct BA based on service code type, facility, and schedule context. The smart routing engine runs during claim creation and resolves the BA via a four-level priority chain.

## 5.1 BA Subtypes for ARP

ARP business arrangements carry a `ba_subtype` column that classifies the ARP arrangement:

| ba_type | ba_subtype | Label |
| --- | --- | --- |
| FFS | null | FFS |
| ARP | ANNUALISED | ARP Annualised |
| ARP | SESSIONAL | ARP Sessional |
| ARP | BCM | ARP BCM |
| PCPCM | null | PCPCM |

During onboarding (Domain 11), the physician labels each BA with its type and, for ARP BAs, its subtype. The subtype is stored on the `business_arrangements` table (`ba_subtype` column) and determines ARP-specific billing rules and analytics grouping.

## 5.2 ARP S-Code Restriction

ARP S-codes are only available when the selected BA has `ba_type = 'ARP'`:

- Service code search and lookup filters include S-codes in results only when the selected BA is an ARP BA.
- If a physician manually enters an S-code with a non-ARP BA selected, the system returns a validation error: "S-codes are only available under an ARP Business Arrangement."

## 5.3 Routing Priority Chain

During claim creation, the system auto-selects the BA using this priority chain:

1. **Service code type (Level 1):** ARP S-code → force ARP BA. No override permitted. The implementation matches service codes with prefixes '03.' or '08.' when an ARP BA is present.
2. **Facility code mapping (Level 2):** Claim facility code → lookup `ba_facility_mappings` for provider → select mapped BA.
3. **Schedule mapping (Level 3):** Claim date of service → extract day-of-week and time → lookup `ba_schedule_mappings` for provider → select mapped BA within the active window.
4. **Primary BA fallback (Level 4):** Physician's designated primary BA.

For single-BA physicians, routing is trivially resolved to their only BA with reason `SINGLE_BA_DEFAULT`.

Each resolution returns the selected BA along with the routing reason (one of: `ARP_SERVICE_CODE`, `BA_FACILITY_MATCH`, `BA_SCHEDULE_MATCH`, `PRIMARY_BA_FALLBACK`, `SINGLE_BA_DEFAULT`, `USER_OVERRIDE`).

## 5.4 Facility-BA Mapping Configuration

During onboarding or via provider settings, the physician maps each BA to functional centre codes. The mapping is stored in the `ba_facility_mappings` table (Section 2.7). Updates replace all existing active mappings — old mappings are deactivated and new ones inserted.

## 5.5 Time-Based Routing Schedule

Schedule mappings define which BA is active at different times (e.g., FFS during clinic hours, ARP during hospital shifts). Each mapping specifies a BA, day of week, start time, end time, and priority. Updates replace all existing active mappings.

## 5.6 Routing Conflict Warning

If a physician manually selects a BA that conflicts with the auto-resolved routing (e.g., FFS BA for a claim at an ARP-mapped facility), the system returns a conflict detection result. The UI displays: "This facility is mapped to your {mappedBaLabel} BA. Are you sure you want to bill under {selectedBaLabel}?" The physician confirms or changes.

The `detectRoutingConflict` function compares the physician's selected BA against the resolved BA and reports whether they differ.

## 5.7 Routing Configuration Changes

Routing configuration is editable at any time via provider settings. Changes apply to new claims only; existing claims are not retroactively re-routed. All routing configuration changes are audit-logged.

# 6. PCPCM Payment Reconciliation

PCPCM-enrolled physicians receive quarterly capitation payments from Alberta Health based on panel size. This subsystem tracks those payments and reconciles expected amounts against actual amounts received.

## 6.1 Payment Recording

Physicians record incoming PCPCM capitation payments via the API. Each payment record captures:
- The PCPCM enrolment it relates to (validated to belong to the authenticated provider)
- Payment period (start and end dates)
- Expected amount (derived from panel size × per-patient capitation rate)
- Actual amount received from Alberta Health
- Panel size at time of payment

If only an expected amount is provided, the payment status is set to `EXPECTED`. If an actual amount is provided, the status is set to `RECEIVED`.

## 6.2 Reconciliation Logic

The reconciliation process compares expected vs actual amounts for all unreconciled payments (status `EXPECTED` or `RECEIVED`):

- Payments with both expected and actual amounts are evaluated.
- If the difference is within $0.01 (tolerance): status transitions to `RECONCILED`, reconciled_at timestamp recorded.
- If the difference exceeds $0.01: status transitions to `DISCREPANCY`, a note is recorded with the exact amounts and difference.
- Payments missing either expected or actual amount are skipped.

Reconciliation returns a summary: count of reconciled payments, count of discrepancies, and per-payment details.

## 6.3 Panel Size Management

Panel sizes in Alberta come from Alberta Health's quarterly Panel Attribution Reports. At MVP, physicians enter their panel size manually. The `updatePanelSize` function validates:
- Panel size is a positive integer
- The enrolment belongs to the authenticated provider (tenant isolation)

The panel size is stored on the `pcpcm_enrolments` table.

## 6.4 Payment History

Paginated payment history retrieval supports filtering by status, period start date, and period end date. Results are ordered by payment period end date (descending).

# 7. Connect Care User Support

The Connect Care user flag controls the mobile app's behaviour for physicians who use Connect Care for clinical documentation. When Connect Care is active, the SCC extract provides all billing data; the mobile app's primary role shifts from billing data capture to shift timing context.

## 7.1 Provider Flag

Two columns on the `providers` table control Connect Care status:
- `is_connect_care_user` (BOOLEAN, default false): whether the physician uses Connect Care
- `connect_care_enabled_at` (TIMESTAMPTZ, nullable): when Connect Care mode was first enabled

## 7.2 Mode Activation

- If `is_connect_care_user = true`: the mobile app's default view is shift-focused (upcoming shifts, active shift, recent reconciliation). Quick claim entry is accessible via a secondary menu item for non-Connect Care clinic days.
- If `is_connect_care_user = false`: the mobile app's default view is claim-entry-focused (standard mode per Domain 10 FRD).

Transition between modes is seamless. Existing favourite codes and templates remain available in both modes. Enabling Connect Care sets `connect_care_enabled_at` to the current timestamp; disabling it does not clear the timestamp (preserves history).

## 7.3 Configuration

Connect Care status is set during onboarding (Domain 11) or via provider settings. Toggling the flag is audit-logged with the `connect_care.toggled` action and emits a `provider.connect_care_toggled` event for the notification service.

# 8. User Stories & Acceptance Criteria

## 8.1 Profile Setup

| ID | Story | Acceptance Criteria |
| --- | --- | --- |
| PRV-001 | As a new physician, I want to set up my professional profile during onboarding so that the platform can configure my billing context | Guided wizard: billing number, CPSA registration, specialty, physician type. Billing number validated against AHCIP format (5-digit numeric). CPSA validated against known format. Specialty selected from AHCIP specialty code list. Profile marked incomplete until all required fields set. |
| PRV-002 | As a physician, I want to add my BA number(s) so that claims route to the correct payment destination | Enter BA number. System validates format. Status set to PENDING until physician confirms linkage with Alberta Health. For PCPCM physicians: guided flow to add both PCPCM BA and FFS BA. System enforces dual-BA requirement. For ARP physicians: prompted to select ba_subtype (ANNUALISED, SESSIONAL, or BCM). |
| PRV-003 | As a physician, I want to add my practice locations so that claims default to the correct functional centre | Add location with name, functional centre code, optional facility number, and address. Community code looked up for RRNP eligibility. Set one location as default. Multiple locations supported. |
| PRV-004 | As a physician, I want to configure my WCB billing identity so I can submit WCB claims | Select Contract ID from dropdown (populated from WCB matrix). System auto-populates permitted Role codes and form types. Physician confirms. Can add multiple Contract IDs if applicable (e.g., GP + OIS). |

## 8.2 Delegate Management

| ID | Story | Acceptance Criteria |
| --- | --- | --- |
| PRV-005 | As a physician, I want to invite a delegate so they can help manage my billing | Enter delegate email. Select permission template or configure custom. System sends invitation email via Notification Service. Invitation expires in 7 days. Delegate creates account (if new) or accepts (if existing) via invitation link. |
| PRV-006 | As a delegate, I want to accept an invitation and access the physician's billing | Click invitation link. Create account or log in. Accept invitation. Relationship becomes ACTIVE. Delegate can now switch to physician's context. |
| PRV-007 | As a physician, I want to modify my delegate's permissions | View current permissions. Toggle individual permissions or switch template. Changes take effect immediately. Audit logged. |
| PRV-008 | As a physician, I want to revoke a delegate's access | Revoke action. Confirm with dialog. Relationship status set to REVOKED. Delegate immediately loses access to this physician's data. Other physician relationships unaffected. |
| PRV-009 | As a delegate, I want to switch between physician contexts | Dropdown shows all physicians I serve (ACTIVE relationships only). Select physician. Auth context updates. All subsequent actions scoped to selected physician. |

## 8.3 Ongoing Management

| ID | Story | Acceptance Criteria |
| --- | --- | --- |
| PRV-010 | As a physician, I want to update my specialty or practice details | Edit specialty, add/remove practice locations, update BA details. Changes are audit-logged. If specialty changes, validation context updates for future claims (existing claims unaffected). |
| PRV-011 | As a physician, I want to set my submission preferences | Select AHCIP mode (Auto Clean, Auto All, Require Approval). Select WCB mode independently. Enable/disable batch review reminders. Set deadline reminder threshold. Defaults applied on registration. |
| PRV-012 | As a physician, I want to see my RRNP eligibility and current rate | Dashboard card shows RRNP status per location. Rate displayed per community. Updated quarterly from Reference Data. If rate changes, notification emitted. |
| PRV-013 | As a physician, I want to add a new practice location when I start working at a different site | Add location flow (same as PRV-003). New location immediately available in claim creation dropdown. Claims for existing locations unaffected. |
| PRV-014 | As a locum physician, I want to manage multiple practice locations across different communities | Add each location with its functional centre and community code. RRNP eligibility calculated per location. Claims select location at creation time. Monthly reporting shows breakdown by location. |

## 8.4 Smart Routing

| ID | Story | Acceptance Criteria |
| --- | --- | --- |
| PRV-015 | As a mixed FFS/ARP physician, I want to map my facilities to BAs so claims auto-route correctly | Configure facility-BA mappings via settings. Each functional centre maps to one BA. Mappings editable at any time. New claims at a mapped facility auto-select the correct BA. |
| PRV-016 | As a mixed FFS/ARP physician, I want time-based routing so my clinic hours and hospital shifts use different BAs | Configure schedule mappings: day of week, start time, end time, BA. Claims at matching times auto-select the scheduled BA. |
| PRV-017 | As a physician, I want to override the auto-selected BA when I know the routing is wrong for a specific case | One-click BA change on claim form. System displays conflict warning if override differs from auto-resolved BA. Override logged for audit. |

## 8.5 PCPCM Payment Management

| ID | Story | Acceptance Criteria |
| --- | --- | --- |
| PRV-018 | As a PCPCM physician, I want to record capitation payments I receive from Alberta Health | Enter payment period and amount. System validates enrolment exists and belongs to provider. Payment recorded with status EXPECTED or RECEIVED based on data provided. |
| PRV-019 | As a PCPCM physician, I want to reconcile expected vs actual payments | Trigger reconciliation. System compares expected vs actual for unreconciled payments. Matches within $0.01 marked RECONCILED. Mismatches marked DISCREPANCY with details. Summary displayed. |
| PRV-020 | As a PCPCM physician, I want to update my panel size from the AH quarterly report | Enter panel size number. Validated as positive integer. Updated on the PCPCM enrolment record. Used for future expected payment calculations. |

# 9. API Contracts

All endpoints require authentication via Domain 1. Provider endpoints are scoped to the authenticated physician or the delegate's active physician context.

## 9.1 Provider Profile

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/providers/me | Get the authenticated physician's full profile including BAs, locations, WCB config, PCPCM status, RRNP eligibility, Connect Care status. |
| PUT | /api/v1/providers/me | Update profile fields (specialty, physician_type, name). Audit-logged. |
| GET | /api/v1/providers/me/onboarding-status | Check onboarding completion status. Returns missing required fields. |
| POST | /api/v1/providers/me/complete-onboarding | Mark onboarding as complete. Validates all required fields are set. Fails if any are missing. |

## 9.2 Business Arrangements

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/providers/me/bas | List all BAs for the physician. |
| POST | /api/v1/providers/me/bas | Add a BA. Validates format, type, and subtype constraints. |
| PUT | /api/v1/providers/me/bas/{id} | Update BA details (status, dates). |
| DELETE | /api/v1/providers/me/bas/{id} | Deactivate a BA. Sets end_date and status = INACTIVE. |

## 9.3 Practice Locations

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/providers/me/locations | List all practice locations. |
| POST | /api/v1/providers/me/locations | Add a practice location. Auto-lookups RRNP eligibility from community code. |
| PUT | /api/v1/providers/me/locations/{id} | Update location details. |
| PUT | /api/v1/providers/me/locations/{id}/set-default | Set as default location. |
| DELETE | /api/v1/providers/me/locations/{id} | Deactivate location (soft-delete). |

## 9.4 WCB Configuration

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/providers/me/wcb | List all WCB configurations. |
| POST | /api/v1/providers/me/wcb | Add a WCB Contract ID/Role. Validates against WCB matrix. Auto-populates permitted form types. |
| PUT | /api/v1/providers/me/wcb/{id} | Update WCB config (skill code, default status). |
| DELETE | /api/v1/providers/me/wcb/{id} | Remove a WCB configuration. |
| GET | /api/v1/providers/me/wcb/form-permissions | Get aggregated permitted form types across all Contract IDs for the physician. |

## 9.5 Delegate Management

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/providers/me/delegates | List all delegates (active, invited, revoked). |
| POST | /api/v1/providers/me/delegates/invite | Invite a delegate. Body: email, permissions (template or custom array). Triggers invitation email. |
| PUT | /api/v1/providers/me/delegates/{rel_id}/permissions | Update delegate permissions. Body: new permission array. |
| POST | /api/v1/providers/me/delegates/{rel_id}/revoke | Revoke delegate access. |
| GET | /api/v1/delegates/me/physicians | For delegates: list all physicians I serve with my permissions for each. |
| POST | /api/v1/delegates/me/switch-context/{provider_id} | For delegates: switch active physician context. |
| POST | /api/v1/delegates/invitations/{token}/accept | Accept a delegate invitation. |

## 9.6 Submission Preferences

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/providers/me/submission-preferences | Get current submission preferences. |
| PUT | /api/v1/providers/me/submission-preferences | Update submission preferences. Audit-logged. |

## 9.7 H-Link Configuration

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/providers/me/hlink | Get H-Link configuration (submitter prefix, accreditation status). Credentials are never returned. |
| PUT | /api/v1/providers/me/hlink | Update H-Link config (submitter prefix, accreditation status). Credential updates route to secrets management. |

## 9.8 Smart Routing Configuration

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/providers/me/routing-config | Get current routing configuration: facility mappings and schedule mappings. |
| PUT | /api/v1/providers/me/routing-config/facilities | Replace all facility-BA mappings. Body: `{ mappings: [{ ba_id, functional_centre, priority }] }`. Old mappings deactivated. |
| PUT | /api/v1/providers/me/routing-config/schedule | Replace all schedule-BA mappings. Body: `{ mappings: [{ ba_id, day_of_week, start_time, end_time, priority }] }`. Old mappings deactivated. |
| POST | /api/v1/claims/routing/resolve | Resolve the correct BA for a claim context. Body: `{ service_code, facility_code?, date_of_service? }`. Returns `{ baId, baNumber, baType, baSubtype, routingReason, conflict }`. |
| POST | /api/v1/claims/routing/conflict | Detect routing conflict between a manually selected BA and the auto-resolved BA. Body: `{ selected_ba_id, service_code, facility_code?, date_of_service? }`. Returns `{ hasConflict, resolvedBaId, resolvedBaNumber, resolvedReason, selectedBaId }`. |

## 9.9 PCPCM Payment Reconciliation

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/providers/me/pcpcm/payments | List PCPCM payment history. Query params: status, periodStart, periodEnd, page, pageSize. Paginated response. |
| POST | /api/v1/providers/me/pcpcm/payments | Record a PCPCM capitation payment. Body: `{ enrolmentId, paymentPeriodStart, paymentPeriodEnd, expectedAmount?, actualAmount?, panelSizeAtPayment?, notes? }`. At least one of expectedAmount or actualAmount required. |
| POST | /api/v1/providers/me/pcpcm/reconcile | Trigger reconciliation of all unreconciled payments. Returns `{ reconciled, discrepancies, details[] }`. |
| PATCH | /api/v1/providers/me/pcpcm/panel-size | Update PCPCM panel size on enrolment. Body: `{ enrolmentId, panelSize }`. Positive integer required. |

## 9.10 Connect Care

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/providers/me/connect-care | Get Connect Care status: `{ isConnectCareUser, connectCareEnabledAt }`. |
| PUT | /api/v1/providers/me/connect-care | Enable or disable Connect Care. Body: `{ is_connect_care: boolean }`. Audit-logged. |

## 9.11 Internal Provider Context API

These endpoints are consumed internally by the Claim Lifecycle and other domains. They are not exposed to the UI but are part of the service-to-service interface.

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/internal/providers/{id}/claim-context | Returns the full context needed for claim creation: BAs (with subtypes), default location, specialty, PCPCM status, WCB configs, RRNP eligibility, Connect Care status. Consumed by Domain 4.0. |
| GET | /api/v1/internal/providers/{id}/ba-for-claim | Given a claim_type and optional HSC code, returns the correct BA number. Handles PCPCM basket routing. |
| GET | /api/v1/internal/providers/{id}/wcb-config-for-form | Given a WCB form_id, returns the matching Contract ID/Role or error if not permitted. Consumed by Domain 4.2. |

# 10. Provider Context Object

The provider context is the key interface between this domain and the Claim Lifecycle. When Domain 4 creates or validates a claim, it requests the provider context for the physician. This context provides all the provider-derived information needed for claim processing without requiring Domain 4 to understand the provider data model.

| Field | Type | Description |
| --- | --- | --- |
| provider_id | UUID | Provider identifier |
| billing_number | VARCHAR(10) | AHCIP practitioner ID |
| specialty_code | VARCHAR(10) | Primary specialty |
| physician_type | VARCHAR(20) | GP, SPECIALIST, LOCUM |
| bas | Array | All active BAs with ba_id, ba_number, ba_type, ba_subtype, is_primary, status |
| default_location | Object | Default practice location with location_id, name, functional_centre, facility_number |
| all_locations | Array | All active locations (for claim creation dropdown) |
| pcpcm_enrolled | BOOLEAN | Whether physician is PCPCM-enrolled |
| pcpcm_ba_number | VARCHAR(10) | PCPCM BA number (null if not enrolled) |
| ffs_ba_number | VARCHAR(10) | FFS BA number (always present) |
| wcb_configs | Array | All WCB configurations with wcb_config_id, contract_id, role_code, permitted_form_types |
| default_wcb_config | Object | Default WCB config (null if none) |
| submission_preferences | Object | AHCIP and WCB submission modes, reminder settings |
| hlink_accreditation_status | VARCHAR(20) | PENDING, ACTIVE, SUSPENDED |
| hlink_submitter_prefix | VARCHAR(10) | H-Link submitter prefix |
| onboarding_completed | BOOLEAN | Whether profile setup is complete |
| status | VARCHAR(20) | Provider status (ACTIVE, SUSPENDED, INACTIVE) |

This context is cached per request and invalidated when any provider data changes. Changes to RRNP rates (quarterly) or PCPCM basket classifications (SOMB update) trigger a cache refresh.

# 11. Locum Support

Locum physicians work at multiple facilities across different communities, often in a single month. Meritum supports this pattern through multi-location management with per-claim location selection.

## 11.1 Locum Workflow

Profile setup: Locum physician adds each practice location with its functional centre and community code. RRNP eligibility and rate are calculated independently per location.

Claim creation: When creating a claim, the locum selects the location from their active locations list. The claim inherits that location's functional centre, facility number, and RRNP rate.

Batch assembly: All claims for the same physician batch together regardless of location. The functional centre and RRNP rate are per-claim, not per-batch.

Reporting: Analytics (Domain 8) breaks down revenue, claims, and rejections by location. Locum physicians see a multi-site comparison view.

## 11.2 Location-Based Defaults

When a locum physician selects a location during claim creation, the following fields auto-populate:

functional_centre: From the location record

facility_number: From the location record (if hospital-based)

rrnp_rate: From the location record (if RRNP-eligible)

after_hours rules: Same statutory holiday list regardless of location (Alberta-wide)

The physician can override any of these defaults on an individual claim.

# 12. Onboarding Workflow

Provider onboarding is a guided wizard that runs after the physician creates their account (Domain 1). The platform is unusable for claim creation until onboarding is complete.

## 12.1 Onboarding Steps

| # | Step | Required Fields | Notes |
| --- | --- | --- | --- |
| 1 | Professional Identity | billing_number, cpsa_registration_number, first/last name | Validated against known formats. Not verified against CPSA registry at MVP (future enhancement). |
| 2 | Specialty & Type | specialty_code, physician_type | Specialty from AHCIP code list. Type determines default workflow (GP vs specialist vs locum). |
| 3 | Business Arrangement | At least one BA number | BA status set to PENDING. Physician can confirm active later. PCPCM flow triggered if physician selects 'PCPCM enrolled'. ARP flow prompts for ba_subtype selection. |
| 4 | Primary Practice Location | At least one location with functional_centre | Community code optional but recommended for RRNP. Address optional. For mixed FFS/ARP physicians, facility-BA mapping prompted. |
| 5 | WCB Configuration | Optional — can be skipped | If physician bills WCB, add Contract ID. Otherwise skip. Can be added later from settings. |
| 6 | Submission Preferences | Defaults applied | Physician can accept defaults (Auto Clean for AHCIP, Require Approval for WCB) or customise. Shown as final step. |
| 7 | IMA Generation | Physician reviews and acknowledges | Information Manager Agreement generated from template. Physician as HIA custodian. Digital acknowledgement stored. |

## 12.2 Onboarding Completion

Onboarding is marked complete (onboarding_completed = true) when steps 1–4 and step 7 are finished. Steps 5–6 are optional at onboarding. The system blocks claim creation until onboarding_completed = true.

If the physician abandons onboarding mid-flow, their progress is saved. They resume from where they left off on next login. A banner in the UI shows 'Complete your profile to start billing' until onboarding is finished.

# 13. Security & Audit

## 13.1 Data Protection

Provider data contains professional identity (billing number, CPSA registration) but not PHI. Encrypted at rest as standard practice.

H-Link credentials and WCB vendor credentials are never stored in the database. Stored in secrets management only. Only a reference key is in the database.

Delegate invitation tokens are single-use, time-limited (7 days), and hashed in storage. Acceptance uses timing-safe comparison.

RRNP rates and PCPCM basket classifications are not sensitive but are versioned for audit traceability.

PCPCM payment amounts are financial data tied to the physician's professional identity, not PHI. Stored encrypted at rest.

## 13.2 Audit Trail

Provider Management actions logged to the system audit log (Domain 1):

| Action | Details Logged |
| --- | --- |
| PROVIDER_PROFILE_UPDATED | Field-level diff (old vs new value). Actor identity. |
| BA_ADDED / BA_UPDATED / BA_DEACTIVATED | BA number, type, subtype, status change. Actor identity. |
| LOCATION_ADDED / LOCATION_UPDATED / LOCATION_DEACTIVATED | Location details. RRNP eligibility change if applicable. |
| WCB_CONFIG_ADDED / WCB_CONFIG_UPDATED / WCB_CONFIG_REMOVED | Contract ID, Role code. Permitted form types delta. |
| DELEGATE_INVITED | Delegate email, permissions granted, invitation timestamp. |
| DELEGATE_ACCEPTED | Delegate user_id, physician_id, timestamp. |
| DELEGATE_PERMISSIONS_CHANGED | Old vs new permission set. Actor identity. |
| DELEGATE_REVOKED | Delegate user_id, actor identity, timestamp. |
| SUBMISSION_PREFERENCE_CHANGED | Old vs new mode. Actor identity. |
| ONBOARDING_COMPLETED | Timestamp, all required fields confirmed. |
| HLINK_CONFIG_UPDATED | Submitter prefix, accreditation status change. Credential changes logged as 'credential rotated' without values. |
| ROUTING_CONFIG_UPDATED | Mapping count and type (facility or schedule). Actor identity. |
| ROUTING_RESOLVED | BA resolution result and routing reason. |
| CONNECT_CARE_TOGGLED | is_connect_care flag value. Actor identity. |

# 14. Testing Requirements

## 14.1 Profile Tests

Create provider with valid billing number and CPSA registration

Reject invalid billing number format

Reject duplicate billing number / CPSA registration

Update specialty — verify claim validation context updates for future claims

Onboarding wizard: complete all steps in order, verify onboarding_completed = true

Onboarding wizard: abandon mid-flow, resume on next login, verify progress saved

## 14.2 BA Tests

Add single BA (FFS). Add second BA (PCPCM + FFS pair).

Add ARP BA with subtype ANNUALISED — verify ba_subtype stored correctly

Add ARP BA with subtype SESSIONAL — verify ba_subtype stored correctly

Reject third BA when two active exist

PCPCM constraint: cannot add PCPCM BA without corresponding FFS BA

Deactivate BA — verify claims using this BA can no longer be submitted

BA status transitions: PENDING → ACTIVE → INACTIVE

## 14.3 Location Tests

Add location with community code — RRNP eligibility auto-calculated

Add location without community code — RRNP shows as not eligible

Set default location — verify claim creation uses it

Multiple active locations — all appear in claim creation dropdown

Deactivate location — verify removed from dropdown, existing claims unaffected

Locum workflow: add 3+ locations, create claims at different locations, verify per-claim RRNP

## 14.4 WCB Configuration Tests

Add Contract ID 000001 (GP) — permitted forms include C050E, C151, C568

Add Contract ID 000053 (OIS) — permitted forms include C050S, C151S, C568

Attempt to create WCB claim with form type not in permitted list — rejected

Multiple Contract IDs for same provider — each independently valid

## 14.5 Delegate Tests

Invite delegate with Full Access template — all 24 permissions granted

Invite delegate with Billing Entry template — only subset granted

Delegate accepts invitation — relationship ACTIVE, can switch to physician context

Delegate attempts action outside permissions — rejected by Domain 1 RBAC

Physician revokes delegate — immediate access loss, other physician relationships unaffected

Delegate serves 3 physicians — independent permission sets, context switching works

Permission modification — takes effect immediately on next API call

Expired invitation (>7 days) — cannot be accepted

## 14.6 Submission Preference Tests

Default preferences applied on registration (AUTO_CLEAN for AHCIP, REQUIRE_APPROVAL for WCB)

Change AHCIP mode to AUTO_ALL — verify batch assembly includes flagged claims

Change WCB mode to AUTO_CLEAN — verify WCB batch assembly behaviour

## 14.7 Smart Routing Tests

ARP S-code with ARP BA present → forces ARP BA, reason ARP_SERVICE_CODE

Facility code matching a ba_facility_mapping → correct BA selected, reason BA_FACILITY_MATCH

Date/time matching a ba_schedule_mapping → correct BA selected, reason BA_SCHEDULE_MATCH

No match on any level → primary BA fallback, reason PRIMARY_BA_FALLBACK

Single BA physician → trivially resolved, reason SINGLE_BA_DEFAULT

Manual override conflicting with auto-resolved BA → conflict detected

Update facility mappings — old mappings deactivated, new mappings active

Update schedule mappings — old mappings deactivated, new mappings active

## 14.8 PCPCM Payment Tests

Record payment with expectedAmount only → status EXPECTED

Record payment with actualAmount → status RECEIVED

Reconcile: expected and actual within $0.01 → status RECONCILED

Reconcile: expected and actual differ by >$0.01 → status DISCREPANCY with note

List payment history with pagination and status filter

Update panel size with positive integer → enrolment updated

Reject panel size with non-positive integer

Tenant isolation: provider A cannot see or reconcile provider B's payments

## 14.9 Connect Care Tests

Get Connect Care status — returns isConnectCareUser and connectCareEnabledAt

Enable Connect Care — sets is_connect_care_user = true, connect_care_enabled_at populated

Disable Connect Care — sets is_connect_care_user = false, connect_care_enabled_at preserved

Toggle produces audit log entry with action connect_care.toggled

Toggle emits provider.connect_care_toggled event

## 14.10 Integration Tests

Full onboarding → claim creation → batch submission pipeline (AHCIP and WCB)

PCPCM routing: create in-basket and out-of-basket claims → verify two separate batches generated with correct BAs

Provider context API: verify claim lifecycle receives correct BA, location, WCB config

RRNP rate change (quarterly): verify cached rate refreshes, new claims use updated rate

Delegate creates claim on behalf of physician: claim owned by physician, delegate in audit trail

Smart routing with facility mapping → claim auto-selects correct BA

Smart routing with schedule mapping → claim auto-selects correct BA based on time

PCPCM payment recording → reconciliation → verify status transitions

# 15. Open Questions

| # | Question | Context |
| --- | --- | --- |
| 1 | Should billing number and CPSA registration be verified against external registries at onboarding? | Currently validated for format only. CPSA has a public registry. AHCIP practitioner lookup may require Alberta Health integration. |
| 2 | How should BA status be confirmed (PENDING → ACTIVE)? | Manual confirmation by physician after they verify with Alberta Health? Or automated via H-Link test submission? |
| 3 | Should delegates have their own submission preference overrides, or always inherit the physician's? | Currently physician-only. Some billing agents may want different notification preferences. |
| 4 | Should practice location addresses be validated against Canada Post data? | Would improve data quality. Cost and complexity of postal code validation API integration vs manual entry. |
| 5 | Is there a maximum number of delegates per physician, or is it unlimited? | Unlimited is simplest. May want a cap for security (e.g., max 10 active delegates). |
| 6 | Should PCPCM basket routing be overridable by the physician, or strictly enforced? | Currently allowing override with warning. Strict enforcement would prevent billing errors but may frustrate physicians who understand edge cases. |

# 16. Document Control

This document specifies the Provider Management domain. It is consumed by the Claim Lifecycle (Domain 4) via the provider context object (Section 10) and the internal provider context API (Section 9.11).

| Item | Value |
| --- | --- |
| Parent document | Meritum PRD v1.3 |
| Domain | Provider Management (Domain 5 of 13) |
| Build sequence position | 5th (consumed by Claim Lifecycle and all submission pathways) |
| Dependencies | Domain 1 (IAM), Domain 2 (Reference Data), Domain 3 (Notifications) |
| Consumed by | Domain 4.0 (Core), Domain 4.1 (AHCIP), Domain 4.2 (WCB), Domain 7 (Intelligence Engine), Domain 8 (Analytics), Domain 10 (Mobile Companion), Domain 11 (Onboarding) |
| Supplementary specs | MHT-PRICING-GAP-001 (Batch 4: PCPCM payments), MHT-FRD-MVPADD-001 (B5: ARP subtypes, B10: Smart routing), MHT-FRD-MOB-002 (C5: Connect Care flag) |
| Version | 2.0 |
| Date | February 2026 |
| Next domain in critical path | Domain 6 (Patient Registry) |
