# Meritum_Domain_05_Provider_Management

MERITUM

Functional Requirements

Provider Management

Domain 5 of 13  |  Critical Path: Position 5

Meritum Health Technologies Inc.

Version 1.0  |  February 2026

CONFIDENTIAL

# Table of Contents

# 1. Domain Overview

## 1.1 Purpose

The Provider Management domain owns the physician's professional identity within Meritum. It is the authoritative source for everything the platform needs to know about a physician's billing configuration: their Business Arrangement (BA) numbers, specialty, practice locations, PCPCM enrolment status, RRNP eligibility, WCB Contract ID and Role, delegate relationships, and submission preferences.

Every claim created in the Claim Lifecycle (Domain 4) inherits context from this domain — the BA number it routes to, the functional centre it bills from, the governing rules that apply, the fee modifiers that are eligible, and the auto-submission mode that determines how it enters a batch. Provider Management is the second most consumed domain in the platform after Reference Data.

## 1.2 Scope

Physician professional profile: name, CPSA registration, specialty, billing numbers

Business Arrangement (BA) management: single-BA and dual-BA (PCPCM) configurations, BA status tracking

Practice locations: functional centres, multi-site support, locum arrangements

PCPCM enrolment management: basket classification routing, panel size tracking

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

## 1.4 Domain Dependencies

# 2. Data Model

## 2.1 Providers Table (providers)

The central table of this domain. One row per physician. Linked 1:1 to the users table in Domain 1 (Identity & Access).

Indexes: (billing_number) unique, (cpsa_registration_number) unique, (specialty_code), (status).

## 2.2 Business Arrangements Table (business_arrangements)

A physician may have one or two active BAs. Standard FFS physicians have one. PCPCM-enrolled physicians have two: a PCPCM BA and a FFS BA. The BA number determines which claims batch together and where payment is deposited.

Constraints: Maximum 2 active BAs per provider. If ba_type = PCPCM, a second BA with ba_type = FFS must exist. ba_number unique across active records.

## 2.3 Practice Locations Table (practice_locations)

A physician may practise at multiple locations (multi-site) or different locations in different months (locum). Each location maps to an AHCIP functional centre, which affects governing rule applicability and RRNP eligibility.

Constraints: Exactly one default location per provider (where is_active = true). Community_code is validated against Reference Data.

## 2.4 PCPCM Enrolment Table (pcpcm_enrolments)

Tracks PCPCM enrolment details for physicians participating in the Patient's Choice Primary Care Model. Only applicable to physicians with a PCPCM-type BA.

## 2.5 WCB Configuration Table (wcb_configurations)

Stores the physician's WCB billing identity. A physician may have multiple Contract IDs (e.g., GP billing under 000001 and OIS under 000053). Each Contract ID maps to a Role and a set of permitted form types per the WCB Contract ID/Role/Form ID matrix (Domain 4.2, Section 2.3).

Constraints: (provider_id, contract_id) unique. At most one default per provider.

## 2.6 Delegate Relationships Table (delegate_relationships)

Manages the physician-delegate linkage and the specific permissions granted. A delegate is a user (Domain 1) who acts on behalf of one or more physicians. The permissions here define what the delegate can do; Domain 1's RBAC middleware enforces them at the API layer.

Constraints: (physician_id, delegate_user_id) unique for active relationships. A delegate can serve multiple physicians with independent permission sets.

## 2.7 Submission Preferences Table (submission_preferences)

Stores the physician's auto-submission configuration. One row per physician. Referenced by the batch assembly process (Domain 4.0, Section 2.4).

## 2.8 H-Link Configuration Table (hlink_configurations)

Stores the physician's H-Link submission identity. One row per physician. Credentials are references to secrets management — actual values are never stored in the database.

# 3. Delegate Permission Model

Delegates are non-physician users who perform billing tasks on behalf of one or more physicians. The physician grants a specific subset of permissions to each delegate. This domain manages the permissions; Domain 1 (Identity & Access) enforces them at the API middleware layer.

## 3.1 Permission Catalogue

## 3.2 Default Permission Sets

When inviting a delegate, the physician can select from preset templates or configure granularly:

Permission changes are audit-logged and take effect immediately. The physician can modify a delegate's permissions at any time.

## 3.3 Multi-Physician Delegation

A single delegate user can serve multiple physicians. Each physician-delegate relationship has its own independent permission set. When a delegate logs in, they select which physician context to work in. The selected physician_id is carried in the auth context (Domain 1) and scopes all subsequent API calls.

A delegate cannot access data across physicians in a single request. Context switching is explicit and logged.

# 4. User Stories & Acceptance Criteria

## 4.1 Profile Setup

## 4.2 Delegate Management

## 4.3 Ongoing Management

# 5. API Contracts

All endpoints require authentication via Domain 1. Provider endpoints are scoped to the authenticated physician or the delegate's active physician context.

## 5.1 Provider Profile

## 5.2 Business Arrangements

## 5.3 Practice Locations

## 5.4 WCB Configuration

## 5.5 Delegate Management

## 5.6 Submission Preferences

## 5.7 H-Link Configuration

## 5.8 Internal Provider Context API

These endpoints are consumed internally by the Claim Lifecycle and other domains. They are not exposed to the UI but are part of the service-to-service interface.

# 6. Provider Context Object

The provider context is the key interface between this domain and the Claim Lifecycle. When Domain 4 creates or validates a claim, it requests the provider context for the physician. This context provides all the provider-derived information needed for claim processing without requiring Domain 4 to understand the provider data model.

This context is cached per request and invalidated when any provider data changes. Changes to RRNP rates (quarterly) or PCPCM basket classifications (SOMB update) trigger a cache refresh.

# 7. PCPCM Routing Logic

PCPCM (Patient's Choice Primary Care Model) creates a dual-BA arrangement that requires intelligent claim routing. This section specifies the routing logic that Domain 4.1 invokes via the internal provider context API.

## 7.1 Routing Decision

When a PCPCM-enrolled physician creates an AHCIP claim, the BA is determined by:

Look up the HSC code's PCPCM basket classification in Reference Data (Domain 2).

If the code is in-basket: route to the PCPCM BA.

If the code is out-of-basket: route to the FFS BA.

If the code has no basket classification (rare edge case): route to FFS BA and flag as warning.

The routing decision is made at claim creation time and stored on the AHCIP claim detail. It does not change if the basket classification is updated in a later SOMB version — the version in effect at the DOS governs.

## 7.2 Batch Assembly Impact

PCPCM physicians generate two separate AHCIP batches per Thursday cycle:

Batch 1: All in-basket claims → submitted under PCPCM BA

Batch 2: All out-of-basket claims → submitted under FFS BA

The batch assembly process (Domain 4.1) groups by provider_id + ba_number, which naturally separates these into two files.

## 7.3 Display in UI

The claim creation form shows the routed BA alongside the HSC code. If the physician changes the HSC code, the BA updates in real-time. A visual indicator (badge or colour) distinguishes PCPCM-routed claims from FFS-routed claims. The physician can override the BA routing if needed (with a warning that this may affect payment).

# 8. Locum Support

Locum physicians work at multiple facilities across different communities, often in a single month. Meritum supports this pattern through multi-location management with per-claim location selection.

## 8.1 Locum Workflow

Profile setup: Locum physician adds each practice location with its functional centre and community code. RRNP eligibility and rate are calculated independently per location.

Claim creation: When creating a claim, the locum selects the location from their active locations list. The claim inherits that location's functional centre, facility number, and RRNP rate.

Batch assembly: All claims for the same physician batch together regardless of location. The functional centre and RRNP rate are per-claim, not per-batch.

Reporting: Analytics (Domain 8) breaks down revenue, claims, and rejections by location. Locum physicians see a multi-site comparison view.

## 8.2 Location-Based Defaults

When a locum physician selects a location during claim creation, the following fields auto-populate:

functional_centre: From the location record

facility_number: From the location record (if hospital-based)

rrnp_rate: From the location record (if RRNP-eligible)

after_hours rules: Same statutory holiday list regardless of location (Alberta-wide)

The physician can override any of these defaults on an individual claim.

# 9. Onboarding Workflow

Provider onboarding is a guided wizard that runs after the physician creates their account (Domain 1). The platform is unusable for claim creation until onboarding is complete.

## 9.1 Onboarding Steps

## 9.2 Onboarding Completion

Onboarding is marked complete (onboarding_completed = true) when steps 1–4 and step 7 are finished. Steps 5–6 are optional at onboarding. The system blocks claim creation until onboarding_completed = true.

If the physician abandons onboarding mid-flow, their progress is saved. They resume from where they left off on next login. A banner in the UI shows 'Complete your profile to start billing' until onboarding is finished.

# 10. Security & Audit

## 10.1 Data Protection

Provider data contains professional identity (billing number, CPSA registration) but not PHI. Encrypted at rest as standard practice.

H-Link credentials and WCB vendor credentials are never stored in the database. Stored in secrets management only. Only a reference key is in the database.

Delegate invitation tokens are single-use, time-limited (7 days), and hashed in storage.

RRNP rates and PCPCM basket classifications are not sensitive but are versioned for audit traceability.

## 10.2 Audit Trail

Provider Management actions logged to the system audit log (Domain 1):

# 11. Testing Requirements

## 11.1 Profile Tests

Create provider with valid billing number and CPSA registration

Reject invalid billing number format

Reject duplicate billing number / CPSA registration

Update specialty — verify claim validation context updates for future claims

Onboarding wizard: complete all steps in order, verify onboarding_completed = true

Onboarding wizard: abandon mid-flow, resume on next login, verify progress saved

## 11.2 BA Tests

Add single BA (FFS). Add second BA (PCPCM + FFS pair).

Reject third BA when two active exist

PCPCM constraint: cannot add PCPCM BA without corresponding FFS BA

Deactivate BA — verify claims using this BA can no longer be submitted

BA status transitions: PENDING → ACTIVE → INACTIVE

## 11.3 Location Tests

Add location with community code — RRNP eligibility auto-calculated

Add location without community code — RRNP shows as not eligible

Set default location — verify claim creation uses it

Multiple active locations — all appear in claim creation dropdown

Deactivate location — verify removed from dropdown, existing claims unaffected

Locum workflow: add 3+ locations, create claims at different locations, verify per-claim RRNP

## 11.4 WCB Configuration Tests

Add Contract ID 000001 (GP) — permitted forms include C050E, C151, C568

Add Contract ID 000053 (OIS) — permitted forms include C050S, C151S, C568

Attempt to create WCB claim with form type not in permitted list — rejected

Multiple Contract IDs for same provider — each independently valid

## 11.5 Delegate Tests

Invite delegate with Full Access template — all 24 permissions granted

Invite delegate with Billing Entry template — only subset granted

Delegate accepts invitation — relationship ACTIVE, can switch to physician context

Delegate attempts action outside permissions — rejected by Domain 1 RBAC

Physician revokes delegate — immediate access loss, other physician relationships unaffected

Delegate serves 3 physicians — independent permission sets, context switching works

Permission modification — takes effect immediately on next API call

Expired invitation (>7 days) — cannot be accepted

## 11.6 Submission Preference Tests

Default preferences applied on registration (AUTO_CLEAN for AHCIP, REQUIRE_APPROVAL for WCB)

Change AHCIP mode to AUTO_ALL — verify batch assembly includes flagged claims

Change WCB mode to AUTO_CLEAN — verify WCB batch assembly behaviour

## 11.7 Integration Tests

Full onboarding → claim creation → batch submission pipeline (AHCIP and WCB)

PCPCM routing: create in-basket and out-of-basket claims → verify two separate batches generated with correct BAs

Provider context API: verify claim lifecycle receives correct BA, location, WCB config

RRNP rate change (quarterly): verify cached rate refreshes, new claims use updated rate

Delegate creates claim on behalf of physician: claim owned by physician, delegate in audit trail

# 12. Open Questions

# 13. Document Control

This document specifies the Provider Management domain. It is consumed by the Claim Lifecycle (Domain 4) via the provider context object (Section 6) and the internal provider context API (Section 5.8).

| Domain | Direction | Interface |
| --- | --- | --- |
| 1 Identity & Access | Consumed | User account linkage (one user = one provider). Auth context carries provider_id. Delegate permission enforcement. |
| 2 Reference Data | Consumed | RRNP rate lookup by community. PCPCM basket classification. Specialty-specific governing rule applicability. WCB Contract ID/Role/Form ID matrix. |
| 3 Notification Service | Consumed | BA status change alerts, delegate invitation notifications, accreditation reminders. |
| 4.0 Claim Lifecycle Core | Consumed by | BA number, functional centre, specialty, PCPCM status, RRNP eligibility, submission preferences, WCB config. |
| 4.1 AHCIP Pathway | Consumed by | BA number(s), submitter prefix, H-Link credentials reference, PCPCM basket routing. |
| 4.2 WCB Pathway | Consumed by | WCB Contract ID, Role code, permitted form types, billing number, skill code. |
| 7 Intelligence Engine | Consumed by | Physician specialty, practice patterns, location context for AI Coach calibration. |
| 8 Analytics | Consumed by | Multi-site breakdown dimensions, BA-level revenue attribution. |

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
| created_at | TIMESTAMPTZ | No |  |
| updated_at | TIMESTAMPTZ | No |  |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| ba_id | UUID | No | Primary key |
| provider_id | UUID FK | No | FK to providers |
| ba_number | VARCHAR(10) | No | Business Arrangement number assigned by Alberta Health |
| ba_type | VARCHAR(10) | No | FFS, PCPCM, ARP. Determines fee routing and claim handling. |
| is_primary | BOOLEAN | No | True for the primary BA. For dual-BA physicians, the FFS BA is primary. |
| status | VARCHAR(20) | No | ACTIVE, PENDING, INACTIVE. PENDING during initial setup before Alberta Health confirms linkage. |
| effective_date | DATE | Yes | When the BA became active |
| end_date | DATE | Yes | When the BA was deactivated (null if active) |
| created_at | TIMESTAMPTZ | No |  |
| updated_at | TIMESTAMPTZ | No |  |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| location_id | UUID | No | Primary key |
| provider_id | UUID FK | No | FK to providers |
| name | VARCHAR(100) | No | Physician-assigned name (e.g., 'Main Clinic', 'Edson Hospital', 'Locum - Whitecourt') |
| functional_centre | VARCHAR(10) | No | AHCIP functional centre code. Determines governing rule applicability. |
| facility_number | VARCHAR(10) | Yes | Facility number for hospital-based locations |
| address_line_1 | VARCHAR(100) | Yes | Street address |
| address_line_2 | VARCHAR(100) | Yes |  |
| city | VARCHAR(50) | Yes |  |
| province | VARCHAR(2) | Yes | Default: AB |
| postal_code | VARCHAR(7) | Yes |  |
| community_code | VARCHAR(10) | Yes | Community code for RRNP eligibility lookup |
| rrnp_eligible | BOOLEAN | No | Whether this location qualifies for RRNP. Derived from community_code via Reference Data lookup. |
| rrnp_rate | DECIMAL(8,2) | Yes | Current RRNP rate for this community. Cached from Reference Data, refreshed quarterly. |
| is_default | BOOLEAN | No | True for the physician's primary practice location. Used as default on new claims. |
| is_active | BOOLEAN | No | Active locations appear in claim creation dropdown. |
| created_at | TIMESTAMPTZ | No |  |
| updated_at | TIMESTAMPTZ | No |  |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| enrolment_id | UUID | No | Primary key |
| provider_id | UUID FK | No | FK to providers |
| pcpcm_ba_id | UUID FK | No | FK to business_arrangements (the PCPCM BA) |
| ffs_ba_id | UUID FK | No | FK to business_arrangements (the paired FFS BA) |
| panel_size | INTEGER | Yes | Current PCPCM panel size. Updated periodically. |
| enrolment_date | DATE | No | When the physician enrolled in PCPCM |
| status | VARCHAR(20) | No | ACTIVE, PENDING, WITHDRAWN |
| created_at | TIMESTAMPTZ | No |  |
| updated_at | TIMESTAMPTZ | No |  |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| wcb_config_id | UUID | No | Primary key |
| provider_id | UUID FK | No | FK to providers |
| contract_id | VARCHAR(10) | No | WCB Contract ID (e.g., 000001, 000006, 000053). Determines available form types. |
| role_code | VARCHAR(10) | No | WCB Role code (e.g., GP, SP, OR, OIS). Paired with Contract ID. |
| skill_code | VARCHAR(10) | Yes | WCB Skill code. Defaults based on specialty but may be overridden. |
| permitted_form_types | JSONB | No | Array of form IDs this Contract ID/Role can create (e.g., ['C050E','C151','C568']). Derived from WCB matrix, stored for fast lookup. |
| is_default | BOOLEAN | No | Default WCB config for this provider. Used when creating WCB claims. |
| created_at | TIMESTAMPTZ | No |  |
| updated_at | TIMESTAMPTZ | No |  |

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
| created_at | TIMESTAMPTZ | No |  |
| updated_at | TIMESTAMPTZ | No |  |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| preference_id | UUID | No | Primary key |
| provider_id | UUID FK | No | FK to providers. Unique. |
| ahcip_submission_mode | VARCHAR(20) | No | AUTO_CLEAN, AUTO_ALL, REQUIRE_APPROVAL. Default: AUTO_CLEAN. |
| wcb_submission_mode | VARCHAR(20) | No | AUTO_CLEAN, AUTO_ALL, REQUIRE_APPROVAL. Default: REQUIRE_APPROVAL (WCB timing is more sensitive). |
| batch_review_reminder | BOOLEAN | No | True = remind physician to review flagged claims before Thursday cutoff. Default: true. |
| deadline_reminder_days | INTEGER | No | Days before submission deadline to send first reminder. Default: 7. |
| updated_at | TIMESTAMPTZ | No |  |
| updated_by | UUID FK | No | Who last changed preferences |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| hlink_config_id | UUID | No | Primary key |
| provider_id | UUID FK | No | FK to providers. Unique. |
| submitter_prefix | VARCHAR(10) | No | H-Link submitter prefix assigned during accreditation |
| credential_secret_ref | VARCHAR(100) | No | Reference to H-Link transmission credentials in secrets management (HashiCorp Vault / DigitalOcean encrypted secrets). NOT the credentials themselves. |
| accreditation_status | VARCHAR(20) | No | PENDING, ACTIVE, SUSPENDED. Claims cannot be submitted until ACTIVE. |
| accreditation_date | DATE | Yes | When H-Link accreditation was granted |
| last_successful_transmission | TIMESTAMPTZ | Yes | Last successful batch transmission timestamp |
| created_at | TIMESTAMPTZ | No |  |
| updated_at | TIMESTAMPTZ | No |  |

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

| Template | Permissions Included |
| --- | --- |
| Full Access | All 24 permissions. For trusted billing agents who manage the entire workflow. |
| Billing Entry | CLAIM_CREATE, CLAIM_EDIT, CLAIM_VIEW, CLAIM_QUEUE, IMPORT_EMR, PATIENT_VIEW, PATIENT_CREATE, SHIFT_MANAGE, AI_COACH_REVIEW. For data entry staff. |
| Review & Submit | CLAIM_VIEW, CLAIM_APPROVE, BATCH_VIEW, BATCH_DOWNLOAD, BATCH_CONFIRM_UPLOAD, REJECTION_MANAGE, REPORT_VIEW. For billing managers who review and submit but don't enter data. |
| View Only | CLAIM_VIEW, BATCH_VIEW, PATIENT_VIEW, REPORT_VIEW. For accountants or auditors. |
| Custom | Physician selects individual permissions. |

| ID | Story | Acceptance Criteria |
| --- | --- | --- |
| PRV-001 | As a new physician, I want to set up my professional profile during onboarding so that the platform can configure my billing context | Guided wizard: billing number, CPSA registration, specialty, physician type. Billing number validated against AHCIP format (5-digit numeric). CPSA validated against known format. Specialty selected from AHCIP specialty code list. Profile marked incomplete until all required fields set. |
| PRV-002 | As a physician, I want to add my BA number(s) so that claims route to the correct payment destination | Enter BA number. System validates format. Status set to PENDING until physician confirms linkage with Alberta Health. For PCPCM physicians: guided flow to add both PCPCM BA and FFS BA. System enforces dual-BA requirement. |
| PRV-003 | As a physician, I want to add my practice locations so that claims default to the correct functional centre | Add location with name, functional centre code, optional facility number, and address. Community code looked up for RRNP eligibility. Set one location as default. Multiple locations supported. |
| PRV-004 | As a physician, I want to configure my WCB billing identity so I can submit WCB claims | Select Contract ID from dropdown (populated from WCB matrix). System auto-populates permitted Role codes and form types. Physician confirms. Can add multiple Contract IDs if applicable (e.g., GP + OIS). |

| ID | Story | Acceptance Criteria |
| --- | --- | --- |
| PRV-005 | As a physician, I want to invite a delegate so they can help manage my billing | Enter delegate email. Select permission template or configure custom. System sends invitation email via Notification Service. Invitation expires in 7 days. Delegate creates account (if new) or accepts (if existing) via invitation link. |
| PRV-006 | As a delegate, I want to accept an invitation and access the physician's billing | Click invitation link. Create account or log in. Accept invitation. Relationship becomes ACTIVE. Delegate can now switch to physician's context. |
| PRV-007 | As a physician, I want to modify my delegate's permissions | View current permissions. Toggle individual permissions or switch template. Changes take effect immediately. Audit logged. |
| PRV-008 | As a physician, I want to revoke a delegate's access | Revoke action. Confirm with dialog. Relationship status set to REVOKED. Delegate immediately loses access to this physician's data. Other physician relationships unaffected. |
| PRV-009 | As a delegate, I want to switch between physician contexts | Dropdown shows all physicians I serve (ACTIVE relationships only). Select physician. Auth context updates. All subsequent actions scoped to selected physician. |

| ID | Story | Acceptance Criteria |
| --- | --- | --- |
| PRV-010 | As a physician, I want to update my specialty or practice details | Edit specialty, add/remove practice locations, update BA details. Changes are audit-logged. If specialty changes, validation context updates for future claims (existing claims unaffected). |
| PRV-011 | As a physician, I want to set my submission preferences | Select AHCIP mode (Auto Clean, Auto All, Require Approval). Select WCB mode independently. Enable/disable batch review reminders. Set deadline reminder threshold. Defaults applied on registration. |
| PRV-012 | As a physician, I want to see my RRNP eligibility and current rate | Dashboard card shows RRNP status per location. Rate displayed per community. Updated quarterly from Reference Data. If rate changes, notification emitted. |
| PRV-013 | As a physician, I want to add a new practice location when I start working at a different site | Add location flow (same as PRV-003). New location immediately available in claim creation dropdown. Claims for existing locations unaffected. |
| PRV-014 | As a locum physician, I want to manage multiple practice locations across different communities | Add each location with its functional centre and community code. RRNP eligibility calculated per location. Claims select location at creation time. Monthly reporting shows breakdown by location. |

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/providers/me | Get the authenticated physician's full profile including BAs, locations, WCB config, PCPCM status, RRNP eligibility. |
| PUT | /api/v1/providers/me | Update profile fields (specialty, physician_type, name). Audit-logged. |
| GET | /api/v1/providers/me/onboarding-status | Check onboarding completion status. Returns missing required fields. |
| POST | /api/v1/providers/me/complete-onboarding | Mark onboarding as complete. Validates all required fields are set. Fails if any are missing. |

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/providers/me/bas | List all BAs for the physician. |
| POST | /api/v1/providers/me/bas | Add a BA. Validates format and type constraints. |
| PUT | /api/v1/providers/me/bas/{id} | Update BA details (status, dates). |
| DELETE | /api/v1/providers/me/bas/{id} | Deactivate a BA. Sets end_date and status = INACTIVE. |

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/providers/me/locations | List all practice locations. |
| POST | /api/v1/providers/me/locations | Add a practice location. Auto-lookups RRNP eligibility from community code. |
| PUT | /api/v1/providers/me/locations/{id} | Update location details. |
| PUT | /api/v1/providers/me/locations/{id}/set-default | Set as default location. |
| DELETE | /api/v1/providers/me/locations/{id} | Deactivate location (soft-delete). |

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/providers/me/wcb | List all WCB configurations. |
| POST | /api/v1/providers/me/wcb | Add a WCB Contract ID/Role. Validates against WCB matrix. Auto-populates permitted form types. |
| PUT | /api/v1/providers/me/wcb/{id} | Update WCB config (skill code, default status). |
| DELETE | /api/v1/providers/me/wcb/{id} | Remove a WCB configuration. |
| GET | /api/v1/providers/me/wcb/form-permissions | Get aggregated permitted form types across all Contract IDs for the physician. |

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/providers/me/delegates | List all delegates (active, invited, revoked). |
| POST | /api/v1/providers/me/delegates/invite | Invite a delegate. Body: email, permissions (template or custom array). Triggers invitation email. |
| PUT | /api/v1/providers/me/delegates/{rel_id}/permissions | Update delegate permissions. Body: new permission array. |
| POST | /api/v1/providers/me/delegates/{rel_id}/revoke | Revoke delegate access. |
| GET | /api/v1/delegates/me/physicians | For delegates: list all physicians I serve with my permissions for each. |
| POST | /api/v1/delegates/me/switch-context/{provider_id} | For delegates: switch active physician context. |
| POST | /api/v1/delegates/invitations/{token}/accept | Accept a delegate invitation. |

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/providers/me/submission-preferences | Get current submission preferences. |
| PUT | /api/v1/providers/me/submission-preferences | Update submission preferences. Audit-logged. |

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/providers/me/hlink | Get H-Link configuration (submitter prefix, accreditation status). Credentials are never returned. |
| PUT | /api/v1/providers/me/hlink | Update H-Link config (submitter prefix, accreditation status). Credential updates route to secrets management. |

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/internal/providers/{id}/claim-context | Returns the full context needed for claim creation: BAs, default location, specialty, PCPCM status, WCB configs, RRNP eligibility. Consumed by Domain 4.0. |
| GET | /api/v1/internal/providers/{id}/ba-for-claim | Given a claim_type and optional HSC code, returns the correct BA number. Handles PCPCM basket routing. |
| GET | /api/v1/internal/providers/{id}/wcb-config-for-form | Given a WCB form_id, returns the matching Contract ID/Role or error if not permitted. Consumed by Domain 4.2. |

| Field | Type | Description |
| --- | --- | --- |
| provider_id | UUID | Provider identifier |
| billing_number | VARCHAR(10) | AHCIP practitioner ID |
| specialty_code | VARCHAR(10) | Primary specialty |
| physician_type | VARCHAR(20) | GP, SPECIALIST, LOCUM |
| bas | Array | All active BAs with ba_number, ba_type, is_primary |
| default_location | Object | Default practice location with functional_centre, facility_number, community_code, rrnp_eligible, rrnp_rate |
| all_locations | Array | All active locations (for claim creation dropdown) |
| pcpcm_enrolled | BOOLEAN | Whether physician is PCPCM-enrolled |
| pcpcm_ba_number | VARCHAR(10) | PCPCM BA number (null if not enrolled) |
| ffs_ba_number | VARCHAR(10) | FFS BA number (always present) |
| wcb_configs | Array | All WCB configurations with contract_id, role_code, permitted_form_types |
| default_wcb_config | Object | Default WCB config (null if none) |
| submission_preferences | Object | AHCIP and WCB submission modes, reminder settings |
| hlink_accreditation_status | VARCHAR(20) | PENDING, ACTIVE, SUSPENDED |
| hlink_submitter_prefix | VARCHAR(10) | H-Link submitter prefix |
| onboarding_completed | BOOLEAN | Whether profile setup is complete |
| status | VARCHAR(20) | Provider status (ACTIVE, SUSPENDED, INACTIVE) |

| # | Step | Required Fields | Notes |
| --- | --- | --- | --- |
| 1 | Professional Identity | billing_number, cpsa_registration_number, first/last name | Validated against known formats. Not verified against CPSA registry at MVP (future enhancement). |
| 2 | Specialty & Type | specialty_code, physician_type | Specialty from AHCIP code list. Type determines default workflow (GP vs specialist vs locum). |
| 3 | Business Arrangement | At least one BA number | BA status set to PENDING. Physician can confirm active later. PCPCM flow triggered if physician selects 'PCPCM enrolled'. |
| 4 | Primary Practice Location | At least one location with functional_centre | Community code optional but recommended for RRNP. Address optional. |
| 5 | WCB Configuration | Optional — can be skipped | If physician bills WCB, add Contract ID. Otherwise skip. Can be added later from settings. |
| 6 | Submission Preferences | Defaults applied | Physician can accept defaults (Auto Clean for AHCIP, Require Approval for WCB) or customise. Shown as final step. |
| 7 | IMA Generation | Physician reviews and acknowledges | Information Manager Agreement generated from template. Physician as HIA custodian. Digital acknowledgement stored. |

| Action | Details Logged |
| --- | --- |
| PROVIDER_PROFILE_UPDATED | Field-level diff (old vs new value). Actor identity. |
| BA_ADDED / BA_UPDATED / BA_DEACTIVATED | BA number, type, status change. Actor identity. |
| LOCATION_ADDED / LOCATION_UPDATED / LOCATION_DEACTIVATED | Location details. RRNP eligibility change if applicable. |
| WCB_CONFIG_ADDED / WCB_CONFIG_UPDATED / WCB_CONFIG_REMOVED | Contract ID, Role code. Permitted form types delta. |
| DELEGATE_INVITED | Delegate email, permissions granted, invitation timestamp. |
| DELEGATE_ACCEPTED | Delegate user_id, physician_id, timestamp. |
| DELEGATE_PERMISSIONS_CHANGED | Old vs new permission set. Actor identity. |
| DELEGATE_REVOKED | Delegate user_id, actor identity, timestamp. |
| SUBMISSION_PREFERENCE_CHANGED | Old vs new mode. Actor identity. |
| ONBOARDING_COMPLETED | Timestamp, all required fields confirmed. |
| HLINK_CONFIG_UPDATED | Submitter prefix, accreditation status change. Credential changes logged as 'credential rotated' without values. |

| # | Question | Context |
| --- | --- | --- |
| 1 | Should billing number and CPSA registration be verified against external registries at onboarding? | Currently validated for format only. CPSA has a public registry. AHCIP practitioner lookup may require Alberta Health integration. |
| 2 | How should BA status be confirmed (PENDING → ACTIVE)? | Manual confirmation by physician after they verify with Alberta Health? Or automated via H-Link test submission? |
| 3 | Should delegates have their own submission preference overrides, or always inherit the physician's? | Currently physician-only. Some billing agents may want different notification preferences. |
| 4 | Should practice location addresses be validated against Canada Post data? | Would improve data quality. Cost and complexity of postal code validation API integration vs manual entry. |
| 5 | Is there a maximum number of delegates per physician, or is it unlimited? | Unlimited is simplest. May want a cap for security (e.g., max 10 active delegates). |
| 6 | Should PCPCM basket routing be overridable by the physician, or strictly enforced? | Currently allowing override with warning. Strict enforcement would prevent billing errors but may frustrate physicians who understand edge cases. |

| Item | Value |
| --- | --- |
| Parent document | Meritum PRD v1.3 |
| Domain | Provider Management (Domain 5 of 13) |
| Build sequence position | 5th (consumed by Claim Lifecycle and all submission pathways) |
| Dependencies | Domain 1 (IAM), Domain 2 (Reference Data), Domain 3 (Notifications) |
| Consumed by | Domain 4.0 (Core), Domain 4.1 (AHCIP), Domain 4.2 (WCB), Domain 7 (Intelligence Engine), Domain 8 (Analytics) |
| Version | 1.0 |
| Date | February 2026 |
| Next domain in critical path | Domain 6 (Patient Registry) |

