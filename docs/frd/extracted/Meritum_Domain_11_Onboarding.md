# Meritum_Domain_11_Onboarding

MERITUM

Functional Requirements

Onboarding

Domain 11 of 13  |  First-Run Experience

Meritum Health Technologies Inc.

Version 1.0  |  February 2026

CONFIDENTIAL

# Table of Contents

# 1. Domain Overview

## 1.1 Purpose

The Onboarding domain orchestrates the first-run experience for new Meritum physicians. It bridges account creation (Domain 1) and full platform usage by guiding the physician through a sequence of steps that configure their billing identity, satisfy regulatory requirements, and prepare the platform for claim creation.

The target: a physician should go from 'I just signed up' to 'I can create my first claim' in under 10 minutes. Every step is essential — the platform is unusable for billing until onboarding is complete — but the experience should feel lightweight and purposeful, not bureaucratic.

## 1.2 Scope

Guided onboarding wizard (7 steps, ~10 minutes)

IMA (Information Manager Agreement) generation per HIA s.66

PIA (Privacy Impact Assessment) appendix download

AHC11236 form pre-fill (BA linkage to Meritum submitter prefix)

BA status tracking during AHCIP processing (2–4 weeks)

Optional patient CSV import during onboarding

Onboarding progress persistence (resume on abandon/return)

Post-onboarding guided tour of the platform

## 1.3 Out of Scope

Account creation and authentication (Domain 1 Identity & Access)

Stripe subscription setup (Domain 12 Platform Operations; payment setup happens before onboarding)

Provider profile management post-onboarding (Domain 5 Provider Management)

WCB vendor accreditation (external process; Meritum captures the resulting Contract ID)

## 1.4 Domain Dependencies

# 2. Onboarding Flow

## 2.1 Step Sequence

Steps 1–4 and 7 are required for onboarding completion. Steps 5–6 are optional and can be deferred. The platform blocks claim creation until onboarding_completed = true (set when required steps are finished).

## 2.2 Progress Persistence

If the physician abandons onboarding mid-flow (closes browser, loses connectivity, gets interrupted):

All completed steps are saved to the provider record immediately on step completion.

On next login, the physician is returned to the first incomplete required step.

A progress indicator shows completed vs remaining steps.

The physician can navigate back to review or edit completed steps.

A persistent banner ('Complete your profile to start billing') appears on every page until onboarding is done.

# 3. IMA Generation

## 3.1 Regulatory Context

Under the Health Information Act (HIA) s.66, a custodian who uses an information manager to collect, use, or disclose individually identifying health information must enter into an Information Manager Agreement (IMA) with that information manager. Meritum acts as the information manager; the physician is the custodian. The IMA must be in place before Meritum processes any PHI on the physician's behalf.

## 3.2 IMA Content

The IMA is generated from a template pre-approved by Meritum's legal counsel. It is pre-filled with:

Physician's legal name (from Step 1)

CPSA registration number

Business Arrangement number(s)

Meritum Health Technologies Inc. corporate details

Effective date (date of acknowledgement)

Service description: electronic claims submission and billing management

Data handling obligations: encryption at rest and in transit, Canadian data residency, breach notification, retention and disposal

Termination provisions: data portability on termination, data deletion timeline

## 3.3 Digital Acknowledgement

The physician reviews the IMA in-app (scrollable document viewer) and clicks 'I Acknowledge and Agree'. This is not a signature in the legal sense — it is a digital acknowledgement. Stored data:

The rendered IMA PDF is stored immutably. If the IMA template is updated, existing physicians are prompted to re-acknowledge on next login.

## 3.4 PIA Appendix

Alongside the IMA, Meritum provides a Privacy Impact Assessment (PIA) summary appendix for the physician's records. This is a downloadable PDF that describes Meritum's privacy safeguards in physician-friendly language. It is informational — no acknowledgement required. Available from the IMA step and from settings post-onboarding.

# 4. AHC11236 Form Pre-Fill

The AHC11236 is the Alberta Health form for linking a Business Arrangement to an accredited submitter. The physician must submit this form to Alberta Health to authorise Meritum to submit claims on their behalf. Processing takes 2–4 weeks.

## 4.1 Pre-Fill Strategy

Meritum pre-fills the AHC11236 with:

Physician's name and billing number (from Step 1)

BA number (from Step 3)

Meritum's submitter prefix and accredited submitter details

Effective date (physician selects)

The pre-filled form is generated as a PDF. The physician downloads it, prints, signs with a wet signature (Alberta Health currently requires a physical signature), and mails or faxes it to Alberta Health. Meritum cannot submit this form electronically on the physician's behalf.

## 4.2 BA Linkage Status Tracking

After the physician submits the AHC11236, the BA status in Meritum is PENDING. The physician manually confirms when Alberta Health processes the linkage (2–4 weeks). Future enhancement: detect active linkage via first successful H-Link test submission.

While BA status is PENDING, the physician can create and validate claims but cannot submit batches. This allows them to start using Meritum immediately while waiting for Alberta Health processing.

# 5. Optional Patient Import

After required onboarding steps, the physician is offered an optional patient import step. This is the same CSV import functionality specified in Domain 6 (Patient Registry) Section 5, surfaced as a convenience during onboarding.

If the physician imports patients now, they have a populated patient registry ready for claim creation.

If they skip, they can import later from the Patient Registry settings or add patients individually during claim creation.

The onboarding flow shows a summary of import results (created, updated, skipped, errors) before proceeding.

# 6. Post-Onboarding Guided Tour

After onboarding completes, the physician is offered an optional guided tour of the platform. The tour highlights key features with overlay tooltips:

**Dashboard overview:** 'This is your billing dashboard. You can see your revenue, pending claims, and recent activity here.'

**Create a claim:** 'Tap here to create your first claim. Select a patient, enter a code, and save.'

**AI Coach:** 'After you save a claim, the AI Coach may suggest optimisations. You can accept or dismiss suggestions.'

**Thursday batch:** 'Your claims are submitted every Thursday. You can review the queue before submission.'

**Notifications:** 'Important events appear here — rejections, deadlines, and assessment results.'

**Help:** 'Hover over any field to see a tooltip. Complex billing rules are explained in plain language.'

The tour is dismissible at any point. It does not re-appear after completion or dismissal. A 'Replay tour' option is available in settings.

# 7. Data Model

Onboarding does not own its own major tables. It writes to Provider Management tables (Domain 5) and tracks onboarding-specific state:

## 7.1 Onboarding Progress Table (onboarding_progress)

## 7.2 IMA Records Table (ima_records)

See Section 3.3 for field definitions. One row per IMA acknowledgement. Multiple rows possible if physician re-acknowledges after template update.

# 8. User Stories & Acceptance Criteria

# 9. API Contracts

# 10. Testing Requirements

Complete all 7 steps in sequence → onboarding_completed = true, claims can be created

Complete steps 1–4 and 7, skip 5–6 → onboarding_completed = true

Complete steps 1–3 only → onboarding_completed = false, claim creation blocked

Abandon after step 2, return → resume at step 3, steps 1–2 data preserved

PCPCM flow: select PCPCM enrolled at step 3 → dual-BA entry enforced

IMA acknowledgement: timestamp, hash, IP stored. PDF downloadable and matches displayed content.

AHC11236 PDF: correct physician details, correct Meritum submitter prefix, downloadable

Patient import during onboarding: same behaviour as Domain 6 CSV import

Guided tour: completes all 6 stops. Dismiss mid-tour. Does not reappear.

BA status: PENDING after step 3. Manual confirm to ACTIVE. Claims submittable only when ACTIVE.

Full onboarding → create first claim → validate → queue: end-to-end integration test

# 11. Open Questions

# 12. Document Control

This domain orchestrates first-run configuration. It writes to Provider Management tables and provides regulatory compliance (IMA, AHC11236 pre-fill) during the setup process.

| Domain | Direction | Interface |
| --- | --- | --- |
| 1 Identity & Access | Consumed | Account exists before onboarding starts. Onboarding creates the provider profile linked to the user. |
| 2 Reference Data | Consumed | AHCIP specialty codes, functional centre codes, community codes for RRNP lookup. |
| 5 Provider Management | Produces | Onboarding creates provider profile, BA records, practice locations, WCB config, submission preferences. |
| 6 Patient Registry | Produces | Optional CSV patient import during onboarding. |
| 12 Platform Operations | Consumed | Subscription must be active (or in trial) before onboarding proceeds. |

| # | Step | Required | Description |
| --- | --- | --- | --- |
| 1 | Professional Identity | Yes | Billing number (AHCIP practitioner ID, 5-digit numeric), CPSA registration number, legal name. Format validation on entry. This data creates the providers record. |
| 2 | Specialty & Type | Yes | Select specialty from AHCIP specialty code list (dropdown with search). Select physician type: GP, Specialist, or Locum. Determines default workflow and validation context. |
| 3 | Business Arrangement | Yes | Enter primary BA number. System validates format. If PCPCM enrolled, guided flow to add both PCPCM BA and FFS BA. BA status set to PENDING until Alberta Health confirms linkage. Pre-fills AHC11236 form. |
| 4 | Practice Location | Yes | Add primary practice location: name, functional centre code (dropdown with search), optional facility number, address, community code. RRNP eligibility auto-calculated from community code. Additional locations can be added now or later. |
| 5 | WCB Configuration | No | If physician bills WCB: add Contract ID, Role, and Skill code. Auto-populates permitted form types. Can be skipped and configured later from settings. |
| 6 | Submission Preferences | No | Review and accept defaults (Auto Clean for AHCIP, Require Approval for WCB) or customise. Explanation of each mode with visual diagram. Can be changed later. |
| 7 | IMA Acknowledgement | Yes | Information Manager Agreement generated from template with physician's details pre-filled. Physician reviews and digitally acknowledges. Acknowledgement timestamp and hash stored. PIA appendix available for download. |

| Field | Type | Description |
| --- | --- | --- |
| ima_id | UUID | Primary key |
| provider_id | UUID FK | FK to providers |
| template_version | VARCHAR(20) | IMA template version used |
| document_hash | VARCHAR(64) | SHA-256 hash of the rendered IMA document at time of acknowledgement |
| acknowledged_at | TIMESTAMPTZ | Timestamp of acknowledgement |
| ip_address | VARCHAR(45) | IP address at time of acknowledgement |
| user_agent | VARCHAR(500) | Browser user agent at time of acknowledgement |

| Status | Meaning |
| --- | --- |
| PENDING | AHC11236 submitted to Alberta Health. Waiting for processing. Claims can be created and queued but not transmitted. |
| ACTIVE | Alberta Health confirmed linkage. Claims can be submitted via H-Link. |
| INACTIVE | BA deactivated (physician request, Alberta Health action, or end date reached). |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| progress_id | UUID | No | Primary key |
| provider_id | UUID FK | No | FK to providers |
| step_1_completed | BOOLEAN | No | Professional Identity |
| step_2_completed | BOOLEAN | No | Specialty & Type |
| step_3_completed | BOOLEAN | No | Business Arrangement |
| step_4_completed | BOOLEAN | No | Practice Location |
| step_5_completed | BOOLEAN | No | WCB Configuration (optional) |
| step_6_completed | BOOLEAN | No | Submission Preferences (optional) |
| step_7_completed | BOOLEAN | No | IMA Acknowledgement |
| patient_import_completed | BOOLEAN | No | Optional patient import |
| guided_tour_completed | BOOLEAN | No | Post-onboarding tour |
| guided_tour_dismissed | BOOLEAN | No | Tour dismissed without completing |
| started_at | TIMESTAMPTZ | No | When onboarding began |
| completed_at | TIMESTAMPTZ | Yes | When onboarding completed (required steps done) |

| ID | Story | Acceptance Criteria |
| --- | --- | --- |
| ONB-001 | As a new physician, I want to set up my billing profile in under 10 minutes | 7-step wizard. Progress indicator. Required fields clearly marked. Format validation on entry. Total time < 10 minutes for required steps. |
| ONB-002 | As a new physician, I want to acknowledge the IMA so I'm compliant with HIA | IMA rendered with my details. Scrollable viewer. Acknowledge button. Timestamp, hash, and IP recorded. PDF stored immutably. |
| ONB-003 | As a new physician, I want a pre-filled AHC11236 to send to Alberta Health | PDF generated with my details and Meritum's submitter info. Download button. Instructions for submission (mail/fax). |
| ONB-004 | As a new physician, I want to import my patient list during setup | CSV upload offered after required steps. Column mapping preview. Import summary. Skippable. |
| ONB-005 | As a new physician, I want to resume onboarding if I get interrupted | Close browser mid-flow. Log in again. Returned to first incomplete required step. All prior steps preserved. |
| ONB-006 | As a new physician, I want a tour of the platform after setup | Guided tour with overlay tooltips. 6 stops. Dismissible. Does not reappear. Replay from settings. |
| ONB-007 | As a physician, I want to know when my BA is active with Alberta Health | BA status visible in settings and onboarding summary. PENDING badge visible. Physician can manually confirm ACTIVE. |
| ONB-008 | As a physician with a PCPCM arrangement, I want the onboarding to guide me through dual-BA setup | When PCPCM selected, wizard explains dual-BA requirement. Guided entry of both PCPCM BA and FFS BA. System enforces both present. |

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/onboarding/progress | Get current onboarding progress. Returns step completion status. |
| POST | /api/v1/onboarding/steps/{step_number} | Complete a step. Body: step-specific data. Writes to Provider Management tables. Returns updated progress. |
| GET | /api/v1/onboarding/ima | Get rendered IMA document for the physician. |
| POST | /api/v1/onboarding/ima/acknowledge | Record IMA acknowledgement. Stores timestamp, hash, IP, user agent. |
| GET | /api/v1/onboarding/ima/download | Download IMA as PDF. |
| GET | /api/v1/onboarding/ahc11236/download | Download pre-filled AHC11236 form as PDF. |
| GET | /api/v1/onboarding/pia/download | Download PIA appendix PDF. |
| POST | /api/v1/onboarding/guided-tour/complete | Mark guided tour as completed. |
| POST | /api/v1/onboarding/guided-tour/dismiss | Mark guided tour as dismissed. |

| # | Question | Context |
| --- | --- | --- |
| 1 | Can the AHC11236 be submitted electronically by the physician? | Currently requires wet signature and mail/fax. Alberta Health may accept electronic submission in future. Monitor. |
| 2 | Should Meritum auto-detect BA linkage activation via H-Link test? | Could eliminate manual PENDING → ACTIVE confirmation. Requires H-Link test submission capability and interpretation of response. |
| 3 | Should IMA re-acknowledgement be blocking? | When IMA template updates, should the physician be blocked from platform use until re-acknowledged? Or warning only? |
| 4 | Should onboarding offer a trial period before payment? | Current: payment setup before onboarding. Alternative: 14-day trial with full onboarding, payment required to continue. Business decision. |

| Item | Value |
| --- | --- |
| Parent document | Meritum PRD v1.3 |
| Domain | Onboarding (Domain 11 of 13) |
| Build sequence position | Parallel with core domains (UI layer on top of Provider Management and Patient Registry) |
| Dependencies | Domain 1 (IAM), Domain 2 (Reference Data), Domain 5 (Provider Management), Domain 6 (Patient Registry), Domain 12 (Platform Ops) |
| Version | 1.0 |
| Date | February 2026 |

