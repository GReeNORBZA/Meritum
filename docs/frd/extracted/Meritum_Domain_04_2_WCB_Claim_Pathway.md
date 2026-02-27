# Meritum_Domain_04_2_WCB_Claim_Pathway

MERITUM

Functional Requirements

WCB Claim Pathway (EIR)

Domain 4.2 of 13  |  Critical Path: Position 4

Meritum Health Technologies Inc.

Version 1.0  |  February 2026

CONFIDENTIAL

# Table of Contents

# 1. Domain Overview

## 1.1 Purpose

The WCB Claim Pathway domain specifies how Meritum captures, validates, assembles, submits, and reconciles Workers' Compensation Board (WCB) Alberta claims. WCB claims follow a submission pathway that is entirely separate from AHCIP/H-Link: different forms, different data schemas, different file formats, different accreditation, different payment cycles, and different fee schedules.

This domain covers the full WCB Electronic Injury Reporting (EIR) lifecycle as defined in the WCB Vendor Accreditation Package. It specifies 8 form types (C050E, C050S, C151, C151S, C568, C568A, C569, C570), the HL7 v2.3.1 XML batch submission format, return file processing, and payment remittance reconciliation. The Phase 2 direct batch submission pathway is the primary specification; the transitional MVP (WCB Submission Helper) is documented as a stepping stone during vendor accreditation.

## 1.2 Scope

WCB claim data capture for all 8 EIR form types with form-specific field sets and conditional logic

WCB-specific validation: POB-NOI combination restrictions, Contract ID/Role/Form ID enforcement, conditional field optionality, timing deadline calculations

WCB fee calculation: timing-based tiers (same-day, on-time, late), 351 premium codes, expedited services, unbundling rules

Phase 2 submission pipeline: HL7 v2.3.1 XML batch file generation, XSD validation, myWCB portal upload, batch return file processing

Transitional MVP: WCB Submission Helper (data capture, fee calculation, deadline tracking, pre-filled export for manual portal entry)

WCB batch return file ingestion: parsing, error matching, claim state transitions

WCB payment remittance reconciliation: separate XML schema, disbursement matching, overpayment tracking

WCB-specific API endpoints for claim CRUD, batch management, return file ingestion, and remittance import

## 1.3 Out of Scope

AHCIP/H-Link claim pathway (Domain 4.1)

Shared claim state machine, base claims table, validation engine architecture, and cross-pathway infrastructure (Domain 4.0 Core)

WCB vendor accreditation process itself (administrative; see Accreditation Package document 10)

myWCB portal automation (Phase 2 is file upload, not portal UI automation)

WCB policy adjudication logic (Meritum submits claims; WCB decides acceptance)

## 1.4 Domain Dependencies

## 1.5 Relationship to Domain 4.0 and 4.1

This document is one of three sub-domains comprising Domain 4 (Claim Lifecycle):

Domain 4.0 (Claim Lifecycle Core) defines the shared claim state machine, base data model, validation engine architecture, clean/flagged classification, tiered auto-submission model, and cross-pathway API patterns. Both 4.1 and 4.2 extend these foundations.

Domain 4.1 (AHCIP Claim Pathway) specifies H-Link file generation, Thursday batch cycle, AHCIP assessment response ingestion, and AHCIP-specific validation rules.

Domain 4.2 (this document) specifies the WCB EIR pathway. A WCB claim in Meritum is a record in the shared claims table (Domain 4.0) with claim_type = 'WCB', linked to WCB-specific detail tables defined here. The claim state machine from 4.0 applies identically; only the submission, return, and reconciliation pipelines differ.

# 2. WCB Form Types

WCB Alberta uses 8 electronic report/invoice form types for physician billing via the Electronic Injury Reporting (EIR) system. Each form serves a distinct purpose, carries different field requirements, and is available only to specific practitioner Contract ID / Role combinations. Understanding these relationships is foundational to the data model and validation engine.

## 2.1 Form Type Overview

## 2.2 Form Sections by Type

Each form type comprises a subset of 10 possible sections. The following matrix identifies which sections appear in which forms. This governs both the UI presentation (which form sections to show) and validation (which field groups are applicable).

## 2.3 Contract ID / Role / Form ID Relationships

Not every practitioner can submit every form type. The WCB enforces a relationship matrix between the practitioner's Contract ID, their Role, and the form types they may create. This matrix is a hard validation rule — submissions violating it are rejected.

### 2.3.1 Initial Report Permissions

### 2.3.2 Follow-Up Report Permissions

Follow-up reports have an additional constraint: they can only be created from specific initial or prior report types. This is enforced during claim creation — the user must link to a prior WCB claim, and the system validates the chain.

# 3. Data Model

The WCB data model extends the base claims table defined in Domain 4.0 Core. A WCB claim is a record in the claims table with claim_type = 'WCB' and a mandatory foreign key to the wcb_claim_details table. WCB-specific child tables capture the repeating groups (injuries, prescriptions, consultations, work restrictions, invoice lines, attachments) that are unique to WCB form types.

The data model is normalised to support all 8 form types from a single set of tables. Not all tables are populated for every form type — the form_id on wcb_claim_details determines which child tables are applicable. The form section matrix (Section 2.2) governs which tables are expected to have data.

## 3.1 WCB Claim Details Table (wcb_claim_details)

The central WCB extension table. One row per WCB claim, linked 1:1 to the base claims table. Contains all scalar (non-repeating) fields across form sections. Fields that are only applicable to certain form types are nullable; the validation engine enforces form-specific requirements.

### 3.1.1 General Fields

### 3.1.2 Practitioner Fields

Populated from Provider Management (Domain 5) but stored on the WCB claim for submission immutability — the values at time of submission are what gets sent.

### 3.1.3 Patient (Claimant) Fields

Core patient demographics are resolved from Patient Registry (Domain 6) at claim creation. Stored on the WCB claim for immutability. WCB has specific field length constraints that differ from AH.

### 3.1.4 Employer Fields

Required for C050E, C050S, C151, C151S only (forms with Employer section per Section 2.2). Null for C568, C568A, C569, C570.

### 3.1.5 Accident Fields

### 3.1.6 Injury Assessment Fields (Scalar)

These fields capture the physician's clinical assessment. Applicable to forms with Injury section (C050E/S, C151/S, C568, C568A). Repeating injury entries (POB/SOB/NOI sets) are in the wcb_injuries child table (Section 3.2).

### 3.1.7 Treatment Plan Fields (Scalar)

Applicable to C050E/S, C151/S, C568A. Repeating groups (prescriptions, consultations) are in child tables.

### 3.1.8 Opioid Management Fields (C151/C151S Only)

The C151 progress report includes 16 opioid monitoring fields that become conditionally required when narcotics_prescribed = Y. These fields track medication side effects and abuse indicators.

### 3.1.9 Return to Work Fields (Scalar)

Applicable to C050E/S, C151/S. Work restriction repeating entries are in the wcb_work_restrictions child table (Section 3.5).

### 3.1.10 Invoice Correction Fields (C570 Only)

Timestamps and metadata (created_at, updated_at, created_by, updated_by) follow the pattern established in Domain 4.0 Core. Soft-delete via deleted_at.

## 3.2 WCB Injuries Table (wcb_injuries)

Each WCB claim with an Injury section can have 1–5 injury entries, each being a Part of Body / Side of Body / Nature of Injury tuple. The combination must pass POB-NOI validation (Section 4.3).

Constraint: UNIQUE on (wcb_claim_detail_id, ordinal). Max 5 rows per claim. POB-NOI combination validated against 382-row exclusion matrix (Section 4.3).

## 3.3 WCB Prescriptions Table (wcb_prescriptions)

1–5 prescription entries when narcotics_prescribed = Y on C050E/S, C151/S, C568A. Each entry captures medication name, strength, and dosage.

## 3.4 WCB Consultations Table (wcb_consultations)

1–5 consultation/referral/investigation entries on C050E/S, C151/S. Each entry has a category (CONREF or INVE), type, details, and optional expedite flag.

## 3.5 WCB Work Restrictions Table (wcb_work_restrictions)

Physical capacity restrictions for Return to Work section (C050E/S, C151/S). Each row represents one activity type with its restriction level and optional hours.

## 3.6 WCB Invoice Lines Table (wcb_invoice_lines)

Every WCB form has an Invoice section with 1–N invoice line items. The structure varies by form type: C050E/C151 have simple lines (HSC + modifiers + calls/encounters), C568 has multi-date-range lines with fees, C569 has quantity-based supply lines, and C570 has paired Was/Should Be correction lines.

Cardinality constraints by form type: C050E/S and C151/S: 1–25 lines. C568/A: 1–25 lines. C569: 1–25 lines. C570: 1–25 Was lines each paired with 1 Should Be line.

## 3.7 WCB Attachments Table (wcb_attachments)

Up to 3 file attachments per claim (all form types). Stored as base64-encoded content for inclusion in HL7 XML batch files.

## 3.8 WCB Batches Table (wcb_batches)

WCB batches are completely separate from AHCIP batches. Each WCB batch generates an HL7 v2.3.1 XML file for upload to myWCB. Unlike H-Link's Thursday cycle, WCB batches can be submitted at any time (though timing affects fees).

## 3.9 WCB Return Records Table (wcb_return_records)

Each row in the batch return file is stored here. The return file is a tab-delimited text file emailed by WCB after batch processing. Each report in the batch gets a status (Complete or Invalid) with error details if rejected.

## 3.10 WCB Return Invoice Lines Table (wcb_return_invoice_lines)

For successfully processed reports, the return file includes per-invoice-line status. Stored for reconciliation with the original invoice lines.

## 3.11 WCB Remittance Records Table (wcb_remittance_records)

WCB payment remittance is delivered as an XML file (separate schema from the batch submission). Each PaymentRemittanceRecord becomes a row here. Matched to WCB claims for financial reconciliation. Weekly cycle with Tuesday remittance reports.

# 4. WCB Validation Engine

The WCB validation engine is a specialised module within the validation pipeline defined in Domain 4.0 Core. When a claim has claim_type = 'WCB', the core pipeline delegates to the WCB validation module after basic structural checks. The WCB module runs form-specific validation that reflects the business rules embedded in the HL7 element mapping spreadsheet and the XSD schema.

Validation results use the same structure as the core pipeline (errors, warnings, info, passed, validation_timestamp, reference_data_version) and feed into the same clean/flagged classification system.

## 4.1 WCB Validation Pipeline

The WCB validation pipeline runs the following checks in order. Each check produces errors (blocking) or warnings (flagging). Checks may short-circuit subsequent checks when prerequisites fail.

## 4.2 Conditional Field Optionality Engine

Many WCB fields are 'Conditionally Available and Required' — they become mandatory based on the value of a trigger field. The validation engine implements a rules table that maps trigger conditions to dependent field requirements. This is the most complex validation area due to the cascading dependencies.

Key conditional chains (representative, not exhaustive):

narcotics_prescribed = Y → prescriptions required (1–5 entries). On C151/S, also triggers all 16 opioid monitoring fields plus pain estimates.

missed_work_beyond_accident = Y → patient_returned_to_work required. If returned = Y → date, modified_hours, modified_duties required. If modified_duties = Y → all 11 activity restriction fields required. If returned = N → estimated_rtw_date required; also triggers hospitalized/pain/opioid reason fields.

patient_no_phn_flag = N → patient_phn required (and must be 9 digits).

prior_conditions_flag = Y → prior_conditions_desc required.

diagnosis_changed = Y (C151/S) → diagnosis_changed_desc required.

consultation_letter_format = TEXT (C568A) → consultation_letter_text required. If = ATTCH → file attachment required.

POB code has Side of Body Required = Yes → side_of_body_code required for that injury entry.

More than 5 body parts affected → additional_injuries_desc conditionally available.

The complete conditional dependency map is maintained as a configuration table in Reference Data (Domain 2), keyed by form_id and trigger_field, returning an array of dependent fields with their required/optional status.

## 4.3 POB-NOI Combination Validation

The WCB maintains a matrix of 382 disallowed Part of Body / Nature of Injury combinations. For example, you cannot report a Sprain/strain/tear (02100) for Brain (01100), Ear (02000), Body systems (50000), or Personal effects only (91000). This matrix is stored in Reference Data and checked for every injury entry on every WCB claim.

Implementation: The exclusion list is loaded into an in-memory set of (NOI_code, POB_code) tuples. For each injury entry, if the tuple exists in the exclusion set, validation fails with error: 'The combination of [NOI description] and [POB description] is not permitted by WCB.' The error references the specific injury ordinal so the physician knows which entry to correct.

The exclusion matrix is versioned in Reference Data. If WCB updates the matrix (which has happened historically with the addition of COVID-19 codes), the new version takes effect on a configured date without code changes.

## 4.4 Contract ID / Role / Form ID Enforcement

This is a gating validation — if it fails, no further validation is attempted. The check confirms that the practitioner's Contract ID and Role combination permits the selected form type. The relationship matrix (Section 2.3) is stored in Reference Data.

For follow-up forms, the check extends to the parent claim chain. A C151 can only be created from a prior C050E or C151 with the same practitioner. The system validates that: (a) a parent_wcb_claim_id is provided, (b) the parent claim exists and is in a terminal state (assessed/paid), (c) the parent form type is in the 'Can Create From' list for the current Contract ID/Role/Form combination, and (d) the parent claim's practitioner matches (same billing number).

## 4.5 WCB Timing Deadline Calculations

WCB fees are tiered by submission timing. The fee tier is determined by when WCB receives the report relative to the date of examination. Meritum calculates the deadline and current tier to warn physicians about impending fee reductions.

### 4.5.1 Timing Rules

### 4.5.2 Business Day Calculation

Business days = Monday through Friday, excluding 10 named Alberta statutory holidays: New Year's Day, Family Day, Good Friday, Victoria Day, Canada Day, Heritage Day (AB), Labour Day, National Day for Truth and Reconciliation, Thanksgiving, Christmas Day.

Date of examination = Day 0 (not counted as a business day).

The 10:00 MT cutoff on the deadline day means: if the report is received by WCB before 10:00 Mountain Time on the deadline business day, it qualifies for the higher tier.

'Received by WCB' = the timestamp when WCB processes the batch, NOT when the physician submits to Meritum. Meritum can estimate but cannot guarantee the tier. The AI Coach should warn when submission is close to cutoff.

### 4.5.3 Fee Tiers (2025 Schedule)

Meritum displays the current tier, the deadline for the next tier down, and the fee difference to motivate timely submission. This is a key AI Coach prompt: 'Submit within [X hours] to earn [$Y] more.'

## 4.6 Business Processing Rules

The HL7 mapping spreadsheet includes form-specific business processing rules in the 'Business Processing Rule' column. These are validations that WCB applies during batch processing (after upload). Meritum replicates these checks pre-submission to catch errors before they reach WCB.

Key business processing rules:

Invoice line HSC validation: Health service codes must be valid WCB codes (which are a subset of SOMB codes). Cross-referenced with WCB fee schedule.

Modifier compatibility: Modifier codes must be valid for the HSC and the practitioner's Contract ID/Role.

351 premium code eligibility: One premium code per operative encounter, excluded within 4 calendar days of accident date. Validated against date_of_injury and date_of_service.

C570 Was/Should Be pairing: Each Was invoice line must have exactly one corresponding Should Be line. The invoice_detail_id must match between pairs. Adjustment indicators must be consistent.

Attachment file constraints: Maximum file sizes per WCB policy. File types must be in the permitted list for the form type. Total attachments per form capped at 3.

# 5. WCB Submission Pipeline

This section specifies the end-to-end submission pipeline for WCB claims. Phase 2 (direct batch submission via HL7 XML) is the primary specification. The transitional MVP (WCB Submission Helper) is documented in Section 5.7 as the pre-accreditation pathway.

Critical architectural insight: Unlike H-Link (which may use SFTP or API), WCB batch submission is a manual file upload to the myWCB portal using a vendor UserID and password. There is no programmatic API. The return file is emailed back to the vendor. This means the upload step is always a manual action by a person (physician or delegate), but Meritum automates everything before and after that step.

## 5.1 Pipeline Overview

The WCB submission pipeline has the following stages:

Capture: Physician enters WCB claim data via guided form (form type determines which sections are shown).

Validate: WCB validation engine runs full pipeline (Section 4). Errors block progression; warnings cause flagging.

Queue: Validated claims enter queued state. Clean/flagged classification per Domain 4.0 Core.

Batch Assembly: Physician (or delegate) initiates batch generation. System groups queued WCB claims by physician.

XML Generation: Meritum generates HL7 v2.3.1 XML batch file per the Batch File Layout specification.

XSD Validation: Generated XML is validated against WCBhl7_v231_modern_v100.xsd and the validation XSD.

Download: Physician/delegate downloads the validated XML file.

Upload (Manual): Physician/delegate logs into myWCB portal and uploads the XML file.

Return Processing: WCB emails batch return file. Meritum parses it and updates claim states.

Remittance: WCB issues weekly payment remittance XML. Meritum imports and reconciles.

## 5.2 HL7 v2.3.1 XML Batch File Structure

The batch XML file follows a strict hierarchical structure defined by the WCB XSD schema. The file wraps one or more reports in HL7 segments.

### 5.2.1 Document Structure

The XML document structure nests as follows (each level must be present in the correct order):

ZRPT_P03 (root element; namespace urn:WCBhl7_v231-schema_modern_v100)

FHS — File Header Segment: sending/receiving application and facility, file creation timestamp, file name/ID, file control ID

ZRPT_P03.LST.6 > ZRPT_P03.GRP.4 — Batch wrapper

BHS — Batch Header Segment: batch-level metadata, batch control ID (used for return file matching)

ZRPT_P03.LST.5 > ZRPT_P03.GRP.3 > ZRPT_P03.GRP.2 — Report wrapper (repeats per report)

MSH — Message Header: per-report metadata, message control ID = submitter_txn_id

EVN — Event: form_id, report completion date

PRD — Provider: practitioner name, skill code, fax

PID — Patient ID: patient demographics, PHN, DOB, address

PV1 — Patient Visit: clinic reference number

FT1 — Financial Transaction: billing number, contract ID, date of exam, diagnosis, invoice lines, facility type. Repeats for each invoice line.

ACC — Accident: date of injury

NTE — Notes: additional comments

OBX — Observation: all clinical data (role, employer, job title, injury description, symptoms, findings, treatment plan, RTW, etc.). Repeats for each observation type.

BTS — Batch Trailer Segment: batch message count

FTS — File Trailer Segment: file batch count

### 5.2.2 Batch Header Values

### 5.2.3 Field-to-Segment Mapping Strategy

The Meritum-to-HL7 field mapping follows the HL7 Element Mapping spreadsheet as the authoritative reference. Rather than duplicating all 804 fields here, the mapping strategy is:

Each Meritum table column maps to a specific HL7 segment.field as documented in the spreadsheet's XML Element Representation column.

The XML generator module maintains a mapping configuration per form type, keyed by form_id, that specifies which Meritum fields to include, their HL7 target paths, and any value transformations needed.

OBX segments are the most complex: each clinical observation is a separate OBX element with a coded identifier (e.g., PRACTITIONER_ROLE, EMPNAME, JOBTITL, INJSYMP, OBJFIND, etc.) in OBX.3/CE.1.

FT1 segments repeat for each invoice line. FT1.19.LST contains the repeating diagnosis/POB/SOB/NOI entries.

Repeating groups (injuries, prescriptions, consultations, restrictions) are serialised into their respective HL7 patterns using the dataset indexing defined in the mapping spreadsheet.

The authoritative field-level mapping reference is: 3 - WCB Report Element to HL7 Element Mapping.xlsx from the Vendor Accreditation Package. Form-specific summary tables are provided in Appendix A.

## 5.3 XSD Validation

Before a batch file is made available for download, Meritum validates it against both XSD schemas:

WCBhl7_v231_modern_v100.xsd — Structural schema: validates XML element hierarchy, required elements, element ordering.

WCBhl7_v231_modern_v100_validate.xsd — Data validation schema: validates data types, lengths, formats, and enumerated values.

If XSD validation fails, the batch status is set to ERROR, the specific validation errors are stored in xsd_validation_errors (JSONB), and the batch cannot be downloaded. The UI displays each XSD error mapped back to the source claim and field where possible.

Implementation note: XSD validation is performed server-side using a validated XML library (e.g., lxml for Python, xmllint, or a Node.js XML validator). The XSD files are stored as versioned assets. If WCB issues updated schemas, they are deployed as a reference data update.

## 5.4 Batch Download and Upload

Once a batch passes XSD validation:

The XML file is made available for authenticated download via a time-limited, single-use signed URL.

The physician or delegate downloads the file and logs into the myWCB portal (https://my.wcb.ab.ca) using Meritum's vendor credentials.

The file is uploaded via the myWCB batch upload interface.

The physician/delegate confirms the upload in Meritum (button: 'Confirm Upload to WCB'). This transitions the batch status from VALIDATED to UPLOADED and records the upload timestamp and actor.

Security: The vendor UserID and password for myWCB are stored in the secrets management system (not in the database). Access to the upload workflow requires the WCB_BATCH_UPLOAD permission in RBAC (Domain 1). The download link expires after 1 hour and is single-use.

## 5.5 Vendor Credentials and Accreditation

Meritum must complete the WCB 9-step vendor accreditation process before Phase 2 submission is live. Key accreditation elements:

Application: Submit form 10.01 (Software Vendor Accreditation Application) to WCB.

Vendor prefix: WCB assigns a 2-character vendor prefix that must appear as the first 2 characters of every submitter_txn_id.

Submitter ID and Source ID: Assigned by WCB. Used in FHS/BHS/MSH sending facility/application fields.

Test cycle: Submit test batch files for each form type with min/max field configurations. WCB validates against all business rules.

Production approval: WCB grants production UserID/password for myWCB batch upload.

Until accreditation is complete, Meritum operates in MVP mode (Section 5.7).

## 5.6 WCB Batch vs AHCIP Batch

WCB and AHCIP batches are fundamentally separate:

## 5.7 Transitional MVP: WCB Submission Helper

Until vendor accreditation is complete, Meritum operates a WCB Submission Helper that provides value without direct batch submission. This is the Day 1 WCB experience.

MVP capabilities:

Full WCB claim data capture with all 8 form types, form-specific guided entry, and conditional field logic.

Complete validation engine (Section 4) runs on all claims — catches errors before the physician ever touches the myWCB portal.

Fee calculation with timing tier display ('Submit now for same-day rate: $94.15. On-time deadline: [date/time].').

Deadline tracking and notification: 'Your C050E for [patient] will drop from on-time ($85.80) to late ($54.08) in [X hours].'

Pre-filled export: Generates a structured summary (PDF or printable view) that mirrors the myWCB form layout, allowing the physician/MOA to manually enter data into the portal with minimal re-keying.

Claim tracking: Physician manually enters the WCB claim number and outcome after portal submission. Meritum tracks the claim lifecycle.

Payment reconciliation: Manual entry of payment amounts for matching against expected fees.

MVP limitations:

No XML batch generation (requires vendor prefix and accreditation).

No automated return file processing.

No automated remittance reconciliation.

Physician/MOA must manually enter data into myWCB portal (49% of physicians already do this today).

Transition path: When accreditation completes, the MVP export endpoint is deprecated. Existing claims in the system transition seamlessly to Phase 2 — the data model and validation are identical. Only the submission, return, and reconciliation modules activate.

# 6. WCB Return File Processing

After WCB processes a batch submission, it emails a return file to the registered vendor email address. This file contains the processing outcome for each report in the batch. Meritum ingests this file to update claim states automatically.

## 6.1 Return File Format

The return file is a tab-delimited text file with two sections per report:

Batch header: BatchID, ReportCount, SubmitterID, SubmitDate

Per-report block: ReportTxnID (WCB-assigned), SubmitterTxnID (ours), ProcessedClaim# (WCB claim number), ClaimDecision (Accepted or empty), ReportStatus (Complete or Invalid), TxnSubmissionDate

For Complete reports: followed by per-invoice-line rows: InvoiceSequence#, ServiceDate, HealthServiceCode, InvoiceStatus

For Invalid reports: followed by error rows: ErrorNumber, ErrorDescription (format: error_code: human-readable message)

## 6.2 Ingestion Workflow

Email received: Meritum monitors the vendor email inbox for return file attachments (or provides a manual upload interface for the return file).

Parse: Tab-delimited file parsed. Batch header matched to wcb_batches by BatchID / batch_control_id.

Match: Each report block matched to wcb_claim_details by SubmitterTxnID.

Store: Each report result stored in wcb_return_records. Invoice line results stored in wcb_return_invoice_lines.

Update claim state: Complete reports → claim transitions to 'assessed' state (Domain 4.0). Invalid reports → claim transitions to 'rejected' state with error details.

Update claim number: If ProcessedClaim# is provided and the claim didn't have a WCB claim number, it is now stored on the wcb_claim_details record.

Notify: Notification events emitted per Domain 3 (Notification Service): WCB_RETURN_RECEIVED, WCB_CLAIM_ACCEPTED, WCB_CLAIM_REJECTED.

Update batch: Batch status transitions to RETURN_RECEIVED. If all reports processed, batch status = RECONCILED.

## 6.3 Error Handling

When a report is returned as Invalid:

The error description is parsed from the format 'error_code: human-readable message' (e.g., '121023: Worker Personal Health Number must be BLANK since Worker Personal Health Number Indicator is No').

Errors are stored in the wcb_return_records.errors JSONB field as an array of {error_number, error_description, mapped_field}. Meritum attempts to map the error back to the specific Meritum field that caused it.

The claim enters the 'rejected' state with the return errors attached. The physician sees the errors in the rejection management UI with corrective guidance.

After the physician corrects the errors, the claim can be resubmitted in the next batch. The resubmission uses the same WCB claim number (if assigned) but a new submitter_txn_id.

# 7. WCB Payment Remittance Reconciliation

WCB issues weekly payment remittance reports in XML format. This is a completely separate schema from the batch submission HL7 XML. The remittance report contains payment details for all claims paid in the reporting week.

## 7.1 Remittance XML Schema

The remittance file uses namespace http://www.wcb.ab.ca/schemas/RR/RRPaymentRemittanceReport-2.01.00 and conforms to Schema_RRPaymentRemittanceReport_2_01_00.xsd.

The structure is:

PaymentRemittanceReport (root): contains ReportWeek (StartDate, EndDate) and 0–N PaymentRemittanceRecord elements.

PaymentRemittanceRecord: one per payment line. Contains disbursement details, payee details, payment amount, service details, and the ElectronicReportTransactionID used for matching.

## 7.2 Reconciliation Workflow

Import: Remittance XML file uploaded (manually or via monitored email). Parsed against XSD schema.

Store: Each PaymentRemittanceRecord stored in wcb_remittance_records.

Match: Records matched to WCB claims via ElectronicReportTransactionID → wcb_return_records.report_txn_id → wcb_claim_details.

Reconcile: Compare payment_amount to expected fee (calculated by Meritum). Flag discrepancies for review.

State update: Matched claims transition from 'assessed' to 'paid'. Overpayment recovery amounts noted.

Notify: WCB_PAYMENT_RECEIVED notification emitted with payment summary.

## 7.3 Payment Status Codes

## 7.4 Discrepancy Detection

When the remittance payment_amount differs from the expected fee calculated by Meritum, the system flags the claim with a reconciliation discrepancy. Common causes:

WCB applied a different timing tier than Meritum predicted (because 'received by WCB' timestamp differs from Meritum's upload timestamp).

WCB disallowed a modifier or premium code.

Overpayment recovery deducted from this payment (overpayment_recovery field).

WCB fee schedule changed between submission and payment.

Discrepancies are surfaced in the Analytics & Reporting domain (Domain 8) with drill-down to the specific remittance record.

# 8. WCB Fee Calculation

WCB fee calculation differs fundamentally from AHCIP. Key differences: timing-based fee tiers, 2× SOMB premiums, unbundling at 100%, and expedited service fees. The fee calculation engine for WCB claims is a separate module from the AHCIP fee calculator, though both are invoked by the shared claim lifecycle.

## 8.1 Report Fees (Timing-Based)

Report fees are calculated per Section 4.5 timing rules. The fee tier is determined at the point of submission and may be recalculated if the claim is resubmitted.

## 8.2 Premium Codes (351)

WCB maintains 351 premium health service codes that are paid at 2× the SOMB base rate. These are operative/procedural codes where the premium incentivises priority treatment for injured workers.

Eligibility: One premium code per operative encounter.

Exclusion: Premium codes are excluded if the date of service is within 4 calendar days of the accident date.

Calculation: premium_fee = SOMB_base_rate × 2. The premium code list is maintained in Reference Data (Domain 2) and versioned with the WCB fee schedule.

## 8.3 Expedited Services

When a physician requests an expedited consultation/investigation (via the consultation table's expedite_requested field) and the service is completed:

Within 15 business days: Full expedited fee.

16–25 business days: Pro-rated fee.

After 25 business days: No expedited fee.

## 8.4 Unbundling

Unlike AHCIP (which has complex bundling rules per governing rules), WCB pays each distinct service component at 100% of its individual fee. There is no bundling discount for multiple services on the same date. This simplifies WCB fee calculation but means the validation engine must not apply AHCIP bundling rules to WCB claims.

## 8.5 RRNP and Variable Fee Premium

Rural and Remote Northern Physician (RRNP) flat fee applies to WCB claims at $32.77/claim. The RRNP Variable Fee Premium is calculated quarterly by WCB. Both are tracked in Reference Data and applied during fee calculation when the physician's practice location qualifies.

# 9. API Contracts (WCB-Specific)

All WCB-specific endpoints extend the base claim API patterns defined in Domain 4.0 Core. Authentication, authorisation, rate limiting, and audit logging follow the same patterns. Endpoints are prefixed with /api/v1/wcb/.

## 9.1 WCB Claim CRUD

## 9.2 WCB Batch Management

## 9.3 WCB Return File Ingestion

## 9.4 WCB Remittance Import

## 9.5 MVP Export Endpoint

# 10. Security Requirements (WCB-Specific)

WCB-specific security requirements supplement the shared security requirements in Domain 4.0 Core and Domain 1 (Identity & Access).

## 10.1 Vendor Credentials

WCB vendor UserID, password, submitter ID, source ID, and vendor prefix are stored in the secrets management system (e.g., HashiCorp Vault, AWS Secrets Manager, or DigitalOcean encrypted secrets).

Credentials are never stored in the application database, environment variables, or source code.

Access to credentials requires the WCB_VENDOR_ADMIN role. Credential rotation follows the cadence mandated by WCB.

The vendor prefix (2 chars) is the only credential-derived value that appears in claim data (as the first 2 chars of submitter_txn_id).

## 10.2 Batch File Security

Generated XML files are encrypted at rest using AES-256.

Download links are time-limited (1 hour), single-use, and authenticated.

XML files contain PHI (patient PHN, name, DOB, diagnosis, employer). Generated and stored on Meritum infrastructure (DigitalOcean Toronto) within Canadian data residency.

Batch generation and download actions are audit-logged with actor, timestamp, and batch reference.

Return files and remittance files are processed immediately upon ingestion. Raw files are stored encrypted for audit retention per HIA requirements.

## 10.3 PHI in WCB Context

WCB claims contain additional PHI beyond AHCIP claims: employer details (name, location, phone), job title, detailed injury descriptions, opioid prescriptions, and work restriction assessments. The physician as HIA custodian retains responsibility for this data. Meritum's IMA (Information Manager Agreement) must explicitly cover WCB-specific PHI categories.

# 11. Testing Requirements

## 11.1 Form Type Tests

Create, validate, and submit claims for each of the 8 form types with minimum required fields.

Create, validate, and submit claims for each form type with maximum fields (including all conditional fields triggered).

Verify that form types not permitted for a Contract ID/Role are rejected at validation.

Verify follow-up chain rules: C151 from C050E (valid), C151 from C568A (invalid for GP).

## 11.2 Validation Matrix Tests

All 382 POB-NOI exclusion combinations: verify each is rejected.

Side of Body required: verify enforcement for all 17 POB codes that require side.

Conditional field cascades: test each trigger chain (narcotics → prescriptions → opioid monitoring, missed work → RTW → restrictions, PHN flag → PHN field).

Data type enforcement: alphabetic-only fields reject numbers, numeric fields reject letters, date fields reject invalid dates.

Length enforcement: test at max length (pass), max+1 (fail).

## 11.3 XML Generation Tests

Generate XML for each form type and validate against both XSD schemas.

Verify batch with multiple reports (mixed form types in one batch).

Verify XML element ordering matches XSD requirements.

Verify special character encoding (ampersand, angle brackets, quotes) in free-text fields.

Verify base64 encoding of file attachments.

Verify batch with attachments vs without attachments.

Compare generated XML structure against sample files 5.01–5.17 from the accreditation package.

## 11.4 Return File Tests

Parse successful return file (sample 7.01): verify all fields extracted, claims matched, states updated to assessed.

Parse error return file (sample 7.02): verify error extraction, claims matched, states updated to rejected with error details.

Return file with unmatched SubmitterTxnID: verify graceful handling and alert.

Return file with mixed Complete and Invalid reports: verify each handled independently.

## 11.5 Remittance Tests

Parse remittance XML (sample 8.02): verify all PaymentRemittanceRecord fields extracted and stored.

Match remittance to WCB claims via ElectronicReportTransactionID chain.

Detect payment discrepancy: billed amount vs payment amount.

Handle overpayment recovery amounts.

Handle all 7 payment status codes correctly.

## 11.6 Timing and Fee Tests

Same-day tier: examination today, submission today → same-day fee.

Same-day tier boundary: examination yesterday, submission today before 10:00 MT → same-day fee.

On-time tier: examination 3 business days ago for C050E → on-time fee.

On-time boundary: examination 3 business days ago, submission at 10:01 MT on day 4 → late fee for C050E.

Statutory holiday: verify holidays are excluded from business day count.

351 premium code: verify 2× SOMB rate applied. Verify exclusion within 4 calendar days of accident.

Unbundling: verify multiple services on same date each paid at 100%.

RRNP flat fee applied when physician qualifies.

## 11.7 WCB Billing Scenarios (End-to-End)

GP first report (C050E) with on-time submission, accepted, paid.

GP progress report (C151) with opioid monitoring, chained from C050E.

Specialist consultation (C568A) with attached consultation letter.

Medical invoice (C568) with multiple invoice lines across date ranges.

Medical supplies invoice (C569) with quantity-based line items.

Invoice correction (C570) with Was/Should Be paired lines.

OIS first report (C050S) with expanded work restriction detail.

Rejected claim → correct errors → resubmit → accepted.

Late submission with fee tier downgrade notification.

Batch with mixed form types: C050E + C568 + C569 in single batch.

# 12. Appendix A: Form Field Summary Tables

The following tables summarise key fields per form type with their Meritum column mapping and HL7 segment targets. These are not exhaustive — the authoritative field-level reference is the HL7 Element Mapping spreadsheet (accreditation package document 3). These summaries cover fields with meaningful business logic, conditional rules, or non-obvious mapping.

## A.1 C050E — Physician First Report (Key Fields)

## A.2 C151 — Physician Progress Report (Key Differences from C050E)

## A.3 C568 — Medical Invoice (Key Differences)

C568 is the simplest clinical form. No Treatment Plan or Return to Work sections. The Invoice section is more complex than C050E/C151, with from/to date ranges, per-line diagnostic codes, per-line facility type and skill code, and an explicit fees_submitted amount per line.

## A.4 C570 — Medical Invoice Correction (Unique Structure)

C570 is structurally unique. Instead of a single set of invoice lines, it has paired 'Was' and 'Should Be' line sets. Each Was line describes what was originally submitted; the paired Should Be line describes the corrected values. The system must enforce 1:1 pairing via the correction_pair_id field and matching invoice_detail_id values.

# 13. Appendix B: WCB Reference Code Tables

The following reference code tables are sourced from the HL7 Element Mapping spreadsheet and maintained in Reference Data (Domain 2). They are listed here for developer reference. The Reference Data domain is the system of record; these are a snapshot.

## B.1 Part of Body Codes (30 values)

## B.2 Practitioner Role Codes (10 values)

## B.3 Facility Types (3 values)

## B.4 Form ID to Attachment Codes

All form types support a maximum of 3 attachments. Permitted file types are defined in the Form ID To Attachment Codes reference table in the HL7 mapping spreadsheet. Common types include PDF, DOC, DOCX, JPG, PNG, TIF.

## B.5 Additional Reference Tables

The following tables are maintained in Reference Data (Domain 2) and are not reproduced here due to size. Developers should reference the HL7 mapping spreadsheet directly:

Nature of Injury Codes (46 values)

POB-NOI Validation Exclusions (382 combinations)

State/Province Codes (65 values)

Country Codes (239 values)

Skill Codes (141 values)

Category Type Expedite Codes (40 form-specific entries)

Pain Scale Codes, Function Level Codes, Weight Category Codes, Fit For Work Codes, Work Restriction Detail Codes, Consultation Letter Formats, Dominant Hand Codes, Gender Codes, Yes/No and Yes/No/NA response codes

# 14. Appendix C: OIS-Specific Forms (C050S / C151S)

The Occupational Injury Service (OIS) forms are expanded variants of the standard GP forms. C050S extends C050E; C151S extends C151. They share the same General, Participant, Accident, and Injury sections but have significantly expanded Return to Work sections with granular functional capacity assessment. These forms are used exclusively by OIS practitioners (Contract ID 000053, Role OIS).

This appendix specifies the OIS-unique data model extensions, additional validation rules, and reference code tables required to support C050S and C151S. The OIS market segment is narrower than standard GP, but the forms must be fully supported for vendor accreditation.

## C.1 OIS Return to Work: Expanded Restrictions

The standard forms (C050E, C151) have 11 activity restriction types with simple Able/Unable levels. The OIS forms replace this with a granular functional capacity model featuring 3 key differences:

All restriction fields are Always Required on C050S (vs Conditionally Required on C050E). The OIS physician must assess every activity, not just ones affected by the injury.

Per-activity hours fields for every timed activity (not just sitting/standing/walking/driving). Bending, twisting, kneeling, and climbing all gain hours sub-fields.

New activity types not present on standard forms: bilateral hand grasping (with sub-assessments), zone-specific lifting, directional reaching, and environmental restrictions.

## C.2 OIS-Unique Field Groups

### C.2.1 Hand Grasping Assessment (12 fields)

The OIS forms assess grasping capacity per hand with 6 sub-fields each. This level of detail is absent from C050E/C151 entirely.

*Required on C050S (Always Required). Conditionally required on C151S (when RTW status changed = Y and modified duties = Y).

### C.2.2 Zone-Specific Lifting (6 fields)

Standard forms have a single Lifting restriction with one max-weight field. OIS forms break lifting into 3 zones, each with its own restriction level and weight limit.

### C.2.3 Directional Reaching (4 fields)

Standard forms have a single 'Overhead reaching' field. OIS forms assess reaching in 4 directions (above/below each shoulder), reflecting the bilateral assessment model.

### C.2.4 Environmental Restrictions (8 fields)

OIS forms add an environmental assessment section entirely absent from standard forms. The physician assesses the worker's tolerance for 7 environmental conditions.

### C.2.5 OIS Assessment Summary (C050S fields 114–141)

The C050S form includes a structured three-party communication summary that is entirely absent from C050E. It captures coordinated return-to-work planning between the OIS physician, the employer, and the worker, plus a handoff to the family physician.

## C.3 C151S: OIS Progress Report Differences

C151S extends C151 with the same expanded restriction model as C050S, but adds an additional trigger: 'Has the patient's return to work status changed?' (field 58). This is a gating question that makes the entire expanded RTW section conditionally required — if the status has not changed since the last report, the OIS physician skips the detailed assessment. This differs from C050S where all RTW fields are Always Required.

The C151S also retains the C151 opioid management section (16 side-effect fields), making it the most field-heavy form at 153 total fields.

## C.4 OIS-Specific Reference Code Tables

## C.5 Data Model Impact

The OIS-specific fields are stored in the wcb_claim_details table as additional nullable columns. This keeps the single-table pattern for scalar fields. The columns are only populated when form_id is C050S or C151S; the validation engine enforces their presence/absence based on form type.

Total additional columns for OIS support: approximately 45 (12 grasping + 6 zone lifting + 4 directional reaching + 8 environmental + 29 assessment summary − 14 that overlap with standard columns as expanded versions).

Alternative approach considered: A separate wcb_ois_details table. Rejected because: (a) it would require an additional join on every OIS claim read, (b) the OIS columns are nullable and incur no storage cost on non-OIS claims, and (c) the form_id-based validation pattern already handles form-specific field requirements.

## C.6 OIS Validation Additions

Form ID gating: C050S requires Contract ID 000053 with Role OIS. No other Contract/Role can create C050S.

Extended restriction codes: OIS restriction fields use Extended Work Restriction Codes (ABLE/UNABLE/LIMITEDTO) rather than Basic codes (ABLE/UNABLE/LIMITED). The validation engine checks the correct code table based on form_id.

C151S RTW status gate: When rtw_status_changed = N on C151S, the entire expanded RTW section is conditionally unavailable. When = Y, all OIS RTW fields become required.

Family physician cascade: ois_has_family_physician = Y triggers 10 dependent fields. If N, all family physician fields must be null.

Grasping sub-field cascade: grasp_right_level = LIMITED triggers prolonged/repetitive/vibration sub-fields. grasp_right_specify = Y triggers specific_desc.

# 15. Open Questions

# 16. Document Control

This document specifies the WCB EIR submission pathway. It should be read in conjunction with Domain 4.0 (Claim Lifecycle Core) for the shared state machine, base data model, and validation architecture, and Domain 4.1 (AHCIP Claim Pathway) for the H-Link submission pathway. Together, the three 4.x documents comprise the complete Claim Lifecycle specification.

| Domain | Dependency Type | Key Interfaces |
| --- | --- | --- |
| 4.0 Claim Lifecycle Core | Parent | State machine, base claims table, validation architecture, audit history |
| 1 Identity & Access | Consumed | Auth, RBAC, delegate permissions, audit logging |
| 2 Reference Data | Consumed | WCB fee schedule, SOMB codes (for premium calc), modifier rules, POB/NOI/skill codes |
| 3 Notification Service | Consumed | Deadline reminders, submission confirmations, return file alerts, payment notifications |
| 5 Provider Management | Consumed | Practitioner billing number, Contract ID, Role, skill code, facility type |
| 6 Patient Registry | Consumed | Patient PHN, demographics, employer details for WCB forms |
| 7 Intelligence Engine | Consumed | AI Coach suggestions for WCB-specific billing optimisation |

| Form ID | Name | Fields | Req'd | Type | Purpose |
| --- | --- | --- | --- | --- | --- |
| C050E | Physician First Report | 111 | 38 | Initial | GP/NP/ERS first report of workplace injury. Full clinical assessment with employer, injury, treatment plan, and return-to-work sections. |
| C050S | OIS Physician First Report | 171 | 70 | Initial | Occupational Injury Service (OIS) variant of C050E with expanded clinical assessment, pain scales, functional capacity, and work restriction detail. |
| C151 | Physician Progress Report | 136 | 39 | Follow-up | GP/NP/ERS follow-up report. Includes opioid management monitoring (16 medication side-effect fields) and updated treatment/return-to-work. |
| C151S | OIS Physician Progress Report | 153 | 39 | Follow-up | OIS variant of C151 with expanded work restriction detail and functional capacity assessment. |
| C568 | Medical Invoice | 61 | 17 | Either | Invoice-only form for services without clinical report. Supports multiple invoice lines with from/to date ranges. |
| C568A | Medical Consultation Report | 69 | 19 | Either | Specialist consultation report with attached consultation letter (plain text or file attachment). |
| C569 | Medical Supplies Invoice | 37 | 18 | Follow-up | Invoice for medical supplies (braces, supports, etc.). Line items by quantity and description. |
| C570 | Medical Invoice Correction | 66 | 18 | Follow-up | Corrects a previously submitted C568 invoice. Contains paired Was/Should Be invoice line sets. |

| Section | C050E | C050S | C151 | C151S | C568 | C568A | C569 | C570 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| General | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Participant: Claimant | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Participant: Practitioner | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Participant: Employer | ✓ | ✓ | ✓ | ✓ |  |  |  |  |
| Accident | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Injury | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |  |  |
| Treatment Plan | ✓ | ✓ | ✓ | ✓ |  | ✓ |  |  |
| Return to Work | ✓ | ✓ | ✓ | ✓ |  |  |  |  |
| Attachments | ✓ | ✓ | ✓ | ✓ | ✓ |  |  |  |
| Invoice | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

| Contract ID | Description | Role | Role Description | Initial Forms |
| --- | --- | --- | --- | --- |
| 000001 | WCB General | GP | General Practitioner | C050E, C568 |
| 000004 | Authorized Ortho | OR | Ortho | C568A, C568 |
| 000006 | Specialist | SP | Specialist | C568A, C568 |
| 000006 | Specialist | ERS | ER Specialist/FTER | C050E, C568 |
| 000006 | Specialist | ANE | Anesthesiologist | C568A, C568 |
| 000022 | MRI | DP | Diagnostic Provider | C568 |
| 000023 | CT Scan | DP | Diagnostic Provider | C568 |
| 000024 | VSC Facility Fee | VSC | Visiting Specialist Clinic | C568A, C568 |
| 000025 | Day Surgery Facility | VSCFAC | VSC Facility | C568 |
| 000052 | Ultrasound FFS | DP | Diagnostic Provider | C568 |
| 000053 | OIS General FFS | OIS | OIS | C050S, C568 |
| 000065 | Alberta Hospitals | HP | Hospital | C568 |
| 000066 | Non-Ortho VSC | SP | Specialist | C568A, C568 |
| 000084 | Nurse Practitioners | NP | Nurse Practitioners | C050E, C568 |

| Contract ID | Role | Progress Forms | Can Create From | Notes |
| --- | --- | --- | --- | --- |
| 000001 | GP | C151, C568, C569, C570 | C050E, C151, C568 | GP progress reports chain from first reports or prior progress |
| 000006 | ERS | C151, C568, C569, C570 | C050E, C151, C568 | ER Specialist follows same chain as GP |
| 000006 | SP | C568A, C568, C569, C570 | C568A, C568 | Specialist chains from consultation/invoice |
| 000006 | ANE | C568A, C568, C569, C570 | C568A, C568 | Anesthesiologist follows specialist pattern |
| 000004 | OR | C568A, C568, C569, C570 | C568A, C568 | Ortho follows specialist pattern |
| 000053 | OIS | C151S, C568, C569, C570 | C050S, C151S, C568 | OIS uses S-variant progress reports |
| 000084 | NP | C151, C568, C570 | C050E, C151, C568 | Nurse Practitioners: no C569 (supplies) |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| wcb_claim_detail_id | UUID | No | Primary key |
| claim_id | UUID FK | No | FK to claims.claim_id (Domain 4.0) |
| form_id | VARCHAR(5) | No | WCB form type: C050E, C050S, C151, C151S, C568, C568A, C569, C570 |
| submitter_txn_id | VARCHAR(16) | No | Unique ID for reconciliation. First 2 chars = Meritum vendor prefix (assigned by WCB during accreditation). |
| wcb_claim_number | VARCHAR(7) | Yes | WCB claim number (7-digit). Null for new/unknown claims; WCB assigns on acceptance. |
| report_completion_date | DATE | No | Date the physician completed the report |
| additional_comments | TEXT | Yes | Free-text additional comments (max 2048 chars) |
| parent_wcb_claim_id | UUID FK | Yes | FK to wcb_claim_details for follow-up reports. Required for C151, C151S, C569, C570; validated against follow-up chain rules (Section 2.3.2). |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| practitioner_billing_number | VARCHAR(8) | No | AH billing number / practitioner ID |
| contract_id | VARCHAR(10) | No | WCB Contract ID (e.g., 000001, 000006). Determines fee schedule and form permissions. |
| role_code | VARCHAR(10) | No | Practitioner role: GP, SP, ERS, ANE, OR, DP, VSC, VSCFAC, OIS, NP, HP |
| practitioner_first_name | VARCHAR(11) | No | Practitioner first name (max 11 chars per WCB spec) |
| practitioner_middle_name | VARCHAR(11) | Yes | Practitioner middle name |
| practitioner_last_name | VARCHAR(21) | No | Practitioner last name (max 21 chars per WCB spec) |
| skill_code | VARCHAR(10) | No | WCB skill code (141 valid values; e.g., GENP, ANES, ORTH). Required for invoice section. |
| facility_type | VARCHAR(1) | No | C = Clinic, F = Facility Non-Hospital, H = Hospital |
| clinic_reference_number | VARCHAR(8) | Yes | Clinic reference number if applicable |
| billing_contact_name | VARCHAR(30) | Yes | Billing contact name for invoice inquiries |
| fax_country_code | VARCHAR(10) | Yes | Billing fax country code |
| fax_number | VARCHAR(24) | Yes | Billing fax number |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| patient_no_phn_flag | VARCHAR(1) | No | Y/N — does the patient lack an Alberta PHN? If Y, PHN field must be blank. |
| patient_phn | VARCHAR(9) | Yes | Alberta PHN (9 digits). Required when patient_no_phn_flag = N. |
| patient_gender | VARCHAR(1) | No | M, F, or U (codes per WCB Gender Codes table) |
| patient_first_name | VARCHAR(11) | No | Patient first name (max 11 chars) |
| patient_middle_name | VARCHAR(11) | Yes | Patient middle name |
| patient_last_name | VARCHAR(21) | No | Patient last name (max 21 chars) |
| patient_dob | DATE | No | Patient date of birth |
| patient_address_line1 | VARCHAR(30) | No | Mailing address line 1 |
| patient_address_line2 | VARCHAR(30) | Yes | Mailing address line 2 |
| patient_city | VARCHAR(20) | No | City |
| patient_province | VARCHAR(10) | Yes | Province code (per State Province Codes table) |
| patient_postal_code | VARCHAR(9) | Yes | Postal code |
| patient_phone_country | VARCHAR(10) | Yes | Phone country code |
| patient_phone_number | VARCHAR(24) | Yes | Phone number |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| employer_name | VARCHAR(50) | Yes* | Employer name. *Required when form has Employer section. |
| employer_location | VARCHAR(100) | Yes* | Location of operations |
| employer_city | VARCHAR(20) | Yes* | Employer city |
| employer_province | VARCHAR(10) | Yes | Employer province |
| employer_phone_country | VARCHAR(10) | Yes | Employer phone country code |
| employer_phone_number | VARCHAR(24) | Yes | Employer phone number |
| employer_phone_ext | VARCHAR(6) | Yes | Employer phone extension |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| worker_job_title | VARCHAR(50) | Yes* | Worker job title. *Required for C050E/S, C151/S. |
| injury_developed_over_time | VARCHAR(1) | Yes* | Y/N. *Required for C050E/S, C151/S, C568A. |
| date_of_injury | DATE | No | Date of workplace injury. Required for all forms (though optional on C568/C568A per schema, our validation requires it for claim integrity). |
| injury_description | TEXT | Yes* | How and when the injury occurred (max 1024 chars). *Required for C050E/S, C151/S. |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| date_of_examination | DATE | Yes* | Date of examination. *Required for forms with Injury section. |
| symptoms | TEXT | Yes* | Symptoms (max 2048 chars). *Required for C050E/S, C151/S. |
| objective_findings | TEXT | Yes* | Objective findings (max 1024 chars). *Required for C050E/S, C151/S. |
| current_diagnosis | TEXT | Yes* | Current diagnosis text (max 1024). *Required for C050E/S. |
| previous_diagnosis | TEXT | Yes* | Previous diagnosis text (max 1024). *Required for C151/S. |
| diagnosis_changed | VARCHAR(1) | Yes* | Y/N: has the diagnosis changed? *C151/S only. |
| diagnosis_changed_desc | TEXT | Yes* | Description of change (max 1024). *Required when diagnosis_changed = Y. |
| diagnostic_code_1 | VARCHAR(8) | Yes* | Primary ICD diagnostic code. *Required for forms with Injury section. |
| diagnostic_code_2 | VARCHAR(8) | Yes | Secondary diagnostic code |
| diagnostic_code_3 | VARCHAR(8) | Yes | Tertiary diagnostic code |
| additional_injuries_desc | TEXT | Yes | Additional injuries beyond 5 POB entries (max 1024) |
| dominant_hand | VARCHAR(10) | Yes | L, R, or AMB. Conditionally available when upper extremity injury. |
| prior_conditions_flag | VARCHAR(1) | Yes* | Y/N: prior conditions in same anatomical area? *Required for C050E/S, C151/S. |
| prior_conditions_desc | TEXT | Yes* | Prior condition diagnosis/treatment (max 1024). *Required when prior_conditions_flag = Y. |
| referring_physician_name | VARCHAR(50) | Yes | Referring physician name (C568, C568A only) |
| date_of_referral | DATE | Yes | Referral date (C568, C568A only) |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| narcotics_prescribed | VARCHAR(1) | Yes* | Y/N: were narcotics/opioids prescribed? *Required for forms with Treatment Plan. |
| treatment_plan_text | TEXT | Yes* | Treatment plan and non-opioid medications (max 1024). *Required for C050E/S, C151/S. |
| case_conf_wcb_manager | VARCHAR(1) | Yes* | Y/N: request case conference with WCB case manager? *C050E/S, C151/S. |
| case_conf_wcb_physician | VARCHAR(1) | Yes* | Y/N: request case conference with WCB physician? *C050E/S, C151/S. |
| referral_rtw_provider | VARCHAR(1) | Yes* | Y/N: referral to Return to Work provider? *C050E/S, C151/S. |
| consultation_letter_format | VARCHAR(5) | Yes* | ATTCH or TEXT. *Required for C568A. |
| consultation_letter_text | TEXT | Yes* | Plain text consultation letter (max varies). *Required when format = TEXT. |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| surgery_past_60_days | VARCHAR(1) | Yes* | Y/N. *Conditional: required when narcotics_prescribed = Y on C151/S. |
| treating_malignant_pain | VARCHAR(1) | Yes* | Y/N |
| wcb_advised_no_mmr | VARCHAR(1) | Yes* | Y/N: has WCB advised not to submit Medication Management Report? |
| side_effect_nausea | VARCHAR(1) | Yes* | Y/N |
| side_effect_sleep | VARCHAR(1) | Yes* | Y/N: sleep disorders/apnea |
| side_effect_constipation | VARCHAR(1) | Yes* | Y/N |
| side_effect_endocrine | VARCHAR(1) | Yes* | Y/N: endocrine dysfunction |
| side_effect_sweating | VARCHAR(1) | Yes* | Y/N |
| side_effect_cognitive | VARCHAR(1) | Yes* | Y/N: cognitive deficits |
| side_effect_dry_mouth | VARCHAR(1) | Yes* | Y/N |
| side_effect_fatigue | VARCHAR(1) | Yes* | Y/N: fatigue/drowsiness |
| side_effect_depression | VARCHAR(1) | Yes* | Y/N: depressed mood |
| side_effect_worsening_pain | VARCHAR(1) | Yes* | Y/N |
| abuse_social_deterioration | VARCHAR(1) | Yes* | Y/N |
| abuse_unsanctioned_use | VARCHAR(1) | Yes* | Y/N |
| abuse_altered_route | VARCHAR(1) | Yes* | Y/N: altering route of delivery |
| abuse_opioid_seeking | VARCHAR(1) | Yes* | Y/N |
| abuse_other_sources | VARCHAR(1) | Yes* | Y/N: accessing opioids from other sources |
| abuse_withdrawal | VARCHAR(1) | Yes* | Y/N: withdrawal symptoms |
| patient_pain_estimate | SMALLINT | Yes* | 0–10 scale. Patient self-reported pain severity. |
| opioid_reducing_pain | VARCHAR(1) | Yes* | Y/N: is current opioid therapy reducing pain? |
| pain_reduction_desc | TEXT | Yes* | Description of reduction (max 2048). Required when opioid_reducing_pain = Y. |
| clinician_function_estimate | SMALLINT | Yes* | 0–10 scale. Clinician estimate of patient function. |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| missed_work_beyond_accident | VARCHAR(1) | Yes* | Y/N. *Required for forms with RTW section. |
| patient_returned_to_work | VARCHAR(1) | Yes* | Y/N. *Conditional: required when missed_work = Y. |
| date_returned_to_work | DATE | Yes* | Date returned. *Required when returned_to_work = Y. |
| modified_hours | VARCHAR(1) | Yes* | Y/N. *Required when returned_to_work = Y. |
| hours_capable_per_day | SMALLINT | Yes* | Hours/day. *Required when modified_hours = Y. |
| modified_duties | VARCHAR(1) | Yes* | Y/N. *Required when returned_to_work = Y. |
| rtw_hospitalized | VARCHAR(1) | Yes* | Y/N: is inability to work due to hospitalisation? |
| rtw_self_reported_pain | VARCHAR(1) | Yes* | Y/N: self-reported pain preventing RTW? |
| rtw_opioid_side_effects | VARCHAR(1) | Yes* | Y/N: opioid/medication side effects preventing RTW? |
| rtw_other_restrictions | TEXT | Yes | Other restrictions/comments (max 2048) |
| estimated_rtw_date | DATE | Yes* | Estimated date for pre-accident level work. *Required when missed_work = Y and returned_to_work = N. |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| reassessment_comments | TEXT | Yes | Additional reassessment comments for C570 corrections (max 2048) |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| wcb_injury_id | UUID | No | Primary key |
| wcb_claim_detail_id | UUID FK | No | FK to wcb_claim_details |
| ordinal | SMALLINT | No | Position 1–5 |
| part_of_body_code | VARCHAR(10) | No | POB code (30 valid values; e.g., 42000 = Ankle, 01100 = Brain) |
| side_of_body_code | VARCHAR(10) | Yes | SOB code: L, R, B. Required when POB requires side (per Side of Body Required flag in POB codes table). |
| nature_of_injury_code | VARCHAR(10) | No | NOI code (46 valid values; e.g., 02100 = Sprain, 01200 = Fracture) |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| wcb_prescription_id | UUID | No | Primary key |
| wcb_claim_detail_id | UUID FK | No | FK to wcb_claim_details |
| ordinal | SMALLINT | No | Position 1–5 |
| prescription_name | VARCHAR(50) | No | Medication name |
| strength | VARCHAR(30) | No | Strength/dosage form |
| daily_intake | VARCHAR(30) | No | Daily intake (tab/ml) |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| wcb_consultation_id | UUID | No | Primary key |
| wcb_claim_detail_id | UUID FK | No | FK to wcb_claim_details |
| ordinal | SMALLINT | No | Position 1–5 |
| category | VARCHAR(10) | No | CONREF (Consultation/Referral) or INVE (Investigation) |
| type_code | VARCHAR(10) | No | Type within category: ORTHO, NEURO, PLASTIC, OTHER, XRAY, ULTRA, CT, MRI, EMG, OTHER |
| details | VARCHAR(50) | No | Free-text details |
| expedite_requested | VARCHAR(1) | Yes | Y/N. Only available for specific Category/Type combinations per Expedite Codes table. |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| wcb_restriction_id | UUID | No | Primary key |
| wcb_claim_detail_id | UUID FK | No | FK to wcb_claim_details |
| activity_type | VARCHAR(20) | No | SITTING, STANDING, WALKING, BENDING, TWISTING, KNEELING_SQUATTING, CLIMBING, LIFTING, PUSHING_PULLING, OVERHEAD_REACHING, DRIVING |
| restriction_level | VARCHAR(10) | No | Able/Unable per Work Restriction Detail Codes (FULL, PART, UNABLE for OIS; simpler for standard) |
| hours_per_day | SMALLINT | Yes | Applicable for SITTING, STANDING, WALKING, DRIVING (activities with hours fields) |
| max_weight | VARCHAR(10) | Yes | Maximum weight category for LIFTING (per Weight Category Codes) |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| wcb_invoice_line_id | UUID | No | Primary key |
| wcb_claim_detail_id | UUID FK | No | FK to wcb_claim_details |
| invoice_detail_id | SMALLINT | No | Sequential line number within the invoice (1-based) |
| line_type | VARCHAR(10) | No | STANDARD (C050E/S, C151/S), DATED (C568/A), SUPPLY (C569), WAS (C570), SHOULD_BE (C570) |
| health_service_code | VARCHAR(7) | Yes | HSC. Required for STANDARD and DATED lines. |
| diagnostic_code_1 | VARCHAR(8) | Yes | Primary diagnostic code (C568/A DATED lines) |
| diagnostic_code_2 | VARCHAR(8) | Yes | Secondary diagnostic code |
| diagnostic_code_3 | VARCHAR(8) | Yes | Tertiary diagnostic code |
| modifier_1 | VARCHAR(6) | Yes | Primary modifier |
| modifier_2 | VARCHAR(6) | Yes | Secondary modifier |
| modifier_3 | VARCHAR(6) | Yes | Tertiary modifier |
| calls | SMALLINT | Yes | Number of calls (0–7) |
| encounters | SMALLINT | Yes | Number of encounters (0 or 1) |
| date_of_service_from | DATE | Yes | Service start date (C568/A DATED lines) |
| date_of_service_to | DATE | Yes | Service end date (C568/A DATED lines) |
| facility_type_override | VARCHAR(1) | Yes | Per-line facility type override for C568/A |
| skill_code_override | VARCHAR(10) | Yes | Per-line skill code override for C568/A |
| invoice_detail_type_code | VARCHAR(10) | Yes | Detail type code for C568/A lines |
| invoice_detail_desc | VARCHAR(50) | Yes | Detail description for C568/A lines |
| quantity | SMALLINT | Yes | Quantity for C569 supply lines |
| supply_description | VARCHAR(50) | Yes | Supply type and description for C569 |
| amount | DECIMAL(10,2) | Yes | Fee amount (C568/A fees_submitted, C569 amount) |
| adjustment_indicator | VARCHAR(10) | Yes | C570 only: adjustment indicator for Was/Should Be pairing |
| billing_number_override | VARCHAR(8) | Yes | C570 only: per-line billing number for corrections |
| correction_pair_id | SMALLINT | Yes | C570 only: links Was line to its corresponding Should Be line |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| wcb_attachment_id | UUID | No | Primary key |
| wcb_claim_detail_id | UUID FK | No | FK to wcb_claim_details |
| ordinal | SMALLINT | No | Position 1–3 |
| file_name | VARCHAR(255) | No | Original file name |
| file_type | VARCHAR(10) | No | File type code per WCB attachment codes (e.g., PDF, DOC, JPG) |
| file_content_b64 | TEXT | No | Base64-encoded file content. Stored encrypted at rest. |
| file_description | VARCHAR(60) | No | Description of attachment content |
| file_size_bytes | INTEGER | No | Original file size in bytes (for validation and UI display) |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| wcb_batch_id | UUID | No | Primary key |
| physician_id | UUID FK | No | FK to providers. Each batch is per-physician. |
| batch_control_id | VARCHAR(50) | No | Batch control ID (appears in BHS.11). Used for return file reconciliation. |
| file_control_id | VARCHAR(50) | No | File control ID (appears in FHS.11). |
| status | VARCHAR(20) | No | ASSEMBLING, GENERATED, VALIDATED, UPLOADED, RETURN_RECEIVED, RECONCILED, ERROR |
| report_count | INTEGER | No | Number of reports in the batch |
| xml_file_path | VARCHAR(255) | Yes | Path to generated XML file (encrypted at rest) |
| xml_file_hash | VARCHAR(64) | Yes | SHA-256 hash of generated XML file |
| xsd_validation_passed | BOOLEAN | Yes | Did the file pass XSD schema validation? |
| xsd_validation_errors | JSONB | Yes | Array of XSD validation errors if failed |
| uploaded_at | TIMESTAMPTZ | Yes | When the file was uploaded to myWCB |
| uploaded_by | UUID FK | Yes | Who uploaded (physician or delegate) |
| return_file_received_at | TIMESTAMPTZ | Yes | When batch return notification was received |
| return_file_path | VARCHAR(255) | Yes | Path to return file |
| created_at | TIMESTAMPTZ | No | Batch creation timestamp |
| created_by | UUID FK | No | Who initiated the batch |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| wcb_return_record_id | UUID | No | Primary key |
| wcb_batch_id | UUID FK | No | FK to wcb_batches |
| wcb_claim_detail_id | UUID FK | Yes | FK to matched wcb_claim_details (null if unable to match) |
| report_txn_id | VARCHAR(20) | No | WCB-assigned transaction ID |
| submitter_txn_id | VARCHAR(16) | No | Our submitter transaction ID (for matching) |
| processed_claim_number | VARCHAR(7) | Yes | WCB claim number assigned/confirmed |
| claim_decision | VARCHAR(20) | No | Accepted or empty (for invalid reports) |
| report_status | VARCHAR(20) | No | Complete or Invalid |
| txn_submission_date | DATE | No | Submission date as recorded by WCB |
| errors | JSONB | Yes | Array of {error_number, error_description} for Invalid reports |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| wcb_return_invoice_line_id | UUID | No | Primary key |
| wcb_return_record_id | UUID FK | No | FK to wcb_return_records |
| invoice_sequence | SMALLINT | No | Invoice line sequence number |
| service_date | DATE | Yes | Service date for the line |
| health_service_code | VARCHAR(7) | Yes | HSC for the line |
| invoice_status | VARCHAR(20) | Yes | Line-level status (typically empty for accepted) |

| Column | Type | Null | Description |
| --- | --- | --- | --- |
| wcb_remittance_id | UUID | No | Primary key |
| remittance_import_id | UUID FK | No | FK to remittance import batch record |
| wcb_claim_detail_id | UUID FK | Yes | FK to matched wcb_claim_details |
| report_week_start | DATE | No | Remittance report week start date |
| report_week_end | DATE | No | Remittance report week end date |
| disbursement_number | VARCHAR(8) | Yes | Disbursement/cheque number |
| disbursement_type | VARCHAR(3) | Yes | EFT or AUT (cheque) |
| disbursement_issue_date | DATE | Yes | Date disbursement was issued |
| disbursement_amount | DECIMAL(11,2) | Yes | Total disbursement amount |
| disbursement_recipient_billing | VARCHAR(8) | Yes | Recipient billing number |
| disbursement_recipient_name | VARCHAR(40) | Yes | Recipient name |
| payment_payee_billing | VARCHAR(8) | No | Payee billing number |
| payment_payee_name | VARCHAR(40) | No | Payee name |
| payment_reason_code | VARCHAR(3) | No | REQ, ISS, etc. |
| payment_status | VARCHAR(3) | No | ISS (Issued), DEL (Deleted), PAE/PGA (Pending Approval), PGD (Pending Decision), REJ (Rejected), REQ (Requested) |
| payment_start_date | DATE | No | Payment period start |
| payment_end_date | DATE | No | Payment period end |
| payment_amount | DECIMAL(11,2) | No | Payment amount for this line |
| billed_amount | DECIMAL(10,2) | Yes | Original billed amount from electronic report |
| electronic_report_txn_id | VARCHAR(20) | Yes | WCB transaction ID (for matching to return records) |
| claim_number | VARCHAR(7) | Yes | WCB claim number |
| worker_phn | VARCHAR(11) | Yes | Worker PHN |
| worker_first_name | VARCHAR(11) | Yes | Worker first name |
| worker_last_name | VARCHAR(21) | Yes | Worker last name |
| service_code | VARCHAR(7) | Yes | Health service code |
| modifier_1 | VARCHAR(6) | Yes | Primary modifier |
| modifier_2 | VARCHAR(6) | Yes | Secondary modifier |
| modifier_3 | VARCHAR(6) | Yes | Tertiary modifier |
| number_of_calls | SMALLINT | Yes | Number of calls |
| encounter_number | SMALLINT | Yes | Encounter number |
| overpayment_recovery | DECIMAL(10,2) | Yes | Overpayment recovery amount deducted |

| # | Check | Severity | Description |
| --- | --- | --- | --- |
| 1 | Form ID Valid | Error | form_id is one of the 8 valid WCB form types. |
| 2 | Contract ID / Role / Form ID | Error | The practitioner's Contract ID and Role permit the selected Form ID (per Section 2.3 matrix). For follow-up forms, validates the parent claim chain. |
| 3 | Required Fields Present | Error | All 'Always Required' fields for this form type are populated and non-empty. |
| 4 | Conditional Field Logic | Error | All 'Conditionally Available and Required' fields are present when their trigger conditions are met (Section 4.2). |
| 5 | Data Type / Length | Error | Each field value conforms to its data type (Alpha, Char, Num, Date, Cur) and length constraints per the HL7 mapping. |
| 6 | Date Validation | Error | All date fields are valid dates in accepted formats (YYYYMMDD, YYYY-MM-DD, YYYY/MM/DD). Date of examination >= date of injury. Report completion date >= date of examination. |
| 7 | POB-NOI Combination | Error | Each injury entry's Part of Body / Nature of Injury combination is not in the 382-entry exclusion list (Section 4.3). |
| 8 | Side of Body Required | Error | Side of Body is provided when the selected Part of Body requires it (per POB codes table 'Side of Body Required' flag). |
| 9 | Code Table Values | Error | All coded fields contain values from their respective code tables (Gender, Province, POB, NOI, Skill Code, Facility Type, etc.). |
| 10 | Submitter Txn ID Format | Error | First 2 characters match Meritum's vendor prefix. Total length 1–16. Unique within this batch. |
| 11 | PHN Logic | Error | If patient_no_phn_flag = N, PHN must be present and 9 digits. If Y, PHN must be blank. |
| 12 | Invoice Line Integrity | Error | At least 1 invoice line present. Line numbers sequential. Form-specific line field requirements met (Section 3.6). |
| 13 | Attachment Constraints | Warning | Max 3 attachments per form. File type is in permitted attachment codes for this form type. |
| 14 | WCB Timing Deadline | Warning | Calculates submission timing tier (same-day, on-time, late) and warns if claim is approaching or past the on-time window (Section 4.5). |
| 15 | Expedite Eligibility | Warning | If expedite_requested = Y on a consultation, validates the Category/Type combination permits expedite per Expedite Codes table. |
| 16 | Duplicate Detection | Warning | Checks for existing WCB claims with same patient + same date of injury + same form type within configurable window. |

| Tier | GP First (C050E) | GP Progress (C151) | Specialist (C568A) |
| --- | --- | --- | --- |
| Same-day | Exam day or next biz day by 10:00 MT | Exam day or next biz day by 10:00 MT | Exam day or next biz day by 10:00 MT |
| On-time | Within 3 biz days (by 10:00 MT day 4) | Within 4 biz days (by 10:00 MT day 5) | Within 4 biz days (by 10:00 MT day 5) |
| Late | After on-time deadline | After on-time deadline | After on-time deadline |

| Report Type | Same-day | On-time | Late | Fee Type |
| --- | --- | --- | --- | --- |
| C050E GP First Report | $94.15 | $85.80 | $54.08 | Report fee |
| C151 GP Progress Report | $57.19 | $52.12 | $32.86 | Report fee |
| RF01E Specialist Consultation | $115.05 | $104.87 | $66.09 | Report fee |
| RF03E Specialist Follow-up | $57.19 | $52.12 | $32.86 | Report fee |

| Segment.Field | Value | Notes |
| --- | --- | --- |
| FHS.3 / BHS.3 / MSH.3 | Meritum vendor source ID | Assigned by WCB during accreditation. Stored in secrets management. |
| FHS.4 / BHS.4 / MSH.4 | Meritum submitter ID | Assigned by WCB during accreditation. |
| FHS.5 / BHS.5 | WCB-EDM | Fixed value: Workers Compensation Board Edmonton |
| FHS.6 / BHS.6 | RAPID-RPT | Fixed value: RapidReport component |
| FHS.7 / BHS.7 / MSH.7 | YYYYMMDDHHmm | File/batch/message creation timestamp in Mountain Time |
| FHS.9 | Generated filename | e.g., meritum_batch_20260212_001.xml |
| FHS.11 | File control ID | Unique per file. Format: MER-{YYYYMMDD}-{sequence} |
| BHS.11 | Batch control ID | Unique per batch. Used to match return files. Format: MER-B-{UUID short} |
| MSH.9 | ZRPT | Fixed: WCB Batch Report Message type |
| MSH.10 | submitter_txn_id | Per-report unique ID. First 2 chars = vendor prefix. |
| EVN.4 | form_id | C050E, C050S, C151, C151S, C568, C568A, C569, C570 |

| Aspect | AHCIP (Domain 4.1) | WCB (Domain 4.2) |
| --- | --- | --- |
| Cycle | Weekly: Thursday 12:00 MT cutoff | On-demand (timing affects fees, not submission window) |
| Format | Fixed-width/delimited per AHCIP spec | HL7 v2.3.1 XML per WCB XSD |
| Transport | H-Link (SFTP/API, TBD) | Manual file upload to myWCB portal |
| Accreditation | H-Link accreditation (AHC2210) | WCB vendor accreditation (9-step process) |
| Return | Assessment file via H-Link | Tab-delimited return file via email |
| Payment | Friday following Thursday submission | Weekly cycle, Tuesday remittance XML |
| Grouping | Per-physician, per-BA | Per-physician (single vendor credentials) |

| Code | Status | Meritum Action |
| --- | --- | --- |
| ISS | Issued | Payment confirmed. Claim → paid state. |
| REQ | Requested | Payment in progress. No state change yet. |
| PAE / PGA | Pending Approval | Awaiting WCB internal approval. No state change. |
| PGD | Pending Decision | Awaiting adjudication. Monitor and notify. |
| REJ | Rejected | Payment rejected. Claim flagged for review. |
| DEL | Deleted | Payment deleted by WCB. Claim flagged for review. |

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | /api/v1/wcb/claims | Create a WCB claim. Body includes form_id, which determines required fields. Returns claim_id and wcb_claim_detail_id. |
| GET | /api/v1/wcb/claims/{id} | Retrieve WCB claim with all child records (injuries, prescriptions, consultations, restrictions, invoice lines, attachments). |
| PUT | /api/v1/wcb/claims/{id} | Update WCB claim. Partial updates supported. Triggers revalidation. |
| DELETE | /api/v1/wcb/claims/{id} | Soft-delete. Only allowed in draft state. |
| POST | /api/v1/wcb/claims/{id}/validate | Run WCB validation pipeline and return results without changing state. |
| GET | /api/v1/wcb/claims/{id}/form-schema | Returns the form field schema for this claim's form_id: which sections are active, which fields are required/conditional/optional, current conditional states based on existing data. |

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | /api/v1/wcb/batches | Initiate WCB batch generation. Includes queued claims for the authenticated physician. Triggers XML generation and XSD validation. |
| GET | /api/v1/wcb/batches/{id} | Retrieve batch details including status, report count, validation results. |
| GET | /api/v1/wcb/batches/{id}/download | Download generated XML file (signed URL, single-use, 1-hour expiry). Requires VALIDATED status. |
| POST | /api/v1/wcb/batches/{id}/confirm-upload | Physician/delegate confirms file was uploaded to myWCB. Transitions batch to UPLOADED. |
| GET | /api/v1/wcb/batches | List batches for the authenticated physician with status filtering and pagination. |

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | /api/v1/wcb/returns/upload | Upload return file (tab-delimited text). Triggers parsing, matching, and state transitions. |
| GET | /api/v1/wcb/returns/{batch_id} | Retrieve return file results for a specific batch, including per-report status and errors. |

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | /api/v1/wcb/remittances/upload | Upload remittance XML file. Triggers parsing, storage, matching, and reconciliation. |
| GET | /api/v1/wcb/remittances | List remittance imports with date range filtering. |
| GET | /api/v1/wcb/remittances/{id}/discrepancies | Retrieve reconciliation discrepancies for a remittance import. |

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/wcb/claims/{id}/export | Generate pre-filled export (PDF/printable) for manual portal entry. MVP only — deprecated after accreditation. |
| POST | /api/v1/wcb/claims/{id}/manual-outcome | Physician manually records WCB outcome (claim number, acceptance status, payment). MVP only. |

| Seq | WCB Field | Meritum Column | HL7 Seg | Notes |
| --- | --- | --- | --- | --- |
| General | General | General | General | General |
| 1 | Submitter Transaction ID | submitter_txn_id | MSH.10 | Vendor prefix + unique ID |
| 2 | Form ID | form_id | EVN.4 | Always C050E |
| 3 | Claim Number | wcb_claim_number | PID.2 | Optional; WCB assigns on acceptance |
| 4 | Report Completion Date | report_completion_date | EVN.6 | YYYYMMDD format in XML |
| Practitioner | Practitioner | Practitioner | Practitioner | Practitioner |
| 6 | Billing number | practitioner_billing_number | FT1.3 | 8-char practitioner ID |
| 7 | Contract ID | contract_id | FT1.14 | Must be valid for GP/ERS/NP + C050E |
| 8 | Role | role_code | OBX | OBX.3 = PRACTITIONER_ROLE |
| 84 | Skill code | skill_code | PRD.1 | From Skill Codes table |
| Injury | Injury | Injury | Injury | Injury |
| 37 | Date of Examination | date_of_examination | FT1.4 | Day 0 for timing calculation |
| 40 | Current diagnosis | current_diagnosis | FT1.19 | Free text + diagnostic codes |
| 44 | Injuries [1..5] | wcb_injuries table | FT1.19.LST | POB/SOB/NOI validated against exclusion matrix |
| Treatment Plan | Treatment Plan | Treatment Plan | Treatment Plan | Treatment Plan |
| 49 | Narcotics prescribed | narcotics_prescribed | OBX | Triggers prescription entries |
| 52 | Consultations [1..5] | wcb_consultations table | OBX | Category + Type + Details + Expedite |
| Return to Work | Return to Work | Return to Work | Return to Work | Return to Work |
| 56 | Missed work | missed_work_beyond_accident | OBX | Triggers entire RTW cascade |
| 62–77 | Activity restrictions | wcb_work_restrictions table | OBX | 11 activity types with levels and hours |
| Invoice | Invoice | Invoice | Invoice | Invoice |
| 90 | Invoice Lines [1..25] | wcb_invoice_lines table | FT1 | HSC + modifiers + calls + encounters |

| Seq | WCB Field | Meritum Column | Notes |
| --- | --- | --- | --- |
| 40 | Previous diagnosis | previous_diagnosis | Text of previous diagnosis (vs C050E's 'current') |
| 41 | Diagnosis changed? | diagnosis_changed | Y/N trigger for changed description |
| 53–75 | Opioid management (16 fields) | Various opioid/side-effect columns | Conditionally required when narcotics = Y. C151-specific feature. |
| 72 | Pain severity 0–10 | patient_pain_estimate | Patient self-report. Conditional on narcotics. |
| 75 | Function level 0–10 | clinician_function_estimate | Clinician estimate. Conditional on narcotics. |

| Code | Description | Side of Body Required |
| --- | --- | --- |
| 00000 | Head | No |
| 01100 | Brain | No |
| 02000 | Ear | Yes |
| 03000 | Face | No |
| 03201 | Eye | Yes |
| 03630 | Teeth | No |
| 10000 | Neck | No |
| 20000 | Trunk | Yes |
| 21000 | Shoulder | Yes |
| 22009 | Chest | No |
| 23000 | Back - Middle | No |
| 23901 | Back - Lower | No |
| 24000 | Abdomen | No |
| 24900 | Internal systems | No |
| 25100 | Hip | Yes |
| 25400 | Groin | Yes |
| 31000 | Arm | Yes |
| 31200 | Elbow | Yes |
| 32000 | Wrist | Yes |
| 33000 | Hand | Yes |
| 34000 | Finger | Yes |
| 34001 | Thumb | Yes |
| 41000 | Leg | Yes |
| 41200 | Knee | Yes |
| 42000 | Ankle | Yes |
| 43000 | Foot | Yes |
| 44000 | Toes | Yes |
| 50000 | Body systems | No |
| 91000 | Personal effects only | No |
| 99990 | Unknown/Other | No |

| Code | Description |
| --- | --- |
| GP | General Practitioner |
| OR | Ortho |
| SP | Specialist |
| ERS | ER Specialist/FTER |
| ANE | Anesthesiologist |
| DP | Diagnostic Provider |
| VSC | Visiting Specialist Clinic |
| VSCFAC | Visiting Specialist Clinic (Facility) |
| OIS | OIS |
| NP | Nurse Practitioners |

| Code | Description |
| --- | --- |
| C | Clinic |
| F | Facility Non-Hospital |
| H | Hospital |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| grasp_right_level | VARCHAR(10) | No* | Right hand grasping: ABLE, UNABLE, LIMITED (per Basic Work Restriction Codes) |
| grasp_right_prolonged | VARCHAR(1) | Yes* | Y/N: prolonged grasping restricted? Conditional on LIMITED. |
| grasp_right_repetitive | VARCHAR(1) | Yes* | Y/N: repetitive grasping restricted? |
| grasp_right_vibration | VARCHAR(1) | Yes* | Y/N: vibration-related grasping restricted? |
| grasp_right_specify | VARCHAR(1) | Yes* | Y/N: specific restriction applies? |
| grasp_right_specific_desc | TEXT | Yes* | Description of specific right-hand restriction. Required when specify = Y. |
| grasp_left_level | VARCHAR(10) | No* | Left hand grasping level |
| grasp_left_prolonged | VARCHAR(1) | Yes* | Y/N: prolonged grasping restricted? |
| grasp_left_repetitive | VARCHAR(1) | Yes* | Y/N: repetitive grasping restricted? |
| grasp_left_vibration | VARCHAR(1) | Yes* | Y/N: vibration-related grasping restricted? |
| grasp_left_specify | VARCHAR(1) | Yes* | Y/N: specific restriction applies? |
| grasp_left_specific_desc | TEXT | Yes* | Description of specific left-hand restriction |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| lift_floor_to_waist | VARCHAR(10) | No* | ABLE, UNABLE, LIMITEDTO (per Extended Work Restriction Codes) |
| lift_floor_to_waist_max | VARCHAR(10) | Yes* | Max weight (per Weight Category Codes). Required when LIMITEDTO. |
| lift_waist_to_shoulder | VARCHAR(10) | No* | Restriction level for waist-to-shoulder zone |
| lift_waist_to_shoulder_max | VARCHAR(10) | Yes* | Max weight for waist-to-shoulder |
| lift_above_shoulder | VARCHAR(10) | No* | Restriction level for above-shoulder zone |
| lift_above_shoulder_max | VARCHAR(10) | Yes* | Max weight for above-shoulder |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| reach_above_right_shoulder | VARCHAR(10) | No* | ABLE, UNABLE, LIMITED |
| reach_below_right_shoulder | VARCHAR(10) | No* | ABLE, UNABLE, LIMITED |
| reach_above_left_shoulder | VARCHAR(10) | No* | ABLE, UNABLE, LIMITED |
| reach_below_left_shoulder | VARCHAR(10) | No* | ABLE, UNABLE, LIMITED |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| environment_restricted | VARCHAR(1) | No* | Y/N: does the worker have environmental restrictions? |
| env_cold | VARCHAR(1) | Yes* | Y/N: cold sensitivity. Required when environment_restricted = Y. |
| env_hot | VARCHAR(1) | Yes* | Y/N: heat sensitivity |
| env_wet | VARCHAR(1) | Yes* | Y/N: wet conditions restricted |
| env_dry | VARCHAR(1) | Yes* | Y/N: dry conditions restricted |
| env_dust | VARCHAR(1) | Yes* | Y/N: dust/particle sensitivity |
| env_lighting | VARCHAR(1) | Yes* | Y/N: lighting sensitivity |
| env_noise | VARCHAR(1) | Yes* | Y/N: noise sensitivity |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| Assessment Outcome | Assessment Outcome | Assessment Outcome | Assessment Outcome |
| ois_reviewed_with_patient | VARCHAR(1) | No* | Y/N: reviewed work capabilities with patient |
| ois_fitness_assessment | VARCHAR(10) | No* | FIT (fit to return) or NOTFIT (not fit for any work) per Fit For Work Codes |
| ois_estimated_rtw_date | DATE | Yes* | Estimated RTW date. Required when NOTFIT. |
| ois_rtw_level | VARCHAR(10) | Yes* | PREINJURY or LIMITATION per Work Level Codes. Required when FIT. |
| ois_followup_required | VARCHAR(1) | No* | Y/N: OIS follow-up visit required |
| ois_followup_date | DATE | Yes* | Follow-up visit date. Required when followup_required = Y. |
| Employer Communication | Employer Communication | Employer Communication | Employer Communication |
| ois_emp_modified_work_required | VARCHAR(1) | No* | Y/N: modified work is required |
| ois_emp_modified_from_date | DATE | Yes* | Modified work required from date |
| ois_emp_modified_to_date | DATE | Yes* | Modified work required to date |
| ois_emp_modified_available | VARCHAR(1) | No* | Y/N/NA: if applicable, modified work is available |
| ois_emp_available_from_date | DATE | Yes* | Modified work available from date |
| ois_emp_available_to_date | DATE | Yes* | Modified work available to date |
| ois_emp_comments | TEXT | Yes | Employer communication comments |
| Worker Communication | Worker Communication | Worker Communication | Worker Communication |
| ois_worker_rtw_date | DATE | No* | Return to work date communicated to worker |
| ois_worker_modified_duration | VARCHAR(50) | No* | Duration of modified work if applicable |
| ois_worker_diagnosis_plan | TEXT | No* | Diagnosis and treatment plan in worker-accessible language |
| ois_worker_self_care | VARCHAR(1) | No* | Y/N: re-education on self-care and prevention of reinjury provided |
| ois_worker_comments | TEXT | Yes | Worker communication comments |
| Family Physician Handoff | Family Physician Handoff | Family Physician Handoff | Family Physician Handoff |
| ois_has_family_physician | VARCHAR(1) | No* | Y/N: patient has a family physician |
| ois_family_physician_name | VARCHAR(50) | Yes* | Family physician name. Required when has_family_physician = Y. |
| ois_family_physician_phone_country | VARCHAR(10) | Yes* | Phone country code |
| ois_family_physician_phone | VARCHAR(24) | Yes* | Phone number |
| ois_family_physician_plan | TEXT | Yes* | Diagnosis/treatment plan for family physician |
| ois_family_physician_support | VARCHAR(10) | Yes* | OIS or FAMILY (per OIS Family Physician Codes): who will support the OIS referral |
| ois_family_physician_rtw_date | DATE | Yes* | RTW date communicated to family physician |
| ois_family_physician_treatment | VARCHAR(10) | Yes* | Who will continue treatment: OIS or FAMILY |
| ois_family_physician_modified | VARCHAR(10) | Yes* | NORESTRICT or RESTRICTFR (per Restriction Codes): return to modified work status |
| ois_family_physician_comments | TEXT | Yes | Family physician communication comments |

| Table | Values |
| --- | --- |
| Basic Work Restriction Codes | ABLE (Able), UNABLE (Unable), LIMITED (Limited) |
| Extended Work Restriction Codes | ABLE (Able), UNABLE (Unable), LIMITEDTO (Limited to) |
| Work Restriction Detail Codes | ABLE, UNABLE, LIMITED, LIMITEDTO |
| Fit For Work Codes | FIT (Fit to return to work), NOTFIT (Not fit for any work) |
| Restriction Codes | NORESTRICT (No restrictions), RESTRICTFR (Restricted from) |
| Work Level Codes | PREINJURY (Pre-injury level), LIMITATION (With work limitations) |
| OIS Family Physician Codes | OIS (OIS physician), FAMILY (Family physician) |

| # | Question | Context |
| --- | --- | --- |
| 1 | What is the maximum batch file size accepted by the myWCB upload interface? | The accreditation package does not specify. Relevant for batches with multiple large attachments. To be determined during accreditation testing. |
| 2 | Does WCB support batch resubmission with the same batch_control_id, or must each submission use a unique ID? | Important for retry logic. Assumed unique per submission until confirmed. |
| 3 | What is the typical WCB batch processing time (upload to return file)? | Needed for setting user expectations and timeout/monitoring thresholds. |
| 4 | Is there a WCB test environment for batch submission during accreditation? | The accreditation document mentions test cycles but does not specify a test endpoint URL. |
| 5 | Can a single batch contain reports for multiple practitioners, or must batches be per-practitioner? | The sample multiple-reports file (5.17) does not clarify. Assumed per-practitioner for simplicity. |
| 6 | What is the email delivery mechanism for return files? Is it IMAP-accessible or does WCB use a custom portal notification? | Determines whether return file ingestion can be automated or requires manual upload. |
| 7 | How does WCB handle the vendor accreditation for the OIS-specific forms (C050S, C151S)? Is separate accreditation required? | OIS forms may have additional requirements. To be confirmed during accreditation. |

| Item | Value |
| --- | --- |
| Parent document | Meritum PRD v1.3 |
| Domain | WCB Claim Pathway (Domain 4.2 of 13) |
| Build sequence position | 4th (sub-domain of Claim Lifecycle) |
| Dependencies | Domain 4.0 (Core), Domain 1 (IAM), Domain 2 (Reference Data), Domain 3 (Notifications) |
| Consumes | Domain 5 (Provider Mgmt), Domain 6 (Patient Registry), Domain 7 (Intelligence Engine) |
| Authoritative WCB reference | WCB Vendor Accreditation Package (40 files) and HL7 Element Mapping Spreadsheet |
| Version | 1.0 |
| Date | February 2026 |
| Next domain in critical path | Domain 5 (Provider Management) |

