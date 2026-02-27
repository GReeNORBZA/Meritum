# Meritum_Domain_06_Patient_Registry

MERITUM

Functional Requirements

Patient Registry

Domain 6 of 13  |  Critical Path: Position 6

Meritum Health Technologies Inc.

Version 1.0  |  February 2026

CONFIDENTIAL

# Table of Contents

# 1. Domain Overview

## 1.1 Purpose

The Patient Registry is the authoritative source of patient identity within Meritum. It stores the minimal demographic data required for claim creation and submission: PHN, name, date of birth, and gender. Every claim in Domain 4 references a patient record from this registry.

This is intentionally a lightweight domain. Meritum is a billing platform, not a clinical EMR. It stores only the demographics needed for AHCIP and WCB claim submission. Clinical data (diagnoses, encounter notes, treatment plans) lives in the physician's EMR; Meritum references patients by PHN and captures claim-level clinical codes (HSC, diagnostic codes, WCB injury details) on the claim itself, not the patient record.

## 1.2 Scope

Patient demographic records: PHN, name, DOB, gender, contact information

PHN validation: Alberta PHN format (9-digit with check digit)

Patient search: by PHN, name, DOB, or combination

Recent patients: quick-access list per physician for repeat visits

CSV bulk import: batch creation of patient records from EMR exports

WCB-extended demographics: employer details, mailing address (stored on WCB claims, not the patient registry — see Section 3.2)

Patient merge: handling duplicate patient records

Data portability: patient list export

## 1.3 Out of Scope

Clinical records, encounter notes, treatment plans (EMR responsibility)

Patient portal or patient-facing features (Meritum is physician-facing only)

Alberta Health patient eligibility verification (future enhancement; currently physician confirms eligibility)

PCPCM panel roster management (panel size is tracked in Provider Management; individual panel membership is managed by Alberta Health)

## 1.4 Domain Dependencies

# 2. Data Model

## 2.1 Patients Table (patients)

One row per patient per physician. Patient records are physician-scoped — the same physical patient seen by two different physicians using Meritum exists as two separate records. This preserves HIA custodian isolation: Physician A cannot see that Physician B also treats this patient.

Indexes: (physician_id, phn) unique where phn is not null, (physician_id, last_name, first_name), (physician_id, date_of_birth), (physician_id, last_visit_date DESC) for recent patients, (physician_id, is_active).

## 2.2 Patient Import Batches Table (patient_import_batches)

Tracks CSV bulk imports of patient records. Separate from the claim import batches in Domain 4.0.

## 2.3 Patient Merge History Table (patient_merge_history)

Records when duplicate patient records are merged. The surviving record absorbs all claims from the merged record.

# 3. PHN Validation

## 3.1 Alberta PHN Format

Alberta Personal Health Numbers are 9-digit numeric strings. The 9th digit is a check digit calculated using the Luhn algorithm (modulus 10, double-add-double). Meritum validates:

Length: Exactly 9 digits

Characters: Numeric only (no spaces, dashes, or letters)

Check digit: 9th digit passes Luhn validation against first 8 digits

Uniqueness: No two active patients for the same physician share a PHN

## 3.2 PHN-Optional Scenarios

PHN is nullable to support the following scenarios:

Newborns: PHN not yet assigned. Claim can use mother's PHN with newborn indicator (AHCIP-specific).

Out-of-province patients: Use home province health number with phn_province set accordingly. Reciprocal billing.

WCB claims with no PHN: WCB forms support patient_no_phn_flag = Y. Patient demographics (name, DOB) are required even without PHN.

Uninsured patients: Rare but possible. Claim may not be submittable to AHCIP but physician may want to track the encounter.

## 3.3 WCB Demographics Note

WCB claim forms require additional patient demographics beyond what the Patient Registry stores: employer name, employer address, employer phone, worker job title. These fields are claim-specific (the patient may have a different employer for each WCB claim) and are stored on the wcb_claim_details table (Domain 4.2), not on the patient record. The Patient Registry provides the identity baseline (PHN, name, DOB, gender); the WCB claim captures the situational context.

# 4. Patient Search

## 4.1 Search Modes

## 4.2 Search Scoping

All searches are scoped to the authenticated physician (or delegate's active physician context). A search never returns patients belonging to other physicians. This is enforced at the query level (WHERE physician_id = :auth_physician_id) and is the primary HIA custodian isolation mechanism.

## 4.3 Search Performance

Expected patient list size per physician: 500–5,000 for typical GPs, up to 20,000 for high-volume specialists or ED physicians. Name search uses trigram indexing (pg_trgm) for efficient prefix matching. PHN lookup uses the unique index. Recent patients query uses the last_visit_date index with a LIMIT 20.

# 5. CSV Bulk Import

Physicians can import their patient list from their EMR or previous billing system via CSV upload. This is typically a one-time onboarding task but can be repeated as the physician's patient panel grows.

## 5.1 Import Workflow

Physician uploads a CSV file.

System detects delimiter (comma, tab, pipe) and header row presence.

System maps columns to patient fields. Physician confirms or adjusts mapping.

Preview shows first 10 rows with mapped values and any validation warnings.

Physician commits the import.

System processes each row: validate PHN (if present), check for existing patient by PHN, create new or update existing.

Results summary: created, updated, skipped, error counts with per-row error details.

## 5.2 Import Column Mapping

## 5.3 Duplicate Handling

During import, existing patients are matched by PHN (within the same physician):

PHN match found: Update existing record with imported values (name, DOB, gender, address). Only non-null import values overwrite. Counts as 'updated'.

PHN match not found: Create new patient record. Counts as 'created'.

No PHN in import row: Always creates a new record (cannot match without PHN). Counts as 'created'. May create duplicates — physician can merge later.

Duplicate PHN in import file: Second occurrence skipped with warning. Counts as 'skipped'.

# 6. Patient Merge

Duplicate patient records can arise from imports without PHN, manual creation, or data entry errors. The merge function combines two patient records into one.

## 6.1 Merge Workflow

Physician identifies two patient records they believe are the same person.

System displays both records side-by-side, highlighting differing fields.

Physician selects the surviving record (the one to keep).

System shows the merge preview: how many claims will be transferred, which field values will be kept.

Physician confirms the merge.

System transfers all claims from the merged record to the surviving record (updates patient_id FK on claims).

Merged record is soft-deleted (is_active = false, marked as merged).

Merge recorded in patient_merge_history for audit.

## 6.2 Merge Rules

Surviving record's values are kept for all conflicting fields. The merge preview clearly shows which values will be retained.

Claims are transferred by updating the patient_id FK. The claim's content (PHN used in submission, etc.) is not altered — the claim retains the PHN that was on it at submission time.

Merge is irreversible in the UI. However, the merge history table preserves all details for administrative recovery if needed.

Only draft/validated claims have their patient_id updated. Claims already submitted retain their original patient_id reference for audit integrity, but the surviving patient record is linked for display purposes.

# 7. User Stories & Acceptance Criteria

# 8. API Contracts

All endpoints require authentication and are scoped to the physician (or delegate's active physician context). Delegate permissions from Domain 5 enforced by Domain 1 RBAC middleware.

## 8.1 Patient CRUD

## 8.2 Patient Search

## 8.3 CSV Import

## 8.4 Patient Merge

## 8.5 Patient Export

## 8.6 Internal Patient API

Consumed by Domain 4 (Claim Lifecycle) during claim creation and validation.

# 9. Security & Audit

## 9.1 Data Protection

Patient records are PHI. Encrypted at rest (AES-256) and in transit (TLS 1.3).

HIA custodian isolation: all queries scoped to physician_id. No cross-physician patient access under any circumstance.

Admin access to patient records requires explicit physician-granted PHI access permission (time-limited, logged) per Domain 1 IAM admin access rules.

Patient notes field may contain sensitive clinical observations. Encrypted at rest. Never transmitted in claims.

CSV import files processed in memory. Uploaded files stored temporarily (encrypted), deleted after import completion. Retained only for audit reference if configured.

Patient export files generated on Meritum infrastructure and delivered via authenticated, time-limited download link. Not emailed.

## 9.2 Audit Trail

## 9.3 PHN Masking

PHN is displayed masked in audit logs and administrative views: first 3 digits shown, remaining 6 replaced with asterisks (e.g., 123******). Full PHN visible only to the physician/delegate in the clinical context. This prevents PHN exposure in audit log exports or admin dashboards.

# 10. Testing Requirements

## 10.1 PHN Validation Tests

Valid 9-digit PHN with correct Luhn check digit → accepted

Invalid check digit → rejected with descriptive error

8-digit or 10-digit PHN → rejected (length check)

Non-numeric characters → rejected

Duplicate PHN for same physician → rejected

Same PHN for different physicians → accepted (HIA isolation)

Null PHN → accepted (WCB/newborn scenarios)

## 10.2 Search Tests

PHN exact match returns single result

Name prefix search returns ranked results (case-insensitive)

DOB search returns all patients with matching DOB

Combined search (name + DOB) narrows results

Search returns only patients for the authenticated physician

Recent patients ordered by last_visit_date DESC, limited to 20

Deactivated patients excluded from search results

## 10.3 Import Tests

CSV with comma delimiter, header row, all fields populated → all created

Tab-delimited, no header, minimal fields (name, DOB, gender) → all created

Import with existing PHN match → existing records updated

Import with duplicate PHN in file → second occurrence skipped

Import with invalid PHN → row rejected, others proceed

Import with missing required field (name, DOB) → row rejected

Duplicate file upload (same SHA-256 hash) → warning displayed

Large import (5,000 rows) → completes within acceptable time, correct counts

## 10.4 Merge Tests

Merge two patients with claims → claims transferred to surviving record

Merge preview shows correct claim count and field conflicts

Merged patient soft-deleted, no longer appears in search

Merge history recorded with full details

Submitted claims retain original patient_id for audit (display linked to surviving)

## 10.5 Integration Tests

Create patient → create AHCIP claim referencing patient → PHN appears in H-Link file

Create patient without PHN → create WCB claim with no_phn_flag → submission succeeds

Import patients → create claims for imported patients → batch submission

Delegate creates patient on behalf of physician → patient scoped to physician

Merge patient with claims in various states → all claim references updated correctly

# 11. Open Questions

# 12. Document Control

This document specifies the Patient Registry domain. It provides the patient identity baseline consumed by the Claim Lifecycle (Domain 4) for both AHCIP and WCB submission pathways.

| Domain | Direction | Interface |
| --- | --- | --- |
| 1 Identity & Access | Consumed | Authentication, RBAC. Patient records scoped to physician (HIA custodian). |
| 4.0 Claim Lifecycle Core | Consumed by | Patient lookup during claim creation. PHN, name, DOB, gender used in claims. |
| 4.1 AHCIP Pathway | Consumed by | Patient PHN for H-Link submission file. |
| 4.2 WCB Pathway | Consumed by | Patient PHN, name, DOB, gender, address for WCB EIR forms. WCB-specific demographics (employer) stored on the claim, not here. |
| 5 Provider Management | Consumed | Physician context determines which patients are accessible (HIA scoping). |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| patient_id | UUID | No | Primary key |
| physician_id | UUID FK | No | FK to providers. The HIA custodian. Scopes all access. |
| phn | VARCHAR(9) | Yes | Alberta Personal Health Number. 9 digits. Null for patients without Alberta coverage (out-of-province, newborns pending PHN assignment). Unique per physician. |
| phn_province | VARCHAR(2) | Yes | Province of PHN issuance. Default: AB. Set for out-of-province reciprocal billing. |
| first_name | VARCHAR(50) | No | Patient first name. As it appears on Alberta Health records. |
| middle_name | VARCHAR(50) | Yes | Patient middle name |
| last_name | VARCHAR(50) | No | Patient last name |
| date_of_birth | DATE | No | Required for age-based fee calculations and WCB form fields. |
| gender | VARCHAR(1) | No | M, F, or X. Required for AHCIP and WCB submissions. |
| phone | VARCHAR(24) | Yes | Primary phone number |
| email | VARCHAR(100) | Yes | Email address (optional; not used in claim submission) |
| address_line_1 | VARCHAR(100) | Yes | Mailing address. Optional for AHCIP; required context for WCB forms (captured on claim). |
| address_line_2 | VARCHAR(100) | Yes |  |
| city | VARCHAR(50) | Yes |  |
| province | VARCHAR(2) | Yes |  |
| postal_code | VARCHAR(7) | Yes |  |
| notes | TEXT | Yes | Physician's private notes about the patient. Not transmitted in any claim. |
| is_active | BOOLEAN | No | Active patients appear in search. Inactive patients are soft-hidden. Default: true. |
| last_visit_date | DATE | Yes | Date of most recent claim for this patient. Updated when claims are created. Drives 'recent patients' list. |
| created_at | TIMESTAMPTZ | No |  |
| updated_at | TIMESTAMPTZ | No |  |
| created_by | UUID FK | No | Creator (physician or delegate) |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| import_id | UUID | No | Primary key |
| physician_id | UUID FK | No | FK to providers |
| file_name | VARCHAR(255) | No | Original uploaded filename |
| file_hash | VARCHAR(64) | No | SHA-256 hash for deduplication |
| total_rows | INTEGER | No | Total rows in the import file |
| created_count | INTEGER | No | New patient records created |
| updated_count | INTEGER | No | Existing patient records updated (matched by PHN) |
| skipped_count | INTEGER | No | Rows skipped (duplicate PHN, no changes) |
| error_count | INTEGER | No | Rows that failed validation |
| error_details | JSONB | Yes | Per-row error details |
| status | VARCHAR(20) | No | PENDING, PROCESSING, COMPLETED, FAILED |
| created_at | TIMESTAMPTZ | No |  |
| created_by | UUID FK | No |  |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| merge_id | UUID | No | Primary key |
| physician_id | UUID FK | No | FK to providers |
| surviving_patient_id | UUID FK | No | The patient record that remains |
| merged_patient_id | UUID FK | No | The patient record that was absorbed (soft-deleted after merge) |
| claims_transferred | INTEGER | No | Number of claims re-linked from merged to surviving |
| field_conflicts | JSONB | Yes | Fields where the two records differed. Surviving record's values were kept. |
| merged_at | TIMESTAMPTZ | No |  |
| merged_by | UUID FK | No | Who performed the merge |

| Mode | Input | Behaviour |
| --- | --- | --- |
| PHN Lookup | 9-digit PHN | Exact match. Returns 0 or 1 result. Fastest path. Used when physician has the PHN card. |
| Name Search | First and/or last name | Case-insensitive prefix match. Returns ranked results. Minimum 2 characters. |
| DOB Search | Date of birth | Exact match on DOB. Typically combined with name for disambiguation. |
| Combined | Any combination of PHN, name, DOB | All criteria AND-ed. Most specific search. |
| Recent Patients | None (implicit) | Returns the 20 most recently seen patients (by last_visit_date). Default view in patient selection. |

| Meritum Field | Common CSV Headers | Required | Notes |
| --- | --- | --- | --- |
| phn | PHN, HealthNumber, AB_PHN | No | Validated with Luhn check. Rows without PHN create patients without PHN. |
| first_name | FirstName, First, GivenName | Yes | Required for all rows. |
| last_name | LastName, Last, Surname | Yes | Required for all rows. |
| date_of_birth | DOB, DateOfBirth, BirthDate | Yes | Parsed per detected or configured date format. |
| gender | Gender, Sex | Yes | M/F/X. Common mappings: Male→M, Female→F. |
| phone | Phone, PhoneNumber, Tel | No | Imported as-is. |
| address_line_1 | Address, Address1, Street | No |  |
| city | City, Town | No |  |
| postal_code | PostalCode, Postal, Zip | No |  |

| ID | Story | Acceptance Criteria |
| --- | --- | --- |
| PAT-001 | As a physician, I want to add a new patient so I can create claims for them | Enter PHN (optional), first/last name, DOB, gender. PHN validated (Luhn check, uniqueness within my patients). Patient created and immediately available for claim creation. |
| PAT-002 | As a physician, I want to search for an existing patient by PHN | Enter 9-digit PHN. Exact match returned instantly. If no match, option to create new patient with that PHN pre-filled. |
| PAT-003 | As a physician, I want to search for a patient by name | Type 2+ characters. Results update as I type. Case-insensitive. Ranked by relevance (exact match > prefix > partial). Recent patients prioritised. |
| PAT-004 | As a physician, I want to see my recent patients for quick access | Patient selection defaults to recent patients view. Shows 20 most recently seen. Each entry shows name, PHN, DOB, last visit date. Click to select for claim creation. |
| PAT-005 | As a physician, I want to import my patient list from a CSV file | Upload CSV. Preview column mapping. Confirm import. See results: created, updated, skipped, errors. Per-row error details for failed rows. |
| PAT-006 | As a physician, I want to edit a patient's demographics | Edit any field. PHN change triggers re-validation (Luhn, uniqueness). Changes audit-logged. Existing submitted claims not affected. |
| PAT-007 | As a physician, I want to merge two duplicate patient records | Select two patients. Side-by-side comparison. Select surviving record. Preview claim transfer count. Confirm merge. Claims transferred. Merged record soft-deleted. |
| PAT-008 | As a physician, I want to deactivate a patient I no longer see | Deactivate action. Patient hidden from search and recent list. Existing claims unaffected. Can be reactivated. |
| PAT-009 | As a physician, I want to export my patient list | Export all active patients as CSV. Includes PHN, name, DOB, gender, phone, address. Downloaded via authenticated link. |
| PAT-010 | As a delegate, I want to manage patients on behalf of my physician | Requires PATIENT_VIEW, PATIENT_CREATE, and/or PATIENT_EDIT permissions (Domain 5). Actions scoped to physician's patient list. Delegate identity in audit trail. |

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | /api/v1/patients | Create a patient. Validates PHN. Requires PATIENT_CREATE. |
| GET | /api/v1/patients/{id} | Get patient details. Requires PATIENT_VIEW. |
| PUT | /api/v1/patients/{id} | Update patient demographics. Requires PATIENT_EDIT. Audit-logged. |
| POST | /api/v1/patients/{id}/deactivate | Soft-deactivate. Requires PATIENT_EDIT. |
| POST | /api/v1/patients/{id}/reactivate | Reactivate. Requires PATIENT_EDIT. |

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/patients/search?phn=&name=&dob= | Search patients by PHN, name, DOB, or combination. Auto-scoped to physician. |
| GET | /api/v1/patients/recent?limit=20 | Get recent patients ordered by last_visit_date DESC. |

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | /api/v1/patients/imports | Upload CSV file. Returns import_id. Requires PATIENT_IMPORT. |
| GET | /api/v1/patients/imports/{id}/preview | Get column mapping preview with first 10 rows. |
| PUT | /api/v1/patients/imports/{id}/mapping | Adjust column mapping before commit. |
| POST | /api/v1/patients/imports/{id}/commit | Commit the import. Processes all rows. |
| GET | /api/v1/patients/imports/{id} | Get import status and results. |

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | /api/v1/patients/merge/preview | Body: {surviving_id, merged_id}. Returns side-by-side comparison and claim transfer count. |
| POST | /api/v1/patients/merge/execute | Body: {surviving_id, merged_id}. Executes the merge. Requires PATIENT_EDIT. |

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | /api/v1/patients/exports | Request patient list export (CSV). Returns export_id. |
| GET | /api/v1/patients/exports/{id} | Check export status and download when ready. |

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/internal/patients/{id}/claim-context | Returns patient identity for claim: PHN, name, DOB, gender. Minimal payload for claim creation. |
| GET | /api/v1/internal/patients/validate-phn/{phn} | Validates PHN format (Luhn) and checks existence in physician's patient list. Used by claim validation pipeline. |

| Action | Details Logged |
| --- | --- |
| PATIENT_CREATED | Patient ID, PHN (masked), creator identity, import_source (MANUAL or CSV_IMPORT). |
| PATIENT_UPDATED | Field-level diff (old vs new). Actor identity. PHN changes logged with both old and new (masked). |
| PATIENT_DEACTIVATED / REACTIVATED | Patient ID, actor identity, timestamp. |
| PATIENT_MERGED | Surviving and merged patient IDs, claims transferred count, field conflicts, actor identity. |
| PATIENT_IMPORT_COMPLETED | Import ID, file hash, row counts (created/updated/skipped/error), actor identity. |
| PATIENT_EXPORT_REQUESTED | Export ID, row count, actor identity. Download logged separately. |
| PATIENT_SEARCHED | Search parameters (not results). PHN searches logged for PHI access audit. Rate-limited to prevent enumeration. |

| # | Question | Context |
| --- | --- | --- |
| 1 | Should Meritum verify patient eligibility with Alberta Health in real-time? | Would catch invalid/expired PHNs before submission. Requires Alberta Health integration (possibly via H-Link). MVP: format validation only. |
| 2 | Should patient records be shareable between physicians in a clinic group? | Current design: strict physician-scoped isolation per HIA. Clinic-level sharing would require explicit consent model and HIA custodian transfer/sharing framework. Deferred to post-MVP. |
| 3 | What is the expected maximum patient list size per physician? | Estimated 500–5,000 for GPs, up to 20,000 for specialists/ED. Need to validate search performance at upper bound. |
| 4 | Should out-of-province PHN formats be validated? | Currently validated only for Alberta (9-digit Luhn). Other provinces have different formats. MVP: accept any 9–12 digit string for out-of-province. |

| Item | Value |
| --- | --- |
| Parent document | Meritum PRD v1.3 |
| Domain | Patient Registry (Domain 6 of 13) |
| Build sequence position | 6th |
| Dependencies | Domain 1 (IAM), Domain 5 (Provider Management) |
| Consumed by | Domain 4.0 (Core), Domain 4.1 (AHCIP), Domain 4.2 (WCB) |
| Version | 1.0 |
| Date | February 2026 |
| Next domain in critical path | Domain 7 (Intelligence Engine) |

