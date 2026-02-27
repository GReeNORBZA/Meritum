# Meritum_Domain_06_Patient_Registry

MERITUM

Functional Requirements

Patient Registry

Domain 6 of 13  |  Critical Path: Position 6

Meritum Health Technologies Inc.

Version 2.0  |  February 2026

CONFIDENTIAL

# Table of Contents

# 1. Domain Overview

## 1.1 Purpose

The Patient Registry is the authoritative source of patient identity within Meritum. It stores the minimal demographic data required for claim creation and submission: PHN, name, date of birth, and gender. Every claim in Domain 4 references a patient record from this registry.

This is intentionally a lightweight domain. Meritum is a billing platform, not a clinical EMR. It stores only the demographics needed for AHCIP and WCB claim submission. Clinical data (diagnoses, encounter notes, treatment plans) lives in the physician's EMR; Meritum references patients by PHN and captures claim-level clinical codes (HSC, diagnostic codes, WCB injury details) on the claim itself, not the patient record.

## 1.2 Scope

Patient demographic records: PHN, name, DOB, gender, contact information

PHN validation: Alberta PHN format (9-digit with Luhn check digit) and out-of-province format detection

Eligibility verification: real-time H-Link eligibility checks with 24-hour cache (Section 7)

Reciprocal billing support: provincial PHN format auto-detection and out-of-province patient identification (Section 8)

Patient search: by PHN, name, DOB, or combination with pg_trgm fuzzy matching

Recent patients: quick-access list per physician for repeat visits

CSV bulk import: batch creation of patient records from EMR exports

WCB-extended demographics: employer details, mailing address (stored on WCB claims, not the patient registry — see Section 3.3)

Patient merge: handling duplicate patient records

Data portability: patient list export (CSV)

Patient access request export: structured export of all health information held for a patient (HIA Section 74 compliance) (Section 9)

Correction audit trail: formal correction of patient records with diff tracking and mandatory correction reason (HIA Section 35 compliance) (Section 10)

## 1.3 Out of Scope

Clinical records, encounter notes, treatment plans (EMR responsibility)

Patient portal or patient-facing features (Meritum is physician-facing only)

PCPCM panel roster management (panel size is tracked in Provider Management; individual panel membership is managed by Alberta Health)

Clinic-level patient sharing between physicians (strict physician-scoped isolation per HIA; deferred to post-MVP)

## 1.4 Domain Dependencies

| Domain | Direction | Interface |
| --- | --- | --- |
| 1 Identity & Access | Consumed | Authentication, RBAC. Patient records scoped to physician (HIA custodian). |
| 2 Reference Data | Consumed | Provincial PHN format definitions (`provincial_phn_formats`) for reciprocal billing province detection. |
| 4.0 Claim Lifecycle Core | Consumed by | Patient lookup during claim creation. PHN, name, DOB, gender used in claims. |
| 4.1 AHCIP Pathway | Consumed by | Patient PHN for H-Link submission file. Eligibility check result consulted pre-submission. |
| 4.2 WCB Pathway | Consumed by | Patient PHN, name, DOB, gender, address for WCB EIR forms. WCB-specific demographics (employer) stored on the claim, not here. |
| 5 Provider Management | Consumed | Physician context determines which patients are accessible (HIA scoping). |
| 9 Notification Service | Consumed | Emits events for patient access export completion and eligibility check results. |

# 2. Data Model

## 2.1 Patients Table (patients)

One row per patient per physician. Patient records are physician-scoped — the same physical patient seen by two different physicians using Meritum exists as two separate records. This preserves HIA custodian isolation: Physician A cannot see that Physician B also treats this patient.

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| patient_id | UUID | No | Primary key |
| provider_id | UUID FK | No | FK to providers. The HIA custodian. Scopes all access. |
| phn | VARCHAR(9) | Yes | Alberta Personal Health Number. 9 digits. Null for patients without Alberta coverage (out-of-province, newborns pending PHN assignment). Unique per physician (partial unique index where phn IS NOT NULL). |
| phn_province | VARCHAR(2) | Yes | Province of PHN issuance. Default: AB. Set for out-of-province reciprocal billing patients. |
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
| notes | TEXT | Yes | Physician's private notes about the patient. Not transmitted in any claim. Encrypted at rest. |
| is_active | BOOLEAN | No | Active patients appear in search. Inactive patients are soft-hidden. Default: true. |
| last_visit_date | DATE | Yes | Date of most recent claim for this patient. Updated when claims are created. Drives 'recent patients' list. |
| created_at | TIMESTAMPTZ | No |  |
| updated_at | TIMESTAMPTZ | No |  |
| created_by | UUID FK | No | Creator (physician or delegate) |

Indexes:

- `patients_provider_phn_unique_idx`: UNIQUE on (provider_id, phn) WHERE phn IS NOT NULL — enforces one PHN per physician while allowing multiple null-PHN patients.
- `patients_provider_name_idx`: B-tree on (provider_id, last_name, first_name) — standard name lookup.
- `patients_provider_dob_idx`: B-tree on (provider_id, date_of_birth) — DOB search.
- `patients_provider_last_visit_idx`: B-tree on (provider_id, last_visit_date) — recent patients sort.
- `patients_provider_is_active_idx`: B-tree on (provider_id, is_active) — active patient filter.
- `patients_name_trgm_idx`: GIN on `(last_name || ' ' || first_name) gin_trgm_ops` — pg_trgm trigram index for fuzzy/prefix name search. Requires: `CREATE EXTENSION IF NOT EXISTS pg_trgm;`

## 2.2 Patient Import Batches Table (patient_import_batches)

Tracks CSV bulk imports of patient records. Separate from the claim import batches in Domain 4.0.

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
| error_details | JSONB | Yes | Per-row error details: array of `{row, field?, message}` |
| status | VARCHAR(20) | No | PENDING, PROCESSING, COMPLETED, FAILED |
| created_at | TIMESTAMPTZ | No |  |
| created_by | UUID FK | No |  |

Indexes:

- `patient_import_batches_physician_created_idx`: B-tree on (physician_id, created_at) — list imports newest-first.
- `patient_import_batches_physician_hash_idx`: B-tree on (physician_id, file_hash) — duplicate upload detection.

## 2.3 Patient Merge History Table (patient_merge_history)

Records when duplicate patient records are merged. The surviving record absorbs all draft/validated claims from the merged record.

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

Indexes:

- `patient_merge_history_physician_merged_at_idx`: B-tree on (physician_id, merged_at).
- `patient_merge_history_surviving_idx`: B-tree on (surviving_patient_id).
- `patient_merge_history_merged_idx`: B-tree on (merged_patient_id).

## 2.4 Eligibility Cache Table (eligibility_cache)

Caches PHN eligibility verification results from H-Link. PHN is stored as a SHA-256 hash (never plaintext outside the verification call) to prevent PHI leakage from the cache table. Each entry has a 24-hour TTL. Physician-scoped via provider_id.

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| cache_id | UUID | No | Primary key |
| provider_id | UUID FK | No | FK to providers. Scopes cache to physician. |
| phn_hash | VARCHAR(64) | No | SHA-256 hash of the PHN (never plaintext). |
| is_eligible | BOOLEAN | No | Whether the PHN was eligible at verification time. |
| eligibility_details | JSONB | Yes | H-Link response metadata: coverage_type, effective_date, expiry_date, override details. |
| verified_at | TIMESTAMPTZ | No | Timestamp of the H-Link verification or override. |
| expires_at | TIMESTAMPTZ | No | Cache expiry (verified_at + 24 hours). |
| created_at | TIMESTAMPTZ | No |  |

Indexes:

- `eligibility_cache_provider_phn_hash_idx`: UNIQUE on (provider_id, phn_hash) — upsert target for cache writes.
- `eligibility_cache_expires_at_idx`: B-tree on (expires_at) — efficient purge of expired entries.

# 3. PHN Validation

## 3.1 Alberta PHN Format

Alberta Personal Health Numbers are 9-digit numeric strings. The 9th digit is a check digit calculated using the Luhn algorithm (modulus 10, double-add-double). Meritum validates:

Length: Exactly 9 digits

Characters: Numeric only (no spaces, dashes, or letters)

Check digit: 9th digit passes Luhn validation against first 8 digits

Uniqueness: No two active patients for the same physician share a PHN

## 3.2 Out-of-Province PHN Validation

For patients with `phn_province` set to a value other than AB, the system applies relaxed validation:

- Accepts 9–12 digit numeric strings (no Luhn check)
- Province-specific format patterns are used for auto-detection (see Section 8) but not for strict validation at this layer
- PHN uniqueness is still enforced within the physician's patient list

## 3.3 PHN-Optional Scenarios

PHN is nullable to support the following scenarios:

Newborns: PHN not yet assigned. Claim can use mother's PHN with newborn indicator (AHCIP-specific).

Out-of-province patients: Use home province health number with phn_province set accordingly. Reciprocal billing.

WCB claims with no PHN: WCB forms support patient_no_phn_flag = Y. Patient demographics (name, DOB) are required even without PHN.

Uninsured patients: Rare but possible. Claim may not be submittable to AHCIP but physician may want to track the encounter.

## 3.4 WCB Demographics Note

WCB claim forms require additional patient demographics beyond what the Patient Registry stores: employer name, employer address, employer phone, worker job title. These fields are claim-specific (the patient may have a different employer for each WCB claim) and are stored on the wcb_claim_details table (Domain 4.2), not on the patient record. The Patient Registry provides the identity baseline (PHN, name, DOB, gender); the WCB claim captures the situational context.

# 4. Patient Search

## 4.1 Search Modes

| Mode | Input | Behaviour |
| --- | --- | --- |
| PHN Lookup | 9-digit PHN | Exact match on (provider_id, phn) WHERE is_active = true. Returns 0 or 1 result. Fastest path. Used when physician has the PHN card. |
| Name Search | First and/or last name | Case-insensitive ILIKE pattern match (`%query%`). Results ranked by pg_trgm similarity score on `last_name || ' ' || first_name`. Minimum 2 characters. Paginated. |
| DOB Search | Date of birth | Exact match on (provider_id, date_of_birth) WHERE is_active = true. Ordered by last_name, first_name. Paginated. |
| Combined | Any combination of PHN, name, DOB | All criteria AND-ed. Most specific search. Paginated. |
| Recent Patients | None (implicit) | Returns the most recently seen patients (by last_visit_date DESC). Only active patients with a non-null last_visit_date. Default limit: 20 (configurable 1–50). |

## 4.2 Search Scoping

All searches are scoped to the authenticated physician (or delegate's active physician context). A search never returns patients belonging to other physicians. This is enforced at the query level (WHERE provider_id = :auth_physician_id) in the repository layer and is the primary HIA custodian isolation mechanism.

## 4.3 Search Performance

Expected patient list size per physician: 500–5,000 for typical GPs, up to 20,000 for high-volume specialists or ED physicians. Name search uses the pg_trgm GIN trigram index (`patients_name_trgm_idx`) for efficient prefix and fuzzy matching with similarity ranking. PHN lookup uses the partial unique index. Recent patients query uses the last_visit_date index with a configurable LIMIT (default 20, maximum 50).

# 5. CSV Bulk Import

Physicians can import their patient list from their EMR or previous billing system via CSV upload. This is typically a one-time onboarding task but can be repeated as the physician's patient panel grows.

## 5.1 Import Workflow

1. Physician uploads a CSV file (maximum 10 MB, `.csv` or `.txt` extension accepted; MIME types: `text/csv`, `text/plain`, `application/csv`, `application/vnd.ms-excel`).

2. System computes SHA-256 hash of the file and rejects duplicate uploads (same physician + same hash).

3. System auto-detects delimiter (comma, tab, pipe) by counting delimiters in the first line; picks the delimiter that produces the most columns (minimum 2).

4. System detects whether the first row is a header by checking if any cell matches a known column alias.

5. System auto-maps columns to patient fields by matching CSV headers against known aliases (see Section 5.2). Physician can confirm or adjust mapping via a PUT endpoint.

6. Preview shows first 10 rows with mapped values and any validation warnings (missing required fields, invalid PHN, unknown gender value).

7. Physician commits the import.

8. System processes each row: validate PHN (Luhn if present), check for existing patient by PHN within physician's roster, create new or update existing. Gender values are normalized using common mappings (Male→M, Female→F, X→X).

9. Results summary: created, updated, skipped, error counts with per-row error details (row number, field, message).

10. Parsed rows are cached in memory during the import session. If the import data expires (e.g. server restart before commit), physician must re-upload the file.

## 5.2 Import Column Mapping

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

## 5.3 Duplicate Handling

During import, existing patients are matched by PHN (within the same physician):

PHN match found: Update existing record with imported values (name, DOB, gender, address, phone). Only non-null import values overwrite. Counts as 'updated'.

PHN match not found: Create new patient record with phn_province defaulted to AB. Counts as 'created'.

No PHN in import row: Always creates a new record (cannot match without PHN). Counts as 'created'. May create duplicates — physician can merge later.

Duplicate PHN in import file: Second occurrence skipped (tracked via in-memory set). Counts as 'skipped'.

Import with invalid PHN (fails Luhn): Row rejected with error detail. Counts as 'error'.

Import with missing required field (first_name, last_name, date_of_birth, or gender): Row rejected with error detail listing missing fields.

# 6. Patient Merge

Duplicate patient records can arise from imports without PHN, manual creation, or data entry errors. The merge function combines two patient records into one.

## 6.1 Merge Workflow

1. Physician identifies two patient records they believe are the same person.

2. System displays both records side-by-side, highlighting differing fields (all demographic fields including phn, phnProvince, firstName, middleName, lastName, dateOfBirth, gender, phone, email, addressLine1, addressLine2, city, province, postalCode, notes).

3. Physician selects the surviving record (the one to keep).

4. System shows the merge preview: how many draft/validated claims will be transferred, which field values differ between the two records.

5. Physician confirms the merge.

6. System executes in a single database transaction: transfers draft/validated claims from the merged record to the surviving record (updates patient_id FK on claims), soft-deletes the merged record (is_active = false).

7. Merge recorded in patient_merge_history with claim transfer count, field conflicts, and actor identity.

## 6.2 Merge Rules

Surviving record's values are kept for all conflicting fields. The merge preview clearly shows which values will be retained.

Claims are transferred by updating the patient_id FK. The claim's content (PHN used in submission, etc.) is not altered — the claim retains the PHN that was on it at submission time.

Merge is irreversible in the UI. However, the merge history table preserves all details for administrative recovery if needed.

Only draft/validated claims have their patient_id updated. Claims already submitted, assessed, or paid retain their original patient_id reference for audit integrity.

Both patients must belong to the same physician and both must be active at the time of merge.

# 7. Eligibility Verification

Real-time eligibility verification catches invalid or expired PHNs before claim submission, reducing rejection rates.

## 7.1 Eligibility Check Flow

1. Physician or system submits a PHN for eligibility check.
2. PHN format is validated locally (Luhn for Alberta).
3. PHN is hashed (SHA-256) and the eligibility cache is checked. If a non-expired entry exists (within 24-hour TTL), the cached result is returned with `source: CACHE`.
4. If no cache hit, the system performs an H-Link eligibility inquiry. The H-Link response includes coverage status, registration status, effective dates, and group number.
5. The result is stored in the eligibility cache (keyed on provider_id + phn_hash) with a 24-hour expiry.
6. Result returned to the physician with eligibility status, source indicator (CACHE, HLINK, or FALLBACK), and verification timestamp.

## 7.2 Eligibility Override

When the system returns an ineligible result but the physician has reason to believe the patient is covered (e.g. recent registration not yet propagated to H-Link), the physician can override the eligibility determination:

- Override requires a mandatory reason text (1–500 characters).
- Override is recorded in the eligibility cache with `status: OVERRIDE`, the override reason, actor identity, and override timestamp.
- Override is audit-logged as `patient.eligibility_overridden` with the masked PHN and reason.

## 7.3 Bulk Eligibility Check

Supports batch eligibility verification for up to 50 PHNs per request. Each PHN is checked individually through the same flow (cache → H-Link → fallback). Returns per-PHN results and a summary (total, eligible, ineligible, errors). Used during Connect Care/EMR import workflows and batch claim preparation.

## 7.4 Fallback Mode

If H-Link is unavailable, the system falls back to format validation only. The result is returned with `source: FALLBACK` and is not cached. The physician is prompted to verify eligibility via Netcare or the Alberta Health IVR line.

## 7.5 Cache Management

Expired eligibility cache entries are purged by a scheduled job (`purgeExpiredEligibilityCache`). The cache table stores only the SHA-256 hash of the PHN — never plaintext — to prevent PHI leakage if the cache is compromised. Cache entries are physician-scoped via provider_id.

# 8. Reciprocal Billing / Out-of-Province Patient Support

Alberta physicians can bill AHCIP for services provided to patients from other Canadian provinces and territories under interprovincial reciprocal billing agreements.

## 8.1 Provincial PHN Format Detection

Meritum auto-detects a patient's home province based on the format of their health number. Province-specific format definitions are maintained in the `province-detection.utils` module:

| Province | Code | Length | Format | Definitive |
| --- | --- | --- | --- | --- |
| Alberta | AB | 9 | 9-digit numeric | No (shared with SK, MB, NB, YT, NU) |
| British Columbia | BC | 10 | 10-digit numeric | Yes |
| Saskatchewan | SK | 9 | 9-digit numeric | No |
| Manitoba | MB | 9 | 9-digit numeric | No |
| Ontario | ON | 10 | ####-###-### or 10-digit numeric | Yes |
| Quebec | QC | 12 | 4 alpha + 8 numeric | Yes |
| New Brunswick | NB | 9 | 9-digit numeric | No |
| Nova Scotia | NS | 10 | 10-digit numeric | Yes |
| Prince Edward Island | PE | 8 | 8-digit numeric | Yes |
| Newfoundland & Labrador | NL | 12 | 12-digit numeric | Yes |
| Yukon | YT | 9 | 9-digit numeric | No |
| Northwest Territories | NT | 8 | 1 alpha + 7 numeric | Yes |
| Nunavut | NU | 9 | 9-digit numeric | No |

When the format is shared by multiple provinces (e.g. 9-digit numeric), the result includes all candidate provinces with `isDefinitive: false`. The physician can manually set the province.

## 8.2 Billing Mode Determination

Based on the detected province, the system determines the billing mode:

- **AB (Alberta):** `STANDARD` — normal AHCIP billing.
- **QC (Quebec):** `PRIVATE` — Quebec does not participate in interprovincial reciprocal billing. Patient billed privately.
- **Other provinces (definitive detection):** `RECIPROCAL` — reciprocal billing through AHCIP. `reciprocal_eligible: true`.
- **Ambiguous / Unknown:** `UNKNOWN` — physician must manually set the province.

## 8.3 Province Storage

Out-of-province patients have `phn_province` set to their home province's 2-character code (e.g. BC, ON, SK). This value is referenced during claim creation to route through the appropriate reciprocal billing pathway in Domain 4.1.

## 8.4 Province Detection API

The `POST /api/v1/patients/province/detect` endpoint accepts a health number and returns the detected province, confidence level (HIGH, LOW, NONE), billing mode, and reciprocal eligibility flag. This is called during patient creation to auto-populate the `phn_province` field for out-of-province patients.

# 9. Patient Access Request Export (HIA Section 74)

Under the Health Information Act (Alberta), Section 74, individuals have the right to request access to their health information held by a custodian. Meritum implements this as a structured export of all health information associated with a patient.

## 9.1 Access Request Workflow

1. Physician initiates a patient access request export via `POST /api/v1/patients/{id}/export`. Requires `DATA_EXPORT` permission.

2. System retrieves all health information for the patient from the following tables, scoped to the authenticated physician:
   - **Demographics:** Full patient record from the `patients` table (including inactive patients).
   - **Claims:** All claims in all states (draft, validated, submitted, assessed, paid, rejected) from the `claims` table, ordered by date of service.
   - **AHCIP Details:** AHCIP claim detail rows linked to the patient's claims, from `ahcip_claim_details` joined through `claims`.
   - **WCB Details:** WCB claim detail rows linked to the patient's claims, from `wcb_claim_details` joined through `claims`.
   - **Audit Entries:** All audit log entries with `resource_type = 'patient'` and matching `resource_id`, ordered by created_at.

3. Each entity type is formatted as a CSV file.

4. The CSV files are bundled into a ZIP archive (store method, no compression).

5. The ZIP archive is stored with a time-limited download URL (24-hour expiry).

6. The export ID and download URL are returned to the physician.

## 9.2 Download

The download endpoint (`GET /api/v1/patients/{id}/export/{exportId}/download`) serves the ZIP archive as `application/zip` with a Content-Disposition header for the filename (`patient_{patientId}_export.zip`). The download requires authentication and is physician-scoped — a different physician cannot access the download URL.

## 9.3 Security Controls

- The access export query enforces physician tenant isolation on every sub-query (demographics, claims, AHCIP details, WCB details).
- Audit entries are retrieved by resource_id only (no physician scope on audit_log), but the export is only initiated by the owning physician.
- The export ZIP is stored in memory with a 24-hour expiry. Expired exports are automatically deleted on next access.
- The audit log records the access request with only patient_id and provider_id — no PHI in the audit entry.
- The `PATIENT_ACCESS_EXPORT_READY` event is emitted for notification delivery.

## 9.4 Regulatory Reference

HIA Section 74: "An individual has the right of access to any record containing health information about the individual that is in the custody or under the control of a custodian." Meritum's implementation fulfills this requirement by providing the physician (custodian) with a structured, complete export of all health information held for a specific patient.

# 10. Correction Audit Trail (HIA Section 35)

Under the Health Information Act (Alberta), custodians must maintain a record of corrections to health information. Meritum implements a formal correction mechanism distinct from standard updates, ensuring corrections are tracked with a mandatory reason and field-level diff.

## 10.1 Correction vs. Standard Update

Standard patient updates (`PUT /api/v1/patients/{id}`) are routine demographic changes (e.g. address change, phone number update). They are audit-logged with field-level diffs but do not require a correction reason.

Formal corrections (`PATCH /api/v1/patients/{id}/correct`) are used when the physician identifies an error in a patient's health information. The correction endpoint requires:

- A mandatory `correction_reason` field (1–2,000 characters) explaining why the correction is being made.
- At least one field to correct (enforced by Zod schema refinement).
- The same PHN validation and uniqueness checks as standard updates.

## 10.2 Correction Audit Record

Each formal correction produces a structured audit log entry with action `patient.correction_applied` containing:

- `correction_reason`: The physician's stated reason for the correction.
- `changes`: An array of `{field, old_value, new_value}` entries for each changed field.
- PHN values in the changes array are masked (first 3 digits visible, remainder asterisks).
- Notes field changes are excluded from the audit detail to prevent clinical observations from appearing in audit exports.

The correction audit record is append-only. The audit log has no PUT or DELETE endpoints — corrections are permanent additions to the audit trail.

## 10.3 Regulatory Reference

HIA Section 35: Custodians must maintain a record of any correction to health information. The correction audit trail satisfies this by recording the reason, the specific fields changed, old and new values, the identity of the person making the correction, and the timestamp.

# 11. User Stories & Acceptance Criteria

| ID | Story | Acceptance Criteria |
| --- | --- | --- |
| PAT-001 | As a physician, I want to add a new patient so I can create claims for them | Enter PHN (optional), first/last name, DOB, gender. PHN validated (Luhn check for AB, 9–12 digit for out-of-province). PHN uniqueness enforced within my patients. Patient created and immediately available for claim creation. |
| PAT-002 | As a physician, I want to search for an existing patient by PHN | Enter 9-digit PHN. Exact match returned instantly via unique index. If no match, option to create new patient with that PHN pre-filled. |
| PAT-003 | As a physician, I want to search for a patient by name | Type 2+ characters. Results ranked by pg_trgm similarity. Case-insensitive. Paginated. |
| PAT-004 | As a physician, I want to see my recent patients for quick access | Patient selection defaults to recent patients view. Shows up to 20 most recently seen (configurable 1–50). Each entry shows name, PHN, DOB, last visit date. |
| PAT-005 | As a physician, I want to import my patient list from a CSV file | Upload CSV (max 10 MB). Preview column mapping. Confirm import. See results: created, updated, skipped, errors. Per-row error details for failed rows. Duplicate file (same SHA-256 hash) rejected with conflict error. |
| PAT-006 | As a physician, I want to edit a patient's demographics | Edit any field. PHN change triggers re-validation (Luhn for AB, format check for out-of-province) and uniqueness check. Changes audit-logged with field-level diff. Existing submitted claims not affected. |
| PAT-007 | As a physician, I want to merge two duplicate patient records | Select two patients. Side-by-side comparison showing all differing fields. Select surviving record. Preview draft/validated claim transfer count. Confirm merge. Claims transferred. Merged record soft-deleted. Merge history recorded. |
| PAT-008 | As a physician, I want to deactivate a patient I no longer see | Deactivate action. Patient hidden from search and recent list. Existing claims unaffected. Can be reactivated. Already-deactivated patient returns validation error. |
| PAT-009 | As a physician, I want to export my patient list | Export all active patients as CSV. Includes PHN, name, DOB, gender, phone, address. Notes excluded. Downloaded via authenticated, time-limited (1-hour) link. Row count audit-logged. |
| PAT-010 | As a delegate, I want to manage patients on behalf of my physician | Requires PATIENT_VIEW, PATIENT_CREATE, and/or PATIENT_EDIT permissions (Domain 5). Actions scoped to physician's patient list. Delegate identity in audit trail. |
| PAT-011 | As a physician, I want to check a patient's eligibility before creating a claim | Enter PHN. System checks cache (24h) then H-Link. Returns eligible/ineligible with details. Can override with reason if system says ineligible. Audit-logged. |
| PAT-012 | As a physician, I want to check eligibility for multiple patients at once | Submit up to 50 PHNs. Each checked individually (cache → H-Link → fallback). Summary returned: total, eligible, ineligible, errors. |
| PAT-013 | As a physician, I want the system to detect when a patient is from out-of-province | Enter health number during patient creation. System auto-detects province and billing mode. Quebec flagged as private billing. Other provinces flagged as reciprocal. Ambiguous formats prompt manual selection. |
| PAT-014 | As a physician, I want to export all health information for a patient (access request) | Initiate access request. System collects demographics, claims, AHCIP details, WCB details, audit entries. Bundled as ZIP of CSVs. Download via authenticated, time-limited (24-hour) link. Audit-logged with no PHI. |
| PAT-015 | As a physician, I want to formally correct a patient's record with a reason | Submit correction with mandatory reason. System validates changed fields, records field-level diff in audit trail with correction reason. PHN changes re-validated. Distinct from routine updates. |

# 12. API Contracts

All endpoints require authentication and are scoped to the physician (or delegate's active physician context). Delegate permissions from Domain 5 enforced by Domain 1 RBAC middleware.

## 12.1 Patient CRUD

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | /api/v1/patients | Create a patient. Validates PHN (Luhn for AB, 9–12 digit for out-of-province). Requires PATIENT_CREATE. Returns 201. |
| GET | /api/v1/patients/{id} | Get patient details. Requires PATIENT_VIEW. Returns 200. Audit-logged. |
| PUT | /api/v1/patients/{id} | Update patient demographics. Requires PATIENT_EDIT. Returns 200. Audit-logged with field-level diff. PHN masked in diff. |
| PATCH | /api/v1/patients/{id}/correct | Formal correction (HIA S35). Body includes `correction_reason` + fields to correct. Requires PATIENT_EDIT. Returns 200. Audit-logged as `patient.correction_applied`. |
| POST | /api/v1/patients/{id}/deactivate | Soft-deactivate. Requires PATIENT_EDIT. Returns 200. |
| POST | /api/v1/patients/{id}/reactivate | Reactivate. Requires PATIENT_EDIT. Returns 200. |

## 12.2 Patient Search

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/patients/search?phn=&name=&dob=&page=&page_size= | Search patients by PHN, name, DOB, or combination. Auto-scoped to physician. Returns paginated results. Requires PATIENT_VIEW. Audit-logged (search parameters only, not results). |
| GET | /api/v1/patients/recent?limit=20 | Get recent patients ordered by last_visit_date DESC. Limit 1–50, default 20. Requires PATIENT_VIEW. Audit-logged. |

## 12.3 CSV Import

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | /api/v1/patients/imports | Upload CSV file (multipart, max 10 MB). Returns import_id. Requires PATIENT_IMPORT. Returns 201. |
| GET | /api/v1/patients/imports/{id}/preview | Get column mapping preview with first 10 rows and validation warnings. Requires PATIENT_IMPORT. Audit-logged. |
| PUT | /api/v1/patients/imports/{id}/mapping | Adjust column mapping before commit. Body: `{mapping: {field: headerName}}`. Requires PATIENT_IMPORT. |
| POST | /api/v1/patients/imports/{id}/commit | Commit the import. Processes all rows. Returns result counts. Requires PATIENT_IMPORT. |
| GET | /api/v1/patients/imports/{id} | Get import status and result counts. Requires PATIENT_IMPORT. Audit-logged. |

## 12.4 Patient Merge

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | /api/v1/patients/merge/preview | Body: `{surviving_id, merged_id}`. Returns side-by-side comparison, field conflicts, and draft/validated claim transfer count. Requires PATIENT_EDIT. |
| POST | /api/v1/patients/merge/execute | Body: `{surviving_id, merged_id}`. Executes the merge in a transaction. Requires PATIENT_EDIT. Returns merge_id and transfer count. |

## 12.5 Patient Export (Data Portability)

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | /api/v1/patients/exports | Request patient list export (CSV of all active patients). Returns export_id and row count. Requires PATIENT_VIEW + REPORT_EXPORT. Returns 201. |
| GET | /api/v1/patients/exports/{id} | Check export status and get download URL when ready. 1-hour expiry. Requires PATIENT_VIEW + REPORT_EXPORT. Audit-logged. |

## 12.6 Patient Access Request Export (HIA S74)

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | /api/v1/patients/{id}/export | Initiate patient health information access export. Returns export_id, download URL, expiry. Requires DATA_EXPORT. Returns 201. Audit-logged. |
| GET | /api/v1/patients/{id}/export/{exportId}/download | Download the ZIP archive of patient health information. Requires DATA_EXPORT. Returns application/zip. Physician-scoped (404 for other physicians). |

## 12.7 Eligibility Verification

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | /api/v1/patients/eligibility/check | Check PHN eligibility. Body: `{phn, date_of_service?}`. PHN must be 9-digit numeric. Returns eligibility status, source (CACHE/HLINK/FALLBACK), details, and verified_at. Requires PATIENT_VIEW. Audit-logged. |
| POST | /api/v1/patients/eligibility/override | Override eligibility for a PHN. Body: `{phn, reason}`. Reason 1–500 chars. Requires PATIENT_EDIT. Audit-logged. |
| POST | /api/v1/patients/eligibility/bulk-check | Bulk eligibility check. Body: `{entries: [{phn, date_of_service?}]}`. Max 50 entries. Returns per-PHN results and summary. Requires PATIENT_VIEW. Audit-logged. |

## 12.8 Province Detection

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | /api/v1/patients/province/detect | Detect province from health number format. Body: `{health_number}`. Returns detected_province, confidence (HIGH/LOW/NONE), is_out_of_province, billing_mode (STANDARD/RECIPROCAL/PRIVATE/UNKNOWN), reciprocal_eligible. Requires PATIENT_VIEW. Audit-logged. |

## 12.9 Internal Patient API

Consumed by Domain 4 (Claim Lifecycle) during claim creation and validation. Authenticated via internal API key (`X-Internal-API-Key` header with timing-safe comparison).

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/internal/patients/{id}/claim-context?physician_id= | Returns minimal patient identity for claim creation: patient_id, phn, phn_province, first_name, last_name, date_of_birth, gender. Only active patients. Requires physician_id query parameter. |
| GET | /api/v1/internal/patients/validate-phn/{phn}?physician_id= | Validates PHN format (Luhn for AB) and checks existence in physician's active patient list. Returns {valid, formatOk, exists, patientId?}. |

# 13. Security & Audit

## 13.1 Data Protection

Patient records are PHI. Encrypted at rest (AES-256 via DigitalOcean Managed DB) and in transit (TLS 1.3).

HIA custodian isolation: all queries scoped to provider_id in the repository layer. No cross-physician patient access under any circumstance.

Admin access to patient records requires explicit physician-granted PHI access permission (time-limited, logged) per Domain 1 IAM admin access rules.

Patient notes field may contain sensitive clinical observations. Encrypted at rest. Never transmitted in claims. Excluded from correction audit diffs and export CSV.

CSV import files processed in memory. File content is consumed from the multipart stream, not written to disk. Parsed rows are cached in a server-side Map keyed by import_id and cleared after commit or on batch failure.

Patient export files (CSV) and patient access export files (ZIP) are generated on Meritum infrastructure and delivered via authenticated, time-limited download links. Not emailed. No PHI in email bodies — only links.

Eligibility cache stores PHN as SHA-256 hash, never plaintext. Cache entries are physician-scoped and expire after 24 hours.

## 13.2 Audit Trail

| Action | Details Logged |
| --- | --- |
| patient.created | Patient ID, PHN (masked), creator identity, source (MANUAL or CSV_IMPORT). |
| patient.updated | Field-level diff (old vs new). Actor identity. PHN changes logged with both old and new (masked). Notes excluded from diff. |
| patient.correction_applied | Correction reason. Array of {field, old_value, new_value} changes. PHN masked in changes. Notes excluded. Actor identity. |
| patient.deactivated | Patient ID, PHN (masked), name, actor identity, timestamp. |
| patient.reactivated | Patient ID, PHN (masked), name, actor identity, timestamp. |
| patient.merged | Surviving and merged patient IDs, claims transferred count, field conflicts (PHN masked), actor identity. |
| patient.import_completed | Import ID, file name, total rows, created/updated/skipped/error counts, actor identity. |
| patient.export_requested | Export ID, row count, actor identity. |
| patient.export_downloaded | Export ID, row count. First-access only. |
| patient.searched | Search parameters (not results). PHN masked in search params. Result count. Mode (PHN_LOOKUP, NAME_SEARCH, DOB_SEARCH, COMBINED). |
| export.patient_access_requested | Export ID, provider ID. No PHI in audit entry. |
| patient.eligibility_checked | PHN (masked), source (CACHE/HLINK/FALLBACK), date of service. |
| patient.eligibility_overridden | PHN (masked), override reason, actor identity. |
| patient.province_detected | Detected province, confidence, billing mode, is_out_of_province. No PHN in audit entry. |

## 13.3 PHN Masking

PHN is displayed masked in audit logs, error responses, and administrative views: first 3 digits shown, remaining 6 replaced with asterisks (e.g., 123******). Full PHN visible only to the physician/delegate in the clinical context. This prevents PHN exposure in audit log exports or admin dashboards. The `maskPhn()` utility is used consistently across all audit log writes.

# 14. Testing Requirements

## 14.1 PHN Validation Tests

Valid 9-digit PHN with correct Luhn check digit → accepted

Invalid check digit → rejected with descriptive error

8-digit or 10-digit PHN → rejected (length check for AB)

Non-numeric characters → rejected

Duplicate PHN for same physician → rejected (409 Conflict)

Same PHN for different physicians → accepted (HIA isolation)

Null PHN → accepted (WCB/newborn scenarios)

Out-of-province PHN (9–12 digit numeric) with phn_province ≠ AB → accepted without Luhn check

## 14.2 Search Tests

PHN exact match returns single result

Name ILIKE search returns results ranked by pg_trgm similarity (case-insensitive)

DOB search returns all patients with matching DOB

Combined search (name + DOB) narrows results

Search returns only patients for the authenticated physician

Recent patients ordered by last_visit_date DESC, limited to requested limit (default 20)

Deactivated patients excluded from search results

## 14.3 Import Tests

CSV with comma delimiter, header row, all fields populated → all created

Tab-delimited file → delimiter auto-detected, parsed correctly

File with no header row (no matching aliases) → synthetic headers assigned, rows processed

Import with existing PHN match → existing records updated (non-null values overwrite)

Import with duplicate PHN in file → second occurrence skipped

Import with invalid PHN (failed Luhn) → row rejected, others proceed

Import with missing required field (first_name, last_name, date_of_birth, gender) → row rejected with field list

Duplicate file upload (same SHA-256 hash) → rejected with ConflictError

Gender normalization: Male→M, Female→F, X→X

Large import (5,000 rows) → completes within acceptable time, correct counts

## 14.4 Merge Tests

Merge two patients with draft/validated claims → claims transferred to surviving record

Merge preview shows correct draft/validated claim count and field conflicts

Merged patient soft-deleted, no longer appears in search

Merge history recorded with full details (merge_id, claim count, field conflicts, actor)

Submitted/assessed/paid claims retain original patient_id for audit integrity

Both patients must be active — merging an inactive patient returns NotFoundError

Both patients must belong to same physician — merging another physician's patient returns NotFoundError

## 14.5 Eligibility Tests

Valid PHN → eligibility check succeeds, result cached, audit logged

Cache hit within 24h → returns cached result with source CACHE

Cache expired → re-queries H-Link, updates cache

Invalid PHN format → returns ValidationError before cache/H-Link check

Override eligibility → cache updated with OVERRIDE status, reason logged

Bulk check with 50 PHNs → all processed, summary returned

Bulk check with >50 PHNs → ValidationError

PHN hash stored in cache, not plaintext → verified

## 14.6 Province Detection Tests

BC 10-digit → detected as BC, definitive, billing mode RECIPROCAL

QC 4-alpha+8-numeric → detected as QC, definitive, billing mode PRIVATE

AB 9-digit → ambiguous (multiple candidates), not definitive

ON ####-###-### format → detected as ON, definitive, billing mode RECIPROCAL

Unknown format → province null, confidence NONE, billing mode UNKNOWN

## 14.7 Patient Access Export Tests

Access export for patient with claims → ZIP contains demographics.csv, claims.csv, ahcip_details.csv, wcb_details.csv, audit_entries.csv

Access export for patient without claims → ZIP contains demographics.csv only

Download URL requires authentication → unauthenticated returns 401

Download URL physician-scoped → other physician returns 404

Download URL expires after 24 hours → returns 404 after expiry

Audit log records export request with no PHI

## 14.8 Correction Tests

Correction with reason and changed field → patient updated, audit log contains correction_reason and field diff

Correction with PHN change → PHN re-validated (Luhn for AB), uniqueness checked

Correction without any changed fields → returns existing patient unchanged

Correction without correction_reason → rejected by Zod schema

PHN masked in correction audit diff

Notes excluded from correction audit diff

## 14.9 Integration Tests

Create patient → create AHCIP claim referencing patient → PHN appears in H-Link file

Create patient without PHN → create WCB claim with no_phn_flag → submission succeeds

Import patients → create claims for imported patients → batch submission

Delegate creates patient on behalf of physician → patient scoped to physician

Merge patient with claims in various states → draft/validated claims transferred, submitted claims unchanged

Check eligibility → create claim → eligibility result available for pre-submission check

Out-of-province patient with phn_province = BC → claim routes through reciprocal billing pathway

# 15. Open Questions

| # | Question | Context | Resolution |
| --- | --- | --- | --- |
| 1 | ~~Should Meritum verify patient eligibility with Alberta Health in real-time?~~ | ~~Would catch invalid/expired PHNs before submission.~~ | Resolved: Yes. Implemented via H-Link eligibility inquiry with 24h cache. See Section 7. |
| 2 | Should patient records be shareable between physicians in a clinic group? | Current design: strict physician-scoped isolation per HIA. Clinic-level sharing would require explicit consent model and HIA custodian transfer/sharing framework. | Deferred to post-MVP. |
| 3 | ~~What is the expected maximum patient list size per physician?~~ | ~~Estimated 500–5,000 for GPs, up to 20,000 for specialists/ED.~~ | Resolved: 500–5,000 GPs, up to 20,000 specialists/ED. pg_trgm GIN index handles upper bound. |
| 4 | ~~Should out-of-province PHN formats be validated?~~ | ~~Currently validated only for Alberta (9-digit Luhn). Other provinces have different formats.~~ | Resolved: Province format auto-detection implemented. AB validated with Luhn; out-of-province accepts 9–12 digit numeric. See Section 8. |

# 16. Document Control

This document specifies the Patient Registry domain. It provides the patient identity baseline consumed by the Claim Lifecycle (Domain 4) for both AHCIP and WCB submission pathways.

| Item | Value |
| --- | --- |
| Parent document | Meritum PRD v1.3 |
| Domain | Patient Registry (Domain 6 of 13) |
| Build sequence position | 6th |
| Dependencies | Domain 1 (IAM), Domain 2 (Reference Data), Domain 5 (Provider Management) |
| Consumed by | Domain 4.0 (Core), Domain 4.1 (AHCIP), Domain 4.2 (WCB) |
| Version | 2.0 |
| Date | February 2026 |
| Next domain in critical path | Domain 7 (Intelligence Engine) |

| Version | Date | Changes |
| --- | --- | --- |
| 1.0 | February 2026 | Initial release: patient CRUD, search, CSV import, merge, export, PHN validation. |
| 2.0 | February 2026 | Added: eligibility verification (Section 7), reciprocal billing / out-of-province support (Section 8), patient access request export per HIA S74 (Section 9), correction audit trail per HIA S35 (Section 10). Updated data model with eligibility_cache table. Updated API contracts with eligibility, province detection, access export, and correction endpoints. Resolved open questions 1, 3, 4. Added user stories PAT-011 through PAT-015. |
