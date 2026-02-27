# [MERITUM] Functional Requirements — Connect Care / SCC Integration

**Document ID:** MHT-FRD-CC-001
**Cross-Cutting Feature** | Version 1.0 | 25 February 2026
**Parent Documents:** MHT-FUNC-CC-001, MHT-GAP-MVP-001 (Part A)
**Classification:** Internal / Confidential

---

## 1. Domain Overview

### 1.1 Purpose

This FRD specifies the integration between Meritum and AHS Connect Care via the Service Code Capture (SCC) extract. Connect Care is Alberta Health Services' province-wide clinical information system (Epic Hyperspace). SCC is the billing module within Connect Care that captures SOMB service codes, modifiers, diagnostic codes, and patient demographics during clinical documentation.

AHS provides two mechanisms for billing software vendors to receive SCC data:

1. **Manual CSV export** — the physician exports "My Billing Codes" (AHCIP) and/or "My WCB Codes" from Connect Care and uploads to Meritum. **This is the MVP integration path.**
2. **Automated sFTP data push** — AHS sends nightly extract files to accredited vendors. **This is Phase 2 (post-MVP).**

Both paths share a common parser, validation engine, and claim creation pipeline. This FRD covers both, with Phase 2 components clearly marked.

### 1.2 Scope

- SCC extract parser for "My Billing Codes" (AHCIP, 21 fields) and "My WCB Codes" (WCB, 13 fields) — **addresses gap A1**
- Connect Care CSV import workflow (upload, parse, validate, confirm, create claims) — **addresses gap A2**
- ICD-10-CA to ICD-9 crosswalk table, lookup API, and resolution UI flow — **addresses gap A3**
- Row-level duplicate detection using composite key matching — **addresses gap A4**
- Correction and deletion handling for SCC Charge Status field — **addresses gap A5**
- Claim data model extensions for Connect Care metadata — **addresses gap A6**
- sFTP integration infrastructure and automated pipeline (Phase 2) — **addresses gap A7**

### 1.3 Out of Scope

- Generic EMR import pipeline (existing `/api/v1/imports` — unmodified)
- Connect Care clinical documentation workflow (physician-side Epic interaction)
- AHS vendor accreditation process management (operational, not software)
- H-Link submission pipeline (Domain 4.1 — SCC import feeds into it)
- WCB form generation from SCC data (Domain 4.2 — receives routed claims)
- Mobile companion reconciliation (Domain 10 v2 — MHT-FRD-MOB-002)

### 1.4 Domain Dependencies

| Domain | Direction | Interface |
|--------|-----------|-----------|
| Domain 2: Reference Data | Consumed | SOMB codes for validation, ICD-9 codes for crosswalk, ICD-10-CA crosswalk table |
| Domain 4.0: Claim Lifecycle Core | Produces → | Draft claims created in DRAFT state via claim creation service |
| Domain 4.1: AHCIP Pathway | Produces → | AHCIP claims routed to H-Link submission pipeline |
| Domain 4.2: WCB Pathway | Produces → | WCB claims routed to WCB form/submission pipeline |
| Domain 5: Provider Management | Consumed | Provider context (billing number, BA number) for identity validation |
| Domain 6: Patient Registry | Consumed / Produces | PHN lookup for patient matching; new patient records created on import |
| Domain 7: Intelligence Engine | Produces → | Import-sourced claims evaluated by Tier 1 rules post-creation |
| Domain 9: Notification Service | Produces → | Import completion events, sFTP delivery alerts (Phase 2) |
| Domain 10: Mobile Companion v2 | Produces → | Shift encounter data consumed during reconciliation |

---

## 2. SCC Extract Specification

The AHS Physician Service Code Extract Specification (December 2025 revision) defines the field layout for both extract types. Meritum must parse and store **all** fields, including those not directly used for claim submission, to maintain data fidelity and support future analytics.

### 2.1 My Billing Codes Extract (AHCIP) — 21 Fields

| # | Field Name | Type | Required | Description |
|---|-----------|------|----------|-------------|
| 1 | Encounter Date | DATE | Yes | Date of service. Maps to claim `date_of_service`. |
| 2 | Patient ULI | VARCHAR(12) | Yes | Alberta PHN (9-digit) or out-of-province health number. Maps to patient identifier. |
| 3 | Patient Name | VARCHAR(200) | Yes | Full name as registered in Connect Care. Display/verification only; not submitted on H-Link. |
| 4 | Patient DOB | DATE | Yes | Date of birth. Required for age-based billing rules. |
| 5 | Patient Gender | VARCHAR(1) | Yes | Gender code per AHCIP spec. Required for sex-specific service code validation. |
| 6 | Patient Insurer | VARCHAR(50) | Yes | Payer identifier (e.g. "ALBERTA HEALTH", "BLUE CROSS", out-of-province). Determines claim routing. |
| 7 | Coverage Status | VARCHAR(20) | No | Whether patient has valid in-province coverage. Used for eligibility validation. |
| 8 | Service Code (SOMB) | VARCHAR(10) | Yes | Schedule of Medical Benefits service code. Primary billing code. |
| 9 | Service Code Description | VARCHAR(200) | No | Textual description of SOMB code. Display only. |
| 10 | Modifier(s) | VARCHAR(50) | No | SOMB modifiers (e.g. CALL, COMP, AGE). Multiple values comma or pipe-delimited. |
| 11 | Diagnostic Code (ICD-9) | VARCHAR(10) | No | ICD-9 code as translated by Connect Care's ICD-10-to-ICD-9 engine. |
| 12 | ICD-10-CA Source Code | VARCHAR(10) | No | Original ICD-10-CA code documented by physician. Preserved for audit trail. |
| 13 | ICD Conversion Flag | BOOLEAN | No | True when ICD-10→ICD-9 translation failed or is uncertain. Physician must manually confirm ICD-9 code. |
| 14 | Referring Provider ID | VARCHAR(10) | No | Alberta Health Practitioner ID of referring physician. Required for specialist consultations. |
| 15 | Referring Provider Name | VARCHAR(200) | No | Name of referring provider. Display/verification only. |
| 16 | Billing Provider ID | VARCHAR(10) | Yes | Alberta Health Practitioner ID of billing physician. Must match authenticated provider. |
| 17 | Business Arrangement Number | VARCHAR(20) | Yes | BA Number for claim submission. Must match provider profile. |
| 18 | Facility Code | VARCHAR(20) | No | AHS facility identifier where service was rendered. |
| 19 | Functional Centre | VARCHAR(20) | No | AHS functional centre code. Relevant for hospital-based billing and ARP reconciliation. |
| 20 | Encounter Type | VARCHAR(20) | No | Type of encounter (inpatient, outpatient, emergency). |
| 21 | Charge Status | VARCHAR(20) | Yes | ACTIVE, MODIFIED, or DELETED. Deleted rows represent corrections to previously exported data. |
| — | Export Timestamp | TIMESTAMPTZ | Yes | Date/time the extract was generated. File-level metadata. |

### 2.2 My WCB Codes Extract — 13 Fields

| # | Field Name | Type | Required | Description |
|---|-----------|------|----------|-------------|
| 1 | WCB Claim Number | VARCHAR(20) | Yes | WCB Alberta claim number assigned to the injured worker. |
| 2 | Employer Name | VARCHAR(200) | No | Injured worker's employer as documented. |
| 3 | Injury Date | DATE | Yes | Date of workplace injury. Required for timing tier calculation. |
| 4 | Date of Service | DATE | Yes | Date physician provided the service. |
| 5 | Patient ULI | VARCHAR(12) | Yes | Patient's PHN. |
| 6 | Patient Name | VARCHAR(200) | Yes | Patient demographics. |
| 7 | Patient DOB | DATE | Yes | Date of birth. |
| 8 | Patient Gender | VARCHAR(1) | Yes | Gender code. |
| 9 | Service Code (SOMB) | VARCHAR(10) | Yes | Service code under WCB fee schedule rules (unbundled, payable at 100%). |
| 10 | Diagnostic Code (ICD-9) | VARCHAR(10) | No | ICD-9 code with same conversion handling as billing codes extract. |
| 11 | Billing Provider ID / BA Number | VARCHAR(20) | Yes | Provider identification fields. |
| 12 | Facility Code | VARCHAR(20) | No | AHS facility identifier. |
| 13 | Charge Status | VARCHAR(20) | Yes | ACTIVE, MODIFIED, or DELETED. |
| — | WCB-Specific Clinical Fields | JSONB | No | Nature of injury, body part, treatment type. Presence depends on physician documentation completeness. |
| — | Export Timestamp | TIMESTAMPTZ | Yes | Date/time of extract generation. File-level metadata. |

---

## 3. SCC Extract Parser

**Addresses gap A1.**

### 3.1 Architecture

The SCC parser is a standalone, stateless service module within the claims domain. It accepts raw extract data and returns a structured, validated result. It is shared between the CSV import workflow (Section 4) and the sFTP pipeline (Section 9).

**Implementation location:** `apps/api/src/domains/claims/scc-parser.service.ts`

**Key design constraints:**

- **Input agnostic:** accepts a CSV string, file stream, or buffer. Does not care whether data originated from user upload or sFTP file drop.
- **Stateless:** all validation is performed against file data and provider profile. No external API calls during parsing.
- **Versioned:** tracks which version of the AHS extract specification is implemented. Supports multiple specification versions simultaneously during transitions.

### 3.2 Parser Behaviour

```
Input (CSV string / Buffer)
  │
  ├─ 1. Delimiter detection (comma, tab, pipe)
  ├─ 2. Header row detection and extract type classification
  │     ├─ WCB-specific columns present → "My WCB Codes"
  │     └─ No WCB columns → "My Billing Codes"
  ├─ 3. Provider identity validation
  │     ├─ Extract Billing Provider ID == ctx.providerBillingNumber? → continue
  │     └─ Mismatch → REJECT entire file with PROVIDER_MISMATCH error
  ├─ 4. Row-by-row parsing and validation
  │     ├─ Map CSV columns to SCC field schema (Zod)
  │     ├─ Classify each row: VALID / WARNING / ERROR / INFORMATIONAL
  │     └─ Accumulate results
  └─ 5. Return ParseResult
```

### 3.3 Extract Type Auto-Detection

The parser identifies the extract type by inspecting column headers after the first row:

| Signal | Extract Type |
|--------|-------------|
| Headers contain `WCB Claim Number`, `Employer Name`, `Injury Date` | My WCB Codes |
| Headers do not contain WCB-specific columns | My Billing Codes |
| Both column sets present in a single file | Split into two streams; process independently |

### 3.4 Provider Identity Validation

Before processing any rows, the parser validates that the `Billing Provider ID` and `Business Arrangement Number` in the extract match the authenticated provider's profile (from `ProviderContext`).

- If `Billing Provider ID` does not match `ctx.providerBillingNumber` → reject entire file with error: `"The billing provider in this file (ID: {extractId}) does not match your profile (ID: {profileId}). This file may belong to another provider."`
- If `Business Arrangement Number` does not match any BA in `ctx.businessArrangements` → reject with error: `"Business Arrangement {baNumber} in this file is not registered on your profile."`

### 3.5 Field Parsing Rules

Each row is parsed against the Zod schema for the detected extract type:

**AHCIP Row Schema** (`packages/shared/src/schemas/scc-extract.schema.ts`):

```typescript
export const sccAhcipRowSchema = z.object({
  encounterDate: z.string().date(),
  patientUli: z.string().min(1),
  patientName: z.string().min(1),
  patientDob: z.string().date(),
  patientGender: z.string().max(1),
  patientInsurer: z.string().min(1),
  coverageStatus: z.string().optional(),
  serviceCode: z.string().min(1).max(10),
  serviceCodeDescription: z.string().optional(),
  modifiers: z.string().optional(),
  diagnosticCode: z.string().optional(),
  icd10SourceCode: z.string().optional(),
  icdConversionFlag: z.boolean().default(false),
  referringProviderId: z.string().optional(),
  referringProviderName: z.string().optional(),
  billingProviderId: z.string().min(1),
  businessArrangementNumber: z.string().min(1),
  facilityCode: z.string().optional(),
  functionalCentre: z.string().optional(),
  encounterType: z.string().optional(),
  chargeStatus: z.enum(['ACTIVE', 'MODIFIED', 'DELETED']),
});
```

**WCB Row Schema:**

```typescript
export const sccWcbRowSchema = z.object({
  wcbClaimNumber: z.string().min(1),
  employerName: z.string().optional(),
  injuryDate: z.string().date(),
  dateOfService: z.string().date(),
  patientUli: z.string().min(1),
  patientName: z.string().min(1),
  patientDob: z.string().date(),
  patientGender: z.string().max(1),
  serviceCode: z.string().min(1).max(10),
  diagnosticCode: z.string().optional(),
  billingProviderIdBa: z.string().min(1),
  facilityCode: z.string().optional(),
  chargeStatus: z.enum(['ACTIVE', 'MODIFIED', 'DELETED']),
  wcbClinicalFields: z.record(z.string()).optional(),
});
```

### 3.6 Validation Rules

Each row is classified using a three-tier severity model:

| Validation Rule | Severity | Handling |
|----------------|----------|----------|
| Missing Patient ULI | **Blocking** | Row rejected. Cannot create claim without patient identifier. |
| Invalid ULI format (not 9-digit numeric for Alberta) | **Blocking** | Row rejected with format error. Out-of-province formats per B8 definitions accepted. |
| Missing Service Code | **Blocking** | Row rejected. No billable service to create. |
| Encounter Date in the future | **Blocking** | Row rejected. Likely data error. |
| Unrecognised SOMB code (not in Reference Data) | **Warning** | Claim created with warning flag. Physician prompted to verify code. |
| ICD Conversion Flag set (unconverted ICD-10) | **Warning** | Claim created. ICD-9 field left blank. Physician must manually select ICD-9 code before submission. See Section 5. |
| Missing Referring Provider ID (specialist claim) | **Warning** | Claim created with warning. Required before submission if SOMB code mandates referral (GR 8). |
| Encounter Date > 90 days old | **Warning** | Claim created with warning. Alberta Health may reject stale claims. |
| Charge Status = Deleted | **Informational** | Correction/deletion indicator. See Section 7. |
| Duplicate detection (same patient + date + code + provider) | **Informational** | Potential duplicate flagged. Physician decides skip or create. See Section 6. |

### 3.7 Parse Result Structure

The parser returns a `ParseResult` object:

```typescript
interface ParseResult {
  extractType: 'AHCIP' | 'WCB';
  specVersion: string;              // e.g. "2025-12"
  exportTimestamp: string;          // ISO 8601
  providerValidation: {
    billingProviderId: string;
    baNumber: string;
    matched: boolean;
  };
  summary: {
    totalRows: number;
    validRows: number;
    warningRows: number;
    errorRows: number;
    deletedRows: number;
    duplicateRows: number;
    dateRange: { earliest: string; latest: string };
  };
  rows: ParsedRow[];               // Each row with its classification
  errors: ParseError[];            // Blocking errors
  warnings: ParseWarning[];        // Non-blocking warnings
}

interface ParsedRow {
  rowNumber: number;
  classification: 'VALID' | 'WARNING' | 'ERROR' | 'DELETED' | 'DUPLICATE';
  data: SccAhcipRow | SccWcbRow;
  validationMessages: ValidationMessage[];
}
```

### 3.8 Versioning

The parser tracks the AHS extract specification version it implements via a constant:

```typescript
// packages/shared/src/constants/scc.constants.ts
export const SCC_SPEC_VERSIONS = {
  '2025-12': { label: 'December 2025', ahcipFields: 21, wcbFields: 13 },
} as const;

export const CURRENT_SCC_SPEC_VERSION = '2025-12';
```

When AHS updates the specification, a new version entry is added and the parser is extended to handle both old and new formats during transition.

---

## 4. Connect Care Import Workflow

**Addresses gap A2.**

### 4.1 User Workflow

1. Physician exports "My Billing Codes" / "My WCB Codes" from Connect Care as CSV.
2. Physician navigates to **Connect Care Import** in Meritum main navigation.
3. Physician uploads the CSV file (drag-and-drop or file picker).
4. Meritum parses the file, validates data, and presents an Import Summary.
5. Physician reviews summary, resolves any warnings, confirms import.
6. Meritum creates draft claims in DRAFT state.
7. Physician reviews, edits if necessary, and submits via standard claim lifecycle.

### 4.2 File Upload

**Endpoint:** `POST /api/v1/claims/connect-care/import`

**Requirements:**

- Accept `.csv`, `.CSV` file extensions. Also attempt to parse `.xlsx` and `.xls` files (convert to CSV internally) since the SCC export may be saved as a password-protected spreadsheet.
- Maximum file size: **10 MB**. The SCC extract is capped at 10,000 rows per report.
- Support drag-and-drop upload (frontend implementation in `apps/web/src/components/domain/claims/ConnectCareImport.tsx`).
- Raw uploaded file retained in encrypted storage (DigitalOcean Spaces, Toronto) for audit. Configurable retention period (default: 12 months), then purged.
- Content-Type: `multipart/form-data`.

**File processing flow:**

```
Upload received
  │
  ├─ 1. Validate file extension (.csv, .CSV, .xlsx, .xls)
  ├─ 2. Validate file size (≤ 10 MB)
  ├─ 3. Store raw file in DO Spaces (encrypted at rest)
  │     Path: imports/{provider_id}/{yyyy-mm}/{uuid}.{ext}
  ├─ 4. If .xlsx/.xls: convert to CSV (using xlsx library)
  ├─ 5. Pass CSV content to SCC Parser (Section 3)
  ├─ 6. Run duplicate detection (Section 6)
  ├─ 7. Run correction/deletion handling (Section 7)
  ├─ 8. Return ParseResult + import_batch_id
  └─ 9. Audit log: CONNECT_CARE_IMPORT_UPLOADED
```

### 4.3 Import Summary Screen

After parsing, the system displays an Import Summary:

```
Connect Care Import Summary
━━━━━━━━━━━━━━━━━━━━━━━━━━
  Source file:    My_Billing_Codes_2026-02-14.csv
  Extract type:   AHCIP (My Billing Codes)
  Date range:     10 Feb 2026 – 14 Feb 2026

  Total rows:     47
  ✓ Ready to import:    42
  ⚠ Warnings (review):  3
  ✗ Rejected (errors):   1
  ↔ Duplicates (skip):   1

  Warnings:
  • Row 12: ICD-10 code J06.9 not converted — manual ICD-9 selection required
  • Row 23: SOMB code 99.99Z not recognised — verify code
  • Row 31: Missing referring provider ID (specialist consultation)

  Errors:
  • Row 45: Missing Patient ULI — cannot create claim

  Duplicates:
  • Row 8: Matches existing claim (PHN ***456789, 12 Feb, 03.03A)

  [Confirm Import (42 claims)]  [Cancel]
```

The physician can expand any warning or error to see the specific row data. The physician must confirm before any claims are created.

### 4.4 Claim Creation on Confirmation

On confirmation:

1. For each VALID and WARNING row, create a claim in DRAFT state via Domain 4.0 claim creation service.
2. Tag every created claim with:
   - `import_source = 'CONNECT_CARE_CSV'`
   - `import_batch_id = {generated UUID linking all claims from this file}`
   - `raw_file_reference = {DO Spaces path to archived file}`
   - `scc_charge_status = 'ACTIVE'` (or 'MODIFIED')
3. Claims with warnings appear in the Unsubmitted queue with a visible warning indicator. Warnings must be resolved before submission.
4. Claims with `icd_conversion_flag = true` have ICD-9 field left blank. Physician must resolve via crosswalk (Section 5) before submission.
5. Modifier string from SCC extract is parsed (comma/pipe-delimited) and mapped to individual modifier fields on the claim.
6. Claims from "My WCB Codes" extract are routed to the WCB pipeline (Domain 4.2) based on `patientInsurer` and presence of WCB-specific fields.
7. DELETED rows are processed per Section 7 (Correction/Deletion Handling).
8. DUPLICATE rows are skipped unless physician explicitly chooses to create.

### 4.5 Post-Import Behaviour

- Created claims are editable exactly as manually-created claims.
- Intelligence Engine (Domain 7) evaluates each created claim and generates Tier 1 suggestions. For Connect Care imports, the rule evaluation checks `claim.importSource` for Tier A deterministic signals (see MHT-FRD-MVPADD-001, Section 7.2).
- Audit log entry: `CONNECT_CARE_IMPORT_COMPLETED` with metadata: `{ importBatchId, totalRows, claimsCreated, claimsWarning, claimsRejected, duplicatesSkipped, rawFileReference }`.

---

## 5. ICD-10-CA to ICD-9 Crosswalk

**Addresses gap A3.**

### 5.1 Context

Connect Care documents in ICD-10-CA but Alberta Health bills in ICD-9. Connect Care's translation engine handles >99% of conversions, but some codes arrive flagged as unconverted (ICD Conversion Flag = true). These claims cannot be submitted until the physician manually selects the correct ICD-9 code.

### 5.2 Crosswalk Table

A new reference data table maps ICD-10-CA codes to candidate ICD-9 codes:

**Table:** `icd_crosswalk` (in `packages/shared/src/schemas/db/reference.schema.ts`)

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| crosswalk_id | UUID | No | Primary key |
| icd10_code | VARCHAR(10) | No | ICD-10-CA code |
| icd10_description | VARCHAR(500) | No | ICD-10-CA code description |
| icd9_code | VARCHAR(10) | No | Candidate ICD-9 code |
| icd9_description | VARCHAR(500) | No | ICD-9 code description |
| match_quality | VARCHAR(20) | No | EXACT, CLOSE, APPROXIMATE, BROAD |
| sort_order | INTEGER | No | Display order within a group of candidates (1 = best match) |
| is_active | BOOLEAN | No | Soft delete. Default true. |
| created_at | TIMESTAMPTZ | No | |
| updated_at | TIMESTAMPTZ | No | |

**Constraints:**

- Unique: `(icd10_code, icd9_code)` — one ICD-10-CA code can map to multiple ICD-9 candidates, but each pair is unique.
- Index on `icd10_code` for fast lookup.

### 5.3 Resolution Interface

When a claim has `icd_conversion_flag = true`:

1. Display the original ICD-10-CA code and description prominently.
2. Query the crosswalk table for candidate ICD-9 codes, ordered by `sort_order`.
3. Display candidates in a selection list with match quality indicator:
   - **EXACT** — green badge, displayed first
   - **CLOSE** — amber badge
   - **APPROXIMATE** — grey badge
   - **BROAD** — grey badge, displayed last
4. If no candidates are appropriate, provide full ICD-9 code search.
5. Physician selects the ICD-9 code. The claim's `diagnostic_code` field is populated.
6. The claim retains `icd10_source_code` for audit trail.
7. Claim cannot be submitted until ICD-9 code is resolved (`diagnostic_code IS NOT NULL` when `icd_conversion_flag = true`).

### 5.4 Crosswalk Lookup API

**Endpoint:** `GET /api/v1/reference/icd-crosswalk/{icd10Code}`

Returns candidate ICD-9 codes for a given ICD-10-CA code, ordered by match quality.

---

## 6. Row-Level Duplicate Detection

**Addresses gap A4.**

### 6.1 Current State

File-level SHA-256 hash deduplication exists (prevents re-import of identical files). Row-level detection is needed.

### 6.2 Composite Key Matching

The duplicate detection key is: **Patient ULI + Encounter Date + Service Code + Billing Provider ID**.

During import processing, for each parsed row:

1. Query `claims` table for existing claims matching all four components, scoped to the authenticated provider (`WHERE provider_id = ctx.providerId`).
2. If a match exists (from a prior import or manual entry), flag the row as `DUPLICATE` in the import summary.
3. The physician decides: **Skip** (default) or **Create anyway**.

### 6.3 Non-Duplicates

Near-duplicates (same patient and date but different service codes) are **not** flagged. This is normal — a physician sees one patient and bills multiple codes.

---

## 7. Correction and Deletion Handling

**Addresses gap A5.**

### 7.1 Charge Status Processing

When processing an imported file, rows with `chargeStatus = 'DELETED'`:

1. Search for a matching draft claim from a prior import: match on Patient ULI + Encounter Date + original Service Code + Provider.
2. **If found and claim is in DRAFT or VALIDATED state:** automatically mark the claim for removal. Display in import summary as "Prior draft removed due to SCC correction."
3. **If found and claim has been SUBMITTED or later:** log the deletion indicator. Surface to the physician as a reconciliation alert: "A billing code you already submitted was deleted in Connect Care. Review claim {claimId}."
4. **If not found:** log the deletion indicator. No action needed (the original may never have been imported).

Rows with `chargeStatus = 'MODIFIED'`:

1. Search for a matching draft claim from a prior import.
2. **If found and claim is in DRAFT state:** replace the claim data with the modified row. Display in import summary as "Prior draft updated from SCC correction."
3. **If found and claim has advanced past DRAFT:** create a new draft with the modified data. Alert physician to review both.
4. **If not found:** create a new draft normally.

---

## 8. Claim Data Model Extensions

**Addresses gap A6.**

The following metadata columns are added to the `claims` table (`packages/shared/src/schemas/db/claims.schema.ts`):

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| import_source | VARCHAR(30) | No | `'MANUAL'`, `'CONNECT_CARE_CSV'`, `'CONNECT_CARE_SFTP'`, `'EMR_GENERIC'`. Default: `'MANUAL'`. |
| import_batch_id | UUID | Yes | Links all claims from a single file import. NULL for manual claims. |
| raw_file_reference | VARCHAR(500) | Yes | DO Spaces path to archived source file. NULL for manual claims. |
| scc_charge_status | VARCHAR(20) | Yes | `'ACTIVE'`, `'MODIFIED'`, `'DELETED'`. NULL for non-SCC claims. |
| icd_conversion_flag | BOOLEAN | No | True when ICD-10→ICD-9 conversion failed. Default false. |
| icd10_source_code | VARCHAR(10) | Yes | Original ICD-10-CA code from SCC extract. Preserved for audit. |
| shift_id | UUID FK | Yes | Foreign key to `ed_shifts`. Links claim to a shift for timestamp inference (see MHT-FRD-MOB-002). |

**Constraints:**

- `import_batch_id` indexed for batch-level queries.
- `shift_id REFERENCES ed_shifts(shift_id)` — nullable, populated during reconciliation.

---

## 9. sFTP Integration (Phase 2 — Post-MVP)

**Addresses gap A7.**

> **This section documents Phase 2 requirements for planning purposes. sFTP integration is NOT in MVP scope.** The AHS application process should begin immediately upon H-Link accreditation to minimise time-to-delivery.

### 9.1 Infrastructure Requirements

| Requirement | Specification |
|-------------|---------------|
| Protocol | SSH2 / sFTP (not FTP or FTPS) |
| Port | 22 (standard SSH). Accessible from AHS IP ranges only. |
| Authentication | SSH public key exchange. AHS generates keys; Meritum authorises on server. |
| Accounts | Separate `meritum-prod` and `meritum-test` accounts |
| Hosting | DigitalOcean Toronto (Canadian data residency per HIA) |
| Availability | Available for nightly batch window (~02:00 MST). AHS does not retry failed deliveries. |
| Storage | Encrypted at rest (AES-256). Sufficient for incoming files + archive. |
| Firewall | Inbound SSH restricted to AHS source IP ranges. All other inbound blocked. |

### 9.2 Automated File Processing Pipeline

```
File lands on sFTP server
  │
  ├─ 1. File Detection: cron job monitors incoming directory (≤15 min latency)
  ├─ 2. File Validation: non-zero size, valid CSV format, expected headers
  ├─ 3. Provider Routing: identify physician from Billing Provider ID + BA Number
  ├─ 4. Parsing: shared SCC Parser (Section 3) — identical to CSV import
  ├─ 5. Duplicate Detection: shared logic (Section 6)
  ├─ 6. Correction/Deletion Handling: shared logic (Section 7)
  ├─ 7. Claim Creation: draft claims tagged import_source='CONNECT_CARE_SFTP'
  ├─ 8. Notification: in-app + optional email to physician with summary
  ├─ 9. Archival: move processed file to archive directory
  └─ 10. Audit log: CONNECT_CARE_SFTP_PROCESSED
```

### 9.3 Monitoring (Phase 2)

| Monitor | Description |
|---------|-------------|
| Missed Delivery Detection | No file received for active sFTP physician by 06:00 MST → operational alert |
| File Integrity | Validate non-zero row count and expected header structure per file |
| SSH Key Expiry | Track AHS-issued SSH key lifecycle. Coordinate rotation proactively. |
| Server Health | Disk space, CPU, memory, SSH daemon, network connectivity to AHS IPs |
| Pipeline Health | End-to-end latency from file arrival to claim creation. Alert if >30 min. |

---

## 10. Data Model

### 10.1 New Tables

#### `icd_crosswalk` (Reference Data domain)

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| crosswalk_id | UUID | No | Primary key |
| icd10_code | VARCHAR(10) | No | ICD-10-CA code |
| icd10_description | VARCHAR(500) | No | ICD-10-CA code description |
| icd9_code | VARCHAR(10) | No | Candidate ICD-9 code |
| icd9_description | VARCHAR(500) | No | ICD-9 code description |
| match_quality | VARCHAR(20) | No | EXACT, CLOSE, APPROXIMATE, BROAD |
| sort_order | INTEGER | No | Display order within candidate group |
| is_active | BOOLEAN | No | Soft delete. Default true. |
| created_at | TIMESTAMPTZ | No | Default now() |
| updated_at | TIMESTAMPTZ | No | Default now() |

**Indexes:** `icd10_code`, `icd9_code`
**Unique:** `(icd10_code, icd9_code)`

#### `import_batches` (Claims domain)

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| import_batch_id | UUID | No | Primary key |
| provider_id | UUID FK | No | Physician who performed the import |
| import_source | VARCHAR(30) | No | CONNECT_CARE_CSV, CONNECT_CARE_SFTP, EMR_GENERIC |
| file_name | VARCHAR(500) | No | Original uploaded filename |
| raw_file_reference | VARCHAR(500) | No | DO Spaces path to archived file |
| file_hash | VARCHAR(64) | No | SHA-256 hash of raw file for deduplication |
| extract_type | VARCHAR(10) | No | AHCIP or WCB |
| spec_version | VARCHAR(20) | No | SCC spec version used for parsing |
| total_rows | INTEGER | No | Total rows in file |
| valid_rows | INTEGER | No | Rows successfully parsed |
| warning_rows | INTEGER | No | Rows with non-blocking warnings |
| error_rows | INTEGER | No | Rows with blocking errors |
| duplicate_rows | INTEGER | No | Rows flagged as duplicates |
| claims_created | INTEGER | No | Number of claims actually created |
| status | VARCHAR(20) | No | PENDING, CONFIRMED, CANCELLED |
| date_range_start | DATE | Yes | Earliest encounter date in file |
| date_range_end | DATE | Yes | Latest encounter date in file |
| confirmed_at | TIMESTAMPTZ | Yes | When physician confirmed import |
| created_at | TIMESTAMPTZ | No | Default now() |
| updated_at | TIMESTAMPTZ | No | Default now() |

**Indexes:** `provider_id`, `file_hash`

### 10.2 Modified Tables

#### `claims` — New Columns

See Section 8 for the full list of added columns (`import_source`, `import_batch_id`, `raw_file_reference`, `scc_charge_status`, `icd_conversion_flag`, `icd10_source_code`, `shift_id`).

---

## 11. API Contracts

### 11.1 Import Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/claims/connect-care/import` | Upload and parse SCC extract file. Returns ParseResult + import_batch_id. |
| GET | `/api/v1/claims/connect-care/import/{batchId}` | Get import batch details and parsed rows. |
| POST | `/api/v1/claims/connect-care/import/{batchId}/confirm` | Confirm import. Creates draft claims for all valid/warning rows. |
| POST | `/api/v1/claims/connect-care/import/{batchId}/cancel` | Cancel a pending import. No claims created. |
| GET | `/api/v1/claims/connect-care/import/history` | List previous imports for authenticated provider. Paginated. |

### 11.2 Import Upload — Request/Response

**POST `/api/v1/claims/connect-care/import`**

Request: `multipart/form-data` with field `file` (CSV/XLSX/XLS, ≤10 MB).

Response (200):
```json
{
  "data": {
    "importBatchId": "uuid",
    "extractType": "AHCIP",
    "specVersion": "2025-12",
    "summary": {
      "totalRows": 47,
      "validRows": 42,
      "warningRows": 3,
      "errorRows": 1,
      "duplicateRows": 1,
      "dateRange": { "earliest": "2026-02-10", "latest": "2026-02-14" }
    },
    "rows": [
      {
        "rowNumber": 1,
        "classification": "VALID",
        "data": { "encounterDate": "2026-02-10", "patientUli": "123456789", "..." : "..." },
        "validationMessages": []
      }
    ],
    "errors": [],
    "warnings": [
      { "rowNumber": 12, "field": "icdConversionFlag", "severity": "WARNING", "message": "ICD-10 code J06.9 not converted" }
    ]
  }
}
```

### 11.3 ICD Crosswalk Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/reference/icd-crosswalk/{icd10Code}` | Get candidate ICD-9 codes for an ICD-10-CA code |
| GET | `/api/v1/reference/icd-crosswalk` | Search crosswalk by ICD-10 or ICD-9 code/description. Query params: `q`, `page`, `pageSize`. |

**GET `/api/v1/reference/icd-crosswalk/{icd10Code}`**

Response (200):
```json
{
  "data": {
    "icd10Code": "J06.9",
    "icd10Description": "Acute upper respiratory infection, unspecified",
    "candidates": [
      {
        "icd9Code": "465.9",
        "icd9Description": "Acute upper respiratory infections of unspecified site",
        "matchQuality": "EXACT",
        "sortOrder": 1
      },
      {
        "icd9Code": "460",
        "icd9Description": "Acute nasopharyngitis (common cold)",
        "matchQuality": "CLOSE",
        "sortOrder": 2
      }
    ]
  }
}
```

---

## 12. Security

### 12.1 Authentication and Authorization

- The CSV upload endpoint (`POST /api/v1/claims/connect-care/import`) requires active authentication and a valid provider session. No anonymous uploads.
- Permission guard: `requirePermission('CLAIM_CREATE')`.
- Delegates with `CLAIM_CREATE` permission may upload on behalf of their physician.
- Import confirmation (`POST .../confirm`) also requires `CLAIM_CREATE`.
- Import history is scoped to the authenticated provider.

### 12.2 Physician Tenant Isolation

- All import operations are scoped to `ctx.providerId`. A physician can only view and manage their own imports.
- The SCC parser validates that the extract's `Billing Provider ID` matches the authenticated provider. Cross-provider data contamination is prevented at the parser level.
- Raw files in DO Spaces are stored under the provider's directory: `imports/{provider_id}/...`.
- The `import_batches` table enforces `provider_id` scoping on all queries.

### 12.3 PHI Handling

- Uploaded files are transmitted over TLS 1.3 and stored encrypted at rest (AES-256) on DO Spaces, Toronto.
- Raw uploaded files containing PHI are purged after the configurable retention period (default 12 months).
- Meritum does **not** request, store, or proxy AHS/Connect Care credentials. The physician extracts data from Connect Care using their own AHS credentials.
- PHN is masked as `123******` in all application logs per existing convention.
- No PHI in error messages: validation errors reference row numbers and field names, not patient data.

### 12.4 Audit Logging

All import activity is recorded in the audit log:

| Audit Event | Trigger |
|-------------|---------|
| `CONNECT_CARE_IMPORT_UPLOADED` | File uploaded and parsed |
| `CONNECT_CARE_IMPORT_CONFIRMED` | Import confirmed, claims created |
| `CONNECT_CARE_IMPORT_CANCELLED` | Import cancelled |
| `CONNECT_CARE_CLAIM_CORRECTION` | Charge Status DELETED/MODIFIED processed |
| `ICD_CROSSWALK_RESOLVED` | Physician selected ICD-9 code via crosswalk |

Each event includes: timestamp, user ID, provider ID, import batch ID, row counts, and raw file reference.

### 12.5 File Retention

- Raw files: retained for configurable period (default 12 months) then purged via scheduled job.
- Parsed/normalised claim data: persists within standard claim data retention policy (10 years per HIA).
- Import batch metadata: retained indefinitely for audit trail.

---

## 13. Testing Requirements

### 13.1 Unit Tests

**Location:** `apps/api/src/domains/claims/scc-parser.test.ts`

- Parse valid AHCIP CSV with all 21 fields → all rows classified VALID
- Parse valid WCB CSV with all 13 fields → all rows classified VALID
- Auto-detect AHCIP extract type (no WCB columns) → `extractType = 'AHCIP'`
- Auto-detect WCB extract type (WCB columns present) → `extractType = 'WCB'`
- Provider ID mismatch → entire file rejected with PROVIDER_MISMATCH
- BA number mismatch → entire file rejected
- Missing Patient ULI → row classified ERROR
- Invalid ULI format → row classified ERROR
- Missing Service Code → row classified ERROR
- Future encounter date → row classified ERROR
- Unrecognised SOMB code → row classified WARNING
- ICD Conversion Flag set → row classified WARNING, ICD-9 blank
- Encounter date >90 days → row classified WARNING
- Charge Status DELETED → row classified DELETED
- Multiple delimiter types (comma, tab, pipe) → all parsed correctly
- Empty file → appropriate error
- File exceeding 10,000 rows → handled without timeout
- Modifier string parsing: "CALL,COMP" → ['CALL', 'COMP']
- Modifier string parsing: "CALL|COMP|AGE" → ['CALL', 'COMP', 'AGE']

### 13.2 Integration Tests

**Location:** `apps/api/test/integration/claims/connect-care-import.test.ts`

- Upload CSV → parse → confirm → claims created in DRAFT state
- Upload CSV → cancel → no claims created
- Upload CSV with warnings → claims created with warning indicators
- Upload CSV with ICD conversion flags → claims created with blank ICD-9, icd10_source_code preserved
- Upload CSV with DELETED rows → matching prior drafts removed
- Upload CSV with MODIFIED rows → matching prior drafts updated
- Upload CSV with duplicates → duplicates flagged, physician skips → not created
- Upload CSV with duplicates → physician chooses create → created
- WCB extract → claims routed to WCB pipeline
- Import history endpoint returns only authenticated provider's imports
- Crosswalk lookup → returns ordered candidates
- Crosswalk lookup for unknown ICD-10 code → empty candidates array

### 13.3 Security Tests

**Location:** `apps/api/test/security/claims/`

#### Authentication Enforcement (`connect-care.authn.security.ts`)
- `POST /api/v1/claims/connect-care/import` returns 401 without session
- `GET /api/v1/claims/connect-care/import/{batchId}` returns 401 without session
- `POST /api/v1/claims/connect-care/import/{batchId}/confirm` returns 401 without session
- `GET /api/v1/claims/connect-care/import/history` returns 401 without session
- `GET /api/v1/reference/icd-crosswalk/{code}` returns 401 without session

#### Authorization (`connect-care.authz.security.ts`)
- Delegate without `CLAIM_CREATE` → 403 on import upload
- Delegate with `CLAIM_CREATE` → 200 on import upload
- Delegate without `CLAIM_CREATE` → 403 on import confirm

#### Tenant Isolation (`connect-care.scoping.security.ts`)
- Physician 1 uploads import → Physician 2 cannot access batch by ID (404)
- Physician 1's import history does not include Physician 2's imports
- SCC file with Physician 2's Billing Provider ID → rejected when uploaded by Physician 1

#### Input Validation (`connect-care.input.security.ts`)
- SQL injection in CSV field values → blocked by Zod/Drizzle
- XSS payload in Patient Name field → sanitised or stored safely
- File >10 MB → rejected (413)
- Non-CSV file (e.g. .exe) → rejected (400)
- Malformed CSV (no headers) → appropriate error

#### Data Leakage (`connect-care.leakage.security.ts`)
- Parse errors do not echo PHN in response body
- 500 errors do not expose file paths or internal details
- Import history endpoint masks PHN in response

#### Audit Trail (`connect-care.audit.security.ts`)
- File upload produces `CONNECT_CARE_IMPORT_UPLOADED` audit entry
- Import confirmation produces `CONNECT_CARE_IMPORT_CONFIRMED` audit entry
- Import cancellation produces `CONNECT_CARE_IMPORT_CANCELLED` audit entry
- Correction/deletion processing produces `CONNECT_CARE_CLAIM_CORRECTION` audit entry
- ICD crosswalk resolution produces `ICD_CROSSWALK_RESOLVED` audit entry

---

## 14. Open Questions

| # | Question | Context |
|---|----------|---------|
| 1 | What is the exact column header format in the AHS SCC CSV export? | The extract specification defines field names, but the actual CSV headers may use different casing, spacing, or abbreviations. Need a sample file from a live Connect Care instance to confirm. |
| 2 | How does Connect Care handle password-protected spreadsheets? | The export may be a password-protected .xlsx. Should Meritum prompt for the password, or require the physician to re-save as unprotected CSV? |
| 3 | What is the source and refresh cadence for the ICD-10-CA to ICD-9 crosswalk data? | CIHI maintains the official crosswalk. Need to confirm licensing and distribution mechanism. |
| 4 | Should the import endpoint support batch imports of multiple files in one session? | A physician may export AHCIP and WCB separately. Should the UI support multi-file upload? |
| 5 | How should the system handle mixed-insurer rows within a single AHCIP extract? | The extract may contain rows for ALBERTA HEALTH, BLUE CROSS, and out-of-province insurers. Should all be processed as AHCIP claims, or should Blue Cross/out-of-province rows be routed differently? |
| 6 | What is the latency expectation for sFTP file processing (Phase 2)? | The spec says ≤15 min detection, but should claims be available to the physician before their morning shift? This may drive the scheduling of the processing pipeline. |
| 7 | Should the parser accept Connect Care's native .xlsx export directly? | If the .xlsx is password-protected by default, this adds complexity. Alternative: document CSV re-save as the required step and support .xlsx as best-effort. |

---

## 15. Document Control

| Item | Value |
|------|-------|
| Parent documents | MHT-FUNC-CC-001 (Connect Care Integration), MHT-GAP-MVP-001 (Part A) |
| Feature scope | Cross-cutting: Claims (Domain 4.0), Reference Data (Domain 2), Infrastructure |
| Version | 1.0 |
| Date | 25 February 2026 |
| Author | Engineering |
| Status | DRAFT |
| Gap analysis items | A1, A2, A3, A4, A5, A6, A7 |

---

*End of Document*
