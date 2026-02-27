# [MERITUM] Functional Requirements — MVP Features Addendum

**Document ID:** MHT-FRD-MVPADD-001
**Cross-Domain Addendum** | Version 1.0 | 25 February 2026
**Parent Documents:** MHT-FUNC-MVP-002, MHT-GAP-MVP-001 (Part B)
**Classification:** Internal / Confidential

---

## 1. Domain Overview

### 1.1 Purpose

This FRD specifies eleven MVP features and one reference data loading requirement identified in the gap analysis (MHT-GAP-MVP-001, Part B). These features are additions or extensions to existing domains. They are organised by domain grouping to clarify which domain modules each feature modifies.

### 1.2 Scope

**Reference Data extensions (Domain 2):**
- B1: Referral Provider Search
- B6: In-App Billing Guidance
- B12: Shared Reference Data Dependencies

**Patient Registry extensions (Domain 6):**
- B2: PHN / Eligibility Verification
- B8: Reciprocal (Out-of-Province) Billing

**Claim Lifecycle extensions (Domain 4.0):**
- B3: Invoice Templates and Favourites (Desktop)
- B7: Anesthesia Benefit Calculations
- B9: Multi-Procedure Bundling and Unbundling
- B11: Text Justification Templates

**Intelligence Engine extensions (Domain 7):**
- B4: Revenue Optimisation Alerts (remaining gaps)
- B4a: Bedside-Contingent Rule Enhancement (confidence-tiered firing)

**Provider Management extensions (Domain 5):**
- B5: ARP/APP Shadow Billing (remaining gaps)
- B10: Mixed FFS/ARP Smart Routing

### 1.3 Out of Scope

- Connect Care / SCC integration (MHT-FRD-CC-001)
- Mobile Companion revisions (MHT-FRD-MOB-002)
- Core claim lifecycle state machine (Domain 4.0 existing FRD)
- H-Link submission pipeline (Domain 4.1 existing FRD)
- WCB form generation (Domain 4.2 existing FRD)

### 1.4 Domain Dependencies

| Domain | Direction | Interface |
|--------|-----------|-----------|
| Domain 2: Reference Data | Extended | Provider registry, crosswalk, bundling matrix, billing guidance, provincial PHN formats, justification templates |
| Domain 4.0: Claim Lifecycle Core | Extended | Templates, favourites, anesthesia calculator, bundling engine, text justification |
| Domain 5: Provider Management | Extended | ARP BA types, facility-BA mapping, time-based routing schedule |
| Domain 6: Patient Registry | Extended | Eligibility verification, reciprocal billing province detection |
| Domain 7: Intelligence Engine | Extended | Remaining alert rules, confidence-tiered firing, bedside-contingent enhancement |
| Domain 8: Analytics & Reporting | Consumed by | ARP dashboard section, TM summary report, reciprocal billing reporting |
| Domain 11: Onboarding | Consumed by | ARP BA type labelling, facility-BA mapping during onboarding |

---

## 2. Reference Data Extensions

### 2.1 Referral Provider Search

**Addresses gap B1.** Priority: P1.

#### 2.1.1 Provider Registry Table

A new reference data table stores the searchable provider registry:

**Table:** `provider_registry` (in `packages/shared/src/schemas/db/reference.schema.ts`)

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| registry_id | UUID | No | Primary key |
| practitioner_id | VARCHAR(10) | No | Alberta Health Practitioner ID (billing number placed on claims) |
| first_name | VARCHAR(100) | No | Provider first name |
| last_name | VARCHAR(100) | No | Provider last name |
| practice_discipline | VARCHAR(100) | Yes | Specialty / practice discipline |
| primary_city | VARCHAR(100) | Yes | Primary practice city |
| registration_status | VARCHAR(20) | No | ACTIVE or INACTIVE |
| data_source | VARCHAR(50) | No | Source of this record (e.g. AH_PROVIDER_REGISTRY, CPSA) |
| last_refreshed_at | TIMESTAMPTZ | No | When this record was last updated from source |
| is_active | BOOLEAN | No | Soft delete. Default true. |
| created_at | TIMESTAMPTZ | No | Default now() |
| updated_at | TIMESTAMPTZ | No | Default now() |

**Indexes:**
- `last_name` (trigram index via pg_trgm for fuzzy search)
- `practitioner_id` (unique, B-tree)
- `registration_status` (partial index on `'ACTIVE'`)

**Constraints:**
- Unique: `practitioner_id`

#### 2.1.2 Recent Referrers

Per-provider recent referrers are tracked in a join table:

**Table:** `recent_referrers`

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| recent_referrer_id | UUID | No | Primary key |
| provider_id | UUID FK | No | Physician who used this referrer |
| registry_id | UUID FK | No | FK to provider_registry |
| times_used | INTEGER | No | Total times selected. Default 1. |
| last_used_at | TIMESTAMPTZ | No | When this referrer was last selected |
| created_at | TIMESTAMPTZ | No | Default now() |
| updated_at | TIMESTAMPTZ | No | Default now() |

**Constraints:**
- Unique: `(provider_id, registry_id)` — one entry per referrer per physician
- Maximum 20 per provider (enforced in service layer; oldest evicted on insert)

#### 2.1.3 Functional Requirements

- The referral provider lookup is accessible from the claim creation form whenever a SOMB code requires a referring physician (codes where GR 8 mandates referral information).
- Search supports: last name, first name, Practitioner ID (partial or full), city, practice discipline.
- Results display: full name, Practitioner ID, practice discipline, primary city, registration status. Only active physicians appear in default results; inactive can be revealed with a filter toggle.
- On selection, the Practitioner ID and provider name auto-populate into the claim's `referring_provider_id` and `referring_provider_name` fields.
- "Recent Referrers" list (last 20 used) displayed as quick-select above search. Ordered by `last_used_at` descending.
- Provider registry data refreshed at minimum monthly. Data currency date displayed in the UI: "Provider data last updated: {date}".
- If SOMB code requires referral and field is blank at submission → block submission with validation error.
- Manual entry fallback: physician can type a Practitioner ID not in the registry. Manual entries are flagged for review but not blocked.

#### 2.1.4 API Contracts

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/reference/providers/search` | Search provider registry. Query params: `q` (free text), `practitionerId`, `city`, `discipline`, `status`, `page`, `pageSize`. |
| GET | `/api/v1/reference/providers/{practitionerId}` | Get a single provider by Practitioner ID. |
| GET | `/api/v1/claims/referrers/recent` | Get authenticated physician's recent referrers (max 20). |
| POST | `/api/v1/claims/referrers/recent` | Record use of a referrer (upserts times_used + last_used_at). |

---

### 2.2 In-App Billing Guidance

**Addresses gap B6.** Priority: P2.

#### 2.2.1 Guidance Content Model

All billing guidance is stored as structured reference data, updateable without code deployment.

**Table:** `billing_guidance` (in `packages/shared/src/schemas/db/reference.schema.ts`)

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| guidance_id | UUID | No | Primary key |
| guidance_type | VARCHAR(30) | No | SOMB_TOOLTIP, REJECTION_HINT, MODIFIER_GUIDANCE, ICD_ASSISTANCE, GOVERNING_RULE, NEW_TO_PRACTICE |
| reference_code | VARCHAR(20) | Yes | SOMB code, modifier code, ICD-9 code, or GR number this guidance relates to |
| title | VARCHAR(200) | No | Short display title |
| content | TEXT | No | Guidance content in Markdown |
| source_reference | VARCHAR(200) | Yes | SOMB section, GR number, or policy reference |
| source_url | VARCHAR(500) | Yes | Link to authoritative source document |
| rejection_threshold | DECIMAL(5,4) | Yes | For REJECTION_HINT: only shown when code's rejection rate exceeds this (default 0.05 = 5%) |
| display_context | VARCHAR(30) | No | CLAIM_FORM, CODE_SEARCH, MODIFIER_FIELD, DIAGNOSTIC_FIELD, GLOBAL_SEARCH |
| is_new_to_practice | BOOLEAN | No | True = shown only in new-to-practice mode. Default false. |
| sort_order | INTEGER | No | Display ordering within context |
| is_active | BOOLEAN | No | Soft delete. Default true. |
| created_at | TIMESTAMPTZ | No | Default now() |
| updated_at | TIMESTAMPTZ | No | Default now() |

**Indexes:** `(guidance_type, reference_code)`, `display_context`

#### 2.2.2 Guidance Categories

| Category | Trigger | Content |
|----------|---------|---------|
| **SOMB Tooltips** | Code selection/search | Official description, current fee, applicable modifiers and fee impact, common pairing codes, governing rules/restrictions |
| **Rejection Prevention Hints** | Code selection (when rejection rate > threshold) | Common rejection reason, guidance to avoid rejection |
| **Modifier Guidance** | Modifier added/omitted on claim form | Contextual prompt (e.g. "Weekend service without CALL modifier — CALL may apply") |
| **ICD-9 Assistance** | Diagnostic code entry | Description, common SOMB associations, commonly-questioned flags |
| **Governing Rules** | Complex code selected | Concise GR summary with link to SOMB source |
| **New-to-Practice** | Always (when mode enabled) | Extended billing concept explanations for new graduates / new-to-Alberta physicians |

#### 2.2.3 Functional Requirements

- Tooltips and hints appear inline within the claim creation form, adjacent to the relevant field. No navigation required.
- **Progressive disclosure:** minimal for experienced users (icon indicators expanding on hover/click); expanded by default for new-to-practice users.
- Persistent **"Billing Help" search** accessible from any screen: `GET /api/v1/reference/guidance/search?q={term}`.
- **Usage tracking:** record which guidance elements are accessed vs dismissed. Stored per provider for content prioritisation.
- **New-to-Practice mode:** toggle in provider settings. When enabled, additional guidance appears for billing concepts (BA numbers, remittance cycles, action codes). Disableable at any time.
- Launch with guidance for the top 20 most-billed SOMB codes. Expand incrementally.

#### 2.2.4 API Contracts

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/reference/guidance` | List guidance entries. Filter by `type`, `referenceCode`, `displayContext`. Paginated. |
| GET | `/api/v1/reference/guidance/search` | Full-text search across guidance content. Query param: `q`. |
| GET | `/api/v1/reference/guidance/code/{sombCode}` | Get all guidance for a specific SOMB code (tooltip, rejection hints, modifier guidance). |
| POST | `/api/v1/reference/guidance/{id}/track` | Record that a guidance element was viewed or dismissed. Body: `{ action: 'VIEWED' | 'DISMISSED' }`. |

---

### 2.3 Shared Reference Data Dependencies

**Addresses gap B12.** Priority: P1.

The following reference data sets must be loaded and maintained. This section defines the data sets, their sources, and refresh cadences. The reference data domain (`apps/api/src/domains/reference/`) owns loading, versioning, and serving these data sets.

| Data Set | Required By | Status | Source | Refresh Cadence |
|----------|-------------|--------|--------|----------------|
| Provider Registry (Practitioner IDs, names, specialties, locations) | B1 (Referral Search) | NOT LOADED | AH Provider Registry / H-Link inquiry | Monthly minimum |
| Provincial Health Number format definitions (11 provinces) | B8 (Reciprocal Billing) | NOT LOADED | Provincial health ministries | Annually or on change |
| ICD-10-CA to ICD-9 crosswalk table | A3 (ICD Crosswalk) | NOT LOADED | CIHI crosswalk distribution | Annually |
| Structured bundling rules matrix (code-pairs, AHCIP + WCB columns) | B9 (Bundling) | NOT LOADED | SOMB governing rules + WCB Physician's Reference Guide | With SOMB/WCB updates |
| Text justification template definitions (5 scenarios) | B11 (Text Justification) | NOT LOADED | Meritum (authored from SOMB + AH assessor expectations) | As needed |
| Reciprocal billing rules (coverage per province, exclusions) | B8 (Reciprocal Billing) | PARTIAL | Interprovincial Health Insurance Agreements | Annually |
| ARP S-code set | B5 (ARP Billing) | PARTIAL | Alberta Health | Within 5 business days of update |
| SOMB GR 12 structured (anesthesia calculations) | B7 (Anesthesia Calc) | NOT LOADED | SOMB | With SOMB updates |
| SOMB GR 2.6 structured (additional compensation) | B11 (Text Justification) | NOT LOADED | SOMB | With SOMB updates |
| Inclusive care period data per surgical code | B9 (Bundling) | NOT LOADED | SOMB | With SOMB updates |
| Rejection reason reference (action codes + plain-language guidance) | B6 (Billing Guidance) | NOT CONFIRMED | Physician's Resource Guide + Meritum operational data | Ongoing |

---

## 3. Patient Registry Extensions

### 3.1 PHN / Eligibility Verification

**Addresses gap B2.** Priority: P1.

#### 3.1.1 Verification Mechanisms

| Mechanism | Type | Description |
|-----------|------|-------------|
| PHN Format Validation | Local | Alberta PHN: 9 digits + Luhn variant check. Out-of-province: per B8 format definitions. |
| H-Link Eligibility Inquiry | Remote (real-time) | Queries Alberta Health via H-Link. Returns coverage status for PHN + date of service. |
| Netcare/IVR Fallback | Manual | Physician verifies via Netcare Portal or IVR (1-888-422-6257). System records attestation. |

#### 3.1.2 Eligibility Check Flow

```
PHN entered on claim form
  │
  ├─ 1. Format validation (local, instant)
  │     ├─ Invalid format → inline error, stop
  │     └─ Valid format → continue
  ├─ 2. Check cache (PHN + date of service, 24h TTL)
  │     ├─ Cached result exists → display cached status
  │     └─ No cache → continue to H-Link
  ├─ 3. H-Link eligibility inquiry (real-time)
  │     ├─ "Eligible" → green indicator, cache result
  │     ├─ "Not Currently Eligible" → red indicator + guidance
  │     └─ "Query Failed" → amber indicator + retry option
  └─ 4. Physician override available on all negative results
```

#### 3.1.3 Eligibility Cache Table

**Table:** `eligibility_cache` (in `packages/shared/src/schemas/db/patients.schema.ts`)

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| cache_id | UUID | No | Primary key |
| provider_id | UUID FK | No | Physician who requested the check (scoping) |
| patient_phn_hash | VARCHAR(64) | No | SHA-256 hash of PHN (not plaintext — reduces PHI exposure in cache table) |
| date_of_service | DATE | No | Date the eligibility was checked against |
| status | VARCHAR(30) | No | ELIGIBLE, NOT_ELIGIBLE, QUERY_FAILED |
| response_details | JSONB | Yes | Raw response metadata from H-Link (no PHI) |
| checked_at | TIMESTAMPTZ | No | When the check was performed |
| expires_at | TIMESTAMPTZ | No | Cache expiry (checked_at + 24 hours) |
| created_at | TIMESTAMPTZ | No | Default now() |

**Indexes:** `(patient_phn_hash, date_of_service)` for lookup
**TTL:** Rows with `expires_at < now()` are evicted by a scheduled cleanup job.

#### 3.1.4 Functional Requirements

- **Real-time check:** when a valid-format PHN is entered on the claim form, the system performs an H-Link eligibility inquiry. Inline display: "Eligible" (green), "Not Currently Eligible" (red + guidance), "Query Failed" (amber + retry).
- **Ineligibility guidance:** common reasons (lapsed coverage, out-of-province, opted out) and options (verify with patient, reciprocal billing, direct billing).
- **Cache:** eligibility results cached for PHN + date of service for 24 hours. Avoids redundant H-Link calls for same-patient claims.
- **Physician override:** override a failed eligibility check with logged warning. Supports Alberta Good Faith Policy.
- **Bulk checks:** on Connect Care imports and EMR imports, eligibility checks run in background. Ineligible claims flagged without blocking the import workflow.
- **90-day patient cache:** once verified, subsequent claims within 90 days display "Last verified: {date}" with one-click re-check.
- **Fallback mode:** if H-Link eligibility inquiry is unavailable at launch: format validation only + prompt to verify via Netcare or IVR + "I have verified this PHN" checkbox.

#### 3.1.5 API Contracts

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/patients/eligibility/check` | Check eligibility for a PHN + date of service. Body: `{ phn, dateOfService }`. Returns status + guidance. |
| GET | `/api/v1/patients/eligibility/cache/{phnHash}` | Get cached eligibility status for a PHN. |
| POST | `/api/v1/patients/eligibility/override` | Record physician override of failed eligibility. Body: `{ claimId, reason }`. |
| POST | `/api/v1/patients/eligibility/bulk` | Bulk eligibility check for a list of PHNs + dates. Used by import workflow. |

---

### 3.2 Reciprocal (Out-of-Province) Billing

**Addresses gap B8.** Priority: P1.

#### 3.2.1 Provincial Health Number Formats

**Table:** `provincial_phn_formats` (in `packages/shared/src/schemas/db/reference.schema.ts`)

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| format_id | UUID | No | Primary key |
| province_code | VARCHAR(2) | No | Standard 2-char province code (AB, BC, SK, MB, ON, QC, NB, NS, PE, NL, YT, NT, NU) |
| province_name | VARCHAR(50) | No | Full province name |
| format_description | VARCHAR(200) | No | Human-readable format description (e.g. "10 digits, numeric only") |
| digit_count_min | INTEGER | No | Minimum digits/characters |
| digit_count_max | INTEGER | No | Maximum digits/characters |
| format_regex | VARCHAR(200) | No | Regex pattern for validation |
| has_check_digit | BOOLEAN | No | Whether format includes a check digit algorithm |
| check_digit_algorithm | VARCHAR(50) | Yes | Algorithm name (e.g. "LUHN_VARIANT") if applicable |
| triggers_private_billing | BOOLEAN | No | True for Quebec (no reciprocal billing) |
| notes | TEXT | Yes | Additional format notes |
| is_active | BOOLEAN | No | Soft delete. Default true. |
| created_at | TIMESTAMPTZ | No | Default now() |
| updated_at | TIMESTAMPTZ | No | Default now() |

**Seed data (11 provinces/territories):**

| Province | Format | Regex | Private Billing |
|----------|--------|-------|----------------|
| AB (Alberta) | 9 digits, Luhn variant | `^\d{9}$` | No |
| BC | 10 digits | `^\d{10}$` | No |
| SK | 9 digits | `^\d{9}$` | No |
| MB | 6 digits + optional letter, or 9 digits | `^\d{6}[A-Z]?$\|^\d{9}$` | No |
| ON | 10 digits | `^\d{10}$` | No |
| QC | 4 letters + 8 digits (RAMC) | `^[A-Z]{4}\d{8}$` | **Yes** |
| NB | 9 digits | `^\d{9}$` | No |
| NS | 10 digits | `^\d{10}$` | No |
| PE | 8 digits | `^\d{8}$` | No |
| NL | 12 digits (older) or MCP format | `^\d{12}$\|^\d{10}$` | No |
| YT, NT, NU | 7–9 digits variable | `^\d{7,9}$` | No |

#### 3.2.2 Reciprocal Billing Rules Table

**Table:** `reciprocal_billing_rules` (in `packages/shared/src/schemas/db/reference.schema.ts`)

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| rule_id | UUID | No | Primary key |
| province_code | VARCHAR(2) | No | Province this rule applies to |
| rule_type | VARCHAR(30) | No | COVERAGE_RULE, EXCLUSION, SPECIAL_HANDLING |
| somb_code | VARCHAR(10) | Yes | Specific SOMB code affected (NULL = applies to all) |
| description | TEXT | No | Rule description |
| action | VARCHAR(30) | No | ALLOW, WARN, BLOCK, REDIRECT_PRIVATE |
| is_active | BOOLEAN | No | Soft delete. Default true. |
| created_at | TIMESTAMPTZ | No | Default now() |
| updated_at | TIMESTAMPTZ | No | Default now() |

#### 3.2.3 Functional Requirements

- **Auto-detection:** when a health number is entered on a claim, the system attempts to detect the province from the number format. If a non-Alberta format is detected, the claim switches to reciprocal billing mode automatically.
- **Reciprocal billing mode:** displays identified province, suppresses Alberta-specific PHN validation, applies province-specific format validation instead.
- **Quebec detection:** Quebec health number (4 letters + 8 digits RAMC format) → redirect to private billing workflow with explanation: "Quebec does not participate in reciprocal physician billing. This patient must be invoiced directly."
- **Reciprocal exclusion flags:** service codes with known reciprocal billing exclusions display a warning: "This service code may not be covered under reciprocal billing for {province} patients."
- **Reciprocal claim tagging:** claims tagged with patient's home province. Separate reporting: volume, acceptance rate, province-specific rejection patterns.
- **Manual province override:** for ambiguous or territory health numbers.
- **Card expiry handling:** prompt physician to verify coverage if entered details suggest expiry.

#### 3.2.4 Province Auto-Detection Logic

```typescript
// packages/shared/src/utils/province-detect.ts
function detectProvince(healthNumber: string): ProvinceDetectionResult {
  // 1. Strip formatting (dashes, spaces)
  const cleaned = healthNumber.replace(/[-\s]/g, '');

  // 2. Test against format patterns in priority order:
  //    - Quebec first (letters+digits pattern is unambiguous)
  //    - Alberta (9 digits + Luhn check)
  //    - Remaining provinces by digit count
  // 3. Return: { provinceCode, confidence: 'HIGH' | 'MEDIUM' | 'LOW', format }
  //    LOW confidence = multiple provinces share the same format (e.g. 9-digit: AB, SK, NB)
}
```

When confidence is LOW (multiple possible provinces), the system displays the top candidate and offers a province selector for manual correction.

#### 3.2.5 API Contracts

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/reference/provincial-phn-formats` | List all provincial PHN format definitions. |
| POST | `/api/v1/patients/detect-province` | Detect province from health number. Body: `{ healthNumber }`. Returns `{ provinceCode, confidence, format }`. |
| GET | `/api/v1/reference/reciprocal-rules/{provinceCode}` | Get reciprocal billing rules for a province. Optional query: `sombCode` for code-specific rules. |

---

## 4. Claim Lifecycle Extensions

### 4.1 Invoice Templates and Favourites (Desktop)

**Addresses gap B3.** Priority: P1.

#### 4.1.1 Favourites — Desktop Extension

The existing mobile favourites (`/api/v1/favourites`) are extended to desktop:

- Quick-access panel at top of service code selection interface on the desktop claim form.
- Ordered by usage frequency (most-used first) by default. Manual drag-and-drop reordering.
- Each favourite stores: service code, optional physician-defined label, commonly-used modifiers for that code.
- **Auto-suggest:** after 5+ billings without the code being favourited, display non-intrusive prompt: "You bill {code} often. Add to favourites?"

No schema changes needed — the existing `favourite_codes` table already supports this. Desktop UI implementation in `apps/web/src/components/domain/claims/FavouritesPanel.tsx`.

#### 4.1.2 Claim Templates

**Table:** `claim_templates` (in `packages/shared/src/schemas/db/claims.schema.ts`)

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| template_id | UUID | No | Primary key |
| provider_id | UUID FK | No | Physician who owns this template |
| name | VARCHAR(200) | No | Template display name |
| description | VARCHAR(500) | Yes | Optional description |
| template_type | VARCHAR(20) | No | CUSTOM, SPECIALTY_STARTER |
| line_items | JSONB | No | Array of template line items (see below) |
| facility_code | VARCHAR(20) | Yes | Default facility code |
| diagnostic_code | VARCHAR(10) | Yes | Default diagnostic code |
| encounter_type | VARCHAR(20) | Yes | Default encounter type |
| sort_order | INTEGER | No | Display order. Default 0. |
| usage_count | INTEGER | No | Times this template has been used. Default 0. |
| is_active | BOOLEAN | No | Soft delete. Default true. |
| created_at | TIMESTAMPTZ | No | Default now() |
| updated_at | TIMESTAMPTZ | No | Default now() |

**`line_items` JSONB structure:**

```typescript
interface TemplateLineItem {
  serviceCode: string;       // SOMB code
  modifiers?: string[];      // Default modifiers
  diagnosticCode?: string;   // Default diagnostic code (overrides template-level)
  label?: string;            // Physician-defined label
}
```

**Specialty starter templates** are seeded during onboarding based on the physician's specialty (e.g. Family Medicine: 03.03A Standard Office Visit, 03.04A Complete Physical, 03.01F Phone Consult). These have `template_type = 'SPECIALTY_STARTER'` and are editable/deletable.

#### 4.1.3 Functional Requirements

- **"New Claim from Template"** action. Selecting a template pre-populates all stored fields. Physician adds patient-specific data (PHN, name, date of service) and submits.
- **Multi-line templates:** single template with multiple service codes creates a claim with all lines pre-populated.
- **Fee display:** templates show current SOMB fee for each included code. Fees update automatically on SOMB revision (looked up at display time, not stored on template).
- **"Quick Bill" workflow:** select template + select patient (from recent or search) → create and optionally auto-submit. Two-click billing target for routine work.
- Templates scoped to provider. Delegates see their physician's templates.

#### 4.1.4 API Contracts

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/claims/templates` | List templates for authenticated provider. Ordered by sort_order, then usage_count desc. |
| POST | `/api/v1/claims/templates` | Create a new template. Body: CreateTemplateSchema. |
| PUT | `/api/v1/claims/templates/{id}` | Update a template. |
| DELETE | `/api/v1/claims/templates/{id}` | Soft-delete a template. |
| POST | `/api/v1/claims/templates/{id}/apply` | Create claim(s) from template. Body: `{ patientId, dateOfService, autoSubmit?: boolean }`. |
| PUT | `/api/v1/claims/templates/reorder` | Reorder templates. Body: `{ templateIds: string[] }`. |

---

### 4.2 Anesthesia Benefit Calculations

**Addresses gap B7.** Priority: P2.

#### 4.2.1 GR 12 Calculation Rules

All rules stored as structured reference data in the governing rules data set, versioned and updateable without code deployment.

**Table:** `anesthesia_rules` (in `packages/shared/src/schemas/db/reference.schema.ts`)

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| rule_id | UUID | No | Primary key |
| rule_type | VARCHAR(30) | No | SINGLE_PROCEDURE, MULTIPLE_PROCEDURE, COMPOUND_FRACTURE, CLOSED_REDUCTION, OPEN_REDUCTION, REDO_CARDIAC, SEQUENTIAL, TIME_BASED, ORAL_SURGERY, SKIN_LESION |
| description | TEXT | No | Human-readable rule description |
| calculation_formula | TEXT | No | Formula expression for benefit calculation |
| rate_multiplier | DECIMAL(5,4) | Yes | Multiplier (e.g. 0.50 for 50% reduction, 1.25 for 125% redo) |
| conditions | JSONB | No | Conditions under which this rule applies |
| prompts | JSONB | Yes | Conditional prompts for the physician (e.g. "Is this a redo through a previous incision?") |
| somb_reference | VARCHAR(50) | No | GR 12 section reference |
| is_active | BOOLEAN | No | Soft delete. Default true. |
| created_at | TIMESTAMPTZ | No | Default now() |
| updated_at | TIMESTAMPTZ | No | Default now() |

#### 4.2.2 Calculation Logic

| Scenario | Logic |
|----------|-------|
| **Single Procedure** | Anaesthetic benefit = listed anesthetic value for the surgical code. Direct SOMB lookup. |
| **Multiple Procedures** | Major procedure (highest listed value) at full rate. Each additional procedure at SOMB-defined reduced rate (typically 50%). System auto-identifies major procedure. |
| **Compound Fractures** | 50% uplift on listed anaesthetic benefit when extensive debridement required. |
| **Multiple Closed-Reduction Fractures** | Major fracture at full rate + 50% for each additional closed-reduction fracture. |
| **Open-Reduction Fractures** | Each fracture requiring open reduction/traction/fixation at full anaesthetic benefit, plus major fracture at full rate. |
| **Redo Cardiac/Thoracic/Vascular** | 150% if entirely through previous incision; 125% if partly. System prompts physician. |
| **Sequential Unrelated Procedures** | Major at full rate, additional at reduced rate (same as multiple procedures). |
| **Time-Based** | Unlisted procedures or codes without listed anesthetic value → time-based calculation using SOMB time rate. |
| **Oral Surgery** | Follows GR 6.9 rules. Separate rate table applies. |
| **Skin Lesion Cap** | Multiple benign skin lesions under <35 min anaesthesia → single benefit cap regardless of lesion count. |

#### 4.2.3 Functional Requirements

- **Activation:** calculator activates when billing physician's specialty is anaesthesia OR when an anesthesia-category code is selected.
- **Auto-identification:** when multiple surgical codes entered, auto-identify major procedure (highest listed anaesthetic benefit).
- **Conditional prompts:** redo procedure (125/150%), compound fracture debridement (50% uplift), open reduction with fixation.
- **Time entry:** start time, end time, and/or duration. Real-time benefit display as values are entered.
- **Transparent breakdown:** display each component of the total anaesthetic benefit (major procedure value, additional at reduced rates, uplifts). Physician sees exactly how total was computed.
- **Skin lesion cap:** enforce single-benefit cap for procedures under 35 min. Display guidance explaining the rule.
- **Manual override logging:** if physician changes calculated value, override logged and flagged for review.
- **All rules from structured reference data**, versioned, updateable without deployment.

#### 4.2.4 API Contracts

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/claims/anesthesia/calculate` | Calculate anaesthetic benefit. Body: `{ procedureCodes[], startTime?, endTime?, duration?, conditionalResponses? }`. Returns breakdown. |
| GET | `/api/v1/reference/anesthesia-rules` | List all active anesthesia calculation rules. |

---

### 4.3 Multi-Procedure Bundling and Unbundling

**Addresses gap B9.** Priority: P1.

#### 4.3.1 Bundling Rules Matrix

**Table:** `bundling_rules` (in `packages/shared/src/schemas/db/reference.schema.ts`)

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| bundling_rule_id | UUID | No | Primary key |
| code_a | VARCHAR(10) | No | First SOMB code in the pair |
| code_b | VARCHAR(10) | No | Second SOMB code in the pair |
| ahcip_relationship | VARCHAR(30) | No | BUNDLED (higher-value only), INDEPENDENT, INTRINSICALLY_LINKED |
| wcb_relationship | VARCHAR(30) | No | BUNDLED, INDEPENDENT, INTRINSICALLY_LINKED |
| higher_value_code | VARCHAR(10) | Yes | Which code is the higher-value (for BUNDLED pairs). NULL if INDEPENDENT. |
| reduction_rate | DECIMAL(5,4) | Yes | Reduction for secondary procedure (e.g. 0.50 = 50%). NULL if fully bundled. |
| inclusive_care_days_pre | INTEGER | Yes | Pre-operative inclusive care period in days |
| inclusive_care_days_post | INTEGER | Yes | Post-operative inclusive care period in days |
| somb_reference | VARCHAR(50) | Yes | Governing rule reference |
| notes | TEXT | Yes | Additional context |
| is_active | BOOLEAN | No | Soft delete. Default true. |
| created_at | TIMESTAMPTZ | No | Default now() |
| updated_at | TIMESTAMPTZ | No | Default now() |

**Indexes:** `(code_a, code_b)` unique, `code_a`, `code_b`
**Constraint:** `code_a < code_b` (normalised ordering to prevent duplicate pairs)

#### 4.3.2 Functional Requirements

- **Automatic bundling check:** when multiple procedure codes entered on a single AHCIP claim, check each pair against the bundling rules matrix.
- **Bundled pair detected:** alert physician, identify higher-value code, recommend removing or replacing lower-value code.
- **WCB unbundling:** same codes on WCB claim → apply WCB rules (each distinct procedure at 100% unless intrinsically linked). Display per-procedure fee and total.
- **Inclusive care period enforcement:** if a visit claim created for a patient with a surgical claim within the inclusive care window → alert: "This visit falls within the inclusive care period for {surgicalCode} on {date}. Not separately billable unless pre-operative conservative measures or post-operative complication." Override with text justification (Section 4.5).
- **Multiple procedure reduction:** automatically apply correct reduction for secondary procedures. Display calculation transparently.
- **Modifier combination validation:** flag invalid or contradictory modifier pairs.
- **Audit logging:** every bundling/unbundling decision logged, including physician overrides.
- All rules in structured reference data, versioned, updateable without deployment.

#### 4.3.3 API Contracts

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/claims/bundling/check` | Check code combination for bundling rules. Body: `{ codes[], claimType: 'AHCIP' | 'WCB', patientId?, dateOfService? }`. Returns bundling analysis. |
| GET | `/api/v1/reference/bundling-rules` | List all bundling rules. Filter by `code`, `relationship`. |
| GET | `/api/v1/reference/bundling-rules/pair/{codeA}/{codeB}` | Get bundling rule for a specific code pair. |

---

### 4.4 Text Justification Templates

**Addresses gap B11.** Priority: P2.

#### 4.4.1 Justification Scenarios

| Scenario | Trigger | Required Fields |
|----------|---------|-----------------|
| **Unlisted Procedure** | Unlisted procedure code selected | Procedure performed, clinical indication, comparable listed code, time involved, requested benefit |
| **Additional Compensation (GR 2.6)** | Physician manually invokes | Nature of additional complexity, additional time, distinguishing circumstances |
| **Pre-Operative Conservative Measures** | Visit during surgical inclusive care period + physician selects pre-op exception | Conservative treatment attempted, clinical decision to proceed to surgery, pre-op visit dates |
| **Post-Operative Complication** | Visit during surgical inclusive care period + physician selects complication exception | Original procedure code [auto], original procedure date [auto], nature of complication, clinical findings, treatment provided |
| **WCB Detailed Narrative** | WCB claim for complex case | Treatment description, progress notes, work capacity assessment |

#### 4.4.2 Justification Template Definition Table

**Table:** `justification_templates` (in `packages/shared/src/schemas/db/reference.schema.ts`)

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| template_id | UUID | No | Primary key |
| scenario | VARCHAR(30) | No | UNLISTED_PROCEDURE, ADDITIONAL_COMPENSATION, PRE_OP_CONSERVATIVE, POST_OP_COMPLICATION, WCB_NARRATIVE |
| name | VARCHAR(200) | No | Display name |
| description | TEXT | No | When this template applies |
| fields | JSONB | No | Array of field definitions: `{ fieldId, label, type: 'FREE_TEXT' | 'AUTO_POPULATED' | 'CODE_LOOKUP', required, autoPopulateSource? }` |
| output_format | TEXT | No | Template string combining field values into formatted text block |
| somb_reference | VARCHAR(50) | Yes | Governing rule reference |
| is_active | BOOLEAN | No | Soft delete. Default true. |
| created_at | TIMESTAMPTZ | No | Default now() |
| updated_at | TIMESTAMPTZ | No | Default now() |

#### 4.4.3 Claim Justification Storage

**Table:** `claim_justifications` (in `packages/shared/src/schemas/db/claims.schema.ts`)

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| justification_id | UUID | No | Primary key |
| claim_id | UUID FK | No | FK to claims |
| provider_id | UUID FK | No | Physician (scoping) |
| template_id | UUID FK | Yes | FK to justification_templates (NULL if fully manual) |
| scenario | VARCHAR(30) | No | Justification scenario type |
| field_values | JSONB | No | Physician's responses to template fields |
| generated_text | TEXT | No | Formatted justification text (editable) |
| linked_claim_id | UUID FK | Yes | For post-op/pre-op: FK to the surgical claim |
| is_personal_template | BOOLEAN | No | True if physician saved this as a personal reusable template. Default false. |
| created_at | TIMESTAMPTZ | No | Default now() |
| updated_at | TIMESTAMPTZ | No | Default now() |

**Indexes:** `claim_id`, `provider_id`, `scenario`

#### 4.4.4 Functional Requirements

- **Auto-detection:** system detects when justification is required based on service code and claim context: unlisted procedure codes trigger unlisted template; inclusive care period conflicts trigger pre-op or post-op template.
- **Structured prompted fields:** each scenario presents specific fields. Post-op complication: original procedure code [auto-populated], date [auto-populated], nature of complication [free text], clinical findings [free text], treatment provided [free text].
- **Formatted text generation:** combine field entries into structure Alberta Health assessors expect. Editable by physician before submission.
- **Required field validation:** all required template fields must be completed before submission.
- **Personal template saving:** physician saves completed justification for reuse. Modify patient-specific details in future cases.
- **Auto-population:** linked claims auto-populate original procedure details (code, date, description).
- **Justification history:** searchable by scenario type and service code. `GET /api/v1/claims/justifications/history`.

#### 4.4.5 API Contracts

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/reference/justification-templates` | List all justification template definitions. Filter by `scenario`. |
| GET | `/api/v1/reference/justification-templates/{id}` | Get a specific template with field definitions. |
| POST | `/api/v1/claims/{claimId}/justification` | Create/update justification for a claim. Body: `{ templateId?, scenario, fieldValues, generatedText }`. |
| GET | `/api/v1/claims/{claimId}/justification` | Get justification for a claim. |
| GET | `/api/v1/claims/justifications/history` | Search justification history. Query: `scenario`, `serviceCode`, `page`, `pageSize`. |
| POST | `/api/v1/claims/justifications/{id}/save-personal` | Save a justification as a personal reusable template. |

---

## 5. Intelligence Engine Extensions

### 5.1 Revenue Optimisation Alerts — Remaining Gaps

**Addresses gap B4.** Priority: P2.

#### 5.1.1 Unbilled WCB Opportunity Alert

New Tier 1 rule:

- **Name:** `UNBILLED_WCB_OPPORTUNITY`
- **Category:** `MISSED_BILLING`
- **Condition:** patient has an active WCB claim number in Meritum AND an AHCIP claim is being submitted for the same patient
- **Suggestion:** "This patient has an active WCB claim ({wcbClaimNumber}). Should this service be billed to WCB instead?"
- **Priority:** HIGH (potential full fee recovery — WCB typically pays higher than AHCIP for the same codes)

Rule definition added to `apps/api/src/domains/intel/intel.seed.ts`.

#### 5.1.2 Periodic Summary Digests

- Scheduled job (weekly, configurable) aggregates suggestions across all claims for the billing period.
- Produces a digest object per provider: total suggestions generated, total accepted, total revenue impact, top categories.
- Digest delivered via:
  - Dashboard summary widget (Domain 8: Analytics)
  - Weekly email digest (Domain 9: Notification Service, event type `INTEL_WEEKLY_DIGEST`)
- Digest job: `apps/api/src/domains/intel/intel.digest.service.ts`

#### 5.1.3 Estimated Revenue Impact Display

- Per-alert revenue impact is already computed via `revenue_impact_formula` on the rule.
- Frontend integration needed: display `revenue_impact` value alongside each suggestion card in the claim form.
- Aggregate revenue impact displayed in the import summary for Connect Care imports (total additional revenue from applied modifiers).

#### 5.1.4 One-Click Apply from Alert

- The `POST /api/v1/intelligence/suggestions/{id}/accept` endpoint exists and applies `suggested_changes` to the claim.
- Frontend integration needed: inline "Apply" button on each suggestion card. On click → call accept endpoint → update claim fields → refresh validation.

---

### 5.2 Bedside-Contingent Rule Enhancement

**Addresses gap B4a.** Priority: P2.

This is architecturally significant. The ~12 rules that depend on clinical context captured at the bedside (BMI, COMP, BILAT, URGN, AFHR, NGHT, ASST, CMXP, CALD, Multiple Calls, Facility Surcharge, Counselling Add-On) currently fire on bare eligibility with soft "may apply" language, creating alert fatigue.

#### 5.2.1 Three-Tier Confidence Model

| Tier | Condition | Behaviour | Example |
|------|-----------|-----------|---------|
| **A — Deterministic** | System has enough data to know the answer: shift timestamps, weekend/holiday date, Connect Care multi-row encounter | **Auto-apply** modifier. Show in import summary as "applied." | AFHR auto-applied because shift encounter logged at 18:32. |
| **B — High-confidence** | Physician's historical acceptance rate > 70% AND `times_shown >= 5` (from `ai_provider_learning`) | **Pre-apply** modifier as opt-out recommendation. Physician removes if inapplicable. | COMP pre-applied because physician accepts it 85% of the time on 03.04A. |
| **C — Low-confidence** | Acceptance rate 30–70%, or insufficient history (`times_shown < 5`) | **Surface as suggestion** (current behaviour). No pre-application. | "This visit may qualify for CMGP — did the encounter exceed 15 minutes?" |
| **Don't fire** | Acceptance rate < 30% AND `times_shown >= 10` | **Suppress entirely.** Stronger than the current 5-dismissal threshold for these specific rules. | Rule suppressed because physician has accepted only 2 of 15 showings. |

#### 5.2.2 Implementation: Rule Evaluation Flow

Modify the rule evaluation flow in `apps/api/src/domains/intel/intel.service.ts`:

```
For each bedside-contingent rule:
  │
  ├─ 1. Check Tier A signals:
  │     ├─ claim.importSource == 'CONNECT_CARE_CSV' or 'CONNECT_CARE_SFTP'?
  │     ├─ claim.shiftId IS NOT NULL? (shift encounter data available)
  │     ├─ Is date a weekend/holiday? (deterministic from calendar)
  │     └─ Multiple SCC rows for same patient+date? (multi-row encounter)
  │     If ANY Tier A signal matches → TIER_A (auto-apply)
  │
  ├─ 2. If no Tier A signal, check learning state:
  │     ├─ Query ai_provider_learning for (provider_id, rule_id)
  │     ├─ If times_shown < 5 → TIER_C (suggestion, insufficient data)
  │     ├─ Calculate acceptance_rate = times_accepted / times_shown
  │     ├─ If acceptance_rate > 0.70 → TIER_B (pre-apply)
  │     ├─ If acceptance_rate 0.30–0.70 → TIER_C (suggestion)
  │     └─ If acceptance_rate < 0.30 AND times_shown >= 10 → SUPPRESS
  │
  └─ 3. Generate suggestion with assigned tier
        ├─ TIER_A: suggested_changes applied to claim, status = 'ACCEPTED' (auto)
        ├─ TIER_B: suggested_changes included, marked as pre-applied (opt-out)
        ├─ TIER_C: suggested_changes included, status = 'PENDING'
        └─ SUPPRESS: no suggestion generated
```

#### 5.2.3 Data Model Extension

Add to the `ai_rules` table:

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| is_bedside_contingent | BOOLEAN | No | True for the ~12 rules requiring bedside context. Default false. |
| confidence_tier_overrides | JSONB | Yes | Maps data-availability signals to tier assignments. E.g. `{ "shiftEncounterAvailable": "A", "weekendHoliday": "A", "multiRowEncounter": "A" }` |

Add to the `ai_provider_learning` table:

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| auto_applied_count | INTEGER | No | Times this rule was auto-applied (Tier A) for this physician. Default 0. |
| pre_applied_count | INTEGER | No | Times this rule was pre-applied (Tier B). Default 0. |
| pre_applied_removed_count | INTEGER | No | Times physician removed a pre-applied modifier (Tier B opt-out). Default 0. |

#### 5.2.4 Learning Loop Adjustment for Bedside Rules

- Tier A auto-applications are tracked in `auto_applied_count` but do **not** affect `times_shown` or acceptance rate (the system applied them, not the physician).
- Tier B pre-applications where the physician **keeps** the modifier → increment `times_accepted`.
- Tier B pre-applications where the physician **removes** the modifier → increment `pre_applied_removed_count` and `times_dismissed`. If removal rate > 50% over last 10 pre-applications, demote rule to Tier C for this physician.
- Tier C follows existing learning loop behaviour.

---

## 6. Provider Management Extensions

### 6.1 ARP/APP Shadow Billing — Remaining Gaps

**Addresses gap B5.** Priority: P1.

#### 6.1.1 ARP BA Type Labelling

During onboarding (Domain 11), the physician labels each BA with its type. Add to `business_arrangements` table:

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| ba_subtype | VARCHAR(30) | Yes | For ARP BAs: ANNUALISED, SESSIONAL, BCM. NULL for FFS. |

The `ba_type` column (existing: 'FFS', 'PCPCM', 'LOCUM') is extended to include 'ARP'. Combined with `ba_subtype`, this gives full classification:

| ba_type | ba_subtype | Label |
|---------|-----------|-------|
| FFS | NULL | FFS |
| ARP | ANNUALISED | ARP Annualised |
| ARP | SESSIONAL | ARP Sessional |
| ARP | BCM | ARP BCM |
| PCPCM | NULL | PCPCM |
| LOCUM | NULL | Locum |

#### 6.1.2 ARP S-Code Restriction

ARP S-codes are only available when the selected BA is an ARP BA:

- Service code search/lookup filters: if selected BA has `ba_type = 'ARP'`, include S-codes in results. Otherwise, exclude S-codes.
- If physician manually enters an S-code with a non-ARP BA selected → validation error: "S-codes are only available under an ARP Business Arrangement."

#### 6.1.3 ARP-Specific Analytics

Extensions to Domain 8 (Analytics & Reporting):

- **ARP dashboard section/filter:** total ARP claims, total TM units, rejection rate, assessment results. Filtered separately from FFS.
- **TM summary report:** per billing period, total time units by date and service type. Supports physician's ARP program reporting obligations.
- Report endpoint: `GET /api/v1/analytics/arp-summary?period={period}` (see API contracts below).

#### 6.1.4 API Contracts

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/analytics/arp-summary` | ARP-specific analytics summary. Query: `period` (this_month, last_month, custom). Returns total claims, TM units, rejection rate. |
| GET | `/api/v1/analytics/arp-tm-report` | TM summary report per billing period. Query: `startDate`, `endDate`. Returns time units by date and service type. |

---

### 6.2 Mixed FFS/ARP Smart Routing

**Addresses gap B10.** Priority: P1.

#### 6.2.1 Facility-BA Mapping

During onboarding (or via provider settings), the physician maps each BA to facility codes / practice locations.

**Table:** `ba_facility_mappings` (in `packages/shared/src/schemas/db/providers.schema.ts`)

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| mapping_id | UUID | No | Primary key |
| provider_id | UUID FK | No | Physician |
| ba_id | UUID FK | No | FK to business_arrangements |
| location_id | UUID FK | No | FK to practice_locations |
| is_active | BOOLEAN | No | Soft delete. Default true. |
| created_at | TIMESTAMPTZ | No | Default now() |
| updated_at | TIMESTAMPTZ | No | Default now() |

**Constraint:** Unique `(provider_id, location_id)` — one location maps to one BA at a time.

#### 6.2.2 Time-Based Routing Schedule

**Table:** `ba_schedule_mappings` (in `packages/shared/src/schemas/db/providers.schema.ts`)

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| schedule_mapping_id | UUID | No | Primary key |
| provider_id | UUID FK | No | Physician |
| ba_id | UUID FK | No | FK to business_arrangements |
| day_of_week | INTEGER | No | 0 (Sunday) through 6 (Saturday) |
| start_time | TIME | Yes | Start of BA-applicable window (NULL = all day) |
| end_time | TIME | Yes | End of BA-applicable window |
| is_active | BOOLEAN | No | Soft delete. Default true. |
| created_at | TIMESTAMPTZ | No | Default now() |
| updated_at | TIMESTAMPTZ | No | Default now() |

#### 6.2.3 Routing Priority

During claim creation, the system auto-selects the BA using this priority chain:

1. **Service code type:** ARP S-code → force ARP BA. No override.
2. **Facility code mapping:** claim facility code → lookup `ba_facility_mappings` → select mapped BA.
3. **Schedule mapping:** claim date of service → day-of-week + time → lookup `ba_schedule_mappings` → select mapped BA.
4. **Primary BA fallback:** physician's designated primary BA.

If auto-selected, the BA is displayed prominently on the claim form: "Billing under: {BA label} — {facility name}". One-click change available.

#### 6.2.4 Routing Conflict Warning

If physician manually selects a BA that conflicts with contextual routing logic (e.g. FFS BA for a claim at an ARP-mapped facility), display warning: "This facility is mapped to your {mappedBaLabel} BA. Are you sure you want to bill under {selectedBaLabel}?" Physician confirms or changes.

#### 6.2.5 Weekly Mis-Routing Summary

A weekly scheduled job identifies potential mis-routed claims:

- FFS claims at ARP-mapped facilities
- ARP claims at FFS-mapped facilities
- Claims where routing override was used

Generates a notification (Domain 9, event type `ROUTING_MISROUTE_SUMMARY`) with claim list.

#### 6.2.6 Functional Requirements

- Routing configuration editable at any time via provider settings. Changes apply to new claims only.
- Existing claims are not retroactively re-routed.
- Configuration UI: `apps/web/src/app/settings/routing/page.tsx`

#### 6.2.7 API Contracts

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/providers/me/routing-config` | Get current routing configuration (facility mappings + schedule mappings). |
| PUT | `/api/v1/providers/me/routing-config/facilities` | Update facility-BA mappings. Body: `{ mappings: { locationId, baId }[] }`. |
| PUT | `/api/v1/providers/me/routing-config/schedule` | Update schedule-BA mappings. Body: `{ mappings: { baId, dayOfWeek, startTime?, endTime? }[] }`. |
| POST | `/api/v1/claims/routing/resolve` | Resolve BA for a claim context. Body: `{ serviceCode, facilityCode?, dateOfService }`. Returns `{ baId, baLabel, routingReason }`. |

---

## 7. Consolidated Data Model

### 7.1 New Tables

| Table | Domain | Description |
|-------|--------|-------------|
| `provider_registry` | Reference (Domain 2) | Searchable Alberta Health provider registry for referral lookup |
| `recent_referrers` | Claims (Domain 4.0) | Per-physician recently-used referral providers |
| `billing_guidance` | Reference (Domain 2) | Structured in-app billing guidance content |
| `eligibility_cache` | Patients (Domain 6) | Cached H-Link eligibility check results (24h TTL) |
| `provincial_phn_formats` | Reference (Domain 2) | Provincial health number format definitions |
| `reciprocal_billing_rules` | Reference (Domain 2) | Per-province reciprocal billing rules and exclusions |
| `claim_templates` | Claims (Domain 4.0) | Physician's saved claim templates |
| `anesthesia_rules` | Reference (Domain 2) | GR 12 anesthesia calculation rules |
| `bundling_rules` | Reference (Domain 2) | Code-pair bundling/unbundling matrix |
| `justification_templates` | Reference (Domain 2) | Text justification template definitions (5 scenarios) |
| `claim_justifications` | Claims (Domain 4.0) | Justification text attached to claims |
| `ba_facility_mappings` | Providers (Domain 5) | BA-to-facility routing configuration |
| `ba_schedule_mappings` | Providers (Domain 5) | BA-to-day/time routing schedule |

### 7.2 Modified Tables

| Table | Changes | Description |
|-------|---------|-------------|
| `business_arrangements` | Add `ba_subtype VARCHAR(30)` | ARP subtype: ANNUALISED, SESSIONAL, BCM |
| `ai_rules` | Add `is_bedside_contingent BOOLEAN`, `confidence_tier_overrides JSONB` | Confidence-tiered firing for bedside rules |
| `ai_provider_learning` | Add `auto_applied_count INT`, `pre_applied_count INT`, `pre_applied_removed_count INT` | Tracking for Tier A/B auto/pre-application |

---

## 8. Security

### 8.1 Physician Tenant Isolation

- All new tables with `provider_id` enforce scoping at the repository layer: `WHERE provider_id = ctx.providerId`.
- `claim_templates`, `recent_referrers`, `claim_justifications`, `ba_facility_mappings`, `ba_schedule_mappings`, `eligibility_cache` are all provider-scoped.
- `provider_registry`, `billing_guidance`, `provincial_phn_formats`, `reciprocal_billing_rules`, `bundling_rules`, `justification_templates`, `anesthesia_rules` are shared reference data — no provider scoping needed (read-only for physicians, admin-managed).
- Cross-provider access returns 404, not 403.

### 8.2 PHI Handling

- **Eligibility cache:** stores PHN as a SHA-256 hash, not plaintext. Response metadata from H-Link contains no PHI.
- **PHN masking:** all application logs mask PHN as `123******`.
- **Reciprocal billing:** out-of-province health numbers receive the same masking and encryption-at-rest treatment as Alberta PHNs.
- **Justification text:** may contain clinical details (complication descriptions, treatment details). Stored encrypted at rest. Not included in email notifications. Not exposed in error responses.
- **No PHI in billing guidance content.** Guidance is generic reference material.

### 8.3 Audit Logging

| Audit Event | Trigger |
|-------------|---------|
| `ELIGIBILITY_CHECK_PERFORMED` | H-Link eligibility inquiry executed |
| `ELIGIBILITY_OVERRIDE` | Physician overrides failed eligibility |
| `TEMPLATE_CREATED` / `TEMPLATE_UPDATED` / `TEMPLATE_DELETED` | Claim template lifecycle |
| `JUSTIFICATION_CREATED` / `JUSTIFICATION_UPDATED` | Text justification attached to claim |
| `BUNDLING_OVERRIDE` | Physician overrides bundling recommendation |
| `ANESTHESIA_OVERRIDE` | Physician overrides calculated anesthesia benefit |
| `ROUTING_OVERRIDE` | Physician overrides auto-selected BA |
| `ROUTING_CONFIG_UPDATED` | Facility or schedule routing configuration changed |
| `CONFIDENCE_TIER_AUTO_APPLIED` | Tier A bedside rule auto-applied modifier |
| `CONFIDENCE_TIER_PRE_APPLIED` | Tier B bedside rule pre-applied modifier |
| `CONFIDENCE_TIER_PRE_REMOVED` | Physician removed Tier B pre-applied modifier |

---

## 9. Testing Requirements

### 9.1 Unit Tests

**Referral Search:**
- Search by last name → matching results returned
- Search by Practitioner ID (partial) → matching results
- Only active providers in default results
- Recent referrers ordered by last_used_at

**Eligibility:**
- Valid Alberta PHN format → pass format check
- Invalid Luhn → fail format check
- Cache hit within 24h → return cached result
- Cache miss → perform H-Link inquiry
- Override recorded with audit entry

**Templates:**
- Create template with multi-line items → stored correctly
- Apply template → claim pre-populated with all fields
- Quick Bill → claim created and optionally submitted
- Specialty starter templates seeded during onboarding

**Anesthesia:**
- Single procedure → correct benefit lookup
- Multiple procedures → major identified, reductions applied
- Compound fracture with debridement → 50% uplift
- Skin lesion <35 min → single benefit cap enforced
- Manual override → logged

**Bundling:**
- Bundled pair on AHCIP claim → higher-value identified, lower flagged
- Same pair on WCB claim → independent billing at 100%
- Inclusive care period conflict → alert generated
- Multiple procedure reduction → correct percentage applied

**Text Justification:**
- Post-op complication → original procedure auto-populated from linked claim
- All required fields validated before submission
- Generated text matches expected format

**Bedside-Contingent Rules (B4a):**
- Shift encounter available → Tier A auto-apply
- Weekend date → Tier A auto-apply
- Acceptance rate >70%, times_shown >= 5 → Tier B pre-apply
- Acceptance rate 30–70% → Tier C suggestion
- Acceptance rate <30%, times_shown >= 10 → suppressed
- Tier B removal → updates pre_applied_removed_count

**Smart Routing:**
- ARP S-code → forces ARP BA
- Facility code match → correct BA selected
- Schedule match → correct BA selected
- No match → primary BA fallback
- Manual override → warning displayed

**Reciprocal Billing:**
- Alberta PHN (9 digits, valid Luhn) → detected as AB
- BC PHN (10 digits) → detected as BC
- Quebec PHN (4 letters + 8 digits) → triggers private billing redirect
- Ambiguous format → LOW confidence, province selector offered

### 9.2 Integration Tests

- Referral search → select → claim populated → submit → GR 8 validation passes
- Eligibility check → ineligible → override → claim submittable with warning
- Template create → apply → edit → submit → claim lifecycle complete
- Bundling check during multi-code claim → warning displayed → physician adjusts
- Justification attached → claim submission includes text → audit recorded
- Smart routing with facility mapping → correct BA auto-selected
- Reciprocal claim with ON PHN → province tagged → submit via H-Link

### 9.3 Security Tests

All security tests located in `apps/api/test/security/` under the respective domain subdirectory.

#### Authentication Enforcement (`authn`)
- Every new endpoint returns 401 without session (all 30+ endpoints across this FRD)

#### Authorization (`authz`)
- Delegate without `CLAIM_CREATE` → 403 on template apply, justification create
- Delegate with `CLAIM_VIEW` → 200 on template list, referral search
- Admin-only endpoints (guidance CRUD, reference data management) → 403 for physician

#### Tenant Isolation (`scoping`)
- Physician 1's templates not visible to Physician 2
- Physician 1's recent referrers not visible to Physician 2
- Physician 1's justification history not visible to Physician 2
- Physician 1's routing config not accessible by Physician 2
- Physician 1's eligibility cache not accessible by Physician 2

#### Input Validation (`input`)
- SQL injection in search queries (referral search, guidance search) → blocked
- XSS in template names, justification text → sanitised
- Non-UUID path parameters → 400
- Negative values in anesthesia time fields → 400
- Invalid province codes → 400

#### Data Leakage (`leakage`)
- Eligibility check errors do not echo PHN in response
- Justification text not included in error responses
- 500 errors expose no internal details
- PHN masked in audit logs

#### Audit Trail (`audit`)
- Eligibility check → audit entry
- Eligibility override → audit entry with reason
- Template CRUD → audit entries
- Justification CRUD → audit entries
- Bundling/anesthesia/routing overrides → audit entries
- Tier A/B auto/pre-application → audit entries

---

## 10. Open Questions

| # | Question | Context |
|---|----------|---------|
| 1 | What is the data source and licensing for the Alberta Health Provider Registry? | B1 requires provider registry data. Confirm whether H-Link inquiry or a bulk data distribution is available. |
| 2 | What H-Link transaction type supports real-time eligibility inquiry? | B2 depends on this. Confirm availability and response format. If not available at launch, fallback mode applies. |
| 3 | How frequently does AHS update the provider registry? | Determines whether monthly refresh is sufficient or more frequent updates are needed. |
| 4 | What is the CIHI licensing model for the ICD-10-CA to ICD-9 crosswalk? | A3 (covered in MHT-FRD-CC-001) and B12 both depend on this. Confirm whether Meritum can distribute the crosswalk data. |
| 5 | Should reciprocal billing auto-detection be opt-in or always-on? | Some physicians may prefer to always manually specify province. A toggle in settings may be appropriate. |
| 6 | What is the exact reduction schedule for secondary anesthesia procedures? | B7 references "SOMB-defined reduced rate" but the exact percentage varies by procedure category. Need GR 12 structured data. |
| 7 | Should templates be shareable between physicians? | Current spec is provider-scoped. Future enhancement could allow template sharing within a practice. |
| 8 | How should the bundling engine handle codes not in the bundling matrix? | If a code pair is not in the matrix, should it be treated as INDEPENDENT or flagged for manual review? |
| 9 | Should the confidence-tier thresholds (70%, 30%, 10 showings) be configurable per physician? | Different physicians may have different tolerance for pre-applied modifiers. A settings option could allow personalisation. |
| 10 | What is the ARP S-code set composition? | B5 references "ARP S-codes" but the exact list needs confirmation from Alberta Health. |

---

## 11. Document Control

| Item | Value |
|------|-------|
| Parent documents | MHT-FUNC-MVP-002 (MVP Feature Set), MHT-GAP-MVP-001 (Part B) |
| Feature scope | Cross-domain addendum: Reference Data (Domain 2), Claims (Domain 4.0), Provider Management (Domain 5), Patient Registry (Domain 6), Intelligence Engine (Domain 7) |
| Version | 1.0 |
| Date | 25 February 2026 |
| Author | Engineering |
| Status | DRAFT |
| Gap analysis items | B1, B2, B3, B4, B4a, B5, B6, B7, B8, B9, B10, B11, B12 |

---

*End of Document*
