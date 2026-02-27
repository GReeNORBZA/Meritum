# Task FRD-08: Update Domain 6 (Patient Registry) FRD

## Objective

Read the current Domain 6 FRD and the actual implementation, then update the FRD in-place. Fold in eligibility verification, reciprocal billing support, patient access request export, and correction audit trail.

## Step 1: Read Current FRD

Read the full file:
- `docs/frd/extracted/Meritum_Domain_06_Patient_Registry.md`

## Step 2: Read Implementation

**Domain module:**
- `apps/api/src/domains/patient/patient.routes.ts`
- `apps/api/src/domains/patient/patient.handlers.ts`
- `apps/api/src/domains/patient/patient.service.ts`
- `apps/api/src/domains/patient/patient.repository.ts`

**Shared schemas and constants:**
- `packages/shared/src/constants/patient.constants.ts`
- `packages/shared/src/schemas/patient.schema.ts`

**Database schema:**
- `packages/shared/src/schemas/db/patient.schema.ts` (if exists)

**Test files:**
- `apps/api/src/domains/patient/patient.test.ts`
- `apps/api/src/domains/patient/patient-eligibility.test.ts`

## Step 3: Read Supplementary Specs

**MVP Features Addendum (patient-related features):**
- `docs/frd/extracted/Meritum_MVP_Features_Addendum.md`
  - B2: PHN/Eligibility Verification — real-time H-Link eligibility checks, 24h cache, format validation per province
  - B8: Reciprocal Billing — provincial PHN format detection, out-of-province patient identification, province stored as 2-char code

**IMA Legal Requirements (patient rights):**
- Read: `scripts/tasks/ima-legal-requirements.tasks`
  - Phase 6: Patient access request export — cross-table patient health information queries, service and route implementation
  - Phase 2: Patient correction audit trail — diff tracking with correction_reason field

## Step 4: Key Changes to Incorporate

1. **Eligibility verification** — New feature confirmed by `patient-eligibility.test.ts`:
   - Real-time H-Link eligibility check by PHN
   - `eligibility_cache` table with 24h TTL
   - Validates coverage status, registration status, and eligibility dates
   - API endpoint for eligibility check (likely `GET /api/v1/patients/{id}/eligibility` or similar)

2. **Reciprocal billing (out-of-province)** — Province-aware patient handling:
   - Provincial PHN format detection (references `provincial_phn_formats` from Domain 2)
   - Province stored as 2-char code (AB default)
   - Out-of-province patients flagged for reciprocal billing pathway

3. **Patient access request export** — HIA compliance:
   - Patient can request their complete health information
   - Cross-table query joining claims, assessments, notes
   - Structured export format
   - Audit trail of access requests

4. **Correction audit trail** — HIA compliance:
   - Patient record corrections tracked with diff (old value → new value)
   - `correction_reason` field on correction records
   - Corrections append to history, never overwrite

5. **Patient merge** — Check if the implementation includes patient deduplication/merge logic (combining duplicate patient records).

6. **CSV import** — Verify the FRD accurately describes the CSV import workflow (column mapping, conflict resolution on PHN match, error reporting).

7. **Search** — Verify the FRD describes the pg_trgm fuzzy name search implementation.

## Step 5: Write Updated FRD

Write the complete updated FRD to: `docs/frd/extracted/Meritum_Domain_06_Patient_Registry.md`

### Format Rules

- Preserve existing section structure and formal writing style
- Add a new section for Eligibility Verification
- Add a section for Reciprocal Billing / Out-of-Province Patient Support
- Add a section for Patient Access Request Export (HIA compliance)
- Add a section for Correction Audit Trail (HIA compliance)
- Update data model with all new/modified tables
- Update API contracts with all new endpoints
- Include regulatory references (HIA) for the access request and correction features
- Do not add TODO/TBD/placeholder content

When complete, output on its own line: [TASK_COMPLETE]
If blocked, output: [TASK_BLOCKED] reason: <explanation>
