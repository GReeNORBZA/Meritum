# Task FRD-02: Update Domain 2 (Reference Data) FRD

## Objective

Read the current Domain 2 FRD and the actual implementation, then update the FRD in-place. Fold in significant new reference data sets from supplementary specifications.

## Step 1: Read Current FRD

Read the full file:
- `docs/frd/extracted/Meritum_Domain_02_Reference_Data.md`

## Step 2: Read Implementation

**Domain module:**
- `apps/api/src/domains/reference/reference.routes.ts`
- `apps/api/src/domains/reference/reference.handlers.ts`
- `apps/api/src/domains/reference/reference.service.ts`
- `apps/api/src/domains/reference/reference.repository.ts`
- `apps/api/src/domains/reference/icd-crosswalk.seed.ts`
- `apps/api/src/domains/reference/provincial-phn-formats.seed.ts`

**Shared schemas and constants:**
- `packages/shared/src/constants/reference.constants.ts`
- `packages/shared/src/schemas/reference.schema.ts`

**Database schema:**
- `packages/shared/src/schemas/db/reference.schema.ts` (if exists)

## Step 3: Read Supplementary Specs

**Connect Care Integration (ICD crosswalk):**
- `docs/frd/extracted/Meritum_Connect_Care_Integration.md`
  - Focus on: ICD-10-CA to ICD-9 crosswalk table, icd_crosswalk schema, lookup endpoints

**MVP Features Addendum (12 feature extensions with major reference data needs):**
- `docs/frd/extracted/Meritum_MVP_Features_Addendum.md`
  - B1: Referral Provider Search — `provider_registry` table, searchable Alberta Health provider directory, `recent_referrers` tracking
  - B2: PHN/Eligibility Verification — `eligibility_cache` table, H-Link real-time eligibility checks
  - B6: In-App Billing Guidance — `billing_guidance` table, SOMB tooltips, rejection hints, modifier guidance
  - B7: Anesthesia Benefit Calculations — `anesthesia_rules` table, GR 12 rule engine
  - B8: Reciprocal Billing — `provincial_phn_formats` table, `reciprocal_billing_rules` per province
  - B9: Multi-Procedure Bundling — `bundling_rules` table, code-pair matrix, inclusive care periods
  - B11: Text Justification Templates — `justification_templates` table, 5 scenario templates
  - B12: Shared Reference Data Dependencies — 12 data sets required across features

## Step 4: Key Changes to Incorporate

1. **ICD-10-CA to ICD-9 crosswalk** — New reference table mapping ICD-10 codes from Connect Care to ICD-9 codes used by AHCIP. Many-to-many mapping with confidence scores. Seed data from `icd-crosswalk.seed.ts`. API endpoint: `GET /api/v1/reference/icd-crosswalk/{icd10Code}`

2. **Provincial PHN formats** — New reference table with PHN validation rules per province (length, Luhn check, prefix patterns). Enables reciprocal (out-of-province) billing. Seed data from `provincial-phn-formats.seed.ts`.

3. **Provider registry** — Searchable Alberta Health provider directory for referral lookups. Provider number, name, specialty, location. Plus `recent_referrers` per physician for quick access.

4. **Billing guidance** — Structured reference data for in-app tooltips: SOMB code descriptions, common rejection reasons, modifier eligibility hints. Consumed by frontend for contextual help.

5. **Anesthesia rules** — GR 12 rule engine with 10+ calculation scenarios. Base units, time units, modifiers, concurrent procedure rules.

6. **Bundling rules** — Code-pair matrix defining which procedure combinations are bundled (inclusive care), which require unbundling, and WCB-specific unbundling exceptions.

7. **Reciprocal billing rules** — Per-province rules for out-of-province patient billing. Eligibility periods, fee schedule differences, submission requirements.

8. **Justification templates** — 5 template types: unlisted codes, additional compensation, pre-op conservative, post-op complication, WCB narrative. Stored as structured templates with variable interpolation.

9. **Admin staging/versioning** — Check if the implementation includes an admin workflow for staging reference data updates before publishing (versioned fee schedules with effective dates).

10. **Reference extensions tests** — The file `reference-extensions.test.ts` suggests additional reference data capabilities were tested. Check for features not in the original FRD.

## Step 5: Write Updated FRD

Write the complete updated FRD to: `docs/frd/extracted/Meritum_Domain_02_Reference_Data.md`

### Format Rules

- Preserve existing section structure and numbered headings
- Maintain the formal, regulatory-aware writing style
- Add new sections for each new reference data set (ICD crosswalk, provincial PHN formats, provider registry, billing guidance, anesthesia rules, bundling rules, reciprocal rules, justification templates)
- Each new reference data section should include: purpose, table schema, seed data source, API endpoints, consumed-by domains
- Update the data model section with all new tables
- Update API contracts with all new endpoints
- Update the "Consumed By" dependency map to reflect which domains use which reference data
- Do not add TODO/TBD/placeholder content

When complete, output on its own line: [TASK_COMPLETE]
If blocked, output: [TASK_BLOCKED] reason: <explanation>
