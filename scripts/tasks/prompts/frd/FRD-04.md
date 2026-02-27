# Task FRD-04: Update Domain 4.0 (Claim Lifecycle Core) FRD

## Objective

Read the current Domain 4.0 FRD and the actual implementation, then update the FRD in-place. This domain has the most significant changes — the state machine expanded from 10 to 14 states, and major new features (Connect Care import, reconciliation, templates, anesthesia, bundling) were added.

## Step 1: Read Current FRD

Read the full file:
- `docs/frd/extracted/Meritum_Domain_04_0_Claim_Lifecycle_Core.md`

## Step 2: Read Implementation

**Domain module:**
- `apps/api/src/domains/claim/claim.routes.ts`
- `apps/api/src/domains/claim/claim.handlers.ts`
- `apps/api/src/domains/claim/claim.service.ts`
- `apps/api/src/domains/claim/claim.repository.ts`
- `apps/api/src/domains/claim/claim.schema.ts`
- `apps/api/src/domains/claim/connect-care-import.service.ts`
- `apps/api/src/domains/claim/reconciliation.service.ts`
- `apps/api/src/domains/claim/scc-parser.service.ts`

**Shared schemas and constants:**
- `packages/shared/src/constants/claim.constants.ts`
- `packages/shared/src/constants/scc.constants.ts`
- `packages/shared/src/schemas/claim.schema.ts`
- `packages/shared/src/schemas/scc.schema.ts`

**Database schema:**
- `packages/shared/src/schemas/db/claim.schema.ts` (if exists)

**Test files (for feature coverage insights):**
- `apps/api/src/domains/claim/claim.test.ts`
- `apps/api/src/domains/claim/claim-extensions.test.ts`
- `apps/api/src/domains/claim/connect-care-import.test.ts`
- `apps/api/src/domains/claim/reconciliation.test.ts`
- `apps/api/src/domains/claim/scc-parser.test.ts`

## Step 3: Read Supplementary Specs

**Connect Care Integration (SCC import, reconciliation):**
- `docs/frd/extracted/Meritum_Connect_Care_Integration.md`
  - Focus on: SCC parser (21-field AHCIP, 13-field WCB), import batch workflow, duplicate detection, correction/deletion handling, import_batches table, 7 new claim columns

**MVP Features Addendum (templates, anesthesia, bundling, justification):**
- `docs/frd/extracted/Meritum_MVP_Features_Addendum.md`
  - B3: Invoice Templates and Favourites — `claim_templates` table, quick-bill workflow
  - B7: Anesthesia Benefit Calculations — GR 12 rule engine integration with claim validation
  - B9: Multi-Procedure Bundling — code-pair matrix enforcement during validation, inclusive care period checks
  - B11: Text Justification Templates — `claim_justifications` table, 5 scenario types

**Mobile Companion v2 (reconciliation integration):**
- `docs/frd/extracted/Meritum_Mobile_Companion_v2.md`
  - Focus on: PHN+date+facility reconciliation matching, inferred service times, modifier annotations from shift data

## Step 4: Key Changes to Incorporate

1. **14-state machine** — The FRD documents 10 states. The implementation has 14. Check `claim.constants.ts` for the full state enum and all valid transitions. Document the complete state diagram.

2. **Connect Care SCC import** — Entire new subsystem:
   - SCC file parsing (21-field AHCIP format, 13-field WCB format)
   - Import batch workflow: upload → parse → preview → confirm → create draft claims
   - Row-level duplicate detection (PHN + date + code + provider composite key)
   - Correction/deletion handling for modified/deleted SCC charge statuses
   - 7 new columns on claims table: import_source, import_batch_id, raw_file_reference, scc_charge_status, icd_conversion_flag, icd10_source_code, shift_id
   - API endpoints: POST import, GET batch details, POST confirm

3. **Reconciliation service** — Matches mobile shift encounters against Connect Care SCC imports:
   - PHN + date + facility matching with 4 match categories
   - Full match: timestamp assigned from encounter
   - Unmatched SCC row: shift window inference
   - Unmatched encounter: missed billing alert
   - Shift-only: fallback to time window

4. **Claim templates and favourites** — Pre-built claim templates by specialty, quick-bill workflow for repeat patients + favourite codes

5. **Anesthesia calculations** — GR 12 integration in the validation engine. Base units + time units + modifiers + concurrent procedure rules.

6. **Bundling engine** — Code-pair matrix enforcement during claim validation. Inclusive care period checks. WCB-specific unbundling exceptions.

7. **Text justification** — Structured justification text attached to claims for 5 scenarios: unlisted codes, additional compensation, pre-op conservative, post-op complication, WCB narrative.

8. **Validation framework updates** — Check if the validation engine has new check types, severity levels, or rule categories beyond the original FRD.

## Step 5: Write Updated FRD

Write the complete updated FRD to: `docs/frd/extracted/Meritum_Domain_04_0_Claim_Lifecycle_Core.md`

### Format Rules

- Preserve existing section structure and formal writing style
- Update the state machine section with all 14 states and transitions
- Add a new major section for Connect Care SCC Import (subsystem within Domain 4.0)
- Add a new section for Reconciliation (shift encounter ↔ SCC import matching)
- Add sections for templates, anesthesia calculations, bundling, and text justification
- Update the data model with all new/modified tables and columns
- Update API contracts with all new endpoints
- Update the validation engine section with any new check types
- Do not add TODO/TBD/placeholder content

When complete, output on its own line: [TASK_COMPLETE]
If blocked, output: [TASK_BLOCKED] reason: <explanation>
