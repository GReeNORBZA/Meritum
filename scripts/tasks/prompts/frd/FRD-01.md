# Task FRD-01: Update Domain 1 (Identity & Access Management) FRD

## Objective

Read the current Domain 1 FRD and the actual implementation code, then update the FRD in-place to accurately reflect what was built. Fold in new functionality from supplementary specifications.

## Step 1: Read Current FRD

Read the full file:
- `docs/frd/extracted/Meritum_Domain_01_Identity_Access_1.md`

## Step 2: Read Implementation

Read these files to understand what was actually built:

**Domain module:**
- `apps/api/src/domains/iam/iam.routes.ts`
- `apps/api/src/domains/iam/iam.handlers.ts`
- `apps/api/src/domains/iam/iam.service.ts`
- `apps/api/src/domains/iam/iam.repository.ts`

**Shared schemas and constants:**
- `packages/shared/src/constants/iam.constants.ts`
- `packages/shared/src/schemas/iam.schema.ts`

**Database schema (if exists):**
- `packages/shared/src/schemas/db/iam.schema.ts`

## Step 3: Read Supplementary Specs

Read these files for new functionality to fold into this domain's FRD:

**Pricing Gap Closure (Section: Batch 1 — PRACTICE_ADMIN role):**
- `docs/frd/extracted/Meritum_Pricing_Gap_Closure_Spec.md`
  - Focus on: PRACTICE_ADMIN role definition, permissions (seat view/manage, invoice view, settings edit — NO claim/patient/analytics access)

**IMA Legal Requirements (multiple features):**
- Read the task manifest for context on IMA changes: `scripts/tasks/ima-legal-requirements.tasks`
  - Focus on: secondary email on users table, IMA amendment system, breach notification system, PHI read-access audit logging on GET routes, patient correction audit trail

## Step 4: Key Changes to Incorporate

Compare the FRD against the implementation and update for these known changes:

1. **PRACTICE_ADMIN role** — New role added for clinic/practice tier. Limited permissions: seat management, invoice viewing, settings editing. Explicitly NO access to claims, patients, or analytics. This is a Domain 1 auth concern because it's a new entry in the RBAC model.

2. **Secondary email** — New `secondary_email` column on users table. Used for dual-delivery of critical notifications (IMA amendments, breach notifications). Requires verification flow.

3. **IMA amendment system** — New tables: `ima_amendments`, `amendment_responses`. Amendments gate access (blocking middleware) until acknowledged. Amendment lifecycle: DRAFT → PUBLISHED → acknowledged by each physician.

4. **Breach notification system** — New tables: `breach_records`, `breach_affected_custodians`, `breach_updates`, `data_destruction_tracking`. 72-hour OIPC notification compliance. Admin-only routes. Evidence hold on affected data.

5. **PHI read-access audit logging** — GET routes across all domains now produce audit records for PHI access (not just state changes). This is a cross-cutting concern wired through Domain 1 middleware.

6. **Audit action identifiers** — Check the constants file for the full list of audit actions. The FRD may list fewer than what was implemented.

7. **Permission keys** — Check the constants file for the complete permission set. New permissions may have been added for practice management, IMA, breach, and export features.

8. **Password hashing parameters** — Verify the FRD matches the implementation (Argon2id with specific memory/iterations/parallelism settings from `@node-rs/argon2`).

## Step 5: Write Updated FRD

Write the complete updated FRD to: `docs/frd/extracted/Meritum_Domain_01_Identity_Access_1.md`

### Format Rules

- Preserve the existing section structure, heading hierarchy, and numbered sections
- Maintain the formal, regulatory-aware writing style with "Design note:" blocks
- Keep all HIA, FOIP, and PIPEDA regulatory references
- Add new sections for PRACTICE_ADMIN role, IMA amendments, breach notification, secondary email
- Update the roles & permissions model section to include all implemented roles and permissions
- Update the data model section to include all implemented tables and columns
- Update the API contracts section to include all implemented endpoints
- Update audit action identifiers to match the full implemented set
- Do not add TODO/TBD/placeholder content — only document what is implemented
- Mark significant changes from the original FRD with "Updated:" annotations in the first instance, then write naturally

When complete, output on its own line: [TASK_COMPLETE]
If blocked, output: [TASK_BLOCKED] reason: <explanation>
