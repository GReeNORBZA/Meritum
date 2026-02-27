# Task FRD-12: Update Domain 11 (Onboarding) FRD

## Objective

Read the current Domain 11 FRD and the actual implementation, then update the FRD in-place. Check for Connect Care onboarding additions and IMA workflow updates.

## Step 1: Read Current FRD

Read the full file:
- `docs/frd/extracted/Meritum_Domain_11_Onboarding.md`

## Step 2: Read Implementation

**Domain module:**
- `apps/api/src/domains/onboarding/onboarding.routes.ts`
- `apps/api/src/domains/onboarding/onboarding.handlers.ts`
- `apps/api/src/domains/onboarding/onboarding.service.ts`
- `apps/api/src/domains/onboarding/onboarding.repository.ts`
- `apps/api/src/domains/onboarding/templates/ima.hbs`

**Shared constants:**
- `packages/shared/src/constants/onboarding.constants.ts`

**Test files:**
- `apps/api/src/domains/onboarding/onboarding.test.ts`

## Step 3: Read Supplementary Specs

**Mobile Companion v2 (Connect Care onboarding):**
- `docs/frd/extracted/Meritum_Mobile_Companion_v2.md`
  - C5: Connect Care onboarding — is_connect_care_user flag, SCC export guidance steps, mode selection

**IMA Legal Requirements:**
- Read: `scripts/tasks/ima-legal-requirements.tasks`
  - Focus on: IMA template updates, amendment acknowledgement flow, IMA version tracking

## Step 4: Key Changes to Incorporate

1. **7-step wizard** — Verify all 7 steps match the implementation: Professional identity → Specialty & type → Business arrangement → Practice location → WCB config → Submission preferences → IMA acknowledgement.

2. **IMA template** — `templates/ima.hbs` is a Handlebars template for the IMA document. Verify the FRD documents: pre-filling from physician data, digital acknowledgement with SHA-256 hash, timestamp, IP, user agent. PDF stored immutably.

3. **Connect Care onboarding** — If implemented: additional onboarding step or question asking if the physician uses Connect Care. Sets `is_connect_care_user` flag. Provides SCC export guidance (how to export "My Billing Codes" from Connect Care).

4. **IMA versioning** — Check if the implementation tracks IMA versions and handles re-acknowledgement when the IMA is amended.

5. **AHC11236 pre-fill** — Verify the FRD documents the Alberta Health BA linkage form pre-fill with physician + Meritum submitter details.

6. **Guided tour** — Check if the implementation includes a guided tour/walkthrough after onboarding completion.

7. **Onboarding progress tracking** — Verify the `onboarding_progress` table schema matches implementation.

8. **BA linkage verification** — Check the onboarding constants for BA linkage status tracking (PENDING, VERIFIED, etc.).

## Step 5: Write Updated FRD

Write the complete updated FRD to: `docs/frd/extracted/Meritum_Domain_11_Onboarding.md`

### Format Rules

- Preserve existing section structure and formal writing style
- Add Connect Care onboarding steps if implemented
- Update IMA section with template details and versioning
- Update data model and API contracts
- Do not add TODO/TBD/placeholder content

When complete, output on its own line: [TASK_COMPLETE]
If blocked, output: [TASK_BLOCKED] reason: <explanation>
