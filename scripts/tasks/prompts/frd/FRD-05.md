# Task FRD-05: Update Domain 4.1 (AHCIP Claim Pathway) FRD

## Objective

Read the current Domain 4.1 FRD and the actual implementation, then update the FRD in-place to reflect what was built.

## Step 1: Read Current FRD

Read the full file:
- `docs/frd/extracted/Meritum_Domain_04_1_AHCIP_Claim_Pathway.md`

## Step 2: Read Implementation

**Domain module:**
- `apps/api/src/domains/ahcip/ahcip.routes.ts`
- `apps/api/src/domains/ahcip/ahcip.handlers.ts`
- `apps/api/src/domains/ahcip/ahcip.service.ts`
- `apps/api/src/domains/ahcip/ahcip.repository.ts`
- `apps/api/src/domains/ahcip/ahcip.schema.ts`

**Shared schemas and constants:**
- `packages/shared/src/constants/ahcip.constants.ts`
- `packages/shared/src/schemas/ahcip.schema.ts`

**Database schema:**
- `packages/shared/src/schemas/db/ahcip.schema.ts` (if exists)

**Test files:**
- `apps/api/src/domains/ahcip/ahcip.test.ts`

## Step 3: Read Supplementary Specs

**MVP Features Addendum (AHCIP-relevant features):**
- `docs/frd/extracted/Meritum_MVP_Features_Addendum.md`
  - B5: ARP/APP Shadow Billing — ARP BA type labelling, S-code restriction, ARP-specific claim routing
  - B8: Reciprocal Billing — Out-of-province claim submission rules for AHCIP
  - B10: Mixed FFS/ARP Smart Routing — Facility-BA mapping, time-based routing schedules for claim pathway selection

**Connect Care Integration (AHCIP SCC format):**
- `docs/frd/extracted/Meritum_Connect_Care_Integration.md`
  - Focus on: 21-field AHCIP SCC extract format, AHCIP-specific import validation, ICD conversion for AHCIP claims

## Step 4: Key Changes to Incorporate

1. **After-hours detection** — Check `ahcip.constants.ts` for after-hours bracket definitions (AFHR, NGHT modifier eligibility windows). Verify the FRD documents the after-hours detection logic.

2. **Fee calculation** — Verify the FRD accurately describes how AHCIP fees are calculated from SOMB base rates + modifiers + RRNP.

3. **Assessment scoring** — Check the implementation for how H-Link assessment responses are parsed, scored, and mapped to human-readable explanatory codes.

4. **Batch processing** — Verify batch assembly rules (max claims per batch, Thursday cutoff, Wednesday reminder).

5. **PCPCM routing** — Verify the FRD describes the intelligent routing between PCPCM BA (capitation) and FFS BA based on service type, patient panel status, and code eligibility.

6. **ARP/APP shadow billing** — If implemented: ARP BA type labelling, S-code restrictions, shadow billing claim flow where claims are submitted but payment is not expected (used for tracking purposes).

7. **Reciprocal billing** — If implemented: out-of-province patient claim submission through AHCIP with province-specific rules.

8. **Mixed FFS/ARP routing** — If implemented: facility-BA mapping and time-based routing schedules that determine which BA receives a claim based on facility and time of service.

9. **Validation rules** — Check for AHCIP-specific validation rules, modifier eligibility, holiday-aware after-hours detection.

## Step 5: Write Updated FRD

Write the complete updated FRD to: `docs/frd/extracted/Meritum_Domain_04_1_AHCIP_Claim_Pathway.md`

### Format Rules

- Preserve existing section structure and formal writing style
- Update or add sections for any new functionality found in the implementation
- Ensure fee calculation, after-hours detection, and assessment parsing are fully documented
- Update data model and API contracts to match implementation
- Do not add TODO/TBD/placeholder content

When complete, output on its own line: [TASK_COMPLETE]
If blocked, output: [TASK_BLOCKED] reason: <explanation>
