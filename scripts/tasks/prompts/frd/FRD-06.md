# Task FRD-06: Update Domain 4.2 (WCB Claim Pathway) FRD

## Objective

Read the current Domain 4.2 FRD and the actual implementation, then update the FRD in-place. This is the largest FRD file (~92KB) so focus on accuracy of implemented features versus documented spec.

## Step 1: Read Current FRD

Read the full file:
- `docs/frd/extracted/Meritum_Domain_04_2_WCB_Claim_Pathway.md`

## Step 2: Read Implementation

**Domain module:**
- `apps/api/src/domains/wcb/wcb.routes.ts`
- `apps/api/src/domains/wcb/wcb.handlers.ts`
- `apps/api/src/domains/wcb/wcb.service.ts`
- `apps/api/src/domains/wcb/wcb.repository.ts`
- `apps/api/src/domains/wcb/wcb.schema.ts`

**Shared schemas and constants:**
- `packages/shared/src/constants/wcb.constants.ts`
- `packages/shared/src/schemas/wcb.schema.ts`

**Database schema:**
- `packages/shared/src/schemas/db/wcb.schema.ts` (if exists)

**Test files:**
- `apps/api/src/domains/wcb/wcb.test.ts`

## Step 3: Read Supplementary Specs

**Connect Care Integration (WCB SCC format):**
- `docs/frd/extracted/Meritum_Connect_Care_Integration.md`
  - Focus on: 13-field WCB SCC extract format, WCB-specific import routing

**MVP Features Addendum (WCB-relevant features):**
- `docs/frd/extracted/Meritum_MVP_Features_Addendum.md`
  - B9: Multi-Procedure Bundling — WCB-specific unbundling exceptions
  - B11: Text Justification Templates — WCB narrative scenario

## Step 4: Key Changes to Incorporate

1. **8 form types** — Verify all 8 WCB form types are documented with correct field counts: C050E (initial short), C050S (initial comprehensive), C053E/S (progress short/comprehensive), C086 (surgery), C137 (return to work), C138 (fitness to work), C139 (specialist referral).

2. **HL7 v2.3.1 XML batching** — Verify the FRD accurately describes the XML batch generation process per WCB specification.

3. **Timing tiers** — Verify the 4-tier timing multiplier system: Tier 1 (0-24 days, 1.0x), Tier 2 (25-56 days, 0.85x), Tier 3 (57-112 days, 0.70x), Tier 4 (113+ days, 0.55x).

4. **Consultation categories** — Check `wcb.constants.ts` for consultation category definitions. These may be more detailed than the original FRD.

5. **Fee schedule** — Check the WCB fee schedule implementation for any differences from the documented spec.

6. **Validation engine** — Check for WCB-specific validation rules (form completeness, required fields per form type, OIS appendix requirements).

7. **WCB-specific unbundling** — If implemented from MVP Addendum B9: code-pair exceptions where WCB allows separate billing for procedures bundled under AHCIP.

8. **WCB narrative justification** — If implemented from MVP Addendum B11: structured narrative text fields for WCB claims.

9. **Connect Care WCB import** — If WCB claims can be created from Connect Care SCC imports, document the routing logic.

## Step 5: Write Updated FRD

Write the complete updated FRD to: `docs/frd/extracted/Meritum_Domain_04_2_WCB_Claim_Pathway.md`

### Format Rules

- Preserve existing section structure — this is a large, detailed document
- Maintain the formal, regulatory-aware writing style
- Update form type documentation if implementation differs
- Update fee schedule, timing tiers, and validation rules to match implementation
- Add sections for any new functionality (unbundling exceptions, narrative justification, Connect Care import routing)
- Update data model and API contracts
- Do not add TODO/TBD/placeholder content

When complete, output on its own line: [TASK_COMPLETE]
If blocked, output: [TASK_BLOCKED] reason: <explanation>
