# Task FRD-09: Update Domain 7 (Intelligence Engine) FRD

## Objective

Read the current Domain 7 FRD and the actual implementation, then update the FRD in-place. Fold in the confidence-tiered rule model, revenue optimisation alerts, and import-sourced claim evaluation.

## Step 1: Read Current FRD

Read the full file:
- `docs/frd/extracted/Meritum_Domain_07_Intelligence_Engine.md`

## Step 2: Read Implementation

**Domain module:**
- `apps/api/src/domains/intel/intel.routes.ts`
- `apps/api/src/domains/intel/intel.handlers.ts`
- `apps/api/src/domains/intel/intel.service.ts`
- `apps/api/src/domains/intel/intel.repository.ts`
- `apps/api/src/domains/intel/intel.llm.ts`
- `apps/api/src/domains/intel/intel.digest.service.ts`
- `apps/api/src/domains/intel/intel.seed.ts`

**Shared schemas and constants:**
- `packages/shared/src/constants/intelligence.constants.ts`
- `packages/shared/src/schemas/intelligence.schema.ts`

**Database schema:**
- `packages/shared/src/schemas/db/intelligence.schema.ts` (if exists)

**Test files:**
- `apps/api/src/domains/intel/intel.test.ts`

## Step 3: Read Supplementary Specs

**MVP Features Addendum (intelligence-related features):**
- `docs/frd/extracted/Meritum_MVP_Features_Addendum.md`
  - B4: Revenue Optimisation Alerts — unbilled WCB opportunities, missing modifier detection
  - B4a: Bedside-contingent rule confidence-tiering — three-tier model:
    - Tier A: Deterministic (auto-apply) — rules with 100% confidence (e.g., after-hours modifier based on shift time)
    - Tier B: High-confidence (pre-apply with undo) — rules with >80% confidence
    - Tier C: Low-confidence (suggestion only) — rules with <80% confidence, shown as suggestions
  - Bedside-contingent rules: rules that fire based on shift encounter data from Mobile v2

**Mobile Companion v2 (Tier A signal source):**
- `docs/frd/extracted/Meritum_Mobile_Companion_v2.md`
  - Focus on: shift encounter data as input to Tier A deterministic signals (AFHR/NGHT modifiers based on encounter timestamps)

## Step 4: Key Changes to Incorporate

1. **Three-tier confidence model** — The original FRD describes 3 tiers (Rules Engine, LLM, Physician Review). The implementation extends this with a confidence-based application model:
   - Tier A: Deterministic auto-apply (no physician review needed, 100% confidence)
   - Tier B: High-confidence pre-apply (applied automatically but physician can undo)
   - Tier C: Low-confidence suggestion (shown to physician for review)
   Check `intelligence.constants.ts` for the exact confidence thresholds and tier definitions.

2. **Bedside-contingent rules** — Rules that fire based on shift encounter data rather than claim data alone. `is_bedside_contingent` flag on `ai_rules` table. `confidence_tier_overrides` field for per-rule tier customisation.

3. **Revenue optimisation alerts** — Proactive alerts for unbilled opportunities:
   - Unbilled WCB opportunities (patient with workplace injury, no WCB claim)
   - Missing modifiers (time-based modifiers not applied despite eligible service time)
   - Under-coded visits (suggest higher-value code based on documentation)

4. **Digest service** — `intel.digest.service.ts` suggests a digest/summary capability for AI suggestions. Check what this does (e.g., daily summary of accepted/dismissed suggestions, learning loop analytics).

5. **LLM integration** — `intel.llm.ts` handles the Tier 2 LLM integration. Verify the FRD describes: self-hosted model requirement (PHI containment), async post-save execution, confidence scores on responses.

6. **Seed rules** — `intel.seed.ts` contains the initial rule set. Check how many rules are seeded and whether the FRD documents the rule categories.

7. **Learning loop** — Verify the FRD accurately describes: accepted suggestions reinforce pattern, dismissed reduce confidence, suppressed rules never fire again for that physician. Check for `ai_provider_learning` table with auto/pre_applied tracking.

8. **Suggestion lifecycle** — Verify: PENDING → ACCEPTED / DISMISSED / SUPPRESSED / EXPIRED matches implementation.

## Step 5: Write Updated FRD

Write the complete updated FRD to: `docs/frd/extracted/Meritum_Domain_07_Intelligence_Engine.md`

### Format Rules

- Preserve existing section structure and formal writing style
- Update the tier model section to include the confidence-based application model (A/B/C)
- Add sections for bedside-contingent rules and revenue optimisation alerts
- Document the digest service
- Update data model with any new/modified tables (ai_rules additions, ai_provider_learning)
- Update API contracts
- Do not add TODO/TBD/placeholder content

When complete, output on its own line: [TASK_COMPLETE]
If blocked, output: [TASK_BLOCKED] reason: <explanation>
