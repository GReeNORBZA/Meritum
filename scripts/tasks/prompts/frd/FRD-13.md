# Task FRD-13: Update Domain 12 (Platform Operations) FRD

## Objective

Read the current Domain 12 FRD and the actual implementation, then update the FRD in-place. This domain has the most supplementary spec content to fold in — the entire Pricing Gap Closure spec (5 batches), plus the referral program redesign, clinic/practice tier, and cancellation policies.

## Step 1: Read Current FRD

Read the full file:
- `docs/frd/extracted/Meritum_Domain_12_Platform_Operations.md`

## Step 2: Read Implementation

**Domain module (extensive — read all files):**
- `apps/api/src/domains/platform/platform.routes.ts`
- `apps/api/src/domains/platform/platform.handlers.ts`
- `apps/api/src/domains/platform/platform.service.ts`
- `apps/api/src/domains/platform/platform.repository.ts`
- `apps/api/src/domains/platform/practice.routes.ts`
- `apps/api/src/domains/platform/practice.handlers.ts`
- `apps/api/src/domains/platform/practice.service.ts`
- `apps/api/src/domains/platform/practice.repository.ts`
- `apps/api/src/domains/platform/cancellation.service.ts`
- `apps/api/src/domains/platform/export.repository.ts`
- `apps/api/src/domains/platform/export.service.ts`
- `apps/api/src/domains/platform/referral.repository.ts`
- `apps/api/src/domains/platform/referral.service.ts`
- `apps/api/src/domains/platform/practice-invitation.repository.ts`
- `apps/api/src/domains/platform/practice-membership.repository.ts`
- `apps/api/src/domains/platform/practice-stripe.service.ts`

**Shared schemas and constants:**
- `packages/shared/src/constants/platform.constants.ts`
- `packages/shared/src/schemas/platform.schema.ts`
- `packages/shared/src/schemas/compliance.schema.ts`

**Database schema:**
- `packages/shared/src/schemas/db/platform.schema.ts` (if exists)

**Test files:**
- `apps/api/src/domains/platform/platform.test.ts`
- `apps/api/src/domains/platform/practice.test.ts`
- `apps/api/src/domains/platform/cancellation.test.ts`
- `apps/api/src/domains/platform/referral.test.ts`
- `apps/api/src/domains/platform/practice-invitation.test.ts`
- `apps/api/src/domains/platform/practice-membership.test.ts`
- `apps/api/src/domains/platform/practice-stripe.test.ts`

**Pricing utilities:**
- `packages/shared/src/utils/pricing.utils.ts` (if exists)

## Step 3: Read Supplementary Specs

**Pricing Gap Closure (ALL 5 batches — this is the primary supplementary spec):**
- `docs/frd/extracted/Meritum_Pricing_Gap_Closure_Spec.md`
  - Batch 0: Pricing constant corrections ($3,181/year standard annual, $2,388/year early bird annual)
  - Batch 1: Clinic/Practice tier (5+ physician minimum, $251.10/month, PRACTICE_ADMIN role, seat management, hybrid billing, practice Stripe consolidation)
  - Batch 2: Pricing lifecycle (discount framework with 5%/10%/15% stacking ceiling at 85% minimum, 12-month early bird rate lock, automatic transition to standard/clinic on expiry)
  - Batch 3: Referral program redesign (1-month free credit, max 3/year, clinic credit destination choice: practice invoice or individual bank)
  - Batch 4: Policy alignment (6-month annual cancellation forfeit, prorated refund, clinic physician removal end-of-month, data portability export, PCPCM payment reconciliation)

## Step 4: Key Changes to Incorporate

1. **Pricing constants update** — Standard annual: $3,181/year (was $2,790). Early bird annual: $2,388/year (new). Clinic monthly: $251.10/month. Check `platform.constants.ts` for all current pricing.

2. **Clinic/Practice tier** — Entirely new subsystem:
   - `practices` table: multi-physician clinic entity
   - `practice_memberships` table: physician-to-practice relationships
   - `practice_invitations` table: invitation workflow
   - 5+ physician minimum requirement
   - Practice admin role (PRACTICE_ADMIN) with limited permissions
   - Consolidated Stripe subscription (quantity-based billing)
   - Hybrid billing for early bird members within a practice
   - 8+ API endpoints for practice management

3. **Pricing lifecycle & discounts** — `pricing.utils.ts`:
   - Discount stacking: annual (up to 17%), clinic, loyalty
   - 85% minimum price ceiling (max 15% total discount)
   - 12-month early bird rate lock with expiry tracking
   - Automatic transition: early bird → standard or clinic rate on expiry
   - Re-signup prevention: early bird available once per physician
   - 30-day expiry warning notifications

4. **Referral program redesign** — Complete replacement of original referral system:
   - 8-char alphanumeric referral codes (auto-generated at signup)
   - PENDING → QUALIFIED → APPLIED/REJECTED status workflow
   - 1-month free credit (was $50)
   - Max 3 referrals per anniversary year (was 10/year)
   - Same-practice referral blocking
   - Clinic credit destination choice (practice invoice vs individual)
   - Referee incentive: 100% Stripe coupon for first month

5. **Cancellation policies** — `cancellation.service.ts`:
   - Monthly: cancel anytime, effective end of billing period
   - Annual: 6-month minimum commitment, forfeit rule for early cancellation
   - Prorated refund calculation for annual after 6 months
   - Stripe refund integration
   - Clinic physician removal: effective end of month
   - 30-day data portability window after cancellation

6. **Data portability export** — `export.service.ts` and `export.repository.ts`:
   - Full ZIP bundle with 6 CSV data types (claims, WCB claims, patients, assessments, analytics, intelligence)
   - Physician-scoped queries
   - Available for 30 days after cancellation
   - Presigned download URLs

7. **Practice Stripe integration** — `practice-stripe.service.ts`:
   - Subscription quantity management per practice
   - Adding/removing seats adjusts Stripe quantity
   - Consolidated invoicing

8. **Compliance schemas** — `compliance.schema.ts` may include IMA, breach, and data destruction schemas. Document if they're part of the platform domain.

9. **Dunning sequence** — Verify the FRD accurately describes: Day 0 → Day 3 → Day 7 → Day 14 (SUSPENDED) → Day 30 (CANCELLED).

## Step 5: Write Updated FRD

Write the complete updated FRD to: `docs/frd/extracted/Meritum_Domain_12_Platform_Operations.md`

### Format Rules

- Preserve existing section structure where applicable, but this will be a major expansion
- Add major new sections for:
  - Pricing Model (updated constants, all plan types)
  - Clinic/Practice Tier (entity model, admin role, seat management, Stripe consolidation)
  - Pricing Lifecycle (discount framework, early bird rate lock, transitions)
  - Referral Program (redesigned workflow, credit model, caps)
  - Cancellation & Refund Policies (monthly/annual rules, forfeit, prorated refund)
  - Data Portability Export (ZIP bundle, CSV types, 30-day window)
- Update data model with all new tables (practices, practice_memberships, practice_invitations, referral redesign)
- Update API contracts with all new endpoints
- Document the pricing utility functions
- Do not add TODO/TBD/placeholder content

When complete, output on its own line: [TASK_COMPLETE]
If blocked, output: [TASK_BLOCKED] reason: <explanation>
