# Task FRD-07: Update Domain 5 (Provider Management) FRD

## Objective

Read the current Domain 5 FRD and the actual implementation, then update the FRD in-place. Fold in PCPCM payment reconciliation, ARP BA types, facility-BA mapping, and Connect Care user support.

## Step 1: Read Current FRD

Read the full file:
- `docs/frd/extracted/Meritum_Domain_05_Provider_Management.md`

## Step 2: Read Implementation

**Domain module:**
- `apps/api/src/domains/provider/provider.routes.ts`
- `apps/api/src/domains/provider/provider.handlers.ts`
- `apps/api/src/domains/provider/provider.service.ts`
- `apps/api/src/domains/provider/provider.repository.ts`
- `apps/api/src/domains/provider/pcpcm-payment.repository.ts`
- `apps/api/src/domains/provider/pcpcm-payment.service.ts`

**Shared schemas and constants:**
- `packages/shared/src/constants/provider.constants.ts`
- `packages/shared/src/schemas/provider.schema.ts`

**Database schema:**
- `packages/shared/src/schemas/db/provider.schema.ts` (if exists)

**Test files:**
- `apps/api/src/domains/provider/provider.test.ts`
- `apps/api/src/domains/provider/provider-routing.test.ts`
- `apps/api/src/domains/provider/pcpcm-payment.test.ts`

## Step 3: Read Supplementary Specs

**Pricing Gap Closure (PCPCM payments, BA subtypes):**
- `docs/frd/extracted/Meritum_Pricing_Gap_Closure_Spec.md`
  - Batch 4 (B4-4, B4-5): PCPCM payment reconciliation — `pcpcm_payments` table, `pcpcm_panel_estimates` table, payment CRUD, reconciliation logic, panel size updates
  - BA subtypes: `ba_subtype` column on business_arrangements (FFS, ARP, APP, PCPCM distinction)

**MVP Features Addendum (provider-related features):**
- `docs/frd/extracted/Meritum_MVP_Features_Addendum.md`
  - B5: ARP/APP Shadow Billing — ARP BA type labelling, S-code restriction logic
  - B10: Mixed FFS/ARP Smart Routing — `ba_facility_mappings` table, `ba_schedule_mappings` table, time-based routing schedules

**Mobile Companion v2 (Connect Care user flag):**
- `docs/frd/extracted/Meritum_Mobile_Companion_v2.md`
  - C5: is_connect_care_user flag on providers table, connect_care_enabled_at timestamp, mode switching

## Step 4: Key Changes to Incorporate

1. **PCPCM payment service** — Entirely new subsystem within the provider domain:
   - `pcpcm_payments` table: records actual capitation payments received from Alberta Health
   - `pcpcm_panel_estimates` table: tracks panel size estimates for revenue forecasting
   - Payment recording, reconciliation against expected amounts, history retrieval
   - API endpoints: `GET /api/v1/providers/me/pcpcm/payments`, panel size updates

2. **PCPCM routing logic** — The `provider-routing.test.ts` file suggests claim routing logic lives in the provider domain. Document how claims are routed between PCPCM BA and FFS BA based on service type and patient panel status.

3. **BA subtypes** — `ba_subtype` column added to business_arrangements: FFS, ARP, APP, PCPCM. This extends the original BA type model.

4. **Facility-BA mapping** — Maps practice locations to BAs. Used by mixed FFS/ARP routing to determine which BA receives claims from a given facility.

5. **Time-based routing schedules** — Schedule mappings that define which BA is active at different times (e.g., FFS during clinic hours, ARP during hospital shifts).

6. **Connect Care user flag** — `is_connect_care_user` boolean and `connect_care_enabled_at` timestamp on providers table. Controls mobile companion mode (shift-first vs quick-claim-first).

7. **Delegate relationships** — Verify the FRD accurately documents the delegate permission matrix and relationship management as implemented.

8. **H-Link configuration** — Verify accreditation/configuration settings match implementation.

## Step 5: Write Updated FRD

Write the complete updated FRD to: `docs/frd/extracted/Meritum_Domain_05_Provider_Management.md`

### Format Rules

- Preserve existing section structure and formal writing style
- Add a new major section for PCPCM Payment Reconciliation
- Add sections for BA subtypes, facility-BA mapping, time-based routing
- Update the provider profile section to include the Connect Care user flag
- Update data model with all new/modified tables and columns
- Update API contracts with all new endpoints
- Do not add TODO/TBD/placeholder content

When complete, output on its own line: [TASK_COMPLETE]
If blocked, output: [TASK_BLOCKED] reason: <explanation>
