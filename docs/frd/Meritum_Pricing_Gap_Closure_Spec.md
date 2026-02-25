# MERITUM HEALTH TECHNOLOGIES
# Pricing Gap Closure Specification
## February 2026 · Internal Engineering Reference

**Purpose:** This document defines all functional requirements needed to align the Meritum codebase with the Pricing Strategy v2 document. It is the single source of truth for Batches 0–4 of the pricing alignment work.

**Authoritative pricing reference:** `/home/developer/projects/meritum-pricing-strategy-v2.docx`

**Scope:** This is NOT a new domain. It modifies existing domains (primarily D12 Platform Operations, D01 IAM, D05 Provider Management) and adds the clinic/practice tier as an extension of D12.

---

## BATCH 0 — Pricing Constant Corrections

Trivial fixes to align hardcoded values with the pricing strategy.

### B0-1. Fix Annual Pricing

**Current state:** `STANDARD_ANNUAL` amount is `'2790.00'` (≈$232.50/month, ~17% discount).

**Required state:** `STANDARD_ANNUAL` amount must be `'3181.00'` ($265.08/month, 5% discount).

Calculation: $279.00 × 12 × 0.95 = $3,181.32, rounded to $3,181.00 per the rate card.

**Files to change:**
- `packages/shared/src/constants/platform.constants.ts`: Change `amount: '2790.00'` → `amount: '3181.00'` for `STANDARD_ANNUAL`
- `CLAUDE.md` line 9: Update pricing reference to `$279/month, $3,181/year, $199/month early bird`

### B0-2. Add Early Bird Annual Plan

**Current state:** Only `EARLY_BIRD_MONTHLY` exists.

**Required state:** Add `EARLY_BIRD_ANNUAL` at $2,388/year ($199 × 12, no additional discount).

**Files to change:**
- `packages/shared/src/constants/platform.constants.ts`:
  - Add `EARLY_BIRD_ANNUAL: 'EARLY_BIRD_ANNUAL'` to `SubscriptionPlan`
  - Add pricing entry: `{ plan: 'EARLY_BIRD_ANNUAL', amount: '2388.00', interval: 'year', label: 'Early Bird Annual' }`
- `packages/shared/src/schemas/platform.schema.ts`: Add `EARLY_BIRD_ANNUAL` to the `createCheckoutSessionSchema` plan enum
- `apps/api/src/domains/platform/platform.service.ts`: `createCheckoutSession()` must apply the same 100-cap check to `EARLY_BIRD_ANNUAL` as it does to `EARLY_BIRD_MONTHLY`. Env var: `STRIPE_PRICE_EARLY_BIRD_ANNUAL`
- `apps/api/src/domains/platform/platform.repository.ts`: `countEarlyBirdSubscriptions()` must count both `EARLY_BIRD_MONTHLY` and `EARLY_BIRD_ANNUAL` plans

---

## BATCH 1 — Clinic/Practice Tier

This is the largest body of work. It introduces a practice entity, a new IAM role, seat management, clinic-specific pricing, and a scoped admin dashboard.

### B1-1. Data Model: Practices

New table `practices` in `packages/shared/src/schemas/db/platform.schema.ts`:

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| practice_id | UUID PK | No | Primary key |
| name | VARCHAR(200) | No | Practice name |
| admin_user_id | UUID FK → users | No | Practice administrator |
| stripe_customer_id | VARCHAR(50) | Yes | Stripe customer for consolidated billing |
| stripe_subscription_id | VARCHAR(50) | Yes | Stripe subscription for the practice |
| billing_frequency | VARCHAR(10) | No | `'MONTHLY'` or `'ANNUAL'` |
| status | VARCHAR(20) | No | `'ACTIVE'`, `'SUSPENDED'`, `'CANCELLED'` |
| current_period_start | TIMESTAMPTZ | No | Current billing period start |
| current_period_end | TIMESTAMPTZ | No | Current billing period end |
| created_at | TIMESTAMPTZ | No | |
| updated_at | TIMESTAMPTZ | No | |

Indexes: `admin_user_id`, `stripe_customer_id`, `status`.

### B1-2. Data Model: Practice Memberships

New table `practice_memberships` in the same schema file:

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| membership_id | UUID PK | No | Primary key |
| practice_id | UUID FK → practices | No | Parent practice |
| physician_user_id | UUID FK → users | No | Physician on this practice |
| billing_mode | VARCHAR(30) | No | `'PRACTICE_CONSOLIDATED'` or `'INDIVIDUAL_EARLY_BIRD'`. Determines how this seat is billed. Default: `'PRACTICE_CONSOLIDATED'`. |
| joined_at | TIMESTAMPTZ | No | When the physician was added |
| removed_at | TIMESTAMPTZ | Yes | When removed (null = active) |
| removal_effective_at | TIMESTAMPTZ | Yes | End of calendar month when removal takes effect |
| is_active | BOOLEAN | No | Default true. False when removed |
| created_at | TIMESTAMPTZ | No | |

Indexes: unique partial on `(practice_id, physician_user_id)` where `is_active = true`. Index on `practice_id` where `is_active = true`.

**Constraints:**
- A physician can belong to at most ONE active practice at a time (unique partial index on `physician_user_id` where `is_active = true`).
- Minimum 5 active memberships for a practice to maintain clinic tier pricing. This counts ALL active members regardless of `billing_mode` — an early bird physician on `INDIVIDUAL_EARLY_BIRD` still counts toward the 5-physician minimum.

**Hybrid billing model (early bird physicians in a practice):**

A practice can contain a mix of billing modes:
- `PRACTICE_CONSOLIDATED`: Physician is billed through the practice's Stripe subscription at clinic rate ($251.10/month or $238.58/month effective for annual). The practice's Stripe subscription `quantity` only counts these members.
- `INDIVIDUAL_EARLY_BIRD`: Physician retains their own individual early bird subscription ($199/month or $2,388/year) and is NOT included in the practice's Stripe subscription quantity. They are still a full practice member, count toward headcount, and appear in the seat list.

When an early bird physician's rate lock expires (see B2-2), their `billing_mode` transitions from `INDIVIDUAL_EARLY_BIRD` to `PRACTICE_CONSOLIDATED`, their individual subscription is cancelled, and the practice's Stripe subscription quantity is incremented.

Example: A practice has 7 physicians — 3 on early bird, 4 post-early-bird.
- Total headcount: 7 → clinic tier qualifies
- Practice Stripe subscription quantity: 4 (only `PRACTICE_CONSOLIDATED` members)
- 3 physicians have their own individual Stripe subscriptions at $199/month
- As each early bird expires, quantity goes 4→5→6→7 over time

### B1-3. Data Model: Practice Invitations

New table `practice_invitations`:

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| invitation_id | UUID PK | No | Primary key |
| practice_id | UUID FK → practices | No | Inviting practice |
| invited_email | VARCHAR(255) | No | Email of physician being invited |
| invited_by_user_id | UUID FK → users | No | Who sent the invitation |
| status | VARCHAR(20) | No | `'PENDING'`, `'ACCEPTED'`, `'DECLINED'`, `'EXPIRED'` |
| token_hash | VARCHAR(128) | No | Hashed invitation token |
| expires_at | TIMESTAMPTZ | No | Default: 7 days from creation |
| created_at | TIMESTAMPTZ | No | |

### B1-4. IAM: PRACTICE_ADMIN Role

**File:** `packages/shared/src/constants/iam.constants.ts`

Add `PRACTICE_ADMIN: 'PRACTICE_ADMIN'` to the `Role` enum.

**PRACTICE_ADMIN permissions** (new permission keys):
- `PRACTICE_SEAT_VIEW` — View list of physicians on the practice
- `PRACTICE_SEAT_MANAGE` — Add/remove physicians
- `PRACTICE_INVOICE_VIEW` — View consolidated practice invoice
- `PRACTICE_SETTINGS_EDIT` — Edit practice name, billing frequency

**PRACTICE_ADMIN does NOT get:**
- Any `CLAIM_*` permissions
- Any `PATIENT_*` permissions
- Any `ANALYTICS_*` permissions
- `ADMIN_PHI_ACCESS`

The practice admin can also be a physician with their own separate physician login. But the PRACTICE_ADMIN role itself is scoped strictly to seat list + invoice.

This is non-negotiable per the pricing strategy document Section 2.4: *"Individual physician billing data is personal professional information. Exposing it to a practice administrator would create a surveillance dynamic."*

### B1-5. Clinic Pricing Constants

**File:** `packages/shared/src/constants/platform.constants.ts`

Add to `SubscriptionPlan`:
```
CLINIC_MONTHLY: 'CLINIC_MONTHLY'
CLINIC_ANNUAL: 'CLINIC_ANNUAL'
```

Add to `SubscriptionPlanPricing`:
```
CLINIC_MONTHLY: { amount: '251.10', interval: 'month', label: 'Clinic Monthly' }
CLINIC_ANNUAL:  { amount: '2863.00', interval: 'year', label: 'Clinic Annual' }
```

Effective monthly rates: $251.10 (10% off $279) and $238.58 (~15% off $279).

Add:
```
CLINIC_MINIMUM_PHYSICIANS = 5
DISCOUNT_ANNUAL = 0.05
DISCOUNT_CLINIC = 0.10
DISCOUNT_CEILING = 0.15
```

### B1-6. Subscription Model Changes

**File:** `packages/shared/src/schemas/db/platform.schema.ts` — `subscriptions` table

Add column:
- `practice_id` UUID FK → practices, NULLABLE. When set, this is a clinic-tier subscription tied to a practice. When null, it's an individual subscription.

The `plan` column now accepts `CLINIC_MONTHLY` and `CLINIC_ANNUAL` in addition to existing values.

**Business rule:** When a subscription has a `practice_id`, the physician's billing is managed by the practice. The physician does not have their own Stripe subscription — the practice's consolidated subscription covers all members.

### B1-7. Practice Service Layer

**New functions** in `apps/api/src/domains/platform/platform.service.ts` (or a new `practice.service.ts` file within the platform domain):

**createPractice(adminUserId, name, billingFrequency):**
- Validates the admin user exists and is a physician
- Creates the practice record
- Creates a practice membership for the admin
- Assigns PRACTICE_ADMIN role to the user (they retain PHYSICIAN role too)
- Creates Stripe customer for the practice
- Returns practice record

**invitePhysician(practiceId, email, invitedByUserId):**
- Validates the inviter is PRACTICE_ADMIN for this practice
- Validates the email is not already on the practice
- Validates the email is not already on another active practice
- Creates invitation with hashed token, 7-day expiry
- Emits notification (email to invited physician)

**acceptInvitation(token):**
- Validates and finds invitation by token hash
- Validates not expired
- Determines `billing_mode`:
  - If physician has an active early bird subscription (rate lock not yet expired): set `billing_mode = 'INDIVIDUAL_EARLY_BIRD'`. Physician keeps their individual early bird subscription. Practice Stripe quantity is NOT incremented.
  - Otherwise: set `billing_mode = 'PRACTICE_CONSOLIDATED'`. Cancel physician's individual subscription (if any). Increment practice Stripe subscription quantity. Physician is now billed through the practice.
- Creates practice membership with the determined `billing_mode`
- Audit logged

**removePhysician(practiceId, physicianUserId, removedByUserId):**
- Validates the remover is PRACTICE_ADMIN
- Cannot remove the admin themselves (must transfer admin first or dissolve practice)
- Sets `removed_at = now()`, `removal_effective_at = end of current calendar month`
- Audit logged
- **If practice drops below 5 active members after this removal:** Emit notification to admin warning that clinic tier pricing will be lost at end of month

**handleEndOfMonthRemovals() — scheduled job:**
- Finds memberships where `removal_effective_at <= now()` and `is_active = true`
- Sets `is_active = false`
- If removed physician was `PRACTICE_CONSOLIDATED`: Decrement practice Stripe subscription quantity
- Checks total active member count (both billing modes). If < 5:
  - Dissolve the practice's consolidated billing (cancel practice Stripe subscription)
  - Each remaining `PRACTICE_CONSOLIDATED` physician gets an individual STANDARD subscription (monthly or annual matching the practice's billing frequency)
  - `INDIVIDUAL_EARLY_BIRD` physicians keep their existing individual subscriptions unchanged
  - All memberships set to `is_active = false` (practice effectively dissolved)
  - Emit notifications to all affected physicians
  - Audit logged

**getPracticeSeats(practiceId, adminUserId):**
- Validates caller is PRACTICE_ADMIN for this practice
- Returns list of active members: physician name, email, joined_at, billing_mode. Nothing else.
- The `billing_mode` field lets the admin see which physicians are still on individual early bird billing vs consolidated practice billing. This is not PHI — it is practice account management data.
- **Does NOT return:** claim counts, billing volumes, revenue, rejection rates, or any PHI

**getPracticeInvoice(practiceId, adminUserId):**
- Validates caller is PRACTICE_ADMIN
- Returns consolidated invoice info: total amount, per-seat rate, number of seats, billing frequency, next invoice date
- Sourced from Stripe invoice data

### B1-8. Practice Routes

**New routes** (all require PRACTICE_ADMIN role unless noted):

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /api/v1/practices | PHYSICIAN | Create a new practice (caller becomes admin) |
| GET | /api/v1/practices/:id | PRACTICE_ADMIN | Get practice details |
| PATCH | /api/v1/practices/:id | PRACTICE_ADMIN | Update practice name/billing frequency |
| GET | /api/v1/practices/:id/seats | PRACTICE_ADMIN | List physician seats |
| POST | /api/v1/practices/:id/invitations | PRACTICE_ADMIN | Invite a physician |
| POST | /api/v1/practice-invitations/:token/accept | PHYSICIAN | Accept invitation |
| DELETE | /api/v1/practices/:id/seats/:userId | PRACTICE_ADMIN | Remove physician |
| GET | /api/v1/practices/:id/invoices | PRACTICE_ADMIN | View consolidated invoices |

### B1-9. Practice Stripe Integration

When a practice is created with 5+ physicians:
1. Create a Stripe Customer for the practice (name + admin email, no PHI)
2. Create a Stripe Subscription with quantity = number of `PRACTICE_CONSOLIDATED` members (NOT total headcount — early bird members retain individual subscriptions)
3. Price ID: `STRIPE_PRICE_CLINIC_MONTHLY` or `STRIPE_PRICE_CLINIC_ANNUAL`
4. When a `PRACTICE_CONSOLIDATED` physician is added: Update Stripe subscription quantity (prorated)
5. When a physician is removed: Update quantity at end of month (only if they were `PRACTICE_CONSOLIDATED`)
6. When an early bird member transitions to `PRACTICE_CONSOLIDATED` (rate lock expired): Increment practice Stripe quantity, cancel individual subscription
7. GST handled identically to individual subscriptions (5% on invoice.created)

**Important:** The 5-physician minimum for clinic tier eligibility counts ALL active members (both billing modes). But the Stripe subscription quantity only counts `PRACTICE_CONSOLIDATED` members. A practice could have 6 members but a Stripe quantity of 3 if the other 3 are still on early bird.

**New Stripe env vars:**
- `STRIPE_PRICE_CLINIC_MONTHLY`
- `STRIPE_PRICE_CLINIC_ANNUAL`

### B1-10. Practice Security Tests

All 6 security test categories:
1. **authn:** Every practice route returns 401 without session
2. **authz:** Only PRACTICE_ADMIN can manage seats/view invoices. A PHYSICIAN without PRACTICE_ADMIN role gets 403. A PRACTICE_ADMIN for practice A cannot manage practice B.
3. **scoping:** Practice admin NEVER sees physician claim data, billing volumes, or any PHI. Seats endpoint returns names + emails only.
4. **input:** SQL injection / XSS on practice name, invitation email
5. **leakage:** Error responses don't leak practice member details or billing data to non-admins
6. **audit:** Practice creation, invitation, acceptance, removal, dissolution all audit logged

### B1-11. Practice Admin Dashboard Data Isolation

This is the hardest security requirement. The following must be verified:

- `GET /api/v1/practices/:id/seats` returns ONLY: `{ physicianName, email, joinedAt, billingMode }` per seat. No claim data, no billing volumes, no rejection rates.
- No practice admin endpoint returns data from: `claims`, `ahcip_claim_details`, `wcb_claim_details`, `patients`, `analytics_cache`, `generated_reports`, `ai_suggestion_events`, `payment_history` (individual physician payments).
- The practice admin sees the PRACTICE invoice (consolidated), not individual physician payment records.
- This is enforced at the repository layer, not the handler layer.

---

## BATCH 2 — Pricing Lifecycle & Discount Framework

### B2-1. Discount Constants & Calculation

**File:** `packages/shared/src/constants/platform.constants.ts`

```
DISCOUNT_ANNUAL_PERCENT = 5
DISCOUNT_CLINIC_PERCENT = 10
DISCOUNT_CEILING_PERCENT = 15
```

**File:** `packages/shared/src/utils/pricing.utils.ts` (new file)

Pure functions for price calculation:

```typescript
calculateEffectiveRate(baseMontly: number, isAnnual: boolean, isClinic: boolean): {
  monthlyRate: number;
  annualRate: number | null;
  appliedDiscounts: string[];
  totalDiscountPercent: number;
}
```

Rules:
- Base rate: $279/month
- Annual only: 5% off → $265.05/month, $3,181/year
- Clinic only: 10% off → $251.10/month
- Clinic + annual: 15% off (ceiling) → $237.15/month, $2,863/year (per rate card: $238.58 effective monthly)
- Early bird: $199/month flat, no discounts stack
- No configuration ever produces a rate below 85% of $279 ($237.15)

### B2-2. Early Bird Rate Lock

**Schema change:** Add column to `subscriptions` table:

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| early_bird_locked_until | TIMESTAMPTZ | Yes | 12 months from signup. Null for non-early-bird plans. |

**Service logic** in `platform.service.ts`:

- On early bird checkout completion: set `early_bird_locked_until = created_at + 12 months`
- New scheduled job `checkEarlyBirdExpiry()`:
  - Finds early bird subscriptions where `early_bird_locked_until <= now() + 30 days` AND notification not yet sent
  - Emits `EARLY_BIRD_EXPIRING` notification with 30 days warning
  - At `early_bird_locked_until`:
    - **If physician is a member of a practice (has active `practice_memberships` row):** Cancel individual early bird subscription. Transition membership `billing_mode` from `INDIVIDUAL_EARLY_BIRD` to `PRACTICE_CONSOLIDATED`. Increment practice Stripe subscription quantity. Emit `EARLY_BIRD_EXPIRED` notification to physician and `PRACTICE_MEMBER_TRANSITIONED` notification to practice admin.
    - **If physician is NOT in a practice:** Transition subscription to STANDARD_MONTHLY or STANDARD_ANNUAL (matching current billing frequency) via Stripe API (price change). Emit `EARLY_BIRD_EXPIRED` notification.

### B2-3. Early Bird Re-Signup Prevention

**Service logic** in `platform.service.ts` — `createCheckoutSession()`:

- When plan is `EARLY_BIRD_MONTHLY` or `EARLY_BIRD_ANNUAL`:
  - Check if user has ANY previous subscription with plan containing `EARLY_BIRD` (including cancelled ones)
  - If yes: throw `BusinessRuleError('Early bird rate does not survive cancellation', { code: 'EARLY_BIRD_INELIGIBLE' })`
- This requires a new repo method: `hasEverHadEarlyBird(userId: string): Promise<boolean>`

### B2-4. Early Bird + Clinic Interaction

Per pricing strategy Section 2.5:

- Early bird and clinic tier DO NOT stack
- A practice signing up during early bird window should take early bird on each physician individually ($199 < $251.10)
- Each early bird signup counts against the 100-spot cap
- Early bird physicians joining a practice are full members and count toward the 5-physician minimum, but remain on individual billing until their rate lock expires
- After early bird expires (per physician), they automatically transition to practice consolidated billing

**Service logic:**
- `invitePhysician()`: If invited physician has an active early bird subscription, they join with `billing_mode = 'INDIVIDUAL_EARLY_BIRD'`. They keep their individual subscription and count toward headcount but are NOT included in the practice's Stripe quantity.
- `acceptInvitation()`: Same logic — determines `billing_mode` based on early bird status at time of acceptance.
- `checkEarlyBirdExpiry()` (B2-2): Handles the automatic transition from `INDIVIDUAL_EARLY_BIRD` to `PRACTICE_CONSOLIDATED` when the rate lock expires. This is seamless — the physician doesn't need to take any action.
- Practice creation during early bird window: All founding members who are on early bird join as `INDIVIDUAL_EARLY_BIRD`. The practice Stripe subscription starts with quantity = number of non-early-bird members (could be 0 if all are early bird). The clinic tier still qualifies as long as total headcount >= 5.

### B2-5. Proactive Transition Notification

When the first physician in a practice is approaching early bird expiry:
- 30 days before: Notify practice admin that physician's early bird rate is expiring
- Include option to transition the practice to clinic tier billing
- If all physicians on the practice are post-early-bird, auto-suggest clinic tier transition

---

## BATCH 3 — Referral Program

### B3-1. Schema Redesign

The existing referral schema uses $50/credit with max 10/year. The pricing strategy requires 1-month-free/credit with max 3/year. The schema must change.

**Replace `referral_codes` table columns:**

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| referral_code_id | UUID PK | No | |
| referrer_user_id | UUID FK → users | No | Physician who owns this code |
| code | VARCHAR(20) | No | Unique referral code |
| is_active | BOOLEAN | No | Default **true** (active from creation, not dormant) |
| created_at | TIMESTAMPTZ | No | |

Remove: `redemption_count`, `max_redemptions` (these are calculated, not stored).

**Replace `referral_redemptions` table:**

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| redemption_id | UUID PK | No | |
| referral_code_id | UUID FK | No | Code that was used |
| referrer_user_id | UUID FK → users | No | Physician who referred (denormalized for queries) |
| referred_user_id | UUID FK → users | No | Physician who was referred |
| status | VARCHAR(20) | No | `'PENDING'`, `'QUALIFIED'`, `'CREDITED'`, `'EXPIRED'` |
| credit_month_value_cad | DECIMAL(10,2) | Yes | Set when qualified: 1 month at referrer's current rate |
| credit_applied_to | VARCHAR(20) | Yes | `'PRACTICE_INVOICE'` or `'INDIVIDUAL_BANK'` (clinic physicians only) |
| credit_applied_at | TIMESTAMPTZ | Yes | When the credit was applied to an invoice |
| qualifying_event_at | TIMESTAMPTZ | Yes | When referred physician completed one full billing cycle |
| anniversary_year | INTEGER | No | Referrer's signup anniversary year (for 3-per-year cap) |
| created_at | TIMESTAMPTZ | No | |

### B3-2. Referral Service Layer

**New functions** in platform service (or `referral.service.ts`):

**generateReferralCode(userId):**
- Creates a unique 8-character alphanumeric code
- Every physician with an active subscription gets one automatically at signup

**redeemReferralCode(code, referredUserId):**
- Validates code is active
- Validates referred user has NEVER had a Meritum subscription (new signups only)
- Validates referrer and referred are NOT on the same practice
- Creates redemption record with status `'PENDING'`

**checkReferralQualification() — scheduled job:**
- Finds `PENDING` redemptions where the referred user's subscription has completed at least one full billing cycle (payment received)
- Transitions to `'QUALIFIED'`
- Calculates credit value: 1 month at the referrer's current rate:
  - $199 (early bird), $279 (standard), $251.10 (clinic monthly), $265.08 (standard annual monthly equivalent), $238.58 (clinic annual monthly equivalent)
- Checks 3-per-year cap: count `QUALIFIED` or `CREDITED` redemptions in the referrer's current anniversary year. If >= 3, transition to `'EXPIRED'` instead.
- If qualified and referrer is on a clinic tier: present choice (see B3-3)
- If qualified and referrer is individual: apply credit to next invoice automatically

**applyReferralCredit(redemptionId):**
- Creates a Stripe invoice credit (negative line item) on the referrer's next invoice
- Sets status to `'CREDITED'`, records `credit_applied_at`
- For annual subscribers: monetary reduction on next annual renewal

### B3-3. Clinic Physician Referral Choice

When a clinic-tier physician earns a referral credit, they choose:

**Option A (default):** Apply to practice invoice. Credit reduces the practice's next invoice by the referring physician's per-seat monthly value.

**Option B:** Bank for future individual subscription. Credit held in physician's personal account. Applied if/when physician moves to individual subscription.

This choice is presented via notification when the referral qualifies. The physician responds via:
- `POST /api/v1/referrals/:redemptionId/apply` with body `{ target: 'PRACTICE_INVOICE' | 'INDIVIDUAL_BANK' }`
- Default (if no response within 7 days): Option A (practice invoice)
- Choice is immutable after application

### B3-4. Referee Incentive

**During early bird window (spots remain):** No incentive for the referred physician beyond accessing early bird rate if spots remain.

**After early bird window closes:** Referred physician receives first month free at standard rate ($279). This is implemented as a 100% coupon on the first Stripe invoice. Does NOT apply to clinic tier signups.

### B3-5. Referral Routes

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /api/v1/referrals/my-code | PHYSICIAN | Get or generate referral code |
| GET | /api/v1/referrals/my-credits | PHYSICIAN | List earned credits + status |
| POST | /api/v1/referrals/:redemptionId/apply | PHYSICIAN | Choose credit application (clinic physicians) |
| POST | /api/v1/signup/referral-code | PUBLIC | Validate a referral code during registration |

---

## BATCH 4 — Policy Alignment

### B4-1. Annual Cancellation: 6-Month Forfeit Rule

**Service logic** in `platform.service.ts`:

When a physician (or practice admin) requests cancellation of an annual subscription:

1. Calculate months elapsed since `current_period_start`
2. If < 6 months: No refund. Subscription continues until `current_period_end`, then cancels. Display message: *"Annual subscriptions require a 6-month minimum commitment. Your access continues until [period end date]."*
3. If >= 6 months: Calculate prorated refund for remaining months (months 7+). Issue Stripe refund via API. Cancel subscription at end of current period.

**Prorated refund calculation:**
```
total_paid = annual_amount  // e.g., $3,181
months_used = floor(months since period_start)
months_remaining = 12 - months_used
monthly_rate = annual_amount / 12
refund = months_remaining * monthly_rate
```

This requires:
- New Stripe refund logic in platform service
- A new `refundAnnualSubscription(subscriptionId, monthsUsed)` function
- The `PaymentStatus.REFUNDED` constant (already exists) must be used when recording refunds in `payment_history`

### B4-2. Clinic Physician Removal Timing

Already specified in B1-7 (`removePhysician`), but to be explicit:

- Removal is effective at the **end of the current calendar month**, regardless of the practice's billing cycle
- Example: Removal requested Feb 16 → effective Feb 28. Physician retains access until Feb 28.
- The `removal_effective_at` column stores this date
- The `handleEndOfMonthRemovals()` scheduled job processes these

### B4-3. Data Export on Cancellation — Full Portability Bundle

**Current state:** Claim exports (CSV/JSON) and patient exports exist separately.

**Required state per Section 7:** "Full export of claims, assessments, and analytics at no charge."

**New function:** `generateFullPortabilityExport(physicianId)` in claim service (or a new data-portability service):

Bundle contents:
1. **Claims:** All AHCIP claims (CSV) — already exists
2. **WCB Claims:** All WCB claim details + child records (CSV) — needs export function
3. **Patients:** All patient records (CSV) — already exists
4. **Assessments:** AHCIP assessment results, rejection details, batch outcomes (CSV) — new
5. **Analytics:** Dashboard summary data, report history (CSV) — new
6. **Intelligence:** Suggestion history, accepted/dismissed actions (CSV) — new

Output: ZIP file containing all CSVs, generated asynchronously, download link emailed to physician.

Available for 30 days after cancellation (enforced by existing `DELETION_GRACE_PERIOD_DAYS`).

### B4-4. PCPCM Payment Reconciliation

This is a moderate enhancement to the existing AHCIP/Provider domains.

**Current state:** PCPCM routing works (dual-BA, basket classification, separate batches). But there is no tracking of capitation payments or reconciliation of expected vs actual PCPCM payments.

**New table:** `pcpcm_payments` in `packages/shared/src/schemas/db/provider.schema.ts`:

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| payment_id | UUID PK | No | |
| provider_id | UUID FK → providers | No | Physician receiving payment |
| enrolment_id | UUID FK → pcpcm_enrolments | No | PCPCM enrolment reference |
| payment_period_start | DATE | No | Start of payment period |
| payment_period_end | DATE | No | End of payment period |
| expected_amount | DECIMAL(10,2) | Yes | Expected capitation based on panel size |
| actual_amount | DECIMAL(10,2) | Yes | Actual amount received from AH |
| panel_size_at_payment | INTEGER | Yes | Panel size at time of payment |
| status | VARCHAR(20) | No | `'EXPECTED'`, `'RECEIVED'`, `'RECONCILED'`, `'DISCREPANCY'` |
| reconciled_at | TIMESTAMPTZ | Yes | |
| notes | TEXT | Yes | |
| created_at | TIMESTAMPTZ | No | |

**Service functions (in provider.service.ts):**
- `recordPcpcmPayment(providerId, paymentData)` — Record an incoming PCPCM capitation payment
- `reconcilePcpcmPayments(providerId)` — Compare expected vs actual for a period
- `getPcpcmPaymentHistory(providerId, filters)` — List payment history with reconciliation status
- `updatePanelSize(providerId, enrolmentId, panelSize)` — Update panel size manually (currently always null). MVP: physician enters the number from their AH quarterly panel attribution report.

**Routes:**
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /api/v1/providers/me/pcpcm/payments | PHYSICIAN | List PCPCM payment history |
| POST | /api/v1/providers/me/pcpcm/payments | PHYSICIAN | Record a payment |
| POST | /api/v1/providers/me/pcpcm/reconcile | PHYSICIAN | Trigger reconciliation |
| PATCH | /api/v1/providers/me/pcpcm/panel-size | PHYSICIAN | Update panel size (manual entry) |

### B4-5. PCPCM Panel Size Estimation — Schema Only (Post-MVP)

**NOT built at MVP.** Schema scaffolding only, for future implementation.

Panel sizes in Alberta come from Alberta Health's quarterly Panel Attribution Reports. Physicians currently enter these manually (B4-4). A future enhancement will estimate panel size from Meritum's claim data as a sanity check alongside the manual entry.

**New table:** `pcpcm_panel_estimates` in `packages/shared/src/schemas/db/provider.schema.ts`:

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| estimate_id | UUID PK | No | |
| provider_id | UUID FK → providers | No | Physician |
| enrolment_id | UUID FK → pcpcm_enrolments | No | PCPCM enrolment |
| estimation_method | VARCHAR(30) | No | `'CLAIM_HISTORY'`, `'AH_REPORT_PARSED'`, `'MANUAL'` |
| estimated_panel_size | INTEGER | No | Estimated number of attributed patients |
| unique_patients_12m | INTEGER | Yes | Distinct patients seen in rolling 12 months (for CLAIM_HISTORY method) |
| confidence | VARCHAR(10) | Yes | `'HIGH'`, `'MEDIUM'`, `'LOW'` — how closely estimate matches known panel methodology |
| period_start | DATE | No | Start of estimation period |
| period_end | DATE | No | End of estimation period |
| created_at | TIMESTAMPTZ | No | |

Indexes: `(provider_id, period_end)`.

**No service logic, no routes, no tests.** This table is defined in the schema only. A comment in the schema file should note: `// Post-MVP: panel size estimation from claim history. Schema defined, not actively used.`

Future implementation will:
1. Count distinct patients per physician over a rolling 12-month window from claim data
2. Display as *"Based on your claims, your estimated panel is ~X patients"* alongside the manual entry field
3. Optionally parse uploaded AH panel report PDFs (if format is stable enough)

---

## INTERACTION RULES SUMMARY

These rules are defined in the pricing strategy and must be enforced in code:

| Scenario | Rule | Enforcement Location |
|----------|------|---------------------|
| Annual + clinic tier | Stack: 10% + 5% = 15% ceiling | Pricing utils + Stripe price selection |
| Early bird + clinic tier | Do NOT stack. Physician keeps early bird ($199) individually. Counts against 100-spot cap AND toward practice 5-physician minimum. `billing_mode = 'INDIVIDUAL_EARLY_BIRD'`. | `acceptInvitation()` + checkout |
| Early bird expires in practice | Auto-transition to `PRACTICE_CONSOLIDATED`. Cancel individual sub, increment practice Stripe quantity. | `checkEarlyBirdExpiry()` |
| Early bird + annual discount | Do NOT stack. EB annual = $2,388. No extra 5%. | `SubscriptionPlanPricing` constant |
| Early bird cancels, re-signs up | Returns at standard rate. EB does not survive cancellation. | `createCheckoutSession()` + `hasEverHadEarlyBird()` |
| Early bird expires, physician in 5+ practice | Practice can transition to clinic tier. Proactive notification. | `checkEarlyBirdExpiry()` |
| Referral within same practice | NOT eligible. Seat addition, not a referral. | `redeemReferralCode()` validation |
| Referral by clinic physician to external | Eligible. Choice: practice invoice or bank for individual. | `checkReferralQualification()` |
| Referee incentive during early bird window | None beyond early bird access. | Checkout coupon logic |
| Referee incentive after early bird | First month free at standard rate. Not for clinic signups. | Checkout coupon logic |
| Clinic drops below 5 physicians | Clinic discount removed. All revert to standard individual. | `handleEndOfMonthRemovals()` |
| Physician removed from clinic | Effective end of current calendar month. | `removePhysician()` + scheduled job |
| Annual cancel within first 6 months | Remaining balance forfeited. No prorated refund. | `handleAnnualCancellation()` |
| Annual cancel after 6 months | Prorated refund for months 7 onward. | `handleAnnualCancellation()` |
| Clinic admin access to physician data | NEVER. Admin sees seat list + consolidated invoice only. | PRACTICE_ADMIN permissions + security tests |

---

## TASK MANIFEST BREAKDOWN

Each batch maps to a task manifest file for the task-runner. Suggested task counts:

| Batch | Manifest | Est. Tasks | Layer Pattern |
|-------|----------|------------|---------------|
| 0 | `domain-15-pricing-fix.tasks` | 4 | Constants → schema → service → validation |
| 1 | `domain-16-clinic-tier.tasks` | 28 | Schema → IAM role → repo → service (incl. hybrid billing) → routes → Stripe → security tests |
| 2 | `domain-17-pricing-lifecycle.tasks` | 18 | Constants → utils → schema → service → scheduled jobs → security tests |
| 3 | `domain-18-referral-program.tasks` | 15 | Schema redesign → repo → service → routes → scheduled jobs → security tests |
| 4 | `domain-19-policy-alignment.tasks` | 16 | Cancellation logic → refund → data export → PCPCM → panel estimate schema → security tests |

**Total: ~81 tasks across 5 batches.**

---

## TESTING REQUIREMENTS

Every batch must include:
1. Unit tests for all new service functions
2. Integration tests for all new routes
3. All 6 security test categories for the practice/clinic tier (Batch 1 is the security-critical batch)
4. Specific regression tests: existing 10,881 tests must continue passing after each batch

## DEPENDENCIES

```
Batch 0 ─── (no dependencies)
Batch 1 ─── depends on Batch 0 (correct pricing constants)
Batch 2 ─── depends on Batch 1 (clinic tier must exist for discount stacking)
Batch 3 ─── depends on Batch 1 (referral needs practice membership for same-practice blocking)
Batch 4 ─── depends on Batch 1 (annual cancellation touches practice dissolution)
```

Batches 2, 3, and 4 can run in parallel after Batch 1 completes, but sequential execution is safer for a single developer.

---

*End of specification. All pricing decisions reference meritum-pricing-strategy-v2.docx as the authoritative source.*
