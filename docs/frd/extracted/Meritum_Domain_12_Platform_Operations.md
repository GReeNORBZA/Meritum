# Meritum_Domain_12_Platform_Operations

MERITUM

Functional Requirements

Platform Operations

Domain 12 of 13  |  Infrastructure & Business Operations

Meritum Health Technologies Inc.

Version 2.0  |  February 2026

CONFIDENTIAL

# Table of Contents

1. [Domain Overview](#1-domain-overview)
2. [Pricing Model](#2-pricing-model)
3. [Stripe Integration](#3-stripe-integration)
4. [Subscription Lifecycle](#4-subscription-lifecycle)
5. [Clinic / Practice Tier](#5-clinic--practice-tier)
6. [Pricing Lifecycle](#6-pricing-lifecycle)
7. [Referral Program](#7-referral-program)
8. [Cancellation & Refund Policies](#8-cancellation--refund-policies)
9. [Account Deletion & Data Destruction](#9-account-deletion--data-destruction)
10. [Data Portability Export](#10-data-portability-export)
11. [IMA Amendment Management](#11-ima-amendment-management)
12. [Breach Notification (HIA Compliance)](#12-breach-notification-hia-compliance)
13. [Status Page](#13-status-page)
14. [System Health Monitoring](#14-system-health-monitoring)
15. [Data Model](#15-data-model)
16. [API Contracts](#16-api-contracts)
17. [Pricing Utility Functions](#17-pricing-utility-functions)
18. [Scheduled Jobs](#18-scheduled-jobs)
19. [User Stories & Acceptance Criteria](#19-user-stories--acceptance-criteria)
20. [Testing Requirements](#20-testing-requirements)
21. [Document Control](#21-document-control)

---

# 1. Domain Overview

## 1.1 Purpose

Platform Operations owns the business infrastructure that keeps Meritum running: subscription billing via Stripe, pricing lifecycle management, clinic/practice tier billing, the referral program, cancellation and refund policies, IMA (Independent Member Agreement) amendment management, HIA breach notification compliance, platform status monitoring, data portability exports, and account deletion with multi-phase data destruction tracking.

## 1.2 Scope

- Stripe subscription management: individual and practice-consolidated plans, payment processing, invoicing with GST
- Pricing model: six plan types (Standard, Early Bird, Clinic) across monthly and annual billing
- Clinic/practice tier: group billing for practices with 5+ physicians, hybrid billing mode, invitation workflow
- Pricing lifecycle: early bird rate lock (12 months), discount framework, rate transitions
- Referral program: 8-character referral codes, 1-month credit per qualified referral, 3/year cap, clinic credit choice
- Cancellation and refund policies: monthly cancel-at-period-end, annual 6-month forfeit, prorated refund
- Dunning and payment recovery: failed payment handling, grace periods, account suspension
- Subscription lifecycle: TRIAL, ACTIVE, PAST_DUE, SUSPENDED, CANCELLED
- IMA amendment management: non-material acknowledgement, material accept/reject, blocking amendments
- HIA breach notification: 72-hour deadline, affected custodian tracking, dual-delivery notifications
- Data portability export: full health information ZIP bundle (CSV/JSON, 25+ entity types)
- Account deletion: 45-day grace period, multi-phase data destruction (active deletion, file deletion, backup purge)
- Status page: public platform status with incident history at status.meritum.ca
- System health monitoring: uptime, error rates, latency tracking
- Operational dashboards: admin-facing metrics for platform-wide health

## 1.3 Out of Scope

- Application features and business logic (all other domains)
- Infrastructure provisioning and deployment (DevOps; this domain specifies what to monitor, not how to deploy)
- HIA compliance legal interpretation (legal; this domain implements technical controls specified elsewhere)

---

# 2. Pricing Model

## 2.1 Plan Types

Meritum offers six subscription plans across three tiers and two billing frequencies:

| Plan | Plan Key | Monthly Rate (CAD) | Annual Rate (CAD) | Interval |
|------|----------|-------------------|-------------------|----------|
| Standard Monthly | `STANDARD_MONTHLY` | $279.00 | N/A | month |
| Standard Annual | `STANDARD_ANNUAL` | $265.08/mo effective | $3,181.00 | year |
| Early Bird Monthly | `EARLY_BIRD_MONTHLY` | $199.00 | N/A | month |
| Early Bird Annual | `EARLY_BIRD_ANNUAL` | $199.00/mo effective | $2,388.00 | year |
| Clinic Monthly | `CLINIC_MONTHLY` | $251.10 | N/A | month |
| Clinic Annual | `CLINIC_ANNUAL` | $238.58/mo effective | $2,863.00 | year |

All prices are GST-exclusive. GST (5%) is added on every Stripe invoice. Currency: CAD only. Payment methods: credit card (Visa, Mastercard, Amex) via Stripe. No cheques, no EFT at MVP.

## 2.2 Discount Framework

Standard discounts may be combined up to a 15% ceiling:

| Discount | Percentage | Condition |
|----------|-----------|-----------|
| Annual billing | 5% | Physician selects annual billing frequency |
| Clinic tier | 10% | Physician is part of a practice with 5+ physicians |
| Combined ceiling | 15% | Maximum combined discount; no configuration may produce a rate below 85% of $279 ($237.15/month) |

**Early bird pricing does not participate in the discount framework.** Early bird is a flat $199/month (or $2,388/year), with no additional discounts applied.

## 2.3 Early Bird Eligibility

- Available to the first 100 physicians who subscribe.
- Cap tracked via subscription count where `plan LIKE '%EARLY_BIRD%'`.
- Once the cap is reached, new physicians receive standard pricing.
- A physician who cancels an early bird subscription and re-subscribes does NOT regain early bird pricing. The system checks `hasEverHadEarlyBird(providerId)` at checkout time.

## 2.4 GST Handling

- GST rate: 5% (Alberta, Canada).
- GST is added as a line item on every Stripe invoice via the `invoice.created` webhook handler.
- Meritum is GST-registered. Invoice line items show base amount and GST separately.

---

# 3. Stripe Integration

## 3.1 Stripe Objects

| Stripe Object | Meritum Usage |
|---------------|---------------|
| Customer | 1:1 with Meritum user account (individual) or 1:1 with practice (clinic tier). Created during checkout or practice creation. |
| Product | Single product: 'Meritum Health Billing Platform'. |
| Price | Six prices: `STANDARD_MONTHLY` ($279), `STANDARD_ANNUAL` ($3,181), `EARLY_BIRD_MONTHLY` ($199), `EARLY_BIRD_ANNUAL` ($2,388), `CLINIC_MONTHLY` ($251.10), `CLINIC_ANNUAL` ($2,863). |
| Subscription | 1:1 with provider (individual) or 1:1 with practice (quantity = consolidated seat count). |
| Invoice | Auto-generated by Stripe per billing cycle. GST added as tax line item. |
| Payment Intent | Managed by Stripe. Meritum receives webhooks on success/failure. |

## 3.2 PHI Isolation

Stripe never receives PHI. The Stripe Customer object stores only:

- Name (physician's name or practice name, not patient data)
- Email (physician's or practice admin's email)
- Stripe-managed payment method token (Meritum never sees full card numbers)

Billing data (Stripe) and health data (Meritum database) are completely separated. Meritum stores only the Stripe `customer_id` and `subscription_id` as references. No claim data, patient data, or billing codes are sent to Stripe.

## 3.3 Webhook Events

Meritum listens for the following Stripe webhook events:

| Webhook Event | Meritum Action |
|---------------|----------------|
| `checkout.session.completed` | Initial subscription created. Link Stripe `customer_id` and `subscription_id` to Meritum user. Set early bird rate lock if applicable (`early_bird_locked_until = created_at + 12 months`). |
| `invoice.paid` | Mark subscription as current. Clear any `past_due` status. Reset `failed_payment_count` to 0. Log payment in `payment_history`. |
| `invoice.payment_failed` | Increment `failed_payment_count`. Start/advance dunning sequence (Section 4.2). Emit `PAYMENT_FAILED` notification. |
| `invoice.created` | Add GST line item (5% of subtotal) if not already present. |
| `customer.subscription.updated` | Sync subscription status (`active`, `past_due`, `cancelled`). Sync `current_period_start` and `current_period_end`. Update plan if changed. |
| `customer.subscription.deleted` | Subscription cancelled. Start account wind-down. Schedule data deletion (45-day grace period). |

## 3.4 Dunning Sequence

When a payment fails, Meritum runs a dunning sequence to recover the payment before suspending the account:

| Step | Timing | Action |
|------|--------|--------|
| 1 | Day 0 (payment fails) | `PAYMENT_FAILED` notification (in-app + email). Stripe automatically retries in 3 days. Platform access unaffected. |
| 2 | Day 3 (Stripe retry 1) | If retry succeeds: resolved. If fails: second notification. "Please update your payment method." |
| 3 | Day 7 (Stripe retry 2) | If fails: third notification. Warning: "Your account will be suspended in 7 days if payment is not resolved." |
| 4 | Day 14 (grace period ends) | Account status set to `SUSPENDED`. Claims preserved but submission blocked. Read-only access to dashboards and reports. Prominent banner: "Update payment to resume billing." |
| 5 | Day 30 (cancellation) | If still unpaid: subscription cancelled via Stripe. Account enters 45-day deletion grace period (Section 9). Data portability export available. |

## 3.5 Customer Portal

Meritum integrates Stripe's Customer Portal for self-service billing management:

- Update payment method
- View invoice history and download invoices
- Switch between monthly and annual plans
- Cancel subscription

The Customer Portal is accessed via a button in Meritum's account settings. Stripe handles the UI. Meritum receives webhook events for any changes made in the portal.

---

# 4. Subscription Lifecycle

## 4.1 States

| State | Description |
|-------|-------------|
| `TRIAL` | Optional trial period (if enabled). Full platform access. No payment required. Duration configurable (14 or 30 days). |
| `ACTIVE` | Payment current. Full platform access. Normal operation. |
| `PAST_DUE` | Payment failed, within dunning sequence (Days 0-14). Full platform access. Notifications active. |
| `SUSPENDED` | Payment not recovered after grace period (Day 14+). Claims preserved. Submission blocked. Read-only dashboards. |
| `CANCELLED` | Subscription cancelled (by physician or after Day 30 non-payment). 45-day grace for data export. Then data destruction per retention policy. |

## 4.2 Subscription-Gated Features

| Feature | `ACTIVE` | `PAST_DUE` | `SUSPENDED` | `CANCELLED` |
|---------|----------|------------|-------------|-------------|
| Create claims | Yes | Yes | No | No |
| Submit batches | Yes | Yes | No | No |
| View claims | Yes | Yes | Yes (read-only) | No |
| View patients | Yes | Yes | Yes (read-only) | No |
| Create/edit patients | Yes | Yes | No | No |
| View dashboards/analytics | Yes | Yes | Yes (read-only) | No |
| View/export reports | Yes | Yes | Yes | No |
| AI Coach suggestions | Yes | Yes | No | No |
| View settings | Yes | Yes | Yes | No |
| Edit settings | Yes | Yes | No | No |
| Update payment method | Yes | Yes | Yes | No |
| Data portability export | Yes | Yes | Yes | Yes |
| Manage delegates | Yes | Yes | No | No |
| Edit provider profile | Yes | Yes | No | No |

The feature access matrix is implemented as the `FeatureAccessMatrix` constant and enforced at the middleware layer via `app.authorize(featureKey)`.

---

# 5. Clinic / Practice Tier

## 5.1 Overview

The clinic/practice tier allows a practice administrator to group multiple physicians under a single consolidated Stripe subscription. This reduces per-physician cost by applying the 10% clinic discount.

## 5.2 Requirements

- **Minimum headcount:** 5 physicians to form or maintain a practice.
- **Practice admin:** The physician who creates the practice becomes the `PRACTICE_ADMIN`. They manage invitations, view the seat roster, and receive consolidated invoices.
- **Billing frequency:** Selected at practice creation time: `month` or `year`.
- **Stripe customer:** Each practice gets its own Stripe customer object (separate from individual physician customers).
- **Subscription quantity:** The practice's Stripe subscription uses quantity-based billing where quantity = number of consolidated seats.

## 5.3 Hybrid Billing Mode

When a physician joins a practice, their billing mode is determined by their current subscription status:

| Scenario | Billing Mode | Behaviour |
|----------|-------------|-----------|
| Physician has active early bird subscription with time remaining on rate lock | `INDIVIDUAL_EARLY_BIRD` | Physician retains their individual Stripe subscription at $199/month. NOT counted in practice's consolidated quantity. Transitions to `PRACTICE_CONSOLIDATED` when early bird lock expires. |
| All other physicians | `PRACTICE_CONSOLIDATED` | Physician's individual Stripe subscription is cancelled. They are counted in the practice's quantity-based subscription at the clinic rate. |

This hybrid model ensures that physicians who earned early bird pricing are not forced to give it up when joining a practice, since the clinic rate ($251.10/month) is higher than the early bird rate ($199/month).

## 5.4 Practice Creation

1. Physician calls `POST /api/v1/practices` with `name` and `billing_frequency`.
2. System validates: physician must have an ACTIVE subscription and not already be in an active practice.
3. Creates `practices` record. Creates `practice_memberships` record for the admin (billing_mode = `PRACTICE_CONSOLIDATED`).
4. Creates a Stripe customer for the practice.
5. Assigns the `PRACTICE_ADMIN` role to the creating physician.
6. Practice starts with 1 member; admin must invite at least 4 more to reach the 5-physician minimum.

## 5.5 Invitation Workflow

1. Practice admin calls `POST /api/v1/practices/:id/invitations` with the invitee's email.
2. System generates a cryptographically random invitation token. Only the SHA-256 hash of the token is stored; the raw token is included in the invitation email link.
3. Invitation expires after 7 days (`PRACTICE_INVITATION_EXPIRY_DAYS`).
4. Invitee calls `POST /api/v1/practice-invitations/:token/accept` to accept.
5. On acceptance:
   - System verifies the token hash matches, invitation is not expired, and invitee is not already in a practice.
   - Determines billing mode based on early bird status.
   - Creates `practice_memberships` record.
   - If `PRACTICE_CONSOLIDATED`, cancels the physician's individual Stripe subscription and increments the practice's subscription quantity.

## 5.6 Physician Removal

1. Practice admin calls `DELETE /api/v1/practices/:id/seats/:userId`.
2. Removal is **scheduled for end-of-month** (`removal_effective_at`). Physician retains access until then.
3. A scheduled job (`handleEndOfMonthRemovals`) processes removals:
   - Deactivates the membership record.
   - If the physician was `PRACTICE_CONSOLIDATED`, decrements the practice's Stripe subscription quantity.
4. If the practice headcount drops below 5 after the removal, the practice is **dissolved** (Section 5.7).

## 5.7 Practice Dissolution

When a practice's active headcount falls below `CLINIC_MINIMUM_PHYSICIANS` (5):

1. Practice status set to `CANCELLED`.
2. The practice's consolidated Stripe subscription is cancelled.
3. All remaining `PRACTICE_CONSOLIDATED` members are transitioned to individual Stripe subscriptions at the standard rate.
4. All members are notified via email and in-app notification.
5. `INDIVIDUAL_EARLY_BIRD` members are unaffected (they already have their own Stripe subscription).

## 5.8 Practice Admin Dashboard (Zero PHI)

The practice admin's seat roster endpoint (`GET /api/v1/practices/:id/seats`) returns only:

- Physician name
- Email
- Joined date
- Billing mode (`PRACTICE_CONSOLIDATED` or `INDIVIDUAL_EARLY_BIRD`)

**No PHI is exposed.** The admin cannot see claims, patients, or clinical data of other physicians in the practice.

## 5.9 Practice Invoice

The `GET /api/v1/practices/:id/invoices` endpoint returns consolidated billing information for the practice:

- Number of consolidated seats
- Per-seat rate (clinic monthly or clinic annual)
- Total before GST
- GST amount
- Total due

---

# 6. Pricing Lifecycle

## 6.1 Early Bird Rate Lock

When a physician subscribes to an early bird plan:

1. The `early_bird_locked_until` field is set to `created_at + 12 months`.
2. The physician retains the early bird rate ($199/month or $2,388/year) for 12 months regardless of any plan changes or practice membership changes.
3. **30-day warning:** A scheduled job (`checkEarlyBirdExpiry`) checks for subscriptions where `early_bird_locked_until` is within 30 days. If `early_bird_expiry_notified = false`, it sends a notification and sets the flag to `true`.

## 6.2 Early Bird Expiry

When the rate lock expires, a scheduled job (`checkEarlyBirdExpiry`) handles two paths:

**Path A — Physician is in a practice:**
1. Cancel the physician's individual early bird Stripe subscription.
2. Transition their billing mode from `INDIVIDUAL_EARLY_BIRD` to `PRACTICE_CONSOLIDATED`.
3. Increment the practice's Stripe subscription quantity.
4. Notify the physician.

**Path B — Physician is NOT in a practice:**
1. Transition the subscription plan from `EARLY_BIRD_*` to the corresponding `STANDARD_*` plan.
2. Update the Stripe subscription price.
3. Notify the physician.

## 6.3 Re-signup Prevention

A physician who has ever had an early bird subscription cannot regain early bird pricing upon re-subscription. The repository method `hasEverHadEarlyBird(providerId)` checks for any historical subscription record with an early bird plan. This check runs at checkout time.

---

# 7. Referral Program

## 7.1 Program Design

- **Referral code:** Each physician receives a unique 8-character alphanumeric code at signup. Character set excludes ambiguous characters (`0`, `O`, `1`, `I`, `L`). Codes are generated with collision detection and retry (up to 10 attempts).
- **Credit value:** 1 month free at the referrer's current rate at time of qualification. Credit values vary by plan:
  - Early Bird: $199.00
  - Standard Monthly: $279.00
  - Standard Annual: $265.08 (monthly equivalent: $3,181 / 12)
  - Clinic Monthly: $251.10
  - Clinic Annual: $238.58 (monthly equivalent: $2,863 / 12)
- **Annual cap:** Maximum 3 referral credits per physician per anniversary year.
- **Implementation:** Stripe negative invoice line items. No cash payouts.

## 7.2 Referral Lifecycle

| Status | Description |
|--------|-------------|
| `PENDING` | Referee has redeemed the code during registration. Waiting for referee to become a paying subscriber. |
| `QUALIFIED` | Referee has completed their first paid month. Referrer earns the credit. Credit value calculated. |
| `CREDITED` | Credit has been applied to the referrer's Stripe invoice (or practice invoice for clinic members). |
| `EXPIRED` | Referee did not become a paying subscriber within the qualifying window. |

## 7.3 Qualification Check

A scheduled job (`checkReferralQualification`) runs periodically to transition redemptions:

1. For each `PENDING` redemption: check if the referred physician now has an `ACTIVE` subscription with at least one paid invoice.
2. If qualified: transition to `QUALIFIED`, calculate credit value, check the referrer's annual cap (3/year).
3. If the referrer is on an individual plan: auto-apply the credit as a Stripe negative invoice item.
4. If the referrer is in a practice (clinic member): create the redemption as `QUALIFIED` and wait for the referrer to choose where to apply the credit (Section 7.4).

## 7.4 Clinic Credit Choice

When a clinic-member referrer earns a credit, they must choose where to apply it:

| Target | Key | Behaviour |
|--------|-----|-----------|
| Practice invoice | `PRACTICE_INVOICE` | Credit applied as a Stripe negative invoice item on the practice's consolidated subscription. |
| Individual bank | `INDIVIDUAL_BANK` | Credit applied directly to the referrer's individual Stripe customer balance. |

- The referrer has 7 days (`REFERRAL_CREDIT_CHOICE_DEADLINE_DAYS`) to make their choice.
- If no choice is made within 7 days, a scheduled job (`applyDefaultCreditChoice`) auto-applies the credit as `PRACTICE_INVOICE`.
- Same-practice referrals are prevented: a physician cannot refer someone who is already in the same practice.

## 7.5 Referee Incentive

After the early bird window closes (cap of 100 reached), referred physicians receive their first month free as a signup incentive. The function `shouldApplyRefereeIncentive()` checks whether the early bird cap has been reached before applying this benefit.

---

# 8. Cancellation & Refund Policies

## 8.1 Monthly Subscriptions

- Cancellation takes effect at the end of the current billing period (`cancel_at_period_end = true` via Stripe).
- No refund. Physician retains access until the period end date.

## 8.2 Annual Subscriptions

Annual subscriptions have a 6-month minimum commitment:

| Months Elapsed | Policy | Refund |
|----------------|--------|--------|
| 0-5 (months 1-6) | `FORFEIT_PERIOD` | No refund. Access continues until period end. Message: "Annual subscriptions require a 6-month minimum commitment." |
| 6-11 (months 7-12) | `PRORATED_REFUND` | Refund = `(12 - months_used) * (annual_amount / 12)`. Stripe refund issued against the latest paid payment intent. |
| 12+ | `PRORATED_REFUND` | $0 refund (fully used). |

**Refund process:**

1. Find the latest `PAID` payment for the subscription.
2. Create a Stripe refund with `payment_intent` and `amount` (in cents).
3. Record in `payment_history` with status `REFUNDED` and negative amounts.
4. Set `cancel_at_period_end = true` on the Stripe subscription.
5. Update local subscription status to `CANCELLED`.

## 8.3 Clinic Member Removal

When a physician is removed from a practice:

- Removal is scheduled for end-of-month, not immediate.
- The physician retains access until the scheduled removal date.
- If the physician was `PRACTICE_CONSOLIDATED`, their seat is decremented from the practice's Stripe subscription quantity at the end of the month.

## 8.4 Cancellation Constants

```
ANNUAL_MINIMUM_COMMITMENT_MONTHS = 6
determineCancellationPolicy(plan, monthsElapsed) → MONTHLY_CANCEL | FORFEIT_PERIOD | PRORATED_REFUND
calculateAnnualRefund(annualAmount, monthsUsed) → { refundAmount, monthsRemaining, monthlyRate } | null
```

---

# 9. Account Deletion & Data Destruction

## 9.1 Deletion Workflow

1. Physician requests account deletion from settings.
2. Confirmation dialog explains consequences: data will be permanently deleted after 45-day grace period.
3. Physician must type `DELETE` to confirm.
4. Subscription cancelled via Stripe immediately.
5. Account enters 45-day grace period. Data portability export available. Read-only access.
6. Data portability reminder notifications at Day 7 and Day 21 (`runExportWindowReminders`).
7. After 45 days: multi-phase data destruction begins (Section 9.2).

## 9.2 Multi-Phase Data Destruction

Data destruction proceeds through distinct phases, tracked in the `data_destruction_tracking` table:

| Phase | Status | Description |
|-------|--------|-------------|
| 1 | `PENDING` | Deletion requested. 45-day grace period begins. |
| 2 | `ACTIVE_DELETED` | Active database records deleted (claims, patients, provider profile, analytics, etc.). |
| 3 | `FILES_DELETED` | Object storage files deleted (report exports, attachments in DO Spaces). |
| 4 | `BACKUP_PURGED` | Backup copies purged. Deadline: 90 days after cancellation (`BACKUP_PURGE_DEADLINE_DAYS`). Admin confirms via `POST /api/v1/admin/destruction/:providerId/backup-purged`. |
| 5 | `CONFIRMED` | Destruction complete. Confirmation email sent to the physician's last known email address (`runDestructionConfirmation`). |

## 9.3 Data Retention After Deletion

| Data Type | Retention |
|-----------|-----------|
| Claims, patient records, provider profile | Deleted during Phase 2 (`ACTIVE_DELETED`). Irrecoverable. |
| Object storage files (reports, exports) | Deleted during Phase 3 (`FILES_DELETED`). |
| Backups | Purged during Phase 4 within 90 days. |
| Audit logs | Retained 10 years per HIA. PII stripped (provider_id replaced with hash, patient PHN removed). |
| IMA records | Retained 10 years (contractual evidence). |
| Stripe billing records | Retained by Stripe per their retention policy. Meritum's reference (customer_id, subscription_id) deleted. |
| AI learning data | Anonymised and retained for specialty cohort aggregates (no individual identification possible). |

---

# 10. Data Portability Export

## 10.1 Standard Portability Export

A ZIP file containing 6 CSV data types for basic data portability:

- `claims.csv` — AHCIP claims
- `wcb_claims.csv` — WCB claims
- `patients.csv` — Patient records
- `assessments.csv` — Assessments
- `analytics.csv` — Summary analytics
- `intelligence.csv` — AI coaching data

Available to physicians in any subscription status (including `CANCELLED` during the 45-day grace period).

## 10.2 Full Health Information Export (IMA-051)

A comprehensive export of ALL health information for a physician, covering every PHI table in the system. Required for HIA data portability compliance.

**Included entity types (25+):**

| Category | Entities |
|----------|----------|
| Patient data | patients (including inactive) |
| Claim lifecycle | claims, claim_audit_history, shifts, claim_exports |
| AHCIP pathway | ahcip_claim_details, ahcip_batches |
| WCB pathway | wcb_claim_details, wcb_batches, wcb_remittance_imports |
| Provider profile | provider, business_arrangements, practice_locations, wcb_configurations, delegate_relationships, submission_preferences, hlink_configurations |
| PCPCM | pcpcm_enrolments, pcpcm_payments, pcpcm_panel_estimates |
| Analytics | analytics_cache, generated_reports, report_subscriptions |
| Intelligence / AI | ai_provider_learning, ai_suggestion_events |
| Mobile | ed_shifts, favourite_codes |
| Platform | subscription, ima_amendment_responses |
| Audit | audit_log (scoped by userId = providerId) |

**Export process:**

1. Retrieve ALL health information via the export repository (`getCompleteHealthInformation`), scoped by `providerId`.
2. Serialise each entity type to the requested format (CSV or JSON).
3. Bundle into a ZIP archive with a `manifest.json` containing export date, provider ID, format, entity counts, and schema version (`1.0.0`).
4. Upload to DigitalOcean Spaces.
5. Generate a presigned download URL with 72-hour expiry.
6. Create a `generated_reports` record with type `FULL_DATA_PORTABILITY`.
7. Audit log entries created for both `export.full_hi_requested` and `export.full_hi_ready`.
8. Notification emitted: `FULL_HI_EXPORT_READY`.

**Security:**
- Endpoint: `POST /api/v1/platform/export/full` with `DATA_EXPORT` permission check and audit logging enabled.
- Available in `CANCELLED` subscription state (required by HIA for data portability).
- Download link requires authentication and physician scoping (another physician cannot access the URL).

---

# 11. IMA Amendment Management

## 11.1 Overview

The Independent Member Agreement (IMA) governs the relationship between Meritum and each physician. Amendments to the IMA require physician notification, acknowledgement, and in some cases acceptance.

## 11.2 Amendment Types

| Type | Key | Physician Action Required |
|------|-----|--------------------------|
| Non-material | `NON_MATERIAL` | Acknowledge (read receipt). No blocking effect. |
| Material | `MATERIAL` | Accept or reject. Unacknowledged material amendments block subscription renewal. |

## 11.3 Amendment Lifecycle

1. **Admin creates amendment:** `POST /api/v1/platform/amendments` — includes title, description, type, notice date, effective date, and a SHA-256 document hash (computed server-side).
2. **Physicians notified:** All active physicians receive a notification about the amendment.
3. **Physician acknowledges (non-material):** `POST /api/v1/platform/amendments/:id/acknowledge` — records response with IP address and user agent for audit.
4. **Physician responds (material):** `POST /api/v1/platform/amendments/:id/respond` with `ACCEPTED` or `REJECTED`.
5. **Blocking check:** `getBlockingAmendments(providerId)` returns any material amendments past their effective date that the physician has not yet responded to. These block subscription-related actions.
6. **Reminders:** A scheduled job (`runAmendmentReminders`) sends periodic reminders for unacknowledged amendments.

## 11.4 Response Recording

Each response is recorded in `ima_amendment_responses` with:

- `response_type`: `ACKNOWLEDGED`, `ACCEPTED`, or `REJECTED`
- `responded_at`: server timestamp
- `ip_address`: from HTTP request (server-extracted, not client-submitted)
- `user_agent`: from HTTP request (server-extracted, not client-submitted)

A unique index on `(amendment_id, provider_id)` prevents duplicate responses.

## 11.5 Pending Amendments

Physicians can view their pending amendments via `GET /api/v1/account/pending-amendments`.

---

# 12. Breach Notification (HIA Compliance)

## 12.1 Overview

Under HIA s.8.1, Meritum must notify affected custodians within 72 hours of becoming aware of a privacy breach. This module tracks breaches, manages notifications, and ensures compliance deadlines are met.

## 12.2 Breach Lifecycle

| Status | Key | Description |
|--------|-----|-------------|
| Investigating | `INVESTIGATING` | Breach identified, under investigation. |
| Notifying | `NOTIFYING` | Notifications being sent to affected custodians. |
| Monitoring | `MONITORING` | Post-notification monitoring period. |
| Resolved | `RESOLVED` | Breach resolved. Resolution timestamp recorded. |

## 12.3 Breach Record

A breach record includes:

- `breach_description`: Description of the breach event.
- `breach_date`: When the breach occurred.
- `awareness_date`: When Meritum became aware (starts the 72-hour clock).
- `hi_description`: Description of the health information involved.
- `includes_iihi`: Whether individually identifying health information is involved.
- `affected_count`: Number of affected individuals (if known).
- `risk_assessment`: Assessment of risk to affected individuals.
- `mitigation_steps`: Steps taken to mitigate the breach.
- `contact_name` / `contact_email`: Privacy officer contact for the breach.
- `evidence_hold_until`: Evidence preservation period (minimum: `awareness_date + 12 months`).

## 12.4 Affected Custodian Tracking

The `breach_affected_custodians` table links breach records to affected physician custodians. Tracks:

- `provider_id`: Affected physician.
- `initial_notified_at`: Timestamp of initial notification.
- `notification_method`: How the notification was delivered (e.g., email, in-app).

## 12.5 Breach Notification Process

1. Admin creates breach: `POST /api/v1/platform/breaches`.
2. Admin triggers notifications: `POST /api/v1/platform/breaches/:id/notify` — sends dual-delivery notifications (email + in-app) to all affected custodians.
3. Admin adds updates: `POST /api/v1/platform/breaches/:id/updates` — append-only update types: `INITIAL` or `SUPPLEMENTARY`.
4. Admin resolves breach: `POST /api/v1/platform/breaches/:id/resolve`.

## 12.6 Breach Deadline Monitoring

A scheduled job (`checkBreachDeadlines`) monitors breaches approaching the 72-hour notification deadline and alerts operations.

## 12.7 Evidence Hold

When a breach is created, an evidence hold is set (`evidence_hold_until`) for a minimum of 12 months. This prevents the data destruction process from purging any records related to the breach within the hold period. Audit action: `breach.evidence_hold_set`.

---

# 13. Status Page

A public status page at status.meritum.ca shows platform health. Accessible without authentication.

## 13.1 Monitored Components

| Component | Key | What is Monitored |
|-----------|-----|-------------------|
| Web Application | `WEB_APP` | Availability, response time, error rate |
| API | `API` | Availability, response time, error rate per endpoint group |
| H-Link Submission | `HLINK_SUBMISSION` | Batch transmission success rate, last successful transmission time |
| WCB Submission | `WCB_SUBMISSION` | Batch generation success rate |
| AI Coach (Tier 2 LLM) | `AI_COACH` | Availability, response time, fallback rate |
| Email Delivery | `EMAIL_DELIVERY` | Delivery rate, bounce rate, queue depth |
| Database | `DATABASE` | Connection pool utilisation, query latency |
| Payment Processing (Stripe) | `PAYMENT_PROCESSING` | Webhook delivery success, payment processing status |

## 13.2 Component Health Statuses

| Status | Key |
|--------|-----|
| Operational | `OPERATIONAL` |
| Degraded Performance | `DEGRADED` |
| Partial Outage | `PARTIAL_OUTAGE` |
| Major Outage | `MAJOR_OUTAGE` |
| Under Maintenance | `MAINTENANCE` |

## 13.3 Incident Management

- Incidents created manually by operations team or auto-created by monitoring alerts: `POST /api/v1/admin/incidents`.
- Incident statuses: `INVESTIGATING`, `IDENTIFIED`, `MONITORING`, `RESOLVED`.
- Incident updates posted via `POST /api/v1/admin/incidents/:id/updates` — append-only timeline.
- Component status updated via `PATCH /api/v1/admin/components/:id/status`.
- Public endpoints (no auth): `GET /api/v1/status`, `GET /api/v1/status/incidents`, `GET /api/v1/status/incidents/:id`.
- Post-incident reports published for significant outages (>30 minutes).

---

# 14. System Health Monitoring

## 14.1 Key Metrics

| Metric | Target | Alert Threshold |
|--------|--------|-----------------|
| API availability | 99.9% | < 99.5% over 5 minutes |
| API p95 latency | < 500ms | > 1000ms over 5 minutes |
| Error rate (5xx) | < 0.1% | > 1% over 5 minutes |
| H-Link batch success rate | 100% | Any failure triggers alert |
| Database connection pool | < 70% utilisation | > 85% utilisation |
| Email delivery rate | > 99% | < 95% over 1 hour |
| LLM availability | > 99% | < 95% (triggers Tier 1 fallback) |
| Disk usage | < 70% | > 85% |

## 14.2 Observability Stack

- **Application logging:** Structured JSON logs with correlation IDs. Shipped to log aggregation service.
- **Metrics collection:** Application metrics (request count, latency, error rate) collected and stored in time-series database.
- **Alerting:** Threshold-based alerts delivered to operations team via PagerDuty or equivalent.
- **Dashboards:** Internal operational dashboards (separate from physician-facing analytics) showing platform health, user activity, and business metrics.

Specific tooling choices (Grafana, Datadog, CloudWatch, etc.) deferred to infrastructure implementation.

---

# 15. Data Model

## 15.1 Subscriptions Table (`subscriptions`)

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `subscription_id` | UUID PK | No | Primary key |
| `provider_id` | UUID FK → users | No | FK to users. Unique (one subscription per physician). |
| `stripe_customer_id` | VARCHAR(50) | No | Stripe customer ID |
| `stripe_subscription_id` | VARCHAR(50) | No | Stripe subscription ID |
| `plan` | VARCHAR(30) | No | `STANDARD_MONTHLY`, `STANDARD_ANNUAL`, `EARLY_BIRD_MONTHLY`, `EARLY_BIRD_ANNUAL`, `CLINIC_MONTHLY`, `CLINIC_ANNUAL` |
| `status` | VARCHAR(20) | No | `TRIAL`, `ACTIVE`, `PAST_DUE`, `SUSPENDED`, `CANCELLED`. Default: `TRIAL`. |
| `current_period_start` | TIMESTAMPTZ | No | Current billing period start |
| `current_period_end` | TIMESTAMPTZ | No | Current billing period end |
| `trial_end` | TIMESTAMPTZ | Yes | Trial period end (if applicable) |
| `failed_payment_count` | INTEGER | No | Consecutive failed payment count. Resets on successful payment. Default: 0. |
| `suspended_at` | TIMESTAMPTZ | Yes | When account was suspended |
| `cancelled_at` | TIMESTAMPTZ | Yes | When subscription was cancelled |
| `practice_id` | UUID FK → practices | Yes | FK to practices (if physician is in a practice) |
| `deletion_scheduled_at` | TIMESTAMPTZ | Yes | When data deletion is scheduled (45 days after cancellation) |
| `early_bird_locked_until` | TIMESTAMPTZ | Yes | Rate lock expiry. Set to `created_at + 12 months` for early bird plans. Null for non-early-bird. |
| `early_bird_expiry_notified` | BOOLEAN | No | Whether the 30-day expiry warning has been sent. Default: `false`. |
| `created_at` | TIMESTAMPTZ | No | |
| `updated_at` | TIMESTAMPTZ | No | |

**Indexes:** `provider_id` (unique), `stripe_customer_id`, `stripe_subscription_id`, `status`, `deletion_scheduled_at`, `practice_id`, `early_bird_locked_until`.

## 15.2 Payment History Table (`payment_history`)

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `payment_id` | UUID PK | No | Primary key |
| `subscription_id` | UUID FK → subscriptions | No | FK to subscriptions |
| `stripe_invoice_id` | VARCHAR(50) | No | Stripe invoice ID (or `refund_{id}` for refunds) |
| `amount_cad` | DECIMAL(10,2) | No | Amount in CAD (before GST). Negative for refunds. |
| `gst_amount` | DECIMAL(10,2) | No | GST amount (5%). 0 for refunds. |
| `total_cad` | DECIMAL(10,2) | No | Total charged (amount + GST). Negative for refunds. |
| `status` | VARCHAR(20) | No | `PAID`, `FAILED`, `REFUNDED` |
| `paid_at` | TIMESTAMPTZ | Yes | When payment was confirmed |
| `created_at` | TIMESTAMPTZ | No | |

**Indexes:** `(subscription_id, created_at)`, `stripe_invoice_id`.

## 15.3 Status Components Table (`status_components`)

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `component_id` | UUID PK | No | Primary key |
| `name` | VARCHAR(50) | No | Component key (unique) |
| `display_name` | VARCHAR(100) | No | Human-readable name |
| `status` | VARCHAR(20) | No | Health status. Default: `operational`. |
| `description` | TEXT | Yes | Component description |
| `sort_order` | INTEGER | No | Display order. Default: 0. |
| `updated_at` | TIMESTAMPTZ | No | |

## 15.4 Status Incidents Table (`status_incidents`)

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `incident_id` | UUID PK | No | Primary key |
| `title` | VARCHAR(200) | No | Incident title |
| `status` | VARCHAR(20) | No | `INVESTIGATING`, `IDENTIFIED`, `MONITORING`, `RESOLVED` |
| `severity` | VARCHAR(20) | No | Severity level |
| `affected_components` | JSONB | No | Array of affected component IDs |
| `resolved_at` | TIMESTAMPTZ | Yes | Resolution timestamp |
| `created_at` | TIMESTAMPTZ | No | |
| `updated_at` | TIMESTAMPTZ | No | |

## 15.5 Incident Updates Table (`incident_updates`)

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `update_id` | UUID PK | No | Primary key |
| `incident_id` | UUID FK → status_incidents | No | FK to incidents |
| `status` | VARCHAR(20) | No | Status at time of update |
| `message` | TEXT | No | Update message |
| `created_at` | TIMESTAMPTZ | No | |

## 15.6 Referral Codes Table (`referral_codes`)

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `referral_code_id` | UUID PK | No | Primary key |
| `referrer_user_id` | UUID FK → users | No | Physician who owns the code |
| `code` | VARCHAR(20) | No | 8-character alphanumeric code (unique) |
| `is_active` | BOOLEAN | No | Whether the code is active. Default: `true`. |
| `created_at` | TIMESTAMPTZ | No | |

**Indexes:** `code` (unique), `referrer_user_id`.

## 15.7 Referral Redemptions Table (`referral_redemptions`)

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `redemption_id` | UUID PK | No | Primary key |
| `referral_code_id` | UUID FK → referral_codes | No | FK to the redeemed referral code |
| `referrer_user_id` | UUID FK → users | No | Referrer physician |
| `referred_user_id` | UUID FK → users | No | Referred physician |
| `status` | VARCHAR(20) | No | `PENDING`, `QUALIFIED`, `CREDITED`, `EXPIRED`. Default: `PENDING`. |
| `credit_month_value_cad` | DECIMAL(10,2) | Yes | Credit value (1 month at referrer's rate). Set on qualification. |
| `credit_applied_to` | VARCHAR(20) | Yes | `PRACTICE_INVOICE` or `INDIVIDUAL_BANK`. Set when credit is applied. |
| `credit_applied_at` | TIMESTAMPTZ | Yes | When credit was applied |
| `qualifying_event_at` | TIMESTAMPTZ | Yes | When the referee qualified |
| `anniversary_year` | INTEGER | No | Anniversary year for the 3/year cap |
| `created_at` | TIMESTAMPTZ | No | |

**Indexes:** `referral_code_id`, `referred_user_id`, `referrer_user_id`, `status`, `(referrer_user_id, anniversary_year)`.

## 15.8 Practices Table (`practices`)

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `practice_id` | UUID PK | No | Primary key |
| `name` | VARCHAR(200) | No | Practice display name |
| `admin_user_id` | UUID FK → users | No | Practice administrator |
| `stripe_customer_id` | VARCHAR(50) | Yes | Stripe customer ID for the practice |
| `stripe_subscription_id` | VARCHAR(50) | Yes | Stripe subscription ID for consolidated billing |
| `billing_frequency` | VARCHAR(10) | No | `month` or `year` |
| `status` | VARCHAR(20) | No | `ACTIVE`, `SUSPENDED`, `CANCELLED`. Default: `ACTIVE`. |
| `current_period_start` | TIMESTAMPTZ | No | Billing period start |
| `current_period_end` | TIMESTAMPTZ | No | Billing period end |
| `created_at` | TIMESTAMPTZ | No | |
| `updated_at` | TIMESTAMPTZ | No | |

**Indexes:** `admin_user_id`, `stripe_customer_id`, `status`.

## 15.9 Practice Memberships Table (`practice_memberships`)

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `membership_id` | UUID PK | No | Primary key |
| `practice_id` | UUID FK → practices | No | FK to practice |
| `physician_user_id` | UUID FK → users | No | FK to physician user |
| `billing_mode` | VARCHAR(30) | No | `PRACTICE_CONSOLIDATED` or `INDIVIDUAL_EARLY_BIRD`. Default: `PRACTICE_CONSOLIDATED`. |
| `joined_at` | TIMESTAMPTZ | No | When physician joined |
| `removed_at` | TIMESTAMPTZ | Yes | When removal was requested |
| `removal_effective_at` | TIMESTAMPTZ | Yes | When removal takes effect (end of month) |
| `is_active` | BOOLEAN | No | Soft delete. Default: `true`. |
| `created_at` | TIMESTAMPTZ | No | |

**Indexes:** `(practice_id, physician_user_id)` unique where `is_active = true`, `physician_user_id` unique where `is_active = true` (physician can only be in one active practice), `practice_id` where `is_active = true`.

## 15.10 Practice Invitations Table (`practice_invitations`)

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `invitation_id` | UUID PK | No | Primary key |
| `practice_id` | UUID FK → practices | No | FK to practice |
| `invited_email` | VARCHAR(255) | No | Email of the invitee |
| `invited_by_user_id` | UUID FK → users | No | Admin who sent the invitation |
| `status` | VARCHAR(20) | No | `PENDING`, `ACCEPTED`, `DECLINED`, `EXPIRED`. Default: `PENDING`. |
| `token_hash` | VARCHAR(128) | No | SHA-256 hash of the invitation token. Raw token is NEVER stored. |
| `expires_at` | TIMESTAMPTZ | No | Expiry: 7 days after creation. |
| `created_at` | TIMESTAMPTZ | No | |

**Indexes:** `practice_id`, `token_hash`, `invited_email`, `status`.

## 15.11 IMA Amendments Table (`ima_amendments`)

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `amendment_id` | UUID PK | No | Primary key |
| `amendment_type` | VARCHAR(20) | No | `NON_MATERIAL` or `MATERIAL` |
| `title` | TEXT | No | Amendment title |
| `description` | TEXT | No | Amendment description |
| `document_hash` | VARCHAR(64) | No | SHA-256 of the amendment document |
| `notice_date` | TIMESTAMPTZ | No | When physicians were notified |
| `effective_date` | TIMESTAMPTZ | No | When the amendment takes effect |
| `created_by` | UUID FK → users | No | Admin who created the amendment |
| `created_at` | TIMESTAMPTZ | No | |

**Indexes:** `amendment_type`, `effective_date`.

## 15.12 IMA Amendment Responses Table (`ima_amendment_responses`)

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `response_id` | UUID PK | No | Primary key |
| `amendment_id` | UUID FK → ima_amendments | No | FK to amendment |
| `provider_id` | UUID FK → providers | No | Responding physician |
| `response_type` | VARCHAR(20) | No | `ACKNOWLEDGED`, `ACCEPTED`, `REJECTED` |
| `responded_at` | TIMESTAMPTZ | No | Server timestamp |
| `ip_address` | VARCHAR(45) | No | Request IP (server-extracted) |
| `user_agent` | VARCHAR(500) | No | Request user agent (server-extracted) |

**Indexes:** `amendment_id`, `provider_id`, `(amendment_id, provider_id)` unique.

## 15.13 Breach Records Table (`breach_records`)

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `breach_id` | UUID PK | No | Primary key |
| `breach_description` | TEXT | No | Description of the breach |
| `breach_date` | TIMESTAMPTZ | No | When the breach occurred |
| `awareness_date` | TIMESTAMPTZ | No | When Meritum became aware (starts 72h clock) |
| `hi_description` | TEXT | No | Description of HI involved |
| `includes_iihi` | BOOLEAN | No | Whether IIHI is involved |
| `affected_count` | INTEGER | Yes | Number of affected individuals |
| `risk_assessment` | TEXT | Yes | Risk assessment |
| `mitigation_steps` | TEXT | Yes | Mitigation actions taken |
| `contact_name` | VARCHAR(200) | No | Privacy officer contact |
| `contact_email` | VARCHAR(100) | No | Privacy officer email |
| `status` | VARCHAR(20) | No | `INVESTIGATING`, `NOTIFYING`, `MONITORING`, `RESOLVED`. Default: `INVESTIGATING`. |
| `evidence_hold_until` | TIMESTAMPTZ | Yes | Evidence preservation deadline (min: awareness + 12 months) |
| `created_by` | UUID FK → users | No | Admin who created the record |
| `created_at` | TIMESTAMPTZ | No | |
| `updated_at` | TIMESTAMPTZ | No | |
| `resolved_at` | TIMESTAMPTZ | Yes | Resolution timestamp |

**Indexes:** `status`, `awareness_date`.

## 15.14 Breach Affected Custodians Table (`breach_affected_custodians`)

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `id` | UUID PK | No | Primary key |
| `breach_id` | UUID FK → breach_records | No | FK to breach |
| `provider_id` | UUID FK → providers | No | Affected physician |
| `initial_notified_at` | TIMESTAMPTZ | Yes | When initial notification was sent |
| `notification_method` | VARCHAR(50) | Yes | Delivery method (e.g., email, in-app) |

**Indexes:** `breach_id`, `(breach_id, provider_id)` unique.

## 15.15 Breach Updates Table (`breach_updates`)

Append-only table. No UPDATE or DELETE operations.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `update_id` | UUID PK | No | Primary key |
| `breach_id` | UUID FK → breach_records | No | FK to breach |
| `update_type` | VARCHAR(20) | No | `INITIAL` or `SUPPLEMENTARY` |
| `content` | TEXT | No | Update content |
| `sent_at` | TIMESTAMPTZ | No | When update was sent |
| `created_by` | UUID FK → users | No | Admin who created the update |

## 15.16 Data Destruction Tracking Table (`data_destruction_tracking`)

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `tracking_id` | UUID PK | No | Primary key |
| `provider_id` | UUID FK → providers | No | Physician (unique — one record per physician) |
| `last_known_email` | VARCHAR(320) | Yes | For sending destruction confirmation |
| `active_deleted_at` | TIMESTAMPTZ | Yes | Phase 2 completion |
| `files_deleted_at` | TIMESTAMPTZ | Yes | Phase 3 completion |
| `backup_purge_deadline` | TIMESTAMPTZ | Yes | Deadline for Phase 4 (90 days) |
| `backup_purged_at` | TIMESTAMPTZ | Yes | Phase 4 completion |
| `confirmation_sent_at` | TIMESTAMPTZ | Yes | Phase 5 confirmation email sent |
| `created_at` | TIMESTAMPTZ | No | |

**Indexes:** `backup_purge_deadline`.

---

# 16. API Contracts

## 16.1 Platform Routes (platform.routes.ts)

### Stripe Webhook

| Method | Path | Auth | Role | Description |
|--------|------|------|------|-------------|
| POST | `/api/v1/webhooks/stripe` | Stripe signature only | — | Stripe webhook receiver. No Meritum auth. |

### Subscription Management

| Method | Path | Auth | Role | Description |
|--------|------|------|------|-------------|
| POST | `/api/v1/subscriptions/checkout` | Yes | PHYSICIAN | Create Stripe Checkout session. Body: `createCheckoutSessionSchema` (plan selection). |
| POST | `/api/v1/subscriptions/portal` | Yes | PHYSICIAN | Create Stripe Customer Portal session. Body: `createPortalSessionSchema`. |
| GET | `/api/v1/subscriptions/current` | Yes | PHYSICIAN | Get current subscription status. |
| GET | `/api/v1/subscriptions/payments` | Yes | PHYSICIAN | List payment history. Query: `page`, `page_size`. |
| POST | `/api/v1/subscriptions/cancel` | Yes | PHYSICIAN | Cancel subscription. Policy determined by plan and months elapsed. |

### Admin Routes

| Method | Path | Auth | Role | Description |
|--------|------|------|------|-------------|
| GET | `/api/v1/admin/subscriptions` | Yes | ADMIN | List all subscriptions. Query: `adminSubscriptionQuerySchema`. |
| PATCH | `/api/v1/admin/subscriptions/:id/status` | Yes | ADMIN | Update subscription status. Params: UUID. Body: `{ status }`. |

### Public Status Routes

| Method | Path | Auth | Role | Description |
|--------|------|------|------|-------------|
| GET | `/api/v1/status` | No | — | Get current platform status page. |
| GET | `/api/v1/status/incidents` | No | — | List incident history. Query: `incidentHistoryQuerySchema`. |
| GET | `/api/v1/status/incidents/:id` | No | — | Get single incident detail. Params: UUID. |

### Admin Incident Management

| Method | Path | Auth | Role | Description |
|--------|------|------|------|-------------|
| POST | `/api/v1/admin/incidents` | Yes | ADMIN | Create incident. Body: `createIncidentSchema`. |
| POST | `/api/v1/admin/incidents/:id/updates` | Yes | ADMIN | Add incident update. Body: `updateIncidentSchema`. |
| PATCH | `/api/v1/admin/components/:id/status` | Yes | ADMIN | Update component status. Body: `updateComponentStatusSchema`. |

### IMA Amendment Routes

| Method | Path | Auth | Role | Description |
|--------|------|------|------|-------------|
| POST | `/api/v1/platform/amendments` | Yes | ADMIN | Create amendment. Body: `createAmendmentSchema`. |
| GET | `/api/v1/platform/amendments` | Yes | ADMIN | List amendments. Query: `listAmendmentsQuerySchema`. |
| GET | `/api/v1/platform/amendments/:id` | Yes | ADMIN | Get amendment detail. |
| POST | `/api/v1/platform/amendments/:id/acknowledge` | Yes | PHYSICIAN | Acknowledge non-material amendment. |
| POST | `/api/v1/platform/amendments/:id/respond` | Yes | PHYSICIAN | Respond to material amendment. Body: `amendmentResponseSchema`. |
| GET | `/api/v1/account/pending-amendments` | Yes | PHYSICIAN | Get physician's pending amendments. |

### Breach Notification Routes

| Method | Path | Auth | Role | Description |
|--------|------|------|------|-------------|
| POST | `/api/v1/platform/breaches` | Yes | ADMIN | Create breach record. Body: `createBreachSchema`. |
| GET | `/api/v1/platform/breaches` | Yes | ADMIN | List breaches. Query: `listBreachesQuerySchema`. |
| GET | `/api/v1/platform/breaches/:id` | Yes | ADMIN | Get breach detail. |
| POST | `/api/v1/platform/breaches/:id/notify` | Yes | ADMIN | Send breach notifications to affected custodians. |
| POST | `/api/v1/platform/breaches/:id/updates` | Yes | ADMIN | Add breach update. Body: `breachUpdateSchema`. |
| POST | `/api/v1/platform/breaches/:id/resolve` | Yes | ADMIN | Resolve breach. |

### Data Export Routes

| Method | Path | Auth | Permission | Description |
|--------|------|------|-----------|-------------|
| POST | `/api/v1/platform/export/full` | Yes | `DATA_EXPORT` | Generate full HI export. Body: `fullHiExportSchema`. Audit logged. |

### Data Destruction Routes

| Method | Path | Auth | Role | Description |
|--------|------|------|------|-------------|
| POST | `/api/v1/admin/destruction/:providerId/backup-purged` | Yes | ADMIN | Mark backup purge complete for a provider. |

## 16.2 Practice Routes (practice.routes.ts)

| Method | Path | Auth | Authorization | Description |
|--------|------|------|--------------|-------------|
| POST | `/api/v1/practices` | Yes | PHYSICIAN or PRACTICE_ADMIN | Create a new practice. Body: `createPracticeSchema` (name, billing_frequency). |
| GET | `/api/v1/practices/:id` | Yes | Practice admin only | Get practice details. |
| PATCH | `/api/v1/practices/:id` | Yes | Practice admin only | Update practice. Body: `updatePracticeSchema`. |
| GET | `/api/v1/practices/:id/seats` | Yes | Practice admin only | Get practice seat roster (zero PHI). Query: `practiceSeatsQuerySchema`. |
| POST | `/api/v1/practices/:id/invitations` | Yes | Practice admin only | Invite physician to practice. Body: `invitePhysicianSchema` (email). |
| POST | `/api/v1/practice-invitations/:token/accept` | Yes | PHYSICIAN or PRACTICE_ADMIN | Accept practice invitation. |
| DELETE | `/api/v1/practices/:id/seats/:userId` | Yes | Practice admin only | Remove physician from practice (scheduled end-of-month). |
| GET | `/api/v1/practices/:id/invoices` | Yes | Practice admin only | Get consolidated practice invoice info. Query: `practiceInvoicesQuerySchema`. |

---

# 17. Pricing Utility Functions

Located in `packages/shared/src/utils/pricing.utils.ts`:

### `calculateEffectiveRate(baseMonthly, isAnnual, isClinic)`

Calculates the effective subscription rate based on billing frequency and tier:

1. Base rate: $279/month.
2. Annual billing: 5% off base -> $265.05/month, $3,180.60/year.
3. Clinic tier: 10% off base -> $251.10/month.
4. Clinic + annual: 15% off (ceiling) -> $237.15/month, $2,845.80/year.
5. Enforces minimum rate floor (85% of base = $237.15/month).

Returns `{ monthlyRate, annualRate, appliedDiscounts, totalDiscountPercent }`.

### `isEarlyBirdRate(plan)`

Returns `true` if the plan string contains `EARLY_BIRD`. Early bird pricing does not participate in the discount framework.

### `getEarlyBirdRate(isAnnual)`

Returns the early bird effective rate. No discounts apply. Annual early bird = $199 * 12 = $2,388.

### `determineCancellationPolicy(plan, monthsElapsed)`

Located in `packages/shared/src/constants/platform.constants.ts`. Returns the applicable cancellation policy:

- Monthly plans: `MONTHLY_CANCEL`.
- Annual plans with < 6 months elapsed: `FORFEIT_PERIOD`.
- Annual plans with >= 6 months elapsed: `PRORATED_REFUND`.

### `calculateAnnualRefund(annualAmount, monthsUsed)`

Located in `packages/shared/src/constants/platform.constants.ts`. Calculates the prorated refund:

- Returns `null` if `monthsUsed < 6` (forfeit period).
- Returns `{ refundAmount, monthsRemaining, monthlyRate }` otherwise.
- Formula: `refund = (12 - months_used) * (annual_amount / 12)`.

---

# 18. Scheduled Jobs

The following background jobs run on scheduled intervals:

| Job | Function | Description |
|-----|----------|-------------|
| Dunning check | `runDunningCheck` | Advances dunning sequence for PAST_DUE subscriptions. Suspends at Day 14, cancels at Day 30. |
| Cancellation check | `runCancellationCheck` | Processes subscriptions set to cancel at period end when period has expired. |
| Deletion check | `runDeletionCheck` | Processes accounts past the 45-day deletion grace period. Initiates data destruction. |
| Export window reminders | `runExportWindowReminders` | Sends data portability export reminders at Day 7 and Day 21 of deletion grace period. |
| Early bird expiry | `checkEarlyBirdExpiry` | Sends 30-day warning for expiring early bird rates. Transitions expired early bird subscriptions (Path A: practice member, Path B: individual). |
| Amendment reminders | `runAmendmentReminders` | Sends periodic reminders for unacknowledged IMA amendments. |
| Destruction confirmation | `runDestructionConfirmation` | Sends destruction confirmation emails when all phases are complete. |
| Breach deadline check | `checkBreachDeadlines` | Monitors breaches approaching the 72-hour notification deadline. |
| End-of-month removals | `handleEndOfMonthRemovals` | Processes scheduled physician removals from practices. Triggers dissolution if headcount drops below 5. |
| Referral qualification | `checkReferralQualification` | Transitions PENDING referral redemptions to QUALIFIED or EXPIRED. Calculates credit value. |
| Default credit choice | `applyDefaultCreditChoice` | Auto-applies clinic referral credits as PRACTICE_INVOICE after 7-day deadline. |

---

# 19. User Stories & Acceptance Criteria

| ID | Story | Acceptance Criteria |
|----|-------|---------------------|
| PLT-001 | As a new physician, I want to subscribe and pay for Meritum | Select plan (6 options). Enter payment via Stripe Checkout. Subscription created. Early bird rate lock set if applicable. Proceed to onboarding. |
| PLT-002 | As a physician, I want to view my invoices and update payment method | Link to Stripe Customer Portal from account settings. View invoices. Update card. Download invoice PDFs. |
| PLT-003 | As a physician, I want to know if my payment failed | PAYMENT_FAILED notification (in-app + email) immediately. Clear instructions to update payment method. |
| PLT-004 | As a physician, I want my account to continue working during payment issues | Full access during PAST_DUE (14 days). Submission blocked only at SUSPENDED. Grace period clearly communicated. |
| PLT-005 | As a physician, I want to delete my account and get my data | Request deletion. Full HI export available (25+ entity types, CSV/JSON). 45-day grace. Reminders at Day 7 and 21. Multi-phase destruction after 45 days. Confirmation email on completion. |
| PLT-006 | As a physician, I want to check platform status during issues | Public status page at status.meritum.ca. 8 components. Incident history. No auth required. |
| PLT-007 | As a physician, I want to switch from monthly to annual billing | Via Stripe Customer Portal. Proration handled by Stripe. Meritum updates plan record on webhook. |
| PLT-008 | As a practice admin, I want to create a practice and invite physicians | Create practice with name and billing frequency. Invite by email. 7-day expiry on invitations. Practice created with 1 member. |
| PLT-009 | As a practice admin, I want to view my practice's seats and invoices | Seat roster shows name, email, joined date, billing mode (zero PHI). Invoice shows consolidated seat count and totals. |
| PLT-010 | As a physician, I want to accept a practice invitation | Accept via invitation link. Billing mode determined automatically (early bird keeps individual, others go consolidated). |
| PLT-011 | As a practice admin, I want to remove a physician from my practice | Removal scheduled for end-of-month. Physician retains access until then. Practice dissolved if headcount drops below 5. |
| PLT-012 | As a physician, I want to refer another physician | Get my 8-character referral code. Referred physician enters code at registration. Earn 1-month credit when referee pays first month. Max 3 credits/year. |
| PLT-013 | As a clinic member, I want to choose where to apply my referral credit | Choose between practice invoice or individual bank account. 7-day deadline; auto-applies to practice invoice if no choice made. |
| PLT-014 | As a physician, I want to cancel my annual subscription and get a prorated refund | Cancel after 6 months: prorated refund issued. Cancel before 6 months: no refund, access continues to period end. |
| PLT-015 | As a physician, I want to acknowledge an IMA amendment | View amendment details. Acknowledge (non-material) or accept/reject (material). Response recorded with timestamp, IP, and user agent. |
| PLT-016 | As an admin, I want to manage privacy breach notifications | Create breach record. Track affected custodians. Send dual-delivery notifications within 72h. Add updates. Resolve. |
| PLT-017 | As a physician, I want a complete export of all my health information | Request full HI export. ZIP file with 25+ entity types in CSV or JSON format. Presigned download link valid 72 hours. Available even in CANCELLED state. |

---

# 20. Testing Requirements

Core subscription flows:

- Stripe Checkout -> subscription created -> webhook received -> Meritum subscription record created (all 6 plan types)
- Payment failure webhook -> PAYMENT_FAILED notification -> dunning sequence starts
- Day 14 without payment -> account SUSPENDED -> claim submission blocked
- Payment recovered -> account ACTIVE -> submission unblocked
- Subscription cancelled -> 45-day grace -> data export available -> multi-phase data destruction

Pricing and billing:

- GST correctly calculated on all invoices (5% of base amount)
- Early bird pricing: first 100 physicians get $199/month. Physician 101 gets $279/month
- Early bird rate lock: locked for 12 months, 30-day warning sent, expires to standard rate
- Re-signup prevention: physician who had early bird cannot regain it
- Discount stacking: annual 5% + clinic 10% = 15% ceiling, minimum floor enforced
- Plan switch monthly -> annual: proration correct, new billing cycle starts

Clinic / Practice tier:

- Practice creation: validates physician status, creates Stripe customer, assigns PRACTICE_ADMIN role
- Invitation workflow: token hashing, 7-day expiry, acceptance, billing mode determination
- Hybrid billing: early bird members keep individual subscriptions, others go consolidated
- Physician removal: end-of-month scheduling, Stripe quantity decrement
- Practice dissolution: triggered when headcount < 5, all members transition to individual
- Zero PHI: seat roster endpoint returns no clinical data

Referral program:

- Code generation: 8-char, no ambiguous characters, collision detection
- Redemption lifecycle: PENDING -> QUALIFIED -> CREDITED (or EXPIRED)
- Credit value calculated correctly per referrer's plan
- Annual cap enforced (3/year)
- Clinic credit choice: PRACTICE_INVOICE vs INDIVIDUAL_BANK
- Default credit choice applied after 7-day deadline
- Same-practice referral prevention

Cancellation and refunds:

- Monthly cancel-at-period-end
- Annual forfeit (months 1-6): no refund
- Annual prorated refund (months 7-12): correct amount, Stripe refund issued
- Negative payment_history record created for refunds

IMA amendments:

- Non-material: acknowledge flow
- Material: accept/reject flow, blocking check
- Duplicate response prevention (unique index)
- Response recording with IP and user agent

Breach notifications:

- Create breach, 72h deadline tracking
- Send notifications to affected custodians (dual delivery)
- Append-only updates (INITIAL, SUPPLEMENTARY)
- Evidence hold enforcement (12 months minimum)
- Resolve breach

Data export:

- Standard portability export: ZIP with 6 CSVs
- Full HI export: ZIP with manifest.json and 25+ entity types (CSV or JSON)
- Upload to DO Spaces, presigned URL (72h expiry)
- Audit log entries for request and completion

Data destruction:

- Multi-phase tracking (PENDING -> ACTIVE_DELETED -> FILES_DELETED -> BACKUP_PURGED -> CONFIRMED)
- Admin backup purge confirmation
- Destruction confirmation email
- 90-day backup purge deadline

Status page:

- Status page reflects real component health
- Incident creation -> visible on status page
- Incident updates append to timeline

Account deletion:

- Data export works during 45-day grace period
- Data irrecoverable after destruction phases complete
- Audit logs retained 10 years with PII stripped

---

# 21. Document Control

| Item | Value |
|------|-------|
| Parent document | Meritum PRD v1.3 |
| Domain | Platform Operations (Domain 12 of 13) |
| Build sequence position | Early (Stripe integration before onboarding; monitoring from Day 1) |
| Dependencies | Domain 1 (IAM for user accounts), Stripe (external), DigitalOcean Spaces (external) |
| Consumed by | Domain 1 (subscription status check), Domain 5 (practice membership context), Domain 11 (onboarding requires active subscription) |
| Version | 2.0 |
| Date | February 2026 |
| Changes from v1.0 | Added: Pricing Model (6 plans), Clinic/Practice Tier, Pricing Lifecycle (early bird rate lock, discount framework), Referral Program (redesigned: 8-char codes, 1-month credit, 3/year cap, clinic credit choice), Cancellation & Refund Policies (annual 6-month forfeit, prorated refund), Data Portability Export (full HI export with 25+ entity types), IMA Amendment Management, Breach Notification (HIA compliance), Multi-phase Data Destruction Tracking. Updated: deletion grace period 30 -> 45 days, pricing corrected (Standard Annual $3,181, Early Bird Annual $2,388 added), expanded data model (16 tables), API contracts (38+ endpoints across platform and practice routes), scheduled jobs (11 background jobs). |
