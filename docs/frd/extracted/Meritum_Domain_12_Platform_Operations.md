# Meritum_Domain_12_Platform_Operations

MERITUM

Functional Requirements

Platform Operations

Domain 12 of 13  |  Infrastructure & Business Operations

Meritum Health Technologies Inc.

Version 1.0  |  February 2026

CONFIDENTIAL

# Table of Contents

# 1. Domain Overview

## 1.1 Purpose

Platform Operations owns the business infrastructure that keeps Meritum running: subscription billing via Stripe, platform status monitoring, system health observability, and operational tooling. This domain is largely invisible to physicians — they interact with it only when paying their subscription, checking system status during an outage, or managing their account settings.

## 1.2 Scope

Stripe subscription management: plan creation, payment processing, invoicing with GST

Dunning and payment recovery: failed payment handling, grace periods, account suspension

Subscription lifecycle: trial, active, past_due, suspended, cancelled

Status page: public platform status with incident history

System health monitoring: uptime, error rates, latency tracking

Operational dashboards: admin-facing metrics for platform-wide health

Referral program (post-PMF): physician referral credits

Account deletion: 30-day grace period, data retention compliance

## 1.3 Out of Scope

Application features and business logic (all other domains)

Infrastructure provisioning and deployment (DevOps; this domain specifies what to monitor, not how to deploy)

HIA compliance (legal; this domain implements technical controls specified elsewhere)

# 2. Stripe Integration

## 2.1 Pricing Model

## 2.2 Stripe Objects

Meritum uses Stripe's subscription model with the following object mapping:

## 2.3 PHI Isolation

Stripe never receives PHI. The Stripe Customer object stores only:

Name (physician's name, not patient data)

Email (physician's email)

Stripe-managed payment method token (Meritum never sees full card numbers)

Billing data (Stripe) and health data (Meritum database) are completely separated. Meritum stores only the Stripe customer_id and subscription_id as references. No claim data, patient data, or billing codes are sent to Stripe.

## 2.4 Webhook Events

Meritum listens for the following Stripe webhook events:

## 2.5 Dunning Sequence

When a payment fails, Meritum runs a dunning sequence to recover the payment before suspending the account:

## 2.6 Customer Portal

Meritum integrates Stripe's Customer Portal for self-service billing management:

Update payment method

View invoice history and download invoices

Switch between monthly and annual plans

Cancel subscription

The Customer Portal is accessed via a button in Meritum's account settings. Stripe handles the UI. Meritum receives webhook events for any changes made in the portal.

# 3. Subscription Lifecycle

## 3.1 States

## 3.2 Subscription-Gated Features

The following features are gated by subscription status:

# 4. Account Deletion

## 4.1 Deletion Workflow

Physician requests account deletion from settings.

Confirmation dialog explains consequences: data will be permanently deleted after 30-day grace period.

Physician must type 'DELETE' to confirm.

Subscription cancelled via Stripe immediately.

Account enters 30-day grace period. Data portability export available. Read-only access.

Data portability reminder notification at Day 7 and Day 21.

After 30 days: all PHI deleted. Audit logs retained per HIA retention requirements (10 years) with PII stripped.

Stripe customer data deleted via API (remove payment methods, redact customer metadata).

## 4.2 Data Retention After Deletion

# 5. Status Page

A public status page at status.meritum.ca shows platform health. Accessible without authentication.

## 5.1 Monitored Components

## 5.2 Incident Management

Incidents created manually by operations team or auto-created by monitoring alerts.

Incident states: Investigating, Identified, Monitoring, Resolved.

Incident updates posted to status page and delivered as MAINTENANCE_SCHEDULED notifications.

Post-incident reports published for significant outages (>30 minutes).

# 6. System Health Monitoring

## 6.1 Key Metrics

## 6.2 Observability Stack

Platform monitoring uses:

Application logging: Structured JSON logs with correlation IDs. Shipped to log aggregation service.

Metrics collection: Application metrics (request count, latency, error rate) collected and stored in time-series database.

Alerting: Threshold-based alerts delivered to operations team via PagerDuty or equivalent.

Dashboards: Internal operational dashboards (separate from physician-facing analytics) showing platform health, user activity, and business metrics.

Specific tooling choices (Grafana, Datadog, CloudWatch, etc.) deferred to infrastructure implementation.

# 7. Referral Program (Post-PMF)

After product-market fit is established, Meritum will launch a referral program. Architecture accommodations at MVP:

## 7.1 Program Design

Referral credit: Referring physician receives $50 credit on their next invoice when a referred physician completes onboarding and pays for their first month.

Implementation: Stripe balance adjustments (negative invoice line items). No cash payouts.

Tracking: Referral codes generated per physician. Referred physician enters code during registration.

Limits: Maximum 10 referral credits per physician per year ($500/year cap).

## 7.2 MVP Accommodations

Referral code field present in registration form (hidden/disabled at MVP).

Referral tracking table defined but not populated.

Stripe balance adjustment logic tested but not triggered.

# 8. Data Model

## 8.1 Subscriptions Table (subscriptions)

## 8.2 Payment History Table (payment_history)

# 9. User Stories & Acceptance Criteria

# 10. Testing Requirements

Stripe Checkout → subscription created → webhook received → Meritum subscription record created

Payment failure webhook → PAYMENT_FAILED notification → dunning sequence starts

Day 14 without payment → account SUSPENDED → claim submission blocked

Payment recovered → account ACTIVE → submission unblocked

Subscription cancelled → 30-day grace → data export available → data deleted

GST correctly calculated on all invoices (5% of base amount)

Early bird pricing: first 100 physicians get $199/month. Physician 101 gets $279/month.

Plan switch monthly → annual: proration correct, new billing cycle starts

Status page reflects real component health. Incident creation → visible on status page.

Account deletion: data export works during grace period. Data irrecoverable after 30 days.

# 11. Open Questions

# 12. Document Control

This domain specifies business operations infrastructure. It is largely invisible to physicians and handles payment, monitoring, and account lifecycle.

| Item | Detail |
| --- | --- |
| Standard monthly | $279/month |
| Standard annual | $2,790/year (equivalent to $232.50/month, ~17% savings) |
| Early bird monthly | $199/month for the first 12 months (available to first 100 physicians) |
| GST handling | All prices are GST-exclusive. GST (5%) added on invoice. Meritum is GST-registered. |
| Currency | CAD only |
| Payment methods | Credit card (Visa, Mastercard, Amex) via Stripe. No cheques, no EFT at MVP. |

| Stripe Object | Meritum Usage |
| --- | --- |
| Customer | 1:1 with Meritum user account. Created during registration. Stores payment method. |
| Product | Single product: 'Meritum Health Billing Platform'. |
| Price | Three prices: standard_monthly ($279), standard_annual ($2,790), early_bird_monthly ($199). Early bird has metadata marking eligibility limit. |
| Subscription | 1:1 with Meritum provider. Tracks billing cycle, status, current period. |
| Invoice | Auto-generated by Stripe per billing cycle. GST added as tax line item. |
| Payment Intent | Managed by Stripe. Meritum receives webhooks on success/failure. |

| Webhook Event | Meritum Action |
| --- | --- |
| invoice.paid | Mark subscription as current. Clear any past_due status. Log payment. |
| invoice.payment_failed | Increment failed_payment_count. Start dunning sequence (Section 2.5). Emit PAYMENT_FAILED notification. |
| customer.subscription.updated | Sync subscription status (active, past_due, cancelled). Update provider status. |
| customer.subscription.deleted | Subscription cancelled. Start account wind-down. Emit ACCOUNT_SUSPENDED notification after grace period. |
| invoice.created | Add GST line item if not already present (Stripe Tax or manual line item). |
| checkout.session.completed | Initial subscription created. Link Stripe customer_id and subscription_id to Meritum user. |

| # | Timing | Action |
| --- | --- | --- |
| 1 | Day 0 (payment fails) | PAYMENT_FAILED notification (in-app + email). Stripe automatically retries in 3 days. Platform access unaffected. |
| 2 | Day 3 (Stripe retry 1) | If retry succeeds: resolved. If fails: second notification. 'Please update your payment method.' |
| 3 | Day 7 (Stripe retry 2) | If fails: third notification. Warning: 'Your account will be suspended in 7 days if payment is not resolved.' |
| 4 | Day 14 (grace period ends) | Account status set to SUSPENDED. Claims preserved but submission blocked. Read-only access to dashboards and reports. Prominent banner: 'Update payment to resume billing.' |
| 5 | Day 30 (cancellation) | If still unpaid: subscription cancelled via Stripe. Account enters 30-day deletion grace period (Section 4). Data portability export available. |

| State | Description |
| --- | --- |
| TRIAL | Optional trial period (if enabled). Full platform access. No payment required. Duration configurable (14 or 30 days). |
| ACTIVE | Payment current. Full platform access. Normal operation. |
| PAST_DUE | Payment failed, within dunning sequence (Days 0–14). Full platform access. Notifications active. |
| SUSPENDED | Payment not recovered after grace period (Day 14+). Claims preserved. Submission blocked. Read-only dashboards. |
| CANCELLED | Subscription cancelled (by physician or after Day 30 non-payment). 30-day grace for data export. Then data deletion per retention policy. |

| Feature | ACTIVE | PAST_DUE | SUSPENDED | CANCELLED |
| --- | --- | --- | --- | --- |
| Create claims | Yes | Yes | No | No |
| Submit batches | Yes | Yes | No | No |
| View dashboards | Yes | Yes | Read-only | No |
| Download reports | Yes | Yes | Yes | Yes (30 days) |
| Data portability export | Yes | Yes | Yes | Yes (30 days) |
| AI Coach suggestions | Yes | Yes | No | No |
| Update settings | Yes | Yes | Payment only | No |

| Data Type | Retention |
| --- | --- |
| Claims, patient records, provider profile | Deleted after 30-day grace period. Irrecoverable. |
| Audit logs | Retained 10 years per HIA. PII stripped (provider_id replaced with hash, patient PHN removed). |
| Generated reports | Deleted with account. |
| IMA records | Retained 10 years (contractual evidence). |
| Stripe billing records | Retained by Stripe per their retention policy. Meritum's reference (customer_id, subscription_id) deleted. |
| AI learning data | Anonymised and retained for specialty cohort aggregates (no individual identification possible). |

| Component | What is Monitored |
| --- | --- |
| Web Application | Availability, response time, error rate |
| API | Availability, response time, error rate per endpoint group |
| H-Link Submission | Batch transmission success rate, last successful transmission time |
| WCB Submission | Batch generation success rate |
| AI Coach (Tier 2 LLM) | Availability, response time, fallback rate |
| Email Delivery | Delivery rate, bounce rate, queue depth |
| Database | Connection pool utilisation, query latency |
| Payment Processing (Stripe) | Webhook delivery success, payment processing status |

| Metric | Target | Alert Threshold |
| --- | --- | --- |
| API availability | 99.9% | < 99.5% over 5 minutes |
| API p95 latency | < 500ms | > 1000ms over 5 minutes |
| Error rate (5xx) | < 0.1% | > 1% over 5 minutes |
| H-Link batch success rate | 100% | Any failure triggers alert |
| Database connection pool | < 70% utilisation | > 85% utilisation |
| Email delivery rate | > 99% | < 95% over 1 hour |
| LLM availability | > 99% | < 95% (triggers Tier 1 fallback) |
| Disk usage | < 70% | > 85% |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| subscription_id | UUID | No | Primary key |
| provider_id | UUID FK | No | FK to providers. Unique. |
| stripe_customer_id | VARCHAR(50) | No | Stripe customer ID |
| stripe_subscription_id | VARCHAR(50) | No | Stripe subscription ID |
| plan | VARCHAR(30) | No | STANDARD_MONTHLY, STANDARD_ANNUAL, EARLY_BIRD_MONTHLY |
| status | VARCHAR(20) | No | TRIAL, ACTIVE, PAST_DUE, SUSPENDED, CANCELLED |
| current_period_start | TIMESTAMPTZ | No | Current billing period start |
| current_period_end | TIMESTAMPTZ | No | Current billing period end |
| trial_end | TIMESTAMPTZ | Yes | Trial period end (if applicable) |
| failed_payment_count | INTEGER | No | Consecutive failed payment count. Resets on successful payment. |
| suspended_at | TIMESTAMPTZ | Yes | When account was suspended (if applicable) |
| cancelled_at | TIMESTAMPTZ | Yes | When subscription was cancelled |
| deletion_scheduled_at | TIMESTAMPTZ | Yes | When data deletion is scheduled (30 days after cancellation) |
| created_at | TIMESTAMPTZ | No |  |
| updated_at | TIMESTAMPTZ | No |  |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| payment_id | UUID | No | Primary key |
| subscription_id | UUID FK | No | FK to subscriptions |
| stripe_invoice_id | VARCHAR(50) | No | Stripe invoice ID |
| amount_cad | DECIMAL(10,2) | No | Amount in CAD (before GST) |
| gst_amount | DECIMAL(10,2) | No | GST amount (5%) |
| total_cad | DECIMAL(10,2) | No | Total charged (amount + GST) |
| status | VARCHAR(20) | No | PAID, FAILED, REFUNDED |
| paid_at | TIMESTAMPTZ | Yes | When payment was confirmed |
| created_at | TIMESTAMPTZ | No |  |

| ID | Story | Acceptance Criteria |
| --- | --- | --- |
| PLT-001 | As a new physician, I want to subscribe and pay for Meritum | Select plan (monthly/annual). Enter payment via Stripe Checkout. Subscription created. Proceed to onboarding. |
| PLT-002 | As a physician, I want to view my invoices and update payment method | Link to Stripe Customer Portal from account settings. View invoices. Update card. Download invoice PDFs. |
| PLT-003 | As a physician, I want to know if my payment failed | PAYMENT_FAILED notification (in-app + email) immediately. Clear instructions to update payment method. |
| PLT-004 | As a physician, I want my account to continue working during payment issues | Full access during PAST_DUE (14 days). Submission blocked only at SUSPENDED. Grace period clearly communicated. |
| PLT-005 | As a physician, I want to delete my account and get my data | Request deletion. Data portability export available. 30-day grace. Reminders at Day 7 and 21. Permanent deletion after 30 days. |
| PLT-006 | As a physician, I want to check platform status during issues | Public status page at status.meritum.ca. Component-level status. Incident history. No auth required. |
| PLT-007 | As a physician, I want to switch from monthly to annual billing | Via Stripe Customer Portal. Proration handled by Stripe. Meritum updates plan record on webhook. |

| # | Question | Context |
| --- | --- | --- |
| 1 | Should Meritum offer a free trial? | Reduces friction to sign-up. Risk: physicians who never convert. Could offer 14-day trial with payment method required upfront. |
| 2 | Should early bird pricing have a time limit in addition to the 100-physician cap? | E.g., first 100 physicians OR first 6 months of launch, whichever comes first. |
| 3 | Which monitoring and observability tools should Meritum use? | Grafana + Prometheus (self-hosted, no per-seat cost) vs Datadog (managed, per-host cost) vs DigitalOcean Monitoring (limited but free). |
| 4 | Should Meritum accept EFT / direct debit in addition to credit cards? | Some physicians prefer EFT. Stripe supports Canadian Pre-Authorized Debit. Adds complexity to reconciliation. |

| Item | Value |
| --- | --- |
| Parent document | Meritum PRD v1.3 |
| Domain | Platform Operations (Domain 12 of 13) |
| Build sequence position | Early (Stripe integration before onboarding; monitoring from Day 1) |
| Dependencies | Domain 1 (IAM for user accounts), Stripe (external) |
| Consumed by | Domain 1 (subscription status check), Domain 11 (onboarding requires active subscription) |
| Version | 1.0 |
| Date | February 2026 |

