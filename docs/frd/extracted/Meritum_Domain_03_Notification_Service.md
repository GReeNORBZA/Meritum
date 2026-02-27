# Meritum_Domain_03_Notification_Service

MERITUM

Functional Requirements

Notification Service

Domain 3 of 13  |  Critical Path: Position 3

Meritum Health Technologies Inc.

Version 1.0  |  February 2026

CONFIDENTIAL

# Table of Contents

# 1. Domain Overview

## 1.1 Purpose

The Notification Service is the cross-cutting communication infrastructure of Meritum. It is responsible for delivering timely, reliable, and configurable notifications to physicians and delegates across all channels. It does not generate notification content—it receives structured events from other domains and delivers them through the appropriate channel(s) based on the notification type, urgency, and physician preferences.

This domain is elevated in the critical path because the tiered auto-submission model (PRD Section 5.2) depends on it for the Thursday submission notification sequence. Without reliable notifications, the auto-submission system cannot inform physicians about pending reviews, and the safety model collapses. Notifications are also the delivery mechanism for SOMB change summaries, rejection alerts, payment failure warnings, and every other time-sensitive communication.

## 1.2 Scope

Email delivery (transactional and scheduled)

In-app notification centre (real-time and historical)

Scheduled notification execution (Thursday submission cycle, deadline reminders)

Event consumption from all producing domains

Physician notification preferences management

Delivery tracking, retry logic, and failure handling

Notification templates and content rendering

Architecture for future push notifications (Phase 2) and SMS (Phase 2+)

## 1.3 Out of Scope

Notification content authoring (producing domains define content in their events)

Business logic that triggers notifications (each domain decides when to emit events)

Push notification delivery (Phase 2, with native mobile apps)

SMS delivery (Phase 2+, evaluated after push notifications)

Marketing emails or promotional campaigns (out of scope entirely)

## 1.4 Domain Dependencies

# 2. Notification Taxonomy

Every notification in Meritum is classified by category, urgency, and channel eligibility. This taxonomy drives delivery logic, preference configuration, and retry behaviour.

## 2.1 Categories & Urgency

## 2.2 Urgency Levels

## 2.3 Channel Capabilities (MVP vs Future)

# 3. User Stories & Acceptance Criteria

## 3.1 Thursday Submission Cycle

## 3.2 Claim Alerts

## 3.3 Reference Data & System

## 3.4 Account & Payment

## 3.5 Notification Preferences

## 3.6 In-App Notification Centre

# 4. Data Model

The Notification Service stores notification records, delivery status, scheduled jobs, and physician preferences.

## 4.1 Notifications Table

## 4.2 Notification Deliveries Table

Tracks delivery attempts per channel. One notification may have multiple delivery records (one per channel).

## 4.3 Scheduled Notifications Table

Manages notifications that must be sent at specific times (the Thursday submission cycle, deadline reminders, etc.).

## 4.4 Notification Preferences Table

Default preferences (applied on account creation): All categories: email = true, in_app = true. Exception: ai_coach: email = false, in_app = true (Low urgency defaults to in-app only). Non-silenceable categories are enforced regardless of preference values.

## 4.5 Email Suppression List

Emails on the suppression list are never sent to, regardless of notification urgency. If a physician’s email is suppressed, a Critical in-app notification is created: “We can no longer deliver emails to your address. Please update your email in account settings.”

# 5. Event Consumption Catalogue

The Notification Service consumes events from every other domain. This catalogue maps source events to notification behaviour.

# 6. Scheduled Notification Engine

Some notifications must be sent at specific times (not in response to real-time events). The scheduled notification engine handles these.

## 6.1 Thursday Submission Cycle Schedule

The scheduler runs the following jobs weekly. All times are Mountain Time (MT), converted to UTC for storage.

## 6.2 Recurring Schedules

## 6.3 Scheduler Implementation

The scheduled notification engine must be reliable: missed notifications in the Thursday cycle directly impact physician revenue. Implementation options (decided during tech stack selection):

Cron-based (simplest): System cron triggers API endpoints at scheduled times. Simple but single point of failure; no built-in retry if the server is down at the scheduled moment.

Database-backed job queue: Scheduled jobs stored in the scheduled_notifications table (Section 4.3). A worker process polls for jobs due. If the worker is restarted, it picks up any missed jobs on the next poll. More resilient.

Dedicated job scheduler (e.g., BullMQ with Redis, node-cron with persistence): Purpose-built for reliable scheduled execution. Adds infrastructure but provides retry, concurrency control, and monitoring.

Recommendation: Database-backed job queue for MVP. Simple, resilient, no additional infrastructure. Jobs are written to the scheduled_notifications table with scheduled_for timestamps. A worker process runs every minute, picks up due jobs, evaluates conditions, and executes or suppresses. Failed jobs are retried. This approach survives server restarts and provides full audit trail via the table.

# 7. Email Delivery

## 7.1 Email Provider Selection

Decision deferred to tech stack selection. Requirements for the email provider:

Transactional email API (not bulk marketing)

Webhook support for delivery status (delivered, bounced, complained)

Canadian data processing or acceptable privacy posture for transactional email

Deliverability reputation management

Template support or HTML email capability

Cost-effective at MVP scale (50–250 physicians = ~2,000–10,000 emails/month)

Candidates: Postmark (excellent deliverability, transactional focus), SendGrid (widely used, Stripe integration), Amazon SES (cheapest, more operational overhead). Postmark is the leading candidate for its transactional focus and deliverability reputation.

## 7.2 Email Templates

All emails follow a consistent Meritum brand template:

Header: Meritum logo, forest green accent

Body: notification content (varies per type)

CTA button: primary action link (e.g., “Review your claims”, “Update payment method”)

Footer: “Meritum Health Technologies Inc.”, unsubscribe link (for silenceable categories), support contact, mailing address per CASL requirements

Templates are defined as server-side rendered HTML. Template variables are populated from the notification’s metadata JSONB field. No PHI is ever included in email bodies—emails reference claim counts and dollar amounts but never patient names, PHNs, or clinical details.

## 7.3 CASL Compliance

The Canadian Anti-Spam Legislation (CASL) applies to commercial electronic messages. Meritum’s transactional notifications (billing confirmations, security alerts, service-related information) are exempt from CASL consent requirements under the “transactional message” exemption. However, best practice requires:

Clear sender identification (“Meritum Health Technologies Inc.”)

Valid mailing address in email footer

Unsubscribe mechanism for categories that can be silenced

No marketing content in transactional emails

Prompt processing of unsubscribe requests (within 10 business days per CASL; Meritum targets immediate effect)

## 7.4 Email Content Safety: No PHI in Email

Critical rule: Email notifications must never contain Protected Health Information. This means: no patient names, no PHNs, no diagnostic codes, no HSC codes tied to identifiable patients, no clinical details. Emails contain aggregate information (claim counts, dollar totals, category summaries) and deep links to the platform where the physician can view full details after authentication.

Example of what an email CAN contain: “You have 23 claims queued for Thursday. 20 are clean and will auto-submit. 3 have AI Coach suggestions requiring your review. Estimated value: $4,200.”

Example of what an email CANNOT contain: “Your claim for John Smith (PHN 123456789) for code 03.04A on Jan 15 was rejected because...”

# 8. API Contracts

## 8.1 Notification Centre (User-Facing)

## 8.2 Event Ingestion (Internal)

## 8.3 Admin

# 9. Delivery Pipeline

When a notification event is received or a scheduled notification fires, the delivery pipeline processes it through the following stages:

Stage 1: Event received. The event is validated (required fields, known event type, valid recipients). Invalid events are logged and dropped.

Stage 2: Recipient resolution. For each recipient: look up user record, determine channels based on (a) notification urgency, (b) physician preferences, (c) suppression list.

Stage 3: Notification record creation. A notification record is created in the notifications table. One record per recipient.

Stage 4: Channel delivery. For each applicable channel: create a delivery record (pending). In-app: set the notification as available in the notification centre (effectively instant). Email: render template with metadata, queue for email provider API call.

Stage 5: Provider dispatch. Email API call to provider. On success: update delivery status to “sent”. On failure: update to “failed” with reason, schedule retry per urgency retry policy.

Stage 6: Delivery confirmation. Email provider webhook fires on delivery/bounce/complaint. Update delivery record accordingly. If bounced: add to suppression list if hard bounce.

Stage 7: Retry processing. Worker process checks for deliveries with next_retry_at in the past. Re-attempts dispatch. Increments retry_count. If max retries exhausted: status = failed (permanent).

## 9.1 Failure Handling

# 10. Interface Contracts with Other Domains

## 10.1 Event Contract

All domains emit events to the Notification Service using a standard event envelope:

Idempotency: The Notification Service deduplicates events by event_id. If the same event_id is received twice (e.g., due to retry in the producing domain), only one notification is created. This prevents duplicate emails.

## 10.2 Claim Lifecycle Interface

The Claim Lifecycle domain is the heaviest producer of notification events. Key interactions:

Claim Lifecycle manages the Thursday batch execution logic (which claims to submit, which to hold).

After batch execution, Claim Lifecycle emits batch.submitted with results. Notification Service generates NTF-004.

Claim Lifecycle emits claim.deadline_approaching, claim.aging_alert, and claim.rejected events. Notification Service delivers per taxonomy.

The scheduled notification engine queries Claim Lifecycle for claim state (queued count, flagged count, unreviewed count) when generating the Monday/Wednesday/Thursday cycle notifications. This is via an internal API call, not an event.

## 10.3 Identity & Access Interface

Identity & Access events are delivered via the same event contract. Special cases:

Email verification and password reset emails are sent synchronously (not queued) because they are part of real-time user flows.

Delegate invitation emails include a unique invitation token in the email body — this is the only case where a sensitive token is included in an email.

Payment failure escalation (NTF-011) is driven by Stripe webhook events processed through Identity & Access, which emits subscription.status_changed events.

# 11. Security & Audit Requirements

## 11.1 PHI Protection

No PHI in email content (see Section 7.4). Aggregate data only.

In-app notifications may reference claim-level data (HSC codes, dates, amounts) because the user is already authenticated. However, patient-identifying information (name, PHN) should be minimised even in in-app notifications. Use “Claim for [date of service]” rather than “Claim for John Smith.”

Email provider (external service) never receives PHI. Only notification metadata (counts, amounts, category labels) flows to the email provider.

Notification body and metadata stored in Meritum’s database is subject to the same encryption-at-rest requirements as all platform data.

## 11.2 Audit Events

## 11.3 Access Control

Physicians see only their own notifications.

Delegates see notifications relevant to the physician(s) they serve, filtered by current context.

Admins can view system-wide delivery statistics and failures but not the content of individual physician notifications (unless granted PHI access per IAM admin access rules).

Email provider webhook endpoint is authenticated via signature verification (provider-specific: e.g., Postmark’s webhook signatures).

Internal event emission endpoint is authenticated via service-to-service token, not exposed externally.

# 12. Testing Requirements

## 12.1 Unit Tests

Urgency-based channel resolution: given urgency + preferences, correct channels selected

Suppression logic: suppressed email skipped, in-app still delivered, Critical in-app alert generated

Preference enforcement: non-silenceable categories ignore physician preferences

Retry scheduling: correct next_retry_at calculated per urgency retry policy

Condition checking for scheduled notifications: conditions evaluated at execution time, not scheduling time

Event deduplication: same event_id processed once

Template rendering: metadata correctly populates template variables; PHI never in email output

Timezone handling: MT scheduled times correctly converted to UTC

## 12.2 Integration Tests

Full Thursday cycle: create queued claims → Monday summary fires → Wednesday reminder fires (if flagged) → Thursday final fires → Thursday post-submission fires

Suppression scenario: physician reviews all flagged claims before Thursday → Thursday final reminder suppressed

Delegate copy: delegate with batch approval authority receives all cycle notifications

Payment failure escalation: Stripe webhook → event emitted → escalating notifications at day 1, 3, 7, 14

Email bounce → suppression list → future emails suppressed → in-app Critical alert

Preference update → subsequent notifications respect new preferences

Scheduled job recovery: simulate server downtime during scheduled time → worker picks up overdue job on restart

SOMB change notification: Reference Data publishes version → all physicians notified → personalised impact for affected physicians

## 12.3 Performance Tests

Monday batch summary for 250 physicians: all notifications created and emails queued within 60 seconds

Unread count endpoint: <50ms response time (called on every page load)

Notification centre pagination: <200ms for 20 results

Email provider API rate limiting: graceful handling if provider rate-limits outbound emails

# 13. Open Questions for Tech Stack Selection

# 14. Document Control

Parent document: Meritum PRD v1.3

Domain: Notification Service (Domain 3 of 13)

Build sequence position: 3rd (depends on Identity & Access for user records and auth; consumed by Claim Lifecycle for Thursday submission cycle)

Event producers: Identity & Access, Reference Data, Claim Lifecycle, Intelligence Engine, Platform Operations

Next domain in critical path: Claim Lifecycle (Domain 4)

| Depends On | Provides To | Interface Type |
| --- | --- | --- |
| Identity & Access | All domains (indirectly) | User records for email addresses and notification routing; auth context for preference management; subscription status for gating |
| Email provider (external) | Claim Lifecycle | SMTP/API integration for email delivery (SendGrid, Postmark, or similar; decision during tech stack) |
| — | Platform Operations | Delivery status, failure alerts, bounce/complaint processing |
| — | Identity & Access | Delivers auth events (verification emails, password resets, delegate invitations, security alerts) |
| — | Reference Data | Delivers SOMB/WCB change summaries |
| — | Provider Management | Delivers onboarding status notifications |

| Category | Examples | Default Urgency | Physician Can Silence? |
| --- | --- | --- | --- |
| submission_cycle | Monday batch summary, Wednesday reminder, Thursday final reminder, post-submission confirmation | Standard → High (escalating) | Can silence Standard; cannot silence High |
| assessment | Payment assessment received, rejection notification, adjustment notification | High | No |
| claim_alert | 90-day deadline approaching, claim aging (unresolved), duplicate detected | High | No |
| ai_coach | New suggestions on queued claims, weekly suggestion summary, acceptance rate insights | Low | Yes |
| reference_data | SOMB update published, WCB update, governing rule change, deprecated code alert | Standard | Can silence general updates; cannot silence deprecated-code-you-use alerts |
| account | BA linkage confirmed, IMA signed, delegate added/removed, subscription renewed | Standard | Yes (except payment failure) |
| payment | Payment processed, payment failed, subscription expiring, account suspension warning | Standard → Critical (escalating) | No |
| security | New device login, account locked, password changed, MFA reconfigured | High | No |
| system | Scheduled maintenance, H-Link outage, WCB submission issue, platform incident | Standard → Critical | Cannot silence Critical |
| delegate | Batch approved by delegate, delegate invitation sent/accepted, delegate access revoked | Standard | Yes |

| Urgency | Delivery Behaviour | Retry on Failure | Can Be Silenced |
| --- | --- | --- | --- |
| Low | In-app only by default; email if physician has opted in for this category | No retry; log failure | Yes |
| Standard | In-app + email | 1 retry after 5 minutes | Configurable per category |
| High | In-app + email; email sent immediately (not batched) | 3 retries: 5 min, 30 min, 2 hours | No |
| Critical | In-app + email; email sent immediately; flagged in status dashboard | 5 retries: 1 min, 5 min, 15 min, 1 hour, 4 hours | No |

| Channel | MVP | Phase 2 | Notes |
| --- | --- | --- | --- |
| In-app notification centre | Yes | Yes | Accessible from all screens; badge count on bell icon; read/unread tracking; paginated history |
| Email (transactional) | Yes | Yes | Individual emails triggered by events; immediate for High/Critical, batched for Low/Standard |
| Email (scheduled) | Yes | Yes | Thursday submission cycle sequence; scheduled at specific times (Monday 08:00, Wednesday 17:00, Thursday 08:00, Thursday 12:00 MT) |
| Push notification | No | Yes | Added with native iOS/Android apps; mirrors High/Critical email notifications |
| SMS | No | Evaluate | Only if email + push prove insufficient for Critical alerts; high per-message cost |

| NTF-001 | Monday Batch Summary |
| --- | --- |
| User Story | As a physician, I want a Monday morning summary of my queued claims so that I know what’s pending for Thursday’s submission without logging in. |
| Acceptance Criteria | • Sent at 08:00 MT every Monday to all physicians with at least one queued claim. • Content includes: total claims queued, count of clean claims (will auto-submit under default mode), count of flagged claims requiring review, estimated total dollar value of queued claims. • Email includes a direct link to the batch review screen. • In-app notification created simultaneously. • Not sent if the physician has zero queued claims (no noise). • Respects physician’s submission preference: if set to “require approval for all,” the notification makes clear that ALL claims require approval, not just flagged ones. • If the physician has a delegate with batch approval authority, the delegate receives a copy with a note: “You have batch approval authority for Dr. [name].” |

| NTF-002 | Wednesday Reminder |
| --- | --- |
| User Story | As a physician with flagged claims, I want a Wednesday evening reminder so that I have time to review before the Thursday deadline. |
| Acceptance Criteria | • Sent at 17:00 MT every Wednesday ONLY if the physician has unreviewed flagged claims. • Not sent if all queued claims are clean (no unnecessary noise). • Content: count of flagged claims still requiring review, brief summary of flag reasons (e.g., “3 claims have AI Coach suggestions, 1 has a validation warning”), direct link to batch review screen. • Urgency: High (email sent immediately, not batched). • Delegate with batch approval authority also receives this notification. • If physician’s preference is “require approval for all,” the notification covers all unreviewed claims, not just flagged ones. |

| NTF-003 | Thursday Final Reminder |
| --- | --- |
| User Story | As a physician with unreviewed claims, I want a final morning reminder on Thursday so that I have a last chance before the noon cutoff. |
| Acceptance Criteria | • Sent at 08:00 MT Thursday ONLY if unreviewed flagged claims (or any unreviewed claims for “require approval” physicians) remain. • Urgency: High. • Content: urgent tone; count of claims that will NOT be submitted unless reviewed; explicit statement of deadline (“by 12:00 PM today”); count of clean claims that WILL auto-submit; direct link to batch review. • For “require approval for all” physicians: “No claims will be submitted unless you or your delegate approves by 12:00 PM MT.” • Delegate with batch approval authority receives the same notification. • If all claims are reviewed between the Wednesday and Thursday notifications, the Thursday notification is suppressed (physician took action; no need to nag). |

| NTF-004 | Post-Submission Confirmation |
| --- | --- |
| User Story | As a physician, I want confirmation after Thursday’s batch is submitted so that I know what went to H-Link and what was held. |
| Acceptance Criteria | • Sent at 12:00 MT Thursday (or shortly after batch processing completes). • Content: count of claims submitted, total dollar value submitted, count of flagged claims held for next week (if any), count of claims held due to “require approval” not being given. • If no claims were submitted (all flagged, none reviewed), the notification states this clearly with a link to the queued claims. • Urgency: Standard. • Sent to all physicians who had queued claims, regardless of whether anything was actually submitted. • Delegate receives a copy if they have batch approval authority. |

| NTF-005 | Assessment Received |
| --- | --- |
| User Story | As a physician, I want to know when AHCIP’s payment assessment arrives so that I can review what was paid, rejected, or adjusted. |
| Acceptance Criteria | • Sent when the H-Link assessment file is retrieved and parsed (typically the Friday following submission). • Content: total claims assessed, count paid, count rejected, count adjusted, total amount paid, total amount rejected/adjusted. • If any claims were rejected, the notification is urgency High and includes the top 3 rejection explanatory codes with plain-language descriptions. • Direct link to the assessment detail screen. • If all claims were paid without issue, urgency is Standard. |

| NTF-006 | 90-Day Deadline Approaching |
| --- | --- |
| User Story | As a physician, I want to be warned when claims are approaching the 90-day submission deadline so that I don’t lose revenue to expired claims. |
| Acceptance Criteria | • Triggered when any draft or validated (not yet queued) claim has a date of service within 14 days of the 90-day submission window closing. • Urgency: High. • Content: count of at-risk claims, earliest deadline date, direct link to the claims list filtered to show at-risk items. • Sent once when the 14-day threshold is crossed, then again at 7 days and 3 days if the claims are still not queued. • Not sent for claims already in the queued or submitted state. |

| NTF-007 | Claim Aging Alert |
| --- | --- |
| User Story | As a physician, I want to know when submitted claims remain unresolved beyond expected timelines so that I can investigate potential issues. |
| Acceptance Criteria | • Triggered when a submitted claim has not received an assessment response within the expected timeframe (configurable, default: 14 days after submission). • Urgency: Standard (first alert), escalating to High if still unresolved after 28 days. • Content: count of aging claims, date of submission, expected assessment date, direct link to aging claims view. • Sent weekly for ongoing aging claims until resolved. |

| NTF-008 | Rejection Received |
| --- | --- |
| User Story | As a physician, I want immediate notification when a claim is rejected so that I can take corrective action while the details are fresh. |
| Acceptance Criteria | • Triggered as part of the assessment notification (NTF-005) but also available as individual per-claim alerts. • Urgency: High for first rejection of a batch; Standard for subsequent rejections in the same batch (batched into assessment notification). • Content: HSC code, patient (name or PHN last 4), date of service, explanatory code, plain-language explanation of rejection reason, suggested corrective action, link to the rejection detail with one-click resubmission. • AI Coach suggestion included if applicable: “This rejection is commonly caused by [X]. Consider [Y] when resubmitting.” |

| NTF-009 | SOMB / WCB Change Summary |
| --- | --- |
| User Story | As a physician, I want to be notified when the fee schedule changes so that I can adjust my billing practices. |
| Acceptance Criteria | • Triggered by reference_data.version_published event from Reference Data domain. • Urgency: Standard for general updates. High if codes the physician has billed in the last 12 months are deprecated. • Content: version label, effective date, narrative change summary, counts of new/modified/deprecated codes, personalised impact (deprecated codes the physician uses, fee changes on frequently-billed codes). • Direct link to the full change detail view in the platform. • Sent to all active physicians. |

| NTF-010 | System Status Alert |
| --- | --- |
| User Story | As a physician, I want to know about platform issues that affect my billing so that I can plan accordingly. |
| Acceptance Criteria | • Triggered by system monitoring when: H-Link connectivity is lost, WCB submission system is unavailable, Meritum scheduled maintenance is approaching, or an unplanned incident occurs. • Urgency: Standard for scheduled maintenance. Critical for unplanned outages during submission windows (Thursday 08:00–12:00 MT). • Content: nature of the issue, expected impact on billing, estimated resolution time (if known), alternative actions the physician can take. • Critical system alerts are also posted to the public status page (meritum.ca/status). |

| NTF-011 | Payment Failure Escalation |
| --- | --- |
| User Story | As a physician whose payment has failed, I want clear communication about what’s happening and what I need to do so that my access isn’t interrupted. |
| Acceptance Criteria | • Triggered by Stripe webhook: invoice.payment_failed. • Escalation sequence: Day 1: Standard urgency. “Your payment of $[amount] failed. Please update your payment method. Your access is unaffected for now.” Link to Stripe customer portal. Day 3: High urgency. “Second payment attempt failed. Please update your payment method to avoid service interruption.” Day 7: High urgency. “Final payment attempt failed. Your account will be restricted to read-only access on [date] unless payment is resolved.” Day 14: Critical urgency. “Your account has been suspended. You can still view your data and export records. Update your payment method to restore full access.” • Each notification includes a direct link to update payment method. • When payment succeeds after failure: immediate Standard notification. “Payment processed successfully. Your access has been fully restored.” • This category cannot be silenced by the physician. |

| NTF-012 | Security Alert |
| --- | --- |
| User Story | As a physician, I want to be notified of security-relevant events on my account so that I can detect unauthorised access. |
| Acceptance Criteria | • Triggered by Identity & Access events: new device login, account locked, password changed, MFA reconfigured. • Urgency: High. • Content: what happened, when, from what IP/device. For new device logins: “New login from [browser] on [OS] at [time]. If this wasn’t you, change your password immediately.” Link to session management. • This category cannot be silenced. |

| NTF-013 | Configure Notification Preferences |
| --- | --- |
| User Story | As a physician, I want to control which notifications I receive and how so that I’m not overwhelmed but don’t miss critical information. |
| Acceptance Criteria | • Physician navigates to Settings → Notifications. • Preferences are displayed per category (matching the taxonomy in Section 2.1). • For each silenceable category, physician can toggle: email delivery on/off, and in-app delivery on/off (in-app cannot be turned off for High/Critical). • Non-silenceable categories are shown but greyed out with explanation: “This notification cannot be silenced because it relates to [payment / security / claim deadlines].” • AI Coach notifications (Low urgency) default to in-app only; physician can opt in to email delivery. • Changes take effect immediately. • Preference change logged in audit trail: user_id, old_preferences, new_preferences, timestamp. |

| NTF-014 | Notification Centre |
| --- | --- |
| User Story | As a physician or delegate, I want a central place to see all my notifications so that I don’t miss anything and can reference past alerts. |
| Acceptance Criteria | • Notification bell icon visible on all screens with unread count badge. • Clicking opens the notification centre: a panel or dropdown showing notifications in reverse chronological order. • Each notification shows: title, summary (1–2 lines), timestamp (“5 minutes ago” / “Monday at 08:00”), category icon, urgency indicator (colour-coded), and a link to the relevant screen. • Notifications are marked as read when clicked or when the physician explicitly marks them read. • “Mark all as read” action available. • Notification history is paginated (20 per page) and retained for 90 days. • Filter by category (submission cycle, claim alerts, AI Coach, etc.). • Delegates see only notifications relevant to the physician(s) they serve, filtered by their current physician context. |

| Field | Type | Constraints | Notes |
| --- | --- | --- | --- |
| id | UUID | PK |  |
| recipient_user_id | UUID | FK → users.id, NOT NULL | Who receives this notification |
| physician_id | UUID | FK → users.id, NULLABLE | For delegate notifications: which physician context. NULL for physician’s own notifications. |
| category | ENUM | NOT NULL | submission_cycle, assessment, claim_alert, ai_coach, reference_data, account, payment, security, system, delegate |
| urgency | ENUM | NOT NULL | low, standard, high, critical |
| title | VARCHAR(255) | NOT NULL | Short notification title |
| summary | TEXT | NOT NULL | 1–2 line summary displayed in notification centre |
| body | TEXT | NULLABLE | Full notification body (used for email rendering) |
| action_url | VARCHAR(500) | NULLABLE | Deep link to relevant platform screen |
| source_event | VARCHAR(100) | NOT NULL | Event that triggered this notification (e.g., claim_lifecycle.batch_submitted) |
| source_event_id | UUID | NULLABLE | ID of the source event for traceability |
| metadata | JSONB | NULLABLE | Additional structured data for template rendering (claim counts, dollar amounts, etc.) |
| read | BOOLEAN | NOT NULL, DEFAULT false | Whether the user has seen/clicked this notification |
| read_at | TIMESTAMP | NULLABLE | When it was read |
| created_at | TIMESTAMP | NOT NULL | When the notification was created |

| Field | Type | Constraints | Notes |
| --- | --- | --- | --- |
| id | UUID | PK |  |
| notification_id | UUID | FK → notifications.id, NOT NULL |  |
| channel | ENUM | NOT NULL | email, in_app, push (Phase 2), sms (Phase 2+) |
| status | ENUM | NOT NULL, DEFAULT pending | pending, sent, delivered, bounced, failed, suppressed |
| provider_message_id | VARCHAR(255) | NULLABLE | Email provider’s message ID for tracking |
| sent_at | TIMESTAMP | NULLABLE | When delivery was attempted |
| delivered_at | TIMESTAMP | NULLABLE | When delivery was confirmed (webhook from email provider) |
| failed_at | TIMESTAMP | NULLABLE | When delivery failed |
| failure_reason | TEXT | NULLABLE | Bounce reason, error message, etc. |
| retry_count | INTEGER | NOT NULL, DEFAULT 0 | Number of retries attempted |
| next_retry_at | TIMESTAMP | NULLABLE | Scheduled next retry time (NULL if no more retries) |
| suppressed_reason | VARCHAR(100) | NULLABLE | If suppressed: physician_preference, unsubscribed, bounced_address |

| Field | Type | Constraints | Notes |
| --- | --- | --- | --- |
| id | UUID | PK |  |
| schedule_type | ENUM | NOT NULL | submission_monday, submission_wednesday, submission_thursday_morning, submission_thursday_post, assessment_received, deadline_reminder, claim_aging, holiday_calendar_reminder |
| physician_id | UUID | FK → users.id, NULLABLE | NULL for system-wide schedules |
| scheduled_for | TIMESTAMP | NOT NULL | When this notification should be sent (MT timezone converted to UTC) |
| condition_check | JSONB | NOT NULL | Conditions that must be true at send time: e.g., { has_flagged_claims: true } for Wednesday reminder. If conditions are false at execution time, the notification is suppressed. |
| status | ENUM | NOT NULL, DEFAULT pending | pending, executed, suppressed, failed |
| notification_id | UUID | NULLABLE | FK to notifications.id; populated when executed |
| created_at | TIMESTAMP | NOT NULL |  |

| Field | Type | Constraints | Notes |
| --- | --- | --- | --- |
| id | UUID | PK |  |
| user_id | UUID | FK → users.id, UNIQUE, NOT NULL | One preference record per user |
| preferences | JSONB | NOT NULL | Per-category channel preferences: { submission_cycle: { email: true, in_app: true }, ai_coach: { email: false, in_app: true }, ... } |
| updated_at | TIMESTAMP | NOT NULL |  |

| Field | Type | Constraints | Notes |
| --- | --- | --- | --- |
| id | UUID | PK |  |
| email | VARCHAR(255) | UNIQUE, NOT NULL | Email address that has bounced or complained |
| reason | ENUM | NOT NULL | hard_bounce, soft_bounce_repeated, complaint |
| suppressed_at | TIMESTAMP | NOT NULL |  |
| source_provider_event | VARCHAR(255) | NULLABLE | Email provider webhook event ID |

| Source Domain | Event | Notification Category | Urgency | Recipients |
| --- | --- | --- | --- | --- |
| Identity & Access | user.registered | account | Standard | New user (welcome email + verification) |
| Identity & Access | user.account_locked | security | High | Affected user |
| Identity & Access | user.login (new device) | security | High | Affected user |
| Identity & Access | delegate.invited | delegate | Standard | Invitee (invitation email) |
| Identity & Access | delegate.accepted | delegate | Standard | Physician (confirmation) |
| Identity & Access | delegate.removed | delegate | Standard | Delegate (access revoked) |
| Identity & Access | delegate.batch_approved | submission_cycle | Standard | Physician (delegate approved batch) |
| Identity & Access | subscription.status_changed | payment | Standard→Critical | Physician (escalating per NTF-011) |
| Reference Data | reference_data.version_published | reference_data | Standard/High | All active physicians |
| Reference Data | reference_data.code_deprecated | reference_data | High | Physicians who billed deprecated codes |
| Claim Lifecycle | claim.deadline_approaching | claim_alert | High | Physician + delegate |
| Claim Lifecycle | claim.aging_alert | claim_alert | Standard→High | Physician |
| Claim Lifecycle | batch.submitted | submission_cycle | Standard | Physician + delegate (post-submission) |
| Claim Lifecycle | assessment.received | assessment | Standard/High | Physician + delegate |
| Claim Lifecycle | claim.rejected | assessment | High | Physician + delegate |
| Intelligence Engine | coach.suggestions_available | ai_coach | Low | Physician |
| Intelligence Engine | coach.weekly_summary | ai_coach | Low | Physician |
| Platform Operations | system.maintenance_scheduled | system | Standard | All active users |
| Platform Operations | system.incident | system | Critical | All active users |
| Platform Operations | hlink.connectivity_lost | system | Critical | All active users |
| Scheduler (internal) | Thursday submission cycle | submission_cycle | Standard→High | Per NTF-001 through NTF-004 |

| Job | Schedule (MT) | Logic |
| --- | --- | --- |
| Monday batch summary | Monday 08:00 | For each physician with ≥1 queued claim: generate summary notification with clean/flagged counts. For each delegate with batch approval authority: generate delegate copy. |
| Wednesday reminder | Wednesday 17:00 | For each physician with unreviewed flagged claims (or all unreviewed if “require approval” mode): generate reminder. Check condition at execution time (not at scheduling time). Suppress if no flagged claims remain. |
| Thursday final reminder | Thursday 08:00 | Same condition check as Wednesday. Suppress if physician reviewed all claims between Wednesday and Thursday. Urgent tone. |
| Thursday batch execution | Thursday 12:00 | Not a notification job—this is a Claim Lifecycle job. But Notification Service is notified of the result and generates the post-submission confirmation (NTF-004). |
| Assessment check | Friday (polling) | Poll for H-Link assessment file arrival. When received and parsed, generate assessment notification (NTF-005). |

| Job | Schedule | Logic |
| --- | --- | --- |
| 90-day deadline scan | Daily 06:00 MT | Scan all draft/validated claims. Flag any within 14/7/3 days of 90-day window. Generate NTF-006 for new threshold crossings. |
| Claim aging scan | Weekly Monday 07:00 MT | Scan submitted claims with no assessment response beyond expected timeline. Generate NTF-007 for newly aging claims. |
| AI Coach weekly summary | Weekly Friday 16:00 MT | Generate summary of AI Coach suggestions: accepted, dismissed, pending. Send to physicians with active suggestions. |
| Holiday calendar reminder | Annual November 1 | Check if next year’s holiday calendar is populated. If not, alert Admin. |

| Method | Endpoint | Description | Auth |
| --- | --- | --- | --- |
| GET | /api/v1/notifications?page={n}&category={cat}&read={bool} | Get paginated notifications for current user. Filtered by category and read status. Returns: { notifications: [...], unread_count, total, page }. | Yes |
| GET | /api/v1/notifications/unread-count | Get unread notification count (for badge). Returns: { count }. Lightweight endpoint called frequently. | Yes |
| PATCH | /api/v1/notifications/{id}/read | Mark a notification as read. | Yes |
| POST | /api/v1/notifications/mark-all-read | Mark all notifications as read for current user. | Yes |
| GET | /api/v1/notifications/preferences | Get current user’s notification preferences. | Yes |
| PUT | /api/v1/notifications/preferences | Update notification preferences. Body: { category: { email: bool, in_app: bool }, ... }. Validates against silenceability rules. | Yes |

| Method | Endpoint | Description | Auth |
| --- | --- | --- | --- |
| POST | /api/v1/notifications/emit | Internal endpoint for other domains to emit notification events. Body: { event_type, recipients: [{ user_id, physician_id? }], category, urgency, title, summary, body?, action_url?, metadata? }. Creates notification records and triggers delivery. | Internal (service-to-service) |
| POST | /api/v1/notifications/schedule | Schedule a future notification. Body: { schedule_type, physician_id?, scheduled_for, condition_check }. Creates a scheduled_notifications record. | Internal |
| POST | /api/v1/notifications/email/webhook | Webhook endpoint for email provider delivery status updates. Processes: delivered, bounced, complained events. Updates delivery records. | Email provider (verified signature) |

| Method | Endpoint | Description | Auth |
| --- | --- | --- | --- |
| GET | /api/v1/admin/notifications/stats | Delivery statistics: sent, delivered, bounced, failed counts by channel and category. Time range filter. | Admin |
| GET | /api/v1/admin/notifications/failures | List failed notifications with failure reasons. Paginated. | Admin |
| POST | /api/v1/admin/notifications/retry/{id} | Manually retry a failed notification delivery. | Admin |
| GET | /api/v1/admin/notifications/suppressions | List suppressed email addresses with reasons. | Admin |
| DELETE | /api/v1/admin/notifications/suppressions/{id} | Remove an email from suppression list (e.g., after physician updates their email). | Admin |
| GET | /api/v1/admin/notifications/scheduled | List pending scheduled notifications. Filterable by type and status. | Admin |

| Failure Type | Action | Max Retries |
| --- | --- | --- |
| Email provider API timeout | Retry with exponential backoff per urgency policy | Per urgency level (1–5) |
| Email provider API error (5xx) | Retry with backoff | Per urgency level |
| Email provider API error (4xx) | Log error; do not retry (likely invalid request) | 0 |
| Hard bounce | Add to suppression list; notify user via in-app Critical notification | 0 |
| Soft bounce | Retry up to 3 times over 24 hours; if persistent, treat as hard bounce | 3 |
| Complaint (spam report) | Add to suppression list; log for review | 0 |
| Scheduled job missed (server down) | Database-backed queue: worker picks up overdue jobs on next poll; executes immediately if still within validity window | 1 (immediate on recovery) |
| All channels failed for Critical notification | Create admin alert; manual intervention may be required | N/A |

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| event_type | STRING | Yes | Namespaced event identifier (e.g., claim_lifecycle.batch_submitted, identity.user_registered) |
| event_id | UUID | Yes | Unique event ID for idempotency and tracing |
| timestamp | TIMESTAMP | Yes | When the event occurred |
| recipients | ARRAY | Yes | [{ user_id, physician_id? }] — who should receive the notification |
| category | ENUM | Yes | Notification category (from taxonomy) |
| urgency | ENUM | Yes | low, standard, high, critical |
| title | STRING | Yes | Notification title |
| summary | STRING | Yes | 1–2 line summary |
| body | STRING | No | Full body (for email rendering). If omitted, email uses summary. |
| action_url | STRING | No | Deep link to relevant platform screen |
| metadata | OBJECT | No | Structured data for template rendering |

| Action | Detail Logged |
| --- | --- |
| notification.created | notification_id, recipient_user_id, category, urgency, source_event |
| notification.delivered | notification_id, channel, provider_message_id |
| notification.failed | notification_id, channel, failure_reason, retry_count |
| notification.suppressed | notification_id, channel, suppression_reason |
| notification.read | notification_id, user_id, timestamp |
| notification.preferences_updated | user_id, old_preferences, new_preferences |
| notification.scheduled | schedule_id, schedule_type, scheduled_for |
| notification.schedule_executed | schedule_id, notification_id, outcome (sent/suppressed) |
| notification.schedule_failed | schedule_id, failure_reason |
| email.bounced | email_hash, bounce_type, provider_event_id |
| email.complained | email_hash, provider_event_id |
| admin.retry_notification | admin_id, notification_id, delivery_id |

| Question | Options | Decision Criteria |
| --- | --- | --- |
| Email provider | Postmark vs. SendGrid vs. Amazon SES | Postmark: best deliverability, transactional focus, ~$1.25/1000 emails. SendGrid: widely used, good API, $0.65/1000. SES: cheapest ($0.10/1000) but more operational overhead. At MVP scale (<10,000 emails/month), cost is negligible. Prioritise deliverability and webhook reliability. |
| Event bus | Direct function calls (in-process) vs. database-backed queue vs. Redis Pub/Sub vs. NATS | In-process is simplest for single-server MVP but events are lost if server crashes mid-processing. Database queue (table-backed) is resilient and auditable. Redis adds latency benefits. Start with database queue; upgrade if event volume justifies it. |
| Job scheduler | System cron vs. database-backed polling vs. BullMQ/Agenda.js | Database-backed polling (recommended in Section 6.3) is the simplest resilient option. Framework-integrated schedulers like Agenda.js add convenience. BullMQ requires Redis. |
| Real-time in-app notifications | Polling vs. Server-Sent Events (SSE) vs. WebSocket | Polling is simplest (check unread count every 30–60 seconds). SSE provides real-time push without the complexity of WebSocket. WebSocket is overkill for notifications. SSE is the recommended starting point. |
| Email template engine | Server-side HTML rendering (EJS, Handlebars, MJML) vs. provider-hosted templates | MJML is excellent for responsive email HTML. Server-side rendering with MJML gives full control. Provider-hosted templates reduce flexibility but simplify deployment. MJML + server rendering recommended. |

| Version | Date | Author | Changes |
| --- | --- | --- | --- |
| 1.0 | February 12, 2026 | Ian Sharland | Initial Notification Service functional requirements |

