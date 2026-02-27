# Meritum_Domain_09_Notification_Service

MERITUM

Functional Requirements

Notification Service

Domain 9 of 13  |  Cross-Cutting Service

Meritum Health Technologies Inc.

Version 2.0  |  February 2026

CONFIDENTIAL

# Table of Contents

1. [Domain Overview](#1-domain-overview)
2. [Notification Channels](#2-notification-channels)
3. [Notification Taxonomy](#3-notification-taxonomy)
4. [Event Catalogue](#4-event-catalogue)
5. [Notification Preferences](#5-notification-preferences)
6. [Data Model](#6-data-model)
7. [Event Processing Pipeline](#7-event-processing-pipeline)
8. [Email Delivery](#8-email-delivery)
9. [Digest Assembly](#9-digest-assembly)
10. [Scheduled Notification Engine](#10-scheduled-notification-engine)
11. [WebSocket Real-Time Delivery](#11-websocket-real-time-delivery)
12. [Delegate Notification Routing](#12-delegate-notification-routing)
13. [User Stories & Acceptance Criteria](#13-user-stories--acceptance-criteria)
14. [API Contracts](#14-api-contracts)
15. [Interface Contracts with Other Domains](#15-interface-contracts-with-other-domains)
16. [Security & Audit](#16-security--audit)
17. [Testing Requirements](#17-testing-requirements)
18. [Document Control](#18-document-control)

# 1. Domain Overview

## 1.1 Purpose

The Notification Service is the cross-cutting communication infrastructure of Meritum. It is responsible for delivering timely, reliable, and configurable notifications to physicians and delegates across all channels. It does not generate notification content — it receives structured events from other domains and delivers them through the appropriate channel(s) based on the notification type, urgency, and physician preferences.

This domain is elevated in the critical path because the tiered auto-submission model depends on it for the Thursday submission notification sequence. Without reliable notifications, the auto-submission system cannot inform physicians about pending reviews, and the safety model collapses. Notifications are also the delivery mechanism for SOMB change summaries, rejection alerts, payment failure warnings, IMA compliance events, and every other time-sensitive communication.

The implementation is consolidated into a single `notification/` domain module within `apps/api/src/domains/`. This FRD supersedes both the original Domain 3 and Domain 9 notification specifications.

## 1.2 Scope

- In-app notification centre: persistent notification feed within the Meritum UI, with real-time push via WebSocket
- Email notifications: transactional emails triggered by platform events, delivered via Postmark
- Event ingestion: consume events from all domains via internal event bus (API key–authenticated endpoints)
- Notification preferences: per-physician, per-category channel and frequency configuration
- Template management: notification message templates with `{{variable}}` substitution and HTML escaping
- Delivery tracking: delivery status, read receipts (in-app), bounce handling (email)
- Retry logic: automatic retry for failed email delivery with exponential backoff
- Batching and digest: aggregate low-priority notifications into daily or weekly digest emails
- Quiet hours: suppress non-urgent email notifications during configured hours (Mountain Time)
- Delegate notification routing: filter notifications to delegates based on their permission set and physician context
- Dual-delivery: breach and IMA amendment events delivered to both primary and secondary email addresses
- Scheduled notification jobs: Thursday submission cycle, daily/weekly digest assembly, email retry
- Postmark webhook processing: delivery confirmation, bounce handling, suppression
- Architecture for push notifications (Phase 2, when native mobile apps ship)

## 1.3 Out of Scope

- Business logic that determines when events fire (owned by source domains)
- Report generation (Domain 8; Notification Service only delivers the download link)
- SMS notifications (deferred; physician communication via email and in-app at MVP)
- Marketing or promotional messaging (Meritum is ad-free; notifications are operational only)
- Push notification delivery (Phase 2, with native mobile apps)
- Notification content authoring (producing domains define content in their events)

## 1.4 Domain Dependencies

| Domain | Direction | Interface |
| --- | --- | --- |
| All domains | Events received | Every domain emits events that the Notification Service consumes via the internal event API. Event catalogue in Section 4. |
| 1 Identity & Access | Consumed | User email addresses (primary + secondary), session validation (for WebSocket auth), delegate linkage relationships (for routing). |
| 5 Provider Management | Consumed | Physician name (for email personalisation), delegate relationships and permissions (for delegate notification filtering). |
| 4.0 Claim Lifecycle | Events received | Claim state change events, batch assembly/submission events, assessment events, deadline warnings. Also queried for flagged claim counts (Wednesday batch reminder). |
| 7 Intelligence Engine | Events received | AI suggestion events, SOMB change impact events. |
| 8 Analytics | Events received | Scheduled report generation complete events, data export ready events. |
| 12 Platform Operations | Events received | Payment failure/recovery, account suspension/reactivation, maintenance events, IMA amendment events, breach notification events, export window events. |

# 2. Notification Channels

## 2.1 In-App Notifications

The primary notification channel. A persistent notification centre in the Meritum UI accessible via a bell icon in the header. Notifications are stored server-side and synced to the client in real time via WebSocket.

- **Unread badge:** Count of unread notifications displayed on the bell icon. Updated in real time via WebSocket `unread_count` messages.
- **Notification feed:** Reverse-chronological list. Each notification shows: icon (category), title, body preview, timestamp, read/unread status, priority indicator (colour-coded).
- **Actions:** Mark as read, mark all as read, dismiss (hides but retains for audit), click to navigate to relevant page (e.g., click rejection notification → navigate to rejected claim).
- **Real-time delivery:** New notifications pushed to the client via WebSocket. No page refresh required. Supports multiple concurrent tabs per user.
- **Persistence:** Notifications retained for 90 days in the primary table. Archived to cold storage after 90 days. Available via 'View all' for up to 1 year.
- **Pagination:** Feed paginated at 20 items per page (configurable via `limit` query parameter, max 100).
- **Filtering:** Filter by read/unread status via `unread_only` query parameter.

## 2.2 Email Notifications

Secondary channel for time-sensitive or important events. Email notifications are sent in addition to (not instead of) in-app notifications. The physician can disable email for specific event categories (except URGENT and non-silenceable categories).

- **Sender:** `notifications@meritum.ca` (transactional, not marketing)
- **Provider:** Postmark (selected for transactional focus, excellent deliverability, and webhook support)
- **Format:** HTML email with plain-text fallback. Meritum branding. No PHI in email body — links to authenticated pages instead.
- **Unsubscribe:** Per-category unsubscribe via preference settings. Global email disable available.
- **Bounce handling:** Hard bounces mark delivery as BOUNCED with no retry. Soft bounces retry per schedule. Hard bounce triggers in-app HIGH priority notification to update email address.
- **Dual-delivery:** Breach and IMA amendment events (BREACH_INITIAL_NOTIFICATION, BREACH_UPDATE, IMA_AMENDMENT_NOTICE, IMA_AMENDMENT_REMINDER, IMA_AMENDMENT_DEADLINE) are delivered to both the physician's primary and secondary email addresses when a secondary email is configured.
- **Email sender authentication:** SPF, DKIM, and DMARC configured for meritum.ca to prevent spoofing.

### 2.2.1 CASL Compliance

Meritum's transactional notifications are exempt from CASL consent requirements under the "transactional message" exemption. Best practice requires:

- Clear sender identification ("Meritum Health Technologies Inc.")
- Valid mailing address in email footer
- Unsubscribe mechanism for categories that can be silenced
- No marketing content in transactional emails
- Prompt processing of unsubscribe requests (within 10 business days per CASL; Meritum targets immediate effect)

### 2.2.2 Email Content Safety: No PHI in Email

Email notifications must never contain Protected Health Information. This means: no patient names, no PHNs, no diagnostic codes, no HSC codes tied to identifiable patients, no clinical details. Emails contain aggregate information (claim counts, dollar totals, category summaries) and deep links to the platform where the physician can view full details after authentication.

Example of what an email CAN contain: "You have 23 claims queued for Thursday. 20 are clean and will auto-submit. 3 have AI Coach suggestions requiring your review. Estimated value: $4,200."

Example of what an email CANNOT contain: "Your claim for John Smith (PHN 123456789) for code 03.04A on Jan 15 was rejected because..."

## 2.3 Push Notifications (Phase 2)

When native mobile apps ship (Phase 2), push notifications will be added as a third channel. Architecture accommodations:

- Notification records include a `push` field in `channels_delivered` JSONB (currently always `false`).
- Channel routing logic supports IN_APP, EMAIL, PUSH as independent toggles.
- Push notification provider integration point defined but not implemented at MVP.
- The `NotificationChannel` constant already includes `PUSH` for forward compatibility.

# 3. Notification Taxonomy

## 3.1 Priority Levels

Every notification has a priority level that determines delivery behaviour, retry policy, and silenceability.

| Priority | Delivery Behaviour | Retry on Email Failure | Can Be Silenced |
| --- | --- | --- | --- |
| LOW | In-app only by default; email if physician has opted in | 4 attempts: immediate, +5min, +30min, +2hr | Yes |
| MEDIUM | In-app + email (default) | 4 attempts: immediate, +5min, +30min, +2hr | Configurable per category |
| HIGH | In-app + email; email sent immediately (not batched) | 4 attempts: immediate, +5min, +30min, +2hr | No |
| URGENT | In-app always on (cannot be disabled) + email; email sent immediately | 4 attempts: immediate, +5min, +30min, +2hr | No |

## 3.2 Event Categories

Events are grouped into categories for preference management. Each category maps to one or more event types.

| Category | Source Domain(s) | Description | Physician Can Silence Email? |
| --- | --- | --- | --- |
| CLAIM_LIFECYCLE | Domain 4 (Claims) | Claim validation, deadlines, batch assembly/submission, assessment, rejection, payment, duplicate detection | No (contains URGENT deadline and batch error events) |
| INTELLIGENCE_ENGINE | Domain 7 (AI Coach) | AI suggestions, SOMB change impacts | Yes (LOW priority defaults to in-app only) |
| PROVIDER_MANAGEMENT | Domain 5 (Providers) | Delegate lifecycle, BA status changes, RRNP rate updates | Configurable per event |
| PLATFORM_OPERATIONS | Domain 12 (Platform) | Payment failure/recovery, account suspension/reactivation, maintenance | No (contains URGENT payment/suspension events) |
| ANALYTICS | Domain 8 (Analytics) | Report ready, data export ready | Yes |
| IMA_COMPLIANCE | Domain 12 (Platform) | Export window lifecycle, IMA amendment lifecycle, breach notifications, data destruction confirmation, patient access export, full HI export | No (contains URGENT breach and amendment deadline events) |

# 4. Event Catalogue

Every notification originates from a domain event. This catalogue defines all 40 events the Notification Service consumes, their source domain, default channels, and priority.

## 4.1 Claim Lifecycle Events (Domain 4) — 13 Events

| Event Type | In-App | Email | Priority | Description |
| --- | --- | --- | --- | --- |
| CLAIM_VALIDATED | Yes | No | LOW | Claim passed validation. Informational. |
| CLAIM_FLAGGED | Yes | No | MEDIUM | Claim classified as flagged. Review needed. |
| DEADLINE_7_DAY | Yes | Yes | MEDIUM | Claim within 7 days of 90-day submission deadline. |
| DEADLINE_3_DAY | Yes | Yes | HIGH | Claim within 3 days of deadline. |
| DEADLINE_1_DAY | Yes | Yes | URGENT | Claim within 1 day of deadline. Cannot be silenced. |
| DEADLINE_EXPIRED | Yes | Yes | HIGH | Claim passed deadline. Revenue lost. |
| BATCH_ASSEMBLED | Yes | No | LOW | Batch generation complete. Ready for transmission. |
| BATCH_SUBMITTED | Yes | Yes | MEDIUM | Batch transmitted to AHCIP or uploaded to WCB. |
| BATCH_ERROR | Yes | Yes | URGENT | Batch transmission failed. Manual intervention required. Cannot be silenced. |
| CLAIM_ASSESSED | Yes | No | LOW | Payer accepted claim. |
| CLAIM_REJECTED | Yes | Yes | HIGH | Payer rejected claim. Corrective action needed. |
| CLAIM_PAID | Yes | No | LOW | Payment confirmed. |
| DUPLICATE_DETECTED | Yes | No | MEDIUM | Potential duplicate claim identified. |

## 4.2 Intelligence Engine Events (Domain 7) — 3 Events

| Event Type | In-App | Email | Priority | Description |
| --- | --- | --- | --- | --- |
| AI_SUGGESTION_READY | Yes | No | LOW | AI Coach suggestions available for review on a claim. |
| AI_HIGH_VALUE_SUGGESTION | Yes | Yes | HIGH | AI Coach identified a suggestion with revenue impact > $50. |
| SOMB_CHANGE_IMPACT | Yes | Yes | MEDIUM | SOMB update affects codes the physician frequently uses. |

## 4.3 Provider Management Events (Domain 5) — 5 Events

| Event Type | In-App | Email | Priority | Description |
| --- | --- | --- | --- | --- |
| DELEGATE_INVITED | Yes | Yes | MEDIUM | Invitation sent to delegate (email to delegate, in-app to physician). |
| DELEGATE_ACCEPTED | Yes | Yes | MEDIUM | Delegate accepted invitation. |
| DELEGATE_REVOKED | Yes | Yes | HIGH | Delegate access revoked (notification to delegate). |
| BA_STATUS_CHANGED | Yes | Yes | HIGH | BA status changed (PENDING → ACTIVE, or ACTIVE → INACTIVE). |
| RRNP_RATE_CHANGED | Yes | Yes | MEDIUM | Quarterly RRNP rate update for physician's community. |

## 4.4 Platform Operations Events (Domain 12) — 5 Events

| Event Type | In-App | Email | Priority | Description |
| --- | --- | --- | --- | --- |
| PAYMENT_FAILED | Yes | Yes | URGENT | Subscription payment failed. Dunning sequence starts. Cannot be silenced. |
| PAYMENT_RECOVERED | Yes | Yes | HIGH | Payment recovered after failure. |
| ACCOUNT_SUSPENDED | Yes | Yes | URGENT | Account suspended due to non-payment. Cannot be silenced. |
| ACCOUNT_REACTIVATED | Yes | Yes | HIGH | Account reactivated after payment. |
| MAINTENANCE_SCHEDULED | Yes | Yes | MEDIUM | Planned maintenance window. |

## 4.5 Analytics Events (Domain 8) — 2 Events

| Event Type | In-App | Email | Priority | Description |
| --- | --- | --- | --- | --- |
| REPORT_READY | Yes | Yes | MEDIUM | Scheduled or on-demand report generated and ready for download. |
| DATA_EXPORT_READY | Yes | Yes | MEDIUM | Data portability export ready for download. |

## 4.6 IMA Compliance Events — 12 Events

These events support Health Information Act compliance requirements including data portability, IMA amendments, and breach notifications.

| Event Type | In-App | Email | Priority | Description | Dual-Delivery |
| --- | --- | --- | --- | --- | --- |
| EXPORT_WINDOW_STARTED | Yes | Yes | HIGH | 30-day data portability export window has opened following cancellation. | No |
| EXPORT_WINDOW_REMINDER | Yes | Yes | HIGH | Reminder that the export window is still open (sent at configurable intervals). | No |
| EXPORT_WINDOW_CLOSING | Yes | Yes | URGENT | Export window closing soon (final warning). Cannot be silenced. | No |
| EXPORT_WINDOW_CLOSED | Yes | Yes | URGENT | Export window has closed. Data destruction can proceed. Cannot be silenced. | No |
| IMA_AMENDMENT_NOTICE | Yes | Yes | HIGH | New IMA amendment published. Physician must acknowledge. | Yes |
| IMA_AMENDMENT_REMINDER | Yes | Yes | HIGH | Reminder to acknowledge pending IMA amendment. | Yes |
| IMA_AMENDMENT_DEADLINE | Yes | Yes | URGENT | IMA amendment acknowledgement deadline approaching. Cannot be silenced. | Yes |
| BREACH_INITIAL_NOTIFICATION | Yes | Yes | URGENT | Privacy breach detected. Initial notification to affected custodian within 72 hours. Cannot be silenced. | Yes |
| BREACH_UPDATE | Yes | Yes | URGENT | Update to an ongoing breach investigation. Cannot be silenced. | Yes |
| DATA_DESTRUCTION_CONFIRMED | Yes | Yes | HIGH | Data destruction completed following export window closure. | No |
| PATIENT_ACCESS_EXPORT_READY | Yes | No | MEDIUM | Patient access request export package ready for download. | No |
| FULL_HI_EXPORT_READY | Yes | Yes | HIGH | Complete health information export package ready for download. | No |

## 4.7 Thursday Submission Sequence

The Thursday batch cycle generates a coordinated sequence of notifications:

| Timing | Notification |
| --- | --- |
| Wednesday 18:00 MT | Batch review reminder: "You have X flagged claims awaiting review before tomorrow's cutoff." (if `batch_review_reminder` preference is enabled and flagged claims exist). Condition checked at execution time, not scheduling time. |
| Thursday 12:00 MT | Cutoff confirmation: "Thursday batch cutoff reached. X claims in your queue." |
| Thursday ~14:00 MT | Batch submitted: "Your Thursday batch (X claims, $Y total) has been transmitted to AHCIP." |
| Thursday evening | WCB batch ready: "Your WCB batch (X claims) is ready for download and upload to myWCB." (if applicable) |
| Friday | Assessment received: "Assessment results for your [date] batch are available. X accepted, Y rejected." |
| Friday | Payment confirmed: "Payment of $X deposited for your [date] batch." |

# 5. Notification Preferences

## 5.1 Preference Model

Each physician configures notification preferences per event category and per channel. Preferences are stored per-physician (keyed by `provider_id` + `event_category`) and apply to all events of that category.

Preference fields per category:
- `in_app_enabled` — whether in-app notifications are shown for this category (default: `true`)
- `email_enabled` — whether email notifications are sent (default varies per event catalogue entry)
- `digest_mode` — `IMMEDIATE`, `DAILY_DIGEST`, or `WEEKLY_DIGEST` (default: `IMMEDIATE`)
- `quiet_hours_start` / `quiet_hours_end` — global quiet hours (shared across all categories, stored on each preference row)

## 5.2 Default Preferences

On registration, default preferences are created for every event category present in the EVENT_CATALOGUE:

- **URGENT events:** In-app always on (cannot disable). Email on. Digest mode: IMMEDIATE.
- **HIGH events:** In-app on. Email on. Digest mode: IMMEDIATE.
- **MEDIUM events:** In-app on. Email on (per catalogue defaults). Digest mode: IMMEDIATE.
- **LOW events:** In-app on. Email off. Digest mode: IMMEDIATE.
- **Quiet hours:** Not set (no suppression by default).

Physicians can customise all settings except: URGENT in-app cannot be disabled (safety-critical events like account suspension, batch failure, and breach notifications must always be visible). This enforcement happens at the service layer when updating preferences.

## 5.3 Delegate Notifications

Delegates receive notifications for the physician context they serve, filtered by their permissions. The `PERMISSION_EVENT_MAP` in the service layer maps permissions to event types:

| Permission | Events Received |
| --- | --- |
| CLAIM_VIEW | CLAIM_VALIDATED, CLAIM_FLAGGED, CLAIM_ASSESSED, CLAIM_REJECTED, CLAIM_PAID, DUPLICATE_DETECTED |
| CLAIM_SUBMIT | BATCH_ASSEMBLED, BATCH_SUBMITTED, BATCH_ERROR |
| CLAIM_MANAGE | DEADLINE_7_DAY, DEADLINE_3_DAY, DEADLINE_1_DAY, DEADLINE_EXPIRED |
| AI_VIEW | AI_SUGGESTION_READY, AI_HIGH_VALUE_SUGGESTION, SOMB_CHANGE_IMPACT |
| DELEGATE_MANAGE | DELEGATE_INVITED, DELEGATE_ACCEPTED, DELEGATE_REVOKED |
| ANALYTICS_VIEW | REPORT_READY, DATA_EXPORT_READY |

Events not in this map (platform operations, IMA compliance) are delivered only to the physician, not to delegates.

When a delegate serves multiple physicians, they receive notifications from each physician's context separately. Each delegate notification includes a `physician_context_id` identifying which physician context it belongs to.

Delegates cannot access or modify notification preferences — only physicians can manage preferences.

# 6. Data Model

## 6.1 Notifications Table (`notifications`)

Stores all rendered notifications. Scoped by `recipient_id`. Dismissed notifications retained for audit trail (soft-hide via `dismissed_at`).

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| notification_id | UUID PK | No | Primary key. Auto-generated (defaultRandom). |
| recipient_id | UUID FK → users.user_id | No | Who receives this notification (physician or delegate). |
| physician_context_id | UUID | Yes | For delegate notifications: which physician context. Null for physician's own notifications or system-wide notifications. |
| event_type | VARCHAR(50) | No | Event type from catalogue (e.g., 'CLAIM_REJECTED'). |
| priority | VARCHAR(10) | No | URGENT, HIGH, MEDIUM, LOW. |
| title | VARCHAR(200) | No | Notification title (rendered from template). |
| body | TEXT | No | Notification body (rendered from template). |
| action_url | VARCHAR(500) | Yes | URL to navigate when notification clicked (e.g., '/claims/{id}'). |
| action_label | VARCHAR(50) | Yes | Button label (e.g., 'View Claim', 'Review Batch'). |
| metadata | JSONB | Yes | Event-specific data: claim_id, batch_id, report_id, etc. For UI rendering and template variables. |
| channels_delivered | JSONB | No | Which channels this notification was delivered to: `{in_app: true, email: true, push: false}`. |
| read_at | TIMESTAMPTZ | Yes | When the notification was read in-app. Null if unread. |
| dismissed_at | TIMESTAMPTZ | Yes | When dismissed. Hidden from feed but retained for audit. |
| created_at | TIMESTAMPTZ | No | Defaults to now(). |

**Indexes:**
- `(recipient_id, read_at)` — for unread count queries (high frequency, must be <50ms)
- `(recipient_id, created_at DESC)` — for notification feed pagination
- `(event_type, created_at)` — for analytics and event-type queries

**Retention:** 90 days in primary table. Archived to cold storage after 90 days. Available via 'View all' for up to 1 year.

## 6.2 Email Delivery Log Table (`email_delivery_log`)

Tracks email delivery status, retries, and bounces. Access restricted to internal services and admin only (contains `recipient_email`).

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| delivery_id | UUID PK | No | Primary key. Auto-generated. |
| notification_id | UUID FK → notifications | No | FK to notifications. |
| recipient_email | VARCHAR(100) | No | Email address sent to. |
| template_id | VARCHAR(50) | No | Email template used. |
| status | VARCHAR(20) | No | QUEUED, SENT, DELIVERED, BOUNCED, FAILED. Default: QUEUED. |
| provider_message_id | VARCHAR(100) | Yes | Postmark message ID for webhook correlation. |
| sent_at | TIMESTAMPTZ | Yes | When email was sent. |
| delivered_at | TIMESTAMPTZ | Yes | When delivery was confirmed via webhook. |
| bounced_at | TIMESTAMPTZ | Yes | When bounce was detected. |
| bounce_reason | TEXT | Yes | Bounce reason from provider. |
| retry_count | INTEGER | No | Number of retry attempts. Default: 0. |
| next_retry_at | TIMESTAMPTZ | Yes | When next retry is scheduled. |
| created_at | TIMESTAMPTZ | No | Defaults to now(). |

**Indexes:**
- `(notification_id)` — for looking up delivery status by notification
- `(status, next_retry_at)` — for retry job queries
- `(recipient_email, created_at)` — for delivery history lookups

## 6.3 Notification Templates Table (`notification_templates`)

Templates are managed by the development team, not physicians. Variable substitution uses `{{variable_name}}` syntax. All variable values are HTML-escaped before rendering to prevent template injection. Variables are validated against the template's declared variables list before rendering.

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| template_id | VARCHAR(50) PK | No | Primary key. Matches event_type (e.g., 'CLAIM_REJECTED'). |
| in_app_title | VARCHAR(200) | No | Title template with `{{variable}}` placeholders. |
| in_app_body | TEXT | No | Body template. |
| email_subject | VARCHAR(200) | Yes | Email subject template. Null if event never sends email. |
| email_html_body | TEXT | Yes | HTML email body template. |
| email_text_body | TEXT | Yes | Plain-text email body fallback. |
| action_url_template | VARCHAR(500) | Yes | URL template with `{{claim_id}}`, `{{batch_id}}`, etc. |
| action_label | VARCHAR(50) | Yes | Static action button label. |
| variables | JSONB | No | Array of variable names expected in the template context. |
| updated_at | TIMESTAMPTZ | No | Defaults to now(). |

Templates are upserted (insert or update on conflict by `template_id`).

## 6.4 Digest Queue Table (`digest_queue`)

Holds notifications awaiting digest assembly. Low-priority events with `digest_mode = DAILY_DIGEST` or `WEEKLY_DIGEST` accumulate here until the digest job runs. Hard-deleted after digest is sent — no PHI retention beyond delivery.

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| queue_id | UUID PK | No | Primary key. Auto-generated. |
| recipient_id | UUID FK → users.user_id | No | FK to users. |
| notification_id | UUID FK → notifications | No | FK to notifications (already created with in-app delivery). |
| digest_type | VARCHAR(20) | No | DAILY_DIGEST or WEEKLY_DIGEST. |
| digest_sent | BOOLEAN | No | Whether this item has been included in a digest email. Default: false. |
| created_at | TIMESTAMPTZ | No | Defaults to now(). |

**Indexes:**
- `(recipient_id, digest_sent, digest_type)` — for finding pending digest items per recipient
- `(created_at)` — for time-based queries and cleanup

## 6.5 Notification Preferences Table (`notification_preferences`)

Per-provider, per-event-category channel and frequency configuration. Scoped to `provider_id` — no cross-physician preference access. URGENT in-app cannot be disabled (enforced at service layer).

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| preference_id | UUID PK | No | Primary key. Auto-generated. |
| provider_id | UUID FK → users.user_id | No | FK to users (physician). |
| event_category | VARCHAR(50) | No | Event category (e.g., 'CLAIM_LIFECYCLE', 'IMA_COMPLIANCE'). |
| in_app_enabled | BOOLEAN | No | Whether in-app notifications are enabled for this category. Default: true. |
| email_enabled | BOOLEAN | No | Whether email notifications are enabled. Default per event catalogue. |
| digest_mode | VARCHAR(20) | No | IMMEDIATE, DAILY_DIGEST, WEEKLY_DIGEST. Default: IMMEDIATE. |
| quiet_hours_start | TIME | Yes | Start of quiet hours (email suppressed). Global setting stored on each row. |
| quiet_hours_end | TIME | Yes | End of quiet hours. |
| updated_at | TIMESTAMPTZ | No | Defaults to now(). |

**Indexes:**
- UNIQUE `(provider_id, event_category)` — one preference record per physician per category
- `(provider_id)` — for loading all preferences at once

# 7. Event Processing Pipeline

## 7.1 Pipeline Steps

**Step 1: Event received.** Source domain calls the internal emit endpoint (`POST /api/v1/internal/notifications/emit`). Request includes: `event_type`, `physician_id`, `metadata`. Authenticated via `X-Internal-API-Key` header with constant-time comparison.

**Step 2: Recipient resolution.** Determine who should receive this notification:
- Primary: the physician (always).
- Secondary: active delegates whose permissions include the capability required for this event type (per `PERMISSION_EVENT_MAP`). Delegates without the required permission are skipped. Events not in the permission map are delivered only to the physician.

**Step 3: Preference check.** For each recipient, look up notification preferences for the event's category. Determine channels (in-app, email) and digest mode. For URGENT events, in-app is forced to `true` regardless of preference.

**Step 4: Template rendering.** Load template matching the event_type. Substitute variables from event metadata. All variable values are HTML-escaped to prevent template injection. If no template exists, fallback content is used (event type as title, "Event: {type}" as body).

**Step 5: Notification creation.** Create notification record in the `notifications` table with rendered content for each recipient.

**Step 6: In-app delivery.** Push notification to recipient's WebSocket connections via the `NotificationWebSocketManager` singleton. Best-effort, fire-and-forget. Always stored in notification table regardless of connection status.

**Step 7: Email routing.** If email enabled for this event/recipient:
- If `digest_mode = IMMEDIATE`: create email delivery log entry with QUEUED status.
- If `digest_mode = DAILY_DIGEST` or `WEEKLY_DIGEST`: add to digest queue for later assembly.
- If event type is in the dual-delivery set and recipient is the physician (not a delegate): also queue a delivery to the secondary email address (if configured).

**Step 8: Delivery tracking and audit.** Record event emission in audit log with recipient count. Email delivery status tracked in `email_delivery_log` and updated via Postmark webhooks.

## 7.2 Batch Event Processing

The `POST /api/v1/internal/notifications/emit-batch` endpoint accepts up to 500 events at once (e.g., batch submission generates events for all claims). Each event is processed through the same pipeline sequentially. Returns the total count of notifications created.

## 7.3 Retry Logic

Email delivery failures are retried automatically:

| Attempt | Timing |
| --- | --- |
| 1 | Immediate |
| 2 | +5 minutes |
| 3 | +30 minutes |
| 4 | +2 hours |

After 4 total failures, status = FAILED. An audit log entry is created with the failure reason.

The retry job runs every 5 minutes (cron: `*/5 * * * *`). It queries `email_delivery_log` for entries with status QUEUED or FAILED, `next_retry_at` in the past, and `retry_count < 4`.

**Hard bounces (invalid email address):** No retry. Status = BOUNCED. In-app HIGH priority notification created: "We could not deliver an email to your address. Please update your email in account settings."

**Soft bounces (mailbox full, server temporarily unavailable):** Retry per schedule. If retries exhausted, status = FAILED.

**Provider outage:** If Postmark is down, queue emails and retry when provider recovers. In-app delivery unaffected.

## 7.4 Quiet Hours

Quiet hours are configured globally per physician (not per category) using Mountain Time (America/Edmonton timezone). The system checks the current time in Edmonton timezone and compares against the configured start/end times.

- Same-day range (e.g., 09:00 – 17:00): suppressed during that window.
- Overnight range (e.g., 22:00 – 07:00): suppressed from 22:00 until 07:00 next day.
- URGENT events bypass quiet hours (email sent immediately regardless).
- In-app notifications are unaffected by quiet hours (always delivered).
- When quiet hours are active, emails are deferred until the quiet hours end time.

# 8. Email Delivery

## 8.1 Postmark Integration

Postmark is the transactional email provider. The service uses an abstracted `PostmarkClient` interface for testability:

```typescript
interface PostmarkClient {
  sendEmail(options: {
    From: string;
    To: string;
    Subject: string;
    HtmlBody: string;
    TextBody: string;
    MessageStream: string;
  }): Promise<{ MessageID: string }>;
}
```

**Sending flow:**
1. Create delivery log entry with QUEUED status.
2. Call Postmark API.
3. On success: update status to SENT, record `provider_message_id` and `sent_at`.
4. On failure: schedule retry per retry schedule, or mark FAILED if max retries exhausted.

**Default sender:** `notifications@meritum.ca` (configurable via `senderEmail` dependency).

**Message stream:** `outbound` (Postmark's default transactional stream).

## 8.2 Postmark Webhook Processing

The `POST /api/v1/webhooks/postmark` endpoint receives delivery status callbacks from Postmark. Authenticated via `X-Postmark-Signature` header using HMAC-SHA256 with constant-time comparison.

**Delivery events (RecordType = 'Delivery'):** Look up delivery log by `MessageID`, update status to DELIVERED with `delivered_at` timestamp.

**Bounce events (RecordType = 'Bounce'):**
- TypeCode 1 (HardBounce): mark BOUNCED, no retry, create in-app bounce alert notification.
- Other TypeCodes (soft bounce): schedule retry per retry schedule if retries remain, otherwise mark FAILED.

## 8.3 Email Templates

All emails follow a consistent Meritum brand template:

- Header: Meritum logo, forest green accent
- Body: notification content (varies per type) — no PHI
- CTA button: primary action link (e.g., "Review your claims", "Update payment method")
- Footer: "Meritum Health Technologies Inc.", unsubscribe link (for silenceable categories), support contact, mailing address per CASL requirements

Templates use `{{variable}}` substitution. Variables are HTML-escaped before rendering.

# 9. Digest Assembly

## 9.1 Daily Digest

Runs at 08:00 MT daily (cron: `0 8 * * *`). Assembles all pending DAILY_DIGEST queue items grouped by recipient into a single summary email.

**Digest email content (no PHI):**
- Subject: "Your Daily Meritum Summary"
- Body: count of notifications grouped by event category
- Link: "View all notifications" → `https://meritum.ca/notifications`

## 9.2 Weekly Digest

Runs Monday at 08:00 MT (cron: `0 8 * * 1`). Assembles all pending WEEKLY_DIGEST queue items from the past 7 days into a single summary email. Same format as daily digest with subject "Your Weekly Meritum Summary".

## 9.3 Digest Rendering

Digest emails group notifications by event category and show counts. No individual notification details that could contain PHI. Each category line shows: category name and count (e.g., "CLAIM_LIFECYCLE: 5 notifications"). Both HTML and plain-text versions are generated.

After sending, digest queue items are marked as `digest_sent = true`. An audit log entry records the digest assembly with digest type, recipient count, and item count.

# 10. Scheduled Notification Engine

## 10.1 Registered Jobs

All scheduled jobs are registered via `registerNotificationJobs()` and use cron expressions in America/Edmonton timezone:

| Job | Cron Expression | Schedule (MT) | Description |
| --- | --- | --- | --- |
| daily-digest | `0 8 * * *` | 08:00 daily | Assemble and send daily digest emails. |
| weekly-digest | `0 8 * * 1` | 08:00 Monday | Assemble and send weekly digest emails. |
| email-retry | `*/5 * * * *` | Every 5 minutes | Find pending retries and attempt resend. |
| wednesday-batch-reminder | `0 18 * * 3` | 18:00 Wednesday | Check flagged claims and send batch review reminders. |

Each job: logs start, executes in try/catch, logs success/error, never crashes the application on handler throw.

## 10.2 Wednesday Batch Reminder

The Wednesday batch reminder is part of the Thursday submission sequence. For each physician with `batch_review_reminder` preference enabled:

1. Query Domain 4 (Claim Lifecycle) for the count of flagged claims for this physician.
2. If flagged count > 0, emit a `BATCH_REVIEW_REMINDER` event via `processEvent`.
3. No claim details in the notification — only the flagged count.
4. Condition checked at execution time, not scheduling time. If the physician reviewed all flagged claims before Wednesday evening, the reminder is suppressed.

## 10.3 Job Resilience

Each scheduled job is wrapped in a try/catch handler that logs errors without crashing the application. The database-backed approach (digest queue, delivery log) ensures resilience: if the server restarts, the next job execution picks up any pending items.

# 11. WebSocket Real-Time Delivery

## 11.1 Connection Management

WebSocket connections are managed by the `NotificationWebSocketManager` singleton class. It provides:

- **Per-user connection tracking:** Multiple concurrent connections supported (multiple browser tabs). Connections stored in a `Map<userId, Set<WebSocket>>`.
- **Heartbeat mechanism:** Ping sent every 30 seconds. If no pong response within 10 seconds, connection is closed with code 1001 ("Heartbeat timeout").
- **Graceful shutdown:** `shutdown()` method closes all connections with code 1001 ("Server shutting down").
- **User disconnection:** `disconnectUser()` closes all connections for a specific user with code 4001 ("Session expired"). Used on session expiry.

## 11.2 WebSocket Route

**Endpoint:** `GET /ws/notifications` (WebSocket upgrade)

**Authentication:** Extracts session token from the `session` cookie (or `?token=` query parameter as fallback). The token is hashed with SHA-256 and validated via the IAM domain's `validateSession` function. Invalid or missing sessions are rejected with close code 4001.

## 11.3 WebSocket Message Types

**Notification push (server → client):**
```json
{
  "type": "notification",
  "data": {
    "notification_id": "uuid",
    "title": "string",
    "body": "string",
    "priority": "HIGH",
    "action_url": "/claims/uuid",
    "event_type": "CLAIM_REJECTED",
    "metadata": {},
    "created_at": "2026-02-13T14:30:00.000Z"
  }
}
```

**Unread count update (server → client):**
```json
{
  "type": "unread_count",
  "data": { "count": 5 }
}
```

Unread count updates are pushed after mark-read and mark-all-read operations (fire-and-forget).

## 11.4 Security

- WebSocket connections require valid session token (cookie or query parameter).
- Disconnected on session expiry (close code 4001).
- All payloads contain rendered content only — no raw database fields or PII beyond what was rendered by the template.
- Connection cleanup on close/error events to prevent memory leaks.

# 12. Delegate Notification Routing

## 12.1 Permission-Based Filtering

When an event is emitted for a physician, the Notification Service:

1. Looks up the event type in `PERMISSION_EVENT_MAP` to find the required permission.
2. Queries the delegate linkage repository for all active delegates linked to the physician.
3. For each active delegate, checks if their permissions include the required permission.
4. If yes, creates a notification for the delegate with `physician_context_id` set to the physician's user ID and `isDelegate = true`.

Events not in the permission map are delivered only to the physician (no delegate copy).

## 12.2 Delegate Access Restrictions

Delegates cannot:
- Access notification preferences (GET returns 403)
- Modify notification preferences (PUT returns 403)
- Update quiet hours (PUT returns 403)

All delegate preference requests are rejected with a `ForbiddenError` at the handler layer.

# 13. User Stories & Acceptance Criteria

| ID | Story | Acceptance Criteria |
| --- | --- | --- |
| NTF-001 | As a physician, I want to see unread notifications in-app | Bell icon shows unread count (updated in real time via WebSocket). Click opens notification feed. Reverse chronological. Mark as read on click or explicit action. Mark all as read available. Paginated (20 per page). |
| NTF-002 | As a physician, I want email alerts for important events | Rejection, deadline, batch failure, breach, IMA amendment trigger email. No PHI in email body. Link to authenticated page. Unsubscribe per category (where allowed). |
| NTF-003 | As a physician, I want to configure which notifications I receive by email | Settings page: per-category email toggle. URGENT in-app cannot be disabled. Quiet hours configurable with HH:MM format. Digest mode configurable (IMMEDIATE, DAILY_DIGEST, WEEKLY_DIGEST). |
| NTF-004 | As a physician, I want low-priority notifications batched into a daily digest | LOW priority events accumulated in digest queue. Single daily email at 08:00 MT. Summary with counts by category. No PHI in digest. |
| NTF-005 | As a physician, I want the Wednesday batch review reminder | If `batch_review_reminder` enabled and flagged claims exist (checked at execution time): notification Wednesday 18:00 MT. Shows flagged claim count only. |
| NTF-006 | As a physician, I want to click a notification and go to the relevant page | Rejection notification → claim detail. Batch notification → batch view. Report notification → download page. Action URL and label rendered from template. |
| NTF-007 | As a delegate, I want notifications for the physicians I serve | Delegate receives notifications filtered by their permissions (PERMISSION_EVENT_MAP). Physician context ID shown per notification. Cannot access or modify preferences. |
| NTF-008 | As a physician, I want to set quiet hours so I'm not emailed at night | Configure start/end time in HH:MM format. Non-urgent emails deferred until quiet hours end. URGENT emails sent regardless. In-app notifications unaffected. Both start and end must be set together (or both null to clear). |
| NTF-009 | As a physician, I want to dismiss a notification without deleting it | Dismiss hides notification from feed but retains it in the database for audit. Dismissed notifications excluded from feed queries but not from admin/audit queries. |
| NTF-010 | As a physician, I want breach and IMA amendment notifications delivered to both my email addresses | Breach and IMA amendment events delivered to primary email and secondary email (if configured). Ensures regulatory notifications reach the physician even if primary email is inaccessible. |
| NTF-011 | As a physician, I want to be notified when my data export window opens and closes | Export window lifecycle events (started, reminder, closing, closed) delivered as HIGH/URGENT priority. Cannot be silenced for URGENT events. |
| NTF-012 | As a physician, I want payment failure escalation notifications | Escalating sequence: PAYMENT_FAILED (URGENT), repeated at intervals until resolved. PAYMENT_RECOVERED when payment succeeds. ACCOUNT_SUSPENDED if unresolved. ACCOUNT_REACTIVATED on recovery. Cannot be silenced. |
| NTF-013 | As a physician, I want real-time notifications without page refresh | WebSocket connection at /ws/notifications. New notifications and unread count updates pushed immediately. Supports multiple tabs. Heartbeat keeps connection alive. |
| NTF-014 | As a physician, I want a weekly digest summarising my notifications | Weekly digest email sent Monday 08:00 MT. Groups notifications by category with counts. No PHI. Link to full notification centre. |

# 14. API Contracts

## 14.1 Notification Feed (User-Facing, Session Auth)

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/notifications | Get notification feed. Query params: `unread_only` (boolean string), `limit` (1–100, default 20), `offset` (min 0, default 0). Ordered by `created_at DESC`. Excludes dismissed notifications. Response: `{ data: { notifications: [...], total: number } }` |
| GET | /api/v1/notifications/unread-count | Get unread notification count. Lightweight call for badge update. Response: `{ data: { count: number } }` |
| POST | /api/v1/notifications/:id/read | Mark notification as read. Requires UUID `:id` param. Returns 404 if not found or not owned by recipient. Pushes updated unread count via WebSocket. Response: `{ data: { success: true } }` |
| POST | /api/v1/notifications/read-all | Mark all notifications as read for the authenticated user. Pushes updated unread count via WebSocket. Response: `{ data: { success: true, count: number } }` |
| POST | /api/v1/notifications/:id/dismiss | Dismiss notification (hide from feed, retain for audit). Requires UUID `:id` param. Returns 404 if not found or not owned by recipient. Response: `{ data: { success: true } }` |

## 14.2 Preferences (User-Facing, Session Auth, Physician Only)

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/notification-preferences | Get all preferences for the authenticated physician. Returns merged defaults from EVENT_CATALOGUE with stored overrides. Includes quiet hours. Delegates receive 403. Response: `{ data: { preferences: [...], quiet_hours: { start, end } } }` |
| PUT | /api/v1/notification-preferences/:category | Update preferences for a specific event category. Body: `{ in_app_enabled?, email_enabled?, digest_mode? }`. Validates category exists in EVENT_CATALOGUE. Rejects disabling in_app for URGENT categories. Delegates receive 403. Old and new values recorded in audit log. |
| PUT | /api/v1/notification-preferences/quiet-hours | Set quiet hours (start/end time in HH:MM format, or both null to clear). Both must be set together. Delegates receive 403. Old and new values recorded in audit log. |

## 14.3 Internal Event Ingestion (API Key Auth)

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | /api/v1/internal/notifications/emit | Emit a single event. Body: `{ event_type: string, physician_id: UUID, metadata?: object }`. Protected by `X-Internal-API-Key` header (constant-time comparison). Returns: `{ data: { notification_ids: string[] } }` |
| POST | /api/v1/internal/notifications/emit-batch | Emit multiple events at once. Body: `{ events: [{ event_type, physician_id, metadata? }] }` (1–500 events). Protected by `X-Internal-API-Key` header. Returns: `{ data: { created_count: number } }` |

## 14.4 Postmark Webhook

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | /api/v1/webhooks/postmark | Handle delivery/bounce callbacks from Postmark. Authenticated via `X-Postmark-Signature` header (HMAC-SHA256). Processes Delivery (updates status to DELIVERED) and Bounce (hard: BOUNCED + in-app alert, soft: retry) record types. Returns `{ ok: true }`. |

## 14.5 WebSocket

| Method | Endpoint | Description |
| --- | --- | --- |
| WS | /ws/notifications | WebSocket endpoint for real-time notification push. Auth via `session` cookie or `?token=` query parameter. Pushes `notification` and `unread_count` message types. Close code 4001 for auth failure. |

# 15. Interface Contracts with Other Domains

## 15.1 Event Contract

All domains emit events to the Notification Service using a standard event envelope via the internal emit endpoint:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| event_type | STRING | Yes | Event identifier matching the EVENT_CATALOGUE (e.g., 'CLAIM_REJECTED', 'BREACH_INITIAL_NOTIFICATION'). Max 50 characters. |
| physician_id | UUID | Yes | Which physician this event pertains to. Used for recipient resolution and delegate routing. |
| metadata | OBJECT | No | Structured data for template rendering (claim counts, dollar amounts, etc.). |

## 15.2 Claim Lifecycle Interface (Domain 4)

The Claim Lifecycle domain is the heaviest producer of notification events. Key interactions:

- Claim Lifecycle manages the Thursday batch execution logic (which claims to submit, which to hold).
- After batch execution, Claim Lifecycle emits `BATCH_SUBMITTED` with results. Notification Service generates the post-submission confirmation.
- Claim Lifecycle emits `CLAIM_REJECTED`, `DEADLINE_*`, and `DUPLICATE_DETECTED` events. Notification Service delivers per catalogue priority.
- The Wednesday batch reminder queries Claim Lifecycle via `ClaimRepo.countFlaggedClaims()` for flagged claim counts.

## 15.3 Identity & Access Interface (Domain 1)

- Session validation for WebSocket authentication (via `WsSessionValidator.validateSession()`).
- Token hashing function for session cookie processing.
- User email lookup (primary) via `UserEmailLookup.getEmailByUserId()`.
- Secondary email lookup via `SecondaryEmailLookup.getSecondaryEmail()` (for dual-delivery of breach/IMA events).
- Delegate linkage repository via `DelegateLinkageRepo.listDelegatesForPhysician()` for delegate notification routing.

## 15.4 Platform Operations Interface (Domain 12)

Platform Operations emits events for:
- Payment failure/recovery escalation sequences
- Account suspension/reactivation
- Scheduled maintenance announcements
- IMA amendment lifecycle (notice, reminder, deadline)
- Breach notification lifecycle (initial, update)
- Export window lifecycle (started, reminder, closing, closed)
- Data destruction confirmation

# 16. Security & Audit

## 16.1 PHI Protection

- **No PHI in email:** Email notifications contain event summaries and links. Patient names, PHNs, and claim details are never in email bodies. The physician clicks through to the authenticated app to see details.
- **No PHI in digest emails:** Digest emails contain only category names and counts with a link to the notification centre.
- **In-app PHI minimisation:** In-app notifications may reference claim-level data (HSC codes, dates, amounts) because the user is already authenticated. However, patient-identifying information (name, PHN) should be minimised. Use "Claim for [date of service]" rather than "Claim for John Smith."
- **Template injection prevention:** All template variable values are HTML-escaped before rendering. No raw HTML injection from event metadata.
- **Email provider isolation:** Postmark (external service) never receives PHI. Only notification metadata (counts, amounts, category labels) flows to the email provider.

## 16.2 Authentication & Access Control

- **User-facing endpoints:** Protected by session authentication (`app.authenticate` preHandler).
- **Internal emit endpoints:** Protected by `X-Internal-API-Key` header with constant-time comparison. Not exposed externally.
- **Postmark webhook endpoint:** Authenticated via `X-Postmark-Signature` header (HMAC-SHA256, constant-time comparison).
- **WebSocket:** Session token validated on connection upgrade. Invalid sessions rejected with close code 4001. Connections terminated on session expiry.
- **Notification scoping:** Recipients can only access their own notifications. All queries filter by `recipient_id`.
- **Delegate restrictions:** Delegates cannot access or modify notification preferences (403 Forbidden).

## 16.3 Audit Events

| Action | Detail Logged |
| --- | --- |
| notification.event_emitted | Event type, recipient count, physician ID |
| notification.read | Notification ID, user ID |
| notification.read_all | User ID, count of notifications marked read |
| notification.dismissed | Notification ID, user ID |
| notification.email_sent | Delivery ID, notification ID, recipient email |
| notification.email_bounced | Delivery ID, notification ID, bounce type (hard/soft), reason |
| notification.email_failed | Delivery ID, notification ID, recipient email, reason |
| notification.preference_updated | User ID, event category, old values, new values |
| notification.quiet_hours_updated | User ID, old quiet hours, new quiet hours |
| notification.digest_assembled | Digest type, recipient count, item count |

All audit log entries are append-only. There are no PUT or DELETE endpoints for audit logs.

# 17. Testing Requirements

## 17.1 Event Processing Tests

- Each event type in the catalogue → correct template rendered, correct recipients resolved
- CLAIM_REJECTED event → in-app notification created + email queued (if enabled)
- LOW priority event with digest mode → queued for digest, not sent immediately
- URGENT event during quiet hours → email sent regardless of quiet hours
- Delegate with CLAIM_VIEW permission → receives claim notifications. Without → does not.
- Event not in PERMISSION_EVENT_MAP → physician only, no delegate copy
- Dual-delivery event (BREACH_INITIAL_NOTIFICATION) → delivery log created for both primary and secondary email
- Batch emit → all events processed, correct total notification count returned

## 17.2 Delivery Tests

- Email delivery success → status = SENT in log, provider_message_id recorded
- Email soft bounce → retry per schedule, eventual delivery or FAILED after max retries
- Email hard bounce → no retry, status = BOUNCED, in-app bounce alert created
- Postmark webhook delivery confirmation → status updated to DELIVERED with delivered_at
- Postmark webhook bounce → appropriate handling based on TypeCode
- Postmark webhook missing/invalid signature → 401 rejected
- Email provider outage → emails queued, delivered when provider recovers
- WebSocket connected → notification pushed in real-time
- WebSocket disconnected → notification stored, available on next page load
- WebSocket heartbeat timeout → stale connection cleaned up

## 17.3 Preference Tests

- Email disabled for category → no email sent, in-app still delivered
- Quiet hours active, non-urgent event → email deferred until quiet hours end
- Quiet hours active, URGENT event → email sent immediately
- Overnight quiet hours range (22:00–07:00) → correctly identifies times within range
- Daily digest: 5 LOW events in 24 hours → single digest email with all 5
- Weekly digest: items accumulated over 7 days → single Monday email
- URGENT in-app cannot be disabled → validation error on attempt
- Unknown event category → validation error on preference update
- Delegate attempts to access preferences → 403 Forbidden

## 17.4 Thursday Sequence Tests

- Wednesday reminder sent if flagged claims exist and reminder enabled (checked at execution time)
- Wednesday reminder not sent if no flagged claims or reminder disabled
- Wednesday reminder not sent if physician reviewed all claims before Wednesday evening
- Thursday cutoff → batch submitted → Friday assessment → correct notification sequence
- Batch error → URGENT notification with manual intervention instructions

## 17.5 Integration Tests

- End-to-end: create claim → validate → reject → notification appears in feed and email queued
- Scheduled report generated (Domain 8) → REPORT_READY notification with download link
- Payment failure (Platform Ops) → URGENT notification to physician
- IMA amendment published → IMA_AMENDMENT_NOTICE notification with dual-delivery
- Breach detected → BREACH_INITIAL_NOTIFICATION with URGENT priority and dual-delivery
- Export window opened → EXPORT_WINDOW_STARTED notification
- Internal API key missing → 401 rejected
- Internal API key tampered → 401 rejected

## 17.6 Performance Tests

- Monday batch summary for 250 physicians: all notifications created and emails queued within 60 seconds
- Unread count endpoint: <50ms response time (called on every page load)
- Notification centre pagination: <200ms for 20 results
- Email provider API rate limiting: graceful handling if provider rate-limits outbound emails
- WebSocket: support 500+ concurrent connections without degradation

## 17.7 Security Tests

Per the mandatory security testing framework in CLAUDE.md:

- **authn.security.ts:** 401 test for every user-facing route (GET /notifications, GET /unread-count, POST /:id/read, POST /read-all, POST /:id/dismiss, GET /preferences, PUT /preferences/:category, PUT /preferences/quiet-hours). Internal API key tests for emit endpoints. Webhook signature tests for Postmark endpoint.
- **authz.security.ts:** Delegate cannot access preferences (403). Delegate receives only permission-filtered notifications.
- **scoping.security.ts:** Physician A cannot see Physician B's notifications. Mark-read only works on own notifications (404 for others). Dismiss only works on own notifications (404 for others).
- **input.security.ts:** SQL injection payloads in metadata fields. XSS payloads in event_type. UUID validation on notification ID params. Type coercion on query parameters.
- **leakage.security.ts:** Error responses do not echo notification content. 404 responses are generic. No server version headers. Template variables are HTML-escaped.
- **audit.security.ts:** Preference changes produce audit records. Read/dismiss actions produce audit records. Event emissions produce audit records. Email delivery status changes produce audit records.

# 18. Document Control

This domain is a cross-cutting infrastructure service consumed by all other domains. It does not generate business logic — it delivers messages triggered by events from source domains.

| Item | Value |
| --- | --- |
| Parent document | Meritum PRD v1.3 |
| Domain | Notification Service (Domain 9 of 13) |
| Build sequence position | 7th (after Provider Management and Patient Registry; before Claim Lifecycle) |
| Dependencies | Domain 1 (IAM for user email, sessions, and delegate relationships), Domain 5 (Provider Management for delegate permissions) |
| Consumed by | All domains (emit events). Domain 8 (report delivery). Domain 12 (IMA compliance delivery). |
| Supersedes | Domain 3 FRD (Notification Service v1.0) and Domain 9 FRD (Notification Service v1.0) — consolidated into this document. |
| Implementation module | `apps/api/src/domains/notification/` |
| Version | 2.0 |
| Date | February 2026 |

| Version | Date | Author | Changes |
| --- | --- | --- | --- |
| 1.0 | February 12, 2026 | Ian Sharland | Initial Notification Service functional requirements |
| 2.0 | February 27, 2026 | Claude (automated) | Consolidated Domain 3 and Domain 9 FRDs. Updated to reflect implementation: Postmark integration, WebSocket real-time delivery, delegate permission-based routing, IMA compliance events (12 new event types), dual-delivery for breach/IMA events, secondary email support, Drizzle DB schema, Zod validation schemas, scheduled job registration, quiet hours in Mountain Time. Updated API contracts, data model, and security requirements to match implementation. |
