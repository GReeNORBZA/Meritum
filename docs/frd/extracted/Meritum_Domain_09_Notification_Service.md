# Meritum_Domain_09_Notification_Service

MERITUM

Functional Requirements

Notification Service

Domain 9 of 13  |  Cross-Cutting Service

Meritum Health Technologies Inc.

Version 1.0  |  February 2026

CONFIDENTIAL

# Table of Contents

# 1. Domain Overview

## 1.1 Purpose

The Notification Service is a cross-cutting infrastructure domain that delivers timely, relevant messages to physicians and delegates across the platform. It is the communication backbone — every domain emits events and the Notification Service translates them into in-app notifications, email alerts, and (future) push notifications.

This domain does not generate business logic or make decisions. It receives events from other domains, applies the physician's notification preferences, renders messages from templates, and delivers them through the configured channels. It is the last mile between a platform event and the physician's attention.

## 1.2 Scope

In-app notification centre: persistent notification feed within the Meritum UI

Email notifications: transactional emails triggered by platform events

Event ingestion: consume events from all domains via internal event bus

Notification preferences: per-physician channel and frequency configuration

Template management: notification message templates with variable substitution

Delivery tracking: delivery status, read receipts (in-app), bounce handling (email)

Retry logic: automatic retry for failed email delivery

Batching and digest: aggregate low-priority notifications into periodic digests

Quiet hours: suppress non-urgent notifications during configured hours

Architecture for push notifications (Phase 2, when native mobile apps ship)

## 1.3 Out of Scope

Business logic that determines when events fire (owned by source domains)

Report generation (Domain 8; Notification Service only delivers the download link)

SMS notifications (deferred; physician communication via email and in-app at MVP)

Marketing or promotional messaging (Meritum is ad-free; notifications are operational only)

## 1.4 Domain Dependencies

# 2. Notification Channels

## 2.1 In-App Notifications

The primary notification channel. A persistent notification centre in the Meritum UI accessible via a bell icon in the header. Notifications are stored server-side and synced to the client.

Unread badge: Count of unread notifications displayed on the bell icon.

Notification feed: Reverse-chronological list. Each notification shows: icon (category), title, body preview, timestamp, read/unread status.

Actions: Mark as read, mark all as read, dismiss (hides but retains for audit), click to navigate to relevant page (e.g., click rejection notification → navigate to rejected claim).

Real-time delivery: New notifications pushed to the client via WebSocket. No page refresh required.

Persistence: Notifications retained for 90 days. Older notifications archived (accessible via 'View all').

## 2.2 Email Notifications

Secondary channel for time-sensitive or important events. Email notifications are sent in addition to (not instead of) in-app notifications. The physician can disable email for specific event categories.

Sender: notifications@meritum.ca (transactional, not marketing)

Format: HTML email with plain-text fallback. Meritum branding. No PHI in email body (links to authenticated pages instead).

Unsubscribe: Per-category unsubscribe link in footer. Global email disable in preferences.

Provider: Transactional email service (e.g., Postmark, AWS SES). Selected for deliverability and Canadian data processing options.

## 2.3 Push Notifications (Phase 2)

When native mobile apps ship (Phase 2), push notifications will be added as a third channel. Architecture accommodations:

Notification records include a push_payload field (nullable) for device-specific push data.

Channel routing logic supports IN_APP, EMAIL, PUSH as independent toggles.

Push notification provider integration point defined but not implemented at MVP.

# 3. Event Catalogue

Every notification originates from a domain event. This catalogue defines all events the Notification Service consumes, their source domain, default channels, and priority.

## 3.1 Claim Lifecycle Events (Domain 4)

## 3.2 Intelligence Engine Events (Domain 7)

## 3.3 Provider Management Events (Domain 5)

## 3.4 Platform Operations Events

## 3.5 Analytics Events (Domain 8)

## 3.6 Thursday Submission Sequence

The Thursday batch cycle generates a coordinated sequence of notifications:

# 4. Notification Preferences

## 4.1 Preference Model

Each physician configures their notification preferences per event category and per channel. Preferences are stored per-physician and apply to all events of that category.

## 4.2 Default Preferences

On registration, physicians receive default preferences:

URGENT events: In-app always on (cannot disable). Email on.

HIGH events: In-app on. Email on.

MEDIUM events: In-app on. Email on.

LOW events: In-app on. Email off. Digest mode: DAILY_DIGEST.

Quiet hours: Not set (no suppression by default).

Physicians can customise all settings except: URGENT in-app cannot be disabled (safety-critical events like account suspension and batch failure must always be visible).

## 4.3 Delegate Notifications

Delegates receive notifications for the physician context they serve, filtered by their permissions. A delegate with CLAIM_VIEW permission receives claim assessment notifications. A delegate without REPORT_VIEW does not receive report-ready notifications. Delegate notification routing uses the permission matrix from Domain 5.

When a delegate serves multiple physicians, they receive notifications from each physician's context separately. The notification centre shows the physician's name for each notification.

# 5. Data Model

## 5.1 Notifications Table (notifications)

Indexes: (recipient_id, read_at) for unread count, (recipient_id, created_at DESC) for feed, (event_type, created_at) for analytics.

Retention: 90 days in primary table. Archived to cold storage after 90 days. Available via 'View all' for up to 1 year.

## 5.2 Email Delivery Log Table (email_delivery_log)

## 5.3 Notification Templates Table (notification_templates)

Templates are managed by the development team, not physicians. Variable substitution uses a simple {{variable_name}} syntax. Variables are validated against the template's declared variables list before rendering.

## 5.4 Digest Queue Table (digest_queue)

Holds notifications waiting for digest assembly. Low-priority events with digest_mode = DAILY_DIGEST or WEEKLY_DIGEST accumulate here until the digest job runs.

# 6. Event Processing Pipeline

## 6.1 Pipeline Steps

**Event received:** Source domain emits an event on the internal event bus. Event includes: event_type, source_domain, physician_id, metadata (claim_id, batch_id, etc.).

**Recipient resolution:** Determine who should receive this notification. Primary: the physician. Secondary: active delegates with relevant permissions.

**Preference check:** Look up recipient's notification preferences for this event category. Determine channels (in-app, email) and digest mode.

**Template rendering:** Load template for event_type. Substitute variables from event metadata. Render in-app title/body and email subject/body.

**Notification creation:** Create notification record in the notifications table with rendered content.

**In-app delivery:** Push notification to recipient's WebSocket connection (if connected). Always stored in notification table regardless of connection status.

**Email routing:** If email enabled for this event/recipient: check quiet hours. If within quiet hours, defer until quiet hours end. If digest mode, add to digest queue. If immediate mode, send email.

**Delivery tracking:** Record delivery status in email_delivery_log. Update notification.channels_delivered.

## 6.2 Retry Logic

Email delivery failures are retried automatically:

Retry schedule: Attempt 1 immediately, Attempt 2 at +5 minutes, Attempt 3 at +30 minutes, Attempt 4 at +2 hours. After 4 failures, status = FAILED.

Hard bounces (invalid email address): No retry. Status = BOUNCED. Physician notified in-app to update email.

Soft bounces (mailbox full, server temporarily unavailable): Retry per schedule.

Provider outage: If email provider is down, queue emails and retry when provider recovers. In-app delivery unaffected.

## 6.3 Digest Assembly

Digest jobs run on schedule:

Daily digest: Runs at 08:00 MT. Assembles all queued notifications from the past 24 hours into a single summary email.

Weekly digest: Runs Monday at 08:00 MT. Assembles past 7 days.

Digest emails use a summary template that groups notifications by category and shows counts. Individual notification details are available in-app.

# 7. User Stories & Acceptance Criteria

# 8. API Contracts

## 8.1 Notification Feed

## 8.2 Preferences

## 8.3 Internal Event Ingestion

# 9. Security & Audit

No PHI in email: Email notifications contain event summaries and links. Patient names, PHNs, and claim details are never in email bodies. The physician clicks through to the authenticated app to see details.

Email sender authentication: SPF, DKIM, and DMARC configured for meritum.ca to prevent spoofing.

WebSocket authentication: WebSocket connections require valid session token. Disconnected on session expiry.

Notification scoping: Notifications are recipient-scoped. A recipient can only access their own notifications.

Template injection prevention: Template variables are escaped before rendering. No raw HTML injection from event metadata.

Delivery audit: All email sends logged with status. Bounce events tracked. Failed deliveries trigger in-app notification to update email address.

# 10. Testing Requirements

## 10.1 Event Processing Tests

Each event type in the catalogue → correct template rendered, correct recipients resolved

CLAIM_REJECTED event → in-app notification created + email sent (if enabled)

LOW priority event with digest mode → queued for digest, not sent immediately

URGENT event during quiet hours → email sent regardless of quiet hours

Delegate with CLAIM_VIEW permission → receives claim notifications. Without → does not.

## 10.2 Delivery Tests

Email delivery success → status = DELIVERED in log

Email soft bounce → retry per schedule, eventual delivery

Email hard bounce → no retry, in-app notification to update email

Email provider outage → emails queued, delivered when provider recovers

WebSocket connected → notification pushed in real-time

WebSocket disconnected → notification stored, available on next page load

## 10.3 Preference Tests

Email disabled for category → no email sent, in-app still delivered

Quiet hours active, non-urgent event → email deferred until quiet hours end

Quiet hours active, URGENT event → email sent immediately

Daily digest: 5 LOW events in 24 hours → single digest email with all 5

## 10.4 Thursday Sequence Tests

Wednesday reminder sent if flagged claims exist and reminder enabled

Wednesday reminder not sent if no flagged claims or reminder disabled

Thursday cutoff → batch submitted → Friday assessment → correct notification sequence

Batch error → URGENT notification with manual intervention instructions

## 10.5 Integration Tests

End-to-end: create claim → validate → reject → notification appears in UI and email delivered

Scheduled report generated (Domain 8) → REPORT_READY notification with download link

Payment failure (Platform Ops) → URGENT notification to physician

# 11. Open Questions

# 12. Document Control

This domain is a cross-cutting infrastructure service consumed by all other domains. It does not generate business logic — it delivers messages triggered by events from source domains.

| Domain | Direction | Interface |
| --- | --- | --- |
| All domains | Events received | Every domain emits events that the Notification Service consumes. Event catalogue in Section 3. |
| 1 Identity & Access | Consumed | User email addresses, notification preferences, delegate relationships (for routing). |
| 5 Provider Management | Consumed | Physician name (for email personalisation), delegate relationships (for delegate notifications). |
| 8 Analytics | Events received | Scheduled report generation complete events. |

| Event | In-App | Email | Priority | Description |
| --- | --- | --- | --- | --- |
| CLAIM_VALIDATED | Yes | No | LOW | Claim passed validation. Informational. |
| CLAIM_FLAGGED | Yes | No | MEDIUM | Claim classified as flagged. Review needed. |
| DEADLINE_7_DAY | Yes | Yes | MEDIUM | Claim within 7 days of submission deadline. |
| DEADLINE_3_DAY | Yes | Yes | HIGH | Claim within 3 days of deadline. |
| DEADLINE_1_DAY | Yes | Yes | URGENT | Claim within 1 day of deadline. |
| DEADLINE_EXPIRED | Yes | Yes | HIGH | Claim passed deadline. Revenue lost. |
| BATCH_ASSEMBLED | Yes | No | LOW | Batch generation complete. Ready for transmission. |
| BATCH_SUBMITTED | Yes | Yes | MEDIUM | Batch transmitted to AHCIP or uploaded to WCB. |
| BATCH_ERROR | Yes | Yes | URGENT | Batch transmission failed. Manual intervention required. |
| CLAIM_ASSESSED | Yes | No | LOW | Payer accepted claim. |
| CLAIM_REJECTED | Yes | Yes | HIGH | Payer rejected claim. Corrective action needed. |
| CLAIM_PAID | Yes | No | LOW | Payment confirmed. |
| DUPLICATE_DETECTED | Yes | No | MEDIUM | Potential duplicate claim identified. |

| Event | In-App | Email | Priority | Description |
| --- | --- | --- | --- | --- |
| AI_SUGGESTION_READY | Yes | No | LOW | AI Coach suggestions available for review on a claim. |
| AI_HIGH_VALUE_SUGGESTION | Yes | Yes | HIGH | AI Coach identified a suggestion with revenue impact > $50. |
| SOMB_CHANGE_IMPACT | Yes | Yes | MEDIUM | SOMB update affects codes the physician frequently uses. |

| Event | In-App | Email | Priority | Description |
| --- | --- | --- | --- | --- |
| DELEGATE_INVITED | Yes | Yes | MEDIUM | Invitation sent to delegate (email to delegate, in-app to physician). |
| DELEGATE_ACCEPTED | Yes | Yes | MEDIUM | Delegate accepted invitation. |
| DELEGATE_REVOKED | Yes | Yes | HIGH | Delegate access revoked (notification to delegate). |
| BA_STATUS_CHANGED | Yes | Yes | HIGH | BA status changed (PENDING → ACTIVE, or ACTIVE → INACTIVE). |
| RRNP_RATE_CHANGED | Yes | Yes | MEDIUM | Quarterly RRNP rate update for physician's community. |

| Event | In-App | Email | Priority | Description |
| --- | --- | --- | --- | --- |
| PAYMENT_FAILED | Yes | Yes | URGENT | Subscription payment failed. Dunning sequence starts. |
| PAYMENT_RECOVERED | Yes | Yes | HIGH | Payment recovered after failure. |
| ACCOUNT_SUSPENDED | Yes | Yes | URGENT | Account suspended due to non-payment. |
| ACCOUNT_REACTIVATED | Yes | Yes | HIGH | Account reactivated after payment. |
| MAINTENANCE_SCHEDULED | Yes | Yes | MEDIUM | Planned maintenance window. |

| Event | In-App | Email | Priority | Description |
| --- | --- | --- | --- | --- |
| REPORT_READY | Yes | Yes | MEDIUM | Scheduled or on-demand report generated and ready for download. |
| DATA_EXPORT_READY | Yes | Yes | MEDIUM | Data portability export ready for download. |

| Timing | Notification |
| --- | --- |
| Wednesday evening | Batch review reminder: 'You have X flagged claims awaiting review before tomorrow’s cutoff.' (if batch_review_reminder = true) |
| Thursday 12:00 MT | Cutoff confirmation: 'Thursday batch cutoff reached. X claims in your queue.' |
| Thursday ~14:00 MT | Batch submitted: 'Your Thursday batch (X claims, $Y total) has been transmitted to AHCIP.' |
| Thursday evening | WCB batch ready: 'Your WCB batch (X claims) is ready for download and upload to myWCB.' (if applicable) |
| Friday | Assessment received: 'Assessment results for your [date] batch are available. X accepted, Y rejected.' |
| Friday | Payment confirmed: 'Payment of $X deposited for your [date] batch.' |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| preference_id | UUID | No | Primary key |
| provider_id | UUID FK | No | FK to providers |
| event_category | VARCHAR(50) | No | Event category (e.g., 'claim_rejection', 'deadline_approaching', 'batch_submission') |
| in_app_enabled | BOOLEAN | No | Whether in-app notifications are enabled for this category. Default: true. Cannot be disabled for URGENT events. |
| email_enabled | BOOLEAN | No | Whether email notifications are enabled. Default per event catalogue. |
| digest_mode | VARCHAR(20) | No | IMMEDIATE, DAILY_DIGEST, WEEKLY_DIGEST. IMMEDIATE = send as they occur. Digest = batch into summary. Default: IMMEDIATE for HIGH/URGENT, DAILY_DIGEST for LOW. |
| quiet_hours_start | TIME | Yes | Start of quiet hours (email suppressed). Global setting, not per-category. |
| quiet_hours_end | TIME | Yes | End of quiet hours. |
| updated_at | TIMESTAMPTZ | No |  |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| notification_id | UUID | No | Primary key |
| recipient_id | UUID FK | No | FK to users (physician or delegate) |
| physician_context_id | UUID FK | Yes | FK to providers. For delegate notifications: which physician context. Null for system-wide notifications. |
| event_type | VARCHAR(50) | No | Event type from catalogue (e.g., 'CLAIM_REJECTED') |
| priority | VARCHAR(10) | No | URGENT, HIGH, MEDIUM, LOW |
| title | VARCHAR(200) | No | Notification title (rendered from template) |
| body | TEXT | No | Notification body (rendered from template) |
| action_url | VARCHAR(500) | Yes | URL to navigate when notification clicked (e.g., '/claims/{id}') |
| action_label | VARCHAR(50) | Yes | Button label (e.g., 'View Claim', 'Review Batch') |
| metadata | JSONB | Yes | Event-specific data: claim_id, batch_id, report_id, etc. For UI rendering. |
| channels_delivered | JSONB | No | Which channels this notification was delivered to: {in_app: true, email: true, push: false} |
| read_at | TIMESTAMPTZ | Yes | When the notification was read in-app. Null if unread. |
| dismissed_at | TIMESTAMPTZ | Yes | When dismissed. Hidden from feed but retained. |
| created_at | TIMESTAMPTZ | No |  |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| delivery_id | UUID | No | Primary key |
| notification_id | UUID FK | No | FK to notifications |
| recipient_email | VARCHAR(100) | No | Email address sent to |
| template_id | VARCHAR(50) | No | Email template used |
| status | VARCHAR(20) | No | QUEUED, SENT, DELIVERED, BOUNCED, FAILED |
| provider_message_id | VARCHAR(100) | Yes | Email provider's message ID for tracking |
| sent_at | TIMESTAMPTZ | Yes | When email was sent |
| delivered_at | TIMESTAMPTZ | Yes | When delivery was confirmed |
| bounced_at | TIMESTAMPTZ | Yes | When bounce was detected |
| bounce_reason | TEXT | Yes | Bounce reason from provider |
| retry_count | INTEGER | No | Number of retry attempts. Default: 0. |
| next_retry_at | TIMESTAMPTZ | Yes | When next retry is scheduled (if failed/bounced) |
| created_at | TIMESTAMPTZ | No |  |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| template_id | VARCHAR(50) | No | Primary key. Matches event_type (e.g., 'CLAIM_REJECTED'). |
| in_app_title | VARCHAR(200) | No | Title template with {{variable}} placeholders |
| in_app_body | TEXT | No | Body template |
| email_subject | VARCHAR(200) | Yes | Email subject template. Null if event never sends email. |
| email_html_body | TEXT | Yes | HTML email body template |
| email_text_body | TEXT | Yes | Plain-text email body fallback |
| action_url_template | VARCHAR(500) | Yes | URL template with {{claim_id}}, {{batch_id}}, etc. |
| action_label | VARCHAR(50) | Yes | Static action button label |
| variables | JSONB | No | Array of variable names expected in the template context |
| updated_at | TIMESTAMPTZ | No |  |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| queue_id | UUID | No | Primary key |
| recipient_id | UUID FK | No | FK to users |
| notification_id | UUID FK | No | FK to notifications (already created with in-app delivery) |
| digest_type | VARCHAR(20) | No | DAILY or WEEKLY |
| digest_sent | BOOLEAN | No | Whether this item has been included in a digest email |
| created_at | TIMESTAMPTZ | No |  |

| ID | Story | Acceptance Criteria |
| --- | --- | --- |
| NTF-001 | As a physician, I want to see unread notifications in-app | Bell icon shows unread count. Click opens notification feed. Reverse chronological. Mark as read on click or explicit action. |
| NTF-002 | As a physician, I want email alerts for important events | Rejection, deadline, batch failure trigger email. No PHI in email body. Link to authenticated page. Unsubscribe per category. |
| NTF-003 | As a physician, I want to configure which notifications I receive by email | Settings page: per-category email toggle. URGENT in-app cannot be disabled. Quiet hours configurable. |
| NTF-004 | As a physician, I want low-priority notifications batched into a daily digest | LOW priority events accumulated. Single daily email at 08:00 MT. Summary with counts by category. |
| NTF-005 | As a physician, I want the Wednesday batch review reminder | If batch_review_reminder = true and flagged claims exist: notification Wednesday evening. Shows flagged claim count. |
| NTF-006 | As a physician, I want to click a notification and go to the relevant page | Rejection notification → claim detail. Batch notification → batch view. Report notification → download page. |
| NTF-007 | As a delegate, I want notifications for the physicians I serve | Delegate receives notifications filtered by their permissions. Physician name shown per notification. Context switching not required to view. |
| NTF-008 | As a physician, I want to set quiet hours so I'm not emailed at night | Configure start/end time. Non-urgent emails deferred until quiet hours end. In-app notifications unaffected. |

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/notifications | Get notification feed. Params: unread_only, limit, offset. Ordered by created_at DESC. |
| GET | /api/v1/notifications/unread-count | Get unread notification count. Lightweight call for badge update. |
| POST | /api/v1/notifications/{id}/read | Mark notification as read. |
| POST | /api/v1/notifications/read-all | Mark all notifications as read. |
| POST | /api/v1/notifications/{id}/dismiss | Dismiss notification (hide from feed, retain for audit). |
| WS | /ws/notifications | WebSocket endpoint for real-time notification push. |

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/notification-preferences | Get all preferences for the physician. |
| PUT | /api/v1/notification-preferences/{category} | Update preferences for a specific event category. |
| PUT | /api/v1/notification-preferences/quiet-hours | Set quiet hours (start/end time). |

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | /api/v1/internal/notifications/emit | Emit an event. Body: event_type, physician_id, metadata. Used by all source domains. Internal only. |
| POST | /api/v1/internal/notifications/emit-batch | Emit multiple events at once (e.g., batch submission generates events for all claims). Internal only. |

| # | Question | Context |
| --- | --- | --- |
| 1 | Which transactional email provider should Meritum use? | Candidates: Postmark (excellent deliverability), AWS SES (cost-effective, Canadian region available), SendGrid. Need to evaluate Canadian data processing compliance. |
| 2 | Should digest emails include brief notification details or just counts? | Counts are simpler but less useful. Brief details risk including sensitive context. MVP: counts with 'View in Meritum' links. |
| 3 | Should notification preferences be managed by delegates, or physician-only? | Currently physician-only. Delegates may want to configure their own notification preferences for the physicians they serve. |
| 4 | What is the right retention period for notifications? | Current: 90 days primary, 1 year archive. May align with claim audit history retention (10 years) for compliance. |

| Item | Value |
| --- | --- |
| Parent document | Meritum PRD v1.3 |
| Domain | Notification Service (Domain 9 of 13) |
| Build sequence position | 3rd (elevated; tiered auto-submission depends on Thursday notification sequence) |
| Dependencies | Domain 1 (IAM for user email and session), Domain 5 (Provider Management for delegate routing) |
| Consumed by | All domains (emit events). Domain 8 (report delivery). |
| Version | 1.0 |
| Date | February 2026 |

