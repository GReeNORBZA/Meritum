import {
  EVENT_CATALOGUE,
  NotificationPriority,
  NotificationAuditAction,
  EMAIL_RETRY_SCHEDULE_MS,
  EMAIL_MAX_RETRY_ATTEMPTS,
  type DigestMode,
} from '@meritum/shared/constants/notification.constants.js';
import type { NotificationRepository } from './notification.repository.js';
import type { SelectNotification, SelectDigestQueueItem } from '@meritum/shared/schemas/db/notification.schema.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface EmitEvent {
  eventType: string;
  physicianId: string;
  metadata?: Record<string, unknown>;
}

export interface Recipient {
  userId: string;
  isDelegate: boolean;
  physicianContextId: string | null;
}

export interface ChannelPreferences {
  inAppEnabled: boolean;
  emailEnabled: boolean;
  digestMode: DigestMode;
}

export interface RenderedContent {
  title: string;
  body: string;
  emailSubject: string | null;
  emailHtmlBody: string | null;
  emailTextBody: string | null;
  actionUrl: string | null;
  actionLabel: string | null;
}

export interface RenderedEmail {
  subject: string;
  htmlBody: string;
  textBody: string;
}

// ---------------------------------------------------------------------------
// Postmark Client interface (abstraction for testability)
// ---------------------------------------------------------------------------

export interface PostmarkSendResult {
  MessageID: string;
}

export interface PostmarkClient {
  sendEmail(options: {
    From: string;
    To: string;
    Subject: string;
    HtmlBody: string;
    TextBody: string;
    MessageStream: string;
  }): Promise<PostmarkSendResult>;
}

// ---------------------------------------------------------------------------
// Delegate Linkage Repository interface (IAM domain dependency)
// ---------------------------------------------------------------------------

export interface DelegateLinkage {
  linkageId: string;
  physicianUserId: string;
  delegateUserId: string;
  permissions: string[];
  isActive: boolean;
}

export interface DelegateLinkageRepo {
  listDelegatesForPhysician(
    physicianUserId: string,
  ): Promise<Array<{ linkage: DelegateLinkage }>>;
}

// ---------------------------------------------------------------------------
// Audit Repository interface
// ---------------------------------------------------------------------------

export interface AuditRepo {
  appendAuditLog(entry: {
    userId?: string | null;
    action: string;
    category: string;
    resourceType?: string | null;
    resourceId?: string | null;
    detail?: Record<string, unknown> | null;
    ipAddress?: string | null;
    userAgent?: string | null;
  }): Promise<unknown>;
}

// ---------------------------------------------------------------------------
// Claim Repository interface (Domain 4 dependency — Wednesday reminder)
// ---------------------------------------------------------------------------

export interface ClaimRepo {
  countFlaggedClaims(providerId: string): Promise<number>;
}

// ---------------------------------------------------------------------------
// User Email Lookup interface
// ---------------------------------------------------------------------------

export interface UserEmailLookup {
  getEmailByUserId(userId: string): Promise<string | null>;
}

// ---------------------------------------------------------------------------
// Digest Summary Item
// ---------------------------------------------------------------------------

export interface DigestSummaryItem {
  category: string;
  count: number;
  latestTitle: string;
}

// ---------------------------------------------------------------------------
// Service Dependencies
// ---------------------------------------------------------------------------

export interface NotificationServiceDeps {
  notificationRepo: NotificationRepository;
  delegateLinkageRepo: DelegateLinkageRepo;
  auditRepo: AuditRepo;
  postmarkClient?: PostmarkClient;
  senderEmail?: string;
  claimRepo?: ClaimRepo;
  userEmailLookup?: UserEmailLookup;
}

// ---------------------------------------------------------------------------
// Permission-to-event mapping (frozen)
// ---------------------------------------------------------------------------

export const PERMISSION_EVENT_MAP: Readonly<Record<string, readonly string[]>> =
  Object.freeze({
    CLAIM_VIEW: Object.freeze([
      'CLAIM_VALIDATED',
      'CLAIM_FLAGGED',
      'CLAIM_ASSESSED',
      'CLAIM_REJECTED',
      'CLAIM_PAID',
      'DUPLICATE_DETECTED',
    ]),
    CLAIM_SUBMIT: Object.freeze([
      'BATCH_ASSEMBLED',
      'BATCH_SUBMITTED',
      'BATCH_ERROR',
    ]),
    CLAIM_MANAGE: Object.freeze([
      'DEADLINE_7_DAY',
      'DEADLINE_3_DAY',
      'DEADLINE_1_DAY',
      'DEADLINE_EXPIRED',
    ]),
    AI_VIEW: Object.freeze([
      'AI_SUGGESTION_READY',
      'AI_HIGH_VALUE_SUGGESTION',
      'SOMB_CHANGE_IMPACT',
    ]),
    DELEGATE_MANAGE: Object.freeze([
      'DELEGATE_INVITED',
      'DELEGATE_ACCEPTED',
      'DELEGATE_REVOKED',
    ]),
    ANALYTICS_VIEW: Object.freeze([
      'REPORT_READY',
      'DATA_EXPORT_READY',
    ]),
  });

// Reverse map: eventType -> required permission
const EVENT_PERMISSION_MAP = new Map<string, string>();
for (const [permission, events] of Object.entries(PERMISSION_EVENT_MAP)) {
  for (const event of events) {
    EVENT_PERMISSION_MAP.set(event, permission);
  }
}

// ---------------------------------------------------------------------------
// HTML escaping for template variable injection prevention
// ---------------------------------------------------------------------------

function escapeHtml(value: unknown): string {
  const str = String(value ?? '');
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

// ---------------------------------------------------------------------------
// Template variable substitution
// ---------------------------------------------------------------------------

function substituteVariables(
  template: string | null | undefined,
  variables: Record<string, unknown>,
  templateVarNames: string[],
): string | null {
  if (template == null) return null;

  return template.replace(/\{\{(\w+)\}\}/g, (_match, varName: string) => {
    if (!(varName in variables)) {
      if (templateVarNames.includes(varName)) {
        throw new Error(`Missing required template variable: ${varName}`);
      }
      return _match; // Leave unrecognized placeholders as-is
    }
    return escapeHtml(variables[varName]);
  });
}

// ---------------------------------------------------------------------------
// Service functions
// ---------------------------------------------------------------------------

/**
 * Resolve recipients for an event: the physician + any delegates whose
 * permissions include the capability required for this event type.
 */
export async function resolveRecipients(
  deps: NotificationServiceDeps,
  physicianId: string,
  eventType: string,
): Promise<Recipient[]> {
  const recipients: Recipient[] = [
    { userId: physicianId, isDelegate: false, physicianContextId: null },
  ];

  const requiredPermission = EVENT_PERMISSION_MAP.get(eventType);
  if (!requiredPermission) {
    // No permission mapping for this event — physician only
    return recipients;
  }

  const delegates =
    await deps.delegateLinkageRepo.listDelegatesForPhysician(physicianId);

  for (const d of delegates) {
    if (!d.linkage.isActive) continue;

    const permissions = d.linkage.permissions as string[];
    if (permissions.includes(requiredPermission)) {
      recipients.push({
        userId: d.linkage.delegateUserId,
        isDelegate: true,
        physicianContextId: physicianId,
      });
    }
  }

  return recipients;
}

/**
 * Check notification preferences for a recipient's provider context.
 * For URGENT events, in-app is always enabled regardless of preference.
 */
export async function checkPreferences(
  deps: NotificationServiceDeps,
  recipientProviderId: string,
  eventType: string,
): Promise<ChannelPreferences> {
  const catalogueEntry =
    EVENT_CATALOGUE[eventType as keyof typeof EVENT_CATALOGUE];

  // Default preferences from EVENT_CATALOGUE
  const defaults: ChannelPreferences = catalogueEntry
    ? {
        inAppEnabled: catalogueEntry.defaultInApp,
        emailEnabled: catalogueEntry.defaultEmail,
        digestMode: 'IMMEDIATE' as DigestMode,
      }
    : { inAppEnabled: true, emailEnabled: false, digestMode: 'IMMEDIATE' as DigestMode };

  const category = catalogueEntry?.category;
  if (!category) return defaults;

  const pref = await deps.notificationRepo.findPreference(
    recipientProviderId,
    category,
  );

  const result: ChannelPreferences = pref
    ? {
        inAppEnabled: pref.inAppEnabled,
        emailEnabled: pref.emailEnabled,
        digestMode: pref.digestMode as DigestMode,
      }
    : defaults;

  // URGENT events: in-app always enabled regardless of preference
  if (catalogueEntry && catalogueEntry.priority === NotificationPriority.URGENT) {
    result.inAppEnabled = true;
  }

  return result;
}

/**
 * Render a notification by loading its template and substituting variables.
 * All variable values are HTML-escaped to prevent template injection.
 */
export async function renderNotification(
  deps: NotificationServiceDeps,
  templateId: string,
  variables: Record<string, unknown>,
): Promise<RenderedContent> {
  const template = await deps.notificationRepo.findTemplateById(templateId);
  if (!template) {
    throw new Error(`Notification template not found: ${templateId}`);
  }

  const templateVars = (template.variables ?? []) as string[];

  // Validate all required variables are present
  for (const varName of templateVars) {
    if (!(varName in variables)) {
      throw new Error(`Missing required template variable: ${varName}`);
    }
  }

  return {
    title: substituteVariables(template.inAppTitle, variables, templateVars)!,
    body: substituteVariables(template.inAppBody, variables, templateVars)!,
    emailSubject: substituteVariables(
      template.emailSubject,
      variables,
      templateVars,
    ),
    emailHtmlBody: substituteVariables(
      template.emailHtmlBody,
      variables,
      templateVars,
    ),
    emailTextBody: substituteVariables(
      template.emailTextBody,
      variables,
      templateVars,
    ),
    actionUrl: substituteVariables(
      template.actionUrlTemplate,
      variables,
      templateVars,
    ),
    actionLabel: template.actionLabel ?? null,
  };
}

/**
 * Main pipeline entry point: process a single event end-to-end.
 *
 * Steps:
 * 1. Resolve recipients (physician + qualifying delegates)
 * 2. For each recipient: check preferences, render template, create notification
 * 3. Route email (immediate queue or digest queue)
 * 4. Emit audit event
 */
export async function processEvent(
  deps: NotificationServiceDeps,
  event: EmitEvent,
): Promise<SelectNotification[]> {
  const { eventType, physicianId, metadata } = event;

  const catalogueEntry =
    EVENT_CATALOGUE[eventType as keyof typeof EVENT_CATALOGUE];
  const priority = catalogueEntry?.priority ?? NotificationPriority.MEDIUM;

  // Step 1: Resolve recipients
  const recipients = await resolveRecipients(deps, physicianId, eventType);

  // Try to load and render a template. If no template exists, use
  // a basic fallback so the notification can still be created.
  let rendered: RenderedContent | null = null;
  try {
    rendered = await renderNotification(deps, eventType, metadata ?? {});
  } catch {
    // Template not found or variable issue — use fallback content
    rendered = null;
  }

  const title = rendered?.title ?? eventType;
  const body = rendered?.body ?? `Event: ${eventType}`;

  const createdNotifications: SelectNotification[] = [];

  // Step 2–4: For each recipient
  for (const recipient of recipients) {
    // Step 2: Check preferences
    const prefs = await checkPreferences(
      deps,
      recipient.isDelegate ? (recipient.physicianContextId ?? physicianId) : physicianId,
      eventType,
    );

    const channelsDelivered = {
      in_app: prefs.inAppEnabled,
      email: prefs.emailEnabled,
      push: false,
    };

    // Step 3: Create notification record
    const notification = await deps.notificationRepo.createNotification({
      recipientId: recipient.userId,
      physicianContextId: recipient.physicianContextId,
      eventType,
      priority,
      title,
      body,
      actionUrl: rendered?.actionUrl ?? null,
      actionLabel: rendered?.actionLabel ?? null,
      metadata: metadata ?? null,
      channelsDelivered,
    });

    createdNotifications.push(notification);

    // Step 3b: Push to WebSocket (best-effort, fire-and-forget)
    wsManager.pushToUser(recipient.userId, notification);

    // Step 4: Email routing
    if (prefs.emailEnabled) {
      if (prefs.digestMode === 'IMMEDIATE') {
        // Queue for immediate email delivery
        await deps.notificationRepo.createDeliveryLog({
          notificationId: notification.notificationId,
          recipientEmail: '', // Will be resolved by the email sender service
          templateId: eventType,
          status: 'QUEUED',
        });
      } else {
        // Add to digest queue (DAILY_DIGEST or WEEKLY_DIGEST)
        await deps.notificationRepo.addToDigestQueue({
          recipientId: recipient.userId,
          notificationId: notification.notificationId,
          digestType: prefs.digestMode,
        });
      }
    }
  }

  // Audit: event emitted
  await deps.auditRepo.appendAuditLog({
    userId: physicianId,
    action: NotificationAuditAction.NOTIFICATION_EVENT_EMITTED,
    category: 'notification',
    resourceType: 'event',
    detail: {
      eventType,
      recipientCount: createdNotifications.length,
      physicianId,
    },
  });

  return createdNotifications;
}

/**
 * Process multiple events efficiently.
 */
export async function processEventBatch(
  deps: NotificationServiceDeps,
  events: EmitEvent[],
): Promise<SelectNotification[]> {
  const allNotifications: SelectNotification[] = [];

  for (const event of events) {
    const notifications = await processEvent(deps, event);
    allNotifications.push(...notifications);
  }

  return allNotifications;
}

// ---------------------------------------------------------------------------
// Mark Read / Mark All Read (with WebSocket unread count push)
// ---------------------------------------------------------------------------

/**
 * Mark a single notification as read, then push updated unread count
 * to the user's WebSocket connections.
 */
export async function markReadAndPush(
  deps: NotificationServiceDeps,
  notificationId: string,
  recipientId: string,
): Promise<SelectNotification | undefined> {
  const result = await deps.notificationRepo.markRead(notificationId, recipientId);
  if (result) {
    // Fire-and-forget: push updated unread count
    wsManager.pushUnreadCount(recipientId).catch(() => {});
  }
  return result;
}

/**
 * Mark all notifications as read for a recipient, then push updated
 * unread count to the user's WebSocket connections.
 */
export async function markAllReadAndPush(
  deps: NotificationServiceDeps,
  recipientId: string,
): Promise<number> {
  const count = await deps.notificationRepo.markAllRead(recipientId);
  if (count > 0) {
    // Fire-and-forget: push updated unread count
    wsManager.pushUnreadCount(recipientId).catch(() => {});
  }
  return count;
}

// ---------------------------------------------------------------------------
// Email Delivery
// ---------------------------------------------------------------------------

const DEFAULT_SENDER_EMAIL = 'notifications@meritum.ca';

/**
 * Send an email via Postmark. Creates a QUEUED delivery log entry, then
 * attempts to send. On success, updates status to SENT with sent_at.
 * On failure, schedules retry using the retry schedule.
 * Returns the delivery_id.
 */
export async function sendEmail(
  deps: NotificationServiceDeps,
  notificationId: string,
  recipientEmail: string,
  rendered: RenderedEmail,
): Promise<string> {
  if (!deps.postmarkClient) {
    throw new Error('Postmark client not configured');
  }

  // Create delivery log entry with QUEUED status
  const deliveryLog = await deps.notificationRepo.createDeliveryLog({
    notificationId,
    recipientEmail,
    templateId: notificationId,
    status: 'QUEUED',
  });

  try {
    const result = await deps.postmarkClient.sendEmail({
      From: deps.senderEmail ?? DEFAULT_SENDER_EMAIL,
      To: recipientEmail,
      Subject: rendered.subject,
      HtmlBody: rendered.htmlBody,
      TextBody: rendered.textBody,
      MessageStream: 'outbound',
    });

    // Success: update to SENT
    await deps.notificationRepo.updateDeliveryStatus(
      deliveryLog.deliveryId,
      'SENT',
      {
        providerMessageId: result.MessageID,
        sentAt: new Date(),
      },
    );

    await deps.auditRepo.appendAuditLog({
      action: NotificationAuditAction.NOTIFICATION_EMAIL_SENT,
      category: 'notification',
      resourceType: 'email_delivery',
      resourceId: deliveryLog.deliveryId,
      detail: { notificationId, recipientEmail },
    });
  } catch {
    // Failure: schedule retry
    const retryIndex = deliveryLog.retryCount + 1;
    if (retryIndex < EMAIL_MAX_RETRY_ATTEMPTS) {
      const nextRetryAt = new Date(
        Date.now() + EMAIL_RETRY_SCHEDULE_MS[retryIndex],
      );
      await deps.notificationRepo.incrementRetry(
        deliveryLog.deliveryId,
        nextRetryAt,
      );
    } else {
      await deps.notificationRepo.updateDeliveryStatus(
        deliveryLog.deliveryId,
        'FAILED',
      );

      await deps.auditRepo.appendAuditLog({
        action: NotificationAuditAction.NOTIFICATION_EMAIL_FAILED,
        category: 'notification',
        resourceType: 'email_delivery',
        resourceId: deliveryLog.deliveryId,
        detail: { notificationId, recipientEmail, reason: 'max_retries_exhausted' },
      });
    }
  }

  return deliveryLog.deliveryId;
}

// ---------------------------------------------------------------------------
// Quiet Hours
// ---------------------------------------------------------------------------

const EDMONTON_TZ = 'America/Edmonton';

/**
 * Check if the current time (Mountain Time — America/Edmonton) falls within
 * the provider's configured quiet hours.
 * Returns false when no quiet hours are configured.
 */
export async function isInQuietHours(
  deps: NotificationServiceDeps,
  providerId: string,
): Promise<boolean> {
  const prefs = await deps.notificationRepo.findPreferencesByProvider(providerId);
  if (prefs.length === 0) return false;

  // All preferences share the same quiet hours; take the first non-null
  const pref = prefs.find(
    (p) => p.quietHoursStart != null && p.quietHoursEnd != null,
  );
  if (!pref || !pref.quietHoursStart || !pref.quietHoursEnd) return false;

  const now = new Date();
  const formatter = new Intl.DateTimeFormat('en-CA', {
    timeZone: EDMONTON_TZ,
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });
  const currentTime = formatter.format(now); // "HH:MM"

  const start = pref.quietHoursStart as string; // "HH:MM"
  const end = pref.quietHoursEnd as string;     // "HH:MM"

  if (start <= end) {
    // Same-day range: e.g., 09:00 – 17:00
    return currentTime >= start && currentTime < end;
  } else {
    // Overnight range: e.g., 22:00 – 07:00
    return currentTime >= start || currentTime < end;
  }
}

/**
 * Calculate the next time after quiet hours end (Mountain Time).
 * Returns a Date for when emails can be sent again.
 */
export async function scheduleAfterQuietHours(
  deps: NotificationServiceDeps,
  providerId: string,
): Promise<Date> {
  const prefs = await deps.notificationRepo.findPreferencesByProvider(providerId);

  const pref = prefs.find(
    (p) => p.quietHoursStart != null && p.quietHoursEnd != null,
  );

  if (!pref || !pref.quietHoursEnd) {
    return new Date(); // No quiet hours, can send now
  }

  const end = pref.quietHoursEnd as string; // "HH:MM"
  const [endHour, endMinute] = end.split(':').map(Number);

  // Build a Date in Edmonton timezone for today's quiet hours end
  const now = new Date();
  const edmontonNow = new Date(
    now.toLocaleString('en-US', { timeZone: EDMONTON_TZ }),
  );

  const candidate = new Date(edmontonNow);
  candidate.setHours(endHour, endMinute, 0, 0);

  // If quiet hours end is already past for today, schedule for tomorrow
  if (candidate <= edmontonNow) {
    candidate.setDate(candidate.getDate() + 1);
  }

  // Convert back from Edmonton local time to UTC
  const offset = now.getTime() - edmontonNow.getTime();
  return new Date(candidate.getTime() + offset);
}

// ---------------------------------------------------------------------------
// Retry Logic
// ---------------------------------------------------------------------------

/**
 * Scheduled job handler: find pending retries and attempt resend.
 * After 4 total failures → status FAILED, emit audit event.
 */
export async function retryFailedEmails(
  deps: NotificationServiceDeps,
): Promise<void> {
  if (!deps.postmarkClient) {
    throw new Error('Postmark client not configured');
  }

  const pendingRetries = await deps.notificationRepo.findPendingRetries();

  for (const delivery of pendingRetries) {
    try {
      // Look up the notification to get content for resend
      const result = await deps.postmarkClient.sendEmail({
        From: deps.senderEmail ?? DEFAULT_SENDER_EMAIL,
        To: delivery.recipientEmail,
        Subject: `Notification ${delivery.notificationId}`,
        HtmlBody: `<p>You have a new notification. <a href="https://meritum.ca/notifications">View in Meritum</a></p>`,
        TextBody: 'You have a new notification. View at https://meritum.ca/notifications',
        MessageStream: 'outbound',
      });

      // Success
      await deps.notificationRepo.updateDeliveryStatus(
        delivery.deliveryId,
        'SENT',
        {
          providerMessageId: result.MessageID,
          sentAt: new Date(),
        },
      );

      await deps.auditRepo.appendAuditLog({
        action: NotificationAuditAction.NOTIFICATION_EMAIL_SENT,
        category: 'notification',
        resourceType: 'email_delivery',
        resourceId: delivery.deliveryId,
        detail: {
          notificationId: delivery.notificationId,
          recipientEmail: delivery.recipientEmail,
          retryAttempt: delivery.retryCount,
        },
      });
    } catch {
      // Failure: increment retry count
      const nextAttempt = delivery.retryCount + 1;

      if (nextAttempt >= EMAIL_MAX_RETRY_ATTEMPTS) {
        // Max retries reached — mark FAILED
        await deps.notificationRepo.updateDeliveryStatus(
          delivery.deliveryId,
          'FAILED',
        );

        await deps.auditRepo.appendAuditLog({
          action: NotificationAuditAction.NOTIFICATION_EMAIL_FAILED,
          category: 'notification',
          resourceType: 'email_delivery',
          resourceId: delivery.deliveryId,
          detail: {
            notificationId: delivery.notificationId,
            recipientEmail: delivery.recipientEmail,
            reason: 'max_retries_exhausted',
          },
        });
      } else {
        // Schedule next retry
        const nextRetryAt = new Date(
          Date.now() + EMAIL_RETRY_SCHEDULE_MS[nextAttempt],
        );
        await deps.notificationRepo.incrementRetry(
          delivery.deliveryId,
          nextRetryAt,
        );
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Bounce Handling
// ---------------------------------------------------------------------------

/**
 * Handle bounce webhook from email provider (Postmark).
 * Hard bounce: mark BOUNCED, no retry, create in-app notification.
 * Soft bounce: schedule retry per retry schedule (if retries remain).
 */
export async function handleBounce(
  deps: NotificationServiceDeps,
  providerMessageId: string,
  bounceType: 'hard' | 'soft',
  reason: string,
): Promise<void> {
  const delivery =
    await deps.notificationRepo.findDeliveryLogByProviderMessageId(
      providerMessageId,
    );

  if (!delivery) return;

  if (bounceType === 'hard') {
    // Mark as BOUNCED with no retry
    await deps.notificationRepo.updateDeliveryStatus(
      delivery.deliveryId,
      'BOUNCED',
      {
        bouncedAt: new Date(),
        bounceReason: reason,
      },
    );

    // Look up the original notification to get the recipientId
    const originalNotification =
      await deps.notificationRepo.findNotificationByIdInternal(
        delivery.notificationId,
      );

    if (originalNotification) {
      // Create in-app notification telling user to update their email
      await deps.notificationRepo.createNotification({
        recipientId: originalNotification.recipientId,
        eventType: 'EMAIL_BOUNCE_ALERT',
        priority: NotificationPriority.HIGH,
        title: 'Email delivery failed',
        body: 'We could not deliver an email to your address. Please update your email in account settings.',
        channelsDelivered: { in_app: true, email: false, push: false },
      });
    }

    await deps.auditRepo.appendAuditLog({
      action: NotificationAuditAction.NOTIFICATION_EMAIL_BOUNCED,
      category: 'notification',
      resourceType: 'email_delivery',
      resourceId: delivery.deliveryId,
      detail: {
        notificationId: delivery.notificationId,
        bounceType: 'hard',
        reason,
      },
    });
  } else {
    // Soft bounce: schedule retry if retries remain
    const nextAttempt = delivery.retryCount + 1;

    if (nextAttempt < EMAIL_MAX_RETRY_ATTEMPTS) {
      const nextRetryAt = new Date(
        Date.now() + EMAIL_RETRY_SCHEDULE_MS[nextAttempt],
      );
      await deps.notificationRepo.incrementRetry(
        delivery.deliveryId,
        nextRetryAt,
      );
    } else {
      await deps.notificationRepo.updateDeliveryStatus(
        delivery.deliveryId,
        'FAILED',
      );
    }

    await deps.auditRepo.appendAuditLog({
      action: NotificationAuditAction.NOTIFICATION_EMAIL_BOUNCED,
      category: 'notification',
      resourceType: 'email_delivery',
      resourceId: delivery.deliveryId,
      detail: {
        notificationId: delivery.notificationId,
        bounceType: 'soft',
        reason,
        retryScheduled: nextAttempt < EMAIL_MAX_RETRY_ATTEMPTS,
      },
    });
  }
}

// ---------------------------------------------------------------------------
// Digest Assembly
// ---------------------------------------------------------------------------

/**
 * Render a digest email from a set of digest queue items. Groups items by
 * event category (from EVENT_CATALOGUE) and produces a summary with counts.
 * No PHI in digest email — only counts and category names.
 */
export function renderDigestEmail(
  items: SelectDigestQueueItem[],
  digestType: 'DAILY' | 'WEEKLY',
  notifications: SelectNotification[],
): RenderedEmail {
  // Build a map from notificationId → notification for quick lookups
  const notifMap = new Map<string, SelectNotification>();
  for (const n of notifications) {
    notifMap.set(n.notificationId, n);
  }

  // Group by category
  const categoryMap = new Map<string, { count: number; latestTitle: string }>();

  for (const item of items) {
    const notif = notifMap.get(item.notificationId);
    if (!notif) continue;

    const catalogueEntry =
      EVENT_CATALOGUE[notif.eventType as keyof typeof EVENT_CATALOGUE];
    const category = catalogueEntry?.category ?? 'General';

    const existing = categoryMap.get(category);
    if (existing) {
      existing.count += 1;
      // Keep the latest title (by notification order — items are in insertion order)
      existing.latestTitle = notif.title;
    } else {
      categoryMap.set(category, { count: 1, latestTitle: notif.title });
    }
  }

  const summaries: DigestSummaryItem[] = [];
  for (const [category, data] of categoryMap) {
    summaries.push({
      category,
      count: data.count,
      latestTitle: data.latestTitle,
    });
  }

  const totalCount = items.length;
  const label = digestType === 'DAILY' ? 'Daily' : 'Weekly';

  const categoryLines = summaries
    .map((s) => `- ${s.category}: ${s.count} notification${s.count !== 1 ? 's' : ''}`)
    .join('\n');

  const textBody = [
    `You have ${totalCount} new notification${totalCount !== 1 ? 's' : ''}:`,
    '',
    categoryLines,
    '',
    'View all notifications: https://meritum.ca/notifications',
  ].join('\n');

  const categoryHtml = summaries
    .map(
      (s) =>
        `<li>${escapeHtml(s.category)}: ${s.count} notification${s.count !== 1 ? 's' : ''}</li>`,
    )
    .join('\n');

  const htmlBody = [
    `<p>You have ${totalCount} new notification${totalCount !== 1 ? 's' : ''}:</p>`,
    '<ul>',
    categoryHtml,
    '</ul>',
    '<p><a href="https://meritum.ca/notifications">View all notifications</a></p>',
  ].join('\n');

  return {
    subject: `Your ${label} Meritum Summary`,
    htmlBody,
    textBody,
  };
}

/**
 * Build the digest summary items (for external consumption / testing).
 */
export function buildDigestSummary(
  items: SelectDigestQueueItem[],
  notifications: SelectNotification[],
): DigestSummaryItem[] {
  const notifMap = new Map<string, SelectNotification>();
  for (const n of notifications) {
    notifMap.set(n.notificationId, n);
  }

  const categoryMap = new Map<string, { count: number; latestTitle: string }>();

  for (const item of items) {
    const notif = notifMap.get(item.notificationId);
    if (!notif) continue;

    const catalogueEntry =
      EVENT_CATALOGUE[notif.eventType as keyof typeof EVENT_CATALOGUE];
    const category = catalogueEntry?.category ?? 'General';

    const existing = categoryMap.get(category);
    if (existing) {
      existing.count += 1;
      existing.latestTitle = notif.title;
    } else {
      categoryMap.set(category, { count: 1, latestTitle: notif.title });
    }
  }

  const summaries: DigestSummaryItem[] = [];
  for (const [category, data] of categoryMap) {
    summaries.push({
      category,
      count: data.count,
      latestTitle: data.latestTitle,
    });
  }
  return summaries;
}

/**
 * Assemble daily digest: runs at 08:00 MT daily.
 * Finds all pending DAILY digest items grouped by recipient.
 * For each recipient: renders digest email, sends it, marks items as sent.
 */
export async function assembleDailyDigest(
  deps: NotificationServiceDeps,
): Promise<void> {
  const grouped = await deps.notificationRepo.findAllPendingDigestItems('DAILY_DIGEST');

  if (grouped.size === 0) return;

  let totalRecipients = 0;
  let totalItems = 0;

  for (const [recipientId, items] of grouped) {
    // Look up the notifications for these digest items
    const notifications: SelectNotification[] = [];
    for (const item of items) {
      const notif = await deps.notificationRepo.findNotificationByIdInternal(
        item.notificationId,
      );
      if (notif) notifications.push(notif);
    }

    if (notifications.length === 0) continue;

    // Render digest email (no PHI — only counts and categories)
    const rendered = renderDigestEmail(items, 'DAILY', notifications);

    // Look up recipient email
    let recipientEmail: string | null = null;
    if (deps.userEmailLookup) {
      recipientEmail = await deps.userEmailLookup.getEmailByUserId(recipientId);
    }

    if (recipientEmail && deps.postmarkClient) {
      // Send digest email
      const dummyNotificationId = items[0].notificationId;
      await sendEmail(deps, dummyNotificationId, recipientEmail, rendered);
    }

    // Mark items as sent
    const queueIds = items.map((i) => i.queueId);
    await deps.notificationRepo.markDigestItemsSent(queueIds);

    totalRecipients += 1;
    totalItems += items.length;
  }

  // Emit audit event
  await deps.auditRepo.appendAuditLog({
    action: NotificationAuditAction.NOTIFICATION_DIGEST_ASSEMBLED,
    category: 'notification',
    resourceType: 'digest',
    detail: {
      digestType: 'DAILY',
      recipientCount: totalRecipients,
      itemCount: totalItems,
    },
  });
}

/**
 * Assemble weekly digest: runs Monday at 08:00 MT.
 * Same as daily but for WEEKLY items from past 7 days.
 */
export async function assembleWeeklyDigest(
  deps: NotificationServiceDeps,
): Promise<void> {
  const grouped = await deps.notificationRepo.findAllPendingDigestItems('WEEKLY_DIGEST');

  if (grouped.size === 0) return;

  let totalRecipients = 0;
  let totalItems = 0;

  for (const [recipientId, items] of grouped) {
    const notifications: SelectNotification[] = [];
    for (const item of items) {
      const notif = await deps.notificationRepo.findNotificationByIdInternal(
        item.notificationId,
      );
      if (notif) notifications.push(notif);
    }

    if (notifications.length === 0) continue;

    const rendered = renderDigestEmail(items, 'WEEKLY', notifications);

    let recipientEmail: string | null = null;
    if (deps.userEmailLookup) {
      recipientEmail = await deps.userEmailLookup.getEmailByUserId(recipientId);
    }

    if (recipientEmail && deps.postmarkClient) {
      const dummyNotificationId = items[0].notificationId;
      await sendEmail(deps, dummyNotificationId, recipientEmail, rendered);
    }

    const queueIds = items.map((i) => i.queueId);
    await deps.notificationRepo.markDigestItemsSent(queueIds);

    totalRecipients += 1;
    totalItems += items.length;
  }

  await deps.auditRepo.appendAuditLog({
    action: NotificationAuditAction.NOTIFICATION_DIGEST_ASSEMBLED,
    category: 'notification',
    resourceType: 'digest',
    detail: {
      digestType: 'WEEKLY',
      recipientCount: totalRecipients,
      itemCount: totalItems,
    },
  });
}

// ---------------------------------------------------------------------------
// Thursday Submission Sequence — Wednesday Batch Reminder
// ---------------------------------------------------------------------------

/**
 * Scheduled job: Wednesday evening. For each physician with
 * batch_review_reminder preference enabled: check if flagged claims
 * exist. If yes, emit BATCH_REVIEW_REMINDER event via processEvent.
 *
 * No claim details in the notification — only the flagged count.
 */
export async function sendWednesdayBatchReminder(
  deps: NotificationServiceDeps,
  physicians: Array<{ userId: string; providerId: string; reminderEnabled: boolean }>,
): Promise<void> {
  if (!deps.claimRepo) return;

  for (const physician of physicians) {
    if (!physician.reminderEnabled) continue;

    const flaggedCount = await deps.claimRepo.countFlaggedClaims(
      physician.providerId,
    );

    if (flaggedCount === 0) continue;

    // Emit BATCH_REVIEW_REMINDER event — no PHI, only flagged count
    await processEvent(deps, {
      eventType: 'BATCH_REVIEW_REMINDER',
      physicianId: physician.userId,
      metadata: { flagged_count: flaggedCount },
    });
  }
}

// ---------------------------------------------------------------------------
// Job Scheduling
// ---------------------------------------------------------------------------

export interface NotificationLogger {
  info(msg: string, data?: Record<string, unknown>): void;
  error(msg: string, data?: Record<string, unknown>): void;
}

/**
 * Register all scheduled notification jobs.
 *
 * Cron expressions (America/Edmonton timezone):
 * - Daily digest:       '0 8 * * *'    (08:00 MT daily)
 * - Weekly digest:      '0 8 * * 1'    (08:00 MT Monday)
 * - Email retry:        '* /5 * * * *'  (every 5 minutes)
 * - Wednesday reminder: '0 18 * * 3'   (18:00 MT Wednesday)
 *
 * Each job: logs start, executes in try/catch, logs success/error,
 * never crashes the application on handler throw.
 */
export function registerNotificationJobs(
  deps: NotificationServiceDeps,
  logger: NotificationLogger,
): Array<{ name: string; cronExpression: string; handler: () => Promise<void> }> {
  const jobs = [
    {
      name: 'daily-digest',
      cronExpression: '0 8 * * *',
      handler: async () => {
        logger.info('Starting daily digest assembly');
        try {
          await assembleDailyDigest(deps);
          logger.info('Daily digest assembly completed');
        } catch (err: unknown) {
          logger.error('Daily digest assembly failed', {
            error: err instanceof Error ? err.message : String(err),
          });
        }
      },
    },
    {
      name: 'weekly-digest',
      cronExpression: '0 8 * * 1',
      handler: async () => {
        logger.info('Starting weekly digest assembly');
        try {
          await assembleWeeklyDigest(deps);
          logger.info('Weekly digest assembly completed');
        } catch (err: unknown) {
          logger.error('Weekly digest assembly failed', {
            error: err instanceof Error ? err.message : String(err),
          });
        }
      },
    },
    {
      name: 'email-retry',
      cronExpression: '*/5 * * * *',
      handler: async () => {
        logger.info('Starting email retry job');
        try {
          await retryFailedEmails(deps);
          logger.info('Email retry job completed');
        } catch (err: unknown) {
          logger.error('Email retry job failed', {
            error: err instanceof Error ? err.message : String(err),
          });
        }
      },
    },
    {
      name: 'wednesday-batch-reminder',
      cronExpression: '0 18 * * 3',
      handler: async () => {
        logger.info('Starting Wednesday batch reminder');
        try {
          // The caller is responsible for providing the physician list
          // In production, this would query the provider repository
          await sendWednesdayBatchReminder(deps, []);
          logger.info('Wednesday batch reminder completed');
        } catch (err: unknown) {
          logger.error('Wednesday batch reminder failed', {
            error: err instanceof Error ? err.message : String(err),
          });
        }
      },
    },
  ];

  return jobs;
}

// ---------------------------------------------------------------------------
// WebSocket Real-time Notification Delivery
// ---------------------------------------------------------------------------

/**
 * Minimal WebSocket interface for testability. Compatible with the `ws`
 * library's WebSocket class used by @fastify/websocket.
 */
export interface NotificationWebSocket {
  readyState: number;
  send(data: string, cb?: (err?: Error) => void): void;
  close(code?: number, reason?: string): void;
  ping(data?: unknown, mask?: boolean, cb?: (err?: Error) => void): void;
  on(event: string, listener: (...args: unknown[]) => void): void;
  removeAllListeners(event?: string): void;
}

/** WebSocket readyState constants (mirrors ws library). */
export const WS_READY_STATE = {
  CONNECTING: 0,
  OPEN: 1,
  CLOSING: 2,
  CLOSED: 3,
} as const;

/** Close code for authentication failure / session expiry. */
export const WS_CLOSE_AUTH_FAILED = 4001;

/** Heartbeat interval in ms (30 seconds). */
const HEARTBEAT_INTERVAL_MS = 30_000;

/** Pong timeout in ms (10 seconds). */
const PONG_TIMEOUT_MS = 10_000;

/**
 * Payload pushed over WebSocket for a new notification.
 */
export interface NotificationWsPayload {
  type: 'notification';
  data: {
    notification_id: string;
    title: string;
    body: string;
    priority: string;
    action_url: string | null;
    event_type: string;
    metadata: Record<string, unknown>;
    created_at: string;
  };
}

/**
 * Payload pushed over WebSocket for unread count updates.
 */
export interface UnreadCountWsPayload {
  type: 'unread_count';
  data: { count: number };
}

/**
 * Session validator interface for WebSocket authentication.
 * Compatible with the IAM domain's validateSession function.
 */
export interface WsSessionValidator {
  validateSession(tokenHash: string): Promise<{ userId: string } | null>;
}

/**
 * Connection metadata tracked per socket.
 */
interface ConnectionMeta {
  heartbeatTimer: ReturnType<typeof setInterval> | null;
  pongTimer: ReturnType<typeof setTimeout> | null;
  alive: boolean;
}

/**
 * Manages WebSocket connections for real-time notification delivery.
 *
 * - Tracks connections per userId (supports multiple tabs).
 * - Pushes notifications and unread counts to connected clients.
 * - Runs heartbeat pings and closes stale connections.
 * - All payloads contain rendered content only — no raw DB fields or PII.
 */
export class NotificationWebSocketManager {
  private connections = new Map<string, Set<NotificationWebSocket>>();
  private connectionMeta = new Map<NotificationWebSocket, ConnectionMeta>();
  private notificationRepo: NotificationRepository | null = null;

  /**
   * Inject the notification repository (for countUnread queries).
   * Called once during server bootstrap.
   */
  setNotificationRepo(repo: NotificationRepository): void {
    this.notificationRepo = repo;
  }

  /**
   * Register a new WebSocket connection for a user.
   * Starts the heartbeat mechanism for the connection.
   */
  registerConnection(userId: string, socket: NotificationWebSocket): void {
    let userSockets = this.connections.get(userId);
    if (!userSockets) {
      userSockets = new Set();
      this.connections.set(userId, userSockets);
    }
    userSockets.add(socket);

    // Set up heartbeat
    const meta: ConnectionMeta = {
      heartbeatTimer: null,
      pongTimer: null,
      alive: true,
    };
    this.connectionMeta.set(socket, meta);

    this.startHeartbeat(userId, socket, meta);
  }

  /**
   * Remove a specific WebSocket connection for a user.
   * Cleans up heartbeat timers. If the user has no remaining
   * connections, removes the map entry entirely.
   */
  removeConnection(userId: string, socket: NotificationWebSocket): void {
    this.stopHeartbeat(socket);
    this.connectionMeta.delete(socket);

    const userSockets = this.connections.get(userId);
    if (!userSockets) return;

    userSockets.delete(socket);
    if (userSockets.size === 0) {
      this.connections.delete(userId);
    }
  }

  /**
   * Push a notification to all active WebSocket connections for a user.
   * No-op if the user has no active connections. Best-effort delivery.
   */
  pushToUser(userId: string, notification: SelectNotification): void {
    const userSockets = this.connections.get(userId);
    if (!userSockets || userSockets.size === 0) return;

    const payload: NotificationWsPayload = {
      type: 'notification',
      data: {
        notification_id: notification.notificationId,
        title: notification.title,
        body: notification.body,
        priority: notification.priority,
        action_url: notification.actionUrl ?? null,
        event_type: notification.eventType,
        metadata: (notification.metadata as Record<string, unknown>) ?? {},
        created_at: notification.createdAt instanceof Date
          ? notification.createdAt.toISOString()
          : String(notification.createdAt),
      },
    };

    const message = JSON.stringify(payload);

    for (const socket of userSockets) {
      if (socket.readyState === WS_READY_STATE.OPEN) {
        socket.send(message);
      }
    }
  }

  /**
   * Query current unread count and push to all active connections for a user.
   */
  async pushUnreadCount(userId: string): Promise<void> {
    if (!this.notificationRepo) return;

    const userSockets = this.connections.get(userId);
    if (!userSockets || userSockets.size === 0) return;

    const count = await this.notificationRepo.countUnread(userId);

    const payload: UnreadCountWsPayload = {
      type: 'unread_count',
      data: { count },
    };

    const message = JSON.stringify(payload);

    for (const socket of userSockets) {
      if (socket.readyState === WS_READY_STATE.OPEN) {
        socket.send(message);
      }
    }
  }

  /**
   * Check if a user has any active WebSocket connections.
   */
  hasConnections(userId: string): boolean {
    const userSockets = this.connections.get(userId);
    return userSockets !== undefined && userSockets.size > 0;
  }

  /**
   * Get the number of active connections for a user.
   */
  getConnectionCount(userId: string): number {
    return this.connections.get(userId)?.size ?? 0;
  }

  /**
   * Disconnect all sockets for a user (e.g., on session expiry).
   */
  disconnectUser(userId: string, code = WS_CLOSE_AUTH_FAILED, reason = 'Session expired'): void {
    const userSockets = this.connections.get(userId);
    if (!userSockets) return;

    for (const socket of userSockets) {
      this.stopHeartbeat(socket);
      this.connectionMeta.delete(socket);
      socket.close(code, reason);
    }

    this.connections.delete(userId);
  }

  /**
   * Shut down all connections and timers. Used during server shutdown.
   */
  shutdown(): void {
    for (const [userId, sockets] of this.connections) {
      for (const socket of sockets) {
        this.stopHeartbeat(socket);
        this.connectionMeta.delete(socket);
        socket.close(1001, 'Server shutting down');
      }
    }
    this.connections.clear();
  }

  // -- Private: Heartbeat ---------------------------------------------------

  private startHeartbeat(
    userId: string,
    socket: NotificationWebSocket,
    meta: ConnectionMeta,
  ): void {
    // Listen for pong responses
    socket.on('pong', () => {
      meta.alive = true;
      if (meta.pongTimer) {
        clearTimeout(meta.pongTimer);
        meta.pongTimer = null;
      }
    });

    meta.heartbeatTimer = setInterval(() => {
      if (socket.readyState !== WS_READY_STATE.OPEN) {
        this.removeConnection(userId, socket);
        return;
      }

      // Send ping
      meta.alive = false;
      socket.ping();

      // Wait for pong — if none arrives within timeout, close the connection
      meta.pongTimer = setTimeout(() => {
        if (!meta.alive) {
          this.removeConnection(userId, socket);
          socket.close(1001, 'Heartbeat timeout');
        }
      }, PONG_TIMEOUT_MS);
    }, HEARTBEAT_INTERVAL_MS);
  }

  private stopHeartbeat(socket: NotificationWebSocket): void {
    const meta = this.connectionMeta.get(socket);
    if (!meta) return;

    if (meta.heartbeatTimer) {
      clearInterval(meta.heartbeatTimer);
      meta.heartbeatTimer = null;
    }
    if (meta.pongTimer) {
      clearTimeout(meta.pongTimer);
      meta.pongTimer = null;
    }
  }
}

/**
 * Singleton WebSocket manager instance.
 * Used across the notification service and route handler.
 */
export const wsManager = new NotificationWebSocketManager();

// ---------------------------------------------------------------------------
// Fastify WebSocket Route Registration
// ---------------------------------------------------------------------------

/**
 * Cookie parsing utility (mirrors auth.plugin.ts).
 */
function parseCookie(cookieHeader: string, name: string): string | null {
  const pairs = cookieHeader.split(';');
  for (const pair of pairs) {
    const [key, ...rest] = pair.trim().split('=');
    if (key === name) {
      return rest.join('=') || null;
    }
  }
  return null;
}

/**
 * Register the `/ws/notifications` WebSocket route on a Fastify instance.
 *
 * Authentication: extracts session token from the `session` cookie (or
 * `?token=` query parameter), hashes it with SHA-256, and validates via
 * the supplied session validator. Invalid sessions are rejected with
 * close code 4001.
 *
 * @param app - Fastify instance (must have @fastify/websocket registered)
 * @param sessionValidator - validates session token hashes
 * @param hashTokenFn - SHA-256 hash function for session tokens
 */
export function registerNotificationWebSocket(
  app: { get(path: string, opts: { websocket: true }, handler: (socket: any, req: any) => void): void },
  sessionValidator: WsSessionValidator,
  hashTokenFn: (token: string) => string,
): void {
  app.get('/ws/notifications', { websocket: true }, async (socket: NotificationWebSocket, req: any) => {
    // Extract session token from cookie or query parameter
    const cookieHeader: string | undefined = req.headers?.cookie;
    const queryToken: string | undefined = req.query?.token;

    let token: string | null = null;
    if (cookieHeader) {
      token = parseCookie(cookieHeader, 'session');
    }
    if (!token && queryToken) {
      token = queryToken;
    }

    if (!token) {
      socket.close(WS_CLOSE_AUTH_FAILED, 'Authentication required');
      return;
    }

    // Validate session
    const tokenHash = hashTokenFn(token);
    const authResult = await sessionValidator.validateSession(tokenHash);

    if (!authResult) {
      socket.close(WS_CLOSE_AUTH_FAILED, 'Invalid or expired session');
      return;
    }

    const userId = authResult.userId;

    // Register connection
    wsManager.registerConnection(userId, socket);

    // Handle close / error
    socket.on('close', () => {
      wsManager.removeConnection(userId, socket);
    });

    socket.on('error', () => {
      wsManager.removeConnection(userId, socket);
    });
  });
}
