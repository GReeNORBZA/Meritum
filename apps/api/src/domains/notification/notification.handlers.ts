import { type FastifyRequest, type FastifyReply } from 'fastify';
import { timingSafeEqual, createHmac } from 'node:crypto';
import {
  type NotificationFeedQuery,
  type NotificationIdParam,
  type UpdatePreference,
  type PreferenceCategoryParam,
  type QuietHours,
  type EmitEvent,
  type EmitBatchEvent,
} from '@meritum/shared/schemas/notification.schema.js';
import {
  NotificationAuditAction,
  EVENT_CATALOGUE,
  NotificationPriority,
  type EventCategory,
} from '@meritum/shared/constants/notification.constants.js';
import { type NotificationRepository } from './notification.repository.js';
import { NotFoundError, ValidationError, ForbiddenError } from '../../lib/errors.js';
import {
  type NotificationServiceDeps,
  processEvent,
  processEventBatch,
  handleBounce,
} from './notification.service.js';

// ---------------------------------------------------------------------------
// Handler Dependencies
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

export interface NotificationHandlerDeps {
  notificationRepo: NotificationRepository;
  auditRepo: AuditRepo;
  pushUnreadCount?: (recipientId: string) => Promise<void>;
}

// ---------------------------------------------------------------------------
// Response mapping helper
// ---------------------------------------------------------------------------

function mapNotificationResponse(n: {
  notificationId: string;
  eventType: string;
  priority: string;
  title: string;
  body: string;
  actionUrl: string | null;
  actionLabel: string | null;
  metadata: Record<string, unknown> | null;
  channelsDelivered: { in_app: boolean; email: boolean; push: boolean };
  readAt: Date | null;
  dismissedAt: Date | null;
  createdAt: Date;
}) {
  return {
    notification_id: n.notificationId,
    event_type: n.eventType,
    priority: n.priority,
    title: n.title,
    body: n.body,
    action_url: n.actionUrl ?? null,
    action_label: n.actionLabel ?? null,
    metadata: n.metadata ?? null,
    channels_delivered: n.channelsDelivered,
    read_at: n.readAt instanceof Date ? n.readAt.toISOString() : n.readAt,
    dismissed_at: n.dismissedAt instanceof Date ? n.dismissedAt.toISOString() : n.dismissedAt,
    created_at: n.createdAt instanceof Date ? n.createdAt.toISOString() : String(n.createdAt),
  };
}

// ---------------------------------------------------------------------------
// Handler Factory
// ---------------------------------------------------------------------------

export function createNotificationHandlers(deps: NotificationHandlerDeps) {
  // -------------------------------------------------------------------------
  // GET /api/v1/notifications
  // -------------------------------------------------------------------------

  async function listNotificationsHandler(
    request: FastifyRequest<{ Querystring: NotificationFeedQuery }>,
    reply: FastifyReply,
  ) {
    const recipientId = request.authContext.userId;
    const { unread_only, limit, offset } = request.query;

    const notifications = await deps.notificationRepo.listNotifications(
      recipientId,
      { unreadOnly: unread_only, limit, offset },
    );

    return reply.code(200).send({
      data: {
        notifications: notifications.map(mapNotificationResponse),
        total: notifications.length,
      },
    });
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/notifications/unread-count
  // -------------------------------------------------------------------------

  async function unreadCountHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const recipientId = request.authContext.userId;
    const count = await deps.notificationRepo.countUnread(recipientId);

    return reply.code(200).send({
      data: { count },
    });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/notifications/:id/read
  // -------------------------------------------------------------------------

  async function markReadHandler(
    request: FastifyRequest<{ Params: NotificationIdParam }>,
    reply: FastifyReply,
  ) {
    const recipientId = request.authContext.userId;
    const { id } = request.params;

    const result = await deps.notificationRepo.markRead(id, recipientId);
    if (!result) {
      throw new NotFoundError('Resource');
    }

    // Fire-and-forget: push updated unread count via WebSocket
    if (deps.pushUnreadCount) {
      deps.pushUnreadCount(recipientId).catch(() => {});
    }

    await deps.auditRepo.appendAuditLog({
      userId: recipientId,
      action: NotificationAuditAction.NOTIFICATION_READ,
      category: 'notification',
      resourceType: 'notification',
      resourceId: id,
    });

    return reply.code(200).send({
      data: { success: true },
    });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/notifications/read-all
  // -------------------------------------------------------------------------

  async function markAllReadHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const recipientId = request.authContext.userId;

    const count = await deps.notificationRepo.markAllRead(recipientId);

    // Fire-and-forget: push updated unread count via WebSocket
    if (count > 0 && deps.pushUnreadCount) {
      deps.pushUnreadCount(recipientId).catch(() => {});
    }

    await deps.auditRepo.appendAuditLog({
      userId: recipientId,
      action: NotificationAuditAction.NOTIFICATION_READ_ALL,
      category: 'notification',
      resourceType: 'notification',
      detail: { count },
    });

    return reply.code(200).send({
      data: { success: true, count },
    });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/notifications/:id/dismiss
  // -------------------------------------------------------------------------

  async function dismissHandler(
    request: FastifyRequest<{ Params: NotificationIdParam }>,
    reply: FastifyReply,
  ) {
    const recipientId = request.authContext.userId;
    const { id } = request.params;

    const result = await deps.notificationRepo.dismiss(id, recipientId);
    if (!result) {
      throw new NotFoundError('Resource');
    }

    await deps.auditRepo.appendAuditLog({
      userId: recipientId,
      action: NotificationAuditAction.NOTIFICATION_DISMISSED,
      category: 'notification',
      resourceType: 'notification',
      resourceId: id,
    });

    return reply.code(200).send({
      data: { success: true },
    });
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/notification-preferences
  // -------------------------------------------------------------------------

  async function getPreferencesHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const ctx = request.authContext;

    // Delegates cannot access preferences
    if (ctx.role?.toUpperCase() === 'DELEGATE') {
      throw new ForbiddenError('Delegates cannot access notification preferences');
    }

    const providerId = ctx.userId;
    const stored = await deps.notificationRepo.findPreferencesByProvider(providerId);

    // Build a set of categories already stored
    const storedCategories = new Map<string, typeof stored[number]>();
    for (const pref of stored) {
      storedCategories.set(pref.eventCategory, pref);
    }

    // Collect all unique categories from EVENT_CATALOGUE
    const allCategories = new Set<string>();
    const categoryHasUrgent = new Map<string, boolean>();
    const categoryDefaults = new Map<string, { defaultInApp: boolean; defaultEmail: boolean }>();

    for (const [, entry] of Object.entries(EVENT_CATALOGUE)) {
      if (!allCategories.has(entry.category)) {
        allCategories.add(entry.category);
        categoryDefaults.set(entry.category, {
          defaultInApp: entry.defaultInApp,
          defaultEmail: entry.defaultEmail,
        });
        categoryHasUrgent.set(entry.category, entry.priority === NotificationPriority.URGENT);
      } else {
        const existing = categoryDefaults.get(entry.category)!;
        if (entry.defaultInApp) existing.defaultInApp = true;
        if (entry.defaultEmail) existing.defaultEmail = true;
        if (entry.priority === NotificationPriority.URGENT) {
          categoryHasUrgent.set(entry.category, true);
        }
      }
    }

    // Merge stored preferences with defaults
    const preferences: Array<{
      event_category: string;
      in_app_enabled: boolean;
      email_enabled: boolean;
      digest_mode: string;
      is_urgent: boolean;
    }> = [];

    for (const category of allCategories) {
      const storedPref = storedCategories.get(category);
      const defaults = categoryDefaults.get(category)!;
      const isUrgent = categoryHasUrgent.get(category) ?? false;

      preferences.push({
        event_category: category,
        in_app_enabled: storedPref ? storedPref.inAppEnabled : defaults.defaultInApp,
        email_enabled: storedPref ? storedPref.emailEnabled : defaults.defaultEmail,
        digest_mode: storedPref ? storedPref.digestMode : 'IMMEDIATE',
        is_urgent: isUrgent,
      });
    }

    // Get quiet hours from the first preference that has them, or null
    let quietHours: { start: string | null; end: string | null } = { start: null, end: null };
    for (const pref of stored) {
      if (pref.quietHoursStart && pref.quietHoursEnd) {
        quietHours = { start: pref.quietHoursStart, end: pref.quietHoursEnd };
        break;
      }
    }

    return reply.code(200).send({
      data: {
        preferences,
        quiet_hours: quietHours,
      },
    });
  }

  // -------------------------------------------------------------------------
  // PUT /api/v1/notification-preferences/:category
  // -------------------------------------------------------------------------

  async function updatePreferenceHandler(
    request: FastifyRequest<{ Params: PreferenceCategoryParam; Body: UpdatePreference }>,
    reply: FastifyReply,
  ) {
    const ctx = request.authContext;

    // Delegates cannot access preferences
    if (ctx.role?.toUpperCase() === 'DELEGATE') {
      throw new ForbiddenError('Delegates cannot access notification preferences');
    }

    const providerId = ctx.userId;
    const { category } = request.params;
    const body = request.body;

    // Validate category exists in EVENT_CATALOGUE
    const validCategories = new Set<string>();
    const categoryHasUrgent = new Map<string, boolean>();
    for (const [, entry] of Object.entries(EVENT_CATALOGUE)) {
      validCategories.add(entry.category);
      if (entry.priority === NotificationPriority.URGENT) {
        categoryHasUrgent.set(entry.category, true);
      }
    }

    if (!validCategories.has(category)) {
      throw new ValidationError(`Unknown event category: ${category}`);
    }

    // URGENT enforcement: cannot disable in_app for urgent event categories
    if (body.in_app_enabled === false && categoryHasUrgent.get(category)) {
      throw new ValidationError('Cannot disable in-app notifications for urgent events');
    }

    // Load old values for audit
    const oldPref = await deps.notificationRepo.findPreference(providerId, category);

    const updated = await deps.notificationRepo.upsertPreference(providerId, category, {
      inAppEnabled: body.in_app_enabled,
      emailEnabled: body.email_enabled,
      digestMode: body.digest_mode,
    });

    await deps.auditRepo.appendAuditLog({
      userId: ctx.userId,
      action: NotificationAuditAction.NOTIFICATION_PREFERENCE_UPDATED,
      category: 'notification',
      resourceType: 'notification_preference',
      resourceId: updated.preferenceId,
      detail: {
        event_category: category,
        old_values: oldPref
          ? {
              in_app_enabled: oldPref.inAppEnabled,
              email_enabled: oldPref.emailEnabled,
              digest_mode: oldPref.digestMode,
            }
          : null,
        new_values: {
          in_app_enabled: updated.inAppEnabled,
          email_enabled: updated.emailEnabled,
          digest_mode: updated.digestMode,
        },
      },
    });

    return reply.code(200).send({
      data: {
        preference_id: updated.preferenceId,
        event_category: updated.eventCategory,
        in_app_enabled: updated.inAppEnabled,
        email_enabled: updated.emailEnabled,
        digest_mode: updated.digestMode,
        quiet_hours_start: updated.quietHoursStart ?? null,
        quiet_hours_end: updated.quietHoursEnd ?? null,
      },
    });
  }

  // -------------------------------------------------------------------------
  // PUT /api/v1/notification-preferences/quiet-hours
  // -------------------------------------------------------------------------

  async function updateQuietHoursHandler(
    request: FastifyRequest<{ Body: QuietHours }>,
    reply: FastifyReply,
  ) {
    const ctx = request.authContext;

    // Delegates cannot access preferences
    if (ctx.role?.toUpperCase() === 'DELEGATE') {
      throw new ForbiddenError('Delegates cannot access notification preferences');
    }

    const providerId = ctx.userId;
    const { quiet_hours_start, quiet_hours_end } = request.body;

    // Load old values for audit
    const oldPrefs = await deps.notificationRepo.findPreferencesByProvider(providerId);
    let oldQuietHours: { start: string | null; end: string | null } = { start: null, end: null };
    for (const pref of oldPrefs) {
      if (pref.quietHoursStart && pref.quietHoursEnd) {
        oldQuietHours = { start: pref.quietHoursStart, end: pref.quietHoursEnd };
        break;
      }
    }

    await deps.notificationRepo.updateQuietHours(
      providerId,
      quiet_hours_start,
      quiet_hours_end,
    );

    await deps.auditRepo.appendAuditLog({
      userId: ctx.userId,
      action: NotificationAuditAction.NOTIFICATION_QUIET_HOURS_UPDATED,
      category: 'notification',
      resourceType: 'notification_preference',
      detail: {
        old_values: oldQuietHours,
        new_values: { start: quiet_hours_start, end: quiet_hours_end },
      },
    });

    return reply.code(200).send({
      data: {
        success: true,
        quiet_hours: {
          start: quiet_hours_start,
          end: quiet_hours_end,
        },
      },
    });
  }

  return {
    listNotificationsHandler,
    unreadCountHandler,
    markReadHandler,
    markAllReadHandler,
    dismissHandler,
    getPreferencesHandler,
    updatePreferenceHandler,
    updateQuietHoursHandler,
  };
}

// ---------------------------------------------------------------------------
// Internal API Key Verification (constant-time comparison)
// ---------------------------------------------------------------------------

/**
 * Verify the X-Internal-API-Key header against process.env.INTERNAL_API_KEY.
 * Uses constant-time comparison to prevent timing attacks.
 */
export function verifyInternalApiKey(
  request: FastifyRequest,
  reply: FastifyReply,
): boolean {
  const apiKey = request.headers['x-internal-api-key'] as string | undefined;
  const expectedKey = process.env.INTERNAL_API_KEY;

  if (!apiKey || !expectedKey) {
    reply.code(401).send({
      error: { code: 'UNAUTHORIZED', message: 'Authentication required' },
    });
    return false;
  }

  const keyBuffer = Buffer.from(apiKey);
  const expectedBuffer = Buffer.from(expectedKey);

  if (keyBuffer.length !== expectedBuffer.length) {
    reply.code(401).send({
      error: { code: 'UNAUTHORIZED', message: 'Authentication required' },
    });
    return false;
  }

  if (!timingSafeEqual(keyBuffer, expectedBuffer)) {
    reply.code(401).send({
      error: { code: 'UNAUTHORIZED', message: 'Authentication required' },
    });
    return false;
  }

  return true;
}

// ---------------------------------------------------------------------------
// Internal Emit Handlers
// ---------------------------------------------------------------------------

export interface InternalNotificationHandlerDeps {
  serviceDeps: NotificationServiceDeps;
}

export function createInternalNotificationHandlers(deps: InternalNotificationHandlerDeps) {
  /**
   * POST /api/v1/internal/notifications/emit
   * Emit a single event. Protected by internal API key.
   */
  async function emitHandler(
    request: FastifyRequest<{ Body: EmitEvent }>,
    reply: FastifyReply,
  ) {
    if (!verifyInternalApiKey(request, reply)) return;

    const { event_type, physician_id, metadata } = request.body;

    const notifications = await processEvent(deps.serviceDeps, {
      eventType: event_type,
      physicianId: physician_id,
      metadata,
    });

    return reply.code(200).send({
      data: {
        notification_ids: notifications.map((n) => n.notificationId),
      },
    });
  }

  /**
   * POST /api/v1/internal/notifications/emit-batch
   * Emit multiple events at once. Protected by internal API key.
   */
  async function emitBatchHandler(
    request: FastifyRequest<{ Body: EmitBatchEvent }>,
    reply: FastifyReply,
  ) {
    if (!verifyInternalApiKey(request, reply)) return;

    const { events } = request.body;

    const allNotifications = await processEventBatch(
      deps.serviceDeps,
      events.map((e) => ({
        eventType: e.event_type,
        physicianId: e.physician_id,
        metadata: e.metadata,
      })),
    );

    return reply.code(200).send({
      data: {
        created_count: allNotifications.length,
      },
    });
  }

  return {
    emitHandler,
    emitBatchHandler,
  };
}

// ---------------------------------------------------------------------------
// Postmark Webhook Handler
// ---------------------------------------------------------------------------

export interface PostmarkWebhookHandlerDeps {
  serviceDeps: NotificationServiceDeps;
  webhookSecret: string;
}

/**
 * Verify Postmark webhook signature using HMAC-SHA256 and constant-time comparison.
 */
function verifyPostmarkSignature(
  rawBody: string,
  signature: string,
  secret: string,
): boolean {
  const computed = createHmac('sha256', secret).update(rawBody).digest('base64');
  const computedBuf = Buffer.from(computed);
  const signatureBuf = Buffer.from(signature);

  if (computedBuf.length !== signatureBuf.length) {
    return false;
  }

  return timingSafeEqual(computedBuf, signatureBuf);
}

export function createPostmarkWebhookHandlers(deps: PostmarkWebhookHandlerDeps) {
  /**
   * POST /api/v1/webhooks/postmark
   * Handle delivery/bounce callbacks from Postmark.
   */
  async function postmarkWebhookHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const signature = request.headers['x-postmark-signature'] as string | undefined;

    if (!signature) {
      return reply.code(401).send({
        error: { code: 'UNAUTHORIZED', message: 'Missing webhook signature' },
      });
    }

    const rawBody = JSON.stringify(request.body);

    if (!verifyPostmarkSignature(rawBody, signature, deps.webhookSecret)) {
      return reply.code(401).send({
        error: { code: 'UNAUTHORIZED', message: 'Invalid webhook signature' },
      });
    }

    const payload = request.body as Record<string, unknown>;
    const recordType = payload.RecordType as string | undefined;

    if (recordType === 'Delivery') {
      const messageId = payload.MessageID as string;
      const deliveredAt = payload.DeliveredAt as string | undefined;

      if (messageId) {
        const delivery = await deps.serviceDeps.notificationRepo.findDeliveryLogByProviderMessageId(messageId);
        if (delivery) {
          await deps.serviceDeps.notificationRepo.updateDeliveryStatus(
            delivery.deliveryId,
            'DELIVERED',
            { deliveredAt: deliveredAt ? new Date(deliveredAt) : new Date() },
          );
        }
      }
    } else if (recordType === 'Bounce') {
      const messageId = payload.MessageID as string;
      const typeCode = payload.TypeCode as number | undefined;
      const description = (payload.Description as string) ?? 'Unknown bounce';

      // Postmark TypeCode: 1 = HardBounce, others are soft
      const bounceType: 'hard' | 'soft' = typeCode === 1 ? 'hard' : 'soft';

      if (messageId) {
        await handleBounce(deps.serviceDeps, messageId, bounceType, description);
      }
    }

    return reply.code(200).send({ ok: true });
  }

  return {
    postmarkWebhookHandler,
  };
}
