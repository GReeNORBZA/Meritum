import { type FastifyInstance } from 'fastify';
import {
  notificationFeedQuerySchema,
  notificationIdParamSchema,
  updatePreferenceSchema,
  preferenceCategoryParamSchema,
  quietHoursSchema,
  emitEventSchema,
  emitBatchEventSchema,
} from '@meritum/shared/schemas/notification.schema.js';
import {
  createNotificationHandlers,
  createInternalNotificationHandlers,
  createPostmarkWebhookHandlers,
  type NotificationHandlerDeps,
  type InternalNotificationHandlerDeps,
  type PostmarkWebhookHandlerDeps,
} from './notification.handlers.js';
import {
  registerNotificationWebSocket,
  type WsSessionValidator,
} from './notification.service.js';

// ---------------------------------------------------------------------------
// Notification Feed Routes
// ---------------------------------------------------------------------------

export async function notificationRoutes(
  app: FastifyInstance,
  opts: { deps: NotificationHandlerDeps },
) {
  const handlers = createNotificationHandlers(opts.deps);

  // GET /api/v1/notifications — notification feed
  app.get('/api/v1/notifications', {
    schema: { querystring: notificationFeedQuerySchema },
    preHandler: [app.authenticate],
    handler: handlers.listNotificationsHandler,
  });

  // GET /api/v1/notifications/unread-count — badge count
  app.get('/api/v1/notifications/unread-count', {
    preHandler: [app.authenticate],
    handler: handlers.unreadCountHandler,
  });

  // POST /api/v1/notifications/read-all — mark all as read
  // NOTE: registered BEFORE /:id routes to avoid Fastify treating "read-all" as an :id param
  app.post('/api/v1/notifications/read-all', {
    preHandler: [app.authenticate],
    handler: handlers.markAllReadHandler,
  });

  // POST /api/v1/notifications/:id/read — mark single as read
  app.post('/api/v1/notifications/:id/read', {
    schema: { params: notificationIdParamSchema },
    preHandler: [app.authenticate],
    handler: handlers.markReadHandler,
  });

  // POST /api/v1/notifications/:id/dismiss — dismiss notification
  app.post('/api/v1/notifications/:id/dismiss', {
    schema: { params: notificationIdParamSchema },
    preHandler: [app.authenticate],
    handler: handlers.dismissHandler,
  });

  // =========================================================================
  // Notification Preference Routes
  // =========================================================================

  // GET /api/v1/notification-preferences — get all preferences
  app.get('/api/v1/notification-preferences', {
    preHandler: [app.authenticate],
    handler: handlers.getPreferencesHandler,
  });

  // PUT /api/v1/notification-preferences/quiet-hours — set quiet hours
  // NOTE: registered BEFORE /:category to avoid Fastify treating "quiet-hours" as a :category param
  app.put('/api/v1/notification-preferences/quiet-hours', {
    schema: { body: quietHoursSchema },
    preHandler: [app.authenticate],
    handler: handlers.updateQuietHoursHandler,
  });

  // PUT /api/v1/notification-preferences/:category — update category preference
  app.put('/api/v1/notification-preferences/:category', {
    schema: {
      params: preferenceCategoryParamSchema,
      body: updatePreferenceSchema,
    },
    preHandler: [app.authenticate],
    handler: handlers.updatePreferenceHandler,
  });
}

// ---------------------------------------------------------------------------
// Internal Notification Routes (API key auth, no session)
// ---------------------------------------------------------------------------

export async function internalNotificationRoutes(
  app: FastifyInstance,
  opts: { deps: InternalNotificationHandlerDeps },
) {
  const handlers = createInternalNotificationHandlers(opts.deps);

  // POST /api/v1/internal/notifications/emit — emit single event
  app.post('/api/v1/internal/notifications/emit', {
    schema: { body: emitEventSchema },
    handler: handlers.emitHandler,
  });

  // POST /api/v1/internal/notifications/emit-batch — emit batch events
  app.post('/api/v1/internal/notifications/emit-batch', {
    schema: { body: emitBatchEventSchema },
    handler: handlers.emitBatchHandler,
  });
}

// ---------------------------------------------------------------------------
// WebSocket Route
// ---------------------------------------------------------------------------

export async function notificationWebSocketRoutes(
  app: FastifyInstance,
  opts: {
    sessionValidator: WsSessionValidator;
    hashTokenFn: (token: string) => string;
  },
) {
  registerNotificationWebSocket(app as any, opts.sessionValidator, opts.hashTokenFn);
}

// ---------------------------------------------------------------------------
// Postmark Webhook Route
// ---------------------------------------------------------------------------

export async function postmarkWebhookRoutes(
  app: FastifyInstance,
  opts: { deps: PostmarkWebhookHandlerDeps },
) {
  const handlers = createPostmarkWebhookHandlers(opts.deps);

  // POST /api/v1/webhooks/postmark — delivery/bounce callbacks
  app.post('/api/v1/webhooks/postmark', {
    handler: handlers.postmarkWebhookHandler,
  });
}
