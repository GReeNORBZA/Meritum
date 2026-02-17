import { type FastifyInstance, type FastifyRequest, type FastifyReply } from 'fastify';
import fp from 'fastify-plugin';
import { createHash } from 'node:crypto';
import { validateSession, type AuthContext } from '../domains/iam/iam.service.js';
import { type SessionManagementDeps } from '../domains/iam/iam.service.js';

// ---------------------------------------------------------------------------
// Type augmentation: add authContext to Fastify request
// ---------------------------------------------------------------------------

declare module 'fastify' {
  interface FastifyRequest {
    authContext: AuthContext;
  }
  interface FastifyInstance {
    authenticate: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
    authorize: (...permissions: string[]) => (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
    checkSubscription: (...statuses: string[]) => (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }
}

// ---------------------------------------------------------------------------
// Session cookie name
// ---------------------------------------------------------------------------

const SESSION_COOKIE_NAME = 'session';

// ---------------------------------------------------------------------------
// Sensitive body fields to strip from audit log
// ---------------------------------------------------------------------------

const SENSITIVE_BODY_FIELDS = new Set([
  'password',
  'new_password',
  'totp_code',
  'current_totp_code',
  'recovery_code',
  'mfa_session_token',
]);

// ---------------------------------------------------------------------------
// Helper: SHA-256 hash
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Helper: sanitize request body for audit logging
// ---------------------------------------------------------------------------

function sanitizeBody(body: unknown): Record<string, unknown> | undefined {
  if (!body || typeof body !== 'object') return undefined;
  const sanitized: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(body as Record<string, unknown>)) {
    if (SENSITIVE_BODY_FIELDS.has(key)) {
      sanitized[key] = '[REDACTED]';
    } else {
      sanitized[key] = value;
    }
  }
  return sanitized;
}

// ---------------------------------------------------------------------------
// Plugin: authenticate
// ---------------------------------------------------------------------------

export interface AuthPluginOptions {
  sessionDeps: SessionManagementDeps;
}

async function authPlugin(app: FastifyInstance, opts: AuthPluginOptions) {
  const { sessionDeps } = opts;

  /**
   * authenticate — preHandler that extracts session token from cookie,
   * validates it, and populates request.authContext.
   */
  app.decorate('authenticate', async function authenticate(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const cookieHeader = request.headers.cookie;
    if (!cookieHeader) {
      reply.code(401).send({
        error: { code: 'UNAUTHORIZED', message: 'Authentication required' },
      });
      return;
    }

    // Parse session token from cookie header
    const token = parseCookie(cookieHeader, SESSION_COOKIE_NAME);
    if (!token) {
      reply.code(401).send({
        error: { code: 'UNAUTHORIZED', message: 'Authentication required' },
      });
      return;
    }

    // Hash and validate
    const tokenHash = hashToken(token);
    const authContext = await validateSession(sessionDeps, tokenHash);

    if (!authContext) {
      reply.code(401).send({
        error: { code: 'UNAUTHORIZED', message: 'Invalid or expired session' },
      });
      return;
    }

    request.authContext = authContext;
  });

  /**
   * authorize — returns a preHandler that checks the user has all required permissions.
   *
   * Physicians and admins have all permissions (pass through).
   * Delegates must have every required permission in their delegateContext.
   */
  app.decorate('authorize', function authorize(
    ...requiredPermissions: string[]
  ) {
    return async function authorizeHandler(
      request: FastifyRequest,
      reply: FastifyReply,
    ) {
      const ctx = request.authContext;
      if (!ctx) {
        reply.code(401).send({
          error: { code: 'UNAUTHORIZED', message: 'Authentication required' },
        });
        return;
      }

      const role = ctx.role?.toUpperCase();

      // Physicians and admins have all permissions
      if (role === 'PHYSICIAN' || role === 'ADMIN') {
        return;
      }

      // Delegates must have matching permissions
      if (role === 'DELEGATE') {
        const delegateContext = (ctx as any).delegateContext;
        if (!delegateContext || !delegateContext.permissions) {
          reply.code(403).send({
            error: { code: 'FORBIDDEN', message: 'Insufficient permissions' },
          });
          return;
        }

        const delegatePerms = delegateContext.permissions as string[];
        const missing = requiredPermissions.filter(
          (p) => !delegatePerms.includes(p),
        );

        if (missing.length > 0) {
          reply.code(403).send({
            error: { code: 'FORBIDDEN', message: 'Insufficient permissions' },
          });
          return;
        }

        return;
      }

      // Unknown role — deny
      reply.code(403).send({
        error: { code: 'FORBIDDEN', message: 'Insufficient permissions' },
      });
    };
  });

  /**
   * checkSubscription — returns a preHandler that checks subscription status.
   *
   * If status is not in the allowedStatuses list:
   * - SUSPENDED → 402 ACCOUNT_SUSPENDED
   * - CANCELLED → 402 SUBSCRIPTION_REQUIRED
   * - anything else → 402 SUBSCRIPTION_REQUIRED
   */
  app.decorate('checkSubscription', function checkSubscription(
    ...allowedStatuses: string[]
  ) {
    return async function checkSubscriptionHandler(
      request: FastifyRequest,
      reply: FastifyReply,
    ) {
      const ctx = request.authContext;
      if (!ctx) {
        reply.code(401).send({
          error: { code: 'UNAUTHORIZED', message: 'Authentication required' },
        });
        return;
      }

      const status = ctx.subscriptionStatus;

      if (allowedStatuses.includes(status)) {
        return;
      }

      if (status === 'SUSPENDED') {
        reply.code(402).send({
          error: {
            code: 'ACCOUNT_SUSPENDED',
            message: 'Your account is suspended. Please contact support.',
          },
        });
        return;
      }

      // CANCELLED or any other non-allowed status
      reply.code(402).send({
        error: {
          code: 'SUBSCRIPTION_REQUIRED',
          message: 'An active subscription is required to access this resource.',
        },
      });
    };
  });
}

// ---------------------------------------------------------------------------
// Plugin: auditLog (onResponse hook)
// ---------------------------------------------------------------------------

export interface AuditLogPluginOptions {
  auditRepo: {
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
  };
}

async function auditLogPlugin(app: FastifyInstance, opts: AuditLogPluginOptions) {
  const { auditRepo } = opts;

  const STATE_CHANGING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

  app.addHook('onResponse', async (request, reply) => {
    // Only log state-changing requests by default
    const routeConfig = (request.routeOptions?.config as any) ?? {};
    const shouldLog = routeConfig.auditLog ?? STATE_CHANGING_METHODS.has(request.method);

    if (!shouldLog) return;

    const userId = request.authContext?.userId ?? null;
    const action = `${request.method} ${request.routeOptions?.url ?? request.url}`;

    try {
      await auditRepo.appendAuditLog({
        userId,
        action,
        category: 'http',
        detail: sanitizeBody(request.body),
        ipAddress: request.ip,
        userAgent: request.headers['user-agent'] ?? null,
      });
    } catch {
      // Audit logging failure should not break the request
      request.log.error('Failed to write audit log');
    }
  });
}

// ---------------------------------------------------------------------------
// Cookie parsing utility
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

export const authPluginFp = fp(authPlugin, {
  name: 'auth-plugin',
});

export const auditLogPluginFp = fp(auditLogPlugin, {
  name: 'audit-log-plugin',
});

// Named exports for direct use in tests
export { authPlugin, auditLogPlugin, parseCookie, sanitizeBody };
