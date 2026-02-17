import { type FastifyInstance } from 'fastify';
import {
  registerSchema,
  verifyEmailSchema,
  loginSchema,
  loginMfaSchema,
  loginRecoverySchema,
  passwordResetRequestSchema,
  passwordResetSchema,
  mfaConfirmSchema,
  sessionIdParamSchema,
  delegateInviteSchema,
  delegateUpdatePermissionsSchema,
  delegateAcceptSchema,
  delegateIdParamSchema,
  accountUpdateSchema,
  accountDeleteSchema,
  mfaReconfigureSchema,
  auditLogQuerySchema,
} from '@meritum/shared/schemas/iam.schema.js';
import { authRateLimit } from '../../plugins/rate-limit.plugin.js';
import { createAuthHandlers, type AuthHandlerDeps } from './iam.handlers.js';
import { Role } from '@meritum/shared/constants/iam.constants.js';

// ---------------------------------------------------------------------------
// Role-checking preHandler helpers
// ---------------------------------------------------------------------------

function requireRole(...roles: string[]) {
  return async function requireRoleHandler(request: any, reply: any) {
    const ctx = request.authContext;
    if (!ctx) {
      reply.code(401).send({
        error: { code: 'UNAUTHORIZED', message: 'Authentication required' },
      });
      return;
    }
    const userRole = ctx.role?.toUpperCase();
    if (!roles.map((r) => r.toUpperCase()).includes(userRole)) {
      reply.code(403).send({
        error: { code: 'FORBIDDEN', message: 'Insufficient permissions' },
      });
      return;
    }
  };
}

// ---------------------------------------------------------------------------
// IAM Auth Routes
// ---------------------------------------------------------------------------

export async function iamAuthRoutes(app: FastifyInstance, opts: { deps: AuthHandlerDeps }) {
  const handlers = createAuthHandlers(opts.deps);

  // ===== Public auth routes (no auth required, auth rate-limited) =====

  app.post('/api/v1/auth/register', {
    schema: { body: registerSchema },
    config: { rateLimit: authRateLimit() },
    handler: handlers.registerHandler,
  });

  app.post('/api/v1/auth/verify-email', {
    schema: { body: verifyEmailSchema },
    config: { rateLimit: authRateLimit() },
    handler: handlers.verifyEmailHandler,
  });

  app.post('/api/v1/auth/login', {
    schema: { body: loginSchema },
    config: { rateLimit: authRateLimit() },
    handler: handlers.loginStep1Handler,
  });

  app.post('/api/v1/auth/login/mfa', {
    schema: { body: loginMfaSchema },
    config: { rateLimit: authRateLimit() },
    handler: handlers.loginStep2MfaHandler,
  });

  app.post('/api/v1/auth/login/recovery', {
    schema: { body: loginRecoverySchema },
    config: { rateLimit: authRateLimit() },
    handler: handlers.loginStep2RecoveryHandler,
  });

  app.post('/api/v1/auth/password/reset-request', {
    schema: { body: passwordResetRequestSchema },
    config: { rateLimit: authRateLimit() },
    handler: handlers.passwordResetRequestHandler,
  });

  app.post('/api/v1/auth/password/reset', {
    schema: { body: passwordResetSchema },
    config: { rateLimit: authRateLimit() },
    handler: handlers.passwordResetHandler,
  });

  // ===== Authenticated auth routes =====

  app.post('/api/v1/auth/mfa/setup', {
    preHandler: [app.authenticate],
    config: { rateLimit: authRateLimit() },
    handler: handlers.mfaSetupHandler,
  });

  app.post('/api/v1/auth/mfa/confirm', {
    schema: { body: mfaConfirmSchema },
    preHandler: [app.authenticate],
    config: { rateLimit: authRateLimit() },
    handler: handlers.mfaConfirmHandler,
  });

  app.post('/api/v1/auth/logout', {
    preHandler: [app.authenticate],
    handler: handlers.logoutHandler,
  });

  // ===== Session routes (auth required) =====

  app.get('/api/v1/sessions', {
    preHandler: [app.authenticate],
    handler: handlers.listSessionsHandler,
  });

  app.delete('/api/v1/sessions/:id', {
    schema: { params: sessionIdParamSchema },
    preHandler: [app.authenticate],
    handler: handlers.revokeSessionHandler,
  });

  app.delete('/api/v1/sessions', {
    preHandler: [app.authenticate],
    handler: handlers.revokeAllSessionsHandler,
  });

  // ===== Delegate routes =====

  // Public: accept invitation (no auth required)
  app.post('/api/v1/delegates/accept', {
    schema: { body: delegateAcceptSchema },
    config: { rateLimit: authRateLimit() },
    handler: handlers.acceptHandler,
  });

  // Physician-only delegate management routes
  app.post('/api/v1/delegates/invite', {
    schema: { body: delegateInviteSchema },
    preHandler: [app.authenticate, requireRole(Role.PHYSICIAN, Role.ADMIN)],
    handler: handlers.inviteHandler,
  });

  app.get('/api/v1/delegates', {
    preHandler: [app.authenticate, requireRole(Role.PHYSICIAN, Role.ADMIN)],
    handler: handlers.listDelegatesHandler,
  });

  app.patch('/api/v1/delegates/:id/permissions', {
    schema: { params: delegateIdParamSchema, body: delegateUpdatePermissionsSchema },
    preHandler: [app.authenticate, requireRole(Role.PHYSICIAN, Role.ADMIN)],
    handler: handlers.updatePermissionsHandler,
  });

  app.delete('/api/v1/delegates/:id', {
    schema: { params: delegateIdParamSchema },
    preHandler: [app.authenticate, requireRole(Role.PHYSICIAN, Role.ADMIN)],
    handler: handlers.revokeHandler,
  });

  // Delegate-only: list linked physicians
  app.get('/api/v1/delegates/physicians', {
    preHandler: [app.authenticate, requireRole(Role.DELEGATE)],
    handler: handlers.listPhysiciansHandler,
  });

  // ===== Account routes (auth required) =====

  app.get('/api/v1/account', {
    preHandler: [app.authenticate],
    handler: handlers.getAccountHandler,
  });

  app.patch('/api/v1/account', {
    schema: { body: accountUpdateSchema },
    preHandler: [app.authenticate],
    handler: handlers.updateAccountHandler,
  });

  app.post('/api/v1/account/mfa/regenerate-codes', {
    schema: { body: mfaConfirmSchema },
    preHandler: [app.authenticate],
    handler: handlers.regenerateCodesHandler,
  });

  app.post('/api/v1/account/mfa/reconfigure', {
    schema: { body: mfaReconfigureSchema },
    preHandler: [app.authenticate],
    handler: handlers.reconfigureMfaHandler,
  });

  app.post('/api/v1/account/delete', {
    schema: { body: accountDeleteSchema },
    preHandler: [app.authenticate, requireRole(Role.PHYSICIAN, Role.ADMIN)],
    handler: handlers.deleteAccountHandler,
  });

  app.get('/api/v1/account/audit-log', {
    schema: { querystring: auditLogQuerySchema },
    preHandler: [app.authenticate, requireRole(Role.PHYSICIAN, Role.ADMIN)],
    handler: handlers.auditLogHandler,
  });
}
