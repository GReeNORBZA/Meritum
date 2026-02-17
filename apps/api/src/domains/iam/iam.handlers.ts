import { type FastifyRequest, type FastifyReply } from 'fastify';
import {
  type Register,
  type VerifyEmail,
  type Login,
  type LoginMfa,
  type LoginRecovery,
  type PasswordResetRequest,
  type PasswordReset,
  type MfaConfirm,
  type SessionIdParam,
  type DelegateInvite,
  type DelegateUpdatePermissions,
  type DelegateAccept,
  type DelegateIdParam,
  type AccountUpdate,
  type AccountDelete,
  type MfaReconfigure,
  type AuditLogQuery,
} from '@meritum/shared/schemas/iam.schema.js';
import {
  registerUser,
  verifyEmail,
  initiateMfaSetup,
  confirmMfaSetup,
  loginStep1,
  loginStep2Mfa,
  loginStep2Recovery,
  requestPasswordReset,
  resetPassword,
  logout,
  listSessions,
  revokeSession,
  revokeAllSessions,
  inviteDelegate,
  acceptInvitation,
  listDelegates,
  updateDelegatePermissions,
  revokeDelegate,
  listPhysiciansForDelegate,
  getAccount,
  updateAccount,
  requestAccountDeletion,
  regenerateRecoveryCodes,
  reconfigureMfa,
  queryAuditLog,
  type ServiceDeps,
  type MfaServiceDeps,
  type LoginServiceDeps,
  type PasswordResetDeps,
  type SessionManagementDeps,
  type DelegateServiceDeps,
  type AccountServiceDeps,
  type AuditLogServiceDeps,
} from './iam.service.js';
import { AppError } from '../../lib/errors.js';

// ---------------------------------------------------------------------------
// Session cookie constants
// ---------------------------------------------------------------------------

const SESSION_COOKIE_NAME = 'session';
const SESSION_COOKIE_MAX_AGE = 86400; // 24 hours in seconds

function setSessionCookie(reply: FastifyReply, token: string): void {
  reply.header(
    'Set-Cookie',
    `${SESSION_COOKIE_NAME}=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_COOKIE_MAX_AGE}`,
  );
}

function clearSessionCookie(reply: FastifyReply): void {
  reply.header(
    'Set-Cookie',
    `${SESSION_COOKIE_NAME}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`,
  );
}

// ---------------------------------------------------------------------------
// Handler factory — creates all auth handlers with injected dependencies
// ---------------------------------------------------------------------------

export interface AuthHandlerDeps {
  serviceDeps: ServiceDeps;
  mfaDeps: MfaServiceDeps;
  loginDeps: LoginServiceDeps;
  passwordResetDeps: PasswordResetDeps;
  sessionDeps: SessionManagementDeps;
  delegateDeps: DelegateServiceDeps;
  accountDeps: AccountServiceDeps;
  auditLogDeps: AuditLogServiceDeps;
}

export function createAuthHandlers(deps: AuthHandlerDeps) {
  // -------------------------------------------------------------------------
  // POST /api/v1/auth/register
  // -------------------------------------------------------------------------

  async function registerHandler(
    request: FastifyRequest<{ Body: Register }>,
    reply: FastifyReply,
  ) {
    const result = await registerUser(deps.serviceDeps, request.body);
    return reply.code(201).send({ data: result });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/auth/verify-email
  // -------------------------------------------------------------------------

  async function verifyEmailHandler(
    request: FastifyRequest<{ Body: VerifyEmail }>,
    reply: FastifyReply,
  ) {
    const result = await verifyEmail(deps.serviceDeps, request.body.token);
    return reply.code(200).send({ data: result });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/auth/login
  // -------------------------------------------------------------------------

  async function loginStep1Handler(
    request: FastifyRequest<{ Body: Login }>,
    reply: FastifyReply,
  ) {
    const result = await loginStep1(
      deps.loginDeps,
      request.body.email,
      request.body.password,
      request.ip,
    );
    return reply.code(200).send({ data: result });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/auth/login/mfa
  // -------------------------------------------------------------------------

  async function loginStep2MfaHandler(
    request: FastifyRequest<{ Body: LoginMfa }>,
    reply: FastifyReply,
  ) {
    const result = await loginStep2Mfa(
      deps.loginDeps,
      request.body.mfa_session_token,
      request.body.totp_code,
      request.ip,
      request.headers['user-agent'] ?? '',
    );
    setSessionCookie(reply, result.session_token);
    return reply.code(200).send({
      data: { message: 'Login successful' },
    });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/auth/login/recovery
  // -------------------------------------------------------------------------

  async function loginStep2RecoveryHandler(
    request: FastifyRequest<{ Body: LoginRecovery }>,
    reply: FastifyReply,
  ) {
    const result = await loginStep2Recovery(
      deps.loginDeps,
      request.body.mfa_session_token,
      request.body.recovery_code,
      request.ip,
      request.headers['user-agent'] ?? '',
    );
    setSessionCookie(reply, result.session_token);
    return reply.code(200).send({
      data: {
        message: 'Login successful',
        remaining_codes: result.remaining_codes,
      },
    });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/auth/password/reset-request
  // -------------------------------------------------------------------------

  async function passwordResetRequestHandler(
    request: FastifyRequest<{ Body: PasswordResetRequest }>,
    reply: FastifyReply,
  ) {
    await requestPasswordReset(deps.passwordResetDeps, request.body.email);
    return reply.code(200).send({
      data: { message: 'If an account exists, a password reset email has been sent.' },
    });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/auth/password/reset
  // -------------------------------------------------------------------------

  async function passwordResetHandler(
    request: FastifyRequest<{ Body: PasswordReset }>,
    reply: FastifyReply,
  ) {
    await resetPassword(
      deps.passwordResetDeps,
      request.body.token,
      request.body.new_password,
    );
    return reply.code(200).send({
      data: { message: 'Password has been reset. Please log in again.' },
    });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/auth/mfa/setup (requires auth)
  // -------------------------------------------------------------------------

  async function mfaSetupHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const result = await initiateMfaSetup(
      deps.mfaDeps,
      request.authContext.userId,
    );
    return reply.code(200).send({ data: result });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/auth/mfa/confirm (requires auth)
  // -------------------------------------------------------------------------

  async function mfaConfirmHandler(
    request: FastifyRequest<{ Body: MfaConfirm }>,
    reply: FastifyReply,
  ) {
    const result = await confirmMfaSetup(
      deps.mfaDeps,
      request.authContext.userId,
      request.body.totp_code,
    );
    return reply.code(200).send({ data: result });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/auth/logout (requires auth)
  // -------------------------------------------------------------------------

  async function logoutHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    await logout(
      deps.sessionDeps,
      request.authContext.sessionId,
      request.authContext.userId,
    );
    clearSessionCookie(reply);
    return reply.code(200).send({
      data: { message: 'Logged out successfully' },
    });
  }

  // =========================================================================
  // Session Management Handlers
  // =========================================================================

  // -------------------------------------------------------------------------
  // GET /api/v1/sessions
  // -------------------------------------------------------------------------

  async function listSessionsHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const sessions = await listSessions(
      deps.sessionDeps,
      request.authContext.userId,
    );
    return reply.code(200).send({ data: sessions });
  }

  // -------------------------------------------------------------------------
  // DELETE /api/v1/sessions/:id
  // -------------------------------------------------------------------------

  async function revokeSessionHandler(
    request: FastifyRequest<{ Params: SessionIdParam }>,
    reply: FastifyReply,
  ) {
    await revokeSession(
      deps.sessionDeps,
      request.authContext.userId,
      request.params.id,
    );
    return reply.code(204).send();
  }

  // -------------------------------------------------------------------------
  // DELETE /api/v1/sessions
  // -------------------------------------------------------------------------

  async function revokeAllSessionsHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    await revokeAllSessions(
      deps.sessionDeps,
      request.authContext.userId,
      request.authContext.sessionId,
    );
    return reply.code(200).send({
      data: { message: 'All other sessions have been revoked' },
    });
  }

  // =========================================================================
  // Delegate Management Handlers
  // =========================================================================

  // -------------------------------------------------------------------------
  // POST /api/v1/delegates/invite
  // -------------------------------------------------------------------------

  async function inviteHandler(
    request: FastifyRequest<{ Body: DelegateInvite }>,
    reply: FastifyReply,
  ) {
    const result = await inviteDelegate(
      deps.delegateDeps,
      request.authContext.userId,
      request.body.email,
      request.body.permissions,
    );
    return reply.code(201).send({ data: result });
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/delegates
  // -------------------------------------------------------------------------

  async function listDelegatesHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const delegates = await listDelegates(
      deps.delegateDeps,
      request.authContext.userId,
    );
    return reply.code(200).send({ data: delegates });
  }

  // -------------------------------------------------------------------------
  // PATCH /api/v1/delegates/:id/permissions
  // -------------------------------------------------------------------------

  async function updatePermissionsHandler(
    request: FastifyRequest<{ Params: DelegateIdParam; Body: DelegateUpdatePermissions }>,
    reply: FastifyReply,
  ) {
    const result = await updateDelegatePermissions(
      deps.delegateDeps,
      request.authContext.userId,
      request.params.id,
      request.body.permissions,
      false,
    );
    return reply.code(200).send({ data: result });
  }

  // -------------------------------------------------------------------------
  // DELETE /api/v1/delegates/:id
  // -------------------------------------------------------------------------

  async function revokeHandler(
    request: FastifyRequest<{ Params: DelegateIdParam }>,
    reply: FastifyReply,
  ) {
    await revokeDelegate(
      deps.delegateDeps,
      request.authContext.userId,
      request.params.id,
    );
    return reply.code(204).send();
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/delegates/accept (no auth required)
  // -------------------------------------------------------------------------

  async function acceptHandler(
    request: FastifyRequest<{ Body: DelegateAccept }>,
    reply: FastifyReply,
  ) {
    const registrationData = request.body.full_name && request.body.password
      ? { fullName: request.body.full_name, password: request.body.password }
      : undefined;

    const result = await acceptInvitation(
      deps.delegateDeps,
      request.body.token,
      registrationData,
    );
    return reply.code(200).send({ data: result });
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/delegates/physicians (delegate role)
  // -------------------------------------------------------------------------

  async function listPhysiciansHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const physicians = await listPhysiciansForDelegate(
      deps.delegateDeps,
      request.authContext.userId,
    );
    return reply.code(200).send({ data: physicians });
  }

  // =========================================================================
  // Account Management Handlers
  // =========================================================================

  // -------------------------------------------------------------------------
  // GET /api/v1/account
  // -------------------------------------------------------------------------

  async function getAccountHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const account = await getAccount(
      deps.accountDeps,
      request.authContext.userId,
    );
    return reply.code(200).send({ data: account });
  }

  // -------------------------------------------------------------------------
  // PATCH /api/v1/account
  // -------------------------------------------------------------------------

  async function updateAccountHandler(
    request: FastifyRequest<{ Body: AccountUpdate }>,
    reply: FastifyReply,
  ) {
    const result = await updateAccount(
      deps.accountDeps,
      request.authContext.userId,
      request.body,
    );
    return reply.code(200).send({ data: result });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/account/mfa/regenerate-codes
  // -------------------------------------------------------------------------

  async function regenerateCodesHandler(
    request: FastifyRequest<{ Body: MfaConfirm }>,
    reply: FastifyReply,
  ) {
    const result = await regenerateRecoveryCodes(
      deps.mfaDeps,
      request.authContext.userId,
      request.body.totp_code,
    );
    return reply.code(200).send({ data: result });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/account/mfa/reconfigure
  // -------------------------------------------------------------------------

  async function reconfigureMfaHandler(
    request: FastifyRequest<{ Body: MfaReconfigure }>,
    reply: FastifyReply,
  ) {
    const result = await reconfigureMfa(
      deps.mfaDeps,
      request.authContext.userId,
      request.body.current_totp_code,
    );
    return reply.code(200).send({ data: result });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/account/delete
  // -------------------------------------------------------------------------

  async function deleteAccountHandler(
    request: FastifyRequest<{ Body: AccountDelete }>,
    reply: FastifyReply,
  ) {
    const result = await requestAccountDeletion(
      deps.accountDeps,
      request.authContext.userId,
      request.body.password,
      request.body.totp_code,
      request.body.confirmation,
    );
    return reply.code(200).send({ data: result });
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/account/audit-log
  // -------------------------------------------------------------------------

  async function auditLogHandler(
    request: FastifyRequest<{ Querystring: AuditLogQuery }>,
    reply: FastifyReply,
  ) {
    const query = request.query;
    const result = await queryAuditLog(
      deps.auditLogDeps,
      request.authContext.userId,
      {
        action: query.action,
        category: query.category,
        startDate: query.start_date,
        endDate: query.end_date,
        page: query.page,
        pageSize: query.page_size,
      },
    );
    return reply.code(200).send(result);
  }

  return {
    registerHandler,
    verifyEmailHandler,
    loginStep1Handler,
    loginStep2MfaHandler,
    loginStep2RecoveryHandler,
    passwordResetRequestHandler,
    passwordResetHandler,
    mfaSetupHandler,
    mfaConfirmHandler,
    logoutHandler,
    // Session management
    listSessionsHandler,
    revokeSessionHandler,
    revokeAllSessionsHandler,
    // Delegate management
    inviteHandler,
    listDelegatesHandler,
    updatePermissionsHandler,
    revokeHandler,
    acceptHandler,
    listPhysiciansHandler,
    // Account management
    getAccountHandler,
    updateAccountHandler,
    regenerateCodesHandler,
    reconfigureMfaHandler,
    deleteAccountHandler,
    auditLogHandler,
  };
}
