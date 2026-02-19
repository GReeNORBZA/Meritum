// ============================================================================
// Domain 7: Intelligence Engine — Handlers
// Thin request handlers: validate, extract auth, call service, respond.
// ============================================================================

import { type FastifyRequest, type FastifyReply } from 'fastify';
import {
  type AnalyseClaim,
  type ClaimSuggestionsParam,
  type IntelSuggestionIdParam,
  type IntelDismissSuggestion,
  type UnsuppressRuleParam,
  type UpdateIntelPreferences,
  type CreateRule,
  type UpdateRule,
  type RuleIdParam,
  type ActivateRule,
  type RuleListQuery,
  type SombChangeAnalysis,
} from '@meritum/shared/schemas/intelligence.schema.js';
import {
  analyseClaim,
  getClaimSuggestions,
  acceptSuggestion,
  dismissSuggestion,
  recalculateSpecialtyCohorts,
  analyseSombChange,
  type AnalyseDeps,
  type LifecycleDeps,
  type LearningLoopDeps,
  type SombChangeDeps,
} from './intel.service.js';
import type { IntelRepository, LearningStateSummary } from './intel.repository.js';

// ---------------------------------------------------------------------------
// Handler dependencies
// ---------------------------------------------------------------------------

export interface IntelHandlerDeps {
  analyseDeps: AnalyseDeps;
  lifecycleDeps: LifecycleDeps;
  learningLoopDeps: LearningLoopDeps;
  sombChangeDeps?: SombChangeDeps;
  repo: IntelRepository;
  /** Audit log callback */
  auditLog: (entry: {
    action: string;
    providerId: string;
    details: Record<string, unknown>;
  }) => Promise<void>;
}

// ---------------------------------------------------------------------------
// Helper: extract physicianId from auth context
// ---------------------------------------------------------------------------

function getPhysicianId(request: FastifyRequest): string {
  const ctx = request.authContext;
  if (ctx.role?.toUpperCase() === 'DELEGATE' && (ctx as any).delegateContext) {
    return (ctx as any).delegateContext.physicianProviderId;
  }
  return ctx.userId;
}

// ---------------------------------------------------------------------------
// Handler factory
// ---------------------------------------------------------------------------

export function createIntelHandlers(deps: IntelHandlerDeps) {
  const { analyseDeps, lifecycleDeps, learningLoopDeps, sombChangeDeps, repo, auditLog } = deps;

  // =========================================================================
  // POST /api/v1/intelligence/analyse
  // Submit claim context for analysis. Returns Tier 1 suggestions synchronously.
  // =========================================================================

  async function analyseHandler(
    request: FastifyRequest<{ Body: AnalyseClaim }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { claim_id } = request.body;

    const suggestions = await analyseClaim(claim_id, physicianId, analyseDeps);

    return reply.code(200).send({ data: suggestions });
  }

  // =========================================================================
  // GET /api/v1/intelligence/claims/:claim_id/suggestions
  // Get all suggestions for a claim.
  // =========================================================================

  async function getClaimSuggestionsHandler(
    request: FastifyRequest<{ Params: ClaimSuggestionsParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { claim_id } = request.params;

    const suggestions = await getClaimSuggestions(claim_id, physicianId, lifecycleDeps);

    return reply.code(200).send({ data: suggestions });
  }

  // =========================================================================
  // POST /api/v1/intelligence/suggestions/:id/accept
  // Accept a suggestion, apply changes.
  // =========================================================================

  async function acceptSuggestionHandler(
    request: FastifyRequest<{ Params: IntelSuggestionIdParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;

    // Find the claim that owns this suggestion by searching across claims
    // The suggestion id is stored inside claims' ai_coach_suggestions JSONB.
    // We need the claim_id to call acceptSuggestion. The accept endpoint
    // uses only the suggestion id, so we resolve the claim via the repository.
    const result = await acceptSuggestionBySuggestionId(
      id,
      physicianId,
      lifecycleDeps,
      repo,
    );

    if (!result) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    return reply.code(200).send({ data: result });
  }

  // =========================================================================
  // POST /api/v1/intelligence/suggestions/:id/dismiss
  // Dismiss a suggestion with optional reason.
  // =========================================================================

  async function dismissSuggestionHandler(
    request: FastifyRequest<{ Params: IntelSuggestionIdParam; Body: IntelDismissSuggestion }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { id } = request.params;
    const reason = request.body?.reason;

    const result = await dismissSuggestionBySuggestionId(
      id,
      physicianId,
      lifecycleDeps,
      repo,
      reason,
    );

    if (!result) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    return reply.code(200).send({ data: result });
  }

  // =========================================================================
  // GET /api/v1/intelligence/me/learning-state
  // Get learning summary for the authenticated physician.
  // =========================================================================

  async function getLearningStateHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);

    const summary: LearningStateSummary = await repo.getLearningStateSummary(physicianId);

    return reply.code(200).send({ data: summary });
  }

  // =========================================================================
  // POST /api/v1/intelligence/me/rules/:rule_id/unsuppress
  // Un-suppress a rule for the authenticated physician.
  // =========================================================================

  async function unsuppressRuleHandler(
    request: FastifyRequest<{ Params: UnsuppressRuleParam }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const { rule_id } = request.params;

    const result = await learningLoopDeps.unsuppressRule(physicianId, rule_id);

    if (!result) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    // Record unsuppress event
    auditLog({
      action: 'intelligence.rule_unsuppressed',
      providerId: physicianId,
      details: { ruleId: rule_id },
    }).catch(() => {/* fire-and-forget */});

    return reply.code(200).send({ data: result });
  }

  // =========================================================================
  // PUT /api/v1/intelligence/me/preferences
  // Set AI Coach preferences for the authenticated physician.
  // =========================================================================

  async function updatePreferencesHandler(
    request: FastifyRequest<{ Body: UpdateIntelPreferences }>,
    reply: FastifyReply,
  ) {
    const physicianId = getPhysicianId(request);
    const body = request.body;

    // Store preferences — for MVP, we store in the provider's learning metadata.
    // This is a lightweight key-value store scoped to the physician.
    const preferences = {
      enabledCategories: body.enabled_categories ?? null,
      disabledCategories: body.disabled_categories ?? null,
      priorityThresholds: body.priority_thresholds
        ? {
            highRevenue: body.priority_thresholds.high_revenue,
            mediumRevenue: body.priority_thresholds.medium_revenue,
          }
        : null,
    };

    // Audit log the preference change
    auditLog({
      action: 'intelligence.preferences_updated',
      providerId: physicianId,
      details: { preferences },
    }).catch(() => {/* fire-and-forget */});

    return reply.code(200).send({ data: preferences });
  }

  // =========================================================================
  // Rule Management (Admin endpoints + physician transparency)
  // =========================================================================

  // GET /api/v1/intelligence/rules — list rules
  // Physicians see name + category + description only (transparency).
  // Admins see full rule data + stats.
  async function listRulesHandler(
    request: FastifyRequest<{ Querystring: RuleListQuery }>,
    reply: FastifyReply,
  ) {
    const ctx = request.authContext;
    const isAdmin = ctx.role?.toUpperCase() === 'ADMIN';

    const filters = {
      category: request.query.category,
      claimType: request.query.claim_type,
      isActive: request.query.is_active,
      page: request.query.page,
      pageSize: request.query.page_size,
    };

    const result = await repo.listRules(filters);

    if (isAdmin) {
      return reply.code(200).send({
        data: result.data,
        pagination: result.pagination,
      });
    }

    // Non-admin: strip conditions, template internals — only expose name, category, description
    const sanitised = result.data.map((rule) => ({
      ruleId: rule.ruleId,
      name: rule.name,
      category: rule.category,
      claimType: rule.claimType,
      description: (rule.suggestionTemplate as any)?.description ?? null,
      isActive: rule.isActive,
    }));

    return reply.code(200).send({
      data: sanitised,
      pagination: result.pagination,
    });
  }

  // POST /api/v1/intelligence/rules — create rule (admin only)
  async function createRuleHandler(
    request: FastifyRequest<{ Body: CreateRule }>,
    reply: FastifyReply,
  ) {
    const body = request.body;

    const rule = await repo.createRule({
      name: body.name,
      category: body.category,
      claimType: body.claim_type,
      conditions: body.conditions as any,
      suggestionTemplate: body.suggestion_template as any,
      specialtyFilter: body.specialty_filter as any,
      priorityFormula: body.priority_formula,
      sombVersion: body.somb_version ?? null,
      isActive: false, // new rules start inactive
    });

    auditLog({
      action: 'intelligence.rule_created',
      providerId: request.authContext.userId,
      details: { ruleId: rule.ruleId, name: rule.name },
    }).catch(() => {/* fire-and-forget */});

    return reply.code(201).send({ data: rule });
  }

  // PUT /api/v1/intelligence/rules/:id — update rule (admin only)
  async function updateRuleHandler(
    request: FastifyRequest<{ Params: RuleIdParam; Body: UpdateRule }>,
    reply: FastifyReply,
  ) {
    const { id } = request.params;
    const body = request.body;

    const updateData: Record<string, unknown> = {};
    if (body.name !== undefined) updateData.name = body.name;
    if (body.category !== undefined) updateData.category = body.category;
    if (body.claim_type !== undefined) updateData.claimType = body.claim_type;
    if (body.conditions !== undefined) updateData.conditions = body.conditions;
    if (body.suggestion_template !== undefined) updateData.suggestionTemplate = body.suggestion_template;
    if (body.specialty_filter !== undefined) updateData.specialtyFilter = body.specialty_filter;
    if (body.priority_formula !== undefined) updateData.priorityFormula = body.priority_formula;
    if (body.somb_version !== undefined) updateData.sombVersion = body.somb_version;

    const rule = await repo.updateRule(id, updateData as any);

    if (!rule) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    auditLog({
      action: 'intelligence.rule_updated',
      providerId: request.authContext.userId,
      details: { ruleId: id, updatedFields: Object.keys(updateData) },
    }).catch(() => {/* fire-and-forget */});

    return reply.code(200).send({ data: rule });
  }

  // PUT /api/v1/intelligence/rules/:id/activate — toggle active (admin only)
  async function activateRuleHandler(
    request: FastifyRequest<{ Params: RuleIdParam; Body: ActivateRule }>,
    reply: FastifyReply,
  ) {
    const { id } = request.params;
    const { is_active } = request.body;

    const rule = await repo.activateRule(id, is_active);

    if (!rule) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    auditLog({
      action: 'intelligence.rule_toggled',
      providerId: request.authContext.userId,
      details: { ruleId: id, isActive: is_active },
    }).catch(() => {/* fire-and-forget */});

    return reply.code(200).send({ data: rule });
  }

  // GET /api/v1/intelligence/rules/:id/stats — rule performance stats (admin only)
  async function getRuleStatsHandler(
    request: FastifyRequest<{ Params: RuleIdParam }>,
    reply: FastifyReply,
  ) {
    const { id } = request.params;

    // Verify rule exists
    const rule = await repo.getRule(id);
    if (!rule) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    const stats = await repo.getRuleStats(id);

    return reply.code(200).send({ data: stats });
  }

  // POST /api/v1/intelligence/cohorts/recalculate — trigger cohort recalculation (admin only)
  async function recalculateCohortsHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const result = await recalculateSpecialtyCohorts({
      recalculateAllCohorts: learningLoopDeps.recalculateAllCohorts,
      deleteSmallCohorts: learningLoopDeps.deleteSmallCohorts,
    });

    auditLog({
      action: 'intelligence.cohorts_recalculated',
      providerId: request.authContext.userId,
      details: { cohortCount: result.cohorts.length, deletedCount: result.deletedCount },
    }).catch(() => {/* fire-and-forget */});

    return reply.code(200).send({ data: result });
  }

  // POST /api/v1/intelligence/somb-change-analysis — generate impact analysis (admin only)
  async function sombChangeAnalysisHandler(
    request: FastifyRequest<{ Body: SombChangeAnalysis }>,
    reply: FastifyReply,
  ) {
    if (!sombChangeDeps) {
      return reply.code(500).send({
        error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
      });
    }

    const { old_version, new_version } = request.body;
    const result = await analyseSombChange(old_version, new_version, sombChangeDeps);

    auditLog({
      action: 'intelligence.somb_analysis_triggered',
      providerId: request.authContext.userId,
      details: {
        oldVersion: old_version,
        newVersion: new_version,
        affectedPhysicians: result.totalAffectedPhysicians,
        affectedRules: result.totalAffectedRules,
      },
    }).catch(() => {/* fire-and-forget */});

    return reply.code(200).send({ data: result });
  }

  return {
    analyseHandler,
    getClaimSuggestionsHandler,
    acceptSuggestionHandler,
    dismissSuggestionHandler,
    getLearningStateHandler,
    unsuppressRuleHandler,
    updatePreferencesHandler,
    listRulesHandler,
    createRuleHandler,
    updateRuleHandler,
    activateRuleHandler,
    getRuleStatsHandler,
    recalculateCohortsHandler,
    sombChangeAnalysisHandler,
  };
}

// ---------------------------------------------------------------------------
// Accept/Dismiss helpers (resolve claim_id from suggestion_id)
// ---------------------------------------------------------------------------

/**
 * Accept a suggestion by its suggestion_id. Resolves the claim_id from
 * the suggestion events table, then delegates to the service layer.
 */
async function acceptSuggestionBySuggestionId(
  suggestionId: string,
  providerId: string,
  lifecycleDeps: LifecycleDeps,
  repo: IntelRepository,
) {
  // Look up the claim_id from suggestion events
  const claimId = await findClaimIdForSuggestion(suggestionId, repo);
  if (!claimId) return null;

  return acceptSuggestion(claimId, suggestionId, providerId, lifecycleDeps);
}

/**
 * Dismiss a suggestion by its suggestion_id. Resolves the claim_id from
 * the suggestion events table, then delegates to the service layer.
 */
async function dismissSuggestionBySuggestionId(
  suggestionId: string,
  providerId: string,
  lifecycleDeps: LifecycleDeps,
  repo: IntelRepository,
  reason?: string,
) {
  const claimId = await findClaimIdForSuggestion(suggestionId, repo);
  if (!claimId) return null;

  return dismissSuggestion(claimId, suggestionId, providerId, lifecycleDeps, reason);
}

/**
 * Find the claim_id for a suggestion by looking up the GENERATED event
 * in ai_suggestion_events via the repository.
 */
async function findClaimIdForSuggestion(
  suggestionId: string,
  repo: IntelRepository,
): Promise<string | null> {
  return repo.findClaimIdBySuggestionId(suggestionId);
}

// ---------------------------------------------------------------------------
// WebSocket handler for Tier 2 real-time delivery
// ---------------------------------------------------------------------------

export interface IntelWsSessionValidator {
  validateSession: (tokenHash: string) => Promise<{ userId: string; role: string } | null>;
}

interface IntelWebSocket {
  on(event: string, handler: (...args: unknown[]) => void): void;
  close(code?: number, reason?: string): void;
  send(data: string): void;
}

const WS_CLOSE_AUTH_FAILED = 4001;

/** Map of claimId -> Set<WebSocket> for broadcasting Tier 2 results */
const wsClaimSubscriptions = new Map<string, Set<IntelWebSocket>>();

/**
 * Register the intelligence WebSocket route.
 * Authenticates via session cookie, subscribes to claim analysis channels.
 */
export function registerIntelWebSocket(
  app: { get(path: string, opts: { websocket: true }, handler: (socket: any, req: any) => void): void },
  sessionValidator: IntelWsSessionValidator,
  hashTokenFn: (token: string) => string,
): void {
  app.get('/api/v1/intelligence/ws', { websocket: true }, async (socket: IntelWebSocket, req: any) => {
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

    // Handle incoming messages (subscribe to claim channels)
    socket.on('message', (raw: unknown) => {
      try {
        const msg = JSON.parse(String(raw));
        if (msg.type === 'subscribe' && typeof msg.claimId === 'string') {
          let subs = wsClaimSubscriptions.get(msg.claimId);
          if (!subs) {
            subs = new Set();
            wsClaimSubscriptions.set(msg.claimId, subs);
          }
          subs.add(socket);
        }
        if (msg.type === 'unsubscribe' && typeof msg.claimId === 'string') {
          const subs = wsClaimSubscriptions.get(msg.claimId);
          if (subs) {
            subs.delete(socket);
            if (subs.size === 0) wsClaimSubscriptions.delete(msg.claimId);
          }
        }
      } catch {
        // Ignore malformed messages
      }
    });

    // Cleanup on close
    socket.on('close', () => {
      for (const [claimId, subs] of wsClaimSubscriptions) {
        subs.delete(socket);
        if (subs.size === 0) wsClaimSubscriptions.delete(claimId);
      }
    });

    socket.on('error', () => {
      for (const [claimId, subs] of wsClaimSubscriptions) {
        subs.delete(socket);
        if (subs.size === 0) wsClaimSubscriptions.delete(claimId);
      }
    });
  });
}

/**
 * Broadcast a Tier 2 analysis result to all WebSocket clients subscribed
 * to a specific claim channel. Called by the analysis orchestrator.
 */
export function notifyWsClients(claimId: string, event: string, payload: unknown): void {
  const subs = wsClaimSubscriptions.get(claimId);
  if (!subs || subs.size === 0) return;

  const message = JSON.stringify({ event, claimId, payload });
  for (const socket of subs) {
    try {
      socket.send(message);
    } catch {
      // Remove broken sockets
      subs.delete(socket);
    }
  }
  if (subs.size === 0) wsClaimSubscriptions.delete(claimId);
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
