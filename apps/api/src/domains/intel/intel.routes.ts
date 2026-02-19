// ============================================================================
// Domain 7: Intelligence Engine — Routes
// Registers all intelligence endpoints under /api/v1/intelligence/.
// All routes require authentication. Permission guards per FRD Section 8.
// ============================================================================

import { type FastifyInstance, type FastifyRequest, type FastifyReply } from 'fastify';
import {
  analyseClaimSchema,
  claimSuggestionsParamSchema,
  intelSuggestionIdParamSchema,
  intelDismissSuggestionSchema,
  unsuppressRuleParamSchema,
  updateIntelPreferencesSchema,
  createRuleSchema,
  updateRuleSchema,
  ruleIdParamSchema,
  activateRuleSchema,
  ruleListQuerySchema,
  sombChangeAnalysisSchema,
} from '@meritum/shared/schemas/intelligence.schema.js';
import {
  createIntelHandlers,
  registerIntelWebSocket,
  type IntelHandlerDeps,
  type IntelWsSessionValidator,
} from './intel.handlers.js';

// ---------------------------------------------------------------------------
// Intelligence HTTP Routes
// ---------------------------------------------------------------------------

export async function intelRoutes(
  app: FastifyInstance,
  opts: { deps: IntelHandlerDeps },
) {
  const handlers = createIntelHandlers(opts.deps);

  // =========================================================================
  // Suggestion Endpoints (consumed by Domain 4)
  // =========================================================================

  // POST /api/v1/intelligence/analyse — submit claim for analysis
  app.post('/api/v1/intelligence/analyse', {
    schema: { body: analyseClaimSchema },
    preHandler: [app.authenticate, app.authorize('AI_COACH_VIEW')],
    handler: handlers.analyseHandler,
  });

  // GET /api/v1/intelligence/claims/:claim_id/suggestions — get suggestions for a claim
  app.get('/api/v1/intelligence/claims/:claim_id/suggestions', {
    schema: { params: claimSuggestionsParamSchema },
    preHandler: [app.authenticate, app.authorize('AI_COACH_VIEW')],
    handler: handlers.getClaimSuggestionsHandler,
  });

  // POST /api/v1/intelligence/suggestions/:id/accept — accept a suggestion
  app.post('/api/v1/intelligence/suggestions/:id/accept', {
    schema: { params: intelSuggestionIdParamSchema },
    preHandler: [app.authenticate, app.authorize('AI_COACH_MANAGE')],
    handler: handlers.acceptSuggestionHandler,
  });

  // POST /api/v1/intelligence/suggestions/:id/dismiss — dismiss a suggestion
  app.post('/api/v1/intelligence/suggestions/:id/dismiss', {
    schema: { params: intelSuggestionIdParamSchema, body: intelDismissSuggestionSchema },
    preHandler: [app.authenticate, app.authorize('AI_COACH_MANAGE')],
    handler: handlers.dismissSuggestionHandler,
  });

  // =========================================================================
  // Learning & Preferences (Physician-facing)
  // =========================================================================

  // GET /api/v1/intelligence/me/learning-state — learning summary
  app.get('/api/v1/intelligence/me/learning-state', {
    preHandler: [app.authenticate, app.authorize('AI_COACH_VIEW')],
    handler: handlers.getLearningStateHandler,
  });

  // POST /api/v1/intelligence/me/rules/:rule_id/unsuppress — un-suppress a rule
  app.post('/api/v1/intelligence/me/rules/:rule_id/unsuppress', {
    schema: { params: unsuppressRuleParamSchema },
    preHandler: [app.authenticate, app.authorize('AI_COACH_MANAGE')],
    handler: handlers.unsuppressRuleHandler,
  });

  // PUT /api/v1/intelligence/me/preferences — set AI Coach preferences
  app.put('/api/v1/intelligence/me/preferences', {
    schema: { body: updateIntelPreferencesSchema },
    preHandler: [app.authenticate, app.authorize('AI_COACH_MANAGE')],
    handler: handlers.updatePreferencesHandler,
  });

  // =========================================================================
  // Rule Management (Admin + physician transparency)
  // =========================================================================

  // Admin role guard
  async function requireAdmin(request: FastifyRequest, reply: FastifyReply) {
    const ctx = request.authContext;
    if (!ctx) {
      reply.code(401).send({
        error: { code: 'UNAUTHORIZED', message: 'Authentication required' },
      });
      return;
    }
    if (ctx.role?.toUpperCase() !== 'ADMIN') {
      reply.code(403).send({
        error: { code: 'FORBIDDEN', message: 'Insufficient permissions' },
      });
      return;
    }
  }

  // GET /api/v1/intelligence/rules — list rules (physician: name+category only; admin: full)
  app.get('/api/v1/intelligence/rules', {
    schema: { querystring: ruleListQuerySchema },
    preHandler: [app.authenticate, app.authorize('AI_COACH_VIEW')],
    handler: handlers.listRulesHandler,
  });

  // POST /api/v1/intelligence/rules — create rule (admin only)
  app.post('/api/v1/intelligence/rules', {
    schema: { body: createRuleSchema },
    preHandler: [app.authenticate, requireAdmin],
    handler: handlers.createRuleHandler,
  });

  // PUT /api/v1/intelligence/rules/:id — update rule (admin only)
  app.put('/api/v1/intelligence/rules/:id', {
    schema: { params: ruleIdParamSchema, body: updateRuleSchema },
    preHandler: [app.authenticate, requireAdmin],
    handler: handlers.updateRuleHandler,
  });

  // PUT /api/v1/intelligence/rules/:id/activate — toggle active (admin only)
  app.put('/api/v1/intelligence/rules/:id/activate', {
    schema: { params: ruleIdParamSchema, body: activateRuleSchema },
    preHandler: [app.authenticate, requireAdmin],
    handler: handlers.activateRuleHandler,
  });

  // GET /api/v1/intelligence/rules/:id/stats — rule performance stats (admin only)
  app.get('/api/v1/intelligence/rules/:id/stats', {
    schema: { params: ruleIdParamSchema },
    preHandler: [app.authenticate, requireAdmin],
    handler: handlers.getRuleStatsHandler,
  });

  // POST /api/v1/intelligence/cohorts/recalculate — trigger cohort recalculation (admin only)
  app.post('/api/v1/intelligence/cohorts/recalculate', {
    preHandler: [app.authenticate, requireAdmin],
    handler: handlers.recalculateCohortsHandler,
  });

  // POST /api/v1/intelligence/somb-change-analysis — generate per-physician impact (admin only)
  app.post('/api/v1/intelligence/somb-change-analysis', {
    schema: { body: sombChangeAnalysisSchema },
    preHandler: [app.authenticate, requireAdmin],
    handler: handlers.sombChangeAnalysisHandler,
  });
}

// ---------------------------------------------------------------------------
// Intelligence WebSocket Route
// ---------------------------------------------------------------------------

export async function intelWebSocketRoutes(
  app: FastifyInstance,
  opts: {
    sessionValidator: IntelWsSessionValidator;
    hashTokenFn: (token: string) => string;
  },
) {
  registerIntelWebSocket(app as any, opts.sessionValidator, opts.hashTokenFn);
}
