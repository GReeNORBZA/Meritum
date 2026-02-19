// ============================================================================
// Domain 13: Help Centre Routes
// Article search, category listing, feedback.
// ============================================================================

import { type FastifyInstance, type FastifyRequest, type FastifyReply } from 'fastify';
import {
  articleListQuerySchema,
  articleSlugParamSchema,
  articleFeedbackSchema,
  type ArticleListQuery,
  type ArticleSlugParam,
  type ArticleFeedbackInput,
} from '@meritum/shared/schemas/validation/support.validation.js';
import { type HelpCentreService } from '../services/help-centre.service.js';

// ---------------------------------------------------------------------------
// Dependencies
// ---------------------------------------------------------------------------

export interface HelpRoutesDeps {
  helpCentreService: HelpCentreService;
}

// ---------------------------------------------------------------------------
// Helper: extract providerId from auth context (for authenticated routes)
// ---------------------------------------------------------------------------

function getProviderId(request: FastifyRequest): string {
  const ctx = request.authContext;
  if (ctx.role?.toUpperCase() === 'DELEGATE' && (ctx as any).delegateContext) {
    return (ctx as any).delegateContext.physicianProviderId;
  }
  return ctx.userId;
}

// ---------------------------------------------------------------------------
// Help Centre Routes
// ---------------------------------------------------------------------------

export async function helpRoutes(
  app: FastifyInstance,
  opts: { deps: HelpRoutesDeps },
) {
  const { helpCentreService } = opts.deps;

  // =========================================================================
  // GET /api/v1/help/articles — List or search articles (public)
  // =========================================================================

  app.get('/api/v1/help/articles', {
    schema: { querystring: articleListQuerySchema },
    handler: async (
      request: FastifyRequest<{ Querystring: ArticleListQuery }>,
      reply: FastifyReply,
    ) => {
      const { search, category, limit, offset } = request.query;

      if (search) {
        // Full-text search — pass anonymous provider for audit (public endpoint)
        const results = await helpCentreService.searchArticles(
          'anonymous',
          search,
          limit,
          offset,
        );
        return reply.code(200).send({ data: results });
      }

      if (category) {
        const results = await helpCentreService.listByCategory(
          category,
          limit,
          offset,
        );
        return reply.code(200).send({ data: results });
      }

      // No search or category — return empty list (require at least one filter)
      return reply.code(200).send({ data: [] });
    },
  });

  // =========================================================================
  // GET /api/v1/help/articles/:slug — Get article by slug (public)
  // =========================================================================

  app.get('/api/v1/help/articles/:slug', {
    schema: { params: articleSlugParamSchema },
    handler: async (
      request: FastifyRequest<{ Params: ArticleSlugParam }>,
      reply: FastifyReply,
    ) => {
      const { slug } = request.params;

      const article = await helpCentreService.getArticle('anonymous', slug);
      if (!article) {
        return reply.code(404).send({
          error: { code: 'NOT_FOUND', message: 'Resource not found' },
        });
      }

      return reply.code(200).send({ data: article });
    },
  });

  // =========================================================================
  // POST /api/v1/help/articles/:slug/feedback — Submit feedback (authenticated)
  // =========================================================================

  app.post('/api/v1/help/articles/:slug/feedback', {
    schema: {
      params: articleSlugParamSchema,
      body: articleFeedbackSchema,
    },
    preHandler: [app.authenticate],
    handler: async (
      request: FastifyRequest<{
        Params: ArticleSlugParam;
        Body: ArticleFeedbackInput;
      }>,
      reply: FastifyReply,
    ) => {
      const { slug } = request.params;
      const { is_helpful } = request.body;
      const providerId = getProviderId(request);

      const result = await helpCentreService.submitFeedback(
        slug,
        providerId,
        is_helpful,
      );

      if (!result.success) {
        return reply.code(404).send({
          error: { code: 'NOT_FOUND', message: 'Resource not found' },
        });
      }

      return reply.code(200).send({ data: { success: true } });
    },
  });
}
