// ============================================================================
// Domain 8: Dashboard Routes
// 7 GET endpoints for analytics dashboard data.
// All require authentication. Delegates need ANALYTICS_VIEW permission.
// ============================================================================

import { type FastifyInstance, type FastifyRequest, type FastifyReply } from 'fastify';
import {
  revenueQuerySchema,
  rejectionQuerySchema,
  agingQuerySchema,
  wcbQuerySchema,
  aiCoachQuerySchema,
  multiSiteQuerySchema,
  kpiQuerySchema,
  type RevenueQuery,
  type RejectionQuery,
  type AgingQuery,
  type WcbQuery,
  type AiCoachQuery,
  type MultiSiteQuery,
  type KpiQuery,
} from '@meritum/shared/schemas/validation/analytics.validation.js';
import { AnalyticsAuditAction } from '@meritum/shared/constants/analytics.constants.js';
import type { DashboardService } from '../services/dashboard.service.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface DashboardRouteDeps {
  dashboardService: DashboardService;
  auditLog: (entry: {
    action: string;
    providerId: string;
    details: Record<string, unknown>;
  }) => Promise<void>;
}

// ---------------------------------------------------------------------------
// Helper: extract providerId from auth context
// ---------------------------------------------------------------------------

function getProviderId(request: FastifyRequest): string {
  const ctx = request.authContext;
  if (ctx.role?.toUpperCase() === 'DELEGATE' && (ctx as any).delegateContext) {
    return (ctx as any).delegateContext.physicianProviderId;
  }
  return ctx.userId;
}

// ---------------------------------------------------------------------------
// Audit rate limiter — max 1 log per dashboard type per 5 min per physician
// ---------------------------------------------------------------------------

const auditTimestamps = new Map<string, number>();
const AUDIT_RATE_LIMIT_MS = 5 * 60 * 1000;

function shouldAuditLog(providerId: string, dashboardType: string): boolean {
  const key = `${providerId}:${dashboardType}`;
  const now = Date.now();
  const lastLog = auditTimestamps.get(key);
  if (lastLog && now - lastLog < AUDIT_RATE_LIMIT_MS) {
    return false;
  }
  auditTimestamps.set(key, now);
  return true;
}

// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

export async function dashboardRoutes(
  app: FastifyInstance,
  opts: { deps: DashboardRouteDeps },
) {
  const { dashboardService, auditLog } = opts.deps;

  // =========================================================================
  // GET /api/v1/analytics/revenue
  // =========================================================================

  app.get('/api/v1/analytics/revenue', {
    schema: { querystring: revenueQuerySchema },
    preHandler: [app.authenticate, app.authorize('ANALYTICS_VIEW')],
    handler: async (
      request: FastifyRequest<{ Querystring: RevenueQuery }>,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);
      const query = request.query;

      const result = await dashboardService.getRevenueDashboard(
        providerId,
        { period: query.period, start_date: query.start_date, end_date: query.end_date },
        {
          claimType: query.claim_type,
          baNumber: query.ba_number,
          locationId: query.location_id,
        },
      );

      if (shouldAuditLog(providerId, 'revenue')) {
        auditLog({
          action: AnalyticsAuditAction.DASHBOARD_VIEWED,
          providerId,
          details: { dashboardType: 'revenue', period: query.period },
        }).catch(() => {});
      }

      return reply.code(200).send({ data: result });
    },
  });

  // =========================================================================
  // GET /api/v1/analytics/rejections
  // =========================================================================

  app.get('/api/v1/analytics/rejections', {
    schema: { querystring: rejectionQuerySchema },
    preHandler: [app.authenticate, app.authorize('ANALYTICS_VIEW')],
    handler: async (
      request: FastifyRequest<{ Querystring: RejectionQuery }>,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);
      const query = request.query;

      const result = await dashboardService.getRejectionDashboard(
        providerId,
        { period: query.period, start_date: query.start_date, end_date: query.end_date },
        { claimType: query.claim_type },
      );

      if (shouldAuditLog(providerId, 'rejections')) {
        auditLog({
          action: AnalyticsAuditAction.DASHBOARD_VIEWED,
          providerId,
          details: { dashboardType: 'rejections', period: query.period },
        }).catch(() => {});
      }

      return reply.code(200).send({ data: result });
    },
  });

  // =========================================================================
  // GET /api/v1/analytics/aging
  // =========================================================================

  app.get('/api/v1/analytics/aging', {
    schema: { querystring: agingQuerySchema },
    preHandler: [app.authenticate, app.authorize('ANALYTICS_VIEW')],
    handler: async (
      request: FastifyRequest<{ Querystring: AgingQuery }>,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);
      const query = request.query;

      const result = await dashboardService.getAgingDashboard(
        providerId,
        { claimType: query.claim_type },
      );

      if (shouldAuditLog(providerId, 'aging')) {
        auditLog({
          action: AnalyticsAuditAction.DASHBOARD_VIEWED,
          providerId,
          details: { dashboardType: 'aging' },
        }).catch(() => {});
      }

      return reply.code(200).send({ data: result });
    },
  });

  // =========================================================================
  // GET /api/v1/analytics/wcb
  // =========================================================================

  app.get('/api/v1/analytics/wcb', {
    schema: { querystring: wcbQuerySchema },
    preHandler: [app.authenticate, app.authorize('ANALYTICS_VIEW')],
    handler: async (
      request: FastifyRequest<{ Querystring: WcbQuery }>,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);
      const query = request.query;

      const result = await dashboardService.getWcbDashboard(
        providerId,
        { period: query.period, start_date: query.start_date, end_date: query.end_date },
      );

      if (result === null) {
        return reply.code(404).send({
          error: { code: 'NOT_FOUND', message: 'Resource not found' },
        });
      }

      if (shouldAuditLog(providerId, 'wcb')) {
        auditLog({
          action: AnalyticsAuditAction.DASHBOARD_VIEWED,
          providerId,
          details: { dashboardType: 'wcb', period: query.period },
        }).catch(() => {});
      }

      return reply.code(200).send({ data: result });
    },
  });

  // =========================================================================
  // GET /api/v1/analytics/ai-coach
  // =========================================================================

  app.get('/api/v1/analytics/ai-coach', {
    schema: { querystring: aiCoachQuerySchema },
    preHandler: [app.authenticate, app.authorize('ANALYTICS_VIEW')],
    handler: async (
      request: FastifyRequest<{ Querystring: AiCoachQuery }>,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);
      const query = request.query;

      const result = await dashboardService.getAiCoachDashboard(
        providerId,
        { period: query.period, start_date: query.start_date, end_date: query.end_date },
      );

      if (shouldAuditLog(providerId, 'ai-coach')) {
        auditLog({
          action: AnalyticsAuditAction.DASHBOARD_VIEWED,
          providerId,
          details: { dashboardType: 'ai-coach', period: query.period },
        }).catch(() => {});
      }

      return reply.code(200).send({ data: result });
    },
  });

  // =========================================================================
  // GET /api/v1/analytics/multi-site
  // =========================================================================

  app.get('/api/v1/analytics/multi-site', {
    schema: { querystring: multiSiteQuerySchema },
    preHandler: [app.authenticate, app.authorize('ANALYTICS_VIEW')],
    handler: async (
      request: FastifyRequest<{ Querystring: MultiSiteQuery }>,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);
      const query = request.query;

      const result = await dashboardService.getMultiSiteDashboard(
        providerId,
        { period: query.period, start_date: query.start_date, end_date: query.end_date },
        query.compare_locations,
      );

      if (result === null) {
        return reply.code(404).send({
          error: { code: 'NOT_FOUND', message: 'Resource not found' },
        });
      }

      if (shouldAuditLog(providerId, 'multi-site')) {
        auditLog({
          action: AnalyticsAuditAction.DASHBOARD_VIEWED,
          providerId,
          details: { dashboardType: 'multi-site', period: query.period },
        }).catch(() => {});
      }

      return reply.code(200).send({ data: result });
    },
  });

  // =========================================================================
  // GET /api/v1/analytics/kpis
  // =========================================================================

  app.get('/api/v1/analytics/kpis', {
    schema: { querystring: kpiQuerySchema },
    preHandler: [app.authenticate, app.authorize('ANALYTICS_VIEW')],
    handler: async (
      request: FastifyRequest<{ Querystring: KpiQuery }>,
      reply: FastifyReply,
    ) => {
      const providerId = getProviderId(request);
      const query = request.query;

      const result = await dashboardService.getKpis(
        providerId,
        { period: query.period, start_date: query.start_date, end_date: query.end_date },
        {
          claimType: query.claim_type,
          baNumber: query.ba_number,
          locationId: query.location_id,
        },
      );

      if (shouldAuditLog(providerId, 'kpis')) {
        auditLog({
          action: AnalyticsAuditAction.DASHBOARD_VIEWED,
          providerId,
          details: { dashboardType: 'kpis', period: query.period },
        }).catch(() => {});
      }

      return reply.code(200).send({ data: result });
    },
  });
}
