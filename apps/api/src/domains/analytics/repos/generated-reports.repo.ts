import { eq, and, lt, sql, desc } from 'drizzle-orm';
import { type NodePgDatabase } from 'drizzle-orm/node-postgres';
import {
  generatedReports,
  type InsertGeneratedReport,
  type SelectGeneratedReport,
} from '@meritum/shared/schemas/db/analytics.schema.js';

// ---------------------------------------------------------------------------
// Generated Reports Repository
// ---------------------------------------------------------------------------

export interface GeneratedReportFilters {
  reportType?: string;
  periodStart?: string;
  periodEnd?: string;
  limit?: number;
  offset?: number;
}

export function createGeneratedReportsRepository(db: NodePgDatabase) {
  return {
    /**
     * Create a new report record with status 'pending'.
     * Scoped to provider_id from the insert data.
     */
    async create(
      data: Omit<InsertGeneratedReport, 'status'>,
    ): Promise<SelectGeneratedReport> {
      const rows = await db
        .insert(generatedReports)
        .values({
          ...data,
          status: 'pending',
        })
        .returning();

      return rows[0];
    },

    /**
     * Fetch report by ID scoped to provider.
     * Returns null if not found or wrong provider (404 pattern, not 403).
     */
    async getById(
      reportId: string,
      providerId: string,
    ): Promise<SelectGeneratedReport | null> {
      const rows = await db
        .select()
        .from(generatedReports)
        .where(
          and(
            eq(generatedReports.reportId, reportId),
            eq(generatedReports.providerId, providerId),
          ),
        );

      return rows[0] ?? null;
    },

    /**
     * Update report status. Used by generation worker.
     * Scoped to provider_id. Returns null if report not found for this provider.
     */
    async updateStatus(
      reportId: string,
      providerId: string,
      status: string,
      filePath?: string,
      fileSizeBytes?: number,
      errorMessage?: string,
    ): Promise<SelectGeneratedReport | null> {
      const setClauses: Record<string, any> = { status };

      if (filePath !== undefined) {
        setClauses.filePath = filePath;
      }
      if (fileSizeBytes !== undefined) {
        setClauses.fileSizeBytes = fileSizeBytes;
      }
      if (errorMessage !== undefined) {
        setClauses.errorMessage = errorMessage;
      }

      const rows = await db
        .update(generatedReports)
        .set(setClauses)
        .where(
          and(
            eq(generatedReports.reportId, reportId),
            eq(generatedReports.providerId, providerId),
          ),
        )
        .returning();

      return rows[0] ?? null;
    },

    /**
     * Set downloaded = true for a report.
     * Scoped to provider_id. Returns null if not found for this provider.
     */
    async markDownloaded(
      reportId: string,
      providerId: string,
    ): Promise<SelectGeneratedReport | null> {
      const rows = await db
        .update(generatedReports)
        .set({ downloaded: true })
        .where(
          and(
            eq(generatedReports.reportId, reportId),
            eq(generatedReports.providerId, providerId),
          ),
        )
        .returning();

      return rows[0] ?? null;
    },

    /**
     * List reports for a provider with optional type/date filters.
     * Paginated (limit, offset). Ordered by created_at DESC.
     * Scoped to provider_id.
     */
    async listByProvider(
      providerId: string,
      filters?: GeneratedReportFilters,
    ): Promise<{ data: SelectGeneratedReport[]; total: number }> {
      const conditions = [eq(generatedReports.providerId, providerId)];

      if (filters?.reportType) {
        conditions.push(eq(generatedReports.reportType, filters.reportType));
      }

      if (filters?.periodStart) {
        conditions.push(
          sql`${generatedReports.periodStart} >= ${filters.periodStart}`,
        );
      }

      if (filters?.periodEnd) {
        conditions.push(
          sql`${generatedReports.periodEnd} <= ${filters.periodEnd}`,
        );
      }

      const whereClause = and(...conditions);

      // Count total matching records
      const countResult = await db
        .select({ count: sql<number>`count(*)` })
        .from(generatedReports)
        .where(whereClause);

      const total = Number(countResult[0]?.count ?? 0);

      // Fetch paginated results
      const limit = filters?.limit ?? 20;
      const offset = filters?.offset ?? 0;

      const rows = await db
        .select()
        .from(generatedReports)
        .where(whereClause)
        .orderBy(desc(generatedReports.createdAt))
        .limit(limit)
        .offset(offset);

      return { data: rows, total };
    },

    /**
     * Delete reports where download_link_expires_at < now().
     * Returns count of deleted records.
     * Note: caller is responsible for deleting physical files before calling this.
     */
    async deleteExpired(): Promise<number> {
      const result = await db
        .delete(generatedReports)
        .where(lt(generatedReports.downloadLinkExpiresAt, sql`NOW()`))
        .returning();

      return result.length;
    },

    /**
     * Fetch report only if status = 'ready' and download_link_expires_at > now().
     * Returns null otherwise.
     * Scoped to provider_id (404 pattern).
     */
    async getReadyForDownload(
      reportId: string,
      providerId: string,
    ): Promise<SelectGeneratedReport | null> {
      const rows = await db
        .select()
        .from(generatedReports)
        .where(
          and(
            eq(generatedReports.reportId, reportId),
            eq(generatedReports.providerId, providerId),
            eq(generatedReports.status, 'ready'),
            sql`${generatedReports.downloadLinkExpiresAt} > NOW()`,
          ),
        );

      return rows[0] ?? null;
    },
  };
}

export type GeneratedReportsRepository = ReturnType<
  typeof createGeneratedReportsRepository
>;
