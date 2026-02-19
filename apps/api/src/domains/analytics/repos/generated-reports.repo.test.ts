import { describe, it, expect, beforeEach, vi } from 'vitest';
import { createGeneratedReportsRepository } from './generated-reports.repo.js';

// ---------------------------------------------------------------------------
// In-memory reports store
// ---------------------------------------------------------------------------

let reportsStore: Record<string, any>[];

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const PROVIDER_A = crypto.randomUUID();
const PROVIDER_B = crypto.randomUUID();

// ---------------------------------------------------------------------------
// Helper: build a valid insert payload
// ---------------------------------------------------------------------------

function makeReportData(overrides: Record<string, any> = {}) {
  return {
    providerId: PROVIDER_A,
    reportType: 'ACCOUNTANT_SUMMARY',
    format: 'PDF',
    periodStart: '2026-01-01',
    periodEnd: '2026-01-31',
    filePath: '/reports/pending.pdf',
    fileSizeBytes: 0,
    downloadLinkExpiresAt: new Date(Date.now() + 72 * 60 * 60 * 1000), // 72h from now
    downloaded: false,
    scheduled: false,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Mock Drizzle DB
// ---------------------------------------------------------------------------

function makeMockDb(): any {
  function chainable(ctx: {
    op: string;
    table?: any;
    values?: any;
    setClauses?: any;
    whereClauses: Array<(row: any) => boolean>;
    shouldReturn?: boolean;
    orderByDesc?: string;
    limitVal?: number;
    offsetVal?: number;
    selectFields?: any;
  }) {
    const chain: any = {
      _ctx: ctx,
      values(v: any) {
        ctx.values = Array.isArray(v) ? v : [v];
        return chain;
      },
      set(s: any) {
        ctx.setClauses = s;
        return chain;
      },
      from(_table: any) {
        return chain;
      },
      where(clause: any) {
        if (typeof clause === 'function') {
          ctx.whereClauses.push(clause);
        } else if (clause && typeof clause === 'object' && clause.__predicate) {
          ctx.whereClauses.push(clause.__predicate);
        }
        return chain;
      },
      orderBy(_order: any) {
        ctx.orderByDesc = 'createdAt';
        return chain;
      },
      limit(n: number) {
        ctx.limitVal = n;
        return chain;
      },
      offset(n: number) {
        ctx.offsetVal = n;
        return chain;
      },
      returning() {
        ctx.shouldReturn = true;
        return chain;
      },
      then(resolve: any, reject?: any) {
        try {
          const result = executeOp(ctx);
          resolve(result);
        } catch (e) {
          if (reject) reject(e);
          else throw e;
        }
      },
    };
    return chain;
  }

  function matchesWhere(
    row: Record<string, any>,
    whereClauses: Array<(row: any) => boolean>,
  ): boolean {
    return whereClauses.every((pred) => pred(row));
  }

  function executeOp(ctx: any): any[] {
    switch (ctx.op) {
      case 'select': {
        let results = reportsStore.filter((row) =>
          matchesWhere(row, ctx.whereClauses),
        );

        // Handle count(*) select: db.select({ count: sql`count(*)` })
        if (ctx.selectFields?.count?.__count) {
          return [{ count: results.length }];
        }

        // Sort by createdAt descending
        if (ctx.orderByDesc === 'createdAt') {
          results = results.sort((a, b) => {
            const timeA =
              a.createdAt instanceof Date
                ? a.createdAt.getTime()
                : new Date(a.createdAt).getTime();
            const timeB =
              b.createdAt instanceof Date
                ? b.createdAt.getTime()
                : new Date(b.createdAt).getTime();
            return timeB - timeA;
          });
        }

        // Apply offset and limit
        if (ctx.offsetVal !== undefined) {
          results = results.slice(ctx.offsetVal);
        }
        if (ctx.limitVal !== undefined) {
          results = results.slice(0, ctx.limitVal);
        }

        return results;
      }

      case 'insert': {
        const inserted: any[] = [];
        for (const entry of ctx.values) {
          const newRow = {
            reportId: crypto.randomUUID(),
            downloaded: false,
            scheduled: false,
            status: 'pending',
            errorMessage: null,
            createdAt: new Date(),
            ...entry,
          };
          reportsStore.push(newRow);
          inserted.push({ ...newRow });
        }
        return ctx.shouldReturn ? inserted : [];
      }

      case 'update': {
        const updated: any[] = [];
        for (const row of reportsStore) {
          if (matchesWhere(row, ctx.whereClauses)) {
            if (ctx.setClauses) {
              for (const [key, val] of Object.entries(ctx.setClauses)) {
                row[key] = val;
              }
            }
            updated.push({ ...row });
          }
        }
        return ctx.shouldReturn ? updated : [];
      }

      case 'delete': {
        const toDelete: any[] = [];
        const remaining: any[] = [];
        for (const row of reportsStore) {
          if (matchesWhere(row, ctx.whereClauses)) {
            toDelete.push({ ...row });
          } else {
            remaining.push(row);
          }
        }
        reportsStore.length = 0;
        reportsStore.push(...remaining);
        return ctx.shouldReturn ? toDelete : [];
      }

      default:
        return [];
    }
  }

  return {
    select(fields?: any) {
      return chainable({
        op: 'select',
        whereClauses: [],
        selectFields: fields,
      });
    },
    insert(_table: any) {
      return chainable({ op: 'insert', whereClauses: [] });
    },
    update(_table: any) {
      return chainable({ op: 'update', whereClauses: [] });
    },
    delete(_table: any) {
      return chainable({ op: 'delete', whereClauses: [] });
    },
  };
}

// ---------------------------------------------------------------------------
// Column name → store key mapping
// ---------------------------------------------------------------------------

function colName(col: any): string {
  if (col && col.name) return col.name;
  return '';
}

const COL_MAP: Record<string, string> = {
  report_id: 'reportId',
  provider_id: 'providerId',
  report_type: 'reportType',
  format: 'format',
  period_start: 'periodStart',
  period_end: 'periodEnd',
  file_path: 'filePath',
  file_size_bytes: 'fileSizeBytes',
  download_link_expires_at: 'downloadLinkExpiresAt',
  downloaded: 'downloaded',
  scheduled: 'scheduled',
  status: 'status',
  error_message: 'errorMessage',
  created_at: 'createdAt',
};

function toStoreKey(col: any): string {
  const name = colName(col);
  return COL_MAP[name] || name;
}

// ---------------------------------------------------------------------------
// Override drizzle-orm operators for in-memory predicates
// ---------------------------------------------------------------------------

vi.mock('drizzle-orm', async () => {
  const actual =
    await vi.importActual<typeof import('drizzle-orm')>('drizzle-orm');
  return {
    ...actual,
    eq(col: any, val: any) {
      const key = toStoreKey(col);
      return {
        __predicate: (row: any) => row[key] === val,
      };
    },
    and(...conditions: any[]) {
      const preds = conditions
        .filter(Boolean)
        .map((c: any) => (typeof c === 'function' ? c : c?.__predicate))
        .filter(Boolean);
      return {
        __predicate: (row: any) => preds.every((pred: any) => pred(row)),
      };
    },
    lt(col: any, val: any) {
      const key = toStoreKey(col);
      return {
        __predicate: (row: any) => {
          const rowVal = row[key];
          // Handle NOW() sentinel
          if (val && typeof val === 'object' && val.__now) {
            const rowTime =
              rowVal instanceof Date
                ? rowVal.getTime()
                : new Date(rowVal).getTime();
            return rowTime < Date.now();
          }
          // Date comparison
          if (rowVal instanceof Date && val instanceof Date) {
            return rowVal.getTime() < val.getTime();
          }
          return rowVal < val;
        },
      };
    },
    desc(col: any) {
      return { __desc: true, key: toStoreKey(col) };
    },
    sql(strings: TemplateStringsArray, ...values: any[]) {
      const fullStr = strings.join('?');

      // Detect NOW() for lt comparison
      if (fullStr.trim() === 'NOW()') {
        return { __now: true };
      }

      // Detect count(*)
      if (fullStr.includes('count(*)')) {
        return { __count: true };
      }

      // Detect download_link_expires_at > NOW() filter
      if (fullStr.includes('> NOW()')) {
        return {
          __predicate: (row: any) => {
            const expiresAt = row.downloadLinkExpiresAt;
            const expiresTime =
              expiresAt instanceof Date
                ? expiresAt.getTime()
                : new Date(expiresAt).getTime();
            return expiresTime > Date.now();
          },
        };
      }

      // Detect period_start >= filter
      if (fullStr.includes('>=')) {
        const filterVal = values[1] ?? values[0];
        return {
          __predicate: (row: any) => {
            return row.periodStart >= filterVal;
          },
        };
      }

      // Detect period_end <= filter
      if (fullStr.includes('<=')) {
        const filterVal = values[1] ?? values[0];
        return {
          __predicate: (row: any) => {
            return row.periodEnd <= filterVal;
          },
        };
      }

      return {};
    },
  };
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('GeneratedReportsRepository', () => {
  let repo: ReturnType<typeof createGeneratedReportsRepository>;

  beforeEach(() => {
    reportsStore = [];
    repo = createGeneratedReportsRepository(makeMockDb());
  });

  // =========================================================================
  // create
  // =========================================================================

  describe('create', () => {
    it('creates a report with status "pending"', async () => {
      const data = makeReportData();
      const result = await repo.create(data);

      expect(result).toBeDefined();
      expect(result.reportId).toBeDefined();
      expect(result.status).toBe('pending');
      expect(result.providerId).toBe(PROVIDER_A);
      expect(result.reportType).toBe('ACCOUNTANT_SUMMARY');
      expect(result.format).toBe('PDF');
      expect(result.downloaded).toBe(false);
      expect(reportsStore).toHaveLength(1);
    });

    it('ignores status override — always sets pending', async () => {
      const data = makeReportData({ status: 'ready' });
      const result = await repo.create(data);

      // The create method overrides status to 'pending'
      expect(result.status).toBe('pending');
    });

    it('stores period start/end from data', async () => {
      const data = makeReportData({
        periodStart: '2026-02-01',
        periodEnd: '2026-02-28',
      });
      const result = await repo.create(data);

      expect(result.periodStart).toBe('2026-02-01');
      expect(result.periodEnd).toBe('2026-02-28');
    });
  });

  // =========================================================================
  // getById
  // =========================================================================

  describe('getById', () => {
    it('returns report when ID and provider match', async () => {
      const data = makeReportData();
      const created = await repo.create(data);

      const result = await repo.getById(created.reportId, PROVIDER_A);

      expect(result).not.toBeNull();
      expect(result!.reportId).toBe(created.reportId);
      expect(result!.providerId).toBe(PROVIDER_A);
    });

    it('returns null for non-existent report ID', async () => {
      const result = await repo.getById(crypto.randomUUID(), PROVIDER_A);
      expect(result).toBeNull();
    });

    it('returns null when provider does not match (404 pattern)', async () => {
      const data = makeReportData({ providerId: PROVIDER_A });
      const created = await repo.create(data);

      // Provider B tries to access Provider A's report
      const result = await repo.getById(created.reportId, PROVIDER_B);

      expect(result).toBeNull();
    });
  });

  // =========================================================================
  // updateStatus
  // =========================================================================

  describe('updateStatus', () => {
    it('transitions status from pending to generating', async () => {
      const created = await repo.create(makeReportData());

      const result = await repo.updateStatus(
        created.reportId,
        PROVIDER_A,
        'generating',
      );

      expect(result).not.toBeNull();
      expect(result!.status).toBe('generating');
    });

    it('transitions status to ready with file info', async () => {
      const created = await repo.create(makeReportData());

      const result = await repo.updateStatus(
        created.reportId,
        PROVIDER_A,
        'ready',
        '/reports/final-report.pdf',
        102400,
      );

      expect(result).not.toBeNull();
      expect(result!.status).toBe('ready');
      expect(result!.filePath).toBe('/reports/final-report.pdf');
      expect(result!.fileSizeBytes).toBe(102400);
    });

    it('transitions status to failed with error message', async () => {
      const created = await repo.create(makeReportData());

      const result = await repo.updateStatus(
        created.reportId,
        PROVIDER_A,
        'failed',
        undefined,
        undefined,
        'Generation timed out',
      );

      expect(result).not.toBeNull();
      expect(result!.status).toBe('failed');
      expect(result!.errorMessage).toBe('Generation timed out');
    });

    it('returns null when provider does not match', async () => {
      const created = await repo.create(makeReportData());

      const result = await repo.updateStatus(
        created.reportId,
        PROVIDER_B,
        'generating',
      );

      expect(result).toBeNull();
    });

    it('returns null for non-existent report', async () => {
      const result = await repo.updateStatus(
        crypto.randomUUID(),
        PROVIDER_A,
        'generating',
      );

      expect(result).toBeNull();
    });
  });

  // =========================================================================
  // markDownloaded
  // =========================================================================

  describe('markDownloaded', () => {
    it('sets downloaded to true', async () => {
      const created = await repo.create(makeReportData());

      const result = await repo.markDownloaded(created.reportId, PROVIDER_A);

      expect(result).not.toBeNull();
      expect(result!.downloaded).toBe(true);
    });

    it('returns null when provider does not match', async () => {
      const created = await repo.create(makeReportData());

      const result = await repo.markDownloaded(created.reportId, PROVIDER_B);

      expect(result).toBeNull();
    });
  });

  // =========================================================================
  // listByProvider
  // =========================================================================

  describe('listByProvider', () => {
    beforeEach(async () => {
      // Seed reports for both providers
      const now = Date.now();
      for (let i = 0; i < 5; i++) {
        reportsStore.push({
          reportId: crypto.randomUUID(),
          providerId: PROVIDER_A,
          reportType: i < 3 ? 'ACCOUNTANT_SUMMARY' : 'WEEKLY_SUMMARY',
          format: 'PDF',
          periodStart: '2026-01-01',
          periodEnd: '2026-01-31',
          filePath: `/reports/report-a-${i}.pdf`,
          fileSizeBytes: 1024 * (i + 1),
          downloadLinkExpiresAt: new Date(now + 72 * 60 * 60 * 1000),
          downloaded: false,
          scheduled: false,
          status: 'ready',
          errorMessage: null,
          createdAt: new Date(now - i * 60000), // spaced 1 min apart
        });
      }

      // Provider B reports
      for (let i = 0; i < 3; i++) {
        reportsStore.push({
          reportId: crypto.randomUUID(),
          providerId: PROVIDER_B,
          reportType: 'ACCOUNTANT_SUMMARY',
          format: 'PDF',
          periodStart: '2026-01-01',
          periodEnd: '2026-01-31',
          filePath: `/reports/report-b-${i}.pdf`,
          fileSizeBytes: 2048,
          downloadLinkExpiresAt: new Date(now + 72 * 60 * 60 * 1000),
          downloaded: false,
          scheduled: false,
          status: 'ready',
          errorMessage: null,
          createdAt: new Date(now - i * 60000),
        });
      }
    });

    it('returns only the authenticated provider\'s reports', async () => {
      const result = await repo.listByProvider(PROVIDER_A);

      expect(result.data.length).toBe(5);
      expect(result.total).toBe(5);
      result.data.forEach((r) => {
        expect(r.providerId).toBe(PROVIDER_A);
      });
    });

    it('never returns another provider\'s reports', async () => {
      const result = await repo.listByProvider(PROVIDER_A);

      result.data.forEach((r) => {
        expect(r.providerId).not.toBe(PROVIDER_B);
      });
    });

    it('filters by report type', async () => {
      const result = await repo.listByProvider(PROVIDER_A, {
        reportType: 'WEEKLY_SUMMARY',
      });

      expect(result.data.length).toBe(2);
      expect(result.total).toBe(2);
      result.data.forEach((r) => {
        expect(r.reportType).toBe('WEEKLY_SUMMARY');
      });
    });

    it('paginates with limit and offset', async () => {
      const page1 = await repo.listByProvider(PROVIDER_A, {
        limit: 2,
        offset: 0,
      });

      expect(page1.data.length).toBe(2);
      expect(page1.total).toBe(5);

      const page2 = await repo.listByProvider(PROVIDER_A, {
        limit: 2,
        offset: 2,
      });

      expect(page2.data.length).toBe(2);
      expect(page2.total).toBe(5);

      // Pages should not overlap
      const page1Ids = page1.data.map((r) => r.reportId);
      const page2Ids = page2.data.map((r) => r.reportId);
      page2Ids.forEach((id) => {
        expect(page1Ids).not.toContain(id);
      });
    });

    it('orders by created_at descending (newest first)', async () => {
      const result = await repo.listByProvider(PROVIDER_A);

      for (let i = 1; i < result.data.length; i++) {
        const prev = new Date(result.data[i - 1].createdAt).getTime();
        const curr = new Date(result.data[i].createdAt).getTime();
        expect(prev).toBeGreaterThanOrEqual(curr);
      }
    });

    it('returns empty data array and total 0 when no reports exist', async () => {
      const unknownProvider = crypto.randomUUID();
      const result = await repo.listByProvider(unknownProvider);

      expect(result.data).toHaveLength(0);
      expect(result.total).toBe(0);
    });
  });

  // =========================================================================
  // deleteExpired
  // =========================================================================

  describe('deleteExpired', () => {
    it('deletes reports with expired download links', async () => {
      const pastDate = new Date(Date.now() - 24 * 60 * 60 * 1000); // 24h ago
      const futureDate = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24h from now

      reportsStore.push(
        {
          reportId: crypto.randomUUID(),
          providerId: PROVIDER_A,
          reportType: 'ACCOUNTANT_SUMMARY',
          format: 'PDF',
          periodStart: '2026-01-01',
          periodEnd: '2026-01-31',
          filePath: '/reports/expired.pdf',
          fileSizeBytes: 1024,
          downloadLinkExpiresAt: pastDate, // Expired
          downloaded: false,
          scheduled: false,
          status: 'ready',
          errorMessage: null,
          createdAt: new Date(),
        },
        {
          reportId: crypto.randomUUID(),
          providerId: PROVIDER_A,
          reportType: 'WEEKLY_SUMMARY',
          format: 'PDF',
          periodStart: '2026-01-01',
          periodEnd: '2026-01-31',
          filePath: '/reports/active.pdf',
          fileSizeBytes: 2048,
          downloadLinkExpiresAt: futureDate, // Not expired
          downloaded: false,
          scheduled: false,
          status: 'ready',
          errorMessage: null,
          createdAt: new Date(),
        },
      );

      const count = await repo.deleteExpired();

      expect(count).toBe(1);
      expect(reportsStore).toHaveLength(1);
      expect(reportsStore[0].reportType).toBe('WEEKLY_SUMMARY');
    });

    it('returns 0 when no reports are expired', async () => {
      const futureDate = new Date(Date.now() + 72 * 60 * 60 * 1000);

      reportsStore.push({
        reportId: crypto.randomUUID(),
        providerId: PROVIDER_A,
        reportType: 'ACCOUNTANT_SUMMARY',
        format: 'PDF',
        periodStart: '2026-01-01',
        periodEnd: '2026-01-31',
        filePath: '/reports/active.pdf',
        fileSizeBytes: 1024,
        downloadLinkExpiresAt: futureDate,
        downloaded: false,
        scheduled: false,
        status: 'ready',
        errorMessage: null,
        createdAt: new Date(),
      });

      const count = await repo.deleteExpired();

      expect(count).toBe(0);
      expect(reportsStore).toHaveLength(1);
    });

    it('deletes expired reports from all providers', async () => {
      const pastDate = new Date(Date.now() - 24 * 60 * 60 * 1000);

      reportsStore.push(
        {
          reportId: crypto.randomUUID(),
          providerId: PROVIDER_A,
          reportType: 'ACCOUNTANT_SUMMARY',
          format: 'PDF',
          periodStart: '2026-01-01',
          periodEnd: '2026-01-31',
          filePath: '/reports/expired-a.pdf',
          fileSizeBytes: 1024,
          downloadLinkExpiresAt: pastDate,
          downloaded: false,
          scheduled: false,
          status: 'ready',
          errorMessage: null,
          createdAt: new Date(),
        },
        {
          reportId: crypto.randomUUID(),
          providerId: PROVIDER_B,
          reportType: 'WEEKLY_SUMMARY',
          format: 'PDF',
          periodStart: '2026-01-01',
          periodEnd: '2026-01-31',
          filePath: '/reports/expired-b.pdf',
          fileSizeBytes: 2048,
          downloadLinkExpiresAt: pastDate,
          downloaded: false,
          scheduled: false,
          status: 'ready',
          errorMessage: null,
          createdAt: new Date(),
        },
      );

      const count = await repo.deleteExpired();

      expect(count).toBe(2);
      expect(reportsStore).toHaveLength(0);
    });
  });

  // =========================================================================
  // getReadyForDownload
  // =========================================================================

  describe('getReadyForDownload', () => {
    it('returns report when status is ready and link not expired', async () => {
      const futureDate = new Date(Date.now() + 72 * 60 * 60 * 1000);

      reportsStore.push({
        reportId: 'ready-report-id',
        providerId: PROVIDER_A,
        reportType: 'ACCOUNTANT_SUMMARY',
        format: 'PDF',
        periodStart: '2026-01-01',
        periodEnd: '2026-01-31',
        filePath: '/reports/ready.pdf',
        fileSizeBytes: 1024,
        downloadLinkExpiresAt: futureDate,
        downloaded: false,
        scheduled: false,
        status: 'ready',
        errorMessage: null,
        createdAt: new Date(),
      });

      const result = await repo.getReadyForDownload(
        'ready-report-id',
        PROVIDER_A,
      );

      expect(result).not.toBeNull();
      expect(result!.reportId).toBe('ready-report-id');
      expect(result!.status).toBe('ready');
    });

    it('returns null when status is not ready', async () => {
      const futureDate = new Date(Date.now() + 72 * 60 * 60 * 1000);

      reportsStore.push({
        reportId: 'pending-report-id',
        providerId: PROVIDER_A,
        reportType: 'ACCOUNTANT_SUMMARY',
        format: 'PDF',
        periodStart: '2026-01-01',
        periodEnd: '2026-01-31',
        filePath: '/reports/pending.pdf',
        fileSizeBytes: 0,
        downloadLinkExpiresAt: futureDate,
        downloaded: false,
        scheduled: false,
        status: 'pending',
        errorMessage: null,
        createdAt: new Date(),
      });

      const result = await repo.getReadyForDownload(
        'pending-report-id',
        PROVIDER_A,
      );

      expect(result).toBeNull();
    });

    it('returns null when download link has expired', async () => {
      const pastDate = new Date(Date.now() - 24 * 60 * 60 * 1000);

      reportsStore.push({
        reportId: 'expired-report-id',
        providerId: PROVIDER_A,
        reportType: 'ACCOUNTANT_SUMMARY',
        format: 'PDF',
        periodStart: '2026-01-01',
        periodEnd: '2026-01-31',
        filePath: '/reports/expired.pdf',
        fileSizeBytes: 1024,
        downloadLinkExpiresAt: pastDate,
        downloaded: false,
        scheduled: false,
        status: 'ready',
        errorMessage: null,
        createdAt: new Date(),
      });

      const result = await repo.getReadyForDownload(
        'expired-report-id',
        PROVIDER_A,
      );

      expect(result).toBeNull();
    });

    it('returns null when provider does not match (404 pattern)', async () => {
      const futureDate = new Date(Date.now() + 72 * 60 * 60 * 1000);

      reportsStore.push({
        reportId: 'other-provider-report',
        providerId: PROVIDER_A,
        reportType: 'ACCOUNTANT_SUMMARY',
        format: 'PDF',
        periodStart: '2026-01-01',
        periodEnd: '2026-01-31',
        filePath: '/reports/ready.pdf',
        fileSizeBytes: 1024,
        downloadLinkExpiresAt: futureDate,
        downloaded: false,
        scheduled: false,
        status: 'ready',
        errorMessage: null,
        createdAt: new Date(),
      });

      // Provider B cannot access Provider A's report
      const result = await repo.getReadyForDownload(
        'other-provider-report',
        PROVIDER_B,
      );

      expect(result).toBeNull();
    });

    it('returns null for failed reports even if link not expired', async () => {
      const futureDate = new Date(Date.now() + 72 * 60 * 60 * 1000);

      reportsStore.push({
        reportId: 'failed-report-id',
        providerId: PROVIDER_A,
        reportType: 'ACCOUNTANT_SUMMARY',
        format: 'PDF',
        periodStart: '2026-01-01',
        periodEnd: '2026-01-31',
        filePath: '/reports/failed.pdf',
        fileSizeBytes: 0,
        downloadLinkExpiresAt: futureDate,
        downloaded: false,
        scheduled: false,
        status: 'failed',
        errorMessage: 'Generation error',
        createdAt: new Date(),
      });

      const result = await repo.getReadyForDownload(
        'failed-report-id',
        PROVIDER_A,
      );

      expect(result).toBeNull();
    });
  });

  // =========================================================================
  // Provider scoping (cross-cutting)
  // =========================================================================

  describe('provider scoping', () => {
    it('create stores the correct provider_id', async () => {
      const dataA = makeReportData({ providerId: PROVIDER_A });
      const dataB = makeReportData({ providerId: PROVIDER_B });

      const reportA = await repo.create(dataA);
      const reportB = await repo.create(dataB);

      expect(reportA.providerId).toBe(PROVIDER_A);
      expect(reportB.providerId).toBe(PROVIDER_B);
    });

    it('getById never returns another provider\'s report', async () => {
      const dataA = makeReportData({ providerId: PROVIDER_A });
      const reportA = await repo.create(dataA);

      const byCorrectProvider = await repo.getById(
        reportA.reportId,
        PROVIDER_A,
      );
      const byWrongProvider = await repo.getById(
        reportA.reportId,
        PROVIDER_B,
      );

      expect(byCorrectProvider).not.toBeNull();
      expect(byWrongProvider).toBeNull();
    });

    it('updateStatus returns null for wrong provider', async () => {
      const reportA = await repo.create(makeReportData());

      const result = await repo.updateStatus(
        reportA.reportId,
        PROVIDER_B,
        'generating',
      );

      expect(result).toBeNull();
      // Original status unchanged
      const original = reportsStore.find(
        (r) => r.reportId === reportA.reportId,
      );
      expect(original!.status).toBe('pending');
    });

    it('markDownloaded returns null for wrong provider', async () => {
      const reportA = await repo.create(makeReportData());

      const result = await repo.markDownloaded(reportA.reportId, PROVIDER_B);

      expect(result).toBeNull();
      const original = reportsStore.find(
        (r) => r.reportId === reportA.reportId,
      );
      expect(original!.downloaded).toBe(false);
    });

    it('listByProvider isolates data between providers', async () => {
      await repo.create(makeReportData({ providerId: PROVIDER_A }));
      await repo.create(makeReportData({ providerId: PROVIDER_A }));
      await repo.create(makeReportData({ providerId: PROVIDER_B }));

      const listA = await repo.listByProvider(PROVIDER_A);
      const listB = await repo.listByProvider(PROVIDER_B);

      expect(listA.total).toBe(2);
      expect(listB.total).toBe(1);
      listA.data.forEach((r) => expect(r.providerId).toBe(PROVIDER_A));
      listB.data.forEach((r) => expect(r.providerId).toBe(PROVIDER_B));
    });
  });
});
