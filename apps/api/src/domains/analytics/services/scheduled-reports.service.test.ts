// ============================================================================
// Domain 8: Scheduled Reports Service — Unit Tests
// ============================================================================

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  createScheduledReportsService,
  getNthBusinessDay,
  isThirdBusinessDay,
  type ScheduledReportNotifier,
  type RejectionChecker,
  type ScheduleClock,
  type ScheduledProcessingResult,
} from './scheduled-reports.service.js';
import {
  ReportType,
  ReportFormat,
  ReportFrequency,
  DeliveryMethod,
  REPORT_DOWNLOAD_EXPIRY_DAYS,
} from '@meritum/shared/constants/analytics.constants.js';
import type { ReportSubscriptionsRepository } from '../repos/report-subscriptions.repo.js';
import type { GeneratedReportsRepository } from '../repos/generated-reports.repo.js';
import type { ReportGenerationService } from './report-generation.service.js';
import type {
  SelectReportSubscription,
  SelectGeneratedReport,
} from '@meritum/shared/schemas/db/analytics.schema.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PROVIDER_ID_1 = '00000000-0000-0000-0000-000000000001';
const PROVIDER_ID_2 = '00000000-0000-0000-0000-000000000002';
const SUBSCRIPTION_ID_1 = 'aaaa0000-0000-0000-0000-000000000001';
const SUBSCRIPTION_ID_2 = 'aaaa0000-0000-0000-0000-000000000002';
const REPORT_ID = 'bbbb0000-0000-0000-0000-000000000001';

// ---------------------------------------------------------------------------
// Sample Data Factories
// ---------------------------------------------------------------------------

function sampleSubscription(
  overrides?: Partial<SelectReportSubscription>,
): SelectReportSubscription {
  return {
    subscriptionId: SUBSCRIPTION_ID_1,
    providerId: PROVIDER_ID_1,
    reportType: ReportType.WEEKLY_SUMMARY,
    frequency: ReportFrequency.WEEKLY,
    deliveryMethod: DeliveryMethod.IN_APP,
    isActive: true,
    createdAt: new Date('2026-01-01T00:00:00Z'),
    updatedAt: new Date('2026-01-01T00:00:00Z'),
    ...overrides,
  };
}

function sampleGeneratedReport(
  overrides?: Partial<SelectGeneratedReport>,
): SelectGeneratedReport {
  return {
    reportId: REPORT_ID,
    providerId: PROVIDER_ID_1,
    reportType: ReportType.WEEKLY_SUMMARY,
    format: ReportFormat.PDF,
    periodStart: '2026-01-06',
    periodEnd: '2026-01-12',
    filePath: '',
    fileSizeBytes: 0,
    downloadLinkExpiresAt: new Date('2026-04-15T00:00:00Z'),
    downloaded: false,
    scheduled: true,
    status: 'pending',
    errorMessage: null,
    createdAt: new Date('2026-01-13T00:00:00Z'),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Mock Factories
// ---------------------------------------------------------------------------

function createMockSubscriptionsRepo(): ReportSubscriptionsRepository {
  return {
    create: vi.fn(),
    getById: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
    listByProvider: vi.fn(),
    getDueSubscriptions: vi.fn().mockResolvedValue([]),
  };
}

function createMockReportsRepo(): GeneratedReportsRepository {
  return {
    create: vi.fn().mockResolvedValue(sampleGeneratedReport()),
    getById: vi.fn().mockResolvedValue(sampleGeneratedReport()),
    updateStatus: vi.fn().mockResolvedValue(sampleGeneratedReport()),
    markDownloaded: vi.fn(),
    listByProvider: vi.fn(),
    deleteExpired: vi.fn(),
    getReadyForDownload: vi.fn(),
  };
}

function createMockReportGeneration(): ReportGenerationService {
  return {
    generateAccountantCsv: vi.fn().mockResolvedValue(undefined),
    generateAccountantPdfSummary: vi.fn().mockResolvedValue(undefined),
    generateAccountantPdfDetail: vi.fn().mockResolvedValue(undefined),
    generateDataPortabilityExport: vi.fn().mockResolvedValue(undefined),
    processReport: vi.fn().mockResolvedValue(undefined),
  };
}

function createMockNotifier(): ScheduledReportNotifier {
  return {
    sendReportReadyNotification: vi.fn().mockResolvedValue(undefined),
    sendReportReadyEmail: vi.fn().mockResolvedValue(undefined),
  };
}

function createMockRejectionChecker(): RejectionChecker {
  return {
    hasRejectionsInPeriod: vi.fn().mockResolvedValue(false),
  };
}

function createMockClock(date: Date): ScheduleClock {
  return { now: () => date };
}

function createService(overrides?: {
  subscriptionsRepo?: ReportSubscriptionsRepository;
  reportsRepo?: GeneratedReportsRepository;
  reportGeneration?: ReportGenerationService;
  notifier?: ScheduledReportNotifier;
  rejectionChecker?: RejectionChecker;
  clock?: ScheduleClock;
}) {
  const subscriptionsRepo =
    overrides?.subscriptionsRepo ?? createMockSubscriptionsRepo();
  const reportsRepo = overrides?.reportsRepo ?? createMockReportsRepo();
  const reportGeneration =
    overrides?.reportGeneration ?? createMockReportGeneration();
  const notifier = overrides?.notifier ?? createMockNotifier();
  const rejectionChecker =
    overrides?.rejectionChecker ?? createMockRejectionChecker();
  // Default: Monday 2026-01-19 (a Monday)
  const clock =
    overrides?.clock ?? createMockClock(new Date(2026, 0, 19));

  const service = createScheduledReportsService({
    subscriptionsRepo,
    reportsRepo,
    reportGeneration,
    notifier,
    rejectionChecker,
    clock,
  });

  return {
    service,
    subscriptionsRepo,
    reportsRepo,
    reportGeneration,
    notifier,
    rejectionChecker,
    clock,
  };
}

// ============================================================================
// getNthBusinessDay — Business day calculation
// ============================================================================

describe('getNthBusinessDay', () => {
  it('returns the 1st business day of January 2026 (Thursday Jan 1)', () => {
    // Jan 2026: 1=Thu, 2=Fri, 3=Sat, 4=Sun, 5=Mon
    const result = getNthBusinessDay(2026, 0, 1);
    expect(result.getDate()).toBe(1);
    expect(result.getDay()).toBe(4); // Thursday
  });

  it('returns the 3rd business day of January 2026 (Monday Jan 5)', () => {
    // Jan 2026: 1=Thu, 2=Fri, 5=Mon (3rd BD)
    const result = getNthBusinessDay(2026, 0, 3);
    expect(result.getDate()).toBe(5);
    expect(result.getDay()).toBe(1); // Monday
  });

  it('returns the 3rd business day of February 2026 (Wednesday Feb 4)', () => {
    // Feb 2026: 1=Sun, 2=Mon(1st), 3=Tue(2nd), 4=Wed(3rd)
    const result = getNthBusinessDay(2026, 1, 3);
    expect(result.getDate()).toBe(4);
    expect(result.getDay()).toBe(3); // Wednesday
  });

  it('skips weekends correctly', () => {
    // March 2026: 1=Sun, 2=Mon(1st BD), 3=Tue(2nd), 4=Wed(3rd)
    const result = getNthBusinessDay(2026, 2, 3);
    expect(result.getDate()).toBe(4);
  });

  it('handles month starting on Saturday', () => {
    // Aug 2026: 1=Sat, 3=Mon(1st BD), 4=Tue(2nd), 5=Wed(3rd)
    const result = getNthBusinessDay(2026, 7, 3);
    expect(result.getDate()).toBe(5);
  });
});

// ============================================================================
// isThirdBusinessDay
// ============================================================================

describe('isThirdBusinessDay', () => {
  it('returns true on the 3rd business day of the month', () => {
    // Jan 2026: 3rd BD = Jan 5 (Mon)
    expect(isThirdBusinessDay(new Date(2026, 0, 5))).toBe(true);
  });

  it('returns false on other days', () => {
    expect(isThirdBusinessDay(new Date(2026, 0, 1))).toBe(false);
    expect(isThirdBusinessDay(new Date(2026, 0, 6))).toBe(false);
    expect(isThirdBusinessDay(new Date(2026, 0, 15))).toBe(false);
  });

  it('returns true for Feb 2026 (3rd BD = Feb 4)', () => {
    expect(isThirdBusinessDay(new Date(2026, 1, 4))).toBe(true);
  });

  it('returns false for Feb 2026 on Feb 3', () => {
    expect(isThirdBusinessDay(new Date(2026, 1, 3))).toBe(false);
  });
});

// ============================================================================
// processDailySubscriptions
// ============================================================================

describe('processDailySubscriptions', () => {
  it('fetches DAILY frequency subscriptions', async () => {
    const { service, subscriptionsRepo } = createService();

    await service.processDailySubscriptions();

    expect(subscriptionsRepo.getDueSubscriptions).toHaveBeenCalledWith(
      ReportFrequency.DAILY,
    );
  });

  it('skips rejection digest when no rejections in past 24 hours', async () => {
    const subscriptionsRepo = createMockSubscriptionsRepo();
    vi.mocked(subscriptionsRepo.getDueSubscriptions).mockResolvedValue([
      sampleSubscription({
        reportType: ReportType.REJECTION_DIGEST,
        frequency: ReportFrequency.DAILY,
      }),
    ]);

    const rejectionChecker = createMockRejectionChecker();
    vi.mocked(rejectionChecker.hasRejectionsInPeriod).mockResolvedValue(false);

    const { service, reportsRepo } = createService({
      subscriptionsRepo,
      rejectionChecker,
    });

    const result = await service.processDailySubscriptions();

    expect(result.skipped).toBe(1);
    expect(result.processed).toBe(0);
    expect(reportsRepo.create).not.toHaveBeenCalled();
  });

  it('processes rejection digest when rejections exist', async () => {
    const subscriptionsRepo = createMockSubscriptionsRepo();
    vi.mocked(subscriptionsRepo.getDueSubscriptions).mockResolvedValue([
      sampleSubscription({
        reportType: ReportType.REJECTION_DIGEST,
        frequency: ReportFrequency.DAILY,
      }),
    ]);

    const rejectionChecker = createMockRejectionChecker();
    vi.mocked(rejectionChecker.hasRejectionsInPeriod).mockResolvedValue(true);

    const { service, reportsRepo, reportGeneration } = createService({
      subscriptionsRepo,
      rejectionChecker,
    });

    const result = await service.processDailySubscriptions();

    expect(result.processed).toBe(1);
    expect(reportsRepo.create).toHaveBeenCalled();
    expect(reportGeneration.processReport).toHaveBeenCalled();
  });

  it('checks rejections for the correct provider and period', async () => {
    const clock = createMockClock(new Date(2026, 0, 15)); // Jan 15
    const subscriptionsRepo = createMockSubscriptionsRepo();
    vi.mocked(subscriptionsRepo.getDueSubscriptions).mockResolvedValue([
      sampleSubscription({
        providerId: PROVIDER_ID_1,
        reportType: ReportType.REJECTION_DIGEST,
        frequency: ReportFrequency.DAILY,
      }),
    ]);

    const rejectionChecker = createMockRejectionChecker();
    vi.mocked(rejectionChecker.hasRejectionsInPeriod).mockResolvedValue(false);

    const { service } = createService({
      subscriptionsRepo,
      rejectionChecker,
      clock,
    });

    await service.processDailySubscriptions();

    expect(rejectionChecker.hasRejectionsInPeriod).toHaveBeenCalledWith(
      PROVIDER_ID_1,
      '2026-01-14', // yesterday
      '2026-01-15', // today
    );
  });

  it('returns empty result when no daily subscriptions exist', async () => {
    const { service } = createService();

    const result = await service.processDailySubscriptions();

    expect(result.processed).toBe(0);
    expect(result.skipped).toBe(0);
    expect(result.failed).toBe(0);
    expect(result.details).toHaveLength(0);
  });

  it('includes skip reason in details for skipped subscriptions', async () => {
    const subscriptionsRepo = createMockSubscriptionsRepo();
    vi.mocked(subscriptionsRepo.getDueSubscriptions).mockResolvedValue([
      sampleSubscription({
        reportType: ReportType.REJECTION_DIGEST,
        frequency: ReportFrequency.DAILY,
      }),
    ]);

    const { service } = createService({ subscriptionsRepo });

    const result = await service.processDailySubscriptions();

    expect(result.details[0].status).toBe('skipped');
    expect(result.details[0].reason).toContain('No rejections');
  });
});

// ============================================================================
// processWeeklySubscriptions
// ============================================================================

describe('processWeeklySubscriptions', () => {
  it('fetches WEEKLY frequency subscriptions', async () => {
    const { service, subscriptionsRepo } = createService();

    await service.processWeeklySubscriptions(1);

    expect(subscriptionsRepo.getDueSubscriptions).toHaveBeenCalledWith(
      ReportFrequency.WEEKLY,
    );
  });

  it('processes WEEKLY_SUMMARY on Monday (dayOfWeek=1)', async () => {
    const clock = createMockClock(new Date(2026, 0, 19)); // Monday Jan 19
    const subscriptionsRepo = createMockSubscriptionsRepo();
    vi.mocked(subscriptionsRepo.getDueSubscriptions).mockResolvedValue([
      sampleSubscription({
        reportType: ReportType.WEEKLY_SUMMARY,
        frequency: ReportFrequency.WEEKLY,
      }),
    ]);

    const { service, reportGeneration } = createService({
      subscriptionsRepo,
      clock,
    });

    const result = await service.processWeeklySubscriptions(1);

    expect(result.processed).toBe(1);
    expect(reportGeneration.processReport).toHaveBeenCalled();
  });

  it('skips WEEKLY_SUMMARY on non-Monday', async () => {
    const subscriptionsRepo = createMockSubscriptionsRepo();
    vi.mocked(subscriptionsRepo.getDueSubscriptions).mockResolvedValue([
      sampleSubscription({
        reportType: ReportType.WEEKLY_SUMMARY,
        frequency: ReportFrequency.WEEKLY,
      }),
    ]);

    const { service, reportGeneration } = createService({ subscriptionsRepo });

    const result = await service.processWeeklySubscriptions(3); // Wednesday

    expect(result.skipped).toBe(1);
    expect(result.processed).toBe(0);
    expect(reportGeneration.processReport).not.toHaveBeenCalled();
  });

  it('processes WCB_TIMING on Wednesday (dayOfWeek=3)', async () => {
    const clock = createMockClock(new Date(2026, 0, 21)); // Wednesday Jan 21
    const subscriptionsRepo = createMockSubscriptionsRepo();
    vi.mocked(subscriptionsRepo.getDueSubscriptions).mockResolvedValue([
      sampleSubscription({
        reportType: ReportType.WCB_TIMING,
        frequency: ReportFrequency.WEEKLY,
      }),
    ]);

    const { service, reportGeneration } = createService({
      subscriptionsRepo,
      clock,
    });

    const result = await service.processWeeklySubscriptions(3);

    expect(result.processed).toBe(1);
    expect(reportGeneration.processReport).toHaveBeenCalled();
  });

  it('skips WCB_TIMING on non-Wednesday', async () => {
    const subscriptionsRepo = createMockSubscriptionsRepo();
    vi.mocked(subscriptionsRepo.getDueSubscriptions).mockResolvedValue([
      sampleSubscription({
        reportType: ReportType.WCB_TIMING,
        frequency: ReportFrequency.WEEKLY,
      }),
    ]);

    const { service, reportGeneration } = createService({ subscriptionsRepo });

    const result = await service.processWeeklySubscriptions(1); // Monday

    expect(result.skipped).toBe(1);
    expect(reportGeneration.processReport).not.toHaveBeenCalled();
  });

  it('uses prior week period for WEEKLY_SUMMARY', async () => {
    const clock = createMockClock(new Date(2026, 0, 19)); // Monday Jan 19
    const subscriptionsRepo = createMockSubscriptionsRepo();
    vi.mocked(subscriptionsRepo.getDueSubscriptions).mockResolvedValue([
      sampleSubscription({
        reportType: ReportType.WEEKLY_SUMMARY,
        frequency: ReportFrequency.WEEKLY,
      }),
    ]);

    const reportsRepo = createMockReportsRepo();
    const { service } = createService({
      subscriptionsRepo,
      reportsRepo,
      clock,
    });

    await service.processWeeklySubscriptions(1);

    // Prior week: Mon Jan 12 to Sun Jan 18
    expect(reportsRepo.create).toHaveBeenCalledWith(
      expect.objectContaining({
        periodStart: '2026-01-12',
        periodEnd: '2026-01-18',
      }),
    );
  });

  it('uses upcoming 7-day period for WCB_TIMING', async () => {
    const clock = createMockClock(new Date(2026, 0, 21)); // Wednesday Jan 21
    const subscriptionsRepo = createMockSubscriptionsRepo();
    vi.mocked(subscriptionsRepo.getDueSubscriptions).mockResolvedValue([
      sampleSubscription({
        reportType: ReportType.WCB_TIMING,
        frequency: ReportFrequency.WEEKLY,
      }),
    ]);

    const reportsRepo = createMockReportsRepo();
    const { service } = createService({
      subscriptionsRepo,
      reportsRepo,
      clock,
    });

    await service.processWeeklySubscriptions(3);

    // Upcoming 7 days: Jan 21 to Jan 28
    expect(reportsRepo.create).toHaveBeenCalledWith(
      expect.objectContaining({
        periodStart: '2026-01-21',
        periodEnd: '2026-01-28',
      }),
    );
  });

  it('handles mixed subscription types on Monday', async () => {
    const subscriptionsRepo = createMockSubscriptionsRepo();
    vi.mocked(subscriptionsRepo.getDueSubscriptions).mockResolvedValue([
      sampleSubscription({
        subscriptionId: SUBSCRIPTION_ID_1,
        reportType: ReportType.WEEKLY_SUMMARY,
      }),
      sampleSubscription({
        subscriptionId: SUBSCRIPTION_ID_2,
        reportType: ReportType.WCB_TIMING,
      }),
    ]);

    const { service } = createService({ subscriptionsRepo });

    const result = await service.processWeeklySubscriptions(1);

    // WEEKLY_SUMMARY processed, WCB_TIMING skipped (not Wednesday)
    expect(result.processed).toBe(1);
    expect(result.skipped).toBe(1);
  });
});

// ============================================================================
// processMonthlySubscriptions
// ============================================================================

describe('processMonthlySubscriptions', () => {
  it('only processes on the 3rd business day of the month', async () => {
    // Jan 2026: 3rd BD = Jan 5 (Mon)
    const clock = createMockClock(new Date(2026, 0, 5));
    const subscriptionsRepo = createMockSubscriptionsRepo();
    vi.mocked(subscriptionsRepo.getDueSubscriptions).mockResolvedValue([
      sampleSubscription({
        reportType: ReportType.MONTHLY_PERFORMANCE,
        frequency: ReportFrequency.MONTHLY,
      }),
    ]);

    const { service, reportGeneration } = createService({
      subscriptionsRepo,
      clock,
    });

    const result = await service.processMonthlySubscriptions();

    expect(result.processed).toBe(1);
    expect(reportGeneration.processReport).toHaveBeenCalled();
  });

  it('returns empty result on non-3rd business day', async () => {
    // Jan 6 is the 4th business day
    const clock = createMockClock(new Date(2026, 0, 6));
    const { service, subscriptionsRepo } = createService({ clock });

    const result = await service.processMonthlySubscriptions();

    expect(result.processed).toBe(0);
    expect(result.skipped).toBe(0);
    expect(result.failed).toBe(0);
    expect(subscriptionsRepo.getDueSubscriptions).not.toHaveBeenCalled();
  });

  it('fetches MONTHLY frequency subscriptions', async () => {
    const clock = createMockClock(new Date(2026, 0, 5)); // 3rd BD
    const { service, subscriptionsRepo } = createService({ clock });

    await service.processMonthlySubscriptions();

    expect(subscriptionsRepo.getDueSubscriptions).toHaveBeenCalledWith(
      ReportFrequency.MONTHLY,
    );
  });

  it('uses prior month period', async () => {
    // On Jan 5, 2026 (3rd BD of Jan), prior month = Dec 2025
    const clock = createMockClock(new Date(2026, 0, 5));
    const subscriptionsRepo = createMockSubscriptionsRepo();
    vi.mocked(subscriptionsRepo.getDueSubscriptions).mockResolvedValue([
      sampleSubscription({
        reportType: ReportType.MONTHLY_PERFORMANCE,
        frequency: ReportFrequency.MONTHLY,
      }),
    ]);

    const reportsRepo = createMockReportsRepo();
    const { service } = createService({
      subscriptionsRepo,
      reportsRepo,
      clock,
    });

    await service.processMonthlySubscriptions();

    expect(reportsRepo.create).toHaveBeenCalledWith(
      expect.objectContaining({
        periodStart: '2025-12-01',
        periodEnd: '2025-12-31',
      }),
    );
  });

  it('processes ACCOUNTANT_SUMMARY on 3rd business day', async () => {
    const clock = createMockClock(new Date(2026, 0, 5));
    const subscriptionsRepo = createMockSubscriptionsRepo();
    vi.mocked(subscriptionsRepo.getDueSubscriptions).mockResolvedValue([
      sampleSubscription({
        reportType: ReportType.ACCOUNTANT_SUMMARY,
        frequency: ReportFrequency.MONTHLY,
      }),
    ]);

    const { service, reportGeneration } = createService({
      subscriptionsRepo,
      clock,
    });

    const result = await service.processMonthlySubscriptions();

    expect(result.processed).toBe(1);
    expect(reportGeneration.processReport).toHaveBeenCalled();
  });

  it('processes multiple monthly subscriptions for different providers', async () => {
    const clock = createMockClock(new Date(2026, 0, 5));
    const subscriptionsRepo = createMockSubscriptionsRepo();
    vi.mocked(subscriptionsRepo.getDueSubscriptions).mockResolvedValue([
      sampleSubscription({
        subscriptionId: SUBSCRIPTION_ID_1,
        providerId: PROVIDER_ID_1,
        reportType: ReportType.MONTHLY_PERFORMANCE,
        frequency: ReportFrequency.MONTHLY,
      }),
      sampleSubscription({
        subscriptionId: SUBSCRIPTION_ID_2,
        providerId: PROVIDER_ID_2,
        reportType: ReportType.MONTHLY_PERFORMANCE,
        frequency: ReportFrequency.MONTHLY,
      }),
    ]);

    const { service, reportGeneration } = createService({
      subscriptionsRepo,
      clock,
    });

    const result = await service.processMonthlySubscriptions();

    expect(result.processed).toBe(2);
    expect(reportGeneration.processReport).toHaveBeenCalledTimes(2);
  });
});

// ============================================================================
// processQuarterlySubscriptions
// ============================================================================

describe('processQuarterlySubscriptions', () => {
  it('fetches QUARTERLY frequency subscriptions', async () => {
    const { service, subscriptionsRepo } = createService();

    await service.processQuarterlySubscriptions();

    expect(subscriptionsRepo.getDueSubscriptions).toHaveBeenCalledWith(
      ReportFrequency.QUARTERLY,
    );
  });

  it('uses prior quarter period', async () => {
    // April 2026 → prior quarter = Q1 (Jan 1 - Mar 31 2026)
    const clock = createMockClock(new Date(2026, 3, 5));
    const subscriptionsRepo = createMockSubscriptionsRepo();
    vi.mocked(subscriptionsRepo.getDueSubscriptions).mockResolvedValue([
      sampleSubscription({
        reportType: ReportType.RRNP_QUARTERLY,
        frequency: ReportFrequency.QUARTERLY,
      }),
    ]);

    const reportsRepo = createMockReportsRepo();
    const { service } = createService({
      subscriptionsRepo,
      reportsRepo,
      clock,
    });

    await service.processQuarterlySubscriptions();

    expect(reportsRepo.create).toHaveBeenCalledWith(
      expect.objectContaining({
        periodStart: '2026-01-01',
        periodEnd: '2026-03-31',
      }),
    );
  });

  it('calculates Q4 of prior year when current quarter is Q1', async () => {
    // Jan 2026 → prior quarter = Q4 2025 (Oct 1 - Dec 31 2025)
    const clock = createMockClock(new Date(2026, 0, 15));
    const subscriptionsRepo = createMockSubscriptionsRepo();
    vi.mocked(subscriptionsRepo.getDueSubscriptions).mockResolvedValue([
      sampleSubscription({
        reportType: ReportType.RRNP_QUARTERLY,
        frequency: ReportFrequency.QUARTERLY,
      }),
    ]);

    const reportsRepo = createMockReportsRepo();
    const { service } = createService({
      subscriptionsRepo,
      reportsRepo,
      clock,
    });

    await service.processQuarterlySubscriptions();

    expect(reportsRepo.create).toHaveBeenCalledWith(
      expect.objectContaining({
        periodStart: '2025-10-01',
        periodEnd: '2025-12-31',
      }),
    );
  });

  it('processes RRNP_QUARTERLY subscription', async () => {
    const subscriptionsRepo = createMockSubscriptionsRepo();
    vi.mocked(subscriptionsRepo.getDueSubscriptions).mockResolvedValue([
      sampleSubscription({
        reportType: ReportType.RRNP_QUARTERLY,
        frequency: ReportFrequency.QUARTERLY,
      }),
    ]);

    const { service, reportGeneration } = createService({ subscriptionsRepo });

    const result = await service.processQuarterlySubscriptions();

    expect(result.processed).toBe(1);
    expect(reportGeneration.processReport).toHaveBeenCalled();
  });
});

// ============================================================================
// processSubscription — Report record creation
// ============================================================================

describe('processSubscription', () => {
  it('creates a generated_reports record with scheduled=true', async () => {
    const subscriptionsRepo = createMockSubscriptionsRepo();
    vi.mocked(subscriptionsRepo.getDueSubscriptions).mockResolvedValue([
      sampleSubscription({
        reportType: ReportType.WEEKLY_SUMMARY,
        frequency: ReportFrequency.WEEKLY,
      }),
    ]);

    const reportsRepo = createMockReportsRepo();
    const { service } = createService({ subscriptionsRepo, reportsRepo });

    await service.processWeeklySubscriptions(1);

    expect(reportsRepo.create).toHaveBeenCalledWith(
      expect.objectContaining({
        scheduled: true,
        providerId: PROVIDER_ID_1,
        reportType: ReportType.WEEKLY_SUMMARY,
      }),
    );
  });

  it('sets download link expiry to SCHEDULED retention period', async () => {
    const clock = createMockClock(new Date(2026, 0, 19));
    const subscriptionsRepo = createMockSubscriptionsRepo();
    vi.mocked(subscriptionsRepo.getDueSubscriptions).mockResolvedValue([
      sampleSubscription({
        reportType: ReportType.WEEKLY_SUMMARY,
        frequency: ReportFrequency.WEEKLY,
      }),
    ]);

    const reportsRepo = createMockReportsRepo();
    const { service } = createService({
      subscriptionsRepo,
      reportsRepo,
      clock,
    });

    await service.processWeeklySubscriptions(1);

    const createCall = vi.mocked(reportsRepo.create).mock.calls[0][0];
    const expiryDate = new Date(createCall.downloadLinkExpiresAt);
    const expectedExpiry = new Date(2026, 0, 19);
    expectedExpiry.setDate(
      expectedExpiry.getDate() + REPORT_DOWNLOAD_EXPIRY_DAYS.SCHEDULED,
    );

    expect(expiryDate.getDate()).toBe(expectedExpiry.getDate());
    expect(expiryDate.getMonth()).toBe(expectedExpiry.getMonth());
  });

  it('calls reportGeneration.processReport with report ID and provider ID', async () => {
    const subscriptionsRepo = createMockSubscriptionsRepo();
    vi.mocked(subscriptionsRepo.getDueSubscriptions).mockResolvedValue([
      sampleSubscription({
        reportType: ReportType.WEEKLY_SUMMARY,
        frequency: ReportFrequency.WEEKLY,
      }),
    ]);

    const reportsRepo = createMockReportsRepo();
    vi.mocked(reportsRepo.create).mockResolvedValue(
      sampleGeneratedReport({ reportId: REPORT_ID }),
    );

    const { service, reportGeneration } = createService({
      subscriptionsRepo,
      reportsRepo,
    });

    await service.processWeeklySubscriptions(1);

    expect(reportGeneration.processReport).toHaveBeenCalledWith(
      REPORT_ID,
      PROVIDER_ID_1,
    );
  });
});

// ============================================================================
// Notification dispatch
// ============================================================================

describe('notification dispatch', () => {
  it('sends in-app notification on successful report generation', async () => {
    const subscriptionsRepo = createMockSubscriptionsRepo();
    vi.mocked(subscriptionsRepo.getDueSubscriptions).mockResolvedValue([
      sampleSubscription({
        reportType: ReportType.WEEKLY_SUMMARY,
        frequency: ReportFrequency.WEEKLY,
        deliveryMethod: DeliveryMethod.IN_APP,
      }),
    ]);

    const reportsRepo = createMockReportsRepo();
    vi.mocked(reportsRepo.create).mockResolvedValue(
      sampleGeneratedReport({ reportId: REPORT_ID }),
    );

    const { service, notifier } = createService({
      subscriptionsRepo,
      reportsRepo,
    });

    await service.processWeeklySubscriptions(1);

    expect(notifier.sendReportReadyNotification).toHaveBeenCalledWith(
      PROVIDER_ID_1,
      REPORT_ID,
      ReportType.WEEKLY_SUMMARY,
    );
  });

  it('sends email notification when delivery method is EMAIL', async () => {
    const subscriptionsRepo = createMockSubscriptionsRepo();
    vi.mocked(subscriptionsRepo.getDueSubscriptions).mockResolvedValue([
      sampleSubscription({
        reportType: ReportType.WEEKLY_SUMMARY,
        frequency: ReportFrequency.WEEKLY,
        deliveryMethod: DeliveryMethod.EMAIL,
      }),
    ]);

    const reportsRepo = createMockReportsRepo();
    vi.mocked(reportsRepo.create).mockResolvedValue(
      sampleGeneratedReport({ reportId: REPORT_ID }),
    );

    const { service, notifier } = createService({
      subscriptionsRepo,
      reportsRepo,
    });

    await service.processWeeklySubscriptions(1);

    expect(notifier.sendReportReadyEmail).toHaveBeenCalledWith(
      PROVIDER_ID_1,
      REPORT_ID,
      ReportType.WEEKLY_SUMMARY,
    );
  });

  it('sends email notification when delivery method is BOTH', async () => {
    const subscriptionsRepo = createMockSubscriptionsRepo();
    vi.mocked(subscriptionsRepo.getDueSubscriptions).mockResolvedValue([
      sampleSubscription({
        reportType: ReportType.MONTHLY_PERFORMANCE,
        frequency: ReportFrequency.WEEKLY,
        deliveryMethod: DeliveryMethod.BOTH,
      }),
    ]);

    const reportsRepo = createMockReportsRepo();
    vi.mocked(reportsRepo.create).mockResolvedValue(
      sampleGeneratedReport({ reportId: REPORT_ID }),
    );

    const { service, notifier } = createService({
      subscriptionsRepo,
      reportsRepo,
    });

    await service.processWeeklySubscriptions(1);

    expect(notifier.sendReportReadyNotification).toHaveBeenCalled();
    expect(notifier.sendReportReadyEmail).toHaveBeenCalled();
  });

  it('does not send email when delivery method is IN_APP only', async () => {
    const subscriptionsRepo = createMockSubscriptionsRepo();
    vi.mocked(subscriptionsRepo.getDueSubscriptions).mockResolvedValue([
      sampleSubscription({
        reportType: ReportType.WEEKLY_SUMMARY,
        frequency: ReportFrequency.WEEKLY,
        deliveryMethod: DeliveryMethod.IN_APP,
      }),
    ]);

    const { service, notifier } = createService({ subscriptionsRepo });

    await service.processWeeklySubscriptions(1);

    expect(notifier.sendReportReadyNotification).toHaveBeenCalled();
    expect(notifier.sendReportReadyEmail).not.toHaveBeenCalled();
  });

  it('does not send notification when report generation fails', async () => {
    const subscriptionsRepo = createMockSubscriptionsRepo();
    vi.mocked(subscriptionsRepo.getDueSubscriptions).mockResolvedValue([
      sampleSubscription({
        reportType: ReportType.WEEKLY_SUMMARY,
        frequency: ReportFrequency.WEEKLY,
      }),
    ]);

    const reportGeneration = createMockReportGeneration();
    vi.mocked(reportGeneration.processReport).mockRejectedValue(
      new Error('Generation failed'),
    );

    const { service, notifier } = createService({
      subscriptionsRepo,
      reportGeneration,
    });

    const result = await service.processWeeklySubscriptions(1);

    expect(result.failed).toBe(1);
    expect(notifier.sendReportReadyNotification).not.toHaveBeenCalled();
    expect(notifier.sendReportReadyEmail).not.toHaveBeenCalled();
  });
});

// ============================================================================
// Error handling
// ============================================================================

describe('error handling', () => {
  it('marks subscription as failed when processReport throws', async () => {
    const subscriptionsRepo = createMockSubscriptionsRepo();
    vi.mocked(subscriptionsRepo.getDueSubscriptions).mockResolvedValue([
      sampleSubscription({
        reportType: ReportType.WEEKLY_SUMMARY,
        frequency: ReportFrequency.WEEKLY,
      }),
    ]);

    const reportGeneration = createMockReportGeneration();
    vi.mocked(reportGeneration.processReport).mockRejectedValue(
      new Error('DB error'),
    );

    const { service } = createService({ subscriptionsRepo, reportGeneration });

    const result = await service.processWeeklySubscriptions(1);

    expect(result.failed).toBe(1);
    expect(result.details[0].status).toBe('failed');
  });

  it('continues processing other subscriptions after one fails', async () => {
    const subscriptionsRepo = createMockSubscriptionsRepo();
    vi.mocked(subscriptionsRepo.getDueSubscriptions).mockResolvedValue([
      sampleSubscription({
        subscriptionId: SUBSCRIPTION_ID_1,
        providerId: PROVIDER_ID_1,
        reportType: ReportType.WEEKLY_SUMMARY,
        frequency: ReportFrequency.WEEKLY,
      }),
      sampleSubscription({
        subscriptionId: SUBSCRIPTION_ID_2,
        providerId: PROVIDER_ID_2,
        reportType: ReportType.WEEKLY_SUMMARY,
        frequency: ReportFrequency.WEEKLY,
      }),
    ]);

    const reportGeneration = createMockReportGeneration();
    let callCount = 0;
    vi.mocked(reportGeneration.processReport).mockImplementation(async () => {
      callCount++;
      if (callCount === 1) {
        throw new Error('First failed');
      }
    });

    const { service } = createService({ subscriptionsRepo, reportGeneration });

    const result = await service.processWeeklySubscriptions(1);

    expect(result.failed).toBe(1);
    expect(result.processed).toBe(1);
    expect(result.details).toHaveLength(2);
  });

  it('marks subscription as failed when notification throws', async () => {
    const subscriptionsRepo = createMockSubscriptionsRepo();
    vi.mocked(subscriptionsRepo.getDueSubscriptions).mockResolvedValue([
      sampleSubscription({
        reportType: ReportType.WEEKLY_SUMMARY,
        frequency: ReportFrequency.WEEKLY,
      }),
    ]);

    const notifier = createMockNotifier();
    vi.mocked(notifier.sendReportReadyNotification).mockRejectedValue(
      new Error('Notification failed'),
    );

    const { service } = createService({ subscriptionsRepo, notifier });

    const result = await service.processWeeklySubscriptions(1);

    expect(result.failed).toBe(1);
  });
});

// ============================================================================
// Provider scoping (security)
// ============================================================================

describe('provider scoping', () => {
  it('creates report record scoped to subscription provider', async () => {
    const subscriptionsRepo = createMockSubscriptionsRepo();
    vi.mocked(subscriptionsRepo.getDueSubscriptions).mockResolvedValue([
      sampleSubscription({
        providerId: PROVIDER_ID_2,
        reportType: ReportType.WEEKLY_SUMMARY,
        frequency: ReportFrequency.WEEKLY,
      }),
    ]);

    const reportsRepo = createMockReportsRepo();
    const { service } = createService({ subscriptionsRepo, reportsRepo });

    await service.processWeeklySubscriptions(1);

    expect(reportsRepo.create).toHaveBeenCalledWith(
      expect.objectContaining({
        providerId: PROVIDER_ID_2,
      }),
    );
  });

  it('calls processReport with subscription provider ID', async () => {
    const subscriptionsRepo = createMockSubscriptionsRepo();
    vi.mocked(subscriptionsRepo.getDueSubscriptions).mockResolvedValue([
      sampleSubscription({
        providerId: PROVIDER_ID_2,
        reportType: ReportType.WEEKLY_SUMMARY,
        frequency: ReportFrequency.WEEKLY,
      }),
    ]);

    const reportsRepo = createMockReportsRepo();
    vi.mocked(reportsRepo.create).mockResolvedValue(
      sampleGeneratedReport({
        reportId: REPORT_ID,
        providerId: PROVIDER_ID_2,
      }),
    );

    const { service, reportGeneration } = createService({
      subscriptionsRepo,
      reportsRepo,
    });

    await service.processWeeklySubscriptions(1);

    expect(reportGeneration.processReport).toHaveBeenCalledWith(
      REPORT_ID,
      PROVIDER_ID_2,
    );
  });

  it('sends notification scoped to subscription provider', async () => {
    const subscriptionsRepo = createMockSubscriptionsRepo();
    vi.mocked(subscriptionsRepo.getDueSubscriptions).mockResolvedValue([
      sampleSubscription({
        providerId: PROVIDER_ID_2,
        reportType: ReportType.WEEKLY_SUMMARY,
        frequency: ReportFrequency.WEEKLY,
      }),
    ]);

    const reportsRepo = createMockReportsRepo();
    vi.mocked(reportsRepo.create).mockResolvedValue(
      sampleGeneratedReport({
        reportId: REPORT_ID,
        providerId: PROVIDER_ID_2,
      }),
    );

    const { service, notifier } = createService({
      subscriptionsRepo,
      reportsRepo,
    });

    await service.processWeeklySubscriptions(1);

    expect(notifier.sendReportReadyNotification).toHaveBeenCalledWith(
      PROVIDER_ID_2,
      REPORT_ID,
      ReportType.WEEKLY_SUMMARY,
    );
  });
});

// ============================================================================
// Default format mapping
// ============================================================================

describe('default format for report types', () => {
  it('creates WEEKLY_SUMMARY as PDF', async () => {
    const subscriptionsRepo = createMockSubscriptionsRepo();
    vi.mocked(subscriptionsRepo.getDueSubscriptions).mockResolvedValue([
      sampleSubscription({
        reportType: ReportType.WEEKLY_SUMMARY,
        frequency: ReportFrequency.WEEKLY,
      }),
    ]);

    const reportsRepo = createMockReportsRepo();
    const { service } = createService({ subscriptionsRepo, reportsRepo });

    await service.processWeeklySubscriptions(1);

    expect(reportsRepo.create).toHaveBeenCalledWith(
      expect.objectContaining({ format: ReportFormat.PDF }),
    );
  });

  it('creates REJECTION_DIGEST as PDF', async () => {
    const subscriptionsRepo = createMockSubscriptionsRepo();
    vi.mocked(subscriptionsRepo.getDueSubscriptions).mockResolvedValue([
      sampleSubscription({
        reportType: ReportType.REJECTION_DIGEST,
        frequency: ReportFrequency.DAILY,
      }),
    ]);

    const rejectionChecker = createMockRejectionChecker();
    vi.mocked(rejectionChecker.hasRejectionsInPeriod).mockResolvedValue(true);

    const reportsRepo = createMockReportsRepo();
    const { service } = createService({
      subscriptionsRepo,
      rejectionChecker,
      reportsRepo,
    });

    await service.processDailySubscriptions();

    expect(reportsRepo.create).toHaveBeenCalledWith(
      expect.objectContaining({ format: ReportFormat.PDF }),
    );
  });
});
