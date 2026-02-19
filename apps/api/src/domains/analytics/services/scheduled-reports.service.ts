// ============================================================================
// Domain 8: Scheduled Reports Service
// Processes report subscriptions on schedule. Called by cron jobs at appropriate
// intervals (daily, weekly, monthly, quarterly).
// ============================================================================

import {
  ReportType,
  ReportFormat,
  ReportFrequency,
  DeliveryMethod,
  REPORT_DOWNLOAD_EXPIRY_DAYS,
} from '@meritum/shared/constants/analytics.constants.js';
import type { SelectReportSubscription } from '@meritum/shared/schemas/db/analytics.schema.js';
import type { ReportSubscriptionsRepository } from '../repos/report-subscriptions.repo.js';
import type { GeneratedReportsRepository } from '../repos/generated-reports.repo.js';
import type { ReportGenerationService } from './report-generation.service.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Notification dispatcher abstraction (Domain 9 dependency). */
export interface ScheduledReportNotifier {
  sendReportReadyNotification(
    providerId: string,
    reportId: string,
    reportType: string,
  ): Promise<void>;
  sendReportReadyEmail(
    providerId: string,
    reportId: string,
    reportType: string,
  ): Promise<void>;
}

/** Rejection check — queries whether rejections exist in a time window. */
export interface RejectionChecker {
  hasRejectionsInPeriod(
    providerId: string,
    since: string,
    until: string,
  ): Promise<boolean>;
}

/** Clock abstraction for testability. */
export interface ScheduleClock {
  now(): Date;
}

export interface ScheduledReportsDeps {
  subscriptionsRepo: ReportSubscriptionsRepository;
  reportsRepo: GeneratedReportsRepository;
  reportGeneration: ReportGenerationService;
  notifier: ScheduledReportNotifier;
  rejectionChecker: RejectionChecker;
  clock?: ScheduleClock;
}

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

export interface ScheduledProcessingResult {
  processed: number;
  skipped: number;
  failed: number;
  details: Array<{
    subscriptionId: string;
    providerId: string;
    reportType: string;
    status: 'processed' | 'skipped' | 'failed';
    reason?: string;
  }>;
}

// ---------------------------------------------------------------------------
// Date / Business Day Helpers
// ---------------------------------------------------------------------------

/** Format a Date as YYYY-MM-DD. */
function formatDate(d: Date): string {
  const year = d.getFullYear();
  const month = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

/** Get the Monday of the week containing the given date. */
function getMondayOfWeek(d: Date): Date {
  const result = new Date(d);
  const day = result.getDay(); // 0=Sun, 1=Mon, ...
  const diff = day === 0 ? 6 : day - 1;
  result.setDate(result.getDate() - diff);
  return result;
}

/**
 * Calculate the Nth business day of a given month/year.
 * Business days = weekdays (Mon-Fri). Does not account for statutory holidays.
 */
export function getNthBusinessDay(
  year: number,
  month: number,
  n: number,
): Date {
  let businessDayCount = 0;
  let day = 1;

  while (businessDayCount < n) {
    const d = new Date(year, month, day);
    const dow = d.getDay();
    if (dow !== 0 && dow !== 6) {
      businessDayCount++;
    }
    if (businessDayCount < n) {
      day++;
    }
  }

  return new Date(year, month, day);
}

/**
 * Check whether today is the 3rd business day of the month.
 */
export function isThirdBusinessDay(today: Date): boolean {
  const thirdBD = getNthBusinessDay(
    today.getFullYear(),
    today.getMonth(),
    3,
  );
  return (
    today.getFullYear() === thirdBD.getFullYear() &&
    today.getMonth() === thirdBD.getMonth() &&
    today.getDate() === thirdBD.getDate()
  );
}

/**
 * Determine the prior month period: first and last day of prior month.
 */
function getPriorMonthPeriod(today: Date): { start: string; end: string } {
  const year = today.getFullYear();
  const month = today.getMonth(); // 0-indexed, so current month
  // Prior month
  const priorMonth = month === 0 ? 11 : month - 1;
  const priorYear = month === 0 ? year - 1 : year;
  const firstDay = new Date(priorYear, priorMonth, 1);
  const lastDay = new Date(priorYear, priorMonth + 1, 0); // last day of prior month
  return { start: formatDate(firstDay), end: formatDate(lastDay) };
}

/**
 * Determine the prior week period: Monday to Sunday of the previous week.
 */
function getPriorWeekPeriod(today: Date): { start: string; end: string } {
  const thisMon = getMondayOfWeek(today);
  const priorMon = new Date(thisMon);
  priorMon.setDate(priorMon.getDate() - 7);
  const priorSun = new Date(priorMon);
  priorSun.setDate(priorSun.getDate() + 6);
  return { start: formatDate(priorMon), end: formatDate(priorSun) };
}

/**
 * Determine the prior quarter period.
 * Q1=Jan-Mar, Q2=Apr-Jun, Q3=Jul-Sep, Q4=Oct-Dec.
 */
function getPriorQuarterPeriod(today: Date): { start: string; end: string } {
  const month = today.getMonth();
  const year = today.getFullYear();
  const currentQuarter = Math.floor(month / 3);
  const priorQuarter = currentQuarter === 0 ? 3 : currentQuarter - 1;
  const priorYear = currentQuarter === 0 ? year - 1 : year;
  const startMonth = priorQuarter * 3;
  const start = new Date(priorYear, startMonth, 1);
  const end = new Date(priorYear, startMonth + 3, 0);
  return { start: formatDate(start), end: formatDate(end) };
}

/**
 * Get the upcoming 7-day window from today (for WCB timing alerts).
 */
function getUpcoming7DayPeriod(today: Date): { start: string; end: string } {
  const end = new Date(today);
  end.setDate(end.getDate() + 7);
  return { start: formatDate(today), end: formatDate(end) };
}

/**
 * Get the past 24-hour window (for daily rejection digest).
 */
function getPast24HourPeriod(today: Date): { start: string; end: string } {
  const yesterday = new Date(today);
  yesterday.setDate(yesterday.getDate() - 1);
  return { start: formatDate(yesterday), end: formatDate(today) };
}

/**
 * Map report type to default format.
 */
function getDefaultFormat(reportType: string): string {
  switch (reportType) {
    case ReportType.WEEKLY_SUMMARY:
    case ReportType.MONTHLY_PERFORMANCE:
    case ReportType.RRNP_QUARTERLY:
    case ReportType.WCB_TIMING:
    case ReportType.REJECTION_DIGEST:
      return ReportFormat.PDF;
    case ReportType.ACCOUNTANT_SUMMARY:
      return ReportFormat.PDF;
    case ReportType.ACCOUNTANT_DETAIL:
      return ReportFormat.CSV;
    default:
      return ReportFormat.PDF;
  }
}

/**
 * Calculate download link expiry date for scheduled reports.
 */
function getExpiryDate(today: Date): Date {
  const expiry = new Date(today);
  expiry.setDate(expiry.getDate() + REPORT_DOWNLOAD_EXPIRY_DAYS.SCHEDULED);
  return expiry;
}

// ---------------------------------------------------------------------------
// Service Factory
// ---------------------------------------------------------------------------

export function createScheduledReportsService(deps: ScheduledReportsDeps) {
  const {
    subscriptionsRepo,
    reportsRepo,
    reportGeneration,
    notifier,
    rejectionChecker,
  } = deps;

  const clock: ScheduleClock = deps.clock ?? { now: () => new Date() };

  /**
   * Process a single subscription: create report record, generate, notify.
   */
  async function processSubscription(
    subscription: SelectReportSubscription,
    periodStart: string,
    periodEnd: string,
  ): Promise<'processed' | 'failed'> {
    const today = clock.now();
    const format = getDefaultFormat(subscription.reportType);

    // Create the generated_reports record with scheduled=true
    const report = await reportsRepo.create({
      providerId: subscription.providerId,
      reportType: subscription.reportType,
      format,
      periodStart,
      periodEnd,
      filePath: '',
      fileSizeBytes: 0,
      downloadLinkExpiresAt: getExpiryDate(today),
      scheduled: true,
      downloaded: false,
    });

    try {
      // Generate the report
      await reportGeneration.processReport(
        report.reportId,
        subscription.providerId,
      );

      // Send in-app notification (always for scheduled reports)
      await notifier.sendReportReadyNotification(
        subscription.providerId,
        report.reportId,
        subscription.reportType,
      );

      // Send email notification if delivery method is EMAIL or BOTH
      if (
        subscription.deliveryMethod === DeliveryMethod.EMAIL ||
        subscription.deliveryMethod === DeliveryMethod.BOTH
      ) {
        await notifier.sendReportReadyEmail(
          subscription.providerId,
          report.reportId,
          subscription.reportType,
        );
      }

      return 'processed';
    } catch {
      return 'failed';
    }
  }

  /**
   * Process DAILY subscriptions.
   * Currently only REJECTION_DIGEST is daily.
   * Skips if no rejections in the past 24 hours (FRD: "Daily (if any)").
   */
  async function processDailySubscriptions(): Promise<ScheduledProcessingResult> {
    const today = clock.now();
    const result: ScheduledProcessingResult = {
      processed: 0,
      skipped: 0,
      failed: 0,
      details: [],
    };

    const subscriptions = await subscriptionsRepo.getDueSubscriptions(
      ReportFrequency.DAILY,
    );

    const past24h = getPast24HourPeriod(today);

    for (const sub of subscriptions) {
      // Daily rejection digest: skip if no rejections
      if (sub.reportType === ReportType.REJECTION_DIGEST) {
        const hasRejections = await rejectionChecker.hasRejectionsInPeriod(
          sub.providerId,
          past24h.start,
          past24h.end,
        );

        if (!hasRejections) {
          result.skipped++;
          result.details.push({
            subscriptionId: sub.subscriptionId,
            providerId: sub.providerId,
            reportType: sub.reportType,
            status: 'skipped',
            reason: 'No rejections in past 24 hours',
          });
          continue;
        }
      }

      const status = await processSubscription(sub, past24h.start, past24h.end);

      if (status === 'processed') {
        result.processed++;
      } else {
        result.failed++;
      }

      result.details.push({
        subscriptionId: sub.subscriptionId,
        providerId: sub.providerId,
        reportType: sub.reportType,
        status,
      });
    }

    return result;
  }

  /**
   * Process WEEKLY subscriptions.
   * WEEKLY_SUMMARY runs on Monday (dayOfWeek=1), covers prior week.
   * WCB_TIMING runs on Wednesday (dayOfWeek=3), covers upcoming 7 days.
   */
  async function processWeeklySubscriptions(
    dayOfWeek: number,
  ): Promise<ScheduledProcessingResult> {
    const today = clock.now();
    const result: ScheduledProcessingResult = {
      processed: 0,
      skipped: 0,
      failed: 0,
      details: [],
    };

    const subscriptions = await subscriptionsRepo.getDueSubscriptions(
      ReportFrequency.WEEKLY,
    );

    for (const sub of subscriptions) {
      // WEEKLY_SUMMARY: only on Monday
      if (sub.reportType === ReportType.WEEKLY_SUMMARY && dayOfWeek !== 1) {
        result.skipped++;
        result.details.push({
          subscriptionId: sub.subscriptionId,
          providerId: sub.providerId,
          reportType: sub.reportType,
          status: 'skipped',
          reason: 'Weekly summary only runs on Monday',
        });
        continue;
      }

      // WCB_TIMING: only on Wednesday
      if (sub.reportType === ReportType.WCB_TIMING && dayOfWeek !== 3) {
        result.skipped++;
        result.details.push({
          subscriptionId: sub.subscriptionId,
          providerId: sub.providerId,
          reportType: sub.reportType,
          status: 'skipped',
          reason: 'WCB timing report only runs on Wednesday',
        });
        continue;
      }

      // Determine period based on report type
      let period: { start: string; end: string };
      if (sub.reportType === ReportType.WCB_TIMING) {
        period = getUpcoming7DayPeriod(today);
      } else {
        period = getPriorWeekPeriod(today);
      }

      const status = await processSubscription(sub, period.start, period.end);

      if (status === 'processed') {
        result.processed++;
      } else {
        result.failed++;
      }

      result.details.push({
        subscriptionId: sub.subscriptionId,
        providerId: sub.providerId,
        reportType: sub.reportType,
        status,
      });
    }

    return result;
  }

  /**
   * Process MONTHLY subscriptions.
   * MONTHLY_PERFORMANCE and ACCOUNTANT reports generated on 3rd business day.
   * Covers the prior month.
   */
  async function processMonthlySubscriptions(): Promise<ScheduledProcessingResult> {
    const today = clock.now();
    const result: ScheduledProcessingResult = {
      processed: 0,
      skipped: 0,
      failed: 0,
      details: [],
    };

    // Only process on the 3rd business day of the month
    if (!isThirdBusinessDay(today)) {
      return result;
    }

    const subscriptions = await subscriptionsRepo.getDueSubscriptions(
      ReportFrequency.MONTHLY,
    );

    const priorMonth = getPriorMonthPeriod(today);

    for (const sub of subscriptions) {
      const status = await processSubscription(
        sub,
        priorMonth.start,
        priorMonth.end,
      );

      if (status === 'processed') {
        result.processed++;
      } else {
        result.failed++;
      }

      result.details.push({
        subscriptionId: sub.subscriptionId,
        providerId: sub.providerId,
        reportType: sub.reportType,
        status,
      });
    }

    return result;
  }

  /**
   * Process QUARTERLY subscriptions.
   * RRNP_QUARTERLY generated after each quarter end.
   * Covers the prior quarter.
   */
  async function processQuarterlySubscriptions(): Promise<ScheduledProcessingResult> {
    const today = clock.now();
    const result: ScheduledProcessingResult = {
      processed: 0,
      skipped: 0,
      failed: 0,
      details: [],
    };

    const subscriptions = await subscriptionsRepo.getDueSubscriptions(
      ReportFrequency.QUARTERLY,
    );

    const priorQuarter = getPriorQuarterPeriod(today);

    for (const sub of subscriptions) {
      const status = await processSubscription(
        sub,
        priorQuarter.start,
        priorQuarter.end,
      );

      if (status === 'processed') {
        result.processed++;
      } else {
        result.failed++;
      }

      result.details.push({
        subscriptionId: sub.subscriptionId,
        providerId: sub.providerId,
        reportType: sub.reportType,
        status,
      });
    }

    return result;
  }

  return {
    processDailySubscriptions,
    processWeeklySubscriptions,
    processMonthlySubscriptions,
    processQuarterlySubscriptions,
    // Exported for testing
    processSubscription,
  };
}

export type ScheduledReportsService = ReturnType<
  typeof createScheduledReportsService
>;
