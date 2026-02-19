import type { SelectEdShift } from '@meritum/shared/schemas/db/mobile.schema.js';
import { MobileAuditAction } from '@meritum/shared/constants/mobile.constants.js';

// ---------------------------------------------------------------------------
// Dependency interfaces (injected by handler / test)
// ---------------------------------------------------------------------------

export interface ClaimCounter {
  countTodayClaims(physicianId: string, todayStart: Date): Promise<number>;
  countPendingQueue(physicianId: string): Promise<number>;
}

export interface UnreadCounter {
  countUnread(recipientId: string): Promise<number>;
}

export interface ActiveShiftLookup {
  getActive(providerId: string): Promise<SelectEdShift | null>;
}

export interface AuditRepo {
  appendAuditLog(entry: {
    userId?: string | null;
    action: string;
    category: string;
    resourceType?: string | null;
    resourceId?: string | null;
    detail?: Record<string, unknown> | null;
    ipAddress?: string | null;
    userAgent?: string | null;
  }): Promise<unknown>;
}

export interface MobileSummaryServiceDeps {
  claimCounter: ClaimCounter;
  unreadCounter: UnreadCounter;
  activeShiftLookup: ActiveShiftLookup;
  auditRepo: AuditRepo;
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

export interface ActiveShiftSummary {
  shiftId: string;
  shiftStart: string;
  patientCount: number;
  estimatedValue: string;
}

export interface MobileSummary {
  todayClaimsCount: number;
  pendingQueueCount: number;
  unreadNotificationsCount: number;
  activeShift: ActiveShiftSummary | null;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const AUDIT_CATEGORY = 'mobile';
const AUDIT_RATE_LIMIT_MS = 10 * 60 * 1000; // 10 minutes

// ---------------------------------------------------------------------------
// Audit rate limiter (in-memory, per provider)
// ---------------------------------------------------------------------------

const lastAuditTimestamps = new Map<string, number>();

function shouldLogAudit(providerId: string): boolean {
  const now = Date.now();
  const lastLogged = lastAuditTimestamps.get(providerId);
  if (lastLogged && now - lastLogged < AUDIT_RATE_LIMIT_MS) {
    return false;
  }
  lastAuditTimestamps.set(providerId, now);
  return true;
}

/**
 * Reset the audit rate limiter. Exposed for testing only.
 */
export function resetAuditRateLimiter(): void {
  lastAuditTimestamps.clear();
}

// ---------------------------------------------------------------------------
// Service functions
// ---------------------------------------------------------------------------

/**
 * Get a lightweight KPI summary for the mobile home screen.
 *
 * Returns:
 * - today_claims_count: claims created today by this physician
 * - pending_queue_count: claims in 'queued' state awaiting submission
 * - unread_notifications_count: unread notification count
 * - active_shift: current active ED shift details or null
 *
 * All queries are provider-scoped. No PHI is returned — counts only.
 * Audit log is rate-limited to max 1 per 10 minutes per physician.
 */
export async function getSummary(
  deps: MobileSummaryServiceDeps,
  providerId: string,
): Promise<MobileSummary> {
  // Compute start of today (UTC midnight)
  const now = new Date();
  const todayStart = new Date(
    Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()),
  );

  // Run all queries in parallel for performance
  const [todayClaimsCount, pendingQueueCount, unreadNotificationsCount, activeShiftRow] =
    await Promise.all([
      deps.claimCounter.countTodayClaims(providerId, todayStart),
      deps.claimCounter.countPendingQueue(providerId),
      deps.unreadCounter.countUnread(providerId),
      deps.activeShiftLookup.getActive(providerId),
    ]);

  // Map active shift to lightweight summary (no PHI)
  const activeShift: ActiveShiftSummary | null = activeShiftRow
    ? {
        shiftId: activeShiftRow.shiftId,
        shiftStart: activeShiftRow.shiftStart.toISOString(),
        patientCount: activeShiftRow.patientCount,
        estimatedValue: activeShiftRow.estimatedValue,
      }
    : null;

  // Rate-limited audit log
  if (shouldLogAudit(providerId)) {
    await deps.auditRepo.appendAuditLog({
      userId: providerId,
      action: MobileAuditAction.SUMMARY_VIEWED,
      category: AUDIT_CATEGORY,
      resourceType: 'mobile_summary',
      detail: {
        todayClaimsCount,
        pendingQueueCount,
        unreadNotificationsCount,
        hasActiveShift: activeShift !== null,
      },
    });
  }

  return {
    todayClaimsCount,
    pendingQueueCount,
    unreadNotificationsCount,
    activeShift,
  };
}
