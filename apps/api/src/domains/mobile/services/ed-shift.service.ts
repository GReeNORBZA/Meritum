import type { EdShiftsRepository, ShiftListFilters, ShiftSummary } from '../repos/ed-shifts.repo.js';
import type { SelectEdShift } from '@meritum/shared/schemas/db/mobile.schema.js';
import {
  MobileShiftStatus,
  MobileAuditAction,
  AfterHoursBracket,
  MOBILE_STANDARD_HOURS_START,
  MOBILE_STANDARD_HOURS_END,
} from '@meritum/shared/constants/mobile.constants.js';
import {
  NotFoundError,
  BusinessRuleError,
  ConflictError,
} from '../../../lib/errors.js';

// ---------------------------------------------------------------------------
// Dependency interfaces (injected by handler / test)
// ---------------------------------------------------------------------------

export interface LocationCheck {
  belongsToPhysician(locationId: string, physicianId: string): Promise<boolean>;
}

export interface ClaimCreator {
  createClaimFromShift(
    physicianId: string,
    actorId: string,
    shiftId: string,
    encounterData: {
      patientId: string;
      dateOfService: string;
      claimType: string;
    },
  ): Promise<{ claimId: string }>;
}

export interface HscEligibilityCheck {
  isEligibleForModifier(hscCode: string, modifier: string): Promise<boolean>;
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

export interface EdShiftServiceDeps {
  repo: EdShiftsRepository;
  locationCheck: LocationCheck;
  claimCreator: ClaimCreator;
  hscEligibility?: HscEligibilityCheck;
  auditRepo: AuditRepo;
}

// ---------------------------------------------------------------------------
// After-hours detection result
// ---------------------------------------------------------------------------

export interface AfterHoursResult {
  modifier: AfterHoursBracket | null;
  eligible: boolean;
}

// ---------------------------------------------------------------------------
// Log patient result
// ---------------------------------------------------------------------------

export interface LogPatientResult {
  claimId: string;
  afterHours: AfterHoursResult;
}

// ---------------------------------------------------------------------------
// End shift result
// ---------------------------------------------------------------------------

export interface EndShiftResult {
  shift: SelectEdShift;
  summary: ShiftSummary;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const AUDIT_CATEGORY = 'mobile';
const DEFAULT_CLAIM_TYPE = 'AHCIP';
const TIMEZONE_AMERICA_EDMONTON = 'America/Edmonton';

// ---------------------------------------------------------------------------
// Alberta statutory holidays
// ---------------------------------------------------------------------------

/**
 * Returns all Alberta statutory holidays for a given year.
 * Fixed-date holidays: New Year's, Canada Day, Truth & Reconciliation Day,
 * Remembrance Day, Christmas Day.
 * Relative holidays: Family Day, Good Friday, Victoria Day, Heritage Day,
 * Labour Day, Thanksgiving.
 */
export function getAlbertaStatutoryHolidays(year: number): Date[] {
  const holidays: Date[] = [];

  // Fixed-date holidays (month is 0-indexed)
  holidays.push(new Date(year, 0, 1));   // New Year's Day
  holidays.push(new Date(year, 6, 1));   // Canada Day
  holidays.push(new Date(year, 8, 30));  // Truth and Reconciliation Day
  holidays.push(new Date(year, 10, 11)); // Remembrance Day
  holidays.push(new Date(year, 11, 25)); // Christmas Day

  // Family Day: 3rd Monday of February
  holidays.push(nthWeekdayOfMonth(year, 1, 1, 3));

  // Good Friday: 2 days before Easter Sunday
  const easter = computeEasterSunday(year);
  const goodFriday = new Date(easter);
  goodFriday.setDate(goodFriday.getDate() - 2);
  holidays.push(goodFriday);

  // Victoria Day: last Monday before May 25
  const may25 = new Date(year, 4, 25);
  const dayOfWeek = may25.getDay();
  const diff = dayOfWeek === 1 ? 7 : (dayOfWeek === 0 ? 1 : dayOfWeek - 1);
  holidays.push(new Date(year, 4, 25 - diff));

  // Heritage Day: 1st Monday of August
  holidays.push(nthWeekdayOfMonth(year, 7, 1, 1));

  // Labour Day: 1st Monday of September
  holidays.push(nthWeekdayOfMonth(year, 8, 1, 1));

  // Thanksgiving: 2nd Monday of October
  holidays.push(nthWeekdayOfMonth(year, 9, 1, 2));

  return holidays;
}

/**
 * Get the nth occurrence of a weekday in a month.
 * @param year - Full year
 * @param month - 0-indexed month
 * @param weekday - Day of week (0=Sun, 1=Mon, ..., 6=Sat)
 * @param n - Which occurrence (1=first, 2=second, etc.)
 */
function nthWeekdayOfMonth(
  year: number,
  month: number,
  weekday: number,
  n: number,
): Date {
  const first = new Date(year, month, 1);
  const firstDay = first.getDay();
  let dayOffset = weekday - firstDay;
  if (dayOffset < 0) dayOffset += 7;
  const date = 1 + dayOffset + (n - 1) * 7;
  return new Date(year, month, date);
}

/**
 * Compute Easter Sunday using the Anonymous Gregorian algorithm.
 */
function computeEasterSunday(year: number): Date {
  const a = year % 19;
  const b = Math.floor(year / 100);
  const c = year % 100;
  const d = Math.floor(b / 4);
  const e = b % 4;
  const f = Math.floor((b + 8) / 25);
  const g = Math.floor((b - f + 1) / 3);
  const h = (19 * a + b - d - g + 15) % 30;
  const i = Math.floor(c / 4);
  const k = c % 4;
  const l = (32 + 2 * e + 2 * i - h - k) % 7;
  const m = Math.floor((a + 11 * h + 22 * l) / 451);
  const month = Math.floor((h + l - 7 * m + 114) / 31) - 1; // 0-indexed
  const day = ((h + l - 7 * m + 114) % 31) + 1;
  return new Date(year, month, day);
}

/**
 * Check whether a local date falls on an Alberta statutory holiday.
 */
function isAlbertaStatutoryHoliday(localDate: Date): boolean {
  const year = localDate.getFullYear();
  const holidays = getAlbertaStatutoryHolidays(year);
  const month = localDate.getMonth();
  const day = localDate.getDate();
  return holidays.some((h) => h.getMonth() === month && h.getDate() === day);
}

// ---------------------------------------------------------------------------
// After-hours detection (pure function)
// ---------------------------------------------------------------------------

/**
 * Detect after-hours bracket for an encounter timestamp.
 *
 * Steps:
 * 1. Convert encounter time to Alberta local time (America/Edmonton).
 * 2. Weekend (Sat/Sun) → WKND.
 * 3. Alberta statutory holiday → WKND.
 * 4. Weekday 17:00–23:00 → AFHR, 23:00–08:00 → NGHR.
 * 5. Otherwise null (standard hours).
 *
 * Returns the detected modifier and whether it's eligible (always true
 * when a modifier is detected; HSC eligibility checked separately).
 */
export function detectAfterHoursBracket(
  encounterTimestamp: Date,
  timezone: string = TIMEZONE_AMERICA_EDMONTON,
): { modifier: AfterHoursBracket | null } {
  // Convert to local time components in the target timezone
  const localParts = getLocalTimeParts(encounterTimestamp, timezone);
  const { hour, dayOfWeek, localDate } = localParts;

  // Weekend check: Saturday (6) or Sunday (0)
  if (dayOfWeek === 0 || dayOfWeek === 6) {
    return { modifier: AfterHoursBracket.WKND };
  }

  // Statutory holiday check
  if (isAlbertaStatutoryHoliday(localDate)) {
    return { modifier: AfterHoursBracket.WKND };
  }

  // Weekday time brackets
  if (hour >= MOBILE_STANDARD_HOURS_END && hour < 23) {
    // 17:00–22:59 → AFHR
    return { modifier: AfterHoursBracket.AFHR };
  }

  if (hour >= 23 || hour < MOBILE_STANDARD_HOURS_START) {
    // 23:00–07:59 → NGHR
    return { modifier: AfterHoursBracket.NGHR };
  }

  // Standard hours (08:00–16:59)
  return { modifier: null };
}

/**
 * Extract local time components from a timestamp in the given timezone.
 */
function getLocalTimeParts(
  timestamp: Date,
  timezone: string,
): { hour: number; dayOfWeek: number; localDate: Date } {
  const formatter = new Intl.DateTimeFormat('en-CA', {
    timeZone: timezone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });

  const parts = formatter.formatToParts(timestamp);
  const get = (type: string) =>
    parts.find((p) => p.type === type)?.value ?? '0';

  const year = parseInt(get('year'), 10);
  const month = parseInt(get('month'), 10) - 1; // 0-indexed
  const day = parseInt(get('day'), 10);
  const hour = parseInt(get('hour'), 10);

  // Build a local date for holiday checks
  const localDate = new Date(year, month, day);
  const dayOfWeek = localDate.getDay();

  return { hour, dayOfWeek, localDate };
}

// ---------------------------------------------------------------------------
// Service functions
// ---------------------------------------------------------------------------

/**
 * Start a new ED shift for the physician at the given location.
 *
 * Validates:
 * - Location belongs to the physician.
 * - No active shift already exists (enforced by DB unique index too).
 *
 * Creates shift with status ACTIVE, logs audit event.
 */
export async function startShift(
  deps: EdShiftServiceDeps,
  providerId: string,
  locationId: string,
): Promise<SelectEdShift> {
  // 1. Validate location belongs to physician
  const locationValid = await deps.locationCheck.belongsToPhysician(
    locationId,
    providerId,
  );
  if (!locationValid) {
    throw new NotFoundError('Practice location');
  }

  // 2. Check for existing active shift
  const existing = await deps.repo.getActive(providerId);
  if (existing) {
    throw new ConflictError(
      'Physician already has an active shift. End the current shift before starting a new one.',
    );
  }

  // 3. Create shift
  const shift = await deps.repo.create({
    providerId,
    locationId,
    shiftStart: new Date(),
  });

  // 4. Audit log
  await deps.auditRepo.appendAuditLog({
    userId: providerId,
    action: MobileAuditAction.SHIFT_STARTED,
    category: AUDIT_CATEGORY,
    resourceType: 'ed_shift',
    resourceId: shift.shiftId,
    detail: {
      locationId,
      shiftStart: shift.shiftStart.toISOString(),
    },
  });

  return shift;
}

/**
 * Get the currently active shift for the physician, or null.
 */
export async function getActiveShift(
  deps: EdShiftServiceDeps,
  providerId: string,
): Promise<SelectEdShift | null> {
  return deps.repo.getActive(providerId);
}

/**
 * Log a patient encounter during an active shift.
 *
 * Creates a draft AHCIP claim linked to the shift, detects after-hours
 * eligibility, increments shift counters.
 */
export async function logPatient(
  deps: EdShiftServiceDeps,
  providerId: string,
  shiftId: string,
  logData: {
    patientId: string;
    healthServiceCode: string;
    modifiers?: string[];
    dateOfService?: string;
    quickNote?: string;
  },
): Promise<LogPatientResult> {
  // 1. Validate shift exists, is active, and belongs to provider
  const shift = await deps.repo.getById(shiftId, providerId);
  if (!shift) {
    throw new NotFoundError('Shift');
  }
  if (shift.status !== MobileShiftStatus.ACTIVE) {
    throw new BusinessRuleError(
      'Cannot log patients to a shift that is not active',
    );
  }

  // 2. Determine date of service (default to today)
  const dateOfService =
    logData.dateOfService ?? new Date().toISOString().split('T')[0];

  // 3. Create draft AHCIP claim via the claim domain
  const encounterTimestamp = new Date();
  const { claimId } = await deps.claimCreator.createClaimFromShift(
    providerId,
    providerId, // actorId = providerId for physician context
    shiftId,
    {
      patientId: logData.patientId,
      dateOfService,
      claimType: DEFAULT_CLAIM_TYPE,
    },
  );

  // 4. Detect after-hours bracket
  const { modifier } = detectAfterHoursBracket(encounterTimestamp);

  // 5. Check HSC eligibility for the detected modifier
  let eligible = modifier !== null;
  if (modifier && deps.hscEligibility) {
    eligible = await deps.hscEligibility.isEligibleForModifier(
      logData.healthServiceCode,
      modifier,
    );
  }

  const afterHours: AfterHoursResult = { modifier, eligible };

  // 6. Increment shift patient count and estimated value
  // Fee amount is 0 for now — the claim is a draft; actual fee comes after validation
  await deps.repo.incrementPatientCount(shiftId, providerId, '0');

  // 7. Audit log
  await deps.auditRepo.appendAuditLog({
    userId: providerId,
    action: MobileAuditAction.PATIENT_LOGGED,
    category: AUDIT_CATEGORY,
    resourceType: 'ed_shift',
    resourceId: shiftId,
    detail: {
      claimId,
      patientId: logData.patientId,
      healthServiceCode: logData.healthServiceCode,
      afterHoursModifier: modifier,
      afterHoursEligible: eligible,
    },
  });

  return { claimId, afterHours };
}

/**
 * End an active shift. Returns the shift and a summary of linked claims.
 */
export async function endShift(
  deps: EdShiftServiceDeps,
  providerId: string,
  shiftId: string,
): Promise<EndShiftResult> {
  // 1. Validate shift exists, is active, and belongs to provider
  const existing = await deps.repo.getById(shiftId, providerId);
  if (!existing) {
    throw new NotFoundError('Shift');
  }
  if (existing.status !== MobileShiftStatus.ACTIVE) {
    throw new BusinessRuleError('Only active shifts can be ended');
  }

  // 2. End the shift (recalculates patient_count and estimated_value)
  const ended = await deps.repo.endShift(shiftId, providerId);
  if (!ended) {
    throw new NotFoundError('Shift');
  }

  // 3. Get the summary with linked claims
  const summary = await deps.repo.getSummary(shiftId, providerId);
  if (!summary) {
    throw new NotFoundError('Shift');
  }

  // 4. Audit log
  await deps.auditRepo.appendAuditLog({
    userId: providerId,
    action: MobileAuditAction.SHIFT_ENDED,
    category: AUDIT_CATEGORY,
    resourceType: 'ed_shift',
    resourceId: shiftId,
    detail: {
      patientCount: ended.patientCount,
      estimatedValue: ended.estimatedValue,
      shiftEnd: ended.shiftEnd?.toISOString() ?? null,
    },
  });

  return { shift: ended, summary };
}

/**
 * Get a shift summary (shift details + linked claims).
 */
export async function getShiftSummary(
  deps: EdShiftServiceDeps,
  providerId: string,
  shiftId: string,
): Promise<ShiftSummary> {
  const summary = await deps.repo.getSummary(shiftId, providerId);
  if (!summary) {
    throw new NotFoundError('Shift');
  }
  return summary;
}

/**
 * List shifts for a physician with optional filters.
 */
export async function listShifts(
  deps: EdShiftServiceDeps,
  providerId: string,
  filters?: ShiftListFilters,
): Promise<{ data: SelectEdShift[]; total: number }> {
  return deps.repo.list(providerId, filters);
}
