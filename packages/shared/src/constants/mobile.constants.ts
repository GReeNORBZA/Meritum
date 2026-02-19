// ============================================================================
// Domain 10: Mobile Companion — Constants
// ============================================================================

// --- Mobile Shift Status ---

export const MobileShiftStatus = {
  ACTIVE: 'ACTIVE',
  ENDED: 'ENDED',
  REVIEWED: 'REVIEWED',
} as const;

export type MobileShiftStatus =
  (typeof MobileShiftStatus)[keyof typeof MobileShiftStatus];

// --- After-Hours Time Brackets (Alberta) ---

export const AfterHoursBracket = {
  AFHR: 'AFHR',
  NGHR: 'NGHR',
  WKND: 'WKND',
} as const;

export type AfterHoursBracket =
  (typeof AfterHoursBracket)[keyof typeof AfterHoursBracket];

interface AfterHoursTimeBracketConfig {
  readonly bracket: AfterHoursBracket;
  readonly label: string;
  readonly description: string;
  readonly startHour: number;
  readonly endHour: number;
}

export const AFTER_HOURS_BRACKET_CONFIGS: Readonly<
  Record<AfterHoursBracket, AfterHoursTimeBracketConfig>
> = Object.freeze({
  [AfterHoursBracket.AFHR]: {
    bracket: AfterHoursBracket.AFHR,
    label: 'Weekday Evening',
    description: 'Weekday evening hours 17:00–23:00',
    startHour: 17,
    endHour: 23,
  },
  [AfterHoursBracket.NGHR]: {
    bracket: AfterHoursBracket.NGHR,
    label: 'Weekday Night',
    description: 'Weekday night hours 23:00–08:00',
    startHour: 23,
    endHour: 8,
  },
  [AfterHoursBracket.WKND]: {
    bracket: AfterHoursBracket.WKND,
    label: 'Weekend / Statutory Holiday',
    description: 'All day Saturday, Sunday, and Alberta statutory holidays',
    startHour: 0,
    endHour: 24,
  },
});

/** Standard hours boundary: weekday 08:00–17:00 (null bracket) */
export const MOBILE_STANDARD_HOURS_START = 8;
export const MOBILE_STANDARD_HOURS_END = 17;

// --- Mobile Viewport Breakpoints ---

export const MobileBreakpoint = {
  MOBILE: 'MOBILE',
  TABLET: 'TABLET',
  DESKTOP: 'DESKTOP',
} as const;

export type MobileBreakpoint =
  (typeof MobileBreakpoint)[keyof typeof MobileBreakpoint];

interface BreakpointConfig {
  readonly breakpoint: MobileBreakpoint;
  readonly minWidth: number;
  readonly maxWidth: number | null;
}

export const MOBILE_BREAKPOINT_CONFIGS: Readonly<
  Record<MobileBreakpoint, BreakpointConfig>
> = Object.freeze({
  [MobileBreakpoint.MOBILE]: {
    breakpoint: MobileBreakpoint.MOBILE,
    minWidth: 360,
    maxWidth: 428,
  },
  [MobileBreakpoint.TABLET]: {
    breakpoint: MobileBreakpoint.TABLET,
    minWidth: 429,
    maxWidth: 1024,
  },
  [MobileBreakpoint.DESKTOP]: {
    breakpoint: MobileBreakpoint.DESKTOP,
    minWidth: 1025,
    maxWidth: null,
  },
});

// --- Bottom Navigation Tabs ---

export const BottomNavTab = {
  HOME: 'HOME',
  SHIFT: 'SHIFT',
  NEW_CLAIM: 'NEW_CLAIM',
  NOTIFICATIONS: 'NOTIFICATIONS',
} as const;

export type BottomNavTab =
  (typeof BottomNavTab)[keyof typeof BottomNavTab];

// --- Favourites Constraints ---

export const MAX_FAVOURITES = 30;
export const AUTO_SEED_COUNT = 10;

// --- Quick Entry Constraints ---

export const QuickEntryClaimType = {
  AHCIP: 'AHCIP',
} as const;

export type QuickEntryClaimType =
  (typeof QuickEntryClaimType)[keyof typeof QuickEntryClaimType];

/** Quick claims start as DRAFT — no validation on mobile */
export const QUICK_ENTRY_INITIAL_STATE = 'DRAFT' as const;

/** Number of recent patients shown in quick entry patient picker */
export const RECENT_PATIENTS_COUNT = 20;

// --- Common Quick-Toggle Modifiers ---

export const QUICK_TOGGLE_MODIFIERS = Object.freeze([
  'CMGP',
  'AFHR',
  'NGHR',
  'TM',
  'WKND',
] as const);

// --- Performance Targets ---

export const TTI_TARGET_MS = 3000;
export const CODE_AUTOCOMPLETE_MS = 200;
export const PATIENT_SEARCH_MS = 500;
export const CLAIM_SAVE_MS = 1000;
export const MAX_TAPS_SHIFT_LOG = 5;

// --- Mobile Audit Action Identifiers ---

export const MobileAuditAction = {
  SHIFT_STARTED: 'mobile.shift_started',
  SHIFT_ENDED: 'mobile.shift_ended',
  PATIENT_LOGGED: 'mobile.patient_logged',
  QUICK_CLAIM_CREATED: 'mobile.quick_claim_created',
  FAVOURITE_ADDED: 'mobile.favourite_added',
  FAVOURITE_REMOVED: 'mobile.favourite_removed',
  FAVOURITE_REORDERED: 'mobile.favourite_reordered',
  SUMMARY_VIEWED: 'mobile.summary_viewed',
} as const;

export type MobileAuditAction =
  (typeof MobileAuditAction)[keyof typeof MobileAuditAction];

// --- Sync Endpoint (Phase 2 Placeholder) ---

/** Offline queue sync endpoint — returns 501 at MVP */
export const SYNC_ENDPOINT = '/api/v1/sync/claims' as const;
