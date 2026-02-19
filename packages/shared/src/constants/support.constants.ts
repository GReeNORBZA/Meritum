// ============================================================================
// Domain 13: Support System — Constants
// ============================================================================

// --- Ticket Status ---

export const TicketStatus = {
  OPEN: 'OPEN',
  IN_PROGRESS: 'IN_PROGRESS',
  WAITING_ON_CUSTOMER: 'WAITING_ON_CUSTOMER',
  RESOLVED: 'RESOLVED',
  CLOSED: 'CLOSED',
} as const;

export type TicketStatus = (typeof TicketStatus)[keyof typeof TicketStatus];

// --- Ticket Priority ---

export const TicketPriority = {
  LOW: 'LOW',
  MEDIUM: 'MEDIUM',
  HIGH: 'HIGH',
  URGENT: 'URGENT',
} as const;

export type TicketPriority =
  (typeof TicketPriority)[keyof typeof TicketPriority];

export const DEFAULT_TICKET_PRIORITY: TicketPriority = TicketPriority.MEDIUM;

// --- Ticket Category ---

export const TicketCategory = {
  BILLING: 'BILLING',
  TECHNICAL: 'TECHNICAL',
  ACCOUNT: 'ACCOUNT',
  FEATURE_REQUEST: 'FEATURE_REQUEST',
} as const;

export type TicketCategory =
  (typeof TicketCategory)[keyof typeof TicketCategory];

// --- SLA Targets (business hours Mon-Fri 08:00-18:00 MT, Thu 06:00-22:00 MT) ---

interface SlaTarget {
  readonly firstResponseMinutes: number;
  readonly resolutionMinutes: number;
}

export const SLA_TARGETS: Readonly<Record<TicketPriority, SlaTarget>> =
  Object.freeze({
    [TicketPriority.URGENT]: {
      firstResponseMinutes: 120,      // 2 hours
      resolutionMinutes: 240,         // 4 hours
    },
    [TicketPriority.HIGH]: {
      firstResponseMinutes: 240,      // 4 hours
      resolutionMinutes: 600,         // 1 business day (10 hours)
    },
    [TicketPriority.MEDIUM]: {
      firstResponseMinutes: 600,      // 1 business day (10 hours)
      resolutionMinutes: 1800,        // 3 business days (30 hours)
    },
    [TicketPriority.LOW]: {
      firstResponseMinutes: 1200,     // 2 business days (20 hours)
      resolutionMinutes: 3000,        // 5 business days (50 hours)
    },
  });

// --- SLA Business Hours ---

interface BusinessHoursConfig {
  readonly startHour: number;
  readonly endHour: number;
}

export const SLA_BUSINESS_HOURS: Readonly<
  Record<string, BusinessHoursConfig>
> = Object.freeze({
  DEFAULT: { startHour: 8, endHour: 18 },    // Mon-Fri 08:00-18:00 MT
  THURSDAY: { startHour: 6, endHour: 22 },    // Thu 06:00-22:00 MT
});

export const SLA_BUSINESS_DAYS = Object.freeze([1, 2, 3, 4, 5] as const); // Mon-Fri (ISO weekday)

// --- Help Centre Article Categories ---

export const HelpCategory = {
  GETTING_STARTED: 'GETTING_STARTED',
  AHCIP_BILLING: 'AHCIP_BILLING',
  WCB_BILLING: 'WCB_BILLING',
  MODIFIERS_AND_RULES: 'MODIFIERS_AND_RULES',
  AI_COACH: 'AI_COACH',
  ACCOUNT_AND_BILLING: 'ACCOUNT_AND_BILLING',
  TROUBLESHOOTING: 'TROUBLESHOOTING',
} as const;

export type HelpCategory = (typeof HelpCategory)[keyof typeof HelpCategory];

// --- Article Feedback ---

export const ArticleFeedback = {
  HELPFUL: 'HELPFUL',
  NOT_HELPFUL: 'NOT_HELPFUL',
} as const;

export type ArticleFeedback =
  (typeof ArticleFeedback)[keyof typeof ArticleFeedback];

// --- Satisfaction Rating ---

export const SATISFACTION_RATING_MIN = 1;
export const SATISFACTION_RATING_MAX = 5;

// --- Context-Aware Help Mapping (page URL pattern -> help category) ---

interface ContextHelpMapping {
  readonly pattern: string;
  readonly category: HelpCategory | null;
  readonly description: string;
}

export const CONTEXT_HELP_MAPPINGS: readonly ContextHelpMapping[] =
  Object.freeze([
    {
      pattern: '/claims/new',
      category: HelpCategory.AHCIP_BILLING,
      description: 'New claim creation',
    },
    {
      pattern: '/claims/*/edit',
      category: HelpCategory.AHCIP_BILLING,
      description: 'Claim editing',
    },
    {
      pattern: '/claims/*/rejected',
      category: null, // Search by rejection code from context_metadata
      description: 'Rejected claim — search by rejection code',
    },
    {
      pattern: '/wcb/*',
      category: HelpCategory.WCB_BILLING,
      description: 'WCB billing pages',
    },
    {
      pattern: '/settings/*',
      category: HelpCategory.ACCOUNT_AND_BILLING,
      description: 'Account settings',
    },
    {
      pattern: '/analytics/*',
      category: HelpCategory.GETTING_STARTED,
      description: 'Analytics help',
    },
    {
      pattern: '/onboarding/*',
      category: HelpCategory.GETTING_STARTED,
      description: 'Onboarding help',
    },
  ] as const);

// --- Support Audit Actions ---

export const SupportAuditAction = {
  TICKET_CREATED: 'support.ticket_created',
  TICKET_UPDATED: 'support.ticket_updated',
  TICKET_RESOLVED: 'support.ticket_resolved',
  TICKET_CLOSED: 'support.ticket_closed',
  TICKET_RATED: 'support.ticket_rated',
  ARTICLE_VIEWED: 'support.article_viewed',
  ARTICLE_FEEDBACK: 'support.article_feedback',
  HELP_SEARCHED: 'support.help_searched',
} as const;

export type SupportAuditAction =
  (typeof SupportAuditAction)[keyof typeof SupportAuditAction];

// --- Phase 1.5 AI Chat Constants (placeholders) ---

export const AI_CHAT_CONFIDENCE_THRESHOLD = 0.70;
export const AI_CHAT_ENABLED = false;
