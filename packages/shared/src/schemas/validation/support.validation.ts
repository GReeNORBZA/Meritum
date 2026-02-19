// ============================================================================
// Domain 13: Support System — Zod Validation Schemas
// ============================================================================

import { z } from 'zod';
import {
  HelpCategory,
  TicketStatus,
  TicketCategory,
  TicketPriority,
  SATISFACTION_RATING_MIN,
  SATISFACTION_RATING_MAX,
} from '../../constants/support.constants.js';

// --- Enum Value Arrays ---

const HELP_CATEGORIES = [
  HelpCategory.GETTING_STARTED,
  HelpCategory.AHCIP_BILLING,
  HelpCategory.WCB_BILLING,
  HelpCategory.MODIFIERS_AND_RULES,
  HelpCategory.AI_COACH,
  HelpCategory.ACCOUNT_AND_BILLING,
  HelpCategory.TROUBLESHOOTING,
] as const;

const TICKET_STATUSES = [
  TicketStatus.OPEN,
  TicketStatus.IN_PROGRESS,
  TicketStatus.WAITING_ON_CUSTOMER,
  TicketStatus.RESOLVED,
  TicketStatus.CLOSED,
] as const;

const TICKET_CATEGORIES = [
  TicketCategory.BILLING,
  TicketCategory.TECHNICAL,
  TicketCategory.ACCOUNT,
  TicketCategory.FEATURE_REQUEST,
] as const;

const PRIORITIES = [
  TicketPriority.LOW,
  TicketPriority.MEDIUM,
  TicketPriority.HIGH,
  TicketPriority.URGENT,
] as const;

// --- Helpers ---

/** Strip HTML tags from text to prevent stored XSS */
function stripHtmlTags(value: string): string {
  return value.replace(/<[^>]*>/g, '');
}

// ============================================================================
// Help Centre
// ============================================================================

// --- Article List Query ---

export const articleListQuerySchema = z.object({
  category: z.enum(HELP_CATEGORIES).optional(),
  search: z.string().max(200).optional(),
  limit: z.coerce.number().int().min(1).max(50).default(20),
  offset: z.coerce.number().int().min(0).default(0),
});

export type ArticleListQuery = z.infer<typeof articleListQuerySchema>;

// --- Article Slug Param ---

export const articleSlugParamSchema = z.object({
  slug: z
    .string()
    .max(200)
    .regex(
      /^[a-z0-9]+(?:-[a-z0-9]+)*$/,
      'Slug must contain only lowercase alphanumeric characters and hyphens',
    ),
});

export type ArticleSlugParam = z.infer<typeof articleSlugParamSchema>;

// --- Article Feedback ---

export const articleFeedbackSchema = z.object({
  is_helpful: z.boolean(),
});

export type ArticleFeedbackInput = z.infer<typeof articleFeedbackSchema>;

// ============================================================================
// Support Tickets
// ============================================================================

// --- Create Ticket ---

export const createTicketSchema = z.object({
  subject: z.string().min(1).max(200),
  description: z.string().min(1).max(5000).transform(stripHtmlTags),
  context_url: z
    .string()
    .max(500)
    .url()
    .refine((url) => url.startsWith('https://'), {
      message: 'context_url must use HTTPS',
    })
    .optional(),
  context_metadata: z.record(z.unknown()).optional(),
  priority: z.enum(PRIORITIES).default(TicketPriority.MEDIUM),
});

export type CreateTicket = z.infer<typeof createTicketSchema>;

// --- Ticket List Query ---

export const ticketListQuerySchema = z.object({
  status: z.enum(TICKET_STATUSES).optional(),
  limit: z.coerce.number().int().min(1).max(50).default(20),
  offset: z.coerce.number().int().min(0).default(0),
});

export type TicketListQuery = z.infer<typeof ticketListQuerySchema>;

// --- Ticket ID Param ---

export const ticketIdParamSchema = z.object({
  id: z.string().uuid(),
});

export type TicketIdParam = z.infer<typeof ticketIdParamSchema>;

// --- Ticket Rating ---

export const ticketRatingSchema = z.object({
  rating: z.number().int().min(SATISFACTION_RATING_MIN).max(SATISFACTION_RATING_MAX),
  comment: z.string().max(1000).optional(),
});

export type TicketRating = z.infer<typeof ticketRatingSchema>;

// ============================================================================
// Internal/Admin Ticket Updates (support team only)
// ============================================================================

// --- Update Ticket ---

export const updateTicketSchema = z
  .object({
    status: z.enum(TICKET_STATUSES).optional(),
    category: z.enum(TICKET_CATEGORIES).optional(),
    priority: z.enum(PRIORITIES).optional(),
    assigned_to: z.string().max(100).optional(),
    resolution_notes: z.string().max(5000).transform(stripHtmlTags).optional(),
  })
  .refine(
    (data) =>
      data.status !== undefined ||
      data.category !== undefined ||
      data.priority !== undefined ||
      data.assigned_to !== undefined ||
      data.resolution_notes !== undefined,
    { message: 'At least one field must be provided' },
  );

export type UpdateTicket = z.infer<typeof updateTicketSchema>;
