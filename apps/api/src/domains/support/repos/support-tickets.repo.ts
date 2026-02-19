import { eq, and, desc, sql, lte, isNull, isNotNull } from 'drizzle-orm';
import { type NodePgDatabase } from 'drizzle-orm/node-postgres';
import {
  supportTickets,
  type InsertSupportTicket,
  type SelectSupportTicket,
} from '@meritum/shared/schemas/db/support.schema.js';
import {
  TicketStatus,
  TicketPriority,
  SLA_TARGETS,
  SLA_BUSINESS_HOURS,
  SLA_BUSINESS_DAYS,
} from '@meritum/shared/constants/support.constants.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface TicketListFilters {
  status?: string;
  limit?: number;
  offset?: number;
}

export interface AdminTicketListFilters {
  status?: string;
  priority?: string;
  category?: string;
  assignedTo?: string;
  limit?: number;
  offset?: number;
}

export interface TicketUpdateData {
  status?: string;
  category?: string;
  priority?: string;
  assignedTo?: string;
  resolutionNotes?: string;
  resolvedAt?: Date | null;
}

export interface PaginatedTickets {
  data: SelectSupportTicket[];
  pagination: {
    total: number;
    page: number;
    pageSize: number;
    hasMore: boolean;
  };
}

export interface SlaBreachTicket extends SelectSupportTicket {
  breachType: 'first_response' | 'resolution';
  elapsedBusinessMinutes: number;
  targetMinutes: number;
}

// ---------------------------------------------------------------------------
// Business Hours Calculation
// ---------------------------------------------------------------------------

/**
 * Calculate elapsed business minutes between two dates.
 * Business hours: Mon-Fri 08:00-18:00 MT, Thursday 06:00-22:00 MT.
 */
export function calculateBusinessMinutes(start: Date, end: Date): number {
  if (end <= start) return 0;

  let minutes = 0;
  const cursor = new Date(start);

  while (cursor < end) {
    const dayOfWeek = cursor.getUTCDay(); // 0=Sun, 1=Mon ... 6=Sat
    // Convert to ISO weekday: 1=Mon, 7=Sun
    const isoDay = dayOfWeek === 0 ? 7 : dayOfWeek;

    if ((SLA_BUSINESS_DAYS as readonly number[]).includes(isoDay)) {
      // Thursday = ISO day 4
      const config =
        isoDay === 4 ? SLA_BUSINESS_HOURS.THURSDAY : SLA_BUSINESS_HOURS.DEFAULT;
      const { startHour, endHour } = config;

      const hour = cursor.getUTCHours();
      const minute = cursor.getUTCMinutes();

      if (hour >= startHour && hour < endHour) {
        // Within business hours — count minutes
        const minutesUntilEnd = (endHour - hour) * 60 - minute;
        const minutesUntilTarget = Math.floor(
          (end.getTime() - cursor.getTime()) / 60000,
        );
        const toAdd = Math.min(minutesUntilEnd, minutesUntilTarget);
        if (toAdd <= 0) {
          // Sub-minute remainder — done
          break;
        }
        minutes += toAdd;
        cursor.setTime(cursor.getTime() + toAdd * 60000);
      } else if (hour < startHour) {
        // Before business hours — skip to start
        cursor.setUTCHours(startHour, 0, 0, 0);
      } else {
        // After business hours — skip to next day
        cursor.setUTCDate(cursor.getUTCDate() + 1);
        cursor.setUTCHours(0, 0, 0, 0);
      }
    } else {
      // Weekend — skip to next day
      cursor.setUTCDate(cursor.getUTCDate() + 1);
      cursor.setUTCHours(0, 0, 0, 0);
    }
  }

  return minutes;
}

// ---------------------------------------------------------------------------
// Auto-URGENT Detection
// ---------------------------------------------------------------------------

/**
 * Check if context_metadata indicates a batch failure, which should auto-
 * escalate priority to URGENT.
 */
function isBatchFailure(
  metadata: Record<string, unknown> | null | undefined,
): boolean {
  if (!metadata || typeof metadata !== 'object') return false;

  // Presence of batch_error key
  if ('batch_error' in metadata && metadata.batch_error) return true;

  // batch_id present with error-related keys
  if ('batch_id' in metadata && metadata.batch_id) {
    if ('error_codes' in metadata && Array.isArray(metadata.error_codes) && metadata.error_codes.length > 0) {
      return true;
    }
    if ('error' in metadata && metadata.error) return true;
  }

  return false;
}

// ---------------------------------------------------------------------------
// Support Tickets Repository
// ---------------------------------------------------------------------------

export function createSupportTicketsRepository(db: NodePgDatabase) {
  return {
    // -----------------------------------------------------------------------
    // Physician-facing methods (require providerId)
    // -----------------------------------------------------------------------

    /**
     * Create a new support ticket with status OPEN.
     * Auto-sets priority to URGENT if context_metadata indicates batch failure.
     */
    async create(data: InsertSupportTicket): Promise<SelectSupportTicket> {
      const priority =
        isBatchFailure(data.contextMetadata as Record<string, unknown> | null)
          ? TicketPriority.URGENT
          : data.priority ?? TicketPriority.MEDIUM;

      const rows = await db
        .insert(supportTickets)
        .values({
          ...data,
          status: TicketStatus.OPEN,
          priority,
        })
        .returning();

      return rows[0];
    },

    /**
     * Fetch a ticket by ID, scoped to the authenticated provider.
     * Returns null if ticket doesn't exist or belongs to another provider (404 pattern).
     */
    async getById(
      ticketId: string,
      providerId: string,
    ): Promise<SelectSupportTicket | null> {
      const rows = await db
        .select()
        .from(supportTickets)
        .where(
          and(
            eq(supportTickets.ticketId, ticketId),
            eq(supportTickets.providerId, providerId),
          ),
        )
        .limit(1);

      return rows[0] ?? null;
    },

    /**
     * List tickets for a specific provider with optional status filter.
     * Paginated, ordered by created_at DESC (newest first).
     */
    async listByProvider(
      providerId: string,
      filters?: TicketListFilters,
    ): Promise<PaginatedTickets> {
      const limit = filters?.limit ?? 20;
      const offset = filters?.offset ?? 0;
      const page = Math.floor(offset / limit) + 1;

      const conditions = [eq(supportTickets.providerId, providerId)];
      if (filters?.status) {
        conditions.push(eq(supportTickets.status, filters.status));
      }

      const whereClause = and(...conditions);

      const [countResult, rows] = await Promise.all([
        db
          .select({ count: sql<number>`count(*)::int` })
          .from(supportTickets)
          .where(whereClause),
        db
          .select()
          .from(supportTickets)
          .where(whereClause)
          .orderBy(desc(supportTickets.createdAt))
          .limit(limit)
          .offset(offset),
      ]);

      const total = countResult[0]?.count ?? 0;

      return {
        data: rows,
        pagination: {
          total,
          page,
          pageSize: limit,
          hasMore: offset + rows.length < total,
        },
      };
    },

    /**
     * Add satisfaction rating to a ticket. Only allowed if ticket status
     * is RESOLVED or CLOSED. Returns null if ticket not found or wrong provider.
     */
    async addRating(
      ticketId: string,
      providerId: string,
      rating: number,
      comment?: string,
    ): Promise<SelectSupportTicket | null> {
      // First verify ticket exists, belongs to provider, and is in RESOLVED/CLOSED status
      const existing = await db
        .select()
        .from(supportTickets)
        .where(
          and(
            eq(supportTickets.ticketId, ticketId),
            eq(supportTickets.providerId, providerId),
          ),
        )
        .limit(1);

      if (!existing[0]) return null;

      if (
        existing[0].status !== TicketStatus.RESOLVED &&
        existing[0].status !== TicketStatus.CLOSED
      ) {
        return null;
      }

      const rows = await db
        .update(supportTickets)
        .set({
          satisfactionRating: rating,
          satisfactionComment: comment ?? null,
          updatedAt: new Date(),
        })
        .where(
          and(
            eq(supportTickets.ticketId, ticketId),
            eq(supportTickets.providerId, providerId),
          ),
        )
        .returning();

      return rows[0] ?? null;
    },

    /**
     * Store screenshot file path after upload processing.
     * Returns null if ticket not found or wrong provider.
     */
    async setScreenshotPath(
      ticketId: string,
      providerId: string,
      path: string,
    ): Promise<SelectSupportTicket | null> {
      const rows = await db
        .update(supportTickets)
        .set({
          screenshotPath: path,
          updatedAt: new Date(),
        })
        .where(
          and(
            eq(supportTickets.ticketId, ticketId),
            eq(supportTickets.providerId, providerId),
          ),
        )
        .returning();

      return rows[0] ?? null;
    },

    // -----------------------------------------------------------------------
    // Admin methods (support team — no provider scoping)
    // -----------------------------------------------------------------------

    /**
     * Update ticket fields (status, category, priority, assigned_to, resolution_notes).
     * Sets updated_at. If status transitions to RESOLVED, sets resolved_at.
     */
    async updateTicket(
      ticketId: string,
      data: TicketUpdateData,
    ): Promise<SelectSupportTicket | null> {
      const setClauses: Record<string, unknown> = { updatedAt: new Date() };

      if (data.status !== undefined) setClauses.status = data.status;
      if (data.category !== undefined) setClauses.category = data.category;
      if (data.priority !== undefined) setClauses.priority = data.priority;
      if (data.assignedTo !== undefined) setClauses.assignedTo = data.assignedTo;
      if (data.resolutionNotes !== undefined)
        setClauses.resolutionNotes = data.resolutionNotes;

      // Auto-set resolvedAt when transitioning to RESOLVED
      if (data.status === TicketStatus.RESOLVED) {
        setClauses.resolvedAt = data.resolvedAt ?? new Date();
      }

      const rows = await db
        .update(supportTickets)
        .set(setClauses)
        .where(eq(supportTickets.ticketId, ticketId))
        .returning();

      return rows[0] ?? null;
    },

    /**
     * List all tickets (support team triage queue) with optional filters.
     * No provider scoping — admin access controlled at route level.
     */
    async listAllTickets(
      filters?: AdminTicketListFilters,
    ): Promise<PaginatedTickets> {
      const limit = filters?.limit ?? 20;
      const offset = filters?.offset ?? 0;
      const page = Math.floor(offset / limit) + 1;

      const conditions: ReturnType<typeof eq>[] = [];
      if (filters?.status) {
        conditions.push(eq(supportTickets.status, filters.status));
      }
      if (filters?.priority) {
        conditions.push(eq(supportTickets.priority, filters.priority));
      }
      if (filters?.category) {
        conditions.push(eq(supportTickets.category, filters.category));
      }
      if (filters?.assignedTo) {
        conditions.push(eq(supportTickets.assignedTo, filters.assignedTo));
      }

      const whereClause =
        conditions.length > 0 ? and(...conditions) : undefined;

      const [countResult, rows] = await Promise.all([
        db
          .select({ count: sql<number>`count(*)::int` })
          .from(supportTickets)
          .where(whereClause),
        db
          .select()
          .from(supportTickets)
          .where(whereClause)
          .orderBy(desc(supportTickets.createdAt))
          .limit(limit)
          .offset(offset),
      ]);

      const total = countResult[0]?.count ?? 0;

      return {
        data: rows,
        pagination: {
          total,
          page,
          pageSize: limit,
          hasMore: offset + rows.length < total,
        },
      };
    },

    /**
     * Return tickets that have breached their SLA targets.
     * Compares elapsed business hours against SLA_TARGETS by priority.
     * Checks both first-response (based on status still OPEN) and resolution targets.
     */
    async getSlaBreach(): Promise<SlaBreachTicket[]> {
      // Fetch all non-closed tickets
      const openTickets = await db
        .select()
        .from(supportTickets)
        .where(
          and(
            sql`${supportTickets.status} != ${TicketStatus.CLOSED}`,
            sql`${supportTickets.status} != ${TicketStatus.RESOLVED}`,
          ),
        );

      const now = new Date();
      const breaches: SlaBreachTicket[] = [];

      for (const ticket of openTickets) {
        const priority = ticket.priority as TicketPriority;
        const targets = SLA_TARGETS[priority];
        if (!targets) continue;

        const elapsed = calculateBusinessMinutes(ticket.createdAt, now);

        // First response breach: ticket still OPEN (never responded to)
        if (
          ticket.status === TicketStatus.OPEN &&
          elapsed > targets.firstResponseMinutes
        ) {
          breaches.push({
            ...ticket,
            breachType: 'first_response',
            elapsedBusinessMinutes: elapsed,
            targetMinutes: targets.firstResponseMinutes,
          });
        }

        // Resolution breach: any non-closed/non-resolved ticket past resolution target
        if (elapsed > targets.resolutionMinutes) {
          // Avoid double-counting if already added as first_response breach
          const alreadyAdded = breaches.some(
            (b) =>
              b.ticketId === ticket.ticketId && b.breachType === 'resolution',
          );
          if (!alreadyAdded) {
            breaches.push({
              ...ticket,
              breachType: 'resolution',
              elapsedBusinessMinutes: elapsed,
              targetMinutes: targets.resolutionMinutes,
            });
          }
        }
      }

      return breaches;
    },
  };
}

export type SupportTicketsRepository = ReturnType<
  typeof createSupportTicketsRepository
>;
