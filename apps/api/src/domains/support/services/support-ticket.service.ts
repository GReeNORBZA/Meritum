// ============================================================================
// Domain 13: Support Ticket Service
// Creation, lifecycle, notifications, SLA, rating.
// ============================================================================

import {
  TicketStatus,
  SupportAuditAction,
} from '@meritum/shared/constants/support.constants.js';
import { BusinessRuleError, ValidationError } from '../../../lib/errors.js';
import type {
  SupportTicketsRepository,
  SlaBreachTicket,
  PaginatedTickets,
  TicketListFilters,
  AdminTicketListFilters,
} from '../repos/support-tickets.repo.js';
import type { SelectSupportTicket } from '@meritum/shared/schemas/db/support.schema.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

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

export interface NotificationService {
  send(event: {
    type: string;
    providerId: string;
    data: Record<string, unknown>;
  }): Promise<void>;
}

export interface FileStorage {
  upload(
    key: string,
    buffer: Buffer,
    contentType: string,
  ): Promise<string>;
}

export interface ScreenshotFile {
  buffer: Buffer;
  mimetype: string;
  size: number;
  originalname: string;
}

export interface CreateTicketData {
  subject: string;
  description: string;
  contextUrl?: string;
  contextMetadata?: Record<string, unknown>;
  priority?: string;
  category?: string;
}

/** Ticket response shape — screenshot_path is always omitted. */
export type TicketResponse = Omit<SelectSupportTicket, 'screenshotPath'>;

// ---------------------------------------------------------------------------
// Valid status transitions
// ---------------------------------------------------------------------------

const VALID_TRANSITIONS: Record<string, string[]> = {
  [TicketStatus.OPEN]: [TicketStatus.IN_PROGRESS],
  [TicketStatus.IN_PROGRESS]: [
    TicketStatus.WAITING_ON_CUSTOMER,
    TicketStatus.RESOLVED,
  ],
  [TicketStatus.WAITING_ON_CUSTOMER]: [
    TicketStatus.IN_PROGRESS,
    TicketStatus.RESOLVED,
  ],
  [TicketStatus.RESOLVED]: [TicketStatus.CLOSED],
  [TicketStatus.CLOSED]: [],
};

// ---------------------------------------------------------------------------
// Screenshot validation
// ---------------------------------------------------------------------------

const ALLOWED_SCREENSHOT_TYPES = new Set([
  'image/png',
  'image/jpeg',
  'image/webp',
]);
const MAX_SCREENSHOT_SIZE = 5 * 1024 * 1024; // 5MB

function validateScreenshot(file: ScreenshotFile): void {
  if (!ALLOWED_SCREENSHOT_TYPES.has(file.mimetype)) {
    throw new ValidationError(
      'Screenshot must be a PNG, JPEG, or WebP image',
    );
  }
  if (file.size > MAX_SCREENSHOT_SIZE) {
    throw new ValidationError('Screenshot must be 5MB or smaller');
  }
}

// ---------------------------------------------------------------------------
// Strip screenshot_path from response
// ---------------------------------------------------------------------------

function stripScreenshotPath(
  ticket: SelectSupportTicket,
): TicketResponse {
  const { screenshotPath: _, ...rest } = ticket;
  return rest;
}

// ---------------------------------------------------------------------------
// Dependencies
// ---------------------------------------------------------------------------

interface SupportTicketDeps {
  ticketsRepo: SupportTicketsRepository;
  auditRepo: AuditRepo;
  notificationService: NotificationService;
  fileStorage: FileStorage;
}

// ---------------------------------------------------------------------------
// Service Factory
// ---------------------------------------------------------------------------

export function createSupportTicketService(deps: SupportTicketDeps) {
  const { ticketsRepo, auditRepo, notificationService, fileStorage } = deps;

  return {
    // -----------------------------------------------------------------------
    // Physician-facing methods
    // -----------------------------------------------------------------------

    /**
     * Create a new support ticket.
     * Auto-detects URGENT priority for batch failures.
     * Handles optional screenshot upload (validated: png/jpg/webp, max 5MB).
     * Sends confirmation email + in-app notification.
     * Audit log: support.ticket_created.
     * Returns created ticket without screenshot_path.
     */
    async createTicket(
      providerId: string,
      data: CreateTicketData,
      screenshotFile?: ScreenshotFile,
    ): Promise<TicketResponse> {
      // Validate screenshot if provided
      if (screenshotFile) {
        validateScreenshot(screenshotFile);
      }

      // Create ticket via repository (handles auto-URGENT logic)
      const ticket = await ticketsRepo.create({
        providerId,
        subject: data.subject,
        description: data.description,
        contextUrl: data.contextUrl ?? null,
        contextMetadata: data.contextMetadata ?? null,
        priority: data.priority,
        category: data.category ?? null,
      });

      // Handle screenshot upload
      if (screenshotFile) {
        const ext = screenshotFile.mimetype.split('/')[1] ?? 'png';
        const key = `support-tickets/${ticket.ticketId}/screenshot.${ext}`;
        await fileStorage.upload(key, screenshotFile.buffer, screenshotFile.mimetype);
        await ticketsRepo.setScreenshotPath(
          ticket.ticketId,
          providerId,
          key,
        );
      }

      // Audit log
      await auditRepo.appendAuditLog({
        userId: providerId,
        action: SupportAuditAction.TICKET_CREATED,
        category: 'support',
        resourceType: 'support_ticket',
        resourceId: ticket.ticketId,
        detail: {
          subject: ticket.subject,
          priority: ticket.priority,
          hasScreenshot: !!screenshotFile,
        },
      });

      // Send confirmation notification (email + in-app)
      await notificationService.send({
        type: 'support.ticket_created',
        providerId,
        data: {
          ticketId: ticket.ticketId,
          subject: ticket.subject,
        },
      });

      return stripScreenshotPath(ticket);
    },

    /**
     * Get a single ticket by ID, scoped to the authenticated provider.
     * Returns null for wrong provider (404 pattern — don't confirm existence).
     * screenshot_path is never returned.
     */
    async getTicket(
      providerId: string,
      ticketId: string,
    ): Promise<TicketResponse | null> {
      const ticket = await ticketsRepo.getById(ticketId, providerId);
      if (!ticket) return null;
      return stripScreenshotPath(ticket);
    },

    /**
     * List tickets for the authenticated provider. Paginated.
     * screenshot_path stripped from all results.
     */
    async listTickets(
      providerId: string,
      filters?: TicketListFilters,
    ): Promise<{ data: TicketResponse[]; pagination: PaginatedTickets['pagination'] }> {
      const result = await ticketsRepo.listByProvider(providerId, filters);
      return {
        data: result.data.map(stripScreenshotPath),
        pagination: result.pagination,
      };
    },

    /**
     * Submit satisfaction rating for a ticket.
     * Only allowed on RESOLVED or CLOSED tickets.
     * Rating must be 1-5.
     * Audit log: support.ticket_rated.
     * Returns updated ticket without screenshot_path.
     */
    async rateTicket(
      providerId: string,
      ticketId: string,
      rating: number,
      comment?: string,
    ): Promise<TicketResponse | null> {
      const updated = await ticketsRepo.addRating(
        ticketId,
        providerId,
        rating,
        comment,
      );

      if (!updated) return null;

      // Audit log
      await auditRepo.appendAuditLog({
        userId: providerId,
        action: SupportAuditAction.TICKET_RATED,
        category: 'support',
        resourceType: 'support_ticket',
        resourceId: ticketId,
        detail: { rating, hasComment: !!comment },
      });

      return stripScreenshotPath(updated);
    },

    // -----------------------------------------------------------------------
    // Admin methods (support team only)
    // -----------------------------------------------------------------------

    /**
     * Update ticket fields (status, category, priority, assigned_to, resolution_notes).
     * Enforces valid status transitions.
     * On status change to RESOLVED: sets resolved_at, sends notification.
     * On any status change: sends notification to physician.
     * Audit log: support.ticket_updated (and support.ticket_resolved if applicable).
     */
    async updateTicket(
      ticketId: string,
      data: {
        status?: string;
        category?: string;
        priority?: string;
        assignedTo?: string;
        resolutionNotes?: string;
      },
      actorId: string,
    ): Promise<TicketResponse | null> {
      // For status transition validation, retrieve the ticket first
      if (data.status) {
        const existing = await this._getTicketAdmin(ticketId);
        if (!existing) return null;

        const currentStatus = existing.status;
        const validNextStatuses = VALID_TRANSITIONS[currentStatus] ?? [];

        if (!validNextStatuses.includes(data.status)) {
          throw new BusinessRuleError(
            `Invalid status transition from ${currentStatus} to ${data.status}`,
          );
        }
      }

      const updated = await ticketsRepo.updateTicket(ticketId, {
        status: data.status,
        category: data.category,
        priority: data.priority,
        assignedTo: data.assignedTo,
        resolutionNotes: data.resolutionNotes,
      });

      if (!updated) return null;

      // Audit log: ticket updated
      await auditRepo.appendAuditLog({
        userId: actorId,
        action: SupportAuditAction.TICKET_UPDATED,
        category: 'support',
        resourceType: 'support_ticket',
        resourceId: ticketId,
        detail: {
          changes: Object.keys(data).filter(
            (k) => data[k as keyof typeof data] !== undefined,
          ),
        },
      });

      // If status changed to RESOLVED, additional audit + notification
      if (data.status === TicketStatus.RESOLVED) {
        await auditRepo.appendAuditLog({
          userId: actorId,
          action: SupportAuditAction.TICKET_RESOLVED,
          category: 'support',
          resourceType: 'support_ticket',
          resourceId: ticketId,
          detail: {
            resolutionNotes: data.resolutionNotes
              ? 'provided'
              : 'none',
          },
        });

        await notificationService.send({
          type: 'support.ticket_resolved',
          providerId: updated.providerId,
          data: {
            ticketId: updated.ticketId,
            subject: updated.subject,
          },
        });
      } else if (data.status) {
        // Other status change — notify physician
        await notificationService.send({
          type: 'support.ticket_status_changed',
          providerId: updated.providerId,
          data: {
            ticketId: updated.ticketId,
            subject: updated.subject,
            newStatus: data.status,
          },
        });
      }

      return stripScreenshotPath(updated);
    },

    /**
     * Close a ticket. Only allowed if current status is RESOLVED.
     * Audit log: support.ticket_closed.
     */
    async closeTicket(
      ticketId: string,
      actorId: string,
    ): Promise<TicketResponse | null> {
      const existing = await this._getTicketAdmin(ticketId);
      if (!existing) return null;

      if (existing.status !== TicketStatus.RESOLVED) {
        throw new BusinessRuleError(
          'Only RESOLVED tickets can be closed',
        );
      }

      const updated = await ticketsRepo.updateTicket(ticketId, {
        status: TicketStatus.CLOSED,
      });

      if (!updated) return null;

      await auditRepo.appendAuditLog({
        userId: actorId,
        action: SupportAuditAction.TICKET_CLOSED,
        category: 'support',
        resourceType: 'support_ticket',
        resourceId: ticketId,
      });

      return stripScreenshotPath(updated);
    },

    /**
     * List all open/in-progress tickets for the support team triage queue.
     * Sorted by priority then created_at.
     */
    async getTriageQueue(
      filters?: AdminTicketListFilters,
    ): Promise<PaginatedTickets> {
      return ticketsRepo.listAllTickets(filters);
    },

    /**
     * Get tickets exceeding their SLA targets.
     */
    async getSlaBreach(): Promise<SlaBreachTicket[]> {
      return ticketsRepo.getSlaBreach();
    },

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /**
     * Fetch a ticket by ID without provider scoping (admin only).
     * Uses the listAllTickets approach to find a specific ticket.
     * @internal
     */
    async _getTicketAdmin(
      ticketId: string,
    ): Promise<SelectSupportTicket | null> {
      // Fetch all tickets and find by ID. In production this would be a direct
      // DB query, but we work with the repository interface available.
      const result = await ticketsRepo.listAllTickets({ limit: 1000 });
      return result.data.find((t) => t.ticketId === ticketId) ?? null;
    },
  };
}

export type SupportTicketService = ReturnType<
  typeof createSupportTicketService
>;
