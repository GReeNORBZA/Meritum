import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  createSupportTicketsRepository,
  calculateBusinessMinutes,
} from './support-tickets.repo.js';
import {
  TicketStatus,
  TicketPriority,
  SLA_TARGETS,
} from '@meritum/shared/constants/support.constants.js';

// ---------------------------------------------------------------------------
// In-memory store
// ---------------------------------------------------------------------------

let ticketsStore: Record<string, any>[];

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const PROVIDER_A = crypto.randomUUID();
const PROVIDER_B = crypto.randomUUID();

// ---------------------------------------------------------------------------
// Column name → camelCase mapping
// ---------------------------------------------------------------------------

const COL_MAP: Record<string, string> = {
  ticket_id: 'ticketId',
  provider_id: 'providerId',
  subject: 'subject',
  description: 'description',
  context_url: 'contextUrl',
  context_metadata: 'contextMetadata',
  category: 'category',
  priority: 'priority',
  status: 'status',
  assigned_to: 'assignedTo',
  resolution_notes: 'resolutionNotes',
  resolved_at: 'resolvedAt',
  satisfaction_rating: 'satisfactionRating',
  satisfaction_comment: 'satisfactionComment',
  screenshot_path: 'screenshotPath',
  created_at: 'createdAt',
  updated_at: 'updatedAt',
};

function toStoreKey(col: any): string {
  const name = col && col.name ? col.name : '';
  return COL_MAP[name] || name;
}

// ---------------------------------------------------------------------------
// Mock Drizzle DB
// ---------------------------------------------------------------------------

function makeMockDb(): any {
  function chainable(ctx: {
    op: string;
    table?: string;
    selectFields?: Record<string, any> | null;
    values?: any;
    setClauses?: any;
    whereClauses: Array<(row: any) => boolean>;
    shouldReturn?: boolean;
    orderFn?: ((a: any, b: any) => number) | null;
    limitVal?: number;
    offsetVal?: number;
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
      from(table: any) {
        ctx.table = 'support_tickets';
        return chain;
      },
      where(clause: any) {
        if (clause === undefined || clause === null) {
          // no-op for undefined where clause
          return chain;
        }
        if (typeof clause === 'function') {
          ctx.whereClauses.push(clause);
        } else if (clause && typeof clause === 'object' && clause.__predicate) {
          ctx.whereClauses.push(clause.__predicate);
        }
        return chain;
      },
      orderBy(...args: any[]) {
        if (args.length > 0 && args[0] && typeof args[0] === 'object' && args[0].__orderFn) {
          ctx.orderFn = args[0].__orderFn;
        }
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
    const store = ticketsStore;

    switch (ctx.op) {
      case 'select': {
        let results = store.filter((row) => matchesWhere(row, ctx.whereClauses));

        if (ctx.orderFn) {
          results = [...results].sort(ctx.orderFn);
        }
        if (ctx.offsetVal) {
          results = results.slice(ctx.offsetVal);
        }
        if (ctx.limitVal !== undefined) {
          results = results.slice(0, ctx.limitVal);
        }

        // Handle count(*) projection
        if (ctx.selectFields) {
          if (ctx.selectFields.count && ctx.selectFields.count.__countFn) {
            // Need to apply where to full store for count
            const fullResults = store.filter((row) =>
              matchesWhere(row, ctx.whereClauses),
            );
            return [{ count: fullResults.length }];
          }
          // Other projections
          results = results.map((row) => {
            const projected: Record<string, any> = {};
            for (const [alias, colRef] of Object.entries(ctx.selectFields!)) {
              if (colRef && typeof colRef === 'object' && (colRef as any).__countFn) {
                // Already handled above
                projected[alias] = store.filter((r) => matchesWhere(r, ctx.whereClauses)).length;
              } else {
                const key = toStoreKey(colRef);
                projected[alias] = row[key] ?? row[alias];
              }
            }
            return projected;
          });
        }

        return results;
      }

      case 'insert': {
        const inserted: any[] = [];
        for (const entry of ctx.values) {
          const newRow: Record<string, any> = { ...entry };
          if (!newRow.ticketId) newRow.ticketId = crypto.randomUUID();
          if (!newRow.createdAt) newRow.createdAt = new Date();
          if (!newRow.updatedAt) newRow.updatedAt = new Date();
          if (!newRow.status) newRow.status = TicketStatus.OPEN;
          if (!newRow.priority) newRow.priority = TicketPriority.MEDIUM;
          store.push(newRow);
          inserted.push({ ...newRow });
        }
        return ctx.shouldReturn ? inserted : [];
      }

      case 'update': {
        const updated: any[] = [];
        for (const row of store) {
          if (matchesWhere(row, ctx.whereClauses)) {
            for (const [key, val] of Object.entries(ctx.setClauses || {})) {
              row[key] = val;
            }
            updated.push({ ...row });
          }
        }
        return ctx.shouldReturn ? updated : [];
      }

      default:
        return [];
    }
  }

  const db: any = {
    select(fields?: Record<string, any>) {
      return chainable({
        op: 'select',
        table: 'support_tickets',
        selectFields: fields || null,
        whereClauses: [],
      });
    },
    insert(table: any) {
      return chainable({ op: 'insert', table: 'support_tickets', whereClauses: [] });
    },
    update(table: any) {
      return chainable({ op: 'update', table: 'support_tickets', whereClauses: [] });
    },
  };

  return db;
}

// ---------------------------------------------------------------------------
// Mock drizzle-orm operators
// ---------------------------------------------------------------------------

vi.mock('drizzle-orm', async () => {
  const actual = await vi.importActual<typeof import('drizzle-orm')>('drizzle-orm');
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
    desc(col: any) {
      const key = toStoreKey(col);
      return {
        __orderFn: (a: any, b: any) => {
          const av = a[key];
          const bv = b[key];
          if (av instanceof Date && bv instanceof Date) {
            return bv.getTime() - av.getTime();
          }
          return av < bv ? 1 : av > bv ? -1 : 0;
        },
      };
    },
    lte(col: any, val: any) {
      const key = toStoreKey(col);
      return {
        __predicate: (row: any) => row[key] <= val,
      };
    },
    isNull(col: any) {
      const key = toStoreKey(col);
      return {
        __predicate: (row: any) => row[key] === null || row[key] === undefined,
      };
    },
    isNotNull(col: any) {
      const key = toStoreKey(col);
      return {
        __predicate: (row: any) => row[key] !== null && row[key] !== undefined,
      };
    },
    sql(strings: TemplateStringsArray, ...values: any[]) {
      const fullStr = strings.join('?');

      // count(*)::int pattern
      if (fullStr.includes('count(*)')) {
        return { __countFn: true };
      }

      // != comparison: status != 'CLOSED'
      if (fullStr.includes('!=')) {
        const col = values[0];
        const val = values[1];
        const key = toStoreKey(col);
        return {
          __predicate: (row: any) => row[key] !== val,
        };
      }

      return {};
    },
  };
});

// ---------------------------------------------------------------------------
// Seed helpers
// ---------------------------------------------------------------------------

function seedTicket(overrides: Partial<Record<string, any>> = {}): Record<string, any> {
  const ticket: Record<string, any> = {
    ticketId: overrides.ticketId ?? crypto.randomUUID(),
    providerId: overrides.providerId ?? PROVIDER_A,
    subject: overrides.subject ?? 'Test ticket',
    description: overrides.description ?? 'Test ticket description',
    contextUrl: overrides.contextUrl ?? null,
    contextMetadata: overrides.contextMetadata ?? null,
    category: overrides.category ?? null,
    priority: overrides.priority ?? TicketPriority.MEDIUM,
    status: overrides.status ?? TicketStatus.OPEN,
    assignedTo: overrides.assignedTo ?? null,
    resolutionNotes: overrides.resolutionNotes ?? null,
    resolvedAt: overrides.resolvedAt ?? null,
    satisfactionRating: overrides.satisfactionRating ?? null,
    satisfactionComment: overrides.satisfactionComment ?? null,
    screenshotPath: overrides.screenshotPath ?? null,
    createdAt: overrides.createdAt ?? new Date(),
    updatedAt: overrides.updatedAt ?? new Date(),
  };
  ticketsStore.push(ticket);
  return ticket;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('SupportTicketsRepository', () => {
  let repo: ReturnType<typeof createSupportTicketsRepository>;

  beforeEach(() => {
    ticketsStore = [];
    repo = createSupportTicketsRepository(makeMockDb());
  });

  // =========================================================================
  // create
  // =========================================================================

  describe('create', () => {
    it('creates a ticket with OPEN status', async () => {
      const result = await repo.create({
        providerId: PROVIDER_A,
        subject: 'Help with claim',
        description: 'My claim was rejected',
      });

      expect(result).toBeDefined();
      expect(result.status).toBe(TicketStatus.OPEN);
      expect(result.providerId).toBe(PROVIDER_A);
      expect(result.subject).toBe('Help with claim');
    });

    it('sets default priority to MEDIUM when no priority given', async () => {
      const result = await repo.create({
        providerId: PROVIDER_A,
        subject: 'General question',
        description: 'How do I use this?',
      });

      expect(result.priority).toBe(TicketPriority.MEDIUM);
    });

    it('auto-sets priority to URGENT when context_metadata contains batch_error', async () => {
      const result = await repo.create({
        providerId: PROVIDER_A,
        subject: 'Batch failed',
        description: 'My batch submission failed',
        contextMetadata: {
          batch_error: true,
          batch_id: 'batch-123',
        },
      });

      expect(result.priority).toBe(TicketPriority.URGENT);
    });

    it('auto-sets priority to URGENT when batch_id has error_codes', async () => {
      const result = await repo.create({
        providerId: PROVIDER_A,
        subject: 'Batch errors',
        description: 'Errors in batch',
        contextMetadata: {
          batch_id: 'batch-456',
          error_codes: ['E01', 'E02'],
        },
      });

      expect(result.priority).toBe(TicketPriority.URGENT);
    });

    it('auto-sets priority to URGENT when batch_id has error flag', async () => {
      const result = await repo.create({
        providerId: PROVIDER_A,
        subject: 'Batch error',
        description: 'Error in batch',
        contextMetadata: {
          batch_id: 'batch-789',
          error: 'Submission timeout',
        },
      });

      expect(result.priority).toBe(TicketPriority.URGENT);
    });

    it('respects explicit priority when no batch failure indicators', async () => {
      const result = await repo.create({
        providerId: PROVIDER_A,
        subject: 'Low priority request',
        description: 'Feature request',
        priority: TicketPriority.LOW,
      });

      expect(result.priority).toBe(TicketPriority.LOW);
    });

    it('overrides explicit priority to URGENT for batch failures', async () => {
      const result = await repo.create({
        providerId: PROVIDER_A,
        subject: 'Batch issue',
        description: 'Batch problem',
        priority: TicketPriority.LOW,
        contextMetadata: {
          batch_error: true,
        },
      });

      expect(result.priority).toBe(TicketPriority.URGENT);
    });

    it('does not auto-URGENT when batch_id present without errors', async () => {
      const result = await repo.create({
        providerId: PROVIDER_A,
        subject: 'Batch question',
        description: 'Question about batch',
        contextMetadata: {
          batch_id: 'batch-000',
        },
      });

      expect(result.priority).toBe(TicketPriority.MEDIUM);
    });

    it('does not auto-URGENT when context_metadata is null', async () => {
      const result = await repo.create({
        providerId: PROVIDER_A,
        subject: 'General question',
        description: 'A question',
        contextMetadata: null,
      });

      expect(result.priority).toBe(TicketPriority.MEDIUM);
    });
  });

  // =========================================================================
  // getById
  // =========================================================================

  describe('getById', () => {
    it('returns ticket when owned by the specified provider', async () => {
      const ticket = seedTicket({
        providerId: PROVIDER_A,
        subject: 'My ticket',
      });

      const result = await repo.getById(ticket.ticketId, PROVIDER_A);

      expect(result).not.toBeNull();
      expect(result!.ticketId).toBe(ticket.ticketId);
      expect(result!.subject).toBe('My ticket');
    });

    it('returns null when ticket belongs to a different provider (404 pattern)', async () => {
      const ticket = seedTicket({
        providerId: PROVIDER_B,
        subject: 'Other provider ticket',
      });

      const result = await repo.getById(ticket.ticketId, PROVIDER_A);

      expect(result).toBeNull();
    });

    it('returns null for non-existent ticket ID', async () => {
      const result = await repo.getById(crypto.randomUUID(), PROVIDER_A);

      expect(result).toBeNull();
    });
  });

  // =========================================================================
  // listByProvider
  // =========================================================================

  describe('listByProvider', () => {
    it('returns only tickets belonging to the specified provider', async () => {
      seedTicket({ providerId: PROVIDER_A, subject: 'Ticket A1' });
      seedTicket({ providerId: PROVIDER_A, subject: 'Ticket A2' });
      seedTicket({ providerId: PROVIDER_B, subject: 'Ticket B1' });

      const result = await repo.listByProvider(PROVIDER_A);

      expect(result.data.length).toBe(2);
      result.data.forEach((t) => {
        expect(t.providerId).toBe(PROVIDER_A);
      });
    });

    it('filters by status when provided', async () => {
      seedTicket({ providerId: PROVIDER_A, status: TicketStatus.OPEN });
      seedTicket({ providerId: PROVIDER_A, status: TicketStatus.RESOLVED });
      seedTicket({ providerId: PROVIDER_A, status: TicketStatus.OPEN });

      const result = await repo.listByProvider(PROVIDER_A, {
        status: TicketStatus.OPEN,
      });

      expect(result.data.length).toBe(2);
      result.data.forEach((t) => {
        expect(t.status).toBe(TicketStatus.OPEN);
      });
    });

    it('returns paginated results with correct pagination metadata', async () => {
      for (let i = 0; i < 5; i++) {
        seedTicket({ providerId: PROVIDER_A, subject: `Ticket ${i}` });
      }

      const result = await repo.listByProvider(PROVIDER_A, {
        limit: 2,
        offset: 0,
      });

      expect(result.data.length).toBe(2);
      expect(result.pagination.total).toBe(5);
      expect(result.pagination.pageSize).toBe(2);
      expect(result.pagination.hasMore).toBe(true);
    });

    it('returns empty data with zero total when no tickets match', async () => {
      seedTicket({ providerId: PROVIDER_B });

      const result = await repo.listByProvider(PROVIDER_A);

      expect(result.data.length).toBe(0);
      expect(result.pagination.total).toBe(0);
      expect(result.pagination.hasMore).toBe(false);
    });

    it('orders by created_at descending (newest first)', async () => {
      const now = new Date();
      seedTicket({
        providerId: PROVIDER_A,
        subject: 'Older',
        createdAt: new Date(now.getTime() - 10000),
      });
      seedTicket({
        providerId: PROVIDER_A,
        subject: 'Newer',
        createdAt: new Date(now.getTime()),
      });

      const result = await repo.listByProvider(PROVIDER_A);

      expect(result.data[0].subject).toBe('Newer');
      expect(result.data[1].subject).toBe('Older');
    });
  });

  // =========================================================================
  // addRating
  // =========================================================================

  describe('addRating', () => {
    it('sets satisfaction rating on RESOLVED ticket', async () => {
      const ticket = seedTicket({
        providerId: PROVIDER_A,
        status: TicketStatus.RESOLVED,
      });

      const result = await repo.addRating(ticket.ticketId, PROVIDER_A, 5, 'Great help!');

      expect(result).not.toBeNull();
      expect(result!.satisfactionRating).toBe(5);
      expect(result!.satisfactionComment).toBe('Great help!');
    });

    it('sets satisfaction rating on CLOSED ticket', async () => {
      const ticket = seedTicket({
        providerId: PROVIDER_A,
        status: TicketStatus.CLOSED,
      });

      const result = await repo.addRating(ticket.ticketId, PROVIDER_A, 3);

      expect(result).not.toBeNull();
      expect(result!.satisfactionRating).toBe(3);
      expect(result!.satisfactionComment).toBeNull();
    });

    it('returns null when ticket is OPEN (not resolved)', async () => {
      const ticket = seedTicket({
        providerId: PROVIDER_A,
        status: TicketStatus.OPEN,
      });

      const result = await repo.addRating(ticket.ticketId, PROVIDER_A, 5);

      expect(result).toBeNull();
    });

    it('returns null when ticket is IN_PROGRESS (not resolved)', async () => {
      const ticket = seedTicket({
        providerId: PROVIDER_A,
        status: TicketStatus.IN_PROGRESS,
      });

      const result = await repo.addRating(ticket.ticketId, PROVIDER_A, 4);

      expect(result).toBeNull();
    });

    it('returns null when ticket is WAITING_ON_CUSTOMER (not resolved)', async () => {
      const ticket = seedTicket({
        providerId: PROVIDER_A,
        status: TicketStatus.WAITING_ON_CUSTOMER,
      });

      const result = await repo.addRating(ticket.ticketId, PROVIDER_A, 4);

      expect(result).toBeNull();
    });

    it('returns null when ticket belongs to a different provider', async () => {
      const ticket = seedTicket({
        providerId: PROVIDER_B,
        status: TicketStatus.RESOLVED,
      });

      const result = await repo.addRating(ticket.ticketId, PROVIDER_A, 5);

      expect(result).toBeNull();
    });

    it('returns null for non-existent ticket', async () => {
      const result = await repo.addRating(crypto.randomUUID(), PROVIDER_A, 5);

      expect(result).toBeNull();
    });
  });

  // =========================================================================
  // setScreenshotPath
  // =========================================================================

  describe('setScreenshotPath', () => {
    it('stores screenshot path for own ticket', async () => {
      const ticket = seedTicket({ providerId: PROVIDER_A });

      const result = await repo.setScreenshotPath(
        ticket.ticketId,
        PROVIDER_A,
        '/uploads/screenshots/abc.png',
      );

      expect(result).not.toBeNull();
      expect(result!.screenshotPath).toBe('/uploads/screenshots/abc.png');
    });

    it('returns null when ticket belongs to a different provider', async () => {
      const ticket = seedTicket({ providerId: PROVIDER_B });

      const result = await repo.setScreenshotPath(
        ticket.ticketId,
        PROVIDER_A,
        '/uploads/screenshots/abc.png',
      );

      expect(result).toBeNull();
    });

    it('returns null for non-existent ticket', async () => {
      const result = await repo.setScreenshotPath(
        crypto.randomUUID(),
        PROVIDER_A,
        '/uploads/screenshots/abc.png',
      );

      expect(result).toBeNull();
    });
  });

  // =========================================================================
  // updateTicket (admin)
  // =========================================================================

  describe('updateTicket (admin)', () => {
    it('updates ticket status', async () => {
      const ticket = seedTicket({
        providerId: PROVIDER_A,
        status: TicketStatus.OPEN,
      });

      const result = await repo.updateTicket(ticket.ticketId, {
        status: TicketStatus.IN_PROGRESS,
      });

      expect(result).not.toBeNull();
      expect(result!.status).toBe(TicketStatus.IN_PROGRESS);
    });

    it('updates multiple fields at once', async () => {
      const ticket = seedTicket({ providerId: PROVIDER_A });

      const result = await repo.updateTicket(ticket.ticketId, {
        status: TicketStatus.IN_PROGRESS,
        category: 'TECHNICAL',
        priority: TicketPriority.HIGH,
        assignedTo: 'agent@meritum.ca',
      });

      expect(result).not.toBeNull();
      expect(result!.status).toBe(TicketStatus.IN_PROGRESS);
      expect(result!.category).toBe('TECHNICAL');
      expect(result!.priority).toBe(TicketPriority.HIGH);
      expect(result!.assignedTo).toBe('agent@meritum.ca');
    });

    it('sets resolvedAt when status transitions to RESOLVED', async () => {
      const ticket = seedTicket({
        providerId: PROVIDER_A,
        status: TicketStatus.IN_PROGRESS,
      });

      const result = await repo.updateTicket(ticket.ticketId, {
        status: TicketStatus.RESOLVED,
        resolutionNotes: 'Fixed the issue',
      });

      expect(result).not.toBeNull();
      expect(result!.status).toBe(TicketStatus.RESOLVED);
      expect(result!.resolvedAt).toBeInstanceOf(Date);
      expect(result!.resolutionNotes).toBe('Fixed the issue');
    });

    it('sets updatedAt on every update', async () => {
      const oldDate = new Date('2025-01-01');
      const ticket = seedTicket({
        providerId: PROVIDER_A,
        updatedAt: oldDate,
      });

      const result = await repo.updateTicket(ticket.ticketId, {
        priority: TicketPriority.HIGH,
      });

      expect(result).not.toBeNull();
      expect(result!.updatedAt.getTime()).toBeGreaterThan(oldDate.getTime());
    });

    it('returns null for non-existent ticket', async () => {
      const result = await repo.updateTicket(crypto.randomUUID(), {
        status: TicketStatus.IN_PROGRESS,
      });

      expect(result).toBeNull();
    });

    it('does not require provider scoping (admin method)', async () => {
      // Admin can update any ticket regardless of provider
      const ticket = seedTicket({
        providerId: PROVIDER_B,
        status: TicketStatus.OPEN,
      });

      const result = await repo.updateTicket(ticket.ticketId, {
        assignedTo: 'admin@meritum.ca',
      });

      expect(result).not.toBeNull();
      expect(result!.assignedTo).toBe('admin@meritum.ca');
    });
  });

  // =========================================================================
  // listAllTickets (admin)
  // =========================================================================

  describe('listAllTickets (admin)', () => {
    it('returns all tickets regardless of provider', async () => {
      seedTicket({ providerId: PROVIDER_A });
      seedTicket({ providerId: PROVIDER_B });

      const result = await repo.listAllTickets();

      expect(result.data.length).toBe(2);
    });

    it('filters by status', async () => {
      seedTicket({ status: TicketStatus.OPEN });
      seedTicket({ status: TicketStatus.IN_PROGRESS });
      seedTicket({ status: TicketStatus.OPEN });

      const result = await repo.listAllTickets({ status: TicketStatus.OPEN });

      expect(result.data.length).toBe(2);
      result.data.forEach((t) => {
        expect(t.status).toBe(TicketStatus.OPEN);
      });
    });

    it('filters by priority', async () => {
      seedTicket({ priority: TicketPriority.URGENT });
      seedTicket({ priority: TicketPriority.LOW });
      seedTicket({ priority: TicketPriority.URGENT });

      const result = await repo.listAllTickets({ priority: TicketPriority.URGENT });

      expect(result.data.length).toBe(2);
      result.data.forEach((t) => {
        expect(t.priority).toBe(TicketPriority.URGENT);
      });
    });

    it('filters by category', async () => {
      seedTicket({ category: 'BILLING' });
      seedTicket({ category: 'TECHNICAL' });

      const result = await repo.listAllTickets({ category: 'BILLING' });

      expect(result.data.length).toBe(1);
      expect(result.data[0].category).toBe('BILLING');
    });

    it('filters by assignedTo', async () => {
      seedTicket({ assignedTo: 'agent1@meritum.ca' });
      seedTicket({ assignedTo: 'agent2@meritum.ca' });
      seedTicket({ assignedTo: 'agent1@meritum.ca' });

      const result = await repo.listAllTickets({
        assignedTo: 'agent1@meritum.ca',
      });

      expect(result.data.length).toBe(2);
    });

    it('returns paginated results', async () => {
      for (let i = 0; i < 5; i++) {
        seedTicket({ subject: `Ticket ${i}` });
      }

      const result = await repo.listAllTickets({ limit: 2, offset: 0 });

      expect(result.data.length).toBe(2);
      expect(result.pagination.total).toBe(5);
      expect(result.pagination.hasMore).toBe(true);
    });

    it('returns empty result when no tickets exist', async () => {
      const result = await repo.listAllTickets();

      expect(result.data.length).toBe(0);
      expect(result.pagination.total).toBe(0);
    });
  });

  // =========================================================================
  // getSlaBreach
  // =========================================================================

  describe('getSlaBreach', () => {
    it('detects first_response breach for OPEN tickets past SLA', async () => {
      // MEDIUM priority first response = 600 minutes (10 hours)
      // Seed a ticket created 15 business hours ago (well past 10h target)
      const pastDate = new Date();
      // Go back enough real time. For simplicity we set created_at far in the past
      // on a weekday. The calculateBusinessMinutes function will determine breach.
      pastDate.setDate(pastDate.getDate() - 5); // 5 days ago (will have ~50h business)
      seedTicket({
        providerId: PROVIDER_A,
        status: TicketStatus.OPEN,
        priority: TicketPriority.MEDIUM,
        createdAt: pastDate,
      });

      const breaches = await repo.getSlaBreach();

      expect(breaches.length).toBeGreaterThan(0);
      const firstResponseBreach = breaches.find(
        (b) => b.breachType === 'first_response',
      );
      expect(firstResponseBreach).toBeDefined();
      expect(firstResponseBreach!.targetMinutes).toBe(
        SLA_TARGETS.MEDIUM.firstResponseMinutes,
      );
    });

    it('detects resolution breach for non-resolved tickets past SLA', async () => {
      // URGENT resolution = 240 minutes (4 hours)
      const pastDate = new Date();
      pastDate.setDate(pastDate.getDate() - 3);
      seedTicket({
        providerId: PROVIDER_A,
        status: TicketStatus.IN_PROGRESS,
        priority: TicketPriority.URGENT,
        createdAt: pastDate,
      });

      const breaches = await repo.getSlaBreach();

      const resolutionBreach = breaches.find(
        (b) => b.breachType === 'resolution',
      );
      expect(resolutionBreach).toBeDefined();
      expect(resolutionBreach!.targetMinutes).toBe(
        SLA_TARGETS.URGENT.resolutionMinutes,
      );
    });

    it('excludes RESOLVED tickets from breach detection', async () => {
      const pastDate = new Date();
      pastDate.setDate(pastDate.getDate() - 10);
      seedTicket({
        providerId: PROVIDER_A,
        status: TicketStatus.RESOLVED,
        priority: TicketPriority.URGENT,
        createdAt: pastDate,
      });

      const breaches = await repo.getSlaBreach();

      expect(breaches.length).toBe(0);
    });

    it('excludes CLOSED tickets from breach detection', async () => {
      const pastDate = new Date();
      pastDate.setDate(pastDate.getDate() - 10);
      seedTicket({
        providerId: PROVIDER_A,
        status: TicketStatus.CLOSED,
        priority: TicketPriority.URGENT,
        createdAt: pastDate,
      });

      const breaches = await repo.getSlaBreach();

      expect(breaches.length).toBe(0);
    });

    it('does not report breach for recently created tickets', async () => {
      // Ticket just created — should not be breached
      seedTicket({
        providerId: PROVIDER_A,
        status: TicketStatus.OPEN,
        priority: TicketPriority.LOW,
        createdAt: new Date(),
      });

      const breaches = await repo.getSlaBreach();

      expect(breaches.length).toBe(0);
    });
  });

  // =========================================================================
  // calculateBusinessMinutes (unit)
  // =========================================================================

  describe('calculateBusinessMinutes', () => {
    it('returns 0 when end is before start', () => {
      const start = new Date('2026-02-18T12:00:00Z'); // Wednesday
      const end = new Date('2026-02-18T10:00:00Z');

      const minutes = calculateBusinessMinutes(start, end);

      expect(minutes).toBe(0);
    });

    it('returns 0 when start equals end', () => {
      const date = new Date('2026-02-18T12:00:00Z');

      const minutes = calculateBusinessMinutes(date, date);

      expect(minutes).toBe(0);
    });

    it('counts minutes within a single business day', () => {
      // Wednesday 10:00 to 12:00 UTC = 2 hours = 120 minutes
      const start = new Date('2026-02-18T10:00:00Z');
      const end = new Date('2026-02-18T12:00:00Z');

      const minutes = calculateBusinessMinutes(start, end);

      expect(minutes).toBe(120);
    });

    it('does not count weekend hours', () => {
      // Saturday 10:00 to Sunday 14:00 — no business hours
      const start = new Date('2026-02-21T10:00:00Z'); // Saturday
      const end = new Date('2026-02-22T14:00:00Z'); // Sunday

      const minutes = calculateBusinessMinutes(start, end);

      expect(minutes).toBe(0);
    });

    it('does not count hours outside business window', () => {
      // Wednesday 20:00 to Wednesday 22:00 UTC (after 18:00 close)
      const start = new Date('2026-02-18T20:00:00Z');
      const end = new Date('2026-02-18T22:00:00Z');

      const minutes = calculateBusinessMinutes(start, end);

      expect(minutes).toBe(0);
    });

    it('uses extended Thursday hours (06:00-22:00)', () => {
      // Thursday 06:00 to 08:00 UTC — 2 hours in extended window
      const start = new Date('2026-02-19T06:00:00Z'); // Thursday
      const end = new Date('2026-02-19T08:00:00Z');

      const minutes = calculateBusinessMinutes(start, end);

      expect(minutes).toBe(120);
    });
  });

  // =========================================================================
  // Provider isolation across methods
  // =========================================================================

  describe('provider isolation', () => {
    it('listByProvider never returns other providers tickets', async () => {
      seedTicket({ providerId: PROVIDER_A, subject: 'Provider A ticket' });
      seedTicket({ providerId: PROVIDER_B, subject: 'Provider B ticket' });

      const resultA = await repo.listByProvider(PROVIDER_A);
      const resultB = await repo.listByProvider(PROVIDER_B);

      expect(resultA.data.length).toBe(1);
      expect(resultA.data[0].subject).toBe('Provider A ticket');
      expect(resultB.data.length).toBe(1);
      expect(resultB.data[0].subject).toBe('Provider B ticket');
    });

    it('getById enforces provider scoping', async () => {
      const ticketA = seedTicket({ providerId: PROVIDER_A });
      const ticketB = seedTicket({ providerId: PROVIDER_B });

      // A cannot see B's ticket
      expect(await repo.getById(ticketB.ticketId, PROVIDER_A)).toBeNull();
      // B cannot see A's ticket
      expect(await repo.getById(ticketA.ticketId, PROVIDER_B)).toBeNull();
      // Each can see their own
      expect(await repo.getById(ticketA.ticketId, PROVIDER_A)).not.toBeNull();
      expect(await repo.getById(ticketB.ticketId, PROVIDER_B)).not.toBeNull();
    });

    it('addRating enforces provider scoping', async () => {
      const ticket = seedTicket({
        providerId: PROVIDER_A,
        status: TicketStatus.RESOLVED,
      });

      // Provider B cannot rate Provider A's ticket
      expect(
        await repo.addRating(ticket.ticketId, PROVIDER_B, 5),
      ).toBeNull();
    });

    it('setScreenshotPath enforces provider scoping', async () => {
      const ticket = seedTicket({ providerId: PROVIDER_A });

      // Provider B cannot set screenshot on Provider A's ticket
      expect(
        await repo.setScreenshotPath(ticket.ticketId, PROVIDER_B, '/path.png'),
      ).toBeNull();
    });
  });
});
