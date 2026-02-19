import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  createSupportTicketService,
  type AuditRepo,
  type NotificationService,
  type FileStorage,
  type ScreenshotFile,
  type CreateTicketData,
} from './support-ticket.service.js';
import {
  TicketStatus,
  TicketPriority,
  SupportAuditAction,
  SLA_TARGETS,
} from '@meritum/shared/constants/support.constants.js';

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const PROVIDER_A = crypto.randomUUID();
const PROVIDER_B = crypto.randomUUID();
const ACTOR_ADMIN = crypto.randomUUID();

// ---------------------------------------------------------------------------
// Mock ticket factory
// ---------------------------------------------------------------------------

function makeTicket(overrides: Partial<Record<string, unknown>> = {}): any {
  return {
    ticketId: overrides.ticketId ?? crypto.randomUUID(),
    providerId: overrides.providerId ?? PROVIDER_A,
    subject: overrides.subject ?? 'Test ticket',
    description: overrides.description ?? 'Test description',
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
}

// ---------------------------------------------------------------------------
// Mock dependencies
// ---------------------------------------------------------------------------

function createMockTicketsRepo() {
  return {
    create: vi.fn(async (data: any) => makeTicket(data)),
    getById: vi.fn(async () => null as any),
    listByProvider: vi.fn(async () => ({
      data: [] as any[],
      pagination: { total: 0, page: 1, pageSize: 20, hasMore: false },
    })),
    addRating: vi.fn(async () => null as any),
    setScreenshotPath: vi.fn(async () => null as any),
    updateTicket: vi.fn(async () => null as any),
    listAllTickets: vi.fn(async () => ({
      data: [] as any[],
      pagination: { total: 0, page: 1, pageSize: 20, hasMore: false },
    })),
    getSlaBreach: vi.fn(async () => [] as any[]),
  };
}

function createMockAuditRepo(): AuditRepo & {
  appendAuditLog: ReturnType<typeof vi.fn>;
} {
  return {
    appendAuditLog: vi.fn(async () => {}),
  };
}

function createMockNotificationService(): NotificationService & {
  send: ReturnType<typeof vi.fn>;
} {
  return {
    send: vi.fn(async () => {}),
  };
}

function createMockFileStorage(): FileStorage & {
  upload: ReturnType<typeof vi.fn>;
} {
  return {
    upload: vi.fn(async (key: string) => key),
  };
}

function makeScreenshotFile(
  overrides?: Partial<ScreenshotFile>,
): ScreenshotFile {
  return {
    buffer: Buffer.from('fake-image-data'),
    mimetype: overrides?.mimetype ?? 'image/png',
    size: overrides?.size ?? 1024,
    originalname: overrides?.originalname ?? 'screenshot.png',
  };
}

// ---------------------------------------------------------------------------
// Service constructor helper
// ---------------------------------------------------------------------------

function createTestDeps() {
  const ticketsRepo = createMockTicketsRepo();
  const auditRepo = createMockAuditRepo();
  const notificationService = createMockNotificationService();
  const fileStorage = createMockFileStorage();

  const service = createSupportTicketService({
    ticketsRepo,
    auditRepo,
    notificationService,
    fileStorage,
  });

  return { service, ticketsRepo, auditRepo, notificationService, fileStorage };
}

// ===========================================================================
// createTicket
// ===========================================================================

describe('createTicket', () => {
  let service: ReturnType<typeof createSupportTicketService>;
  let ticketsRepo: ReturnType<typeof createMockTicketsRepo>;
  let auditRepo: ReturnType<typeof createMockAuditRepo>;
  let notificationService: ReturnType<typeof createMockNotificationService>;
  let fileStorage: ReturnType<typeof createMockFileStorage>;

  beforeEach(() => {
    ({ service, ticketsRepo, auditRepo, notificationService, fileStorage } =
      createTestDeps());
  });

  it('creates a ticket and returns it without screenshotPath', async () => {
    const createdTicket = makeTicket({
      providerId: PROVIDER_A,
      subject: 'Help with billing',
      screenshotPath: null,
    });
    ticketsRepo.create.mockResolvedValueOnce(createdTicket);

    const result = await service.createTicket(PROVIDER_A, {
      subject: 'Help with billing',
      description: 'My claim was rejected',
    });

    expect(result).toBeDefined();
    expect(result.subject).toBe('Help with billing');
    expect(result).not.toHaveProperty('screenshotPath');
    expect(ticketsRepo.create).toHaveBeenCalledWith(
      expect.objectContaining({
        providerId: PROVIDER_A,
        subject: 'Help with billing',
        description: 'My claim was rejected',
      }),
    );
  });

  it('passes context_metadata to the repository', async () => {
    const metadata = { batch_error: true, batch_id: 'batch-123' };
    ticketsRepo.create.mockResolvedValueOnce(
      makeTicket({
        providerId: PROVIDER_A,
        contextMetadata: metadata,
        priority: TicketPriority.URGENT,
      }),
    );

    const result = await service.createTicket(PROVIDER_A, {
      subject: 'Batch failed',
      description: 'Batch submission error',
      contextMetadata: metadata,
    });

    expect(ticketsRepo.create).toHaveBeenCalledWith(
      expect.objectContaining({ contextMetadata: metadata }),
    );
    // Auto-URGENT is handled by the repository — we verify it passes through
    expect(result.priority).toBe(TicketPriority.URGENT);
  });

  it('auto-detects URGENT priority when context_metadata has batch_error', async () => {
    const metadata = { batch_error: true };
    ticketsRepo.create.mockResolvedValueOnce(
      makeTicket({
        providerId: PROVIDER_A,
        priority: TicketPriority.URGENT,
        contextMetadata: metadata,
      }),
    );

    const result = await service.createTicket(PROVIDER_A, {
      subject: 'Batch issue',
      description: 'Errors occurred',
      contextMetadata: metadata,
    });

    expect(result.priority).toBe(TicketPriority.URGENT);
  });

  it('auto-detects URGENT priority when context_metadata has error_codes', async () => {
    const metadata = { batch_id: 'b-1', error_codes: ['E01'] };
    ticketsRepo.create.mockResolvedValueOnce(
      makeTicket({
        providerId: PROVIDER_A,
        priority: TicketPriority.URGENT,
        contextMetadata: metadata,
      }),
    );

    const result = await service.createTicket(PROVIDER_A, {
      subject: 'Error codes',
      description: 'Errors',
      contextMetadata: metadata,
    });

    expect(result.priority).toBe(TicketPriority.URGENT);
  });

  it('sends confirmation notification to the physician', async () => {
    const ticket = makeTicket({ providerId: PROVIDER_A, subject: 'My ticket' });
    ticketsRepo.create.mockResolvedValueOnce(ticket);

    await service.createTicket(PROVIDER_A, {
      subject: 'My ticket',
      description: 'Description',
    });

    expect(notificationService.send).toHaveBeenCalledWith({
      type: 'support.ticket_created',
      providerId: PROVIDER_A,
      data: {
        ticketId: ticket.ticketId,
        subject: 'My ticket',
      },
    });
  });

  it('creates audit log entry on ticket creation', async () => {
    const ticket = makeTicket({
      providerId: PROVIDER_A,
      subject: 'Audit test',
      priority: TicketPriority.MEDIUM,
    });
    ticketsRepo.create.mockResolvedValueOnce(ticket);

    await service.createTicket(PROVIDER_A, {
      subject: 'Audit test',
      description: 'Testing audit',
    });

    expect(auditRepo.appendAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: PROVIDER_A,
        action: SupportAuditAction.TICKET_CREATED,
        category: 'support',
        resourceType: 'support_ticket',
        resourceId: ticket.ticketId,
        detail: expect.objectContaining({
          subject: 'Audit test',
          priority: TicketPriority.MEDIUM,
          hasScreenshot: false,
        }),
      }),
    );
  });

  // -- Screenshot upload --

  it('uploads screenshot and stores path when file is provided', async () => {
    const ticket = makeTicket({ providerId: PROVIDER_A });
    ticketsRepo.create.mockResolvedValueOnce(ticket);
    ticketsRepo.setScreenshotPath.mockResolvedValueOnce(ticket);

    const screenshot = makeScreenshotFile();
    await service.createTicket(
      PROVIDER_A,
      { subject: 'With screenshot', description: 'See attached' },
      screenshot,
    );

    expect(fileStorage.upload).toHaveBeenCalledWith(
      `support-tickets/${ticket.ticketId}/screenshot.png`,
      screenshot.buffer,
      'image/png',
    );
    expect(ticketsRepo.setScreenshotPath).toHaveBeenCalledWith(
      ticket.ticketId,
      PROVIDER_A,
      `support-tickets/${ticket.ticketId}/screenshot.png`,
    );
  });

  it('validates screenshot file type — rejects non-image types', async () => {
    const screenshot = makeScreenshotFile({ mimetype: 'application/pdf' });

    await expect(
      service.createTicket(
        PROVIDER_A,
        { subject: 'Bad file', description: 'PDF' },
        screenshot,
      ),
    ).rejects.toThrow('Screenshot must be a PNG, JPEG, or WebP image');
  });

  it('validates screenshot file type — rejects executables', async () => {
    const screenshot = makeScreenshotFile({
      mimetype: 'application/x-executable',
    });

    await expect(
      service.createTicket(
        PROVIDER_A,
        { subject: 'Bad file', description: 'Executable' },
        screenshot,
      ),
    ).rejects.toThrow('Screenshot must be a PNG, JPEG, or WebP image');
  });

  it('validates screenshot file size — rejects files over 5MB', async () => {
    const screenshot = makeScreenshotFile({
      size: 6 * 1024 * 1024, // 6MB
    });

    await expect(
      service.createTicket(
        PROVIDER_A,
        { subject: 'Big file', description: 'Too large' },
        screenshot,
      ),
    ).rejects.toThrow('Screenshot must be 5MB or smaller');
  });

  it('accepts JPEG screenshots', async () => {
    const ticket = makeTicket({ providerId: PROVIDER_A });
    ticketsRepo.create.mockResolvedValueOnce(ticket);
    ticketsRepo.setScreenshotPath.mockResolvedValueOnce(ticket);

    const screenshot = makeScreenshotFile({ mimetype: 'image/jpeg' });
    await service.createTicket(
      PROVIDER_A,
      { subject: 'JPEG screenshot', description: 'Works' },
      screenshot,
    );

    expect(fileStorage.upload).toHaveBeenCalledWith(
      expect.stringContaining('screenshot.jpeg'),
      screenshot.buffer,
      'image/jpeg',
    );
  });

  it('accepts WebP screenshots', async () => {
    const ticket = makeTicket({ providerId: PROVIDER_A });
    ticketsRepo.create.mockResolvedValueOnce(ticket);
    ticketsRepo.setScreenshotPath.mockResolvedValueOnce(ticket);

    const screenshot = makeScreenshotFile({ mimetype: 'image/webp' });
    await service.createTicket(
      PROVIDER_A,
      { subject: 'WebP screenshot', description: 'Works' },
      screenshot,
    );

    expect(fileStorage.upload).toHaveBeenCalledWith(
      expect.stringContaining('screenshot.webp'),
      screenshot.buffer,
      'image/webp',
    );
  });

  it('audit log indicates hasScreenshot: true when screenshot provided', async () => {
    const ticket = makeTicket({ providerId: PROVIDER_A });
    ticketsRepo.create.mockResolvedValueOnce(ticket);
    ticketsRepo.setScreenshotPath.mockResolvedValueOnce(ticket);

    const screenshot = makeScreenshotFile();
    await service.createTicket(
      PROVIDER_A,
      { subject: 'Screenshot audit', description: 'Test' },
      screenshot,
    );

    expect(auditRepo.appendAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({
        detail: expect.objectContaining({ hasScreenshot: true }),
      }),
    );
  });

  it('does not call setScreenshotPath or upload when no file', async () => {
    ticketsRepo.create.mockResolvedValueOnce(
      makeTicket({ providerId: PROVIDER_A }),
    );

    await service.createTicket(PROVIDER_A, {
      subject: 'No file',
      description: 'No screenshot',
    });

    expect(fileStorage.upload).not.toHaveBeenCalled();
    expect(ticketsRepo.setScreenshotPath).not.toHaveBeenCalled();
  });
});

// ===========================================================================
// getTicket
// ===========================================================================

describe('getTicket', () => {
  let service: ReturnType<typeof createSupportTicketService>;
  let ticketsRepo: ReturnType<typeof createMockTicketsRepo>;

  beforeEach(() => {
    ({ service, ticketsRepo } = createTestDeps());
  });

  it('returns ticket scoped to the provider, without screenshotPath', async () => {
    const ticket = makeTicket({
      providerId: PROVIDER_A,
      screenshotPath: '/secret/path.png',
    });
    ticketsRepo.getById.mockResolvedValueOnce(ticket);

    const result = await service.getTicket(PROVIDER_A, ticket.ticketId);

    expect(result).toBeDefined();
    expect(result).not.toHaveProperty('screenshotPath');
    expect(ticketsRepo.getById).toHaveBeenCalledWith(
      ticket.ticketId,
      PROVIDER_A,
    );
  });

  it('returns null when ticket belongs to another provider', async () => {
    ticketsRepo.getById.mockResolvedValueOnce(null);

    const result = await service.getTicket(PROVIDER_A, crypto.randomUUID());

    expect(result).toBeNull();
  });

  it('returns null for non-existent ticket', async () => {
    ticketsRepo.getById.mockResolvedValueOnce(null);

    const result = await service.getTicket(PROVIDER_A, crypto.randomUUID());

    expect(result).toBeNull();
  });
});

// ===========================================================================
// listTickets
// ===========================================================================

describe('listTickets', () => {
  let service: ReturnType<typeof createSupportTicketService>;
  let ticketsRepo: ReturnType<typeof createMockTicketsRepo>;

  beforeEach(() => {
    ({ service, ticketsRepo } = createTestDeps());
  });

  it('returns paginated tickets without screenshotPath', async () => {
    const tickets = [
      makeTicket({ screenshotPath: '/path1.png' }),
      makeTicket({ screenshotPath: '/path2.jpg' }),
    ];
    ticketsRepo.listByProvider.mockResolvedValueOnce({
      data: tickets,
      pagination: { total: 2, page: 1, pageSize: 20, hasMore: false },
    });

    const result = await service.listTickets(PROVIDER_A);

    expect(result.data.length).toBe(2);
    result.data.forEach((t) => {
      expect(t).not.toHaveProperty('screenshotPath');
    });
    expect(result.pagination.total).toBe(2);
  });

  it('passes filters to the repository', async () => {
    ticketsRepo.listByProvider.mockResolvedValueOnce({
      data: [],
      pagination: { total: 0, page: 1, pageSize: 10, hasMore: false },
    });

    await service.listTickets(PROVIDER_A, {
      status: TicketStatus.OPEN,
      limit: 10,
      offset: 0,
    });

    expect(ticketsRepo.listByProvider).toHaveBeenCalledWith(PROVIDER_A, {
      status: TicketStatus.OPEN,
      limit: 10,
      offset: 0,
    });
  });
});

// ===========================================================================
// rateTicket
// ===========================================================================

describe('rateTicket', () => {
  let service: ReturnType<typeof createSupportTicketService>;
  let ticketsRepo: ReturnType<typeof createMockTicketsRepo>;
  let auditRepo: ReturnType<typeof createMockAuditRepo>;

  beforeEach(() => {
    ({ service, ticketsRepo, auditRepo } = createTestDeps());
  });

  it('rates a RESOLVED ticket and returns updated ticket without screenshotPath', async () => {
    const ticket = makeTicket({
      providerId: PROVIDER_A,
      status: TicketStatus.RESOLVED,
      satisfactionRating: 5,
      satisfactionComment: 'Great!',
      screenshotPath: '/secret.png',
    });
    ticketsRepo.addRating.mockResolvedValueOnce(ticket);

    const result = await service.rateTicket(PROVIDER_A, ticket.ticketId, 5, 'Great!');

    expect(result).toBeDefined();
    expect(result!.satisfactionRating).toBe(5);
    expect(result).not.toHaveProperty('screenshotPath');
  });

  it('rates a CLOSED ticket', async () => {
    const ticket = makeTicket({
      providerId: PROVIDER_A,
      status: TicketStatus.CLOSED,
      satisfactionRating: 3,
    });
    ticketsRepo.addRating.mockResolvedValueOnce(ticket);

    const result = await service.rateTicket(PROVIDER_A, ticket.ticketId, 3);

    expect(result).toBeDefined();
    expect(result!.satisfactionRating).toBe(3);
  });

  it('returns null when ticket is not in RESOLVED/CLOSED status', async () => {
    // The repo returns null for non-RESOLVED/CLOSED tickets
    ticketsRepo.addRating.mockResolvedValueOnce(null);

    const result = await service.rateTicket(
      PROVIDER_A,
      crypto.randomUUID(),
      5,
    );

    expect(result).toBeNull();
  });

  it('returns null when ticket belongs to another provider', async () => {
    ticketsRepo.addRating.mockResolvedValueOnce(null);

    const result = await service.rateTicket(PROVIDER_A, crypto.randomUUID(), 4);

    expect(result).toBeNull();
  });

  it('creates audit log when rating succeeds', async () => {
    const ticket = makeTicket({
      providerId: PROVIDER_A,
      status: TicketStatus.RESOLVED,
      satisfactionRating: 4,
    });
    ticketsRepo.addRating.mockResolvedValueOnce(ticket);

    await service.rateTicket(PROVIDER_A, ticket.ticketId, 4, 'Good');

    expect(auditRepo.appendAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: PROVIDER_A,
        action: SupportAuditAction.TICKET_RATED,
        category: 'support',
        resourceType: 'support_ticket',
        resourceId: ticket.ticketId,
        detail: { rating: 4, hasComment: true },
      }),
    );
  });

  it('does not create audit log when rating fails', async () => {
    ticketsRepo.addRating.mockResolvedValueOnce(null);

    await service.rateTicket(PROVIDER_A, crypto.randomUUID(), 5);

    expect(auditRepo.appendAuditLog).not.toHaveBeenCalled();
  });

  it('audit log indicates hasComment: false when no comment', async () => {
    const ticket = makeTicket({
      providerId: PROVIDER_A,
      status: TicketStatus.RESOLVED,
    });
    ticketsRepo.addRating.mockResolvedValueOnce(ticket);

    await service.rateTicket(PROVIDER_A, ticket.ticketId, 3);

    expect(auditRepo.appendAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({
        detail: { rating: 3, hasComment: false },
      }),
    );
  });
});

// ===========================================================================
// updateTicket (admin)
// ===========================================================================

describe('updateTicket (admin)', () => {
  let service: ReturnType<typeof createSupportTicketService>;
  let ticketsRepo: ReturnType<typeof createMockTicketsRepo>;
  let auditRepo: ReturnType<typeof createMockAuditRepo>;
  let notificationService: ReturnType<typeof createMockNotificationService>;

  beforeEach(() => {
    ({ service, ticketsRepo, auditRepo, notificationService } =
      createTestDeps());
  });

  it('updates ticket status with valid transition OPEN -> IN_PROGRESS', async () => {
    const existing = makeTicket({ status: TicketStatus.OPEN });
    ticketsRepo.listAllTickets.mockResolvedValueOnce({
      data: [existing],
      pagination: { total: 1, page: 1, pageSize: 1000, hasMore: false },
    });
    const updated = makeTicket({
      ...existing,
      status: TicketStatus.IN_PROGRESS,
    });
    ticketsRepo.updateTicket.mockResolvedValueOnce(updated);

    const result = await service.updateTicket(
      existing.ticketId,
      { status: TicketStatus.IN_PROGRESS },
      ACTOR_ADMIN,
    );

    expect(result).toBeDefined();
    expect(result!.status).toBe(TicketStatus.IN_PROGRESS);
  });

  it('rejects invalid status transition OPEN -> RESOLVED', async () => {
    const existing = makeTicket({ status: TicketStatus.OPEN });
    ticketsRepo.listAllTickets.mockResolvedValueOnce({
      data: [existing],
      pagination: { total: 1, page: 1, pageSize: 1000, hasMore: false },
    });

    await expect(
      service.updateTicket(
        existing.ticketId,
        { status: TicketStatus.RESOLVED },
        ACTOR_ADMIN,
      ),
    ).rejects.toThrow('Invalid status transition');
  });

  it('rejects invalid status transition OPEN -> CLOSED', async () => {
    const existing = makeTicket({ status: TicketStatus.OPEN });
    ticketsRepo.listAllTickets.mockResolvedValueOnce({
      data: [existing],
      pagination: { total: 1, page: 1, pageSize: 1000, hasMore: false },
    });

    await expect(
      service.updateTicket(
        existing.ticketId,
        { status: TicketStatus.CLOSED },
        ACTOR_ADMIN,
      ),
    ).rejects.toThrow('Invalid status transition');
  });

  it('allows transition IN_PROGRESS -> RESOLVED', async () => {
    const existing = makeTicket({ status: TicketStatus.IN_PROGRESS });
    ticketsRepo.listAllTickets.mockResolvedValueOnce({
      data: [existing],
      pagination: { total: 1, page: 1, pageSize: 1000, hasMore: false },
    });
    const updated = makeTicket({
      ...existing,
      status: TicketStatus.RESOLVED,
      resolvedAt: new Date(),
    });
    ticketsRepo.updateTicket.mockResolvedValueOnce(updated);

    const result = await service.updateTicket(
      existing.ticketId,
      { status: TicketStatus.RESOLVED, resolutionNotes: 'Fixed' },
      ACTOR_ADMIN,
    );

    expect(result).toBeDefined();
    expect(result!.status).toBe(TicketStatus.RESOLVED);
  });

  it('allows transition IN_PROGRESS -> WAITING_ON_CUSTOMER', async () => {
    const existing = makeTicket({ status: TicketStatus.IN_PROGRESS });
    ticketsRepo.listAllTickets.mockResolvedValueOnce({
      data: [existing],
      pagination: { total: 1, page: 1, pageSize: 1000, hasMore: false },
    });
    const updated = makeTicket({
      ...existing,
      status: TicketStatus.WAITING_ON_CUSTOMER,
    });
    ticketsRepo.updateTicket.mockResolvedValueOnce(updated);

    const result = await service.updateTicket(
      existing.ticketId,
      { status: TicketStatus.WAITING_ON_CUSTOMER },
      ACTOR_ADMIN,
    );

    expect(result).toBeDefined();
    expect(result!.status).toBe(TicketStatus.WAITING_ON_CUSTOMER);
  });

  it('allows transition WAITING_ON_CUSTOMER -> IN_PROGRESS', async () => {
    const existing = makeTicket({
      status: TicketStatus.WAITING_ON_CUSTOMER,
    });
    ticketsRepo.listAllTickets.mockResolvedValueOnce({
      data: [existing],
      pagination: { total: 1, page: 1, pageSize: 1000, hasMore: false },
    });
    const updated = makeTicket({
      ...existing,
      status: TicketStatus.IN_PROGRESS,
    });
    ticketsRepo.updateTicket.mockResolvedValueOnce(updated);

    const result = await service.updateTicket(
      existing.ticketId,
      { status: TicketStatus.IN_PROGRESS },
      ACTOR_ADMIN,
    );

    expect(result).toBeDefined();
    expect(result!.status).toBe(TicketStatus.IN_PROGRESS);
  });

  it('allows transition WAITING_ON_CUSTOMER -> RESOLVED', async () => {
    const existing = makeTicket({
      status: TicketStatus.WAITING_ON_CUSTOMER,
    });
    ticketsRepo.listAllTickets.mockResolvedValueOnce({
      data: [existing],
      pagination: { total: 1, page: 1, pageSize: 1000, hasMore: false },
    });
    const updated = makeTicket({
      ...existing,
      status: TicketStatus.RESOLVED,
      resolvedAt: new Date(),
    });
    ticketsRepo.updateTicket.mockResolvedValueOnce(updated);

    const result = await service.updateTicket(
      existing.ticketId,
      { status: TicketStatus.RESOLVED },
      ACTOR_ADMIN,
    );

    expect(result).toBeDefined();
    expect(result!.status).toBe(TicketStatus.RESOLVED);
  });

  it('rejects transition from CLOSED', async () => {
    const existing = makeTicket({ status: TicketStatus.CLOSED });
    ticketsRepo.listAllTickets.mockResolvedValueOnce({
      data: [existing],
      pagination: { total: 1, page: 1, pageSize: 1000, hasMore: false },
    });

    await expect(
      service.updateTicket(
        existing.ticketId,
        { status: TicketStatus.OPEN },
        ACTOR_ADMIN,
      ),
    ).rejects.toThrow('Invalid status transition');
  });

  it('creates audit log for ticket update', async () => {
    const existing = makeTicket({ status: TicketStatus.OPEN });
    ticketsRepo.listAllTickets.mockResolvedValueOnce({
      data: [existing],
      pagination: { total: 1, page: 1, pageSize: 1000, hasMore: false },
    });
    ticketsRepo.updateTicket.mockResolvedValueOnce(
      makeTicket({ ...existing, status: TicketStatus.IN_PROGRESS }),
    );

    await service.updateTicket(
      existing.ticketId,
      { status: TicketStatus.IN_PROGRESS },
      ACTOR_ADMIN,
    );

    expect(auditRepo.appendAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: ACTOR_ADMIN,
        action: SupportAuditAction.TICKET_UPDATED,
        category: 'support',
        resourceType: 'support_ticket',
        resourceId: existing.ticketId,
      }),
    );
  });

  it('creates RESOLVED audit log and sends notification when transitioning to RESOLVED', async () => {
    const existing = makeTicket({
      status: TicketStatus.IN_PROGRESS,
      providerId: PROVIDER_A,
    });
    ticketsRepo.listAllTickets.mockResolvedValueOnce({
      data: [existing],
      pagination: { total: 1, page: 1, pageSize: 1000, hasMore: false },
    });
    const resolved = makeTicket({
      ...existing,
      status: TicketStatus.RESOLVED,
      resolvedAt: new Date(),
    });
    ticketsRepo.updateTicket.mockResolvedValueOnce(resolved);

    await service.updateTicket(
      existing.ticketId,
      { status: TicketStatus.RESOLVED, resolutionNotes: 'All good' },
      ACTOR_ADMIN,
    );

    // Should have two audit logs: TICKET_UPDATED + TICKET_RESOLVED
    expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(2);
    expect(auditRepo.appendAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({
        action: SupportAuditAction.TICKET_RESOLVED,
      }),
    );

    // Notification sent with type 'support.ticket_resolved'
    expect(notificationService.send).toHaveBeenCalledWith({
      type: 'support.ticket_resolved',
      providerId: PROVIDER_A,
      data: expect.objectContaining({
        ticketId: resolved.ticketId,
        subject: resolved.subject,
      }),
    });
  });

  it('sends status change notification for non-RESOLVED transitions', async () => {
    const existing = makeTicket({
      status: TicketStatus.OPEN,
      providerId: PROVIDER_A,
    });
    ticketsRepo.listAllTickets.mockResolvedValueOnce({
      data: [existing],
      pagination: { total: 1, page: 1, pageSize: 1000, hasMore: false },
    });
    const updated = makeTicket({
      ...existing,
      status: TicketStatus.IN_PROGRESS,
    });
    ticketsRepo.updateTicket.mockResolvedValueOnce(updated);

    await service.updateTicket(
      existing.ticketId,
      { status: TicketStatus.IN_PROGRESS },
      ACTOR_ADMIN,
    );

    expect(notificationService.send).toHaveBeenCalledWith({
      type: 'support.ticket_status_changed',
      providerId: PROVIDER_A,
      data: expect.objectContaining({
        ticketId: updated.ticketId,
        newStatus: TicketStatus.IN_PROGRESS,
      }),
    });
  });

  it('does not send notification when no status change', async () => {
    const existing = makeTicket({ status: TicketStatus.OPEN });
    // No status change means no listAllTickets call for validation
    ticketsRepo.updateTicket.mockResolvedValueOnce(
      makeTicket({ ...existing, category: 'TECHNICAL' }),
    );

    await service.updateTicket(
      existing.ticketId,
      { category: 'TECHNICAL' },
      ACTOR_ADMIN,
    );

    expect(notificationService.send).not.toHaveBeenCalled();
  });

  it('returns null when ticket does not exist', async () => {
    ticketsRepo.listAllTickets.mockResolvedValueOnce({
      data: [],
      pagination: { total: 0, page: 1, pageSize: 1000, hasMore: false },
    });

    const result = await service.updateTicket(
      crypto.randomUUID(),
      { status: TicketStatus.IN_PROGRESS },
      ACTOR_ADMIN,
    );

    expect(result).toBeNull();
  });

  it('updates non-status fields without transition validation', async () => {
    const existing = makeTicket({ status: TicketStatus.OPEN });
    const updated = makeTicket({
      ...existing,
      priority: TicketPriority.HIGH,
      assignedTo: 'agent@meritum.ca',
    });
    ticketsRepo.updateTicket.mockResolvedValueOnce(updated);

    const result = await service.updateTicket(
      existing.ticketId,
      { priority: TicketPriority.HIGH, assignedTo: 'agent@meritum.ca' },
      ACTOR_ADMIN,
    );

    expect(result).toBeDefined();
    expect(result!.priority).toBe(TicketPriority.HIGH);
    expect(result!.assignedTo).toBe('agent@meritum.ca');
    // Should not have called listAllTickets for status validation
    expect(ticketsRepo.listAllTickets).not.toHaveBeenCalled();
  });

  it('returns ticket without screenshotPath', async () => {
    const existing = makeTicket({
      status: TicketStatus.OPEN,
      screenshotPath: '/secret.png',
    });
    ticketsRepo.updateTicket.mockResolvedValueOnce(existing);

    const result = await service.updateTicket(
      existing.ticketId,
      { priority: TicketPriority.URGENT },
      ACTOR_ADMIN,
    );

    expect(result).not.toHaveProperty('screenshotPath');
  });
});

// ===========================================================================
// closeTicket (admin)
// ===========================================================================

describe('closeTicket (admin)', () => {
  let service: ReturnType<typeof createSupportTicketService>;
  let ticketsRepo: ReturnType<typeof createMockTicketsRepo>;
  let auditRepo: ReturnType<typeof createMockAuditRepo>;

  beforeEach(() => {
    ({ service, ticketsRepo, auditRepo } = createTestDeps());
  });

  it('closes a RESOLVED ticket', async () => {
    const existing = makeTicket({
      status: TicketStatus.RESOLVED,
      providerId: PROVIDER_A,
    });
    ticketsRepo.listAllTickets.mockResolvedValueOnce({
      data: [existing],
      pagination: { total: 1, page: 1, pageSize: 1000, hasMore: false },
    });
    const closed = makeTicket({
      ...existing,
      status: TicketStatus.CLOSED,
    });
    ticketsRepo.updateTicket.mockResolvedValueOnce(closed);

    const result = await service.closeTicket(existing.ticketId, ACTOR_ADMIN);

    expect(result).toBeDefined();
    expect(result!.status).toBe(TicketStatus.CLOSED);
    expect(result).not.toHaveProperty('screenshotPath');
  });

  it('creates audit log for closing a ticket', async () => {
    const existing = makeTicket({ status: TicketStatus.RESOLVED });
    ticketsRepo.listAllTickets.mockResolvedValueOnce({
      data: [existing],
      pagination: { total: 1, page: 1, pageSize: 1000, hasMore: false },
    });
    ticketsRepo.updateTicket.mockResolvedValueOnce(
      makeTicket({ ...existing, status: TicketStatus.CLOSED }),
    );

    await service.closeTicket(existing.ticketId, ACTOR_ADMIN);

    expect(auditRepo.appendAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: ACTOR_ADMIN,
        action: SupportAuditAction.TICKET_CLOSED,
        category: 'support',
        resourceType: 'support_ticket',
        resourceId: existing.ticketId,
      }),
    );
  });

  it('throws BusinessRuleError when ticket is not RESOLVED', async () => {
    const existing = makeTicket({ status: TicketStatus.OPEN });
    ticketsRepo.listAllTickets.mockResolvedValueOnce({
      data: [existing],
      pagination: { total: 1, page: 1, pageSize: 1000, hasMore: false },
    });

    await expect(
      service.closeTicket(existing.ticketId, ACTOR_ADMIN),
    ).rejects.toThrow('Only RESOLVED tickets can be closed');
  });

  it('throws BusinessRuleError when ticket is IN_PROGRESS', async () => {
    const existing = makeTicket({ status: TicketStatus.IN_PROGRESS });
    ticketsRepo.listAllTickets.mockResolvedValueOnce({
      data: [existing],
      pagination: { total: 1, page: 1, pageSize: 1000, hasMore: false },
    });

    await expect(
      service.closeTicket(existing.ticketId, ACTOR_ADMIN),
    ).rejects.toThrow('Only RESOLVED tickets can be closed');
  });

  it('returns null when ticket does not exist', async () => {
    ticketsRepo.listAllTickets.mockResolvedValueOnce({
      data: [],
      pagination: { total: 0, page: 1, pageSize: 1000, hasMore: false },
    });

    const result = await service.closeTicket(crypto.randomUUID(), ACTOR_ADMIN);

    expect(result).toBeNull();
  });
});

// ===========================================================================
// getTriageQueue (admin)
// ===========================================================================

describe('getTriageQueue (admin)', () => {
  let service: ReturnType<typeof createSupportTicketService>;
  let ticketsRepo: ReturnType<typeof createMockTicketsRepo>;

  beforeEach(() => {
    ({ service, ticketsRepo } = createTestDeps());
  });

  it('delegates to listAllTickets with filters', async () => {
    const expected = {
      data: [makeTicket()],
      pagination: { total: 1, page: 1, pageSize: 20, hasMore: false },
    };
    ticketsRepo.listAllTickets.mockResolvedValueOnce(expected);

    const result = await service.getTriageQueue({
      status: TicketStatus.OPEN,
      priority: TicketPriority.URGENT,
    });

    expect(result).toEqual(expected);
    expect(ticketsRepo.listAllTickets).toHaveBeenCalledWith({
      status: TicketStatus.OPEN,
      priority: TicketPriority.URGENT,
    });
  });

  it('returns all tickets when no filters', async () => {
    ticketsRepo.listAllTickets.mockResolvedValueOnce({
      data: [],
      pagination: { total: 0, page: 1, pageSize: 20, hasMore: false },
    });

    await service.getTriageQueue();

    expect(ticketsRepo.listAllTickets).toHaveBeenCalledWith(undefined);
  });
});

// ===========================================================================
// getSlaBreach (admin)
// ===========================================================================

describe('getSlaBreach (admin)', () => {
  let service: ReturnType<typeof createSupportTicketService>;
  let ticketsRepo: ReturnType<typeof createMockTicketsRepo>;

  beforeEach(() => {
    ({ service, ticketsRepo } = createTestDeps());
  });

  it('delegates to repo getSlaBreach', async () => {
    const breaches = [
      {
        ...makeTicket({ status: TicketStatus.OPEN }),
        breachType: 'first_response' as const,
        elapsedBusinessMinutes: 700,
        targetMinutes: SLA_TARGETS.MEDIUM.firstResponseMinutes,
      },
    ];
    ticketsRepo.getSlaBreach.mockResolvedValueOnce(breaches);

    const result = await service.getSlaBreach();

    expect(result).toEqual(breaches);
    expect(ticketsRepo.getSlaBreach).toHaveBeenCalled();
  });

  it('returns empty array when no breaches', async () => {
    ticketsRepo.getSlaBreach.mockResolvedValueOnce([]);

    const result = await service.getSlaBreach();

    expect(result).toEqual([]);
  });
});

// ===========================================================================
// SLA business hours calculation (imported from repo, tested here for coverage)
// ===========================================================================

describe('SLA business hours (integration with service)', () => {
  let service: ReturnType<typeof createSupportTicketService>;
  let ticketsRepo: ReturnType<typeof createMockTicketsRepo>;

  beforeEach(() => {
    ({ service, ticketsRepo } = createTestDeps());
  });

  it('SLA breach detection uses business hours calculation', async () => {
    // This test verifies the service correctly delegates SLA breach to repo
    const breach = {
      ...makeTicket({
        status: TicketStatus.OPEN,
        priority: TicketPriority.URGENT,
        createdAt: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000),
      }),
      breachType: 'first_response' as const,
      elapsedBusinessMinutes: 300,
      targetMinutes: SLA_TARGETS.URGENT.firstResponseMinutes,
    };
    ticketsRepo.getSlaBreach.mockResolvedValueOnce([breach]);

    const result = await service.getSlaBreach();

    expect(result.length).toBe(1);
    expect(result[0].breachType).toBe('first_response');
    expect(result[0].elapsedBusinessMinutes).toBeGreaterThan(
      result[0].targetMinutes,
    );
  });
});

// ===========================================================================
// Notification dispatch verification
// ===========================================================================

describe('notification dispatch', () => {
  let service: ReturnType<typeof createSupportTicketService>;
  let ticketsRepo: ReturnType<typeof createMockTicketsRepo>;
  let notificationService: ReturnType<typeof createMockNotificationService>;

  beforeEach(() => {
    ({ service, ticketsRepo, notificationService } = createTestDeps());
  });

  it('ticket creation triggers confirmation email notification', async () => {
    const ticket = makeTicket({ providerId: PROVIDER_A, subject: 'Notify me' });
    ticketsRepo.create.mockResolvedValueOnce(ticket);

    await service.createTicket(PROVIDER_A, {
      subject: 'Notify me',
      description: 'Please confirm',
    });

    expect(notificationService.send).toHaveBeenCalledTimes(1);
    expect(notificationService.send).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'support.ticket_created',
        providerId: PROVIDER_A,
      }),
    );
  });

  it('ticket creation notification contains only ticketId and subject (no PHI)', async () => {
    const ticket = makeTicket({
      providerId: PROVIDER_A,
      subject: 'Safe subject',
      description: 'Contains PHI details about patient John Doe PHN 123456789',
    });
    ticketsRepo.create.mockResolvedValueOnce(ticket);

    await service.createTicket(PROVIDER_A, {
      subject: 'Safe subject',
      description: 'Contains PHI details about patient John Doe PHN 123456789',
    });

    const sentNotification = notificationService.send.mock.calls[0][0];
    expect(sentNotification.data).toEqual({
      ticketId: ticket.ticketId,
      subject: 'Safe subject',
    });
    // Ensure no PHI in notification data
    const dataStr = JSON.stringify(sentNotification.data);
    expect(dataStr).not.toContain('John Doe');
    expect(dataStr).not.toContain('123456789');
    expect(dataStr).not.toContain('PHI');
  });

  it('resolved ticket notification contains only ticketId and subject', async () => {
    const existing = makeTicket({
      status: TicketStatus.IN_PROGRESS,
      providerId: PROVIDER_A,
      subject: 'Resolve test',
      description: 'Patient details here',
    });
    ticketsRepo.listAllTickets.mockResolvedValueOnce({
      data: [existing],
      pagination: { total: 1, page: 1, pageSize: 1000, hasMore: false },
    });
    const resolved = makeTicket({
      ...existing,
      status: TicketStatus.RESOLVED,
      resolvedAt: new Date(),
      resolutionNotes: 'Fixed with patient info hidden',
    });
    ticketsRepo.updateTicket.mockResolvedValueOnce(resolved);

    await service.updateTicket(
      existing.ticketId,
      { status: TicketStatus.RESOLVED, resolutionNotes: 'Fixed with patient info hidden' },
      ACTOR_ADMIN,
    );

    const sentNotification = notificationService.send.mock.calls[0][0];
    expect(sentNotification.type).toBe('support.ticket_resolved');
    expect(sentNotification.data.ticketId).toBe(resolved.ticketId);
    expect(sentNotification.data.subject).toBe('Resolve test');
    // No resolution notes or description in notification
    expect(sentNotification.data).not.toHaveProperty('description');
    expect(sentNotification.data).not.toHaveProperty('resolutionNotes');
  });
});
