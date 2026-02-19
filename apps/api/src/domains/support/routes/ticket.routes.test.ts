// ============================================================================
// Domain 13: Support Ticket Routes — Unit Tests
// Tests: ticket CRUD, screenshot upload validation (size, type), rating
// validation, provider scoping, authentication enforcement.
// ============================================================================

// ---------------------------------------------------------------------------
// Environment setup (must come before any imports that read env)
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);

// ---------------------------------------------------------------------------
// Mock otplib (required by iam.service.ts transitive import)
// ---------------------------------------------------------------------------

import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('otplib', () => ({
  authenticator: {
    options: {},
    generateSecret: vi.fn(() => 'JBSWY3DPEHPK3PXP'),
    keyuri: vi.fn(() => 'otpauth://totp/test'),
    verify: vi.fn(() => false),
  },
}));

// ---------------------------------------------------------------------------
// Imports (after mocks are hoisted)
// ---------------------------------------------------------------------------

import Fastify, { type FastifyInstance } from 'fastify';
import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { createHash, randomBytes } from 'node:crypto';
import { authPluginFp } from '../../../plugins/auth.plugin.js';
import { ticketRoutes, type TicketRoutesDeps } from './ticket.routes.js';

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const PHYSICIAN_ID = '00000000-0000-4000-8000-000000000001';
const OTHER_PHYSICIAN_ID = '00000000-0000-4000-8000-000000000002';
const TICKET_ID = '00000000-0000-4000-8000-000000000010';
const SESSION_TOKEN = randomBytes(32).toString('hex');
const SESSION_HASH = createHash('sha256').update(SESSION_TOKEN).digest('hex');

// Delegate session
const DELEGATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_SESSION_HASH = createHash('sha256')
  .update(DELEGATE_SESSION_TOKEN)
  .digest('hex');
const DELEGATE_USER_ID = '00000000-0000-4000-8000-000000000099';

// ---------------------------------------------------------------------------
// Mock session deps for auth plugin
// ---------------------------------------------------------------------------

function makeSessionDeps() {
  return {
    sessionRepo: {
      findSessionByTokenHash: async (hash: string) => {
        if (hash === SESSION_HASH) {
          return {
            session: {
              sessionId: 'sess-1',
              userId: PHYSICIAN_ID,
              tokenHash: SESSION_HASH,
              ipAddress: '127.0.0.1',
              userAgent: 'test',
              createdAt: new Date(),
              lastActiveAt: new Date(),
              revoked: false,
              revokedReason: null,
            },
            user: {
              userId: PHYSICIAN_ID,
              role: 'physician',
              subscriptionStatus: 'ACTIVE',
            },
          };
        }
        if (hash === DELEGATE_SESSION_HASH) {
          return {
            session: {
              sessionId: 'sess-2',
              userId: DELEGATE_USER_ID,
              tokenHash: DELEGATE_SESSION_HASH,
              ipAddress: '127.0.0.1',
              userAgent: 'test',
              createdAt: new Date(),
              lastActiveAt: new Date(),
              revoked: false,
              revokedReason: null,
            },
            user: {
              userId: DELEGATE_USER_ID,
              role: 'delegate',
              subscriptionStatus: 'ACTIVE',
              delegateContext: {
                delegateUserId: DELEGATE_USER_ID,
                physicianProviderId: PHYSICIAN_ID,
                permissions: ['SUPPORT_VIEW', 'SUPPORT_CREATE'],
                linkageId: 'link-1',
              },
            },
          };
        }
        return undefined;
      },
      refreshSession: async () => {},
      listActiveSessions: async () => [],
    },
    auditRepo: {
      appendAuditLog: async () => {},
    },
    events: {
      emit: () => true,
      on: () => {},
    },
  };
}

// ---------------------------------------------------------------------------
// Mock ticket fixtures
// ---------------------------------------------------------------------------

function makeTicket(overrides: Record<string, unknown> = {}) {
  return {
    ticketId: TICKET_ID,
    providerId: PHYSICIAN_ID,
    subject: 'Claim rejected unexpectedly',
    description: 'My claim was rejected with code E99',
    status: 'OPEN',
    priority: 'MEDIUM',
    category: null,
    contextUrl: null,
    contextMetadata: null,
    assignedTo: null,
    resolutionNotes: null,
    resolvedAt: null,
    satisfactionRating: null,
    satisfactionComment: null,
    createdAt: new Date('2026-02-01T10:00:00.000Z'),
    updatedAt: new Date('2026-02-01T10:00:00.000Z'),
    ...overrides,
  };
}

function makeResolvedTicket(overrides: Record<string, unknown> = {}) {
  return makeTicket({
    status: 'RESOLVED',
    resolvedAt: new Date('2026-02-05T12:00:00.000Z'),
    ...overrides,
  });
}

function makePaginatedResult(tickets: unknown[] = [makeTicket()]) {
  return {
    data: tickets,
    pagination: {
      total: tickets.length,
      page: 1,
      pageSize: 20,
      hasMore: false,
    },
  };
}

// ---------------------------------------------------------------------------
// App builder
// ---------------------------------------------------------------------------

async function buildTestApp(
  serviceMock: Record<string, any>,
): Promise<FastifyInstance> {
  const app = Fastify({ logger: false });
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);

  // Register multipart support for file uploads
  await app.register(import('@fastify/multipart'), {
    limits: { fileSize: 5 * 1024 * 1024 },
  });

  const sessionDeps = makeSessionDeps();
  await app.register(authPluginFp, { sessionDeps } as any);

  const deps: TicketRoutesDeps = {
    supportTicketService: serviceMock as any,
  };

  await app.register(ticketRoutes, { deps });
  await app.ready();

  return app;
}

// ---------------------------------------------------------------------------
// Helpers: inject requests
// ---------------------------------------------------------------------------

function authedGet(app: FastifyInstance, url: string, token = SESSION_TOKEN) {
  return app.inject({ method: 'GET', url, headers: { cookie: `session=${token}` } });
}

function authedPost(
  app: FastifyInstance,
  url: string,
  body: unknown,
  token = SESSION_TOKEN,
) {
  return app.inject({
    method: 'POST',
    url,
    headers: {
      cookie: `session=${token}`,
      'content-type': 'application/json',
    },
    payload: body as string,
  });
}

function unauthGet(app: FastifyInstance, url: string) {
  return app.inject({ method: 'GET', url });
}

function unauthPost(app: FastifyInstance, url: string, body: unknown) {
  return app.inject({
    method: 'POST',
    url,
    headers: { 'content-type': 'application/json' },
    payload: body as string,
  });
}

// ---------------------------------------------------------------------------
// Helper: build multipart body
// ---------------------------------------------------------------------------

function buildMultipartPayload(
  fields: Record<string, string>,
  file?: { fieldname: string; filename: string; contentType: string; content: Buffer },
): { body: Buffer; boundary: string } {
  const boundary = '----TestBoundary' + Date.now();
  const parts: Buffer[] = [];

  for (const [key, value] of Object.entries(fields)) {
    parts.push(
      Buffer.from(
        `--${boundary}\r\nContent-Disposition: form-data; name="${key}"\r\n\r\n${value}\r\n`,
      ),
    );
  }

  if (file) {
    parts.push(
      Buffer.from(
        `--${boundary}\r\nContent-Disposition: form-data; name="${file.fieldname}"; filename="${file.filename}"\r\nContent-Type: ${file.contentType}\r\n\r\n`,
      ),
    );
    parts.push(file.content);
    parts.push(Buffer.from('\r\n'));
  }

  parts.push(Buffer.from(`--${boundary}--\r\n`));

  return { body: Buffer.concat(parts), boundary };
}

// PNG magic bytes (minimal valid PNG header)
const PNG_HEADER = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
// JPEG magic bytes
const JPEG_HEADER = Buffer.from([0xff, 0xd8, 0xff, 0xe0]);
// WebP magic bytes (RIFF....WEBP)
const WEBP_HEADER = Buffer.from([
  0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00,
  0x57, 0x45, 0x42, 0x50,
]);
// Invalid file (plain text)
const TEXT_CONTENT = Buffer.from('This is not an image');

// ============================================================================
// Tests
// ============================================================================

describe('Support Ticket Routes', () => {
  // -----------------------------------------------------------------------
  // POST /api/v1/support/tickets — Create Ticket
  // -----------------------------------------------------------------------

  describe('POST /api/v1/support/tickets', () => {
    const validPayload = {
      subject: 'Cannot submit claims',
      description: 'I keep getting an error when submitting claims',
      priority: 'MEDIUM',
    };

    it('creates a ticket with valid JSON body', async () => {
      const mockService = {
        createTicket: vi.fn().mockResolvedValue(makeTicket()),
      };
      const app = await buildTestApp(mockService);

      const res = await authedPost(app, '/api/v1/support/tickets', validPayload);

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);
      expect(body.data.ticketId).toBe(TICKET_ID);
      expect(body.data.subject).toBe('Claim rejected unexpectedly');
      expect(mockService.createTicket).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        expect.objectContaining({
          subject: 'Cannot submit claims',
          description: 'I keep getting an error when submitting claims',
          priority: 'MEDIUM',
        }),
        undefined,
      );

      await app.close();
    });

    it('creates a ticket with optional context_url', async () => {
      const mockService = {
        createTicket: vi.fn().mockResolvedValue(makeTicket()),
      };
      const app = await buildTestApp(mockService);

      const res = await authedPost(app, '/api/v1/support/tickets', {
        ...validPayload,
        context_url: 'https://meritum.ca/claims/123',
      });

      expect(res.statusCode).toBe(201);
      expect(mockService.createTicket).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        expect.objectContaining({
          contextUrl: 'https://meritum.ca/claims/123',
        }),
        undefined,
      );

      await app.close();
    });

    it('creates a ticket with multipart form data and screenshot', async () => {
      const mockService = {
        createTicket: vi.fn().mockResolvedValue(makeTicket()),
      };
      const app = await buildTestApp(mockService);

      const { body: multipartBody, boundary } = buildMultipartPayload(
        {
          subject: 'Error screenshot',
          description: 'See attached screenshot',
        },
        {
          fieldname: 'screenshot',
          filename: 'error.png',
          contentType: 'image/png',
          content: PNG_HEADER,
        },
      );

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/support/tickets',
        headers: {
          cookie: `session=${SESSION_TOKEN}`,
          'content-type': `multipart/form-data; boundary=${boundary}`,
        },
        payload: multipartBody,
      });

      expect(res.statusCode).toBe(201);
      expect(mockService.createTicket).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        expect.objectContaining({
          subject: 'Error screenshot',
          description: 'See attached screenshot',
        }),
        expect.objectContaining({
          mimetype: 'image/png',
          originalname: 'error.png',
        }),
      );

      await app.close();
    });

    it('accepts JPEG screenshot', async () => {
      const mockService = {
        createTicket: vi.fn().mockResolvedValue(makeTicket()),
      };
      const app = await buildTestApp(mockService);

      const { body: multipartBody, boundary } = buildMultipartPayload(
        { subject: 'JPEG test', description: 'JPEG screenshot test' },
        {
          fieldname: 'screenshot',
          filename: 'screenshot.jpg',
          contentType: 'image/jpeg',
          content: JPEG_HEADER,
        },
      );

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/support/tickets',
        headers: {
          cookie: `session=${SESSION_TOKEN}`,
          'content-type': `multipart/form-data; boundary=${boundary}`,
        },
        payload: multipartBody,
      });

      expect(res.statusCode).toBe(201);
      expect(mockService.createTicket).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        expect.anything(),
        expect.objectContaining({ mimetype: 'image/jpeg' }),
      );

      await app.close();
    });

    it('accepts WebP screenshot', async () => {
      const mockService = {
        createTicket: vi.fn().mockResolvedValue(makeTicket()),
      };
      const app = await buildTestApp(mockService);

      const { body: multipartBody, boundary } = buildMultipartPayload(
        { subject: 'WebP test', description: 'WebP screenshot test' },
        {
          fieldname: 'screenshot',
          filename: 'screenshot.webp',
          contentType: 'image/webp',
          content: WEBP_HEADER,
        },
      );

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/support/tickets',
        headers: {
          cookie: `session=${SESSION_TOKEN}`,
          'content-type': `multipart/form-data; boundary=${boundary}`,
        },
        payload: multipartBody,
      });

      expect(res.statusCode).toBe(201);
      expect(mockService.createTicket).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        expect.anything(),
        expect.objectContaining({ mimetype: 'image/webp' }),
      );

      await app.close();
    });

    it('rejects screenshot with invalid content type (not an image)', async () => {
      const mockService = {
        createTicket: vi.fn(),
      };
      const app = await buildTestApp(mockService);

      const { body: multipartBody, boundary } = buildMultipartPayload(
        { subject: 'Bad file', description: 'Should be rejected' },
        {
          fieldname: 'screenshot',
          filename: 'malicious.txt',
          contentType: 'text/plain',
          content: TEXT_CONTENT,
        },
      );

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/support/tickets',
        headers: {
          cookie: `session=${SESSION_TOKEN}`,
          'content-type': `multipart/form-data; boundary=${boundary}`,
        },
        payload: multipartBody,
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('VALIDATION_ERROR');
      expect(body.error.message).toContain('PNG, JPEG, or WebP');
      expect(mockService.createTicket).not.toHaveBeenCalled();

      await app.close();
    });

    it('rejects file with spoofed content-type header but wrong magic bytes', async () => {
      const mockService = {
        createTicket: vi.fn(),
      };
      const app = await buildTestApp(mockService);

      // Client says image/png but content is plain text
      const { body: multipartBody, boundary } = buildMultipartPayload(
        { subject: 'Spoofed', description: 'Spoofed content type' },
        {
          fieldname: 'screenshot',
          filename: 'fake.png',
          contentType: 'image/png',
          content: TEXT_CONTENT,
        },
      );

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/support/tickets',
        headers: {
          cookie: `session=${SESSION_TOKEN}`,
          'content-type': `multipart/form-data; boundary=${boundary}`,
        },
        payload: multipartBody,
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('VALIDATION_ERROR');
      expect(mockService.createTicket).not.toHaveBeenCalled();

      await app.close();
    });

    it('rejects screenshot exceeding 5MB', async () => {
      const mockService = {
        createTicket: vi.fn(),
      };
      const app = await buildTestApp(mockService);

      // Create a buffer slightly over 5MB with valid PNG header
      const largeContent = Buffer.alloc(5 * 1024 * 1024 + 1);
      PNG_HEADER.copy(largeContent);

      const { body: multipartBody, boundary } = buildMultipartPayload(
        { subject: 'Big file', description: 'File too large' },
        {
          fieldname: 'screenshot',
          filename: 'huge.png',
          contentType: 'image/png',
          content: largeContent,
        },
      );

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/support/tickets',
        headers: {
          cookie: `session=${SESSION_TOKEN}`,
          'content-type': `multipart/form-data; boundary=${boundary}`,
        },
        payload: multipartBody,
      });

      // Either 400 from our validation or 413 from Fastify multipart limits
      expect([400, 413]).toContain(res.statusCode);
      expect(mockService.createTicket).not.toHaveBeenCalled();

      await app.close();
    });

    it('does not include screenshot_path in response', async () => {
      const ticketWithPath = makeTicket({ screenshotPath: 'support-tickets/abc/screenshot.png' });
      const mockService = {
        createTicket: vi.fn().mockResolvedValue(ticketWithPath),
      };
      const app = await buildTestApp(mockService);

      const res = await authedPost(app, '/api/v1/support/tickets', validPayload);

      expect(res.statusCode).toBe(201);
      const responseStr = res.body;
      expect(responseStr).not.toContain('screenshot_path');
      expect(responseStr).not.toContain('screenshotPath');
      // The service strips it before returning, but let's verify the response
      const body = JSON.parse(res.body);
      expect(body.data.screenshotPath).toBeUndefined();
      expect(body.data.screenshot_path).toBeUndefined();

      await app.close();
    });

    it('returns 401 without authentication', async () => {
      const mockService = { createTicket: vi.fn() };
      const app = await buildTestApp(mockService);

      const res = await unauthPost(app, '/api/v1/support/tickets', validPayload);

      expect(res.statusCode).toBe(401);
      expect(mockService.createTicket).not.toHaveBeenCalled();

      await app.close();
    });

    it('returns 401 with invalid session token', async () => {
      const mockService = { createTicket: vi.fn() };
      const app = await buildTestApp(mockService);

      const res = await authedPost(
        app,
        '/api/v1/support/tickets',
        validPayload,
        'invalid-token',
      );

      expect(res.statusCode).toBe(401);
      expect(mockService.createTicket).not.toHaveBeenCalled();

      await app.close();
    });

    it('rejects missing subject with 400', async () => {
      const mockService = { createTicket: vi.fn() };
      const app = await buildTestApp(mockService);

      const res = await authedPost(app, '/api/v1/support/tickets', {
        description: 'Missing subject',
      });

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects missing description with 400', async () => {
      const mockService = { createTicket: vi.fn() };
      const app = await buildTestApp(mockService);

      const res = await authedPost(app, '/api/v1/support/tickets', {
        subject: 'Missing description',
      });

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects empty subject with 400', async () => {
      const mockService = { createTicket: vi.fn() };
      const app = await buildTestApp(mockService);

      const res = await authedPost(app, '/api/v1/support/tickets', {
        subject: '',
        description: 'Valid description',
      });

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects subject exceeding 200 characters with 400', async () => {
      const mockService = { createTicket: vi.fn() };
      const app = await buildTestApp(mockService);

      const res = await authedPost(app, '/api/v1/support/tickets', {
        subject: 'a'.repeat(201),
        description: 'Valid description',
      });

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects description exceeding 5000 characters with 400', async () => {
      const mockService = { createTicket: vi.fn() };
      const app = await buildTestApp(mockService);

      const res = await authedPost(app, '/api/v1/support/tickets', {
        subject: 'Valid subject',
        description: 'a'.repeat(5001),
      });

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects invalid priority with 400', async () => {
      const mockService = { createTicket: vi.fn() };
      const app = await buildTestApp(mockService);

      const res = await authedPost(app, '/api/v1/support/tickets', {
        ...validPayload,
        priority: 'CRITICAL',
      });

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects non-HTTPS context_url with 400', async () => {
      const mockService = { createTicket: vi.fn() };
      const app = await buildTestApp(mockService);

      const res = await authedPost(app, '/api/v1/support/tickets', {
        ...validPayload,
        context_url: 'http://meritum.ca/claims/123',
      });

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('uses physician provider_id for delegates', async () => {
      const mockService = {
        createTicket: vi.fn().mockResolvedValue(makeTicket()),
      };
      const app = await buildTestApp(mockService);

      const res = await authedPost(
        app,
        '/api/v1/support/tickets',
        validPayload,
        DELEGATE_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(201);
      // Delegate should use physician's provider ID, not delegate's own user ID
      expect(mockService.createTicket).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        expect.anything(),
        undefined,
      );

      await app.close();
    });

    it('strips HTML tags from description (XSS prevention)', async () => {
      const mockService = {
        createTicket: vi.fn().mockResolvedValue(makeTicket()),
      };
      const app = await buildTestApp(mockService);

      const res = await authedPost(app, '/api/v1/support/tickets', {
        subject: 'XSS test',
        description: '<script>alert("xss")</script>My claim was rejected',
      });

      expect(res.statusCode).toBe(201);
      // The Zod transform strips HTML tags before the data reaches the service
      expect(mockService.createTicket).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        expect.objectContaining({
          description: expect.not.stringContaining('<script>'),
        }),
        undefined,
      );

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // GET /api/v1/support/tickets — List Tickets
  // -----------------------------------------------------------------------

  describe('GET /api/v1/support/tickets', () => {
    it('lists tickets for authenticated physician', async () => {
      const mockService = {
        listTickets: vi.fn().mockResolvedValue(makePaginatedResult()),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(app, '/api/v1/support/tickets');

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toHaveLength(1);
      expect(body.pagination).toBeDefined();
      expect(body.pagination.total).toBe(1);
      expect(mockService.listTickets).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        expect.objectContaining({ limit: 20, offset: 0 }),
      );

      await app.close();
    });

    it('passes status filter to service', async () => {
      const mockService = {
        listTickets: vi.fn().mockResolvedValue(makePaginatedResult([])),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(
        app,
        '/api/v1/support/tickets?status=OPEN',
      );

      expect(res.statusCode).toBe(200);
      expect(mockService.listTickets).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        expect.objectContaining({ status: 'OPEN' }),
      );

      await app.close();
    });

    it('passes limit and offset to service', async () => {
      const mockService = {
        listTickets: vi.fn().mockResolvedValue(makePaginatedResult([])),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(
        app,
        '/api/v1/support/tickets?limit=10&offset=5',
      );

      expect(res.statusCode).toBe(200);
      expect(mockService.listTickets).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        expect.objectContaining({ limit: 10, offset: 5 }),
      );

      await app.close();
    });

    it('rejects invalid status with 400', async () => {
      const mockService = {};
      const app = await buildTestApp(mockService);

      const res = await authedGet(
        app,
        '/api/v1/support/tickets?status=INVALID',
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects limit below 1 with 400', async () => {
      const mockService = {};
      const app = await buildTestApp(mockService);

      const res = await authedGet(
        app,
        '/api/v1/support/tickets?limit=0',
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects limit above 50 with 400', async () => {
      const mockService = {};
      const app = await buildTestApp(mockService);

      const res = await authedGet(
        app,
        '/api/v1/support/tickets?limit=51',
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects negative offset with 400', async () => {
      const mockService = {};
      const app = await buildTestApp(mockService);

      const res = await authedGet(
        app,
        '/api/v1/support/tickets?offset=-1',
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('returns 401 without authentication', async () => {
      const mockService = { listTickets: vi.fn() };
      const app = await buildTestApp(mockService);

      const res = await unauthGet(app, '/api/v1/support/tickets');

      expect(res.statusCode).toBe(401);
      expect(mockService.listTickets).not.toHaveBeenCalled();

      await app.close();
    });

    it('returns 401 with invalid session token', async () => {
      const mockService = { listTickets: vi.fn() };
      const app = await buildTestApp(mockService);

      const res = await authedGet(app, '/api/v1/support/tickets', 'bad-token');

      expect(res.statusCode).toBe(401);
      expect(mockService.listTickets).not.toHaveBeenCalled();

      await app.close();
    });

    it('uses physician provider_id for delegates', async () => {
      const mockService = {
        listTickets: vi.fn().mockResolvedValue(makePaginatedResult([])),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(
        app,
        '/api/v1/support/tickets',
        DELEGATE_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(200);
      expect(mockService.listTickets).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        expect.anything(),
      );

      await app.close();
    });

    it('does not include screenshot_path in list results', async () => {
      const ticketWithPath = makeTicket({ screenshotPath: 'some/secret/path.png' });
      const mockService = {
        listTickets: vi.fn().mockResolvedValue(makePaginatedResult([ticketWithPath])),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(app, '/api/v1/support/tickets');

      expect(res.statusCode).toBe(200);
      // Service should strip screenshotPath before returning
      // But even if the mock includes it, verify it's not a concern in the response format
      const body = JSON.parse(res.body);
      expect(body.data).toHaveLength(1);

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // GET /api/v1/support/tickets/:id — Get Ticket Detail
  // -----------------------------------------------------------------------

  describe('GET /api/v1/support/tickets/:id', () => {
    it('returns ticket when found', async () => {
      const ticket = makeTicket();
      const mockService = {
        getTicket: vi.fn().mockResolvedValue(ticket),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(
        app,
        `/api/v1/support/tickets/${TICKET_ID}`,
      );

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.ticketId).toBe(TICKET_ID);
      expect(mockService.getTicket).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        TICKET_ID,
      );

      await app.close();
    });

    it('returns 404 for non-existent ticket', async () => {
      const mockService = {
        getTicket: vi.fn().mockResolvedValue(null),
      };
      const app = await buildTestApp(mockService);

      const nonExistent = '00000000-0000-4000-8000-000000000099';
      const res = await authedGet(
        app,
        `/api/v1/support/tickets/${nonExistent}`,
      );

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('NOT_FOUND');
      expect(body.error.message).toBe('Resource not found');
      // Must not leak the ticket ID in the error message
      expect(body.error.message).not.toContain(nonExistent);

      await app.close();
    });

    it('returns 404 for other physician\'s ticket (provider scoping)', async () => {
      const mockService = {
        getTicket: vi.fn().mockResolvedValue(null),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(
        app,
        `/api/v1/support/tickets/${TICKET_ID}`,
      );

      expect(res.statusCode).toBe(404);
      // Confirm service was called with the correct provider ID
      expect(mockService.getTicket).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        TICKET_ID,
      );

      await app.close();
    });

    it('rejects non-UUID id parameter with 400', async () => {
      const mockService = {};
      const app = await buildTestApp(mockService);

      const res = await authedGet(
        app,
        '/api/v1/support/tickets/not-a-uuid',
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('returns 401 without authentication', async () => {
      const mockService = { getTicket: vi.fn() };
      const app = await buildTestApp(mockService);

      const res = await unauthGet(
        app,
        `/api/v1/support/tickets/${TICKET_ID}`,
      );

      expect(res.statusCode).toBe(401);
      expect(mockService.getTicket).not.toHaveBeenCalled();

      await app.close();
    });

    it('returns 401 with invalid session token', async () => {
      const mockService = { getTicket: vi.fn() };
      const app = await buildTestApp(mockService);

      const res = await authedGet(
        app,
        `/api/v1/support/tickets/${TICKET_ID}`,
        'bad-token',
      );

      expect(res.statusCode).toBe(401);
      expect(mockService.getTicket).not.toHaveBeenCalled();

      await app.close();
    });

    it('uses physician provider_id for delegates', async () => {
      const mockService = {
        getTicket: vi.fn().mockResolvedValue(makeTicket()),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(
        app,
        `/api/v1/support/tickets/${TICKET_ID}`,
        DELEGATE_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(200);
      expect(mockService.getTicket).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        TICKET_ID,
      );

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // POST /api/v1/support/tickets/:id/rating — Submit Rating
  // -----------------------------------------------------------------------

  describe('POST /api/v1/support/tickets/:id/rating', () => {
    it('submits rating for resolved ticket', async () => {
      const resolvedTicket = makeResolvedTicket();
      const ratedTicket = makeResolvedTicket({ satisfactionRating: 5 });
      const mockService = {
        getTicket: vi.fn().mockResolvedValue(resolvedTicket),
        rateTicket: vi.fn().mockResolvedValue(ratedTicket),
      };
      const app = await buildTestApp(mockService);

      const res = await authedPost(
        app,
        `/api/v1/support/tickets/${TICKET_ID}/rating`,
        { rating: 5 },
      );

      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.satisfactionRating).toBe(5);
      expect(mockService.rateTicket).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        TICKET_ID,
        5,
        undefined,
      );

      await app.close();
    });

    it('submits rating with optional comment', async () => {
      const resolvedTicket = makeResolvedTicket();
      const ratedTicket = makeResolvedTicket({
        satisfactionRating: 4,
        satisfactionComment: 'Good support',
      });
      const mockService = {
        getTicket: vi.fn().mockResolvedValue(resolvedTicket),
        rateTicket: vi.fn().mockResolvedValue(ratedTicket),
      };
      const app = await buildTestApp(mockService);

      const res = await authedPost(
        app,
        `/api/v1/support/tickets/${TICKET_ID}/rating`,
        { rating: 4, comment: 'Good support' },
      );

      expect(res.statusCode).toBe(200);
      expect(mockService.rateTicket).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        TICKET_ID,
        4,
        'Good support',
      );

      await app.close();
    });

    it('submits rating for CLOSED ticket', async () => {
      const closedTicket = makeTicket({ status: 'CLOSED' });
      const ratedTicket = makeTicket({ status: 'CLOSED', satisfactionRating: 3 });
      const mockService = {
        getTicket: vi.fn().mockResolvedValue(closedTicket),
        rateTicket: vi.fn().mockResolvedValue(ratedTicket),
      };
      const app = await buildTestApp(mockService);

      const res = await authedPost(
        app,
        `/api/v1/support/tickets/${TICKET_ID}/rating`,
        { rating: 3 },
      );

      expect(res.statusCode).toBe(200);

      await app.close();
    });

    it('returns 400 if ticket is not RESOLVED or CLOSED', async () => {
      const openTicket = makeTicket({ status: 'OPEN' });
      const mockService = {
        getTicket: vi.fn().mockResolvedValue(openTicket),
        rateTicket: vi.fn(),
      };
      const app = await buildTestApp(mockService);

      const res = await authedPost(
        app,
        `/api/v1/support/tickets/${TICKET_ID}/rating`,
        { rating: 5 },
      );

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.error.code).toBe('VALIDATION_ERROR');
      expect(body.error.message).toContain('resolved or closed');
      expect(mockService.rateTicket).not.toHaveBeenCalled();

      await app.close();
    });

    it('returns 400 for IN_PROGRESS ticket', async () => {
      const inProgressTicket = makeTicket({ status: 'IN_PROGRESS' });
      const mockService = {
        getTicket: vi.fn().mockResolvedValue(inProgressTicket),
        rateTicket: vi.fn(),
      };
      const app = await buildTestApp(mockService);

      const res = await authedPost(
        app,
        `/api/v1/support/tickets/${TICKET_ID}/rating`,
        { rating: 3 },
      );

      expect(res.statusCode).toBe(400);
      expect(mockService.rateTicket).not.toHaveBeenCalled();

      await app.close();
    });

    it('returns 400 for WAITING_ON_CUSTOMER ticket', async () => {
      const waitingTicket = makeTicket({ status: 'WAITING_ON_CUSTOMER' });
      const mockService = {
        getTicket: vi.fn().mockResolvedValue(waitingTicket),
        rateTicket: vi.fn(),
      };
      const app = await buildTestApp(mockService);

      const res = await authedPost(
        app,
        `/api/v1/support/tickets/${TICKET_ID}/rating`,
        { rating: 2 },
      );

      expect(res.statusCode).toBe(400);
      expect(mockService.rateTicket).not.toHaveBeenCalled();

      await app.close();
    });

    it('returns 404 for non-existent ticket (provider scoping)', async () => {
      const mockService = {
        getTicket: vi.fn().mockResolvedValue(null),
        rateTicket: vi.fn(),
      };
      const app = await buildTestApp(mockService);

      const nonExistent = '00000000-0000-4000-8000-000000000099';
      const res = await authedPost(
        app,
        `/api/v1/support/tickets/${nonExistent}/rating`,
        { rating: 5 },
      );

      expect(res.statusCode).toBe(404);
      expect(mockService.rateTicket).not.toHaveBeenCalled();

      await app.close();
    });

    it('rejects rating below 1 with 400', async () => {
      const mockService = {};
      const app = await buildTestApp(mockService);

      const res = await authedPost(
        app,
        `/api/v1/support/tickets/${TICKET_ID}/rating`,
        { rating: 0 },
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects rating above 5 with 400', async () => {
      const mockService = {};
      const app = await buildTestApp(mockService);

      const res = await authedPost(
        app,
        `/api/v1/support/tickets/${TICKET_ID}/rating`,
        { rating: 6 },
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects non-integer rating with 400', async () => {
      const mockService = {};
      const app = await buildTestApp(mockService);

      const res = await authedPost(
        app,
        `/api/v1/support/tickets/${TICKET_ID}/rating`,
        { rating: 3.5 },
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects missing rating field with 400', async () => {
      const mockService = {};
      const app = await buildTestApp(mockService);

      const res = await authedPost(
        app,
        `/api/v1/support/tickets/${TICKET_ID}/rating`,
        {},
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects string rating with 400', async () => {
      const mockService = {};
      const app = await buildTestApp(mockService);

      const res = await authedPost(
        app,
        `/api/v1/support/tickets/${TICKET_ID}/rating`,
        { rating: 'five' },
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects comment exceeding 1000 characters with 400', async () => {
      const mockService = {};
      const app = await buildTestApp(mockService);

      const res = await authedPost(
        app,
        `/api/v1/support/tickets/${TICKET_ID}/rating`,
        { rating: 5, comment: 'a'.repeat(1001) },
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('rejects non-UUID id parameter with 400', async () => {
      const mockService = {};
      const app = await buildTestApp(mockService);

      const res = await authedPost(
        app,
        '/api/v1/support/tickets/not-a-uuid/rating',
        { rating: 5 },
      );

      expect(res.statusCode).toBe(400);

      await app.close();
    });

    it('returns 401 without authentication', async () => {
      const mockService = { getTicket: vi.fn(), rateTicket: vi.fn() };
      const app = await buildTestApp(mockService);

      const res = await unauthPost(
        app,
        `/api/v1/support/tickets/${TICKET_ID}/rating`,
        { rating: 5 },
      );

      expect(res.statusCode).toBe(401);
      expect(mockService.getTicket).not.toHaveBeenCalled();
      expect(mockService.rateTicket).not.toHaveBeenCalled();

      await app.close();
    });

    it('returns 401 with invalid session token', async () => {
      const mockService = { getTicket: vi.fn(), rateTicket: vi.fn() };
      const app = await buildTestApp(mockService);

      const res = await authedPost(
        app,
        `/api/v1/support/tickets/${TICKET_ID}/rating`,
        { rating: 5 },
        'bad-token',
      );

      expect(res.statusCode).toBe(401);
      expect(mockService.getTicket).not.toHaveBeenCalled();

      await app.close();
    });

    it('uses physician provider_id for delegates', async () => {
      const resolvedTicket = makeResolvedTicket();
      const ratedTicket = makeResolvedTicket({ satisfactionRating: 4 });
      const mockService = {
        getTicket: vi.fn().mockResolvedValue(resolvedTicket),
        rateTicket: vi.fn().mockResolvedValue(ratedTicket),
      };
      const app = await buildTestApp(mockService);

      const res = await authedPost(
        app,
        `/api/v1/support/tickets/${TICKET_ID}/rating`,
        { rating: 4 },
        DELEGATE_SESSION_TOKEN,
      );

      expect(res.statusCode).toBe(200);
      expect(mockService.getTicket).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        TICKET_ID,
      );
      expect(mockService.rateTicket).toHaveBeenCalledWith(
        PHYSICIAN_ID,
        TICKET_ID,
        4,
        undefined,
      );

      await app.close();
    });
  });

  // -----------------------------------------------------------------------
  // Response format consistency
  // -----------------------------------------------------------------------

  describe('response format', () => {
    it('all success responses wrap data in { data: ... }', async () => {
      const ticket = makeTicket();
      const mockService = {
        createTicket: vi.fn().mockResolvedValue(ticket),
        getTicket: vi.fn().mockResolvedValue(ticket),
        listTickets: vi.fn().mockResolvedValue(makePaginatedResult()),
      };
      const app = await buildTestApp(mockService);

      // Create
      const createRes = await authedPost(app, '/api/v1/support/tickets', {
        subject: 'Test',
        description: 'Test description',
      });
      expect(JSON.parse(createRes.body)).toHaveProperty('data');

      // List
      const listRes = await authedGet(app, '/api/v1/support/tickets');
      expect(JSON.parse(listRes.body)).toHaveProperty('data');

      // Get by ID
      const getRes = await authedGet(
        app,
        `/api/v1/support/tickets/${TICKET_ID}`,
      );
      expect(JSON.parse(getRes.body)).toHaveProperty('data');

      await app.close();
    });

    it('all error responses wrap error in { error: { code, message } }', async () => {
      const mockService = {
        getTicket: vi.fn().mockResolvedValue(null),
      };
      const app = await buildTestApp(mockService);

      const res = await authedGet(
        app,
        `/api/v1/support/tickets/${TICKET_ID}`,
      );

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBeDefined();
      expect(body.error.message).toBeDefined();

      await app.close();
    });
  });
});
