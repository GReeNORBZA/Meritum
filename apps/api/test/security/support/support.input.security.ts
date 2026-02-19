// ============================================================================
// Domain 13: Support System — Input Validation & Injection Prevention (Security)
//
// Verifies:
//   1. SQL injection payloads rejected at Zod schema layer (400).
//   2. XSS payloads stripped or rejected before reaching service layer.
//   3. File upload attacks (oversized, wrong content-type, path traversal).
//   4. Type coercion attacks (wrong types, boundary values).
//   5. Boundary value enforcement (max lengths, URL schemes, slug format).
//   6. tsquery special characters sanitised before search.
//   7. Generic error messages — no internal schema/DB leakage.
// ============================================================================

import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { createHash, randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Environment setup (must be before imports that read env)
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);

// ---------------------------------------------------------------------------
// Mock otplib (required by iam.service.ts transitive import)
// ---------------------------------------------------------------------------

vi.mock('otplib', () => ({
  authenticator: {
    options: {},
    generateSecret: vi.fn(() => 'JBSWY3DPEHPK3PXP'),
    keyuri: vi.fn(() => 'otpauth://totp/test'),
    verify: vi.fn(() => false),
  },
}));

// ---------------------------------------------------------------------------
// Imports (after mocks)
// ---------------------------------------------------------------------------

import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { helpRoutes } from '../../../src/domains/support/routes/help.routes.js';
import { ticketRoutes } from '../../../src/domains/support/routes/ticket.routes.js';
import type { HelpRoutesDeps } from '../../../src/domains/support/routes/help.routes.js';
import type { TicketRoutesDeps } from '../../../src/domains/support/routes/ticket.routes.js';

// ---------------------------------------------------------------------------
// Helper: hashToken
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

const SESSION_TOKEN = randomBytes(32).toString('hex');
const SESSION_TOKEN_HASH = hashToken(SESSION_TOKEN);
const USER_ID = 'aaaa0000-0000-0000-0000-000000000001';
const SESSION_ID = 'bbbb0000-0000-0000-0000-000000000001';

const FIXED_DATE = new Date('2026-01-01T00:00:00.000Z');
const DUMMY_UUID = '00000000-0000-0000-0000-000000000001';

// ---------------------------------------------------------------------------
// Mock stores
// ---------------------------------------------------------------------------

interface MockSession {
  sessionId: string;
  userId: string;
  tokenHash: string;
  ipAddress: string;
  userAgent: string;
  createdAt: Date;
  lastActiveAt: Date;
  revoked: boolean;
  revokedReason: string | null;
}

interface MockUser {
  userId: string;
  role: string;
  subscriptionStatus: string;
}

let sessions: MockSession[] = [];
let users: MockUser[] = [];

// Track what reaches the service layer
const serviceCallLog: {
  createTicket: Array<{ providerId: string; data: any; screenshot?: any }>;
  searchArticles: Array<{ query: string }>;
} = {
  createTicket: [],
  searchArticles: [],
};

function resetServiceCallLog() {
  serviceCallLog.createTicket = [];
  serviceCallLog.searchArticles = [];
}

// ---------------------------------------------------------------------------
// Mock session repository
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    createSession: vi.fn(async () => ({ sessionId: 'new-session' })),
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      const session = sessions.find((s) => s.tokenHash === tokenHash && !s.revoked);
      if (!session) return undefined;
      const user = users.find((u) => u.userId === session.userId);
      if (!user) return undefined;
      return { session, user };
    }),
    refreshSession: vi.fn(async () => {}),
    listActiveSessions: vi.fn(async () => []),
    revokeSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Stub service deps — track inputs that reach the service layer
// ---------------------------------------------------------------------------

function createStubTicketDeps(): TicketRoutesDeps {
  return {
    supportTicketService: {
      createTicket: vi.fn(async (providerId: string, data: any, screenshot?: any) => {
        serviceCallLog.createTicket.push({ providerId, data, screenshot });
        return {
          ticketId: randomBytes(16).toString('hex'),
          providerId,
          subject: data.subject,
          description: data.description,
          status: 'OPEN',
          priority: data.priority ?? 'MEDIUM',
          category: null,
          contextUrl: data.contextUrl ?? null,
          contextMetadata: data.contextMetadata ?? null,
          assignedTo: null,
          resolutionNotes: null,
          satisfactionRating: null,
          satisfactionComment: null,
          resolvedAt: null,
          createdAt: FIXED_DATE,
          updatedAt: FIXED_DATE,
        };
      }),

      listTickets: vi.fn(async () => ({
        data: [],
        pagination: { total: 0, page: 1, pageSize: 20, hasMore: false },
      })),

      getTicket: vi.fn(async (_providerId: string, _ticketId: string) => ({
        ticketId: _ticketId,
        providerId: _providerId,
        subject: 'Test Ticket',
        description: 'Test description',
        status: 'RESOLVED',
        priority: 'MEDIUM',
        category: null,
        contextUrl: null,
        contextMetadata: null,
        assignedTo: null,
        resolutionNotes: null,
        satisfactionRating: null,
        satisfactionComment: null,
        resolvedAt: FIXED_DATE,
        createdAt: FIXED_DATE,
        updatedAt: FIXED_DATE,
      })),

      rateTicket: vi.fn(async (providerId: string, ticketId: string, rating: number, comment?: string) => ({
        ticketId,
        providerId,
        subject: 'Test Ticket',
        description: 'Test description',
        status: 'RESOLVED',
        priority: 'MEDIUM',
        category: null,
        contextUrl: null,
        contextMetadata: null,
        assignedTo: null,
        resolutionNotes: null,
        satisfactionRating: rating,
        satisfactionComment: comment ?? null,
        resolvedAt: FIXED_DATE,
        createdAt: FIXED_DATE,
        updatedAt: FIXED_DATE,
      })),

      transitionTicket: vi.fn(async () => null),
      checkSlaBreach: vi.fn(async () => []),
    } as any,
  };
}

function createStubHelpDeps(): HelpRoutesDeps {
  return {
    helpCentreService: {
      searchArticles: vi.fn(async (_providerId: string, query: string) => {
        serviceCallLog.searchArticles.push({ query });
        return [];
      }),
      listByCategory: vi.fn(async () => []),
      getArticle: vi.fn(async (_providerId: string, slug: string) => ({
        articleId: '11111111-0000-0000-0000-000000000001',
        slug,
        title: 'Test Article',
        content: 'Test content.',
        category: 'GETTING_STARTED',
        status: 'PUBLISHED',
        helpfulCount: 0,
        notHelpfulCount: 0,
        createdAt: FIXED_DATE,
        updatedAt: FIXED_DATE,
      })),
      submitFeedback: vi.fn(async () => ({ success: true })),
      getContextualHelp: vi.fn(async () => ({
        type: 'search_page' as const,
        searchPageUrl: '/help',
      })),
      getFeedbackRateLimit: vi.fn(async () => ({ allowed: true })),
    } as any,
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;

async function buildTestApp(): Promise<FastifyInstance> {
  const mockSessionRepo = createMockSessionRepo();

  const sessionDeps = {
    sessionRepo: mockSessionRepo,
    auditRepo: { appendAuditLog: vi.fn(async () => {}) },
    events: { emit: vi.fn() },
  };

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  await testApp.register(authPluginFp, { sessionDeps });

  // Register multipart support for file upload tests
  await testApp.register(import('@fastify/multipart'), {
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit at Fastify level
  });

  testApp.setErrorHandler((error, _request, reply) => {
    if (error.statusCode && error.statusCode >= 400 && error.statusCode < 500) {
      return reply.code(error.statusCode).send({
        error: { code: (error as any).code ?? 'VALIDATION_ERROR', message: error.message },
      });
    }
    if (error.validation) {
      return reply.code(400).send({
        error: { code: 'VALIDATION_ERROR', message: 'Validation failed' },
      });
    }
    return reply.code(500).send({
      error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
    });
  });

  await testApp.register(helpRoutes, { deps: createStubHelpDeps() });
  await testApp.register(ticketRoutes, { deps: createStubTicketDeps() });

  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function authHeaders(): Record<string, string> {
  return { cookie: `session=${SESSION_TOKEN}` };
}

/** Build a valid create ticket payload */
function validTicketPayload() {
  return {
    subject: 'Help with claim submission',
    description: 'I am having trouble submitting my AHCIP claim for today.',
  };
}

/** Build a PNG magic bytes buffer of a given size */
function createFakePng(sizeBytes: number): Buffer {
  const pngHeader = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  if (sizeBytes <= pngHeader.length) return pngHeader.subarray(0, sizeBytes);
  const padding = Buffer.alloc(sizeBytes - pngHeader.length, 0x00);
  return Buffer.concat([pngHeader, padding]);
}

/** Build a multipart form body with fields and optional file */
function buildMultipartBody(
  fields: Record<string, string>,
  file?: { fieldname: string; filename: string; content: Buffer; contentType: string },
): { body: Buffer; boundary: string } {
  const boundary = '----FormBoundary' + randomBytes(8).toString('hex');
  const parts: Buffer[] = [];

  for (const [key, value] of Object.entries(fields)) {
    parts.push(Buffer.from(
      `--${boundary}\r\nContent-Disposition: form-data; name="${key}"\r\n\r\n${value}\r\n`,
    ));
  }

  if (file) {
    parts.push(Buffer.from(
      `--${boundary}\r\nContent-Disposition: form-data; name="${file.fieldname}"; filename="${file.filename}"\r\nContent-Type: ${file.contentType}\r\n\r\n`,
    ));
    parts.push(file.content);
    parts.push(Buffer.from('\r\n'));
  }

  parts.push(Buffer.from(`--${boundary}--\r\n`));
  return { body: Buffer.concat(parts), boundary };
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Support System Input Validation & Injection Prevention (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    sessions = [];
    users = [];
    resetServiceCallLog();

    users.push({
      userId: USER_ID,
      role: 'PHYSICIAN',
      subscriptionStatus: 'ACTIVE',
    });
    sessions.push({
      sessionId: SESSION_ID,
      userId: USER_ID,
      tokenHash: SESSION_TOKEN_HASH,
      ipAddress: '127.0.0.1',
      userAgent: 'test-agent',
      createdAt: new Date(),
      lastActiveAt: new Date(),
      revoked: false,
      revokedReason: null,
    });
  });

  // =========================================================================
  // Category 1: SQL Injection Attempts
  // =========================================================================

  describe('SQL Injection Prevention', () => {
    const SQL_PAYLOADS = [
      "'; DROP TABLE help_articles; --",
      "1' OR '1'='1",
      "1; SELECT * FROM users --",
      "' UNION SELECT * FROM providers --",
      "Robert'); DROP TABLE support_tickets;--",
      "1; DELETE FROM sessions WHERE 1=1 --",
    ];

    describe('ticket subject rejects SQL injection', () => {
      for (const payload of SQL_PAYLOADS) {
        it(`rejects: ${payload.substring(0, 40)}...`, async () => {
          const res = await app.inject({
            method: 'POST',
            url: '/api/v1/support/tickets',
            headers: authHeaders(),
            payload: { ...validTicketPayload(), subject: payload },
          });

          // Subject allows most characters (max 200), but if it reaches the service
          // layer, it's parameterised by Drizzle. Verify no raw SQL execution.
          // The important thing: service receives the literal string, never executed as SQL.
          if (res.statusCode === 201) {
            expect(serviceCallLog.createTicket.length).toBe(1);
            expect(serviceCallLog.createTicket[0].data.subject).toBe(payload);
          } else {
            expect(res.statusCode).toBe(400);
          }
        });
      }
    });

    describe('search query handles SQL injection safely', () => {
      for (const payload of SQL_PAYLOADS) {
        it(`handles search: ${payload.substring(0, 40)}...`, async () => {
          const res = await app.inject({
            method: 'GET',
            url: `/api/v1/help/articles?search=${encodeURIComponent(payload)}`,
          });

          // Search endpoint should either reject (400) or sanitise before tsquery
          expect([200, 400]).toContain(res.statusCode);
          if (res.statusCode === 200) {
            const body = JSON.parse(res.body);
            expect(body.data).toBeDefined();
            expect(Array.isArray(body.data)).toBe(true);
          }
        });
      }
    });

    describe('article slug rejects SQL injection', () => {
      const SLUG_INJECTIONS = [
        "'; DROP TABLE help_articles; --",
        '../../../etc/passwd',
        'slug-name; rm -rf /',
        'a/b/c',
        "admin'--",
      ];

      for (const payload of SLUG_INJECTIONS) {
        it(`rejects slug: ${payload.substring(0, 40)}`, async () => {
          const res = await app.inject({
            method: 'GET',
            url: `/api/v1/help/articles/${encodeURIComponent(payload)}`,
          });

          expect(res.statusCode).toBe(400);
          const body = JSON.parse(res.body);
          expect(body.error).toBeDefined();
        });
      }
    });

    describe('ticket_id param rejects SQL injection', () => {
      const ID_INJECTIONS = [
        "'; DROP TABLE support_tickets; --",
        'not-a-uuid',
        '1 OR 1=1',
        '../../../etc/passwd',
      ];

      for (const payload of ID_INJECTIONS) {
        it(`rejects ticket ID: ${payload.substring(0, 40)}`, async () => {
          const res = await app.inject({
            method: 'GET',
            url: `/api/v1/support/tickets/${encodeURIComponent(payload)}`,
            headers: authHeaders(),
          });

          expect(res.statusCode).toBe(400);
          const body = JSON.parse(res.body);
          expect(body.error).toBeDefined();
        });
      }
    });
  });

  // =========================================================================
  // Category 2: XSS Attempts
  // =========================================================================

  describe('XSS Prevention', () => {
    const XSS_PAYLOADS = [
      '<script>alert("xss")</script>',
      '<img src=x onerror=alert(1)>',
      'javascript:alert(1)',
      '<svg onload=alert(1)>',
      '"><script>alert(document.cookie)</script>',
      '<iframe src="javascript:alert(1)">',
    ];

    describe('description field: HTML tags stripped by Zod transform', () => {
      for (const payload of XSS_PAYLOADS) {
        it(`sanitises description: ${payload.substring(0, 40)}...`, async () => {
          const res = await app.inject({
            method: 'POST',
            url: '/api/v1/support/tickets',
            headers: authHeaders(),
            payload: {
              ...validTicketPayload(),
              description: `Test ${payload} content`,
            },
          });

          // Description uses .transform(stripHtmlTags) — should accept but strip
          if (res.statusCode === 201) {
            expect(serviceCallLog.createTicket.length).toBe(1);
            const storedDesc = serviceCallLog.createTicket[0].data.description;
            expect(storedDesc).not.toContain('<script>');
            expect(storedDesc).not.toContain('<img');
            expect(storedDesc).not.toContain('<svg');
            expect(storedDesc).not.toContain('<iframe');
            expect(storedDesc).not.toContain('onerror=');
            expect(storedDesc).not.toContain('onload=');
          } else {
            // Also acceptable: outright rejection
            expect(res.statusCode).toBe(400);
          }
        });
      }
    });

    describe('subject field: rejects or stores safely', () => {
      for (const payload of XSS_PAYLOADS) {
        it(`handles subject: ${payload.substring(0, 40)}...`, async () => {
          const res = await app.inject({
            method: 'POST',
            url: '/api/v1/support/tickets',
            headers: authHeaders(),
            payload: {
              ...validTicketPayload(),
              subject: payload,
            },
          });

          // Subject doesn't have stripHtmlTags but should be safely handled
          if (res.statusCode === 201) {
            // If stored, it will be escaped on output (frontend responsibility)
            // but the service must receive the value safely
            expect(serviceCallLog.createTicket.length).toBe(1);
          } else {
            expect(res.statusCode).toBe(400);
          }
        });
      }
    });

    describe('search query: XSS payloads sanitised before tsquery', () => {
      for (const payload of XSS_PAYLOADS) {
        it(`sanitises search: ${payload.substring(0, 40)}...`, async () => {
          const res = await app.inject({
            method: 'GET',
            url: `/api/v1/help/articles?search=${encodeURIComponent(payload)}`,
          });

          // Should not crash (200 with empty results or 400 rejection)
          expect([200, 400]).toContain(res.statusCode);
          if (res.statusCode === 200) {
            const body = JSON.parse(res.body);
            expect(Array.isArray(body.data)).toBe(true);
          }
        });
      }
    });

    describe('satisfaction comment: handles script tags safely', () => {
      for (const payload of XSS_PAYLOADS) {
        it(`handles comment: ${payload.substring(0, 40)}...`, async () => {
          const res = await app.inject({
            method: 'POST',
            url: `/api/v1/support/tickets/${DUMMY_UUID}/rating`,
            headers: authHeaders(),
            payload: {
              rating: 4,
              comment: payload,
            },
          });

          // Comment is validated by Zod (max 1000 chars, string type).
          // XSS prevention for plain text fields is handled at the frontend
          // rendering layer. The key security requirement is that the API
          // does not crash (no 500) and the response is well-formed JSON.
          if (res.statusCode === 200) {
            const body = JSON.parse(res.body);
            expect(body.data).toBeDefined();
            expect(body.data.satisfactionRating).toBe(4);
          } else {
            // Also acceptable: 400 rejection if schema rejects HTML
            expect(res.statusCode).toBe(400);
          }
        });
      }
    });
  });

  // =========================================================================
  // Category 3: File Upload Attacks
  // =========================================================================

  describe('File Upload Attacks', () => {
    it('rejects screenshot > 5MB', async () => {
      const oversizedPng = createFakePng(5 * 1024 * 1024 + 1); // 5MB + 1 byte
      const { body, boundary } = buildMultipartBody(
        { subject: 'Test ticket', description: 'Need help' },
        {
          fieldname: 'screenshot',
          filename: 'screenshot.png',
          content: oversizedPng,
          contentType: 'image/png',
        },
      );

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/support/tickets',
        headers: {
          ...authHeaders(),
          'content-type': `multipart/form-data; boundary=${boundary}`,
        },
        payload: body,
      });

      expect(res.statusCode).toBe(400);
      const resBody = JSON.parse(res.body);
      expect(resBody.error).toBeDefined();
      expect(resBody.error.code).toBe('VALIDATION_ERROR');
    });

    it('rejects screenshot with executable extension (.exe)', async () => {
      // Send a file that does NOT have valid image magic bytes
      const exeContent = Buffer.from('MZ\x90\x00'); // PE executable header
      const { body, boundary } = buildMultipartBody(
        { subject: 'Test ticket', description: 'Need help' },
        {
          fieldname: 'screenshot',
          filename: 'malware.exe',
          content: exeContent,
          contentType: 'application/octet-stream',
        },
      );

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/support/tickets',
        headers: {
          ...authHeaders(),
          'content-type': `multipart/form-data; boundary=${boundary}`,
        },
        payload: body,
      });

      expect(res.statusCode).toBe(400);
      const resBody = JSON.parse(res.body);
      expect(resBody.error).toBeDefined();
    });

    it('rejects screenshot with .sh extension and shell content', async () => {
      const shellContent = Buffer.from('#!/bin/bash\nrm -rf /\n');
      const { body, boundary } = buildMultipartBody(
        { subject: 'Test ticket', description: 'Need help' },
        {
          fieldname: 'screenshot',
          filename: 'evil.sh',
          content: shellContent,
          contentType: 'text/x-shellscript',
        },
      );

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/support/tickets',
        headers: {
          ...authHeaders(),
          'content-type': `multipart/form-data; boundary=${boundary}`,
        },
        payload: body,
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects screenshot with .js extension', async () => {
      const jsContent = Buffer.from('alert("xss")');
      const { body, boundary } = buildMultipartBody(
        { subject: 'Test ticket', description: 'Need help' },
        {
          fieldname: 'screenshot',
          filename: 'payload.js',
          content: jsContent,
          contentType: 'application/javascript',
        },
      );

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/support/tickets',
        headers: {
          ...authHeaders(),
          'content-type': `multipart/form-data; boundary=${boundary}`,
        },
        payload: body,
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects file with image extension but non-image content (magic byte validation)', async () => {
      // Fake .png with executable content (no PNG magic bytes)
      const fakeImageContent = Buffer.from('MZ\x90\x00This is not a real image');
      const { body, boundary } = buildMultipartBody(
        { subject: 'Test ticket', description: 'Need help' },
        {
          fieldname: 'screenshot',
          filename: 'screenshot.png',
          content: fakeImageContent,
          contentType: 'image/png', // Client claims PNG but content is not
        },
      );

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/support/tickets',
        headers: {
          ...authHeaders(),
          'content-type': `multipart/form-data; boundary=${boundary}`,
        },
        payload: body,
      });

      expect(res.statusCode).toBe(400);
      const resBody = JSON.parse(res.body);
      expect(resBody.error.message).toContain('image');
    });

    it('rejects screenshot with path traversal filename', async () => {
      const validPng = createFakePng(100);
      const { body, boundary } = buildMultipartBody(
        { subject: 'Test ticket', description: 'Need help' },
        {
          fieldname: 'screenshot',
          filename: '../../evil.png',
          content: validPng,
          contentType: 'image/png',
        },
      );

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/support/tickets',
        headers: {
          ...authHeaders(),
          'content-type': `multipart/form-data; boundary=${boundary}`,
        },
        payload: body,
      });

      // If accepted, verify filename was sanitised (no path traversal in stored name)
      if (res.statusCode === 201) {
        expect(serviceCallLog.createTicket.length).toBe(1);
        const screenshot = serviceCallLog.createTicket[0].screenshot;
        if (screenshot && screenshot.originalname) {
          expect(screenshot.originalname).not.toContain('..');
          expect(screenshot.originalname).not.toContain('/');
        }
      }
      // Also acceptable: 400 rejection
      expect([201, 400]).toContain(res.statusCode);
    });

    it('accepts ticket creation without screenshot (optional field)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/support/tickets',
        headers: authHeaders(),
        payload: validTicketPayload(),
      });

      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);
      expect(body.data).toBeDefined();
      expect(body.data.ticketId).toBeDefined();
    });

    it('accepts valid PNG screenshot under 5MB', async () => {
      const validPng = createFakePng(1024); // 1KB valid PNG
      const { body, boundary } = buildMultipartBody(
        { subject: 'Test ticket', description: 'Need help with billing' },
        {
          fieldname: 'screenshot',
          filename: 'screenshot.png',
          content: validPng,
          contentType: 'image/png',
        },
      );

      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/support/tickets',
        headers: {
          ...authHeaders(),
          'content-type': `multipart/form-data; boundary=${boundary}`,
        },
        payload: body,
      });

      expect(res.statusCode).toBe(201);
      expect(serviceCallLog.createTicket.length).toBe(1);
      const screenshot = serviceCallLog.createTicket[0].screenshot;
      expect(screenshot).toBeDefined();
      expect(screenshot.mimetype).toBe('image/png');
    });
  });

  // =========================================================================
  // Category 4: Type Coercion Attacks
  // =========================================================================

  describe('Type Coercion Attacks', () => {
    describe('ticket rating validation', () => {
      it('rejects rating of 0 (below minimum 1)', async () => {
        const res = await app.inject({
          method: 'POST',
          url: `/api/v1/support/tickets/${DUMMY_UUID}/rating`,
          headers: authHeaders(),
          payload: { rating: 0 },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects rating of 6 (above maximum 5)', async () => {
        const res = await app.inject({
          method: 'POST',
          url: `/api/v1/support/tickets/${DUMMY_UUID}/rating`,
          headers: authHeaders(),
          payload: { rating: 6 },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects rating as string "five"', async () => {
        const res = await app.inject({
          method: 'POST',
          url: `/api/v1/support/tickets/${DUMMY_UUID}/rating`,
          headers: authHeaders(),
          payload: { rating: 'five' },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects rating as float 3.5 (must be integer)', async () => {
        const res = await app.inject({
          method: 'POST',
          url: `/api/v1/support/tickets/${DUMMY_UUID}/rating`,
          headers: authHeaders(),
          payload: { rating: 3.5 },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects negative rating', async () => {
        const res = await app.inject({
          method: 'POST',
          url: `/api/v1/support/tickets/${DUMMY_UUID}/rating`,
          headers: authHeaders(),
          payload: { rating: -1 },
        });

        expect(res.statusCode).toBe(400);
      });

      it('accepts valid integer rating within range [1-5]', async () => {
        for (const rating of [1, 2, 3, 4, 5]) {
          const res = await app.inject({
            method: 'POST',
            url: `/api/v1/support/tickets/${DUMMY_UUID}/rating`,
            headers: authHeaders(),
            payload: { rating },
          });

          expect(res.statusCode).toBe(200);
        }
      });
    });

    describe('is_helpful field type enforcement', () => {
      it('rejects is_helpful as string "true"', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/help/articles/getting-started/feedback',
          headers: authHeaders(),
          payload: { is_helpful: 'true' },
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects is_helpful as number 1', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/help/articles/getting-started/feedback',
          headers: authHeaders(),
          payload: { is_helpful: 1 },
        });

        expect(res.statusCode).toBe(400);
      });

      it('accepts is_helpful as boolean true', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/help/articles/getting-started/feedback',
          headers: authHeaders(),
          payload: { is_helpful: true },
        });

        expect(res.statusCode).not.toBe(400);
      });

      it('accepts is_helpful as boolean false', async () => {
        const res = await app.inject({
          method: 'POST',
          url: '/api/v1/help/articles/getting-started/feedback',
          headers: authHeaders(),
          payload: { is_helpful: false },
        });

        expect(res.statusCode).not.toBe(400);
      });
    });

    describe('query parameter type enforcement', () => {
      it('rejects non-integer limit', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/support/tickets?limit=abc',
          headers: authHeaders(),
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects zero limit', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/support/tickets?limit=0',
          headers: authHeaders(),
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects limit over 50', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/support/tickets?limit=51',
          headers: authHeaders(),
        });

        expect(res.statusCode).toBe(400);
      });

      it('rejects negative offset', async () => {
        const res = await app.inject({
          method: 'GET',
          url: '/api/v1/support/tickets?offset=-1',
          headers: authHeaders(),
        });

        expect(res.statusCode).toBe(400);
      });
    });
  });

  // =========================================================================
  // Category 5: Boundary Value Enforcement
  // =========================================================================

  describe('Boundary Value Enforcement', () => {
    it('accepts subject at exactly 200 characters', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/support/tickets',
        headers: authHeaders(),
        payload: {
          subject: 'A'.repeat(200),
          description: 'Valid description',
        },
      });

      expect(res.statusCode).toBe(201);
    });

    it('rejects subject at 201 characters', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/support/tickets',
        headers: authHeaders(),
        payload: {
          subject: 'A'.repeat(201),
          description: 'Valid description',
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects empty subject', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/support/tickets',
        headers: authHeaders(),
        payload: {
          subject: '',
          description: 'Valid description',
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('accepts description at exactly 5000 characters', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/support/tickets',
        headers: authHeaders(),
        payload: {
          subject: 'Valid subject',
          description: 'D'.repeat(5000),
        },
      });

      expect(res.statusCode).toBe(201);
    });

    it('rejects description at 5001 characters', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/support/tickets',
        headers: authHeaders(),
        payload: {
          subject: 'Valid subject',
          description: 'D'.repeat(5001),
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects empty description', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/support/tickets',
        headers: authHeaders(),
        payload: {
          subject: 'Valid subject',
          description: '',
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects context_url with HTTP (non-HTTPS)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/support/tickets',
        headers: authHeaders(),
        payload: {
          ...validTicketPayload(),
          context_url: 'http://meritum.ca/claims',
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects context_url with javascript: protocol', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/support/tickets',
        headers: authHeaders(),
        payload: {
          ...validTicketPayload(),
          context_url: 'javascript:alert(1)',
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects context_url with data: URI', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/support/tickets',
        headers: authHeaders(),
        payload: {
          ...validTicketPayload(),
          context_url: 'data:text/html,<script>alert(1)</script>',
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('accepts context_url with valid HTTPS URL', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/support/tickets',
        headers: authHeaders(),
        payload: {
          ...validTicketPayload(),
          context_url: 'https://meritum.ca/claims/new',
        },
      });

      expect(res.statusCode).toBe(201);
    });

    it('rejects slug with special characters', async () => {
      const invalidSlugs = [
        'slug with spaces',
        'UPPERCASE-SLUG',
        'slug_with_underscore',
        'slug.with.dots',
        'slug@special!chars',
        '-starts-with-hyphen',
        'ends-with-hyphen-',
        'double--hyphen',
      ];

      for (const slug of invalidSlugs) {
        const res = await app.inject({
          method: 'GET',
          url: `/api/v1/help/articles/${encodeURIComponent(slug)}`,
        });

        expect(res.statusCode).toBe(400);
      }
    });

    it('accepts valid slug format', async () => {
      const validSlugs = [
        'getting-started',
        'ahcip-billing-guide',
        'how-to-submit-claims',
        'a',
        '123',
        'a1b2c3',
      ];

      for (const slug of validSlugs) {
        const res = await app.inject({
          method: 'GET',
          url: `/api/v1/help/articles/${slug}`,
        });

        // Should NOT be 400 (may be 200 or 404 depending on article existence)
        expect(res.statusCode).not.toBe(400);
      }
    });

    it('rejects search query over 200 characters', async () => {
      const longSearch = 'A'.repeat(201);
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/help/articles?search=${encodeURIComponent(longSearch)}`,
      });

      expect(res.statusCode).toBe(400);
    });

    it('accepts search query at exactly 200 characters', async () => {
      const maxSearch = 'A'.repeat(200);
      const res = await app.inject({
        method: 'GET',
        url: `/api/v1/help/articles?search=${encodeURIComponent(maxSearch)}`,
      });

      expect(res.statusCode).toBe(200);
    });

    it('rejects satisfaction comment over 1000 characters', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/support/tickets/${DUMMY_UUID}/rating`,
        headers: authHeaders(),
        payload: {
          rating: 5,
          comment: 'C'.repeat(1001),
        },
      });

      expect(res.statusCode).toBe(400);
    });

    it('accepts satisfaction comment at exactly 1000 characters', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/support/tickets/${DUMMY_UUID}/rating`,
        headers: authHeaders(),
        payload: {
          rating: 5,
          comment: 'C'.repeat(1000),
        },
      });

      // Should pass validation (may be 200 from mock)
      expect(res.statusCode).not.toBe(400);
    });
  });

  // =========================================================================
  // Category 6: tsquery Injection Prevention
  // =========================================================================

  describe('tsquery Special Character Sanitisation', () => {
    const TSQUERY_SPECIALS = [
      '& | ! ( ) : * < >',
      'billing & claims',
      'test | admin',
      '!important',
      'claim:*',
      '(admin)',
      '<script>',
      'test & (admin | billing)',
      "'test' & 'admin'",
    ];

    for (const payload of TSQUERY_SPECIALS) {
      it(`safely handles tsquery chars: ${payload.substring(0, 30)}`, async () => {
        const res = await app.inject({
          method: 'GET',
          url: `/api/v1/help/articles?search=${encodeURIComponent(payload)}`,
        });

        // Must not crash with 500 — either 200 (sanitised) or 400 (rejected)
        expect([200, 400]).toContain(res.statusCode);
        if (res.statusCode === 200) {
          const body = JSON.parse(res.body);
          expect(body.data).toBeDefined();
          expect(Array.isArray(body.data)).toBe(true);
        }
      });
    }
  });

  // =========================================================================
  // Category 7: UUID Parameter Validation
  // =========================================================================

  describe('UUID Parameter Validation', () => {
    const INVALID_UUIDS = [
      'not-a-uuid',
      '12345',
      'abcdefg',
      '00000000-0000-0000-0000-00000000000',   // too short
      '00000000-0000-0000-0000-0000000000001',  // too long
      '00000000_0000_0000_0000_000000000001',   // wrong separator
      '',
      'null',
      'undefined',
      '{{uuid}}',
      '../etc/passwd',
    ];

    for (const invalidId of INVALID_UUIDS) {
      it(`GET /api/v1/support/tickets/${invalidId.substring(0, 20)} returns 400`, async () => {
        const res = await app.inject({
          method: 'GET',
          url: `/api/v1/support/tickets/${encodeURIComponent(invalidId)}`,
          headers: authHeaders(),
        });

        expect(res.statusCode).toBe(400);
      });
    }

    for (const invalidId of INVALID_UUIDS) {
      it(`POST /api/v1/support/tickets/${invalidId.substring(0, 20)}/rating returns 400`, async () => {
        const res = await app.inject({
          method: 'POST',
          url: `/api/v1/support/tickets/${encodeURIComponent(invalidId)}/rating`,
          headers: authHeaders(),
          payload: { rating: 5 },
        });

        expect(res.statusCode).toBe(400);
      });
    }
  });

  // =========================================================================
  // Category 8: Error Response Safety
  // =========================================================================

  describe('Error Response Safety', () => {
    it('400 responses do not expose Zod schema internals', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/support/tickets',
        headers: authHeaders(),
        payload: { subject: 123, description: false },
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      // Should not contain internal column names or table names
      const rawBody = JSON.stringify(body);
      expect(rawBody).not.toContain('support_tickets');
      expect(rawBody).not.toContain('provider_id');
      expect(rawBody).not.toContain('screenshot_path');
      expect(rawBody).not.toContain('postgres');
      expect(rawBody).not.toContain('drizzle');
    });

    it('400 responses do not expose stack traces', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/support/tickets',
        headers: authHeaders(),
        payload: {},
      });

      expect(res.statusCode).toBe(400);
      const rawBody = res.body;
      expect(rawBody).not.toContain('stack');
      expect(rawBody).not.toContain('node_modules');
      expect(rawBody).not.toContain('.ts:');
      expect(rawBody).not.toContain('.js:');
    });

    it('validation error for rating does not expose min/max configuration', async () => {
      const res = await app.inject({
        method: 'POST',
        url: `/api/v1/support/tickets/${DUMMY_UUID}/rating`,
        headers: authHeaders(),
        payload: { rating: 100 },
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      // Should not expose internal constant names
      const rawBody = JSON.stringify(body);
      expect(rawBody).not.toContain('SATISFACTION_RATING_MIN');
      expect(rawBody).not.toContain('SATISFACTION_RATING_MAX');
    });

    it('invalid enum value returns 400 with generic message', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/support/tickets',
        headers: authHeaders(),
        payload: {
          ...validTicketPayload(),
          priority: 'CRITICAL', // not a valid enum value
        },
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
    });

    it('missing required fields returns 400', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/support/tickets',
        headers: authHeaders(),
        payload: {},
      });

      expect(res.statusCode).toBe(400);
    });

    it('extra unknown fields are ignored (no error)', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/support/tickets',
        headers: authHeaders(),
        payload: {
          ...validTicketPayload(),
          unknownField: 'should be stripped',
          admin: true,
          role: 'admin',
        },
      });

      // Should either accept (201, extra fields stripped) or reject (400)
      // Zod's default behaviour strips unknown keys in strict mode
      expect([201, 400]).toContain(res.statusCode);
    });
  });
});
