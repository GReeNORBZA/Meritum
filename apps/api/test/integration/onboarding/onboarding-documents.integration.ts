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
import { onboardingRoutes } from '../../../src/domains/onboarding/onboarding.routes.js';
import { type OnboardingHandlerDeps } from '../../../src/domains/onboarding/onboarding.handlers.js';
import { type OnboardingServiceDeps } from '../../../src/domains/onboarding/onboarding.service.js';

// ---------------------------------------------------------------------------
// Helper: hashToken
// ---------------------------------------------------------------------------

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

const PHYSICIAN1_USER_ID = '00000000-1111-0000-0000-000000000001';
const PHYSICIAN1_PROVIDER_ID = '00000000-5555-0000-0000-000000000001';
const PHYSICIAN1_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN1_SESSION_TOKEN_HASH = hashToken(PHYSICIAN1_SESSION_TOKEN);

// ---------------------------------------------------------------------------
// IMA Template / PDF constants
// ---------------------------------------------------------------------------

const TEST_IMA_TEMPLATE = '<html><body>IMA for {{physician_first_name}} {{physician_last_name}}</body></html>';
const TEST_IMA_RENDERED = '<html><body>IMA for John Doe</body></html>';
const TEST_IMA_HASH = createHash('sha256').update(TEST_IMA_RENDERED, 'utf-8').digest('hex');
const TEST_PDF_BUFFER = Buffer.from('%PDF-1.4 test pdf content');
const TEST_PIA_BUFFER = Buffer.from('%PDF-1.4 PIA appendix content');

// ---------------------------------------------------------------------------
// Mock session repo
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      if (tokenHash === PHYSICIAN1_SESSION_TOKEN_HASH) {
        return {
          session: {
            sessionId: '00000000-2222-0000-0000-000000000001',
            userId: PHYSICIAN1_USER_ID,
            tokenHash: PHYSICIAN1_SESSION_TOKEN_HASH,
            createdAt: new Date(),
            lastActiveAt: new Date(),
            revoked: false,
          },
          user: {
            userId: PHYSICIAN1_USER_ID,
            role: 'PHYSICIAN',
            subscriptionStatus: 'ACTIVE',
          },
        };
      }
      return undefined;
    }),
    refreshSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Mock onboarding repository
// ---------------------------------------------------------------------------

function createMockOnboardingRepo() {
  return {
    createProgress: vi.fn(),
    findProgressByProviderId: vi.fn(async () => null as any),
    markStepCompleted: vi.fn(),
    markOnboardingCompleted: vi.fn(),
    markPatientImportCompleted: vi.fn(),
    markGuidedTourCompleted: vi.fn(),
    markGuidedTourDismissed: vi.fn(),
    createImaRecord: vi.fn(async (data: any) => ({
      imaId: '00000000-7777-0000-0000-000000000001',
      providerId: data.providerId,
      templateVersion: data.templateVersion,
      documentHash: data.documentHash,
      acknowledgedAt: new Date('2026-02-01T12:00:00Z'),
      ipAddress: data.ipAddress,
      userAgent: data.userAgent,
    })),
    findLatestImaRecord: vi.fn(async () => null as any),
    listImaRecords: vi.fn(async () => []),
  };
}

// ---------------------------------------------------------------------------
// Mock provider service
// ---------------------------------------------------------------------------

function createMockProviderService() {
  return {
    createOrUpdateProvider: vi.fn(async () => ({ providerId: PHYSICIAN1_PROVIDER_ID })),
    updateProviderSpecialty: vi.fn(async () => {}),
    createBa: vi.fn(async () => ({ baId: crypto.randomUUID() })),
    createLocation: vi.fn(async () => ({ locationId: crypto.randomUUID() })),
    createWcbConfig: vi.fn(async () => ({ wcbConfigId: crypto.randomUUID() })),
    updateSubmissionPreferences: vi.fn(async () => {}),
    findProviderByUserId: vi.fn(async (userId: string) => {
      if (userId === PHYSICIAN1_USER_ID) {
        return { providerId: PHYSICIAN1_PROVIDER_ID };
      }
      return null;
    }),
    getProviderDetails: vi.fn(async (providerId: string) => {
      if (providerId === PHYSICIAN1_PROVIDER_ID) {
        return {
          billingNumber: '12345',
          cpsaRegistrationNumber: 'CPSA001',
          firstName: 'John',
          lastName: 'Doe',
          baNumbers: ['BA001'],
        };
      }
      return null;
    }),
    findBaById: vi.fn(async () => null),
    updateBaStatus: vi.fn(async () => ({ baId: '', status: '' })),
  };
}

// ---------------------------------------------------------------------------
// Mock reference data service
// ---------------------------------------------------------------------------

function createMockReferenceData() {
  return {
    validateSpecialtyCode: vi.fn(async () => true),
    validateFunctionalCentreCode: vi.fn(async () => true),
    validateCommunityCode: vi.fn(async () => true),
    getRrnpRate: vi.fn(async () => null),
    getWcbFormTypes: vi.fn(async () => ['C8', 'C10']),
  };
}

// ---------------------------------------------------------------------------
// Mock template renderer
// ---------------------------------------------------------------------------

function createMockTemplateRenderer() {
  return {
    render: vi.fn((_template: string, _data: Record<string, unknown>) => {
      return TEST_IMA_RENDERED;
    }),
  };
}

// ---------------------------------------------------------------------------
// Mock PDF generator
// ---------------------------------------------------------------------------

function createMockPdfGenerator() {
  return {
    htmlToPdf: vi.fn(async () => TEST_PDF_BUFFER),
    generateAhc11236: vi.fn(async () => TEST_PDF_BUFFER),
  };
}

// ---------------------------------------------------------------------------
// Mock file storage
// ---------------------------------------------------------------------------

function createMockFileStorage() {
  const store = new Map<string, Buffer>();
  return {
    store: vi.fn(async (key: string, data: Buffer, _contentType: string) => {
      store.set(key, data);
    }),
    retrieve: vi.fn(async (key: string) => {
      const data = store.get(key);
      if (!data) throw new Error(`File not found: ${key}`);
      return data;
    }),
    _store: store,
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let mockRepo: ReturnType<typeof createMockOnboardingRepo>;
let mockAuditRepo: { appendAuditLog: ReturnType<typeof vi.fn> };
let mockEvents: { emit: ReturnType<typeof vi.fn> };
let mockProviderService: ReturnType<typeof createMockProviderService>;
let mockReferenceData: ReturnType<typeof createMockReferenceData>;
let mockTemplateRenderer: ReturnType<typeof createMockTemplateRenderer>;
let mockPdfGenerator: ReturnType<typeof createMockPdfGenerator>;
let mockFileStorage: ReturnType<typeof createMockFileStorage>;

async function buildTestApp(): Promise<FastifyInstance> {
  mockRepo = createMockOnboardingRepo();
  mockAuditRepo = { appendAuditLog: vi.fn() };
  mockEvents = { emit: vi.fn() };
  mockProviderService = createMockProviderService();
  mockReferenceData = createMockReferenceData();
  mockTemplateRenderer = createMockTemplateRenderer();
  mockPdfGenerator = createMockPdfGenerator();
  mockFileStorage = createMockFileStorage();

  const serviceDeps: OnboardingServiceDeps = {
    repo: mockRepo as any,
    auditRepo: mockAuditRepo,
    events: mockEvents,
    providerService: mockProviderService,
    referenceData: mockReferenceData,
    templateRenderer: mockTemplateRenderer,
    pdfGenerator: mockPdfGenerator,
    fileStorage: mockFileStorage,
    imaTemplate: TEST_IMA_TEMPLATE,
    piaPdfBuffer: TEST_PIA_BUFFER,
    submitterPrefix: 'MRT',
  };

  const handlerDeps: OnboardingHandlerDeps = { serviceDeps };

  const testApp = Fastify({ logger: false });

  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  // Register auth plugin
  const mockSessionRepo = createMockSessionRepo();
  await testApp.register(authPluginFp, {
    sessionDeps: {
      sessionRepo: mockSessionRepo,
      auditRepo: { appendAuditLog: vi.fn() },
      events: { emit: vi.fn() },
    },
  });

  // Error handler
  testApp.setErrorHandler((error, _request, reply) => {
    if ('statusCode' in error && 'code' in error && typeof (error as any).code === 'string') {
      const statusCode = (error as any).statusCode ?? 500;
      if (statusCode >= 400 && statusCode < 500) {
        return reply.code(statusCode).send({
          error: {
            code: (error as any).code,
            message: error.message,
            details: (error as any).details,
          },
        });
      }
    }
    if (error.validation) {
      return reply.code(400).send({
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Validation failed',
          details: error.validation,
        },
      });
    }
    return reply.code(500).send({
      error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
    });
  });

  // Register onboarding routes
  await testApp.register(onboardingRoutes, { deps: handlerDeps });

  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function authedGet(
  target: FastifyInstance,
  url: string,
  token = PHYSICIAN1_SESSION_TOKEN,
) {
  return target.inject({
    method: 'GET',
    url,
    headers: { cookie: `session=${token}` },
  });
}

function authedPost(
  target: FastifyInstance,
  url: string,
  body?: Record<string, unknown>,
  token = PHYSICIAN1_SESSION_TOKEN,
) {
  return target.inject({
    method: 'POST',
    url,
    headers: {
      cookie: `session=${token}`,
      'content-type': 'application/json',
    },
    payload: body ?? {},
  });
}

function unauthedGet(target: FastifyInstance, url: string) {
  return target.inject({ method: 'GET', url });
}

function unauthedPost(target: FastifyInstance, url: string, body?: Record<string, unknown>) {
  return target.inject({
    method: 'POST',
    url,
    headers: { 'content-type': 'application/json' },
    payload: body ?? {},
  });
}

// ---------------------------------------------------------------------------
// Tests: Document Endpoints
// ---------------------------------------------------------------------------

describe('Onboarding Document Endpoints Integration Tests', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    vi.clearAllMocks();
    // Reset provider service defaults
    mockProviderService.findProviderByUserId.mockImplementation(async (userId: string) => {
      if (userId === PHYSICIAN1_USER_ID) {
        return { providerId: PHYSICIAN1_PROVIDER_ID };
      }
      return null;
    });
    mockProviderService.getProviderDetails.mockImplementation(async (providerId: string) => {
      if (providerId === PHYSICIAN1_PROVIDER_ID) {
        return {
          billingNumber: '12345',
          cpsaRegistrationNumber: 'CPSA001',
          firstName: 'John',
          lastName: 'Doe',
          baNumbers: ['BA001'],
        };
      }
      return null;
    });
    mockTemplateRenderer.render.mockReturnValue(TEST_IMA_RENDERED);
    mockPdfGenerator.htmlToPdf.mockResolvedValue(TEST_PDF_BUFFER);
    mockPdfGenerator.generateAhc11236.mockResolvedValue(TEST_PDF_BUFFER);
    mockRepo.createImaRecord.mockImplementation(async (data: any) => ({
      imaId: '00000000-7777-0000-0000-000000000001',
      providerId: data.providerId,
      templateVersion: data.templateVersion,
      documentHash: data.documentHash,
      acknowledgedAt: new Date('2026-02-01T12:00:00Z'),
      ipAddress: data.ipAddress,
      userAgent: data.userAgent,
    }));
    // Reset file storage mock with working implementation
    mockFileStorage.store.mockImplementation(async () => {});
    mockFileStorage.retrieve.mockImplementation(async () => TEST_PDF_BUFFER);
  });

  // =========================================================================
  // 1. GET /api/v1/onboarding/ima — Rendered IMA with hash
  // =========================================================================

  describe('GET /api/v1/onboarding/ima', () => {
    it('returns rendered IMA with hash', async () => {
      const res = await authedGet(app, '/api/v1/onboarding/ima');
      expect(res.statusCode).toBe(200);

      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.content).toBe(TEST_IMA_RENDERED);
      expect(body.data.hash).toBe(TEST_IMA_HASH);
      expect(body.data.template_version).toBe('1.0.0');
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedGet(app, '/api/v1/onboarding/ima');
      expect(res.statusCode).toBe(401);
      expect(res.json().data).toBeUndefined();
    });

    it('returns 404 if no provider exists', async () => {
      mockProviderService.findProviderByUserId.mockResolvedValueOnce(null);

      const res = await authedGet(app, '/api/v1/onboarding/ima');
      expect(res.statusCode).toBe(404);
    });
  });

  // =========================================================================
  // 2. POST /api/v1/onboarding/ima/acknowledge
  // =========================================================================

  describe('POST /api/v1/onboarding/ima/acknowledge', () => {
    it('creates IMA record with matching hash', async () => {
      // Mock markStepCompleted for step 7 (called by acknowledgeIma -> completeStep7)
      const progressAfterStep7 = {
        progressId: '00000000-3333-0000-0000-000000000001',
        providerId: PHYSICIAN1_PROVIDER_ID,
        step1Completed: true,
        step2Completed: true,
        step3Completed: true,
        step4Completed: true,
        step5Completed: false,
        step6Completed: false,
        step7Completed: true,
        patientImportCompleted: false,
        guidedTourCompleted: false,
        guidedTourDismissed: false,
        startedAt: new Date('2026-01-01T00:00:00Z'),
        completedAt: null,
      };
      mockRepo.markStepCompleted.mockResolvedValueOnce(progressAfterStep7);
      // All required steps complete -> markOnboardingCompleted will be called
      mockRepo.markOnboardingCompleted.mockResolvedValueOnce({
        ...progressAfterStep7,
        completedAt: new Date(),
      });

      const res = await authedPost(app, '/api/v1/onboarding/ima/acknowledge', {
        document_hash: TEST_IMA_HASH,
      });
      expect(res.statusCode).toBe(201);

      const body = res.json();
      expect(body.data).toBeDefined();
      expect(body.data.ima_id).toBe('00000000-7777-0000-0000-000000000001');
      expect(body.data.document_hash).toBe(TEST_IMA_HASH);
      expect(body.data.template_version).toBe('1.0.0');
      expect(body.data.acknowledged_at).toBeDefined();
    });

    it('returns 422 with mismatched hash', async () => {
      const wrongHash = 'a'.repeat(64);

      const res = await authedPost(app, '/api/v1/onboarding/ima/acknowledge', {
        document_hash: wrongHash,
      });
      expect(res.statusCode).toBe(422);
    });

    it('returns 400 with invalid hash length', async () => {
      const res = await authedPost(app, '/api/v1/onboarding/ima/acknowledge', {
        document_hash: 'tooshort',
      });
      expect(res.statusCode).toBe(400);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedPost(app, '/api/v1/onboarding/ima/acknowledge', {
        document_hash: TEST_IMA_HASH,
      });
      expect(res.statusCode).toBe(401);
    });

    it('stores PDF in file storage after acknowledgement', async () => {
      const progressAfterStep7 = {
        progressId: '00000000-3333-0000-0000-000000000001',
        providerId: PHYSICIAN1_PROVIDER_ID,
        step1Completed: true,
        step2Completed: true,
        step3Completed: true,
        step4Completed: true,
        step5Completed: false,
        step6Completed: false,
        step7Completed: true,
        patientImportCompleted: false,
        guidedTourCompleted: false,
        guidedTourDismissed: false,
        startedAt: new Date('2026-01-01T00:00:00Z'),
        completedAt: null,
      };
      mockRepo.markStepCompleted.mockResolvedValueOnce(progressAfterStep7);
      mockRepo.markOnboardingCompleted.mockResolvedValueOnce({
        ...progressAfterStep7,
        completedAt: new Date(),
      });

      await authedPost(app, '/api/v1/onboarding/ima/acknowledge', {
        document_hash: TEST_IMA_HASH,
      });

      expect(mockFileStorage.store).toHaveBeenCalledTimes(1);
      expect(mockPdfGenerator.htmlToPdf).toHaveBeenCalledWith(TEST_IMA_RENDERED);
    });
  });

  // =========================================================================
  // 3. GET /api/v1/onboarding/ima/download
  // =========================================================================

  describe('GET /api/v1/onboarding/ima/download', () => {
    it('returns PDF for provider with acknowledged IMA', async () => {
      // Setup: IMA record exists
      mockRepo.findLatestImaRecord.mockResolvedValueOnce({
        imaId: '00000000-7777-0000-0000-000000000001',
        providerId: PHYSICIAN1_PROVIDER_ID,
        templateVersion: '1.0.0',
        documentHash: TEST_IMA_HASH,
        acknowledgedAt: new Date('2026-02-01T12:00:00Z'),
        ipAddress: '127.0.0.1',
        userAgent: 'test-agent',
      });

      // File storage returns the PDF
      mockFileStorage.retrieve.mockResolvedValueOnce(TEST_PDF_BUFFER);

      const res = await authedGet(app, '/api/v1/onboarding/ima/download');
      expect(res.statusCode).toBe(200);
      expect(res.headers['content-type']).toBe('application/pdf');
      expect(res.headers['content-disposition']).toContain('IMA-John-Doe.pdf');
    });

    it('returns 404 if no IMA acknowledged', async () => {
      mockRepo.findLatestImaRecord.mockResolvedValueOnce(null);

      const res = await authedGet(app, '/api/v1/onboarding/ima/download');
      expect(res.statusCode).toBe(404);
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedGet(app, '/api/v1/onboarding/ima/download');
      expect(res.statusCode).toBe(401);
    });
  });

  // =========================================================================
  // 4. GET /api/v1/onboarding/ahc11236/download
  // =========================================================================

  describe('GET /api/v1/onboarding/ahc11236/download', () => {
    it('returns pre-filled PDF', async () => {
      const res = await authedGet(app, '/api/v1/onboarding/ahc11236/download');
      expect(res.statusCode).toBe(200);
      expect(res.headers['content-type']).toBe('application/pdf');
      expect(res.headers['content-disposition']).toContain('AHC11236.pdf');
    });

    it('passes correct BA number to PDF generator', async () => {
      await authedGet(app, '/api/v1/onboarding/ahc11236/download');

      expect(mockPdfGenerator.generateAhc11236).toHaveBeenCalledWith(
        expect.objectContaining({
          billingNumber: '12345',
          baNumber: 'BA001',
          submitterPrefix: 'MRT',
          physicianName: 'Dr. John Doe',
        }),
      );
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedGet(app, '/api/v1/onboarding/ahc11236/download');
      expect(res.statusCode).toBe(401);
    });

    it('returns 404 if no provider exists', async () => {
      mockProviderService.findProviderByUserId.mockResolvedValueOnce(null);

      const res = await authedGet(app, '/api/v1/onboarding/ahc11236/download');
      expect(res.statusCode).toBe(404);
    });
  });

  // =========================================================================
  // 5. GET /api/v1/onboarding/pia/download
  // =========================================================================

  describe('GET /api/v1/onboarding/pia/download', () => {
    it('returns PIA PDF', async () => {
      const res = await authedGet(app, '/api/v1/onboarding/pia/download');
      expect(res.statusCode).toBe(200);
      expect(res.headers['content-type']).toBe('application/pdf');
      expect(res.headers['content-disposition']).toContain('PIA-Appendix.pdf');
    });

    it('returns 401 without authentication', async () => {
      const res = await unauthedGet(app, '/api/v1/onboarding/pia/download');
      expect(res.statusCode).toBe(401);
    });
  });
});
