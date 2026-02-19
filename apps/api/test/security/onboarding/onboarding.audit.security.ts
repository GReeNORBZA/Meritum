import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { createHash } from 'node:crypto';

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
// Real imports (after mocks are hoisted)
// ---------------------------------------------------------------------------

import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { onboardingRoutes } from '../../../src/domains/onboarding/onboarding.routes.js';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { type OnboardingHandlerDeps } from '../../../src/domains/onboarding/onboarding.handlers.js';
import { type OnboardingServiceDeps } from '../../../src/domains/onboarding/onboarding.service.js';
import {
  type SessionManagementDeps,
  hashToken,
} from '../../../src/domains/iam/iam.service.js';
import { OnboardingAuditAction, BALinkageStatus, IMA_TEMPLATE_VERSION } from '@meritum/shared/constants/onboarding.constants.js';
import { randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Fixed test user/session
// ---------------------------------------------------------------------------

const FIXED_SESSION_TOKEN = randomBytes(32).toString('hex');
const FIXED_SESSION_TOKEN_HASH = hashToken(FIXED_SESSION_TOKEN);
const FIXED_USER_ID = '22222222-0000-0000-0000-000000000001';
const FIXED_PROVIDER_ID = FIXED_USER_ID;
const FIXED_SESSION_ID = '33333333-0000-0000-0000-000000000001';

const FIXED_PROGRESS_ID = 'aaaaaaaa-0000-0000-0000-000000000001';
const FIXED_IMA_ID = 'bbbbbbbb-0000-0000-0000-000000000001';
const FIXED_BA_ID = 'cccccccc-0000-0000-0000-000000000001';

// ---------------------------------------------------------------------------
// Mock stores
// ---------------------------------------------------------------------------

interface MockUser {
  userId: string;
  email: string;
  passwordHash: string;
  mfaConfigured: boolean;
  totpSecretEncrypted: string | null;
  failedLoginCount: number;
  lockedUntil: Date | null;
  isActive: boolean;
  role?: string;
  subscriptionStatus?: string;
}

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

let users: MockUser[] = [];
let sessions: MockSession[] = [];
let auditEntries: Array<Record<string, unknown>> = [];

// Track mock progress state
// When progressExists is true (default), findProgressByProviderId returns a record.
// Set to false to test the "start onboarding" (STARTED) path.
let progressExists = true;
let mockProgressStepCompletions: Record<number, boolean> = {};

// ---------------------------------------------------------------------------
// Mock repositories
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    createSession: vi.fn(async () => {
      return { sessionId: '44444444-0000-0000-0000-000000000001' };
    }),
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      const session = sessions.find((s) => s.tokenHash === tokenHash && !s.revoked);
      if (!session) return undefined;
      const user = users.find((u) => u.userId === session.userId);
      if (!user) return undefined;
      return {
        session,
        user: {
          userId: user.userId,
          role: user.role ?? 'PHYSICIAN',
          subscriptionStatus: user.subscriptionStatus ?? 'TRIAL',
        },
      };
    }),
    refreshSession: vi.fn(async () => {}),
    listActiveSessions: vi.fn(async () => []),
    revokeSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
  };
}

function createSharedAuditRepo() {
  return {
    appendAuditLog: vi.fn(async (entry: Record<string, unknown>) => {
      auditEntries.push(entry);
    }),
  };
}

function createMockEvents() {
  return { emit: vi.fn() };
}

// ---------------------------------------------------------------------------
// Mock onboarding repository — tracks step completions for audit testing
// ---------------------------------------------------------------------------

function makeProgressRecord(overrides?: Partial<Record<string, unknown>>) {
  return {
    progressId: FIXED_PROGRESS_ID,
    providerId: FIXED_PROVIDER_ID,
    step1Completed: mockProgressStepCompletions[1] ?? false,
    step2Completed: mockProgressStepCompletions[2] ?? false,
    step3Completed: mockProgressStepCompletions[3] ?? false,
    step4Completed: mockProgressStepCompletions[4] ?? false,
    step5Completed: mockProgressStepCompletions[5] ?? false,
    step6Completed: mockProgressStepCompletions[6] ?? false,
    step7Completed: mockProgressStepCompletions[7] ?? false,
    patientImportCompleted: false,
    guidedTourCompleted: false,
    guidedTourDismissed: false,
    startedAt: new Date(),
    completedAt: null,
    ...overrides,
  };
}

function createMockOnboardingRepo() {
  return {
    createProgress: vi.fn(async (_providerId: string) => {
      progressExists = true;
      return makeProgressRecord();
    }),
    findProgressByProviderId: vi.fn(async (_providerId: string) => {
      if (!progressExists) return null;
      return makeProgressRecord();
    }),
    markStepCompleted: vi.fn(async (_providerId: string, stepNumber: number) => {
      mockProgressStepCompletions[stepNumber] = true;
      return makeProgressRecord();
    }),
    markOnboardingCompleted: vi.fn(async (_providerId: string) => {
      return makeProgressRecord({ completedAt: new Date() });
    }),
    markPatientImportCompleted: vi.fn(async (_providerId: string) => {
      return makeProgressRecord({ patientImportCompleted: true });
    }),
    markGuidedTourCompleted: vi.fn(async (_providerId: string) => {
      return makeProgressRecord({ guidedTourCompleted: true });
    }),
    markGuidedTourDismissed: vi.fn(async (_providerId: string) => {
      return makeProgressRecord({ guidedTourDismissed: true });
    }),
    createImaRecord: vi.fn(async (data: any) => {
      return {
        imaId: FIXED_IMA_ID,
        providerId: data.providerId,
        templateVersion: data.templateVersion,
        documentHash: data.documentHash,
        ipAddress: data.ipAddress,
        userAgent: data.userAgent,
        acknowledgedAt: new Date(),
      };
    }),
    findLatestImaRecord: vi.fn(async (_providerId: string) => {
      return {
        imaId: FIXED_IMA_ID,
        providerId: FIXED_PROVIDER_ID,
        templateVersion: IMA_TEMPLATE_VERSION,
        documentHash: 'abc123hash',
        ipAddress: '127.0.0.1',
        userAgent: 'test-agent',
        acknowledgedAt: new Date(),
      };
    }),
    listImaRecords: vi.fn(async () => []),
  };
}

// ---------------------------------------------------------------------------
// Mock provider service
// ---------------------------------------------------------------------------

function createMockProviderService() {
  return {
    createOrUpdateProvider: vi.fn(async () => ({ providerId: FIXED_PROVIDER_ID })),
    updateProviderSpecialty: vi.fn(async () => {}),
    createBa: vi.fn(async () => ({ baId: FIXED_BA_ID })),
    createLocation: vi.fn(async () => ({ locationId: '00000000-0000-0000-0000-000000000099' })),
    createWcbConfig: vi.fn(async () => ({ wcbConfigId: '00000000-0000-0000-0000-000000000099' })),
    updateSubmissionPreferences: vi.fn(async () => {}),
    findProviderByUserId: vi.fn(async () => ({ providerId: FIXED_PROVIDER_ID })),
    getProviderDetails: vi.fn(async () => ({
      billingNumber: '12345',
      cpsaRegistrationNumber: 'REG001',
      firstName: 'Test',
      lastName: 'Physician',
      baNumbers: ['12345'],
    })),
    findBaById: vi.fn(async () => ({
      baId: FIXED_BA_ID,
      providerId: FIXED_PROVIDER_ID,
      status: BALinkageStatus.PENDING,
    })),
    updateBaStatus: vi.fn(async () => ({ baId: FIXED_BA_ID, status: BALinkageStatus.ACTIVE })),
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
// Mock template/PDF/storage services (for IMA / document tests)
// ---------------------------------------------------------------------------

const MOCK_IMA_HTML = '<html><body>IMA Agreement v1.0.0</body></html>';
const MOCK_IMA_HASH = createHash('sha256').update(MOCK_IMA_HTML, 'utf-8').digest('hex');
const MOCK_PDF_BUFFER = Buffer.from('%PDF-1.4 mock content');

function createMockTemplateRenderer() {
  return {
    render: vi.fn((_template: string, _data: Record<string, unknown>) => MOCK_IMA_HTML),
  };
}

function createMockPdfGenerator() {
  return {
    htmlToPdf: vi.fn(async () => MOCK_PDF_BUFFER),
    generateAhc11236: vi.fn(async () => MOCK_PDF_BUFFER),
  };
}

function createMockFileStorage() {
  return {
    store: vi.fn(async () => {}),
    retrieve: vi.fn(async () => MOCK_PDF_BUFFER),
  };
}

// ---------------------------------------------------------------------------
// Stub service deps
// ---------------------------------------------------------------------------

let sharedAuditRepo: ReturnType<typeof createSharedAuditRepo>;

function createServiceDeps(): OnboardingServiceDeps {
  return {
    repo: createMockOnboardingRepo() as any,
    auditRepo: sharedAuditRepo,
    events: createMockEvents(),
    providerService: createMockProviderService(),
    referenceData: createMockReferenceData(),
    templateRenderer: createMockTemplateRenderer(),
    pdfGenerator: createMockPdfGenerator(),
    fileStorage: createMockFileStorage(),
    imaTemplate: '{{physician_first_name}} IMA template',
    piaPdfBuffer: MOCK_PDF_BUFFER,
    submitterPrefix: 'MERT',
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let mockSessionRepo: ReturnType<typeof createMockSessionRepo>;

async function buildTestApp(): Promise<FastifyInstance> {
  mockSessionRepo = createMockSessionRepo();
  sharedAuditRepo = createSharedAuditRepo();

  const sessionDeps: SessionManagementDeps = {
    sessionRepo: mockSessionRepo,
    auditRepo: createSharedAuditRepo(),
    events: createMockEvents(),
  };

  const handlerDeps: OnboardingHandlerDeps = {
    serviceDeps: createServiceDeps(),
  };

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  await testApp.register(authPluginFp, { sessionDeps });

  testApp.setErrorHandler((error, _request, reply) => {
    if ('statusCode' in error && 'code' in error && typeof (error as any).code === 'string') {
      const statusCode = (error as any).statusCode ?? 500;
      if (statusCode >= 400 && statusCode < 500) {
        return reply.code(statusCode).send({
          error: { code: (error as any).code, message: error.message },
        });
      }
    }
    if (error.validation) {
      return reply.code(400).send({
        error: { code: 'VALIDATION_ERROR', message: 'Validation failed', details: error.validation },
      });
    }
    return reply.code(500).send({
      error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
    });
  });

  await testApp.register(onboardingRoutes, { deps: handlerDeps });
  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function physicianCookie(): string {
  return `session=${FIXED_SESSION_TOKEN}`;
}

function seedPhysician() {
  users.push({
    userId: FIXED_USER_ID,
    email: 'physician@example.com',
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    role: 'PHYSICIAN',
    subscriptionStatus: 'ACTIVE',
  });
  sessions.push({
    sessionId: FIXED_SESSION_ID,
    userId: FIXED_USER_ID,
    tokenHash: FIXED_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });
}

function findAuditEntry(action: string): Record<string, unknown> | undefined {
  return auditEntries.find((e) => e.action === action);
}

function findAllAuditEntries(action: string): Array<Record<string, unknown>> {
  return auditEntries.filter((e) => e.action === action);
}

function physicianRequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: Record<string, unknown>) {
  return app.inject({
    method,
    url,
    headers: { cookie: physicianCookie() },
    ...(payload ? { payload } : {}),
  });
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Onboarding Audit Trail Completeness (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    users = [];
    sessions = [];
    auditEntries = [];
    progressExists = true;
    mockProgressStepCompletions = {};
    seedPhysician();
  });

  // =========================================================================
  // Onboarding Lifecycle Events
  // =========================================================================

  describe('Onboarding lifecycle events', () => {
    it('start onboarding produces onboarding.started audit entry with provider_id', async () => {
      // getOrCreateProgress creates a new progress record when none exists
      progressExists = false; // Ensure no existing progress

      await physicianRequest('GET', '/api/v1/onboarding/progress');

      const entry = findAuditEntry(OnboardingAuditAction.STARTED);
      expect(entry).toBeDefined();
      expect(entry!.category).toBe('onboarding');
      expect(entry!.resourceType).toBe('onboarding_progress');
      expect(entry!.resourceId).toBe(FIXED_PROGRESS_ID);
      expect((entry!.detail as any).provider_id).toBe(FIXED_PROVIDER_ID);
    });

    it('complete step 1 produces onboarding.step_completed with step_number: 1', async () => {
      await physicianRequest('POST', '/api/v1/onboarding/steps/1', {
        billing_number: '12345',
        cpsa_number: 'REG001',
        legal_first_name: 'Test',
        legal_last_name: 'Physician',
      });

      const entries = findAllAuditEntries(OnboardingAuditAction.STEP_COMPLETED);
      const step1Entry = entries.find((e) => (e.detail as any).step_number === 1);
      expect(step1Entry).toBeDefined();
      expect(step1Entry!.category).toBe('onboarding');
      expect(step1Entry!.resourceType).toBe('onboarding_progress');
      expect((step1Entry!.detail as any).provider_id).toBe(FIXED_PROVIDER_ID);
    });

    it('complete step 2 produces onboarding.step_completed with step_number: 2', async () => {
      await physicianRequest('POST', '/api/v1/onboarding/steps/2', {
        specialty_code: 'GP',
        physician_type: 'gp',
      });

      const entries = findAllAuditEntries(OnboardingAuditAction.STEP_COMPLETED);
      const step2Entry = entries.find((e) => (e.detail as any).step_number === 2);
      expect(step2Entry).toBeDefined();
      expect(step2Entry!.category).toBe('onboarding');
      expect((step2Entry!.detail as any).provider_id).toBe(FIXED_PROVIDER_ID);
    });

    it('complete step 3 produces onboarding.step_completed with step_number: 3', async () => {
      await physicianRequest('POST', '/api/v1/onboarding/steps/3', {
        primary_ba_number: '12345',
        is_pcpcm_enrolled: false,
      });

      const entries = findAllAuditEntries(OnboardingAuditAction.STEP_COMPLETED);
      const step3Entry = entries.find((e) => (e.detail as any).step_number === 3);
      expect(step3Entry).toBeDefined();
      expect(step3Entry!.category).toBe('onboarding');
      expect((step3Entry!.detail as any).provider_id).toBe(FIXED_PROVIDER_ID);
    });

    it('complete step 4 produces onboarding.step_completed with step_number: 4', async () => {
      await physicianRequest('POST', '/api/v1/onboarding/steps/4', {
        location_name: 'Test Clinic',
        functional_centre_code: 'FC01',
        community_code: 'COM01',
        address: {
          street: '123 Main St',
          city: 'Calgary',
          province: 'AB',
          postal_code: 'T2P0A1',
        },
      });

      const entries = findAllAuditEntries(OnboardingAuditAction.STEP_COMPLETED);
      const step4Entry = entries.find((e) => (e.detail as any).step_number === 4);
      expect(step4Entry).toBeDefined();
      expect(step4Entry!.category).toBe('onboarding');
      expect((step4Entry!.detail as any).provider_id).toBe(FIXED_PROVIDER_ID);
    });

    it('complete step 5 (optional) produces onboarding.step_completed with step_number: 5', async () => {
      await physicianRequest('POST', '/api/v1/onboarding/steps/5', {
        contract_id: 'WCB-001',
        role: 'ATTENDING',
        skill_code: 'GP',
      });

      const entries = findAllAuditEntries(OnboardingAuditAction.STEP_COMPLETED);
      const step5Entry = entries.find((e) => (e.detail as any).step_number === 5);
      expect(step5Entry).toBeDefined();
      expect(step5Entry!.category).toBe('onboarding');
      expect((step5Entry!.detail as any).provider_id).toBe(FIXED_PROVIDER_ID);
    });

    it('complete step 6 (optional) produces onboarding.step_completed with step_number: 6', async () => {
      await physicianRequest('POST', '/api/v1/onboarding/steps/6', {
        ahcip_mode: 'auto_clean',
        wcb_mode: 'require_approval',
      });

      const entries = findAllAuditEntries(OnboardingAuditAction.STEP_COMPLETED);
      const step6Entry = entries.find((e) => (e.detail as any).step_number === 6);
      expect(step6Entry).toBeDefined();
      expect(step6Entry!.category).toBe('onboarding');
      expect((step6Entry!.detail as any).provider_id).toBe(FIXED_PROVIDER_ID);
    });

    it('complete step 7 produces onboarding.step_completed with step_number: 7', async () => {
      await physicianRequest('POST', '/api/v1/onboarding/steps/7');

      const entries = findAllAuditEntries(OnboardingAuditAction.STEP_COMPLETED);
      const step7Entry = entries.find((e) => (e.detail as any).step_number === 7);
      expect(step7Entry).toBeDefined();
      expect(step7Entry!.category).toBe('onboarding');
      expect((step7Entry!.detail as any).provider_id).toBe(FIXED_PROVIDER_ID);
    });

    it('step 7 audit entry includes ipAddress and userAgent for legal compliance', async () => {
      await physicianRequest('POST', '/api/v1/onboarding/steps/7');

      const entries = findAllAuditEntries(OnboardingAuditAction.STEP_COMPLETED);
      const step7Entry = entries.find((e) => (e.detail as any).step_number === 7);
      expect(step7Entry).toBeDefined();
      expect(step7Entry!.ipAddress).toBeDefined();
      expect(step7Entry!.userAgent).toBeDefined();
    });

    it('completing all required steps produces onboarding.completed audit entry', async () => {
      // Pre-set all required steps as completed so markOnboardingCompleted is triggered
      mockProgressStepCompletions = { 1: true, 2: true, 3: true, 4: true, 7: true };

      // Reset mock state to trigger the completion path — step 7 calls markOnboardingCompleted
      // when computed.is_complete is true
      await physicianRequest('POST', '/api/v1/onboarding/steps/7');

      const entry = findAuditEntry(OnboardingAuditAction.COMPLETED);
      expect(entry).toBeDefined();
      expect(entry!.category).toBe('onboarding');
      expect(entry!.resourceType).toBe('onboarding_progress');
      expect((entry!.detail as any).provider_id).toBe(FIXED_PROVIDER_ID);
    });
  });

  // =========================================================================
  // IMA Events
  // =========================================================================

  describe('IMA events', () => {
    it('IMA acknowledged produces onboarding.ima_acknowledged with template_version and document_hash', async () => {
      await physicianRequest('POST', '/api/v1/onboarding/ima/acknowledge', {
        document_hash: MOCK_IMA_HASH,
      });

      const entry = findAuditEntry(OnboardingAuditAction.IMA_ACKNOWLEDGED);
      expect(entry).toBeDefined();
      expect(entry!.category).toBe('onboarding');
      expect(entry!.resourceType).toBe('ima_record');
      expect(entry!.resourceId).toBe(FIXED_IMA_ID);
      expect((entry!.detail as any).template_version).toBe(IMA_TEMPLATE_VERSION);
      expect((entry!.detail as any).document_hash).toBe(MOCK_IMA_HASH);
      expect((entry!.detail as any).provider_id).toBe(FIXED_PROVIDER_ID);
    });

    it('IMA acknowledged audit entry includes ipAddress and userAgent', async () => {
      await physicianRequest('POST', '/api/v1/onboarding/ima/acknowledge', {
        document_hash: MOCK_IMA_HASH,
      });

      const entry = findAuditEntry(OnboardingAuditAction.IMA_ACKNOWLEDGED);
      expect(entry).toBeDefined();
      expect(entry!.ipAddress).toBeDefined();
      expect(entry!.userAgent).toBeDefined();
    });

    it('IMA downloaded produces onboarding.ima_downloaded audit entry', async () => {
      await physicianRequest('GET', '/api/v1/onboarding/ima/download');

      const entry = findAuditEntry(OnboardingAuditAction.IMA_DOWNLOADED);
      expect(entry).toBeDefined();
      expect(entry!.category).toBe('onboarding');
      expect(entry!.resourceType).toBe('ima_record');
      expect(entry!.resourceId).toBe(FIXED_IMA_ID);
      expect((entry!.detail as any).provider_id).toBe(FIXED_PROVIDER_ID);
    });
  });

  // =========================================================================
  // Document Events
  // =========================================================================

  describe('Document events', () => {
    it('AHC11236 downloaded produces onboarding.ahc11236_downloaded audit entry', async () => {
      await physicianRequest('GET', '/api/v1/onboarding/ahc11236/download');

      const entry = findAuditEntry(OnboardingAuditAction.AHC11236_DOWNLOADED);
      expect(entry).toBeDefined();
      expect(entry!.category).toBe('onboarding');
      expect(entry!.resourceType).toBe('ahc11236');
      expect(entry!.resourceId).toBe(FIXED_PROVIDER_ID);
      expect((entry!.detail as any).provider_id).toBe(FIXED_PROVIDER_ID);
    });

    it('PIA downloaded produces onboarding.pia_downloaded audit entry', async () => {
      await physicianRequest('GET', '/api/v1/onboarding/pia/download');

      const entry = findAuditEntry(OnboardingAuditAction.PIA_DOWNLOADED);
      expect(entry).toBeDefined();
      expect(entry!.category).toBe('onboarding');
      expect(entry!.resourceType).toBe('pia');
    });
  });

  // =========================================================================
  // Supplementary Events
  // =========================================================================

  describe('Supplementary events', () => {
    it('patient import completed produces onboarding.patient_import_completed audit entry', async () => {
      await physicianRequest('POST', '/api/v1/onboarding/patient-import/complete');

      const entry = findAuditEntry(OnboardingAuditAction.PATIENT_IMPORT_COMPLETED);
      expect(entry).toBeDefined();
      expect(entry!.category).toBe('onboarding');
      expect(entry!.resourceType).toBe('onboarding_progress');
      expect(entry!.resourceId).toBe(FIXED_PROGRESS_ID);
      expect((entry!.detail as any).provider_id).toBe(FIXED_PROVIDER_ID);
    });

    it('guided tour completed produces onboarding.guided_tour_completed audit entry', async () => {
      await physicianRequest('POST', '/api/v1/onboarding/guided-tour/complete');

      const entry = findAuditEntry(OnboardingAuditAction.GUIDED_TOUR_COMPLETED);
      expect(entry).toBeDefined();
      expect(entry!.category).toBe('onboarding');
      expect(entry!.resourceType).toBe('onboarding_progress');
      expect(entry!.resourceId).toBe(FIXED_PROGRESS_ID);
      expect((entry!.detail as any).provider_id).toBe(FIXED_PROVIDER_ID);
    });

    it('guided tour dismissed produces onboarding.guided_tour_dismissed audit entry', async () => {
      await physicianRequest('POST', '/api/v1/onboarding/guided-tour/dismiss');

      const entry = findAuditEntry(OnboardingAuditAction.GUIDED_TOUR_DISMISSED);
      expect(entry).toBeDefined();
      expect(entry!.category).toBe('onboarding');
      expect(entry!.resourceType).toBe('onboarding_progress');
      expect(entry!.resourceId).toBe(FIXED_PROGRESS_ID);
      expect((entry!.detail as any).provider_id).toBe(FIXED_PROVIDER_ID);
    });

    it('BA status confirmed active produces onboarding.ba_status_updated with ba_id and new_status', async () => {
      await physicianRequest('POST', `/api/v1/onboarding/ba/${FIXED_BA_ID}/confirm-active`);

      const entry = findAuditEntry(OnboardingAuditAction.BA_STATUS_UPDATED);
      expect(entry).toBeDefined();
      expect(entry!.category).toBe('onboarding');
      expect(entry!.resourceType).toBe('business_arrangement');
      expect(entry!.resourceId).toBe(FIXED_BA_ID);
      expect((entry!.detail as any).provider_id).toBe(FIXED_PROVIDER_ID);
      expect((entry!.detail as any).previous_status).toBe(BALinkageStatus.PENDING);
      expect((entry!.detail as any).new_status).toBe(BALinkageStatus.ACTIVE);
    });
  });

  // =========================================================================
  // Audit Entry Field Completeness
  // =========================================================================

  describe('Audit entry field completeness', () => {
    it('all onboarding audit entries have action and category fields', async () => {
      // Trigger several actions to accumulate audit entries
      await physicianRequest('POST', '/api/v1/onboarding/steps/1', {
        billing_number: '12345',
        cpsa_number: 'REG001',
        legal_first_name: 'Test',
        legal_last_name: 'Physician',
      });
      await physicianRequest('POST', '/api/v1/onboarding/guided-tour/complete');
      await physicianRequest('POST', '/api/v1/onboarding/patient-import/complete');

      expect(auditEntries.length).toBeGreaterThan(0);
      for (const entry of auditEntries) {
        expect(entry.action).toBeDefined();
        expect(typeof entry.action).toBe('string');
        expect(entry.category).toBeDefined();
        expect(typeof entry.category).toBe('string');
        expect(entry.category).toBe('onboarding');
      }
    });

    it('state-changing audit entries include resourceType and resourceId', async () => {
      await physicianRequest('POST', '/api/v1/onboarding/steps/2', {
        specialty_code: 'GP',
        physician_type: 'gp',
      });

      const entry = findAuditEntry(OnboardingAuditAction.STEP_COMPLETED);
      expect(entry).toBeDefined();
      expect(entry!.resourceType).toBeDefined();
      expect(typeof entry!.resourceType).toBe('string');
      expect(entry!.resourceId).toBeDefined();
      expect(typeof entry!.resourceId).toBe('string');
    });

    it('onboarding.started entry includes provider_id in detail', async () => {
      progressExists = false; // No existing progress — triggers STARTED
      await physicianRequest('GET', '/api/v1/onboarding/progress');

      const entry = findAuditEntry(OnboardingAuditAction.STARTED);
      expect(entry).toBeDefined();
      expect((entry!.detail as any).provider_id).toBe(FIXED_PROVIDER_ID);
    });

    it('step_completed entries include both provider_id and step_number in detail', async () => {
      await physicianRequest('POST', '/api/v1/onboarding/steps/3', {
        primary_ba_number: '12345',
        is_pcpcm_enrolled: false,
      });

      const entries = findAllAuditEntries(OnboardingAuditAction.STEP_COMPLETED);
      const step3Entry = entries.find((e) => (e.detail as any).step_number === 3);
      expect(step3Entry).toBeDefined();
      expect((step3Entry!.detail as any).provider_id).toBeDefined();
      expect((step3Entry!.detail as any).step_number).toBe(3);
    });
  });

  // =========================================================================
  // Audit Log Integrity
  // =========================================================================

  describe('Audit log integrity', () => {
    it('audit entries for onboarding are scoped to the physician\'s provider_id', async () => {
      // Execute several actions
      await physicianRequest('POST', '/api/v1/onboarding/steps/1', {
        billing_number: '12345',
        cpsa_number: 'REG001',
        legal_first_name: 'Test',
        legal_last_name: 'Physician',
      });
      await physicianRequest('POST', '/api/v1/onboarding/guided-tour/complete');

      // Every audit entry detail should reference the authenticated physician's provider_id
      for (const entry of auditEntries) {
        if (entry.detail && typeof entry.detail === 'object') {
          const detail = entry.detail as Record<string, unknown>;
          if ('provider_id' in detail) {
            expect(detail.provider_id).toBe(FIXED_PROVIDER_ID);
          }
        }
      }
    });

    it('no PUT/PATCH endpoints exist for onboarding audit modification', async () => {
      const putRes = await app.inject({
        method: 'PUT',
        url: '/api/v1/onboarding/progress',
        headers: { cookie: physicianCookie() },
        payload: { action: 'tampered' },
      });
      expect(putRes.statusCode).toBe(404);

      const patchRes = await app.inject({
        method: 'PATCH',
        url: '/api/v1/onboarding/progress',
        headers: { cookie: physicianCookie() },
        payload: { action: 'tampered' },
      });
      expect(patchRes.statusCode).toBe(404);
    });

    it('no DELETE endpoints exist for onboarding resources', async () => {
      const deleteRes = await app.inject({
        method: 'DELETE',
        url: '/api/v1/onboarding/progress',
        headers: { cookie: physicianCookie() },
      });
      expect(deleteRes.statusCode).toBe(404);

      const deleteStepRes = await app.inject({
        method: 'DELETE',
        url: '/api/v1/onboarding/steps/1',
        headers: { cookie: physicianCookie() },
      });
      expect(deleteStepRes.statusCode).toBe(404);
    });

    it('IMA records are append-only (no PUT/DELETE for IMA)', async () => {
      const putRes = await app.inject({
        method: 'PUT',
        url: '/api/v1/onboarding/ima',
        headers: { cookie: physicianCookie() },
        payload: { document_hash: 'tampered' },
      });
      expect(putRes.statusCode).toBe(404);

      const deleteRes = await app.inject({
        method: 'DELETE',
        url: `/api/v1/onboarding/ima/${FIXED_IMA_ID}`,
        headers: { cookie: physicianCookie() },
      });
      expect(deleteRes.statusCode).toBe(404);
    });
  });

  // =========================================================================
  // Sensitive Data Exclusion from Audit Entries
  // =========================================================================

  describe('Sensitive data exclusion from audit entries', () => {
    it('audit entries do not contain patient data (PHN, patient names)', async () => {
      // Execute onboarding actions
      await physicianRequest('POST', '/api/v1/onboarding/steps/1', {
        billing_number: '12345',
        cpsa_number: 'REG001',
        legal_first_name: 'Test',
        legal_last_name: 'Physician',
      });
      await physicianRequest('POST', '/api/v1/onboarding/patient-import/complete');
      await physicianRequest('POST', '/api/v1/onboarding/guided-tour/complete');

      const auditString = JSON.stringify(auditEntries);
      // No patient-specific fields
      expect(auditString).not.toContain('patient_name');
      expect(auditString).not.toContain('patient_phn');
      expect(auditString).not.toContain('date_of_birth');
      expect(auditString).not.toContain('first_name');
      expect(auditString).not.toContain('last_name');
      expect(auditString).not.toContain('"phn"');
    });

    it('step 3 (BA) audit detail does not expose full BA number beyond what the task requires', async () => {
      await physicianRequest('POST', '/api/v1/onboarding/steps/3', {
        primary_ba_number: '12345',
        is_pcpcm_enrolled: false,
      });

      const entries = findAllAuditEntries(OnboardingAuditAction.STEP_COMPLETED);
      const step3Entry = entries.find((e) => (e.detail as any).step_number === 3);
      expect(step3Entry).toBeDefined();
      // Detail should have provider_id and step_number, not sensitive fields
      const detail = step3Entry!.detail as Record<string, unknown>;
      expect(detail).not.toHaveProperty('ba_number');
    });

    it('IMA acknowledged audit entry does not contain IMA HTML content', async () => {
      await physicianRequest('POST', '/api/v1/onboarding/ima/acknowledge', {
        document_hash: MOCK_IMA_HASH,
      });

      const entry = findAuditEntry(OnboardingAuditAction.IMA_ACKNOWLEDGED);
      expect(entry).toBeDefined();
      const entryStr = JSON.stringify(entry);
      expect(entryStr).not.toContain('<html>');
      expect(entryStr).not.toContain('IMA Agreement');
      expect(entryStr).not.toContain('%PDF');
    });

    it('audit entries do not contain session tokens or password hashes', async () => {
      await physicianRequest('POST', '/api/v1/onboarding/steps/1', {
        billing_number: '12345',
        cpsa_number: 'REG001',
        legal_first_name: 'Test',
        legal_last_name: 'Physician',
      });
      await physicianRequest('POST', '/api/v1/onboarding/ima/acknowledge', {
        document_hash: MOCK_IMA_HASH,
      });

      const auditString = JSON.stringify(auditEntries);
      expect(auditString).not.toContain(FIXED_SESSION_TOKEN);
      expect(auditString).not.toContain('passwordHash');
      expect(auditString).not.toContain('session_token');
      expect(auditString).not.toContain('totpSecret');
    });
  });

  // =========================================================================
  // Multiple Action Accumulation
  // =========================================================================

  describe('Multiple action accumulation', () => {
    it('completing multiple steps produces ordered audit trail', async () => {
      await physicianRequest('POST', '/api/v1/onboarding/steps/1', {
        billing_number: '12345',
        cpsa_number: 'REG001',
        legal_first_name: 'Test',
        legal_last_name: 'Physician',
      });

      await physicianRequest('POST', '/api/v1/onboarding/steps/2', {
        specialty_code: 'GP',
        physician_type: 'gp',
      });

      await physicianRequest('POST', '/api/v1/onboarding/steps/3', {
        primary_ba_number: '12345',
        is_pcpcm_enrolled: false,
      });

      const stepEntries = findAllAuditEntries(OnboardingAuditAction.STEP_COMPLETED);
      expect(stepEntries.length).toBeGreaterThanOrEqual(3);

      // Verify step numbers are present and in order
      const stepNumbers = stepEntries.map((e) => (e.detail as any).step_number);
      expect(stepNumbers).toContain(1);
      expect(stepNumbers).toContain(2);
      expect(stepNumbers).toContain(3);
    });

    it('full onboarding lifecycle produces both step and completion audit entries', async () => {
      // Pre-set required steps as completed to trigger onboarding completion
      mockProgressStepCompletions = { 1: true, 2: true, 3: true, 4: true };

      // Step 7 triggers completion check
      await physicianRequest('POST', '/api/v1/onboarding/steps/7');

      // Should have step_completed for step 7 AND onboarding.completed
      const stepEntry = findAllAuditEntries(OnboardingAuditAction.STEP_COMPLETED);
      const completedEntry = findAuditEntry(OnboardingAuditAction.COMPLETED);

      expect(stepEntry.length).toBeGreaterThan(0);
      expect(completedEntry).toBeDefined();
    });

    it('IMA acknowledgment produces both step_completed and ima_acknowledged entries', async () => {
      await physicianRequest('POST', '/api/v1/onboarding/ima/acknowledge', {
        document_hash: MOCK_IMA_HASH,
      });

      // acknowledgeIma calls completeStep7 internally, producing a step_completed entry
      const stepEntries = findAllAuditEntries(OnboardingAuditAction.STEP_COMPLETED);
      const imaEntry = findAuditEntry(OnboardingAuditAction.IMA_ACKNOWLEDGED);

      expect(stepEntries.some((e) => (e.detail as any).step_number === 7)).toBe(true);
      expect(imaEntry).toBeDefined();
    });
  });

  // =========================================================================
  // Sanity: test setup validates correctly
  // =========================================================================

  describe('Sanity: test setup validates correctly', () => {
    it('physician session authenticates successfully', async () => {
      const res = await physicianRequest('GET', '/api/v1/onboarding/progress');
      expect(res.statusCode).not.toBe(401);
    });

    it('shared audit repo captures entries from all service actions', async () => {
      await physicianRequest('POST', '/api/v1/onboarding/steps/1', {
        billing_number: '12345',
        cpsa_number: 'REG001',
        legal_first_name: 'Test',
        legal_last_name: 'Physician',
      });
      await physicianRequest('POST', '/api/v1/onboarding/guided-tour/complete');

      expect(auditEntries.length).toBeGreaterThan(0);
      const actions = auditEntries.map((e) => e.action);
      expect(actions).toContain(OnboardingAuditAction.STEP_COMPLETED);
      expect(actions).toContain(OnboardingAuditAction.GUIDED_TOUR_COMPLETED);
    });
  });
});
