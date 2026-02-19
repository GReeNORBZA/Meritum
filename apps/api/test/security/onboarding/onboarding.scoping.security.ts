import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

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
import { randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Fixed test identities — Two isolated physicians
// ---------------------------------------------------------------------------

// Physician 1 — "our" physician
const P1_SESSION_TOKEN = randomBytes(32).toString('hex');
const P1_SESSION_TOKEN_HASH = hashToken(P1_SESSION_TOKEN);
const P1_USER_ID = '11111111-1111-0000-0000-000000000001';
const P1_PROVIDER_ID = '11111111-1111-0000-0000-000000000011';
const P1_SESSION_ID = '11111111-1111-0000-0000-000000000021';

// Physician 2 — "other" physician (attacker perspective)
const P2_SESSION_TOKEN = randomBytes(32).toString('hex');
const P2_SESSION_TOKEN_HASH = hashToken(P2_SESSION_TOKEN);
const P2_USER_ID = '22222222-2222-0000-0000-000000000002';
const P2_PROVIDER_ID = '22222222-2222-0000-0000-000000000022';
const P2_SESSION_ID = '22222222-2222-0000-0000-000000000032';

// ---------------------------------------------------------------------------
// Test data IDs — resources owned by each physician
// ---------------------------------------------------------------------------

// BA IDs
const P1_BA_ID = 'aaaa1111-0000-0000-0000-000000000001';
const P2_BA_ID = 'aaaa2222-0000-0000-0000-000000000002';

// IMA record IDs
const P1_IMA_ID = 'bbbb1111-0000-0000-0000-000000000001';
const P2_IMA_ID = 'bbbb2222-0000-0000-0000-000000000002';

// Progress record IDs
const P1_PROGRESS_ID = 'cccc1111-0000-0000-0000-000000000001';
const P2_PROGRESS_ID = 'cccc2222-0000-0000-0000-000000000002';

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
  role: string;
  subscriptionStatus: string;
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

interface MockProgress {
  progressId: string;
  providerId: string;
  step1Completed: boolean;
  step2Completed: boolean;
  step3Completed: boolean;
  step4Completed: boolean;
  step5Completed: boolean;
  step6Completed: boolean;
  step7Completed: boolean;
  patientImportCompleted: boolean;
  guidedTourCompleted: boolean;
  guidedTourDismissed: boolean;
  startedAt: Date;
  completedAt: Date | null;
}

interface MockBa {
  baId: string;
  providerId: string;
  baNumber: string;
  baType: string;
  isPrimary: boolean;
  status: string;
}

interface MockImaRecord {
  imaId: string;
  providerId: string;
  templateVersion: string;
  documentHash: string;
  ipAddress: string;
  userAgent: string;
  acknowledgedAt: Date;
}

let users: MockUser[] = [];
let sessions: MockSession[] = [];
let auditEntries: Array<Record<string, unknown>> = [];

// Physician-scoped stores
const progressStore: Record<string, MockProgress> = {};
const baStore: Record<string, MockBa> = {};
const imaStore: Record<string, MockImaRecord> = {};

// ---------------------------------------------------------------------------
// Mock repositories
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    createSession: vi.fn(async () => ({ sessionId: 'new-session-id' })),
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      const session = sessions.find((s) => s.tokenHash === tokenHash && !s.revoked);
      if (!session) return undefined;
      const user = users.find((u) => u.userId === session.userId);
      if (!user) return undefined;
      return {
        session,
        user: {
          userId: user.userId,
          role: user.role,
          subscriptionStatus: user.subscriptionStatus,
        },
      };
    }),
    refreshSession: vi.fn(async () => {}),
    listActiveSessions: vi.fn(async () => []),
    revokeSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
  };
}

function createMockAuditRepo() {
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
// Mock onboarding repository (physician-scoped)
// ---------------------------------------------------------------------------

function createScopedOnboardingRepo() {
  return {
    createProgress: vi.fn(async (providerId: string) => {
      const id = crypto.randomUUID();
      const progress: MockProgress = {
        progressId: id,
        providerId,
        step1Completed: false,
        step2Completed: false,
        step3Completed: false,
        step4Completed: false,
        step5Completed: false,
        step6Completed: false,
        step7Completed: false,
        patientImportCompleted: false,
        guidedTourCompleted: false,
        guidedTourDismissed: false,
        startedAt: new Date(),
        completedAt: null,
      };
      progressStore[id] = progress;
      return progress;
    }),

    findProgressByProviderId: vi.fn(async (providerId: string) => {
      return Object.values(progressStore).find(
        (p) => p.providerId === providerId,
      ) ?? null;
    }),

    markStepCompleted: vi.fn(async (providerId: string, stepNumber: number) => {
      const progress = Object.values(progressStore).find(
        (p) => p.providerId === providerId,
      );
      if (!progress) return null;
      const colName = `step${stepNumber}Completed` as keyof MockProgress;
      (progress as any)[colName] = true;
      return progress;
    }),

    markOnboardingCompleted: vi.fn(async (providerId: string) => {
      const progress = Object.values(progressStore).find(
        (p) => p.providerId === providerId,
      );
      if (!progress) return null;
      progress.completedAt = new Date();
      return progress;
    }),

    markPatientImportCompleted: vi.fn(async (providerId: string) => {
      const progress = Object.values(progressStore).find(
        (p) => p.providerId === providerId,
      );
      if (!progress) return null;
      progress.patientImportCompleted = true;
      return progress;
    }),

    markGuidedTourCompleted: vi.fn(async (providerId: string) => {
      const progress = Object.values(progressStore).find(
        (p) => p.providerId === providerId,
      );
      if (!progress) return null;
      progress.guidedTourCompleted = true;
      return progress;
    }),

    markGuidedTourDismissed: vi.fn(async (providerId: string) => {
      const progress = Object.values(progressStore).find(
        (p) => p.providerId === providerId,
      );
      if (!progress) return null;
      progress.guidedTourDismissed = true;
      return progress;
    }),

    createImaRecord: vi.fn(async (data: any) => {
      const id = crypto.randomUUID();
      const record: MockImaRecord = {
        imaId: id,
        providerId: data.providerId,
        templateVersion: data.templateVersion,
        documentHash: data.documentHash,
        ipAddress: data.ipAddress,
        userAgent: data.userAgent,
        acknowledgedAt: new Date(),
      };
      imaStore[id] = record;
      return record;
    }),

    findLatestImaRecord: vi.fn(async (providerId: string) => {
      const records = Object.values(imaStore)
        .filter((r) => r.providerId === providerId)
        .sort((a, b) => b.acknowledgedAt.getTime() - a.acknowledgedAt.getTime());
      return records[0] ?? null;
    }),

    listImaRecords: vi.fn(async (providerId: string) => {
      return Object.values(imaStore)
        .filter((r) => r.providerId === providerId)
        .sort((a, b) => b.acknowledgedAt.getTime() - a.acknowledgedAt.getTime());
    }),
  };
}

// ---------------------------------------------------------------------------
// Mock provider service (physician-scoped)
// ---------------------------------------------------------------------------

function createScopedProviderService() {
  return {
    createOrUpdateProvider: vi.fn(async (providerId: string) => {
      return { providerId };
    }),
    updateProviderSpecialty: vi.fn(async () => {}),
    createBa: vi.fn(async (providerId: string) => {
      return { baId: crypto.randomUUID() };
    }),
    createLocation: vi.fn(async () => ({ locationId: crypto.randomUUID() })),
    createWcbConfig: vi.fn(async () => ({ wcbConfigId: crypto.randomUUID() })),
    updateSubmissionPreferences: vi.fn(async () => {}),

    // CRITICAL: Maps userId to the correct providerId (physician scoping)
    findProviderByUserId: vi.fn(async (userId: string) => {
      if (userId === P1_USER_ID) return { providerId: P1_PROVIDER_ID };
      if (userId === P2_USER_ID) return { providerId: P2_PROVIDER_ID };
      return null;
    }),

    getProviderDetails: vi.fn(async (providerId: string) => {
      if (providerId === P1_PROVIDER_ID) {
        return {
          billingNumber: '11111',
          cpsaRegistrationNumber: 'CPSA-P1',
          firstName: 'Alice',
          lastName: 'Smith',
          baNumbers: ['BA-P1-001'],
        };
      }
      if (providerId === P2_PROVIDER_ID) {
        return {
          billingNumber: '22222',
          cpsaRegistrationNumber: 'CPSA-P2',
          firstName: 'Bob',
          lastName: 'Jones',
          baNumbers: ['BA-P2-001'],
        };
      }
      return null;
    }),

    // CRITICAL: BA lookup is scoped to providerId
    findBaById: vi.fn(async (baId: string, providerId: string) => {
      const ba = baStore[baId];
      if (!ba || ba.providerId !== providerId) return null;
      return ba;
    }),

    updateBaStatus: vi.fn(async (providerId: string, baId: string, status: string) => {
      const ba = baStore[baId];
      if (!ba || ba.providerId !== providerId) return null;
      ba.status = status;
      return { baId, status };
    }),
  };
}

// ---------------------------------------------------------------------------
// Mock reference data service
// ---------------------------------------------------------------------------

function createStubReferenceData() {
  return {
    validateSpecialtyCode: vi.fn(async () => true),
    validateFunctionalCentreCode: vi.fn(async () => true),
    validateCommunityCode: vi.fn(async () => true),
    getRrnpRate: vi.fn(async () => null),
    getWcbFormTypes: vi.fn(async () => ['C8', 'C10']),
  };
}

// ---------------------------------------------------------------------------
// Mock template renderer and PDF generator
// ---------------------------------------------------------------------------

function createMockTemplateRenderer() {
  return {
    render: vi.fn((template: string, data: Record<string, unknown>) => {
      // Return HTML that includes physician-specific details so we can verify isolation
      return `<html><body>IMA for ${data.physician_first_name} ${data.physician_last_name} (CPSA: ${data.cpsa_number})</body></html>`;
    }),
  };
}

function createMockPdfGenerator() {
  return {
    htmlToPdf: vi.fn(async (html: string) => {
      return Buffer.from(`PDF:${html}`, 'utf-8');
    }),
    generateAhc11236: vi.fn(async (data: any) => {
      return Buffer.from(
        `AHC11236:billing=${data.billingNumber},ba=${data.baNumber},name=${data.physicianName}`,
        'utf-8',
      );
    }),
  };
}

function createMockFileStorage() {
  const store: Record<string, Buffer> = {};
  return {
    store: vi.fn(async (key: string, data: Buffer) => {
      store[key] = data;
    }),
    retrieve: vi.fn(async (key: string) => {
      const data = store[key];
      if (!data) throw new Error(`File not found: ${key}`);
      return data;
    }),
    _store: store,
  };
}

// ---------------------------------------------------------------------------
// Stub service deps
// ---------------------------------------------------------------------------

let mockProviderService: ReturnType<typeof createScopedProviderService>;
let mockFileStorage: ReturnType<typeof createMockFileStorage>;

function createStubServiceDeps(): OnboardingServiceDeps {
  mockProviderService = createScopedProviderService();
  mockFileStorage = createMockFileStorage();

  return {
    repo: createScopedOnboardingRepo() as any,
    auditRepo: createMockAuditRepo(),
    events: createMockEvents(),
    providerService: mockProviderService,
    referenceData: createStubReferenceData(),
    templateRenderer: createMockTemplateRenderer(),
    pdfGenerator: createMockPdfGenerator(),
    fileStorage: mockFileStorage,
    imaTemplate: '<html>{{physician_first_name}} {{physician_last_name}}</html>',
    piaPdfBuffer: Buffer.from('PIA-STATIC-PDF', 'utf-8'),
    submitterPrefix: 'MRT',
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;

async function buildTestApp(): Promise<FastifyInstance> {
  const mockSessionRepo = createMockSessionRepo();

  const sessionDeps: SessionManagementDeps = {
    sessionRepo: mockSessionRepo,
    auditRepo: createMockAuditRepo(),
    events: createMockEvents(),
  };

  const handlerDeps: OnboardingHandlerDeps = {
    serviceDeps: createStubServiceDeps(),
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
// Request helpers
// ---------------------------------------------------------------------------

function asPhysician1(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function asPhysician2(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${P2_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

// ---------------------------------------------------------------------------
// Seed users and sessions
// ---------------------------------------------------------------------------

function seedUsersAndSessions() {
  users = [];
  sessions = [];
  auditEntries = [];

  // Physician 1
  users.push({
    userId: P1_USER_ID,
    email: 'physician1@example.com',
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    role: 'PHYSICIAN',
    subscriptionStatus: 'TRIAL',
  });
  sessions.push({
    sessionId: P1_SESSION_ID,
    userId: P1_USER_ID,
    tokenHash: P1_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

  // Physician 2
  users.push({
    userId: P2_USER_ID,
    email: 'physician2@example.com',
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    role: 'PHYSICIAN',
    subscriptionStatus: 'TRIAL',
  });
  sessions.push({
    sessionId: P2_SESSION_ID,
    userId: P2_USER_ID,
    tokenHash: P2_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.2',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });
}

// ---------------------------------------------------------------------------
// Seed test data — physician-scoped onboarding resources
// ---------------------------------------------------------------------------

function seedTestData() {
  // Clear stores
  Object.keys(progressStore).forEach((k) => delete progressStore[k]);
  Object.keys(baStore).forEach((k) => delete baStore[k]);
  Object.keys(imaStore).forEach((k) => delete imaStore[k]);

  // --- Physician 1's progress ---
  progressStore[P1_PROGRESS_ID] = {
    progressId: P1_PROGRESS_ID,
    providerId: P1_PROVIDER_ID,
    step1Completed: true,
    step2Completed: true,
    step3Completed: false,
    step4Completed: false,
    step5Completed: false,
    step6Completed: false,
    step7Completed: false,
    patientImportCompleted: false,
    guidedTourCompleted: false,
    guidedTourDismissed: false,
    startedAt: new Date(),
    completedAt: null,
  };

  // --- Physician 2's progress ---
  progressStore[P2_PROGRESS_ID] = {
    progressId: P2_PROGRESS_ID,
    providerId: P2_PROVIDER_ID,
    step1Completed: true,
    step2Completed: true,
    step3Completed: true,
    step4Completed: true,
    step5Completed: false,
    step6Completed: false,
    step7Completed: false,
    patientImportCompleted: false,
    guidedTourCompleted: false,
    guidedTourDismissed: false,
    startedAt: new Date(),
    completedAt: null,
  };

  // --- Physician 1's BA ---
  baStore[P1_BA_ID] = {
    baId: P1_BA_ID,
    providerId: P1_PROVIDER_ID,
    baNumber: 'BA-P1-001',
    baType: 'FFS',
    isPrimary: true,
    status: 'PENDING',
  };

  // --- Physician 2's BA ---
  baStore[P2_BA_ID] = {
    baId: P2_BA_ID,
    providerId: P2_PROVIDER_ID,
    baNumber: 'BA-P2-001',
    baType: 'FFS',
    isPrimary: true,
    status: 'PENDING',
  };

  // --- Physician 1's IMA record ---
  imaStore[P1_IMA_ID] = {
    imaId: P1_IMA_ID,
    providerId: P1_PROVIDER_ID,
    templateVersion: '1.0.0',
    documentHash: 'hash-p1-ima',
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    acknowledgedAt: new Date(),
  };

  // --- Physician 2's IMA record ---
  imaStore[P2_IMA_ID] = {
    imaId: P2_IMA_ID,
    providerId: P2_PROVIDER_ID,
    templateVersion: '1.0.0',
    documentHash: 'hash-p2-ima',
    ipAddress: '127.0.0.2',
    userAgent: 'test-agent',
    acknowledgedAt: new Date(),
  };

  // Pre-store IMA PDFs so download tests work
  if (mockFileStorage) {
    mockFileStorage._store[`ima/${P1_PROVIDER_ID}/${P1_IMA_ID}.pdf`] =
      Buffer.from('IMA-PDF-P1-Alice-Smith', 'utf-8');
    mockFileStorage._store[`ima/${P2_PROVIDER_ID}/${P2_IMA_ID}.pdf`] =
      Buffer.from('IMA-PDF-P2-Bob-Jones', 'utf-8');
  }
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Onboarding Physician Tenant Isolation — MOST CRITICAL (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    seedUsersAndSessions();
    seedTestData();
  });

  // =========================================================================
  // 1. Onboarding Progress Isolation
  // =========================================================================

  describe('Onboarding progress isolation — GET /progress', () => {
    it('physician1 GET /progress returns only physician1 progress', async () => {
      const res = await asPhysician1('GET', '/api/v1/onboarding/progress');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.provider_id).toBe(P1_PROVIDER_ID);
      // P1 has steps 1&2 completed, P2 has steps 1-4 completed
      expect(body.data.step_1_completed).toBe(true);
      expect(body.data.step_2_completed).toBe(true);
      expect(body.data.step_3_completed).toBe(false);
      expect(body.data.step_4_completed).toBe(false);
    });

    it('physician2 GET /progress returns only physician2 progress', async () => {
      const res = await asPhysician2('GET', '/api/v1/onboarding/progress');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.provider_id).toBe(P2_PROVIDER_ID);
      // P2 has steps 1-4 completed
      expect(body.data.step_1_completed).toBe(true);
      expect(body.data.step_2_completed).toBe(true);
      expect(body.data.step_3_completed).toBe(true);
      expect(body.data.step_4_completed).toBe(true);
    });

    it('physician1 progress response does not contain physician2 data', async () => {
      const res = await asPhysician1('GET', '/api/v1/onboarding/progress');
      expect(res.statusCode).toBe(200);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain(P2_PROGRESS_ID);
      expect(rawBody).not.toContain(P2_USER_ID);
    });

    it('physician2 progress response does not contain physician1 data', async () => {
      const res = await asPhysician2('GET', '/api/v1/onboarding/progress');
      expect(res.statusCode).toBe(200);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P1_PROVIDER_ID);
      expect(rawBody).not.toContain(P1_PROGRESS_ID);
      expect(rawBody).not.toContain(P1_USER_ID);
    });

    it('both physicians see different current_step values (isolation verified)', async () => {
      const res1 = await asPhysician1('GET', '/api/v1/onboarding/progress');
      const res2 = await asPhysician2('GET', '/api/v1/onboarding/progress');
      const body1 = JSON.parse(res1.body);
      const body2 = JSON.parse(res2.body);

      // P1 stopped at step 3, P2 should be at step 7 (required: 1,2,3,4,7)
      expect(body1.data.current_step).toBe(3);
      expect(body2.data.current_step).toBe(7);
    });
  });

  // =========================================================================
  // 2. Step Completion Isolation
  // =========================================================================

  describe('Step completion isolation — POST /steps/:step_number', () => {
    it('physician1 completing step 1 does not affect physician2 progress', async () => {
      // Get physician2 progress before physician1 acts
      const before = await asPhysician2('GET', '/api/v1/onboarding/progress');
      const beforeBody = JSON.parse(before.body);
      const p2StepsBefore = {
        s1: beforeBody.data.step_1_completed,
        s2: beforeBody.data.step_2_completed,
        s3: beforeBody.data.step_3_completed,
        s4: beforeBody.data.step_4_completed,
        s5: beforeBody.data.step_5_completed,
        s6: beforeBody.data.step_6_completed,
        s7: beforeBody.data.step_7_completed,
      };

      // Physician1 completes step 7 (IMA acknowledgement — no body needed)
      await asPhysician1('POST', '/api/v1/onboarding/steps/7');

      // Get physician2 progress after physician1 acted
      const after = await asPhysician2('GET', '/api/v1/onboarding/progress');
      const afterBody = JSON.parse(after.body);

      // Physician2's progress must be unchanged
      expect(afterBody.data.step_1_completed).toBe(p2StepsBefore.s1);
      expect(afterBody.data.step_2_completed).toBe(p2StepsBefore.s2);
      expect(afterBody.data.step_3_completed).toBe(p2StepsBefore.s3);
      expect(afterBody.data.step_4_completed).toBe(p2StepsBefore.s4);
      expect(afterBody.data.step_5_completed).toBe(p2StepsBefore.s5);
      expect(afterBody.data.step_6_completed).toBe(p2StepsBefore.s6);
      expect(afterBody.data.step_7_completed).toBe(p2StepsBefore.s7);
    });

    it('physician1 step completion response only contains physician1 provider_id', async () => {
      const res = await asPhysician1('POST', '/api/v1/onboarding/steps/7');
      // May be 200 (success) or other — check it doesn't contain P2 data
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain(P2_USER_ID);
      expect(rawBody).not.toContain(P2_PROGRESS_ID);
    });

    it('physician2 step completion response only contains physician2 provider_id', async () => {
      const res = await asPhysician2('POST', '/api/v1/onboarding/steps/7');
      const rawBody = res.body;
      expect(rawBody).not.toContain(P1_PROVIDER_ID);
      expect(rawBody).not.toContain(P1_USER_ID);
      expect(rawBody).not.toContain(P1_PROGRESS_ID);
    });
  });

  // =========================================================================
  // 3. IMA Isolation — GET /ima
  // =========================================================================

  describe('IMA isolation — GET /ima', () => {
    it('physician1 GET /ima returns IMA pre-filled with physician1 details only', async () => {
      const res = await asPhysician1('GET', '/api/v1/onboarding/ima');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      // Verify P1 details are present
      expect(body.data.content).toContain('Alice');
      expect(body.data.content).toContain('Smith');
      // Verify P2 details are NOT present
      expect(body.data.content).not.toContain('Bob');
      expect(body.data.content).not.toContain('Jones');
      expect(body.data.content).not.toContain('CPSA-P2');
    });

    it('physician2 GET /ima returns IMA pre-filled with physician2 details only', async () => {
      const res = await asPhysician2('GET', '/api/v1/onboarding/ima');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      // Verify P2 details are present
      expect(body.data.content).toContain('Bob');
      expect(body.data.content).toContain('Jones');
      // Verify P1 details are NOT present
      expect(body.data.content).not.toContain('Alice');
      expect(body.data.content).not.toContain('Smith');
      expect(body.data.content).not.toContain('CPSA-P1');
    });

    it('physician1 IMA response does not contain physician2 identifiers', async () => {
      const res = await asPhysician1('GET', '/api/v1/onboarding/ima');
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain(P2_USER_ID);
      expect(rawBody).not.toContain('22222'); // P2 billing number
    });
  });

  // =========================================================================
  // 4. IMA Download Isolation — GET /ima/download
  // =========================================================================

  describe('IMA download isolation — GET /ima/download', () => {
    it('physician1 GET /ima/download returns only physician1 IMA PDF', async () => {
      const res = await asPhysician1('GET', '/api/v1/onboarding/ima/download');
      expect(res.statusCode).toBe(200);
      expect(res.headers['content-type']).toContain('application/pdf');
      // PDF contains P1 name
      const pdfContent = res.body;
      expect(pdfContent).toContain('Alice');
      expect(pdfContent).toContain('Smith');
      // PDF does NOT contain P2 data
      expect(pdfContent).not.toContain('Bob');
      expect(pdfContent).not.toContain('Jones');
      expect(pdfContent).not.toContain(P2_PROVIDER_ID);
    });

    it('physician2 GET /ima/download returns only physician2 IMA PDF', async () => {
      const res = await asPhysician2('GET', '/api/v1/onboarding/ima/download');
      expect(res.statusCode).toBe(200);
      expect(res.headers['content-type']).toContain('application/pdf');
      const pdfContent = res.body;
      expect(pdfContent).toContain('Bob');
      expect(pdfContent).toContain('Jones');
      expect(pdfContent).not.toContain('Alice');
      expect(pdfContent).not.toContain('Smith');
      expect(pdfContent).not.toContain(P1_PROVIDER_ID);
    });

    it('physician1 cannot download physician2 IMA (scoped to authenticated provider)', async () => {
      // Both physicians request their own IMA — verify PDFs are different
      const res1 = await asPhysician1('GET', '/api/v1/onboarding/ima/download');
      const res2 = await asPhysician2('GET', '/api/v1/onboarding/ima/download');

      expect(res1.statusCode).toBe(200);
      expect(res2.statusCode).toBe(200);

      // Content must be different (physician-specific)
      expect(res1.body).not.toBe(res2.body);
    });
  });

  // =========================================================================
  // 5. AHC11236 Download Isolation — GET /ahc11236/download
  // =========================================================================

  describe('AHC11236 download isolation — GET /ahc11236/download', () => {
    it('physician1 GET /ahc11236/download returns PDF with physician1 details only', async () => {
      const res = await asPhysician1('GET', '/api/v1/onboarding/ahc11236/download');
      expect(res.statusCode).toBe(200);
      expect(res.headers['content-type']).toContain('application/pdf');
      const pdfContent = res.body;
      // P1 billing number and name
      expect(pdfContent).toContain('11111');
      expect(pdfContent).toContain('Alice');
      expect(pdfContent).toContain('Smith');
      // NOT P2 data
      expect(pdfContent).not.toContain('22222');
      expect(pdfContent).not.toContain('Bob');
      expect(pdfContent).not.toContain('Jones');
    });

    it('physician2 GET /ahc11236/download returns PDF with physician2 details only', async () => {
      const res = await asPhysician2('GET', '/api/v1/onboarding/ahc11236/download');
      expect(res.statusCode).toBe(200);
      const pdfContent = res.body;
      // P2 billing number and name
      expect(pdfContent).toContain('22222');
      expect(pdfContent).toContain('Bob');
      expect(pdfContent).toContain('Jones');
      // NOT P1 data
      expect(pdfContent).not.toContain('11111');
      expect(pdfContent).not.toContain('Alice');
      expect(pdfContent).not.toContain('Smith');
    });

    it('physician1 and physician2 receive different AHC11236 PDFs', async () => {
      const res1 = await asPhysician1('GET', '/api/v1/onboarding/ahc11236/download');
      const res2 = await asPhysician2('GET', '/api/v1/onboarding/ahc11236/download');

      expect(res1.statusCode).toBe(200);
      expect(res2.statusCode).toBe(200);
      expect(res1.body).not.toBe(res2.body);
    });
  });

  // =========================================================================
  // 6. BA Confirmation Isolation — POST /ba/:ba_id/confirm-active
  // =========================================================================

  describe('BA confirmation isolation — POST /ba/:ba_id/confirm-active', () => {
    it('physician1 can confirm own BA as active', async () => {
      const res = await asPhysician1('POST', `/api/v1/onboarding/ba/${P1_BA_ID}/confirm-active`);
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.ba_id).toBe(P1_BA_ID);
      expect(body.data.status).toBe('ACTIVE');
    });

    it('physician1 POST /ba/:ba_id/confirm-active with physician2 BA ID returns 404', async () => {
      const res = await asPhysician1('POST', `/api/v1/onboarding/ba/${P2_BA_ID}/confirm-active`);
      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();
    });

    it('physician2 POST /ba/:ba_id/confirm-active with physician1 BA ID returns 404', async () => {
      const res = await asPhysician2('POST', `/api/v1/onboarding/ba/${P1_BA_ID}/confirm-active`);
      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();
    });

    it('cross-tenant BA confirmation response does not reveal BA details', async () => {
      const res = await asPhysician1('POST', `/api/v1/onboarding/ba/${P2_BA_ID}/confirm-active`);
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_BA_ID);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain('BA-P2-001');
      expect(rawBody).not.toContain('PENDING');
    });

    it('physician2 BA remains unchanged after physician1 cross-tenant confirmation attempt', async () => {
      // Attempt to confirm P2's BA as P1
      await asPhysician1('POST', `/api/v1/onboarding/ba/${P2_BA_ID}/confirm-active`);

      // Verify P2's BA is still PENDING via P2's session
      const res = await asPhysician2('POST', `/api/v1/onboarding/ba/${P2_BA_ID}/confirm-active`);
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      // P2 should still be able to confirm — BA wasn't modified by P1's attempt
      expect(body.data.ba_id).toBe(P2_BA_ID);
      expect(body.data.status).toBe('ACTIVE');
    });

    it('non-existent BA ID returns 404 (not 500)', async () => {
      const NONEXISTENT_UUID = '99999999-9999-9999-9999-999999999999';
      const res = await asPhysician1('POST', `/api/v1/onboarding/ba/${NONEXISTENT_UUID}/confirm-active`);
      expect(res.statusCode).toBe(404);
    });
  });

  // =========================================================================
  // 7. Cross-Tenant Access Returns 404 (NOT 403)
  // =========================================================================

  describe('Cross-tenant access returns 404 not 403 (prevents resource enumeration)', () => {
    it('BA confirmation cross-tenant returns 404 not 403', async () => {
      const res = await asPhysician1('POST', `/api/v1/onboarding/ba/${P2_BA_ID}/confirm-active`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('cross-tenant 404 response does not confirm resource existence', async () => {
      // The 404 for a cross-tenant BA should look identical to a 404 for
      // a truly non-existent BA — attacker cannot distinguish
      const crossTenantRes = await asPhysician1('POST', `/api/v1/onboarding/ba/${P2_BA_ID}/confirm-active`);
      const nonExistentRes = await asPhysician1(
        'POST',
        '/api/v1/onboarding/ba/99999999-9999-9999-9999-999999999999/confirm-active',
      );

      expect(crossTenantRes.statusCode).toBe(404);
      expect(nonExistentRes.statusCode).toBe(404);

      // Both responses should have the same shape
      const crossBody = JSON.parse(crossTenantRes.body);
      const nonExistBody = JSON.parse(nonExistentRes.body);
      expect(crossBody.error.code).toBe(nonExistBody.error.code);
    });
  });

  // =========================================================================
  // 8. Guided Tour Isolation
  // =========================================================================

  describe('Guided tour isolation', () => {
    it('physician1 completing guided tour does not affect physician2 progress', async () => {
      const before = await asPhysician2('GET', '/api/v1/onboarding/progress');
      const beforeBody = JSON.parse(before.body);
      expect(beforeBody.data.guided_tour_completed).toBe(false);

      // P1 completes guided tour
      await asPhysician1('POST', '/api/v1/onboarding/guided-tour/complete');

      const after = await asPhysician2('GET', '/api/v1/onboarding/progress');
      const afterBody = JSON.parse(after.body);
      expect(afterBody.data.guided_tour_completed).toBe(false);
    });

    it('physician1 dismissing guided tour does not affect physician2 progress', async () => {
      const before = await asPhysician2('GET', '/api/v1/onboarding/progress');
      const beforeBody = JSON.parse(before.body);
      expect(beforeBody.data.guided_tour_dismissed).toBe(false);

      // P1 dismisses guided tour
      await asPhysician1('POST', '/api/v1/onboarding/guided-tour/dismiss');

      const after = await asPhysician2('GET', '/api/v1/onboarding/progress');
      const afterBody = JSON.parse(after.body);
      expect(afterBody.data.guided_tour_dismissed).toBe(false);
    });
  });

  // =========================================================================
  // 9. Patient Import Completion Isolation
  // =========================================================================

  describe('Patient import completion isolation', () => {
    it('physician1 completing patient import does not affect physician2 progress', async () => {
      const before = await asPhysician2('GET', '/api/v1/onboarding/progress');
      const beforeBody = JSON.parse(before.body);
      expect(beforeBody.data.patient_import_completed).toBe(false);

      // P1 completes patient import
      await asPhysician1('POST', '/api/v1/onboarding/patient-import/complete');

      const after = await asPhysician2('GET', '/api/v1/onboarding/progress');
      const afterBody = JSON.parse(after.body);
      expect(afterBody.data.patient_import_completed).toBe(false);
    });
  });

  // =========================================================================
  // 10. Bidirectional Isolation
  // =========================================================================

  describe('Bidirectional isolation (both physicians verified)', () => {
    it('physician1 progress contains P1 provider_id and not P2 provider_id', async () => {
      const res = await asPhysician1('GET', '/api/v1/onboarding/progress');
      const body = JSON.parse(res.body);
      expect(body.data.provider_id).toBe(P1_PROVIDER_ID);
      expect(body.data.provider_id).not.toBe(P2_PROVIDER_ID);
    });

    it('physician2 progress contains P2 provider_id and not P1 provider_id', async () => {
      const res = await asPhysician2('GET', '/api/v1/onboarding/progress');
      const body = JSON.parse(res.body);
      expect(body.data.provider_id).toBe(P2_PROVIDER_ID);
      expect(body.data.provider_id).not.toBe(P1_PROVIDER_ID);
    });

    it('physician1 can confirm own BA while physician2 BA is unaffected', async () => {
      // P1 confirms own BA
      const p1Res = await asPhysician1('POST', `/api/v1/onboarding/ba/${P1_BA_ID}/confirm-active`);
      expect(p1Res.statusCode).toBe(200);

      // P2's BA should still be PENDING
      expect(baStore[P2_BA_ID].status).toBe('PENDING');
    });

    it('both physicians can independently complete steps without interference', async () => {
      // Both complete step 7
      const res1 = await asPhysician1('POST', '/api/v1/onboarding/steps/7');
      const res2 = await asPhysician2('POST', '/api/v1/onboarding/steps/7');

      // Both should succeed (or at least not error due to cross-tenant interference)
      expect(res1.statusCode).toBeLessThan(500);
      expect(res2.statusCode).toBeLessThan(500);

      // Verify progress is independent
      const p1 = await asPhysician1('GET', '/api/v1/onboarding/progress');
      const p2 = await asPhysician2('GET', '/api/v1/onboarding/progress');
      const p1Body = JSON.parse(p1.body);
      const p2Body = JSON.parse(p2.body);

      // P1 still has steps 3/4 incomplete, P2 does not
      expect(p1Body.data.step_3_completed).toBe(false);
      expect(p2Body.data.step_3_completed).toBe(true);
    });
  });

  // =========================================================================
  // 11. Response Isolation — No Cross-Tenant Identifiers
  // =========================================================================

  describe('Response body never leaks cross-tenant identifiers', () => {
    it('physician1 progress response contains no P2 identifiers', async () => {
      const res = await asPhysician1('GET', '/api/v1/onboarding/progress');
      expect(res.statusCode).toBe(200);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain(P2_USER_ID);
      expect(rawBody).not.toContain(P2_PROGRESS_ID);
    });

    it('physician1 IMA response contains no P2 identifiers', async () => {
      const res = await asPhysician1('GET', '/api/v1/onboarding/ima');
      expect(res.statusCode).toBe(200);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain(P2_USER_ID);
      expect(rawBody).not.toContain('Bob');
      expect(rawBody).not.toContain('Jones');
    });

    it('physician1 AHC11236 response contains no P2 identifiers', async () => {
      const res = await asPhysician1('GET', '/api/v1/onboarding/ahc11236/download');
      expect(res.statusCode).toBe(200);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain('22222');
      expect(rawBody).not.toContain('Bob');
      expect(rawBody).not.toContain('Jones');
    });

    it('physician1 BA confirmation response contains no P2 identifiers', async () => {
      const res = await asPhysician1('POST', `/api/v1/onboarding/ba/${P1_BA_ID}/confirm-active`);
      expect(res.statusCode).toBe(200);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain(P2_BA_ID);
      expect(rawBody).not.toContain('BA-P2-001');
    });
  });
});
