import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

// ---------------------------------------------------------------------------
// Environment setup (must be before imports that read env)
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);

// ---------------------------------------------------------------------------
// Mock otplib
// ---------------------------------------------------------------------------

vi.mock('otplib', () => {
  const mockAuthenticator = {
    options: {},
    generateSecret: vi.fn(() => 'JBSWY3DPEHPK3PXP'),
    keyuri: vi.fn(
      (email: string, issuer: string, secret: string) =>
        `otpauth://totp/${issuer}:${email}?secret=${secret}&issuer=${issuer}`,
    ),
    verify: vi.fn(({ token }: { token: string }) => token === '123456'),
  };
  return { authenticator: mockAuthenticator };
});

// ---------------------------------------------------------------------------
// Real imports (after mocks are hoisted)
// ---------------------------------------------------------------------------

import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { wcbRoutes } from '../../../src/domains/wcb/wcb.routes.js';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { type WcbHandlerDeps } from '../../../src/domains/wcb/wcb.handlers.js';
import {
  type SessionManagementDeps,
  hashToken,
} from '../../../src/domains/iam/iam.service.js';
import { randomBytes } from 'node:crypto';

import {
  createWcbClaim,
  updateWcbClaim,
  deleteWcbClaim,
  assembleAndGenerateBatch,
  validateBatchXsd,
  generateDownloadUrl,
  confirmBatchUpload,
  processReturnFile,
  processRemittanceFile,
  generateMvpExport,
  recordManualOutcome,
  type WcbServiceDeps,
} from '../../../src/domains/wcb/wcb.service.js';

import {
  WcbAuditAction,
  WcbFormType,
  WcbBatchStatus,
  WcbPhase,
} from '@meritum/shared/constants/wcb.constants.js';
import { ClaimState } from '@meritum/shared/constants/claim.constants.js';

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_USER_ID = '11111111-0000-0000-0000-000000000001';
const PHYSICIAN_SESSION_ID = '11111111-0000-0000-0000-000000000011';
const PHYSICIAN_PROVIDER_ID = PHYSICIAN_USER_ID;

const DELEGATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_SESSION_TOKEN_HASH = hashToken(DELEGATE_SESSION_TOKEN);
const DELEGATE_USER_ID = '22222222-0000-0000-0000-000000000002';
const DELEGATE_SESSION_ID = '22222222-0000-0000-0000-000000000022';

const PLACEHOLDER_UUID = '00000000-0000-0000-0000-000000000001';
const PLACEHOLDER_PATIENT_ID = '00000000-0000-0000-0000-000000000010';

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
  delegateContext?: {
    delegateUserId: string;
    physicianProviderId: string;
    permissions: string[];
    linkageId: string;
  };
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
let claimAuditEntries: Array<Record<string, unknown>> = [];

// ---------------------------------------------------------------------------
// UUID generator
// ---------------------------------------------------------------------------

function generateUuid(): string {
  return 'aaaaaaaa-bbbb-cccc-dddd-' + Math.random().toString(36).substring(2, 14).padEnd(12, '0');
}

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
      const result: any = {
        session,
        user: {
          userId: user.userId,
          role: user.role,
          subscriptionStatus: user.subscriptionStatus,
        },
      };
      if (user.delegateContext) {
        result.user.delegateContext = user.delegateContext;
      }
      return result;
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
// In-memory stores for WCB domain
// ---------------------------------------------------------------------------

let claimStore: Record<string, any>[] = [];
let wcbDetailStore: Record<string, any>[] = [];
let batchStore: Record<string, any>[] = [];
let returnRecordStore: Record<string, any>[] = [];
let remittanceImportStore: Record<string, any>[] = [];
let notificationEvents: Array<{ event: string; payload: Record<string, unknown> }> = [];
let batchStatusUpdates: Array<{
  batchId: string;
  physicianId: string;
  status: string;
  extraFields?: Record<string, unknown>;
}> = [];

// ---------------------------------------------------------------------------
// Mock WCB Repository
// ---------------------------------------------------------------------------

function createMockWcbRepo() {
  return {
    createWcbClaim: vi.fn(async (data: any) => {
      const detail = {
        wcbClaimDetailId: generateUuid(),
        claimId: data.claimId,
        formId: data.formId,
        submitterTxnId: 'MRT' + randomBytes(6).toString('hex').substring(0, 13),
        ...data,
        deletedAt: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      wcbDetailStore.push(detail);
      return detail;
    }),
    getWcbClaim: vi.fn(async (wcbClaimDetailId: string, physicianId: string) => {
      const detail = wcbDetailStore.find(
        (d) => d.wcbClaimDetailId === wcbClaimDetailId && !d.deletedAt,
      );
      if (!detail) return null;
      const claim = claimStore.find(
        (c) => c.claimId === detail.claimId && c.physicianId === physicianId,
      );
      if (!claim) return null;
      return {
        detail,
        claim: {
          claimId: claim.claimId,
          physicianId: claim.physicianId,
          state: claim.state,
        },
        injuries: [],
        prescriptions: [],
        consultations: [],
        workRestrictions: [],
        invoiceLines: [],
        attachments: [],
      };
    }),
    updateWcbClaim: vi.fn(async (wcbClaimDetailId: string, physicianId: string, data: any) => {
      const detail = wcbDetailStore.find((d) => d.wcbClaimDetailId === wcbClaimDetailId);
      if (detail) Object.assign(detail, data, { updatedAt: new Date() });
      return detail;
    }),
    softDeleteWcbClaim: vi.fn(async (wcbClaimDetailId: string, physicianId: string) => {
      const detail = wcbDetailStore.find((d) => d.wcbClaimDetailId === wcbClaimDetailId);
      if (detail) {
        detail.deletedAt = new Date();
        return true;
      }
      return false;
    }),
    createBatch: vi.fn(async (physicianId: string, userId: string) => {
      const batch = {
        wcbBatchId: generateUuid(),
        physicianId,
        batchControlId: 'MER-B-' + randomBytes(4).toString('hex'),
        fileControlId: 'MER-20260215-' + randomBytes(3).toString('hex'),
        status: WcbBatchStatus.ASSEMBLING,
        reportCount: 0,
        xmlFilePath: null,
        xmlFileHash: null,
        uploadedAt: null,
        uploadedBy: null,
        returnFilePath: null,
        returnFileReceivedAt: null,
        createdAt: new Date(),
        updatedAt: new Date(),
        createdBy: userId,
      };
      batchStore.push(batch);
      return batch;
    }),
    getBatch: vi.fn(async (wcbBatchId: string, physicianId: string) => {
      return batchStore.find(
        (b) => b.wcbBatchId === wcbBatchId && b.physicianId === physicianId,
      ) ?? null;
    }),
    getBatchByControlId: vi.fn(async (controlId: string, physicianId: string) => {
      return batchStore.find(
        (b) => b.batchControlId === controlId && b.physicianId === physicianId,
      ) ?? null;
    }),
    listBatches: vi.fn(async () => ({
      data: [],
      pagination: { total: 0, page: 1, pageSize: 25, hasMore: false },
    })),
    updateBatchStatus: vi.fn(async (wcbBatchId: string, physicianId: string, status: string, extraFields?: any) => {
      batchStatusUpdates.push({ batchId: wcbBatchId, physicianId, status, extraFields });
      const batch = batchStore.find(
        (b) => b.wcbBatchId === wcbBatchId && b.physicianId === physicianId,
      );
      if (batch) {
        batch.status = status;
        if (extraFields) Object.assign(batch, extraFields);
      }
      return batch;
    }),
    setBatchUploaded: vi.fn(async (wcbBatchId: string, physicianId: string, userId: string) => {
      const batch = batchStore.find(
        (b) => b.wcbBatchId === wcbBatchId && b.physicianId === physicianId,
      );
      if (!batch) return null;
      if (batch.status !== WcbBatchStatus.VALIDATED) return null;
      batch.status = WcbBatchStatus.UPLOADED;
      batch.uploadedAt = new Date();
      batch.uploadedBy = userId;
      return batch;
    }),
    setBatchReturnReceived: vi.fn(async (wcbBatchId: string, physicianId: string, filePath: string) => {
      const batch = batchStore.find((b) => b.wcbBatchId === wcbBatchId);
      if (batch) {
        batch.status = WcbBatchStatus.RETURN_RECEIVED;
        batch.returnFilePath = filePath;
        batch.returnFileReceivedAt = new Date();
      }
      return batch;
    }),
    getQueuedClaimsForBatch: vi.fn(async (physicianId: string) => {
      return wcbDetailStore
        .filter((d) => !d.deletedAt)
        .map((d) => {
          const claim = claimStore.find((c) => c.claimId === d.claimId);
          if (!claim || claim.state !== ClaimState.QUEUED || claim.physicianId !== physicianId) return null;
          return { detail: d, claim };
        })
        .filter(Boolean);
    }),
    assignClaimsToBatch: vi.fn(async () => {}),
    getWcbClaimBySubmitterTxnId: vi.fn(async (txnId: string) => {
      const detail = wcbDetailStore.find((d) => d.submitterTxnId === txnId);
      if (!detail) return null;
      return detail;
    }),
    matchReturnToClaimBySubmitterTxnId: vi.fn(async (txnId: string) => {
      const detail = wcbDetailStore.find((d) => d.submitterTxnId === txnId);
      return detail?.wcbClaimDetailId ?? null;
    }),
    createReturnRecords: vi.fn(async (batchId: string, records: any[]) => {
      return records.map((r) => {
        const record = {
          wcbReturnRecordId: generateUuid(),
          wcbBatchId: batchId,
          ...r,
        };
        returnRecordStore.push(record);
        return record;
      });
    }),
    createReturnInvoiceLines: vi.fn(async () => {}),
    createRemittanceImport: vi.fn(async (physicianId: string) => {
      const id = generateUuid();
      remittanceImportStore.push({ importId: id, physicianId });
      return id;
    }),
    createRemittanceRecords: vi.fn(async () => {}),
    listRemittanceImports: vi.fn(async () => ({
      data: [],
      pagination: { total: 0, page: 1, pageSize: 25, hasMore: false },
    })),
    getRemittanceDiscrepancies: vi.fn(async () => []),
    updateWcbClaimNumber: vi.fn(async () => {}),
    matchRemittanceToClaimByTxnId: vi.fn(async () => null),
    listWcbClaimsForPhysician: vi.fn(async () => ({
      data: [],
      pagination: { total: 0, page: 1, pageSize: 25, hasMore: false },
    })),
    // Child record methods
    createInjuries: vi.fn(async () => []),
    createPrescriptions: vi.fn(async () => []),
    createConsultations: vi.fn(async () => []),
    createWorkRestrictions: vi.fn(async () => []),
    createInvoiceLines: vi.fn(async () => []),
    createAttachments: vi.fn(async () => []),
    deleteInjuries: vi.fn(async () => {}),
    deletePrescriptions: vi.fn(async () => {}),
    deleteConsultations: vi.fn(async () => {}),
    deleteWorkRestrictions: vi.fn(async () => {}),
    deleteInvoiceLines: vi.fn(async () => {}),
    deleteAttachments: vi.fn(async () => {}),
  };
}

// ---------------------------------------------------------------------------
// Mock Claim Repository
// ---------------------------------------------------------------------------

function createMockClaimRepo() {
  return {
    createClaim: vi.fn(async (data: any) => {
      const claim = {
        claimId: generateUuid(),
        physicianId: data.physicianId,
        patientId: data.patientId,
        claimType: data.claimType,
        state: ClaimState.DRAFT,
        importSource: data.importSource ?? 'MANUAL',
        dateOfService: data.dateOfService,
        submissionDeadline: data.submissionDeadline,
        createdAt: new Date(),
        createdBy: data.createdBy,
        updatedAt: new Date(),
        updatedBy: data.updatedBy,
        deletedAt: null,
      };
      claimStore.push(claim);
      return claim;
    }),
    findClaimById: vi.fn(async (claimId: string, physicianId: string) => {
      return claimStore.find(
        (c) => c.claimId === claimId && c.physicianId === physicianId && !c.deletedAt,
      ) ?? undefined;
    }),
    appendClaimAudit: vi.fn(async (entry: Record<string, unknown>) => {
      const auditEntry = {
        auditId: generateUuid(),
        ...entry,
        createdAt: new Date(),
      };
      claimAuditEntries.push(auditEntry);
      return auditEntry;
    }),
    transitionClaimState: vi.fn(async (claimId: string, physicianId: string, newState: string) => {
      const claim = claimStore.find(
        (c) => c.claimId === claimId && c.physicianId === physicianId,
      );
      if (claim) {
        const previous = claim.state;
        claim.state = newState;
        return { claimId, state: newState, previousState: previous };
      }
      return undefined;
    }),
  };
}

// ---------------------------------------------------------------------------
// Mock Provider & Patient Lookup
// ---------------------------------------------------------------------------

function createMockProviderLookup() {
  return {
    findProviderById: vi.fn(async () => ({
      providerId: PHYSICIAN_PROVIDER_ID,
      billingNumber: '123456',
      firstName: 'Test',
      lastName: 'Physician',
      status: 'ACTIVE',
      specialtyCode: 'GP',
      isRrnpQualified: false,
    })),
    getWcbConfigForForm: vi.fn(async () => ({
      wcbConfigId: generateUuid(),
      contractId: '000001',
      roleCode: 'GP',
    })),
  };
}

function createMockPatientLookup() {
  return {
    findPatientById: vi.fn(async () => ({
      patientId: PLACEHOLDER_PATIENT_ID,
      phn: '123456789',
      firstName: 'John',
      lastName: 'Doe',
      dateOfBirth: '1980-01-01',
      gender: 'M',
      isActive: true,
    })),
  };
}

// ---------------------------------------------------------------------------
// Service dependencies builder
// ---------------------------------------------------------------------------

let mockWcbRepo: ReturnType<typeof createMockWcbRepo>;
let mockClaimRepo: ReturnType<typeof createMockClaimRepo>;
let mockProviderLookup: ReturnType<typeof createMockProviderLookup>;
let mockPatientLookup: ReturnType<typeof createMockPatientLookup>;

function createServiceDeps(overrides?: Partial<WcbServiceDeps>): WcbServiceDeps {
  mockWcbRepo = createMockWcbRepo();
  mockClaimRepo = createMockClaimRepo();
  mockProviderLookup = createMockProviderLookup();
  mockPatientLookup = createMockPatientLookup();

  return {
    wcbRepo: mockWcbRepo as any,
    claimRepo: mockClaimRepo as any,
    providerLookup: mockProviderLookup as any,
    patientLookup: mockPatientLookup as any,
    auditEmitter: {
      emit: vi.fn(async () => {}),
    },
    notificationEmitter: {
      emit: vi.fn(async (event: string, payload: Record<string, unknown>) => {
        notificationEvents.push({ event, payload });
      }),
    },
    fileStorage: {
      storeEncrypted: vi.fn(async () => {}),
      readEncrypted: vi.fn(async () => Buffer.from('<xml>test</xml>', 'utf-8')),
    },
    secretsProvider: {
      getVendorSourceId: () => 'MERITUM',
      getSubmitterId: () => 'MRT',
    },
    xsdValidator: {
      validate: vi.fn(() => ({ valid: true, errors: [] })),
    },
    downloadUrlGenerator: {
      generateSignedUrl: vi.fn(async () => 'https://example.com/download/batch.xml?sig=abc123'),
    },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Test app builder (for HTTP-level audit integrity tests)
// ---------------------------------------------------------------------------

let app: FastifyInstance;

async function buildTestApp(): Promise<FastifyInstance> {
  const mockSessionRepo = createMockSessionRepo();

  const sessionDeps: SessionManagementDeps = {
    sessionRepo: mockSessionRepo,
    auditRepo: createMockAuditRepo(),
    events: createMockEvents(),
  };

  const deps = createServiceDeps();

  const handlerDeps: WcbHandlerDeps = {
    serviceDeps: deps,
    wcbPhase: WcbPhase.MVP,
  };

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  await testApp.register(authPluginFp, { sessionDeps });

  testApp.setErrorHandler((error, request, reply) => {
    if (error.statusCode && error.statusCode >= 400 && error.statusCode < 500) {
      return reply.code(error.statusCode).send({
        error: { code: (error as any).code ?? 'ERROR', message: error.message },
      });
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

  await testApp.register(wcbRoutes, { deps: handlerDeps });
  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function physicianRequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function lastAuditEntry(): Record<string, unknown> {
  return claimAuditEntries[claimAuditEntries.length - 1];
}

function auditEntriesForClaim(claimId: string): Array<Record<string, unknown>> {
  return claimAuditEntries.filter((e) => e.claimId === claimId);
}

function findAuditEntry(claimId: string, action: string): Record<string, unknown> | undefined {
  return claimAuditEntries.find((e) => e.claimId === claimId && e.action === action);
}

function findAuditEntryByAction(action: string): Record<string, unknown> | undefined {
  return claimAuditEntries.find((e) => e.action === action);
}

/** Seed a WCB claim in the mock store with a base claim + wcb detail. */
function seedWcbClaim(overrides?: Partial<Record<string, any>>): {
  claimId: string;
  wcbClaimDetailId: string;
  submitterTxnId: string;
} {
  const claimId = generateUuid();
  const wcbClaimDetailId = generateUuid();
  const submitterTxnId = 'MRT' + randomBytes(6).toString('hex').substring(0, 13);

  claimStore.push({
    claimId,
    physicianId: PHYSICIAN_PROVIDER_ID,
    patientId: PLACEHOLDER_PATIENT_ID,
    claimType: 'WCB',
    state: ClaimState.DRAFT,
    importSource: 'MANUAL',
    dateOfService: '2026-01-15',
    submissionDeadline: '2026-02-15',
    createdAt: new Date(),
    updatedAt: new Date(),
    deletedAt: null,
    ...overrides,
  });

  wcbDetailStore.push({
    wcbClaimDetailId,
    claimId,
    formId: WcbFormType.C050E,
    submitterTxnId,
    patientPhn: '123456789',
    patientFirstName: 'John',
    patientLastName: 'Doe',
    deletedAt: null,
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  });

  return { claimId, wcbClaimDetailId, submitterTxnId };
}

/** Seed a WCB batch in the given status. */
function seedBatch(overrides?: Partial<Record<string, unknown>>): Record<string, any> {
  const batch = {
    wcbBatchId: generateUuid(),
    physicianId: PHYSICIAN_PROVIDER_ID,
    batchControlId: 'MER-B-' + randomBytes(4).toString('hex'),
    fileControlId: 'MER-20260215-' + randomBytes(3).toString('hex'),
    status: WcbBatchStatus.ASSEMBLING,
    reportCount: 0,
    xmlFilePath: null,
    xmlFileHash: null,
    uploadedAt: null,
    uploadedBy: null,
    returnFilePath: null,
    returnFileReceivedAt: null,
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  };
  batchStore.push(batch);
  return batch;
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('WCB Audit Trail Completeness (Security)', () => {
  let deps: WcbServiceDeps;

  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    // Reset stores
    users = [];
    sessions = [];
    auditEntries = [];
    claimAuditEntries = [];
    claimStore = [];
    wcbDetailStore = [];
    batchStore = [];
    returnRecordStore = [];
    remittanceImportStore = [];
    notificationEvents = [];
    batchStatusUpdates = [];

    // Seed physician
    users.push({
      userId: PHYSICIAN_USER_ID,
      email: 'physician@example.com',
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
      sessionId: PHYSICIAN_SESSION_ID,
      userId: PHYSICIAN_USER_ID,
      tokenHash: PHYSICIAN_SESSION_TOKEN_HASH,
      ipAddress: '127.0.0.1',
      userAgent: 'test-agent',
      createdAt: new Date(),
      lastActiveAt: new Date(),
      revoked: false,
      revokedReason: null,
    });

    // Seed delegate
    users.push({
      userId: DELEGATE_USER_ID,
      email: 'delegate@example.com',
      passwordHash: 'hashed',
      mfaConfigured: true,
      totpSecretEncrypted: null,
      failedLoginCount: 0,
      lockedUntil: null,
      isActive: true,
      role: 'DELEGATE',
      subscriptionStatus: 'TRIAL',
      delegateContext: {
        delegateUserId: DELEGATE_USER_ID,
        physicianProviderId: PHYSICIAN_USER_ID,
        permissions: ['CLAIM_CREATE', 'CLAIM_VIEW', 'CLAIM_EDIT', 'CLAIM_DELETE', 'BATCH_APPROVE', 'BATCH_VIEW', 'WCB_BATCH_UPLOAD', 'REPORT_VIEW'],
        linkageId: '99999999-0000-0000-0000-000000000099',
      },
    });
    sessions.push({
      sessionId: DELEGATE_SESSION_ID,
      userId: DELEGATE_USER_ID,
      tokenHash: DELEGATE_SESSION_TOKEN_HASH,
      ipAddress: '127.0.0.1',
      userAgent: 'test-agent',
      createdAt: new Date(),
      lastActiveAt: new Date(),
      revoked: false,
      revokedReason: null,
    });

    // Create fresh service deps per test
    deps = createServiceDeps();
  });

  // =========================================================================
  // Category 1: Claim Events Produce Audit Records
  // =========================================================================

  describe('Claim events produce audit records', () => {
    it('WCB claim created produces WCB_FORM_CREATED audit entry with claim_id and form_id', async () => {
      const result = await createWcbClaim(
        deps,
        PHYSICIAN_PROVIDER_ID,
        PHYSICIAN_USER_ID,
        {
          form_id: WcbFormType.C050E,
          patient_id: PLACEHOLDER_PATIENT_ID,
          date_of_injury: '2026-01-10',
        },
      );

      expect(claimAuditEntries.length).toBeGreaterThanOrEqual(1);
      const entry = findAuditEntryByAction(WcbAuditAction.WCB_FORM_CREATED);
      expect(entry).toBeDefined();
      expect(entry!.claimId).toBeDefined();
      expect(entry!.actorId).toBe(PHYSICIAN_USER_ID);
      expect((entry!.changes as any).formId).toBe(WcbFormType.C050E);
      expect((entry!.changes as any).wcbClaimDetailId).toBeDefined();
    });

    it('WCB claim updated produces WCB_FORM_UPDATED audit entry with changed fields', async () => {
      // Create a claim first
      const created = await createWcbClaim(
        deps,
        PHYSICIAN_PROVIDER_ID,
        PHYSICIAN_USER_ID,
        {
          form_id: WcbFormType.C050E,
          patient_id: PLACEHOLDER_PATIENT_ID,
          date_of_injury: '2026-01-10',
        },
      );
      claimAuditEntries = []; // Clear creation audit

      await updateWcbClaim(
        deps,
        PHYSICIAN_PROVIDER_ID,
        PHYSICIAN_USER_ID,
        created.wcbClaimDetailId,
        { additional_comments: 'Updated comments' },
      );

      const entry = findAuditEntryByAction(WcbAuditAction.WCB_FORM_UPDATED);
      expect(entry).toBeDefined();
      expect(entry!.actorId).toBe(PHYSICIAN_USER_ID);
      expect((entry!.changes as any).wcbClaimDetailId).toBe(created.wcbClaimDetailId);
      expect((entry!.changes as any).updatedFields).toBeDefined();
      expect((entry!.changes as any).updatedFields).toContain('additional_comments');
    });

    it('WCB claim deleted produces audit entry with claim_id', async () => {
      const created = await createWcbClaim(
        deps,
        PHYSICIAN_PROVIDER_ID,
        PHYSICIAN_USER_ID,
        {
          form_id: WcbFormType.C050E,
          patient_id: PLACEHOLDER_PATIENT_ID,
          date_of_injury: '2026-01-10',
        },
      );
      claimAuditEntries = [];

      await deleteWcbClaim(
        deps,
        PHYSICIAN_PROVIDER_ID,
        PHYSICIAN_USER_ID,
        created.wcbClaimDetailId,
      );

      // Delete emits WCB_FORM_CREATED with action: 'soft_delete' in changes
      expect(claimAuditEntries.length).toBeGreaterThanOrEqual(1);
      const entry = lastAuditEntry();
      expect(entry.actorId).toBe(PHYSICIAN_USER_ID);
      expect((entry.changes as any).wcbClaimDetailId).toBe(created.wcbClaimDetailId);
      expect((entry.changes as any).action).toBe('soft_delete');
    });

    it('WCB claim validated via batch assembly emits WCB_BATCH_ASSEMBLED audit', async () => {
      // Seed a queued WCB claim
      const claim = seedWcbClaim({ state: ClaimState.QUEUED });
      const txnId = 'MRT' + randomBytes(8).toString('hex').substring(0, 13);
      // Make the getWcbClaim return full claim data with all required fields for validation
      deps = createServiceDeps();
      const fullClaim = {
        detail: {
          wcbClaimDetailId: claim.wcbClaimDetailId,
          formId: WcbFormType.C050E,
          submitterTxnId: txnId,
          contractId: '000001',
          roleCode: 'GP',
          patientPhn: '123456789',
          patientNoPhnFlag: 'N',
          patientFirstName: 'John',
          patientLastName: 'Doe',
          patientGender: 'M',
          patientDob: '1980-01-01',
          patientAddressLine1: '123 Main St',
          patientCity: 'Calgary',
          dateOfInjury: '2026-01-10',
          dateOfExamination: '2026-01-12',
          reportCompletionDate: '2026-01-12',
          practitionerBillingNumber: '123456',
          practitionerFirstName: 'Test',
          practitionerLastName: 'Physician',
          skillCode: '01',
          facilityType: 'C',
          symptoms: 'Lower back pain after lifting',
          objectiveFindings: 'Tenderness in lumbar region',
          currentDiagnosis: 'Lumbar strain',
        },
        claim: {
          claimId: claim.claimId,
          physicianId: PHYSICIAN_PROVIDER_ID,
          state: ClaimState.QUEUED,
        },
        injuries: [],
        prescriptions: [],
        consultations: [],
        workRestrictions: [],
        invoiceLines: [],
        attachments: [],
      };

      (deps.wcbRepo.getQueuedClaimsForBatch as any).mockResolvedValue([
        { detail: fullClaim.detail, claim: fullClaim.claim },
      ]);
      (deps.wcbRepo.getWcbClaim as any).mockResolvedValue(fullClaim);

      await assembleAndGenerateBatch(deps, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID);

      const entry = findAuditEntryByAction(WcbAuditAction.WCB_BATCH_ASSEMBLED);
      expect(entry).toBeDefined();
      expect(entry!.actorId).toBe(PHYSICIAN_USER_ID);
      expect((entry!.changes as any).wcbBatchId).toBeDefined();
      expect((entry!.changes as any).reportCount).toBeGreaterThan(0);
    });
  });

  // =========================================================================
  // Category 2: Batch Events Produce Audit Records
  // =========================================================================

  describe('Batch events produce audit records', () => {
    it('batch XSD validated (passed) produces WCB_BATCH_VALIDATED audit', async () => {
      const batch = seedBatch({ status: WcbBatchStatus.GENERATED, xmlFilePath: '/encrypted/batch.xml' });
      deps = createServiceDeps();

      // Mock the getBatch and file read for XSD validation
      (deps.wcbRepo.getBatch as any).mockResolvedValue(batch);

      const result = await validateBatchXsd(
        deps,
        batch.wcbBatchId,
        PHYSICIAN_PROVIDER_ID,
        { structural: '<xsd>structural</xsd>', data: '<xsd>data</xsd>' },
      );

      expect(result.passed).toBe(true);

      const entry = findAuditEntryByAction(WcbAuditAction.WCB_BATCH_VALIDATED);
      expect(entry).toBeDefined();
      expect(entry!.actorId).toBe(PHYSICIAN_PROVIDER_ID);
      expect((entry!.changes as any).wcbBatchId).toBe(batch.wcbBatchId);
      expect((entry!.changes as any).xsdValidationPassed).toBe(true);
    });

    it('batch XSD validated (failed) produces WCB_BATCH_VALIDATED audit with error_count', async () => {
      const batch = seedBatch({ status: WcbBatchStatus.GENERATED, xmlFilePath: '/encrypted/batch.xml' });
      deps = createServiceDeps();

      (deps.wcbRepo.getBatch as any).mockResolvedValue(batch);
      // Make XSD validation fail
      (deps.xsdValidator!.validate as any).mockReturnValue({
        valid: false,
        errors: [{ message: 'Invalid element' }],
      });

      const result = await validateBatchXsd(
        deps,
        batch.wcbBatchId,
        PHYSICIAN_PROVIDER_ID,
        { structural: '<xsd>structural</xsd>', data: '<xsd>data</xsd>' },
      );

      expect(result.passed).toBe(false);

      const entry = findAuditEntryByAction(WcbAuditAction.WCB_BATCH_VALIDATED);
      expect(entry).toBeDefined();
      expect((entry!.changes as any).xsdValidationPassed).toBe(false);
      expect((entry!.changes as any).errorCount).toBeGreaterThan(0);
    });

    it('batch downloaded produces WCB_BATCH_DOWNLOADED audit with actor', async () => {
      const batch = seedBatch({ status: WcbBatchStatus.VALIDATED, xmlFilePath: '/encrypted/batch.xml' });
      deps = createServiceDeps();

      (deps.wcbRepo.getBatch as any).mockResolvedValue(batch);

      await generateDownloadUrl(
        deps,
        batch.wcbBatchId,
        PHYSICIAN_PROVIDER_ID,
        PHYSICIAN_USER_ID,
      );

      const entry = findAuditEntryByAction(WcbAuditAction.WCB_BATCH_DOWNLOADED);
      expect(entry).toBeDefined();
      expect(entry!.actorId).toBe(PHYSICIAN_USER_ID);
      expect((entry!.changes as any).wcbBatchId).toBe(batch.wcbBatchId);
      expect((entry!.changes as any).expiresAt).toBeDefined();
    });

    it('batch upload confirmed produces WCB_BATCH_UPLOADED audit with actor and timestamp', async () => {
      const batch = seedBatch({ status: WcbBatchStatus.VALIDATED });
      deps = createServiceDeps();

      (deps.wcbRepo.setBatchUploaded as any).mockResolvedValue({
        ...batch,
        status: WcbBatchStatus.UPLOADED,
        uploadedAt: new Date(),
        uploadedBy: PHYSICIAN_USER_ID,
        reportCount: 3,
      });

      await confirmBatchUpload(
        deps,
        batch.wcbBatchId,
        PHYSICIAN_PROVIDER_ID,
        PHYSICIAN_USER_ID,
      );

      const entry = findAuditEntryByAction(WcbAuditAction.WCB_BATCH_UPLOADED);
      expect(entry).toBeDefined();
      expect(entry!.actorId).toBe(PHYSICIAN_USER_ID);
      expect((entry!.changes as any).wcbBatchId).toBe(batch.wcbBatchId);
      expect((entry!.changes as any).uploadedBy).toBe(PHYSICIAN_USER_ID);
      expect((entry!.changes as any).uploadedAt).toBeDefined();
    });
  });

  // =========================================================================
  // Category 3: Return / Remittance Events Produce Audit Records
  // =========================================================================

  describe('Return/remittance events produce audit records', () => {
    it('return file processed produces WCB_RETURN_RECEIVED audit with matched_count', async () => {
      const claim = seedWcbClaim({ state: ClaimState.SUBMITTED });
      const batch = seedBatch({
        status: WcbBatchStatus.UPLOADED,
        batchControlId: 'BATCH-001',
      });

      deps = createServiceDeps();
      (deps.wcbRepo.getBatchByControlId as any).mockResolvedValue(batch);
      (deps.wcbRepo.matchReturnToClaimBySubmitterTxnId as any).mockResolvedValue(claim.wcbClaimDetailId);
      (deps.wcbRepo.getWcbClaimBySubmitterTxnId as any).mockResolvedValue({
        wcbClaimDetailId: claim.wcbClaimDetailId,
        claimId: claim.claimId,
      });
      (deps.wcbRepo.createReturnRecords as any).mockResolvedValue([
        { wcbReturnRecordId: generateUuid() },
      ]);

      const returnFileContent = [
        `BATCH-001\t1\tMERITUM\t20260215`,
        '',
        `RPT-001\t${claim.submitterTxnId}\tCLM-001\tACCEPTED\tComplete\t20260115`,
        '',
      ].join('\n');

      await processReturnFile(
        deps,
        PHYSICIAN_PROVIDER_ID,
        PHYSICIAN_USER_ID,
        returnFileContent,
      );

      const entry = findAuditEntryByAction(WcbAuditAction.WCB_RETURN_RECEIVED);
      expect(entry).toBeDefined();
      expect(entry!.actorId).toBe(PHYSICIAN_USER_ID);
      expect((entry!.changes as any).wcbBatchId).toBe(batch.wcbBatchId);
      expect((entry!.changes as any).matchedCount).toBeDefined();
    });

    it('remittance processed produces WCB_PAYMENT_RECEIVED audit with record_count and total_payment', async () => {
      deps = createServiceDeps();

      const remittanceXml = `<?xml version="1.0" encoding="UTF-8"?>
<PaymentRemittanceReport xmlns="http://www.wcb.ab.ca/schemas/RR/RRPaymentRemittanceReport-2.01.00">
<ReportWeek>
  <StartDate>2026-02-01</StartDate>
  <EndDate>2026-02-07</EndDate>
</ReportWeek>
<PaymentRemittanceRecord>
  <PaymentPayeeBillingNumber>123456</PaymentPayeeBillingNumber>
  <PaymentPayeeName>Test Physician</PaymentPayeeName>
  <PaymentReasonCode>C561</PaymentReasonCode>
  <PaymentStatus>ISS</PaymentStatus>
  <PaymentStartDate>2026-01-15</PaymentStartDate>
  <PaymentEndDate>2026-01-15</PaymentEndDate>
  <PaymentAmount>150.00</PaymentAmount>
</PaymentRemittanceRecord>
</PaymentRemittanceReport>`;

      await processRemittanceFile(
        deps,
        PHYSICIAN_PROVIDER_ID,
        PHYSICIAN_USER_ID,
        remittanceXml,
      );

      const entry = findAuditEntryByAction(WcbAuditAction.WCB_PAYMENT_RECEIVED);
      expect(entry).toBeDefined();
      expect(entry!.actorId).toBe(PHYSICIAN_USER_ID);
      expect((entry!.changes as any).recordCount).toBeGreaterThan(0);
      expect((entry!.changes as any).totalPayment).toBeDefined();
    });
  });

  // =========================================================================
  // Category 4: MVP Events Produce Audit Records
  // =========================================================================

  describe('MVP events produce audit records', () => {
    it('MVP export generated produces WCB_MVP_EXPORT_GENERATED audit with claim_id', async () => {
      const claim = seedWcbClaim({ state: ClaimState.QUEUED });
      deps = createServiceDeps();

      // Set up a full claim response with all required fields
      const fullClaim = {
        detail: {
          wcbClaimDetailId: claim.wcbClaimDetailId,
          formId: WcbFormType.C050E,
          submitterTxnId: claim.submitterTxnId,
          patientPhn: '123456789',
          patientFirstName: 'John',
          patientLastName: 'Doe',
          dateOfInjury: '2026-01-10',
          dateOfExamination: '2026-01-12',
          reportCompletionDate: '2026-01-12',
        },
        claim: {
          claimId: claim.claimId,
          physicianId: PHYSICIAN_PROVIDER_ID,
          state: ClaimState.QUEUED,
          dateOfService: '2026-01-15',
        },
        injuries: [],
        prescriptions: [],
        consultations: [],
        workRestrictions: [],
        invoiceLines: [],
        attachments: [],
      };
      (deps.wcbRepo.getWcbClaim as any).mockResolvedValue(fullClaim);

      await generateMvpExport(
        deps,
        PHYSICIAN_PROVIDER_ID,
        claim.wcbClaimDetailId,
        PHYSICIAN_USER_ID,
        WcbPhase.MVP,
      );

      const entry = findAuditEntryByAction(WcbAuditAction.WCB_MVP_EXPORT_GENERATED);
      expect(entry).toBeDefined();
      expect(entry!.claimId).toBe(claim.claimId);
      expect(entry!.actorId).toBe(PHYSICIAN_USER_ID);
      expect((entry!.changes as any).wcbClaimDetailId).toBe(claim.wcbClaimDetailId);
      expect((entry!.changes as any).formId).toBe(WcbFormType.C050E);
    });

    it('manual outcome recorded produces WCB_MANUAL_OUTCOME_RECORDED audit with outcome_type', async () => {
      const claim = seedWcbClaim({ state: ClaimState.SUBMITTED });
      deps = createServiceDeps();

      const fullClaim = {
        detail: {
          wcbClaimDetailId: claim.wcbClaimDetailId,
          formId: WcbFormType.C050E,
        },
        claim: {
          claimId: claim.claimId,
          physicianId: PHYSICIAN_PROVIDER_ID,
          state: ClaimState.SUBMITTED,
        },
        injuries: [],
        prescriptions: [],
        consultations: [],
        workRestrictions: [],
        invoiceLines: [],
        attachments: [],
      };
      (deps.wcbRepo.getWcbClaim as any).mockResolvedValue(fullClaim);

      await recordManualOutcome(
        deps,
        PHYSICIAN_PROVIDER_ID,
        claim.wcbClaimDetailId,
        PHYSICIAN_USER_ID,
        {
          acceptance_status: 'accepted',
          wcb_claim_number: 'CLM-12345',
          payment_amount: 250,
        },
        WcbPhase.MVP,
      );

      const entry = findAuditEntryByAction(WcbAuditAction.WCB_MANUAL_OUTCOME_RECORDED);
      expect(entry).toBeDefined();
      expect(entry!.claimId).toBe(claim.claimId);
      expect(entry!.actorId).toBe(PHYSICIAN_USER_ID);
      expect((entry!.changes as any).acceptanceStatus).toBe('accepted');
      expect((entry!.changes as any).wcbClaimNumber).toBe('CLM-12345');
      expect((entry!.changes as any).paymentAmount).toBe(250);
    });

    it('manual outcome rejected produces audit with rejected status', async () => {
      const claim = seedWcbClaim({ state: ClaimState.SUBMITTED });
      deps = createServiceDeps();

      const fullClaim = {
        detail: {
          wcbClaimDetailId: claim.wcbClaimDetailId,
          formId: WcbFormType.C050E,
        },
        claim: {
          claimId: claim.claimId,
          physicianId: PHYSICIAN_PROVIDER_ID,
          state: ClaimState.SUBMITTED,
        },
        injuries: [],
        prescriptions: [],
        consultations: [],
        workRestrictions: [],
        invoiceLines: [],
        attachments: [],
      };
      (deps.wcbRepo.getWcbClaim as any).mockResolvedValue(fullClaim);

      await recordManualOutcome(
        deps,
        PHYSICIAN_PROVIDER_ID,
        claim.wcbClaimDetailId,
        PHYSICIAN_USER_ID,
        { acceptance_status: 'rejected' },
        WcbPhase.MVP,
      );

      const entry = findAuditEntryByAction(WcbAuditAction.WCB_MANUAL_OUTCOME_RECORDED);
      expect(entry).toBeDefined();
      expect((entry!.changes as any).acceptanceStatus).toBe('rejected');
    });
  });

  // =========================================================================
  // Category 5: Audit Entry Field Completeness
  // =========================================================================

  describe('Audit entry fields are correctly populated', () => {
    it('every WCB audit entry has claimId, action, actorId, actorContext, and createdAt', async () => {
      await createWcbClaim(
        deps,
        PHYSICIAN_PROVIDER_ID,
        PHYSICIAN_USER_ID,
        {
          form_id: WcbFormType.C050E,
          patient_id: PLACEHOLDER_PATIENT_ID,
          date_of_injury: '2026-01-10',
        },
      );

      for (const entry of claimAuditEntries) {
        expect(entry.claimId).toBeDefined();
        expect(entry.action).toBeDefined();
        expect(entry.actorId).toBeDefined();
        expect(entry.actorContext).toBeDefined();
        expect(entry.createdAt).toBeDefined();
      }
    });

    it('batch upload audit entry contains correct actor identity', async () => {
      const batch = seedBatch({ status: WcbBatchStatus.VALIDATED });
      deps = createServiceDeps();

      (deps.wcbRepo.setBatchUploaded as any).mockResolvedValue({
        ...batch,
        status: WcbBatchStatus.UPLOADED,
        uploadedAt: new Date(),
        uploadedBy: PHYSICIAN_USER_ID,
        reportCount: 2,
      });

      await confirmBatchUpload(deps, batch.wcbBatchId, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID);

      const entry = findAuditEntryByAction(WcbAuditAction.WCB_BATCH_UPLOADED);
      expect(entry).toBeDefined();
      expect(entry!.actorId).toBe(PHYSICIAN_USER_ID);
      expect(entry!.actorContext).toBe('physician');
    });

    it('create audit includes form_id in changes', async () => {
      await createWcbClaim(
        deps,
        PHYSICIAN_PROVIDER_ID,
        PHYSICIAN_USER_ID,
        {
          form_id: WcbFormType.C050E,
          patient_id: PLACEHOLDER_PATIENT_ID,
          date_of_injury: '2026-01-10',
        },
      );

      const entry = findAuditEntryByAction(WcbAuditAction.WCB_FORM_CREATED);
      expect(entry).toBeDefined();
      expect((entry!.changes as any).formId).toBe(WcbFormType.C050E);
    });

    it('update audit includes list of updated fields in changes', async () => {
      const created = await createWcbClaim(
        deps,
        PHYSICIAN_PROVIDER_ID,
        PHYSICIAN_USER_ID,
        {
          form_id: WcbFormType.C050E,
          patient_id: PLACEHOLDER_PATIENT_ID,
          date_of_injury: '2026-01-10',
        },
      );
      claimAuditEntries = [];

      await updateWcbClaim(
        deps,
        PHYSICIAN_PROVIDER_ID,
        PHYSICIAN_USER_ID,
        created.wcbClaimDetailId,
        {
          employer_name: 'Acme Corp',
          employer_city: 'Calgary',
        },
      );

      const entry = findAuditEntryByAction(WcbAuditAction.WCB_FORM_UPDATED);
      expect(entry).toBeDefined();
      const updatedFields = (entry!.changes as any).updatedFields as string[];
      expect(updatedFields).toContain('employer_name');
      expect(updatedFields).toContain('employer_city');
    });
  });

  // =========================================================================
  // Category 6: Audit Log Integrity (Append-Only)
  // =========================================================================

  describe('Audit log is append-only — no modification or deletion API for WCB entries', () => {
    it('no PUT endpoint exists for WCB claim audit history', async () => {
      const res = await physicianRequest('PUT', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}/audit`);
      expect([404, 405]).toContain(res.statusCode);
    });

    it('no DELETE endpoint exists for WCB claim audit history', async () => {
      const res = await physicianRequest('DELETE', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}/audit`);
      expect([404, 405]).toContain(res.statusCode);
    });

    it('no POST endpoint exists for WCB claim audit injection', async () => {
      const res = await physicianRequest('POST', `/api/v1/wcb/claims/${PLACEHOLDER_UUID}/audit`, {
        action: 'FAKE_WCB_ACTION',
        changes: { injected: true },
      });
      expect([404, 405]).toContain(res.statusCode);
    });

    it('no PUT endpoint exists for WCB batch audit modification', async () => {
      const res = await physicianRequest('PUT', `/api/v1/wcb/batches/${PLACEHOLDER_UUID}/audit`);
      expect([404, 405]).toContain(res.statusCode);
    });

    it('no DELETE endpoint exists for WCB batch audit deletion', async () => {
      const res = await physicianRequest('DELETE', `/api/v1/wcb/batches/${PLACEHOLDER_UUID}/audit`);
      expect([404, 405]).toContain(res.statusCode);
    });

    it('no POST endpoint exists for WCB batch audit injection', async () => {
      const res = await physicianRequest('POST', `/api/v1/wcb/batches/${PLACEHOLDER_UUID}/audit`, {
        action: 'FAKE_BATCH_AUDIT',
        status: 'SUBMITTED',
      });
      expect([404, 405]).toContain(res.statusCode);
    });

    it('no PUT endpoint exists for WCB return audit modification', async () => {
      const res = await physicianRequest('PUT', `/api/v1/wcb/returns/${PLACEHOLDER_UUID}/audit`);
      expect([404, 405]).toContain(res.statusCode);
    });

    it('no DELETE endpoint exists for WCB return audit deletion', async () => {
      const res = await physicianRequest('DELETE', `/api/v1/wcb/returns/${PLACEHOLDER_UUID}/audit`);
      expect([404, 405]).toContain(res.statusCode);
    });
  });

  // =========================================================================
  // Category 7: Sensitive Data Exclusion from Audit Entries
  // =========================================================================

  describe('Audit entries do not contain sensitive PHI', () => {
    it('WCB claim creation audit does not contain patient PHN', async () => {
      await createWcbClaim(
        deps,
        PHYSICIAN_PROVIDER_ID,
        PHYSICIAN_USER_ID,
        {
          form_id: WcbFormType.C050E,
          patient_id: PLACEHOLDER_PATIENT_ID,
          date_of_injury: '2026-01-10',
        },
      );

      const allEntries = JSON.stringify(claimAuditEntries);
      // PHN pattern: 9-digit number
      expect(allEntries).not.toContain('123456789');
    });

    it('WCB claim update audit does not contain patient names', async () => {
      const created = await createWcbClaim(
        deps,
        PHYSICIAN_PROVIDER_ID,
        PHYSICIAN_USER_ID,
        {
          form_id: WcbFormType.C050E,
          patient_id: PLACEHOLDER_PATIENT_ID,
          date_of_injury: '2026-01-10',
        },
      );
      claimAuditEntries = [];

      await updateWcbClaim(
        deps,
        PHYSICIAN_PROVIDER_ID,
        PHYSICIAN_USER_ID,
        created.wcbClaimDetailId,
        { additional_comments: 'Test update' },
      );

      const allEntries = JSON.stringify(claimAuditEntries);
      expect(allEntries).not.toMatch(/firstName|lastName|first_name|last_name/i);
    });

    it('batch audit entries do not contain patient demographics', async () => {
      const batch = seedBatch({ status: WcbBatchStatus.VALIDATED });
      deps = createServiceDeps();

      (deps.wcbRepo.setBatchUploaded as any).mockResolvedValue({
        ...batch,
        status: WcbBatchStatus.UPLOADED,
        uploadedAt: new Date(),
        uploadedBy: PHYSICIAN_USER_ID,
        reportCount: 1,
      });

      await confirmBatchUpload(deps, batch.wcbBatchId, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID);

      const allEntries = JSON.stringify(claimAuditEntries);
      expect(allEntries).not.toMatch(/\bpatientPhn\b/i);
      expect(allEntries).not.toMatch(/\bpatientFirstName\b/i);
      expect(allEntries).not.toMatch(/\bpatientLastName\b/i);
    });

    it('remittance audit entries do not leak worker PHN', async () => {
      deps = createServiceDeps();

      const remittanceXml = `<?xml version="1.0" encoding="UTF-8"?>
<PaymentRemittanceReport xmlns="http://www.wcb.ab.ca/schemas/RR/RRPaymentRemittanceReport-2.01.00">
<ReportWeek>
  <StartDate>2026-02-01</StartDate>
  <EndDate>2026-02-07</EndDate>
</ReportWeek>
<PaymentRemittanceRecord>
  <PaymentPayeeBillingNumber>123456</PaymentPayeeBillingNumber>
  <PaymentPayeeName>Test</PaymentPayeeName>
  <PaymentReasonCode>C561</PaymentReasonCode>
  <PaymentStatus>ISS</PaymentStatus>
  <PaymentStartDate>2026-01-15</PaymentStartDate>
  <PaymentEndDate>2026-01-15</PaymentEndDate>
  <PaymentAmount>150.00</PaymentAmount>
  <WorkerPHN>987654321</WorkerPHN>
  <WorkerFirstName>Jane</WorkerFirstName>
  <WorkerLastName>Worker</WorkerLastName>
</PaymentRemittanceRecord>
</PaymentRemittanceReport>`;

      await processRemittanceFile(
        deps,
        PHYSICIAN_PROVIDER_ID,
        PHYSICIAN_USER_ID,
        remittanceXml,
      );

      const auditStr = JSON.stringify(claimAuditEntries);
      expect(auditStr).not.toContain('987654321');
      expect(auditStr).not.toContain('Jane');
      expect(auditStr).not.toContain('Worker');
    });
  });

  // =========================================================================
  // Category 8: Multiple Actions on Same Claim Accumulate Correctly
  // =========================================================================

  describe('Multiple actions on same claim accumulate correctly', () => {
    it('each WCB service call produces exactly one audit entry', async () => {
      const result = await createWcbClaim(
        deps,
        PHYSICIAN_PROVIDER_ID,
        PHYSICIAN_USER_ID,
        {
          form_id: WcbFormType.C050E,
          patient_id: PLACEHOLDER_PATIENT_ID,
          date_of_injury: '2026-01-10',
        },
      );

      expect(claimAuditEntries.length).toBe(1);

      await updateWcbClaim(
        deps,
        PHYSICIAN_PROVIDER_ID,
        PHYSICIAN_USER_ID,
        result.wcbClaimDetailId,
        { additional_comments: 'Update 1' },
      );

      const updateEntries = claimAuditEntries.filter(
        (e) => e.action === WcbAuditAction.WCB_FORM_UPDATED,
      );
      expect(updateEntries.length).toBe(1);
    });

    it('create then update then delete produces 3 ordered audit entries', async () => {
      const result = await createWcbClaim(
        deps,
        PHYSICIAN_PROVIDER_ID,
        PHYSICIAN_USER_ID,
        {
          form_id: WcbFormType.C050E,
          patient_id: PLACEHOLDER_PATIENT_ID,
          date_of_injury: '2026-01-10',
        },
      );

      await updateWcbClaim(
        deps,
        PHYSICIAN_PROVIDER_ID,
        PHYSICIAN_USER_ID,
        result.wcbClaimDetailId,
        { additional_comments: 'Updated' },
      );

      await deleteWcbClaim(
        deps,
        PHYSICIAN_PROVIDER_ID,
        PHYSICIAN_USER_ID,
        result.wcbClaimDetailId,
      );

      expect(claimAuditEntries.length).toBe(3);

      const actions = claimAuditEntries.map((e) => e.action);
      expect(actions[0]).toBe(WcbAuditAction.WCB_FORM_CREATED);
      expect(actions[1]).toBe(WcbAuditAction.WCB_FORM_UPDATED);
      // Delete uses WCB_FORM_CREATED with soft_delete action marker
      expect(actions[2]).toBe(WcbAuditAction.WCB_FORM_CREATED);
      expect((claimAuditEntries[2].changes as any).action).toBe('soft_delete');
    });

    it('audit entries for different WCB claims are independent', async () => {
      const claim1 = await createWcbClaim(
        deps,
        PHYSICIAN_PROVIDER_ID,
        PHYSICIAN_USER_ID,
        {
          form_id: WcbFormType.C050E,
          patient_id: PLACEHOLDER_PATIENT_ID,
          date_of_injury: '2026-01-10',
        },
      );

      const claim2 = await createWcbClaim(
        deps,
        PHYSICIAN_PROVIDER_ID,
        PHYSICIAN_USER_ID,
        {
          form_id: WcbFormType.C050E,
          patient_id: PLACEHOLDER_PATIENT_ID,
          date_of_injury: '2026-01-12',
        },
      );

      const entries1 = auditEntriesForClaim(claim1.claimId);
      const entries2 = auditEntriesForClaim(claim2.claimId);

      expect(entries1.length).toBe(1);
      expect(entries2.length).toBe(1);
      expect(entries1[0].claimId).not.toBe(entries2[0].claimId);
    });
  });

  // =========================================================================
  // Category 9: Notification Events as External Audit Trail
  // =========================================================================

  describe('Notification events serve as external audit trail', () => {
    it('batch upload confirmation emits WCB_BATCH_UPLOADED notification', async () => {
      const batch = seedBatch({ status: WcbBatchStatus.VALIDATED });
      deps = createServiceDeps();

      (deps.wcbRepo.setBatchUploaded as any).mockResolvedValue({
        ...batch,
        status: WcbBatchStatus.UPLOADED,
        uploadedAt: new Date(),
        uploadedBy: PHYSICIAN_USER_ID,
        reportCount: 3,
      });

      await confirmBatchUpload(deps, batch.wcbBatchId, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID);

      const uploadEvents = notificationEvents.filter((e) => e.event === 'WCB_BATCH_UPLOADED');
      expect(uploadEvents.length).toBe(1);
      expect(uploadEvents[0].payload.wcbBatchId).toBe(batch.wcbBatchId);
      expect(uploadEvents[0].payload.physicianId).toBe(PHYSICIAN_PROVIDER_ID);
      expect(uploadEvents[0].payload.uploadedBy).toBe(PHYSICIAN_USER_ID);
    });

    it('remittance import emits WCB_PAYMENT_RECEIVED notification with summary', async () => {
      deps = createServiceDeps();

      const remittanceXml = `<?xml version="1.0" encoding="UTF-8"?>
<PaymentRemittanceReport xmlns="http://www.wcb.ab.ca/schemas/RR/RRPaymentRemittanceReport-2.01.00">
<ReportWeek>
  <StartDate>2026-02-01</StartDate>
  <EndDate>2026-02-07</EndDate>
</ReportWeek>
<PaymentRemittanceRecord>
  <PaymentPayeeBillingNumber>123456</PaymentPayeeBillingNumber>
  <PaymentPayeeName>Test</PaymentPayeeName>
  <PaymentReasonCode>C561</PaymentReasonCode>
  <PaymentStatus>ISS</PaymentStatus>
  <PaymentStartDate>2026-01-15</PaymentStartDate>
  <PaymentEndDate>2026-01-15</PaymentEndDate>
  <PaymentAmount>200.00</PaymentAmount>
</PaymentRemittanceRecord>
</PaymentRemittanceReport>`;

      await processRemittanceFile(deps, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, remittanceXml);

      const paymentEvents = notificationEvents.filter((e) => e.event === 'WCB_PAYMENT_RECEIVED');
      expect(paymentEvents.length).toBe(1);
      expect(paymentEvents[0].payload.physicianId).toBe(PHYSICIAN_PROVIDER_ID);
      expect(paymentEvents[0].payload.recordCount).toBeGreaterThan(0);
    });

    it('notification payloads do not contain PHI', async () => {
      const batch = seedBatch({ status: WcbBatchStatus.VALIDATED });
      deps = createServiceDeps();

      (deps.wcbRepo.setBatchUploaded as any).mockResolvedValue({
        ...batch,
        status: WcbBatchStatus.UPLOADED,
        uploadedAt: new Date(),
        uploadedBy: PHYSICIAN_USER_ID,
        reportCount: 2,
      });

      await confirmBatchUpload(deps, batch.wcbBatchId, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID);

      for (const event of notificationEvents) {
        const payloadStr = JSON.stringify(event.payload);
        // Must NOT contain PHI patterns
        expect(payloadStr).not.toMatch(/\b\d{9}\b/); // PHN
        expect(payloadStr).not.toMatch(/firstName|lastName|first_name|last_name/i);
        expect(payloadStr).not.toMatch(/dateOfBirth|date_of_birth/i);
      }
    });
  });
});
