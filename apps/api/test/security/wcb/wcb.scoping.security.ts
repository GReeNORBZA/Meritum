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
import { type WcbServiceDeps } from '../../../src/domains/wcb/wcb.service.js';
import {
  type SessionManagementDeps,
  hashToken,
} from '../../../src/domains/iam/iam.service.js';
import { randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Fixed test identities — Two isolated physicians + delegate
// ---------------------------------------------------------------------------

// Physician 1 — "our" physician
const P1_SESSION_TOKEN = randomBytes(32).toString('hex');
const P1_SESSION_TOKEN_HASH = hashToken(P1_SESSION_TOKEN);
const P1_USER_ID = '11111111-1111-0000-0000-000000000001';
const P1_PROVIDER_ID = P1_USER_ID;
const P1_SESSION_ID = '11111111-1111-0000-0000-000000000011';

// Physician 2 — "other" physician (attacker perspective)
const P2_SESSION_TOKEN = randomBytes(32).toString('hex');
const P2_SESSION_TOKEN_HASH = hashToken(P2_SESSION_TOKEN);
const P2_USER_ID = '22222222-2222-0000-0000-000000000002';
const P2_PROVIDER_ID = P2_USER_ID;
const P2_SESSION_ID = '22222222-2222-0000-0000-000000000022';

// Delegate linked to Physician 1 only (with CLAIM_VIEW + BATCH_VIEW + REPORT_VIEW)
const DELEGATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_SESSION_TOKEN_HASH = hashToken(DELEGATE_SESSION_TOKEN);
const DELEGATE_USER_ID = '33333333-3333-0000-0000-000000000003';
const DELEGATE_SESSION_ID = '33333333-3333-0000-0000-000000000033';

// ---------------------------------------------------------------------------
// Test data IDs — resources owned by each physician
// ---------------------------------------------------------------------------

// Physician 1's WCB claims
const P1_CLAIM_ID = 'cccc1111-0000-0000-0000-000000000001';
const P1_CLAIM_ID_B = 'cccc1111-0000-0000-0000-000000000002';

// Physician 2's WCB claims
const P2_CLAIM_ID = 'cccc2222-0000-0000-0000-000000000001';
const P2_CLAIM_ID_B = 'cccc2222-0000-0000-0000-000000000002';

// Physician 1's WCB batches
const P1_BATCH_ID = 'bbbb1111-0000-0000-0000-000000000001';

// Physician 2's WCB batches
const P2_BATCH_ID = 'bbbb2222-0000-0000-0000-000000000001';

// Physician 1's remittance import
const P1_REMITTANCE_ID = 'dddd1111-0000-0000-0000-000000000001';

// Physician 2's remittance import
const P2_REMITTANCE_ID = 'dddd2222-0000-0000-0000-000000000001';

// Physician 1's attachment
const P1_ATTACHMENT_ID = 'aaaa1111-0000-0000-0000-000000000001';

// Physician 2's attachment
const P2_ATTACHMENT_ID = 'aaaa2222-0000-0000-0000-000000000001';

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

// ---------------------------------------------------------------------------
// WCB data stores (physician-scoped)
// ---------------------------------------------------------------------------

interface MockWcbClaim {
  wcbClaimId: string;
  claimId: string;
  physicianId: string;
  formId: string;
  patientId: string;
  dateOfInjury: string;
  reportCompletionDate: string;
  status: string;
  detail: Record<string, unknown>;
  injuries: any[];
  prescriptions: any[];
  consultations: any[];
  workRestrictions: any[];
  invoiceLines: any[];
  attachments: any[];
}

interface MockWcbBatch {
  wcbBatchId: string;
  physicianId: string;
  controlId: string;
  status: string;
  claimCount: number;
  xmlStoragePath: string;
  uploadedAt: string | null;
  createdAt: Date;
  updatedAt: Date;
}

interface MockRemittanceImport {
  wcbRemittanceImportId: string;
  physicianId: string;
  importDate: string;
  recordCount: number;
  totalPaid: string;
  createdAt: Date;
}

interface MockReturnRecord {
  wcbReturnRecordId: string;
  batchId: string;
  physicianId: string;
  submitterTxnId: string;
  reportStatus: string;
  claimNumber: string | null;
  errorMessages: string[];
}

interface MockAttachment {
  wcbAttachmentId: string;
  claimId: string;
  physicianId: string;
  fileName: string;
  mimeType: string;
  storagePath: string;
}

interface MockDiscrepancy {
  discrepancyId: string;
  remittanceImportId: string;
  physicianId: string;
  claimId: string;
  field: string;
  expected: string;
  actual: string;
}

const wcbClaimStore: Record<string, MockWcbClaim> = {};
const wcbBatchStore: Record<string, MockWcbBatch> = {};
const remittanceStore: Record<string, MockRemittanceImport> = {};
const returnStore: Record<string, MockReturnRecord[]> = {};
const attachmentStore: Record<string, MockAttachment> = {};
const discrepancyStore: Record<string, MockDiscrepancy[]> = {};

// ---------------------------------------------------------------------------
// Seed test data
// ---------------------------------------------------------------------------

function seedTestData() {
  // Clear stores
  Object.keys(wcbClaimStore).forEach((k) => delete wcbClaimStore[k]);
  Object.keys(wcbBatchStore).forEach((k) => delete wcbBatchStore[k]);
  Object.keys(remittanceStore).forEach((k) => delete remittanceStore[k]);
  Object.keys(returnStore).forEach((k) => delete returnStore[k]);
  Object.keys(attachmentStore).forEach((k) => delete attachmentStore[k]);
  Object.keys(discrepancyStore).forEach((k) => delete discrepancyStore[k]);

  // --- Physician 1's WCB claims ---
  wcbClaimStore[P1_CLAIM_ID] = {
    wcbClaimId: P1_CLAIM_ID,
    claimId: P1_CLAIM_ID,
    physicianId: P1_PROVIDER_ID,
    formId: 'C050E',
    patientId: '00000000-0000-0000-0000-100000000001',
    dateOfInjury: '2026-01-14',
    reportCompletionDate: '2026-01-15',
    status: 'DRAFT',
    detail: {
      formId: 'C050E',
      dateOfInjury: '2026-01-14',
      symptoms: 'P1 symptoms',
    },
    injuries: [{ type: 'laceration', bodyPart: 'hand' }],
    prescriptions: [],
    consultations: [],
    workRestrictions: [],
    invoiceLines: [{ lineType: 'PROFESSIONAL_FEE', amount: '150.00' }],
    attachments: [],
  };
  wcbClaimStore[P1_CLAIM_ID_B] = {
    wcbClaimId: P1_CLAIM_ID_B,
    claimId: P1_CLAIM_ID_B,
    physicianId: P1_PROVIDER_ID,
    formId: 'C050E',
    patientId: '00000000-0000-0000-0000-100000000002',
    dateOfInjury: '2026-02-01',
    reportCompletionDate: '2026-02-02',
    status: 'VALIDATED',
    detail: {
      formId: 'C050E',
      dateOfInjury: '2026-02-01',
      symptoms: 'P1 second claim symptoms',
    },
    injuries: [],
    prescriptions: [],
    consultations: [],
    workRestrictions: [],
    invoiceLines: [],
    attachments: [],
  };

  // --- Physician 2's WCB claims ---
  wcbClaimStore[P2_CLAIM_ID] = {
    wcbClaimId: P2_CLAIM_ID,
    claimId: P2_CLAIM_ID,
    physicianId: P2_PROVIDER_ID,
    formId: 'C050E',
    patientId: '00000000-0000-0000-0000-200000000001',
    dateOfInjury: '2026-01-20',
    reportCompletionDate: '2026-01-21',
    status: 'DRAFT',
    detail: {
      formId: 'C050E',
      dateOfInjury: '2026-01-20',
      symptoms: 'P2 symptoms confidential',
    },
    injuries: [{ type: 'fracture', bodyPart: 'wrist' }],
    prescriptions: [{ medication: 'acetaminophen' }],
    consultations: [],
    workRestrictions: [],
    invoiceLines: [{ lineType: 'PROFESSIONAL_FEE', amount: '275.00' }],
    attachments: [],
  };
  wcbClaimStore[P2_CLAIM_ID_B] = {
    wcbClaimId: P2_CLAIM_ID_B,
    claimId: P2_CLAIM_ID_B,
    physicianId: P2_PROVIDER_ID,
    formId: 'C570E',
    patientId: '00000000-0000-0000-0000-200000000002',
    dateOfInjury: '2026-02-10',
    reportCompletionDate: '2026-02-11',
    status: 'QUEUED',
    detail: {
      formId: 'C570E',
      dateOfInjury: '2026-02-10',
      symptoms: 'P2 second claim',
    },
    injuries: [],
    prescriptions: [],
    consultations: [],
    workRestrictions: [],
    invoiceLines: [],
    attachments: [],
  };

  // --- Physician 1's batches ---
  wcbBatchStore[P1_BATCH_ID] = {
    wcbBatchId: P1_BATCH_ID,
    physicianId: P1_PROVIDER_ID,
    controlId: 'CTL-P1-001',
    status: 'GENERATED',
    claimCount: 2,
    xmlStoragePath: `wcb/batches/${P1_PROVIDER_ID}/${P1_BATCH_ID}.xml`,
    uploadedAt: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  // --- Physician 2's batches ---
  wcbBatchStore[P2_BATCH_ID] = {
    wcbBatchId: P2_BATCH_ID,
    physicianId: P2_PROVIDER_ID,
    controlId: 'CTL-P2-001',
    status: 'UPLOADED',
    claimCount: 3,
    xmlStoragePath: `wcb/batches/${P2_PROVIDER_ID}/${P2_BATCH_ID}.xml`,
    uploadedAt: '2026-02-15T10:00:00.000Z',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  // --- Physician 1's remittance imports ---
  remittanceStore[P1_REMITTANCE_ID] = {
    wcbRemittanceImportId: P1_REMITTANCE_ID,
    physicianId: P1_PROVIDER_ID,
    importDate: '2026-02-10',
    recordCount: 5,
    totalPaid: '750.00',
    createdAt: new Date(),
  };

  // --- Physician 2's remittance imports ---
  remittanceStore[P2_REMITTANCE_ID] = {
    wcbRemittanceImportId: P2_REMITTANCE_ID,
    physicianId: P2_PROVIDER_ID,
    importDate: '2026-02-12',
    recordCount: 8,
    totalPaid: '1200.00',
    createdAt: new Date(),
  };

  // --- Return records (keyed by batch ID) ---
  returnStore[P1_BATCH_ID] = [
    {
      wcbReturnRecordId: 'ret-p1-001',
      batchId: P1_BATCH_ID,
      physicianId: P1_PROVIDER_ID,
      submitterTxnId: 'TXN-P1-001',
      reportStatus: 'ACCEPTED',
      claimNumber: 'WCB-P1-12345',
      errorMessages: [],
    },
  ];
  returnStore[P2_BATCH_ID] = [
    {
      wcbReturnRecordId: 'ret-p2-001',
      batchId: P2_BATCH_ID,
      physicianId: P2_PROVIDER_ID,
      submitterTxnId: 'TXN-P2-001',
      reportStatus: 'REJECTED',
      claimNumber: null,
      errorMessages: ['Invalid employer code'],
    },
  ];

  // --- Attachments ---
  attachmentStore[P1_ATTACHMENT_ID] = {
    wcbAttachmentId: P1_ATTACHMENT_ID,
    claimId: P1_CLAIM_ID,
    physicianId: P1_PROVIDER_ID,
    fileName: 'xray_p1.pdf',
    mimeType: 'application/pdf',
    storagePath: `wcb/attachments/${P1_PROVIDER_ID}/${P1_ATTACHMENT_ID}`,
  };
  attachmentStore[P2_ATTACHMENT_ID] = {
    wcbAttachmentId: P2_ATTACHMENT_ID,
    claimId: P2_CLAIM_ID,
    physicianId: P2_PROVIDER_ID,
    fileName: 'xray_p2.pdf',
    mimeType: 'application/pdf',
    storagePath: `wcb/attachments/${P2_PROVIDER_ID}/${P2_ATTACHMENT_ID}`,
  };

  // --- Discrepancies (keyed by remittance import ID) ---
  discrepancyStore[P1_REMITTANCE_ID] = [
    {
      discrepancyId: 'disc-p1-001',
      remittanceImportId: P1_REMITTANCE_ID,
      physicianId: P1_PROVIDER_ID,
      claimId: P1_CLAIM_ID,
      field: 'amount',
      expected: '150.00',
      actual: '140.00',
    },
  ];
  discrepancyStore[P2_REMITTANCE_ID] = [
    {
      discrepancyId: 'disc-p2-001',
      remittanceImportId: P2_REMITTANCE_ID,
      physicianId: P2_PROVIDER_ID,
      claimId: P2_CLAIM_ID,
      field: 'amount',
      expected: '275.00',
      actual: '250.00',
    },
  ];
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
    appendAuditLog: vi.fn(async () => {}),
  };
}

function createMockEvents() {
  return { emit: vi.fn() };
}

// ---------------------------------------------------------------------------
// Physician-scoped mock WCB repository
// ---------------------------------------------------------------------------

function createScopedWcbRepo() {
  return {
    createWcbClaim: vi.fn(async () => ({})),

    getWcbClaim: vi.fn(async (id: string, physicianId: string) => {
      const claim = wcbClaimStore[id];
      if (!claim || claim.physicianId !== physicianId) return null;
      return {
        ...claim,
        detail: claim.detail,
        injuries: claim.injuries,
        prescriptions: claim.prescriptions,
        consultations: claim.consultations,
        workRestrictions: claim.workRestrictions,
        invoiceLines: claim.invoiceLines,
        attachments: claim.attachments,
      };
    }),

    updateWcbClaim: vi.fn(async (id: string, physicianId: string, data: any) => {
      const claim = wcbClaimStore[id];
      if (!claim || claim.physicianId !== physicianId) return null;
      return { ...claim, ...data };
    }),

    softDeleteWcbClaim: vi.fn(async (id: string, physicianId: string) => {
      const claim = wcbClaimStore[id];
      if (!claim || claim.physicianId !== physicianId) return false;
      return true;
    }),

    getWcbClaimBySubmitterTxnId: vi.fn(async () => null),
    updateWcbClaimNumber: vi.fn(async () => ({})),

    upsertInjuries: vi.fn(async () => []),
    getInjuries: vi.fn(async () => []),
    upsertPrescriptions: vi.fn(async () => []),
    getPrescriptions: vi.fn(async () => []),
    upsertConsultations: vi.fn(async () => []),
    getConsultations: vi.fn(async () => []),
    upsertWorkRestrictions: vi.fn(async () => []),
    getWorkRestrictions: vi.fn(async () => []),

    listWcbClaimsForPhysician: vi.fn(async (physicianId: string, _filters: any) => {
      const matches = Object.values(wcbClaimStore).filter(
        (c) => c.physicianId === physicianId,
      );
      return {
        data: matches,
        pagination: { total: matches.length, page: 1, pageSize: 25, hasMore: false },
      };
    }),

    upsertInvoiceLines: vi.fn(async () => []),
    getInvoiceLines: vi.fn(async () => []),

    validateC570Pairing: vi.fn(async () => ({ valid: true, errors: [] })),

    upsertAttachments: vi.fn(async () => []),

    getAttachments: vi.fn(async (claimId: string, physicianId: string) => {
      return Object.values(attachmentStore).filter(
        (a) => a.claimId === claimId && a.physicianId === physicianId,
      );
    }),

    getAttachmentContent: vi.fn(async (attachmentId: string, physicianId: string) => {
      const att = attachmentStore[attachmentId];
      if (!att || att.physicianId !== physicianId) return null;
      return { ...att, content: Buffer.from('fake-content') };
    }),

    createBatch: vi.fn(async () => ({})),

    getBatch: vi.fn(async (id: string, physicianId: string) => {
      const batch = wcbBatchStore[id];
      if (!batch || batch.physicianId !== physicianId) return null;
      return batch;
    }),

    getBatchByControlId: vi.fn(async () => null),

    listBatches: vi.fn(async (physicianId: string, _filters: any) => {
      const matches = Object.values(wcbBatchStore).filter(
        (b) => b.physicianId === physicianId,
      );
      return {
        data: matches,
        pagination: { total: matches.length, page: 1, pageSize: 25, hasMore: false },
      };
    }),

    updateBatchStatus: vi.fn(async () => ({})),

    setBatchUploaded: vi.fn(async (id: string, physicianId: string, _data: any) => {
      const batch = wcbBatchStore[id];
      if (!batch || batch.physicianId !== physicianId) return null;
      return { ...batch, status: 'UPLOADED' };
    }),

    setBatchReturnReceived: vi.fn(async () => ({})),

    getQueuedClaimsForBatch: vi.fn(async () => []),
    assignClaimsToBatch: vi.fn(async () => ({})),

    createReturnRecords: vi.fn(async () => []),
    createReturnInvoiceLines: vi.fn(async () => []),

    getReturnRecordsByBatch: vi.fn(async (batchId: string) => {
      return returnStore[batchId] ?? [];
    }),

    matchReturnToClaimBySubmitterTxnId: vi.fn(async () => null),

    createRemittanceImport: vi.fn(async () => ({ wcbRemittanceImportId: crypto.randomUUID() })),
    createRemittanceRecords: vi.fn(async () => []),
    matchRemittanceToClaimByTxnId: vi.fn(async () => null),

    listRemittanceImports: vi.fn(async (physicianId: string, _filters: any) => {
      const matches = Object.values(remittanceStore).filter(
        (r) => r.physicianId === physicianId,
      );
      return {
        data: matches,
        pagination: { total: matches.length, page: 1, pageSize: 25, hasMore: false },
      };
    }),

    getRemittanceDiscrepancies: vi.fn(async (id: string, physicianId: string) => {
      const discs = discrepancyStore[id] ?? [];
      return discs.filter((d) => d.physicianId === physicianId);
    }),
  };
}

function createStubClaimRepo() {
  return {
    createClaim: vi.fn(async () => ({ claimId: crypto.randomUUID(), state: 'DRAFT' })),
    findClaimById: vi.fn(async (claimId: string, physicianId: string) => {
      const claim = wcbClaimStore[claimId];
      if (!claim || claim.physicianId !== physicianId) return undefined;
      return { claimId: claim.claimId, state: claim.status, physicianId: claim.physicianId };
    }),
    appendClaimAudit: vi.fn(async () => {}),
    transitionClaimState: vi.fn(async () => ({})),
  };
}

function createScopedServiceDeps(): WcbServiceDeps {
  return {
    wcbRepo: createScopedWcbRepo() as any,
    claimRepo: createStubClaimRepo() as any,
    providerLookup: {
      findProviderById: vi.fn(async () => undefined),
      getWcbConfigForForm: vi.fn(async () => null),
    },
    patientLookup: {
      findPatientById: vi.fn(async () => undefined),
    },
    auditEmitter: { emit: vi.fn(async () => {}) },
    referenceLookup: {
      findHscBaseRate: vi.fn(async () => null),
      getRrnpVariablePremiumRate: vi.fn(async () => '0.00'),
    },
    fileStorage: {
      storeEncrypted: vi.fn(async () => {}),
      readEncrypted: vi.fn(async () => Buffer.from('<xml/>')),
    },
    secretsProvider: {
      getVendorSourceId: () => 'MERITUM',
      getSubmitterId: () => 'MRT-SUBMIT',
    },
    downloadUrlGenerator: {
      generateSignedUrl: vi.fn(async () => 'https://meritum.ca/download/signed-url'),
    },
    notificationEmitter: { emit: vi.fn(async () => {}) },
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

  const handlerDeps: WcbHandlerDeps = {
    serviceDeps: createScopedServiceDeps(),
    wcbPhase: 'mvp',
  };

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  await testApp.register(authPluginFp, { sessionDeps });

  testApp.setErrorHandler((error, request, reply) => {
    const statusCode = (error as any).statusCode;
    if (statusCode && statusCode >= 400 && statusCode < 500) {
      return reply.code(statusCode).send({
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

function asDelegate(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${DELEGATE_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

// ---------------------------------------------------------------------------
// Seed users and sessions
// ---------------------------------------------------------------------------

function seedUsersAndSessions() {
  users = [];
  sessions = [];

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

  // Delegate linked to Physician 1 (with CLAIM_VIEW + BATCH_VIEW + REPORT_VIEW)
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
      physicianProviderId: P1_PROVIDER_ID,
      permissions: ['CLAIM_VIEW', 'BATCH_VIEW', 'REPORT_VIEW'],
      linkageId: '44444444-4444-0000-0000-000000000044',
    },
  });
  sessions.push({
    sessionId: DELEGATE_SESSION_ID,
    userId: DELEGATE_USER_ID,
    tokenHash: DELEGATE_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.3',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('WCB Physician Tenant Isolation — MOST CRITICAL (Security)', () => {
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
  // 1. Claim Isolation — GET by ID
  // =========================================================================

  describe('Claim isolation — GET by ID', () => {
    it('physician1 can retrieve own WCB claim', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/claims/${P1_CLAIM_ID}`);
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.physicianId).toBe(P1_PROVIDER_ID);
    });

    it('physician2 can retrieve own WCB claim', async () => {
      const res = await asPhysician2('GET', `/api/v1/wcb/claims/${P2_CLAIM_ID}`);
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.physicianId).toBe(P2_PROVIDER_ID);
    });

    it('physician2 CANNOT retrieve physician1 claim — returns 404 (not 403)', async () => {
      const res = await asPhysician2('GET', `/api/v1/wcb/claims/${P1_CLAIM_ID}`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();
    });

    it('physician1 CANNOT retrieve physician2 claim — returns 404 (not 403)', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/claims/${P2_CLAIM_ID}`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();
    });

    it('cross-tenant GET claim response does not leak claim details', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/claims/${P2_CLAIM_ID}`);
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_CLAIM_ID);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain('P2 symptoms');
      expect(rawBody).not.toContain('275.00');
    });
  });

  // =========================================================================
  // 2. Claim Isolation — UPDATE (PUT)
  // =========================================================================

  describe('Claim isolation — UPDATE', () => {
    it('physician2 CANNOT update physician1 claim — returns 404', async () => {
      const res = await asPhysician2('PUT', `/api/v1/wcb/claims/${P1_CLAIM_ID}`, {
        symptoms: 'hacked symptoms',
      });
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
    });

    it('physician1 CANNOT update physician2 claim — returns 404', async () => {
      const res = await asPhysician1('PUT', `/api/v1/wcb/claims/${P2_CLAIM_ID}`, {
        symptoms: 'hacked symptoms',
      });
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('physician1 claim remains unchanged after physician2 update attempt', async () => {
      await asPhysician2('PUT', `/api/v1/wcb/claims/${P1_CLAIM_ID}`, {
        symptoms: 'hacked',
      });
      const res = await asPhysician1('GET', `/api/v1/wcb/claims/${P1_CLAIM_ID}`);
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.detail.symptoms).toBe('P1 symptoms');
    });
  });

  // =========================================================================
  // 3. Claim Isolation — DELETE
  // =========================================================================

  describe('Claim isolation — DELETE', () => {
    it('physician2 CANNOT delete physician1 claim — returns 404', async () => {
      const res = await asPhysician2('DELETE', `/api/v1/wcb/claims/${P1_CLAIM_ID}`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('physician1 CANNOT delete physician2 claim — returns 404', async () => {
      const res = await asPhysician1('DELETE', `/api/v1/wcb/claims/${P2_CLAIM_ID}`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('physician1 claim still exists after physician2 delete attempt', async () => {
      await asPhysician2('DELETE', `/api/v1/wcb/claims/${P1_CLAIM_ID}`);
      const res = await asPhysician1('GET', `/api/v1/wcb/claims/${P1_CLAIM_ID}`);
      expect(res.statusCode).toBe(200);
    });
  });

  // =========================================================================
  // 4. Claim Isolation — Validate
  // =========================================================================

  describe('Claim isolation — Validate', () => {
    it('physician2 CANNOT validate physician1 claim — returns 404', async () => {
      const res = await asPhysician2('POST', `/api/v1/wcb/claims/${P1_CLAIM_ID}/validate`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('physician1 CANNOT validate physician2 claim — returns 404', async () => {
      const res = await asPhysician1('POST', `/api/v1/wcb/claims/${P2_CLAIM_ID}/validate`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });
  });

  // =========================================================================
  // 5. Claim Isolation — Form Schema
  // =========================================================================

  describe('Claim isolation — Form Schema', () => {
    it('physician2 CANNOT get physician1 claim form schema — returns 404', async () => {
      const res = await asPhysician2('GET', `/api/v1/wcb/claims/${P1_CLAIM_ID}/form-schema`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('physician1 CANNOT get physician2 claim form schema — returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/claims/${P2_CLAIM_ID}/form-schema`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });
  });

  // =========================================================================
  // 6. Claim Isolation — Export (MVP)
  // =========================================================================

  describe('Claim isolation — Export (MVP)', () => {
    it('physician2 CANNOT export physician1 claim — returns 404', async () => {
      const res = await asPhysician2('GET', `/api/v1/wcb/claims/${P1_CLAIM_ID}/export`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('physician1 CANNOT export physician2 claim — returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/claims/${P2_CLAIM_ID}/export`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });
  });

  // =========================================================================
  // 7. Claim Isolation — Manual Outcome (MVP)
  // =========================================================================

  describe('Claim isolation — Manual Outcome (MVP)', () => {
    it('physician2 CANNOT record outcome on physician1 claim — returns 404', async () => {
      const res = await asPhysician2('POST', `/api/v1/wcb/claims/${P1_CLAIM_ID}/manual-outcome`, {
        acceptance_status: 'accepted',
      });
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('physician1 CANNOT record outcome on physician2 claim — returns 404', async () => {
      const res = await asPhysician1('POST', `/api/v1/wcb/claims/${P2_CLAIM_ID}/manual-outcome`, {
        acceptance_status: 'accepted',
      });
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });
  });

  // =========================================================================
  // 8. Batch Isolation — GET by ID
  // =========================================================================

  describe('Batch isolation — GET by ID', () => {
    it('physician1 can retrieve own batch', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/batches/${P1_BATCH_ID}`);
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.physicianId).toBe(P1_PROVIDER_ID);
    });

    it('physician2 can retrieve own batch', async () => {
      const res = await asPhysician2('GET', `/api/v1/wcb/batches/${P2_BATCH_ID}`);
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.physicianId).toBe(P2_PROVIDER_ID);
    });

    it('physician2 CANNOT view physician1 batch — returns 404', async () => {
      const res = await asPhysician2('GET', `/api/v1/wcb/batches/${P1_BATCH_ID}`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
    });

    it('physician1 CANNOT view physician2 batch — returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/batches/${P2_BATCH_ID}`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
    });

    it('cross-tenant GET batch response does not leak batch details', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/batches/${P2_BATCH_ID}`);
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_BATCH_ID);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain('CTL-P2');
      expect(rawBody).not.toContain('UPLOADED');
    });
  });

  // =========================================================================
  // 9. Batch Isolation — LIST
  // =========================================================================

  describe('Batch isolation — LIST', () => {
    it('physician1 listing batches returns only physician1 batches', async () => {
      const res = await asPhysician1('GET', '/api/v1/wcb/batches');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBeGreaterThan(0);
      body.data.forEach((batch: any) => {
        expect(batch.physicianId).toBe(P1_PROVIDER_ID);
      });
    });

    it('physician2 listing batches returns only physician2 batches', async () => {
      const res = await asPhysician2('GET', '/api/v1/wcb/batches');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBeGreaterThan(0);
      body.data.forEach((batch: any) => {
        expect(batch.physicianId).toBe(P2_PROVIDER_ID);
      });
    });

    it('physician1 batch list never contains physician2 batch IDs', async () => {
      const res = await asPhysician1('GET', '/api/v1/wcb/batches');
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_BATCH_ID);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
    });

    it('physician2 batch list never contains physician1 batch IDs', async () => {
      const res = await asPhysician2('GET', '/api/v1/wcb/batches');
      const rawBody = res.body;
      expect(rawBody).not.toContain(P1_BATCH_ID);
      expect(rawBody).not.toContain(P1_PROVIDER_ID);
    });
  });

  // =========================================================================
  // 10. Batch Isolation — Download XML
  // =========================================================================

  describe('Batch isolation — Download XML', () => {
    it('physician2 CANNOT download physician1 batch XML — returns 404', async () => {
      const res = await asPhysician2('GET', `/api/v1/wcb/batches/${P1_BATCH_ID}/download`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('physician1 CANNOT download physician2 batch XML — returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/batches/${P2_BATCH_ID}/download`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('cross-tenant download response does not leak storage path', async () => {
      const res = await asPhysician2('GET', `/api/v1/wcb/batches/${P1_BATCH_ID}/download`);
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P1_BATCH_ID);
      expect(rawBody).not.toContain(P1_PROVIDER_ID);
      expect(rawBody).not.toContain('xml');
      expect(rawBody).not.toContain('signed-url');
    });
  });

  // =========================================================================
  // 11. Batch Isolation — Confirm Upload
  // =========================================================================

  describe('Batch isolation — Confirm Upload', () => {
    it('physician2 CANNOT confirm upload for physician1 batch — returns 404', async () => {
      const res = await asPhysician2('POST', `/api/v1/wcb/batches/${P1_BATCH_ID}/confirm-upload`, {
        uploaded_at: '2026-02-18T10:00:00.000Z',
      });
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('physician1 CANNOT confirm upload for physician2 batch — returns 404', async () => {
      const res = await asPhysician1('POST', `/api/v1/wcb/batches/${P2_BATCH_ID}/confirm-upload`, {
        uploaded_at: '2026-02-18T10:00:00.000Z',
      });
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('physician1 batch status unchanged after physician2 confirm-upload attempt', async () => {
      await asPhysician2('POST', `/api/v1/wcb/batches/${P1_BATCH_ID}/confirm-upload`, {
        uploaded_at: '2026-02-18T10:00:00.000Z',
      });
      const res = await asPhysician1('GET', `/api/v1/wcb/batches/${P1_BATCH_ID}`);
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.status).toBe('GENERATED');
    });
  });

  // =========================================================================
  // 12. Return Record Isolation
  // =========================================================================

  describe('Return record isolation', () => {
    it('physician2 CANNOT access physician1 return results — returns 404', async () => {
      const res = await asPhysician2('GET', `/api/v1/wcb/returns/${P1_BATCH_ID}`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('physician1 CANNOT access physician2 return results — returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/returns/${P2_BATCH_ID}`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('cross-tenant return results response does not leak return data', async () => {
      const res = await asPhysician2('GET', `/api/v1/wcb/returns/${P1_BATCH_ID}`);
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P1_BATCH_ID);
      expect(rawBody).not.toContain('TXN-P1');
      expect(rawBody).not.toContain('WCB-P1');
      expect(rawBody).not.toContain('ACCEPTED');
    });
  });

  // =========================================================================
  // 13. Remittance Isolation — LIST
  // =========================================================================

  describe('Remittance isolation — LIST', () => {
    it('physician1 listing remittances returns only physician1 imports', async () => {
      const res = await asPhysician1('GET', '/api/v1/wcb/remittances');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBeGreaterThan(0);
      body.data.forEach((r: any) => {
        expect(r.physicianId).toBe(P1_PROVIDER_ID);
      });
    });

    it('physician2 listing remittances returns only physician2 imports', async () => {
      const res = await asPhysician2('GET', '/api/v1/wcb/remittances');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBeGreaterThan(0);
      body.data.forEach((r: any) => {
        expect(r.physicianId).toBe(P2_PROVIDER_ID);
      });
    });

    it('physician1 remittance list never contains physician2 identifiers', async () => {
      const res = await asPhysician1('GET', '/api/v1/wcb/remittances');
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_REMITTANCE_ID);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain('1200.00');
    });

    it('physician2 remittance list never contains physician1 identifiers', async () => {
      const res = await asPhysician2('GET', '/api/v1/wcb/remittances');
      const rawBody = res.body;
      expect(rawBody).not.toContain(P1_REMITTANCE_ID);
      expect(rawBody).not.toContain(P1_PROVIDER_ID);
      expect(rawBody).not.toContain('750.00');
    });
  });

  // =========================================================================
  // 14. Remittance Isolation — Discrepancies
  // =========================================================================

  describe('Remittance isolation — Discrepancies', () => {
    it('physician2 CANNOT access physician1 remittance discrepancies', async () => {
      const res = await asPhysician2('GET', `/api/v1/wcb/remittances/${P1_REMITTANCE_ID}/discrepancies`);
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      // Even if endpoint returns 200, scoped repo returns empty for wrong physician
      expect(body.data).toHaveLength(0);
    });

    it('physician1 CANNOT access physician2 remittance discrepancies', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/remittances/${P2_REMITTANCE_ID}/discrepancies`);
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data).toHaveLength(0);
    });

    it('physician1 can access own remittance discrepancies', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/remittances/${P1_REMITTANCE_ID}/discrepancies`);
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBeGreaterThan(0);
      body.data.forEach((d: any) => {
        expect(d.physicianId).toBe(P1_PROVIDER_ID);
      });
    });

    it('cross-tenant discrepancy response contains no P2 data', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/remittances/${P2_REMITTANCE_ID}/discrepancies`);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_REMITTANCE_ID);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain(P2_CLAIM_ID);
      expect(rawBody).not.toContain('250.00');
    });
  });

  // =========================================================================
  // 15. Delegate Cross-Context Isolation
  // =========================================================================

  describe('Delegate cross-context isolation', () => {
    it('delegate linked to physician1 can access physician1 WCB claim', async () => {
      const res = await asDelegate('GET', `/api/v1/wcb/claims/${P1_CLAIM_ID}`);
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.physicianId).toBe(P1_PROVIDER_ID);
    });

    it('delegate linked to physician1 CANNOT access physician2 WCB claim — returns 404', async () => {
      const res = await asDelegate('GET', `/api/v1/wcb/claims/${P2_CLAIM_ID}`);
      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
    });

    it('delegate linked to physician1 can access physician1 batch list', async () => {
      const res = await asDelegate('GET', '/api/v1/wcb/batches');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      body.data.forEach((batch: any) => {
        expect(batch.physicianId).toBe(P1_PROVIDER_ID);
      });
    });

    it('delegate linked to physician1 CANNOT access physician2 batch — returns 404', async () => {
      const res = await asDelegate('GET', `/api/v1/wcb/batches/${P2_BATCH_ID}`);
      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
    });

    it('delegate linked to physician1 CANNOT access physician2 return results — returns 404', async () => {
      const res = await asDelegate('GET', `/api/v1/wcb/returns/${P2_BATCH_ID}`);
      expect(res.statusCode).toBe(404);
    });

    it('delegate linked to physician1 remittance list only returns physician1 data', async () => {
      const res = await asDelegate('GET', '/api/v1/wcb/remittances');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      body.data.forEach((r: any) => {
        expect(r.physicianId).toBe(P1_PROVIDER_ID);
      });
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_REMITTANCE_ID);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
    });

    it('delegate linked to physician1 discrepancies scoped to physician1', async () => {
      const res = await asDelegate('GET', `/api/v1/wcb/remittances/${P2_REMITTANCE_ID}/discrepancies`);
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      // Scoped repo returns empty for P2's remittance when accessed as P1 delegate
      expect(body.data).toHaveLength(0);
    });

    it('delegate batch list response contains no physician2 identifiers', async () => {
      const res = await asDelegate('GET', '/api/v1/wcb/batches');
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_BATCH_ID);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
    });
  });

  // =========================================================================
  // 16. Cross-user access ALWAYS returns 404 not 403
  // =========================================================================

  describe('Cross-user access returns 404 not 403 (prevents resource enumeration)', () => {
    it('GET claim by cross-tenant ID returns 404 not 403', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/claims/${P2_CLAIM_ID}`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('PUT claim by cross-tenant ID returns 404 not 403', async () => {
      const res = await asPhysician1('PUT', `/api/v1/wcb/claims/${P2_CLAIM_ID}`, { symptoms: 'x' });
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('DELETE claim by cross-tenant ID returns 404 not 403', async () => {
      const res = await asPhysician1('DELETE', `/api/v1/wcb/claims/${P2_CLAIM_ID}`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST validate claim by cross-tenant ID returns 404 not 403', async () => {
      const res = await asPhysician1('POST', `/api/v1/wcb/claims/${P2_CLAIM_ID}/validate`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET form-schema by cross-tenant ID returns 404 not 403', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/claims/${P2_CLAIM_ID}/form-schema`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET batch by cross-tenant ID returns 404 not 403', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/batches/${P2_BATCH_ID}`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET batch download by cross-tenant ID returns 404 not 403', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/batches/${P2_BATCH_ID}/download`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST confirm-upload by cross-tenant ID returns 404 not 403', async () => {
      const res = await asPhysician1('POST', `/api/v1/wcb/batches/${P2_BATCH_ID}/confirm-upload`, {
        uploaded_at: '2026-02-18T10:00:00.000Z',
      });
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET return results by cross-tenant batch ID returns 404 not 403', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/returns/${P2_BATCH_ID}`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET export by cross-tenant claim ID returns 404 not 403', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/claims/${P2_CLAIM_ID}/export`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST manual-outcome by cross-tenant claim ID returns 404 not 403', async () => {
      const res = await asPhysician1('POST', `/api/v1/wcb/claims/${P2_CLAIM_ID}/manual-outcome`, {
        acceptance_status: 'accepted',
      });
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });
  });

  // =========================================================================
  // 17. Non-existent resource IDs return 404 (not 500)
  // =========================================================================

  describe('Non-existent resource IDs return 404', () => {
    const NONEXISTENT_UUID = '99999999-9999-9999-9999-999999999999';

    it('GET non-existent WCB claim ID returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/claims/${NONEXISTENT_UUID}`);
      expect(res.statusCode).toBe(404);
    });

    it('PUT non-existent WCB claim ID returns 404', async () => {
      const res = await asPhysician1('PUT', `/api/v1/wcb/claims/${NONEXISTENT_UUID}`, {
        symptoms: 'test',
      });
      expect(res.statusCode).toBe(404);
    });

    it('DELETE non-existent WCB claim ID returns 404', async () => {
      const res = await asPhysician1('DELETE', `/api/v1/wcb/claims/${NONEXISTENT_UUID}`);
      expect(res.statusCode).toBe(404);
    });

    it('GET non-existent batch ID returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/batches/${NONEXISTENT_UUID}`);
      expect(res.statusCode).toBe(404);
    });

    it('GET non-existent return batch ID returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/returns/${NONEXISTENT_UUID}`);
      expect(res.statusCode).toBe(404);
    });
  });

  // =========================================================================
  // 18. Bidirectional isolation — verify BOTH directions
  // =========================================================================

  describe('Bidirectional isolation (both physicians tested)', () => {
    it('physician1 and physician2 see different claim sets', async () => {
      const res1 = await asPhysician1('GET', `/api/v1/wcb/claims/${P1_CLAIM_ID}`);
      expect(res1.statusCode).toBe(200);
      const res2 = await asPhysician2('GET', `/api/v1/wcb/claims/${P1_CLAIM_ID}`);
      expect(res2.statusCode).toBe(404);

      const res3 = await asPhysician2('GET', `/api/v1/wcb/claims/${P2_CLAIM_ID}`);
      expect(res3.statusCode).toBe(200);
      const res4 = await asPhysician1('GET', `/api/v1/wcb/claims/${P2_CLAIM_ID}`);
      expect(res4.statusCode).toBe(404);
    });

    it('physician1 and physician2 see different batch sets', async () => {
      const res1 = await asPhysician1('GET', `/api/v1/wcb/batches/${P1_BATCH_ID}`);
      expect(res1.statusCode).toBe(200);
      const res2 = await asPhysician2('GET', `/api/v1/wcb/batches/${P1_BATCH_ID}`);
      expect(res2.statusCode).toBe(404);

      const res3 = await asPhysician2('GET', `/api/v1/wcb/batches/${P2_BATCH_ID}`);
      expect(res3.statusCode).toBe(200);
      const res4 = await asPhysician1('GET', `/api/v1/wcb/batches/${P2_BATCH_ID}`);
      expect(res4.statusCode).toBe(404);
    });
  });

  // =========================================================================
  // 19. 404 responses reveal no information about the target resource
  // =========================================================================

  describe('404 responses reveal no information about the target resource', () => {
    it('404 for cross-tenant claim does not contain claim details', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/claims/${P2_CLAIM_ID}`);
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_CLAIM_ID);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain('P2 symptoms');
      expect(rawBody).not.toContain('fracture');
      expect(rawBody).not.toContain('wrist');
    });

    it('404 for cross-tenant batch does not contain batch details', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/batches/${P2_BATCH_ID}`);
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_BATCH_ID);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain('CTL-P2');
      expect(rawBody).not.toContain('UPLOADED');
    });

    it('404 for cross-tenant download does not contain file path or URL', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/batches/${P2_BATCH_ID}/download`);
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_BATCH_ID);
      expect(rawBody).not.toContain('download');
    });

    it('404 for cross-tenant return results does not contain return data', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/returns/${P2_BATCH_ID}`);
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_BATCH_ID);
      expect(rawBody).not.toContain('TXN-P2');
      expect(rawBody).not.toContain('REJECTED');
      expect(rawBody).not.toContain('Invalid employer code');
    });

    it('404 for cross-tenant update does not leak claim state', async () => {
      const res = await asPhysician1('PUT', `/api/v1/wcb/claims/${P2_CLAIM_ID}`, { symptoms: 'x' });
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_CLAIM_ID);
      expect(rawBody).not.toContain('DRAFT');
    });
  });

  // =========================================================================
  // 20. Response body never leaks cross-tenant identifiers (success paths)
  // =========================================================================

  describe('Response body never leaks cross-tenant identifiers', () => {
    it('physician1 claim GET response contains no P2 identifiers', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/claims/${P1_CLAIM_ID}`);
      expect(res.statusCode).toBe(200);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain(P2_CLAIM_ID);
      expect(rawBody).not.toContain(P2_BATCH_ID);
    });

    it('physician1 batch list response contains no P2 identifiers', async () => {
      const res = await asPhysician1('GET', '/api/v1/wcb/batches');
      expect(res.statusCode).toBe(200);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain(P2_BATCH_ID);
    });

    it('physician1 remittance list response contains no P2 identifiers', async () => {
      const res = await asPhysician1('GET', '/api/v1/wcb/remittances');
      expect(res.statusCode).toBe(200);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain(P2_REMITTANCE_ID);
    });
  });
});
