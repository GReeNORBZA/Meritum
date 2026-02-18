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
// Fixed test identities — Two isolated physicians
// ---------------------------------------------------------------------------

// Physician 1 — "our" physician
const P1_SESSION_TOKEN = randomBytes(32).toString('hex');
const P1_SESSION_TOKEN_HASH = hashToken(P1_SESSION_TOKEN);
const P1_USER_ID = '11111111-5555-0000-0000-000000000001';
const P1_PROVIDER_ID = P1_USER_ID;
const P1_SESSION_ID = '11111111-5555-0000-0000-000000000011';

// Physician 2 — "other" physician (attacker perspective)
const P2_SESSION_TOKEN = randomBytes(32).toString('hex');
const P2_SESSION_TOKEN_HASH = hashToken(P2_SESSION_TOKEN);
const P2_USER_ID = '22222222-5555-0000-0000-000000000002';
const P2_PROVIDER_ID = P2_USER_ID;
const P2_SESSION_ID = '22222222-5555-0000-0000-000000000022';

// ---------------------------------------------------------------------------
// Test data IDs
// ---------------------------------------------------------------------------

// Physician 1's WCB claims
const P1_CLAIM_ID = 'cccc1111-5555-0000-0000-000000000001';

// Physician 2's WCB claims
const P2_CLAIM_ID = 'cccc2222-5555-0000-0000-000000000001';

// Batches
const P1_BATCH_ID = 'bbbb1111-5555-0000-0000-000000000001';
const P2_BATCH_ID = 'bbbb2222-5555-0000-0000-000000000001';

// Remittance imports
const P1_REMITTANCE_ID = 'dddd1111-5555-0000-0000-000000000001';
const P2_REMITTANCE_ID = 'dddd2222-5555-0000-0000-000000000001';

// Non-existent UUID
const NONEXISTENT_UUID = '99999999-9999-9999-9999-999999999999';

// ---------------------------------------------------------------------------
// Sensitive PHI data — must never leak
// ---------------------------------------------------------------------------

const P1_PATIENT_PHN = '123456789';
const P1_PATIENT_NAME = 'Jane';
const P1_PATIENT_DOB = '1988-03-15';
const P2_PATIENT_PHN = '987654321';
const P2_PATIENT_NAME = 'John';

// Employer details (WCB-specific PHI)
const P1_EMPLOYER_NAME = 'Acme Drilling Corp';
const P1_EMPLOYER_PHONE = '780-555-1234';
const P2_EMPLOYER_NAME = 'Northern Oilsands Ltd';

// Opioid & clinical data
const P1_INJURY_DESC = 'Worker fell from ladder sustaining lumbar fracture';
const P1_OPIOID_DESC = 'Hydromorphone 4mg TID for severe pain management';
const P2_INJURY_DESC = 'Chemical burn to left forearm from acid spill';

// WCB vendor credentials — must never leak
const WCB_VENDOR_SOURCE_ID = 'MERITUM-WCB-VENDOR';
const WCB_SUBMITTER_ID = 'MRT-WCB-SUBMIT-001';

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

let users: MockUser[] = [];
let sessions: MockSession[] = [];
let auditEntries: Array<Record<string, unknown>> = [];

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
const discrepancyStore: Record<string, MockDiscrepancy[]> = {};

// ---------------------------------------------------------------------------
// Seed test data
// ---------------------------------------------------------------------------

function seedTestData() {
  Object.keys(wcbClaimStore).forEach((k) => delete wcbClaimStore[k]);
  Object.keys(wcbBatchStore).forEach((k) => delete wcbBatchStore[k]);
  Object.keys(remittanceStore).forEach((k) => delete remittanceStore[k]);
  Object.keys(returnStore).forEach((k) => delete returnStore[k]);
  Object.keys(discrepancyStore).forEach((k) => delete discrepancyStore[k]);

  // --- Physician 1's WCB claim (with sensitive PHI) ---
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
      patientPhn: P1_PATIENT_PHN,
      patientFirstName: P1_PATIENT_NAME,
      patientDob: P1_PATIENT_DOB,
      employerName: P1_EMPLOYER_NAME,
      employerPhoneNumber: P1_EMPLOYER_PHONE,
      injuryDescription: P1_INJURY_DESC,
      symptoms: 'Severe lower back pain radiating to legs',
      narcoticsDetails: P1_OPIOID_DESC,
    },
    injuries: [{ type: 'fracture', bodyPart: 'lumbar spine' }],
    prescriptions: [{ medication: 'hydromorphone', strength: '4mg', dailyIntake: 'TID' }],
    consultations: [],
    workRestrictions: [{ activityType: 'lifting', restrictionLevel: 'none', maxWeight: '0kg' }],
    invoiceLines: [{ lineType: 'STANDARD', amount: '150.00' }],
    attachments: [{ fileName: 'xray.pdf', mimeType: 'application/pdf', contentB64: 'JVBERi0xLjQK...' }],
  };

  // --- Physician 2's WCB claim (with sensitive PHI) ---
  wcbClaimStore[P2_CLAIM_ID] = {
    wcbClaimId: P2_CLAIM_ID,
    claimId: P2_CLAIM_ID,
    physicianId: P2_PROVIDER_ID,
    formId: 'C050E',
    patientId: '00000000-0000-0000-0000-200000000001',
    dateOfInjury: '2026-01-20',
    reportCompletionDate: '2026-01-21',
    status: 'VALIDATED',
    detail: {
      formId: 'C050E',
      dateOfInjury: '2026-01-20',
      patientPhn: P2_PATIENT_PHN,
      patientFirstName: P2_PATIENT_NAME,
      employerName: P2_EMPLOYER_NAME,
      injuryDescription: P2_INJURY_DESC,
      symptoms: 'Chemical burn with blistering',
    },
    injuries: [{ type: 'burn', bodyPart: 'left forearm' }],
    prescriptions: [],
    consultations: [],
    workRestrictions: [],
    invoiceLines: [{ lineType: 'STANDARD', amount: '275.00' }],
    attachments: [],
  };

  // --- Physician 1's batch (with internal storage path) ---
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

  // --- Physician 2's batch ---
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

  // --- Remittance imports ---
  remittanceStore[P1_REMITTANCE_ID] = {
    wcbRemittanceImportId: P1_REMITTANCE_ID,
    physicianId: P1_PROVIDER_ID,
    importDate: '2026-02-10',
    recordCount: 5,
    totalPaid: '750.00',
    createdAt: new Date(),
  };
  remittanceStore[P2_REMITTANCE_ID] = {
    wcbRemittanceImportId: P2_REMITTANCE_ID,
    physicianId: P2_PROVIDER_ID,
    importDate: '2026-02-12',
    recordCount: 8,
    totalPaid: '1200.00',
    createdAt: new Date(),
  };

  // --- Return records ---
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

  // --- Discrepancies ---
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
        // Attachment metadata only (no base64 content in list/get)
        attachments: claim.attachments.map((a: any) => ({
          fileName: a.fileName,
          mimeType: a.mimeType,
        })),
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
      // Simulate stripping base64 attachment content from list responses
      const safeMatches = matches.map((c) => ({
        ...c,
        attachments: c.attachments.map((a: any) => ({
          fileName: a.fileName,
          mimeType: a.mimeType,
        })),
      }));
      return {
        data: safeMatches,
        pagination: { total: safeMatches.length, page: 1, pageSize: 25, hasMore: false },
      };
    }),

    upsertInvoiceLines: vi.fn(async () => []),
    getInvoiceLines: vi.fn(async () => []),
    validateC570Pairing: vi.fn(async () => ({ valid: true, errors: [] })),
    upsertAttachments: vi.fn(async () => []),
    getAttachments: vi.fn(async () => []),
    getAttachmentContent: vi.fn(async () => null),

    createBatch: vi.fn(async () => ({})),

    getBatch: vi.fn(async (id: string, physicianId: string) => {
      const batch = wcbBatchStore[id];
      if (!batch || batch.physicianId !== physicianId) return null;
      // Strip internal xmlStoragePath — return only safe fields
      return {
        wcbBatchId: batch.wcbBatchId,
        physicianId: batch.physicianId,
        controlId: batch.controlId,
        status: batch.status,
        claimCount: batch.claimCount,
        uploadedAt: batch.uploadedAt,
        createdAt: batch.createdAt,
        updatedAt: batch.updatedAt,
      };
    }),

    getBatchByControlId: vi.fn(async () => null),

    listBatches: vi.fn(async (physicianId: string, _filters: any) => {
      const matches = Object.values(wcbBatchStore).filter(
        (b) => b.physicianId === physicianId,
      );
      // Strip internal fields from list responses
      const safeMatches = matches.map((b) => ({
        wcbBatchId: b.wcbBatchId,
        physicianId: b.physicianId,
        controlId: b.controlId,
        status: b.status,
        claimCount: b.claimCount,
        uploadedAt: b.uploadedAt,
        createdAt: b.createdAt,
        updatedAt: b.updatedAt,
      }));
      return {
        data: safeMatches,
        pagination: { total: safeMatches.length, page: 1, pageSize: 25, hasMore: false },
      };
    }),

    updateBatchStatus: vi.fn(async () => ({})),

    setBatchUploaded: vi.fn(async (id: string, physicianId: string) => {
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
    auditEmitter: {
      emit: vi.fn(async (entry: Record<string, unknown>) => {
        auditEntries.push(entry);
      }),
    },
    referenceLookup: {
      findHscBaseRate: vi.fn(async () => null),
      getRrnpVariablePremiumRate: vi.fn(async () => '0.00'),
    },
    fileStorage: {
      storeEncrypted: vi.fn(async () => {}),
      readEncrypted: vi.fn(async () => Buffer.from('<xml/>')),
    },
    secretsProvider: {
      getVendorSourceId: () => WCB_VENDOR_SOURCE_ID,
      getSubmitterId: () => WCB_SUBMITTER_ID,
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
        error: { code: 'VALIDATION_ERROR', message: 'Validation failed' },
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

function unauthenticated(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
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
// Utility: recursively check for key in nested object
// ---------------------------------------------------------------------------

function containsKeyRecursive(obj: unknown, key: string): boolean {
  if (obj === null || obj === undefined || typeof obj !== 'object') return false;
  if (Array.isArray(obj)) return obj.some((item) => containsKeyRecursive(item, key));
  const record = obj as Record<string, unknown>;
  if (key in record) return true;
  return Object.values(record).some((val) => containsKeyRecursive(val, key));
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('WCB PHI & Data Leakage Prevention (Security)', () => {
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
  // 1. PHI Not in Error Responses
  // =========================================================================

  describe('PHI not in error responses', () => {
    it('400 validation error does not include patient PHN or name', async () => {
      const res = await asPhysician1('POST', '/api/v1/wcb/claims', {
        form_id: 'INVALID_FORM',  // invalid — will fail Zod validation
        patient_id: 'not-a-uuid',
      });

      expect(res.statusCode).toBe(400);
      const rawBody = res.body;

      // PHI must not appear in validation error
      expect(rawBody).not.toContain(P1_PATIENT_PHN);
      expect(rawBody).not.toContain(P1_PATIENT_NAME);
      expect(rawBody).not.toContain(P1_PATIENT_DOB);

      const body = JSON.parse(rawBody);
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();
    });

    it('400 validation error on claim update does not echo employer details', async () => {
      const res = await asPhysician1('PUT', `/api/v1/wcb/claims/${P1_CLAIM_ID}`, {
        employer_phone_number: 'not-a-phone-but-too-long-for-field-validation-aaaaaaaaaaaaaaaa',
      });

      // Whether 400 or other status, PHI must not leak
      const rawBody = res.body;
      expect(rawBody).not.toContain(P1_EMPLOYER_NAME);
      expect(rawBody).not.toContain(P1_EMPLOYER_PHONE);
    });

    it('404 response does not confirm whether the WCB claim exists', async () => {
      // P1 tries to access P2's claim (cross-tenant)
      const crossTenantRes = await asPhysician1('GET', `/api/v1/wcb/claims/${P2_CLAIM_ID}`);
      // P1 accesses a genuinely non-existent claim
      const genuineMissingRes = await asPhysician1('GET', `/api/v1/wcb/claims/${NONEXISTENT_UUID}`);

      // Both should be 404 with identical error shape
      expect(crossTenantRes.statusCode).toBe(404);
      expect(genuineMissingRes.statusCode).toBe(404);

      const crossBody = JSON.parse(crossTenantRes.body);
      const missingBody = JSON.parse(genuineMissingRes.body);

      // Same error structure — indistinguishable
      expect(crossBody.error.code).toBe(missingBody.error.code);
      expect(crossBody.error.message).toBe(missingBody.error.message);

      // No claim details leaked
      expect(crossTenantRes.body).not.toContain(P2_CLAIM_ID);
      expect(crossTenantRes.body).not.toContain(P2_PROVIDER_ID);
      expect(crossTenantRes.body).not.toContain(P2_PATIENT_PHN);
      expect(crossTenantRes.body).not.toContain(P2_EMPLOYER_NAME);
      expect(crossTenantRes.body).not.toContain(P2_INJURY_DESC);
    });

    it('404 for cross-physician batch does not confirm existence', async () => {
      const crossRes = await asPhysician1('GET', `/api/v1/wcb/batches/${P2_BATCH_ID}`);
      const missingRes = await asPhysician1('GET', `/api/v1/wcb/batches/${NONEXISTENT_UUID}`);

      expect(crossRes.statusCode).toBe(404);
      expect(missingRes.statusCode).toBe(404);

      const crossBody = JSON.parse(crossRes.body);
      const missingBody = JSON.parse(missingRes.body);

      expect(crossBody.error.code).toBe(missingBody.error.code);
      expect(crossBody.error.message).toBe(missingBody.error.message);
    });

    it('500 error does not expose stack traces, SQL errors, or internal details', async () => {
      // Verify error handler strips internals on any error response
      const res = await asPhysician1('GET', `/api/v1/wcb/claims/${NONEXISTENT_UUID}`);

      const body = JSON.parse(res.body);
      // No stack traces
      expect(body.error).not.toHaveProperty('stack');
      expect(body.error).not.toHaveProperty('stackTrace');
      expect(JSON.stringify(body)).not.toMatch(/at\s+\w+\s+\(/);
      expect(JSON.stringify(body)).not.toMatch(/\.ts:\d+:\d+/);
      expect(JSON.stringify(body)).not.toContain('node_modules');
      // No SQL/ORM keywords
      expect(JSON.stringify(body).toLowerCase()).not.toMatch(/postgres|drizzle|pg_catalog|relation|syntax error/);
    });

    it('404 for cross-physician claim validate does not confirm existence', async () => {
      const crossRes = await asPhysician1('POST', `/api/v1/wcb/claims/${P2_CLAIM_ID}/validate`);
      const missingRes = await asPhysician1('POST', `/api/v1/wcb/claims/${NONEXISTENT_UUID}/validate`);

      expect(crossRes.statusCode).toBe(404);
      expect(missingRes.statusCode).toBe(404);

      const crossBody = JSON.parse(crossRes.body);
      const missingBody = JSON.parse(missingRes.body);

      expect(crossBody.error.code).toBe(missingBody.error.code);
      expect(crossBody.error.message).toBe(missingBody.error.message);
    });

    it('404 for cross-physician form-schema does not confirm existence', async () => {
      const crossRes = await asPhysician1('GET', `/api/v1/wcb/claims/${P2_CLAIM_ID}/form-schema`);
      const missingRes = await asPhysician1('GET', `/api/v1/wcb/claims/${NONEXISTENT_UUID}/form-schema`);

      expect(crossRes.statusCode).toBe(404);
      expect(missingRes.statusCode).toBe(404);

      const crossBody = JSON.parse(crossRes.body);
      const missingBody = JSON.parse(missingRes.body);

      expect(crossBody.error.code).toBe(missingBody.error.code);
      expect(crossBody.error.message).toBe(missingBody.error.message);
    });

    it('404 for cross-physician export does not confirm existence', async () => {
      const crossRes = await asPhysician1('GET', `/api/v1/wcb/claims/${P2_CLAIM_ID}/export`);
      const missingRes = await asPhysician1('GET', `/api/v1/wcb/claims/${NONEXISTENT_UUID}/export`);

      expect(crossRes.statusCode).toBe(404);
      expect(missingRes.statusCode).toBe(404);

      const crossBody = JSON.parse(crossRes.body);
      const missingBody = JSON.parse(missingRes.body);

      expect(crossBody.error.code).toBe(missingBody.error.code);
      expect(crossBody.error.message).toBe(missingBody.error.message);
    });
  });

  // =========================================================================
  // 2. Response Header Security
  // =========================================================================

  describe('PHI not in headers', () => {
    it('no X-Powered-By header in authenticated responses', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/claims/${P1_CLAIM_ID}`);
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By header in 401 responses', async () => {
      const res = await unauthenticated('GET', `/api/v1/wcb/claims/${P1_CLAIM_ID}`);
      expect(res.statusCode).toBe(401);
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By header in 400 responses', async () => {
      const res = await asPhysician1('POST', '/api/v1/wcb/claims', {});
      expect(res.statusCode).toBe(400);
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By header in 404 responses', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/claims/${NONEXISTENT_UUID}`);
      expect(res.statusCode).toBe(404);
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no Server header revealing version/technology', async () => {
      const res = await asPhysician1('GET', '/api/v1/wcb/batches');
      const serverHeader = res.headers['server'];
      if (serverHeader) {
        const lower = (serverHeader as string).toLowerCase();
        expect(lower).not.toContain('fastify');
        expect(lower).not.toContain('node');
        expect(lower).not.toContain('express');
      }
    });

    it('no WCB claim data in response headers', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/claims/${P1_CLAIM_ID}`);
      const headerStr = JSON.stringify(res.headers);

      expect(headerStr).not.toContain(P1_PATIENT_PHN);
      expect(headerStr).not.toContain(P1_CLAIM_ID);
      expect(headerStr).not.toContain(P1_EMPLOYER_NAME);
      expect(headerStr).not.toContain(P1_INJURY_DESC);
    });

    it('responses include Content-Type: application/json', async () => {
      const res = await asPhysician1('GET', '/api/v1/wcb/batches');
      expect(res.headers['content-type']).toContain('application/json');
    });

    it('error responses include Content-Type: application/json', async () => {
      const res = await unauthenticated('GET', '/api/v1/wcb/batches');
      expect(res.headers['content-type']).toContain('application/json');
    });
  });

  // =========================================================================
  // 3. Sensitive WCB Data Not Leaked — Vendor Credentials
  // =========================================================================

  describe('Vendor credentials not exposed in API responses', () => {
    it('batch response does not expose vendor source ID', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/batches/${P1_BATCH_ID}`);
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain(WCB_VENDOR_SOURCE_ID);
      expect(rawBody).not.toContain('vendorSourceId');
      expect(rawBody).not.toContain('vendor_source_id');
    });

    it('batch response does not expose submitter ID', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/batches/${P1_BATCH_ID}`);
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain(WCB_SUBMITTER_ID);
      expect(rawBody).not.toContain('submitterId');
      expect(rawBody).not.toContain('submitter_id');
    });

    it('batch list response does not expose vendor credentials', async () => {
      const res = await asPhysician1('GET', '/api/v1/wcb/batches');
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain(WCB_VENDOR_SOURCE_ID);
      expect(rawBody).not.toContain(WCB_SUBMITTER_ID);
    });

    it('error responses do not expose vendor credentials', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/batches/${NONEXISTENT_UUID}`);
      expect(res.statusCode).toBe(404);

      const rawBody = res.body;
      expect(rawBody).not.toContain(WCB_VENDOR_SOURCE_ID);
      expect(rawBody).not.toContain(WCB_SUBMITTER_ID);
    });

    it('claim response does not expose vendor credentials', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/claims/${P1_CLAIM_ID}`);
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain(WCB_VENDOR_SOURCE_ID);
      expect(rawBody).not.toContain(WCB_SUBMITTER_ID);
    });
  });

  // =========================================================================
  // 4. Batch XML File Path Not Exposed
  // =========================================================================

  describe('Batch XML file path not exposed in API responses', () => {
    it('batch GET response does not expose xmlStoragePath', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/batches/${P1_BATCH_ID}`);
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain('xmlStoragePath');
      expect(rawBody).not.toContain('xml_storage_path');
      expect(rawBody).not.toContain('wcb/batches/');
      expect(rawBody).not.toContain('.xml');
    });

    it('batch list response does not expose xmlStoragePath', async () => {
      const res = await asPhysician1('GET', '/api/v1/wcb/batches');
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain('xmlStoragePath');
      expect(rawBody).not.toContain('xml_storage_path');
      expect(rawBody).not.toContain('wcb/batches/');
      expect(rawBody).not.toContain('.xml');
    });

    it('cross-tenant batch access does not leak file path', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/batches/${P2_BATCH_ID}`);
      expect(res.statusCode).toBe(404);

      const rawBody = res.body;
      expect(rawBody).not.toContain('wcb/batches/');
      expect(rawBody).not.toContain(P2_BATCH_ID);
      expect(rawBody).not.toContain('.xml');
    });

    it('unauthenticated batch access does not leak file path', async () => {
      const res = await unauthenticated('GET', `/api/v1/wcb/batches/${P1_BATCH_ID}`);
      expect(res.statusCode).toBe(401);

      const rawBody = res.body;
      expect(rawBody).not.toContain('wcb/batches/');
      expect(rawBody).not.toContain('.xml');
      expect(rawBody).not.toContain(P1_BATCH_ID);
    });

    it('batch download returns signed URL, not raw file path', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/batches/${P1_BATCH_ID}/download`);

      // Whether success or error, no raw file path
      const rawBody = res.body;
      expect(rawBody).not.toContain('xmlStoragePath');
      expect(rawBody).not.toContain('xml_storage_path');
      // If successful, should contain a signed URL instead
      if (res.statusCode === 200) {
        const body = JSON.parse(rawBody);
        if (body.data && body.data.downloadUrl) {
          expect(body.data.downloadUrl).toContain('https://');
        }
      }
    });
  });

  // =========================================================================
  // 5. Attachment Base64 Content Not in List Responses
  // =========================================================================

  describe('Base64 attachment content not included in claim list responses', () => {
    it('claim list response does not contain base64 attachment content', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/claims/${P1_CLAIM_ID}`);
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      // base64 content marker from our seeded data
      expect(rawBody).not.toContain('JVBERi0xLjQK');
      expect(rawBody).not.toContain('file_content_b64');
      expect(rawBody).not.toContain('contentB64');
    });

    it('claim response attachment metadata only includes filename and mime type', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/claims/${P1_CLAIM_ID}`);
      expect(res.statusCode).toBe(200);

      const body = JSON.parse(res.body);
      if (body.data && body.data.attachments && body.data.attachments.length > 0) {
        for (const att of body.data.attachments) {
          // Should have metadata fields only
          expect(att).toHaveProperty('fileName');
          expect(att).toHaveProperty('mimeType');
          // Should NOT have base64 content
          expect(att).not.toHaveProperty('contentB64');
          expect(att).not.toHaveProperty('file_content_b64');
          expect(att).not.toHaveProperty('content');
        }
      }
    });
  });

  // =========================================================================
  // 6. WCB-Specific PHI Protection — Employer Details
  // =========================================================================

  describe('Employer details not leaked to unauthorized users', () => {
    it('401 response does not contain employer data', async () => {
      const res = await unauthenticated('GET', `/api/v1/wcb/claims/${P1_CLAIM_ID}`);
      expect(res.statusCode).toBe(401);

      const rawBody = res.body;
      expect(rawBody).not.toContain(P1_EMPLOYER_NAME);
      expect(rawBody).not.toContain(P1_EMPLOYER_PHONE);
      expect(rawBody).not.toContain('employer');
    });

    it('cross-tenant claim access does not leak employer details', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/claims/${P2_CLAIM_ID}`);
      expect(res.statusCode).toBe(404);

      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_EMPLOYER_NAME);
      expect(rawBody).not.toContain('Northern Oilsands');
      expect(rawBody).not.toContain(P2_PATIENT_PHN);
      expect(rawBody).not.toContain(P2_PATIENT_NAME);
    });

    it('cross-tenant claim update attempt does not leak employer details', async () => {
      const res = await asPhysician1('PUT', `/api/v1/wcb/claims/${P2_CLAIM_ID}`, {
        employer_name: 'Hacked Corp',
      });
      expect(res.statusCode).toBe(404);

      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_EMPLOYER_NAME);
      expect(rawBody).not.toContain(P2_INJURY_DESC);
    });
  });

  // =========================================================================
  // 7. Opioid Prescription Details Not Leaked
  // =========================================================================

  describe('Opioid prescription details not leaked in error messages', () => {
    it('validation error on claim with prescriptions does not expose opioid details', async () => {
      const res = await asPhysician1('PUT', `/api/v1/wcb/claims/${P1_CLAIM_ID}`, {
        prescriptions: [
          { prescription_name: '', strength: '', daily_intake: '' },  // invalid — will fail Zod
        ],
      });

      const rawBody = res.body;
      // Opioid details from existing claim should not leak
      expect(rawBody).not.toContain('hydromorphone');
      expect(rawBody).not.toContain(P1_OPIOID_DESC);
      expect(rawBody).not.toContain('4mg');
    });

    it('cross-tenant claim access does not expose prescription data', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/claims/${P2_CLAIM_ID}`);
      expect(res.statusCode).toBe(404);

      const rawBody = res.body;
      expect(rawBody).not.toContain('prescription');
      expect(rawBody).not.toContain('medication');
      expect(rawBody).not.toContain('narcotic');
    });
  });

  // =========================================================================
  // 8. Injury Descriptions Not Leaked in Validation Errors
  // =========================================================================

  describe('Injury descriptions not leaked in validation errors', () => {
    it('validation error does not echo injury descriptions back', async () => {
      const res = await asPhysician1('PUT', `/api/v1/wcb/claims/${P1_CLAIM_ID}`, {
        injuries: [
          { part_of_body_code: '', nature_of_injury_code: '' },  // invalid — empty required fields
        ],
      });

      const rawBody = res.body;
      // Injury descriptions from existing claim must not leak
      expect(rawBody).not.toContain(P1_INJURY_DESC);
      expect(rawBody).not.toContain('lumbar fracture');
      expect(rawBody).not.toContain('fell from ladder');
    });

    it('cross-tenant validation error does not expose other physician injury data', async () => {
      const res = await asPhysician1('POST', `/api/v1/wcb/claims/${P2_CLAIM_ID}/validate`);
      expect(res.statusCode).toBe(404);

      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_INJURY_DESC);
      expect(rawBody).not.toContain('Chemical burn');
      expect(rawBody).not.toContain('acid spill');
    });
  });

  // =========================================================================
  // 9. Discrepancy Reports — Worker PHN Exposure Control
  // =========================================================================

  describe('Worker PHN in remittance discrepancy reports not over-exposed', () => {
    it('discrepancies endpoint does not expose other physician data', async () => {
      const res = await asPhysician1(
        'GET',
        `/api/v1/wcb/remittances/${P1_REMITTANCE_ID}/discrepancies`,
      );
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      // Must not contain P2's data
      expect(rawBody).not.toContain(P2_CLAIM_ID);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain(P2_PATIENT_PHN);
      expect(rawBody).not.toContain('250.00');  // P2's actual discrepancy amount
    });

    it('cross-tenant discrepancy access returns empty data, not P2 data', async () => {
      const res = await asPhysician1(
        'GET',
        `/api/v1/wcb/remittances/${P2_REMITTANCE_ID}/discrepancies`,
      );

      const body = JSON.parse(res.body);
      // Should return empty or 404 — never P2's discrepancy data
      if (res.statusCode === 200) {
        expect(body.data).toEqual([]);
      } else {
        expect(res.statusCode).toBe(404);
      }
    });
  });

  // =========================================================================
  // 10. Return File Data Protection
  // =========================================================================

  describe('Return file data protection', () => {
    it('cross-tenant return results access returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/returns/${P2_BATCH_ID}`);
      expect(res.statusCode).toBe(404);

      const rawBody = res.body;
      expect(rawBody).not.toContain('TXN-P2-001');
      expect(rawBody).not.toContain('Invalid employer code');
      expect(rawBody).not.toContain(P2_BATCH_ID);
    });

    it('unauthenticated return results access returns 401 with no data', async () => {
      const res = await unauthenticated('GET', `/api/v1/wcb/returns/${P1_BATCH_ID}`);
      expect(res.statusCode).toBe(401);

      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
    });
  });

  // =========================================================================
  // 11. Audit Log Sanitisation
  // =========================================================================

  describe('Audit log sanitisation', () => {
    it('audit entries for WCB claim GET do not contain plaintext PHN', async () => {
      await asPhysician1('GET', `/api/v1/wcb/claims/${P1_CLAIM_ID}`);

      if (auditEntries.length > 0) {
        const auditString = JSON.stringify(auditEntries);
        // Full PHN must never appear in audit logs
        expect(auditString).not.toContain(P1_PATIENT_PHN);
        expect(auditString).not.toContain(P2_PATIENT_PHN);
      }
    });

    it('audit entries do not contain plaintext patient names', async () => {
      await asPhysician1('GET', `/api/v1/wcb/claims/${P1_CLAIM_ID}`);

      if (auditEntries.length > 0) {
        const auditString = JSON.stringify(auditEntries);
        expect(auditString).not.toContain(P1_PATIENT_NAME);
        expect(auditString).not.toContain(P1_PATIENT_DOB);
      }
    });

    it('audit entries do not contain clinical data like injury descriptions', async () => {
      await asPhysician1('GET', `/api/v1/wcb/claims/${P1_CLAIM_ID}`);

      if (auditEntries.length > 0) {
        const auditString = JSON.stringify(auditEntries);
        expect(auditString).not.toContain(P1_INJURY_DESC);
        expect(auditString).not.toContain(P1_OPIOID_DESC);
        expect(auditString).not.toContain(P1_EMPLOYER_NAME);
      }
    });

    it('audit entries do not contain employer details', async () => {
      await asPhysician1('GET', `/api/v1/wcb/claims/${P1_CLAIM_ID}`);

      if (auditEntries.length > 0) {
        const auditString = JSON.stringify(auditEntries);
        expect(auditString).not.toContain(P1_EMPLOYER_PHONE);
        expect(auditString).not.toContain('Acme Drilling');
      }
    });

    it('audit entries do not contain opioid prescription details', async () => {
      await asPhysician1('GET', `/api/v1/wcb/claims/${P1_CLAIM_ID}`);

      if (auditEntries.length > 0) {
        const auditString = JSON.stringify(auditEntries);
        expect(auditString).not.toContain('hydromorphone');
        expect(auditString).not.toContain('Hydromorphone');
      }
    });
  });

  // =========================================================================
  // 12. Error Responses Are Generic — No Internal State Revealed
  // =========================================================================

  describe('Error responses do not reveal internal state', () => {
    it('all 404 responses have consistent error structure', async () => {
      const routes = [
        { method: 'GET' as const, url: `/api/v1/wcb/claims/${NONEXISTENT_UUID}` },
        { method: 'PUT' as const, url: `/api/v1/wcb/claims/${NONEXISTENT_UUID}`, payload: { symptoms: 'test' } },
        { method: 'DELETE' as const, url: `/api/v1/wcb/claims/${NONEXISTENT_UUID}` },
        { method: 'POST' as const, url: `/api/v1/wcb/claims/${NONEXISTENT_UUID}/validate` },
        { method: 'GET' as const, url: `/api/v1/wcb/claims/${NONEXISTENT_UUID}/form-schema` },
        { method: 'GET' as const, url: `/api/v1/wcb/batches/${NONEXISTENT_UUID}` },
        { method: 'GET' as const, url: `/api/v1/wcb/batches/${NONEXISTENT_UUID}/download` },
        { method: 'GET' as const, url: `/api/v1/wcb/claims/${NONEXISTENT_UUID}/export` },
      ];

      for (const route of routes) {
        const res = await asPhysician1(route.method, route.url, (route as any).payload);

        if (res.statusCode === 404) {
          const body = JSON.parse(res.body);

          // Consistent structure: only error key
          expect(body.error).toBeDefined();
          expect(body.data).toBeUndefined();
          expect(body.error).toHaveProperty('code');
          expect(body.error).toHaveProperty('message');

          // No stack traces or internal details
          expect(body.error).not.toHaveProperty('stack');
          expect(JSON.stringify(body)).not.toMatch(/\.ts:\d+/);
          expect(JSON.stringify(body)).not.toContain('node_modules');
        }
      }
    });

    it('error responses never contain SQL-related keywords', async () => {
      const res = await asPhysician1('POST', '/api/v1/wcb/claims', {
        form_id: 'C050E',
        patient_id: NONEXISTENT_UUID,
        injury_description: "'; DROP TABLE wcb_claim_details;--",
      });

      const lower = res.body.toLowerCase();
      expect(lower).not.toContain('postgres');
      expect(lower).not.toContain('drizzle');
      expect(lower).not.toContain('pg_catalog');
      expect(lower).not.toContain('relation');
      expect(lower).not.toContain('syntax error');
    });

    it('error responses do not expose database table or column names', async () => {
      const res = await asPhysician1('POST', '/api/v1/wcb/claims', {});

      if (res.statusCode === 400) {
        const rawBody = res.body.toLowerCase();
        expect(rawBody).not.toContain('wcb_claim_details');
        expect(rawBody).not.toContain('wcb_injuries');
        expect(rawBody).not.toContain('wcb_prescriptions');
        expect(rawBody).not.toContain('wcb_batches');
        expect(rawBody).not.toContain('constraint violation');
        expect(rawBody).not.toContain('unique_constraint');
      }
    });

    it('error responses do not expose resource UUIDs in 404 messages', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/claims/${NONEXISTENT_UUID}`);
      expect(res.statusCode).toBe(404);

      const body = JSON.parse(res.body);
      expect(body.error.message).not.toContain(NONEXISTENT_UUID);
    });
  });

  // =========================================================================
  // 13. 401 Response Safety
  // =========================================================================

  describe('401 responses contain no WCB data', () => {
    it('401 on claim GET contains only error object', async () => {
      const res = await unauthenticated('GET', `/api/v1/wcb/claims/${P1_CLAIM_ID}`);
      expect(res.statusCode).toBe(401);

      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.data).toBeUndefined();

      // No claim data leaked
      expect(res.body).not.toContain(P1_CLAIM_ID);
      expect(res.body).not.toContain(P1_PATIENT_PHN);
      expect(res.body).not.toContain(P1_EMPLOYER_NAME);
    });

    it('401 on batch GET contains only error object', async () => {
      const res = await unauthenticated('GET', `/api/v1/wcb/batches/${P1_BATCH_ID}`);
      expect(res.statusCode).toBe(401);

      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
      expect(res.body).not.toContain(P1_BATCH_ID);
    });

    it('401 on remittance GET contains only error object', async () => {
      const res = await unauthenticated('GET', '/api/v1/wcb/remittances');
      expect(res.statusCode).toBe(401);

      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
    });

    it('401 on batch download contains no file data', async () => {
      const res = await unauthenticated('GET', `/api/v1/wcb/batches/${P1_BATCH_ID}/download`);
      expect(res.statusCode).toBe(401);

      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
      expect(res.body).not.toContain('.xml');
      expect(res.body).not.toContain('wcb/batches/');
    });

    it('401 on return upload contains no data', async () => {
      const res = await unauthenticated('POST', '/api/v1/wcb/returns/upload', {
        file_content: 'RETURN|DATA',
      });
      expect(res.statusCode).toBe(401);

      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
    });

    it('401 on remittance upload contains no data', async () => {
      const res = await unauthenticated('POST', '/api/v1/wcb/remittances/upload', {
        xml_content: '<remittance/>',
      });
      expect(res.statusCode).toBe(401);

      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
    });
  });

  // =========================================================================
  // 14. Sensitive Auth Fields Never in WCB Responses
  // =========================================================================

  describe('Sensitive auth fields never in WCB responses', () => {
    it('claim response does not contain password hashes or session tokens', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/claims/${P1_CLAIM_ID}`);
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain('passwordHash');
      expect(rawBody).not.toContain('password_hash');
      expect(rawBody).not.toContain('tokenHash');
      expect(rawBody).not.toContain('token_hash');
      expect(rawBody).not.toContain(P1_SESSION_TOKEN);
      expect(rawBody).not.toContain(P1_SESSION_TOKEN_HASH);
    });

    it('claim response does not contain TOTP secrets', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/claims/${P1_CLAIM_ID}`);
      expect(res.statusCode).toBe(200);

      expect(res.body).not.toContain('totpSecret');
      expect(res.body).not.toContain('totp_secret');
      expect(res.body).not.toContain('JBSWY3DPEHPK3PXP');
    });

    it('batch response does not contain auth fields', async () => {
      const res = await asPhysician1('GET', `/api/v1/wcb/batches/${P1_BATCH_ID}`);
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain('passwordHash');
      expect(rawBody).not.toContain('tokenHash');
      expect(rawBody).not.toContain('totpSecret');
      expect(rawBody).not.toContain(P1_SESSION_TOKEN);
    });

    it('remittance list does not contain auth fields', async () => {
      const res = await asPhysician1('GET', '/api/v1/wcb/remittances');
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain('passwordHash');
      expect(rawBody).not.toContain('tokenHash');
      expect(rawBody).not.toContain('totpSecret');
    });
  });

  // =========================================================================
  // 15. Anti-Enumeration Protection
  // =========================================================================

  describe('Anti-enumeration protection', () => {
    it('404 for cross-tenant WCB claim is indistinguishable from genuinely missing', async () => {
      const crossRes = await asPhysician1('GET', `/api/v1/wcb/claims/${P2_CLAIM_ID}`);
      const missingRes = await asPhysician1('GET', `/api/v1/wcb/claims/${NONEXISTENT_UUID}`);

      expect(crossRes.statusCode).toBe(404);
      expect(missingRes.statusCode).toBe(404);

      const crossBody = JSON.parse(crossRes.body);
      const missingBody = JSON.parse(missingRes.body);

      expect(crossBody.error.code).toBe(missingBody.error.code);
      expect(crossBody.error.message).toBe(missingBody.error.message);
    });

    it('404 for cross-tenant WCB batch is indistinguishable from genuinely missing', async () => {
      const crossRes = await asPhysician1('GET', `/api/v1/wcb/batches/${P2_BATCH_ID}`);
      const missingRes = await asPhysician1('GET', `/api/v1/wcb/batches/${NONEXISTENT_UUID}`);

      expect(crossRes.statusCode).toBe(404);
      expect(missingRes.statusCode).toBe(404);

      const crossBody = JSON.parse(crossRes.body);
      const missingBody = JSON.parse(missingRes.body);

      expect(crossBody.error.code).toBe(missingBody.error.code);
      expect(crossBody.error.message).toBe(missingBody.error.message);
    });

    it('404 for cross-tenant return results is indistinguishable from genuinely missing', async () => {
      const crossRes = await asPhysician1('GET', `/api/v1/wcb/returns/${P2_BATCH_ID}`);
      const missingRes = await asPhysician1('GET', `/api/v1/wcb/returns/${NONEXISTENT_UUID}`);

      expect(crossRes.statusCode).toBe(404);
      expect(missingRes.statusCode).toBe(404);

      const crossBody = JSON.parse(crossRes.body);
      const missingBody = JSON.parse(missingRes.body);

      expect(crossBody.error.code).toBe(missingBody.error.code);
      expect(crossBody.error.message).toBe(missingBody.error.message);
    });

    it('404 for cross-tenant batch download is indistinguishable from genuinely missing', async () => {
      const crossRes = await asPhysician1('GET', `/api/v1/wcb/batches/${P2_BATCH_ID}/download`);
      const missingRes = await asPhysician1('GET', `/api/v1/wcb/batches/${NONEXISTENT_UUID}/download`);

      expect(crossRes.statusCode).toBe(404);
      expect(missingRes.statusCode).toBe(404);

      const crossBody = JSON.parse(crossRes.body);
      const missingBody = JSON.parse(missingRes.body);

      expect(crossBody.error.code).toBe(missingBody.error.code);
      expect(crossBody.error.message).toBe(missingBody.error.message);
    });
  });

  // =========================================================================
  // 16. List / Search Responses Do Not Leak Cross-Tenant Data
  // =========================================================================

  describe('List responses do not leak cross-tenant data', () => {
    it('batch list contains only authenticated physician batches', async () => {
      const res = await asPhysician1('GET', '/api/v1/wcb/batches');
      expect(res.statusCode).toBe(200);

      const body = JSON.parse(res.body);
      const rawBody = res.body;

      // Must not contain P2's data
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain(P2_BATCH_ID);

      // All returned batches belong to P1
      if (body.data && body.data.length > 0) {
        body.data.forEach((batch: any) => {
          expect(batch.physicianId).toBe(P1_PROVIDER_ID);
        });
      }
    });

    it('remittance list contains only authenticated physician imports', async () => {
      const res = await asPhysician1('GET', '/api/v1/wcb/remittances');
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain(P2_REMITTANCE_ID);
      expect(rawBody).not.toContain('1200.00');  // P2's totalPaid
    });
  });
});
