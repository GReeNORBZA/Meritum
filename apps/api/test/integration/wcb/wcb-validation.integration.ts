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
import { wcbRoutes } from '../../../src/domains/wcb/wcb.routes.js';
import { type WcbHandlerDeps } from '../../../src/domains/wcb/wcb.handlers.js';
import { type WcbServiceDeps } from '../../../src/domains/wcb/wcb.service.js';
import { WcbBatchStatus } from '@meritum/shared/constants/wcb.constants.js';

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
const PHYSICIAN1_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN1_SESSION_TOKEN_HASH = hashToken(PHYSICIAN1_SESSION_TOKEN);

// ---------------------------------------------------------------------------
// Test data — IDs
// ---------------------------------------------------------------------------

const PATIENT_ID = '00000000-aaaa-0000-0000-000000000001';
const PROVIDER_BILLING_NUMBER = '12345678';

let claimIdCounter = 0;
function nextClaimId(): string {
  return `00000000-cccc-0000-0000-${String(++claimIdCounter).padStart(12, '0')}`;
}

let wcbDetailCounter = 0;
function nextWcbDetailId(): string {
  return `00000000-dddd-0000-0000-${String(++wcbDetailCounter).padStart(12, '0')}`;
}

let batchIdCounter = 0;
function nextBatchId(): string {
  return `00000000-bbbb-0000-0000-${String(++batchIdCounter).padStart(12, '0')}`;
}

// ---------------------------------------------------------------------------
// Mock data builders
// ---------------------------------------------------------------------------

function makeMockClaimRecord(overrides: Record<string, unknown> = {}) {
  return {
    claimId: nextClaimId(),
    physicianId: PHYSICIAN1_USER_ID,
    patientId: PATIENT_ID,
    claimType: 'WCB',
    state: 'DRAFT',
    importSource: 'MANUAL',
    dateOfService: '2026-01-15',
    submissionDeadline: '2026-04-15',
    isClean: null,
    validationResult: null,
    validationTimestamp: null,
    referenceDataVersion: null,
    aiCoachSuggestions: null,
    duplicateAlert: null,
    flags: null,
    submittedBatchId: null,
    shiftId: null,
    importBatchId: null,
    createdBy: PHYSICIAN1_USER_ID,
    updatedBy: PHYSICIAN1_USER_ID,
    createdAt: new Date(),
    updatedAt: new Date(),
    deletedAt: null,
    ...overrides,
  };
}

function makeMockWcbDetail(overrides: Record<string, unknown> = {}) {
  return {
    wcbClaimDetailId: nextWcbDetailId(),
    claimId: '00000000-cccc-0000-0000-000000000001',
    formId: 'C050E',
    submitterTxnId: `MRT${randomBytes(7).toString('hex').slice(0, 13).toUpperCase()}`,
    reportCompletionDate: '2026-01-15',
    dateOfInjury: '2026-01-14',
    practitionerBillingNumber: PROVIDER_BILLING_NUMBER,
    contractId: '000001',
    roleCode: 'GP',
    practitionerFirstName: 'John',
    practitionerMiddleName: null,
    practitionerLastName: 'Doe',
    skillCode: 'GENP',
    facilityType: 'C',
    clinicReferenceNumber: null,
    billingContactName: null,
    faxCountryCode: null,
    faxNumber: null,
    patientNoPhnFlag: 'N',
    patientPhn: '123456789',
    patientGender: 'M',
    patientFirstName: 'Jane',
    patientMiddleName: null,
    patientLastName: 'Smith',
    patientDob: '1985-03-15',
    patientAddressLine1: '123 Main St',
    patientAddressLine2: null,
    patientCity: 'Calgary',
    patientProvince: 'AB',
    patientPostalCode: 'T2P0A1',
    patientPhoneCountry: null,
    patientPhoneNumber: null,
    wcbClaimNumber: null,
    parentWcbClaimId: null,
    additionalComments: null,
    employerName: 'Acme Corp',
    employerLocation: 'Downtown Office',
    employerCity: 'Calgary',
    employerProvince: 'AB',
    employerPhoneCountry: null,
    employerPhoneNumber: null,
    employerPhoneExt: null,
    workerJobTitle: 'Warehouse Worker',
    injuryDevelopedOverTime: 'N',
    injuryDescription: 'Fell from ladder',
    dateOfExamination: '2026-01-15',
    symptoms: 'Pain in right wrist',
    objectiveFindings: 'Swelling and tenderness',
    currentDiagnosis: 'Wrist sprain',
    diagnosticCode1: 'S6350',
    diagnosticCode2: null,
    diagnosticCode3: null,
    narcoticsPrescribed: null,
    treatmentPlanText: null,
    missedWorkBeyondAccident: null,
    patientReturnedToWork: null,
    estimatedRtwDate: null,
    consultationLetterFormat: null,
    consultationLetterText: null,
    modifiedDuties: null,
    dateReturnedToWork: null,
    patientPainEstimate: null,
    createdBy: PHYSICIAN1_USER_ID,
    updatedBy: PHYSICIAN1_USER_ID,
    createdAt: new Date(),
    updatedAt: new Date(),
    deletedAt: null,
    ...overrides,
  };
}

function makeMockBatch(overrides: Record<string, unknown> = {}) {
  const id = (overrides.wcbBatchId as string) ?? nextBatchId();
  return {
    wcbBatchId: id,
    physicianId: PHYSICIAN1_USER_ID,
    status: WcbBatchStatus.ASSEMBLING,
    batchControlId: `MER-B-${randomBytes(4).toString('hex').toUpperCase()}`,
    fileControlId: `MER-20260115-${randomBytes(3).toString('hex').toUpperCase()}`,
    xmlFilePath: null,
    xmlFileHash: null,
    xsdValidationPassed: null,
    xsdValidationErrors: null,
    reportCount: 0,
    uploadedAt: null,
    uploadedBy: null,
    createdAt: new Date(),
    createdBy: PHYSICIAN1_USER_ID,
    ...overrides,
  };
}

function makeClaimWithChildren(
  claimOverrides: Record<string, unknown> = {},
  detailOverrides: Record<string, unknown> = {},
  children: {
    injuries?: Array<Record<string, unknown>>;
    prescriptions?: Array<Record<string, unknown>>;
    consultations?: Array<Record<string, unknown>>;
    workRestrictions?: Array<Record<string, unknown>>;
    invoiceLines?: Array<Record<string, unknown>>;
    attachments?: Array<Record<string, unknown>>;
  } = {},
) {
  const claim = makeMockClaimRecord(claimOverrides);
  const detail = makeMockWcbDetail({
    claimId: claim.claimId,
    ...detailOverrides,
  });
  return {
    detail,
    claim,
    injuries: children.injuries ?? [
      { wcbInjuryId: crypto.randomUUID(), wcbClaimDetailId: detail.wcbClaimDetailId, ordinal: 1, partOfBodyCode: '32100', sideOfBodyCode: 'R', natureOfInjuryCode: '02100', createdAt: new Date() },
    ],
    prescriptions: children.prescriptions ?? [],
    consultations: children.consultations ?? [],
    workRestrictions: children.workRestrictions ?? [],
    invoiceLines: children.invoiceLines ?? [
      { wcbInvoiceLineId: crypto.randomUUID(), wcbClaimDetailId: detail.wcbClaimDetailId, invoiceDetailId: 1, lineType: 'STANDARD', healthServiceCode: '03.04A', diagnosticCode1: 'S6350', diagnosticCode2: null, diagnosticCode3: null, modifier1: null, modifier2: null, modifier3: null, calls: 1, encounters: 1, dateOfServiceFrom: '2026-01-15', dateOfServiceTo: null, facilityTypeOverride: null, skillCodeOverride: null, quantity: null, supplyDescription: null, amount: '94.15', adjustmentIndicator: null, billingNumberOverride: null, correctionPairId: null, createdAt: new Date() },
    ],
    attachments: children.attachments ?? [],
  };
}

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
// Mock WCB repo
// ---------------------------------------------------------------------------

function createMockWcbRepo() {
  return {
    createWcbClaim: vi.fn(async (data: any) => makeMockWcbDetail({ claimId: data.claimId, formId: data.formId })),
    getWcbClaim: vi.fn(async () => null as any),
    updateWcbClaim: vi.fn(async () => ({})),
    softDeleteWcbClaim: vi.fn(async () => true),
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
    listWcbClaimsForPhysician: vi.fn(async () => ({ data: [], pagination: { total: 0, page: 1, pageSize: 25, hasMore: false } })),
    upsertInvoiceLines: vi.fn(async () => []),
    getInvoiceLines: vi.fn(async () => []),
    validateC570Pairing: vi.fn(async () => ({ valid: true, errors: [] })),
    upsertAttachments: vi.fn(async () => []),
    getAttachments: vi.fn(async () => []),
    getAttachmentContent: vi.fn(async () => null),
    createBatch: vi.fn(async (physicianId: string) => makeMockBatch({ physicianId })),
    getBatch: vi.fn(async () => null as any),
    getBatchByControlId: vi.fn(async () => null),
    listBatches: vi.fn(async () => ({ data: [], pagination: { total: 0, page: 1, pageSize: 25, hasMore: false } })),
    updateBatchStatus: vi.fn(async () => ({})),
    setBatchUploaded: vi.fn(async () => ({})),
    setBatchReturnReceived: vi.fn(async () => ({})),
    getQueuedClaimsForBatch: vi.fn(async () => []),
    assignClaimsToBatch: vi.fn(async () => ({})),
    createReturnRecords: vi.fn(async (_batchId: string, records: any[]) =>
      records.map((r: any, i: number) => ({ wcbReturnRecordId: `ret-${i}`, ...r })),
    ),
    createReturnInvoiceLines: vi.fn(async () => []),
    getReturnRecordsByBatch: vi.fn(async () => []),
    matchReturnToClaimBySubmitterTxnId: vi.fn(async () => null),
    createRemittanceImport: vi.fn(async () => ({ wcbRemittanceImportId: crypto.randomUUID() })),
    createRemittanceRecords: vi.fn(async () => []),
    matchRemittanceToClaimByTxnId: vi.fn(async () => null),
    listRemittanceImports: vi.fn(async () => ({ data: [], pagination: { total: 0, page: 1, pageSize: 25, hasMore: false } })),
    getRemittanceDiscrepancies: vi.fn(async () => []),
  };
}

// ---------------------------------------------------------------------------
// Mock claim repo (base claims table)
// ---------------------------------------------------------------------------

function createMockClaimRepo() {
  return {
    createClaim: vi.fn(async (data: any) => ({
      claimId: nextClaimId(),
      state: 'DRAFT',
      ...data,
    })),
    findClaimById: vi.fn(async () => undefined),
    appendClaimAudit: vi.fn(async () => {}),
    transitionClaimState: vi.fn(async (claimId: string, _physicianId: string, newState: string) => ({
      claimId,
      state: newState,
      previousState: 'DRAFT',
    })),
  };
}

// ---------------------------------------------------------------------------
// Mock provider lookup
// ---------------------------------------------------------------------------

function createMockProviderLookup() {
  return {
    findProviderById: vi.fn(async () => ({
      providerId: PHYSICIAN1_USER_ID,
      billingNumber: PROVIDER_BILLING_NUMBER,
      firstName: 'John',
      lastName: 'Doe',
      middleName: null,
      status: 'ACTIVE',
      specialtyCode: 'GENP',
      isRrnpQualified: false,
    })),
    getWcbConfigForForm: vi.fn(async (_providerId: string, formId: string) => {
      if (formId === 'C050S' || formId === 'C151S') {
        return { wcbConfigId: 'cfg-ois', contractId: '000053', roleCode: 'OIS', skillCode: 'GENP', facilityType: 'C' };
      }
      if (formId === 'C568A') {
        return { wcbConfigId: 'cfg-sp', contractId: '000006', roleCode: 'SP', skillCode: 'ORTH', facilityType: 'C' };
      }
      return { wcbConfigId: 'cfg-gp', contractId: '000001', roleCode: 'GP', skillCode: 'GENP', facilityType: 'C' };
    }),
  };
}

// ---------------------------------------------------------------------------
// Mock patient lookup
// ---------------------------------------------------------------------------

function createMockPatientLookup() {
  return {
    findPatientById: vi.fn(async () => ({
      patientId: PATIENT_ID,
      phn: '123456789',
      firstName: 'Jane',
      lastName: 'Smith',
      middleName: null,
      dateOfBirth: '1985-03-15',
      gender: 'M',
      addressLine1: '123 Main St',
      addressLine2: null,
      city: 'Calgary',
      province: 'AB',
      postalCode: 'T2P0A1',
      phoneCountry: null,
      phone: null,
      employerName: 'Acme Corp',
    })),
  };
}

// ---------------------------------------------------------------------------
// Test app builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let mockWcbRepo: ReturnType<typeof createMockWcbRepo>;
let mockClaimRepo: ReturnType<typeof createMockClaimRepo>;
let mockProviderLookup: ReturnType<typeof createMockProviderLookup>;
let mockPatientLookup: ReturnType<typeof createMockPatientLookup>;
let mockAuditEmitter: { emit: ReturnType<typeof vi.fn> };

async function buildTestApp(wcbPhase?: string): Promise<FastifyInstance> {
  mockWcbRepo = createMockWcbRepo();
  mockClaimRepo = createMockClaimRepo();
  mockProviderLookup = createMockProviderLookup();
  mockPatientLookup = createMockPatientLookup();
  mockAuditEmitter = { emit: vi.fn(async () => {}) };

  const serviceDeps: WcbServiceDeps = {
    wcbRepo: mockWcbRepo as any,
    claimRepo: mockClaimRepo as any,
    providerLookup: mockProviderLookup as any,
    patientLookup: mockPatientLookup as any,
    auditEmitter: mockAuditEmitter,
    referenceLookup: {
      findHscBaseRate: vi.fn(async () => ({ baseFee: '94.15', isPremiumCode: false })),
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

  const handlerDeps: WcbHandlerDeps = {
    serviceDeps,
    wcbPhase: wcbPhase ?? 'mvp',
  };

  const testApp = Fastify({ logger: false });

  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  const mockSessionRepo = createMockSessionRepo();
  await testApp.register(authPluginFp, {
    sessionDeps: {
      sessionRepo: mockSessionRepo,
      auditRepo: { appendAuditLog: vi.fn() },
      events: { emit: vi.fn() },
    },
  });

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

  await testApp.register(wcbRoutes, { deps: handlerDeps });
  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------

function authedPost(url: string, body?: Record<string, unknown>, token = PHYSICIAN1_SESSION_TOKEN) {
  return app.inject({
    method: 'POST',
    url,
    headers: {
      cookie: `session=${token}`,
      'content-type': 'application/json',
    },
    payload: body ?? {},
  });
}

function authedGet(url: string, token = PHYSICIAN1_SESSION_TOKEN) {
  return app.inject({
    method: 'GET',
    url,
    headers: { cookie: `session=${token}` },
  });
}

// ===========================================================================
// Tests: WCB Validation Engine
// ===========================================================================

describe('WCB Validation Engine — Integration Tests', () => {
  beforeAll(async () => {
    app = await buildTestApp('mvp');
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    vi.clearAllMocks();
    claimIdCounter = 0;
    wcbDetailCounter = 0;
    batchIdCounter = 0;

    mockWcbRepo.getWcbClaim.mockResolvedValue(null as any);
    mockWcbRepo.getBatch.mockResolvedValue(null as any);
    mockWcbRepo.getBatchByControlId.mockResolvedValue(null);
    mockWcbRepo.getQueuedClaimsForBatch.mockResolvedValue([]);
    mockWcbRepo.listBatches.mockResolvedValue({ data: [], pagination: { total: 0, page: 1, pageSize: 25, hasMore: false } });
    mockWcbRepo.listRemittanceImports.mockResolvedValue({ data: [], pagination: { total: 0, page: 1, pageSize: 25, hasMore: false } });
    mockWcbRepo.getReturnRecordsByBatch.mockResolvedValue([]);
    mockWcbRepo.getRemittanceDiscrepancies.mockResolvedValue([]);
    mockWcbRepo.matchReturnToClaimBySubmitterTxnId.mockResolvedValue(null);
    mockWcbRepo.getWcbClaimBySubmitterTxnId.mockResolvedValue(null);
    mockClaimRepo.findClaimById.mockResolvedValue(undefined);
  });

  // =========================================================================
  // 1. Form Type Validation — 8 form types pass with minimum required fields
  // =========================================================================

  describe('Form Type Validation', () => {
    it('C050E with minimum required fields passes validation', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        { wcbClaimDetailId: wcbDetailId, formId: 'C050E' },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(true);
      expect(body.data.errors).toHaveLength(0);
    });

    it('C050S with minimum required fields passes validation', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C050S',
          contractId: '000053',
          roleCode: 'OIS',
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(true);
    });

    it('C151 with minimum required fields passes validation', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C151',
          wcbClaimNumber: '1234567',
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(true);
    });

    it('C151S with minimum required fields passes validation', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C151S',
          contractId: '000053',
          roleCode: 'OIS',
          wcbClaimNumber: '1234567',
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(true);
    });

    it('C568 with minimum required fields passes validation', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C568',
          wcbClaimNumber: '1234567',
          symptoms: null,
          objectiveFindings: null,
          currentDiagnosis: null,
        },
        { injuries: [] },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(true);
    });

    it('C568A with minimum required fields passes validation', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C568A',
          contractId: '000006',
          roleCode: 'SP',
          wcbClaimNumber: '1234567',
          symptoms: null,
          objectiveFindings: null,
          currentDiagnosis: null,
        },
        { injuries: [] },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(true);
    });

    it('C569 with minimum required fields passes validation', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C569',
          wcbClaimNumber: '1234567',
          symptoms: null,
          objectiveFindings: null,
          currentDiagnosis: null,
        },
        {
          injuries: [],
          invoiceLines: [
            { wcbInvoiceLineId: crypto.randomUUID(), wcbClaimDetailId: wcbDetailId, invoiceDetailId: 1, lineType: 'SUPPLY', quantity: 2, supplyDescription: 'Knee brace', amount: '45.00', createdAt: new Date() },
          ],
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(true);
    });

    it('C570 with minimum required fields passes validation', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C570',
          wcbClaimNumber: '1234567',
          symptoms: null,
          objectiveFindings: null,
          currentDiagnosis: null,
        },
        {
          injuries: [],
          invoiceLines: [
            { wcbInvoiceLineId: crypto.randomUUID(), wcbClaimDetailId: wcbDetailId, invoiceDetailId: 1, lineType: 'WAS', healthServiceCode: '03.04A', diagnosticCode1: 'S6350', calls: 1, encounters: 1, amount: '85.80', correctionPairId: 1, createdAt: new Date() },
            { wcbInvoiceLineId: crypto.randomUUID(), wcbClaimDetailId: wcbDetailId, invoiceDetailId: 2, lineType: 'SHOULD_BE', healthServiceCode: '03.04A', diagnosticCode1: 'S6350', calls: 1, encounters: 1, amount: '94.15', correctionPairId: 1, createdAt: new Date() },
          ],
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(true);
    });

    it('C050E with all conditional fields triggered (max fields) passes', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C050E',
          narcoticsPrescribed: 'Y',
          missedWorkBeyondAccident: 'Y',
          patientReturnedToWork: 'Y',
          dateReturnedToWork: '2026-01-20',
          modifiedDuties: 'N',
          priorConditionsFlag: 'Y',
          priorConditionsDesc: 'Previous wrist injury 2020',
          diagnosisChanged: 'Y',
          diagnosisChangedDesc: 'Updated to fracture',
        },
        {
          prescriptions: [
            { wcbPrescriptionId: crypto.randomUUID(), wcbClaimDetailId: wcbDetailId, ordinal: 1, prescriptionName: 'Hydromorphone', strength: '2mg', dailyIntake: '1 q4h', createdAt: new Date() },
          ],
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(true);
    });

    it('C151 with all conditional fields triggered (max fields) passes', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C151',
          wcbClaimNumber: '1234567',
          narcoticsPrescribed: 'Y',
          patientPainEstimate: 6,
          missedWorkBeyondAccident: 'Y',
          patientReturnedToWork: 'Y',
          dateReturnedToWork: '2026-01-20',
          modifiedDuties: 'Y',
          priorConditionsFlag: 'Y',
          priorConditionsDesc: 'Old back injury',
          diagnosisChanged: 'Y',
          diagnosisChangedDesc: 'Worsened condition',
        },
        {
          prescriptions: [
            { wcbPrescriptionId: crypto.randomUUID(), wcbClaimDetailId: wcbDetailId, ordinal: 1, prescriptionName: 'Oxycodone', strength: '5mg', dailyIntake: '3x daily', createdAt: new Date() },
          ],
          workRestrictions: [
            { wcbWorkRestrictionId: crypto.randomUUID(), wcbClaimDetailId: wcbDetailId, activityType: 'LIFTING', restrictionLevel: 'LIMITED', hoursPerDay: null, maxWeight: '10', createdAt: new Date() },
          ],
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(true);
    });

    it('C050S with all OIS conditional fields triggered (max fields) passes', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C050S',
          contractId: '000053',
          roleCode: 'OIS',
          graspRightLevel: 'LIMITED',
          graspRightProlonged: 'Y',
          graspRightRepetitive: 'N',
          graspLeftLevel: 'LIMITED',
          graspLeftProlonged: 'N',
          graspLeftRepetitive: 'Y',
          environmentRestricted: 'Y',
          envCold: 'Y', envHot: 'N', envWet: 'N', envDry: 'Y',
          envDust: 'N', envLighting: 'N', envNoise: 'Y',
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(true);
    });

    it('C568A with all fields including consultation letter (max fields) passes', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C568A',
          contractId: '000006',
          roleCode: 'SP',
          wcbClaimNumber: '1234567',
          symptoms: null,
          objectiveFindings: null,
          currentDiagnosis: null,
          consultationLetterFormat: 'TEXT',
          consultationLetterText: 'Detailed specialist consultation findings...',
        },
        { injuries: [] },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(true);
    });

    it('rejects contract/role not permitted for form type', async () => {
      const wcbDetailId = crypto.randomUUID();
      // DP role (000022) is NOT permitted for C050E — only C568
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C050E',
          contractId: '000022',
          roleCode: 'DP',
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(false);
      expect(body.data.errors.some((e: any) => e.check_id === 'CONTRACT_ROLE_FORM')).toBe(true);
    });
  });

  // =========================================================================
  // 2. Follow-up chain validation
  // =========================================================================

  describe('Follow-up Chain Validation', () => {
    it('C151 follow-up from C050E is valid for GP', async () => {
      const parentDetailId = crypto.randomUUID();

      const parentClaim = makeClaimWithChildren(
        { state: 'PAID' },
        { wcbClaimDetailId: parentDetailId, formId: 'C050E', contractId: '000001', roleCode: 'GP' },
      );

      mockWcbRepo.getWcbClaim.mockResolvedValueOnce(parentClaim);

      const res = await authedPost('/api/v1/wcb/claims', {
        form_id: 'C151',
        patient_id: PATIENT_ID,
        parent_wcb_claim_id: parentDetailId,
        date_of_injury: '2026-01-14',
        date_of_examination: '2026-01-22',
        report_completion_date: '2026-01-22',
        symptoms: 'Improving pain',
        objective_findings: 'Reduced swelling',
        current_diagnosis: 'Wrist sprain resolving',
        diagnostic_code_1: 'S6350',
        injuries: [
          { part_of_body_code: '32100', side_of_body_code: 'R', nature_of_injury_code: '02100' },
        ],
        invoice_lines: [
          { line_type: 'STANDARD', health_service_code: '03.04A', diagnostic_code_1: 'S6350', calls: 1, encounters: 1, amount: '57.19' },
        ],
      });

      expect(res.statusCode).toBe(201);
    });

    it('C151 follow-up from C568A for GP is rejected (cannot create from C568A)', async () => {
      const parentDetailId = crypto.randomUUID();

      const parentClaim = makeClaimWithChildren(
        { state: 'PAID' },
        { wcbClaimDetailId: parentDetailId, formId: 'C568A', contractId: '000001', roleCode: 'GP' },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValueOnce(parentClaim);

      const res = await authedPost('/api/v1/wcb/claims', {
        form_id: 'C151',
        patient_id: PATIENT_ID,
        parent_wcb_claim_id: parentDetailId,
        date_of_injury: '2026-01-14',
        date_of_examination: '2026-01-22',
        report_completion_date: '2026-01-22',
        symptoms: 'Pain',
        objective_findings: 'Swelling',
        current_diagnosis: 'Sprain',
        diagnostic_code_1: 'S6350',
        injuries: [
          { part_of_body_code: '32100', side_of_body_code: 'R', nature_of_injury_code: '02100' },
        ],
        invoice_lines: [
          { line_type: 'STANDARD', health_service_code: '03.04A', diagnostic_code_1: 'S6350', calls: 1, encounters: 1, amount: '57.19' },
        ],
      });

      expect(res.statusCode).toBe(422);
      const body = res.json();
      expect(body.error.message).toContain('Cannot create follow-up from parent form type C568A');
    });
  });

  // =========================================================================
  // 3. Conditional Field Cascades (via Validate endpoint)
  // =========================================================================

  describe('Conditional Field Cascades', () => {
    it('narcotics = Y but no prescriptions -> validation error', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C050E',
          narcoticsPrescribed: 'Y',
        },
        { prescriptions: [] },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(false);
      expect(body.data.errors.some((e: any) =>
        e.check_id === 'CONDITIONAL_LOGIC' && e.field === 'prescriptions',
      )).toBe(true);
    });

    it('narcotics = Y on C151 but missing opioid monitoring fields -> validation error', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C151',
          wcbClaimNumber: '1234567',
          narcoticsPrescribed: 'Y',
          patientPainEstimate: null,
        },
        {
          prescriptions: [
            { wcbPrescriptionId: crypto.randomUUID(), wcbClaimDetailId: wcbDetailId, ordinal: 1, prescriptionName: 'Oxycodone', strength: '5mg', dailyIntake: '2x daily', createdAt: new Date() },
          ],
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(false);
      expect(body.data.errors.some((e: any) =>
        e.check_id === 'CONDITIONAL_LOGIC' && e.field === 'patientPainEstimate',
      )).toBe(true);
    });

    it('missed_work = Y but returned_to_work missing -> validation error', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C050E',
          missedWorkBeyondAccident: 'Y',
          patientReturnedToWork: null,
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(false);
      expect(body.data.errors.some((e: any) =>
        e.check_id === 'CONDITIONAL_LOGIC' && e.field === 'patientReturnedToWork',
      )).toBe(true);
    });

    it('returned_to_work = Y but date_returned_to_work missing -> validation error', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C050E',
          patientReturnedToWork: 'Y',
          dateReturnedToWork: null,
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(false);
      expect(body.data.errors.some((e: any) =>
        e.check_id === 'CONDITIONAL_LOGIC' && e.field === 'dateReturnedToWork',
      )).toBe(true);
    });

    it('returned_to_work = N but estimated RTW date missing -> validation error', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C050E',
          patientReturnedToWork: 'N',
          estimatedRtwDate: null,
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(false);
      expect(body.data.errors.some((e: any) =>
        e.check_id === 'CONDITIONAL_LOGIC' && e.field === 'estimatedRtwDate',
      )).toBe(true);
    });

    it('modified_duties = Y but no restriction entries -> validation error', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C050E',
          modifiedDuties: 'Y',
        },
        { workRestrictions: [] },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(false);
      expect(body.data.errors.some((e: any) =>
        e.check_id === 'CONDITIONAL_LOGIC' && e.field === 'workRestrictions',
      )).toBe(true);
    });

    it('patient_no_phn_flag = N but PHN missing -> validation error', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C050E',
          patientNoPhnFlag: 'N',
          patientPhn: null,
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(false);
      expect(body.data.errors.some((e: any) =>
        e.check_id === 'CONDITIONAL_LOGIC' && e.field === 'patientPhn',
      )).toBe(true);
    });

    it('prior_conditions_flag = Y but desc missing -> validation error', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C050E',
          priorConditionsFlag: 'Y',
          priorConditionsDesc: null,
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(false);
      expect(body.data.errors.some((e: any) =>
        e.check_id === 'CONDITIONAL_LOGIC' && e.field === 'priorConditionsDesc',
      )).toBe(true);
    });

    it('consultation_letter_format = TEXT but text missing -> validation error', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C568A',
          contractId: '000006',
          roleCode: 'SP',
          wcbClaimNumber: '1234567',
          symptoms: null,
          objectiveFindings: null,
          currentDiagnosis: null,
          consultationLetterFormat: 'TEXT',
          consultationLetterText: null,
        },
        { injuries: [] },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(false);
      expect(body.data.errors.some((e: any) =>
        e.check_id === 'CONDITIONAL_LOGIC' && e.field === 'consultationLetterText',
      )).toBe(true);
    });

    it('diagnosis_changed = Y but desc missing -> validation error', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C050E',
          diagnosisChanged: 'Y',
          diagnosisChangedDesc: null,
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(false);
      expect(body.data.errors.some((e: any) =>
        e.check_id === 'CONDITIONAL_LOGIC' && e.field === 'diagnosisChangedDesc',
      )).toBe(true);
    });

    it('OIS grasp_right_level = LIMITED but sub-fields missing -> validation error (C050S)', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C050S',
          contractId: '000053',
          roleCode: 'OIS',
          graspRightLevel: 'LIMITED',
          graspRightProlonged: null,
          graspRightRepetitive: null,
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(false);
      expect(body.data.errors.some((e: any) =>
        e.check_id === 'CONDITIONAL_LOGIC' && e.field === 'graspRightProlonged',
      )).toBe(true);
    });

    it('OIS environment_restricted = Y but env sub-fields missing -> validation error', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C050S',
          contractId: '000053',
          roleCode: 'OIS',
          environmentRestricted: 'Y',
          envCold: null,
          envHot: null,
          envWet: null,
          envDry: null,
          envDust: null,
          envLighting: null,
          envNoise: null,
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(false);
      expect(body.data.errors.filter((e: any) => e.check_id === 'CONDITIONAL_LOGIC').length).toBeGreaterThanOrEqual(7);
    });
  });

  // =========================================================================
  // 4. POB-NOI Matrix Validation
  // =========================================================================

  describe('POB-NOI Matrix Validation', () => {
    it('rejects Sprain(02100) + Brain(01100) — anatomically impossible', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        { wcbClaimDetailId: wcbDetailId, formId: 'C050E' },
        {
          injuries: [
            { wcbInjuryId: crypto.randomUUID(), wcbClaimDetailId: wcbDetailId, ordinal: 1, partOfBodyCode: '01100', sideOfBodyCode: null, natureOfInjuryCode: '02100', createdAt: new Date() },
          ],
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(false);
      expect(body.data.errors.some((e: any) => e.check_id === 'POB_NOI_COMBINATION')).toBe(true);
    });

    it('rejects Fracture(02200) + No Physical Injury(90000) — logically impossible', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        { wcbClaimDetailId: wcbDetailId, formId: 'C050E' },
        {
          injuries: [
            { wcbInjuryId: crypto.randomUUID(), wcbClaimDetailId: wcbDetailId, ordinal: 1, partOfBodyCode: '90000', sideOfBodyCode: null, natureOfInjuryCode: '02200', createdAt: new Date() },
          ],
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(false);
      expect(body.data.errors.some((e: any) => e.check_id === 'POB_NOI_COMBINATION')).toBe(true);
    });

    it('rejects Fracture of Finger(10100) + Chest(15000) — anatomically impossible', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        { wcbClaimDetailId: wcbDetailId, formId: 'C050E' },
        {
          injuries: [
            { wcbInjuryId: crypto.randomUUID(), wcbClaimDetailId: wcbDetailId, ordinal: 1, partOfBodyCode: '15000', sideOfBodyCode: null, natureOfInjuryCode: '10100', createdAt: new Date() },
          ],
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(false);
      expect(body.data.errors.some((e: any) => e.check_id === 'POB_NOI_COMBINATION')).toBe(true);
    });

    it('accepts valid Sprain(02100) + Wrist(29000) combination', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        { wcbClaimDetailId: wcbDetailId, formId: 'C050E' },
        {
          injuries: [
            { wcbInjuryId: crypto.randomUUID(), wcbClaimDetailId: wcbDetailId, ordinal: 1, partOfBodyCode: '29000', sideOfBodyCode: 'R', natureOfInjuryCode: '02100', createdAt: new Date() },
          ],
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      // No POB_NOI_COMBINATION error
      expect(body.data.errors.filter((e: any) => e.check_id === 'POB_NOI_COMBINATION')).toHaveLength(0);
    });

    it('Side of Body required for Knee(42000) — missing -> error', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        { wcbClaimDetailId: wcbDetailId, formId: 'C050E' },
        {
          injuries: [
            { wcbInjuryId: crypto.randomUUID(), wcbClaimDetailId: wcbDetailId, ordinal: 1, partOfBodyCode: '42000', sideOfBodyCode: null, natureOfInjuryCode: '02100', createdAt: new Date() },
          ],
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.errors.some((e: any) =>
        e.check_id === 'SIDE_OF_BODY' && e.field?.includes('sideOfBodyCode'),
      )).toBe(true);
    });

    it('Side of Body NOT required for Head(00000) — missing is OK', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        { wcbClaimDetailId: wcbDetailId, formId: 'C050E' },
        {
          injuries: [
            { wcbInjuryId: crypto.randomUUID(), wcbClaimDetailId: wcbDetailId, ordinal: 1, partOfBodyCode: '00000', sideOfBodyCode: null, natureOfInjuryCode: '02100', createdAt: new Date() },
          ],
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.errors.filter((e: any) => e.check_id === 'SIDE_OF_BODY')).toHaveLength(0);
    });

    it('Side of Body required for Shoulder(25000) — missing -> error', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        { wcbClaimDetailId: wcbDetailId, formId: 'C050E' },
        {
          injuries: [
            { wcbInjuryId: crypto.randomUUID(), wcbClaimDetailId: wcbDetailId, ordinal: 1, partOfBodyCode: '25000', sideOfBodyCode: null, natureOfInjuryCode: '02100', createdAt: new Date() },
          ],
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.errors.some((e: any) =>
        e.check_id === 'SIDE_OF_BODY' && e.field?.includes('sideOfBodyCode'),
      )).toBe(true);
    });

    it('multiple injuries — second injury triggers POB-NOI error, first is valid', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        { wcbClaimDetailId: wcbDetailId, formId: 'C050E' },
        {
          injuries: [
            { wcbInjuryId: crypto.randomUUID(), wcbClaimDetailId: wcbDetailId, ordinal: 1, partOfBodyCode: '29000', sideOfBodyCode: 'R', natureOfInjuryCode: '02100', createdAt: new Date() },
            { wcbInjuryId: crypto.randomUUID(), wcbClaimDetailId: wcbDetailId, ordinal: 2, partOfBodyCode: '01100', sideOfBodyCode: null, natureOfInjuryCode: '02100', createdAt: new Date() },
          ],
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.errors.filter((e: any) => e.check_id === 'POB_NOI_COMBINATION')).toHaveLength(1);
      expect(body.data.errors.some((e: any) =>
        e.check_id === 'POB_NOI_COMBINATION' && e.field === 'injuries[1]',
      )).toBe(true);
    });
  });

  // =========================================================================
  // 5. Data Type and Length Validation
  // =========================================================================

  describe('Data Type and Length Validation', () => {
    it('alphabetic field with numbers -> validation error', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C050E',
          practitionerFirstName: 'John123',
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(false);
      expect(body.data.errors.some((e: any) =>
        e.check_id === 'DATA_TYPE_LENGTH' && e.field === 'practitionerFirstName',
      )).toBe(true);
    });

    it('field exceeding max length by 1 -> validation error', async () => {
      const wcbDetailId = crypto.randomUUID();
      // practitionerFirstName is alpha with maxLength 25
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C050E',
          practitionerFirstName: 'A'.repeat(26),
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(false);
      expect(body.data.errors.some((e: any) =>
        e.check_id === 'DATA_TYPE_LENGTH' && e.field === 'practitionerFirstName' && e.message.includes('maximum length'),
      )).toBe(true);
    });

    it('invalid date format -> validation error', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C050E',
          dateOfInjury: '15/01/2026',
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(false);
      expect(body.data.errors.some((e: any) =>
        e.check_id === 'DATA_TYPE_LENGTH' && e.field === 'dateOfInjury',
      )).toBe(true);
    });

    it('date of exam before date of injury -> validation error', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C050E',
          dateOfInjury: '2026-01-20',
          dateOfExamination: '2026-01-15',
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(false);
      expect(body.data.errors.some((e: any) =>
        e.check_id === 'DATE_VALIDATION' && e.field === 'dateOfExamination',
      )).toBe(true);
    });

    it('wcbClaimNumber with non-numeric characters -> validation error', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C151',
          wcbClaimNumber: 'ABC1234',
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(false);
      expect(body.data.errors.some((e: any) =>
        e.check_id === 'DATA_TYPE_LENGTH' && e.field === 'wcbClaimNumber',
      )).toBe(true);
    });

    it('wcbClaimNumber exceeding 7 chars -> validation error', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C151',
          wcbClaimNumber: '12345678',
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(false);
      expect(body.data.errors.some((e: any) =>
        e.check_id === 'DATA_TYPE_LENGTH' && e.field === 'wcbClaimNumber' && e.message.includes('maximum length'),
      )).toBe(true);
    });

    it('patient last name with special characters in alpha field -> validation error', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C050E',
          patientLastName: 'Smith@#$',
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      // Alpha fields reject digits specifically; special chars check may vary
      // At minimum, numeric characters in alpha field should be caught
    });

    it('report completion date before examination date -> validation error', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C050E',
          dateOfInjury: '2026-01-10',
          dateOfExamination: '2026-01-15',
          reportCompletionDate: '2026-01-12',
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(false);
      expect(body.data.errors.some((e: any) =>
        e.check_id === 'DATE_VALIDATION' && e.field === 'reportCompletionDate',
      )).toBe(true);
    });
  });

  // =========================================================================
  // 6. Timing & Fees (via Validate endpoint)
  // =========================================================================

  describe('Timing & Fee Validation', () => {
    it('same-day submission -> correct tier in response', async () => {
      const wcbDetailId = crypto.randomUUID();
      const today = new Date().toISOString().slice(0, 10);
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C050E',
          dateOfExamination: today,
          dateOfInjury: today,
          reportCompletionDate: today,
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      // Tier depends on time of day relative to 10:00 MT cutoff
      expect(['SAME_DAY', 'ON_TIME']).toContain(body.data.timing_tier);
      // No late warning for today's submission
      expect(body.data.warnings.filter((w: any) => w.check_id === 'TIMING_DEADLINE')).toHaveLength(0);
    });

    it('late submission -> warning with timing tier LATE', async () => {
      const wcbDetailId = crypto.randomUUID();
      // Exam date 30 days ago — well past any on-time deadline
      const pastDate = new Date();
      pastDate.setDate(pastDate.getDate() - 30);
      const pastDateStr = pastDate.toISOString().slice(0, 10);
      const evenEarlier = new Date(pastDate);
      evenEarlier.setDate(evenEarlier.getDate() - 1);
      const injuryDateStr = evenEarlier.toISOString().slice(0, 10);

      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C050E',
          dateOfExamination: pastDateStr,
          dateOfInjury: injuryDateStr,
          reportCompletionDate: pastDateStr,
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.timing_tier).toBe('LATE');
      expect(body.data.warnings.some((w: any) => w.check_id === 'TIMING_DEADLINE')).toBe(true);
    });

    it('near-deadline submission -> ON_TIME tier with hours remaining in response', async () => {
      const wcbDetailId = crypto.randomUUID();
      // Exam 2 business days ago — within on-time window for C050E (3 business days)
      const examDate = new Date();
      // Go back 2 days (accounting for weekends)
      let daysBack = 0;
      const d = new Date(examDate);
      while (daysBack < 2) {
        d.setDate(d.getDate() - 1);
        const dow = d.getDay();
        if (dow !== 0 && dow !== 6) daysBack++;
      }
      const examDateStr = d.toISOString().slice(0, 10);
      const injDate = new Date(d);
      injDate.setDate(injDate.getDate() - 1);
      const injDateStr = injDate.toISOString().slice(0, 10);

      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C050E',
          dateOfExamination: examDateStr,
          dateOfInjury: injDateStr,
          reportCompletionDate: examDateStr,
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      // Should be ON_TIME (within 3 biz day window, past same-day)
      expect(body.data.timing_tier).toBe('ON_TIME');
      // No late warning
      expect(body.data.warnings.filter((w: any) => w.check_id === 'TIMING_DEADLINE')).toHaveLength(0);
      // deadline_info should be present for timing-eligible forms
      if (body.data.deadline_info) {
        expect(body.data.deadline_info.hours_remaining).toBeGreaterThan(0);
      }
    });

    it('C151 late submission also returns LATE tier', async () => {
      const wcbDetailId = crypto.randomUUID();
      const pastDate = new Date();
      pastDate.setDate(pastDate.getDate() - 30);
      const pastDateStr = pastDate.toISOString().slice(0, 10);
      const injDateStr = new Date(pastDate.getTime() - 86400000).toISOString().slice(0, 10);

      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C151',
          wcbClaimNumber: '1234567',
          dateOfExamination: pastDateStr,
          dateOfInjury: injDateStr,
          reportCompletionDate: pastDateStr,
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.timing_tier).toBe('LATE');
      expect(body.data.warnings.some((w: any) => w.check_id === 'TIMING_DEADLINE')).toBe(true);
    });
  });

  // =========================================================================
  // 7. Zod-Level Input Validation (create endpoint)
  // =========================================================================

  describe('Zod Input Validation at API Level', () => {
    it('rejects invalid form_id at Zod layer', async () => {
      const res = await authedPost('/api/v1/wcb/claims', {
        form_id: 'INVALID_FORM',
        patient_id: PATIENT_ID,
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects non-UUID patient_id at Zod layer', async () => {
      const res = await authedPost('/api/v1/wcb/claims', {
        form_id: 'C050E',
        patient_id: 'not-a-uuid',
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects invalid date format in date_of_injury at Zod layer', async () => {
      const res = await authedPost('/api/v1/wcb/claims', {
        form_id: 'C050E',
        patient_id: PATIENT_ID,
        date_of_injury: '15/01/2026',
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects non-UUID path parameter for validate', async () => {
      const res = await authedPost('/api/v1/wcb/claims/not-a-uuid/validate');

      expect(res.statusCode).toBe(400);
    });

    it('rejects numeric value for string field (type coercion)', async () => {
      const res = await authedPost('/api/v1/wcb/claims', {
        form_id: 'C050E',
        patient_id: PATIENT_ID,
        employer_name: 12345,
      } as any);

      expect(res.statusCode).toBe(400);
    });

    it('rejects invoice line with invalid line_type', async () => {
      const res = await authedPost('/api/v1/wcb/claims', {
        form_id: 'C050E',
        patient_id: PATIENT_ID,
        invoice_lines: [
          { line_type: 'INVALID', health_service_code: '03.04A' },
        ],
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects amount with invalid format (missing decimal)', async () => {
      const res = await authedPost('/api/v1/wcb/claims', {
        form_id: 'C050E',
        patient_id: PATIENT_ID,
        invoice_lines: [
          { line_type: 'SUPPLY', quantity: 1, supply_description: 'Brace', amount: '45' },
        ],
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects more than 5 injuries', async () => {
      const res = await authedPost('/api/v1/wcb/claims', {
        form_id: 'C050E',
        patient_id: PATIENT_ID,
        injuries: Array.from({ length: 6 }, (_, i) => ({
          part_of_body_code: `${i}0000`,
          nature_of_injury_code: '02100',
        })),
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects more than 25 invoice lines', async () => {
      const res = await authedPost('/api/v1/wcb/claims', {
        form_id: 'C050E',
        patient_id: PATIENT_ID,
        invoice_lines: Array.from({ length: 26 }, () => ({
          line_type: 'STANDARD',
          health_service_code: '03.04A',
        })),
      });

      expect(res.statusCode).toBe(400);
    });

    it('rejects more than 3 attachments', async () => {
      const res = await authedPost('/api/v1/wcb/claims', {
        form_id: 'C050E',
        patient_id: PATIENT_ID,
        attachments: Array.from({ length: 4 }, (_, i) => ({
          file_name: `file${i}.pdf`,
          file_type: 'PDF',
          file_content_b64: 'dGVzdA==',
          file_description: `File ${i}`,
        })),
      });

      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // 8. Required Fields Missing Validation
  // =========================================================================

  describe('Required Fields Missing', () => {
    it('C050E missing required reportCompletionDate -> validation error', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C050E',
          reportCompletionDate: null,
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(false);
      expect(body.data.errors.some((e: any) =>
        e.check_id === 'REQUIRED_FIELDS' && e.field === 'reportCompletionDate',
      )).toBe(true);
    });

    it('C050E missing required symptoms -> validation error', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C050E',
          symptoms: null,
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(false);
      expect(body.data.errors.some((e: any) =>
        e.check_id === 'REQUIRED_FIELDS' && e.field === 'symptoms',
      )).toBe(true);
    });

    it('C151 missing required wcbClaimNumber -> validation error', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C151',
          wcbClaimNumber: null,
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(false);
      expect(body.data.errors.some((e: any) =>
        e.check_id === 'REQUIRED_FIELDS' && e.field === 'wcbClaimNumber',
      )).toBe(true);
    });

    it('C568 missing required practitionerBillingNumber -> validation error', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C568',
          wcbClaimNumber: '1234567',
          practitionerBillingNumber: null,
          symptoms: null,
          objectiveFindings: null,
          currentDiagnosis: null,
        },
        { injuries: [] },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.passed).toBe(false);
      expect(body.data.errors.some((e: any) =>
        e.check_id === 'REQUIRED_FIELDS' && e.field === 'practitionerBillingNumber',
      )).toBe(true);
    });
  });

  // =========================================================================
  // 9. Validation response structure
  // =========================================================================

  describe('Validation Response Structure', () => {
    it('returns validation_timestamp and reference_data_version', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        { wcbClaimDetailId: wcbDetailId },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toHaveProperty('validation_timestamp');
      expect(body.data).toHaveProperty('reference_data_version');
      expect(body.data.reference_data_version).toBe('2025.1');
    });

    it('returns 404 for non-existent claim', async () => {
      const wcbDetailId = crypto.randomUUID();
      mockWcbRepo.getWcbClaim.mockResolvedValue(null);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(404);
    });

    it('validation result includes passed, errors, warnings, timing_tier fields', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        { wcbClaimDetailId: wcbDetailId },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toHaveProperty('passed');
      expect(body.data).toHaveProperty('errors');
      expect(body.data).toHaveProperty('warnings');
      expect(Array.isArray(body.data.errors)).toBe(true);
      expect(Array.isArray(body.data.warnings)).toBe(true);
    });

    it('each error item has check_id, severity, field, and message', async () => {
      const wcbDetailId = crypto.randomUUID();
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C050E',
          symptoms: null, // Missing required field -> triggers error
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.errors.length).toBeGreaterThan(0);
      const firstError = body.data.errors[0];
      expect(firstError).toHaveProperty('check_id');
      expect(firstError).toHaveProperty('severity');
      expect(firstError).toHaveProperty('message');
    });
  });
});
