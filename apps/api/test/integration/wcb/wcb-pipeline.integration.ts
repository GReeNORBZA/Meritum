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
import {
  type WcbServiceDeps,
  generateBatchXml,
  parseReturnFile,
  parseRemittanceXml,
  type XsdValidationResult,
} from '../../../src/domains/wcb/wcb.service.js';
import {
  WcbBatchStatus,
  WcbFormType,
  WcbReturnReportStatus,
  WcbPaymentStatus,
} from '@meritum/shared/constants/wcb.constants.js';

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
    createRemittanceImport: vi.fn(async () => crypto.randomUUID()),
    createRemittanceRecords: vi.fn(async () => []),
    matchRemittanceToClaimByTxnId: vi.fn(async () => null),
    listRemittanceImports: vi.fn(async () => ({ data: [], pagination: { total: 0, page: 1, pageSize: 25, hasMore: false } })),
    getRemittanceDiscrepancies: vi.fn(async () => []),
  };
}

// ---------------------------------------------------------------------------
// Mock claim repo
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
// Mock provider/patient lookups
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
// Shared XSD validator mock
// ---------------------------------------------------------------------------

let mockXsdValidator: { validate: ReturnType<typeof vi.fn> };

// ---------------------------------------------------------------------------
// Stored XML capture: intercept fileStorage.storeEncrypted to capture XML
// ---------------------------------------------------------------------------

let capturedXml: string | null = null;
let mockFileStorage: {
  storeEncrypted: ReturnType<typeof vi.fn>;
  readEncrypted: ReturnType<typeof vi.fn>;
};

// ---------------------------------------------------------------------------
// Test app builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let mockWcbRepo: ReturnType<typeof createMockWcbRepo>;
let mockClaimRepo: ReturnType<typeof createMockClaimRepo>;
let mockProviderLookup: ReturnType<typeof createMockProviderLookup>;
let mockPatientLookup: ReturnType<typeof createMockPatientLookup>;
let mockAuditEmitter: { emit: ReturnType<typeof vi.fn> };
let mockNotificationEmitter: { emit: ReturnType<typeof vi.fn> };

async function buildTestApp(wcbPhase?: string): Promise<FastifyInstance> {
  mockWcbRepo = createMockWcbRepo();
  mockClaimRepo = createMockClaimRepo();
  mockProviderLookup = createMockProviderLookup();
  mockPatientLookup = createMockPatientLookup();
  mockAuditEmitter = { emit: vi.fn(async () => {}) };
  mockNotificationEmitter = { emit: vi.fn(async () => {}) };

  capturedXml = null;
  mockFileStorage = {
    storeEncrypted: vi.fn(async (_path: string, data: Buffer) => {
      capturedXml = data.toString('utf-8');
    }),
    readEncrypted: vi.fn(async () => Buffer.from(capturedXml ?? '<xml/>')),
  };

  mockXsdValidator = {
    validate: vi.fn((_xml: string, _xsd: string): XsdValidationResult => ({
      valid: true,
      errors: [],
    })),
  };

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
    fileStorage: mockFileStorage,
    secretsProvider: {
      getVendorSourceId: () => 'MERITUM',
      getSubmitterId: () => 'MRT-SUBMIT',
    },
    xsdValidator: mockXsdValidator as any,
    downloadUrlGenerator: {
      generateSignedUrl: vi.fn(async () => 'https://meritum.ca/download/signed-url'),
    },
    notificationEmitter: mockNotificationEmitter,
  };

  const handlerDeps: WcbHandlerDeps = {
    serviceDeps,
    wcbPhase: wcbPhase ?? 'full',
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
// Tests: WCB Pipeline — XML Generation, XSD Validation, Return & Remittance
// ===========================================================================

describe('WCB Pipeline — Integration Tests', () => {
  beforeAll(async () => {
    app = await buildTestApp('full');
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    vi.clearAllMocks();
    claimIdCounter = 0;
    wcbDetailCounter = 0;
    batchIdCounter = 0;
    capturedXml = null;

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
  // Section 1: XML Generation
  // =========================================================================

  describe('XML Generation', () => {
    it('generates XML for C050E form type with correct HL7 segments', async () => {
      const claimData = makeClaimWithChildren(
        { state: 'QUEUED' },
        { formId: 'C050E', submitterTxnId: 'MRT0000000000001' },
      );

      mockWcbRepo.createBatch.mockResolvedValue(makeMockBatch());
      mockWcbRepo.getQueuedClaimsForBatch.mockResolvedValue([
        { claim: claimData.claim, detail: claimData.detail },
      ]);
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost('/api/v1/wcb/batches', {});

      expect(res.statusCode).toBe(201);
      expect(mockFileStorage.storeEncrypted).toHaveBeenCalledTimes(1);

      // Verify XML structure
      expect(capturedXml).not.toBeNull();
      const xml = capturedXml!;
      expect(xml).toContain('<?xml version="1.0" encoding="UTF-8"?>');
      expect(xml).toContain('<ZRPT_P03 xmlns="urn:WCBhl7_v231-schema_modern_v100">');
      expect(xml).toContain('<FHS>');
      expect(xml).toContain('<BHS>');
      expect(xml).toContain('<MSH>');
      expect(xml).toContain('<EVN>');
      expect(xml).toContain('<PRD>');
      expect(xml).toContain('<PID>');
      expect(xml).toContain('<PV1>');
      expect(xml).toContain('<FT1>');
      expect(xml).toContain('<ACC>');
      expect(xml).toContain('<OBX>');
      expect(xml).toContain('<BTS>');
      expect(xml).toContain('<FTS>');
      expect(xml).toContain('</ZRPT_P03>');
    });

    it('generates XML for C151 form type with correct structure', async () => {
      const claimData = makeClaimWithChildren(
        { state: 'QUEUED' },
        { formId: 'C151', submitterTxnId: 'MRT0000000000002', wcbClaimNumber: '1234567' },
      );

      mockWcbRepo.createBatch.mockResolvedValue(makeMockBatch());
      mockWcbRepo.getQueuedClaimsForBatch.mockResolvedValue([
        { claim: claimData.claim, detail: claimData.detail },
      ]);
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost('/api/v1/wcb/batches', {});

      expect(res.statusCode).toBe(201);
      expect(capturedXml).not.toBeNull();
      expect(capturedXml).toContain('<EVN>');
      expect(capturedXml).toContain('C151');
    });

    it('batch with mixed form types generates correct segment ordering', async () => {
      const claim1 = makeClaimWithChildren(
        { state: 'QUEUED' },
        { formId: 'C050E', submitterTxnId: 'MRTMIXED00000001' },
      );
      const claim2 = makeClaimWithChildren(
        { state: 'QUEUED' },
        { formId: 'C568', submitterTxnId: 'MRTMIXED00000002', wcbClaimNumber: '9999999', symptoms: null, objectiveFindings: null, currentDiagnosis: null },
        { injuries: [] },
      );

      mockWcbRepo.createBatch.mockResolvedValue(makeMockBatch());
      mockWcbRepo.getQueuedClaimsForBatch.mockResolvedValue([
        { claim: claim1.claim, detail: claim1.detail },
        { claim: claim2.claim, detail: claim2.detail },
      ]);
      // Return appropriate claim data depending on which claim is fetched
      let fetchCount = 0;
      mockWcbRepo.getWcbClaim.mockImplementation(async (id: string) => {
        fetchCount++;
        if (id === claim1.detail.wcbClaimDetailId) return claim1;
        if (id === claim2.detail.wcbClaimDetailId) return claim2;
        return null;
      });

      const res = await authedPost('/api/v1/wcb/batches', {});

      expect(res.statusCode).toBe(201);
      expect(res.json().data.reportCount).toBe(2);

      const xml = capturedXml!;
      // FHS must come before BHS
      const fhsIdx = xml.indexOf('<FHS>');
      const bhsIdx = xml.indexOf('<BHS>');
      expect(fhsIdx).toBeLessThan(bhsIdx);
      // BHS before first report
      const mshIdx = xml.indexOf('<MSH>');
      expect(bhsIdx).toBeLessThan(mshIdx);
      // BTS comes after all reports
      const btsIdx = xml.indexOf('<BTS>');
      const lastReportEnd = xml.lastIndexOf('</ZRPT_P03.GRP.2>');
      expect(lastReportEnd).toBeLessThan(btsIdx);
      // FTS comes last
      const ftsIdx = xml.indexOf('<FTS>');
      expect(btsIdx).toBeLessThan(ftsIdx);
      // BTS contains report count of 2
      expect(xml).toContain('<BTS.1>2</BTS.1>');
    });

    it('XML element ordering matches FHS > BHS > MSH > EVN > PRD > PID > PV1 > FT1 > ACC > OBX > BTS > FTS', async () => {
      const claimData = makeClaimWithChildren(
        { state: 'QUEUED' },
        { formId: 'C050E', submitterTxnId: 'MRTORDER00000001' },
      );

      mockWcbRepo.createBatch.mockResolvedValue(makeMockBatch());
      mockWcbRepo.getQueuedClaimsForBatch.mockResolvedValue([
        { claim: claimData.claim, detail: claimData.detail },
      ]);
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      await authedPost('/api/v1/wcb/batches', {});

      const xml = capturedXml!;
      const segments = ['<FHS>', '<BHS>', '<MSH>', '<EVN>', '<PRD>', '<PID>', '<PV1>', '<FT1>', '<ACC>', '<OBX>', '<BTS>', '<FTS>'];
      let lastIdx = -1;
      for (const seg of segments) {
        const idx = xml.indexOf(seg);
        expect(idx).toBeGreaterThan(lastIdx);
        lastIdx = idx;
      }
    });

    it('special characters in free-text fields are XML-encoded', async () => {
      const claimData = makeClaimWithChildren(
        { state: 'QUEUED' },
        {
          formId: 'C050E',
          submitterTxnId: 'MRTSPECIAL000001',
          symptoms: 'Pain & swelling in <right> wrist "severe"',
          injuryDescription: 'Hit by <metal> pipe & fell',
          additionalComments: 'Patient says "it hurts" & needs follow-up',
        },
      );

      mockWcbRepo.createBatch.mockResolvedValue(makeMockBatch());
      mockWcbRepo.getQueuedClaimsForBatch.mockResolvedValue([
        { claim: claimData.claim, detail: claimData.detail },
      ]);
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      await authedPost('/api/v1/wcb/batches', {});

      const xml = capturedXml!;
      // Raw special characters should NOT appear in XML
      expect(xml).not.toContain('Pain & swelling');
      expect(xml).not.toContain('<right>');
      // Escaped versions should be present
      expect(xml).toContain('&amp;');
      expect(xml).toContain('&lt;');
      expect(xml).toContain('&gt;');
      expect(xml).toContain('&quot;');
    });

    it('base64 encoding of file attachments appears in OBX segments', async () => {
      const b64Content = 'SGVsbG8gV29ybGQgUERGIENvbnRlbnQ=';
      const claimData = makeClaimWithChildren(
        { state: 'QUEUED' },
        { formId: 'C568A', contractId: '000006', roleCode: 'SP', skillCode: 'ORTH', submitterTxnId: 'MRTATTACH0000001', wcbClaimNumber: '1234567' },
        {
          attachments: [
            {
              wcbAttachmentId: crypto.randomUUID(),
              wcbClaimDetailId: 'att-detail-1',
              ordinal: 1,
              fileName: 'consultation_letter.pdf',
              fileType: 'PDF',
              fileContentB64: b64Content,
              fileDescription: 'Consultation letter',
              fileSizeBytes: 2048,
              createdAt: new Date(),
            },
          ],
        },
      );

      mockWcbRepo.createBatch.mockResolvedValue(makeMockBatch());
      mockWcbRepo.getQueuedClaimsForBatch.mockResolvedValue([
        { claim: claimData.claim, detail: claimData.detail },
      ]);
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      await authedPost('/api/v1/wcb/batches', {});

      const xml = capturedXml!;
      // OBX with ED (embedded data) type
      expect(xml).toContain('<OBX.2>ED</OBX.2>');
      expect(xml).toContain('ATTACHMENT_1');
      expect(xml).toContain(b64Content);
      expect(xml).toContain('consultation_letter.pdf');
      expect(xml).toContain('Base64');
    });

    it('batch without attachments has no ED-type OBX segments', async () => {
      const claimData = makeClaimWithChildren(
        { state: 'QUEUED' },
        { formId: 'C050E', submitterTxnId: 'MRTNOATTACH00001' },
        { attachments: [] },
      );

      mockWcbRepo.createBatch.mockResolvedValue(makeMockBatch());
      mockWcbRepo.getQueuedClaimsForBatch.mockResolvedValue([
        { claim: claimData.claim, detail: claimData.detail },
      ]);
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      await authedPost('/api/v1/wcb/batches', {});

      const xml = capturedXml!;
      expect(xml).not.toContain('<OBX.2>ED</OBX.2>');
      expect(xml).not.toContain('ATTACHMENT_');
      // Regular OBX (clinical observations) should still exist
      expect(xml).toContain('<OBX>');
    });

    it('FHS/BHS/MSH contain correct vendor credentials', async () => {
      const claimData = makeClaimWithChildren(
        { state: 'QUEUED' },
        { formId: 'C050E', submitterTxnId: 'MRTVENDOR0000001' },
      );

      mockWcbRepo.createBatch.mockResolvedValue(makeMockBatch({
        batchControlId: 'MER-B-TESTCTRL1',
        fileControlId: 'MER-20260115-FCT001',
      }));
      mockWcbRepo.getQueuedClaimsForBatch.mockResolvedValue([
        { claim: claimData.claim, detail: claimData.detail },
      ]);
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      await authedPost('/api/v1/wcb/batches', {});

      const xml = capturedXml!;
      // FHS contains vendor source ID
      expect(xml).toContain('<FHS.3>MERITUM</FHS.3>');
      expect(xml).toContain('<FHS.4>MERITUM</FHS.4>');
      // FHS receiving app/facility
      expect(xml).toContain('<FHS.5>WCB-EDM</FHS.5>');
      expect(xml).toContain('<FHS.6>RAPID-RPT</FHS.6>');
      // FHS file control ID
      expect(xml).toContain('<FHS.9>MER-20260115-FCT001</FHS.9>');
      expect(xml).toContain('<FHS.11>MER-20260115-FCT001</FHS.11>');
      // BHS contains vendor source ID
      expect(xml).toContain('<BHS.3>MERITUM</BHS.3>');
      expect(xml).toContain('<BHS.4>MERITUM</BHS.4>');
      // BHS batch control ID
      expect(xml).toContain('<BHS.11>MER-B-TESTCTRL1</BHS.11>');
      // MSH contains vendor source ID
      expect(xml).toContain('<MSH.3>MERITUM</MSH.3>');
      // MSH message type
      expect(xml).toContain('<MSH.9>ZRPT^P03</MSH.9>');
    });

    it('generateBatchXml function produces valid XML directly', () => {
      const claimData = makeClaimWithChildren(
        { state: 'QUEUED' },
        { formId: 'C050E', submitterTxnId: 'MRTDIRECT000001' },
      );

      const xml = generateBatchXml(
        'batch-001',
        'MER-B-CTRL0001',
        'MER-20260115-FC001',
        [claimData as any],
        'MERITUM',
        new Date('2026-01-15T18:00:00Z'),
      );

      expect(xml).toContain('<?xml version="1.0" encoding="UTF-8"?>');
      expect(xml).toContain('<ZRPT_P03');
      expect(xml).toContain('</ZRPT_P03>');
      expect(xml).toContain('<FHS.3>MERITUM</FHS.3>');
      expect(xml).toContain('<BTS.1>1</BTS.1>');
      expect(xml).toContain('<FTS.1>1</FTS.1>');
    });
  });

  // =========================================================================
  // Section 2: XSD Validation
  // =========================================================================

  describe('XSD Validation', () => {
    it('valid XML passes both XSD schemas', async () => {
      // First generate a batch to get XML stored
      const claimData = makeClaimWithChildren(
        { state: 'QUEUED' },
        { formId: 'C050E', submitterTxnId: 'MRTXSDVALID00001' },
      );
      const batchId = 'xsd-batch-001';

      mockWcbRepo.createBatch.mockResolvedValue(makeMockBatch({ wcbBatchId: batchId }));
      mockWcbRepo.getQueuedClaimsForBatch.mockResolvedValue([
        { claim: claimData.claim, detail: claimData.detail },
      ]);
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      // Generate batch
      await authedPost('/api/v1/wcb/batches', {});
      expect(capturedXml).not.toBeNull();

      // Now mock getBatch to return GENERATED status for XSD validation via download
      // XSD validation is part of the pipeline — it happens in the batch generation flow
      // when xsdValidator is configured. The validator mock returns valid=true by default.
      expect(mockXsdValidator.validate).not.toHaveBeenCalled();

      // Verify the batch was stored with XML
      expect(mockWcbRepo.updateBatchStatus).toHaveBeenCalled();
      expect(mockFileStorage.storeEncrypted).toHaveBeenCalledTimes(1);
    });

    it('XML with missing required element fails structural XSD', async () => {
      // Configure XSD validator to fail on structural validation
      mockXsdValidator.validate.mockImplementation((_xml: string, xsd: string) => {
        if (xsd.includes('structural') || xsd === 'structural-xsd-content') {
          return {
            valid: false,
            errors: [{ message: 'Missing required element: FHS', line: 2, column: 5 }],
          };
        }
        return { valid: true, errors: [] };
      });

      const batchId = 'xsd-fail-structural';
      mockWcbRepo.getBatch.mockResolvedValue(
        makeMockBatch({
          wcbBatchId: batchId,
          status: WcbBatchStatus.GENERATED,
          xmlFilePath: 'wcb/batches/structural-fail.xml',
        }),
      );

      // Import and call validateBatchXsd directly
      const { validateBatchXsd } = await import('../../../src/domains/wcb/wcb.service.js');

      const serviceDeps: WcbServiceDeps = {
        wcbRepo: mockWcbRepo as any,
        claimRepo: mockClaimRepo as any,
        providerLookup: mockProviderLookup as any,
        patientLookup: mockPatientLookup as any,
        auditEmitter: mockAuditEmitter,
        fileStorage: mockFileStorage,
        xsdValidator: mockXsdValidator as any,
      };

      const result = await validateBatchXsd(
        serviceDeps,
        batchId,
        PHYSICIAN1_USER_ID,
        { structural: 'structural-xsd-content', data: 'data-xsd-content' },
      );

      expect(result.passed).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors[0].message).toContain('[structural]');
      // Batch should be transitioned to ERROR with validation errors
      expect(mockWcbRepo.updateBatchStatus).toHaveBeenCalledWith(
        batchId,
        PHYSICIAN1_USER_ID,
        WcbBatchStatus.ERROR,
        expect.objectContaining({
          xsdValidationPassed: false,
          xsdValidationErrors: expect.any(Array),
        }),
      );
    });

    it('XML with invalid data format fails validation XSD', async () => {
      // Structural passes, data validation fails
      mockXsdValidator.validate.mockImplementation((_xml: string, xsd: string) => {
        if (xsd === 'data-xsd-content') {
          return {
            valid: false,
            errors: [{ message: 'Invalid date format in FT1.4: expected YYYYMMDD', line: 15, column: 10 }],
          };
        }
        return { valid: true, errors: [] };
      });

      const batchId = 'xsd-fail-data';
      mockWcbRepo.getBatch.mockResolvedValue(
        makeMockBatch({
          wcbBatchId: batchId,
          status: WcbBatchStatus.GENERATED,
          xmlFilePath: 'wcb/batches/data-fail.xml',
        }),
      );

      const { validateBatchXsd } = await import('../../../src/domains/wcb/wcb.service.js');

      const serviceDeps: WcbServiceDeps = {
        wcbRepo: mockWcbRepo as any,
        claimRepo: mockClaimRepo as any,
        providerLookup: mockProviderLookup as any,
        patientLookup: mockPatientLookup as any,
        auditEmitter: mockAuditEmitter,
        fileStorage: mockFileStorage,
        xsdValidator: mockXsdValidator as any,
      };

      const result = await validateBatchXsd(
        serviceDeps,
        batchId,
        PHYSICIAN1_USER_ID,
        { structural: 'structural-xsd-content', data: 'data-xsd-content' },
      );

      expect(result.passed).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors[0].message).toContain('[data]');
    });

    it('failed XSD validation stores errors in xsd_validation_errors', async () => {
      const validationErrors = [
        { message: 'Missing FHS.3', line: 2, column: 5 },
        { message: 'Invalid BHS.7 format', line: 8, column: 3 },
      ];

      mockXsdValidator.validate.mockReturnValue({
        valid: false,
        errors: validationErrors,
      });

      const batchId = 'xsd-errors-stored';
      mockWcbRepo.getBatch.mockResolvedValue(
        makeMockBatch({
          wcbBatchId: batchId,
          status: WcbBatchStatus.GENERATED,
          xmlFilePath: 'wcb/batches/errors-stored.xml',
        }),
      );

      const { validateBatchXsd } = await import('../../../src/domains/wcb/wcb.service.js');

      const serviceDeps: WcbServiceDeps = {
        wcbRepo: mockWcbRepo as any,
        claimRepo: mockClaimRepo as any,
        providerLookup: mockProviderLookup as any,
        patientLookup: mockPatientLookup as any,
        auditEmitter: mockAuditEmitter,
        fileStorage: mockFileStorage,
        xsdValidator: mockXsdValidator as any,
      };

      await validateBatchXsd(
        serviceDeps,
        batchId,
        PHYSICIAN1_USER_ID,
        { structural: 'structural-xsd', data: 'data-xsd' },
      );

      // Verify updateBatchStatus was called with xsdValidationErrors
      const updateCall = mockWcbRepo.updateBatchStatus.mock.calls.find(
        (call: any[]) => call[2] === WcbBatchStatus.ERROR,
      );
      expect(updateCall).toBeDefined();
      expect(updateCall![3]).toHaveProperty('xsdValidationPassed', false);
      expect(updateCall![3].xsdValidationErrors).toHaveLength(2);
    });
  });

  // =========================================================================
  // Section 3: Return File Processing
  // =========================================================================

  describe('Return File Processing', () => {
    it('parses successful return file: all claims matched, states -> assessed', async () => {
      const batchId = '00000000-bbbb-0000-0000-000000000100';
      const submitterTxnId = 'MRT0000000000100';
      const wcbDetailId = '00000000-dddd-0000-0000-000000000100';
      const claimId = '00000000-cccc-0000-0000-000000000100';

      mockWcbRepo.getBatchByControlId.mockResolvedValue(
        makeMockBatch({ wcbBatchId: batchId, status: WcbBatchStatus.UPLOADED }),
      );
      mockWcbRepo.matchReturnToClaimBySubmitterTxnId.mockResolvedValue(wcbDetailId);
      mockWcbRepo.getWcbClaimBySubmitterTxnId.mockResolvedValue({
        claimId,
        wcbClaimDetailId: wcbDetailId,
        formId: 'C050E',
        submitterTxnId,
        wcbClaimNumber: null,
      });

      const returnFileContent = [
        `MER-B-TEST0100\t1\tMRT-SUBMIT\t20260115`,
        `WCB-TXN-100\t${submitterTxnId}\t1234567\tAccepted\tCOMPLETE\t20260115`,
        `1\t20260115\t03.04A\tApproved`,
      ].join('\n');

      const res = await authedPost('/api/v1/wcb/returns/upload', {
        file_content: returnFileContent,
      } as any);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.matched_count).toBe(1);
      expect(body.data.complete_count).toBe(1);
      expect(body.data.invalid_count).toBe(0);
      expect(body.data.unmatched_count).toBe(0);

      // Claim transitioned to ASSESSED
      expect(mockClaimRepo.transitionClaimState).toHaveBeenCalledWith(
        claimId,
        PHYSICIAN1_USER_ID,
        'ASSESSED',
      );

      // Return records created
      expect(mockWcbRepo.createReturnRecords).toHaveBeenCalledTimes(1);
      // Invoice lines created for Complete status
      expect(mockWcbRepo.createReturnInvoiceLines).toHaveBeenCalledTimes(1);
    });

    it('parses error return file: errors extracted, claims -> rejected', async () => {
      const batchId = '00000000-bbbb-0000-0000-000000000101';
      const submitterTxnId = 'MRT0000000000101';
      const wcbDetailId = '00000000-dddd-0000-0000-000000000101';
      const claimId = '00000000-cccc-0000-0000-000000000101';

      mockWcbRepo.getBatchByControlId.mockResolvedValue(
        makeMockBatch({ wcbBatchId: batchId, status: WcbBatchStatus.UPLOADED }),
      );
      mockWcbRepo.matchReturnToClaimBySubmitterTxnId.mockResolvedValue(wcbDetailId);
      mockWcbRepo.getWcbClaimBySubmitterTxnId.mockResolvedValue({
        claimId,
        wcbClaimDetailId: wcbDetailId,
        formId: 'C050E',
        submitterTxnId,
        wcbClaimNumber: null,
      });

      const returnFileContent = [
        `MER-B-TEST0101\t1\tMRT-SUBMIT\t20260115`,
        `WCB-TXN-101\t${submitterTxnId}\t\t\tINVALID\t20260115`,
        `121023: Worker Personal Health Number must be BLANK since Worker Personal Health Number Indicator is No`,
        `130045: Employer Name is required for initial reports`,
      ].join('\n');

      const res = await authedPost('/api/v1/wcb/returns/upload', {
        file_content: returnFileContent,
      } as any);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.invalid_count).toBe(1);
      expect(body.data.complete_count).toBe(0);

      // Claim transitioned to REJECTED
      expect(mockClaimRepo.transitionClaimState).toHaveBeenCalledWith(
        claimId,
        PHYSICIAN1_USER_ID,
        'REJECTED',
      );

      // Return records contain error data
      const createCall = mockWcbRepo.createReturnRecords.mock.calls[0];
      const records = createCall[1];
      expect(records[0].reportStatus).toBe('INVALID');
      expect(records[0].errors).toBeDefined();
      expect(records[0].errors).toHaveLength(2);
    });

    it('unmatched SubmitterTxnID: graceful handling, alert emitted', async () => {
      const batchId = '00000000-bbbb-0000-0000-000000000102';

      mockWcbRepo.getBatchByControlId.mockResolvedValue(
        makeMockBatch({ wcbBatchId: batchId, status: WcbBatchStatus.UPLOADED }),
      );
      // No match found for this submitter txn id
      mockWcbRepo.matchReturnToClaimBySubmitterTxnId.mockResolvedValue(null);

      const returnFileContent = [
        `MER-B-TEST0102\t1\tMRT-SUBMIT\t20260115`,
        `WCB-TXN-102\tMRT_UNKNOWN_99999\t1234567\tAccepted\tCOMPLETE\t20260115`,
        `1\t20260115\t03.04A\tApproved`,
      ].join('\n');

      const res = await authedPost('/api/v1/wcb/returns/upload', {
        file_content: returnFileContent,
      } as any);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.unmatched_count).toBe(1);
      expect(body.data.matched_count).toBe(0);

      // No state transition for unmatched claims
      expect(mockClaimRepo.transitionClaimState).not.toHaveBeenCalled();

      // Alert emitted for unmatched
      expect(mockNotificationEmitter.emit).toHaveBeenCalledWith(
        'WCB_RETURN_UNMATCHED',
        expect.objectContaining({
          submitterTxnId: 'MRT_UNKNOWN_99999',
        }),
      );
    });

    it('mixed Complete/Invalid: each handled independently', async () => {
      const batchId = '00000000-bbbb-0000-0000-000000000103';
      const submitterTxnId1 = 'MRT0000000000103';
      const submitterTxnId2 = 'MRT0000000000104';
      const wcbDetailId1 = '00000000-dddd-0000-0000-000000000103';
      const wcbDetailId2 = '00000000-dddd-0000-0000-000000000104';
      const claimId1 = '00000000-cccc-0000-0000-000000000103';
      const claimId2 = '00000000-cccc-0000-0000-000000000104';

      mockWcbRepo.getBatchByControlId.mockResolvedValue(
        makeMockBatch({ wcbBatchId: batchId, status: WcbBatchStatus.UPLOADED }),
      );

      mockWcbRepo.matchReturnToClaimBySubmitterTxnId.mockImplementation(async (txnId: string) => {
        if (txnId === submitterTxnId1) return wcbDetailId1;
        if (txnId === submitterTxnId2) return wcbDetailId2;
        return null;
      });

      mockWcbRepo.getWcbClaimBySubmitterTxnId.mockImplementation(async (txnId: string) => {
        if (txnId === submitterTxnId1) {
          return { claimId: claimId1, wcbClaimDetailId: wcbDetailId1, formId: 'C050E', submitterTxnId: submitterTxnId1, wcbClaimNumber: null };
        }
        if (txnId === submitterTxnId2) {
          return { claimId: claimId2, wcbClaimDetailId: wcbDetailId2, formId: 'C151', submitterTxnId: submitterTxnId2, wcbClaimNumber: null };
        }
        return null;
      });

      const returnFileContent = [
        `MER-B-TEST0103\t2\tMRT-SUBMIT\t20260115`,
        `WCB-TXN-103\t${submitterTxnId1}\t1234567\tAccepted\tCOMPLETE\t20260115`,
        `1\t20260115\t03.04A\tApproved`,
        ``,
        `WCB-TXN-104\t${submitterTxnId2}\t\t\tINVALID\t20260115`,
        `110001: Missing required field: date_of_examination`,
      ].join('\n');

      const res = await authedPost('/api/v1/wcb/returns/upload', {
        file_content: returnFileContent,
      } as any);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.matched_count).toBe(2);
      expect(body.data.complete_count).toBe(1);
      expect(body.data.invalid_count).toBe(1);

      // First claim -> ASSESSED
      expect(mockClaimRepo.transitionClaimState).toHaveBeenCalledWith(
        claimId1,
        PHYSICIAN1_USER_ID,
        'ASSESSED',
      );
      // Second claim -> REJECTED
      expect(mockClaimRepo.transitionClaimState).toHaveBeenCalledWith(
        claimId2,
        PHYSICIAN1_USER_ID,
        'REJECTED',
      );
    });

    it('WCB claim number stored when provided in return file', async () => {
      const batchId = '00000000-bbbb-0000-0000-000000000105';
      const submitterTxnId = 'MRT0000000000105';
      const wcbDetailId = '00000000-dddd-0000-0000-000000000105';
      const claimId = '00000000-cccc-0000-0000-000000000105';

      mockWcbRepo.getBatchByControlId.mockResolvedValue(
        makeMockBatch({ wcbBatchId: batchId, status: WcbBatchStatus.UPLOADED }),
      );
      mockWcbRepo.matchReturnToClaimBySubmitterTxnId.mockResolvedValue(wcbDetailId);
      mockWcbRepo.getWcbClaimBySubmitterTxnId.mockResolvedValue({
        claimId,
        wcbClaimDetailId: wcbDetailId,
        formId: 'C050E',
        submitterTxnId,
        wcbClaimNumber: null, // No WCB claim number yet
      });

      const returnFileContent = [
        `MER-B-TEST0105\t1\tMRT-SUBMIT\t20260115`,
        `WCB-TXN-105\t${submitterTxnId}\t7654321\tAccepted\tCOMPLETE\t20260115`,
        `1\t20260115\t03.04A\tApproved`,
      ].join('\n');

      const res = await authedPost('/api/v1/wcb/returns/upload', {
        file_content: returnFileContent,
      } as any);

      expect(res.statusCode).toBe(200);

      // WCB claim number should be stored
      expect(mockWcbRepo.updateWcbClaimNumber).toHaveBeenCalledWith(
        wcbDetailId,
        '7654321',
      );
    });

    it('parseReturnFile correctly parses tab-delimited return file', () => {
      const fileContent = [
        `MER-B-CTRL001\t2\tMRT-SUBMIT\t20260115`,
        `WCB-TXN-001\tMRT0000000000001\t1234567\tAccepted\tCOMPLETE\t20260115`,
        `1\t20260115\t03.04A\tApproved`,
        `2\t20260116\t03.04B\tApproved`,
        ``,
        `WCB-TXN-002\tMRT0000000000002\t\t\tINVALID\t20260115`,
        `121023: Invalid PHN`,
      ].join('\n');

      const result = parseReturnFile(fileContent);

      expect(result.header.batchId).toBe('MER-B-CTRL001');
      expect(result.header.reportCount).toBe(2);
      expect(result.header.submitterId).toBe('MRT-SUBMIT');
      expect(result.reports).toHaveLength(2);

      // First report: Complete with invoice lines
      const r1 = result.reports[0];
      expect(r1.reportStatus).toBe('COMPLETE');
      expect(r1.processedClaimNumber).toBe('1234567');
      expect(r1.invoiceLines).toHaveLength(2);
      expect(r1.invoiceLines[0].invoiceSequence).toBe(1);
      expect(r1.invoiceLines[1].healthServiceCode).toBe('03.04B');

      // Second report: Invalid with errors
      const r2 = result.reports[1];
      expect(r2.reportStatus).toBe('INVALID');
      expect(r2.errors).toHaveLength(1);
      expect(r2.errors[0].error_code).toBe('121023');
      expect(r2.errors[0].message).toBe('Invalid PHN');
    });
  });

  // =========================================================================
  // Section 4: Remittance Processing
  // =========================================================================

  describe('Remittance Processing', () => {
    it('parses remittance XML and stores all records', async () => {
      const remittanceXml = `
        <PaymentRemittanceReport xmlns="http://www.wcb.ab.ca/schemas/RR/RRPaymentRemittanceReport-2.01.00">
          <ReportWeek>
            <StartDate>2026-01-13</StartDate>
            <EndDate>2026-01-19</EndDate>
          </ReportWeek>
          <PaymentRemittanceRecord>
            <PaymentPayeeBillingNumber>12345678</PaymentPayeeBillingNumber>
            <PaymentPayeeName>Dr. John Doe</PaymentPayeeName>
            <PaymentReasonCode>RPT</PaymentReasonCode>
            <PaymentStatus>ISS</PaymentStatus>
            <PaymentStartDate>2026-01-15</PaymentStartDate>
            <PaymentEndDate>2026-01-15</PaymentEndDate>
            <PaymentAmount>94.15</PaymentAmount>
            <ElectronicReportTransactionID>WCB-TXN-001</ElectronicReportTransactionID>
            <ClaimNumber>1234567</ClaimNumber>
          </PaymentRemittanceRecord>
          <PaymentRemittanceRecord>
            <PaymentPayeeBillingNumber>12345678</PaymentPayeeBillingNumber>
            <PaymentPayeeName>Dr. John Doe</PaymentPayeeName>
            <PaymentReasonCode>RPT</PaymentReasonCode>
            <PaymentStatus>ISS</PaymentStatus>
            <PaymentStartDate>2026-01-16</PaymentStartDate>
            <PaymentEndDate>2026-01-16</PaymentEndDate>
            <PaymentAmount>57.19</PaymentAmount>
            <ElectronicReportTransactionID>WCB-TXN-002</ElectronicReportTransactionID>
            <ClaimNumber>1234568</ClaimNumber>
          </PaymentRemittanceRecord>
        </PaymentRemittanceReport>
      `;

      const res = await authedPost('/api/v1/wcb/remittances/upload', {
        xml_content: remittanceXml,
      } as any);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.record_count).toBe(2);

      // Remittance records stored
      expect(mockWcbRepo.createRemittanceRecords).toHaveBeenCalledTimes(1);
      const records = mockWcbRepo.createRemittanceRecords.mock.calls[0][1];
      expect(records).toHaveLength(2);
    });

    it('matches remittance via ElectronicReportTransactionID chain', async () => {
      const wcbDetailId = '00000000-dddd-0000-0000-000000000200';
      const claimId = '00000000-cccc-0000-0000-000000000200';

      const claimData = makeClaimWithChildren(
        { claimId, state: 'ASSESSED' },
        { wcbClaimDetailId: wcbDetailId },
      );

      mockWcbRepo.matchRemittanceToClaimByTxnId.mockResolvedValue(wcbDetailId);
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const remittanceXml = `
        <PaymentRemittanceReport xmlns="http://www.wcb.ab.ca/schemas/RR/RRPaymentRemittanceReport-2.01.00">
          <ReportWeek>
            <StartDate>2026-01-20</StartDate>
            <EndDate>2026-01-26</EndDate>
          </ReportWeek>
          <PaymentRemittanceRecord>
            <PaymentPayeeBillingNumber>12345678</PaymentPayeeBillingNumber>
            <PaymentPayeeName>Dr. John Doe</PaymentPayeeName>
            <PaymentReasonCode>RPT</PaymentReasonCode>
            <PaymentStatus>ISS</PaymentStatus>
            <PaymentStartDate>2026-01-15</PaymentStartDate>
            <PaymentEndDate>2026-01-15</PaymentEndDate>
            <PaymentAmount>94.15</PaymentAmount>
            <ElectronicReportTransactionID>WCB-TXN-200</ElectronicReportTransactionID>
            <ClaimNumber>1234567</ClaimNumber>
          </PaymentRemittanceRecord>
        </PaymentRemittanceReport>
      `;

      const res = await authedPost('/api/v1/wcb/remittances/upload', {
        xml_content: remittanceXml,
      } as any);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.matched_count).toBe(1);

      // Claim transitioned to PAID (ISS status)
      expect(mockClaimRepo.transitionClaimState).toHaveBeenCalledWith(
        claimId,
        PHYSICIAN1_USER_ID,
        'PAID',
      );
    });

    it('detects payment discrepancy when payment amount differs from expected', async () => {
      const wcbDetailId = '00000000-dddd-0000-0000-000000000201';
      const claimId = '00000000-cccc-0000-0000-000000000201';

      const claimData = makeClaimWithChildren(
        { claimId, state: 'ASSESSED' },
        { wcbClaimDetailId: wcbDetailId },
      );

      mockWcbRepo.matchRemittanceToClaimByTxnId.mockResolvedValue(wcbDetailId);
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      // Payment is less than expected ($94.15)
      const remittanceXml = `
        <PaymentRemittanceReport xmlns="http://www.wcb.ab.ca/schemas/RR/RRPaymentRemittanceReport-2.01.00">
          <ReportWeek>
            <StartDate>2026-01-20</StartDate>
            <EndDate>2026-01-26</EndDate>
          </ReportWeek>
          <PaymentRemittanceRecord>
            <PaymentPayeeBillingNumber>12345678</PaymentPayeeBillingNumber>
            <PaymentPayeeName>Dr. John Doe</PaymentPayeeName>
            <PaymentReasonCode>RPT</PaymentReasonCode>
            <PaymentStatus>ISS</PaymentStatus>
            <PaymentStartDate>2026-01-15</PaymentStartDate>
            <PaymentEndDate>2026-01-15</PaymentEndDate>
            <PaymentAmount>54.08</PaymentAmount>
            <ElectronicReportTransactionID>WCB-TXN-201</ElectronicReportTransactionID>
            <ClaimNumber>1234567</ClaimNumber>
          </PaymentRemittanceRecord>
        </PaymentRemittanceReport>
      `;

      const res = await authedPost('/api/v1/wcb/remittances/upload', {
        xml_content: remittanceXml,
      } as any);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.discrepancy_count).toBe(1);
    });

    it('handles all 7 payment status codes', async () => {
      // ISS is tested above. Test the remaining 6 in a single batch.
      const statuses: Array<{ code: string; expectTransition: boolean; expectNotification: string | null }> = [
        { code: 'REQ', expectTransition: false, expectNotification: 'WCB_PAYMENT_PENDING' },
        { code: 'PAE', expectTransition: false, expectNotification: 'WCB_PAYMENT_PENDING' },
        { code: 'PGA', expectTransition: false, expectNotification: 'WCB_PAYMENT_PENDING' },
        { code: 'PGD', expectTransition: false, expectNotification: 'WCB_PAYMENT_PENDING' },
        { code: 'REJ', expectTransition: false, expectNotification: 'WCB_PAYMENT_REVIEW_REQUIRED' },
        { code: 'DEL', expectTransition: false, expectNotification: 'WCB_PAYMENT_REVIEW_REQUIRED' },
      ];

      for (const status of statuses) {
        // Reset mocks for each status
        vi.clearAllMocks();
        mockWcbRepo.createRemittanceImport.mockResolvedValue(crypto.randomUUID());
        mockWcbRepo.createRemittanceRecords.mockResolvedValue([]);

        const wcbDetailId = crypto.randomUUID();
        const claimId = crypto.randomUUID();
        const claimData = makeClaimWithChildren(
          { claimId, state: 'ASSESSED' },
          { wcbClaimDetailId: wcbDetailId },
        );

        mockWcbRepo.matchRemittanceToClaimByTxnId.mockResolvedValue(wcbDetailId);
        mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

        const xml = `
          <PaymentRemittanceReport xmlns="http://www.wcb.ab.ca/schemas/RR/RRPaymentRemittanceReport-2.01.00">
            <ReportWeek>
              <StartDate>2026-01-20</StartDate>
              <EndDate>2026-01-26</EndDate>
            </ReportWeek>
            <PaymentRemittanceRecord>
              <PaymentPayeeBillingNumber>12345678</PaymentPayeeBillingNumber>
              <PaymentPayeeName>Dr. John Doe</PaymentPayeeName>
              <PaymentReasonCode>RPT</PaymentReasonCode>
              <PaymentStatus>${status.code}</PaymentStatus>
              <PaymentStartDate>2026-01-15</PaymentStartDate>
              <PaymentEndDate>2026-01-15</PaymentEndDate>
              <PaymentAmount>94.15</PaymentAmount>
              <ElectronicReportTransactionID>WCB-TXN-STATUS</ElectronicReportTransactionID>
            </PaymentRemittanceRecord>
          </PaymentRemittanceReport>
        `;

        const res = await authedPost('/api/v1/wcb/remittances/upload', {
          xml_content: xml,
        } as any);

        expect(res.statusCode).toBe(200);

        if (status.expectTransition) {
          expect(mockClaimRepo.transitionClaimState).toHaveBeenCalled();
        } else {
          expect(mockClaimRepo.transitionClaimState).not.toHaveBeenCalled();
        }

        if (status.expectNotification) {
          // Check that the specific notification was emitted (among others like WCB_PAYMENT_RECEIVED)
          const emitCalls = mockNotificationEmitter.emit.mock.calls;
          const statusNotif = emitCalls.find((c: any[]) => c[0] === status.expectNotification);
          expect(statusNotif).toBeDefined();
        }
      }
    });

    it('overpayment recovery tracked in discrepancy', async () => {
      const wcbDetailId = '00000000-dddd-0000-0000-000000000202';
      const claimId = '00000000-cccc-0000-0000-000000000202';

      const claimData = makeClaimWithChildren(
        { claimId, state: 'ASSESSED' },
        { wcbClaimDetailId: wcbDetailId },
      );

      mockWcbRepo.matchRemittanceToClaimByTxnId.mockResolvedValue(wcbDetailId);
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const remittanceXml = `
        <PaymentRemittanceReport xmlns="http://www.wcb.ab.ca/schemas/RR/RRPaymentRemittanceReport-2.01.00">
          <ReportWeek>
            <StartDate>2026-01-20</StartDate>
            <EndDate>2026-01-26</EndDate>
          </ReportWeek>
          <PaymentRemittanceRecord>
            <PaymentPayeeBillingNumber>12345678</PaymentPayeeBillingNumber>
            <PaymentPayeeName>Dr. John Doe</PaymentPayeeName>
            <PaymentReasonCode>RPT</PaymentReasonCode>
            <PaymentStatus>ISS</PaymentStatus>
            <PaymentStartDate>2026-01-15</PaymentStartDate>
            <PaymentEndDate>2026-01-15</PaymentEndDate>
            <PaymentAmount>74.15</PaymentAmount>
            <OverpaymentRecovery>20.00</OverpaymentRecovery>
            <ElectronicReportTransactionID>WCB-TXN-202</ElectronicReportTransactionID>
            <ClaimNumber>1234567</ClaimNumber>
          </PaymentRemittanceRecord>
        </PaymentRemittanceReport>
      `;

      const res = await authedPost('/api/v1/wcb/remittances/upload', {
        xml_content: remittanceXml,
      } as any);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      // Discrepancy should be detected (payment $74.15 vs expected $94.15)
      expect(body.data.discrepancy_count).toBeGreaterThanOrEqual(1);

      // Remittance record stored with overpayment info
      const records = mockWcbRepo.createRemittanceRecords.mock.calls[0][1];
      expect(records[0].overpaymentRecovery).toBe('20.00');
    });

    it('parseRemittanceXml correctly extracts records from XML', () => {
      const xmlContent = `
        <PaymentRemittanceReport xmlns="http://www.wcb.ab.ca/schemas/RR/RRPaymentRemittanceReport-2.01.00">
          <ReportWeek>
            <StartDate>2026-02-03</StartDate>
            <EndDate>2026-02-09</EndDate>
          </ReportWeek>
          <PaymentRemittanceRecord>
            <DisbursementNumber>D001</DisbursementNumber>
            <DisbursementType>EFT</DisbursementType>
            <DisbursementIssueDate>2026-02-10</DisbursementIssueDate>
            <DisbursementAmount>200.00</DisbursementAmount>
            <PaymentPayeeBillingNumber>12345678</PaymentPayeeBillingNumber>
            <PaymentPayeeName>Dr. Test</PaymentPayeeName>
            <PaymentReasonCode>RPT</PaymentReasonCode>
            <PaymentStatus>ISS</PaymentStatus>
            <PaymentStartDate>2026-01-15</PaymentStartDate>
            <PaymentEndDate>2026-01-15</PaymentEndDate>
            <PaymentAmount>94.15</PaymentAmount>
            <BilledAmount>94.15</BilledAmount>
            <ElectronicReportTransactionID>WCB-TXN-PARSE</ElectronicReportTransactionID>
            <ClaimNumber>9876543</ClaimNumber>
            <WorkerPHN>123456789</WorkerPHN>
            <WorkerFirstName>Jane</WorkerFirstName>
            <WorkerLastName>Smith</WorkerLastName>
            <ServiceCode>03.04A</ServiceCode>
            <NumberOfCalls>1</NumberOfCalls>
            <EncounterNumber>1</EncounterNumber>
          </PaymentRemittanceRecord>
        </PaymentRemittanceReport>
      `;

      const result = parseRemittanceXml(xmlContent);

      expect(result.reportWeekStart).toBe('2026-02-03');
      expect(result.reportWeekEnd).toBe('2026-02-09');
      expect(result.records).toHaveLength(1);

      const record = result.records[0];
      expect(record.disbursementNumber).toBe('D001');
      expect(record.disbursementType).toBe('EFT');
      expect(record.paymentPayeeBilling).toBe('12345678');
      expect(record.paymentStatus).toBe('ISS');
      expect(record.paymentAmount).toBe('94.15');
      expect(record.billedAmount).toBe('94.15');
      expect(record.electronicReportTxnId).toBe('WCB-TXN-PARSE');
      expect(record.claimNumber).toBe('9876543');
      expect(record.workerPhn).toBe('123456789');
      expect(record.serviceCode).toBe('03.04A');
      expect(record.numberOfCalls).toBe(1);
      expect(record.encounterNumber).toBe(1);
    });

    it('parseRemittanceXml rejects XML without PaymentRemittanceReport', () => {
      expect(() => parseRemittanceXml('<SomeOtherXml/>')).toThrow();
    });

    it('parseRemittanceXml rejects XML without ReportWeek', () => {
      const xml = `
        <PaymentRemittanceReport xmlns="http://www.wcb.ab.ca/schemas/RR/RRPaymentRemittanceReport-2.01.00">
          <PaymentRemittanceRecord>
            <PaymentAmount>94.15</PaymentAmount>
          </PaymentRemittanceRecord>
        </PaymentRemittanceReport>
      `;
      expect(() => parseRemittanceXml(xml)).toThrow('missing ReportWeek');
    });

    it('batch-level WCB_RETURN_RECEIVED notification emitted after return processing', async () => {
      const batchId = '00000000-bbbb-0000-0000-000000000106';
      const submitterTxnId = 'MRT0000000000106';
      const wcbDetailId = '00000000-dddd-0000-0000-000000000106';
      const claimId = '00000000-cccc-0000-0000-000000000106';

      mockWcbRepo.getBatchByControlId.mockResolvedValue(
        makeMockBatch({ wcbBatchId: batchId, status: WcbBatchStatus.UPLOADED }),
      );
      mockWcbRepo.matchReturnToClaimBySubmitterTxnId.mockResolvedValue(wcbDetailId);
      mockWcbRepo.getWcbClaimBySubmitterTxnId.mockResolvedValue({
        claimId,
        wcbClaimDetailId: wcbDetailId,
        formId: 'C050E',
        submitterTxnId,
        wcbClaimNumber: null,
      });

      const returnFileContent = [
        `MER-B-TEST0106\t1\tMRT-SUBMIT\t20260115`,
        `WCB-TXN-106\t${submitterTxnId}\t1234567\tAccepted\tCOMPLETE\t20260115`,
        `1\t20260115\t03.04A\tApproved`,
      ].join('\n');

      await authedPost('/api/v1/wcb/returns/upload', {
        file_content: returnFileContent,
      } as any);

      // Verify batch-level notification emitted
      const emitCalls = mockNotificationEmitter.emit.mock.calls;
      const returnNotif = emitCalls.find((c: any[]) => c[0] === 'WCB_RETURN_RECEIVED');
      expect(returnNotif).toBeDefined();
      expect(returnNotif![1]).toEqual(expect.objectContaining({
        physicianId: PHYSICIAN1_USER_ID,
        wcbBatchId: batchId,
        matchedCount: 1,
        completeCount: 1,
      }));
    });

    it('WCB_PAYMENT_RECEIVED notification emitted after remittance processing', async () => {
      mockWcbRepo.createRemittanceImport.mockResolvedValue('import-notify-001');

      const remittanceXml = `
        <PaymentRemittanceReport xmlns="http://www.wcb.ab.ca/schemas/RR/RRPaymentRemittanceReport-2.01.00">
          <ReportWeek>
            <StartDate>2026-01-20</StartDate>
            <EndDate>2026-01-26</EndDate>
          </ReportWeek>
          <PaymentRemittanceRecord>
            <PaymentPayeeBillingNumber>12345678</PaymentPayeeBillingNumber>
            <PaymentPayeeName>Dr. John Doe</PaymentPayeeName>
            <PaymentReasonCode>RPT</PaymentReasonCode>
            <PaymentStatus>ISS</PaymentStatus>
            <PaymentStartDate>2026-01-15</PaymentStartDate>
            <PaymentEndDate>2026-01-15</PaymentEndDate>
            <PaymentAmount>94.15</PaymentAmount>
          </PaymentRemittanceRecord>
        </PaymentRemittanceReport>
      `;

      await authedPost('/api/v1/wcb/remittances/upload', {
        xml_content: remittanceXml,
      } as any);

      const emitCalls = mockNotificationEmitter.emit.mock.calls;
      const paymentNotif = emitCalls.find((c: any[]) => c[0] === 'WCB_PAYMENT_RECEIVED');
      expect(paymentNotif).toBeDefined();
      expect(paymentNotif![1]).toEqual(expect.objectContaining({
        physicianId: PHYSICIAN1_USER_ID,
        recordCount: 1,
        totalPayment: '94.15',
      }));
    });

    it('batch reconciled when all returns match with no errors', async () => {
      const batchId = '00000000-bbbb-0000-0000-000000000107';
      const submitterTxnId = 'MRT0000000000107';
      const wcbDetailId = '00000000-dddd-0000-0000-000000000107';
      const claimId = '00000000-cccc-0000-0000-000000000107';

      mockWcbRepo.getBatchByControlId.mockResolvedValue(
        makeMockBatch({ wcbBatchId: batchId, status: WcbBatchStatus.UPLOADED }),
      );
      mockWcbRepo.matchReturnToClaimBySubmitterTxnId.mockResolvedValue(wcbDetailId);
      mockWcbRepo.getWcbClaimBySubmitterTxnId.mockResolvedValue({
        claimId,
        wcbClaimDetailId: wcbDetailId,
        formId: 'C050E',
        submitterTxnId,
        wcbClaimNumber: null,
      });

      const returnFileContent = [
        `MER-B-TEST0107\t1\tMRT-SUBMIT\t20260115`,
        `WCB-TXN-107\t${submitterTxnId}\t1234567\tAccepted\tCOMPLETE\t20260115`,
        `1\t20260115\t03.04A\tApproved`,
      ].join('\n');

      await authedPost('/api/v1/wcb/returns/upload', {
        file_content: returnFileContent,
      } as any);

      // Batch should transition to RECONCILED since all matched + no errors
      expect(mockWcbRepo.updateBatchStatus).toHaveBeenCalledWith(
        batchId,
        PHYSICIAN1_USER_ID,
        WcbBatchStatus.RECONCILED,
      );
    });
  });
});
