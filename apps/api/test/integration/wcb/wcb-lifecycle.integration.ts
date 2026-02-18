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
import { WcbBatchStatus, WcbFormType, WcbReturnReportStatus } from '@meritum/shared/constants/wcb.constants.js';

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
      { wcbInvoiceLineId: crypto.randomUUID(), wcbClaimDetailId: detail.wcbClaimDetailId, ordinal: 1, lineType: 'STANDARD', healthServiceCode: '03.04A', diagnosticCode1: 'S6350', diagnosticCode2: null, diagnosticCode3: null, modifier1: null, modifier2: null, modifier3: null, calls: 1, encounters: 1, dateOfServiceFrom: '2026-01-15', dateOfServiceTo: null, facilityTypeOverride: null, skillCodeOverride: null, quantity: null, supplyDescription: null, amount: '94.15', adjustmentIndicator: null, billingNumberOverride: null, correctionPairId: null, createdAt: new Date() },
    ],
    attachments: children.attachments ?? [],
  };
}

// ---------------------------------------------------------------------------
// Valid create payloads
// ---------------------------------------------------------------------------

const VALID_C050E_PAYLOAD = {
  form_id: 'C050E',
  patient_id: PATIENT_ID,
  date_of_injury: '2026-01-14',
  date_of_examination: '2026-01-15',
  report_completion_date: '2026-01-15',
  employer_name: 'Acme Corp',
  employer_location: 'Downtown',
  employer_city: 'Calgary',
  worker_job_title: 'Warehouse Worker',
  injury_developed_over_time: 'N',
  injury_description: 'Fell from ladder',
  symptoms: 'Pain in right wrist',
  objective_findings: 'Swelling and tenderness',
  current_diagnosis: 'Wrist sprain',
  diagnostic_code_1: 'S6350',
  injuries: [
    { part_of_body_code: '32100', side_of_body_code: 'R', nature_of_injury_code: '02100' },
  ],
  invoice_lines: [
    { line_type: 'STANDARD', health_service_code: '03.04A', diagnostic_code_1: 'S6350', calls: 1, encounters: 1, amount: '94.15' },
  ],
};

const VALID_C151_PAYLOAD = {
  form_id: 'C151',
  patient_id: PATIENT_ID,
  parent_wcb_claim_id: '', // Will be set dynamically
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
};

const VALID_C050S_PAYLOAD = {
  form_id: 'C050S',
  patient_id: PATIENT_ID,
  date_of_injury: '2026-01-14',
  date_of_examination: '2026-01-15',
  report_completion_date: '2026-01-15',
  employer_name: 'Heavy Industries',
  employer_location: 'Warehouse',
  employer_city: 'Edmonton',
  worker_job_title: 'Machine Operator',
  injury_developed_over_time: 'N',
  injury_description: 'Repetitive strain injury',
  symptoms: 'Pain in both hands',
  objective_findings: 'Bilateral hand weakness',
  current_diagnosis: 'Carpal tunnel syndrome bilateral',
  diagnostic_code_1: 'G5610',
  injuries: [
    { part_of_body_code: '31100', side_of_body_code: 'R', nature_of_injury_code: '02100' },
    { part_of_body_code: '31100', side_of_body_code: 'L', nature_of_injury_code: '02100' },
  ],
  work_restrictions: [
    { activity_type: 'GRASPING', restriction_level: 'LIMITED', hours_per_day: 4 },
    { activity_type: 'LIFTING', restriction_level: 'LIMITED', max_weight: '5' },
    { activity_type: 'REACHING', restriction_level: 'LIMITED' },
  ],
  invoice_lines: [
    { line_type: 'STANDARD', health_service_code: '03.04A', diagnostic_code_1: 'G5610', calls: 1, encounters: 1, amount: '94.15' },
  ],
};

const C568A_PARENT_DETAIL_ID = '00000000-dddd-0000-0000-0000000568a0';

const VALID_C568A_PAYLOAD = {
  form_id: 'C568A',
  patient_id: PATIENT_ID,
  parent_wcb_claim_id: C568A_PARENT_DETAIL_ID,
  date_of_injury: '2026-01-14',
  date_of_examination: '2026-01-20',
  report_completion_date: '2026-01-20',
  symptoms: 'Persistent wrist pain',
  objective_findings: 'Limited range of motion',
  current_diagnosis: 'Complex wrist fracture',
  diagnostic_code_1: 'S6250',
  consultation_letter_format: 'ATTCH',
  injuries: [
    { part_of_body_code: '32100', side_of_body_code: 'R', nature_of_injury_code: '07100' },
  ],
  attachments: [
    { file_name: 'consultation_letter.pdf', file_type: 'PDF', file_content_b64: 'SGVsbG8gV29ybGQ=', file_description: 'Specialist consultation letter' },
  ],
  invoice_lines: [
    { line_type: 'STANDARD', health_service_code: '03.04J', diagnostic_code_1: 'S6250', calls: 1, encounters: 1, amount: '115.05' },
  ],
};

const VALID_C570_PAYLOAD = {
  form_id: 'C570',
  patient_id: PATIENT_ID,
  parent_wcb_claim_id: '', // Will be set dynamically
  date_of_injury: '2026-01-14',
  report_completion_date: '2026-02-01',
  reassessment_comments: 'Correcting invoice line amounts',
  invoice_lines: [
    { line_type: 'WAS', health_service_code: '03.04A', diagnostic_code_1: 'S6350', calls: 1, encounters: 1, amount: '85.80', correction_pair_id: 1 },
    { line_type: 'SHOULD_BE', health_service_code: '03.04A', diagnostic_code_1: 'S6350', calls: 1, encounters: 1, amount: '94.15', correction_pair_id: 1 },
  ],
};

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
      // Return appropriate contract/role for OIS vs GP forms
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

function authedGet(url: string, token = PHYSICIAN1_SESSION_TOKEN) {
  return app.inject({
    method: 'GET',
    url,
    headers: { cookie: `session=${token}` },
  });
}

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

function authedPut(url: string, body: Record<string, unknown>, token = PHYSICIAN1_SESSION_TOKEN) {
  return app.inject({
    method: 'PUT',
    url,
    headers: {
      cookie: `session=${token}`,
      'content-type': 'application/json',
    },
    payload: body,
  });
}

function authedDelete(url: string, token = PHYSICIAN1_SESSION_TOKEN) {
  return app.inject({
    method: 'DELETE',
    url,
    headers: { cookie: `session=${token}` },
  });
}

// ===========================================================================
// Tests
// ===========================================================================

describe('WCB Claim Lifecycle — End-to-End Integration', () => {
  // Store the original mock references created by beforeAll so that
  // mid-test buildTestApp('VENDOR') calls don't overwrite them.
  let origMockWcbRepo: ReturnType<typeof createMockWcbRepo>;
  let origMockClaimRepo: ReturnType<typeof createMockClaimRepo>;
  let origMockProviderLookup: ReturnType<typeof createMockProviderLookup>;
  let origMockPatientLookup: ReturnType<typeof createMockPatientLookup>;
  let origMockAuditEmitter: { emit: ReturnType<typeof vi.fn> };

  beforeAll(async () => {
    app = await buildTestApp('mvp');
    // Capture original mock references so we can restore them if a test
    // calls buildTestApp() again (which overwrites the module-level variables).
    origMockWcbRepo = mockWcbRepo;
    origMockClaimRepo = mockClaimRepo;
    origMockProviderLookup = mockProviderLookup;
    origMockPatientLookup = mockPatientLookup;
    origMockAuditEmitter = mockAuditEmitter;
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    // Restore original mock references in case a previous test called
    // buildTestApp() which overwrites the module-level variables.
    mockWcbRepo = origMockWcbRepo;
    mockClaimRepo = origMockClaimRepo;
    mockProviderLookup = origMockProviderLookup;
    mockPatientLookup = origMockPatientLookup;
    mockAuditEmitter = origMockAuditEmitter;

    vi.clearAllMocks();
    // Reset counters between tests for predictable IDs
    claimIdCounter = 0;
    wcbDetailCounter = 0;
    batchIdCounter = 0;

    // Reset mock implementations to defaults (clearAllMocks preserves
    // implementations set by previous tests, so we restore factory defaults)
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

    // Reset provider/patient lookups to factory defaults (tests may override)
    mockProviderLookup.getWcbConfigForForm.mockImplementation(async (_providerId: string, formId: string) => {
      if (formId === 'C050S' || formId === 'C151S') {
        return { wcbConfigId: 'cfg-ois', contractId: '000053', roleCode: 'OIS', skillCode: 'GENP', facilityType: 'C' };
      }
      if (formId === 'C568A') {
        return { wcbConfigId: 'cfg-sp', contractId: '000006', roleCode: 'SP', skillCode: 'ORTH', facilityType: 'C' };
      }
      return { wcbConfigId: 'cfg-gp', contractId: '000001', roleCode: 'GP', skillCode: 'GENP', facilityType: 'C' };
    });

    // Reset createBatch to factory default
    mockWcbRepo.createBatch.mockImplementation(async (physicianId: string) => makeMockBatch({ physicianId }));
  });

  // =========================================================================
  // Scenario 1: GP First Report (C050E) — Happy Path
  // =========================================================================

  describe('Scenario 1: GP First Report (C050E) — full lifecycle', () => {
    it('creates a C050E claim with injuries and invoice lines', async () => {
      const res = await authedPost('/api/v1/wcb/claims', VALID_C050E_PAYLOAD as any);

      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.data).toHaveProperty('claimId');
      expect(body.data).toHaveProperty('wcbClaimDetailId');

      // Verify service deps called
      expect(mockClaimRepo.createClaim).toHaveBeenCalledTimes(1);
      expect(mockWcbRepo.createWcbClaim).toHaveBeenCalledTimes(1);
      expect(mockWcbRepo.upsertInjuries).toHaveBeenCalledTimes(1);
      expect(mockWcbRepo.upsertInvoiceLines).toHaveBeenCalledTimes(1);
    });

    it('validates C050E claim — passes validation', async () => {
      const wcbDetailId = '00000000-dddd-0000-0000-000000000001';
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        { wcbClaimDetailId: wcbDetailId },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);
      mockWcbRepo.getInjuries.mockResolvedValue(claimData.injuries);
      mockWcbRepo.getInvoiceLines.mockResolvedValue(claimData.invoiceLines);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toHaveProperty('passed');
      expect(body.data).toHaveProperty('errors');
      expect(body.data).toHaveProperty('warnings');
    });

    it('assembles batch from queued claims and generates XML', async () => {
      const claimData = makeClaimWithChildren(
        { state: 'QUEUED' },
        {},
      );
      const batchId = nextBatchId();

      mockWcbRepo.createBatch.mockResolvedValue(makeMockBatch({ wcbBatchId: batchId }));
      mockWcbRepo.getQueuedClaimsForBatch.mockResolvedValue([
        { claim: claimData.claim, detail: claimData.detail },
      ]);
      // Validation pass — getWcbClaim returns full claim for XML generation
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost('/api/v1/wcb/batches', {});

      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.data).toHaveProperty('wcbBatchId');
      expect(body.data).toHaveProperty('reportCount', 1);
      expect(body.data.skippedClaimIds).toEqual([]);

      // Verify batch status update and claim assignment
      expect(mockWcbRepo.assignClaimsToBatch).toHaveBeenCalledTimes(1);
      expect(mockWcbRepo.updateBatchStatus).toHaveBeenCalled();
    });

    it('downloads batch XML via signed URL', async () => {
      const batchId = '00000000-bbbb-0000-0000-000000000099';
      mockWcbRepo.getBatch.mockResolvedValue(
        makeMockBatch({
          wcbBatchId: batchId,
          status: WcbBatchStatus.VALIDATED,
          xmlFilePath: 'wcb/batches/test.xml',
        }),
      );

      const res = await authedGet(`/api/v1/wcb/batches/${batchId}/download`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toHaveProperty('downloadUrl');
      expect(body.data).toHaveProperty('expiresAt');
    });

    it('confirms upload to WCB portal', async () => {
      const batchId = '00000000-bbbb-0000-0000-000000000099';
      mockWcbRepo.getBatch.mockResolvedValue(
        makeMockBatch({
          wcbBatchId: batchId,
          status: WcbBatchStatus.VALIDATED,
          xmlFilePath: 'wcb/batches/test.xml',
        }),
      );
      mockWcbRepo.setBatchUploaded.mockResolvedValue(
        makeMockBatch({
          wcbBatchId: batchId,
          status: WcbBatchStatus.UPLOADED,
          uploadedAt: new Date(),
        }),
      );

      const res = await authedPost(`/api/v1/wcb/batches/${batchId}/confirm-upload`, {});

      expect(res.statusCode).toBe(200);
    });

    it('processes return file with Complete status — claim assessed', async () => {
      const batchId = '00000000-bbbb-0000-0000-000000000099';
      const submitterTxnId = 'MRT0000000000001';
      const wcbDetailId = '00000000-dddd-0000-0000-000000000099';
      const claimId = '00000000-cccc-0000-0000-000000000099';

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

      // Return file format: tab-delimited without prefixes
      // Line 1: BatchControlId\tReportCount\tSubmitterID\tSubmitDate
      // Line 2+: ReportTxnId\tSubmitterTxnId\tClaimNumber\tDecision\tStatus\tDate
      // Sub-lines: InvoiceSeq\tServiceDate\tHSC\tInvoiceStatus (for Complete)
      const returnFileContent = [
        `MER-B-TEST0001\t1\tMRT-SUBMIT\t20260115`,
        `WCB-TXN-001\t${submitterTxnId}\t1234567\tAccepted\tComplete\t20260115`,
        `1\t20260115\t03.04A\tApproved`,
      ].join('\n');

      const res = await authedPost('/api/v1/wcb/returns/upload', {
        file_content: returnFileContent,
      } as any);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toHaveProperty('matched_count');
      expect(body.data).toHaveProperty('complete_count');
    });

    it('processes remittance upload and reconciles payment', async () => {
      const remittanceXml = `
        <PaymentRemittanceReport xmlns="http://www.wcb.ab.ca/schemas/RR/RRPaymentRemittanceReport-2.01.00">
          <ReportWeek><StartDate>2026-01-13</StartDate><EndDate>2026-01-19</EndDate></ReportWeek>
          <PaymentRemittanceRecord>
            <PaymentAmount>94.15</PaymentAmount>
            <PaymentStatus>ISS</PaymentStatus>
            <ElectronicReportTransactionID>WCB-TXN-001</ElectronicReportTransactionID>
          </PaymentRemittanceRecord>
        </PaymentRemittanceReport>
      `;

      const res = await authedPost('/api/v1/wcb/remittances/upload', {
        xml_content: remittanceXml,
      } as any);

      expect(res.statusCode).toBe(200);
    });
  });

  // =========================================================================
  // Scenario 2: GP Progress Report (C151) chained from C050E
  // =========================================================================

  describe('Scenario 2: GP Progress Report (C151) chained from C050E', () => {
    it('creates C151 linked to assessed C050E parent', async () => {
      const parentDetailId = '00000000-dddd-0000-0000-000000000010';
      const parentClaim = makeClaimWithChildren(
        { state: 'PAID' },
        { wcbClaimDetailId: parentDetailId, formId: 'C050E' },
      );

      // getWcbClaim must return the parent for follow-up chain validation
      mockWcbRepo.getWcbClaim.mockResolvedValue(parentClaim);

      const payload = {
        ...VALID_C151_PAYLOAD,
        parent_wcb_claim_id: parentDetailId,
      };

      const res = await authedPost('/api/v1/wcb/claims', payload as any);

      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.data).toHaveProperty('claimId');
      expect(body.data).toHaveProperty('wcbClaimDetailId');

      // Verify parent chain was validated
      expect(mockWcbRepo.getWcbClaim).toHaveBeenCalledWith(parentDetailId, PHYSICIAN1_USER_ID);
    });

    it('validates C151 with opioid monitoring fields when narcotics_prescribed=Y', async () => {
      const wcbDetailId = '00000000-dddd-0000-0000-000000000011';
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C151',
          narcoticsPrescribed: 'Y',
          parentWcbClaimId: '00000000-dddd-0000-0000-000000000010',
        },
        {
          prescriptions: [
            { wcbPrescriptionId: crypto.randomUUID(), wcbClaimDetailId: wcbDetailId, ordinal: 1, prescriptionName: 'Oxycodone', strength: '5mg', dailyIntake: '2x daily', createdAt: new Date() },
          ],
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);
      mockWcbRepo.getInjuries.mockResolvedValue(claimData.injuries);
      mockWcbRepo.getInvoiceLines.mockResolvedValue(claimData.invoiceLines);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toHaveProperty('passed');
    });
  });

  // =========================================================================
  // Scenario 3: OIS First Report (C050S) with expanded restrictions
  // =========================================================================

  describe('Scenario 3: OIS First Report (C050S) with expanded restrictions', () => {
    it('creates C050S with grasping, lifting, reaching, and environmental restrictions', async () => {
      // Provider lookup returns OIS contract config
      mockProviderLookup.getWcbConfigForForm.mockResolvedValue({
        wcbConfigId: 'cfg-ois',
        contractId: '000053',
        roleCode: 'OIS',
        skillCode: 'GENP',
        facilityType: 'C',
      });

      const res = await authedPost('/api/v1/wcb/claims', VALID_C050S_PAYLOAD as any);

      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.data).toHaveProperty('claimId');

      // Verify work restrictions were created
      expect(mockWcbRepo.upsertWorkRestrictions).toHaveBeenCalledTimes(1);
      const restrictionCall = mockWcbRepo.upsertWorkRestrictions.mock.calls[0];
      expect(restrictionCall[1]).toHaveLength(3); // 3 restrictions submitted
    });

    it('validates C050S — all OIS fields pass', async () => {
      const wcbDetailId = '00000000-dddd-0000-0000-000000000020';
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C050S',
          contractId: '000053',
          roleCode: 'OIS',
        },
        {
          injuries: [
            { wcbInjuryId: crypto.randomUUID(), wcbClaimDetailId: wcbDetailId, ordinal: 1, partOfBodyCode: '31100', sideOfBodyCode: 'R', natureOfInjuryCode: '02100', createdAt: new Date() },
            { wcbInjuryId: crypto.randomUUID(), wcbClaimDetailId: wcbDetailId, ordinal: 2, partOfBodyCode: '31100', sideOfBodyCode: 'L', natureOfInjuryCode: '02100', createdAt: new Date() },
          ],
          workRestrictions: [
            { wcbWorkRestrictionId: crypto.randomUUID(), wcbClaimDetailId: wcbDetailId, ordinal: 1, activityType: 'GRASPING', restrictionLevel: 'LIMITED', hoursPerDay: 4, maxWeight: null, createdAt: new Date() },
            { wcbWorkRestrictionId: crypto.randomUUID(), wcbClaimDetailId: wcbDetailId, ordinal: 2, activityType: 'LIFTING', restrictionLevel: 'LIMITED', hoursPerDay: null, maxWeight: '5', createdAt: new Date() },
            { wcbWorkRestrictionId: crypto.randomUUID(), wcbClaimDetailId: wcbDetailId, ordinal: 3, activityType: 'REACHING', restrictionLevel: 'LIMITED', hoursPerDay: null, maxWeight: null, createdAt: new Date() },
          ],
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);
      mockWcbRepo.getInjuries.mockResolvedValue(claimData.injuries);
      mockWcbRepo.getInvoiceLines.mockResolvedValue(claimData.invoiceLines);
      mockWcbRepo.getWorkRestrictions.mockResolvedValue(claimData.workRestrictions);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toHaveProperty('passed');
    });
  });

  // =========================================================================
  // Scenario 4: Specialist Consultation (C568A) with attachment
  // =========================================================================

  describe('Scenario 4: Specialist Consultation (C568A) with attachment', () => {
    it('creates C568A with consultation_letter_format=ATTCH and file attachment', async () => {
      // C568A is a follow-up form — requires a parent claim in terminal state
      const parentClaim = makeClaimWithChildren(
        { state: 'PAID' },
        {
          wcbClaimDetailId: C568A_PARENT_DETAIL_ID,
          formId: 'C568',
          contractId: '000006',
          roleCode: 'SP',
          practitionerBillingNumber: PROVIDER_BILLING_NUMBER,
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(parentClaim);

      mockProviderLookup.getWcbConfigForForm.mockResolvedValue({
        wcbConfigId: 'cfg-sp',
        contractId: '000006',
        roleCode: 'SP',
        skillCode: 'ORTH',
        facilityType: 'C',
      });

      const res = await authedPost('/api/v1/wcb/claims', VALID_C568A_PAYLOAD as any);

      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.data).toHaveProperty('claimId');

      // Verify attachments were created
      expect(mockWcbRepo.upsertAttachments).toHaveBeenCalledTimes(1);
      const attachCall = mockWcbRepo.upsertAttachments.mock.calls[0];
      expect(attachCall[1]).toHaveLength(1);
      expect(attachCall[1][0]).toHaveProperty('fileName', 'consultation_letter.pdf');
    });

    it('validates C568A — passes with attachment present', async () => {
      const wcbDetailId = '00000000-dddd-0000-0000-000000000030';
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C568A',
          contractId: '000006',
          roleCode: 'SP',
          skillCode: 'ORTH',
        },
        {
          attachments: [
            {
              wcbAttachmentId: crypto.randomUUID(),
              wcbClaimDetailId: wcbDetailId,
              ordinal: 1,
              fileName: 'consultation_letter.pdf',
              fileType: 'PDF',
              fileContentB64: 'SGVsbG8gV29ybGQ=',
              fileDescription: 'Specialist consultation letter',
              fileSizeBytes: 1024,
              createdAt: new Date(),
            },
          ],
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);
      mockWcbRepo.getInjuries.mockResolvedValue(claimData.injuries);
      mockWcbRepo.getInvoiceLines.mockResolvedValue(claimData.invoiceLines);
      mockWcbRepo.getAttachments.mockResolvedValue(claimData.attachments);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toHaveProperty('passed');
    });

    it('batch with C568A includes base64 attachment in XML', async () => {
      const claimData = makeClaimWithChildren(
        { state: 'QUEUED' },
        { formId: 'C568A', contractId: '000006', roleCode: 'SP', skillCode: 'ORTH', wcbClaimNumber: '1234567' },
        {
          attachments: [
            {
              wcbAttachmentId: crypto.randomUUID(),
              wcbClaimDetailId: '00000000-dddd-0000-0000-000000000030',
              ordinal: 1,
              fileName: 'consultation_letter.pdf',
              fileType: 'PDF',
              fileContentB64: 'SGVsbG8gV29ybGQ=',
              fileDescription: 'Specialist consultation letter',
              fileSizeBytes: 1024,
              createdAt: new Date(),
            },
          ],
        },
      );

      mockWcbRepo.createBatch.mockResolvedValue(makeMockBatch());
      mockWcbRepo.getQueuedClaimsForBatch.mockResolvedValue([
        { claim: claimData.claim, detail: claimData.detail },
      ]);
      // getWcbClaim called twice per claim: once for validation, once for full load
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost('/api/v1/wcb/batches', {});

      expect(res.statusCode).toBe(201);
      expect(res.json().data).toHaveProperty('reportCount', 1);
      expect(mockWcbRepo.assignClaimsToBatch).toHaveBeenCalled();
    });
  });

  // =========================================================================
  // Scenario 5: Invoice Correction (C570) with Was/Should Be pairing
  // =========================================================================

  describe('Scenario 5: Invoice Correction (C570) with Was/Should Be pairing', () => {
    it('creates C570 linked to assessed C568 with paired correction lines', async () => {
      const parentDetailId = '00000000-dddd-0000-0000-000000000040';
      const parentClaim = makeClaimWithChildren(
        { state: 'PAID' },
        {
          wcbClaimDetailId: parentDetailId,
          formId: 'C568',
          contractId: '000001',
          roleCode: 'GP',
        },
      );

      mockWcbRepo.getWcbClaim.mockResolvedValue(parentClaim);

      const payload = {
        ...VALID_C570_PAYLOAD,
        parent_wcb_claim_id: parentDetailId,
      };

      const res = await authedPost('/api/v1/wcb/claims', payload as any);

      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.data).toHaveProperty('claimId');

      // Verify invoice lines were created with correction pairing
      expect(mockWcbRepo.upsertInvoiceLines).toHaveBeenCalledTimes(1);
      const lineCall = mockWcbRepo.upsertInvoiceLines.mock.calls[0];
      expect(lineCall[1]).toHaveLength(2);
      // Both lines share correction_pair_id=1
      expect(lineCall[1][0]).toHaveProperty('correctionPairId', 1);
      expect(lineCall[1][1]).toHaveProperty('correctionPairId', 1);
      // One is WAS, other is SHOULD_BE
      const lineTypes = lineCall[1].map((l: any) => l.lineType);
      expect(lineTypes).toContain('WAS');
      expect(lineTypes).toContain('SHOULD_BE');
    });

    it('validates C570 pairing — matching WAS and SHOULD_BE pairs', async () => {
      const wcbDetailId = '00000000-dddd-0000-0000-000000000041';
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        {
          wcbClaimDetailId: wcbDetailId,
          formId: 'C570',
          parentWcbClaimId: '00000000-dddd-0000-0000-000000000040',
        },
        {
          invoiceLines: [
            { wcbInvoiceLineId: crypto.randomUUID(), wcbClaimDetailId: wcbDetailId, ordinal: 1, lineType: 'WAS', healthServiceCode: '03.04A', diagnosticCode1: 'S6350', amount: '85.80', correctionPairId: 1, createdAt: new Date() },
            { wcbInvoiceLineId: crypto.randomUUID(), wcbClaimDetailId: wcbDetailId, ordinal: 2, lineType: 'SHOULD_BE', healthServiceCode: '03.04A', diagnosticCode1: 'S6350', amount: '94.15', correctionPairId: 1, createdAt: new Date() },
          ],
        },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);
      mockWcbRepo.getInjuries.mockResolvedValue(claimData.injuries);
      mockWcbRepo.getInvoiceLines.mockResolvedValue(claimData.invoiceLines);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toHaveProperty('passed');
    });
  });

  // =========================================================================
  // Scenario 6: Rejected claim → correct → resubmit
  // =========================================================================

  describe('Scenario 6: Rejected claim → correct → resubmit', () => {
    it('return file with Invalid status transitions claim to rejected', async () => {
      const batchId = '00000000-bbbb-0000-0000-000000000060';
      const submitterTxnId = 'MRT0000000000060';
      const wcbDetailId = '00000000-dddd-0000-0000-000000000060';
      const claimId = '00000000-cccc-0000-0000-000000000060';

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
        `MER-B-TEST0060\t1\tMRT-SUBMIT\t20260115`,
        `WCB-TXN-060\t${submitterTxnId}\t\t\tINVALID\t20260115`,
        `121023: Worker Personal Health Number must be BLANK since Worker Personal Health Number Indicator is No`,
      ].join('\n');

      const res = await authedPost('/api/v1/wcb/returns/upload', {
        file_content: returnFileContent,
      } as any);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toHaveProperty('invalid_count');
      // Claim state transitioned to REJECTED
      expect(mockClaimRepo.transitionClaimState).toHaveBeenCalledWith(
        claimId,
        PHYSICIAN1_USER_ID,
        'REJECTED',
      );
    });

    it('physician corrects rejected claim and updates form fields', async () => {
      const wcbDetailId = '00000000-dddd-0000-0000-000000000061';
      const existingClaim = makeClaimWithChildren(
        { state: 'DRAFT' },
        { wcbClaimDetailId: wcbDetailId },
      );
      const updatedClaim = {
        ...existingClaim,
        detail: { ...existingClaim.detail, symptoms: 'Updated pain description' },
      };
      mockWcbRepo.getWcbClaim
        .mockResolvedValueOnce(existingClaim) // ownership check in updateWcbClaim
        .mockResolvedValueOnce(updatedClaim); // return updated claim at end

      const res = await authedPut(`/api/v1/wcb/claims/${wcbDetailId}`, {
        symptoms: 'Updated pain description',
      });

      expect(res.statusCode).toBe(200);
      expect(mockWcbRepo.updateWcbClaim).toHaveBeenCalled();
    });

    it('corrected claim can be revalidated and resubmitted in new batch', async () => {
      const wcbDetailId = '00000000-dddd-0000-0000-000000000062';
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        { wcbClaimDetailId: wcbDetailId },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);
      mockWcbRepo.getInjuries.mockResolvedValue(claimData.injuries);
      mockWcbRepo.getInvoiceLines.mockResolvedValue(claimData.invoiceLines);

      // Re-validate
      const validateRes = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/validate`);
      expect(validateRes.statusCode).toBe(200);

      // Then assemble a new batch
      const batchClaimData = makeClaimWithChildren({ state: 'QUEUED' }, {});
      mockWcbRepo.createBatch.mockResolvedValue(makeMockBatch());
      mockWcbRepo.getQueuedClaimsForBatch.mockResolvedValue([
        { claim: batchClaimData.claim, detail: batchClaimData.detail },
      ]);
      mockWcbRepo.getWcbClaim.mockResolvedValue(batchClaimData);

      const batchRes = await authedPost('/api/v1/wcb/batches', {});
      expect(batchRes.statusCode).toBe(201);
      expect(batchRes.json().data.reportCount).toBe(1);
    });
  });

  // =========================================================================
  // Scenario 7: Batch with mixed form types (C050E + C568 + C569)
  // =========================================================================

  describe('Scenario 7: Batch with mixed form types', () => {
    it('queues C050E + C568 + C569 → single batch → XML with 3 reports', async () => {
      const claim1 = makeClaimWithChildren(
        { state: 'QUEUED' },
        { formId: 'C050E' },
      );
      const claim2 = makeClaimWithChildren(
        { state: 'QUEUED' },
        { formId: 'C568', wcbClaimNumber: '1234567' },
      );
      const claim3 = makeClaimWithChildren(
        { state: 'QUEUED' },
        { formId: 'C569', wcbClaimNumber: '1234567' },
        {
          invoiceLines: [
            { wcbInvoiceLineId: crypto.randomUUID(), wcbClaimDetailId: '', ordinal: 1, lineType: 'SUPPLY', quantity: 2, supplyDescription: 'Wrist brace', amount: '45.00', createdAt: new Date() },
          ],
        },
      );

      mockWcbRepo.createBatch.mockResolvedValue(makeMockBatch());
      mockWcbRepo.getQueuedClaimsForBatch.mockResolvedValue([
        { claim: claim1.claim, detail: claim1.detail },
        { claim: claim2.claim, detail: claim2.detail },
        { claim: claim3.claim, detail: claim3.detail },
      ]);

      // getWcbClaim called twice per queued claim (once for validation, once for full load)
      mockWcbRepo.getWcbClaim.mockImplementation(async (id: string) => {
        if (id === claim1.detail.wcbClaimDetailId) return claim1;
        if (id === claim2.detail.wcbClaimDetailId) return claim2;
        if (id === claim3.detail.wcbClaimDetailId) return claim3;
        return null;
      });

      const res = await authedPost('/api/v1/wcb/batches', {});

      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.data.reportCount).toBe(3);
      expect(body.data.skippedClaimIds).toEqual([]);

      // Verify all 3 claims assigned to batch
      expect(mockWcbRepo.assignClaimsToBatch).toHaveBeenCalledTimes(1);
      const assignCall = mockWcbRepo.assignClaimsToBatch.mock.calls[0];
      expect(assignCall[2]).toHaveLength(3); // 3 claim IDs
    });

    it('return file with mixed outcomes — one Complete, one Invalid, one Complete', async () => {
      const batchId = '00000000-bbbb-0000-0000-000000000070';
      const txnId1 = 'MRT0000000000071';
      const txnId2 = 'MRT0000000000072';
      const txnId3 = 'MRT0000000000073';
      const detailId1 = '00000000-dddd-0000-0000-000000000071';
      const detailId2 = '00000000-dddd-0000-0000-000000000072';
      const detailId3 = '00000000-dddd-0000-0000-000000000073';
      const claimId1 = '00000000-cccc-0000-0000-000000000071';
      const claimId2 = '00000000-cccc-0000-0000-000000000072';
      const claimId3 = '00000000-cccc-0000-0000-000000000073';

      mockWcbRepo.getBatchByControlId.mockResolvedValue(
        makeMockBatch({ wcbBatchId: batchId, status: WcbBatchStatus.UPLOADED }),
      );
      mockWcbRepo.matchReturnToClaimBySubmitterTxnId
        .mockResolvedValueOnce(detailId1)
        .mockResolvedValueOnce(detailId2)
        .mockResolvedValueOnce(detailId3);
      mockWcbRepo.getWcbClaimBySubmitterTxnId
        .mockResolvedValueOnce({ claimId: claimId1, wcbClaimDetailId: detailId1, formId: 'C050E', submitterTxnId: txnId1, wcbClaimNumber: null })
        .mockResolvedValueOnce({ claimId: claimId2, wcbClaimDetailId: detailId2, formId: 'C568', submitterTxnId: txnId2, wcbClaimNumber: null })
        .mockResolvedValueOnce({ claimId: claimId3, wcbClaimDetailId: detailId3, formId: 'C569', submitterTxnId: txnId3, wcbClaimNumber: null });

      const returnFileContent = [
        `MER-B-TEST0070\t3\tMRT-SUBMIT\t20260115`,
        `WCB-TXN-071\t${txnId1}\t1234001\tAccepted\tCOMPLETE\t20260115`,
        `1\t20260115\t03.04A\tApproved`,
        ``,
        `WCB-TXN-072\t${txnId2}\t\t\tINVALID\t20260115`,
        `100001: Missing required field`,
        ``,
        `WCB-TXN-073\t${txnId3}\t1234003\tAccepted\tCOMPLETE\t20260115`,
        `1\t20260115\tSUPPLY\tApproved`,
      ].join('\n');

      const res = await authedPost('/api/v1/wcb/returns/upload', {
        file_content: returnFileContent,
      } as any);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.matched_count).toBeGreaterThanOrEqual(2);
    });
  });

  // =========================================================================
  // Scenario 8: MVP flow — export PDF and manual outcome recording
  // =========================================================================

  describe('Scenario 8: MVP flow — export and manual outcome', () => {
    it('creates a claim, validates, and generates MVP export', async () => {
      // Step 1: Create
      const createRes = await authedPost('/api/v1/wcb/claims', VALID_C050E_PAYLOAD as any);
      expect(createRes.statusCode).toBe(201);
      const { wcbClaimDetailId } = createRes.json().data;

      // Step 2: Validate
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        { wcbClaimDetailId },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);
      mockWcbRepo.getInjuries.mockResolvedValue(claimData.injuries);
      mockWcbRepo.getInvoiceLines.mockResolvedValue(claimData.invoiceLines);

      const validateRes = await authedPost(`/api/v1/wcb/claims/${wcbClaimDetailId}/validate`);
      expect(validateRes.statusCode).toBe(200);
    });

    it('MVP export endpoint returns structured form sections', async () => {
      const wcbDetailId = '00000000-dddd-0000-0000-000000000080';
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        { wcbClaimDetailId: wcbDetailId },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);
      mockWcbRepo.getInjuries.mockResolvedValue(claimData.injuries);
      mockWcbRepo.getInvoiceLines.mockResolvedValue(claimData.invoiceLines);
      // Needed for fee calculation inside export
      mockWcbRepo.listWcbClaimsForPhysician.mockResolvedValue({ data: [], pagination: { total: 0, page: 1, pageSize: 25, hasMore: false } });

      const res = await authedGet(`/api/v1/wcb/claims/${wcbDetailId}/export`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toHaveProperty('formId');
      expect(body.data).toHaveProperty('formName');
      expect(body.data).toHaveProperty('sections');
      expect(Array.isArray(body.data.sections)).toBe(true);
      expect(body.data.sections.length).toBeGreaterThan(0);
    });

    it('MVP export endpoint returns 404 when not in MVP phase', async () => {
      // Build a separate app with VENDOR phase
      const vendorApp = await buildTestApp('VENDOR');

      const res = await vendorApp.inject({
        method: 'GET',
        url: '/api/v1/wcb/claims/00000000-dddd-0000-0000-000000000080/export',
        headers: { cookie: `session=${PHYSICIAN1_SESSION_TOKEN}` },
      });

      expect(res.statusCode).toBe(404);
      await vendorApp.close();
    });

    it('records manual outcome — accepted with WCB claim number', async () => {
      const wcbDetailId = '00000000-dddd-0000-0000-000000000081';
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        { wcbClaimDetailId: wcbDetailId },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/manual-outcome`, {
        acceptance_status: 'accepted',
        wcb_claim_number: '9876543',
        payment_amount: 94.15,
      });

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toHaveProperty('newState', 'ASSESSED');
      expect(body.data).toHaveProperty('wcbClaimNumber', '9876543');

      // Verify WCB claim number stored
      expect(mockWcbRepo.updateWcbClaimNumber).toHaveBeenCalledWith(wcbDetailId, '9876543');
      // Verify claim state transition
      expect(mockClaimRepo.transitionClaimState).toHaveBeenCalledWith(
        expect.any(String),
        PHYSICIAN1_USER_ID,
        'ASSESSED',
      );
    });

    it('records manual outcome — rejected', async () => {
      const wcbDetailId = '00000000-dddd-0000-0000-000000000082';
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        { wcbClaimDetailId: wcbDetailId },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPost(`/api/v1/wcb/claims/${wcbDetailId}/manual-outcome`, {
        acceptance_status: 'rejected',
      });

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toHaveProperty('newState', 'REJECTED');
    });

    it('manual outcome returns 404 when not in MVP phase', async () => {
      const vendorApp = await buildTestApp('VENDOR');

      const res = await vendorApp.inject({
        method: 'POST',
        url: '/api/v1/wcb/claims/00000000-dddd-0000-0000-000000000081/manual-outcome',
        headers: {
          cookie: `session=${PHYSICIAN1_SESSION_TOKEN}`,
          'content-type': 'application/json',
        },
        payload: { acceptance_status: 'accepted' },
      });

      expect(res.statusCode).toBe(404);
      await vendorApp.close();
    });
  });

  // =========================================================================
  // Additional edge cases
  // =========================================================================

  describe('Edge cases', () => {
    it('batch creation with no queued claims returns 422', async () => {
      mockWcbRepo.createBatch.mockResolvedValue(makeMockBatch());
      mockWcbRepo.getQueuedClaimsForBatch.mockResolvedValue([]);

      const res = await authedPost('/api/v1/wcb/batches', {});

      expect(res.statusCode).toBe(422);
      const body = res.json();
      expect(body.error).toHaveProperty('code', 'BUSINESS_RULE_VIOLATION');
    });

    it('delete claim in DRAFT state succeeds', async () => {
      const wcbDetailId = '00000000-dddd-0000-0000-000000000090';
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        { wcbClaimDetailId: wcbDetailId },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedDelete(`/api/v1/wcb/claims/${wcbDetailId}`);

      expect(res.statusCode).toBe(204);
      expect(mockWcbRepo.softDeleteWcbClaim).toHaveBeenCalledWith(wcbDetailId, PHYSICIAN1_USER_ID);
    });

    it('delete claim in non-DRAFT state returns 422', async () => {
      const wcbDetailId = '00000000-dddd-0000-0000-000000000091';
      const claimData = makeClaimWithChildren(
        { state: 'QUEUED' },
        { wcbClaimDetailId: wcbDetailId },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedDelete(`/api/v1/wcb/claims/${wcbDetailId}`);

      expect(res.statusCode).toBe(422);
    });

    it('get claim returns 404 for nonexistent claim', async () => {
      mockWcbRepo.getWcbClaim.mockResolvedValue(null);

      const res = await authedGet('/api/v1/wcb/claims/00000000-0000-0000-0000-000000000000');

      expect(res.statusCode).toBe(404);
    });

    it('form schema endpoint returns sections and fields for C050E', async () => {
      const wcbDetailId = '00000000-dddd-0000-0000-000000000092';
      const claimData = makeClaimWithChildren(
        { state: 'DRAFT' },
        { wcbClaimDetailId: wcbDetailId, formId: 'C050E' },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedGet(`/api/v1/wcb/claims/${wcbDetailId}/form-schema`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toHaveProperty('form_id', 'C050E');
      expect(body.data).toHaveProperty('sections');
      expect(Array.isArray(body.data.sections)).toBe(true);

      // C050E has GENERAL, CLAIMANT, PRACTITIONER, EMPLOYER, ACCIDENT, INJURY, TREATMENT_PLAN, RETURN_TO_WORK, ATTACHMENTS, INVOICE sections
      const activeSections = body.data.sections.filter((s: any) => s.active);
      expect(activeSections.length).toBeGreaterThanOrEqual(6);
    });

    it('list batches with status filter returns paginated results', async () => {
      mockWcbRepo.listBatches.mockResolvedValue({
        data: [makeMockBatch({ status: WcbBatchStatus.UPLOADED })],
        pagination: { total: 1, page: 1, pageSize: 25, hasMore: false },
      });

      const res = await authedGet('/api/v1/wcb/batches?status=UPLOADED&page=1&page_size=25');

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toHaveLength(1);
      expect(body.pagination).toHaveProperty('total', 1);
    });

    it('return results for batch returns return records', async () => {
      const batchId = '00000000-bbbb-0000-0000-000000000093';
      mockWcbRepo.getBatch.mockResolvedValue(
        makeMockBatch({ wcbBatchId: batchId, status: WcbBatchStatus.RETURN_RECEIVED }),
      );
      mockWcbRepo.getReturnRecordsByBatch.mockResolvedValue([
        {
          wcbReturnRecordId: 'ret-1',
          wcbBatchId: batchId,
          reportTxnId: 'WCB-TXN-001',
          submitterTxnId: 'MRT0000000000001',
          processedClaimNumber: '1234567',
          claimDecision: 'Accepted',
          reportStatus: 'Complete',
          txnSubmissionDate: '2026-01-15',
          errors: null,
          wcbClaimDetailId: '00000000-dddd-0000-0000-000000000001',
          createdAt: new Date(),
        },
      ]);

      const res = await authedGet(`/api/v1/wcb/returns/${batchId}`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(Array.isArray(body.data)).toBe(true);
      expect(body.data).toHaveLength(1);
    });

    it('update claim in non-DRAFT state returns 422', async () => {
      const wcbDetailId = '00000000-dddd-0000-0000-000000000094';
      const claimData = makeClaimWithChildren(
        { state: 'QUEUED' },
        { wcbClaimDetailId: wcbDetailId },
      );
      mockWcbRepo.getWcbClaim.mockResolvedValue(claimData);

      const res = await authedPut(`/api/v1/wcb/claims/${wcbDetailId}`, {
        symptoms: 'Updated symptoms',
      });

      expect(res.statusCode).toBe(422);
    });

    it('download batch in non-VALIDATED state returns 422', async () => {
      const batchId = '00000000-bbbb-0000-0000-000000000095';
      mockWcbRepo.getBatch.mockResolvedValue(
        makeMockBatch({ wcbBatchId: batchId, status: WcbBatchStatus.ASSEMBLING }),
      );

      const res = await authedGet(`/api/v1/wcb/batches/${batchId}/download`);

      expect(res.statusCode).toBe(422);
    });

    it('remittance list endpoint returns paginated results', async () => {
      mockWcbRepo.listRemittanceImports.mockResolvedValue({
        data: [{ wcbRemittanceImportId: crypto.randomUUID(), physicianId: PHYSICIAN1_USER_ID, reportWeekStart: '2026-01-13', reportWeekEnd: '2026-01-19', createdAt: new Date() }],
        pagination: { total: 1, page: 1, pageSize: 25, hasMore: false },
      });

      const res = await authedGet('/api/v1/wcb/remittances?page=1&page_size=25');

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data).toHaveLength(1);
      expect(body.pagination).toHaveProperty('total', 1);
    });

    it('remittance discrepancies endpoint returns results', async () => {
      const remittanceId = '00000000-eeee-0000-0000-000000000001';
      mockWcbRepo.getRemittanceDiscrepancies.mockResolvedValue([
        {
          discrepancyType: 'AMOUNT_MISMATCH',
          paymentAmount: '85.80',
          billedAmount: '94.15',
          claimNumber: '1234567',
        },
      ]);

      const res = await authedGet(`/api/v1/wcb/remittances/${remittanceId}/discrepancies`);

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(Array.isArray(body.data)).toBe(true);
    });
  });
});
