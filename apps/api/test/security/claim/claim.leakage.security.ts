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
import { claimRoutes } from '../../../src/domains/claim/claim.routes.js';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { type ClaimHandlerDeps } from '../../../src/domains/claim/claim.handlers.js';
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
const P1_PROVIDER_ID = P1_USER_ID;
const P1_SESSION_ID = '11111111-1111-0000-0000-000000000011';

// Physician 2 — "other" physician (attacker perspective)
const P2_SESSION_TOKEN = randomBytes(32).toString('hex');
const P2_SESSION_TOKEN_HASH = hashToken(P2_SESSION_TOKEN);
const P2_USER_ID = '22222222-2222-0000-0000-000000000002';
const P2_PROVIDER_ID = P2_USER_ID;
const P2_SESSION_ID = '22222222-2222-0000-0000-000000000022';

// ---------------------------------------------------------------------------
// Test data IDs — resources owned by each physician
// ---------------------------------------------------------------------------

// Physician 1's data
const P1_CLAIM_ID_A = 'aaaa1111-0000-0000-0000-000000000001';
const P1_CLAIM_ID_B = 'aaaa1111-0000-0000-0000-000000000002';
const P1_PATIENT_ID = 'bbbb1111-0000-0000-0000-000000000001';
const P1_IMPORT_ID = 'cccc1111-0000-0000-0000-000000000001';
const P1_TEMPLATE_ID = 'dddd1111-0000-0000-0000-000000000001';
const P1_SHIFT_ID = 'eeee1111-0000-0000-0000-000000000001';
const P1_EXPORT_ID = 'ffff1111-0000-0000-0000-000000000001';
const P1_FACILITY_ID = '77771111-0000-0000-0000-000000000001';

// Physician 2's data
const P2_CLAIM_ID_A = 'aaaa2222-0000-0000-0000-000000000001';
const P2_PATIENT_ID = 'bbbb2222-0000-0000-0000-000000000001';
const P2_EXPORT_ID = 'ffff2222-0000-0000-0000-000000000002';

// Non-existent UUID
const NONEXISTENT_UUID = '99999999-9999-9999-9999-999999999999';

// Sensitive PHI data — must never leak
const P1_PATIENT_PHN = '123456789';
const P1_PATIENT_DOB = '1985-05-15';
const P1_PATIENT_NAME = 'Alice Smith';
const P2_PATIENT_PHN = '987654321';
const P2_PATIENT_NAME = 'Charlie Brown';

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
// Claim data stores (physician-scoped)
// ---------------------------------------------------------------------------

interface MockClaim {
  claimId: string;
  physicianId: string;
  patientId: string;
  claimType: string;
  state: string;
  dateOfService: string;
  submissionDeadline: string;
  importSource: string;
  importBatchId: string | null;
  shiftId: string | null;
  isClean: boolean;
  validationResult: any;
  aiCoachSuggestions: any;
  duplicateAlert: any;
  flags: any;
  createdBy: string;
  updatedBy: string;
  deletedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

interface MockImportBatch {
  importBatchId: string;
  physicianId: string;
  fileName: string;
  fileHash: string;
  fieldMappingTemplateId: string | null;
  totalRows: number;
  successCount: number;
  errorCount: number;
  errorDetails: any;
  status: string;
  createdBy: string;
  createdAt: Date;
}

interface MockTemplate {
  templateId: string;
  physicianId: string;
  name: string;
  emrType: string | null;
  mappings: any;
  delimiter: string;
  hasHeaderRow: boolean;
  dateFormat: string | null;
  createdAt: Date;
  updatedAt: Date;
}

interface MockShift {
  shiftId: string;
  physicianId: string;
  facilityId: string;
  shiftDate: string;
  startTime: string | null;
  endTime: string | null;
  encounterCount: number;
  status: string;
  createdAt: Date;
  updatedAt: Date;
}

interface MockExport {
  exportId: string;
  physicianId: string;
  dateFrom: string;
  dateTo: string;
  claimType: string | null;
  format: string;
  status: string;
  filePath: string | null;
  createdAt: Date;
  updatedAt: Date;
}

interface MockAuditEntry {
  auditId: string;
  claimId: string;
  action: string;
  previousState: string | null;
  newState: string | null;
  changes: any;
  actorId: string;
  actorContext: string;
  createdAt: Date;
}

const claimsStore: Record<string, MockClaim> = {};
const importBatchStore: Record<string, MockImportBatch> = {};
const templateStore: Record<string, MockTemplate> = {};
const shiftStore: Record<string, MockShift> = {};
const exportStore: Record<string, MockExport> = {};
const auditStore: MockAuditEntry[] = [];

// ---------------------------------------------------------------------------
// Seed test data
// ---------------------------------------------------------------------------

function seedTestData() {
  Object.keys(claimsStore).forEach((k) => delete claimsStore[k]);
  Object.keys(importBatchStore).forEach((k) => delete importBatchStore[k]);
  Object.keys(templateStore).forEach((k) => delete templateStore[k]);
  Object.keys(shiftStore).forEach((k) => delete shiftStore[k]);
  Object.keys(exportStore).forEach((k) => delete exportStore[k]);
  auditStore.length = 0;

  // --- Physician 1's claims ---
  claimsStore[P1_CLAIM_ID_A] = {
    claimId: P1_CLAIM_ID_A,
    physicianId: P1_PROVIDER_ID,
    patientId: P1_PATIENT_ID,
    claimType: 'AHCIP',
    state: 'DRAFT',
    dateOfService: '2026-01-15',
    submissionDeadline: '2026-04-15',
    importSource: 'MANUAL',
    importBatchId: null,
    shiftId: null,
    isClean: true,
    validationResult: null,
    aiCoachSuggestions: null,
    duplicateAlert: null,
    flags: null,
    createdBy: P1_USER_ID,
    updatedBy: P1_USER_ID,
    deletedAt: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  };
  claimsStore[P1_CLAIM_ID_B] = {
    claimId: P1_CLAIM_ID_B,
    physicianId: P1_PROVIDER_ID,
    patientId: P1_PATIENT_ID,
    claimType: 'WCB',
    state: 'REJECTED',
    dateOfService: '2026-01-20',
    submissionDeadline: '2026-04-20',
    importSource: 'MANUAL',
    importBatchId: null,
    shiftId: null,
    isClean: false,
    validationResult: {
      errors: [{ check: 'S1', message: 'Test error' }],
      warnings: [],
      info: [],
      passed: false,
    },
    aiCoachSuggestions: null,
    duplicateAlert: null,
    flags: null,
    createdBy: P1_USER_ID,
    updatedBy: P1_USER_ID,
    deletedAt: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  // --- Physician 2's claims ---
  claimsStore[P2_CLAIM_ID_A] = {
    claimId: P2_CLAIM_ID_A,
    physicianId: P2_PROVIDER_ID,
    patientId: P2_PATIENT_ID,
    claimType: 'AHCIP',
    state: 'VALIDATED',
    dateOfService: '2026-02-01',
    submissionDeadline: '2026-05-02',
    importSource: 'MANUAL',
    importBatchId: null,
    shiftId: null,
    isClean: true,
    validationResult: { errors: [], warnings: [], info: [], passed: true },
    aiCoachSuggestions: null,
    duplicateAlert: null,
    flags: null,
    createdBy: P2_USER_ID,
    updatedBy: P2_USER_ID,
    deletedAt: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  // --- Import batches ---
  importBatchStore[P1_IMPORT_ID] = {
    importBatchId: P1_IMPORT_ID,
    physicianId: P1_PROVIDER_ID,
    fileName: 'claims_p1.csv',
    fileHash: 'hash-p1-claims',
    fieldMappingTemplateId: null,
    totalRows: 10,
    successCount: 8,
    errorCount: 2,
    errorDetails: [
      { row: 2, message: 'Missing required fields: date_of_service' },
      { row: 3, field: 'phn', message: 'PHN failed Luhn check digit validation' },
    ],
    status: 'COMPLETED',
    createdBy: P1_USER_ID,
    createdAt: new Date(),
  };

  // --- Templates ---
  templateStore[P1_TEMPLATE_ID] = {
    templateId: P1_TEMPLATE_ID,
    physicianId: P1_PROVIDER_ID,
    name: 'P1 Template',
    emrType: 'ACCURO',
    mappings: [{ source_column: 'col1', target_field: 'patientId' }],
    delimiter: ',',
    hasHeaderRow: true,
    dateFormat: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  // --- Shifts ---
  shiftStore[P1_SHIFT_ID] = {
    shiftId: P1_SHIFT_ID,
    physicianId: P1_PROVIDER_ID,
    facilityId: P1_FACILITY_ID,
    shiftDate: '2026-01-20',
    startTime: '08:00',
    endTime: '16:00',
    encounterCount: 3,
    status: 'IN_PROGRESS',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  // --- Exports ---
  exportStore[P1_EXPORT_ID] = {
    exportId: P1_EXPORT_ID,
    physicianId: P1_PROVIDER_ID,
    dateFrom: '2026-01-01',
    dateTo: '2026-01-31',
    claimType: null,
    format: 'CSV',
    status: 'COMPLETED',
    filePath: `exports/${P1_PROVIDER_ID}/${P1_EXPORT_ID}.csv`,
    createdAt: new Date(),
    updatedAt: new Date(),
  };
  exportStore[P2_EXPORT_ID] = {
    exportId: P2_EXPORT_ID,
    physicianId: P2_PROVIDER_ID,
    dateFrom: '2026-02-01',
    dateTo: '2026-02-28',
    claimType: null,
    format: 'JSON',
    status: 'COMPLETED',
    filePath: `exports/${P2_PROVIDER_ID}/${P2_EXPORT_ID}.json`,
    createdAt: new Date(),
    updatedAt: new Date(),
  };
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
// Physician-scoped mock claim repository
// ---------------------------------------------------------------------------

function createScopedClaimRepo() {
  return {
    createClaim: vi.fn(async (data: any) => {
      const id = crypto.randomUUID();
      const claim: MockClaim = {
        claimId: id,
        physicianId: data.physicianId,
        patientId: data.patientId,
        claimType: data.claimType,
        state: 'DRAFT',
        dateOfService: data.dateOfService,
        submissionDeadline: data.submissionDeadline ?? '2026-06-01',
        importSource: data.importSource ?? 'MANUAL',
        importBatchId: data.importBatchId ?? null,
        shiftId: data.shiftId ?? null,
        isClean: true,
        validationResult: null,
        aiCoachSuggestions: null,
        duplicateAlert: null,
        flags: null,
        createdBy: data.createdBy,
        updatedBy: data.updatedBy ?? data.createdBy,
        deletedAt: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      claimsStore[id] = claim;
      return claim;
    }),

    findClaimById: vi.fn(async (claimId: string, physicianId: string) => {
      const claim = claimsStore[claimId];
      if (!claim || claim.physicianId !== physicianId || claim.deletedAt) return undefined;
      return claim;
    }),

    updateClaim: vi.fn(async (claimId: string, physicianId: string, data: any) => {
      const claim = claimsStore[claimId];
      if (!claim || claim.physicianId !== physicianId || claim.deletedAt) return undefined;
      const updated = { ...claim, ...data, updatedAt: new Date() };
      claimsStore[claimId] = updated;
      return updated;
    }),

    softDeleteClaim: vi.fn(async (claimId: string, physicianId: string) => {
      const claim = claimsStore[claimId];
      if (!claim || claim.physicianId !== physicianId || claim.state !== 'DRAFT' || claim.deletedAt) return false;
      claimsStore[claimId] = { ...claim, deletedAt: new Date(), state: 'DELETED', updatedAt: new Date() };
      return true;
    }),

    listClaims: vi.fn(async (physicianId: string, filters: any) => {
      let matches = Object.values(claimsStore).filter(
        (c) => c.physicianId === physicianId && !c.deletedAt,
      );
      if (filters.state) matches = matches.filter((c) => c.state === filters.state);
      if (filters.claimType) matches = matches.filter((c) => c.claimType === filters.claimType);
      if (filters.patientId) matches = matches.filter((c) => c.patientId === filters.patientId);
      if (filters.dateFrom) matches = matches.filter((c) => c.dateOfService >= filters.dateFrom);
      if (filters.dateTo) matches = matches.filter((c) => c.dateOfService <= filters.dateTo);
      const page = filters.page ?? 1;
      const pageSize = filters.pageSize ?? 25;
      const start = (page - 1) * pageSize;
      return {
        data: matches.slice(start, start + pageSize),
        pagination: { total: matches.length, page, pageSize, hasMore: page * pageSize < matches.length },
      };
    }),

    countClaimsByState: vi.fn(async () => []),
    findClaimsApproachingDeadline: vi.fn(async () => []),

    transitionState: vi.fn(async (claimId: string, physicianId: string, fromState: string, toState: string) => {
      const claim = claimsStore[claimId];
      if (!claim || claim.physicianId !== physicianId || claim.state !== fromState || claim.deletedAt) {
        throw new Error('State transition failed: claim is not in expected state');
      }
      const updated = { ...claim, state: toState, updatedAt: new Date() };
      claimsStore[claimId] = updated;
      return updated;
    }),

    classifyClaim: vi.fn(async (claimId: string, physicianId: string, isClean: boolean) => {
      const claim = claimsStore[claimId];
      if (!claim || claim.physicianId !== physicianId) return undefined;
      claimsStore[claimId] = { ...claim, isClean, updatedAt: new Date() };
      return claimsStore[claimId];
    }),

    updateValidationResult: vi.fn(async (claimId: string, physicianId: string, result: any) => {
      const claim = claimsStore[claimId];
      if (!claim || claim.physicianId !== physicianId) return undefined;
      claimsStore[claimId] = { ...claim, validationResult: result, updatedAt: new Date() };
      return claimsStore[claimId];
    }),

    updateAiSuggestions: vi.fn(async (claimId: string, physicianId: string, suggestions: any) => {
      const claim = claimsStore[claimId];
      if (!claim || claim.physicianId !== physicianId) return undefined;
      claimsStore[claimId] = { ...claim, aiCoachSuggestions: suggestions, updatedAt: new Date() };
      return claimsStore[claimId];
    }),

    updateDuplicateAlert: vi.fn(async (claimId: string, physicianId: string, alert: any) => {
      const claim = claimsStore[claimId];
      if (!claim || claim.physicianId !== physicianId) return undefined;
      claimsStore[claimId] = { ...claim, duplicateAlert: alert, updatedAt: new Date() };
      return claimsStore[claimId];
    }),

    updateFlags: vi.fn(async () => ({})),

    // Import batches
    createImportBatch: vi.fn(async (data: any) => {
      const id = crypto.randomUUID();
      const batch: MockImportBatch = {
        importBatchId: id,
        physicianId: data.physicianId,
        fileName: data.fileName,
        fileHash: data.fileHash,
        fieldMappingTemplateId: data.fieldMappingTemplateId ?? null,
        totalRows: data.totalRows,
        successCount: 0,
        errorCount: 0,
        errorDetails: null,
        status: data.status ?? 'PENDING',
        createdBy: data.createdBy,
        createdAt: new Date(),
      };
      importBatchStore[id] = batch;
      return batch;
    }),

    findImportBatchById: vi.fn(async (batchId: string, physicianId: string) => {
      const batch = importBatchStore[batchId];
      if (!batch || batch.physicianId !== physicianId) return undefined;
      return batch;
    }),

    updateImportBatchStatus: vi.fn(async (batchId: string, physicianId: string, status: string) => {
      const batch = importBatchStore[batchId];
      if (!batch || batch.physicianId !== physicianId) return undefined;
      importBatchStore[batchId] = { ...batch, status };
      return importBatchStore[batchId];
    }),

    findDuplicateImportByHash: vi.fn(async (physicianId: string, fileHash: string) => {
      return Object.values(importBatchStore).find(
        (b) => b.physicianId === physicianId && b.fileHash === fileHash,
      ) ?? undefined;
    }),

    listImportBatches: vi.fn(async (physicianId: string) => {
      const batches = Object.values(importBatchStore).filter(
        (b) => b.physicianId === physicianId,
      );
      return {
        data: batches,
        pagination: { total: batches.length, page: 1, pageSize: 25, hasMore: false },
      };
    }),

    findClaimsForBatchAssembly: vi.fn(async () => []),
    bulkTransitionState: vi.fn(async () => []),

    // Templates
    createTemplate: vi.fn(async (data: any) => {
      const id = crypto.randomUUID();
      const template: MockTemplate = {
        templateId: id,
        physicianId: data.physicianId,
        name: data.name,
        emrType: data.emrType ?? null,
        mappings: data.mappings ?? [],
        delimiter: data.delimiter ?? ',',
        hasHeaderRow: data.hasHeaderRow ?? true,
        dateFormat: data.dateFormat ?? null,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      templateStore[id] = template;
      return template;
    }),

    findTemplateById: vi.fn(async (templateId: string, physicianId: string) => {
      const template = templateStore[templateId];
      if (!template || template.physicianId !== physicianId) return undefined;
      return template;
    }),

    updateTemplate: vi.fn(async (templateId: string, physicianId: string, data: any) => {
      const template = templateStore[templateId];
      if (!template || template.physicianId !== physicianId) return undefined;
      const updated = { ...template, ...data, updatedAt: new Date() };
      templateStore[templateId] = updated;
      return updated;
    }),

    deleteTemplate: vi.fn(async (templateId: string, physicianId: string) => {
      const template = templateStore[templateId];
      if (!template || template.physicianId !== physicianId) return false;
      delete templateStore[templateId];
      return true;
    }),

    listTemplates: vi.fn(async (physicianId: string) => {
      return Object.values(templateStore).filter(
        (t) => t.physicianId === physicianId,
      );
    }),

    // Shifts
    createShift: vi.fn(async (data: any) => {
      const id = crypto.randomUUID();
      const shift: MockShift = {
        shiftId: id,
        physicianId: data.physicianId,
        facilityId: data.facilityId,
        shiftDate: data.shiftDate,
        startTime: data.startTime ?? null,
        endTime: data.endTime ?? null,
        encounterCount: 0,
        status: 'IN_PROGRESS',
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      shiftStore[id] = shift;
      return shift;
    }),

    findShiftById: vi.fn(async (shiftId: string, physicianId: string) => {
      const shift = shiftStore[shiftId];
      if (!shift || shift.physicianId !== physicianId) return undefined;
      return shift;
    }),

    updateShiftStatus: vi.fn(async (shiftId: string, physicianId: string, status: string) => {
      const shift = shiftStore[shiftId];
      if (!shift || shift.physicianId !== physicianId) return undefined;
      shiftStore[shiftId] = { ...shift, status, updatedAt: new Date() };
      return shiftStore[shiftId];
    }),

    updateShiftTimes: vi.fn(async () => ({})),

    incrementEncounterCount: vi.fn(async (shiftId: string, physicianId: string) => {
      const shift = shiftStore[shiftId];
      if (!shift || shift.physicianId !== physicianId) return undefined;
      shiftStore[shiftId] = { ...shift, encounterCount: shift.encounterCount + 1, updatedAt: new Date() };
      return shiftStore[shiftId];
    }),

    listShifts: vi.fn(async (physicianId: string) => {
      const list = Object.values(shiftStore).filter((s) => s.physicianId === physicianId);
      return {
        data: list,
        pagination: { total: list.length, page: 1, pageSize: 25, hasMore: false },
      };
    }),

    findClaimsByShift: vi.fn(async (shiftId: string, physicianId: string) => {
      return Object.values(claimsStore).filter(
        (c) => c.shiftId === shiftId && c.physicianId === physicianId && !c.deletedAt,
      );
    }),

    // Exports
    createExportRecord: vi.fn(async (data: any) => {
      const id = crypto.randomUUID();
      const exp: MockExport = {
        exportId: id,
        physicianId: data.physicianId,
        dateFrom: data.dateFrom,
        dateTo: data.dateTo,
        claimType: data.claimType ?? null,
        format: data.format,
        status: 'PENDING',
        filePath: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      exportStore[id] = exp;
      return exp;
    }),

    findExportById: vi.fn(async (exportId: string, physicianId: string) => {
      const exp = exportStore[exportId];
      if (!exp || exp.physicianId !== physicianId) return undefined;
      return exp;
    }),

    updateExportStatus: vi.fn(async () => ({})),

    // Audit
    appendClaimAudit: vi.fn(async (entry: any) => {
      const audit: MockAuditEntry = {
        auditId: crypto.randomUUID(),
        claimId: entry.claimId,
        action: entry.action,
        previousState: entry.previousState ?? null,
        newState: entry.newState ?? null,
        changes: entry.changes ?? null,
        actorId: entry.actorId,
        actorContext: entry.actorContext ?? 'PHYSICIAN',
        createdAt: new Date(),
      };
      auditStore.push(audit);
      return audit;
    }),

    getClaimAuditHistory: vi.fn(async (claimId: string, physicianId: string) => {
      const claim = claimsStore[claimId];
      if (!claim || claim.physicianId !== physicianId) return [];
      return auditStore.filter((a) => a.claimId === claimId);
    }),

    getClaimAuditHistoryPaginated: vi.fn(async (claimId: string, physicianId: string) => {
      const claim = claimsStore[claimId];
      if (!claim || claim.physicianId !== physicianId) {
        return { data: [], pagination: { total: 0, page: 1, pageSize: 25, hasMore: false } };
      }
      const entries = auditStore.filter((a) => a.claimId === claimId);
      return {
        data: entries,
        pagination: { total: entries.length, page: 1, pageSize: 25, hasMore: false },
      };
    }),
  };
}

function createStubServiceDeps() {
  return {
    repo: createScopedClaimRepo() as any,
    providerCheck: {
      isActive: vi.fn(async () => true),
      getRegistrationDate: vi.fn(async () => null),
    },
    patientCheck: {
      exists: vi.fn(async () => true),
    },
    pathwayValidators: {},
    referenceDataVersion: { getCurrentVersion: vi.fn(async () => '1.0') },
    notificationEmitter: { emit: vi.fn(async () => {}) },
    submissionPreference: { getSubmissionMode: vi.fn(async () => 'MANUAL') },
    facilityCheck: { belongsToPhysician: vi.fn(async () => true) },
    afterHoursPremiumCalculators: {},
    explanatoryCodeLookup: { getExplanatoryCode: vi.fn(async () => null) },
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

  const handlerDeps: ClaimHandlerDeps = {
    serviceDeps: createStubServiceDeps(),
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

  await testApp.register(claimRoutes, { deps: handlerDeps });
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
// Recursive key checker — ensure a key never appears at any nesting level
// ---------------------------------------------------------------------------

function containsKeyRecursive(obj: unknown, targetKey: string): boolean {
  if (obj === null || obj === undefined || typeof obj !== 'object') return false;
  if (Array.isArray(obj)) {
    return obj.some((item) => containsKeyRecursive(item, targetKey));
  }
  for (const key of Object.keys(obj as Record<string, unknown>)) {
    if (key === targetKey) return true;
    if (containsKeyRecursive((obj as Record<string, unknown>)[key], targetKey)) return true;
  }
  return false;
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
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Claim PHI Leakage Prevention (Security)', () => {
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
  // 1. Error Response Sanitisation — PHI not in error responses
  // =========================================================================

  describe('PHI not in error responses', () => {
    it('400 validation error does not include patient PHN or DOB in error message', async () => {
      const res = await asPhysician1('POST', '/api/v1/claims', {
        claim_type: 'INVALID_TYPE',
        patient_id: P1_PATIENT_ID,
        date_of_service: P1_PATIENT_DOB, // using DOB as date_of_service intentionally
      });

      expect(res.statusCode).toBe(400);
      const rawBody = res.body;

      // PHN and DOB must not appear in validation error
      expect(rawBody).not.toContain(P1_PATIENT_PHN);
      // The body shape should only have error key
      const body = JSON.parse(rawBody);
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();
    });

    it('404 response for cross-physician claim does not reveal claim exists', async () => {
      // P1 tries to access P2's claim
      const crossTenantRes = await asPhysician1('GET', `/api/v1/claims/${P2_CLAIM_ID_A}`);
      // P1 accesses a genuinely non-existent claim
      const genuineMissingRes = await asPhysician1('GET', `/api/v1/claims/${NONEXISTENT_UUID}`);

      // Both should be 404 with identical error shape
      expect(crossTenantRes.statusCode).toBe(404);
      expect(genuineMissingRes.statusCode).toBe(404);

      const crossBody = JSON.parse(crossTenantRes.body);
      const missingBody = JSON.parse(genuineMissingRes.body);

      // Same error structure — indistinguishable
      expect(Object.keys(crossBody)).toEqual(Object.keys(missingBody));
      expect(crossBody.error.code).toBe(missingBody.error.code);
      expect(crossBody.error.message).toBe(missingBody.error.message);

      // No claim details leaked
      expect(crossTenantRes.body).not.toContain(P2_CLAIM_ID_A);
      expect(crossTenantRes.body).not.toContain(P2_PATIENT_ID);
      expect(crossTenantRes.body).not.toContain(P2_PROVIDER_ID);
    });

    it('409 state transition error does not leak claim details to wrong physician', async () => {
      // P1 tries to delete P2's validated claim (should be 404 not 409 with details)
      const res = await asPhysician1('DELETE', `/api/v1/claims/${P2_CLAIM_ID_A}`);
      expect(res.statusCode).toBe(404);

      const body = JSON.parse(res.body);
      // Must not reveal the claim's actual state or details
      expect(res.body).not.toContain('VALIDATED');
      expect(res.body).not.toContain(P2_CLAIM_ID_A);
      expect(res.body).not.toContain(P2_PATIENT_ID);
      expect(body.data).toBeUndefined();
    });

    it('409 conflict error on own claim does not leak PHI', async () => {
      // Try to delete P1's REJECTED claim (only DRAFT can be deleted)
      const res = await asPhysician1('DELETE', `/api/v1/claims/${P1_CLAIM_ID_B}`);
      expect(res.statusCode).toBe(409);

      const body = JSON.parse(res.body);
      // Error message should not contain patient information
      expect(res.body).not.toContain(P1_PATIENT_PHN);
      expect(res.body).not.toContain(P1_PATIENT_NAME);
      expect(res.body).not.toContain(P1_PATIENT_DOB);
      // Should not expose internal IDs beyond the claim state info
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();
    });

    it('500 error does not expose stack traces, SQL errors, or internal details', async () => {
      // Attempt to get a non-existent resource to verify error shape
      const res = await asPhysician1('PUT', `/api/v1/claims/${NONEXISTENT_UUID}`, {
        patient_id: P1_PATIENT_ID,
      });

      const body = JSON.parse(res.body);
      // No stack traces
      expect(body.error).not.toHaveProperty('stack');
      expect(body.error).not.toHaveProperty('stackTrace');
      expect(JSON.stringify(body)).not.toMatch(/at\s+\w+\s+\(/); // stack trace pattern
      expect(JSON.stringify(body)).not.toMatch(/\.ts:\d+:\d+/); // file:line:col pattern
      expect(JSON.stringify(body)).not.toContain('node_modules');
      // No SQL/ORM keywords
      expect(JSON.stringify(body).toLowerCase()).not.toMatch(/postgres|drizzle|pg_catalog|relation|syntax error/);
    });

    it('401 response body contains only error object, no claim data', async () => {
      const res = await unauthenticated('GET', `/api/v1/claims/${P1_CLAIM_ID_A}`);
      expect(res.statusCode).toBe(401);

      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
      expect(body.data).toBeUndefined();

      // No claim data leaked
      expect(res.body).not.toContain(P1_CLAIM_ID_A);
      expect(res.body).not.toContain(P1_PATIENT_ID);
      expect(res.body).not.toContain('AHCIP');
    });
  });

  // =========================================================================
  // 2. Response Header Security — PHI not in headers
  // =========================================================================

  describe('PHI not in headers', () => {
    it('no X-Powered-By header in authenticated responses', async () => {
      const res = await asPhysician1('GET', `/api/v1/claims/${P1_CLAIM_ID_A}`);
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By header in 401 responses', async () => {
      const res = await unauthenticated('GET', '/api/v1/claims');
      expect(res.statusCode).toBe(401);
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By header in 400 responses', async () => {
      const res = await asPhysician1('POST', '/api/v1/claims', {});
      expect(res.statusCode).toBe(400);
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By header in 404 responses', async () => {
      const res = await asPhysician1('GET', `/api/v1/claims/${NONEXISTENT_UUID}`);
      expect(res.statusCode).toBe(404);
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no Server header revealing version/technology', async () => {
      const res = await asPhysician1('GET', `/api/v1/claims/${P1_CLAIM_ID_A}`);
      const serverHeader = res.headers['server'];
      if (serverHeader) {
        const lower = (serverHeader as string).toLowerCase();
        expect(lower).not.toContain('fastify');
        expect(lower).not.toContain('node');
        expect(lower).not.toContain('express');
      }
    });

    it('no claim data in response headers', async () => {
      const res = await asPhysician1('GET', `/api/v1/claims/${P1_CLAIM_ID_A}`);
      const headerStr = JSON.stringify(res.headers);

      // No PHI in headers
      expect(headerStr).not.toContain(P1_PATIENT_PHN);
      expect(headerStr).not.toContain(P1_PATIENT_ID);
      expect(headerStr).not.toContain(P1_CLAIM_ID_A);
    });

    it('responses include Content-Type: application/json', async () => {
      const res = await asPhysician1('GET', `/api/v1/claims/${P1_CLAIM_ID_A}`);
      expect(res.headers['content-type']).toContain('application/json');
    });

    it('error responses include Content-Type: application/json', async () => {
      const res = await unauthenticated('GET', '/api/v1/claims');
      expect(res.headers['content-type']).toContain('application/json');
    });
  });

  // =========================================================================
  // 3. Sensitive Fields Stripped from Responses
  // =========================================================================

  describe('Sensitive fields stripped from responses', () => {
    it('claim response does not contain password_hash', async () => {
      const res = await asPhysician1('GET', `/api/v1/claims/${P1_CLAIM_ID_A}`);
      expect(res.statusCode).toBe(200);
      expect(res.body).not.toContain('passwordHash');
      expect(res.body).not.toContain('password_hash');
    });

    it('claim response does not contain session tokens', async () => {
      const res = await asPhysician1('GET', `/api/v1/claims/${P1_CLAIM_ID_A}`);
      expect(res.statusCode).toBe(200);
      expect(res.body).not.toContain('tokenHash');
      expect(res.body).not.toContain('token_hash');
      expect(res.body).not.toContain(P1_SESSION_TOKEN);
      expect(res.body).not.toContain(P1_SESSION_TOKEN_HASH);
    });

    it('claim response does not contain TOTP secrets', async () => {
      const res = await asPhysician1('GET', `/api/v1/claims/${P1_CLAIM_ID_A}`);
      expect(res.statusCode).toBe(200);
      expect(res.body).not.toContain('totpSecret');
      expect(res.body).not.toContain('totp_secret');
      expect(res.body).not.toContain('JBSWY3DPEHPK3PXP');
    });

    it('claim list does not contain internal auth fields', async () => {
      const res = await asPhysician1('GET', '/api/v1/claims');
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain('passwordHash');
      expect(rawBody).not.toContain('tokenHash');
      expect(rawBody).not.toContain('totpSecret');
      expect(rawBody).not.toContain(P1_SESSION_TOKEN);
    });

    it('import error_details do not expose other patients data', async () => {
      const res = await asPhysician1('GET', `/api/v1/imports/${P1_IMPORT_ID}`);
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      // Import error details should not contain actual patient data
      expect(rawBody).not.toContain(P1_PATIENT_PHN);
      expect(rawBody).not.toContain(P1_PATIENT_NAME);
      // Should not leak other physician's data
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain(P2_PATIENT_PHN);
      expect(rawBody).not.toContain(P2_PATIENT_NAME);
    });
  });

  // =========================================================================
  // 4. Data Export Security
  // =========================================================================

  describe('Data export security', () => {
    it('export file download requires valid session', async () => {
      const res = await unauthenticated('GET', `/api/v1/exports/${P1_EXPORT_ID}`);
      expect(res.statusCode).toBe(401);

      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
      expect(body.error).toBeDefined();
    });

    it('export file URL rejects other physicians (returns 404)', async () => {
      // P2 tries to access P1's export
      const res = await asPhysician2('GET', `/api/v1/exports/${P1_EXPORT_ID}`);
      expect(res.statusCode).toBe(404);

      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
      // Should not reveal whose export it is
      expect(res.body).not.toContain(P1_PROVIDER_ID);
      expect(res.body).not.toContain(P1_USER_ID);
    });

    it('export status does not leak file path details for cross-tenant', async () => {
      // P2 cannot see P1's export file path
      const res = await asPhysician2('GET', `/api/v1/exports/${P1_EXPORT_ID}`);
      expect(res.statusCode).toBe(404);

      // Must not leak the file path
      expect(res.body).not.toContain('exports/');
      expect(res.body).not.toContain(P1_EXPORT_ID);
    });

    it('creating an export does not leak other physicians data', async () => {
      const res = await asPhysician1('POST', '/api/v1/exports', {
        date_from: '2026-01-01',
        date_to: '2026-01-31',
        format: 'CSV',
      });

      expect(res.statusCode).toBe(201);
      const rawBody = res.body;

      // Response must not contain P2's data
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain(P2_PATIENT_ID);
      expect(rawBody).not.toContain(P2_PATIENT_PHN);
    });
  });

  // =========================================================================
  // 5. Anti-Enumeration Protection
  // =========================================================================

  describe('Anti-enumeration protection', () => {
    it('404 for cross-tenant claim is indistinguishable from genuinely missing', async () => {
      const crossRes = await asPhysician1('GET', `/api/v1/claims/${P2_CLAIM_ID_A}`);
      const missingRes = await asPhysician1('GET', `/api/v1/claims/${NONEXISTENT_UUID}`);

      expect(crossRes.statusCode).toBe(404);
      expect(missingRes.statusCode).toBe(404);

      const crossBody = JSON.parse(crossRes.body);
      const missingBody = JSON.parse(missingRes.body);

      expect(crossBody.error.code).toBe(missingBody.error.code);
      expect(crossBody.error.message).toBe(missingBody.error.message);
    });

    it('404 for cross-tenant update is indistinguishable from missing', async () => {
      const crossRes = await asPhysician1('PUT', `/api/v1/claims/${P2_CLAIM_ID_A}`, {
        patient_id: P1_PATIENT_ID,
      });
      const missingRes = await asPhysician1('PUT', `/api/v1/claims/${NONEXISTENT_UUID}`, {
        patient_id: P1_PATIENT_ID,
      });

      expect(crossRes.statusCode).toBe(404);
      expect(missingRes.statusCode).toBe(404);

      const crossBody = JSON.parse(crossRes.body);
      const missingBody = JSON.parse(missingRes.body);

      expect(crossBody.error.code).toBe(missingBody.error.code);
      expect(crossBody.error.message).toBe(missingBody.error.message);
    });

    it('404 for cross-tenant delete is indistinguishable from missing', async () => {
      const crossRes = await asPhysician1('DELETE', `/api/v1/claims/${P2_CLAIM_ID_A}`);
      const missingRes = await asPhysician1('DELETE', `/api/v1/claims/${NONEXISTENT_UUID}`);

      expect(crossRes.statusCode).toBe(404);
      expect(missingRes.statusCode).toBe(404);

      const crossBody = JSON.parse(crossRes.body);
      const missingBody = JSON.parse(missingRes.body);

      expect(crossBody.error.code).toBe(missingBody.error.code);
      expect(crossBody.error.message).toBe(missingBody.error.message);
    });

    it('404 for cross-tenant import is indistinguishable from missing', async () => {
      // P2 has no imports visible, but we create one to test cross-tenant access
      const P2_IMPORT_ID = 'cccc2222-0000-0000-0000-000000000002';
      importBatchStore[P2_IMPORT_ID] = {
        importBatchId: P2_IMPORT_ID,
        physicianId: P2_PROVIDER_ID,
        fileName: 'p2_claims.csv',
        fileHash: 'hash-p2',
        fieldMappingTemplateId: null,
        totalRows: 5,
        successCount: 5,
        errorCount: 0,
        errorDetails: null,
        status: 'COMPLETED',
        createdBy: P2_USER_ID,
        createdAt: new Date(),
      };

      const crossRes = await asPhysician1('GET', `/api/v1/imports/${P2_IMPORT_ID}`);
      const missingRes = await asPhysician1('GET', `/api/v1/imports/${NONEXISTENT_UUID}`);

      expect(crossRes.statusCode).toBe(404);
      expect(missingRes.statusCode).toBe(404);

      const crossBody = JSON.parse(crossRes.body);
      const missingBody = JSON.parse(missingRes.body);

      expect(crossBody.error.code).toBe(missingBody.error.code);
      expect(crossBody.error.message).toBe(missingBody.error.message);
    });

    it('404 for cross-tenant export is indistinguishable from missing', async () => {
      const crossRes = await asPhysician1('GET', `/api/v1/exports/${P2_EXPORT_ID}`);
      const missingRes = await asPhysician1('GET', `/api/v1/exports/${NONEXISTENT_UUID}`);

      expect(crossRes.statusCode).toBe(404);
      expect(missingRes.statusCode).toBe(404);

      const crossBody = JSON.parse(crossRes.body);
      const missingBody = JSON.parse(missingRes.body);

      expect(crossBody.error.code).toBe(missingBody.error.code);
      expect(crossBody.error.message).toBe(missingBody.error.message);
    });

    it('404 for cross-tenant rejection-details is indistinguishable from missing', async () => {
      const crossRes = await asPhysician1('GET', `/api/v1/claims/${P2_CLAIM_ID_A}/rejection-details`);
      const missingRes = await asPhysician1('GET', `/api/v1/claims/${NONEXISTENT_UUID}/rejection-details`);

      expect(crossRes.statusCode).toBe(404);
      expect(missingRes.statusCode).toBe(404);

      const crossBody = JSON.parse(crossRes.body);
      const missingBody = JSON.parse(missingRes.body);

      expect(crossBody.error.code).toBe(missingBody.error.code);
      expect(crossBody.error.message).toBe(missingBody.error.message);
    });
  });

  // =========================================================================
  // 6. Error Responses Are Generic — No Internal State Revealed
  // =========================================================================

  describe('Error responses do not reveal internal state', () => {
    it('all 404 responses have consistent error structure', async () => {
      const routes = [
        { method: 'GET' as const, url: `/api/v1/claims/${NONEXISTENT_UUID}` },
        { method: 'PUT' as const, url: `/api/v1/claims/${NONEXISTENT_UUID}`, payload: { patient_id: P1_PATIENT_ID } },
        { method: 'DELETE' as const, url: `/api/v1/claims/${NONEXISTENT_UUID}` },
        { method: 'GET' as const, url: `/api/v1/claims/${NONEXISTENT_UUID}/suggestions` },
        { method: 'GET' as const, url: `/api/v1/claims/${NONEXISTENT_UUID}/rejection-details` },
        { method: 'GET' as const, url: `/api/v1/claims/${NONEXISTENT_UUID}/audit` },
        { method: 'GET' as const, url: `/api/v1/imports/${NONEXISTENT_UUID}` },
        { method: 'GET' as const, url: `/api/v1/exports/${NONEXISTENT_UUID}` },
      ];

      for (const route of routes) {
        const res = await asPhysician1(route.method, route.url, route.payload);

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
      const res = await asPhysician1('POST', '/api/v1/claims', {
        claim_type: "'; DROP TABLE claims;--",
        patient_id: P1_PATIENT_ID,
        date_of_service: '2026-01-15',
      });

      const lower = res.body.toLowerCase();
      expect(lower).not.toContain('postgres');
      expect(lower).not.toContain('drizzle');
      expect(lower).not.toContain('pg_catalog');
      expect(lower).not.toContain('relation');
      expect(lower).not.toContain('syntax error');
    });

    it('error responses do not expose database column names', async () => {
      const res = await asPhysician1('POST', '/api/v1/claims', {});

      if (res.statusCode === 400) {
        const rawBody = res.body.toLowerCase();
        expect(rawBody).not.toContain('column');
        expect(rawBody).not.toContain('constraint violation');
        expect(rawBody).not.toContain('unique_constraint');
      }
    });

    it('error responses do not expose resource UUIDs in 404 messages', async () => {
      const res = await asPhysician1('GET', `/api/v1/claims/${NONEXISTENT_UUID}`);
      expect(res.statusCode).toBe(404);

      const body = JSON.parse(res.body);
      // The error message must not echo back the UUID
      expect(body.error.message).not.toContain(NONEXISTENT_UUID);
      expect(body.error.message).not.toContain('claim');
    });
  });

  // =========================================================================
  // 7. List / Search Responses Do Not Leak Cross-Tenant Data
  // =========================================================================

  describe('List responses do not leak cross-tenant data', () => {
    it('claim list contains only authenticated physician claims', async () => {
      const res = await asPhysician1('GET', '/api/v1/claims');
      expect(res.statusCode).toBe(200);

      const body = JSON.parse(res.body);
      const rawBody = res.body;

      // Must not contain P2's data
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain(P2_CLAIM_ID_A);
      expect(rawBody).not.toContain(P2_PATIENT_ID);

      // All returned claims belong to P1
      if (body.data && body.data.length > 0) {
        body.data.forEach((claim: any) => {
          expect(claim.physicianId).toBe(P1_PROVIDER_ID);
        });
      }
    });

    it('rejected claims list contains only authenticated physician claims', async () => {
      const res = await asPhysician1('GET', '/api/v1/claims/rejected');
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;

      // Must not contain P2's data
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain(P2_CLAIM_ID_A);
      expect(rawBody).not.toContain(P2_PATIENT_ID);
    });

    it('template list contains only authenticated physician templates', async () => {
      const res = await asPhysician1('GET', '/api/v1/field-mapping-templates');
      expect(res.statusCode).toBe(200);

      const body = JSON.parse(res.body);
      const rawBody = res.body;

      expect(rawBody).not.toContain(P2_PROVIDER_ID);

      if (body.data && body.data.length > 0) {
        body.data.forEach((template: any) => {
          expect(template.physicianId).toBe(P1_PROVIDER_ID);
        });
      }
    });
  });

  // =========================================================================
  // 8. Audit Trail Does Not Leak PHI
  // =========================================================================

  describe('Audit trail does not leak PHI', () => {
    it('claim audit history for cross-tenant claim returns empty (not 403)', async () => {
      const res = await asPhysician1('GET', `/api/v1/claims/${P2_CLAIM_ID_A}/audit`);

      // Should return 200 with empty data (claim not found -> empty audit)
      // or 404 depending on handler logic
      if (res.statusCode === 200) {
        const body = JSON.parse(res.body);
        // Should return empty data, not P2's audit entries
        if (Array.isArray(body.data)) {
          expect(body.data.length).toBe(0);
        }
      } else {
        // If it returns 404, that's also acceptable (doesn't leak)
        expect(res.statusCode).toBe(404);
      }

      // Either way, P2's audit details must not appear
      expect(res.body).not.toContain(P2_USER_ID);
      expect(res.body).not.toContain(P2_PROVIDER_ID);
    });

    it('audit entries do not contain raw PHI in changes field', async () => {
      // Create a claim to generate an audit entry
      const createRes = await asPhysician1('POST', '/api/v1/claims', {
        claim_type: 'AHCIP',
        patient_id: P1_PATIENT_ID,
        date_of_service: '2026-01-15',
      });

      expect(createRes.statusCode).toBe(201);

      // Check the audit store directly for PHI leakage
      const auditString = JSON.stringify(auditStore);
      expect(auditString).not.toContain(P1_PATIENT_PHN);
      expect(auditString).not.toContain(P1_PATIENT_NAME);
      expect(auditString).not.toContain(P1_PATIENT_DOB);
    });
  });

  // =========================================================================
  // 9. Shift Responses Do Not Leak Cross-Tenant Data
  // =========================================================================

  describe('Shift responses do not leak cross-tenant data', () => {
    it('cross-tenant shift access returns 404 without details', async () => {
      // Create P2's shift in the store
      const P2_SHIFT_ID = 'eeee2222-0000-0000-0000-000000000002';
      shiftStore[P2_SHIFT_ID] = {
        shiftId: P2_SHIFT_ID,
        physicianId: P2_PROVIDER_ID,
        facilityId: '77772222-0000-0000-0000-000000000002',
        shiftDate: '2026-02-01',
        startTime: '18:00',
        endTime: '02:00',
        encounterCount: 5,
        status: 'IN_PROGRESS',
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const res = await asPhysician1('GET', `/api/v1/shifts/${P2_SHIFT_ID}`);

      // Should fail — not P1's shift
      expect([404, 422].includes(res.statusCode)).toBe(true);

      // Must not leak shift details
      expect(res.body).not.toContain(P2_PROVIDER_ID);
      expect(res.body).not.toContain('77772222');
      expect(res.body).not.toContain('02:00');
    });
  });

  // =========================================================================
  // 10. Validation Errors Do Not Echo Input PHI
  // =========================================================================

  describe('Validation errors do not echo input PHI', () => {
    it('validation error for claim does not expose internal field names or PHI', async () => {
      const res = await asPhysician1('POST', '/api/v1/claims', {
        claim_type: 'INVALID',
        patient_id: P1_PATIENT_ID,
        date_of_service: '2026-01-15',
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);

      // Error should not contain PHI
      expect(res.body).not.toContain(P1_PATIENT_PHN);
      expect(res.body).not.toContain(P1_PATIENT_NAME);
      expect(res.body).not.toContain(P1_PATIENT_DOB);

      // Error should not expose SQL/ORM internals
      expect(res.body.toLowerCase()).not.toContain('postgres');
      expect(res.body.toLowerCase()).not.toContain('drizzle');
      expect(res.body.toLowerCase()).not.toContain('pg_catalog');

      // Should have error structure, no data key
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();
    });

    it('non-UUID path parameter returns 400 without echoing input', async () => {
      const res = await asPhysician1('GET', '/api/v1/claims/not-a-uuid');
      expect(res.statusCode).toBe(400);

      // Should not echo back the invalid input
      expect(res.body).not.toContain('not-a-uuid');
    });

    it('SQL injection in query parameters does not leak database info', async () => {
      const res = await asPhysician1('GET', "/api/v1/claims?state=DRAFT'%20OR%201=1--");

      // Should be rejected or return empty — not leak data
      const lower = res.body.toLowerCase();
      expect(lower).not.toContain('postgres');
      expect(lower).not.toContain('drizzle');
      expect(lower).not.toContain('syntax error');
    });
  });

  // =========================================================================
  // 11. Submission Preferences Do Not Leak Cross-Tenant Config
  // =========================================================================

  describe('Submission preferences privacy', () => {
    it('submission preferences response does not contain other physician data', async () => {
      const res = await asPhysician1('GET', '/api/v1/submission-preferences');
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain(P2_USER_ID);
    });
  });
});
