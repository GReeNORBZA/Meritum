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
// Fixed test identities — Two isolated physicians + delegates
// ---------------------------------------------------------------------------

// Physician 1 — "our" physician
const P1_SESSION_TOKEN = randomBytes(32).toString('hex');
const P1_SESSION_TOKEN_HASH = hashToken(P1_SESSION_TOKEN);
const P1_USER_ID = '11111111-1111-0000-0000-000000000001';
const P1_PROVIDER_ID = P1_USER_ID; // 1:1 mapping
const P1_SESSION_ID = '11111111-1111-0000-0000-000000000011';

// Physician 2 — "other" physician (attacker perspective)
const P2_SESSION_TOKEN = randomBytes(32).toString('hex');
const P2_SESSION_TOKEN_HASH = hashToken(P2_SESSION_TOKEN);
const P2_USER_ID = '22222222-2222-0000-0000-000000000002';
const P2_PROVIDER_ID = P2_USER_ID;
const P2_SESSION_ID = '22222222-2222-0000-0000-000000000022';

// Delegate linked to Physician 1 only (with CLAIM_VIEW only)
const DELEGATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_SESSION_TOKEN_HASH = hashToken(DELEGATE_SESSION_TOKEN);
const DELEGATE_USER_ID = '33333333-3333-0000-0000-000000000003';
const DELEGATE_SESSION_ID = '33333333-3333-0000-0000-000000000033';
const DELEGATE_LINKAGE_ID = '44444444-4444-0000-0000-000000000044';

// Dual delegate — linked to Physician 1 context currently
const DUAL_DELEGATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DUAL_DELEGATE_SESSION_TOKEN_HASH = hashToken(DUAL_DELEGATE_SESSION_TOKEN);
const DUAL_DELEGATE_USER_ID = '55555555-5555-0000-0000-000000000005';
const DUAL_DELEGATE_SESSION_ID = '55555555-5555-0000-0000-000000000055';

// ---------------------------------------------------------------------------
// Test data IDs — resources owned by each physician
// ---------------------------------------------------------------------------

// Physician 1's claims
const P1_CLAIM_ID_A = 'aaaa1111-0000-0000-0000-000000000001';
const P1_CLAIM_ID_B = 'aaaa1111-0000-0000-0000-000000000002';
const P1_PATIENT_ID = 'bbbb1111-0000-0000-0000-000000000001';

// Physician 2's claims
const P2_CLAIM_ID_A = 'aaaa2222-0000-0000-0000-000000000001';
const P2_CLAIM_ID_B = 'aaaa2222-0000-0000-0000-000000000002';
const P2_PATIENT_ID = 'bbbb2222-0000-0000-0000-000000000001';

// Import batch IDs
const P1_IMPORT_ID = 'cccc1111-0000-0000-0000-000000000001';
const P2_IMPORT_ID = 'cccc2222-0000-0000-0000-000000000002';

// Template IDs
const P1_TEMPLATE_ID = 'dddd1111-0000-0000-0000-000000000001';
const P2_TEMPLATE_ID = 'dddd2222-0000-0000-0000-000000000002';

// Shift IDs
const P1_SHIFT_ID = 'eeee1111-0000-0000-0000-000000000001';
const P2_SHIFT_ID = 'eeee2222-0000-0000-0000-000000000002';

// Export IDs
const P1_EXPORT_ID = 'ffff1111-0000-0000-0000-000000000001';
const P2_EXPORT_ID = 'ffff2222-0000-0000-0000-000000000002';

// Facility ID for shifts
const P1_FACILITY_ID = '77771111-0000-0000-0000-000000000001';

// Suggestion IDs
const P1_SUGGESTION_ID = 'aabb1111-0000-0000-0000-000000000001';
const P2_SUGGESTION_ID = 'aabb2222-0000-0000-0000-000000000002';

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
  // Clear stores
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
    aiCoachSuggestions: {
      suggestions: [
        { id: P1_SUGGESTION_ID, field: 'healthServiceCode', suggestedValue: '03.04A', status: 'PENDING' },
      ],
    },
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
    validationResult: { errors: [{ check: 'S1', message: 'Test error' }], warnings: [], info: [], passed: false },
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
    aiCoachSuggestions: {
      suggestions: [
        { id: P2_SUGGESTION_ID, field: 'modifier1', suggestedValue: 'ANES', status: 'PENDING' },
      ],
    },
    duplicateAlert: null,
    flags: null,
    createdBy: P2_USER_ID,
    updatedBy: P2_USER_ID,
    deletedAt: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  };
  claimsStore[P2_CLAIM_ID_B] = {
    claimId: P2_CLAIM_ID_B,
    physicianId: P2_PROVIDER_ID,
    patientId: P2_PATIENT_ID,
    claimType: 'WCB',
    state: 'DRAFT',
    dateOfService: '2026-02-05',
    submissionDeadline: '2026-05-06',
    importSource: 'MANUAL',
    importBatchId: null,
    shiftId: null,
    isClean: true,
    validationResult: null,
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
    errorDetails: null,
    status: 'COMPLETED',
    createdBy: P1_USER_ID,
    createdAt: new Date(),
  };
  importBatchStore[P2_IMPORT_ID] = {
    importBatchId: P2_IMPORT_ID,
    physicianId: P2_PROVIDER_ID,
    fileName: 'claims_p2.csv',
    fileHash: 'hash-p2-claims',
    fieldMappingTemplateId: null,
    totalRows: 5,
    successCount: 5,
    errorCount: 0,
    errorDetails: null,
    status: 'COMPLETED',
    createdBy: P2_USER_ID,
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
  templateStore[P2_TEMPLATE_ID] = {
    templateId: P2_TEMPLATE_ID,
    physicianId: P2_PROVIDER_ID,
    name: 'P2 Template',
    emrType: 'WOLF',
    mappings: [{ source_column: 'col2', target_field: 'dateOfService' }],
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

  // --- Audit entries ---
  auditStore.push({
    auditId: crypto.randomUUID(),
    claimId: P1_CLAIM_ID_A,
    action: 'CREATED',
    previousState: null,
    newState: 'DRAFT',
    changes: null,
    actorId: P1_USER_ID,
    actorContext: 'PHYSICIAN',
    createdAt: new Date(),
  });
  auditStore.push({
    auditId: crypto.randomUUID(),
    claimId: P2_CLAIM_ID_A,
    action: 'CREATED',
    previousState: null,
    newState: 'DRAFT',
    changes: null,
    actorId: P2_USER_ID,
    actorContext: 'PHYSICIAN',
    createdAt: new Date(),
  });
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

    countClaimsByState: vi.fn(async (physicianId: string) => {
      const grouped: Record<string, number> = {};
      Object.values(claimsStore)
        .filter((c) => c.physicianId === physicianId && !c.deletedAt)
        .forEach((c) => {
          grouped[c.state] = (grouped[c.state] || 0) + 1;
        });
      return Object.entries(grouped).map(([state, count]) => ({ state, count }));
    }),

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

    updateFlags: vi.fn(async (claimId: string, physicianId: string, flags: any) => {
      const claim = claimsStore[claimId];
      if (!claim || claim.physicianId !== physicianId) return undefined;
      claimsStore[claimId] = { ...claim, flags, updatedAt: new Date() };
      return claimsStore[claimId];
    }),

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
      // Verify claim ownership first
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
        error: { code: 'VALIDATION_ERROR', message: 'Validation failed', details: error.validation },
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

function asDelegate(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${DELEGATE_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function asDualDelegateP1(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${DUAL_DELEGATE_SESSION_TOKEN}` },
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

  // Delegate linked to Physician 1 only (with CLAIM_VIEW + CLAIM_EDIT)
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
      permissions: ['CLAIM_VIEW', 'CLAIM_EDIT', 'CLAIM_CREATE', 'CLAIM_DELETE', 'CLAIM_SUBMIT'],
      linkageId: DELEGATE_LINKAGE_ID,
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

  // Dual delegate — linked to Physician 1 context currently
  users.push({
    userId: DUAL_DELEGATE_USER_ID,
    email: 'dual-delegate@example.com',
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    role: 'DELEGATE',
    subscriptionStatus: 'TRIAL',
    delegateContext: {
      delegateUserId: DUAL_DELEGATE_USER_ID,
      physicianProviderId: P1_PROVIDER_ID, // Currently in P1 context
      permissions: ['CLAIM_VIEW', 'CLAIM_EDIT', 'CLAIM_CREATE', 'CLAIM_DELETE', 'CLAIM_SUBMIT'],
      linkageId: '66666666-6666-0000-0000-000000000066',
    },
  });
  sessions.push({
    sessionId: DUAL_DELEGATE_SESSION_ID,
    userId: DUAL_DELEGATE_USER_ID,
    tokenHash: DUAL_DELEGATE_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.5',
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

describe('Claim Physician Tenant Isolation — MOST CRITICAL (Security)', () => {
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
  // 1. Claim Record Isolation — GET by ID
  // =========================================================================

  describe('Claim record isolation — GET by ID', () => {
    it('physician1 can retrieve own claim via GET /api/v1/claims/:id', async () => {
      const res = await asPhysician1('GET', `/api/v1/claims/${P1_CLAIM_ID_A}`);
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.claimId).toBe(P1_CLAIM_ID_A);
      expect(body.data.physicianId).toBe(P1_PROVIDER_ID);
    });

    it('physician2 can retrieve own claim via GET /api/v1/claims/:id', async () => {
      const res = await asPhysician2('GET', `/api/v1/claims/${P2_CLAIM_ID_A}`);
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.claimId).toBe(P2_CLAIM_ID_A);
      expect(body.data.physicianId).toBe(P2_PROVIDER_ID);
    });

    it('physician1 CANNOT retrieve physician2 claim — returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/claims/${P2_CLAIM_ID_A}`);
      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();
    });

    it('physician2 CANNOT retrieve physician1 claim — returns 404', async () => {
      const res = await asPhysician2('GET', `/api/v1/claims/${P1_CLAIM_ID_A}`);
      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();
    });

    it('cross-tenant GET response does not leak claim details', async () => {
      const res = await asPhysician1('GET', `/api/v1/claims/${P2_CLAIM_ID_A}`);
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_CLAIM_ID_A);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain(P2_PATIENT_ID);
    });
  });

  // =========================================================================
  // 2. Claim Record Isolation — LIST
  // =========================================================================

  describe('Claim record isolation — LIST', () => {
    it('physician1 listing claims returns only physician1 claims', async () => {
      const res = await asPhysician1('GET', '/api/v1/claims');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBeGreaterThan(0);
      body.data.forEach((claim: any) => {
        expect(claim.physicianId).toBe(P1_PROVIDER_ID);
      });
    });

    it('physician2 listing claims returns only physician2 claims', async () => {
      const res = await asPhysician2('GET', '/api/v1/claims');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBeGreaterThan(0);
      body.data.forEach((claim: any) => {
        expect(claim.physicianId).toBe(P2_PROVIDER_ID);
      });
    });

    it('physician1 claim list never contains physician2 claim IDs', async () => {
      const res = await asPhysician1('GET', '/api/v1/claims');
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_CLAIM_ID_A);
      expect(rawBody).not.toContain(P2_CLAIM_ID_B);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
    });
  });

  // =========================================================================
  // 3. Claim Record Isolation — UPDATE
  // =========================================================================

  describe('Claim record isolation — UPDATE', () => {
    it('physician1 CANNOT update physician2 claim via PUT — returns 404', async () => {
      const res = await asPhysician1('PUT', `/api/v1/claims/${P2_CLAIM_ID_B}`, {
        date_of_service: '2026-03-01',
      });
      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();
    });

    it('physician2 CANNOT update physician1 claim — returns 404', async () => {
      const res = await asPhysician2('PUT', `/api/v1/claims/${P1_CLAIM_ID_A}`, {
        date_of_service: '2026-03-01',
      });
      expect(res.statusCode).toBe(404);
    });

    it('physician2 claim data remains unchanged after physician1 update attempt', async () => {
      await asPhysician1('PUT', `/api/v1/claims/${P2_CLAIM_ID_B}`, {
        date_of_service: '2026-03-01',
      });
      const res = await asPhysician2('GET', `/api/v1/claims/${P2_CLAIM_ID_B}`);
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.dateOfService).toBe('2026-02-05');
    });
  });

  // =========================================================================
  // 4. Claim Record Isolation — DELETE
  // =========================================================================

  describe('Claim record isolation — DELETE', () => {
    it('physician1 CANNOT delete physician2 draft claim — returns 404', async () => {
      const res = await asPhysician1('DELETE', `/api/v1/claims/${P2_CLAIM_ID_B}`);
      expect(res.statusCode).toBe(404);
    });

    it('physician2 CANNOT delete physician1 draft claim — returns 404', async () => {
      const res = await asPhysician2('DELETE', `/api/v1/claims/${P1_CLAIM_ID_A}`);
      expect(res.statusCode).toBe(404);
    });

    it('physician2 draft claim remains after physician1 delete attempt', async () => {
      await asPhysician1('DELETE', `/api/v1/claims/${P2_CLAIM_ID_B}`);
      const res = await asPhysician2('GET', `/api/v1/claims/${P2_CLAIM_ID_B}`);
      expect(res.statusCode).toBe(200);
      expect(JSON.parse(res.body).data.state).toBe('DRAFT');
    });
  });

  // =========================================================================
  // 5. State Transition Isolation — validate, queue, write-off
  // =========================================================================

  describe('State transition isolation', () => {
    it('physician1 CANNOT validate physician2 claim — returns 404', async () => {
      const res = await asPhysician1('POST', `/api/v1/claims/${P2_CLAIM_ID_A}/validate`);
      expect(res.statusCode).toBe(404);
    });

    it('physician1 CANNOT queue physician2 claim — returns 404', async () => {
      const res = await asPhysician1('POST', `/api/v1/claims/${P2_CLAIM_ID_A}/queue`);
      expect(res.statusCode).toBe(404);
    });

    it('physician1 CANNOT unqueue physician2 claim — returns 404', async () => {
      const res = await asPhysician1('POST', `/api/v1/claims/${P2_CLAIM_ID_A}/unqueue`);
      expect(res.statusCode).toBe(404);
    });

    it('physician1 CANNOT write-off physician2 claim — returns 404', async () => {
      const res = await asPhysician1('POST', `/api/v1/claims/${P2_CLAIM_ID_A}/write-off`, {
        reason: 'test',
      });
      expect(res.statusCode).toBe(404);
    });

    it('physician1 CANNOT resubmit physician2 claim — returns 404', async () => {
      const res = await asPhysician1('POST', `/api/v1/claims/${P2_CLAIM_ID_A}/resubmit`);
      expect(res.statusCode).toBe(404);
    });

    it('physician2 claim state remains unchanged after physician1 transition attempts', async () => {
      await asPhysician1('POST', `/api/v1/claims/${P2_CLAIM_ID_A}/validate`);
      const res = await asPhysician2('GET', `/api/v1/claims/${P2_CLAIM_ID_A}`);
      expect(res.statusCode).toBe(200);
      expect(JSON.parse(res.body).data.state).toBe('VALIDATED');
    });
  });

  // =========================================================================
  // 6. AI Coach Suggestion Isolation
  // =========================================================================

  describe('AI Coach suggestion isolation', () => {
    it('physician1 CANNOT view physician2 claim suggestions — returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/claims/${P2_CLAIM_ID_A}/suggestions`);
      expect(res.statusCode).toBe(404);
    });

    it('physician1 CANNOT accept physician2 claim suggestion — returns 404', async () => {
      const res = await asPhysician1(
        'POST',
        `/api/v1/claims/${P2_CLAIM_ID_A}/suggestions/${P2_SUGGESTION_ID}/accept`,
      );
      expect(res.statusCode).toBe(404);
    });

    it('physician1 CANNOT dismiss physician2 claim suggestion — returns 404', async () => {
      const res = await asPhysician1(
        'POST',
        `/api/v1/claims/${P2_CLAIM_ID_A}/suggestions/${P2_SUGGESTION_ID}/dismiss`,
        { reason: 'not relevant' },
      );
      expect(res.statusCode).toBe(404);
    });
  });

  // =========================================================================
  // 7. Rejection Management Isolation
  // =========================================================================

  describe('Rejection management isolation', () => {
    it('physician1 rejected claims list does not include physician2 claims', async () => {
      const res = await asPhysician1('GET', '/api/v1/claims/rejected');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      body.data.forEach((claim: any) => {
        expect(claim.physicianId).toBe(P1_PROVIDER_ID);
      });
      expect(res.body).not.toContain(P2_PROVIDER_ID);
    });

    it('physician1 CANNOT view physician2 rejection details — returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/claims/${P2_CLAIM_ID_A}/rejection-details`);
      expect(res.statusCode).toBe(404);
    });
  });

  // =========================================================================
  // 8. Claim Audit Isolation
  // =========================================================================

  describe('Claim audit isolation', () => {
    it('physician1 CANNOT view physician2 claim audit history — returns 404 or empty', async () => {
      const res = await asPhysician1('GET', `/api/v1/claims/${P2_CLAIM_ID_A}/audit`);
      // The handler calls repo.getClaimAuditHistory which checks ownership.
      // Since ownership check fails, it returns []. But we render 200 with empty data.
      // This is acceptable since the handler returns { data: history } and history is [].
      // However, a proper implementation might return 404.
      // Accept either 404 or 200 with empty data as both prevent cross-tenant access.
      if (res.statusCode === 200) {
        const body = JSON.parse(res.body);
        expect(body.data).toEqual([]);
      } else {
        expect(res.statusCode).toBe(404);
      }
    });

    it('physician1 audit response for physician2 claim contains no P2 data', async () => {
      const res = await asPhysician1('GET', `/api/v1/claims/${P2_CLAIM_ID_A}/audit`);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_USER_ID);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
    });
  });

  // =========================================================================
  // 9. Import Batch Isolation
  // =========================================================================

  describe('Import batch isolation', () => {
    it('physician1 CANNOT view physician2 import batch — returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/imports/${P2_IMPORT_ID}`);
      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
    });

    it('physician2 CANNOT view physician1 import batch — returns 404', async () => {
      const res = await asPhysician2('GET', `/api/v1/imports/${P1_IMPORT_ID}`);
      expect(res.statusCode).toBe(404);
    });

    it('physician1 CANNOT preview physician2 import — returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/imports/${P2_IMPORT_ID}/preview`);
      expect(res.statusCode).toBe(404);
    });

    it('physician1 CANNOT commit physician2 import — returns 404', async () => {
      const res = await asPhysician1('POST', `/api/v1/imports/${P2_IMPORT_ID}/commit`);
      expect(res.statusCode).toBe(404);
    });

    it('cross-tenant import response does not reveal batch details', async () => {
      const res = await asPhysician1('GET', `/api/v1/imports/${P2_IMPORT_ID}`);
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_IMPORT_ID);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain('claims_p2.csv');
    });
  });

  // =========================================================================
  // 10. Field Mapping Template Isolation
  // =========================================================================

  describe('Field mapping template isolation', () => {
    it('physician1 template list returns only physician1 templates', async () => {
      const res = await asPhysician1('GET', '/api/v1/field-mapping-templates');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      body.data.forEach((template: any) => {
        expect(template.physicianId).toBe(P1_PROVIDER_ID);
      });
      expect(res.body).not.toContain(P2_TEMPLATE_ID);
      expect(res.body).not.toContain('P2 Template');
    });

    it('physician1 CANNOT update physician2 template — returns 404', async () => {
      const res = await asPhysician1('PUT', `/api/v1/field-mapping-templates/${P2_TEMPLATE_ID}`, {
        name: 'Hijacked Template',
      });
      expect(res.statusCode).toBe(404);
    });

    it('physician1 CANNOT delete physician2 template — returns 404', async () => {
      const res = await asPhysician1('DELETE', `/api/v1/field-mapping-templates/${P2_TEMPLATE_ID}`);
      expect(res.statusCode).toBe(404);
    });

    it('physician2 template unchanged after physician1 update attempt', async () => {
      await asPhysician1('PUT', `/api/v1/field-mapping-templates/${P2_TEMPLATE_ID}`, {
        name: 'Hijacked',
      });
      const res = await asPhysician2('GET', '/api/v1/field-mapping-templates');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      const p2Template = body.data.find((t: any) => t.templateId === P2_TEMPLATE_ID);
      expect(p2Template).toBeDefined();
      expect(p2Template.name).toBe('P2 Template');
    });

    it('physician2 template still exists after physician1 delete attempt', async () => {
      await asPhysician1('DELETE', `/api/v1/field-mapping-templates/${P2_TEMPLATE_ID}`);
      const res = await asPhysician2('GET', '/api/v1/field-mapping-templates');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      const p2Template = body.data.find((t: any) => t.templateId === P2_TEMPLATE_ID);
      expect(p2Template).toBeDefined();
    });
  });

  // =========================================================================
  // 11. ED Shift Isolation
  // =========================================================================

  describe('ED shift isolation', () => {
    it('physician1 CANNOT view physician2 shift — returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/shifts/${P2_SHIFT_ID}`);
      expect(res.statusCode).toBe(404);
    });

    it('physician2 CANNOT view physician1 shift — returns 404', async () => {
      const res = await asPhysician2('GET', `/api/v1/shifts/${P1_SHIFT_ID}`);
      expect(res.statusCode).toBe(404);
    });

    it('physician1 CANNOT add encounters to physician2 shift — returns 404', async () => {
      const res = await asPhysician1('POST', `/api/v1/shifts/${P2_SHIFT_ID}/encounters`, {
        patient_id: P1_PATIENT_ID,
        date_of_service: '2026-02-01',
        claim_type: 'AHCIP',
      });
      expect(res.statusCode).toBe(404);
    });

    it('physician1 CANNOT complete physician2 shift — returns 404', async () => {
      const res = await asPhysician1('PUT', `/api/v1/shifts/${P2_SHIFT_ID}/complete`);
      expect(res.statusCode).toBe(404);
    });

    it('physician2 shift remains IN_PROGRESS after physician1 complete attempt', async () => {
      await asPhysician1('PUT', `/api/v1/shifts/${P2_SHIFT_ID}/complete`);
      const res = await asPhysician2('GET', `/api/v1/shifts/${P2_SHIFT_ID}`);
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.shift.status).toBe('IN_PROGRESS');
    });
  });

  // =========================================================================
  // 12. Export Isolation
  // =========================================================================

  describe('Export isolation', () => {
    it('physician1 CANNOT view physician2 export — returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/exports/${P2_EXPORT_ID}`);
      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
    });

    it('physician2 CANNOT view physician1 export — returns 404', async () => {
      const res = await asPhysician2('GET', `/api/v1/exports/${P1_EXPORT_ID}`);
      expect(res.statusCode).toBe(404);
    });

    it('cross-tenant export response does not leak export info', async () => {
      const res = await asPhysician1('GET', `/api/v1/exports/${P2_EXPORT_ID}`);
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_EXPORT_ID);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain('download');
    });
  });

  // =========================================================================
  // 13. Delegate Cross-Context Isolation
  // =========================================================================

  describe('Delegate cross-context isolation', () => {
    it('delegate linked to physician1 can access physician1 claim', async () => {
      const res = await asDelegate('GET', `/api/v1/claims/${P1_CLAIM_ID_A}`);
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.claimId).toBe(P1_CLAIM_ID_A);
      expect(body.data.physicianId).toBe(P1_PROVIDER_ID);
    });

    it('delegate linked to physician1 CANNOT access physician2 claim — returns 404', async () => {
      const res = await asDelegate('GET', `/api/v1/claims/${P2_CLAIM_ID_A}`);
      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
    });

    it('delegate claim list only returns physician1 claims', async () => {
      const res = await asDelegate('GET', '/api/v1/claims');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      body.data.forEach((claim: any) => {
        expect(claim.physicianId).toBe(P1_PROVIDER_ID);
      });
      expect(res.body).not.toContain(P2_PROVIDER_ID);
    });

    it('delegate CANNOT update physician2 claim — returns 404', async () => {
      const res = await asDelegate('PUT', `/api/v1/claims/${P2_CLAIM_ID_B}`, {
        date_of_service: '2026-03-01',
      });
      expect(res.statusCode).toBe(404);
    });

    it('delegate CANNOT delete physician2 claim — returns 404', async () => {
      const res = await asDelegate('DELETE', `/api/v1/claims/${P2_CLAIM_ID_B}`);
      expect(res.statusCode).toBe(404);
    });

    it('delegate CANNOT validate physician2 claim — returns 404', async () => {
      const res = await asDelegate('POST', `/api/v1/claims/${P2_CLAIM_ID_A}/validate`);
      expect(res.statusCode).toBe(404);
    });

    it('delegate CANNOT access physician2 import batch — returns 404', async () => {
      const res = await asDelegate('GET', `/api/v1/imports/${P2_IMPORT_ID}`);
      expect(res.statusCode).toBe(404);
    });

    it('delegate CANNOT access physician2 shift — returns 404', async () => {
      const res = await asDelegate('GET', `/api/v1/shifts/${P2_SHIFT_ID}`);
      expect(res.statusCode).toBe(404);
    });

    it('delegate CANNOT access physician2 export — returns 404', async () => {
      const res = await asDelegate('GET', `/api/v1/exports/${P2_EXPORT_ID}`);
      expect(res.statusCode).toBe(404);
    });
  });

  // =========================================================================
  // 14. Dual-Delegate Cross-Context Isolation
  // =========================================================================

  describe('Dual-delegate in physician1 context does not leak physician2 data', () => {
    it('dual delegate in P1 context sees only P1 claims in list', async () => {
      const res = await asDualDelegateP1('GET', '/api/v1/claims');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      body.data.forEach((claim: any) => {
        expect(claim.physicianId).toBe(P1_PROVIDER_ID);
      });
      expect(res.body).not.toContain(P2_PROVIDER_ID);
      expect(res.body).not.toContain(P2_CLAIM_ID_A);
      expect(res.body).not.toContain(P2_CLAIM_ID_B);
    });

    it('dual delegate in P1 context CANNOT access P2 claim by ID — returns 404', async () => {
      const res = await asDualDelegateP1('GET', `/api/v1/claims/${P2_CLAIM_ID_A}`);
      expect(res.statusCode).toBe(404);
    });

    it('dual delegate in P1 context CANNOT update P2 claim — returns 404', async () => {
      const res = await asDualDelegateP1('PUT', `/api/v1/claims/${P2_CLAIM_ID_B}`, {
        date_of_service: '2026-03-15',
      });
      expect(res.statusCode).toBe(404);
    });

    it('dual delegate in P1 context CANNOT access P2 shift — returns 404', async () => {
      const res = await asDualDelegateP1('GET', `/api/v1/shifts/${P2_SHIFT_ID}`);
      expect(res.statusCode).toBe(404);
    });

    it('dual delegate in P1 context CANNOT access P2 export — returns 404', async () => {
      const res = await asDualDelegateP1('GET', `/api/v1/exports/${P2_EXPORT_ID}`);
      expect(res.statusCode).toBe(404);
    });

    it('dual delegate in P1 context template list contains only P1 templates', async () => {
      const res = await asDualDelegateP1('GET', '/api/v1/field-mapping-templates');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      body.data.forEach((template: any) => {
        expect(template.physicianId).toBe(P1_PROVIDER_ID);
      });
      expect(res.body).not.toContain(P2_TEMPLATE_ID);
    });
  });

  // =========================================================================
  // 15. Cross-user access always returns 404 (NOT 403)
  // =========================================================================

  describe('Cross-user access returns 404 not 403 (prevents resource enumeration)', () => {
    it('GET claim by cross-tenant ID returns 404 not 403', async () => {
      const res = await asPhysician1('GET', `/api/v1/claims/${P2_CLAIM_ID_A}`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('PUT claim cross-tenant returns 404 not 403', async () => {
      const res = await asPhysician1('PUT', `/api/v1/claims/${P2_CLAIM_ID_B}`, {
        date_of_service: '2026-03-01',
      });
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('DELETE claim cross-tenant returns 404 not 403', async () => {
      const res = await asPhysician1('DELETE', `/api/v1/claims/${P2_CLAIM_ID_B}`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST validate cross-tenant returns 404 not 403', async () => {
      const res = await asPhysician1('POST', `/api/v1/claims/${P2_CLAIM_ID_A}/validate`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST queue cross-tenant returns 404 not 403', async () => {
      const res = await asPhysician1('POST', `/api/v1/claims/${P2_CLAIM_ID_A}/queue`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST write-off cross-tenant returns 404 not 403', async () => {
      const res = await asPhysician1('POST', `/api/v1/claims/${P2_CLAIM_ID_A}/write-off`, { reason: 'test' });
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET import batch cross-tenant returns 404 not 403', async () => {
      const res = await asPhysician1('GET', `/api/v1/imports/${P2_IMPORT_ID}`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('PUT template cross-tenant returns 404 not 403', async () => {
      const res = await asPhysician1('PUT', `/api/v1/field-mapping-templates/${P2_TEMPLATE_ID}`, { name: 'X' });
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('DELETE template cross-tenant returns 404 not 403', async () => {
      const res = await asPhysician1('DELETE', `/api/v1/field-mapping-templates/${P2_TEMPLATE_ID}`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET shift cross-tenant returns 404 not 403', async () => {
      const res = await asPhysician1('GET', `/api/v1/shifts/${P2_SHIFT_ID}`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('POST encounter cross-tenant returns 404 not 403', async () => {
      const res = await asPhysician1('POST', `/api/v1/shifts/${P2_SHIFT_ID}/encounters`, {
        patient_id: P1_PATIENT_ID,
        date_of_service: '2026-02-01',
        claim_type: 'AHCIP',
      });
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('PUT complete shift cross-tenant returns 404 not 403', async () => {
      const res = await asPhysician1('PUT', `/api/v1/shifts/${P2_SHIFT_ID}/complete`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET export cross-tenant returns 404 not 403', async () => {
      const res = await asPhysician1('GET', `/api/v1/exports/${P2_EXPORT_ID}`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET suggestions cross-tenant returns 404 not 403', async () => {
      const res = await asPhysician1('GET', `/api/v1/claims/${P2_CLAIM_ID_A}/suggestions`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('GET rejection-details cross-tenant returns 404 not 403', async () => {
      const res = await asPhysician1('GET', `/api/v1/claims/${P2_CLAIM_ID_A}/rejection-details`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });
  });

  // =========================================================================
  // 16. 404 responses reveal no information about the target resource
  // =========================================================================

  describe('404 responses reveal no information about the target resource', () => {
    it('404 for cross-tenant claim does not contain claim ID or details', async () => {
      const res = await asPhysician1('GET', `/api/v1/claims/${P2_CLAIM_ID_A}`);
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_CLAIM_ID_A);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain(P2_PATIENT_ID);
      expect(rawBody).not.toContain('VALIDATED');
    });

    it('404 for cross-tenant import does not contain batch details', async () => {
      const res = await asPhysician1('GET', `/api/v1/imports/${P2_IMPORT_ID}`);
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_IMPORT_ID);
      expect(rawBody).not.toContain('claims_p2.csv');
    });

    it('404 for cross-tenant template does not contain template details', async () => {
      const res = await asPhysician1('PUT', `/api/v1/field-mapping-templates/${P2_TEMPLATE_ID}`, { name: 'X' });
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_TEMPLATE_ID);
      expect(rawBody).not.toContain('P2 Template');
    });

    it('404 for cross-tenant shift does not contain shift details', async () => {
      const res = await asPhysician1('GET', `/api/v1/shifts/${P2_SHIFT_ID}`);
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_SHIFT_ID);
    });

    it('404 for cross-tenant export does not contain export details', async () => {
      const res = await asPhysician1('GET', `/api/v1/exports/${P2_EXPORT_ID}`);
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_EXPORT_ID);
    });
  });

  // =========================================================================
  // 17. Non-existent resource IDs return 404 (not 500)
  // =========================================================================

  describe('Non-existent resource IDs return 404', () => {
    const NONEXISTENT_UUID = '99999999-9999-9999-9999-999999999999';

    it('GET non-existent claim ID returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/claims/${NONEXISTENT_UUID}`);
      expect(res.statusCode).toBe(404);
    });

    it('PUT non-existent claim ID returns 404', async () => {
      const res = await asPhysician1('PUT', `/api/v1/claims/${NONEXISTENT_UUID}`, {
        date_of_service: '2026-03-01',
      });
      expect(res.statusCode).toBe(404);
    });

    it('DELETE non-existent claim ID returns 404', async () => {
      const res = await asPhysician1('DELETE', `/api/v1/claims/${NONEXISTENT_UUID}`);
      expect(res.statusCode).toBe(404);
    });

    it('GET non-existent import batch returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/imports/${NONEXISTENT_UUID}`);
      expect(res.statusCode).toBe(404);
    });

    it('GET non-existent shift returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/shifts/${NONEXISTENT_UUID}`);
      expect(res.statusCode).toBe(404);
    });

    it('GET non-existent export returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/exports/${NONEXISTENT_UUID}`);
      expect(res.statusCode).toBe(404);
    });

    it('GET non-existent claim audit returns 404 or empty', async () => {
      const res = await asPhysician1('GET', `/api/v1/claims/${NONEXISTENT_UUID}/audit`);
      if (res.statusCode === 200) {
        const body = JSON.parse(res.body);
        expect(body.data).toEqual([]);
      } else {
        expect(res.statusCode).toBe(404);
      }
    });

    it('POST validate non-existent claim returns 404', async () => {
      const res = await asPhysician1('POST', `/api/v1/claims/${NONEXISTENT_UUID}/validate`);
      expect(res.statusCode).toBe(404);
    });

    it('GET non-existent claim suggestions returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/claims/${NONEXISTENT_UUID}/suggestions`);
      expect(res.statusCode).toBe(404);
    });

    it('GET non-existent rejection-details returns 404', async () => {
      const res = await asPhysician1('GET', `/api/v1/claims/${NONEXISTENT_UUID}/rejection-details`);
      expect(res.statusCode).toBe(404);
    });
  });

  // =========================================================================
  // 18. Bidirectional isolation — verify BOTH directions
  // =========================================================================

  describe('Bidirectional isolation (both physicians tested)', () => {
    it('physician1 claim list contains P1 IDs and not P2 IDs', async () => {
      const res = await asPhysician1('GET', '/api/v1/claims');
      const body = JSON.parse(res.body);
      const ids = body.data.map((c: any) => c.claimId);
      expect(ids).toContain(P1_CLAIM_ID_A);
      expect(ids).toContain(P1_CLAIM_ID_B);
      expect(ids).not.toContain(P2_CLAIM_ID_A);
      expect(ids).not.toContain(P2_CLAIM_ID_B);
    });

    it('physician2 claim list contains P2 IDs and not P1 IDs', async () => {
      const res = await asPhysician2('GET', '/api/v1/claims');
      const body = JSON.parse(res.body);
      const ids = body.data.map((c: any) => c.claimId);
      expect(ids).toContain(P2_CLAIM_ID_A);
      expect(ids).toContain(P2_CLAIM_ID_B);
      expect(ids).not.toContain(P1_CLAIM_ID_A);
      expect(ids).not.toContain(P1_CLAIM_ID_B);
    });

    it('physician1 template list contains P1 templates only', async () => {
      const res = await asPhysician1('GET', '/api/v1/field-mapping-templates');
      const body = JSON.parse(res.body);
      const ids = body.data.map((t: any) => t.templateId);
      expect(ids).toContain(P1_TEMPLATE_ID);
      expect(ids).not.toContain(P2_TEMPLATE_ID);
    });

    it('physician2 template list contains P2 templates only', async () => {
      const res = await asPhysician2('GET', '/api/v1/field-mapping-templates');
      const body = JSON.parse(res.body);
      const ids = body.data.map((t: any) => t.templateId);
      expect(ids).toContain(P2_TEMPLATE_ID);
      expect(ids).not.toContain(P1_TEMPLATE_ID);
    });
  });

  // =========================================================================
  // 19. Response body never leaks cross-tenant identifiers
  // =========================================================================

  describe('Response body never leaks cross-tenant identifiers', () => {
    it('physician1 claim GET response contains no P2 identifiers', async () => {
      const res = await asPhysician1('GET', `/api/v1/claims/${P1_CLAIM_ID_A}`);
      expect(res.statusCode).toBe(200);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain(P2_USER_ID);
      expect(rawBody).not.toContain(P2_CLAIM_ID_A);
      expect(rawBody).not.toContain(P2_CLAIM_ID_B);
    });

    it('physician1 claim list response contains no P2 identifiers', async () => {
      const res = await asPhysician1('GET', '/api/v1/claims');
      expect(res.statusCode).toBe(200);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain(P2_CLAIM_ID_A);
      expect(rawBody).not.toContain(P2_CLAIM_ID_B);
    });

    it('physician1 rejected list response contains no P2 identifiers', async () => {
      const res = await asPhysician1('GET', '/api/v1/claims/rejected');
      expect(res.statusCode).toBe(200);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain(P2_CLAIM_ID_A);
    });

    it('physician1 template list response contains no P2 identifiers', async () => {
      const res = await asPhysician1('GET', '/api/v1/field-mapping-templates');
      expect(res.statusCode).toBe(200);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain(P2_TEMPLATE_ID);
    });
  });
});
