import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  listRecentReferrers,
  recordRecentReferrer,
  listClaimTemplates,
  createClaimTemplate,
  updateClaimTemplate,
  deleteClaimTemplate,
  applyClaimTemplate,
  createJustification,
  getJustificationForClaim,
  updateJustification,
  searchJustificationHistory,
  saveJustificationAsPersonalTemplate,
  checkBundlingConflicts,
  calculateAnesthesiaBenefit,
  autoDetectJustificationRequired,
  type ClaimServiceDeps,
} from './claim.service.js';

// ---------------------------------------------------------------------------
// Mock drizzle-orm
// ---------------------------------------------------------------------------

vi.mock('drizzle-orm', () => ({
  eq: (column: any, value: any) => {
    const colName = column?.name;
    return { __predicate: (row: any) => row[colName] === value };
  },
  and: (...conditions: any[]) => ({
    __predicate: (row: any) =>
      conditions.every((c: any) => {
        if (!c) return true;
        if (c.__predicate) return c.__predicate(row);
        return true;
      }),
  }),
  desc: (column: any) => ({
    __sortFn: (a: any, b: any) => {
      const colName = column?.name;
      const va = a[colName] ?? '';
      const vb = b[colName] ?? '';
      return va > vb ? -1 : va < vb ? 1 : 0;
    },
  }),
  count: () => ({ __count: true }),
  sql: (strings: TemplateStringsArray, ...values: any[]) => ({
    __sql: true,
    raw: strings.join('?'),
    values,
  }),
  isNull: (column: any) => {
    const colName = column?.name;
    return { __predicate: (row: any) => row[colName] == null };
  },
  inArray: (column: any, arr: any[]) => {
    const colName = column?.name;
    return { __predicate: (row: any) => arr.includes(row[colName]) };
  },
  lte: () => ({ __predicate: () => true }),
  gte: () => ({ __predicate: () => true }),
}));

// ---------------------------------------------------------------------------
// Mock claim constants
// ---------------------------------------------------------------------------

vi.mock('@meritum/shared/constants/claim.constants.js', () => ({
  ClaimState: {
    DRAFT: 'DRAFT', VALIDATED: 'VALIDATED', QUEUED: 'QUEUED',
    SUBMITTED: 'SUBMITTED', ASSESSED: 'ASSESSED', PAID: 'PAID',
    REJECTED: 'REJECTED', ADJUSTED: 'ADJUSTED', WRITTEN_OFF: 'WRITTEN_OFF',
    EXPIRED: 'EXPIRED', DELETED: 'DELETED',
  },
  ClaimType: { AHCIP: 'AHCIP', WCB: 'WCB' },
  ClaimImportSource: {
    MANUAL: 'MANUAL', EMR_IMPORT: 'EMR_IMPORT', ED_SHIFT: 'ED_SHIFT',
    CONNECT_CARE_CSV: 'CONNECT_CARE_CSV', CONNECT_CARE_SFTP: 'CONNECT_CARE_SFTP',
    EMR_GENERIC: 'EMR_GENERIC',
  },
  ClaimAuditAction: {
    CREATED: 'claim.created', EDITED: 'claim.edited',
    VALIDATED: 'claim.validated', QUEUED: 'claim.queued',
    UNQUEUED: 'claim.unqueued', SUBMITTED: 'claim.submitted',
    ASSESSED: 'claim.assessed', REJECTED: 'claim.rejected',
    RESUBMITTED: 'claim.resubmitted', WRITTEN_OFF: 'claim.written_off',
    DELETED: 'claim.deleted', EXPIRED: 'claim.expired',
    AI_SUGGESTION_ACCEPTED: 'claim.ai_suggestion_accepted',
    AI_SUGGESTION_DISMISSED: 'claim.ai_suggestion_dismissed',
    DUPLICATE_ACKNOWLEDGED: 'claim.duplicate_acknowledged',
    SHIFT_CREATED: 'shift.created', SHIFT_COMPLETED: 'shift.completed',
    TEMPLATE_CREATED: 'claim.template_created',
    TEMPLATE_UPDATED: 'claim.template_updated',
    TEMPLATE_DELETED: 'claim.template_deleted',
    JUSTIFICATION_CREATED: 'claim.justification_created',
    JUSTIFICATION_UPDATED: 'claim.justification_updated',
    BUNDLING_OVERRIDE: 'claim.bundling_override',
    ANESTHESIA_OVERRIDE: 'claim.anesthesia_override',
    ROUTING_OVERRIDE: 'claim.routing_override',
  },
  ActorContext: { PHYSICIAN: 'PHYSICIAN', DELEGATE: 'DELEGATE', SYSTEM: 'SYSTEM' },
  ImportBatchStatus: { PENDING: 'PENDING', PROCESSING: 'PROCESSING', COMPLETED: 'COMPLETED', FAILED: 'FAILED' },
  ShiftStatus: { IN_PROGRESS: 'IN_PROGRESS', COMPLETED: 'COMPLETED', SUBMITTED: 'SUBMITTED' },
  ExportStatus: { PENDING: 'PENDING', PROCESSING: 'PROCESSING', COMPLETED: 'COMPLETED', FAILED: 'FAILED' },
  AutoSubmissionMode: { AUTO_CLEAN: 'AUTO_CLEAN', AUTO_ALL: 'AUTO_ALL', REQUIRE_APPROVAL: 'REQUIRE_APPROVAL' },
  JustificationScenario: {
    UNLISTED_PROCEDURE: 'UNLISTED_PROCEDURE',
    ADDITIONAL_COMPENSATION: 'ADDITIONAL_COMPENSATION',
    PRE_OP_CONSERVATIVE: 'PRE_OP_CONSERVATIVE',
    POST_OP_COMPLICATION: 'POST_OP_COMPLICATION',
    WCB_NARRATIVE: 'WCB_NARRATIVE',
  },
  BundlingRelationship: { BUNDLED: 'BUNDLED', INDEPENDENT: 'INDEPENDENT', INTRINSICALLY_LINKED: 'INTRINSICALLY_LINKED' },
  ClaimTemplateType: { CUSTOM: 'CUSTOM', SPECIALTY_STARTER: 'SPECIALTY_STARTER' },
  ValidationCheckId: {
    S1_CLAIM_TYPE_VALID: 'S1_CLAIM_TYPE_VALID',
    S2_REQUIRED_BASE_FIELDS: 'S2_REQUIRED_BASE_FIELDS',
    S3_PATIENT_EXISTS: 'S3_PATIENT_EXISTS',
    S4_PHYSICIAN_ACTIVE: 'S4_PHYSICIAN_ACTIVE',
    S5_DOS_VALID: 'S5_DOS_VALID',
    S6_SUBMISSION_WINDOW: 'S6_SUBMISSION_WINDOW',
    S7_DUPLICATE_DETECTION: 'S7_DUPLICATE_DETECTION',
  },
  ValidationSeverity: { ERROR: 'ERROR', WARNING: 'WARNING', INFO: 'INFO' },
  VALIDATION_CHECKS: {},
  TERMINAL_STATES: new Set(['PAID', 'ADJUSTED', 'WRITTEN_OFF', 'EXPIRED', 'DELETED']),
  STATE_TRANSITIONS: {
    DRAFT: ['VALIDATED', 'DELETED'],
    VALIDATED: ['DRAFT', 'QUEUED'],
    QUEUED: ['VALIDATED', 'SUBMITTED'],
    SUBMITTED: ['ASSESSED', 'REJECTED'],
    ASSESSED: ['PAID', 'ADJUSTED'],
    REJECTED: ['DRAFT', 'QUEUED', 'WRITTEN_OFF'],
    PAID: [], ADJUSTED: [], WRITTEN_OFF: [], EXPIRED: [], DELETED: [],
  },
  ClaimNotificationEvent: {
    CLAIM_VALIDATED: 'CLAIM_VALIDATED', CLAIM_FLAGGED: 'CLAIM_FLAGGED',
    DEADLINE_APPROACHING: 'DEADLINE_APPROACHING', DEADLINE_EXPIRED: 'DEADLINE_EXPIRED',
    BATCH_ASSEMBLED: 'BATCH_ASSEMBLED', BATCH_SUBMITTED: 'BATCH_SUBMITTED',
    CLAIM_ASSESSED: 'CLAIM_ASSESSED', CLAIM_REJECTED: 'CLAIM_REJECTED',
    CLAIM_PAID: 'CLAIM_PAID', DUPLICATE_DETECTED: 'DUPLICATE_DETECTED',
    AI_SUGGESTION_READY: 'AI_SUGGESTION_READY',
  },
}));

// ---------------------------------------------------------------------------
// Mock provider constants (needed by SubmissionMode re-export)
// ---------------------------------------------------------------------------

vi.mock('@meritum/shared/constants/provider.constants.js', () => ({
  SubmissionMode: { AUTO_CLEAN: 'AUTO_CLEAN', AUTO_ALL: 'AUTO_ALL', REQUIRE_APPROVAL: 'REQUIRE_APPROVAL' },
}));

// ---------------------------------------------------------------------------
// Mock errors module
// ---------------------------------------------------------------------------

vi.mock('../../lib/errors.js', () => ({
  BusinessRuleError: class BusinessRuleError extends Error {
    constructor(msg: string) { super(msg); this.name = 'BusinessRuleError'; }
  },
  ConflictError: class ConflictError extends Error {
    constructor(msg: string) { super(msg); this.name = 'ConflictError'; }
  },
  ForbiddenError: class ForbiddenError extends Error {
    constructor(msg: string) { super(msg); this.name = 'ForbiddenError'; }
  },
  NotFoundError: class NotFoundError extends Error {
    constructor(msg: string) { super(msg); this.name = 'NotFoundError'; }
  },
}));

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const PHYSICIAN_ID = '11111111-1111-1111-1111-111111111111';
const ACTOR_ID = '22222222-2222-2222-2222-222222222222';
const TEMPLATE_ID = '33333333-3333-3333-3333-333333333333';
const CLAIM_ID = '44444444-4444-4444-4444-444444444444';
const JUSTIFICATION_ID = '55555555-5555-5555-5555-555555555555';

function makeMockRepo() {
  return {
    // Existing methods (stubs)
    createClaim: vi.fn(),
    findClaimById: vi.fn(),
    updateClaim: vi.fn(),
    softDeleteClaim: vi.fn(),
    listClaims: vi.fn(),
    countClaimsByState: vi.fn(),
    findClaimsApproachingDeadline: vi.fn(),
    transitionState: vi.fn(),
    classifyClaim: vi.fn(),
    updateValidationResult: vi.fn(),
    updateAiSuggestions: vi.fn(),
    updateDuplicateAlert: vi.fn(),
    updateFlags: vi.fn(),
    createImportBatch: vi.fn(),
    findImportBatchById: vi.fn(),
    updateImportBatchStatus: vi.fn(),
    findDuplicateImportByHash: vi.fn(),
    listImportBatches: vi.fn(),
    findClaimsForBatchAssembly: vi.fn(),
    bulkTransitionState: vi.fn(),
    createTemplate: vi.fn(),
    findTemplateById: vi.fn(),
    updateTemplate: vi.fn(),
    deleteTemplate: vi.fn(),
    listTemplates: vi.fn(),
    createShift: vi.fn(),
    findShiftById: vi.fn(),
    updateShiftStatus: vi.fn(),
    updateShiftTimes: vi.fn(),
    incrementEncounterCount: vi.fn(),
    listShifts: vi.fn(),
    findClaimsByShift: vi.fn(),
    createExportRecord: vi.fn(),
    findExportById: vi.fn(),
    updateExportStatus: vi.fn(),
    appendClaimAudit: vi.fn(),
    getClaimAuditHistory: vi.fn(),
    getClaimAuditHistoryPaginated: vi.fn(),
    // Phase 5 methods
    getRecentReferrers: vi.fn(),
    upsertRecentReferrer: vi.fn(),
    evictOldestReferrers: vi.fn(),
    listClaimTemplates: vi.fn(),
    findClaimTemplateById: vi.fn(),
    createClaimTemplate: vi.fn(),
    updateClaimTemplate: vi.fn(),
    deleteClaimTemplate: vi.fn(),
    incrementClaimTemplateUsage: vi.fn(),
    createJustification: vi.fn(),
    getJustificationForClaim: vi.fn(),
    updateJustification: vi.fn(),
    searchJustificationHistory: vi.fn(),
    findJustificationById: vi.fn(),
  };
}

function makeDeps(overrides: Partial<ClaimServiceDeps> = {}): ClaimServiceDeps {
  return {
    repo: makeMockRepo() as any,
    providerCheck: { isActive: vi.fn().mockResolvedValue(true) },
    patientCheck: { exists: vi.fn().mockResolvedValue(true) },
    ...overrides,
  };
}

// ===========================================================================
// Tests
// ===========================================================================

describe('Claim Extensions — Phase 5', () => {
  let deps: ClaimServiceDeps;

  beforeEach(() => {
    vi.clearAllMocks();
    deps = makeDeps();
  });

  // =========================================================================
  // Recent Referrers
  // =========================================================================

  describe('Recent Referrers', () => {
    it('should list recent referrers for a physician', async () => {
      const mockReferrers = [
        { id: 'r1', physicianId: PHYSICIAN_ID, referrerCpsa: '12345', referrerName: 'Dr. Smith', useCount: 5, lastUsedAt: new Date() },
        { id: 'r2', physicianId: PHYSICIAN_ID, referrerCpsa: '67890', referrerName: 'Dr. Jones', useCount: 3, lastUsedAt: new Date() },
      ];
      (deps.repo as any).getRecentReferrers.mockResolvedValue(mockReferrers);

      const result = await listRecentReferrers(deps, PHYSICIAN_ID);

      expect(result).toHaveLength(2);
      expect((deps.repo as any).getRecentReferrers).toHaveBeenCalledWith(PHYSICIAN_ID, 20);
    });

    it('should upsert a referrer and evict oldest beyond 20', async () => {
      const mockReferrer = {
        id: 'r1', physicianId: PHYSICIAN_ID, referrerCpsa: '12345',
        referrerName: 'Dr. Smith', useCount: 1, lastUsedAt: new Date(),
      };
      (deps.repo as any).upsertRecentReferrer.mockResolvedValue(mockReferrer);
      (deps.repo as any).evictOldestReferrers.mockResolvedValue(0);

      const result = await recordRecentReferrer(deps, PHYSICIAN_ID, '12345', 'Dr. Smith');

      expect(result).toEqual(mockReferrer);
      expect((deps.repo as any).upsertRecentReferrer).toHaveBeenCalledWith(PHYSICIAN_ID, '12345', 'Dr. Smith');
      expect((deps.repo as any).evictOldestReferrers).toHaveBeenCalledWith(PHYSICIAN_ID, 20);
    });

    it('should evict oldest referrers when over max count', async () => {
      (deps.repo as any).upsertRecentReferrer.mockResolvedValue({ id: 'r21' });
      (deps.repo as any).evictOldestReferrers.mockResolvedValue(1);

      await recordRecentReferrer(deps, PHYSICIAN_ID, '99999', 'Dr. New');

      expect((deps.repo as any).evictOldestReferrers).toHaveBeenCalledWith(PHYSICIAN_ID, 20);
    });
  });

  // =========================================================================
  // Claim Templates
  // =========================================================================

  describe('Claim Templates', () => {
    it('should list claim templates with pagination', async () => {
      const mockResult = {
        data: [{ templateId: TEMPLATE_ID, name: 'Quick Bill', usageCount: 10 }],
        pagination: { total: 1, page: 1, pageSize: 20, hasMore: false },
      };
      (deps.repo as any).listClaimTemplates.mockResolvedValue(mockResult);

      const result = await listClaimTemplates(deps, PHYSICIAN_ID, { claimType: 'AHCIP' });

      expect(result.data).toHaveLength(1);
      expect((deps.repo as any).listClaimTemplates).toHaveBeenCalledWith(PHYSICIAN_ID, { claimType: 'AHCIP' });
    });

    it('should create a claim template', async () => {
      const mockTemplate = {
        templateId: TEMPLATE_ID, physicianId: PHYSICIAN_ID, name: 'GP Visit',
        templateType: 'CUSTOM', claimType: 'AHCIP',
        lineItems: [{ health_service_code: '03.04A' }],
        usageCount: 0, isActive: true,
      };
      (deps.repo as any).createClaimTemplate.mockResolvedValue(mockTemplate);

      const result = await createClaimTemplate(deps, PHYSICIAN_ID, ACTOR_ID, {
        name: 'GP Visit',
        claimType: 'AHCIP',
        lineItems: [{ health_service_code: '03.04A' }],
      });

      expect(result.name).toBe('GP Visit');
      expect((deps.repo as any).createClaimTemplate).toHaveBeenCalledWith(
        expect.objectContaining({ name: 'GP Visit', claimType: 'AHCIP' }),
      );
    });

    it('should update a claim template', async () => {
      (deps.repo as any).findClaimTemplateById.mockResolvedValue({ templateId: TEMPLATE_ID });
      (deps.repo as any).updateClaimTemplate.mockResolvedValue({ templateId: TEMPLATE_ID, name: 'Updated' });

      const result = await updateClaimTemplate(deps, PHYSICIAN_ID, TEMPLATE_ID, { name: 'Updated' });

      expect(result?.name).toBe('Updated');
    });

    it('should throw NotFoundError when updating non-existent template', async () => {
      (deps.repo as any).findClaimTemplateById.mockResolvedValue(undefined);

      await expect(
        updateClaimTemplate(deps, PHYSICIAN_ID, TEMPLATE_ID, { name: 'Updated' }),
      ).rejects.toThrow('Claim template not found');
    });

    it('should soft-delete a claim template', async () => {
      (deps.repo as any).findClaimTemplateById.mockResolvedValue({ templateId: TEMPLATE_ID });
      (deps.repo as any).deleteClaimTemplate.mockResolvedValue(true);

      const result = await deleteClaimTemplate(deps, PHYSICIAN_ID, TEMPLATE_ID);

      expect(result).toBe(true);
    });

    it('should apply a template to create a claim', async () => {
      const mockTemplate = {
        templateId: TEMPLATE_ID, physicianId: PHYSICIAN_ID,
        claimType: 'AHCIP', lineItems: [{ health_service_code: '03.04A' }],
      };
      const mockClaim = {
        claimId: CLAIM_ID, physicianId: PHYSICIAN_ID, claimType: 'AHCIP',
        state: 'DRAFT', patientId: 'patient-1', dateOfService: '2025-01-15',
      };
      (deps.repo as any).findClaimTemplateById.mockResolvedValue(mockTemplate);
      (deps.repo as any).createClaim.mockResolvedValue(mockClaim);
      (deps.repo as any).appendClaimAudit.mockResolvedValue({});
      (deps.repo as any).incrementClaimTemplateUsage.mockResolvedValue({});

      const result = await applyClaimTemplate(
        deps, PHYSICIAN_ID, ACTOR_ID, 'PHYSICIAN',
        TEMPLATE_ID, 'patient-1', '2025-01-15',
      );

      expect(result.template_applied).toBe(true);
      expect(result.claim.claimId).toBe(CLAIM_ID);
      expect((deps.repo as any).incrementClaimTemplateUsage).toHaveBeenCalledWith(TEMPLATE_ID, PHYSICIAN_ID);
    });

    it('should throw NotFoundError when applying non-existent template', async () => {
      (deps.repo as any).findClaimTemplateById.mockResolvedValue(undefined);

      await expect(
        applyClaimTemplate(deps, PHYSICIAN_ID, ACTOR_ID, 'PHYSICIAN', TEMPLATE_ID, 'patient-1', '2025-01-15'),
      ).rejects.toThrow('Claim template not found');
    });
  });

  // =========================================================================
  // Justifications
  // =========================================================================

  describe('Justifications', () => {
    it('should create a justification for a claim', async () => {
      const mockClaim = { claimId: CLAIM_ID, physicianId: PHYSICIAN_ID, state: 'DRAFT' };
      const mockJustification = {
        justificationId: JUSTIFICATION_ID, claimId: CLAIM_ID,
        scenario: 'UNLISTED_PROCEDURE', justificationText: 'This procedure is medically necessary...',
      };
      (deps.repo as any).findClaimById.mockResolvedValue(mockClaim);
      (deps.repo as any).createJustification.mockResolvedValue(mockJustification);

      const result = await createJustification(deps, PHYSICIAN_ID, ACTOR_ID, {
        claimId: CLAIM_ID,
        scenario: 'UNLISTED_PROCEDURE',
        justificationText: 'This procedure is medically necessary...',
      });

      expect(result.scenario).toBe('UNLISTED_PROCEDURE');
      expect((deps.repo as any).createJustification).toHaveBeenCalledWith(
        expect.objectContaining({ claimId: CLAIM_ID, scenario: 'UNLISTED_PROCEDURE' }),
      );
    });

    it('should throw NotFoundError when creating justification for missing claim', async () => {
      (deps.repo as any).findClaimById.mockResolvedValue(undefined);

      await expect(
        createJustification(deps, PHYSICIAN_ID, ACTOR_ID, {
          claimId: CLAIM_ID,
          scenario: 'UNLISTED_PROCEDURE',
          justificationText: 'text',
        }),
      ).rejects.toThrow('Claim not found');
    });

    it('should get justification for a claim', async () => {
      const mockClaim = { claimId: CLAIM_ID, physicianId: PHYSICIAN_ID };
      const mockJustification = { justificationId: JUSTIFICATION_ID, claimId: CLAIM_ID };
      (deps.repo as any).findClaimById.mockResolvedValue(mockClaim);
      (deps.repo as any).getJustificationForClaim.mockResolvedValue(mockJustification);

      const result = await getJustificationForClaim(deps, PHYSICIAN_ID, CLAIM_ID);

      expect(result?.justificationId).toBe(JUSTIFICATION_ID);
    });

    it('should update justification text', async () => {
      (deps.repo as any).findJustificationById.mockResolvedValue({ justificationId: JUSTIFICATION_ID });
      (deps.repo as any).updateJustification.mockResolvedValue({
        justificationId: JUSTIFICATION_ID, justificationText: 'Updated text',
      });

      const result = await updateJustification(deps, PHYSICIAN_ID, JUSTIFICATION_ID, 'Updated text');

      expect(result?.justificationText).toBe('Updated text');
    });

    it('should throw NotFoundError when updating non-existent justification', async () => {
      (deps.repo as any).findJustificationById.mockResolvedValue(undefined);

      await expect(
        updateJustification(deps, PHYSICIAN_ID, JUSTIFICATION_ID, 'text'),
      ).rejects.toThrow('Justification not found');
    });

    it('should search justification history with filters', async () => {
      const mockResult = {
        data: [{ justificationId: JUSTIFICATION_ID, scenario: 'UNLISTED_PROCEDURE' }],
        pagination: { total: 1, page: 1, pageSize: 20, hasMore: false },
      };
      (deps.repo as any).searchJustificationHistory.mockResolvedValue(mockResult);

      const result = await searchJustificationHistory(deps, PHYSICIAN_ID, {
        scenario: 'UNLISTED_PROCEDURE',
        page: 1,
        pageSize: 20,
      });

      expect(result.data).toHaveLength(1);
      expect(result.data[0].scenario).toBe('UNLISTED_PROCEDURE');
    });

    it('should save justification as personal template', async () => {
      (deps.repo as any).findJustificationById.mockResolvedValue({
        justificationId: JUSTIFICATION_ID, scenario: 'WCB_NARRATIVE',
      });

      const result = await saveJustificationAsPersonalTemplate(deps, PHYSICIAN_ID, JUSTIFICATION_ID);

      expect(result.saved).toBe(true);
      expect(result.scenario).toBe('WCB_NARRATIVE');
    });

    it('should auto-detect justification requirement', async () => {
      const mockClaim = { claimId: CLAIM_ID, physicianId: PHYSICIAN_ID, state: 'DRAFT' };
      (deps.repo as any).findClaimById.mockResolvedValue(mockClaim);

      const result = await autoDetectJustificationRequired(deps, PHYSICIAN_ID, CLAIM_ID);

      expect(result).toHaveProperty('required');
      expect(result).toHaveProperty('scenarios');
    });
  });

  // =========================================================================
  // Bundling Check
  // =========================================================================

  describe('Bundling Check', () => {
    it('should check bundling conflicts between two codes', async () => {
      const result = await checkBundlingConflicts(
        deps, PHYSICIAN_ID, ['03.04A', '03.05A'], 'AHCIP',
      );

      expect(result.hasBundlingConflict).toBe(false);
      expect(result.pairs).toHaveLength(1);
      expect(result.pairs[0].relationship).toBe('INDEPENDENT');
    });

    it('should handle multiple code pairs for bundling check', async () => {
      const result = await checkBundlingConflicts(
        deps, PHYSICIAN_ID, ['A', 'B', 'C'], 'AHCIP',
      );

      // 3 codes → 3 pairs: A-B, A-C, B-C
      expect(result.pairs).toHaveLength(3);
    });

    it('should normalize code pair ordering', async () => {
      const result = await checkBundlingConflicts(
        deps, PHYSICIAN_ID, ['Z99', 'A01'], 'WCB',
      );

      // Should be alphabetically ordered: A01 < Z99
      expect(result.pairs[0].codeA).toBe('A01');
      expect(result.pairs[0].codeB).toBe('Z99');
    });
  });

  // =========================================================================
  // Anesthesia Calculator
  // =========================================================================

  describe('Anesthesia Calculator', () => {
    it('should calculate benefit for a single procedure', async () => {
      const result = await calculateAnesthesiaBenefit(
        deps, PHYSICIAN_ID, ['99100'],
      );

      expect(result.majorProcedureCode).toBe('99100');
      expect(result.baseBenefit).toBeGreaterThan(0);
      expect(result.appliedRules).toContain('GR12_MAJOR_PROCEDURE_IDENTIFICATION');
      expect(result.appliedRules).toContain('GR12_BASE_UNIT');
    });

    it('should apply multiple procedure reduction', async () => {
      const result = await calculateAnesthesiaBenefit(
        deps, PHYSICIAN_ID, ['99100', '99200', '99300'],
      );

      expect(result.reductions).toHaveLength(2);
      expect(result.reductions[0].reductionPercent).toBe(50);
      expect(result.appliedRules).toContain('GR12_MULTIPLE_PROCEDURE_REDUCTION');
    });

    it('should calculate time-based component from start/end times', async () => {
      const result = await calculateAnesthesiaBenefit(
        deps, PHYSICIAN_ID, ['99100'], '08:00', '09:00',
      );

      expect(result.timeBasedComponent).toBeGreaterThan(0);
      expect(result.appliedRules).toContain('GR12_TIME_BASED_COMPONENT');
    });

    it('should calculate time-based component from duration', async () => {
      const result = await calculateAnesthesiaBenefit(
        deps, PHYSICIAN_ID, ['99100'], undefined, undefined, 45,
      );

      expect(result.timeBasedComponent).toBeGreaterThan(0);
      expect(result.appliedRules).toContain('GR12_TIME_BASED_COMPONENT');
    });

    it('should handle overnight duration correctly', async () => {
      const result = await calculateAnesthesiaBenefit(
        deps, PHYSICIAN_ID, ['99100'], '23:00', '01:00',
      );

      // 23:00 to 01:00 = 120 minutes (overnight)
      expect(result.timeBasedComponent).toBeGreaterThan(0);
    });

    it('should include total benefit as sum of base and time', async () => {
      const result = await calculateAnesthesiaBenefit(
        deps, PHYSICIAN_ID, ['99100'], '08:00', '09:00',
      );

      expect(result.totalBenefit).toBe(result.baseBenefit + result.timeBasedComponent);
    });
  });
});
