import { createHash } from 'node:crypto';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createOnboardingRepository } from './onboarding.repository.js';
import type {
  OnboardingServiceDeps,
  TemplateRenderer,
  PdfGenerator,
  FileStorage,
} from './onboarding.service.js';
import {
  getOrCreateProgress,
  getOnboardingStatus,
  completeStep1,
  completeStep2,
  completeStep3,
  completeStep4,
  completeStep5,
  completeStep6,
  completeStep7,
  renderIma,
  acknowledgeIma,
  downloadImaPdf,
  checkImaCurrentVersion,
  generateAhc11236Pdf,
  downloadPiaPdf,
  completeGuidedTour,
  dismissGuidedTour,
  shouldShowGuidedTour,
  completePatientImport,
  confirmBaActive,
} from './onboarding.service.js';

// ---------------------------------------------------------------------------
// In-memory stores
// ---------------------------------------------------------------------------

let progressStore: Record<string, any>[];
let imaStore: Record<string, any>[];

// ---------------------------------------------------------------------------
// Mock Drizzle DB
// ---------------------------------------------------------------------------

function makeMockDb() {
  function getStoreForTable(table: any): Record<string, any>[] {
    if (table?.__table === 'ima_records') return imaStore;
    return progressStore;
  }

  function chainable(ctx: {
    op: string;
    table?: any;
    values?: any;
    setClauses?: any;
    whereClauses: Array<(row: any) => boolean>;
    limitN?: number;
    orderByFns: Array<{ field: string; direction: 'asc' | 'desc' }>;
  }) {
    const chain: any = {
      _ctx: ctx,
      values(v: any) { ctx.values = v; return chain; },
      set(s: any) { ctx.setClauses = s; return chain; },
      from(table: any) { ctx.table = table; return chain; },
      where(clause: any) {
        if (typeof clause === 'function') {
          ctx.whereClauses.push(clause);
        } else if (clause && typeof clause === 'object' && clause.__predicate) {
          ctx.whereClauses.push(clause.__predicate);
        }
        return chain;
      },
      orderBy(...args: any[]) {
        for (const arg of args) {
          if (arg && arg.__orderBy) {
            ctx.orderByFns.push(arg.__orderBy);
          }
        }
        return chain;
      },
      limit(n: number) { ctx.limitN = n; return chain; },
      returning() { return chain; },
      then(resolve: any, reject?: any) {
        try {
          const result = executeOp(ctx);
          resolve(result);
        } catch (e) {
          if (reject) reject(e); else throw e;
        }
      },
    };
    return chain;
  }

  function insertProgressRow(values: any): any {
    // Enforce unique provider_id
    const duplicate = progressStore.find(
      (p) => p.providerId === values.providerId,
    );
    if (duplicate) {
      const err: any = new Error(
        'duplicate key value violates unique constraint "onboarding_progress_provider_id_idx"',
      );
      err.code = '23505';
      throw err;
    }

    const newProgress = {
      progressId: values.progressId ?? crypto.randomUUID(),
      providerId: values.providerId,
      step1Completed: values.step1Completed ?? false,
      step2Completed: values.step2Completed ?? false,
      step3Completed: values.step3Completed ?? false,
      step4Completed: values.step4Completed ?? false,
      step5Completed: values.step5Completed ?? false,
      step6Completed: values.step6Completed ?? false,
      step7Completed: values.step7Completed ?? false,
      patientImportCompleted: values.patientImportCompleted ?? false,
      guidedTourCompleted: values.guidedTourCompleted ?? false,
      guidedTourDismissed: values.guidedTourDismissed ?? false,
      startedAt: values.startedAt ?? new Date(),
      completedAt: values.completedAt ?? null,
    };
    progressStore.push(newProgress);
    return newProgress;
  }

  function insertImaRow(values: any): any {
    const newIma = {
      imaId: values.imaId ?? crypto.randomUUID(),
      providerId: values.providerId,
      templateVersion: values.templateVersion,
      documentHash: values.documentHash,
      acknowledgedAt: values.acknowledgedAt ?? new Date(),
      ipAddress: values.ipAddress,
      userAgent: values.userAgent,
    };
    imaStore.push(newIma);
    return newIma;
  }

  function executeOp(ctx: any): any[] {
    const store = getStoreForTable(ctx.table);

    switch (ctx.op) {
      case 'select': {
        let matches = store.filter((row) =>
          ctx.whereClauses.every((pred: any) => pred(row)),
        );
        // Apply ordering
        for (const ob of ctx.orderByFns) {
          matches.sort((a, b) => {
            const aVal = a[ob.field];
            const bVal = b[ob.field];
            if (aVal < bVal) return ob.direction === 'asc' ? -1 : 1;
            if (aVal > bVal) return ob.direction === 'asc' ? 1 : -1;
            return 0;
          });
        }
        const limited = ctx.limitN ? matches.slice(0, ctx.limitN) : matches;
        return limited;
      }
      case 'insert': {
        const isIma = ctx.table?.__table === 'ima_records';
        const values = ctx.values;
        if (Array.isArray(values)) {
          return values.map((v: any) =>
            isIma ? insertImaRow(v) : insertProgressRow(v),
          );
        }
        return [isIma ? insertImaRow(values) : insertProgressRow(values)];
      }
      case 'update': {
        const updated: any[] = [];
        const matches = store.filter((row) =>
          ctx.whereClauses.every((pred: any) => pred(row)),
        );
        for (const row of matches) {
          const setClauses = ctx.setClauses;
          if (!setClauses) continue;
          for (const [key, value] of Object.entries(setClauses)) {
            (row as any)[key] = value;
          }
          updated.push({ ...row });
        }
        return updated;
      }
      default:
        return [];
    }
  }

  const mockDb: any = {
    insert(table: any) {
      return chainable({ op: 'insert', table, whereClauses: [], orderByFns: [] });
    },
    select() {
      return chainable({ op: 'select', whereClauses: [], orderByFns: [] });
    },
    update(table: any) {
      return chainable({ op: 'update', table, whereClauses: [], orderByFns: [] });
    },
  };

  return mockDb;
}

// ---------------------------------------------------------------------------
// Mock drizzle-orm operators
// ---------------------------------------------------------------------------

vi.mock('drizzle-orm', () => {
  return {
    eq: (column: any, value: any) => {
      const colName = column?.name;
      return {
        __predicate: (row: any) => row[colName] === value,
      };
    },
    and: (...conditions: any[]) => {
      return {
        __predicate: (row: any) =>
          conditions.every((c: any) => {
            if (!c) return true;
            if (c.__predicate) return c.__predicate(row);
            return true;
          }),
      };
    },
    desc: (column: any) => {
      const colName = column?.name;
      return {
        __orderBy: { field: colName, direction: 'desc' as const },
      };
    },
  };
});

// ---------------------------------------------------------------------------
// Mock the onboarding schema module
// ---------------------------------------------------------------------------

vi.mock('@meritum/shared/schemas/db/onboarding.schema.js', () => {
  const makeCol = (name: string) => ({ name });

  const onboardingProgressProxy: any = {
    __table: 'onboarding_progress',
    progressId: makeCol('progressId'),
    providerId: makeCol('providerId'),
    step1Completed: makeCol('step1Completed'),
    step2Completed: makeCol('step2Completed'),
    step3Completed: makeCol('step3Completed'),
    step4Completed: makeCol('step4Completed'),
    step5Completed: makeCol('step5Completed'),
    step6Completed: makeCol('step6Completed'),
    step7Completed: makeCol('step7Completed'),
    patientImportCompleted: makeCol('patientImportCompleted'),
    guidedTourCompleted: makeCol('guidedTourCompleted'),
    guidedTourDismissed: makeCol('guidedTourDismissed'),
    startedAt: makeCol('startedAt'),
    completedAt: makeCol('completedAt'),
  };

  const imaRecordsProxy: any = {
    __table: 'ima_records',
    imaId: makeCol('imaId'),
    providerId: makeCol('providerId'),
    templateVersion: makeCol('templateVersion'),
    documentHash: makeCol('documentHash'),
    acknowledgedAt: makeCol('acknowledgedAt'),
    ipAddress: makeCol('ipAddress'),
    userAgent: makeCol('userAgent'),
  };

  return {
    onboardingProgress: onboardingProgressProxy,
    imaRecords: imaRecordsProxy,
  };
});

// ---------------------------------------------------------------------------
// Mock the onboarding constants module
// ---------------------------------------------------------------------------

vi.mock('@meritum/shared/constants/onboarding.constants.js', () => {
  return {
    REQUIRED_ONBOARDING_STEPS: new Set([1, 2, 3, 4, 7]),
    OnboardingStep: {
      PROFESSIONAL_IDENTITY: 1,
      SPECIALTY_TYPE: 2,
      BUSINESS_ARRANGEMENT: 3,
      PRACTICE_LOCATION: 4,
      WCB_CONFIGURATION: 5,
      SUBMISSION_PREFERENCES: 6,
      IMA_ACKNOWLEDGEMENT: 7,
    },
    OnboardingAuditAction: {
      STARTED: 'onboarding.started',
      STEP_COMPLETED: 'onboarding.step_completed',
      COMPLETED: 'onboarding.completed',
      IMA_ACKNOWLEDGED: 'onboarding.ima_acknowledged',
      IMA_DOWNLOADED: 'onboarding.ima_downloaded',
      AHC11236_DOWNLOADED: 'onboarding.ahc11236_downloaded',
      PIA_DOWNLOADED: 'onboarding.pia_downloaded',
      PATIENT_IMPORT_COMPLETED: 'onboarding.patient_import_completed',
      GUIDED_TOUR_COMPLETED: 'onboarding.guided_tour_completed',
      GUIDED_TOUR_DISMISSED: 'onboarding.guided_tour_dismissed',
      BA_STATUS_UPDATED: 'onboarding.ba_status_updated',
    },
    BALinkageStatus: {
      PENDING: 'PENDING',
      ACTIVE: 'ACTIVE',
      INACTIVE: 'INACTIVE',
    },
    IMA_TEMPLATE_VERSION: '1.0.0',
    GuidedTourStop: {
      DASHBOARD_OVERVIEW: 'DASHBOARD_OVERVIEW',
      CREATE_CLAIM: 'CREATE_CLAIM',
      AI_COACH: 'AI_COACH',
      THURSDAY_BATCH: 'THURSDAY_BATCH',
      NOTIFICATIONS: 'NOTIFICATIONS',
      HELP: 'HELP',
    },
  };
});

// ---------------------------------------------------------------------------
// Mock errors module
// ---------------------------------------------------------------------------

vi.mock('../../lib/errors.js', () => {
  class AppError extends Error {
    constructor(
      public statusCode: number,
      public code: string,
      message: string,
      public details?: unknown,
    ) {
      super(message);
    }
  }
  class ValidationError extends AppError {
    constructor(message: string, details?: unknown) {
      super(400, 'VALIDATION_ERROR', message, details);
    }
  }
  class NotFoundError extends AppError {
    constructor(resource: string) {
      super(404, 'NOT_FOUND', `${resource} not found`);
    }
  }
  class ConflictError extends AppError {
    constructor(message: string) {
      super(409, 'CONFLICT', message);
    }
  }
  class BusinessRuleError extends AppError {
    constructor(message: string, details?: unknown) {
      super(422, 'BUSINESS_RULE_VIOLATION', message, details);
    }
  }
  return { AppError, ValidationError, NotFoundError, ConflictError, BusinessRuleError };
});

// ---------------------------------------------------------------------------
// Test data helpers
// ---------------------------------------------------------------------------

const PROVIDER_1 = crypto.randomUUID();
const PROVIDER_2 = crypto.randomUUID();

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Onboarding Repository', () => {
  let repo: ReturnType<typeof createOnboardingRepository>;

  beforeEach(() => {
    progressStore = [];
    imaStore = [];
    repo = createOnboardingRepository(makeMockDb());
  });

  // =========================================================================
  // createProgress
  // =========================================================================

  it('createProgress creates record with all steps false', async () => {
    const result = await repo.createProgress(PROVIDER_1);

    expect(result.progressId).toBeDefined();
    expect(result.providerId).toBe(PROVIDER_1);
    expect(result.step1Completed).toBe(false);
    expect(result.step2Completed).toBe(false);
    expect(result.step3Completed).toBe(false);
    expect(result.step4Completed).toBe(false);
    expect(result.step5Completed).toBe(false);
    expect(result.step6Completed).toBe(false);
    expect(result.step7Completed).toBe(false);
    expect(result.patientImportCompleted).toBe(false);
    expect(result.guidedTourCompleted).toBe(false);
    expect(result.guidedTourDismissed).toBe(false);
    expect(result.startedAt).toBeInstanceOf(Date);
    expect(result.completedAt).toBeNull();
    expect(progressStore).toHaveLength(1);
  });

  it('createProgress rejects duplicate provider_id', async () => {
    await repo.createProgress(PROVIDER_1);

    await expect(repo.createProgress(PROVIDER_1)).rejects.toThrow(
      'Onboarding progress already exists for this provider',
    );
    expect(progressStore).toHaveLength(1);
  });

  // =========================================================================
  // findProgressByProviderId
  // =========================================================================

  it('findProgressByProviderId returns progress for existing provider', async () => {
    await repo.createProgress(PROVIDER_1);

    const found = await repo.findProgressByProviderId(PROVIDER_1);

    expect(found).not.toBeNull();
    expect(found!.providerId).toBe(PROVIDER_1);
  });

  it('findProgressByProviderId returns null for non-existent provider', async () => {
    const found = await repo.findProgressByProviderId(PROVIDER_2);

    expect(found).toBeNull();
  });

  // =========================================================================
  // markStepCompleted
  // =========================================================================

  it('markStepCompleted sets specific step to true', async () => {
    await repo.createProgress(PROVIDER_1);

    const result = await repo.markStepCompleted(PROVIDER_1, 1);

    expect(result.step1Completed).toBe(true);
    // Other steps remain false
    expect(result.step2Completed).toBe(false);
    expect(result.step3Completed).toBe(false);
    expect(result.step4Completed).toBe(false);
    expect(result.step5Completed).toBe(false);
    expect(result.step6Completed).toBe(false);
    expect(result.step7Completed).toBe(false);
  });

  it('markStepCompleted is idempotent (re-completing a step is no-op)', async () => {
    await repo.createProgress(PROVIDER_1);

    await repo.markStepCompleted(PROVIDER_1, 3);
    const result = await repo.markStepCompleted(PROVIDER_1, 3);

    expect(result.step3Completed).toBe(true);
    expect(progressStore).toHaveLength(1);
  });

  it('markStepCompleted rejects invalid step number', async () => {
    await repo.createProgress(PROVIDER_1);

    await expect(repo.markStepCompleted(PROVIDER_1, 8)).rejects.toThrow(
      'Invalid step number: 8',
    );
    await expect(repo.markStepCompleted(PROVIDER_1, 0)).rejects.toThrow(
      'Invalid step number: 0',
    );
  });

  // =========================================================================
  // markOnboardingCompleted
  // =========================================================================

  it('markOnboardingCompleted sets completed_at when required steps done', async () => {
    await repo.createProgress(PROVIDER_1);

    // Complete all required steps: 1, 2, 3, 4, 7
    await repo.markStepCompleted(PROVIDER_1, 1);
    await repo.markStepCompleted(PROVIDER_1, 2);
    await repo.markStepCompleted(PROVIDER_1, 3);
    await repo.markStepCompleted(PROVIDER_1, 4);
    await repo.markStepCompleted(PROVIDER_1, 7);

    const result = await repo.markOnboardingCompleted(PROVIDER_1);

    expect(result.completedAt).toBeInstanceOf(Date);
  });

  it('markOnboardingCompleted throws when required steps incomplete', async () => {
    await repo.createProgress(PROVIDER_1);

    // Only complete steps 1 and 2 — missing 3, 4, 7
    await repo.markStepCompleted(PROVIDER_1, 1);
    await repo.markStepCompleted(PROVIDER_1, 2);

    await expect(repo.markOnboardingCompleted(PROVIDER_1)).rejects.toThrow(
      'Cannot complete onboarding: required steps incomplete',
    );
  });

  it('markOnboardingCompleted does not require optional steps', async () => {
    await repo.createProgress(PROVIDER_1);

    // Complete required steps only (1, 2, 3, 4, 7) — skip 5 and 6
    await repo.markStepCompleted(PROVIDER_1, 1);
    await repo.markStepCompleted(PROVIDER_1, 2);
    await repo.markStepCompleted(PROVIDER_1, 3);
    await repo.markStepCompleted(PROVIDER_1, 4);
    await repo.markStepCompleted(PROVIDER_1, 7);

    const result = await repo.markOnboardingCompleted(PROVIDER_1);

    expect(result.completedAt).toBeInstanceOf(Date);
    expect(result.step5Completed).toBe(false);
    expect(result.step6Completed).toBe(false);
  });

  // =========================================================================
  // markGuidedTourCompleted
  // =========================================================================

  it('markGuidedTourCompleted sets tour completed', async () => {
    await repo.createProgress(PROVIDER_1);

    const result = await repo.markGuidedTourCompleted(PROVIDER_1);

    expect(result.guidedTourCompleted).toBe(true);
  });

  // =========================================================================
  // markGuidedTourDismissed
  // =========================================================================

  it('markGuidedTourDismissed sets tour dismissed', async () => {
    await repo.createProgress(PROVIDER_1);

    const result = await repo.markGuidedTourDismissed(PROVIDER_1);

    expect(result.guidedTourDismissed).toBe(true);
  });

  // =========================================================================
  // markPatientImportCompleted
  // =========================================================================

  it('markPatientImportCompleted sets patient import completed', async () => {
    await repo.createProgress(PROVIDER_1);

    const result = await repo.markPatientImportCompleted(PROVIDER_1);

    expect(result.patientImportCompleted).toBe(true);
  });

  // =========================================================================
  // IMA Records — createImaRecord
  // =========================================================================

  it('createImaRecord inserts record with correct fields and acknowledged_at', async () => {
    const result = await repo.createImaRecord({
      providerId: PROVIDER_1,
      templateVersion: '1.0',
      documentHash: 'abc123def456',
      ipAddress: '192.168.1.1',
      userAgent: 'Mozilla/5.0',
    });

    expect(result.imaId).toBeDefined();
    expect(result.providerId).toBe(PROVIDER_1);
    expect(result.templateVersion).toBe('1.0');
    expect(result.documentHash).toBe('abc123def456');
    expect(result.ipAddress).toBe('192.168.1.1');
    expect(result.userAgent).toBe('Mozilla/5.0');
    expect(result.acknowledgedAt).toBeInstanceOf(Date);
    expect(imaStore).toHaveLength(1);
  });

  // =========================================================================
  // IMA Records — findLatestImaRecord
  // =========================================================================

  it('findLatestImaRecord returns most recent for provider', async () => {
    // Insert two records with different timestamps
    const older = new Date('2026-01-01T00:00:00Z');
    const newer = new Date('2026-02-01T00:00:00Z');

    imaStore.push({
      imaId: crypto.randomUUID(),
      providerId: PROVIDER_1,
      templateVersion: '1.0',
      documentHash: 'hash-v1',
      acknowledgedAt: older,
      ipAddress: '10.0.0.1',
      userAgent: 'Agent/1',
    });
    imaStore.push({
      imaId: crypto.randomUUID(),
      providerId: PROVIDER_1,
      templateVersion: '2.0',
      documentHash: 'hash-v2',
      acknowledgedAt: newer,
      ipAddress: '10.0.0.2',
      userAgent: 'Agent/2',
    });

    const result = await repo.findLatestImaRecord(PROVIDER_1);

    expect(result).not.toBeNull();
    expect(result!.templateVersion).toBe('2.0');
    expect(result!.acknowledgedAt).toEqual(newer);
  });

  it('findLatestImaRecord returns null for provider with no IMA records', async () => {
    const result = await repo.findLatestImaRecord(PROVIDER_1);

    expect(result).toBeNull();
  });

  // =========================================================================
  // IMA Records — listImaRecords
  // =========================================================================

  it('listImaRecords returns all records in reverse chronological order', async () => {
    const t1 = new Date('2026-01-01T00:00:00Z');
    const t2 = new Date('2026-02-01T00:00:00Z');
    const t3 = new Date('2026-03-01T00:00:00Z');

    imaStore.push({
      imaId: crypto.randomUUID(),
      providerId: PROVIDER_1,
      templateVersion: '1.0',
      documentHash: 'hash-1',
      acknowledgedAt: t1,
      ipAddress: '10.0.0.1',
      userAgent: 'Agent/1',
    });
    imaStore.push({
      imaId: crypto.randomUUID(),
      providerId: PROVIDER_1,
      templateVersion: '2.0',
      documentHash: 'hash-2',
      acknowledgedAt: t3,
      ipAddress: '10.0.0.2',
      userAgent: 'Agent/2',
    });
    imaStore.push({
      imaId: crypto.randomUUID(),
      providerId: PROVIDER_1,
      templateVersion: '1.5',
      documentHash: 'hash-1.5',
      acknowledgedAt: t2,
      ipAddress: '10.0.0.3',
      userAgent: 'Agent/3',
    });

    const results = await repo.listImaRecords(PROVIDER_1);

    expect(results).toHaveLength(3);
    expect(results[0].templateVersion).toBe('2.0');
    expect(results[1].templateVersion).toBe('1.5');
    expect(results[2].templateVersion).toBe('1.0');
  });

  // =========================================================================
  // IMA Records — Append-Only (no update or delete)
  // =========================================================================

  it('ima_records has no update function exported by repository', () => {
    // Verify the repository does not expose updateImaRecord or similar
    const repoKeys = Object.keys(repo);
    const imaUpdateKeys = repoKeys.filter(
      (k) => k.toLowerCase().includes('ima') && k.toLowerCase().includes('update'),
    );
    expect(imaUpdateKeys).toHaveLength(0);
  });

  it('ima_records has no delete function exported by repository', () => {
    // Verify the repository does not expose deleteImaRecord or similar
    const repoKeys = Object.keys(repo);
    const imaDeleteKeys = repoKeys.filter(
      (k) => k.toLowerCase().includes('ima') && k.toLowerCase().includes('delete'),
    );
    expect(imaDeleteKeys).toHaveLength(0);
  });
});

// ===========================================================================
// Onboarding Service Tests
// ===========================================================================

describe('Onboarding Service', () => {
  const PROVIDER_A = crypto.randomUUID();
  const USER_A = PROVIDER_A; // 1:1 mapping in this codebase

  // Mock repository
  let mockRepo: any;
  // Mock audit repo
  let mockAuditRepo: any;
  // Mock event emitter
  let mockEvents: any;
  // Mock provider service
  let mockProviderService: any;
  // Mock reference data service
  let mockReferenceData: any;
  // Service deps
  let deps: OnboardingServiceDeps;

  // Progress record factory
  function makeProgress(overrides?: Partial<any>): any {
    return {
      progressId: crypto.randomUUID(),
      providerId: PROVIDER_A,
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
      ...overrides,
    };
  }

  beforeEach(() => {
    mockRepo = {
      createProgress: vi.fn(),
      findProgressByProviderId: vi.fn(),
      markStepCompleted: vi.fn(),
      markOnboardingCompleted: vi.fn(),
      markPatientImportCompleted: vi.fn(),
      markGuidedTourCompleted: vi.fn(),
      markGuidedTourDismissed: vi.fn(),
      createImaRecord: vi.fn(),
      findLatestImaRecord: vi.fn(),
      listImaRecords: vi.fn(),
    };

    mockAuditRepo = {
      appendAuditLog: vi.fn().mockResolvedValue(undefined),
    };

    mockEvents = {
      emit: vi.fn(),
    };

    mockProviderService = {
      createOrUpdateProvider: vi.fn().mockResolvedValue({ providerId: PROVIDER_A }),
      updateProviderSpecialty: vi.fn().mockResolvedValue(undefined),
      createBa: vi.fn().mockResolvedValue({ baId: crypto.randomUUID() }),
      createLocation: vi.fn().mockResolvedValue({ locationId: crypto.randomUUID() }),
      createWcbConfig: vi.fn().mockResolvedValue({ wcbConfigId: crypto.randomUUID() }),
      updateSubmissionPreferences: vi.fn().mockResolvedValue(undefined),
      findProviderByUserId: vi.fn(),
      getProviderDetails: vi.fn().mockResolvedValue({
        billingNumber: '12345',
        cpsaRegistrationNumber: 'CPSA-001',
        firstName: 'John',
        lastName: 'Smith',
        baNumbers: ['BA-001', 'BA-002'],
      }),
    };

    mockReferenceData = {
      validateSpecialtyCode: vi.fn().mockResolvedValue(true),
      validateFunctionalCentreCode: vi.fn().mockResolvedValue(true),
      validateCommunityCode: vi.fn().mockResolvedValue(true),
      getRrnpRate: vi.fn().mockResolvedValue(null),
      getWcbFormTypes: vi.fn().mockResolvedValue(['C-WCB-PHYS', 'C-WCB-SURG']),
    };

    deps = {
      repo: mockRepo,
      auditRepo: mockAuditRepo,
      events: mockEvents,
      providerService: mockProviderService,
      referenceData: mockReferenceData,
    };
  });

  // =========================================================================
  // getOrCreateProgress
  // =========================================================================

  it('getOrCreateProgress creates new progress on first call', async () => {
    const newProgress = makeProgress();
    mockRepo.findProgressByProviderId.mockResolvedValue(null);
    mockRepo.createProgress.mockResolvedValue(newProgress);

    const result = await getOrCreateProgress(deps, PROVIDER_A);

    expect(mockRepo.findProgressByProviderId).toHaveBeenCalledWith(PROVIDER_A);
    expect(mockRepo.createProgress).toHaveBeenCalledWith(PROVIDER_A);
    expect(result.progress).toEqual(newProgress);
    expect(result.current_step).toBe(1); // First required step
    expect(result.is_complete).toBe(false);
    expect(result.required_steps_remaining).toBe(5); // Steps 1,2,3,4,7
    expect(mockAuditRepo.appendAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'onboarding.started' }),
    );
  });

  it('getOrCreateProgress returns existing progress on subsequent calls', async () => {
    const existingProgress = makeProgress({ step1Completed: true });
    mockRepo.findProgressByProviderId.mockResolvedValue(existingProgress);

    const result = await getOrCreateProgress(deps, PROVIDER_A);

    expect(mockRepo.createProgress).not.toHaveBeenCalled();
    expect(result.progress).toEqual(existingProgress);
    expect(result.current_step).toBe(2); // Step 1 done, next is 2
    expect(result.required_steps_remaining).toBe(4);
  });

  // =========================================================================
  // getOnboardingStatus
  // =========================================================================

  it('getOnboardingStatus returns is_complete false when steps incomplete', async () => {
    mockProviderService.findProviderByUserId.mockResolvedValue({ providerId: PROVIDER_A });
    const progress = makeProgress({ step1Completed: true });
    mockRepo.findProgressByProviderId.mockResolvedValue(progress);

    const result = await getOnboardingStatus(deps, USER_A);

    expect(result.has_provider).toBe(true);
    expect(result.is_complete).toBe(false);
    expect(result.progress).toEqual(progress);
  });

  it('getOnboardingStatus returns has_provider false when no provider', async () => {
    mockProviderService.findProviderByUserId.mockResolvedValue(null);

    const result = await getOnboardingStatus(deps, USER_A);

    expect(result.has_provider).toBe(false);
    expect(result.progress).toBeNull();
    expect(result.is_complete).toBe(false);
  });

  // =========================================================================
  // completeStep1 — Professional Identity
  // =========================================================================

  it('completeStep1 creates provider record and marks step complete', async () => {
    const updatedProgress = makeProgress({ step1Completed: true });
    mockRepo.markStepCompleted.mockResolvedValue(updatedProgress);

    const result = await completeStep1(deps, PROVIDER_A, {
      billing_number: '12345',
      cpsa_number: 'CPSA-001',
      legal_first_name: 'John',
      legal_last_name: 'Smith',
    });

    expect(mockProviderService.createOrUpdateProvider).toHaveBeenCalledWith(
      PROVIDER_A,
      {
        billingNumber: '12345',
        cpsaRegistrationNumber: 'CPSA-001',
        firstName: 'John',
        lastName: 'Smith',
      },
    );
    expect(mockRepo.markStepCompleted).toHaveBeenCalledWith(PROVIDER_A, 1);
    expect(result.progress.step1Completed).toBe(true);
    expect(mockAuditRepo.appendAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'onboarding.step_completed',
        detail: expect.objectContaining({ step_number: 1 }),
      }),
    );
  });

  it('completeStep1 validates billing number format (rejects non-5-digit)', async () => {
    await expect(
      completeStep1(deps, PROVIDER_A, {
        billing_number: '1234', // only 4 digits
        cpsa_number: 'CPSA-001',
        legal_first_name: 'John',
        legal_last_name: 'Smith',
      }),
    ).rejects.toThrow('Billing number must be exactly 5 digits');

    await expect(
      completeStep1(deps, PROVIDER_A, {
        billing_number: 'ABCDE', // non-numeric
        cpsa_number: 'CPSA-001',
        legal_first_name: 'John',
        legal_last_name: 'Smith',
      }),
    ).rejects.toThrow('Billing number must be exactly 5 digits');

    await expect(
      completeStep1(deps, PROVIDER_A, {
        billing_number: '123456', // 6 digits
        cpsa_number: 'CPSA-001',
        legal_first_name: 'John',
        legal_last_name: 'Smith',
      }),
    ).rejects.toThrow('Billing number must be exactly 5 digits');

    // Provider service should never be called
    expect(mockProviderService.createOrUpdateProvider).not.toHaveBeenCalled();
  });

  // =========================================================================
  // completeStep2 — Specialty & Type
  // =========================================================================

  it('completeStep2 validates specialty_code against Reference Data', async () => {
    // Valid specialty code
    const updatedProgress = makeProgress({ step2Completed: true });
    mockRepo.markStepCompleted.mockResolvedValue(updatedProgress);

    await completeStep2(deps, PROVIDER_A, {
      specialty_code: '01',
      physician_type: 'gp',
    });

    expect(mockReferenceData.validateSpecialtyCode).toHaveBeenCalledWith('01');
    expect(mockProviderService.updateProviderSpecialty).toHaveBeenCalledWith(
      PROVIDER_A,
      { specialtyCode: '01', physicianType: 'gp' },
    );
  });

  it('completeStep2 rejects invalid specialty_code', async () => {
    mockReferenceData.validateSpecialtyCode.mockResolvedValue(false);

    await expect(
      completeStep2(deps, PROVIDER_A, {
        specialty_code: 'INVALID',
        physician_type: 'gp',
      }),
    ).rejects.toThrow('Invalid specialty code');

    expect(mockProviderService.updateProviderSpecialty).not.toHaveBeenCalled();
  });

  // =========================================================================
  // completeStep3 — Business Arrangement
  // =========================================================================

  it('completeStep3 creates BA record with PENDING status', async () => {
    const updatedProgress = makeProgress({ step3Completed: true });
    mockRepo.markStepCompleted.mockResolvedValue(updatedProgress);

    await completeStep3(deps, PROVIDER_A, {
      primary_ba_number: 'BA-001',
      is_pcpcm_enrolled: false,
    });

    expect(mockProviderService.createBa).toHaveBeenCalledWith(PROVIDER_A, {
      baNumber: 'BA-001',
      baType: 'FFS',
      isPrimary: true,
      status: 'PENDING',
    });
    expect(mockRepo.markStepCompleted).toHaveBeenCalledWith(PROVIDER_A, 3);
  });

  it('completeStep3 with PCPCM enforces dual-BA present', async () => {
    await expect(
      completeStep3(deps, PROVIDER_A, {
        primary_ba_number: 'BA-001',
        is_pcpcm_enrolled: true,
        // Missing pcpcm_ba_number and ffs_ba_number
      }),
    ).rejects.toThrow('PCPCM enrolment requires both pcpcm_ba_number and ffs_ba_number');

    expect(mockProviderService.createBa).not.toHaveBeenCalled();
  });

  it('completeStep3 without PCPCM allows single BA', async () => {
    const updatedProgress = makeProgress({ step3Completed: true });
    mockRepo.markStepCompleted.mockResolvedValue(updatedProgress);

    const result = await completeStep3(deps, PROVIDER_A, {
      primary_ba_number: 'BA-001',
      is_pcpcm_enrolled: false,
    });

    // Only one BA created
    expect(mockProviderService.createBa).toHaveBeenCalledTimes(1);
    expect(result.progress.step3Completed).toBe(true);
  });

  it('completeStep3 with PCPCM creates multiple BA records', async () => {
    const updatedProgress = makeProgress({ step3Completed: true });
    mockRepo.markStepCompleted.mockResolvedValue(updatedProgress);

    await completeStep3(deps, PROVIDER_A, {
      primary_ba_number: 'BA-001',
      is_pcpcm_enrolled: true,
      pcpcm_ba_number: 'PCPCM-001',
      ffs_ba_number: 'FFS-001',
    });

    // Primary + FFS + PCPCM = 3 BA records
    expect(mockProviderService.createBa).toHaveBeenCalledTimes(3);
    expect(mockProviderService.createBa).toHaveBeenCalledWith(
      PROVIDER_A,
      expect.objectContaining({ baNumber: 'BA-001', baType: 'FFS', isPrimary: true }),
    );
    expect(mockProviderService.createBa).toHaveBeenCalledWith(
      PROVIDER_A,
      expect.objectContaining({ baNumber: 'PCPCM-001', baType: 'PCPCM' }),
    );
  });

  // =========================================================================
  // completeStep4 — Practice Location
  // =========================================================================

  it('completeStep4 validates functional_centre_code against Reference Data', async () => {
    const updatedProgress = makeProgress({ step4Completed: true });
    mockRepo.markStepCompleted.mockResolvedValue(updatedProgress);

    await completeStep4(deps, PROVIDER_A, {
      location_name: 'Main Clinic',
      functional_centre_code: 'FC01',
      address: {
        street: '123 Main St',
        city: 'Calgary',
        province: 'AB',
        postal_code: 'T2P1A1',
      },
      community_code: 'COM01',
    });

    expect(mockReferenceData.validateFunctionalCentreCode).toHaveBeenCalledWith('FC01');
    expect(mockReferenceData.validateCommunityCode).toHaveBeenCalledWith('COM01');
    expect(mockProviderService.createLocation).toHaveBeenCalledWith(
      PROVIDER_A,
      expect.objectContaining({
        name: 'Main Clinic',
        functionalCentre: 'FC01',
        communityCode: 'COM01',
      }),
    );
  });

  it('completeStep4 rejects invalid functional_centre_code', async () => {
    mockReferenceData.validateFunctionalCentreCode.mockResolvedValue(false);

    await expect(
      completeStep4(deps, PROVIDER_A, {
        location_name: 'Main Clinic',
        functional_centre_code: 'INVALID',
        address: {
          street: '123 Main St',
          city: 'Calgary',
          province: 'AB',
          postal_code: 'T2P1A1',
        },
        community_code: 'COM01',
      }),
    ).rejects.toThrow('Invalid functional centre code');
  });

  it('completeStep4 rejects invalid community_code', async () => {
    mockReferenceData.validateCommunityCode.mockResolvedValue(false);

    await expect(
      completeStep4(deps, PROVIDER_A, {
        location_name: 'Main Clinic',
        functional_centre_code: 'FC01',
        address: {
          street: '123 Main St',
          city: 'Calgary',
          province: 'AB',
          postal_code: 'T2P1A1',
        },
        community_code: 'INVALID',
      }),
    ).rejects.toThrow('Invalid community code');
  });

  it('completeStep4 calculates RRNP eligibility from community code', async () => {
    const updatedProgress = makeProgress({ step4Completed: true });
    mockRepo.markStepCompleted.mockResolvedValue(updatedProgress);
    mockReferenceData.getRrnpRate.mockResolvedValue({ rrnpPercentage: '15.00' });

    await completeStep4(deps, PROVIDER_A, {
      location_name: 'Rural Clinic',
      functional_centre_code: 'FC02',
      address: {
        street: '456 Rural Rd',
        city: 'Athabasca',
        province: 'AB',
        postal_code: 'T9S1A1',
      },
      community_code: 'RURAL01',
    });

    expect(mockProviderService.createLocation).toHaveBeenCalledWith(
      PROVIDER_A,
      expect.objectContaining({
        rrnpEligible: true,
        rrnpRate: '15.00',
      }),
    );
  });

  it('completeStep4 sets rrnpEligible false when no RRNP rate', async () => {
    const updatedProgress = makeProgress({ step4Completed: true });
    mockRepo.markStepCompleted.mockResolvedValue(updatedProgress);
    mockReferenceData.getRrnpRate.mockResolvedValue(null);

    await completeStep4(deps, PROVIDER_A, {
      location_name: 'Urban Clinic',
      functional_centre_code: 'FC01',
      address: {
        street: '789 Urban Ave',
        city: 'Calgary',
        province: 'AB',
        postal_code: 'T2P1A1',
      },
      community_code: 'URBAN01',
    });

    expect(mockProviderService.createLocation).toHaveBeenCalledWith(
      PROVIDER_A,
      expect.objectContaining({
        rrnpEligible: false,
        rrnpRate: null,
      }),
    );
  });

  // =========================================================================
  // completeStep5 — WCB Configuration (optional)
  // =========================================================================

  it('completeStep5 creates WCB configuration (optional step)', async () => {
    const updatedProgress = makeProgress({ step5Completed: true });
    mockRepo.markStepCompleted.mockResolvedValue(updatedProgress);

    await completeStep5(deps, PROVIDER_A, {
      contract_id: 'WCB-001',
      role: 'attending_physician',
      skill_code: 'GP',
    });

    expect(mockReferenceData.getWcbFormTypes).toHaveBeenCalledWith(
      'attending_physician',
      'GP',
    );
    expect(mockProviderService.createWcbConfig).toHaveBeenCalledWith(
      PROVIDER_A,
      expect.objectContaining({
        contractId: 'WCB-001',
        roleCode: 'attending_physician',
        skillCode: 'GP',
        permittedFormTypes: ['C-WCB-PHYS', 'C-WCB-SURG'],
      }),
    );
    expect(mockRepo.markStepCompleted).toHaveBeenCalledWith(PROVIDER_A, 5);
  });

  // =========================================================================
  // completeStep6 — Submission Preferences (optional)
  // =========================================================================

  it('completeStep6 sets submission preferences (optional step)', async () => {
    const updatedProgress = makeProgress({ step6Completed: true });
    mockRepo.markStepCompleted.mockResolvedValue(updatedProgress);

    await completeStep6(deps, PROVIDER_A, {
      ahcip_mode: 'auto_clean',
      wcb_mode: 'require_approval',
    });

    expect(mockProviderService.updateSubmissionPreferences).toHaveBeenCalledWith(
      PROVIDER_A,
      {
        ahcipSubmissionMode: 'auto_clean',
        wcbSubmissionMode: 'require_approval',
      },
    );
    expect(mockRepo.markStepCompleted).toHaveBeenCalledWith(PROVIDER_A, 6);
  });

  // =========================================================================
  // Completing all required steps sets onboarding_completed
  // =========================================================================

  it('completing steps 1, 2, 3, 4, 7 sets onboarding_completed', async () => {
    // After step 7, all required steps are done
    const allRequiredDone = makeProgress({
      step1Completed: true,
      step2Completed: true,
      step3Completed: true,
      step4Completed: true,
      step7Completed: true,
    });
    mockRepo.markStepCompleted.mockResolvedValue(allRequiredDone);
    mockRepo.markOnboardingCompleted.mockResolvedValue({
      ...allRequiredDone,
      completedAt: new Date(),
    });

    await completeStep7(deps, PROVIDER_A, '192.168.1.1', 'TestAgent/1.0');

    expect(mockRepo.markOnboardingCompleted).toHaveBeenCalledWith(PROVIDER_A);
    expect(mockAuditRepo.appendAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'onboarding.completed' }),
    );
    expect(mockEvents.emit).toHaveBeenCalledWith(
      'onboarding.completed',
      expect.objectContaining({ providerId: PROVIDER_A }),
    );
  });

  it('completing steps 1, 2, 3, 4 without 7 does NOT set onboarding_completed', async () => {
    // After step 4, step 7 still missing
    const missingStep7 = makeProgress({
      step1Completed: true,
      step2Completed: true,
      step3Completed: true,
      step4Completed: true,
      step7Completed: false,
    });
    mockRepo.markStepCompleted.mockResolvedValue(missingStep7);

    await completeStep4(deps, PROVIDER_A, {
      location_name: 'Main Clinic',
      functional_centre_code: 'FC01',
      address: {
        street: '123 Main St',
        city: 'Calgary',
        province: 'AB',
        postal_code: 'T2P1A1',
      },
      community_code: 'COM01',
    });

    expect(mockRepo.markOnboardingCompleted).not.toHaveBeenCalled();
  });

  // =========================================================================
  // Re-completing a step updates provider data
  // =========================================================================

  it('re-completing a step updates provider data', async () => {
    const updatedProgress = makeProgress({ step1Completed: true });
    mockRepo.markStepCompleted.mockResolvedValue(updatedProgress);

    // Complete step 1 a first time
    await completeStep1(deps, PROVIDER_A, {
      billing_number: '12345',
      cpsa_number: 'CPSA-001',
      legal_first_name: 'John',
      legal_last_name: 'Smith',
    });

    // Re-complete step 1 with updated data
    await completeStep1(deps, PROVIDER_A, {
      billing_number: '99999',
      cpsa_number: 'CPSA-002',
      legal_first_name: 'Jane',
      legal_last_name: 'Doe',
    });

    // Provider service called twice with different data
    expect(mockProviderService.createOrUpdateProvider).toHaveBeenCalledTimes(2);
    expect(mockProviderService.createOrUpdateProvider).toHaveBeenLastCalledWith(
      PROVIDER_A,
      {
        billingNumber: '99999',
        cpsaRegistrationNumber: 'CPSA-002',
        firstName: 'Jane',
        lastName: 'Doe',
      },
    );
    // Step marked twice
    expect(mockRepo.markStepCompleted).toHaveBeenCalledTimes(2);
  });
});

// ===========================================================================
// IMA, AHC11236, and PIA Document Operations
// ===========================================================================

describe('IMA Document Operations', () => {
  const PROVIDER_A = crypto.randomUUID();

  // Mock dependencies
  let mockRepo: any;
  let mockAuditRepo: any;
  let mockEvents: any;
  let mockProviderService: any;
  let mockReferenceData: any;
  let mockTemplateRenderer: TemplateRenderer;
  let mockPdfGenerator: PdfGenerator;
  let mockFileStorage: FileStorage;
  let deps: OnboardingServiceDeps;

  const IMA_TEMPLATE_CONTENT = '<html><body>{{physician_first_name}} {{physician_last_name}} - {{cpsa_number}} - {{ba_numbers}} - {{company_name}} - {{effective_date}} - {{template_version}}</body></html>';
  const MOCK_PDF_BUFFER = Buffer.from('mock-pdf-content');
  const MOCK_PIA_BUFFER = Buffer.from('mock-pia-document');

  function makeProgress(overrides?: Partial<any>): any {
    return {
      progressId: crypto.randomUUID(),
      providerId: PROVIDER_A,
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
      ...overrides,
    };
  }

  beforeEach(() => {
    mockRepo = {
      createProgress: vi.fn(),
      findProgressByProviderId: vi.fn(),
      markStepCompleted: vi.fn(),
      markOnboardingCompleted: vi.fn(),
      markPatientImportCompleted: vi.fn(),
      markGuidedTourCompleted: vi.fn(),
      markGuidedTourDismissed: vi.fn(),
      createImaRecord: vi.fn(),
      findLatestImaRecord: vi.fn(),
      listImaRecords: vi.fn(),
    };

    mockAuditRepo = {
      appendAuditLog: vi.fn().mockResolvedValue(undefined),
    };

    mockEvents = {
      emit: vi.fn(),
    };

    mockProviderService = {
      createOrUpdateProvider: vi.fn().mockResolvedValue({ providerId: PROVIDER_A }),
      updateProviderSpecialty: vi.fn().mockResolvedValue(undefined),
      createBa: vi.fn().mockResolvedValue({ baId: crypto.randomUUID() }),
      createLocation: vi.fn().mockResolvedValue({ locationId: crypto.randomUUID() }),
      createWcbConfig: vi.fn().mockResolvedValue({ wcbConfigId: crypto.randomUUID() }),
      updateSubmissionPreferences: vi.fn().mockResolvedValue(undefined),
      findProviderByUserId: vi.fn(),
      getProviderDetails: vi.fn().mockResolvedValue({
        billingNumber: '12345',
        cpsaRegistrationNumber: 'CPSA-001',
        firstName: 'John',
        lastName: 'Smith',
        baNumbers: ['BA-001', 'BA-002'],
      }),
    };

    mockReferenceData = {
      validateSpecialtyCode: vi.fn().mockResolvedValue(true),
      validateFunctionalCentreCode: vi.fn().mockResolvedValue(true),
      validateCommunityCode: vi.fn().mockResolvedValue(true),
      getRrnpRate: vi.fn().mockResolvedValue(null),
      getWcbFormTypes: vi.fn().mockResolvedValue(['C-WCB-PHYS', 'C-WCB-SURG']),
    };

    mockTemplateRenderer = {
      render: vi.fn((template: string, data: Record<string, unknown>) => {
        // Simple mustache-like replacement for testing
        let result = template;
        for (const [key, value] of Object.entries(data)) {
          result = result.replace(new RegExp(`\\{\\{${key}\\}\\}`, 'g'), String(value));
        }
        return result;
      }),
    };

    mockPdfGenerator = {
      htmlToPdf: vi.fn().mockResolvedValue(MOCK_PDF_BUFFER),
      generateAhc11236: vi.fn().mockResolvedValue(MOCK_PDF_BUFFER),
    };

    mockFileStorage = {
      store: vi.fn().mockResolvedValue(undefined),
      retrieve: vi.fn().mockResolvedValue(MOCK_PDF_BUFFER),
    };

    deps = {
      repo: mockRepo,
      auditRepo: mockAuditRepo,
      events: mockEvents,
      providerService: mockProviderService,
      referenceData: mockReferenceData,
      templateRenderer: mockTemplateRenderer,
      pdfGenerator: mockPdfGenerator,
      fileStorage: mockFileStorage,
      imaTemplate: IMA_TEMPLATE_CONTENT,
      piaPdfBuffer: MOCK_PIA_BUFFER,
      submitterPrefix: 'MRT',
    };
  });

  // =========================================================================
  // renderIma
  // =========================================================================

  it('renderIma pre-fills physician details correctly', async () => {
    const result = await renderIma(deps, PROVIDER_A);

    expect(result.html).toContain('John');
    expect(result.html).toContain('Smith');
    expect(result.html).toContain('CPSA-001');
    expect(result.html).toContain('BA-001, BA-002');
    expect(result.html).toContain('Meritum Health Technologies Inc.');
    expect(result.html).toContain('1.0.0');
    expect(result.templateVersion).toBe('1.0.0');

    expect(mockProviderService.getProviderDetails).toHaveBeenCalledWith(PROVIDER_A);
    expect(mockTemplateRenderer.render).toHaveBeenCalledWith(
      IMA_TEMPLATE_CONTENT,
      expect.objectContaining({
        physician_first_name: 'John',
        physician_last_name: 'Smith',
        cpsa_number: 'CPSA-001',
        ba_numbers: 'BA-001, BA-002',
      }),
    );
  });

  it('renderIma returns consistent SHA-256 hash for same input', async () => {
    const result1 = await renderIma(deps, PROVIDER_A);
    const result2 = await renderIma(deps, PROVIDER_A);

    expect(result1.hash).toBe(result2.hash);
    expect(result1.hash).toHaveLength(64); // SHA-256 hex length

    // Verify hash matches manual computation
    const expectedHash = createHash('sha256')
      .update(result1.html, 'utf-8')
      .digest('hex');
    expect(result1.hash).toBe(expectedHash);
  });

  it('renderIma throws NotFoundError when provider not found', async () => {
    mockProviderService.getProviderDetails.mockResolvedValue(null);

    await expect(renderIma(deps, PROVIDER_A)).rejects.toThrow('Provider not found');
  });

  it('renderIma throws when template renderer not configured', async () => {
    const depsNoRenderer = { ...deps, templateRenderer: undefined };

    await expect(renderIma(depsNoRenderer, PROVIDER_A)).rejects.toThrow(
      'Template renderer not configured',
    );
  });

  it('renderIma throws when IMA template not loaded', async () => {
    const depsNoTemplate = { ...deps, imaTemplate: undefined };

    await expect(renderIma(depsNoTemplate, PROVIDER_A)).rejects.toThrow(
      'IMA template not loaded',
    );
  });

  // =========================================================================
  // acknowledgeIma
  // =========================================================================

  it('acknowledgeIma verifies client hash matches server hash', async () => {
    // First render to get the correct hash
    const rendered = await renderIma(deps, PROVIDER_A);
    const correctHash = rendered.hash;

    const imaRecord = {
      imaId: crypto.randomUUID(),
      providerId: PROVIDER_A,
      templateVersion: '1.0.0',
      documentHash: correctHash,
      acknowledgedAt: new Date(),
      ipAddress: '192.168.1.1',
      userAgent: 'TestAgent/1.0',
    };
    mockRepo.createImaRecord.mockResolvedValue(imaRecord);
    mockRepo.markStepCompleted.mockResolvedValue(makeProgress({ step7Completed: true }));

    const result = await acknowledgeIma(
      deps,
      PROVIDER_A,
      correctHash,
      '192.168.1.1',
      'TestAgent/1.0',
    );

    expect(result.imaId).toBe(imaRecord.imaId);
    expect(result.documentHash).toBe(correctHash);
    expect(result.templateVersion).toBe('1.0.0');
  });

  it('acknowledgeIma rejects mismatched hash', async () => {
    await expect(
      acknowledgeIma(
        deps,
        PROVIDER_A,
        'wrong-hash-value',
        '192.168.1.1',
        'TestAgent/1.0',
      ),
    ).rejects.toThrow('Document hash mismatch');

    // IMA record should NOT have been created
    expect(mockRepo.createImaRecord).not.toHaveBeenCalled();
  });

  it('acknowledgeIma creates IMA record with correct fields', async () => {
    const rendered = await renderIma(deps, PROVIDER_A);

    const imaRecord = {
      imaId: crypto.randomUUID(),
      providerId: PROVIDER_A,
      templateVersion: '1.0.0',
      documentHash: rendered.hash,
      acknowledgedAt: new Date(),
      ipAddress: '10.0.0.1',
      userAgent: 'Chrome/120',
    };
    mockRepo.createImaRecord.mockResolvedValue(imaRecord);
    mockRepo.markStepCompleted.mockResolvedValue(makeProgress({ step7Completed: true }));

    await acknowledgeIma(deps, PROVIDER_A, rendered.hash, '10.0.0.1', 'Chrome/120');

    expect(mockRepo.createImaRecord).toHaveBeenCalledWith({
      providerId: PROVIDER_A,
      templateVersion: '1.0.0',
      documentHash: rendered.hash,
      ipAddress: '10.0.0.1',
      userAgent: 'Chrome/120',
    });
  });

  it('acknowledgeIma stores PDF to Spaces (mock DigitalOcean Spaces client)', async () => {
    const rendered = await renderIma(deps, PROVIDER_A);
    const imaId = crypto.randomUUID();

    const imaRecord = {
      imaId,
      providerId: PROVIDER_A,
      templateVersion: '1.0.0',
      documentHash: rendered.hash,
      acknowledgedAt: new Date(),
      ipAddress: '192.168.1.1',
      userAgent: 'TestAgent/1.0',
    };
    mockRepo.createImaRecord.mockResolvedValue(imaRecord);
    mockRepo.markStepCompleted.mockResolvedValue(makeProgress({ step7Completed: true }));

    await acknowledgeIma(
      deps,
      PROVIDER_A,
      rendered.hash,
      '192.168.1.1',
      'TestAgent/1.0',
    );

    // Verify PDF was generated from HTML
    expect(mockPdfGenerator.htmlToPdf).toHaveBeenCalledWith(rendered.html);

    // Verify PDF was stored with correct key and content type
    expect(mockFileStorage.store).toHaveBeenCalledWith(
      `ima/${PROVIDER_A}/${imaId}.pdf`,
      MOCK_PDF_BUFFER,
      'application/pdf',
    );
  });

  it('acknowledgeIma triggers step 7 completion', async () => {
    const rendered = await renderIma(deps, PROVIDER_A);

    const imaRecord = {
      imaId: crypto.randomUUID(),
      providerId: PROVIDER_A,
      templateVersion: '1.0.0',
      documentHash: rendered.hash,
      acknowledgedAt: new Date(),
      ipAddress: '192.168.1.1',
      userAgent: 'TestAgent/1.0',
    };
    mockRepo.createImaRecord.mockResolvedValue(imaRecord);
    mockRepo.markStepCompleted.mockResolvedValue(makeProgress({ step7Completed: true }));

    await acknowledgeIma(
      deps,
      PROVIDER_A,
      rendered.hash,
      '192.168.1.1',
      'TestAgent/1.0',
    );

    // Step 7 should be marked complete
    expect(mockRepo.markStepCompleted).toHaveBeenCalledWith(PROVIDER_A, 7);

    // IMA_ACKNOWLEDGED audit event should be emitted
    expect(mockAuditRepo.appendAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'onboarding.ima_acknowledged',
        resourceType: 'ima_record',
        resourceId: imaRecord.imaId,
      }),
    );
  });

  // =========================================================================
  // downloadImaPdf
  // =========================================================================

  it('downloadImaPdf returns stored PDF', async () => {
    const imaRecord = {
      imaId: crypto.randomUUID(),
      providerId: PROVIDER_A,
      templateVersion: '1.0.0',
      documentHash: 'abc123',
      acknowledgedAt: new Date(),
      ipAddress: '10.0.0.1',
      userAgent: 'Agent/1',
    };
    mockRepo.findLatestImaRecord.mockResolvedValue(imaRecord);

    const result = await downloadImaPdf(deps, PROVIDER_A);

    expect(result).toEqual(MOCK_PDF_BUFFER);
    expect(mockFileStorage.retrieve).toHaveBeenCalledWith(
      `ima/${PROVIDER_A}/${imaRecord.imaId}.pdf`,
    );
    expect(mockAuditRepo.appendAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'onboarding.ima_downloaded',
        resourceType: 'ima_record',
        resourceId: imaRecord.imaId,
      }),
    );
  });

  it('downloadImaPdf throws NotFoundError when no IMA record exists', async () => {
    mockRepo.findLatestImaRecord.mockResolvedValue(null);

    await expect(downloadImaPdf(deps, PROVIDER_A)).rejects.toThrow('IMA record not found');
  });

  // =========================================================================
  // checkImaCurrentVersion
  // =========================================================================

  it('checkImaCurrentVersion detects current template version', async () => {
    mockRepo.findLatestImaRecord.mockResolvedValue({
      imaId: crypto.randomUUID(),
      providerId: PROVIDER_A,
      templateVersion: '1.0.0', // matches IMA_TEMPLATE_VERSION
      documentHash: 'abc',
      acknowledgedAt: new Date(),
      ipAddress: '10.0.0.1',
      userAgent: 'Agent/1',
    });

    const result = await checkImaCurrentVersion(deps, PROVIDER_A);

    expect(result.is_current).toBe(true);
    expect(result.needs_reacknowledgement).toBe(false);
  });

  it('checkImaCurrentVersion detects outdated template version', async () => {
    mockRepo.findLatestImaRecord.mockResolvedValue({
      imaId: crypto.randomUUID(),
      providerId: PROVIDER_A,
      templateVersion: '0.9.0', // older than IMA_TEMPLATE_VERSION
      documentHash: 'abc',
      acknowledgedAt: new Date(),
      ipAddress: '10.0.0.1',
      userAgent: 'Agent/1',
    });

    const result = await checkImaCurrentVersion(deps, PROVIDER_A);

    expect(result.is_current).toBe(false);
    expect(result.needs_reacknowledgement).toBe(true);
  });

  it('checkImaCurrentVersion returns needs_reacknowledgement when no IMA exists', async () => {
    mockRepo.findLatestImaRecord.mockResolvedValue(null);

    const result = await checkImaCurrentVersion(deps, PROVIDER_A);

    expect(result.is_current).toBe(false);
    expect(result.needs_reacknowledgement).toBe(true);
  });

  // =========================================================================
  // generateAhc11236Pdf
  // =========================================================================

  it('generateAhc11236Pdf pre-fills correct physician and submitter details', async () => {
    const result = await generateAhc11236Pdf(deps, PROVIDER_A);

    expect(result).toEqual(MOCK_PDF_BUFFER);
    expect(mockPdfGenerator.generateAhc11236).toHaveBeenCalledWith({
      billingNumber: '12345',
      baNumber: 'BA-001',
      submitterPrefix: 'MRT',
      physicianName: 'Dr. John Smith',
    });
    expect(mockAuditRepo.appendAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'onboarding.ahc11236_downloaded',
        resourceType: 'ahc11236',
      }),
    );
  });

  it('generateAhc11236Pdf throws NotFoundError when provider not found', async () => {
    mockProviderService.getProviderDetails.mockResolvedValue(null);

    await expect(generateAhc11236Pdf(deps, PROVIDER_A)).rejects.toThrow(
      'Provider not found',
    );
  });

  it('generateAhc11236Pdf throws when PDF generator not configured', async () => {
    const depsNoPdf = { ...deps, pdfGenerator: undefined };

    await expect(generateAhc11236Pdf(depsNoPdf, PROVIDER_A)).rejects.toThrow(
      'PDF generator not configured',
    );
  });

  // =========================================================================
  // downloadPiaPdf
  // =========================================================================

  it('downloadPiaPdf returns static PIA document', async () => {
    const result = await downloadPiaPdf(deps);

    expect(result).toEqual(MOCK_PIA_BUFFER);
    expect(mockAuditRepo.appendAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'onboarding.pia_downloaded',
        resourceType: 'pia',
      }),
    );
  });

  it('downloadPiaPdf throws when PIA buffer not configured', async () => {
    const depsNoPia = { ...deps, piaPdfBuffer: undefined };

    await expect(downloadPiaPdf(depsNoPia)).rejects.toThrow(
      'PIA document not configured',
    );
  });
});

// ===========================================================================
// Guided Tour, Patient Import, and BA Status Operations
// ===========================================================================

describe('Guided Tour, Patient Import, and BA Status', () => {
  const PROVIDER_A = crypto.randomUUID();

  // Mock dependencies
  let mockRepo: any;
  let mockAuditRepo: any;
  let mockEvents: any;
  let mockProviderService: any;
  let mockReferenceData: any;
  let deps: OnboardingServiceDeps;

  function makeProgress(overrides?: Partial<any>): any {
    return {
      progressId: crypto.randomUUID(),
      providerId: PROVIDER_A,
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
      ...overrides,
    };
  }

  beforeEach(() => {
    mockRepo = {
      createProgress: vi.fn(),
      findProgressByProviderId: vi.fn(),
      markStepCompleted: vi.fn(),
      markOnboardingCompleted: vi.fn(),
      markPatientImportCompleted: vi.fn(),
      markGuidedTourCompleted: vi.fn(),
      markGuidedTourDismissed: vi.fn(),
      createImaRecord: vi.fn(),
      findLatestImaRecord: vi.fn(),
      listImaRecords: vi.fn(),
    };

    mockAuditRepo = {
      appendAuditLog: vi.fn().mockResolvedValue(undefined),
    };

    mockEvents = {
      emit: vi.fn(),
    };

    mockProviderService = {
      createOrUpdateProvider: vi.fn().mockResolvedValue({ providerId: PROVIDER_A }),
      updateProviderSpecialty: vi.fn().mockResolvedValue(undefined),
      createBa: vi.fn().mockResolvedValue({ baId: crypto.randomUUID() }),
      createLocation: vi.fn().mockResolvedValue({ locationId: crypto.randomUUID() }),
      createWcbConfig: vi.fn().mockResolvedValue({ wcbConfigId: crypto.randomUUID() }),
      updateSubmissionPreferences: vi.fn().mockResolvedValue(undefined),
      findProviderByUserId: vi.fn(),
      getProviderDetails: vi.fn().mockResolvedValue({
        billingNumber: '12345',
        cpsaRegistrationNumber: 'CPSA-001',
        firstName: 'John',
        lastName: 'Smith',
        baNumbers: ['BA-001', 'BA-002'],
      }),
      findBaById: vi.fn(),
      updateBaStatus: vi.fn().mockResolvedValue({ baId: crypto.randomUUID(), status: 'ACTIVE' }),
    };

    mockReferenceData = {
      validateSpecialtyCode: vi.fn().mockResolvedValue(true),
      validateFunctionalCentreCode: vi.fn().mockResolvedValue(true),
      validateCommunityCode: vi.fn().mockResolvedValue(true),
      getRrnpRate: vi.fn().mockResolvedValue(null),
      getWcbFormTypes: vi.fn().mockResolvedValue(['C-WCB-PHYS', 'C-WCB-SURG']),
    };

    deps = {
      repo: mockRepo,
      auditRepo: mockAuditRepo,
      events: mockEvents,
      providerService: mockProviderService,
      referenceData: mockReferenceData,
    };
  });

  // =========================================================================
  // completeGuidedTour
  // =========================================================================

  it('completeGuidedTour marks tour completed', async () => {
    const progress = makeProgress();
    mockRepo.findProgressByProviderId.mockResolvedValue(progress);
    mockRepo.markGuidedTourCompleted.mockResolvedValue({
      ...progress,
      guidedTourCompleted: true,
    });

    await completeGuidedTour(deps, PROVIDER_A);

    expect(mockRepo.markGuidedTourCompleted).toHaveBeenCalledWith(PROVIDER_A);
    expect(mockAuditRepo.appendAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'onboarding.guided_tour_completed',
        resourceType: 'onboarding_progress',
        resourceId: progress.progressId,
      }),
    );
    expect(mockEvents.emit).toHaveBeenCalledWith(
      'onboarding.guided_tour_completed',
      expect.objectContaining({ providerId: PROVIDER_A }),
    );
  });

  it('completeGuidedTour is idempotent', async () => {
    const progress = makeProgress({ guidedTourCompleted: true });
    mockRepo.findProgressByProviderId.mockResolvedValue(progress);

    await completeGuidedTour(deps, PROVIDER_A);

    // Should not call repo or audit again
    expect(mockRepo.markGuidedTourCompleted).not.toHaveBeenCalled();
    expect(mockAuditRepo.appendAuditLog).not.toHaveBeenCalled();
  });

  // =========================================================================
  // dismissGuidedTour
  // =========================================================================

  it('dismissGuidedTour marks tour dismissed', async () => {
    const progress = makeProgress();
    mockRepo.findProgressByProviderId.mockResolvedValue(progress);
    mockRepo.markGuidedTourDismissed.mockResolvedValue({
      ...progress,
      guidedTourDismissed: true,
    });

    await dismissGuidedTour(deps, PROVIDER_A);

    expect(mockRepo.markGuidedTourDismissed).toHaveBeenCalledWith(PROVIDER_A);
    expect(mockAuditRepo.appendAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'onboarding.guided_tour_dismissed',
        resourceType: 'onboarding_progress',
        resourceId: progress.progressId,
      }),
    );
    expect(mockEvents.emit).toHaveBeenCalledWith(
      'onboarding.guided_tour_dismissed',
      expect.objectContaining({ providerId: PROVIDER_A }),
    );
  });

  // =========================================================================
  // shouldShowGuidedTour
  // =========================================================================

  it('shouldShowGuidedTour returns true when onboarding complete and tour not done', async () => {
    const progress = makeProgress({ completedAt: new Date() });
    mockRepo.findProgressByProviderId.mockResolvedValue(progress);

    const result = await shouldShowGuidedTour(deps, PROVIDER_A);

    expect(result).toBe(true);
  });

  it('shouldShowGuidedTour returns false when tour completed', async () => {
    const progress = makeProgress({
      completedAt: new Date(),
      guidedTourCompleted: true,
    });
    mockRepo.findProgressByProviderId.mockResolvedValue(progress);

    const result = await shouldShowGuidedTour(deps, PROVIDER_A);

    expect(result).toBe(false);
  });

  it('shouldShowGuidedTour returns false when tour dismissed', async () => {
    const progress = makeProgress({
      completedAt: new Date(),
      guidedTourDismissed: true,
    });
    mockRepo.findProgressByProviderId.mockResolvedValue(progress);

    const result = await shouldShowGuidedTour(deps, PROVIDER_A);

    expect(result).toBe(false);
  });

  it('shouldShowGuidedTour returns false when onboarding not complete', async () => {
    const progress = makeProgress(); // completedAt is null
    mockRepo.findProgressByProviderId.mockResolvedValue(progress);

    const result = await shouldShowGuidedTour(deps, PROVIDER_A);

    expect(result).toBe(false);
  });

  // =========================================================================
  // completePatientImport
  // =========================================================================

  it('completePatientImport marks import completed on progress', async () => {
    const progress = makeProgress();
    mockRepo.findProgressByProviderId.mockResolvedValue(progress);
    mockRepo.markPatientImportCompleted.mockResolvedValue({
      ...progress,
      patientImportCompleted: true,
    });

    await completePatientImport(deps, PROVIDER_A);

    expect(mockRepo.markPatientImportCompleted).toHaveBeenCalledWith(PROVIDER_A);
    expect(mockAuditRepo.appendAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'onboarding.patient_import_completed',
        resourceType: 'onboarding_progress',
        resourceId: progress.progressId,
      }),
    );
    expect(mockEvents.emit).toHaveBeenCalledWith(
      'onboarding.patient_import_completed',
      expect.objectContaining({ providerId: PROVIDER_A }),
    );
  });

  // =========================================================================
  // confirmBaActive
  // =========================================================================

  it('confirmBaActive updates BA status from PENDING to ACTIVE', async () => {
    const baId = crypto.randomUUID();
    mockProviderService.findBaById.mockResolvedValue({
      baId,
      providerId: PROVIDER_A,
      status: 'PENDING',
    });

    await confirmBaActive(deps, PROVIDER_A, baId);

    expect(mockProviderService.findBaById).toHaveBeenCalledWith(baId, PROVIDER_A);
    expect(mockProviderService.updateBaStatus).toHaveBeenCalledWith(
      PROVIDER_A,
      baId,
      'ACTIVE',
      PROVIDER_A,
    );
    expect(mockAuditRepo.appendAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'onboarding.ba_status_updated',
        resourceType: 'business_arrangement',
        resourceId: baId,
        detail: expect.objectContaining({
          previous_status: 'PENDING',
          new_status: 'ACTIVE',
        }),
      }),
    );
    expect(mockEvents.emit).toHaveBeenCalledWith(
      'onboarding.ba_status_updated',
      expect.objectContaining({
        providerId: PROVIDER_A,
        baId,
        previousStatus: 'PENDING',
        newStatus: 'ACTIVE',
      }),
    );
  });

  it('confirmBaActive rejects if BA not in PENDING state', async () => {
    const baId = crypto.randomUUID();
    mockProviderService.findBaById.mockResolvedValue({
      baId,
      providerId: PROVIDER_A,
      status: 'ACTIVE', // Already active
    });

    await expect(confirmBaActive(deps, PROVIDER_A, baId)).rejects.toThrow(
      'Cannot confirm BA: current status is ACTIVE, expected PENDING',
    );

    expect(mockProviderService.updateBaStatus).not.toHaveBeenCalled();
  });

  it('confirmBaActive throws 404 if BA does not belong to provider', async () => {
    const baId = crypto.randomUUID();
    mockProviderService.findBaById.mockResolvedValue(null);

    await expect(confirmBaActive(deps, PROVIDER_A, baId)).rejects.toThrow(
      'Business arrangement not found',
    );

    expect(mockProviderService.updateBaStatus).not.toHaveBeenCalled();
  });
});
