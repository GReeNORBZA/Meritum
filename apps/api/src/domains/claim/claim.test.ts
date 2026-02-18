import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createClaimRepository } from './claim.repository.js';
import {
  createClaim,
  createClaimFromImport,
  createClaimFromShift,
  createShift,
  addEncounter,
  completeShift,
  getShiftDetails,
  validateClaim,
  queueClaim,
  unqueueClaim,
  approveFlaggedClaim,
  writeOffClaim,
  listRejectedClaims,
  getRejectionDetails,
  resubmitClaim,
  expireClaimWithContext,
  classifyCleanFlagged,
  getClaimsForAutoSubmission,
  reclassifyQueuedClaim,
  uploadImport,
  previewImport,
  commitImport,
  detectDelimiter,
  parseDate,
  parseRows,
  getClaimSuggestions,
  acceptSuggestion,
  dismissSuggestion,
  acknowledgeDuplicate,
  getSubmissionPreferences,
  updateSubmissionPreferences,
  requestExport,
  getExportStatus,
  generateExportFile,
  type ClaimServiceDeps,
  type ValidationResult,
  type NotificationEmitter,
  type SubmissionPreferenceLookup,
  type FacilityCheck,
  type AfterHoursPremiumCalculator,
  type ExplanatoryCodeLookup,
} from './claim.service.js';

// ---------------------------------------------------------------------------
// In-memory stores
// ---------------------------------------------------------------------------

let claimStore: Record<string, any>[];
let importBatchStore: Record<string, any>[];
let templateStore: Record<string, any>[];
let shiftStore: Record<string, any>[];
let exportStore: Record<string, any>[];
let auditStore: Record<string, any>[];

// ---------------------------------------------------------------------------
// Mock Drizzle DB
// ---------------------------------------------------------------------------

function makeMockDb() {
  function chainable(ctx: {
    op: string;
    table?: any;
    values?: any;
    setClauses?: any;
    selectFields?: any;
    whereClauses: Array<(row: any) => boolean>;
    limitN?: number;
    offsetN?: number;
    orderByFns?: Array<(a: any, b: any) => number>;
    groupByFields?: any[];
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
      limit(n: number) { ctx.limitN = n; return chain; },
      offset(n: number) { ctx.offsetN = n; return chain; },
      orderBy(...fns: any[]) {
        if (!ctx.orderByFns) ctx.orderByFns = [];
        for (const fn of fns) {
          if (typeof fn === 'function') {
            ctx.orderByFns.push(fn);
          } else if (fn && fn.__sortFn) {
            ctx.orderByFns.push(fn.__sortFn);
          } else if (fn && fn.name) {
            const colName = fn.name;
            ctx.orderByFns.push((a: any, b: any) => {
              const va = a[colName] ?? '';
              const vb = b[colName] ?? '';
              return va < vb ? -1 : va > vb ? 1 : 0;
            });
          }
        }
        return chain;
      },
      groupBy(...cols: any[]) {
        ctx.groupByFields = cols;
        return chain;
      },
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

  function insertClaimRow(values: any): any {
    const newClaim = {
      claimId: values.claimId ?? crypto.randomUUID(),
      physicianId: values.physicianId,
      patientId: values.patientId,
      claimType: values.claimType,
      state: values.state ?? 'DRAFT',
      isClean: values.isClean ?? null,
      importSource: values.importSource,
      importBatchId: values.importBatchId ?? null,
      shiftId: values.shiftId ?? null,
      dateOfService: values.dateOfService,
      submissionDeadline: values.submissionDeadline,
      submittedBatchId: values.submittedBatchId ?? null,
      validationResult: values.validationResult ?? null,
      validationTimestamp: values.validationTimestamp ?? null,
      referenceDataVersion: values.referenceDataVersion ?? null,
      aiCoachSuggestions: values.aiCoachSuggestions ?? null,
      duplicateAlert: values.duplicateAlert ?? null,
      flags: values.flags ?? null,
      createdAt: values.createdAt ?? new Date(),
      createdBy: values.createdBy,
      updatedAt: values.updatedAt ?? new Date(),
      updatedBy: values.updatedBy,
      deletedAt: values.deletedAt ?? null,
    };
    claimStore.push(newClaim);
    return newClaim;
  }

  function insertImportBatchRow(values: any): any {
    const newBatch = {
      importBatchId: values.importBatchId ?? crypto.randomUUID(),
      physicianId: values.physicianId,
      fileName: values.fileName,
      fileHash: values.fileHash,
      fieldMappingTemplateId: values.fieldMappingTemplateId ?? null,
      totalRows: values.totalRows,
      successCount: values.successCount,
      errorCount: values.errorCount,
      errorDetails: values.errorDetails ?? null,
      status: values.status,
      createdAt: values.createdAt ?? new Date(),
      createdBy: values.createdBy,
    };
    importBatchStore.push(newBatch);
    return newBatch;
  }

  function insertTemplateRow(values: any): any {
    const newTemplate = {
      templateId: values.templateId ?? crypto.randomUUID(),
      physicianId: values.physicianId,
      name: values.name,
      emrType: values.emrType ?? null,
      mappings: values.mappings,
      delimiter: values.delimiter ?? null,
      hasHeaderRow: values.hasHeaderRow,
      dateFormat: values.dateFormat ?? null,
      createdAt: values.createdAt ?? new Date(),
      updatedAt: values.updatedAt ?? new Date(),
    };
    templateStore.push(newTemplate);
    return newTemplate;
  }

  function insertShiftRow(values: any): any {
    const newShift = {
      shiftId: values.shiftId ?? crypto.randomUUID(),
      physicianId: values.physicianId,
      facilityId: values.facilityId,
      shiftDate: values.shiftDate,
      startTime: values.startTime ?? null,
      endTime: values.endTime ?? null,
      status: values.status ?? 'IN_PROGRESS',
      encounterCount: values.encounterCount ?? 0,
      createdAt: values.createdAt ?? new Date(),
      updatedAt: values.updatedAt ?? new Date(),
    };
    shiftStore.push(newShift);
    return newShift;
  }

  function insertExportRow(values: any): any {
    const newExport = {
      exportId: values.exportId ?? crypto.randomUUID(),
      physicianId: values.physicianId,
      dateFrom: values.dateFrom,
      dateTo: values.dateTo,
      claimType: values.claimType ?? null,
      format: values.format,
      status: values.status ?? 'PENDING',
      filePath: values.filePath ?? null,
      createdAt: values.createdAt ?? new Date(),
      updatedAt: values.updatedAt ?? new Date(),
    };
    exportStore.push(newExport);
    return newExport;
  }

  function insertAuditRow(values: any): any {
    const newAudit = {
      auditId: values.auditId ?? crypto.randomUUID(),
      claimId: values.claimId,
      action: values.action,
      previousState: values.previousState ?? null,
      newState: values.newState ?? null,
      changes: values.changes ?? null,
      actorId: values.actorId,
      actorContext: values.actorContext,
      reason: values.reason ?? null,
      createdAt: values.createdAt ?? new Date(),
    };
    auditStore.push(newAudit);
    return newAudit;
  }

  function getStoreForTable(ctx: any): Record<string, any>[] {
    if (ctx.table && ctx.table.__table === 'import_batches') {
      return importBatchStore;
    }
    if (ctx.table && ctx.table.__table === 'field_mapping_templates') {
      return templateStore;
    }
    if (ctx.table && ctx.table.__table === 'shifts') {
      return shiftStore;
    }
    if (ctx.table && ctx.table.__table === 'claim_exports') {
      return exportStore;
    }
    if (ctx.table && ctx.table.__table === 'claim_audit_history') {
      return auditStore;
    }
    return claimStore;
  }

  function executeOp(ctx: any): any[] {
    const store = getStoreForTable(ctx);

    switch (ctx.op) {
      case 'select': {
        let matches = store.filter((row) =>
          ctx.whereClauses.every((pred: any) => pred(row)),
        );

        // Handle count queries
        if (ctx.selectFields && ctx.selectFields.total && ctx.selectFields.total.__count) {
          return [{ total: matches.length }];
        }

        // Handle groupBy + count queries
        if (ctx.groupByFields && ctx.selectFields) {
          const groups = new Map<string, number>();
          for (const row of matches) {
            const key = ctx.groupByFields.map((col: any) => row[col.name]).join('|');
            groups.set(key, (groups.get(key) ?? 0) + 1);
          }
          const result: any[] = [];
          for (const [key, cnt] of groups) {
            const groupRow: any = {};
            ctx.groupByFields.forEach((col: any, i: number) => {
              groupRow[col.name] = key.split('|')[i];
            });
            // Map select fields
            for (const [alias, col] of Object.entries(ctx.selectFields)) {
              if ((col as any)?.__count) {
                groupRow[alias] = cnt;
              } else if ((col as any)?.name) {
                groupRow[alias] = groupRow[(col as any).name];
              }
            }
            result.push(groupRow);
          }
          return result;
        }

        // Apply sorting
        if (ctx.orderByFns && ctx.orderByFns.length > 0) {
          matches = [...matches].sort((a, b) => {
            for (const sortFn of ctx.orderByFns) {
              const result = sortFn(a, b);
              if (result !== 0) return result;
            }
            return 0;
          });
        }

        // Apply offset
        if (ctx.offsetN) {
          matches = matches.slice(ctx.offsetN);
        }

        // Apply limit
        const limited = ctx.limitN ? matches.slice(0, ctx.limitN) : matches;

        // Apply field projection if specific fields were selected
        if (ctx.selectFields && !ctx.selectFields.total) {
          return limited.map((row: any) => {
            const projected: any = {};
            for (const [alias, col] of Object.entries(ctx.selectFields)) {
              const colName = (col as any)?.name;
              if (colName) {
                projected[alias] = row[colName];
              }
            }
            return projected;
          });
        }

        return limited;
      }
      case 'insert': {
        const values = ctx.values;
        let insertFn = insertClaimRow;
        if (ctx.table && ctx.table.__table === 'import_batches') {
          insertFn = insertImportBatchRow;
        } else if (ctx.table && ctx.table.__table === 'field_mapping_templates') {
          insertFn = insertTemplateRow;
        } else if (ctx.table && ctx.table.__table === 'shifts') {
          insertFn = insertShiftRow;
        } else if (ctx.table && ctx.table.__table === 'claim_exports') {
          insertFn = insertExportRow;
        } else if (ctx.table && ctx.table.__table === 'claim_audit_history') {
          insertFn = insertAuditRow;
        }
        if (Array.isArray(values)) {
          return values.map((v: any) => insertFn(v));
        }
        return [insertFn(values)];
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
            // Handle sql`column + 1` computed values
            if (value && typeof value === 'object' && (value as any).__sql && (value as any).__computeValue) {
              const computed = (value as any).__computeValue(row);
              if (computed !== undefined) {
                (row as any)[key] = computed;
                continue;
              }
            }
            (row as any)[key] = value;
          }
          updated.push({ ...row });
        }
        return updated;
      }
      case 'delete': {
        const deleted: any[] = [];
        const matches = store.filter((row) =>
          ctx.whereClauses.every((pred: any) => pred(row)),
        );
        for (const row of matches) {
          const idx = store.indexOf(row);
          if (idx !== -1) {
            store.splice(idx, 1);
            deleted.push({ ...row });
          }
        }
        return deleted;
      }
      default:
        return [];
    }
  }

  const mockDb: any = {
    insert(table: any) {
      return chainable({ op: 'insert', table, whereClauses: [] });
    },
    select(fields?: any) {
      return chainable({ op: 'select', selectFields: fields, whereClauses: [], orderByFns: [] });
    },
    update(table: any) {
      return chainable({ op: 'update', table, whereClauses: [] });
    },
    delete(table: any) {
      return chainable({ op: 'delete', table, whereClauses: [] });
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
    desc: (colOrExpr: any) => {
      if (colOrExpr && colOrExpr.name) {
        const colName = colOrExpr.name;
        return {
          __sortFn: (a: any, b: any) => {
            const va = a[colName] ?? '';
            const vb = b[colName] ?? '';
            return va > vb ? -1 : va < vb ? 1 : 0;
          },
        };
      }
      return { __sortFn: (_a: any, _b: any) => 0 };
    },
    count: () => ({ __count: true }),
    isNull: (column: any) => {
      const colName = column?.name;
      return {
        __predicate: (row: any) => row[colName] == null,
      };
    },
    lte: (column: any, value: any) => {
      const colName = column?.name;
      return {
        __predicate: (row: any) => {
          const v = row[colName];
          if (v == null) return false;
          return v <= value;
        },
      };
    },
    gte: (column: any, value: any) => {
      const colName = column?.name;
      return {
        __predicate: (row: any) => {
          const v = row[colName];
          if (v == null) return false;
          return v >= value;
        },
      };
    },
    inArray: (column: any, values: any[]) => {
      const colName = column?.name;
      return {
        __predicate: (row: any) => values.includes(row[colName]),
      };
    },
    sql: (strings: TemplateStringsArray, ...values: any[]) => {
      // For the NOT IN terminal states clause — simulate with a predicate
      const raw = strings.join('?');
      return {
        __sql: true,
        __predicate: (row: any) => {
          // Handle "state NOT IN (...)" pattern
          if (raw.includes('NOT IN')) {
            const terminalStates = ['PAID', 'ADJUSTED', 'WRITTEN_OFF', 'EXPIRED', 'DELETED'];
            const stateValue = row.state;
            return !terminalStates.includes(stateValue);
          }
          return true;
        },
        // Handle "column + 1" pattern for increment operations
        __computeValue: (row: any) => {
          if (raw.includes('+ 1') && values[0] && values[0].name) {
            return (row[values[0].name] ?? 0) + 1;
          }
          return undefined;
        },
        raw,
        values,
      };
    },
  };
});

// ---------------------------------------------------------------------------
// Mock the claim schema module
// ---------------------------------------------------------------------------

vi.mock('@meritum/shared/schemas/db/claim.schema.js', () => {
  const makeCol = (name: string) => ({ name });

  const claimsProxy: any = {
    __table: 'claims',
    claimId: makeCol('claimId'),
    physicianId: makeCol('physicianId'),
    patientId: makeCol('patientId'),
    claimType: makeCol('claimType'),
    state: makeCol('state'),
    isClean: makeCol('isClean'),
    importSource: makeCol('importSource'),
    importBatchId: makeCol('importBatchId'),
    shiftId: makeCol('shiftId'),
    dateOfService: makeCol('dateOfService'),
    submissionDeadline: makeCol('submissionDeadline'),
    submittedBatchId: makeCol('submittedBatchId'),
    validationResult: makeCol('validationResult'),
    validationTimestamp: makeCol('validationTimestamp'),
    referenceDataVersion: makeCol('referenceDataVersion'),
    aiCoachSuggestions: makeCol('aiCoachSuggestions'),
    duplicateAlert: makeCol('duplicateAlert'),
    flags: makeCol('flags'),
    createdAt: makeCol('createdAt'),
    createdBy: makeCol('createdBy'),
    updatedAt: makeCol('updatedAt'),
    updatedBy: makeCol('updatedBy'),
    deletedAt: makeCol('deletedAt'),
  };

  const importBatchesProxy: any = {
    __table: 'import_batches',
    importBatchId: makeCol('importBatchId'),
    physicianId: makeCol('physicianId'),
    fileName: makeCol('fileName'),
    fileHash: makeCol('fileHash'),
    fieldMappingTemplateId: makeCol('fieldMappingTemplateId'),
    totalRows: makeCol('totalRows'),
    successCount: makeCol('successCount'),
    errorCount: makeCol('errorCount'),
    errorDetails: makeCol('errorDetails'),
    status: makeCol('status'),
    createdAt: makeCol('createdAt'),
    createdBy: makeCol('createdBy'),
  };

  const fieldMappingTemplatesProxy: any = {
    __table: 'field_mapping_templates',
    templateId: makeCol('templateId'),
    physicianId: makeCol('physicianId'),
    name: makeCol('name'),
    emrType: makeCol('emrType'),
    mappings: makeCol('mappings'),
    delimiter: makeCol('delimiter'),
    hasHeaderRow: makeCol('hasHeaderRow'),
    dateFormat: makeCol('dateFormat'),
    createdAt: makeCol('createdAt'),
    updatedAt: makeCol('updatedAt'),
  };

  const shiftsProxy: any = {
    __table: 'shifts',
    shiftId: makeCol('shiftId'),
    physicianId: makeCol('physicianId'),
    facilityId: makeCol('facilityId'),
    shiftDate: makeCol('shiftDate'),
    startTime: makeCol('startTime'),
    endTime: makeCol('endTime'),
    status: makeCol('status'),
    encounterCount: makeCol('encounterCount'),
    createdAt: makeCol('createdAt'),
    updatedAt: makeCol('updatedAt'),
  };

  const claimExportsProxy: any = {
    __table: 'claim_exports',
    exportId: makeCol('exportId'),
    physicianId: makeCol('physicianId'),
    dateFrom: makeCol('dateFrom'),
    dateTo: makeCol('dateTo'),
    claimType: makeCol('claimType'),
    format: makeCol('format'),
    status: makeCol('status'),
    filePath: makeCol('filePath'),
    createdAt: makeCol('createdAt'),
    updatedAt: makeCol('updatedAt'),
  };

  const claimAuditHistoryProxy: any = {
    __table: 'claim_audit_history',
    auditId: makeCol('auditId'),
    claimId: makeCol('claimId'),
    action: makeCol('action'),
    previousState: makeCol('previousState'),
    newState: makeCol('newState'),
    changes: makeCol('changes'),
    actorId: makeCol('actorId'),
    actorContext: makeCol('actorContext'),
    reason: makeCol('reason'),
    createdAt: makeCol('createdAt'),
  };

  return {
    claims: claimsProxy,
    importBatches: importBatchesProxy,
    fieldMappingTemplates: fieldMappingTemplatesProxy,
    shifts: shiftsProxy,
    claimExports: claimExportsProxy,
    claimAuditHistory: claimAuditHistoryProxy,
  };
});

// ---------------------------------------------------------------------------
// Mock claim constants
// ---------------------------------------------------------------------------

vi.mock('@meritum/shared/constants/claim.constants.js', () => {
  const ClaimState = {
    DRAFT: 'DRAFT',
    VALIDATED: 'VALIDATED',
    QUEUED: 'QUEUED',
    SUBMITTED: 'SUBMITTED',
    ASSESSED: 'ASSESSED',
    PAID: 'PAID',
    REJECTED: 'REJECTED',
    ADJUSTED: 'ADJUSTED',
    WRITTEN_OFF: 'WRITTEN_OFF',
    EXPIRED: 'EXPIRED',
    DELETED: 'DELETED',
  };
  const ShiftStatus = {
    IN_PROGRESS: 'IN_PROGRESS',
    COMPLETED: 'COMPLETED',
    SUBMITTED: 'SUBMITTED',
  };
  const ExportStatus = {
    PENDING: 'PENDING',
    PROCESSING: 'PROCESSING',
    COMPLETED: 'COMPLETED',
    FAILED: 'FAILED',
  };
  const ClaimType = {
    AHCIP: 'AHCIP',
    WCB: 'WCB',
  };
  const ClaimImportSource = {
    MANUAL: 'MANUAL',
    EMR_IMPORT: 'EMR_IMPORT',
    ED_SHIFT: 'ED_SHIFT',
  };
  const ClaimAuditAction = {
    CREATED: 'claim.created',
    EDITED: 'claim.edited',
    VALIDATED: 'claim.validated',
    QUEUED: 'claim.queued',
    UNQUEUED: 'claim.unqueued',
    SUBMITTED: 'claim.submitted',
    ASSESSED: 'claim.assessed',
    REJECTED: 'claim.rejected',
    RESUBMITTED: 'claim.resubmitted',
    WRITTEN_OFF: 'claim.written_off',
    DELETED: 'claim.deleted',
    EXPIRED: 'claim.expired',
    AI_SUGGESTION_ACCEPTED: 'claim.ai_suggestion_accepted',
    AI_SUGGESTION_DISMISSED: 'claim.ai_suggestion_dismissed',
    DUPLICATE_ACKNOWLEDGED: 'claim.duplicate_acknowledged',
  };
  const ActorContext = {
    PHYSICIAN: 'PHYSICIAN',
    DELEGATE: 'DELEGATE',
    SYSTEM: 'SYSTEM',
  };
  const ValidationCheckId = {
    S1_CLAIM_TYPE_VALID: 'S1_CLAIM_TYPE_VALID',
    S2_REQUIRED_BASE_FIELDS: 'S2_REQUIRED_BASE_FIELDS',
    S3_PATIENT_EXISTS: 'S3_PATIENT_EXISTS',
    S4_PHYSICIAN_ACTIVE: 'S4_PHYSICIAN_ACTIVE',
    S5_DOS_VALID: 'S5_DOS_VALID',
    S6_SUBMISSION_WINDOW: 'S6_SUBMISSION_WINDOW',
    S7_DUPLICATE_DETECTION: 'S7_DUPLICATE_DETECTION',
  };
  const ValidationSeverity = {
    ERROR: 'ERROR',
    WARNING: 'WARNING',
    INFO: 'INFO',
  };
  const AutoSubmissionMode = {
    AUTO_CLEAN: 'AUTO_CLEAN',
    AUTO_ALL: 'AUTO_ALL',
    REQUIRE_APPROVAL: 'REQUIRE_APPROVAL',
  };
  const ClaimNotificationEvent = {
    CLAIM_VALIDATED: 'CLAIM_VALIDATED',
    CLAIM_FLAGGED: 'CLAIM_FLAGGED',
    DEADLINE_APPROACHING: 'DEADLINE_APPROACHING',
    DEADLINE_EXPIRED: 'DEADLINE_EXPIRED',
    BATCH_ASSEMBLED: 'BATCH_ASSEMBLED',
    BATCH_SUBMITTED: 'BATCH_SUBMITTED',
    CLAIM_ASSESSED: 'CLAIM_ASSESSED',
    CLAIM_REJECTED: 'CLAIM_REJECTED',
    CLAIM_PAID: 'CLAIM_PAID',
    DUPLICATE_DETECTED: 'DUPLICATE_DETECTED',
    AI_SUGGESTION_READY: 'AI_SUGGESTION_READY',
  };
  const ImportBatchStatus = {
    PENDING: 'PENDING',
    PROCESSING: 'PROCESSING',
    COMPLETED: 'COMPLETED',
    FAILED: 'FAILED',
  };
  return {
    ClaimState,
    ClaimType,
    ClaimImportSource,
    ClaimAuditAction,
    ActorContext,
    ShiftStatus,
    ExportStatus,
    ImportBatchStatus,
    ValidationCheckId,
    ValidationSeverity,
    AutoSubmissionMode,
    ClaimNotificationEvent,
    TERMINAL_STATES: new Set(['PAID', 'ADJUSTED', 'WRITTEN_OFF', 'EXPIRED', 'DELETED']),
    STATE_TRANSITIONS: Object.freeze({
      DRAFT: ['VALIDATED', 'DELETED'],
      VALIDATED: ['DRAFT', 'QUEUED'],
      QUEUED: ['VALIDATED', 'SUBMITTED'],
      SUBMITTED: ['ASSESSED', 'REJECTED'],
      ASSESSED: ['PAID', 'ADJUSTED'],
      REJECTED: ['DRAFT', 'QUEUED', 'WRITTEN_OFF'],
      PAID: [],
      ADJUSTED: [],
      WRITTEN_OFF: [],
      EXPIRED: [],
      DELETED: [],
    }),
  };
});

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
  class NotFoundError extends AppError {
    constructor(resource: string) {
      super(404, 'NOT_FOUND', `${resource} not found`);
    }
  }
  class ForbiddenError extends AppError {
    constructor(message = 'Insufficient permissions') {
      super(403, 'FORBIDDEN', message);
    }
  }
  return { AppError, ConflictError, BusinessRuleError, NotFoundError, ForbiddenError };
});

vi.mock('node:crypto', async () => {
  const actual = await vi.importActual<typeof import('node:crypto')>('node:crypto');
  return {
    ...actual,
    createHash: (algorithm: string) => {
      let data = '';
      return {
        update(input: string) { data = input; return this; },
        digest(_encoding: string) {
          // Deterministic hash for testing: SHA-256 hex = 64 char hex string
          // Use a simple hash based on content length + first chars for uniqueness
          let hash = 0;
          for (let i = 0; i < data.length; i++) {
            hash = ((hash << 5) - hash + data.charCodeAt(i)) | 0;
          }
          const hex = Math.abs(hash).toString(16).padStart(16, '0');
          return hex.repeat(4); // 64 char hex string
        },
      };
    },
  };
});

// ---------------------------------------------------------------------------
// Test data helpers
// ---------------------------------------------------------------------------

const PHYSICIAN_1 = crypto.randomUUID();
const PHYSICIAN_2 = crypto.randomUUID();
const USER_1 = crypto.randomUUID();
const PATIENT_1 = crypto.randomUUID();

function makeClaimData(overrides?: Partial<Record<string, any>>) {
  return {
    physicianId: PHYSICIAN_1,
    patientId: PATIENT_1,
    claimType: 'AHCIP',
    importSource: 'MANUAL',
    dateOfService: '2026-01-15',
    submissionDeadline: '2026-04-15',
    createdBy: USER_1,
    updatedBy: USER_1,
    ...overrides,
  };
}

function seedClaim(overrides?: Partial<Record<string, any>>): Record<string, any> {
  const data = {
    claimId: crypto.randomUUID(),
    physicianId: PHYSICIAN_1,
    patientId: PATIENT_1,
    claimType: 'AHCIP',
    state: 'DRAFT',
    isClean: null,
    importSource: 'MANUAL',
    importBatchId: null,
    shiftId: null,
    dateOfService: '2026-01-15',
    submissionDeadline: '2026-04-15',
    submittedBatchId: null,
    validationResult: null,
    validationTimestamp: null,
    referenceDataVersion: null,
    aiCoachSuggestions: null,
    duplicateAlert: null,
    flags: null,
    createdAt: new Date(),
    createdBy: USER_1,
    updatedAt: new Date(),
    updatedBy: USER_1,
    deletedAt: null,
    ...overrides,
  };
  claimStore.push(data);
  return data;
}

function makeImportBatchData(overrides?: Partial<Record<string, any>>) {
  return {
    physicianId: PHYSICIAN_1,
    fileName: 'claims_export.csv',
    fileHash: 'a'.repeat(64),
    totalRows: 50,
    successCount: 0,
    errorCount: 0,
    status: 'PENDING',
    createdBy: USER_1,
    ...overrides,
  };
}

function seedImportBatch(overrides?: Partial<Record<string, any>>): Record<string, any> {
  const data = {
    importBatchId: crypto.randomUUID(),
    physicianId: PHYSICIAN_1,
    fileName: 'claims_export.csv',
    fileHash: 'a'.repeat(64),
    fieldMappingTemplateId: null,
    totalRows: 50,
    successCount: 0,
    errorCount: 0,
    errorDetails: null,
    status: 'PENDING',
    createdAt: new Date(),
    createdBy: USER_1,
    ...overrides,
  };
  importBatchStore.push(data);
  return data;
}

function makeTemplateData(overrides?: Partial<Record<string, any>>) {
  return {
    physicianId: PHYSICIAN_1,
    name: 'Wolf EMR Default',
    emrType: 'WOLF',
    mappings: { patientId: 'col_A', dateOfService: 'col_B', healthServiceCode: 'col_C' },
    delimiter: ',',
    hasHeaderRow: true,
    dateFormat: 'YYYY-MM-DD',
    ...overrides,
  };
}

function seedTemplate(overrides?: Partial<Record<string, any>>): Record<string, any> {
  const data = {
    templateId: crypto.randomUUID(),
    physicianId: PHYSICIAN_1,
    name: 'Wolf EMR Default',
    emrType: 'WOLF',
    mappings: { patientId: 'col_A', dateOfService: 'col_B', healthServiceCode: 'col_C' },
    delimiter: ',',
    hasHeaderRow: true,
    dateFormat: 'YYYY-MM-DD',
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  };
  templateStore.push(data);
  return data;
}

const FACILITY_1 = crypto.randomUUID();

function makeShiftData(overrides?: Partial<Record<string, any>>) {
  return {
    physicianId: PHYSICIAN_1,
    facilityId: FACILITY_1,
    shiftDate: '2026-02-15',
    startTime: null,
    endTime: null,
    ...overrides,
  };
}

function seedShift(overrides?: Partial<Record<string, any>>): Record<string, any> {
  const data = {
    shiftId: crypto.randomUUID(),
    physicianId: PHYSICIAN_1,
    facilityId: FACILITY_1,
    shiftDate: '2026-02-15',
    startTime: null,
    endTime: null,
    status: 'IN_PROGRESS',
    encounterCount: 0,
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  };
  shiftStore.push(data);
  return data;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Claim Repository', () => {
  let repo: ReturnType<typeof createClaimRepository>;

  beforeEach(() => {
    claimStore = [];
    importBatchStore = [];
    templateStore = [];
    shiftStore = [];
    exportStore = [];
    auditStore = [];
    repo = createClaimRepository(makeMockDb());
  });

  // =========================================================================
  // createClaim
  // =========================================================================

  it('createClaim inserts with draft state and correct import_source', async () => {
    const data = makeClaimData();
    const result = await repo.createClaim(data as any);

    expect(result.claimId).toBeDefined();
    expect(result.state).toBe('DRAFT');
    expect(result.importSource).toBe('MANUAL');
    expect(result.physicianId).toBe(PHYSICIAN_1);
    expect(result.patientId).toBe(PATIENT_1);
    expect(result.claimType).toBe('AHCIP');
    expect(result.dateOfService).toBe('2026-01-15');
  });

  it('createClaim with EMR_IMPORT source', async () => {
    const data = makeClaimData({ importSource: 'EMR_IMPORT' });
    const result = await repo.createClaim(data as any);

    expect(result.state).toBe('DRAFT');
    expect(result.importSource).toBe('EMR_IMPORT');
  });

  it('createClaim always sets state to DRAFT regardless of input', async () => {
    const data = makeClaimData({ state: 'VALIDATED' });
    const result = await repo.createClaim(data as any);

    expect(result.state).toBe('DRAFT');
  });

  // =========================================================================
  // findClaimById
  // =========================================================================

  it('findClaimById returns claim for owning physician', async () => {
    const seeded = seedClaim();
    const result = await repo.findClaimById(seeded.claimId, PHYSICIAN_1);

    expect(result).toBeDefined();
    expect(result!.claimId).toBe(seeded.claimId);
    expect(result!.physicianId).toBe(PHYSICIAN_1);
  });

  it('findClaimById returns undefined for different physician', async () => {
    const seeded = seedClaim();
    const result = await repo.findClaimById(seeded.claimId, PHYSICIAN_2);

    expect(result).toBeUndefined();
  });

  it('findClaimById returns undefined for soft-deleted claim', async () => {
    const seeded = seedClaim({ deletedAt: new Date() });
    const result = await repo.findClaimById(seeded.claimId, PHYSICIAN_1);

    expect(result).toBeUndefined();
  });

  it('findClaimById returns undefined for non-existent ID', async () => {
    const result = await repo.findClaimById(crypto.randomUUID(), PHYSICIAN_1);
    expect(result).toBeUndefined();
  });

  // =========================================================================
  // updateClaim
  // =========================================================================

  it('updateClaim updates allowed fields', async () => {
    const seeded = seedClaim();
    const newPatientId = crypto.randomUUID();

    const result = await repo.updateClaim(seeded.claimId, PHYSICIAN_1, {
      patientId: newPatientId,
      dateOfService: '2026-02-01',
    } as any);

    expect(result).toBeDefined();
    expect(result!.patientId).toBe(newPatientId);
    expect(result!.dateOfService).toBe('2026-02-01');
    expect(result!.updatedAt).toBeInstanceOf(Date);
  });

  it('updateClaim rejects update for wrong physician', async () => {
    const seeded = seedClaim();
    const result = await repo.updateClaim(seeded.claimId, PHYSICIAN_2, {
      dateOfService: '2026-02-01',
    } as any);

    expect(result).toBeUndefined();
  });

  it('updateClaim rejects update for soft-deleted claim', async () => {
    const seeded = seedClaim({ deletedAt: new Date() });
    const result = await repo.updateClaim(seeded.claimId, PHYSICIAN_1, {
      dateOfService: '2026-02-01',
    } as any);

    expect(result).toBeUndefined();
  });

  // =========================================================================
  // softDeleteClaim
  // =========================================================================

  it('softDeleteClaim sets deleted_at when state is draft', async () => {
    const seeded = seedClaim({ state: 'DRAFT' });
    const result = await repo.softDeleteClaim(seeded.claimId, PHYSICIAN_1);

    expect(result).toBe(true);
    const inStore = claimStore.find((c) => c.claimId === seeded.claimId);
    expect(inStore!.deletedAt).toBeInstanceOf(Date);
    expect(inStore!.state).toBe('DELETED');
  });

  it('softDeleteClaim rejects delete when state is not draft', async () => {
    const seeded = seedClaim({ state: 'VALIDATED' });
    const result = await repo.softDeleteClaim(seeded.claimId, PHYSICIAN_1);

    expect(result).toBe(false);
    const inStore = claimStore.find((c) => c.claimId === seeded.claimId);
    expect(inStore!.deletedAt).toBeNull();
  });

  it('softDeleteClaim rejects delete for wrong physician', async () => {
    const seeded = seedClaim({ state: 'DRAFT' });
    const result = await repo.softDeleteClaim(seeded.claimId, PHYSICIAN_2);

    expect(result).toBe(false);
  });

  it('softDeleteClaim rejects delete for already-deleted claim', async () => {
    const seeded = seedClaim({ state: 'DRAFT', deletedAt: new Date() });
    const result = await repo.softDeleteClaim(seeded.claimId, PHYSICIAN_1);

    expect(result).toBe(false);
  });

  // =========================================================================
  // listClaims
  // =========================================================================

  it('listClaims filters by state correctly', async () => {
    seedClaim({ state: 'DRAFT' });
    seedClaim({ state: 'VALIDATED' });
    seedClaim({ state: 'DRAFT' });

    const result = await repo.listClaims(PHYSICIAN_1, {
      state: 'DRAFT',
      page: 1,
      pageSize: 25,
    });

    expect(result.data).toHaveLength(2);
    expect(result.data.every((c) => c.state === 'DRAFT')).toBe(true);
    expect(result.pagination.total).toBe(2);
  });

  it('listClaims filters by claim_type correctly', async () => {
    seedClaim({ claimType: 'AHCIP' });
    seedClaim({ claimType: 'WCB' });
    seedClaim({ claimType: 'AHCIP' });

    const result = await repo.listClaims(PHYSICIAN_1, {
      claimType: 'WCB',
      page: 1,
      pageSize: 25,
    });

    expect(result.data).toHaveLength(1);
    expect(result.data[0].claimType).toBe('WCB');
  });

  it('listClaims filters by date range', async () => {
    seedClaim({ dateOfService: '2026-01-01' });
    seedClaim({ dateOfService: '2026-02-15' });
    seedClaim({ dateOfService: '2026-03-30' });

    const result = await repo.listClaims(PHYSICIAN_1, {
      dateFrom: '2026-01-15',
      dateTo: '2026-03-01',
      page: 1,
      pageSize: 25,
    });

    expect(result.data).toHaveLength(1);
    expect(result.data[0].dateOfService).toBe('2026-02-15');
  });

  it('listClaims filters by patient_id', async () => {
    const otherPatient = crypto.randomUUID();
    seedClaim({ patientId: PATIENT_1 });
    seedClaim({ patientId: otherPatient });

    const result = await repo.listClaims(PHYSICIAN_1, {
      patientId: PATIENT_1,
      page: 1,
      pageSize: 25,
    });

    expect(result.data).toHaveLength(1);
    expect(result.data[0].patientId).toBe(PATIENT_1);
  });

  it('listClaims filters by is_clean', async () => {
    seedClaim({ isClean: true });
    seedClaim({ isClean: false });
    seedClaim({ isClean: true });

    const result = await repo.listClaims(PHYSICIAN_1, {
      isClean: true,
      page: 1,
      pageSize: 25,
    });

    expect(result.data).toHaveLength(2);
    expect(result.data.every((c) => c.isClean === true)).toBe(true);
  });

  it('listClaims paginates correctly', async () => {
    for (let i = 0; i < 10; i++) {
      seedClaim();
    }

    const page1 = await repo.listClaims(PHYSICIAN_1, {
      page: 1,
      pageSize: 3,
    });

    expect(page1.data).toHaveLength(3);
    expect(page1.pagination.total).toBe(10);
    expect(page1.pagination.page).toBe(1);
    expect(page1.pagination.pageSize).toBe(3);
    expect(page1.pagination.hasMore).toBe(true);

    const page4 = await repo.listClaims(PHYSICIAN_1, {
      page: 4,
      pageSize: 3,
    });

    expect(page4.data).toHaveLength(1);
    expect(page4.pagination.hasMore).toBe(false);
  });

  it('listClaims excludes soft-deleted claims', async () => {
    seedClaim();
    seedClaim({ deletedAt: new Date() });

    const result = await repo.listClaims(PHYSICIAN_1, {
      page: 1,
      pageSize: 25,
    });

    expect(result.data).toHaveLength(1);
  });

  it('listClaims only returns claims for the authenticated physician', async () => {
    seedClaim({ physicianId: PHYSICIAN_1 });
    seedClaim({ physicianId: PHYSICIAN_2 });

    const result = await repo.listClaims(PHYSICIAN_1, {
      page: 1,
      pageSize: 25,
    });

    expect(result.data).toHaveLength(1);
    expect(result.data[0].physicianId).toBe(PHYSICIAN_1);
  });

  // =========================================================================
  // countClaimsByState
  // =========================================================================

  it('countClaimsByState returns grouped counts', async () => {
    seedClaim({ state: 'DRAFT' });
    seedClaim({ state: 'DRAFT' });
    seedClaim({ state: 'VALIDATED' });
    seedClaim({ state: 'SUBMITTED' });

    const result = await repo.countClaimsByState(PHYSICIAN_1);

    expect(result).toHaveLength(3);

    const draftCount = result.find((r) => r.state === 'DRAFT');
    expect(draftCount).toBeDefined();
    expect(draftCount!.count).toBe(2);

    const validatedCount = result.find((r) => r.state === 'VALIDATED');
    expect(validatedCount).toBeDefined();
    expect(validatedCount!.count).toBe(1);

    const submittedCount = result.find((r) => r.state === 'SUBMITTED');
    expect(submittedCount).toBeDefined();
    expect(submittedCount!.count).toBe(1);
  });

  it('countClaimsByState excludes soft-deleted claims', async () => {
    seedClaim({ state: 'DRAFT' });
    seedClaim({ state: 'DRAFT', deletedAt: new Date() });

    const result = await repo.countClaimsByState(PHYSICIAN_1);

    const draftCount = result.find((r) => r.state === 'DRAFT');
    expect(draftCount!.count).toBe(1);
  });

  it('countClaimsByState only counts for authenticated physician', async () => {
    seedClaim({ physicianId: PHYSICIAN_1, state: 'DRAFT' });
    seedClaim({ physicianId: PHYSICIAN_2, state: 'DRAFT' });

    const result = await repo.countClaimsByState(PHYSICIAN_1);

    const total = result.reduce((sum, r) => sum + r.count, 0);
    expect(total).toBe(1);
  });

  // =========================================================================
  // findClaimsApproachingDeadline
  // =========================================================================

  it('findClaimsApproachingDeadline returns claims within threshold', async () => {
    const today = new Date();
    const in3Days = new Date(today);
    in3Days.setDate(today.getDate() + 3);
    const in3DaysStr = in3Days.toISOString().split('T')[0];

    const in10Days = new Date(today);
    in10Days.setDate(today.getDate() + 10);
    const in10DaysStr = in10Days.toISOString().split('T')[0];

    seedClaim({ submissionDeadline: in3DaysStr, state: 'DRAFT' });
    seedClaim({ submissionDeadline: in10DaysStr, state: 'DRAFT' });

    const result = await repo.findClaimsApproachingDeadline(PHYSICIAN_1, 7);

    expect(result).toHaveLength(1);
    expect(result[0].submissionDeadline).toBe(in3DaysStr);
  });

  it('findClaimsApproachingDeadline excludes terminal-state claims', async () => {
    const today = new Date();
    const in3Days = new Date(today);
    in3Days.setDate(today.getDate() + 3);
    const in3DaysStr = in3Days.toISOString().split('T')[0];

    seedClaim({ submissionDeadline: in3DaysStr, state: 'DRAFT' });
    seedClaim({ submissionDeadline: in3DaysStr, state: 'PAID' });
    seedClaim({ submissionDeadline: in3DaysStr, state: 'DELETED' });

    const result = await repo.findClaimsApproachingDeadline(PHYSICIAN_1, 7);

    expect(result).toHaveLength(1);
    expect(result[0].state).toBe('DRAFT');
  });

  it('findClaimsApproachingDeadline excludes soft-deleted claims', async () => {
    const today = new Date();
    const in3Days = new Date(today);
    in3Days.setDate(today.getDate() + 3);
    const in3DaysStr = in3Days.toISOString().split('T')[0];

    seedClaim({ submissionDeadline: in3DaysStr, state: 'DRAFT' });
    seedClaim({ submissionDeadline: in3DaysStr, state: 'DRAFT', deletedAt: new Date() });

    const result = await repo.findClaimsApproachingDeadline(PHYSICIAN_1, 7);

    expect(result).toHaveLength(1);
  });

  it('findClaimsApproachingDeadline excludes past-deadline claims', async () => {
    const today = new Date();
    const yesterday = new Date(today);
    yesterday.setDate(today.getDate() - 1);
    const yesterdayStr = yesterday.toISOString().split('T')[0];

    const in3Days = new Date(today);
    in3Days.setDate(today.getDate() + 3);
    const in3DaysStr = in3Days.toISOString().split('T')[0];

    seedClaim({ submissionDeadline: yesterdayStr, state: 'DRAFT' });
    seedClaim({ submissionDeadline: in3DaysStr, state: 'DRAFT' });

    const result = await repo.findClaimsApproachingDeadline(PHYSICIAN_1, 7);

    expect(result).toHaveLength(1);
    expect(result[0].submissionDeadline).toBe(in3DaysStr);
  });

  it('findClaimsApproachingDeadline only returns for authenticated physician', async () => {
    const today = new Date();
    const in3Days = new Date(today);
    in3Days.setDate(today.getDate() + 3);
    const in3DaysStr = in3Days.toISOString().split('T')[0];

    seedClaim({ physicianId: PHYSICIAN_1, submissionDeadline: in3DaysStr, state: 'DRAFT' });
    seedClaim({ physicianId: PHYSICIAN_2, submissionDeadline: in3DaysStr, state: 'DRAFT' });

    const result = await repo.findClaimsApproachingDeadline(PHYSICIAN_1, 7);

    expect(result).toHaveLength(1);
    expect(result[0].physicianId).toBe(PHYSICIAN_1);
  });

  // =========================================================================
  // transitionState
  // =========================================================================

  it('transitionState succeeds with correct fromState', async () => {
    const seeded = seedClaim({ state: 'DRAFT' });
    const result = await repo.transitionState(
      seeded.claimId,
      PHYSICIAN_1,
      'DRAFT',
      'VALIDATED',
    );

    expect(result).toBeDefined();
    expect(result.state).toBe('VALIDATED');
    expect(result.claimId).toBe(seeded.claimId);
    expect(result.updatedAt).toBeInstanceOf(Date);
  });

  it('transitionState rejects incorrect fromState (optimistic lock)', async () => {
    const seeded = seedClaim({ state: 'DRAFT' });

    await expect(
      repo.transitionState(
        seeded.claimId,
        PHYSICIAN_1,
        'VALIDATED', // Wrong — claim is in DRAFT
        'QUEUED',
      ),
    ).rejects.toThrow('State transition failed');
  });

  it('transitionState rejects transition for wrong physician', async () => {
    const seeded = seedClaim({ state: 'DRAFT' });

    await expect(
      repo.transitionState(
        seeded.claimId,
        PHYSICIAN_2,
        'DRAFT',
        'VALIDATED',
      ),
    ).rejects.toThrow('State transition failed');
  });

  it('transitionState rejects transition for soft-deleted claim', async () => {
    const seeded = seedClaim({ state: 'DRAFT', deletedAt: new Date() });

    await expect(
      repo.transitionState(
        seeded.claimId,
        PHYSICIAN_1,
        'DRAFT',
        'VALIDATED',
      ),
    ).rejects.toThrow('State transition failed');
  });

  it('transitionState rejects transition for non-existent claim', async () => {
    await expect(
      repo.transitionState(
        crypto.randomUUID(),
        PHYSICIAN_1,
        'DRAFT',
        'VALIDATED',
      ),
    ).rejects.toThrow('State transition failed');
  });

  // =========================================================================
  // classifyClaim
  // =========================================================================

  it('classifyClaim sets is_clean to true', async () => {
    const seeded = seedClaim({ state: 'QUEUED', isClean: null });
    const result = await repo.classifyClaim(seeded.claimId, PHYSICIAN_1, true);

    expect(result).toBeDefined();
    expect(result!.isClean).toBe(true);
  });

  it('classifyClaim sets is_clean to false', async () => {
    const seeded = seedClaim({ state: 'QUEUED', isClean: null });
    const result = await repo.classifyClaim(seeded.claimId, PHYSICIAN_1, false);

    expect(result).toBeDefined();
    expect(result!.isClean).toBe(false);
  });

  it('classifyClaim returns undefined for wrong physician', async () => {
    const seeded = seedClaim({ state: 'QUEUED', isClean: null });
    const result = await repo.classifyClaim(seeded.claimId, PHYSICIAN_2, true);

    expect(result).toBeUndefined();
  });

  it('classifyClaim returns undefined for soft-deleted claim', async () => {
    const seeded = seedClaim({ state: 'QUEUED', isClean: null, deletedAt: new Date() });
    const result = await repo.classifyClaim(seeded.claimId, PHYSICIAN_1, true);

    expect(result).toBeUndefined();
  });

  // =========================================================================
  // updateValidationResult
  // =========================================================================

  it('updateValidationResult stores structured result with timestamp and version', async () => {
    const seeded = seedClaim({ state: 'DRAFT' });
    const validationResult = {
      checks: [
        { checkId: 'S1_CLAIM_TYPE_VALID', severity: 'ERROR', passed: true },
        { checkId: 'S2_REQUIRED_BASE_FIELDS', severity: 'ERROR', passed: true },
      ],
      isValid: true,
    };

    const result = await repo.updateValidationResult(
      seeded.claimId,
      PHYSICIAN_1,
      validationResult,
      '2026-02-01',
    );

    expect(result).toBeDefined();
    expect(result!.validationResult).toEqual(validationResult);
    expect(result!.validationTimestamp).toBeInstanceOf(Date);
    expect(result!.referenceDataVersion).toBe('2026-02-01');
    expect(result!.updatedAt).toBeInstanceOf(Date);
  });

  it('updateValidationResult returns undefined for wrong physician', async () => {
    const seeded = seedClaim({ state: 'DRAFT' });
    const result = await repo.updateValidationResult(
      seeded.claimId,
      PHYSICIAN_2,
      { checks: [], isValid: false },
      '2026-02-01',
    );

    expect(result).toBeUndefined();
  });

  // =========================================================================
  // updateAiSuggestions
  // =========================================================================

  it('updateAiSuggestions stores suggestions JSONB', async () => {
    const seeded = seedClaim({ state: 'VALIDATED' });
    const suggestions = {
      suggestions: [
        { type: 'modifier', message: 'Consider adding modifier 01', confidence: 0.85 },
      ],
    };

    const result = await repo.updateAiSuggestions(
      seeded.claimId,
      PHYSICIAN_1,
      suggestions,
    );

    expect(result).toBeDefined();
    expect(result!.aiCoachSuggestions).toEqual(suggestions);
  });

  // =========================================================================
  // updateDuplicateAlert
  // =========================================================================

  it('updateDuplicateAlert stores alert JSONB', async () => {
    const seeded = seedClaim({ state: 'VALIDATED' });
    const alert = {
      duplicateClaimIds: [crypto.randomUUID()],
      matchType: 'EXACT',
    };

    const result = await repo.updateDuplicateAlert(
      seeded.claimId,
      PHYSICIAN_1,
      alert,
    );

    expect(result).toBeDefined();
    expect(result!.duplicateAlert).toEqual(alert);
  });

  // =========================================================================
  // updateFlags
  // =========================================================================

  it('updateFlags stores flags JSONB', async () => {
    const seeded = seedClaim({ state: 'VALIDATED' });
    const flags = {
      validationWarnings: ['Approaching submission deadline'],
      requiresReview: true,
    };

    const result = await repo.updateFlags(
      seeded.claimId,
      PHYSICIAN_1,
      flags,
    );

    expect(result).toBeDefined();
    expect(result!.flags).toEqual(flags);
  });

  // =========================================================================
  // findClaimsForBatchAssembly
  // =========================================================================

  it('findClaimsForBatchAssembly returns only QUEUED claims matching criteria', async () => {
    seedClaim({ state: 'QUEUED', claimType: 'AHCIP', isClean: true });
    seedClaim({ state: 'DRAFT', claimType: 'AHCIP', isClean: true }); // Wrong state
    seedClaim({ state: 'QUEUED', claimType: 'WCB', isClean: true });  // Wrong type
    seedClaim({ state: 'QUEUED', claimType: 'AHCIP', isClean: true });

    const result = await repo.findClaimsForBatchAssembly(
      PHYSICIAN_1,
      'AHCIP',
      true,
      false,
    );

    expect(result).toHaveLength(2);
    expect(result.every((c) => c.state === 'QUEUED')).toBe(true);
    expect(result.every((c) => c.claimType === 'AHCIP')).toBe(true);
  });

  it('findClaimsForBatchAssembly respects clean filter (clean only)', async () => {
    seedClaim({ state: 'QUEUED', claimType: 'AHCIP', isClean: true });
    seedClaim({ state: 'QUEUED', claimType: 'AHCIP', isClean: false });

    const result = await repo.findClaimsForBatchAssembly(
      PHYSICIAN_1,
      'AHCIP',
      true,   // includeClean
      false,  // includeFlagged
    );

    expect(result).toHaveLength(1);
    expect(result[0].isClean).toBe(true);
  });

  it('findClaimsForBatchAssembly respects flagged filter (flagged only)', async () => {
    seedClaim({ state: 'QUEUED', claimType: 'AHCIP', isClean: true });
    seedClaim({ state: 'QUEUED', claimType: 'AHCIP', isClean: false });

    const result = await repo.findClaimsForBatchAssembly(
      PHYSICIAN_1,
      'AHCIP',
      false,  // includeClean
      true,   // includeFlagged
    );

    expect(result).toHaveLength(1);
    expect(result[0].isClean).toBe(false);
  });

  it('findClaimsForBatchAssembly returns both when both flags true', async () => {
    seedClaim({ state: 'QUEUED', claimType: 'AHCIP', isClean: true });
    seedClaim({ state: 'QUEUED', claimType: 'AHCIP', isClean: false });

    const result = await repo.findClaimsForBatchAssembly(
      PHYSICIAN_1,
      'AHCIP',
      true,
      true,
    );

    expect(result).toHaveLength(2);
  });

  it('findClaimsForBatchAssembly returns empty when both flags false', async () => {
    seedClaim({ state: 'QUEUED', claimType: 'AHCIP', isClean: true });
    seedClaim({ state: 'QUEUED', claimType: 'AHCIP', isClean: false });

    const result = await repo.findClaimsForBatchAssembly(
      PHYSICIAN_1,
      'AHCIP',
      false,
      false,
    );

    expect(result).toHaveLength(0);
  });

  it('findClaimsForBatchAssembly excludes soft-deleted claims', async () => {
    seedClaim({ state: 'QUEUED', claimType: 'AHCIP', isClean: true });
    seedClaim({ state: 'QUEUED', claimType: 'AHCIP', isClean: true, deletedAt: new Date() });

    const result = await repo.findClaimsForBatchAssembly(
      PHYSICIAN_1,
      'AHCIP',
      true,
      true,
    );

    expect(result).toHaveLength(1);
  });

  it('findClaimsForBatchAssembly only returns for authenticated physician', async () => {
    seedClaim({ physicianId: PHYSICIAN_1, state: 'QUEUED', claimType: 'AHCIP', isClean: true });
    seedClaim({ physicianId: PHYSICIAN_2, state: 'QUEUED', claimType: 'AHCIP', isClean: true });

    const result = await repo.findClaimsForBatchAssembly(
      PHYSICIAN_1,
      'AHCIP',
      true,
      true,
    );

    expect(result).toHaveLength(1);
    expect(result[0].physicianId).toBe(PHYSICIAN_1);
  });

  // =========================================================================
  // bulkTransitionState
  // =========================================================================

  it('bulkTransitionState transitions all claims atomically', async () => {
    const claim1 = seedClaim({ state: 'QUEUED', claimType: 'AHCIP' });
    const claim2 = seedClaim({ state: 'QUEUED', claimType: 'AHCIP' });
    const batchId = crypto.randomUUID();

    const result = await repo.bulkTransitionState(
      [claim1.claimId, claim2.claimId],
      PHYSICIAN_1,
      'QUEUED',
      'SUBMITTED',
      batchId,
    );

    expect(result).toHaveLength(2);
    expect(result.every((c) => c.state === 'SUBMITTED')).toBe(true);
  });

  it('bulkTransitionState sets submitted_batch_id on all claims', async () => {
    const claim1 = seedClaim({ state: 'QUEUED', claimType: 'AHCIP' });
    const claim2 = seedClaim({ state: 'QUEUED', claimType: 'AHCIP' });
    const batchId = crypto.randomUUID();

    const result = await repo.bulkTransitionState(
      [claim1.claimId, claim2.claimId],
      PHYSICIAN_1,
      'QUEUED',
      'SUBMITTED',
      batchId,
    );

    expect(result).toHaveLength(2);
    expect(result.every((c) => c.submittedBatchId === batchId)).toBe(true);
  });

  it('bulkTransitionState throws when some claims not in expected state', async () => {
    const claim1 = seedClaim({ state: 'QUEUED', claimType: 'AHCIP' });
    const claim2 = seedClaim({ state: 'DRAFT', claimType: 'AHCIP' }); // Wrong state
    const batchId = crypto.randomUUID();

    await expect(
      repo.bulkTransitionState(
        [claim1.claimId, claim2.claimId],
        PHYSICIAN_1,
        'QUEUED',
        'SUBMITTED',
        batchId,
      ),
    ).rejects.toThrow('Bulk state transition failed');
  });

  it('bulkTransitionState throws when claim belongs to different physician', async () => {
    const claim1 = seedClaim({ physicianId: PHYSICIAN_1, state: 'QUEUED' });
    const claim2 = seedClaim({ physicianId: PHYSICIAN_2, state: 'QUEUED' });
    const batchId = crypto.randomUUID();

    await expect(
      repo.bulkTransitionState(
        [claim1.claimId, claim2.claimId],
        PHYSICIAN_1,
        'QUEUED',
        'SUBMITTED',
        batchId,
      ),
    ).rejects.toThrow('Bulk state transition failed');
  });

  it('bulkTransitionState returns empty array for empty input', async () => {
    const batchId = crypto.randomUUID();
    const result = await repo.bulkTransitionState(
      [],
      PHYSICIAN_1,
      'QUEUED',
      'SUBMITTED',
      batchId,
    );

    expect(result).toHaveLength(0);
  });

  it('bulkTransitionState excludes soft-deleted claims', async () => {
    const claim1 = seedClaim({ state: 'QUEUED' });
    const claim2 = seedClaim({ state: 'QUEUED', deletedAt: new Date() });
    const batchId = crypto.randomUUID();

    await expect(
      repo.bulkTransitionState(
        [claim1.claimId, claim2.claimId],
        PHYSICIAN_1,
        'QUEUED',
        'SUBMITTED',
        batchId,
      ),
    ).rejects.toThrow('Bulk state transition failed');
  });

  // =========================================================================
  // createImportBatch
  // =========================================================================

  it('createImportBatch creates record with PENDING status', async () => {
    const data = makeImportBatchData();
    const result = await repo.createImportBatch(data as any);

    expect(result.importBatchId).toBeDefined();
    expect(result.status).toBe('PENDING');
    expect(result.physicianId).toBe(PHYSICIAN_1);
    expect(result.fileName).toBe('claims_export.csv');
    expect(result.fileHash).toBe('a'.repeat(64));
    expect(result.totalRows).toBe(50);
    expect(result.successCount).toBe(0);
    expect(result.errorCount).toBe(0);
  });

  // =========================================================================
  // findImportBatchById
  // =========================================================================

  it('findImportBatchById returns batch for owning physician', async () => {
    const seeded = seedImportBatch();
    const result = await repo.findImportBatchById(seeded.importBatchId, PHYSICIAN_1);

    expect(result).toBeDefined();
    expect(result!.importBatchId).toBe(seeded.importBatchId);
    expect(result!.physicianId).toBe(PHYSICIAN_1);
  });

  it('findImportBatchById returns undefined for different physician', async () => {
    const seeded = seedImportBatch();
    const result = await repo.findImportBatchById(seeded.importBatchId, PHYSICIAN_2);

    expect(result).toBeUndefined();
  });

  // =========================================================================
  // updateImportBatchStatus
  // =========================================================================

  it('updateImportBatchStatus updates status and counts', async () => {
    const seeded = seedImportBatch();
    const result = await repo.updateImportBatchStatus(
      seeded.importBatchId,
      PHYSICIAN_1,
      'COMPLETED',
      { successCount: 45, errorCount: 5, errorDetails: [{ row: 3, error: 'Invalid date' }] },
    );

    expect(result).toBeDefined();
    expect(result!.status).toBe('COMPLETED');
    expect(result!.successCount).toBe(45);
    expect(result!.errorCount).toBe(5);
    expect(result!.errorDetails).toEqual([{ row: 3, error: 'Invalid date' }]);
  });

  // =========================================================================
  // findDuplicateImportByHash
  // =========================================================================

  it('findDuplicateImportByHash detects duplicate file', async () => {
    const fileHash = 'b'.repeat(64);
    seedImportBatch({ fileHash });

    const result = await repo.findDuplicateImportByHash(PHYSICIAN_1, fileHash);

    expect(result).toBeDefined();
    expect(result!.fileHash).toBe(fileHash);
  });

  it('findDuplicateImportByHash returns undefined for new file', async () => {
    seedImportBatch({ fileHash: 'c'.repeat(64) });

    const result = await repo.findDuplicateImportByHash(PHYSICIAN_1, 'd'.repeat(64));

    expect(result).toBeUndefined();
  });

  // =========================================================================
  // listImportBatches
  // =========================================================================

  it('listImportBatches paginates correctly', async () => {
    for (let i = 0; i < 7; i++) {
      seedImportBatch({ fileHash: `${i}`.repeat(64) });
    }

    const page1 = await repo.listImportBatches(PHYSICIAN_1, 1, 3);

    expect(page1.data).toHaveLength(3);
    expect(page1.pagination.total).toBe(7);
    expect(page1.pagination.page).toBe(1);
    expect(page1.pagination.pageSize).toBe(3);
    expect(page1.pagination.hasMore).toBe(true);

    const page3 = await repo.listImportBatches(PHYSICIAN_1, 3, 3);

    expect(page3.data).toHaveLength(1);
    expect(page3.pagination.hasMore).toBe(false);
  });

  it('listImportBatches only returns batches for the authenticated physician', async () => {
    seedImportBatch({ physicianId: PHYSICIAN_1, fileHash: 'e'.repeat(64) });
    seedImportBatch({ physicianId: PHYSICIAN_2, fileHash: 'f'.repeat(64) });

    const result = await repo.listImportBatches(PHYSICIAN_1, 1, 25);

    expect(result.data).toHaveLength(1);
    expect(result.data[0].physicianId).toBe(PHYSICIAN_1);
  });

  // =========================================================================
  // createTemplate
  // =========================================================================

  it('createTemplate creates template for physician', async () => {
    const data = makeTemplateData();
    const result = await repo.createTemplate(data as any);

    expect(result.templateId).toBeDefined();
    expect(result.physicianId).toBe(PHYSICIAN_1);
    expect(result.name).toBe('Wolf EMR Default');
    expect(result.emrType).toBe('WOLF');
    expect(result.mappings).toEqual({ patientId: 'col_A', dateOfService: 'col_B', healthServiceCode: 'col_C' });
    expect(result.delimiter).toBe(',');
    expect(result.hasHeaderRow).toBe(true);
    expect(result.dateFormat).toBe('YYYY-MM-DD');
  });

  // =========================================================================
  // findTemplateById
  // =========================================================================

  it('findTemplateById returns template for owning physician', async () => {
    const seeded = seedTemplate();
    const result = await repo.findTemplateById(seeded.templateId, PHYSICIAN_1);

    expect(result).toBeDefined();
    expect(result!.templateId).toBe(seeded.templateId);
    expect(result!.physicianId).toBe(PHYSICIAN_1);
  });

  it('findTemplateById returns undefined for different physician', async () => {
    const seeded = seedTemplate();
    const result = await repo.findTemplateById(seeded.templateId, PHYSICIAN_2);

    expect(result).toBeUndefined();
  });

  // =========================================================================
  // updateTemplate
  // =========================================================================

  it('updateTemplate updates mapping fields', async () => {
    const seeded = seedTemplate();
    const newMappings = { patientId: 'col_X', dateOfService: 'col_Y', healthServiceCode: 'col_Z' };

    const result = await repo.updateTemplate(seeded.templateId, PHYSICIAN_1, {
      name: 'Updated Template',
      mappings: newMappings,
    } as any);

    expect(result).toBeDefined();
    expect(result!.name).toBe('Updated Template');
    expect(result!.mappings).toEqual(newMappings);
    expect(result!.updatedAt).toBeInstanceOf(Date);
  });

  it('updateTemplate rejects update for wrong physician', async () => {
    const seeded = seedTemplate();
    const result = await repo.updateTemplate(seeded.templateId, PHYSICIAN_2, {
      name: 'Hacked Template',
    } as any);

    expect(result).toBeUndefined();
  });

  // =========================================================================
  // deleteTemplate
  // =========================================================================

  it('deleteTemplate removes template for owning physician', async () => {
    const seeded = seedTemplate();
    const result = await repo.deleteTemplate(seeded.templateId, PHYSICIAN_1);

    expect(result).toBe(true);
    expect(templateStore.find((t) => t.templateId === seeded.templateId)).toBeUndefined();
  });

  it('deleteTemplate rejects delete for wrong physician', async () => {
    const seeded = seedTemplate();
    const result = await repo.deleteTemplate(seeded.templateId, PHYSICIAN_2);

    expect(result).toBe(false);
    expect(templateStore.find((t) => t.templateId === seeded.templateId)).toBeDefined();
  });

  // =========================================================================
  // listTemplates
  // =========================================================================

  it('listTemplates returns only physician\'s templates', async () => {
    seedTemplate({ physicianId: PHYSICIAN_1, name: 'Template A' });
    seedTemplate({ physicianId: PHYSICIAN_1, name: 'Template B' });
    seedTemplate({ physicianId: PHYSICIAN_2, name: 'Template C' });

    const result = await repo.listTemplates(PHYSICIAN_1);

    expect(result).toHaveLength(2);
    expect(result.every((t) => t.physicianId === PHYSICIAN_1)).toBe(true);
  });

  // =========================================================================
  // createShift
  // =========================================================================

  it('createShift creates shift with IN_PROGRESS status', async () => {
    const data = makeShiftData();
    const result = await repo.createShift(data as any);

    expect(result.shiftId).toBeDefined();
    expect(result.status).toBe('IN_PROGRESS');
    expect(result.physicianId).toBe(PHYSICIAN_1);
    expect(result.facilityId).toBeDefined();
    expect(result.shiftDate).toBe('2026-02-15');
    expect(result.encounterCount).toBe(0);
  });

  it('createShift always sets status to IN_PROGRESS regardless of input', async () => {
    const data = makeShiftData({ status: 'COMPLETED' });
    const result = await repo.createShift(data as any);

    expect(result.status).toBe('IN_PROGRESS');
  });

  // =========================================================================
  // findShiftById
  // =========================================================================

  it('findShiftById returns shift for owning physician', async () => {
    const seeded = seedShift();
    const result = await repo.findShiftById(seeded.shiftId, PHYSICIAN_1);

    expect(result).toBeDefined();
    expect(result!.shiftId).toBe(seeded.shiftId);
    expect(result!.physicianId).toBe(PHYSICIAN_1);
  });

  it('findShiftById returns undefined for different physician', async () => {
    const seeded = seedShift();
    const result = await repo.findShiftById(seeded.shiftId, PHYSICIAN_2);

    expect(result).toBeUndefined();
  });

  it('findShiftById returns undefined for non-existent ID', async () => {
    const result = await repo.findShiftById(crypto.randomUUID(), PHYSICIAN_1);
    expect(result).toBeUndefined();
  });

  // =========================================================================
  // updateShiftStatus
  // =========================================================================

  it('updateShiftStatus transitions status correctly', async () => {
    const seeded = seedShift({ status: 'IN_PROGRESS' });
    const result = await repo.updateShiftStatus(seeded.shiftId, PHYSICIAN_1, 'COMPLETED');

    expect(result).toBeDefined();
    expect(result!.status).toBe('COMPLETED');
    expect(result!.updatedAt).toBeInstanceOf(Date);
  });

  it('updateShiftStatus returns undefined for wrong physician', async () => {
    const seeded = seedShift({ status: 'IN_PROGRESS' });
    const result = await repo.updateShiftStatus(seeded.shiftId, PHYSICIAN_2, 'COMPLETED');

    expect(result).toBeUndefined();
  });

  // =========================================================================
  // updateShiftTimes
  // =========================================================================

  it('updateShiftTimes updates start and end times', async () => {
    const seeded = seedShift();
    const result = await repo.updateShiftTimes(seeded.shiftId, PHYSICIAN_1, '18:00', '06:00');

    expect(result).toBeDefined();
    expect(result!.startTime).toBe('18:00');
    expect(result!.endTime).toBe('06:00');
    expect(result!.updatedAt).toBeInstanceOf(Date);
  });

  it('updateShiftTimes returns undefined for wrong physician', async () => {
    const seeded = seedShift();
    const result = await repo.updateShiftTimes(seeded.shiftId, PHYSICIAN_2, '18:00', '06:00');

    expect(result).toBeUndefined();
  });

  // =========================================================================
  // incrementEncounterCount
  // =========================================================================

  it('incrementEncounterCount increments counter', async () => {
    const seeded = seedShift({ encounterCount: 3 });
    const result = await repo.incrementEncounterCount(seeded.shiftId, PHYSICIAN_1);

    expect(result).toBeDefined();
    expect(result!.encounterCount).toBe(4);
  });

  it('incrementEncounterCount increments from zero', async () => {
    const seeded = seedShift({ encounterCount: 0 });
    const result = await repo.incrementEncounterCount(seeded.shiftId, PHYSICIAN_1);

    expect(result).toBeDefined();
    expect(result!.encounterCount).toBe(1);
  });

  it('incrementEncounterCount returns undefined for wrong physician', async () => {
    const seeded = seedShift({ encounterCount: 3 });
    const result = await repo.incrementEncounterCount(seeded.shiftId, PHYSICIAN_2);

    expect(result).toBeUndefined();
  });

  // =========================================================================
  // listShifts
  // =========================================================================

  it('listShifts paginates correctly', async () => {
    for (let i = 0; i < 7; i++) {
      seedShift({ shiftDate: `2026-02-${String(i + 1).padStart(2, '0')}` });
    }

    const page1 = await repo.listShifts(PHYSICIAN_1, 1, 3);

    expect(page1.data).toHaveLength(3);
    expect(page1.pagination.total).toBe(7);
    expect(page1.pagination.page).toBe(1);
    expect(page1.pagination.pageSize).toBe(3);
    expect(page1.pagination.hasMore).toBe(true);

    const page3 = await repo.listShifts(PHYSICIAN_1, 3, 3);

    expect(page3.data).toHaveLength(1);
    expect(page3.pagination.hasMore).toBe(false);
  });

  it('listShifts only returns shifts for the authenticated physician', async () => {
    seedShift({ physicianId: PHYSICIAN_1 });
    seedShift({ physicianId: PHYSICIAN_2 });

    const result = await repo.listShifts(PHYSICIAN_1, 1, 25);

    expect(result.data).toHaveLength(1);
    expect(result.data[0].physicianId).toBe(PHYSICIAN_1);
  });

  // =========================================================================
  // findClaimsByShift
  // =========================================================================

  it('findClaimsByShift returns only claims linked to shift', async () => {
    const shift = seedShift();
    seedClaim({ shiftId: shift.shiftId, importSource: 'ED_SHIFT' });
    seedClaim({ shiftId: shift.shiftId, importSource: 'ED_SHIFT' });
    seedClaim({ shiftId: null, importSource: 'MANUAL' }); // Not linked to shift

    const result = await repo.findClaimsByShift(shift.shiftId, PHYSICIAN_1);

    expect(result).toHaveLength(2);
    expect(result.every((c) => c.shiftId === shift.shiftId)).toBe(true);
  });

  it('findClaimsByShift returns empty for wrong physician', async () => {
    const shift = seedShift();
    seedClaim({ shiftId: shift.shiftId, importSource: 'ED_SHIFT' });

    const result = await repo.findClaimsByShift(shift.shiftId, PHYSICIAN_2);

    expect(result).toHaveLength(0);
  });

  it('findClaimsByShift excludes soft-deleted claims', async () => {
    const shift = seedShift();
    seedClaim({ shiftId: shift.shiftId, importSource: 'ED_SHIFT' });
    seedClaim({ shiftId: shift.shiftId, importSource: 'ED_SHIFT', deletedAt: new Date() });

    const result = await repo.findClaimsByShift(shift.shiftId, PHYSICIAN_1);

    expect(result).toHaveLength(1);
  });

  // =========================================================================
  // Claim Audit History (Append-Only)
  // =========================================================================

  it('appendClaimAudit inserts entry with correct fields', async () => {
    const claim = seedClaim();
    const entry = {
      claimId: claim.claimId,
      action: 'STATE_CHANGE',
      previousState: 'DRAFT',
      newState: 'VALIDATED',
      changes: { state: { from: 'DRAFT', to: 'VALIDATED' } },
      actorId: USER_1,
      actorContext: 'physician',
      reason: 'Claim validated after review',
    };

    const result = await repo.appendClaimAudit(entry as any);

    expect(result.auditId).toBeDefined();
    expect(result.claimId).toBe(claim.claimId);
    expect(result.action).toBe('STATE_CHANGE');
    expect(result.previousState).toBe('DRAFT');
    expect(result.newState).toBe('VALIDATED');
    expect(result.changes).toEqual({ state: { from: 'DRAFT', to: 'VALIDATED' } });
    expect(result.actorId).toBe(USER_1);
    expect(result.actorContext).toBe('physician');
    expect(result.reason).toBe('Claim validated after review');
    expect(result.createdAt).toBeInstanceOf(Date);
  });

  it('getClaimAuditHistory returns entries for owned claim', async () => {
    const claim = seedClaim({ physicianId: PHYSICIAN_1 });

    // Seed audit entries directly
    auditStore.push({
      auditId: crypto.randomUUID(),
      claimId: claim.claimId,
      action: 'STATE_CHANGE',
      previousState: 'DRAFT',
      newState: 'VALIDATED',
      changes: null,
      actorId: USER_1,
      actorContext: 'physician',
      reason: null,
      createdAt: new Date('2026-01-10T10:00:00Z'),
    });
    auditStore.push({
      auditId: crypto.randomUUID(),
      claimId: claim.claimId,
      action: 'STATE_CHANGE',
      previousState: 'VALIDATED',
      newState: 'QUEUED',
      changes: null,
      actorId: USER_1,
      actorContext: 'physician',
      reason: null,
      createdAt: new Date('2026-01-11T10:00:00Z'),
    });

    const result = await repo.getClaimAuditHistory(claim.claimId, PHYSICIAN_1);

    expect(result).toHaveLength(2);
    expect(result.every((e) => e.claimId === claim.claimId)).toBe(true);
  });

  it('getClaimAuditHistory returns empty for different physician\'s claim', async () => {
    const claim = seedClaim({ physicianId: PHYSICIAN_2 });

    auditStore.push({
      auditId: crypto.randomUUID(),
      claimId: claim.claimId,
      action: 'STATE_CHANGE',
      previousState: 'DRAFT',
      newState: 'VALIDATED',
      changes: null,
      actorId: USER_1,
      actorContext: 'physician',
      reason: null,
      createdAt: new Date(),
    });

    const result = await repo.getClaimAuditHistory(claim.claimId, PHYSICIAN_1);

    expect(result).toHaveLength(0);
  });

  it('getClaimAuditHistory returns reverse chronological order', async () => {
    const claim = seedClaim({ physicianId: PHYSICIAN_1 });

    const t1 = new Date('2026-01-01T10:00:00Z');
    const t2 = new Date('2026-01-02T10:00:00Z');
    const t3 = new Date('2026-01-03T10:00:00Z');

    auditStore.push({
      auditId: crypto.randomUUID(),
      claimId: claim.claimId,
      action: 'STATE_CHANGE',
      previousState: 'DRAFT',
      newState: 'VALIDATED',
      changes: null,
      actorId: USER_1,
      actorContext: 'physician',
      reason: null,
      createdAt: t1,
    });
    auditStore.push({
      auditId: crypto.randomUUID(),
      claimId: claim.claimId,
      action: 'STATE_CHANGE',
      previousState: 'VALIDATED',
      newState: 'QUEUED',
      changes: null,
      actorId: USER_1,
      actorContext: 'physician',
      reason: null,
      createdAt: t3,
    });
    auditStore.push({
      auditId: crypto.randomUUID(),
      claimId: claim.claimId,
      action: 'FIELD_EDIT',
      previousState: null,
      newState: null,
      changes: { dateOfService: { from: '2026-01-01', to: '2026-01-02' } },
      actorId: USER_1,
      actorContext: 'physician',
      reason: null,
      createdAt: t2,
    });

    const result = await repo.getClaimAuditHistory(claim.claimId, PHYSICIAN_1);

    expect(result).toHaveLength(3);
    // Reverse chronological: t3, t2, t1
    expect(result[0].createdAt).toEqual(t3);
    expect(result[1].createdAt).toEqual(t2);
    expect(result[2].createdAt).toEqual(t1);
  });

  it('getClaimAuditHistoryPaginated paginates correctly', async () => {
    const claim = seedClaim({ physicianId: PHYSICIAN_1 });

    // Seed 5 audit entries
    for (let i = 0; i < 5; i++) {
      auditStore.push({
        auditId: crypto.randomUUID(),
        claimId: claim.claimId,
        action: 'STATE_CHANGE',
        previousState: 'DRAFT',
        newState: 'VALIDATED',
        changes: null,
        actorId: USER_1,
        actorContext: 'physician',
        reason: null,
        createdAt: new Date(`2026-01-${String(i + 1).padStart(2, '0')}T10:00:00Z`),
      });
    }

    const page1 = await repo.getClaimAuditHistoryPaginated(
      claim.claimId,
      PHYSICIAN_1,
      1,
      2,
    );

    expect(page1.data).toHaveLength(2);
    expect(page1.pagination.total).toBe(5);
    expect(page1.pagination.page).toBe(1);
    expect(page1.pagination.pageSize).toBe(2);
    expect(page1.pagination.hasMore).toBe(true);

    const page3 = await repo.getClaimAuditHistoryPaginated(
      claim.claimId,
      PHYSICIAN_1,
      3,
      2,
    );

    expect(page3.data).toHaveLength(1);
    expect(page3.pagination.hasMore).toBe(false);
  });

  it('getClaimAuditHistoryPaginated returns empty for different physician', async () => {
    const claim = seedClaim({ physicianId: PHYSICIAN_2 });

    auditStore.push({
      auditId: crypto.randomUUID(),
      claimId: claim.claimId,
      action: 'STATE_CHANGE',
      previousState: 'DRAFT',
      newState: 'VALIDATED',
      changes: null,
      actorId: USER_1,
      actorContext: 'physician',
      reason: null,
      createdAt: new Date(),
    });

    const result = await repo.getClaimAuditHistoryPaginated(
      claim.claimId,
      PHYSICIAN_1,
      1,
      10,
    );

    expect(result.data).toHaveLength(0);
    expect(result.pagination.total).toBe(0);
    expect(result.pagination.hasMore).toBe(false);
  });

  it('claim_audit_history has no update function', () => {
    // Verify the repository does not expose any update function for audit history
    const repoKeys = Object.keys(repo);
    const auditUpdateFns = repoKeys.filter(
      (key) =>
        key.toLowerCase().includes('audit') &&
        (key.toLowerCase().includes('update') || key.toLowerCase().includes('edit') || key.toLowerCase().includes('modify')),
    );
    expect(auditUpdateFns).toHaveLength(0);
  });

  it('claim_audit_history has no delete function', () => {
    // Verify the repository does not expose any delete function for audit history
    const repoKeys = Object.keys(repo);
    const auditDeleteFns = repoKeys.filter(
      (key) =>
        key.toLowerCase().includes('audit') &&
        (key.toLowerCase().includes('delete') || key.toLowerCase().includes('remove') || key.toLowerCase().includes('purge')),
    );
    expect(auditDeleteFns).toHaveLength(0);
  });

  // =========================================================================
  // Data Export Records
  // =========================================================================

  it('createExportRecord creates record with pending status', async () => {
    const result = await repo.createExportRecord({
      physicianId: PHYSICIAN_1,
      dateFrom: '2026-01-01',
      dateTo: '2026-01-31',
      claimType: 'AHCIP',
      format: 'CSV',
    });

    expect(result.exportId).toBeDefined();
    expect(result.status).toBe('PENDING');
    expect(result.physicianId).toBe(PHYSICIAN_1);
    expect(result.dateFrom).toBe('2026-01-01');
    expect(result.dateTo).toBe('2026-01-31');
    expect(result.claimType).toBe('AHCIP');
    expect(result.format).toBe('CSV');
    expect(result.filePath).toBeNull();
  });

  it('createExportRecord always sets status to PENDING regardless of input', async () => {
    const result = await repo.createExportRecord({
      physicianId: PHYSICIAN_1,
      dateFrom: '2026-01-01',
      dateTo: '2026-01-31',
      format: 'JSON',
      status: 'COMPLETED',
    });

    expect(result.status).toBe('PENDING');
  });

  it('createExportRecord works without claim_type (all types)', async () => {
    const result = await repo.createExportRecord({
      physicianId: PHYSICIAN_1,
      dateFrom: '2026-01-01',
      dateTo: '2026-01-31',
      format: 'CSV',
    });

    expect(result.exportId).toBeDefined();
    expect(result.claimType).toBeNull();
  });

  it('findExportById returns record for owning physician', async () => {
    const created = await repo.createExportRecord({
      physicianId: PHYSICIAN_1,
      dateFrom: '2026-01-01',
      dateTo: '2026-01-31',
      format: 'CSV',
    });

    const result = await repo.findExportById(created.exportId, PHYSICIAN_1);

    expect(result).toBeDefined();
    expect(result!.exportId).toBe(created.exportId);
    expect(result!.physicianId).toBe(PHYSICIAN_1);
  });

  it('findExportById returns undefined for different physician', async () => {
    const created = await repo.createExportRecord({
      physicianId: PHYSICIAN_1,
      dateFrom: '2026-01-01',
      dateTo: '2026-01-31',
      format: 'CSV',
    });

    const result = await repo.findExportById(created.exportId, PHYSICIAN_2);

    expect(result).toBeUndefined();
  });

  it('findExportById returns undefined for non-existent ID', async () => {
    const result = await repo.findExportById(crypto.randomUUID(), PHYSICIAN_1);
    expect(result).toBeUndefined();
  });

  it('updateExportStatus updates status and file path', async () => {
    const created = await repo.createExportRecord({
      physicianId: PHYSICIAN_1,
      dateFrom: '2026-01-01',
      dateTo: '2026-01-31',
      format: 'CSV',
    });

    const result = await repo.updateExportStatus(
      created.exportId,
      PHYSICIAN_1,
      'COMPLETED',
      'exports/physician1/2026-01-claims.csv',
    );

    expect(result).toBeDefined();
    expect(result!.status).toBe('COMPLETED');
    expect(result!.filePath).toBe('exports/physician1/2026-01-claims.csv');
    expect(result!.updatedAt).toBeInstanceOf(Date);
  });

  it('updateExportStatus updates status without file path', async () => {
    const created = await repo.createExportRecord({
      physicianId: PHYSICIAN_1,
      dateFrom: '2026-01-01',
      dateTo: '2026-01-31',
      format: 'CSV',
    });

    const result = await repo.updateExportStatus(
      created.exportId,
      PHYSICIAN_1,
      'PROCESSING',
    );

    expect(result).toBeDefined();
    expect(result!.status).toBe('PROCESSING');
    expect(result!.filePath).toBeNull();
  });

  it('updateExportStatus returns undefined for different physician', async () => {
    const created = await repo.createExportRecord({
      physicianId: PHYSICIAN_1,
      dateFrom: '2026-01-01',
      dateTo: '2026-01-31',
      format: 'CSV',
    });

    const result = await repo.updateExportStatus(
      created.exportId,
      PHYSICIAN_2,
      'COMPLETED',
      'exports/hacked.csv',
    );

    expect(result).toBeUndefined();
  });

  it('updateExportStatus to FAILED status', async () => {
    const created = await repo.createExportRecord({
      physicianId: PHYSICIAN_1,
      dateFrom: '2026-01-01',
      dateTo: '2026-01-31',
      format: 'CSV',
    });

    const result = await repo.updateExportStatus(
      created.exportId,
      PHYSICIAN_1,
      'FAILED',
    );

    expect(result).toBeDefined();
    expect(result!.status).toBe('FAILED');
    expect(result!.filePath).toBeNull();
  });
});

// ===========================================================================
// Claim Service Tests
// ===========================================================================

describe('Claim Service', () => {
  let repo: ReturnType<typeof createClaimRepository>;
  let deps: ClaimServiceDeps;

  const activeProviderCheck = {
    isActive: vi.fn().mockResolvedValue(true),
  };
  const inactiveProviderCheck = {
    isActive: vi.fn().mockResolvedValue(false),
  };
  const patientExistsCheck = {
    exists: vi.fn().mockResolvedValue(true),
  };
  const patientNotFoundCheck = {
    exists: vi.fn().mockResolvedValue(false),
  };

  beforeEach(() => {
    claimStore = [];
    importBatchStore = [];
    templateStore = [];
    shiftStore = [];
    exportStore = [];
    auditStore = [];
    repo = createClaimRepository(makeMockDb());
    deps = {
      repo,
      providerCheck: activeProviderCheck,
      patientCheck: patientExistsCheck,
    };
    vi.clearAllMocks();
    activeProviderCheck.isActive.mockResolvedValue(true);
    inactiveProviderCheck.isActive.mockResolvedValue(false);
    patientExistsCheck.exists.mockResolvedValue(true);
    patientNotFoundCheck.exists.mockResolvedValue(false);
  });

  // =========================================================================
  // createClaim
  // =========================================================================

  it('createClaim creates draft claim with correct deadline', async () => {
    const result = await createClaim(deps, PHYSICIAN_1, USER_1, 'PHYSICIAN', {
      claimType: 'AHCIP',
      patientId: PATIENT_1,
      dateOfService: '2026-01-15',
    });

    expect(result.claimId).toBeDefined();

    // Verify claim is in the store with correct fields
    const claim = claimStore.find((c) => c.claimId === result.claimId);
    expect(claim).toBeDefined();
    expect(claim!.state).toBe('DRAFT');
    expect(claim!.physicianId).toBe(PHYSICIAN_1);
    expect(claim!.patientId).toBe(PATIENT_1);
    expect(claim!.claimType).toBe('AHCIP');
    expect(claim!.importSource).toBe('MANUAL');
    expect(claim!.submissionDeadline).toBeDefined();
  });

  it('createClaim appends CREATED audit entry', async () => {
    const result = await createClaim(deps, PHYSICIAN_1, USER_1, 'PHYSICIAN', {
      claimType: 'AHCIP',
      patientId: PATIENT_1,
      dateOfService: '2026-01-15',
    });

    // Verify audit entry was created
    const auditEntry = auditStore.find(
      (a) => a.claimId === result.claimId && a.action === 'claim.created',
    );
    expect(auditEntry).toBeDefined();
    expect(auditEntry!.actorId).toBe(USER_1);
    expect(auditEntry!.actorContext).toBe('PHYSICIAN');
    expect(auditEntry!.newState).toBe('DRAFT');
    expect(auditEntry!.previousState).toBeNull();
  });

  it('createClaim calculates AHCIP deadline as DOS + 90 days', async () => {
    const result = await createClaim(deps, PHYSICIAN_1, USER_1, 'PHYSICIAN', {
      claimType: 'AHCIP',
      patientId: PATIENT_1,
      dateOfService: '2026-01-15',
    });

    const claim = claimStore.find((c) => c.claimId === result.claimId);
    // 2026-01-15 + 90 days = 2026-04-15
    expect(claim!.submissionDeadline).toBe('2026-04-15');
  });

  it('createClaim calculates WCB deadline (defaults to DOS + 90 days)', async () => {
    const result = await createClaim(deps, PHYSICIAN_1, USER_1, 'PHYSICIAN', {
      claimType: 'WCB',
      patientId: PATIENT_1,
      dateOfService: '2026-03-01',
    });

    const claim = claimStore.find((c) => c.claimId === result.claimId);
    // 2026-03-01 + 90 days = 2026-05-30
    expect(claim!.submissionDeadline).toBe('2026-05-30');
  });

  it('createClaim rejects when physician is not active', async () => {
    const inactiveDeps: ClaimServiceDeps = {
      ...deps,
      providerCheck: inactiveProviderCheck,
    };

    await expect(
      createClaim(inactiveDeps, PHYSICIAN_1, USER_1, 'PHYSICIAN', {
        claimType: 'AHCIP',
        patientId: PATIENT_1,
        dateOfService: '2026-01-15',
      }),
    ).rejects.toThrow('Physician is not active');
  });

  it('createClaim rejects when patient does not exist', async () => {
    const noPatientDeps: ClaimServiceDeps = {
      ...deps,
      patientCheck: patientNotFoundCheck,
    };

    await expect(
      createClaim(noPatientDeps, PHYSICIAN_1, USER_1, 'PHYSICIAN', {
        claimType: 'AHCIP',
        patientId: PATIENT_1,
        dateOfService: '2026-01-15',
      }),
    ).rejects.toThrow('Patient not found');
  });

  it('createClaim records actor_context correctly for delegate', async () => {
    const delegateUserId = crypto.randomUUID();

    const result = await createClaim(deps, PHYSICIAN_1, delegateUserId, 'DELEGATE', {
      claimType: 'AHCIP',
      patientId: PATIENT_1,
      dateOfService: '2026-01-15',
    });

    const auditEntry = auditStore.find(
      (a) => a.claimId === result.claimId && a.action === 'claim.created',
    );
    expect(auditEntry).toBeDefined();
    expect(auditEntry!.actorId).toBe(delegateUserId);
    expect(auditEntry!.actorContext).toBe('DELEGATE');

    // Claim is still created under the physician's ID, not the delegate's
    const claim = claimStore.find((c) => c.claimId === result.claimId);
    expect(claim!.physicianId).toBe(PHYSICIAN_1);
  });

  // =========================================================================
  // createClaimFromImport
  // =========================================================================

  it('createClaimFromImport sets import_source and batch_id', async () => {
    const batchId = crypto.randomUUID();

    const result = await createClaimFromImport(
      deps,
      PHYSICIAN_1,
      USER_1,
      batchId,
      {
        claimType: 'AHCIP',
        patientId: PATIENT_1,
        dateOfService: '2026-02-10',
      },
    );

    expect(result.claimId).toBeDefined();

    const claim = claimStore.find((c) => c.claimId === result.claimId);
    expect(claim).toBeDefined();
    expect(claim!.importSource).toBe('EMR_IMPORT');
    expect(claim!.importBatchId).toBe(batchId);
    expect(claim!.state).toBe('DRAFT');
  });

  it('createClaimFromImport appends CREATED audit entry with import metadata', async () => {
    const batchId = crypto.randomUUID();

    const result = await createClaimFromImport(
      deps,
      PHYSICIAN_1,
      USER_1,
      batchId,
      {
        claimType: 'AHCIP',
        patientId: PATIENT_1,
        dateOfService: '2026-02-10',
      },
    );

    const auditEntry = auditStore.find(
      (a) => a.claimId === result.claimId && a.action === 'claim.created',
    );
    expect(auditEntry).toBeDefined();
    expect(auditEntry!.actorContext).toBe('SYSTEM');
    expect(auditEntry!.changes).toEqual({ importBatchId: batchId });
  });

  it('createClaimFromImport rejects when physician is not active', async () => {
    const inactiveDeps: ClaimServiceDeps = {
      ...deps,
      providerCheck: inactiveProviderCheck,
    };

    await expect(
      createClaimFromImport(
        inactiveDeps,
        PHYSICIAN_1,
        USER_1,
        crypto.randomUUID(),
        {
          claimType: 'AHCIP',
          patientId: PATIENT_1,
          dateOfService: '2026-02-10',
        },
      ),
    ).rejects.toThrow('Physician is not active');
  });

  it('createClaimFromImport rejects when patient does not exist', async () => {
    const noPatientDeps: ClaimServiceDeps = {
      ...deps,
      patientCheck: patientNotFoundCheck,
    };

    await expect(
      createClaimFromImport(
        noPatientDeps,
        PHYSICIAN_1,
        USER_1,
        crypto.randomUUID(),
        {
          claimType: 'AHCIP',
          patientId: PATIENT_1,
          dateOfService: '2026-02-10',
        },
      ),
    ).rejects.toThrow('Patient not found');
  });

  // =========================================================================
  // createClaimFromShift
  // =========================================================================

  it('createClaimFromShift sets import_source and shift_id', async () => {
    const shift = seedShift({ status: 'IN_PROGRESS', encounterCount: 0 });

    const result = await createClaimFromShift(
      deps,
      PHYSICIAN_1,
      USER_1,
      shift.shiftId,
      {
        patientId: PATIENT_1,
        dateOfService: '2026-02-15',
        claimType: 'AHCIP',
      },
    );

    expect(result.claimId).toBeDefined();

    const claim = claimStore.find((c) => c.claimId === result.claimId);
    expect(claim).toBeDefined();
    expect(claim!.importSource).toBe('ED_SHIFT');
    expect(claim!.shiftId).toBe(shift.shiftId);
    expect(claim!.state).toBe('DRAFT');
  });

  it('createClaimFromShift increments shift encounter count', async () => {
    const shift = seedShift({ status: 'IN_PROGRESS', encounterCount: 2 });

    await createClaimFromShift(
      deps,
      PHYSICIAN_1,
      USER_1,
      shift.shiftId,
      {
        patientId: PATIENT_1,
        dateOfService: '2026-02-15',
        claimType: 'AHCIP',
      },
    );

    // Verify the shift encounter count was incremented
    const updatedShift = shiftStore.find((s) => s.shiftId === shift.shiftId);
    expect(updatedShift!.encounterCount).toBe(3);
  });

  it('createClaimFromShift appends CREATED audit entry with shift metadata', async () => {
    const shift = seedShift({ status: 'IN_PROGRESS', encounterCount: 0 });

    const result = await createClaimFromShift(
      deps,
      PHYSICIAN_1,
      USER_1,
      shift.shiftId,
      {
        patientId: PATIENT_1,
        dateOfService: '2026-02-15',
        claimType: 'AHCIP',
      },
    );

    const auditEntry = auditStore.find(
      (a) => a.claimId === result.claimId && a.action === 'claim.created',
    );
    expect(auditEntry).toBeDefined();
    expect(auditEntry!.actorContext).toBe('PHYSICIAN');
    expect(auditEntry!.changes).toEqual({ shiftId: shift.shiftId });
  });

  it('createClaimFromShift rejects when shift does not exist', async () => {
    await expect(
      createClaimFromShift(
        deps,
        PHYSICIAN_1,
        USER_1,
        crypto.randomUUID(), // Non-existent shift
        {
          patientId: PATIENT_1,
          dateOfService: '2026-02-15',
          claimType: 'AHCIP',
        },
      ),
    ).rejects.toThrow('Shift not found');
  });

  it('createClaimFromShift rejects when shift is COMPLETED (not IN_PROGRESS)', async () => {
    const shift = seedShift({ status: 'COMPLETED', encounterCount: 5 });

    await expect(
      createClaimFromShift(
        deps,
        PHYSICIAN_1,
        USER_1,
        shift.shiftId,
        {
          patientId: PATIENT_1,
          dateOfService: '2026-02-15',
          claimType: 'AHCIP',
        },
      ),
    ).rejects.toThrow('Cannot add encounters to a shift that is not in progress');
  });

  it('createClaimFromShift rejects when physician is not active', async () => {
    const shift = seedShift({ status: 'IN_PROGRESS', encounterCount: 0 });
    const inactiveDeps: ClaimServiceDeps = {
      ...deps,
      providerCheck: inactiveProviderCheck,
    };

    await expect(
      createClaimFromShift(
        inactiveDeps,
        PHYSICIAN_1,
        USER_1,
        shift.shiftId,
        {
          patientId: PATIENT_1,
          dateOfService: '2026-02-15',
          claimType: 'AHCIP',
        },
      ),
    ).rejects.toThrow('Physician is not active');
  });

  it('createClaimFromShift rejects when patient does not exist', async () => {
    const shift = seedShift({ status: 'IN_PROGRESS', encounterCount: 0 });
    const noPatientDeps: ClaimServiceDeps = {
      ...deps,
      patientCheck: patientNotFoundCheck,
    };

    await expect(
      createClaimFromShift(
        noPatientDeps,
        PHYSICIAN_1,
        USER_1,
        shift.shiftId,
        {
          patientId: PATIENT_1,
          dateOfService: '2026-02-15',
          claimType: 'AHCIP',
        },
      ),
    ).rejects.toThrow('Patient not found');
  });

  it('createClaimFromShift rejects when shift belongs to different physician', async () => {
    const shift = seedShift({
      physicianId: PHYSICIAN_2,
      status: 'IN_PROGRESS',
      encounterCount: 0,
    });

    await expect(
      createClaimFromShift(
        deps,
        PHYSICIAN_1, // Authenticated physician differs from shift owner
        USER_1,
        shift.shiftId,
        {
          patientId: PATIENT_1,
          dateOfService: '2026-02-15',
          claimType: 'AHCIP',
        },
      ),
    ).rejects.toThrow('Shift not found');
  });

  // =========================================================================
  // createShift
  // =========================================================================

  it('createShift creates shift with IN_PROGRESS status', async () => {
    const facilityCheck: FacilityCheck = {
      belongsToPhysician: vi.fn().mockResolvedValue(true),
    };
    const shiftDeps: ClaimServiceDeps = { ...deps, facilityCheck };

    const result = await createShift(shiftDeps, PHYSICIAN_1, {
      facilityId: FACILITY_1,
      shiftDate: '2026-02-15',
      startTime: '18:00',
      endTime: '06:00',
    });

    expect(result.shiftId).toBeDefined();

    const shift = shiftStore.find((s) => s.shiftId === result.shiftId);
    expect(shift).toBeDefined();
    expect(shift!.status).toBe('IN_PROGRESS');
    expect(shift!.physicianId).toBe(PHYSICIAN_1);
    expect(shift!.facilityId).toBe(FACILITY_1);
    expect(shift!.shiftDate).toBe('2026-02-15');
    expect(shift!.startTime).toBe('18:00');
    expect(shift!.endTime).toBe('06:00');
    expect(shift!.encounterCount).toBe(0);
  });

  it('createShift verifies facility belongs to physician', async () => {
    const facilityCheck: FacilityCheck = {
      belongsToPhysician: vi.fn().mockResolvedValue(false),
    };
    const shiftDeps: ClaimServiceDeps = { ...deps, facilityCheck };

    await expect(
      createShift(shiftDeps, PHYSICIAN_1, {
        facilityId: crypto.randomUUID(), // facility not belonging to physician
        shiftDate: '2026-02-15',
      }),
    ).rejects.toThrow('Facility not found');
  });

  it('createShift rejects when physician is not active', async () => {
    const facilityCheck: FacilityCheck = {
      belongsToPhysician: vi.fn().mockResolvedValue(true),
    };
    const shiftDeps: ClaimServiceDeps = {
      ...deps,
      providerCheck: inactiveProviderCheck,
      facilityCheck,
    };

    await expect(
      createShift(shiftDeps, PHYSICIAN_1, {
        facilityId: FACILITY_1,
        shiftDate: '2026-02-15',
      }),
    ).rejects.toThrow('Physician is not active');
  });

  it('createShift works without facilityCheck dependency (no verification)', async () => {
    // When facilityCheck is not provided, skip facility verification
    const result = await createShift(deps, PHYSICIAN_1, {
      facilityId: FACILITY_1,
      shiftDate: '2026-02-15',
    });

    expect(result.shiftId).toBeDefined();
    const shift = shiftStore.find((s) => s.shiftId === result.shiftId);
    expect(shift).toBeDefined();
    expect(shift!.status).toBe('IN_PROGRESS');
  });

  // =========================================================================
  // addEncounter
  // =========================================================================

  it('addEncounter creates claim linked to shift', async () => {
    const shift = seedShift({ status: 'IN_PROGRESS', encounterCount: 0 });

    const result = await addEncounter(
      deps,
      PHYSICIAN_1,
      USER_1,
      shift.shiftId,
      {
        patientId: PATIENT_1,
        dateOfService: '2026-02-15',
        claimType: 'AHCIP',
      },
    );

    expect(result.claimId).toBeDefined();

    const claim = claimStore.find((c) => c.claimId === result.claimId);
    expect(claim).toBeDefined();
    expect(claim!.importSource).toBe('ED_SHIFT');
    expect(claim!.shiftId).toBe(shift.shiftId);
    expect(claim!.state).toBe('DRAFT');
  });

  it('addEncounter increments encounter count', async () => {
    const shift = seedShift({ status: 'IN_PROGRESS', encounterCount: 3 });

    await addEncounter(deps, PHYSICIAN_1, USER_1, shift.shiftId, {
      patientId: PATIENT_1,
      dateOfService: '2026-02-15',
      claimType: 'AHCIP',
    });

    const updatedShift = shiftStore.find((s) => s.shiftId === shift.shiftId);
    expect(updatedShift!.encounterCount).toBe(4);
  });

  it('addEncounter rejects if shift is not IN_PROGRESS', async () => {
    const shift = seedShift({ status: 'COMPLETED', encounterCount: 5 });

    await expect(
      addEncounter(deps, PHYSICIAN_1, USER_1, shift.shiftId, {
        patientId: PATIENT_1,
        dateOfService: '2026-02-15',
        claimType: 'AHCIP',
      }),
    ).rejects.toThrow('Cannot add encounters to a shift that is not in progress');
  });

  // =========================================================================
  // completeShift
  // =========================================================================

  it('completeShift sets status to COMPLETED', async () => {
    const shift = seedShift({ status: 'IN_PROGRESS', encounterCount: 2 });

    const result = await completeShift(deps, PHYSICIAN_1, shift.shiftId);

    expect(result.shift.status).toBe('COMPLETED');
    const storedShift = shiftStore.find((s) => s.shiftId === shift.shiftId);
    expect(storedShift!.status).toBe('COMPLETED');
  });

  it('completeShift returns shift with all encounters', async () => {
    const shift = seedShift({ status: 'IN_PROGRESS', encounterCount: 2 });

    // Seed two claims linked to this shift
    seedClaim({ shiftId: shift.shiftId, importSource: 'ED_SHIFT' });
    seedClaim({ shiftId: shift.shiftId, importSource: 'ED_SHIFT' });

    const result = await completeShift(deps, PHYSICIAN_1, shift.shiftId);

    expect(result.shift.shiftId).toBe(shift.shiftId);
    expect(result.claims).toHaveLength(2);
    result.claims.forEach((c: any) => {
      expect(c.shiftId).toBe(shift.shiftId);
    });
  });

  it('completeShift rejects when shift is not IN_PROGRESS', async () => {
    const shift = seedShift({ status: 'COMPLETED', encounterCount: 3 });

    await expect(
      completeShift(deps, PHYSICIAN_1, shift.shiftId),
    ).rejects.toThrow('Cannot complete a shift that is not in progress');
  });

  it('completeShift rejects when shift does not exist', async () => {
    await expect(
      completeShift(deps, PHYSICIAN_1, crypto.randomUUID()),
    ).rejects.toThrow('Shift not found');
  });

  it('completeShift rejects when shift belongs to different physician', async () => {
    const shift = seedShift({
      physicianId: PHYSICIAN_2,
      status: 'IN_PROGRESS',
      encounterCount: 0,
    });

    await expect(
      completeShift(deps, PHYSICIAN_1, shift.shiftId),
    ).rejects.toThrow('Shift not found');
  });

  it('completeShift triggers after-hours calculation when times are set', async () => {
    const shift = seedShift({
      status: 'IN_PROGRESS',
      encounterCount: 1,
      startTime: '18:00',
      endTime: '06:00',
    });

    // Seed a claim linked to this shift
    seedClaim({ shiftId: shift.shiftId, importSource: 'ED_SHIFT', claimType: 'AHCIP' });

    const mockCalculator: AfterHoursPremiumCalculator = {
      calculatePremiums: vi.fn().mockResolvedValue([]),
    };

    const shiftDeps: ClaimServiceDeps = {
      ...deps,
      afterHoursPremiumCalculators: { AHCIP: mockCalculator },
    };

    await completeShift(shiftDeps, PHYSICIAN_1, shift.shiftId);

    expect(mockCalculator.calculatePremiums).toHaveBeenCalledWith(
      expect.any(Array),
      '18:00',
      '06:00',
    );
  });

  it('completeShift skips after-hours calculation when times are not set', async () => {
    const shift = seedShift({
      status: 'IN_PROGRESS',
      encounterCount: 1,
      startTime: null,
      endTime: null,
    });

    seedClaim({ shiftId: shift.shiftId, importSource: 'ED_SHIFT', claimType: 'AHCIP' });

    const mockCalculator: AfterHoursPremiumCalculator = {
      calculatePremiums: vi.fn().mockResolvedValue([]),
    };

    const shiftDeps: ClaimServiceDeps = {
      ...deps,
      afterHoursPremiumCalculators: { AHCIP: mockCalculator },
    };

    await completeShift(shiftDeps, PHYSICIAN_1, shift.shiftId);

    expect(mockCalculator.calculatePremiums).not.toHaveBeenCalled();
  });

  // =========================================================================
  // getShiftDetails
  // =========================================================================

  it('getShiftDetails returns shift with all encounters', async () => {
    const shift = seedShift({ status: 'IN_PROGRESS', encounterCount: 3 });

    // Seed three claims linked to this shift
    seedClaim({ shiftId: shift.shiftId, importSource: 'ED_SHIFT' });
    seedClaim({ shiftId: shift.shiftId, importSource: 'ED_SHIFT' });
    seedClaim({ shiftId: shift.shiftId, importSource: 'ED_SHIFT' });

    const result = await getShiftDetails(deps, PHYSICIAN_1, shift.shiftId);

    expect(result.shift.shiftId).toBe(shift.shiftId);
    expect(result.claims).toHaveLength(3);
    result.claims.forEach((c: any) => {
      expect(c.shiftId).toBe(shift.shiftId);
    });
  });

  it('getShiftDetails rejects when shift does not exist', async () => {
    await expect(
      getShiftDetails(deps, PHYSICIAN_1, crypto.randomUUID()),
    ).rejects.toThrow('Shift not found');
  });

  it('getShiftDetails rejects when shift belongs to different physician', async () => {
    const shift = seedShift({
      physicianId: PHYSICIAN_2,
      status: 'IN_PROGRESS',
      encounterCount: 0,
    });

    await expect(
      getShiftDetails(deps, PHYSICIAN_1, shift.shiftId),
    ).rejects.toThrow('Shift not found');
  });

  it('getShiftDetails excludes soft-deleted claims', async () => {
    const shift = seedShift({ status: 'COMPLETED', encounterCount: 2 });

    seedClaim({ shiftId: shift.shiftId, importSource: 'ED_SHIFT' });
    seedClaim({ shiftId: shift.shiftId, importSource: 'ED_SHIFT', deletedAt: new Date() });

    const result = await getShiftDetails(deps, PHYSICIAN_1, shift.shiftId);

    expect(result.claims).toHaveLength(1);
    expect(result.claims[0].deletedAt).toBeNull();
  });

  // =========================================================================
  // validateClaim
  // =========================================================================

  describe('validateClaim', () => {
    it('runs all 7 shared checks in order on a valid claim', async () => {
      const claim = seedClaim({
        dateOfService: '2026-01-15',
        submissionDeadline: '2026-04-15',
        claimType: 'AHCIP',
      });

      const result = await validateClaim(
        deps,
        claim.claimId,
        PHYSICIAN_1,
        USER_1,
        'PHYSICIAN',
      );

      expect(result.passed).toBe(true);
      expect(result.errors).toHaveLength(0);
      expect(result.validation_timestamp).toBeDefined();
      expect(result.reference_data_version).toBe('unknown');
    });

    it('S1 failure short-circuits all subsequent checks', async () => {
      const claim = seedClaim({ claimType: 'INVALID_TYPE' });

      // Use a patient check spy to verify it's never called
      const spyPatientCheck = {
        exists: vi.fn().mockResolvedValue(true),
      };
      const spyProviderCheck = {
        isActive: vi.fn().mockResolvedValue(true),
      };
      const spyDeps: ClaimServiceDeps = {
        repo,
        providerCheck: spyProviderCheck,
        patientCheck: spyPatientCheck,
      };

      const result = await validateClaim(
        spyDeps,
        claim.claimId,
        PHYSICIAN_1,
        USER_1,
        'PHYSICIAN',
      );

      expect(result.passed).toBe(false);
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].check).toBe('S1_CLAIM_TYPE_VALID');
      // S1 short-circuits, so patient and provider checks should NOT be called
      expect(spyPatientCheck.exists).not.toHaveBeenCalled();
      expect(spyProviderCheck.isActive).not.toHaveBeenCalled();
    });

    it('S2 returns error for missing required fields', async () => {
      // Create claim with missing patient_id
      const claim = seedClaim({ patientId: null, dateOfService: null });

      const result = await validateClaim(
        deps,
        claim.claimId,
        PHYSICIAN_1,
        USER_1,
        'PHYSICIAN',
      );

      expect(result.passed).toBe(false);
      const s2Error = result.errors.find((e) => e.check === 'S2_REQUIRED_BASE_FIELDS');
      expect(s2Error).toBeDefined();
      expect(s2Error!.message).toContain('patient_id');
      expect(s2Error!.message).toContain('date_of_service');
    });

    it('S3 returns error for non-existent patient', async () => {
      const claim = seedClaim({
        dateOfService: '2026-01-15',
        submissionDeadline: '2026-04-15',
      });

      const noPatientDeps: ClaimServiceDeps = {
        ...deps,
        patientCheck: patientNotFoundCheck,
      };

      const result = await validateClaim(
        noPatientDeps,
        claim.claimId,
        PHYSICIAN_1,
        USER_1,
        'PHYSICIAN',
      );

      expect(result.passed).toBe(false);
      const s3Error = result.errors.find((e) => e.check === 'S3_PATIENT_EXISTS');
      expect(s3Error).toBeDefined();
      expect(s3Error!.message).toContain('Patient record not found');
    });

    it('S4 returns error for inactive physician', async () => {
      const claim = seedClaim({
        dateOfService: '2026-01-15',
        submissionDeadline: '2026-04-15',
      });

      const inactiveDeps: ClaimServiceDeps = {
        ...deps,
        providerCheck: inactiveProviderCheck,
      };

      const result = await validateClaim(
        inactiveDeps,
        claim.claimId,
        PHYSICIAN_1,
        USER_1,
        'PHYSICIAN',
      );

      expect(result.passed).toBe(false);
      const s4Error = result.errors.find((e) => e.check === 'S4_PHYSICIAN_ACTIVE');
      expect(s4Error).toBeDefined();
      expect(s4Error!.message).toContain('not active');
    });

    it('S5 returns error for future date_of_service', async () => {
      // Set DOS far in the future
      const futureDate = new Date();
      futureDate.setUTCFullYear(futureDate.getUTCFullYear() + 1);
      const futureDos = futureDate.toISOString().split('T')[0];

      const claim = seedClaim({
        dateOfService: futureDos,
        submissionDeadline: '2028-01-01',
      });

      const result = await validateClaim(
        deps,
        claim.claimId,
        PHYSICIAN_1,
        USER_1,
        'PHYSICIAN',
      );

      expect(result.passed).toBe(false);
      const s5Error = result.errors.find((e) => e.check === 'S5_DOS_VALID');
      expect(s5Error).toBeDefined();
      expect(s5Error!.message).toContain('future');
    });

    it('S6 returns error for expired submission window', async () => {
      // Deadline in the past
      const claim = seedClaim({
        dateOfService: '2024-01-15',
        submissionDeadline: '2024-04-15',
      });

      const result = await validateClaim(
        deps,
        claim.claimId,
        PHYSICIAN_1,
        USER_1,
        'PHYSICIAN',
      );

      expect(result.passed).toBe(false);
      const s6Error = result.errors.find((e) => e.check === 'S6_SUBMISSION_WINDOW');
      expect(s6Error).toBeDefined();
      expect(s6Error!.message).toContain('expired');
    });

    it('S6 returns warning for claim within 7 days of deadline', async () => {
      // Set deadline to 3 days from now
      const deadline = new Date();
      deadline.setUTCDate(deadline.getUTCDate() + 3);
      const deadlineStr = deadline.toISOString().split('T')[0];

      const claim = seedClaim({
        dateOfService: '2026-01-15',
        submissionDeadline: deadlineStr,
      });

      const result = await validateClaim(
        deps,
        claim.claimId,
        PHYSICIAN_1,
        USER_1,
        'PHYSICIAN',
      );

      // Should still pass (warning, not error)
      expect(result.passed).toBe(true);
      const s6Warning = result.warnings.find((w) => w.check === 'S6_SUBMISSION_WINDOW');
      expect(s6Warning).toBeDefined();
      expect(s6Warning!.message).toContain('day(s)');
    });

    it('S7 returns warning for duplicate match', async () => {
      // Seed an existing claim for the same patient + same DOS
      seedClaim({
        patientId: PATIENT_1,
        dateOfService: '2026-01-15',
        submissionDeadline: '2026-04-15',
      });

      // Create the claim to validate
      const claim = seedClaim({
        patientId: PATIENT_1,
        dateOfService: '2026-01-15',
        submissionDeadline: '2026-04-15',
      });

      const result = await validateClaim(
        deps,
        claim.claimId,
        PHYSICIAN_1,
        USER_1,
        'PHYSICIAN',
      );

      // Duplicates are warnings, not errors
      expect(result.passed).toBe(true);
      const s7Warning = result.warnings.find((w) => w.check === 'S7_DUPLICATE_DETECTION');
      expect(s7Warning).toBeDefined();
      expect(s7Warning!.message).toContain('duplicate');
    });

    it('stores result with reference_data_version', async () => {
      const mockRefVersion = {
        getCurrentVersion: vi.fn().mockResolvedValue('2026.02.01'),
      };
      const versionedDeps: ClaimServiceDeps = {
        ...deps,
        referenceDataVersion: mockRefVersion,
      };

      const claim = seedClaim({
        dateOfService: '2026-01-15',
        submissionDeadline: '2026-04-15',
      });

      const result = await validateClaim(
        versionedDeps,
        claim.claimId,
        PHYSICIAN_1,
        USER_1,
        'PHYSICIAN',
      );

      expect(result.reference_data_version).toBe('2026.02.01');

      // Check the stored validation result on the claim
      const updatedClaim = claimStore.find((c) => c.claimId === claim.claimId);
      expect(updatedClaim!.validationResult).toBeDefined();
      expect(updatedClaim!.referenceDataVersion).toBe('2026.02.01');
    });

    it('transitions DRAFT -> VALIDATED on pass', async () => {
      const claim = seedClaim({
        state: 'DRAFT',
        dateOfService: '2026-01-15',
        submissionDeadline: '2026-04-15',
      });

      const result = await validateClaim(
        deps,
        claim.claimId,
        PHYSICIAN_1,
        USER_1,
        'PHYSICIAN',
      );

      expect(result.passed).toBe(true);

      // Verify state transitioned
      const updatedClaim = claimStore.find((c) => c.claimId === claim.claimId);
      expect(updatedClaim!.state).toBe('VALIDATED');

      // Verify audit entry was created
      const auditEntry = auditStore.find(
        (a) => a.claimId === claim.claimId && a.action === 'claim.validated',
      );
      expect(auditEntry).toBeDefined();
      expect(auditEntry!.previousState).toBe('DRAFT');
      expect(auditEntry!.newState).toBe('VALIDATED');
    });

    it('does not transition on errors', async () => {
      const claim = seedClaim({
        state: 'DRAFT',
        dateOfService: '2024-01-15',
        submissionDeadline: '2024-04-15', // expired
      });

      const result = await validateClaim(
        deps,
        claim.claimId,
        PHYSICIAN_1,
        USER_1,
        'PHYSICIAN',
      );

      expect(result.passed).toBe(false);

      // State should remain DRAFT
      const updatedClaim = claimStore.find((c) => c.claimId === claim.claimId);
      expect(updatedClaim!.state).toBe('DRAFT');

      // No validated audit entry
      const auditEntry = auditStore.find(
        (a) => a.claimId === claim.claimId && a.action === 'claim.validated',
      );
      expect(auditEntry).toBeUndefined();
    });

    it('throws NotFoundError for non-existent claim', async () => {
      await expect(
        validateClaim(deps, crypto.randomUUID(), PHYSICIAN_1, USER_1, 'PHYSICIAN'),
      ).rejects.toThrow('Claim not found');
    });
  });

  // =========================================================================
  // classifyCleanFlagged
  // =========================================================================

  describe('classifyCleanFlagged', () => {
    it('returns true (clean) for claim with no warnings, no suggestions, no flags, no duplicates', () => {
      const claim = {
        validationResult: { errors: [], warnings: [], info: [] },
        aiCoachSuggestions: null,
        flags: null,
        duplicateAlert: null,
      };
      expect(classifyCleanFlagged(claim)).toBe(true);
    });

    it('returns false (flagged) when validation warnings exist', () => {
      const claim = {
        validationResult: {
          errors: [],
          warnings: [{ check: 'S6', message: 'deadline approaching' }],
          info: [],
        },
        aiCoachSuggestions: null,
        flags: null,
        duplicateAlert: null,
      };
      expect(classifyCleanFlagged(claim)).toBe(false);
    });

    it('returns false (flagged) when pending AI suggestions exist', () => {
      const claim = {
        validationResult: { errors: [], warnings: [], info: [] },
        aiCoachSuggestions: {
          suggestions: [{ id: '1', status: 'PENDING', text: 'Use modifier' }],
        },
        flags: null,
        duplicateAlert: null,
      };
      expect(classifyCleanFlagged(claim)).toBe(false);
    });

    it('returns true (clean) when all AI suggestions are dismissed', () => {
      const claim = {
        validationResult: { errors: [], warnings: [], info: [] },
        aiCoachSuggestions: {
          suggestions: [{ id: '1', status: 'DISMISSED', text: 'Use modifier' }],
        },
        flags: null,
        duplicateAlert: null,
      };
      expect(classifyCleanFlagged(claim)).toBe(true);
    });

    it('returns false (flagged) when unresolved flags exist', () => {
      const claim = {
        validationResult: { errors: [], warnings: [], info: [] },
        aiCoachSuggestions: null,
        flags: { items: [{ id: '1', resolved: false, reason: 'Missing modifier' }] },
        duplicateAlert: null,
      };
      expect(classifyCleanFlagged(claim)).toBe(false);
    });

    it('returns true (clean) when all flags are resolved', () => {
      const claim = {
        validationResult: { errors: [], warnings: [], info: [] },
        aiCoachSuggestions: null,
        flags: { items: [{ id: '1', resolved: true, reason: 'Missing modifier' }] },
        duplicateAlert: null,
      };
      expect(classifyCleanFlagged(claim)).toBe(true);
    });

    it('returns false (flagged) when duplicate alerts exist', () => {
      const claim = {
        validationResult: { errors: [], warnings: [], info: [] },
        aiCoachSuggestions: null,
        flags: null,
        duplicateAlert: {
          alerts: [{ duplicateClaimId: 'abc', similarity: 0.95 }],
        },
      };
      expect(classifyCleanFlagged(claim)).toBe(false);
    });

    it('returns true (clean) for null fields', () => {
      const claim = {
        validationResult: null,
        aiCoachSuggestions: null,
        flags: null,
        duplicateAlert: null,
      };
      expect(classifyCleanFlagged(claim)).toBe(true);
    });
  });

  // =========================================================================
  // queueClaim
  // =========================================================================

  describe('queueClaim', () => {
    it('re-validates before queuing', async () => {
      const claim = seedClaim({
        state: 'VALIDATED',
        dateOfService: '2026-01-15',
        submissionDeadline: '2026-04-15',
      });

      const result = await queueClaim(
        deps,
        claim.claimId,
        PHYSICIAN_1,
        USER_1,
        'PHYSICIAN',
      );

      expect(result).toBeDefined();
      expect(result.isClean).toBeDefined();

      // Validation result should be stored on the claim
      const updatedClaim = claimStore.find((c) => c.claimId === claim.claimId);
      expect(updatedClaim!.validationResult).toBeDefined();
    });

    it('classifies clean claim correctly', async () => {
      const claim = seedClaim({
        state: 'VALIDATED',
        dateOfService: '2026-01-15',
        submissionDeadline: '2026-04-15',
        aiCoachSuggestions: null,
        flags: null,
        duplicateAlert: null,
      });

      const result = await queueClaim(
        deps,
        claim.claimId,
        PHYSICIAN_1,
        USER_1,
        'PHYSICIAN',
      );

      expect(result.isClean).toBe(true);

      const updatedClaim = claimStore.find((c) => c.claimId === claim.claimId);
      expect(updatedClaim!.isClean).toBe(true);
      expect(updatedClaim!.state).toBe('QUEUED');
    });

    it('classifies flagged claim correctly (pending AI suggestions)', async () => {
      const claim = seedClaim({
        state: 'VALIDATED',
        dateOfService: '2026-01-15',
        submissionDeadline: '2026-04-15',
        aiCoachSuggestions: {
          suggestions: [{ id: '1', status: 'PENDING', text: 'Consider modifier' }],
        },
      });

      const result = await queueClaim(
        deps,
        claim.claimId,
        PHYSICIAN_1,
        USER_1,
        'PHYSICIAN',
      );

      expect(result.isClean).toBe(false);

      const updatedClaim = claimStore.find((c) => c.claimId === claim.claimId);
      expect(updatedClaim!.isClean).toBe(false);
      expect(updatedClaim!.state).toBe('QUEUED');
    });

    it('classifies flagged claim correctly (validation warnings)', async () => {
      // Seed a claim that will get a validation warning (near deadline)
      const nearDeadline = new Date();
      nearDeadline.setDate(nearDeadline.getDate() + 3);
      const deadlineStr = nearDeadline.toISOString().split('T')[0];

      const claim = seedClaim({
        state: 'VALIDATED',
        dateOfService: '2026-01-15',
        submissionDeadline: deadlineStr,
      });

      const result = await queueClaim(
        deps,
        claim.claimId,
        PHYSICIAN_1,
        USER_1,
        'PHYSICIAN',
      );

      // Should be flagged due to the deadline warning
      expect(result.isClean).toBe(false);
    });

    it('emits CLAIM_FLAGGED notification for flagged claims', async () => {
      const mockEmitter: NotificationEmitter = {
        emit: vi.fn().mockResolvedValue(undefined),
      };

      const depsWithNotifier: ClaimServiceDeps = {
        ...deps,
        notificationEmitter: mockEmitter,
      };

      const claim = seedClaim({
        state: 'VALIDATED',
        dateOfService: '2026-01-15',
        submissionDeadline: '2026-04-15',
        aiCoachSuggestions: {
          suggestions: [{ id: '1', status: 'PENDING', text: 'Consider modifier' }],
        },
      });

      await queueClaim(
        depsWithNotifier,
        claim.claimId,
        PHYSICIAN_1,
        USER_1,
        'PHYSICIAN',
      );

      expect(mockEmitter.emit).toHaveBeenCalledWith(
        'CLAIM_FLAGGED',
        expect.objectContaining({ claimId: claim.claimId, physicianId: PHYSICIAN_1 }),
      );
    });

    it('does not emit notification for clean claims', async () => {
      const mockEmitter: NotificationEmitter = {
        emit: vi.fn().mockResolvedValue(undefined),
      };

      const depsWithNotifier: ClaimServiceDeps = {
        ...deps,
        notificationEmitter: mockEmitter,
      };

      const claim = seedClaim({
        state: 'VALIDATED',
        dateOfService: '2026-01-15',
        submissionDeadline: '2026-04-15',
        aiCoachSuggestions: null,
        flags: null,
        duplicateAlert: null,
      });

      await queueClaim(
        depsWithNotifier,
        claim.claimId,
        PHYSICIAN_1,
        USER_1,
        'PHYSICIAN',
      );

      expect(mockEmitter.emit).not.toHaveBeenCalled();
    });

    it('appends QUEUED audit entry', async () => {
      const claim = seedClaim({
        state: 'VALIDATED',
        dateOfService: '2026-01-15',
        submissionDeadline: '2026-04-15',
      });

      await queueClaim(deps, claim.claimId, PHYSICIAN_1, USER_1, 'PHYSICIAN');

      const auditEntry = auditStore.find(
        (a) => a.claimId === claim.claimId && a.action === 'claim.queued',
      );
      expect(auditEntry).toBeDefined();
      expect(auditEntry!.previousState).toBe('VALIDATED');
      expect(auditEntry!.newState).toBe('QUEUED');
      expect(auditEntry!.actorId).toBe(USER_1);
    });

    it('rejects queueing a DRAFT claim', async () => {
      const claim = seedClaim({ state: 'DRAFT' });

      await expect(
        queueClaim(deps, claim.claimId, PHYSICIAN_1, USER_1, 'PHYSICIAN'),
      ).rejects.toThrow('Cannot queue claim');
    });

    it('rejects queueing a SUBMITTED claim', async () => {
      const claim = seedClaim({ state: 'SUBMITTED' });

      await expect(
        queueClaim(deps, claim.claimId, PHYSICIAN_1, USER_1, 'PHYSICIAN'),
      ).rejects.toThrow('Cannot queue claim');
    });

    it('throws NotFoundError for non-existent claim', async () => {
      await expect(
        queueClaim(deps, crypto.randomUUID(), PHYSICIAN_1, USER_1, 'PHYSICIAN'),
      ).rejects.toThrow('Claim not found');
    });
  });

  // =========================================================================
  // unqueueClaim
  // =========================================================================

  describe('unqueueClaim', () => {
    it('transitions QUEUED -> VALIDATED', async () => {
      const claim = seedClaim({ state: 'QUEUED' });

      await unqueueClaim(deps, claim.claimId, PHYSICIAN_1, USER_1);

      const updatedClaim = claimStore.find((c) => c.claimId === claim.claimId);
      expect(updatedClaim!.state).toBe('VALIDATED');
    });

    it('appends UNQUEUED audit entry', async () => {
      const claim = seedClaim({ state: 'QUEUED' });

      await unqueueClaim(deps, claim.claimId, PHYSICIAN_1, USER_1);

      const auditEntry = auditStore.find(
        (a) => a.claimId === claim.claimId && a.action === 'claim.unqueued',
      );
      expect(auditEntry).toBeDefined();
      expect(auditEntry!.previousState).toBe('QUEUED');
      expect(auditEntry!.newState).toBe('VALIDATED');
      expect(auditEntry!.actorId).toBe(USER_1);
    });

    it('rejects unqueueing a VALIDATED claim', async () => {
      const claim = seedClaim({ state: 'VALIDATED' });

      await expect(
        unqueueClaim(deps, claim.claimId, PHYSICIAN_1, USER_1),
      ).rejects.toThrow('Cannot unqueue claim');
    });

    it('throws NotFoundError for non-existent claim', async () => {
      await expect(
        unqueueClaim(deps, crypto.randomUUID(), PHYSICIAN_1, USER_1),
      ).rejects.toThrow('Claim not found');
    });
  });

  // =========================================================================
  // approveFlaggedClaim
  // =========================================================================

  describe('approveFlaggedClaim', () => {
    it('approves a flagged queued claim (sets isClean to true)', async () => {
      const claim = seedClaim({ state: 'QUEUED', isClean: false });

      await approveFlaggedClaim(
        deps,
        claim.claimId,
        PHYSICIAN_1,
        USER_1,
        'DELEGATE',
      );

      const updatedClaim = claimStore.find((c) => c.claimId === claim.claimId);
      expect(updatedClaim!.isClean).toBe(true);
    });

    it('appends audit entry with approval metadata', async () => {
      const claim = seedClaim({ state: 'QUEUED', isClean: false });

      await approveFlaggedClaim(
        deps,
        claim.claimId,
        PHYSICIAN_1,
        USER_1,
        'DELEGATE',
      );

      const auditEntry = auditStore.find(
        (a) =>
          a.claimId === claim.claimId &&
          a.action === 'claim.queued' &&
          a.changes?.flaggedApproval === true,
      );
      expect(auditEntry).toBeDefined();
      expect(auditEntry!.changes.approvedBy).toBe(USER_1);
      expect(auditEntry!.actorContext).toBe('DELEGATE');
    });

    it('rejects approval of already clean claim', async () => {
      const claim = seedClaim({ state: 'QUEUED', isClean: true });

      await expect(
        approveFlaggedClaim(deps, claim.claimId, PHYSICIAN_1, USER_1, 'DELEGATE'),
      ).rejects.toThrow('already clean');
    });

    it('rejects approval of non-QUEUED claim', async () => {
      const claim = seedClaim({ state: 'VALIDATED', isClean: false });

      await expect(
        approveFlaggedClaim(deps, claim.claimId, PHYSICIAN_1, USER_1, 'DELEGATE'),
      ).rejects.toThrow('Cannot approve claim');
    });

    it('throws NotFoundError for non-existent claim', async () => {
      await expect(
        approveFlaggedClaim(deps, crypto.randomUUID(), PHYSICIAN_1, USER_1, 'DELEGATE'),
      ).rejects.toThrow('Claim not found');
    });
  });

  // =========================================================================
  // writeOffClaim
  // =========================================================================

  describe('writeOffClaim', () => {
    it('transitions REJECTED -> WRITTEN_OFF', async () => {
      const claim = seedClaim({ state: 'REJECTED' });

      await writeOffClaim(
        deps,
        claim.claimId,
        PHYSICIAN_1,
        USER_1,
        'Payer denied — unrecoverable',
      );

      const updatedClaim = claimStore.find((c) => c.claimId === claim.claimId);
      expect(updatedClaim!.state).toBe('WRITTEN_OFF');
    });

    it('records reason in audit entry', async () => {
      const claim = seedClaim({ state: 'REJECTED' });
      const reason = 'Payer denied — unrecoverable';

      await writeOffClaim(
        deps,
        claim.claimId,
        PHYSICIAN_1,
        USER_1,
        reason,
      );

      const auditEntry = auditStore.find(
        (a) => a.claimId === claim.claimId && a.action === 'claim.written_off',
      );
      expect(auditEntry).toBeDefined();
      expect(auditEntry!.reason).toBe(reason);
      expect(auditEntry!.previousState).toBe('REJECTED');
      expect(auditEntry!.newState).toBe('WRITTEN_OFF');
    });

    it('rejects write-off from DRAFT state', async () => {
      const claim = seedClaim({ state: 'DRAFT' });

      await expect(
        writeOffClaim(deps, claim.claimId, PHYSICIAN_1, USER_1, 'reason'),
      ).rejects.toThrow('Cannot write off claim');
    });

    it('rejects write-off from VALIDATED state', async () => {
      const claim = seedClaim({ state: 'VALIDATED' });

      await expect(
        writeOffClaim(deps, claim.claimId, PHYSICIAN_1, USER_1, 'reason'),
      ).rejects.toThrow('Cannot write off claim');
    });

    it('rejects write-off from QUEUED state', async () => {
      const claim = seedClaim({ state: 'QUEUED' });

      await expect(
        writeOffClaim(deps, claim.claimId, PHYSICIAN_1, USER_1, 'reason'),
      ).rejects.toThrow('Cannot write off claim');
    });

    it('only allows write-off from REJECTED state', async () => {
      const claim = seedClaim({ state: 'REJECTED' });

      await writeOffClaim(
        deps,
        claim.claimId,
        PHYSICIAN_1,
        USER_1,
        'reason',
      );

      const updatedClaim = claimStore.find((c) => c.claimId === claim.claimId);
      expect(updatedClaim!.state).toBe('WRITTEN_OFF');
    });

    it('throws NotFoundError for non-existent claim', async () => {
      await expect(
        writeOffClaim(deps, crypto.randomUUID(), PHYSICIAN_1, USER_1, 'reason'),
      ).rejects.toThrow('Claim not found');
    });
  });

  // =========================================================================
  // listRejectedClaims
  // =========================================================================

  describe('listRejectedClaims', () => {
    it('returns only REJECTED state claims', async () => {
      seedClaim({ state: 'REJECTED' });
      seedClaim({ state: 'REJECTED' });
      seedClaim({ state: 'DRAFT' });
      seedClaim({ state: 'VALIDATED' });
      seedClaim({ state: 'QUEUED' });
      seedClaim({ state: 'PAID' });

      const result = await listRejectedClaims(deps, PHYSICIAN_1, 1, 50);

      expect(result.data).toHaveLength(2);
      for (const claim of result.data) {
        expect(claim.state).toBe('REJECTED');
      }
      expect(result.pagination.total).toBe(2);
    });

    it('returns empty list when no rejected claims exist', async () => {
      seedClaim({ state: 'DRAFT' });
      seedClaim({ state: 'VALIDATED' });

      const result = await listRejectedClaims(deps, PHYSICIAN_1, 1, 50);

      expect(result.data).toHaveLength(0);
      expect(result.pagination.total).toBe(0);
    });

    it('enriches rejected claims with corrective guidance from explanatory codes', async () => {
      const mockLookup: ExplanatoryCodeLookup = {
        getExplanatoryCode: vi.fn().mockResolvedValue({
          code: 'INVALID_HSC',
          description: 'Invalid health service code',
          severity: 'ERROR',
          commonCause: 'Code not found in schedule',
          suggestedAction: 'Verify the health service code against SOMB fee schedule.',
          helpText: 'Check SOMB code listing.',
        }),
      };

      const depsWithLookup: ClaimServiceDeps = {
        ...deps,
        explanatoryCodeLookup: mockLookup,
      };

      seedClaim({
        state: 'REJECTED',
        validationResult: {
          errors: [{ check: 'INVALID_HSC', message: 'Invalid code' }],
          warnings: [],
          info: [],
          passed: false,
        },
      });

      const result = await listRejectedClaims(depsWithLookup, PHYSICIAN_1, 1, 50);

      expect(result.data).toHaveLength(1);
      expect(result.data[0].rejectionCodes).toHaveLength(1);
      expect(result.data[0].rejectionCodes[0].code).toBe('INVALID_HSC');
      expect(result.data[0].rejectionCodes[0].suggestedAction).toContain('Verify');
    });

    it('only returns claims for the authenticated physician', async () => {
      seedClaim({ state: 'REJECTED', physicianId: PHYSICIAN_1 });
      seedClaim({ state: 'REJECTED', physicianId: PHYSICIAN_2 });

      const result = await listRejectedClaims(deps, PHYSICIAN_1, 1, 50);

      expect(result.data).toHaveLength(1);
      expect(result.data[0].physicianId).toBe(PHYSICIAN_1);
    });

    it('respects pagination parameters', async () => {
      for (let i = 0; i < 5; i++) {
        seedClaim({ state: 'REJECTED' });
      }

      const page1 = await listRejectedClaims(deps, PHYSICIAN_1, 1, 2);
      expect(page1.data).toHaveLength(2);
      expect(page1.pagination.hasMore).toBe(true);

      const page3 = await listRejectedClaims(deps, PHYSICIAN_1, 3, 2);
      expect(page3.data).toHaveLength(1);
      expect(page3.pagination.hasMore).toBe(false);
    });
  });

  // =========================================================================
  // getRejectionDetails
  // =========================================================================

  describe('getRejectionDetails', () => {
    it('returns codes and corrective guidance', async () => {
      const claim = seedClaim({
        state: 'REJECTED',
        validationResult: {
          errors: [
            {
              check: 'S4_PHYSICIAN_ACTIVE',
              message: 'Physician is not active',
              help_text: 'Ensure your provider profile is active.',
            },
          ],
          warnings: [],
          info: [],
          passed: false,
        },
      });

      const result = await getRejectionDetails(deps, claim.claimId, PHYSICIAN_1);

      expect(result).not.toBeNull();
      expect(result!.claimId).toBe(claim.claimId);
      expect(result!.state).toBe('REJECTED');
      expect(result!.rejectionCodes).toHaveLength(1);
      expect(result!.rejectionCodes[0].code).toBe('S4_PHYSICIAN_ACTIVE');
      expect(result!.rejectionCodes[0].description).toBe('Physician is not active');
      expect(result!.resubmissionEligible).toBe(true);
    });

    it('returns null for different physician\'s claim', async () => {
      const claim = seedClaim({
        state: 'REJECTED',
        physicianId: PHYSICIAN_2,
      });

      const result = await getRejectionDetails(deps, claim.claimId, PHYSICIAN_1);

      expect(result).toBeNull();
    });

    it('returns null for non-existent claim', async () => {
      const result = await getRejectionDetails(deps, crypto.randomUUID(), PHYSICIAN_1);
      expect(result).toBeNull();
    });

    it('enriches codes via explanatory code lookup', async () => {
      const mockLookup: ExplanatoryCodeLookup = {
        getExplanatoryCode: vi.fn().mockResolvedValue({
          code: 'EXP_001',
          description: 'Service code not covered',
          severity: 'ERROR',
          commonCause: 'Code removed from schedule',
          suggestedAction: 'Use updated code from current fee schedule.',
          helpText: 'Check current SOMB schedule.',
        }),
      };

      const depsWithLookup: ClaimServiceDeps = {
        ...deps,
        explanatoryCodeLookup: mockLookup,
      };

      const claim = seedClaim({
        state: 'REJECTED',
        validationResult: {
          errors: [{ check: 'EXP_001', message: 'Not covered' }],
          warnings: [],
          info: [],
          passed: false,
        },
      });

      const result = await getRejectionDetails(depsWithLookup, claim.claimId, PHYSICIAN_1);

      expect(result!.rejectionCodes[0].description).toBe('Service code not covered');
      expect(result!.rejectionCodes[0].suggestedAction).toBe('Use updated code from current fee schedule.');
    });

    it('returns resubmissionEligible as false for non-REJECTED claims', async () => {
      const claim = seedClaim({
        state: 'DRAFT',
        validationResult: null,
      });

      const result = await getRejectionDetails(deps, claim.claimId, PHYSICIAN_1);

      expect(result).not.toBeNull();
      expect(result!.resubmissionEligible).toBe(false);
    });

    it('returns empty rejection codes when no validation result', async () => {
      const claim = seedClaim({
        state: 'REJECTED',
        validationResult: null,
      });

      const result = await getRejectionDetails(deps, claim.claimId, PHYSICIAN_1);

      expect(result!.rejectionCodes).toHaveLength(0);
      expect(result!.resubmissionEligible).toBe(true);
    });
  });

  // =========================================================================
  // resubmitClaim
  // =========================================================================

  describe('resubmitClaim', () => {
    it('re-validates before requeuing', async () => {
      const claim = seedClaim({
        state: 'REJECTED',
        claimType: 'AHCIP',
        patientId: PATIENT_1,
        dateOfService: '2026-01-15',
        submissionDeadline: '2026-04-15',
      });

      // Track providerCheck calls to confirm re-validation happened
      const providerCheckSpy = vi.fn().mockResolvedValue(true);
      const depsResubmit: ClaimServiceDeps = {
        ...deps,
        providerCheck: { isActive: providerCheckSpy },
      };

      await resubmitClaim(depsResubmit, claim.claimId, PHYSICIAN_1, USER_1);

      // providerCheck.isActive should have been called during re-validation
      expect(providerCheckSpy).toHaveBeenCalledWith(PHYSICIAN_1);
    });

    it('transitions REJECTED -> QUEUED on valid', async () => {
      const claim = seedClaim({
        state: 'REJECTED',
        claimType: 'AHCIP',
        patientId: PATIENT_1,
        dateOfService: '2026-01-15',
        submissionDeadline: '2026-04-15',
      });

      const result = await resubmitClaim(deps, claim.claimId, PHYSICIAN_1, USER_1);

      expect(result.newState).toBe('QUEUED');
      const updatedClaim = claimStore.find((c) => c.claimId === claim.claimId);
      expect(updatedClaim!.state).toBe('QUEUED');
    });

    it('appends RESUBMITTED audit entry', async () => {
      const claim = seedClaim({
        state: 'REJECTED',
        claimType: 'AHCIP',
        patientId: PATIENT_1,
        dateOfService: '2026-01-15',
        submissionDeadline: '2026-04-15',
      });

      await resubmitClaim(deps, claim.claimId, PHYSICIAN_1, USER_1);

      const auditEntries = auditStore.filter((a) => a.claimId === claim.claimId);
      const resubmitEntry = auditEntries.find(
        (a) => a.action === 'claim.resubmitted',
      );
      expect(resubmitEntry).toBeDefined();
      expect(resubmitEntry!.previousState).toBe('REJECTED');
      expect(resubmitEntry!.newState).toBe('QUEUED');
      expect(resubmitEntry!.actorId).toBe(USER_1);
    });

    it('rejects if validation fails after correction', async () => {
      const claim = seedClaim({
        state: 'REJECTED',
        claimType: 'AHCIP',
        patientId: PATIENT_1,
        dateOfService: '2026-01-15',
        submissionDeadline: '2026-04-15',
      });

      // Make the provider check fail so re-validation fails
      const depsInactive: ClaimServiceDeps = {
        ...deps,
        providerCheck: { isActive: vi.fn().mockResolvedValue(false) },
      };

      await expect(
        resubmitClaim(depsInactive, claim.claimId, PHYSICIAN_1, USER_1),
      ).rejects.toThrow('Claim failed re-validation and cannot be resubmitted');

      // Claim should still be in REJECTED state
      const updatedClaim = claimStore.find((c) => c.claimId === claim.claimId);
      expect(updatedClaim!.state).toBe('REJECTED');
    });

    it('throws ConflictError for non-REJECTED claim', async () => {
      const claim = seedClaim({ state: 'DRAFT' });

      await expect(
        resubmitClaim(deps, claim.claimId, PHYSICIAN_1, USER_1),
      ).rejects.toThrow('Cannot resubmit claim');
    });

    it('throws NotFoundError for non-existent claim', async () => {
      await expect(
        resubmitClaim(deps, crypto.randomUUID(), PHYSICIAN_1, USER_1),
      ).rejects.toThrow('Claim not found');
    });

    it('emits notification on successful resubmission', async () => {
      const emitSpy = vi.fn().mockResolvedValue(undefined);
      const depsNotify: ClaimServiceDeps = {
        ...deps,
        notificationEmitter: { emit: emitSpy },
      };

      const claim = seedClaim({
        state: 'REJECTED',
        claimType: 'AHCIP',
        patientId: PATIENT_1,
        dateOfService: '2026-01-15',
        submissionDeadline: '2026-04-15',
      });

      await resubmitClaim(depsNotify, claim.claimId, PHYSICIAN_1, USER_1);

      expect(emitSpy).toHaveBeenCalledWith(
        'CLAIM_VALIDATED',
        expect.objectContaining({
          claimId: claim.claimId,
          physicianId: PHYSICIAN_1,
          resubmission: true,
        }),
      );
    });
  });

  // =========================================================================
  // expireClaimWithContext
  // =========================================================================

  describe('expireClaimWithContext', () => {
    it('transitions non-terminal claim past deadline to EXPIRED', async () => {
      const claim = seedClaim({
        state: 'DRAFT',
        submissionDeadline: '2024-01-15', // past deadline
      });

      await expireClaimWithContext(
        deps,
        claim.claimId,
        PHYSICIAN_1,
        'DRAFT',
      );

      const updatedClaim = claimStore.find((c) => c.claimId === claim.claimId);
      expect(updatedClaim!.state).toBe('EXPIRED');
    });

    it('emits DEADLINE_EXPIRED notification', async () => {
      const mockEmitter: NotificationEmitter = {
        emit: vi.fn().mockResolvedValue(undefined),
      };

      const depsWithNotifier: ClaimServiceDeps = {
        ...deps,
        notificationEmitter: mockEmitter,
      };

      const claim = seedClaim({
        state: 'VALIDATED',
        submissionDeadline: '2024-01-15',
      });

      await expireClaimWithContext(
        depsWithNotifier,
        claim.claimId,
        PHYSICIAN_1,
        'VALIDATED',
      );

      expect(mockEmitter.emit).toHaveBeenCalledWith(
        'DEADLINE_EXPIRED',
        expect.objectContaining({ claimId: claim.claimId, physicianId: PHYSICIAN_1 }),
      );
    });

    it('appends EXPIRED audit entry with SYSTEM actor', async () => {
      const claim = seedClaim({
        state: 'QUEUED',
        submissionDeadline: '2024-01-15',
      });

      await expireClaimWithContext(
        deps,
        claim.claimId,
        PHYSICIAN_1,
        'QUEUED',
      );

      const auditEntry = auditStore.find(
        (a) => a.claimId === claim.claimId && a.action === 'claim.expired',
      );
      expect(auditEntry).toBeDefined();
      expect(auditEntry!.actorId).toBe('SYSTEM');
      expect(auditEntry!.actorContext).toBe('SYSTEM');
      expect(auditEntry!.previousState).toBe('QUEUED');
      expect(auditEntry!.newState).toBe('EXPIRED');
    });

    it('rejects expiring a terminal state claim (PAID)', async () => {
      const claim = seedClaim({
        state: 'PAID',
        submissionDeadline: '2024-01-15',
      });

      await expect(
        expireClaimWithContext(deps, claim.claimId, PHYSICIAN_1, 'PAID'),
      ).rejects.toThrow('already in terminal state');
    });

    it('rejects expiring a terminal state claim (WRITTEN_OFF)', async () => {
      const claim = seedClaim({
        state: 'WRITTEN_OFF',
        submissionDeadline: '2024-01-15',
      });

      await expect(
        expireClaimWithContext(deps, claim.claimId, PHYSICIAN_1, 'WRITTEN_OFF'),
      ).rejects.toThrow('already in terminal state');
    });

    it('rejects expiring a claim whose deadline has not passed', async () => {
      const futureDate = new Date();
      futureDate.setDate(futureDate.getDate() + 30);
      const futureDateStr = futureDate.toISOString().split('T')[0];

      const claim = seedClaim({
        state: 'DRAFT',
        submissionDeadline: futureDateStr,
      });

      await expect(
        expireClaimWithContext(deps, claim.claimId, PHYSICIAN_1, 'DRAFT'),
      ).rejects.toThrow('deadline has not yet passed');
    });

    it('can expire a VALIDATED claim', async () => {
      const claim = seedClaim({
        state: 'VALIDATED',
        submissionDeadline: '2024-01-15',
      });

      await expireClaimWithContext(
        deps,
        claim.claimId,
        PHYSICIAN_1,
        'VALIDATED',
      );

      const updatedClaim = claimStore.find((c) => c.claimId === claim.claimId);
      expect(updatedClaim!.state).toBe('EXPIRED');
    });

    it('can expire a QUEUED claim', async () => {
      const claim = seedClaim({
        state: 'QUEUED',
        submissionDeadline: '2024-01-15',
      });

      await expireClaimWithContext(
        deps,
        claim.claimId,
        PHYSICIAN_1,
        'QUEUED',
      );

      const updatedClaim = claimStore.find((c) => c.claimId === claim.claimId);
      expect(updatedClaim!.state).toBe('EXPIRED');
    });
  });

  // =========================================================================
  // getClaimsForAutoSubmission
  // =========================================================================

  describe('getClaimsForAutoSubmission', () => {
    it('AUTO_CLEAN mode includes clean claims, excludes flagged', async () => {
      seedClaim({ state: 'QUEUED', isClean: true, claimType: 'AHCIP' });
      seedClaim({ state: 'QUEUED', isClean: false, claimType: 'AHCIP' });
      seedClaim({ state: 'QUEUED', isClean: true, claimType: 'AHCIP' });

      const mockPref: SubmissionPreferenceLookup = {
        getSubmissionMode: vi.fn().mockResolvedValue('AUTO_CLEAN'),
      };

      const depsWithPref: ClaimServiceDeps = {
        ...deps,
        submissionPreference: mockPref,
      };

      const result = await getClaimsForAutoSubmission(
        depsWithPref,
        PHYSICIAN_1,
        'AHCIP',
      );

      expect(result.mode).toBe('AUTO_CLEAN');
      expect(result.claims).toHaveLength(2);
      expect(result.claims.every((c: any) => c.isClean === true)).toBe(true);
    });

    it('AUTO_ALL mode includes both clean and flagged', async () => {
      seedClaim({ state: 'QUEUED', isClean: true, claimType: 'AHCIP' });
      seedClaim({ state: 'QUEUED', isClean: false, claimType: 'AHCIP' });

      const mockPref: SubmissionPreferenceLookup = {
        getSubmissionMode: vi.fn().mockResolvedValue('AUTO_ALL'),
      };

      const depsWithPref: ClaimServiceDeps = {
        ...deps,
        submissionPreference: mockPref,
      };

      const result = await getClaimsForAutoSubmission(
        depsWithPref,
        PHYSICIAN_1,
        'AHCIP',
      );

      expect(result.mode).toBe('AUTO_ALL');
      expect(result.claims).toHaveLength(2);
    });

    it('REQUIRE_APPROVAL mode includes only approved (clean) claims', async () => {
      seedClaim({ state: 'QUEUED', isClean: true, claimType: 'AHCIP' }); // approved
      seedClaim({ state: 'QUEUED', isClean: false, claimType: 'AHCIP' }); // not approved

      const mockPref: SubmissionPreferenceLookup = {
        getSubmissionMode: vi.fn().mockResolvedValue('REQUIRE_APPROVAL'),
      };

      const depsWithPref: ClaimServiceDeps = {
        ...deps,
        submissionPreference: mockPref,
      };

      const result = await getClaimsForAutoSubmission(
        depsWithPref,
        PHYSICIAN_1,
        'AHCIP',
      );

      expect(result.mode).toBe('REQUIRE_APPROVAL');
      expect(result.claims).toHaveLength(1);
      expect(result.claims[0].isClean).toBe(true);
    });

    it('defaults to AUTO_CLEAN when no submission preference provider', async () => {
      seedClaim({ state: 'QUEUED', isClean: true, claimType: 'AHCIP' });
      seedClaim({ state: 'QUEUED', isClean: false, claimType: 'AHCIP' });

      const result = await getClaimsForAutoSubmission(
        deps,
        PHYSICIAN_1,
        'AHCIP',
      );

      expect(result.mode).toBe('AUTO_CLEAN');
      expect(result.claims).toHaveLength(1);
      expect(result.claims[0].isClean).toBe(true);
    });
  });

  // =========================================================================
  // reclassifyQueuedClaim
  // =========================================================================

  describe('reclassifyQueuedClaim', () => {
    it('re-evaluates clean/flagged on queued claim update', async () => {
      // Start as clean, then add AI suggestions making it flagged
      const claim = seedClaim({
        state: 'QUEUED',
        isClean: true,
        aiCoachSuggestions: {
          suggestions: [{ id: '1', status: 'PENDING', text: 'Consider modifier' }],
        },
      });

      const result = await reclassifyQueuedClaim(deps, claim.claimId, PHYSICIAN_1);

      expect(result.isClean).toBe(false);
      const updatedClaim = claimStore.find((c) => c.claimId === claim.claimId);
      expect(updatedClaim!.isClean).toBe(false);
    });

    it('re-evaluates to clean when issues resolved', async () => {
      const claim = seedClaim({
        state: 'QUEUED',
        isClean: false,
        aiCoachSuggestions: {
          suggestions: [{ id: '1', status: 'DISMISSED', text: 'Consider modifier' }],
        },
        flags: null,
        duplicateAlert: null,
        validationResult: { errors: [], warnings: [], info: [] },
      });

      const result = await reclassifyQueuedClaim(deps, claim.claimId, PHYSICIAN_1);

      expect(result.isClean).toBe(true);
    });

    it('rejects reclassification for non-QUEUED claim', async () => {
      const claim = seedClaim({ state: 'VALIDATED' });

      await expect(
        reclassifyQueuedClaim(deps, claim.claimId, PHYSICIAN_1),
      ).rejects.toThrow('QUEUED state');
    });

    it('throws NotFoundError for non-existent claim', async () => {
      await expect(
        reclassifyQueuedClaim(deps, crypto.randomUUID(), PHYSICIAN_1),
      ).rejects.toThrow('Claim not found');
    });
  });

  // =========================================================================
  // EMR Import: uploadImport
  // =========================================================================

  describe('uploadImport', () => {
    it('computes SHA-256 hash and creates import batch', async () => {
      const file = {
        fileName: 'test.csv',
        content: 'patient_id,date_of_service,claim_type\np1,2026-01-15,AHCIP\n',
      };

      const result = await uploadImport(deps, PHYSICIAN_1, USER_1, file);

      expect(result.importBatchId).toBeDefined();

      const batch = importBatchStore.find(
        (b) => b.importBatchId === result.importBatchId,
      );
      expect(batch).toBeDefined();
      expect(batch!.physicianId).toBe(PHYSICIAN_1);
      expect(batch!.fileName).toBe('test.csv');
      expect(batch!.fileHash).toBeDefined();
      expect(batch!.fileHash.length).toBe(64); // SHA-256 hex
      expect(batch!.status).toBe('PENDING');
    });

    it('detects duplicate file by hash', async () => {
      const fileContent = 'patient_id,date_of_service,claim_type\np1,2026-01-15,AHCIP\n';

      // First upload should succeed
      await uploadImport(deps, PHYSICIAN_1, USER_1, {
        fileName: 'test.csv',
        content: fileContent,
      });

      // Second upload with identical content should fail
      await expect(
        uploadImport(deps, PHYSICIAN_1, USER_1, {
          fileName: 'test_copy.csv',
          content: fileContent,
        }),
      ).rejects.toThrow('already been imported');
    });

    it('parses CSV with comma delimiter', async () => {
      const file = {
        fileName: 'comma.csv',
        content: 'patient_id,date_of_service,claim_type\np1,2026-01-15,AHCIP\np2,2026-02-20,WCB\n',
      };

      const result = await uploadImport(deps, PHYSICIAN_1, USER_1, file);
      const batch = importBatchStore.find((b) => b.importBatchId === result.importBatchId);
      expect(batch!.totalRows).toBe(2); // 2 data rows (header excluded)
    });

    it('parses TSV with tab delimiter', async () => {
      const templateId = seedTemplate({
        delimiter: '\t',
        hasHeaderRow: true,
        mappings: [
          { source_column: 'patient_id', target_field: 'patientId' },
          { source_column: 'date_of_service', target_field: 'dateOfService' },
        ],
      }).templateId;

      const file = {
        fileName: 'tab.tsv',
        content: 'patient_id\tdate_of_service\tclaim_type\np1\t2026-01-15\tAHCIP\n',
      };

      const result = await uploadImport(deps, PHYSICIAN_1, USER_1, file, templateId);
      const batch = importBatchStore.find((b) => b.importBatchId === result.importBatchId);
      expect(batch!.totalRows).toBe(1);
      expect(batch!.fieldMappingTemplateId).toBe(templateId);
    });

    it('uses template delimiter when specified', async () => {
      const templateId = seedTemplate({
        delimiter: '|',
        hasHeaderRow: true,
      }).templateId;

      const file = {
        fileName: 'pipe.csv',
        content: 'patient_id|date_of_service|claim_type\np1|2026-01-15|AHCIP\n',
      };

      const result = await uploadImport(deps, PHYSICIAN_1, USER_1, file, templateId);
      const batch = importBatchStore.find((b) => b.importBatchId === result.importBatchId);
      expect(batch!.totalRows).toBe(1);
    });

    it('throws NotFoundError for non-existent template', async () => {
      await expect(
        uploadImport(deps, PHYSICIAN_1, USER_1, {
          fileName: 'test.csv',
          content: 'a,b,c\n1,2,3\n',
        }, crypto.randomUUID()),
      ).rejects.toThrow('Field mapping template not found');
    });
  });

  // =========================================================================
  // EMR Import: previewImport
  // =========================================================================

  describe('previewImport', () => {
    it('applies field mapping template', async () => {
      const templateId = seedTemplate({
        delimiter: ',',
        hasHeaderRow: true,
        dateFormat: 'YYYY-MM-DD',
        mappings: [
          { source_column: 'pid', target_field: 'patientId' },
          { source_column: 'dos', target_field: 'dateOfService' },
          { source_column: 'type', target_field: 'claimType' },
        ],
      }).templateId;

      const batchId = seedImportBatch({
        fieldMappingTemplateId: templateId,
        fileHash: 'b'.repeat(64),
      }).importBatchId;

      const content = 'pid,dos,type\n' + PATIENT_1 + ',2026-01-15,AHCIP\n';
      const preview = await previewImport(deps, batchId, PHYSICIAN_1, content);

      expect(preview.rows).toHaveLength(1);
      expect(preview.rows[0].mapped.patientId).toBe(PATIENT_1);
      expect(preview.rows[0].mapped.dateOfService).toBe('2026-01-15');
      expect(preview.rows[0].mapped.claimType).toBe('AHCIP');
      expect(preview.rows[0].errors).toHaveLength(0);
    });

    it('reports unmapped columns', async () => {
      const templateId = seedTemplate({
        delimiter: ',',
        hasHeaderRow: true,
        mappings: [
          { source_column: 'pid', target_field: 'patientId' },
          { source_column: 'dos', target_field: 'dateOfService' },
          { source_column: 'type', target_field: 'claimType' },
        ],
      }).templateId;

      const batchId = seedImportBatch({
        fieldMappingTemplateId: templateId,
        fileHash: 'c'.repeat(64),
      }).importBatchId;

      const content = 'pid,dos,type,extra_col,notes\n' + PATIENT_1 + ',2026-01-15,AHCIP,foo,bar\n';
      const preview = await previewImport(deps, batchId, PHYSICIAN_1, content);

      expect(preview.unmappedColumns).toContain('extra_col');
      expect(preview.unmappedColumns).toContain('notes');
      expect(preview.unmappedColumns).not.toContain('pid');
    });

    it('validates each row and reports errors for missing required fields', async () => {
      const templateId = seedTemplate({
        delimiter: ',',
        hasHeaderRow: true,
        mappings: [
          { source_column: 'pid', target_field: 'patientId' },
          // dateOfService mapping intentionally missing
          { source_column: 'type', target_field: 'claimType' },
        ],
      }).templateId;

      const batchId = seedImportBatch({
        fieldMappingTemplateId: templateId,
        fileHash: 'd'.repeat(64),
      }).importBatchId;

      const content = 'pid,dos,type\n' + PATIENT_1 + ',2026-01-15,AHCIP\n';
      const preview = await previewImport(deps, batchId, PHYSICIAN_1, content);

      expect(preview.rows[0].errors.length).toBeGreaterThan(0);
      expect(preview.rows[0].errors.some((e) => e.field === 'dateOfService')).toBe(true);
      expect(preview.errorRows).toBe(1);
      expect(preview.validRows).toBe(0);
    });

    it('handles multiple date formats via template', async () => {
      const templateId = seedTemplate({
        delimiter: ',',
        hasHeaderRow: true,
        dateFormat: 'DD/MM/YYYY',
        mappings: [
          { source_column: 'pid', target_field: 'patientId' },
          { source_column: 'dos', target_field: 'dateOfService' },
          { source_column: 'type', target_field: 'claimType' },
        ],
      }).templateId;

      const batchId = seedImportBatch({
        fieldMappingTemplateId: templateId,
        fileHash: 'e'.repeat(64),
      }).importBatchId;

      const content = 'pid,dos,type\n' + PATIENT_1 + ',15/01/2026,AHCIP\n';
      const preview = await previewImport(deps, batchId, PHYSICIAN_1, content);

      expect(preview.rows[0].mapped.dateOfService).toBe('2026-01-15');
      expect(preview.rows[0].errors).toHaveLength(0);
    });

    it('auto-detects delimiter when no template', async () => {
      const batchId = seedImportBatch({
        fieldMappingTemplateId: null,
        fileHash: 'f'.repeat(64),
      }).importBatchId;

      // Tab-separated content should be auto-detected
      const content = 'pid\tdos\ttype\n' + PATIENT_1 + '\t2026-01-15\tAHCIP\n';
      const preview = await previewImport(deps, batchId, PHYSICIAN_1, content);

      // Without mappings, all required fields are missing
      expect(preview.totalRows).toBe(1);
    });

    it('throws NotFoundError for non-existent import batch', async () => {
      await expect(
        previewImport(deps, crypto.randomUUID(), PHYSICIAN_1, 'a,b\n1,2\n'),
      ).rejects.toThrow('Import batch not found');
    });
  });

  // =========================================================================
  // EMR Import: commitImport
  // =========================================================================

  describe('commitImport', () => {
    it('creates claims for valid rows', async () => {
      const templateId = seedTemplate({
        delimiter: ',',
        hasHeaderRow: true,
        mappings: [
          { source_column: 'pid', target_field: 'patientId' },
          { source_column: 'dos', target_field: 'dateOfService' },
          { source_column: 'type', target_field: 'claimType' },
        ],
      }).templateId;

      const batchId = seedImportBatch({
        fieldMappingTemplateId: templateId,
        fileHash: 'g'.repeat(64),
        status: 'PENDING',
      }).importBatchId;

      const content = 'pid,dos,type\n' + PATIENT_1 + ',2026-01-15,AHCIP\n';
      const result = await commitImport(deps, batchId, PHYSICIAN_1, USER_1, content);

      expect(result.successCount).toBe(1);
      expect(result.errorCount).toBe(0);
      expect(result.errorDetails).toHaveLength(0);

      // Verify a claim was created
      const importedClaims = claimStore.filter(
        (c) => c.importSource === 'EMR_IMPORT' && c.importBatchId === batchId,
      );
      expect(importedClaims).toHaveLength(1);
      expect(importedClaims[0].patientId).toBe(PATIENT_1);
      expect(importedClaims[0].dateOfService).toBe('2026-01-15');
    });

    it('skips failed rows with error details', async () => {
      const templateId = seedTemplate({
        delimiter: ',',
        hasHeaderRow: true,
        mappings: [
          { source_column: 'pid', target_field: 'patientId' },
          // dateOfService mapping missing — will cause error
          { source_column: 'type', target_field: 'claimType' },
        ],
      }).templateId;

      const batchId = seedImportBatch({
        fieldMappingTemplateId: templateId,
        fileHash: 'h'.repeat(64),
        status: 'PENDING',
      }).importBatchId;

      const content = 'pid,dos,type\n' + PATIENT_1 + ',2026-01-15,AHCIP\n';
      const result = await commitImport(deps, batchId, PHYSICIAN_1, USER_1, content);

      expect(result.errorCount).toBeGreaterThan(0);
      expect(result.errorDetails.length).toBeGreaterThan(0);
      expect(result.errorDetails[0].rowNumber).toBe(1);
    });

    it('updates batch counts after commit', async () => {
      const templateId = seedTemplate({
        delimiter: ',',
        hasHeaderRow: true,
        mappings: [
          { source_column: 'pid', target_field: 'patientId' },
          { source_column: 'dos', target_field: 'dateOfService' },
          { source_column: 'type', target_field: 'claimType' },
        ],
      }).templateId;

      const batchId = seedImportBatch({
        fieldMappingTemplateId: templateId,
        fileHash: 'i'.repeat(64),
        status: 'PENDING',
      }).importBatchId;

      const content = 'pid,dos,type\n' + PATIENT_1 + ',2026-01-15,AHCIP\n' + PATIENT_1 + ',2026-01-20,WCB\n';
      const result = await commitImport(deps, batchId, PHYSICIAN_1, USER_1, content);

      expect(result.successCount).toBe(2);

      // Verify batch record was updated
      const batch = importBatchStore.find((b) => b.importBatchId === batchId);
      expect(batch!.status).toBe('COMPLETED');
      expect(batch!.successCount).toBe(2);
    });

    it('handles partial failures correctly', async () => {
      // Set patient check to return false for second patient
      let callCount = 0;
      const conditionalPatientCheck = {
        exists: vi.fn().mockImplementation(async (patientId: string) => {
          callCount++;
          // First claim's patient exists, second doesn't
          return patientId === PATIENT_1;
        }),
      };

      const depsWithConditional: ClaimServiceDeps = {
        ...deps,
        patientCheck: conditionalPatientCheck,
      };

      const PATIENT_BAD = crypto.randomUUID();

      const templateId = seedTemplate({
        delimiter: ',',
        hasHeaderRow: true,
        mappings: [
          { source_column: 'pid', target_field: 'patientId' },
          { source_column: 'dos', target_field: 'dateOfService' },
          { source_column: 'type', target_field: 'claimType' },
        ],
      }).templateId;

      const batchId = seedImportBatch({
        fieldMappingTemplateId: templateId,
        fileHash: 'j'.repeat(64),
        status: 'PENDING',
      }).importBatchId;

      const content = 'pid,dos,type\n' + PATIENT_1 + ',2026-01-15,AHCIP\n' + PATIENT_BAD + ',2026-02-20,AHCIP\n';
      const result = await commitImport(depsWithConditional, batchId, PHYSICIAN_1, USER_1, content);

      // First row succeeds, second fails (patient not found)
      expect(result.successCount).toBe(1);
      expect(result.errorCount).toBe(1);
      expect(result.errorDetails).toHaveLength(1);
      expect(result.errorDetails[0].rowNumber).toBe(2);
    });

    it('rejects already-processed batch', async () => {
      const batchId = seedImportBatch({
        status: 'COMPLETED',
        fileHash: 'k'.repeat(64),
      }).importBatchId;

      await expect(
        commitImport(deps, batchId, PHYSICIAN_1, USER_1, 'a,b\n1,2\n'),
      ).rejects.toThrow('already been processed');
    });

    it('throws NotFoundError for non-existent batch', async () => {
      await expect(
        commitImport(deps, crypto.randomUUID(), PHYSICIAN_1, USER_1, 'a,b\n1,2\n'),
      ).rejects.toThrow('Import batch not found');
    });
  });

  // =========================================================================
  // EMR Import: parsing helpers
  // =========================================================================

  describe('detectDelimiter', () => {
    it('detects comma delimiter', () => {
      expect(detectDelimiter('a,b,c,d')).toBe(',');
    });

    it('detects tab delimiter', () => {
      expect(detectDelimiter('a\tb\tc\td')).toBe('\t');
    });

    it('detects pipe delimiter', () => {
      expect(detectDelimiter('a|b|c|d')).toBe('|');
    });

    it('defaults to comma when no delimiter found', () => {
      expect(detectDelimiter('abcd')).toBe(',');
    });
  });

  describe('parseDate', () => {
    it('parses YYYY-MM-DD', () => {
      expect(parseDate('2026-01-15')).toBe('2026-01-15');
    });

    it('parses DD/MM/YYYY with explicit format', () => {
      expect(parseDate('15/01/2026', 'DD/MM/YYYY')).toBe('2026-01-15');
    });

    it('parses MM/DD/YYYY with explicit format', () => {
      expect(parseDate('01/15/2026', 'MM/DD/YYYY')).toBe('2026-01-15');
    });

    it('auto-detects DD/MM/YYYY when day > 12', () => {
      expect(parseDate('25/06/2026')).toBe('2026-06-25');
    });

    it('auto-detects MM/DD/YYYY when month > 12', () => {
      expect(parseDate('06/25/2026')).toBe('2026-06-25');
    });

    it('returns null for empty string', () => {
      expect(parseDate('')).toBeNull();
    });

    it('returns null for unparseable date', () => {
      expect(parseDate('not-a-date')).toBeNull();
    });
  });

  describe('parseRows', () => {
    it('parses comma-separated rows', () => {
      const rows = parseRows('a,b,c\n1,2,3\n4,5,6', ',');
      expect(rows).toHaveLength(3);
      expect(rows[0]).toEqual(['a', 'b', 'c']);
      expect(rows[1]).toEqual(['1', '2', '3']);
    });

    it('parses tab-separated rows', () => {
      const rows = parseRows('a\tb\tc\n1\t2\t3', '\t');
      expect(rows).toHaveLength(2);
      expect(rows[0]).toEqual(['a', 'b', 'c']);
    });

    it('handles quoted fields with commas', () => {
      const rows = parseRows('a,"b,c",d\n1,"2,3",4', ',');
      expect(rows[0]).toEqual(['a', 'b,c', 'd']);
      expect(rows[1]).toEqual(['1', '2,3', '4']);
    });

    it('handles empty lines', () => {
      const rows = parseRows('a,b\n\n1,2\n\n', ',');
      expect(rows).toHaveLength(2);
    });
  });

  // =========================================================================
  // AI Coach: getClaimSuggestions
  // =========================================================================

  describe('getClaimSuggestions', () => {
    it('returns suggestions for owned claim', async () => {
      const suggestions = [
        { id: crypto.randomUUID(), status: 'PENDING', field: 'healthServiceCode', suggestedValue: '03.04A' },
        { id: crypto.randomUUID(), status: 'ACCEPTED', field: 'modifier1', suggestedValue: 'CMGP' },
      ];
      seedClaim({ aiCoachSuggestions: { suggestions } });
      const claim = claimStore[0];

      const result = await getClaimSuggestions(deps, claim.claimId, PHYSICIAN_1);

      expect(result.suggestions).toHaveLength(2);
      expect(result.suggestions[0].status).toBe('PENDING');
      expect(result.suggestions[1].status).toBe('ACCEPTED');
    });

    it('returns empty array when no suggestions exist', async () => {
      seedClaim({ aiCoachSuggestions: null });
      const claim = claimStore[0];

      const result = await getClaimSuggestions(deps, claim.claimId, PHYSICIAN_1);

      expect(result.suggestions).toHaveLength(0);
    });

    it('throws NotFoundError for non-existent claim', async () => {
      await expect(
        getClaimSuggestions(deps, crypto.randomUUID(), PHYSICIAN_1),
      ).rejects.toThrow('Claim not found');
    });

    it('handles array-format suggestions', async () => {
      const suggestions = [
        { id: crypto.randomUUID(), status: 'PENDING', field: 'healthServiceCode', suggestedValue: '03.04A' },
      ];
      seedClaim({ aiCoachSuggestions: suggestions });
      const claim = claimStore[0];

      const result = await getClaimSuggestions(deps, claim.claimId, PHYSICIAN_1);

      expect(result.suggestions).toHaveLength(1);
    });
  });

  // =========================================================================
  // AI Coach: acceptSuggestion
  // =========================================================================

  describe('acceptSuggestion', () => {
    it('marks suggestion as accepted and applies change', async () => {
      const sugId = crypto.randomUUID();
      const suggestions = [
        { id: sugId, status: 'PENDING', field: 'healthServiceCode', suggestedValue: '03.04A' },
      ];
      seedClaim({
        state: 'VALIDATED',
        aiCoachSuggestions: { suggestions },
      });
      const claim = claimStore[0];

      await acceptSuggestion(deps, claim.claimId, sugId, PHYSICIAN_1, USER_1);

      // Verify suggestion is marked as ACCEPTED in store
      const updated = claimStore.find((c) => c.claimId === claim.claimId);
      const updatedSuggestions = updated!.aiCoachSuggestions.suggestions;
      expect(updatedSuggestions[0].status).toBe('ACCEPTED');

      // Verify the claim field was updated
      expect(updated!.healthServiceCode).toBe('03.04A');
    });

    it('re-validates claim after applying suggestion', async () => {
      const sugId = crypto.randomUUID();
      const suggestions = [
        { id: sugId, status: 'PENDING', field: 'dateOfService', suggestedValue: '2026-01-20' },
      ];
      seedClaim({
        state: 'VALIDATED',
        aiCoachSuggestions: { suggestions },
      });
      const claim = claimStore[0];

      await acceptSuggestion(deps, claim.claimId, sugId, PHYSICIAN_1, USER_1);

      // Verify validation result was updated
      const updated = claimStore.find((c) => c.claimId === claim.claimId);
      expect(updated!.validationResult).toBeDefined();
      expect(updated!.validationTimestamp).toBeDefined();
    });

    it('appends AI_SUGGESTION_ACCEPTED audit entry', async () => {
      const sugId = crypto.randomUUID();
      const suggestions = [
        { id: sugId, status: 'PENDING', field: 'healthServiceCode', suggestedValue: '03.04A' },
      ];
      seedClaim({
        state: 'VALIDATED',
        aiCoachSuggestions: { suggestions },
      });
      const claim = claimStore[0];

      await acceptSuggestion(deps, claim.claimId, sugId, PHYSICIAN_1, USER_1);

      const auditEntry = auditStore.find(
        (a) => a.claimId === claim.claimId && a.action === 'claim.ai_suggestion_accepted',
      );
      expect(auditEntry).toBeDefined();
      expect(auditEntry!.changes.suggestionId).toBe(sugId);
      expect(auditEntry!.actorId).toBe(USER_1);
    });

    it('re-evaluates clean/flagged if claim is queued', async () => {
      const sugId = crypto.randomUUID();
      const suggestions = [
        { id: sugId, status: 'PENDING', field: 'healthServiceCode', suggestedValue: '03.04A' },
      ];
      seedClaim({
        state: 'QUEUED',
        isClean: false,
        aiCoachSuggestions: { suggestions },
      });
      const claim = claimStore[0];

      await acceptSuggestion(deps, claim.claimId, sugId, PHYSICIAN_1, USER_1);

      // After accepting the only pending suggestion, claim should become clean
      const updated = claimStore.find((c) => c.claimId === claim.claimId);
      expect(updated!.isClean).toBe(true);
    });

    it('throws NotFoundError for non-existent suggestion', async () => {
      seedClaim({
        state: 'VALIDATED',
        aiCoachSuggestions: { suggestions: [] },
      });
      const claim = claimStore[0];

      await expect(
        acceptSuggestion(deps, claim.claimId, crypto.randomUUID(), PHYSICIAN_1, USER_1),
      ).rejects.toThrow('Suggestion not found');
    });

    it('throws BusinessRuleError for already processed suggestion', async () => {
      const sugId = crypto.randomUUID();
      seedClaim({
        state: 'VALIDATED',
        aiCoachSuggestions: { suggestions: [{ id: sugId, status: 'ACCEPTED', field: 'x', suggestedValue: 'y' }] },
      });
      const claim = claimStore[0];

      await expect(
        acceptSuggestion(deps, claim.claimId, sugId, PHYSICIAN_1, USER_1),
      ).rejects.toThrow('Suggestion has already been processed');
    });
  });

  // =========================================================================
  // AI Coach: dismissSuggestion
  // =========================================================================

  describe('dismissSuggestion', () => {
    it('marks suggestion as dismissed with optional reason', async () => {
      const sugId = crypto.randomUUID();
      const suggestions = [
        { id: sugId, status: 'PENDING', field: 'healthServiceCode', suggestedValue: '03.04A' },
      ];
      seedClaim({
        state: 'VALIDATED',
        aiCoachSuggestions: { suggestions },
      });
      const claim = claimStore[0];

      await dismissSuggestion(deps, claim.claimId, sugId, PHYSICIAN_1, USER_1, 'Not applicable');

      const updated = claimStore.find((c) => c.claimId === claim.claimId);
      const updatedSuggestions = updated!.aiCoachSuggestions.suggestions;
      expect(updatedSuggestions[0].status).toBe('DISMISSED');
      expect(updatedSuggestions[0].dismissReason).toBe('Not applicable');
    });

    it('appends AI_SUGGESTION_DISMISSED audit entry with reason', async () => {
      const sugId = crypto.randomUUID();
      const suggestions = [
        { id: sugId, status: 'PENDING', field: 'healthServiceCode', suggestedValue: '03.04A' },
      ];
      seedClaim({
        state: 'VALIDATED',
        aiCoachSuggestions: { suggestions },
      });
      const claim = claimStore[0];

      await dismissSuggestion(deps, claim.claimId, sugId, PHYSICIAN_1, USER_1, 'Physician override');

      const auditEntry = auditStore.find(
        (a) => a.claimId === claim.claimId && a.action === 'claim.ai_suggestion_dismissed',
      );
      expect(auditEntry).toBeDefined();
      expect(auditEntry!.changes.suggestionId).toBe(sugId);
      expect(auditEntry!.changes.reason).toBe('Physician override');
    });

    it('dismissSuggestion re-evaluates clean/flagged if queued', async () => {
      const sugId = crypto.randomUUID();
      const suggestions = [
        { id: sugId, status: 'PENDING', field: 'healthServiceCode', suggestedValue: '03.04A' },
      ];
      seedClaim({
        state: 'QUEUED',
        isClean: false,
        aiCoachSuggestions: { suggestions },
      });
      const claim = claimStore[0];

      await dismissSuggestion(deps, claim.claimId, sugId, PHYSICIAN_1, USER_1);

      // After dismissing the only pending suggestion, claim should become clean
      const updated = claimStore.find((c) => c.claimId === claim.claimId);
      expect(updated!.isClean).toBe(true);
    });

    it('dismissSuggestion without reason defaults to null', async () => {
      const sugId = crypto.randomUUID();
      const suggestions = [
        { id: sugId, status: 'PENDING', field: 'healthServiceCode', suggestedValue: '03.04A' },
      ];
      seedClaim({
        state: 'VALIDATED',
        aiCoachSuggestions: { suggestions },
      });
      const claim = claimStore[0];

      await dismissSuggestion(deps, claim.claimId, sugId, PHYSICIAN_1, USER_1);

      const updated = claimStore.find((c) => c.claimId === claim.claimId);
      const updatedSuggestions = updated!.aiCoachSuggestions.suggestions;
      expect(updatedSuggestions[0].dismissReason).toBeNull();
    });
  });

  // =========================================================================
  // acknowledgeDuplicate
  // =========================================================================

  describe('acknowledgeDuplicate', () => {
    it('clears duplicate alert', async () => {
      seedClaim({
        state: 'QUEUED',
        isClean: false,
        duplicateAlert: { duplicateCount: 1, acknowledged: false, alerts: [{ claimId: crypto.randomUUID() }] },
      });
      const claim = claimStore[0];

      await acknowledgeDuplicate(deps, claim.claimId, PHYSICIAN_1, USER_1);

      const updated = claimStore.find((c) => c.claimId === claim.claimId);
      expect(updated!.duplicateAlert).toBeNull();
    });

    it('appends DUPLICATE_ACKNOWLEDGED audit entry', async () => {
      const prevAlert = { duplicateCount: 1, acknowledged: false };
      seedClaim({
        state: 'VALIDATED',
        duplicateAlert: prevAlert,
      });
      const claim = claimStore[0];

      await acknowledgeDuplicate(deps, claim.claimId, PHYSICIAN_1, USER_1);

      const auditEntry = auditStore.find(
        (a) => a.claimId === claim.claimId && a.action === 'claim.duplicate_acknowledged',
      );
      expect(auditEntry).toBeDefined();
      expect(auditEntry!.actorId).toBe(USER_1);
      expect(auditEntry!.changes.previousAlert).toEqual(prevAlert);
    });

    it('re-evaluates clean/flagged if queued', async () => {
      seedClaim({
        state: 'QUEUED',
        isClean: false,
        duplicateAlert: { duplicateCount: 1, acknowledged: false },
      });
      const claim = claimStore[0];

      await acknowledgeDuplicate(deps, claim.claimId, PHYSICIAN_1, USER_1);

      const updated = claimStore.find((c) => c.claimId === claim.claimId);
      expect(updated!.isClean).toBe(true);
    });

    it('throws NotFoundError for non-existent claim', async () => {
      await expect(
        acknowledgeDuplicate(deps, crypto.randomUUID(), PHYSICIAN_1, USER_1),
      ).rejects.toThrow('Claim not found');
    });
  });

  // =========================================================================
  // getSubmissionPreferences
  // =========================================================================

  describe('getSubmissionPreferences', () => {
    it('reads from provider management', async () => {
      const mockPref: SubmissionPreferenceLookup = {
        getSubmissionMode: vi.fn()
          .mockResolvedValueOnce('AUTO_ALL')
          .mockResolvedValueOnce('REQUIRE_APPROVAL'),
      };
      const prefDeps: ClaimServiceDeps = { ...deps, submissionPreference: mockPref };

      const result = await getSubmissionPreferences(prefDeps, PHYSICIAN_1);

      expect(result.ahcipMode).toBe('AUTO_ALL');
      expect(result.wcbMode).toBe('REQUIRE_APPROVAL');
      expect(mockPref.getSubmissionMode).toHaveBeenCalledWith(PHYSICIAN_1, 'AHCIP');
      expect(mockPref.getSubmissionMode).toHaveBeenCalledWith(PHYSICIAN_1, 'WCB');
    });

    it('returns defaults when no dependency configured', async () => {
      const result = await getSubmissionPreferences(deps, PHYSICIAN_1);

      expect(result.ahcipMode).toBe('AUTO_CLEAN');
      expect(result.wcbMode).toBe('REQUIRE_APPROVAL');
    });
  });

  // =========================================================================
  // updateSubmissionPreferences
  // =========================================================================

  describe('updateSubmissionPreferences', () => {
    it('updates mode and appends audit entry', async () => {
      await updateSubmissionPreferences(deps, PHYSICIAN_1, USER_1, 'AUTO_ALL');

      const auditEntry = auditStore.find(
        (a) => a.action === 'submission_preferences.updated',
      );
      expect(auditEntry).toBeDefined();
      expect(auditEntry!.changes.mode).toBe('AUTO_ALL');
      expect(auditEntry!.changes.physicianId).toBe(PHYSICIAN_1);
      expect(auditEntry!.actorId).toBe(USER_1);
    });

    it('rejects invalid submission mode', async () => {
      await expect(
        updateSubmissionPreferences(deps, PHYSICIAN_1, USER_1, 'INVALID_MODE'),
      ).rejects.toThrow('Invalid submission mode');
    });
  });

  // =========================================================================
  // requestExport
  // =========================================================================

  describe('requestExport', () => {
    it('creates export record with PENDING status', async () => {
      const result = await requestExport(deps, PHYSICIAN_1, {
        dateFrom: '2026-01-01',
        dateTo: '2026-03-31',
        format: 'CSV',
      });

      expect(result.exportId).toBeDefined();
      const exportRecord = exportStore.find((e) => e.exportId === result.exportId);
      expect(exportRecord).toBeDefined();
      expect(exportRecord!.status).toBe('PENDING');
      expect(exportRecord!.physicianId).toBe(PHYSICIAN_1);
      expect(exportRecord!.dateFrom).toBe('2026-01-01');
      expect(exportRecord!.dateTo).toBe('2026-03-31');
      expect(exportRecord!.format).toBe('CSV');
    });

    it('rejects when dateFrom is after dateTo', async () => {
      await expect(
        requestExport(deps, PHYSICIAN_1, {
          dateFrom: '2026-06-01',
          dateTo: '2026-01-01',
          format: 'CSV',
        }),
      ).rejects.toThrow('date_from must be before or equal to date_to');
    });

    it('creates export with optional claimType filter', async () => {
      const result = await requestExport(deps, PHYSICIAN_1, {
        dateFrom: '2026-01-01',
        dateTo: '2026-03-31',
        claimType: 'AHCIP',
        format: 'JSON',
      });

      const exportRecord = exportStore.find((e) => e.exportId === result.exportId);
      expect(exportRecord!.claimType).toBe('AHCIP');
      expect(exportRecord!.format).toBe('JSON');
    });
  });

  // =========================================================================
  // getExportStatus
  // =========================================================================

  describe('getExportStatus', () => {
    it('returns status for owned export', async () => {
      const exportRecord = {
        exportId: crypto.randomUUID(),
        physicianId: PHYSICIAN_1,
        dateFrom: '2026-01-01',
        dateTo: '2026-03-31',
        claimType: null,
        format: 'CSV',
        status: 'COMPLETED',
        filePath: 'exports/test.csv',
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      exportStore.push(exportRecord);

      const result = await getExportStatus(deps, exportRecord.exportId, PHYSICIAN_1);

      expect(result).toBeDefined();
      expect(result!.exportId).toBe(exportRecord.exportId);
      expect(result!.status).toBe('COMPLETED');
      expect(result!.filePath).toBe('exports/test.csv');
    });

    it('returns null for different physician', async () => {
      const exportRecord = {
        exportId: crypto.randomUUID(),
        physicianId: PHYSICIAN_2,
        dateFrom: '2026-01-01',
        dateTo: '2026-03-31',
        claimType: null,
        format: 'CSV',
        status: 'PENDING',
        filePath: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      exportStore.push(exportRecord);

      const result = await getExportStatus(deps, exportRecord.exportId, PHYSICIAN_1);

      expect(result).toBeNull();
    });

    it('returns null for non-existent export', async () => {
      const result = await getExportStatus(deps, crypto.randomUUID(), PHYSICIAN_1);
      expect(result).toBeNull();
    });
  });

  // =========================================================================
  // generateExportFile
  // =========================================================================

  describe('generateExportFile', () => {
    it('generates CSV export and transitions to COMPLETED', async () => {
      // Seed some claims for the physician
      seedClaim({ dateOfService: '2026-02-01' });
      seedClaim({ dateOfService: '2026-02-15' });

      // Create export record
      const exportRecord = {
        exportId: crypto.randomUUID(),
        physicianId: PHYSICIAN_1,
        dateFrom: '2026-01-01',
        dateTo: '2026-03-31',
        claimType: null,
        format: 'CSV',
        status: 'PENDING',
        filePath: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      exportStore.push(exportRecord);

      const result = await generateExportFile(deps, exportRecord.exportId, PHYSICIAN_1);

      expect(result.filePath).toContain('exports/');
      expect(result.filePath).toContain('.csv');

      // Verify export record was updated
      const updated = exportStore.find((e) => e.exportId === exportRecord.exportId);
      expect(updated!.status).toBe('COMPLETED');
      expect(updated!.filePath).toBe(result.filePath);
    });

    it('generates JSON export', async () => {
      seedClaim({ dateOfService: '2026-02-01' });

      const exportRecord = {
        exportId: crypto.randomUUID(),
        physicianId: PHYSICIAN_1,
        dateFrom: '2026-01-01',
        dateTo: '2026-12-31',
        claimType: null,
        format: 'JSON',
        status: 'PENDING',
        filePath: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      exportStore.push(exportRecord);

      const result = await generateExportFile(deps, exportRecord.exportId, PHYSICIAN_1);

      expect(result.filePath).toContain('.json');

      const updated = exportStore.find((e) => e.exportId === exportRecord.exportId);
      expect(updated!.status).toBe('COMPLETED');
    });

    it('throws NotFoundError for non-existent export', async () => {
      await expect(
        generateExportFile(deps, crypto.randomUUID(), PHYSICIAN_1),
      ).rejects.toThrow('Export not found');
    });
  });
});
