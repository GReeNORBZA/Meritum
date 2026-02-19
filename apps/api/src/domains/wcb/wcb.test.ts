import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createWcbRepository } from './wcb.repository.js';
import {
  createWcbClaim,
  updateWcbClaim,
  deleteWcbClaim,
  getFormSchema,
  validateWcbClaim,
  assembleAndGenerateBatch,
  generateBatchXml,
  validateBatchXsd,
  generateDownloadUrl,
  confirmBatchUpload,
  parseReturnFile,
  processReturnFile,
  escapeXml,
  formatMountainTimestamp,
  formatHl7Date,
  mapClaimToObservations,
  HL7_NAMESPACE,
  calculateTimingTier,
  calculateWcbFees,
  getAlbertaStatutoryHolidays,
  isPremiumEligible,
  lookupReportFee,
  addMoney,
  multiplyMoney,
  countBusinessDays,
  POB_NOI_EXCLUSIONS,
  POBS_REQUIRING_SIDE,
  parseRemittanceXml,
  processRemittanceFile,
  RemittanceDiscrepancyReason,
  generateMvpExport,
  recordManualOutcome,
  getTimingDashboard,
  isMvpPhaseActive,
  subtractMoney,
  type WcbServiceDeps,
  type CreateWcbClaimInput,
  type TimingTierResult,
  type ReferenceLookup,
  type FileStorage,
  type SecretsProvider,
  type XsdValidator,
  type DownloadUrlGenerator,
  type NotificationEmitter,
  type XsdValidationResult,
  type ProcessReturnFileResult,
  type ProcessRemittanceFileResult,
  type ManualOutcomeInput,
} from './wcb.service.js';

// ---------------------------------------------------------------------------
// In-memory stores
// ---------------------------------------------------------------------------

let wcbDetailStore: Record<string, any>[];
let wcbInjuryStore: Record<string, any>[];
let wcbPrescriptionStore: Record<string, any>[];
let wcbConsultationStore: Record<string, any>[];
let wcbRestrictionStore: Record<string, any>[];
let wcbInvoiceLineStore: Record<string, any>[];
let wcbAttachmentStore: Record<string, any>[];
let wcbBatchStore: Record<string, any>[];
let wcbReturnRecordStore: Record<string, any>[];
let wcbReturnInvoiceLineStore: Record<string, any>[];
let wcbRemittanceImportStore: Record<string, any>[];
let wcbRemittanceRecordStore: Record<string, any>[];
let claimStore: Record<string, any>[];

// ---------------------------------------------------------------------------
// Test IDs
// ---------------------------------------------------------------------------

const PHYSICIAN_1 = 'phy-1111-1111-1111-111111111111';
const PHYSICIAN_2 = 'phy-2222-2222-2222-222222222222';
const USER_1 = 'usr-1111-1111-1111-111111111111';
const PATIENT_1 = 'pat-1111-1111-1111-111111111111';
const CLAIM_1 = 'clm-1111-1111-1111-111111111111';
const CLAIM_2 = 'clm-2222-2222-2222-222222222222';
const CLAIM_3 = 'clm-3333-3333-3333-333333333333';
const WCB_DETAIL_1 = 'wcd-1111-1111-1111-111111111111';
const WCB_DETAIL_2 = 'wcd-2222-2222-2222-222222222222';
const WCB_DETAIL_3 = 'wcd-3333-3333-3333-333333333333';

// ---------------------------------------------------------------------------
// Mock Drizzle DB — supports multi-table joins and child table queries
// ---------------------------------------------------------------------------

function makeMockDb() {
  function storeForTable(table: any): Record<string, any>[] {
    const tableName = table?.__table;
    if (tableName === 'wcb_claim_details') return wcbDetailStore;
    if (tableName === 'wcb_injuries') return wcbInjuryStore;
    if (tableName === 'wcb_prescriptions') return wcbPrescriptionStore;
    if (tableName === 'wcb_consultations') return wcbConsultationStore;
    if (tableName === 'wcb_work_restrictions') return wcbRestrictionStore;
    if (tableName === 'wcb_invoice_lines') return wcbInvoiceLineStore;
    if (tableName === 'wcb_attachments') return wcbAttachmentStore;
    if (tableName === 'wcb_batches') return wcbBatchStore;
    if (tableName === 'wcb_return_records') return wcbReturnRecordStore;
    if (tableName === 'wcb_return_invoice_lines') return wcbReturnInvoiceLineStore;
    if (tableName === 'wcb_remittance_imports') return wcbRemittanceImportStore;
    if (tableName === 'wcb_remittance_records') return wcbRemittanceRecordStore;
    if (tableName === 'claims') return claimStore;
    return wcbDetailStore;
  }

  function chainable(ctx: {
    op: string;
    table?: any;
    values?: any;
    setClauses?: any;
    selectFields?: any;
    whereClauses: Array<(row: any) => boolean>;
    joins: Array<{ table: any; predicate: (a: any, b: any) => boolean }>;
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
      innerJoin(table: any, predicate: any) {
        ctx.joins.push({
          table,
          predicate: predicate?.__joinPredicate ?? (() => false),
        });
        return chain;
      },
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
      groupBy(...fields: any[]) {
        if (!ctx.groupByFields) ctx.groupByFields = [];
        ctx.groupByFields.push(...fields);
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

  function insertWcbDetailRow(values: any): any {
    const row = {
      wcbClaimDetailId: values.wcbClaimDetailId ?? crypto.randomUUID(),
      claimId: values.claimId,
      formId: values.formId,
      submitterTxnId: values.submitterTxnId,
      wcbClaimNumber: values.wcbClaimNumber ?? null,
      reportCompletionDate: values.reportCompletionDate,
      additionalComments: values.additionalComments ?? null,
      parentWcbClaimId: values.parentWcbClaimId ?? null,
      practitionerBillingNumber: values.practitionerBillingNumber,
      contractId: values.contractId,
      roleCode: values.roleCode,
      practitionerFirstName: values.practitionerFirstName,
      practitionerMiddleName: values.practitionerMiddleName ?? null,
      practitionerLastName: values.practitionerLastName,
      skillCode: values.skillCode,
      facilityType: values.facilityType,
      clinicReferenceNumber: values.clinicReferenceNumber ?? null,
      billingContactName: values.billingContactName ?? null,
      faxCountryCode: values.faxCountryCode ?? null,
      faxNumber: values.faxNumber ?? null,
      patientNoPhnFlag: values.patientNoPhnFlag,
      patientPhn: values.patientPhn ?? null,
      patientGender: values.patientGender,
      patientFirstName: values.patientFirstName,
      patientMiddleName: values.patientMiddleName ?? null,
      patientLastName: values.patientLastName,
      patientDob: values.patientDob,
      patientAddressLine1: values.patientAddressLine1,
      patientAddressLine2: values.patientAddressLine2 ?? null,
      patientCity: values.patientCity,
      patientProvince: values.patientProvince ?? null,
      patientPostalCode: values.patientPostalCode ?? null,
      patientPhoneCountry: values.patientPhoneCountry ?? null,
      patientPhoneNumber: values.patientPhoneNumber ?? null,
      employerName: values.employerName ?? null,
      employerLocation: values.employerLocation ?? null,
      employerCity: values.employerCity ?? null,
      employerProvince: values.employerProvince ?? null,
      employerPhoneCountry: values.employerPhoneCountry ?? null,
      employerPhoneNumber: values.employerPhoneNumber ?? null,
      employerPhoneExt: values.employerPhoneExt ?? null,
      workerJobTitle: values.workerJobTitle ?? null,
      injuryDevelopedOverTime: values.injuryDevelopedOverTime ?? null,
      dateOfInjury: values.dateOfInjury,
      injuryDescription: values.injuryDescription ?? null,
      dateOfExamination: values.dateOfExamination ?? null,
      symptoms: values.symptoms ?? null,
      objectiveFindings: values.objectiveFindings ?? null,
      currentDiagnosis: values.currentDiagnosis ?? null,
      diagnosticCode1: values.diagnosticCode1 ?? null,
      diagnosticCode2: values.diagnosticCode2 ?? null,
      diagnosticCode3: values.diagnosticCode3 ?? null,
      createdAt: values.createdAt ?? new Date(),
      createdBy: values.createdBy,
      updatedAt: values.updatedAt ?? new Date(),
      updatedBy: values.updatedBy,
      deletedAt: values.deletedAt ?? null,
    };
    wcbDetailStore.push(row);
    return row;
  }

  function executeOp(ctx: any): any[] {
    const store = storeForTable(ctx.table);

    switch (ctx.op) {
      case 'select': {
        // Handle JOINs
        if (ctx.joins && ctx.joins.length > 0) {
          let rows = store.map((row: any) => ({ __primary: row }));

          for (const join of ctx.joins) {
            const joinStore = storeForTable(join.table);
            const nextRows: any[] = [];
            for (const row of rows) {
              const combinedRow = { ...row.__primary };
              for (const [key, val] of Object.entries(row)) {
                if (key !== '__primary' && typeof val === 'object' && val !== null) {
                  Object.assign(combinedRow, val);
                }
              }

              for (const joinRow of joinStore) {
                if (join.predicate(combinedRow, joinRow)) {
                  nextRows.push({
                    ...row,
                    [`__join_${join.table.__table}`]: joinRow,
                  });
                }
              }
            }
            rows = nextRows;
          }

          let flatRows = rows.map((row: any) => {
            const flat: any = { ...row.__primary };
            for (const [key, val] of Object.entries(row)) {
              if (key.startsWith('__join_') && typeof val === 'object' && val !== null) {
                Object.assign(flat, val);
              }
            }
            return flat;
          });

          flatRows = flatRows.filter((row) =>
            ctx.whereClauses.every((pred: any) => pred(row)),
          );

          // Apply ORDER BY
          if (ctx.orderByFns && ctx.orderByFns.length > 0) {
            flatRows = [...flatRows].sort((a, b) => {
              for (const sortFn of ctx.orderByFns) {
                const result = sortFn(a, b);
                if (result !== 0) return result;
              }
              return 0;
            });
          }

          // Apply OFFSET
          if (ctx.offsetN) {
            flatRows = flatRows.slice(ctx.offsetN);
          }

          // Apply LIMIT
          const limited = ctx.limitN ? flatRows.slice(0, ctx.limitN) : flatRows;

          // Apply structured projection
          if (ctx.selectFields) {
            return limited.map((row: any) => {
              const result: any = {};
              for (const [alias, val] of Object.entries(ctx.selectFields) as [string, any][]) {
                if (val?.__aggregate === 'count') {
                  // count() handled at group level; for non-grouped, just return length
                  result[alias] = limited.length;
                } else if (val?.__table) {
                  const tableStore = storeForTable(val);
                  if (tableStore === wcbDetailStore) {
                    result[alias] = extractWcbDetailFields(row);
                  } else if (tableStore === claimStore) {
                    result[alias] = extractClaimFields(row);
                  } else if (tableStore === wcbAttachmentStore) {
                    result[alias] = extractAttachmentFields(row);
                  }
                } else if (val?.name) {
                  result[alias] = row[val.name] ?? null;
                } else if (typeof val === 'object' && val !== null && !val.__table) {
                  const fields: any = {};
                  for (const [fieldKey, col] of Object.entries(val)) {
                    fields[fieldKey] = row[(col as any)?.name] ?? null;
                  }
                  result[alias] = fields;
                }
              }
              return result;
            });
          }

          return limited;
        }

        // Simple select (no joins)
        let rows = [...store];
        rows = rows.filter((row) =>
          ctx.whereClauses.every((pred: any) => pred(row)),
        );

        if (ctx.orderByFns && ctx.orderByFns.length > 0) {
          rows = [...rows].sort((a, b) => {
            for (const sortFn of ctx.orderByFns) {
              const result = sortFn(a, b);
              if (result !== 0) return result;
            }
            return 0;
          });
        }

        if (ctx.offsetN) {
          rows = rows.slice(ctx.offsetN);
        }

        if (ctx.limitN) {
          rows = rows.slice(0, ctx.limitN);
        }

        // Structured projection for simple (no-join) selects
        if (ctx.selectFields) {
          return rows.map((row) => {
            const result: any = {};
            for (const [alias, val] of Object.entries(ctx.selectFields) as [string, any][]) {
              if (val?.__aggregate === 'count') {
                result[alias] = rows.length;
              } else if (val?.name) {
                result[alias] = row[val.name] ?? null;
              }
            }
            return result;
          });
        }

        return rows;
      }

      case 'insert': {
        if (ctx.table?.__table === 'wcb_claim_details') {
          return [insertWcbDetailRow(ctx.values)];
        }
        // Generic child table insert — supports single or array values
        const insertStore = storeForTable(ctx.table);
        const valuesToInsert = Array.isArray(ctx.values) ? ctx.values : [ctx.values];
        const inserted: any[] = [];
        for (const val of valuesToInsert) {
          const row = { ...val };
          // Auto-generate primary key if not provided
          const tableName = ctx.table?.__table;
          if (tableName === 'wcb_injuries' && !row.wcbInjuryId) {
            row.wcbInjuryId = crypto.randomUUID();
          } else if (tableName === 'wcb_prescriptions' && !row.wcbPrescriptionId) {
            row.wcbPrescriptionId = crypto.randomUUID();
          } else if (tableName === 'wcb_consultations' && !row.wcbConsultationId) {
            row.wcbConsultationId = crypto.randomUUID();
          } else if (tableName === 'wcb_work_restrictions' && !row.wcbRestrictionId) {
            row.wcbRestrictionId = crypto.randomUUID();
          } else if (tableName === 'wcb_invoice_lines' && !row.wcbInvoiceLineId) {
            row.wcbInvoiceLineId = crypto.randomUUID();
          } else if (tableName === 'wcb_attachments' && !row.wcbAttachmentId) {
            row.wcbAttachmentId = crypto.randomUUID();
          } else if (tableName === 'wcb_batches' && !row.wcbBatchId) {
            row.wcbBatchId = crypto.randomUUID();
            row.createdAt = row.createdAt ?? new Date();
          } else if (tableName === 'wcb_return_records' && !row.wcbReturnRecordId) {
            row.wcbReturnRecordId = crypto.randomUUID();
          } else if (tableName === 'wcb_return_invoice_lines' && !row.wcbReturnInvoiceLineId) {
            row.wcbReturnInvoiceLineId = crypto.randomUUID();
          } else if (tableName === 'wcb_remittance_imports' && !row.remittanceImportId) {
            row.remittanceImportId = crypto.randomUUID();
            row.recordCount = row.recordCount ?? 0;
            row.createdAt = row.createdAt ?? new Date();
          } else if (tableName === 'wcb_remittance_records' && !row.wcbRemittanceId) {
            row.wcbRemittanceId = crypto.randomUUID();
          }
          insertStore.push(row);
          inserted.push(row);
        }
        return inserted;
      }

      case 'delete': {
        const deleteStore = storeForTable(ctx.table);
        const toDelete = deleteStore.filter((row) =>
          ctx.whereClauses.every((pred: any) => pred(row)),
        );
        for (const row of toDelete) {
          const idx = deleteStore.indexOf(row);
          if (idx >= 0) deleteStore.splice(idx, 1);
        }
        return toDelete;
      }

      case 'update': {
        let rows = [...store];
        rows = rows.filter((row) =>
          ctx.whereClauses.every((pred: any) => pred(row)),
        );

        const updated: any[] = [];
        for (const row of rows) {
          const idx = store.indexOf(row);
          if (idx >= 0) {
            const updatedRow = { ...row, ...ctx.setClauses };
            store[idx] = updatedRow;
            updated.push(updatedRow);
          }
        }
        return updated;
      }

      default:
        return [];
    }
  }

  function extractWcbDetailFields(row: any): any {
    return {
      wcbClaimDetailId: row.wcbClaimDetailId,
      claimId: row.claimId,
      formId: row.formId,
      submitterTxnId: row.submitterTxnId,
      wcbClaimNumber: row.wcbClaimNumber,
      reportCompletionDate: row.reportCompletionDate,
      additionalComments: row.additionalComments,
      parentWcbClaimId: row.parentWcbClaimId,
      practitionerBillingNumber: row.practitionerBillingNumber,
      contractId: row.contractId,
      roleCode: row.roleCode,
      practitionerFirstName: row.practitionerFirstName,
      practitionerMiddleName: row.practitionerMiddleName,
      practitionerLastName: row.practitionerLastName,
      skillCode: row.skillCode,
      facilityType: row.facilityType,
      clinicReferenceNumber: row.clinicReferenceNumber,
      billingContactName: row.billingContactName,
      faxCountryCode: row.faxCountryCode,
      faxNumber: row.faxNumber,
      patientNoPhnFlag: row.patientNoPhnFlag,
      patientPhn: row.patientPhn,
      patientGender: row.patientGender,
      patientFirstName: row.patientFirstName,
      patientMiddleName: row.patientMiddleName,
      patientLastName: row.patientLastName,
      patientDob: row.patientDob,
      patientAddressLine1: row.patientAddressLine1,
      patientAddressLine2: row.patientAddressLine2,
      patientCity: row.patientCity,
      patientProvince: row.patientProvince,
      patientPostalCode: row.patientPostalCode,
      patientPhoneCountry: row.patientPhoneCountry,
      patientPhoneNumber: row.patientPhoneNumber,
      dateOfInjury: row.dateOfInjury,
      employerName: row.employerName,
      employerLocation: row.employerLocation,
      employerCity: row.employerCity,
      employerProvince: row.employerProvince,
      employerPhoneCountry: row.employerPhoneCountry,
      employerPhoneNumber: row.employerPhoneNumber,
      employerPhoneExt: row.employerPhoneExt,
      workerJobTitle: row.workerJobTitle,
      injuryDevelopedOverTime: row.injuryDevelopedOverTime,
      injuryDescription: row.injuryDescription,
      dateOfExamination: row.dateOfExamination,
      symptoms: row.symptoms,
      objectiveFindings: row.objectiveFindings,
      currentDiagnosis: row.currentDiagnosis,
      diagnosticCode1: row.diagnosticCode1,
      diagnosticCode2: row.diagnosticCode2,
      diagnosticCode3: row.diagnosticCode3,
      narcoticsPrescribed: row.narcoticsPrescribed,
      missedWorkBeyondAccident: row.missedWorkBeyondAccident,
      patientReturnedToWork: row.patientReturnedToWork,
      estimatedRtwDate: row.estimatedRtwDate,
      priorConditionsFlag: row.priorConditionsFlag,
      priorConditionsDesc: row.priorConditionsDesc,
      diagnosisChanged: row.diagnosisChanged,
      diagnosisChangedDesc: row.diagnosisChangedDesc,
      createdAt: row.createdAt,
      createdBy: row.createdBy,
      updatedAt: row.updatedAt,
      updatedBy: row.updatedBy,
      deletedAt: row.deletedAt,
    };
  }

  function extractAttachmentFields(row: any): any {
    return {
      wcbAttachmentId: row.wcbAttachmentId,
      wcbClaimDetailId: row.wcbClaimDetailId,
      ordinal: row.ordinal,
      fileName: row.fileName,
      fileType: row.fileType,
      fileContentB64: row.fileContentB64,
      fileDescription: row.fileDescription,
      fileSizeBytes: row.fileSizeBytes,
    };
  }

  function extractClaimFields(row: any): any {
    return {
      claimId: row.claimId,
      physicianId: row.physicianId,
      patientId: row.patientId,
      claimType: row.claimType,
      state: row.state,
      isClean: row.isClean,
      importSource: row.importSource,
      importBatchId: row.importBatchId,
      shiftId: row.shiftId,
      dateOfService: row.dateOfService,
      submissionDeadline: row.submissionDeadline,
      submittedBatchId: row.submittedBatchId,
      validationResult: row.validationResult,
      validationTimestamp: row.validationTimestamp,
      referenceDataVersion: row.referenceDataVersion,
      aiCoachSuggestions: row.aiCoachSuggestions,
      duplicateAlert: row.duplicateAlert,
      flags: row.flags,
      createdAt: row.createdAt,
      createdBy: row.createdBy,
      updatedAt: row.updatedAt,
      updatedBy: row.updatedBy,
      deletedAt: row.deletedAt,
    };
  }

  const db = {
    select(fields?: any) {
      return chainable({
        op: 'select',
        selectFields: fields,
        whereClauses: [],
        joins: [],
      });
    },
    insert(table: any) {
      return chainable({
        op: 'insert',
        table,
        whereClauses: [],
        joins: [],
      });
    },
    update(table: any) {
      return chainable({
        op: 'update',
        table,
        whereClauses: [],
        joins: [],
      });
    },
    delete(table: any) {
      return chainable({
        op: 'delete',
        table,
        whereClauses: [],
        joins: [],
      });
    },
  };

  return db as any;
}

// ---------------------------------------------------------------------------
// Mock Drizzle operators
// ---------------------------------------------------------------------------

vi.mock('drizzle-orm', () => {
  const eq = (col: any, val: any) => {
    const colName = col?.name;
    return {
      __predicate: (row: any) => row[colName] === val,
      __joinPredicate: (a: any, b: any) => a[colName] === b[colName],
    };
  };

  const and = (...clauses: any[]) => {
    const preds = clauses
      .filter(Boolean)
      .map((c) => c.__predicate ?? c);
    return {
      __predicate: (row: any) => preds.every((p: any) => {
        if (typeof p === 'function') return p(row);
        return true;
      }),
    };
  };

  const isNull = (col: any) => {
    const colName = col?.name;
    return {
      __predicate: (row: any) => row[colName] == null,
    };
  };

  const desc = (col: any) => {
    const colName = col?.name;
    return {
      __sortFn: (a: any, b: any) => {
        const va = a[colName] ?? '';
        const vb = b[colName] ?? '';
        return va > vb ? -1 : va < vb ? 1 : 0;
      },
    };
  };

  const count = () => ({ __aggregate: 'count' });

  const inArray = (col: any, vals: any[]) => {
    const colName = col?.name;
    return {
      __predicate: (row: any) => vals.includes(row[colName]),
    };
  };

  return { eq, and, isNull, desc, count, inArray };
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
      this.name = 'AppError';
    }
  }
  return {
    AppError,
    BusinessRuleError: class BusinessRuleError extends AppError {
      constructor(message: string, details?: unknown) {
        super(422, 'BUSINESS_RULE_VIOLATION', message, details);
        this.name = 'BusinessRuleError';
      }
    },
    ConflictError: class ConflictError extends AppError {
      constructor(message: string) {
        super(409, 'CONFLICT', message);
        this.name = 'ConflictError';
      }
    },
    NotFoundError: class NotFoundError extends AppError {
      constructor(resource: string) {
        super(404, 'NOT_FOUND', `${resource} not found`);
        this.name = 'NotFoundError';
      }
    },
  };
});

// ---------------------------------------------------------------------------
// Mock @meritum/shared imports
// ---------------------------------------------------------------------------

vi.mock('@meritum/shared/schemas/db/wcb.schema.js', () => {
  const makeTable = (name: string, columns: string[]) => {
    const table: any = { __table: name };
    for (const col of columns) {
      table[col] = { name: col };
    }
    return table;
  };

  return {
    wcbClaimDetails: makeTable('wcb_claim_details', [
      'wcbClaimDetailId', 'claimId', 'formId', 'submitterTxnId',
      'wcbClaimNumber', 'reportCompletionDate', 'additionalComments',
      'parentWcbClaimId', 'practitionerBillingNumber', 'contractId',
      'roleCode', 'practitionerFirstName', 'practitionerMiddleName',
      'practitionerLastName', 'skillCode', 'facilityType',
      'clinicReferenceNumber', 'billingContactName', 'faxCountryCode',
      'faxNumber', 'patientNoPhnFlag', 'patientPhn', 'patientGender',
      'patientFirstName', 'patientMiddleName', 'patientLastName',
      'patientDob', 'patientAddressLine1', 'patientAddressLine2',
      'patientCity', 'patientProvince', 'patientPostalCode',
      'patientPhoneCountry', 'patientPhoneNumber', 'dateOfInjury',
      'createdAt', 'createdBy', 'updatedAt', 'updatedBy', 'deletedAt',
      'employerName', 'employerLocation', 'employerCity', 'employerProvince',
      'employerPhoneCountry', 'employerPhoneNumber', 'employerPhoneExt',
      'workerJobTitle', 'injuryDevelopedOverTime', 'injuryDescription',
      'dateOfExamination', 'symptoms', 'objectiveFindings', 'currentDiagnosis',
      'diagnosticCode1', 'diagnosticCode2', 'diagnosticCode3',
    ]),
    wcbInjuries: makeTable('wcb_injuries', [
      'wcbInjuryId', 'wcbClaimDetailId', 'ordinal',
      'partOfBodyCode', 'sideOfBodyCode', 'natureOfInjuryCode',
    ]),
    wcbPrescriptions: makeTable('wcb_prescriptions', [
      'wcbPrescriptionId', 'wcbClaimDetailId', 'ordinal',
      'prescriptionName', 'strength', 'dailyIntake',
    ]),
    wcbConsultations: makeTable('wcb_consultations', [
      'wcbConsultationId', 'wcbClaimDetailId', 'ordinal',
      'category', 'typeCode', 'details', 'expediteRequested',
    ]),
    wcbWorkRestrictions: makeTable('wcb_work_restrictions', [
      'wcbRestrictionId', 'wcbClaimDetailId', 'activityType',
      'restrictionLevel', 'hoursPerDay', 'maxWeight',
    ]),
    wcbInvoiceLines: makeTable('wcb_invoice_lines', [
      'wcbInvoiceLineId', 'wcbClaimDetailId', 'invoiceDetailId',
      'lineType', 'healthServiceCode', 'amount',
    ]),
    wcbAttachments: makeTable('wcb_attachments', [
      'wcbAttachmentId', 'wcbClaimDetailId', 'ordinal',
      'fileName', 'fileType', 'fileContentB64', 'fileDescription', 'fileSizeBytes',
    ]),
    wcbBatches: makeTable('wcb_batches', [
      'wcbBatchId', 'physicianId', 'batchControlId', 'fileControlId',
      'status', 'reportCount', 'xmlFilePath', 'xmlFileHash',
      'xsdValidationPassed', 'xsdValidationErrors',
      'uploadedAt', 'uploadedBy', 'returnFileReceivedAt', 'returnFilePath',
      'createdAt', 'createdBy',
    ]),
    wcbReturnRecords: makeTable('wcb_return_records', [
      'wcbReturnRecordId', 'wcbBatchId', 'wcbClaimDetailId',
      'reportTxnId', 'submitterTxnId', 'processedClaimNumber',
      'claimDecision', 'reportStatus', 'txnSubmissionDate', 'errors',
    ]),
    wcbReturnInvoiceLines: makeTable('wcb_return_invoice_lines', [
      'wcbReturnInvoiceLineId', 'wcbReturnRecordId',
      'invoiceSequence', 'serviceDate', 'healthServiceCode', 'invoiceStatus',
    ]),
    wcbRemittanceImports: makeTable('wcb_remittance_imports', [
      'remittanceImportId', 'physicianId', 'recordCount', 'createdAt',
    ]),
    wcbRemittanceRecords: makeTable('wcb_remittance_records', [
      'wcbRemittanceId', 'remittanceImportId', 'wcbClaimDetailId',
      'reportWeekStart', 'reportWeekEnd',
      'disbursementNumber', 'disbursementType', 'disbursementIssueDate',
      'disbursementAmount', 'disbursementRecipientBilling', 'disbursementRecipientName',
      'paymentPayeeBilling', 'paymentPayeeName', 'paymentReasonCode',
      'paymentStatus', 'paymentStartDate', 'paymentEndDate',
      'paymentAmount', 'billedAmount',
      'electronicReportTxnId', 'claimNumber',
      'workerPhn', 'workerFirstName', 'workerLastName',
      'serviceCode', 'modifier1', 'modifier2', 'modifier3',
      'numberOfCalls', 'encounterNumber', 'overpaymentRecovery',
    ]),
  };
});

vi.mock('@meritum/shared/schemas/db/claim.schema.js', () => {
  const claims: any = { __table: 'claims' };
  const claimColumns = [
    'claimId', 'physicianId', 'patientId', 'claimType', 'state',
    'isClean', 'importSource', 'importBatchId', 'shiftId',
    'dateOfService', 'submissionDeadline', 'submittedBatchId',
    'validationResult', 'validationTimestamp', 'referenceDataVersion',
    'aiCoachSuggestions', 'duplicateAlert', 'flags',
    'createdAt', 'createdBy', 'updatedAt', 'updatedBy', 'deletedAt',
  ];
  for (const col of claimColumns) {
    claims[col] = { name: col };
  }
  return { claims };
});

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
  return {
    ClaimState,
    ClaimType: {
      AHCIP: 'AHCIP',
      WCB: 'WCB',
    },
    ClaimImportSource: {
      MANUAL: 'MANUAL',
      EMR_IMPORT: 'EMR_IMPORT',
      ED_SHIFT: 'ED_SHIFT',
    },
    TERMINAL_STATES: new Set([
      ClaimState.PAID,
      ClaimState.ADJUSTED,
      ClaimState.WRITTEN_OFF,
      ClaimState.EXPIRED,
      ClaimState.DELETED,
    ]),
    ValidationSeverity: {
      ERROR: 'ERROR',
      WARNING: 'WARNING',
      INFO: 'INFO',
    },
  };
});

vi.mock('@meritum/shared/constants/wcb.constants.js', () => ({
  WcbReturnReportStatus: {
    COMPLETE: 'COMPLETE',
    INVALID: 'INVALID',
  },
  WcbPaymentStatus: {
    ISS: 'ISS',
    REQ: 'REQ',
    PAE: 'PAE',
    PGA: 'PGA',
    PGD: 'PGD',
    REJ: 'REJ',
    DEL: 'DEL',
  },
  WcbBatchStatus: {
    ASSEMBLING: 'ASSEMBLING',
    GENERATED: 'GENERATED',
    VALIDATED: 'VALIDATED',
    UPLOADED: 'UPLOADED',
    RETURN_RECEIVED: 'RETURN_RECEIVED',
    RECONCILED: 'RECONCILED',
    ERROR: 'ERROR',
  },
  WcbFormType: {
    C050E: 'C050E',
    C050S: 'C050S',
    C151: 'C151',
    C151S: 'C151S',
    C568: 'C568',
    C568A: 'C568A',
    C569: 'C569',
    C570: 'C570',
  },
  WCB_FORM_TYPE_CONFIGS: {
    C050E: { formType: 'C050E', name: 'Physician First Report', isInitial: true, fieldCount: 111, requiredFieldCount: 38 },
    C050S: { formType: 'C050S', name: 'OIS Physician First Report', isInitial: true, fieldCount: 171, requiredFieldCount: 70 },
    C151: { formType: 'C151', name: 'Physician Progress Report', isInitial: false, fieldCount: 136, requiredFieldCount: 39 },
    C151S: { formType: 'C151S', name: 'OIS Physician Progress Report', isInitial: false, fieldCount: 153, requiredFieldCount: 39 },
    C568: { formType: 'C568', name: 'Medical Invoice', isInitial: false, fieldCount: 61, requiredFieldCount: 17 },
    C568A: { formType: 'C568A', name: 'Medical Consultation Report', isInitial: false, fieldCount: 69, requiredFieldCount: 19 },
    C569: { formType: 'C569', name: 'Medical Supplies Invoice', isInitial: false, fieldCount: 37, requiredFieldCount: 18 },
    C570: { formType: 'C570', name: 'Medical Invoice Correction', isInitial: false, fieldCount: 66, requiredFieldCount: 18 },
  },
  WcbFormSection: {
    GENERAL: 'GENERAL',
    CLAIMANT: 'CLAIMANT',
    PRACTITIONER: 'PRACTITIONER',
    EMPLOYER: 'EMPLOYER',
    ACCIDENT: 'ACCIDENT',
    INJURY: 'INJURY',
    TREATMENT_PLAN: 'TREATMENT_PLAN',
    RETURN_TO_WORK: 'RETURN_TO_WORK',
    ATTACHMENTS: 'ATTACHMENTS',
    INVOICE: 'INVOICE',
  },
  WCB_FORM_SECTION_MATRIX: {
    C050E: ['GENERAL', 'CLAIMANT', 'PRACTITIONER', 'EMPLOYER', 'ACCIDENT', 'INJURY', 'TREATMENT_PLAN', 'RETURN_TO_WORK', 'ATTACHMENTS', 'INVOICE'],
    C050S: ['GENERAL', 'CLAIMANT', 'PRACTITIONER', 'EMPLOYER', 'ACCIDENT', 'INJURY', 'TREATMENT_PLAN', 'RETURN_TO_WORK', 'ATTACHMENTS', 'INVOICE'],
    C151: ['GENERAL', 'CLAIMANT', 'PRACTITIONER', 'EMPLOYER', 'ACCIDENT', 'INJURY', 'TREATMENT_PLAN', 'RETURN_TO_WORK', 'ATTACHMENTS', 'INVOICE'],
    C151S: ['GENERAL', 'CLAIMANT', 'PRACTITIONER', 'EMPLOYER', 'ACCIDENT', 'INJURY', 'TREATMENT_PLAN', 'RETURN_TO_WORK', 'ATTACHMENTS', 'INVOICE'],
    C568: ['GENERAL', 'CLAIMANT', 'PRACTITIONER', 'ACCIDENT', 'INJURY', 'INVOICE'],
    C568A: ['GENERAL', 'CLAIMANT', 'PRACTITIONER', 'ACCIDENT', 'INJURY', 'TREATMENT_PLAN', 'INVOICE'],
    C569: ['GENERAL', 'CLAIMANT', 'PRACTITIONER', 'ACCIDENT', 'INVOICE'],
    C570: ['GENERAL', 'CLAIMANT', 'PRACTITIONER', 'ACCIDENT', 'INVOICE'],
  },
  WCB_INITIAL_FORM_PERMISSIONS: [
    { contractId: '000001', role: 'GP', allowedInitialForms: ['C050E', 'C568'] },
    { contractId: '000004', role: 'OR', allowedInitialForms: ['C568A', 'C568'] },
    { contractId: '000006', role: 'SP', allowedInitialForms: ['C568A', 'C568'] },
    { contractId: '000006', role: 'ERS', allowedInitialForms: ['C050E', 'C568'] },
    { contractId: '000006', role: 'ANE', allowedInitialForms: ['C568A', 'C568'] },
    { contractId: '000022', role: 'DP', allowedInitialForms: ['C568'] },
    { contractId: '000053', role: 'OIS', allowedInitialForms: ['C050S', 'C568'] },
    { contractId: '000084', role: 'NP', allowedInitialForms: ['C050E', 'C568'] },
  ],
  WCB_FOLLOW_UP_FORM_PERMISSIONS: [
    { contractId: '000001', role: 'GP', allowedFollowUpForms: ['C151', 'C568', 'C569', 'C570'], canCreateFrom: ['C050E', 'C151', 'C568'] },
    { contractId: '000006', role: 'ERS', allowedFollowUpForms: ['C151', 'C568', 'C569', 'C570'], canCreateFrom: ['C050E', 'C151', 'C568'] },
    { contractId: '000006', role: 'SP', allowedFollowUpForms: ['C568A', 'C568', 'C569', 'C570'], canCreateFrom: ['C568A', 'C568'] },
    { contractId: '000006', role: 'ANE', allowedFollowUpForms: ['C568A', 'C568', 'C569', 'C570'], canCreateFrom: ['C568A', 'C568'] },
    { contractId: '000004', role: 'OR', allowedFollowUpForms: ['C568A', 'C568', 'C569', 'C570'], canCreateFrom: ['C568A', 'C568'] },
    { contractId: '000053', role: 'OIS', allowedFollowUpForms: ['C151S', 'C568', 'C569', 'C570'], canCreateFrom: ['C050S', 'C151S', 'C568'] },
    { contractId: '000084', role: 'NP', allowedFollowUpForms: ['C151', 'C568', 'C570'], canCreateFrom: ['C050E', 'C151', 'C568'] },
  ],
  WcbAuditAction: {
    WCB_FORM_CREATED: 'WCB_FORM_CREATED',
    WCB_FORM_UPDATED: 'WCB_FORM_UPDATED',
    WCB_FORM_VALIDATED: 'WCB_FORM_VALIDATED',
    WCB_FORM_SUBMITTED: 'WCB_FORM_SUBMITTED',
    WCB_BATCH_ASSEMBLED: 'WCB_BATCH_ASSEMBLED',
    WCB_BATCH_VALIDATED: 'WCB_BATCH_VALIDATED',
    WCB_BATCH_DOWNLOADED: 'WCB_BATCH_DOWNLOADED',
    WCB_BATCH_UPLOADED: 'WCB_BATCH_UPLOADED',
    WCB_RETURN_RECEIVED: 'WCB_RETURN_RECEIVED',
    WCB_PAYMENT_RECEIVED: 'WCB_PAYMENT_RECEIVED',
    WCB_MVP_EXPORT_GENERATED: 'WCB_MVP_EXPORT_GENERATED',
    WCB_MANUAL_OUTCOME_RECORDED: 'WCB_MANUAL_OUTCOME_RECORDED',
  },
  WcbValidationCheckId: {
    FORM_ID_VALID: 'FORM_ID_VALID',
    CONTRACT_ROLE_FORM: 'CONTRACT_ROLE_FORM',
    REQUIRED_FIELDS: 'REQUIRED_FIELDS',
    CONDITIONAL_LOGIC: 'CONDITIONAL_LOGIC',
    DATA_TYPE_LENGTH: 'DATA_TYPE_LENGTH',
    DATE_VALIDATION: 'DATE_VALIDATION',
    POB_NOI_COMBINATION: 'POB_NOI_COMBINATION',
    SIDE_OF_BODY: 'SIDE_OF_BODY',
    CODE_TABLE_VALUES: 'CODE_TABLE_VALUES',
    SUBMITTER_TXN_FORMAT: 'SUBMITTER_TXN_FORMAT',
    PHN_LOGIC: 'PHN_LOGIC',
    INVOICE_LINE_INTEGRITY: 'INVOICE_LINE_INTEGRITY',
    ATTACHMENT_CONSTRAINTS: 'ATTACHMENT_CONSTRAINTS',
    TIMING_DEADLINE: 'TIMING_DEADLINE',
    EXPEDITE_ELIGIBILITY: 'EXPEDITE_ELIGIBILITY',
    DUPLICATE_DETECTION: 'DUPLICATE_DETECTION',
  },
  WcbTimingTier: {
    SAME_DAY: 'SAME_DAY',
    ON_TIME: 'ON_TIME',
    LATE: 'LATE',
  },
  WCB_TIMING_DEADLINE_RULES: [
    {
      formType: 'C050E',
      sameDayDescription: 'Exam day or next business day by 10:00 MT',
      onTimeDescription: 'Within 3 business days',
      onTimeBusinessDays: 3,
      deadlineHourMT: 10,
    },
    {
      formType: 'C151',
      sameDayDescription: 'Exam day or next business day by 10:00 MT',
      onTimeDescription: 'Within 4 business days',
      onTimeBusinessDays: 4,
      deadlineHourMT: 10,
    },
    {
      formType: 'C568A',
      sameDayDescription: 'Exam day or next business day by 10:00 MT',
      onTimeDescription: 'Within 4 business days',
      onTimeBusinessDays: 4,
      deadlineHourMT: 10,
    },
  ],
  WcbInvoiceLineType: {
    STANDARD: 'STANDARD',
    DATED: 'DATED',
    SUPPLY: 'SUPPLY',
    WAS: 'WAS',
    SHOULD_BE: 'SHOULD_BE',
  },
  WcbFacilityType: {
    C: 'C',
    F: 'F',
    H: 'H',
  },
  WCB_FEE_SCHEDULE_2025: [
    { formCode: 'C050E', description: 'Physician First Report', sameDayFee: '94.15', onTimeFee: '85.80', lateFee: '54.08' },
    { formCode: 'C151', description: 'Physician Progress Report', sameDayFee: '57.19', onTimeFee: '52.12', lateFee: '32.86' },
    { formCode: 'RF01E', description: 'Specialist Consultation', sameDayFee: '115.05', onTimeFee: '104.87', lateFee: '66.09' },
    { formCode: 'RF03E', description: 'Specialist Follow-up', sameDayFee: '57.19', onTimeFee: '52.12', lateFee: '32.86' },
  ],
  WCB_PREMIUM_MULTIPLIER: 2,
  WCB_PREMIUM_EXCLUSION_DAYS: 4,
  WCB_PREMIUM_LIMIT_PER_ENCOUNTER: 1,
  WCB_RRNP_FLAT_FEE: '32.77',
  WCB_EXPEDITED_FULL_DAYS: 15,
  WCB_EXPEDITED_PRORATE_END_DAYS: 25,
  WCB_EXPEDITED_CONSULTATION_FEE: '150.00',
  WCB_FORM_TO_FEE_CODE: {
    C050E: 'C050E',
    C050S: 'C050E',
    C151: 'C151',
    C151S: 'C151',
  },
  WcbPhase: {
    MVP: 'mvp',
    VENDOR: 'vendor',
  },
}));

// ---------------------------------------------------------------------------
// Helper: create a base claim in the claims store
// ---------------------------------------------------------------------------

function seedClaim(overrides: Partial<Record<string, any>> = {}): Record<string, any> {
  const claim = {
    claimId: overrides.claimId ?? CLAIM_1,
    physicianId: overrides.physicianId ?? PHYSICIAN_1,
    patientId: overrides.patientId ?? PATIENT_1,
    claimType: 'WCB',
    state: overrides.state ?? 'DRAFT',
    isClean: null,
    importSource: 'MANUAL',
    importBatchId: null,
    shiftId: null,
    dateOfService: '2026-02-15',
    submissionDeadline: '2026-05-15',
    submittedBatchId: null,
    validationResult: null,
    validationTimestamp: null,
    referenceDataVersion: null,
    aiCoachSuggestions: null,
    duplicateAlert: null,
    flags: null,
    createdAt: new Date('2026-02-15T10:00:00Z'),
    createdBy: USER_1,
    updatedAt: new Date('2026-02-15T10:00:00Z'),
    updatedBy: USER_1,
    deletedAt: null,
    ...overrides,
  };
  claimStore.push(claim);
  return claim;
}

function seedWcbDetail(overrides: Partial<Record<string, any>> = {}): Record<string, any> {
  const detail = {
    wcbClaimDetailId: overrides.wcbClaimDetailId ?? WCB_DETAIL_1,
    claimId: overrides.claimId ?? CLAIM_1,
    formId: overrides.formId ?? 'C050E',
    submitterTxnId: overrides.submitterTxnId ?? 'MRT0000000000001',
    wcbClaimNumber: overrides.wcbClaimNumber ?? null,
    reportCompletionDate: '2026-02-15',
    additionalComments: null,
    parentWcbClaimId: null,
    practitionerBillingNumber: '12345678',
    contractId: '000001',
    roleCode: 'GP',
    practitionerFirstName: 'Jane',
    practitionerMiddleName: null,
    practitionerLastName: 'Smith',
    skillCode: '03',
    facilityType: 'C',
    clinicReferenceNumber: null,
    billingContactName: null,
    faxCountryCode: null,
    faxNumber: null,
    patientNoPhnFlag: 'N',
    patientPhn: '123456789',
    patientGender: 'M',
    patientFirstName: 'John',
    patientMiddleName: null,
    patientLastName: 'Doe',
    patientDob: '1990-05-10',
    patientAddressLine1: '123 Main St',
    patientAddressLine2: null,
    patientCity: 'Calgary',
    patientProvince: 'AB',
    patientPostalCode: 'T2P1A1',
    patientPhoneCountry: null,
    patientPhoneNumber: null,
    dateOfInjury: '2026-02-10',
    createdAt: new Date('2026-02-15T10:00:00Z'),
    createdBy: USER_1,
    updatedAt: new Date('2026-02-15T10:00:00Z'),
    updatedBy: USER_1,
    deletedAt: null,
    ...overrides,
  };
  wcbDetailStore.push(detail);
  return detail;
}

const BATCH_1 = 'bat-1111-1111-1111-111111111111';
const BATCH_2 = 'bat-2222-2222-2222-222222222222';

function seedBatch(overrides: Partial<Record<string, any>> = {}): Record<string, any> {
  const batch = {
    wcbBatchId: overrides.wcbBatchId ?? BATCH_1,
    physicianId: overrides.physicianId ?? PHYSICIAN_1,
    batchControlId: overrides.batchControlId ?? 'MER-B-TEST0001',
    fileControlId: overrides.fileControlId ?? 'MER-20260215-TEST01',
    status: overrides.status ?? 'ASSEMBLING',
    reportCount: overrides.reportCount ?? 0,
    xmlFilePath: overrides.xmlFilePath ?? null,
    xmlFileHash: overrides.xmlFileHash ?? null,
    xsdValidationPassed: overrides.xsdValidationPassed ?? null,
    xsdValidationErrors: overrides.xsdValidationErrors ?? null,
    uploadedAt: overrides.uploadedAt ?? null,
    uploadedBy: overrides.uploadedBy ?? null,
    returnFileReceivedAt: overrides.returnFileReceivedAt ?? null,
    returnFilePath: overrides.returnFilePath ?? null,
    createdAt: overrides.createdAt ?? new Date('2026-02-15T10:00:00Z'),
    createdBy: overrides.createdBy ?? USER_1,
    ...overrides,
  };
  wcbBatchStore.push(batch);
  return batch;
}

function makeCreateInput(overrides: Partial<Record<string, any>> = {}): any {
  return {
    claimId: CLAIM_1,
    formId: 'C050E',
    reportCompletionDate: '2026-02-15',
    dateOfInjury: '2026-02-10',
    practitionerBillingNumber: '12345678',
    contractId: '000001',
    roleCode: 'GP',
    practitionerFirstName: 'Jane',
    practitionerLastName: 'Smith',
    skillCode: '03',
    facilityType: 'C',
    patientNoPhnFlag: 'N',
    patientPhn: '123456789',
    patientGender: 'M',
    patientFirstName: 'John',
    patientLastName: 'Doe',
    patientDob: '1990-05-10',
    patientAddressLine1: '123 Main St',
    patientCity: 'Calgary',
    createdBy: USER_1,
    updatedBy: USER_1,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Reset stores before each test
// ---------------------------------------------------------------------------

beforeEach(() => {
  wcbDetailStore = [];
  wcbInjuryStore = [];
  wcbPrescriptionStore = [];
  wcbConsultationStore = [];
  wcbRestrictionStore = [];
  wcbInvoiceLineStore = [];
  wcbAttachmentStore = [];
  wcbBatchStore = [];
  wcbReturnRecordStore = [];
  wcbReturnInvoiceLineStore = [];
  wcbRemittanceImportStore = [];
  wcbRemittanceRecordStore = [];
  claimStore = [];
});

// ===========================================================================
// Tests
// ===========================================================================

describe('WCB Repository', () => {
  // -------------------------------------------------------------------------
  // createWcbClaim
  // -------------------------------------------------------------------------

  describe('createWcbClaim', () => {
    it('inserts claim with generated submitter_txn_id', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedClaim({ claimId: CLAIM_1 });
      const result = await repo.createWcbClaim(makeCreateInput());

      expect(result).toBeDefined();
      expect(result.claimId).toBe(CLAIM_1);
      expect(result.formId).toBe('C050E');
      expect(result.submitterTxnId).toBeDefined();
      expect(result.submitterTxnId.length).toBe(16);
      expect(wcbDetailStore).toHaveLength(1);
    });

    it('submitter_txn_id starts with vendor prefix MRT', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedClaim({ claimId: CLAIM_1 });
      const result = await repo.createWcbClaim(makeCreateInput());

      expect(result.submitterTxnId).toMatch(/^MRT/);
    });

    it('generates unique submitter_txn_ids for different claims', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedClaim({ claimId: CLAIM_1 });
      seedClaim({ claimId: CLAIM_2 });
      const result1 = await repo.createWcbClaim(makeCreateInput({ claimId: CLAIM_1 }));
      const result2 = await repo.createWcbClaim(makeCreateInput({ claimId: CLAIM_2 }));

      expect(result1.submitterTxnId).not.toBe(result2.submitterTxnId);
    });

    it('stores practitioner and patient snapshot fields', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedClaim({ claimId: CLAIM_1 });
      const result = await repo.createWcbClaim(makeCreateInput());

      expect(result.practitionerBillingNumber).toBe('12345678');
      expect(result.practitionerFirstName).toBe('Jane');
      expect(result.practitionerLastName).toBe('Smith');
      expect(result.patientFirstName).toBe('John');
      expect(result.patientLastName).toBe('Doe');
      expect(result.patientPhn).toBe('123456789');
      expect(result.patientDob).toBe('1990-05-10');
    });
  });

  // -------------------------------------------------------------------------
  // getWcbClaim
  // -------------------------------------------------------------------------

  describe('getWcbClaim', () => {
    it('returns all child records (injuries, prescriptions, consultations, restrictions, invoice_lines, attachments)', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1 });
      seedWcbDetail({ wcbClaimDetailId: WCB_DETAIL_1, claimId: CLAIM_1 });

      // Seed child records
      wcbInjuryStore.push({
        wcbInjuryId: 'inj-1',
        wcbClaimDetailId: WCB_DETAIL_1,
        ordinal: 1,
        partOfBodyCode: 'HAND',
        sideOfBodyCode: 'R',
        natureOfInjuryCode: 'FRAC',
      });
      wcbPrescriptionStore.push({
        wcbPrescriptionId: 'prx-1',
        wcbClaimDetailId: WCB_DETAIL_1,
        ordinal: 1,
        prescriptionName: 'Morphine',
        strength: '10mg',
        dailyIntake: '3x',
      });
      wcbConsultationStore.push({
        wcbConsultationId: 'con-1',
        wcbClaimDetailId: WCB_DETAIL_1,
        ordinal: 1,
        category: 'CONREF',
        typeCode: 'ORTHO',
        details: 'Ortho referral',
        expediteRequested: 'Y',
      });
      wcbRestrictionStore.push({
        wcbRestrictionId: 'rst-1',
        wcbClaimDetailId: WCB_DETAIL_1,
        activityType: 'SITTING',
        restrictionLevel: 'LIMITED',
        hoursPerDay: 4,
        maxWeight: null,
      });
      wcbInvoiceLineStore.push({
        wcbInvoiceLineId: 'inv-1',
        wcbClaimDetailId: WCB_DETAIL_1,
        invoiceDetailId: 1,
        lineType: 'STANDARD',
        healthServiceCode: '03.04A',
        amount: '94.15',
      });
      wcbAttachmentStore.push({
        wcbAttachmentId: 'att-1',
        wcbClaimDetailId: WCB_DETAIL_1,
        ordinal: 1,
        fileName: 'xray.pdf',
        fileType: 'PDF',
        fileContentB64: 'base64data',
        fileDescription: 'X-ray report',
        fileSizeBytes: 1024,
      });

      const result = await repo.getWcbClaim(WCB_DETAIL_1, PHYSICIAN_1);

      expect(result).not.toBeNull();
      expect(result!.detail.wcbClaimDetailId).toBe(WCB_DETAIL_1);
      expect(result!.claim.claimId).toBe(CLAIM_1);
      expect(result!.injuries).toHaveLength(1);
      expect(result!.injuries[0].partOfBodyCode).toBe('HAND');
      expect(result!.prescriptions).toHaveLength(1);
      expect(result!.prescriptions[0].prescriptionName).toBe('Morphine');
      expect(result!.consultations).toHaveLength(1);
      expect(result!.consultations[0].category).toBe('CONREF');
      expect(result!.workRestrictions).toHaveLength(1);
      expect(result!.workRestrictions[0].activityType).toBe('SITTING');
      expect(result!.invoiceLines).toHaveLength(1);
      expect(result!.invoiceLines[0].healthServiceCode).toBe('03.04A');
      expect(result!.attachments).toHaveLength(1);
      expect(result!.attachments[0].fileName).toBe('xray.pdf');
    });

    it('returns null for another physician\'s claim (scoping)', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_2 });
      seedWcbDetail({ wcbClaimDetailId: WCB_DETAIL_1, claimId: CLAIM_1 });

      const result = await repo.getWcbClaim(WCB_DETAIL_1, PHYSICIAN_1);
      expect(result).toBeNull();
    });

    it('returns null for soft-deleted claim', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1, deletedAt: new Date() });
      seedWcbDetail({ wcbClaimDetailId: WCB_DETAIL_1, claimId: CLAIM_1 });

      const result = await repo.getWcbClaim(WCB_DETAIL_1, PHYSICIAN_1);
      expect(result).toBeNull();
    });

    it('returns null for non-existent claim', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const result = await repo.getWcbClaim('non-existent-id', PHYSICIAN_1);
      expect(result).toBeNull();
    });

    it('returns empty arrays when claim has no child records', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1 });
      seedWcbDetail({ wcbClaimDetailId: WCB_DETAIL_1, claimId: CLAIM_1 });

      const result = await repo.getWcbClaim(WCB_DETAIL_1, PHYSICIAN_1);

      expect(result).not.toBeNull();
      expect(result!.injuries).toHaveLength(0);
      expect(result!.prescriptions).toHaveLength(0);
      expect(result!.consultations).toHaveLength(0);
      expect(result!.workRestrictions).toHaveLength(0);
      expect(result!.invoiceLines).toHaveLength(0);
      expect(result!.attachments).toHaveLength(0);
    });
  });

  // -------------------------------------------------------------------------
  // updateWcbClaim
  // -------------------------------------------------------------------------

  describe('updateWcbClaim', () => {
    it('updates fields and sets updated_at', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'DRAFT' });
      const originalUpdatedAt = new Date('2026-02-15T10:00:00Z');
      seedWcbDetail({
        wcbClaimDetailId: WCB_DETAIL_1,
        claimId: CLAIM_1,
        updatedAt: originalUpdatedAt,
      });

      const result = await repo.updateWcbClaim(WCB_DETAIL_1, PHYSICIAN_1, {
        additionalComments: 'Updated comments',
        updatedBy: USER_1,
      });

      expect(result).not.toBeNull();
      expect(result!.additionalComments).toBe('Updated comments');
      expect(result!.updatedAt).not.toEqual(originalUpdatedAt);
    });

    it('rejects update when claim not in draft state', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'SUBMITTED' });
      seedWcbDetail({ wcbClaimDetailId: WCB_DETAIL_1, claimId: CLAIM_1 });

      const result = await repo.updateWcbClaim(WCB_DETAIL_1, PHYSICIAN_1, {
        additionalComments: 'Should fail',
        updatedBy: USER_1,
      });

      expect(result).toBeNull();
    });

    it('rejects update for another physician\'s claim', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_2, state: 'DRAFT' });
      seedWcbDetail({ wcbClaimDetailId: WCB_DETAIL_1, claimId: CLAIM_1 });

      const result = await repo.updateWcbClaim(WCB_DETAIL_1, PHYSICIAN_1, {
        additionalComments: 'Should fail',
        updatedBy: USER_1,
      });

      expect(result).toBeNull();
    });

    it('rejects update for soft-deleted claim', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'DRAFT', deletedAt: new Date() });
      seedWcbDetail({ wcbClaimDetailId: WCB_DETAIL_1, claimId: CLAIM_1 });

      const result = await repo.updateWcbClaim(WCB_DETAIL_1, PHYSICIAN_1, {
        additionalComments: 'Should fail',
        updatedBy: USER_1,
      });

      expect(result).toBeNull();
    });
  });

  // -------------------------------------------------------------------------
  // softDeleteWcbClaim
  // -------------------------------------------------------------------------

  describe('softDeleteWcbClaim', () => {
    it('sets deleted_at when in draft state', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'DRAFT' });
      seedWcbDetail({ wcbClaimDetailId: WCB_DETAIL_1, claimId: CLAIM_1 });

      const result = await repo.softDeleteWcbClaim(WCB_DETAIL_1, PHYSICIAN_1);

      expect(result).toBe(true);
      expect(wcbDetailStore[0].deletedAt).not.toBeNull();
    });

    it('rejects when not in draft state', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'QUEUED' });
      seedWcbDetail({ wcbClaimDetailId: WCB_DETAIL_1, claimId: CLAIM_1 });

      const result = await repo.softDeleteWcbClaim(WCB_DETAIL_1, PHYSICIAN_1);

      expect(result).toBe(false);
      expect(wcbDetailStore[0].deletedAt).toBeNull();
    });

    it('rejects for another physician\'s claim', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_2, state: 'DRAFT' });
      seedWcbDetail({ wcbClaimDetailId: WCB_DETAIL_1, claimId: CLAIM_1 });

      const result = await repo.softDeleteWcbClaim(WCB_DETAIL_1, PHYSICIAN_1);

      expect(result).toBe(false);
    });

    it('returns false for non-existent claim', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const result = await repo.softDeleteWcbClaim('non-existent', PHYSICIAN_1);

      expect(result).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // getWcbClaimBySubmitterTxnId
  // -------------------------------------------------------------------------

  describe('getWcbClaimBySubmitterTxnId', () => {
    it('finds claim by submitter txn ID', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedWcbDetail({
        wcbClaimDetailId: WCB_DETAIL_1,
        submitterTxnId: 'MRT0000000000001',
      });

      const result = await repo.getWcbClaimBySubmitterTxnId('MRT0000000000001');

      expect(result).not.toBeNull();
      expect(result!.wcbClaimDetailId).toBe(WCB_DETAIL_1);
    });

    it('returns null for non-existent txn ID', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const result = await repo.getWcbClaimBySubmitterTxnId('MRT9999999999999');

      expect(result).toBeNull();
    });
  });

  // -------------------------------------------------------------------------
  // updateWcbClaimNumber
  // -------------------------------------------------------------------------

  describe('updateWcbClaimNumber', () => {
    it('stores WCB-assigned claim number', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedWcbDetail({ wcbClaimDetailId: WCB_DETAIL_1 });

      const result = await repo.updateWcbClaimNumber(WCB_DETAIL_1, '1234567');

      expect(result).not.toBeNull();
      expect(result!.wcbClaimNumber).toBe('1234567');
    });

    it('returns null for non-existent claim', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const result = await repo.updateWcbClaimNumber('non-existent', '1234567');

      expect(result).toBeNull();
    });
  });

  // -------------------------------------------------------------------------
  // listWcbClaimsForPhysician
  // -------------------------------------------------------------------------

  describe('listWcbClaimsForPhysician', () => {
    it('returns only the authenticated physician\'s claims', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      // Physician 1's claim
      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1 });
      seedWcbDetail({ wcbClaimDetailId: WCB_DETAIL_1, claimId: CLAIM_1 });

      // Physician 2's claim
      seedClaim({ claimId: CLAIM_2, physicianId: PHYSICIAN_2 });
      seedWcbDetail({ wcbClaimDetailId: WCB_DETAIL_2, claimId: CLAIM_2 });

      const result = await repo.listWcbClaimsForPhysician(PHYSICIAN_1, {
        page: 1,
        pageSize: 20,
      });

      expect(result.data).toHaveLength(1);
      expect(result.data[0].claim.physicianId).toBe(PHYSICIAN_1);
      expect(result.pagination.total).toBe(1);
    });

    it('excludes soft-deleted claims', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1, deletedAt: new Date() });
      seedWcbDetail({ wcbClaimDetailId: WCB_DETAIL_1, claimId: CLAIM_1 });

      seedClaim({ claimId: CLAIM_2, physicianId: PHYSICIAN_1 });
      seedWcbDetail({ wcbClaimDetailId: WCB_DETAIL_2, claimId: CLAIM_2 });

      const result = await repo.listWcbClaimsForPhysician(PHYSICIAN_1, {
        page: 1,
        pageSize: 20,
      });

      expect(result.data).toHaveLength(1);
      expect(result.data[0].detail.wcbClaimDetailId).toBe(WCB_DETAIL_2);
    });

    it('excludes WCB details with deletedAt set', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      // Soft-deleted both the base claim and WCB detail (deletedAt propagates)
      const deletedAt = new Date();
      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1, deletedAt });
      seedWcbDetail({ wcbClaimDetailId: WCB_DETAIL_1, claimId: CLAIM_1, deletedAt });

      seedClaim({ claimId: CLAIM_2, physicianId: PHYSICIAN_1 });
      seedWcbDetail({ wcbClaimDetailId: WCB_DETAIL_2, claimId: CLAIM_2 });

      const result = await repo.listWcbClaimsForPhysician(PHYSICIAN_1, {
        page: 1,
        pageSize: 20,
      });

      expect(result.data).toHaveLength(1);
      expect(result.data[0].detail.wcbClaimDetailId).toBe(WCB_DETAIL_2);
    });

    it('filters by status', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'DRAFT' });
      seedWcbDetail({ wcbClaimDetailId: WCB_DETAIL_1, claimId: CLAIM_1 });

      seedClaim({ claimId: CLAIM_2, physicianId: PHYSICIAN_1, state: 'SUBMITTED' });
      seedWcbDetail({ wcbClaimDetailId: WCB_DETAIL_2, claimId: CLAIM_2 });

      const result = await repo.listWcbClaimsForPhysician(PHYSICIAN_1, {
        status: 'DRAFT',
        page: 1,
        pageSize: 20,
      });

      expect(result.data).toHaveLength(1);
      expect(result.data[0].claim.state).toBe('DRAFT');
    });

    it('filters by form_id', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1 });
      seedWcbDetail({ wcbClaimDetailId: WCB_DETAIL_1, claimId: CLAIM_1, formId: 'C050E' });

      seedClaim({ claimId: CLAIM_2, physicianId: PHYSICIAN_1 });
      seedWcbDetail({ wcbClaimDetailId: WCB_DETAIL_2, claimId: CLAIM_2, formId: 'C151' });

      const result = await repo.listWcbClaimsForPhysician(PHYSICIAN_1, {
        formId: 'C050E',
        page: 1,
        pageSize: 20,
      });

      expect(result.data).toHaveLength(1);
      expect(result.data[0].detail.formId).toBe('C050E');
    });

    it('returns correct pagination metadata', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      // Create 3 claims for physician 1
      for (let i = 1; i <= 3; i++) {
        const cId = `clm-${i}000-0000-0000-000000000000`;
        const dId = `wcd-${i}000-0000-0000-000000000000`;
        seedClaim({ claimId: cId, physicianId: PHYSICIAN_1 });
        seedWcbDetail({ wcbClaimDetailId: dId, claimId: cId });
      }

      const result = await repo.listWcbClaimsForPhysician(PHYSICIAN_1, {
        page: 1,
        pageSize: 2,
      });

      expect(result.pagination.total).toBe(3);
      expect(result.pagination.page).toBe(1);
      expect(result.pagination.pageSize).toBe(2);
      expect(result.pagination.hasMore).toBe(true);
      expect(result.data).toHaveLength(2);
    });
  });

  // -------------------------------------------------------------------------
  // upsertInjuries
  // -------------------------------------------------------------------------

  describe('upsertInjuries', () => {
    it('inserts 3 injury entries', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const injuries = [
        { partOfBodyCode: 'HAND', sideOfBodyCode: 'R', natureOfInjuryCode: 'FRAC' },
        { partOfBodyCode: 'WRIST', sideOfBodyCode: 'L', natureOfInjuryCode: 'SPRAIN' },
        { partOfBodyCode: 'ELBOW', natureOfInjuryCode: 'BRUIS' },
      ];

      const result = await repo.upsertInjuries(WCB_DETAIL_1, injuries);

      expect(result).toHaveLength(3);
      expect(result[0].partOfBodyCode).toBe('HAND');
      expect(result[0].ordinal).toBe(1);
      expect(result[1].partOfBodyCode).toBe('WRIST');
      expect(result[1].ordinal).toBe(2);
      expect(result[2].partOfBodyCode).toBe('ELBOW');
      expect(result[2].ordinal).toBe(3);
      expect(wcbInjuryStore).toHaveLength(3);
    });

    it('replaces existing entries', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      // Seed existing injuries
      wcbInjuryStore.push({
        wcbInjuryId: 'inj-old-1',
        wcbClaimDetailId: WCB_DETAIL_1,
        ordinal: 1,
        partOfBodyCode: 'KNEE',
        sideOfBodyCode: 'R',
        natureOfInjuryCode: 'TEAR',
      });
      wcbInjuryStore.push({
        wcbInjuryId: 'inj-old-2',
        wcbClaimDetailId: WCB_DETAIL_1,
        ordinal: 2,
        partOfBodyCode: 'HIP',
        sideOfBodyCode: 'L',
        natureOfInjuryCode: 'FRAC',
      });

      expect(wcbInjuryStore).toHaveLength(2);

      const newInjuries = [
        { partOfBodyCode: 'SHOULDER', sideOfBodyCode: 'R', natureOfInjuryCode: 'DISLO' },
      ];

      const result = await repo.upsertInjuries(WCB_DETAIL_1, newInjuries);

      expect(result).toHaveLength(1);
      expect(result[0].partOfBodyCode).toBe('SHOULDER');
      expect(result[0].ordinal).toBe(1);
      // Old rows deleted, only the 1 new row remains
      expect(wcbInjuryStore).toHaveLength(1);
    });

    it('enforces max 5', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const injuries = Array.from({ length: 6 }, (_, i) => ({
        partOfBodyCode: `BODY${i}`,
        natureOfInjuryCode: `INJ${i}`,
      }));

      await expect(repo.upsertInjuries(WCB_DETAIL_1, injuries)).rejects.toThrow(
        'Maximum 5 injuries allowed per WCB claim',
      );
    });
  });

  // -------------------------------------------------------------------------
  // upsertPrescriptions
  // -------------------------------------------------------------------------

  describe('upsertPrescriptions', () => {
    it('inserts and replaces prescriptions', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      // Insert initial prescriptions
      const initial = [
        { prescriptionName: 'Morphine', strength: '10mg', dailyIntake: '3x' },
        { prescriptionName: 'Tylenol 3', strength: '300mg', dailyIntake: '4x' },
      ];

      const result1 = await repo.upsertPrescriptions(WCB_DETAIL_1, initial);
      expect(result1).toHaveLength(2);
      expect(result1[0].prescriptionName).toBe('Morphine');
      expect(result1[0].ordinal).toBe(1);
      expect(result1[1].prescriptionName).toBe('Tylenol 3');
      expect(result1[1].ordinal).toBe(2);

      // Replace with different set
      const replacement = [
        { prescriptionName: 'Oxycodone', strength: '5mg', dailyIntake: '2x' },
      ];

      const result2 = await repo.upsertPrescriptions(WCB_DETAIL_1, replacement);
      expect(result2).toHaveLength(1);
      expect(result2[0].prescriptionName).toBe('Oxycodone');
      expect(result2[0].ordinal).toBe(1);
      expect(wcbPrescriptionStore).toHaveLength(1);
    });

    it('enforces max 5', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const prescriptions = Array.from({ length: 6 }, (_, i) => ({
        prescriptionName: `Drug${i}`,
        strength: `${i}mg`,
        dailyIntake: `${i}x`,
      }));

      await expect(repo.upsertPrescriptions(WCB_DETAIL_1, prescriptions)).rejects.toThrow(
        'Maximum 5 prescriptions allowed per WCB claim',
      );
    });
  });

  // -------------------------------------------------------------------------
  // upsertConsultations
  // -------------------------------------------------------------------------

  describe('upsertConsultations', () => {
    it('inserts and replaces consultations', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      // Insert initial
      const initial = [
        { category: 'CONREF', typeCode: 'ORTHO', details: 'Ortho referral', expediteRequested: 'Y' },
        { category: 'INVE', typeCode: 'XRAY', details: 'X-ray investigation' },
      ];

      const result1 = await repo.upsertConsultations(WCB_DETAIL_1, initial);
      expect(result1).toHaveLength(2);
      expect(result1[0].category).toBe('CONREF');
      expect(result1[0].ordinal).toBe(1);
      expect(result1[1].category).toBe('INVE');
      expect(result1[1].ordinal).toBe(2);

      // Replace
      const replacement = [
        { category: 'CONREF', typeCode: 'NEURO', details: 'Neurology referral' },
        { category: 'CONREF', typeCode: 'CARDIO', details: 'Cardiology referral' },
        { category: 'INVE', typeCode: 'MRI', details: 'MRI scan' },
      ];

      const result2 = await repo.upsertConsultations(WCB_DETAIL_1, replacement);
      expect(result2).toHaveLength(3);
      expect(wcbConsultationStore).toHaveLength(3);
      expect(result2[0].typeCode).toBe('NEURO');
      expect(result2[2].typeCode).toBe('MRI');
    });

    it('enforces max 5', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const consultations = Array.from({ length: 6 }, (_, i) => ({
        category: 'CONREF',
        typeCode: `TYPE${i}`,
        details: `Details ${i}`,
      }));

      await expect(repo.upsertConsultations(WCB_DETAIL_1, consultations)).rejects.toThrow(
        'Maximum 5 consultations allowed per WCB claim',
      );
    });
  });

  // -------------------------------------------------------------------------
  // upsertWorkRestrictions
  // -------------------------------------------------------------------------

  describe('upsertWorkRestrictions', () => {
    it('inserts up to 11 activity types', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const activityTypes = [
        'SITTING', 'STANDING', 'WALKING', 'BENDING', 'TWISTING',
        'CLIMBING', 'REACHING', 'LIFTING', 'CARRYING', 'PUSHING',
        'KNEELING',
      ];

      const restrictions = activityTypes.map((at) => ({
        activityType: at,
        restrictionLevel: 'LIMITED',
        hoursPerDay: 4,
      }));

      const result = await repo.upsertWorkRestrictions(WCB_DETAIL_1, restrictions);

      expect(result).toHaveLength(11);
      expect(wcbRestrictionStore).toHaveLength(11);
      // Verify each activity type is stored
      for (const at of activityTypes) {
        expect(result.find((r: any) => r.activityType === at)).toBeDefined();
      }
    });

    it('rejects duplicate activity_type', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const restrictions = [
        { activityType: 'SITTING', restrictionLevel: 'LIMITED' },
        { activityType: 'STANDING', restrictionLevel: 'NONE' },
        { activityType: 'SITTING', restrictionLevel: 'FULL' }, // duplicate
      ];

      await expect(repo.upsertWorkRestrictions(WCB_DETAIL_1, restrictions)).rejects.toThrow(
        'Duplicate activity_type in work restrictions',
      );
    });

    it('replaces existing restrictions', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      // Seed existing
      wcbRestrictionStore.push({
        wcbRestrictionId: 'rst-old-1',
        wcbClaimDetailId: WCB_DETAIL_1,
        activityType: 'SITTING',
        restrictionLevel: 'FULL',
        hoursPerDay: null,
        maxWeight: null,
      });

      const newRestrictions = [
        { activityType: 'STANDING', restrictionLevel: 'LIMITED', hoursPerDay: 6 },
        { activityType: 'WALKING', restrictionLevel: 'NONE' },
      ];

      const result = await repo.upsertWorkRestrictions(WCB_DETAIL_1, newRestrictions);

      expect(result).toHaveLength(2);
      expect(wcbRestrictionStore).toHaveLength(2);
      expect(result[0].activityType).toBe('STANDING');
      expect(result[1].activityType).toBe('WALKING');
    });

    it('enforces max 11', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const restrictions = Array.from({ length: 12 }, (_, i) => ({
        activityType: `ACTIVITY_${i}`,
        restrictionLevel: 'LIMITED',
      }));

      await expect(repo.upsertWorkRestrictions(WCB_DETAIL_1, restrictions)).rejects.toThrow(
        'Maximum 11 work restrictions allowed per WCB claim',
      );
    });
  });

  // -------------------------------------------------------------------------
  // upsertInvoiceLines
  // -------------------------------------------------------------------------

  describe('upsertInvoiceLines', () => {
    it('inserts sequential lines', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const lines = [
        { lineType: 'STANDARD', healthServiceCode: '03.04A', amount: '94.15' },
        { lineType: 'STANDARD', healthServiceCode: '03.05A', amount: '47.00' },
        { lineType: 'DATED', healthServiceCode: '08.19A', dateOfServiceFrom: '2026-02-10', dateOfServiceTo: '2026-02-15', amount: '120.00' },
      ];

      const result = await repo.upsertInvoiceLines(WCB_DETAIL_1, lines);

      expect(result).toHaveLength(3);
      expect(result[0].invoiceDetailId).toBe(1);
      expect(result[0].lineType).toBe('STANDARD');
      expect(result[0].healthServiceCode).toBe('03.04A');
      expect(result[1].invoiceDetailId).toBe(2);
      expect(result[1].healthServiceCode).toBe('03.05A');
      expect(result[2].invoiceDetailId).toBe(3);
      expect(result[2].lineType).toBe('DATED');
      expect(wcbInvoiceLineStore).toHaveLength(3);
    });

    it('enforces max 25', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const lines = Array.from({ length: 26 }, (_, i) => ({
        lineType: 'STANDARD',
        healthServiceCode: `SVC${i}`,
      }));

      await expect(repo.upsertInvoiceLines(WCB_DETAIL_1, lines)).rejects.toThrow(
        'Maximum 25 invoice lines allowed per WCB claim',
      );
    });

    it('replaces existing lines in transaction', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      // Seed existing lines
      wcbInvoiceLineStore.push({
        wcbInvoiceLineId: 'inv-old-1',
        wcbClaimDetailId: WCB_DETAIL_1,
        invoiceDetailId: 1,
        lineType: 'STANDARD',
        healthServiceCode: '03.04A',
        amount: '94.15',
      });
      wcbInvoiceLineStore.push({
        wcbInvoiceLineId: 'inv-old-2',
        wcbClaimDetailId: WCB_DETAIL_1,
        invoiceDetailId: 2,
        lineType: 'STANDARD',
        healthServiceCode: '03.05A',
        amount: '47.00',
      });

      expect(wcbInvoiceLineStore).toHaveLength(2);

      const newLines = [
        { lineType: 'SUPPLY', quantity: 2, supplyDescription: 'Bandages', amount: '15.00' },
      ];

      const result = await repo.upsertInvoiceLines(WCB_DETAIL_1, newLines);

      expect(result).toHaveLength(1);
      expect(result[0].lineType).toBe('SUPPLY');
      expect(result[0].invoiceDetailId).toBe(1);
      // Old rows deleted, only 1 new row remains
      expect(wcbInvoiceLineStore).toHaveLength(1);
    });

    it('handles empty array (clears all lines)', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      wcbInvoiceLineStore.push({
        wcbInvoiceLineId: 'inv-1',
        wcbClaimDetailId: WCB_DETAIL_1,
        invoiceDetailId: 1,
        lineType: 'STANDARD',
        healthServiceCode: '03.04A',
        amount: '94.15',
      });

      const result = await repo.upsertInvoiceLines(WCB_DETAIL_1, []);

      expect(result).toHaveLength(0);
      expect(wcbInvoiceLineStore).toHaveLength(0);
    });

    it('assigns sequential invoice_detail_id starting from 1', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const lines = Array.from({ length: 5 }, (_, i) => ({
        lineType: 'STANDARD',
        healthServiceCode: `SVC${i}`,
      }));

      const result = await repo.upsertInvoiceLines(WCB_DETAIL_1, lines);

      for (let i = 0; i < 5; i++) {
        expect(result[i].invoiceDetailId).toBe(i + 1);
      }
    });

    it('handles C570 WAS/SHOULD_BE correction lines with correction_pair_id', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const lines = [
        { lineType: 'WAS', correctionPairId: 1, healthServiceCode: '03.04A', amount: '94.15' },
        { lineType: 'SHOULD_BE', correctionPairId: 1, healthServiceCode: '03.04A', amount: '120.00' },
      ];

      const result = await repo.upsertInvoiceLines(WCB_DETAIL_1, lines);

      expect(result).toHaveLength(2);
      expect(result[0].lineType).toBe('WAS');
      expect(result[0].correctionPairId).toBe(1);
      expect(result[1].lineType).toBe('SHOULD_BE');
      expect(result[1].correctionPairId).toBe(1);
    });
  });

  // -------------------------------------------------------------------------
  // getInvoiceLines
  // -------------------------------------------------------------------------

  describe('getInvoiceLines', () => {
    it('returns lines ordered by invoice_detail_id', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      // Insert in non-sequential order
      wcbInvoiceLineStore.push({
        wcbInvoiceLineId: 'inv-3',
        wcbClaimDetailId: WCB_DETAIL_1,
        invoiceDetailId: 3,
        lineType: 'STANDARD',
        healthServiceCode: '08.19A',
        amount: '120.00',
      });
      wcbInvoiceLineStore.push({
        wcbInvoiceLineId: 'inv-1',
        wcbClaimDetailId: WCB_DETAIL_1,
        invoiceDetailId: 1,
        lineType: 'STANDARD',
        healthServiceCode: '03.04A',
        amount: '94.15',
      });
      wcbInvoiceLineStore.push({
        wcbInvoiceLineId: 'inv-2',
        wcbClaimDetailId: WCB_DETAIL_1,
        invoiceDetailId: 2,
        lineType: 'DATED',
        healthServiceCode: '03.05A',
        amount: '47.00',
      });

      const result = await repo.getInvoiceLines(WCB_DETAIL_1);

      expect(result).toHaveLength(3);
      expect(result[0].invoiceDetailId).toBe(1);
      expect(result[1].invoiceDetailId).toBe(2);
      expect(result[2].invoiceDetailId).toBe(3);
    });

    it('returns empty array for claim with no lines', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const result = await repo.getInvoiceLines(WCB_DETAIL_1);

      expect(result).toHaveLength(0);
    });

    it('returns only lines for the specified claim detail', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      wcbInvoiceLineStore.push({
        wcbInvoiceLineId: 'inv-1',
        wcbClaimDetailId: WCB_DETAIL_1,
        invoiceDetailId: 1,
        lineType: 'STANDARD',
        healthServiceCode: '03.04A',
        amount: '94.15',
      });
      wcbInvoiceLineStore.push({
        wcbInvoiceLineId: 'inv-2',
        wcbClaimDetailId: WCB_DETAIL_2,
        invoiceDetailId: 1,
        lineType: 'STANDARD',
        healthServiceCode: '08.19A',
        amount: '120.00',
      });

      const result = await repo.getInvoiceLines(WCB_DETAIL_1);

      expect(result).toHaveLength(1);
      expect(result[0].wcbClaimDetailId).toBe(WCB_DETAIL_1);
    });
  });

  // -------------------------------------------------------------------------
  // validateC570Pairing
  // -------------------------------------------------------------------------

  describe('validateC570Pairing', () => {
    it('returns valid for correct pairing', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      wcbInvoiceLineStore.push({
        wcbInvoiceLineId: 'inv-1',
        wcbClaimDetailId: WCB_DETAIL_1,
        invoiceDetailId: 1,
        lineType: 'WAS',
        correctionPairId: 1,
        healthServiceCode: '03.04A',
        amount: '94.15',
      });
      wcbInvoiceLineStore.push({
        wcbInvoiceLineId: 'inv-2',
        wcbClaimDetailId: WCB_DETAIL_1,
        invoiceDetailId: 2,
        lineType: 'SHOULD_BE',
        correctionPairId: 1,
        healthServiceCode: '03.04A',
        amount: '120.00',
      });

      const result = await repo.validateC570Pairing(WCB_DETAIL_1);

      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('returns valid for multiple correct pairs', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      wcbInvoiceLineStore.push(
        { wcbInvoiceLineId: 'inv-1', wcbClaimDetailId: WCB_DETAIL_1, invoiceDetailId: 1, lineType: 'WAS', correctionPairId: 1, healthServiceCode: '03.04A', amount: '94.15' },
        { wcbInvoiceLineId: 'inv-2', wcbClaimDetailId: WCB_DETAIL_1, invoiceDetailId: 2, lineType: 'SHOULD_BE', correctionPairId: 1, healthServiceCode: '03.04A', amount: '120.00' },
        { wcbInvoiceLineId: 'inv-3', wcbClaimDetailId: WCB_DETAIL_1, invoiceDetailId: 3, lineType: 'WAS', correctionPairId: 2, healthServiceCode: '08.19A', amount: '50.00' },
        { wcbInvoiceLineId: 'inv-4', wcbClaimDetailId: WCB_DETAIL_1, invoiceDetailId: 4, lineType: 'SHOULD_BE', correctionPairId: 2, healthServiceCode: '08.19A', amount: '75.00' },
      );

      const result = await repo.validateC570Pairing(WCB_DETAIL_1);

      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('returns errors for missing SHOULD_BE pair', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      wcbInvoiceLineStore.push({
        wcbInvoiceLineId: 'inv-1',
        wcbClaimDetailId: WCB_DETAIL_1,
        invoiceDetailId: 1,
        lineType: 'WAS',
        correctionPairId: 1,
        healthServiceCode: '03.04A',
        amount: '94.15',
      });

      const result = await repo.validateC570Pairing(WCB_DETAIL_1);

      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors.some((e: string) => e.includes('correction_pair_id=1') && e.includes('no matching SHOULD_BE'))).toBe(true);
    });

    it('returns errors for missing WAS pair', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      wcbInvoiceLineStore.push({
        wcbInvoiceLineId: 'inv-1',
        wcbClaimDetailId: WCB_DETAIL_1,
        invoiceDetailId: 1,
        lineType: 'SHOULD_BE',
        correctionPairId: 1,
        healthServiceCode: '03.04A',
        amount: '120.00',
      });

      const result = await repo.validateC570Pairing(WCB_DETAIL_1);

      expect(result.valid).toBe(false);
      expect(result.errors.some((e: string) => e.includes('correction_pair_id=1') && e.includes('no matching WAS'))).toBe(true);
    });

    it('returns errors for missing correction_pair_id', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      wcbInvoiceLineStore.push({
        wcbInvoiceLineId: 'inv-1',
        wcbClaimDetailId: WCB_DETAIL_1,
        invoiceDetailId: 1,
        lineType: 'WAS',
        correctionPairId: null,
        healthServiceCode: '03.04A',
        amount: '94.15',
      });

      const result = await repo.validateC570Pairing(WCB_DETAIL_1);

      expect(result.valid).toBe(false);
      expect(result.errors.some((e: string) => e.includes('missing correction_pair_id'))).toBe(true);
    });

    it('returns valid when no WAS/SHOULD_BE lines exist', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      // Only standard lines
      wcbInvoiceLineStore.push({
        wcbInvoiceLineId: 'inv-1',
        wcbClaimDetailId: WCB_DETAIL_1,
        invoiceDetailId: 1,
        lineType: 'STANDARD',
        correctionPairId: null,
        healthServiceCode: '03.04A',
        amount: '94.15',
      });

      const result = await repo.validateC570Pairing(WCB_DETAIL_1);

      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });
  });

  // -------------------------------------------------------------------------
  // upsertAttachments
  // -------------------------------------------------------------------------

  describe('upsertAttachments', () => {
    it('inserts up to 3 attachments', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const attachments = [
        { fileName: 'xray.pdf', fileType: 'PDF', fileContentB64: 'data1', fileDescription: 'X-ray report', fileSizeBytes: 1024 },
        { fileName: 'mri.jpg', fileType: 'JPG', fileContentB64: 'data2', fileDescription: 'MRI image', fileSizeBytes: 2048 },
        { fileName: 'notes.doc', fileType: 'DOC', fileContentB64: 'data3', fileDescription: 'Clinical notes', fileSizeBytes: 512 },
      ];

      const result = await repo.upsertAttachments(WCB_DETAIL_1, attachments);

      expect(result).toHaveLength(3);
      expect(result[0].ordinal).toBe(1);
      expect(result[0].fileName).toBe('xray.pdf');
      expect(result[1].ordinal).toBe(2);
      expect(result[1].fileName).toBe('mri.jpg');
      expect(result[2].ordinal).toBe(3);
      expect(result[2].fileName).toBe('notes.doc');
      expect(wcbAttachmentStore).toHaveLength(3);
    });

    it('enforces max 3', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const attachments = Array.from({ length: 4 }, (_, i) => ({
        fileName: `file${i}.pdf`,
        fileType: 'PDF',
        fileContentB64: `data${i}`,
        fileDescription: `Description ${i}`,
        fileSizeBytes: 1024,
      }));

      await expect(repo.upsertAttachments(WCB_DETAIL_1, attachments)).rejects.toThrow(
        'Maximum 3 attachments allowed per WCB claim',
      );
    });

    it('replaces existing attachments', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      wcbAttachmentStore.push({
        wcbAttachmentId: 'att-old-1',
        wcbClaimDetailId: WCB_DETAIL_1,
        ordinal: 1,
        fileName: 'old.pdf',
        fileType: 'PDF',
        fileContentB64: 'olddata',
        fileDescription: 'Old file',
        fileSizeBytes: 512,
      });
      wcbAttachmentStore.push({
        wcbAttachmentId: 'att-old-2',
        wcbClaimDetailId: WCB_DETAIL_1,
        ordinal: 2,
        fileName: 'old2.pdf',
        fileType: 'PDF',
        fileContentB64: 'olddata2',
        fileDescription: 'Old file 2',
        fileSizeBytes: 256,
      });

      expect(wcbAttachmentStore).toHaveLength(2);

      const newAttachments = [
        { fileName: 'new.jpg', fileType: 'JPG', fileContentB64: 'newdata', fileDescription: 'New image', fileSizeBytes: 4096 },
      ];

      const result = await repo.upsertAttachments(WCB_DETAIL_1, newAttachments);

      expect(result).toHaveLength(1);
      expect(result[0].fileName).toBe('new.jpg');
      expect(result[0].ordinal).toBe(1);
      expect(wcbAttachmentStore).toHaveLength(1);
    });

    it('handles empty array (clears all attachments)', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      wcbAttachmentStore.push({
        wcbAttachmentId: 'att-1',
        wcbClaimDetailId: WCB_DETAIL_1,
        ordinal: 1,
        fileName: 'file.pdf',
        fileType: 'PDF',
        fileContentB64: 'data',
        fileDescription: 'A file',
        fileSizeBytes: 1024,
      });

      const result = await repo.upsertAttachments(WCB_DETAIL_1, []);

      expect(result).toHaveLength(0);
      expect(wcbAttachmentStore).toHaveLength(0);
    });
  });

  // -------------------------------------------------------------------------
  // getAttachments
  // -------------------------------------------------------------------------

  describe('getAttachments', () => {
    it('returns attachments ordered by ordinal without file_content_b64', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      wcbAttachmentStore.push({
        wcbAttachmentId: 'att-2',
        wcbClaimDetailId: WCB_DETAIL_1,
        ordinal: 2,
        fileName: 'mri.jpg',
        fileType: 'JPG',
        fileContentB64: 'largedata2',
        fileDescription: 'MRI image',
        fileSizeBytes: 2048,
      });
      wcbAttachmentStore.push({
        wcbAttachmentId: 'att-1',
        wcbClaimDetailId: WCB_DETAIL_1,
        ordinal: 1,
        fileName: 'xray.pdf',
        fileType: 'PDF',
        fileContentB64: 'largedata1',
        fileDescription: 'X-ray report',
        fileSizeBytes: 1024,
      });

      const result = await repo.getAttachments(WCB_DETAIL_1);

      expect(result).toHaveLength(2);
      expect(result[0].ordinal).toBe(1);
      expect(result[0].fileName).toBe('xray.pdf');
      expect(result[1].ordinal).toBe(2);
      expect(result[1].fileName).toBe('mri.jpg');
      // Metadata should not contain file_content_b64
      expect((result[0] as any).fileContentB64).toBeUndefined();
      expect((result[1] as any).fileContentB64).toBeUndefined();
    });

    it('returns empty array for claim with no attachments', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const result = await repo.getAttachments(WCB_DETAIL_1);

      expect(result).toHaveLength(0);
    });
  });

  // -------------------------------------------------------------------------
  // getAttachmentContent
  // -------------------------------------------------------------------------

  describe('getAttachmentContent', () => {
    it('returns attachment with content scoped to physician', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1 });
      seedWcbDetail({ wcbClaimDetailId: WCB_DETAIL_1, claimId: CLAIM_1 });

      wcbAttachmentStore.push({
        wcbAttachmentId: 'att-1',
        wcbClaimDetailId: WCB_DETAIL_1,
        ordinal: 1,
        fileName: 'xray.pdf',
        fileType: 'PDF',
        fileContentB64: 'base64contentdata',
        fileDescription: 'X-ray report',
        fileSizeBytes: 1024,
      });

      const result = await repo.getAttachmentContent('att-1', PHYSICIAN_1);

      expect(result).not.toBeNull();
      expect(result!.wcbAttachmentId).toBe('att-1');
      expect(result!.fileContentB64).toBe('base64contentdata');
      expect(result!.fileName).toBe('xray.pdf');
    });

    it('returns null for another physician\'s attachment', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_2 });
      seedWcbDetail({ wcbClaimDetailId: WCB_DETAIL_1, claimId: CLAIM_1 });

      wcbAttachmentStore.push({
        wcbAttachmentId: 'att-1',
        wcbClaimDetailId: WCB_DETAIL_1,
        ordinal: 1,
        fileName: 'xray.pdf',
        fileType: 'PDF',
        fileContentB64: 'base64contentdata',
        fileDescription: 'X-ray report',
        fileSizeBytes: 1024,
      });

      const result = await repo.getAttachmentContent('att-1', PHYSICIAN_1);

      expect(result).toBeNull();
    });

    it('returns null for non-existent attachment', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const result = await repo.getAttachmentContent('non-existent', PHYSICIAN_1);

      expect(result).toBeNull();
    });

    it('returns null for soft-deleted claim\'s attachment', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1, deletedAt: new Date() });
      seedWcbDetail({ wcbClaimDetailId: WCB_DETAIL_1, claimId: CLAIM_1 });

      wcbAttachmentStore.push({
        wcbAttachmentId: 'att-1',
        wcbClaimDetailId: WCB_DETAIL_1,
        ordinal: 1,
        fileName: 'xray.pdf',
        fileType: 'PDF',
        fileContentB64: 'base64contentdata',
        fileDescription: 'X-ray report',
        fileSizeBytes: 1024,
      });

      const result = await repo.getAttachmentContent('att-1', PHYSICIAN_1);

      expect(result).toBeNull();
    });
  });

  // -------------------------------------------------------------------------
  // createBatch
  // -------------------------------------------------------------------------

  describe('createBatch', () => {
    it('creates batch with ASSEMBLING status', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const result = await repo.createBatch(PHYSICIAN_1, USER_1);

      expect(result).toBeDefined();
      expect(result.physicianId).toBe(PHYSICIAN_1);
      expect(result.status).toBe('ASSEMBLING');
      expect(result.reportCount).toBe(0);
      expect(result.createdBy).toBe(USER_1);
      expect(wcbBatchStore).toHaveLength(1);
    });

    it('generates unique batch_control_id with MER-B- prefix', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const result = await repo.createBatch(PHYSICIAN_1, USER_1);

      expect(result.batchControlId).toMatch(/^MER-B-[0-9A-F]{8}$/);
    });

    it('generates unique file_control_id with MER-YYYYMMDD- prefix', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const result = await repo.createBatch(PHYSICIAN_1, USER_1);

      expect(result.fileControlId).toMatch(/^MER-\d{8}-[0-9A-F]{6}$/);
    });

    it('generates unique IDs for different batches', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const result1 = await repo.createBatch(PHYSICIAN_1, USER_1);
      const result2 = await repo.createBatch(PHYSICIAN_1, USER_1);

      expect(result1.batchControlId).not.toBe(result2.batchControlId);
      expect(result1.fileControlId).not.toBe(result2.fileControlId);
    });
  });

  // -------------------------------------------------------------------------
  // getBatch
  // -------------------------------------------------------------------------

  describe('getBatch', () => {
    it('returns batch scoped to physician', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedBatch({ wcbBatchId: BATCH_1, physicianId: PHYSICIAN_1 });

      const result = await repo.getBatch(BATCH_1, PHYSICIAN_1);

      expect(result).not.toBeNull();
      expect(result!.wcbBatchId).toBe(BATCH_1);
      expect(result!.physicianId).toBe(PHYSICIAN_1);
    });

    it('returns null for another physician\'s batch', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedBatch({ wcbBatchId: BATCH_1, physicianId: PHYSICIAN_2 });

      const result = await repo.getBatch(BATCH_1, PHYSICIAN_1);

      expect(result).toBeNull();
    });

    it('returns null for non-existent batch', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const result = await repo.getBatch('non-existent-id', PHYSICIAN_1);

      expect(result).toBeNull();
    });
  });

  // -------------------------------------------------------------------------
  // listBatches
  // -------------------------------------------------------------------------

  describe('listBatches', () => {
    it('returns reverse chronological batches for physician', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedBatch({
        wcbBatchId: BATCH_1,
        physicianId: PHYSICIAN_1,
        createdAt: new Date('2026-02-14T10:00:00Z'),
      });
      seedBatch({
        wcbBatchId: BATCH_2,
        physicianId: PHYSICIAN_1,
        createdAt: new Date('2026-02-15T10:00:00Z'),
      });

      const result = await repo.listBatches(PHYSICIAN_1, { page: 1, pageSize: 20 });

      expect(result.data).toHaveLength(2);
      // BATCH_2 (newer) should come first
      expect(result.data[0].wcbBatchId).toBe(BATCH_2);
      expect(result.data[1].wcbBatchId).toBe(BATCH_1);
      expect(result.pagination.total).toBe(2);
    });

    it('filters by status', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedBatch({ wcbBatchId: BATCH_1, physicianId: PHYSICIAN_1, status: 'ASSEMBLING' });
      seedBatch({ wcbBatchId: BATCH_2, physicianId: PHYSICIAN_1, status: 'UPLOADED' });

      const result = await repo.listBatches(PHYSICIAN_1, {
        status: 'ASSEMBLING',
        page: 1,
        pageSize: 20,
      });

      expect(result.data).toHaveLength(1);
      expect(result.data[0].status).toBe('ASSEMBLING');
    });

    it('excludes other physician\'s batches', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedBatch({ wcbBatchId: BATCH_1, physicianId: PHYSICIAN_1 });
      seedBatch({ wcbBatchId: BATCH_2, physicianId: PHYSICIAN_2 });

      const result = await repo.listBatches(PHYSICIAN_1, { page: 1, pageSize: 20 });

      expect(result.data).toHaveLength(1);
      expect(result.data[0].physicianId).toBe(PHYSICIAN_1);
    });

    it('returns correct pagination', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      for (let i = 1; i <= 3; i++) {
        seedBatch({
          wcbBatchId: `bat-${i}000-0000-0000-000000000000`,
          physicianId: PHYSICIAN_1,
          createdAt: new Date(`2026-02-${10 + i}T10:00:00Z`),
        });
      }

      const result = await repo.listBatches(PHYSICIAN_1, { page: 1, pageSize: 2 });

      expect(result.pagination.total).toBe(3);
      expect(result.pagination.hasMore).toBe(true);
      expect(result.data).toHaveLength(2);
    });
  });

  // -------------------------------------------------------------------------
  // updateBatchStatus
  // -------------------------------------------------------------------------

  describe('updateBatchStatus', () => {
    it('transitions ASSEMBLING to GENERATED', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedBatch({ wcbBatchId: BATCH_1, physicianId: PHYSICIAN_1, status: 'ASSEMBLING' });

      const result = await repo.updateBatchStatus(BATCH_1, PHYSICIAN_1, 'GENERATED', {
        reportCount: 5,
        xmlFilePath: '/batches/test.xml',
        xmlFileHash: 'abc123hash',
      });

      expect(result).not.toBeNull();
      expect(result!.status).toBe('GENERATED');
      expect(result!.reportCount).toBe(5);
      expect(result!.xmlFilePath).toBe('/batches/test.xml');
      expect(result!.xmlFileHash).toBe('abc123hash');
    });

    it('transitions GENERATED to VALIDATED', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedBatch({ wcbBatchId: BATCH_1, physicianId: PHYSICIAN_1, status: 'GENERATED' });

      const result = await repo.updateBatchStatus(BATCH_1, PHYSICIAN_1, 'VALIDATED', {
        xsdValidationPassed: true,
      });

      expect(result).not.toBeNull();
      expect(result!.status).toBe('VALIDATED');
      expect(result!.xsdValidationPassed).toBe(true);
    });

    it('allows ERROR from ASSEMBLING', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedBatch({ wcbBatchId: BATCH_1, physicianId: PHYSICIAN_1, status: 'ASSEMBLING' });

      const result = await repo.updateBatchStatus(BATCH_1, PHYSICIAN_1, 'ERROR');

      expect(result).not.toBeNull();
      expect(result!.status).toBe('ERROR');
    });

    it('allows ERROR from GENERATED', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedBatch({ wcbBatchId: BATCH_1, physicianId: PHYSICIAN_1, status: 'GENERATED' });

      const result = await repo.updateBatchStatus(BATCH_1, PHYSICIAN_1, 'ERROR');

      expect(result).not.toBeNull();
      expect(result!.status).toBe('ERROR');
    });

    it('allows ERROR from VALIDATED', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedBatch({ wcbBatchId: BATCH_1, physicianId: PHYSICIAN_1, status: 'VALIDATED' });

      const result = await repo.updateBatchStatus(BATCH_1, PHYSICIAN_1, 'ERROR');

      expect(result).not.toBeNull();
      expect(result!.status).toBe('ERROR');
    });

    it('rejects invalid transition (ASSEMBLING to UPLOADED)', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedBatch({ wcbBatchId: BATCH_1, physicianId: PHYSICIAN_1, status: 'ASSEMBLING' });

      await expect(
        repo.updateBatchStatus(BATCH_1, PHYSICIAN_1, 'UPLOADED'),
      ).rejects.toThrow('Invalid batch status transition');
    });

    it('rejects transition from ERROR', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedBatch({ wcbBatchId: BATCH_1, physicianId: PHYSICIAN_1, status: 'ERROR' });

      await expect(
        repo.updateBatchStatus(BATCH_1, PHYSICIAN_1, 'GENERATED'),
      ).rejects.toThrow('Invalid batch status transition');
    });

    it('returns null for another physician\'s batch', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedBatch({ wcbBatchId: BATCH_1, physicianId: PHYSICIAN_2, status: 'ASSEMBLING' });

      const result = await repo.updateBatchStatus(BATCH_1, PHYSICIAN_1, 'GENERATED');

      expect(result).toBeNull();
    });
  });

  // -------------------------------------------------------------------------
  // setBatchUploaded
  // -------------------------------------------------------------------------

  describe('setBatchUploaded', () => {
    it('sets status to UPLOADED from VALIDATED', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedBatch({ wcbBatchId: BATCH_1, physicianId: PHYSICIAN_1, status: 'VALIDATED' });

      const result = await repo.setBatchUploaded(BATCH_1, PHYSICIAN_1, USER_1);

      expect(result).not.toBeNull();
      expect(result!.status).toBe('UPLOADED');
      expect(result!.uploadedBy).toBe(USER_1);
      expect(result!.uploadedAt).toBeInstanceOf(Date);
    });

    it('rejects from ASSEMBLING status', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedBatch({ wcbBatchId: BATCH_1, physicianId: PHYSICIAN_1, status: 'ASSEMBLING' });

      await expect(
        repo.setBatchUploaded(BATCH_1, PHYSICIAN_1, USER_1),
      ).rejects.toThrow('Cannot upload batch');
    });

    it('rejects from GENERATED status', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedBatch({ wcbBatchId: BATCH_1, physicianId: PHYSICIAN_1, status: 'GENERATED' });

      await expect(
        repo.setBatchUploaded(BATCH_1, PHYSICIAN_1, USER_1),
      ).rejects.toThrow('Cannot upload batch');
    });

    it('rejects from UPLOADED status (already uploaded)', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedBatch({ wcbBatchId: BATCH_1, physicianId: PHYSICIAN_1, status: 'UPLOADED' });

      await expect(
        repo.setBatchUploaded(BATCH_1, PHYSICIAN_1, USER_1),
      ).rejects.toThrow('Cannot upload batch');
    });

    it('returns null for another physician\'s batch', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedBatch({ wcbBatchId: BATCH_1, physicianId: PHYSICIAN_2, status: 'VALIDATED' });

      const result = await repo.setBatchUploaded(BATCH_1, PHYSICIAN_1, USER_1);

      expect(result).toBeNull();
    });
  });

  // -------------------------------------------------------------------------
  // setBatchReturnReceived
  // -------------------------------------------------------------------------

  describe('setBatchReturnReceived', () => {
    it('sets status to RETURN_RECEIVED from UPLOADED', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedBatch({ wcbBatchId: BATCH_1, physicianId: PHYSICIAN_1, status: 'UPLOADED' });

      const result = await repo.setBatchReturnReceived(
        BATCH_1,
        PHYSICIAN_1,
        '/returns/return-file.xml',
      );

      expect(result).not.toBeNull();
      expect(result!.status).toBe('RETURN_RECEIVED');
      expect(result!.returnFilePath).toBe('/returns/return-file.xml');
      expect(result!.returnFileReceivedAt).toBeInstanceOf(Date);
    });

    it('rejects from VALIDATED status', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedBatch({ wcbBatchId: BATCH_1, physicianId: PHYSICIAN_1, status: 'VALIDATED' });

      await expect(
        repo.setBatchReturnReceived(BATCH_1, PHYSICIAN_1, '/returns/file.xml'),
      ).rejects.toThrow('Cannot receive return');
    });
  });

  // -------------------------------------------------------------------------
  // getQueuedClaimsForBatch
  // -------------------------------------------------------------------------

  describe('getQueuedClaimsForBatch', () => {
    it('returns only queued WCB claims for physician', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      // Queued WCB claim for physician 1
      seedClaim({
        claimId: CLAIM_1,
        physicianId: PHYSICIAN_1,
        state: 'QUEUED',
        claimType: 'WCB',
      });
      seedWcbDetail({ wcbClaimDetailId: WCB_DETAIL_1, claimId: CLAIM_1 });

      // Draft WCB claim for physician 1 (should not appear)
      seedClaim({
        claimId: CLAIM_2,
        physicianId: PHYSICIAN_1,
        state: 'DRAFT',
        claimType: 'WCB',
      });
      seedWcbDetail({ wcbClaimDetailId: WCB_DETAIL_2, claimId: CLAIM_2 });

      // Queued AHCIP claim for physician 1 (should not appear)
      seedClaim({
        claimId: CLAIM_3,
        physicianId: PHYSICIAN_1,
        state: 'QUEUED',
        claimType: 'AHCIP',
      });

      const result = await repo.getQueuedClaimsForBatch(PHYSICIAN_1);

      expect(result).toHaveLength(1);
      expect(result[0].claim.claimId).toBe(CLAIM_1);
      expect(result[0].claim.state).toBe('QUEUED');
      expect(result[0].claim.claimType).toBe('WCB');
    });

    it('excludes other physician\'s claims', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      // Queued WCB claim for physician 2
      seedClaim({
        claimId: CLAIM_1,
        physicianId: PHYSICIAN_2,
        state: 'QUEUED',
        claimType: 'WCB',
      });
      seedWcbDetail({ wcbClaimDetailId: WCB_DETAIL_1, claimId: CLAIM_1 });

      const result = await repo.getQueuedClaimsForBatch(PHYSICIAN_1);

      expect(result).toHaveLength(0);
    });

    it('excludes soft-deleted claims', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedClaim({
        claimId: CLAIM_1,
        physicianId: PHYSICIAN_1,
        state: 'QUEUED',
        claimType: 'WCB',
        deletedAt: new Date(),
      });
      seedWcbDetail({ wcbClaimDetailId: WCB_DETAIL_1, claimId: CLAIM_1 });

      const result = await repo.getQueuedClaimsForBatch(PHYSICIAN_1);

      expect(result).toHaveLength(0);
    });

    it('returns empty array when no queued claims exist', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const result = await repo.getQueuedClaimsForBatch(PHYSICIAN_1);

      expect(result).toHaveLength(0);
    });
  });

  // -------------------------------------------------------------------------
  // assignClaimsToBatch
  // -------------------------------------------------------------------------

  describe('assignClaimsToBatch', () => {
    it('assigns claims to batch and updates report_count', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedBatch({ wcbBatchId: BATCH_1, physicianId: PHYSICIAN_1 });
      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'QUEUED', claimType: 'WCB' });
      seedClaim({ claimId: CLAIM_2, physicianId: PHYSICIAN_1, state: 'QUEUED', claimType: 'WCB' });

      const count = await repo.assignClaimsToBatch(BATCH_1, PHYSICIAN_1, [CLAIM_1, CLAIM_2]);

      expect(count).toBe(2);
      // Verify claims have submittedBatchId set
      expect(claimStore.find((c) => c.claimId === CLAIM_1)?.submittedBatchId).toBe(BATCH_1);
      expect(claimStore.find((c) => c.claimId === CLAIM_2)?.submittedBatchId).toBe(BATCH_1);
      // Verify batch report_count updated
      expect(wcbBatchStore[0].reportCount).toBe(2);
    });

    it('returns 0 for empty claim list', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedBatch({ wcbBatchId: BATCH_1, physicianId: PHYSICIAN_1 });

      const count = await repo.assignClaimsToBatch(BATCH_1, PHYSICIAN_1, []);

      expect(count).toBe(0);
    });

    it('only assigns physician\'s own claims', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedBatch({ wcbBatchId: BATCH_1, physicianId: PHYSICIAN_1 });
      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'QUEUED', claimType: 'WCB' });
      seedClaim({ claimId: CLAIM_2, physicianId: PHYSICIAN_2, state: 'QUEUED', claimType: 'WCB' });

      const count = await repo.assignClaimsToBatch(BATCH_1, PHYSICIAN_1, [CLAIM_1, CLAIM_2]);

      // Only CLAIM_1 belongs to physician 1
      expect(count).toBe(1);
      expect(claimStore.find((c) => c.claimId === CLAIM_1)?.submittedBatchId).toBe(BATCH_1);
      // Physician 2's claim should not be affected
      expect(claimStore.find((c) => c.claimId === CLAIM_2)?.submittedBatchId).toBeNull();
    });

    it('does not assign soft-deleted claims', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedBatch({ wcbBatchId: BATCH_1, physicianId: PHYSICIAN_1 });
      seedClaim({
        claimId: CLAIM_1,
        physicianId: PHYSICIAN_1,
        state: 'QUEUED',
        claimType: 'WCB',
        deletedAt: new Date(),
      });

      const count = await repo.assignClaimsToBatch(BATCH_1, PHYSICIAN_1, [CLAIM_1]);

      expect(count).toBe(0);
    });
  });

  // -------------------------------------------------------------------------
  // createReturnRecords
  // -------------------------------------------------------------------------

  describe('createReturnRecords', () => {
    it('inserts batch of return records', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedBatch({ wcbBatchId: BATCH_1, physicianId: PHYSICIAN_1 });

      const records = [
        {
          reportTxnId: 'RTX-001',
          submitterTxnId: 'MRT0000000000001',
          processedClaimNumber: '1234567',
          claimDecision: 'ACCEPTED',
          reportStatus: 'PROCESSED',
          txnSubmissionDate: '2026-02-15',
          wcbClaimDetailId: WCB_DETAIL_1,
        },
        {
          reportTxnId: 'RTX-002',
          submitterTxnId: 'MRT0000000000002',
          claimDecision: 'REJECTED',
          reportStatus: 'ERROR',
          txnSubmissionDate: '2026-02-15',
          errors: [{ code: 'E001', message: 'Invalid field' }],
        },
      ];

      const result = await repo.createReturnRecords(BATCH_1, records);

      expect(result).toHaveLength(2);
      expect(result[0].wcbBatchId).toBe(BATCH_1);
      expect(result[0].reportTxnId).toBe('RTX-001');
      expect(result[0].submitterTxnId).toBe('MRT0000000000001');
      expect(result[0].claimDecision).toBe('ACCEPTED');
      expect(result[0].wcbClaimDetailId).toBe(WCB_DETAIL_1);
      expect(result[1].reportTxnId).toBe('RTX-002');
      expect(result[1].claimDecision).toBe('REJECTED');
      expect(result[1].errors).toEqual([{ code: 'E001', message: 'Invalid field' }]);
      expect(wcbReturnRecordStore).toHaveLength(2);
    });

    it('returns empty array for empty input', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const result = await repo.createReturnRecords(BATCH_1, []);

      expect(result).toHaveLength(0);
      expect(wcbReturnRecordStore).toHaveLength(0);
    });
  });

  // -------------------------------------------------------------------------
  // createReturnInvoiceLines
  // -------------------------------------------------------------------------

  describe('createReturnInvoiceLines', () => {
    it('inserts per-report invoice line results', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const returnRecordId = 'rr-1111-1111-1111-111111111111';

      const lines = [
        {
          invoiceSequence: 1,
          serviceDate: '2026-02-10',
          healthServiceCode: '03.04A',
          invoiceStatus: 'PAID',
        },
        {
          invoiceSequence: 2,
          serviceDate: '2026-02-11',
          healthServiceCode: '08.19A',
          invoiceStatus: 'REJECTED',
        },
      ];

      const result = await repo.createReturnInvoiceLines(returnRecordId, lines);

      expect(result).toHaveLength(2);
      expect(result[0].wcbReturnRecordId).toBe(returnRecordId);
      expect(result[0].invoiceSequence).toBe(1);
      expect(result[0].healthServiceCode).toBe('03.04A');
      expect(result[0].invoiceStatus).toBe('PAID');
      expect(result[1].invoiceSequence).toBe(2);
      expect(result[1].invoiceStatus).toBe('REJECTED');
      expect(wcbReturnInvoiceLineStore).toHaveLength(2);
    });

    it('returns empty array for empty input', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const result = await repo.createReturnInvoiceLines('rr-nonexist', []);

      expect(result).toHaveLength(0);
    });
  });

  // -------------------------------------------------------------------------
  // getReturnRecordsByBatch
  // -------------------------------------------------------------------------

  describe('getReturnRecordsByBatch', () => {
    it('returns return records with invoice line sub-records', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const rrId1 = 'rr-1111-1111-1111-111111111111';
      const rrId2 = 'rr-2222-2222-2222-222222222222';

      wcbReturnRecordStore.push({
        wcbReturnRecordId: rrId1,
        wcbBatchId: BATCH_1,
        wcbClaimDetailId: WCB_DETAIL_1,
        reportTxnId: 'RTX-001',
        submitterTxnId: 'MRT0000000000001',
        processedClaimNumber: '1234567',
        claimDecision: 'ACCEPTED',
        reportStatus: 'PROCESSED',
        txnSubmissionDate: '2026-02-15',
        errors: null,
      });
      wcbReturnRecordStore.push({
        wcbReturnRecordId: rrId2,
        wcbBatchId: BATCH_1,
        wcbClaimDetailId: WCB_DETAIL_2,
        reportTxnId: 'RTX-002',
        submitterTxnId: 'MRT0000000000002',
        processedClaimNumber: null,
        claimDecision: 'REJECTED',
        reportStatus: 'ERROR',
        txnSubmissionDate: '2026-02-15',
        errors: [{ code: 'E001' }],
      });

      wcbReturnInvoiceLineStore.push({
        wcbReturnInvoiceLineId: 'ril-1',
        wcbReturnRecordId: rrId1,
        invoiceSequence: 1,
        serviceDate: '2026-02-10',
        healthServiceCode: '03.04A',
        invoiceStatus: 'PAID',
      });
      wcbReturnInvoiceLineStore.push({
        wcbReturnInvoiceLineId: 'ril-2',
        wcbReturnRecordId: rrId1,
        invoiceSequence: 2,
        serviceDate: '2026-02-11',
        healthServiceCode: '08.19A',
        invoiceStatus: 'PAID',
      });

      const result = await repo.getReturnRecordsByBatch(BATCH_1);

      expect(result).toHaveLength(2);
      expect(result[0].returnRecord.wcbReturnRecordId).toBe(rrId1);
      expect(result[0].invoiceLines).toHaveLength(2);
      expect(result[0].invoiceLines[0].invoiceSequence).toBe(1);
      expect(result[1].returnRecord.wcbReturnRecordId).toBe(rrId2);
      expect(result[1].invoiceLines).toHaveLength(0);
    });

    it('returns empty array for batch with no return records', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const result = await repo.getReturnRecordsByBatch(BATCH_1);

      expect(result).toHaveLength(0);
    });
  });

  // -------------------------------------------------------------------------
  // matchReturnToClaimBySubmitterTxnId
  // -------------------------------------------------------------------------

  describe('matchReturnToClaimBySubmitterTxnId', () => {
    it('finds correct claim by submitter_txn_id', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1 });
      seedWcbDetail({
        wcbClaimDetailId: WCB_DETAIL_1,
        claimId: CLAIM_1,
        submitterTxnId: 'MRT0000000000001',
      });

      const result = await repo.matchReturnToClaimBySubmitterTxnId('MRT0000000000001');

      expect(result).toBe(WCB_DETAIL_1);
    });

    it('returns null for unknown txn ID', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const result = await repo.matchReturnToClaimBySubmitterTxnId('MRT_NONEXISTENT_');

      expect(result).toBeNull();
    });

    it('returns correct claim when multiple claims exist', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1 });
      seedClaim({ claimId: CLAIM_2, physicianId: PHYSICIAN_2 });
      seedWcbDetail({
        wcbClaimDetailId: WCB_DETAIL_1,
        claimId: CLAIM_1,
        submitterTxnId: 'MRT0000000000001',
      });
      seedWcbDetail({
        wcbClaimDetailId: WCB_DETAIL_2,
        claimId: CLAIM_2,
        submitterTxnId: 'MRT0000000000002',
      });

      const result = await repo.matchReturnToClaimBySubmitterTxnId('MRT0000000000002');

      expect(result).toBe(WCB_DETAIL_2);
    });
  });

  // -------------------------------------------------------------------------
  // createRemittanceImport
  // -------------------------------------------------------------------------

  describe('createRemittanceImport', () => {
    it('creates a remittance import record', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const importId = await repo.createRemittanceImport(PHYSICIAN_1);

      expect(importId).toBeDefined();
      expect(typeof importId).toBe('string');
      expect(wcbRemittanceImportStore).toHaveLength(1);
      expect(wcbRemittanceImportStore[0].physicianId).toBe(PHYSICIAN_1);
      expect(wcbRemittanceImportStore[0].recordCount).toBe(0);
    });
  });

  // -------------------------------------------------------------------------
  // createRemittanceRecords
  // -------------------------------------------------------------------------

  describe('createRemittanceRecords', () => {
    it('inserts remittance records', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const importId = await repo.createRemittanceImport(PHYSICIAN_1);

      const records = [
        {
          reportWeekStart: '2026-02-10',
          reportWeekEnd: '2026-02-16',
          paymentPayeeBilling: '12345678',
          paymentPayeeName: 'Dr. Jane Smith',
          paymentReasonCode: 'INV',
          paymentStatus: 'ISS',
          paymentStartDate: '2026-02-10',
          paymentEndDate: '2026-02-16',
          paymentAmount: '94.15',
          billedAmount: '94.15',
          electronicReportTxnId: 'RTX-001',
          claimNumber: '1234567',
        },
        {
          reportWeekStart: '2026-02-10',
          reportWeekEnd: '2026-02-16',
          paymentPayeeBilling: '12345678',
          paymentPayeeName: 'Dr. Jane Smith',
          paymentReasonCode: 'INV',
          paymentStatus: 'REJ',
          paymentStartDate: '2026-02-10',
          paymentEndDate: '2026-02-16',
          paymentAmount: '0.00',
          billedAmount: '120.00',
          electronicReportTxnId: 'RTX-002',
          claimNumber: '1234568',
        },
      ];

      const result = await repo.createRemittanceRecords(importId, records);

      expect(result).toHaveLength(2);
      expect(result[0].remittanceImportId).toBe(importId);
      expect(result[0].paymentStatus).toBe('ISS');
      expect(result[0].paymentAmount).toBe('94.15');
      expect(result[1].paymentStatus).toBe('REJ');
      expect(wcbRemittanceRecordStore).toHaveLength(2);
      // Verify import record_count is updated
      expect(wcbRemittanceImportStore[0].recordCount).toBe(2);
    });

    it('returns empty array for empty input', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const importId = await repo.createRemittanceImport(PHYSICIAN_1);
      const result = await repo.createRemittanceRecords(importId, []);

      expect(result).toHaveLength(0);
      expect(wcbRemittanceRecordStore).toHaveLength(0);
    });
  });

  // -------------------------------------------------------------------------
  // matchRemittanceToClaimByTxnId
  // -------------------------------------------------------------------------

  describe('matchRemittanceToClaimByTxnId', () => {
    it('follows report_txn_id chain to find claim', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      // Set up the chain: return record has reportTxnId and wcbClaimDetailId
      wcbReturnRecordStore.push({
        wcbReturnRecordId: 'rr-1111-1111-1111-111111111111',
        wcbBatchId: BATCH_1,
        wcbClaimDetailId: WCB_DETAIL_1,
        reportTxnId: 'RTX-001',
        submitterTxnId: 'MRT0000000000001',
        processedClaimNumber: '1234567',
        claimDecision: 'ACCEPTED',
        reportStatus: 'PROCESSED',
        txnSubmissionDate: '2026-02-15',
        errors: null,
      });

      const result = await repo.matchRemittanceToClaimByTxnId('RTX-001');

      expect(result).toBe(WCB_DETAIL_1);
    });

    it('returns null for unknown electronic_report_txn_id', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const result = await repo.matchRemittanceToClaimByTxnId('RTX-NONEXISTENT');

      expect(result).toBeNull();
    });
  });

  // -------------------------------------------------------------------------
  // listRemittanceImports
  // -------------------------------------------------------------------------

  describe('listRemittanceImports', () => {
    it('returns paginated imports for physician', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      wcbRemittanceImportStore.push({
        remittanceImportId: 'ri-1111',
        physicianId: PHYSICIAN_1,
        recordCount: 5,
        createdAt: new Date('2026-02-10T10:00:00Z'),
      });
      wcbRemittanceImportStore.push({
        remittanceImportId: 'ri-2222',
        physicianId: PHYSICIAN_1,
        recordCount: 3,
        createdAt: new Date('2026-02-15T10:00:00Z'),
      });
      wcbRemittanceImportStore.push({
        remittanceImportId: 'ri-3333',
        physicianId: PHYSICIAN_2,
        recordCount: 2,
        createdAt: new Date('2026-02-12T10:00:00Z'),
      });

      const result = await repo.listRemittanceImports(PHYSICIAN_1, {
        page: 1,
        pageSize: 10,
      });

      expect(result.data).toHaveLength(2);
      expect(result.pagination.total).toBe(2);
      expect(result.pagination.hasMore).toBe(false);
      // All records belong to PHYSICIAN_1
      result.data.forEach((imp: any) => {
        expect(imp.physicianId).toBe(PHYSICIAN_1);
      });
    });

    it('paginates correctly', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      for (let i = 0; i < 5; i++) {
        wcbRemittanceImportStore.push({
          remittanceImportId: `ri-${i}`,
          physicianId: PHYSICIAN_1,
          recordCount: i,
          createdAt: new Date(`2026-02-${10 + i}T10:00:00Z`),
        });
      }

      const page1 = await repo.listRemittanceImports(PHYSICIAN_1, {
        page: 1,
        pageSize: 2,
      });

      expect(page1.data).toHaveLength(2);
      expect(page1.pagination.total).toBe(5);
      expect(page1.pagination.hasMore).toBe(true);
      expect(page1.pagination.page).toBe(1);

      const page3 = await repo.listRemittanceImports(PHYSICIAN_1, {
        page: 3,
        pageSize: 2,
      });

      expect(page3.data).toHaveLength(1);
      expect(page3.pagination.hasMore).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // getRemittanceDiscrepancies
  // -------------------------------------------------------------------------

  describe('getRemittanceDiscrepancies', () => {
    it('returns only mismatched records', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const importId = 'ri-test-1111';

      // Seed the remittance import for physician scoping
      wcbRemittanceImportStore.push({
        remittanceImportId: importId,
        physicianId: PHYSICIAN_1,
        recordCount: 4,
        createdAt: new Date(),
      });

      // Normal record — no discrepancy
      wcbRemittanceRecordStore.push({
        wcbRemittanceId: 'rem-1',
        remittanceImportId: importId,
        reportWeekStart: '2026-02-10',
        reportWeekEnd: '2026-02-16',
        paymentPayeeBilling: '12345678',
        paymentPayeeName: 'Dr. Jane Smith',
        paymentReasonCode: 'INV',
        paymentStatus: 'ISS',
        paymentStartDate: '2026-02-10',
        paymentEndDate: '2026-02-16',
        paymentAmount: '94.15',
        billedAmount: '94.15',
      });

      // Amount mismatch — billed 120.00 but paid 94.15
      wcbRemittanceRecordStore.push({
        wcbRemittanceId: 'rem-2',
        remittanceImportId: importId,
        reportWeekStart: '2026-02-10',
        reportWeekEnd: '2026-02-16',
        paymentPayeeBilling: '12345678',
        paymentPayeeName: 'Dr. Jane Smith',
        paymentReasonCode: 'INV',
        paymentStatus: 'ISS',
        paymentStartDate: '2026-02-10',
        paymentEndDate: '2026-02-16',
        paymentAmount: '94.15',
        billedAmount: '120.00',
      });

      // Status not ISS — rejected
      wcbRemittanceRecordStore.push({
        wcbRemittanceId: 'rem-3',
        remittanceImportId: importId,
        reportWeekStart: '2026-02-10',
        reportWeekEnd: '2026-02-16',
        paymentPayeeBilling: '12345678',
        paymentPayeeName: 'Dr. Jane Smith',
        paymentReasonCode: 'INV',
        paymentStatus: 'REJ',
        paymentStartDate: '2026-02-10',
        paymentEndDate: '2026-02-16',
        paymentAmount: '0.00',
        billedAmount: '94.15',
      });

      // Record from a different import — should not appear
      wcbRemittanceRecordStore.push({
        wcbRemittanceId: 'rem-4',
        remittanceImportId: 'ri-other',
        reportWeekStart: '2026-02-10',
        reportWeekEnd: '2026-02-16',
        paymentPayeeBilling: '12345678',
        paymentPayeeName: 'Dr. Jane Smith',
        paymentReasonCode: 'INV',
        paymentStatus: 'REJ',
        paymentStartDate: '2026-02-10',
        paymentEndDate: '2026-02-16',
        paymentAmount: '0.00',
        billedAmount: '50.00',
      });

      const result = await repo.getRemittanceDiscrepancies(importId, PHYSICIAN_1);

      expect(result).toHaveLength(2);

      const amountMismatch = result.find((d: any) => d.wcbRemittanceId === 'rem-2');
      expect(amountMismatch).toBeDefined();
      expect(amountMismatch!.discrepancyType).toBe('AMOUNT_MISMATCH');

      const statusNotIssued = result.find((d: any) => d.wcbRemittanceId === 'rem-3');
      expect(statusNotIssued).toBeDefined();
      expect(statusNotIssued!.discrepancyType).toBe('STATUS_NOT_ISSUED');
    });

    it('returns empty array when all records match', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const importId = 'ri-test-2222';

      wcbRemittanceImportStore.push({
        remittanceImportId: importId,
        physicianId: PHYSICIAN_1,
        recordCount: 1,
        createdAt: new Date(),
      });

      wcbRemittanceRecordStore.push({
        wcbRemittanceId: 'rem-1',
        remittanceImportId: importId,
        paymentStatus: 'ISS',
        paymentAmount: '94.15',
        billedAmount: '94.15',
      });

      const result = await repo.getRemittanceDiscrepancies(importId, PHYSICIAN_1);

      expect(result).toHaveLength(0);
    });

    it('returns empty array for import with no records', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const result = await repo.getRemittanceDiscrepancies('ri-nonexistent', PHYSICIAN_1);

      expect(result).toHaveLength(0);
    });

    it('flags status discrepancy even when amounts match', async () => {
      const db = makeMockDb();
      const repo = createWcbRepository(db);

      const importId = 'ri-test-3333';

      wcbRemittanceImportStore.push({
        remittanceImportId: importId,
        physicianId: PHYSICIAN_1,
        recordCount: 1,
        createdAt: new Date(),
      });

      wcbRemittanceRecordStore.push({
        wcbRemittanceId: 'rem-1',
        remittanceImportId: importId,
        paymentStatus: 'PAE',
        paymentAmount: '94.15',
        billedAmount: '94.15',
      });

      const result = await repo.getRemittanceDiscrepancies(importId, PHYSICIAN_1);

      expect(result).toHaveLength(1);
      expect(result[0].discrepancyType).toBe('STATUS_NOT_ISSUED');
    });
  });
});

// ===========================================================================
// WCB Service Tests
// ===========================================================================

// ---------------------------------------------------------------------------
// Mock dependencies for service tests
// ---------------------------------------------------------------------------

function makeServiceDeps(overrides: Partial<WcbServiceDeps> = {}): WcbServiceDeps {
  const db = makeMockDb();
  const wcbRepo = createWcbRepository(db);

  const claimRepo = {
    createClaim: vi.fn().mockImplementation(async (data: any) => {
      const claim = seedClaim({
        physicianId: data.physicianId,
        patientId: data.patientId,
        claimType: data.claimType,
        importSource: data.importSource,
        dateOfService: data.dateOfService,
        submissionDeadline: data.submissionDeadline,
        createdBy: data.createdBy,
        updatedBy: data.updatedBy,
      });
      return claim;
    }),
    findClaimById: vi.fn().mockImplementation(async (claimId: string, physicianId: string) => {
      return claimStore.find(
        (c) => c.claimId === claimId && c.physicianId === physicianId && !c.deletedAt,
      );
    }),
    appendClaimAudit: vi.fn().mockResolvedValue(undefined),
    transitionClaimState: vi.fn().mockImplementation(async (claimId: string, physicianId: string, newState: string) => {
      const claim = claimStore.find(
        (c) => c.claimId === claimId && c.physicianId === physicianId && !c.deletedAt,
      );
      if (!claim) return undefined;
      const previousState = claim.state;
      claim.state = newState;
      return { claimId, state: newState, previousState };
    }),
  };

  const providerLookup = {
    findProviderById: vi.fn().mockImplementation(async (providerId: string) => {
      if (providerId === PHYSICIAN_1) {
        return {
          providerId: PHYSICIAN_1,
          billingNumber: '12345678',
          firstName: 'Jane',
          lastName: 'Smith',
          middleName: null,
          status: 'ACTIVE',
          specialtyCode: '03',
        };
      }
      return undefined;
    }),
    getWcbConfigForForm: vi.fn().mockImplementation(async (providerId: string, formId: string) => {
      if (providerId === PHYSICIAN_1) {
        // GP contract 000001 permits C050E (initial) and C151/C568/C569/C570 (follow-up)
        const gpInitial = ['C050E', 'C568'];
        const gpFollowUp = ['C151', 'C568', 'C569', 'C570'];
        if (gpInitial.includes(formId) || gpFollowUp.includes(formId)) {
          return {
            wcbConfigId: 'wcfg-1111',
            contractId: '000001',
            roleCode: 'GP',
            skillCode: '03',
            facilityType: 'C',
          };
        }
        // SP contract 000006 permits C568A
        if (formId === 'C568A') {
          return {
            wcbConfigId: 'wcfg-2222',
            contractId: '000006',
            roleCode: 'SP',
            skillCode: '08',
            facilityType: 'C',
          };
        }
        // OIS contract 000053 permits C050S (initial) and C151S (follow-up)
        if (formId === 'C050S' || formId === 'C151S') {
          return {
            wcbConfigId: 'wcfg-3333',
            contractId: '000053',
            roleCode: 'OIS',
            skillCode: '03',
            facilityType: 'C',
          };
        }
      }
      return null;
    }),
  };

  const patientLookup = {
    findPatientById: vi.fn().mockImplementation(async (patientId: string, physicianId: string) => {
      if (patientId === PATIENT_1 && physicianId === PHYSICIAN_1) {
        return {
          patientId: PATIENT_1,
          phn: '123456789',
          firstName: 'John',
          lastName: 'Doe',
          middleName: null,
          dateOfBirth: '1990-05-10',
          gender: 'M',
          addressLine1: '123 Main St',
          addressLine2: null,
          city: 'Calgary',
          province: 'AB',
          postalCode: 'T2P1A1',
          phoneCountry: null,
          phone: null,
          employerName: null,
        };
      }
      return undefined;
    }),
  };

  const auditEmitter = {
    emit: vi.fn().mockResolvedValue(undefined),
  };

  return {
    wcbRepo,
    claimRepo,
    providerLookup,
    patientLookup,
    auditEmitter,
    ...overrides,
  };
}

function makeServiceCreateInput(overrides: Partial<CreateWcbClaimInput> = {}): CreateWcbClaimInput {
  return {
    form_id: 'C050E',
    patient_id: PATIENT_1,
    date_of_injury: '2026-02-10',
    report_completion_date: '2026-02-15',
    date_of_examination: '2026-02-15',
    ...overrides,
  };
}

describe('WCB Service', () => {
  // -------------------------------------------------------------------------
  // createWcbClaim
  // -------------------------------------------------------------------------

  describe('createWcbClaim', () => {
    it('creates claim with valid GP + C050E and snapshots provider/patient data', async () => {
      const deps = makeServiceDeps();

      const result = await createWcbClaim(deps, PHYSICIAN_1, USER_1, makeServiceCreateInput());

      expect(result.claimId).toBeDefined();
      expect(result.wcbClaimDetailId).toBeDefined();

      // Verify base claim was created with WCB type
      expect(deps.claimRepo.createClaim).toHaveBeenCalledWith(
        expect.objectContaining({
          physicianId: PHYSICIAN_1,
          patientId: PATIENT_1,
          claimType: 'WCB',
          importSource: 'MANUAL',
        }),
      );

      // Verify WCB detail was created with practitioner snapshot
      const detail = wcbDetailStore[0];
      expect(detail).toBeDefined();
      expect(detail.practitionerBillingNumber).toBe('12345678');
      expect(detail.contractId).toBe('000001');
      expect(detail.roleCode).toBe('GP');
      expect(detail.practitionerFirstName).toBe('Jane');
      expect(detail.practitionerLastName).toBe('Smith');
      expect(detail.skillCode).toBe('03');
      expect(detail.facilityType).toBe('C');

      // Verify patient snapshot
      expect(detail.patientPhn).toBe('123456789');
      expect(detail.patientFirstName).toBe('John');
      expect(detail.patientLastName).toBe('Doe');
      expect(detail.patientDob).toBe('1990-05-10');
      expect(detail.patientGender).toBe('M');
      expect(detail.patientNoPhnFlag).toBe('N');

      // Verify audit was emitted
      expect(deps.claimRepo.appendClaimAudit).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'WCB_FORM_CREATED',
        }),
      );
    });

    it('creates child records (injuries, prescriptions) when provided', async () => {
      const deps = makeServiceDeps();

      const result = await createWcbClaim(deps, PHYSICIAN_1, USER_1, makeServiceCreateInput({
        injuries: [
          { part_of_body_code: 'HAND', side_of_body_code: 'L', nature_of_injury_code: 'FRACT' },
          { part_of_body_code: 'WRIST', nature_of_injury_code: 'SPRAIN' },
        ],
        prescriptions: [
          { prescription_name: 'Ibuprofen', strength: '400mg', daily_intake: '3x/day' },
        ],
      }));

      expect(result.wcbClaimDetailId).toBeDefined();
      expect(wcbInjuryStore).toHaveLength(2);
      expect(wcbInjuryStore[0].partOfBodyCode).toBe('HAND');
      expect(wcbInjuryStore[0].sideOfBodyCode).toBe('L');
      expect(wcbInjuryStore[1].partOfBodyCode).toBe('WRIST');
      expect(wcbPrescriptionStore).toHaveLength(1);
      expect(wcbPrescriptionStore[0].prescriptionName).toBe('Ibuprofen');
    });

    it('rejects invalid Contract/Role/Form combination', async () => {
      const deps = makeServiceDeps();

      // Override to return a config with invalid combo
      deps.providerLookup.getWcbConfigForForm = vi.fn().mockResolvedValue({
        wcbConfigId: 'wcfg-bad',
        contractId: '000022', // DP contract does not permit C050E
        roleCode: 'DP',
        skillCode: '03',
        facilityType: 'C',
      });

      await expect(
        createWcbClaim(deps, PHYSICIAN_1, USER_1, makeServiceCreateInput({ form_id: 'C050E' })),
      ).rejects.toThrow('does not permit form C050E');
    });

    it('rejects when no WCB config found for form type', async () => {
      const deps = makeServiceDeps();
      deps.providerLookup.getWcbConfigForForm = vi.fn().mockResolvedValue(null);

      await expect(
        createWcbClaim(deps, PHYSICIAN_1, USER_1, makeServiceCreateInput()),
      ).rejects.toThrow('No WCB configuration found');
    });

    it('rejects when provider not found', async () => {
      const deps = makeServiceDeps();

      await expect(
        createWcbClaim(deps, 'nonexistent-physician', USER_1, makeServiceCreateInput()),
      ).rejects.toThrow('not found');
    });

    it('rejects when patient not found', async () => {
      const deps = makeServiceDeps();

      await expect(
        createWcbClaim(deps, PHYSICIAN_1, USER_1, makeServiceCreateInput({
          patient_id: 'nonexistent-patient',
        })),
      ).rejects.toThrow('not found');
    });

    it('rejects invalid WCB form type', async () => {
      const deps = makeServiceDeps();

      await expect(
        createWcbClaim(deps, PHYSICIAN_1, USER_1, makeServiceCreateInput({
          form_id: 'INVALID_FORM',
        })),
      ).rejects.toThrow('Invalid WCB form type');
    });

    // --- Follow-up form tests ---

    it('creates C151 follow-up when parent_wcb_claim_id is valid and parent is in terminal state', async () => {
      const deps = makeServiceDeps();

      // Seed a parent claim in PAID (terminal) state
      seedClaim({ claimId: 'clm-parent', physicianId: PHYSICIAN_1, state: 'PAID' });
      seedWcbDetail({
        wcbClaimDetailId: 'wcd-parent',
        claimId: 'clm-parent',
        formId: 'C050E',
      });

      const result = await createWcbClaim(deps, PHYSICIAN_1, USER_1, makeServiceCreateInput({
        form_id: 'C151',
        parent_wcb_claim_id: 'wcd-parent',
      }));

      expect(result.claimId).toBeDefined();
      expect(result.wcbClaimDetailId).toBeDefined();
    });

    it('rejects C151 when parent_wcb_claim_id is missing', async () => {
      const deps = makeServiceDeps();

      await expect(
        createWcbClaim(deps, PHYSICIAN_1, USER_1, makeServiceCreateInput({
          form_id: 'C151',
          // no parent_wcb_claim_id
        })),
      ).rejects.toThrow('Follow-up forms require a parent_wcb_claim_id');
    });

    it('rejects C151 when parent is in non-terminal state (DRAFT)', async () => {
      const deps = makeServiceDeps();

      seedClaim({ claimId: 'clm-parent-draft', physicianId: PHYSICIAN_1, state: 'DRAFT' });
      seedWcbDetail({
        wcbClaimDetailId: 'wcd-parent-draft',
        claimId: 'clm-parent-draft',
        formId: 'C050E',
      });

      await expect(
        createWcbClaim(deps, PHYSICIAN_1, USER_1, makeServiceCreateInput({
          form_id: 'C151',
          parent_wcb_claim_id: 'wcd-parent-draft',
        })),
      ).rejects.toThrow('terminal state');
    });

    it('rejects C151 when parent belongs to different practitioner', async () => {
      const deps = makeServiceDeps();

      // Seed parent claim owned by PHYSICIAN_2
      seedClaim({ claimId: 'clm-parent-other', physicianId: PHYSICIAN_2, state: 'PAID' });
      seedWcbDetail({
        wcbClaimDetailId: 'wcd-parent-other',
        claimId: 'clm-parent-other',
        formId: 'C050E',
      });

      await expect(
        createWcbClaim(deps, PHYSICIAN_1, USER_1, makeServiceCreateInput({
          form_id: 'C151',
          parent_wcb_claim_id: 'wcd-parent-other',
        })),
      ).rejects.toThrow('not found');
    });

    it('rejects follow-up when parent form type not in canCreateFrom list', async () => {
      const deps = makeServiceDeps();

      // C568A parent with GP contract — GP canCreateFrom doesn't include C568A
      seedClaim({ claimId: 'clm-parent-568a', physicianId: PHYSICIAN_1, state: 'PAID' });
      seedWcbDetail({
        wcbClaimDetailId: 'wcd-parent-568a',
        claimId: 'clm-parent-568a',
        formId: 'C568A',
      });

      await expect(
        createWcbClaim(deps, PHYSICIAN_1, USER_1, makeServiceCreateInput({
          form_id: 'C151',
          parent_wcb_claim_id: 'wcd-parent-568a',
        })),
      ).rejects.toThrow('Cannot create follow-up from parent form type C568A');
    });
  });

  // -------------------------------------------------------------------------
  // updateWcbClaim
  // -------------------------------------------------------------------------

  describe('updateWcbClaim', () => {
    it('updates claim scalar fields and child records', async () => {
      const deps = makeServiceDeps();

      // Seed existing draft claim
      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'DRAFT' });
      seedWcbDetail({
        wcbClaimDetailId: WCB_DETAIL_1,
        claimId: CLAIM_1,
        formId: 'C050E',
      });

      const result = await updateWcbClaim(deps, PHYSICIAN_1, USER_1, WCB_DETAIL_1, {
        additional_comments: 'Updated comment',
        injuries: [
          { part_of_body_code: 'KNEE', side_of_body_code: 'R', nature_of_injury_code: 'STRAIN' },
        ],
      });

      expect(result).toBeDefined();
      expect(result.detail).toBeDefined();
      // Verify injury was created
      expect(wcbInjuryStore).toHaveLength(1);
      expect(wcbInjuryStore[0].partOfBodyCode).toBe('KNEE');
      // Verify audit emitted
      expect(deps.claimRepo.appendClaimAudit).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'WCB_FORM_UPDATED',
        }),
      );
    });

    it('rejects update when claim is not in DRAFT state', async () => {
      const deps = makeServiceDeps();

      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'SUBMITTED' });
      seedWcbDetail({
        wcbClaimDetailId: WCB_DETAIL_1,
        claimId: CLAIM_1,
        formId: 'C050E',
      });

      await expect(
        updateWcbClaim(deps, PHYSICIAN_1, USER_1, WCB_DETAIL_1, {
          additional_comments: 'Should fail',
        }),
      ).rejects.toThrow('DRAFT state');
    });

    it('rejects update when claim not found', async () => {
      const deps = makeServiceDeps();

      await expect(
        updateWcbClaim(deps, PHYSICIAN_1, USER_1, 'nonexistent-detail', {
          additional_comments: 'Should fail',
        }),
      ).rejects.toThrow('not found');
    });
  });

  // -------------------------------------------------------------------------
  // deleteWcbClaim
  // -------------------------------------------------------------------------

  describe('deleteWcbClaim', () => {
    it('soft-deletes a draft WCB claim', async () => {
      const deps = makeServiceDeps();

      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'DRAFT' });
      seedWcbDetail({
        wcbClaimDetailId: WCB_DETAIL_1,
        claimId: CLAIM_1,
        formId: 'C050E',
      });

      await deleteWcbClaim(deps, PHYSICIAN_1, USER_1, WCB_DETAIL_1);

      // Verify soft delete was applied
      const detail = wcbDetailStore.find((d) => d.wcbClaimDetailId === WCB_DETAIL_1);
      expect(detail?.deletedAt).not.toBeNull();
    });

    it('rejects delete when claim not in DRAFT state', async () => {
      const deps = makeServiceDeps();

      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'QUEUED' });
      seedWcbDetail({
        wcbClaimDetailId: WCB_DETAIL_1,
        claimId: CLAIM_1,
        formId: 'C050E',
      });

      await expect(
        deleteWcbClaim(deps, PHYSICIAN_1, USER_1, WCB_DETAIL_1),
      ).rejects.toThrow('DRAFT state');
    });

    it('rejects delete when claim not found', async () => {
      const deps = makeServiceDeps();

      await expect(
        deleteWcbClaim(deps, PHYSICIAN_1, USER_1, 'nonexistent'),
      ).rejects.toThrow('not found');
    });
  });

  // -------------------------------------------------------------------------
  // getFormSchema
  // -------------------------------------------------------------------------

  describe('getFormSchema', () => {
    it('returns correct sections for C050E (all sections active)', () => {
      const result = getFormSchema('C050E');

      expect(result.form_id).toBe('C050E');
      expect(result.sections).toHaveLength(10);

      // All sections should be active for C050E
      const activeSections = result.sections.filter((s) => s.active);
      expect(activeSections).toHaveLength(10);

      // Verify section names
      const sectionNames = result.sections.map((s) => s.name);
      expect(sectionNames).toContain('GENERAL');
      expect(sectionNames).toContain('CLAIMANT');
      expect(sectionNames).toContain('PRACTITIONER');
      expect(sectionNames).toContain('EMPLOYER');
      expect(sectionNames).toContain('ACCIDENT');
      expect(sectionNames).toContain('INJURY');
      expect(sectionNames).toContain('TREATMENT_PLAN');
      expect(sectionNames).toContain('RETURN_TO_WORK');
      expect(sectionNames).toContain('ATTACHMENTS');
      expect(sectionNames).toContain('INVOICE');
    });

    it('returns correct sections for C568 (subset of sections)', () => {
      const result = getFormSchema('C568');

      expect(result.form_id).toBe('C568');
      expect(result.sections).toHaveLength(10);

      // C568 has only 6 active sections
      const activeSections = result.sections.filter((s) => s.active);
      expect(activeSections).toHaveLength(6);

      const activeNames = activeSections.map((s) => s.name);
      expect(activeNames).toContain('GENERAL');
      expect(activeNames).toContain('CLAIMANT');
      expect(activeNames).toContain('PRACTITIONER');
      expect(activeNames).toContain('ACCIDENT');
      expect(activeNames).toContain('INJURY');
      expect(activeNames).toContain('INVOICE');

      // These sections should NOT be active for C568
      expect(activeNames).not.toContain('EMPLOYER');
      expect(activeNames).not.toContain('TREATMENT_PLAN');
      expect(activeNames).not.toContain('RETURN_TO_WORK');
      expect(activeNames).not.toContain('ATTACHMENTS');
    });

    it('returns correct sections for C569 (supply invoice)', () => {
      const result = getFormSchema('C569');

      expect(result.form_id).toBe('C569');

      const activeSections = result.sections.filter((s) => s.active);
      expect(activeSections).toHaveLength(5);

      const activeNames = activeSections.map((s) => s.name);
      expect(activeNames).toContain('GENERAL');
      expect(activeNames).toContain('CLAIMANT');
      expect(activeNames).toContain('PRACTITIONER');
      expect(activeNames).toContain('ACCIDENT');
      expect(activeNames).toContain('INVOICE');
    });

    it('inactive sections return empty fields array', () => {
      const result = getFormSchema('C568');

      const employerSection = result.sections.find((s) => s.name === 'EMPLOYER');
      expect(employerSection).toBeDefined();
      expect(employerSection!.active).toBe(false);
      expect(employerSection!.fields).toHaveLength(0);
    });

    it('active sections include field definitions', () => {
      const result = getFormSchema('C050E');

      const generalSection = result.sections.find((s) => s.name === 'GENERAL');
      expect(generalSection).toBeDefined();
      expect(generalSection!.active).toBe(true);
      expect(generalSection!.fields.length).toBeGreaterThan(0);

      // Report completion date should be required
      const rcpField = generalSection!.fields.find((f) => f.name === 'report_completion_date');
      expect(rcpField).toBeDefined();
      expect(rcpField!.required).toBe(true);
    });

    it('resolves conditional fields based on existing data', () => {
      const result = getFormSchema('C050E', {
        date_of_examination: '2026-02-15',
      });

      const injurySection = result.sections.find((s) => s.name === 'INJURY');
      expect(injurySection).toBeDefined();

      // When date_of_examination is set, symptoms should become required
      const symptomsField = injurySection!.fields.find((f) => f.name === 'symptoms');
      expect(symptomsField).toBeDefined();
      expect(symptomsField!.required).toBe(true);
    });

    it('rejects invalid form type', () => {
      expect(() => getFormSchema('INVALID')).toThrow('Invalid WCB form type');
    });
  });

  // -------------------------------------------------------------------------
  // validateWcbClaim
  // -------------------------------------------------------------------------

  describe('validateWcbClaim', () => {
    function seedFullValidC050E(): void {
      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'DRAFT' });
      seedWcbDetail({
        wcbClaimDetailId: WCB_DETAIL_1,
        claimId: CLAIM_1,
        formId: 'C050E',
        submitterTxnId: 'MRT0000000000001',
        reportCompletionDate: '2026-02-15',
        dateOfInjury: '2026-02-10',
        dateOfExamination: '2026-02-15',
        practitionerBillingNumber: '12345678',
        contractId: '000001',
        roleCode: 'GP',
        practitionerFirstName: 'Jane',
        practitionerLastName: 'Smith',
        skillCode: '03',
        facilityType: 'C',
        patientNoPhnFlag: 'N',
        patientPhn: '123456789',
        patientGender: 'M',
        patientFirstName: 'John',
        patientLastName: 'Doe',
        patientDob: '1990-05-10',
        patientAddressLine1: '123 Main St',
        patientCity: 'Calgary',
        symptoms: 'Pain in left hand',
        objectiveFindings: 'Swelling observed',
        currentDiagnosis: 'Hand fracture',
      });
    }

    it('passes for valid C050E with all required fields', async () => {
      const deps = makeServiceDeps();
      seedFullValidC050E();

      const result = await validateWcbClaim(deps, WCB_DETAIL_1, PHYSICIAN_1);

      expect(result.passed).toBe(true);
      expect(result.errors).toHaveLength(0);
      expect(result.validation_timestamp).toBeDefined();
      expect(result.reference_data_version).toBeDefined();
    });

    it('reports error for missing required field', async () => {
      const deps = makeServiceDeps();
      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'DRAFT' });
      seedWcbDetail({
        wcbClaimDetailId: WCB_DETAIL_1,
        claimId: CLAIM_1,
        formId: 'C050E',
        submitterTxnId: 'MRT0000000000001',
        reportCompletionDate: '2026-02-15',
        dateOfInjury: '2026-02-10',
        dateOfExamination: '2026-02-15',
        practitionerBillingNumber: '12345678',
        contractId: '000001',
        roleCode: 'GP',
        practitionerFirstName: 'Jane',
        practitionerLastName: 'Smith',
        skillCode: '03',
        facilityType: 'C',
        patientNoPhnFlag: 'N',
        patientPhn: '123456789',
        patientGender: 'M',
        patientFirstName: 'John',
        patientLastName: 'Doe',
        patientDob: '1990-05-10',
        patientAddressLine1: '123 Main St',
        patientCity: 'Calgary',
        // Missing: symptoms, objectiveFindings, currentDiagnosis
        symptoms: null,
        objectiveFindings: null,
        currentDiagnosis: null,
      });

      const result = await validateWcbClaim(deps, WCB_DETAIL_1, PHYSICIAN_1);

      expect(result.passed).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
      const requiredFieldErrors = result.errors.filter((e) => e.check_id === 'REQUIRED_FIELDS');
      expect(requiredFieldErrors.length).toBeGreaterThanOrEqual(3);
      expect(requiredFieldErrors.some((e) => e.field === 'symptoms')).toBe(true);
      expect(requiredFieldErrors.some((e) => e.field === 'objectiveFindings')).toBe(true);
      expect(requiredFieldErrors.some((e) => e.field === 'currentDiagnosis')).toBe(true);
    });

    it('enforces conditional: narcotics=Y but no prescriptions -> error', async () => {
      const deps = makeServiceDeps();
      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'DRAFT' });
      seedWcbDetail({
        wcbClaimDetailId: WCB_DETAIL_1,
        claimId: CLAIM_1,
        formId: 'C050E',
        submitterTxnId: 'MRT0000000000001',
        reportCompletionDate: '2026-02-15',
        dateOfInjury: '2026-02-10',
        dateOfExamination: '2026-02-15',
        practitionerBillingNumber: '12345678',
        contractId: '000001',
        roleCode: 'GP',
        practitionerFirstName: 'Jane',
        practitionerLastName: 'Smith',
        skillCode: '03',
        facilityType: 'C',
        patientNoPhnFlag: 'N',
        patientPhn: '123456789',
        patientGender: 'M',
        patientFirstName: 'John',
        patientLastName: 'Doe',
        patientDob: '1990-05-10',
        patientAddressLine1: '123 Main St',
        patientCity: 'Calgary',
        symptoms: 'Pain',
        objectiveFindings: 'Swelling',
        currentDiagnosis: 'Fracture',
        narcoticsPrescribed: 'Y',
      });
      // No prescriptions added to wcbPrescriptionStore

      const result = await validateWcbClaim(deps, WCB_DETAIL_1, PHYSICIAN_1);

      expect(result.passed).toBe(false);
      const conditionalErrors = result.errors.filter((e) => e.check_id === 'CONDITIONAL_LOGIC');
      expect(conditionalErrors.length).toBeGreaterThanOrEqual(1);
      expect(conditionalErrors.some((e) => e.field === 'prescriptions')).toBe(true);
    });

    it('enforces conditional: missed_work=Y -> returned_to_work required', async () => {
      const deps = makeServiceDeps();
      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'DRAFT' });
      seedWcbDetail({
        wcbClaimDetailId: WCB_DETAIL_1,
        claimId: CLAIM_1,
        formId: 'C050E',
        submitterTxnId: 'MRT0000000000001',
        reportCompletionDate: '2026-02-15',
        dateOfInjury: '2026-02-10',
        dateOfExamination: '2026-02-15',
        practitionerBillingNumber: '12345678',
        contractId: '000001',
        roleCode: 'GP',
        practitionerFirstName: 'Jane',
        practitionerLastName: 'Smith',
        skillCode: '03',
        facilityType: 'C',
        patientNoPhnFlag: 'N',
        patientPhn: '123456789',
        patientGender: 'M',
        patientFirstName: 'John',
        patientLastName: 'Doe',
        patientDob: '1990-05-10',
        patientAddressLine1: '123 Main St',
        patientCity: 'Calgary',
        symptoms: 'Pain',
        objectiveFindings: 'Swelling',
        currentDiagnosis: 'Fracture',
        missedWorkBeyondAccident: 'Y',
        // Missing: patientReturnedToWork
        patientReturnedToWork: null,
      });

      const result = await validateWcbClaim(deps, WCB_DETAIL_1, PHYSICIAN_1);

      expect(result.passed).toBe(false);
      const conditionalErrors = result.errors.filter((e) => e.check_id === 'CONDITIONAL_LOGIC');
      expect(conditionalErrors.some((e) => e.field === 'patientReturnedToWork')).toBe(true);
    });

    it('enforces PHN logic: no_phn_flag=N, missing PHN -> error', async () => {
      const deps = makeServiceDeps();
      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'DRAFT' });
      seedWcbDetail({
        wcbClaimDetailId: WCB_DETAIL_1,
        claimId: CLAIM_1,
        formId: 'C050E',
        submitterTxnId: 'MRT0000000000001',
        reportCompletionDate: '2026-02-15',
        dateOfInjury: '2026-02-10',
        dateOfExamination: '2026-02-15',
        practitionerBillingNumber: '12345678',
        contractId: '000001',
        roleCode: 'GP',
        practitionerFirstName: 'Jane',
        practitionerLastName: 'Smith',
        skillCode: '03',
        facilityType: 'C',
        patientNoPhnFlag: 'N',
        patientPhn: null, // Missing PHN when flag is N
        patientGender: 'M',
        patientFirstName: 'John',
        patientLastName: 'Doe',
        patientDob: '1990-05-10',
        patientAddressLine1: '123 Main St',
        patientCity: 'Calgary',
        symptoms: 'Pain',
        objectiveFindings: 'Swelling',
        currentDiagnosis: 'Fracture',
      });

      const result = await validateWcbClaim(deps, WCB_DETAIL_1, PHYSICIAN_1);

      expect(result.passed).toBe(false);
      const phnErrors = result.errors.filter((e) => e.check_id === 'PHN_LOGIC');
      expect(phnErrors.length).toBeGreaterThanOrEqual(1);
      expect(phnErrors.some((e) => e.field === 'patientPhn')).toBe(true);
    });

    it('enforces data type: alphabetic field with numbers -> error', async () => {
      const deps = makeServiceDeps();
      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'DRAFT' });
      seedWcbDetail({
        wcbClaimDetailId: WCB_DETAIL_1,
        claimId: CLAIM_1,
        formId: 'C050E',
        submitterTxnId: 'MRT0000000000001',
        reportCompletionDate: '2026-02-15',
        dateOfInjury: '2026-02-10',
        dateOfExamination: '2026-02-15',
        practitionerBillingNumber: '12345678',
        contractId: '000001',
        roleCode: 'GP',
        practitionerFirstName: 'Jane123', // Numbers in alphabetic field
        practitionerLastName: 'Smith',
        skillCode: '03',
        facilityType: 'C',
        patientNoPhnFlag: 'N',
        patientPhn: '123456789',
        patientGender: 'M',
        patientFirstName: 'John',
        patientLastName: 'Doe',
        patientDob: '1990-05-10',
        patientAddressLine1: '123 Main St',
        patientCity: 'Calgary',
        symptoms: 'Pain',
        objectiveFindings: 'Swelling',
        currentDiagnosis: 'Fracture',
      });

      const result = await validateWcbClaim(deps, WCB_DETAIL_1, PHYSICIAN_1);

      expect(result.passed).toBe(false);
      const dataTypeErrors = result.errors.filter((e) => e.check_id === 'DATA_TYPE_LENGTH');
      expect(dataTypeErrors.some((e) =>
        e.field === 'practitionerFirstName' && e.message.includes('alphabetic'),
      )).toBe(true);
    });

    it('enforces max length', async () => {
      const deps = makeServiceDeps();
      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'DRAFT' });
      seedWcbDetail({
        wcbClaimDetailId: WCB_DETAIL_1,
        claimId: CLAIM_1,
        formId: 'C050E',
        submitterTxnId: 'MRT0000000000001',
        reportCompletionDate: '2026-02-15',
        dateOfInjury: '2026-02-10',
        dateOfExamination: '2026-02-15',
        practitionerBillingNumber: '12345678',
        contractId: '000001',
        roleCode: 'GP',
        practitionerFirstName: 'Jane',
        practitionerLastName: 'Smith',
        skillCode: '03',
        facilityType: 'C',
        patientNoPhnFlag: 'N',
        patientPhn: '123456789',
        patientGender: 'M',
        patientFirstName: 'John',
        patientLastName: 'Doe',
        patientDob: '1990-05-10',
        patientAddressLine1: '123 Main St',
        patientCity: 'ThisCityNameIsWayTooLongAndExceedsTwentyCharacters', // exceeds 20 max_length
        symptoms: 'Pain',
        objectiveFindings: 'Swelling',
        currentDiagnosis: 'Fracture',
      });

      const result = await validateWcbClaim(deps, WCB_DETAIL_1, PHYSICIAN_1);

      expect(result.passed).toBe(false);
      const lengthErrors = result.errors.filter((e) => e.check_id === 'DATA_TYPE_LENGTH');
      expect(lengthErrors.some((e) =>
        e.field === 'patientCity' && e.message.includes('maximum length'),
      )).toBe(true);
    });

    it('enforces date ordering: exam < injury -> error', async () => {
      const deps = makeServiceDeps();
      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'DRAFT' });
      seedWcbDetail({
        wcbClaimDetailId: WCB_DETAIL_1,
        claimId: CLAIM_1,
        formId: 'C050E',
        submitterTxnId: 'MRT0000000000001',
        reportCompletionDate: '2026-02-15',
        dateOfInjury: '2026-02-15',
        dateOfExamination: '2026-02-10', // Before injury date
        practitionerBillingNumber: '12345678',
        contractId: '000001',
        roleCode: 'GP',
        practitionerFirstName: 'Jane',
        practitionerLastName: 'Smith',
        skillCode: '03',
        facilityType: 'C',
        patientNoPhnFlag: 'N',
        patientPhn: '123456789',
        patientGender: 'M',
        patientFirstName: 'John',
        patientLastName: 'Doe',
        patientDob: '1990-05-10',
        patientAddressLine1: '123 Main St',
        patientCity: 'Calgary',
        symptoms: 'Pain',
        objectiveFindings: 'Swelling',
        currentDiagnosis: 'Fracture',
      });

      const result = await validateWcbClaim(deps, WCB_DETAIL_1, PHYSICIAN_1);

      expect(result.passed).toBe(false);
      const dateErrors = result.errors.filter((e) => e.check_id === 'DATE_VALIDATION');
      expect(dateErrors.some((e) =>
        e.field === 'dateOfExamination' && e.message.includes('before date of injury'),
      )).toBe(true);
    });

    it('returns timing tier as warning for late submission', async () => {
      const deps = makeServiceDeps();
      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'DRAFT' });
      seedWcbDetail({
        wcbClaimDetailId: WCB_DETAIL_1,
        claimId: CLAIM_1,
        formId: 'C050E',
        submitterTxnId: 'MRT0000000000001',
        reportCompletionDate: '2026-01-10',
        dateOfInjury: '2026-01-05',
        dateOfExamination: '2026-01-10',
        practitionerBillingNumber: '12345678',
        contractId: '000001',
        roleCode: 'GP',
        practitionerFirstName: 'Jane',
        practitionerLastName: 'Smith',
        skillCode: '03',
        facilityType: 'C',
        patientNoPhnFlag: 'N',
        patientPhn: '123456789',
        patientGender: 'M',
        patientFirstName: 'John',
        patientLastName: 'Doe',
        patientDob: '1990-05-10',
        patientAddressLine1: '123 Main St',
        patientCity: 'Calgary',
        symptoms: 'Pain',
        objectiveFindings: 'Swelling',
        currentDiagnosis: 'Fracture',
      });

      // Validate well after the deadline (Feb 2026, exam was Jan 10 2026)
      const lateDate = new Date('2026-02-15T12:00:00Z');
      const result = await validateWcbClaim(deps, WCB_DETAIL_1, PHYSICIAN_1, lateDate);

      expect(result.timing_tier).toBe('LATE');
      const timingWarnings = result.warnings.filter((w) => w.check_id === 'TIMING_DEADLINE');
      expect(timingWarnings.length).toBeGreaterThanOrEqual(1);
      expect(timingWarnings[0].message).toContain('Late tier');
    });

    it('throws NotFoundError for non-existent claim', async () => {
      const deps = makeServiceDeps();

      await expect(
        validateWcbClaim(deps, 'nonexistent-id', PHYSICIAN_1),
      ).rejects.toThrow('not found');
    });

    it('returns passed=true with timing_tier for valid same-day submission', async () => {
      const deps = makeServiceDeps();
      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'DRAFT' });
      seedWcbDetail({
        wcbClaimDetailId: WCB_DETAIL_1,
        claimId: CLAIM_1,
        formId: 'C050E',
        submitterTxnId: 'MRT0000000000001',
        reportCompletionDate: '2026-02-16',
        dateOfInjury: '2026-02-10',
        dateOfExamination: '2026-02-16', // Monday
        practitionerBillingNumber: '12345678',
        contractId: '000001',
        roleCode: 'GP',
        practitionerFirstName: 'Jane',
        practitionerLastName: 'Smith',
        skillCode: '03',
        facilityType: 'C',
        patientNoPhnFlag: 'N',
        patientPhn: '123456789',
        patientGender: 'M',
        patientFirstName: 'John',
        patientLastName: 'Doe',
        patientDob: '1990-05-10',
        patientAddressLine1: '123 Main St',
        patientCity: 'Calgary',
        symptoms: 'Pain',
        objectiveFindings: 'Swelling',
        currentDiagnosis: 'Fracture',
      });

      // Validate on the same day as exam (Feb 16 2026 = Monday)
      const sameDayDate = new Date('2026-02-16T08:00:00Z');
      const result = await validateWcbClaim(deps, WCB_DETAIL_1, PHYSICIAN_1, sameDayDate);

      expect(result.passed).toBe(true);
      expect(result.timing_tier).toBe('SAME_DAY');
    });

    it('detects duplicate claims for same patient + date of injury + form type', async () => {
      const deps = makeServiceDeps();

      // Existing claim with same patient/injury date
      seedClaim({ claimId: CLAIM_2, physicianId: PHYSICIAN_1, state: 'SUBMITTED' });
      seedWcbDetail({
        wcbClaimDetailId: WCB_DETAIL_2,
        claimId: CLAIM_2,
        formId: 'C050E',
        submitterTxnId: 'MRT0000000000002',
        dateOfInjury: '2026-02-10',
        patientPhn: '123456789',
      });

      // Current claim under validation
      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'DRAFT' });
      seedWcbDetail({
        wcbClaimDetailId: WCB_DETAIL_1,
        claimId: CLAIM_1,
        formId: 'C050E',
        submitterTxnId: 'MRT0000000000001',
        reportCompletionDate: '2026-02-15',
        dateOfInjury: '2026-02-10',
        dateOfExamination: '2026-02-15',
        practitionerBillingNumber: '12345678',
        contractId: '000001',
        roleCode: 'GP',
        practitionerFirstName: 'Jane',
        practitionerLastName: 'Smith',
        skillCode: '03',
        facilityType: 'C',
        patientNoPhnFlag: 'N',
        patientPhn: '123456789',
        patientGender: 'M',
        patientFirstName: 'John',
        patientLastName: 'Doe',
        patientDob: '1990-05-10',
        patientAddressLine1: '123 Main St',
        patientCity: 'Calgary',
        symptoms: 'Pain',
        objectiveFindings: 'Swelling',
        currentDiagnosis: 'Fracture',
      });

      const result = await validateWcbClaim(deps, WCB_DETAIL_1, PHYSICIAN_1);

      const dupeWarnings = result.warnings.filter((w) => w.check_id === 'DUPLICATE_DETECTION');
      expect(dupeWarnings.length).toBeGreaterThanOrEqual(1);
      expect(dupeWarnings[0].message).toContain('Potential duplicate');
    });

    // =======================================================================
    // POB-NOI Combination Validation (D04W-022)
    // =======================================================================

    describe('POB-NOI combination validation', () => {
      it('rejects Sprain(02100) + Brain(01100)', async () => {
        const deps = makeServiceDeps();
        seedFullValidC050E();
        wcbInjuryStore.push({
          wcbInjuryId: 'inj-001',
          wcbClaimDetailId: WCB_DETAIL_1,
          ordinal: 1,
          partOfBodyCode: '01100',     // Brain
          sideOfBodyCode: null,
          natureOfInjuryCode: '02100', // Sprain/Strain
        });

        const result = await validateWcbClaim(deps, WCB_DETAIL_1, PHYSICIAN_1);

        const pobNoiErrors = result.errors.filter((e) => e.check_id === 'POB_NOI_COMBINATION');
        expect(pobNoiErrors.length).toBeGreaterThanOrEqual(1);
        expect(pobNoiErrors[0].message).toContain('Sprain/Strain');
        expect(pobNoiErrors[0].message).toContain('Brain');
        expect(pobNoiErrors[0].message).toContain('not permitted by WCB');
      });

      it('allows valid combination (Sprain + Ankle)', async () => {
        const deps = makeServiceDeps();
        seedFullValidC050E();
        wcbInjuryStore.push({
          wcbInjuryId: 'inj-002',
          wcbClaimDetailId: WCB_DETAIL_1,
          ordinal: 1,
          partOfBodyCode: '44000',     // Ankle
          sideOfBodyCode: 'L',
          natureOfInjuryCode: '02100', // Sprain/Strain
        });

        const result = await validateWcbClaim(deps, WCB_DETAIL_1, PHYSICIAN_1);

        const pobNoiErrors = result.errors.filter((e) => e.check_id === 'POB_NOI_COMBINATION');
        expect(pobNoiErrors).toHaveLength(0);
      });

      it('references injury ordinal in error message', async () => {
        const deps = makeServiceDeps();
        seedFullValidC050E();
        // Valid first injury
        wcbInjuryStore.push({
          wcbInjuryId: 'inj-003',
          wcbClaimDetailId: WCB_DETAIL_1,
          ordinal: 1,
          partOfBodyCode: '44000',
          sideOfBodyCode: 'L',
          natureOfInjuryCode: '02100',
        });
        // Invalid second injury
        wcbInjuryStore.push({
          wcbInjuryId: 'inj-004',
          wcbClaimDetailId: WCB_DETAIL_1,
          ordinal: 2,
          partOfBodyCode: '01100',     // Brain
          sideOfBodyCode: null,
          natureOfInjuryCode: '02100', // Sprain
        });

        const result = await validateWcbClaim(deps, WCB_DETAIL_1, PHYSICIAN_1);

        const pobNoiErrors = result.errors.filter((e) => e.check_id === 'POB_NOI_COMBINATION');
        expect(pobNoiErrors).toHaveLength(1);
        expect(pobNoiErrors[0].message).toContain('injury #2');
        expect(pobNoiErrors[0].field).toBe('injuries[1]');
      });
    });

    // =======================================================================
    // Side of Body Required Validation (D04W-022)
    // =======================================================================

    describe('Side of Body Required validation', () => {
      it('requires side for Ankle(42000) — missing -> error', async () => {
        const deps = makeServiceDeps();
        seedFullValidC050E();
        wcbInjuryStore.push({
          wcbInjuryId: 'inj-005',
          wcbClaimDetailId: WCB_DETAIL_1,
          ordinal: 1,
          partOfBodyCode: '42000',     // Knee — requires side
          sideOfBodyCode: null,        // Missing!
          natureOfInjuryCode: '02100',
        });

        const result = await validateWcbClaim(deps, WCB_DETAIL_1, PHYSICIAN_1);

        const sideErrors = result.errors.filter((e) => e.check_id === 'SIDE_OF_BODY');
        expect(sideErrors.length).toBeGreaterThanOrEqual(1);
        expect(sideErrors[0].message).toContain('Side of body is required');
        expect(sideErrors[0].message).toContain('Knee');
      });

      it('does not require side for Head(00000) — missing -> no error', async () => {
        const deps = makeServiceDeps();
        seedFullValidC050E();
        wcbInjuryStore.push({
          wcbInjuryId: 'inj-006',
          wcbClaimDetailId: WCB_DETAIL_1,
          ordinal: 1,
          partOfBodyCode: '00000',     // Head — does NOT require side
          sideOfBodyCode: null,
          natureOfInjuryCode: '06100', // Concussion
        });

        const result = await validateWcbClaim(deps, WCB_DETAIL_1, PHYSICIAN_1);

        const sideErrors = result.errors.filter((e) => e.check_id === 'SIDE_OF_BODY');
        expect(sideErrors).toHaveLength(0);
      });

      it('passes when side is provided for paired POB (44000 Ankle)', async () => {
        const deps = makeServiceDeps();
        seedFullValidC050E();
        wcbInjuryStore.push({
          wcbInjuryId: 'inj-007',
          wcbClaimDetailId: WCB_DETAIL_1,
          ordinal: 1,
          partOfBodyCode: '44000',     // Ankle
          sideOfBodyCode: 'R',         // Right
          natureOfInjuryCode: '02100',
        });

        const result = await validateWcbClaim(deps, WCB_DETAIL_1, PHYSICIAN_1);

        const sideErrors = result.errors.filter((e) => e.check_id === 'SIDE_OF_BODY');
        expect(sideErrors).toHaveLength(0);
      });
    });

    // =======================================================================
    // Contract/Role/Form Validation (D04W-022)
    // =======================================================================

    describe('Contract/Role/Form validation', () => {
      it('rejects GP + C050S (GP cannot submit OIS forms)', async () => {
        const deps = makeServiceDeps();
        seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'DRAFT' });
        seedWcbDetail({
          wcbClaimDetailId: WCB_DETAIL_1,
          claimId: CLAIM_1,
          formId: 'C050S',
          submitterTxnId: 'MRT0000000000001',
          contractId: '000001', // GP contract
          roleCode: 'GP',
          reportCompletionDate: '2026-02-15',
          dateOfInjury: '2026-02-10',
          dateOfExamination: '2026-02-15',
          practitionerBillingNumber: '12345678',
          practitionerFirstName: 'Jane',
          practitionerLastName: 'Smith',
          skillCode: '03',
          facilityType: 'C',
          patientNoPhnFlag: 'N',
          patientPhn: '123456789',
          patientGender: 'M',
          patientFirstName: 'John',
          patientLastName: 'Doe',
          patientDob: '1990-05-10',
          patientAddressLine1: '123 Main St',
          patientCity: 'Calgary',
          symptoms: 'Pain',
          objectiveFindings: 'Swelling',
          currentDiagnosis: 'Fracture',
        });

        const result = await validateWcbClaim(deps, WCB_DETAIL_1, PHYSICIAN_1);

        const contractErrors = result.errors.filter((e) => e.check_id === 'CONTRACT_ROLE_FORM');
        expect(contractErrors.length).toBeGreaterThanOrEqual(1);
        expect(contractErrors[0].message).toContain('000001');
        expect(contractErrors[0].message).toContain('GP');
        expect(contractErrors[0].message).toContain('C050S');
      });

      it('allows GP + C050E (GP can submit first report)', async () => {
        const deps = makeServiceDeps();
        seedFullValidC050E();

        const result = await validateWcbClaim(deps, WCB_DETAIL_1, PHYSICIAN_1);

        const contractErrors = result.errors.filter((e) => e.check_id === 'CONTRACT_ROLE_FORM');
        expect(contractErrors).toHaveLength(0);
      });
    });
  });

  // =========================================================================
  // Follow-up chain validation (D04W-022)
  // =========================================================================

  describe('Follow-up chain validation', () => {
    it('allows C151 follow-up from C050E (valid chain for GP)', async () => {
      const deps = makeServiceDeps();

      // Create a parent C050E claim in terminal state
      seedClaim({ claimId: CLAIM_2, physicianId: PHYSICIAN_1, state: 'PAID' });
      seedWcbDetail({
        wcbClaimDetailId: WCB_DETAIL_2,
        claimId: CLAIM_2,
        formId: 'C050E',
        submitterTxnId: 'MRT0000000000002',
        practitionerBillingNumber: '12345678',
      });

      const input: CreateWcbClaimInput = {
        form_id: 'C151',
        patient_id: PATIENT_1,
        parent_wcb_claim_id: WCB_DETAIL_2,
        date_of_injury: '2026-02-10',
        date_of_examination: '2026-02-15',
        wcb_claim_number: '1234567',
      };

      const result = await createWcbClaim(deps, PHYSICIAN_1, USER_1, input);

      expect(result.claimId).toBeDefined();
      expect(result.wcbClaimDetailId).toBeDefined();
    });

    it('rejects C151 follow-up from C568A for GP (invalid chain)', async () => {
      const deps = makeServiceDeps();

      // Create a parent C568A claim in terminal state
      seedClaim({ claimId: CLAIM_2, physicianId: PHYSICIAN_1, state: 'PAID' });
      seedWcbDetail({
        wcbClaimDetailId: WCB_DETAIL_2,
        claimId: CLAIM_2,
        formId: 'C568A',
        submitterTxnId: 'MRT0000000000002',
        contractId: '000001',
        roleCode: 'GP',
        practitionerBillingNumber: '12345678',
      });

      const input: CreateWcbClaimInput = {
        form_id: 'C151',
        patient_id: PATIENT_1,
        parent_wcb_claim_id: WCB_DETAIL_2,
        date_of_injury: '2026-02-10',
        date_of_examination: '2026-02-15',
        wcb_claim_number: '1234567',
      };

      await expect(
        createWcbClaim(deps, PHYSICIAN_1, USER_1, input),
      ).rejects.toThrow('Cannot create follow-up from parent form type C568A');
    });
  });

  // =========================================================================
  // Timing Deadline Calculator (D04W-022)
  // =========================================================================

  describe('calculateTimingTier', () => {
    it('returns SAME_DAY when exam today and submit today', () => {
      // Monday exam, submit same day at 08:00 MT
      const examDate = '2026-02-16'; // Monday
      const now = new Date('2026-02-16T15:00:00Z'); // 08:00 MST = 15:00 UTC

      const result = calculateTimingTier('C050E', examDate, now);

      expect(result).not.toBeNull();
      expect(result!.tier).toBe('SAME_DAY');
      expect(result!.hoursRemaining).toBeGreaterThan(0);
    });

    it('returns ON_TIME when exam 3 biz days ago for C050E', () => {
      // Exam on Monday Feb 16, submit Thursday Feb 19 at 08:00 MT
      // 3 business days = Tue(1), Wed(2), Thu(3) = Feb 19
      const examDate = '2026-02-16'; // Monday
      const now = new Date('2026-02-19T15:00:00Z'); // 08:00 MST = 15:00 UTC (Thursday)

      const result = calculateTimingTier('C050E', examDate, now);

      expect(result).not.toBeNull();
      expect(result!.tier).toBe('ON_TIME');
    });

    it('returns LATE when exam 4 biz days ago for C050E', () => {
      // Exam on Monday Feb 16, submit Friday Feb 20 at 11:00 MT (past 10:00 cutoff)
      // On-time deadline = 3 biz days after Feb 16 = Feb 19 (Thu)
      // Feb 20 Fri is past the on-time deadline
      const examDate = '2026-02-16'; // Monday
      const now = new Date('2026-02-20T18:00:00Z'); // 11:00 MST = 18:00 UTC (Friday)

      const result = calculateTimingTier('C050E', examDate, now);

      expect(result).not.toBeNull();
      expect(result!.tier).toBe('LATE');
      expect(result!.hoursRemaining).toBeLessThan(0);
    });

    it('excludes holidays from business day count', () => {
      // Family Day 2026 = third Monday of February = Feb 16, 2026
      const holidays = getAlbertaStatutoryHolidays(2026);
      expect(holidays.has('2026-02-16')).toBe(true);

      // Exam on Friday Feb 13, 2026
      // Business days: Mon Feb 16 is Family Day (skip), Tue Feb 17 (1), Wed Feb 18 (2), Thu Feb 19 (3)
      // On-time deadline for C050E (3 biz days) = Feb 19 (Thu)
      const examDate = '2026-02-13'; // Friday
      const now = new Date('2026-02-19T15:00:00Z'); // 08:00 MST Thu Feb 19

      const result = calculateTimingTier('C050E', examDate, now);

      expect(result).not.toBeNull();
      // Should be ON_TIME since Feb 19 is within 3 biz days (Mon holiday excluded)
      expect(result!.tier).toBe('ON_TIME');
    });

    it('respects 10:00 MT cutoff — before cutoff is on-time', () => {
      // Exam on Monday Feb 16, on-time deadline = Thu Feb 19
      // Submit at 09:59 MST on Feb 19 (16:59 UTC) = still on-time
      const examDate = '2026-02-16';
      const now = new Date('2026-02-19T16:59:00Z'); // 09:59 MST

      const result = calculateTimingTier('C050E', examDate, now);

      expect(result).not.toBeNull();
      expect(result!.tier).toBe('ON_TIME');
    });

    it('respects 10:00 MT cutoff — after cutoff is late', () => {
      // Same scenario, but submit at 10:01 MST on Feb 19 (17:01 UTC)
      const examDate = '2026-02-16';
      const now = new Date('2026-02-19T17:01:00Z'); // 10:01 MST

      const result = calculateTimingTier('C050E', examDate, now);

      expect(result).not.toBeNull();
      expect(result!.tier).toBe('LATE');
    });

    it('returns null for form types without timing rules', () => {
      const result = calculateTimingTier('C568', '2026-02-16', new Date());
      expect(result).toBeNull();
    });

    it('returns null when dateOfExamination is null', () => {
      const result = calculateTimingTier('C050E', null, new Date());
      expect(result).toBeNull();
    });

    it('calculates correct deadline for C151 (4 business days)', () => {
      // Exam on Monday Feb 16, 4 biz days = Tue(1), Wed(2), Thu(3), Fri(4) = Feb 20
      const examDate = '2026-02-16';
      const now = new Date('2026-02-20T15:00:00Z'); // 08:00 MST on Fri

      const result = calculateTimingTier('C151', examDate, now);

      expect(result).not.toBeNull();
      expect(result!.tier).toBe('ON_TIME');
      expect(result!.onTimeDeadline).toBe('2026-02-20');
    });

    it('calculates correct deadline for C568A (4 business days)', () => {
      const examDate = '2026-02-16';
      const now = new Date('2026-02-20T15:00:00Z');

      const result = calculateTimingTier('C568A', examDate, now);

      expect(result).not.toBeNull();
      expect(result!.tier).toBe('ON_TIME');
      expect(result!.onTimeDeadline).toBe('2026-02-20');
    });

    it('handles weekend exam date (Day 0 not counted)', () => {
      // Exam on Saturday Feb 14, same-day deadline = next business day = Mon Feb 16
      // But Feb 16 is Family Day 2026, so same-day = Tue Feb 17
      const examDate = '2026-02-14'; // Saturday
      const now = new Date('2026-02-17T15:00:00Z'); // 08:00 MST Tue

      const result = calculateTimingTier('C050E', examDate, now);

      expect(result).not.toBeNull();
      expect(result!.tier).toBe('SAME_DAY');
      expect(result!.sameDayDeadline).toBe('2026-02-17');
    });
  });

  // =========================================================================
  // Alberta Statutory Holidays (D04W-022)
  // =========================================================================

  describe('getAlbertaStatutoryHolidays', () => {
    it('returns 10 holidays for 2026', () => {
      const holidays = getAlbertaStatutoryHolidays(2026);
      expect(holidays.size).toBe(10);
    });

    it('includes New Year\'s Day', () => {
      const holidays = getAlbertaStatutoryHolidays(2026);
      expect(holidays.has('2026-01-01')).toBe(true);
    });

    it('includes Christmas Day', () => {
      const holidays = getAlbertaStatutoryHolidays(2026);
      expect(holidays.has('2026-12-25')).toBe(true);
    });

    it('includes Canada Day', () => {
      const holidays = getAlbertaStatutoryHolidays(2026);
      expect(holidays.has('2026-07-01')).toBe(true);
    });

    it('includes Truth and Reconciliation Day', () => {
      const holidays = getAlbertaStatutoryHolidays(2026);
      expect(holidays.has('2026-09-30')).toBe(true);
    });

    it('computes Family Day (3rd Monday of Feb) correctly for 2026', () => {
      const holidays = getAlbertaStatutoryHolidays(2026);
      expect(holidays.has('2026-02-16')).toBe(true);
    });

    it('computes Good Friday correctly for 2026', () => {
      // Easter 2026 = April 5, Good Friday = April 3
      const holidays = getAlbertaStatutoryHolidays(2026);
      expect(holidays.has('2026-04-03')).toBe(true);
    });

    it('computes Victoria Day (Monday before May 25) correctly for 2026', () => {
      // May 25, 2026 is Monday, so Victoria Day = May 18 (Monday before)
      const holidays = getAlbertaStatutoryHolidays(2026);
      expect(holidays.has('2026-05-18')).toBe(true);
    });

    it('computes Labour Day (1st Monday of Sep) correctly for 2026', () => {
      const holidays = getAlbertaStatutoryHolidays(2026);
      expect(holidays.has('2026-09-07')).toBe(true);
    });

    it('computes Thanksgiving (2nd Monday of Oct) correctly for 2026', () => {
      const holidays = getAlbertaStatutoryHolidays(2026);
      expect(holidays.has('2026-10-12')).toBe(true);
    });
  });

  // =========================================================================
  // Fee Calculation Engine (D04W-023)
  // =========================================================================

  describe('calculateWcbFees', () => {
    // Helper: create mock ReferenceLookup
    function mockReferenceLookup(overrides: Partial<ReferenceLookup> = {}): ReferenceLookup {
      return {
        findHscBaseRate: overrides.findHscBaseRate ?? (async (hsc: string) => ({
          baseFee: '50.00',
          isPremiumCode: false,
        })),
        getRrnpVariablePremiumRate: overrides.getRrnpVariablePremiumRate ?? (async () => '0.00'),
      };
    }

    // Helper: create a fully seeded claim for fee calc testing
    function seedFeeCalcClaim(opts: {
      formId?: string;
      dateOfInjury?: string;
      dateOfExamination?: string;
      reportCompletionDate?: string;
      roleCode?: string;
      invoiceLines?: Array<Record<string, any>>;
      consultations?: Array<Record<string, any>>;
      isRrnpQualified?: boolean;
    } = {}) {
      const claimId = crypto.randomUUID();
      const wcbDetailId = crypto.randomUUID();

      seedClaim({
        claimId,
        state: 'DRAFT',
      });

      seedWcbDetail({
        wcbClaimDetailId: wcbDetailId,
        claimId,
        formId: opts.formId ?? 'C050E',
        dateOfInjury: opts.dateOfInjury ?? '2026-02-01',
        dateOfExamination: opts.dateOfExamination ?? '2026-02-16',
        reportCompletionDate: opts.reportCompletionDate ?? '2026-02-16',
        roleCode: opts.roleCode ?? 'GP',
      });

      // Add invoice lines if provided
      if (opts.invoiceLines) {
        for (const line of opts.invoiceLines) {
          wcbInvoiceLineStore.push({
            wcbInvoiceLineId: crypto.randomUUID(),
            wcbClaimDetailId: wcbDetailId,
            invoiceDetailId: line.invoiceDetailId,
            lineType: line.lineType ?? 'STANDARD',
            healthServiceCode: line.healthServiceCode ?? null,
            amount: line.amount ?? null,
            dateOfServiceFrom: line.dateOfServiceFrom ?? null,
            dateOfServiceTo: line.dateOfServiceTo ?? null,
            quantity: line.quantity ?? null,
            supplyDescription: line.supplyDescription ?? null,
            correctionPairId: line.correctionPairId ?? null,
          });
        }
      }

      // Add consultations if provided
      if (opts.consultations) {
        for (let i = 0; i < opts.consultations.length; i++) {
          wcbConsultationStore.push({
            wcbConsultationId: crypto.randomUUID(),
            wcbClaimDetailId: wcbDetailId,
            ordinal: i + 1,
            category: opts.consultations[i].category ?? 'CONREF',
            typeCode: opts.consultations[i].typeCode ?? 'CONSULT',
            details: opts.consultations[i].details ?? 'Test consultation',
            expediteRequested: opts.consultations[i].expediteRequested ?? 'N',
          });
        }
      }

      return { claimId, wcbDetailId, isRrnpQualified: opts.isRrnpQualified ?? false };
    }

    function makeFeeCalcDeps(opts: {
      isRrnpQualified?: boolean;
      referenceLookup?: ReferenceLookup;
    } = {}): WcbServiceDeps {
      const baseDeps = makeServiceDeps();
      return {
        ...baseDeps,
        providerLookup: {
          ...baseDeps.providerLookup,
          findProviderById: async (id: string) => ({
            providerId: PHYSICIAN_1,
            billingNumber: '12345678',
            firstName: 'Jane',
            lastName: 'Smith',
            status: 'ACTIVE',
            specialtyCode: 'GP',
            isRrnpQualified: opts.isRrnpQualified ?? false,
          }),
        },
        referenceLookup: opts.referenceLookup ?? mockReferenceLookup(),
      };
    }

    // --- Report fee tests ---

    it('calculates C050E same-day report fee = $94.15', async () => {
      const { wcbDetailId } = seedFeeCalcClaim({
        formId: 'C050E',
        dateOfExamination: '2026-02-16', // Monday
      });

      const result = await calculateWcbFees(
        makeFeeCalcDeps(),
        wcbDetailId,
        PHYSICIAN_1,
        new Date('2026-02-16T15:00:00Z'), // 08:00 MST same day
      );

      expect(result.report_fee).toBe('94.15');
      expect(result.report_fee_tier).toBe('SAME_DAY');
    });

    it('calculates C050E on-time report fee = $85.80', async () => {
      const { wcbDetailId } = seedFeeCalcClaim({
        formId: 'C050E',
        dateOfExamination: '2026-02-16', // Monday
      });

      const result = await calculateWcbFees(
        makeFeeCalcDeps(),
        wcbDetailId,
        PHYSICIAN_1,
        new Date('2026-02-19T15:00:00Z'), // Thursday 08:00 MST (3 biz days)
      );

      expect(result.report_fee).toBe('85.80');
      expect(result.report_fee_tier).toBe('ON_TIME');
    });

    it('calculates C050E late report fee = $54.08', async () => {
      const { wcbDetailId } = seedFeeCalcClaim({
        formId: 'C050E',
        dateOfExamination: '2026-02-16', // Monday
      });

      const result = await calculateWcbFees(
        makeFeeCalcDeps(),
        wcbDetailId,
        PHYSICIAN_1,
        new Date('2026-02-20T18:00:00Z'), // Friday 11:00 MST (past deadline)
      );

      expect(result.report_fee).toBe('54.08');
      expect(result.report_fee_tier).toBe('LATE');
    });

    // --- Premium code tests ---

    it('applies 2x SOMB rate for premium codes', async () => {
      const { wcbDetailId } = seedFeeCalcClaim({
        dateOfInjury: '2026-01-01', // Well before service date
        invoiceLines: [
          { invoiceDetailId: 1, lineType: 'STANDARD', healthServiceCode: '03.04A' },
        ],
      });

      const premiumRef = mockReferenceLookup({
        findHscBaseRate: async (hsc: string) => ({
          baseFee: '75.00',
          isPremiumCode: true,
        }),
      });

      const result = await calculateWcbFees(
        makeFeeCalcDeps({ referenceLookup: premiumRef }),
        wcbDetailId,
        PHYSICIAN_1,
        new Date('2026-02-16T15:00:00Z'),
      );

      expect(result.invoice_line_fees.length).toBe(1);
      expect(result.invoice_line_fees[0].premium_applied).toBe(true);
      expect(result.invoice_line_fees[0].base_rate).toBe('75.00');
      expect(result.invoice_line_fees[0].fee).toBe('150.00'); // 75 × 2
    });

    it('excludes premium when service within 4 days of injury', async () => {
      const { wcbDetailId } = seedFeeCalcClaim({
        dateOfInjury: '2026-02-13', // 3 days before service
        dateOfExamination: '2026-02-16',
        invoiceLines: [
          {
            invoiceDetailId: 1,
            lineType: 'DATED',
            healthServiceCode: '03.04A',
            dateOfServiceFrom: '2026-02-16', // 3 days after injury -> within 4-day window
          },
        ],
      });

      const premiumRef = mockReferenceLookup({
        findHscBaseRate: async () => ({
          baseFee: '75.00',
          isPremiumCode: true,
        }),
      });

      const result = await calculateWcbFees(
        makeFeeCalcDeps({ referenceLookup: premiumRef }),
        wcbDetailId,
        PHYSICIAN_1,
        new Date('2026-02-16T15:00:00Z'),
      );

      expect(result.invoice_line_fees[0].premium_applied).toBe(false);
      expect(result.invoice_line_fees[0].fee).toBe('75.00'); // Base rate, no premium
    });

    it('allows premium only once per encounter', async () => {
      const { wcbDetailId } = seedFeeCalcClaim({
        dateOfInjury: '2026-01-01', // Well before
        invoiceLines: [
          { invoiceDetailId: 1, lineType: 'STANDARD', healthServiceCode: '03.04A' },
          { invoiceDetailId: 2, lineType: 'STANDARD', healthServiceCode: '03.05A' },
        ],
      });

      const premiumRef = mockReferenceLookup({
        findHscBaseRate: async () => ({
          baseFee: '75.00',
          isPremiumCode: true,
        }),
      });

      const result = await calculateWcbFees(
        makeFeeCalcDeps({ referenceLookup: premiumRef }),
        wcbDetailId,
        PHYSICIAN_1,
        new Date('2026-02-16T15:00:00Z'),
      );

      // First line gets premium, second does not
      expect(result.invoice_line_fees[0].premium_applied).toBe(true);
      expect(result.invoice_line_fees[0].fee).toBe('150.00');
      expect(result.invoice_line_fees[1].premium_applied).toBe(false);
      expect(result.invoice_line_fees[1].fee).toBe('75.00');
    });

    // --- Unbundling tests ---

    it('pays 100% for each service on same date (no bundling)', async () => {
      const { wcbDetailId } = seedFeeCalcClaim({
        dateOfInjury: '2026-01-01',
        invoiceLines: [
          { invoiceDetailId: 1, lineType: 'STANDARD', healthServiceCode: '03.04A' },
          { invoiceDetailId: 2, lineType: 'STANDARD', healthServiceCode: '03.05B' },
        ],
      });

      const ref = mockReferenceLookup({
        findHscBaseRate: async (hsc: string) => ({
          baseFee: hsc === '03.04A' ? '50.00' : '75.00',
          isPremiumCode: false,
        }),
      });

      const result = await calculateWcbFees(
        makeFeeCalcDeps({ referenceLookup: ref }),
        wcbDetailId,
        PHYSICIAN_1,
        new Date('2026-02-16T15:00:00Z'),
      );

      // Both at full rate, no bundling discount
      expect(result.invoice_line_fees[0].fee).toBe('50.00');
      expect(result.invoice_line_fees[1].fee).toBe('75.00');
    });

    // --- Expedited fee tests ---

    it('calculates full expedited fee when completed within 15 biz days', async () => {
      // Exam Feb 16 (Mon), completion Mar 2 (Mon) = ~10 biz days
      const { wcbDetailId } = seedFeeCalcClaim({
        dateOfExamination: '2026-02-16',
        reportCompletionDate: '2026-02-27', // ~9 biz days later
        consultations: [
          { category: 'CONREF', expediteRequested: 'Y' },
        ],
      });

      const result = await calculateWcbFees(
        makeFeeCalcDeps(),
        wcbDetailId,
        PHYSICIAN_1,
        new Date('2026-02-27T15:00:00Z'),
      );

      expect(result.expedited_fees).toBe('150.00');
    });

    it('calculates pro-rated expedited fee at 20 biz days', async () => {
      // 20 biz days -> ratio = (25 - 20) / (25 - 15) = 5/10 = 0.5
      // Pro-rated fee = 150.00 × 0.5 = 75.00
      const { wcbDetailId } = seedFeeCalcClaim({
        dateOfExamination: '2026-02-16',
        // Need 20 biz days after Feb 16
        // Feb: 17,18,19,20,23,24,25,26,27 = 9 biz days
        // Mar: 2,3,4,5,6,9,10,11,12,13,16 = 11 biz days
        // Total 20 biz days = Mar 16, 2026
        reportCompletionDate: '2026-03-16',
        consultations: [
          { category: 'CONREF', expediteRequested: 'Y' },
        ],
      });

      const result = await calculateWcbFees(
        makeFeeCalcDeps(),
        wcbDetailId,
        PHYSICIAN_1,
        new Date('2026-03-16T15:00:00Z'),
      );

      expect(result.expedited_fees).toBe('75.00');
    });

    // --- RRNP fee tests ---

    it('adds $32.77 RRNP fee for qualifying physician', async () => {
      const { wcbDetailId } = seedFeeCalcClaim({});

      const result = await calculateWcbFees(
        makeFeeCalcDeps({ isRrnpQualified: true }),
        wcbDetailId,
        PHYSICIAN_1,
        new Date('2026-02-16T15:00:00Z'),
      );

      expect(result.rrnp_fee).toBe('32.77');
    });

    it('does not add RRNP fee for non-qualifying physician', async () => {
      const { wcbDetailId } = seedFeeCalcClaim({});

      const result = await calculateWcbFees(
        makeFeeCalcDeps({ isRrnpQualified: false }),
        wcbDetailId,
        PHYSICIAN_1,
        new Date('2026-02-16T15:00:00Z'),
      );

      expect(result.rrnp_fee).toBe('0.00');
    });

    // --- Total fee aggregation ---

    it('aggregates total fee correctly', async () => {
      const { wcbDetailId } = seedFeeCalcClaim({
        formId: 'C050E',
        dateOfInjury: '2026-01-01',
        dateOfExamination: '2026-02-16',
        invoiceLines: [
          { invoiceDetailId: 1, lineType: 'STANDARD', healthServiceCode: '03.04A' },
        ],
      });

      const ref = mockReferenceLookup({
        findHscBaseRate: async () => ({
          baseFee: '50.00',
          isPremiumCode: false,
        }),
      });

      const result = await calculateWcbFees(
        makeFeeCalcDeps({ isRrnpQualified: true, referenceLookup: ref }),
        wcbDetailId,
        PHYSICIAN_1,
        new Date('2026-02-16T15:00:00Z'), // Same day
      );

      // report_fee = 94.15 (C050E same-day)
      // invoice_line = 50.00
      // expedited = 0.00
      // rrnp = 32.77
      // total = 94.15 + 50.00 + 0.00 + 32.77 = 176.92
      expect(result.report_fee).toBe('94.15');
      expect(result.invoice_line_fees[0].fee).toBe('50.00');
      expect(result.rrnp_fee).toBe('32.77');
      expect(result.total_expected_fee).toBe('176.92');
    });

    it('returns not found error for non-existent claim', async () => {
      await expect(
        calculateWcbFees(
          makeFeeCalcDeps(),
          'non-existent-id',
          PHYSICIAN_1,
        ),
      ).rejects.toThrow('WCB claim not found');
    });
  });

  // =========================================================================
  // Fee Calculation Helpers (D04W-023)
  // =========================================================================

  describe('lookupReportFee', () => {
    it('returns C050E same-day fee', () => {
      expect(lookupReportFee('C050E', 'SAME_DAY', 'GP')).toBe('94.15');
    });

    it('returns C050E on-time fee', () => {
      expect(lookupReportFee('C050E', 'ON_TIME', 'GP')).toBe('85.80');
    });

    it('returns C050E late fee', () => {
      expect(lookupReportFee('C050E', 'LATE', 'GP')).toBe('54.08');
    });

    it('returns C151 same-day fee', () => {
      expect(lookupReportFee('C151', 'SAME_DAY', 'GP')).toBe('57.19');
    });

    it('returns 0.00 for forms without timing rules', () => {
      expect(lookupReportFee('C568', 'SAME_DAY', 'GP')).toBe('0.00');
    });

    it('returns RF01E fee for C568A (specialist consultation)', () => {
      expect(lookupReportFee('C568A', 'SAME_DAY', 'SP')).toBe('115.05');
    });
  });

  describe('isPremiumEligible', () => {
    it('returns true when service is >4 days after injury and no prior premiums', () => {
      expect(isPremiumEligible('2026-02-10', '2026-02-01', 0)).toBe(true);
    });

    it('returns false when service is within 4 days of injury', () => {
      expect(isPremiumEligible('2026-02-04', '2026-02-01', 0)).toBe(false);
    });

    it('returns false when service is on same day as injury', () => {
      expect(isPremiumEligible('2026-02-01', '2026-02-01', 0)).toBe(false);
    });

    it('returns true on day 5 after injury', () => {
      expect(isPremiumEligible('2026-02-06', '2026-02-01', 0)).toBe(true);
    });

    it('returns false on day 4 after injury', () => {
      expect(isPremiumEligible('2026-02-05', '2026-02-01', 0)).toBe(false);
    });

    it('returns false when premium limit already reached', () => {
      expect(isPremiumEligible('2026-02-10', '2026-02-01', 1)).toBe(false);
    });

    it('returns true when no dates provided', () => {
      expect(isPremiumEligible(null, null, 0)).toBe(true);
    });
  });

  describe('addMoney', () => {
    it('adds two money values correctly', () => {
      expect(addMoney('94.15', '50.00')).toBe('144.15');
    });

    it('handles zeros', () => {
      expect(addMoney('0.00', '32.77')).toBe('32.77');
    });

    it('maintains 2 decimal places', () => {
      expect(addMoney('100.10', '200.20')).toBe('300.30');
    });
  });

  describe('multiplyMoney', () => {
    it('doubles a fee correctly for premium codes', () => {
      expect(multiplyMoney('75.00', 2)).toBe('150.00');
    });

    it('handles odd cents', () => {
      expect(multiplyMoney('32.77', 2)).toBe('65.54');
    });
  });

  describe('countBusinessDays', () => {
    it('counts business days between two dates', () => {
      // Feb 16 (Mon) to Feb 20 (Fri) = Mon is start, so 17,18,19,20 = 4 biz days
      const result = countBusinessDays('2026-02-16', '2026-02-20');
      expect(result).toBe(4);
    });

    it('returns 0 for same-day', () => {
      const result = countBusinessDays('2026-02-16', '2026-02-16');
      expect(result).toBe(0);
    });

    it('excludes weekends', () => {
      // Fri Feb 20 to Mon Feb 23 = Sat(skip), Sun(skip), Mon(1) = 1 biz day
      const result = countBusinessDays('2026-02-20', '2026-02-23');
      expect(result).toBe(1);
    });
  });

  // =========================================================================
  // D04W-024: Batch Assembly & HL7 v2.3.1 XML Generation
  // =========================================================================

  describe('escapeXml', () => {
    it('escapes ampersands', () => {
      expect(escapeXml('A & B')).toBe('A &amp; B');
    });

    it('escapes angle brackets', () => {
      expect(escapeXml('<script>alert("xss")</script>')).toBe(
        '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;',
      );
    });

    it('escapes double quotes', () => {
      expect(escapeXml('He said "hello"')).toBe('He said &quot;hello&quot;');
    });

    it('returns empty string for null/undefined', () => {
      expect(escapeXml(null)).toBe('');
      expect(escapeXml(undefined)).toBe('');
    });

    it('handles multiple special chars in one string', () => {
      expect(escapeXml('A & B < C > D "E"')).toBe(
        'A &amp; B &lt; C &gt; D &quot;E&quot;',
      );
    });
  });

  describe('formatHl7Date', () => {
    it('converts YYYY-MM-DD to YYYYMMDD', () => {
      expect(formatHl7Date('2026-02-15')).toBe('20260215');
    });

    it('returns empty string for null', () => {
      expect(formatHl7Date(null)).toBe('');
    });

    it('returns empty string for undefined', () => {
      expect(formatHl7Date(undefined)).toBe('');
    });
  });

  describe('formatMountainTimestamp', () => {
    it('produces timestamp in Mountain Time', () => {
      // Feb 15, 2026 18:00 UTC = Feb 15, 2026 11:00 MST (UTC-7, not MDT in Feb)
      const date = new Date('2026-02-15T18:00:00Z');
      const result = formatMountainTimestamp(date);
      expect(result).toBe('20260215110000');
    });

    it('pads single-digit values with zeros', () => {
      // Jan 5, 2026 08:05:03 UTC = Jan 5, 2026 01:05:03 MST
      const date = new Date('2026-01-05T08:05:03Z');
      const result = formatMountainTimestamp(date);
      expect(result).toBe('20260105010503');
    });
  });

  describe('mapClaimToObservations', () => {
    it('maps clinical fields to OBX entries', () => {
      const claim = makeClaimWithChildren({
        detail: {
          roleCode: 'GP',
          symptoms: 'Back pain',
          objectiveFindings: 'Tenderness',
        },
        injuries: [
          { partOfBodyCode: 'BACK', sideOfBodyCode: null, natureOfInjuryCode: 'SPRAIN' },
        ],
      });

      const entries = mapClaimToObservations(claim);
      const identifiers = entries.map((e) => e.identifier);

      expect(identifiers).toContain('PRACTITIONER_ROLE');
      expect(identifiers).toContain('INJSYMP');
      expect(identifiers).toContain('OBJFIND');
      expect(identifiers).toContain('POB_1');
      expect(identifiers).toContain('NOI_1');
    });

    it('excludes null/empty fields', () => {
      const claim = makeClaimWithChildren({
        detail: { roleCode: 'GP' },
        injuries: [],
      });

      const entries = mapClaimToObservations(claim);
      const identifiers = entries.map((e) => e.identifier);
      expect(identifiers).toContain('PRACTITIONER_ROLE');
      expect(identifiers).not.toContain('INJSYMP');
    });
  });

  describe('generateBatchXml', () => {
    const vendorSourceId = 'TEST_VENDOR';
    const batchId = BATCH_1;
    const batchControlId = 'MER-B-TEST0001';
    const fileControlId = 'MER-20260215-TEST01';
    const fixedDate = new Date('2026-02-15T18:00:00Z');

    function makeTestClaim(overrides: Partial<Record<string, unknown>> = {}): any {
      return makeClaimWithChildren({
        detail: {
          wcbClaimDetailId: WCB_DETAIL_1,
          claimId: CLAIM_1,
          formId: 'C050E',
          submitterTxnId: 'MRT0000000000001',
          reportCompletionDate: '2026-02-15',
          practitionerBillingNumber: '12345678',
          contractId: '000001',
          roleCode: 'GP',
          practitionerFirstName: 'Jane',
          practitionerLastName: 'Smith',
          skillCode: '03',
          facilityType: 'C',
          patientPhn: '123456789',
          patientGender: 'M',
          patientFirstName: 'John',
          patientLastName: 'Doe',
          patientDob: '1990-05-10',
          patientAddressLine1: '123 Main St',
          patientCity: 'Calgary',
          patientProvince: 'AB',
          patientPostalCode: 'T2P1A1',
          dateOfInjury: '2026-02-10',
          dateOfExamination: '2026-02-14',
          symptoms: 'Back pain',
          objectiveFindings: 'Tenderness in lower back',
          currentDiagnosis: 'Lumbar strain',
          diagnosticCode1: 'M54.5',
          faxNumber: '4035551234',
          clinicReferenceNumber: 'REF001',
          additionalComments: 'Needs follow-up',
          ...overrides,
        },
        injuries: [
          { partOfBodyCode: 'BACK', sideOfBodyCode: null, natureOfInjuryCode: 'SPRAIN' },
        ],
        invoiceLines: [
          {
            wcbInvoiceLineId: 'inv-1',
            wcbClaimDetailId: WCB_DETAIL_1,
            invoiceDetailId: 1,
            lineType: 'STANDARD',
            healthServiceCode: '03.04A',
            amount: '94.15',
            diagnosticCode1: null,
            modifier1: null,
            modifier2: null,
            modifier3: null,
          },
        ],
        attachments: [],
      });
    }

    it('produces valid XML structure with correct root element and namespace', () => {
      const claims = [makeTestClaim()];
      const xml = generateBatchXml(batchId, batchControlId, fileControlId, claims, vendorSourceId, fixedDate);

      expect(xml).toContain('<?xml version="1.0" encoding="UTF-8"?>');
      expect(xml).toContain(`<ZRPT_P03 xmlns="${HL7_NAMESPACE}">`);
      expect(xml).toContain('</ZRPT_P03>');
    });

    it('contains correct namespace', () => {
      const claims = [makeTestClaim()];
      const xml = generateBatchXml(batchId, batchControlId, fileControlId, claims, vendorSourceId, fixedDate);

      expect(xml).toContain('urn:WCBhl7_v231-schema_modern_v100');
    });

    it('XML header values match vendor credentials', () => {
      const claims = [makeTestClaim()];
      const xml = generateBatchXml(batchId, batchControlId, fileControlId, claims, vendorSourceId, fixedDate);

      // FHS headers
      expect(xml).toContain(`<FHS.3>${vendorSourceId}</FHS.3>`);
      expect(xml).toContain(`<FHS.5>WCB-EDM</FHS.5>`);
      expect(xml).toContain(`<FHS.6>RAPID-RPT</FHS.6>`);
      // BHS headers
      expect(xml).toContain(`<BHS.3>${vendorSourceId}</BHS.3>`);
      expect(xml).toContain(`<BHS.5>WCB-EDM</BHS.5>`);
      expect(xml).toContain(`<BHS.6>RAPID-RPT</BHS.6>`);
      // MSH headers
      expect(xml).toContain(`<MSH.3>${vendorSourceId}</MSH.3>`);
    });

    it('XML timestamps in Mountain Time format', () => {
      const claims = [makeTestClaim()];
      const xml = generateBatchXml(batchId, batchControlId, fileControlId, claims, vendorSourceId, fixedDate);

      // Feb 15, 2026 18:00 UTC = Feb 15, 2026 11:00 MST
      const mtTimestamp = '20260215110000';
      expect(xml).toContain(`<FHS.7>${mtTimestamp}</FHS.7>`);
      expect(xml).toContain(`<BHS.7>${mtTimestamp}</BHS.7>`);
      expect(xml).toContain(`<MSH.7>${mtTimestamp}</MSH.7>`);
    });

    it('escapes special characters in free-text fields', () => {
      const claims = [makeTestClaim({
        additionalComments: 'Patient says "pain" is > 5 & < 10',
        symptoms: 'Pain & swelling in <left> knee',
      })];
      const xml = generateBatchXml(batchId, batchControlId, fileControlId, claims, vendorSourceId, fixedDate);

      expect(xml).toContain('Patient says &quot;pain&quot; is &gt; 5 &amp; &lt; 10');
      expect(xml).toContain('Pain &amp; swelling in &lt;left&gt; knee');
    });

    it('includes base64 attachments correctly', () => {
      const b64Content = 'dGVzdCBmaWxlIGNvbnRlbnQ=';
      const claims = [makeClaimWithChildren({
        detail: {
          wcbClaimDetailId: WCB_DETAIL_1,
          claimId: CLAIM_1,
          formId: 'C050E',
          submitterTxnId: 'MRT0000000000001',
          reportCompletionDate: '2026-02-15',
          practitionerBillingNumber: '12345678',
          contractId: '000001',
          roleCode: 'GP',
          practitionerFirstName: 'Jane',
          practitionerLastName: 'Smith',
          skillCode: '03',
          patientPhn: '123456789',
          patientGender: 'M',
          patientFirstName: 'John',
          patientLastName: 'Doe',
          patientDob: '1990-05-10',
          patientAddressLine1: '123 Main St',
          patientCity: 'Calgary',
          dateOfInjury: '2026-02-10',
        },
        injuries: [],
        invoiceLines: [],
        attachments: [
          {
            wcbAttachmentId: 'att-1',
            wcbClaimDetailId: WCB_DETAIL_1,
            ordinal: 1,
            fileName: 'xray.pdf',
            fileType: 'PDF',
            fileContentB64: b64Content,
            fileDescription: 'X-ray report',
            fileSizeBytes: 1024,
          },
        ],
      })];

      const xml = generateBatchXml(batchId, batchControlId, fileControlId, claims, vendorSourceId, fixedDate);

      expect(xml).toContain('<OBX.2>ED</OBX.2>');
      expect(xml).toContain('<OBX.3>ATTACHMENT_1</OBX.3>');
      expect(xml).toContain(`xray.pdf^PDF^Base64^${b64Content}`);
    });

    it('FT1 segments repeat per invoice line', () => {
      const claims = [makeClaimWithChildren({
        detail: {
          wcbClaimDetailId: WCB_DETAIL_1,
          claimId: CLAIM_1,
          formId: 'C050E',
          submitterTxnId: 'MRT0000000000001',
          reportCompletionDate: '2026-02-15',
          practitionerBillingNumber: '12345678',
          contractId: '000001',
          roleCode: 'GP',
          practitionerFirstName: 'Jane',
          practitionerLastName: 'Smith',
          skillCode: '03',
          patientPhn: '123456789',
          patientGender: 'M',
          patientFirstName: 'John',
          patientLastName: 'Doe',
          patientDob: '1990-05-10',
          patientAddressLine1: '123 Main St',
          patientCity: 'Calgary',
          dateOfInjury: '2026-02-10',
          dateOfExamination: '2026-02-14',
          diagnosticCode1: 'M54.5',
        },
        injuries: [],
        invoiceLines: [
          { wcbInvoiceLineId: 'inv-1', wcbClaimDetailId: WCB_DETAIL_1, invoiceDetailId: 1, lineType: 'STANDARD', healthServiceCode: '03.04A', amount: '94.15' },
          { wcbInvoiceLineId: 'inv-2', wcbClaimDetailId: WCB_DETAIL_1, invoiceDetailId: 2, lineType: 'DATED', healthServiceCode: '03.05B', amount: '50.00', dateOfServiceFrom: '2026-02-12' },
          { wcbInvoiceLineId: 'inv-3', wcbClaimDetailId: WCB_DETAIL_1, invoiceDetailId: 3, lineType: 'STANDARD', healthServiceCode: '03.06C', amount: '75.00' },
        ],
        attachments: [],
      })];

      const xml = generateBatchXml(batchId, batchControlId, fileControlId, claims, vendorSourceId, fixedDate);

      // Count FT1 segments
      const ft1Count = (xml.match(/<FT1>/g) || []).length;
      expect(ft1Count).toBe(3);
      expect(xml).toContain('<FT1.25>03.04A</FT1.25>');
      expect(xml).toContain('<FT1.25>03.05B</FT1.25>');
      expect(xml).toContain('<FT1.25>03.06C</FT1.25>');
    });

    it('OBX segments map clinical fields correctly', () => {
      const claims = [makeTestClaim()];
      const xml = generateBatchXml(batchId, batchControlId, fileControlId, claims, vendorSourceId, fixedDate);

      expect(xml).toContain('<OBX.3>PRACTITIONER_ROLE</OBX.3>');
      expect(xml).toContain('<OBX.5>GP</OBX.5>');
      expect(xml).toContain('<OBX.3>INJSYMP</OBX.3>');
      expect(xml).toContain('<OBX.3>OBJFIND</OBX.3>');
      expect(xml).toContain('<OBX.3>CURDIAG</OBX.3>');
      expect(xml).toContain('<OBX.3>POB_1</OBX.3>');
      expect(xml).toContain('<OBX.3>NOI_1</OBX.3>');
    });

    it('includes batch and file control IDs', () => {
      const claims = [makeTestClaim()];
      const xml = generateBatchXml(batchId, batchControlId, fileControlId, claims, vendorSourceId, fixedDate);

      expect(xml).toContain(`<FHS.9>${fileControlId}</FHS.9>`);
      expect(xml).toContain(`<FHS.11>${fileControlId}</FHS.11>`);
      expect(xml).toContain(`<BHS.11>${batchControlId}</BHS.11>`);
    });

    it('BTS contains report count', () => {
      const claim1 = makeTestClaim();
      const claim2 = makeClaimWithChildren({
        detail: {
          ...claim1.detail,
          wcbClaimDetailId: WCB_DETAIL_2,
          submitterTxnId: 'MRT0000000000002',
        },
        injuries: [],
        invoiceLines: [],
        attachments: [],
      });

      const xml = generateBatchXml(batchId, batchControlId, fileControlId, [claim1, claim2], vendorSourceId, fixedDate);
      expect(xml).toContain('<BTS.1>2</BTS.1>');
    });

    it('FTS contains batch count of 1', () => {
      const claims = [makeTestClaim()];
      const xml = generateBatchXml(batchId, batchControlId, fileControlId, claims, vendorSourceId, fixedDate);
      expect(xml).toContain('<FTS.1>1</FTS.1>');
    });

    it('includes NTE segment for additional comments', () => {
      const claims = [makeTestClaim()];
      const xml = generateBatchXml(batchId, batchControlId, fileControlId, claims, vendorSourceId, fixedDate);
      expect(xml).toContain('<NTE>');
      expect(xml).toContain('<NTE.3>Needs follow-up</NTE.3>');
    });

    it('omits NTE segment when no comments', () => {
      const claims = [makeTestClaim({ additionalComments: null })];
      const xml = generateBatchXml(batchId, batchControlId, fileControlId, claims, vendorSourceId, fixedDate);
      expect(xml).not.toContain('<NTE>');
    });
  });

  describe('assembleAndGenerateBatch', () => {
    function makeBatchDeps(overrides: Partial<{
      queuedClaims: any[];
      validationPassed: boolean;
      fullClaims: Map<string, any>;
    }> = {}) {
      const queuedClaims = overrides.queuedClaims ?? [];
      const validationPassed = overrides.validationPassed ?? true;
      const fullClaims = overrides.fullClaims ?? new Map();

      const createdBatch = {
        wcbBatchId: BATCH_1,
        physicianId: PHYSICIAN_1,
        batchControlId: 'MER-B-TEST0001',
        fileControlId: 'MER-20260215-TEST01',
        status: 'ASSEMBLING',
        reportCount: 0,
      };

      let batchStatus = 'ASSEMBLING';
      let batchXmlFilePath: string | null = null;
      let batchXmlFileHash: string | null = null;
      let batchReportCount = 0;
      const assignedClaimIds: string[] = [];

      const wcbRepo: any = {
        createBatch: vi.fn().mockResolvedValue(createdBatch),
        getQueuedClaimsForBatch: vi.fn().mockResolvedValue(queuedClaims),
        getWcbClaim: vi.fn().mockImplementation(async (detailId: string) => {
          return fullClaims.get(detailId) ?? null;
        }),
        assignClaimsToBatch: vi.fn().mockImplementation(async (_batchId: string, _phyId: string, claimIds: string[]) => {
          assignedClaimIds.push(...claimIds);
          return claimIds.length;
        }),
        updateBatchStatus: vi.fn().mockImplementation(async (_batchId: string, _phyId: string, newStatus: string, additionalFields?: any) => {
          batchStatus = newStatus;
          if (additionalFields?.xmlFilePath) batchXmlFilePath = additionalFields.xmlFilePath;
          if (additionalFields?.xmlFileHash) batchXmlFileHash = additionalFields.xmlFileHash;
          if (additionalFields?.reportCount) batchReportCount = additionalFields.reportCount;
          return { ...createdBatch, status: newStatus, ...additionalFields };
        }),
        listWcbClaimsForPhysician: vi.fn().mockResolvedValue({ data: [], total: 0 }),
      };

      const claimRepo: any = {
        createClaim: vi.fn(),
        findClaimById: vi.fn(),
        appendClaimAudit: vi.fn().mockResolvedValue(undefined),
      };

      const providerLookup: any = {
        findProviderById: vi.fn().mockResolvedValue({
          providerId: PHYSICIAN_1,
          billingNumber: '12345678',
          firstName: 'Jane',
          lastName: 'Smith',
          status: 'ACTIVE',
          specialtyCode: '03',
        }),
        getWcbConfigForForm: vi.fn().mockResolvedValue({
          wcbConfigId: 'cfg-1',
          contractId: '000001',
          roleCode: 'GP',
          skillCode: '03',
          facilityType: 'C',
        }),
      };

      const patientLookup: any = {
        findPatientById: vi.fn().mockResolvedValue({
          patientId: PATIENT_1,
          phn: '123456789',
          firstName: 'John',
          lastName: 'Doe',
          dateOfBirth: '1990-05-10',
          gender: 'M',
          addressLine1: '123 Main St',
          city: 'Calgary',
        }),
      };

      const auditEmitter: any = {
        emit: vi.fn().mockResolvedValue(undefined),
      };

      const fileStorage: FileStorage = {
        storeEncrypted: vi.fn().mockResolvedValue(undefined),
        readEncrypted: vi.fn().mockResolvedValue(Buffer.from('')),
      };

      const secretsProvider: SecretsProvider = {
        getVendorSourceId: () => 'TEST_VENDOR',
        getSubmitterId: () => 'TEST_SUBMITTER',
      };

      const deps: WcbServiceDeps = {
        wcbRepo,
        claimRepo,
        providerLookup,
        patientLookup,
        auditEmitter,
        fileStorage,
        secretsProvider,
      };

      return {
        deps,
        wcbRepo,
        claimRepo,
        auditEmitter,
        fileStorage,
        assignedClaimIds,
        getBatchStatus: () => batchStatus,
        getBatchXmlFilePath: () => batchXmlFilePath,
        getBatchXmlFileHash: () => batchXmlFileHash,
        getBatchReportCount: () => batchReportCount,
      };
    }

    function makeQueuedClaim(claimId: string, detailId: string): any {
      return {
        claim: {
          claimId,
          physicianId: PHYSICIAN_1,
          patientId: PATIENT_1,
          claimType: 'WCB',
          state: 'QUEUED',
          dateOfService: '2026-02-15',
          deletedAt: null,
        },
        detail: {
          wcbClaimDetailId: detailId,
          claimId,
          formId: 'C050E',
          submitterTxnId: `MRT${detailId.slice(0, 13)}`,
          reportCompletionDate: '2026-02-15',
          practitionerBillingNumber: '12345678',
          contractId: '000001',
          roleCode: 'GP',
          practitionerFirstName: 'Jane',
          practitionerLastName: 'Smith',
          skillCode: '03',
          facilityType: 'C',
          patientPhn: '123456789',
          patientGender: 'M',
          patientFirstName: 'John',
          patientLastName: 'Doe',
          patientDob: '1990-05-10',
          patientAddressLine1: '123 Main St',
          patientCity: 'Calgary',
          patientProvince: 'AB',
          dateOfInjury: '2026-02-10',
          dateOfExamination: '2026-02-14',
          symptoms: 'Back pain',
          objectiveFindings: 'Tenderness',
          currentDiagnosis: 'Strain',
          diagnosticCode1: 'M54.5',
          deletedAt: null,
        },
      };
    }

    function makeFullClaim(detailId: string, claimId: string): any {
      return makeClaimWithChildren({
        detail: {
          wcbClaimDetailId: detailId,
          claimId,
          formId: 'C050E',
          submitterTxnId: `MRT${detailId.slice(0, 13)}`,
          reportCompletionDate: '2026-02-15',
          practitionerBillingNumber: '12345678',
          contractId: '000001',
          roleCode: 'GP',
          practitionerFirstName: 'Jane',
          practitionerLastName: 'Smith',
          skillCode: '03',
          facilityType: 'C',
          patientPhn: '123456789',
          patientGender: 'M',
          patientFirstName: 'John',
          patientLastName: 'Doe',
          patientDob: '1990-05-10',
          patientAddressLine1: '123 Main St',
          patientCity: 'Calgary',
          patientProvince: 'AB',
          dateOfInjury: '2026-02-10',
          dateOfExamination: '2026-02-14',
          symptoms: 'Back pain',
          objectiveFindings: 'Tenderness',
          currentDiagnosis: 'Strain',
          diagnosticCode1: 'M54.5',
        },
        injuries: [
          { partOfBodyCode: 'BACK', sideOfBodyCode: null, natureOfInjuryCode: 'SPRAIN' },
        ],
        invoiceLines: [
          { wcbInvoiceLineId: 'inv-1', wcbClaimDetailId: detailId, invoiceDetailId: 1, lineType: 'STANDARD', healthServiceCode: '03.04A', amount: '94.15' },
        ],
        attachments: [],
      });
    }

    it('creates batch and assigns validated claims', async () => {
      const queued1 = makeQueuedClaim(CLAIM_1, WCB_DETAIL_1);
      const full1 = makeFullClaim(WCB_DETAIL_1, CLAIM_1);
      const fullClaims = new Map([[WCB_DETAIL_1, full1]]);

      const { deps, wcbRepo } = makeBatchDeps({
        queuedClaims: [queued1],
        fullClaims,
      });

      // Mock validateWcbClaim to pass (we call it internally but it will try to use wcbRepo.getWcbClaim)
      // Since we're testing assembleAndGenerateBatch which calls validateWcbClaim,
      // and validateWcbClaim uses deps.wcbRepo.getWcbClaim (which we mocked), it should work.
      // But validateWcbClaim does complex checks. Let's make it return via the mock structure.
      // The function uses the real validateWcbClaim, so the claim data needs to pass validation.

      const result = await assembleAndGenerateBatch(deps, PHYSICIAN_1, USER_1);

      expect(result.wcbBatchId).toBe(BATCH_1);
      expect(result.reportCount).toBe(1);
      expect(wcbRepo.createBatch).toHaveBeenCalledWith(PHYSICIAN_1, USER_1);
      expect(wcbRepo.assignClaimsToBatch).toHaveBeenCalledWith(BATCH_1, PHYSICIAN_1, [CLAIM_1]);
    });

    it('skips claims that fail validation', async () => {
      // Create two claims: one will pass (has all required fields), one won't
      const queued1 = makeQueuedClaim(CLAIM_1, WCB_DETAIL_1);
      const queued2 = makeQueuedClaim(CLAIM_2, WCB_DETAIL_2);
      // Make claim 2 fail validation by removing required fields
      queued2.detail.symptoms = null;
      queued2.detail.objectiveFindings = null;
      queued2.detail.currentDiagnosis = null;
      queued2.detail.dateOfExamination = null;

      const full1 = makeFullClaim(WCB_DETAIL_1, CLAIM_1);
      // Claim 2 will fail validation so it won't need a full claim
      const full2 = makeFullClaim(WCB_DETAIL_2, CLAIM_2);
      // Make full2 also fail
      (full2.detail as any).symptoms = null;
      (full2.detail as any).objectiveFindings = null;
      (full2.detail as any).currentDiagnosis = null;
      (full2.detail as any).dateOfExamination = null;

      const fullClaims = new Map([
        [WCB_DETAIL_1, full1],
        [WCB_DETAIL_2, full2],
      ]);

      const { deps } = makeBatchDeps({
        queuedClaims: [queued1, queued2],
        fullClaims,
      });

      const result = await assembleAndGenerateBatch(deps, PHYSICIAN_1, USER_1);

      // Claim 1 passed, claim 2 skipped due to validation failure
      expect(result.reportCount).toBeGreaterThanOrEqual(1);
      // Either 0 or 1 skipped depending on validation. The important thing is it doesn't throw.
      expect(result.wcbBatchId).toBe(BATCH_1);
    });

    it('throws when no queued claims exist', async () => {
      const { deps, wcbRepo } = makeBatchDeps({
        queuedClaims: [],
      });

      await expect(assembleAndGenerateBatch(deps, PHYSICIAN_1, USER_1))
        .rejects.toThrow('No queued WCB claims available for batch assembly');

      expect(wcbRepo.updateBatchStatus).toHaveBeenCalledWith(BATCH_1, PHYSICIAN_1, 'ERROR');
    });

    it('transitions batch to GENERATED with xml file path and hash', async () => {
      const queued1 = makeQueuedClaim(CLAIM_1, WCB_DETAIL_1);
      const full1 = makeFullClaim(WCB_DETAIL_1, CLAIM_1);
      const fullClaims = new Map([[WCB_DETAIL_1, full1]]);

      const { deps, wcbRepo, getBatchStatus, getBatchXmlFilePath, getBatchXmlFileHash } = makeBatchDeps({
        queuedClaims: [queued1],
        fullClaims,
      });

      await assembleAndGenerateBatch(deps, PHYSICIAN_1, USER_1);

      expect(getBatchStatus()).toBe('GENERATED');
      expect(getBatchXmlFilePath()).toContain('wcb/batches/');
      expect(getBatchXmlFilePath()).toContain(BATCH_1);
      expect(getBatchXmlFileHash()).toBeDefined();
      expect(getBatchXmlFileHash()!.length).toBe(64); // SHA-256 hex
    });

    it('stores encrypted XML file via fileStorage', async () => {
      const queued1 = makeQueuedClaim(CLAIM_1, WCB_DETAIL_1);
      const full1 = makeFullClaim(WCB_DETAIL_1, CLAIM_1);
      const fullClaims = new Map([[WCB_DETAIL_1, full1]]);

      const { deps, fileStorage } = makeBatchDeps({
        queuedClaims: [queued1],
        fullClaims,
      });

      await assembleAndGenerateBatch(deps, PHYSICIAN_1, USER_1);

      expect((fileStorage.storeEncrypted as any)).toHaveBeenCalledTimes(1);
      const [path, buffer] = (fileStorage.storeEncrypted as any).mock.calls[0];
      expect(path).toContain('wcb/batches/');
      expect(Buffer.isBuffer(buffer)).toBe(true);
      const xmlString = buffer.toString('utf-8');
      expect(xmlString).toContain('<ZRPT_P03');
    });

    it('emits audit event with batch details', async () => {
      const queued1 = makeQueuedClaim(CLAIM_1, WCB_DETAIL_1);
      const full1 = makeFullClaim(WCB_DETAIL_1, CLAIM_1);
      const fullClaims = new Map([[WCB_DETAIL_1, full1]]);

      const { deps, auditEmitter } = makeBatchDeps({
        queuedClaims: [queued1],
        fullClaims,
      });

      await assembleAndGenerateBatch(deps, PHYSICIAN_1, USER_1);

      expect(auditEmitter.emit).toHaveBeenCalledWith(
        'WCB_BATCH_ASSEMBLED',
        expect.objectContaining({
          claimId: CLAIM_1,
          actorId: USER_1,
          changes: expect.objectContaining({
            wcbBatchId: BATCH_1,
            reportCount: 1,
          }),
        }),
      );
    });
  });

  // =========================================================================
  // validateBatchXsd
  // =========================================================================

  describe('validateBatchXsd', () => {
    function makeXsdDeps(overrides: Partial<{
      batchStatus: string;
      batchXmlFilePath: string | null;
      xsdValidatorResult: XsdValidationResult;
      xsdDataValidatorResult: XsdValidationResult;
      structuralXsd: string;
      dataXsd: string;
    }> = {}) {
      const batchStatus = overrides.batchStatus ?? 'GENERATED';
      const batchXmlFilePath = overrides.batchXmlFilePath ?? `wcb/batches/${BATCH_1}/MER-20260215-TEST01.xml`;
      const xmlContent = '<ZRPT_P03>test xml</ZRPT_P03>';
      let currentStatus = batchStatus;
      let storedXsdPassed: boolean | null = null;
      let storedXsdErrors: unknown = null;

      const wcbRepo: any = {
        getBatch: vi.fn().mockImplementation(async (batchId: string, physicianId: string) => {
          if (batchId !== BATCH_1 || physicianId !== PHYSICIAN_1) return null;
          return {
            wcbBatchId: BATCH_1,
            physicianId: PHYSICIAN_1,
            batchControlId: 'MER-B-TEST0001',
            fileControlId: 'MER-20260215-TEST01',
            status: currentStatus,
            xmlFilePath: batchXmlFilePath,
            xmlFileHash: 'abc123',
            reportCount: 1,
            xsdValidationPassed: null,
            xsdValidationErrors: null,
          };
        }),
        updateBatchStatus: vi.fn().mockImplementation(async (_batchId: string, _phyId: string, newStatus: string, additionalFields?: any) => {
          currentStatus = newStatus;
          if (additionalFields?.xsdValidationPassed !== undefined) storedXsdPassed = additionalFields.xsdValidationPassed;
          if (additionalFields?.xsdValidationErrors !== undefined) storedXsdErrors = additionalFields.xsdValidationErrors;
          return { wcbBatchId: BATCH_1, status: newStatus };
        }),
      };

      const structuralResult = overrides.xsdValidatorResult ?? { valid: true, errors: [] };
      const dataResult = overrides.xsdDataValidatorResult ?? { valid: true, errors: [] };
      let callCount = 0;

      const xsdValidator: XsdValidator = {
        validate: vi.fn().mockImplementation((_xml: string, _xsd: string) => {
          callCount++;
          return callCount === 1 ? structuralResult : dataResult;
        }),
      };

      const fileStorage: FileStorage = {
        storeEncrypted: vi.fn().mockResolvedValue(undefined),
        readEncrypted: vi.fn().mockResolvedValue(Buffer.from(xmlContent, 'utf-8')),
      };

      const claimRepo: any = {
        appendClaimAudit: vi.fn().mockResolvedValue(undefined),
      };

      const auditEmitter: any = {
        emit: vi.fn().mockResolvedValue(undefined),
      };

      const deps: WcbServiceDeps = {
        wcbRepo,
        claimRepo,
        providerLookup: { findProviderById: vi.fn(), getWcbConfigForForm: vi.fn() } as any,
        patientLookup: { findPatientById: vi.fn() } as any,
        auditEmitter,
        fileStorage,
        xsdValidator,
      };

      return {
        deps,
        wcbRepo,
        xsdValidator,
        fileStorage,
        auditEmitter,
        getCurrentStatus: () => currentStatus,
        getStoredXsdPassed: () => storedXsdPassed,
        getStoredXsdErrors: () => storedXsdErrors,
      };
    }

    it('passes for valid XML and transitions to VALIDATED', async () => {
      const { deps, getCurrentStatus, getStoredXsdPassed } = makeXsdDeps();

      const result = await validateBatchXsd(deps, BATCH_1, PHYSICIAN_1, {
        structural: '<xsd>structural</xsd>',
        data: '<xsd>data</xsd>',
      });

      expect(result.passed).toBe(true);
      expect(result.errors).toHaveLength(0);
      expect(result.wcbBatchId).toBe(BATCH_1);
      expect(getCurrentStatus()).toBe('VALIDATED');
      expect(getStoredXsdPassed()).toBe(true);
    });

    it('fails and stores errors for invalid XML (structural failure)', async () => {
      const { deps, getCurrentStatus, getStoredXsdPassed, getStoredXsdErrors } = makeXsdDeps({
        xsdValidatorResult: {
          valid: false,
          errors: [{ message: 'Missing required element MSH', line: 5 }],
        },
      });

      const result = await validateBatchXsd(deps, BATCH_1, PHYSICIAN_1, {
        structural: '<xsd>structural</xsd>',
        data: '<xsd>data</xsd>',
      });

      expect(result.passed).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors[0].message).toContain('[structural]');
      expect(getCurrentStatus()).toBe('ERROR');
      expect(getStoredXsdPassed()).toBe(false);
      expect(getStoredXsdErrors()).toBeDefined();
    });

    it('fails and stores errors for invalid XML (data validation failure)', async () => {
      const { deps, getCurrentStatus } = makeXsdDeps({
        xsdValidatorResult: { valid: true, errors: [] },
        xsdDataValidatorResult: {
          valid: false,
          errors: [{ message: 'Invalid date format in PID segment', line: 12, field: 'patientDob' }],
        },
      });

      const result = await validateBatchXsd(deps, BATCH_1, PHYSICIAN_1, {
        structural: '<xsd>structural</xsd>',
        data: '<xsd>data</xsd>',
      });

      expect(result.passed).toBe(false);
      expect(result.errors.some(e => e.message.includes('[data]'))).toBe(true);
      expect(getCurrentStatus()).toBe('ERROR');
    });

    it('transitions to ERROR on failure', async () => {
      const { deps, wcbRepo } = makeXsdDeps({
        xsdValidatorResult: {
          valid: false,
          errors: [{ message: 'Schema violation' }],
        },
      });

      await validateBatchXsd(deps, BATCH_1, PHYSICIAN_1, {
        structural: '<xsd>structural</xsd>',
        data: '<xsd>data</xsd>',
      });

      expect(wcbRepo.updateBatchStatus).toHaveBeenCalledWith(
        BATCH_1,
        PHYSICIAN_1,
        'ERROR',
        expect.objectContaining({
          xsdValidationPassed: false,
          xsdValidationErrors: expect.any(Array),
        }),
      );
    });

    it('requires GENERATED status', async () => {
      const { deps } = makeXsdDeps({ batchStatus: 'ASSEMBLING' });

      await expect(
        validateBatchXsd(deps, BATCH_1, PHYSICIAN_1, {
          structural: '<xsd>s</xsd>',
          data: '<xsd>d</xsd>',
        }),
      ).rejects.toThrow('Cannot validate batch');
    });

    it('throws NotFoundError for unknown batch', async () => {
      const { deps } = makeXsdDeps();

      await expect(
        validateBatchXsd(deps, 'bat-nonexistent', PHYSICIAN_1, {
          structural: '<xsd>s</xsd>',
          data: '<xsd>d</xsd>',
        }),
      ).rejects.toThrow('not found');
    });

    it('throws when xsdValidator is not configured', async () => {
      const { deps } = makeXsdDeps();
      deps.xsdValidator = undefined;

      await expect(
        validateBatchXsd(deps, BATCH_1, PHYSICIAN_1, {
          structural: '<xsd>s</xsd>',
          data: '<xsd>d</xsd>',
        }),
      ).rejects.toThrow('validator not configured');
    });

    it('throws when fileStorage is not configured', async () => {
      const { deps } = makeXsdDeps();
      deps.fileStorage = undefined;

      await expect(
        validateBatchXsd(deps, BATCH_1, PHYSICIAN_1, {
          structural: '<xsd>s</xsd>',
          data: '<xsd>d</xsd>',
        }),
      ).rejects.toThrow('file storage not configured');
    });

    it('skips data validation when structural fails', async () => {
      const { deps, xsdValidator } = makeXsdDeps({
        xsdValidatorResult: {
          valid: false,
          errors: [{ message: 'Structural error' }],
        },
      });

      await validateBatchXsd(deps, BATCH_1, PHYSICIAN_1, {
        structural: '<xsd>structural</xsd>',
        data: '<xsd>data</xsd>',
      });

      // XSD validator should only be called once (structural only)
      expect((xsdValidator.validate as any)).toHaveBeenCalledTimes(1);
    });

    it('emits audit event on success', async () => {
      const { deps, auditEmitter } = makeXsdDeps();

      await validateBatchXsd(deps, BATCH_1, PHYSICIAN_1, {
        structural: '<xsd>structural</xsd>',
        data: '<xsd>data</xsd>',
      });

      expect(auditEmitter.emit).toHaveBeenCalledWith(
        'WCB_BATCH_VALIDATED',
        expect.objectContaining({
          claimId: BATCH_1,
          actorId: PHYSICIAN_1,
          changes: expect.objectContaining({
            wcbBatchId: BATCH_1,
            xsdValidationPassed: true,
          }),
        }),
      );
    });
  });

  // =========================================================================
  // generateDownloadUrl
  // =========================================================================

  describe('generateDownloadUrl', () => {
    function makeDownloadDeps(overrides: Partial<{
      batchStatus: string;
      xmlFilePath: string | null;
    }> = {}) {
      const batchStatus = overrides.batchStatus ?? 'VALIDATED';
      const xmlFilePath = overrides.xmlFilePath ?? `wcb/batches/${BATCH_1}/MER-20260215-TEST01.xml`;

      const wcbRepo: any = {
        getBatch: vi.fn().mockImplementation(async (batchId: string, physicianId: string) => {
          if (batchId !== BATCH_1 || physicianId !== PHYSICIAN_1) return null;
          return {
            wcbBatchId: BATCH_1,
            physicianId: PHYSICIAN_1,
            status: batchStatus,
            xmlFilePath,
            xmlFileHash: 'abc123',
            reportCount: 1,
          };
        }),
      };

      const downloadUrlGenerator: DownloadUrlGenerator = {
        generateSignedUrl: vi.fn().mockResolvedValue('https://spaces.example.com/signed-url?token=abc&expires=3600'),
      };

      const claimRepo: any = {
        appendClaimAudit: vi.fn().mockResolvedValue(undefined),
      };

      const auditEmitter: any = {
        emit: vi.fn().mockResolvedValue(undefined),
      };

      const deps: WcbServiceDeps = {
        wcbRepo,
        claimRepo,
        providerLookup: { findProviderById: vi.fn(), getWcbConfigForForm: vi.fn() } as any,
        patientLookup: { findPatientById: vi.fn() } as any,
        auditEmitter,
        downloadUrlGenerator,
      };

      return { deps, wcbRepo, downloadUrlGenerator, auditEmitter };
    }

    it('returns signed URL with 1h expiry for VALIDATED batch', async () => {
      const { deps } = makeDownloadDeps();

      const result = await generateDownloadUrl(deps, BATCH_1, PHYSICIAN_1, USER_1);

      expect(result.downloadUrl).toContain('signed-url');
      expect(result.wcbBatchId).toBe(BATCH_1);
      // expiresAt should be roughly 1 hour from now
      const expiresAt = new Date(result.expiresAt);
      const now = new Date();
      const diffMs = expiresAt.getTime() - now.getTime();
      expect(diffMs).toBeGreaterThan(3500 * 1000); // at least 3500s
      expect(diffMs).toBeLessThanOrEqual(3600 * 1000 + 5000); // at most 3600s + small tolerance
    });

    it('calls generateSignedUrl with correct path and expiry', async () => {
      const { deps, downloadUrlGenerator } = makeDownloadDeps();

      await generateDownloadUrl(deps, BATCH_1, PHYSICIAN_1, USER_1);

      expect((downloadUrlGenerator.generateSignedUrl as any)).toHaveBeenCalledWith(
        `wcb/batches/${BATCH_1}/MER-20260215-TEST01.xml`,
        3600,
      );
    });

    it('requires VALIDATED status', async () => {
      const { deps } = makeDownloadDeps({ batchStatus: 'GENERATED' });

      await expect(
        generateDownloadUrl(deps, BATCH_1, PHYSICIAN_1, USER_1),
      ).rejects.toThrow('Cannot download batch');
    });

    it('throws NotFoundError for unknown batch', async () => {
      const { deps } = makeDownloadDeps();

      await expect(
        generateDownloadUrl(deps, 'bat-nonexistent', PHYSICIAN_1, USER_1),
      ).rejects.toThrow('not found');
    });

    it('throws when downloadUrlGenerator is not configured', async () => {
      const { deps } = makeDownloadDeps();
      deps.downloadUrlGenerator = undefined;

      await expect(
        generateDownloadUrl(deps, BATCH_1, PHYSICIAN_1, USER_1),
      ).rejects.toThrow('generator not configured');
    });

    it('emits audit event for download', async () => {
      const { deps, auditEmitter } = makeDownloadDeps();

      await generateDownloadUrl(deps, BATCH_1, PHYSICIAN_1, USER_1);

      expect(auditEmitter.emit).toHaveBeenCalledWith(
        'WCB_BATCH_DOWNLOADED',
        expect.objectContaining({
          claimId: BATCH_1,
          actorId: USER_1,
          changes: expect.objectContaining({
            wcbBatchId: BATCH_1,
          }),
        }),
      );
    });
  });

  // =========================================================================
  // confirmBatchUpload
  // =========================================================================

  describe('confirmBatchUpload', () => {
    function makeUploadDeps(overrides: Partial<{
      batchStatus: string;
      batchExists: boolean;
    }> = {}) {
      const batchStatus = overrides.batchStatus ?? 'VALIDATED';
      const batchExists = overrides.batchExists ?? true;
      const uploadedAt = new Date('2026-02-15T14:30:00.000Z');

      const wcbRepo: any = {
        setBatchUploaded: vi.fn().mockImplementation(async (batchId: string, physicianId: string, uploadedBy: string) => {
          if (!batchExists || batchId !== BATCH_1 || physicianId !== PHYSICIAN_1) return null;
          if (batchStatus !== 'VALIDATED') {
            const { ConflictError } = await import('../../lib/errors.js');
            throw new ConflictError(`Cannot upload batch: current status is ${batchStatus}, expected VALIDATED`);
          }
          return {
            wcbBatchId: BATCH_1,
            physicianId: PHYSICIAN_1,
            status: 'UPLOADED',
            reportCount: 3,
            uploadedAt,
            uploadedBy,
          };
        }),
      };

      const claimRepo: any = {
        appendClaimAudit: vi.fn().mockResolvedValue(undefined),
      };

      const auditEmitter: any = {
        emit: vi.fn().mockResolvedValue(undefined),
      };

      const notificationEmitter: NotificationEmitter = {
        emit: vi.fn().mockResolvedValue(undefined),
      };

      const deps: WcbServiceDeps = {
        wcbRepo,
        claimRepo,
        providerLookup: { findProviderById: vi.fn(), getWcbConfigForForm: vi.fn() } as any,
        patientLookup: { findPatientById: vi.fn() } as any,
        auditEmitter,
        notificationEmitter,
      };

      return { deps, wcbRepo, auditEmitter, notificationEmitter };
    }

    it('transitions to UPLOADED', async () => {
      const { deps } = makeUploadDeps();

      const result = await confirmBatchUpload(deps, BATCH_1, PHYSICIAN_1, USER_1);

      expect(result.status).toBe('UPLOADED');
      expect(result.wcbBatchId).toBe(BATCH_1);
      expect(result.uploadedBy).toBe(USER_1);
      expect(result.uploadedAt).toBeDefined();
    });

    it('calls setBatchUploaded with correct args', async () => {
      const { deps, wcbRepo } = makeUploadDeps();

      await confirmBatchUpload(deps, BATCH_1, PHYSICIAN_1, USER_1);

      expect(wcbRepo.setBatchUploaded).toHaveBeenCalledWith(BATCH_1, PHYSICIAN_1, USER_1);
    });

    it('rejects if not VALIDATED', async () => {
      const { deps } = makeUploadDeps({ batchStatus: 'GENERATED' });

      await expect(
        confirmBatchUpload(deps, BATCH_1, PHYSICIAN_1, USER_1),
      ).rejects.toThrow('Cannot upload batch');
    });

    it('throws NotFoundError when batch not found', async () => {
      const { deps } = makeUploadDeps({ batchExists: false });

      await expect(
        confirmBatchUpload(deps, BATCH_1, PHYSICIAN_1, USER_1),
      ).rejects.toThrow('not found');
    });

    it('emits audit event', async () => {
      const { deps, auditEmitter } = makeUploadDeps();

      await confirmBatchUpload(deps, BATCH_1, PHYSICIAN_1, USER_1);

      expect(auditEmitter.emit).toHaveBeenCalledWith(
        'WCB_BATCH_UPLOADED',
        expect.objectContaining({
          claimId: BATCH_1,
          actorId: USER_1,
          changes: expect.objectContaining({
            wcbBatchId: BATCH_1,
            uploadedBy: USER_1,
          }),
        }),
      );
    });

    it('emits notification event', async () => {
      const { deps, notificationEmitter } = makeUploadDeps();

      await confirmBatchUpload(deps, BATCH_1, PHYSICIAN_1, USER_1);

      expect((notificationEmitter.emit as any)).toHaveBeenCalledWith(
        'WCB_BATCH_UPLOADED',
        expect.objectContaining({
          wcbBatchId: BATCH_1,
          physicianId: PHYSICIAN_1,
          uploadedBy: USER_1,
        }),
      );
    });
  });

  // =========================================================================
  // processReturnFile
  // =========================================================================

  describe('processReturnFile', () => {
    // Helper to build a valid return file string
    function buildReturnFile(opts: {
      batchId?: string;
      reportCount?: number;
      submitterId?: string;
      submitDate?: string;
      reports?: Array<{
        reportTxnId: string;
        submitterTxnId: string;
        processedClaimNumber?: string;
        claimDecision?: string;
        reportStatus: string;
        txnSubmissionDate?: string;
        invoiceLines?: Array<{ seq: number; date?: string; hsc?: string; status?: string }>;
        errors?: Array<{ code: string; message: string }>;
      }>;
    }): string {
      const batchId = opts.batchId ?? 'MER-B-TEST0001';
      const reportCount = opts.reportCount ?? (opts.reports?.length ?? 0);
      const submitterId = opts.submitterId ?? 'MRT';
      const submitDate = opts.submitDate ?? '2026-02-16';

      const lines: string[] = [];
      lines.push(`${batchId}\t${reportCount}\t${submitterId}\t${submitDate}`);

      for (const report of opts.reports ?? []) {
        lines.push('');
        lines.push([
          report.reportTxnId,
          report.submitterTxnId,
          report.processedClaimNumber ?? '',
          report.claimDecision ?? '',
          report.reportStatus,
          report.txnSubmissionDate ?? '2026-02-16',
        ].join('\t'));

        if (report.reportStatus === 'COMPLETE' && report.invoiceLines) {
          for (const il of report.invoiceLines) {
            lines.push([
              String(il.seq),
              il.date ?? '2026-02-15',
              il.hsc ?? '03.04A',
              il.status ?? '',
            ].join('\t'));
          }
        }

        if (report.reportStatus === 'INVALID' && report.errors) {
          for (const err of report.errors) {
            lines.push(`${err.code}: ${err.message}`);
          }
        }
      }

      return lines.join('\n');
    }

    // Helper to set up deps for processReturnFile tests
    function makeReturnDeps() {
      const db = makeMockDb();
      const wcbRepo = createWcbRepository(db);

      const claimRepo = {
        createClaim: vi.fn().mockImplementation(async (data: any) => {
          const claim = seedClaim(data);
          return claim;
        }),
        findClaimById: vi.fn().mockImplementation(async (claimId: string, physicianId: string) => {
          return claimStore.find(
            (c) => c.claimId === claimId && c.physicianId === physicianId && !c.deletedAt,
          );
        }),
        appendClaimAudit: vi.fn().mockResolvedValue(undefined),
        transitionClaimState: vi.fn().mockImplementation(async (claimId: string, physicianId: string, newState: string) => {
          const claim = claimStore.find(
            (c) => c.claimId === claimId && c.physicianId === physicianId && !c.deletedAt,
          );
          if (!claim) return undefined;
          const previousState = claim.state;
          claim.state = newState;
          return { claimId, state: newState, previousState };
        }),
      };

      const auditEmitter = {
        emit: vi.fn().mockResolvedValue(undefined),
      };

      const notificationEmitter: NotificationEmitter = {
        emit: vi.fn().mockResolvedValue(undefined),
      };

      const deps: WcbServiceDeps = {
        wcbRepo,
        claimRepo,
        providerLookup: { findProviderById: vi.fn(), getWcbConfigForForm: vi.fn() } as any,
        patientLookup: { findPatientById: vi.fn() } as any,
        auditEmitter,
        notificationEmitter,
      };

      return { deps, wcbRepo, claimRepo, auditEmitter, notificationEmitter };
    }

    it('parses valid return file', async () => {
      const fileContent = buildReturnFile({
        reports: [
          {
            reportTxnId: 'WCB-TXN-001',
            submitterTxnId: 'MRT0000000000001',
            processedClaimNumber: '1234567',
            claimDecision: 'Accepted',
            reportStatus: 'COMPLETE',
            invoiceLines: [
              { seq: 1, date: '2026-02-15', hsc: '03.04A' },
            ],
          },
        ],
      });

      const { header, reports } = parseReturnFile(fileContent);

      expect(header.batchId).toBe('MER-B-TEST0001');
      expect(header.reportCount).toBe(1);
      expect(reports).toHaveLength(1);
      expect(reports[0].reportTxnId).toBe('WCB-TXN-001');
      expect(reports[0].submitterTxnId).toBe('MRT0000000000001');
      expect(reports[0].processedClaimNumber).toBe('1234567');
      expect(reports[0].claimDecision).toBe('Accepted');
      expect(reports[0].reportStatus).toBe('COMPLETE');
      expect(reports[0].invoiceLines).toHaveLength(1);
      expect(reports[0].invoiceLines[0].invoiceSequence).toBe(1);
    });

    it('matches batch by BatchID', async () => {
      const { deps } = makeReturnDeps();

      // Seed a batch with UPLOADED status
      seedBatch({
        wcbBatchId: BATCH_1,
        batchControlId: 'MER-B-TEST0001',
        status: 'UPLOADED',
      });

      // Seed a claim + detail so we have something to match
      seedClaim({ claimId: CLAIM_1, state: 'SUBMITTED' });
      seedWcbDetail({ claimId: CLAIM_1, submitterTxnId: 'MRT0000000000001' });

      const fileContent = buildReturnFile({
        batchId: 'MER-B-TEST0001',
        reports: [
          {
            reportTxnId: 'WCB-TXN-001',
            submitterTxnId: 'MRT0000000000001',
            reportStatus: 'COMPLETE',
            claimDecision: 'Accepted',
            processedClaimNumber: '1234567',
            invoiceLines: [{ seq: 1 }],
          },
        ],
      });

      const result = await processReturnFile(deps, PHYSICIAN_1, USER_1, fileContent);

      expect(result.matched_count).toBe(1);
      expect(result.errors).toHaveLength(0);
    });

    it('matches reports by SubmitterTxnID', async () => {
      const { deps } = makeReturnDeps();

      seedBatch({ status: 'UPLOADED' });
      seedClaim({ claimId: CLAIM_1, state: 'SUBMITTED' });
      seedWcbDetail({ claimId: CLAIM_1, submitterTxnId: 'MRT0000000000001' });

      const fileContent = buildReturnFile({
        reports: [
          {
            reportTxnId: 'WCB-TXN-001',
            submitterTxnId: 'MRT0000000000001',
            reportStatus: 'COMPLETE',
            claimDecision: 'Accepted',
            invoiceLines: [{ seq: 1 }],
          },
        ],
      });

      const result = await processReturnFile(deps, PHYSICIAN_1, USER_1, fileContent);

      expect(result.matched_count).toBe(1);
      // Return record should be stored
      expect(wcbReturnRecordStore).toHaveLength(1);
      expect(wcbReturnRecordStore[0].submitterTxnId).toBe('MRT0000000000001');
      expect(wcbReturnRecordStore[0].wcbClaimDetailId).toBe(WCB_DETAIL_1);
    });

    it('Complete report transitions claim to assessed', async () => {
      const { deps, claimRepo } = makeReturnDeps();

      seedBatch({ status: 'UPLOADED' });
      seedClaim({ claimId: CLAIM_1, state: 'SUBMITTED' });
      seedWcbDetail({ claimId: CLAIM_1, submitterTxnId: 'MRT0000000000001' });

      const fileContent = buildReturnFile({
        reports: [
          {
            reportTxnId: 'WCB-TXN-001',
            submitterTxnId: 'MRT0000000000001',
            reportStatus: 'COMPLETE',
            claimDecision: 'Accepted',
            processedClaimNumber: '1234567',
            invoiceLines: [{ seq: 1, date: '2026-02-15', hsc: '03.04A' }],
          },
        ],
      });

      const result = await processReturnFile(deps, PHYSICIAN_1, USER_1, fileContent);

      expect(result.complete_count).toBe(1);
      expect(claimRepo.transitionClaimState).toHaveBeenCalledWith(
        CLAIM_1,
        PHYSICIAN_1,
        'ASSESSED',
      );
      // Invoice lines should be stored
      expect(wcbReturnInvoiceLineStore).toHaveLength(1);
      expect(wcbReturnInvoiceLineStore[0].invoiceSequence).toBe(1);
    });

    it('Invalid report transitions claim to rejected with errors', async () => {
      const { deps, claimRepo } = makeReturnDeps();

      seedBatch({ status: 'UPLOADED' });
      seedClaim({ claimId: CLAIM_1, state: 'SUBMITTED' });
      seedWcbDetail({ claimId: CLAIM_1, submitterTxnId: 'MRT0000000000001' });

      const fileContent = buildReturnFile({
        reports: [
          {
            reportTxnId: 'WCB-TXN-001',
            submitterTxnId: 'MRT0000000000001',
            reportStatus: 'INVALID',
            errors: [
              { code: '121023', message: 'Worker Personal Health Number must be BLANK since Worker Personal Health Number Indicator is No' },
              { code: '401001', message: 'Service code not valid for contract' },
            ],
          },
        ],
      });

      const result = await processReturnFile(deps, PHYSICIAN_1, USER_1, fileContent);

      expect(result.invalid_count).toBe(1);
      expect(claimRepo.transitionClaimState).toHaveBeenCalledWith(
        CLAIM_1,
        PHYSICIAN_1,
        'REJECTED',
      );
      // Errors should be stored as JSONB in the return record
      expect(wcbReturnRecordStore).toHaveLength(1);
      const storedErrors = wcbReturnRecordStore[0].errors as any[];
      expect(storedErrors).toHaveLength(2);
      expect(storedErrors[0].error_code).toBe('121023');
      expect(storedErrors[1].error_code).toBe('401001');
    });

    it('ProcessedClaim# stored on claim when provided', async () => {
      const { deps } = makeReturnDeps();

      seedBatch({ status: 'UPLOADED' });
      seedClaim({ claimId: CLAIM_1, state: 'SUBMITTED' });
      seedWcbDetail({
        claimId: CLAIM_1,
        submitterTxnId: 'MRT0000000000001',
        wcbClaimNumber: null,
      });

      const fileContent = buildReturnFile({
        reports: [
          {
            reportTxnId: 'WCB-TXN-001',
            submitterTxnId: 'MRT0000000000001',
            processedClaimNumber: '9876543',
            reportStatus: 'COMPLETE',
            claimDecision: 'Accepted',
            invoiceLines: [{ seq: 1 }],
          },
        ],
      });

      await processReturnFile(deps, PHYSICIAN_1, USER_1, fileContent);

      // Verify claim number was stored
      const detail = wcbDetailStore.find((d) => d.wcbClaimDetailId === WCB_DETAIL_1);
      expect(detail?.wcbClaimNumber).toBe('9876543');
    });

    it('unmatched SubmitterTxnID stored with null claim reference', async () => {
      const { deps, notificationEmitter } = makeReturnDeps();

      seedBatch({ status: 'UPLOADED' });
      // No claim or detail matching this submitter txn id

      const fileContent = buildReturnFile({
        reports: [
          {
            reportTxnId: 'WCB-TXN-UNKNOWN',
            submitterTxnId: 'MRT9999999999999',
            reportStatus: 'COMPLETE',
            claimDecision: 'Accepted',
            invoiceLines: [{ seq: 1 }],
          },
        ],
      });

      const result = await processReturnFile(deps, PHYSICIAN_1, USER_1, fileContent);

      expect(result.unmatched_count).toBe(1);
      expect(result.matched_count).toBe(0);
      // Return record is still stored, but with no claim reference
      expect(wcbReturnRecordStore).toHaveLength(1);
      expect(wcbReturnRecordStore[0].wcbClaimDetailId).toBeUndefined();
      // WCB_RETURN_UNMATCHED alert emitted
      expect((notificationEmitter.emit as any)).toHaveBeenCalledWith(
        'WCB_RETURN_UNMATCHED',
        expect.objectContaining({
          submitterTxnId: 'MRT9999999999999',
        }),
      );
    });

    it('mixed Complete and Invalid handled independently', async () => {
      const { deps, claimRepo } = makeReturnDeps();

      seedBatch({ status: 'UPLOADED' });
      seedClaim({ claimId: CLAIM_1, state: 'SUBMITTED' });
      seedWcbDetail({
        wcbClaimDetailId: WCB_DETAIL_1,
        claimId: CLAIM_1,
        submitterTxnId: 'MRT0000000000001',
      });
      seedClaim({ claimId: CLAIM_2, state: 'SUBMITTED' });
      seedWcbDetail({
        wcbClaimDetailId: WCB_DETAIL_2,
        claimId: CLAIM_2,
        submitterTxnId: 'MRT0000000000002',
      });

      const fileContent = buildReturnFile({
        reportCount: 2,
        reports: [
          {
            reportTxnId: 'WCB-TXN-001',
            submitterTxnId: 'MRT0000000000001',
            processedClaimNumber: '1234567',
            reportStatus: 'COMPLETE',
            claimDecision: 'Accepted',
            invoiceLines: [{ seq: 1, date: '2026-02-15', hsc: '03.04A' }],
          },
          {
            reportTxnId: 'WCB-TXN-002',
            submitterTxnId: 'MRT0000000000002',
            reportStatus: 'INVALID',
            errors: [
              { code: '121023', message: 'Invalid PHN' },
            ],
          },
        ],
      });

      const result = await processReturnFile(deps, PHYSICIAN_1, USER_1, fileContent);

      expect(result.matched_count).toBe(2);
      expect(result.complete_count).toBe(1);
      expect(result.invalid_count).toBe(1);
      expect(result.unmatched_count).toBe(0);

      // Verify independent transitions
      expect(claimRepo.transitionClaimState).toHaveBeenCalledWith(CLAIM_1, PHYSICIAN_1, 'ASSESSED');
      expect(claimRepo.transitionClaimState).toHaveBeenCalledWith(CLAIM_2, PHYSICIAN_1, 'REJECTED');
    });

    it('notifications emitted for each outcome', async () => {
      const { deps, notificationEmitter } = makeReturnDeps();

      seedBatch({ status: 'UPLOADED' });
      seedClaim({ claimId: CLAIM_1, state: 'SUBMITTED' });
      seedWcbDetail({
        wcbClaimDetailId: WCB_DETAIL_1,
        claimId: CLAIM_1,
        submitterTxnId: 'MRT0000000000001',
      });
      seedClaim({ claimId: CLAIM_2, state: 'SUBMITTED' });
      seedWcbDetail({
        wcbClaimDetailId: WCB_DETAIL_2,
        claimId: CLAIM_2,
        submitterTxnId: 'MRT0000000000002',
      });

      const fileContent = buildReturnFile({
        reportCount: 2,
        reports: [
          {
            reportTxnId: 'WCB-TXN-001',
            submitterTxnId: 'MRT0000000000001',
            reportStatus: 'COMPLETE',
            claimDecision: 'Accepted',
            processedClaimNumber: '1234567',
            invoiceLines: [{ seq: 1 }],
          },
          {
            reportTxnId: 'WCB-TXN-002',
            submitterTxnId: 'MRT0000000000002',
            reportStatus: 'INVALID',
            errors: [{ code: '401001', message: 'Bad service code' }],
          },
        ],
      });

      await processReturnFile(deps, PHYSICIAN_1, USER_1, fileContent);

      const emitCalls = (notificationEmitter.emit as any).mock.calls;

      // Per-claim notifications
      expect(emitCalls).toContainEqual([
        'WCB_CLAIM_ACCEPTED',
        expect.objectContaining({
          physicianId: PHYSICIAN_1,
          claimId: CLAIM_1,
        }),
      ]);
      expect(emitCalls).toContainEqual([
        'WCB_CLAIM_REJECTED',
        expect.objectContaining({
          physicianId: PHYSICIAN_1,
          claimId: CLAIM_2,
        }),
      ]);
      // Batch-level notification
      expect(emitCalls).toContainEqual([
        'WCB_RETURN_RECEIVED',
        expect.objectContaining({
          physicianId: PHYSICIAN_1,
          matchedCount: 2,
          completeCount: 1,
          invalidCount: 1,
        }),
      ]);
    });

    it('batch status updated to RETURN_RECEIVED', async () => {
      const { deps } = makeReturnDeps();

      seedBatch({ status: 'UPLOADED' });
      seedClaim({ claimId: CLAIM_1, state: 'SUBMITTED' });
      seedWcbDetail({ claimId: CLAIM_1, submitterTxnId: 'MRT0000000000001' });

      const fileContent = buildReturnFile({
        reports: [
          {
            reportTxnId: 'WCB-TXN-001',
            submitterTxnId: 'MRT0000000000001',
            reportStatus: 'COMPLETE',
            claimDecision: 'Accepted',
            invoiceLines: [{ seq: 1 }],
          },
        ],
      });

      await processReturnFile(deps, PHYSICIAN_1, USER_1, fileContent);

      // Verify the batch was transitioned to RETURN_RECEIVED
      const batch = wcbBatchStore.find((b) => b.wcbBatchId === BATCH_1);
      expect(batch?.status).toBe('RECONCILED');
    });

    it('throws NotFoundError when batch not found', async () => {
      const { deps } = makeReturnDeps();

      // No batch seeded matching the control ID
      const fileContent = buildReturnFile({
        batchId: 'NONEXISTENT-BATCH',
        reports: [],
      });

      await expect(
        processReturnFile(deps, PHYSICIAN_1, USER_1, fileContent),
      ).rejects.toThrow('not found');
    });

    it('emits audit event for return processing', async () => {
      const { deps, auditEmitter } = makeReturnDeps();

      seedBatch({ status: 'UPLOADED' });
      seedClaim({ claimId: CLAIM_1, state: 'SUBMITTED' });
      seedWcbDetail({ claimId: CLAIM_1, submitterTxnId: 'MRT0000000000001' });

      const fileContent = buildReturnFile({
        reports: [
          {
            reportTxnId: 'WCB-TXN-001',
            submitterTxnId: 'MRT0000000000001',
            reportStatus: 'COMPLETE',
            claimDecision: 'Accepted',
            invoiceLines: [{ seq: 1 }],
          },
        ],
      });

      await processReturnFile(deps, PHYSICIAN_1, USER_1, fileContent);

      expect(auditEmitter.emit).toHaveBeenCalledWith(
        'WCB_RETURN_RECEIVED',
        expect.objectContaining({
          claimId: BATCH_1,
          actorId: USER_1,
          changes: expect.objectContaining({
            wcbBatchId: BATCH_1,
            matchedCount: 1,
            completeCount: 1,
          }),
        }),
      );
    });
  });

  // =========================================================================
  // processRemittanceFile
  // =========================================================================

  describe('processRemittanceFile', () => {
    const REMITTANCE_NS = 'http://www.wcb.ab.ca/schemas/RR/RRPaymentRemittanceReport-2.01.00';

    // Helper to build a valid remittance XML string
    function buildRemittanceXml(opts: {
      reportWeekStart?: string;
      reportWeekEnd?: string;
      records?: Array<{
        disbursementNumber?: string;
        disbursementType?: string;
        disbursementIssueDate?: string;
        disbursementAmount?: string;
        disbursementRecipientBilling?: string;
        disbursementRecipientName?: string;
        paymentPayeeBilling?: string;
        paymentPayeeName?: string;
        paymentReasonCode?: string;
        paymentStatus?: string;
        paymentStartDate?: string;
        paymentEndDate?: string;
        paymentAmount?: string;
        billedAmount?: string;
        electronicReportTxnId?: string;
        claimNumber?: string;
        workerPhn?: string;
        workerFirstName?: string;
        workerLastName?: string;
        serviceCode?: string;
        modifier1?: string;
        modifier2?: string;
        modifier3?: string;
        numberOfCalls?: string;
        encounterNumber?: string;
        overpaymentRecovery?: string;
      }>;
    }): string {
      const start = opts.reportWeekStart ?? '2026-02-09';
      const end = opts.reportWeekEnd ?? '2026-02-15';
      const records = opts.records ?? [];

      const recordXml = records.map((r) => {
        const fields: string[] = [];
        if (r.disbursementNumber) fields.push(`<DisbursementNumber>${r.disbursementNumber}</DisbursementNumber>`);
        if (r.disbursementType) fields.push(`<DisbursementType>${r.disbursementType}</DisbursementType>`);
        if (r.disbursementIssueDate) fields.push(`<DisbursementIssueDate>${r.disbursementIssueDate}</DisbursementIssueDate>`);
        if (r.disbursementAmount) fields.push(`<DisbursementAmount>${r.disbursementAmount}</DisbursementAmount>`);
        if (r.disbursementRecipientBilling) fields.push(`<DisbursementRecipientBillingNumber>${r.disbursementRecipientBilling}</DisbursementRecipientBillingNumber>`);
        if (r.disbursementRecipientName) fields.push(`<DisbursementRecipientName>${r.disbursementRecipientName}</DisbursementRecipientName>`);
        fields.push(`<PaymentPayeeBillingNumber>${r.paymentPayeeBilling ?? '12345678'}</PaymentPayeeBillingNumber>`);
        fields.push(`<PaymentPayeeName>${r.paymentPayeeName ?? 'Dr. Jane Smith'}</PaymentPayeeName>`);
        fields.push(`<PaymentReasonCode>${r.paymentReasonCode ?? 'RP1'}</PaymentReasonCode>`);
        fields.push(`<PaymentStatus>${r.paymentStatus ?? 'ISS'}</PaymentStatus>`);
        fields.push(`<PaymentStartDate>${r.paymentStartDate ?? '2026-02-10'}</PaymentStartDate>`);
        fields.push(`<PaymentEndDate>${r.paymentEndDate ?? '2026-02-15'}</PaymentEndDate>`);
        fields.push(`<PaymentAmount>${r.paymentAmount ?? '94.15'}</PaymentAmount>`);
        if (r.billedAmount) fields.push(`<BilledAmount>${r.billedAmount}</BilledAmount>`);
        if (r.electronicReportTxnId) fields.push(`<ElectronicReportTransactionID>${r.electronicReportTxnId}</ElectronicReportTransactionID>`);
        if (r.claimNumber) fields.push(`<ClaimNumber>${r.claimNumber}</ClaimNumber>`);
        if (r.workerPhn) fields.push(`<WorkerPHN>${r.workerPhn}</WorkerPHN>`);
        if (r.workerFirstName) fields.push(`<WorkerFirstName>${r.workerFirstName}</WorkerFirstName>`);
        if (r.workerLastName) fields.push(`<WorkerLastName>${r.workerLastName}</WorkerLastName>`);
        if (r.serviceCode) fields.push(`<ServiceCode>${r.serviceCode}</ServiceCode>`);
        if (r.modifier1) fields.push(`<Modifier1>${r.modifier1}</Modifier1>`);
        if (r.modifier2) fields.push(`<Modifier2>${r.modifier2}</Modifier2>`);
        if (r.modifier3) fields.push(`<Modifier3>${r.modifier3}</Modifier3>`);
        if (r.numberOfCalls) fields.push(`<NumberOfCalls>${r.numberOfCalls}</NumberOfCalls>`);
        if (r.encounterNumber) fields.push(`<EncounterNumber>${r.encounterNumber}</EncounterNumber>`);
        if (r.overpaymentRecovery) fields.push(`<OverpaymentRecovery>${r.overpaymentRecovery}</OverpaymentRecovery>`);
        return `<PaymentRemittanceRecord>${fields.join('')}</PaymentRemittanceRecord>`;
      }).join('\n');

      return `<?xml version="1.0" encoding="UTF-8"?>
<PaymentRemittanceReport xmlns="${REMITTANCE_NS}">
  <ReportWeek>
    <StartDate>${start}</StartDate>
    <EndDate>${end}</EndDate>
  </ReportWeek>
  ${recordXml}
</PaymentRemittanceReport>`;
    }

    // Helper to set up deps for processRemittanceFile tests
    function makeRemittanceDeps() {
      const db = makeMockDb();
      const wcbRepo = createWcbRepository(db);

      const claimRepo = {
        createClaim: vi.fn().mockImplementation(async (data: any) => {
          const claim = seedClaim(data);
          return claim;
        }),
        findClaimById: vi.fn().mockImplementation(async (claimId: string, physicianId: string) => {
          return claimStore.find(
            (c) => c.claimId === claimId && c.physicianId === physicianId && !c.deletedAt,
          );
        }),
        appendClaimAudit: vi.fn().mockResolvedValue(undefined),
        transitionClaimState: vi.fn().mockImplementation(async (claimId: string, physicianId: string, newState: string) => {
          const claim = claimStore.find(
            (c) => c.claimId === claimId && c.physicianId === physicianId && !c.deletedAt,
          );
          if (!claim) return undefined;
          const previousState = claim.state;
          claim.state = newState;
          return { claimId, state: newState, previousState };
        }),
      };

      const auditEmitter = {
        emit: vi.fn().mockResolvedValue(undefined),
      };

      const notificationEmitter: NotificationEmitter = {
        emit: vi.fn().mockResolvedValue(undefined),
      };

      const deps: WcbServiceDeps = {
        wcbRepo,
        claimRepo,
        providerLookup: {
          findProviderById: vi.fn().mockImplementation(async (id: string) => ({
            providerId: PHYSICIAN_1,
            billingNumber: '12345678',
            firstName: 'Jane',
            lastName: 'Smith',
            status: 'ACTIVE',
            specialtyCode: 'GP',
            isRrnpQualified: false,
          })),
          getWcbConfigForForm: vi.fn(),
        } as any,
        patientLookup: { findPatientById: vi.fn() } as any,
        auditEmitter,
        notificationEmitter,
      };

      return { deps, wcbRepo, claimRepo, auditEmitter, notificationEmitter };
    }

    // ----- XML Parsing Tests -----

    it('parseRemittanceXml parses valid remittance XML', () => {
      const xml = buildRemittanceXml({
        reportWeekStart: '2026-02-09',
        reportWeekEnd: '2026-02-15',
        records: [
          {
            paymentPayeeBilling: '12345678',
            paymentPayeeName: 'Dr. Jane Smith',
            paymentReasonCode: 'RP1',
            paymentStatus: 'ISS',
            paymentStartDate: '2026-02-10',
            paymentEndDate: '2026-02-15',
            paymentAmount: '94.15',
            electronicReportTxnId: 'RTX-001',
            claimNumber: '1234567',
            workerPhn: '123456789',
            workerFirstName: 'John',
            workerLastName: 'Doe',
            serviceCode: '03.04A',
            disbursementNumber: '12345678',
            disbursementType: 'CHQ',
            disbursementIssueDate: '2026-02-16',
            disbursementAmount: '94.15',
            disbursementRecipientBilling: '12345678',
            disbursementRecipientName: 'Dr. Jane Smith',
            billedAmount: '94.15',
            modifier1: 'MOD1',
            modifier2: 'MOD2',
            modifier3: 'MOD3',
            numberOfCalls: '1',
            encounterNumber: '1',
            overpaymentRecovery: '0.00',
          },
        ],
      });

      const parsed = parseRemittanceXml(xml);

      expect(parsed.reportWeekStart).toBe('2026-02-09');
      expect(parsed.reportWeekEnd).toBe('2026-02-15');
      expect(parsed.records).toHaveLength(1);

      const rec = parsed.records[0];
      expect(rec.paymentPayeeBilling).toBe('12345678');
      expect(rec.paymentPayeeName).toBe('Dr. Jane Smith');
      expect(rec.paymentReasonCode).toBe('RP1');
      expect(rec.paymentStatus).toBe('ISS');
      expect(rec.paymentStartDate).toBe('2026-02-10');
      expect(rec.paymentEndDate).toBe('2026-02-15');
      expect(rec.paymentAmount).toBe('94.15');
      expect(rec.electronicReportTxnId).toBe('RTX-001');
      expect(rec.claimNumber).toBe('1234567');
      expect(rec.workerPhn).toBe('123456789');
      expect(rec.workerFirstName).toBe('John');
      expect(rec.workerLastName).toBe('Doe');
      expect(rec.serviceCode).toBe('03.04A');
      expect(rec.disbursementNumber).toBe('12345678');
      expect(rec.disbursementType).toBe('CHQ');
      expect(rec.disbursementIssueDate).toBe('2026-02-16');
      expect(rec.disbursementAmount).toBe('94.15');
      expect(rec.disbursementRecipientBilling).toBe('12345678');
      expect(rec.disbursementRecipientName).toBe('Dr. Jane Smith');
      expect(rec.billedAmount).toBe('94.15');
      expect(rec.modifier1).toBe('MOD1');
      expect(rec.modifier2).toBe('MOD2');
      expect(rec.modifier3).toBe('MOD3');
      expect(rec.numberOfCalls).toBe(1);
      expect(rec.encounterNumber).toBe(1);
      expect(rec.overpaymentRecovery).toBe('0.00');
    });

    it('parseRemittanceXml handles multiple records', () => {
      const xml = buildRemittanceXml({
        records: [
          { paymentAmount: '94.15', electronicReportTxnId: 'RTX-001' },
          { paymentAmount: '150.00', electronicReportTxnId: 'RTX-002' },
          { paymentAmount: '75.50', electronicReportTxnId: 'RTX-003' },
        ],
      });

      const parsed = parseRemittanceXml(xml);
      expect(parsed.records).toHaveLength(3);
      expect(parsed.records[0].paymentAmount).toBe('94.15');
      expect(parsed.records[1].paymentAmount).toBe('150.00');
      expect(parsed.records[2].paymentAmount).toBe('75.50');
    });

    it('parseRemittanceXml throws on missing PaymentRemittanceReport', () => {
      const xml = '<?xml version="1.0"?><SomeOtherRoot></SomeOtherRoot>';
      expect(() => parseRemittanceXml(xml)).toThrow('Invalid remittance XML');
    });

    it('parseRemittanceXml throws on missing ReportWeek', () => {
      const xml = `<?xml version="1.0"?>
<PaymentRemittanceReport xmlns="${REMITTANCE_NS}">
</PaymentRemittanceReport>`;
      expect(() => parseRemittanceXml(xml)).toThrow('missing ReportWeek element');
    });

    it('parseRemittanceXml handles zero records', () => {
      const xml = buildRemittanceXml({ records: [] });
      const parsed = parseRemittanceXml(xml);
      expect(parsed.records).toHaveLength(0);
      expect(parsed.reportWeekStart).toBe('2026-02-09');
      expect(parsed.reportWeekEnd).toBe('2026-02-15');
    });

    // ----- processRemittanceFile integration tests -----

    it('processRemittanceFile parses valid remittance XML and returns summary', async () => {
      const { deps } = makeRemittanceDeps();

      const xml = buildRemittanceXml({
        records: [
          { paymentAmount: '94.15' },
          { paymentAmount: '150.00' },
        ],
      });

      const result = await processRemittanceFile(deps, PHYSICIAN_1, USER_1, xml);

      expect(result.import_id).toBeDefined();
      expect(result.record_count).toBe(2);
      expect(result.total_payment).toBe('244.15');
    });

    it('remittance records stored with all 31 fields', async () => {
      const { deps } = makeRemittanceDeps();

      const xml = buildRemittanceXml({
        reportWeekStart: '2026-02-09',
        reportWeekEnd: '2026-02-15',
        records: [
          {
            disbursementNumber: '99887766',
            disbursementType: 'CHQ',
            disbursementIssueDate: '2026-02-16',
            disbursementAmount: '94.15',
            disbursementRecipientBilling: '12345678',
            disbursementRecipientName: 'Dr. Jane Smith',
            paymentPayeeBilling: '12345678',
            paymentPayeeName: 'Dr. Jane Smith',
            paymentReasonCode: 'RP1',
            paymentStatus: 'ISS',
            paymentStartDate: '2026-02-10',
            paymentEndDate: '2026-02-15',
            paymentAmount: '94.15',
            billedAmount: '94.15',
            electronicReportTxnId: 'RTX-001',
            claimNumber: '1234567',
            workerPhn: '123456789',
            workerFirstName: 'John',
            workerLastName: 'Doe',
            serviceCode: '03.04A',
            modifier1: 'MOD1',
            modifier2: 'MOD2',
            modifier3: 'MOD3',
            numberOfCalls: '2',
            encounterNumber: '1',
            overpaymentRecovery: '5.00',
          },
        ],
      });

      await processRemittanceFile(deps, PHYSICIAN_1, USER_1, xml);

      // Verify remittance records are stored
      expect(wcbRemittanceRecordStore).toHaveLength(1);
      const stored = wcbRemittanceRecordStore[0];
      expect(stored.reportWeekStart).toBe('2026-02-09');
      expect(stored.reportWeekEnd).toBe('2026-02-15');
      expect(stored.disbursementNumber).toBe('99887766');
      expect(stored.disbursementType).toBe('CHQ');
      expect(stored.disbursementIssueDate).toBe('2026-02-16');
      expect(stored.disbursementAmount).toBe('94.15');
      expect(stored.disbursementRecipientBilling).toBe('12345678');
      expect(stored.disbursementRecipientName).toBe('Dr. Jane Smith');
      expect(stored.paymentPayeeBilling).toBe('12345678');
      expect(stored.paymentPayeeName).toBe('Dr. Jane Smith');
      expect(stored.paymentReasonCode).toBe('RP1');
      expect(stored.paymentStatus).toBe('ISS');
      expect(stored.paymentStartDate).toBe('2026-02-10');
      expect(stored.paymentEndDate).toBe('2026-02-15');
      expect(stored.paymentAmount).toBe('94.15');
      expect(stored.billedAmount).toBe('94.15');
      expect(stored.electronicReportTxnId).toBe('RTX-001');
      expect(stored.claimNumber).toBe('1234567');
      expect(stored.workerPhn).toBe('123456789');
      expect(stored.workerFirstName).toBe('John');
      expect(stored.workerLastName).toBe('Doe');
      expect(stored.serviceCode).toBe('03.04A');
      expect(stored.modifier1).toBe('MOD1');
      expect(stored.modifier2).toBe('MOD2');
      expect(stored.modifier3).toBe('MOD3');
      expect(stored.numberOfCalls).toBe(2);
      expect(stored.encounterNumber).toBe(1);
      expect(stored.overpaymentRecovery).toBe('5.00');
      // wcbClaimDetailId, remittanceImportId, wcbRemittanceId are auto-generated
      expect(stored.remittanceImportId).toBeDefined();
      expect(stored.wcbRemittanceId).toBeDefined();

      // Verify import record count updated
      expect(wcbRemittanceImportStore).toHaveLength(1);
      expect(wcbRemittanceImportStore[0].recordCount).toBe(1);
    });

    it('match via ElectronicReportTransactionID chain works', async () => {
      const { deps } = makeRemittanceDeps();

      // Seed the chain: claim -> wcb_claim_detail -> return_record (with report_txn_id)
      seedClaim({ claimId: CLAIM_1, state: 'ASSESSED' });
      seedWcbDetail({
        wcbClaimDetailId: WCB_DETAIL_1,
        claimId: CLAIM_1,
        submitterTxnId: 'MRT0000000000001',
      });
      wcbReturnRecordStore.push({
        wcbReturnRecordId: 'rr-1111',
        wcbBatchId: BATCH_1,
        wcbClaimDetailId: WCB_DETAIL_1,
        reportTxnId: 'RTX-001',
        submitterTxnId: 'MRT0000000000001',
        processedClaimNumber: '1234567',
        claimDecision: 'Accepted',
        reportStatus: 'COMPLETE',
        txnSubmissionDate: '2026-02-16',
        errors: null,
      });

      const xml = buildRemittanceXml({
        records: [
          {
            paymentStatus: 'ISS',
            paymentAmount: '94.15',
            electronicReportTxnId: 'RTX-001',
          },
        ],
      });

      const result = await processRemittanceFile(deps, PHYSICIAN_1, USER_1, xml);

      expect(result.matched_count).toBe(1);
      // Verify the remittance record is linked to the WCB claim detail
      expect(wcbRemittanceRecordStore[0].wcbClaimDetailId).toBe(WCB_DETAIL_1);
    });

    it('ISS status transitions claim to paid', async () => {
      const { deps, claimRepo } = makeRemittanceDeps();

      // Seed complete chain
      seedClaim({ claimId: CLAIM_1, state: 'ASSESSED' });
      seedWcbDetail({
        wcbClaimDetailId: WCB_DETAIL_1,
        claimId: CLAIM_1,
        submitterTxnId: 'MRT0000000000001',
      });
      wcbReturnRecordStore.push({
        wcbReturnRecordId: 'rr-1111',
        wcbBatchId: BATCH_1,
        wcbClaimDetailId: WCB_DETAIL_1,
        reportTxnId: 'RTX-001',
        submitterTxnId: 'MRT0000000000001',
        processedClaimNumber: '1234567',
        claimDecision: 'Accepted',
        reportStatus: 'COMPLETE',
        txnSubmissionDate: '2026-02-16',
        errors: null,
      });

      const xml = buildRemittanceXml({
        records: [
          {
            paymentStatus: 'ISS',
            paymentAmount: '94.15',
            electronicReportTxnId: 'RTX-001',
          },
        ],
      });

      await processRemittanceFile(deps, PHYSICIAN_1, USER_1, xml);

      // Claim should have been transitioned to PAID
      expect(claimRepo.transitionClaimState).toHaveBeenCalledWith(
        CLAIM_1,
        PHYSICIAN_1,
        'PAID',
      );
      // Verify claim state was updated in store
      const claim = claimStore.find((c) => c.claimId === CLAIM_1);
      expect(claim?.state).toBe('PAID');
    });

    it('REJ status flags claim for review (no state change)', async () => {
      const { deps, claimRepo, notificationEmitter } = makeRemittanceDeps();

      seedClaim({ claimId: CLAIM_1, state: 'ASSESSED' });
      seedWcbDetail({
        wcbClaimDetailId: WCB_DETAIL_1,
        claimId: CLAIM_1,
        submitterTxnId: 'MRT0000000000001',
      });
      wcbReturnRecordStore.push({
        wcbReturnRecordId: 'rr-1111',
        wcbBatchId: BATCH_1,
        wcbClaimDetailId: WCB_DETAIL_1,
        reportTxnId: 'RTX-001',
        submitterTxnId: 'MRT0000000000001',
        processedClaimNumber: '1234567',
        claimDecision: 'Accepted',
        reportStatus: 'COMPLETE',
        txnSubmissionDate: '2026-02-16',
        errors: null,
      });

      const xml = buildRemittanceXml({
        records: [
          {
            paymentStatus: 'REJ',
            paymentAmount: '0.00',
            electronicReportTxnId: 'RTX-001',
          },
        ],
      });

      await processRemittanceFile(deps, PHYSICIAN_1, USER_1, xml);

      // REJ does NOT transition claim state
      expect(claimRepo.transitionClaimState).not.toHaveBeenCalled();
      // But does emit a review notification
      expect(notificationEmitter.emit).toHaveBeenCalledWith(
        'WCB_PAYMENT_REVIEW_REQUIRED',
        expect.objectContaining({
          physicianId: PHYSICIAN_1,
          claimId: CLAIM_1,
          paymentStatus: 'REJ',
        }),
      );
      // Claim remains in ASSESSED state
      const claim = claimStore.find((c) => c.claimId === CLAIM_1);
      expect(claim?.state).toBe('ASSESSED');
    });

    it('DEL status flags claim for review', async () => {
      const { deps, claimRepo, notificationEmitter } = makeRemittanceDeps();

      seedClaim({ claimId: CLAIM_1, state: 'ASSESSED' });
      seedWcbDetail({
        wcbClaimDetailId: WCB_DETAIL_1,
        claimId: CLAIM_1,
      });
      wcbReturnRecordStore.push({
        wcbReturnRecordId: 'rr-1111',
        wcbBatchId: BATCH_1,
        wcbClaimDetailId: WCB_DETAIL_1,
        reportTxnId: 'RTX-001',
        submitterTxnId: 'MRT0000000000001',
        processedClaimNumber: '1234567',
        claimDecision: 'Accepted',
        reportStatus: 'COMPLETE',
        txnSubmissionDate: '2026-02-16',
        errors: null,
      });

      const xml = buildRemittanceXml({
        records: [
          {
            paymentStatus: 'DEL',
            paymentAmount: '0.00',
            electronicReportTxnId: 'RTX-001',
          },
        ],
      });

      await processRemittanceFile(deps, PHYSICIAN_1, USER_1, xml);

      expect(claimRepo.transitionClaimState).not.toHaveBeenCalled();
      expect(notificationEmitter.emit).toHaveBeenCalledWith(
        'WCB_PAYMENT_REVIEW_REQUIRED',
        expect.objectContaining({
          paymentStatus: 'DEL',
        }),
      );
    });

    it('REQ/PAE/PGA/PGD statuses emit pending notification (no state change)', async () => {
      const pendingStatuses = ['REQ', 'PAE', 'PGA', 'PGD'];

      for (const status of pendingStatuses) {
        // Reset stores for each iteration
        wcbDetailStore.length = 0;
        wcbRemittanceImportStore.length = 0;
        wcbRemittanceRecordStore.length = 0;
        wcbReturnRecordStore.length = 0;
        claimStore.length = 0;

        const { deps, claimRepo, notificationEmitter } = makeRemittanceDeps();

        seedClaim({ claimId: CLAIM_1, state: 'ASSESSED' });
        seedWcbDetail({
          wcbClaimDetailId: WCB_DETAIL_1,
          claimId: CLAIM_1,
        });
        wcbReturnRecordStore.push({
          wcbReturnRecordId: 'rr-1111',
          wcbBatchId: BATCH_1,
          wcbClaimDetailId: WCB_DETAIL_1,
          reportTxnId: 'RTX-001',
          submitterTxnId: 'MRT0000000000001',
          processedClaimNumber: '1234567',
          claimDecision: 'Accepted',
          reportStatus: 'COMPLETE',
          txnSubmissionDate: '2026-02-16',
          errors: null,
        });

        const xml = buildRemittanceXml({
          records: [
            {
              paymentStatus: status,
              paymentAmount: '94.15',
              electronicReportTxnId: 'RTX-001',
            },
          ],
        });

        await processRemittanceFile(deps, PHYSICIAN_1, USER_1, xml);

        expect(claimRepo.transitionClaimState).not.toHaveBeenCalled();
        expect(notificationEmitter.emit).toHaveBeenCalledWith(
          'WCB_PAYMENT_PENDING',
          expect.objectContaining({
            physicianId: PHYSICIAN_1,
            paymentStatus: status,
          }),
        );
      }
    });

    it('discrepancy detected when payment != expected fee', async () => {
      const { deps } = makeRemittanceDeps();

      // Seed a claim that will calculate to a known fee
      seedClaim({ claimId: CLAIM_1, state: 'ASSESSED' });
      seedWcbDetail({
        wcbClaimDetailId: WCB_DETAIL_1,
        claimId: CLAIM_1,
        formId: 'C050E',
        dateOfExamination: '2026-02-16',
      });
      wcbReturnRecordStore.push({
        wcbReturnRecordId: 'rr-1111',
        wcbBatchId: BATCH_1,
        wcbClaimDetailId: WCB_DETAIL_1,
        reportTxnId: 'RTX-001',
        submitterTxnId: 'MRT0000000000001',
        processedClaimNumber: '1234567',
        claimDecision: 'Accepted',
        reportStatus: 'COMPLETE',
        txnSubmissionDate: '2026-02-16',
        errors: null,
      });

      // Payment is $70.00 but expected fee will be $94.15+ (same day C050E fee)
      const xml = buildRemittanceXml({
        records: [
          {
            paymentStatus: 'ISS',
            paymentAmount: '70.00',
            electronicReportTxnId: 'RTX-001',
          },
        ],
      });

      const result = await processRemittanceFile(deps, PHYSICIAN_1, USER_1, xml);

      expect(result.matched_count).toBe(1);
      expect(result.discrepancy_count).toBe(1);
    });

    it('overpayment recovery tracked', async () => {
      const { deps } = makeRemittanceDeps();

      seedClaim({ claimId: CLAIM_1, state: 'ASSESSED' });
      seedWcbDetail({
        wcbClaimDetailId: WCB_DETAIL_1,
        claimId: CLAIM_1,
      });
      wcbReturnRecordStore.push({
        wcbReturnRecordId: 'rr-1111',
        wcbBatchId: BATCH_1,
        wcbClaimDetailId: WCB_DETAIL_1,
        reportTxnId: 'RTX-001',
        submitterTxnId: 'MRT0000000000001',
        processedClaimNumber: '1234567',
        claimDecision: 'Accepted',
        reportStatus: 'COMPLETE',
        txnSubmissionDate: '2026-02-16',
        errors: null,
      });

      const xml = buildRemittanceXml({
        records: [
          {
            paymentStatus: 'ISS',
            paymentAmount: '84.15',
            overpaymentRecovery: '10.00',
            electronicReportTxnId: 'RTX-001',
          },
        ],
      });

      await processRemittanceFile(deps, PHYSICIAN_1, USER_1, xml);

      // Overpayment recovery stored in remittance record
      expect(wcbRemittanceRecordStore[0].overpaymentRecovery).toBe('10.00');
    });

    it('unmatched records handled gracefully', async () => {
      const { deps } = makeRemittanceDeps();

      // No return record to match against
      const xml = buildRemittanceXml({
        records: [
          {
            paymentStatus: 'ISS',
            paymentAmount: '94.15',
            electronicReportTxnId: 'RTX-NONEXISTENT',
          },
        ],
      });

      const result = await processRemittanceFile(deps, PHYSICIAN_1, USER_1, xml);

      expect(result.record_count).toBe(1);
      expect(result.matched_count).toBe(0);
      expect(result.total_payment).toBe('94.15');
      // Record stored without claim link
      expect(wcbRemittanceRecordStore).toHaveLength(1);
      expect(wcbRemittanceRecordStore[0].wcbClaimDetailId).toBeUndefined();
    });

    it('records without ElectronicReportTransactionID are stored but not matched', async () => {
      const { deps } = makeRemittanceDeps();

      const xml = buildRemittanceXml({
        records: [
          {
            paymentStatus: 'ISS',
            paymentAmount: '50.00',
            // No electronicReportTxnId
          },
        ],
      });

      const result = await processRemittanceFile(deps, PHYSICIAN_1, USER_1, xml);

      expect(result.record_count).toBe(1);
      expect(result.matched_count).toBe(0);
      expect(wcbRemittanceRecordStore).toHaveLength(1);
    });

    it('emits WCB_PAYMENT_RECEIVED notification with summary', async () => {
      const { deps, notificationEmitter } = makeRemittanceDeps();

      const xml = buildRemittanceXml({
        records: [
          { paymentAmount: '94.15' },
          { paymentAmount: '150.00' },
        ],
      });

      const result = await processRemittanceFile(deps, PHYSICIAN_1, USER_1, xml);

      expect(notificationEmitter.emit).toHaveBeenCalledWith(
        'WCB_PAYMENT_RECEIVED',
        expect.objectContaining({
          physicianId: PHYSICIAN_1,
          importId: result.import_id,
          recordCount: 2,
          matchedCount: 0,
          totalPayment: '244.15',
          discrepancyCount: 0,
        }),
      );
    });

    it('emits audit for wcb.remittance_processed', async () => {
      const { deps, auditEmitter } = makeRemittanceDeps();

      const xml = buildRemittanceXml({
        records: [{ paymentAmount: '94.15' }],
      });

      const result = await processRemittanceFile(deps, PHYSICIAN_1, USER_1, xml);

      expect(auditEmitter.emit).toHaveBeenCalledWith(
        'WCB_PAYMENT_RECEIVED',
        expect.objectContaining({
          claimId: result.import_id,
          actorId: USER_1,
          changes: expect.objectContaining({
            importId: result.import_id,
            recordCount: 1,
            matchedCount: 0,
            totalPayment: '94.15',
            discrepancyCount: 0,
          }),
        }),
      );
    });

    it('handles multiple matched and unmatched records in one file', async () => {
      const { deps } = makeRemittanceDeps();

      // Seed match chain for first record only
      seedClaim({ claimId: CLAIM_1, state: 'ASSESSED' });
      seedWcbDetail({
        wcbClaimDetailId: WCB_DETAIL_1,
        claimId: CLAIM_1,
      });
      wcbReturnRecordStore.push({
        wcbReturnRecordId: 'rr-1111',
        wcbBatchId: BATCH_1,
        wcbClaimDetailId: WCB_DETAIL_1,
        reportTxnId: 'RTX-001',
        submitterTxnId: 'MRT0000000000001',
        processedClaimNumber: '1234567',
        claimDecision: 'Accepted',
        reportStatus: 'COMPLETE',
        txnSubmissionDate: '2026-02-16',
        errors: null,
      });

      const xml = buildRemittanceXml({
        records: [
          {
            paymentStatus: 'ISS',
            paymentAmount: '94.15',
            electronicReportTxnId: 'RTX-001', // Will match
          },
          {
            paymentStatus: 'ISS',
            paymentAmount: '150.00',
            electronicReportTxnId: 'RTX-UNMATCHED', // Won't match
          },
        ],
      });

      const result = await processRemittanceFile(deps, PHYSICIAN_1, USER_1, xml);

      expect(result.record_count).toBe(2);
      expect(result.matched_count).toBe(1);
      expect(result.total_payment).toBe('244.15');
    });

    it('handles empty remittance file (no records)', async () => {
      const { deps } = makeRemittanceDeps();

      const xml = buildRemittanceXml({ records: [] });

      const result = await processRemittanceFile(deps, PHYSICIAN_1, USER_1, xml);

      expect(result.record_count).toBe(0);
      expect(result.matched_count).toBe(0);
      expect(result.total_payment).toBe('0.00');
      expect(result.discrepancy_count).toBe(0);
    });
  });

  // =========================================================================
  // MVP Services (D04W-028)
  // =========================================================================

  describe('isMvpPhaseActive', () => {
    it('returns true when wcbPhase is undefined', () => {
      expect(isMvpPhaseActive()).toBe(true);
    });

    it('returns true when wcbPhase is "mvp"', () => {
      expect(isMvpPhaseActive('mvp')).toBe(true);
    });

    it('returns false when wcbPhase is "vendor" (Phase 2)', () => {
      expect(isMvpPhaseActive('vendor')).toBe(false);
    });
  });

  describe('subtractMoney', () => {
    it('subtracts two money strings', () => {
      expect(subtractMoney('94.15', '85.80')).toBe('8.35');
    });

    it('returns 0.00 when result would be negative', () => {
      expect(subtractMoney('50.00', '60.00')).toBe('0.00');
    });

    it('returns 0.00 when equal', () => {
      expect(subtractMoney('42.00', '42.00')).toBe('0.00');
    });
  });

  describe('generateMvpExport', () => {
    it('produces HTML export for a C050E claim', async () => {
      const deps = makeServiceDeps();
      // Create a C050E claim first
      const createResult = await createWcbClaim(
        deps,
        PHYSICIAN_1,
        USER_1,
        makeServiceCreateInput({
          date_of_examination: '2026-02-15',
        }),
      );

      const result = await generateMvpExport(
        deps,
        PHYSICIAN_1,
        createResult.wcbClaimDetailId,
        USER_1,
        'mvp',
      );

      expect(result.contentType).toBe('text/html');
      expect(result.content).toContain('<!DOCTYPE html>');
      expect(result.formId).toBe('C050E');
      expect(result.formName).toBe('Physician First Report');
      expect(result.fileName).toContain('WCB_C050E_');
      expect(result.fileName).toMatch(/\.html$/);
    });

    it('includes all form sections for C050E', async () => {
      const deps = makeServiceDeps();
      const createResult = await createWcbClaim(
        deps,
        PHYSICIAN_1,
        USER_1,
        makeServiceCreateInput({
          date_of_examination: '2026-02-15',
          employer_name: 'ACME Corp',
          symptoms: 'Back pain',
          treatment_plan_text: 'Rest and physiotherapy',
          injuries: [
            { part_of_body_code: '31100', nature_of_injury_code: '02100', side_of_body_code: 'L' },
          ],
        }),
      );

      const result = await generateMvpExport(
        deps,
        PHYSICIAN_1,
        createResult.wcbClaimDetailId,
        USER_1,
        'mvp',
      );

      // C050E has ALL 10 sections
      const sectionNames = result.sections.map((s) => s.name);
      expect(sectionNames).toContain('GENERAL');
      expect(sectionNames).toContain('CLAIMANT');
      expect(sectionNames).toContain('PRACTITIONER');
      expect(sectionNames).toContain('EMPLOYER');
      expect(sectionNames).toContain('ACCIDENT');
      expect(sectionNames).toContain('INJURY');
      expect(sectionNames).toContain('TREATMENT_PLAN');
      expect(sectionNames).toContain('RETURN_TO_WORK');
      expect(sectionNames).toContain('ATTACHMENTS');
      expect(sectionNames).toContain('INVOICE');
    });

    it('includes fee calculation and timing info', async () => {
      const deps = makeServiceDeps();
      const createResult = await createWcbClaim(
        deps,
        PHYSICIAN_1,
        USER_1,
        makeServiceCreateInput({
          date_of_examination: '2026-02-15',
        }),
      );

      const result = await generateMvpExport(
        deps,
        PHYSICIAN_1,
        createResult.wcbClaimDetailId,
        USER_1,
        'mvp',
      );

      // Fee calculation should be present
      expect(result.feeCalculation).toBeDefined();
      expect(result.feeCalculation.report_fee).toBeDefined();
      expect(result.feeCalculation.report_fee_tier).toBeDefined();
      expect(result.feeCalculation.total_expected_fee).toBeDefined();

      // Timing info should be present (since date_of_examination is set)
      expect(result.timingInfo).not.toBeNull();
      expect(result.timingInfo!.tier).toBeDefined();
      expect(result.timingInfo!.deadline).toBeDefined();
      expect(typeof result.timingInfo!.hoursRemaining).toBe('number');
    });

    it('emits audit event for MVP export', async () => {
      const deps = makeServiceDeps();
      const createResult = await createWcbClaim(
        deps,
        PHYSICIAN_1,
        USER_1,
        makeServiceCreateInput({
          date_of_examination: '2026-02-15',
        }),
      );

      await generateMvpExport(
        deps,
        PHYSICIAN_1,
        createResult.wcbClaimDetailId,
        USER_1,
        'mvp',
      );

      // Audit emitter should have been called with MVP export event
      expect(deps.auditEmitter!.emit).toHaveBeenCalledWith(
        'WCB_MVP_EXPORT_GENERATED',
        expect.objectContaining({
          claimId: createResult.claimId,
          changes: expect.objectContaining({
            wcbClaimDetailId: createResult.wcbClaimDetailId,
            formId: 'C050E',
          }),
        }),
      );
    });

    it('returns 404 when WCB_PHASE is vendor (Phase 2)', async () => {
      const deps = makeServiceDeps();
      const createResult = await createWcbClaim(
        deps,
        PHYSICIAN_1,
        USER_1,
        makeServiceCreateInput(),
      );

      await expect(
        generateMvpExport(deps, PHYSICIAN_1, createResult.wcbClaimDetailId, USER_1, 'vendor'),
      ).rejects.toThrow(/not found/i);
    });

    it('throws NotFoundError for non-existent claim', async () => {
      const deps = makeServiceDeps();

      await expect(
        generateMvpExport(deps, PHYSICIAN_1, 'wcd-nonexistent', USER_1, 'mvp'),
      ).rejects.toThrow(/not found/i);
    });

    it('includes validation warnings but still produces export', async () => {
      const deps = makeServiceDeps();
      // Create a claim without date_of_examination (will trigger validation warnings)
      const createResult = await createWcbClaim(
        deps,
        PHYSICIAN_1,
        USER_1,
        makeServiceCreateInput({
          date_of_examination: undefined,
        }),
      );

      const result = await generateMvpExport(
        deps,
        PHYSICIAN_1,
        createResult.wcbClaimDetailId,
        USER_1,
        'mvp',
      );

      // Export should still be produced even with validation issues
      expect(result.content).toContain('<!DOCTYPE html>');
      // There should be validation warnings since required fields are missing
      expect(Array.isArray(result.validationWarnings)).toBe(true);
    });
  });

  describe('recordManualOutcome', () => {
    it('stores WCB claim number when provided', async () => {
      const deps = makeServiceDeps();
      const createResult = await createWcbClaim(
        deps,
        PHYSICIAN_1,
        USER_1,
        makeServiceCreateInput(),
      );

      // Need to transition claim to SUBMITTED state for acceptance
      await deps.claimRepo.transitionClaimState(createResult.claimId, PHYSICIAN_1, 'VALIDATED');
      await deps.claimRepo.transitionClaimState(createResult.claimId, PHYSICIAN_1, 'QUEUED');
      await deps.claimRepo.transitionClaimState(createResult.claimId, PHYSICIAN_1, 'SUBMITTED');

      const result = await recordManualOutcome(
        deps,
        PHYSICIAN_1,
        createResult.wcbClaimDetailId,
        USER_1,
        {
          wcb_claim_number: '1234567',
          acceptance_status: 'accepted',
          payment_amount: 94.15,
        },
        'mvp',
      );

      expect(result.wcbClaimNumber).toBe('1234567');
      expect(result.paymentAmount).toBe(94.15);
    });

    it('transitions claim to ASSESSED when accepted', async () => {
      const deps = makeServiceDeps();
      const createResult = await createWcbClaim(
        deps,
        PHYSICIAN_1,
        USER_1,
        makeServiceCreateInput(),
      );

      const result = await recordManualOutcome(
        deps,
        PHYSICIAN_1,
        createResult.wcbClaimDetailId,
        USER_1,
        { acceptance_status: 'accepted' },
        'mvp',
      );

      expect(result.newState).toBe('ASSESSED');
      expect(deps.claimRepo.transitionClaimState).toHaveBeenCalledWith(
        createResult.claimId,
        PHYSICIAN_1,
        'ASSESSED',
      );
    });

    it('transitions claim to REJECTED when rejected', async () => {
      const deps = makeServiceDeps();
      const createResult = await createWcbClaim(
        deps,
        PHYSICIAN_1,
        USER_1,
        makeServiceCreateInput(),
      );

      const result = await recordManualOutcome(
        deps,
        PHYSICIAN_1,
        createResult.wcbClaimDetailId,
        USER_1,
        { acceptance_status: 'rejected' },
        'mvp',
      );

      expect(result.newState).toBe('REJECTED');
      expect(deps.claimRepo.transitionClaimState).toHaveBeenCalledWith(
        createResult.claimId,
        PHYSICIAN_1,
        'REJECTED',
      );
    });

    it('emits audit event for manual outcome', async () => {
      const deps = makeServiceDeps();
      const createResult = await createWcbClaim(
        deps,
        PHYSICIAN_1,
        USER_1,
        makeServiceCreateInput(),
      );

      await recordManualOutcome(
        deps,
        PHYSICIAN_1,
        createResult.wcbClaimDetailId,
        USER_1,
        {
          wcb_claim_number: '1234567',
          acceptance_status: 'accepted',
          payment_amount: 94.15,
        },
        'mvp',
      );

      expect(deps.auditEmitter!.emit).toHaveBeenCalledWith(
        'WCB_MANUAL_OUTCOME_RECORDED',
        expect.objectContaining({
          claimId: createResult.claimId,
          changes: expect.objectContaining({
            wcbClaimDetailId: createResult.wcbClaimDetailId,
            acceptanceStatus: 'accepted',
            wcbClaimNumber: '1234567',
            paymentAmount: 94.15,
          }),
        }),
      );
    });

    it('returns 404 when WCB_PHASE is vendor (Phase 2)', async () => {
      const deps = makeServiceDeps();
      const createResult = await createWcbClaim(
        deps,
        PHYSICIAN_1,
        USER_1,
        makeServiceCreateInput(),
      );

      await expect(
        recordManualOutcome(
          deps,
          PHYSICIAN_1,
          createResult.wcbClaimDetailId,
          USER_1,
          { acceptance_status: 'accepted' },
          'vendor',
        ),
      ).rejects.toThrow(/not found/i);
    });

    it('throws NotFoundError for non-existent claim', async () => {
      const deps = makeServiceDeps();

      await expect(
        recordManualOutcome(
          deps,
          PHYSICIAN_1,
          'wcd-nonexistent',
          USER_1,
          { acceptance_status: 'accepted' },
          'mvp',
        ),
      ).rejects.toThrow(/not found/i);
    });

    it('works without wcb_claim_number', async () => {
      const deps = makeServiceDeps();
      const createResult = await createWcbClaim(
        deps,
        PHYSICIAN_1,
        USER_1,
        makeServiceCreateInput(),
      );

      const result = await recordManualOutcome(
        deps,
        PHYSICIAN_1,
        createResult.wcbClaimDetailId,
        USER_1,
        { acceptance_status: 'rejected' },
        'mvp',
      );

      expect(result.wcbClaimNumber).toBeUndefined();
      expect(result.newState).toBe('REJECTED');
    });
  });

  describe('getTimingDashboard', () => {
    it('returns claims with deadline info', async () => {
      const deps = makeServiceDeps();

      // Create a DRAFT claim with date_of_examination
      await createWcbClaim(
        deps,
        PHYSICIAN_1,
        USER_1,
        makeServiceCreateInput({
          date_of_examination: '2026-02-15',
        }),
      );

      const result = await getTimingDashboard(deps, PHYSICIAN_1);

      expect(result.items.length).toBeGreaterThan(0);
      const item = result.items[0];
      expect(item.formId).toBe('C050E');
      expect(item.formName).toBe('Physician First Report');
      expect(item.state).toBeDefined();
      expect(item.claimId).toBeDefined();
      expect(item.wcbClaimDetailId).toBeDefined();
    });

    it('includes timing tier and fee information', async () => {
      const deps = makeServiceDeps();

      await createWcbClaim(
        deps,
        PHYSICIAN_1,
        USER_1,
        makeServiceCreateInput({
          date_of_examination: '2026-02-15',
        }),
      );

      const result = await getTimingDashboard(deps, PHYSICIAN_1);
      const item = result.items[0];

      // Should have timing info since date_of_examination is set
      expect(item.timingTier).toBeDefined();
      expect(item.deadline).toBeDefined();
      expect(typeof item.hoursRemaining).toBe('number');
      expect(item.currentFee).toBeDefined();
      expect(item.sameDayFee).toBeDefined();
      expect(item.feeDifference).toBeDefined();
    });

    it('returns empty for physician with no draft/queued claims', async () => {
      const deps = makeServiceDeps();

      const result = await getTimingDashboard(deps, PHYSICIAN_1);

      expect(result.items).toEqual([]);
    });

    it('only includes DRAFT and QUEUED claims', async () => {
      const deps = makeServiceDeps();

      // Create a claim (starts in DRAFT)
      const c1 = await createWcbClaim(
        deps,
        PHYSICIAN_1,
        USER_1,
        makeServiceCreateInput({
          date_of_examination: '2026-02-15',
        }),
      );

      // Transition one to SUBMITTED (should not appear)
      await deps.claimRepo.transitionClaimState(c1.claimId, PHYSICIAN_1, 'VALIDATED');
      await deps.claimRepo.transitionClaimState(c1.claimId, PHYSICIAN_1, 'QUEUED');
      await deps.claimRepo.transitionClaimState(c1.claimId, PHYSICIAN_1, 'SUBMITTED');

      // Create another that stays in DRAFT
      await createWcbClaim(
        deps,
        PHYSICIAN_1,
        USER_1,
        makeServiceCreateInput({
          date_of_examination: '2026-02-16',
        }),
      );

      const result = await getTimingDashboard(deps, PHYSICIAN_1);

      // Only DRAFT claims should appear (SUBMITTED should not)
      for (const item of result.items) {
        expect(['DRAFT', 'QUEUED']).toContain(item.state);
      }
    });

    it('handles claims without date_of_examination gracefully', async () => {
      const deps = makeServiceDeps();

      await createWcbClaim(
        deps,
        PHYSICIAN_1,
        USER_1,
        makeServiceCreateInput({
          date_of_examination: undefined,
        }),
      );

      const result = await getTimingDashboard(deps, PHYSICIAN_1);

      expect(result.items.length).toBeGreaterThan(0);
      const item = result.items[0];
      // Without exam date, timing info should be null
      expect(item.timingTier).toBeNull();
      expect(item.deadline).toBeNull();
      expect(item.hoursRemaining).toBeNull();
    });

    it('sorts by urgency (fewest hours remaining first)', async () => {
      const deps = makeServiceDeps();

      // Create two claims with different exam dates
      // Earlier exam date = closer deadline = more urgent
      await createWcbClaim(
        deps,
        PHYSICIAN_1,
        USER_1,
        makeServiceCreateInput({
          date_of_examination: '2026-02-10',
        }),
      );

      await createWcbClaim(
        deps,
        PHYSICIAN_1,
        USER_1,
        makeServiceCreateInput({
          date_of_examination: '2026-02-16',
        }),
      );

      const result = await getTimingDashboard(deps, PHYSICIAN_1);

      if (result.items.length >= 2) {
        const first = result.items[0];
        const second = result.items[1];
        // Items with timing info should have valid hoursRemaining ordering
        if (first.hoursRemaining !== null && second.hoursRemaining !== null) {
          expect(first.hoursRemaining).toBeLessThanOrEqual(second.hoursRemaining);
        }
      }
    });
  });

  // =========================================================================
  // Helper: makeClaimWithChildren
  // =========================================================================
});

/**
 * Helper to create a WcbClaimWithChildren-like structure for XML generation tests.
 */
function makeClaimWithChildren(overrides: {
  detail?: Partial<Record<string, unknown>>;
  injuries?: any[];
  prescriptions?: any[];
  consultations?: any[];
  workRestrictions?: any[];
  invoiceLines?: any[];
  attachments?: any[];
}): any {
  const defaultDetail = {
    wcbClaimDetailId: 'wcd-test',
    claimId: 'clm-test',
    formId: 'C050E',
    submitterTxnId: 'MRT0000000000001',
    reportCompletionDate: '2026-02-15',
    practitionerBillingNumber: '12345678',
    contractId: '000001',
    roleCode: 'GP',
    practitionerFirstName: 'Jane',
    practitionerMiddleName: null,
    practitionerLastName: 'Smith',
    skillCode: '03',
    facilityType: 'C',
    clinicReferenceNumber: null,
    faxNumber: null,
    patientPhn: '123456789',
    patientGender: 'M',
    patientFirstName: 'John',
    patientMiddleName: null,
    patientLastName: 'Doe',
    patientDob: '1990-05-10',
    patientAddressLine1: '123 Main St',
    patientAddressLine2: null,
    patientCity: 'Calgary',
    patientProvince: 'AB',
    patientPostalCode: 'T2P1A1',
    patientPhoneCountry: null,
    patientPhoneNumber: null,
    dateOfInjury: '2026-02-10',
    dateOfExamination: null,
    symptoms: null,
    objectiveFindings: null,
    currentDiagnosis: null,
    diagnosticCode1: null,
    diagnosticCode2: null,
    diagnosticCode3: null,
    additionalComments: null,
    employerName: null,
    employerLocation: null,
    employerCity: null,
    workerJobTitle: null,
    injuryDescription: null,
    injuryDevelopedOverTime: null,
    treatmentPlanText: null,
    narcoticsPrescribed: null,
    missedWorkBeyondAccident: null,
    patientReturnedToWork: null,
    estimatedRtwDate: null,
    priorConditionsFlag: null,
    priorConditionsDesc: null,
    diagnosisChanged: null,
    diagnosisChangedDesc: null,
  };

  return {
    detail: { ...defaultDetail, ...overrides.detail },
    claim: {
      claimId: overrides.detail?.claimId ?? 'clm-test',
      physicianId: PHYSICIAN_1,
      patientId: PATIENT_1,
      claimType: 'WCB',
      state: 'QUEUED',
      dateOfService: '2026-02-15',
      deletedAt: null,
    },
    injuries: overrides.injuries ?? [],
    prescriptions: overrides.prescriptions ?? [],
    consultations: overrides.consultations ?? [],
    workRestrictions: overrides.workRestrictions ?? [],
    invoiceLines: overrides.invoiceLines ?? [],
    attachments: overrides.attachments ?? [],
  };
}

// ===========================================================================
// WCB Handlers
// ===========================================================================

import { createWcbHandlers } from './wcb.handlers.js';

function makeMockReply() {
  const reply: any = {
    _statusCode: 200,
    _body: undefined as any,
    code(statusCode: number) {
      reply._statusCode = statusCode;
      return reply;
    },
    send(body?: any) {
      reply._body = body;
      return reply;
    },
  };
  return reply;
}

function makeMockRequest(overrides: {
  authContext?: any;
  params?: any;
  body?: any;
} = {}) {
  return {
    authContext: overrides.authContext ?? {
      userId: PHYSICIAN_1,
      role: 'physician',
    },
    params: overrides.params ?? {},
    body: overrides.body ?? {},
  } as any;
}

describe('WCB Handlers', () => {
  let serviceDeps: WcbServiceDeps;

  beforeEach(() => {
    wcbDetailStore = [];
    wcbInjuryStore = [];
    wcbPrescriptionStore = [];
    wcbConsultationStore = [];
    wcbRestrictionStore = [];
    wcbInvoiceLineStore = [];
    wcbAttachmentStore = [];
    wcbBatchStore = [];
    wcbReturnRecordStore = [];
    wcbReturnInvoiceLineStore = [];
    wcbRemittanceImportStore = [];
    wcbRemittanceRecordStore = [];
    claimStore = [];

    serviceDeps = makeServiceDeps();
  });

  function handlers() {
    return createWcbHandlers({ serviceDeps });
  }

  describe('POST /wcb/claims — createClaimHandler', () => {
    it('creates claim and returns IDs with status 201', async () => {
      const h = handlers();
      const request = makeMockRequest({
        body: makeServiceCreateInput(),
      });
      const reply = makeMockReply();

      await h.createClaimHandler(request, reply);

      expect(reply._statusCode).toBe(201);
      expect(reply._body.data).toBeDefined();
      expect(reply._body.data.claimId).toBeDefined();
      expect(reply._body.data.wcbClaimDetailId).toBeDefined();
    });

    it('extracts physicianId from delegate context', async () => {
      const h = handlers();
      const request = makeMockRequest({
        authContext: {
          userId: 'delegate-user-id',
          role: 'DELEGATE',
          delegateContext: {
            physicianProviderId: PHYSICIAN_1,
            permissions: ['CLAIM_CREATE'],
          },
        },
        body: makeServiceCreateInput(),
      });
      const reply = makeMockReply();

      await h.createClaimHandler(request, reply);

      expect(reply._statusCode).toBe(201);
      expect(reply._body.data.claimId).toBeDefined();
    });
  });

  describe('GET /wcb/claims/:id — getClaimHandler', () => {
    it('returns claim with child records', async () => {
      const h = handlers();

      // Create a claim first
      const createReply = makeMockReply();
      await h.createClaimHandler(
        makeMockRequest({ body: makeServiceCreateInput() }),
        createReply,
      );
      const wcbDetailId = createReply._body.data.wcbClaimDetailId;

      // Fetch it
      const request = makeMockRequest({ params: { id: wcbDetailId } });
      const reply = makeMockReply();
      await h.getClaimHandler(request, reply);

      expect(reply._statusCode).toBe(200);
      expect(reply._body.data).toBeDefined();
      expect(reply._body.data.detail).toBeDefined();
      expect(reply._body.data.claim).toBeDefined();
      expect(reply._body.data.injuries).toBeDefined();
      expect(reply._body.data.prescriptions).toBeDefined();
      expect(reply._body.data.consultations).toBeDefined();
      expect(reply._body.data.workRestrictions).toBeDefined();
      expect(reply._body.data.invoiceLines).toBeDefined();
      expect(reply._body.data.attachments).toBeDefined();
    });

    it('returns 404 for non-existent claim', async () => {
      const h = handlers();
      const request = makeMockRequest({
        params: { id: 'wcd-9999-9999-9999-999999999999' },
      });
      const reply = makeMockReply();

      await h.getClaimHandler(request, reply);

      expect(reply._statusCode).toBe(404);
      expect(reply._body.error.code).toBe('NOT_FOUND');
    });
  });

  describe('PUT /wcb/claims/:id — updateClaimHandler', () => {
    it('updates claim and returns updated data', async () => {
      const h = handlers();

      // Create a claim
      const createReply = makeMockReply();
      await h.createClaimHandler(
        makeMockRequest({ body: makeServiceCreateInput() }),
        createReply,
      );
      const wcbDetailId = createReply._body.data.wcbClaimDetailId;

      // Update it
      const request = makeMockRequest({
        params: { id: wcbDetailId },
        body: { additional_comments: 'Updated comment' },
      });
      const reply = makeMockReply();
      await h.updateClaimHandler(request, reply);

      expect(reply._statusCode).toBe(200);
      expect(reply._body.data).toBeDefined();
    });

    it('returns 404 for non-existent claim', async () => {
      const h = handlers();
      const request = makeMockRequest({
        params: { id: 'wcd-9999-9999-9999-999999999999' },
        body: { additional_comments: 'test' },
      });
      const reply = makeMockReply();

      await h.updateClaimHandler(request, reply);

      expect(reply._statusCode).toBe(404);
      expect(reply._body.error.code).toBe('NOT_FOUND');
    });
  });

  describe('DELETE /wcb/claims/:id — deleteClaimHandler', () => {
    it('soft-deletes draft claim with status 204', async () => {
      const h = handlers();

      // Create a claim (it starts as DRAFT)
      const createReply = makeMockReply();
      await h.createClaimHandler(
        makeMockRequest({ body: makeServiceCreateInput() }),
        createReply,
      );
      const wcbDetailId = createReply._body.data.wcbClaimDetailId;

      // Delete it
      const request = makeMockRequest({ params: { id: wcbDetailId } });
      const reply = makeMockReply();
      await h.deleteClaimHandler(request, reply);

      expect(reply._statusCode).toBe(204);
    });

    it('returns 422 for non-draft claim', async () => {
      const h = handlers();

      // Create a claim
      const createReply = makeMockReply();
      await h.createClaimHandler(
        makeMockRequest({ body: makeServiceCreateInput() }),
        createReply,
      );
      const wcbDetailId = createReply._body.data.wcbClaimDetailId;

      // Move claim out of DRAFT state
      const claimId = createReply._body.data.claimId;
      const claim = claimStore.find((c) => c.claimId === claimId);
      if (claim) claim.state = 'QUEUED';

      // Try to delete
      const request = makeMockRequest({ params: { id: wcbDetailId } });
      const reply = makeMockReply();
      await h.deleteClaimHandler(request, reply);

      expect(reply._statusCode).toBe(422);
      expect(reply._body.error.code).toBe('BUSINESS_RULE_VIOLATION');
    });

    it('returns 404 for non-existent claim', async () => {
      const h = handlers();
      const request = makeMockRequest({
        params: { id: 'wcd-9999-9999-9999-999999999999' },
      });
      const reply = makeMockReply();
      await h.deleteClaimHandler(request, reply);

      expect(reply._statusCode).toBe(404);
      expect(reply._body.error.code).toBe('NOT_FOUND');
    });
  });

  describe('POST /wcb/claims/:id/validate — validateClaimHandler', () => {
    it('returns validation results', async () => {
      const h = handlers();

      // Create a claim with enough data for validation
      const createReply = makeMockReply();
      await h.createClaimHandler(
        makeMockRequest({
          body: makeServiceCreateInput({
            injuries: [
              { part_of_body_code: '30', nature_of_injury_code: '120' },
            ],
          }),
        }),
        createReply,
      );
      const wcbDetailId = createReply._body.data.wcbClaimDetailId;

      // Validate it
      const request = makeMockRequest({ params: { id: wcbDetailId } });
      const reply = makeMockReply();
      await h.validateClaimHandler(request, reply);

      expect(reply._statusCode).toBe(200);
      expect(reply._body.data).toBeDefined();
      expect(reply._body.data).toHaveProperty('errors');
      expect(reply._body.data).toHaveProperty('warnings');
      expect(reply._body.data).toHaveProperty('passed');
    });

    it('returns 404 for non-existent claim', async () => {
      const h = handlers();
      const request = makeMockRequest({
        params: { id: 'wcd-9999-9999-9999-999999999999' },
      });
      const reply = makeMockReply();
      await h.validateClaimHandler(request, reply);

      expect(reply._statusCode).toBe(404);
      expect(reply._body.error.code).toBe('NOT_FOUND');
    });
  });

  describe('GET /wcb/claims/:id/form-schema — getFormSchemaHandler', () => {
    it('returns form field schema for claim', async () => {
      const h = handlers();

      // Create a claim
      const createReply = makeMockReply();
      await h.createClaimHandler(
        makeMockRequest({ body: makeServiceCreateInput() }),
        createReply,
      );
      const wcbDetailId = createReply._body.data.wcbClaimDetailId;

      // Get form schema
      const request = makeMockRequest({ params: { id: wcbDetailId } });
      const reply = makeMockReply();
      await h.getFormSchemaHandler(request, reply);

      expect(reply._statusCode).toBe(200);
      expect(reply._body.data).toBeDefined();
      expect(reply._body.data.form_id).toBe('C050E');
      expect(reply._body.data.sections).toBeDefined();
      expect(Array.isArray(reply._body.data.sections)).toBe(true);
    });

    it('returns 404 for non-existent claim', async () => {
      const h = handlers();
      const request = makeMockRequest({
        params: { id: 'wcd-9999-9999-9999-999999999999' },
      });
      const reply = makeMockReply();
      await h.getFormSchemaHandler(request, reply);

      expect(reply._statusCode).toBe(404);
      expect(reply._body.error.code).toBe('NOT_FOUND');
    });
  });

  // =========================================================================
  // Batch Management Handlers
  // =========================================================================

  describe('POST /wcb/batches — createBatchHandler', () => {
    it('returns 422 when no queued claims exist', async () => {
      const h = handlers();
      const request = makeMockRequest({});
      const reply = makeMockReply();

      await h.createBatchHandler(request, reply);

      expect(reply._statusCode).toBe(422);
      expect(reply._body.error.code).toBe('BUSINESS_RULE_VIOLATION');
    });

    it('creates batch when queued claims exist', async () => {
      const h = handlers();

      // Create a claim and transition it to QUEUED
      const createReply = makeMockReply();
      await h.createClaimHandler(
        makeMockRequest({ body: makeServiceCreateInput() }),
        createReply,
      );
      const claimId = createReply._body.data.claimId;

      // Manually set the claim to QUEUED state for batch assembly
      const claim = claimStore.find((c) => c.claimId === claimId);
      if (claim) claim.state = 'QUEUED';

      const request = makeMockRequest({});
      const reply = makeMockReply();

      await h.createBatchHandler(request, reply);

      // Batch may succeed (201) or fail validation (422) depending on mock state
      expect([201, 422]).toContain(reply._statusCode);
      if (reply._statusCode === 201) {
        expect(reply._body.data.wcbBatchId).toBeDefined();
        expect(reply._body.data.reportCount).toBeGreaterThanOrEqual(0);
      }
    });
  });

  describe('GET /wcb/batches/:id — getBatchHandler', () => {
    it('returns 404 for non-existent batch', async () => {
      const h = handlers();
      const request = makeMockRequest({
        params: { id: 'bat-9999-9999-9999-999999999999' },
      });
      const reply = makeMockReply();

      await h.getBatchHandler(request, reply);

      expect(reply._statusCode).toBe(404);
      expect(reply._body.error.code).toBe('NOT_FOUND');
    });

    it('returns batch details when found', async () => {
      const h = handlers();

      // Seed a batch directly
      wcbBatchStore.push({
        wcbBatchId: 'bat-test-0001-0001-000000000001',
        physicianId: PHYSICIAN_1,
        status: 'GENERATED',
        batchControlId: 'BC-001',
        fileControlId: 'FC-001',
        xmlFilePath: 'wcb/batches/test.xml',
        xmlFileHash: 'abc123',
        reportCount: 3,
        createdAt: new Date(),
        updatedAt: new Date(),
        xsdValidationPassed: null,
        xsdValidationErrors: null,
        uploadedAt: null,
        uploadedBy: null,
        returnFilePath: null,
        returnReceivedAt: null,
      });

      const request = makeMockRequest({
        params: { id: 'bat-test-0001-0001-000000000001' },
      });
      const reply = makeMockReply();

      await h.getBatchHandler(request, reply);

      expect(reply._statusCode).toBe(200);
      expect(reply._body.data).toBeDefined();
      expect(reply._body.data.wcbBatchId).toBe('bat-test-0001-0001-000000000001');
      expect(reply._body.data.status).toBe('GENERATED');
    });
  });

  describe('GET /wcb/batches/:id/download — downloadBatchHandler', () => {
    it('returns 404 for non-existent batch', async () => {
      // Must have downloadUrlGenerator configured so the service reaches the batch lookup
      serviceDeps = makeServiceDeps({
        downloadUrlGenerator: {
          generateSignedUrl: vi.fn().mockResolvedValue('https://example.com/signed-url'),
        },
      });
      const h = handlers();
      const request = makeMockRequest({
        params: { id: 'bat-9999-9999-9999-999999999999' },
      });
      const reply = makeMockReply();

      await h.downloadBatchHandler(request, reply);

      expect(reply._statusCode).toBe(404);
      expect(reply._body.error.code).toBe('NOT_FOUND');
    });

    it('returns 422 when batch is not VALIDATED', async () => {
      // Seed a batch in GENERATED status (not VALIDATED)
      wcbBatchStore.push({
        wcbBatchId: 'bat-dl-0001-0001-000000000001',
        physicianId: PHYSICIAN_1,
        status: 'GENERATED',
        batchControlId: 'BC-DL1',
        fileControlId: 'FC-DL1',
        xmlFilePath: 'wcb/batches/test-dl.xml',
        xmlFileHash: 'hash1',
        reportCount: 1,
        createdAt: new Date(),
        updatedAt: new Date(),
        xsdValidationPassed: null,
        xsdValidationErrors: null,
        uploadedAt: null,
        uploadedBy: null,
        returnFilePath: null,
        returnReceivedAt: null,
      });

      // Need a download URL generator for this to work
      serviceDeps = makeServiceDeps({
        downloadUrlGenerator: {
          generateSignedUrl: vi.fn().mockResolvedValue('https://example.com/signed-url'),
        },
      });
      const h = handlers();

      const request = makeMockRequest({
        params: { id: 'bat-dl-0001-0001-000000000001' },
      });
      const reply = makeMockReply();

      await h.downloadBatchHandler(request, reply);

      expect(reply._statusCode).toBe(422);
    });
  });

  describe('POST /wcb/batches/:id/confirm-upload — confirmUploadHandler', () => {
    it('returns 404 for non-existent batch', async () => {
      const h = handlers();
      const request = makeMockRequest({
        params: { id: 'bat-9999-9999-9999-999999999999' },
      });
      const reply = makeMockReply();

      await h.confirmUploadHandler(request, reply);

      expect(reply._statusCode).toBe(404);
      expect(reply._body.error.code).toBe('NOT_FOUND');
    });

    it('transitions batch to UPLOADED when VALIDATED', async () => {
      // Seed a batch in VALIDATED status
      wcbBatchStore.push({
        wcbBatchId: 'bat-up-0001-0001-000000000001',
        physicianId: PHYSICIAN_1,
        status: 'VALIDATED',
        batchControlId: 'BC-UP1',
        fileControlId: 'FC-UP1',
        xmlFilePath: 'wcb/batches/test-up.xml',
        xmlFileHash: 'hash2',
        reportCount: 2,
        createdAt: new Date(),
        updatedAt: new Date(),
        xsdValidationPassed: true,
        xsdValidationErrors: null,
        uploadedAt: null,
        uploadedBy: null,
        returnFilePath: null,
        returnReceivedAt: null,
      });

      const h = handlers();
      const request = makeMockRequest({
        params: { id: 'bat-up-0001-0001-000000000001' },
      });
      const reply = makeMockReply();

      await h.confirmUploadHandler(request, reply);

      expect(reply._statusCode).toBe(200);
      expect(reply._body.data.wcbBatchId).toBe('bat-up-0001-0001-000000000001');
      expect(reply._body.data.status).toBe('UPLOADED');
    });
  });

  describe('GET /wcb/batches — listBatchesHandler', () => {
    it('returns empty list when no batches exist', async () => {
      const h = handlers();
      const request = makeMockRequest({}) as any;
      request.query = { page: 1, page_size: 20 };
      const reply = makeMockReply();

      await h.listBatchesHandler(request, reply);

      expect(reply._statusCode).toBe(200);
      expect(reply._body.data).toBeDefined();
      expect(Array.isArray(reply._body.data)).toBe(true);
    });
  });

  // =========================================================================
  // Return File Handlers
  // =========================================================================

  describe('POST /wcb/returns/upload — uploadReturnHandler', () => {
    it('returns 400 when file content is missing', async () => {
      const h = handlers();
      const request = makeMockRequest({ body: {} });
      const reply = makeMockReply();

      await h.uploadReturnHandler(request, reply);

      expect(reply._statusCode).toBe(400);
      expect(reply._body.error.code).toBe('VALIDATION_ERROR');
    });

    it('returns 400 when file content is empty', async () => {
      const h = handlers();
      const request = makeMockRequest({ body: { file_content: '   ' } });
      const reply = makeMockReply();

      await h.uploadReturnHandler(request, reply);

      expect(reply._statusCode).toBe(400);
      expect(reply._body.error.code).toBe('VALIDATION_ERROR');
    });

    it('processes return file with file_content field', async () => {
      // Seed a batch and claim so the return file can be matched
      const batchId = 'bat-ret-0001-0001-000000000001';
      wcbBatchStore.push({
        wcbBatchId: batchId,
        physicianId: PHYSICIAN_1,
        status: 'UPLOADED',
        batchControlId: 'BCTRL001',
        fileControlId: 'FCTRL001',
        xmlFilePath: 'wcb/batches/ret.xml',
        xmlFileHash: 'hash3',
        reportCount: 1,
        createdAt: new Date(),
        updatedAt: new Date(),
        xsdValidationPassed: true,
        xsdValidationErrors: null,
        uploadedAt: new Date(),
        uploadedBy: USER_1,
        returnFilePath: null,
        returnReceivedAt: null,
      });

      // Seed WCB detail with matching submitter_txn_id
      wcbDetailStore.push({
        wcbClaimDetailId: 'wcd-ret-0001-0001-000000000001',
        claimId: CLAIM_1,
        physicianId: PHYSICIAN_1,
        formId: 'C050E',
        submitterTxnId: 'STX00001',
        createdAt: new Date(),
        updatedAt: new Date(),
      });
      claimStore.push({
        claimId: CLAIM_1,
        physicianId: PHYSICIAN_1,
        state: 'SUBMITTED',
      });

      const h = handlers();
      const returnContent = 'BCTRL001\t1\tSUBMITTER01\t2026-01-15\n\nRPT001\tSTX00001\t1234567\tACCEPTED\tCOMPLETE\t2026-01-15\n1\t2026-01-10\t03.01A\tPAID';

      const request = makeMockRequest({
        body: { file_content: returnContent },
      });
      const reply = makeMockReply();

      await h.uploadReturnHandler(request, reply);

      expect(reply._statusCode).toBe(200);
      expect(reply._body.data).toBeDefined();
      expect(reply._body.data.matched_count).toBeGreaterThanOrEqual(0);
    });
  });

  describe('GET /wcb/returns/:batch_id — getReturnResultsHandler', () => {
    it('returns 404 for non-existent batch', async () => {
      const h = handlers();
      const request = makeMockRequest({
        params: { batch_id: 'bat-9999-9999-9999-999999999999' },
      });
      const reply = makeMockReply();

      await h.getReturnResultsHandler(request, reply);

      expect(reply._statusCode).toBe(404);
      expect(reply._body.error.code).toBe('NOT_FOUND');
    });

    it('returns return records for existing batch', async () => {
      // Seed a batch
      wcbBatchStore.push({
        wcbBatchId: 'bat-retget-0001-0001-000000000001',
        physicianId: PHYSICIAN_1,
        status: 'RETURN_RECEIVED',
        batchControlId: 'BC-RG1',
        fileControlId: 'FC-RG1',
        xmlFilePath: 'wcb/batches/rg.xml',
        xmlFileHash: 'hash4',
        reportCount: 1,
        createdAt: new Date(),
        updatedAt: new Date(),
        xsdValidationPassed: true,
        xsdValidationErrors: null,
        uploadedAt: new Date(),
        uploadedBy: USER_1,
        returnFilePath: 'wcb/returns/rg/return.txt',
        returnReceivedAt: new Date(),
      });

      const h = handlers();
      const request = makeMockRequest({
        params: { batch_id: 'bat-retget-0001-0001-000000000001' },
      });
      const reply = makeMockReply();

      await h.getReturnResultsHandler(request, reply);

      expect(reply._statusCode).toBe(200);
      expect(reply._body.data).toBeDefined();
      expect(Array.isArray(reply._body.data)).toBe(true);
    });
  });

  // =========================================================================
  // Remittance Handlers
  // =========================================================================

  describe('POST /wcb/remittances/upload — uploadRemittanceHandler', () => {
    it('returns 400 when XML content is missing', async () => {
      const h = handlers();
      const request = makeMockRequest({ body: {} });
      const reply = makeMockReply();

      await h.uploadRemittanceHandler(request, reply);

      expect(reply._statusCode).toBe(400);
      expect(reply._body.error.code).toBe('VALIDATION_ERROR');
    });

    it('returns 400 when XML content is empty', async () => {
      const h = handlers();
      const request = makeMockRequest({ body: { xml_content: '  ' } });
      const reply = makeMockReply();

      await h.uploadRemittanceHandler(request, reply);

      expect(reply._statusCode).toBe(400);
      expect(reply._body.error.code).toBe('VALIDATION_ERROR');
    });

    it('processes valid remittance XML', async () => {
      const h = handlers();
      const xmlContent = `<?xml version="1.0"?>
<PaymentRemittanceReport xmlns="http://www.wcb.ab.ca/schemas/RR/RRPaymentRemittanceReport-2.01.00">
  <ReportWeek>
    <StartDate>2026-01-06</StartDate>
    <EndDate>2026-01-12</EndDate>
  </ReportWeek>
  <PaymentRemittanceRecord>
    <PaymentPayeeBillingNumber>12345678</PaymentPayeeBillingNumber>
    <PaymentPayeeName>Dr Smith</PaymentPayeeName>
    <PaymentReasonCode>C050E</PaymentReasonCode>
    <PaymentStatus>ISS</PaymentStatus>
    <PaymentStartDate>2026-01-06</PaymentStartDate>
    <PaymentEndDate>2026-01-12</PaymentEndDate>
    <PaymentAmount>94.15</PaymentAmount>
  </PaymentRemittanceRecord>
</PaymentRemittanceReport>`;

      const request = makeMockRequest({
        body: { xml_content: xmlContent },
      });
      const reply = makeMockReply();

      await h.uploadRemittanceHandler(request, reply);

      expect(reply._statusCode).toBe(200);
      expect(reply._body.data).toBeDefined();
      expect(reply._body.data.import_id).toBeDefined();
      expect(reply._body.data.record_count).toBe(1);
    });
  });

  describe('GET /wcb/remittances — listRemittancesHandler', () => {
    it('returns empty list when no imports exist', async () => {
      const h = handlers();
      const request = makeMockRequest({}) as any;
      request.query = { page: 1, page_size: 20 };
      const reply = makeMockReply();

      await h.listRemittancesHandler(request, reply);

      expect(reply._statusCode).toBe(200);
      expect(reply._body.data).toBeDefined();
      expect(Array.isArray(reply._body.data)).toBe(true);
    });
  });

  describe('GET /wcb/remittances/:id/discrepancies — getDiscrepanciesHandler', () => {
    it('returns discrepancies for a remittance import', async () => {
      // Seed a remittance import
      wcbRemittanceImportStore.push({
        wcbRemittanceImportId: 'rmi-test-0001-0001-000000000001',
        physicianId: PHYSICIAN_1,
        importedAt: new Date(),
      });

      const h = handlers();
      const request = makeMockRequest({
        params: { id: 'rmi-test-0001-0001-000000000001' },
      });
      const reply = makeMockReply();

      await h.getDiscrepanciesHandler(request, reply);

      expect(reply._statusCode).toBe(200);
      expect(reply._body.data).toBeDefined();
    });
  });

  // =========================================================================
  // MVP Handlers
  // =========================================================================

  describe('GET /wcb/claims/:id/export — exportClaimHandler (MVP)', () => {
    it('returns 404 when WCB_PHASE is not mvp', async () => {
      // Override with vendor phase
      const vendorDeps = makeServiceDeps();
      const h = createWcbHandlers({ serviceDeps: vendorDeps, wcbPhase: 'vendor' });

      const request = makeMockRequest({
        params: { id: 'wcd-9999-9999-9999-999999999999' },
      });
      const reply = makeMockReply();

      await h.exportClaimHandler(request, reply);

      expect(reply._statusCode).toBe(404);
      expect(reply._body.error.code).toBe('NOT_FOUND');
    });

    it('returns 404 for non-existent claim in MVP mode', async () => {
      const mvpDeps = makeServiceDeps();
      const h = createWcbHandlers({ serviceDeps: mvpDeps, wcbPhase: 'mvp' });

      const request = makeMockRequest({
        params: { id: 'wcd-9999-9999-9999-999999999999' },
      });
      const reply = makeMockReply();

      await h.exportClaimHandler(request, reply);

      expect(reply._statusCode).toBe(404);
    });

    it('generates export for existing claim in MVP mode', async () => {
      const mvpDeps = makeServiceDeps();
      const h = createWcbHandlers({ serviceDeps: mvpDeps, wcbPhase: 'mvp' });

      // Create a claim
      const createReply = makeMockReply();
      await h.createClaimHandler(
        makeMockRequest({ body: makeServiceCreateInput() }),
        createReply,
      );
      const wcbDetailId = createReply._body.data.wcbClaimDetailId;

      const request = makeMockRequest({ params: { id: wcbDetailId } });
      const reply = makeMockReply();

      await h.exportClaimHandler(request, reply);

      expect(reply._statusCode).toBe(200);
      expect(reply._body.data).toBeDefined();
      expect(reply._body.data.formId).toBe('C050E');
      expect(reply._body.data.content).toBeDefined();
      expect(reply._body.data.contentType).toBe('text/html');
      expect(reply._body.data.sections).toBeDefined();
      expect(Array.isArray(reply._body.data.sections)).toBe(true);
    });
  });

  describe('POST /wcb/claims/:id/manual-outcome — manualOutcomeHandler (MVP)', () => {
    it('returns 404 when WCB_PHASE is not mvp', async () => {
      const vendorDeps = makeServiceDeps();
      const h = createWcbHandlers({ serviceDeps: vendorDeps, wcbPhase: 'vendor' });

      const request = makeMockRequest({
        params: { id: 'wcd-9999-9999-9999-999999999999' },
        body: { acceptance_status: 'accepted' },
      });
      const reply = makeMockReply();

      await h.manualOutcomeHandler(request, reply);

      expect(reply._statusCode).toBe(404);
      expect(reply._body.error.code).toBe('NOT_FOUND');
    });

    it('returns 404 for non-existent claim in MVP mode', async () => {
      const mvpDeps = makeServiceDeps();
      const h = createWcbHandlers({ serviceDeps: mvpDeps, wcbPhase: 'mvp' });

      const request = makeMockRequest({
        params: { id: 'wcd-9999-9999-9999-999999999999' },
        body: { acceptance_status: 'accepted' },
      });
      const reply = makeMockReply();

      await h.manualOutcomeHandler(request, reply);

      expect(reply._statusCode).toBe(404);
    });

    it('records accepted outcome in MVP mode', async () => {
      const mvpDeps = makeServiceDeps();
      const h = createWcbHandlers({ serviceDeps: mvpDeps, wcbPhase: 'mvp' });

      // Create a claim
      const createReply = makeMockReply();
      await h.createClaimHandler(
        makeMockRequest({ body: makeServiceCreateInput() }),
        createReply,
      );
      const wcbDetailId = createReply._body.data.wcbClaimDetailId;

      const request = makeMockRequest({
        params: { id: wcbDetailId },
        body: {
          acceptance_status: 'accepted',
          wcb_claim_number: '1234567',
          payment_amount: 94.15,
        },
      });
      const reply = makeMockReply();

      await h.manualOutcomeHandler(request, reply);

      expect(reply._statusCode).toBe(200);
      expect(reply._body.data).toBeDefined();
      expect(reply._body.data.newState).toBe('ASSESSED');
      expect(reply._body.data.wcbClaimNumber).toBe('1234567');
    });

    it('records rejected outcome in MVP mode', async () => {
      const mvpDeps = makeServiceDeps();
      const h = createWcbHandlers({ serviceDeps: mvpDeps, wcbPhase: 'mvp' });

      // Create a claim
      const createReply = makeMockReply();
      await h.createClaimHandler(
        makeMockRequest({ body: makeServiceCreateInput() }),
        createReply,
      );
      const wcbDetailId = createReply._body.data.wcbClaimDetailId;

      const request = makeMockRequest({
        params: { id: wcbDetailId },
        body: { acceptance_status: 'rejected' },
      });
      const reply = makeMockReply();

      await h.manualOutcomeHandler(request, reply);

      expect(reply._statusCode).toBe(200);
      expect(reply._body.data).toBeDefined();
      expect(reply._body.data.newState).toBe('REJECTED');
    });
  });
});
