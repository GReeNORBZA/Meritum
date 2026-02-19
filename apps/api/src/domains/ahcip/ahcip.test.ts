import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createAhcipRepository } from './ahcip.repository.js';

// ---------------------------------------------------------------------------
// In-memory stores
// ---------------------------------------------------------------------------

let ahcipDetailStore: Record<string, any>[];
let ahcipBatchStore: Record<string, any>[];
let claimStore: Record<string, any>[];
let patientStore: Record<string, any>[];

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
const CLAIM_4 = 'clm-4444-4444-4444-444444444444';
const BATCH_1 = 'bat-1111-1111-1111-111111111111';
const BATCH_2 = 'bat-2222-2222-2222-222222222222';

// ---------------------------------------------------------------------------
// Mock Drizzle DB — supports multi-table joins
// ---------------------------------------------------------------------------

function makeMockDb() {
  function storeForTable(table: any): Record<string, any>[] {
    const tableName = table?.__table;
    if (tableName === 'ahcip_claim_details') return ahcipDetailStore;
    if (tableName === 'ahcip_batches') return ahcipBatchStore;
    if (tableName === 'claims') return claimStore;
    if (tableName === 'patients') return patientStore;
    return ahcipDetailStore;
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

  function insertAhcipDetailRow(values: any): any {
    const row = {
      ahcipDetailId: values.ahcipDetailId ?? crypto.randomUUID(),
      claimId: values.claimId,
      baNumber: values.baNumber,
      functionalCentre: values.functionalCentre,
      healthServiceCode: values.healthServiceCode,
      modifier1: values.modifier1 ?? null,
      modifier2: values.modifier2 ?? null,
      modifier3: values.modifier3 ?? null,
      diagnosticCode: values.diagnosticCode ?? null,
      facilityNumber: values.facilityNumber ?? null,
      referralPractitioner: values.referralPractitioner ?? null,
      encounterType: values.encounterType,
      calls: values.calls ?? 1,
      timeSpent: values.timeSpent ?? null,
      patientLocation: values.patientLocation ?? null,
      shadowBillingFlag: values.shadowBillingFlag ?? false,
      pcpcmBasketFlag: values.pcpcmBasketFlag ?? false,
      afterHoursFlag: values.afterHoursFlag ?? false,
      afterHoursType: values.afterHoursType ?? null,
      submittedFee: values.submittedFee ?? null,
      assessedFee: values.assessedFee ?? null,
      assessmentExplanatoryCodes: values.assessmentExplanatoryCodes ?? null,
    };
    ahcipDetailStore.push(row);
    return row;
  }

  function insertAhcipBatchRow(values: any): any {
    // Check unique constraint (physician_id, ba_number, batch_week)
    const duplicate = ahcipBatchStore.find(
      (r) =>
        r.physicianId === values.physicianId &&
        r.baNumber === values.baNumber &&
        r.batchWeek === values.batchWeek,
    );
    if (duplicate) {
      throw new Error(
        'duplicate key value violates unique constraint "ahcip_batches_physician_ba_week_uniq"',
      );
    }

    const row = {
      ahcipBatchId: values.ahcipBatchId ?? crypto.randomUUID(),
      physicianId: values.physicianId,
      baNumber: values.baNumber,
      batchWeek: values.batchWeek,
      status: values.status,
      claimCount: values.claimCount,
      totalSubmittedValue: values.totalSubmittedValue,
      filePath: values.filePath ?? null,
      fileHash: values.fileHash ?? null,
      submissionReference: values.submissionReference ?? null,
      submittedAt: values.submittedAt ?? null,
      responseReceivedAt: values.responseReceivedAt ?? null,
      createdAt: values.createdAt ?? new Date(),
      createdBy: values.createdBy,
    };
    ahcipBatchStore.push(row);
    return row;
  }

  function executeOp(ctx: any): any[] {
    const store = storeForTable(ctx.table);

    switch (ctx.op) {
      case 'select': {
        // Handle JOINs
        if (ctx.joins && ctx.joins.length > 0) {
          // Start from the "from" table
          let rows = store.map((row: any) => ({ __primary: row }));

          // Apply each join sequentially
          for (const join of ctx.joins) {
            const joinStore = storeForTable(join.table);
            const nextRows: any[] = [];
            for (const row of rows) {
              // Use the combined row for join predicate
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

          // Flatten combined rows for where/projection
          let flatRows = rows.map((row: any) => {
            const flat: any = { ...row.__primary };
            for (const [key, val] of Object.entries(row)) {
              if (key.startsWith('__join_') && typeof val === 'object' && val !== null) {
                Object.assign(flat, val);
              }
            }
            return flat;
          });

          // Apply WHERE predicates
          flatRows = flatRows.filter((row) =>
            ctx.whereClauses.every((pred: any) => pred(row)),
          );

          // Apply GROUP BY with aggregates
          if (ctx.groupByFields && ctx.groupByFields.length > 0 && ctx.selectFields) {
            const groups = new Map<string, any[]>();
            for (const row of flatRows) {
              const key = ctx.groupByFields
                .map((f: any) => row[f?.name] ?? '')
                .join('|');
              if (!groups.has(key)) groups.set(key, []);
              groups.get(key)!.push(row);
            }

            return Array.from(groups.values()).map((groupRows) => {
              const result: any = {};
              const representative = groupRows[0];
              for (const [alias, val] of Object.entries(ctx.selectFields) as [string, any][]) {
                if (val?.__aggregate === 'count') {
                  result[alias] = groupRows.length;
                } else if (val?.__aggregate === 'sum') {
                  const colName = val.__column?.name;
                  result[alias] = groupRows
                    .reduce((acc: number, r: any) => acc + (parseFloat(r[colName]) || 0), 0)
                    .toFixed(2);
                } else if (val?.name) {
                  result[alias] = representative[val.name];
                }
              }
              return result;
            });
          }

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

          // Apply LIMIT
          const limited = ctx.limitN ? flatRows.slice(0, ctx.limitN) : flatRows;

          // Apply structured projection
          if (ctx.selectFields) {
            return limited.map((row: any) => {
              const result: any = {};
              for (const [alias, val] of Object.entries(ctx.selectFields) as [string, any][]) {
                if (val?.__table) {
                  // Table reference — return only columns from that table
                  const tableStore = storeForTable(val);
                  if (tableStore === ahcipDetailStore) {
                    result[alias] = extractAhcipDetailFields(row);
                  } else if (tableStore === ahcipBatchStore) {
                    result[alias] = extractAhcipBatchFields(row);
                  } else if (tableStore === claimStore) {
                    result[alias] = extractClaimFields(row);
                  } else if (tableStore === patientStore) {
                    result[alias] = extractPatientFields(row);
                  }
                } else if (typeof val === 'object' && val !== null && !val.name) {
                  // Object of column refs
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

        // No-join SELECT (simple)
        let matches = store.filter((row) =>
          ctx.whereClauses.every((pred: any) => pred(row)),
        );

        if (ctx.orderByFns && ctx.orderByFns.length > 0) {
          matches = [...matches].sort((a, b) => {
            for (const sortFn of ctx.orderByFns) {
              const result = sortFn(a, b);
              if (result !== 0) return result;
            }
            return 0;
          });
        }

        if (ctx.offsetN) matches = matches.slice(ctx.offsetN);
        const limited = ctx.limitN ? matches.slice(0, ctx.limitN) : matches;

        // Handle aggregate-only selects (e.g., select({ total: count() }))
        if (ctx.selectFields) {
          const hasAggregates = Object.values(ctx.selectFields).some(
            (v: any) => v?.__aggregate,
          );

          if (hasAggregates) {
            const result: any = {};
            for (const [alias, col] of Object.entries(ctx.selectFields) as [string, any][]) {
              if (col?.__aggregate === 'count') {
                result[alias] = matches.length;
              } else if (col?.__aggregate === 'sum') {
                const colName = col.__column?.name;
                result[alias] = matches
                  .reduce((acc: number, r: any) => acc + (parseFloat(r[colName]) || 0), 0)
                  .toFixed(2);
              } else if (col?.name) {
                result[alias] = limited[0]?.[col.name];
              }
            }
            return [result];
          }

          return limited.map((row: any) => {
            const result: any = {};
            for (const [alias, col] of Object.entries(ctx.selectFields)) {
              const colName = (col as any)?.name;
              if (colName) {
                result[alias] = row[colName];
              }
            }
            return result;
          });
        }

        return limited;
      }
      case 'insert': {
        const values = ctx.values;
        const insertFn =
          store === ahcipBatchStore ? insertAhcipBatchRow : insertAhcipDetailRow;
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

  // Extraction helpers for projections
  function extractAhcipDetailFields(row: any): any {
    return {
      ahcipDetailId: row.ahcipDetailId,
      claimId: row.claimId,
      baNumber: row.baNumber,
      functionalCentre: row.functionalCentre,
      healthServiceCode: row.healthServiceCode,
      modifier1: row.modifier1,
      modifier2: row.modifier2,
      modifier3: row.modifier3,
      diagnosticCode: row.diagnosticCode,
      facilityNumber: row.facilityNumber,
      referralPractitioner: row.referralPractitioner,
      encounterType: row.encounterType,
      calls: row.calls,
      timeSpent: row.timeSpent,
      patientLocation: row.patientLocation,
      shadowBillingFlag: row.shadowBillingFlag,
      pcpcmBasketFlag: row.pcpcmBasketFlag,
      afterHoursFlag: row.afterHoursFlag,
      afterHoursType: row.afterHoursType,
      submittedFee: row.submittedFee,
      assessedFee: row.assessedFee,
      assessmentExplanatoryCodes: row.assessmentExplanatoryCodes,
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

  function extractAhcipBatchFields(row: any): any {
    return {
      ahcipBatchId: row.ahcipBatchId,
      physicianId: row.physicianId,
      baNumber: row.baNumber,
      batchWeek: row.batchWeek,
      status: row.status,
      claimCount: row.claimCount,
      totalSubmittedValue: row.totalSubmittedValue,
      filePath: row.filePath,
      fileHash: row.fileHash,
      submissionReference: row.submissionReference,
      submittedAt: row.submittedAt,
      responseReceivedAt: row.responseReceivedAt,
      createdAt: row.createdAt,
      createdBy: row.createdBy,
    };
  }

  function extractPatientFields(row: any): any {
    return {
      patientId: row.patientId,
      providerId: row.providerId,
      phn: row.phn,
      phnProvince: row.phnProvince,
      firstName: row.firstName,
      middleName: row.middleName,
      lastName: row.lastName,
      dateOfBirth: row.dateOfBirth,
      gender: row.gender,
      phone: row.phone,
      email: row.email,
      addressLine1: row.addressLine1,
      addressLine2: row.addressLine2,
      city: row.city,
      province: row.province,
      postalCode: row.postalCode,
      notes: row.notes,
      isActive: row.isActive,
      lastVisitDate: row.lastVisitDate,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
      createdBy: row.createdBy,
    };
  }

  const mockDb: any = {
    insert(table: any) {
      return chainable({ op: 'insert', table, whereClauses: [], joins: [] });
    },
    select(fields?: any) {
      return chainable({
        op: 'select',
        selectFields: fields,
        whereClauses: [],
        orderByFns: [],
        joins: [],
      });
    },
    update(table: any) {
      return chainable({ op: 'update', table, whereClauses: [], joins: [] });
    },
    delete(table: any) {
      return chainable({ op: 'delete', table, whereClauses: [], joins: [] });
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
        __joinPredicate: (a: any, b: any) => {
          if (value?.name) {
            return a[colName] === b[value.name];
          }
          return a[colName] === value;
        },
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
    isNull: (column: any) => {
      const colName = column?.name;
      return {
        __predicate: (row: any) => row[colName] == null,
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
      return { __sortFn: () => 0 };
    },
    gte: (column: any, value: any) => {
      const colName = column?.name;
      return {
        __predicate: (row: any) => (row[colName] ?? '') >= value,
      };
    },
    lte: (column: any, value: any) => {
      const colName = column?.name;
      return {
        __predicate: (row: any) => (row[colName] ?? '') <= value,
      };
    },
    count: () => {
      return { __aggregate: 'count' };
    },
    sum: (column: any) => {
      return { __aggregate: 'sum', __column: column };
    },
    inArray: (column: any, values: any[]) => {
      const colName = column?.name;
      return {
        __predicate: (row: any) => values.includes(row[colName]),
      };
    },
  };
});

// Mock table references so they carry __table metadata
vi.mock('@meritum/shared/schemas/db/ahcip.schema.js', () => {
  const makeCol = (name: string) => ({ name });
  return {
    ahcipClaimDetails: {
      __table: 'ahcip_claim_details',
      ahcipDetailId: makeCol('ahcipDetailId'),
      claimId: makeCol('claimId'),
      baNumber: makeCol('baNumber'),
      functionalCentre: makeCol('functionalCentre'),
      healthServiceCode: makeCol('healthServiceCode'),
      modifier1: makeCol('modifier1'),
      modifier2: makeCol('modifier2'),
      modifier3: makeCol('modifier3'),
      diagnosticCode: makeCol('diagnosticCode'),
      facilityNumber: makeCol('facilityNumber'),
      referralPractitioner: makeCol('referralPractitioner'),
      encounterType: makeCol('encounterType'),
      calls: makeCol('calls'),
      timeSpent: makeCol('timeSpent'),
      patientLocation: makeCol('patientLocation'),
      shadowBillingFlag: makeCol('shadowBillingFlag'),
      pcpcmBasketFlag: makeCol('pcpcmBasketFlag'),
      afterHoursFlag: makeCol('afterHoursFlag'),
      afterHoursType: makeCol('afterHoursType'),
      submittedFee: makeCol('submittedFee'),
      assessedFee: makeCol('assessedFee'),
      assessmentExplanatoryCodes: makeCol('assessmentExplanatoryCodes'),
    },
    ahcipBatches: {
      __table: 'ahcip_batches',
      ahcipBatchId: makeCol('ahcipBatchId'),
      physicianId: makeCol('physicianId'),
      baNumber: makeCol('baNumber'),
      batchWeek: makeCol('batchWeek'),
      status: makeCol('status'),
      claimCount: makeCol('claimCount'),
      totalSubmittedValue: makeCol('totalSubmittedValue'),
      filePath: makeCol('filePath'),
      fileHash: makeCol('fileHash'),
      submissionReference: makeCol('submissionReference'),
      submittedAt: makeCol('submittedAt'),
      responseReceivedAt: makeCol('responseReceivedAt'),
      createdAt: makeCol('createdAt'),
      createdBy: makeCol('createdBy'),
    },
  };
});

vi.mock('@meritum/shared/schemas/db/claim.schema.js', () => {
  const makeCol = (name: string) => ({ name });
  return {
    claims: {
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
    },
  };
});

vi.mock('@meritum/shared/schemas/db/patient.schema.js', () => {
  const makeCol = (name: string) => ({ name });
  return {
    patients: {
      __table: 'patients',
      patientId: makeCol('patientId'),
      providerId: makeCol('providerId'),
      phn: makeCol('phn'),
      phnProvince: makeCol('phnProvince'),
      firstName: makeCol('firstName'),
      middleName: makeCol('middleName'),
      lastName: makeCol('lastName'),
      dateOfBirth: makeCol('dateOfBirth'),
      gender: makeCol('gender'),
      phone: makeCol('phone'),
      email: makeCol('email'),
      addressLine1: makeCol('addressLine1'),
      addressLine2: makeCol('addressLine2'),
      city: makeCol('city'),
      province: makeCol('province'),
      postalCode: makeCol('postalCode'),
      notes: makeCol('notes'),
      isActive: makeCol('isActive'),
      lastVisitDate: makeCol('lastVisitDate'),
      createdAt: makeCol('createdAt'),
      updatedAt: makeCol('updatedAt'),
      createdBy: makeCol('createdBy'),
    },
  };
});

vi.mock('@meritum/shared/constants/claim.constants.js', () => ({
  ClaimState: {
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
  },
  ClaimType: {
    AHCIP: 'AHCIP',
    WCB: 'WCB',
  },
}));

vi.mock('@meritum/shared/constants/ahcip.constants.js', () => ({
  AhcipBatchStatus: {
    ASSEMBLING: 'ASSEMBLING',
    GENERATED: 'GENERATED',
    SUBMITTED: 'SUBMITTED',
    RESPONSE_RECEIVED: 'RESPONSE_RECEIVED',
    RECONCILED: 'RECONCILED',
    ERROR: 'ERROR',
  },
  AhcipModifierCode: {
    TM: 'TM',
    AFHR: 'AFHR',
    CMGP: 'CMGP',
    LOCI: 'LOCI',
    ED_SURCHARGE: '13.99H',
    BMI: 'BMI',
  },
  AhcipValidationCheckId: {
    A1_HSC_CODE_VALID: 'A1_HSC_CODE_VALID',
    A2_HSC_ACTIVE_ON_DOS: 'A2_HSC_ACTIVE_ON_DOS',
    A3_BA_NUMBER_VALID: 'A3_BA_NUMBER_VALID',
    A4_GOVERNING_RULES: 'A4_GOVERNING_RULES',
    A5_MODIFIER_ELIGIBILITY: 'A5_MODIFIER_ELIGIBILITY',
    A6_MODIFIER_COMBINATION: 'A6_MODIFIER_COMBINATION',
    A7_DIAGNOSTIC_CODE_REQUIRED: 'A7_DIAGNOSTIC_CODE_REQUIRED',
    A8_FACILITY_REQUIRED: 'A8_FACILITY_REQUIRED',
    A9_REFERRAL_REQUIRED: 'A9_REFERRAL_REQUIRED',
    A10_DI_SURCHARGE_ELIGIBILITY: 'A10_DI_SURCHARGE_ELIGIBILITY',
    A11_PCPCM_ROUTING: 'A11_PCPCM_ROUTING',
    A12_AFTER_HOURS_ELIGIBILITY: 'A12_AFTER_HOURS_ELIGIBILITY',
    A13_90_DAY_WINDOW: 'A13_90_DAY_WINDOW',
    A14_TIME_BASED_DURATION: 'A14_TIME_BASED_DURATION',
    A15_CALL_COUNT_VALID: 'A15_CALL_COUNT_VALID',
    A16_SHADOW_BILLING_CONSISTENCY: 'A16_SHADOW_BILLING_CONSISTENCY',
    A17_RRNP_ELIGIBILITY: 'A17_RRNP_ELIGIBILITY',
    A18_PREMIUM_ELIGIBILITY_351: 'A18_PREMIUM_ELIGIBILITY_351',
    A19_BUNDLING_CHECK: 'A19_BUNDLING_CHECK',
  },
  AfterHoursType: {
    EVENING: 'EVENING',
    WEEKEND: 'WEEKEND',
    NIGHT: 'NIGHT',
    STAT_HOLIDAY: 'STAT_HOLIDAY',
  },
  STANDARD_HOURS_START: 8,
  STANDARD_HOURS_END: 17,
  EVENING_HOURS_END: 23,
  SHADOW_BILLING_FEE: '0.00',
  BATCH_RETRY_INTERVALS_S: Object.freeze([60, 300, 900, 3600]),
  BATCH_MAX_RETRIES: 4,
  BATCH_CUTOFF_DAY: 4,
  BATCH_CUTOFF_HOUR: 12,
}));

// ---------------------------------------------------------------------------
// Test Helpers
// ---------------------------------------------------------------------------

function seedClaim(overrides: Partial<Record<string, any>> = {}): Record<string, any> {
  const claim = {
    claimId: overrides.claimId ?? crypto.randomUUID(),
    physicianId: overrides.physicianId ?? PHYSICIAN_1,
    patientId: overrides.patientId ?? PATIENT_1,
    claimType: overrides.claimType ?? 'AHCIP',
    state: overrides.state ?? 'QUEUED',
    isClean: overrides.isClean ?? true,
    importSource: overrides.importSource ?? 'MANUAL',
    importBatchId: overrides.importBatchId ?? null,
    shiftId: overrides.shiftId ?? null,
    dateOfService: overrides.dateOfService ?? '2026-02-01',
    submissionDeadline: overrides.submissionDeadline ?? '2026-05-02',
    submittedBatchId: overrides.submittedBatchId ?? null,
    validationResult: overrides.validationResult ?? null,
    validationTimestamp: overrides.validationTimestamp ?? null,
    referenceDataVersion: overrides.referenceDataVersion ?? null,
    aiCoachSuggestions: overrides.aiCoachSuggestions ?? null,
    duplicateAlert: overrides.duplicateAlert ?? null,
    flags: overrides.flags ?? null,
    createdAt: overrides.createdAt ?? new Date(),
    createdBy: overrides.createdBy ?? USER_1,
    updatedAt: overrides.updatedAt ?? new Date(),
    updatedBy: overrides.updatedBy ?? USER_1,
    deletedAt: overrides.deletedAt ?? null,
  };
  claimStore.push(claim);
  return claim;
}

function seedPatient(overrides: Partial<Record<string, any>> = {}): Record<string, any> {
  const patient = {
    patientId: overrides.patientId ?? PATIENT_1,
    providerId: overrides.providerId ?? PHYSICIAN_1,
    phn: overrides.phn ?? '123456789',
    phnProvince: overrides.phnProvince ?? 'AB',
    firstName: overrides.firstName ?? 'Jane',
    middleName: overrides.middleName ?? null,
    lastName: overrides.lastName ?? 'Doe',
    dateOfBirth: overrides.dateOfBirth ?? '1985-03-15',
    gender: overrides.gender ?? 'F',
    phone: overrides.phone ?? null,
    email: overrides.email ?? null,
    addressLine1: overrides.addressLine1 ?? null,
    addressLine2: overrides.addressLine2 ?? null,
    city: overrides.city ?? null,
    province: overrides.province ?? null,
    postalCode: overrides.postalCode ?? null,
    notes: overrides.notes ?? null,
    isActive: overrides.isActive ?? true,
    lastVisitDate: overrides.lastVisitDate ?? null,
    createdAt: overrides.createdAt ?? new Date(),
    updatedAt: overrides.updatedAt ?? new Date(),
    createdBy: overrides.createdBy ?? USER_1,
  };
  patientStore.push(patient);
  return patient;
}

function seedBatch(overrides: Partial<Record<string, any>> = {}): Record<string, any> {
  const batch = {
    ahcipBatchId: overrides.ahcipBatchId ?? crypto.randomUUID(),
    physicianId: overrides.physicianId ?? PHYSICIAN_1,
    baNumber: overrides.baNumber ?? '12345',
    batchWeek: overrides.batchWeek ?? '2026-02-19',
    status: overrides.status ?? 'ASSEMBLING',
    claimCount: overrides.claimCount ?? 5,
    totalSubmittedValue: overrides.totalSubmittedValue ?? '425.00',
    filePath: overrides.filePath ?? null,
    fileHash: overrides.fileHash ?? null,
    submissionReference: overrides.submissionReference ?? null,
    submittedAt: overrides.submittedAt ?? null,
    responseReceivedAt: overrides.responseReceivedAt ?? null,
    createdAt: overrides.createdAt ?? new Date(),
    createdBy: overrides.createdBy ?? USER_1,
  };
  ahcipBatchStore.push(batch);
  return batch;
}

function makeAhcipDetailData(
  claimId: string,
  overrides: Partial<Record<string, any>> = {},
): Record<string, any> {
  return {
    claimId,
    baNumber: overrides.baNumber ?? '12345',
    functionalCentre: overrides.functionalCentre ?? 'FC001',
    healthServiceCode: overrides.healthServiceCode ?? '03.04A',
    modifier1: overrides.modifier1 ?? null,
    modifier2: overrides.modifier2 ?? null,
    modifier3: overrides.modifier3 ?? null,
    diagnosticCode: overrides.diagnosticCode ?? '780',
    facilityNumber: overrides.facilityNumber ?? null,
    referralPractitioner: overrides.referralPractitioner ?? null,
    encounterType: overrides.encounterType ?? 'FOLLOW_UP',
    calls: overrides.calls ?? 1,
    timeSpent: overrides.timeSpent ?? null,
    patientLocation: overrides.patientLocation ?? null,
    shadowBillingFlag: overrides.shadowBillingFlag ?? false,
    pcpcmBasketFlag: overrides.pcpcmBasketFlag ?? false,
    afterHoursFlag: overrides.afterHoursFlag ?? false,
    afterHoursType: overrides.afterHoursType ?? null,
    submittedFee: overrides.submittedFee ?? '85.00',
    assessedFee: overrides.assessedFee ?? null,
    assessmentExplanatoryCodes: overrides.assessmentExplanatoryCodes ?? null,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('AHCIP Repository', () => {
  let repo: ReturnType<typeof createAhcipRepository>;

  beforeEach(() => {
    ahcipDetailStore = [];
    ahcipBatchStore = [];
    claimStore = [];
    patientStore = [];
    const mockDb = makeMockDb();
    repo = createAhcipRepository(mockDb);
  });

  // =========================================================================
  // createAhcipDetail
  // =========================================================================

  describe('createAhcipDetail', () => {
    it('creates extension row linked to base claim', async () => {
      seedClaim({ claimId: CLAIM_1 });

      const data = makeAhcipDetailData(CLAIM_1);
      const result = await repo.createAhcipDetail(data as any);

      expect(result).toBeDefined();
      expect(result.ahcipDetailId).toBeDefined();
      expect(result.claimId).toBe(CLAIM_1);
      expect(result.baNumber).toBe('12345');
      expect(result.healthServiceCode).toBe('03.04A');
      expect(result.encounterType).toBe('FOLLOW_UP');
      expect(result.calls).toBe(1);
      expect(result.submittedFee).toBe('85.00');
      expect(result.assessedFee).toBeNull();
      expect(ahcipDetailStore).toHaveLength(1);
    });

    it('stores all AHCIP-specific fields correctly', async () => {
      seedClaim({ claimId: CLAIM_1 });

      const data = makeAhcipDetailData(CLAIM_1, {
        modifier1: 'AFHR',
        modifier2: 'CMGP',
        diagnosticCode: '460',
        facilityNumber: 'FAC001',
        referralPractitioner: 'PRAC001',
        timeSpent: 30,
        shadowBillingFlag: true,
        pcpcmBasketFlag: true,
        afterHoursFlag: true,
        afterHoursType: 'EVENING',
      });

      const result = await repo.createAhcipDetail(data as any);

      expect(result.modifier1).toBe('AFHR');
      expect(result.modifier2).toBe('CMGP');
      expect(result.diagnosticCode).toBe('460');
      expect(result.facilityNumber).toBe('FAC001');
      expect(result.referralPractitioner).toBe('PRAC001');
      expect(result.timeSpent).toBe(30);
      expect(result.shadowBillingFlag).toBe(true);
      expect(result.pcpcmBasketFlag).toBe(true);
      expect(result.afterHoursFlag).toBe(true);
      expect(result.afterHoursType).toBe('EVENING');
    });
  });

  // =========================================================================
  // findAhcipDetailByClaimId
  // =========================================================================

  describe('findAhcipDetailByClaimId', () => {
    it('returns detail for owning physician', async () => {
      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1 });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_1),
      });

      const result = await repo.findAhcipDetailByClaimId(CLAIM_1, PHYSICIAN_1);

      expect(result).not.toBeNull();
      expect(result!.claimId).toBe(CLAIM_1);
      expect(result!.claim).toBeDefined();
      expect(result!.claim.physicianId).toBe(PHYSICIAN_1);
    });

    it('returns null for different physician (no existence leakage)', async () => {
      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1 });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_1),
      });

      const result = await repo.findAhcipDetailByClaimId(CLAIM_1, PHYSICIAN_2);

      expect(result).toBeNull();
    });

    it('returns null for soft-deleted claims', async () => {
      seedClaim({
        claimId: CLAIM_1,
        physicianId: PHYSICIAN_1,
        deletedAt: new Date(),
      });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_1),
      });

      const result = await repo.findAhcipDetailByClaimId(CLAIM_1, PHYSICIAN_1);

      expect(result).toBeNull();
    });

    it('returns null for non-existent claim', async () => {
      const result = await repo.findAhcipDetailByClaimId(
        'non-existent-id',
        PHYSICIAN_1,
      );

      expect(result).toBeNull();
    });
  });

  // =========================================================================
  // updateAhcipDetail
  // =========================================================================

  describe('updateAhcipDetail', () => {
    it('updates AHCIP fields for owning physician', async () => {
      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1 });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_1),
      });

      const result = await repo.updateAhcipDetail(CLAIM_1, PHYSICIAN_1, {
        healthServiceCode: '08.19A',
        submittedFee: '120.50',
        modifier1: 'AFHR',
      } as any);

      expect(result).toBeDefined();
      expect(result!.healthServiceCode).toBe('08.19A');
      expect(result!.submittedFee).toBe('120.50');
      expect(result!.modifier1).toBe('AFHR');
    });

    it('rejects update for wrong physician', async () => {
      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1 });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_1),
      });

      const result = await repo.updateAhcipDetail(CLAIM_1, PHYSICIAN_2, {
        healthServiceCode: '08.19A',
      } as any);

      expect(result).toBeUndefined();
    });

    it('rejects update for soft-deleted claim', async () => {
      seedClaim({
        claimId: CLAIM_1,
        physicianId: PHYSICIAN_1,
        deletedAt: new Date(),
      });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_1),
      });

      const result = await repo.updateAhcipDetail(CLAIM_1, PHYSICIAN_1, {
        healthServiceCode: '08.19A',
      } as any);

      expect(result).toBeUndefined();
    });
  });

  // =========================================================================
  // findAhcipClaimWithDetails
  // =========================================================================

  describe('findAhcipClaimWithDetails', () => {
    it('returns joined claim + detail + patient for owning physician', async () => {
      seedPatient({ patientId: PATIENT_1 });
      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1, patientId: PATIENT_1 });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_1),
      });

      const result = await repo.findAhcipClaimWithDetails(CLAIM_1, PHYSICIAN_1);

      expect(result).not.toBeNull();
      expect(result!.claim.claimId).toBe(CLAIM_1);
      expect(result!.detail.healthServiceCode).toBe('03.04A');
      expect(result!.patient.firstName).toBe('Jane');
      expect(result!.patient.lastName).toBe('Doe');
      expect(result!.patient.phn).toBe('123456789');
      expect(result!.patient.dateOfBirth).toBe('1985-03-15');
    });

    it('returns null for wrong physician', async () => {
      seedPatient({ patientId: PATIENT_1 });
      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1, patientId: PATIENT_1 });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_1),
      });

      const result = await repo.findAhcipClaimWithDetails(CLAIM_1, PHYSICIAN_2);

      expect(result).toBeNull();
    });

    it('returns null for soft-deleted claim', async () => {
      seedPatient({ patientId: PATIENT_1 });
      seedClaim({
        claimId: CLAIM_1,
        physicianId: PHYSICIAN_1,
        patientId: PATIENT_1,
        deletedAt: new Date(),
      });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_1),
      });

      const result = await repo.findAhcipClaimWithDetails(CLAIM_1, PHYSICIAN_1);

      expect(result).toBeNull();
    });
  });

  // =========================================================================
  // listAhcipClaimsForBatch
  // =========================================================================

  describe('listAhcipClaimsForBatch', () => {
    it('returns only queued AHCIP claims for the specified BA', async () => {
      // QUEUED AHCIP claim for BA 12345 — should be included
      seedClaim({
        claimId: CLAIM_1,
        physicianId: PHYSICIAN_1,
        claimType: 'AHCIP',
        state: 'QUEUED',
        dateOfService: '2026-02-01',
      });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_1, { baNumber: '12345' }),
      });

      // QUEUED AHCIP claim for different BA — should NOT be included
      seedClaim({
        claimId: CLAIM_2,
        physicianId: PHYSICIAN_1,
        claimType: 'AHCIP',
        state: 'QUEUED',
        dateOfService: '2026-02-02',
      });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_2, { baNumber: '67890' }),
      });

      const result = await repo.listAhcipClaimsForBatch(
        PHYSICIAN_1,
        '12345',
      );

      expect(result).toHaveLength(1);
      expect(result[0].claim.claimId).toBe(CLAIM_1);
      expect(result[0].detail.baNumber).toBe('12345');
    });

    it('excludes non-QUEUED claims', async () => {
      // DRAFT state — not queued, should be excluded
      seedClaim({
        claimId: CLAIM_1,
        physicianId: PHYSICIAN_1,
        claimType: 'AHCIP',
        state: 'DRAFT',
      });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_1, { baNumber: '12345' }),
      });

      const result = await repo.listAhcipClaimsForBatch(
        PHYSICIAN_1,
        '12345',
      );

      expect(result).toHaveLength(0);
    });

    it('excludes WCB claims', async () => {
      seedClaim({
        claimId: CLAIM_1,
        physicianId: PHYSICIAN_1,
        claimType: 'WCB',
        state: 'QUEUED',
      });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_1, { baNumber: '12345' }),
      });

      const result = await repo.listAhcipClaimsForBatch(
        PHYSICIAN_1,
        '12345',
      );

      expect(result).toHaveLength(0);
    });

    it('excludes claims from other physicians', async () => {
      seedClaim({
        claimId: CLAIM_1,
        physicianId: PHYSICIAN_2,
        claimType: 'AHCIP',
        state: 'QUEUED',
      });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_1, { baNumber: '12345' }),
      });

      const result = await repo.listAhcipClaimsForBatch(
        PHYSICIAN_1,
        '12345',
      );

      expect(result).toHaveLength(0);
    });

    it('filters by ba_number for PCPCM routing', async () => {
      // PCPCM BA claim
      seedClaim({
        claimId: CLAIM_1,
        physicianId: PHYSICIAN_1,
        claimType: 'AHCIP',
        state: 'QUEUED',
      });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_1, { baNumber: 'PCPCM_BA', pcpcmBasketFlag: true }),
      });

      // FFS BA claim
      seedClaim({
        claimId: CLAIM_2,
        physicianId: PHYSICIAN_1,
        claimType: 'AHCIP',
        state: 'QUEUED',
      });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_2, { baNumber: 'FFS_BA', pcpcmBasketFlag: false }),
      });

      const pcpcmBatch = await repo.listAhcipClaimsForBatch(
        PHYSICIAN_1,
        'PCPCM_BA',
      );
      expect(pcpcmBatch).toHaveLength(1);
      expect(pcpcmBatch[0].detail.pcpcmBasketFlag).toBe(true);

      const ffsBatch = await repo.listAhcipClaimsForBatch(
        PHYSICIAN_1,
        'FFS_BA',
      );
      expect(ffsBatch).toHaveLength(1);
      expect(ffsBatch[0].detail.pcpcmBasketFlag).toBe(false);
    });

    it('filters by isClean flag when specified', async () => {
      seedClaim({
        claimId: CLAIM_1,
        physicianId: PHYSICIAN_1,
        claimType: 'AHCIP',
        state: 'QUEUED',
        isClean: true,
      });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_1, { baNumber: '12345' }),
      });

      seedClaim({
        claimId: CLAIM_2,
        physicianId: PHYSICIAN_1,
        claimType: 'AHCIP',
        state: 'QUEUED',
        isClean: false,
      });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_2, { baNumber: '12345' }),
      });

      const cleanOnly = await repo.listAhcipClaimsForBatch(
        PHYSICIAN_1,
        '12345',
        true,
      );
      expect(cleanOnly).toHaveLength(1);
      expect(cleanOnly[0].claim.claimId).toBe(CLAIM_1);

      const flaggedOnly = await repo.listAhcipClaimsForBatch(
        PHYSICIAN_1,
        '12345',
        false,
      );
      expect(flaggedOnly).toHaveLength(1);
      expect(flaggedOnly[0].claim.claimId).toBe(CLAIM_2);
    });

    it('excludes soft-deleted claims', async () => {
      seedClaim({
        claimId: CLAIM_1,
        physicianId: PHYSICIAN_1,
        claimType: 'AHCIP',
        state: 'QUEUED',
        deletedAt: new Date(),
      });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_1, { baNumber: '12345' }),
      });

      const result = await repo.listAhcipClaimsForBatch(
        PHYSICIAN_1,
        '12345',
      );

      expect(result).toHaveLength(0);
    });
  });

  // =========================================================================
  // updateAssessmentResult
  // =========================================================================

  describe('updateAssessmentResult', () => {
    it('stores assessed fee and explanatory codes', async () => {
      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1 });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_1),
      });

      const codes = [
        { code: 'E01', message: 'Fee adjusted per schedule' },
        { code: 'E02', message: 'Modifier not applicable' },
      ];

      const result = await repo.updateAssessmentResult(
        CLAIM_1,
        PHYSICIAN_1,
        '75.00',
        codes,
      );

      expect(result).toBeDefined();
      expect(result!.assessedFee).toBe('75.00');
      expect(result!.assessmentExplanatoryCodes).toEqual(codes);
    });

    it('returns undefined for wrong physician', async () => {
      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1 });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_1),
      });

      const result = await repo.updateAssessmentResult(
        CLAIM_1,
        PHYSICIAN_2,
        '75.00',
        [],
      );

      expect(result).toBeUndefined();
    });

    it('returns undefined for soft-deleted claim', async () => {
      seedClaim({
        claimId: CLAIM_1,
        physicianId: PHYSICIAN_1,
        deletedAt: new Date(),
      });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_1),
      });

      const result = await repo.updateAssessmentResult(
        CLAIM_1,
        PHYSICIAN_1,
        '75.00',
        [],
      );

      expect(result).toBeUndefined();
    });

    it('returns undefined for non-existent claim', async () => {
      const result = await repo.updateAssessmentResult(
        'non-existent-id',
        PHYSICIAN_1,
        '75.00',
        [],
      );

      expect(result).toBeUndefined();
    });
  });

  // =========================================================================
  // createAhcipBatch
  // =========================================================================

  describe('createAhcipBatch', () => {
    it('creates batch with ASSEMBLING status', async () => {
      const result = await repo.createAhcipBatch({
        physicianId: PHYSICIAN_1,
        baNumber: '12345',
        batchWeek: '2026-02-19',
        status: 'IGNORED', // should be overridden to ASSEMBLING
        claimCount: 5,
        totalSubmittedValue: '425.00',
        createdBy: USER_1,
      } as any);

      expect(result).toBeDefined();
      expect(result.ahcipBatchId).toBeDefined();
      expect(result.status).toBe('ASSEMBLING');
      expect(result.physicianId).toBe(PHYSICIAN_1);
      expect(result.baNumber).toBe('12345');
      expect(result.batchWeek).toBe('2026-02-19');
      expect(result.claimCount).toBe(5);
      expect(result.totalSubmittedValue).toBe('425.00');
      expect(ahcipBatchStore).toHaveLength(1);
    });

    it('stores all batch fields correctly', async () => {
      const result = await repo.createAhcipBatch({
        physicianId: PHYSICIAN_1,
        baNumber: '67890',
        batchWeek: '2026-02-26',
        status: 'ASSEMBLING',
        claimCount: 10,
        totalSubmittedValue: '1500.00',
        createdBy: USER_1,
      } as any);

      expect(result.baNumber).toBe('67890');
      expect(result.batchWeek).toBe('2026-02-26');
      expect(result.claimCount).toBe(10);
      expect(result.totalSubmittedValue).toBe('1500.00');
      expect(result.filePath).toBeNull();
      expect(result.fileHash).toBeNull();
      expect(result.submissionReference).toBeNull();
      expect(result.submittedAt).toBeNull();
      expect(result.responseReceivedAt).toBeNull();
    });
  });

  // =========================================================================
  // findBatchById
  // =========================================================================

  describe('findBatchById', () => {
    it('returns batch for owning physician', async () => {
      const batch = seedBatch({
        ahcipBatchId: BATCH_1,
        physicianId: PHYSICIAN_1,
      });

      const result = await repo.findBatchById(BATCH_1, PHYSICIAN_1);

      expect(result).not.toBeNull();
      expect(result!.ahcipBatchId).toBe(BATCH_1);
      expect(result!.physicianId).toBe(PHYSICIAN_1);
    });

    it('returns null for different physician (no existence leakage)', async () => {
      seedBatch({
        ahcipBatchId: BATCH_1,
        physicianId: PHYSICIAN_1,
      });

      const result = await repo.findBatchById(BATCH_1, PHYSICIAN_2);

      expect(result).toBeNull();
    });

    it('returns null for non-existent batch', async () => {
      const result = await repo.findBatchById(
        'non-existent-id',
        PHYSICIAN_1,
      );

      expect(result).toBeNull();
    });
  });

  // =========================================================================
  // updateBatchStatus
  // =========================================================================

  describe('updateBatchStatus', () => {
    it('transitions status correctly', async () => {
      seedBatch({
        ahcipBatchId: BATCH_1,
        physicianId: PHYSICIAN_1,
        status: 'ASSEMBLING',
      });

      const result = await repo.updateBatchStatus(
        BATCH_1,
        PHYSICIAN_1,
        'GENERATED',
      );

      expect(result).toBeDefined();
      expect(result!.status).toBe('GENERATED');
    });

    it('updates extra fields when provided', async () => {
      seedBatch({
        ahcipBatchId: BATCH_1,
        physicianId: PHYSICIAN_1,
        status: 'GENERATED',
      });

      const submittedAt = new Date('2026-02-20T12:00:00Z');
      const result = await repo.updateBatchStatus(
        BATCH_1,
        PHYSICIAN_1,
        'SUBMITTED',
        {
          filePath: '/batches/2026-02-19/batch-12345.enc',
          fileHash: 'abc123def456',
          submissionReference: 'HLINK-REF-001',
          submittedAt,
        } as any,
      );

      expect(result).toBeDefined();
      expect(result!.status).toBe('SUBMITTED');
      expect(result!.filePath).toBe('/batches/2026-02-19/batch-12345.enc');
      expect(result!.fileHash).toBe('abc123def456');
      expect(result!.submissionReference).toBe('HLINK-REF-001');
      expect(result!.submittedAt).toEqual(submittedAt);
    });

    it('returns undefined for wrong physician', async () => {
      seedBatch({
        ahcipBatchId: BATCH_1,
        physicianId: PHYSICIAN_1,
      });

      const result = await repo.updateBatchStatus(
        BATCH_1,
        PHYSICIAN_2,
        'GENERATED',
      );

      expect(result).toBeUndefined();
    });
  });

  // =========================================================================
  // listBatches
  // =========================================================================

  describe('listBatches', () => {
    it('returns physician-scoped batches', async () => {
      seedBatch({ physicianId: PHYSICIAN_1, batchWeek: '2026-02-19' });
      seedBatch({ physicianId: PHYSICIAN_2, batchWeek: '2026-02-19' });

      const result = await repo.listBatches(PHYSICIAN_1, {
        page: 1,
        pageSize: 20,
      });

      expect(result.data).toHaveLength(1);
      expect(result.data[0].physicianId).toBe(PHYSICIAN_1);
      expect(result.pagination.total).toBe(1);
    });

    it('filters by status', async () => {
      seedBatch({ physicianId: PHYSICIAN_1, status: 'ASSEMBLING', batchWeek: '2026-02-12' });
      seedBatch({ physicianId: PHYSICIAN_1, status: 'SUBMITTED', batchWeek: '2026-02-19', baNumber: '67890' });

      const result = await repo.listBatches(PHYSICIAN_1, {
        status: 'SUBMITTED',
        page: 1,
        pageSize: 20,
      });

      expect(result.data).toHaveLength(1);
      expect(result.data[0].status).toBe('SUBMITTED');
    });

    it('filters by date range', async () => {
      seedBatch({ physicianId: PHYSICIAN_1, batchWeek: '2026-01-09', baNumber: '11111' });
      seedBatch({ physicianId: PHYSICIAN_1, batchWeek: '2026-02-13', baNumber: '22222' });
      seedBatch({ physicianId: PHYSICIAN_1, batchWeek: '2026-03-20', baNumber: '33333' });

      const result = await repo.listBatches(PHYSICIAN_1, {
        dateFrom: '2026-02-01',
        dateTo: '2026-02-28',
        page: 1,
        pageSize: 20,
      });

      expect(result.data).toHaveLength(1);
      expect(result.data[0].batchWeek).toBe('2026-02-13');
    });

    it('paginates correctly', async () => {
      // Create 5 batches with different weeks/BAs to avoid unique constraint
      seedBatch({ physicianId: PHYSICIAN_1, batchWeek: '2026-01-02', baNumber: '11111' });
      seedBatch({ physicianId: PHYSICIAN_1, batchWeek: '2026-01-09', baNumber: '11111' });
      seedBatch({ physicianId: PHYSICIAN_1, batchWeek: '2026-01-16', baNumber: '11111' });
      seedBatch({ physicianId: PHYSICIAN_1, batchWeek: '2026-01-23', baNumber: '11111' });
      seedBatch({ physicianId: PHYSICIAN_1, batchWeek: '2026-01-30', baNumber: '11111' });

      const page1 = await repo.listBatches(PHYSICIAN_1, {
        page: 1,
        pageSize: 2,
      });

      expect(page1.data).toHaveLength(2);
      expect(page1.pagination.total).toBe(5);
      expect(page1.pagination.page).toBe(1);
      expect(page1.pagination.pageSize).toBe(2);
      expect(page1.pagination.hasMore).toBe(true);

      const page3 = await repo.listBatches(PHYSICIAN_1, {
        page: 3,
        pageSize: 2,
      });

      expect(page3.data).toHaveLength(1);
      expect(page3.pagination.hasMore).toBe(false);
    });
  });

  // =========================================================================
  // findNextBatchPreview
  // =========================================================================

  describe('findNextBatchPreview', () => {
    it('returns queued claims grouped by BA', async () => {
      // BA 12345: 2 queued claims
      seedClaim({
        claimId: CLAIM_1,
        physicianId: PHYSICIAN_1,
        claimType: 'AHCIP',
        state: 'QUEUED',
      });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_1, { baNumber: '12345', submittedFee: '85.00' }),
      });

      seedClaim({
        claimId: CLAIM_2,
        physicianId: PHYSICIAN_1,
        claimType: 'AHCIP',
        state: 'QUEUED',
      });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_2, { baNumber: '12345', submittedFee: '120.00' }),
      });

      // BA 67890: 1 queued claim
      seedClaim({
        claimId: CLAIM_3,
        physicianId: PHYSICIAN_1,
        claimType: 'AHCIP',
        state: 'QUEUED',
      });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_3, { baNumber: '67890', submittedFee: '50.00' }),
      });

      const result = await repo.findNextBatchPreview(PHYSICIAN_1);

      expect(result).toHaveLength(2);

      const ba12345 = result.find((g) => g.baNumber === '12345');
      expect(ba12345).toBeDefined();
      expect(ba12345!.claimCount).toBe(2);
      expect(ba12345!.totalValue).toBe('205.00');

      const ba67890 = result.find((g) => g.baNumber === '67890');
      expect(ba67890).toBeDefined();
      expect(ba67890!.claimCount).toBe(1);
      expect(ba67890!.totalValue).toBe('50.00');
    });

    it('excludes non-queued and non-AHCIP claims', async () => {
      // DRAFT AHCIP — excluded
      seedClaim({
        claimId: CLAIM_1,
        physicianId: PHYSICIAN_1,
        claimType: 'AHCIP',
        state: 'DRAFT',
      });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_1, { baNumber: '12345', submittedFee: '85.00' }),
      });

      // WCB QUEUED — excluded (wrong type)
      seedClaim({
        claimId: CLAIM_2,
        physicianId: PHYSICIAN_1,
        claimType: 'WCB',
        state: 'QUEUED',
      });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_2, { baNumber: '12345', submittedFee: '100.00' }),
      });

      const result = await repo.findNextBatchPreview(PHYSICIAN_1);

      expect(result).toHaveLength(0);
    });

    it('excludes other physician claims', async () => {
      seedClaim({
        claimId: CLAIM_1,
        physicianId: PHYSICIAN_2,
        claimType: 'AHCIP',
        state: 'QUEUED',
      });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_1, { baNumber: '12345', submittedFee: '85.00' }),
      });

      const result = await repo.findNextBatchPreview(PHYSICIAN_1);

      expect(result).toHaveLength(0);
    });
  });

  // =========================================================================
  // findBatchesAwaitingResponse
  // =========================================================================

  describe('findBatchesAwaitingResponse', () => {
    it('returns only SUBMITTED batches', async () => {
      seedBatch({
        physicianId: PHYSICIAN_1,
        status: 'SUBMITTED',
        batchWeek: '2026-02-12',
        baNumber: '11111',
      });
      seedBatch({
        physicianId: PHYSICIAN_1,
        status: 'ASSEMBLING',
        batchWeek: '2026-02-19',
        baNumber: '22222',
      });
      seedBatch({
        physicianId: PHYSICIAN_1,
        status: 'RECONCILED',
        batchWeek: '2026-02-05',
        baNumber: '33333',
      });

      const result = await repo.findBatchesAwaitingResponse(PHYSICIAN_1);

      expect(result).toHaveLength(1);
      expect(result[0].status).toBe('SUBMITTED');
    });

    it('excludes other physician batches', async () => {
      seedBatch({
        physicianId: PHYSICIAN_2,
        status: 'SUBMITTED',
        batchWeek: '2026-02-12',
      });

      const result = await repo.findBatchesAwaitingResponse(PHYSICIAN_1);

      expect(result).toHaveLength(0);
    });
  });

  // =========================================================================
  // findBatchByWeek
  // =========================================================================

  describe('findBatchByWeek', () => {
    it('returns batch for specific cycle', async () => {
      seedBatch({
        ahcipBatchId: BATCH_1,
        physicianId: PHYSICIAN_1,
        baNumber: '12345',
        batchWeek: '2026-02-19',
      });

      const result = await repo.findBatchByWeek(
        PHYSICIAN_1,
        '12345',
        '2026-02-19',
      );

      expect(result).not.toBeNull();
      expect(result!.ahcipBatchId).toBe(BATCH_1);
      expect(result!.baNumber).toBe('12345');
      expect(result!.batchWeek).toBe('2026-02-19');
    });

    it('returns null for non-existent week', async () => {
      seedBatch({
        physicianId: PHYSICIAN_1,
        baNumber: '12345',
        batchWeek: '2026-02-19',
      });

      const result = await repo.findBatchByWeek(
        PHYSICIAN_1,
        '12345',
        '2026-02-26',
      );

      expect(result).toBeNull();
    });

    it('returns null for different BA number', async () => {
      seedBatch({
        physicianId: PHYSICIAN_1,
        baNumber: '12345',
        batchWeek: '2026-02-19',
      });

      const result = await repo.findBatchByWeek(
        PHYSICIAN_1,
        '67890',
        '2026-02-19',
      );

      expect(result).toBeNull();
    });

    it('rejects duplicate (unique constraint on physician + BA + week)', async () => {
      // First batch succeeds
      await repo.createAhcipBatch({
        physicianId: PHYSICIAN_1,
        baNumber: '12345',
        batchWeek: '2026-02-19',
        status: 'ASSEMBLING',
        claimCount: 3,
        totalSubmittedValue: '255.00',
        createdBy: USER_1,
      } as any);

      // Duplicate should throw
      await expect(
        repo.createAhcipBatch({
          physicianId: PHYSICIAN_1,
          baNumber: '12345',
          batchWeek: '2026-02-19',
          status: 'ASSEMBLING',
          claimCount: 2,
          totalSubmittedValue: '170.00',
          createdBy: USER_1,
        } as any),
      ).rejects.toThrow(/unique constraint/);
    });
  });

  // =========================================================================
  // linkClaimsToBatch
  // =========================================================================

  describe('linkClaimsToBatch', () => {
    it('sets submitted_batch_id on all claims', async () => {
      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'QUEUED' });
      seedClaim({ claimId: CLAIM_2, physicianId: PHYSICIAN_1, state: 'QUEUED' });
      seedClaim({ claimId: CLAIM_3, physicianId: PHYSICIAN_1, state: 'QUEUED' });

      const linkedCount = await repo.linkClaimsToBatch(
        [CLAIM_1, CLAIM_2, CLAIM_3],
        BATCH_1,
      );

      expect(linkedCount).toBe(3);

      // Verify all claims now have the batch ID
      const claim1 = claimStore.find((c) => c.claimId === CLAIM_1);
      const claim2 = claimStore.find((c) => c.claimId === CLAIM_2);
      const claim3 = claimStore.find((c) => c.claimId === CLAIM_3);

      expect(claim1!.submittedBatchId).toBe(BATCH_1);
      expect(claim2!.submittedBatchId).toBe(BATCH_1);
      expect(claim3!.submittedBatchId).toBe(BATCH_1);
    });

    it('returns 0 for empty claim list', async () => {
      const linkedCount = await repo.linkClaimsToBatch([], BATCH_1);

      expect(linkedCount).toBe(0);
    });

    it('only links matching claims', async () => {
      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1 });
      // CLAIM_2 does not exist

      const linkedCount = await repo.linkClaimsToBatch(
        [CLAIM_1, CLAIM_2],
        BATCH_1,
      );

      // Only CLAIM_1 matched
      expect(linkedCount).toBe(1);
      const claim1 = claimStore.find((c) => c.claimId === CLAIM_1);
      expect(claim1!.submittedBatchId).toBe(BATCH_1);
    });
  });
});

// ===========================================================================
// AHCIP Service Tests
// ===========================================================================

import {
  createAhcipClaim,
  resolveAfterHoursFromShift,
  validateAhcipClaim,
  calculateFee,
  calculateFeePreview,
  getFeeBreakdown,
  assembleBatch,
  generateHlinkFile,
  transmitBatch,
  previewNextBatch,
  retryFailedBatch,
  formatHlinkHeader,
  formatHlinkClaimRecord,
  formatHlinkTrailer,
  computeChecksum,
  sleep,
  ingestAssessmentFile,
  processAssessmentRecord,
  reconcilePayment,
  getAssessmentResults,
  listBatchesAwaitingResponse,
  parseAssessmentFile,
  type AhcipServiceDeps,
  type ClaimService,
  type ProviderService,
  type ReferenceDataService,
  type ShiftLookup,
  type CreateClaimInput,
  type CreateAhcipDetailInput,
  type AhcipValidationDeps,
  type AhcipValidationRefData,
  type AhcipValidationProviderService,
  type AhcipValidationClaimLookup,
  type AhcipClaimForValidation,
  type HscDetail,
  type ModifierDetail,
  type GoverningRuleDetail,
  type FeeCalculationDeps,
  type FeeReferenceDataService,
  type FeeProviderService,
  type FeeCalculateInput,
  type ModifierFeeImpact,
  type BatchCycleDeps,
  type BatchNotificationService,
  type ClaimStateService,
  type HlinkTransmissionService,
  type FileEncryptionService,
  type SubmissionPreferenceService,
  type BatchValidationRunner,
  type AssessmentIngestionDeps,
  type HlinkAssessmentRetrievalService,
  type ExplanatoryCodeService,
  type AssessmentRecord,
} from './ahcip.service.js';

// ---------------------------------------------------------------------------
// Service Test Helpers
// ---------------------------------------------------------------------------

function makeClaimServiceMock(): ClaimService {
  return {
    createClaim: vi.fn().mockResolvedValue({ claimId: CLAIM_1 }),
  };
}

function makeProviderServiceMock(overrides?: Partial<{
  ba_number: string;
  ba_type: 'FFS' | 'PCPCM';
  routing_reason: string;
  warning?: string;
}>): ProviderService {
  return {
    routeClaimToBa: vi.fn().mockResolvedValue({
      ba_number: overrides?.ba_number ?? 'BA-FFS-001',
      ba_type: overrides?.ba_type ?? 'FFS',
      routing_reason: overrides?.routing_reason ?? 'NON_PCPCM',
      ...(overrides?.warning ? { warning: overrides.warning } : {}),
    }),
  };
}

function makeReferenceDataMock(overrides?: Partial<{
  isHoliday: boolean;
  holidayName?: string;
  pcpcmBasket?: string | null;
}>): ReferenceDataService {
  return {
    getPcpcmBasket: vi.fn().mockResolvedValue(
      overrides?.pcpcmBasket !== undefined
        ? { hscCode: '03.04A', basket: overrides.pcpcmBasket, notes: null }
        : null,
    ),
    isHoliday: vi.fn().mockResolvedValue({
      is_holiday: overrides?.isHoliday ?? false,
      ...(overrides?.holidayName ? { holiday_name: overrides.holidayName } : {}),
    }),
  };
}

function makeShiftLookupMock(shiftInfo?: {
  startTime: string | null;
  endTime: string | null;
}): ShiftLookup {
  return {
    getShift: vi.fn().mockResolvedValue(
      shiftInfo
        ? {
            shiftId: 'shift-001',
            facilityId: 'fac-001',
            shiftDate: '2026-02-01',
            startTime: shiftInfo.startTime,
            endTime: shiftInfo.endTime,
          }
        : null,
    ),
  };
}

function makeServiceDeps(overrides?: {
  claimService?: ClaimService;
  providerService?: ProviderService;
  referenceData?: ReferenceDataService;
  shiftLookup?: ShiftLookup;
}): AhcipServiceDeps {
  const mockDb = makeMockDb();
  const repo = createAhcipRepository(mockDb);
  return {
    repo,
    claimService: overrides?.claimService ?? makeClaimServiceMock(),
    providerService: overrides?.providerService ?? makeProviderServiceMock(),
    referenceData: overrides?.referenceData ?? makeReferenceDataMock(),
    shiftLookup: overrides?.shiftLookup,
  };
}

const BASE_DATA: CreateClaimInput = {
  claimType: 'AHCIP',
  patientId: PATIENT_1,
  dateOfService: '2026-02-02', // Monday
};

const AHCIP_DATA: CreateAhcipDetailInput = {
  healthServiceCode: '03.04A',
  functionalCentre: 'FC001',
  encounterType: 'FOLLOW_UP',
  calls: 1,
  submittedFee: '85.00',
};

// ---------------------------------------------------------------------------
// Service Test Suite
// ---------------------------------------------------------------------------

describe('AHCIP Service', () => {
  beforeEach(() => {
    ahcipDetailStore = [];
    ahcipBatchStore = [];
    claimStore = [];
    patientStore = [];
  });

  // =========================================================================
  // createAhcipClaim
  // =========================================================================

  describe('createAhcipClaim', () => {
    it('creates base claim + AHCIP detail', async () => {
      const deps = makeServiceDeps();

      const result = await createAhcipClaim(
        deps,
        PHYSICIAN_1,
        USER_1,
        'physician',
        BASE_DATA,
        AHCIP_DATA,
      );

      expect(result.claimId).toBe(CLAIM_1);
      expect(result.ahcipDetailId).toBeDefined();
      expect(result.baNumber).toBe('BA-FFS-001');
      expect(result.pcpcmBasketFlag).toBe(false);
      expect(result.shadowBillingFlag).toBe(false);
      expect(result.afterHoursFlag).toBe(false);
      expect(result.afterHoursType).toBeNull();

      // Verify Domain 4.0 createClaim was called with correct args
      expect(deps.claimService.createClaim).toHaveBeenCalledWith(
        PHYSICIAN_1,
        USER_1,
        'physician',
        expect.objectContaining({
          claimType: 'AHCIP',
          patientId: PATIENT_1,
          dateOfService: '2026-02-02',
        }),
      );

      // Verify provider routing was called
      expect(deps.providerService.routeClaimToBa).toHaveBeenCalledWith(
        PHYSICIAN_1,
        'AHCIP',
        '03.04A',
        '2026-02-02',
      );
    });

    it('resolves FFS BA for non-PCPCM physician', async () => {
      const providerService = makeProviderServiceMock({
        ba_number: 'BA-FFS-999',
        ba_type: 'FFS',
        routing_reason: 'NON_PCPCM',
      });
      const deps = makeServiceDeps({ providerService });

      const result = await createAhcipClaim(
        deps,
        PHYSICIAN_1,
        USER_1,
        'physician',
        BASE_DATA,
        AHCIP_DATA,
      );

      expect(result.baNumber).toBe('BA-FFS-999');
      expect(result.pcpcmBasketFlag).toBe(false);
    });

    it('resolves PCPCM BA for in-basket code', async () => {
      const providerService = makeProviderServiceMock({
        ba_number: 'BA-PCPCM-001',
        ba_type: 'PCPCM',
        routing_reason: 'IN_BASKET',
      });
      const deps = makeServiceDeps({ providerService });

      const result = await createAhcipClaim(
        deps,
        PHYSICIAN_1,
        USER_1,
        'physician',
        BASE_DATA,
        AHCIP_DATA,
      );

      expect(result.baNumber).toBe('BA-PCPCM-001');
      expect(result.pcpcmBasketFlag).toBe(true);
    });

    it('resolves FFS BA for out-of-basket code on PCPCM physician', async () => {
      const providerService = makeProviderServiceMock({
        ba_number: 'BA-FFS-001',
        ba_type: 'FFS',
        routing_reason: 'OUT_OF_BASKET',
      });
      const deps = makeServiceDeps({ providerService });

      const result = await createAhcipClaim(
        deps,
        PHYSICIAN_1,
        USER_1,
        'physician',
        BASE_DATA,
        AHCIP_DATA,
      );

      expect(result.baNumber).toBe('BA-FFS-001');
      expect(result.pcpcmBasketFlag).toBe(false);
    });

    it('sets submission_deadline to DOS + 90 days', async () => {
      const deps = makeServiceDeps();

      const result = await createAhcipClaim(
        deps,
        PHYSICIAN_1,
        USER_1,
        'physician',
        { ...BASE_DATA, dateOfService: '2026-01-15' },
        AHCIP_DATA,
      );

      // 2026-01-15 + 90 days = 2026-04-15
      expect(result.submissionDeadline).toBe('2026-04-15');
    });

    it('calculates deadline correctly across month boundaries', async () => {
      const deps = makeServiceDeps();

      const result = await createAhcipClaim(
        deps,
        PHYSICIAN_1,
        USER_1,
        'physician',
        { ...BASE_DATA, dateOfService: '2026-11-15' },
        AHCIP_DATA,
      );

      // 2026-11-15 + 90 days = 2027-02-13
      expect(result.submissionDeadline).toBe('2027-02-13');
    });

    it('auto-detects after-hours from shift times (evening)', async () => {
      const referenceData = makeReferenceDataMock({ isHoliday: false });
      const deps = makeServiceDeps({ referenceData });

      // Tuesday service at 19:00 → evening after-hours
      const result = await createAhcipClaim(
        deps,
        PHYSICIAN_1,
        USER_1,
        'physician',
        { ...BASE_DATA, dateOfService: '2026-02-03' }, // Tuesday
        { ...AHCIP_DATA, serviceTime: '19:00' },
      );

      expect(result.afterHoursFlag).toBe(true);
      expect(result.afterHoursType).toBe('EVENING');
    });

    it('auto-detects after-hours from night time', async () => {
      const referenceData = makeReferenceDataMock({ isHoliday: false });
      const deps = makeServiceDeps({ referenceData });

      // Wednesday service at 02:00 → night after-hours
      const result = await createAhcipClaim(
        deps,
        PHYSICIAN_1,
        USER_1,
        'physician',
        { ...BASE_DATA, dateOfService: '2026-02-04' }, // Wednesday
        { ...AHCIP_DATA, serviceTime: '02:00' },
      );

      expect(result.afterHoursFlag).toBe(true);
      expect(result.afterHoursType).toBe('NIGHT');
    });

    it('detects weekend after-hours', async () => {
      const referenceData = makeReferenceDataMock({ isHoliday: false });
      const deps = makeServiceDeps({ referenceData });

      // Saturday
      const result = await createAhcipClaim(
        deps,
        PHYSICIAN_1,
        USER_1,
        'physician',
        { ...BASE_DATA, dateOfService: '2026-02-07' }, // Saturday
        AHCIP_DATA,
      );

      expect(result.afterHoursFlag).toBe(true);
      expect(result.afterHoursType).toBe('WEEKEND');
    });

    it('detects stat holiday after-hours', async () => {
      const referenceData = makeReferenceDataMock({
        isHoliday: true,
        holidayName: 'Family Day',
      });
      const deps = makeServiceDeps({ referenceData });

      // Family Day (Monday) — stat holiday takes priority
      const result = await createAhcipClaim(
        deps,
        PHYSICIAN_1,
        USER_1,
        'physician',
        { ...BASE_DATA, dateOfService: '2026-02-16' }, // Family Day
        AHCIP_DATA,
      );

      expect(result.afterHoursFlag).toBe(true);
      expect(result.afterHoursType).toBe('STAT_HOLIDAY');
    });

    it('sets standard hours when weekday within 08:00–17:00', async () => {
      const referenceData = makeReferenceDataMock({ isHoliday: false });
      const deps = makeServiceDeps({ referenceData });

      // Tuesday at 10:00 → standard hours
      const result = await createAhcipClaim(
        deps,
        PHYSICIAN_1,
        USER_1,
        'physician',
        { ...BASE_DATA, dateOfService: '2026-02-03' }, // Tuesday
        { ...AHCIP_DATA, serviceTime: '10:00' },
      );

      expect(result.afterHoursFlag).toBe(false);
      expect(result.afterHoursType).toBeNull();
    });

    it('sets shadow_billing_flag for TM modifier in modifier1', async () => {
      const deps = makeServiceDeps();

      const result = await createAhcipClaim(
        deps,
        PHYSICIAN_1,
        USER_1,
        'physician',
        BASE_DATA,
        { ...AHCIP_DATA, modifier1: 'TM', submittedFee: '85.00' },
      );

      expect(result.shadowBillingFlag).toBe(true);
      // Verify the detail was stored with fee $0.00
      expect(ahcipDetailStore[0].submittedFee).toBe('0.00');
    });

    it('sets shadow_billing_flag for TM modifier in modifier2', async () => {
      const deps = makeServiceDeps();

      const result = await createAhcipClaim(
        deps,
        PHYSICIAN_1,
        USER_1,
        'physician',
        BASE_DATA,
        { ...AHCIP_DATA, modifier2: 'TM', submittedFee: '85.00' },
      );

      expect(result.shadowBillingFlag).toBe(true);
      expect(ahcipDetailStore[0].submittedFee).toBe('0.00');
    });

    it('sets shadow_billing_flag for TM modifier in modifier3', async () => {
      const deps = makeServiceDeps();

      const result = await createAhcipClaim(
        deps,
        PHYSICIAN_1,
        USER_1,
        'physician',
        BASE_DATA,
        { ...AHCIP_DATA, modifier3: 'TM', submittedFee: '85.00' },
      );

      expect(result.shadowBillingFlag).toBe(true);
      expect(ahcipDetailStore[0].submittedFee).toBe('0.00');
    });

    it('preserves submitted fee when no TM modifier', async () => {
      const deps = makeServiceDeps();

      const result = await createAhcipClaim(
        deps,
        PHYSICIAN_1,
        USER_1,
        'physician',
        BASE_DATA,
        { ...AHCIP_DATA, modifier1: 'AFHR', submittedFee: '120.50' },
      );

      expect(result.shadowBillingFlag).toBe(false);
      expect(ahcipDetailStore[0].submittedFee).toBe('120.50');
    });

    it('stores all AHCIP detail fields correctly', async () => {
      const deps = makeServiceDeps();

      await createAhcipClaim(
        deps,
        PHYSICIAN_1,
        USER_1,
        'physician',
        BASE_DATA,
        {
          healthServiceCode: '08.19A',
          functionalCentre: 'FC002',
          encounterType: 'CONSULTATION',
          modifier1: 'AFHR',
          modifier2: 'CMGP',
          diagnosticCode: '460',
          facilityNumber: 'FAC001',
          referralPractitioner: 'PRAC001',
          calls: 2,
          timeSpent: 30,
          patientLocation: 'WARD',
          submittedFee: '150.00',
        },
      );

      expect(ahcipDetailStore).toHaveLength(1);
      const detail = ahcipDetailStore[0];
      expect(detail.healthServiceCode).toBe('08.19A');
      expect(detail.functionalCentre).toBe('FC002');
      expect(detail.encounterType).toBe('CONSULTATION');
      expect(detail.modifier1).toBe('AFHR');
      expect(detail.modifier2).toBe('CMGP');
      expect(detail.diagnosticCode).toBe('460');
      expect(detail.facilityNumber).toBe('FAC001');
      expect(detail.referralPractitioner).toBe('PRAC001');
      expect(detail.calls).toBe(2);
      expect(detail.timeSpent).toBe(30);
      expect(detail.patientLocation).toBe('WARD');
      expect(detail.submittedFee).toBe('150.00');
    });
  });

  // =========================================================================
  // resolveAfterHoursFromShift
  // =========================================================================

  describe('resolveAfterHoursFromShift', () => {
    it('detects after-hours from shift start time (evening)', async () => {
      const referenceData = makeReferenceDataMock({ isHoliday: false });
      const deps = makeServiceDeps({ referenceData });

      const result = await resolveAfterHoursFromShift(
        deps,
        '2026-02-03', // Tuesday
        '18:30',
        '23:30',
      );

      expect(result.afterHoursFlag).toBe(true);
      expect(result.afterHoursType).toBe('EVENING');
    });

    it('detects after-hours from shift on stat holiday', async () => {
      const referenceData = makeReferenceDataMock({
        isHoliday: true,
        holidayName: 'Canada Day',
      });
      const deps = makeServiceDeps({ referenceData });

      const result = await resolveAfterHoursFromShift(
        deps,
        '2026-07-01', // Canada Day (Wednesday)
        '09:00',
        '17:00',
      );

      expect(result.afterHoursFlag).toBe(true);
      expect(result.afterHoursType).toBe('STAT_HOLIDAY');
    });

    it('detects after-hours from shift on weekend', async () => {
      const referenceData = makeReferenceDataMock({ isHoliday: false });
      const deps = makeServiceDeps({ referenceData });

      const result = await resolveAfterHoursFromShift(
        deps,
        '2026-02-08', // Sunday
        '10:00',
        '18:00',
      );

      expect(result.afterHoursFlag).toBe(true);
      expect(result.afterHoursType).toBe('WEEKEND');
    });

    it('detects night shift from shift start time', async () => {
      const referenceData = makeReferenceDataMock({ isHoliday: false });
      const deps = makeServiceDeps({ referenceData });

      const result = await resolveAfterHoursFromShift(
        deps,
        '2026-02-03', // Tuesday
        '23:30',
        '07:00',
      );

      expect(result.afterHoursFlag).toBe(true);
      expect(result.afterHoursType).toBe('NIGHT');
    });

    it('returns standard hours for weekday daytime shift', async () => {
      const referenceData = makeReferenceDataMock({ isHoliday: false });
      const deps = makeServiceDeps({ referenceData });

      const result = await resolveAfterHoursFromShift(
        deps,
        '2026-02-03', // Tuesday
        '09:00',
        '16:00',
      );

      expect(result.afterHoursFlag).toBe(false);
      expect(result.afterHoursType).toBeNull();
    });

    it('returns not after-hours when no shift time provided on weekday', async () => {
      const referenceData = makeReferenceDataMock({ isHoliday: false });
      const deps = makeServiceDeps({ referenceData });

      const result = await resolveAfterHoursFromShift(
        deps,
        '2026-02-03', // Tuesday
        null,
        null,
      );

      expect(result.afterHoursFlag).toBe(false);
      expect(result.afterHoursType).toBeNull();
    });
  });
});

// ===========================================================================
// AHCIP Fee Calculation Tests
// ===========================================================================

// ---------------------------------------------------------------------------
// Fee Calculation Test Helpers
// ---------------------------------------------------------------------------

function makeFeeRefDataMock(overrides?: {
  baseFee?: string | null;
  hscOverrides?: Partial<HscDetail>;
  modifierImpacts?: Record<string, ModifierFeeImpact>;
  afterHoursPremium?: string | null;
  cmgpPremium?: string | null;
  rrnpPremium?: string | null;
  edSurcharge?: string | null;
}): FeeReferenceDataService {
  const hsc = makeHscDetail({
    baseFee: overrides?.baseFee ?? '85.00',
    ...overrides?.hscOverrides,
  });

  return {
    getHscDetail: vi.fn().mockResolvedValue(
      overrides?.baseFee === null ? null : hsc,
    ),
    getModifierFeeImpact: vi.fn().mockImplementation(
      async (modifierCode: string) => {
        if (overrides?.modifierImpacts && overrides.modifierImpacts[modifierCode]) {
          return overrides.modifierImpacts[modifierCode];
        }
        return null;
      },
    ),
    getAfterHoursPremium: vi.fn().mockResolvedValue(overrides?.afterHoursPremium ?? null),
    getCmgpPremium: vi.fn().mockResolvedValue(overrides?.cmgpPremium ?? null),
    getRrnpPremium: vi.fn().mockResolvedValue(overrides?.rrnpPremium ?? null),
    getEdSurcharge: vi.fn().mockResolvedValue(overrides?.edSurcharge ?? null),
  };
}

function makeFeeProviderServiceMock(overrides?: {
  rrnpEligible?: boolean;
}): FeeProviderService {
  return {
    isRrnpEligible: vi.fn().mockResolvedValue(overrides?.rrnpEligible ?? false),
  };
}

function makeFeeDeps(overrides?: {
  feeRefData?: FeeReferenceDataService;
  feeProviderService?: FeeProviderService;
}): FeeCalculationDeps {
  const mockDb = makeMockDb();
  const repo = createAhcipRepository(mockDb);
  return {
    repo,
    feeRefData: overrides?.feeRefData ?? makeFeeRefDataMock(),
    feeProviderService: overrides?.feeProviderService ?? makeFeeProviderServiceMock(),
  };
}

/** Seed a claim + AHCIP detail in the stores and return the IDs. */
function seedClaimWithDetail(overrides?: {
  claimOverrides?: Partial<Record<string, any>>;
  detailOverrides?: Partial<Record<string, any>>;
}): { claimId: string; ahcipDetailId: string } {
  const claimId = overrides?.claimOverrides?.claimId ?? CLAIM_1;
  const claim = seedClaim({
    claimId,
    physicianId: PHYSICIAN_1,
    dateOfService: '2026-02-02',
    ...overrides?.claimOverrides,
  });
  const ahcipDetailId = crypto.randomUUID();
  ahcipDetailStore.push({
    ahcipDetailId,
    ...makeAhcipDetailData(claimId, {
      submittedFee: null,
      ...overrides?.detailOverrides,
    }),
  });
  return { claimId, ahcipDetailId };
}

// ---------------------------------------------------------------------------
// Fee Calculation Test Suite
// ---------------------------------------------------------------------------

describe('AHCIP Fee Calculation', () => {
  beforeEach(() => {
    ahcipDetailStore = [];
    ahcipBatchStore = [];
    claimStore = [];
    patientStore = [];
  });

  // =========================================================================
  // calculateFee
  // =========================================================================

  describe('calculateFee', () => {
    it('returns correct base fee from SOMB', async () => {
      const { claimId } = seedClaimWithDetail();
      const feeRefData = makeFeeRefDataMock({ baseFee: '85.00' });
      const deps = makeFeeDeps({ feeRefData });

      const result = await calculateFee(deps, claimId, PHYSICIAN_1);

      expect(result.base_fee).toBe('85.00');
      expect(result.calls).toBe(1);
      expect(result.total_fee).toBe('85.00');
      // Verify fee was persisted
      expect(ahcipDetailStore[0].submittedFee).toBe('85.00');
    });

    it('applies modifier adjustments in priority order', async () => {
      const { claimId } = seedClaimWithDetail({
        detailOverrides: { modifier1: 'CMGP', modifier2: 'BMI' },
      });
      const feeRefData = makeFeeRefDataMock({
        baseFee: '100.00',
        modifierImpacts: {
          CMGP: {
            modifierCode: 'CMGP',
            calculationMethod: 'ADDITIVE',
            value: '15.00',
            priority: 1,
          },
          BMI: {
            modifierCode: 'BMI',
            calculationMethod: 'PERCENTAGE',
            value: '0.10',
            priority: 2,
          },
        },
      });
      const deps = makeFeeDeps({ feeRefData });

      const result = await calculateFee(deps, claimId, PHYSICIAN_1);

      // base_fee (100.00) + CMGP (15.00) + BMI (10% of 100 = 10.00) = 125.00
      expect(result.modifier_adjustments).toHaveLength(2);
      expect(result.modifier_adjustments[0].modifier).toBe('CMGP');
      expect(result.modifier_adjustments[0].amount).toBe('15.00');
      expect(result.modifier_adjustments[1].modifier).toBe('BMI');
      expect(result.modifier_adjustments[1].amount).toBe('10.00');
      expect(result.total_fee).toBe('125.00');
    });

    it('adds CMGP premium for qualifying code', async () => {
      const { claimId } = seedClaimWithDetail({
        detailOverrides: { modifier1: 'CMGP' },
      });
      const feeRefData = makeFeeRefDataMock({
        baseFee: '85.00',
        cmgpPremium: '20.00',
      });
      const deps = makeFeeDeps({ feeRefData });

      const result = await calculateFee(deps, claimId, PHYSICIAN_1);

      expect(result.premiums).toContainEqual({ type: 'CMGP', amount: '20.00' });
      expect(result.total_fee).toBe('105.00');
    });

    it('adds after-hours premium for evening', async () => {
      const { claimId } = seedClaimWithDetail({
        detailOverrides: {
          afterHoursFlag: true,
          afterHoursType: 'EVENING',
        },
      });
      const feeRefData = makeFeeRefDataMock({
        baseFee: '85.00',
        afterHoursPremium: '25.00',
        hscOverrides: { afterHoursEligible: true },
      });
      const deps = makeFeeDeps({ feeRefData });

      const result = await calculateFee(deps, claimId, PHYSICIAN_1);

      expect(result.premiums).toContainEqual({ type: 'AFTER_HOURS_EVENING', amount: '25.00' });
      expect(result.total_fee).toBe('110.00');
    });

    it('adds after-hours premium for weekend', async () => {
      const { claimId } = seedClaimWithDetail({
        detailOverrides: {
          afterHoursFlag: true,
          afterHoursType: 'WEEKEND',
        },
      });
      const feeRefData = makeFeeRefDataMock({
        baseFee: '85.00',
        afterHoursPremium: '30.00',
        hscOverrides: { afterHoursEligible: true },
      });
      const deps = makeFeeDeps({ feeRefData });

      const result = await calculateFee(deps, claimId, PHYSICIAN_1);

      expect(result.premiums).toContainEqual({ type: 'AFTER_HOURS_WEEKEND', amount: '30.00' });
      expect(result.total_fee).toBe('115.00');
    });

    it('adds after-hours premium for stat holiday', async () => {
      const { claimId } = seedClaimWithDetail({
        detailOverrides: {
          afterHoursFlag: true,
          afterHoursType: 'STAT_HOLIDAY',
        },
      });
      const feeRefData = makeFeeRefDataMock({
        baseFee: '85.00',
        afterHoursPremium: '40.00',
        hscOverrides: { afterHoursEligible: true },
      });
      const deps = makeFeeDeps({ feeRefData });

      const result = await calculateFee(deps, claimId, PHYSICIAN_1);

      expect(result.premiums).toContainEqual({ type: 'AFTER_HOURS_STAT_HOLIDAY', amount: '40.00' });
      expect(result.total_fee).toBe('125.00');
    });

    it('adds RRNP premium for qualifying physician', async () => {
      const { claimId } = seedClaimWithDetail();
      const feeRefData = makeFeeRefDataMock({
        baseFee: '85.00',
        rrnpPremium: '18.50',
      });
      const feeProviderService = makeFeeProviderServiceMock({ rrnpEligible: true });
      const deps = makeFeeDeps({ feeRefData, feeProviderService });

      const result = await calculateFee(deps, claimId, PHYSICIAN_1);

      expect(result.rrnp_premium).toBe('18.50');
      expect(result.total_fee).toBe('103.50');
    });

    it('returns $0 for shadow billing (TM modifier)', async () => {
      const { claimId } = seedClaimWithDetail({
        detailOverrides: {
          modifier1: 'TM',
          shadowBillingFlag: true,
        },
      });
      const feeRefData = makeFeeRefDataMock({ baseFee: '85.00' });
      const deps = makeFeeDeps({ feeRefData });

      const result = await calculateFee(deps, claimId, PHYSICIAN_1);

      expect(result.total_fee).toBe('0.00');
      expect(result.base_fee).toBe('85.00'); // base fee still shown in breakdown
    });

    it('handles multiple calls correctly', async () => {
      const { claimId } = seedClaimWithDetail({
        detailOverrides: { calls: 3 },
      });
      const feeRefData = makeFeeRefDataMock({ baseFee: '50.00' });
      const deps = makeFeeDeps({ feeRefData });

      const result = await calculateFee(deps, claimId, PHYSICIAN_1);

      expect(result.calls).toBe(3);
      expect(result.total_fee).toBe('150.00'); // 50.00 × 3
    });

    it('applies ED surcharge (13.99H)', async () => {
      const { claimId } = seedClaimWithDetail({
        detailOverrides: { modifier1: '13.99H' },
      });
      const feeRefData = makeFeeRefDataMock({
        baseFee: '85.00',
        edSurcharge: '13.99',
        hscOverrides: { surchargeEligible: true },
      });
      const deps = makeFeeDeps({ feeRefData });

      const result = await calculateFee(deps, claimId, PHYSICIAN_1);

      expect(result.premiums).toContainEqual({ type: 'ED_SURCHARGE', amount: '13.99' });
      expect(result.total_fee).toBe('98.99');
    });

    it('handles PCPCM in-basket code', async () => {
      const { claimId } = seedClaimWithDetail({
        detailOverrides: {
          pcpcmBasketFlag: true,
          healthServiceCode: '03.04F',
        },
      });
      const feeRefData = makeFeeRefDataMock({
        baseFee: '85.00',
        hscOverrides: { pcpcmBasket: 'IN_BASKET' },
      });
      const deps = makeFeeDeps({ feeRefData });

      const result = await calculateFee(deps, claimId, PHYSICIAN_1);

      // PCPCM in-basket: fee is calculated for tracking
      expect(result.base_fee).toBe('85.00');
      expect(result.total_fee).toBe('85.00');
    });

    it('returns zero breakdown when HSC code not found', async () => {
      const { claimId } = seedClaimWithDetail();
      const feeRefData = makeFeeRefDataMock({ baseFee: null });
      const deps = makeFeeDeps({ feeRefData });

      const result = await calculateFee(deps, claimId, PHYSICIAN_1);

      expect(result.base_fee).toBe('0.00');
      expect(result.total_fee).toBe('0.00');
      expect(result.modifier_adjustments).toHaveLength(0);
      expect(result.premiums).toHaveLength(0);
    });

    it('does not add RRNP premium for non-eligible physician', async () => {
      const { claimId } = seedClaimWithDetail();
      const feeRefData = makeFeeRefDataMock({ baseFee: '85.00' });
      const feeProviderService = makeFeeProviderServiceMock({ rrnpEligible: false });
      const deps = makeFeeDeps({ feeRefData, feeProviderService });

      const result = await calculateFee(deps, claimId, PHYSICIAN_1);

      expect(result.rrnp_premium).toBeNull();
      expect(result.total_fee).toBe('85.00');
    });
  });

  // =========================================================================
  // calculateFeePreview
  // =========================================================================

  describe('calculateFeePreview', () => {
    it('returns result without saving', async () => {
      const feeRefData = makeFeeRefDataMock({ baseFee: '85.00' });
      const deps = makeFeeDeps({ feeRefData });

      const data: FeeCalculateInput = {
        healthServiceCode: '03.04A',
        dateOfService: '2026-02-02',
        calls: 1,
      };

      const result = await calculateFeePreview(deps, PHYSICIAN_1, data);

      expect(result.base_fee).toBe('85.00');
      expect(result.total_fee).toBe('85.00');
      // No detail was seeded, so nothing was persisted
      expect(ahcipDetailStore).toHaveLength(0);
    });

    it('calculates with modifier adjustments without saving', async () => {
      const feeRefData = makeFeeRefDataMock({
        baseFee: '100.00',
        modifierImpacts: {
          BMI: {
            modifierCode: 'BMI',
            calculationMethod: 'PERCENTAGE',
            value: '0.15',
            priority: 1,
          },
        },
      });
      const deps = makeFeeDeps({ feeRefData });

      const data: FeeCalculateInput = {
        healthServiceCode: '03.04A',
        dateOfService: '2026-02-02',
        modifier1: 'BMI',
        calls: 2,
      };

      const result = await calculateFeePreview(deps, PHYSICIAN_1, data);

      // (100 × 2) + BMI (15% of 100 = 15.00) = 215.00
      expect(result.total_fee).toBe('215.00');
      expect(result.calls).toBe(2);
    });

    it('returns $0 for shadow billing preview', async () => {
      const feeRefData = makeFeeRefDataMock({ baseFee: '85.00' });
      const deps = makeFeeDeps({ feeRefData });

      const data: FeeCalculateInput = {
        healthServiceCode: '03.04A',
        dateOfService: '2026-02-02',
        modifier1: 'TM',
        shadowBillingFlag: true,
      };

      const result = await calculateFeePreview(deps, PHYSICIAN_1, data);

      expect(result.total_fee).toBe('0.00');
      expect(result.base_fee).toBe('85.00');
    });
  });

  // =========================================================================
  // getFeeBreakdown
  // =========================================================================

  describe('getFeeBreakdown', () => {
    it('returns itemised breakdown', async () => {
      const { claimId } = seedClaimWithDetail({
        detailOverrides: {
          modifier1: 'CMGP',
          afterHoursFlag: true,
          afterHoursType: 'EVENING',
        },
      });
      const feeRefData = makeFeeRefDataMock({
        baseFee: '85.00',
        cmgpPremium: '20.00',
        afterHoursPremium: '25.00',
        hscOverrides: { afterHoursEligible: true },
      });
      const feeProviderService = makeFeeProviderServiceMock({ rrnpEligible: true });
      const feeRefDataWithRrnp: FeeReferenceDataService = {
        ...feeRefData,
        getRrnpPremium: vi.fn().mockResolvedValue('18.50'),
      };
      const deps = makeFeeDeps({ feeRefData: feeRefDataWithRrnp, feeProviderService });

      const result = await getFeeBreakdown(deps, claimId, PHYSICIAN_1);

      expect(result.base_fee).toBe('85.00');
      expect(result.calls).toBe(1);
      expect(result.premiums).toContainEqual({ type: 'CMGP', amount: '20.00' });
      expect(result.premiums).toContainEqual({ type: 'AFTER_HOURS_EVENING', amount: '25.00' });
      expect(result.rrnp_premium).toBe('18.50');
      // 85.00 + 20.00 + 25.00 + 18.50 = 148.50
      expect(result.total_fee).toBe('148.50');
    });

    it('throws for non-existent claim', async () => {
      const deps = makeFeeDeps();

      await expect(
        getFeeBreakdown(deps, 'non-existent-id', PHYSICIAN_1),
      ).rejects.toThrow('Claim not found');
    });

    it('throws for wrong physician (tenant isolation)', async () => {
      seedClaimWithDetail({
        claimOverrides: { physicianId: PHYSICIAN_1 },
      });
      const deps = makeFeeDeps();

      await expect(
        getFeeBreakdown(deps, CLAIM_1, PHYSICIAN_2),
      ).rejects.toThrow('Claim not found');
    });
  });
});

// ===========================================================================
// AHCIP Validation Tests (A1–A19)
// ===========================================================================

// ---------------------------------------------------------------------------
// Validation Test Helpers
// ---------------------------------------------------------------------------

function makeHscDetail(overrides?: Partial<HscDetail>): HscDetail {
  return {
    code: '03.04A',
    description: 'Office visit — follow-up',
    baseFee: '85.00',
    feeType: 'FFS',
    isActive: true,
    effectiveFrom: '2020-01-01',
    effectiveTo: null,
    specialtyRestrictions: [],
    facilityRestrictions: [],
    requiresReferral: false,
    requiresDiagnosticCode: false,
    requiresFacility: false,
    isTimeBased: false,
    minTime: null,
    maxTime: null,
    minCalls: null,
    maxCalls: null,
    maxPerDay: null,
    surchargeEligible: false,
    pcpcmBasket: null,
    afterHoursEligible: true,
    premium351Eligible: false,
    combinationGroup: null,
    ...overrides,
  };
}

function makeModifierDetail(overrides?: Partial<ModifierDetail>): ModifierDetail {
  return {
    modifierCode: 'AFHR',
    name: 'After-Hours',
    calculationMethod: 'ADDITIVE',
    combinableWith: [],
    exclusiveWith: [],
    ...overrides,
  };
}

function makeValidationRefData(overrides?: {
  hscDetail?: HscDetail | null;
  modifiers?: ModifierDetail[];
  rules?: GoverningRuleDetail[];
  version?: string;
}): AhcipValidationRefData {
  const hscValue = overrides && 'hscDetail' in overrides
    ? overrides.hscDetail
    : makeHscDetail();
  return {
    getHscDetail: vi.fn().mockResolvedValue(hscValue),
    getModifiersForHsc: vi.fn().mockResolvedValue(overrides?.modifiers ?? [
      makeModifierDetail({ modifierCode: 'AFHR' }),
      makeModifierDetail({ modifierCode: 'CMGP' }),
      makeModifierDetail({ modifierCode: 'TM' }),
    ]),
    getModifierDetail: vi.fn().mockImplementation(async (code: string) => {
      const defaultMods = overrides?.modifiers ?? [
        makeModifierDetail({ modifierCode: 'AFHR', exclusiveWith: [] }),
        makeModifierDetail({ modifierCode: 'CMGP', exclusiveWith: [] }),
        makeModifierDetail({ modifierCode: 'TM', exclusiveWith: [] }),
      ];
      return defaultMods.find((m) => m.modifierCode === code) ?? null;
    }),
    getApplicableRules: vi.fn().mockResolvedValue(overrides?.rules ?? []),
    getCurrentVersion: vi.fn().mockResolvedValue(overrides?.version ?? 'somb-v2026.1'),
  };
}

function makeValidationProviderService(overrides?: {
  baValid?: boolean;
  rrnpEligible?: boolean;
}): AhcipValidationProviderService {
  return {
    validateBa: vi.fn().mockResolvedValue({
      valid: overrides?.baValid ?? true,
    }),
    isRrnpEligible: vi.fn().mockResolvedValue(overrides?.rrnpEligible ?? false),
  };
}

function makeValidationClaimLookup(overrides?: {
  otherClaims?: Array<{ claimId: string; healthServiceCode: string }>;
}): AhcipValidationClaimLookup {
  return {
    findClaimsForPatientOnDate: vi.fn().mockResolvedValue(overrides?.otherClaims ?? []),
  };
}

function makeValidationDeps(overrides?: {
  refData?: AhcipValidationRefData;
  providerService?: AhcipValidationProviderService;
  claimLookup?: AhcipValidationClaimLookup;
}): AhcipValidationDeps {
  return {
    refData: overrides?.refData ?? makeValidationRefData(),
    providerService: overrides?.providerService ?? makeValidationProviderService(),
    claimLookup: overrides?.claimLookup ?? makeValidationClaimLookup(),
  };
}

/** Calculate a deadline date from DOS + days offset. */
function deadlineFromToday(daysFromNow: number): string {
  const d = new Date();
  d.setUTCHours(0, 0, 0, 0);
  d.setUTCDate(d.getUTCDate() + daysFromNow);
  return d.toISOString().split('T')[0];
}

function makeTestClaim(overrides?: Partial<AhcipClaimForValidation>): AhcipClaimForValidation {
  return {
    claimId: CLAIM_1,
    physicianId: PHYSICIAN_1,
    patientId: PATIENT_1,
    dateOfService: '2026-02-02',
    submissionDeadline: deadlineFromToday(60), // 60 days from now (safe)
    healthServiceCode: '03.04A',
    baNumber: 'BA-12345',
    modifier1: null,
    modifier2: null,
    modifier3: null,
    diagnosticCode: null,
    facilityNumber: null,
    referralPractitioner: null,
    encounterType: 'FOLLOW_UP',
    calls: 1,
    timeSpent: null,
    shadowBillingFlag: false,
    pcpcmBasketFlag: false,
    afterHoursFlag: false,
    afterHoursType: null,
    ...overrides,
  };
}

function findEntry(entries: Array<{ check: string; severity: string; message: string }>, check: string, severity?: string) {
  return entries.find(
    (e) => e.check === check && (severity ? e.severity === severity : true),
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('validateAhcipClaim', () => {
  // =========================================================================
  // A1: HSC code valid
  // =========================================================================

  describe('A1: HSC code valid', () => {
    it('valid HSC code passes (no A1 error)', async () => {
      const deps = makeValidationDeps();
      const claim = makeTestClaim();

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_1);

      expect(findEntry(result.entries, 'A1_HSC_CODE_VALID', 'ERROR')).toBeUndefined();
      expect(result.referenceDataVersion).toBe('somb-v2026.1');
    });

    it('invalid HSC code returns error and short-circuits', async () => {
      const refData = makeValidationRefData({ hscDetail: null });
      const deps = makeValidationDeps({ refData });
      const claim = makeTestClaim({ healthServiceCode: 'INVALID' });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_1);

      const a1 = findEntry(result.entries, 'A1_HSC_CODE_VALID', 'ERROR');
      expect(a1).toBeDefined();
      expect(a1!.message).toContain('INVALID');
      // Short-circuit: only A1 error, no further checks
      expect(result.entries).toHaveLength(1);
    });
  });

  // =========================================================================
  // A2: HSC active on DOS
  // =========================================================================

  describe('A2: HSC active on DOS', () => {
    it('active HSC on DOS passes', async () => {
      const deps = makeValidationDeps();
      const claim = makeTestClaim();

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_1);

      expect(findEntry(result.entries, 'A2_HSC_ACTIVE_ON_DOS', 'ERROR')).toBeUndefined();
    });

    it('retired HSC code on DOS returns error', async () => {
      const refData = makeValidationRefData({
        hscDetail: makeHscDetail({ isActive: false }),
      });
      const deps = makeValidationDeps({ refData });
      const claim = makeTestClaim();

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_1);

      const a2 = findEntry(result.entries, 'A2_HSC_ACTIVE_ON_DOS', 'ERROR');
      expect(a2).toBeDefined();
      expect(a2!.message).toContain('not active');
    });
  });

  // =========================================================================
  // A3: BA number valid
  // =========================================================================

  describe('A3: BA number valid', () => {
    it('valid BA number passes', async () => {
      const deps = makeValidationDeps();
      const claim = makeTestClaim();

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_1);

      expect(findEntry(result.entries, 'A3_BA_NUMBER_VALID', 'ERROR')).toBeUndefined();
    });

    it('invalid BA number returns error', async () => {
      const providerService = makeValidationProviderService({ baValid: false });
      const deps = makeValidationDeps({ providerService });
      const claim = makeTestClaim({ baNumber: 'INVALID-BA' });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_1);

      const a3 = findEntry(result.entries, 'A3_BA_NUMBER_VALID', 'ERROR');
      expect(a3).toBeDefined();
      expect(a3!.message).toContain('INVALID-BA');
    });
  });

  // =========================================================================
  // A4: Governing rules
  // =========================================================================

  describe('A4: Governing rules', () => {
    it('GR 3 visit limit exceeded returns error', async () => {
      const refData = makeValidationRefData({
        rules: [
          {
            ruleId: 'GR_3',
            ruleName: 'Visit Limits',
            ruleCategory: 'VISIT_LIMIT',
            severity: 'ERROR',
            ruleLogic: { maxVisitsPerDay: 1 },
            errorMessage: 'Maximum visits per day exceeded.',
          },
        ],
      });
      const deps = makeValidationDeps({ refData });
      const claim = makeTestClaim({ calls: 3 });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_1);

      const a4 = findEntry(result.entries, 'A4_GOVERNING_RULES', 'ERROR');
      expect(a4).toBeDefined();
      expect(a4!.message).toContain('GR_3');
      expect(a4!.message).toContain('Visit limit exceeded');
    });

    it('GR 8 referral missing returns error', async () => {
      const refData = makeValidationRefData({
        rules: [
          {
            ruleId: 'GR_8',
            ruleName: 'Referrals',
            ruleCategory: 'REFERRAL',
            severity: 'ERROR',
            ruleLogic: { requiresReferral: true },
            errorMessage: 'Specialist consultations require a referring practitioner.',
          },
        ],
      });
      const deps = makeValidationDeps({ refData });
      const claim = makeTestClaim({ referralPractitioner: null });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_1);

      const a4 = findEntry(result.entries, 'A4_GOVERNING_RULES', 'ERROR');
      expect(a4).toBeDefined();
      expect(a4!.message).toContain('GR_8');
      expect(a4!.message).toContain('Referring practitioner required');
    });
  });

  // =========================================================================
  // A5: Modifier eligibility
  // =========================================================================

  describe('A5: Modifier eligibility', () => {
    it('valid modifier for HSC passes', async () => {
      const deps = makeValidationDeps();
      const claim = makeTestClaim({ modifier1: 'AFHR' });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_1);

      expect(findEntry(result.entries, 'A5_MODIFIER_ELIGIBILITY', 'ERROR')).toBeUndefined();
    });

    it('invalid modifier for HSC returns error', async () => {
      const deps = makeValidationDeps();
      const claim = makeTestClaim({ modifier1: 'BOGUS' });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_1);

      const a5 = findEntry(result.entries, 'A5_MODIFIER_ELIGIBILITY', 'ERROR');
      expect(a5).toBeDefined();
      expect(a5!.message).toContain('BOGUS');
      expect(a5!.message).toContain('not valid');
    });
  });

  // =========================================================================
  // A6: Modifier combination
  // =========================================================================

  describe('A6: Modifier combination', () => {
    it('mutually exclusive modifiers returns error', async () => {
      const refData = makeValidationRefData({
        modifiers: [
          makeModifierDetail({ modifierCode: 'AFHR', exclusiveWith: ['CMGP'] }),
          makeModifierDetail({ modifierCode: 'CMGP', exclusiveWith: ['AFHR'] }),
          makeModifierDetail({ modifierCode: 'TM', exclusiveWith: [] }),
        ],
      });
      const deps = makeValidationDeps({ refData });
      const claim = makeTestClaim({ modifier1: 'AFHR', modifier2: 'CMGP' });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_1);

      const a6 = findEntry(result.entries, 'A6_MODIFIER_COMBINATION', 'ERROR');
      expect(a6).toBeDefined();
      expect(a6!.message).toContain('mutually exclusive');
    });
  });

  // =========================================================================
  // A7: Diagnostic code required
  // =========================================================================

  describe('A7: Diagnostic code required', () => {
    it('missing required diagnostic code returns error', async () => {
      const refData = makeValidationRefData({
        hscDetail: makeHscDetail({ requiresDiagnosticCode: true }),
      });
      const deps = makeValidationDeps({ refData });
      const claim = makeTestClaim({ diagnosticCode: null });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_1);

      const a7 = findEntry(result.entries, 'A7_DIAGNOSTIC_CODE_REQUIRED', 'ERROR');
      expect(a7).toBeDefined();
      expect(a7!.message).toContain('Diagnostic code');
    });
  });

  // =========================================================================
  // A8: Facility required
  // =========================================================================

  describe('A8: Facility required', () => {
    it('missing facility for hospital claim returns error', async () => {
      const refData = makeValidationRefData({
        hscDetail: makeHscDetail({ requiresFacility: true }),
      });
      const deps = makeValidationDeps({ refData });
      const claim = makeTestClaim({ facilityNumber: null });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_1);

      const a8 = findEntry(result.entries, 'A8_FACILITY_REQUIRED', 'ERROR');
      expect(a8).toBeDefined();
      expect(a8!.message).toContain('Facility number');
    });
  });

  // =========================================================================
  // A9: Referral required
  // =========================================================================

  describe('A9: Referral required', () => {
    it('missing referral for specialist consultation returns error', async () => {
      const refData = makeValidationRefData({
        hscDetail: makeHscDetail({ requiresReferral: true }),
      });
      const deps = makeValidationDeps({ refData });
      const claim = makeTestClaim({ referralPractitioner: null });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_1);

      const a9 = findEntry(result.entries, 'A9_REFERRAL_REQUIRED', 'ERROR');
      expect(a9).toBeDefined();
      expect(a9!.message).toContain('Referring practitioner');
    });
  });

  // =========================================================================
  // A13: 90-day window
  // =========================================================================

  describe('A13: 90-day window', () => {
    it('expired 90-day window returns error', async () => {
      const deps = makeValidationDeps();
      const claim = makeTestClaim({
        submissionDeadline: '2025-01-01', // Far in the past
      });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_1);

      const a13 = findEntry(result.entries, 'A13_90_DAY_WINDOW', 'ERROR');
      expect(a13).toBeDefined();
      expect(a13!.message).toContain('expired');
    });

    it('within 7 days of deadline returns warning', async () => {
      const deps = makeValidationDeps();
      const claim = makeTestClaim({
        submissionDeadline: deadlineFromToday(5), // 5 days from now
      });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_1);

      const a13 = findEntry(result.entries, 'A13_90_DAY_WINDOW', 'WARNING');
      expect(a13).toBeDefined();
      expect(a13!.message).toContain('day(s)');
    });
  });

  // =========================================================================
  // A14: Time-based code duration
  // =========================================================================

  describe('A14: Time-based code duration', () => {
    it('missing time_spent for time-based code returns error', async () => {
      const refData = makeValidationRefData({
        hscDetail: makeHscDetail({ isTimeBased: true, minTime: 15, maxTime: 60 }),
      });
      const deps = makeValidationDeps({ refData });
      const claim = makeTestClaim({ timeSpent: null });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_1);

      const a14 = findEntry(result.entries, 'A14_TIME_BASED_DURATION', 'ERROR');
      expect(a14).toBeDefined();
      expect(a14!.message).toContain('time_spent is required');
    });
  });

  // =========================================================================
  // A16: Shadow billing consistency
  // =========================================================================

  describe('A16: Shadow billing consistency', () => {
    it('shadow billing flag without TM modifier returns warning', async () => {
      const deps = makeValidationDeps();
      const claim = makeTestClaim({
        shadowBillingFlag: true,
        modifier1: null,
        modifier2: null,
        modifier3: null,
      });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_1);

      const a16 = findEntry(result.entries, 'A16_SHADOW_BILLING_CONSISTENCY', 'WARNING');
      expect(a16).toBeDefined();
      expect(a16!.message).toContain('TM modifier is missing');
    });

    it('TM modifier without shadow billing flag returns warning', async () => {
      const deps = makeValidationDeps();
      const claim = makeTestClaim({
        shadowBillingFlag: false,
        modifier1: 'TM',
      });

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_1);

      const a16 = findEntry(result.entries, 'A16_SHADOW_BILLING_CONSISTENCY', 'WARNING');
      expect(a16).toBeDefined();
      expect(a16!.message).toContain('shadow billing flag is not set');
    });
  });

  // =========================================================================
  // A19: Bundling check
  // =========================================================================

  describe('A19: Bundling check', () => {
    it('potential bundling returns warning', async () => {
      const claimLookup = makeValidationClaimLookup({
        otherClaims: [
          { claimId: 'other-claim-1', healthServiceCode: '08.19A' },
        ],
      });
      const deps = makeValidationDeps({ claimLookup });
      const claim = makeTestClaim();

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_1);

      const a19 = findEntry(result.entries, 'A19_BUNDLING_CHECK', 'WARNING');
      expect(a19).toBeDefined();
      expect(a19!.message).toContain('Potential bundling');
      expect(a19!.message).toContain('08.19A');
    });

    it('no other claims means no bundling warning', async () => {
      const deps = makeValidationDeps();
      const claim = makeTestClaim();

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_1);

      expect(findEntry(result.entries, 'A19_BUNDLING_CHECK')).toBeUndefined();
    });
  });

  // =========================================================================
  // Clean claim — no entries for a well-formed claim
  // =========================================================================

  describe('Clean claim validation', () => {
    it('well-formed claim produces no errors or warnings', async () => {
      const deps = makeValidationDeps();
      const claim = makeTestClaim();

      const result = await validateAhcipClaim(deps, claim, PHYSICIAN_1);

      const errors = result.entries.filter((e) => e.severity === 'ERROR');
      expect(errors).toHaveLength(0);
      expect(result.referenceDataVersion).toBe('somb-v2026.1');
    });
  });
});

// ===========================================================================
// AHCIP Batch Cycle Tests
// ===========================================================================

function makeBatchCycleDeps(overrides?: Partial<BatchCycleDeps>): BatchCycleDeps {
  const mockDb = makeMockDb();
  const repo = createAhcipRepository(mockDb);

  const defaultFeeRefData: FeeReferenceDataService = {
    getHscDetail: vi.fn().mockResolvedValue({
      code: '03.04A',
      description: 'Office visit',
      baseFee: '85.00',
      feeType: 'FIXED',
      isActive: true,
      effectiveFrom: '2025-01-01',
      effectiveTo: null,
      specialtyRestrictions: [],
      facilityRestrictions: [],
      requiresReferral: false,
      requiresDiagnosticCode: false,
      requiresFacility: false,
      isTimeBased: false,
      minTime: null,
      maxTime: null,
      minCalls: null,
      maxCalls: null,
      maxPerDay: null,
      surchargeEligible: false,
      pcpcmBasket: null,
      afterHoursEligible: false,
      premium351Eligible: false,
      combinationGroup: null,
    }),
    getModifierFeeImpact: vi.fn().mockResolvedValue(null),
    getAfterHoursPremium: vi.fn().mockResolvedValue(null),
    getCmgpPremium: vi.fn().mockResolvedValue(null),
    getRrnpPremium: vi.fn().mockResolvedValue(null),
    getEdSurcharge: vi.fn().mockResolvedValue(null),
  };

  const defaultFeeProviderService: FeeProviderService = {
    isRrnpEligible: vi.fn().mockResolvedValue(false),
  };

  const defaultClaimStateService: ClaimStateService = {
    transitionState: vi.fn().mockResolvedValue(true),
  };

  const defaultNotificationService: BatchNotificationService = {
    emit: vi.fn().mockResolvedValue(undefined),
  };

  const defaultHlinkTransmission: HlinkTransmissionService = {
    transmit: vi.fn().mockResolvedValue({ submissionReference: 'HLINK-REF-001' }),
  };

  const defaultFileEncryption: FileEncryptionService = {
    encryptAndStore: vi.fn().mockResolvedValue({
      filePath: '/encrypted/batch-file.enc',
      fileHash: 'abcdef1234567890',
    }),
  };

  const defaultSubmissionPreferences: SubmissionPreferenceService = {
    getAutoSubmissionMode: vi.fn().mockResolvedValue('AUTO_ALL'),
  };

  const defaultValidationRunner: BatchValidationRunner = {
    validateClaim: vi.fn().mockResolvedValue({ passed: true, errors: [] }),
  };

  return {
    repo: overrides?.repo ?? repo,
    feeRefData: overrides?.feeRefData ?? defaultFeeRefData,
    feeProviderService: overrides?.feeProviderService ?? defaultFeeProviderService,
    claimStateService: overrides?.claimStateService ?? defaultClaimStateService,
    notificationService: overrides?.notificationService ?? defaultNotificationService,
    hlinkTransmission: overrides?.hlinkTransmission ?? defaultHlinkTransmission,
    fileEncryption: overrides?.fileEncryption ?? defaultFileEncryption,
    submissionPreferences: overrides?.submissionPreferences ?? defaultSubmissionPreferences,
    validationRunner: overrides?.validationRunner ?? defaultValidationRunner,
    sleep: overrides?.sleep ?? (async () => {}),
  };
}

function seedClaimWithDetailForBatch(
  claimOverrides: Partial<Record<string, any>> = {},
  detailOverrides: Partial<Record<string, any>> = {},
): { claim: Record<string, any>; detail: Record<string, any> } {
  const claim = seedClaim(claimOverrides);
  const detail = {
    ahcipDetailId: crypto.randomUUID(),
    ...makeAhcipDetailData(claim.claimId, detailOverrides),
  };
  ahcipDetailStore.push(detail);
  return { claim, detail };
}

describe('AHCIP Batch Cycle', () => {
  beforeEach(() => {
    ahcipDetailStore = [];
    ahcipBatchStore = [];
    claimStore = [];
    patientStore = [];
  });

  // =========================================================================
  // assembleBatch
  // =========================================================================

  describe('assembleBatch', () => {
    it('groups claims by BA number', async () => {
      const deps = makeBatchCycleDeps();

      // Create queued claims for two different BAs
      seedClaimWithDetailForBatch(
        { claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'QUEUED', claimType: 'AHCIP' },
        { baNumber: '12345', submittedFee: '85.00' },
      );
      seedClaimWithDetailForBatch(
        { claimId: CLAIM_2, physicianId: PHYSICIAN_1, state: 'QUEUED', claimType: 'AHCIP' },
        { baNumber: '67890', submittedFee: '120.00' },
      );

      const result = await assembleBatch(deps, PHYSICIAN_1, '2026-02-19');

      expect(result.batches).toHaveLength(2);
      const ba12345 = result.batches.find((b) => b.baNumber === '12345');
      const ba67890 = result.batches.find((b) => b.baNumber === '67890');
      expect(ba12345).toBeDefined();
      expect(ba12345!.claimCount).toBe(1);
      expect(ba67890).toBeDefined();
      expect(ba67890!.claimCount).toBe(1);
    });

    it('creates separate batches for PCPCM dual-BA', async () => {
      const deps = makeBatchCycleDeps();

      // PCPCM BA claim
      seedClaimWithDetailForBatch(
        { claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'QUEUED', claimType: 'AHCIP' },
        { baNumber: 'PCPCM_BA', pcpcmBasketFlag: true, submittedFee: '85.00' },
      );

      // FFS BA claim
      seedClaimWithDetailForBatch(
        { claimId: CLAIM_2, physicianId: PHYSICIAN_1, state: 'QUEUED', claimType: 'AHCIP' },
        { baNumber: 'FFS_BA', pcpcmBasketFlag: false, submittedFee: '120.00' },
      );

      const result = await assembleBatch(deps, PHYSICIAN_1, '2026-02-19');

      expect(result.batches).toHaveLength(2);
      expect(result.batches.map((b) => b.baNumber).sort()).toEqual(['FFS_BA', 'PCPCM_BA']);
    });

    it('removes claims failing pre-submission validation', async () => {
      const validationRunner: BatchValidationRunner = {
        validateClaim: vi.fn()
          .mockResolvedValueOnce({ passed: true, errors: [] })
          .mockResolvedValueOnce({
            passed: false,
            errors: [{ check: 'A1', severity: 'ERROR', rule_reference: '', message: 'HSC code invalid', help_text: '' }],
          }),
      };
      const claimStateService: ClaimStateService = {
        transitionState: vi.fn().mockResolvedValue(true),
      };
      const notificationService: BatchNotificationService = {
        emit: vi.fn().mockResolvedValue(undefined),
      };
      const deps = makeBatchCycleDeps({ validationRunner, claimStateService, notificationService });

      seedClaimWithDetailForBatch(
        { claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'QUEUED', claimType: 'AHCIP' },
        { baNumber: '12345', submittedFee: '85.00' },
      );
      seedClaimWithDetailForBatch(
        { claimId: CLAIM_2, physicianId: PHYSICIAN_1, state: 'QUEUED', claimType: 'AHCIP' },
        { baNumber: '12345', submittedFee: '120.00' },
      );

      const result = await assembleBatch(deps, PHYSICIAN_1, '2026-02-19');

      expect(result.batches).toHaveLength(1);
      expect(result.batches[0].claimCount).toBe(1);
      expect(result.removedClaims).toHaveLength(1);
      expect(result.removedClaims[0].claimId).toBe(CLAIM_2);

      // Verify failed claim was returned to VALIDATED
      expect(claimStateService.transitionState).toHaveBeenCalledWith(
        CLAIM_2, PHYSICIAN_1, 'QUEUED', 'VALIDATED', 'SYSTEM', 'SYSTEM',
      );

      // Verify notification emitted for removed claim
      expect(notificationService.emit).toHaveBeenCalledWith(
        'CLAIM_VALIDATION_FAILED_PRE_BATCH',
        expect.objectContaining({ claimId: CLAIM_2, physicianId: PHYSICIAN_1 }),
      );
    });

    it('calculates fee for each claim', async () => {
      const feeRefData: FeeReferenceDataService = {
        getHscDetail: vi.fn().mockResolvedValue({
          code: '03.04A', description: 'Office visit', baseFee: '85.00', feeType: 'FIXED',
          isActive: true, effectiveFrom: '2025-01-01', effectiveTo: null,
          specialtyRestrictions: [], facilityRestrictions: [],
          requiresReferral: false, requiresDiagnosticCode: false, requiresFacility: false,
          isTimeBased: false, minTime: null, maxTime: null, minCalls: null, maxCalls: null,
          maxPerDay: null, surchargeEligible: false, pcpcmBasket: null,
          afterHoursEligible: false, premium351Eligible: false, combinationGroup: null,
        }),
        getModifierFeeImpact: vi.fn().mockResolvedValue(null),
        getAfterHoursPremium: vi.fn().mockResolvedValue(null),
        getCmgpPremium: vi.fn().mockResolvedValue(null),
        getRrnpPremium: vi.fn().mockResolvedValue(null),
        getEdSurcharge: vi.fn().mockResolvedValue(null),
      };
      const deps = makeBatchCycleDeps({ feeRefData });

      seedClaimWithDetailForBatch(
        { claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'QUEUED', claimType: 'AHCIP' },
        { baNumber: '12345', submittedFee: null },
      );

      const result = await assembleBatch(deps, PHYSICIAN_1, '2026-02-19');

      expect(result.batches).toHaveLength(1);
      expect(result.batches[0].totalValue).toBe('85.00');

      // Verify fee was calculated (getHscDetail was called)
      expect(feeRefData.getHscDetail).toHaveBeenCalled();
    });

    it('transitions claims to SUBMITTED', async () => {
      const claimStateService: ClaimStateService = {
        transitionState: vi.fn().mockResolvedValue(true),
      };
      const deps = makeBatchCycleDeps({ claimStateService });

      seedClaimWithDetailForBatch(
        { claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'QUEUED', claimType: 'AHCIP' },
        { baNumber: '12345', submittedFee: '85.00' },
      );

      await assembleBatch(deps, PHYSICIAN_1, '2026-02-19');

      expect(claimStateService.transitionState).toHaveBeenCalledWith(
        CLAIM_1, PHYSICIAN_1, 'QUEUED', 'SUBMITTED', 'SYSTEM', 'SYSTEM',
      );
    });

    it('emits BATCH_ASSEMBLED notification', async () => {
      const notificationService: BatchNotificationService = {
        emit: vi.fn().mockResolvedValue(undefined),
      };
      const deps = makeBatchCycleDeps({ notificationService });

      seedClaimWithDetailForBatch(
        { claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'QUEUED', claimType: 'AHCIP' },
        { baNumber: '12345', submittedFee: '85.00' },
      );

      await assembleBatch(deps, PHYSICIAN_1, '2026-02-19');

      expect(notificationService.emit).toHaveBeenCalledWith(
        'BATCH_ASSEMBLED',
        expect.objectContaining({
          physicianId: PHYSICIAN_1,
          batchWeek: '2026-02-19',
          batches: expect.arrayContaining([
            expect.objectContaining({
              baNumber: '12345',
              claimCount: 1,
            }),
          ]),
        }),
      );
    });

    it('returns empty result when no queued claims', async () => {
      const deps = makeBatchCycleDeps();

      const result = await assembleBatch(deps, PHYSICIAN_1, '2026-02-19');

      expect(result.batches).toHaveLength(0);
      expect(result.removedClaims).toHaveLength(0);
    });

    it('respects AUTO_CLEAN submission mode (only clean claims)', async () => {
      const submissionPreferences: SubmissionPreferenceService = {
        getAutoSubmissionMode: vi.fn().mockResolvedValue('AUTO_CLEAN'),
      };
      const deps = makeBatchCycleDeps({ submissionPreferences });

      // Clean claim — should be included
      seedClaimWithDetailForBatch(
        { claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'QUEUED', claimType: 'AHCIP', isClean: true },
        { baNumber: '12345', submittedFee: '85.00' },
      );
      // Flagged claim — should NOT be included
      seedClaimWithDetailForBatch(
        { claimId: CLAIM_2, physicianId: PHYSICIAN_1, state: 'QUEUED', claimType: 'AHCIP', isClean: false },
        { baNumber: '12345', submittedFee: '120.00' },
      );

      const result = await assembleBatch(deps, PHYSICIAN_1, '2026-02-19');

      expect(result.batches).toHaveLength(1);
      expect(result.batches[0].claimCount).toBe(1);
    });

    it('skips batches in REQUIRE_APPROVAL mode', async () => {
      const submissionPreferences: SubmissionPreferenceService = {
        getAutoSubmissionMode: vi.fn().mockResolvedValue('REQUIRE_APPROVAL'),
      };
      const deps = makeBatchCycleDeps({ submissionPreferences });

      seedClaimWithDetailForBatch(
        { claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'QUEUED', claimType: 'AHCIP' },
        { baNumber: '12345', submittedFee: '85.00' },
      );

      const result = await assembleBatch(deps, PHYSICIAN_1, '2026-02-19');

      expect(result.batches).toHaveLength(0);
    });
  });

  // =========================================================================
  // generateHlinkFile
  // =========================================================================

  describe('generateHlinkFile', () => {
    it('creates correct header structure', async () => {
      const deps = makeBatchCycleDeps();

      // Seed batch in ASSEMBLING status
      const batchId = 'bat-gen-1111-1111-111111111111';
      seedBatch({
        ahcipBatchId: batchId,
        physicianId: PHYSICIAN_1,
        baNumber: '12345',
        batchWeek: '2026-02-19',
        status: 'ASSEMBLING',
        claimCount: 2,
      });

      // Seed two claims linked to this batch
      seedClaimWithDetailForBatch(
        { claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'QUEUED', claimType: 'AHCIP', submittedBatchId: batchId },
        { baNumber: '12345', submittedFee: '85.00' },
      );
      seedClaimWithDetailForBatch(
        { claimId: CLAIM_2, physicianId: PHYSICIAN_1, state: 'QUEUED', claimType: 'AHCIP', submittedBatchId: batchId },
        { baNumber: '12345', submittedFee: '120.00' },
      );

      const result = await generateHlinkFile(deps, batchId, PHYSICIAN_1);

      // Header format: H|submitter_prefix|batch_date|record_count|vendor_id
      expect(result.header).toMatch(/^H\|/);
      expect(result.header).toContain('MERITUM');
      expect(result.header).toContain('2026-02-19');
      expect(result.header).toContain('000002'); // 2 records, zero-padded
      expect(result.header).toContain('MERITUM_V1');
    });

    it('orders claims by DOS ascending', async () => {
      const deps = makeBatchCycleDeps();

      const batchId = 'bat-order-1111-1111-111111111111';
      seedBatch({
        ahcipBatchId: batchId,
        physicianId: PHYSICIAN_1,
        baNumber: '12345',
        batchWeek: '2026-02-19',
        status: 'ASSEMBLING',
        claimCount: 2,
      });

      // Claim with later DOS first in store
      seedClaimWithDetailForBatch(
        { claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'QUEUED', claimType: 'AHCIP', dateOfService: '2026-02-10', submittedBatchId: batchId },
        { baNumber: '12345', submittedFee: '120.00' },
      );
      seedClaimWithDetailForBatch(
        { claimId: CLAIM_2, physicianId: PHYSICIAN_1, state: 'QUEUED', claimType: 'AHCIP', dateOfService: '2026-02-01', submittedBatchId: batchId },
        { baNumber: '12345', submittedFee: '85.00' },
      );

      const result = await generateHlinkFile(deps, batchId, PHYSICIAN_1);

      // First record should be the earlier DOS (2026-02-01)
      expect(result.records).toHaveLength(2);
      expect(result.records[0]).toContain('2026-02-01');
      expect(result.records[1]).toContain('2026-02-10');
    });

    it('creates correct trailer with count and checksum', async () => {
      const deps = makeBatchCycleDeps();

      const batchId = 'bat-trail-1111-1111-111111111111';
      seedBatch({
        ahcipBatchId: batchId,
        physicianId: PHYSICIAN_1,
        baNumber: '12345',
        batchWeek: '2026-02-19',
        status: 'ASSEMBLING',
        claimCount: 1,
      });

      seedClaimWithDetailForBatch(
        { claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'QUEUED', claimType: 'AHCIP', submittedBatchId: batchId },
        { baNumber: '12345', submittedFee: '85.00' },
      );

      const result = await generateHlinkFile(deps, batchId, PHYSICIAN_1);

      // Trailer format: T|record_count|total_value|checksum
      expect(result.trailer).toMatch(/^T\|/);
      expect(result.trailer).toContain('000001'); // 1 record
      expect(result.trailer).toContain('85.00'); // total value
      // Checksum is a 16-char hex string
      const parts = result.trailer.split('|');
      expect(parts).toHaveLength(4);
      expect(parts[3]).toMatch(/^[a-f0-9]{16}$/);
    });

    it('stores encrypted file with hash', async () => {
      const fileEncryption: FileEncryptionService = {
        encryptAndStore: vi.fn().mockResolvedValue({
          filePath: '/encrypted/hlink_12345_2026-02-19.enc',
          fileHash: 'sha256hashvalue1234',
        }),
      };
      const deps = makeBatchCycleDeps({ fileEncryption });

      const batchId = 'bat-enc-1111-1111-111111111111';
      seedBatch({
        ahcipBatchId: batchId,
        physicianId: PHYSICIAN_1,
        baNumber: '12345',
        batchWeek: '2026-02-19',
        status: 'ASSEMBLING',
        claimCount: 1,
      });

      seedClaimWithDetailForBatch(
        { claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'QUEUED', claimType: 'AHCIP', submittedBatchId: batchId },
        { baNumber: '12345', submittedFee: '85.00' },
      );

      await generateHlinkFile(deps, batchId, PHYSICIAN_1);

      // Verify encrypt was called
      expect(fileEncryption.encryptAndStore).toHaveBeenCalledWith(
        expect.any(Buffer),
        expect.stringContaining('hlink_12345_2026-02-19'),
      );

      // Verify batch was updated to GENERATED with file info
      const updatedBatch = ahcipBatchStore.find((b) => b.ahcipBatchId === batchId);
      expect(updatedBatch!.status).toBe('GENERATED');
      expect(updatedBatch!.filePath).toBe('/encrypted/hlink_12345_2026-02-19.enc');
      expect(updatedBatch!.fileHash).toBe('sha256hashvalue1234');
    });

    it('throws for batch not in ASSEMBLING status', async () => {
      const deps = makeBatchCycleDeps();

      const batchId = 'bat-wrong-status';
      seedBatch({
        ahcipBatchId: batchId,
        physicianId: PHYSICIAN_1,
        status: 'SUBMITTED',
      });

      await expect(
        generateHlinkFile(deps, batchId, PHYSICIAN_1),
      ).rejects.toThrow('Cannot generate file for batch in SUBMITTED status');
    });
  });

  // =========================================================================
  // transmitBatch
  // =========================================================================

  describe('transmitBatch', () => {
    it('updates status to SUBMITTED on success', async () => {
      const hlinkTransmission: HlinkTransmissionService = {
        transmit: vi.fn().mockResolvedValue({ submissionReference: 'HLINK-REF-999' }),
      };
      const deps = makeBatchCycleDeps({ hlinkTransmission });

      const batchId = 'bat-tx-1111-1111-111111111111';
      seedBatch({
        ahcipBatchId: batchId,
        physicianId: PHYSICIAN_1,
        status: 'GENERATED',
        filePath: '/encrypted/file.enc',
        claimCount: 5,
        totalSubmittedValue: '425.00',
      });

      const result = await transmitBatch(deps, batchId, PHYSICIAN_1);

      expect(result.success).toBe(true);
      expect(result.submissionReference).toBe('HLINK-REF-999');

      const updatedBatch = ahcipBatchStore.find((b) => b.ahcipBatchId === batchId);
      expect(updatedBatch!.status).toBe('SUBMITTED');
      expect(updatedBatch!.submissionReference).toBe('HLINK-REF-999');
      expect(updatedBatch!.submittedAt).toBeDefined();
    });

    it('retries with exponential backoff on failure', async () => {
      const hlinkTransmission: HlinkTransmissionService = {
        transmit: vi.fn()
          .mockRejectedValueOnce(new Error('Connection timeout'))
          .mockRejectedValueOnce(new Error('Connection timeout'))
          .mockResolvedValueOnce({ submissionReference: 'HLINK-REF-RETRY' }),
      };
      const deps = makeBatchCycleDeps({ hlinkTransmission });

      const batchId = 'bat-retry-1111-1111-111111111111';
      seedBatch({
        ahcipBatchId: batchId,
        physicianId: PHYSICIAN_1,
        status: 'GENERATED',
        filePath: '/encrypted/file.enc',
        claimCount: 3,
        totalSubmittedValue: '255.00',
      });

      const result = await transmitBatch(deps, batchId, PHYSICIAN_1);

      expect(result.success).toBe(true);
      expect(result.submissionReference).toBe('HLINK-REF-RETRY');
      expect(hlinkTransmission.transmit).toHaveBeenCalledTimes(3);
    });

    it('sets ERROR after max retries', async () => {
      const hlinkTransmission: HlinkTransmissionService = {
        transmit: vi.fn().mockRejectedValue(new Error('Connection refused')),
      };
      const notificationService: BatchNotificationService = {
        emit: vi.fn().mockResolvedValue(undefined),
      };
      const deps = makeBatchCycleDeps({ hlinkTransmission, notificationService });

      const batchId = 'bat-fail-1111-1111-111111111111';
      seedBatch({
        ahcipBatchId: batchId,
        physicianId: PHYSICIAN_1,
        status: 'GENERATED',
        filePath: '/encrypted/file.enc',
        claimCount: 3,
        totalSubmittedValue: '255.00',
        baNumber: '12345',
        batchWeek: '2026-02-19',
      });

      const result = await transmitBatch(deps, batchId, PHYSICIAN_1);

      expect(result.success).toBe(false);
      expect(result.error).toBe('Connection refused');

      // Verify 5 attempts total (initial + 4 retries)
      expect(hlinkTransmission.transmit).toHaveBeenCalledTimes(5);

      // Verify batch set to ERROR
      const updatedBatch = ahcipBatchStore.find((b) => b.ahcipBatchId === batchId);
      expect(updatedBatch!.status).toBe('ERROR');

      // Verify failure notification emitted
      expect(notificationService.emit).toHaveBeenCalledWith(
        'BATCH_TRANSMISSION_FAILED',
        expect.objectContaining({
          physicianId: PHYSICIAN_1,
          batchId,
          error: 'Connection refused',
        }),
      );
    });

    it('throws for batch not in GENERATED or ERROR status', async () => {
      const deps = makeBatchCycleDeps();

      const batchId = 'bat-wrong-state';
      seedBatch({
        ahcipBatchId: batchId,
        physicianId: PHYSICIAN_1,
        status: 'ASSEMBLING',
      });

      await expect(
        transmitBatch(deps, batchId, PHYSICIAN_1),
      ).rejects.toThrow('Cannot transmit batch in ASSEMBLING status');
    });
  });

  // =========================================================================
  // previewNextBatch
  // =========================================================================

  describe('previewNextBatch', () => {
    it('returns preview without assembly', async () => {
      const deps = makeBatchCycleDeps();

      seedClaimWithDetailForBatch(
        { claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'QUEUED', claimType: 'AHCIP' },
        { baNumber: '12345', submittedFee: '85.00' },
      );
      seedClaimWithDetailForBatch(
        { claimId: CLAIM_2, physicianId: PHYSICIAN_1, state: 'QUEUED', claimType: 'AHCIP' },
        { baNumber: '12345', submittedFee: '120.00' },
      );
      seedClaimWithDetailForBatch(
        { claimId: CLAIM_3, physicianId: PHYSICIAN_1, state: 'QUEUED', claimType: 'AHCIP' },
        { baNumber: '67890', submittedFee: '50.00' },
      );

      const result = await previewNextBatch(deps, PHYSICIAN_1);

      expect(result.groups).toHaveLength(2);
      expect(result.totalClaims).toBe(3);
      expect(result.totalValue).toBe('255.00');

      const ba12345 = result.groups.find((g) => g.baNumber === '12345');
      expect(ba12345).toBeDefined();
      expect(ba12345!.claimCount).toBe(2);

      const ba67890 = result.groups.find((g) => g.baNumber === '67890');
      expect(ba67890).toBeDefined();
      expect(ba67890!.claimCount).toBe(1);

      // Verify no batches were created (preview only)
      expect(ahcipBatchStore).toHaveLength(0);

      // Verify batch week is returned
      expect(result.batchWeek).toBeDefined();
      expect(result.batchWeek).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    });

    it('returns empty preview when no queued claims', async () => {
      const deps = makeBatchCycleDeps();

      const result = await previewNextBatch(deps, PHYSICIAN_1);

      expect(result.groups).toHaveLength(0);
      expect(result.totalClaims).toBe(0);
      expect(result.totalValue).toBe('0.00');
    });
  });

  // =========================================================================
  // retryFailedBatch
  // =========================================================================

  describe('retryFailedBatch', () => {
    it('retransmits ERROR status batch', async () => {
      const hlinkTransmission: HlinkTransmissionService = {
        transmit: vi.fn().mockResolvedValue({ submissionReference: 'HLINK-RETRY-001' }),
      };
      const deps = makeBatchCycleDeps({ hlinkTransmission });

      const batchId = 'bat-retry-err-1111-111111111111';
      seedBatch({
        ahcipBatchId: batchId,
        physicianId: PHYSICIAN_1,
        status: 'ERROR',
        filePath: '/encrypted/file.enc',
        claimCount: 3,
        totalSubmittedValue: '255.00',
      });

      const result = await retryFailedBatch(deps, batchId, PHYSICIAN_1);

      expect(result.success).toBe(true);
      expect(result.submissionReference).toBe('HLINK-RETRY-001');

      // Verify batch transitions: ERROR → GENERATED → SUBMITTED
      const updatedBatch = ahcipBatchStore.find((b) => b.ahcipBatchId === batchId);
      expect(updatedBatch!.status).toBe('SUBMITTED');
    });

    it('throws for batch not in ERROR status', async () => {
      const deps = makeBatchCycleDeps();

      const batchId = 'bat-not-error';
      seedBatch({
        ahcipBatchId: batchId,
        physicianId: PHYSICIAN_1,
        status: 'SUBMITTED',
      });

      await expect(
        retryFailedBatch(deps, batchId, PHYSICIAN_1),
      ).rejects.toThrow('Can only retry batches in ERROR status');
    });

    it('throws for batch not found', async () => {
      const deps = makeBatchCycleDeps();

      await expect(
        retryFailedBatch(deps, 'non-existent', PHYSICIAN_1),
      ).rejects.toThrow('Batch not found');
    });
  });

  // =========================================================================
  // H-Link Format Helpers (unit)
  // =========================================================================

  describe('H-Link format helpers', () => {
    it('formatHlinkHeader creates correct format', () => {
      const header = formatHlinkHeader('MERITUM', '2026-02-19', 5, 'MERITUM_V1');
      expect(header).toBe('H|MERITUM|2026-02-19|000005|MERITUM_V1');
    });

    it('formatHlinkClaimRecord creates correct format', () => {
      const record = formatHlinkClaimRecord(
        { dateOfService: '2026-02-01' },
        {
          baNumber: '12345',
          healthServiceCode: '03.04A',
          modifier1: 'AFHR',
          modifier2: null,
          modifier3: null,
          diagnosticCode: '780',
          facilityNumber: null,
          referralPractitioner: null,
          calls: 1,
          timeSpent: null,
          submittedFee: '85.00',
        },
      );
      expect(record).toBe('C|12345|03.04A|2026-02-01|AFHR|||780|||1||85.00');
    });

    it('formatHlinkTrailer creates correct format', () => {
      const trailer = formatHlinkTrailer(10, '850.00', 'abcdef1234567890');
      expect(trailer).toBe('T|000010|850.00|abcdef1234567890');
    });

    it('computeChecksum returns 16-char hex string', () => {
      const header = 'H|MERITUM|2026-02-19|000001|MERITUM_V1';
      const records = ['C|12345|03.04A|2026-02-01|||||||||85.00'];
      const checksum = computeChecksum(header, records);
      expect(checksum).toMatch(/^[a-f0-9]{16}$/);
    });

    it('computeChecksum is deterministic', () => {
      const header = 'H|MERITUM|2026-02-19|000001|MERITUM_V1';
      const records = ['C|12345|03.04A|2026-02-01|||||||||85.00'];
      const checksum1 = computeChecksum(header, records);
      const checksum2 = computeChecksum(header, records);
      expect(checksum1).toBe(checksum2);
    });
  });
});

// ===========================================================================
// AHCIP Assessment Ingestion Tests
// ===========================================================================

function makeAssessmentIngestionDeps(overrides?: Partial<AssessmentIngestionDeps>): AssessmentIngestionDeps {
  const mockDb = makeMockDb();
  const repo = createAhcipRepository(mockDb);

  const defaultClaimStateService: ClaimStateService = {
    transitionState: vi.fn().mockResolvedValue(true),
  };

  const defaultNotificationService: BatchNotificationService = {
    emit: vi.fn().mockResolvedValue(undefined),
  };

  const defaultHlinkRetrieval: HlinkAssessmentRetrievalService = {
    retrieveAssessmentFile: vi.fn().mockResolvedValue(Buffer.from('')),
  };

  const defaultExplanatoryCodeService: ExplanatoryCodeService = {
    resolveExplanatoryCode: vi.fn().mockResolvedValue(null),
  };

  const defaultFileEncryption: FileEncryptionService = {
    encryptAndStore: vi.fn().mockResolvedValue({
      filePath: '/encrypted/assessment.enc',
      fileHash: 'assesshash123',
    }),
  };

  return {
    repo: overrides?.repo ?? repo,
    claimStateService: overrides?.claimStateService ?? defaultClaimStateService,
    notificationService: overrides?.notificationService ?? defaultNotificationService,
    hlinkRetrieval: overrides?.hlinkRetrieval ?? defaultHlinkRetrieval,
    explanatoryCodeService: overrides?.explanatoryCodeService ?? defaultExplanatoryCodeService,
    fileEncryption: overrides?.fileEncryption ?? defaultFileEncryption,
  };
}

function buildAssessmentFileContent(records: Array<{
  claimReference: string;
  status: string;
  assessedFee: string;
  explanatoryCodes?: string[];
}>): Buffer {
  const lines: string[] = [];
  lines.push(`H|HLINK-REF-001|2026-02-19|${String(records.length).padStart(6, '0')}`);
  for (const rec of records) {
    const codes = rec.explanatoryCodes?.join(';') ?? '';
    lines.push(`R|${rec.claimReference}|${rec.status}|${rec.assessedFee}|${codes}`);
  }
  const totalValue = records.reduce((sum, r) => sum + parseFloat(r.assessedFee || '0'), 0).toFixed(2);
  lines.push(`T|${String(records.length).padStart(6, '0')}|${totalValue}`);
  return Buffer.from(lines.join('\n') + '\n', 'utf-8');
}

describe('AHCIP Assessment Ingestion', () => {
  beforeEach(() => {
    ahcipDetailStore = [];
    ahcipBatchStore = [];
    claimStore = [];
    patientStore = [];
  });

  // =========================================================================
  // parseAssessmentFile
  // =========================================================================

  describe('parseAssessmentFile', () => {
    it('parses assessment file correctly', () => {
      const file = buildAssessmentFileContent([
        { claimReference: CLAIM_1, status: 'ACCEPTED', assessedFee: '85.00' },
        { claimReference: CLAIM_2, status: 'REJECTED', assessedFee: '0.00', explanatoryCodes: ['E01', 'E02'] },
      ]);

      const parsed = parseAssessmentFile(file);

      expect(parsed.submissionReference).toBe('HLINK-REF-001');
      expect(parsed.batchDate).toBe('2026-02-19');
      expect(parsed.recordCount).toBe(2);
      expect(parsed.records).toHaveLength(2);
      expect(parsed.records[0]).toEqual(expect.objectContaining({
        claimReference: CLAIM_1,
        status: 'ACCEPTED',
        assessedFee: '85.00',
        explanatoryCodes: [],
      }));
      expect(parsed.records[1]).toEqual(expect.objectContaining({
        claimReference: CLAIM_2,
        status: 'REJECTED',
        assessedFee: '0.00',
        explanatoryCodes: ['E01', 'E02'],
      }));
    });

    it('throws on insufficient lines', () => {
      const file = Buffer.from('H|REF|2026-02-19|0\n', 'utf-8');
      // Header + trailer at minimum should be 2 lines, but no content fails gracefully
      const parsed = parseAssessmentFile(file);
      expect(parsed.records).toHaveLength(0);
    });

    it('throws on missing header', () => {
      const file = Buffer.from('X|bad\nR|claim|ACCEPTED|85.00|\n', 'utf-8');
      expect(() => parseAssessmentFile(file)).toThrow('Invalid assessment file: missing header');
    });
  });

  // =========================================================================
  // ingestAssessmentFile
  // =========================================================================

  describe('ingestAssessmentFile', () => {
    it('parses assessment file and processes records correctly', async () => {
      const assessmentFile = buildAssessmentFileContent([
        { claimReference: CLAIM_1, status: 'ACCEPTED', assessedFee: '85.00' },
      ]);

      const hlinkRetrieval: HlinkAssessmentRetrievalService = {
        retrieveAssessmentFile: vi.fn().mockResolvedValue(assessmentFile),
      };

      const deps = makeAssessmentIngestionDeps({ hlinkRetrieval });

      // Seed a submitted batch
      const batchId = BATCH_1;
      seedBatch({
        ahcipBatchId: batchId,
        physicianId: PHYSICIAN_1,
        status: 'SUBMITTED',
        submissionReference: 'HLINK-REF-001',
        baNumber: '12345',
      });

      // Seed a claim linked to the batch
      seedClaim({
        claimId: CLAIM_1,
        physicianId: PHYSICIAN_1,
        state: 'SUBMITTED',
        claimType: 'AHCIP',
        submittedBatchId: batchId,
      });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_1, { baNumber: '12345', submittedFee: '85.00' }),
      });

      const result = await ingestAssessmentFile(deps, batchId, PHYSICIAN_1);

      expect(result.totalRecords).toBe(1);
      expect(result.accepted).toBe(1);
      expect(result.rejected).toBe(0);
      expect(result.adjusted).toBe(0);
      expect(result.unmatched).toBe(0);
      expect(result.results).toHaveLength(1);
      expect(result.results[0].status).toBe('ACCEPTED');

      // Verify batch status updated to RESPONSE_RECEIVED
      const updatedBatch = ahcipBatchStore.find((b) => b.ahcipBatchId === batchId);
      expect(updatedBatch!.status).toBe('RESPONSE_RECEIVED');
    });

    it('handles unmatched records gracefully', async () => {
      const assessmentFile = buildAssessmentFileContent([
        { claimReference: CLAIM_1, status: 'ACCEPTED', assessedFee: '85.00' },
        { claimReference: 'non-existent-claim', status: 'REJECTED', assessedFee: '0.00', explanatoryCodes: ['E01'] },
      ]);

      const hlinkRetrieval: HlinkAssessmentRetrievalService = {
        retrieveAssessmentFile: vi.fn().mockResolvedValue(assessmentFile),
      };

      const deps = makeAssessmentIngestionDeps({ hlinkRetrieval });

      seedBatch({
        ahcipBatchId: BATCH_1,
        physicianId: PHYSICIAN_1,
        status: 'SUBMITTED',
        submissionReference: 'HLINK-REF-001',
        baNumber: '12345',
      });

      seedClaim({
        claimId: CLAIM_1,
        physicianId: PHYSICIAN_1,
        state: 'SUBMITTED',
        claimType: 'AHCIP',
        submittedBatchId: BATCH_1,
      });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_1, { baNumber: '12345', submittedFee: '85.00' }),
      });

      const result = await ingestAssessmentFile(deps, BATCH_1, PHYSICIAN_1);

      expect(result.accepted).toBe(1);
      expect(result.unmatched).toBe(1);
      expect(result.unmatchedRecords).toHaveLength(1);
      expect(result.unmatchedRecords[0].claimReference).toBe('non-existent-claim');
    });

    it('handles mixed results (accepted + rejected + adjusted)', async () => {
      const assessmentFile = buildAssessmentFileContent([
        { claimReference: CLAIM_1, status: 'ACCEPTED', assessedFee: '85.00' },
        { claimReference: CLAIM_2, status: 'REJECTED', assessedFee: '0.00', explanatoryCodes: ['E01'] },
        { claimReference: CLAIM_3, status: 'ADJUSTED', assessedFee: '70.00', explanatoryCodes: ['A01'] },
      ]);

      const hlinkRetrieval: HlinkAssessmentRetrievalService = {
        retrieveAssessmentFile: vi.fn().mockResolvedValue(assessmentFile),
      };

      const deps = makeAssessmentIngestionDeps({ hlinkRetrieval });

      seedBatch({
        ahcipBatchId: BATCH_1,
        physicianId: PHYSICIAN_1,
        status: 'SUBMITTED',
        submissionReference: 'HLINK-REF-001',
        baNumber: '12345',
      });

      // Seed three claims
      for (const claimId of [CLAIM_1, CLAIM_2, CLAIM_3]) {
        seedClaim({
          claimId,
          physicianId: PHYSICIAN_1,
          state: 'SUBMITTED',
          claimType: 'AHCIP',
          submittedBatchId: BATCH_1,
        });
        ahcipDetailStore.push({
          ahcipDetailId: crypto.randomUUID(),
          ...makeAhcipDetailData(claimId, { baNumber: '12345', submittedFee: '85.00' }),
        });
      }

      const result = await ingestAssessmentFile(deps, BATCH_1, PHYSICIAN_1);

      expect(result.totalRecords).toBe(3);
      expect(result.accepted).toBe(1);
      expect(result.rejected).toBe(1);
      expect(result.adjusted).toBe(1);
      expect(result.unmatched).toBe(0);
      expect(result.results).toHaveLength(3);
    });

    it('throws for batch not in SUBMITTED status', async () => {
      const deps = makeAssessmentIngestionDeps();

      seedBatch({
        ahcipBatchId: BATCH_1,
        physicianId: PHYSICIAN_1,
        status: 'ASSEMBLING',
      });

      await expect(
        ingestAssessmentFile(deps, BATCH_1, PHYSICIAN_1),
      ).rejects.toThrow('Cannot ingest assessment for batch in ASSEMBLING status');
    });

    it('throws for batch not found', async () => {
      const deps = makeAssessmentIngestionDeps();

      await expect(
        ingestAssessmentFile(deps, 'non-existent', PHYSICIAN_1),
      ).rejects.toThrow('Batch not found');
    });
  });

  // =========================================================================
  // processAssessmentRecord
  // =========================================================================

  describe('processAssessmentRecord', () => {
    it('transitions accepted claim to ASSESSED', async () => {
      const claimStateService: ClaimStateService = {
        transitionState: vi.fn().mockResolvedValue(true),
      };
      const deps = makeAssessmentIngestionDeps({ claimStateService });

      const record: AssessmentRecord = {
        submissionReference: 'HLINK-REF-001',
        claimReference: CLAIM_1,
        status: 'ACCEPTED',
        assessedFee: '85.00',
        explanatoryCodes: [],
      };

      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'SUBMITTED' });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_1, { submittedFee: '85.00' }),
      });

      const claimData = {
        claim: claimStore.find((c) => c.claimId === CLAIM_1),
        detail: ahcipDetailStore.find((d) => d.claimId === CLAIM_1),
      };

      const result = await processAssessmentRecord(deps, record, claimData, PHYSICIAN_1);

      expect(result.status).toBe('ACCEPTED');
      expect(claimStateService.transitionState).toHaveBeenCalledWith(
        CLAIM_1, PHYSICIAN_1, 'SUBMITTED', 'ASSESSED', 'SYSTEM', 'SYSTEM',
      );
    });

    it('stores assessed_fee on accepted claim', async () => {
      const deps = makeAssessmentIngestionDeps();

      const record: AssessmentRecord = {
        submissionReference: 'HLINK-REF-001',
        claimReference: CLAIM_1,
        status: 'ACCEPTED',
        assessedFee: '85.00',
        explanatoryCodes: [],
      };

      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'SUBMITTED' });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_1, { submittedFee: '85.00' }),
      });

      const claimData = {
        claim: claimStore.find((c) => c.claimId === CLAIM_1),
        detail: ahcipDetailStore.find((d) => d.claimId === CLAIM_1),
      };

      const result = await processAssessmentRecord(deps, record, claimData, PHYSICIAN_1);

      expect(result.assessedFee).toBe('85.00');
      expect(result.isCleanAcceptance).toBe(true);

      // Verify fee was persisted
      const updatedDetail = ahcipDetailStore.find((d) => d.claimId === CLAIM_1);
      expect(updatedDetail!.assessedFee).toBe('85.00');
    });

    it('transitions rejected claim to REJECTED', async () => {
      const claimStateService: ClaimStateService = {
        transitionState: vi.fn().mockResolvedValue(true),
      };
      const notificationService: BatchNotificationService = {
        emit: vi.fn().mockResolvedValue(undefined),
      };
      const deps = makeAssessmentIngestionDeps({ claimStateService, notificationService });

      const record: AssessmentRecord = {
        submissionReference: 'HLINK-REF-001',
        claimReference: CLAIM_1,
        status: 'REJECTED',
        assessedFee: '0.00',
        explanatoryCodes: ['E01'],
      };

      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'SUBMITTED' });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_1, { submittedFee: '85.00' }),
      });

      const claimData = {
        claim: claimStore.find((c) => c.claimId === CLAIM_1),
        detail: ahcipDetailStore.find((d) => d.claimId === CLAIM_1),
      };

      const result = await processAssessmentRecord(deps, record, claimData, PHYSICIAN_1);

      expect(result.status).toBe('REJECTED');
      expect(claimStateService.transitionState).toHaveBeenCalledWith(
        CLAIM_1, PHYSICIAN_1, 'SUBMITTED', 'REJECTED', 'SYSTEM', 'SYSTEM',
      );

      // Verify CLAIM_REJECTED notification emitted
      expect(notificationService.emit).toHaveBeenCalledWith(
        'CLAIM_REJECTED',
        expect.objectContaining({ claimId: CLAIM_1, physicianId: PHYSICIAN_1 }),
      );
    });

    it('stores explanatory codes on rejected claim', async () => {
      const explanatoryCodeService: ExplanatoryCodeService = {
        resolveExplanatoryCode: vi.fn().mockImplementation(async (code: string) => ({
          code,
          description: `Description for ${code}`,
          category: 'MISSING_REFERRAL',
          correctiveGuidance: 'Add referring practitioner',
        })),
      };
      const deps = makeAssessmentIngestionDeps({ explanatoryCodeService });

      const record: AssessmentRecord = {
        submissionReference: 'HLINK-REF-001',
        claimReference: CLAIM_1,
        status: 'REJECTED',
        assessedFee: '0.00',
        explanatoryCodes: ['E01', 'E02'],
      };

      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'SUBMITTED' });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_1, { submittedFee: '85.00' }),
      });

      const claimData = {
        claim: claimStore.find((c) => c.claimId === CLAIM_1),
        detail: ahcipDetailStore.find((d) => d.claimId === CLAIM_1),
      };

      const result = await processAssessmentRecord(deps, record, claimData, PHYSICIAN_1);

      expect(result.explanatoryCodes).toHaveLength(2);
      expect(result.explanatoryCodes[0].code).toBe('E01');
      expect(result.explanatoryCodes[1].code).toBe('E02');

      // Verify codes were persisted
      const updatedDetail = ahcipDetailStore.find((d) => d.claimId === CLAIM_1);
      expect(updatedDetail!.assessmentExplanatoryCodes).toHaveLength(2);
    });

    it('handles adjusted claim (different fee)', async () => {
      const claimStateService: ClaimStateService = {
        transitionState: vi.fn().mockResolvedValue(true),
      };
      const notificationService: BatchNotificationService = {
        emit: vi.fn().mockResolvedValue(undefined),
      };
      const deps = makeAssessmentIngestionDeps({ claimStateService, notificationService });

      const record: AssessmentRecord = {
        submissionReference: 'HLINK-REF-001',
        claimReference: CLAIM_1,
        status: 'ADJUSTED',
        assessedFee: '70.00',
        explanatoryCodes: ['A01'],
      };

      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'SUBMITTED' });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_1, { submittedFee: '85.00' }),
      });

      const claimData = {
        claim: claimStore.find((c) => c.claimId === CLAIM_1),
        detail: ahcipDetailStore.find((d) => d.claimId === CLAIM_1),
      };

      const result = await processAssessmentRecord(deps, record, claimData, PHYSICIAN_1);

      expect(result.status).toBe('ADJUSTED');
      expect(result.assessedFee).toBe('70.00');
      expect(result.submittedFee).toBe('85.00');
      expect(result.isCleanAcceptance).toBe(false);

      // Adjusted claims transition to ASSESSED (not ADJUSTED)
      expect(claimStateService.transitionState).toHaveBeenCalledWith(
        CLAIM_1, PHYSICIAN_1, 'SUBMITTED', 'ASSESSED', 'SYSTEM', 'SYSTEM',
      );

      // Verify adjusted notification emitted
      expect(notificationService.emit).toHaveBeenCalledWith(
        'CLAIM_ASSESSED',
        expect.objectContaining({
          claimId: CLAIM_1,
          isAdjusted: true,
          assessedFee: '70.00',
          submittedFee: '85.00',
        }),
      );
    });

    it('resolves explanatory codes via Reference Data', async () => {
      const explanatoryCodeService: ExplanatoryCodeService = {
        resolveExplanatoryCode: vi.fn()
          .mockResolvedValueOnce({
            code: 'E01',
            description: 'Missing referral practitioner',
            category: 'MISSING_REFERRAL',
            correctiveGuidance: 'Add the referring practitioner billing number.',
          })
          .mockResolvedValueOnce(null), // Unknown code
      };
      const deps = makeAssessmentIngestionDeps({ explanatoryCodeService });

      const record: AssessmentRecord = {
        submissionReference: 'HLINK-REF-001',
        claimReference: CLAIM_1,
        status: 'REJECTED',
        assessedFee: '0.00',
        explanatoryCodes: ['E01', 'UNKNOWN_CODE'],
      };

      seedClaim({ claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'SUBMITTED' });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_1, { submittedFee: '85.00' }),
      });

      const claimData = {
        claim: claimStore.find((c) => c.claimId === CLAIM_1),
        detail: ahcipDetailStore.find((d) => d.claimId === CLAIM_1),
      };

      const result = await processAssessmentRecord(deps, record, claimData, PHYSICIAN_1);

      // First code resolved normally
      expect(result.explanatoryCodes[0].description).toBe('Missing referral practitioner');
      expect(result.explanatoryCodes[0].category).toBe('MISSING_REFERRAL');

      // Second code had no resolution — falls back to unknown
      expect(result.explanatoryCodes[1].description).toContain('Unknown explanatory code');
      expect(result.explanatoryCodes[1].category).toBe('UNKNOWN');

      // Corrective action generated for MISSING_REFERRAL
      expect(result.correctiveActions).toHaveLength(1);
      expect(result.correctiveActions[0].actionType).toBe('ADD_REFERRAL');
    });
  });

  // =========================================================================
  // reconcilePayment
  // =========================================================================

  describe('reconcilePayment', () => {
    it('transitions ASSESSED claims to PAID', async () => {
      const claimStateService: ClaimStateService = {
        transitionState: vi.fn().mockResolvedValue(true),
      };
      const notificationService: BatchNotificationService = {
        emit: vi.fn().mockResolvedValue(undefined),
      };
      const deps = makeAssessmentIngestionDeps({ claimStateService, notificationService });

      seedBatch({
        ahcipBatchId: BATCH_1,
        physicianId: PHYSICIAN_1,
        status: 'RESPONSE_RECEIVED',
        baNumber: '12345',
      });

      // Seed two ASSESSED claims and one REJECTED (should be skipped)
      seedClaim({
        claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'ASSESSED',
        claimType: 'AHCIP', submittedBatchId: BATCH_1,
      });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_1, { baNumber: '12345', assessedFee: '85.00' }),
      });

      seedClaim({
        claimId: CLAIM_2, physicianId: PHYSICIAN_1, state: 'ASSESSED',
        claimType: 'AHCIP', submittedBatchId: BATCH_1,
      });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_2, { baNumber: '12345', assessedFee: '120.00' }),
      });

      seedClaim({
        claimId: CLAIM_3, physicianId: PHYSICIAN_1, state: 'REJECTED',
        claimType: 'AHCIP', submittedBatchId: BATCH_1,
      });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_3, { baNumber: '12345' }),
      });

      const result = await reconcilePayment(deps, BATCH_1, PHYSICIAN_1);

      expect(result.reconciledCount).toBe(2);

      // Verify ASSESSED → PAID transitions
      expect(claimStateService.transitionState).toHaveBeenCalledWith(
        CLAIM_1, PHYSICIAN_1, 'ASSESSED', 'PAID', 'SYSTEM', 'SYSTEM',
      );
      expect(claimStateService.transitionState).toHaveBeenCalledWith(
        CLAIM_2, PHYSICIAN_1, 'ASSESSED', 'PAID', 'SYSTEM', 'SYSTEM',
      );

      // Verify REJECTED claim was not transitioned
      expect(claimStateService.transitionState).not.toHaveBeenCalledWith(
        CLAIM_3, PHYSICIAN_1, expect.anything(), expect.anything(), expect.anything(), expect.anything(),
      );

      // Verify CLAIM_PAID notifications emitted
      expect(notificationService.emit).toHaveBeenCalledWith(
        'CLAIM_PAID',
        expect.objectContaining({ claimId: CLAIM_1, physicianId: PHYSICIAN_1 }),
      );
      expect(notificationService.emit).toHaveBeenCalledWith(
        'CLAIM_PAID',
        expect.objectContaining({ claimId: CLAIM_2, physicianId: PHYSICIAN_1 }),
      );
    });

    it('updates batch status to RECONCILED', async () => {
      const deps = makeAssessmentIngestionDeps();

      seedBatch({
        ahcipBatchId: BATCH_1,
        physicianId: PHYSICIAN_1,
        status: 'RESPONSE_RECEIVED',
        baNumber: '12345',
      });

      await reconcilePayment(deps, BATCH_1, PHYSICIAN_1);

      const updatedBatch = ahcipBatchStore.find((b) => b.ahcipBatchId === BATCH_1);
      expect(updatedBatch!.status).toBe('RECONCILED');
    });

    it('throws for batch not in RESPONSE_RECEIVED status', async () => {
      const deps = makeAssessmentIngestionDeps();

      seedBatch({
        ahcipBatchId: BATCH_1,
        physicianId: PHYSICIAN_1,
        status: 'SUBMITTED',
      });

      await expect(
        reconcilePayment(deps, BATCH_1, PHYSICIAN_1),
      ).rejects.toThrow('Cannot reconcile batch in SUBMITTED status');
    });

    it('throws for batch not found', async () => {
      const deps = makeAssessmentIngestionDeps();

      await expect(
        reconcilePayment(deps, 'non-existent', PHYSICIAN_1),
      ).rejects.toThrow('Batch not found');
    });
  });

  // =========================================================================
  // getAssessmentResults
  // =========================================================================

  describe('getAssessmentResults', () => {
    it('returns per-claim results for physician', async () => {
      const deps = makeAssessmentIngestionDeps();

      seedBatch({
        ahcipBatchId: BATCH_1,
        physicianId: PHYSICIAN_1,
        status: 'RESPONSE_RECEIVED',
        baNumber: '12345',
        submissionReference: 'HLINK-REF-001',
      });

      // Accepted claim
      seedClaim({
        claimId: CLAIM_1, physicianId: PHYSICIAN_1, state: 'ASSESSED',
        claimType: 'AHCIP', submittedBatchId: BATCH_1, dateOfService: '2026-02-01',
      });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_1, {
          baNumber: '12345',
          submittedFee: '85.00',
          assessedFee: '85.00',
          assessmentExplanatoryCodes: [],
        }),
      });

      // Rejected claim
      seedClaim({
        claimId: CLAIM_2, physicianId: PHYSICIAN_1, state: 'REJECTED',
        claimType: 'AHCIP', submittedBatchId: BATCH_1, dateOfService: '2026-02-02',
      });
      ahcipDetailStore.push({
        ahcipDetailId: crypto.randomUUID(),
        ...makeAhcipDetailData(CLAIM_2, {
          baNumber: '12345',
          submittedFee: '120.00',
          assessedFee: '0.00',
          assessmentExplanatoryCodes: [
            { code: 'E01', description: 'Missing referral', category: 'MISSING_REFERRAL', correctiveGuidance: 'Add referral' },
          ],
        }),
      });

      const result = await getAssessmentResults(deps, BATCH_1, PHYSICIAN_1);

      expect(result.batchId).toBe(BATCH_1);
      expect(result.batchStatus).toBe('RESPONSE_RECEIVED');
      expect(result.submissionReference).toBe('HLINK-REF-001');
      expect(result.totalClaims).toBe(2);
      expect(result.accepted).toBe(1);
      expect(result.rejected).toBe(1);
      expect(result.claims).toHaveLength(2);

      const acceptedClaim = result.claims.find((c) => c.claimId === CLAIM_1);
      expect(acceptedClaim!.assessedFee).toBe('85.00');
      expect(acceptedClaim!.state).toBe('ASSESSED');

      const rejectedClaim = result.claims.find((c) => c.claimId === CLAIM_2);
      expect(rejectedClaim!.state).toBe('REJECTED');
      expect(rejectedClaim!.explanatoryCodes).toHaveLength(1);
    });

    it('throws for batch not found', async () => {
      const deps = makeAssessmentIngestionDeps();

      await expect(
        getAssessmentResults(deps, 'non-existent', PHYSICIAN_1),
      ).rejects.toThrow('Batch not found');
    });
  });

  // =========================================================================
  // listBatchesAwaitingResponse
  // =========================================================================

  describe('listBatchesAwaitingResponse', () => {
    it('returns only SUBMITTED batches', async () => {
      const deps = makeAssessmentIngestionDeps();

      // SUBMITTED batch (should be returned)
      seedBatch({
        ahcipBatchId: BATCH_1,
        physicianId: PHYSICIAN_1,
        status: 'SUBMITTED',
        baNumber: '12345',
        batchWeek: '2026-02-19',
        claimCount: 5,
        totalSubmittedValue: '425.00',
        submittedAt: new Date('2026-02-19T12:00:00Z'),
        submissionReference: 'HLINK-REF-001',
      });

      // RESPONSE_RECEIVED batch (should NOT be returned)
      seedBatch({
        ahcipBatchId: BATCH_2,
        physicianId: PHYSICIAN_1,
        status: 'RESPONSE_RECEIVED',
        baNumber: '67890',
        batchWeek: '2026-02-12',
      });

      const result = await listBatchesAwaitingResponse(deps, PHYSICIAN_1);

      expect(result).toHaveLength(1);
      expect(result[0].batchId).toBe(BATCH_1);
      expect(result[0].baNumber).toBe('12345');
      expect(result[0].batchWeek).toBe('2026-02-19');
      expect(result[0].claimCount).toBe(5);
      expect(result[0].totalSubmittedValue).toBe('425.00');
      expect(result[0].submissionReference).toBe('HLINK-REF-001');
    });

    it('returns empty array when no SUBMITTED batches exist', async () => {
      const deps = makeAssessmentIngestionDeps();

      seedBatch({
        ahcipBatchId: BATCH_1,
        physicianId: PHYSICIAN_1,
        status: 'RECONCILED',
      });

      const result = await listBatchesAwaitingResponse(deps, PHYSICIAN_1);
      expect(result).toHaveLength(0);
    });

    it('does not return batches for other physicians', async () => {
      const deps = makeAssessmentIngestionDeps();

      seedBatch({
        ahcipBatchId: BATCH_1,
        physicianId: PHYSICIAN_2,
        status: 'SUBMITTED',
      });

      const result = await listBatchesAwaitingResponse(deps, PHYSICIAN_1);
      expect(result).toHaveLength(0);
    });
  });
});
