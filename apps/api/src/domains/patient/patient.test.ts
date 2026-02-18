import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createPatientRepository } from './patient.repository.js';
import {
  createPatient,
  getPatient,
  updatePatient,
  deactivatePatient,
  reactivatePatient,
  searchPatients,
  getRecentPatients,
  initiateImport,
  getImportPreview,
  updateImportMapping,
  commitImport,
  getImportStatus,
  getMergePreview,
  executeMerge,
  getMergeHistory,
  requestExport,
  getExportStatus,
  getPatientClaimContext,
  validatePhnService,
  _parsedRowsCache,
  _exportStore,
  type PatientServiceDeps,
  type PatientSearchInput,
} from './patient.service.js';

// ---------------------------------------------------------------------------
// In-memory stores
// ---------------------------------------------------------------------------

let patientStore: Record<string, any>[];
let importBatchStore: Record<string, any>[];
let mergeHistoryStore: Record<string, any>[];
let claimsStore: Record<string, any>[];

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
            // Column reference — sort ascending by column name
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

  function getStoreForTable(table: any): Record<string, any>[] {
    if (table && table.__table === 'patient_import_batches') {
      return importBatchStore;
    }
    if (table && table.__table === 'patient_merge_history') {
      return mergeHistoryStore;
    }
    return patientStore;
  }

  function insertPatientRow(values: any): any {
    // Enforce partial unique: (provider_id, phn) WHERE phn IS NOT NULL
    if (values.phn != null) {
      const duplicate = patientStore.find(
        (p) => p.providerId === values.providerId && p.phn === values.phn,
      );
      if (duplicate) {
        const err: any = new Error(
          'duplicate key value violates unique constraint "patients_provider_phn_unique_idx"',
        );
        err.code = '23505';
        throw err;
      }
    }

    const newPatient = {
      patientId: values.patientId ?? crypto.randomUUID(),
      providerId: values.providerId,
      phn: values.phn ?? null,
      phnProvince: values.phnProvince ?? 'AB',
      firstName: values.firstName,
      middleName: values.middleName ?? null,
      lastName: values.lastName,
      dateOfBirth: values.dateOfBirth,
      gender: values.gender,
      phone: values.phone ?? null,
      email: values.email ?? null,
      addressLine1: values.addressLine1 ?? null,
      addressLine2: values.addressLine2 ?? null,
      city: values.city ?? null,
      province: values.province ?? null,
      postalCode: values.postalCode ?? null,
      notes: values.notes ?? null,
      isActive: values.isActive ?? true,
      lastVisitDate: values.lastVisitDate ?? null,
      createdAt: values.createdAt ?? new Date(),
      updatedAt: values.updatedAt ?? new Date(),
      createdBy: values.createdBy,
    };
    patientStore.push(newPatient);
    return newPatient;
  }

  function insertImportBatchRow(values: any): any {
    const newBatch = {
      importId: values.importId ?? crypto.randomUUID(),
      physicianId: values.physicianId,
      fileName: values.fileName,
      fileHash: values.fileHash,
      totalRows: values.totalRows ?? 0,
      createdCount: values.createdCount ?? 0,
      updatedCount: values.updatedCount ?? 0,
      skippedCount: values.skippedCount ?? 0,
      errorCount: values.errorCount ?? 0,
      errorDetails: values.errorDetails ?? null,
      status: values.status ?? 'PENDING',
      createdAt: values.createdAt ?? new Date(),
      createdBy: values.createdBy,
    };
    importBatchStore.push(newBatch);
    return newBatch;
  }

  function insertMergeHistoryRow(values: any): any {
    const newMerge = {
      mergeId: values.mergeId ?? crypto.randomUUID(),
      physicianId: values.physicianId,
      survivingPatientId: values.survivingPatientId,
      mergedPatientId: values.mergedPatientId,
      claimsTransferred: values.claimsTransferred,
      fieldConflicts: values.fieldConflicts ?? null,
      mergedAt: values.mergedAt ?? new Date(),
      mergedBy: values.mergedBy,
    };
    mergeHistoryStore.push(newMerge);
    return newMerge;
  }

  function executeOp(ctx: any): any[] {
    const store = getStoreForTable(ctx.table);

    switch (ctx.op) {
      case 'select': {
        let matches = store.filter((row) =>
          ctx.whereClauses.every((pred: any) => pred(row)),
        );

        // Handle count queries
        if (ctx.selectFields && ctx.selectFields.total && ctx.selectFields.total.__count) {
          return [{ total: matches.length }];
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
        const isImportBatch = ctx.table && ctx.table.__table === 'patient_import_batches';
        const isMergeHistory = ctx.table && ctx.table.__table === 'patient_merge_history';
        const insertFn = isImportBatch
          ? insertImportBatchRow
          : isMergeHistory
            ? insertMergeHistoryRow
            : insertPatientRow;
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
      case 'delete': {
        const deleted: any[] = [];
        for (let i = store.length - 1; i >= 0; i--) {
          if (ctx.whereClauses.every((pred: any) => pred(store[i]))) {
            deleted.push({ ...store[i] });
            store.splice(i, 1);
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
    async execute(query: any) {
      // Mock raw SQL execution for claims queries
      // The sql`` template tag produces { __sql: true, raw: string, values: any[] }
      const queryValues = query?.values ?? [];
      const rawSql = query?.raw ?? '';

      // Detect SELECT COUNT vs UPDATE based on the raw SQL string
      if (rawSql.includes('COUNT') || rawSql.includes('count')) {
        // SELECT COUNT(*)::int AS count FROM claims WHERE patient_id = $1 AND provider_id = $2 AND status IN (...)
        // values: [mergedId, physicianId]
        const mergedPatientId = queryValues[0];
        const physicianId = queryValues[1];
        const matching = claimsStore.filter(
          (c) =>
            c.patientId === mergedPatientId &&
            c.providerId === physicianId &&
            ['draft', 'validated'].includes(c.status),
        );
        return { rows: [{ count: matching.length }] };
      }

      // UPDATE claims SET patient_id = $1 WHERE patient_id = $2 AND provider_id = $3 AND status IN (...)
      // values: [survivingId, mergedId, physicianId]
      const survivingId = queryValues[0];
      const mergedPatientId = queryValues[1];
      const physicianId = queryValues[2];
      let rowCount = 0;
      for (const claim of claimsStore) {
        if (
          claim.patientId === mergedPatientId &&
          claim.providerId === physicianId &&
          ['draft', 'validated'].includes(claim.status)
        ) {
          claim.patientId = survivingId;
          claim.updatedAt = new Date();
          rowCount++;
        }
      }
      return { rowCount };
    },
    async transaction(fn: any) {
      return fn(mockDb);
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
    ne: (column: any, value: any) => {
      const colName = column?.name;
      return {
        __predicate: (row: any) => row[colName] !== value,
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
    or: (...conditions: any[]) => {
      return {
        __predicate: (row: any) =>
          conditions.some((c: any) => {
            if (!c) return false;
            if (c.__predicate) return c.__predicate(row);
            return false;
          }),
      };
    },
    ilike: (column: any, pattern: any) => {
      const colName = column?.name;
      return {
        __predicate: (row: any) => {
          const val = row[colName];
          if (val == null) return false;
          // Convert SQL ILIKE pattern (%x%) to regex
          const escaped = pattern
            .replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
            .replace(/%/g, '.*');
          const re = new RegExp(`^${escaped}$`, 'i');
          return re.test(val);
        },
      };
    },
    isNotNull: (column: any) => {
      const colName = column?.name;
      return {
        __predicate: (row: any) => row[colName] != null,
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
      // For sql expressions (similarity), fall through to no-op sort
      return {
        __sortFn: (_a: any, _b: any) => 0,
      };
    },
    count: () => ({ __count: true }),
    sql: (strings: TemplateStringsArray, ...values: any[]) => {
      // Return a marker for the sql template tag; capture values for mock execute
      return { __sql: true, raw: strings.join('?'), values };
    },
  };
});

// ---------------------------------------------------------------------------
// Mock the patient schema module
// ---------------------------------------------------------------------------

vi.mock('@meritum/shared/utils/phn.utils.js', () => {
  return {
    validateAlbertaPhn: (phn: string) => {
      if (typeof phn !== 'string') {
        return { valid: false, error: 'PHN must be a string' };
      }
      if (!/^\d{9}$/.test(phn)) {
        return { valid: false, error: 'PHN must be exactly 9 digits' };
      }
      // Luhn algorithm
      let sum = 0;
      for (let i = phn.length - 1; i >= 0; i--) {
        let digit = parseInt(phn[i], 10);
        const positionFromRight = phn.length - 1 - i;
        if (positionFromRight % 2 === 1) {
          digit *= 2;
          if (digit > 9) digit -= 9;
        }
        sum += digit;
      }
      if (sum % 10 !== 0) {
        return { valid: false, error: 'PHN failed Luhn check digit validation' };
      }
      return { valid: true };
    },
    maskPhn: (phn: string) => {
      if (typeof phn !== 'string' || phn.length < 3) return '***';
      return phn.slice(0, 3) + '*'.repeat(phn.length - 3);
    },
  };
});

vi.mock('@meritum/shared/schemas/db/patient.schema.js', () => {
  const makeCol = (name: string) => ({ name });

  const patientsProxy: any = {
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
  };

  const patientImportBatchesProxy: any = {
    __table: 'patient_import_batches',
    importId: makeCol('importId'),
    physicianId: makeCol('physicianId'),
    fileName: makeCol('fileName'),
    fileHash: makeCol('fileHash'),
    totalRows: makeCol('totalRows'),
    createdCount: makeCol('createdCount'),
    updatedCount: makeCol('updatedCount'),
    skippedCount: makeCol('skippedCount'),
    errorCount: makeCol('errorCount'),
    errorDetails: makeCol('errorDetails'),
    status: makeCol('status'),
    createdAt: makeCol('createdAt'),
    createdBy: makeCol('createdBy'),
  };

  const patientMergeHistoryProxy: any = {
    __table: 'patient_merge_history',
    mergeId: makeCol('mergeId'),
    physicianId: makeCol('physicianId'),
    survivingPatientId: makeCol('survivingPatientId'),
    mergedPatientId: makeCol('mergedPatientId'),
    claimsTransferred: makeCol('claimsTransferred'),
    fieldConflicts: makeCol('fieldConflicts'),
    mergedAt: makeCol('mergedAt'),
    mergedBy: makeCol('mergedBy'),
  };

  return {
    patients: patientsProxy,
    patientImportBatches: patientImportBatchesProxy,
    patientMergeHistory: patientMergeHistoryProxy,
  };
});

// ---------------------------------------------------------------------------
// Test data helpers
// ---------------------------------------------------------------------------

const PHYSICIAN_1 = crypto.randomUUID();
const PHYSICIAN_2 = crypto.randomUUID();
const USER_1 = crypto.randomUUID();

function makePatientData(overrides?: Partial<Record<string, any>>) {
  return {
    providerId: PHYSICIAN_1,
    phn: '123456789',
    firstName: 'Jane',
    lastName: 'Smith',
    dateOfBirth: '1985-03-15',
    gender: 'F',
    createdBy: USER_1,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Patient Repository', () => {
  let repo: ReturnType<typeof createPatientRepository>;

  beforeEach(() => {
    patientStore = [];
    importBatchStore = [];
    mergeHistoryStore = [];
    claimsStore = [];
    repo = createPatientRepository(makeMockDb());
  });

  // =========================================================================
  // createPatient
  // =========================================================================

  it('createPatient inserts patient record', async () => {
    const data = makePatientData();
    const result = await repo.createPatient(data as any);

    expect(result.patientId).toBeDefined();
    expect(result.providerId).toBe(PHYSICIAN_1);
    expect(result.phn).toBe('123456789');
    expect(result.firstName).toBe('Jane');
    expect(result.lastName).toBe('Smith');
    expect(result.dateOfBirth).toBe('1985-03-15');
    expect(result.gender).toBe('F');
    expect(result.isActive).toBe(true);
    expect(result.createdAt).toBeInstanceOf(Date);
    expect(result.updatedAt).toBeInstanceOf(Date);
    expect(patientStore).toHaveLength(1);
  });

  it('createPatient rejects duplicate PHN for same physician', async () => {
    const data = makePatientData();
    await repo.createPatient(data as any);

    await expect(
      repo.createPatient(makePatientData({ firstName: 'John' }) as any),
    ).rejects.toThrow('duplicate key value');
  });

  it('createPatient allows same PHN for different physicians', async () => {
    await repo.createPatient(makePatientData() as any);

    const otherPhysician = makePatientData({
      providerId: PHYSICIAN_2,
      firstName: 'John',
    });
    const result = await repo.createPatient(otherPhysician as any);

    expect(result.providerId).toBe(PHYSICIAN_2);
    expect(result.phn).toBe('123456789');
    expect(patientStore).toHaveLength(2);
  });

  it('createPatient allows null PHN', async () => {
    const data1 = makePatientData({ phn: null });
    const data2 = makePatientData({ phn: null, firstName: 'John' });

    const result1 = await repo.createPatient(data1 as any);
    const result2 = await repo.createPatient(data2 as any);

    expect(result1.phn).toBeNull();
    expect(result2.phn).toBeNull();
    expect(patientStore).toHaveLength(2);
  });

  // =========================================================================
  // findPatientById
  // =========================================================================

  it('findPatientById returns patient scoped to physician', async () => {
    const created = await repo.createPatient(makePatientData() as any);

    const found = await repo.findPatientById(created.patientId, PHYSICIAN_1);

    expect(found).toBeDefined();
    expect(found!.patientId).toBe(created.patientId);
    expect(found!.providerId).toBe(PHYSICIAN_1);
  });

  it('findPatientById returns undefined for different physician', async () => {
    const created = await repo.createPatient(makePatientData() as any);

    const found = await repo.findPatientById(created.patientId, PHYSICIAN_2);

    expect(found).toBeUndefined();
  });

  it('findPatientById returns undefined for non-existent patient', async () => {
    const found = await repo.findPatientById(crypto.randomUUID(), PHYSICIAN_1);
    expect(found).toBeUndefined();
  });

  // =========================================================================
  // findPatientByPhn
  // =========================================================================

  it('findPatientByPhn returns exact match', async () => {
    await repo.createPatient(makePatientData() as any);

    const found = await repo.findPatientByPhn(PHYSICIAN_1, '123456789');

    expect(found).toBeDefined();
    expect(found!.phn).toBe('123456789');
    expect(found!.providerId).toBe(PHYSICIAN_1);
  });

  it('findPatientByPhn returns undefined for wrong physician', async () => {
    await repo.createPatient(makePatientData() as any);

    const found = await repo.findPatientByPhn(PHYSICIAN_2, '123456789');

    expect(found).toBeUndefined();
  });

  it('findPatientByPhn returns undefined for non-existent PHN', async () => {
    const found = await repo.findPatientByPhn(PHYSICIAN_1, '999999999');
    expect(found).toBeUndefined();
  });

  // =========================================================================
  // updatePatient
  // =========================================================================

  it('updatePatient updates fields and updated_at', async () => {
    const created = await repo.createPatient(makePatientData() as any);
    const originalUpdatedAt = created.updatedAt;

    const updated = await repo.updatePatient(
      created.patientId,
      PHYSICIAN_1,
      { firstName: 'Janet', phone: '403-555-1234' } as any,
    );

    expect(updated).toBeDefined();
    expect(updated!.firstName).toBe('Janet');
    expect(updated!.phone).toBe('403-555-1234');
    expect(updated!.lastName).toBe('Smith');
    expect(updated!.updatedAt).toBeInstanceOf(Date);
  });

  it('updatePatient returns undefined for wrong physician', async () => {
    const created = await repo.createPatient(makePatientData() as any);

    const updated = await repo.updatePatient(
      created.patientId,
      PHYSICIAN_2,
      { firstName: 'Hacker' } as any,
    );

    expect(updated).toBeUndefined();
    // Verify data was not modified
    expect(patientStore[0].firstName).toBe('Jane');
  });

  // =========================================================================
  // deactivatePatient
  // =========================================================================

  it('deactivatePatient sets is_active false', async () => {
    const created = await repo.createPatient(makePatientData() as any);

    const deactivated = await repo.deactivatePatient(
      created.patientId,
      PHYSICIAN_1,
    );

    expect(deactivated).toBeDefined();
    expect(deactivated!.isActive).toBe(false);
    expect(patientStore[0].isActive).toBe(false);
  });

  it('deactivatePatient returns undefined for wrong physician', async () => {
    const created = await repo.createPatient(makePatientData() as any);

    const result = await repo.deactivatePatient(
      created.patientId,
      PHYSICIAN_2,
    );

    expect(result).toBeUndefined();
    expect(patientStore[0].isActive).toBe(true);
  });

  // =========================================================================
  // reactivatePatient
  // =========================================================================

  it('reactivatePatient sets is_active true', async () => {
    const created = await repo.createPatient(
      makePatientData({ isActive: false }) as any,
    );
    expect(created.isActive).toBe(false);

    const reactivated = await repo.reactivatePatient(
      created.patientId,
      PHYSICIAN_1,
    );

    expect(reactivated).toBeDefined();
    expect(reactivated!.isActive).toBe(true);
    expect(patientStore[0].isActive).toBe(true);
  });

  it('reactivatePatient returns undefined for wrong physician', async () => {
    const created = await repo.createPatient(
      makePatientData({ isActive: false }) as any,
    );

    const result = await repo.reactivatePatient(
      created.patientId,
      PHYSICIAN_2,
    );

    expect(result).toBeUndefined();
    expect(patientStore[0].isActive).toBe(false);
  });

  // =========================================================================
  // updateLastVisitDate
  // =========================================================================

  it('updateLastVisitDate updates date', async () => {
    const created = await repo.createPatient(makePatientData() as any);
    expect(created.lastVisitDate).toBeNull();

    const visitDate = new Date('2026-02-15');
    const updated = await repo.updateLastVisitDate(
      created.patientId,
      PHYSICIAN_1,
      visitDate,
    );

    expect(updated).toBeDefined();
    expect(updated!.lastVisitDate).toBe('2026-02-15');
    expect(updated!.updatedAt).toBeInstanceOf(Date);
  });

  it('updateLastVisitDate returns undefined for wrong physician', async () => {
    const created = await repo.createPatient(makePatientData() as any);

    const result = await repo.updateLastVisitDate(
      created.patientId,
      PHYSICIAN_2,
      new Date('2026-02-15'),
    );

    expect(result).toBeUndefined();
    expect(patientStore[0].lastVisitDate).toBeNull();
  });

  // =========================================================================
  // searchByPhn
  // =========================================================================

  it('searchByPhn returns exact match for physician\'s active patient', async () => {
    await repo.createPatient(makePatientData() as any);

    const found = await repo.searchByPhn(PHYSICIAN_1, '123456789');

    expect(found).toBeDefined();
    expect(found!.phn).toBe('123456789');
    expect(found!.providerId).toBe(PHYSICIAN_1);
  });

  it('searchByPhn returns undefined for different physician', async () => {
    await repo.createPatient(makePatientData() as any);

    const found = await repo.searchByPhn(PHYSICIAN_2, '123456789');

    expect(found).toBeUndefined();
  });

  it('searchByPhn excludes inactive patients', async () => {
    await repo.createPatient(makePatientData({ isActive: false }) as any);

    const found = await repo.searchByPhn(PHYSICIAN_1, '123456789');

    expect(found).toBeUndefined();
  });

  // =========================================================================
  // searchByName
  // =========================================================================

  it('searchByName returns case-insensitive matches', async () => {
    await repo.createPatient(makePatientData({ firstName: 'Alice', lastName: 'Johnson' }) as any);
    await repo.createPatient(
      makePatientData({ phn: '987654321', firstName: 'Bob', lastName: 'Jones' }) as any,
    );

    const result = await repo.searchByName(PHYSICIAN_1, 'jo', 1, 20);

    expect(result.data.length).toBe(2);
    expect(result.pagination.total).toBe(2);
    expect(result.pagination.page).toBe(1);
    expect(result.pagination.pageSize).toBe(20);
    expect(result.pagination.hasMore).toBe(false);
  });

  it('searchByName requires minimum 2 characters', async () => {
    await repo.createPatient(makePatientData() as any);

    const result = await repo.searchByName(PHYSICIAN_1, 'J', 1, 20);

    expect(result.data).toHaveLength(0);
    expect(result.pagination.total).toBe(0);
  });

  it('searchByName excludes inactive patients', async () => {
    await repo.createPatient(
      makePatientData({ firstName: 'Alice', lastName: 'Johnson', isActive: false }) as any,
    );
    await repo.createPatient(
      makePatientData({ phn: '987654321', firstName: 'Bob', lastName: 'Johnson' }) as any,
    );

    const result = await repo.searchByName(PHYSICIAN_1, 'Johnson', 1, 20);

    expect(result.data.length).toBe(1);
    expect(result.data[0].firstName).toBe('Bob');
  });

  it('searchByName excludes other physician\'s patients', async () => {
    await repo.createPatient(
      makePatientData({ firstName: 'Alice', lastName: 'Johnson' }) as any,
    );
    await repo.createPatient(
      makePatientData({
        providerId: PHYSICIAN_2,
        firstName: 'Bob',
        lastName: 'Johnson',
      }) as any,
    );

    const result = await repo.searchByName(PHYSICIAN_1, 'Johnson', 1, 20);

    expect(result.data.length).toBe(1);
    expect(result.data[0].providerId).toBe(PHYSICIAN_1);
  });

  it('searchByName paginates results', async () => {
    // Create 3 patients all matching "Sm"
    await repo.createPatient(
      makePatientData({ phn: '111111111', firstName: 'A', lastName: 'Smith' }) as any,
    );
    await repo.createPatient(
      makePatientData({ phn: '222222222', firstName: 'B', lastName: 'Smith' }) as any,
    );
    await repo.createPatient(
      makePatientData({ phn: '333333333', firstName: 'C', lastName: 'Smith' }) as any,
    );

    const page1 = await repo.searchByName(PHYSICIAN_1, 'Smith', 1, 2);

    expect(page1.data.length).toBe(2);
    expect(page1.pagination.total).toBe(3);
    expect(page1.pagination.hasMore).toBe(true);

    const page2 = await repo.searchByName(PHYSICIAN_1, 'Smith', 2, 2);

    expect(page2.data.length).toBe(1);
    expect(page2.pagination.hasMore).toBe(false);
  });

  // =========================================================================
  // searchByDob
  // =========================================================================

  it('searchByDob returns matching patients', async () => {
    await repo.createPatient(
      makePatientData({ dateOfBirth: '1985-03-15' }) as any,
    );
    await repo.createPatient(
      makePatientData({
        phn: '987654321',
        firstName: 'Bob',
        dateOfBirth: '1990-06-20',
      }) as any,
    );

    const result = await repo.searchByDob(PHYSICIAN_1, new Date('1985-03-15'), 1, 20);

    expect(result.data.length).toBe(1);
    expect(result.data[0].dateOfBirth).toBe('1985-03-15');
    expect(result.pagination.total).toBe(1);
  });

  it('searchByDob excludes other physician\'s patients', async () => {
    await repo.createPatient(
      makePatientData({ dateOfBirth: '1985-03-15' }) as any,
    );
    await repo.createPatient(
      makePatientData({
        providerId: PHYSICIAN_2,
        firstName: 'Bob',
        dateOfBirth: '1985-03-15',
      }) as any,
    );

    const result = await repo.searchByDob(PHYSICIAN_1, new Date('1985-03-15'), 1, 20);

    expect(result.data.length).toBe(1);
    expect(result.data[0].providerId).toBe(PHYSICIAN_1);
  });

  it('searchByDob excludes inactive patients', async () => {
    await repo.createPatient(
      makePatientData({ dateOfBirth: '1985-03-15', isActive: false }) as any,
    );

    const result = await repo.searchByDob(PHYSICIAN_1, new Date('1985-03-15'), 1, 20);

    expect(result.data.length).toBe(0);
  });

  // =========================================================================
  // searchCombined
  // =========================================================================

  it('searchCombined ANDs all criteria', async () => {
    await repo.createPatient(
      makePatientData({
        phn: '111111111',
        firstName: 'Alice',
        lastName: 'Johnson',
        dateOfBirth: '1985-03-15',
      }) as any,
    );
    await repo.createPatient(
      makePatientData({
        phn: '222222222',
        firstName: 'Bob',
        lastName: 'Johnson',
        dateOfBirth: '1990-06-20',
      }) as any,
    );

    // Search with name + dob: only Alice matches
    const result = await repo.searchCombined(
      PHYSICIAN_1,
      { name: 'Johnson', dob: new Date('1985-03-15') },
      1,
      20,
    );

    expect(result.data.length).toBe(1);
    expect(result.data[0].firstName).toBe('Alice');
  });

  it('searchCombined with PHN only returns exact match', async () => {
    await repo.createPatient(makePatientData({ phn: '111111111' }) as any);
    await repo.createPatient(
      makePatientData({ phn: '222222222', firstName: 'Bob' }) as any,
    );

    const result = await repo.searchCombined(
      PHYSICIAN_1,
      { phn: '111111111' },
      1,
      20,
    );

    expect(result.data.length).toBe(1);
    expect(result.data[0].phn).toBe('111111111');
  });

  it('searchCombined excludes other physician\'s patients', async () => {
    await repo.createPatient(
      makePatientData({ firstName: 'Alice', lastName: 'Johnson' }) as any,
    );
    await repo.createPatient(
      makePatientData({
        providerId: PHYSICIAN_2,
        firstName: 'Bob',
        lastName: 'Johnson',
      }) as any,
    );

    const result = await repo.searchCombined(
      PHYSICIAN_1,
      { name: 'Johnson' },
      1,
      20,
    );

    expect(result.data.length).toBe(1);
    expect(result.data[0].providerId).toBe(PHYSICIAN_1);
  });

  // =========================================================================
  // getRecentPatients
  // =========================================================================

  it('getRecentPatients returns ordered by last_visit_date DESC', async () => {
    await repo.createPatient(
      makePatientData({
        phn: '111111111',
        firstName: 'Alice',
        lastVisitDate: '2026-01-10',
      }) as any,
    );
    await repo.createPatient(
      makePatientData({
        phn: '222222222',
        firstName: 'Bob',
        lastVisitDate: '2026-02-15',
      }) as any,
    );
    await repo.createPatient(
      makePatientData({
        phn: '333333333',
        firstName: 'Charlie',
        lastVisitDate: '2026-01-20',
      }) as any,
    );

    const result = await repo.getRecentPatients(PHYSICIAN_1);

    expect(result.length).toBe(3);
    expect(result[0].firstName).toBe('Bob');       // 2026-02-15
    expect(result[1].firstName).toBe('Charlie');   // 2026-01-20
    expect(result[2].firstName).toBe('Alice');     // 2026-01-10
  });

  it('getRecentPatients respects limit', async () => {
    await repo.createPatient(
      makePatientData({
        phn: '111111111',
        firstName: 'Alice',
        lastVisitDate: '2026-01-10',
      }) as any,
    );
    await repo.createPatient(
      makePatientData({
        phn: '222222222',
        firstName: 'Bob',
        lastVisitDate: '2026-02-15',
      }) as any,
    );
    await repo.createPatient(
      makePatientData({
        phn: '333333333',
        firstName: 'Charlie',
        lastVisitDate: '2026-01-20',
      }) as any,
    );

    const result = await repo.getRecentPatients(PHYSICIAN_1, 2);

    expect(result.length).toBe(2);
    expect(result[0].firstName).toBe('Bob');
    expect(result[1].firstName).toBe('Charlie');
  });

  it('getRecentPatients excludes patients with null last_visit_date', async () => {
    await repo.createPatient(
      makePatientData({
        phn: '111111111',
        firstName: 'Alice',
        lastVisitDate: '2026-01-10',
      }) as any,
    );
    await repo.createPatient(
      makePatientData({
        phn: '222222222',
        firstName: 'Bob',
        // lastVisitDate is null by default
      }) as any,
    );

    const result = await repo.getRecentPatients(PHYSICIAN_1);

    expect(result.length).toBe(1);
    expect(result[0].firstName).toBe('Alice');
  });

  it('getRecentPatients excludes inactive patients', async () => {
    await repo.createPatient(
      makePatientData({
        phn: '111111111',
        firstName: 'Alice',
        lastVisitDate: '2026-01-10',
        isActive: false,
      }) as any,
    );
    await repo.createPatient(
      makePatientData({
        phn: '222222222',
        firstName: 'Bob',
        lastVisitDate: '2026-02-15',
      }) as any,
    );

    const result = await repo.getRecentPatients(PHYSICIAN_1);

    expect(result.length).toBe(1);
    expect(result[0].firstName).toBe('Bob');
  });

  it('getRecentPatients excludes other physician\'s patients', async () => {
    await repo.createPatient(
      makePatientData({
        phn: '111111111',
        firstName: 'Alice',
        lastVisitDate: '2026-01-10',
      }) as any,
    );
    await repo.createPatient(
      makePatientData({
        providerId: PHYSICIAN_2,
        firstName: 'Bob',
        lastVisitDate: '2026-02-15',
      }) as any,
    );

    const result = await repo.getRecentPatients(PHYSICIAN_1);

    expect(result.length).toBe(1);
    expect(result[0].firstName).toBe('Alice');
  });

  // =========================================================================
  // CSV Import Batch Operations
  // =========================================================================

  // -------------------------------------------------------------------------
  // createImportBatch
  // -------------------------------------------------------------------------

  it('createImportBatch inserts with PENDING status', async () => {
    const data = {
      physicianId: PHYSICIAN_1,
      fileName: 'patients.csv',
      fileHash: 'abc123def456',
      totalRows: 50,
      createdBy: USER_1,
    };
    const result = await repo.createImportBatch(data as any);

    expect(result.importId).toBeDefined();
    expect(result.physicianId).toBe(PHYSICIAN_1);
    expect(result.fileName).toBe('patients.csv');
    expect(result.fileHash).toBe('abc123def456');
    expect(result.totalRows).toBe(50);
    expect(result.status).toBe('PENDING');
    expect(result.createdCount).toBe(0);
    expect(result.updatedCount).toBe(0);
    expect(result.skippedCount).toBe(0);
    expect(result.errorCount).toBe(0);
    expect(result.errorDetails).toBeNull();
    expect(result.createdAt).toBeInstanceOf(Date);
    expect(importBatchStore).toHaveLength(1);
  });

  // -------------------------------------------------------------------------
  // findImportBatchById
  // -------------------------------------------------------------------------

  it('findImportBatchById returns batch scoped to physician', async () => {
    const batch = await repo.createImportBatch({
      physicianId: PHYSICIAN_1,
      fileName: 'patients.csv',
      fileHash: 'abc123',
      totalRows: 10,
      createdBy: USER_1,
    } as any);

    const found = await repo.findImportBatchById(batch.importId, PHYSICIAN_1);

    expect(found).toBeDefined();
    expect(found!.importId).toBe(batch.importId);
    expect(found!.physicianId).toBe(PHYSICIAN_1);
  });

  it('findImportBatchById returns undefined for different physician', async () => {
    const batch = await repo.createImportBatch({
      physicianId: PHYSICIAN_1,
      fileName: 'patients.csv',
      fileHash: 'abc123',
      totalRows: 10,
      createdBy: USER_1,
    } as any);

    const found = await repo.findImportBatchById(batch.importId, PHYSICIAN_2);

    expect(found).toBeUndefined();
  });

  // -------------------------------------------------------------------------
  // findImportByFileHash
  // -------------------------------------------------------------------------

  it('findImportByFileHash detects duplicate file upload', async () => {
    const fileHash = 'sha256_abcdef1234567890';
    await repo.createImportBatch({
      physicianId: PHYSICIAN_1,
      fileName: 'patients.csv',
      fileHash,
      totalRows: 10,
      createdBy: USER_1,
    } as any);

    const found = await repo.findImportByFileHash(PHYSICIAN_1, fileHash);

    expect(found).toBeDefined();
    expect(found!.fileHash).toBe(fileHash);
    expect(found!.physicianId).toBe(PHYSICIAN_1);
  });

  it('findImportByFileHash returns undefined for different physician', async () => {
    const fileHash = 'sha256_abcdef1234567890';
    await repo.createImportBatch({
      physicianId: PHYSICIAN_1,
      fileName: 'patients.csv',
      fileHash,
      totalRows: 10,
      createdBy: USER_1,
    } as any);

    const found = await repo.findImportByFileHash(PHYSICIAN_2, fileHash);

    expect(found).toBeUndefined();
  });

  it('findImportByFileHash returns undefined when hash not found', async () => {
    const found = await repo.findImportByFileHash(PHYSICIAN_1, 'nonexistent_hash');

    expect(found).toBeUndefined();
  });

  // -------------------------------------------------------------------------
  // updateImportStatus
  // -------------------------------------------------------------------------

  it('updateImportStatus updates status and counts', async () => {
    const batch = await repo.createImportBatch({
      physicianId: PHYSICIAN_1,
      fileName: 'patients.csv',
      fileHash: 'abc123',
      totalRows: 100,
      createdBy: USER_1,
    } as any);

    const updated = await repo.updateImportStatus(
      batch.importId,
      'COMPLETED',
      { created: 80, updated: 10, skipped: 5, error: 5 },
    );

    expect(updated).toBeDefined();
    expect(updated!.status).toBe('COMPLETED');
    expect(updated!.createdCount).toBe(80);
    expect(updated!.updatedCount).toBe(10);
    expect(updated!.skippedCount).toBe(5);
    expect(updated!.errorCount).toBe(5);
  });

  it('updateImportStatus updates error details', async () => {
    const batch = await repo.createImportBatch({
      physicianId: PHYSICIAN_1,
      fileName: 'patients.csv',
      fileHash: 'abc123',
      totalRows: 10,
      createdBy: USER_1,
    } as any);

    const errorDetails = [{ row: 3, field: 'phn', message: 'Invalid PHN' }];
    const updated = await repo.updateImportStatus(
      batch.importId,
      'FAILED',
      { created: 0, updated: 0, skipped: 0, error: 1 },
      errorDetails,
    );

    expect(updated).toBeDefined();
    expect(updated!.status).toBe('FAILED');
    expect(updated!.errorDetails).toEqual(errorDetails);
  });

  it('updateImportStatus updates status without counts', async () => {
    const batch = await repo.createImportBatch({
      physicianId: PHYSICIAN_1,
      fileName: 'patients.csv',
      fileHash: 'abc123',
      totalRows: 10,
      createdBy: USER_1,
    } as any);

    const updated = await repo.updateImportStatus(batch.importId, 'PROCESSING');

    expect(updated).toBeDefined();
    expect(updated!.status).toBe('PROCESSING');
    expect(updated!.createdCount).toBe(0); // unchanged
  });

  // -------------------------------------------------------------------------
  // listImportBatches
  // -------------------------------------------------------------------------

  it('listImportBatches returns newest first for physician', async () => {
    const date1 = new Date('2026-01-01T00:00:00Z');
    const date2 = new Date('2026-02-01T00:00:00Z');
    const date3 = new Date('2026-03-01T00:00:00Z');

    await repo.createImportBatch({
      physicianId: PHYSICIAN_1,
      fileName: 'jan.csv',
      fileHash: 'hash1',
      totalRows: 10,
      createdBy: USER_1,
      createdAt: date1,
    } as any);
    await repo.createImportBatch({
      physicianId: PHYSICIAN_1,
      fileName: 'mar.csv',
      fileHash: 'hash3',
      totalRows: 30,
      createdBy: USER_1,
      createdAt: date3,
    } as any);
    await repo.createImportBatch({
      physicianId: PHYSICIAN_1,
      fileName: 'feb.csv',
      fileHash: 'hash2',
      totalRows: 20,
      createdBy: USER_1,
      createdAt: date2,
    } as any);

    const result = await repo.listImportBatches(PHYSICIAN_1, 1, 10);

    expect(result.data).toHaveLength(3);
    expect(result.data[0].fileName).toBe('mar.csv');
    expect(result.data[1].fileName).toBe('feb.csv');
    expect(result.data[2].fileName).toBe('jan.csv');
    expect(result.pagination.total).toBe(3);
    expect(result.pagination.page).toBe(1);
    expect(result.pagination.pageSize).toBe(10);
    expect(result.pagination.hasMore).toBe(false);
  });

  it('listImportBatches excludes other physician\'s batches', async () => {
    await repo.createImportBatch({
      physicianId: PHYSICIAN_1,
      fileName: 'mine.csv',
      fileHash: 'hash1',
      totalRows: 10,
      createdBy: USER_1,
    } as any);
    await repo.createImportBatch({
      physicianId: PHYSICIAN_2,
      fileName: 'theirs.csv',
      fileHash: 'hash2',
      totalRows: 20,
      createdBy: USER_1,
    } as any);

    const result = await repo.listImportBatches(PHYSICIAN_1, 1, 10);

    expect(result.data).toHaveLength(1);
    expect(result.data[0].fileName).toBe('mine.csv');
  });

  it('listImportBatches paginates results', async () => {
    for (let i = 0; i < 5; i++) {
      await repo.createImportBatch({
        physicianId: PHYSICIAN_1,
        fileName: `file${i}.csv`,
        fileHash: `hash${i}`,
        totalRows: 10,
        createdBy: USER_1,
      } as any);
    }

    const page1 = await repo.listImportBatches(PHYSICIAN_1, 1, 2);
    expect(page1.data).toHaveLength(2);
    expect(page1.pagination.total).toBe(5);
    expect(page1.pagination.hasMore).toBe(true);

    const page3 = await repo.listImportBatches(PHYSICIAN_1, 3, 2);
    expect(page3.data).toHaveLength(1);
    expect(page3.pagination.hasMore).toBe(false);
  });

  // -------------------------------------------------------------------------
  // bulkCreatePatients
  // -------------------------------------------------------------------------

  it('bulkCreatePatients inserts all patients in transaction', async () => {
    const patientsData = [
      makePatientData({ phn: '111111111', firstName: 'Alice' }),
      makePatientData({ phn: '222222222', firstName: 'Bob' }),
      makePatientData({ phn: '333333333', firstName: 'Charlie' }),
    ];

    const ids = await repo.bulkCreatePatients(PHYSICIAN_1, patientsData as any);

    expect(ids).toHaveLength(3);
    expect(patientStore).toHaveLength(3);
    for (const id of ids) {
      expect(typeof id).toBe('string');
      expect(id.length).toBeGreaterThan(0);
    }
    // All scoped to PHYSICIAN_1
    for (const p of patientStore) {
      expect(p.providerId).toBe(PHYSICIAN_1);
    }
  });

  it('bulkCreatePatients rolls back on failure', async () => {
    // First insert will succeed, second will have same PHN causing duplicate error
    const patientsData = [
      makePatientData({ phn: '111111111', firstName: 'Alice' }),
      makePatientData({ phn: '111111111', firstName: 'Bob' }), // duplicate PHN
    ];

    await expect(
      repo.bulkCreatePatients(PHYSICIAN_1, patientsData as any),
    ).rejects.toThrow('duplicate key value');
  });

  it('bulkCreatePatients stamps providerId on all rows', async () => {
    const patientsData = [
      makePatientData({ phn: '111111111', firstName: 'Alice', providerId: 'should-be-overridden' }),
    ];

    const ids = await repo.bulkCreatePatients(PHYSICIAN_1, patientsData as any);

    expect(ids).toHaveLength(1);
    expect(patientStore[0].providerId).toBe(PHYSICIAN_1);
  });

  // -------------------------------------------------------------------------
  // bulkUpsertPatients
  // -------------------------------------------------------------------------

  it('bulkUpsertPatients creates new and updates existing by PHN match', async () => {
    // Pre-existing patient with PHN 111111111
    await repo.createPatient(
      makePatientData({
        phn: '111111111',
        firstName: 'Alice',
        lastName: 'OldName',
      }) as any,
    );

    const upsertData = [
      { phn: '111111111', data: { firstName: 'Alice', lastName: 'NewName', dateOfBirth: '1985-03-15', gender: 'F', createdBy: USER_1 } },
      { phn: '222222222', data: { firstName: 'Bob', lastName: 'Smith', dateOfBirth: '1990-06-20', gender: 'M', createdBy: USER_1 } },
    ];

    const result = await repo.bulkUpsertPatients(PHYSICIAN_1, upsertData as any);

    expect(result.updated).toBe(1);
    expect(result.created).toBe(1);
    expect(patientStore).toHaveLength(2);

    // Verify updated record
    const alice = patientStore.find((p) => p.phn === '111111111');
    expect(alice!.lastName).toBe('NewName');

    // Verify created record
    const bob = patientStore.find((p) => p.phn === '222222222');
    expect(bob).toBeDefined();
    expect(bob!.firstName).toBe('Bob');
    expect(bob!.providerId).toBe(PHYSICIAN_1);
  });

  it('bulkUpsertPatients scopes PHN lookup to physician', async () => {
    // Create patient for PHYSICIAN_2
    await repo.createPatient(
      makePatientData({
        providerId: PHYSICIAN_2,
        phn: '111111111',
        firstName: 'OtherPhysicianPatient',
      }) as any,
    );

    // Upsert for PHYSICIAN_1 with same PHN — should create, not update
    const upsertData = [
      { phn: '111111111', data: { firstName: 'NewPatient', lastName: 'Smith', dateOfBirth: '1990-01-01', gender: 'F', createdBy: USER_1 } },
    ];

    const result = await repo.bulkUpsertPatients(PHYSICIAN_1, upsertData as any);

    expect(result.created).toBe(1);
    expect(result.updated).toBe(0);
    expect(patientStore).toHaveLength(2);

    // Original patient unchanged
    const original = patientStore.find(
      (p) => p.providerId === PHYSICIAN_2 && p.phn === '111111111',
    );
    expect(original!.firstName).toBe('OtherPhysicianPatient');
  });

  it('bulkUpsertPatients handles all new records', async () => {
    const upsertData = [
      { phn: '111111111', data: { firstName: 'Alice', lastName: 'Smith', dateOfBirth: '1985-03-15', gender: 'F', createdBy: USER_1 } },
      { phn: '222222222', data: { firstName: 'Bob', lastName: 'Jones', dateOfBirth: '1990-06-20', gender: 'M', createdBy: USER_1 } },
    ];

    const result = await repo.bulkUpsertPatients(PHYSICIAN_1, upsertData as any);

    expect(result.created).toBe(2);
    expect(result.updated).toBe(0);
    expect(patientStore).toHaveLength(2);
  });

  it('bulkUpsertPatients handles all existing records', async () => {
    await repo.createPatient(
      makePatientData({ phn: '111111111', firstName: 'Alice' }) as any,
    );
    await repo.createPatient(
      makePatientData({ phn: '222222222', firstName: 'Bob' }) as any,
    );

    const upsertData = [
      { phn: '111111111', data: { firstName: 'AliceUpdated' } },
      { phn: '222222222', data: { firstName: 'BobUpdated' } },
    ];

    const result = await repo.bulkUpsertPatients(PHYSICIAN_1, upsertData as any);

    expect(result.created).toBe(0);
    expect(result.updated).toBe(2);

    const alice = patientStore.find((p) => p.phn === '111111111');
    expect(alice!.firstName).toBe('AliceUpdated');
    const bob = patientStore.find((p) => p.phn === '222222222');
    expect(bob!.firstName).toBe('BobUpdated');
  });

  // =========================================================================
  // Patient Merge Operations
  // =========================================================================

  // -------------------------------------------------------------------------
  // getMergePreview
  // -------------------------------------------------------------------------

  it('getMergePreview returns side-by-side comparison', async () => {
    const surviving = await repo.createPatient(
      makePatientData({
        phn: '111111111',
        firstName: 'Alice',
        lastName: 'Smith',
        phone: '403-555-1111',
      }) as any,
    );
    const merged = await repo.createPatient(
      makePatientData({
        phn: '222222222',
        firstName: 'Alicia',
        lastName: 'Smith',
        phone: '403-555-2222',
      }) as any,
    );

    const preview = await repo.getMergePreview(
      PHYSICIAN_1,
      surviving.patientId,
      merged.patientId,
    );

    expect(preview).not.toBeNull();
    expect(preview!.surviving.patientId).toBe(surviving.patientId);
    expect(preview!.merged.patientId).toBe(merged.patientId);
    expect(preview!.surviving.firstName).toBe('Alice');
    expect(preview!.merged.firstName).toBe('Alicia');
  });

  it('getMergePreview returns correct claim transfer count', async () => {
    const surviving = await repo.createPatient(
      makePatientData({ phn: '111111111', firstName: 'Alice' }) as any,
    );
    const merged = await repo.createPatient(
      makePatientData({ phn: '222222222', firstName: 'Bob' }) as any,
    );

    // Add claims to claims store for the merged patient
    claimsStore.push(
      { claimId: crypto.randomUUID(), patientId: merged.patientId, providerId: PHYSICIAN_1, status: 'draft' },
      { claimId: crypto.randomUUID(), patientId: merged.patientId, providerId: PHYSICIAN_1, status: 'validated' },
      { claimId: crypto.randomUUID(), patientId: merged.patientId, providerId: PHYSICIAN_1, status: 'submitted' },
      { claimId: crypto.randomUUID(), patientId: merged.patientId, providerId: PHYSICIAN_1, status: 'assessed' },
    );

    const preview = await repo.getMergePreview(
      PHYSICIAN_1,
      surviving.patientId,
      merged.patientId,
    );

    expect(preview).not.toBeNull();
    // Only draft and validated should be counted
    expect(preview!.claimsToTransfer).toBe(2);
  });

  it('getMergePreview returns field conflicts', async () => {
    const surviving = await repo.createPatient(
      makePatientData({
        phn: '111111111',
        firstName: 'Alice',
        lastName: 'Smith',
        phone: '403-555-1111',
        city: 'Calgary',
      }) as any,
    );
    const merged = await repo.createPatient(
      makePatientData({
        phn: '222222222',
        firstName: 'Alicia',
        lastName: 'Smith',
        phone: '403-555-2222',
        city: 'Edmonton',
      }) as any,
    );

    const preview = await repo.getMergePreview(
      PHYSICIAN_1,
      surviving.patientId,
      merged.patientId,
    );

    expect(preview).not.toBeNull();
    expect(preview!.fieldConflicts).toHaveProperty('phn');
    expect(preview!.fieldConflicts).toHaveProperty('firstName');
    expect(preview!.fieldConflicts).toHaveProperty('phone');
    expect(preview!.fieldConflicts).toHaveProperty('city');
    // lastName is the same — not a conflict
    expect(preview!.fieldConflicts).not.toHaveProperty('lastName');
    expect(preview!.fieldConflicts.firstName).toEqual({
      surviving: 'Alice',
      merged: 'Alicia',
    });
  });

  it('getMergePreview rejects if either patient belongs to different physician', async () => {
    const surviving = await repo.createPatient(
      makePatientData({ phn: '111111111', firstName: 'Alice' }) as any,
    );
    const merged = await repo.createPatient(
      makePatientData({
        providerId: PHYSICIAN_2,
        phn: '222222222',
        firstName: 'Bob',
      }) as any,
    );

    const preview = await repo.getMergePreview(
      PHYSICIAN_1,
      surviving.patientId,
      merged.patientId,
    );

    expect(preview).toBeNull();
  });

  it('getMergePreview rejects if surviving patient does not exist', async () => {
    const merged = await repo.createPatient(
      makePatientData({ phn: '222222222', firstName: 'Bob' }) as any,
    );

    const preview = await repo.getMergePreview(
      PHYSICIAN_1,
      crypto.randomUUID(),
      merged.patientId,
    );

    expect(preview).toBeNull();
  });

  it('getMergePreview rejects if merged patient does not exist', async () => {
    const surviving = await repo.createPatient(
      makePatientData({ phn: '111111111', firstName: 'Alice' }) as any,
    );

    const preview = await repo.getMergePreview(
      PHYSICIAN_1,
      surviving.patientId,
      crypto.randomUUID(),
    );

    expect(preview).toBeNull();
  });

  // -------------------------------------------------------------------------
  // executeMerge
  // -------------------------------------------------------------------------

  it('executeMerge transfers draft/validated claims to surviving patient', async () => {
    const surviving = await repo.createPatient(
      makePatientData({ phn: '111111111', firstName: 'Alice' }) as any,
    );
    const merged = await repo.createPatient(
      makePatientData({ phn: '222222222', firstName: 'Bob' }) as any,
    );

    // Add draft and validated claims for merged patient
    claimsStore.push(
      { claimId: crypto.randomUUID(), patientId: merged.patientId, providerId: PHYSICIAN_1, status: 'draft' },
      { claimId: crypto.randomUUID(), patientId: merged.patientId, providerId: PHYSICIAN_1, status: 'validated' },
    );

    const result = await repo.executeMerge(
      PHYSICIAN_1,
      surviving.patientId,
      merged.patientId,
      USER_1,
    );

    expect(result).not.toBeNull();
    expect(result!.claimsTransferred).toBe(2);

    // Verify claims now point to surviving patient
    for (const claim of claimsStore) {
      expect(claim.patientId).toBe(surviving.patientId);
    }
  });

  it('executeMerge does NOT transfer submitted/assessed claims', async () => {
    const surviving = await repo.createPatient(
      makePatientData({ phn: '111111111', firstName: 'Alice' }) as any,
    );
    const merged = await repo.createPatient(
      makePatientData({ phn: '222222222', firstName: 'Bob' }) as any,
    );

    // Add claims with various statuses
    const draftClaim = { claimId: crypto.randomUUID(), patientId: merged.patientId, providerId: PHYSICIAN_1, status: 'draft' };
    const submittedClaim = { claimId: crypto.randomUUID(), patientId: merged.patientId, providerId: PHYSICIAN_1, status: 'submitted' };
    const assessedClaim = { claimId: crypto.randomUUID(), patientId: merged.patientId, providerId: PHYSICIAN_1, status: 'assessed' };
    const paidClaim = { claimId: crypto.randomUUID(), patientId: merged.patientId, providerId: PHYSICIAN_1, status: 'paid' };
    claimsStore.push(draftClaim, submittedClaim, assessedClaim, paidClaim);

    const result = await repo.executeMerge(
      PHYSICIAN_1,
      surviving.patientId,
      merged.patientId,
      USER_1,
    );

    expect(result).not.toBeNull();
    expect(result!.claimsTransferred).toBe(1); // Only draft

    // Draft claim transferred
    expect(draftClaim.patientId).toBe(surviving.patientId);
    // Submitted, assessed, paid claims NOT transferred
    expect(submittedClaim.patientId).toBe(merged.patientId);
    expect(assessedClaim.patientId).toBe(merged.patientId);
    expect(paidClaim.patientId).toBe(merged.patientId);
  });

  it('executeMerge soft-deletes merged patient', async () => {
    const surviving = await repo.createPatient(
      makePatientData({ phn: '111111111', firstName: 'Alice' }) as any,
    );
    const merged = await repo.createPatient(
      makePatientData({ phn: '222222222', firstName: 'Bob' }) as any,
    );

    expect(merged.isActive).toBe(true);

    await repo.executeMerge(
      PHYSICIAN_1,
      surviving.patientId,
      merged.patientId,
      USER_1,
    );

    // The merged patient in the store should be soft-deleted
    const mergedInStore = patientStore.find((p) => p.patientId === merged.patientId);
    expect(mergedInStore!.isActive).toBe(false);

    // The surviving patient should remain active
    const survivingInStore = patientStore.find((p) => p.patientId === surviving.patientId);
    expect(survivingInStore!.isActive).toBe(true);
  });

  it('executeMerge records merge history with field conflicts', async () => {
    const surviving = await repo.createPatient(
      makePatientData({
        phn: '111111111',
        firstName: 'Alice',
        lastName: 'Smith',
        phone: '403-555-1111',
      }) as any,
    );
    const merged = await repo.createPatient(
      makePatientData({
        phn: '222222222',
        firstName: 'Alicia',
        lastName: 'Smith',
        phone: '403-555-2222',
      }) as any,
    );

    const result = await repo.executeMerge(
      PHYSICIAN_1,
      surviving.patientId,
      merged.patientId,
      USER_1,
    );

    expect(result).not.toBeNull();
    expect(result!.mergeId).toBeDefined();
    expect(typeof result!.mergeId).toBe('string');

    // Check merge history was recorded
    expect(mergeHistoryStore).toHaveLength(1);
    const history = mergeHistoryStore[0];
    expect(history.physicianId).toBe(PHYSICIAN_1);
    expect(history.survivingPatientId).toBe(surviving.patientId);
    expect(history.mergedPatientId).toBe(merged.patientId);
    expect(history.mergedBy).toBe(USER_1);
    expect(history.claimsTransferred).toBe(0);

    // Verify field conflicts recorded
    expect(result!.fieldConflicts).toHaveProperty('phn');
    expect(result!.fieldConflicts).toHaveProperty('firstName');
    expect(result!.fieldConflicts).toHaveProperty('phone');
    expect(result!.fieldConflicts).not.toHaveProperty('lastName'); // same value
  });

  it('executeMerge runs in single transaction (rollback on failure)', async () => {
    const surviving = await repo.createPatient(
      makePatientData({ phn: '111111111', firstName: 'Alice' }) as any,
    );
    const merged = await repo.createPatient(
      makePatientData({ phn: '222222222', firstName: 'Bob' }) as any,
    );

    // Add a draft claim
    claimsStore.push({
      claimId: crypto.randomUUID(),
      patientId: merged.patientId,
      providerId: PHYSICIAN_1,
      status: 'draft',
    });

    // Use a modified repo where insert into merge history fails
    const failingDb = makeMockDb();
    const originalInsert = failingDb.insert.bind(failingDb);
    failingDb.insert = (table: any) => {
      if (table && table.__table === 'patient_merge_history') {
        // Return a chain that throws when .returning() is awaited
        return {
          values: () => ({
            returning: () => ({
              then: (_resolve: any, reject?: any) => {
                const err = new Error('Simulated DB failure on merge history insert');
                if (reject) reject(err); else throw err;
              },
            }),
          }),
        };
      }
      return originalInsert(table);
    };

    // Override transaction to revert state on failure (simulating real PG rollback)
    const storeSnapshot = {
      patients: [...patientStore.map((p) => ({ ...p }))],
      claims: [...claimsStore.map((c) => ({ ...c }))],
      mergeHistory: [...mergeHistoryStore.map((m) => ({ ...m }))],
    };
    failingDb.transaction = async (fn: any) => {
      try {
        return await fn(failingDb);
      } catch (e) {
        // Rollback: restore stores to snapshot
        patientStore.length = 0;
        patientStore.push(...storeSnapshot.patients);
        claimsStore.length = 0;
        claimsStore.push(...storeSnapshot.claims);
        mergeHistoryStore.length = 0;
        mergeHistoryStore.push(...storeSnapshot.mergeHistory);
        throw e;
      }
    };
    const failingRepo = createPatientRepository(failingDb);

    await expect(
      failingRepo.executeMerge(PHYSICIAN_1, surviving.patientId, merged.patientId, USER_1),
    ).rejects.toThrow('Simulated DB failure');

    // Verify rollback: merged patient still active, no merge history
    const mergedInStore = patientStore.find((p) => p.patientId === merged.patientId);
    expect(mergedInStore!.isActive).toBe(true);
    expect(mergeHistoryStore).toHaveLength(0);

    // Claims should not have been transferred (rolled back)
    const claim = claimsStore.find((c) => c.patientId === merged.patientId);
    expect(claim).toBeDefined();
  });

  it('executeMerge returns null if either patient belongs to different physician', async () => {
    const surviving = await repo.createPatient(
      makePatientData({ phn: '111111111', firstName: 'Alice' }) as any,
    );
    const merged = await repo.createPatient(
      makePatientData({
        providerId: PHYSICIAN_2,
        phn: '222222222',
        firstName: 'Bob',
      }) as any,
    );

    const result = await repo.executeMerge(
      PHYSICIAN_1,
      surviving.patientId,
      merged.patientId,
      USER_1,
    );

    expect(result).toBeNull();
  });

  // -------------------------------------------------------------------------
  // listMergeHistory
  // -------------------------------------------------------------------------

  it('listMergeHistory returns newest first for physician', async () => {
    const date1 = new Date('2026-01-01T00:00:00Z');
    const date2 = new Date('2026-02-01T00:00:00Z');
    const date3 = new Date('2026-03-01T00:00:00Z');

    mergeHistoryStore.push(
      {
        mergeId: crypto.randomUUID(),
        physicianId: PHYSICIAN_1,
        survivingPatientId: crypto.randomUUID(),
        mergedPatientId: crypto.randomUUID(),
        claimsTransferred: 2,
        fieldConflicts: null,
        mergedAt: date1,
        mergedBy: USER_1,
      },
      {
        mergeId: crypto.randomUUID(),
        physicianId: PHYSICIAN_1,
        survivingPatientId: crypto.randomUUID(),
        mergedPatientId: crypto.randomUUID(),
        claimsTransferred: 5,
        fieldConflicts: null,
        mergedAt: date3,
        mergedBy: USER_1,
      },
      {
        mergeId: crypto.randomUUID(),
        physicianId: PHYSICIAN_1,
        survivingPatientId: crypto.randomUUID(),
        mergedPatientId: crypto.randomUUID(),
        claimsTransferred: 1,
        fieldConflicts: null,
        mergedAt: date2,
        mergedBy: USER_1,
      },
    );

    const result = await repo.listMergeHistory(PHYSICIAN_1, 1, 10);

    expect(result.data).toHaveLength(3);
    expect(result.data[0].claimsTransferred).toBe(5);   // date3 (newest)
    expect(result.data[1].claimsTransferred).toBe(1);   // date2
    expect(result.data[2].claimsTransferred).toBe(2);   // date1 (oldest)
    expect(result.pagination.total).toBe(3);
    expect(result.pagination.page).toBe(1);
    expect(result.pagination.pageSize).toBe(10);
    expect(result.pagination.hasMore).toBe(false);
  });

  it('listMergeHistory excludes other physician\'s history', async () => {
    mergeHistoryStore.push(
      {
        mergeId: crypto.randomUUID(),
        physicianId: PHYSICIAN_1,
        survivingPatientId: crypto.randomUUID(),
        mergedPatientId: crypto.randomUUID(),
        claimsTransferred: 2,
        fieldConflicts: null,
        mergedAt: new Date(),
        mergedBy: USER_1,
      },
      {
        mergeId: crypto.randomUUID(),
        physicianId: PHYSICIAN_2,
        survivingPatientId: crypto.randomUUID(),
        mergedPatientId: crypto.randomUUID(),
        claimsTransferred: 3,
        fieldConflicts: null,
        mergedAt: new Date(),
        mergedBy: USER_1,
      },
    );

    const result = await repo.listMergeHistory(PHYSICIAN_1, 1, 10);

    expect(result.data).toHaveLength(1);
    expect(result.data[0].physicianId).toBe(PHYSICIAN_1);
  });

  it('listMergeHistory paginates results', async () => {
    for (let i = 0; i < 5; i++) {
      mergeHistoryStore.push({
        mergeId: crypto.randomUUID(),
        physicianId: PHYSICIAN_1,
        survivingPatientId: crypto.randomUUID(),
        mergedPatientId: crypto.randomUUID(),
        claimsTransferred: i,
        fieldConflicts: null,
        mergedAt: new Date(),
        mergedBy: USER_1,
      });
    }

    const page1 = await repo.listMergeHistory(PHYSICIAN_1, 1, 2);
    expect(page1.data).toHaveLength(2);
    expect(page1.pagination.total).toBe(5);
    expect(page1.pagination.hasMore).toBe(true);

    const page3 = await repo.listMergeHistory(PHYSICIAN_1, 3, 2);
    expect(page3.data).toHaveLength(1);
    expect(page3.pagination.hasMore).toBe(false);
  });

  // =========================================================================
  // Export Operations
  // =========================================================================

  // -------------------------------------------------------------------------
  // exportActivePatients
  // -------------------------------------------------------------------------

  it('exportActivePatients returns all active patients without notes', async () => {
    await repo.createPatient(
      makePatientData({
        phn: '111111111',
        firstName: 'Alice',
        lastName: 'Smith',
        phone: '403-555-1111',
        city: 'Calgary',
        notes: 'Private clinical observation about Alice',
      }) as any,
    );
    await repo.createPatient(
      makePatientData({
        phn: '222222222',
        firstName: 'Bob',
        lastName: 'Jones',
        phone: '403-555-2222',
        city: 'Edmonton',
        notes: 'Private clinical observation about Bob',
      }) as any,
    );

    const rows = await repo.exportActivePatients(PHYSICIAN_1);

    expect(rows).toHaveLength(2);
    for (const row of rows) {
      expect(row).toHaveProperty('phn');
      expect(row).toHaveProperty('firstName');
      expect(row).toHaveProperty('lastName');
      expect(row).toHaveProperty('dateOfBirth');
      expect(row).toHaveProperty('gender');
      expect(row).toHaveProperty('phone');
      expect(row).toHaveProperty('addressLine1');
      expect(row).toHaveProperty('addressLine2');
      expect(row).toHaveProperty('city');
      expect(row).toHaveProperty('province');
      expect(row).toHaveProperty('postalCode');
      // Notes must NOT be present in export
      expect(row).not.toHaveProperty('notes');
      // Provider ID must NOT be present in export
      expect(row).not.toHaveProperty('providerId');
      expect(row).not.toHaveProperty('patientId');
    }
  });

  it('exportActivePatients excludes inactive patients', async () => {
    await repo.createPatient(
      makePatientData({
        phn: '111111111',
        firstName: 'Alice',
        isActive: true,
      }) as any,
    );
    await repo.createPatient(
      makePatientData({
        phn: '222222222',
        firstName: 'Bob',
        isActive: false,
      }) as any,
    );

    const rows = await repo.exportActivePatients(PHYSICIAN_1);

    expect(rows).toHaveLength(1);
    expect(rows[0].firstName).toBe('Alice');
  });

  it('exportActivePatients scoped to physician', async () => {
    await repo.createPatient(
      makePatientData({ phn: '111111111', firstName: 'Alice' }) as any,
    );
    await repo.createPatient(
      makePatientData({
        providerId: PHYSICIAN_2,
        phn: '222222222',
        firstName: 'Bob',
      }) as any,
    );

    const rows = await repo.exportActivePatients(PHYSICIAN_1);

    expect(rows).toHaveLength(1);
    expect(rows[0].firstName).toBe('Alice');
  });

  // -------------------------------------------------------------------------
  // countActivePatients
  // -------------------------------------------------------------------------

  it('countActivePatients returns correct count', async () => {
    await repo.createPatient(
      makePatientData({ phn: '111111111', firstName: 'Alice' }) as any,
    );
    await repo.createPatient(
      makePatientData({ phn: '222222222', firstName: 'Bob' }) as any,
    );
    await repo.createPatient(
      makePatientData({ phn: '333333333', firstName: 'Charlie', isActive: false }) as any,
    );
    // Different physician
    await repo.createPatient(
      makePatientData({ providerId: PHYSICIAN_2, phn: '444444444', firstName: 'Dave' }) as any,
    );

    const count = await repo.countActivePatients(PHYSICIAN_1);

    expect(count).toBe(2);
  });

  // =========================================================================
  // Internal API (consumed by Domain 4)
  // =========================================================================

  // -------------------------------------------------------------------------
  // getPatientClaimContext
  // -------------------------------------------------------------------------

  it('getPatientClaimContext returns minimal claim fields', async () => {
    const created = await repo.createPatient(
      makePatientData({
        phn: '111111111',
        firstName: 'Alice',
        lastName: 'Smith',
        dateOfBirth: '1985-03-15',
        gender: 'F',
        phone: '403-555-1111',
        addressLine1: '123 Main St',
        city: 'Calgary',
        notes: 'Secret clinical observation',
      }) as any,
    );

    const ctx = await repo.getPatientClaimContext(created.patientId, PHYSICIAN_1);

    expect(ctx).not.toBeNull();
    expect(ctx!.patientId).toBe(created.patientId);
    expect(ctx!.phn).toBe('111111111');
    expect(ctx!.phnProvince).toBe('AB');
    expect(ctx!.firstName).toBe('Alice');
    expect(ctx!.lastName).toBe('Smith');
    expect(ctx!.dateOfBirth).toBe('1985-03-15');
    expect(ctx!.gender).toBe('F');
    // Must NOT include non-claim fields
    expect(ctx).not.toHaveProperty('notes');
    expect(ctx).not.toHaveProperty('phone');
    expect(ctx).not.toHaveProperty('addressLine1');
    expect(ctx).not.toHaveProperty('city');
  });

  it('getPatientClaimContext returns null for different physician\'s patient', async () => {
    const created = await repo.createPatient(
      makePatientData({
        providerId: PHYSICIAN_2,
        phn: '111111111',
        firstName: 'Alice',
      }) as any,
    );

    const ctx = await repo.getPatientClaimContext(created.patientId, PHYSICIAN_1);

    expect(ctx).toBeNull();
  });

  it('getPatientClaimContext returns null for inactive patient', async () => {
    const created = await repo.createPatient(
      makePatientData({
        phn: '111111111',
        firstName: 'Alice',
        isActive: false,
      }) as any,
    );

    const ctx = await repo.getPatientClaimContext(created.patientId, PHYSICIAN_1);

    expect(ctx).toBeNull();
  });

  // -------------------------------------------------------------------------
  // validatePhnExists
  // -------------------------------------------------------------------------

  it('validatePhnExists returns valid and exists for known PHN', async () => {
    // Use a PHN that passes Luhn: 123456782
    await repo.createPatient(
      makePatientData({ phn: '123456782', firstName: 'Alice' }) as any,
    );

    const result = await repo.validatePhnExists(PHYSICIAN_1, '123456782');

    expect(result.valid).toBe(true);
    expect(result.exists).toBe(true);
    expect(result.patientId).toBeDefined();
  });

  it('validatePhnExists returns valid but not exists for unknown PHN', async () => {
    // PHN 123456782 passes Luhn but no patient has it
    const result = await repo.validatePhnExists(PHYSICIAN_1, '123456782');

    expect(result.valid).toBe(true);
    expect(result.exists).toBe(false);
    expect(result.patientId).toBeUndefined();
  });

  it('validatePhnExists returns invalid for bad Luhn check', async () => {
    // PHN 123456789 fails Luhn
    const result = await repo.validatePhnExists(PHYSICIAN_1, '123456789');

    expect(result.valid).toBe(false);
    expect(result.exists).toBe(false);
    expect(result.patientId).toBeUndefined();
  });

  it('validatePhnExists is scoped to physician', async () => {
    // Create patient for PHYSICIAN_2 with valid Luhn PHN
    await repo.createPatient(
      makePatientData({
        providerId: PHYSICIAN_2,
        phn: '123456782',
        firstName: 'Bob',
      }) as any,
    );

    // PHYSICIAN_1 should not see PHYSICIAN_2's patient
    const result = await repo.validatePhnExists(PHYSICIAN_1, '123456782');

    expect(result.valid).toBe(true);
    expect(result.exists).toBe(false);
    expect(result.patientId).toBeUndefined();
  });

  it('validatePhnExists excludes inactive patients', async () => {
    await repo.createPatient(
      makePatientData({
        phn: '123456782',
        firstName: 'Alice',
        isActive: false,
      }) as any,
    );

    const result = await repo.validatePhnExists(PHYSICIAN_1, '123456782');

    expect(result.valid).toBe(true);
    expect(result.exists).toBe(false);
  });
});

// ===========================================================================
// Patient Service Tests
// ===========================================================================

describe('Patient Service', () => {
  let repo: ReturnType<typeof createPatientRepository>;
  let auditRepo: { appendAuditLog: ReturnType<typeof vi.fn> };
  let events: { emit: ReturnType<typeof vi.fn> };
  let deps: PatientServiceDeps;

  beforeEach(() => {
    patientStore = [];
    importBatchStore = [];
    mergeHistoryStore = [];
    claimsStore = [];
    repo = createPatientRepository(makeMockDb());
    auditRepo = { appendAuditLog: vi.fn().mockResolvedValue(undefined) };
    events = { emit: vi.fn() };
    deps = { repo, auditRepo, events };
  });

  // A valid Alberta PHN that passes Luhn: 123456782
  const VALID_AB_PHN = '123456782';
  // An Alberta PHN with invalid Luhn check digit
  const INVALID_LUHN_PHN = '123456789';

  function makeServiceInput(overrides?: Record<string, unknown>) {
    return {
      firstName: 'Jane',
      lastName: 'Smith',
      dateOfBirth: '1985-03-15',
      gender: 'F',
      ...overrides,
    };
  }

  // =========================================================================
  // createPatient
  // =========================================================================

  it('createPatient with valid Alberta PHN succeeds', async () => {
    const input = makeServiceInput({ phn: VALID_AB_PHN });
    const result = await createPatient(deps, PHYSICIAN_1, input as any, USER_1);

    expect(result.patientId).toBeDefined();
    expect(result.phn).toBe(VALID_AB_PHN);
    expect(result.firstName).toBe('Jane');
    expect(result.providerId).toBe(PHYSICIAN_1);
  });

  it('createPatient rejects invalid Luhn check digit', async () => {
    const input = makeServiceInput({ phn: INVALID_LUHN_PHN });

    await expect(
      createPatient(deps, PHYSICIAN_1, input as any, USER_1),
    ).rejects.toThrow('Luhn');
  });

  it('createPatient rejects 8-digit PHN', async () => {
    const input = makeServiceInput({ phn: '12345678' });

    await expect(
      createPatient(deps, PHYSICIAN_1, input as any, USER_1),
    ).rejects.toThrow('9 digits');
  });

  it('createPatient rejects non-numeric PHN', async () => {
    const input = makeServiceInput({ phn: '12345678A' });

    await expect(
      createPatient(deps, PHYSICIAN_1, input as any, USER_1),
    ).rejects.toThrow('9 digits');
  });

  it('createPatient rejects duplicate PHN for same physician', async () => {
    const input1 = makeServiceInput({ phn: VALID_AB_PHN });
    await createPatient(deps, PHYSICIAN_1, input1 as any, USER_1);

    const input2 = makeServiceInput({ phn: VALID_AB_PHN, firstName: 'John' });
    await expect(
      createPatient(deps, PHYSICIAN_1, input2 as any, USER_1),
    ).rejects.toThrow('already exists');
  });

  it('createPatient allows same PHN for different physicians', async () => {
    const input1 = makeServiceInput({ phn: VALID_AB_PHN });
    await createPatient(deps, PHYSICIAN_1, input1 as any, USER_1);

    const input2 = makeServiceInput({ phn: VALID_AB_PHN, firstName: 'John' });
    const result = await createPatient(deps, PHYSICIAN_2, input2 as any, USER_1);

    expect(result.phn).toBe(VALID_AB_PHN);
    expect(result.providerId).toBe(PHYSICIAN_2);
  });

  it('createPatient allows null PHN', async () => {
    const input = makeServiceInput({ phn: null });
    const result = await createPatient(deps, PHYSICIAN_1, input as any, USER_1);

    expect(result.phn).toBeNull();
    expect(result.patientId).toBeDefined();
  });

  it('createPatient with out-of-province PHN skips Luhn check', async () => {
    // 10-digit PHN with non-AB province — would fail Luhn check if AB
    const input = makeServiceInput({ phn: '1234567890', phnProvince: 'ON' });
    const result = await createPatient(deps, PHYSICIAN_1, input as any, USER_1);

    expect(result.phn).toBe('1234567890');
    expect(result.phnProvince).toBe('ON');
  });

  it('createPatient emits audit event with masked PHN', async () => {
    const input = makeServiceInput({ phn: VALID_AB_PHN });
    await createPatient(deps, PHYSICIAN_1, input as any, USER_1);

    expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(1);
    const auditCall = auditRepo.appendAuditLog.mock.calls[0][0];
    expect(auditCall.action).toBe('patient.created');
    expect(auditCall.detail.phn).toBe('123******');
    expect(auditCall.detail.source).toBe('MANUAL');
    // Should not contain raw PHN
    expect(JSON.stringify(auditCall)).not.toContain(VALID_AB_PHN);
  });

  // =========================================================================
  // getPatient
  // =========================================================================

  it('getPatient returns patient for correct physician', async () => {
    const input = makeServiceInput({ phn: VALID_AB_PHN });
    const created = await createPatient(deps, PHYSICIAN_1, input as any, USER_1);

    const result = await getPatient(deps, created.patientId, PHYSICIAN_1);

    expect(result).not.toBeNull();
    expect(result!.patientId).toBe(created.patientId);
  });

  it('getPatient returns null for wrong physician', async () => {
    const input = makeServiceInput({ phn: VALID_AB_PHN });
    const created = await createPatient(deps, PHYSICIAN_1, input as any, USER_1);

    const result = await getPatient(deps, created.patientId, PHYSICIAN_2);

    expect(result).toBeNull();
  });

  // =========================================================================
  // updatePatient
  // =========================================================================

  it('updatePatient re-validates PHN on change', async () => {
    const input = makeServiceInput({ phn: VALID_AB_PHN });
    const created = await createPatient(deps, PHYSICIAN_1, input as any, USER_1);

    // Try to change PHN to an invalid one
    await expect(
      updatePatient(
        deps,
        created.patientId,
        PHYSICIAN_1,
        { phn: INVALID_LUHN_PHN } as any,
        USER_1,
      ),
    ).rejects.toThrow('Luhn');
  });

  it('updatePatient emits audit with field-level diff', async () => {
    const input = makeServiceInput({ phn: VALID_AB_PHN });
    const created = await createPatient(deps, PHYSICIAN_1, input as any, USER_1);
    auditRepo.appendAuditLog.mockClear();

    await updatePatient(
      deps,
      created.patientId,
      PHYSICIAN_1,
      { firstName: 'Janet', phone: '403-555-0000' } as any,
      USER_1,
    );

    expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(1);
    const auditCall = auditRepo.appendAuditLog.mock.calls[0][0];
    expect(auditCall.action).toBe('patient.updated');
    expect(auditCall.detail.changes).toHaveProperty('firstName');
    expect(auditCall.detail.changes.firstName).toEqual({
      old: 'Jane',
      new: 'Janet',
    });
    expect(auditCall.detail.changes).toHaveProperty('phone');
  });

  it('updatePatient masks PHN in audit diff', async () => {
    const input = makeServiceInput({ phn: VALID_AB_PHN });
    const created = await createPatient(deps, PHYSICIAN_1, input as any, USER_1);
    auditRepo.appendAuditLog.mockClear();

    // Change PHN to a different valid one: 000000018 (passes Luhn)
    const newPhn = '000000018';
    await updatePatient(
      deps,
      created.patientId,
      PHYSICIAN_1,
      { phn: newPhn } as any,
      USER_1,
    );

    const auditCall = auditRepo.appendAuditLog.mock.calls[0][0];
    expect(auditCall.detail.changes.phn.old).toBe('123******');
    expect(auditCall.detail.changes.phn.new).toBe('000******');
    // Raw PHNs should not appear in audit
    expect(JSON.stringify(auditCall)).not.toContain(VALID_AB_PHN);
    expect(JSON.stringify(auditCall)).not.toContain(newPhn);
  });

  it('updatePatient excludes notes from audit diff', async () => {
    const input = makeServiceInput({ phn: VALID_AB_PHN, notes: 'old notes' });
    const created = await createPatient(deps, PHYSICIAN_1, input as any, USER_1);
    auditRepo.appendAuditLog.mockClear();

    await updatePatient(
      deps,
      created.patientId,
      PHYSICIAN_1,
      { notes: 'updated clinical notes' } as any,
      USER_1,
    );

    const auditCall = auditRepo.appendAuditLog.mock.calls[0][0];
    expect(auditCall.detail.changes).not.toHaveProperty('notes');
    expect(JSON.stringify(auditCall)).not.toContain('updated clinical notes');
    expect(JSON.stringify(auditCall)).not.toContain('old notes');
  });

  it('updatePatient rejects duplicate PHN for same physician', async () => {
    const input1 = makeServiceInput({ phn: VALID_AB_PHN });
    await createPatient(deps, PHYSICIAN_1, input1 as any, USER_1);

    const newPhn = '000000018';
    const input2 = makeServiceInput({ phn: newPhn, firstName: 'Bob' });
    const patient2 = await createPatient(deps, PHYSICIAN_1, input2 as any, USER_1);

    // Try to change patient2's PHN to match patient1's
    await expect(
      updatePatient(
        deps,
        patient2.patientId,
        PHYSICIAN_1,
        { phn: VALID_AB_PHN } as any,
        USER_1,
      ),
    ).rejects.toThrow('already exists');
  });

  it('updatePatient throws NotFoundError for wrong physician', async () => {
    const input = makeServiceInput({ phn: VALID_AB_PHN });
    const created = await createPatient(deps, PHYSICIAN_1, input as any, USER_1);

    await expect(
      updatePatient(
        deps,
        created.patientId,
        PHYSICIAN_2,
        { firstName: 'Hacker' } as any,
        USER_1,
      ),
    ).rejects.toThrow('not found');
  });

  // =========================================================================
  // deactivatePatient
  // =========================================================================

  it('deactivatePatient soft-deletes patient', async () => {
    const input = makeServiceInput({ phn: VALID_AB_PHN });
    const created = await createPatient(deps, PHYSICIAN_1, input as any, USER_1);

    const result = await deactivatePatient(deps, created.patientId, PHYSICIAN_1, USER_1);

    expect(result.isActive).toBe(false);
  });

  it('deactivatePatient emits audit event', async () => {
    const input = makeServiceInput({ phn: VALID_AB_PHN });
    const created = await createPatient(deps, PHYSICIAN_1, input as any, USER_1);
    auditRepo.appendAuditLog.mockClear();

    await deactivatePatient(deps, created.patientId, PHYSICIAN_1, USER_1);

    expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(1);
    const auditCall = auditRepo.appendAuditLog.mock.calls[0][0];
    expect(auditCall.action).toBe('patient.deactivated');
    expect(auditCall.detail.phn).toBe('123******');
  });

  it('deactivatePatient throws NotFoundError for wrong physician', async () => {
    const input = makeServiceInput({ phn: VALID_AB_PHN });
    const created = await createPatient(deps, PHYSICIAN_1, input as any, USER_1);

    await expect(
      deactivatePatient(deps, created.patientId, PHYSICIAN_2, USER_1),
    ).rejects.toThrow('not found');
  });

  // =========================================================================
  // reactivatePatient
  // =========================================================================

  it('reactivatePatient restores patient', async () => {
    const input = makeServiceInput({ phn: VALID_AB_PHN });
    const created = await createPatient(deps, PHYSICIAN_1, input as any, USER_1);
    await deactivatePatient(deps, created.patientId, PHYSICIAN_1, USER_1);

    const result = await reactivatePatient(deps, created.patientId, PHYSICIAN_1, USER_1);

    expect(result.isActive).toBe(true);
  });

  it('reactivatePatient emits audit event', async () => {
    const input = makeServiceInput({ phn: VALID_AB_PHN });
    const created = await createPatient(deps, PHYSICIAN_1, input as any, USER_1);
    await deactivatePatient(deps, created.patientId, PHYSICIAN_1, USER_1);
    auditRepo.appendAuditLog.mockClear();

    await reactivatePatient(deps, created.patientId, PHYSICIAN_1, USER_1);

    expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(1);
    const auditCall = auditRepo.appendAuditLog.mock.calls[0][0];
    expect(auditCall.action).toBe('patient.reactivated');
    expect(auditCall.detail.phn).toBe('123******');
  });

  it('reactivatePatient throws NotFoundError for wrong physician', async () => {
    const input = makeServiceInput({ phn: VALID_AB_PHN });
    const created = await createPatient(deps, PHYSICIAN_1, input as any, USER_1);
    await deactivatePatient(deps, created.patientId, PHYSICIAN_1, USER_1);

    await expect(
      reactivatePatient(deps, created.patientId, PHYSICIAN_2, USER_1),
    ).rejects.toThrow('not found');
  });

  // =========================================================================
  // searchPatients
  // =========================================================================

  it('searchPatients routes to PHN lookup when phn provided', async () => {
    const input = makeServiceInput({ phn: VALID_AB_PHN });
    await createPatient(deps, PHYSICIAN_1, input as any, USER_1);
    auditRepo.appendAuditLog.mockClear();

    const query: PatientSearchInput = {
      phn: VALID_AB_PHN,
      page: 1,
      pageSize: 20,
    };
    const result = await searchPatients(deps, PHYSICIAN_1, query, USER_1);

    expect(result.patients).toHaveLength(1);
    expect(result.patients[0].phn).toBe(VALID_AB_PHN);
    expect(result.total).toBe(1);
    expect(result.page).toBe(1);
    expect(result.page_size).toBe(20);
  });

  it('searchPatients routes to name search when name provided', async () => {
    await createPatient(
      deps,
      PHYSICIAN_1,
      makeServiceInput({ phn: VALID_AB_PHN, firstName: 'Alice', lastName: 'Johnson' }) as any,
      USER_1,
    );
    await createPatient(
      deps,
      PHYSICIAN_1,
      makeServiceInput({ firstName: 'Bob', lastName: 'Jones' }) as any,
      USER_1,
    );
    auditRepo.appendAuditLog.mockClear();

    const query: PatientSearchInput = {
      name: 'Jo',
      page: 1,
      pageSize: 20,
    };
    const result = await searchPatients(deps, PHYSICIAN_1, query, USER_1);

    expect(result.patients.length).toBe(2);
    expect(result.total).toBe(2);
  });

  it('searchPatients routes to DOB search when dob provided', async () => {
    await createPatient(
      deps,
      PHYSICIAN_1,
      makeServiceInput({ phn: VALID_AB_PHN, dateOfBirth: '1985-03-15' }) as any,
      USER_1,
    );
    await createPatient(
      deps,
      PHYSICIAN_1,
      makeServiceInput({ dateOfBirth: '1990-06-20' }) as any,
      USER_1,
    );
    auditRepo.appendAuditLog.mockClear();

    const query: PatientSearchInput = {
      dob: '1985-03-15',
      page: 1,
      pageSize: 20,
    };
    const result = await searchPatients(deps, PHYSICIAN_1, query, USER_1);

    expect(result.patients.length).toBe(1);
    expect(result.patients[0].dateOfBirth).toBe('1985-03-15');
    expect(result.total).toBe(1);
  });

  it('searchPatients combines criteria with AND logic', async () => {
    await createPatient(
      deps,
      PHYSICIAN_1,
      makeServiceInput({
        phn: VALID_AB_PHN,
        firstName: 'Alice',
        lastName: 'Johnson',
        dateOfBirth: '1985-03-15',
      }) as any,
      USER_1,
    );
    await createPatient(
      deps,
      PHYSICIAN_1,
      makeServiceInput({
        firstName: 'Bob',
        lastName: 'Johnson',
        dateOfBirth: '1990-06-20',
      }) as any,
      USER_1,
    );
    auditRepo.appendAuditLog.mockClear();

    const query: PatientSearchInput = {
      name: 'Johnson',
      dob: '1985-03-15',
      page: 1,
      pageSize: 20,
    };
    const result = await searchPatients(deps, PHYSICIAN_1, query, USER_1);

    // Only Alice matches both criteria
    expect(result.patients.length).toBe(1);
    expect(result.patients[0].firstName).toBe('Alice');
    expect(result.total).toBe(1);
  });

  it('searchPatients returns paginated results with total count', async () => {
    // Create 3 patients all matching "Sm"
    await createPatient(
      deps,
      PHYSICIAN_1,
      makeServiceInput({ phn: '111111118', firstName: 'A', lastName: 'Smith' }) as any,
      USER_1,
    );
    await createPatient(
      deps,
      PHYSICIAN_1,
      makeServiceInput({ phn: '000000018', firstName: 'B', lastName: 'Smith' }) as any,
      USER_1,
    );
    await createPatient(
      deps,
      PHYSICIAN_1,
      makeServiceInput({ firstName: 'C', lastName: 'Smith' }) as any,
      USER_1,
    );
    auditRepo.appendAuditLog.mockClear();

    const query: PatientSearchInput = {
      name: 'Smith',
      page: 1,
      pageSize: 2,
    };
    const result = await searchPatients(deps, PHYSICIAN_1, query, USER_1);

    expect(result.patients.length).toBe(2);
    expect(result.total).toBe(3);
    expect(result.page).toBe(1);
    expect(result.page_size).toBe(2);
  });

  it('searchPatients emits audit event with search parameters', async () => {
    await createPatient(
      deps,
      PHYSICIAN_1,
      makeServiceInput({ phn: VALID_AB_PHN }) as any,
      USER_1,
    );
    auditRepo.appendAuditLog.mockClear();

    const query: PatientSearchInput = {
      phn: VALID_AB_PHN,
      name: 'Smith',
      page: 1,
      pageSize: 20,
    };
    await searchPatients(deps, PHYSICIAN_1, query, USER_1);

    expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(1);
    const auditCall = auditRepo.appendAuditLog.mock.calls[0][0];
    expect(auditCall.action).toBe('patient.searched');
    expect(auditCall.category).toBe('patient');
    expect(auditCall.detail.mode).toBe('COMBINED');
    // PHN must be masked in audit
    expect(auditCall.detail.phn).toBe('123******');
    expect(auditCall.detail.name).toBe('Smith');
    expect(auditCall.detail).toHaveProperty('resultCount');
    // Raw PHN should not appear in audit
    expect(JSON.stringify(auditCall)).not.toContain(VALID_AB_PHN);
  });

  // =========================================================================
  // getRecentPatients
  // =========================================================================

  it('getRecentPatients returns ordered list', async () => {
    const p1 = await createPatient(
      deps,
      PHYSICIAN_1,
      makeServiceInput({ phn: '111111118', firstName: 'Alice' }) as any,
      USER_1,
    );
    const p2 = await createPatient(
      deps,
      PHYSICIAN_1,
      makeServiceInput({ phn: '000000018', firstName: 'Bob' }) as any,
      USER_1,
    );

    // Set last visit dates via repo directly
    await deps.repo.updateLastVisitDate(p1.patientId, PHYSICIAN_1, new Date('2026-01-10'));
    await deps.repo.updateLastVisitDate(p2.patientId, PHYSICIAN_1, new Date('2026-02-15'));

    const result = await getRecentPatients(deps, PHYSICIAN_1, 20);

    expect(result.length).toBe(2);
    expect(result[0].firstName).toBe('Bob');   // 2026-02-15 — most recent
    expect(result[1].firstName).toBe('Alice'); // 2026-01-10
  });

  it('getRecentPatients does not emit audit event', async () => {
    const p1 = await createPatient(
      deps,
      PHYSICIAN_1,
      makeServiceInput({ phn: VALID_AB_PHN }) as any,
      USER_1,
    );
    await deps.repo.updateLastVisitDate(p1.patientId, PHYSICIAN_1, new Date('2026-01-10'));
    auditRepo.appendAuditLog.mockClear();

    await getRecentPatients(deps, PHYSICIAN_1, 20);

    expect(auditRepo.appendAuditLog).not.toHaveBeenCalled();
  });

  // =========================================================================
  // CSV Bulk Import Workflow
  // =========================================================================

  // Helper to build a CSV Buffer from lines
  function makeCsvBuffer(lines: string[]): Buffer {
    return Buffer.from(lines.join('\n'), 'utf-8');
  }

  // A valid Alberta PHN that passes Luhn check
  // 123456782 is used in other tests; let's use a second valid one for import: 000000018
  const IMPORT_VALID_PHN_1 = '123456782';
  const IMPORT_VALID_PHN_2 = '000000018';
  // Invalid Luhn
  const IMPORT_INVALID_PHN = '123456789';

  // ----- initiateImport -----

  it('initiateImport parses comma-delimited CSV with headers', async () => {
    const csv = makeCsvBuffer([
      'FirstName,LastName,DOB,Gender,PHN',
      'Jane,Smith,1985-03-15,F,123456782',
      'John,Doe,1990-07-20,M,000000018',
    ]);

    const result = await initiateImport(deps, PHYSICIAN_1, csv, 'patients.csv', USER_1);

    expect(result.importId).toBeDefined();
    expect(importBatchStore).toHaveLength(1);
    expect(importBatchStore[0].fileName).toBe('patients.csv');
    expect(importBatchStore[0].totalRows).toBe(2);
    expect(importBatchStore[0].status).toBe('PENDING');

    // Verify parsed rows cache
    const cached = _parsedRowsCache.get(result.importId);
    expect(cached).toBeDefined();
    expect(cached!.delimiter).toBe(',');
    expect(cached!.headers).toEqual(['FirstName', 'LastName', 'DOB', 'Gender', 'PHN']);
    expect(cached!.rows).toHaveLength(2);
  });

  it('initiateImport parses tab-delimited CSV without headers', async () => {
    const csv = makeCsvBuffer([
      'Jane\tSmith\t1985-03-15\tF\t123456782',
      'John\tDoe\t1990-07-20\tM\t000000018',
    ]);

    const result = await initiateImport(deps, PHYSICIAN_1, csv, 'patients.tsv', USER_1);

    expect(result.importId).toBeDefined();
    const cached = _parsedRowsCache.get(result.importId);
    expect(cached).toBeDefined();
    expect(cached!.delimiter).toBe('\t');
    // No recognized headers → generated column names
    expect(cached!.headers[0]).toMatch(/^column_/);
    // All rows are data (no header skipped)
    expect(cached!.rows).toHaveLength(2);
  });

  it('initiateImport detects duplicate file upload by hash', async () => {
    const csv = makeCsvBuffer([
      'FirstName,LastName,DOB,Gender',
      'Jane,Smith,1985-03-15,F',
    ]);

    await initiateImport(deps, PHYSICIAN_1, csv, 'patients.csv', USER_1);

    // Same file again → conflict
    await expect(
      initiateImport(deps, PHYSICIAN_1, csv, 'patients_copy.csv', USER_1),
    ).rejects.toThrow('already been imported');
  });

  // ----- getImportPreview -----

  it('getImportPreview returns auto-mapped columns', async () => {
    const csv = makeCsvBuffer([
      'FirstName,LastName,DOB,Gender,PHN,Phone,Address,City,PostalCode',
      'Jane,Smith,1985-03-15,F,123456782,403-555-0000,123 Main St,Calgary,T2P1J9',
    ]);

    const { importId } = await initiateImport(deps, PHYSICIAN_1, csv, 'test.csv', USER_1);
    const preview = await getImportPreview(deps, importId, PHYSICIAN_1);

    expect(preview.delimiter).toBe(',');
    expect(preview.mapping.first_name).toBe('FirstName');
    expect(preview.mapping.last_name).toBe('LastName');
    expect(preview.mapping.date_of_birth).toBe('DOB');
    expect(preview.mapping.gender).toBe('Gender');
    expect(preview.mapping.phn).toBe('PHN');
    expect(preview.mapping.phone).toBe('Phone');
    expect(preview.mapping.address_line_1).toBe('Address');
    expect(preview.mapping.city).toBe('City');
    expect(preview.mapping.postal_code).toBe('PostalCode');
    expect(preview.totalRows).toBe(1);
  });

  it('getImportPreview returns first 10 rows with validation warnings', async () => {
    // Build CSV with 12 data rows — preview should show only 10
    const headerLine = 'FirstName,LastName,DOB,Gender,PHN';
    const dataLines: string[] = [];
    for (let i = 0; i < 12; i++) {
      if (i === 0) {
        // Row missing gender → warning
        dataLines.push('Jane,Smith,1985-03-15,,123456782');
      } else if (i === 1) {
        // Row with invalid PHN → warning
        dataLines.push(`John,Doe,1990-07-20,M,${IMPORT_INVALID_PHN}`);
      } else {
        dataLines.push(`Person${i},Last${i},2000-01-0${i % 9 + 1},M,`);
      }
    }

    const csv = makeCsvBuffer([headerLine, ...dataLines]);
    const { importId } = await initiateImport(deps, PHYSICIAN_1, csv, 'big.csv', USER_1);
    const preview = await getImportPreview(deps, importId, PHYSICIAN_1);

    expect(preview.previewRows).toHaveLength(10);
    expect(preview.totalRows).toBe(12);

    // First row should have a warning about missing gender
    expect(preview.previewRows[0].warnings.length).toBeGreaterThan(0);
    expect(preview.previewRows[0].warnings.some((w: string) => w.includes('gender'))).toBe(true);

    // Second row should have warning about invalid PHN
    expect(preview.previewRows[1].warnings.length).toBeGreaterThan(0);
    expect(preview.previewRows[1].warnings.some((w: string) => w.includes('PHN'))).toBe(true);
  });

  // ----- commitImport -----

  it('commitImport creates patients for new rows', async () => {
    const csv = makeCsvBuffer([
      'FirstName,LastName,DOB,Gender,PHN',
      'Jane,Smith,1985-03-15,Female,123456782',
      'John,Doe,1990-07-20,Male,000000018',
    ]);

    const { importId } = await initiateImport(deps, PHYSICIAN_1, csv, 'test.csv', USER_1);
    const result = await commitImport(deps, importId, PHYSICIAN_1, USER_1);

    expect(result.created).toBe(2);
    expect(result.updated).toBe(0);
    expect(result.skipped).toBe(0);
    expect(result.errors).toBe(0);
    expect(result.status).toBe('COMPLETED');

    // Verify patients created in store
    expect(patientStore).toHaveLength(2);
    expect(patientStore[0].firstName).toBe('Jane');
    expect(patientStore[0].gender).toBe('F');  // Gender normalized from "Female" to "F"
    expect(patientStore[1].firstName).toBe('John');
    expect(patientStore[1].gender).toBe('M');  // Gender normalized from "Male" to "M"
  });

  it('commitImport updates existing patients by PHN match', async () => {
    // Pre-create a patient with PHN
    await createPatient(
      deps,
      PHYSICIAN_1,
      makeServiceInput({ phn: IMPORT_VALID_PHN_1, firstName: 'OldName', phone: '403-000-0000' }) as any,
      USER_1,
    );
    expect(patientStore).toHaveLength(1);
    expect(patientStore[0].firstName).toBe('OldName');

    const csv = makeCsvBuffer([
      'FirstName,LastName,DOB,Gender,PHN,Phone',
      `NewName,Smith,1985-03-15,F,${IMPORT_VALID_PHN_1},403-999-9999`,
    ]);

    const { importId } = await initiateImport(deps, PHYSICIAN_1, csv, 'update.csv', USER_1);
    const result = await commitImport(deps, importId, PHYSICIAN_1, USER_1);

    expect(result.created).toBe(0);
    expect(result.updated).toBe(1);

    // Verify patient was updated — not created a second one
    // The original should have been modified
    expect(patientStore[0].firstName).toBe('NewName');
    expect(patientStore[0].phone).toBe('403-999-9999');
  });

  it('commitImport skips duplicate PHN in same file', async () => {
    const csv = makeCsvBuffer([
      'FirstName,LastName,DOB,Gender,PHN',
      `Jane,Smith,1985-03-15,F,${IMPORT_VALID_PHN_1}`,
      `John,Doe,1990-07-20,M,${IMPORT_VALID_PHN_1}`,  // duplicate PHN — skip
    ]);

    const { importId } = await initiateImport(deps, PHYSICIAN_1, csv, 'dup.csv', USER_1);
    const result = await commitImport(deps, importId, PHYSICIAN_1, USER_1);

    expect(result.created).toBe(1);
    expect(result.skipped).toBe(1);
    expect(result.updated).toBe(0);
    expect(result.errors).toBe(0);

    // Only one patient created
    expect(patientStore).toHaveLength(1);
    expect(patientStore[0].firstName).toBe('Jane');
  });

  it('commitImport rejects rows with invalid PHN (bad Luhn)', async () => {
    const csv = makeCsvBuffer([
      'FirstName,LastName,DOB,Gender,PHN',
      `Jane,Smith,1985-03-15,F,${IMPORT_INVALID_PHN}`,
    ]);

    const { importId } = await initiateImport(deps, PHYSICIAN_1, csv, 'bad_phn.csv', USER_1);
    const result = await commitImport(deps, importId, PHYSICIAN_1, USER_1);

    expect(result.errors).toBe(1);
    expect(result.created).toBe(0);
    expect(result.errorDetails).toHaveLength(1);
    expect(result.errorDetails[0].row).toBe(1);
    expect(result.errorDetails[0].field).toBe('phn');
    expect(result.errorDetails[0].message).toContain('Luhn');

    // No patient created
    expect(patientStore).toHaveLength(0);
  });

  it('commitImport rejects rows missing required fields', async () => {
    const csv = makeCsvBuffer([
      'FirstName,LastName,DOB,Gender',
      'Jane,,1985-03-15,F',      // missing last_name
      ',Smith,,M',                 // missing first_name and dob
    ]);

    const { importId } = await initiateImport(deps, PHYSICIAN_1, csv, 'missing.csv', USER_1);
    const result = await commitImport(deps, importId, PHYSICIAN_1, USER_1);

    expect(result.errors).toBe(2);
    expect(result.created).toBe(0);
    expect(result.errorDetails).toHaveLength(2);
    expect(result.errorDetails[0].message).toContain('last_name');
    expect(result.errorDetails[1].message).toContain('first_name');
    expect(result.errorDetails[1].message).toContain('date_of_birth');
  });

  it('commitImport tracks correct created/updated/skipped/error counts', async () => {
    // Pre-create a patient with known PHN
    await createPatient(
      deps,
      PHYSICIAN_1,
      makeServiceInput({ phn: IMPORT_VALID_PHN_1 }) as any,
      USER_1,
    );

    const csv = makeCsvBuffer([
      'FirstName,LastName,DOB,Gender,PHN',
      // Row 1: Update (matches existing PHN)
      `Updated,Smith,1985-03-15,F,${IMPORT_VALID_PHN_1}`,
      // Row 2: Create (new PHN)
      `New,Person,2000-01-01,M,${IMPORT_VALID_PHN_2}`,
      // Row 3: Error (invalid PHN)
      `Bad,Phn,1995-06-15,F,${IMPORT_INVALID_PHN}`,
      // Row 4: Create (no PHN → always creates)
      'NoPhn,Patient,1988-12-25,M,',
      // Row 5: Skip (duplicate PHN of row 2 in same file)
      `Dup,InFile,1999-01-01,F,${IMPORT_VALID_PHN_2}`,
    ]);

    const { importId } = await initiateImport(deps, PHYSICIAN_1, csv, 'mixed.csv', USER_1);
    const result = await commitImport(deps, importId, PHYSICIAN_1, USER_1);

    expect(result.updated).toBe(1);    // Row 1: PHN match → update
    expect(result.created).toBe(2);    // Row 2 + Row 4: new patients
    expect(result.errors).toBe(1);     // Row 3: bad Luhn
    expect(result.skipped).toBe(1);    // Row 5: duplicate PHN in file
    expect(result.status).toBe('COMPLETED');

    // Import batch status should be persisted
    expect(importBatchStore[0].status).toBe('COMPLETED');
    expect(importBatchStore[0].createdCount).toBe(2);
    expect(importBatchStore[0].updatedCount).toBe(1);
    expect(importBatchStore[0].skippedCount).toBe(1);
    expect(importBatchStore[0].errorCount).toBe(1);
  });

  it('commitImport emits audit event with counts', async () => {
    const csv = makeCsvBuffer([
      'FirstName,LastName,DOB,Gender',
      'Jane,Smith,1985-03-15,F',
    ]);

    const { importId } = await initiateImport(deps, PHYSICIAN_1, csv, 'audit.csv', USER_1);
    auditRepo.appendAuditLog.mockClear();
    events.emit.mockClear();

    await commitImport(deps, importId, PHYSICIAN_1, USER_1);

    // Verify audit log
    expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(1);
    const auditCall = auditRepo.appendAuditLog.mock.calls[0][0];
    expect(auditCall.action).toBe('patient.import_completed');
    expect(auditCall.resourceType).toBe('import_batch');
    expect(auditCall.resourceId).toBe(importId);
    expect(auditCall.detail.created).toBe(1);
    expect(auditCall.detail.updated).toBe(0);
    expect(auditCall.detail.skipped).toBe(0);
    expect(auditCall.detail.errors).toBe(0);

    // Verify event emitted
    expect(events.emit).toHaveBeenCalledWith(
      'patient.import_completed',
      expect.objectContaining({
        importId,
        physicianId: PHYSICIAN_1,
        actorId: USER_1,
        created: 1,
      }),
    );
  });

  // ----- getImportStatus -----

  it('getImportStatus returns current status and result counts', async () => {
    const csv = makeCsvBuffer([
      'FirstName,LastName,DOB,Gender',
      'Jane,Smith,1985-03-15,F',
    ]);

    const { importId } = await initiateImport(deps, PHYSICIAN_1, csv, 'status.csv', USER_1);
    await commitImport(deps, importId, PHYSICIAN_1, USER_1);

    const status = await getImportStatus(deps, importId, PHYSICIAN_1);

    expect(status.importId).toBe(importId);
    expect(status.status).toBe('COMPLETED');
    expect(status.created).toBe(1);
    expect(status.updated).toBe(0);
    expect(status.skipped).toBe(0);
    expect(status.errors).toBe(0);
  });

  // ----- updateImportMapping -----

  it('updateImportMapping allows physician to adjust column mapping', async () => {
    const csv = makeCsvBuffer([
      'Name1,Name2,Birth,Sex',
      'Jane,Smith,1985-03-15,F',
    ]);

    const { importId } = await initiateImport(deps, PHYSICIAN_1, csv, 'custom.csv', USER_1);

    // Original mapping may not auto-detect all fields
    const cached = _parsedRowsCache.get(importId);
    expect(cached).toBeDefined();

    // Manually set mapping
    const newMapping = {
      first_name: 'Name1',
      last_name: 'Name2',
      date_of_birth: 'Birth',
      gender: 'Sex',
      phn: null,
      phone: null,
      address_line_1: null,
      city: null,
      postal_code: null,
    };

    await updateImportMapping(deps, importId, PHYSICIAN_1, newMapping);

    // Verify mapping was updated
    expect(cached!.mapping).toEqual(newMapping);

    // Now commit — should work with the custom mapping
    const result = await commitImport(deps, importId, PHYSICIAN_1, USER_1);
    expect(result.created).toBe(1);
    expect(patientStore[0].firstName).toBe('Jane');
    expect(patientStore[0].lastName).toBe('Smith');
  });

  // =========================================================================
  // Patient Merge Workflow (Service Layer)
  // =========================================================================

  const VALID_PHN_A = '123456782';
  const VALID_PHN_B = '000000018';

  function makeMergePatient(overrides?: Record<string, unknown>) {
    return makeServiceInput({
      firstName: 'Alice',
      lastName: 'Johnson',
      dateOfBirth: '1985-03-15',
      gender: 'F',
      phone: '403-555-0001',
      ...overrides,
    });
  }

  // ----- getMergePreview -----

  it('getMergePreview returns side-by-side comparison with field diffs', async () => {
    const surviving = await createPatient(
      deps,
      PHYSICIAN_1,
      makeMergePatient({ phn: VALID_PHN_A, firstName: 'Alice', phone: '403-111-1111' }) as any,
      USER_1,
    );
    const merged = await createPatient(
      deps,
      PHYSICIAN_1,
      makeMergePatient({ phn: VALID_PHN_B, firstName: 'Alicia', phone: '403-222-2222' }) as any,
      USER_1,
    );
    auditRepo.appendAuditLog.mockClear();

    const preview = await getMergePreview(deps, PHYSICIAN_1, surviving.patientId, merged.patientId);

    expect(preview.surviving.patientId).toBe(surviving.patientId);
    expect(preview.merged.patientId).toBe(merged.patientId);
    expect(preview.fieldConflicts).toHaveProperty('firstName');
    expect(preview.fieldConflicts.firstName).toEqual({
      surviving: 'Alice',
      merged: 'Alicia',
    });
    expect(preview.fieldConflicts).toHaveProperty('phn');
    expect(preview.fieldConflicts).toHaveProperty('phone');
  });

  it('getMergePreview returns correct claim count (draft/validated only)', async () => {
    const surviving = await createPatient(
      deps,
      PHYSICIAN_1,
      makeMergePatient({ phn: VALID_PHN_A }) as any,
      USER_1,
    );
    const merged = await createPatient(
      deps,
      PHYSICIAN_1,
      makeMergePatient({ phn: VALID_PHN_B }) as any,
      USER_1,
    );

    // Add claims to the merged patient in the mock claims store
    claimsStore.push(
      { claimId: crypto.randomUUID(), patientId: merged.patientId, providerId: PHYSICIAN_1, status: 'draft' },
      { claimId: crypto.randomUUID(), patientId: merged.patientId, providerId: PHYSICIAN_1, status: 'validated' },
      { claimId: crypto.randomUUID(), patientId: merged.patientId, providerId: PHYSICIAN_1, status: 'submitted' },
    );

    const preview = await getMergePreview(deps, PHYSICIAN_1, surviving.patientId, merged.patientId);

    // Only draft + validated = 2 (not submitted)
    expect(preview.claimsToTransfer).toBe(2);
  });

  it('getMergePreview rejects if patient belongs to different physician', async () => {
    const surviving = await createPatient(
      deps,
      PHYSICIAN_1,
      makeMergePatient({ phn: VALID_PHN_A }) as any,
      USER_1,
    );
    const otherPhysicianPatient = await createPatient(
      deps,
      PHYSICIAN_2,
      makeMergePatient({ phn: VALID_PHN_B }) as any,
      USER_1,
    );

    await expect(
      getMergePreview(deps, PHYSICIAN_1, surviving.patientId, otherPhysicianPatient.patientId),
    ).rejects.toThrow('not found');
  });

  it('getMergePreview rejects if either patient is inactive', async () => {
    const surviving = await createPatient(
      deps,
      PHYSICIAN_1,
      makeMergePatient({ phn: VALID_PHN_A }) as any,
      USER_1,
    );
    const merged = await createPatient(
      deps,
      PHYSICIAN_1,
      makeMergePatient({ phn: VALID_PHN_B }) as any,
      USER_1,
    );

    // Deactivate merged patient
    await deactivatePatient(deps, merged.patientId, PHYSICIAN_1, USER_1);

    await expect(
      getMergePreview(deps, PHYSICIAN_1, surviving.patientId, merged.patientId),
    ).rejects.toThrow('not found');
  });

  // ----- executeMerge -----

  it('executeMerge transfers claims and soft-deletes merged patient', async () => {
    const surviving = await createPatient(
      deps,
      PHYSICIAN_1,
      makeMergePatient({ phn: VALID_PHN_A }) as any,
      USER_1,
    );
    const merged = await createPatient(
      deps,
      PHYSICIAN_1,
      makeMergePatient({ phn: VALID_PHN_B }) as any,
      USER_1,
    );

    // Add draft claims to merged patient
    claimsStore.push(
      { claimId: crypto.randomUUID(), patientId: merged.patientId, providerId: PHYSICIAN_1, status: 'draft' },
      { claimId: crypto.randomUUID(), patientId: merged.patientId, providerId: PHYSICIAN_1, status: 'validated' },
    );

    const result = await executeMerge(deps, PHYSICIAN_1, surviving.patientId, merged.patientId, USER_1);

    expect(result.mergeId).toBeDefined();
    expect(result.claimsTransferred).toBe(2);

    // Claims should now point to surviving patient
    expect(claimsStore.every((c) => c.patientId === surviving.patientId)).toBe(true);

    // Merged patient should be deactivated
    const mergedPatient = patientStore.find((p) => p.patientId === merged.patientId);
    expect(mergedPatient!.isActive).toBe(false);
  });

  it('executeMerge emits audit event with full merge details', async () => {
    const surviving = await createPatient(
      deps,
      PHYSICIAN_1,
      makeMergePatient({ phn: VALID_PHN_A, firstName: 'Alice' }) as any,
      USER_1,
    );
    const merged = await createPatient(
      deps,
      PHYSICIAN_1,
      makeMergePatient({ phn: VALID_PHN_B, firstName: 'Alicia' }) as any,
      USER_1,
    );

    claimsStore.push(
      { claimId: crypto.randomUUID(), patientId: merged.patientId, providerId: PHYSICIAN_1, status: 'draft' },
    );
    auditRepo.appendAuditLog.mockClear();
    events.emit.mockClear();

    const result = await executeMerge(deps, PHYSICIAN_1, surviving.patientId, merged.patientId, USER_1);

    // Audit log
    expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(1);
    const auditCall = auditRepo.appendAuditLog.mock.calls[0][0];
    expect(auditCall.action).toBe('patient.merged');
    expect(auditCall.category).toBe('patient');
    expect(auditCall.resourceType).toBe('patient');
    expect(auditCall.resourceId).toBe(surviving.patientId);
    expect(auditCall.detail.surviving_patient_id).toBe(surviving.patientId);
    expect(auditCall.detail.merged_patient_id).toBe(merged.patientId);
    expect(auditCall.detail.claims_transferred).toBe(1);
    expect(auditCall.detail.field_conflicts).toBeDefined();

    // PHN should be masked in audit
    if (auditCall.detail.field_conflicts.phn) {
      expect(auditCall.detail.field_conflicts.phn.surviving).toBe('123******');
      expect(auditCall.detail.field_conflicts.phn.merged).toBe('000******');
    }

    // Raw PHN should not appear in audit
    expect(JSON.stringify(auditCall)).not.toContain(VALID_PHN_A);
    expect(JSON.stringify(auditCall)).not.toContain(VALID_PHN_B);

    // Event emitted
    expect(events.emit).toHaveBeenCalledWith(
      'patient.merged',
      expect.objectContaining({
        mergeId: result.mergeId,
        physicianId: PHYSICIAN_1,
        actorId: USER_1,
        survivingPatientId: surviving.patientId,
        mergedPatientId: merged.patientId,
        claimsTransferred: 1,
      }),
    );
  });

  it('executeMerge records in merge history', async () => {
    const surviving = await createPatient(
      deps,
      PHYSICIAN_1,
      makeMergePatient({ phn: VALID_PHN_A }) as any,
      USER_1,
    );
    const merged = await createPatient(
      deps,
      PHYSICIAN_1,
      makeMergePatient({ phn: VALID_PHN_B }) as any,
      USER_1,
    );

    await executeMerge(deps, PHYSICIAN_1, surviving.patientId, merged.patientId, USER_1);

    expect(mergeHistoryStore).toHaveLength(1);
    expect(mergeHistoryStore[0].survivingPatientId).toBe(surviving.patientId);
    expect(mergeHistoryStore[0].mergedPatientId).toBe(merged.patientId);
    expect(mergeHistoryStore[0].mergedBy).toBe(USER_1);
    expect(mergeHistoryStore[0].physicianId).toBe(PHYSICIAN_1);
  });

  // ----- getMergeHistory -----

  it('getMergeHistory returns paginated results', async () => {
    // Create and merge two pairs
    const s1 = await createPatient(deps, PHYSICIAN_1, makeMergePatient({ phn: VALID_PHN_A }) as any, USER_1);
    const m1 = await createPatient(deps, PHYSICIAN_1, makeMergePatient({ phn: VALID_PHN_B }) as any, USER_1);
    await executeMerge(deps, PHYSICIAN_1, s1.patientId, m1.patientId, USER_1);

    const s2 = await createPatient(deps, PHYSICIAN_1, makeMergePatient({ phn: '111111118' }) as any, USER_1);
    const m2 = await createPatient(deps, PHYSICIAN_1, makeMergePatient({ phn: '222222226' }) as any, USER_1);
    await executeMerge(deps, PHYSICIAN_1, s2.patientId, m2.patientId, USER_1);

    const result = await getMergeHistory(deps, PHYSICIAN_1, 1, 10);

    expect(result.data).toHaveLength(2);
    expect(result.pagination.total).toBe(2);
    expect(result.pagination.page).toBe(1);
    expect(result.pagination.pageSize).toBe(10);
    expect(result.pagination.hasMore).toBe(false);
  });

  // =========================================================================
  // Patient Export (Service Layer)
  // =========================================================================

  // ----- requestExport -----

  it('requestExport generates CSV without notes field', async () => {
    await createPatient(
      deps,
      PHYSICIAN_1,
      makeServiceInput({
        phn: VALID_AB_PHN,
        firstName: 'Alice',
        lastName: 'Smith',
        phone: '403-555-1111',
        notes: 'Private clinical observation — must NOT appear in export',
      }) as any,
      USER_1,
    );
    await createPatient(
      deps,
      PHYSICIAN_1,
      makeServiceInput({
        firstName: 'Bob',
        lastName: 'Jones',
        phone: '403-555-2222',
        notes: 'Another private note',
      }) as any,
      USER_1,
    );
    auditRepo.appendAuditLog.mockClear();

    const result = await requestExport(deps, PHYSICIAN_1, USER_1);

    expect(result.exportId).toBeDefined();
    expect(result.rowCount).toBe(2);
    expect(result.status).toBe('PROCESSING');

    // Verify CSV content in the export store
    const entry = _exportStore.get(result.exportId);
    expect(entry).toBeDefined();
    expect(entry!.csvContent).toContain('first_name');
    expect(entry!.csvContent).toContain('Alice');
    expect(entry!.csvContent).toContain('Bob');
    // Notes must NOT appear in CSV
    expect(entry!.csvContent).not.toContain('Private clinical observation');
    expect(entry!.csvContent).not.toContain('Another private note');
    expect(entry!.csvContent).not.toContain('notes');
  });

  it('requestExport emits audit event with row count', async () => {
    await createPatient(
      deps,
      PHYSICIAN_1,
      makeServiceInput({ phn: VALID_AB_PHN, firstName: 'Alice' }) as any,
      USER_1,
    );
    await createPatient(
      deps,
      PHYSICIAN_1,
      makeServiceInput({ firstName: 'Bob' }) as any,
      USER_1,
    );
    auditRepo.appendAuditLog.mockClear();
    events.emit.mockClear();

    const result = await requestExport(deps, PHYSICIAN_1, USER_1);

    // Audit log
    expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(1);
    const auditCall = auditRepo.appendAuditLog.mock.calls[0][0];
    expect(auditCall.action).toBe('patient.export_requested');
    expect(auditCall.category).toBe('patient');
    expect(auditCall.resourceType).toBe('patient_export');
    expect(auditCall.resourceId).toBe(result.exportId);
    expect(auditCall.detail.rowCount).toBe(2);

    // Event emitted
    expect(events.emit).toHaveBeenCalledWith(
      'patient.export_requested',
      expect.objectContaining({
        exportId: result.exportId,
        physicianId: PHYSICIAN_1,
        actorId: USER_1,
        rowCount: 2,
      }),
    );
  });

  // ----- getExportStatus -----

  it('getExportStatus returns download URL when ready', async () => {
    await createPatient(
      deps,
      PHYSICIAN_1,
      makeServiceInput({ phn: VALID_AB_PHN, firstName: 'Alice' }) as any,
      USER_1,
    );

    const exportResult = await requestExport(deps, PHYSICIAN_1, USER_1);
    auditRepo.appendAuditLog.mockClear();

    const status = await getExportStatus(deps, exportResult.exportId, PHYSICIAN_1, USER_1);

    expect(status.exportId).toBe(exportResult.exportId);
    expect(status.status).toBe('READY');
    expect(status.rowCount).toBe(1);
    expect(status.downloadUrl).toBeDefined();
    expect(status.downloadUrl).toContain(exportResult.exportId);

    // First access should emit download audit
    expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(1);
    const auditCall = auditRepo.appendAuditLog.mock.calls[0][0];
    expect(auditCall.action).toBe('patient.export_downloaded');
    expect(auditCall.resourceId).toBe(exportResult.exportId);
  });

  it('getExportStatus throws NotFoundError for wrong physician', async () => {
    await createPatient(
      deps,
      PHYSICIAN_1,
      makeServiceInput({ phn: VALID_AB_PHN, firstName: 'Alice' }) as any,
      USER_1,
    );

    const exportResult = await requestExport(deps, PHYSICIAN_1, USER_1);

    await expect(
      getExportStatus(deps, exportResult.exportId, PHYSICIAN_2, USER_1),
    ).rejects.toThrow('not found');
  });

  it('getExportStatus emits download event only on first access', async () => {
    await createPatient(
      deps,
      PHYSICIAN_1,
      makeServiceInput({ phn: VALID_AB_PHN, firstName: 'Alice' }) as any,
      USER_1,
    );

    const exportResult = await requestExport(deps, PHYSICIAN_1, USER_1);
    auditRepo.appendAuditLog.mockClear();
    events.emit.mockClear();

    // First access
    await getExportStatus(deps, exportResult.exportId, PHYSICIAN_1, USER_1);
    expect(auditRepo.appendAuditLog).toHaveBeenCalledTimes(1);
    expect(events.emit).toHaveBeenCalledTimes(1);

    auditRepo.appendAuditLog.mockClear();
    events.emit.mockClear();

    // Second access — no duplicate audit
    await getExportStatus(deps, exportResult.exportId, PHYSICIAN_1, USER_1);
    expect(auditRepo.appendAuditLog).not.toHaveBeenCalled();
    expect(events.emit).not.toHaveBeenCalled();
  });

  // =========================================================================
  // Internal API — Service Layer (consumed by Domain 4)
  // =========================================================================

  // ----- getPatientClaimContext -----

  it('getPatientClaimContext returns minimal claim fields', async () => {
    const created = await createPatient(
      deps,
      PHYSICIAN_1,
      makeServiceInput({
        phn: VALID_AB_PHN,
        firstName: 'Alice',
        lastName: 'Smith',
        dateOfBirth: '1985-03-15',
        gender: 'F',
        phone: '403-555-1111',
        addressLine1: '123 Main St',
        city: 'Calgary',
        notes: 'Secret clinical observation',
      }) as any,
      USER_1,
    );

    const ctx = await getPatientClaimContext(deps, created.patientId, PHYSICIAN_1);

    expect(ctx).not.toBeNull();
    expect(ctx!.patientId).toBe(created.patientId);
    expect(ctx!.phn).toBe(VALID_AB_PHN);
    expect(ctx!.phnProvince).toBe('AB');
    expect(ctx!.firstName).toBe('Alice');
    expect(ctx!.lastName).toBe('Smith');
    expect(ctx!.dateOfBirth).toBe('1985-03-15');
    expect(ctx!.gender).toBe('F');
    // Must NOT include non-claim fields
    expect(ctx).not.toHaveProperty('notes');
    expect(ctx).not.toHaveProperty('phone');
    expect(ctx).not.toHaveProperty('addressLine1');
    expect(ctx).not.toHaveProperty('city');
  });

  it('getPatientClaimContext returns null for wrong physician', async () => {
    const created = await createPatient(
      deps,
      PHYSICIAN_1,
      makeServiceInput({ phn: VALID_AB_PHN, firstName: 'Alice' }) as any,
      USER_1,
    );

    const ctx = await getPatientClaimContext(deps, created.patientId, PHYSICIAN_2);

    expect(ctx).toBeNull();
  });

  // ----- validatePhnService -----

  it('validatePhnService returns valid for correct Luhn', async () => {
    const result = await validatePhnService(deps, PHYSICIAN_1, VALID_AB_PHN);

    expect(result.valid).toBe(true);
    expect(result.formatOk).toBe(true);
  });

  it('validatePhnService returns exists for known patient', async () => {
    await createPatient(
      deps,
      PHYSICIAN_1,
      makeServiceInput({ phn: VALID_AB_PHN, firstName: 'Alice' }) as any,
      USER_1,
    );

    const result = await validatePhnService(deps, PHYSICIAN_1, VALID_AB_PHN);

    expect(result.valid).toBe(true);
    expect(result.formatOk).toBe(true);
    expect(result.exists).toBe(true);
    expect(result.patientId).toBeDefined();
  });

  it('validatePhnService returns not exists for unknown PHN', async () => {
    const result = await validatePhnService(deps, PHYSICIAN_1, VALID_AB_PHN);

    expect(result.valid).toBe(true);
    expect(result.formatOk).toBe(true);
    expect(result.exists).toBe(false);
    expect(result.patientId).toBeUndefined();
  });

  it('validatePhnService returns invalid for bad Luhn', async () => {
    const result = await validatePhnService(deps, PHYSICIAN_1, INVALID_LUHN_PHN);

    expect(result.valid).toBe(false);
    expect(result.formatOk).toBe(false);
    expect(result.exists).toBe(false);
  });

  it('validatePhnService scoped to physician — does not find other physician patients', async () => {
    await createPatient(
      deps,
      PHYSICIAN_2,
      makeServiceInput({ phn: VALID_AB_PHN, firstName: 'Bob' }) as any,
      USER_1,
    );

    const result = await validatePhnService(deps, PHYSICIAN_1, VALID_AB_PHN);

    expect(result.valid).toBe(true);
    expect(result.formatOk).toBe(true);
    expect(result.exists).toBe(false);
    expect(result.patientId).toBeUndefined();
  });

  // ----- Cleanup: clear caches after each test -----

  afterEach(() => {
    _parsedRowsCache.clear();
    _exportStore.clear();
  });
});
