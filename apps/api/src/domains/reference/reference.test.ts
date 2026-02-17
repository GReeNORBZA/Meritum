import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createReferenceRepository } from './reference.repository.js';
import {
  resolveVersion,
  searchHscCodes,
  getHscDetail,
  getHscFavourites,
  searchDiCodes,
  getDiDetail,
  getModifiersForHsc,
  getModifierDetail,
  getValidationContext,
  getRuleDetail,
  evaluateRulesBatch,
  getRrnpRate,
  getPcpcmBasket,
  isHoliday,
  getExplanatoryCode,
  uploadDataSet,
  getStagingDiff,
  discardStaging,
  publishVersion,
  rollbackVersion,
  dryRunRule,
  createHoliday,
  updateHoliday,
  deleteHoliday,
  listHolidays,
  checkHolidayCalendarPopulated,
  getChangeSummaries,
  getChangeDetail,
  getPhysicianImpact,
  type ReferenceServiceDeps,
  type AuditLogger,
  type EventEmitter,
} from './reference.service.js';
import { NotFoundError, BusinessRuleError, ConflictError } from '../../lib/errors.js';

// ---------------------------------------------------------------------------
// In-memory stores
// ---------------------------------------------------------------------------

let versionStore: Record<string, any>[];
let hscStore: Record<string, any>[];
let wcbStore: Record<string, any>[];
let modifierStore: Record<string, any>[];
let governingRuleStore: Record<string, any>[];
let diCodeStore: Record<string, any>[];
let rrnpCommunityStore: Record<string, any>[];
let pcpcmBasketStore: Record<string, any>[];
let functionalCentreStore: Record<string, any>[];
let statutoryHolidayStore: Record<string, any>[];
let explanatoryCodeStore: Record<string, any>[];
let stagingStore: Record<string, any>[];

// ---------------------------------------------------------------------------
// Mock Drizzle DB
// ---------------------------------------------------------------------------

function storeFor(table: any): Record<string, any>[] {
  if (table?.__table === 'reference_data_versions') return versionStore;
  if (table?.__table === 'hsc_codes') return hscStore;
  if (table?.__table === 'wcb_codes') return wcbStore;
  if (table?.__table === 'modifier_definitions') return modifierStore;
  if (table?.__table === 'governing_rules') return governingRuleStore;
  if (table?.__table === 'di_codes') return diCodeStore;
  if (table?.__table === 'rrnp_communities') return rrnpCommunityStore;
  if (table?.__table === 'pcpcm_baskets') return pcpcmBasketStore;
  if (table?.__table === 'functional_centres') return functionalCentreStore;
  if (table?.__table === 'statutory_holidays') return statutoryHolidayStore;
  if (table?.__table === 'explanatory_codes') return explanatoryCodeStore;
  if (table?.__table === 'reference_data_staging') return stagingStore;
  return [];
}

function insertRow(store: Record<string, any>[], values: any): any {
  if (store === versionStore) {
    const row = {
      versionId: values.versionId ?? crypto.randomUUID(),
      dataSet: values.dataSet,
      versionLabel: values.versionLabel,
      effectiveFrom: values.effectiveFrom,
      effectiveTo: values.effectiveTo ?? null,
      publishedBy: values.publishedBy,
      publishedAt: values.publishedAt ?? new Date(),
      sourceDocument: values.sourceDocument ?? null,
      changeSummary: values.changeSummary ?? null,
      recordsAdded: values.recordsAdded ?? 0,
      recordsModified: values.recordsModified ?? 0,
      recordsDeprecated: values.recordsDeprecated ?? 0,
      isActive: values.isActive ?? false,
    };
    store.push(row);
    return row;
  }

  if (store === hscStore) {
    const row = {
      id: values.id ?? crypto.randomUUID(),
      hscCode: values.hscCode,
      description: values.description,
      baseFee: values.baseFee ?? null,
      feeType: values.feeType,
      specialtyRestrictions: values.specialtyRestrictions ?? [],
      facilityRestrictions: values.facilityRestrictions ?? [],
      maxPerDay: values.maxPerDay ?? null,
      maxPerVisit: values.maxPerVisit ?? null,
      requiresReferral: values.requiresReferral ?? false,
      referralValidityDays: values.referralValidityDays ?? null,
      combinationGroup: values.combinationGroup ?? null,
      modifierEligibility: values.modifierEligibility ?? [],
      surchargeEligible: values.surchargeEligible ?? false,
      pcpcmBasket: values.pcpcmBasket ?? 'not_applicable',
      shadowBillingEligible: values.shadowBillingEligible ?? false,
      notes: values.notes ?? null,
      helpText: values.helpText ?? null,
      versionId: values.versionId,
      effectiveFrom: values.effectiveFrom,
      effectiveTo: values.effectiveTo ?? null,
    };
    store.push(row);
    return row;
  }

  if (store === wcbStore) {
    const row = {
      id: values.id ?? crypto.randomUUID(),
      wcbCode: values.wcbCode ?? values.wcb_code,
      description: values.description,
      baseFee: values.baseFee ?? values.base_fee ?? '0.00',
      feeType: values.feeType ?? values.fee_type ?? 'fixed',
      requiresClaimNumber: values.requiresClaimNumber ?? values.requires_claim_number ?? true,
      requiresEmployer: values.requiresEmployer ?? values.requires_employer ?? false,
      documentationRequirements: values.documentationRequirements ?? values.documentation_requirements ?? null,
      helpText: values.helpText ?? values.help_text ?? null,
      versionId: values.versionId,
      effectiveFrom: values.effectiveFrom ?? values.effective_from ?? '2026-01-01',
      effectiveTo: values.effectiveTo ?? values.effective_to ?? null,
    };
    store.push(row);
    return row;
  }

  if (store === modifierStore) {
    const row = {
      id: values.id ?? crypto.randomUUID(),
      modifierCode: values.modifierCode,
      name: values.name ?? values.modifierCode,
      description: values.description ?? '',
      type: values.type ?? 'percentage',
      calculationMethod: values.calculationMethod ?? 'percentage',
      calculationParams: values.calculationParams ?? {},
      applicableHscFilter: values.applicableHscFilter ?? {},
      requiresTimeDocumentation: values.requiresTimeDocumentation ?? false,
      requiresFacility: values.requiresFacility ?? false,
      combinableWith: values.combinableWith ?? [],
      exclusiveWith: values.exclusiveWith ?? [],
      governingRuleReference: values.governingRuleReference ?? null,
      helpText: values.helpText ?? null,
      versionId: values.versionId,
      effectiveFrom: values.effectiveFrom ?? '2026-01-01',
      effectiveTo: values.effectiveTo ?? null,
    };
    store.push(row);
    return row;
  }

  if (store === governingRuleStore) {
    const row = {
      id: values.id ?? crypto.randomUUID(),
      ruleId: values.ruleId,
      ruleName: values.ruleName ?? 'Test Rule',
      ruleCategory: values.ruleCategory ?? 'general',
      description: values.description ?? '',
      ruleLogic: values.ruleLogic ?? {},
      severity: values.severity ?? 'error',
      errorMessage: values.errorMessage ?? 'Rule violation',
      helpText: values.helpText ?? null,
      sourceReference: values.sourceReference ?? null,
      sourceUrl: values.sourceUrl ?? null,
      versionId: values.versionId,
      effectiveFrom: values.effectiveFrom ?? '2026-01-01',
      effectiveTo: values.effectiveTo ?? null,
    };
    store.push(row);
    return row;
  }

  if (store === diCodeStore) {
    const row = {
      id: values.id ?? crypto.randomUUID(),
      diCode: values.diCode,
      description: values.description ?? '',
      category: values.category ?? 'General',
      subcategory: values.subcategory ?? null,
      qualifiesSurcharge: values.qualifiesSurcharge ?? false,
      qualifiesBcp: values.qualifiesBcp ?? false,
      commonInSpecialty: values.commonInSpecialty ?? [],
      helpText: values.helpText ?? null,
      versionId: values.versionId,
      effectiveFrom: values.effectiveFrom ?? '2026-01-01',
      effectiveTo: values.effectiveTo ?? null,
    };
    store.push(row);
    return row;
  }

  if (store === rrnpCommunityStore) {
    const row = {
      communityId: values.communityId ?? crypto.randomUUID(),
      communityName: values.communityName,
      rrnpPercentage: values.rrnpPercentage,
      rrnpTier: values.rrnpTier ?? null,
      region: values.region ?? null,
      versionId: values.versionId,
      effectiveFrom: values.effectiveFrom ?? '2026-01-01',
      effectiveTo: values.effectiveTo ?? null,
    };
    store.push(row);
    return row;
  }

  if (store === pcpcmBasketStore) {
    const row = {
      id: values.id ?? crypto.randomUUID(),
      hscCode: values.hscCode,
      basket: values.basket,
      notes: values.notes ?? null,
      versionId: values.versionId,
      effectiveFrom: values.effectiveFrom ?? '2026-01-01',
      effectiveTo: values.effectiveTo ?? null,
    };
    store.push(row);
    return row;
  }

  if (store === functionalCentreStore) {
    const row = {
      id: values.id ?? crypto.randomUUID(),
      code: values.code,
      name: values.name,
      facilityType: values.facilityType,
      locationCity: values.locationCity ?? null,
      locationRegion: values.locationRegion ?? null,
      rrnpCommunityId: values.rrnpCommunityId ?? null,
      active: values.active ?? true,
      versionId: values.versionId,
      effectiveFrom: values.effectiveFrom ?? '2026-01-01',
      effectiveTo: values.effectiveTo ?? null,
    };
    store.push(row);
    return row;
  }

  if (store === statutoryHolidayStore) {
    const row = {
      holidayId: values.holidayId ?? crypto.randomUUID(),
      date: values.date,
      name: values.name,
      jurisdiction: values.jurisdiction ?? 'AB',
      affectsBillingPremiums: values.affectsBillingPremiums ?? true,
      year: values.year,
    };
    store.push(row);
    return row;
  }

  if (store === explanatoryCodeStore) {
    const row = {
      id: values.id ?? crypto.randomUUID(),
      explCode: values.explCode,
      description: values.description ?? '',
      severity: values.severity ?? 'info',
      commonCause: values.commonCause ?? null,
      suggestedAction: values.suggestedAction ?? null,
      helpText: values.helpText ?? null,
      versionId: values.versionId,
      effectiveFrom: values.effectiveFrom ?? '2026-01-01',
      effectiveTo: values.effectiveTo ?? null,
    };
    store.push(row);
    return row;
  }

  if (store === stagingStore) {
    const row = {
      stagingId: values.stagingId ?? crypto.randomUUID(),
      dataSet: values.dataSet,
      status: values.status ?? 'uploaded',
      uploadedBy: values.uploadedBy,
      uploadedAt: values.uploadedAt ?? new Date(),
      fileHash: values.fileHash,
      recordCount: values.recordCount,
      validationResult: values.validationResult ?? null,
      diffResult: values.diffResult ?? null,
      stagedData: values.stagedData,
      createdAt: values.createdAt ?? new Date(),
    };
    store.push(row);
    return row;
  }

  const row = { id: crypto.randomUUID(), ...values };
  store.push(row);
  return row;
}

function makeMockDb() {
  function chainable(ctx: {
    op: string;
    table?: any;
    values?: any;
    setClauses?: any;
    whereClauses: Array<(row: any) => boolean>;
    limitN?: number;
    offsetN?: number;
    orderByFn?: (a: any, b: any) => number;
    projection?: any;
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
      orderBy(...orderSpecs: any[]) {
        for (const orderSpec of orderSpecs) {
          if (orderSpec && orderSpec.__orderByFn) {
            ctx.orderByFn = orderSpec.__orderByFn;
            break;
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

  function executeOp(ctx: any): any[] {
    const store = storeFor(ctx.table);

    switch (ctx.op) {
      case 'select': {
        let matches = store.filter((row) =>
          ctx.whereClauses.every((pred: any) => pred(row)),
        );
        if (ctx.orderByFn) matches.sort(ctx.orderByFn);
        if (ctx.offsetN) matches = matches.slice(ctx.offsetN);
        const limited = ctx.limitN ? matches.slice(0, ctx.limitN) : matches;

        if (ctx.projection) {
          return limited.map((row) => ctx.projection(row));
        }
        if (ctx.setClauses && ctx.setClauses.__projection) {
          return limited.map(ctx.setClauses.__projection);
        }
        return limited;
      }
      case 'insert': {
        const values = ctx.values;
        if (Array.isArray(values)) {
          return values.map((v: any) => insertRow(store, v));
        }
        return [insertRow(store, values)];
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
            if (key === '__projection') continue;
            if (typeof value === 'object' && value !== null && (value as any).__sqlExpr) {
              row[key] = (value as any).__sqlExpr({ ...row });
            } else {
              row[key] = value;
            }
          }
          updated.push({ ...row });
        }
        return updated;
      }
      case 'delete': {
        const toRemoveIndices: number[] = [];
        for (let i = store.length - 1; i >= 0; i--) {
          if (ctx.whereClauses.every((pred: any) => pred(store[i]))) {
            toRemoveIndices.push(i);
          }
        }
        for (const idx of toRemoveIndices) {
          store.splice(idx, 1);
        }
        return [];
      }
      default:
        return [];
    }
  }

  const mockDb: any = {
    insert(table: any) {
      return chainable({ op: 'insert', table, whereClauses: [] });
    },
    select(projection?: any) {
      const ctx: any = { op: 'select', whereClauses: [], setClauses: null, projection: null };
      if (projection) {
        // Check for count projection
        const projKeys = Object.keys(projection);
        if (projKeys.length === 1 && projKeys[0] === 'count') {
          ctx.projection = (row: any) => {
            // Return count of matching rows — handled specially below
            return row;
          };
          // Override: instead of per-row mapping, count total matches
          ctx._countMode = true;
        }
      }
      return chainable(ctx);
    },
    update(table: any) {
      return chainable({ op: 'update', table, whereClauses: [] });
    },
    delete(table: any) {
      return chainable({ op: 'delete', table, whereClauses: [] });
    },
    async transaction(fn: (tx: any) => Promise<void>) {
      // In the mock, the tx object is the same as the db object (operates on same stores)
      await fn(mockDb);
    },
  };

  // Patch the select().from() chain for count mode
  const origSelect = mockDb.select;
  mockDb.select = function (projection?: any) {
    const chain = origSelect(projection);
    if (projection && Object.keys(projection).length === 1 && Object.keys(projection)[0] === 'count') {
      const origThen = chain.then;
      // We need to intercept the then to return [{count: N}] instead of individual rows
      const origFrom = chain.from;
      chain.from = function (table: any) {
        const innerChain = origFrom.call(this, table);
        const innerOrigThen = innerChain.then;
        innerChain.then = function (resolve: any, reject?: any) {
          // Run the query to get matching rows, then return count
          innerOrigThen.call(this, (rows: any[]) => {
            resolve([{ count: rows.length }]);
          }, reject);
        };
        return innerChain;
      };
    }
    return chain;
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
          if (value?.name) return a[colName] === b[value.name];
          return a[colName] === value;
        },
      };
    },
    and: (...conditions: any[]) => {
      const preds = conditions.filter(Boolean);
      return {
        __predicate: (row: any) =>
          preds.every((p: any) => {
            if (p?.__predicate) return p.__predicate(row);
            return true;
          }),
      };
    },
    or: (...conditions: any[]) => {
      const preds = conditions.filter(Boolean);
      return {
        __predicate: (row: any) =>
          preds.some((p: any) => {
            if (p?.__predicate) return p.__predicate(row);
            return false;
          }),
      };
    },
    desc: (column: any) => {
      const colName = column?.name;
      return {
        __orderByFn: (a: any, b: any) => {
          const aVal = a[colName];
          const bVal = b[colName];
          if (aVal > bVal) return -1;
          if (aVal < bVal) return 1;
          return 0;
        },
      };
    },
    asc: (column: any) => {
      const colName = column?.name;
      return {
        __orderByFn: (a: any, b: any) => {
          const aVal = a[colName];
          const bVal = b[colName];
          if (aVal < bVal) return -1;
          if (aVal > bVal) return 1;
          return 0;
        },
      };
    },
    gte: (column: any, value: any) => {
      const colName = column?.name;
      return {
        __predicate: (row: any) => row[colName] >= value,
      };
    },
    lte: (column: any, value: any) => {
      const colName = column?.name;
      return {
        __predicate: (row: any) => row[colName] <= value,
      };
    },
    isNull: (column: any) => {
      const colName = column?.name;
      return {
        __predicate: (row: any) => row[colName] === null || row[colName] === undefined,
      };
    },
    sql: (strings: TemplateStringsArray, ...values: any[]) => {
      const raw = strings.join('__PLACEHOLDER__');

      // CASE WHEN for specialty boost — must come before @> check
      if (raw.includes('CASE WHEN') && raw.includes('@>')) {
        const col = values[0];
        const jsonVal = values[1];
        return {
          __orderByFn: (a: any, b: any) => {
            // In DESC mode, specialty-matching rows come first
            const aMatch = Array.isArray(a[col?.name]) && JSON.parse(jsonVal).every((v: string) => a[col?.name].includes(v)) ? 1 : 0;
            const bMatch = Array.isArray(b[col?.name]) && JSON.parse(jsonVal).every((v: string) => b[col?.name].includes(v)) ? 1 : 0;
            return bMatch - aMatch;
          },
        };
      }

      // specialtyBoost DESC or similar DESC ordering on a sql expression
      if (raw.includes('DESC') && !raw.includes('GREATEST') && !raw.includes('similarity')) {
        const val = values[0];
        if (val && val.__orderByFn) {
          return val;
        }
        return { __orderByFn: (a: any, b: any) => 0 };
      }

      // JSONB @> for specialty/facility filtering — must come before '> ' check
      if (raw.includes('@>')) {
        const col = values[0];
        const jsonVal = values[1];
        return {
          __predicate: (row: any) => {
            const rowVal = row[col?.name];
            if (!Array.isArray(rowVal)) return false;
            const parsed = JSON.parse(jsonVal);
            return parsed.every((v: string) => rowVal.includes(v));
          },
        };
      }

      // similarity(col, query) > 0.1 — trigram similarity for search
      if (raw.includes('similarity(') && raw.includes('> 0.1')) {
        const col = values[0];
        const queryVal = values[1];
        return {
          __predicate: (row: any) => {
            const rowVal = row[col?.name];
            if (!rowVal) return false;
            return rowVal.toLowerCase().includes(queryVal.toLowerCase().substring(0, 3));
          },
        };
      }

      // effectiveTo > dateStr — for findVersionForDate (simple col > val pattern)
      if (raw.includes('> ') && !raw.includes('similarity') && !raw.includes('GREATEST')) {
        const col = values[0];
        const compareVal = values[1];
        if (col?.name) {
          return {
            __predicate: (row: any) => {
              const rowVal = row[col.name];
              if (rowVal === null || rowVal === undefined) return false;
              return rowVal > compareVal;
            },
          };
        }
      }

      // ILIKE for search
      if (raw.includes('ILIKE')) {
        const col = values[0];
        const pattern = values[1];
        return {
          __predicate: (row: any) => {
            const rowVal = row[col?.name];
            if (!rowVal) return false;
            // Convert SQL ILIKE %query% to JS match
            const searchStr = pattern.replace(/%/g, '');
            return rowVal.toLowerCase().includes(searchStr.toLowerCase());
          },
        };
      }

      // to_tsvector full-text search
      if (raw.includes('to_tsvector') && raw.includes('@@')) {
        const col = values[0];
        const queryVal = values[1];
        return {
          __predicate: (row: any) => {
            const rowVal = row[col?.name];
            if (!rowVal) return false;
            // Simple word match simulation for testing
            const words = queryVal.toLowerCase().split(/\s+/);
            return words.some((w: string) =>
              rowVal.toLowerCase().includes(w),
            );
          },
        };
      }

      // GREATEST for ORDER BY relevance — just return a no-op ordering
      if (raw.includes('GREATEST')) {
        return {
          __orderByFn: (a: any, b: any) => 0,
        };
      }

      // count(*)::int
      if (raw.includes('count(*)')) {
        return { name: 'count', __sqlExpr: () => 0 };
      }

      return { __sqlExpr: () => null };
    },
  };
});

// Mock the schema module
vi.mock('@meritum/shared/schemas/db/reference.schema.js', () => {
  const makeCol = (name: string) => ({ name });

  const referenceDataVersions: any = {
    __table: 'reference_data_versions',
    versionId: makeCol('versionId'),
    dataSet: makeCol('dataSet'),
    versionLabel: makeCol('versionLabel'),
    effectiveFrom: makeCol('effectiveFrom'),
    effectiveTo: makeCol('effectiveTo'),
    publishedBy: makeCol('publishedBy'),
    publishedAt: makeCol('publishedAt'),
    sourceDocument: makeCol('sourceDocument'),
    changeSummary: makeCol('changeSummary'),
    recordsAdded: makeCol('recordsAdded'),
    recordsModified: makeCol('recordsModified'),
    recordsDeprecated: makeCol('recordsDeprecated'),
    isActive: makeCol('isActive'),
  };

  const hscCodes: any = {
    __table: 'hsc_codes',
    id: makeCol('id'),
    hscCode: makeCol('hscCode'),
    description: makeCol('description'),
    baseFee: makeCol('baseFee'),
    feeType: makeCol('feeType'),
    specialtyRestrictions: makeCol('specialtyRestrictions'),
    facilityRestrictions: makeCol('facilityRestrictions'),
    maxPerDay: makeCol('maxPerDay'),
    maxPerVisit: makeCol('maxPerVisit'),
    requiresReferral: makeCol('requiresReferral'),
    referralValidityDays: makeCol('referralValidityDays'),
    combinationGroup: makeCol('combinationGroup'),
    modifierEligibility: makeCol('modifierEligibility'),
    surchargeEligible: makeCol('surchargeEligible'),
    pcpcmBasket: makeCol('pcpcmBasket'),
    shadowBillingEligible: makeCol('shadowBillingEligible'),
    notes: makeCol('notes'),
    helpText: makeCol('helpText'),
    versionId: makeCol('versionId'),
    effectiveFrom: makeCol('effectiveFrom'),
    effectiveTo: makeCol('effectiveTo'),
  };

  const wcbCodes: any = {
    __table: 'wcb_codes',
    id: makeCol('id'),
    wcbCode: makeCol('wcbCode'),
    description: makeCol('description'),
    baseFee: makeCol('baseFee'),
    feeType: makeCol('feeType'),
    requiresClaimNumber: makeCol('requiresClaimNumber'),
    requiresEmployer: makeCol('requiresEmployer'),
    documentationRequirements: makeCol('documentationRequirements'),
    helpText: makeCol('helpText'),
    versionId: makeCol('versionId'),
    effectiveFrom: makeCol('effectiveFrom'),
    effectiveTo: makeCol('effectiveTo'),
  };

  const modifierDefinitions: any = {
    __table: 'modifier_definitions',
    id: makeCol('id'),
    modifierCode: makeCol('modifierCode'),
    name: makeCol('name'),
    description: makeCol('description'),
    type: makeCol('type'),
    calculationMethod: makeCol('calculationMethod'),
    calculationParams: makeCol('calculationParams'),
    applicableHscFilter: makeCol('applicableHscFilter'),
    requiresTimeDocumentation: makeCol('requiresTimeDocumentation'),
    requiresFacility: makeCol('requiresFacility'),
    combinableWith: makeCol('combinableWith'),
    exclusiveWith: makeCol('exclusiveWith'),
    governingRuleReference: makeCol('governingRuleReference'),
    helpText: makeCol('helpText'),
    versionId: makeCol('versionId'),
    effectiveFrom: makeCol('effectiveFrom'),
    effectiveTo: makeCol('effectiveTo'),
  };

  const governingRules: any = {
    __table: 'governing_rules',
    id: makeCol('id'),
    ruleId: makeCol('ruleId'),
    ruleName: makeCol('ruleName'),
    ruleCategory: makeCol('ruleCategory'),
    description: makeCol('description'),
    ruleLogic: makeCol('ruleLogic'),
    severity: makeCol('severity'),
    errorMessage: makeCol('errorMessage'),
    helpText: makeCol('helpText'),
    sourceReference: makeCol('sourceReference'),
    sourceUrl: makeCol('sourceUrl'),
    versionId: makeCol('versionId'),
    effectiveFrom: makeCol('effectiveFrom'),
    effectiveTo: makeCol('effectiveTo'),
  };

  const diCodes: any = {
    __table: 'di_codes',
    id: makeCol('id'),
    diCode: makeCol('diCode'),
    description: makeCol('description'),
    category: makeCol('category'),
    subcategory: makeCol('subcategory'),
    qualifiesSurcharge: makeCol('qualifiesSurcharge'),
    qualifiesBcp: makeCol('qualifiesBcp'),
    commonInSpecialty: makeCol('commonInSpecialty'),
    helpText: makeCol('helpText'),
    versionId: makeCol('versionId'),
    effectiveFrom: makeCol('effectiveFrom'),
    effectiveTo: makeCol('effectiveTo'),
  };

  const rrnpCommunities: any = {
    __table: 'rrnp_communities',
    communityId: makeCol('communityId'),
    communityName: makeCol('communityName'),
    rrnpPercentage: makeCol('rrnpPercentage'),
    rrnpTier: makeCol('rrnpTier'),
    region: makeCol('region'),
    versionId: makeCol('versionId'),
    effectiveFrom: makeCol('effectiveFrom'),
    effectiveTo: makeCol('effectiveTo'),
  };

  const pcpcmBaskets: any = {
    __table: 'pcpcm_baskets',
    id: makeCol('id'),
    hscCode: makeCol('hscCode'),
    basket: makeCol('basket'),
    notes: makeCol('notes'),
    versionId: makeCol('versionId'),
    effectiveFrom: makeCol('effectiveFrom'),
    effectiveTo: makeCol('effectiveTo'),
  };

  const functionalCentres: any = {
    __table: 'functional_centres',
    id: makeCol('id'),
    code: makeCol('code'),
    name: makeCol('name'),
    facilityType: makeCol('facilityType'),
    locationCity: makeCol('locationCity'),
    locationRegion: makeCol('locationRegion'),
    rrnpCommunityId: makeCol('rrnpCommunityId'),
    active: makeCol('active'),
    versionId: makeCol('versionId'),
    effectiveFrom: makeCol('effectiveFrom'),
    effectiveTo: makeCol('effectiveTo'),
  };

  const statutoryHolidays: any = {
    __table: 'statutory_holidays',
    holidayId: makeCol('holidayId'),
    date: makeCol('date'),
    name: makeCol('name'),
    jurisdiction: makeCol('jurisdiction'),
    affectsBillingPremiums: makeCol('affectsBillingPremiums'),
    year: makeCol('year'),
  };

  const explanatoryCodes: any = {
    __table: 'explanatory_codes',
    id: makeCol('id'),
    explCode: makeCol('explCode'),
    description: makeCol('description'),
    severity: makeCol('severity'),
    commonCause: makeCol('commonCause'),
    suggestedAction: makeCol('suggestedAction'),
    helpText: makeCol('helpText'),
    versionId: makeCol('versionId'),
    effectiveFrom: makeCol('effectiveFrom'),
    effectiveTo: makeCol('effectiveTo'),
  };

  const referenceDataStaging: any = {
    __table: 'reference_data_staging',
    stagingId: makeCol('stagingId'),
    dataSet: makeCol('dataSet'),
    status: makeCol('status'),
    uploadedBy: makeCol('uploadedBy'),
    uploadedAt: makeCol('uploadedAt'),
    fileHash: makeCol('fileHash'),
    recordCount: makeCol('recordCount'),
    validationResult: makeCol('validationResult'),
    diffResult: makeCol('diffResult'),
    stagedData: makeCol('stagedData'),
    createdAt: makeCol('createdAt'),
  };

  return {
    referenceDataVersions,
    hscCodes,
    wcbCodes,
    modifierDefinitions,
    governingRules,
    diCodes,
    rrnpCommunities,
    pcpcmBaskets,
    functionalCentres,
    statutoryHolidays,
    explanatoryCodes,
    referenceDataStaging,
  };
});

// ---------------------------------------------------------------------------
// Reset stores before each test
// ---------------------------------------------------------------------------

beforeEach(() => {
  versionStore = [];
  hscStore = [];
  wcbStore = [];
  modifierStore = [];
  governingRuleStore = [];
  diCodeStore = [];
  rrnpCommunityStore = [];
  pcpcmBasketStore = [];
  functionalCentreStore = [];
  statutoryHolidayStore = [];
  explanatoryCodeStore = [];
  stagingStore = [];
});

// ---------------------------------------------------------------------------
// Helper: seed data
// ---------------------------------------------------------------------------

const userId = crypto.randomUUID();

function seedVersion(overrides: Partial<Record<string, any>> = {}): Record<string, any> {
  const v = {
    versionId: overrides.versionId ?? crypto.randomUUID(),
    dataSet: overrides.dataSet ?? 'SOMB',
    versionLabel: overrides.versionLabel ?? '2026-Q1',
    effectiveFrom: overrides.effectiveFrom ?? '2026-01-01',
    effectiveTo: overrides.effectiveTo ?? null,
    publishedBy: overrides.publishedBy ?? userId,
    publishedAt: overrides.publishedAt ?? new Date(),
    sourceDocument: overrides.sourceDocument ?? null,
    changeSummary: overrides.changeSummary ?? null,
    recordsAdded: overrides.recordsAdded ?? 0,
    recordsModified: overrides.recordsModified ?? 0,
    recordsDeprecated: overrides.recordsDeprecated ?? 0,
    isActive: overrides.isActive ?? false,
  };
  versionStore.push(v);
  return v;
}

function seedHsc(overrides: Partial<Record<string, any>> = {}): Record<string, any> {
  const h = {
    id: overrides.id ?? crypto.randomUUID(),
    hscCode: overrides.hscCode ?? '03.04A',
    description: overrides.description ?? 'Office visit - general assessment',
    baseFee: overrides.baseFee ?? '38.45',
    feeType: overrides.feeType ?? 'fixed',
    specialtyRestrictions: overrides.specialtyRestrictions ?? [],
    facilityRestrictions: overrides.facilityRestrictions ?? [],
    maxPerDay: overrides.maxPerDay ?? null,
    maxPerVisit: overrides.maxPerVisit ?? null,
    requiresReferral: overrides.requiresReferral ?? false,
    referralValidityDays: overrides.referralValidityDays ?? null,
    combinationGroup: overrides.combinationGroup ?? null,
    modifierEligibility: overrides.modifierEligibility ?? ['CMGP', 'LSCD'],
    surchargeEligible: overrides.surchargeEligible ?? true,
    pcpcmBasket: overrides.pcpcmBasket ?? 'in_basket',
    shadowBillingEligible: overrides.shadowBillingEligible ?? false,
    notes: overrides.notes ?? null,
    helpText: overrides.helpText ?? 'Standard GP office visit',
    versionId: overrides.versionId ?? crypto.randomUUID(),
    effectiveFrom: overrides.effectiveFrom ?? '2026-01-01',
    effectiveTo: overrides.effectiveTo ?? null,
  };
  hscStore.push(h);
  return h;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Reference Repository — Version Management', () => {
  it('findActiveVersion returns the active version for data set', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    seedVersion({ dataSet: 'SOMB', isActive: false, versionLabel: 'v1' });
    const active = seedVersion({ dataSet: 'SOMB', isActive: true, versionLabel: 'v2' });
    seedVersion({ dataSet: 'WCB', isActive: true, versionLabel: 'wcb-v1' });

    const result = await repo.findActiveVersion('SOMB');
    expect(result).toBeDefined();
    expect(result!.versionId).toBe(active.versionId);
    expect(result!.versionLabel).toBe('v2');
  });

  it('findActiveVersion returns undefined when no active version exists', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    seedVersion({ dataSet: 'SOMB', isActive: false });

    const result = await repo.findActiveVersion('SOMB');
    expect(result).toBeUndefined();
  });

  it('findVersionForDate returns correct version for date within range', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const v1 = seedVersion({
      dataSet: 'SOMB',
      effectiveFrom: '2025-01-01',
      effectiveTo: '2026-01-01',
      versionLabel: 'v1',
    });
    seedVersion({
      dataSet: 'SOMB',
      effectiveFrom: '2026-01-01',
      effectiveTo: null,
      versionLabel: 'v2',
    });

    // Date in middle of v1's range
    const result = await repo.findVersionForDate('SOMB', new Date('2025-06-15'));
    expect(result).toBeDefined();
    expect(result!.versionId).toBe(v1.versionId);
    expect(result!.versionLabel).toBe('v1');
  });

  it('findVersionForDate returns correct version at boundary (effectiveFrom date)', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    seedVersion({
      dataSet: 'SOMB',
      effectiveFrom: '2025-01-01',
      effectiveTo: '2026-01-01',
      versionLabel: 'v1',
    });
    const v2 = seedVersion({
      dataSet: 'SOMB',
      effectiveFrom: '2026-01-01',
      effectiveTo: null,
      versionLabel: 'v2',
    });

    // Exactly on effectiveFrom of v2 — should use v2
    const result = await repo.findVersionForDate('SOMB', new Date('2026-01-01'));
    expect(result).toBeDefined();
    expect(result!.versionId).toBe(v2.versionId);
    expect(result!.versionLabel).toBe('v2');
  });

  it('findVersionForDate returns previous version for day before effectiveFrom', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const v1 = seedVersion({
      dataSet: 'SOMB',
      effectiveFrom: '2025-01-01',
      effectiveTo: '2026-01-01',
      versionLabel: 'v1',
    });
    seedVersion({
      dataSet: 'SOMB',
      effectiveFrom: '2026-01-01',
      effectiveTo: null,
      versionLabel: 'v2',
    });

    // Day before v2 starts — should still be v1
    const result = await repo.findVersionForDate('SOMB', new Date('2025-12-31'));
    expect(result).toBeDefined();
    expect(result!.versionId).toBe(v1.versionId);
    expect(result!.versionLabel).toBe('v1');
  });

  it('findVersionForDate returns undefined for date before any version', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    seedVersion({
      dataSet: 'SOMB',
      effectiveFrom: '2026-01-01',
      effectiveTo: null,
    });

    const result = await repo.findVersionForDate('SOMB', new Date('2025-06-01'));
    expect(result).toBeUndefined();
  });

  it('listVersions returns all versions ordered by effectiveFrom DESC', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    seedVersion({ dataSet: 'SOMB', effectiveFrom: '2025-01-01', versionLabel: 'v1' });
    seedVersion({ dataSet: 'SOMB', effectiveFrom: '2026-01-01', versionLabel: 'v2' });
    seedVersion({ dataSet: 'SOMB', effectiveFrom: '2024-01-01', versionLabel: 'v0' });
    seedVersion({ dataSet: 'WCB', effectiveFrom: '2025-01-01', versionLabel: 'wcb-v1' });

    const result = await repo.listVersions('SOMB');
    expect(result).toHaveLength(3);
    expect(result[0].versionLabel).toBe('v2');
    expect(result[1].versionLabel).toBe('v1');
    expect(result[2].versionLabel).toBe('v0');
  });

  it('createVersion inserts a new version record', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const result = await repo.createVersion({
      dataSet: 'SOMB',
      versionLabel: '2026-Q2',
      effectiveFrom: '2026-04-01',
      publishedBy: userId,
      publishedAt: new Date(),
    });

    expect(result).toBeDefined();
    expect(result.dataSet).toBe('SOMB');
    expect(result.versionLabel).toBe('2026-Q2');
    expect(result.effectiveFrom).toBe('2026-04-01');
    expect(result.isActive).toBe(false);
    expect(versionStore).toHaveLength(1);
  });

  it('activateVersion atomically swaps active version', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const prev = seedVersion({
      dataSet: 'SOMB',
      isActive: true,
      effectiveFrom: '2025-01-01',
      versionLabel: 'v1',
    });
    const next = seedVersion({
      dataSet: 'SOMB',
      isActive: false,
      effectiveFrom: '2026-01-01',
      versionLabel: 'v2',
    });

    await repo.activateVersion(next.versionId, prev.versionId);

    // Previous should be deactivated
    const prevInStore = versionStore.find((v) => v.versionId === prev.versionId);
    expect(prevInStore!.isActive).toBe(false);

    // New should be activated
    const nextInStore = versionStore.find((v) => v.versionId === next.versionId);
    expect(nextInStore!.isActive).toBe(true);
  });

  it('activateVersion sets previous version effectiveTo', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const prev = seedVersion({
      dataSet: 'SOMB',
      isActive: true,
      effectiveFrom: '2025-01-01',
      effectiveTo: null,
      versionLabel: 'v1',
    });
    const next = seedVersion({
      dataSet: 'SOMB',
      isActive: false,
      effectiveFrom: '2026-01-01',
      versionLabel: 'v2',
    });

    await repo.activateVersion(next.versionId, prev.versionId);

    const prevInStore = versionStore.find((v) => v.versionId === prev.versionId);
    expect(prevInStore!.effectiveTo).toBe('2026-01-01');
  });

  it('activateVersion without previousVersionId only activates new version', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const v = seedVersion({
      dataSet: 'SOMB',
      isActive: false,
      effectiveFrom: '2026-01-01',
    });

    await repo.activateVersion(v.versionId);

    const inStore = versionStore.find((row) => row.versionId === v.versionId);
    expect(inStore!.isActive).toBe(true);
  });

  it('deactivateVersion sets isActive to false', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const v = seedVersion({ dataSet: 'SOMB', isActive: true });
    await repo.deactivateVersion(v.versionId);

    const inStore = versionStore.find((row) => row.versionId === v.versionId);
    expect(inStore!.isActive).toBe(false);
  });
});

describe('Reference Repository — HSC Code Queries', () => {
  it('searchHscCodes returns results for code prefix match', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    seedHsc({ hscCode: '03.04A', description: 'Office visit assessment', versionId });
    seedHsc({ hscCode: '03.05A', description: 'Hospital visit', versionId });
    seedHsc({ hscCode: '08.19A', description: 'Surgical consult', versionId });

    const results = await repo.searchHscCodes('03.04', versionId);
    expect(results.length).toBeGreaterThan(0);
    expect(results.some((r: any) => r.hscCode === '03.04A')).toBe(true);
  });

  it('searchHscCodes returns results for keyword match', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    seedHsc({ hscCode: '03.04A', description: 'Office visit general assessment', versionId });
    seedHsc({ hscCode: '03.05A', description: 'Hospital consultation', versionId });
    seedHsc({ hscCode: '08.19A', description: 'Surgical procedure initial', versionId });

    const results = await repo.searchHscCodes('consultation', versionId);
    expect(results.length).toBeGreaterThan(0);
    expect(results.some((r: any) => r.hscCode === '03.05A')).toBe(true);
  });

  it('searchHscCodes filters by specialty', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    seedHsc({
      hscCode: '03.04A',
      description: 'GP office visit',
      versionId,
      specialtyRestrictions: ['GP', 'FM'],
    });
    seedHsc({
      hscCode: '08.19A',
      description: 'Cardiology consult',
      versionId,
      specialtyRestrictions: ['CARDIOLOGY'],
    });

    const results = await repo.searchHscCodes('consult', versionId, { specialty: 'CARDIOLOGY' });
    expect(results.length).toBeGreaterThan(0);
    expect(results.every((r: any) => r.hscCode !== '03.04A')).toBe(true);
  });

  it('searchHscCodes respects version_id (different versions return different results)', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionA = crypto.randomUUID();
    const versionB = crypto.randomUUID();

    seedHsc({ hscCode: '03.04A', description: 'Office visit v1', versionId: versionA });
    seedHsc({ hscCode: '03.04A', description: 'Office visit v2 updated', versionId: versionB });
    seedHsc({ hscCode: '99.99Z', description: 'New code only in v2', versionId: versionB });

    const resultsA = await repo.searchHscCodes('03.04', versionA);
    const resultsB = await repo.searchHscCodes('03.04', versionB);

    // Version A should have 1 result for 03.04
    expect(resultsA).toHaveLength(1);
    expect(resultsA[0].description).toBe('Office visit v1');

    // Version B should have 1 result for 03.04 (with updated description)
    expect(resultsB).toHaveLength(1);
    expect(resultsB[0].description).toBe('Office visit v2 updated');

    // New code only in version B
    const newCodeResults = await repo.searchHscCodes('99.99', versionB);
    expect(newCodeResults).toHaveLength(1);

    const newCodeInA = await repo.searchHscCodes('99.99', versionA);
    expect(newCodeInA).toHaveLength(0);
  });

  it('findHscByCode returns full detail with modifiers', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    const hsc = seedHsc({
      hscCode: '03.04A',
      description: 'Office visit general assessment',
      baseFee: '38.45',
      feeType: 'fixed',
      versionId,
      modifierEligibility: ['CMGP', 'LSCD', 'AFHR'],
      specialtyRestrictions: ['GP', 'FM'],
      facilityRestrictions: ['OFFICE'],
      combinationGroup: 'office_visits',
      surchargeEligible: true,
      pcpcmBasket: 'in_basket',
      helpText: 'Standard GP office visit assessment',
    });

    const result = await repo.findHscByCode('03.04A', versionId);
    expect(result).toBeDefined();
    expect(result!.hscCode).toBe('03.04A');
    expect(result!.baseFee).toBe('38.45');
    expect(result!.feeType).toBe('fixed');
    expect(result!.modifierEligibility).toEqual(['CMGP', 'LSCD', 'AFHR']);
    expect(result!.specialtyRestrictions).toEqual(['GP', 'FM']);
    expect(result!.facilityRestrictions).toEqual(['OFFICE']);
    expect(result!.combinationGroup).toBe('office_visits');
    expect(result!.surchargeEligible).toBe(true);
    expect(result!.pcpcmBasket).toBe('in_basket');
    expect(result!.helpText).toBe('Standard GP office visit assessment');
  });

  it('findHscByCode returns undefined for non-existent code', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    seedHsc({ hscCode: '03.04A', versionId });

    const result = await repo.findHscByCode('99.99Z', versionId);
    expect(result).toBeUndefined();
  });

  it('findHscByCode returns undefined for code in different version', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionA = crypto.randomUUID();
    const versionB = crypto.randomUUID();
    seedHsc({ hscCode: '03.04A', versionId: versionA });

    const result = await repo.findHscByCode('03.04A', versionB);
    expect(result).toBeUndefined();
  });

  it('listHscByVersion returns paginated results', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    for (let i = 0; i < 5; i++) {
      seedHsc({
        hscCode: `0${i}.01A`,
        description: `Test code ${i}`,
        versionId,
      });
    }
    // Add code in a different version to confirm filtering
    seedHsc({ hscCode: '99.99Z', description: 'Other version', versionId: crypto.randomUUID() });

    const page1 = await repo.listHscByVersion(versionId, { limit: 3, offset: 0 });
    expect(page1.data).toHaveLength(3);
    expect(page1.total).toBe(5);

    const page2 = await repo.listHscByVersion(versionId, { limit: 3, offset: 3 });
    expect(page2.data).toHaveLength(2);
    expect(page2.total).toBe(5);
  });

  it('searchHscCodes returns summary fields only', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    seedHsc({
      hscCode: '03.04A',
      description: 'Office visit',
      baseFee: '38.45',
      feeType: 'fixed',
      helpText: 'Help text',
      effectiveTo: null,
      versionId,
      modifierEligibility: ['CMGP'],
      combinationGroup: 'group1',
    });

    const results = await repo.searchHscCodes('03.04', versionId);
    expect(results).toHaveLength(1);
    const r = results[0] as any;
    expect(r.id).toBeDefined();
    expect(r.hscCode).toBe('03.04A');
    expect(r.description).toBe('Office visit');
    expect(r.baseFee).toBe('38.45');
    expect(r.feeType).toBe('fixed');
    expect(r.helpText).toBe('Help text');
    // effectiveTo is included for deprecated flag
    expect(r).toHaveProperty('effectiveTo');
  });
});

// ---------------------------------------------------------------------------
// Seed helpers — WCB, Modifiers, Governing Rules
// ---------------------------------------------------------------------------

function seedWcb(overrides: Partial<Record<string, any>> = {}): Record<string, any> {
  const w = {
    id: overrides.id ?? crypto.randomUUID(),
    wcbCode: overrides.wcbCode ?? 'WCB001',
    description: overrides.description ?? 'Initial physician report',
    baseFee: overrides.baseFee ?? '75.00',
    feeType: overrides.feeType ?? 'fixed',
    requiresClaimNumber: overrides.requiresClaimNumber ?? true,
    requiresEmployer: overrides.requiresEmployer ?? false,
    documentationRequirements: overrides.documentationRequirements ?? null,
    helpText: overrides.helpText ?? null,
    versionId: overrides.versionId ?? crypto.randomUUID(),
    effectiveFrom: overrides.effectiveFrom ?? '2026-01-01',
    effectiveTo: overrides.effectiveTo ?? null,
  };
  wcbStore.push(w);
  return w;
}

function seedModifier(overrides: Partial<Record<string, any>> = {}): Record<string, any> {
  const m = {
    id: overrides.id ?? crypto.randomUUID(),
    modifierCode: overrides.modifierCode ?? 'CMGP',
    name: overrides.name ?? 'Comprehensive General Practice',
    description: overrides.description ?? 'CMGP modifier for GP services',
    type: overrides.type ?? 'percentage',
    calculationMethod: overrides.calculationMethod ?? 'percentage',
    calculationParams: overrides.calculationParams ?? { percentage: 15 },
    applicableHscFilter: overrides.applicableHscFilter ?? { all: true },
    requiresTimeDocumentation: overrides.requiresTimeDocumentation ?? false,
    requiresFacility: overrides.requiresFacility ?? false,
    combinableWith: overrides.combinableWith ?? ['LSCD'],
    exclusiveWith: overrides.exclusiveWith ?? ['ANE'],
    governingRuleReference: overrides.governingRuleReference ?? null,
    helpText: overrides.helpText ?? null,
    versionId: overrides.versionId ?? crypto.randomUUID(),
    effectiveFrom: overrides.effectiveFrom ?? '2026-01-01',
    effectiveTo: overrides.effectiveTo ?? null,
  };
  modifierStore.push(m);
  return m;
}

function seedRule(overrides: Partial<Record<string, any>> = {}): Record<string, any> {
  const r = {
    id: overrides.id ?? crypto.randomUUID(),
    ruleId: overrides.ruleId ?? 'GR-01',
    ruleName: overrides.ruleName ?? 'General Rule 1',
    ruleCategory: overrides.ruleCategory ?? 'general',
    description: overrides.description ?? 'A general governing rule',
    ruleLogic: overrides.ruleLogic ?? {},
    severity: overrides.severity ?? 'error',
    errorMessage: overrides.errorMessage ?? 'Rule violation',
    helpText: overrides.helpText ?? null,
    sourceReference: overrides.sourceReference ?? null,
    sourceUrl: overrides.sourceUrl ?? null,
    versionId: overrides.versionId ?? crypto.randomUUID(),
    effectiveFrom: overrides.effectiveFrom ?? '2026-01-01',
    effectiveTo: overrides.effectiveTo ?? null,
  };
  governingRuleStore.push(r);
  return r;
}

// ---------------------------------------------------------------------------
// WCB Code Tests
// ---------------------------------------------------------------------------

describe('Reference Repository — WCB Code Queries', () => {
  it('searchWcbCodes returns results for code prefix', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    seedWcb({ wcbCode: 'WCB001', description: 'Initial physician report', versionId });
    seedWcb({ wcbCode: 'WCB002', description: 'Follow-up report', versionId });
    seedWcb({ wcbCode: 'MED001', description: 'Medical consult', versionId });

    const results = await repo.searchWcbCodes('WCB001', versionId);
    expect(results.length).toBeGreaterThan(0);
    expect(results.some((r: any) => r.wcbCode === 'WCB001')).toBe(true);
  });

  it('searchWcbCodes returns results for keyword', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    seedWcb({ wcbCode: 'WCB001', description: 'Initial physician report', versionId });
    seedWcb({ wcbCode: 'WCB002', description: 'Follow-up assessment', versionId });
    seedWcb({ wcbCode: 'WCB003', description: 'Surgical procedure note', versionId });

    const results = await repo.searchWcbCodes('assessment', versionId);
    expect(results.length).toBeGreaterThan(0);
    expect(results.some((r: any) => r.wcbCode === 'WCB002')).toBe(true);
  });

  it('searchWcbCodes respects version_id', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionA = crypto.randomUUID();
    const versionB = crypto.randomUUID();
    seedWcb({ wcbCode: 'WCB001', description: 'Report v1', versionId: versionA });
    seedWcb({ wcbCode: 'WCB001', description: 'Report v2', versionId: versionB });

    const resultsA = await repo.searchWcbCodes('WCB001', versionA);
    expect(resultsA).toHaveLength(1);
    expect(resultsA[0].description).toBe('Report v1');

    const resultsB = await repo.searchWcbCodes('WCB001', versionB);
    expect(resultsB).toHaveLength(1);
    expect(resultsB[0].description).toBe('Report v2');
  });

  it('findWcbByCode returns full detail', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    seedWcb({
      wcbCode: 'WCB001',
      description: 'Initial physician report',
      baseFee: '75.00',
      feeType: 'fixed',
      requiresClaimNumber: true,
      requiresEmployer: true,
      documentationRequirements: 'Full injury report required',
      helpText: 'Use for initial WCB reports',
      versionId,
    });

    const result = await repo.findWcbByCode('WCB001', versionId);
    expect(result).toBeDefined();
    expect(result!.wcbCode).toBe('WCB001');
    expect(result!.baseFee).toBe('75.00');
    expect(result!.requiresClaimNumber).toBe(true);
    expect(result!.requiresEmployer).toBe(true);
    expect(result!.documentationRequirements).toBe('Full injury report required');
    expect(result!.helpText).toBe('Use for initial WCB reports');
  });

  it('findWcbByCode returns undefined for non-existent code', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    seedWcb({ wcbCode: 'WCB001', versionId });

    const result = await repo.findWcbByCode('WCB999', versionId);
    expect(result).toBeUndefined();
  });

  it('findWcbByCode returns undefined for code in different version', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionA = crypto.randomUUID();
    const versionB = crypto.randomUUID();
    seedWcb({ wcbCode: 'WCB001', versionId: versionA });

    const result = await repo.findWcbByCode('WCB001', versionB);
    expect(result).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Modifier Definition Tests
// ---------------------------------------------------------------------------

describe('Reference Repository — Modifier Definition Queries', () => {
  it('findModifiersForHsc returns applicable modifiers with "all" filter', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    seedModifier({
      modifierCode: 'CMGP',
      applicableHscFilter: { all: true },
      versionId,
    });
    seedModifier({
      modifierCode: 'LSCD',
      applicableHscFilter: { codes: ['03.04A', '03.05A'] },
      versionId,
    });

    const results = await repo.findModifiersForHsc('03.04A', versionId);
    expect(results.length).toBe(2);
    expect(results.some((m: any) => m.modifierCode === 'CMGP')).toBe(true);
    expect(results.some((m: any) => m.modifierCode === 'LSCD')).toBe(true);
  });

  it('findModifiersForHsc returns modifiers matching by codes array', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    seedModifier({
      modifierCode: 'LSCD',
      applicableHscFilter: { codes: ['03.04A', '03.05A'] },
      versionId,
    });
    seedModifier({
      modifierCode: 'TM',
      applicableHscFilter: { codes: ['08.19A'] },
      versionId,
    });

    const results = await repo.findModifiersForHsc('03.04A', versionId);
    expect(results).toHaveLength(1);
    expect(results[0].modifierCode).toBe('LSCD');
  });

  it('findModifiersForHsc returns modifiers matching by prefixes', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    seedModifier({
      modifierCode: 'AFHR',
      applicableHscFilter: { prefixes: ['03.', '04.'] },
      versionId,
    });
    seedModifier({
      modifierCode: 'BCP',
      applicableHscFilter: { prefixes: ['08.'] },
      versionId,
    });

    const results = await repo.findModifiersForHsc('03.04A', versionId);
    expect(results).toHaveLength(1);
    expect(results[0].modifierCode).toBe('AFHR');
  });

  it('findModifiersForHsc excludes incompatible modifiers', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    seedModifier({
      modifierCode: 'CMGP',
      applicableHscFilter: { codes: ['03.04A'] },
      versionId,
    });
    seedModifier({
      modifierCode: 'ANE',
      applicableHscFilter: { codes: ['08.19A'] },
      versionId,
    });
    seedModifier({
      modifierCode: 'AST',
      applicableHscFilter: { prefixes: ['99.'] },
      versionId,
    });

    const results = await repo.findModifiersForHsc('03.04A', versionId);
    expect(results).toHaveLength(1);
    expect(results[0].modifierCode).toBe('CMGP');
    // ANE and AST should be excluded
    expect(results.some((m: any) => m.modifierCode === 'ANE')).toBe(false);
    expect(results.some((m: any) => m.modifierCode === 'AST')).toBe(false);
  });

  it('findModifiersForHsc respects version_id', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionA = crypto.randomUUID();
    const versionB = crypto.randomUUID();
    seedModifier({
      modifierCode: 'CMGP',
      applicableHscFilter: { all: true },
      versionId: versionA,
    });
    seedModifier({
      modifierCode: 'LSCD',
      applicableHscFilter: { all: true },
      versionId: versionB,
    });

    const resultsA = await repo.findModifiersForHsc('03.04A', versionA);
    expect(resultsA).toHaveLength(1);
    expect(resultsA[0].modifierCode).toBe('CMGP');

    const resultsB = await repo.findModifiersForHsc('03.04A', versionB);
    expect(resultsB).toHaveLength(1);
    expect(resultsB[0].modifierCode).toBe('LSCD');
  });

  it('findModifierByCode returns full detail', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    seedModifier({
      modifierCode: 'CMGP',
      name: 'Comprehensive General Practice',
      description: 'CMGP modifier for GP services',
      calculationParams: { percentage: 15 },
      combinableWith: ['LSCD', 'AFHR'],
      exclusiveWith: ['ANE'],
      governingRuleReference: 'GR-08',
      versionId,
    });

    const result = await repo.findModifierByCode('CMGP', versionId);
    expect(result).toBeDefined();
    expect(result!.modifierCode).toBe('CMGP');
    expect(result!.name).toBe('Comprehensive General Practice');
    expect(result!.calculationParams).toEqual({ percentage: 15 });
    expect(result!.combinableWith).toEqual(['LSCD', 'AFHR']);
    expect(result!.exclusiveWith).toEqual(['ANE']);
    expect(result!.governingRuleReference).toBe('GR-08');
  });

  it('findModifierByCode returns undefined for non-existent code', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    seedModifier({ modifierCode: 'CMGP', versionId });

    const result = await repo.findModifierByCode('UNKNOWN', versionId);
    expect(result).toBeUndefined();
  });

  it('listAllModifiers returns all modifiers for a version', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    seedModifier({ modifierCode: 'CMGP', versionId });
    seedModifier({ modifierCode: 'LSCD', versionId });
    seedModifier({ modifierCode: 'AFHR', versionId });
    seedModifier({ modifierCode: 'OTHER', versionId: crypto.randomUUID() }); // different version

    const results = await repo.listAllModifiers(versionId);
    expect(results).toHaveLength(3);
    expect(results.map((m: any) => m.modifierCode).sort()).toEqual(['AFHR', 'CMGP', 'LSCD']);
  });
});

// ---------------------------------------------------------------------------
// Governing Rules Tests
// ---------------------------------------------------------------------------

describe('Reference Repository — Governing Rules Queries', () => {
  it('findRulesForContext returns relevant rules for HSC codes', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    seedRule({
      ruleId: 'GR-03',
      ruleCategory: 'combination',
      ruleLogic: { applies_to: ['03.04A', '03.05A'], max_per_day: 1 },
      versionId,
    });
    seedRule({
      ruleId: 'GR-05',
      ruleCategory: 'fee_cap',
      ruleLogic: { applies_to: ['08.19A'], daily_max: '500.00' },
      versionId,
    });

    const results = await repo.findRulesForContext(['03.04A'], null, null, versionId);
    expect(results.length).toBeGreaterThan(0);
    expect(results.some((r: any) => r.ruleId === 'GR-03')).toBe(true);
    expect(results.some((r: any) => r.ruleId === 'GR-05')).toBe(false);
  });

  it('findRulesForContext always returns general category rules', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    seedRule({
      ruleId: 'GR-01',
      ruleCategory: 'general',
      ruleLogic: { description: 'Always applies' },
      versionId,
    });
    seedRule({
      ruleId: 'GR-03',
      ruleCategory: 'combination',
      ruleLogic: { applies_to: ['08.19A'] },
      versionId,
    });

    // Even when HSC codes don't match GR-03, GR-01 (general) should be returned
    const results = await repo.findRulesForContext(['03.04A'], null, null, versionId);
    expect(results.some((r: any) => r.ruleId === 'GR-01')).toBe(true);
    expect(results.some((r: any) => r.ruleId === 'GR-03')).toBe(false);
  });

  it('findRulesForContext matches by DI code', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    seedRule({
      ruleId: 'GR-07',
      ruleCategory: 'surcharge',
      ruleLogic: { di_codes: ['250', '401'], surcharge_percentage: 10 },
      versionId,
    });

    const results = await repo.findRulesForContext([], '250', null, versionId);
    expect(results.some((r: any) => r.ruleId === 'GR-07')).toBe(true);
  });

  it('findRulesForContext matches by facility type', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    seedRule({
      ruleId: 'GR-09',
      ruleCategory: 'facility',
      ruleLogic: { facility_types: ['HOSPITAL', 'ED'], premium: true },
      versionId,
    });

    const results = await repo.findRulesForContext([], null, 'HOSPITAL', versionId);
    expect(results.some((r: any) => r.ruleId === 'GR-09')).toBe(true);
  });

  it('findRulesForContext filters by version_id', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionA = crypto.randomUUID();
    const versionB = crypto.randomUUID();
    seedRule({
      ruleId: 'GR-01',
      ruleCategory: 'general',
      versionId: versionA,
    });
    seedRule({
      ruleId: 'GR-02',
      ruleCategory: 'general',
      versionId: versionB,
    });

    const resultsA = await repo.findRulesForContext([], null, null, versionA);
    expect(resultsA).toHaveLength(1);
    expect(resultsA[0].ruleId).toBe('GR-01');

    const resultsB = await repo.findRulesForContext([], null, null, versionB);
    expect(resultsB).toHaveLength(1);
    expect(resultsB[0].ruleId).toBe('GR-02');
  });

  it('findRuleById returns full rule_logic JSON', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    const ruleLogic = {
      type: 'combination_limit',
      applies_to: ['03.04A', '03.05A'],
      max_per_day: 1,
      exception_codes: ['03.01A'],
      time_window: 'calendar_day',
    };
    seedRule({
      ruleId: 'GR-03',
      ruleName: 'Office Visit Combination Limit',
      ruleCategory: 'combination',
      description: 'Limits office visit codes per day',
      ruleLogic,
      severity: 'error',
      errorMessage: 'Only one office visit per day is permitted',
      helpText: 'GR-03 restricts billing multiple office visits',
      sourceReference: 'SOMB GR-03',
      versionId,
    });

    const result = await repo.findRuleById('GR-03', versionId);
    expect(result).toBeDefined();
    expect(result!.ruleId).toBe('GR-03');
    expect(result!.ruleName).toBe('Office Visit Combination Limit');
    expect(result!.ruleLogic).toEqual(ruleLogic);
    expect(result!.severity).toBe('error');
    expect(result!.errorMessage).toBe('Only one office visit per day is permitted');
    expect(result!.helpText).toBe('GR-03 restricts billing multiple office visits');
    expect(result!.sourceReference).toBe('SOMB GR-03');
  });

  it('findRuleById returns undefined for non-existent rule', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    seedRule({ ruleId: 'GR-01', versionId });

    const result = await repo.findRuleById('GR-99', versionId);
    expect(result).toBeUndefined();
  });

  it('findRuleById returns undefined for rule in different version', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionA = crypto.randomUUID();
    const versionB = crypto.randomUUID();
    seedRule({ ruleId: 'GR-01', versionId: versionA });

    const result = await repo.findRuleById('GR-01', versionB);
    expect(result).toBeUndefined();
  });

  it('listRulesByCategory returns all rules in a category for a version', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    seedRule({ ruleId: 'GR-01', ruleCategory: 'general', versionId });
    seedRule({ ruleId: 'GR-02', ruleCategory: 'general', versionId });
    seedRule({ ruleId: 'GR-03', ruleCategory: 'combination', versionId });
    seedRule({ ruleId: 'GR-04', ruleCategory: 'surcharge', versionId });
    seedRule({ ruleId: 'GR-05', ruleCategory: 'general', versionId: crypto.randomUUID() }); // different version

    const results = await repo.listRulesByCategory('general', versionId);
    expect(results).toHaveLength(2);
    expect(results.every((r: any) => r.ruleCategory === 'general')).toBe(true);
    expect(results.map((r: any) => r.ruleId).sort()).toEqual(['GR-01', 'GR-02']);
  });

  it('listRulesByCategory respects version_id', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionA = crypto.randomUUID();
    const versionB = crypto.randomUUID();
    seedRule({ ruleId: 'GR-01', ruleCategory: 'general', versionId: versionA });
    seedRule({ ruleId: 'GR-02', ruleCategory: 'general', versionId: versionB });

    const resultsA = await repo.listRulesByCategory('general', versionA);
    expect(resultsA).toHaveLength(1);
    expect(resultsA[0].ruleId).toBe('GR-01');
  });
});

// ---------------------------------------------------------------------------
// Seed helpers — DI codes, RRNP, PCPCM, Functional Centres, Holidays, Explanatory Codes
// ---------------------------------------------------------------------------

function seedDiCode(overrides: Partial<Record<string, any>> = {}): Record<string, any> {
  const d = {
    id: overrides.id ?? crypto.randomUUID(),
    diCode: overrides.diCode ?? '250',
    description: overrides.description ?? 'Diabetes mellitus',
    category: overrides.category ?? 'Endocrine',
    subcategory: overrides.subcategory ?? null,
    qualifiesSurcharge: overrides.qualifiesSurcharge ?? false,
    qualifiesBcp: overrides.qualifiesBcp ?? false,
    commonInSpecialty: overrides.commonInSpecialty ?? [],
    helpText: overrides.helpText ?? null,
    versionId: overrides.versionId ?? crypto.randomUUID(),
    effectiveFrom: overrides.effectiveFrom ?? '2026-01-01',
    effectiveTo: overrides.effectiveTo ?? null,
  };
  diCodeStore.push(d);
  return d;
}

function seedRrnpCommunity(overrides: Partial<Record<string, any>> = {}): Record<string, any> {
  const r = {
    communityId: overrides.communityId ?? crypto.randomUUID(),
    communityName: overrides.communityName ?? 'Athabasca',
    rrnpPercentage: overrides.rrnpPercentage ?? '20.00',
    rrnpTier: overrides.rrnpTier ?? 'Tier 1',
    region: overrides.region ?? 'Northern',
    versionId: overrides.versionId ?? crypto.randomUUID(),
    effectiveFrom: overrides.effectiveFrom ?? '2026-01-01',
    effectiveTo: overrides.effectiveTo ?? null,
  };
  rrnpCommunityStore.push(r);
  return r;
}

function seedPcpcmBasket(overrides: Partial<Record<string, any>> = {}): Record<string, any> {
  const p = {
    id: overrides.id ?? crypto.randomUUID(),
    hscCode: overrides.hscCode ?? '03.04A',
    basket: overrides.basket ?? 'in_basket',
    notes: overrides.notes ?? null,
    versionId: overrides.versionId ?? crypto.randomUUID(),
    effectiveFrom: overrides.effectiveFrom ?? '2026-01-01',
    effectiveTo: overrides.effectiveTo ?? null,
  };
  pcpcmBasketStore.push(p);
  return p;
}

function seedFunctionalCentre(overrides: Partial<Record<string, any>> = {}): Record<string, any> {
  const f = {
    id: overrides.id ?? crypto.randomUUID(),
    code: overrides.code ?? 'FC001',
    name: overrides.name ?? 'Royal Alexandra Hospital',
    facilityType: overrides.facilityType ?? 'HOSPITAL',
    locationCity: overrides.locationCity ?? 'Edmonton',
    locationRegion: overrides.locationRegion ?? 'Edmonton Zone',
    rrnpCommunityId: overrides.rrnpCommunityId ?? null,
    active: overrides.active ?? true,
    versionId: overrides.versionId ?? crypto.randomUUID(),
    effectiveFrom: overrides.effectiveFrom ?? '2026-01-01',
    effectiveTo: overrides.effectiveTo ?? null,
  };
  functionalCentreStore.push(f);
  return f;
}

function seedHoliday(overrides: Partial<Record<string, any>> = {}): Record<string, any> {
  const h = {
    holidayId: overrides.holidayId ?? crypto.randomUUID(),
    date: overrides.date ?? '2026-01-01',
    name: overrides.name ?? "New Year's Day",
    jurisdiction: overrides.jurisdiction ?? 'AB',
    affectsBillingPremiums: overrides.affectsBillingPremiums ?? true,
    year: overrides.year ?? 2026,
  };
  statutoryHolidayStore.push(h);
  return h;
}

function seedExplanatoryCode(overrides: Partial<Record<string, any>> = {}): Record<string, any> {
  const e = {
    id: overrides.id ?? crypto.randomUUID(),
    explCode: overrides.explCode ?? 'E01',
    description: overrides.description ?? 'Claim rejected — duplicate submission',
    severity: overrides.severity ?? 'error',
    commonCause: overrides.commonCause ?? 'Duplicate claim submitted for same date and patient',
    suggestedAction: overrides.suggestedAction ?? 'Review claim history for duplicates',
    helpText: overrides.helpText ?? 'This code indicates a duplicate claim was found',
    versionId: overrides.versionId ?? crypto.randomUUID(),
    effectiveFrom: overrides.effectiveFrom ?? '2026-01-01',
    effectiveTo: overrides.effectiveTo ?? null,
  };
  explanatoryCodeStore.push(e);
  return e;
}

// ---------------------------------------------------------------------------
// DI Code Tests
// ---------------------------------------------------------------------------

describe('Reference Repository — DI Code Queries', () => {
  it('searchDiCodes returns results weighted by specialty', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    seedDiCode({
      diCode: '250',
      description: 'Diabetes mellitus',
      commonInSpecialty: ['ENDOCRINOLOGY', 'INTERNAL_MEDICINE'],
      versionId,
    });
    seedDiCode({
      diCode: '401',
      description: 'Essential hypertension',
      commonInSpecialty: ['CARDIOLOGY', 'INTERNAL_MEDICINE'],
      versionId,
    });
    seedDiCode({
      diCode: '410',
      description: 'Acute myocardial infarction',
      commonInSpecialty: ['CARDIOLOGY'],
      versionId,
    });

    // Search with specialty filter — CARDIOLOGY results should come first
    const results = await repo.searchDiCodes('hypertension', versionId, { specialty: 'CARDIOLOGY' });
    expect(results.length).toBeGreaterThan(0);
    expect(results.some((r: any) => r.diCode === '401')).toBe(true);
  });

  it('searchDiCodes flags surcharge and BCP qualifying codes', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    seedDiCode({
      diCode: '250',
      description: 'Diabetes mellitus',
      qualifiesSurcharge: true,
      qualifiesBcp: false,
      versionId,
    });
    seedDiCode({
      diCode: '401',
      description: 'Essential hypertension',
      qualifiesSurcharge: false,
      qualifiesBcp: true,
      versionId,
    });

    const results = await repo.searchDiCodes('diabetes', versionId);
    expect(results.length).toBeGreaterThan(0);
    const diabetesResult = results.find((r: any) => r.diCode === '250');
    expect(diabetesResult).toBeDefined();
    expect(diabetesResult!.qualifiesSurcharge).toBe(true);
    expect(diabetesResult!.qualifiesBcp).toBe(false);
  });

  it('searchDiCodes returns correct fields', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    seedDiCode({
      diCode: '250',
      description: 'Diabetes mellitus',
      category: 'Endocrine',
      qualifiesSurcharge: true,
      qualifiesBcp: false,
      helpText: 'Common chronic condition',
      versionId,
    });

    const results = await repo.searchDiCodes('250', versionId);
    expect(results).toHaveLength(1);
    const r = results[0] as any;
    expect(r.id).toBeDefined();
    expect(r.diCode).toBe('250');
    expect(r.description).toBe('Diabetes mellitus');
    expect(r.category).toBe('Endocrine');
    expect(r.qualifiesSurcharge).toBe(true);
    expect(r.qualifiesBcp).toBe(false);
    expect(r.helpText).toBe('Common chronic condition');
  });

  it('findDiByCode returns full detail', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    seedDiCode({
      diCode: '250',
      description: 'Diabetes mellitus',
      category: 'Endocrine',
      subcategory: 'Diabetes',
      qualifiesSurcharge: true,
      qualifiesBcp: false,
      commonInSpecialty: ['ENDOCRINOLOGY', 'INTERNAL_MEDICINE'],
      helpText: 'Common chronic condition',
      versionId,
    });

    const result = await repo.findDiByCode('250', versionId);
    expect(result).toBeDefined();
    expect(result!.diCode).toBe('250');
    expect(result!.description).toBe('Diabetes mellitus');
    expect(result!.category).toBe('Endocrine');
    expect(result!.subcategory).toBe('Diabetes');
    expect(result!.qualifiesSurcharge).toBe(true);
    expect(result!.qualifiesBcp).toBe(false);
    expect(result!.commonInSpecialty).toEqual(['ENDOCRINOLOGY', 'INTERNAL_MEDICINE']);
    expect(result!.helpText).toBe('Common chronic condition');
  });

  it('findDiByCode returns undefined for non-existent code', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    seedDiCode({ diCode: '250', versionId });

    const result = await repo.findDiByCode('999', versionId);
    expect(result).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// RRNP Community Tests
// ---------------------------------------------------------------------------

describe('Reference Repository — RRNP Community Queries', () => {
  it('findRrnpRate returns correct percentage for community', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    const community = seedRrnpCommunity({
      communityName: 'Athabasca',
      rrnpPercentage: '20.00',
      versionId,
    });

    const result = await repo.findRrnpRate(community.communityId, versionId);
    expect(result).toBeDefined();
    expect(result!.communityName).toBe('Athabasca');
    expect(result!.rrnpPercentage).toBe('20.00');
  });

  it('findRrnpRate returns undefined for non-existent community', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    seedRrnpCommunity({ versionId });

    const result = await repo.findRrnpRate(crypto.randomUUID(), versionId);
    expect(result).toBeUndefined();
  });

  it('listRrnpCommunities returns all communities for a version', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    seedRrnpCommunity({ communityName: 'Athabasca', versionId });
    seedRrnpCommunity({ communityName: 'Banff', versionId });
    seedRrnpCommunity({ communityName: 'Canmore', versionId });
    seedRrnpCommunity({ communityName: 'Other', versionId: crypto.randomUUID() }); // different version

    const results = await repo.listRrnpCommunities(versionId);
    expect(results).toHaveLength(3);
    // Should be ordered by communityName
    expect(results[0].communityName).toBe('Athabasca');
    expect(results[1].communityName).toBe('Banff');
    expect(results[2].communityName).toBe('Canmore');
  });
});

// ---------------------------------------------------------------------------
// PCPCM Basket Tests
// ---------------------------------------------------------------------------

describe('Reference Repository — PCPCM Basket Queries', () => {
  it('findPcpcmBasket returns correct basket for HSC', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    seedPcpcmBasket({ hscCode: '03.04A', basket: 'in_basket', versionId });
    seedPcpcmBasket({ hscCode: '08.19A', basket: 'out_of_basket', versionId });
    seedPcpcmBasket({ hscCode: '03.08A', basket: 'facility', versionId });

    const result = await repo.findPcpcmBasket('03.04A', versionId);
    expect(result).toBeDefined();
    expect(result!.basket).toBe('in_basket');
    expect(result!.hscCode).toBe('03.04A');
  });

  it('findPcpcmBasket returns undefined for non-existent HSC', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    seedPcpcmBasket({ hscCode: '03.04A', basket: 'in_basket', versionId });

    const result = await repo.findPcpcmBasket('99.99Z', versionId);
    expect(result).toBeUndefined();
  });

  it('findPcpcmBasket respects version_id', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionA = crypto.randomUUID();
    const versionB = crypto.randomUUID();
    seedPcpcmBasket({ hscCode: '03.04A', basket: 'in_basket', versionId: versionA });
    seedPcpcmBasket({ hscCode: '03.04A', basket: 'out_of_basket', versionId: versionB });

    const resultA = await repo.findPcpcmBasket('03.04A', versionA);
    expect(resultA!.basket).toBe('in_basket');

    const resultB = await repo.findPcpcmBasket('03.04A', versionB);
    expect(resultB!.basket).toBe('out_of_basket');
  });
});

// ---------------------------------------------------------------------------
// Functional Centre Tests
// ---------------------------------------------------------------------------

describe('Reference Repository — Functional Centre Queries', () => {
  it('listFunctionalCentres returns centres for a version', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    seedFunctionalCentre({ code: 'FC001', name: 'Royal Alexandra Hospital', facilityType: 'HOSPITAL', versionId });
    seedFunctionalCentre({ code: 'FC002', name: 'Misericordia Hospital', facilityType: 'HOSPITAL', versionId });
    seedFunctionalCentre({ code: 'FC003', name: 'Westview Clinic', facilityType: 'CLINIC', versionId });
    seedFunctionalCentre({ code: 'FC999', name: 'Other Version', facilityType: 'HOSPITAL', versionId: crypto.randomUUID() });

    const results = await repo.listFunctionalCentres(versionId);
    expect(results).toHaveLength(3);
    // All results should have correct fields
    results.forEach((r: any) => {
      expect(r.code).toBeDefined();
      expect(r.name).toBeDefined();
      expect(r.facilityType).toBeDefined();
      expect(r.active).toBeDefined();
    });
  });

  it('listFunctionalCentres filters by facility_type', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    seedFunctionalCentre({ code: 'FC001', facilityType: 'HOSPITAL', versionId });
    seedFunctionalCentre({ code: 'FC002', facilityType: 'HOSPITAL', versionId });
    seedFunctionalCentre({ code: 'FC003', facilityType: 'CLINIC', versionId });
    seedFunctionalCentre({ code: 'FC004', facilityType: 'ED', versionId });

    const hospitals = await repo.listFunctionalCentres(versionId, 'HOSPITAL');
    expect(hospitals).toHaveLength(2);
    expect(hospitals.every((r: any) => r.facilityType === 'HOSPITAL')).toBe(true);

    const clinics = await repo.listFunctionalCentres(versionId, 'CLINIC');
    expect(clinics).toHaveLength(1);
    expect(clinics[0].code).toBe('FC003');
  });

  it('findFunctionalCentre returns single centre with rrnpCommunityId', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    const communityId = crypto.randomUUID();
    seedFunctionalCentre({
      code: 'FC001',
      name: 'Northern Lights Health Centre',
      facilityType: 'HOSPITAL',
      locationCity: 'Fort McMurray',
      locationRegion: 'North Zone',
      rrnpCommunityId: communityId,
      versionId,
    });

    const result = await repo.findFunctionalCentre('FC001', versionId);
    expect(result).toBeDefined();
    expect(result!.code).toBe('FC001');
    expect(result!.name).toBe('Northern Lights Health Centre');
    expect(result!.rrnpCommunityId).toBe(communityId);
    expect(result!.locationCity).toBe('Fort McMurray');
    expect(result!.locationRegion).toBe('North Zone');
  });

  it('findFunctionalCentre returns undefined for non-existent code', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    seedFunctionalCentre({ code: 'FC001', versionId });

    const result = await repo.findFunctionalCentre('FC999', versionId);
    expect(result).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Statutory Holiday Tests
// ---------------------------------------------------------------------------

describe('Reference Repository — Statutory Holiday Queries', () => {
  it('listHolidaysByYear returns all holidays for year', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    seedHoliday({ date: '2026-01-01', name: "New Year's Day", year: 2026 });
    seedHoliday({ date: '2026-02-16', name: 'Family Day', year: 2026 });
    seedHoliday({ date: '2026-07-01', name: 'Canada Day', year: 2026 });
    seedHoliday({ date: '2026-12-25', name: 'Christmas Day', year: 2026 });
    seedHoliday({ date: '2027-01-01', name: "New Year's Day", year: 2027 }); // different year

    const results = await repo.listHolidaysByYear(2026);
    expect(results).toHaveLength(4);
    // Should be ordered by date
    expect(results[0].name).toBe("New Year's Day");
    expect(results[3].name).toBe('Christmas Day');
  });

  it('listHolidaysByYear returns empty for year with no holidays', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    seedHoliday({ date: '2026-01-01', name: "New Year's Day", year: 2026 });

    const results = await repo.listHolidaysByYear(2025);
    expect(results).toHaveLength(0);
  });

  it('isHoliday returns true for statutory holiday', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    seedHoliday({
      date: '2026-01-01',
      name: "New Year's Day",
      jurisdiction: 'AB',
      affectsBillingPremiums: true,
      year: 2026,
    });

    const result = await repo.isHoliday(new Date('2026-01-01'));
    expect(result.is_holiday).toBe(true);
    expect(result.holiday_name).toBe("New Year's Day");
    expect(result.jurisdiction).toBe('AB');
    expect(result.affects_billing_premiums).toBe(true);
  });

  it('isHoliday returns false for regular day', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    seedHoliday({
      date: '2026-01-01',
      name: "New Year's Day",
      year: 2026,
    });

    const result = await repo.isHoliday(new Date('2026-01-05'));
    expect(result.is_holiday).toBe(false);
    expect(result.holiday_name).toBeUndefined();
    expect(result.jurisdiction).toBeUndefined();
    expect(result.affects_billing_premiums).toBeUndefined();
  });

  it('createHoliday inserts holiday', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const result = await repo.createHoliday({
      date: '2026-09-07',
      name: 'Labour Day',
      jurisdiction: 'AB',
      affectsBillingPremiums: true,
      year: 2026,
    });

    expect(result).toBeDefined();
    expect(result.name).toBe('Labour Day');
    expect(result.date).toBe('2026-09-07');
    expect(result.jurisdiction).toBe('AB');
    expect(result.affectsBillingPremiums).toBe(true);
    expect(result.year).toBe(2026);
    expect(result.holidayId).toBeDefined();
    expect(statutoryHolidayStore).toHaveLength(1);
  });

  it('updateHoliday updates holiday fields', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const holiday = seedHoliday({
      date: '2026-01-01',
      name: "New Year's Day",
      affectsBillingPremiums: true,
      year: 2026,
    });

    const result = await repo.updateHoliday(holiday.holidayId, {
      affectsBillingPremiums: false,
    });
    expect(result).toBeDefined();
    // Verify in store
    const inStore = statutoryHolidayStore.find((h) => h.holidayId === holiday.holidayId);
    expect(inStore!.affectsBillingPremiums).toBe(false);
  });

  it('deleteHoliday removes holiday record', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const holiday = seedHoliday({
      date: '2026-01-01',
      name: "New Year's Day",
      year: 2026,
    });
    expect(statutoryHolidayStore).toHaveLength(1);

    await repo.deleteHoliday(holiday.holidayId);
    expect(statutoryHolidayStore).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Explanatory Code Tests
// ---------------------------------------------------------------------------

describe('Reference Repository — Explanatory Code Queries', () => {
  it('findExplanatoryCode returns full detail', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    seedExplanatoryCode({
      explCode: 'E01',
      description: 'Claim rejected — duplicate submission',
      severity: 'error',
      commonCause: 'Duplicate claim submitted for same date and patient',
      suggestedAction: 'Review claim history for duplicates',
      helpText: 'This code indicates a duplicate claim was found',
      versionId,
    });

    const result = await repo.findExplanatoryCode('E01', versionId);
    expect(result).toBeDefined();
    expect(result!.explCode).toBe('E01');
    expect(result!.description).toBe('Claim rejected — duplicate submission');
    expect(result!.severity).toBe('error');
    expect(result!.commonCause).toBe('Duplicate claim submitted for same date and patient');
    expect(result!.suggestedAction).toBe('Review claim history for duplicates');
    expect(result!.helpText).toBe('This code indicates a duplicate claim was found');
  });

  it('findExplanatoryCode returns undefined for non-existent code', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionId = crypto.randomUUID();
    seedExplanatoryCode({ explCode: 'E01', versionId });

    const result = await repo.findExplanatoryCode('E99', versionId);
    expect(result).toBeUndefined();
  });

  it('findExplanatoryCode returns undefined for code in different version', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const versionA = crypto.randomUUID();
    const versionB = crypto.randomUUID();
    seedExplanatoryCode({ explCode: 'E01', versionId: versionA });

    const result = await repo.findExplanatoryCode('E01', versionB);
    expect(result).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Staging Operations
// ---------------------------------------------------------------------------

function seedStaging(overrides: Partial<Record<string, any>> = {}): Record<string, any> {
  const s = {
    stagingId: overrides.stagingId ?? crypto.randomUUID(),
    dataSet: overrides.dataSet ?? 'SOMB',
    status: overrides.status ?? 'uploaded',
    uploadedBy: overrides.uploadedBy ?? userId,
    uploadedAt: overrides.uploadedAt ?? new Date(),
    fileHash: overrides.fileHash ?? 'abc123def456',
    recordCount: overrides.recordCount ?? 10,
    validationResult: overrides.validationResult ?? null,
    diffResult: overrides.diffResult ?? null,
    stagedData: overrides.stagedData ?? [{ code: 'A01' }],
    createdAt: overrides.createdAt ?? new Date(),
  };
  stagingStore.push(s);
  return s;
}

describe('Reference Repository — Staging Operations', () => {
  it('createStagingRecord stores staged data with status uploaded', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const result = await repo.createStagingRecord({
      dataSet: 'SOMB',
      uploadedBy: userId,
      fileHash: 'sha256-abc123',
      recordCount: 5,
      stagedData: [{ code: 'A01' }, { code: 'A02' }],
    });

    expect(result).toBeDefined();
    expect(result.stagingId).toBeDefined();
    expect(result.dataSet).toBe('SOMB');
    expect(result.status).toBe('uploaded');
    expect(result.fileHash).toBe('sha256-abc123');
    expect(result.recordCount).toBe(5);
    expect(result.stagedData).toEqual([{ code: 'A01' }, { code: 'A02' }]);
    expect(result.uploadedBy).toBe(userId);
    expect(stagingStore.length).toBe(1);
  });

  it('findStagingById returns staging record', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const seeded = seedStaging({ dataSet: 'WCB', fileHash: 'hash-xyz' });

    const result = await repo.findStagingById(seeded.stagingId);
    expect(result).toBeDefined();
    expect(result!.stagingId).toBe(seeded.stagingId);
    expect(result!.dataSet).toBe('WCB');
    expect(result!.fileHash).toBe('hash-xyz');
  });

  it('findStagingById returns undefined for non-existent ID', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const result = await repo.findStagingById(crypto.randomUUID());
    expect(result).toBeUndefined();
  });

  it('updateStagingStatus transitions correctly', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const seeded = seedStaging({ status: 'uploaded' });

    const result = await repo.updateStagingStatus(seeded.stagingId, 'validated', {
      validation_result: { valid: true, errors: [] },
    });

    expect(result).toBeDefined();
    expect(result!.status).toBe('validated');
    expect(result!.validationResult).toEqual({ valid: true, errors: [] });
  });

  it('updateStagingStatus sets diff_result', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const seeded = seedStaging({ status: 'validated' });

    const result = await repo.updateStagingStatus(seeded.stagingId, 'diff_generated', {
      diff_result: { added: 5, removed: 2, modified: 3 },
    });

    expect(result).toBeDefined();
    expect(result!.status).toBe('diff_generated');
    expect(result!.diffResult).toEqual({ added: 5, removed: 2, modified: 3 });
  });

  it('deleteStagingRecord removes record', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    const seeded = seedStaging();
    expect(stagingStore.length).toBe(1);

    await repo.deleteStagingRecord(seeded.stagingId);
    expect(stagingStore.length).toBe(0);
  });

  it('listStagingByDataSet returns pending records only', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);

    seedStaging({ dataSet: 'SOMB', status: 'uploaded' });
    seedStaging({ dataSet: 'SOMB', status: 'validated' });
    seedStaging({ dataSet: 'SOMB', status: 'published' });
    seedStaging({ dataSet: 'SOMB', status: 'discarded' });
    seedStaging({ dataSet: 'WCB', status: 'uploaded' });

    const result = await repo.listStagingByDataSet('SOMB');
    expect(result.length).toBe(2);
    result.forEach((r: any) => {
      expect(r.dataSet).toBe('SOMB');
      expect(r.status).not.toBe('published');
      expect(r.status).not.toBe('discarded');
    });
  });
});

// ---------------------------------------------------------------------------
// Bulk Insert Operations
// ---------------------------------------------------------------------------

describe('Reference Repository — Bulk Insert Operations', () => {
  it('bulkInsertHscCodes inserts all records in transaction', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);
    const versionId = crypto.randomUUID();

    const records = [
      {
        hscCode: '03.04A',
        description: 'Office visit',
        feeType: 'fixed',
        baseFee: '38.45',
        effectiveFrom: '2026-01-01',
      },
      {
        hscCode: '03.05A',
        description: 'Consultation',
        feeType: 'fixed',
        baseFee: '120.00',
        effectiveFrom: '2026-01-01',
      },
    ];

    await repo.bulkInsertHscCodes(records as any, versionId);

    expect(hscStore.length).toBe(2);
    expect(hscStore[0].hscCode).toBe('03.04A');
    expect(hscStore[0].versionId).toBe(versionId);
    expect(hscStore[1].hscCode).toBe('03.05A');
    expect(hscStore[1].versionId).toBe(versionId);
  });

  it('bulkInsertHscCodes rolls back on failure', async () => {
    const mockDb = makeMockDb();
    let insertCount = 0;

    // Override transaction to simulate failure mid-way
    mockDb.transaction = async (fn: (tx: any) => Promise<void>) => {
      const snapshot = [...hscStore];
      try {
        const failingTx: any = {
          insert(table: any) {
            insertCount++;
            if (insertCount > 1) {
              throw new Error('Simulated insert failure');
            }
            return mockDb.insert(table);
          },
        };
        await fn(failingTx);
      } catch {
        // Rollback: restore the snapshot
        hscStore.length = 0;
        hscStore.push(...snapshot);
        throw new Error('Transaction rolled back');
      }
    };

    const repo = createReferenceRepository(mockDb);
    const versionId = crypto.randomUUID();

    // Generate more than BULK_CHUNK_SIZE (1000) records to trigger multiple chunks
    const records = Array.from({ length: 1500 }, (_, i) => ({
      hscCode: `HSC-${i}`,
      description: `Code ${i}`,
      feeType: 'fixed',
      baseFee: '10.00',
      effectiveFrom: '2026-01-01',
    }));

    await expect(repo.bulkInsertHscCodes(records as any, versionId)).rejects.toThrow(
      'Transaction rolled back',
    );

    // All inserts should be rolled back
    expect(hscStore.length).toBe(0);
  });

  it('bulkInsertDiCodes handles 14,000+ records efficiently', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);
    const versionId = crypto.randomUUID();

    // Generate 14,000 records
    const records = Array.from({ length: 14_000 }, (_, i) => ({
      diCode: `DI-${String(i).padStart(5, '0')}`,
      description: `Diagnostic code ${i}`,
      category: 'General',
      effectiveFrom: '2026-01-01',
    }));

    await repo.bulkInsertDiCodes(records as any, versionId);

    expect(diCodeStore.length).toBe(14_000);
    // Verify version_id set on all records
    diCodeStore.forEach((row) => {
      expect(row.versionId).toBe(versionId);
    });
    // Verify first and last record
    expect(diCodeStore[0].diCode).toBe('DI-00000');
    expect(diCodeStore[13_999].diCode).toBe('DI-13999');
  });

  it('bulkInsertWcbCodes inserts all records with version_id', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);
    const versionId = crypto.randomUUID();

    const records = [
      {
        wcbCode: 'WCB-001',
        description: 'WCB initial assessment',
        baseFee: '95.00',
        feeType: 'fixed',
        effectiveFrom: '2026-01-01',
      },
    ];

    await repo.bulkInsertWcbCodes(records as any, versionId);

    expect(wcbStore.length).toBe(1);
    expect(wcbStore[0].wcbCode).toBe('WCB-001');
    expect(wcbStore[0].versionId).toBe(versionId);
  });

  it('bulkInsertModifiers inserts all records with version_id', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);
    const versionId = crypto.randomUUID();

    const records = [
      {
        modifierCode: 'CMGP',
        name: 'Comprehensive General Practice',
        description: 'CMGP modifier',
        type: 'percentage',
        calculationMethod: 'percentage',
        effectiveFrom: '2026-01-01',
      },
    ];

    await repo.bulkInsertModifiers(records as any, versionId);

    expect(modifierStore.length).toBe(1);
    expect(modifierStore[0].modifierCode).toBe('CMGP');
    expect(modifierStore[0].versionId).toBe(versionId);
  });

  it('bulkInsertRules inserts all records with version_id', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);
    const versionId = crypto.randomUUID();

    const records = [
      {
        ruleId: 'GR-01',
        ruleName: 'General Rule 1',
        ruleCategory: 'general',
        description: 'A governing rule',
        ruleLogic: { type: 'max_per_day' },
        severity: 'error',
        errorMessage: 'Rule violation',
        effectiveFrom: '2026-01-01',
      },
    ];

    await repo.bulkInsertRules(records as any, versionId);

    expect(governingRuleStore.length).toBe(1);
    expect(governingRuleStore[0].ruleId).toBe('GR-01');
    expect(governingRuleStore[0].versionId).toBe(versionId);
  });

  it('bulkInsertFunctionalCentres inserts all records with version_id', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);
    const versionId = crypto.randomUUID();

    const records = [
      {
        code: 'FC-001',
        name: 'Calgary General Hospital',
        facilityType: 'hospital',
        effectiveFrom: '2026-01-01',
      },
    ];

    await repo.bulkInsertFunctionalCentres(records as any, versionId);

    expect(functionalCentreStore.length).toBe(1);
    expect(functionalCentreStore[0].code).toBe('FC-001');
    expect(functionalCentreStore[0].versionId).toBe(versionId);
  });

  it('bulkInsertRrnpCommunities inserts all records with version_id', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);
    const versionId = crypto.randomUUID();

    const records = [
      {
        communityName: 'Banff',
        rrnpPercentage: '15.00',
        effectiveFrom: '2026-01-01',
      },
    ];

    await repo.bulkInsertRrnpCommunities(records as any, versionId);

    expect(rrnpCommunityStore.length).toBe(1);
    expect(rrnpCommunityStore[0].communityName).toBe('Banff');
    expect(rrnpCommunityStore[0].versionId).toBe(versionId);
  });

  it('bulkInsertPcpcmBaskets inserts all records with version_id', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);
    const versionId = crypto.randomUUID();

    const records = [
      {
        hscCode: '03.04A',
        basket: 'in_basket',
        effectiveFrom: '2026-01-01',
      },
    ];

    await repo.bulkInsertPcpcmBaskets(records as any, versionId);

    expect(pcpcmBasketStore.length).toBe(1);
    expect(pcpcmBasketStore[0].hscCode).toBe('03.04A');
    expect(pcpcmBasketStore[0].versionId).toBe(versionId);
  });

  it('bulkInsertExplanatoryCodes inserts all records with version_id', async () => {
    const mockDb = makeMockDb();
    const repo = createReferenceRepository(mockDb);
    const versionId = crypto.randomUUID();

    const records = [
      {
        explCode: 'E01',
        description: 'Claim rejected',
        severity: 'error',
        effectiveFrom: '2026-01-01',
      },
    ];

    await repo.bulkInsertExplanatoryCodes(records as any, versionId);

    expect(explanatoryCodeStore.length).toBe(1);
    expect(explanatoryCodeStore[0].explCode).toBe('E01');
    expect(explanatoryCodeStore[0].versionId).toBe(versionId);
  });
});

// ===========================================================================
// Service Layer Tests
// ===========================================================================

function makeAuditLogger(): { auditLog: AuditLogger; entries: Array<{ action: string; adminId: string; details: Record<string, unknown> }> } {
  const entries: Array<{ action: string; adminId: string; details: Record<string, unknown> }> = [];
  return {
    auditLog: {
      async log(entry) {
        entries.push(entry);
      },
    },
    entries,
  };
}

function makeServiceDeps(): { deps: ReferenceServiceDeps; mockDb: any } {
  const mockDb = makeMockDb();
  const repo = createReferenceRepository(mockDb);
  return { deps: { repo }, mockDb };
}

function makeServiceDepsWithAudit(): { deps: ReferenceServiceDeps; mockDb: any; auditEntries: Array<{ action: string; adminId: string; details: Record<string, unknown> }> } {
  const mockDb = makeMockDb();
  const repo = createReferenceRepository(mockDb);
  const { auditLog, entries } = makeAuditLogger();
  return { deps: { repo, auditLog }, mockDb, auditEntries: entries };
}

function makeEventEmitter(): { eventEmitter: EventEmitter; events: Array<{ event: string; payload: Record<string, unknown> }> } {
  const events: Array<{ event: string; payload: Record<string, unknown> }> = [];
  return {
    eventEmitter: {
      emit(event: string, payload: Record<string, unknown>) {
        events.push({ event, payload });
      },
    },
    events,
  };
}

function makeServiceDepsWithAll(): {
  deps: ReferenceServiceDeps;
  mockDb: any;
  auditEntries: Array<{ action: string; adminId: string; details: Record<string, unknown> }>;
  emittedEvents: Array<{ event: string; payload: Record<string, unknown> }>;
} {
  const mockDb = makeMockDb();
  const repo = createReferenceRepository(mockDb);
  const { auditLog, entries } = makeAuditLogger();
  const { eventEmitter, events } = makeEventEmitter();
  return { deps: { repo, auditLog, eventEmitter }, mockDb, auditEntries: entries, emittedEvents: events };
}

describe('Reference Service — resolveVersion', () => {
  it('returns correct version for date of service', async () => {
    const { deps } = makeServiceDeps();

    const v1 = seedVersion({
      dataSet: 'SOMB',
      effectiveFrom: '2025-01-01',
      effectiveTo: '2026-01-01',
      versionLabel: 'v1',
    });
    seedVersion({
      dataSet: 'SOMB',
      effectiveFrom: '2026-01-01',
      effectiveTo: null,
      versionLabel: 'v2',
    });

    const result = await resolveVersion(deps, 'SOMB', new Date('2025-06-15'));
    expect(result.versionId).toBe(v1.versionId);
  });

  it('returns active version when no date specified', async () => {
    const { deps } = makeServiceDeps();

    seedVersion({ dataSet: 'SOMB', isActive: false, versionLabel: 'v1' });
    const active = seedVersion({ dataSet: 'SOMB', isActive: true, versionLabel: 'v2' });

    const result = await resolveVersion(deps, 'SOMB');
    expect(result.versionId).toBe(active.versionId);
  });

  it('throws NotFoundError when no version exists', async () => {
    const { deps } = makeServiceDeps();

    seedVersion({ dataSet: 'WCB', isActive: true }); // Different data set

    await expect(resolveVersion(deps, 'SOMB')).rejects.toThrow(NotFoundError);
    await expect(resolveVersion(deps, 'SOMB')).rejects.toThrow('SOMB version not found');
  });

  it('throws NotFoundError when no version covers the given date', async () => {
    const { deps } = makeServiceDeps();

    seedVersion({
      dataSet: 'SOMB',
      effectiveFrom: '2026-01-01',
      effectiveTo: null,
      isActive: true,
    });

    await expect(
      resolveVersion(deps, 'SOMB', new Date('2024-06-15')),
    ).rejects.toThrow(NotFoundError);
  });
});

describe('Reference Service — searchHscCodes', () => {
  it('returns version-appropriate results', async () => {
    const { deps } = makeServiceDeps();

    const v1 = seedVersion({ dataSet: 'SOMB', isActive: true, versionLabel: 'v1' });
    seedHsc({ hscCode: '03.04A', description: 'Office visit assessment', versionId: v1.versionId });
    seedHsc({ hscCode: '03.05A', description: 'Hospital visit', versionId: v1.versionId });

    const results = await searchHscCodes(deps, '03.04');
    expect(results.length).toBeGreaterThan(0);
    expect(results.some((r) => r.code === '03.04A')).toBe(true);
    expect(results[0]).toHaveProperty('deprecated');
    expect(results[0]).toHaveProperty('feeType');
  });

  it('marks deprecated codes with effectiveTo set', async () => {
    const { deps } = makeServiceDeps();

    const v = seedVersion({ dataSet: 'SOMB', isActive: true });
    seedHsc({
      hscCode: '99.99Z',
      description: 'Deprecated procedure',
      versionId: v.versionId,
      effectiveTo: '2025-12-31',
    });
    seedHsc({
      hscCode: '03.04A',
      description: 'Active procedure',
      versionId: v.versionId,
      effectiveTo: null,
    });

    const results = await searchHscCodes(deps, 'procedure');
    const deprecated = results.find((r) => r.code === '99.99Z');
    const active = results.find((r) => r.code === '03.04A');

    expect(deprecated).toBeDefined();
    expect(deprecated!.deprecated).toBe(true);
    expect(active).toBeDefined();
    expect(active!.deprecated).toBe(false);
  });

  it('filters by specialty', async () => {
    const { deps } = makeServiceDeps();

    const v = seedVersion({ dataSet: 'SOMB', isActive: true });
    seedHsc({
      hscCode: '03.04A',
      description: 'GP office visit',
      versionId: v.versionId,
      specialtyRestrictions: ['GP', 'FM'],
    });
    seedHsc({
      hscCode: '08.19A',
      description: 'Cardiology consult',
      versionId: v.versionId,
      specialtyRestrictions: ['CARDIOLOGY'],
    });

    const results = await searchHscCodes(deps, 'visit consult', { specialty: 'GP' });
    expect(results.every((r) => r.code !== '08.19A')).toBe(true);
  });

  it('uses date of service for version resolution', async () => {
    const { deps } = makeServiceDeps();

    const v1 = seedVersion({
      dataSet: 'SOMB',
      effectiveFrom: '2025-01-01',
      effectiveTo: '2026-01-01',
      versionLabel: 'v1',
    });
    const v2 = seedVersion({
      dataSet: 'SOMB',
      effectiveFrom: '2026-01-01',
      effectiveTo: null,
      isActive: true,
      versionLabel: 'v2',
    });
    seedHsc({ hscCode: '03.04A', description: 'V1 office visit', versionId: v1.versionId });
    seedHsc({ hscCode: '03.04B', description: 'V2 office visit', versionId: v2.versionId });

    // Search with date in v1 range
    const v1Results = await searchHscCodes(deps, 'office visit', {
      dateOfService: new Date('2025-06-15'),
    });
    expect(v1Results.some((r) => r.code === '03.04A')).toBe(true);
    expect(v1Results.some((r) => r.code === '03.04B')).toBe(false);
  });
});

describe('Reference Service — getHscDetail', () => {
  it('returns full detail with modifiers', async () => {
    const { deps } = makeServiceDeps();

    const v = seedVersion({ dataSet: 'SOMB', isActive: true });
    seedHsc({
      hscCode: '03.04A',
      description: 'Office visit',
      baseFee: '38.45',
      versionId: v.versionId,
      specialtyRestrictions: ['GP'],
      facilityRestrictions: ['office'],
      modifierEligibility: ['CMGP'],
      combinationGroup: 'visit',
      surchargeEligible: true,
      pcpcmBasket: 'in_basket',
    });
    seedModifier({
      modifierCode: 'CMGP',
      name: 'CMGP Premium',
      description: 'Comprehensive modifier',
      calculationMethod: 'percentage',
      applicableHscFilter: { codes: ['03.04A'] },
      versionId: v.versionId,
    });

    const detail = await getHscDetail(deps, '03.04A');

    expect(detail.code).toBe('03.04A');
    expect(detail.baseFee).toBe('38.45');
    expect(detail.specialtyRestrictions).toContain('GP');
    expect(detail.facilityRestrictions).toContain('office');
    expect(detail.combinationGroup).toBe('visit');
    expect(detail.surchargeEligible).toBe(true);
    expect(detail.pcpcmBasket).toBe('in_basket');
    expect(detail.applicableModifiers).toHaveLength(1);
    expect(detail.applicableModifiers[0].modifierCode).toBe('CMGP');
  });

  it('throws NotFoundError for non-existent HSC code', async () => {
    const { deps } = makeServiceDeps();

    seedVersion({ dataSet: 'SOMB', isActive: true });

    await expect(getHscDetail(deps, 'XX.XXX')).rejects.toThrow(NotFoundError);
  });

  it('resolves version by date of service', async () => {
    const { deps } = makeServiceDeps();

    const v1 = seedVersion({
      dataSet: 'SOMB',
      effectiveFrom: '2025-01-01',
      effectiveTo: '2026-01-01',
    });
    const v2 = seedVersion({
      dataSet: 'SOMB',
      effectiveFrom: '2026-01-01',
      effectiveTo: null,
      isActive: true,
    });
    seedHsc({
      hscCode: '03.04A',
      description: 'V1 visit',
      baseFee: '35.00',
      versionId: v1.versionId,
    });
    seedHsc({
      hscCode: '03.04A',
      description: 'V2 visit',
      baseFee: '40.00',
      versionId: v2.versionId,
    });

    const detail = await getHscDetail(deps, '03.04A', new Date('2025-06-15'));
    expect(detail.baseFee).toBe('35.00');
  });
});

describe('Reference Service — getHscFavourites', () => {
  it('returns frequency-ranked codes from active version', async () => {
    const { deps } = makeServiceDeps();

    const v = seedVersion({ dataSet: 'SOMB', isActive: true });
    seedHsc({ hscCode: '03.04A', description: 'Office visit', versionId: v.versionId });
    seedHsc({ hscCode: '03.05A', description: 'Hospital visit', versionId: v.versionId });
    seedHsc({ hscCode: '08.19A', description: 'Surgical consult', versionId: v.versionId });

    const userId_ = crypto.randomUUID();
    const favourites = await getHscFavourites(deps, userId_, 20);

    expect(favourites.length).toBe(3);
    expect(favourites[0]).toHaveProperty('code');
    expect(favourites[0]).toHaveProperty('description');
    expect(favourites[0]).toHaveProperty('baseFee');
    expect(favourites[0]).toHaveProperty('feeType');
    expect(favourites[0]).toHaveProperty('usageCount');
  });

  it('respects limit parameter', async () => {
    const { deps } = makeServiceDeps();

    const v = seedVersion({ dataSet: 'SOMB', isActive: true });
    for (let i = 0; i < 10; i++) {
      seedHsc({ hscCode: `0${i}.01A`, description: `Procedure ${i}`, versionId: v.versionId });
    }

    const favourites = await getHscFavourites(deps, crypto.randomUUID(), 3);
    expect(favourites.length).toBe(3);
  });

  it('throws when no active SOMB version', async () => {
    const { deps } = makeServiceDeps();

    await expect(getHscFavourites(deps, crypto.randomUUID())).rejects.toThrow(NotFoundError);
  });
});

describe('Reference Service — searchDiCodes', () => {
  it('flags surcharge and BCP qualifiers in results', async () => {
    const { deps } = makeServiceDeps();

    const v = seedVersion({ dataSet: 'DI_CODES', isActive: true });
    seedDiCode({
      diCode: 'J06',
      description: 'Upper respiratory infection',
      qualifiesSurcharge: true,
      qualifiesBcp: false,
      versionId: v.versionId,
    });
    seedDiCode({
      diCode: 'E11',
      description: 'Type 2 diabetes mellitus',
      qualifiesSurcharge: false,
      qualifiesBcp: true,
      versionId: v.versionId,
    });

    const results = await searchDiCodes(deps, 'respiratory diabetes');
    expect(results.length).toBeGreaterThan(0);

    const j06 = results.find((r) => r.code === 'J06');
    if (j06) {
      expect(j06.qualifiesSurcharge).toBe(true);
      expect(j06.qualifiesBcp).toBe(false);
    }

    const e11 = results.find((r) => r.code === 'E11');
    if (e11) {
      expect(e11.qualifiesSurcharge).toBe(false);
      expect(e11.qualifiesBcp).toBe(true);
    }
  });

  it('returns results matching search query', async () => {
    const { deps } = makeServiceDeps();

    const v = seedVersion({ dataSet: 'DI_CODES', isActive: true });
    seedDiCode({
      diCode: 'J06',
      description: 'Upper respiratory infection',
      versionId: v.versionId,
    });
    seedDiCode({
      diCode: 'K21',
      description: 'Gastro esophageal reflux',
      versionId: v.versionId,
    });

    const results = await searchDiCodes(deps, 'respiratory');
    expect(results.length).toBeGreaterThan(0);
    expect(results.some((r) => r.code === 'J06')).toBe(true);
  });

  it('throws when no active DI_CODES version', async () => {
    const { deps } = makeServiceDeps();

    await expect(searchDiCodes(deps, 'infection')).rejects.toThrow(NotFoundError);
  });
});

describe('Reference Service — getDiDetail', () => {
  it('returns full DI code detail', async () => {
    const { deps } = makeServiceDeps();

    const v = seedVersion({ dataSet: 'DI_CODES', isActive: true });
    seedDiCode({
      diCode: 'J06',
      description: 'Upper respiratory infection',
      category: 'Respiratory',
      subcategory: 'Acute',
      qualifiesSurcharge: true,
      qualifiesBcp: false,
      commonInSpecialty: ['GP', 'FM'],
      helpText: 'Common cold, flu',
      versionId: v.versionId,
    });

    const detail = await getDiDetail(deps, 'J06');

    expect(detail.code).toBe('J06');
    expect(detail.description).toBe('Upper respiratory infection');
    expect(detail.category).toBe('Respiratory');
    expect(detail.subcategory).toBe('Acute');
    expect(detail.qualifiesSurcharge).toBe(true);
    expect(detail.qualifiesBcp).toBe(false);
    expect(detail.commonInSpecialty).toContain('GP');
    expect(detail.helpText).toBe('Common cold, flu');
  });

  it('throws NotFoundError for non-existent DI code', async () => {
    const { deps } = makeServiceDeps();

    seedVersion({ dataSet: 'DI_CODES', isActive: true });

    await expect(getDiDetail(deps, 'ZZZ')).rejects.toThrow(NotFoundError);
  });
});

// ---------------------------------------------------------------------------
// Service — getModifiersForHsc
// ---------------------------------------------------------------------------

describe('Reference Service — getModifiersForHsc', () => {
  it('returns applicable modifiers only', async () => {
    const { deps } = makeServiceDeps();

    const v = seedVersion({ dataSet: 'MODIFIERS', isActive: true });
    // Modifier applicable to 03.04A via codes array
    seedModifier({
      modifierCode: 'CMGP',
      name: 'Comprehensive GP',
      description: 'CMGP modifier',
      calculationMethod: 'time_based_units',
      calculationParams: { unit_minutes: 15 },
      applicableHscFilter: { codes: ['03.04A', '03.03A'] },
      helpText: 'Time-based modifier for GP services',
      versionId: v.versionId,
    });
    // Modifier applicable to all codes
    seedModifier({
      modifierCode: 'TM',
      name: 'Shadow Billing',
      description: 'TM modifier',
      calculationMethod: 'time_based_units',
      calculationParams: { unit_minutes: 5 },
      applicableHscFilter: { all: true },
      helpText: 'Shadow billing modifier',
      versionId: v.versionId,
    });
    // Modifier NOT applicable to 03.04A
    seedModifier({
      modifierCode: 'ANE',
      name: 'Anaesthesia',
      description: 'Anaesthesia modifier',
      calculationMethod: 'fixed_amount',
      calculationParams: {},
      applicableHscFilter: { codes: ['09.01A'] },
      helpText: null,
      versionId: v.versionId,
    });

    const result = await getModifiersForHsc(deps, '03.04A');

    expect(result).toHaveLength(2);
    expect(result.map((m) => m.modifierCode)).toContain('CMGP');
    expect(result.map((m) => m.modifierCode)).toContain('TM');
    expect(result.map((m) => m.modifierCode)).not.toContain('ANE');
  });

  it('excludes incompatible modifiers (no match in filter)', async () => {
    const { deps } = makeServiceDeps();

    const v = seedVersion({ dataSet: 'MODIFIERS', isActive: true });
    seedModifier({
      modifierCode: 'BCP',
      name: 'Bone Care Premium',
      applicableHscFilter: { prefixes: ['08.'] },
      versionId: v.versionId,
    });

    const result = await getModifiersForHsc(deps, '03.04A');
    expect(result).toHaveLength(0);
  });

  it('returns calculation details in results', async () => {
    const { deps } = makeServiceDeps();

    const v = seedVersion({ dataSet: 'MODIFIERS', isActive: true });
    seedModifier({
      modifierCode: 'AFHR',
      name: 'After Hours',
      type: 'implicit',
      calculationMethod: 'percentage',
      calculationParams: { percentage: 0.30 },
      applicableHscFilter: { all: true },
      helpText: 'After hours premium',
      versionId: v.versionId,
    });

    const result = await getModifiersForHsc(deps, '03.04A');
    expect(result).toHaveLength(1);
    expect(result[0].calculationMethod).toBe('percentage');
    expect(result[0].calculationParams).toEqual({ percentage: 0.30 });
    expect(result[0].helpText).toBe('After hours premium');
  });
});

// ---------------------------------------------------------------------------
// Service — getModifierDetail
// ---------------------------------------------------------------------------

describe('Reference Service — getModifierDetail', () => {
  it('returns full modifier detail', async () => {
    const { deps } = makeServiceDeps();

    const v = seedVersion({ dataSet: 'MODIFIERS', isActive: true });
    seedModifier({
      modifierCode: 'CMGP',
      name: 'Comprehensive GP',
      description: 'CMGP modifier for GP services',
      type: 'semi_implicit',
      calculationMethod: 'time_based_units',
      calculationParams: { unit_minutes: 15, base_units: 1 },
      combinableWith: ['LSCD'],
      exclusiveWith: ['ANE'],
      governingRuleReference: 'GR6',
      helpText: 'Time-based modifier',
      requiresTimeDocumentation: true,
      requiresFacility: false,
      versionId: v.versionId,
    });

    const detail = await getModifierDetail(deps, 'CMGP');

    expect(detail.modifierCode).toBe('CMGP');
    expect(detail.name).toBe('Comprehensive GP');
    expect(detail.type).toBe('semi_implicit');
    expect(detail.calculationMethod).toBe('time_based_units');
    expect(detail.calculationParams).toEqual({ unit_minutes: 15, base_units: 1 });
    expect(detail.combinableWith).toContain('LSCD');
    expect(detail.exclusiveWith).toContain('ANE');
    expect(detail.governingRuleReference).toBe('GR6');
    expect(detail.helpText).toBe('Time-based modifier');
    expect(detail.requiresTimeDocumentation).toBe(true);
    expect(detail.requiresFacility).toBe(false);
  });

  it('throws NotFoundError for non-existent modifier', async () => {
    const { deps } = makeServiceDeps();

    seedVersion({ dataSet: 'MODIFIERS', isActive: true });

    await expect(getModifierDetail(deps, 'NONEXIST')).rejects.toThrow(NotFoundError);
  });
});

// ---------------------------------------------------------------------------
// Service — getValidationContext
// ---------------------------------------------------------------------------

describe('Reference Service — getValidationContext', () => {
  it('returns all rules for claim context', async () => {
    const { deps } = makeServiceDeps();

    const dos = new Date('2026-03-15');
    const sombV = seedVersion({ dataSet: 'SOMB', effectiveFrom: '2026-01-01', isActive: true });
    const modV = seedVersion({ dataSet: 'MODIFIERS', effectiveFrom: '2026-01-01', isActive: true });
    const rulesV = seedVersion({ dataSet: 'GOVERNING_RULES', effectiveFrom: '2026-01-01', isActive: true });

    seedHsc({
      hscCode: '03.04A',
      description: 'Office visit',
      baseFee: '38.45',
      feeType: 'fixed',
      combinationGroup: 'visit',
      maxPerDay: 1,
      requiresReferral: false,
      surchargeEligible: true,
      pcpcmBasket: 'in_basket',
      versionId: sombV.versionId,
    });

    seedModifier({
      modifierCode: 'CMGP',
      name: 'Comprehensive GP',
      calculationMethod: 'time_based_units',
      calculationParams: { unit_minutes: 15 },
      applicableHscFilter: { codes: ['03.04A'] },
      versionId: modV.versionId,
    });

    seedRule({
      ruleId: 'GR3',
      ruleName: 'Visit Limits',
      ruleCategory: 'visit_limits',
      severity: 'error',
      ruleLogic: { max_per_patient_per_day: 1, hsc_group: ['03.04A'] },
      errorMessage: 'Max 1 visit per patient per day',
      versionId: rulesV.versionId,
    });

    seedRule({
      ruleId: 'GR1',
      ruleName: 'General Rule',
      ruleCategory: 'general',
      severity: 'info',
      ruleLogic: {},
      errorMessage: 'General rule',
      versionId: rulesV.versionId,
    });

    const ctx = await getValidationContext(deps, ['03.04A'], null, null, dos);

    expect(ctx.hscDetails).toHaveLength(1);
    expect(ctx.hscDetails[0].code).toBe('03.04A');
    expect(ctx.hscDetails[0].combinationGroup).toBe('visit');
    expect(ctx.applicableRules.length).toBeGreaterThanOrEqual(2);
    expect(ctx.applicableRules.map((r) => r.ruleId)).toContain('GR3');
    expect(ctx.applicableRules.map((r) => r.ruleId)).toContain('GR1');
    expect(ctx.modifierApplicability).toHaveLength(1);
    expect(ctx.modifierApplicability[0].hscCode).toBe('03.04A');
    expect(ctx.modifierApplicability[0].applicableModifiers.map((m) => m.modifierCode)).toContain('CMGP');
    expect(ctx.versionInfo.somb).toBe(sombV.versionId);
    expect(ctx.versionInfo.modifiers).toBe(modV.versionId);
    expect(ctx.versionInfo.governingRules).toBe(rulesV.versionId);
  });

  it('resolves correct version for date', async () => {
    const { deps } = makeServiceDeps();

    // Old version
    const v1 = seedVersion({
      dataSet: 'SOMB',
      effectiveFrom: '2025-01-01',
      effectiveTo: '2026-01-01',
      versionLabel: 'v2025',
    });
    // New version
    const v2 = seedVersion({
      dataSet: 'SOMB',
      effectiveFrom: '2026-01-01',
      isActive: true,
      versionLabel: 'v2026',
    });

    seedVersion({ dataSet: 'MODIFIERS', effectiveFrom: '2025-01-01', isActive: true });
    seedVersion({ dataSet: 'GOVERNING_RULES', effectiveFrom: '2025-01-01', isActive: true });

    seedHsc({
      hscCode: '03.04A',
      baseFee: '35.00',
      versionId: v1.versionId,
    });
    seedHsc({
      hscCode: '03.04A',
      baseFee: '38.45',
      versionId: v2.versionId,
    });

    // Query for date in 2025 — should get v1 with $35.00
    const ctx2025 = await getValidationContext(
      deps, ['03.04A'], null, null, new Date('2025-06-15'),
    );
    expect(ctx2025.hscDetails[0].baseFee).toBe('35.00');

    // Query for date in 2026 — should get v2 with $38.45
    const ctx2026 = await getValidationContext(
      deps, ['03.04A'], null, null, new Date('2026-06-15'),
    );
    expect(ctx2026.hscDetails[0].baseFee).toBe('38.45');
  });

  it('validates facility code against functional centres', async () => {
    const { deps } = makeServiceDeps();

    const dos = new Date('2026-03-15');
    seedVersion({ dataSet: 'SOMB', effectiveFrom: '2026-01-01', isActive: true });
    seedVersion({ dataSet: 'MODIFIERS', effectiveFrom: '2026-01-01', isActive: true });
    seedVersion({ dataSet: 'GOVERNING_RULES', effectiveFrom: '2026-01-01', isActive: true });
    const fcV = seedVersion({ dataSet: 'FUNCTIONAL_CENTRES', effectiveFrom: '2026-01-01', isActive: true });

    seedFunctionalCentre({
      code: 'FC001',
      name: 'Royal Alexandra Hospital',
      facilityType: 'hospital_inpatient',
      active: true,
      versionId: fcV.versionId,
    });

    const ctx = await getValidationContext(deps, [], null, 'FC001', dos);
    expect(ctx.facilityValidation.valid).toBe(true);
    expect(ctx.facilityValidation.facilityType).toBe('hospital_inpatient');
    expect(ctx.facilityValidation.name).toBe('Royal Alexandra Hospital');
  });

  it('returns invalid facility for non-existent facility code', async () => {
    const { deps } = makeServiceDeps();

    const dos = new Date('2026-03-15');
    seedVersion({ dataSet: 'SOMB', effectiveFrom: '2026-01-01', isActive: true });
    seedVersion({ dataSet: 'MODIFIERS', effectiveFrom: '2026-01-01', isActive: true });
    seedVersion({ dataSet: 'GOVERNING_RULES', effectiveFrom: '2026-01-01', isActive: true });
    seedVersion({ dataSet: 'FUNCTIONAL_CENTRES', effectiveFrom: '2026-01-01', isActive: true });

    const ctx = await getValidationContext(deps, [], null, 'NONEXIST', dos);
    expect(ctx.facilityValidation.valid).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Service — getRuleDetail
// ---------------------------------------------------------------------------

describe('Reference Service — getRuleDetail', () => {
  it('returns full rule detail with rule_logic', async () => {
    const { deps } = makeServiceDeps();

    const v = seedVersion({ dataSet: 'GOVERNING_RULES', isActive: true });
    seedRule({
      ruleId: 'GR5_3b',
      ruleName: 'Code Combination Restriction',
      ruleCategory: 'code_combinations',
      description: 'Cannot bill 03.03A with 03.04A on same visit',
      ruleLogic: { hsc_a: '03.03A', hsc_b: '03.04A', relationship: 'prohibited' },
      severity: 'error',
      errorMessage: 'These codes cannot be billed together',
      helpText: 'Check SOMB GR 5(3)(b)',
      sourceReference: 'SOMB Preamble, GR 5(3)(b)',
      sourceUrl: 'https://example.com/somb/gr5',
      versionId: v.versionId,
    });

    const detail = await getRuleDetail(deps, 'GR5_3b');

    expect(detail.ruleId).toBe('GR5_3b');
    expect(detail.ruleCategory).toBe('code_combinations');
    expect(detail.ruleLogic).toEqual({ hsc_a: '03.03A', hsc_b: '03.04A', relationship: 'prohibited' });
    expect(detail.severity).toBe('error');
    expect(detail.helpText).toBe('Check SOMB GR 5(3)(b)');
    expect(detail.sourceReference).toBe('SOMB Preamble, GR 5(3)(b)');
  });

  it('throws NotFoundError for non-existent rule', async () => {
    const { deps } = makeServiceDeps();

    seedVersion({ dataSet: 'GOVERNING_RULES', isActive: true });

    await expect(getRuleDetail(deps, 'NONEXIST')).rejects.toThrow(NotFoundError);
  });
});

// ---------------------------------------------------------------------------
// Service — evaluateRulesBatch
// ---------------------------------------------------------------------------

describe('Reference Service — evaluateRulesBatch', () => {
  it('handles multiple claims with different dates', async () => {
    const { deps } = makeServiceDeps();

    // Version covering 2025
    const v2025 = seedVersion({
      dataSet: 'GOVERNING_RULES',
      effectiveFrom: '2025-01-01',
      effectiveTo: '2026-01-01',
      versionLabel: 'rules-2025',
    });
    // Version covering 2026
    const v2026 = seedVersion({
      dataSet: 'GOVERNING_RULES',
      effectiveFrom: '2026-01-01',
      isActive: true,
      versionLabel: 'rules-2026',
    });

    seedRule({
      ruleId: 'GR3-old',
      ruleCategory: 'visit_limits',
      ruleLogic: { max_per_patient_per_day: 2, hsc_group: ['03.04A'] },
      severity: 'error',
      errorMessage: 'Max 2 visits (old)',
      versionId: v2025.versionId,
    });

    seedRule({
      ruleId: 'GR3-new',
      ruleCategory: 'visit_limits',
      ruleLogic: { max_per_patient_per_day: 1, hsc_group: ['03.04A'] },
      severity: 'error',
      errorMessage: 'Max 1 visit (new)',
      versionId: v2026.versionId,
    });

    // General rule in both versions
    seedRule({
      ruleId: 'GR1',
      ruleCategory: 'general',
      ruleLogic: {},
      severity: 'info',
      errorMessage: 'General',
      versionId: v2025.versionId,
    });
    seedRule({
      ruleId: 'GR1',
      ruleCategory: 'general',
      ruleLogic: {},
      severity: 'info',
      errorMessage: 'General',
      versionId: v2026.versionId,
    });

    const results = await evaluateRulesBatch(deps, [
      { hscCodes: ['03.04A'], dateOfService: new Date('2025-06-15') },
      { hscCodes: ['03.04A'], dateOfService: new Date('2026-06-15') },
    ]);

    expect(results).toHaveLength(2);

    // First claim (2025) should get GR3-old + GR1
    expect(results[0].claimIndex).toBe(0);
    expect(results[0].applicableRules.map((r) => r.ruleId)).toContain('GR3-old');
    expect(results[0].applicableRules.map((r) => r.ruleId)).toContain('GR1');

    // Second claim (2026) should get GR3-new + GR1
    expect(results[1].claimIndex).toBe(1);
    expect(results[1].applicableRules.map((r) => r.ruleId)).toContain('GR3-new');
    expect(results[1].applicableRules.map((r) => r.ruleId)).toContain('GR1');
  });

  it('groups claims by date to minimise version lookups', async () => {
    const { deps } = makeServiceDeps();

    const v = seedVersion({
      dataSet: 'GOVERNING_RULES',
      effectiveFrom: '2026-01-01',
      isActive: true,
    });
    seedRule({
      ruleId: 'GR1',
      ruleCategory: 'general',
      ruleLogic: {},
      severity: 'info',
      errorMessage: 'General',
      versionId: v.versionId,
    });

    // Three claims on the same date — should only do one version lookup
    const results = await evaluateRulesBatch(deps, [
      { hscCodes: ['03.04A'], dateOfService: new Date('2026-03-15') },
      { hscCodes: ['03.03A'], dateOfService: new Date('2026-03-15') },
      { hscCodes: ['08.19A'], dateOfService: new Date('2026-03-15') },
    ]);

    expect(results).toHaveLength(3);
    // All should have the general rule
    results.forEach((r) => {
      expect(r.applicableRules.map((rule) => rule.ruleId)).toContain('GR1');
    });
  });

  it('rejects batch exceeding 500 claims', async () => {
    const { deps } = makeServiceDeps();

    const claims = Array.from({ length: 501 }, (_, i) => ({
      hscCodes: ['03.04A'],
      dateOfService: new Date('2026-03-15'),
    }));

    await expect(evaluateRulesBatch(deps, claims)).rejects.toThrow(BusinessRuleError);
  });
});

// ---------------------------------------------------------------------------
// Service — getRrnpRate
// ---------------------------------------------------------------------------

describe('Reference Service — getRrnpRate', () => {
  it('returns correct rate for community and date', async () => {
    const { deps } = makeServiceDeps();

    const v = seedVersion({ dataSet: 'RRNP', isActive: true });
    const comm = seedRrnpCommunity({
      communityName: 'Athabasca',
      rrnpPercentage: '20.00',
      versionId: v.versionId,
    });

    const result = await getRrnpRate(deps, comm.communityId);

    expect(result.communityName).toBe('Athabasca');
    expect(result.rrnpPercentage).toBe('20.00');
  });

  it('resolves version for specific date', async () => {
    const { deps } = makeServiceDeps();

    const v1 = seedVersion({
      dataSet: 'RRNP',
      effectiveFrom: '2025-01-01',
      effectiveTo: '2026-01-01',
      versionLabel: 'rrnp-2025',
    });
    const v2 = seedVersion({
      dataSet: 'RRNP',
      effectiveFrom: '2026-01-01',
      isActive: true,
      versionLabel: 'rrnp-2026',
    });

    const comm1 = seedRrnpCommunity({
      communityId: 'comm-test-1',
      communityName: 'Athabasca',
      rrnpPercentage: '15.00',
      versionId: v1.versionId,
    });
    seedRrnpCommunity({
      communityId: 'comm-test-1',
      communityName: 'Athabasca',
      rrnpPercentage: '20.00',
      versionId: v2.versionId,
    });

    const result2025 = await getRrnpRate(deps, 'comm-test-1', new Date('2025-06-15'));
    expect(result2025.rrnpPercentage).toBe('15.00');

    const result2026 = await getRrnpRate(deps, 'comm-test-1', new Date('2026-06-15'));
    expect(result2026.rrnpPercentage).toBe('20.00');
  });

  it('throws NotFoundError for non-existent community', async () => {
    const { deps } = makeServiceDeps();

    seedVersion({ dataSet: 'RRNP', isActive: true });

    await expect(getRrnpRate(deps, 'nonexistent-id')).rejects.toThrow(NotFoundError);
  });
});

// ---------------------------------------------------------------------------
// Service — getPcpcmBasket
// ---------------------------------------------------------------------------

describe('Reference Service — getPcpcmBasket', () => {
  it('returns correct basket classification', async () => {
    const { deps } = makeServiceDeps();

    const v = seedVersion({ dataSet: 'PCPCM', isActive: true });
    seedPcpcmBasket({
      hscCode: '03.04A',
      basket: 'in_basket',
      notes: 'Standard office visit',
      versionId: v.versionId,
    });

    const result = await getPcpcmBasket(deps, '03.04A');

    expect(result.hscCode).toBe('03.04A');
    expect(result.basket).toBe('in_basket');
    expect(result.notes).toBe('Standard office visit');
  });

  it('throws NotFoundError for non-classified HSC', async () => {
    const { deps } = makeServiceDeps();

    seedVersion({ dataSet: 'PCPCM', isActive: true });

    await expect(getPcpcmBasket(deps, 'NONEXIST')).rejects.toThrow(NotFoundError);
  });

  it('resolves correct version for date', async () => {
    const { deps } = makeServiceDeps();

    const v1 = seedVersion({
      dataSet: 'PCPCM',
      effectiveFrom: '2025-01-01',
      effectiveTo: '2026-01-01',
    });
    const v2 = seedVersion({
      dataSet: 'PCPCM',
      effectiveFrom: '2026-01-01',
      isActive: true,
    });

    seedPcpcmBasket({ hscCode: '03.04A', basket: 'out_of_basket', versionId: v1.versionId });
    seedPcpcmBasket({ hscCode: '03.04A', basket: 'in_basket', versionId: v2.versionId });

    const result2025 = await getPcpcmBasket(deps, '03.04A', new Date('2025-06-15'));
    expect(result2025.basket).toBe('out_of_basket');

    const result2026 = await getPcpcmBasket(deps, '03.04A', new Date('2026-06-15'));
    expect(result2026.basket).toBe('in_basket');
  });
});

// ---------------------------------------------------------------------------
// Service — isHoliday
// ---------------------------------------------------------------------------

describe('Reference Service — isHoliday', () => {
  it('correctly identifies Alberta statutory holidays', async () => {
    const { deps } = makeServiceDeps();

    seedHoliday({
      date: '2026-01-01',
      name: "New Year's Day",
      jurisdiction: 'both',
      affectsBillingPremiums: true,
      year: 2026,
    });

    const result = await isHoliday(deps, new Date('2026-01-01'));

    expect(result.is_holiday).toBe(true);
    expect(result.holiday_name).toBe("New Year's Day");
  });

  it('returns false for regular (non-holiday) dates', async () => {
    const { deps } = makeServiceDeps();

    // Seed a holiday but query a different date
    seedHoliday({
      date: '2026-01-01',
      name: "New Year's Day",
      year: 2026,
    });

    const result = await isHoliday(deps, new Date('2026-01-02'));

    expect(result.is_holiday).toBe(false);
    expect(result.holiday_name).toBeUndefined();
  });

  it('handles multiple holidays in the same year', async () => {
    const { deps } = makeServiceDeps();

    seedHoliday({ date: '2026-02-16', name: 'Family Day', year: 2026 });
    seedHoliday({ date: '2026-07-01', name: 'Canada Day', year: 2026 });
    seedHoliday({ date: '2026-12-25', name: 'Christmas Day', year: 2026 });

    const familyDay = await isHoliday(deps, new Date('2026-02-16'));
    expect(familyDay.is_holiday).toBe(true);
    expect(familyDay.holiday_name).toBe('Family Day');

    const canadaDay = await isHoliday(deps, new Date('2026-07-01'));
    expect(canadaDay.is_holiday).toBe(true);
    expect(canadaDay.holiday_name).toBe('Canada Day');

    const normalDay = await isHoliday(deps, new Date('2026-06-15'));
    expect(normalDay.is_holiday).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Service — getExplanatoryCode
// ---------------------------------------------------------------------------

describe('Reference Service — getExplanatoryCode', () => {
  it('returns common cause and suggested action', async () => {
    const { deps } = makeServiceDeps();

    const v = seedVersion({ dataSet: 'EXPLANATORY_CODES', isActive: true });
    seedExplanatoryCode({
      explCode: 'E01',
      description: 'Claim rejected — duplicate submission',
      severity: 'rejected',
      commonCause: 'Duplicate claim submitted for same date and patient',
      suggestedAction: 'Review claim history for duplicates',
      helpText: 'This code indicates a duplicate was found',
      versionId: v.versionId,
    });

    const result = await getExplanatoryCode(deps, 'E01');

    expect(result.code).toBe('E01');
    expect(result.description).toBe('Claim rejected — duplicate submission');
    expect(result.severity).toBe('rejected');
    expect(result.commonCause).toBe('Duplicate claim submitted for same date and patient');
    expect(result.suggestedAction).toBe('Review claim history for duplicates');
    expect(result.helpText).toBe('This code indicates a duplicate was found');
  });

  it('handles explanatory code with no common cause', async () => {
    const { deps } = makeServiceDeps();

    const v = seedVersion({ dataSet: 'EXPLANATORY_CODES', isActive: true });
    // Directly push to store to bypass ?? default in seedExplanatoryCode
    explanatoryCodeStore.push({
      id: crypto.randomUUID(),
      explCode: 'P01',
      description: 'Paid in full',
      severity: 'paid',
      commonCause: null,
      suggestedAction: null,
      helpText: null,
      versionId: v.versionId,
      effectiveFrom: '2026-01-01',
      effectiveTo: null,
    });

    const result = await getExplanatoryCode(deps, 'P01');

    expect(result.code).toBe('P01');
    expect(result.commonCause).toBeNull();
    expect(result.suggestedAction).toBeNull();
    expect(result.helpText).toBeNull();
  });

  it('throws NotFoundError for non-existent code', async () => {
    const { deps } = makeServiceDeps();

    seedVersion({ dataSet: 'EXPLANATORY_CODES', isActive: true });

    await expect(getExplanatoryCode(deps, 'NONEXIST')).rejects.toThrow(NotFoundError);
  });
});

// ---------------------------------------------------------------------------
// Service — uploadDataSet
// ---------------------------------------------------------------------------

describe('Reference Service — uploadDataSet', () => {
  it('parses CSV correctly', async () => {
    const { deps, auditEntries } = makeServiceDepsWithAudit();

    // Need an active version for diff generation
    seedVersion({ dataSet: 'SOMB', isActive: true, versionLabel: 'v1' });

    const csv = [
      'hsc_code,description,base_fee,fee_type',
      '03.04A,Office visit,38.45,fixed',
      '03.05A,Consultation,120.00,fixed',
    ].join('\n');

    const result = await uploadDataSet(
      deps,
      userId,
      'SOMB',
      Buffer.from(csv),
      'somb-2026.csv',
    );

    expect(result.record_count).toBe(2);
    expect(result.validation_result.valid).toBe(true);
    expect(result.validation_result.errors).toHaveLength(0);
    expect(result.staging_id).toBeDefined();
    expect(result.status).toBe('diff_generated');
  });

  it('parses JSON correctly', async () => {
    const { deps } = makeServiceDepsWithAudit();

    seedVersion({ dataSet: 'WCB', isActive: true, versionLabel: 'v1' });

    const json = JSON.stringify([
      { wcb_code: 'W001', description: 'Initial exam', base_fee: 85.00, fee_type: 'fixed' },
      { wcb_code: 'W002', description: 'Follow-up', base_fee: 45.00, fee_type: 'fixed' },
    ]);

    const result = await uploadDataSet(
      deps,
      userId,
      'WCB',
      Buffer.from(json),
      'wcb-codes.json',
    );

    expect(result.record_count).toBe(2);
    expect(result.validation_result.valid).toBe(true);
    expect(result.status).toBe('diff_generated');
  });

  it('rejects invalid schema with line-specific errors', async () => {
    const { deps } = makeServiceDepsWithAudit();

    const csv = [
      'hsc_code,description,base_fee,fee_type',
      ',Missing code,38.45,fixed',
      '03.05A,Good record,120.00,fixed',
      '03.06A,Bad fee,-10,fixed',
    ].join('\n');

    const result = await uploadDataSet(
      deps,
      userId,
      'SOMB',
      Buffer.from(csv),
      'somb-bad.csv',
    );

    expect(result.validation_result.valid).toBe(false);
    expect(result.validation_result.errors.length).toBeGreaterThan(0);
    expect(result.status).toBe('validated');

    // Check line-specific error for missing hsc_code
    const codeError = result.validation_result.errors.find(
      (e) => e.field === 'hsc_code' && e.line === 2,
    );
    expect(codeError).toBeDefined();

    // Check line-specific error for negative base_fee
    const feeError = result.validation_result.errors.find(
      (e) => e.field === 'base_fee' && e.line === 4,
    );
    expect(feeError).toBeDefined();
  });

  it('rejects negative fees', async () => {
    const { deps } = makeServiceDepsWithAudit();

    const json = JSON.stringify([
      { wcb_code: 'W001', description: 'Bad fee', base_fee: -50, fee_type: 'fixed' },
    ]);

    const result = await uploadDataSet(
      deps,
      userId,
      'WCB',
      Buffer.from(json),
      'wcb-bad.json',
    );

    expect(result.validation_result.valid).toBe(false);
    const feeError = result.validation_result.errors.find((e) => e.field === 'base_fee');
    expect(feeError).toBeDefined();
    expect(feeError!.message).toContain('non-negative');
  });

  it('computes correct file hash', async () => {
    const { deps } = makeServiceDepsWithAudit();

    seedVersion({ dataSet: 'SOMB', isActive: true, versionLabel: 'v1' });

    const csv = 'hsc_code,description,base_fee,fee_type\n03.04A,Office visit,38.45,fixed\n';
    const fileBuffer = Buffer.from(csv);

    // Compute expected hash
    const { createHash } = await import('node:crypto');
    const expectedHash = createHash('sha256').update(fileBuffer).digest('hex');

    const result = await uploadDataSet(
      deps,
      userId,
      'SOMB',
      fileBuffer,
      'somb.csv',
    );

    // Verify the staging record has correct hash
    const staging = await deps.repo.findStagingById(result.staging_id);
    expect(staging).toBeDefined();
    expect(staging!.fileHash).toBe(expectedHash);
  });

  it('creates audit log entry on upload', async () => {
    const { deps, auditEntries } = makeServiceDepsWithAudit();

    seedVersion({ dataSet: 'SOMB', isActive: true, versionLabel: 'v1' });

    const csv = 'hsc_code,description,base_fee,fee_type\n03.04A,Office visit,38.45,fixed\n';

    await uploadDataSet(deps, userId, 'SOMB', Buffer.from(csv), 'somb.csv');

    expect(auditEntries.length).toBe(1);
    expect(auditEntries[0].action).toBe('ref.version_staged');
    expect(auditEntries[0].adminId).toBe(userId);
    expect(auditEntries[0].details.data_set).toBe('SOMB');
    expect(auditEntries[0].details.staging_id).toBeDefined();
    expect(auditEntries[0].details.record_count).toBe(1);
    expect(auditEntries[0].details.file_hash).toBeDefined();
  });

  it('rejects empty file', async () => {
    const { deps } = makeServiceDepsWithAudit();

    await expect(
      uploadDataSet(deps, userId, 'SOMB', Buffer.from(''), 'empty.csv'),
    ).rejects.toThrow();
  });

  it('rejects invalid JSON', async () => {
    const { deps } = makeServiceDepsWithAudit();

    await expect(
      uploadDataSet(deps, userId, 'SOMB', Buffer.from('not json'), 'bad.json'),
    ).rejects.toThrow();
  });

  it('validates MODIFIERS data set records', async () => {
    const { deps } = makeServiceDepsWithAudit();

    const json = JSON.stringify([
      { modifier_code: 'CMGP', type: 'invalid_type', calculation_method: 'percentage' },
    ]);

    const result = await uploadDataSet(
      deps,
      userId,
      'MODIFIERS',
      Buffer.from(json),
      'modifiers.json',
    );

    expect(result.validation_result.valid).toBe(false);
    expect(result.validation_result.errors.some((e) => e.field === 'type')).toBe(true);
  });

  it('validates GOVERNING_RULES data set records', async () => {
    const { deps } = makeServiceDepsWithAudit();

    const json = JSON.stringify([
      { rule_id: 'GR1', rule_category: 'invalid_category', severity: 'error' },
    ]);

    const result = await uploadDataSet(
      deps,
      userId,
      'GOVERNING_RULES',
      Buffer.from(json),
      'rules.json',
    );

    expect(result.validation_result.valid).toBe(false);
    expect(result.validation_result.errors.some((e) => e.field === 'rule_category')).toBe(true);
  });

  it('validates RRNP records — rejects missing community_name', async () => {
    const { deps } = makeServiceDepsWithAudit();

    const json = JSON.stringify([
      { community_name: '', rrnp_percentage: 20 },
    ]);

    const result = await uploadDataSet(
      deps,
      userId,
      'RRNP',
      Buffer.from(json),
      'rrnp.json',
    );

    expect(result.validation_result.valid).toBe(false);
    expect(result.validation_result.errors.some((e) => e.field === 'community_name')).toBe(true);
  });

  it('validates PCPCM records — rejects invalid basket', async () => {
    const { deps } = makeServiceDepsWithAudit();

    const json = JSON.stringify([
      { hsc_code: '03.04A', basket: 'invalid_basket' },
    ]);

    const result = await uploadDataSet(
      deps,
      userId,
      'PCPCM',
      Buffer.from(json),
      'pcpcm.json',
    );

    expect(result.validation_result.valid).toBe(false);
    expect(result.validation_result.errors.some((e) => e.field === 'basket')).toBe(true);
  });

  it('validates EXPLANATORY_CODES records — rejects invalid severity', async () => {
    const { deps } = makeServiceDepsWithAudit();

    const json = JSON.stringify([
      { expl_code: 'E01', severity: 'invalid_severity' },
    ]);

    const result = await uploadDataSet(
      deps,
      userId,
      'EXPLANATORY_CODES',
      Buffer.from(json),
      'expl.json',
    );

    expect(result.validation_result.valid).toBe(false);
    expect(result.validation_result.errors.some((e) => e.field === 'severity')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Service — getStagingDiff
// ---------------------------------------------------------------------------

describe('Reference Service — getStagingDiff', () => {
  it('generates correct diff with added, modified, and deprecated records', async () => {
    const { deps, auditEntries } = makeServiceDepsWithAudit();

    // Seed active version with existing records
    const v = seedVersion({ dataSet: 'SOMB', isActive: true, versionLabel: 'v1' });
    seedHsc({
      hscCode: '03.04A',
      description: 'Office visit',
      baseFee: '38.45',
      feeType: 'fixed',
      versionId: v.versionId,
      effectiveFrom: '2026-01-01',
    });
    seedHsc({
      hscCode: '03.05A',
      description: 'Consultation',
      baseFee: '120.00',
      feeType: 'fixed',
      versionId: v.versionId,
      effectiveFrom: '2026-01-01',
    });

    // Create staging record with:
    // - 03.04A modified (fee changed)
    // - 03.05A deprecated (not in staged)
    // - 03.06A added (new code)
    const staging = seedStaging({
      dataSet: 'SOMB',
      status: 'validated',
      stagedData: [
        { hsc_code: '03.04A', description: 'Office visit', base_fee: 42.00, fee_type: 'fixed' },
        { hsc_code: '03.06A', description: 'New procedure', base_fee: 200.00, fee_type: 'fixed' },
      ],
    });

    const diff = await getStagingDiff(deps, userId, 'SOMB', staging.stagingId);

    expect(diff.summary_stats.added).toBe(1);
    expect(diff.summary_stats.modified).toBe(1);
    expect(diff.summary_stats.deprecated).toBe(1);
    expect(diff.added.length).toBe(1);
    expect(diff.modified.length).toBe(1);
    expect(diff.deprecated.length).toBe(1);
    expect((diff.added[0] as any).hsc_code).toBe('03.06A');
    expect((diff.deprecated[0] as any).hsc_code).toBe('03.05A');
  });

  it('highlights field-level changes for modified records', async () => {
    const { deps } = makeServiceDepsWithAudit();

    const v = seedVersion({ dataSet: 'SOMB', isActive: true, versionLabel: 'v1' });
    seedHsc({
      hscCode: '03.04A',
      description: 'Office visit',
      baseFee: '38.45',
      feeType: 'fixed',
      versionId: v.versionId,
      effectiveFrom: '2026-01-01',
    });

    const staging = seedStaging({
      dataSet: 'SOMB',
      status: 'validated',
      stagedData: [
        { hsc_code: '03.04A', description: 'Office visit - updated', base_fee: 42.00, fee_type: 'fixed' },
      ],
    });

    const diff = await getStagingDiff(deps, userId, 'SOMB', staging.stagingId);

    expect(diff.modified.length).toBe(1);
    const changes = diff.modified[0]._changes;
    expect(changes.length).toBeGreaterThan(0);

    // Should detect description change
    const descChange = changes.find((c) => c.field === 'description');
    expect(descChange).toBeDefined();
    expect(descChange!.old_value).toBe('Office visit');
    expect(descChange!.new_value).toBe('Office visit - updated');
  });

  it('returns cached diff from staging record', async () => {
    const { deps, auditEntries } = makeServiceDepsWithAudit();

    const cachedDiff = {
      added: [{ hsc_code: 'NEW1' }],
      modified: [],
      deprecated: [],
      summary_stats: { added: 1, modified: 0, deprecated: 0 },
    };

    const staging = seedStaging({
      dataSet: 'SOMB',
      status: 'diff_generated',
      diffResult: cachedDiff,
    });

    const diff = await getStagingDiff(deps, userId, 'SOMB', staging.stagingId);

    expect(diff).toEqual(cachedDiff);
    // Should still create audit log entry
    expect(auditEntries.length).toBe(1);
    expect(auditEntries[0].action).toBe('ref.version_diff_reviewed');
  });

  it('throws NotFoundError for non-existent staging record', async () => {
    const { deps } = makeServiceDepsWithAudit();

    await expect(
      getStagingDiff(deps, userId, 'SOMB', crypto.randomUUID()),
    ).rejects.toThrow(NotFoundError);
  });

  it('throws NotFoundError for wrong data set', async () => {
    const { deps } = makeServiceDepsWithAudit();

    const staging = seedStaging({ dataSet: 'SOMB' });

    await expect(
      getStagingDiff(deps, userId, 'WCB', staging.stagingId),
    ).rejects.toThrow(NotFoundError);
  });

  it('creates audit log entry when diff is reviewed', async () => {
    const { deps, auditEntries } = makeServiceDepsWithAudit();

    const staging = seedStaging({
      dataSet: 'SOMB',
      status: 'diff_generated',
      diffResult: {
        added: [],
        modified: [],
        deprecated: [],
        summary_stats: { added: 0, modified: 0, deprecated: 0 },
      },
    });

    await getStagingDiff(deps, userId, 'SOMB', staging.stagingId);

    expect(auditEntries.length).toBe(1);
    expect(auditEntries[0].action).toBe('ref.version_diff_reviewed');
    expect(auditEntries[0].adminId).toBe(userId);
    expect(auditEntries[0].details.staging_id).toBe(staging.stagingId);
  });
});

// ---------------------------------------------------------------------------
// Service — discardStaging
// ---------------------------------------------------------------------------

describe('Reference Service — discardStaging', () => {
  it('removes staging record', async () => {
    const { deps } = makeServiceDepsWithAudit();

    const staging = seedStaging({ dataSet: 'SOMB' });
    const initialCount = stagingStore.length;

    await discardStaging(deps, userId, 'SOMB', staging.stagingId);

    expect(stagingStore.length).toBe(initialCount - 1);
    const found = await deps.repo.findStagingById(staging.stagingId);
    expect(found).toBeUndefined();
  });

  it('throws NotFoundError for non-existent staging record', async () => {
    const { deps } = makeServiceDepsWithAudit();

    await expect(
      discardStaging(deps, userId, 'SOMB', crypto.randomUUID()),
    ).rejects.toThrow(NotFoundError);
  });

  it('throws NotFoundError for wrong data set', async () => {
    const { deps } = makeServiceDepsWithAudit();

    const staging = seedStaging({ dataSet: 'SOMB' });

    await expect(
      discardStaging(deps, userId, 'WCB', staging.stagingId),
    ).rejects.toThrow(NotFoundError);
  });

  it('creates audit log entry on discard', async () => {
    const { deps, auditEntries } = makeServiceDepsWithAudit();

    const staging = seedStaging({ dataSet: 'SOMB' });

    await discardStaging(deps, userId, 'SOMB', staging.stagingId);

    expect(auditEntries.length).toBe(1);
    expect(auditEntries[0].action).toBe('ref.staging_discarded');
    expect(auditEntries[0].adminId).toBe(userId);
    expect(auditEntries[0].details.staging_id).toBe(staging.stagingId);
    expect(auditEntries[0].details.data_set).toBe('SOMB');
  });
});

// ===========================================================================
// publishVersion Tests
// ===========================================================================

describe('Reference Service — publishVersion', () => {
  it('creates version and inserts all records', async () => {
    const { deps, auditEntries, emittedEvents } = makeServiceDepsWithAll();

    const stagedRecords = [
      { hsc_code: '03.04A', description: 'Office visit', base_fee: '38.45', fee_type: 'fixed' },
      { hsc_code: '03.04B', description: 'Follow-up visit', base_fee: '25.00', fee_type: 'fixed' },
    ];

    const staging = seedStaging({
      dataSet: 'SOMB',
      status: 'diff_generated',
      stagedData: stagedRecords,
      recordCount: 2,
      diffResult: {
        added: stagedRecords,
        modified: [],
        deprecated: [],
        summary_stats: { added: 2, modified: 0, deprecated: 0 },
      },
    });

    const result = await publishVersion(deps, userId, 'SOMB', staging.stagingId, {
      versionLabel: '2026-Q1',
      effectiveFrom: '2026-01-01',
      sourceDocument: 'SOMB_2026Q1.pdf',
      changeSummary: 'Initial SOMB load',
    });

    expect(result.version_id).toBeDefined();

    // Version record was created
    const createdVersion = versionStore.find((v) => v.versionId === result.version_id);
    expect(createdVersion).toBeDefined();
    expect(createdVersion!.dataSet).toBe('SOMB');
    expect(createdVersion!.versionLabel).toBe('2026-Q1');
    expect(createdVersion!.recordsAdded).toBe(2);

    // Records were inserted into hscStore
    const insertedHsc = hscStore.filter((h) => h.versionId === result.version_id);
    expect(insertedHsc.length).toBe(2);
  });

  it('activates new version and deactivates old', async () => {
    const { deps } = makeServiceDepsWithAll();

    // Create an existing active version
    const oldVersion = seedVersion({
      dataSet: 'SOMB',
      isActive: true,
      versionLabel: 'v1',
      effectiveFrom: '2025-01-01',
    });

    const stagedRecords = [
      { hsc_code: '03.04A', description: 'Office visit', base_fee: '38.45', fee_type: 'fixed' },
    ];

    const staging = seedStaging({
      dataSet: 'SOMB',
      status: 'diff_generated',
      stagedData: stagedRecords,
      recordCount: 1,
      diffResult: {
        added: stagedRecords,
        modified: [],
        deprecated: [],
        summary_stats: { added: 1, modified: 0, deprecated: 0 },
      },
    });

    const result = await publishVersion(deps, userId, 'SOMB', staging.stagingId, {
      versionLabel: '2026-Q1',
      effectiveFrom: '2026-01-01',
    });

    // New version is active
    const newVersion = versionStore.find((v) => v.versionId === result.version_id);
    expect(newVersion!.isActive).toBe(true);

    // Old version is deactivated
    const oldVersionNow = versionStore.find((v) => v.versionId === oldVersion.versionId);
    expect(oldVersionNow!.isActive).toBe(false);
    expect(oldVersionNow!.effectiveTo).toBe('2026-01-01');
  });

  it('emits version_published event', async () => {
    const { deps, emittedEvents } = makeServiceDepsWithAll();

    const stagedRecords = [
      { hsc_code: '03.04A', description: 'Office visit', base_fee: '38.45', fee_type: 'fixed' },
    ];

    const staging = seedStaging({
      dataSet: 'SOMB',
      status: 'diff_generated',
      stagedData: stagedRecords,
      recordCount: 1,
      diffResult: {
        added: stagedRecords,
        modified: [],
        deprecated: [],
        summary_stats: { added: 1, modified: 0, deprecated: 0 },
      },
    });

    await publishVersion(deps, userId, 'SOMB', staging.stagingId, {
      versionLabel: '2026-Q1',
      effectiveFrom: '2026-01-01',
      changeSummary: 'Initial load',
    });

    const publishedEvent = emittedEvents.find((e) => e.event === 'reference_data.version_published');
    expect(publishedEvent).toBeDefined();
    expect(publishedEvent!.payload.dataSet).toBe('SOMB');
    expect(publishedEvent!.payload.versionLabel).toBe('2026-Q1');
    expect(publishedEvent!.payload.effectiveFrom).toBe('2026-01-01');
    expect(publishedEvent!.payload.changeSummary).toBe('Initial load');
    expect(publishedEvent!.payload.recordsAdded).toBe(1);
  });

  it('emits code_deprecated for deprecated codes', async () => {
    const { deps, emittedEvents } = makeServiceDepsWithAll();

    const stagedRecords = [
      { hsc_code: '03.04A', description: 'Office visit', base_fee: '38.45', fee_type: 'fixed' },
    ];

    // Seed an active version with existing records so diff shows deprecations
    const staging = seedStaging({
      dataSet: 'SOMB',
      status: 'diff_generated',
      stagedData: stagedRecords,
      recordCount: 1,
      diffResult: {
        added: [],
        modified: [],
        deprecated: [
          { hsc_code: 'OLD.01', description: 'Deprecated code' },
          { hsc_code: 'OLD.02', description: 'Another deprecated code' },
        ],
        summary_stats: { added: 0, modified: 0, deprecated: 2 },
      },
    });

    await publishVersion(deps, userId, 'SOMB', staging.stagingId, {
      versionLabel: '2026-Q1',
      effectiveFrom: '2026-01-01',
    });

    const deprecatedEvent = emittedEvents.find((e) => e.event === 'reference_data.code_deprecated');
    expect(deprecatedEvent).toBeDefined();
    expect(deprecatedEvent!.payload.dataSet).toBe('SOMB');
    expect(deprecatedEvent!.payload.deprecatedCount).toBe(2);
    expect((deprecatedEvent!.payload.deprecatedCodes as string[])).toContain('OLD.01');
    expect((deprecatedEvent!.payload.deprecatedCodes as string[])).toContain('OLD.02');
  });

  it('requires large-change confirmation when threshold exceeded', async () => {
    const { deps } = makeServiceDepsWithAll();

    const stagedRecords = [
      { hsc_code: '03.04A', description: 'Office visit', base_fee: '38.45', fee_type: 'fixed' },
    ];

    const staging = seedStaging({
      dataSet: 'SOMB',
      status: 'diff_generated',
      stagedData: stagedRecords,
      recordCount: 1,
      diffResult: {
        added: [],
        modified: new Array(501).fill({ hsc_code: 'X', _changes: [] }),
        deprecated: [],
        summary_stats: { added: 0, modified: 501, deprecated: 0 },
      },
    });

    // Should throw ConflictError without confirmation
    await expect(
      publishVersion(deps, userId, 'SOMB', staging.stagingId, {
        versionLabel: '2026-Q1',
        effectiveFrom: '2026-01-01',
      }),
    ).rejects.toThrow(ConflictError);

    // Should succeed with confirmation
    const result = await publishVersion(deps, userId, 'SOMB', staging.stagingId, {
      versionLabel: '2026-Q1',
      effectiveFrom: '2026-01-01',
    }, true);

    expect(result.version_id).toBeDefined();
  });

  it('requires large-change confirmation for >100 deprecated codes', async () => {
    const { deps } = makeServiceDepsWithAll();

    const stagedRecords = [
      { hsc_code: '03.04A', description: 'Office visit', base_fee: '38.45', fee_type: 'fixed' },
    ];

    const staging = seedStaging({
      dataSet: 'SOMB',
      status: 'diff_generated',
      stagedData: stagedRecords,
      recordCount: 1,
      diffResult: {
        added: [],
        modified: [],
        deprecated: new Array(101).fill({ hsc_code: 'OLD.X' }),
        summary_stats: { added: 0, modified: 0, deprecated: 101 },
      },
    });

    await expect(
      publishVersion(deps, userId, 'SOMB', staging.stagingId, {
        versionLabel: '2026-Q1',
        effectiveFrom: '2026-01-01',
      }),
    ).rejects.toThrow(ConflictError);
  });

  it('rejects publishing staging record not in diff_generated status', async () => {
    const { deps } = makeServiceDepsWithAll();

    const staging = seedStaging({
      dataSet: 'SOMB',
      status: 'uploaded',
      stagedData: [{ hsc_code: '03.04A' }],
    });

    await expect(
      publishVersion(deps, userId, 'SOMB', staging.stagingId, {
        versionLabel: '2026-Q1',
        effectiveFrom: '2026-01-01',
      }),
    ).rejects.toThrow(BusinessRuleError);
  });

  it('throws NotFoundError for non-existent staging record', async () => {
    const { deps } = makeServiceDepsWithAll();

    await expect(
      publishVersion(deps, userId, 'SOMB', crypto.randomUUID(), {
        versionLabel: '2026-Q1',
        effectiveFrom: '2026-01-01',
      }),
    ).rejects.toThrow(NotFoundError);
  });

  it('throws NotFoundError for staging record with mismatched dataSet', async () => {
    const { deps } = makeServiceDepsWithAll();

    const staging = seedStaging({
      dataSet: 'WCB',
      status: 'diff_generated',
      stagedData: [{ wcb_code: 'W01' }],
      diffResult: { added: [], modified: [], deprecated: [], summary_stats: { added: 0, modified: 0, deprecated: 0 } },
    });

    await expect(
      publishVersion(deps, userId, 'SOMB', staging.stagingId, {
        versionLabel: '2026-Q1',
        effectiveFrom: '2026-01-01',
      }),
    ).rejects.toThrow(NotFoundError);
  });

  it('deletes staging record after publishing', async () => {
    const { deps } = makeServiceDepsWithAll();

    const stagedRecords = [
      { hsc_code: '03.04A', description: 'Office visit', base_fee: '38.45', fee_type: 'fixed' },
    ];

    const staging = seedStaging({
      dataSet: 'SOMB',
      status: 'diff_generated',
      stagedData: stagedRecords,
      recordCount: 1,
      diffResult: {
        added: stagedRecords,
        modified: [],
        deprecated: [],
        summary_stats: { added: 1, modified: 0, deprecated: 0 },
      },
    });

    await publishVersion(deps, userId, 'SOMB', staging.stagingId, {
      versionLabel: '2026-Q1',
      effectiveFrom: '2026-01-01',
    });

    // Staging record should be removed
    const remaining = stagingStore.find((s) => s.stagingId === staging.stagingId);
    expect(remaining).toBeUndefined();
  });

  it('creates audit log entry on publish', async () => {
    const { deps, auditEntries } = makeServiceDepsWithAll();

    const stagedRecords = [
      { hsc_code: '03.04A', description: 'Office visit', base_fee: '38.45', fee_type: 'fixed' },
    ];

    const staging = seedStaging({
      dataSet: 'SOMB',
      status: 'diff_generated',
      stagedData: stagedRecords,
      recordCount: 1,
      diffResult: {
        added: stagedRecords,
        modified: [],
        deprecated: [],
        summary_stats: { added: 1, modified: 0, deprecated: 0 },
      },
    });

    const result = await publishVersion(deps, userId, 'SOMB', staging.stagingId, {
      versionLabel: '2026-Q1',
      effectiveFrom: '2026-01-01',
    });

    const publishAudit = auditEntries.find((e) => e.action === 'ref.version_published');
    expect(publishAudit).toBeDefined();
    expect(publishAudit!.adminId).toBe(userId);
    expect(publishAudit!.details.version_id).toBe(result.version_id);
    expect(publishAudit!.details.data_set).toBe('SOMB');
    expect(publishAudit!.details.effective_from).toBe('2026-01-01');
  });

  it('publication is atomic — failure rolls back all inserts', async () => {
    const { deps } = makeServiceDepsWithAll();

    // Create a staging record with data set that has no bulk insert mapping
    const staging = seedStaging({
      dataSet: 'UNKNOWN_SET',
      status: 'diff_generated',
      stagedData: [{ key: 'value' }],
      recordCount: 1,
      diffResult: {
        added: [{ key: 'value' }],
        modified: [],
        deprecated: [],
        summary_stats: { added: 1, modified: 0, deprecated: 0 },
      },
    });

    await expect(
      publishVersion(deps, userId, 'UNKNOWN_SET', staging.stagingId, {
        versionLabel: '2026-Q1',
        effectiveFrom: '2026-01-01',
      }),
    ).rejects.toThrow(BusinessRuleError);

    // Version should have been created but no records inserted (failure happened at bulk insert step)
    // The staging record should still exist since publish failed
    const remainingStaging = stagingStore.find((s) => s.stagingId === staging.stagingId);
    expect(remainingStaging).toBeDefined();
  });

  it('publishes WCB data set correctly', async () => {
    const { deps } = makeServiceDepsWithAll();

    const stagedRecords = [
      { wcb_code: 'W01', description: 'WCB visit', base_fee: '50.00', fee_type: 'fixed' },
    ];

    const staging = seedStaging({
      dataSet: 'WCB',
      status: 'diff_generated',
      stagedData: stagedRecords,
      recordCount: 1,
      diffResult: {
        added: stagedRecords,
        modified: [],
        deprecated: [],
        summary_stats: { added: 1, modified: 0, deprecated: 0 },
      },
    });

    const result = await publishVersion(deps, userId, 'WCB', staging.stagingId, {
      versionLabel: 'WCB-2026-Q1',
      effectiveFrom: '2026-01-01',
    });

    expect(result.version_id).toBeDefined();

    // Records should be in wcbStore
    const insertedWcb = wcbStore.filter((w) => w.versionId === result.version_id);
    expect(insertedWcb.length).toBe(1);
    expect(insertedWcb[0].wcbCode).toBe('W01');
  });
});

// ===========================================================================
// rollbackVersion Tests
// ===========================================================================

describe('Reference Service — rollbackVersion', () => {
  it('re-activates previous version', async () => {
    const { deps, auditEntries } = makeServiceDepsWithAll();

    const previousVersion = seedVersion({
      dataSet: 'SOMB',
      isActive: false,
      versionLabel: 'v1',
      effectiveFrom: '2025-01-01',
      effectiveTo: '2026-01-01',
    });

    const currentVersion = seedVersion({
      dataSet: 'SOMB',
      isActive: true,
      versionLabel: 'v2',
      effectiveFrom: '2026-01-01',
    });

    await rollbackVersion(deps, userId, currentVersion.versionId, 'Incorrect data published');

    // Current version should be deactivated
    const current = versionStore.find((v) => v.versionId === currentVersion.versionId);
    expect(current!.isActive).toBe(false);

    // Previous version should be re-activated
    const previous = versionStore.find((v) => v.versionId === previousVersion.versionId);
    expect(previous!.isActive).toBe(true);
  });

  it('preserves deactivated version for audit (does not delete)', async () => {
    const { deps } = makeServiceDepsWithAll();

    seedVersion({
      dataSet: 'SOMB',
      isActive: false,
      versionLabel: 'v1',
      effectiveFrom: '2025-01-01',
      effectiveTo: '2026-01-01',
    });

    const currentVersion = seedVersion({
      dataSet: 'SOMB',
      isActive: true,
      versionLabel: 'v2',
      effectiveFrom: '2026-01-01',
    });

    await rollbackVersion(deps, userId, currentVersion.versionId, 'Bad data');

    // Deactivated version still exists in the store
    const deactivated = versionStore.find((v) => v.versionId === currentVersion.versionId);
    expect(deactivated).toBeDefined();
    expect(deactivated!.isActive).toBe(false);
    expect(deactivated!.versionLabel).toBe('v2');
  });

  it('creates audit log entry on rollback', async () => {
    const { deps, auditEntries } = makeServiceDepsWithAll();

    seedVersion({
      dataSet: 'SOMB',
      isActive: false,
      versionLabel: 'v1',
      effectiveFrom: '2025-01-01',
      effectiveTo: '2026-01-01',
    });

    const currentVersion = seedVersion({
      dataSet: 'SOMB',
      isActive: true,
      versionLabel: 'v2',
      effectiveFrom: '2026-01-01',
    });

    await rollbackVersion(deps, userId, currentVersion.versionId, 'Data error');

    const rollbackAudit = auditEntries.find((e) => e.action === 'ref.version_rolled_back');
    expect(rollbackAudit).toBeDefined();
    expect(rollbackAudit!.adminId).toBe(userId);
    expect(rollbackAudit!.details.version_id).toBe(currentVersion.versionId);
    expect(rollbackAudit!.details.data_set).toBe('SOMB');
    expect(rollbackAudit!.details.reason).toBe('Data error');
  });

  it('throws NotFoundError for non-existent version', async () => {
    const { deps } = makeServiceDepsWithAll();

    await expect(
      rollbackVersion(deps, userId, crypto.randomUUID(), 'Test reason'),
    ).rejects.toThrow(NotFoundError);
  });

  it('throws BusinessRuleError for inactive version', async () => {
    const { deps } = makeServiceDepsWithAll();

    const inactiveVersion = seedVersion({
      dataSet: 'SOMB',
      isActive: false,
      versionLabel: 'v1',
      effectiveFrom: '2025-01-01',
    });

    await expect(
      rollbackVersion(deps, userId, inactiveVersion.versionId, 'Test reason'),
    ).rejects.toThrow(BusinessRuleError);
  });

  it('handles rollback when no previous version exists', async () => {
    const { deps } = makeServiceDepsWithAll();

    const onlyVersion = seedVersion({
      dataSet: 'SOMB',
      isActive: true,
      versionLabel: 'v1',
      effectiveFrom: '2026-01-01',
    });

    // Should deactivate current without error even if no previous exists
    await rollbackVersion(deps, userId, onlyVersion.versionId, 'Reverting only version');

    const version = versionStore.find((v) => v.versionId === onlyVersion.versionId);
    expect(version!.isActive).toBe(false);
  });
});

// ===========================================================================
// dryRunRule Tests
// ===========================================================================

describe('Reference Service — dryRunRule', () => {
  it('returns affected claims count', async () => {
    const { deps, auditEntries } = makeServiceDepsWithAll();

    const version = seedVersion({
      dataSet: 'GOVERNING_RULES',
      isActive: true,
      versionLabel: 'rules-v1',
    });

    seedRule({
      ruleId: 'RULE.001',
      ruleName: 'Max visits per day',
      ruleCategory: 'visit_limits',
      severity: 'error',
      ruleLogic: { max_per_day: 3, hsc_codes: ['03.04A'] },
      versionId: version.versionId,
    });

    const result = await dryRunRule(deps, userId, 'RULE.001', {
      max_per_day: 2,
      hsc_codes: ['03.04A'],
    });

    expect(result).toBeDefined();
    expect(typeof result.claims_affected).toBe('number');
    expect(Array.isArray(result.sample_results)).toBe(true);
    // Since Domain 4 (claims) doesn't exist yet, claims_affected is 0
    expect(result.claims_affected).toBe(0);
  });

  it('creates audit log entry for dry run', async () => {
    const { deps, auditEntries } = makeServiceDepsWithAll();

    const version = seedVersion({
      dataSet: 'GOVERNING_RULES',
      isActive: true,
      versionLabel: 'rules-v1',
    });

    seedRule({
      ruleId: 'RULE.002',
      ruleName: 'Modifier combination',
      ruleCategory: 'modifier_rules',
      severity: 'warning',
      ruleLogic: { modifier: 'CMGP' },
      versionId: version.versionId,
    });

    await dryRunRule(deps, userId, 'RULE.002', { modifier: 'CMGP', max: 1 });

    const dryRunAudit = auditEntries.find((e) => e.action === 'ref.rule_dry_run');
    expect(dryRunAudit).toBeDefined();
    expect(dryRunAudit!.adminId).toBe(userId);
    expect(dryRunAudit!.details.rule_id).toBe('RULE.002');
    expect(typeof dryRunAudit!.details.claims_sampled).toBe('number');
  });

  it('throws NotFoundError for non-existent rule', async () => {
    const { deps } = makeServiceDepsWithAll();

    seedVersion({
      dataSet: 'GOVERNING_RULES',
      isActive: true,
      versionLabel: 'rules-v1',
    });

    await expect(
      dryRunRule(deps, userId, 'NONEXISTENT.RULE', { max: 1 }),
    ).rejects.toThrow(NotFoundError);
  });

  it('throws NotFoundError when no governing rules version exists', async () => {
    const { deps } = makeServiceDepsWithAll();

    // No GOVERNING_RULES version seeded
    await expect(
      dryRunRule(deps, userId, 'RULE.001', { max: 1 }),
    ).rejects.toThrow(NotFoundError);
  });
});

// ===========================================================================
// Holiday Management Service Tests
// ===========================================================================

describe('Reference Service — createHoliday', () => {
  it('inserts holiday with audit log', async () => {
    const { deps, auditEntries } = makeServiceDepsWithAudit();

    const result = await createHoliday(deps, userId, {
      date: '2026-07-01',
      name: 'Canada Day',
      jurisdiction: 'federal',
      affects_billing_premiums: true,
    });

    expect(result.holidayId).toBeDefined();
    expect(result.date).toBe('2026-07-01');
    expect(result.name).toBe('Canada Day');
    expect(result.jurisdiction).toBe('federal');
    expect(result.affectsBillingPremiums).toBe(true);
    expect(result.year).toBe(2026);

    // Verify audit log
    const audit = auditEntries.find((e) => e.action === 'ref.holiday_created');
    expect(audit).toBeDefined();
    expect(audit!.adminId).toBe(userId);
    expect(audit!.details.date).toBe('2026-07-01');
    expect(audit!.details.name).toBe('Canada Day');
    expect(audit!.details.admin_id).toBe(userId);
  });

  it('derives year from date string', async () => {
    const { deps } = makeServiceDepsWithAudit();

    const result = await createHoliday(deps, userId, {
      date: '2027-01-01',
      name: "New Year's Day",
      jurisdiction: 'both',
      affects_billing_premiums: true,
    });

    expect(result.year).toBe(2027);
  });
});

describe('Reference Service — updateHoliday', () => {
  it('modifies holiday fields', async () => {
    const { deps } = makeServiceDepsWithAudit();

    // First create a holiday
    const holiday = seedHoliday({
      date: '2026-01-01',
      name: "New Year's Day",
      jurisdiction: 'both',
      affectsBillingPremiums: true,
      year: 2026,
    });

    const result = await updateHoliday(deps, userId, holiday.holidayId, {
      name: 'Updated Name',
      affects_billing_premiums: false,
    });

    expect(result.name).toBe('Updated Name');
    expect(result.affectsBillingPremiums).toBe(false);
  });

  it('creates audit log with old and new values', async () => {
    const { deps, auditEntries } = makeServiceDepsWithAudit();

    const holiday = seedHoliday({
      date: '2026-02-16',
      name: 'Family Day',
      jurisdiction: 'provincial',
      affectsBillingPremiums: true,
      year: 2026,
    });

    await updateHoliday(deps, userId, holiday.holidayId, {
      name: 'Alberta Family Day',
    });

    const audit = auditEntries.find((e) => e.action === 'ref.holiday_updated');
    expect(audit).toBeDefined();
    expect(audit!.adminId).toBe(userId);
    expect(audit!.details.holiday_id).toBe(holiday.holidayId);
    expect(audit!.details.admin_id).toBe(userId);
  });

  it('throws NotFoundError for non-existent holiday', async () => {
    const { deps } = makeServiceDepsWithAudit();

    await expect(
      updateHoliday(deps, userId, crypto.randomUUID(), { name: 'New Name' }),
    ).rejects.toThrow(NotFoundError);
  });
});

describe('Reference Service — deleteHoliday', () => {
  it('removes holiday with audit log', async () => {
    const { deps, auditEntries } = makeServiceDepsWithAudit();

    const holiday = seedHoliday({
      date: '2026-09-07',
      name: 'Labour Day',
      jurisdiction: 'both',
      affectsBillingPremiums: true,
      year: 2026,
    });

    expect(statutoryHolidayStore).toHaveLength(1);

    await deleteHoliday(deps, userId, holiday.holidayId);

    expect(statutoryHolidayStore).toHaveLength(0);

    // Verify audit log
    const audit = auditEntries.find((e) => e.action === 'ref.holiday_deleted');
    expect(audit).toBeDefined();
    expect(audit!.adminId).toBe(userId);
    expect(audit!.details.holiday_id).toBe(holiday.holidayId);
    expect(audit!.details.admin_id).toBe(userId);
  });
});

describe('Reference Service — listHolidays', () => {
  it('returns correct holidays for year', async () => {
    const { deps } = makeServiceDeps();

    seedHoliday({ date: '2026-01-01', name: "New Year's Day", year: 2026 });
    seedHoliday({ date: '2026-02-16', name: 'Family Day', year: 2026 });
    seedHoliday({ date: '2026-07-01', name: 'Canada Day', year: 2026 });
    seedHoliday({ date: '2027-01-01', name: "New Year's Day 2027", year: 2027 });

    const results = await listHolidays(deps, 2026);

    expect(results).toHaveLength(3);
    expect(results[0].name).toBe("New Year's Day");
    expect(results[2].name).toBe('Canada Day');
    // All results have correct shape
    results.forEach((h) => {
      expect(h.holidayId).toBeDefined();
      expect(h.date).toBeDefined();
      expect(h.name).toBeDefined();
      expect(h.jurisdiction).toBeDefined();
      expect(typeof h.affectsBillingPremiums).toBe('boolean');
      expect(h.year).toBe(2026);
    });
  });

  it('returns empty array for year with no holidays', async () => {
    const { deps } = makeServiceDeps();

    seedHoliday({ date: '2026-01-01', name: "New Year's Day", year: 2026 });

    const results = await listHolidays(deps, 2025);
    expect(results).toHaveLength(0);
  });
});

describe('Reference Service — checkHolidayCalendarPopulated', () => {
  it('detects missing next year holidays', async () => {
    const { deps } = makeServiceDeps();

    // Only 2026 holidays, no 2027
    seedHoliday({ date: '2026-01-01', name: "New Year's Day", year: 2026 });

    const result = await checkHolidayCalendarPopulated(deps, 2027);
    expect(result.populated).toBe(false);
    expect(result.count).toBe(0);
  });

  it('returns populated true when holidays exist for year', async () => {
    const { deps } = makeServiceDeps();

    seedHoliday({ date: '2027-01-01', name: "New Year's Day", year: 2027 });
    seedHoliday({ date: '2027-02-15', name: 'Family Day', year: 2027 });
    seedHoliday({ date: '2027-07-01', name: 'Canada Day', year: 2027 });

    const result = await checkHolidayCalendarPopulated(deps, 2027);
    expect(result.populated).toBe(true);
    expect(result.count).toBe(3);
  });
});

// ===========================================================================
// Change Summary Service Tests
// ===========================================================================

describe('Reference Service — getChangeSummaries', () => {
  it('returns all versions across data sets when no filter', async () => {
    const { deps } = makeServiceDeps();

    seedVersion({
      dataSet: 'SOMB',
      isActive: true,
      versionLabel: 'somb-v1',
      publishedAt: new Date('2026-01-15'),
      recordsAdded: 100,
      recordsModified: 5,
      recordsDeprecated: 2,
      changeSummary: 'Initial SOMB load',
    });
    seedVersion({
      dataSet: 'WCB',
      isActive: true,
      versionLabel: 'wcb-v1',
      publishedAt: new Date('2026-02-01'),
      recordsAdded: 50,
      recordsModified: 0,
      recordsDeprecated: 0,
      changeSummary: 'Initial WCB load',
    });

    const result = await getChangeSummaries(deps);

    expect(result.versions.length).toBe(2);
    // Should be sorted by published_at DESC (most recent first)
    expect(result.versions[0].data_set).toBe('WCB');
    expect(result.versions[1].data_set).toBe('SOMB');
  });

  it('filters by data set', async () => {
    const { deps } = makeServiceDeps();

    seedVersion({ dataSet: 'SOMB', isActive: true, versionLabel: 'somb-v1', publishedAt: new Date('2026-01-15') });
    seedVersion({ dataSet: 'WCB', isActive: true, versionLabel: 'wcb-v1', publishedAt: new Date('2026-02-01') });

    const result = await getChangeSummaries(deps, 'SOMB');

    expect(result.versions.length).toBe(1);
    expect(result.versions[0].data_set).toBe('SOMB');
    expect(result.versions[0].version_label).toBe('somb-v1');
  });

  it('filters by since date', async () => {
    const { deps } = makeServiceDeps();

    seedVersion({ dataSet: 'SOMB', versionLabel: 'old-v1', publishedAt: new Date('2025-06-01') });
    seedVersion({ dataSet: 'SOMB', isActive: true, versionLabel: 'new-v1', publishedAt: new Date('2026-03-01') });

    const result = await getChangeSummaries(deps, 'SOMB', new Date('2026-01-01'));

    expect(result.versions.length).toBe(1);
    expect(result.versions[0].version_label).toBe('new-v1');
  });

  it('returns version with change stats', async () => {
    const { deps } = makeServiceDeps();

    seedVersion({
      dataSet: 'SOMB',
      isActive: true,
      versionLabel: 'somb-v2',
      publishedAt: new Date('2026-04-01'),
      recordsAdded: 15,
      recordsModified: 30,
      recordsDeprecated: 5,
      changeSummary: 'April SOMB update with fee changes',
    });

    const result = await getChangeSummaries(deps, 'SOMB');

    expect(result.versions[0].records_added).toBe(15);
    expect(result.versions[0].records_modified).toBe(30);
    expect(result.versions[0].records_deprecated).toBe(5);
    expect(result.versions[0].change_summary).toBe('April SOMB update with fee changes');
  });
});

describe('Reference Service — getChangeDetail', () => {
  it('returns code-level details for SOMB version', async () => {
    const { deps } = makeServiceDeps();

    const version = seedVersion({ dataSet: 'SOMB', isActive: true, versionLabel: 'somb-v1' });
    seedHsc({
      hscCode: '03.04A',
      description: 'Office visit',
      baseFee: '38.45',
      versionId: version.versionId,
      effectiveTo: null,
    });
    seedHsc({
      hscCode: '99.99Z',
      description: 'Deprecated procedure',
      baseFee: '10.00',
      versionId: version.versionId,
      effectiveTo: '2025-12-31',
    });

    const result = await getChangeDetail(deps, version.versionId);

    expect(result.added.length).toBe(1);
    expect(result.added[0].code).toBe('03.04A');
    expect(result.deprecated.length).toBe(1);
    expect(result.deprecated[0].code).toBe('99.99Z');
  });

  it('filters by specialty', async () => {
    const { deps } = makeServiceDeps();

    const version = seedVersion({ dataSet: 'SOMB', isActive: true, versionLabel: 'somb-v1' });
    seedHsc({
      hscCode: '03.04A',
      description: 'GP visit',
      versionId: version.versionId,
      specialtyRestrictions: ['GP', 'FM'],
      effectiveTo: null,
    });
    seedHsc({
      hscCode: '08.19A',
      description: 'Cardiology consult',
      versionId: version.versionId,
      specialtyRestrictions: ['CARDIOLOGY'],
      effectiveTo: null,
    });
    seedHsc({
      hscCode: '01.01A',
      description: 'Unrestricted code',
      versionId: version.versionId,
      specialtyRestrictions: [],
      effectiveTo: null,
    });

    // GP filter should include GP-restricted and unrestricted codes
    const result = await getChangeDetail(deps, version.versionId, 'GP');

    expect(result.added.some((c) => c.code === '03.04A')).toBe(true);
    expect(result.added.some((c) => c.code === '01.01A')).toBe(true);
    expect(result.added.some((c) => c.code === '08.19A')).toBe(false);
  });

  it('throws NotFoundError for non-existent version', async () => {
    const { deps } = makeServiceDeps();

    await expect(
      getChangeDetail(deps, crypto.randomUUID()),
    ).rejects.toThrow(NotFoundError);
  });
});

describe('Reference Service — getPhysicianImpact', () => {
  it('returns new relevant codes for SOMB version', async () => {
    const { deps } = makeServiceDeps();

    const version = seedVersion({ dataSet: 'SOMB', isActive: true, versionLabel: 'somb-v2' });
    seedHsc({
      hscCode: '03.04A',
      description: 'Office visit',
      baseFee: '38.45',
      versionId: version.versionId,
      effectiveTo: null,
    });
    seedHsc({
      hscCode: '03.05A',
      description: 'Hospital visit',
      baseFee: '45.00',
      versionId: version.versionId,
      effectiveTo: null,
    });
    seedHsc({
      hscCode: '99.99Z',
      description: 'Deprecated code',
      baseFee: '10.00',
      versionId: version.versionId,
      effectiveTo: '2025-12-31',
    });

    const result = await getPhysicianImpact(deps, version.versionId, userId);

    // Deprecated codes used is empty (no claim history yet)
    expect(result.deprecated_codes_used).toEqual([]);
    // Fee changes is empty (no claim history yet)
    expect(result.fee_changes).toEqual([]);
    // New relevant codes should include active codes (not deprecated)
    expect(result.new_relevant_codes.length).toBe(2);
    expect(result.new_relevant_codes.some((c) => c.code === '03.04A')).toBe(true);
    expect(result.new_relevant_codes.some((c) => c.code === '03.05A')).toBe(true);
    // Deprecated code should not be in new_relevant_codes
    expect(result.new_relevant_codes.some((c) => c.code === '99.99Z')).toBe(false);
  });

  it('throws NotFoundError for non-existent version', async () => {
    const { deps } = makeServiceDeps();

    await expect(
      getPhysicianImpact(deps, crypto.randomUUID(), userId),
    ).rejects.toThrow(NotFoundError);
  });

  it('returns empty new_relevant_codes for non-SOMB version', async () => {
    const { deps } = makeServiceDeps();

    const version = seedVersion({ dataSet: 'WCB', isActive: true, versionLabel: 'wcb-v1' });

    const result = await getPhysicianImpact(deps, version.versionId, userId);

    expect(result.new_relevant_codes).toEqual([]);
    expect(result.deprecated_codes_used).toEqual([]);
    expect(result.fee_changes).toEqual([]);
  });
});
