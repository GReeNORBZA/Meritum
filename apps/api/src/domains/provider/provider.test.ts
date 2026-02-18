import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  createProviderRepository,
  OnboardingIncompleteError,
  InvalidPermittedFormTypesError,
} from './provider.repository.js';
import {
  getProviderProfile,
  updateProviderProfile,
  getOnboardingStatus,
  completeOnboarding,
  createProviderFromOnboarding,
  addBa,
  updateBa,
  deactivateBa,
  listBas,
  addLocation,
  updateLocation,
  setDefaultLocation,
  deactivateLocation,
  listLocations,
  listActiveLocations,
  refreshRrnpRates,
  routeClaimToBa,
  isPcpcmEnrolled,
  addWcbConfig,
  updateWcbConfig,
  removeWcbConfig,
  listWcbConfigs,
  getFormPermissions,
  getWcbConfigForForm,
  inviteDelegate,
  acceptInvitation,
  listDelegates,
  updateDelegatePermissions,
  revokeDelegate,
  listPhysiciansForDelegate,
  switchPhysicianContext,
  getSubmissionPreferences,
  updateSubmissionPreferences,
  initDefaultPreferences,
  getHlinkConfig,
  updateHlinkConfig,
  isSubmissionAllowed,
  getProviderContext,
  getBaForClaim,
  getWcbConfigForFormOrThrow,
  type ProviderServiceDeps,
  type ReferenceDataLookup,
  type PendingClaimsCheck,
  type BaRoutingResult,
  type TokenStore,
} from './provider.service.js';

// ---------------------------------------------------------------------------
// In-memory stores
// ---------------------------------------------------------------------------

let providerStore: Record<string, any>[];
let baStore: Record<string, any>[];
let locationStore: Record<string, any>[];
let pcpcmEnrolmentStore: Record<string, any>[];
let wcbConfigStore: Record<string, any>[];
let delegateRelStore: Record<string, any>[];
let userStore: Record<string, any>[];
let submissionPrefStore: Record<string, any>[];
let hlinkConfigStore: Record<string, any>[];
let hscCodeStore: Record<string, any>[];
let referenceVersionStore: Record<string, any>[];

// ---------------------------------------------------------------------------
// Mock Drizzle DB
// ---------------------------------------------------------------------------

function getStoreForTable(table: any): Record<string, any>[] {
  if (table?.__table === 'business_arrangements') return baStore;
  if (table?.__table === 'practice_locations') return locationStore;
  if (table?.__table === 'pcpcm_enrolments') return pcpcmEnrolmentStore;
  if (table?.__table === 'wcb_configurations') return wcbConfigStore;
  if (table?.__table === 'delegate_relationships') return delegateRelStore;
  if (table?.__table === 'users') return userStore;
  if (table?.__table === 'submission_preferences') return submissionPrefStore;
  if (table?.__table === 'hlink_configurations') return hlinkConfigStore;
  if (table?.__table === 'hsc_codes') return hscCodeStore;
  if (table?.__table === 'reference_data_versions') return referenceVersionStore;
  return providerStore;
}

function makeMockDb() {
  function chainable(ctx: {
    op: string;
    table?: any;
    values?: any;
    setClauses?: any;
    selectFields?: any;
    whereClauses: Array<(row: any) => boolean>;
    limitN?: number;
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

  function insertProviderRow(values: any): any {
    // Enforce unique billing_number
    const existingBilling = providerStore.find(
      (p) => p.billingNumber === values.billingNumber,
    );
    if (existingBilling) {
      const err: any = new Error(
        'duplicate key value violates unique constraint "providers_billing_number_idx"',
      );
      err.code = '23505';
      throw err;
    }

    // Enforce unique cpsa_registration_number
    const existingCpsa = providerStore.find(
      (p) => p.cpsaRegistrationNumber === values.cpsaRegistrationNumber,
    );
    if (existingCpsa) {
      const err: any = new Error(
        'duplicate key value violates unique constraint "providers_cpsa_registration_number_idx"',
      );
      err.code = '23505';
      throw err;
    }

    const newProvider = {
      providerId: values.providerId ?? crypto.randomUUID(),
      billingNumber: values.billingNumber,
      cpsaRegistrationNumber: values.cpsaRegistrationNumber,
      firstName: values.firstName,
      middleName: values.middleName ?? null,
      lastName: values.lastName,
      specialtyCode: values.specialtyCode,
      specialtyDescription: values.specialtyDescription ?? null,
      subSpecialtyCode: values.subSpecialtyCode ?? null,
      physicianType: values.physicianType,
      status: values.status ?? 'ACTIVE',
      onboardingCompleted: values.onboardingCompleted ?? false,
      createdAt: values.createdAt ?? new Date(),
      updatedAt: values.updatedAt ?? new Date(),
    };
    providerStore.push(newProvider);
    return newProvider;
  }

  function insertBaRow(values: any): any {
    // Enforce partial unique: ba_number unique among non-INACTIVE BAs
    const existingBa = baStore.find(
      (b) => b.baNumber === values.baNumber && b.status !== 'INACTIVE',
    );
    if (existingBa) {
      const err: any = new Error(
        'duplicate key value violates unique constraint "ba_number_active_unique_idx"',
      );
      err.code = '23505';
      throw err;
    }

    const newBa = {
      baId: values.baId ?? crypto.randomUUID(),
      providerId: values.providerId,
      baNumber: values.baNumber,
      baType: values.baType,
      isPrimary: values.isPrimary,
      status: values.status ?? 'PENDING',
      effectiveDate: values.effectiveDate ?? null,
      endDate: values.endDate ?? null,
      createdAt: values.createdAt ?? new Date(),
      updatedAt: values.updatedAt ?? new Date(),
    };
    baStore.push(newBa);
    return newBa;
  }

  function insertLocationRow(values: any): any {
    const newLocation = {
      locationId: values.locationId ?? crypto.randomUUID(),
      providerId: values.providerId,
      name: values.name,
      functionalCentre: values.functionalCentre,
      facilityNumber: values.facilityNumber ?? null,
      addressLine1: values.addressLine1 ?? null,
      addressLine2: values.addressLine2 ?? null,
      city: values.city ?? null,
      province: values.province ?? 'AB',
      postalCode: values.postalCode ?? null,
      communityCode: values.communityCode ?? null,
      rrnpEligible: values.rrnpEligible ?? false,
      rrnpRate: values.rrnpRate ?? null,
      isDefault: values.isDefault ?? false,
      isActive: values.isActive ?? true,
      createdAt: values.createdAt ?? new Date(),
      updatedAt: values.updatedAt ?? new Date(),
    };
    locationStore.push(newLocation);
    return newLocation;
  }

  function insertPcpcmEnrolmentRow(values: any): any {
    // Enforce partial unique: one active (non-WITHDRAWN) enrolment per provider
    const existingActive = pcpcmEnrolmentStore.find(
      (e) => e.providerId === values.providerId && e.status !== 'WITHDRAWN',
    );
    if (existingActive) {
      const err: any = new Error(
        'duplicate key value violates unique constraint "pcpcm_enrolments_one_active_per_provider_idx"',
      );
      err.code = '23505';
      throw err;
    }

    const newEnrolment = {
      enrolmentId: values.enrolmentId ?? crypto.randomUUID(),
      providerId: values.providerId,
      pcpcmBaId: values.pcpcmBaId,
      ffsBaId: values.ffsBaId,
      panelSize: values.panelSize ?? null,
      enrolmentDate: values.enrolmentDate,
      status: values.status ?? 'PENDING',
      createdAt: values.createdAt ?? new Date(),
      updatedAt: values.updatedAt ?? new Date(),
    };
    pcpcmEnrolmentStore.push(newEnrolment);
    return newEnrolment;
  }

  function insertWcbConfigRow(values: any): any {
    // Enforce unique (provider_id, contract_id)
    const existingDup = wcbConfigStore.find(
      (c) =>
        c.providerId === values.providerId &&
        c.contractId === values.contractId,
    );
    if (existingDup) {
      const err: any = new Error(
        'duplicate key value violates unique constraint "wcb_configurations_provider_contract_idx"',
      );
      err.code = '23505';
      throw err;
    }

    const newConfig = {
      wcbConfigId: values.wcbConfigId ?? crypto.randomUUID(),
      providerId: values.providerId,
      contractId: values.contractId,
      roleCode: values.roleCode,
      skillCode: values.skillCode ?? null,
      permittedFormTypes: values.permittedFormTypes,
      isDefault: values.isDefault ?? false,
      createdAt: values.createdAt ?? new Date(),
      updatedAt: values.updatedAt ?? new Date(),
    };
    wcbConfigStore.push(newConfig);
    return newConfig;
  }

  function insertDelegateRelRow(values: any): any {
    // Enforce partial unique: (physician_id, delegate_user_id) where status != 'REVOKED'
    const existingActive = delegateRelStore.find(
      (r) =>
        r.physicianId === values.physicianId &&
        r.delegateUserId === values.delegateUserId &&
        r.status !== 'REVOKED',
    );
    if (existingActive) {
      const err: any = new Error(
        'duplicate key value violates unique constraint "delegate_relationships_active_unique_idx"',
      );
      err.code = '23505';
      throw err;
    }

    const newRel = {
      relationshipId: values.relationshipId ?? crypto.randomUUID(),
      physicianId: values.physicianId,
      delegateUserId: values.delegateUserId,
      permissions: values.permissions,
      status: values.status ?? 'INVITED',
      invitedAt: values.invitedAt ?? new Date(),
      acceptedAt: values.acceptedAt ?? null,
      revokedAt: values.revokedAt ?? null,
      revokedBy: values.revokedBy ?? null,
      createdAt: values.createdAt ?? new Date(),
      updatedAt: values.updatedAt ?? new Date(),
    };
    delegateRelStore.push(newRel);
    return newRel;
  }

  function insertSubmissionPrefRow(values: any): any {
    // Enforce unique provider_id
    const existing = submissionPrefStore.find(
      (p) => p.providerId === values.providerId,
    );
    if (existing) {
      const err: any = new Error(
        'duplicate key value violates unique constraint "submission_preferences_provider_id_unique"',
      );
      err.code = '23505';
      throw err;
    }

    const newPref = {
      preferenceId: values.preferenceId ?? crypto.randomUUID(),
      providerId: values.providerId,
      ahcipSubmissionMode: values.ahcipSubmissionMode ?? 'AUTO_CLEAN',
      wcbSubmissionMode: values.wcbSubmissionMode ?? 'REQUIRE_APPROVAL',
      batchReviewReminder: values.batchReviewReminder ?? true,
      deadlineReminderDays: values.deadlineReminderDays ?? 7,
      updatedAt: values.updatedAt ?? new Date(),
      updatedBy: values.updatedBy,
    };
    submissionPrefStore.push(newPref);
    return newPref;
  }

  function insertHlinkConfigRow(values: any): any {
    // Enforce unique provider_id
    const existing = hlinkConfigStore.find(
      (c) => c.providerId === values.providerId,
    );
    if (existing) {
      const err: any = new Error(
        'duplicate key value violates unique constraint "hlink_configurations_provider_id_unique"',
      );
      err.code = '23505';
      throw err;
    }

    const newConfig = {
      hlinkConfigId: values.hlinkConfigId ?? crypto.randomUUID(),
      providerId: values.providerId,
      submitterPrefix: values.submitterPrefix,
      credentialSecretRef: values.credentialSecretRef,
      accreditationStatus: values.accreditationStatus ?? 'PENDING',
      accreditationDate: values.accreditationDate ?? null,
      lastSuccessfulTransmission: values.lastSuccessfulTransmission ?? null,
      createdAt: values.createdAt ?? new Date(),
      updatedAt: values.updatedAt ?? new Date(),
    };
    hlinkConfigStore.push(newConfig);
    return newConfig;
  }

  function insertRow(table: any, values: any): any {
    if (table?.__table === 'business_arrangements') {
      return insertBaRow(values);
    }
    if (table?.__table === 'practice_locations') {
      return insertLocationRow(values);
    }
    if (table?.__table === 'pcpcm_enrolments') {
      return insertPcpcmEnrolmentRow(values);
    }
    if (table?.__table === 'wcb_configurations') {
      return insertWcbConfigRow(values);
    }
    if (table?.__table === 'delegate_relationships') {
      return insertDelegateRelRow(values);
    }
    if (table?.__table === 'submission_preferences') {
      return insertSubmissionPrefRow(values);
    }
    if (table?.__table === 'hlink_configurations') {
      return insertHlinkConfigRow(values);
    }
    return insertProviderRow(values);
  }

  function executeOp(ctx: any): any[] {
    const store = getStoreForTable(ctx.table);

    switch (ctx.op) {
      case 'select': {
        let matches = store.filter((row) =>
          ctx.whereClauses.every((pred: any) => pred(row)),
        );
        const limited = ctx.limitN ? matches.slice(0, ctx.limitN) : matches;
        // Handle count() select: db.select({ value: count() })
        if (ctx.selectFields && ctx.selectFields.value && ctx.selectFields.value.__count) {
          return [{ value: limited.length }];
        }
        // Handle field projection with joins (for delegate relationship queries)
        if (ctx.selectFields && !ctx.selectFields.value) {
          return limited.map((row) => {
            const projected: any = {};
            for (const [alias, col] of Object.entries(ctx.selectFields)) {
              const colDef = col as any;
              const colName = colDef?.name;
              if (!colName) continue;
              // Check if the column belongs to a joined table
              if (colDef.__fromTable === 'users') {
                const user = userStore.find((u) => u.userId === row.delegateUserId);
                projected[alias] = user ? user[colName] : null;
              } else if (colDef.__fromTable === 'providers') {
                const provider = providerStore.find((p) => p.providerId === row.physicianId);
                projected[alias] = provider ? provider[colName] : null;
              } else {
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
        if (Array.isArray(values)) {
          return values.map((v: any) => insertRow(ctx.table, v));
        }
        return [insertRow(ctx.table, values)];
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
      return chainable({ op: 'select', selectFields: fields, whereClauses: [] });
    },
    update(table: any) {
      return chainable({ op: 'update', table, whereClauses: [] });
    },
    delete(table: any) {
      return chainable({ op: 'delete', table, whereClauses: [] });
    },
    async transaction(fn: any) {
      // The transaction callback receives the same DB (in-memory, no rollback needed)
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
    lte: (column: any, value: any) => {
      const colName = column?.name;
      return {
        __predicate: (row: any) => row[colName] <= value,
      };
    },
    gte: (column: any, value: any) => {
      const colName = column?.name;
      return {
        __predicate: (row: any) => row[colName] >= value,
      };
    },
    count: () => ({ __count: true }),
  };
});

// ---------------------------------------------------------------------------
// Mock the provider schema module
// ---------------------------------------------------------------------------

vi.mock('@meritum/shared/schemas/db/iam.schema.js', () => {
  const makeCol = (name: string) => ({ name, __fromTable: 'users' });

  const usersProxy: any = {
    __table: 'users',
    userId: makeCol('userId'),
    email: makeCol('email'),
    fullName: makeCol('fullName'),
    role: makeCol('role'),
    isActive: makeCol('isActive'),
  };

  return { users: usersProxy };
});

vi.mock('@meritum/shared/schemas/db/provider.schema.js', () => {
  const makeCol = (name: string) => ({ name });

  const makeProviderCol = (name: string) => ({ name, __fromTable: 'providers' });

  const providersProxy: any = {
    __table: 'providers',
    providerId: makeProviderCol('providerId'),
    billingNumber: makeProviderCol('billingNumber'),
    cpsaRegistrationNumber: makeProviderCol('cpsaRegistrationNumber'),
    firstName: makeProviderCol('firstName'),
    middleName: makeProviderCol('middleName'),
    lastName: makeProviderCol('lastName'),
    specialtyCode: makeProviderCol('specialtyCode'),
    specialtyDescription: makeProviderCol('specialtyDescription'),
    subSpecialtyCode: makeProviderCol('subSpecialtyCode'),
    physicianType: makeProviderCol('physicianType'),
    status: makeProviderCol('status'),
    onboardingCompleted: makeProviderCol('onboardingCompleted'),
    createdAt: makeProviderCol('createdAt'),
    updatedAt: makeProviderCol('updatedAt'),
  };

  const businessArrangementsProxy: any = {
    __table: 'business_arrangements',
    baId: makeCol('baId'),
    providerId: makeCol('providerId'),
    baNumber: makeCol('baNumber'),
    baType: makeCol('baType'),
    isPrimary: makeCol('isPrimary'),
    status: makeCol('status'),
    effectiveDate: makeCol('effectiveDate'),
    endDate: makeCol('endDate'),
    createdAt: makeCol('createdAt'),
    updatedAt: makeCol('updatedAt'),
  };

  const practiceLocationsProxy: any = {
    __table: 'practice_locations',
    locationId: makeCol('locationId'),
    providerId: makeCol('providerId'),
    name: makeCol('name'),
    functionalCentre: makeCol('functionalCentre'),
    facilityNumber: makeCol('facilityNumber'),
    addressLine1: makeCol('addressLine1'),
    addressLine2: makeCol('addressLine2'),
    city: makeCol('city'),
    province: makeCol('province'),
    postalCode: makeCol('postalCode'),
    communityCode: makeCol('communityCode'),
    rrnpEligible: makeCol('rrnpEligible'),
    rrnpRate: makeCol('rrnpRate'),
    isDefault: makeCol('isDefault'),
    isActive: makeCol('isActive'),
    createdAt: makeCol('createdAt'),
    updatedAt: makeCol('updatedAt'),
  };

  const pcpcmEnrolmentsProxy: any = {
    __table: 'pcpcm_enrolments',
    enrolmentId: makeCol('enrolmentId'),
    providerId: makeCol('providerId'),
    pcpcmBaId: makeCol('pcpcmBaId'),
    ffsBaId: makeCol('ffsBaId'),
    panelSize: makeCol('panelSize'),
    enrolmentDate: makeCol('enrolmentDate'),
    status: makeCol('status'),
    createdAt: makeCol('createdAt'),
    updatedAt: makeCol('updatedAt'),
  };

  const wcbConfigurationsProxy: any = {
    __table: 'wcb_configurations',
    wcbConfigId: makeCol('wcbConfigId'),
    providerId: makeCol('providerId'),
    contractId: makeCol('contractId'),
    roleCode: makeCol('roleCode'),
    skillCode: makeCol('skillCode'),
    permittedFormTypes: makeCol('permittedFormTypes'),
    isDefault: makeCol('isDefault'),
    createdAt: makeCol('createdAt'),
    updatedAt: makeCol('updatedAt'),
  };

  const delegateRelationshipsProxy: any = {
    __table: 'delegate_relationships',
    relationshipId: makeCol('relationshipId'),
    physicianId: makeCol('physicianId'),
    delegateUserId: makeCol('delegateUserId'),
    permissions: makeCol('permissions'),
    status: makeCol('status'),
    invitedAt: makeCol('invitedAt'),
    acceptedAt: makeCol('acceptedAt'),
    revokedAt: makeCol('revokedAt'),
    revokedBy: makeCol('revokedBy'),
    createdAt: makeCol('createdAt'),
    updatedAt: makeCol('updatedAt'),
  };

  const submissionPreferencesProxy: any = {
    __table: 'submission_preferences',
    preferenceId: makeCol('preferenceId'),
    providerId: makeCol('providerId'),
    ahcipSubmissionMode: makeCol('ahcipSubmissionMode'),
    wcbSubmissionMode: makeCol('wcbSubmissionMode'),
    batchReviewReminder: makeCol('batchReviewReminder'),
    deadlineReminderDays: makeCol('deadlineReminderDays'),
    updatedAt: makeCol('updatedAt'),
    updatedBy: makeCol('updatedBy'),
  };

  const hlinkConfigurationsProxy: any = {
    __table: 'hlink_configurations',
    hlinkConfigId: makeCol('hlinkConfigId'),
    providerId: makeCol('providerId'),
    submitterPrefix: makeCol('submitterPrefix'),
    credentialSecretRef: makeCol('credentialSecretRef'),
    accreditationStatus: makeCol('accreditationStatus'),
    accreditationDate: makeCol('accreditationDate'),
    lastSuccessfulTransmission: makeCol('lastSuccessfulTransmission'),
    createdAt: makeCol('createdAt'),
    updatedAt: makeCol('updatedAt'),
  };

  return {
    providers: providersProxy,
    businessArrangements: businessArrangementsProxy,
    practiceLocations: practiceLocationsProxy,
    pcpcmEnrolments: pcpcmEnrolmentsProxy,
    wcbConfigurations: wcbConfigurationsProxy,
    delegateRelationships: delegateRelationshipsProxy,
    submissionPreferences: submissionPreferencesProxy,
    hlinkConfigurations: hlinkConfigurationsProxy,
  };
});

vi.mock('@meritum/shared/schemas/db/reference.schema.js', () => {
  const makeCol = (name: string) => ({ name });

  const hscCodesProxy: any = {
    __table: 'hsc_codes',
    id: makeCol('id'),
    hscCode: makeCol('hscCode'),
    description: makeCol('description'),
    baseFee: makeCol('baseFee'),
    feeType: makeCol('feeType'),
    pcpcmBasket: makeCol('pcpcmBasket'),
    versionId: makeCol('versionId'),
    effectiveFrom: makeCol('effectiveFrom'),
    effectiveTo: makeCol('effectiveTo'),
  };

  const referenceDataVersionsProxy: any = {
    __table: 'reference_data_versions',
    versionId: makeCol('versionId'),
    dataSet: makeCol('dataSet'),
    versionLabel: makeCol('versionLabel'),
    effectiveFrom: makeCol('effectiveFrom'),
    effectiveTo: makeCol('effectiveTo'),
    isActive: makeCol('isActive'),
  };

  return {
    hscCodes: hscCodesProxy,
    referenceDataVersions: referenceDataVersionsProxy,
  };
});

vi.mock('@meritum/shared/schemas/provider.schema.js', () => {
  return {};
});

// ---------------------------------------------------------------------------
// Helper: default valid provider data
// ---------------------------------------------------------------------------

function validProviderData(overrides: Record<string, any> = {}) {
  return {
    providerId: overrides.providerId ?? crypto.randomUUID(),
    billingNumber: overrides.billingNumber ?? '123456',
    cpsaRegistrationNumber: overrides.cpsaRegistrationNumber ?? 'CPSA001',
    firstName: overrides.firstName ?? 'Jane',
    lastName: overrides.lastName ?? 'Smith',
    specialtyCode: overrides.specialtyCode ?? '01',
    physicianType: overrides.physicianType ?? 'GP',
    ...overrides,
  };
}

function validBaData(overrides: Record<string, any> = {}) {
  return {
    providerId: overrides.providerId ?? crypto.randomUUID(),
    baNumber: overrides.baNumber ?? 'BA001',
    baType: overrides.baType ?? 'FFS',
    isPrimary: overrides.isPrimary ?? true,
    status: overrides.status ?? 'ACTIVE',
    effectiveDate: overrides.effectiveDate ?? '2026-01-01',
    ...overrides,
  };
}

function validLocationData(overrides: Record<string, any> = {}) {
  return {
    providerId: overrides.providerId ?? crypto.randomUUID(),
    name: overrides.name ?? 'Main Clinic',
    functionalCentre: overrides.functionalCentre ?? 'FC001',
    facilityNumber: overrides.facilityNumber ?? 'FAC001',
    city: overrides.city ?? 'Calgary',
    province: overrides.province ?? 'AB',
    postalCode: overrides.postalCode ?? 'T2P1A1',
    isDefault: overrides.isDefault ?? false,
    isActive: overrides.isActive ?? true,
    ...overrides,
  };
}

function validPcpcmEnrolmentData(overrides: Record<string, any> = {}) {
  return {
    providerId: overrides.providerId ?? crypto.randomUUID(),
    pcpcmBaId: overrides.pcpcmBaId ?? crypto.randomUUID(),
    ffsBaId: overrides.ffsBaId ?? crypto.randomUUID(),
    panelSize: overrides.panelSize ?? 500,
    enrolmentDate: overrides.enrolmentDate ?? '2026-01-15',
    status: overrides.status ?? 'ACTIVE',
    ...overrides,
  };
}

function validWcbConfigData(overrides: Record<string, any> = {}) {
  return {
    providerId: overrides.providerId ?? crypto.randomUUID(),
    contractId: overrides.contractId ?? 'C001',
    roleCode: overrides.roleCode ?? 'PHYSICIAN',
    skillCode: overrides.skillCode ?? null,
    permittedFormTypes: overrides.permittedFormTypes ?? ['PHYSICIAN_FIRST_REPORT', 'PROGRESS_REPORT'],
    isDefault: overrides.isDefault ?? false,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Provider Repository', () => {
  let repo: ReturnType<typeof createProviderRepository>;

  beforeEach(() => {
    providerStore = [];
    baStore = [];
    locationStore = [];
    pcpcmEnrolmentStore = [];
    wcbConfigStore = [];
    delegateRelStore = [];
    userStore = [];
    submissionPrefStore = [];
    hlinkConfigStore = [];
    hscCodeStore = [];
    referenceVersionStore = [];
    const db = makeMockDb();
    repo = createProviderRepository(db);
  });

  // --- createProvider ---

  describe('createProvider', () => {
    it('inserts a provider record', async () => {
      const data = validProviderData();
      const result = await repo.createProvider(data);

      expect(result).toBeDefined();
      expect(result.providerId).toBe(data.providerId);
      expect(result.billingNumber).toBe('123456');
      expect(result.cpsaRegistrationNumber).toBe('CPSA001');
      expect(result.firstName).toBe('Jane');
      expect(result.lastName).toBe('Smith');
      expect(result.specialtyCode).toBe('01');
      expect(result.physicianType).toBe('GP');
      expect(result.status).toBe('ACTIVE');
      expect(result.onboardingCompleted).toBe(false);
      expect(providerStore).toHaveLength(1);
    });

    it('rejects duplicate billing_number', async () => {
      await repo.createProvider(validProviderData({ billingNumber: '111111' }));

      await expect(
        repo.createProvider(
          validProviderData({
            billingNumber: '111111',
            cpsaRegistrationNumber: 'CPSA999',
          }),
        ),
      ).rejects.toThrow('duplicate key value');
    });

    it('rejects duplicate cpsa_registration_number', async () => {
      await repo.createProvider(
        validProviderData({ cpsaRegistrationNumber: 'CPSA001' }),
      );

      await expect(
        repo.createProvider(
          validProviderData({
            billingNumber: '999999',
            cpsaRegistrationNumber: 'CPSA001',
          }),
        ),
      ).rejects.toThrow('duplicate key value');
    });
  });

  // --- findProviderById ---

  describe('findProviderById', () => {
    it('returns provider for valid ID', async () => {
      const data = validProviderData();
      await repo.createProvider(data);

      const found = await repo.findProviderById(data.providerId);
      expect(found).toBeDefined();
      expect(found!.providerId).toBe(data.providerId);
      expect(found!.billingNumber).toBe(data.billingNumber);
    });

    it('returns undefined for unknown ID', async () => {
      const found = await repo.findProviderById(crypto.randomUUID());
      expect(found).toBeUndefined();
    });
  });

  // --- findProviderByBillingNumber ---

  describe('findProviderByBillingNumber', () => {
    it('returns provider for valid billing number', async () => {
      const data = validProviderData({ billingNumber: '555555' });
      await repo.createProvider(data);

      const found = await repo.findProviderByBillingNumber('555555');
      expect(found).toBeDefined();
      expect(found!.billingNumber).toBe('555555');
    });

    it('returns undefined for unknown billing number', async () => {
      const found = await repo.findProviderByBillingNumber('000000');
      expect(found).toBeUndefined();
    });
  });

  // --- findProviderByCpsaNumber ---

  describe('findProviderByCpsaNumber', () => {
    it('returns provider for valid CPSA number', async () => {
      const data = validProviderData({ cpsaRegistrationNumber: 'CPSA123' });
      await repo.createProvider(data);

      const found = await repo.findProviderByCpsaNumber('CPSA123');
      expect(found).toBeDefined();
      expect(found!.cpsaRegistrationNumber).toBe('CPSA123');
    });

    it('returns undefined for unknown CPSA number', async () => {
      const found = await repo.findProviderByCpsaNumber('NOPE');
      expect(found).toBeUndefined();
    });
  });

  // --- updateProvider ---

  describe('updateProvider', () => {
    it('updates fields and updated_at', async () => {
      const data = validProviderData();
      const created = await repo.createProvider(data);
      const originalUpdatedAt = created.updatedAt;

      // Small delay to ensure updatedAt differs
      await new Promise((r) => setTimeout(r, 5));

      const updated = await repo.updateProvider(data.providerId, {
        firstName: 'Updated',
        lastName: 'Name',
      });

      expect(updated).toBeDefined();
      expect(updated!.firstName).toBe('Updated');
      expect(updated!.lastName).toBe('Name');
      expect(updated!.updatedAt).not.toEqual(originalUpdatedAt);
    });

    it('returns undefined for non-existent provider', async () => {
      const updated = await repo.updateProvider(crypto.randomUUID(), {
        firstName: 'Ghost',
      });
      expect(updated).toBeUndefined();
    });
  });

  // --- completeOnboarding ---

  describe('completeOnboarding', () => {
    it('sets onboarding_completed to true when all required fields present', async () => {
      const data = validProviderData();
      await repo.createProvider(data);

      const result = await repo.completeOnboarding(data.providerId);
      expect(result).toBeDefined();
      expect(result!.onboardingCompleted).toBe(true);
    });

    it('throws OnboardingIncompleteError if required fields are missing', async () => {
      // Create provider with missing firstName (set to empty string to simulate missing)
      const data = validProviderData({ firstName: '' });
      await repo.createProvider(data);

      await expect(
        repo.completeOnboarding(data.providerId),
      ).rejects.toThrow(OnboardingIncompleteError);

      try {
        await repo.completeOnboarding(data.providerId);
      } catch (err) {
        expect(err).toBeInstanceOf(OnboardingIncompleteError);
        expect((err as OnboardingIncompleteError).missingFields).toContain(
          'firstName',
        );
      }
    });

    it('returns undefined for non-existent provider', async () => {
      const result = await repo.completeOnboarding(crypto.randomUUID());
      expect(result).toBeUndefined();
    });
  });

  // --- getOnboardingStatus ---

  describe('getOnboardingStatus', () => {
    it('reports all fields populated when complete', async () => {
      const data = validProviderData();
      await repo.createProvider(data);

      const status = await repo.getOnboardingStatus(data.providerId);
      expect(status).toBeDefined();
      expect(status!.complete).toBe(true);
      expect(status!.missing).toHaveLength(0);
      expect(status!.populated).toContain('billingNumber');
      expect(status!.populated).toContain('firstName');
      expect(status!.populated).toContain('lastName');
      expect(status!.populated).toContain('specialtyCode');
      expect(status!.populated).toContain('physicianType');
      expect(status!.populated).toContain('cpsaRegistrationNumber');
    });

    it('reports missing fields accurately', async () => {
      // Create a provider with empty firstName and specialtyCode
      const data = validProviderData({
        firstName: '',
        specialtyCode: '',
      });
      await repo.createProvider(data);

      const status = await repo.getOnboardingStatus(data.providerId);
      expect(status).toBeDefined();
      expect(status!.complete).toBe(false);
      expect(status!.missing).toContain('firstName');
      expect(status!.missing).toContain('specialtyCode');
      expect(status!.populated).not.toContain('firstName');
      expect(status!.populated).not.toContain('specialtyCode');
      // Other fields should be populated
      expect(status!.populated).toContain('billingNumber');
      expect(status!.populated).toContain('lastName');
    });

    it('returns undefined for non-existent provider', async () => {
      const status = await repo.getOnboardingStatus(crypto.randomUUID());
      expect(status).toBeUndefined();
    });

    it('reflects onboardingCompleted flag accurately', async () => {
      const data = validProviderData();
      await repo.createProvider(data);

      // Before completing onboarding
      let status = await repo.getOnboardingStatus(data.providerId);
      expect(status!.onboardingCompleted).toBe(false);

      // Complete onboarding
      await repo.completeOnboarding(data.providerId);

      // After completing onboarding
      status = await repo.getOnboardingStatus(data.providerId);
      expect(status!.onboardingCompleted).toBe(true);
    });
  });

  // --- Business Arrangement: createBa ---

  describe('createBa', () => {
    it('inserts a BA record', async () => {
      const providerId = crypto.randomUUID();
      const data = validBaData({ providerId });
      const result = await repo.createBa(data);

      expect(result).toBeDefined();
      expect(result.providerId).toBe(providerId);
      expect(result.baNumber).toBe('BA001');
      expect(result.baType).toBe('FFS');
      expect(result.isPrimary).toBe(true);
      expect(result.status).toBe('ACTIVE');
      expect(result.effectiveDate).toBe('2026-01-01');
      expect(result.endDate).toBeNull();
      expect(baStore).toHaveLength(1);
    });
  });

  // --- Business Arrangement: listBasForProvider ---

  describe('listBasForProvider', () => {
    it('returns only this provider\'s BAs', async () => {
      const provider1 = crypto.randomUUID();
      const provider2 = crypto.randomUUID();

      await repo.createBa(validBaData({ providerId: provider1, baNumber: 'BA001' }));
      await repo.createBa(validBaData({ providerId: provider1, baNumber: 'BA002', status: 'INACTIVE' }));
      await repo.createBa(validBaData({ providerId: provider2, baNumber: 'BA003' }));

      const results = await repo.listBasForProvider(provider1);
      expect(results).toHaveLength(2);
      results.forEach((ba: any) => {
        expect(ba.providerId).toBe(provider1);
      });
    });

    it('returns empty array when provider has no BAs', async () => {
      const results = await repo.listBasForProvider(crypto.randomUUID());
      expect(results).toHaveLength(0);
    });
  });

  // --- Business Arrangement: listActiveBasForProvider ---

  describe('listActiveBasForProvider', () => {
    it('excludes INACTIVE BAs', async () => {
      const providerId = crypto.randomUUID();

      await repo.createBa(validBaData({ providerId, baNumber: 'BA001', status: 'ACTIVE' }));
      await repo.createBa(validBaData({ providerId, baNumber: 'BA002', status: 'PENDING' }));
      await repo.createBa(validBaData({ providerId, baNumber: 'BA003', status: 'INACTIVE' }));

      const results = await repo.listActiveBasForProvider(providerId);
      expect(results).toHaveLength(1);
      expect(results[0].baNumber).toBe('BA001');
      expect(results[0].status).toBe('ACTIVE');
    });
  });

  // --- Business Arrangement: countActiveBasForProvider ---

  describe('countActiveBasForProvider', () => {
    it('returns correct count of active BAs', async () => {
      const providerId = crypto.randomUUID();

      await repo.createBa(validBaData({ providerId, baNumber: 'BA001', status: 'ACTIVE' }));
      await repo.createBa(validBaData({ providerId, baNumber: 'BA002', status: 'ACTIVE' }));
      await repo.createBa(validBaData({ providerId, baNumber: 'BA003', status: 'INACTIVE' }));
      await repo.createBa(validBaData({ providerId, baNumber: 'BA004', status: 'PENDING' }));

      const result = await repo.countActiveBasForProvider(providerId);
      expect(result).toBe(2);
    });

    it('returns 0 when no active BAs exist', async () => {
      const result = await repo.countActiveBasForProvider(crypto.randomUUID());
      expect(result).toBe(0);
    });
  });

  // --- Business Arrangement: updateBa ---

  describe('updateBa', () => {
    it('updates fields scoped to provider', async () => {
      const providerId = crypto.randomUUID();
      const ba = await repo.createBa(validBaData({ providerId, baNumber: 'BA001', status: 'PENDING' }));

      const updated = await repo.updateBa(ba.baId, providerId, {
        status: 'ACTIVE',
        effectiveDate: '2026-03-01',
      });

      expect(updated).toBeDefined();
      expect(updated!.status).toBe('ACTIVE');
      expect(updated!.effectiveDate).toBe('2026-03-01');
    });

    it('rejects if BA belongs to different provider', async () => {
      const provider1 = crypto.randomUUID();
      const provider2 = crypto.randomUUID();
      const ba = await repo.createBa(validBaData({ providerId: provider1, baNumber: 'BA001' }));

      const result = await repo.updateBa(ba.baId, provider2, { status: 'INACTIVE' });
      expect(result).toBeUndefined();
    });

    it('returns undefined for non-existent BA', async () => {
      const result = await repo.updateBa(crypto.randomUUID(), crypto.randomUUID(), { status: 'ACTIVE' });
      expect(result).toBeUndefined();
    });
  });

  // --- Business Arrangement: deactivateBa ---

  describe('deactivateBa', () => {
    it('sets INACTIVE and end_date', async () => {
      const providerId = crypto.randomUUID();
      const ba = await repo.createBa(validBaData({ providerId, baNumber: 'BA001', status: 'ACTIVE' }));

      const result = await repo.deactivateBa(ba.baId, providerId);

      expect(result).toBeDefined();
      expect(result!.status).toBe('INACTIVE');
      expect(result!.endDate).toBeDefined();
      expect(result!.endDate).not.toBeNull();
    });

    it('returns undefined if BA belongs to different provider', async () => {
      const provider1 = crypto.randomUUID();
      const provider2 = crypto.randomUUID();
      const ba = await repo.createBa(validBaData({ providerId: provider1, baNumber: 'BA001' }));

      const result = await repo.deactivateBa(ba.baId, provider2);
      expect(result).toBeUndefined();
    });
  });

  // --- Business Arrangement: findBaByNumber ---

  describe('findBaByNumber', () => {
    it('finds active BA across system', async () => {
      const provider1 = crypto.randomUUID();
      await repo.createBa(validBaData({ providerId: provider1, baNumber: 'BA777', status: 'ACTIVE' }));

      const found = await repo.findBaByNumber('BA777');
      expect(found).toBeDefined();
      expect(found!.baNumber).toBe('BA777');
    });

    it('finds pending BA (non-INACTIVE)', async () => {
      const providerId = crypto.randomUUID();
      await repo.createBa(validBaData({ providerId, baNumber: 'BA888', status: 'PENDING' }));

      const found = await repo.findBaByNumber('BA888');
      expect(found).toBeDefined();
      expect(found!.baNumber).toBe('BA888');
    });

    it('does not find INACTIVE BA', async () => {
      const providerId = crypto.randomUUID();
      await repo.createBa(validBaData({ providerId, baNumber: 'BA999', status: 'INACTIVE' }));

      const found = await repo.findBaByNumber('BA999');
      expect(found).toBeUndefined();
    });

    it('returns undefined for non-existent ba_number', async () => {
      const found = await repo.findBaByNumber('NOPE');
      expect(found).toBeUndefined();
    });
  });

  // --- Business Arrangement: findBaById ---

  describe('findBaById', () => {
    it('returns BA for valid ID and provider', async () => {
      const providerId = crypto.randomUUID();
      const ba = await repo.createBa(validBaData({ providerId, baNumber: 'BA001' }));

      const found = await repo.findBaById(ba.baId, providerId);
      expect(found).toBeDefined();
      expect(found!.baId).toBe(ba.baId);
      expect(found!.providerId).toBe(providerId);
    });

    it('returns undefined when provider does not own the BA', async () => {
      const provider1 = crypto.randomUUID();
      const provider2 = crypto.randomUUID();
      const ba = await repo.createBa(validBaData({ providerId: provider1, baNumber: 'BA001' }));

      const found = await repo.findBaById(ba.baId, provider2);
      expect(found).toBeUndefined();
    });

    it('returns undefined for non-existent BA', async () => {
      const found = await repo.findBaById(crypto.randomUUID(), crypto.randomUUID());
      expect(found).toBeUndefined();
    });
  });

  // --- Practice Location: createLocation ---

  describe('createLocation', () => {
    it('inserts a location record', async () => {
      const providerId = crypto.randomUUID();
      const data = validLocationData({ providerId });
      const result = await repo.createLocation(data);

      expect(result).toBeDefined();
      expect(result.providerId).toBe(providerId);
      expect(result.name).toBe('Main Clinic');
      expect(result.functionalCentre).toBe('FC001');
      expect(result.isDefault).toBe(false);
      expect(result.isActive).toBe(true);
      expect(locationStore).toHaveLength(1);
    });
  });

  // --- Practice Location: listActiveLocationsForProvider ---

  describe('listActiveLocationsForProvider', () => {
    it('returns only active locations', async () => {
      const providerId = crypto.randomUUID();

      await repo.createLocation(validLocationData({ providerId, name: 'Active1', isActive: true }));
      await repo.createLocation(validLocationData({ providerId, name: 'Active2', isActive: true }));
      await repo.createLocation(validLocationData({ providerId, name: 'Inactive1', isActive: false }));

      const results = await repo.listActiveLocationsForProvider(providerId);
      expect(results).toHaveLength(2);
      results.forEach((loc: any) => {
        expect(loc.isActive).toBe(true);
        expect(loc.providerId).toBe(providerId);
      });
    });

    it('does not return other providers locations', async () => {
      const provider1 = crypto.randomUUID();
      const provider2 = crypto.randomUUID();

      await repo.createLocation(validLocationData({ providerId: provider1, name: 'Clinic A' }));
      await repo.createLocation(validLocationData({ providerId: provider2, name: 'Clinic B' }));

      const results = await repo.listActiveLocationsForProvider(provider1);
      expect(results).toHaveLength(1);
      expect(results[0].providerId).toBe(provider1);
    });
  });

  // --- Practice Location: updateLocation ---

  describe('updateLocation', () => {
    it('updates fields scoped to provider', async () => {
      const providerId = crypto.randomUUID();
      const loc = await repo.createLocation(validLocationData({ providerId }));

      const updated = await repo.updateLocation(loc.locationId, providerId, {
        name: 'Renamed Clinic',
        city: 'Edmonton',
      });

      expect(updated).toBeDefined();
      expect(updated!.name).toBe('Renamed Clinic');
      expect(updated!.city).toBe('Edmonton');
    });

    it('rejects if location belongs to different provider', async () => {
      const provider1 = crypto.randomUUID();
      const provider2 = crypto.randomUUID();
      const loc = await repo.createLocation(validLocationData({ providerId: provider1 }));

      const result = await repo.updateLocation(loc.locationId, provider2, { name: 'Hacked' });
      expect(result).toBeUndefined();
    });
  });

  // --- Practice Location: setDefaultLocation ---

  describe('setDefaultLocation', () => {
    it('unsets previous default and sets new', async () => {
      const providerId = crypto.randomUUID();
      const loc1 = await repo.createLocation(validLocationData({ providerId, name: 'Clinic A', isDefault: true }));
      const loc2 = await repo.createLocation(validLocationData({ providerId, name: 'Clinic B', isDefault: false }));

      const result = await repo.setDefaultLocation(loc2.locationId, providerId);

      expect(result).toBeDefined();
      expect(result!.isDefault).toBe(true);
      expect(result!.locationId).toBe(loc2.locationId);

      // Verify the old default was unset
      const oldDefault = locationStore.find((l) => l.locationId === loc1.locationId);
      expect(oldDefault!.isDefault).toBe(false);
    });

    it('returns undefined if location belongs to different provider', async () => {
      const provider1 = crypto.randomUUID();
      const provider2 = crypto.randomUUID();
      const loc = await repo.createLocation(validLocationData({ providerId: provider1, isDefault: false }));

      const result = await repo.setDefaultLocation(loc.locationId, provider2);
      expect(result).toBeUndefined();
    });
  });

  // --- Practice Location: deactivateLocation ---

  describe('deactivateLocation', () => {
    it('sets is_active false', async () => {
      const providerId = crypto.randomUUID();
      const loc = await repo.createLocation(validLocationData({ providerId }));

      const result = await repo.deactivateLocation(loc.locationId, providerId);

      expect(result).toBeDefined();
      expect(result!.isActive).toBe(false);
    });

    it('clears is_default if was default', async () => {
      const providerId = crypto.randomUUID();
      const loc = await repo.createLocation(validLocationData({ providerId, isDefault: true }));

      const result = await repo.deactivateLocation(loc.locationId, providerId);

      expect(result).toBeDefined();
      expect(result!.isActive).toBe(false);
      expect(result!.isDefault).toBe(false);
    });

    it('returns undefined if location belongs to different provider', async () => {
      const provider1 = crypto.randomUUID();
      const provider2 = crypto.randomUUID();
      const loc = await repo.createLocation(validLocationData({ providerId: provider1 }));

      const result = await repo.deactivateLocation(loc.locationId, provider2);
      expect(result).toBeUndefined();
    });
  });

  // --- Practice Location: getDefaultLocation ---

  describe('getDefaultLocation', () => {
    it('returns default location', async () => {
      const providerId = crypto.randomUUID();
      await repo.createLocation(validLocationData({ providerId, name: 'Regular', isDefault: false }));
      await repo.createLocation(validLocationData({ providerId, name: 'Default', isDefault: true }));

      const result = await repo.getDefaultLocation(providerId);

      expect(result).toBeDefined();
      expect(result!.name).toBe('Default');
      expect(result!.isDefault).toBe(true);
    });

    it('returns undefined when no default is set', async () => {
      const providerId = crypto.randomUUID();
      await repo.createLocation(validLocationData({ providerId, isDefault: false }));

      const result = await repo.getDefaultLocation(providerId);
      expect(result).toBeUndefined();
    });

    it('does not return inactive default', async () => {
      const providerId = crypto.randomUUID();
      await repo.createLocation(validLocationData({ providerId, isDefault: true, isActive: false }));

      const result = await repo.getDefaultLocation(providerId);
      expect(result).toBeUndefined();
    });
  });

  // --- PCPCM Enrolment: createPcpcmEnrolment ---

  describe('createPcpcmEnrolment', () => {
    it('inserts enrolment record', async () => {
      const providerId = crypto.randomUUID();
      const data = validPcpcmEnrolmentData({ providerId });
      const result = await repo.createPcpcmEnrolment(data);

      expect(result).toBeDefined();
      expect(result.providerId).toBe(providerId);
      expect(result.pcpcmBaId).toBe(data.pcpcmBaId);
      expect(result.ffsBaId).toBe(data.ffsBaId);
      expect(result.panelSize).toBe(500);
      expect(result.enrolmentDate).toBe('2026-01-15');
      expect(result.status).toBe('ACTIVE');
      expect(pcpcmEnrolmentStore).toHaveLength(1);
    });

    it('rejects duplicate active enrolment for same provider', async () => {
      const providerId = crypto.randomUUID();
      await repo.createPcpcmEnrolment(validPcpcmEnrolmentData({ providerId, status: 'ACTIVE' }));

      await expect(
        repo.createPcpcmEnrolment(
          validPcpcmEnrolmentData({ providerId, status: 'PENDING' }),
        ),
      ).rejects.toThrow('duplicate key value');
    });

    it('allows new enrolment if previous is WITHDRAWN', async () => {
      const providerId = crypto.randomUUID();
      await repo.createPcpcmEnrolment(
        validPcpcmEnrolmentData({ providerId, status: 'WITHDRAWN' }),
      );

      const result = await repo.createPcpcmEnrolment(
        validPcpcmEnrolmentData({ providerId, status: 'ACTIVE' }),
      );
      expect(result).toBeDefined();
      expect(result.status).toBe('ACTIVE');
      expect(pcpcmEnrolmentStore).toHaveLength(2);
    });
  });

  // --- PCPCM Enrolment: findPcpcmEnrolmentForProvider ---

  describe('findPcpcmEnrolmentForProvider', () => {
    it('returns active enrolment', async () => {
      const providerId = crypto.randomUUID();
      await repo.createPcpcmEnrolment(
        validPcpcmEnrolmentData({ providerId, status: 'ACTIVE' }),
      );

      const found = await repo.findPcpcmEnrolmentForProvider(providerId);
      expect(found).toBeDefined();
      expect(found!.providerId).toBe(providerId);
      expect(found!.status).toBe('ACTIVE');
    });

    it('returns pending enrolment (non-WITHDRAWN)', async () => {
      const providerId = crypto.randomUUID();
      await repo.createPcpcmEnrolment(
        validPcpcmEnrolmentData({ providerId, status: 'PENDING' }),
      );

      const found = await repo.findPcpcmEnrolmentForProvider(providerId);
      expect(found).toBeDefined();
      expect(found!.status).toBe('PENDING');
    });

    it('does not return WITHDRAWN enrolment', async () => {
      const providerId = crypto.randomUUID();
      await repo.createPcpcmEnrolment(
        validPcpcmEnrolmentData({ providerId, status: 'WITHDRAWN' }),
      );

      const found = await repo.findPcpcmEnrolmentForProvider(providerId);
      expect(found).toBeUndefined();
    });

    it('returns undefined when no enrolment exists', async () => {
      const found = await repo.findPcpcmEnrolmentForProvider(crypto.randomUUID());
      expect(found).toBeUndefined();
    });

    it('does not return another provider\'s enrolment', async () => {
      const provider1 = crypto.randomUUID();
      const provider2 = crypto.randomUUID();
      await repo.createPcpcmEnrolment(
        validPcpcmEnrolmentData({ providerId: provider1, status: 'ACTIVE' }),
      );

      const found = await repo.findPcpcmEnrolmentForProvider(provider2);
      expect(found).toBeUndefined();
    });
  });

  // --- PCPCM Enrolment: updatePcpcmEnrolment ---

  describe('updatePcpcmEnrolment', () => {
    it('updates panel size scoped to provider', async () => {
      const providerId = crypto.randomUUID();
      const enrolment = await repo.createPcpcmEnrolment(
        validPcpcmEnrolmentData({ providerId, panelSize: 500 }),
      );

      const updated = await repo.updatePcpcmEnrolment(
        enrolment.enrolmentId,
        providerId,
        { panelSize: 750 },
      );

      expect(updated).toBeDefined();
      expect(updated!.panelSize).toBe(750);
    });

    it('updates status scoped to provider', async () => {
      const providerId = crypto.randomUUID();
      const enrolment = await repo.createPcpcmEnrolment(
        validPcpcmEnrolmentData({ providerId, status: 'PENDING' }),
      );

      const updated = await repo.updatePcpcmEnrolment(
        enrolment.enrolmentId,
        providerId,
        { status: 'ACTIVE' },
      );

      expect(updated).toBeDefined();
      expect(updated!.status).toBe('ACTIVE');
    });

    it('returns undefined if enrolment belongs to different provider', async () => {
      const provider1 = crypto.randomUUID();
      const provider2 = crypto.randomUUID();
      const enrolment = await repo.createPcpcmEnrolment(
        validPcpcmEnrolmentData({ providerId: provider1 }),
      );

      const result = await repo.updatePcpcmEnrolment(
        enrolment.enrolmentId,
        provider2,
        { panelSize: 999 },
      );
      expect(result).toBeUndefined();
    });

    it('returns undefined for non-existent enrolment', async () => {
      const result = await repo.updatePcpcmEnrolment(
        crypto.randomUUID(),
        crypto.randomUUID(),
        { panelSize: 100 },
      );
      expect(result).toBeUndefined();
    });
  });

  // --- WCB Configuration: createWcbConfig ---

  describe('createWcbConfig', () => {
    it('inserts WCB config', async () => {
      const providerId = crypto.randomUUID();
      const data = validWcbConfigData({ providerId });
      const result = await repo.createWcbConfig(data);

      expect(result).toBeDefined();
      expect(result.providerId).toBe(providerId);
      expect(result.contractId).toBe('C001');
      expect(result.roleCode).toBe('PHYSICIAN');
      expect(result.permittedFormTypes).toEqual(['PHYSICIAN_FIRST_REPORT', 'PROGRESS_REPORT']);
      expect(result.isDefault).toBe(false);
      expect(wcbConfigStore).toHaveLength(1);
    });

    it('rejects duplicate (provider_id, contract_id)', async () => {
      const providerId = crypto.randomUUID();
      await repo.createWcbConfig(
        validWcbConfigData({ providerId, contractId: 'C001' }),
      );

      await expect(
        repo.createWcbConfig(
          validWcbConfigData({ providerId, contractId: 'C001', roleCode: 'SPECIALIST' }),
        ),
      ).rejects.toThrow('duplicate key value');
    });

    it('allows same contract_id for different providers', async () => {
      const provider1 = crypto.randomUUID();
      const provider2 = crypto.randomUUID();

      await repo.createWcbConfig(validWcbConfigData({ providerId: provider1, contractId: 'C001' }));
      const result = await repo.createWcbConfig(
        validWcbConfigData({ providerId: provider2, contractId: 'C001' }),
      );

      expect(result).toBeDefined();
      expect(wcbConfigStore).toHaveLength(2);
    });

    it('rejects non-array permittedFormTypes', async () => {
      const providerId = crypto.randomUUID();

      await expect(
        repo.createWcbConfig(
          validWcbConfigData({ providerId, permittedFormTypes: 'not-an-array' }),
        ),
      ).rejects.toThrow(InvalidPermittedFormTypesError);
    });

    it('rejects permittedFormTypes with non-string items', async () => {
      const providerId = crypto.randomUUID();

      await expect(
        repo.createWcbConfig(
          validWcbConfigData({ providerId, permittedFormTypes: ['valid', 123, true] }),
        ),
      ).rejects.toThrow(InvalidPermittedFormTypesError);
    });
  });

  // --- WCB Configuration: listWcbConfigsForProvider ---

  describe('listWcbConfigsForProvider', () => {
    it('returns only this provider\'s configs', async () => {
      const provider1 = crypto.randomUUID();
      const provider2 = crypto.randomUUID();

      await repo.createWcbConfig(validWcbConfigData({ providerId: provider1, contractId: 'C001' }));
      await repo.createWcbConfig(validWcbConfigData({ providerId: provider1, contractId: 'C002' }));
      await repo.createWcbConfig(validWcbConfigData({ providerId: provider2, contractId: 'C003' }));

      const results = await repo.listWcbConfigsForProvider(provider1);
      expect(results).toHaveLength(2);
      results.forEach((c: any) => {
        expect(c.providerId).toBe(provider1);
      });
    });

    it('returns empty array when provider has no configs', async () => {
      const results = await repo.listWcbConfigsForProvider(crypto.randomUUID());
      expect(results).toHaveLength(0);
    });
  });

  // --- WCB Configuration: findWcbConfigById ---

  describe('findWcbConfigById', () => {
    it('returns config for valid ID and provider', async () => {
      const providerId = crypto.randomUUID();
      const config = await repo.createWcbConfig(
        validWcbConfigData({ providerId }),
      );

      const found = await repo.findWcbConfigById(config.wcbConfigId, providerId);
      expect(found).toBeDefined();
      expect(found!.wcbConfigId).toBe(config.wcbConfigId);
    });

    it('returns undefined when provider does not own the config', async () => {
      const provider1 = crypto.randomUUID();
      const provider2 = crypto.randomUUID();
      const config = await repo.createWcbConfig(
        validWcbConfigData({ providerId: provider1 }),
      );

      const found = await repo.findWcbConfigById(config.wcbConfigId, provider2);
      expect(found).toBeUndefined();
    });
  });

  // --- WCB Configuration: updateWcbConfig ---

  describe('updateWcbConfig', () => {
    it('updates fields scoped to provider', async () => {
      const providerId = crypto.randomUUID();
      const config = await repo.createWcbConfig(
        validWcbConfigData({ providerId }),
      );

      const updated = await repo.updateWcbConfig(config.wcbConfigId, providerId, {
        skillCode: 'SURG',
      });

      expect(updated).toBeDefined();
      expect(updated!.skillCode).toBe('SURG');
    });

    it('validates permittedFormTypes on update', async () => {
      const providerId = crypto.randomUUID();
      const config = await repo.createWcbConfig(
        validWcbConfigData({ providerId }),
      );

      await expect(
        repo.updateWcbConfig(config.wcbConfigId, providerId, {
          permittedFormTypes: 'bad' as any,
        }),
      ).rejects.toThrow(InvalidPermittedFormTypesError);
    });

    it('returns undefined if config belongs to different provider', async () => {
      const provider1 = crypto.randomUUID();
      const provider2 = crypto.randomUUID();
      const config = await repo.createWcbConfig(
        validWcbConfigData({ providerId: provider1 }),
      );

      const result = await repo.updateWcbConfig(config.wcbConfigId, provider2, {
        skillCode: 'HACK',
      });
      expect(result).toBeUndefined();
    });
  });

  // --- WCB Configuration: deleteWcbConfig ---

  describe('deleteWcbConfig', () => {
    it('removes config scoped to provider', async () => {
      const providerId = crypto.randomUUID();
      const config = await repo.createWcbConfig(
        validWcbConfigData({ providerId }),
      );

      const result = await repo.deleteWcbConfig(config.wcbConfigId, providerId);
      expect(result).toBe(true);
      expect(wcbConfigStore).toHaveLength(0);
    });

    it('returns false if config belongs to different provider', async () => {
      const provider1 = crypto.randomUUID();
      const provider2 = crypto.randomUUID();
      const config = await repo.createWcbConfig(
        validWcbConfigData({ providerId: provider1 }),
      );

      const result = await repo.deleteWcbConfig(config.wcbConfigId, provider2);
      expect(result).toBe(false);
      expect(wcbConfigStore).toHaveLength(1); // Not deleted
    });

    it('returns false for non-existent config', async () => {
      const result = await repo.deleteWcbConfig(
        crypto.randomUUID(),
        crypto.randomUUID(),
      );
      expect(result).toBe(false);
    });
  });

  // --- WCB Configuration: setDefaultWcbConfig ---

  describe('setDefaultWcbConfig', () => {
    it('unsets previous default and sets new', async () => {
      const providerId = crypto.randomUUID();
      const config1 = await repo.createWcbConfig(
        validWcbConfigData({ providerId, contractId: 'C001', isDefault: true }),
      );
      const config2 = await repo.createWcbConfig(
        validWcbConfigData({ providerId, contractId: 'C002', isDefault: false }),
      );

      const result = await repo.setDefaultWcbConfig(config2.wcbConfigId, providerId);

      expect(result).toBeDefined();
      expect(result!.isDefault).toBe(true);
      expect(result!.wcbConfigId).toBe(config2.wcbConfigId);

      // Verify the old default was unset
      const oldDefault = wcbConfigStore.find(
        (c) => c.wcbConfigId === config1.wcbConfigId,
      );
      expect(oldDefault!.isDefault).toBe(false);
    });

    it('returns undefined if config belongs to different provider', async () => {
      const provider1 = crypto.randomUUID();
      const provider2 = crypto.randomUUID();
      const config = await repo.createWcbConfig(
        validWcbConfigData({ providerId: provider1, isDefault: false }),
      );

      const result = await repo.setDefaultWcbConfig(config.wcbConfigId, provider2);
      expect(result).toBeUndefined();
    });
  });

  // --- WCB Configuration: getAggregatedFormPermissions ---

  describe('getAggregatedFormPermissions', () => {
    it('unions all permitted form types', async () => {
      const providerId = crypto.randomUUID();
      await repo.createWcbConfig(
        validWcbConfigData({
          providerId,
          contractId: 'C001',
          permittedFormTypes: ['PHYSICIAN_FIRST_REPORT', 'PROGRESS_REPORT'],
        }),
      );
      await repo.createWcbConfig(
        validWcbConfigData({
          providerId,
          contractId: 'C002',
          permittedFormTypes: ['PROGRESS_REPORT', 'SPECIALIST_REPORT'],
        }),
      );

      const result = await repo.getAggregatedFormPermissions(providerId);

      expect(result).toHaveLength(3);
      expect(result).toContain('PHYSICIAN_FIRST_REPORT');
      expect(result).toContain('PROGRESS_REPORT');
      expect(result).toContain('SPECIALIST_REPORT');
    });

    it('returns empty array when provider has no configs', async () => {
      const result = await repo.getAggregatedFormPermissions(crypto.randomUUID());
      expect(result).toHaveLength(0);
    });

    it('deduplicates form types across configs', async () => {
      const providerId = crypto.randomUUID();
      await repo.createWcbConfig(
        validWcbConfigData({
          providerId,
          contractId: 'C001',
          permittedFormTypes: ['FORM_A', 'FORM_B'],
        }),
      );
      await repo.createWcbConfig(
        validWcbConfigData({
          providerId,
          contractId: 'C002',
          permittedFormTypes: ['FORM_A', 'FORM_B'],
        }),
      );

      const result = await repo.getAggregatedFormPermissions(providerId);
      expect(result).toHaveLength(2);
      expect(result).toContain('FORM_A');
      expect(result).toContain('FORM_B');
    });

    it('does not include other provider\'s form types', async () => {
      const provider1 = crypto.randomUUID();
      const provider2 = crypto.randomUUID();

      await repo.createWcbConfig(
        validWcbConfigData({
          providerId: provider1,
          contractId: 'C001',
          permittedFormTypes: ['FORM_A'],
        }),
      );
      await repo.createWcbConfig(
        validWcbConfigData({
          providerId: provider2,
          contractId: 'C002',
          permittedFormTypes: ['FORM_B'],
        }),
      );

      const result = await repo.getAggregatedFormPermissions(provider1);
      expect(result).toHaveLength(1);
      expect(result).toContain('FORM_A');
      expect(result).not.toContain('FORM_B');
    });
  });

  // --- Delegate Relationship: createDelegateRelationship ---

  describe('createDelegateRelationship', () => {
    it('inserts with status INVITED', async () => {
      const physicianId = crypto.randomUUID();
      const delegateUserId = crypto.randomUUID();
      const result = await repo.createDelegateRelationship({
        physicianId,
        delegateUserId,
        permissions: ['CLAIM_VIEW', 'CLAIM_CREATE'],
        invitedAt: new Date(),
      });

      expect(result).toBeDefined();
      expect(result.physicianId).toBe(physicianId);
      expect(result.delegateUserId).toBe(delegateUserId);
      expect(result.status).toBe('INVITED');
      expect(result.permissions).toEqual(['CLAIM_VIEW', 'CLAIM_CREATE']);
      expect(result.acceptedAt).toBeNull();
      expect(result.revokedAt).toBeNull();
      expect(result.revokedBy).toBeNull();
      expect(delegateRelStore).toHaveLength(1);
    });

    it('rejects duplicate active (physician, delegate) pair', async () => {
      const physicianId = crypto.randomUUID();
      const delegateUserId = crypto.randomUUID();

      await repo.createDelegateRelationship({
        physicianId,
        delegateUserId,
        permissions: ['CLAIM_VIEW'],
        invitedAt: new Date(),
      });

      await expect(
        repo.createDelegateRelationship({
          physicianId,
          delegateUserId,
          permissions: ['CLAIM_CREATE'],
          invitedAt: new Date(),
        }),
      ).rejects.toThrow('duplicate key value');
    });

    it('allows new relationship if previous is REVOKED', async () => {
      const physicianId = crypto.randomUUID();
      const delegateUserId = crypto.randomUUID();

      // Create and then manually revoke the first relationship
      const first = await repo.createDelegateRelationship({
        physicianId,
        delegateUserId,
        permissions: ['CLAIM_VIEW'],
        invitedAt: new Date(),
      });
      await repo.revokeRelationship(first.relationshipId, physicianId, physicianId);

      // Should succeed because old one is REVOKED
      const second = await repo.createDelegateRelationship({
        physicianId,
        delegateUserId,
        permissions: ['CLAIM_CREATE'],
        invitedAt: new Date(),
      });
      expect(second).toBeDefined();
      expect(second.status).toBe('INVITED');
      expect(delegateRelStore).toHaveLength(2);
    });
  });

  // --- Delegate Relationship: findRelationshipById ---

  describe('findRelationshipById', () => {
    it('returns relationship scoped to physician', async () => {
      const physicianId = crypto.randomUUID();
      const delegateUserId = crypto.randomUUID();
      const rel = await repo.createDelegateRelationship({
        physicianId,
        delegateUserId,
        permissions: ['CLAIM_VIEW'],
        invitedAt: new Date(),
      });

      const found = await repo.findRelationshipById(rel.relationshipId, physicianId);
      expect(found).toBeDefined();
      expect(found!.relationshipId).toBe(rel.relationshipId);
      expect(found!.physicianId).toBe(physicianId);
    });

    it('returns undefined if relationship belongs to different physician', async () => {
      const physician1 = crypto.randomUUID();
      const physician2 = crypto.randomUUID();
      const rel = await repo.createDelegateRelationship({
        physicianId: physician1,
        delegateUserId: crypto.randomUUID(),
        permissions: ['CLAIM_VIEW'],
        invitedAt: new Date(),
      });

      const found = await repo.findRelationshipById(rel.relationshipId, physician2);
      expect(found).toBeUndefined();
    });
  });

  // --- Delegate Relationship: findActiveRelationship ---

  describe('findActiveRelationship', () => {
    it('returns active relationship', async () => {
      const physicianId = crypto.randomUUID();
      const delegateUserId = crypto.randomUUID();
      const rel = await repo.createDelegateRelationship({
        physicianId,
        delegateUserId,
        permissions: ['CLAIM_VIEW'],
        invitedAt: new Date(),
      });
      // Accept to make it ACTIVE
      await repo.acceptRelationship(rel.relationshipId);

      const found = await repo.findActiveRelationship(physicianId, delegateUserId);
      expect(found).toBeDefined();
      expect(found!.status).toBe('ACTIVE');
    });

    it('returns invited relationship (non-REVOKED)', async () => {
      const physicianId = crypto.randomUUID();
      const delegateUserId = crypto.randomUUID();
      await repo.createDelegateRelationship({
        physicianId,
        delegateUserId,
        permissions: ['CLAIM_VIEW'],
        invitedAt: new Date(),
      });

      const found = await repo.findActiveRelationship(physicianId, delegateUserId);
      expect(found).toBeDefined();
      expect(found!.status).toBe('INVITED');
    });

    it('does not return revoked relationship', async () => {
      const physicianId = crypto.randomUUID();
      const delegateUserId = crypto.randomUUID();
      const rel = await repo.createDelegateRelationship({
        physicianId,
        delegateUserId,
        permissions: ['CLAIM_VIEW'],
        invitedAt: new Date(),
      });
      await repo.revokeRelationship(rel.relationshipId, physicianId, physicianId);

      const found = await repo.findActiveRelationship(physicianId, delegateUserId);
      expect(found).toBeUndefined();
    });

    it('returns undefined when no relationship exists', async () => {
      const found = await repo.findActiveRelationship(crypto.randomUUID(), crypto.randomUUID());
      expect(found).toBeUndefined();
    });
  });

  // --- Delegate Relationship: listDelegatesForPhysician ---

  describe('listDelegatesForPhysician', () => {
    it('returns only this physician\'s delegates', async () => {
      const physician1 = crypto.randomUUID();
      const physician2 = crypto.randomUUID();
      const delegate1 = crypto.randomUUID();
      const delegate2 = crypto.randomUUID();
      const delegate3 = crypto.randomUUID();

      // Add users for join
      userStore.push(
        { userId: delegate1, email: 'd1@test.com', fullName: 'Delegate One', role: 'delegate', isActive: true },
        { userId: delegate2, email: 'd2@test.com', fullName: 'Delegate Two', role: 'delegate', isActive: true },
        { userId: delegate3, email: 'd3@test.com', fullName: 'Delegate Three', role: 'delegate', isActive: true },
      );

      await repo.createDelegateRelationship({
        physicianId: physician1, delegateUserId: delegate1,
        permissions: ['CLAIM_VIEW'], invitedAt: new Date(),
      });
      await repo.createDelegateRelationship({
        physicianId: physician1, delegateUserId: delegate2,
        permissions: ['CLAIM_CREATE'], invitedAt: new Date(),
      });
      await repo.createDelegateRelationship({
        physicianId: physician2, delegateUserId: delegate3,
        permissions: ['CLAIM_VIEW'], invitedAt: new Date(),
      });

      const results = await repo.listDelegatesForPhysician(physician1);
      expect(results).toHaveLength(2);
      results.forEach((r: any) => {
        expect(r.physicianId).toBe(physician1);
      });
    });

    it('includes delegate user info from join', async () => {
      const physicianId = crypto.randomUUID();
      const delegateUserId = crypto.randomUUID();

      userStore.push({
        userId: delegateUserId,
        email: 'delegate@test.com',
        fullName: 'Test Delegate',
        role: 'delegate',
        isActive: true,
      });

      await repo.createDelegateRelationship({
        physicianId, delegateUserId,
        permissions: ['CLAIM_VIEW'], invitedAt: new Date(),
      });

      const results = await repo.listDelegatesForPhysician(physicianId);
      expect(results).toHaveLength(1);
      expect(results[0].delegateEmail).toBe('delegate@test.com');
      expect(results[0].delegateFullName).toBe('Test Delegate');
    });

    it('returns empty array when physician has no delegates', async () => {
      const results = await repo.listDelegatesForPhysician(crypto.randomUUID());
      expect(results).toHaveLength(0);
    });
  });

  // --- Delegate Relationship: listPhysiciansForDelegate ---

  describe('listPhysiciansForDelegate', () => {
    it('returns only ACTIVE relationships', async () => {
      const delegateUserId = crypto.randomUUID();
      const physician1 = crypto.randomUUID();
      const physician2 = crypto.randomUUID();
      const physician3 = crypto.randomUUID();

      // Add providers for join
      providerStore.push(
        { providerId: physician1, firstName: 'Dr', lastName: 'One', billingNumber: '111', cpsaRegistrationNumber: 'C1', specialtyCode: '01', physicianType: 'GP', status: 'ACTIVE', onboardingCompleted: true, createdAt: new Date(), updatedAt: new Date() },
        { providerId: physician2, firstName: 'Dr', lastName: 'Two', billingNumber: '222', cpsaRegistrationNumber: 'C2', specialtyCode: '01', physicianType: 'GP', status: 'ACTIVE', onboardingCompleted: true, createdAt: new Date(), updatedAt: new Date() },
        { providerId: physician3, firstName: 'Dr', lastName: 'Three', billingNumber: '333', cpsaRegistrationNumber: 'C3', specialtyCode: '01', physicianType: 'GP', status: 'ACTIVE', onboardingCompleted: true, createdAt: new Date(), updatedAt: new Date() },
      );

      // ACTIVE relationship
      const rel1 = await repo.createDelegateRelationship({
        physicianId: physician1, delegateUserId,
        permissions: ['CLAIM_VIEW'], invitedAt: new Date(),
      });
      await repo.acceptRelationship(rel1.relationshipId);

      // INVITED relationship (should NOT be returned)
      await repo.createDelegateRelationship({
        physicianId: physician2, delegateUserId,
        permissions: ['CLAIM_CREATE'], invitedAt: new Date(),
      });

      // REVOKED relationship (should NOT be returned)
      const rel3 = await repo.createDelegateRelationship({
        physicianId: physician3, delegateUserId,
        permissions: ['CLAIM_VIEW'], invitedAt: new Date(),
      });
      await repo.acceptRelationship(rel3.relationshipId);
      await repo.revokeRelationship(rel3.relationshipId, physician3, physician3);

      const results = await repo.listPhysiciansForDelegate(delegateUserId);
      expect(results).toHaveLength(1);
      expect(results[0].physicianId).toBe(physician1);
      expect(results[0].status).toBe('ACTIVE');
    });

    it('includes physician info from join', async () => {
      const delegateUserId = crypto.randomUUID();
      const physicianId = crypto.randomUUID();

      providerStore.push({
        providerId: physicianId, firstName: 'Jane', lastName: 'Smith',
        billingNumber: '444', cpsaRegistrationNumber: 'C4', specialtyCode: '01',
        physicianType: 'GP', status: 'ACTIVE', onboardingCompleted: true,
        createdAt: new Date(), updatedAt: new Date(),
      });

      const rel = await repo.createDelegateRelationship({
        physicianId, delegateUserId,
        permissions: ['CLAIM_VIEW', 'PATIENT_VIEW'], invitedAt: new Date(),
      });
      await repo.acceptRelationship(rel.relationshipId);

      const results = await repo.listPhysiciansForDelegate(delegateUserId);
      expect(results).toHaveLength(1);
      expect(results[0].physicianFirstName).toBe('Jane');
      expect(results[0].physicianLastName).toBe('Smith');
      expect(results[0].permissions).toEqual(['CLAIM_VIEW', 'PATIENT_VIEW']);
    });

    it('returns empty array when delegate has no active physicians', async () => {
      const results = await repo.listPhysiciansForDelegate(crypto.randomUUID());
      expect(results).toHaveLength(0);
    });
  });

  // --- Delegate Relationship: updateDelegatePermissions ---

  describe('updateDelegatePermissions', () => {
    it('replaces permission set', async () => {
      const physicianId = crypto.randomUUID();
      const delegateUserId = crypto.randomUUID();
      const rel = await repo.createDelegateRelationship({
        physicianId, delegateUserId,
        permissions: ['CLAIM_VIEW'], invitedAt: new Date(),
      });

      const updated = await repo.updateDelegatePermissions(
        rel.relationshipId,
        physicianId,
        ['CLAIM_VIEW', 'CLAIM_CREATE', 'PATIENT_VIEW'],
      );

      expect(updated).toBeDefined();
      expect(updated!.permissions).toEqual(['CLAIM_VIEW', 'CLAIM_CREATE', 'PATIENT_VIEW']);
    });

    it('rejects if relationship belongs to different physician', async () => {
      const physician1 = crypto.randomUUID();
      const physician2 = crypto.randomUUID();
      const rel = await repo.createDelegateRelationship({
        physicianId: physician1, delegateUserId: crypto.randomUUID(),
        permissions: ['CLAIM_VIEW'], invitedAt: new Date(),
      });

      const result = await repo.updateDelegatePermissions(
        rel.relationshipId,
        physician2,
        ['CLAIM_CREATE'],
      );
      expect(result).toBeUndefined();
    });

    it('returns undefined for non-existent relationship', async () => {
      const result = await repo.updateDelegatePermissions(
        crypto.randomUUID(),
        crypto.randomUUID(),
        ['CLAIM_VIEW'],
      );
      expect(result).toBeUndefined();
    });
  });

  // --- Delegate Relationship: acceptRelationship ---

  describe('acceptRelationship', () => {
    it('sets ACTIVE and accepted_at', async () => {
      const physicianId = crypto.randomUUID();
      const delegateUserId = crypto.randomUUID();
      const rel = await repo.createDelegateRelationship({
        physicianId, delegateUserId,
        permissions: ['CLAIM_VIEW'], invitedAt: new Date(),
      });

      expect(rel.status).toBe('INVITED');
      expect(rel.acceptedAt).toBeNull();

      const accepted = await repo.acceptRelationship(rel.relationshipId);

      expect(accepted).toBeDefined();
      expect(accepted!.status).toBe('ACTIVE');
      expect(accepted!.acceptedAt).toBeInstanceOf(Date);
    });

    it('returns undefined for non-existent relationship', async () => {
      const result = await repo.acceptRelationship(crypto.randomUUID());
      expect(result).toBeUndefined();
    });
  });

  // --- Delegate Relationship: revokeRelationship ---

  describe('revokeRelationship', () => {
    it('sets REVOKED with revoked_at and revoked_by', async () => {
      const physicianId = crypto.randomUUID();
      const delegateUserId = crypto.randomUUID();
      const revokerUserId = physicianId; // physician revokes

      const rel = await repo.createDelegateRelationship({
        physicianId, delegateUserId,
        permissions: ['CLAIM_VIEW'], invitedAt: new Date(),
      });
      await repo.acceptRelationship(rel.relationshipId);

      const revoked = await repo.revokeRelationship(rel.relationshipId, physicianId, revokerUserId);

      expect(revoked).toBeDefined();
      expect(revoked!.status).toBe('REVOKED');
      expect(revoked!.revokedAt).toBeInstanceOf(Date);
      expect(revoked!.revokedBy).toBe(revokerUserId);
    });

    it('returns undefined if relationship belongs to different physician', async () => {
      const physician1 = crypto.randomUUID();
      const physician2 = crypto.randomUUID();
      const rel = await repo.createDelegateRelationship({
        physicianId: physician1, delegateUserId: crypto.randomUUID(),
        permissions: ['CLAIM_VIEW'], invitedAt: new Date(),
      });

      const result = await repo.revokeRelationship(rel.relationshipId, physician2, physician2);
      expect(result).toBeUndefined();
    });

    it('returns undefined for non-existent relationship', async () => {
      const result = await repo.revokeRelationship(
        crypto.randomUUID(),
        crypto.randomUUID(),
        crypto.randomUUID(),
      );
      expect(result).toBeUndefined();
    });
  });

  // =====================================================================
  // Submission Preferences
  // =====================================================================

  describe('createSubmissionPreferences', () => {
    it('inserts with defaults (AUTO_CLEAN for AHCIP, REQUIRE_APPROVAL for WCB)', async () => {
      const providerId = crypto.randomUUID();
      const updatedBy = crypto.randomUUID();

      const prefs = await repo.createSubmissionPreferences({
        providerId,
        updatedBy,
      });

      expect(prefs).toBeDefined();
      expect(prefs.providerId).toBe(providerId);
      expect(prefs.ahcipSubmissionMode).toBe('AUTO_CLEAN');
      expect(prefs.wcbSubmissionMode).toBe('REQUIRE_APPROVAL');
      expect(prefs.batchReviewReminder).toBe(true);
      expect(prefs.deadlineReminderDays).toBe(7);
      expect(prefs.updatedBy).toBe(updatedBy);
      expect(prefs.preferenceId).toBeDefined();
    });

    it('inserts with explicit values overriding defaults', async () => {
      const providerId = crypto.randomUUID();
      const updatedBy = crypto.randomUUID();

      const prefs = await repo.createSubmissionPreferences({
        providerId,
        updatedBy,
        ahcipSubmissionMode: 'MANUAL',
        wcbSubmissionMode: 'AUTO_CLEAN',
        batchReviewReminder: false,
        deadlineReminderDays: 14,
      });

      expect(prefs.ahcipSubmissionMode).toBe('MANUAL');
      expect(prefs.wcbSubmissionMode).toBe('AUTO_CLEAN');
      expect(prefs.batchReviewReminder).toBe(false);
      expect(prefs.deadlineReminderDays).toBe(14);
    });

    it('rejects duplicate provider_id', async () => {
      const providerId = crypto.randomUUID();
      const updatedBy = crypto.randomUUID();

      await repo.createSubmissionPreferences({ providerId, updatedBy });
      await expect(
        repo.createSubmissionPreferences({ providerId, updatedBy }),
      ).rejects.toThrow(/duplicate key/);
    });
  });

  describe('findSubmissionPreferences', () => {
    it('returns correct preferences for provider', async () => {
      const providerId = crypto.randomUUID();
      const updatedBy = crypto.randomUUID();

      await repo.createSubmissionPreferences({
        providerId,
        updatedBy,
        ahcipSubmissionMode: 'MANUAL',
      });

      const found = await repo.findSubmissionPreferences(providerId);

      expect(found).toBeDefined();
      expect(found!.providerId).toBe(providerId);
      expect(found!.ahcipSubmissionMode).toBe('MANUAL');
    });

    it('returns undefined for non-existent provider', async () => {
      const found = await repo.findSubmissionPreferences(crypto.randomUUID());
      expect(found).toBeUndefined();
    });

    it('does not return another provider\'s preferences', async () => {
      const provider1 = crypto.randomUUID();
      const provider2 = crypto.randomUUID();
      const updatedBy = crypto.randomUUID();

      await repo.createSubmissionPreferences({
        providerId: provider1,
        updatedBy,
        ahcipSubmissionMode: 'MANUAL',
      });
      await repo.createSubmissionPreferences({
        providerId: provider2,
        updatedBy,
        ahcipSubmissionMode: 'AUTO_CLEAN',
      });

      const found = await repo.findSubmissionPreferences(provider1);
      expect(found!.providerId).toBe(provider1);
      expect(found!.ahcipSubmissionMode).toBe('MANUAL');
    });
  });

  describe('updateSubmissionPreferences', () => {
    it('updates modes and sets updated_by', async () => {
      const providerId = crypto.randomUUID();
      const originalUser = crypto.randomUUID();
      const updatingUser = crypto.randomUUID();

      await repo.createSubmissionPreferences({
        providerId,
        updatedBy: originalUser,
      });

      const updated = await repo.updateSubmissionPreferences(
        providerId,
        { ahcipSubmissionMode: 'REQUIRE_APPROVAL', wcbSubmissionMode: 'AUTO_CLEAN' },
        updatingUser,
      );

      expect(updated).toBeDefined();
      expect(updated!.ahcipSubmissionMode).toBe('REQUIRE_APPROVAL');
      expect(updated!.wcbSubmissionMode).toBe('AUTO_CLEAN');
      expect(updated!.updatedBy).toBe(updatingUser);
      expect(updated!.updatedAt).toBeInstanceOf(Date);
    });

    it('updates only specified fields', async () => {
      const providerId = crypto.randomUUID();
      const updatedBy = crypto.randomUUID();

      await repo.createSubmissionPreferences({
        providerId,
        updatedBy,
        deadlineReminderDays: 7,
      });

      const updated = await repo.updateSubmissionPreferences(
        providerId,
        { deadlineReminderDays: 14 },
        updatedBy,
      );

      expect(updated!.deadlineReminderDays).toBe(14);
      expect(updated!.ahcipSubmissionMode).toBe('AUTO_CLEAN'); // unchanged default
    });

    it('returns undefined for non-existent provider', async () => {
      const result = await repo.updateSubmissionPreferences(
        crypto.randomUUID(),
        { ahcipSubmissionMode: 'MANUAL' },
        crypto.randomUUID(),
      );
      expect(result).toBeUndefined();
    });
  });

  // =====================================================================
  // H-Link Configuration
  // =====================================================================

  describe('createHlinkConfig', () => {
    it('inserts H-Link config with required fields', async () => {
      const providerId = crypto.randomUUID();

      const config = await repo.createHlinkConfig({
        providerId,
        submitterPrefix: 'MRT',
        credentialSecretRef: 'vault://hlink/provider-123',
      });

      expect(config).toBeDefined();
      expect(config.providerId).toBe(providerId);
      expect(config.submitterPrefix).toBe('MRT');
      expect(config.credentialSecretRef).toBe('vault://hlink/provider-123');
      expect(config.accreditationStatus).toBe('PENDING');
      expect(config.accreditationDate).toBeNull();
      expect(config.lastSuccessfulTransmission).toBeNull();
      expect(config.hlinkConfigId).toBeDefined();
    });

    it('inserts with explicit accreditation status', async () => {
      const providerId = crypto.randomUUID();

      const config = await repo.createHlinkConfig({
        providerId,
        submitterPrefix: 'MRT',
        credentialSecretRef: 'vault://hlink/provider-456',
        accreditationStatus: 'ACCREDITED',
        accreditationDate: '2026-01-15',
      });

      expect(config.accreditationStatus).toBe('ACCREDITED');
      expect(config.accreditationDate).toBe('2026-01-15');
    });

    it('rejects duplicate provider_id', async () => {
      const providerId = crypto.randomUUID();

      await repo.createHlinkConfig({
        providerId,
        submitterPrefix: 'MRT',
        credentialSecretRef: 'vault://hlink/1',
      });
      await expect(
        repo.createHlinkConfig({
          providerId,
          submitterPrefix: 'MRT',
          credentialSecretRef: 'vault://hlink/2',
        }),
      ).rejects.toThrow(/duplicate key/);
    });
  });

  describe('findHlinkConfig', () => {
    it('returns config without actual credentials', async () => {
      const providerId = crypto.randomUUID();

      await repo.createHlinkConfig({
        providerId,
        submitterPrefix: 'MRT',
        credentialSecretRef: 'vault://hlink/provider-789',
      });

      const found = await repo.findHlinkConfig(providerId);

      expect(found).toBeDefined();
      expect(found!.providerId).toBe(providerId);
      expect(found!.submitterPrefix).toBe('MRT');
      // credentialSecretRef is a reference, not actual credentials
      expect(found!.credentialSecretRef).toBe('vault://hlink/provider-789');
      // Verify no plain-text credential fields exist
      expect((found as any).password).toBeUndefined();
      expect((found as any).secret).toBeUndefined();
      expect((found as any).apiKey).toBeUndefined();
    });

    it('returns undefined for non-existent provider', async () => {
      const found = await repo.findHlinkConfig(crypto.randomUUID());
      expect(found).toBeUndefined();
    });

    it('does not return another provider\'s config', async () => {
      const provider1 = crypto.randomUUID();
      const provider2 = crypto.randomUUID();

      await repo.createHlinkConfig({
        providerId: provider1,
        submitterPrefix: 'AAA',
        credentialSecretRef: 'vault://hlink/1',
      });
      await repo.createHlinkConfig({
        providerId: provider2,
        submitterPrefix: 'BBB',
        credentialSecretRef: 'vault://hlink/2',
      });

      const found = await repo.findHlinkConfig(provider1);
      expect(found!.providerId).toBe(provider1);
      expect(found!.submitterPrefix).toBe('AAA');
    });
  });

  describe('updateHlinkConfig', () => {
    it('updates submitter_prefix and accreditation_status', async () => {
      const providerId = crypto.randomUUID();

      await repo.createHlinkConfig({
        providerId,
        submitterPrefix: 'MRT',
        credentialSecretRef: 'vault://hlink/provider-update',
      });

      const updated = await repo.updateHlinkConfig(providerId, {
        submitterPrefix: 'NEW',
        accreditationStatus: 'ACCREDITED',
        accreditationDate: '2026-02-01',
      });

      expect(updated).toBeDefined();
      expect(updated!.submitterPrefix).toBe('NEW');
      expect(updated!.accreditationStatus).toBe('ACCREDITED');
      expect(updated!.accreditationDate).toBe('2026-02-01');
      expect(updated!.updatedAt).toBeInstanceOf(Date);
    });

    it('returns undefined for non-existent provider', async () => {
      const result = await repo.updateHlinkConfig(crypto.randomUUID(), {
        submitterPrefix: 'XYZ',
      });
      expect(result).toBeUndefined();
    });
  });

  describe('updateLastTransmission', () => {
    it('updates timestamp', async () => {
      const providerId = crypto.randomUUID();
      const transmissionTime = new Date('2026-02-17T10:30:00Z');

      await repo.createHlinkConfig({
        providerId,
        submitterPrefix: 'MRT',
        credentialSecretRef: 'vault://hlink/provider-tx',
      });

      const updated = await repo.updateLastTransmission(providerId, transmissionTime);

      expect(updated).toBeDefined();
      expect(updated!.lastSuccessfulTransmission).toEqual(transmissionTime);
      expect(updated!.updatedAt).toBeInstanceOf(Date);
    });

    it('returns undefined for non-existent provider', async () => {
      const result = await repo.updateLastTransmission(
        crypto.randomUUID(),
        new Date(),
      );
      expect(result).toBeUndefined();
    });
  });

  // ==========================================================================
  // Provider Context Queries (Internal API for Domain 4)
  // ==========================================================================

  describe('getFullProviderContext', () => {
    it('returns complete context for active provider', async () => {
      const providerId = crypto.randomUUID();

      // Create provider
      await repo.createProvider(
        validProviderData({ providerId, billingNumber: 'BN100', cpsaRegistrationNumber: 'CPSA100' }),
      );

      // Create FFS and PCPCM BAs
      const ffsBa = await repo.createBa(
        validBaData({
          providerId,
          baNumber: 'FFS100',
          baType: 'FFS',
          isPrimary: true,
          status: 'ACTIVE',
        }),
      );
      const pcpcmBa = await repo.createBa(
        validBaData({
          providerId,
          baNumber: 'PCPCM100',
          baType: 'PCPCM',
          isPrimary: false,
          status: 'ACTIVE',
        }),
      );

      // Create default location
      await repo.createLocation(
        validLocationData({
          providerId,
          name: 'Main Office',
          functionalCentre: 'FC100',
          facilityNumber: 'FAC100',
          isDefault: true,
          isActive: true,
        }),
      );
      // Create another active location
      await repo.createLocation(
        validLocationData({
          providerId,
          name: 'Satellite',
          functionalCentre: 'FC200',
          isDefault: false,
          isActive: true,
        }),
      );

      // Create PCPCM enrolment
      await repo.createPcpcmEnrolment(
        validPcpcmEnrolmentData({
          providerId,
          pcpcmBaId: pcpcmBa.baId,
          ffsBaId: ffsBa.baId,
          status: 'ACTIVE',
        }),
      );

      // Create WCB config (default)
      await repo.createWcbConfig(
        validWcbConfigData({
          providerId,
          contractId: 'WCB-C1',
          roleCode: 'PHYSICIAN',
          permittedFormTypes: ['PHYSICIAN_FIRST_REPORT'],
          isDefault: true,
        }),
      );

      // Create submission preferences
      await repo.createSubmissionPreferences({
        providerId,
        ahcipSubmissionMode: 'AUTO_CLEAN',
        wcbSubmissionMode: 'REQUIRE_APPROVAL',
        batchReviewReminder: true,
        deadlineReminderDays: 7,
        updatedBy: providerId,
      });

      // Create H-Link config
      await repo.createHlinkConfig({
        providerId,
        submitterPrefix: 'MRT',
        credentialSecretRef: 'vault://hlink/100',
        accreditationStatus: 'ACTIVE',
      });

      const ctx = await repo.getFullProviderContext(providerId);

      expect(ctx).not.toBeNull();
      expect(ctx!.provider_id).toBe(providerId);
      expect(ctx!.billing_number).toBe('BN100');
      expect(ctx!.specialty_code).toBe('01');
      expect(ctx!.physician_type).toBe('GP');
      expect(ctx!.status).toBe('ACTIVE');
      expect(ctx!.onboarding_completed).toBe(false);

      // BAs
      expect(ctx!.bas).toHaveLength(2);
      expect(ctx!.bas.map((b) => b.ba_number).sort()).toEqual(['FFS100', 'PCPCM100']);

      // Locations
      expect(ctx!.all_locations).toHaveLength(2);
      expect(ctx!.default_location).not.toBeNull();
      expect(ctx!.default_location!.name).toBe('Main Office');
      expect(ctx!.default_location!.functional_centre).toBe('FC100');
      expect(ctx!.default_location!.facility_number).toBe('FAC100');

      // PCPCM
      expect(ctx!.pcpcm_enrolled).toBe(true);
      expect(ctx!.pcpcm_ba_number).toBe('PCPCM100');
      expect(ctx!.ffs_ba_number).toBe('FFS100');

      // WCB configs
      expect(ctx!.wcb_configs).toHaveLength(1);
      expect(ctx!.wcb_configs[0].contract_id).toBe('WCB-C1');
      expect(ctx!.wcb_configs[0].permitted_form_types).toEqual(['PHYSICIAN_FIRST_REPORT']);
      expect(ctx!.default_wcb_config).not.toBeNull();
      expect(ctx!.default_wcb_config!.contract_id).toBe('WCB-C1');

      // Submission preferences
      expect(ctx!.submission_preferences).not.toBeNull();
      expect(ctx!.submission_preferences!.ahcip_submission_mode).toBe('AUTO_CLEAN');
      expect(ctx!.submission_preferences!.deadline_reminder_days).toBe(7);

      // H-Link
      expect(ctx!.hlink_accreditation_status).toBe('ACTIVE');
      expect(ctx!.hlink_submitter_prefix).toBe('MRT');
    });

    it('returns null for unknown provider', async () => {
      const ctx = await repo.getFullProviderContext(crypto.randomUUID());
      expect(ctx).toBeNull();
    });
  });

  describe('getBaForClaim', () => {
    it('returns FFS BA for non-PCPCM physician (AHCIP)', async () => {
      const providerId = crypto.randomUUID();

      await repo.createProvider(
        validProviderData({
          providerId,
          billingNumber: 'BN200',
          cpsaRegistrationNumber: 'CPSA200',
        }),
      );

      await repo.createBa(
        validBaData({
          providerId,
          baNumber: 'FFS200',
          baType: 'FFS',
          isPrimary: true,
          status: 'ACTIVE',
        }),
      );

      const result = await repo.getBaForClaim(providerId, 'AHCIP', '03.04A');

      expect(result).not.toBeNull();
      expect(result!.baNumber).toBe('FFS200');
      expect(result!.routing).toBe('PRIMARY');
    });

    it('returns PCPCM BA for in-basket HSC code', async () => {
      const providerId = crypto.randomUUID();

      await repo.createProvider(
        validProviderData({
          providerId,
          billingNumber: 'BN300',
          cpsaRegistrationNumber: 'CPSA300',
        }),
      );

      const ffsBa = await repo.createBa(
        validBaData({
          providerId,
          baNumber: 'FFS300',
          baType: 'FFS',
          isPrimary: true,
          status: 'ACTIVE',
        }),
      );
      const pcpcmBa = await repo.createBa(
        validBaData({
          providerId,
          baNumber: 'PCPCM300',
          baType: 'PCPCM',
          isPrimary: false,
          status: 'ACTIVE',
        }),
      );

      // Create active PCPCM enrolment
      await repo.createPcpcmEnrolment(
        validPcpcmEnrolmentData({
          providerId,
          pcpcmBaId: pcpcmBa.baId,
          ffsBaId: ffsBa.baId,
          status: 'ACTIVE',
        }),
      );

      // Seed reference data: SOMB version + HSC code with in-basket classification
      const versionId = crypto.randomUUID();
      referenceVersionStore.push({
        versionId,
        dataSet: 'somb',
        versionLabel: 'SOMB 2026-Q1',
        effectiveFrom: '2026-01-01',
        effectiveTo: null,
        isActive: true,
      });
      hscCodeStore.push({
        id: crypto.randomUUID(),
        hscCode: '03.04A',
        description: 'Office Visit - GP',
        baseFee: '40.00',
        feeType: 'FFS',
        pcpcmBasket: 'chronic_disease_management',
        versionId,
        effectiveFrom: '2026-01-01',
        effectiveTo: null,
      });

      const result = await repo.getBaForClaim(providerId, 'AHCIP', '03.04A');

      expect(result).not.toBeNull();
      expect(result!.baNumber).toBe('PCPCM300');
      expect(result!.baType).toBe('PCPCM');
      expect(result!.routing).toBe('PCPCM');
    });

    it('returns FFS BA for out-of-basket HSC code', async () => {
      const providerId = crypto.randomUUID();

      await repo.createProvider(
        validProviderData({
          providerId,
          billingNumber: 'BN400',
          cpsaRegistrationNumber: 'CPSA400',
        }),
      );

      const ffsBa = await repo.createBa(
        validBaData({
          providerId,
          baNumber: 'FFS400',
          baType: 'FFS',
          isPrimary: true,
          status: 'ACTIVE',
        }),
      );
      const pcpcmBa = await repo.createBa(
        validBaData({
          providerId,
          baNumber: 'PCPCM400',
          baType: 'PCPCM',
          isPrimary: false,
          status: 'ACTIVE',
        }),
      );

      await repo.createPcpcmEnrolment(
        validPcpcmEnrolmentData({
          providerId,
          pcpcmBaId: pcpcmBa.baId,
          ffsBaId: ffsBa.baId,
          status: 'ACTIVE',
        }),
      );

      // HSC code is out-of-basket (pcpcmBasket = 'not_applicable')
      const versionId = crypto.randomUUID();
      referenceVersionStore.push({
        versionId,
        dataSet: 'somb',
        versionLabel: 'SOMB 2026-Q1',
        effectiveFrom: '2026-01-01',
        effectiveTo: null,
        isActive: true,
      });
      hscCodeStore.push({
        id: crypto.randomUUID(),
        hscCode: '99.99Z',
        description: 'Out of basket service',
        baseFee: '100.00',
        feeType: 'FFS',
        pcpcmBasket: 'not_applicable',
        versionId,
        effectiveFrom: '2026-01-01',
        effectiveTo: null,
      });

      const result = await repo.getBaForClaim(providerId, 'AHCIP', '99.99Z');

      expect(result).not.toBeNull();
      expect(result!.baNumber).toBe('FFS400');
      expect(result!.baType).toBe('FFS');
      expect(result!.routing).toBe('FFS');
    });

    it('returns FFS BA when HSC code has no basket classification', async () => {
      const providerId = crypto.randomUUID();

      await repo.createProvider(
        validProviderData({
          providerId,
          billingNumber: 'BN500',
          cpsaRegistrationNumber: 'CPSA500',
        }),
      );

      const ffsBa = await repo.createBa(
        validBaData({
          providerId,
          baNumber: 'FFS500',
          baType: 'FFS',
          isPrimary: true,
          status: 'ACTIVE',
        }),
      );
      const pcpcmBa = await repo.createBa(
        validBaData({
          providerId,
          baNumber: 'PCPCM500',
          baType: 'PCPCM',
          isPrimary: false,
          status: 'ACTIVE',
        }),
      );

      await repo.createPcpcmEnrolment(
        validPcpcmEnrolmentData({
          providerId,
          pcpcmBaId: pcpcmBa.baId,
          ffsBaId: ffsBa.baId,
          status: 'ACTIVE',
        }),
      );

      // SOMB version exists but HSC code not found in reference data
      const versionId = crypto.randomUUID();
      referenceVersionStore.push({
        versionId,
        dataSet: 'somb',
        versionLabel: 'SOMB 2026-Q1',
        effectiveFrom: '2026-01-01',
        effectiveTo: null,
        isActive: true,
      });
      // No hscCodeStore entry for 'UNKNOWN_CODE'

      const result = await repo.getBaForClaim(providerId, 'AHCIP', 'UNKNOWN_CODE');

      expect(result).not.toBeNull();
      expect(result!.baNumber).toBe('FFS500');
      expect(result!.routing).toBe('FFS');
    });

    it('returns primary BA for WCB claim', async () => {
      const providerId = crypto.randomUUID();

      await repo.createProvider(
        validProviderData({
          providerId,
          billingNumber: 'BN600',
          cpsaRegistrationNumber: 'CPSA600',
        }),
      );

      await repo.createBa(
        validBaData({
          providerId,
          baNumber: 'BA600',
          baType: 'FFS',
          isPrimary: true,
          status: 'ACTIVE',
        }),
      );

      const result = await repo.getBaForClaim(providerId, 'WCB');

      expect(result).not.toBeNull();
      expect(result!.baNumber).toBe('BA600');
      expect(result!.routing).toBe('PRIMARY');
    });

    it('returns null when provider has no active BAs', async () => {
      const providerId = crypto.randomUUID();

      await repo.createProvider(
        validProviderData({
          providerId,
          billingNumber: 'BN700',
          cpsaRegistrationNumber: 'CPSA700',
        }),
      );

      const result = await repo.getBaForClaim(providerId, 'AHCIP');
      expect(result).toBeNull();
    });
  });

  describe('getWcbConfigForForm', () => {
    it('returns matching config for permitted form', async () => {
      const providerId = crypto.randomUUID();

      await repo.createWcbConfig(
        validWcbConfigData({
          providerId,
          contractId: 'WCB-C10',
          roleCode: 'PHYSICIAN',
          permittedFormTypes: ['PHYSICIAN_FIRST_REPORT', 'PROGRESS_REPORT'],
        }),
      );
      await repo.createWcbConfig(
        validWcbConfigData({
          providerId,
          contractId: 'WCB-C20',
          roleCode: 'SPECIALIST',
          permittedFormTypes: ['SPECIALIST_CONSULT'],
        }),
      );

      const result = await repo.getWcbConfigForForm(providerId, 'PROGRESS_REPORT');

      expect(result).not.toBeNull();
      expect(result!.contractId).toBe('WCB-C10');
      expect(result!.roleCode).toBe('PHYSICIAN');
    });

    it('returns null for non-permitted form', async () => {
      const providerId = crypto.randomUUID();

      await repo.createWcbConfig(
        validWcbConfigData({
          providerId,
          contractId: 'WCB-C30',
          roleCode: 'PHYSICIAN',
          permittedFormTypes: ['PHYSICIAN_FIRST_REPORT'],
        }),
      );

      const result = await repo.getWcbConfigForForm(providerId, 'SPECIALIST_CONSULT');

      expect(result).toBeNull();
    });

    it('returns null when provider has no WCB configs', async () => {
      const result = await repo.getWcbConfigForForm(crypto.randomUUID(), 'PHYSICIAN_FIRST_REPORT');
      expect(result).toBeNull();
    });
  });
});

// ===========================================================================
// Provider Service Tests
// ===========================================================================

describe('Provider Service', () => {
  let repo: ReturnType<typeof createProviderRepository>;
  let auditLogs: Record<string, unknown>[];
  let emittedEvents: { event: string; payload: Record<string, unknown> }[];
  let deps: ProviderServiceDeps;

  beforeEach(() => {
    providerStore = [];
    baStore = [];
    locationStore = [];
    pcpcmEnrolmentStore = [];
    wcbConfigStore = [];
    delegateRelStore = [];
    userStore = [];
    submissionPrefStore = [];
    hlinkConfigStore = [];
    hscCodeStore = [];
    referenceVersionStore = [];

    const db = makeMockDb();
    repo = createProviderRepository(db);
    auditLogs = [];
    emittedEvents = [];

    deps = {
      repo,
      auditRepo: {
        async appendAuditLog(entry) {
          auditLogs.push(entry);
        },
      },
      events: {
        emit(event, payload) {
          emittedEvents.push({ event, payload });
        },
      },
    };
  });

  // -----------------------------------------------------------------------
  // getProviderProfile
  // -----------------------------------------------------------------------

  describe('getProviderProfile', () => {
    it('returns complete profile for active provider', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId }));

      // Add a BA
      await repo.createBa(validBaData({ providerId, baNumber: 'BA100' }));

      // Add a location
      await repo.createLocation(
        validLocationData({ providerId, isDefault: true }),
      );

      const profile = await getProviderProfile(deps, providerId);

      expect(profile).toBeDefined();
      expect(profile.provider_id).toBe(providerId);
      expect(profile.billing_number).toBe('123456');
      expect(profile.bas).toHaveLength(1);
      expect(profile.bas[0].ba_number).toBe('BA100');
      expect(profile.all_locations).toHaveLength(1);
      expect(profile.default_location).toBeDefined();
      expect(profile.onboarding_completed).toBe(false);
      expect(profile.status).toBe('ACTIVE');
    });

    it('throws NotFoundError for non-existent provider', async () => {
      await expect(
        getProviderProfile(deps, crypto.randomUUID()),
      ).rejects.toThrow('not found');
    });
  });

  // -----------------------------------------------------------------------
  // updateProviderProfile
  // -----------------------------------------------------------------------

  describe('updateProviderProfile', () => {
    it('updates fields and emits audit event', async () => {
      const providerId = crypto.randomUUID();
      const actorId = providerId;
      await repo.createProvider(validProviderData({ providerId }));

      const result = await updateProviderProfile(deps, providerId, {
        firstName: 'Updated',
        lastName: 'Doctor',
      }, actorId);

      expect(result.firstName).toBe('Updated');
      expect(result.lastName).toBe('Doctor');
      expect(auditLogs).toHaveLength(1);
      expect(auditLogs[0].action).toBe('provider.profile_updated');
      expect(auditLogs[0].resourceId).toBe(providerId);
    });

    it('captures field-level diff in audit detail', async () => {
      const providerId = crypto.randomUUID();
      const actorId = providerId;
      await repo.createProvider(
        validProviderData({ providerId, firstName: 'Jane', specialtyCode: '01' }),
      );

      await updateProviderProfile(deps, providerId, {
        firstName: 'Janet',
        specialtyCode: '03',
      }, actorId);

      expect(auditLogs).toHaveLength(1);
      const detail = auditLogs[0].detail as Record<string, unknown>;
      const changes = detail.changes as Record<string, { old: unknown; new: unknown }>;

      expect(changes.firstName).toEqual({ old: 'Jane', new: 'Janet' });
      expect(changes.specialtyCode).toEqual({ old: '01', new: '03' });
      expect(detail.specialtyChanged).toBe(true);
    });

    it('does not emit audit when no fields actually changed', async () => {
      const providerId = crypto.randomUUID();
      const actorId = providerId;
      await repo.createProvider(
        validProviderData({ providerId, firstName: 'Jane' }),
      );

      const result = await updateProviderProfile(deps, providerId, {
        firstName: 'Jane', // same value
      }, actorId);

      expect(result.firstName).toBe('Jane');
      expect(auditLogs).toHaveLength(0);
    });

    it('throws NotFoundError for non-existent provider', async () => {
      await expect(
        updateProviderProfile(deps, crypto.randomUUID(), { firstName: 'X' }, crypto.randomUUID()),
      ).rejects.toThrow('not found');
    });

    it('emits PROVIDER_PROFILE_UPDATED event', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId }));

      await updateProviderProfile(deps, providerId, {
        lastName: 'NewName',
      }, providerId);

      expect(emittedEvents).toHaveLength(1);
      expect(emittedEvents[0].event).toBe('PROVIDER_PROFILE_UPDATED');
      expect(emittedEvents[0].payload.providerId).toBe(providerId);
    });
  });

  // -----------------------------------------------------------------------
  // getOnboardingStatus
  // -----------------------------------------------------------------------

  describe('getOnboardingStatus', () => {
    it('reports missing fields accurately', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId }));
      // No BA and no location added

      const status = await getOnboardingStatus(deps, providerId);

      expect(status).toBeDefined();
      expect(status.onboardingCompleted).toBe(false);

      // Provider fields should be complete
      const billingStep = status.steps.find((s) => s.field === 'billing_number');
      expect(billingStep?.complete).toBe(true);

      const cpsaStep = status.steps.find((s) => s.field === 'cpsa_registration');
      expect(cpsaStep?.complete).toBe(true);

      const specialtyStep = status.steps.find((s) => s.field === 'specialty');
      expect(specialtyStep?.complete).toBe(true);

      // BA and location should be missing
      const baStep = status.steps.find((s) => s.field === 'business_arrangement');
      expect(baStep?.complete).toBe(false);

      const locationStep = status.steps.find((s) => s.field === 'location');
      expect(locationStep?.complete).toBe(false);

      // All required are NOT complete
      expect(status.allRequiredComplete).toBe(false);
    });

    it('reports all complete when BA and location exist', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(
        validProviderData({ providerId, onboardingCompleted: true }),
      );
      await repo.createBa(validBaData({ providerId, baNumber: 'BA200' }));
      await repo.createLocation(validLocationData({ providerId }));

      const status = await getOnboardingStatus(deps, providerId);

      expect(status.onboardingCompleted).toBe(true);
      expect(status.allRequiredComplete).toBe(true);
      expect(status.steps.every((s) => s.complete)).toBe(true);
    });

    it('throws NotFoundError for non-existent provider', async () => {
      await expect(
        getOnboardingStatus(deps, crypto.randomUUID()),
      ).rejects.toThrow('not found');
    });
  });

  // -----------------------------------------------------------------------
  // completeOnboarding
  // -----------------------------------------------------------------------

  describe('completeOnboarding', () => {
    it('succeeds when all required fields populated', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId }));
      await repo.createBa(validBaData({ providerId, baNumber: 'BA300' }));
      await repo.createLocation(validLocationData({ providerId }));

      const result = await completeOnboarding(deps, providerId);

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.provider.onboardingCompleted).toBe(true);
      }

      // Verify audit event emitted
      expect(auditLogs).toHaveLength(1);
      expect(auditLogs[0].action).toBe('provider.onboarding_completed');
      expect(auditLogs[0].resourceId).toBe(providerId);

      // Verify event emitted
      expect(emittedEvents).toHaveLength(1);
      expect(emittedEvents[0].event).toBe('PROVIDER_ONBOARDING_COMPLETED');
    });

    it('fails listing missing fields when BA missing', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId }));
      // No BA added
      await repo.createLocation(validLocationData({ providerId }));

      const result = await completeOnboarding(deps, providerId);

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.missingFields).toContain('business_arrangement');
      }

      // No audit event should be emitted
      expect(auditLogs).toHaveLength(0);
    });

    it('fails listing missing fields when location missing', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId }));
      await repo.createBa(validBaData({ providerId, baNumber: 'BA301' }));
      // No location added

      const result = await completeOnboarding(deps, providerId);

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.missingFields).toContain('location');
      }
    });

    it('fails listing missing fields when provider fields missing', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(
        validProviderData({ providerId, specialtyCode: '', physicianType: '' }),
      );
      await repo.createBa(validBaData({ providerId, baNumber: 'BA302' }));
      await repo.createLocation(validLocationData({ providerId }));

      const result = await completeOnboarding(deps, providerId);

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.missingFields).toContain('specialty_code');
        expect(result.missingFields).toContain('physician_type');
      }
    });

    it('throws NotFoundError for non-existent provider', async () => {
      await expect(
        completeOnboarding(deps, crypto.randomUUID()),
      ).rejects.toThrow('not found');
    });
  });

  // -----------------------------------------------------------------------
  // createProviderFromOnboarding
  // -----------------------------------------------------------------------

  describe('createProviderFromOnboarding', () => {
    it('creates provider with provider_id = userId', async () => {
      const userId = crypto.randomUUID();

      const result = await createProviderFromOnboarding(deps, userId, {
        billingNumber: '654321',
        cpsaRegistrationNumber: 'CPSA999',
        firstName: 'John',
        lastName: 'Doe',
        specialtyCode: '02',
        physicianType: 'SPECIALIST',
      });

      expect(result).toBeDefined();
      expect(result.providerId).toBe(userId);
      expect(result.billingNumber).toBe('654321');
      expect(result.cpsaRegistrationNumber).toBe('CPSA999');
      expect(result.firstName).toBe('John');
      expect(result.lastName).toBe('Doe');
      expect(result.specialtyCode).toBe('02');
      expect(result.physicianType).toBe('SPECIALIST');
      expect(result.onboardingCompleted).toBe(false);
      expect(result.status).toBe('ACTIVE');

      // Verify audit event
      expect(auditLogs).toHaveLength(1);
      expect(auditLogs[0].userId).toBe(userId);
      expect(auditLogs[0].resourceId).toBe(userId);

      // Verify event emitted
      expect(emittedEvents).toHaveLength(1);
      expect(emittedEvents[0].event).toBe('PROVIDER_CREATED');
      expect(emittedEvents[0].payload.providerId).toBe(userId);
    });

    it('throws BusinessRuleError if provider already exists', async () => {
      const userId = crypto.randomUUID();

      // Create provider first
      await repo.createProvider(validProviderData({ providerId: userId }));

      await expect(
        createProviderFromOnboarding(deps, userId, {
          billingNumber: '777777',
          cpsaRegistrationNumber: 'CPSA777',
          firstName: 'Dup',
          lastName: 'Doctor',
          specialtyCode: '01',
          physicianType: 'GP',
        }),
      ).rejects.toThrow('already exists');
    });
  });

  // -----------------------------------------------------------------------
  // addBa
  // -----------------------------------------------------------------------

  describe('addBa', () => {
    it('creates BA with valid data', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_AB1', cpsaRegistrationNumber: 'CPSA_AB1' }));

      const result = await addBa(deps, providerId, {
        baNumber: '11111',
        baType: 'FFS',
      }, providerId);

      expect(result).toBeDefined();
      expect(result.baNumber).toBe('11111');
      expect(result.baType).toBe('FFS');
      expect(result.status).toBe('PENDING');
      expect(result.providerId).toBe(providerId);
      expect(result.isPrimary).toBe(true); // first BA is always primary

      // Verify audit event
      expect(auditLogs).toHaveLength(1);
      expect(auditLogs[0].action).toBe('ba.added');
      expect(auditLogs[0].resourceId).toBe(result.baId);

      // Verify event emitted
      expect(emittedEvents).toHaveLength(1);
      expect(emittedEvents[0].event).toBe('BA_ADDED');
    });

    it('rejects third active BA', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_AB2', cpsaRegistrationNumber: 'CPSA_AB2' }));

      // Create 2 active BAs directly via repo
      await repo.createBa(validBaData({ providerId, baNumber: '22221', baType: 'FFS', status: 'ACTIVE' }));
      await repo.createBa(validBaData({ providerId, baNumber: '22222', baType: 'PCPCM', status: 'ACTIVE' }));

      await expect(
        addBa(deps, providerId, { baNumber: '22223', baType: 'ARP' }, providerId),
      ).rejects.toThrow('Maximum of 2 active business arrangements allowed');
    });

    it('rejects PCPCM without existing FFS BA', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_AB3', cpsaRegistrationNumber: 'CPSA_AB3' }));

      await expect(
        addBa(deps, providerId, { baNumber: '33331', baType: 'PCPCM' }, providerId),
      ).rejects.toThrow('requires an existing FFS business arrangement');
    });

    it('creates PCPCM enrolment when adding PCPCM BA', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_AB4', cpsaRegistrationNumber: 'CPSA_AB4' }));

      // Add FFS BA first (through service to get proper primary)
      const ffsBa = await addBa(deps, providerId, {
        baNumber: '44441',
        baType: 'FFS',
      }, providerId);
      // Activate it so PCPCM can find it
      await repo.updateBa(ffsBa.baId, providerId, { status: 'ACTIVE' });

      // Reset audit/events
      auditLogs.length = 0;
      emittedEvents.length = 0;

      // Now add PCPCM BA
      const pcpcmBa = await addBa(deps, providerId, {
        baNumber: '44442',
        baType: 'PCPCM',
      }, providerId);

      expect(pcpcmBa.baType).toBe('PCPCM');
      expect(pcpcmBa.isPrimary).toBe(false);

      // Verify PCPCM enrolment was created
      const enrolment = await repo.findPcpcmEnrolmentForProvider(providerId);
      expect(enrolment).toBeDefined();
      expect(enrolment!.pcpcmBaId).toBe(pcpcmBa.baId);
      expect(enrolment!.ffsBaId).toBe(ffsBa.baId);
      expect(enrolment!.status).toBe('PENDING');
    });

    it('rejects duplicate ba_number across system', async () => {
      const provider1 = crypto.randomUUID();
      const provider2 = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId: provider1, billingNumber: 'BN_AB5', cpsaRegistrationNumber: 'CPSA_AB5' }));
      await repo.createProvider(validProviderData({ providerId: provider2, billingNumber: 'BN_AB6', cpsaRegistrationNumber: 'CPSA_AB6' }));

      // Provider 1 adds a BA
      await addBa(deps, provider1, { baNumber: '55551', baType: 'FFS' }, provider1);

      // Provider 2 tries the same ba_number
      await expect(
        addBa(deps, provider2, { baNumber: '55551', baType: 'FFS' }, provider2),
      ).rejects.toThrow('already in use');
    });

    it('allows PCPCM when FFS BA is in PENDING status', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_AB7', cpsaRegistrationNumber: 'CPSA_AB7' }));

      // Add FFS BA (stays PENDING by default)
      await addBa(deps, providerId, { baNumber: '66661', baType: 'FFS' }, providerId);

      // Add PCPCM BA — should succeed because FFS exists (even if PENDING)
      const pcpcmBa = await addBa(deps, providerId, { baNumber: '66662', baType: 'PCPCM' }, providerId);
      expect(pcpcmBa.baType).toBe('PCPCM');
    });
  });

  // -----------------------------------------------------------------------
  // updateBa
  // -----------------------------------------------------------------------

  describe('updateBa', () => {
    it('validates status transitions (PENDING -> ACTIVE OK)', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_UB1', cpsaRegistrationNumber: 'CPSA_UB1' }));

      const ba = await addBa(deps, providerId, { baNumber: '77771', baType: 'FFS' }, providerId);
      expect(ba.status).toBe('PENDING');

      auditLogs.length = 0;
      emittedEvents.length = 0;

      const updated = await updateBa(deps, providerId, ba.baId, { status: 'ACTIVE' }, providerId);
      expect(updated.status).toBe('ACTIVE');

      // Verify audit
      expect(auditLogs).toHaveLength(1);
      expect(auditLogs[0].action).toBe('ba.updated');
      expect((auditLogs[0].detail as any).previousStatus).toBe('PENDING');
    });

    it('rejects ACTIVE -> PENDING transition', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_UB2', cpsaRegistrationNumber: 'CPSA_UB2' }));

      const ba = await repo.createBa(validBaData({ providerId, baNumber: '88881', status: 'ACTIVE' }));

      await expect(
        updateBa(deps, providerId, ba.baId, { status: 'PENDING' }, providerId),
      ).rejects.toThrow('Invalid status transition from ACTIVE to PENDING');
    });

    it('rejects INACTIVE -> any transition', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_UB3', cpsaRegistrationNumber: 'CPSA_UB3' }));

      const ba = await repo.createBa(validBaData({ providerId, baNumber: '88882', status: 'INACTIVE' }));

      await expect(
        updateBa(deps, providerId, ba.baId, { status: 'ACTIVE' }, providerId),
      ).rejects.toThrow('Invalid status transition from INACTIVE to ACTIVE');
    });

    it('updates effective_date without changing status', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_UB4', cpsaRegistrationNumber: 'CPSA_UB4' }));

      const ba = await addBa(deps, providerId, { baNumber: '88883', baType: 'FFS' }, providerId);
      auditLogs.length = 0;

      const updated = await updateBa(deps, providerId, ba.baId, { effectiveDate: '2026-03-01' }, providerId);
      expect(updated.effectiveDate).toBe('2026-03-01');
    });

    it('throws NotFoundError for non-existent BA', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_UB5', cpsaRegistrationNumber: 'CPSA_UB5' }));

      await expect(
        updateBa(deps, providerId, crypto.randomUUID(), { status: 'ACTIVE' }, providerId),
      ).rejects.toThrow('not found');
    });

    it('returns existing BA when no fields changed', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_UB6', cpsaRegistrationNumber: 'CPSA_UB6' }));

      const ba = await addBa(deps, providerId, { baNumber: '88884', baType: 'FFS' }, providerId);
      auditLogs.length = 0;

      const result = await updateBa(deps, providerId, ba.baId, {}, providerId);
      expect(result.baId).toBe(ba.baId);
      expect(auditLogs).toHaveLength(0); // no audit when nothing changed
    });
  });

  // -----------------------------------------------------------------------
  // deactivateBa
  // -----------------------------------------------------------------------

  describe('deactivateBa', () => {
    it('sets INACTIVE and end_date', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_DB1', cpsaRegistrationNumber: 'CPSA_DB1' }));

      const ba = await repo.createBa(validBaData({ providerId, baNumber: '99991', status: 'ACTIVE' }));

      const result = await deactivateBa(deps, providerId, ba.baId, providerId);

      expect(result.status).toBe('INACTIVE');
      expect(result.endDate).toBeDefined();
    });

    it('withdraws PCPCM enrolment when deactivating PCPCM BA', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_DB2', cpsaRegistrationNumber: 'CPSA_DB2' }));

      const ffsBa = await repo.createBa(validBaData({ providerId, baNumber: '99992', baType: 'FFS', status: 'ACTIVE', isPrimary: true }));
      const pcpcmBa = await repo.createBa(validBaData({ providerId, baNumber: '99993', baType: 'PCPCM', status: 'ACTIVE', isPrimary: false }));

      await repo.createPcpcmEnrolment(validPcpcmEnrolmentData({
        providerId,
        pcpcmBaId: pcpcmBa.baId,
        ffsBaId: ffsBa.baId,
        status: 'ACTIVE',
      }));

      await deactivateBa(deps, providerId, pcpcmBa.baId, providerId);

      // Verify PCPCM enrolment was withdrawn
      const enrolment = pcpcmEnrolmentStore.find(
        (e) => e.providerId === providerId,
      );
      expect(enrolment!.status).toBe('WITHDRAWN');
      expect(enrolment!.withdrawalDate).toBeDefined();
    });

    it('emits audit event', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_DB3', cpsaRegistrationNumber: 'CPSA_DB3' }));

      const ba = await repo.createBa(validBaData({ providerId, baNumber: '99994', status: 'ACTIVE' }));

      auditLogs.length = 0;
      emittedEvents.length = 0;

      await deactivateBa(deps, providerId, ba.baId, providerId);

      expect(auditLogs).toHaveLength(1);
      expect(auditLogs[0].action).toBe('ba.deactivated');
      expect(auditLogs[0].resourceId).toBe(ba.baId);
      expect((auditLogs[0].detail as any).baNumber).toBe('99994');

      expect(emittedEvents).toHaveLength(1);
      expect(emittedEvents[0].event).toBe('BA_DEACTIVATED');
    });

    it('rejects deactivation of non-ACTIVE BA', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_DB4', cpsaRegistrationNumber: 'CPSA_DB4' }));

      const ba = await repo.createBa(validBaData({ providerId, baNumber: '99995', status: 'PENDING' }));

      await expect(
        deactivateBa(deps, providerId, ba.baId, providerId),
      ).rejects.toThrow('Cannot deactivate a business arrangement with status PENDING');
    });

    it('throws NotFoundError for non-existent BA', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_DB5', cpsaRegistrationNumber: 'CPSA_DB5' }));

      await expect(
        deactivateBa(deps, providerId, crypto.randomUUID(), providerId),
      ).rejects.toThrow('not found');
    });
  });

  // -----------------------------------------------------------------------
  // listBas
  // -----------------------------------------------------------------------

  describe('listBas', () => {
    it('returns all BAs for the provider', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_LB1', cpsaRegistrationNumber: 'CPSA_LB1' }));

      await repo.createBa(validBaData({ providerId, baNumber: '10001', baType: 'FFS', status: 'ACTIVE' }));
      await repo.createBa(validBaData({ providerId, baNumber: '10002', baType: 'PCPCM', status: 'PENDING' }));
      await repo.createBa(validBaData({ providerId, baNumber: '10003', baType: 'ARP', status: 'INACTIVE' }));

      const result = await listBas(deps, providerId);

      expect(result).toHaveLength(3);
      expect(result.map((b) => b.baNumber).sort()).toEqual(['10001', '10002', '10003']);
    });

    it('returns empty array when no BAs exist', async () => {
      const providerId = crypto.randomUUID();
      const result = await listBas(deps, providerId);
      expect(result).toEqual([]);
    });
  });

  // -----------------------------------------------------------------------
  // Location Management
  // -----------------------------------------------------------------------

  describe('addLocation', () => {
    it('creates location and derives RRNP eligibility when community_code provided', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_AL1', cpsaRegistrationNumber: 'CPSA_AL1' }));

      const mockRefData: ReferenceDataLookup = {
        async getRrnpRate(communityId: string) {
          if (communityId === 'RURAL01') {
            return { communityName: 'Rural Town', rrnpPercentage: '15.00' };
          }
          return null;
        },
      };

      const depsWithRef: ProviderServiceDeps = { ...deps, referenceData: mockRefData };

      const result = await addLocation(depsWithRef, providerId, {
        name: 'Rural Clinic',
        functionalCentre: 'FC100',
        communityCode: 'RURAL01',
      }, providerId);

      expect(result.name).toBe('Rural Clinic');
      expect(result.rrnpEligible).toBe(true);
      expect(result.rrnpRate).toBe('15.00');
      expect(result.communityCode).toBe('RURAL01');

      // Audit log emitted
      expect(auditLogs).toHaveLength(1);
      expect(auditLogs[0].action).toBe('location.added');
      expect((auditLogs[0].detail as any).rrnpEligible).toBe(true);

      // Event emitted
      expect(emittedEvents).toHaveLength(1);
      expect(emittedEvents[0].event).toBe('LOCATION_ADDED');
    });

    it('creates location with rrnp_eligible false when no community_code', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_AL2', cpsaRegistrationNumber: 'CPSA_AL2' }));

      const result = await addLocation(deps, providerId, {
        name: 'Urban Clinic',
        functionalCentre: 'FC200',
      }, providerId);

      expect(result.rrnpEligible).toBe(false);
      expect(result.rrnpRate).toBeNull();
      expect(result.communityCode).toBeNull();
    });

    it('auto-sets default for first location', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_AL3', cpsaRegistrationNumber: 'CPSA_AL3' }));

      const first = await addLocation(deps, providerId, {
        name: 'First Location',
        functionalCentre: 'FC300',
      }, providerId);

      expect(first.isDefault).toBe(true);

      // Second location should NOT be default
      const second = await addLocation(deps, providerId, {
        name: 'Second Location',
        functionalCentre: 'FC301',
      }, providerId);

      expect(second.isDefault).toBe(false);
    });

    it('sets rrnp_eligible false when community_code not found in Reference Data', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_AL4', cpsaRegistrationNumber: 'CPSA_AL4' }));

      const mockRefData: ReferenceDataLookup = {
        async getRrnpRate() { return null; },
      };

      const depsWithRef: ProviderServiceDeps = { ...deps, referenceData: mockRefData };

      const result = await addLocation(depsWithRef, providerId, {
        name: 'Unknown Community',
        functionalCentre: 'FC400',
        communityCode: 'UNKNOWN',
      }, providerId);

      expect(result.rrnpEligible).toBe(false);
      expect(result.rrnpRate).toBeNull();
    });
  });

  describe('updateLocation', () => {
    it('re-derives RRNP when community_code changes', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_UL1', cpsaRegistrationNumber: 'CPSA_UL1' }));

      // Create location without community code
      const location = await repo.createLocation(
        validLocationData({ providerId, name: 'Test Clinic', communityCode: null, rrnpEligible: false, rrnpRate: null }),
      );

      const mockRefData: ReferenceDataLookup = {
        async getRrnpRate(communityId: string) {
          if (communityId === 'RURAL02') {
            return { communityName: 'Small Town', rrnpPercentage: '20.00' };
          }
          return null;
        },
      };

      const depsWithRef: ProviderServiceDeps = { ...deps, referenceData: mockRefData };

      const result = await updateLocation(depsWithRef, providerId, location.locationId, {
        communityCode: 'RURAL02',
      }, providerId);

      expect(result.communityCode).toBe('RURAL02');
      expect(result.rrnpEligible).toBe(true);
      expect(result.rrnpRate).toBe('20.00');

      // Audit log should contain changes
      expect(auditLogs).toHaveLength(1);
      expect(auditLogs[0].action).toBe('location.updated');
      const detail = auditLogs[0].detail as any;
      expect(detail.changes.communityCode).toEqual({ old: null, new: 'RURAL02' });
      expect(detail.changes.rrnpEligible).toEqual({ old: false, new: true });
    });

    it('throws NotFoundError for non-existent location', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_UL2', cpsaRegistrationNumber: 'CPSA_UL2' }));

      await expect(
        updateLocation(deps, providerId, crypto.randomUUID(), { name: 'New Name' }, providerId),
      ).rejects.toThrow('not found');
    });

    it('returns existing when no fields changed', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_UL3', cpsaRegistrationNumber: 'CPSA_UL3' }));

      const location = await repo.createLocation(
        validLocationData({ providerId, name: 'Unchanged' }),
      );

      const result = await updateLocation(deps, providerId, location.locationId, {
        name: 'Unchanged', // same value
      }, providerId);

      expect(result.name).toBe('Unchanged');
      expect(auditLogs).toHaveLength(0); // no audit if no changes
    });
  });

  describe('setDefaultLocation', () => {
    it('swaps default in transaction', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_SDL1', cpsaRegistrationNumber: 'CPSA_SDL1' }));

      // Create two locations, first is default
      const loc1 = await repo.createLocation(
        validLocationData({ providerId, name: 'Loc A', isDefault: true }),
      );
      const loc2 = await repo.createLocation(
        validLocationData({ providerId, name: 'Loc B', isDefault: false }),
      );

      // Set loc2 as default
      const result = await setDefaultLocation(deps, providerId, loc2.locationId, providerId);

      expect(result.isDefault).toBe(true);
      expect(result.locationId).toBe(loc2.locationId);

      // Verify loc1 is no longer default
      const refreshedLoc1 = locationStore.find((l) => l.locationId === loc1.locationId);
      expect(refreshedLoc1?.isDefault).toBe(false);

      // Audit log
      expect(auditLogs).toHaveLength(1);
      const detail = auditLogs[0].detail as any;
      expect(detail.action).toBe('set_default');
      expect(detail.previousDefaultLocationId).toBe(loc1.locationId);
      expect(detail.newDefaultLocationId).toBe(loc2.locationId);
    });

    it('throws NotFoundError for non-existent location', async () => {
      const providerId = crypto.randomUUID();
      await expect(
        setDefaultLocation(deps, providerId, crypto.randomUUID(), providerId),
      ).rejects.toThrow('not found');
    });

    it('throws BusinessRuleError for inactive location', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_SDL2', cpsaRegistrationNumber: 'CPSA_SDL2' }));

      const loc = await repo.createLocation(
        validLocationData({ providerId, name: 'Inactive Loc', isActive: false }),
      );

      await expect(
        setDefaultLocation(deps, providerId, loc.locationId, providerId),
      ).rejects.toThrow('inactive');
    });
  });

  describe('deactivateLocation', () => {
    it('clears default if was default', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_DL1', cpsaRegistrationNumber: 'CPSA_DL1' }));

      const loc = await repo.createLocation(
        validLocationData({ providerId, name: 'Default Loc', isDefault: true }),
      );

      const result = await deactivateLocation(deps, providerId, loc.locationId, providerId);

      expect(result.isActive).toBe(false);
      expect(result.isDefault).toBe(false);

      // Audit should record wasDefault
      expect(auditLogs).toHaveLength(1);
      expect(auditLogs[0].action).toBe('location.deactivated');
      expect((auditLogs[0].detail as any).wasDefault).toBe(true);
    });

    it('does not affect existing claims (soft delete only)', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_DL2', cpsaRegistrationNumber: 'CPSA_DL2' }));

      const loc = await repo.createLocation(
        validLocationData({ providerId, name: 'Used By Claims', isDefault: false }),
      );

      // Deactivate should succeed — claims are unaffected
      const result = await deactivateLocation(deps, providerId, loc.locationId, providerId);
      expect(result.isActive).toBe(false);

      // The location record still exists (soft delete)
      const allLocs = await repo.listLocationsForProvider(providerId);
      expect(allLocs).toHaveLength(1);
      expect(allLocs[0].locationId).toBe(loc.locationId);
      expect(allLocs[0].isActive).toBe(false);
    });

    it('throws NotFoundError for non-existent location', async () => {
      const providerId = crypto.randomUUID();
      await expect(
        deactivateLocation(deps, providerId, crypto.randomUUID(), providerId),
      ).rejects.toThrow('not found');
    });

    it('throws BusinessRuleError for already inactive location', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_DL3', cpsaRegistrationNumber: 'CPSA_DL3' }));

      const loc = await repo.createLocation(
        validLocationData({ providerId, name: 'Already Inactive', isActive: false }),
      );

      await expect(
        deactivateLocation(deps, providerId, loc.locationId, providerId),
      ).rejects.toThrow('already inactive');
    });
  });

  describe('refreshRrnpRates', () => {
    it('updates all active locations from Reference Data', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_RR1', cpsaRegistrationNumber: 'CPSA_RR1' }));

      // Location with community code, currently stale RRNP
      await repo.createLocation(
        validLocationData({
          providerId,
          name: 'Rural Clinic',
          communityCode: 'RURAL01',
          rrnpEligible: true,
          rrnpRate: '10.00', // stale rate
        }),
      );

      // Location with community code, not currently RRNP eligible
      await repo.createLocation(
        validLocationData({
          providerId,
          name: 'Another Rural',
          communityCode: 'RURAL02',
          rrnpEligible: false,
          rrnpRate: null,
        }),
      );

      // Location without community code
      await repo.createLocation(
        validLocationData({
          providerId,
          name: 'Urban Clinic',
          communityCode: null,
          rrnpEligible: false,
          rrnpRate: null,
        }),
      );

      const mockRefData: ReferenceDataLookup = {
        async getRrnpRate(communityId: string) {
          if (communityId === 'RURAL01') {
            return { communityName: 'Rural Town', rrnpPercentage: '15.00' }; // updated rate
          }
          if (communityId === 'RURAL02') {
            return { communityName: 'Another Town', rrnpPercentage: '12.50' }; // now eligible
          }
          return null;
        },
      };

      const depsWithRef: ProviderServiceDeps = { ...deps, referenceData: mockRefData };

      const result = await refreshRrnpRates(depsWithRef, providerId);

      // Two locations should have been updated (RURAL01 rate changed, RURAL02 became eligible)
      expect(result.updatedCount).toBe(2);

      // Verify store was updated
      const loc1 = locationStore.find((l) => l.communityCode === 'RURAL01');
      expect(loc1?.rrnpRate).toBe('15.00');
      expect(loc1?.rrnpEligible).toBe(true);

      const loc2 = locationStore.find((l) => l.communityCode === 'RURAL02');
      expect(loc2?.rrnpRate).toBe('12.50');
      expect(loc2?.rrnpEligible).toBe(true);

      // Urban clinic unchanged
      const loc3 = locationStore.find((l) => l.communityCode === null);
      expect(loc3?.rrnpEligible).toBe(false);
      expect(loc3?.rrnpRate).toBeNull();
    });

    it('clears RRNP for locations whose community is no longer eligible', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_RR2', cpsaRegistrationNumber: 'CPSA_RR2' }));

      await repo.createLocation(
        validLocationData({
          providerId,
          name: 'Was Rural',
          communityCode: 'DELISTED01',
          rrnpEligible: true,
          rrnpRate: '10.00',
        }),
      );

      const mockRefData: ReferenceDataLookup = {
        async getRrnpRate() { return null; }, // no longer eligible
      };

      const depsWithRef: ProviderServiceDeps = { ...deps, referenceData: mockRefData };

      const result = await refreshRrnpRates(depsWithRef, providerId);

      expect(result.updatedCount).toBe(1);

      const loc = locationStore.find((l) => l.communityCode === 'DELISTED01');
      expect(loc?.rrnpEligible).toBe(false);
      expect(loc?.rrnpRate).toBeNull();
    });

    it('skips locations that already have correct RRNP data', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_RR3', cpsaRegistrationNumber: 'CPSA_RR3' }));

      await repo.createLocation(
        validLocationData({
          providerId,
          name: 'Up to Date',
          communityCode: 'RURAL01',
          rrnpEligible: true,
          rrnpRate: '15.00',
        }),
      );

      const mockRefData: ReferenceDataLookup = {
        async getRrnpRate() { return { communityName: 'Rural Town', rrnpPercentage: '15.00' }; },
      };

      const depsWithRef: ProviderServiceDeps = { ...deps, referenceData: mockRefData };

      const result = await refreshRrnpRates(depsWithRef, providerId);

      expect(result.updatedCount).toBe(0); // already up to date
    });
  });

  // -----------------------------------------------------------------------
  // isPcpcmEnrolled
  // -----------------------------------------------------------------------

  describe('isPcpcmEnrolled', () => {
    it('returns true for enrolled provider', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_PE1', cpsaRegistrationNumber: 'CPSA_PE1' }));

      const ffsBa = await repo.createBa(validBaData({ providerId, baNumber: 'FFS_PE1', baType: 'FFS', isPrimary: true, status: 'ACTIVE' }));
      const pcpcmBa = await repo.createBa(validBaData({ providerId, baNumber: 'PCPCM_PE1', baType: 'PCPCM', isPrimary: false, status: 'ACTIVE' }));

      await repo.createPcpcmEnrolment(validPcpcmEnrolmentData({
        providerId,
        pcpcmBaId: pcpcmBa.baId,
        ffsBaId: ffsBa.baId,
        status: 'ACTIVE',
      }));

      const result = await isPcpcmEnrolled(deps, providerId);
      expect(result).toBe(true);
    });

    it('returns false for non-enrolled provider', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_PE2', cpsaRegistrationNumber: 'CPSA_PE2' }));
      await repo.createBa(validBaData({ providerId, baNumber: 'FFS_PE2', baType: 'FFS', isPrimary: true, status: 'ACTIVE' }));

      const result = await isPcpcmEnrolled(deps, providerId);
      expect(result).toBe(false);
    });
  });

  // -----------------------------------------------------------------------
  // routeClaimToBa
  // -----------------------------------------------------------------------

  describe('routeClaimToBa', () => {
    it('returns primary BA for WCB claims', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_RT1', cpsaRegistrationNumber: 'CPSA_RT1' }));
      await repo.createBa(validBaData({ providerId, baNumber: 'BA_RT1', baType: 'FFS', isPrimary: true, status: 'ACTIVE' }));

      const result = await routeClaimToBa(deps, providerId, 'WCB');

      expect(result.ba_number).toBe('BA_RT1');
      expect(result.routing_reason).toBe('WCB_PRIMARY');
      expect(result.warning).toBeUndefined();
    });

    it('returns FFS BA for non-PCPCM physician', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_RT2', cpsaRegistrationNumber: 'CPSA_RT2' }));
      await repo.createBa(validBaData({ providerId, baNumber: 'FFS_RT2', baType: 'FFS', isPrimary: true, status: 'ACTIVE' }));

      const result = await routeClaimToBa(deps, providerId, 'AHCIP', '03.04A');

      expect(result.ba_number).toBe('FFS_RT2');
      expect(result.ba_type).toBe('FFS');
      expect(result.routing_reason).toBe('NON_PCPCM');
      expect(result.warning).toBeUndefined();
    });

    it('returns PCPCM BA for in-basket HSC code', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_RT3', cpsaRegistrationNumber: 'CPSA_RT3' }));

      const ffsBa = await repo.createBa(validBaData({ providerId, baNumber: 'FFS_RT3', baType: 'FFS', isPrimary: true, status: 'ACTIVE' }));
      const pcpcmBa = await repo.createBa(validBaData({ providerId, baNumber: 'PCPCM_RT3', baType: 'PCPCM', isPrimary: false, status: 'ACTIVE' }));

      await repo.createPcpcmEnrolment(validPcpcmEnrolmentData({
        providerId,
        pcpcmBaId: pcpcmBa.baId,
        ffsBaId: ffsBa.baId,
        status: 'ACTIVE',
      }));

      // Seed SOMB reference data with in-basket HSC code
      const versionId = crypto.randomUUID();
      referenceVersionStore.push({
        versionId,
        dataSet: 'somb',
        versionLabel: 'SOMB 2026-Q1',
        effectiveFrom: '2026-01-01',
        effectiveTo: null,
        isActive: true,
      });
      hscCodeStore.push({
        id: crypto.randomUUID(),
        hscCode: '03.04A',
        description: 'Office Visit',
        baseFee: '40.00',
        feeType: 'FFS',
        pcpcmBasket: 'chronic_disease_management',
        versionId,
        effectiveFrom: '2026-01-01',
        effectiveTo: null,
      });

      const mockRefData: ReferenceDataLookup = {
        async getRrnpRate() { return null; },
        async getPcpcmBasket() { return 'chronic_disease_management'; },
      };
      const depsWithRef: ProviderServiceDeps = { ...deps, referenceData: mockRefData };

      const result = await routeClaimToBa(depsWithRef, providerId, 'AHCIP', '03.04A', '2026-02-15');

      expect(result.ba_number).toBe('PCPCM_RT3');
      expect(result.ba_type).toBe('PCPCM');
      expect(result.routing_reason).toBe('IN_BASKET');
      expect(result.warning).toBeUndefined();
    });

    it('returns FFS BA for out-of-basket HSC code', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_RT4', cpsaRegistrationNumber: 'CPSA_RT4' }));

      const ffsBa = await repo.createBa(validBaData({ providerId, baNumber: 'FFS_RT4', baType: 'FFS', isPrimary: true, status: 'ACTIVE' }));
      const pcpcmBa = await repo.createBa(validBaData({ providerId, baNumber: 'PCPCM_RT4', baType: 'PCPCM', isPrimary: false, status: 'ACTIVE' }));

      await repo.createPcpcmEnrolment(validPcpcmEnrolmentData({
        providerId,
        pcpcmBaId: pcpcmBa.baId,
        ffsBaId: ffsBa.baId,
        status: 'ACTIVE',
      }));

      // Seed SOMB reference data with out-of-basket HSC code
      const versionId = crypto.randomUUID();
      referenceVersionStore.push({
        versionId,
        dataSet: 'somb',
        versionLabel: 'SOMB 2026-Q1',
        effectiveFrom: '2026-01-01',
        effectiveTo: null,
        isActive: true,
      });
      hscCodeStore.push({
        id: crypto.randomUUID(),
        hscCode: '99.99Z',
        description: 'Out of basket service',
        baseFee: '100.00',
        feeType: 'FFS',
        pcpcmBasket: 'not_applicable',
        versionId,
        effectiveFrom: '2026-01-01',
        effectiveTo: null,
      });

      const mockRefData: ReferenceDataLookup = {
        async getRrnpRate() { return null; },
        async getPcpcmBasket() { return 'not_applicable'; },
      };
      const depsWithRef: ProviderServiceDeps = { ...deps, referenceData: mockRefData };

      const result = await routeClaimToBa(depsWithRef, providerId, 'AHCIP', '99.99Z', '2026-02-15');

      expect(result.ba_number).toBe('FFS_RT4');
      expect(result.ba_type).toBe('FFS');
      expect(result.routing_reason).toBe('OUT_OF_BASKET');
      expect(result.warning).toBeUndefined();
    });

    it('returns FFS BA with warning for unclassified HSC code', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_RT5', cpsaRegistrationNumber: 'CPSA_RT5' }));

      const ffsBa = await repo.createBa(validBaData({ providerId, baNumber: 'FFS_RT5', baType: 'FFS', isPrimary: true, status: 'ACTIVE' }));
      const pcpcmBa = await repo.createBa(validBaData({ providerId, baNumber: 'PCPCM_RT5', baType: 'PCPCM', isPrimary: false, status: 'ACTIVE' }));

      await repo.createPcpcmEnrolment(validPcpcmEnrolmentData({
        providerId,
        pcpcmBaId: pcpcmBa.baId,
        ffsBaId: ffsBa.baId,
        status: 'ACTIVE',
      }));

      // SOMB version exists but HSC code is not in reference data
      const versionId = crypto.randomUUID();
      referenceVersionStore.push({
        versionId,
        dataSet: 'somb',
        versionLabel: 'SOMB 2026-Q1',
        effectiveFrom: '2026-01-01',
        effectiveTo: null,
        isActive: true,
      });
      // No hscCodeStore entry for 'UNKNOWN_HSC'

      const mockRefData: ReferenceDataLookup = {
        async getRrnpRate() { return null; },
        async getPcpcmBasket() { return null; }, // code not found
      };
      const depsWithRef: ProviderServiceDeps = { ...deps, referenceData: mockRefData };

      const result = await routeClaimToBa(depsWithRef, providerId, 'AHCIP', 'UNKNOWN_HSC', '2026-02-15');

      expect(result.ba_number).toBe('FFS_RT5');
      expect(result.ba_type).toBe('FFS');
      expect(result.routing_reason).toBe('UNCLASSIFIED');
      expect(result.warning).toBeDefined();
      expect(result.warning).toContain('UNKNOWN_HSC');
    });

    it('uses SOMB version effective at dateOfService', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_RT6', cpsaRegistrationNumber: 'CPSA_RT6' }));

      const ffsBa = await repo.createBa(validBaData({ providerId, baNumber: 'FFS_RT6', baType: 'FFS', isPrimary: true, status: 'ACTIVE' }));
      const pcpcmBa = await repo.createBa(validBaData({ providerId, baNumber: 'PCPCM_RT6', baType: 'PCPCM', isPrimary: false, status: 'ACTIVE' }));

      await repo.createPcpcmEnrolment(validPcpcmEnrolmentData({
        providerId,
        pcpcmBaId: pcpcmBa.baId,
        ffsBaId: ffsBa.baId,
        status: 'ACTIVE',
      }));

      // Old SOMB version (Q1) — HSC code is in-basket
      const oldVersionId = crypto.randomUUID();
      referenceVersionStore.push({
        versionId: oldVersionId,
        dataSet: 'somb',
        versionLabel: 'SOMB 2026-Q1',
        effectiveFrom: '2026-01-01',
        effectiveTo: null,
        isActive: true,
      });
      hscCodeStore.push({
        id: crypto.randomUUID(),
        hscCode: '03.04A',
        description: 'Office Visit',
        baseFee: '40.00',
        feeType: 'FFS',
        pcpcmBasket: 'chronic_disease_management',
        versionId: oldVersionId,
        effectiveFrom: '2026-01-01',
        effectiveTo: null,
      });

      // The repo's getBaForClaim uses dateOfService to find the correct SOMB version.
      // Since the old version (effectiveFrom: 2026-01-01) contains 03.04A as in-basket,
      // passing dateOfService '2026-01-15' should match that version and route to PCPCM.
      const mockRefData: ReferenceDataLookup = {
        async getRrnpRate() { return null; },
        async getPcpcmBasket() { return 'chronic_disease_management'; },
      };
      const depsWithRef: ProviderServiceDeps = { ...deps, referenceData: mockRefData };

      const result = await routeClaimToBa(depsWithRef, providerId, 'AHCIP', '03.04A', '2026-01-15');

      // The repo resolved the SOMB version effective at 2026-01-15 and found
      // the HSC code as in-basket — proving dateOfService was used correctly
      expect(result.ba_number).toBe('PCPCM_RT6');
      expect(result.ba_type).toBe('PCPCM');
      expect(result.routing_reason).toBe('IN_BASKET');
    });

    it('throws NotFoundError when provider has no active BAs', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_RT7', cpsaRegistrationNumber: 'CPSA_RT7' }));

      await expect(
        routeClaimToBa(deps, providerId, 'AHCIP', '03.04A'),
      ).rejects.toThrow('not found');
    });
  });

  // -----------------------------------------------------------------------
  // WCB Configuration Management
  // -----------------------------------------------------------------------

  describe('addWcbConfig', () => {
    function depsWithWcbMatrix(
      baseDeps: ProviderServiceDeps,
      matrixEntries: Array<{ contractId: string; roleCode: string; permittedFormTypes: string[] }>,
    ): ProviderServiceDeps {
      const refData: ReferenceDataLookup = {
        async getRrnpRate() { return null; },
        async getWcbMatrixEntry(contractId: string, roleCode: string) {
          const entry = matrixEntries.find(
            (e) => e.contractId === contractId && e.roleCode === roleCode,
          );
          return entry ?? null;
        },
      };
      return { ...baseDeps, referenceData: refData };
    }

    const MATRIX_ENTRIES = [
      { contractId: 'C001', roleCode: 'PHYSICIAN', permittedFormTypes: ['PHYSICIAN_FIRST_REPORT', 'PROGRESS_REPORT'] },
      { contractId: 'C002', roleCode: 'SURGEON', permittedFormTypes: ['SURGICAL_REPORT', 'OPERATIVE_NOTE'] },
    ];

    it('validates against WCB matrix and creates config', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_WCB1', cpsaRegistrationNumber: 'CPSA_WCB1' }));

      const wcbDeps = depsWithWcbMatrix(deps, MATRIX_ENTRIES);

      const result = await addWcbConfig(wcbDeps, providerId, {
        contractId: 'C001',
        roleCode: 'PHYSICIAN',
      }, providerId);

      expect(result).toBeDefined();
      expect(result.contractId).toBe('C001');
      expect(result.roleCode).toBe('PHYSICIAN');
      expect(result.providerId).toBe(providerId);
    });

    it('auto-populates permitted_form_types from matrix', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_WCB2', cpsaRegistrationNumber: 'CPSA_WCB2' }));

      const wcbDeps = depsWithWcbMatrix(deps, MATRIX_ENTRIES);

      const result = await addWcbConfig(wcbDeps, providerId, {
        contractId: 'C001',
        roleCode: 'PHYSICIAN',
      }, providerId);

      expect(result.permittedFormTypes).toEqual(['PHYSICIAN_FIRST_REPORT', 'PROGRESS_REPORT']);
    });

    it('rejects invalid (contract_id, role_code) combination', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_WCB3', cpsaRegistrationNumber: 'CPSA_WCB3' }));

      const wcbDeps = depsWithWcbMatrix(deps, MATRIX_ENTRIES);

      await expect(
        addWcbConfig(wcbDeps, providerId, {
          contractId: 'INVALID',
          roleCode: 'INVALID',
        }, providerId),
      ).rejects.toThrow('not a valid combination');
    });

    it('rejects duplicate (provider, contract_id)', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_WCB4', cpsaRegistrationNumber: 'CPSA_WCB4' }));

      const wcbDeps = depsWithWcbMatrix(deps, MATRIX_ENTRIES);

      // First config succeeds
      await addWcbConfig(wcbDeps, providerId, {
        contractId: 'C001',
        roleCode: 'PHYSICIAN',
      }, providerId);

      // Second config with same contract_id fails (repo constraint)
      await expect(
        addWcbConfig(wcbDeps, providerId, {
          contractId: 'C001',
          roleCode: 'PHYSICIAN',
        }, providerId),
      ).rejects.toThrow('duplicate key');
    });

    it('emits wcb_config.added audit event', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_WCB5', cpsaRegistrationNumber: 'CPSA_WCB5' }));

      const wcbDeps = depsWithWcbMatrix(deps, MATRIX_ENTRIES);

      await addWcbConfig(wcbDeps, providerId, {
        contractId: 'C001',
        roleCode: 'PHYSICIAN',
      }, providerId);

      expect(auditLogs).toHaveLength(1);
      expect(auditLogs[0].action).toBe('wcb_config.added');
      expect((auditLogs[0].detail as any).contractId).toBe('C001');
      expect((auditLogs[0].detail as any).roleCode).toBe('PHYSICIAN');
      expect((auditLogs[0].detail as any).permittedFormTypes).toEqual(['PHYSICIAN_FIRST_REPORT', 'PROGRESS_REPORT']);
    });

    it('rejects when reference data service is unavailable', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_WCB6', cpsaRegistrationNumber: 'CPSA_WCB6' }));

      // deps has no referenceData configured
      await expect(
        addWcbConfig(deps, providerId, {
          contractId: 'C001',
          roleCode: 'PHYSICIAN',
        }, providerId),
      ).rejects.toThrow('WCB matrix lookup is not available');
    });

    it('sets skill_code when provided', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_WCB7', cpsaRegistrationNumber: 'CPSA_WCB7' }));

      const wcbDeps = depsWithWcbMatrix(deps, MATRIX_ENTRIES);

      const result = await addWcbConfig(wcbDeps, providerId, {
        contractId: 'C001',
        roleCode: 'PHYSICIAN',
        skillCode: 'ORTHO',
      }, providerId);

      expect(result.skillCode).toBe('ORTHO');
    });
  });

  describe('updateWcbConfig', () => {
    function depsWithWcbMatrix(baseDeps: ProviderServiceDeps): ProviderServiceDeps {
      const refData: ReferenceDataLookup = {
        async getRrnpRate() { return null; },
        async getWcbMatrixEntry(contractId: string, roleCode: string) {
          if (contractId === 'C001' && roleCode === 'PHYSICIAN') {
            return { contractId, roleCode, permittedFormTypes: ['PHYSICIAN_FIRST_REPORT', 'PROGRESS_REPORT'] };
          }
          return null;
        },
      };
      return { ...baseDeps, referenceData: refData };
    }

    it('updates skill_code', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_UWC1', cpsaRegistrationNumber: 'CPSA_UWC1' }));

      const wcbDeps = depsWithWcbMatrix(deps);

      const config = await addWcbConfig(wcbDeps, providerId, {
        contractId: 'C001',
        roleCode: 'PHYSICIAN',
      }, providerId);
      auditLogs.length = 0; // Clear audit from addWcbConfig

      const updated = await updateWcbConfig(wcbDeps, providerId, config.wcbConfigId, {
        skillCode: 'ORTHO_NEW',
      }, providerId);

      expect(updated.skillCode).toBe('ORTHO_NEW');
      expect(auditLogs).toHaveLength(1);
      expect(auditLogs[0].action).toBe('wcb_config.updated');
    });

    it('updates is_default', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_UWC2', cpsaRegistrationNumber: 'CPSA_UWC2' }));

      const wcbDeps = depsWithWcbMatrix(deps);

      const config = await addWcbConfig(wcbDeps, providerId, {
        contractId: 'C001',
        roleCode: 'PHYSICIAN',
      }, providerId);
      auditLogs.length = 0;

      const updated = await updateWcbConfig(wcbDeps, providerId, config.wcbConfigId, {
        isDefault: true,
      }, providerId);

      expect(updated.isDefault).toBe(true);
    });

    it('returns existing when nothing changed', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_UWC3', cpsaRegistrationNumber: 'CPSA_UWC3' }));

      const wcbDeps = depsWithWcbMatrix(deps);

      const config = await addWcbConfig(wcbDeps, providerId, {
        contractId: 'C001',
        roleCode: 'PHYSICIAN',
      }, providerId);
      auditLogs.length = 0;

      const result = await updateWcbConfig(wcbDeps, providerId, config.wcbConfigId, {}, providerId);

      expect(result.wcbConfigId).toBe(config.wcbConfigId);
      expect(auditLogs).toHaveLength(0); // No audit for no-op
    });

    it('throws NotFoundError for non-existent config', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_UWC4', cpsaRegistrationNumber: 'CPSA_UWC4' }));

      await expect(
        updateWcbConfig(deps, providerId, crypto.randomUUID(), {
          skillCode: 'TEST',
        }, providerId),
      ).rejects.toThrow('not found');
    });
  });

  describe('removeWcbConfig', () => {
    function depsWithWcbMatrixAndClaims(
      baseDeps: ProviderServiceDeps,
      hasPending: boolean,
    ): ProviderServiceDeps {
      const refData: ReferenceDataLookup = {
        async getRrnpRate() { return null; },
        async getWcbMatrixEntry(contractId: string, roleCode: string) {
          if (contractId === 'C001' && roleCode === 'PHYSICIAN') {
            return { contractId, roleCode, permittedFormTypes: ['PHYSICIAN_FIRST_REPORT', 'PROGRESS_REPORT'] };
          }
          return null;
        },
      };
      const claimsCheck: PendingClaimsCheck = {
        async hasPendingWcbClaims() { return hasPending; },
      };
      return { ...baseDeps, referenceData: refData, pendingClaimsCheck: claimsCheck };
    }

    it('deletes config scoped to provider', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_RWC1', cpsaRegistrationNumber: 'CPSA_RWC1' }));

      const wcbDeps = depsWithWcbMatrixAndClaims(deps, false);

      const config = await addWcbConfig(wcbDeps, providerId, {
        contractId: 'C001',
        roleCode: 'PHYSICIAN',
      }, providerId);
      auditLogs.length = 0;

      await removeWcbConfig(wcbDeps, providerId, config.wcbConfigId, providerId);

      // Verify config is gone
      const configs = await listWcbConfigs(wcbDeps, providerId);
      expect(configs).toHaveLength(0);

      // Verify audit
      expect(auditLogs).toHaveLength(1);
      expect(auditLogs[0].action).toBe('wcb_config.removed');
      expect((auditLogs[0].detail as any).contractId).toBe('C001');
      expect((auditLogs[0].detail as any).roleCode).toBe('PHYSICIAN');
    });

    it('rejects if pending claims reference config', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_RWC2', cpsaRegistrationNumber: 'CPSA_RWC2' }));

      const wcbDeps = depsWithWcbMatrixAndClaims(deps, true); // hasPending = true

      const config = await addWcbConfig(wcbDeps, providerId, {
        contractId: 'C001',
        roleCode: 'PHYSICIAN',
      }, providerId);

      await expect(
        removeWcbConfig(wcbDeps, providerId, config.wcbConfigId, providerId),
      ).rejects.toThrow('pending WCB claims');
    });

    it('throws NotFoundError for non-existent config', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_RWC3', cpsaRegistrationNumber: 'CPSA_RWC3' }));

      const wcbDeps = depsWithWcbMatrixAndClaims(deps, false);

      await expect(
        removeWcbConfig(wcbDeps, providerId, crypto.randomUUID(), providerId),
      ).rejects.toThrow('not found');
    });

    it('does not check pending claims when pendingClaimsCheck unavailable', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_RWC4', cpsaRegistrationNumber: 'CPSA_RWC4' }));

      // deps without pendingClaimsCheck but with referenceData
      const refData: ReferenceDataLookup = {
        async getRrnpRate() { return null; },
        async getWcbMatrixEntry(contractId: string, roleCode: string) {
          if (contractId === 'C001' && roleCode === 'PHYSICIAN') {
            return { contractId, roleCode, permittedFormTypes: ['PHYSICIAN_FIRST_REPORT'] };
          }
          return null;
        },
      };
      const wcbDeps: ProviderServiceDeps = { ...deps, referenceData: refData };

      const config = await addWcbConfig(wcbDeps, providerId, {
        contractId: 'C001',
        roleCode: 'PHYSICIAN',
      }, providerId);

      // Should succeed since no pendingClaimsCheck is configured
      await expect(
        removeWcbConfig(wcbDeps, providerId, config.wcbConfigId, providerId),
      ).resolves.toBeUndefined();
    });
  });

  describe('getFormPermissions', () => {
    function depsWithWcbMatrix(baseDeps: ProviderServiceDeps): ProviderServiceDeps {
      const refData: ReferenceDataLookup = {
        async getRrnpRate() { return null; },
        async getWcbMatrixEntry(contractId: string, roleCode: string) {
          if (contractId === 'C001' && roleCode === 'PHYSICIAN') {
            return { contractId, roleCode, permittedFormTypes: ['PHYSICIAN_FIRST_REPORT', 'PROGRESS_REPORT'] };
          }
          if (contractId === 'C002' && roleCode === 'SURGEON') {
            return { contractId, roleCode, permittedFormTypes: ['SURGICAL_REPORT', 'PROGRESS_REPORT'] };
          }
          return null;
        },
      };
      return { ...baseDeps, referenceData: refData };
    }

    it('returns union of all permitted forms across configs', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_FP1', cpsaRegistrationNumber: 'CPSA_FP1' }));

      const wcbDeps = depsWithWcbMatrix(deps);

      // Add two configs with overlapping form types
      await addWcbConfig(wcbDeps, providerId, {
        contractId: 'C001',
        roleCode: 'PHYSICIAN',
      }, providerId);

      await addWcbConfig(wcbDeps, providerId, {
        contractId: 'C002',
        roleCode: 'SURGEON',
      }, providerId);

      const permissions = await getFormPermissions(wcbDeps, providerId);

      // Should be deduplicated union: PHYSICIAN_FIRST_REPORT, PROGRESS_REPORT, SURGICAL_REPORT
      expect(permissions).toHaveLength(3);
      expect(permissions).toContain('PHYSICIAN_FIRST_REPORT');
      expect(permissions).toContain('PROGRESS_REPORT');
      expect(permissions).toContain('SURGICAL_REPORT');
    });

    it('returns empty array when no configs exist', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_FP2', cpsaRegistrationNumber: 'CPSA_FP2' }));

      const permissions = await getFormPermissions(deps, providerId);
      expect(permissions).toEqual([]);
    });
  });

  describe('getWcbConfigForForm', () => {
    function depsWithWcbMatrix(baseDeps: ProviderServiceDeps): ProviderServiceDeps {
      const refData: ReferenceDataLookup = {
        async getRrnpRate() { return null; },
        async getWcbMatrixEntry(contractId: string, roleCode: string) {
          if (contractId === 'C001' && roleCode === 'PHYSICIAN') {
            return { contractId, roleCode, permittedFormTypes: ['PHYSICIAN_FIRST_REPORT', 'PROGRESS_REPORT'] };
          }
          return null;
        },
      };
      return { ...baseDeps, referenceData: refData };
    }

    it('returns matching config for permitted form', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_WF1', cpsaRegistrationNumber: 'CPSA_WF1' }));

      const wcbDeps = depsWithWcbMatrix(deps);

      await addWcbConfig(wcbDeps, providerId, {
        contractId: 'C001',
        roleCode: 'PHYSICIAN',
      }, providerId);

      const result = await getWcbConfigForForm(wcbDeps, providerId, 'PHYSICIAN_FIRST_REPORT');

      expect(result).not.toBeNull();
      expect(result!.contractId).toBe('C001');
      expect(result!.roleCode).toBe('PHYSICIAN');
    });

    it('returns null for non-permitted form', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_WF2', cpsaRegistrationNumber: 'CPSA_WF2' }));

      const wcbDeps = depsWithWcbMatrix(deps);

      await addWcbConfig(wcbDeps, providerId, {
        contractId: 'C001',
        roleCode: 'PHYSICIAN',
      }, providerId);

      const result = await getWcbConfigForForm(wcbDeps, providerId, 'SURGICAL_REPORT');

      expect(result).toBeNull();
    });

    it('returns null when no configs exist', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_WF3', cpsaRegistrationNumber: 'CPSA_WF3' }));

      const result = await getWcbConfigForForm(deps, providerId, 'PHYSICIAN_FIRST_REPORT');

      expect(result).toBeNull();
    });
  });

  describe('listWcbConfigs', () => {
    function depsWithWcbMatrix(baseDeps: ProviderServiceDeps): ProviderServiceDeps {
      const refData: ReferenceDataLookup = {
        async getRrnpRate() { return null; },
        async getWcbMatrixEntry(contractId: string, roleCode: string) {
          if (contractId === 'C001' && roleCode === 'PHYSICIAN') {
            return { contractId, roleCode, permittedFormTypes: ['PHYSICIAN_FIRST_REPORT'] };
          }
          if (contractId === 'C002' && roleCode === 'SURGEON') {
            return { contractId, roleCode, permittedFormTypes: ['SURGICAL_REPORT'] };
          }
          return null;
        },
      };
      return { ...baseDeps, referenceData: refData };
    }

    it('lists all configs for provider', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_LWC1', cpsaRegistrationNumber: 'CPSA_LWC1' }));

      const wcbDeps = depsWithWcbMatrix(deps);

      await addWcbConfig(wcbDeps, providerId, {
        contractId: 'C001',
        roleCode: 'PHYSICIAN',
      }, providerId);

      await addWcbConfig(wcbDeps, providerId, {
        contractId: 'C002',
        roleCode: 'SURGEON',
      }, providerId);

      const configs = await listWcbConfigs(wcbDeps, providerId);

      expect(configs).toHaveLength(2);
      expect(configs.map((c: any) => c.contractId).sort()).toEqual(['C001', 'C002']);
    });

    it('returns empty array when no configs exist', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_LWC2', cpsaRegistrationNumber: 'CPSA_LWC2' }));

      const configs = await listWcbConfigs(deps, providerId);
      expect(configs).toEqual([]);
    });
  });

  // -----------------------------------------------------------------------
  // Delegate Management
  // -----------------------------------------------------------------------

  function makeTokenStore(): TokenStore & { store: Map<string, { tokenHash: string; expiresAt: Date }> } {
    const store = new Map<string, { tokenHash: string; expiresAt: Date }>();
    return {
      store,
      async storeTokenHash(relationshipId, tokenHash, expiresAt) {
        store.set(relationshipId, { tokenHash, expiresAt });
      },
      async getTokenHash(relationshipId) {
        return store.get(relationshipId) ?? null;
      },
      async deleteToken(relationshipId) {
        store.delete(relationshipId);
      },
    };
  }

  function depsWithTokenStore(baseDeps: ProviderServiceDeps): ProviderServiceDeps & { tokenStore: ReturnType<typeof makeTokenStore> } {
    const tokenStore = makeTokenStore();
    return { ...baseDeps, tokenStore };
  }

  describe('inviteDelegate', () => {
    it('creates relationship with INVITED status', async () => {
      const physicianId = crypto.randomUUID();
      const delegateUserId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId: physicianId, billingNumber: 'BN_INV1', cpsaRegistrationNumber: 'CPSA_INV1' }));

      const tDeps = depsWithTokenStore(deps);

      const result = await inviteDelegate(
        tDeps,
        physicianId,
        'delegate@example.com',
        ['CLAIM_VIEW', 'CLAIM_CREATE'],
        physicianId,
      );

      expect(result.relationship).toBeDefined();
      expect(result.relationship.status).toBe('INVITED');
      expect(result.relationship.physicianId).toBe(physicianId);
      expect(result.relationship.permissions).toEqual(['CLAIM_VIEW', 'CLAIM_CREATE']);
      expect(result.rawToken).toBeDefined();
      expect(typeof result.rawToken).toBe('string');
      expect(result.rawToken.length).toBe(64); // 32 bytes hex

      // Verify token was stored
      expect(tDeps.tokenStore.store.size).toBe(1);
      const storedToken = tDeps.tokenStore.store.get(result.relationship.relationshipId);
      expect(storedToken).toBeDefined();
      expect(storedToken!.tokenHash).toBeDefined();
      expect(storedToken!.expiresAt).toBeInstanceOf(Date);
    });

    it('validates permissions against catalogue', async () => {
      const physicianId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId: physicianId, billingNumber: 'BN_INV2', cpsaRegistrationNumber: 'CPSA_INV2' }));

      const tDeps = depsWithTokenStore(deps);

      // Valid permissions should work
      const result = await inviteDelegate(
        tDeps,
        physicianId,
        'delegate@example.com',
        ['CLAIM_VIEW', 'PATIENT_VIEW', 'REPORT_VIEW'],
        physicianId,
      );

      expect(result.relationship.permissions).toEqual(['CLAIM_VIEW', 'PATIENT_VIEW', 'REPORT_VIEW']);
    });

    it('rejects invalid permission keys', async () => {
      const physicianId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId: physicianId, billingNumber: 'BN_INV3', cpsaRegistrationNumber: 'CPSA_INV3' }));

      const tDeps = depsWithTokenStore(deps);

      await expect(
        inviteDelegate(
          tDeps,
          physicianId,
          'delegate@example.com',
          ['CLAIM_VIEW', 'INVALID_PERM', 'ALSO_INVALID'],
          physicianId,
        ),
      ).rejects.toThrow('Invalid delegate permission keys: INVALID_PERM, ALSO_INVALID');
    });

    it('rejects empty permissions array', async () => {
      const physicianId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId: physicianId, billingNumber: 'BN_INV4', cpsaRegistrationNumber: 'CPSA_INV4' }));

      const tDeps = depsWithTokenStore(deps);

      await expect(
        inviteDelegate(
          tDeps,
          physicianId,
          'delegate@example.com',
          [],
          physicianId,
        ),
      ).rejects.toThrow('At least one permission must be granted');
    });

    it('emits DELEGATE_INVITED event and audit log', async () => {
      const physicianId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId: physicianId, billingNumber: 'BN_INV5', cpsaRegistrationNumber: 'CPSA_INV5' }));

      const tDeps = depsWithTokenStore(deps);

      await inviteDelegate(
        tDeps,
        physicianId,
        'delegate@example.com',
        ['CLAIM_VIEW'],
        physicianId,
      );

      expect(auditLogs).toHaveLength(1);
      expect(auditLogs[0].action).toBe('delegate.invited');
      expect((auditLogs[0].detail as any).delegateEmail).toBe('delegate@example.com');

      const invitedEvent = emittedEvents.find((e) => e.event === 'DELEGATE_INVITED');
      expect(invitedEvent).toBeDefined();
      expect(invitedEvent!.payload.delegateEmail).toBe('delegate@example.com');
      expect(invitedEvent!.payload.rawToken).toBeDefined();
    });
  });

  describe('acceptInvitation', () => {
    it('activates relationship with valid token', async () => {
      const physicianId = crypto.randomUUID();
      const delegateUserId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId: physicianId, billingNumber: 'BN_ACC1', cpsaRegistrationNumber: 'CPSA_ACC1' }));

      const tDeps = depsWithTokenStore(deps);

      const { relationship, rawToken } = await inviteDelegate(
        tDeps,
        physicianId,
        'delegate@example.com',
        ['CLAIM_VIEW'],
        physicianId,
      );

      auditLogs.length = 0;
      emittedEvents.length = 0;

      const accepted = await acceptInvitation(
        tDeps,
        rawToken,
        delegateUserId,
        relationship.relationshipId,
      );

      expect(accepted.status).toBe('ACTIVE');
      expect(accepted.acceptedAt).toBeInstanceOf(Date);

      // Token should be cleaned up (single-use)
      expect(tDeps.tokenStore.store.size).toBe(0);

      // Audit log emitted
      expect(auditLogs).toHaveLength(1);
      expect(auditLogs[0].action).toBe('delegate.accepted');

      // Event emitted
      const acceptedEvent = emittedEvents.find((e) => e.event === 'DELEGATE_ACCEPTED');
      expect(acceptedEvent).toBeDefined();
    });

    it('rejects expired token (>7 days)', async () => {
      const physicianId = crypto.randomUUID();
      const delegateUserId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId: physicianId, billingNumber: 'BN_ACC2', cpsaRegistrationNumber: 'CPSA_ACC2' }));

      const tDeps = depsWithTokenStore(deps);

      const { relationship, rawToken } = await inviteDelegate(
        tDeps,
        physicianId,
        'delegate@example.com',
        ['CLAIM_VIEW'],
        physicianId,
      );

      // Manually expire the token
      const storedToken = tDeps.tokenStore.store.get(relationship.relationshipId)!;
      const expiredDate = new Date();
      expiredDate.setDate(expiredDate.getDate() - 1); // 1 day in the past
      tDeps.tokenStore.store.set(relationship.relationshipId, {
        ...storedToken,
        expiresAt: expiredDate,
      });

      await expect(
        acceptInvitation(tDeps, rawToken, delegateUserId, relationship.relationshipId),
      ).rejects.toThrow('Invitation token has expired');
    });

    it('rejects already-accepted invitation (token consumed)', async () => {
      const physicianId = crypto.randomUUID();
      const delegateUserId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId: physicianId, billingNumber: 'BN_ACC3', cpsaRegistrationNumber: 'CPSA_ACC3' }));

      const tDeps = depsWithTokenStore(deps);

      const { relationship, rawToken } = await inviteDelegate(
        tDeps,
        physicianId,
        'delegate@example.com',
        ['CLAIM_VIEW'],
        physicianId,
      );

      // Accept once
      await acceptInvitation(tDeps, rawToken, delegateUserId, relationship.relationshipId);

      // Second acceptance attempt — token was deleted (single-use)
      await expect(
        acceptInvitation(tDeps, rawToken, delegateUserId, relationship.relationshipId),
      ).rejects.toThrow('not found');
    });

    it('rejects invalid token', async () => {
      const physicianId = crypto.randomUUID();
      const delegateUserId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId: physicianId, billingNumber: 'BN_ACC4', cpsaRegistrationNumber: 'CPSA_ACC4' }));

      const tDeps = depsWithTokenStore(deps);

      const { relationship } = await inviteDelegate(
        tDeps,
        physicianId,
        'delegate@example.com',
        ['CLAIM_VIEW'],
        physicianId,
      );

      await expect(
        acceptInvitation(tDeps, 'wrong-token-value', delegateUserId, relationship.relationshipId),
      ).rejects.toThrow('Invalid invitation token');
    });
  });

  describe('updateDelegatePermissions', () => {
    it('updates JSONB and logs old/new diff', async () => {
      const physicianId = crypto.randomUUID();
      const delegateUserId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId: physicianId, billingNumber: 'BN_UDP1', cpsaRegistrationNumber: 'CPSA_UDP1' }));

      // Create a delegate relationship directly
      await repo.createDelegateRelationship({
        physicianId,
        delegateUserId,
        permissions: ['CLAIM_VIEW'],
        invitedAt: new Date(),
      });

      const relationships = await repo.listDelegatesForPhysician(physicianId);
      const relId = relationships[0].relationshipId;

      const updated = await updateDelegatePermissions(
        deps,
        physicianId,
        relId,
        ['CLAIM_VIEW', 'CLAIM_CREATE', 'PATIENT_VIEW'],
        physicianId,
      );

      expect(updated.permissions).toEqual(['CLAIM_VIEW', 'CLAIM_CREATE', 'PATIENT_VIEW']);

      // Audit log includes diff
      expect(auditLogs).toHaveLength(1);
      expect(auditLogs[0].action).toBe('delegate.permissions_changed');
      const detail = auditLogs[0].detail as any;
      expect(detail.oldPermissions).toEqual(['CLAIM_VIEW']);
      expect(detail.newPermissions).toEqual(['CLAIM_VIEW', 'CLAIM_CREATE', 'PATIENT_VIEW']);
      expect(detail.added).toEqual(['CLAIM_CREATE', 'PATIENT_VIEW']);
      expect(detail.removed).toEqual([]);
    });

    it('rejects if relationship not owned by physician', async () => {
      const physician1 = crypto.randomUUID();
      const physician2 = crypto.randomUUID();
      const delegateUserId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId: physician1, billingNumber: 'BN_UDP2', cpsaRegistrationNumber: 'CPSA_UDP2' }));
      await repo.createProvider(validProviderData({ providerId: physician2, billingNumber: 'BN_UDP3', cpsaRegistrationNumber: 'CPSA_UDP3' }));

      await repo.createDelegateRelationship({
        physicianId: physician1,
        delegateUserId,
        permissions: ['CLAIM_VIEW'],
        invitedAt: new Date(),
      });

      const relationships = await repo.listDelegatesForPhysician(physician1);
      const relId = relationships[0].relationshipId;

      // physician2 tries to update physician1's delegate
      await expect(
        updateDelegatePermissions(deps, physician2, relId, ['CLAIM_VIEW', 'CLAIM_CREATE'], physician2),
      ).rejects.toThrow('not found');
    });

    it('rejects invalid permission keys', async () => {
      const physicianId = crypto.randomUUID();
      const delegateUserId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId: physicianId, billingNumber: 'BN_UDP4', cpsaRegistrationNumber: 'CPSA_UDP4' }));

      await repo.createDelegateRelationship({
        physicianId,
        delegateUserId,
        permissions: ['CLAIM_VIEW'],
        invitedAt: new Date(),
      });

      const relationships = await repo.listDelegatesForPhysician(physicianId);
      const relId = relationships[0].relationshipId;

      await expect(
        updateDelegatePermissions(deps, physicianId, relId, ['CLAIM_VIEW', 'FAKE_PERM'], physicianId),
      ).rejects.toThrow('Invalid delegate permission keys');
    });

    it('emits DELEGATE_PERMISSIONS_CHANGED event', async () => {
      const physicianId = crypto.randomUUID();
      const delegateUserId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId: physicianId, billingNumber: 'BN_UDP5', cpsaRegistrationNumber: 'CPSA_UDP5' }));

      await repo.createDelegateRelationship({
        physicianId,
        delegateUserId,
        permissions: ['CLAIM_VIEW'],
        invitedAt: new Date(),
      });

      const relationships = await repo.listDelegatesForPhysician(physicianId);
      const relId = relationships[0].relationshipId;

      await updateDelegatePermissions(deps, physicianId, relId, ['CLAIM_VIEW', 'REPORT_VIEW'], physicianId);

      const event = emittedEvents.find((e) => e.event === 'DELEGATE_PERMISSIONS_CHANGED');
      expect(event).toBeDefined();
      expect(event!.payload.oldPermissions).toEqual(['CLAIM_VIEW']);
      expect(event!.payload.newPermissions).toEqual(['CLAIM_VIEW', 'REPORT_VIEW']);
    });
  });

  describe('revokeDelegate', () => {
    it('sets REVOKED and emits events', async () => {
      const physicianId = crypto.randomUUID();
      const delegateUserId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId: physicianId, billingNumber: 'BN_REV1', cpsaRegistrationNumber: 'CPSA_REV1' }));

      await repo.createDelegateRelationship({
        physicianId,
        delegateUserId,
        permissions: ['CLAIM_VIEW'],
        invitedAt: new Date(),
      });

      // Accept the relationship first
      const relationships = await repo.listDelegatesForPhysician(physicianId);
      const relId = relationships[0].relationshipId;
      await repo.acceptRelationship(relId);

      auditLogs.length = 0;
      emittedEvents.length = 0;

      const revoked = await revokeDelegate(deps, physicianId, relId, physicianId);

      expect(revoked.status).toBe('REVOKED');
      expect(revoked.revokedAt).toBeInstanceOf(Date);
      expect(revoked.revokedBy).toBe(physicianId);

      // Audit
      expect(auditLogs).toHaveLength(1);
      expect(auditLogs[0].action).toBe('delegate.revoked');

      // Event for session revocation by Domain 1
      const revokedEvent = emittedEvents.find((e) => e.event === 'DELEGATE_REVOKED');
      expect(revokedEvent).toBeDefined();
      expect(revokedEvent!.payload.delegateUserId).toBe(delegateUserId);
    });

    it('throws NotFoundError for non-existent relationship', async () => {
      const physicianId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId: physicianId, billingNumber: 'BN_REV2', cpsaRegistrationNumber: 'CPSA_REV2' }));

      await expect(
        revokeDelegate(deps, physicianId, crypto.randomUUID(), physicianId),
      ).rejects.toThrow('not found');
    });

    it('rejects revocation of already-revoked relationship', async () => {
      const physicianId = crypto.randomUUID();
      const delegateUserId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId: physicianId, billingNumber: 'BN_REV3', cpsaRegistrationNumber: 'CPSA_REV3' }));

      await repo.createDelegateRelationship({
        physicianId,
        delegateUserId,
        permissions: ['CLAIM_VIEW'],
        invitedAt: new Date(),
      });

      const relationships = await repo.listDelegatesForPhysician(physicianId);
      const relId = relationships[0].relationshipId;

      // Revoke once
      await revokeDelegate(deps, physicianId, relId, physicianId);

      // Second revocation should fail
      await expect(
        revokeDelegate(deps, physicianId, relId, physicianId),
      ).rejects.toThrow('already revoked');
    });
  });

  describe('listDelegates', () => {
    it('returns delegates with status and permissions', async () => {
      const physicianId = crypto.randomUUID();
      const delegate1 = crypto.randomUUID();
      const delegate2 = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId: physicianId, billingNumber: 'BN_LD1', cpsaRegistrationNumber: 'CPSA_LD1' }));

      userStore.push(
        { userId: delegate1, email: 'd1@test.com', fullName: 'Delegate One', role: 'delegate', isActive: true },
        { userId: delegate2, email: 'd2@test.com', fullName: 'Delegate Two', role: 'delegate', isActive: true },
      );

      await repo.createDelegateRelationship({
        physicianId, delegateUserId: delegate1,
        permissions: ['CLAIM_VIEW'], invitedAt: new Date(),
      });
      await repo.createDelegateRelationship({
        physicianId, delegateUserId: delegate2,
        permissions: ['CLAIM_VIEW', 'CLAIM_CREATE'], invitedAt: new Date(),
      });

      const delegates = await listDelegates(deps, physicianId);

      expect(delegates).toHaveLength(2);
      expect(delegates.map((d: any) => d.delegateEmail).sort()).toEqual(['d1@test.com', 'd2@test.com']);
    });
  });

  describe('listPhysiciansForDelegate (service)', () => {
    it('returns only ACTIVE relationships', async () => {
      const physician1 = crypto.randomUUID();
      const physician2 = crypto.randomUUID();
      const delegateUserId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId: physician1, billingNumber: 'BN_LPD1', cpsaRegistrationNumber: 'CPSA_LPD1' }));
      await repo.createProvider(validProviderData({ providerId: physician2, billingNumber: 'BN_LPD2', cpsaRegistrationNumber: 'CPSA_LPD2' }));

      await repo.createDelegateRelationship({
        physicianId: physician1, delegateUserId,
        permissions: ['CLAIM_VIEW'], invitedAt: new Date(),
      });
      // Accept physician1's relationship
      const rels1 = await repo.listDelegatesForPhysician(physician1);
      await repo.acceptRelationship(rels1[0].relationshipId);

      await repo.createDelegateRelationship({
        physicianId: physician2, delegateUserId,
        permissions: ['CLAIM_VIEW'], invitedAt: new Date(),
      });
      // Leave physician2's relationship as INVITED (not accepted)

      const physicians = await listPhysiciansForDelegate(deps, delegateUserId);

      // Only physician1's relationship is ACTIVE
      expect(physicians).toHaveLength(1);
      expect(physicians[0].physicianId).toBe(physician1);
    });
  });

  describe('switchPhysicianContext', () => {
    it('succeeds with active relationship', async () => {
      const physicianId = crypto.randomUUID();
      const delegateUserId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId: physicianId, billingNumber: 'BN_SPC1', cpsaRegistrationNumber: 'CPSA_SPC1' }));

      await repo.createDelegateRelationship({
        physicianId, delegateUserId,
        permissions: ['CLAIM_VIEW', 'PATIENT_VIEW'], invitedAt: new Date(),
      });
      const rels = await repo.listDelegatesForPhysician(physicianId);
      await repo.acceptRelationship(rels[0].relationshipId);

      const context = await switchPhysicianContext(deps, delegateUserId, physicianId);

      expect(context.physicianId).toBe(physicianId);
      expect(context.delegateUserId).toBe(delegateUserId);
      expect(context.permissions).toEqual(['CLAIM_VIEW', 'PATIENT_VIEW']);

      // Audit emitted
      expect(auditLogs).toHaveLength(1);
      expect(auditLogs[0].action).toBe('delegate.context_switched');

      // Event emitted
      const event = emittedEvents.find((e) => e.event === 'DELEGATE_CONTEXT_SWITCHED');
      expect(event).toBeDefined();
    });

    it('fails without active relationship', async () => {
      const physicianId = crypto.randomUUID();
      const delegateUserId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId: physicianId, billingNumber: 'BN_SPC2', cpsaRegistrationNumber: 'CPSA_SPC2' }));

      // No relationship exists
      await expect(
        switchPhysicianContext(deps, delegateUserId, physicianId),
      ).rejects.toThrow('not found');
    });

    it('fails with INVITED (not yet ACTIVE) relationship', async () => {
      const physicianId = crypto.randomUUID();
      const delegateUserId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId: physicianId, billingNumber: 'BN_SPC3', cpsaRegistrationNumber: 'CPSA_SPC3' }));

      await repo.createDelegateRelationship({
        physicianId, delegateUserId,
        permissions: ['CLAIM_VIEW'], invitedAt: new Date(),
      });
      // Do NOT accept — status stays INVITED

      // findActiveRelationship looks for non-REVOKED, so INVITED will be found
      // but switchPhysicianContext should reject non-ACTIVE
      await expect(
        switchPhysicianContext(deps, delegateUserId, physicianId),
      ).rejects.toThrow('not active');
    });

    it('fails with REVOKED relationship', async () => {
      const physicianId = crypto.randomUUID();
      const delegateUserId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId: physicianId, billingNumber: 'BN_SPC4', cpsaRegistrationNumber: 'CPSA_SPC4' }));

      await repo.createDelegateRelationship({
        physicianId, delegateUserId,
        permissions: ['CLAIM_VIEW'], invitedAt: new Date(),
      });
      const rels = await repo.listDelegatesForPhysician(physicianId);
      await repo.acceptRelationship(rels[0].relationshipId);
      await repo.revokeRelationship(rels[0].relationshipId, physicianId, physicianId);

      // findActiveRelationship excludes REVOKED, so this returns not found
      await expect(
        switchPhysicianContext(deps, delegateUserId, physicianId),
      ).rejects.toThrow('not found');
    });
  });

  // -----------------------------------------------------------------------
  // getSubmissionPreferences
  // -----------------------------------------------------------------------

  describe('getSubmissionPreferences', () => {
    it('returns current preferences', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_SP1', cpsaRegistrationNumber: 'CPSA_SP1' }));
      await repo.createSubmissionPreferences({
        providerId,
        ahcipSubmissionMode: 'AUTO_ALL',
        wcbSubmissionMode: 'REQUIRE_APPROVAL',
        batchReviewReminder: false,
        deadlineReminderDays: 14,
        updatedBy: providerId,
      });

      const result = await getSubmissionPreferences(deps, providerId);

      expect(result).not.toBeNull();
      expect(result!.ahcipSubmissionMode).toBe('AUTO_ALL');
      expect(result!.wcbSubmissionMode).toBe('REQUIRE_APPROVAL');
      expect(result!.batchReviewReminder).toBe(false);
      expect(result!.deadlineReminderDays).toBe(14);
    });

    it('returns null when preferences not yet initialised', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_SP2', cpsaRegistrationNumber: 'CPSA_SP2' }));

      const result = await getSubmissionPreferences(deps, providerId);
      expect(result).toBeNull();
    });
  });

  // -----------------------------------------------------------------------
  // updateSubmissionPreferences
  // -----------------------------------------------------------------------

  describe('updateSubmissionPreferences', () => {
    it('updates modes and emits audit event', async () => {
      const providerId = crypto.randomUUID();
      const actorId = providerId;
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_USP1', cpsaRegistrationNumber: 'CPSA_USP1' }));
      await repo.createSubmissionPreferences({
        providerId,
        ahcipSubmissionMode: 'AUTO_CLEAN',
        wcbSubmissionMode: 'REQUIRE_APPROVAL',
        batchReviewReminder: true,
        deadlineReminderDays: 7,
        updatedBy: providerId,
      });

      const result = await updateSubmissionPreferences(deps, providerId, {
        ahcipSubmissionMode: 'AUTO_ALL',
        deadlineReminderDays: 14,
      }, actorId);

      expect(result.ahcipSubmissionMode).toBe('AUTO_ALL');
      expect(result.wcbSubmissionMode).toBe('REQUIRE_APPROVAL'); // unchanged
      expect(result.deadlineReminderDays).toBe(14);
      expect(result.batchReviewReminder).toBe(true); // unchanged

      // Verify audit log
      const auditEntry = auditLogs.find((log) => log.action === 'submission_preference.changed');
      expect(auditEntry).toBeDefined();
      expect((auditEntry!.detail as any).changes.ahcipSubmissionMode).toEqual({
        old: 'AUTO_CLEAN',
        new: 'AUTO_ALL',
      });
      expect((auditEntry!.detail as any).changes.deadlineReminderDays).toEqual({
        old: 7,
        new: 14,
      });
    });

    it('returns existing values when nothing changes', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_USP2', cpsaRegistrationNumber: 'CPSA_USP2' }));
      await repo.createSubmissionPreferences({
        providerId,
        ahcipSubmissionMode: 'AUTO_CLEAN',
        wcbSubmissionMode: 'REQUIRE_APPROVAL',
        batchReviewReminder: true,
        deadlineReminderDays: 7,
        updatedBy: providerId,
      });

      const result = await updateSubmissionPreferences(deps, providerId, {
        ahcipSubmissionMode: 'AUTO_CLEAN', // same as existing
      }, providerId);

      expect(result.ahcipSubmissionMode).toBe('AUTO_CLEAN');
      // No audit event should be emitted for no-op
      expect(auditLogs.filter((l) => l.action === 'submission_preference.changed')).toHaveLength(0);
    });

    it('throws NotFoundError when preferences not initialised', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_USP3', cpsaRegistrationNumber: 'CPSA_USP3' }));

      await expect(
        updateSubmissionPreferences(deps, providerId, { ahcipSubmissionMode: 'AUTO_ALL' }, providerId),
      ).rejects.toThrow('not found');
    });
  });

  // -----------------------------------------------------------------------
  // initDefaultPreferences
  // -----------------------------------------------------------------------

  describe('initDefaultPreferences', () => {
    it('creates defaults (AUTO_CLEAN, REQUIRE_APPROVAL)', async () => {
      const providerId = crypto.randomUUID();
      const actorId = providerId;
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_IDP1', cpsaRegistrationNumber: 'CPSA_IDP1' }));

      const result = await initDefaultPreferences(deps, providerId, actorId);

      expect(result.ahcipSubmissionMode).toBe('AUTO_CLEAN');
      expect(result.wcbSubmissionMode).toBe('REQUIRE_APPROVAL');
      expect(result.batchReviewReminder).toBe(true);
      expect(result.deadlineReminderDays).toBe(7);

      // Verify persisted
      const persisted = await repo.findSubmissionPreferences(providerId);
      expect(persisted).toBeDefined();
      expect(persisted!.ahcipSubmissionMode).toBe('AUTO_CLEAN');

      // Verify audit
      const auditEntry = auditLogs.find((log) => log.action === 'submission_preference.changed');
      expect(auditEntry).toBeDefined();
      expect((auditEntry!.detail as any).action).toBe('initialized_defaults');
    });

    it('is idempotent — returns existing preferences if already initialised', async () => {
      const providerId = crypto.randomUUID();
      const actorId = providerId;
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_IDP2', cpsaRegistrationNumber: 'CPSA_IDP2' }));

      // Initialise with custom values via repo directly
      await repo.createSubmissionPreferences({
        providerId,
        ahcipSubmissionMode: 'AUTO_ALL',
        wcbSubmissionMode: 'REQUIRE_APPROVAL',
        batchReviewReminder: false,
        deadlineReminderDays: 3,
        updatedBy: providerId,
      });

      const result = await initDefaultPreferences(deps, providerId, actorId);

      // Should return existing, not overwrite with defaults
      expect(result.ahcipSubmissionMode).toBe('AUTO_ALL');
      expect(result.batchReviewReminder).toBe(false);
      expect(result.deadlineReminderDays).toBe(3);
      // No audit since we returned existing
      expect(auditLogs).toHaveLength(0);
    });
  });

  // -----------------------------------------------------------------------
  // getHlinkConfig
  // -----------------------------------------------------------------------

  describe('getHlinkConfig', () => {
    it('returns config without credential_secret_ref', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_HLC1', cpsaRegistrationNumber: 'CPSA_HLC1' }));
      await repo.createHlinkConfig({
        providerId,
        submitterPrefix: 'MER',
        credentialSecretRef: 'secret-vault-ref-123',
        accreditationStatus: 'ACTIVE',
        accreditationDate: '2026-01-15',
      });

      const result = await getHlinkConfig(deps, providerId);

      expect(result).not.toBeNull();
      expect(result!.submitterPrefix).toBe('MER');
      expect(result!.accreditationStatus).toBe('ACTIVE');
      expect(result!.accreditationDate).toBe('2026-01-15');
      // CRITICAL: credential_secret_ref must NEVER be returned
      expect((result as any).credentialSecretRef).toBeUndefined();
      expect((result as any).credential_secret_ref).toBeUndefined();
    });

    it('returns null when H-Link not configured', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_HLC2', cpsaRegistrationNumber: 'CPSA_HLC2' }));

      const result = await getHlinkConfig(deps, providerId);
      expect(result).toBeNull();
    });
  });

  // -----------------------------------------------------------------------
  // updateHlinkConfig
  // -----------------------------------------------------------------------

  describe('updateHlinkConfig', () => {
    it('updates prefix and accreditation status', async () => {
      const providerId = crypto.randomUUID();
      const actorId = providerId;
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_UHC1', cpsaRegistrationNumber: 'CPSA_UHC1' }));
      await repo.createHlinkConfig({
        providerId,
        submitterPrefix: 'OLD',
        credentialSecretRef: 'secret-ref',
        accreditationStatus: 'PENDING',
      });

      const result = await updateHlinkConfig(deps, providerId, {
        submitterPrefix: 'NEW',
        accreditationStatus: 'ACTIVE',
      }, actorId);

      expect(result.submitterPrefix).toBe('NEW');
      expect(result.accreditationStatus).toBe('ACTIVE');
      // SECURITY: no credential_secret_ref in result
      expect((result as any).credentialSecretRef).toBeUndefined();

      // Verify audit
      const auditEntry = auditLogs.find((log) => log.action === 'hlink_config.updated');
      expect(auditEntry).toBeDefined();
      expect((auditEntry!.detail as any).changes.submitterPrefix).toEqual({
        old: 'OLD',
        new: 'NEW',
      });
      expect((auditEntry!.detail as any).changes.accreditationStatus).toEqual({
        old: 'PENDING',
        new: 'ACTIVE',
      });
    });

    it('returns existing values when nothing changes', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_UHC2', cpsaRegistrationNumber: 'CPSA_UHC2' }));
      await repo.createHlinkConfig({
        providerId,
        submitterPrefix: 'MER',
        credentialSecretRef: 'secret-ref',
        accreditationStatus: 'ACTIVE',
      });

      const result = await updateHlinkConfig(deps, providerId, {
        submitterPrefix: 'MER', // same value
      }, providerId);

      expect(result.submitterPrefix).toBe('MER');
      expect(auditLogs.filter((l) => l.action === 'hlink_config.updated')).toHaveLength(0);
    });

    it('throws NotFoundError when H-Link not configured', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({ providerId, billingNumber: 'BN_UHC3', cpsaRegistrationNumber: 'CPSA_UHC3' }));

      await expect(
        updateHlinkConfig(deps, providerId, { submitterPrefix: 'MER' }, providerId),
      ).rejects.toThrow('not found');
    });
  });

  // -----------------------------------------------------------------------
  // isSubmissionAllowed
  // -----------------------------------------------------------------------

  describe('isSubmissionAllowed', () => {
    it('returns true for fully configured provider', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({
        providerId,
        billingNumber: 'BN_ISA1',
        cpsaRegistrationNumber: 'CPSA_ISA1',
        status: 'ACTIVE',
        onboardingCompleted: true,
      }));
      await repo.createHlinkConfig({
        providerId,
        submitterPrefix: 'MER',
        credentialSecretRef: 'secret-ref',
        accreditationStatus: 'ACTIVE',
      });

      const result = await isSubmissionAllowed(deps, providerId);

      expect(result.allowed).toBe(true);
      expect(result.reasons).toHaveLength(0);
    });

    it('returns false with reason for incomplete onboarding', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({
        providerId,
        billingNumber: 'BN_ISA2',
        cpsaRegistrationNumber: 'CPSA_ISA2',
        status: 'ACTIVE',
        onboardingCompleted: false,
      }));
      await repo.createHlinkConfig({
        providerId,
        submitterPrefix: 'MER',
        credentialSecretRef: 'secret-ref',
        accreditationStatus: 'ACTIVE',
      });

      const result = await isSubmissionAllowed(deps, providerId);

      expect(result.allowed).toBe(false);
      expect(result.reasons).toContain('ONBOARDING_INCOMPLETE');
    });

    it('returns false for SUSPENDED provider', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({
        providerId,
        billingNumber: 'BN_ISA3',
        cpsaRegistrationNumber: 'CPSA_ISA3',
        status: 'SUSPENDED',
        onboardingCompleted: true,
      }));
      await repo.createHlinkConfig({
        providerId,
        submitterPrefix: 'MER',
        credentialSecretRef: 'secret-ref',
        accreditationStatus: 'ACTIVE',
      });

      const result = await isSubmissionAllowed(deps, providerId);

      expect(result.allowed).toBe(false);
      expect(result.reasons).toContain('PROVIDER_SUSPENDED');
    });

    it('returns false for PENDING H-Link accreditation', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({
        providerId,
        billingNumber: 'BN_ISA4',
        cpsaRegistrationNumber: 'CPSA_ISA4',
        status: 'ACTIVE',
        onboardingCompleted: true,
      }));
      await repo.createHlinkConfig({
        providerId,
        submitterPrefix: 'MER',
        credentialSecretRef: 'secret-ref',
        accreditationStatus: 'PENDING',
      });

      const result = await isSubmissionAllowed(deps, providerId);

      expect(result.allowed).toBe(false);
      expect(result.reasons).toContain('HLINK_NOT_ACTIVE');
    });

    it('returns false with HLINK_NOT_CONFIGURED when no H-Link config exists', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({
        providerId,
        billingNumber: 'BN_ISA5',
        cpsaRegistrationNumber: 'CPSA_ISA5',
        status: 'ACTIVE',
        onboardingCompleted: true,
      }));

      const result = await isSubmissionAllowed(deps, providerId);

      expect(result.allowed).toBe(false);
      expect(result.reasons).toContain('HLINK_NOT_CONFIGURED');
    });

    it('returns multiple reasons when multiple conditions fail', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({
        providerId,
        billingNumber: 'BN_ISA6',
        cpsaRegistrationNumber: 'CPSA_ISA6',
        status: 'SUSPENDED',
        onboardingCompleted: false,
      }));
      // No H-Link config

      const result = await isSubmissionAllowed(deps, providerId);

      expect(result.allowed).toBe(false);
      expect(result.reasons).toContain('ONBOARDING_INCOMPLETE');
      expect(result.reasons).toContain('PROVIDER_SUSPENDED');
      expect(result.reasons).toContain('HLINK_NOT_CONFIGURED');
      expect(result.reasons).toHaveLength(3);
    });

    it('throws NotFoundError for non-existent provider', async () => {
      await expect(
        isSubmissionAllowed(deps, crypto.randomUUID()),
      ).rejects.toThrow('not found');
    });

    it('returns false for INACTIVE provider status', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({
        providerId,
        billingNumber: 'BN_ISA7',
        cpsaRegistrationNumber: 'CPSA_ISA7',
        status: 'INACTIVE',
        onboardingCompleted: true,
      }));
      await repo.createHlinkConfig({
        providerId,
        submitterPrefix: 'MER',
        credentialSecretRef: 'secret-ref',
        accreditationStatus: 'ACTIVE',
      });

      const result = await isSubmissionAllowed(deps, providerId);

      expect(result.allowed).toBe(false);
      expect(result.reasons).toContain('PROVIDER_INACTIVE');
    });
  });

  // -----------------------------------------------------------------------
  // Provider Context (Internal API for Domain 4)
  // -----------------------------------------------------------------------

  describe('getProviderContext', () => {
    it('returns complete context with all 17 fields', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({
        providerId,
        billingNumber: 'BN_PC1',
        cpsaRegistrationNumber: 'CPSA_PC1',
        specialtyCode: '03',
        physicianType: 'SPECIALIST',
        status: 'ACTIVE',
        onboardingCompleted: true,
      }));

      // Add FFS BA
      const ffsBa = await repo.createBa(validBaData({
        providerId,
        baNumber: 'FFS100',
        baType: 'FFS',
        isPrimary: true,
        status: 'ACTIVE',
      }));

      // Add PCPCM BA
      const pcpcmBa = await repo.createBa(validBaData({
        providerId,
        baNumber: 'PCPCM100',
        baType: 'PCPCM',
        isPrimary: false,
        status: 'ACTIVE',
      }));

      // Add PCPCM enrolment linking the two BAs
      await repo.createPcpcmEnrolment(validPcpcmEnrolmentData({
        providerId,
        pcpcmBaId: pcpcmBa.baId,
        ffsBaId: ffsBa.baId,
        status: 'ACTIVE',
      }));

      // Add locations
      await repo.createLocation(validLocationData({
        providerId,
        name: 'Primary Clinic',
        isDefault: true,
        isActive: true,
      }));
      await repo.createLocation(validLocationData({
        providerId,
        name: 'Secondary Clinic',
        functionalCentre: 'FC002',
        isDefault: false,
        isActive: true,
      }));

      // Add WCB config
      await repo.createWcbConfig(validWcbConfigData({
        providerId,
        contractId: 'WCB01',
        roleCode: 'PHYSICIAN',
        isDefault: true,
        permittedFormTypes: ['PHYSICIAN_FIRST_REPORT'],
      }));

      // Add submission preferences
      await repo.createSubmissionPreferences({
        providerId,
        ahcipSubmissionMode: 'AUTO_CLEAN',
        wcbSubmissionMode: 'REQUIRE_APPROVAL',
        batchReviewReminder: true,
        deadlineReminderDays: 7,
        updatedBy: providerId,
      });

      // Add H-Link config
      await repo.createHlinkConfig({
        providerId,
        submitterPrefix: 'MER',
        credentialSecretRef: 'secret-ref',
        accreditationStatus: 'ACTIVE',
      });

      const context = await getProviderContext(deps, providerId);

      expect(context).not.toBeNull();

      // Verify all 17 fields
      expect(context!.provider_id).toBe(providerId);
      expect(context!.billing_number).toBe('BN_PC1');
      expect(context!.specialty_code).toBe('03');
      expect(context!.physician_type).toBe('SPECIALIST');

      // BAs
      expect(context!.bas).toHaveLength(2);
      expect(context!.bas.map((b) => b.ba_number).sort()).toEqual(['FFS100', 'PCPCM100']);

      // Locations
      expect(context!.default_location).not.toBeNull();
      expect(context!.default_location!.name).toBe('Primary Clinic');
      expect(context!.all_locations).toHaveLength(2);

      // PCPCM
      expect(context!.pcpcm_enrolled).toBe(true);
      expect(context!.pcpcm_ba_number).toBe('PCPCM100');
      expect(context!.ffs_ba_number).toBe('FFS100');

      // WCB
      expect(context!.wcb_configs).toHaveLength(1);
      expect(context!.wcb_configs[0].contract_id).toBe('WCB01');
      expect(context!.default_wcb_config).not.toBeNull();
      expect(context!.default_wcb_config!.contract_id).toBe('WCB01');

      // Submission preferences
      expect(context!.submission_preferences).not.toBeNull();
      expect(context!.submission_preferences!.ahcip_submission_mode).toBe('AUTO_CLEAN');
      expect(context!.submission_preferences!.wcb_submission_mode).toBe('REQUIRE_APPROVAL');
      expect(context!.submission_preferences!.batch_review_reminder).toBe(true);
      expect(context!.submission_preferences!.deadline_reminder_days).toBe(7);

      // H-Link
      expect(context!.hlink_accreditation_status).toBe('ACTIVE');
      expect(context!.hlink_submitter_prefix).toBe('MER');

      // Status
      expect(context!.onboarding_completed).toBe(true);
      expect(context!.status).toBe('ACTIVE');
    });

    it('returns null for unknown provider', async () => {
      const result = await getProviderContext(deps, crypto.randomUUID());
      expect(result).toBeNull();
    });

    it('reflects latest BA changes', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({
        providerId,
        billingNumber: 'BN_PC2',
        cpsaRegistrationNumber: 'CPSA_PC2',
      }));

      // Initially no BAs
      let context = await getProviderContext(deps, providerId);
      expect(context).not.toBeNull();
      expect(context!.bas).toHaveLength(0);

      // Add a BA
      await repo.createBa(validBaData({
        providerId,
        baNumber: 'FFS200',
        baType: 'FFS',
        isPrimary: true,
        status: 'ACTIVE',
      }));

      // Context should now reflect the new BA
      context = await getProviderContext(deps, providerId);
      expect(context).not.toBeNull();
      expect(context!.bas).toHaveLength(1);
      expect(context!.bas[0].ba_number).toBe('FFS200');

      // Deactivate the BA
      const ba = context!.bas[0];
      await repo.deactivateBa(ba.ba_id, providerId);

      // Context should reflect deactivation (no active BAs)
      context = await getProviderContext(deps, providerId);
      expect(context).not.toBeNull();
      expect(context!.bas).toHaveLength(0);
    });
  });

  describe('getBaForClaim (internal API)', () => {
    it('delegates to PCPCM routing logic for AHCIP claims', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({
        providerId,
        billingNumber: 'BN_BC1',
        cpsaRegistrationNumber: 'CPSA_BC1',
      }));

      const ffsBa = await repo.createBa(validBaData({
        providerId,
        baNumber: 'FFS300',
        baType: 'FFS',
        isPrimary: true,
        status: 'ACTIVE',
      }));

      const result = await getBaForClaim(deps, providerId, 'AHCIP');

      expect(result).toBeDefined();
      expect(result.ba_number).toBe('FFS300');
      expect(result.ba_type).toBe('FFS');
      expect(result.routing_reason).toBe('NON_PCPCM');
    });

    it('routes WCB claims to primary BA', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({
        providerId,
        billingNumber: 'BN_BC2',
        cpsaRegistrationNumber: 'CPSA_BC2',
      }));

      await repo.createBa(validBaData({
        providerId,
        baNumber: 'FFS400',
        baType: 'FFS',
        isPrimary: true,
        status: 'ACTIVE',
      }));

      const result = await getBaForClaim(deps, providerId, 'WCB');

      expect(result).toBeDefined();
      expect(result.ba_number).toBe('FFS400');
      expect(result.routing_reason).toBe('WCB_PRIMARY');
    });

    it('returns ba_number, ba_type, and routing_reason', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({
        providerId,
        billingNumber: 'BN_BC3',
        cpsaRegistrationNumber: 'CPSA_BC3',
      }));

      await repo.createBa(validBaData({
        providerId,
        baNumber: 'FFS500',
        baType: 'FFS',
        isPrimary: true,
        status: 'ACTIVE',
      }));

      const result = await getBaForClaim(deps, providerId, 'AHCIP');

      expect(result).toHaveProperty('ba_number');
      expect(result).toHaveProperty('ba_type');
      expect(result).toHaveProperty('routing_reason');
      expect(typeof result.ba_number).toBe('string');
      expect(typeof result.ba_type).toBe('string');
      expect(typeof result.routing_reason).toBe('string');
    });

    it('throws NotFoundError when provider has no active BAs', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({
        providerId,
        billingNumber: 'BN_BC4',
        cpsaRegistrationNumber: 'CPSA_BC4',
      }));

      await expect(
        getBaForClaim(deps, providerId, 'AHCIP'),
      ).rejects.toThrow('not found');
    });
  });

  describe('getWcbConfigForFormOrThrow', () => {
    function depsWithWcbMatrix(baseDeps: ProviderServiceDeps): ProviderServiceDeps {
      const refData: ReferenceDataLookup = {
        async getRrnpRate() { return null; },
        async getWcbMatrixEntry(contractId: string, roleCode: string) {
          if (contractId === 'C001' && roleCode === 'PHYSICIAN') {
            return { contractId, roleCode, permittedFormTypes: ['PHYSICIAN_FIRST_REPORT', 'PROGRESS_REPORT'] };
          }
          return null;
        },
      };
      return { ...baseDeps, referenceData: refData };
    }

    it('returns matching config with skill_code for permitted form', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({
        providerId,
        billingNumber: 'BN_WCF1',
        cpsaRegistrationNumber: 'CPSA_WCF1',
      }));

      const wcbDeps = depsWithWcbMatrix(deps);

      await addWcbConfig(wcbDeps, providerId, {
        contractId: 'C001',
        roleCode: 'PHYSICIAN',
        skillCode: 'GENERAL',
      }, providerId);

      const result = await getWcbConfigForFormOrThrow(wcbDeps, providerId, 'PHYSICIAN_FIRST_REPORT');

      expect(result).toBeDefined();
      expect(result.contractId).toBe('C001');
      expect(result.roleCode).toBe('PHYSICIAN');
      expect(result.skillCode).toBe('GENERAL');
    });

    it('throws BusinessRuleError for non-permitted form', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({
        providerId,
        billingNumber: 'BN_WCF2',
        cpsaRegistrationNumber: 'CPSA_WCF2',
      }));

      const wcbDeps = depsWithWcbMatrix(deps);

      await addWcbConfig(wcbDeps, providerId, {
        contractId: 'C001',
        roleCode: 'PHYSICIAN',
      }, providerId);

      await expect(
        getWcbConfigForFormOrThrow(wcbDeps, providerId, 'SURGICAL_REPORT'),
      ).rejects.toThrow('Provider is not permitted to submit WCB form type: SURGICAL_REPORT');
    });

    it('throws BusinessRuleError when no WCB configs exist', async () => {
      const providerId = crypto.randomUUID();
      await repo.createProvider(validProviderData({
        providerId,
        billingNumber: 'BN_WCF3',
        cpsaRegistrationNumber: 'CPSA_WCF3',
      }));

      await expect(
        getWcbConfigForFormOrThrow(deps, providerId, 'PHYSICIAN_FIRST_REPORT'),
      ).rejects.toThrow('Provider is not permitted to submit WCB form type: PHYSICIAN_FIRST_REPORT');
    });
  });
});
