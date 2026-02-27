import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  resolveRoutingBa,
  detectRoutingConflict,
  getConnectCareStatus,
  setConnectCareStatus,
  getRoutingConfig,
  updateFacilityMappings,
  updateScheduleMappings,
  type ProviderServiceDeps,
} from './provider.service.js';

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
  ne: (column: any, value: any) => {
    const colName = column?.name;
    return { __predicate: (row: any) => row[colName] !== value };
  },
  count: () => ({ __count: true }),
  lte: (column: any, value: any) => {
    const colName = column?.name;
    return { __predicate: (row: any) => row[colName] <= value };
  },
  gte: (column: any, value: any) => {
    const colName = column?.name;
    return { __predicate: (row: any) => row[colName] >= value };
  },
  sql: (strings: TemplateStringsArray, ...values: any[]) => ({
    __sql: true,
    raw: strings.join('?'),
    values,
  }),
}));

// ---------------------------------------------------------------------------
// Mock provider constants
// ---------------------------------------------------------------------------

vi.mock('@meritum/shared/constants/provider.constants.js', () => ({
  ProviderStatus: { ACTIVE: 'ACTIVE', SUSPENDED: 'SUSPENDED', INACTIVE: 'INACTIVE' },
  BAType: { FFS: 'FFS', PCPCM: 'PCPCM', ARP: 'ARP' },
  BASubtype: { ANNUALISED: 'ANNUALISED', SESSIONAL: 'SESSIONAL', BCM: 'BCM' },
  BAStatus: { ACTIVE: 'ACTIVE', PENDING: 'PENDING', INACTIVE: 'INACTIVE' },
  PcpcmEnrolmentStatus: { ACTIVE: 'ACTIVE', PENDING: 'PENDING', WITHDRAWN: 'WITHDRAWN' },
  DelegatePermission: {
    CLAIM_CREATE: 'CLAIM_CREATE', CLAIM_EDIT: 'CLAIM_EDIT', CLAIM_VIEW: 'CLAIM_VIEW',
    CLAIM_DELETE: 'CLAIM_DELETE', CLAIM_QUEUE: 'CLAIM_QUEUE', CLAIM_APPROVE: 'CLAIM_APPROVE',
    CLAIM_RESUBMIT: 'CLAIM_RESUBMIT', CLAIM_WRITE_OFF: 'CLAIM_WRITE_OFF',
    BATCH_VIEW: 'BATCH_VIEW', BATCH_DOWNLOAD: 'BATCH_DOWNLOAD', BATCH_CONFIRM_UPLOAD: 'BATCH_CONFIRM_UPLOAD',
    IMPORT_EMR: 'IMPORT_EMR', IMPORT_MANAGE_TEMPLATES: 'IMPORT_MANAGE_TEMPLATES',
    PATIENT_VIEW: 'PATIENT_VIEW', PATIENT_CREATE: 'PATIENT_CREATE', PATIENT_EDIT: 'PATIENT_EDIT', PATIENT_IMPORT: 'PATIENT_IMPORT',
    SHIFT_MANAGE: 'SHIFT_MANAGE', REPORT_VIEW: 'REPORT_VIEW', REPORT_EXPORT: 'REPORT_EXPORT',
    AI_COACH_REVIEW: 'AI_COACH_REVIEW', REJECTION_MANAGE: 'REJECTION_MANAGE',
    PREFERENCE_VIEW: 'PREFERENCE_VIEW', PREFERENCE_EDIT: 'PREFERENCE_EDIT',
  },
  DelegateRelationshipStatus: { ACTIVE: 'ACTIVE', INVITED: 'INVITED', REVOKED: 'REVOKED' },
  SubmissionMode: { AUTO_CLEAN: 'AUTO_CLEAN', AUTO_ALL: 'AUTO_ALL', REQUIRE_APPROVAL: 'REQUIRE_APPROVAL' },
  HLinkAccreditationStatus: { PENDING: 'PENDING', ACTIVE: 'ACTIVE', SUSPENDED: 'SUSPENDED' },
  RoutingReason: {
    ARP_SERVICE_CODE: 'ARP_SERVICE_CODE',
    BA_FACILITY_MATCH: 'BA_FACILITY_MATCH',
    BA_SCHEDULE_MATCH: 'BA_SCHEDULE_MATCH',
    PRIMARY_BA_FALLBACK: 'PRIMARY_BA_FALLBACK',
    SINGLE_BA_DEFAULT: 'SINGLE_BA_DEFAULT',
    USER_OVERRIDE: 'USER_OVERRIDE',
  },
  ProviderAuditAction: {
    PROFILE_UPDATED: 'provider.profile_updated',
    ONBOARDING_COMPLETED: 'provider.onboarding_completed',
    BA_ADDED: 'ba.added', BA_UPDATED: 'ba.updated', BA_DEACTIVATED: 'ba.deactivated',
    LOCATION_ADDED: 'location.added', LOCATION_UPDATED: 'location.updated', LOCATION_DEACTIVATED: 'location.deactivated',
    WCB_CONFIG_ADDED: 'wcb_config.added', WCB_CONFIG_UPDATED: 'wcb_config.updated', WCB_CONFIG_REMOVED: 'wcb_config.removed',
    DELEGATE_INVITED: 'delegate.invited', DELEGATE_ACCEPTED: 'delegate.accepted',
    DELEGATE_PERMISSIONS_CHANGED: 'delegate.permissions_changed', DELEGATE_REVOKED: 'delegate.revoked',
    SUBMISSION_PREFERENCE_CHANGED: 'submission_preference.changed',
    HLINK_CONFIG_UPDATED: 'hlink_config.updated',
    ROUTING_CONFIG_UPDATED: 'routing_config.updated',
    ROUTING_RESOLVED: 'routing.resolved',
    CONNECT_CARE_TOGGLED: 'connect_care.toggled',
  },
  DEFAULT_SUBMISSION_PREFERENCES: {
    ahcip: 'AUTO_CLEAN',
    wcb: 'REQUIRE_APPROVAL',
    batchReviewReminder: true,
    deadlineReminderDays: 7,
  },
  PhysicianType: { GP: 'GP', SPECIALIST: 'SPECIALIST', LOCUM: 'LOCUM' },
  DelegatePermissionTemplate: { FULL_ACCESS: 'FULL_ACCESS', BILLING_ENTRY: 'BILLING_ENTRY', REVIEW_SUBMIT: 'REVIEW_SUBMIT', VIEW_ONLY: 'VIEW_ONLY', CUSTOM: 'CUSTOM' },
  DelegatePermissionTemplatePermissions: {},
  PcpcmPaymentStatus: { EXPECTED: 'EXPECTED', RECEIVED: 'RECEIVED', RECONCILED: 'RECONCILED', DISCREPANCY: 'DISCREPANCY' },
}));

// ---------------------------------------------------------------------------
// Mock DB schema modules
// ---------------------------------------------------------------------------

vi.mock('@meritum/shared/schemas/db/provider.schema.js', () => {
  const makeCol = (name: string) => ({ name });
  return {
    providers: { __table: 'providers', providerId: makeCol('providerId'), isConnectCareUser: makeCol('isConnectCareUser'), connectCareEnabledAt: makeCol('connectCareEnabledAt') },
    businessArrangements: { __table: 'business_arrangements', baId: makeCol('baId'), providerId: makeCol('providerId'), baType: makeCol('baType'), isPrimary: makeCol('isPrimary'), status: makeCol('status') },
    practiceLocations: { __table: 'practice_locations' },
    pcpcmEnrolments: { __table: 'pcpcm_enrolments' },
    wcbConfigurations: { __table: 'wcb_configurations' },
    delegateRelationships: { __table: 'delegate_relationships' },
    submissionPreferences: { __table: 'submission_preferences' },
    hlinkConfigurations: { __table: 'hlink_configurations' },
    baFacilityMappings: { __table: 'ba_facility_mappings', providerId: makeCol('providerId'), functionalCentre: makeCol('functionalCentre'), baId: makeCol('baId'), isActive: makeCol('isActive') },
    baScheduleMappings: { __table: 'ba_schedule_mappings', providerId: makeCol('providerId'), dayOfWeek: makeCol('dayOfWeek'), startTime: makeCol('startTime'), endTime: makeCol('endTime'), baId: makeCol('baId'), isActive: makeCol('isActive') },
  };
});

vi.mock('@meritum/shared/schemas/db/iam.schema.js', () => ({
  users: { __table: 'users' },
}));

vi.mock('@meritum/shared/schemas/db/reference.schema.js', () => ({
  hscCodes: { __table: 'hsc_codes' },
  referenceDataVersions: { __table: 'reference_data_versions' },
}));

vi.mock('@meritum/shared/schemas/provider.schema.js', () => ({}));

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const PROVIDER_1 = crypto.randomUUID();
const USER_1 = crypto.randomUUID();
const BA_FFS_ID = crypto.randomUUID();
const BA_ARP_ID = crypto.randomUUID();
const BA_PCPCM_ID = crypto.randomUUID();

// ---------------------------------------------------------------------------
// Build mock deps
// ---------------------------------------------------------------------------

function makeMockRepo(overrides?: Record<string, any>) {
  return {
    listActiveBasForProvider: vi.fn().mockResolvedValue([]),
    findFacilityMappingByFc: vi.fn().mockResolvedValue(undefined),
    findScheduleMappingByTime: vi.fn().mockResolvedValue(undefined),
    getConnectCareStatus: vi.fn().mockResolvedValue({ isConnectCareUser: false, connectCareEnabledAt: null }),
    setConnectCareUser: vi.fn().mockResolvedValue({ isConnectCareUser: false, connectCareEnabledAt: null }),
    getFacilityMappings: vi.fn().mockResolvedValue([]),
    getScheduleMappings: vi.fn().mockResolvedValue([]),
    upsertFacilityMappings: vi.fn().mockResolvedValue([]),
    upsertScheduleMappings: vi.fn().mockResolvedValue([]),
    deactivateAllFacilityMappings: vi.fn().mockResolvedValue(0),
    deactivateAllScheduleMappings: vi.fn().mockResolvedValue(0),
    // Other methods needed for type compatibility
    findProviderById: vi.fn(),
    findPcpcmEnrolmentForProvider: vi.fn().mockResolvedValue(null),
    getBaForClaim: vi.fn(),
    ...overrides,
  } as any;
}

function makeMockDeps(repoOverrides?: Record<string, any>): ProviderServiceDeps {
  return {
    repo: makeMockRepo(repoOverrides),
    auditRepo: { appendAuditLog: vi.fn().mockResolvedValue(undefined) },
    events: { emit: vi.fn() },
  } as any;
}

// ---------------------------------------------------------------------------
// Tests: Smart Routing
// ---------------------------------------------------------------------------

describe('Provider Smart Routing', () => {
  let deps: ProviderServiceDeps;

  beforeEach(() => {
    deps = makeMockDeps();
  });

  // =========================================================================
  // resolveRoutingBa
  // =========================================================================

  describe('resolveRoutingBa', () => {
    it('returns SINGLE_BA_DEFAULT when only one active BA', async () => {
      const singleBa = {
        baId: BA_FFS_ID,
        baNumber: 'BA001',
        baType: 'FFS',
        baSubtype: null,
        isPrimary: true,
        status: 'ACTIVE',
      };
      (deps.repo as any).listActiveBasForProvider.mockResolvedValueOnce([singleBa]);

      const result = await resolveRoutingBa(deps, PROVIDER_1, '03.01A', undefined, undefined);

      expect(result.routingReason).toBe('SINGLE_BA_DEFAULT');
      expect(result.baId).toBe(BA_FFS_ID);
      expect(result.baNumber).toBe('BA001');
      expect(result.conflict).toBe(false);
    });

    it('routes ARP service code to ARP BA', async () => {
      const ffsBa = {
        baId: BA_FFS_ID, baNumber: 'BA001', baType: 'FFS', baSubtype: null, isPrimary: true, status: 'ACTIVE',
      };
      const arpBa = {
        baId: BA_ARP_ID, baNumber: 'BA002', baType: 'ARP', baSubtype: 'SESSIONAL', isPrimary: false, status: 'ACTIVE',
      };
      (deps.repo as any).listActiveBasForProvider.mockResolvedValueOnce([ffsBa, arpBa]);

      const result = await resolveRoutingBa(deps, PROVIDER_1, '03.01A', undefined, undefined);

      expect(result.routingReason).toBe('ARP_SERVICE_CODE');
      expect(result.baId).toBe(BA_ARP_ID);
      expect(result.baType).toBe('ARP');
      expect(result.baSubtype).toBe('SESSIONAL');
    });

    it('does not route non-ARP service code to ARP BA', async () => {
      const ffsBa = {
        baId: BA_FFS_ID, baNumber: 'BA001', baType: 'FFS', baSubtype: null, isPrimary: true, status: 'ACTIVE',
      };
      const arpBa = {
        baId: BA_ARP_ID, baNumber: 'BA002', baType: 'ARP', baSubtype: 'SESSIONAL', isPrimary: false, status: 'ACTIVE',
      };
      (deps.repo as any).listActiveBasForProvider.mockResolvedValueOnce([ffsBa, arpBa]);

      const result = await resolveRoutingBa(deps, PROVIDER_1, '99.99Z', undefined, undefined);

      // Should NOT be ARP, should fall through to primary BA
      expect(result.routingReason).toBe('PRIMARY_BA_FALLBACK');
      expect(result.baId).toBe(BA_FFS_ID);
    });

    it('routes by facility mapping when matching functional centre', async () => {
      const ba1 = {
        baId: BA_FFS_ID, baNumber: 'BA001', baType: 'FFS', baSubtype: null, isPrimary: true, status: 'ACTIVE',
      };
      const ba2 = {
        baId: BA_PCPCM_ID, baNumber: 'BA002', baType: 'PCPCM', baSubtype: null, isPrimary: false, status: 'ACTIVE',
      };
      (deps.repo as any).listActiveBasForProvider.mockResolvedValueOnce([ba1, ba2]);
      (deps.repo as any).findFacilityMappingByFc.mockResolvedValueOnce({
        mappingId: crypto.randomUUID(),
        baId: BA_PCPCM_ID,
        functionalCentre: 'FC001',
        priority: 0,
        isActive: true,
      });

      const result = await resolveRoutingBa(deps, PROVIDER_1, '99.99Z', 'FC001', undefined);

      expect(result.routingReason).toBe('BA_FACILITY_MATCH');
      expect(result.baId).toBe(BA_PCPCM_ID);
      expect(result.baNumber).toBe('BA002');
    });

    it('routes by schedule mapping when matching day/time', async () => {
      const ba1 = {
        baId: BA_FFS_ID, baNumber: 'BA001', baType: 'FFS', baSubtype: null, isPrimary: true, status: 'ACTIVE',
      };
      const ba2 = {
        baId: BA_PCPCM_ID, baNumber: 'BA002', baType: 'PCPCM', baSubtype: null, isPrimary: false, status: 'ACTIVE',
      };
      (deps.repo as any).listActiveBasForProvider.mockResolvedValueOnce([ba1, ba2]);
      (deps.repo as any).findScheduleMappingByTime.mockResolvedValueOnce({
        mappingId: crypto.randomUUID(),
        baId: BA_PCPCM_ID,
        dayOfWeek: 1, // Monday
        startTime: '09:00',
        endTime: '17:00',
        priority: 0,
        isActive: true,
      });

      // Monday at 10:30 — 2025-01-06 is a Monday
      const result = await resolveRoutingBa(deps, PROVIDER_1, '99.99Z', undefined, '2025-01-06T10:30:00Z');

      expect(result.routingReason).toBe('BA_SCHEDULE_MATCH');
      expect(result.baId).toBe(BA_PCPCM_ID);
    });

    it('falls back to primary BA when no mappings match', async () => {
      const primaryBa = {
        baId: BA_FFS_ID, baNumber: 'BA001', baType: 'FFS', baSubtype: null, isPrimary: true, status: 'ACTIVE',
      };
      const otherBa = {
        baId: BA_PCPCM_ID, baNumber: 'BA002', baType: 'PCPCM', baSubtype: null, isPrimary: false, status: 'ACTIVE',
      };
      (deps.repo as any).listActiveBasForProvider.mockResolvedValueOnce([primaryBa, otherBa]);

      const result = await resolveRoutingBa(deps, PROVIDER_1, '99.99Z', undefined, undefined);

      expect(result.routingReason).toBe('PRIMARY_BA_FALLBACK');
      expect(result.baId).toBe(BA_FFS_ID);
      expect(result.baNumber).toBe('BA001');
    });

    it('throws NotFoundError when no active BAs', async () => {
      (deps.repo as any).listActiveBasForProvider.mockResolvedValueOnce([]);

      await expect(
        resolveRoutingBa(deps, PROVIDER_1, '03.01A', undefined, undefined),
      ).rejects.toThrow('not found');
    });

    it('respects priority chain: ARP > facility > schedule > fallback', async () => {
      const ffsBa = {
        baId: BA_FFS_ID, baNumber: 'BA001', baType: 'FFS', baSubtype: null, isPrimary: true, status: 'ACTIVE',
      };
      const arpBa = {
        baId: BA_ARP_ID, baNumber: 'BA002', baType: 'ARP', baSubtype: 'ANNUALISED', isPrimary: false, status: 'ACTIVE',
      };
      (deps.repo as any).listActiveBasForProvider.mockResolvedValueOnce([ffsBa, arpBa]);

      // Both facility and schedule match the FFS BA, but ARP service code takes precedence
      (deps.repo as any).findFacilityMappingByFc.mockResolvedValueOnce({
        mappingId: crypto.randomUUID(), baId: BA_FFS_ID, functionalCentre: 'FC001',
      });
      (deps.repo as any).findScheduleMappingByTime.mockResolvedValueOnce({
        mappingId: crypto.randomUUID(), baId: BA_FFS_ID, dayOfWeek: 1, startTime: '09:00', endTime: '17:00',
      });

      // ARP service code → ARP BA takes priority
      const result = await resolveRoutingBa(deps, PROVIDER_1, '03.01A', 'FC001', '2025-01-06T10:30:00Z');

      expect(result.routingReason).toBe('ARP_SERVICE_CODE');
      expect(result.baId).toBe(BA_ARP_ID);
    });
  });

  // =========================================================================
  // detectRoutingConflict
  // =========================================================================

  describe('detectRoutingConflict', () => {
    it('detects conflict when selected BA differs from resolved', async () => {
      const primaryBa = {
        baId: BA_FFS_ID, baNumber: 'BA001', baType: 'FFS', baSubtype: null, isPrimary: true, status: 'ACTIVE',
      };
      const otherBa = {
        baId: BA_PCPCM_ID, baNumber: 'BA002', baType: 'PCPCM', baSubtype: null, isPrimary: false, status: 'ACTIVE',
      };
      (deps.repo as any).listActiveBasForProvider.mockResolvedValueOnce([primaryBa, otherBa]);

      const result = await detectRoutingConflict(
        deps, PROVIDER_1, BA_PCPCM_ID, '99.99Z', undefined, undefined,
      );

      expect(result.hasConflict).toBe(true);
      expect(result.resolvedBaId).toBe(BA_FFS_ID);
      expect(result.selectedBaId).toBe(BA_PCPCM_ID);
    });

    it('no conflict when selected BA matches resolved', async () => {
      const singleBa = {
        baId: BA_FFS_ID, baNumber: 'BA001', baType: 'FFS', baSubtype: null, isPrimary: true, status: 'ACTIVE',
      };
      (deps.repo as any).listActiveBasForProvider.mockResolvedValueOnce([singleBa]);

      const result = await detectRoutingConflict(
        deps, PROVIDER_1, BA_FFS_ID, '99.99Z', undefined, undefined,
      );

      expect(result.hasConflict).toBe(false);
      expect(result.resolvedBaId).toBe(BA_FFS_ID);
      expect(result.selectedBaId).toBe(BA_FFS_ID);
    });
  });
});

// ---------------------------------------------------------------------------
// Tests: Connect Care
// ---------------------------------------------------------------------------

describe('Provider Connect Care', () => {
  let deps: ProviderServiceDeps;

  beforeEach(() => {
    deps = makeMockDeps();
  });

  describe('getConnectCareStatus', () => {
    it('returns Connect Care status', async () => {
      (deps.repo as any).getConnectCareStatus.mockResolvedValueOnce({
        isConnectCareUser: true,
        connectCareEnabledAt: new Date('2025-01-01'),
      });

      const result = await getConnectCareStatus(deps, PROVIDER_1);

      expect(result.isConnectCareUser).toBe(true);
      expect(result.connectCareEnabledAt).toBeInstanceOf(Date);
    });

    it('throws when provider not found', async () => {
      (deps.repo as any).getConnectCareStatus.mockResolvedValueOnce(undefined);

      await expect(
        getConnectCareStatus(deps, PROVIDER_1),
      ).rejects.toThrow('not found');
    });
  });

  describe('setConnectCareStatus', () => {
    it('enables Connect Care and logs audit', async () => {
      (deps.repo as any).setConnectCareUser.mockResolvedValueOnce({
        isConnectCareUser: true,
        connectCareEnabledAt: new Date(),
      });

      const result = await setConnectCareStatus(deps, PROVIDER_1, true, USER_1);

      expect(result.isConnectCareUser).toBe(true);
      expect((deps as any).auditRepo.appendAuditLog).toHaveBeenCalledTimes(1);
      const auditCall = (deps as any).auditRepo.appendAuditLog.mock.calls[0][0];
      expect(auditCall.action).toBe('connect_care.toggled');
      expect(auditCall.detail.is_connect_care).toBe(true);
    });

    it('emits event on toggle', async () => {
      (deps.repo as any).setConnectCareUser.mockResolvedValueOnce({
        isConnectCareUser: false,
        connectCareEnabledAt: null,
      });

      await setConnectCareStatus(deps, PROVIDER_1, false, USER_1);

      expect((deps as any).events.emit).toHaveBeenCalledWith(
        'provider.connect_care_toggled',
        expect.objectContaining({
          providerId: PROVIDER_1,
          isConnectCare: false,
        }),
      );
    });
  });
});

// ---------------------------------------------------------------------------
// Tests: Routing Config Management
// ---------------------------------------------------------------------------

describe('Provider Routing Config', () => {
  let deps: ProviderServiceDeps;

  beforeEach(() => {
    deps = makeMockDeps();
  });

  describe('getRoutingConfig', () => {
    it('returns facility and schedule mappings', async () => {
      const facilityMapping = {
        mappingId: crypto.randomUUID(),
        baId: BA_FFS_ID,
        providerId: PROVIDER_1,
        functionalCentre: 'FC001',
        priority: 0,
        isActive: true,
      };
      const scheduleMapping = {
        mappingId: crypto.randomUUID(),
        baId: BA_FFS_ID,
        providerId: PROVIDER_1,
        dayOfWeek: 1,
        startTime: '09:00',
        endTime: '17:00',
        priority: 0,
        isActive: true,
      };
      (deps.repo as any).getFacilityMappings.mockResolvedValueOnce([facilityMapping]);
      (deps.repo as any).getScheduleMappings.mockResolvedValueOnce([scheduleMapping]);

      const result = await getRoutingConfig(deps, PROVIDER_1);

      expect(result.facilityMappings).toHaveLength(1);
      expect(result.scheduleMappings).toHaveLength(1);
      expect(result.facilityMappings[0].functionalCentre).toBe('FC001');
      expect(result.scheduleMappings[0].dayOfWeek).toBe(1);
    });
  });

  describe('updateFacilityMappings', () => {
    it('deactivates old mappings and upserts new ones', async () => {
      (deps.repo as any).upsertFacilityMappings.mockResolvedValueOnce([
        { mappingId: crypto.randomUUID(), baId: BA_FFS_ID, functionalCentre: 'FC002' },
      ]);

      const result = await updateFacilityMappings(
        deps,
        PROVIDER_1,
        [{ baId: BA_FFS_ID, functionalCentre: 'FC002', priority: 1 }],
        USER_1,
      );

      expect((deps.repo as any).deactivateAllFacilityMappings).toHaveBeenCalledWith(PROVIDER_1);
      expect((deps.repo as any).upsertFacilityMappings).toHaveBeenCalledTimes(1);
      expect(result).toHaveLength(1);
      expect((deps as any).auditRepo.appendAuditLog).toHaveBeenCalledTimes(1);
    });
  });

  describe('updateScheduleMappings', () => {
    it('deactivates old mappings and inserts new ones', async () => {
      (deps.repo as any).upsertScheduleMappings.mockResolvedValueOnce([
        { mappingId: crypto.randomUUID(), baId: BA_FFS_ID, dayOfWeek: 1, startTime: '09:00', endTime: '12:00' },
      ]);

      const result = await updateScheduleMappings(
        deps,
        PROVIDER_1,
        [{ baId: BA_FFS_ID, dayOfWeek: 1, startTime: '09:00', endTime: '12:00', priority: 0 }],
        USER_1,
      );

      expect((deps.repo as any).deactivateAllScheduleMappings).toHaveBeenCalledWith(PROVIDER_1);
      expect((deps.repo as any).upsertScheduleMappings).toHaveBeenCalledTimes(1);
      expect(result).toHaveLength(1);
      expect((deps as any).auditRepo.appendAuditLog).toHaveBeenCalledTimes(1);
    });
  });
});
