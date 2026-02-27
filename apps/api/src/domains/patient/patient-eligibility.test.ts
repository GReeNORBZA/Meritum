import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createHash } from 'node:crypto';
import {
  checkEligibility,
  overrideEligibility,
  bulkCheckEligibility,
  detectPatientProvince,
  type PatientServiceDeps,
} from './patient.service.js';

// ---------------------------------------------------------------------------
// In-memory stores
// ---------------------------------------------------------------------------

let eligibilityCacheStore: Record<string, any>[];
let auditLogEntries: Record<string, any>[];

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
  gt: (column: any, value: any) => {
    const colName = column?.name;
    return { __predicate: (row: any) => row[colName] > value };
  },
  lt: (column: any, value: any) => {
    const colName = column?.name;
    return { __predicate: (row: any) => row[colName] < value };
  },
  sql: (strings: TemplateStringsArray, ...values: any[]) => ({
    __sql: true,
    raw: strings.join('?'),
    values,
  }),
  count: () => ({ __count: true }),
}));

// ---------------------------------------------------------------------------
// Mock PHN utilities
// ---------------------------------------------------------------------------

vi.mock('@meritum/shared/utils/phn.utils.js', () => ({
  validateAlbertaPhn: (phn: string) => {
    if (typeof phn !== 'string' || !/^\d{9}$/.test(phn)) {
      return { valid: false, error: 'PHN must be exactly 9 digits' };
    }
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
}));

// ---------------------------------------------------------------------------
// Mock province detection utilities
// ---------------------------------------------------------------------------

vi.mock('@meritum/shared/utils/province-detection.utils.js', () => ({
  detectProvinceFromPhn: (phn: string) => {
    const normalised = phn.trim();
    // QC: 4 alpha + 8 numeric
    if (/^[A-Z]{4}\d{8}$/.test(normalised)) {
      return { provinceCode: 'QC', candidates: ['QC'], isDefinitive: true };
    }
    // BC: 10-digit
    if (/^\d{10}$/.test(normalised)) {
      return { provinceCode: 'BC', candidates: ['BC'], isDefinitive: true };
    }
    // ON: with dash
    if (/^\d{4}-\d{3}-\d{3}$/.test(normalised)) {
      return { provinceCode: 'ON', candidates: ['ON'], isDefinitive: true };
    }
    // 9-digit: ambiguous (AB, SK, MB, NB, YT, NU)
    if (/^\d{9}$/.test(normalised)) {
      return {
        provinceCode: null,
        candidates: ['AB', 'SK', 'MB', 'NB', 'YT', 'NU'],
        isDefinitive: false,
      };
    }
    return { provinceCode: null, candidates: [], isDefinitive: false };
  },
  isOutOfProvincePhn: (phn: string, declaredProvince?: string) => {
    if (declaredProvince && declaredProvince !== 'AB') return true;
    const normalised = phn.trim();
    if (/^[A-Z]{4}\d{8}$/.test(normalised)) return true; // QC
    if (/^\d{10}$/.test(normalised)) return true; // BC
    if (/^\d{4}-\d{3}-\d{3}$/.test(normalised)) return true; // ON
    return false;
  },
}));

// ---------------------------------------------------------------------------
// Mock patient constants
// ---------------------------------------------------------------------------

vi.mock('@meritum/shared/constants/patient.constants.js', () => ({
  PatientAuditAction: {
    CREATED: 'patient.created',
    UPDATED: 'patient.updated',
    DEACTIVATED: 'patient.deactivated',
    REACTIVATED: 'patient.reactivated',
    MERGED: 'patient.merged',
    IMPORT_COMPLETED: 'patient.import_completed',
    EXPORT_REQUESTED: 'patient.export_requested',
    EXPORT_DOWNLOADED: 'patient.export_downloaded',
    SEARCHED: 'patient.searched',
    CORRECTION_APPLIED: 'patient.correction_applied',
    ACCESS_EXPORT_REQUESTED: 'export.patient_access_requested',
    ACCESS_EXPORT_READY: 'export.patient_access_ready',
    ELIGIBILITY_CHECKED: 'patient.eligibility_checked',
    ELIGIBILITY_OVERRIDDEN: 'patient.eligibility_overridden',
    PROVINCE_DETECTED: 'patient.province_detected',
  },
  PatientSearchMode: {
    PHN_LOOKUP: 'PHN_LOOKUP',
    NAME_SEARCH: 'NAME_SEARCH',
    DOB_SEARCH: 'DOB_SEARCH',
    COMBINED: 'COMBINED',
    RECENT: 'RECENT',
  },
  DEFAULT_PHN_PROVINCE: 'AB',
  ImportStatus: {
    PENDING: 'PENDING',
    PROCESSING: 'PROCESSING',
    COMPLETED: 'COMPLETED',
    FAILED: 'FAILED',
  },
  CSV_COLUMN_MAPPINGS: {
    phn: ['PHN'],
    first_name: ['FirstName'],
    last_name: ['LastName'],
    date_of_birth: ['DOB'],
    gender: ['Gender'],
    phone: ['Phone'],
    address_line_1: ['Address'],
    city: ['City'],
    postal_code: ['PostalCode'],
  },
  CSV_GENDER_VALUE_MAPPINGS: {
    Male: 'M',
    Female: 'F',
    M: 'M',
    F: 'F',
    X: 'X',
  },
}));

// ---------------------------------------------------------------------------
// Mock schema modules
// ---------------------------------------------------------------------------

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
      lastName: makeCol('lastName'),
      dateOfBirth: makeCol('dateOfBirth'),
      gender: makeCol('gender'),
      isActive: makeCol('isActive'),
      createdAt: makeCol('createdAt'),
      updatedAt: makeCol('updatedAt'),
      createdBy: makeCol('createdBy'),
    },
    patientImportBatches: {
      __table: 'patient_import_batches',
    },
    patientMergeHistory: {
      __table: 'patient_merge_history',
    },
    eligibilityCache: {
      __table: 'eligibility_cache',
      cacheId: makeCol('cacheId'),
      providerId: makeCol('providerId'),
      phnHash: makeCol('phnHash'),
      isEligible: makeCol('isEligible'),
      eligibilityDetails: makeCol('eligibilityDetails'),
      verifiedAt: makeCol('verifiedAt'),
      expiresAt: makeCol('expiresAt'),
      createdAt: makeCol('createdAt'),
    },
  };
});

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const PHYSICIAN_1 = crypto.randomUUID();
const USER_1 = crypto.randomUUID();

// Valid Alberta PHN that passes Luhn: 123456782
const VALID_AB_PHN = '123456782';
// Invalid Luhn PHN
const INVALID_LUHN_PHN = '123456789';

// ---------------------------------------------------------------------------
// Build mock deps
// ---------------------------------------------------------------------------

function makeMockDeps(): PatientServiceDeps {
  const auditRepo = { appendAuditLog: vi.fn().mockResolvedValue(undefined) };
  const events = { emit: vi.fn() };

  // Build a minimal repo mock that only includes the eligibility cache methods
  const repo: any = {
    getCachedEligibility: vi.fn().mockResolvedValue(null),
    setCachedEligibility: vi.fn().mockResolvedValue(undefined),
    purgeExpiredEligibilityCache: vi.fn().mockResolvedValue(0),
    // Other methods needed by validateAlbertaPhn path (not used directly but referenced)
    findPatientByPhn: vi.fn().mockResolvedValue(undefined),
    createPatient: vi.fn(),
    findPatientById: vi.fn(),
    updatePatient: vi.fn(),
    searchPatients: vi.fn(),
    countPatients: vi.fn(),
    findRecentPatients: vi.fn(),
    createImportBatch: vi.fn(),
    findImportBatch: vi.fn(),
    updateImportBatch: vi.fn(),
    createMergeRecord: vi.fn(),
    findMergeHistory: vi.fn(),
    getPatientClaimContext: vi.fn(),
    validatePhnExists: vi.fn(),
  };

  return { repo, auditRepo, events } as PatientServiceDeps;
}

// ---------------------------------------------------------------------------
// Tests: Eligibility Check
// ---------------------------------------------------------------------------

describe('Patient Eligibility Service', () => {
  let deps: PatientServiceDeps;

  beforeEach(() => {
    eligibilityCacheStore = [];
    auditLogEntries = [];
    deps = makeMockDeps();
  });

  // =========================================================================
  // checkEligibility
  // =========================================================================

  describe('checkEligibility', () => {
    it('returns eligibility from H-Link when cache is empty', async () => {
      const result = await checkEligibility(deps, PHYSICIAN_1, VALID_AB_PHN, undefined, USER_1);

      expect(result.isEligible).toBe(true);
      expect(result.source).toBe('HLINK');
      expect(result.phnMasked).toBe('123******');
      expect(result.verifiedAt).toBeInstanceOf(Date);
      expect(result.details).toBeDefined();
    });

    it('caches result after H-Link inquiry', async () => {
      await checkEligibility(deps, PHYSICIAN_1, VALID_AB_PHN, undefined, USER_1);

      expect((deps.repo as any).setCachedEligibility).toHaveBeenCalledTimes(1);
      const cacheCall = (deps.repo as any).setCachedEligibility.mock.calls[0][0];
      expect(cacheCall.providerId).toBe(PHYSICIAN_1);
      expect(cacheCall.phnHash).toBe(createHash('sha256').update(VALID_AB_PHN).digest('hex'));
      expect(cacheCall.isEligible).toBe(true);
      expect(cacheCall.expiresAt).toBeInstanceOf(Date);
    });

    it('returns cached result when available', async () => {
      const cachedEntry = {
        isEligible: true,
        eligibilityDetails: { status: 'ELIGIBLE' },
        verifiedAt: new Date(),
      };
      (deps.repo as any).getCachedEligibility.mockResolvedValueOnce(cachedEntry);

      const result = await checkEligibility(deps, PHYSICIAN_1, VALID_AB_PHN, undefined, USER_1);

      expect(result.source).toBe('CACHE');
      expect(result.isEligible).toBe(true);
      // Should NOT call setCachedEligibility when returning from cache
      expect((deps.repo as any).setCachedEligibility).not.toHaveBeenCalled();
    });

    it('rejects invalid PHN format', async () => {
      await expect(
        checkEligibility(deps, PHYSICIAN_1, INVALID_LUHN_PHN, undefined, USER_1),
      ).rejects.toThrow('Invalid Alberta PHN format');
    });

    it('emits event after H-Link inquiry', async () => {
      await checkEligibility(deps, PHYSICIAN_1, VALID_AB_PHN, undefined, USER_1);

      expect((deps as any).events.emit).toHaveBeenCalledWith(
        'patient.eligibility_checked',
        expect.objectContaining({
          physicianId: PHYSICIAN_1,
          source: 'HLINK',
          isEligible: true,
        }),
      );
    });

    it('logs audit entry with masked PHN', async () => {
      await checkEligibility(deps, PHYSICIAN_1, VALID_AB_PHN, '2025-01-15', USER_1);

      expect((deps as any).auditRepo.appendAuditLog).toHaveBeenCalled();
      const auditCall = (deps as any).auditRepo.appendAuditLog.mock.calls[0][0];
      expect(auditCall.action).toBe('patient.eligibility_checked');
      expect(auditCall.detail.phn_masked).toBe('123******');
      expect(auditCall.detail.date_of_service).toBe('2025-01-15');
      // PHN should not appear in audit log
      expect(JSON.stringify(auditCall)).not.toContain(VALID_AB_PHN);
    });

    it('passes date_of_service to details', async () => {
      const result = await checkEligibility(deps, PHYSICIAN_1, VALID_AB_PHN, '2025-06-01', USER_1);

      expect(result.details.date_of_service).toBe('2025-06-01');
    });
  });

  // =========================================================================
  // overrideEligibility
  // =========================================================================

  describe('overrideEligibility', () => {
    it('overrides eligibility and caches override entry', async () => {
      const result = await overrideEligibility(
        deps,
        PHYSICIAN_1,
        VALID_AB_PHN,
        'Patient presented valid coverage card',
        USER_1,
      );

      expect(result.overridden).toBe(true);
      expect(result.phnMasked).toBe('123******');
      expect(result.reason).toBe('Patient presented valid coverage card');

      // Should cache with OVERRIDE status
      expect((deps.repo as any).setCachedEligibility).toHaveBeenCalledTimes(1);
      const cacheCall = (deps.repo as any).setCachedEligibility.mock.calls[0][0];
      expect(cacheCall.isEligible).toBe(true);
      expect(cacheCall.eligibilityDetails.status).toBe('OVERRIDE');
      expect(cacheCall.eligibilityDetails.reason).toBe('Patient presented valid coverage card');
    });

    it('logs audit entry for override', async () => {
      await overrideEligibility(deps, PHYSICIAN_1, VALID_AB_PHN, 'Override reason', USER_1);

      const auditCall = (deps as any).auditRepo.appendAuditLog.mock.calls[0][0];
      expect(auditCall.action).toBe('patient.eligibility_overridden');
      expect(auditCall.detail.reason).toBe('Override reason');
      expect(auditCall.detail.phn_masked).toBe('123******');
    });

    it('emits override event', async () => {
      await overrideEligibility(deps, PHYSICIAN_1, VALID_AB_PHN, 'reason', USER_1);

      expect((deps as any).events.emit).toHaveBeenCalledWith(
        'patient.eligibility_overridden',
        expect.objectContaining({
          physicianId: PHYSICIAN_1,
          reason: 'reason',
          actorId: USER_1,
        }),
      );
    });
  });

  // =========================================================================
  // bulkCheckEligibility
  // =========================================================================

  describe('bulkCheckEligibility', () => {
    it('checks multiple PHNs and returns summary', async () => {
      const entries = [
        { phn: VALID_AB_PHN },
        { phn: VALID_AB_PHN, dateOfService: '2025-03-01' },
      ];

      const result = await bulkCheckEligibility(deps, PHYSICIAN_1, entries, USER_1);

      expect(result.results).toHaveLength(2);
      expect(result.summary.total).toBe(2);
      expect(result.summary.eligible).toBe(2);
      expect(result.summary.ineligible).toBe(0);
      expect(result.summary.errors).toBe(0);
    });

    it('rejects more than 50 entries', async () => {
      const entries = Array.from({ length: 51 }, (_, i) => ({
        phn: VALID_AB_PHN,
      }));

      await expect(
        bulkCheckEligibility(deps, PHYSICIAN_1, entries, USER_1),
      ).rejects.toThrow('Bulk eligibility check limited to 50 entries');
    });

    it('handles individual failures with FALLBACK', async () => {
      const entries = [
        { phn: VALID_AB_PHN },
        { phn: INVALID_LUHN_PHN }, // Will fail validation
      ];

      const result = await bulkCheckEligibility(deps, PHYSICIAN_1, entries, USER_1);

      expect(result.results).toHaveLength(2);
      expect(result.summary.eligible).toBe(1);
      expect(result.summary.errors).toBe(1);
      expect(result.results[1].source).toBe('FALLBACK');
      expect(result.results[1].isEligible).toBe(false);
    });

    it('returns correct masked PHN for failures', async () => {
      const entries = [{ phn: INVALID_LUHN_PHN }];

      const result = await bulkCheckEligibility(deps, PHYSICIAN_1, entries, USER_1);

      expect(result.results[0].phnMasked).toBe('123******');
      expect(result.results[0].source).toBe('FALLBACK');
    });
  });
});

// ---------------------------------------------------------------------------
// Tests: Province Detection
// ---------------------------------------------------------------------------

describe('Patient Province Detection Service', () => {
  let deps: PatientServiceDeps;

  beforeEach(() => {
    deps = makeMockDeps();
  });

  describe('detectPatientProvince', () => {
    it('detects ambiguous 9-digit PHN as UNKNOWN billing mode', async () => {
      // 9-digit PHN is ambiguous (could be AB, SK, MB, etc.)
      const result = await detectPatientProvince(deps, PHYSICIAN_1, VALID_AB_PHN, USER_1);

      // Since 9-digit is ambiguous (isDefinitive=false), confidence is LOW
      expect(result.confidence).toBe('LOW');
      expect(result.detectedProvince).toBeNull();
      expect(result.billingMode).toBe('UNKNOWN');
      expect(result.isOutOfProvince).toBe(false);
    });

    it('detects Quebec PHN as PRIVATE billing mode', async () => {
      // QC format: 4 alpha + 8 numeric
      const result = await detectPatientProvince(deps, PHYSICIAN_1, 'ABCD12345678', USER_1);

      expect(result.detectedProvince).toBe('QC');
      expect(result.confidence).toBe('HIGH');
      expect(result.billingMode).toBe('PRIVATE');
      expect(result.isOutOfProvince).toBe(true);
      expect(result.reciprocalEligible).toBe(false);
    });

    it('detects BC PHN as RECIPROCAL billing mode', async () => {
      // BC format: 10-digit
      const result = await detectPatientProvince(deps, PHYSICIAN_1, '1234567890', USER_1);

      expect(result.detectedProvince).toBe('BC');
      expect(result.confidence).toBe('HIGH');
      expect(result.billingMode).toBe('RECIPROCAL');
      expect(result.isOutOfProvince).toBe(true);
      expect(result.reciprocalEligible).toBe(true);
    });

    it('detects Ontario PHN as RECIPROCAL billing mode', async () => {
      // ON format: ####-###-###
      const result = await detectPatientProvince(deps, PHYSICIAN_1, '1234-567-890', USER_1);

      expect(result.detectedProvince).toBe('ON');
      expect(result.confidence).toBe('HIGH');
      expect(result.billingMode).toBe('RECIPROCAL');
      expect(result.isOutOfProvince).toBe(true);
      expect(result.reciprocalEligible).toBe(true);
    });

    it('returns UNKNOWN for unrecognised format', async () => {
      const result = await detectPatientProvince(deps, PHYSICIAN_1, 'XYZ', USER_1);

      expect(result.detectedProvince).toBeNull();
      expect(result.confidence).toBe('NONE');
      expect(result.billingMode).toBe('UNKNOWN');
      expect(result.reciprocalEligible).toBe(false);
    });

    it('logs audit entry with detection details', async () => {
      await detectPatientProvince(deps, PHYSICIAN_1, '1234567890', USER_1);

      const auditCall = (deps as any).auditRepo.appendAuditLog.mock.calls[0][0];
      expect(auditCall.action).toBe('patient.province_detected');
      expect(auditCall.detail.detected_province).toBe('BC');
      expect(auditCall.detail.confidence).toBe('HIGH');
      expect(auditCall.detail.billing_mode).toBe('RECIPROCAL');
      expect(auditCall.detail.is_out_of_province).toBe(true);
    });
  });
});
