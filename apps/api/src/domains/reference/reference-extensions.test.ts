// ============================================================================
// Phase 2: Reference Data Extensions — Unit Tests
// Tests for all new service functions added for CC-001 / MVPADD-001 FRDs.
// ============================================================================

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  getIcdCrosswalk,
  searchIcdCrosswalkEntries,
  searchProviderRegistryEntries,
  getProviderByCpsa,
  listBillingGuidanceEntries,
  searchBillingGuidanceEntries,
  getBillingGuidanceDetail,
  listProvincialPhnFormats,
  getReciprocalBillingRules,
  listAnesthesiaRulesEntries,
  getAnesthesiaRuleByScenario,
  calculateAnesthesiaFee,
  getBundlingRuleForPair,
  checkBundlingConflicts,
  listJustificationTemplatesEntries,
  getJustificationTemplateDetail,
  type ReferenceServiceDeps,
} from './reference.service.js';
import { NotFoundError } from '../../lib/errors.js';

// ---------------------------------------------------------------------------
// Mock Repository Builder
// ---------------------------------------------------------------------------

function makeMockRepo(overrides: Partial<Record<string, (...args: any[]) => any>> = {}) {
  const defaults: Record<string, (...args: any[]) => any> = {
    findActiveVersion: vi.fn().mockResolvedValue({ versionId: 'v-active' }),
    findVersionForDate: vi.fn().mockResolvedValue({ versionId: 'v-date' }),
    getIcdCrosswalkByIcd10: vi.fn().mockResolvedValue([]),
    searchIcdCrosswalk: vi.fn().mockResolvedValue([]),
    searchProviderRegistry: vi.fn().mockResolvedValue([]),
    getProviderByCpsa: vi.fn().mockResolvedValue(undefined),
    listBillingGuidance: vi.fn().mockResolvedValue([]),
    searchBillingGuidance: vi.fn().mockResolvedValue([]),
    getBillingGuidanceById: vi.fn().mockResolvedValue(undefined),
    listProvincialPhnFormats: vi.fn().mockResolvedValue([]),
    getReciprocalRules: vi.fn().mockResolvedValue([]),
    listAnesthesiaRules: vi.fn().mockResolvedValue([]),
    getAnesthesiaRuleByScenario: vi.fn().mockResolvedValue(undefined),
    getBundlingRuleForPair: vi.fn().mockResolvedValue(undefined),
    checkBundlingConflicts: vi.fn().mockResolvedValue([]),
    listJustificationTemplates: vi.fn().mockResolvedValue([]),
    getJustificationTemplate: vi.fn().mockResolvedValue(undefined),
  };

  const repo = { ...defaults, ...overrides } as unknown as ReferenceServiceDeps['repo'];
  const deps: ReferenceServiceDeps = { repo };
  return { deps, repo };
}

// ---------------------------------------------------------------------------
// ICD Crosswalk
// ---------------------------------------------------------------------------

describe('ICD Crosswalk', () => {
  it('getIcdCrosswalk resolves version and returns mapped results', async () => {
    const { deps, repo } = makeMockRepo({
      findActiveVersion: vi.fn().mockResolvedValue({ versionId: 'icd-v1' }),
      getIcdCrosswalkByIcd10: vi.fn().mockResolvedValue([
        {
          icd10Code: 'J06.9',
          icd10Description: 'Acute upper respiratory infection',
          icd9Code: '465',
          icd9Description: 'Acute URI',
          matchQuality: 'EXACT',
          isPreferred: true,
          notes: null,
        },
        {
          icd10Code: 'J06.9',
          icd10Description: 'Acute upper respiratory infection',
          icd9Code: '460',
          icd9Description: 'Acute nasopharyngitis',
          matchQuality: 'APPROXIMATE',
          isPreferred: false,
          notes: 'Less specific',
        },
      ]),
    });

    const results = await getIcdCrosswalk(deps, 'J06.9');

    expect(results).toHaveLength(2);
    expect(results[0].icd10Code).toBe('J06.9');
    expect(results[0].isPreferred).toBe(true);
    expect(results[0].matchQuality).toBe('EXACT');
    expect(results[1].isPreferred).toBe(false);
    expect((repo as any).getIcdCrosswalkByIcd10).toHaveBeenCalledWith('J06.9', 'icd-v1');
  });

  it('getIcdCrosswalk returns empty array when no mappings exist', async () => {
    const { deps } = makeMockRepo();
    const results = await getIcdCrosswalk(deps, 'Z99.9');
    expect(results).toEqual([]);
  });

  it('searchIcdCrosswalkEntries searches by query', async () => {
    const { deps, repo } = makeMockRepo({
      findActiveVersion: vi.fn().mockResolvedValue({ versionId: 'icd-v1' }),
      searchIcdCrosswalk: vi.fn().mockResolvedValue([
        {
          icd10Code: 'J06.9',
          icd10Description: 'Acute upper respiratory infection',
          icd9Code: '465',
          icd9Description: 'Acute URI',
          matchQuality: 'EXACT',
          isPreferred: true,
          notes: null,
        },
      ]),
    });

    const results = await searchIcdCrosswalkEntries(deps, 'J06', 10);

    expect(results).toHaveLength(1);
    expect((repo as any).searchIcdCrosswalk).toHaveBeenCalledWith('J06', 'icd-v1', 10);
  });

  it('getIcdCrosswalk throws NotFoundError when version is missing', async () => {
    const { deps } = makeMockRepo({
      findActiveVersion: vi.fn().mockResolvedValue(null),
    });

    await expect(getIcdCrosswalk(deps, 'J06.9')).rejects.toThrow(NotFoundError);
  });
});

// ---------------------------------------------------------------------------
// Provider Registry
// ---------------------------------------------------------------------------

describe('Provider Registry', () => {
  const sampleProvider = {
    registryId: 'reg-1',
    cpsa: '12345',
    firstName: 'Jane',
    lastName: 'Smith',
    specialtyCode: 'GP',
    specialtyDescription: 'General Practice',
    city: 'Calgary',
    facilityName: 'Smith Clinic',
    phone: '403-555-1234',
    fax: '403-555-5678',
    isActive: true,
  };

  it('searchProviderRegistryEntries returns formatted results', async () => {
    const { deps } = makeMockRepo({
      searchProviderRegistry: vi.fn().mockResolvedValue([sampleProvider]),
    });

    const results = await searchProviderRegistryEntries(deps, 'Smith', {}, 10);

    expect(results).toHaveLength(1);
    expect(results[0].firstName).toBe('Jane');
    expect(results[0].lastName).toBe('Smith');
    expect(results[0].cpsa).toBe('12345');
  });

  it('searchProviderRegistryEntries passes filters to repo', async () => {
    const { deps, repo } = makeMockRepo({
      searchProviderRegistry: vi.fn().mockResolvedValue([]),
    });

    await searchProviderRegistryEntries(deps, 'Smith', { specialty: 'CARD', city: 'Edmonton' }, 5);

    expect((repo as any).searchProviderRegistry).toHaveBeenCalledWith(
      'Smith',
      { specialty: 'CARD', city: 'Edmonton' },
      5,
    );
  });

  it('getProviderByCpsa returns provider detail', async () => {
    const { deps } = makeMockRepo({
      getProviderByCpsa: vi.fn().mockResolvedValue(sampleProvider),
    });

    const result = await getProviderByCpsa(deps, '12345');

    expect(result.cpsa).toBe('12345');
    expect(result.firstName).toBe('Jane');
  });

  it('getProviderByCpsa throws NotFoundError for unknown CPSA', async () => {
    const { deps } = makeMockRepo();

    await expect(getProviderByCpsa(deps, '99999')).rejects.toThrow(NotFoundError);
  });
});

// ---------------------------------------------------------------------------
// Billing Guidance
// ---------------------------------------------------------------------------

describe('Billing Guidance', () => {
  const sampleGuidance = {
    guidanceId: 'guid-1',
    category: 'SOMB_INTERPRETATION',
    title: 'Complex Visit Billing',
    content: 'When billing for a complex office visit, ensure the documentation supports...',
    applicableHscCodes: ['03.04A', '03.05A'],
    applicableSpecialties: ['GP'],
    sourceReference: 'SOMB 2026 §4.2',
    sourceUrl: null,
    sortOrder: 1,
    isActive: true,
  };

  it('listBillingGuidanceEntries returns filtered results', async () => {
    const { deps } = makeMockRepo({
      listBillingGuidance: vi.fn().mockResolvedValue([sampleGuidance]),
    });

    const results = await listBillingGuidanceEntries(deps, { category: 'SOMB_INTERPRETATION' });

    expect(results).toHaveLength(1);
    expect(results[0].title).toBe('Complex Visit Billing');
    expect(results[0].applicableHscCodes).toEqual(['03.04A', '03.05A']);
  });

  it('searchBillingGuidanceEntries does full-text search', async () => {
    const { deps, repo } = makeMockRepo({
      searchBillingGuidance: vi.fn().mockResolvedValue([sampleGuidance]),
    });

    const results = await searchBillingGuidanceEntries(deps, 'complex visit');

    expect(results).toHaveLength(1);
    expect((repo as any).searchBillingGuidance).toHaveBeenCalledWith('complex visit', 20);
  });

  it('getBillingGuidanceDetail returns single entry', async () => {
    const { deps } = makeMockRepo({
      getBillingGuidanceById: vi.fn().mockResolvedValue(sampleGuidance),
    });

    const result = await getBillingGuidanceDetail(deps, 'guid-1');
    expect(result.guidanceId).toBe('guid-1');
  });

  it('getBillingGuidanceDetail throws NotFoundError for missing ID', async () => {
    const { deps } = makeMockRepo();
    await expect(getBillingGuidanceDetail(deps, 'missing')).rejects.toThrow(NotFoundError);
  });
});

// ---------------------------------------------------------------------------
// Provincial PHN Formats
// ---------------------------------------------------------------------------

describe('Provincial PHN Formats', () => {
  it('listProvincialPhnFormats returns all formats', async () => {
    const { deps } = makeMockRepo({
      listProvincialPhnFormats: vi.fn().mockResolvedValue([
        {
          formatId: 'fmt-ab',
          provinceCode: 'AB',
          provinceName: 'Alberta',
          formatPattern: '9999-99999',
          formatDescription: '9-digit numeric',
          examplePhn: '1234-56789',
          validationRegex: '^\\d{4}-?\\d{5}$',
          phnLength: 9,
          isReciprocal: false,
        },
        {
          formatId: 'fmt-bc',
          provinceCode: 'BC',
          provinceName: 'British Columbia',
          formatPattern: '9999 999 999',
          formatDescription: '10-digit starting with 9',
          examplePhn: '9876543210',
          validationRegex: '^9\\d{9}$',
          phnLength: 10,
          isReciprocal: true,
        },
      ]),
    });

    const results = await listProvincialPhnFormats(deps);

    expect(results).toHaveLength(2);
    expect(results[0].provinceCode).toBe('AB');
    expect(results[0].isReciprocal).toBe(false);
    expect(results[1].provinceCode).toBe('BC');
    expect(results[1].isReciprocal).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Reciprocal Billing Rules
// ---------------------------------------------------------------------------

describe('Reciprocal Billing Rules', () => {
  it('getReciprocalBillingRules returns rules for a province', async () => {
    const { deps, repo } = makeMockRepo({
      getReciprocalRules: vi.fn().mockResolvedValue([
        {
          ruleId: 'rule-1',
          sourceProvince: 'BC',
          targetProvince: 'AB',
          billingMethod: 'RECIPROCAL',
          maxFeePercentage: '100',
          requiresPreApproval: false,
          effectiveFrom: '2025-01-01',
          effectiveTo: null,
          notes: null,
          isActive: true,
        },
      ]),
    });

    const results = await getReciprocalBillingRules(deps, 'BC');

    expect(results).toHaveLength(1);
    expect(results[0].sourceProvince).toBe('BC');
    expect(results[0].billingMethod).toBe('RECIPROCAL');
    expect((repo as any).getReciprocalRules).toHaveBeenCalledWith('BC');
  });

  it('returns empty array for province with no rules', async () => {
    const { deps } = makeMockRepo();
    const results = await getReciprocalBillingRules(deps, 'QC');
    expect(results).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Anesthesia Rules
// ---------------------------------------------------------------------------

describe('Anesthesia Rules', () => {
  const sampleRule = {
    ruleId: 'anes-1',
    scenarioCode: 'GENERAL_ANESTHESIA',
    scenarioName: 'General Anesthesia',
    description: 'Standard general anesthesia procedure',
    baseUnits: 4,
    timeUnitMinutes: 15,
    calculationFormula: 'base_units + ceil(duration_min / 15)',
    modifierInteractions: { BMI_GT_40: 'add_2_units' },
    exampleCalculation: '4 + ceil(60/15) = 8 units',
    sortOrder: 1,
    isActive: true,
  };

  it('listAnesthesiaRulesEntries returns sorted list', async () => {
    const { deps } = makeMockRepo({
      listAnesthesiaRules: vi.fn().mockResolvedValue([sampleRule]),
    });

    const results = await listAnesthesiaRulesEntries(deps);

    expect(results).toHaveLength(1);
    expect(results[0].scenarioCode).toBe('GENERAL_ANESTHESIA');
    expect(results[0].baseUnits).toBe(4);
  });

  it('getAnesthesiaRuleByScenario returns single rule', async () => {
    const { deps } = makeMockRepo({
      getAnesthesiaRuleByScenario: vi.fn().mockResolvedValue(sampleRule),
    });

    const result = await getAnesthesiaRuleByScenario(deps, 'GENERAL_ANESTHESIA');
    expect(result.scenarioCode).toBe('GENERAL_ANESTHESIA');
  });

  it('getAnesthesiaRuleByScenario throws NotFoundError for unknown scenario', async () => {
    const { deps } = makeMockRepo();
    await expect(getAnesthesiaRuleByScenario(deps, 'UNKNOWN')).rejects.toThrow(NotFoundError);
  });

  it('calculateAnesthesiaFee computes correct units', async () => {
    const { deps } = makeMockRepo({
      getAnesthesiaRuleByScenario: vi.fn().mockResolvedValue(sampleRule),
    });

    const result = await calculateAnesthesiaFee(deps, 'GENERAL_ANESTHESIA', 60);

    // base_units=4, timeUnits=ceil(60/15)=4, total=8
    expect(result.baseUnits).toBe(4);
    expect(result.timeUnits).toBe(4);
    expect(result.totalUnits).toBe(8);
  });

  it('calculateAnesthesiaFee handles partial time units', async () => {
    const { deps } = makeMockRepo({
      getAnesthesiaRuleByScenario: vi.fn().mockResolvedValue(sampleRule),
    });

    const result = await calculateAnesthesiaFee(deps, 'GENERAL_ANESTHESIA', 37);

    // base_units=4, timeUnits=ceil(37/15)=3, total=7
    expect(result.timeUnits).toBe(3);
    expect(result.totalUnits).toBe(7);
  });

  it('calculateAnesthesiaFee throws NotFoundError for unknown scenario', async () => {
    const { deps } = makeMockRepo();
    await expect(calculateAnesthesiaFee(deps, 'UNKNOWN', 60)).rejects.toThrow(NotFoundError);
  });
});

// ---------------------------------------------------------------------------
// Bundling Rules
// ---------------------------------------------------------------------------

describe('Bundling Rules', () => {
  const sampleBundlingRule = {
    ruleId: 'bund-1',
    codeA: '03.04A',
    codeB: '03.05A',
    relationship: 'BUNDLED',
    description: 'These codes are bundled — only bill the higher-fee code',
    resolution: 'Bill the higher fee code only',
    overrideAllowed: true,
    sourceReference: 'SOMB 2026 §5.1',
    isActive: true,
  };

  it('getBundlingRuleForPair returns rule for known pair', async () => {
    const { deps } = makeMockRepo({
      getBundlingRuleForPair: vi.fn().mockResolvedValue(sampleBundlingRule),
    });

    const result = await getBundlingRuleForPair(deps, '03.04A', '03.05A');

    expect(result).not.toBeNull();
    expect(result!.relationship).toBe('BUNDLED');
    expect(result!.overrideAllowed).toBe(true);
  });

  it('getBundlingRuleForPair returns null for unknown pair', async () => {
    const { deps } = makeMockRepo();
    const result = await getBundlingRuleForPair(deps, 'XX.XX', 'YY.YY');
    expect(result).toBeNull();
  });

  it('checkBundlingConflicts returns all conflicts for code set', async () => {
    const { deps, repo } = makeMockRepo({
      checkBundlingConflicts: vi.fn().mockResolvedValue([sampleBundlingRule]),
    });

    const results = await checkBundlingConflicts(deps, ['03.04A', '03.05A', '03.06A']);

    expect(results).toHaveLength(1);
    expect(results[0].codeA).toBe('03.04A');
    expect(results[0].codeB).toBe('03.05A');
    expect((repo as any).checkBundlingConflicts).toHaveBeenCalledWith(['03.04A', '03.05A', '03.06A']);
  });

  it('checkBundlingConflicts returns empty for non-conflicting codes', async () => {
    const { deps } = makeMockRepo();
    const results = await checkBundlingConflicts(deps, ['AA.AA', 'BB.BB']);
    expect(results).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Justification Templates
// ---------------------------------------------------------------------------

describe('Justification Templates', () => {
  const sampleTemplate = {
    templateId: 'tmpl-1',
    scenario: 'DUPLICATE_SERVICE',
    title: 'Medically Necessary Duplicate Service',
    templateText: 'Patient {patient_name} required a second {procedure} on {date} because {reason}.',
    placeholders: ['patient_name', 'procedure', 'date', 'reason'],
    sortOrder: 1,
    isActive: true,
  };

  it('listJustificationTemplatesEntries returns templates', async () => {
    const { deps } = makeMockRepo({
      listJustificationTemplates: vi.fn().mockResolvedValue([sampleTemplate]),
    });

    const results = await listJustificationTemplatesEntries(deps);

    expect(results).toHaveLength(1);
    expect(results[0].scenario).toBe('DUPLICATE_SERVICE');
    expect(results[0].placeholders).toEqual(['patient_name', 'procedure', 'date', 'reason']);
  });

  it('listJustificationTemplatesEntries filters by scenario', async () => {
    const { deps, repo } = makeMockRepo({
      listJustificationTemplates: vi.fn().mockResolvedValue([sampleTemplate]),
    });

    await listJustificationTemplatesEntries(deps, 'DUPLICATE_SERVICE');

    expect((repo as any).listJustificationTemplates).toHaveBeenCalledWith('DUPLICATE_SERVICE');
  });

  it('getJustificationTemplateDetail returns single template', async () => {
    const { deps } = makeMockRepo({
      getJustificationTemplate: vi.fn().mockResolvedValue(sampleTemplate),
    });

    const result = await getJustificationTemplateDetail(deps, 'tmpl-1');
    expect(result.templateId).toBe('tmpl-1');
    expect(result.templateText).toContain('{patient_name}');
  });

  it('getJustificationTemplateDetail throws NotFoundError for missing template', async () => {
    const { deps } = makeMockRepo();
    await expect(getJustificationTemplateDetail(deps, 'missing')).rejects.toThrow(NotFoundError);
  });
});
